"""规则获取模块 — 负责本地规则文件读取与远程规则订阅拉取"""

import logging
import re
from pathlib import Path
from typing import Iterator

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .rule_store import RuleStore
from .rule_resolver import RuleResolver
from .source_cache import SourceCache
from .sources_reader import SourcesReader
from .config import PathConfig

logger = logging.getLogger(__name__)


class SourceTooLarge(Exception):
    """响应体超过单源上限。"""

    def __init__(self, limit: int):
        super().__init__(f"响应体超过 {limit // (1024 * 1024)}MB 上限")
        self.limit = limit


class RuleFetcher:
    """规则获取器（容错式聚合）

    单个源拉取失败、解析失败或超出大小上限时均不中止构建：
    优先回退该源「最近一次成功」的缓存，无可用缓存时跳过并记录原因。

    每个源解析出的规则先暂存，只有该源被接受（拉取成功或缓存回退）才并入规则集合，
    避免半途失败的源留下不完整数据。每个源的处理结果记录在 source_status 中，
    供构建日志汇总使用。
    """

    # 单个远程源的响应体上限（按解压后的字节数累计），作为异常响应的安全阀；
    # 解析按行流式进行，不把整个响应体驻留内存。
    # 取 100MB 与 GitHub「仓库单文件 100MB」的限制对齐：托管在 GitHub 的源不会更大。
    # 目前最大的源是 blocklistproject 的 malware-ags.txt（约 56MB / 265 万条）。
    DEFAULT_MAX_RESPONSE_SIZE = 100 * 1024 * 1024  # 100 MB
    _CHUNK_SIZE = 8192

    # 匹配合法域名（与 RuleResolver 保持一致）
    _DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    )

    # 单个源的处理状态
    STATUS_OK = 'ok'
    STATUS_CACHE = 'cache'
    STATUS_SKIPPED = 'skipped'

    def __init__(self,
                 sources_reader: SourcesReader,
                 resolver: RuleResolver,
                 rule_store: RuleStore,
                 path_config: PathConfig | None = None,
                 max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
                 source_cache: SourceCache | None = None):
        """
        :param sources_reader:    规则源读取器
        :param resolver:          规则解析器
        :param rule_store:        规则存储容器
        :param path_config:       路径配置
        :param max_response_size: 单源响应体上限（字节），超出即回退缓存或跳过
        :param source_cache:      源缓存（默认按路径配置创建）
        """
        self._sources_reader = sources_reader
        self._resolver = resolver
        self._store = rule_store
        self._path_config = path_config or PathConfig()
        self._max_response_size = max_response_size
        self._cache = source_cache or SourceCache(self._path_config.source_cache_dir)

        # 本次运行中每个远程源的处理结果
        self.source_status: list[dict] = []

    # ------------------------------------------------------------------
    # 本地规则
    # ------------------------------------------------------------------

    def read_local_rules(self) -> None:
        """读取本地自定义规则目录中所有 .txt 文件。"""
        logger.info("读取本地自定义规则...")

        c_path = Path(self._path_config.custom_rules_dir)
        if not c_path.exists():
            logger.warning("自定义规则目录不存在: %s", self._path_config.custom_rules_dir)
            return

        for f in c_path.glob('*.txt'):
            try:
                skipped = 0
                is_whitelist_file = (f.name == 'custom_whitelist.txt')
                with open(f, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        stripped = line.strip()

                        if is_whitelist_file and stripped and not stripped.startswith(('!', '#')):
                            # 白名单文件只接受域名或 @@ 开头的规则：
                            # 纯域名行自动包装为 @@||domain^，
                            # 其余无法识别的行直接跳过，避免被误判为黑名单
                            if stripped.startswith('@@'):
                                pass  # 原样解析
                            elif self._DOMAIN_PATTERN.match(stripped):
                                line = f'@@||{stripped}^'
                            else:
                                skipped += 1
                                continue

                        rtype, rule = self._resolver.resolve(line)
                        if rtype:
                            self._store.add_rule(rtype, rule)
                            # 自定义规则同样适用于精简版：白名单本身就是全局共享，
                            # 拦截规则若只进完整版，会让 Lite 用户拿不到自己的屏蔽项
                            lite_type = self._map_lite_rtype(rtype)
                            if lite_type and lite_type != rtype:
                                self._store.add_rule(lite_type, rule)
                        elif stripped and not stripped.startswith(('!', '#', '/')):
                            skipped += 1

                if skipped:
                    logger.info("成功读取 %s，%d 行无法识别已跳过", f.name, skipped)
                else:
                    logger.info("成功读取 %s", f.name)

            except (OSError, UnicodeDecodeError) as e:
                logger.error("读取 %s 时出错: %s", f.name, e)

    # ------------------------------------------------------------------
    # Lite 规则类型映射
    # ------------------------------------------------------------------

    @staticmethod
    def _map_lite_rtype(rtype: str) -> str | None:
        """将解析出的规则类型映射到 Lite 集合名称。"""
        mapping = {
            'hosts_rules': RuleStore.R_TYPE_HOSTS_LITE,
            'adguard_rules': RuleStore.R_TYPE_ADGUARD_LITE,
            'whitelist': RuleStore.R_TYPE_WHITELIST,  # 白名单全局共享
        }
        return mapping.get(rtype)

    @staticmethod
    def _is_comment(line: str) -> bool:
        """判断是否为注释或空行（不计入"无法识别"统计）。"""
        s = line.strip()
        return not s or s.startswith(('!', '#'))

    # ------------------------------------------------------------------
    # 状态记录
    # ------------------------------------------------------------------

    def _record(self, url: str, status: str, rules: int = 0,
                reason: str = '', cached_at: str = '') -> None:
        """记录单个源的处理结果。"""
        self.source_status.append({
            'url': url,
            'status': status,
            'rules': rules,
            'reason': reason,
            'cached_at': cached_at,
        })

    def degraded_sources(self) -> list[dict]:
        """未能使用最新上游内容的源（缓存回退或跳过）。"""
        return [s for s in self.source_status if s['status'] != self.STATUS_OK]

    # ------------------------------------------------------------------
    # 远程规则
    # ------------------------------------------------------------------

    def _stream_lines(self, response: requests.Response) -> Iterator[str]:
        """按行解码响应体，并累计解压后的大小做上限保护。"""
        total = 0
        for raw in response.iter_lines(chunk_size=self._CHUNK_SIZE):
            if not raw:
                continue
            total += len(raw) + 1
            if total > self._max_response_size:
                raise SourceTooLarge(self._max_response_size)
            yield raw.decode('utf-8', errors='replace')

    def _ingest_lines(self, lines: Iterator[str], is_lite: bool,
                      sink: '_CacheWriter | None' = None) -> tuple[dict[str, set[str]], dict[str, int]]:
        """解析行迭代器，结果先暂存，不直接写入规则集合。

        :param lines:   已解码的行迭代器
        :param is_lite: 是否按 Lite 集合归类
        :param sink:    非空时同步写入源缓存
        :returns: (暂存的 {集合名: 规则集合}, 统计信息)
        """
        staged: dict[str, set[str]] = {}
        stats = {'added': 0, 'skipped': 0, 'errors': 0, 'replaced': 0}

        for line in lines:
            if sink is not None:
                sink.write_line(line)
            if '\ufffd' in line:
                stats['replaced'] += 1

            try:
                rtype, rule = self._resolver.resolve(line)
            except Exception:
                stats['errors'] += 1
                continue

            if not rtype:
                if not self._is_comment(line):
                    stats['skipped'] += 1
                continue

            target = self._map_lite_rtype(rtype) if is_lite else rtype
            if not target:
                continue
            staged.setdefault(target, set()).add(rule)
            stats['added'] += 1

        return staged, stats

    def _merge_staged(self, staged: dict[str, set[str]]) -> int:
        """把暂存的规则并入规则集合，返回并入的规则条数。"""
        merged = 0
        for rtype, rules in staged.items():
            for rule in rules:
                self._store.add_rule(rtype, rule)
            merged += len(rules)
        return merged

    @staticmethod
    def _log_stats(url: str, stats: dict[str, int]) -> None:
        logger.info("处理完成: 解析出 %d 条规则，跳过 %d 行非规则内容",
                    stats['added'], stats['skipped'])
        if stats['replaced']:
            logger.warning("⚠ %s 含 %d 行非 UTF-8 字符，已按替换字符处理", url, stats['replaced'])
        if stats['errors']:
            logger.warning("⚠ %d 行解析异常", stats['errors'])

    def _fallback_to_cache(self, url: str, is_lite: bool, reason: str) -> None:
        """拉取失败后的容错处理：优先用最近一次成功缓存，否则跳过并记录原因。"""
        meta = self._cache.entry(url)
        if meta is None:
            self._record(url, self.STATUS_SKIPPED, reason=f"{reason}；无可用缓存")
            logger.warning("跳过规则源 %s（%s，且无可用缓存）", url, reason)
            return

        staged, stats = self._ingest_lines(self._cache.read_lines(url), is_lite)
        merged = self._merge_staged(staged)
        cached_at = meta.get('fetched_at', '未知时间')
        self._record(url, self.STATUS_CACHE, rules=merged, reason=reason, cached_at=cached_at)
        logger.warning("回退缓存: %s（拉取失败: %s；使用 %s 的缓存，%d 条）",
                       url, reason, cached_at, merged)
        self._log_stats(url, stats)

    def _process_single_source(self, session: requests.Session, url: str,
                                is_host_source: bool, is_lite: bool, index: int,
                                total: int) -> None:
        """拉取并处理单个远程源；失败时回退缓存或跳过，不中断构建。"""
        logger.info("[%d/%d] 获取: %s%s", index, total, url,
                    ' [Lite]' if is_lite else '')
        timeout = 30 if is_host_source else 10
        problem = ''

        try:
            with session.get(url, timeout=timeout, stream=True) as response:
                if response.status_code != 200:
                    problem = f"HTTP {response.status_code}"
                else:
                    # 边解析边把原始内容写入缓存；只有完整读完才提交
                    with self._cache.writer(url) as sink:
                        staged, stats = self._ingest_lines(self._stream_lines(response), is_lite, sink)
                        merged = self._merge_staged(staged)
                        sink.commit(merged)
                    self._record(url, self.STATUS_OK, rules=merged)
                    self._log_stats(url, stats)
                    logger.info("当前规则数量: %s", self._store.get_status_str())
                    return
        except SourceTooLarge as e:
            problem = str(e)
        except requests.RequestException as e:
            problem = f"网络异常: {e}"
        except Exception as e:
            logger.error("获取 %s 时出错: %s", url, e, exc_info=True)
            problem = f"处理异常: {e}"

        logger.error("规则源异常: %s — %s", url, problem)
        self._fallback_to_cache(url, is_lite, problem)
        logger.info("当前规则数量: %s", self._store.get_status_str())

    def read_remote_rules(self) -> None:
        """读取远程订阅源（含完整版和 Lite 精简版）。"""
        logger.info("读取远程订阅源...")

        # 读取四个来源文件
        adguard_urls = self._sources_reader.read_adguard_sources()
        host_urls = self._sources_reader.read_host_sources()
        adguard_lite_urls = self._sources_reader.read_adguard_lite_sources()
        host_lite_urls = self._sources_reader.read_host_lite_sources()

        # 构建处理列表：每个元素为 (url, is_host_source, is_lite)
        processed = (
            [(url, False, False) for url in adguard_urls]
            + [(url, True, False) for url in host_urls]
            + [(url, False, True) for url in adguard_lite_urls]
            + [(url, True, True) for url in host_lite_urls]
        )

        total = len(processed)
        if total == 0:
            logger.warning("没有配置远程订阅源")
            return

        logger.info(
            "共有 %d 个远程规则源（完整版 AdGuard: %d, Hosts: %d | Lite: AdGuard: %d, Hosts: %d）",
            total, len(adguard_urls), len(host_urls),
            len(adguard_lite_urls), len(host_lite_urls),
        )

        self.source_status.clear()

        # 构建带重试的 Session
        session = requests.Session()
        retries = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount('https://', adapter)
        session.mount('http://', adapter)

        try:
            for i, (url, is_host_source, is_lite) in enumerate(processed, 1):
                self._process_single_source(session, url, is_host_source, is_lite, i, total)
        finally:
            session.close()
            self._log_summary()

    def _log_summary(self) -> None:
        """按状态汇总每个源的处理结果（正常 / 缓存回退 / 跳过）。"""
        ok = [s for s in self.source_status if s['status'] == self.STATUS_OK]
        cached = [s for s in self.source_status if s['status'] == self.STATUS_CACHE]
        skipped = [s for s in self.source_status if s['status'] == self.STATUS_SKIPPED]

        logger.info("远程源汇总: 正常 %d 个 / 缓存回退 %d 个 / 跳过 %d 个",
                    len(ok), len(cached), len(skipped))

        for s in cached:
            logger.warning("  [缓存回退] %s（原因: %s；%d 条；缓存于 %s）",
                           s['url'], s['reason'], s['rules'], s['cached_at'])
        for s in skipped:
            logger.error("  [跳过] %s（原因: %s）", s['url'], s['reason'])

        if cached or skipped:
            logger.warning("以上 %d 个源未使用最新上游内容，产物会缺少对应规则（已记录，非静默忽略）",
                           len(cached) + len(skipped))