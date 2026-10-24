"""规则获取模块 — 负责本地规则文件读取与远程规则订阅拉取"""

import logging
import re
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

from .rule_store import RuleStore
from .rule_resolver import RuleResolver
from .sources_reader import SourcesReader
from .config import PathConfig

logger = logging.getLogger(__name__)


class RuleFetcher:
    """规则获取器

    依赖精简后：
      - SourcesReader  读取两个规则源文件（AdGuard / Hosts）
      - RuleResolver   规则解析
      - RuleStore      规则存储
      - PathConfig     路径配置
    """

    # 单个远程源的响应体上限（按解压后的字节数累计），作为异常响应的安全阀；
    # 解析按行流式进行，不把整个响应体驻留内存。
    # 取 100MB 与 GitHub「仓库单文件 100MB」的限制对齐：托管在 GitHub 的源不会更大。
    # 目前最大的源是 blocklistproject 的 malware-ags.txt（约 56MB / 265 万条）。
    # 超过该上限的源会被标记并让整次运行失败，不会静默丢弃。
    DEFAULT_MAX_RESPONSE_SIZE = 100 * 1024 * 1024  # 100 MB
    _CHUNK_SIZE = 8192

    # 匹配合法域名（与 RuleResolver 保持一致）
    _DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    )

    def __init__(self,
                 sources_reader: SourcesReader,
                 resolver: RuleResolver,
                 rule_store: RuleStore,
                 path_config: PathConfig | None = None,
                 max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE):
        """
        :param sources_reader:    规则源读取器
        :param resolver:          规则解析器
        :param rule_store:        规则存储容器
        :param path_config:       路径配置
        :param max_response_size: 单源响应体上限（字节），超出视为异常并计入失败
        """
        self._sources_reader = sources_reader
        self._resolver = resolver
        self._store = rule_store
        self._path_config = path_config or PathConfig()
        self._max_response_size = max_response_size

        # 远程源拉取统计（供外部查询）
        self.fetch_stats: dict[str, int] = {
            'success': 0,
            'failed': 0,
            'truncated': 0,
        }

        # 本次运行中未能完整拉取的源（url, 原因），供完整性检查使用
        self.problem_sources: list[tuple[str, str]] = []

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

    def _mark_problem(self, url: str, reason: str, *, truncated: bool = False) -> None:
        """记录未能完整拉取的规则源。"""
        self.fetch_stats['truncated' if truncated else 'failed'] += 1
        self.problem_sources.append((url, reason))
        logger.error("规则源异常: %s — %s", url, reason)

    # ------------------------------------------------------------------
    # 远程规则
    # ------------------------------------------------------------------

    def _process_single_source(self, session: requests.Session, url: str,
                                is_host_source: bool, is_lite: bool, index: int,
                                total: int) -> None:
        """拉取并处理单个远程源的内容（逐行流式解析，不在内存中缓存响应体）。

        :param session:        requests Session
        :param url:            远程源 URL
        :param is_host_source: 是否为 Hosts 类型源（影响超时）
        :param is_lite:        是否为 Lite 精简版源
        :param index:          当前序号（日志用）
        :param total:          总数（日志用）
        """
        try:
            logger.info("[%d/%d] 获取: %s%s", index, total, url,
                        ' [Lite]' if is_lite else '')
            timeout = 30 if is_host_source else 10

            with session.get(url, timeout=timeout, stream=True) as response:
                if response.status_code != 200:
                    self._mark_problem(url, f"HTTP {response.status_code}")
                    return

                added = 0
                skipped = 0
                replaced = 0
                error_count = 0
                total_size = 0

                for raw_line in response.iter_lines(chunk_size=self._CHUNK_SIZE):
                    if not raw_line:
                        continue

                    total_size += len(raw_line) + 1
                    if total_size > self._max_response_size:
                        self._mark_problem(
                            url,
                            f"响应体超过 {self._max_response_size // (1024 * 1024)}MB 上限",
                            truncated=True,
                        )
                        return

                    line = raw_line.decode('utf-8', errors='replace')
                    if '\ufffd' in line:
                        replaced += 1

                    try:
                        rtype, rule = self._resolver.resolve(line)
                    except Exception:
                        error_count += 1
                        continue

                    if rtype:
                        added += 1
                        if is_lite:
                            target = self._map_lite_rtype(rtype)
                            if target:
                                self._store.add_rule(target, rule)
                        else:
                            self._store.add_rule(rtype, rule)
                    elif not self._is_comment(line):
                        skipped += 1

                self.fetch_stats['success'] += 1
                logger.info("处理完成: 解析出 %d 条规则，跳过 %d 行非规则内容", added, skipped)
                if replaced:
                    logger.warning("⚠ %s 含 %d 行非 UTF-8 字符，已按替换字符处理", url, replaced)
                if error_count:
                    logger.warning("⚠ %d 行解析失败", error_count)

        except requests.RequestException as e:
            self._mark_problem(url, f"网络异常: {e}")
        except Exception as e:
            logger.error("获取 %s 时出错: %s", url, e, exc_info=True)
            self._mark_problem(url, f"处理异常: {e}")

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

        self.fetch_stats.update(success=0, failed=0, truncated=0)
        self.problem_sources.clear()

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
            # 汇总远程源拉取结果
            logger.info(
                "远程源拉取汇总: 成功 %d, 失败 %d, 截断 %d",
                self.fetch_stats['success'],
                self.fetch_stats['failed'],
                self.fetch_stats['truncated'],
            )
            if self.problem_sources:
                logger.error("以下规则源未能完整拉取（本次产出会缺少对应规则）:")
                for url, reason in self.problem_sources:
                    logger.error("  - %s （%s）", url, reason)