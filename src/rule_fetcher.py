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

    # 远程下载约束
    _MAX_RESPONSE_SIZE = 50 * 1024 * 1024  # 50 MB
    _CHUNK_SIZE = 8192

    # 匹配合法域名（与 RuleResolver 保持一致）
    _DOMAIN_PATTERN = re.compile(
        r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    )

    def __init__(self,
                 sources_reader: SourcesReader,
                 resolver: RuleResolver,
                 rule_store: RuleStore,
                 path_config: PathConfig | None = None):
        """
        :param sources_reader: 规则源读取器
        :param resolver:       规则解析器
        :param rule_store:     规则存储容器
        :param path_config:    路径配置
        """
        self._sources_reader = sources_reader
        self._resolver = resolver
        self._store = rule_store
        self._path_config = path_config or PathConfig()

        # 远程源拉取统计（供外部查询）
        self.fetch_stats: dict[str, int] = {
            'success': 0,
            'failed': 0,
            'truncated': 0,
        }

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
            if f.name == 'anti_whitelist.txt':
                continue  # 逆向白名单由 RuleProcessor 单独处理

            try:
                skipped = 0
                is_whitelist_file = (f.name == 'custom_whitelist.txt')
                with open(f, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        stripped = line.strip()

                        # 如果是白名单文件的纯域名行，自动包装为 @@||domain^ 格式
                        if is_whitelist_file and stripped and not stripped.startswith(('#', '!', '@', '/')):
                            if self._DOMAIN_PATTERN.match(stripped):
                                line = f'@@||{stripped}^'

                        rtype, rule = self._resolver.resolve(line)
                        if rtype:
                            self._store.add_rule(rtype, rule)
                        elif line.strip() and not line.strip().startswith(('!', '#', '/')):
                            skipped += 1

                if skipped:
                    logger.info("成功读取 %s，%d 行无法识别已跳过", f.name, skipped)
                else:
                    logger.info("成功读取 %s", f.name)

            except (OSError, UnicodeDecodeError) as e:
                logger.error("读取 %s 时出错: %s", f.name, e)

    # ------------------------------------------------------------------
    # 远程规则
    # ------------------------------------------------------------------

    def read_remote_rules(self) -> None:
        """读取远程订阅源。"""
        logger.info("读取远程订阅源...")

        # 直接从两个来源文件读取，无需关键词匹配
        adguard_urls = self._sources_reader.read_adguard_sources()
        host_urls = self._sources_reader.read_host_sources()

        total_urls = len(adguard_urls) + len(host_urls)
        if total_urls == 0:
            logger.warning("没有配置远程订阅源")
            return

        logger.info("共有 %d 个远程规则源（AdGuard: %d, Hosts: %d）",
                     total_urls, len(adguard_urls), len(host_urls))

        # 按类型分组：Hosts 源使用更长超时
        processed = [(url, False) for url in adguard_urls] + [(url, True) for url in host_urls]

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

        total = len(processed)
        try:
            for i, (url, is_host_source) in enumerate(processed, 1):
                try:
                    logger.info("[%d/%d] 获取: %s", i, total, url)
                    timeout = 30 if is_host_source else 10

                    with session.get(url, timeout=timeout, stream=True) as response:
                        if response.status_code != 200:
                            logger.warning("获取 %s 失败: HTTP %d", url, response.status_code)
                            self.fetch_stats['failed'] += 1
                            continue

                        # 流式读取 + 大小保护
                        content_chunks: list[bytes] = []
                        total_size = 0
                        exceeded = False

                        for chunk in response.iter_content(chunk_size=self._CHUNK_SIZE):
                            total_size += len(chunk)
                            if total_size > self._MAX_RESPONSE_SIZE:
                                logger.warning(
                                    "跳过 %s：响应体过大 (>%dMB)",
                                    url, self._MAX_RESPONSE_SIZE // (1024 * 1024),
                                )
                                self.fetch_stats['truncated'] += 1
                                exceeded = True
                                break
                            content_chunks.append(chunk)

                        if exceeded:
                            continue

                        raw_bytes = b''.join(content_chunks)

                        # 解码
                        try:
                            text = raw_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            text = raw_bytes.decode('utf-8', errors='replace')
                            logger.warning("警告: %s 包含非 UTF-8 字符，已替换处理", url)

                        lines = text.splitlines()
                        logger.info("成功获取 %s，共 %d 行", url, len(lines))

                        # 逐行解析
                        count = 0
                        error_count = 0
                        for line in lines:
                            try:
                                rtype, rule = self._resolver.resolve(line)
                                if rtype:
                                    count += 1
                                    self._store.add_rule(rtype, rule)
                            except Exception:
                                error_count += 1

                        self.fetch_stats['success'] += 1
                        logger.info("处理完成，共添加 %d 条规则", count)
                        if error_count:
                            logger.warning("⚠ %d 行解析失败", error_count)

                except requests.RequestException as e:
                    logger.error("获取 %s 时网络异常: %s", url, e)
                    self.fetch_stats['failed'] += 1
                except Exception as e:
                    logger.error("获取 %s 时出错: %s", url, e, exc_info=True)
                    self.fetch_stats['failed'] += 1

                logger.info("当前规则数量: %s", self._store.get_status_str())

        finally:
            session.close()
            # 汇总远程源拉取结果
            logger.info(
                "远程源拉取汇总: 成功 %d, 失败 %d, 截断 %d",
                self.fetch_stats['success'],
                self.fetch_stats['failed'],
                self.fetch_stats['truncated'],
            )
