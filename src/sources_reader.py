"""规则源读取器 — 读取两个分开的规则源文件（AdGuard / Hosts）"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class SourcesReader:
    """规则源读取器

    支持两个独立的规则源文件：
      - AdGuard 源文件（sources_adguard.txt）
      - Hosts 源文件（sources_host.txt）
    分别读取后用于不同的超时策略。
    """

    def __init__(self, adguard_file: str = 'sources_adguard.txt',
                 host_file: str = 'sources_host.txt',
                 adguard_lite_file: str = 'sources_adguard_lite.txt',
                 host_lite_file: str = 'sources_host_lite.txt'):
        """
        :param adguard_file:      AdGuard 格式规则源文件路径（完整版）
        :param host_file:         Hosts 格式规则源文件路径（完整版）
        :param adguard_lite_file: AdGuard 格式规则源文件路径（精简版）
        :param host_lite_file:    Hosts 格式规则源文件路径（精简版）
        """
        self._adguard_file = Path(adguard_file)
        self._host_file = Path(host_file)
        self._adguard_lite_file = Path(adguard_lite_file)
        self._host_lite_file = Path(host_lite_file)

    @property
    def adguard_sources_path(self) -> Path:
        """AdGuard 规则源文件路径（只读）。"""
        return self._adguard_file

    @property
    def host_sources_path(self) -> Path:
        """Hosts 规则源文件路径（只读）。"""
        return self._host_file

    @property
    def adguard_lite_sources_path(self) -> Path:
        """AdGuard Lite 规则源文件路径（只读）。"""
        return self._adguard_lite_file

    @property
    def host_lite_sources_path(self) -> Path:
        """Hosts Lite 规则源文件路径（只读）。"""
        return self._host_lite_file

    def _read_file(self, file_path: Path, label: str) -> list[str]:
        """从单个文件读取 URL 列表。

        :param file_path: 文件路径
        :param label:     日志标签（如 'AdGuard' / 'Hosts'）
        :returns: URL 列表，文件不存在或出错时返回空列表
        """
        if not file_path.exists():
            logger.warning("%s 规则源文件不存在: %s", label, file_path)
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                urls = [
                    line.strip() for line in f
                    if line.strip().startswith(('http://', 'https://'))
                ]
            logger.info("从 %s 读取到 %d 个 %s 源", file_path, len(urls), label)
            return urls
        except OSError as e:
            logger.error("读取规则源文件失败: %s — %s", file_path, e)
            return []

    def read_adguard_sources(self) -> list[str]:
        """读取 AdGuard 格式规则源 URL 列表。"""
        return self._read_file(self._adguard_file, 'AdGuard')

    def read_host_sources(self) -> list[str]:
        """读取 Hosts 格式规则源 URL 列表。"""
        return self._read_file(self._host_file, 'Hosts')

    def read_adguard_lite_sources(self) -> list[str]:
        """读取 AdGuard Lite 格式规则源 URL 列表。"""
        return self._read_file(self._adguard_lite_file, 'AdGuard Lite')

    def read_host_lite_sources(self) -> list[str]:
        """读取 Hosts Lite 格式规则源 URL 列表。"""
        return self._read_file(self._host_lite_file, 'Hosts Lite')

    def read_sources(self) -> list[str]:
        """读取所有远程规则源 URL 列表（合并两个文件，向后兼容）。

        :returns: 合并后的 URL 列表
        """
        return self.read_adguard_sources() + self.read_host_sources()
