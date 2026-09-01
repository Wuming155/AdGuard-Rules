"""README 统计更新器 — 负责文件规则行数统计和 README.md 表格更新"""

import re
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import quote

logger = logging.getLogger(__name__)


class StatsUpdater:
    """统计更新器"""

    # 规则文件说明映射（同时决定 README 表格的展示顺序，新增文件请在此登记）
    _RULE_DESCRIPTIONS = {
        'adguard_rules.txt': 'AdGuard DNS 格式完整规则集，适用于 AGHForRoot / AdGuard Home',
        'hosts_rules.txt': 'Hosts 格式，适用于 bindhosts 等 Magisk 模块',
        'hosts_rules_dedup.txt': '去重版，去掉 AdGuard 已覆盖域名，可搭配 adguard_rules.txt 使用',
        'adguard_lite.txt': 'AdGuard 格式精简版（仅广告过滤）',
        'hosts_lite.txt': 'Hosts 格式精简版（仅广告过滤）',
        'hosts_lite_dedup.txt': '去重版精简 Hosts，可搭配 adguard_lite.txt 使用',
        'whitelist.txt': '收录的白名单域名，按需导入即可放行',
    }

    def __init__(self, readme_path: str = 'README.md',
                 github_repo: str = 'Wuming155/AdGuard-Rules'):
        """
        :param readme_path: README.md 文件路径
        :param github_repo: GitHub 仓库名（用于生成 Release 附件下载链接）
        """
        self._readme_path = Path(readme_path)
        self._github_repo = github_repo

    @property
    def _download_base(self) -> str:
        """规则文件下载地址前缀。

        指向固定 Release 的永久链接，地址恒定不变，
        始终解析到最新一次上传的附件。
        """
        return f"https://github.com/{self._github_repo}/releases/latest/download"

    # ------------------------------------------------------------------
    # 文件统计
    # ------------------------------------------------------------------

    @staticmethod
    def get_file_stats(folder_path: str,
                       exclude_files: set[str] | frozenset[str] | None = None) -> list[dict]:
        """扫描文件夹并统计每个 .txt 文件的有效规则行数。

        :param folder_path:   目标文件夹路径
        :param exclude_files: 排除的文件名集合
        :returns: [{name, count, folder}, ...] 列表
        """
        exclude = set(exclude_files) if exclude_files else set()
        stats_list: list[dict] = []
        path = Path(folder_path)

        if not path.exists():
            logger.warning("文件夹不存在，跳过统计: %s", folder_path)
            return stats_list

        # sorted() 保证顺序稳定，避免 README 表格行序在每次运行时跳动
        for f in sorted(path.glob('*.txt')):
            if f.name in exclude:
                continue
            try:
                count = 0
                with open(f, 'r', encoding='utf-8') as fh:
                    for line in fh:
                        stripped = line.strip()
                        if stripped and not stripped.startswith(('!', '#')):
                            count += 1
                stats_list.append({
                    'name': f.name,
                    'count': count,
                    'folder': folder_path,
                })
            except (OSError, UnicodeDecodeError) as e:
                logger.warning("统计 %s 时出错: %s", f.name, e)

        return stats_list

    # ------------------------------------------------------------------
    # README 更新
    # ------------------------------------------------------------------

    @classmethod
    def _sort_stats(cls, all_file_stats: list[dict]) -> list[dict]:
        """按 _RULE_DESCRIPTIONS 登记顺序排序，未登记的文件排在最后（按名称）。

        :param all_file_stats: get_file_stats 返回的统计列表
        :returns: 排序后的新列表
        """
        order = list(cls._RULE_DESCRIPTIONS)

        def _key(item: dict) -> tuple[int, int | str]:
            try:
                return (0, order.index(item['name']))
            except ValueError:
                return (1, item['name'])

        return sorted(all_file_stats, key=_key)

    def update_readme(self, all_file_stats: list[dict]) -> None:
        """更新 README.md 中的规则统计表格和最后更新时间。

        :param all_file_stats: get_file_stats 返回的统计列表
        """
        if not self._readme_path.exists():
            logger.warning("README 文件不存在: %s", self._readme_path)
            return

        try:
            content = self._readme_path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError) as e:
            logger.error("读取 README 失败: %s", e)
            return

        download_base = self._download_base
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 构建表格（含说明列）
        table_header = "| 规则文件 | 说明 | 规则数量 | 下载链接 |\n| :--- | :--- | :--- | :--- |\n"
        table_rows = ""
        for item in self._sort_stats(all_file_stats):
            safe_name = quote(item['name'], safe='')
            desc = self._RULE_DESCRIPTIONS.get(item['name'], '')
            download_url = f"[点击下载]({download_base}/{safe_name})"
            table_rows += f"| {item['name']} | {desc} | {item['count']} | {download_url} |\n"

        table_content = f"{table_header}{table_rows}\n⏰ 最后更新: {now}\n"

        # 匹配 "## 规则统计" 或 "## 一、规则统计" 等变体（行首锚定，避免误匹配表格内容）
        pattern = r"^(##\s*.*规则统计[\s\S]*?)(?=^##\s|\Z)"

        match = re.search(pattern, content, flags=re.MULTILINE)
        try:
            if match:
                original_title_line = match.group(1).splitlines()[0]
                new_section = f"{original_title_line}\n\n{table_content}\n"
                # 用 lambda 传入替换文本，避免内容中的反斜杠被当作正则替换模板解析
                new_content = re.sub(pattern, lambda _m: new_section,
                                     content, count=1, flags=re.MULTILINE)
                self._readme_path.write_text(new_content, encoding='utf-8')
                logger.info("README 统计已更新，时间: %s", now)
            else:
                section = f"\n## 规则统计\n\n{table_content}\n"
                new_content = content + section
                self._readme_path.write_text(new_content, encoding='utf-8')
                logger.info("README 中未找到'规则统计'章节，已在末尾自动添加。时间: %s", now)
        except OSError as e:
            logger.error("写入 README 失败: %s", e)

    # ------------------------------------------------------------------
    # 白名单规则展示
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_whitelist_domain(rule: str) -> str | None:
        """从白名单规则（如 @@||domain^）中提取纯小写域名。"""
        s = rule.strip()
        if s.startswith('@@'):
            s = s[2:]
        if s.startswith('||'):
            s = s[2:]
        for ch in ('^', '$', '/', '#'):
            idx = s.find(ch)
            if idx != -1:
                s = s[:idx]
        s = s.lstrip('*').lstrip('.')
        if '.' in s and ' ' not in s:
            return s.lower()
        return None

    def update_whitelist_in_readme(self, whitelist_rules: set[str] | frozenset[str]) -> None:
        """更新 README『白名单规则』章节：一张统计表格 + 可折叠的域名列表。

        与『规则统计』章节保持同一风格，不展开分类与说明文字。
        """
        if not self._readme_path.exists():
            logger.warning("README 文件不存在: %s", self._readme_path)
            return

        domains = sorted({
            d for d in (self._extract_whitelist_domain(r) for r in whitelist_rules) if d
        })
        if not domains:
            logger.warning("白名单为空，跳过更新 README")
            return

        total = len(domains)
        desc = self._RULE_DESCRIPTIONS.get('whitelist.txt', '')
        lines: list[str] = [
            "| 规则文件 | 说明 | 规则数量 | 下载链接 |",
            "| :--- | :--- | :--- | :--- |",
            f"| whitelist.txt | {desc} | {total} | "
            f"[点击下载]({self._download_base}/whitelist.txt) |",
            "",
            "<details>",
            f"<summary>展开查看全部 {total} 条白名单域名</summary>",
            "",
        ]
        lines.extend(f"- `{d}`" for d in domains)
        lines.extend(["", "</details>"])
        section_body = "\n".join(lines)

        try:
            content = self._readme_path.read_text(encoding='utf-8')
        except (OSError, UnicodeDecodeError) as e:
            logger.error("读取 README 失败: %s", e)
            return

        pattern = r"^(##\s*.*白名单规则[\s\S]*?)(?=^##\s|\Z)"
        match = re.search(pattern, content, flags=re.MULTILINE)
        try:
            if match:
                title_line = match.group(1).splitlines()[0]
                new_section = f"{title_line}\n\n{section_body}\n"
                new_content = re.sub(pattern, lambda _m: new_section,
                                     content, count=1, flags=re.MULTILINE)
                logger.info("README 白名单章节已更新，共 %d 条", total)
            else:
                new_content = content.rstrip() + f"\n\n## 白名单规则\n\n{section_body}\n"
                logger.info("README 中未找到'白名单规则'章节，已在末尾自动添加，共 %d 条", total)
            self._readme_path.write_text(new_content, encoding='utf-8')
        except OSError as e:
            logger.error("写入 README 失败: %s", e)
