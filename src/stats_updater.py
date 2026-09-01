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
    }

    def __init__(self, readme_path: str = 'README.md',
                 github_repo: str = 'Wuming155/AdGuard-Rules',
                 whitelist_path: str = 'custom-rules/custom_whitelist.txt'):
        """
        :param readme_path:    README.md 文件路径
        :param github_repo:    GitHub 仓库名（用于生成 Release 附件下载链接）
        :param whitelist_path: 自定义白名单源文件路径（用于展示到 README）
        """
        self._readme_path = Path(readme_path)
        self._github_repo = github_repo
        self._whitelist_path = Path(whitelist_path)

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
    def _is_separator_line(stripped: str) -> bool:
        """判断是否为分类分隔行（形如 '# ====...'）。"""
        body = stripped.lstrip('#').strip()
        return body != '' and set(body) <= {'='}

    @classmethod
    def parse_whitelist(cls, raw_text: str) -> tuple[list[dict], int]:
        """解析自定义白名单源文件，按大分类/小分类归类域名。

        :param raw_text: custom_whitelist.txt 的文本内容
        :returns: (categories, total)
            categories = [{'name': 大分类, 'subcats': [{'name': 小分类, 'rules': [(domain, desc)]}]}]
            total = 有效域名规则总数
        """
        categories: list[dict] = []
        current_cat: dict | None = None
        current_sub: dict | None = None
        pending_desc: str | None = None
        total = 0
        separator_open = False

        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # 分类分隔行（# =====），切换分隔块状态
            if cls._is_separator_line(stripped):
                separator_open = not separator_open
                pending_desc = None
                continue

            # 分隔块内的标题行即大分类名
            if separator_open:
                if stripped.startswith('#'):
                    title = stripped.lstrip('#').strip()
                    if title:
                        current_cat = {'name': title, 'subcats': []}
                        categories.append(current_cat)
                        current_sub = None
                continue

            # 普通注释行
            if stripped.startswith('#'):
                m = re.match(r'^#\s*-{3,}\s*(.+?)\s*-{3,}\s*$', stripped)
                if m:
                    if current_cat is None:
                        current_cat = {'name': '其他', 'subcats': []}
                        categories.append(current_cat)
                    current_sub = {'name': m.group(1).strip(), 'rules': []}
                    current_cat['subcats'].append(current_sub)
                else:
                    # 普通说明行，关联到紧随其后的域名
                    pending_desc = stripped.lstrip('#').strip()
                continue

            # 域名行（不以 # 开头）
            domain = stripped
            desc = pending_desc
            pending_desc = None

            # 兼顾行尾注释形式：example.com # 说明
            if not desc and ' #' in domain:
                domain, _, tail = domain.partition(' #')
                domain = domain.strip()
                desc = tail.strip() or None

            if not domain:
                continue

            if current_cat is None:
                current_cat = {'name': '白名单', 'subcats': []}
                categories.append(current_cat)
            if current_sub is None:
                current_sub = {'name': '', 'rules': []}
                current_cat['subcats'].append(current_sub)

            current_sub['rules'].append((domain, desc))
            total += 1

        return categories, total

    def build_whitelist_section(self, categories: list[dict], total: int) -> str:
        """根据解析结果生成白名单章节正文（不含 '## 白名单规则' 标题）。

        :param categories: parse_whitelist 返回的 categories
        :param total:      有效域名总数
        :returns: Markdown 正文字符串
        """
        whitelist_url = f"{self._download_base}/whitelist.txt"
        lines: list[str] = []
        lines.append(
            f"> 当前收录白名单 **{total}** 条域名（含自定义与远程订阅源提取），"
            f"已单独整理为 [whitelist.txt]({whitelist_url})，"
            f"可按需导入以放行下列域名。"
        )
        lines.append("")

        for cat in categories:
            lines.append(f"### {cat['name']}")
            lines.append("")
            for sub in cat['subcats']:
                if sub['name']:
                    lines.append(f"**{sub['name']}**")
                    lines.append("")
                for domain, desc in sub['rules']:
                    if desc:
                        lines.append(f"- `{domain}` — {desc}")
                    else:
                        lines.append(f"- `{domain}`")
                if sub['rules']:
                    lines.append("")

        # 清理尾部多余空行
        while lines and lines[-1] == '':
            lines.pop()

        return "\n".join(lines)

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
        """根据运行时生效的白名单集合更新 README『白名单规则』章节。

        自定义白名单（custom_whitelist.txt）提供分类框架与中文说明；
        其余来自远程订阅源的白名单归入『🌐 远程订阅源提取』分组。
        """
        if not self._readme_path.exists():
            logger.warning("README 文件不存在: %s", self._readme_path)
            return

        # 1. 解析自定义白名单分类框架（带中文说明）
        custom_categories: list[dict] = []
        custom_domains: set[str] = set()
        if self._whitelist_path.exists():
            try:
                raw = self._whitelist_path.read_text(encoding='utf-8')
                custom_categories, _ = self.parse_whitelist(raw)
                for cat in custom_categories:
                    for sub in cat['subcats']:
                        for domain, _desc in sub['rules']:
                            custom_domains.add(domain.lower())
            except (OSError, UnicodeDecodeError) as e:
                logger.error("读取白名单源文件失败: %s", e)

        # 2. 将运行时白名单拆分为『自定义』与『远程提取』
        remote_domains: list[str] = []
        for rule in whitelist_rules:
            domain = self._extract_whitelist_domain(rule)
            if domain is None:
                continue
            if domain not in custom_domains:
                remote_domains.append(domain)
        remote_domains = sorted(set(remote_domains))

        # 3. 组装最终分类结构
        final_categories = list(custom_categories)
        if remote_domains:
            final_categories.append({
                'name': '🌐 远程订阅源提取',
                'subcats': [{'name': '', 'rules': [(d, None) for d in remote_domains]}],
            })

        total = sum(len(sub['rules']) for cat in final_categories for sub in cat['subcats'])
        if total == 0:
            logger.warning("白名单为空，跳过更新 README")
            return

        section_body = self.build_whitelist_section(final_categories, total)

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
                logger.info(
                    "README 白名单章节已更新，共 %d 条（含远程提取 %d 条）",
                    total, len(remote_domains),
                )
            else:
                new_content = content.rstrip() + f"\n\n## 白名单规则\n\n{section_body}\n"
                logger.info("README 中未找到'白名单规则'章节，已在末尾自动添加，共 %d 条", total)
            self._readme_path.write_text(new_content, encoding='utf-8')
        except OSError as e:
            logger.error("写入 README 失败: %s", e)
