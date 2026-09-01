"""规则文件写出器 — 仅负责将规则集合写入 dist/ 目录"""

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class RuleWriter:
    """规则文件写出器"""

    def __init__(self, dist_dir: str = 'dist', github_repo: str = 'Wuming155/AdGuard-Rules'):
        """
        :param dist_dir:   输出目录
        :param github_repo: GitHub 仓库名（用于文件头 Homepage 链接）
        """
        self._dist_dir = Path(dist_dir)
        self._github_repo = github_repo

    def write_rules_file(self, file_name: str, rules: set[str] | frozenset[str],
                         update_time: str) -> None:
        """将规则集合写入文件。

        :param file_name:   输出文件名（不含 .txt 扩展名）
        :param rules:       规则集合
        :param update_time: 更新时间字符串（格式 YYYY-MM-DD HH:MM:SS）
        """
        self._dist_dir.mkdir(exist_ok=True)

        sorted_rules = sorted(rules)

        # Hosts 文件使用 # 注释，其他用 ! 注释
        comment_char = '#' if file_name.startswith('hosts_') else '!'

        display_name = file_name.replace('_', ' ').title().replace('Adguard', 'AdGuard')

        header = [
            f"{comment_char} Title: {display_name}",
            f"{comment_char} Homepage: https://github.com/{self._github_repo}",
            f"{comment_char} Total Rules: {len(sorted_rules)}",
            f"{comment_char} Last Update: {update_time}",
            f"{comment_char}",
        ]

        header.append(f"{comment_char}\n")

        file_content = "\n".join(header) + "\n" + "\n".join(sorted_rules) + "\n"

        file_path = self._dist_dir / f"{file_name}.txt"
        try:
            file_path.write_text(file_content, encoding='utf-8')
            logger.info("已写入 %s.txt，共 %d 条规则", file_name, len(sorted_rules))
        except OSError as e:
            logger.error("写入 %s.txt 失败: %s", file_name, e)
