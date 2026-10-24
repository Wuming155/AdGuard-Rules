"""文件处理器 — 外观（Facade），聚合规则写出与统计更新两个子模块"""

from .rule_writer import RuleWriter
from .stats_updater import StatsUpdater
from .config import Config


class FileHandler:
    """文件处理器（外观模式）"""

    def __init__(self, config: Config = None):
        cfg = config or Config()

        self.config = cfg
        self._rule_writer = RuleWriter(cfg.path.dist_dir, cfg.github_repo)
        self._stats_updater = StatsUpdater(cfg.path.readme_path, cfg.github_repo)

    # ------------------------------------------------------------------
    # 委托给 RuleWriter
    # ------------------------------------------------------------------

    def write_rules_file(self, file_name: str, rules: set[str], update_time: str) -> None:
        """写入规则文件。"""
        self._rule_writer.write_rules_file(file_name, rules, update_time)

    # ------------------------------------------------------------------
    # 委托给 StatsUpdater
    # ------------------------------------------------------------------

    def get_file_stats(self, folder_path: str,
                       exclude_files: set[str] | None = None) -> list[dict]:
        """扫描文件夹并统计每个文件的规则行数。"""
        return self._stats_updater.get_file_stats(folder_path, exclude_files)

    def update_readme(self, all_file_stats: list[dict]) -> None:
        """更新 README.md。"""
        self._stats_updater.update_readme(all_file_stats)
