"""China AdGuard Rules 模块 — 公开接口"""

from .config import Config, PathConfig, RuleConfig
from .rule_resolver import RuleResolver
from .rule_store import RuleStore
from .rule_fetcher import RuleFetcher
from .rule_processor import RuleProcessor
from .file_handler import FileHandler
from .sources_reader import SourcesReader
from .rule_writer import RuleWriter
from .stats_updater import StatsUpdater
from .main import MainExecutor

__all__ = [
    # 配置
    'Config', 'PathConfig', 'RuleConfig',
    # 核心
    'RuleResolver',
    'RuleStore',
    'RuleFetcher',
    'RuleProcessor',
    # 文件相关（外观 + 子模块）
    'FileHandler',
    'SourcesReader',
    'RuleWriter',
    'StatsUpdater',
    # 主执行器
    'MainExecutor',
]
