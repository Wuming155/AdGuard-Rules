"""主执行器模块 — Pipeline/Step 模式编排，支持日志和依赖注入"""

import logging
import traceback
from abc import ABC, abstractmethod
from datetime import datetime

from .config import Config
from .rule_resolver import RuleResolver
from .rule_store import RuleStore
from .rule_fetcher import RuleFetcher
from .rule_processor import RuleProcessor
from .file_handler import FileHandler
from .sources_reader import SourcesReader

logger = logging.getLogger(__name__)


# ======================================================================
# Pipeline Step 抽象
# ======================================================================

class PipelineStep(ABC):
    """流水线步骤抽象基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """步骤名称（用于日志）。"""
        ...

    @abstractmethod
    def execute(self) -> None:
        """执行步骤逻辑。"""
        ...


# ======================================================================
# 具体步骤实现
# ======================================================================

class ReadLocalRulesStep(PipelineStep):
    """步骤 1：读取本地自定义规则"""

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "读取本地规则"

    def execute(self) -> None:
        self._fetcher.read_local_rules()


class ReadRemoteRulesStep(PipelineStep):
    """步骤 2：读取远程订阅源规则"""

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "读取远程规则"

    def execute(self) -> None:
        self._fetcher.read_remote_rules()


class ProcessAntiWhitelistStep(PipelineStep):
    """步骤 3：逆向白名单处理（读取 + 移除）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "逆向白名单处理"

    def execute(self) -> None:
        self._processor.read_anti_whitelist()
        self._processor.remove_anti_whitelist_rules()


class PrintSummaryStep(PipelineStep):
    """步骤 4：打印规则概况"""

    def __init__(self, rule_store: RuleStore):
        self._store = rule_store

    @property
    def name(self) -> str:
        return "规则概况输出"

    def execute(self) -> None:
        self._store.print_summary()


class RemoveWhitelistFromHostsStep(PipelineStep):
    """步骤 5：从 Hosts 规则中移除白名单域名（必须在 mihomo 生成前）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Hosts 白名单清洗"

    def execute(self) -> None:
        self._processor.remove_whitelist_from_hosts()


class RemoveWhitelistFromAdguardStep(PipelineStep):
    """步骤 6：从 AdGuard 规则中移除白名单域名"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "AdGuard 白名单清洗"

    def execute(self) -> None:
        self._processor.remove_whitelist_from_adguard()


class GenerateMihomoRulesStep(PipelineStep):
    """步骤 7：生成 mihomo 规则"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "生成 Mihomo 规则"

    def execute(self) -> None:
        self._processor.generate_mihomo_rules()


class GenerateDedupHostsStep(PipelineStep):
    """步骤 8：生成去重 Hosts 规则（去掉 AdGuard 已覆盖的域名）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Hosts 规则去重"

    def execute(self) -> None:
        self._processor.generate_dedup_hosts_rules()


class WriteRulesStep(PipelineStep):
    """步骤 9：将规则集合写入文件"""

    def __init__(self, file_handler: FileHandler, rule_store: RuleStore):
        self._fh = file_handler
        self._store = rule_store

    @property
    def name(self) -> str:
        return "写入规则文件"

    def execute(self) -> None:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # 遍历规则集合写入文件
        for rtype in RuleStore.ALL_RULE_TYPES:
            rules = self._store.get_collection(rtype)
            self._fh.write_rules_file(rtype, set(rules), update_time)

        # 去重版 Hosts 规则单独写出
        dedup = self._store.get_collection(RuleStore.R_TYPE_HOSTS_DEDUP)
        self._fh.write_rules_file(RuleStore.R_TYPE_HOSTS_DEDUP, set(dedup), update_time)

        # mihomo 规则单独写出
        self._fh.write_rules_file('reject_domains', self._store.mihomo_rules, update_time)


class UpdateStatsStep(PipelineStep):
    """步骤 10：更新 README 统计"""

    def __init__(self, file_handler: FileHandler, config: Config):
        self._fh = file_handler
        self._config = config

    @property
    def name(self) -> str:
        return "更新 README 统计"

    def execute(self) -> None:
        all_stats = (
            self._fh.get_file_stats(
                self._config.custom_rules_dir,
                exclude_files=self._config.custom_exclude_files,
            )
            + self._fh.get_file_stats(self._config.dist_dir)
        )
        # 过滤掉不需要展示的文件（白名单已内嵌到规则中，不单独列出）
        all_stats = [s for s in all_stats if s['name'] not in ('whitelist.txt',)]
        self._fh.update_readme(all_stats)


# ======================================================================
# 主执行器
# ======================================================================

class MainExecutor:
    """主执行器（Pipeline 流水线调度器）

    将所有步骤组织为 Pipeline，执行顺序由 steps 列表显式定义，
    增加/删除/重排步骤只需修改 _build_steps() 方法。
    """

    def __init__(self, config: Config | None = None,
                 resolver: RuleResolver | None = None,
                 file_handler: FileHandler | None = None,
                 rule_store: RuleStore | None = None,
                 rule_fetcher: RuleFetcher | None = None,
                 rule_processor: RuleProcessor | None = None):
        """初始化主执行器，全部支持依赖注入。"""
        self.config = config or Config()

        self.resolver = resolver or RuleResolver(self.config.rule)
        self.file_handler = file_handler or FileHandler(self.config)
        self.rule_store = rule_store or RuleStore()

        sources_reader = SourcesReader(
            adguard_file=self.config.path.sources_adguard_file,
            host_file=self.config.path.sources_host_file,
        )

        self.rule_fetcher = rule_fetcher or RuleFetcher(
            sources_reader=sources_reader,
            resolver=self.resolver,
            rule_store=self.rule_store,
            path_config=self.config.path,
        )

        self.rule_processor = rule_processor or RuleProcessor(
            rule_store=self.rule_store,
            path_config=self.config.path,
        )

    # ------------------------------------------------------------------
    # 流水线构建
    # ------------------------------------------------------------------

    def _build_pipeline(self) -> list[PipelineStep]:
        """构建流水线步骤列表。

        步骤顺序在此显式定义，有严格先后依赖的步骤由注释标明。
        如需增加新步骤，只需向列表对应位置插入即可。
        """
        return [
            ReadLocalRulesStep(self.rule_fetcher),
            ReadRemoteRulesStep(self.rule_fetcher),

            # 逆向白名单必须在规则全部加载后、写入前执行
            ProcessAntiWhitelistStep(self.rule_processor),

            PrintSummaryStep(self.rule_store),

            # 白名单清洗必须在 mihomo 和去重生成前执行
            RemoveWhitelistFromHostsStep(self.rule_processor),
            RemoveWhitelistFromAdguardStep(self.rule_processor),
            GenerateMihomoRulesStep(self.rule_processor),

            # Hosts 去重必须在白名单清洗和 mihomo 生成之后、写入之前
            GenerateDedupHostsStep(self.rule_processor),

            WriteRulesStep(self.file_handler, self.rule_store),
            UpdateStatsStep(self.file_handler, self.config),
        ]

    # ------------------------------------------------------------------
    # 执行入口
    # ------------------------------------------------------------------

    def run(self) -> None:
        """按 Pipeline 编排执行完整规则同步流程。"""
        try:
            logger.info("=" * 50)
            logger.info("开始执行规则同步...")
            logger.info("=" * 50)

            pipeline = self._build_pipeline()

            for i, step in enumerate(pipeline, 1):
                logger.info("[步骤 %d/%d] %s", i, len(pipeline), step.name)
                step.execute()
                logger.info(
                    "[步骤 %d/%d] %s 完成 — 当前: %s",
                    i, len(pipeline), step.name, self.rule_store.get_status_str(),
                )

            logger.info("=" * 50)
            logger.info("规则同步完成！总计: %s", self.rule_store.get_status_str())
            logger.info("=" * 50)

        except Exception:
            logger.critical("执行过程中出错: %s", traceback.format_exc())
