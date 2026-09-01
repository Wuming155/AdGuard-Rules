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


class PrintSummaryStep(PipelineStep):
    """步骤 3：打印规则概况"""

    def __init__(self, rule_store: RuleStore):
        self._store = rule_store

    @property
    def name(self) -> str:
        return "规则概况输出"

    def execute(self) -> None:
        self._store.print_summary()


class GenerateDedupHostsStep(PipelineStep):
    """步骤 4：生成去重 Hosts 规则（去掉 AdGuard 已覆盖的域名）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Hosts 规则去重"

    def execute(self) -> None:
        self._processor.generate_dedup_hosts_rules()


class GenerateDedupHostsLiteStep(PipelineStep):
    """步骤 5：生成去重 Lite Hosts 规则（去掉 Lite AdGuard 已覆盖的域名）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Lite Hosts 规则去重"

    def execute(self) -> None:
        self._processor.generate_dedup_hosts_lite_rules()


class WriteRulesStep(PipelineStep):
    """步骤 6：将规则集合写入文件"""

    def __init__(self, file_handler: FileHandler, rule_store: RuleStore):
        self._fh = file_handler
        self._store = rule_store

    @property
    def name(self) -> str:
        return "写入规则文件"

    def execute(self) -> None:
        update_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        for rtype in RuleStore.OUTPUT_RULE_TYPES:
            rules = self._store.get_collection(rtype)
            self._fh.write_rules_file(rtype, rules, update_time)


class UpdateStatsStep(PipelineStep):
    """步骤 7：更新 README 统计"""

    def __init__(self, file_handler: FileHandler, config: Config, rule_store: RuleStore):
        self._fh = file_handler
        self._config = config
        self._store = rule_store

    @property
    def name(self) -> str:
        return "更新 README 统计"

    def execute(self) -> None:
        all_stats = self._fh.get_file_stats(self._config.dist_dir)

        # 只统计本次实际产出的文件，避免 dist/ 中的历史残留混入表格。
        # whitelist.txt 已在独立章节展示，不重复列入统计表格。
        expected_names = {
            f"{rtype}.txt"
            for rtype in RuleStore.OUTPUT_RULE_TYPES
            if rtype != RuleStore.R_TYPE_WHITELIST
        }
        all_stats = [s for s in all_stats if s['name'] in expected_names]

        self._fh.update_readme(all_stats)
        # 将生效白名单规则（含远程源提取）展示到 README（随定时任务自动更新）
        whitelist_rules = self._store.get_collection(RuleStore.R_TYPE_WHITELIST)
        self._fh.update_whitelist_in_readme(whitelist_rules)


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
            adguard_lite_file=self.config.path.sources_adguard_lite_file,
            host_lite_file=self.config.path.sources_host_lite_file,
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

            PrintSummaryStep(self.rule_store),

            # Hosts 去重（生成去重版规则）
            GenerateDedupHostsStep(self.rule_processor),

            # Lite 版规则处理
            GenerateDedupHostsLiteStep(self.rule_processor),

            WriteRulesStep(self.file_handler, self.rule_store),
            UpdateStatsStep(self.file_handler, self.config, self.rule_store),
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
            raise  # 重新抛出，保证进程以非零退出码结束，让 CI 能感知失败
