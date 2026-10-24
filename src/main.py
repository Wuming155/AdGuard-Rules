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


class SourceIntegrityError(RuntimeError):
    """远程规则源未能全部拉取（失败或超过大小上限）。"""


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
    """读取本地自定义规则"""

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "读取本地规则"

    def execute(self) -> None:
        self._fetcher.read_local_rules()


class ReadRemoteRulesStep(PipelineStep):
    """读取远程订阅源规则"""

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "读取远程规则"

    def execute(self) -> None:
        self._fetcher.read_remote_rules()


class CheckSourceHealthStep(PipelineStep):
    """远程规则源完整性检查

    只要有源失败或超出大小上限就直接失败：宁可让 CI 变红、沿用上一次的产物，
    也不要静默产出缺少规则的"完整规则集"。
    """

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "规则源完整性检查"

    def execute(self) -> None:
        problems = self._fetcher.problem_sources
        if not problems:
            return

        stats = self._fetcher.fetch_stats
        detail = "\n".join(f"  - {url} （{reason}）" for url, reason in problems)
        raise SourceIntegrityError(
            f"{len(problems)} 个远程规则源未能完整拉取"
            f"（成功 {stats['success']} / 失败 {stats['failed']} / 截断 {stats['truncated']}）:\n"
            f"{detail}\n"
            "请确认源是否失效、被限流或体积超出上限。"
            "本次不写入也不发布产物，避免静默产出缺规则的规则集。"
        )


class ApplyWhitelistToHostsStep(PipelineStep):
    """把白名单域名从 Hosts 结果中剔除

    Hosts 格式没有例外语法：白名单若不在这里生效，
    使用 bindhosts 等模块的用户会继续拦截自己放行的域名。
    """

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "白名单剔除 Hosts"

    def execute(self) -> None:
        self._processor.apply_whitelist_exclusions()


class PrintSummaryStep(PipelineStep):
    """打印规则概况"""

    def __init__(self, rule_store: RuleStore):
        self._store = rule_store

    @property
    def name(self) -> str:
        return "规则概况输出"

    def execute(self) -> None:
        self._store.print_summary()


class GenerateDedupHostsStep(PipelineStep):
    """生成去重 Hosts 规则（去掉 AdGuard 已覆盖的域名）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Hosts 规则去重"

    def execute(self) -> None:
        self._processor.generate_dedup_hosts_rules()


class GenerateDedupHostsLiteStep(PipelineStep):
    """生成去重 Lite Hosts 规则（去掉 Lite AdGuard 已覆盖的域名）"""

    def __init__(self, rule_processor: RuleProcessor):
        self._processor = rule_processor

    @property
    def name(self) -> str:
        return "Lite Hosts 规则去重"

    def execute(self) -> None:
        self._processor.generate_dedup_hosts_lite_rules()


class WriteRulesStep(PipelineStep):
    """将规则集合写入文件"""

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
    """更新 README 统计"""

    def __init__(self, file_handler: FileHandler, config: Config, rule_store: RuleStore):
        self._fh = file_handler
        self._config = config
        self._store = rule_store

    @property
    def name(self) -> str:
        return "更新 README 统计"

    def execute(self) -> None:
        all_stats = self._fh.get_file_stats(self._config.path.dist_dir)

        # 只统计本次实际产出的文件，避免 dist/ 中的历史残留混入表格。
        # 白名单与拦截规则在同一张表格中展示。
        expected_names = {f"{rtype}.txt" for rtype in RuleStore.OUTPUT_RULE_TYPES}
        all_stats = [s for s in all_stats if s['name'] in expected_names]

        self._fh.update_readme(all_stats)


# ======================================================================
# 主执行器
# ======================================================================

class MainExecutor:
    """主执行器（Pipeline 流水线调度器）

    将所有步骤组织为 Pipeline，执行顺序由 steps 列表显式定义，
    增加/删除/重排步骤只需修改 _build_pipeline() 方法。
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

            # 完整性检查：源没拉全就中止，不产出缺规则的产物
            CheckSourceHealthStep(self.rule_fetcher),

            # 白名单剔除必须先于去重：去重结果同样不应包含白名单域名
            ApplyWhitelistToHostsStep(self.rule_processor),

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