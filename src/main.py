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
from .build_baseline import BuildBaseline

logger = logging.getLogger(__name__)


class BuildQualityError(RuntimeError):
    """产物质量不过关：整体为空、缺少基础规则集，或覆盖范围异常收缩。"""


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
    """读取远程订阅源规则（单源失败回退缓存或跳过，不中断构建）"""

    def __init__(self, rule_fetcher: RuleFetcher):
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "读取远程规则"

    def execute(self) -> None:
        self._fetcher.read_remote_rules()


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


class QualityGateStep(PipelineStep):
    """整体质量门禁

    只拦截"整体不可用"的情况：产物为空、缺少基础拦截规则，
    或相对上一次成功构建出现无法解释的严重收缩。
    个别源失败（已回退缓存或跳过）不阻止构建与发布。
    """

    # 相对上一次成功构建的允许跌幅；超过即视为严重异常
    _MAX_DROP_RATIO = 0.5

    def __init__(self, rule_store: RuleStore, baseline: BuildBaseline,
                 rule_fetcher: RuleFetcher):
        self._store = rule_store
        self._baseline = baseline
        self._fetcher = rule_fetcher

    @property
    def name(self) -> str:
        return "产物质量门禁"

    def execute(self) -> None:
        counts = {
            name: self._store.get_collection_size(name)
            for name in RuleStore.OUTPUT_RULE_TYPES
        }
        problems: list[str] = []

        if counts[RuleStore.R_TYPE_ADGUARD] == 0:
            problems.append("adguard_rules 为空，缺少基础拦截规则")
        if counts[RuleStore.R_TYPE_HOSTS] == 0:
            problems.append("hosts_rules 为空，缺少基础拦截规则")

        baseline = self._baseline.load()
        if baseline:
            for name, current in counts.items():
                previous = baseline.get(name)
                if previous and current < previous * (1.0 - self._MAX_DROP_RATIO):
                    problems.append(
                        f"{name} 覆盖范围异常收缩: {previous} 条 → {current} 条"
                        f"（-{(previous - current) / previous:.0%}）"
                    )
        else:
            logger.info("无历史构建基线，本次仅做基础校验（空值与规模下限）")

        if not problems:
            logger.info("质量门禁通过: %s", ", ".join(f"{k}={v}" for k, v in counts.items()))
            return

        degraded = self._fetcher.degraded_sources()
        degraded_text = "\n".join(
            f"  - [{s['status']}] {s['url']}（{s['reason']}）" for s in degraded
        ) or "  - 无（所有源均正常拉取，请重点排查上游变更）"

        raise BuildQualityError(
            "产物质量门禁未通过，已阻止本次发布（保留上一成功版本）:\n"
            + "\n".join(f"  - {p}" for p in problems)
            + "\n本次降级的规则源:\n" + degraded_text
        )


class WriteRulesStep(PipelineStep):
    """将规则集合写入文件（临时文件 + 原子替换）"""

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


class RecordBaselineStep(PipelineStep):
    """记录本次成功构建的规模，作为下次质量比对的基线"""

    def __init__(self, rule_store: RuleStore, baseline: BuildBaseline):
        self._store = rule_store
        self._baseline = baseline

    @property
    def name(self) -> str:
        return "记录构建基线"

    def execute(self) -> None:
        counts = {
            name: self._store.get_collection_size(name)
            for name in RuleStore.OUTPUT_RULE_TYPES
        }
        self._baseline.save(counts)
        logger.info("已记录构建基线: %s", ", ".join(f"{k}={v}" for k, v in counts.items()))


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
                 rule_processor: RuleProcessor | None = None,
                 build_baseline: BuildBaseline | None = None):
        """初始化主执行器，全部支持依赖注入。"""
        self.config = config or Config()

        self.resolver = resolver or RuleResolver(self.config.rule)
        self.file_handler = file_handler or FileHandler(self.config)
        self.rule_store = rule_store or RuleStore()
        self.build_baseline = build_baseline or BuildBaseline(self.config.path.build_baseline_file)

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

            # 白名单剔除必须先于去重：去重结果同样不应包含白名单域名
            ApplyWhitelistToHostsStep(self.rule_processor),

            PrintSummaryStep(self.rule_store),

            # Hosts 去重（生成去重版规则）
            GenerateDedupHostsStep(self.rule_processor),

            # Lite 版规则处理
            GenerateDedupHostsLiteStep(self.rule_processor),

            # 整体质量门禁：仅当产物整体不可用时中止，个别源失败不阻止发布
            QualityGateStep(self.rule_store, self.build_baseline, self.rule_fetcher),

            WriteRulesStep(self.file_handler, self.rule_store),
            UpdateStatsStep(self.file_handler, self.config, self.rule_store),

            # 全部成功后更新基线；本次未通过则保留上一次的基准
            RecordBaselineStep(self.rule_store, self.build_baseline),
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