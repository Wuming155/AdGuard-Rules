#!/usr/bin/env python3
"""执行入口 — 配置日志并启动规则同步流水线"""

import sys
import logging

from src.config import Config
from src.build_baseline import BuildBaseline
from src.main import MainExecutor
from src.stats_updater import StatsUpdater


def _check_python_version() -> None:
    """检查 Python 版本是否符合要求（3.10+）。"""
    if sys.version_info < (3, 10):
        sys.exit(
            f"错误: 需要 Python 3.10 或更高版本 (当前: {sys.version_info.major}.{sys.version_info.minor})\n"
            f"源码使用了 str | None、frozenset[str] 等 3.10+ 语法。"
        )


def _setup_logging() -> None:
    """配置全项目日志格式和级别。

    仅当尚未配置时添加 handler，避免覆盖测试/调用方的日志设置。
    """
    root_logger = logging.getLogger()

    # 如果已有 handler 则直接使用现有配置
    if root_logger.handlers:
        root_logger.setLevel(logging.INFO)
        return

    fmt = logging.Formatter(
        fmt='%(asctime)s [%(levelname)-7s] %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(fmt)
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(handler)


def record_baseline(dist_dir: str, baseline_path: str) -> dict[str, int]:
    """按 dist/ 实际产出记录构建基线（供下次质量门禁比对）。

    由 CI 在「发布成功后」调用，使基准只反映真正发布出去的构建：
    若本次通过门禁但后续上传 Release 失败，就不会把这次规模记为上一成功版本。
    """
    counts = {
        item['name'][: -len('.txt')]: item['count']
        for item in StatsUpdater.get_file_stats(dist_dir)
        if item['name'].endswith('.txt')
    }
    BuildBaseline(baseline_path).save(counts)
    return counts


def main() -> None:
    """主函数"""
    _check_python_version()
    _setup_logging()

    logger = logging.getLogger("main_executor")

    if '--record-baseline' in sys.argv[1:]:
        config = Config()
        counts = record_baseline(config.path.dist_dir, config.path.build_baseline_file)
        logger.info("已记录构建基线: %s",
                    ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        return

    logger.info("启动 AdGuard-Rules 规则同步...")

    executor = MainExecutor()
    executor.run()


if __name__ == "__main__":
    main()