#!/usr/bin/env python3
"""执行入口 — 配置日志并启动规则同步流水线"""

import sys
import logging

from src.main import MainExecutor


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


def main() -> None:
    """主函数"""
    _check_python_version()
    _setup_logging()

    logger = logging.getLogger("main_executor")
    logger.info("启动 AdGuard-Rules 规则同步...")

    executor = MainExecutor()
    executor.run()


if __name__ == "__main__":
    main()
