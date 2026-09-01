#!/usr/bin/env python3
"""
定期清理 Git 旧历史，仅保留最近 N 个月的提交记录。

工作原理:
  1. 找到截止日期之后的第一个提交（作为新根提交的起点）
  2. 创建孤立分支，将截止日期前的所有旧提交压缩为一个根提交
  3. 在新根上重放所有需要保留的提交
  4. 运行 git gc 优化存储

安全性:
  - 提供 --dry-run 预览模式
  - 检测未提交更改并中止
  - 仅操作当前分支

用法:
  python tools/maintain_git_history.py                  # 保留最近 3 个月
  python tools/maintain_git_history.py --keep-months 6  # 保留最近 6 个月
  python tools/maintain_git_history.py --dry-run        # 预览模式
"""

import argparse
import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("git_history")


def run_git(*args: str, cwd: str | Path) -> str:
    """执行 git 命令并返回 stdout（去除首尾空白）。若失败则退出进程。"""
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Git 命令失败: git %s\n%s", " ".join(args), exc.stderr.strip())
        sys.exit(exc.returncode)
    return result.stdout.strip()


def get_repo_size(cwd: str | Path) -> str:
    """获取 .git 目录的磁盘占用。"""
    output = run_git("count-objects", "-vH", cwd=cwd)
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("size-pack:"):
            return stripped.split(":")[1].strip()
        if stripped.startswith("size:") and "size-pack" not in stripped:
            return stripped.split(":")[1].strip()
    return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="清理 Git 旧历史记录，仅保留最近 N 个月的提交。"
    )
    parser.add_argument(
        "--keep-months",
        type=int,
        default=3,
        help="保留最近多少个月的提交记录（默认: 3）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅预览要执行的操作，不实际修改仓库",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)-7s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    repo_root = Path.cwd()
    logger.info("仓库路径: %s", repo_root)

    # 检查是否在 git 仓库中
    try:
        run_git("rev-parse", "--git-dir", cwd=repo_root)
    except SystemExit:
        logger.error("当前目录不是 Git 仓库，请确认在仓库根目录运行。")
        sys.exit(1)

    # 检查是否有未提交的更改
    status = run_git("status", "--porcelain", cwd=repo_root)
    if status:
        logger.error(
            "存在未提交的更改，请先提交或 stash 后再运行清理:\n%s", status[:500]
        )
        if not args.dry_run:
            sys.exit(1)

    # 获取当前分支
    current_branch = run_git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo_root)
    logger.info("当前分支: %s", current_branch)

    if current_branch == "HEAD":
        logger.error("处于 detached HEAD 状态，请在具体分支上运行。")
        sys.exit(1)

    # 确定截止日期
    cutoff_date = (datetime.now() - timedelta(days=args.keep_months * 30)).strftime(
        "%Y-%m-%d"
    )
    logger.info(
        "保留最近 %d 个月的提交（从 %s 之后）", args.keep_months, cutoff_date
    )

    # 获取截止日期之后的第一个提交（这将是新历史的根）
    after_list = run_git(
        "rev-list", "--after=" + cutoff_date, "--reverse", "HEAD", cwd=repo_root
    )
    if not after_list:
        logger.info("没有 %s 之后的提交，无需清理。", cutoff_date)
        logger.info("总提交数: %s", run_git("rev-list", "--count", "HEAD", cwd=repo_root))
        return

    new_root = after_list.splitlines()[0]
    logger.info("将要保留的最旧提交: %s", new_root[:12])

    # 获取 new_root 的父提交（即旧历史的最后一个提交）
    try:
        old_tail = run_git("rev-parse", f"{new_root}^", cwd=repo_root)
    except SystemExit:
        logger.info("%s 已经是根提交，没有旧历史需要清理。", new_root[:12])
        return

    if not old_tail or old_tail == new_root:
        logger.info("没有要清理的旧历史。")
        return

    # 统计提交数
    old_count = int(run_git("rev-list", "--count", old_tail, cwd=repo_root))
    new_count = int(
        run_git("rev-list", "--count", f"{old_tail}..HEAD", cwd=repo_root)
    )
    total_count = old_count + new_count

    logger.info("- 将被压缩的旧提交数: %s", old_count)
    logger.info("- 将保留的新提交数:   %s", new_count)
    logger.info("- 清理后总提交数:     ~%s", new_count + 1)  # +1 为压缩后的根提交

    size_before = get_repo_size(repo_root)
    logger.info("- 当前 .git 大小:     %s", size_before)

    if args.dry_run:
        logger.info("=" * 50)
        logger.info("DRY-RUN 模式 — 以上为预览信息，未做任何修改。")
        logger.info("=" * 50)
        return

    # ==================== 开始执行清理 ====================
    logger.info("=" * 50)
    logger.info("开始执行清理...")
    logger.info("=" * 50)

    # 1. 在 old_tail 的位置创建孤立分支
    logger.info("步骤 1/5: 创建新的根提交（压缩旧历史）...")
    run_git("checkout", "--orphan", "__cleanup_temp__", old_tail, cwd=repo_root)
    run_git("commit", "-m",
            f"chore: 合并历史提交（{cutoff_date} 前）\n\n"
            f"此提交由自动维护脚本创建，包含截至 {cutoff_date} 的所有历史记录。\n"
            f"共压缩 {old_count} 个旧提交。",
            cwd=repo_root)
    new_root_id = run_git("rev-parse", "HEAD", cwd=repo_root)
    logger.info("  新的根提交: %s", new_root_id[:12])

    # 2. 切回原始分支
    logger.info("步骤 2/5: 切换回 %s 分支...", current_branch)
    run_git("checkout", current_branch, cwd=repo_root)

    # 3. 在 new_root_id 上重放保留的提交
    logger.info("步骤 3/5: 重放 %s 个保留提交...", new_count)
    try:
        run_git("rebase", "--onto", new_root_id, old_tail, cwd=repo_root)
    except SystemExit:
        # run_git 失败时会直接 sys.exit，在此捕获以便回滚现场
        logger.error("Rebase 失败（可能存在冲突），正在中止并恢复原分支...")
        subprocess.run(
            ["git", "rebase", "--abort"],
            cwd=repo_root, capture_output=True, text=True,
        )
        subprocess.run(
            ["git", "branch", "-D", "__cleanup_temp__"],
            cwd=repo_root, capture_output=True, text=True,
        )
        logger.error("已恢复到 rebase 前状态，请手动检查后重试。")
        sys.exit(1)
    logger.info("  Rebase 完成")

    # 4. 删除临时分支
    logger.info("步骤 4/5: 清理临时分支...")
    run_git("branch", "-D", "__cleanup_temp__", cwd=repo_root)

    # 5. 运行垃圾回收
    logger.info("步骤 5/5: 运行 git gc 优化存储...")
    run_git("gc", "--aggressive", "--prune=now", cwd=repo_root)

    # 结果报告
    final_count = run_git("rev-list", "--count", "HEAD", cwd=repo_root)
    size_after = get_repo_size(repo_root)
    logger.info("=" * 50)
    logger.info("清理完成！")
    logger.info("- 清理前: %s 个提交, .git 大小 %s", total_count, size_before)
    logger.info("- 清理后: %s 个提交, .git 大小 %s", final_count, size_after)
    logger.info("=" * 50)
    logger.info("")
    logger.info("提示: 请在确认无误后运行以下命令强制推送:")
    logger.info("  git push origin %s --force", current_branch)


if __name__ == "__main__":
    main()
