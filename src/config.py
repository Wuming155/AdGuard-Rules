"""配置管理模块 — 按职责拆分为路径、规则两块专题配置"""

import os
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# 专题子配置（不可变 dataclass，按模块注入）
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PathConfig:
    """文件路径相关配置"""
    sources_adguard_file: str = 'sources/sources_adguard.txt'
    sources_host_file: str = 'sources/sources_host.txt'
    sources_adguard_lite_file: str = 'sources/sources_adguard_lite.txt'
    sources_host_lite_file: str = 'sources/sources_host_lite.txt'
    dist_dir: str = 'dist'
    custom_rules_dir: str = 'custom-rules'
    readme_path: str = 'README.md'
    source_cache_dir: str = 'cache/sources'
    build_baseline_file: str = 'cache/last_build.json'

    def __post_init__(self):
        if not self.dist_dir:
            raise ValueError("dist_dir 不能为空")


@dataclass(frozen=True)
class RuleConfig:
    """规则处理相关配置"""
    hosts_ip: str = '0.0.0.0'

    def __post_init__(self):
        if not self.hosts_ip:
            raise ValueError("hosts_ip 不能为空，需设置为有效的 IP 地址（如 0.0.0.0）")


# ---------------------------------------------------------------------------
# 聚合 Config（向后兼容旧接口）
# ---------------------------------------------------------------------------

class Config:
    """聚合配置类 — 组合路径与规则两个专题子配置。"""

    def __init__(self):
        self.github_repo = os.getenv('GITHUB_REPOSITORY', 'Wuming155/AdGuard-Rules')

        # 子配置（不可变，按模块注入）
        self.path = PathConfig()
        self.rule = RuleConfig()
