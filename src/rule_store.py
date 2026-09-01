"""规则集合存储与容器类模块 — 带完整封装和类型常量"""

import logging

logger = logging.getLogger(__name__)


class RuleStore:
    """规则数据存储容器（零依赖，纯数据层）"""

    # ------------------------------------------------------------------
    # 规则类型常量（消除字符串散落）
    # ------------------------------------------------------------------
    R_TYPE_HOSTS: str = 'hosts_rules'
    R_TYPE_WHITELIST: str = 'whitelist'
    R_TYPE_ADGUARD: str = 'adguard_rules'
    R_TYPE_HOSTS_DEDUP: str = 'hosts_rules_dedup'
    R_TYPE_HOSTS_LITE: str = 'hosts_lite'
    R_TYPE_ADGUARD_LITE: str = 'adguard_lite'
    R_TYPE_HOSTS_LITE_DEDUP: str = 'hosts_lite_dedup'

    ALL_RULE_TYPES = frozenset({
        R_TYPE_HOSTS, R_TYPE_WHITELIST, R_TYPE_ADGUARD,
    })

    # ------------------------------------------------------------------
    # 初始化
    # ------------------------------------------------------------------

    def __init__(self):
        self.collections: dict[str, set[str]] = {
            self.R_TYPE_HOSTS: set(),
            self.R_TYPE_WHITELIST: set(),
            self.R_TYPE_ADGUARD: set(),
            self.R_TYPE_HOSTS_DEDUP: set(),
            self.R_TYPE_HOSTS_LITE: set(),
            self.R_TYPE_ADGUARD_LITE: set(),
            self.R_TYPE_HOSTS_LITE_DEDUP: set(),
        }

    # ------------------------------------------------------------------
    # 规则添加（统一入口）
    # ------------------------------------------------------------------

    def add_rule(self, rtype: str, rule: str) -> None:
        """添加单条规则到对应集合。

        :param rtype: 规则类型（如 'hosts_rules'、'whitelist'、'adguard_rules'）
        :param rule:  规则文本
        """
        if rtype not in self.collections:
            logger.warning("未知规则类型 '%s'，已忽略规则: %s", rtype, rule[:80])
            return

        self.collections[rtype].add(rule)

    # ------------------------------------------------------------------
    # 集合查询（返回不可变视图，防止外部意外修改）
    # ------------------------------------------------------------------

    def get_collection(self, name: str) -> frozenset[str]:
        """获取规则集合的只读快照。"""
        return frozenset(self.collections.get(name, set()))

    def get_collection_size(self, name: str) -> int:
        """获取集合规则数量。"""
        return len(self.collections.get(name, set()))

    # ------------------------------------------------------------------
    # 集合级操作（原子替换，不暴露内部 set 对象）
    # ------------------------------------------------------------------

    def replace_collection(self, name: str, rules: set[str]) -> None:
        """原子替换整个规则集合。

        :param name:  集合名称（必须是已知类型）
        :param rules: 新的规则集合
        """
        if name not in self.collections:
            logger.warning("尝试替换未知集合 '%s'", name)
            return
        self.collections[name] = rules

    def remove_from_collection(self, name: str, predicate: callable) -> int:
        """从集合中移除满足谓词的规则。

        :param name:      集合名称
        :param predicate: 谓词函数 rule → bool（True 表示应移除）
        :returns: 移除的规则数
        """
        if name not in self.collections:
            logger.warning("尝试从未知集合 '%s' 移除", name)
            return 0

        target = self.collections[name]
        before = len(target)
        self.collections[name] = {r for r in target if not predicate(r)}
        after = len(self.collections[name])
        return before - after

    # ------------------------------------------------------------------
    # 统计 & 日志
    # ------------------------------------------------------------------

    def print_summary(self) -> None:
        """打印各集合规则数量概况。"""
        logger.info("规则集合概况:")
        for name, rules in self.collections.items():
            logger.info("  %s: %d 条", name, len(rules))

    def get_status_str(self) -> str:
        """获取当前规则数量的摘要描述字符串。"""
        return (
            f"Host规则 {len(self.collections[self.R_TYPE_HOSTS])} 条, "
            f"AdGuard规则 {len(self.collections[self.R_TYPE_ADGUARD])} 条, "
            f"白名单 {len(self.collections[self.R_TYPE_WHITELIST])} 条"
        )
