"""规则处理器模块 — 逆向白名单处理、Hosts 清洗及 mihomo 规则生成"""

import re
import logging
from pathlib import Path

from .rule_store import RuleStore
from .config import PathConfig

logger = logging.getLogger(__name__)


class RuleProcessor:
    """规则处理器算法类

    所有对 RuleStore 内部状态的修改均通过封装方法完成。
    """

    # CSS/JS 注入类规则标记（这些规则不应转为域名级拦截）
    _COSMETIC_MARKERS = frozenset({
        '##', '#@#', '#?#', '#@?#',
        '#$#', '#@$#', '#$?#', '#@$?#',
        '#%#', '#@%#',
    })

    def __init__(self, rule_store: RuleStore, path_config: PathConfig = None):
        """
        :param rule_store:  RuleStore 规则存储实例
        :param path_config: PathConfig 路径配置
        """
        self._store = rule_store
        self._path_config = path_config or PathConfig()

    # ------------------------------------------------------------------
    # 域名提取工具
    # ------------------------------------------------------------------

    @staticmethod
    def extract_domain(rule: str) -> str | None:
        """从 AdGuard / 白名单规则中提取纯域名。

        :param rule: 原始规则字符串
        :returns: 提取的小写域名，无法提取时返回 None
        """
        s = rule
        if s.startswith('@@'):
            s = s[2:]
        if s.startswith('||'):
            s = s[2:]
        if s.startswith(('http://', 'https://')):
            s = s.split('://', 1)[1]

        # 截断到第一个特殊字符
        for c in ('^', '$', '/', '#', '*', '?'):
            idx = s.find(c)
            if idx != -1:
                s = s[:idx]

        if not s:
            return None

        s = s.lstrip('*').lstrip('.')

        if '*' in s:
            return None
        if '.' not in s:
            return None
        if not all(c.isalnum() or c in '.-' for c in s):
            return None

        return s.lower()

    # ------------------------------------------------------------------
    # 逆向白名单
    # ------------------------------------------------------------------

    def read_anti_whitelist(self) -> None:
        """读取逆向白名单文件，构建域名集合和预编译正则。"""
        anti_path = Path(self._path_config.custom_rules_dir) / 'anti_whitelist.txt'
        if not anti_path.exists():
            logger.info("逆向白名单文件不存在，跳过: %s", anti_path)
            return

        domains: set[str] = set()
        try:
            with open(anti_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and not line.startswith('!'):
                        domains.add(line)
        except (OSError, UnicodeDecodeError) as e:
            logger.error("读取逆向白名单失败: %s — %s", anti_path, e)
            return

        if domains:
            combined = '|'.join(
                r'(?:(?:^|[.\#])' + re.escape(d) + r'(?=$|[.\#^/]))'
                for d in domains
            )
            pattern = re.compile(combined)
            self._store.set_anti_whitelist(domains, pattern)
        else:
            self._store.set_anti_whitelist(set(), None)

        logger.info("成功读取逆向白名单，共 %d 个域名", self._store.anti_whitelist_count)

    def remove_anti_whitelist_rules(self) -> None:
        """从白名单集合中移除匹配逆向白名单域名的规则。"""
        pattern = self._store.anti_whitelist_pattern
        domains = self._store.anti_whitelist_domains

        if not domains or not pattern:
            return

        logger.info("移除逆向白名单规则...")
        name = RuleStore.R_TYPE_WHITELIST
        before = self._store.get_collection_size(name)

        existing = self._store.get_collection(name)
        filtered = {rule for rule in existing if not pattern.search(rule)}
        self._store.replace_collection(name, filtered)

        after = self._store.get_collection_size(name)
        logger.info("已移除 %d 条逆向白名单规则", before - after)

    # ------------------------------------------------------------------
    # Hosts 白名单清洗
    # ------------------------------------------------------------------

    def remove_whitelist_from_hosts(self) -> None:
        """将白名单域名从 hosts_rules 中移除。"""
        whitelist = self._store.get_collection(RuleStore.R_TYPE_WHITELIST)
        if not whitelist:
            return

        logger.info("从 Hosts 规则中移除白名单域名...")

        whitelist_domains: set[str] = set()
        skipped_wildcards: list[str] = []
        for rule in whitelist:
            domain = self.extract_domain(rule)
            if domain:
                whitelist_domains.add(domain)
            elif any(c in rule for c in ('*', '?')):
                skipped_wildcards.append(rule)

        if skipped_wildcards:
            display = ', '.join(skipped_wildcards[:5])
            suffix = '...' if len(skipped_wildcards) > 5 else ''
            logger.warning(
                "%d 条包含通配符的白名单规则无法从 Hosts 中移除: %s%s",
                len(skipped_wildcards), display, suffix,
            )

        def _is_whitelisted(rule: str) -> bool:
            parts = rule.split()
            if len(parts) < 2:
                return False
            target_domain = parts[1].lower()
            return target_domain in whitelist_domains or any(
                target_domain.endswith('.' + wd) for wd in whitelist_domains
            )

        removed = self._store.remove_from_collection(
            RuleStore.R_TYPE_HOSTS, _is_whitelisted,
        )
        logger.info("已从 Hosts 规则中移除 %d 条白名单域名", removed)

    # ------------------------------------------------------------------
    # AdGuard 白名单清洗（去掉白名单对应的黑名单规则）
    # ------------------------------------------------------------------

    def remove_whitelist_from_adguard(self) -> None:
        """将白名单域名从 adguard_rules 中移除。"""
        whitelist = self._store.get_collection(RuleStore.R_TYPE_WHITELIST)
        if not whitelist:
            return

        logger.info("从 AdGuard 规则中移除白名单域名...")

        # 提取白名单域名
        whitelist_domains: set[str] = set()
        for rule in whitelist:
            domain = self.extract_domain(rule)
            if domain:
                whitelist_domains.add(domain)

        if not whitelist_domains:
            return

        # 过滤 adguard_rules：去掉域名在白名单中的规则
        def _is_whitelisted(rule: str) -> bool:
            domain = self.extract_domain(rule)
            return domain is not None and (
                domain in whitelist_domains
                or any(domain.endswith('.' + wd) for wd in whitelist_domains)
            )

        removed = self._store.remove_from_collection(
            RuleStore.R_TYPE_ADGUARD, _is_whitelisted,
        )
        logger.info("已从 AdGuard 规则中移除 %d 条白名单域名", removed)

    # ------------------------------------------------------------------
    # Mihomo 规则生成
    # ------------------------------------------------------------------

    def generate_mihomo_rules(self) -> None:
        """从 hosts_rules + adguard_rules 提取域名，生成 mihomo 规则。"""
        logger.info("生成 mihomo 规则...")
        domains: set[str] = set()

        # 1. 从 hosts_rules 提取
        for rule in self._store.get_collection(RuleStore.R_TYPE_HOSTS):
            parts = rule.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                if domain and '.' in domain and all(c.isalnum() or c in '.-' for c in domain):
                    domains.add(domain)

        # 2. 从 adguard_rules 提取（跳过 CSS/JS 注入类规则，它们不应转为域名级拦截）
        for rule in self._store.get_collection(RuleStore.R_TYPE_ADGUARD):
            if any(m in rule for m in self._COSMETIC_MARKERS):
                continue
            domain = self.extract_domain(rule)
            if domain:
                domains.add(domain)

        # 3. 移除逆向白名单域名
        anti = self._store.anti_whitelist_domains
        if anti:
            domains -= anti

        # 4. 移除白名单域名（含子域名匹配）
        whitelist_domains_for_mihomo = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_WHITELIST):
            domain = self.extract_domain(rule)
            if domain:
                whitelist_domains_for_mihomo.add(domain)

        if whitelist_domains_for_mihomo:
            to_remove = set()
            for d in domains:
                if d in whitelist_domains_for_mihomo or any(
                    d.endswith('.' + wd) for wd in whitelist_domains_for_mihomo
                ):
                    to_remove.add(d)
            domains -= to_remove

        # 5. 全量替换写入 Store
        self._store.replace_mihomo_rules(domains)
        logger.info("mihomo 拦截规则: %d 条", self._store.mihomo_count)

    # ------------------------------------------------------------------
    # Hosts 规则去重（去掉已被 AdGuard 覆盖的域名）
    # ------------------------------------------------------------------

    def generate_dedup_hosts_rules(self) -> None:
        """从 hosts_rules 中去掉 adguard_rules 已覆盖的域名（AdGuard 覆盖范围更大）。"""
        logger.info("生成去重 Hosts 规则...")

        # 1. 构建 adguard_rules 域名集合
        adguard_domains: set[str] = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_ADGUARD):
            domain = self.extract_domain(rule)
            if domain:
                adguard_domains.add(domain)

        before = self._store.get_collection_size(RuleStore.R_TYPE_HOSTS)

        # 2. 过滤 hosts_rules：去掉域名已在 AdGuard 中出现的
        dedup_rules: set[str] = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_HOSTS):
            parts = rule.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                # 如果该域名已被 AdGuard 覆盖（||domain^ 拦 domain + 所有子域名），则去掉
                if domain not in adguard_domains:
                    dedup_rules.add(rule)
            else:
                dedup_rules.add(rule)

        # 3. 写入去重集合
        self._store.replace_collection(RuleStore.R_TYPE_HOSTS_DEDUP, dedup_rules)

        after = len(dedup_rules)
        logger.info(
            "去重完成: Hosts %d 条 → %d 条（去除 %d 条 AdGuard 已覆盖域名）",
            before, after, before - after,
        )
