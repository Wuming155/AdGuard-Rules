"""规则处理器模块 — Hosts 规则去重"""

import re
import logging
from pathlib import Path

from .rule_store import RuleStore
from .config import PathConfig

logger = logging.getLogger(__name__)


class RuleProcessor:
    """规则处理器算法类

    所有对 RuleStore 内部状态的修改均通过封装方法完成。
    白名单规则独立于拦截集合保存（dist/whitelist.txt），不做交叉剔除。
    """

    # CSS/JS 注入类规则标记（这些规则不应转为域名级拦截）
    _COSMETIC_MARKERS = frozenset({
        '##', '#@#', '#?#', '#@?#',
        '#$#', '#@$#', '#$?#', '#@$?#',
        '#%#', '#@%#',
    })

    # 合法域名（用于判定规则主体是否为纯域名）
    _DOMAIN_RE = re.compile(
        r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$'
    )

    # 不改变"拦截整个域名"语义的修饰符。
    # 除此之外的修饰符（$third-party / $image / $removeparam / $app 等）
    # 都把规则收缩为 URL 级或条件级，不能当成整域覆盖。
    _NEUTRAL_MODIFIERS = frozenset({'important'})

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

    @classmethod
    def extract_blocking_domain(cls, rule: str) -> str | None:
        """提取『被整域拦截』的域名，仅当规则覆盖整个域名时返回域名。

        本方法是严格判定，用于判断某域名是否已被完整覆盖。
        以下情况返回 None，避免把 URL 级规则误当成整域拦截：

            ||a.com/ads.js              — 仅拦截特定路径
            ||a.com^$third-party        — 仅拦截第三方请求
            ||a.com^$removeparam=utm    — 非拦截语义，仅清理参数
            ||a.com^$app=com.xxx        — 仅在指定 App 内生效（DNS 层不支持）
            ||a.com^$badfilter          — 规则已被显式禁用
            a.com##.ad / *-ad.a.com*    — 修饰类与通配符规则

        :param rule: 原始规则字符串
        :returns: 被整域拦截的小写域名，非整域拦截时返回 None
        """
        s = rule.strip()

        # 白名单与修饰类规则不构成拦截
        if s.startswith('@@'):
            return None
        if any(m in s for m in cls._COSMETIC_MARKERS):
            return None

        # 只有 || 开头的规则才表示"域名锚定"
        if s.startswith('||'):
            s = s[2:]
        elif s.startswith(('http://', 'https://')):
            s = s.split('://', 1)[1]
        else:
            return None

        # 拆分修饰符：仅允许中性修饰符，其余一律视为条件拦截
        body, sep, modifiers = s.partition('$')
        if sep:
            mods = {m.split('=', 1)[0].strip() for m in modifiers.split(',')}
            if not mods or not mods <= cls._NEUTRAL_MODIFIERS:
                return None

        # 主体必须是纯域名（允许可选的分隔符 ^）
        if body.endswith('^'):
            body = body[:-1]
        if not body or not cls._DOMAIN_RE.match(body):
            return None

        # 排除纯 IPv4 地址（域名级集合不应包含 IP）
        if body.count('.') == 3 and all(p.isdigit() for p in body.split('.')):
            return None

        return body.lower()

    @classmethod
    def extract_exception_domain(cls, rule: str) -> str | None:
        """提取『放行整个域名』的白名单域名，仅当例外覆盖整个域名时返回域名。

        与 extract_blocking_domain 同样严格：只认 @@||domain^ 形式。
        带通配符、路径或非中性修饰符的例外（如 @@||profile*.se.360.cn^、
        @@||a.com^$document）无法映射到单个域名，返回 None，
        避免把"单条路径放行"误扩成"整域放行"。

        :param rule: 原始规则字符串
        :returns: 被整域放行的小写域名，非整域放行时返回 None
        """
        s = rule.strip()
        if not s.startswith('@@||'):
            return None

        body, sep, modifiers = s[4:].partition('$')
        if sep:
            mods = {m.split('=', 1)[0].strip() for m in modifiers.split(',')}
            if not mods or not mods <= cls._NEUTRAL_MODIFIERS:
                return None

        if body.endswith('^'):
            body = body[:-1]
        if not body or not cls._DOMAIN_RE.match(body):
            return None

        return body.lower()

    # ------------------------------------------------------------------
    # Hosts 规则去重（去掉已被 AdGuard 覆盖的域名）
    # ------------------------------------------------------------------

    def generate_dedup_hosts_rules(self) -> None:
        """从 hosts_rules 中去掉 adguard_rules 已覆盖的域名（AdGuard 覆盖范围更大）。"""
        logger.info("生成去重 Hosts 规则...")

        # 1. 构建 adguard_rules 整域拦截域名集合
        #    （仅 ||domain^ 形式才算覆盖整域；带路径/修饰符的规则不算，
        #     否则会把 hosts 中仍需整域拦截的条目误删，造成漏拦）
        adguard_domains: set[str] = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_ADGUARD):
            domain = self.extract_blocking_domain(rule)
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

    # ------------------------------------------------------------------
    # Lite Hosts 规则去重（去掉已被 Lite AdGuard 覆盖的域名）
    # ------------------------------------------------------------------

    def generate_dedup_hosts_lite_rules(self) -> None:
        """从 hosts_lite 中去掉 adguard_lite 已覆盖的域名。"""
        logger.info("生成去重 Lite Hosts 规则...")

        # 1. 构建 adguard_lite 整域拦截域名集合（仅 ||domain^ 形式才算覆盖整域）
        adguard_domains: set[str] = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_ADGUARD_LITE):
            domain = self.extract_blocking_domain(rule)
            if domain:
                adguard_domains.add(domain)

        before = self._store.get_collection_size(RuleStore.R_TYPE_HOSTS_LITE)

        # 2. 过滤 hosts_lite：去掉域名已在 AdGuard Lite 中出现的
        dedup_rules: set[str] = set()
        for rule in self._store.get_collection(RuleStore.R_TYPE_HOSTS_LITE):
            parts = rule.split()
            if len(parts) >= 2:
                domain = parts[1].lower()
                if domain not in adguard_domains:
                    dedup_rules.add(rule)
            else:
                dedup_rules.add(rule)

        # 3. 写入 Lite 去重集合
        self._store.replace_collection(RuleStore.R_TYPE_HOSTS_LITE_DEDUP, dedup_rules)

        after = len(dedup_rules)
        logger.info(
            "Lite 去重完成: Hosts Lite %d 条 → %d 条（去除 %d 条 AdGuard Lite 已覆盖域名）",
            before, after, before - after,
        )

    # ------------------------------------------------------------------
    # 白名单剔除（Hosts 格式没有例外语法，只能在这里生效）
    # ------------------------------------------------------------------

    @staticmethod
    def _hosts_domain(rule: str) -> str | None:
        """取出 Hosts 规则中的域名部分。"""
        parts = rule.split()
        return parts[1].lower() if len(parts) >= 2 else None

    @classmethod
    def _is_domain_exempt(cls, rule: str, exceptions: set[str]) -> bool:
        """判断 Hosts 规则是否被白名单覆盖（自身或任一上级域名被放行）。

        @@||parent^ 在 AdGuard 里放行 parent 及其全部子域名，
        Hosts 侧要得到等价效果，需按域名后缀逐级比对。
        """
        domain = cls._hosts_domain(rule)
        if not domain:
            return False

        candidate = domain
        while True:
            if candidate in exceptions:
                return True
            if '.' not in candidate:
                return False
            candidate = candidate.split('.', 1)[1]

    def apply_whitelist_exclusions(self) -> None:
        """从 Hosts 输出中剔除白名单域名。

        AdGuard 侧由 @@ 例外自动生效，而 Hosts 格式无法表达例外，
        若不在此处剔除，使用 bindhosts 等模块的用户会继续拦截自己放行的域名。
        """
        logger.info("将白名单域名从 Hosts 规则中剔除...")

        exceptions: set[str] = set()
        unmappable = 0
        for rule in self._store.get_collection(RuleStore.R_TYPE_WHITELIST):
            domain = self.extract_exception_domain(rule)
            if domain:
                exceptions.add(domain)
            else:
                unmappable += 1

        if unmappable:
            logger.info(
                "白名单中 %d 条例外无法映射到单一域名（含通配符或路径），未参与剔除",
                unmappable,
            )

        for rtype in (RuleStore.R_TYPE_HOSTS, RuleStore.R_TYPE_HOSTS_LITE):
            before = self._store.get_collection_size(rtype)
            remaining = {
                rule for rule in self._store.get_collection(rtype)
                if not self._is_domain_exempt(rule, exceptions)
            }
            self._store.replace_collection(rtype, remaining)
            logger.info(
                "%s: %d 条 → %d 条（剔除 %d 条白名单域名）",
                rtype, before, len(remaining), before - len(remaining),
            )
