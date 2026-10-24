"""RuleProcessor 测试 — 整域判定、白名单剔除与 Hosts 去重"""

import unittest

from src.rule_processor import RuleProcessor
from src.rule_store import RuleStore


class TestExtractBlockingDomain(unittest.TestCase):
    """只有"覆盖整个域名"的规则才算整域拦截"""

    def test_whole_domain_rules_are_extracted(self) -> None:
        cases = (
            ('||example.com^', 'example.com'),
            ('||sub.example.co.uk^', 'sub.example.co.uk'),
            ('||EXAMPLE.COM^', 'example.com'),
            ('||example.com^$important', 'example.com'),
        )
        for rule, expected in cases:
            with self.subTest(rule=rule):
                self.assertEqual(expected, RuleProcessor.extract_blocking_domain(rule))

    def test_partial_rules_are_not_whole_domain(self) -> None:
        cases = (
            '||example.com^$third-party',
            '||example.com^$important,removeparam=x',
            '||example.com/ads.js',
            '@@||example.com^',
            'example.com##.ad',
            '*://ads.example.com/*',
        )
        for rule in cases:
            with self.subTest(rule=rule):
                self.assertIsNone(RuleProcessor.extract_blocking_domain(rule))


class TestExtractExceptionDomain(unittest.TestCase):
    """白名单例外同样只认 @@||domain^ 形式"""

    def test_whole_domain_exceptions(self) -> None:
        cases = (
            ('@@||example.com^', 'example.com'),
            ('@@||EXAMPLE.COM^', 'example.com'),
            ('@@||example.com^$important', 'example.com'),
        )
        for rule, expected in cases:
            with self.subTest(rule=rule):
                self.assertEqual(expected, RuleProcessor.extract_exception_domain(rule))

    def test_partial_exceptions_are_not_whole_domain(self) -> None:
        cases = (
            '@@||example.com^$document',        # 修饰符收窄了放行范围
            '@@||profile*.se.360.cn^',          # 通配符无法映射到单一域名
            '@@||example.com/ads.js',           # 仅放行特定路径
            '@@example.com',                    # 缺少 || 与 ^
            '||example.com^',                   # 不是例外规则
        )
        for rule in cases:
            with self.subTest(rule=rule):
                self.assertIsNone(RuleProcessor.extract_exception_domain(rule))


class TestWhitelistExclusions(unittest.TestCase):
    """Hosts 输出必须剔除白名单域名（Hosts 格式没有例外语法）"""

    def setUp(self) -> None:
        self.store = RuleStore()
        self.processor = RuleProcessor(self.store)

        for rule in ('0.0.0.0 ads.example.com', '0.0.0.0 sub.ads.example.com',
                     '0.0.0.0 keep.com', '0.0.0.0 c.keep.com'):
            self.store.add_rule(RuleStore.R_TYPE_HOSTS, rule)
            self.store.add_rule(RuleStore.R_TYPE_HOSTS_LITE, rule)

        self.store.add_rule(RuleStore.R_TYPE_WHITELIST, '@@||ads.example.com^')
        self.store.add_rule(RuleStore.R_TYPE_WHITELIST, '@@||keep.com^$document')

    def test_exception_covers_domain_and_subdomains(self) -> None:
        self.processor.apply_whitelist_exclusions()

        hosts = self.store.get_collection(RuleStore.R_TYPE_HOSTS)
        lite = self.store.get_collection(RuleStore.R_TYPE_HOSTS_LITE)

        self.assertNotIn('0.0.0.0 ads.example.com', hosts)
        self.assertNotIn('0.0.0.0 sub.ads.example.com', hosts)
        # @@||keep.com^$document 无法映射到单一域名，不应连带放行 keep.com
        self.assertIn('0.0.0.0 keep.com', hosts)
        self.assertIn('0.0.0.0 c.keep.com', hosts)

        self.assertEqual(set(hosts), set(lite))


class TestDedupHostsRules(unittest.TestCase):
    """去重：只在 AdGuard 覆盖整个域名时才移除对应 Hosts 条目"""

    def test_covered_domain_is_removed(self) -> None:
        store = RuleStore()
        processor = RuleProcessor(store)

        for rule in ('0.0.0.0 covered.com', '0.0.0.0 uncovered.com'):
            store.add_rule(RuleStore.R_TYPE_HOSTS, rule)
        store.add_rule(RuleStore.R_TYPE_ADGUARD, '||covered.com^')
        store.add_rule(RuleStore.R_TYPE_ADGUARD, '||path-only.com/ads.js')

        processor.generate_dedup_hosts_rules()

        self.assertEqual(
            {'0.0.0.0 uncovered.com'},
            set(store.get_collection(RuleStore.R_TYPE_HOSTS_DEDUP)),
        )


if __name__ == '__main__':
    unittest.main()