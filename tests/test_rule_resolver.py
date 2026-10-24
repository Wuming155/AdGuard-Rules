"""RuleResolver 表驱动测试 — 规则分类与 Hosts 归一化"""

import unittest

from src.config import RuleConfig
from src.rule_resolver import RuleResolver

HOSTS_IP = '0.0.0.0'


class TestRuleResolver(unittest.TestCase):
    """测试单行规则 -> (类型, 规范化规则) 的判定"""

    def setUp(self) -> None:
        self.resolver = RuleResolver(RuleConfig(hosts_ip=HOSTS_IP))

    def test_comments_and_blank_lines_are_ignored(self) -> None:
        for line in ('', '   ', '! comment', '# comment', '#s#invalid-hash-prefix'):
            with self.subTest(line=line):
                self.assertEqual((None, None), self.resolver.resolve(line))

    def test_whitelist_rule(self) -> None:
        line = '@@||example.com^'
        self.assertEqual(('whitelist', line), self.resolver.resolve(line))

    def test_adguard_rules_keep_original_text(self) -> None:
        cases = (
            '||example.com^',
            '||example.com^$important',
            '||example.com^$third-party',
            'example.com##.banner',
            r'/^adsage\./',
            'ads.example.com/path/ad.js',
            'http://ads.example.com/x',   # 带协议头的 URL 规则
            'https://ads.example.com',    # 无路径的纯 URL 规则
        )
        for line in cases:
            with self.subTest(line=line):
                self.assertEqual(('adguard_rules', line), self.resolver.resolve(line))

    def test_hosts_rules_are_normalized_to_configured_ip(self) -> None:
        cases = (
            ('0.0.0.0 ads.example.com', f'{HOSTS_IP} ads.example.com'),
            ('127.0.0.1 ads.example.com', f'{HOSTS_IP} ads.example.com'),
            ('::1 ads.example.com', f'{HOSTS_IP} ads.example.com'),
            ('ads.example.com', f'{HOSTS_IP} ads.example.com'),
            ('127.0.0.1 ads.example.com  # 注释', f'{HOSTS_IP} ads.example.com'),
        )
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertEqual(('hosts_rules', expected), self.resolver.resolve(line))

    def test_localhost_and_ip_targets_are_not_block_rules(self) -> None:
        for line in ('0.0.0.0 localhost', '127.0.0.1 localhost.localdomain', '0.0.0.0 1.2.3.4'):
            with self.subTest(line=line):
                self.assertEqual((None, None), self.resolver.resolve(line))

    def test_real_ip_pinning_lines_are_not_blocks(self) -> None:
        # `8.8.8.8 dns.example.com` 这类"把域名钉到真实 IP"的条目不是拦截规则，
        # 归一化成 0.0.0.0 会改变语义，因此必须丢弃
        self.assertEqual((None, None), self.resolver.resolve('8.8.8.8 dns.example.com'))


if __name__ == '__main__':
    unittest.main()