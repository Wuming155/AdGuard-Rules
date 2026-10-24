"""RuleFetcher 测试 — 单源超限/失败必须被记录，不能静默丢弃"""

import unittest

from src.config import PathConfig, RuleConfig
from src.rule_fetcher import RuleFetcher
from src.rule_resolver import RuleResolver
from src.rule_store import RuleStore
from src.sources_reader import SourcesReader


class _FakeResponse:
    """requests.Response 的最小替身（只需迭代行 + 上下文管理）"""

    def __init__(self, status_code: int = 200, lines: tuple[str, ...] = ()):
        self.status_code = status_code
        self._lines = lines

    def __enter__(self) -> '_FakeResponse':
        return self

    def __exit__(self, *exc_info) -> bool:
        return False

    def iter_lines(self, chunk_size: int = 512):
        for line in self._lines:
            yield line.encode('utf-8')


class _FakeSession:
    def __init__(self, response: _FakeResponse):
        self._response = response

    def get(self, url: str, timeout=None, stream: bool = False) -> _FakeResponse:
        return self._response


class TestRuleFetcher(unittest.TestCase):
    """直接驱动单源处理逻辑（避免测试依赖外网）"""

    def setUp(self) -> None:
        self.store = RuleStore()
        self.fetcher = RuleFetcher(
            sources_reader=SourcesReader(),
            resolver=RuleResolver(RuleConfig()),
            rule_store=self.store,
            path_config=PathConfig(),
            max_response_size=1024 * 1024,  # 1MB，便于构造超限场景
        )

    def _process(self, response: _FakeResponse, url: str, is_lite: bool = False, is_host: bool = False) -> None:
        self.fetcher._process_single_source(_FakeSession(response), url, is_host, is_lite, 1, 1)

    def test_source_over_size_limit_is_reported(self) -> None:
        lines = tuple(f'||oversized-{i:07d}.example^' for i in range(40000))  # 约 1.3MB
        self._process(_FakeResponse(200, lines), 'http://example.test/big.txt')

        self.assertEqual([('http://example.test/big.txt', '响应体超过 1MB 上限')],
                         self.fetcher.problem_sources)
        self.assertEqual(1, self.fetcher.fetch_stats['truncated'])
        # 超限即停止读取：只可能写入截断前的部分规则
        self.assertLess(self.store.get_collection_size(RuleStore.R_TYPE_ADGUARD), len(lines))

    def test_http_error_is_reported(self) -> None:
        self._process(_FakeResponse(404), 'http://example.test/gone.txt')

        self.assertEqual([('http://example.test/gone.txt', 'HTTP 404')], self.fetcher.problem_sources)
        self.assertEqual(1, self.fetcher.fetch_stats['failed'])

    def test_fetched_rules_land_in_full_collections(self) -> None:
        self._process(_FakeResponse(200, ('||ads.example.com^', '0.0.0.0 tracker.example.com')), 'http://example.test/ok.txt')

        self.assertIn('||ads.example.com^', self.store.get_collection(RuleStore.R_TYPE_ADGUARD))
        self.assertIn('0.0.0.0 tracker.example.com', self.store.get_collection(RuleStore.R_TYPE_HOSTS))
        self.assertEqual([], self.fetcher.problem_sources)

    def test_lite_source_lands_only_in_lite_collections(self) -> None:
        self._process(_FakeResponse(200, ('||ads.example.com^', '0.0.0.0 tracker.example.com')), 'http://example.test/lite.txt', is_lite=True)

        self.assertEqual(0, self.store.get_collection_size(RuleStore.R_TYPE_ADGUARD))
        self.assertEqual(0, self.store.get_collection_size(RuleStore.R_TYPE_HOSTS))
        self.assertIn('||ads.example.com^', self.store.get_collection(RuleStore.R_TYPE_ADGUARD_LITE))
        self.assertIn('0.0.0.0 tracker.example.com', self.store.get_collection(RuleStore.R_TYPE_HOSTS_LITE))


if __name__ == '__main__':
    unittest.main()