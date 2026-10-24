"""RuleFetcher 测试 — 单源失败必须容错：回退缓存或跳过，且状态可查"""

import tempfile
import unittest
from pathlib import Path

from src.config import PathConfig, RuleConfig
from src.rule_fetcher import RuleFetcher
from src.rule_resolver import RuleResolver
from src.rule_store import RuleStore
from src.sources_reader import SourcesReader
from src.source_cache import SourceCache


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


class RuleFetcherTestCase(unittest.TestCase):
    """公共夹具：临时缓存目录 + 便于构造超限场景的 1MB 上限"""

    MAX_RESPONSE_SIZE = 1024 * 1024

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache_dir = str(Path(tmp.name) / 'sources')
        self.fetcher = self.new_fetcher(RuleStore())

    def new_fetcher(self, store: RuleStore) -> RuleFetcher:
        """模拟"下一次运行"：同一缓存目录、新的规则容器"""
        return RuleFetcher(
            sources_reader=SourcesReader(),
            resolver=RuleResolver(RuleConfig()),
            rule_store=store,
            path_config=PathConfig(source_cache_dir=self.cache_dir),
            max_response_size=self.MAX_RESPONSE_SIZE,
        )

    def process(self, response: _FakeResponse, url: str,
                is_lite: bool = False, is_host: bool = False,
                fetcher: RuleFetcher | None = None) -> None:
        fetcher = fetcher or self.fetcher
        fetcher._process_single_source(_FakeSession(response), url, is_host, is_lite, 1, 1)

    @staticmethod
    def oversized_lines() -> tuple[str, ...]:
        return tuple(f'||oversized-{i:07d}.example^' for i in range(40000))  # 约 1.3MB


class TestSuccessfulFetch(RuleFetcherTestCase):
    def test_rules_land_in_full_collections_and_cache(self) -> None:
        self.process(_FakeResponse(200, ('||ads.example.com^', '0.0.0.0 tracker.example.com')),
                     'http://x/ok.txt')

        self.assertIn('||ads.example.com^', self.fetcher._store.get_collection(RuleStore.R_TYPE_ADGUARD))
        self.assertIn('0.0.0.0 tracker.example.com', self.fetcher._store.get_collection(RuleStore.R_TYPE_HOSTS))
        self.assertEqual('ok', self.fetcher.source_status[0]['status'])
        # 成功拉取后写入缓存，供后续回退
        self.assertIsNotNone(SourceCache(self.cache_dir).entry('http://x/ok.txt'))

    def test_lite_source_lands_only_in_lite_collections(self) -> None:
        self.process(_FakeResponse(200, ('||ads.example.com^', '0.0.0.0 tracker.example.com')),
                     'http://x/lite.txt', is_lite=True)

        store = self.fetcher._store
        self.assertEqual(0, store.get_collection_size(RuleStore.R_TYPE_ADGUARD))
        self.assertEqual(0, store.get_collection_size(RuleStore.R_TYPE_HOSTS))
        self.assertIn('||ads.example.com^', store.get_collection(RuleStore.R_TYPE_ADGUARD_LITE))
        self.assertIn('0.0.0.0 tracker.example.com', store.get_collection(RuleStore.R_TYPE_HOSTS_LITE))


class TestFaultTolerance(RuleFetcherTestCase):
    """单个源失败不得中止构建"""

    def test_http_error_without_cache_is_skipped_with_reason(self) -> None:
        self.process(_FakeResponse(404), 'http://x/gone.txt')

        entry = self.fetcher.source_status[0]
        self.assertEqual('skipped', entry['status'])
        self.assertIn('HTTP 404', entry['reason'])
        self.assertIn('无可用缓存', entry['reason'])

    def test_oversized_source_is_skipped_with_reason(self) -> None:
        self.process(_FakeResponse(200, self.oversized_lines()), 'http://x/big.txt')

        entry = self.fetcher.source_status[0]
        self.assertEqual('skipped', entry['status'])
        self.assertIn('响应体超过 1MB 上限', entry['reason'])
        # 半途超限的源不得把已经解析到的部分规则留在集合里
        self.assertEqual(0, self.fetcher._store.get_collection_size(RuleStore.R_TYPE_ADGUARD))

    def test_failure_falls_back_to_last_successful_cache(self) -> None:
        url = 'http://x/flaky.txt'
        self.process(_FakeResponse(200, ('||cached-one.example^', '||cached-two.example^')), url)
        cached = set(self.fetcher._store.get_collection(RuleStore.R_TYPE_ADGUARD))
        self.assertEqual(2, len(cached))

        # 下一次运行：该源 503，应从缓存回退，规则照旧可用
        next_store = RuleStore()
        next_fetcher = self.new_fetcher(next_store)
        self.process(_FakeResponse(503), url, fetcher=next_fetcher)

        entry = next_fetcher.source_status[0]
        self.assertEqual('cache', entry['status'])
        self.assertIn('HTTP 503', entry['reason'])
        self.assertEqual(cached, set(next_store.get_collection(RuleStore.R_TYPE_ADGUARD)))

    def test_oversized_source_falls_back_to_cache_too(self) -> None:
        url = 'http://x/big-flaky.txt'
        self.process(_FakeResponse(200, ('||small.example^',)), url)

        next_store = RuleStore()
        next_fetcher = self.new_fetcher(next_store)
        self.process(_FakeResponse(200, self.oversized_lines()), url, fetcher=next_fetcher)

        entry = next_fetcher.source_status[0]
        self.assertEqual('cache', entry['status'])
        self.assertEqual({'||small.example^'}, set(next_store.get_collection(RuleStore.R_TYPE_ADGUARD)))

    def test_degraded_sources_lists_only_problem_sources(self) -> None:
        self.process(_FakeResponse(200, ('||ok.example^',)), 'http://x/a.txt')
        self.process(_FakeResponse(404), 'http://x/b.txt')

        self.assertEqual(['http://x/b.txt'],
                         [s['url'] for s in self.fetcher.degraded_sources()])


if __name__ == '__main__':
    unittest.main()