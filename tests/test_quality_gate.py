"""质量门禁与构建基线测试 — 只拦"整体不可用"，个别源失败不阻止发布"""

import json
import tempfile
import unittest
from pathlib import Path

from main_executor import record_baseline
from src.build_baseline import BuildBaseline
from src.main import BuildQualityError, QualityGateStep
from src.rule_store import RuleStore


class _FetcherStub:
    """只提供 degraded_sources()，避免门禁测试依赖真实拉取"""

    def __init__(self, degraded: list[dict] | None = None):
        self._degraded = degraded or []

    def degraded_sources(self) -> list[dict]:
        return self._degraded


def _store_with(adguard: int, hosts: int) -> RuleStore:
    store = RuleStore()
    for i in range(adguard):
        store.add_rule(RuleStore.R_TYPE_ADGUARD, f'||a{i}.example^')
    for i in range(hosts):
        store.add_rule(RuleStore.R_TYPE_HOSTS, f'0.0.0.0 h{i}.example')
    return store


class QualityGateTestCase(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp_dir = Path(tmp.name)
        self.baseline_path = str(self.tmp_dir / 'last_build.json')
        self.baseline = BuildBaseline(self.baseline_path)

    def gate(self, store: RuleStore, degraded: list[dict] | None = None) -> QualityGateStep:
        return QualityGateStep(store, self.baseline, _FetcherStub(degraded))


class TestQualityGate(QualityGateTestCase):
    def test_empty_base_rules_block_publish(self) -> None:
        with self.assertRaises(BuildQualityError) as ctx:
            self.gate(RuleStore()).execute()

        self.assertIn('为空', str(ctx.exception))

    def test_error_message_lists_degraded_sources(self) -> None:
        degraded = [{'status': 'skipped', 'url': 'http://x/gone.txt', 'reason': 'HTTP 404', 'rules': 0}]
        with self.assertRaises(BuildQualityError) as ctx:
            self.gate(RuleStore(), degraded).execute()

        self.assertIn('http://x/gone.txt', str(ctx.exception))

    def test_severe_shrink_blocks_publish(self) -> None:
        self.baseline.save({RuleStore.R_TYPE_ADGUARD: 1000, RuleStore.R_TYPE_HOSTS: 100})

        with self.assertRaises(BuildQualityError) as ctx:
            self.gate(_store_with(adguard=400, hosts=100)).execute()

        self.assertIn('异常收缩', str(ctx.exception))

    def test_partial_source_failure_still_publishes(self) -> None:
        self.baseline.save({RuleStore.R_TYPE_ADGUARD: 1000, RuleStore.R_TYPE_HOSTS: 100})
        degraded = [{'status': 'cache', 'url': 'http://x/flaky.txt', 'reason': 'HTTP 503',
                     'rules': 80, 'cached_at': '2026-10-23 13:00:00'}]

        # 轻微下降（5%/10%）属于可解释的正常波动，不应阻止发布
        self.gate(_store_with(adguard=950, hosts=90), degraded).execute()

    def test_first_publish_without_baseline_only_checks_presence(self) -> None:
        self.gate(_store_with(adguard=3, hosts=2)).execute()


class TestBaselineRecording(QualityGateTestCase):
    """基线由入口脚本在发布成功后记录（python main_executor.py --record-baseline）"""

    def test_baseline_written_from_dist_outputs(self) -> None:
        dist = self.tmp_dir / 'dist'
        dist.mkdir()
        (dist / 'adguard_rules.txt').write_text('||a.example^\n||b.example^\n', encoding='utf-8')
        (dist / 'hosts_rules.txt').write_text('0.0.0.0 c.example\n', encoding='utf-8')

        counts = record_baseline(str(dist), self.baseline_path)

        self.assertEqual(2, counts['adguard_rules'])
        self.assertEqual(1, counts['hosts_rules'])
        self.assertEqual(counts, self.baseline.load())

    def test_recorded_baseline_blocks_next_severe_drop(self) -> None:
        self.baseline.save({RuleStore.R_TYPE_ADGUARD: 1000, RuleStore.R_TYPE_HOSTS: 100})

        with self.assertRaises(BuildQualityError):
            self.gate(_store_with(adguard=100, hosts=100)).execute()


class TestBaselineSchema(QualityGateTestCase):
    """聚合口径变化（如后续引入祖先域名压缩）时自动跳过规模比对，避免误报"""

    def test_incompatible_schema_is_not_compared(self) -> None:
        path = Path(self.baseline_path)
        path.write_text(
            json.dumps({'schema': 0, 'counts': {RuleStore.R_TYPE_ADGUARD: 1000}}),
            encoding='utf-8',
        )

        self.assertEqual({}, self.baseline.load())
        # 口径不可比时只做基础校验，因此严重收缩也不会误拦
        self.gate(_store_with(adguard=1, hosts=1)).execute()

    def test_missing_schema_is_not_compared(self) -> None:
        Path(self.baseline_path).write_text(
            json.dumps({RuleStore.R_TYPE_ADGUARD: 1000}), encoding='utf-8')

        self.assertEqual({}, self.baseline.load())


if __name__ == '__main__':
    unittest.main()