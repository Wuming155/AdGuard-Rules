"""RuleStore 测试 — 只读快照缓存必须随集合变更失效"""

import unittest

from src.rule_store import RuleStore


class TestRuleStoreSnapshots(unittest.TestCase):
    """get_collection 返回的快照不能滞留旧数据"""

    def test_snapshot_reflects_later_mutations(self) -> None:
        store = RuleStore()

        store.add_rule(RuleStore.R_TYPE_HOSTS, '0.0.0.0 a.com')
        self.assertEqual({'0.0.0.0 a.com'}, set(store.get_collection(RuleStore.R_TYPE_HOSTS)))

        store.add_rule(RuleStore.R_TYPE_HOSTS, '0.0.0.0 b.com')
        self.assertEqual(2, len(store.get_collection(RuleStore.R_TYPE_HOSTS)))

        store.replace_collection(RuleStore.R_TYPE_HOSTS, {'0.0.0.0 c.com'})
        self.assertEqual({'0.0.0.0 c.com'}, set(store.get_collection(RuleStore.R_TYPE_HOSTS)))

    def test_unknown_rule_type_is_ignored(self) -> None:
        store = RuleStore()
        store.add_rule('no_such_type', 'whatever')
        self.assertEqual(0, store.get_collection_size('no_such_type'))


if __name__ == '__main__':
    unittest.main()