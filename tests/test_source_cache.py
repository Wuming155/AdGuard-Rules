"""SourceCache 测试 — 只有提交才生效，临时文件不残留，索引可持久化"""

import tempfile
import unittest
from pathlib import Path

from src.source_cache import SourceCache


class TestSourceCache(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cache_dir = str(Path(tmp.name) / 'sources')

    @staticmethod
    def _tmp_files(directory: str) -> list[str]:
        return sorted(p.name for p in Path(directory).iterdir() if p.name.endswith('.tmp'))

    def test_committed_content_is_readable_and_persisted(self) -> None:
        cache = SourceCache(self.cache_dir)
        with cache.writer('http://x/a.txt') as writer:
            writer.write_line('||one.example^')
            writer.write_line('0.0.0.0 two.example')
            writer.commit(2)

        self.assertEqual(['||one.example^', '0.0.0.0 two.example'],
                         list(cache.read_lines('http://x/a.txt')))
        self.assertEqual(2, cache.entry('http://x/a.txt')['rules'])
        # 索引持久化：新实例（相当于下一次运行）仍能读到
        self.assertIsNotNone(SourceCache(self.cache_dir).entry('http://x/a.txt'))

    def test_uncommitted_writer_leaves_nothing_behind(self) -> None:
        cache = SourceCache(self.cache_dir)
        with cache.writer('http://x/b.txt') as writer:
            writer.write_line('||never.example^')

        self.assertIsNone(cache.read_lines('http://x/b.txt'))
        self.assertEqual([], self._tmp_files(self.cache_dir))

    def test_writer_discards_partial_content_on_error(self) -> None:
        cache = SourceCache(self.cache_dir)
        with self.assertRaises(RuntimeError):
            with cache.writer('http://x/c.txt') as writer:
                writer.write_line('||partial.example^')
                raise RuntimeError('boom')

        self.assertIsNone(cache.read_lines('http://x/c.txt'))
        self.assertEqual([], self._tmp_files(self.cache_dir))

    def test_deleted_cache_file_is_treated_as_no_cache(self) -> None:
        cache = SourceCache(self.cache_dir)
        with cache.writer('http://x/d.txt') as writer:
            writer.write_line('||gone.example^')
            writer.commit(1)

        cache.file_for('http://x/d.txt').unlink()
        self.assertIsNone(cache.entry('http://x/d.txt'))
        self.assertIsNone(cache.read_lines('http://x/d.txt'))


if __name__ == '__main__':
    unittest.main()