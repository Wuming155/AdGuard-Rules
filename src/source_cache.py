"""规则源缓存 — 保存每个源最近一次成功拉取的原始内容，供拉取失败时回退"""

import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Iterator

logger = logging.getLogger(__name__)


class SourceCache:
    """按 URL 保存「最近一次成功」的响应内容。

    目录结构::

        <cache_dir>/<sha1(url)[:16]>.txt   该源的原始响应内容
        <cache_dir>/index.json             {url: {file, fetched_at, rules}}

    缓存写入始终先落到 .tmp 再原子替换，中途失败不会留下半截缓存；
    索引同样以临时文件 + 原子替换更新。
    """

    _INDEX_NAME = 'index.json'

    def __init__(self, cache_dir: str = 'cache/sources'):
        self._dir = Path(cache_dir)
        self._index: dict[str, dict] = self._read_index()

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def file_for(self, url: str) -> Path:
        """该 URL 对应的缓存文件路径。"""
        digest = hashlib.sha1(url.encode('utf-8')).hexdigest()[:16]
        return self._dir / f"{digest}.txt"

    def entry(self, url: str) -> dict | None:
        """返回缓存元信息；无缓存或缓存文件缺失时返回 None。"""
        meta = self._index.get(url)
        if not meta:
            return None
        if not (self._dir / meta['file']).exists():
            return None
        return meta

    def read_lines(self, url: str) -> Iterator[str] | None:
        """读取缓存内容的行迭代器；无可用缓存时返回 None。"""
        meta = self.entry(url)
        if meta is None:
            return None
        return self._iter_file(self._dir / meta['file'])

    @staticmethod
    def _iter_file(path: Path) -> Iterator[str]:
        with path.open('r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                yield line.rstrip('\n')

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def writer(self, url: str) -> '_CacheWriter':
        """打开一个流式写入器；必须显式 commit() 才会替换正式缓存。"""
        return _CacheWriter(self, url, self.file_for(url))

    def record(self, url: str, rules: int) -> None:
        """登记缓存元信息（由 _CacheWriter.commit 调用）。"""
        self._index[url] = {
            'file': self.file_for(url).name,
            'fetched_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'rules': rules,
        }
        self._dir.mkdir(parents=True, exist_ok=True)
        tmp = self._dir / f"{self._INDEX_NAME}.tmp"
        tmp.write_text(json.dumps(self._index, ensure_ascii=False, indent=1), encoding='utf-8')
        os.replace(tmp, self._dir / self._INDEX_NAME)

    def _read_index(self) -> dict[str, dict]:
        try:
            return json.loads((self._dir / self._INDEX_NAME).read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            logger.warning("源缓存索引读取失败（%s），本次按空缓存处理: %s", self._dir, e)
            return {}


class _CacheWriter:
    """流式写入缓存：commit() 才原子替换，否则丢弃临时文件。"""

    def __init__(self, cache: SourceCache, url: str, target: Path):
        self._cache = cache
        self._url = url
        self._target = target
        self._tmp = target.with_name(f"{target.name}.tmp")
        self._tmp.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self._tmp.open('w', encoding='utf-8', newline='\n')
        self._committed = False

    def write_line(self, line: str) -> None:
        self._fh.write(line)
        self._fh.write('\n')

    def commit(self, rules: int) -> None:
        """落盘并原子替换正式缓存，同时更新索引。"""
        self._fh.close()
        os.replace(self._tmp, self._target)
        self._cache.record(self._url, rules)
        self._committed = True

    def __enter__(self) -> '_CacheWriter':
        return self

    def __exit__(self, *exc_info) -> bool:
        if not self._fh.closed:
            self._fh.close()
        if not self._committed:
            self._tmp.unlink(missing_ok=True)
        return False