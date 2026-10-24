"""构建基线 — 记录上一次成功发布的规则规模，供质量门禁比对"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class BuildBaseline:
    """上一次成功发布的各集合规模（JSON 文件，原子写入）。

    文件中带 schema 版本：规则聚合口径变化时（例如后续引入祖先域名压缩），
    只要同步提升 _SCHEMA，旧基线就会被判为不可比，门禁自动跳过规模比对，
    避免拿压缩前后的数量直接比较而误报。
    """

    _SCHEMA = 1

    def __init__(self, path: str = 'cache/last_build.json'):
        self._path = Path(path)

    def load(self) -> dict[str, int]:
        """读取基线；不存在、损坏或口径不一致时返回空字典（本次跳过规模比对）。"""
        try:
            data = json.loads(self._path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            logger.warning("构建基线读取失败（%s），本次不做规模比对: %s", self._path, e)
            return {}

        if not isinstance(data, dict) or data.get('schema') != self._SCHEMA:
            logger.info("构建基线口径与当前不一致（%s），本次跳过规模比对", self._path)
            return {}

        counts = data.get('counts')
        if not isinstance(counts, dict):
            logger.warning("构建基线格式异常（%s），本次不做规模比对", self._path)
            return {}
        return {k: int(v) for k, v in counts.items() if isinstance(v, (int, float))}

    def save(self, counts: dict[str, int]) -> None:
        """写入基线（先临时文件再原子替换）。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {'schema': self._SCHEMA, 'counts': counts}
        tmp = self._path.with_name(f"{self._path.name}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding='utf-8')
        os.replace(tmp, self._path)