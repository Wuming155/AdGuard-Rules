"""构建基线 — 记录上一次成功发布的规则规模，供质量门禁比对"""

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class BuildBaseline:
    """上一次成功发布的各集合规模（JSON 文件，原子写入）。

    文件结构::

        {"schema": 1, "counts": {"adguard_rules": 3690142, ...}}

    schema 用于标记统计口径：聚合口径变化时（例如后续引入祖先域名压缩），
    提升 SCHEMA 即可让旧基线自动判为不可比、跳过规模比对，
    避免拿不同口径的数量直接比较而误报。

    load() 返回空字典时表示本次不做规模比对，具体原因见 status / detail
    （区分"文件不存在"与"存在但口径不兼容"）。
    """

    SCHEMA = 1

    # load() 的结果状态
    STATUS_MISSING = 'missing'          # 文件不存在（首次构建）
    STATUS_INCOMPATIBLE = 'incompatible'  # 文件存在但统计口径不兼容
    STATUS_UNREADABLE = 'unreadable'    # 文件存在但读取/解析失败
    STATUS_LOADED = 'loaded'            # 成功加载，可用于规模比对

    def __init__(self, path: str = 'cache/last_build.json'):
        self._path = Path(path)
        # 最近一次 load() 的结果
        self.status: str = self.STATUS_MISSING
        self.detail: str = ''

    def load(self) -> dict[str, int]:
        """读取基线；空字典表示本次不做规模比对（原因见 status / detail）。"""
        try:
            data = json.loads(self._path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            self._set(self.STATUS_MISSING, '')
            return {}
        except (OSError, ValueError) as e:
            self._set(self.STATUS_UNREADABLE, str(e))
            return {}

        if not isinstance(data, dict) or data.get('schema') != self.SCHEMA:
            found = data.get('schema') if isinstance(data, dict) else None
            self._set(self.STATUS_INCOMPATIBLE, f'文件 schema={found}，当前 schema={self.SCHEMA}')
            return {}

        counts = data.get('counts')
        if not isinstance(counts, dict):
            self._set(self.STATUS_UNREADABLE, '缺少 counts 字段')
            return {}

        self._set(self.STATUS_LOADED, '')
        return {k: int(v) for k, v in counts.items() if isinstance(v, (int, float))}

    def save(self, counts: dict[str, int]) -> None:
        """写入基线（先临时文件再原子替换）。"""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = {'schema': self.SCHEMA, 'counts': counts}
        tmp = self._path.with_name(f"{self._path.name}.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding='utf-8')
        os.replace(tmp, self._path)

    def _set(self, status: str, detail: str) -> None:
        self.status = status
        self.detail = detail