"""共享缓存模块 — 下载规则源到本地，24 小时内复用"""

import json
import os
import time
from pathlib import Path

import requests

CACHE_DIR = Path(__file__).resolve().parent / 'cache'
CACHE_META_FILE = CACHE_DIR / '_meta.json'
CACHE_TTL = 24 * 3600  # 24 小时

# 代理配置（通过环境变量 HTTP_PROXY 设定，如 http://127.0.0.1:7890）
_PROXY = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')


def _ensure_cache_dir():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _load_meta() -> dict:
    if CACHE_META_FILE.exists():
        try:
            return json.loads(CACHE_META_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {}


def _save_meta(meta: dict):
    _ensure_cache_dir()
    CACHE_META_FILE.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')


def safe_filename(url: str) -> str:
    """将 URL 转成安全的文件名"""
    safe = url.replace('https://', '').replace('http://', '')
    safe = safe.replace('/', '_').replace(':', '_').replace('?', '_').replace('&', '_')
    if len(safe) > 100:
        safe = safe[:100]
    return safe + '.txt'


def fetch(url: str, label: str = '') -> str | None:
    """获取规则源内容（优先读本地缓存）"""
    _ensure_cache_dir()
    meta = _load_meta()
    fname = safe_filename(url)
    cache_path = CACHE_DIR / fname
    now = time.time()

    # 检查缓存是否有效
    cached_info = meta.get(url)
    if cached_info and cache_path.exists():
        age = now - cached_info['timestamp']
        if age < CACHE_TTL:
            text = cache_path.read_text(encoding='utf-8')
            cnt = len(text.splitlines())
            print(f"缓存 ({cnt} 行, {age/3600:.0f} 小时前)")
            return text
        else:
            print(f"缓存过期 ({age/3600:.0f}h > 24h), 重新下载")

    # 重新下载
    try:
        proxies = {'http': _PROXY, 'https': _PROXY} if _PROXY else None
        resp = requests.get(url, timeout=120, proxies=proxies)
        if resp.status_code != 200:
            print(f"HTTP {resp.status_code}")
            return None
        text = resp.text
        cache_path.write_text(text, encoding='utf-8')
        meta[url] = {'timestamp': now, 'label': label, 'size': len(text)}
        _save_meta(meta)
        cnt = len(text.splitlines())
        print(f"下载 ({cnt} 行)")
        return text
    except Exception as e:
        print(f"失败: {e}")
        return None


def clear_cache():
    """清空所有缓存（手动调用）"""
    import shutil
    if CACHE_DIR.exists():
        shutil.rmtree(CACHE_DIR)
    print("缓存已清空")
