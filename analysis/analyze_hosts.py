"""分析 Hosts 规则源之间的重复情况

使用方法:
    cd 项目根目录
    python analysis/analyze_hosts.py

说明:
    - 优先读取 analysis/cache/ 内的缓存（24 小时内有效）
    - 缓存过期或不存在时自动重新下载
"""

import sys
from pathlib import Path

from _cache import fetch
from _analyze import analyze_category, read_source_urls, extract_domains

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILE = PROJECT_ROOT / 'sources' / 'sources_host.txt'


def main():
    urls = read_source_urls(SOURCE_FILE)
    if urls is None:
        return

    print(f"\n{'=' * 60}")
    print(f"  Hosts 规则源分析 — {len(urls)} 个源")
    print(f"{'=' * 60}")

    all_data = {}
    for url in urls:
        label = url.rstrip('/').split('/')[-1]
        if len(label) > 35:
            label = label[:35]
        sys.stdout.write(f"  [{label:<30s}] ")
        sys.stdout.flush()
        content = fetch(url, label)
        if content is None:
            continue
        domains = extract_domains(content)
        all_data[label] = domains

    if len(all_data) >= 2:
        analyze_category('Hosts', all_data)
    else:
        print(f"  至少需要 2 个源才能分析（当前 {len(all_data)} 个）")


if __name__ == '__main__':
    main()
