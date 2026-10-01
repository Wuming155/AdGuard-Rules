"""综合分析 — 分别分析 AdGuard 和 Hosts 两类规则源的重复情况

使用方法:
    cd 项目根目录
    python analysis/analyze_overlap.py

说明:
    - 优先读取 analysis/cache/ 内的缓存（24 小时内有效）
    - 缓存过期或不存在时自动重新下载
"""

import sys
from pathlib import Path

from _cache import fetch
from _analyze import analyze_category, read_source_urls

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILES = {
    'AdGuard': PROJECT_ROOT / 'sources' / 'sources_adguard.txt',
    'Hosts':   PROJECT_ROOT / 'sources' / 'sources_host.txt',
}

SEP = '=' * 60


def main():
    for cat, fpath in SOURCE_FILES.items():
        urls = read_source_urls(fpath)
        if urls is None:
            continue
        print(f"\n{SEP}")
        print(f"  {cat} 规则源 — {len(urls)} 个源")
        print(f"{SEP}")

        all_data = {}
        for url in urls:
            label = url.rstrip('/').split('/')[-1][:35]
            sys.stdout.write(f"  [{label:<30s}] ")
            sys.stdout.flush()
            content = fetch(url, label)
            if content is None:
                continue
            from _analyze import extract_domains
            domains = extract_domains(content)
            all_data[label] = domains

        if len(all_data) >= 2:
            analyze_category(cat, all_data)
        else:
            print(f"  至少需要 2 个源才能分析（当前 {len(all_data)} 个）")


if __name__ == '__main__':
    main()
