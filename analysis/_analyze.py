"""共享分析模块 — 域名提取、源文件读取、分析报告输出"""

import re
from pathlib import Path
from typing import Optional

HOSTS_IP_RE = re.compile(r'^(?:0\.0\.0\.0|127\.0\.0\.1|::(?:1)?)\s+([^\s#]+)')
DOMAIN_RE   = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$')


def extract_domains(text: str) -> set[str]:
    """从规则文本中提取域名集合（兼容 hosts / AdGuard / 纯域名三种格式）"""
    domains = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('!', '#', '/')):
            continue
        # hosts 格式: 0.0.0.0 domain
        m = HOSTS_IP_RE.match(line)
        if m:
            d = m.group(1).lower()
            if DOMAIN_RE.match(d):
                domains.add(d)
            continue
        # AdGuard 格式: ||domain^
        if line.startswith('||'):
            s = line[2:]
            for c in ('^', '$', '/'):
                idx = s.find(c)
                if idx != -1:
                    s = s[:idx]
            if DOMAIN_RE.match(s):
                domains.add(s.lower())
            continue
        # 纯域名
        d = line.lower()
        if DOMAIN_RE.match(d):
            domains.add(d)
    return domains


def read_source_urls(fpath: Path) -> Optional[list[str]]:
    """从源文件读取 URL 列表。返回 None 表示文件不存在或没有 URL。"""
    if not fpath.exists():
        print(f"\n[跳过] 源文件不存在: {fpath}")
        return None
    urls = [
        line.strip() for line in fpath.read_text(encoding='utf-8').splitlines()
        if line.strip().startswith(('http://', 'https://'))
    ]
    if not urls:
        print(f"\n[跳过] 源文件中没有 URL: {fpath}")
        return None
    return urls


def analyze_category(cat_name: str, all_data: dict[str, set[str]]) -> None:
    """分析同类别内各源的重复情况并输出报告"""
    names = sorted(all_data.keys(), key=lambda n: -len(all_data[n]))

    # ---- 两两重叠 ----
    print(f"\n  {'─' * 56}")
    print(f"  重复分析")
    print(f"  {'─' * 56}")
    has_overlap = False
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            sa, sb = all_data[a], all_data[b]
            overlap = sa & sb
            if not overlap:
                continue
            has_overlap = True
            ra = len(overlap) / len(sa) * 100
            rb = len(overlap) / len(sb) * 100
            print(f"  {a:<30s}  vs  {b}")
            print(f"  {'':30s}  重叠 {len(overlap):>10,}  |  {a} 的 {ra:5.1f}%  |  {b} 的 {rb:5.1f}%")
    if not has_overlap:
        print("  （各源之间无重叠）")

    # ---- 总体统计 ----
    total_sum = sum(len(s) for s in all_data.values())
    total_union = set().union(*all_data.values())
    total_overlap = total_sum - len(total_union)
    print(f"\n  {'─' * 56}")
    print(f"  各源合计:     {total_sum:>10,}")
    print(f"  去重后唯一:   {len(total_union):>10,}")
    print(f"  重复域名:     {total_overlap:>10,}  ({total_overlap/total_sum*100:.1f}%)")

    # ---- 各源独有 ----
    print(f"\n  {'─' * 56}")
    print(f"  各源独有（其他源都没有的）")
    print(f"  {'─' * 56}")
    for n in names:
        others = set().union(*(all_data[o] for o in names if o != n))
        unique = all_data[n] - others
        pct = len(unique) / len(all_data[n]) * 100
        print(f"  {n:<30s}  独有 {len(unique):>8,}  ({pct:5.1f}%)")
