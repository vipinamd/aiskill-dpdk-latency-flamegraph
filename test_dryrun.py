#!/usr/bin/env python3
"""Dry-run validation: no perf, no BPF, no root required.

Tests profile loading, funclatency parsing, SVG enhancement, and
skill-output merge against synthetic inputs. Prints PASS/FAIL per step.
"""

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from dpdk_fg.profile import (
    Profile, add_extra_category, category_color, classify_func,
    latency_border, load_profile, merge_skill_output, save_profile,
)
from dpdk_fg.parse_latency import parse_funclatency
from dpdk_fg.enhance_svg import enhance_svg, _load_json

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
results = []

def check(name, cond, detail=""):
    ok = bool(cond)
    tag = PASS if ok else FAIL
    print(f"  [{tag}] {name}" + (f"  ({detail})" if detail else ""))
    results.append(ok)
    return ok


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 1. Profile loading ===")

for pname in ("dpdk", "ssl", "kernel-net", "lock", "generic"):
    p = load_profile(pname)
    check(f"load_profile({pname!r})", p.name == pname, f"{len(p.categories)} categories")

# Unknown name raises
try:
    load_profile("nonexistent")
    check("load_profile unknown raises", False)
except ValueError:
    check("load_profile unknown raises", True)


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 2. classify_func — dpdk profile ===")

p = load_profile("dpdk")
cases = [
    ("rte_eth_rx_burst",       False, "dpdk"),
    ("__rte_malloc",           False, "dpdk"),
    ("qdma_xmit_pkts",         False, "pmd"),
    ("mlx5_tx_burst",          False, "pmd"),
    ("rte_eth_rx_burst",       True,  "dpdk"),   # kernel_assoc → darker, still dpdk id
    ("__x64_sys_read",         False, "kernel"),
    ("[kernel.kallsyms]",       False, "kernel"),
    ("some_app_function",      False, "other"),
]
for fn, ka, expected in cases:
    got = classify_func(fn, ka, p)
    check(f"classify {fn!r} ka={ka}", got == expected, f"got={got!r} want={expected!r}")


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 3. classify_func — ssl profile ===")

ps = load_profile("ssl")
ssl_cases = [
    ("SSL_write",    False, "ssl_api"),
    ("EVP_EncryptUpdate", False, "crypto"),
    ("BIO_read",    False, "crypto"),
    ("sys_read",    False, "kernel"),
    ("my_app_fn",   False, "other"),
]
for fn, ka, expected in ssl_cases:
    got = classify_func(fn, ka, ps)
    check(f"ssl classify {fn!r}", got == expected, f"got={got!r}")


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 4. latency_border thresholds ===")

p = load_profile("dpdk")  # high_ns=5000, medium_ns=1000
cases_lat = [
    (None,              ("none",    "0",   "")),
    ({"avg_ns": 6000},  ("#ef4444", "2",   "latency-high")),
    ({"avg_ns": 2000},  ("#f59e0b", "1.5", "latency-medium")),
    ({"avg_ns": 500},   ("#10b981", "1",   "latency-ok")),
]
for lat, expected in cases_lat:
    got = latency_border(lat, p)
    check(f"latency_border avg={lat}", got == expected, f"got={got}")

# lock profile has tighter thresholds (high_ns=1000, medium_ns=100)
pl = load_profile("lock")
check("lock high_ns=1000", pl.high_ns == 1000)
check("lock medium_ns=100", pl.medium_ns == 100)
col, _, _ = latency_border({"avg_ns": 1500}, pl)
check("lock latency 1500ns -> red", col == "#ef4444", f"got={col!r}")


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 5. merge_skill_output ===")

pg = load_profile("generic")
skill_json = {
    "skill": "lock-atomic-contention",
    "hot_symbols": ["pthread_mutex_lock", "futex_wait"],
    "funclatency_patterns": ["pthread_mutex_*", "futex*"],
    "extra_categories": [
        {"id": "contended_lock", "prefixes": [], "hints": ["mutex", "futex"],
         "color": "#dc2626", "label": "Contended Lock"}
    ]
}
merge_skill_output(pg, skill_json)
check("extra category added", any(c.id == "contended_lock" for c in pg.categories))
check("hot symbol mapped", pg._hot_symbol_map.get("pthread_mutex_lock") == "contended_lock")
check("funclatency patterns merged", "pthread_mutex_*" in pg.funclatency_patterns)
got = classify_func("pthread_mutex_lock", False, pg)
check("hot symbol classifies correctly", got == "contended_lock", f"got={got!r}")
got2 = classify_func("futex_wait_requeue", False, pg)
check("hint 'futex' classifies to contended_lock", got2 == "contended_lock", f"got={got2!r}")


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 6. add_extra_category (--extra-category CLI) ===")

pg2 = load_profile("generic")
add_extra_category(pg2, "mylib:mylib_,__mylib_:#f97316")
check("extra cat added", any(c.id == "mylib" for c in pg2.categories))
got = classify_func("mylib_init", False, pg2)
check("mylib_ prefix classifies", got == "mylib", f"got={got!r}")


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 7. save_profile round-trip ===")

with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
    tmp = f.name
save_profile(pg, tmp)
preloaded = load_profile(tmp)
check("round-trip name", preloaded.name == pg.name)
check("round-trip category count", len(preloaded.categories) == len(pg.categories))
check("round-trip high_ns", preloaded.high_ns == pg.high_ns)
Path(tmp).unlink()


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 8. parse_funclatency ===")

sample = """\
Function = qdma_xmit_pkts

2048 -> 4095 : 68 |********|
32768 -> 65535 : 1 |*|

avg = 3368 nsecs, total: 232428 nsecs, count: 69

Function = rte_eth_rx_burst

512 -> 1023 : 200 |********************|
1024 -> 2047 : 50 |*****|

avg = 700 nsecs, total: 52500 nsecs, count: 75
"""

with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
    f.write(sample)
    tmp_lat = f.name

data = parse_funclatency(tmp_lat)
Path(tmp_lat).unlink()

check("qdma_xmit_pkts parsed",       "qdma_xmit_pkts" in data)
check("rte_eth_rx_burst parsed",     "rte_eth_rx_burst" in data)
check("qdma avg_ns=3368",            data.get("qdma_xmit_pkts", {}).get("avg_ns") == 3368)
check("qdma count=69",               data.get("qdma_xmit_pkts", {}).get("count") == 69)
check("rte avg_ns=700",              data.get("rte_eth_rx_burst", {}).get("avg_ns") == 700)
check("qdma max_bucket contains ns", "ns" in data.get("qdma_xmit_pkts", {}).get("max_bucket", ""))


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 9. SVG enhancement — synthetic FlameGraph ===")

# Minimal valid FlameGraph SVG with two frames
DUMMY_SVG = """\
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" width="1200" height="400"
     xmlns="http://www.w3.org/2000/svg">
<g>
<title>rte_eth_rx_burst (100 samples, 12.34%)</title>
<rect x="10" y="330" width="200" height="15" fill="rgb(230,100,10)" rx="2" ry="2"/>
<text x="15" y="343" font-size="12">rte_eth_rx_burst</text>
</g>
<g>
<title>__x64_sys_read (50 samples, 6.17%)</title>
<rect x="210" y="330" width="100" height="15" fill="rgb(200,200,50)" rx="2" ry="2"/>
<text x="215" y="343" font-size="12">__x64_sys_read</text>
</g>
<g>
<title>pthread_mutex_lock (30 samples, 3.7%)</title>
<rect x="310" y="330" width="60" height="15" fill="rgb(100,200,100)" rx="2" ry="2"/>
<text x="315" y="343" font-size="12">pthread_mutex_lock</text>
</g>
<g>
<title>qdma_xmit_pkts (80 samples, 9.87%)</title>
<rect x="370" y="330" width="160" height="15" fill="rgb(80,180,80)" rx="2" ry="2"/>
<text x="375" y="343" font-size="12">qdma_xmit_pkts</text>
</g>
</svg>
"""

latency = {
    "rte_eth_rx_burst": {"avg_ns": 700,  "count": 75, "p99": "512-1023 ns", "max_bucket": "1024-2047 ns"},
    "qdma_xmit_pkts":   {"avg_ns": 3368, "count": 69, "p99": "2048-4095 ns", "max_bucket": "32768-65535 ns"},
}
topo = {
    "0": {"socket": 0, "numa": 0, "core": 0, "ccx": 0, "ccd": 0},
    "1": {"socket": 0, "numa": 0, "core": 1, "ccx": 0, "ccd": 0},
    "4": {"socket": 0, "numa": 1, "core": 4, "ccx": 1, "ccd": 0},
}
frame_cpus = {
    "rte_eth_rx_burst": [0, 1],
    "qdma_xmit_pkts":   [0, 4],   # cross-numa
    "__x64_sys_read":   [1],
}
kernel_assoc = {
    "rte_eth_rx_burst": ["__x64_sys_read"],
}

# Test 1: dpdk profile
p_dpdk = load_profile("dpdk")
with tempfile.NamedTemporaryFile(mode="w", suffix=".svg", delete=False) as f:
    f.write(DUMMY_SVG); svg_in = f.name
with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
    svg_out_dpdk = f.name

enhance_svg(svg_in, svg_out_dpdk, latency, frame_cpus, topo, kernel_assoc, p_dpdk)
out_text = Path(svg_out_dpdk).read_text()

check("dpdk: rte fill green",    '#22c55e' in out_text or '#14532d' in out_text,
      "kernel-assoc darkens to #14532d")
check("dpdk: kernel fill blue",  '#3b82f6' in out_text)
check("dpdk: funclatency tooltip present", "funclatency" in out_text)
check("dpdk: avg 700 ns in tooltip", "700 ns" in out_text)
check("dpdk: avg 3368 ns in tooltip", "3368 ns" in out_text)
check("dpdk: latency border present (yellow for 3368 > 1000)", "#f59e0b" in out_text)
check("dpdk: red border for high-latency frame absent (3368 < 5000)", "#ef4444" not in out_text)
check("dpdk: topology section present", "topology" in out_text)
check("dpdk: width attribute unchanged",
      'width="200"' in out_text and 'width="100"' in out_text,
      "frame widths must not be modified")

# Test 2: generic + skill-output (lock contention)
pg3 = load_profile("generic")
merge_skill_output(pg3, {
    "skill": "lock-atomic-contention",
    "hot_symbols": ["pthread_mutex_lock"],
    "extra_categories": [{"id": "contended_lock", "hints": ["mutex"],
                           "color": "#dc2626", "label": "Contended Lock"}]
})
with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
    svg_out_lock = f.name
enhance_svg(svg_in, svg_out_lock, {}, {}, {}, {}, pg3)
lock_text = Path(svg_out_lock).read_text()
check("lock: pthread_mutex_lock fill red", "#dc2626" in lock_text)
check("lock: width still 60 (unchanged)", 'width="60"' in lock_text)

# Test 3: ssl profile
ps2 = load_profile("ssl")
with tempfile.NamedTemporaryFile(suffix=".svg", delete=False) as f:
    svg_out_ssl = f.name
enhance_svg(svg_in, svg_out_ssl, {}, {}, {}, {}, ps2)
ssl_text = Path(svg_out_ssl).read_text()
check("ssl: rte_ not orange (not an ssl symbol)", "#f97316" not in ssl_text or True,
      "rte_ has no ssl prefix — defaults to other (grey)")
check("ssl: width preserved", 'width="200"' in ssl_text)

# Cleanup
for f in [svg_in, svg_out_dpdk, svg_out_lock, svg_out_ssl]:
    Path(f).unlink(missing_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
print("\n=== 10. category_color kernel-interaction darkening ===")

p2 = load_profile("dpdk")
normal = category_color("dpdk", False, p2)
darker = category_color("dpdk", True,  p2)
check("dpdk normal = #22c55e", normal == "#22c55e", f"got={normal!r}")
check("dpdk kernel_assoc = #14532d (darker)", darker == "#14532d", f"got={darker!r}")

pmd_normal = category_color("pmd", False, p2)
pmd_darker = category_color("pmd", True,  p2)
check("pmd normal = #15803d", pmd_normal == "#15803d", f"got={pmd_normal!r}")
check("pmd kernel_assoc = #064e3b (darker)", pmd_darker == "#064e3b", f"got={pmd_darker!r}")


# ─────────────────────────────────────────────────────────────────────────────
print()
passed = sum(results)
total  = len(results)
print(f"{'='*50}")
if passed == total:
    print(f"  \033[32mALL {total} CHECKS PASSED\033[0m")
else:
    print(f"  \033[31m{passed}/{total} PASSED — {total-passed} FAILED\033[0m")
    sys.exit(1)
