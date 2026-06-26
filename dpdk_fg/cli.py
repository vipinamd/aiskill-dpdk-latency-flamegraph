#!/usr/bin/env python3
"""One-command DPDK topology + latency FlameGraph enhancer.

Prototype CLI:
- collects topology, thread placement, IRQ snapshots
- runs perf record
- optionally runs funclatency patterns in parallel
- creates base FlameGraph
- parses latency and CPU placement
- enhances SVG with DPDK coloring, latency, topology, kernel interaction
"""

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

DPDK_PATTERNS = ("rte_", "__rte_")
PMD_HINTS = ("rx", "tx", "burst", "qdma", "mlx5", "bnxt", "iavf", "ice", "ena", "sfc")
KERNEL_HINTS = (
    "sys_", "__x64_sys", "ioctl", "read", "write", "mmap", "munmap",
    "epoll", "eventfd", "vfio", "uio", "irq", "softirq", "napi",
    "net_rx_action", "__softirqentry", "schedule", "fput", "sock_"
)

COLORS = {
    "dpdk": "#22c55e",
    "dpdk_kernel": "#14532d",
    "pmd": "#15803d",
    "pmd_kernel": "#064e3b",
    "kernel": "#3b82f6",
    "other": "#9ca3af",
}


def run(cmd, *, cwd=None, stdout=None, stderr=None, check=True):
    print("[cmd]", " ".join(shlex.quote(str(x)) for x in cmd))
    return subprocess.run(cmd, cwd=cwd, stdout=stdout, stderr=stderr, check=check, text=True)


def popen(cmd, *, cwd=None, stdout=None, stderr=None):
    print("[bg]", " ".join(shlex.quote(str(x)) for x in cmd))
    return subprocess.Popen(cmd, cwd=cwd, stdout=stdout, stderr=stderr, text=True)


def normalize_func(name: str) -> str:
    name = name.strip()
    name = name.split("+")[0]
    name = name.replace("@plt", "")
    return name


def is_kernel_func(fn):
    return any(k in fn for k in KERNEL_HINTS) or "[kernel.kallsyms]" in fn


def classify_func(fn, kernel_associated=False):
    if is_kernel_func(fn):
        return "kernel"
    if fn.startswith(DPDK_PATTERNS):
        return "dpdk_kernel" if kernel_associated else "dpdk"
    if any(h in fn.lower() for h in PMD_HINTS):
        return "pmd_kernel" if kernel_associated else "pmd"
    return "other"


def collect_static(pid, outdir):
    with open(outdir / "lscpu.txt", "w") as f:
        run(["lscpu", "-e=CPU,SOCKET,NODE,CORE"], stdout=f, check=False)
    with open(outdir / "threads.txt", "w") as f:
        run(["ps", "-L", "-p", str(pid), "-o", "pid,tid,psr,pcpu,comm"], stdout=f, check=False)
    with open(outdir / "interrupts_before.txt", "w") as f:
        run(["cat", "/proc/interrupts"], stdout=f, check=False)


def collect_interrupts_after(outdir):
    with open(outdir / "interrupts_after.txt", "w") as f:
        run(["cat", "/proc/interrupts"], stdout=f, check=False)


def parse_lscpu(path):
    topo = {}
    lines = Path(path).read_text(errors="ignore").splitlines()
    if not lines:
        return topo
    header = re.split(r"\s+", lines[0].strip())
    for line in lines[1:]:
        if not line.strip():
            continue
        parts = re.split(r"\s+", line.strip())
        row = dict(zip(header, parts))
        cpu = row.get("CPU")
        if cpu is None:
            continue
        topo[cpu] = {
            "socket": int(row.get("SOCKET", -1)),
            "numa": int(row.get("NODE", -1)),
            "core": int(row.get("CORE", -1)),
        }
    return topo


def parse_funclatency(path):
    data = {}
    current = None
    buckets = []
    if not Path(path).exists():
        return data
    for raw in Path(path).read_text(errors="ignore").splitlines():
        line = raw.strip()
        m = re.search(r"Function\s*=\s*(.*)", line)
        if m:
            current = normalize_func(m.group(1).strip())
            data[current] = {}
            buckets = []
            continue
        m = re.match(r"(\d+)\s*->\s*(\d+)\s*:\s*(\d+)", line)
        if m:
            buckets.append(tuple(map(int, m.groups())))
            continue
        if "avg =" in line and current:
            m = re.search(r"avg\s*=\s*(\d+).*count:\s*(\d+)", line)
            if m:
                avg, count = map(int, m.groups())
                nonzero = [b for b in buckets if b[2] > 0]
                max_bucket = max(nonzero, key=lambda x: x[1]) if nonzero else (0, 0, 0)
                mode_bucket = max(nonzero, key=lambda x: x[2]) if nonzero else (0, 0, 0)
                data[current] = {
                    "avg_ns": avg,
                    "count": count,
                    "p99": f"{mode_bucket[0]}-{mode_bucket[1]} ns",
                    "max_bucket": f"{max_bucket[0]}-{max_bucket[1]} ns",
                }
    return data


def parse_perf_cpu(path):
    frame_cpus = defaultdict(set)
    kernel_assoc = defaultdict(set)
    stack = []
    current_cpu = None

    def flush_stack():
        if not stack:
            return
        has_kernel = any(is_kernel_func(fn) for fn in stack)
        kernel_symbols = {fn for fn in stack if is_kernel_func(fn)}
        for fn in stack:
            if current_cpu is not None:
                frame_cpus[fn].add(current_cpu)
            if has_kernel and not is_kernel_func(fn):
                kernel_assoc[fn].update(kernel_symbols)

    # perf script format varies. We handle common symbol stack lines and header lines containing [NNN].
    cpu_re = re.compile(r"\[(\d+)\]")
    sym_re = re.compile(r"^\s*([A-Za-z0-9_.$@<>~:+\-/\[\]]+)(?:\s|$)")
    for raw in Path(path).read_text(errors="ignore").splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            flush_stack()
            stack = []
            current_cpu = None
            continue
        cm = cpu_re.search(line)
        if cm:
            current_cpu = int(cm.group(1))
            continue
        # Stack frame lines from perf script usually start with whitespace and symbol.
        if line.startswith("\t") or line.startswith("        ") or line.startswith(" "):
            sm = sym_re.match(line)
            if sm:
                fn = normalize_func(sm.group(1))
                if fn and fn not in ("0", "unknown"):
                    stack.append(fn)
    flush_stack()
    return ({k: sorted(v) for k, v in frame_cpus.items()},
            {k: sorted(v) for k, v in kernel_assoc.items()})


def topology_scope(cpus, topo):
    if not cpus:
        return "unknown"
    sockets = {topo.get(str(c), {}).get("socket", -1) for c in cpus}
    numas = {topo.get(str(c), {}).get("numa", -1) for c in cpus}
    if len(cpus) == 1:
        return "single-cpu"
    if len(sockets) > 1:
        return "cross-socket"
    if len(numas) > 1:
        return "cross-numa"
    return "same-numa"


def latency_border(lat):
    if not lat:
        return "none", "0", ""
    avg = int(lat.get("avg_ns", 0))
    if avg > 5000:
        return "#ef4444", "2", "latency-high"
    if avg > 1000:
        return "#f59e0b", "1.5", "latency-medium"
    return "#10b981", "1", "latency-ok"


def enhance_svg(svg_path, out_svg, latency, frame_cpus, topo, kernel_assoc):
    svg = Path(svg_path).read_text(errors="ignore")
    groups = re.findall(r"<g>.*?</g>", svg, re.DOTALL)

    for g in groups:
        tm = re.search(r"<title>(.*?)</title>", g, re.DOTALL)
        rm = re.search(r"<rect ([^>]*)>", g, re.DOTALL)
        if not tm or not rm:
            continue
        title = tm.group(1)
        fn = normalize_func(title.split()[0])
        ksyms = kernel_assoc.get(fn, [])
        cat = classify_func(fn, bool(ksyms))
        fill = COLORS[cat]
        lat = latency.get(fn)
        bcol, bwid, _ = latency_border(lat)
        cpus = frame_cpus.get(fn, [])
        scope = topology_scope(cpus, topo)

        extra = []
        if lat:
            extra.append("--- funclatency ---")
            extra.append(f"avg   : {lat.get('avg_ns')} ns")
            extra.append(f"p99   : {lat.get('p99')}")
            extra.append(f"count : {lat.get('count')}")
            extra.append(f"max   : {lat.get('max_bucket')}")
        if cpus:
            sockets = sorted({topo.get(str(c), {}).get('socket', -1) for c in cpus})
            numas = sorted({topo.get(str(c), {}).get('numa', -1) for c in cpus})
            extra.append("--- topology ---")
            extra.append(f"cpus   : {','.join(map(str, cpus[:16]))}{'...' if len(cpus) > 16 else ''}")
            extra.append(f"socket : {sockets}")
            extra.append(f"numa   : {numas}")
            extra.append(f"scope  : {scope}")
        if ksyms:
            extra.append("--- kernel interaction ---")
            extra.append("type   : direct_stack")
            extra.append("note   : associated with kernel interaction, not proof of causality")
            extra.append("symbols: " + ", ".join(ksyms[:8]))

        new_title = title + (("\n" + "\n".join(extra)) if extra else "")
        attrs = rm.group(1)
        attrs = re.sub(r'fill="[^"]*"', f'fill="{fill}"', attrs)
        if 'fill=' not in attrs:
            attrs += f' fill="{fill}"'
        attrs = re.sub(r'stroke="[^"]*"', '', attrs)
        attrs = re.sub(r'stroke-width="[^"]*"', '', attrs)
        attrs = re.sub(r'stroke-dasharray="[^"]*"', '', attrs)
        dash = ""
        # Topology stronger than normal latency only when cross-domain and no severe latency border.
        if scope == "cross-socket" and bcol in ("none", "#10b981"):
            bcol, bwid, dash = "#111827", "3", ' stroke-dasharray="6,2"'
        elif scope == "cross-numa" and bcol in ("none", "#10b981"):
            bcol, bwid, dash = "#7e22ce", "2", ' stroke-dasharray="2,2"'
        elif scope == "same-numa" and len(cpus) > 1 and bcol == "none":
            bcol, bwid, dash = "#a855f7", "1", ' stroke-dasharray="4,2"'
        attrs += f' stroke="{bcol}" stroke-width="{bwid}"{dash}'
        new_g = re.sub(r"<title>.*?</title>", f"<title>{new_title}</title>", g, flags=re.DOTALL)
        new_g = re.sub(r"<rect [^>]*>", f"<rect {attrs}>", new_g, flags=re.DOTALL)
        svg = svg.replace(g, new_g)

    Path(out_svg).write_text(svg)


def main(argv=None):
    ap = argparse.ArgumentParser(description="DPDK topology + latency FlameGraph one-command tool")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pid", type=int, help="Attach to existing PID")
    mode.add_argument("--app", action="store_true", help="Launch app after --")
    ap.add_argument("--duration", type=int, default=30)
    ap.add_argument("--functions", nargs="*", default=["rte_*", "qdma_*"], help="funclatency patterns")
    ap.add_argument("--flamegraph-dir", required=True, help="Path to Brendan Gregg FlameGraph directory")
    ap.add_argument("--out", default="out")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="Command after -- when using --app")
    args = ap.parse_args(argv)

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    fg = Path(args.flamegraph_dir)
    stackcollapse = fg / "stackcollapse-perf.pl"
    flamegraph = fg / "flamegraph.pl"

    app_proc = None
    if args.app:
        cmd = args.cmd
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            ap.error("--app requires command after --")
        app_proc = popen(cmd)
        pid = app_proc.pid
        time.sleep(1)
    else:
        pid = args.pid

    collect_static(pid, outdir)

    perf_data = outdir / "perf.data"
    perf_proc = popen(["perf", "record", "-F", "999", "-g", "--call-graph", "dwarf", "-p", str(pid), "-o", str(perf_data), "--", "sleep", str(args.duration)])

    flogs = []
    fprocs = []
    for i, pat in enumerate(args.functions):
        fpath = outdir / f"funclatency_{i}.txt"
        flogs.append(fpath)
        f = open(fpath, "w")
        # Try bpfcc name first. Some systems install funclatency as funclatency-bpfcc.
        fprocs.append((popen(["funclatency-bpfcc", "-p", str(pid), "-u", pat], stdout=f, stderr=subprocess.STDOUT), f))

    try:
        perf_proc.wait()
    finally:
        for p, f in fprocs:
            try:
                p.send_signal(signal.SIGINT)
                p.wait(timeout=2)
            except Exception:
                p.kill()
            f.close()
        collect_interrupts_after(outdir)
        if app_proc:
            try:
                app_proc.terminate()
            except Exception:
                pass

    # perf outputs
    with open(outdir / "perf_with_cpu.txt", "w") as f:
        run(["perf", "script", "-F", "comm,pid,tid,cpu,time,event,ip,sym,dso", "-i", str(perf_data)], stdout=f, check=False)
    with open(outdir / "out.perf", "w") as f:
        run(["perf", "script", "-i", str(perf_data)], stdout=f, check=False)
    with open(outdir / "out.folded", "w") as f:
        run([str(stackcollapse), str(outdir / "out.perf")], stdout=f, check=False)
    with open(outdir / "base.svg", "w") as f:
        run([str(flamegraph), str(outdir / "out.folded")], stdout=f, check=False)

    # Parse artifacts
    combined_funclat = outdir / "funclatency.txt"
    combined_funclat.write_text("\n".join(p.read_text(errors="ignore") for p in flogs if p.exists()))
    latency = parse_funclatency(combined_funclat)
    topo = parse_lscpu(outdir / "lscpu.txt")
    frame_cpu, kernel_assoc = parse_perf_cpu(outdir / "perf_with_cpu.txt")

    (outdir / "latency.json").write_text(json.dumps(latency, indent=2))
    (outdir / "topology.json").write_text(json.dumps(topo, indent=2))
    (outdir / "frame_cpu.json").write_text(json.dumps(frame_cpu, indent=2))
    (outdir / "kernel_interaction.json").write_text(json.dumps(kernel_assoc, indent=2))

    enhance_svg(outdir / "base.svg", outdir / "dpdk-final.svg", latency, frame_cpu, topo, kernel_assoc)
    print(f"[OK] final SVG: {outdir / 'dpdk-final.svg'}")


if __name__ == "__main__":
    main()
