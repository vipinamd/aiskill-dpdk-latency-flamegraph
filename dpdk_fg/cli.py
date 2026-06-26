#!/usr/bin/env python3
"""One-command FlameGraph enhancer with target-profile system.

Supports any userspace or kernel target via --profile.
Built-in profiles: dpdk | ssl | kernel-net | lock | generic
Skills feed hot symbol data via --skill-output.

Usage:
  # DPDK (default, backward-compatible)
  dpdk-fg --pid <PID> --duration 30 --flamegraph-dir ./FlameGraph --out out/

  # SSL profiling
  dpdk-fg --pid <PID> --profile ssl --flamegraph-dir ./FlameGraph --out out/

  # Skill-fed lock contention
  dpdk-fg --pid <PID> --profile generic --skill-output /tmp/lock.json \\
          --flamegraph-dir ./FlameGraph --out out/

  # Inline custom category
  dpdk-fg --pid <PID> --profile generic \\
          --extra-category "mylib:mylib_,__mylib_:#f97316" \\
          --flamegraph-dir ./FlameGraph --out out/
"""

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from .profile import (
    Profile,
    add_extra_category,
    category_color,
    classify_func,
    is_kernel_frame,
    latency_border,
    load_profile,
    merge_skill_output,
    save_profile,
)
from .topology import (
    SCOPE_STROKE,
    collect_amd_topology,
    collect_gmi,
    detect_ccd_confidence,
    infer_gmi,
    merge_topology,
    parse_amd_topology,
    topology_scope,
    topology_tooltip,
)


# ---------------------------------------------------------------------------
# Shell helpers
# ---------------------------------------------------------------------------

def run(cmd, *, cwd=None, stdout=None, stderr=None, check=True):
    print("[cmd]", " ".join(shlex.quote(str(x)) for x in cmd))
    return subprocess.run(cmd, cwd=cwd, stdout=stdout, stderr=stderr, check=check, text=True)


def popen(cmd, *, cwd=None, stdout=None, stderr=None):
    print("[bg]", " ".join(shlex.quote(str(x)) for x in cmd))
    return subprocess.Popen(cmd, cwd=cwd, stdout=stdout, stderr=stderr, text=True)


# ---------------------------------------------------------------------------
# Symbol normalization
# ---------------------------------------------------------------------------

def normalize_func(name: str) -> str:
    name = name.strip()
    name = name.split("+")[0]   # strip +offset
    name = name.replace("@plt", "")
    return name


# ---------------------------------------------------------------------------
# Collection helpers
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

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
    """Parse bpftrace / funclatency-bpfcc histogram output into a dict.

    Expected format per function:
        Function = <name>
        <lo> -> <hi> : <count> |***|
        avg = <N> nsecs, total: <T> nsecs, count: <C>
    """
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
                # mode bucket = highest-count bucket ≈ p50; used as p99 approximation
                mode_bucket = max(nonzero, key=lambda x: x[2]) if nonzero else (0, 0, 0)
                data[current] = {
                    "avg_ns": avg,
                    "count": count,
                    "p99": f"{mode_bucket[0]}-{mode_bucket[1]} ns",
                    "max_bucket": f"{max_bucket[0]}-{max_bucket[1]} ns",
                }
    return data


def parse_perf_cpu(path):
    """Parse 'perf script -F comm,pid,tid,cpu,...' output.

    Returns:
        frame_cpus: {fn: [cpu_ids]} — which CPUs a symbol appeared on
        kernel_assoc: {fn: [kernel_syms]} — non-kernel syms co-appearing with kernel syms
    """
    frame_cpus = defaultdict(set)
    kernel_assoc = defaultdict(set)
    stack = []
    current_cpu = None

    def flush_stack():
        if not stack:
            return
        has_kernel = any("[kernel" in fn or fn.startswith("__x64_sys") for fn in stack)
        kernel_symbols = {fn for fn in stack if "[kernel" in fn or fn.startswith("__x64_sys")}
        for fn in stack:
            if current_cpu is not None:
                frame_cpus[fn].add(current_cpu)
            if has_kernel and "[kernel" not in fn:
                kernel_assoc[fn].update(kernel_symbols)

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
        if line.startswith(("\t", "        ", " ")):
            sm = sym_re.match(line)
            if sm:
                fn = normalize_func(sm.group(1))
                if fn and fn not in ("0", "unknown"):
                    stack.append(fn)
    flush_stack()
    return (
        {k: sorted(v) for k, v in frame_cpus.items()},
        {k: sorted(v) for k, v in kernel_assoc.items()},
    )


# ---------------------------------------------------------------------------
# SVG enhancement (profile-aware)
# ---------------------------------------------------------------------------

def enhance_svg(svg_path, out_svg, latency, frame_cpus, topo, kernel_assoc, profile: Profile,
                gmi_map=None):
    """Rewrite SVG frames with profile-based coloring, latency borders, and topology tooltips.

    Invariant: frame WIDTH is never changed — it represents CPU sample weight.
    """
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
        cat_id = classify_func(fn, bool(ksyms), profile)
        fill = category_color(cat_id, bool(ksyms), profile)

        lat = latency.get(fn)
        bcol, bwid, _ = latency_border(lat, profile)

        cpus = frame_cpus.get(fn, [])
        scope = topology_scope(cpus, topo)

        # Build tooltip extensions
        extra = []
        if lat:
            extra.append("--- funclatency ---")
            extra.append(f"avg   : {lat.get('avg_ns')} ns")
            extra.append(f"p99   : {lat.get('p99')}")
            extra.append(f"count : {lat.get('count')}")
            extra.append(f"max   : {lat.get('max_bucket')}")
        if cpus:
            extra.extend(topology_tooltip(cpus, topo, gmi_map))
        if ksyms:
            extra.append("--- kernel interaction ---")
            extra.append("type   : direct_stack")
            extra.append("note   : associated with kernel interaction, not proof of causality")
            extra.append("symbols: " + ", ".join(ksyms[:8]))

        new_title = title + (("\n" + "\n".join(extra)) if extra else "")

        # Rewrite rect attributes (fill + stroke only — never width)
        attrs = rm.group(1)
        attrs = re.sub(r'fill="[^"]*"', f'fill="{fill}"', attrs)
        if "fill=" not in attrs:
            attrs += f' fill="{fill}"'
        attrs = re.sub(r'stroke="[^"]*"', "", attrs)
        attrs = re.sub(r'stroke-width="[^"]*"', "", attrs)
        attrs = re.sub(r'stroke-dasharray="[^"]*"', "", attrs)

        dash = ""
        # Topology stroke overrides latency stroke when latency is not severe.
        # "same"-level scopes only paint when there is no latency border at all.
        sev_ok = bcol in ("none", "#10b981")
        weak_scope = scope in ("same-ccx", "same-numa")
        if scope in SCOPE_STROKE and (sev_ok if not weak_scope else bcol == "none"):
            if not weak_scope or len(cpus) > 1:
                col, wid, da = SCOPE_STROKE[scope]
                bcol, bwid = col, wid
                dash = f' stroke-dasharray="{da}"' if da else ""

        if bcol != "none":
            attrs += f' stroke="{bcol}" stroke-width="{bwid}"{dash}'

        new_g = re.sub(r"<title>.*?</title>", f"<title>{new_title}</title>", g, flags=re.DOTALL)
        new_g = re.sub(r"<rect [^>]*>", f"<rect {attrs}>", new_g, flags=re.DOTALL)
        svg = svg.replace(g, new_g)

    Path(out_svg).write_text(svg)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="FlameGraph enhancer with target-profile system (DPDK, SSL, lock, custom)"
    )

    # Target / collection
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--pid", type=int, help="Attach to existing PID")
    mode.add_argument("--app", action="store_true", help="Launch app after --")
    ap.add_argument("--duration", type=int, default=30, metavar="S")
    ap.add_argument("--functions", nargs="*", metavar="PATTERN",
                    help="funclatency patterns (overrides profile defaults)")
    ap.add_argument("--flamegraph-dir", required=True, help="Path to Brendan Gregg FlameGraph dir")
    ap.add_argument("--out", default="out", help="Output directory")
    ap.add_argument("cmd", nargs=argparse.REMAINDER, help="Command after -- when using --app")

    # Profile system (new in 0.2)
    ap.add_argument("--profile", default="dpdk", metavar="NAME|PATH",
                    help="Target profile: dpdk|ssl|kernel-net|lock|generic, or path to .json "
                         "(default: dpdk)")
    ap.add_argument("--skill-output", metavar="PATH",
                    help="Skill-emitted JSON to merge into profile (hot symbols + categories)")
    ap.add_argument("--extra-category", action="append", default=[], metavar="id:hints:color",
                    help="Inline category: 'mylib:mylib_,__mylib_:#f97316' (repeatable)")
    ap.add_argument("--save-profile", metavar="PATH",
                    help="Save resolved profile to JSON after merging all inputs")

    args = ap.parse_args(argv)

    # ── Resolve profile ──────────────────────────────────────────────────────
    profile = load_profile(args.profile)
    if args.skill_output:
        skill_json = json.loads(Path(args.skill_output).read_text())
        merge_skill_output(profile, skill_json)
        print(f"[profile] merged skill output: {args.skill_output}")
    for spec in args.extra_category:
        add_extra_category(profile, spec)
    if args.save_profile:
        save_profile(profile, args.save_profile)
        print(f"[profile] saved resolved profile: {args.save_profile}")

    # funclatency patterns: CLI arg overrides profile defaults
    funclat_patterns = args.functions if args.functions else profile.funclatency_patterns
    print(f"[profile] {profile.name!r} — funclatency patterns: {funclat_patterns}")

    # ── Output directory ─────────────────────────────────────────────────────
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    fg = Path(args.flamegraph_dir)
    stackcollapse = fg / "stackcollapse-perf.pl"
    flamegraph = fg / "flamegraph.pl"

    # ── Launch app or attach ─────────────────────────────────────────────────
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

    # ── AMD CCX / CCD / GMI snapshot (passive sysfs + best-effort HSMP) ────────
    amd_raw = collect_amd_topology(outdir)
    gmi_text = collect_gmi(outdir)

    # ── Parallel collection: perf + funclatency ───────────────────────────────
    perf_data = outdir / "perf.data"
    perf_proc = popen([
        "perf", "record", "-F", "999", "-g", "--call-graph", "dwarf",
        "-p", str(pid), "-o", str(perf_data), "--", "sleep", str(args.duration),
    ])

    flogs = []
    fprocs = []
    for i, pat in enumerate(funclat_patterns):
        fpath = outdir / f"funclatency_{i}.txt"
        flogs.append(fpath)
        f = open(fpath, "w")
        # funclatency-bpfcc is the Debian/Ubuntu package name
        fprocs.append((
            popen(["funclatency-bpfcc", "-p", str(pid), "-u", pat],
                  stdout=f, stderr=subprocess.STDOUT),
            f,
        ))

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

    # ── Postprocess perf ─────────────────────────────────────────────────────
    with open(outdir / "perf_with_cpu.txt", "w") as f:
        run(["perf", "script", "-F", "comm,pid,tid,cpu,time,event,ip,sym,dso",
             "-i", str(perf_data)], stdout=f, check=False)
    with open(outdir / "out.perf", "w") as f:
        run(["perf", "script", "-i", str(perf_data)], stdout=f, check=False)
    with open(outdir / "out.folded", "w") as f:
        run([str(stackcollapse), str(outdir / "out.perf")], stdout=f, check=False)
    with open(outdir / "base.svg", "w") as f:
        run([str(flamegraph), str(outdir / "out.folded")], stdout=f, check=False)

    # ── Parse artifacts ───────────────────────────────────────────────────────
    combined = outdir / "funclatency.txt"
    combined.write_text("\n".join(
        p.read_text(errors="ignore") for p in flogs if p.exists()
    ))
    latency = parse_funclatency(combined)
    topo = parse_lscpu(outdir / "lscpu.txt")
    frame_cpu, kernel_assoc = parse_perf_cpu(outdir / "perf_with_cpu.txt")

    # Merge AMD CCX/CCD into the lscpu topo, infer GMI, check confidence.
    ccx_map, n_ccx, n_ccd = parse_amd_topology(amd_raw)
    merge_topology(topo, ccx_map)
    gmi_map = infer_gmi(topo, gmi_text)
    lstopo_text = None
    tool = shutil.which("lstopo") or shutil.which("lstopo-no-graphics")
    if tool:
        try:
            lstopo_text = subprocess.run([tool, "--of", "console"],
                                         capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            lstopo_text = None
    confidence = detect_ccd_confidence(amd_raw, platform.release(), lstopo_text)
    if confidence:
        print(f"[warn] CCD/CCX confidence: {confidence}")

    (outdir / "latency.json").write_text(json.dumps(latency, indent=2))
    (outdir / "topology.json").write_text(json.dumps(topo, indent=2))
    (outdir / "frame_cpu.json").write_text(json.dumps(frame_cpu, indent=2))
    (outdir / "kernel_interaction.json").write_text(json.dumps(kernel_assoc, indent=2))
    (outdir / "ccx_topology.json").write_text(json.dumps({
        "cpu_map": {c: {**topo.get(c, {}), **v} for c, v in ccx_map.items()},
        "n_ccx": n_ccx,
        "n_ccd": n_ccd,
        "gmi": gmi_map,
        "confidence": confidence,
        "kernel": platform.release(),
    }, indent=2))

    # ── Enhance SVG ───────────────────────────────────────────────────────────
    out_svg_name = f"{profile.name}-final.svg"
    enhance_svg(
        outdir / "base.svg",
        outdir / out_svg_name,
        latency, frame_cpu, topo, kernel_assoc,
        profile,
        gmi_map=gmi_map,
    )
    print(f"[OK] final SVG: {outdir / out_svg_name}")


if __name__ == "__main__":
    main()
