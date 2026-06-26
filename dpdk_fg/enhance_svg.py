#!/usr/bin/env python3
"""Standalone: enhance a FlameGraph SVG with profile-based coloring, latency, and topology.

Usage:
  python3 enhance_svg.py base.svg \\
    --latency latency.json \\
    --topology topology.json \\
    --frame-cpu frame_cpu.json \\
    --kernel-interaction kernel_interaction.json \\
    --profile dpdk \\
    --out enhanced.svg

  # With skill-emitted hot symbol data
  python3 enhance_svg.py base.svg --profile generic \\
    --skill-output /tmp/lock-skill-output.json \\
    --out lock-enhanced.svg

  # Custom inline category
  python3 enhance_svg.py base.svg --profile generic \\
    --extra-category "mylib:mylib_,__mylib_:#f97316" \\
    --out mylib-enhanced.svg

Invariant: frame WIDTH is never modified. Width = CPU sample weight.
"""

import argparse
import json
import re
import sys
from pathlib import Path

# profile.py must be on sys.path — either installed via dpdk-fg package
# or present in the same directory.
try:
    from dpdk_fg.profile import (
        add_extra_category, category_color, classify_func,
        latency_border, load_profile, merge_skill_output, save_profile,
    )
except ImportError:
    # Standalone mode: profile.py copied to same dir
    import importlib.util, os
    _here = Path(__file__).parent
    spec = importlib.util.spec_from_file_location("profile", _here / "profile.py")
    _mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(_mod)
    add_extra_category = _mod.add_extra_category
    category_color = _mod.category_color
    classify_func = _mod.classify_func
    latency_border = _mod.latency_border
    load_profile = _mod.load_profile
    merge_skill_output = _mod.merge_skill_output
    save_profile = _mod.save_profile


try:
    from dpdk_fg.topology import SCOPE_STROKE, topology_scope, topology_tooltip
except ImportError:
    import importlib.util
    _here2 = Path(__file__).parent
    _spec2 = importlib.util.spec_from_file_location("topology", _here2 / "topology.py")
    _topo_mod = importlib.util.module_from_spec(_spec2)
    _spec2.loader.exec_module(_topo_mod)
    SCOPE_STROKE = _topo_mod.SCOPE_STROKE
    topology_scope = _topo_mod.topology_scope
    topology_tooltip = _topo_mod.topology_tooltip


def normalize_func(name: str) -> str:
    name = name.strip()
    name = name.split("+")[0]
    name = name.replace("@plt", "")
    return name


def enhance_svg(svg_path, out_path, latency, frame_cpus, topo, kernel_assoc, profile,
                gmi_map=None):
    """Rewrite FlameGraph SVG frames. Width is never changed."""
    svg = Path(svg_path).read_text(errors="ignore")
    # flamegraph.pl emits frame groups as "<g >" / "<g class=...>"; match any opening <g ...>.
    groups = re.findall(r"<g\b[^>]*>.*?</g>", svg, re.DOTALL)

    for g in groups:
        tm = re.search(r"<title>(.*?)</title>", g, re.DOTALL)
        # rects may be self-closing ("<rect ... />") in modern flamegraph.pl.
        rm = re.search(r"<rect ([^>]*?)\s*/?>", g, re.DOTALL)
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

        attrs = rm.group(1).rstrip().rstrip("/").rstrip()
        attrs = re.sub(r'fill="[^"]*"', f'fill="{fill}"', attrs)
        if "fill=" not in attrs:
            attrs += f' fill="{fill}"'
        attrs = re.sub(r'stroke="[^"]*"', "", attrs)
        attrs = re.sub(r'stroke-width="[^"]*"', "", attrs)
        attrs = re.sub(r'stroke-dasharray="[^"]*"', "", attrs)

        dash = ""
        sev_ok = bcol in ("none", "#10b981")
        weak_scope = scope in ("same-ccx", "same-numa")
        if scope in SCOPE_STROKE and (sev_ok if not weak_scope else bcol == "none"):
            if not weak_scope or len(cpus) > 1:
                col, wid, da = SCOPE_STROKE[scope]
                bcol, bwid = col, wid
                dash = f' stroke-dasharray="{da}"' if da else ""

        if bcol != "none":
            attrs += f' stroke="{bcol}" stroke-width="{bwid}"{dash}'

        new_g = re.sub(r"<title>.*?</title>", lambda _: f"<title>{new_title}</title>", g, count=1, flags=re.DOTALL)
        new_g = re.sub(r"<rect [^>]*?/?>", lambda _: f"<rect {attrs} />", new_g, count=1, flags=re.DOTALL)
        svg = svg.replace(g, new_g)

    Path(out_path).write_text(svg)
    print(f"[OK] enhanced SVG: {out_path}", file=sys.stderr)


def _load_json(path):
    if not path or not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text())


def main():
    ap = argparse.ArgumentParser(description="Enhance FlameGraph SVG with profile coloring + latency")
    ap.add_argument("svg", help="Input base.svg from FlameGraph")
    ap.add_argument("--latency",            metavar="PATH", help="latency.json from parse_latency.py")
    ap.add_argument("--topology",           metavar="PATH", help="topology.json from lscpu parse")
    ap.add_argument("--frame-cpu",          metavar="PATH", help="frame_cpu.json from perf script parse")
    ap.add_argument("--kernel-interaction", metavar="PATH", help="kernel_interaction.json")
    ap.add_argument("--out",  default="enhanced.svg", help="Output SVG path")
    ap.add_argument("--profile", default="dpdk",
                    help="Profile name or .json path (default: dpdk)")
    ap.add_argument("--skill-output", metavar="PATH",
                    help="Skill-emitted JSON for extra categories / hot symbols")
    ap.add_argument("--extra-category", action="append", default=[], metavar="id:hints:color",
                    help="Inline category spec 'id:hints:color' (repeatable)")
    ap.add_argument("--save-profile", metavar="PATH", help="Dump resolved profile to JSON")
    args = ap.parse_args()

    profile = load_profile(args.profile)
    if args.skill_output:
        merge_skill_output(profile, _load_json(args.skill_output))
    for spec in args.extra_category:
        add_extra_category(profile, spec)
    if args.save_profile:
        save_profile(profile, args.save_profile)

    enhance_svg(
        args.svg,
        args.out,
        latency=_load_json(args.latency),
        frame_cpus=_load_json(args.frame_cpu),
        topo=_load_json(args.topology),
        kernel_assoc=_load_json(args.kernel_interaction),
        profile=profile,
    )


if __name__ == "__main__":
    main()
