#!/usr/bin/env python3
"""Standalone: parse bpftrace / funclatency-bpfcc output → latency.json

Usage:
  python3 parse_latency.py funclatency.txt > latency.json
  python3 parse_latency.py funclatency.txt -o latency.json

Input format (funclatency-bpfcc / bpftrace histogram):
  Function = <name>
  <lo> -> <hi> : <count> |***|
  avg = <N> nsecs, total: <T> nsecs, count: <C>

Output (JSON):
  {
    "function_name": {
      "avg_ns": int,
      "count": int,
      "p99": "low-high ns",
      "max_bucket": "low-high ns"
    }
  }
"""

import argparse
import json
import re
import sys
from pathlib import Path


def normalize_func(name: str) -> str:
    name = name.strip()
    name = name.split("+")[0]   # strip +offset
    name = name.replace("@plt", "")
    return name


def parse_funclatency(path: str) -> dict:
    data = {}
    current = None
    buckets = []
    for raw in Path(path).read_text(errors="ignore").splitlines():
        line = raw.strip()

        # Multi-function block header: "Function = <name>"
        m = re.search(r"Function\s*=\s*(.*)", line)
        if m:
            current = normalize_func(m.group(1).strip())
            data[current] = {}
            buckets = []
            continue

        # Single-function header (funclatency -p PID <pat> or uprobe lib:func):
        #   Tracing 1 functions for "EVP_EncryptUpdate"... Hit Ctrl-C to end.
        #   Tracing 1 functions for "/usr/lib/.../libcrypto.so.3:EVP_EncryptUpdate"...
        m = re.search(r'Tracing\s+\d+\s+functions?\s+for\s+"([^"]+)"', line)
        if m:
            name = m.group(1).split(":")[-1]   # strip 'binpath:' for uprobes
            current = normalize_func(name)
            data[current] = {}
            buckets = []
            continue

        # Histogram bucket line: "2048 -> 4095 : 68 |***|"
        m = re.match(r"(\d+)\s*->\s*(\d+)\s*:\s*(\d+)", line)
        if m:
            buckets.append(tuple(map(int, m.groups())))
            continue

        # Summary line: "avg = 3368 nsecs, total: 232428 nsecs, count: 69"
        if "avg =" in line and current:
            m = re.search(r"avg\s*=\s*(\d+).*count:\s*(\d+)", line)
            if m:
                avg, count = map(int, m.groups())
                nonzero = [b for b in buckets if b[2] > 0]
                # max_bucket: highest latency range with any samples
                max_bucket = max(nonzero, key=lambda x: x[1]) if nonzero else (0, 0, 0)
                # mode_bucket: highest-count bucket (used as p99 approximation)
                mode_bucket = max(nonzero, key=lambda x: x[2]) if nonzero else (0, 0, 0)
                data[current] = {
                    "avg_ns": avg,
                    "count": count,
                    "p99": f"{mode_bucket[0]}-{mode_bucket[1]} ns",
                    "max_bucket": f"{max_bucket[0]}-{max_bucket[1]} ns",
                }
    return data


def main():
    ap = argparse.ArgumentParser(description="Parse funclatency output → JSON")
    ap.add_argument("input", help="funclatency text file")
    ap.add_argument("-o", "--output", default="-", help="Output file (default: stdout)")
    args = ap.parse_args()

    data = parse_funclatency(args.input)
    text = json.dumps(data, indent=2)

    if args.output == "-":
        print(text)
    else:
        Path(args.output).write_text(text)
        print(f"Written: {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
