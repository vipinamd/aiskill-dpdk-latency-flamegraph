# DPDK Topology + Latency FlameGraph

A one-command CLI tool to collect, parse, and enhance Linux FlameGraph output for DPDK-style workloads.

It combines four signals into one SVG:

| Signal | Source | Visual encoding |
|---|---|---|
| CPU cost | `perf` FlameGraph | frame width |
| DPDK / PMD / kernel classification | function name / stack | fill color |
| function latency | `funclatency-bpfcc` output | border + tooltip |
| CPU placement | `perf script` CPU field + `lscpu` + sysfs CCX/CCD (+ HSMP GMI) | topology tooltip / cross-domain stroke |
| kernel interaction | stack contains syscall / VFIO / UIO / IRQ / softirq symbols | darker DPDK / PMD shade |

The tool does **not** change FlameGraph frame width. Width remains the original CPU sample weight.

---

## Why this exists

Standard FlameGraph is excellent for answering:

> Where is CPU time going?

But for DPDK and accelerator workloads, that is not enough. In real debugging, you often also need:

- Is this path a DPDK API, PMD callback, kernel path, or application path?
- Does the same function have `funclatency` data?
- Is this running on one CCX / NUMA node / socket, or crossing topology domains?
- Is a supposedly userspace datapath associated with syscall, VFIO, UIO, IRQ, softirq, or event handling?

This tool makes those signals visible in the same FlameGraph SVG.

---

## Key design rule

Do **not** mix metrics.

```text
FlameGraph width = CPU sample weight
Latency          = border + tooltip
Topology         = stroke / tooltip
Kernel relation  = darker shade + tooltip
```

This keeps the visualization honest.

---

## Install prerequisites

Required:

```bash
sudo apt install linux-tools-common linux-tools-$(uname -r) bpfcc-tools python3
```

Also clone Brendan Gregg's FlameGraph tools:

```bash
git clone --depth 1 https://github.com/brendangregg/FlameGraph.git
```

Make sure these are available in `$PATH` or pass their paths through CLI arguments:

- `perf`
- `stackcollapse-perf.pl`
- `flamegraph.pl`
- `funclatency-bpfcc`

---

## One-command usage

### Attach to an existing process

```bash
sudo python3 -m dpdk_fg.cli \
  --pid <PID> \
  --duration 30 \
  --functions 'rte_*' 'qdma_*' 'mlx5_*' 'bnxt_*' \
  --flamegraph-dir ./FlameGraph \
  --out out
```

Final output:

```text
out/dpdk-final.svg
```

---

### Launch an application and profile it

```bash
sudo python3 -m dpdk_fg.cli \
  --duration 30 \
  --functions 'rte_*' 'qdma_*' \
  --flamegraph-dir ./FlameGraph \
  --out out \
  --app -- ./build/app/dpdk-testpmd -l 4,5 -a 0000:01:00.0 -- -i
```

Everything after `--app --` is treated as the workload command.

---

## What gets collected

The CLI collects these artifacts:

```text
out/
├── lscpu.txt
├── threads.txt
├── interrupts_before.txt
├── interrupts_after.txt
├── amd_topology_raw.json
├── gmi_raw.txt            # only if HSMP/E-SMI is reachable
├── perf.data
├── perf_with_cpu.txt
├── out.perf
├── out.folded
├── base.svg
├── funclatency.txt
├── latency.json
├── topology.json
├── frame_cpu.json
├── kernel_interaction.json
├── ccx_topology.json
└── dpdk-final.svg
```

---

## Visual legend

### Fill color

| Color | Meaning |
|---|---|
| green | DPDK API, for example `rte_*` / `__rte_*` |
| dark green | PMD / driver-like path, for example `rx`, `tx`, `burst`, `qdma`, `mlx5`, `bnxt` |
| blue | kernel path |
| grey | other / application / library |
| deeper green | DPDK / PMD frame associated with kernel interaction |

### Border color

| Border | Meaning |
|---|---|
| none | no `funclatency` data |
| green | latency data found, average under threshold |
| yellow | moderate latency |
| red | high latency |

### Topology stroke

Painted only when the latency border is absent or non-severe (latency severity wins):

| Stroke | Scope |
|---|---|
| cyan dash | `cross-ccx` (different L3, same die) |
| rose dash | `cross-ccd` (different compute die) |
| purple dash | `cross-numa` |
| dark solid | `cross-socket` |
| light purple dash | `same-ccx` / `same-numa` (multi-CPU) |

### Tooltip sections

Hovering a frame may show:

```text
--- funclatency ---
avg   : 3368 ns
p99   : 2048-4095 ns
count : 69
max   : 32768-65535 ns

--- topology ---
cpus   : 96,102
socket : [0]
numa   : [0]
ccd    : [8, 9]
ccx    : [8, 9]
gmi    : likely-wide (inferred)
scope  : cross-ccd

--- kernel interaction ---
type   : direct_stack
symbols: ioctl, vfio, epoll
note   : associated with kernel interaction, not proof of causality
```

---

## Kernel interaction logic

A DPDK / PMD / userspace frame is darkened when the stack contains kernel-facing signals such as:

```text
syscall, ioctl, read, write, mmap, epoll, eventfd,
vfio, uio, irq, softirq, napi, net_rx_action, __softirqentry
```

Important: the tool reports **association**, not guaranteed causality.

Good wording:

> This DPDK/PMD frame is associated with kernel interaction in the sampled stack.

Avoid:

> This DPDK API caused the IRQ.

---

## Topology logic

The tool reads CPU placement from `perf script`, NUMA/socket from `lscpu`, and the
AMD on-die hierarchy (CCX / CCD) directly from sysfs. Each frame's CPU set is
classified along this scope ladder (cheapest → most expensive boundary):

- `single-cpu`
- `same-ccx` — all CPUs share one L3 (Core Complex)
- `cross-ccx` — different CCX, same compute die (CCD)
- `cross-ccd` — different CCD, same NUMA node
- `cross-numa`
- `cross-socket`

When CCX/CCD data is unavailable (non-AMD, missing sysfs, or old kernel) the tool
degrades gracefully to the `single-cpu` / `same-numa` / `cross-numa` / `cross-socket`
classification — no crash, no false on-die claims.

### AMD CCX / CCD / GMI detection

| Signal | Source | Notes |
|---|---|---|
| CCX | `/sys/devices/system/cpu/cpuN/cache/index{level==3}/id` | cores sharing one L3 |
| CCD | `/sys/devices/system/cpu/cpuN/topology/die_id` | compute die |
| socket | `/sys/.../topology/physical_package_id` | |
| GMI width | HSMP (`/dev/hsmp`, `e_smi_tool`), else inferred | narrow (1 link) vs wide (2 links/CCD) |

All detection is **passive** (sysfs reads + an optional read-only HSMP query). The
tool never runs an active latency benchmark against the target.

**GMI link width** (narrow vs wide) governs each CCD's bandwidth to the IO die
(~62 GB/s narrow vs ~100 GB/s wide). It is read from HSMP/E-SMI when available
(needs BIOS HSMP support + `amd_hsmp` driver + root); otherwise it is **inferred**
from CCD count (≤4 CCD parts are the wide OPNs) and clearly labeled `(inferred)`.

**CCD confidence**: `die_id` is misreported on kernels **< 6.10** for dense
EPYC parts (Bergamo / Zen 4c), which need CPUID leaf `0x80000026`. The tool emits
a `[warn] CCD/CCX confidence:` note (also stored in `ccx_topology.json`) when the
kernel is too old or when an `lstopo` cross-check disagrees with sysfs.

---

## Limitations

- Function-name matching is heuristic.
- Inlined DPDK APIs may not appear as symbols.
- `funclatency` can perturb very hot functions; trace narrow patterns first.
- `funclatency` histogram buckets give bucket ranges, not exact max latency unless the collector is extended.
- Kernel interaction detection is stack/correlation based; it should not be treated as causality without additional tracing.
- Topology is only as accurate as CPU IDs recorded by `perf script` and CPU topology exported by the OS.
- CCD (`die_id`) is unreliable on kernels < 6.10 for dense EPYC parts; the tool warns but cannot correct it.
- GMI link width is read from HSMP when available, otherwise **inferred** from CCD count — treat `(inferred)` values as a hint, not a measurement.

---

## Recommended workflow

Start narrow:

```bash
sudo python3 -m dpdk_fg.cli \
  --pid <PID> \
  --duration 15 \
  --functions 'rte_eth_*' 'qdma_*' \
  --flamegraph-dir ./FlameGraph \
  --out out
```

Then widen patterns only after confirming overhead is acceptable.

---

## Target Profile System (v0.2)

Classification, coloring, and funclatency patterns are now controlled by a **profile** —
not hardcoded DPDK prefixes. Pass `--profile` to select a built-in or custom profile:

| Profile | Use for |
|---|---|
| `dpdk` | DPDK / PMD datapath — default, backward-compatible |
| `ssl` | OpenSSL / TLS / crypto |
| `kernel-net` | Linux kernel networking (softirq, NAPI, socket) |
| `lock` | Lock and atomic contention |
| `generic` | Any target — add categories via `--extra-category` or `--skill-output` |

```bash
# SSL profiling
dpdk-fg --pid <PID> --profile ssl --duration 30 --flamegraph-dir ./FlameGraph --out out/

# Custom inline category
dpdk-fg --pid <PID> --profile generic \
  --extra-category "mylib:mylib_,__mylib_:#f97316" \
  --flamegraph-dir ./FlameGraph --out out/

# Save resolved profile for reproducibility
dpdk-fg --pid <PID> --profile dpdk --save-profile /tmp/resolved-profile.json \
  --flamegraph-dir ./FlameGraph --out out/
```

### Skill output contract

Diagnostic skills can feed hot symbol data via `--skill-output`:

```json
{
  "skill": "lock-atomic-contention",
  "hot_symbols": ["pthread_mutex_lock", "futex_wait"],
  "funclatency_patterns": ["pthread_mutex_*"],
  "extra_categories": [
    {"id": "contended_lock", "hints": ["mutex", "futex"],
     "color": "#dc2626", "label": "Contended Lock"}
  ]
}
```

```bash
dpdk-fg --pid <PID> --profile generic \
  --skill-output /tmp/lock-skill-output.json \
  --flamegraph-dir ./FlameGraph --out out/
```

### Custom profile JSON

Copy any built-in from `dpdk_fg/profiles/` and modify:

```bash
dpdk-fg --pid <PID> --profile /path/to/myprofile.json \
  --flamegraph-dir ./FlameGraph --out out/
```

### Standalone scripts (no package install)

```bash
python3 dpdk_fg/parse_latency.py funclatency.txt -o latency.json

python3 dpdk_fg/enhance_svg.py base.svg \
  --latency latency.json --profile ssl --out enhanced.svg
```

---

## Project status

v0.2 — Profile system shipped.

Planned next steps:

- Add DSO-based classification (override name-matching with ELF DSO path).
- ~~Add AMD CCX / CCD parser from sysfs or `lstopo` output~~ — done (sysfs CCX/CCD
  + best-effort/inferred GMI link width, see Topology logic).
- Add IRQ delta parser using `/proc/interrupts` before/after snapshots.
- Add HTML report with summary table.
- Add unit tests for profile + parser edge cases.
- Add skill output emitters to `lock-atomic-contention` and `cross-ccd-false-sharing` diagnose scripts.

---

## Suggested repository name

```text
dpdk-topology-latency-flamegraph
```

---

## License

Choose a license before publishing. Suggested: BSD-3-Clause or MIT.
