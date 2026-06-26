# DPDK Topology + Latency FlameGraph

A one-command CLI tool to collect, parse, and enhance Linux FlameGraph output for DPDK-style workloads.

It combines four signals into one SVG:

| Signal | Source | Visual encoding |
|---|---|---|
| CPU cost | `perf` FlameGraph | frame width |
| DPDK / PMD / kernel classification | function name / stack | fill color |
| function latency | `funclatency-bpfcc` output | border + tooltip |
| CPU placement | `perf script` CPU field + `lscpu` | topology tooltip / cross-domain style |
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
socket : 0
numa   : 0
scope  : same-numa

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

The tool reads CPU placement from `perf script` and topology from `lscpu`.

It can classify a frame as:

- `single-cpu`
- `same-numa`
- `cross-numa`
- `cross-socket`

CCX / CCD detection is left as an extension point because standard `lscpu` output does not always expose AMD CCX / CCD directly.

---

## Limitations

- Function-name matching is heuristic.
- Inlined DPDK APIs may not appear as symbols.
- `funclatency` can perturb very hot functions; trace narrow patterns first.
- `funclatency` histogram buckets give bucket ranges, not exact max latency unless the collector is extended.
- Kernel interaction detection is stack/correlation based; it should not be treated as causality without additional tracing.
- Topology is only as accurate as CPU IDs recorded by `perf script` and CPU topology exported by the OS.

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

## Project status

Prototype / skill seed.

Planned next steps:

- Add DSO-based classification.
- Add AMD CCX / CCD parser from sysfs or `lstopo` output.
- Add IRQ delta parser using `/proc/interrupts` before/after snapshots.
- Add HTML report with summary table.
- Add unit tests for parser edge cases.

---

## Suggested repository name

```text
dpdk-topology-latency-flamegraph
```

---

## License

Choose a license before publishing. Suggested: BSD-3-Clause or MIT.
