#!/usr/bin/env python3
"""AMD CCX / CCD / GMI topology detection (passive sysfs + best-effort HSMP).

Extends the NUMA/socket topology with the on-die hierarchy that matters for
DPDK/PMD datapaths on EPYC:

    single-cpu < same-ccx < cross-ccx < cross-ccd < cross-numa < cross-socket

Signals and where they come from:

  CCX     cores sharing one L3 → /sys/.../cpuN/cache/index{level==3}/id
  CCD     compute die          → /sys/.../cpuN/topology/die_id
  socket                       → /sys/.../cpuN/topology/physical_package_id
  GMI     narrow(1)/wide(2)    → HSMP (/dev/hsmp, e_smi_tool); else inferred

Design rules inherited from the tool:
  - Passive parsing only. The discarded quadrant-detect.py latency benchmark
    perturbed the system under profile; we never run active probes here.
  - Report confidence, never assert. die_id is wrong on kernels < 6.10 for
    dense parts; GMI inference is labeled "(inferred)".
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

SYSFS_CPU = "/sys/devices/system/cpu"


# ---------------------------------------------------------------------------
# Collection (passive)
# ---------------------------------------------------------------------------

def _read(path):
    try:
        return Path(path).read_text(errors="ignore").strip()
    except OSError:
        return None


def collect_amd_topology(outdir, sysfs_cpu=SYSFS_CPU):
    """Snapshot per-CPU sysfs topology to amd_topology_raw.json. Pure reads.

    Returns the raw dict {cpu: {package, die, l3_id, l3_shared}} so callers can
    parse it directly without re-reading disk.
    """
    raw = {}
    for cpu_dir in sorted(Path(sysfs_cpu).glob("cpu[0-9]*")):
        m = re.fullmatch(r"cpu(\d+)", cpu_dir.name)
        if not m:
            continue
        cpu = m.group(1)
        entry = {
            "package": _read(cpu_dir / "topology" / "physical_package_id"),
            "die": _read(cpu_dir / "topology" / "die_id"),
            "l3_id": None,
            "l3_shared": None,
        }
        # L3 cache = CCX. Find the cache index whose level == 3.
        for idx_dir in sorted((cpu_dir / "cache").glob("index*")):
            if _read(idx_dir / "level") == "3":
                entry["l3_id"] = _read(idx_dir / "id")
                entry["l3_shared"] = _read(idx_dir / "shared_cpu_list")
                break
        raw[cpu] = entry

    out = Path(outdir) / "amd_topology_raw.json"
    out.write_text(json.dumps(raw, indent=2))
    return raw


def collect_gmi(outdir):
    """Best-effort GMI link-width capture via HSMP / E-SMI. Non-fatal.

    Requires BIOS HSMP support + amd_hsmp driver (/dev/hsmp) + e_smi_tool on
    PATH, and typically root. Returns the captured text or None.
    """
    if not Path("/dev/hsmp").exists():
        return None
    tool = shutil.which("e_smi_tool") or shutil.which("esmi_tool") or shutil.which("esmi")
    if not tool:
        return None
    try:
        # No single portable flag exposes GMI width across e-smi versions; capture
        # the full dump and let parse_gmi() scrape what it can.
        proc = subprocess.run([tool], capture_output=True, text=True, timeout=10)
        text = (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return None
    if not text.strip():
        return None
    (Path(outdir) / "gmi_raw.txt").write_text(text)
    return text


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _to_int(v, default=-1):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_amd_topology(raw):
    """Turn the raw sysfs snapshot into {cpu: {ccx, ccd}} keyed by CPU string.

    CCX id is the (package, l3_id) pair flattened to a stable small integer so
    L3 ids that repeat across sockets do not collide. CCD is (package, die_id).
    Returns ({cpu: {"ccx": int, "ccd": int}}, n_ccx, n_ccd).
    """
    ccx_key_to_id = {}
    ccd_key_to_id = {}
    result = {}
    for cpu, e in raw.items():
        pkg = e.get("package")
        l3 = e.get("l3_id")
        die = e.get("die")
        ccx = -1
        ccd = -1
        if l3 is not None and l3 != "":
            key = (pkg, l3)
            ccx = ccx_key_to_id.setdefault(key, len(ccx_key_to_id))
        if die is not None and die != "":
            key = (pkg, die)
            ccd = ccd_key_to_id.setdefault(key, len(ccd_key_to_id))
        result[cpu] = {"ccx": ccx, "ccd": ccd}
    return result, len(ccx_key_to_id), len(ccd_key_to_id)


def merge_topology(topo, ccx_map):
    """Augment the lscpu topo dict in place with per-CPU ccx/ccd keys."""
    for cpu, vals in ccx_map.items():
        topo.setdefault(cpu, {"socket": -1, "numa": -1, "core": -1})
        topo[cpu]["ccx"] = vals.get("ccx", -1)
        topo[cpu]["ccd"] = vals.get("ccd", -1)
    return topo


def infer_gmi(topo, gmi_text=None):
    """Determine GMI link width per socket.

    Real value from HSMP text wins; otherwise infer from CCD count. Wide-GMI is
    a property of low-CCD-count EPYC OPNs (≈4 CCD parts get 2 links per CCD).
    Returns {socket: "wide"|"narrow"|"likely-wide (inferred)"|...}.
    """
    # Try to scrape a real value first.
    if gmi_text:
        low = gmi_text.lower()
        if "wide" in low:
            return {"_global": "wide"}
        if "narrow" in low:
            return {"_global": "narrow"}

    # Infer from CCD count per socket.
    socket_ccds = {}
    for vals in topo.values():
        sock = vals.get("socket", -1)
        ccd = vals.get("ccd", -1)
        if ccd != -1:
            socket_ccds.setdefault(sock, set()).add(ccd)
    out = {}
    for sock, ccds in socket_ccds.items():
        # 4-CCD-and-below parts are the wide OPNs; higher counts are narrow.
        out[sock] = "likely-wide (inferred)" if len(ccds) <= 4 else "likely-narrow (inferred)"
    return out


def gmi_for_socket(gmi_map, socket):
    if not gmi_map:
        return None
    if "_global" in gmi_map:
        return gmi_map["_global"]
    return gmi_map.get(socket)


def detect_ccd_confidence(raw, kernel_release=None, lstopo_text=None):
    """Return a confidence note string, or None when sources agree and kernel is new enough.

    die_id is unreliable on kernels < 6.10 for dense (Bergamo/Zen4c) parts,
    which need CPUID leaf 0x80000026.
    """
    notes = []
    if not any(e.get("die") not in (None, "") for e in raw.values()):
        notes.append("die_id unavailable in sysfs; CCD grouping unknown")

    if kernel_release:
        m = re.match(r"(\d+)\.(\d+)", kernel_release)
        if m:
            major, minor = int(m.group(1)), int(m.group(2))
            if (major, minor) < (6, 10):
                notes.append(
                    f"kernel {kernel_release} < 6.10: CCD/CCX may be misreported on "
                    "dense EPYC parts (needs CPUID leaf 0x80000026)"
                )

    if lstopo_text:
        # lstopo reports one L3 per "L3" line; cross-check CCX count.
        lstopo_l3 = len(re.findall(r"\bL3\b", lstopo_text))
        _, n_ccx, _ = parse_amd_topology(raw)
        if lstopo_l3 and n_ccx and lstopo_l3 != n_ccx:
            notes.append(
                f"sysfs CCX count ({n_ccx}) disagrees with lstopo L3 count "
                f"({lstopo_l3})"
            )
    return "; ".join(notes) if notes else None


# ---------------------------------------------------------------------------
# Scope classification
# ---------------------------------------------------------------------------

def topology_scope(cpus, topo):
    """Classify the placement of a set of CPUs, finest expensive boundary first.

    Hierarchy (cheap → expensive):
        single-cpu < same-ccx < cross-ccx < cross-ccd < cross-numa < cross-socket

    Degrades gracefully to same-numa when ccx/ccd data is absent (-1).
    """
    if not cpus:
        return "unknown"
    if len(cpus) == 1:
        return "single-cpu"

    def field(c, k):
        return topo.get(str(c), {}).get(k, -1)

    sockets = {field(c, "socket") for c in cpus}
    numas = {field(c, "numa") for c in cpus}
    ccds = {field(c, "ccd") for c in cpus}
    ccxs = {field(c, "ccx") for c in cpus}

    if len(sockets) > 1:
        return "cross-socket"
    if len(numas) > 1:
        return "cross-numa"
    # On-die boundaries only when we actually have the data (no -1 sentinels).
    if -1 not in ccds and len(ccds) > 1:
        return "cross-ccd"
    if -1 not in ccxs and len(ccxs) > 1:
        return "cross-ccx"
    if -1 not in ccxs and len(ccxs) == 1:
        return "same-ccx"
    return "same-numa"


# Stroke styling per scope: (color, width, dasharray-or-empty).
# Only applied when latency border is not severe (none / ok-green).
SCOPE_STROKE = {
    "cross-socket": ("#111827", "3", "6,2"),
    "cross-numa":   ("#7e22ce", "2", "2,2"),
    "cross-ccd":    ("#be123c", "2", "5,2"),
    "cross-ccx":    ("#0891b2", "1.5", "3,2"),
    "same-ccx":     ("#a855f7", "1", "4,2"),
    "same-numa":    ("#a855f7", "1", "4,2"),
}


def topology_tooltip(cpus, topo, gmi_map=None):
    """Build the '--- topology ---' tooltip lines for a frame, or [] if no cpus."""
    if not cpus:
        return []
    sockets = sorted({topo.get(str(c), {}).get("socket", -1) for c in cpus})
    numas = sorted({topo.get(str(c), {}).get("numa", -1) for c in cpus})
    ccds = sorted({topo.get(str(c), {}).get("ccd", -1) for c in cpus})
    ccxs = sorted({topo.get(str(c), {}).get("ccx", -1) for c in cpus})
    scope = topology_scope(cpus, topo)

    lines = ["--- topology ---"]
    lines.append(f"cpus   : {','.join(map(str, cpus[:16]))}{'...' if len(cpus) > 16 else ''}")
    lines.append(f"socket : {sockets}")
    lines.append(f"numa   : {numas}")
    if -1 not in ccds:
        lines.append(f"ccd    : {ccds}")
    if -1 not in ccxs:
        lines.append(f"ccx    : {ccxs}")
    gmi = gmi_for_socket(gmi_map, sockets[0]) if len(sockets) == 1 else None
    if gmi:
        lines.append(f"gmi    : {gmi}")
    lines.append(f"scope  : {scope}")
    return lines
