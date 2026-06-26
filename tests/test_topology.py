"""Tests for AMD CCX/CCD/GMI topology logic (run on any OS, no root/sysfs needed).

    python -m pytest tests/test_topology.py      # or
    python tests/test_topology.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dpdk_fg.topology import (
    detect_ccd_confidence,
    infer_gmi,
    merge_topology,
    parse_amd_topology,
    topology_scope,
    topology_tooltip,
)

FIXTURE = Path(__file__).parent.parent / "examples" / "sample_amd_topology_raw.json"


def _load():
    raw = json.loads(FIXTURE.read_text())
    ccx_map, n_ccx, n_ccd = parse_amd_topology(raw)
    # Minimal socket/numa from package field so scope logic has something to chew.
    topo = {c: {"socket": int(raw[c]["package"]), "numa": int(raw[c]["package"])} for c in raw}
    merge_topology(topo, ccx_map)
    return raw, topo, ccx_map, n_ccx, n_ccd


def test_counts():
    _, _, _, n_ccx, n_ccd = _load()
    assert n_ccx == 3   # two CCX on socket0, one on socket1
    assert n_ccd == 3


def test_scopes():
    _, topo, _, _, _ = _load()
    assert topology_scope([0], topo) == "single-cpu"
    assert topology_scope([0, 1], topo) == "same-ccx"      # same die, same L3
    assert topology_scope([0, 8], topo) == "cross-ccd"     # diff die, same socket
    assert topology_scope([0, 96], topo) == "cross-socket"  # diff package


def test_degrade_without_amd_data():
    topo = {"0": {"socket": 0, "numa": 0}, "1": {"socket": 0, "numa": 0}}
    assert topology_scope([0, 1], topo) == "same-numa"


def test_gmi_inference_and_override():
    _, topo, _, _, _ = _load()
    inferred = infer_gmi(topo)
    assert any("inferred" in v for v in inferred.values())
    assert infer_gmi(topo, "xGMI link width: WIDE") == {"_global": "wide"}


def test_confidence_old_kernel():
    raw, _, _, _, _ = _load()
    assert "6.10" in detect_ccd_confidence(raw, "5.15.0")
    assert detect_ccd_confidence(raw, "6.11.0") is None


def test_tooltip_has_ccx_ccd():
    _, topo, _, _, _ = _load()
    lines = topology_tooltip([0, 8], topo, {0: "narrow"})
    joined = "\n".join(lines)
    assert "ccd" in joined and "ccx" in joined and "scope  : cross-ccd" in joined


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all passed")
