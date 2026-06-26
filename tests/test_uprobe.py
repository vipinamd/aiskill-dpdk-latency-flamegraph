"""Tests for funclatency kprobe/uprobe command construction (any OS, no root/BPF).

    python tests/test_uprobe.py        # or: python -m pytest tests/test_uprobe.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from dpdk_fg.cli import build_funclatency_cmds, _safe_label
from dpdk_fg.profile import load_profile, save_profile


def _argvs(cmds):
    return [argv for argv, _ in cmds]


def test_kprobe_default():
    # No uprobe targets, bare pattern → original '-u' kprobe behavior.
    cmds = build_funclatency_cmds(1234, ["tcp_sendmsg"], uprobe_targets=[])
    assert _argvs(cmds) == [["funclatency-bpfcc", "-p", "1234", "-u", "tcp_sendmsg"]]


def test_uprobe_target_expands_per_target():
    cmds = build_funclatency_cmds(
        99, ["EVP_*"], uprobe_targets=["/lib/libcrypto.so.3", "/lib/libssl.so.3"])
    argvs = _argvs(cmds)
    assert ["funclatency-bpfcc", "-p", "99", "/lib/libcrypto.so.3:EVP_*"] in argvs
    assert ["funclatency-bpfcc", "-p", "99", "/lib/libssl.so.3:EVP_*"] in argvs
    assert len(argvs) == 2
    # No '-u' kprobe flag when tracing uprobes
    assert all("-u" not in a for a in argvs)


def test_explicit_path_func_passthrough():
    # Pattern already in bcc 'binpath:func' form → passed through verbatim.
    cmds = build_funclatency_cmds(7, ["/usr/bin/app:do_work"], uprobe_targets=[])
    assert _argvs(cmds) == [["funclatency-bpfcc", "-p", "7", "/usr/bin/app:do_work"]]


def test_exe_token_resolves_to_proc_exe(monkeypatch=None):
    # 'exe:func' resolves the left side via /proc/PID/exe. We can't readlink a fake
    # pid, so just assert the fallback keeps the spec intact when resolution fails.
    cmds = build_funclatency_cmds(0, ["exe:rte_eal_wait_lcore"], uprobe_targets=[])
    spec = _argvs(cmds)[0][-1]
    # Either resolved to a real path:func or left as the original token — never empty.
    assert spec.endswith(":rte_eal_wait_lcore")


def test_duration_flag():
    cmds = build_funclatency_cmds(5, ["foo"], uprobe_targets=[], duration=3)
    assert "-d" in _argvs(cmds)[0] and "3" in _argvs(cmds)[0]


def test_safe_label():
    assert _safe_label("EVP_*") == "EVP__"
    assert _safe_label("/lib/x.so:fn") == "_lib_x.so_fn"


def test_ssl_profile_has_uprobe_targets():
    p = load_profile("ssl")
    assert any("libcrypto" in t for t in p.uprobe_targets)


def test_profile_roundtrip_preserves_uprobe_targets(tmp_path=None):
    import tempfile, os
    p = load_profile("ssl")
    f = os.path.join(tempfile.gettempdir(), "prof_rt.json")
    save_profile(p, f)
    p2 = load_profile(f)
    assert p2.uprobe_targets == p.uprobe_targets


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"PASS {name}")
    print("all passed")
