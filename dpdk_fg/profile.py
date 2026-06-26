"""Target profile system for FlameGraph enhancement.

A Profile defines how to classify, color, and annotate FlameGraph frames for a
specific target (DPDK, SSL, kernel networking, lock contention, or user-defined).

Built-in profiles: dpdk | ssl | kernel-net | lock | generic

Usage:
    profile = load_profile("dpdk")
    profile = load_profile("/path/to/custom.json")
    merge_skill_output(profile, skill_json_dict)
    category_id = classify_func("rte_eth_rx_burst", kernel_assoc=False, profile=profile)
    color, width, css_class = latency_border({"avg_ns": 6000}, profile)
"""

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------

@dataclass
class Category:
    """One classification bucket inside a profile."""
    id: str
    label: str
    color: str
    # A frame is matched if its normalized name starts with any prefix
    prefixes: List[str] = field(default_factory=list)
    # …or contains any hint as a substring (case-insensitive)
    hints: List[str] = field(default_factory=list)
    # When True this category matches kernel-path frames from perf
    is_kernel: bool = False
    # When True this is the catch-all fallback (matched last)
    is_default: bool = False
    # Darker shade when parent stack contains kernel interaction
    kernel_interaction_color: Optional[str] = None


@dataclass
class Profile:
    name: str
    description: str
    categories: List[Category] = field(default_factory=list)
    # Substrings that mark a frame as kernel-facing (darkens DPDK/userspace parent)
    kernel_hints: List[str] = field(default_factory=list)
    # Thresholds for border coloring
    high_ns: int = 5000
    medium_ns: int = 1000
    # Default funclatency patterns (may be overridden via CLI)
    funclatency_patterns: List[str] = field(default_factory=list)
    # Hot symbol → category_id override injected by --skill-output
    _hot_symbol_map: Dict[str, str] = field(default_factory=dict, repr=False)


# ---------------------------------------------------------------------------
# Built-in profile definitions
# ---------------------------------------------------------------------------

_BUILTIN: Dict[str, dict] = {

    "dpdk": {
        "name": "dpdk",
        "description": "DPDK and PMD userspace datapath",
        "categories": [
            {"id": "dpdk",   "label": "DPDK API",
             "color": "#22c55e", "prefixes": ["rte_", "__rte_"],
             "kernel_interaction_color": "#14532d"},
            {"id": "pmd",    "label": "PMD / Driver",
             "color": "#15803d",
             "hints": ["rx", "tx", "burst", "qdma", "mlx5", "bnxt",
                       "iavf", "ice", "ena", "sfc", "i40e"],
             "kernel_interaction_color": "#064e3b"},
            {"id": "kernel", "label": "Kernel",
             "color": "#3b82f6", "is_kernel": True},
            {"id": "other",  "label": "Other",
             "color": "#9ca3af", "is_default": True},
        ],
        "kernel_hints": [
            "sys_", "__x64_sys", "ioctl", "read", "write", "mmap", "munmap",
            "epoll", "eventfd", "vfio", "uio", "irq", "softirq", "napi",
            "net_rx_action", "__softirqentry", "schedule", "fput", "sock_",
        ],
        "high_ns": 5000,
        "medium_ns": 1000,
        "funclatency_patterns": ["rte_*", "qdma_*"],
    },

    "ssl": {
        "name": "ssl",
        "description": "OpenSSL / TLS / crypto userspace",
        "categories": [
            {"id": "ssl_api",  "label": "SSL/TLS API",
             "color": "#f97316",
             "prefixes": ["SSL_", "TLS_", "ssl_", "tls_"],
             "kernel_interaction_color": "#c2410c"},
            {"id": "crypto",   "label": "Crypto / BIO",
             "color": "#fbbf24",
             "prefixes": ["EVP_", "BIO_", "BN_", "EC_", "RSA_", "AES_",
                          "SHA", "HMAC_", "RAND_"],
             "kernel_interaction_color": "#92400e"},
            {"id": "kernel",   "label": "Kernel",
             "color": "#3b82f6", "is_kernel": True},
            {"id": "other",    "label": "Other",
             "color": "#9ca3af", "is_default": True},
        ],
        "kernel_hints": [
            "sys_", "__x64_sys_", "__se_sys_", "__ia32_sys_",
            "ksys_", "kernel_", "__sys_",
        ],
        "high_ns": 10000,
        "medium_ns": 2000,
        "funclatency_patterns": ["SSL_*", "EVP_*", "BIO_*"],
    },

    "kernel-net": {
        "name": "kernel-net",
        "description": "Linux kernel networking stack",
        "categories": [
            {"id": "softirq", "label": "SoftIRQ / NAPI",
             "color": "#a855f7",
             "hints": ["softirq", "napi", "net_rx_action", "__softirqentry",
                       "ksoftirqd"]},
            {"id": "socket",  "label": "Socket / VFS",
             "color": "#6366f1",
             "prefixes": ["sock_", "tcp_", "udp_", "ip_", "skb_", "sk_"],
             "hints": ["socket", "sendmsg", "recvmsg"]},
            {"id": "driver",  "label": "NIC Driver",
             "color": "#0ea5e9",
             "hints": ["mlx5", "bnxt", "i40e", "iavf", "igb_", "ixgbe",
                       "ena_", "sfc_", "nfp_"]},
            {"id": "other",   "label": "Other Kernel",
             "color": "#9ca3af", "is_default": True},
        ],
        "kernel_hints": [],
        "high_ns": 20000,
        "medium_ns": 5000,
        "funclatency_patterns": ["tcp_*", "udp_*", "napi_*"],
    },

    "lock": {
        "name": "lock",
        "description": "Lock and atomic contention (from skill output)",
        "categories": [
            {"id": "contended_lock", "label": "Contended Lock",
             "color": "#dc2626",
             "hints": ["mutex", "futex", "__lll_lock", "pthread_mutex",
                       "spin_lock", "spin_trylock", "osq_lock", "mcs_spin"],
             "kernel_interaction_color": "#7f1d1d"},
            {"id": "atomic",         "label": "Atomic / CAS",
             "color": "#f59e0b",
             "hints": ["atomic_cmpxchg", "__cmpxchg", "_raw_spin",
                       "atomic_fetch", "atomic_add", "xchg"]},
            {"id": "kernel",         "label": "Kernel",
             "color": "#3b82f6", "is_kernel": True},
            {"id": "other",          "label": "Other",
             "color": "#9ca3af", "is_default": True},
        ],
        "kernel_hints": [
            "sys_", "schedule", "futex_wait", "mutex_lock",
        ],
        "high_ns": 1000,
        "medium_ns": 100,
        "funclatency_patterns": ["pthread_mutex_*", "futex*"],
    },

    "generic": {
        "name": "generic",
        "description": "User-defined: add categories via --extra-category or --skill-output",
        "categories": [
            {"id": "kernel", "label": "Kernel",
             "color": "#3b82f6", "is_kernel": True},
            {"id": "other",  "label": "Other",
             "color": "#9ca3af", "is_default": True},
        ],
        "kernel_hints": [
            "sys_", "__x64_sys", "ioctl", "schedule", "softirq",
        ],
        "high_ns": 5000,
        "medium_ns": 1000,
        "funclatency_patterns": [],
    },
}


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _category_from_dict(d: dict) -> Category:
    return Category(
        id=d["id"],
        label=d.get("label", d["id"]),
        color=d["color"],
        prefixes=d.get("prefixes", []),
        hints=d.get("hints", []),
        is_kernel=d.get("is_kernel", False),
        is_default=d.get("is_default", False),
        kernel_interaction_color=d.get("kernel_interaction_color"),
    )


def _profile_from_dict(d: dict) -> Profile:
    return Profile(
        name=d["name"],
        description=d.get("description", ""),
        categories=[_category_from_dict(c) for c in d.get("categories", [])],
        kernel_hints=d.get("kernel_hints", []),
        high_ns=d.get("high_ns", d.get("latency_thresholds", {}).get("high_ns", 5000)),
        medium_ns=d.get("medium_ns", d.get("latency_thresholds", {}).get("medium_ns", 1000)),
        funclatency_patterns=d.get("funclatency_patterns", []),
    )


def load_profile(name_or_path: str) -> Profile:
    """Load a built-in profile by name, or a JSON file by path.

    Built-in names: dpdk | ssl | kernel-net | lock | generic
    File: any path ending in .json
    """
    if name_or_path in _BUILTIN:
        return _profile_from_dict(_BUILTIN[name_or_path])
    p = Path(name_or_path)
    if p.exists() and p.suffix == ".json":
        return _profile_from_dict(json.loads(p.read_text()))
    raise ValueError(
        f"Unknown profile {name_or_path!r}. "
        f"Built-ins: {', '.join(_BUILTIN)}. Or pass a path to a .json file."
    )


def save_profile(profile: Profile, path: str) -> None:
    """Dump the resolved profile to JSON (for repeatability / audit)."""
    d = {
        "name": profile.name,
        "description": profile.description,
        "categories": [
            {
                "id": c.id, "label": c.label, "color": c.color,
                "prefixes": c.prefixes, "hints": c.hints,
                "is_kernel": c.is_kernel, "is_default": c.is_default,
                "kernel_interaction_color": c.kernel_interaction_color,
            }
            for c in profile.categories
        ],
        "kernel_hints": profile.kernel_hints,
        "high_ns": profile.high_ns,
        "medium_ns": profile.medium_ns,
        "funclatency_patterns": profile.funclatency_patterns,
    }
    Path(path).write_text(json.dumps(d, indent=2))


# ---------------------------------------------------------------------------
# Skill-output merge
# ---------------------------------------------------------------------------

def merge_skill_output(profile: Profile, skill: dict) -> None:
    """Merge extra categories and hot symbol hints from a skill-emitted JSON.

    Expected schema:
    {
      "skill": "lock-atomic-contention",
      "hot_symbols": ["pthread_mutex_lock", "futex_wait"],
      "funclatency_patterns": ["pthread_mutex_*"],
      "extra_categories": [
        {"id": "contended_lock", "hints": ["mutex", "futex"],
         "color": "#dc2626", "label": "Contended Lock"}
      ]
    }
    """
    # Prepend extra categories before the default catch-all
    for cat_dict in skill.get("extra_categories", []):
        cat = _category_from_dict(cat_dict)
        # Insert before the default category so it takes precedence
        default_pos = next(
            (i for i, c in enumerate(profile.categories) if c.is_default), len(profile.categories)
        )
        profile.categories.insert(default_pos, cat)

    # Map hot symbols to a category (first extra_category if present, else "contended_lock")
    extra_ids = [c["id"] for c in skill.get("extra_categories", [])]
    target_id = extra_ids[0] if extra_ids else None
    for sym in skill.get("hot_symbols", []):
        if target_id:
            profile._hot_symbol_map[sym] = target_id

    # Merge funclatency patterns (deduplicate)
    for pat in skill.get("funclatency_patterns", []):
        if pat not in profile.funclatency_patterns:
            profile.funclatency_patterns.append(pat)


def add_extra_category(profile: Profile, spec: str) -> None:
    """Parse a CLI --extra-category spec: 'id:prefix1,prefix2:color'.

    Examples:
      mylib:mylib_,__mylib_:#f97316
      contended:mutex,futex:#dc2626
    """
    parts = spec.split(":")
    if len(parts) < 3:
        raise ValueError(
            f"--extra-category must be 'id:prefix1,prefix2:color' — got {spec!r}"
        )
    cat_id, raw_hints, color = parts[0], parts[1], parts[2]
    prefixes = [h for h in raw_hints.split(",") if h.endswith("_") or h.endswith("*")]
    hints = [h for h in raw_hints.split(",") if not h.endswith("_") and not h.endswith("*")]
    cat = Category(id=cat_id, label=cat_id, color=color, prefixes=prefixes, hints=hints)
    default_pos = next(
        (i for i, c in enumerate(profile.categories) if c.is_default), len(profile.categories)
    )
    profile.categories.insert(default_pos, cat)


# ---------------------------------------------------------------------------
# Classification and coloring
# ---------------------------------------------------------------------------

def is_kernel_frame(fn: str, profile: Profile) -> bool:
    """Return True if this frame name looks like a kernel path.

    Kernel hints are matched as PREFIXES only (not arbitrary substrings) to
    avoid false positives like 'write' matching 'SSL_write'. The only exception
    is the explicit [kernel...] markers which are checked as substrings.
    """
    if "[kernel.kallsyms]" in fn or "[kernel]" in fn or "[kernel" in fn:
        return True
    return any(fn.startswith(h) for h in profile.kernel_hints)


def classify_func(fn: str, kernel_associated: bool, profile: Profile) -> str:
    """Return the category id that best matches fn under profile.

    Lookup order:
    1. Hot symbol map (from --skill-output)
    2. Explicit kernel frame detection
    3. Category prefixes (longest match first)
    4. Category hints (substring, case-insensitive)
    5. Default catch-all category
    """
    # Hot symbol override (from skill output)
    if fn in profile._hot_symbol_map:
        return profile._hot_symbol_map[fn]

    # Kernel frame
    if is_kernel_frame(fn, profile):
        for cat in profile.categories:
            if cat.is_kernel:
                return cat.id

    fn_lower = fn.lower()
    default_id = None

    for cat in profile.categories:
        if cat.is_kernel:
            continue
        if cat.is_default:
            default_id = cat.id
            continue
        for prefix in cat.prefixes:
            if fn.startswith(prefix):
                return cat.id
        for hint in cat.hints:
            if hint in fn_lower:
                return cat.id

    return default_id or "other"


def category_color(cat_id: str, kernel_associated: bool, profile: Profile) -> str:
    """Return the fill hex color for this category."""
    for cat in profile.categories:
        if cat.id == cat_id:
            if kernel_associated and cat.kernel_interaction_color:
                return cat.kernel_interaction_color
            return cat.color
    return "#9ca3af"


def latency_border(lat: Optional[dict], profile: Profile) -> Tuple[str, str, str]:
    """Return (stroke_color, stroke_width, css_hint) for a frame's latency data."""
    if not lat:
        return "none", "0", ""
    avg = int(lat.get("avg_ns", 0))
    if avg > profile.high_ns:
        return "#ef4444", "2", "latency-high"
    if avg > profile.medium_ns:
        return "#f59e0b", "1.5", "latency-medium"
    return "#10b981", "1", "latency-ok"
