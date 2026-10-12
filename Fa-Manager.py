"""
Fa-Manager — Fa-Crab's central state, config, cache, error, warning,
link, optimization, and loading engine.

Public API:
    from Fa_Manager import get_manager, reset_manager

    mgr = get_manager()
    mgr.config.get("fetch.timeout_total_seconds")
    mgr.write_record(record)
    if mgr.is_seen(url): ...

Everything else is a subsystem accessed through the facade:
    mgr.config, mgr.agents, mgr.errors, mgr.warnings, mgr.cache,
    mgr.links, mgr.optimizer, mgr.loader, mgr.output, mgr.state,
    mgr.dedup, mgr.checkpoint, mgr.frontier, mgr.cookies,
    mgr.domain_state, mgr.rate_state, mgr.stats, mgr.metrics,
    mgr.export, mgr.query, mgr.locks, mgr.secrets

Manager never imports Crawl, Scraper, Terminal, or GUI.
Manager is a leaf module.
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import asyncio
import atexit
import contextlib
import functools
import gc
import hashlib
import heapq
import json
import logging
import logging.handlers
import mmap
import os
import queue
import re
import shutil
import signal
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import traceback
import types
import unicodedata
import uuid
import warnings
import weakref
from abc import ABC, abstractmethod
from collections import OrderedDict, defaultdict, deque
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timedelta, timezone
from enum import Enum, IntEnum, auto
from pathlib import Path
from typing import (
    Any, AsyncIterator, Callable, Iterable, Iterator, Mapping, MutableMapping,
    Optional, Sequence, Union,
)

# ─── third-party ─────────────────────────────────────────────────────────────
try:
    import orjson
except ImportError:  # pragma: no cover
    orjson = None

try:
    import xxhash
except ImportError:  # pragma: no cover
    xxhash = None

try:
    import zstandard as zstd
except ImportError:  # pragma: no cover
    zstd = None

try:
    import aiosqlite
except ImportError:  # pragma: no cover
    aiosqlite = None

try:
    from cachetools import Cache, LRUCache, LFUCache, TTLCache
except ImportError:  # pragma: no cover
    Cache = LRUCache = LFUCache = TTLCache = None  # type: ignore

FileLockTimeout: type[BaseException]
try:
    from filelock import FileLock, Timeout as _FileLockTimeout
    FileLockTimeout = _FileLockTimeout
except ImportError:  # pragma: no cover
    FileLock = None  # type: ignore
    FileLockTimeout = TimeoutError

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

try:
    from dateutil import parser as dateutil_parser
except ImportError:  # pragma: no cover
    dateutil_parser = None

try:
    import tzlocal
except ImportError:  # pragma: no cover
    tzlocal = None

try:
    import py7zr
    HAS_PY7ZR = True
except ImportError:
    py7zr = None
    HAS_PY7ZR = False

try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    Fernet = None  # type: ignore
    HAS_CRYPTO = False


__all__ = [
    "get_manager",
    "reset_manager",
    "ManagerFacade",
    "ManagerError",
    "ConfigError",
    "StateError",
    "OutputError",
    "ErrorRecord",
    "ErrorSeverity",
    "ErrorCategory",
    "WarningRecord",
    "WarningSeverity",
    "cachetools",
]


# ════════════════════════════════════════════════════════════════════════════
# Constants & exceptions
# ════════════════════════════════════════════════════════════════════════════

MANAGER_VERSION = "1.0.0"
ENV_PREFIX = "FA_CRAB_"
DEFAULT_CHUNK_SIZE = 1 << 20  # 1 MiB
MAX_JSONL_LINE = 64 << 20     # 64 MiB — safety cap for FastLoader


class ManagerError(Exception):
    """Base for all Fa-Manager errors."""


class ConfigError(ManagerError):
    """Config file missing, invalid, or schema-violating."""


class StateError(ManagerError):
    """State DB, dedup, checkpoint, or frontier failure."""


class OutputError(ManagerError):
    """Output write, rotation, compression, or manifest failure."""


class CacheKeyError(ManagerError):
    """Cache key computation or lookup failure."""


class LoaderError(ManagerError):
    """FastLoader failed to open or read a file."""


# ════════════════════════════════════════════════════════════════════════════
# Enums & dataclasses
# ════════════════════════════════════════════════════════════════════════════

class ErrorSeverity(IntEnum):
    DEBUG = 10
    INFO = 20
    WARNING = 30
    ERROR = 40
    CRITICAL = 50

    @classmethod
    def from_name(cls, name: str) -> "ErrorSeverity":
        return cls[name.upper()]


class ErrorCategory(str, Enum):
    CONFIG = "config"
    NETWORK = "network"
    PARSE = "parse"
    EXTRACT = "extract"
    STORAGE = "storage"
    CACHE = "cache"
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    VALIDATION = "validation"
    ROBOTS = "robots"
    LINK = "link"
    OUTPUT = "output"
    INTERNAL = "internal"
    UNKNOWN = "unknown"


class WarningSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CacheTier(str, Enum):
    RESPONSE = "response"
    DOM = "dom"
    EXTRACT = "extract"
    ROBOTS = "robots"
    DNS = "dns"
    CONFIG = "config"
    URL_NORM = "url_norm"
    LINK = "link"
    UA = "ua"
    HEADER = "header"


class OutputMode(str, Enum):
    JSONL = "jsonl"
    JSONL_ZST = "jsonl.zst"
    JSONL_GZ = "jsonl.gz"
    PARQUET = "parquet"
    CSV = "csv"
    SQLITE = "sqlite"


@dataclass(slots=True)
class ErrorRecord:
    """One captured error event."""
    id: str
    timestamp: float
    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    exception_type: str
    exception_repr: str
    traceback_str: str
    context: dict = field(default_factory=dict)
    url: Optional[str] = None
    domain: Optional[str] = None
    retryable: bool = False
    retry_hint_seconds: Optional[float] = None
    count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0

    def signature(self) -> str:
        """Stable identity for deduplication."""
        h = xxhash.xxh64() if xxhash else hashlib.sha1()
        h.update(self.exception_type.encode())
        h.update(b"\x00")
        h.update(self.message[:512].encode("utf-8", "replace"))
        if xxhash:
            return h.hexdigest()
        return h.hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = int(self.severity)
        return d


@dataclass(slots=True)
class WarningRecord:
    """One captured warning."""
    id: str
    timestamp: float
    severity: WarningSeverity
    code: str
    message: str
    context: dict = field(default_factory=dict)
    count: int = 1
    first_seen: float = 0.0
    last_seen: float = 0.0
    suppressed: bool = False

    def signature(self) -> str:
        h = xxhash.xxh64() if xxhash else hashlib.sha1()
        h.update(self.code.encode())
        h.update(b"\x00")
        h.update(self.message[:512].encode("utf-8", "replace"))
        if xxhash:
            return h.hexdigest()
        return h.hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass(slots=True)
class LinkEdge:
    """One directed link from a page to a target."""
    source_url: str
    target_url: str
    anchor_text: str = ""
    rel: str = ""
    is_internal: bool = False
    discovered_at: float = 0.0


@dataclass(slots=True)
class CrawlStats:
    """Aggregate counters. Thread-safe snapshot via StatsCollector."""
    fetched: int = 0
    parsed: int = 0
    written: int = 0
    skipped: int = 0
    errors: int = 0
    warnings: int = 0
    retries: int = 0
    dedup_hits: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    links_seen: int = 0
    links_unique: int = 0
    started_at: float = 0.0
    last_update: float = 0.0


@dataclass(slots=True)
class OptimizerHint:
    """A single optimization recommendation from the Optimization Center."""
    key: str
    current_value: Any
    suggested_value: Any
    reason: str
    confidence: float  # 0.0 – 1.0
    applied: bool = False


# ════════════════════════════════════════════════════════════════════════════
# Small utilities
# ════════════════════════════════════════════════════════════════════════════

def _utc_now() -> float:
    return time.time()


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _xxh64(data: Union[bytes, str], seed: int = 0) -> str:
    """Fast 64-bit hash. Falls back to blake2b if xxhash is missing."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if xxhash is not None:
        return xxhash.xxh64(data, seed=seed).hexdigest()
    return hashlib.blake2b(data, digest_size=8).hexdigest()


def _xxh3_128(data: Union[bytes, str]) -> str:
    """Fast 128-bit hash for content dedup."""
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if xxhash is not None:
        return xxhash.xxh3_128(data).hexdigest()
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def _json_dumps(obj: Any) -> bytes:
    """orjson fast path, stdlib fallback."""
    if orjson is not None:
        return orjson.dumps(obj, option=orjson.OPT_NON_STR_KEYS)
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_loads(data: Union[bytes, str]) -> Any:
    if orjson is not None:
        return orjson.loads(data)
    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data)


def _safe_mkdir(path: Union[str, Path]) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _atomic_write(path: Union[str, Path], data: bytes) -> None:
    """Write bytes atomically: temp file → fsync → rename."""
    path = Path(path)
    tmp = path.with_suffix(path.suffix + f".tmp.{uuid.uuid4().hex[:8]}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _deep_freeze(obj: Any) -> Any:
    """Recursively freeze dicts/lists into immutable equivalents."""
    if isinstance(obj, Mapping):
        return types.MappingProxyType({k: _deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, (list, tuple)):
        return tuple(_deep_freeze(v) for v in obj)
    return obj


def _deep_merge(base: dict, overlay: dict) -> dict:
    """Deep-merge overlay into base, returning a new dict."""
    out = dict(base)
    for k, v in overlay.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, Mapping):
            out[k] = _deep_merge(out[k], dict(v))
        else:
            out[k] = v
    return out


def _dot_get(d: Mapping, path: str, default: Any = None) -> Any:
    node: Any = d
    for part in path.split("."):
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        else:
            return default
    return node


def _dot_set(d: MutableMapping, path: str, value: Any) -> None:
    parts = path.split(".")
    node = d
    for p in parts[:-1]:
        node = node.setdefault(p, {})
    node[parts[-1]] = value


# ════════════════════════════════════════════════════════════════════════════
# 1. Config layer
# ════════════════════════════════════════════════════════════════════════════

class ConfigAccessor:
    """Read-only dot-path view over a nested config dict."""

    __slots__ = ("_data", "_frozen", "_lock")

    def __init__(self, data: Mapping, freeze: bool = True):
        self._data = dict(data)
        self._frozen = _deep_freeze(self._data) if freeze else self._data
        self._lock = threading.RLock()

    def get(self, path: str, default: Any = None) -> Any:
        with self._lock:
            v = _dot_get(self._frozen, path, default=default)
            if isinstance(v, types.MappingProxyType):
                return dict(v)
            return v

    def __getitem__(self, path: str) -> Any:
        sentinel = object()
        v = self.get(path, default=sentinel)
        if v is sentinel:
            raise KeyError(path)
        return v

    def __contains__(self, path: str) -> bool:
        sentinel = object()
        return self.get(path, default=sentinel) is not sentinel

    def keys(self) -> list[str]:
        return list(self._frozen.keys())

    def raw(self) -> Mapping:
        return self._frozen

    def as_dict(self) -> dict:
        def unfreeze(v: Any) -> Any:
            if isinstance(v, types.MappingProxyType):
                return {k: unfreeze(x) for k, x in v.items()}
            if isinstance(v, tuple):
                return [unfreeze(x) for x in v]
            return v
        return unfreeze(self._frozen)


class ConfigLoader:
    """Loads Config.json, applies env overlay, validates, wraps in accessor."""

    REQUIRED_TOP_KEYS = ("metadata", "global", "fetch", "parse", "extract")

    def __init__(self, path: Union[str, Path], env_prefix: str = ENV_PREFIX,
                 strict: bool = True):
        self.path = Path(path)
        self.env_prefix = env_prefix
        self.strict = strict

    def load(self) -> ConfigAccessor:
        if not self.path.exists():
            raise ConfigError(f"Config file not found: {self.path}")
        try:
            raw = _json_loads(self.path.read_bytes())
        except Exception as e:
            raise ConfigError(f"Config parse failure: {e}") from e
        if not isinstance(raw, dict):
            raise ConfigError("Config root must be an object")
        if self.strict:
            missing = [k for k in self.REQUIRED_TOP_KEYS if k not in raw]
            if missing:
                raise ConfigError(f"Missing required top-level keys: {missing}")
        overlaid = self._apply_env(raw)
        return ConfigAccessor(overlaid, freeze=True)

    def _apply_env(self, cfg: dict) -> dict:
        if load_dotenv is not None:
            with suppress(Exception):
                load_dotenv(override=False)
        out = dict(cfg)
        for key, val in os.environ.items():
            if not key.startswith(self.env_prefix):
                continue
            path = key[len(self.env_prefix):].lower().replace("__", ".")
            coerced = self._coerce(val)
            _dot_set(out, path, coerced)
        return out

    @staticmethod
    def _coerce(v: str) -> Any:
        vl = v.strip().lower()
        if vl in ("true", "yes", "on"): return True
        if vl in ("false", "no", "off"): return False
        if vl in ("null", "none", ""): return None
        try: return int(v)
        except ValueError: pass
        try: return float(v)
        except ValueError: pass
        if v.startswith("[") or v.startswith("{"):
            try: return _json_loads(v)
            except Exception: pass
        return v


class AgentsLoader:
    """Loads Agents.json with a built-in minimal fallback."""

    FALLBACK = {
        "user_agents": {
            "chrome_windows": [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/140.0.7200.0 Safari/537.36",
            ],
        },
        "header_presets": {},
        "cookie_acceptors": {},
        "rotation": {"strategy": "random"},
        "behaviors": {},
    }

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)

    def load(self) -> ConfigAccessor:
        if not self.path.exists():
            warnings.warn(f"Agents file missing ({self.path}); using fallback",
                          RuntimeWarning, stacklevel=2)
            return ConfigAccessor(self.FALLBACK, freeze=True)
        try:
            data = _json_loads(self.path.read_bytes())
        except Exception as e:
            warnings.warn(f"Agents parse failure ({e}); using fallback",
                          RuntimeWarning, stacklevel=2)
            return ConfigAccessor(self.FALLBACK, freeze=True)
        # merge missing sections from fallback
        for k, v in self.FALLBACK.items():
            data.setdefault(k, v)
        return ConfigAccessor(data, freeze=True)


class ConfigWatcher:
    """Polls mtime of config files and triggers a callback on change."""

    def __init__(self, paths: Sequence[Path], interval: float = 2.0,
                 callback: Optional[Callable[[Path], None]] = None):
        self.paths = [Path(p) for p in paths]
        self.interval = interval
        self.callback = callback
        self._mtimes: dict[Path, float] = {}
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._snapshot()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop,
                                        name="FaConfigWatcher",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self.interval * 2)

    def _snapshot(self) -> None:
        for p in self.paths:
            with suppress(OSError):
                self._mtimes[p] = p.stat().st_mtime

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            for p in self.paths:
                try:
                    m = p.stat().st_mtime
                except OSError:
                    continue
                old = self._mtimes.get(p)
                if old is not None and m > old:
                    self._mtimes[p] = m
                    if self.callback:
                        try:
                            self.callback(p)
                        except Exception:
                            pass


class ConfigBackup:
    """Timestamped config backups on every save."""

    def __init__(self, backup_dir: Union[str, Path]):
        self.dir = _safe_mkdir(backup_dir)

    def backup(self, src: Path) -> Optional[Path]:
        if not src.exists():
            return None
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        dst = self.dir / f"{src.stem}.backup.{ts}{src.suffix}"
        shutil.copy2(src, dst)
        return dst

    def prune(self, keep: int = 20) -> int:
        files = sorted(self.dir.glob("*.backup.*"),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        removed = 0
        for f in files[keep:]:
            with suppress(OSError):
                f.unlink()
                removed += 1
        return removed


# ════════════════════════════════════════════════════════════════════════════
# 2. Cache Manager (cachetools-backed, multi-tier)
# ════════════════════════════════════════════════════════════════════════════

class _ThreadSafeCache:
    """Wraps any cachetools cache with an RLock."""

    __slots__ = ("_cache", "_lock", "_hits", "_misses", "_evictions")

    def __init__(self, cache):
        if cache is None:
            raise RuntimeError("cachetools is required but not installed")
        self._cache = cache
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key, default=None):
        with self._lock:
            try:
                v = self._cache[key]
                self._hits += 1
                return v
            except KeyError:
                self._misses += 1
                return default

    def set(self, key, value):
        with self._lock:
            before = len(self._cache)
            self._cache[key] = value
            if len(self._cache) == before and key not in self._cache:
                self._evictions += 1

    def pop(self, key, default=None):
        with self._lock:
            return self._cache.pop(key, default)

    def clear(self):
        with self._lock:
            self._cache.clear()

    def __contains__(self, key):
        with self._lock:
            return key in self._cache

    def __len__(self):
        with self._lock:
            return len(self._cache)

    def stats(self) -> dict:
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "maxsize": getattr(self._cache, "maxsize", None),
                "hits": self._hits,
                "misses": self._misses,
                "evictions": self._evictions,
                "hit_rate": (self._hits / total) if total else 0.0,
            }


class CacheManager:
    """
    Multi-tier cache manager. Each tier is a cachetools cache wrapped
    for thread safety. Tiers can be individually resized, cleared, and
    introspected at runtime.
    """

    DEFAULT_SIZES = {
        CacheTier.RESPONSE:  1000,
        CacheTier.DOM:       500,
        CacheTier.EXTRACT:   500,
        CacheTier.ROBOTS:    2000,
        CacheTier.DNS:       10000,
        CacheTier.CONFIG:    500,
        CacheTier.URL_NORM:  50000,
        CacheTier.LINK:      20000,
        CacheTier.UA:        100,
        CacheTier.HEADER:    200,
    }

    DEFAULT_TTLS = {
        CacheTier.RESPONSE:  3600.0,
        CacheTier.DOM:       900.0,
        CacheTier.EXTRACT:   900.0,
        CacheTier.ROBOTS:    86400.0,
        CacheTier.DNS:       300.0,
        CacheTier.CONFIG:    0.0,       # no TTL — LFU only
        CacheTier.URL_NORM:  0.0,       # LRU only
        CacheTier.LINK:      0.0,
        CacheTier.UA:        0.0,
        CacheTier.HEADER:    0.0,
    }

    def __init__(self, sizes: Optional[dict[CacheTier, int]] = None,
                 ttls: Optional[dict[CacheTier, float]] = None):
        if TTLCache is None or LFUCache is None or LRUCache is None:
            raise RuntimeError("cachetools is required for CacheManager")
        self._lock = threading.RLock()
        self._tiers: dict[CacheTier, _ThreadSafeCache] = {}
        sizes = sizes or {}
        ttls = ttls or {}
        for tier in CacheTier:
            maxsize = sizes.get(tier, self.DEFAULT_SIZES[tier])
            ttl = ttls.get(tier, self.DEFAULT_TTLS[tier])
            if ttl and ttl > 0:
                backend = TTLCache(maxsize=maxsize, ttl=ttl)
            elif tier in (CacheTier.CONFIG,):
                backend = LFUCache(maxsize=maxsize)
            else:
                backend = LRUCache(maxsize=maxsize)
            self._tiers[tier] = _ThreadSafeCache(backend)

    def get(self, tier: CacheTier, key: Any, default: Any = None) -> Any:
        return self._tiers[tier].get(key, default)

    def set(self, tier: CacheTier, key: Any, value: Any) -> None:
        self._tiers[tier].set(key, value)

    def get_or_compute(self, tier: CacheTier, key: Any,
                       factory: Callable[[], Any]) -> Any:
        v = self._tiers[tier].get(key)
        if v is not None:
            return v
        v = factory()
        if v is not None:
            self._tiers[tier].set(key, v)
        return v

    def invalidate(self, tier: CacheTier, key: Any) -> None:
        self._tiers[tier].pop(key, None)

    def clear(self, tier: Optional[CacheTier] = None) -> None:
        if tier is None:
            for t in self._tiers.values():
                t.clear()
        else:
            self._tiers[tier].clear()

    def resize(self, tier: CacheTier, new_maxsize: int) -> None:
        """Create a fresh backend with new maxsize. Preserves hot items."""
        if TTLCache is None or LFUCache is None or LRUCache is None:
            raise RuntimeError("cachetools is required for CacheManager")
        with self._lock:
            old = self._tiers[tier]._cache  # noqa: SLF001
            ttl = getattr(old, "ttl", 0)
            items = list(old.items())
            if ttl and ttl > 0:
                backend = TTLCache(maxsize=new_maxsize, ttl=ttl)
            elif tier in (CacheTier.CONFIG,):
                backend = LFUCache(maxsize=new_maxsize)
            else:
                backend = LRUCache(maxsize=new_maxsize)
            # keep most recent items
            keep = items[-new_maxsize:]
            for k, v in keep:
                with suppress(Exception):
                    backend[k] = v
            self._tiers[tier] = _ThreadSafeCache(backend)

    def stats(self) -> dict[str, dict]:
        return {t.value: c.stats() for t, c in self._tiers.items()}

    def tiers(self) -> list[CacheTier]:
        return list(self._tiers.keys())

    @staticmethod
    def make_key(*parts: Any) -> str:
        """Deterministic cache key from arbitrary parts."""
        h = xxhash.xxh64() if xxhash else hashlib.sha1()
        for p in parts:
            if p is None:
                continue
            if isinstance(p, (bytes, bytearray)):
                h.update(p)
            elif isinstance(p, str):
                h.update(p.encode("utf-8", "replace"))
            else:
                h.update(repr(p).encode("utf-8", "replace"))
            h.update(b"\x1f")
        return h.hexdigest() if xxhash else h.hexdigest()[:16]


# ════════════════════════════════════════════════════════════════════════════
# 3. Error Manager
# ════════════════════════════════════════════════════════════════════════════

class ErrorManager:
    """
    Centralized error capture, classification, dedup, and dispatch.

    Usage:
        with mgr.errors.capture(category=ErrorCategory.NETWORK, url=url):
            do_network_thing()

        @mgr.errors.guard(category=ErrorCategory.PARSE, reraise=False)
        def risky():
            ...

    Errors are deduplicated by (exception_type, first 512 bytes of message).
    Each unique signature is stored once with a rolling count. Callbacks can
    subscribe to specific severities or categories.
    """

    RETRYABLE_EXCEPTIONS = (
        "TimeoutError", "ConnectionError", "ConnectionResetError",
        "ConnectionRefusedError", "ConnectionAbortedError",
        "socket.timeout", "socket.gaierror", "ssl.SSLError",
        "aiohttp.ClientConnectionError", "aiohttp.ServerTimeoutError",
        "asyncio.TimeoutError", "OSError",
    )

    RETRY_HINT_BY_STATUS = {
        408: 5.0, 425: 2.0, 429: 60.0, 500: 5.0, 502: 10.0, 503: 30.0,
        504: 15.0, 507: 60.0, 509: 60.0, 520: 30.0, 521: 30.0,
        522: 30.0, 523: 30.0, 524: 30.0,
    }

    def __init__(self, log: logging.Logger,
                 dedup_window_seconds: float = 300.0,
                 max_records: int = 10000):
        self._log = log
        self._lock = threading.RLock()
        self._by_sig: "OrderedDict[str, ErrorRecord]" = OrderedDict()
        self._by_category: dict[ErrorCategory, int] = defaultdict(int)
        self._by_severity: dict[ErrorSeverity, int] = defaultdict(int)
        self._callbacks: list[tuple[Optional[ErrorCategory],
                                    Optional[ErrorSeverity],
                                    Callable[[ErrorRecord], None]]] = []
        self._dedup_window = dedup_window_seconds
        self._max_records = max_records
        self._total = 0

    def capture(self, category: ErrorCategory = ErrorCategory.UNKNOWN,
                severity: ErrorSeverity = ErrorSeverity.ERROR,
                url: Optional[str] = None,
                context: Optional[dict] = None,
                reraise: bool = True,
                message: Optional[str] = None,
                retryable: Optional[bool] = None,
                retry_hint_seconds: Optional[float] = None):
        """Context manager. On exception, records it then optionally re-raises."""
        return _ErrorCapture(self, category, severity, url,
                             context or {}, reraise, message,
                             retryable, retry_hint_seconds)

    def guard(self, category: ErrorCategory = ErrorCategory.UNKNOWN,
              severity: ErrorSeverity = ErrorSeverity.ERROR,
              reraise: bool = False,
              default_return: Any = None):
        """Decorator form of capture."""
        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                with self.capture(category=category, severity=severity,
                                  reraise=reraise):
                    return fn(*args, **kwargs)
                return default_return
            return wrapper
        return deco

    def record_exception(self, exc: BaseException,
                         category: ErrorCategory = ErrorCategory.UNKNOWN,
                         severity: ErrorSeverity = ErrorSeverity.ERROR,
                         url: Optional[str] = None,
                         context: Optional[dict] = None,
                         message: Optional[str] = None,
                         retryable: Optional[bool] = None,
                         retry_hint_seconds: Optional[float] = None) -> ErrorRecord:
        exc_type = type(exc).__name__
        exc_mod = type(exc).__module__
        full_type = f"{exc_mod}.{exc_type}" if exc_mod else exc_type
        msg = message or str(exc) or exc_type
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        if retryable is None:
            retryable = self._is_retryable(exc, full_type)
        domain = self._extract_domain(url)
        now = _utc_now()
        rec = ErrorRecord(
            id=uuid.uuid4().hex[:12],
            timestamp=now,
            category=category,
            severity=severity,
            message=msg,
            exception_type=full_type,
            exception_repr=repr(exc)[:1000],
            traceback_str=tb,
            context=dict(context or {}),
            url=url,
            domain=domain,
            retryable=retryable,
            retry_hint_seconds=retry_hint_seconds,
            first_seen=now,
            last_seen=now,
        )
        self._ingest(rec)
        return rec

    def record_message(self, message: str,
                       category: ErrorCategory = ErrorCategory.INTERNAL,
                       severity: ErrorSeverity = ErrorSeverity.ERROR,
                       url: Optional[str] = None,
                       context: Optional[dict] = None) -> ErrorRecord:
        now = _utc_now()
        rec = ErrorRecord(
            id=uuid.uuid4().hex[:12],
            timestamp=now,
            category=category,
            severity=severity,
            message=message,
            exception_type="MessageOnly",
            exception_repr=message,
            traceback_str="",
            context=dict(context or {}),
            url=url,
            domain=self._extract_domain(url),
            retryable=False,
            first_seen=now,
            last_seen=now,
        )
        self._ingest(rec)
        return rec

    def subscribe(self, callback: Callable[[ErrorRecord], None],
                  category: Optional[ErrorCategory] = None,
                  min_severity: Optional[ErrorSeverity] = None) -> None:
        with self._lock:
            self._callbacks.append((category, min_severity, callback))

    def unsubscribe(self, callback: Callable[[ErrorRecord], None]) -> None:
        with self._lock:
            self._callbacks = [c for c in self._callbacks if c[2] is not callback]

    def snapshot(self) -> list[ErrorRecord]:
        with self._lock:
            return list(self._by_sig.values())

    def stats(self) -> dict:
        with self._lock:
            return {
                "total": self._total,
                "unique": len(self._by_sig),
                "by_category": {k.value: v for k, v in self._by_category.items()},
                "by_severity": {int(k): v for k, v in self._by_severity.items()},
            }

    def clear(self) -> None:
        with self._lock:
            self._by_sig.clear()
            self._by_category.clear()
            self._by_severity.clear()
            self._total = 0

    def _ingest(self, rec: ErrorRecord) -> None:
        sig = rec.signature()
        with self._lock:
            existing = self._by_sig.get(sig)
            if existing and (rec.timestamp - existing.last_seen) < self._dedup_window:
                existing.count += 1
                existing.last_seen = rec.timestamp
                self._total += 1
                return
            self._by_sig[sig] = rec
            self._by_category[rec.category] += 1
            self._by_severity[rec.severity] += 1
            self._total += 1
            if len(self._by_sig) > self._max_records:
                self._by_sig.popitem(last=False)
        self._log.log(int(rec.severity),
                      f"[{rec.category.value}] {rec.message}",
                      extra={"error_id": rec.id, "url": rec.url})
        self._dispatch(rec)

    def _dispatch(self, rec: ErrorRecord) -> None:
        for cat, sev, cb in list(self._callbacks):
            if cat is not None and rec.category != cat:
                continue
            if sev is not None and rec.severity < sev:
                continue
            try:
                cb(rec)
            except Exception:
                self._log.exception("Error callback raised")

    def _is_retryable(self, exc: BaseException, full_type: str) -> bool:
        for name in self.RETRYABLE_EXCEPTIONS:
            if name in full_type or name in type(exc).__name__:
                return True
        return isinstance(exc, (TimeoutError, ConnectionError, OSError))

    @staticmethod
    def _extract_domain(url: Optional[str]) -> Optional[str]:
        if not url:
            return None
        try:
            m = re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://([^/?#]+)", url)
            if m:
                host = m.group(1).split("@")[-1].split(":")[0]
                return host.lower()
        except Exception:
            pass
        return None


class _ErrorCapture:
    __slots__ = ("_mgr", "_cat", "_sev", "_url", "_ctx", "_reraise",
                 "_message", "_retryable", "_hint")

    def __init__(self, mgr, cat, sev, url, ctx, reraise, message,
                 retryable, hint):
        self._mgr = mgr
        self._cat = cat
        self._sev = sev
        self._url = url
        self._ctx = ctx
        self._reraise = reraise
        self._message = message
        self._retryable = retryable
        self._hint = hint

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_val is None:
            return False
        self._mgr.record_exception(
            exc_val,
            category=self._cat,
            severity=self._sev,
            url=self._url,
            context=self._ctx,
            message=self._message,
            retryable=self._retryable,
            retry_hint_seconds=self._hint,
        )
        return not self._reraise


# ════════════════════════════════════════════════════════════════════════════
# 4. Warning Manager
# ════════════════════════════════════════════════════════════════════════════

class WarningManager:
    """
    Non-fatal issue tracking. Rate-limits repeated warnings, deduplicates
    them, and exposes callbacks per code or severity.
    """

    def __init__(self, log: logging.Logger,
                 dedup_window_seconds: float = 600.0,
                 rate_limit_per_minute: int = 120):
        self._log = log
        self._lock = threading.RLock()
        self._records: "OrderedDict[str, WarningRecord]" = OrderedDict()
        self._callbacks: list[tuple[Optional[str],
                                    Optional[WarningSeverity],
                                    Callable[[WarningRecord], None]]] = []
        self._dedup_window = dedup_window_seconds
        self._rate_limit = rate_limit_per_minute
        self._window: deque[float] = deque(maxlen=rate_limit_per_minute * 2)
        self._suppressed = 0

    def warn(self, code: str, message: str,
             severity: WarningSeverity = WarningSeverity.MEDIUM,
             context: Optional[dict] = None) -> Optional[WarningRecord]:
        now = _utc_now()
        with self._lock:
            if len(self._window) >= self._rate_limit:
                oldest = self._window[0]
                if now - oldest < 60.0:
                    self._suppressed += 1
                    return None
            self._window.append(now)
        rec = WarningRecord(
            id=uuid.uuid4().hex[:10],
            timestamp=now,
            severity=severity,
            code=code,
            message=message,
            context=dict(context or {}),
            first_seen=now,
            last_seen=now,
        )
        sig = rec.signature()
        with self._lock:
            existing = self._records.get(sig)
            if existing and (rec.timestamp - existing.last_seen) < self._dedup_window:
                existing.count += 1
                existing.last_seen = rec.timestamp
                return existing
            self._records[sig] = rec
        self._log.warning(f"[{code}] {message}")
        self._dispatch(rec)
        return rec

    def subscribe(self, callback: Callable[[WarningRecord], None],
                  code: Optional[str] = None,
                  min_severity: Optional[WarningSeverity] = None) -> None:
        with self._lock:
            self._callbacks.append((code, min_severity, callback))

    def snapshot(self) -> list[WarningRecord]:
        with self._lock:
            return list(self._records.values())

    def stats(self) -> dict:
        with self._lock:
            return {
                "unique": len(self._records),
                "suppressed": self._suppressed,
                "rate_limit_per_minute": self._rate_limit,
            }

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._window.clear()
            self._suppressed = 0

    def _dispatch(self, rec: WarningRecord) -> None:
        sev_order = {WarningSeverity.LOW: 0, WarningSeverity.MEDIUM: 1,
                     WarningSeverity.HIGH: 2}
        for code, min_sev, cb in list(self._callbacks):
            if code is not None and rec.code != code:
                continue
            if min_sev is not None and \
                    sev_order[rec.severity] < sev_order[min_sev]:
                continue
            try:
                cb(rec)
            except Exception:
                self._log.exception("Warning callback raised")


# ════════════════════════════════════════════════════════════════════════════
# 5. Link Manager
# ════════════════════════════════════════════════════════════════════════════

class LinkManager:
    """
    Link graph store. Tracks every (source → target) edge, normalizes
    URLs, classifies internal vs external, resolves registered domains,
    and maintains in-degree/out-degree counters. Backed by SQLite for
    persistence, with an in-memory LRU for hot lookups.
    """

    _TLD_CACHE_MAX = 50000

    def __init__(self, db_path: Union[str, Path], cache: CacheManager,
                 log: logging.Logger):
        self._db_path = Path(db_path)
        _safe_mkdir(self._db_path.parent)
        self._cache = cache
        self._log = log
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self._db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-65536")
        self._init_schema()
        self._pending_edges: list[tuple] = []
        self._flush_threshold = 1000

        try:
            from tld import get_fld  # type: ignore
            self._get_fld = get_fld
        except Exception:
            self._get_fld = None

    def _init_schema(self) -> None:
        c = self._conn
        c.executescript("""
            CREATE TABLE IF NOT EXISTS urls (
                id      INTEGER PRIMARY KEY,
                url     TEXT UNIQUE NOT NULL,
                hash    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_urls_hash ON urls(hash);

            CREATE TABLE IF NOT EXISTS edges (
                id           INTEGER PRIMARY KEY,
                source_id    INTEGER NOT NULL,
                target_id    INTEGER NOT NULL,
                anchor_text  TEXT,
                rel          TEXT,
                is_internal  INTEGER NOT NULL DEFAULT 0,
                discovered   REAL NOT NULL,
                UNIQUE(source_id, target_id, anchor_text)
            );
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
            CREATE INDEX IF NOT EXISTS idx_edges_internal ON edges(is_internal);

            CREATE TABLE IF NOT EXISTS domain_edges (
                id           INTEGER PRIMARY KEY,
                source_host  TEXT NOT NULL,
                target_host  TEXT NOT NULL,
                count        INTEGER NOT NULL DEFAULT 0,
                UNIQUE(source_host, target_host)
            );
            CREATE INDEX IF NOT EXISTS idx_domain_edges_src
                ON domain_edges(source_host);
            CREATE INDEX IF NOT EXISTS idx_domain_edges_tgt
                ON domain_edges(target_host);
        """)

    def _url_id(self, url: str) -> int:
        h = _xxh64(url)
        with self._lock:
            row = self._conn.execute(
                "SELECT id FROM urls WHERE url = ?", (url,)
            ).fetchone()
            if row:
                return row[0]
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO urls(url, hash) VALUES (?, ?)",
                (url, h),
            )
            if cur.lastrowid:
                return cur.lastrowid
            row = self._conn.execute(
                "SELECT id FROM urls WHERE url = ?", (url,)
            ).fetchone()
            return row[0]

    def add_edge(self, source_url: str, target_url: str,
                 anchor_text: str = "", rel: str = "",
                 is_internal: bool = False) -> None:
        edge = (source_url, target_url, anchor_text[:512], rel[:64],
                1 if is_internal else 0, _utc_now())
        with self._lock:
            self._pending_edges.append(edge)
            if len(self._pending_edges) >= self._flush_threshold:
                self._flush_locked()

    def add_edges(self, edges: Iterable[LinkEdge]) -> None:
        for e in edges:
            self.add_edge(e.source_url, e.target_url, e.anchor_text,
                          e.rel, e.is_internal)

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._pending_edges:
            return
        batch = self._pending_edges
        self._pending_edges = []
        try:
            self._conn.execute("BEGIN")
            for s, t, a, r, i, d in batch:
                sid = self._url_id(s)
                tid = self._url_id(t)
                self._conn.execute(
                    "INSERT OR IGNORE INTO edges "
                    "(source_id, target_id, anchor_text, rel, is_internal, discovered) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (sid, tid, a, r, i, d),
                )
                sh = self._host_of(s)
                th = self._host_of(t)
                if sh and th:
                    self._conn.execute(
                        "INSERT INTO domain_edges(source_host, target_host, count) "
                        "VALUES (?, ?, 1) "
                        "ON CONFLICT(source_host, target_host) "
                        "DO UPDATE SET count = count + 1",
                        (sh, th),
                    )
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            self._log.exception("LinkManager flush failed")

    def out_degree(self, url: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM edges e JOIN urls u ON e.source_id = u.id "
                "WHERE u.url = ?", (url,)
            ).fetchone()
            return int(row[0]) if row else 0

    def in_degree(self, url: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM edges e JOIN urls u ON e.target_id = u.id "
                "WHERE u.url = ?", (url,)
            ).fetchone()
            return int(row[0]) if row else 0

    def registered_domain(self, host: str) -> str:
        if not host:
            return ""
        key = ("rd", host)
        cached = self._cache.get(CacheTier.LINK, key)
        if cached is not None:
            return cached
        result = host.lower()
        if self._get_fld:
            try:
                fld = self._get_fld("http://" + host, fix_protocol=True)
                if fld:
                    result = fld
            except Exception:
                pass
        self._cache.set(CacheTier.LINK, key, result)
        return result

    def is_same_registered_domain(self, a: str, b: str) -> bool:
        return self.registered_domain(a) == self.registered_domain(b)

    def stats(self) -> dict:
        with self._lock:
            urls = self._conn.execute("SELECT COUNT(*) FROM urls").fetchone()[0]
            edges = self._conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            internal = self._conn.execute(
                "SELECT COUNT(*) FROM edges WHERE is_internal = 1"
            ).fetchone()[0]
            domains = self._conn.execute(
                "SELECT COUNT(DISTINCT source_host) FROM domain_edges"
            ).fetchone()[0]
            return {
                "urls": int(urls),
                "edges": int(edges),
                "internal_edges": int(internal),
                "external_edges": int(edges) - int(internal),
                "domains": int(domains),
                "pending": len(self._pending_edges),
            }

    def top_domains(self, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source_host, SUM(count) as c FROM domain_edges "
                "GROUP BY source_host ORDER BY c DESC LIMIT ?", (limit,)
            ).fetchall()
            return [{"domain": r[0], "edges": int(r[1])} for r in rows]

    def clear(self) -> None:
        with self._lock:
            self._conn.executescript(
                "DELETE FROM edges; DELETE FROM urls; DELETE FROM domain_edges;"
            )
            self._pending_edges.clear()
            self._conn.execute("VACUUM")

    def close(self) -> None:
        self.flush()
        with self._lock:
            with suppress(Exception):
                self._conn.close()

    @staticmethod
    def _host_of(url: str) -> str:
        if not url:
            return ""
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://([^/?#]+)", url)
        if not m:
            return ""
        return m.group(1).split("@")[-1].split(":")[0].lower()


# ════════════════════════════════════════════════════════════════════════════
# 6. Dedup layer
# ════════════════════════════════════════════════════════════════════════════

class DedupSet:
    """Single-shard XXHash64 URL dedup set with SQLite persistence."""

    def __init__(self, db_path: Union[str, Path], table: str = "seen"):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self.table = table
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                hash TEXT PRIMARY KEY,
                url  TEXT NOT NULL,
                ts   REAL NOT NULL
            )
        """)
        self._conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{table}_ts ON {table}(ts)"
        )

    def contains(self, url: str) -> bool:
        h = _xxh64(url)
        with self._lock:
            row = self._conn.execute(
                f"SELECT 1 FROM {self.table} WHERE hash = ? LIMIT 1", (h,)
            ).fetchone()
            return row is not None

    def add(self, url: str) -> bool:
        h = _xxh64(url)
        with self._lock:
            try:
                self._conn.execute(
                    f"INSERT INTO {self.table}(hash, url, ts) VALUES (?, ?, ?)",
                    (h, url, _utc_now()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def add_many(self, urls: Iterable[str]) -> int:
        count = 0
        now = _utc_now()
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                for u in urls:
                    try:
                        self._conn.execute(
                            f"INSERT INTO {self.table}(hash, url, ts) "
                            "VALUES (?, ?, ?)",
                            (_xxh64(u), u, now),
                        )
                        count += 1
                    except sqlite3.IntegrityError:
                        pass
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return count

    def size(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                f"SELECT COUNT(*) FROM {self.table}"
            ).fetchone()[0])

    def clear(self) -> None:
        with self._lock:
            self._conn.execute(f"DELETE FROM {self.table}")

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class ShardedDedupSet:
    """Sharded dedup: 16 SQLite tables, one per shard, chosen by hash byte."""

    def __init__(self, db_path: Union[str, Path], shards: int = 16):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self.shards = shards
        self._sets = [DedupSet(self.db_path, table=f"seen_{i}")
                      for i in range(shards)]

    def _shard(self, url: str) -> int:
        h = _xxh64(url)
        return int(h[:2], 16) % self.shards

    def contains(self, url: str) -> bool:
        return self._sets[self._shard(url)].contains(url)

    def add(self, url: str) -> bool:
        return self._sets[self._shard(url)].add(url)

    def add_many(self, urls: Iterable[str]) -> int:
        buckets: list[list[str]] = [[] for _ in range(self.shards)]
        for u in urls:
            buckets[self._shard(u)].append(u)
        total = 0
        for i, b in enumerate(buckets):
            if b:
                total += self._sets[i].add_many(b)
        return total

    def size(self) -> int:
        return sum(s.size() for s in self._sets)

    def clear(self) -> None:
        for s in self._sets:
            s.clear()

    def close(self) -> None:
        for s in self._sets:
            s.close()


class ContentHashDedup:
    """XXH3-128 content-hash dedup for near-duplicate page detection."""

    def __init__(self, db_path: Union[str, Path], table: str = "content_hash"):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self.table = table
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                hash TEXT PRIMARY KEY,
                url  TEXT NOT NULL,
                ts   REAL NOT NULL
            )
        """)

    def check_and_add(self, text: str, url: str) -> bool:
        h = _xxh3_128(text)
        with self._lock:
            try:
                self._conn.execute(
                    f"INSERT INTO {self.table}(hash, url, ts) VALUES (?, ?, ?)",
                    (h, url, _utc_now()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


# ════════════════════════════════════════════════════════════════════════════
# 7. State DB & checkpoint
# ════════════════════════════════════════════════════════════════════════════

class StateDB:
    """General-purpose state SQLite with migrations support."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS kv (
                    key   TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    ts    REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied REAL NOT NULL
                );
            """)
            row = self._conn.execute(
                "SELECT MAX(version) FROM schema_version"
            ).fetchone()
            current = row[0] if row and row[0] else 0
            if current < self.SCHEMA_VERSION:
                self._conn.execute(
                    "INSERT INTO schema_version(version, applied) VALUES (?, ?)",
                    (self.SCHEMA_VERSION, _utc_now()),
                )

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                return default
            return _json_loads(row[0])

    def set(self, key: str, value: Any) -> None:
        blob = _json_dumps(value)
        with self._lock:
            self._conn.execute(
                "INSERT INTO kv(key, value, ts) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "ts = excluded.ts",
                (key, blob, _utc_now()),
            )

    def delete(self, key: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM kv WHERE key = ?", (key,))

    def keys(self) -> list[str]:
        with self._lock:
            return [r[0] for r in self._conn.execute("SELECT key FROM kv")]

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class CheckpointManager:
    """Atomic checkpoint save/load with rotation of previous generations."""

    def __init__(self, path: Union[str, Path], keep: int = 3):
        self.path = Path(path)
        _safe_mkdir(self.path.parent)
        self.keep = keep
        self._lock = threading.RLock()

    def save(self, state: Mapping) -> None:
        with self._lock:
            self._rotate()
            payload = _json_dumps({
                "version": MANAGER_VERSION,
                "saved_at": _iso_now(),
                "state": dict(state),
            })
            _atomic_write(self.path, payload)

    def load(self) -> Optional[dict]:
        with self._lock:
            if not self.path.exists():
                return None
            try:
                data = _json_loads(self.path.read_bytes())
                return data.get("state")
            except Exception:
                # try previous generations
                for gen in self._generations():
                    try:
                        return _json_loads(gen.read_bytes()).get("state")
                    except Exception:
                        continue
                return None

    def _rotate(self) -> None:
        if not self.path.exists():
            return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        gen = self.path.with_suffix(self.path.suffix + f".{ts}")
        with suppress(OSError):
            os.replace(self.path, gen)
        gens = self._generations()
        for old in gens[self.keep:]:
            with suppress(OSError):
                old.unlink()

    def _generations(self) -> list[Path]:
        return sorted(
            self.path.parent.glob(self.path.name + ".*"),
            key=lambda p: p.stat().st_mtime, reverse=True,
        )


# ════════════════════════════════════════════════════════════════════════════
# 8. Frontier, cookie, domain-state, rate-limit stores
# ════════════════════════════════════════════════════════════════════════════

class FrontierStore:
    """Persisted FIFO frontier with priority buckets."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS frontier (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                url      TEXT NOT NULL,
                depth    INTEGER NOT NULL DEFAULT 0,
                priority REAL NOT NULL DEFAULT 0,
                enqueued REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_frontier_pri ON frontier(priority DESC);
        """)

    def push(self, url: str, depth: int = 0, priority: float = 0.0) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO frontier(url, depth, priority, enqueued) "
                "VALUES (?, ?, ?, ?)",
                (url, depth, priority, _utc_now()),
            )

    def push_many(self, items: Iterable[tuple[str, int, float]]) -> int:
        n = 0
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                for url, depth, pri in items:
                    self._conn.execute(
                        "INSERT INTO frontier(url, depth, priority, enqueued) "
                        "VALUES (?, ?, ?, ?)",
                        (url, depth, pri, _utc_now()),
                    )
                    n += 1
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return n

    def pop_many(self, n: int = 1000) -> list[tuple[str, int, float]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, url, depth, priority FROM frontier "
                "ORDER BY priority DESC, id ASC LIMIT ?", (n,)
            ).fetchall()
            if not rows:
                return []
            ids = [r[0] for r in rows]
            placeholders = ",".join("?" * len(ids))
            self._conn.execute(
                f"DELETE FROM frontier WHERE id IN ({placeholders})", ids
            )
            return [(r[1], r[2], r[3]) for r in rows]

    def snapshot(self) -> list[tuple[str, int, float]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT url, depth, priority FROM frontier "
                "ORDER BY priority DESC, id ASC"
            ).fetchall()
            return [(r[0], r[1], r[2]) for r in rows]

    def size(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM frontier"
            ).fetchone()[0])

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM frontier")

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class CookieJarStore:
    """SQLite-backed cookie persistence compatible with aiohttp/curl_cffi."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS cookies (
                id          INTEGER PRIMARY KEY,
                domain      TEXT NOT NULL,
                path        TEXT NOT NULL DEFAULT '/',
                name        TEXT NOT NULL,
                value       TEXT NOT NULL,
                expires     REAL,
                secure      INTEGER NOT NULL DEFAULT 0,
                httponly    INTEGER NOT NULL DEFAULT 0,
                samesite    TEXT,
                created     REAL NOT NULL,
                UNIQUE(domain, path, name)
            );
            CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies(domain);
        """)

    def put(self, domain: str, name: str, value: str,
            path: str = "/", expires: Optional[float] = None,
            secure: bool = False, httponly: bool = False,
            samesite: Optional[str] = None) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO cookies "
                "(domain, path, name, value, expires, secure, httponly, "
                "samesite, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(domain, path, name) DO UPDATE SET "
                "value = excluded.value, expires = excluded.expires, "
                "secure = excluded.secure, httponly = excluded.httponly, "
                "samesite = excluded.samesite",
                (domain, path, name, value, expires,
                 1 if secure else 0, 1 if httponly else 0,
                 samesite, _utc_now()),
            )

    def all_for_domain(self, domain: str) -> list[dict]:
        now = _utc_now()
        with self._lock:
            rows = self._conn.execute(
                "SELECT domain, path, name, value, expires, secure, "
                "httponly, samesite FROM cookies "
                "WHERE domain = ? AND (expires IS NULL OR expires > ?)",
                (domain, now),
            ).fetchall()
            return [dict(zip(
                ("domain", "path", "name", "value", "expires",
                 "secure", "httponly", "samesite"), r)) for r in rows]

    def purge_expired(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM cookies WHERE expires IS NOT NULL AND expires < ?",
                (_utc_now(),),
            )
            return cur.rowcount

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM cookies")

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class DomainStateStore:
    """Per-domain crawl history: last crawl, backoff, counters."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS domain_state (
                domain         TEXT PRIMARY KEY,
                last_crawl     REAL,
                last_robots    REAL,
                pages_crawled  INTEGER NOT NULL DEFAULT 0,
                errors         INTEGER NOT NULL DEFAULT 0,
                cooldown_until REAL,
                etag           TEXT,
                last_modified  TEXT,
                consecutive_errors INTEGER NOT NULL DEFAULT 0
            );
        """)

    def get(self, domain: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT last_crawl, last_robots, pages_crawled, errors, "
                "cooldown_until, etag, last_modified, consecutive_errors "
                "FROM domain_state WHERE domain = ?", (domain,)
            ).fetchone()
            if not row:
                return None
            keys = ("last_crawl", "last_robots", "pages_crawled", "errors",
                    "cooldown_until", "etag", "last_modified",
                    "consecutive_errors")
            return dict(zip(keys, row))

    def upsert(self, domain: str, **fields) -> None:
        if not fields:
            return
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO domain_state(domain) VALUES (?)",
                (domain,),
            )
            assignments = ", ".join(f"{k} = ?" for k in fields)
            self._conn.execute(
                f"UPDATE domain_state SET {assignments} WHERE domain = ?",
                (*fields.values(), domain),
            )

    def bump(self, domain: str, field: str, delta: int = 1) -> None:
        if field not in ("pages_crawled", "errors", "consecutive_errors"):
            raise ValueError(f"Not a counter: {field}")
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO domain_state(domain) VALUES (?)",
                (domain,),
            )
            self._conn.execute(
                f"UPDATE domain_state SET {field} = {field} + ? "
                "WHERE domain = ?", (delta, domain),
            )

    def in_cooldown(self, domain: str) -> Optional[float]:
        with self._lock:
            row = self._conn.execute(
                "SELECT cooldown_until FROM domain_state WHERE domain = ?",
                (domain,),
            ).fetchone()
            if row and row[0] and row[0] > _utc_now():
                return row[0] - _utc_now()
            return None

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class RateLimitStateStore:
    """Persisted token buckets for adaptive rate limiting."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS rate_state (
                domain       TEXT PRIMARY KEY,
                tokens       REAL NOT NULL DEFAULT 0,
                last_refill  REAL NOT NULL,
                rps          REAL NOT NULL,
                burst        INTEGER NOT NULL
            );
        """)

    def get(self, domain: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT tokens, last_refill, rps, burst FROM rate_state "
                "WHERE domain = ?", (domain,)
            ).fetchone()
            if not row:
                return None
            return dict(zip(("tokens", "last_refill", "rps", "burst"), row))

    def set(self, domain: str, tokens: float, last_refill: float,
            rps: float, burst: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO rate_state(domain, tokens, last_refill, rps, burst) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(domain) DO UPDATE SET tokens = excluded.tokens, "
                "last_refill = excluded.last_refill, rps = excluded.rps, "
                "burst = excluded.burst",
                (domain, tokens, last_refill, rps, burst),
            )

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


# ════════════════════════════════════════════════════════════════════════════
# 9. Output layer
# ════════════════════════════════════════════════════════════════════════════

class StatsCollector:
    """Thread-safe crawl statistics."""

    def __init__(self):
        self._lock = threading.RLock()
        self._stats = CrawlStats(started_at=_utc_now(), last_update=_utc_now())

    def bump(self, field: str, amount: int = 1) -> None:
        with self._lock:
            setattr(self._stats, field, getattr(self._stats, field) + amount)
            self._stats.last_update = _utc_now()

    def snapshot(self) -> CrawlStats:
        with self._lock:
            return replace(self._stats)

    def reset(self) -> None:
        with self._lock:
            self._stats = CrawlStats(started_at=_utc_now(),
                                     last_update=_utc_now())


class ZstdCompressor:
    """Streaming Zstd compressor."""

    def __init__(self, path: Union[str, Path], level: int = 3):
        if zstd is None:
            raise OutputError("zstandard is required for ZstdCompressor")
        self.path = Path(path)
        _safe_mkdir(self.path.parent)
        self._fh = open(self.path, "wb")
        self._compressor = zstd.ZstdCompressor(level=level)
        self._writer = self._compressor.stream_writer(self._fh, closefd=False)
        self._bytes_in = 0
        self._bytes_out = 0
        self._closed = False

    def write(self, data: bytes) -> int:
        if self._closed:
            raise OutputError("Compressor closed")
        n = self._writer.write(data)
        self._bytes_in += len(data)
        return n

    def flush(self) -> None:
        if not self._closed:
            self._writer.flush()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._writer.close()
        finally:
            with suppress(Exception):
                self._bytes_out = self.path.stat().st_size
            self._fh.close()
            self._closed = True

    @property
    def bytes_in(self) -> int:
        return self._bytes_in

    @property
    def bytes_out(self) -> int:
        return self._bytes_out


class Py7zrArchiver:
    """Cold-storage archiver for old output chunks."""

    def __init__(self, archive_dir: Union[str, Path]):
        if py7zr is None:
            raise OutputError("py7zr is required for archival")
        self.dir = _safe_mkdir(archive_dir)

    def archive_files(self, files: Sequence[Path],
                      archive_name: Optional[str] = None) -> Path:
        if not files:
            raise OutputError("No files to archive")
        name = archive_name or \
            f"archive.{datetime.now().strftime('%Y%m%d-%H%M%S')}.7z"
        target = self.dir / name
        with py7zr.SevenZipFile(target, "w") as z:
            for f in files:
                z.write(f, arcname=f.name)
        for f in files:
            with suppress(OSError):
                f.unlink()
        return target


class FileRotator:
    """Size- and count-based rotation controller."""

    def __init__(self, base_dir: Union[str, Path], pattern: str,
                 max_bytes: int, max_records: int):
        self.dir = _safe_mkdir(base_dir)
        self.pattern = pattern
        self.max_bytes = max_bytes
        self.max_records = max_records
        self._current_bytes = 0
        self._current_records = 0
        self._sequence = 0
        self._lock = threading.RLock()

    def next_path(self, domain: str = "crawl") -> Path:
        with self._lock:
            self._sequence += 1
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            name = self.pattern.format(
                domain=domain, date=ts,
                time=ts, seq=self._sequence,
                ext="jsonl.zst",
            )
            return self.dir / name

    def should_rotate(self, incoming_bytes: int = 0,
                      incoming_records: int = 0) -> bool:
        with self._lock:
            if self._current_bytes + incoming_bytes > self.max_bytes:
                return True
            if self._current_records + incoming_records > self.max_records:
                return True
            return False

    def reset(self) -> None:
        with self._lock:
            self._current_bytes = 0
            self._current_records = 0

    def account(self, nbytes: int, nrecords: int = 1) -> None:
        with self._lock:
            self._current_bytes += nbytes
            self._current_records += nrecords


class ManifestWriter:
    """JSON manifest tracking every output chunk."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        _safe_mkdir(self.path.parent)
        self._lock = threading.RLock()
        self._chunks: list[dict] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = _json_loads(self.path.read_bytes())
                self._chunks = data.get("chunks", [])
            except Exception:
                self._chunks = []

    def add_chunk(self, path: Path, records: int, bytes_in: int,
                  bytes_out: int, crc32: Optional[str] = None) -> None:
        with self._lock:
            self._chunks.append({
                "path": str(path),
                "records": records,
                "bytes_in": bytes_in,
                "bytes_out": bytes_out,
                "crc32": crc32,
                "created": _iso_now(),
            })
            self._flush()

    def _flush(self) -> None:
        payload = _json_dumps({
            "version": MANAGER_VERSION,
            "updated": _iso_now(),
            "chunks": self._chunks,
        })
        _atomic_write(self.path, payload)

    def chunks(self) -> list[dict]:
        return list(self._chunks)

    def total_records(self) -> int:
        return sum(c["records"] for c in self._chunks)

    def total_bytes(self) -> int:
        return sum(c["bytes_out"] for c in self._chunks)


class IndexWriter:
    """SQLite index of every record written."""

    def __init__(self, db_path: Union[str, Path]):
        self.db_path = Path(db_path)
        _safe_mkdir(self.db_path.parent)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.db_path),
                                     check_same_thread=False,
                                     isolation_level=None)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS records (
                id        INTEGER PRIMARY KEY,
                url       TEXT NOT NULL,
                domain    TEXT,
                status    INTEGER,
                chunk     TEXT,
                ts        REAL NOT NULL,
                words     INTEGER,
                size      INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_records_url ON records(url);
            CREATE INDEX IF NOT EXISTS idx_records_domain ON records(domain);
            CREATE INDEX IF NOT EXISTS idx_records_status ON records(status);
            CREATE INDEX IF NOT EXISTS idx_records_ts ON records(ts);
        """)

    def add(self, url: str, domain: str, status: int, chunk: str,
            words: int = 0, size: int = 0) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO records(url, domain, status, chunk, ts, words, size) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (url, domain, status, chunk, _utc_now(), words, size),
            )

    def add_many(self, rows: Iterable[tuple]) -> None:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                self._conn.executemany(
                    "INSERT INTO records(url, domain, status, chunk, ts, "
                    "words, size) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    rows,
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def query(self, domain: Optional[str] = None, status: Optional[int] = None,
              since: Optional[float] = None,
              limit: int = 1000) -> list[dict]:
        q = "SELECT url, domain, status, chunk, ts, words, size FROM records WHERE 1=1"
        params: list = []
        if domain:
            q += " AND domain = ?"
            params.append(domain)
        if status is not None:
            q += " AND status = ?"
            params.append(status)
        if since is not None:
            q += " AND ts >= ?"
            params.append(since)
        q += " ORDER BY ts DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(q, params).fetchall()
        keys = ("url", "domain", "status", "chunk", "ts", "words", "size")
        return [dict(zip(keys, r)) for r in rows]

    def count_by_domain(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT domain, COUNT(*) FROM records "
                "WHERE domain IS NOT NULL GROUP BY domain"
            ).fetchall()
        return {r[0]: int(r[1]) for r in rows}

    def count_by_status(self) -> dict[int, int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT status, COUNT(*) FROM records GROUP BY status"
            ).fetchall()
        return {int(r[0]): int(r[1]) for r in rows}

    def total(self) -> int:
        with self._lock:
            return int(self._conn.execute(
                "SELECT COUNT(*) FROM records"
            ).fetchone()[0])

    def close(self) -> None:
        with self._lock:
            with suppress(Exception):
                self._conn.close()


class OutputWriter:
    """Facade over rotation, compression, manifest, and index."""

    def __init__(self, base_dir: Union[str, Path],
                 pattern: str, max_bytes: int, max_records: int,
                 compress: bool, compression_level: int,
                 manifest: ManifestWriter,
                 index: IndexWriter,
                 log: logging.Logger):
        self.base_dir = _safe_mkdir(base_dir)
        self.rotator = FileRotator(base_dir, pattern, max_bytes, max_records)
        self.compress = compress
        self.level = compression_level
        self.manifest = manifest
        self.index = index
        self.log = log
        self._lock = threading.RLock()
        self._current_path: Optional[Path] = None
        self._compressor: Optional[ZstdCompressor] = None
        self._current_records = 0
        self._write_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop = threading.Event()
        self._worker: Optional[threading.Thread] = None
        self._pending_index: list[tuple] = []

    def start(self, domain: str = "crawl") -> None:
        if self._worker and self._worker.is_alive():
            return
        self._open_new_chunk(domain)
        self._stop.clear()
        self._worker = threading.Thread(target=self._loop,
                                        name="FaOutputWriter", daemon=True)
        self._worker.start()

    def write(self, record: Mapping) -> None:
        try:
            self._write_queue.put_nowait(record)
        except queue.Full:
            self.log.warning("Output queue full; blocking writer")
            self._write_queue.put(record, timeout=30.0)

    def flush(self) -> None:
        self._write_queue.join()
        self._flush_index()
        if self._compressor:
            self._compressor.flush()

    def close(self) -> None:
        self._stop.set()
        if self._worker:
            self._worker.join(timeout=10.0)
        self.flush()
        self._close_chunk()

    def _loop(self) -> None:
        while not self._stop.is_set() or not self._write_queue.empty():
            try:
                rec = self._write_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._write_record(rec)
            except Exception:
                self.log.exception("Output write failed")
            finally:
                self._write_queue.task_done()

    def _write_record(self, rec: Mapping) -> None:
        line = _json_dumps(rec) + b"\n"
        with self._lock:
            if self.rotator.should_rotate(len(line), 1):
                self._close_chunk()
                self._open_new_chunk(rec.get("domain") or "crawl")
            assert self._compressor is not None
            self._compressor.write(line)
            self.rotator.account(len(line), 1)
            self._current_records += 1
            url = rec.get("url") or ""
            domain = rec.get("domain") or ""
            status = rec.get("status") or 0
            words = rec.get("words_count") or 0
            self._pending_index.append((
                url, domain, int(status),
                str(self._current_path), _utc_now(), int(words), len(line),
            ))
            if len(self._pending_index) >= 500:
                self._flush_index()

    def _flush_index(self) -> None:
        if not self._pending_index:
            return
        batch = self._pending_index
        self._pending_index = []
        try:
            self.index.add_many(batch)
        except Exception:
            self.log.exception("Index write failed")

    def _open_new_chunk(self, domain: str) -> None:
        path = self.rotator.next_path(domain)
        self.rotator.reset()
        self._current_path = path
        self._current_records = 0
        if self.compress:
            self._compressor = ZstdCompressor(path, level=self.level)
        else:
            raise OutputError("Uncompressed output not yet supported in facade")

    def _close_chunk(self) -> None:
        if self._compressor is None:
            return
        if self._current_path is None:
            raise OutputError("Current output chunk has no path")
        try:
            self._compressor.close()
            self.manifest.add_chunk(
                self._current_path,
                records=self._current_records,
                bytes_in=self._compressor.bytes_in,
                bytes_out=self._compressor.bytes_out,
                crc32=None,
            )
        finally:
            self._compressor = None
            self._current_path = None
            self._current_records = 0


# ════════════════════════════════════════════════════════════════════════════
# 10. Optimization Center
# ════════════════════════════════════════════════════════════════════════════

class OptimizationCenter:
    """
    Monitors system pressure and emits optimization hints. Runs a
    background thread that samples CPU, memory, disk, and crawl
    throughput, then generates recommendations.

    Does not apply changes automatically unless `auto_apply=True`.
    """

    def __init__(self, stats: StatsCollector, cache: CacheManager,
                 config: ConfigAccessor, log: logging.Logger,
                 interval: float = 30.0, auto_apply: bool = False):
        self._stats = stats
        self._cache = cache
        self._config = config
        self._log = log
        self._interval = interval
        self._auto_apply = auto_apply
        self._lock = threading.RLock()
        self._hints: list[OptimizerHint] = []
        self._applied_count = 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._subscribers: list[Callable[[OptimizerHint], None]] = []
        # track peak rates to detect regressions
        self._last_snapshot: Optional[CrawlStats] = None
        self._last_ts: float = 0.0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop,
                                        name="FaOptimizer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=self._interval * 2)

    def subscribe(self, cb: Callable[[OptimizerHint], None]) -> None:
        with self._lock:
            self._subscribers.append(cb)

    def hints(self) -> list[OptimizerHint]:
        with self._lock:
            return list(self._hints)

    def stats(self) -> dict:
        with self._lock:
            return {
                "hints_generated": len(self._hints),
                "hints_applied": self._applied_count,
                "auto_apply": self._auto_apply,
            }

    def analyze_once(self) -> list[OptimizerHint]:
        """Run one analysis pass. Returns newly generated hints."""
        generated: list[OptimizerHint] = []
        if psutil is None:
            return generated
        # Memory pressure
        try:
            vm = psutil.virtual_memory()
            if vm.percent >= 90:
                generated.append(OptimizerHint(
                    key="cache.tier_resize",
                    current_value="default",
                    suggested_value="shrink_all_50pct",
                    reason=f"System memory at {vm.percent:.1f}%",
                    confidence=0.9,
                ))
        except Exception:
            pass
        # CPU pressure
        try:
            cpu = psutil.cpu_percent(interval=None)
            if cpu >= 90:
                cfg_c = self._config.get(
                    "performance.max_concurrent_tasks", 100)
                suggested = max(10, int(cfg_c * 0.7))
                generated.append(OptimizerHint(
                    key="performance.max_concurrent_tasks",
                    current_value=cfg_c,
                    suggested_value=suggested,
                    reason=f"CPU at {cpu:.1f}%",
                    confidence=0.7,
                ))
        except Exception:
            pass
        # Disk pressure
        try:
            du = psutil.disk_usage(str(Path.cwd()))
            if du.percent >= 85:
                generated.append(OptimizerHint(
                    key="output.compression_level",
                    current_value=self._config.get(
                        "output.compression_level", 3),
                    suggested_value=min(
                        19, self._config.get("output.compression_level", 3) + 3),
                    reason=f"Disk usage at {du.percent:.1f}%",
                    confidence=0.6,
                ))
        except Exception:
            pass
        # Throughput regression detection
        now = _utc_now()
        cur = self._stats.snapshot()
        if self._last_snapshot is not None and self._last_ts > 0:
            dt = now - self._last_ts
            if dt > 0:
                rate_now = (cur.fetched - self._last_snapshot.fetched) / dt
                err_now = (cur.errors - self._last_snapshot.errors) / dt
                if rate_now < 0.1 and cur.fetched > 50:
                    generated.append(OptimizerHint(
                        key="rate_limit.adaptive_decrease_on_429",
                        current_value=self._config.get(
                            "rate_limit.adaptive_decrease_on_429", 0.5),
                        suggested_value=0.3,
                        reason=f"Crawl throughput dropped to {rate_now:.2f} pages/s",
                        confidence=0.5,
                    ))
                if err_now > rate_now and err_now > 1:
                    generated.append(OptimizerHint(
                        key="fetch.retry_max_attempts",
                        current_value=self._config.get(
                            "fetch.retry_max_attempts", 5),
                        suggested_value=min(10, self._config.get(
                            "fetch.retry_max_attempts", 5) + 2),
                        reason=f"Error rate {err_now:.2f}/s exceeds throughput",
                        confidence=0.6,
                    ))
        self._last_snapshot = cur
        self._last_ts = now
        # Cache hit rate
        for tier, s in self._cache.stats().items():
            if s["hits"] + s["misses"] > 200 and s["hit_rate"] < 0.3:
                generated.append(OptimizerHint(
                    key=f"cache.{tier}.maxsize",
                    current_value=s["size"],
                    suggested_value=max(100, s["size"] * 2),
                    reason=f"Cache tier {tier} hit rate {s['hit_rate']:.2f}",
                    confidence=0.5,
                ))
        with self._lock:
            self._hints.extend(generated)
            if len(self._hints) > 2000:
                self._hints = self._hints[-2000:]
        for h in generated:
            for cb in list(self._subscribers):
                with suppress(Exception):
                    cb(h)
        return generated

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.analyze_once()
            except Exception:
                self._log.exception("Optimizer pass failed")

    def apply_hint(self, hint: OptimizerHint) -> None:
        """Mark a hint as applied. The actual application is the caller's job."""
        hint.applied = True
        with self._lock:
            self._applied_count += 1


# ════════════════════════════════════════════════════════════════════════════
# 11. Fast Loader
# ════════════════════════════════════════════════════════════════════════════

class FastLoader:
    """
    High-throughput, memory-efficient reader for large JSONL(.zst) files,
    lazy config loaders, and bulk SQLite iterators.

    Provides:
        - iter_jsonl(path): streams records without loading the whole file
        - read_jsonl(path, limit): reads at most N records
        - iter_jsonl_zst(path): streams a Zstd-compressed JSONL
        - iter_sqlite(table, batch): batches a SQLite table
        - lazy_json(path): returns a callable that loads JSON on first call
    """

    def __init__(self, cache: CacheManager, log: logging.Logger):
        self._cache = cache
        self._log = log

    def iter_jsonl(self, path: Union[str, Path],
                   chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[dict]:
        p = Path(path)
        if not p.exists():
            raise LoaderError(f"File not found: {p}")
        with open(p, "rb") as f:
            buf = b""
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buf += chunk
                lines = buf.split(b"\n")
                buf = lines.pop()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > MAX_JSONL_LINE:
                        self._log.warning(
                            "Skipping oversized JSONL line (%d bytes)",
                            len(line))
                        continue
                    try:
                        yield _json_loads(line)
                    except Exception as e:
                        self._log.warning("Bad JSONL line: %s", e)
            if buf.strip():
                try:
                    yield _json_loads(buf.strip())
                except Exception as e:
                    self._log.warning("Bad trailing JSONL: %s", e)

    def read_jsonl(self, path: Union[str, Path],
                   limit: Optional[int] = None) -> list[dict]:
        out: list[dict] = []
        for i, rec in enumerate(self.iter_jsonl(path)):
            if limit is not None and i >= limit:
                break
            out.append(rec)
        return out

    def iter_jsonl_zst(self, path: Union[str, Path],
                       chunk_size: int = DEFAULT_CHUNK_SIZE
                       ) -> Iterator[dict]:
        if zstd is None:
            raise LoaderError("zstandard required for compressed JSONL")
        p = Path(path)
        if not p.exists():
            raise LoaderError(f"File not found: {p}")
        dctx = zstd.ZstdDecompressor()
        with open(p, "rb") as fh:
            with dctx.stream_reader(fh) as reader:
                buf = b""
                while True:
                    chunk = reader.read(chunk_size)
                    if not chunk:
                        break
                    buf += chunk
                    lines = buf.split(b"\n")
                    buf = lines.pop()
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            yield _json_loads(line)
                        except Exception as e:
                            self._log.warning("Bad JSONL line: %s", e)
                if buf.strip():
                    try:
                        yield _json_loads(buf.strip())
                    except Exception as e:
                        self._log.warning("Bad trailing JSONL: %s", e)

    def iter_sqlite(self, db_path: Union[str, Path], query: str,
                    params: tuple = (), batch: int = 1000
                    ) -> Iterator[tuple]:
        p = Path(db_path)
        if not p.exists():
            raise LoaderError(f"DB not found: {p}")
        conn = sqlite3.connect(str(p), check_same_thread=False)
        try:
            cur = conn.execute(query, params)
            while True:
                rows = cur.fetchmany(batch)
                if not rows:
                    break
                for r in rows:
                    yield r
        finally:
            conn.close()

    def lazy_json(self, path: Union[str, Path],
                  refresh_seconds: float = 0.0) -> Callable[[], Any]:
        """
        Return a callable that reads JSON on first call and caches the result.
        Set refresh_seconds > 0 to re-read after that many seconds.
        """
        p = Path(path)
        state = {"value": None, "loaded_at": 0.0}

        def load() -> Any:
            now = _utc_now()
            if state["value"] is not None and \
                    (refresh_seconds <= 0 or
                     now - state["loaded_at"] < refresh_seconds):
                return state["value"]
            try:
                state["value"] = _json_loads(p.read_bytes())
                state["loaded_at"] = now
            except Exception as e:
                raise LoaderError(f"Failed loading {p}: {e}") from e
            return state["value"]

        return load

    def bulk_insert_sqlite(self, db_path: Union[str, Path], table: str,
                           rows: Iterable[Sequence], columns: Sequence[str],
                           batch: int = 5000) -> int:
        p = Path(db_path)
        _safe_mkdir(p.parent)
        placeholders = ",".join("?" * len(columns))
        cols = ",".join(columns)
        conn = sqlite3.connect(str(p), check_same_thread=False,
                               isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            n = 0
            buf: list[Sequence] = []
            for r in rows:
                buf.append(tuple(r))
                if len(buf) >= batch:
                    conn.execute("BEGIN")
                    try:
                        conn.executemany(
                            f"INSERT INTO {table}({cols}) "
                            f"VALUES ({placeholders})", buf,
                        )
                        conn.execute("COMMIT")
                    except Exception:
                        conn.execute("ROLLBACK")
                        raise
                    n += len(buf)
                    buf.clear()
            if buf:
                conn.execute("BEGIN")
                try:
                    conn.executemany(
                        f"INSERT INTO {table}({cols}) "
                        f"VALUES ({placeholders})", buf,
                    )
                    conn.execute("COMMIT")
                except Exception:
                    conn.execute("ROLLBACK")
                    raise
                n += len(buf)
            return n
        finally:
            conn.close()


# ════════════════════════════════════════════════════════════════════════════
# 12. Misc services: locks, secrets, export, query, metrics, retention
# ════════════════════════════════════════════════════════════════════════════

class LockService:
    """Single-instance file lock per resource."""

    def __init__(self, state_dir: Union[str, Path]):
        self.dir = _safe_mkdir(state_dir)
        self._locks: dict[str, Any] = {}
        self._lock = threading.RLock()

    @contextmanager
    def acquire(self, name: str, timeout: float = 0.0):
        if FileLock is None:
            yield  # no-op if filelock missing
            return
        path = self.dir / f"{name}.lock"
        with self._lock:
            fl = self._locks.setdefault(name, FileLock(str(path)))
        try:
            fl.acquire(timeout=timeout)
        except FileLockTimeout as e:
            raise StateError(f"Lock held: {name}") from e
        try:
            yield
        finally:
            with suppress(Exception):
                fl.release()


class SecretsResolver:
    """Resolve secrets from env, .env, or Fernet-encrypted config values."""

    def __init__(self, key_env: str = "FA_CRAB_SECRET_KEY"):
        self._key_env = key_env
        self._fernet: Optional[Any] = None
        if HAS_CRYPTO:
            key = os.environ.get(key_env)
            if key:
                try:
                    self._fernet = Fernet(key.encode())
                except Exception:
                    self._fernet = None

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        v = os.environ.get(key)
        if v is not None:
            return v
        return default

    def decrypt(self, token: str) -> str:
        if not self._fernet:
            raise ManagerError("Fernet key not configured")
        return self._fernet.decrypt(token.encode()).decode()

    def encrypt(self, value: str) -> str:
        if not self._fernet:
            raise ManagerError("Fernet key not configured")
        return self._fernet.encrypt(value.encode()).decode()


class ExportService:
    """Converts JSONL outputs into other formats."""

    def __init__(self, loader: FastLoader, log: logging.Logger):
        self._loader = loader
        self._log = log

    def to_csv(self, src: Union[str, Path], dst: Union[str, Path],
               fields: Optional[Sequence[str]] = None) -> int:
        import csv
        rows = 0
        keys: Optional[list[str]] = None
        with open(dst, "w", newline="", encoding="utf-8") as fh:
            w = None
            for rec in self._loader.iter_jsonl(src):
                if keys is None:
                    keys = list(fields) if fields else list(rec.keys())
                    w = csv.DictWriter(fh, fieldnames=keys)
                    w.writeheader()
                if w:
                    w.writerow({k: rec.get(k) for k in keys})
                    rows += 1
        return rows

    def to_sqlite(self, src: Union[str, Path], dst: Union[str, Path],
                  table: str = "records") -> int:
        conn = sqlite3.connect(str(dst), check_same_thread=False,
                               isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(f"""
            CREATE TABLE IF NOT EXISTS {table} (
                url TEXT, domain TEXT, status INTEGER, ts REAL,
                words INTEGER, payload TEXT
            )
        """)
        n = 0
        try:
            conn.execute("BEGIN")
            for rec in self._loader.iter_jsonl(src):
                conn.execute(
                    f"INSERT INTO {table}(url, domain, status, ts, words, "
                    "payload) VALUES (?, ?, ?, ?, ?, ?)",
                    (rec.get("url"), rec.get("domain"),
                     rec.get("status"), rec.get("timestamp"),
                     rec.get("words_count"), _json_dumps(rec).decode("utf-8")),
                )
                n += 1
                if n % 5000 == 0:
                    conn.execute("COMMIT")
                    conn.execute("BEGIN")
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
        return n


class QueryService:
    """High-level queries against the index and manifest."""

    def __init__(self, index: IndexWriter, manifest: ManifestWriter):
        self.index = index
        self.manifest = manifest

    def find_by_domain(self, domain: str, limit: int = 1000) -> list[dict]:
        return self.index.query(domain=domain, limit=limit)

    def find_by_status(self, status: int, limit: int = 1000) -> list[dict]:
        return self.index.query(status=status, limit=limit)

    def find_since(self, timestamp: float, limit: int = 1000) -> list[dict]:
        return self.index.query(since=timestamp, limit=limit)

    def count_by_domain(self) -> dict[str, int]:
        return self.index.count_by_domain()

    def count_by_status(self) -> dict[int, int]:
        return self.index.count_by_status()

    def total_records(self) -> int:
        return self.index.total()

    def chunks(self) -> list[dict]:
        return self.manifest.chunks()


class MetricsLogger:
    """Appends JSONL time-series metrics."""

    def __init__(self, path: Union[str, Path]):
        self.path = Path(path)
        _safe_mkdir(self.path.parent)
        self._lock = threading.RLock()

    def log(self, event: str, **fields) -> None:
        row = {"ts": _utc_now(), "iso": _iso_now(), "event": event, **fields}
        line = _json_dumps(row) + b"\n"
        with self._lock:
            with open(self.path, "ab") as fh:
                fh.write(line)

    def iter_events(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with open(self.path, "rb") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield _json_loads(line)
                except Exception:
                    continue


class RetentionManager:
    """Delete or archive output chunks older than N days."""

    def __init__(self, output_dir: Union[str, Path],
                 archive_dir: Union[str, Path], log: logging.Logger):
        self.output_dir = _safe_mkdir(output_dir)
        self.archive_dir = _safe_mkdir(archive_dir)
        self.log = log

    def enforce(self, max_age_days: int, archive: bool = True,
                dry_run: bool = False) -> dict:
        cutoff = _utc_now() - max_age_days * 86400
        moved = deleted = 0
        to_archive: list[Path] = []
        for p in self.output_dir.glob("*.jsonl.zst"):
            try:
                if p.stat().st_mtime >= cutoff:
                    continue
                if dry_run:
                    moved += 1
                elif archive:
                    to_archive.append(p)
                else:
                    p.unlink()
                    deleted += 1
            except OSError:
                continue
        if to_archive and archive and not dry_run:
            if HAS_PY7ZR:
                try:
                    arch = Py7zrArchiver(self.archive_dir)
                    arch.archive_files(to_archive)
                    moved += len(to_archive)
                except Exception:
                    self.log.exception("Archive failed")
            else:
                for p in to_archive:
                    with suppress(OSError):
                        shutil.move(str(p), str(self.archive_dir / p.name))
                        moved += 1
        return {"moved": moved, "deleted": deleted,
                "cutoff_age_days": max_age_days}


class IntegrityChecker:
    """Verify manifest vs index vs chunk files on disk."""

    def __init__(self, manifest: ManifestWriter, index: IndexWriter,
                 log: logging.Logger):
        self.manifest = manifest
        self.index = index
        self.log = log

    def verify(self) -> dict:
        missing: list[str] = []
        total_records = 0
        for chunk in self.manifest.chunks():
            p = Path(chunk["path"])
            if not p.exists():
                missing.append(str(p))
            total_records += chunk.get("records", 0)
        return {
            "manifest_chunks": len(self.manifest.chunks()),
            "manifest_records": total_records,
            "missing_files": missing,
            "index_records": self.index.total(),
        }


# ════════════════════════════════════════════════════════════════════════════
# 13. Logging bootstrap
# ════════════════════════════════════════════════════════════════════════════

class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": record.created,
            "iso": datetime.fromtimestamp(record.created, tz=timezone.utc)
                    .isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
        }
        for k in ("url", "domain", "error_id", "request_id"):
            v = getattr(record, k, None)
            if v is not None:
                payload[k] = v
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return _json_dumps(payload).decode("utf-8")


def _build_logger(name: str, cfg: ConfigAccessor) -> logging.Logger:
    log = logging.getLogger(name)
    if log.handlers:
        return log
    level = cfg.get("logging.level", "INFO")
    log.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    fmt = cfg.get("logging.format", "json")
    formatter = _JsonFormatter() if fmt == "json" \
        else logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    outputs = cfg.get("logging.output", ["stdout", "file"])
    if "stdout" in outputs:
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(formatter)
        log.addHandler(sh)
    if "file" in outputs:
        path = cfg.get("logging.log_file_path", "./logs/fa-crab.log")
        _safe_mkdir(Path(path).parent)
        max_mb = cfg.get("logging.log_rotate_mb", 50)
        count = cfg.get("logging.log_rotate_count", 10)
        fh = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_mb * 1024 * 1024, backupCount=count,
            encoding="utf-8",
        )
        fh.setFormatter(formatter)
        log.addHandler(fh)
    log.propagate = False
    return log


# ════════════════════════════════════════════════════════════════════════════
# 14. ManagerFacade — the public API
# ════════════════════════════════════════════════════════════════════════════

class ManagerFacade:
    """
    Fa-Crab's central facade.

    Instantiate via `get_manager()` in normal use. The constructor is
    exposed for tests and for embedding in unusual hosts.
    """

    def __init__(self,
                 config_path: Union[str, Path] = "./Config.json",
                 agents_path: Union[str, Path] = "./Agents.json",
                 state_dir: Union[str, Path] = "./state",
                 output_dir: Union[str, Path] = "./output",
                 log_dir: Union[str, Path] = "./logs",
                 archive_dir: Union[str, Path] = "./archive",
                 env_prefix: str = ENV_PREFIX,
                 strict_config: bool = True,
                 start_optimizer: bool = True,
                 start_config_watch: bool = True,
                 output_pattern: str = "{domain}_{date}_{seq}.{ext}",
                 integration: Optional[dict] = None):
        self._closed = False
        self._rlock = threading.RLock()
        self._integration: dict = {
            "auto_start_output_writer": True,
            "auto_start_optimizer": start_optimizer,
            "auto_start_config_watch": start_config_watch,
            "output_worker_enabled": True,
            "output_queue_maxsize": 10000,
            "strict_shutdown": True,
            **(integration or {}),
        }

        # ── paths ─────────────────────────────────────────────────────────
        self._paths = {
            "config": Path(config_path).resolve(),
            "agents": Path(agents_path).resolve(),
            "state":  _safe_mkdir(state_dir).resolve(),
            "output": _safe_mkdir(output_dir).resolve(),
            "logs":   _safe_mkdir(log_dir).resolve(),
            "archive": _safe_mkdir(archive_dir).resolve(),
        }
        for sub in ("checkpoints", "backups", "cookies", "index", "dedup"):
            _safe_mkdir(self._paths["state"] / sub)

        # ── config ────────────────────────────────────────────────────────
        self._config_loader = ConfigLoader(
            self._paths["config"], env_prefix=env_prefix, strict=strict_config
        )
        self._config: ConfigAccessor = self._config_loader.load()
        self._agents_loader = AgentsLoader(self._paths["agents"])
        self._agents: ConfigAccessor = self._agents_loader.load()

        # ── logging ───────────────────────────────────────────────────────
        self._log = _build_logger("FaManager", self._config)

        # ── backup + watcher ──────────────────────────────────────────────
        self._backup = ConfigBackup(self._paths["state"] / "backups")
        self._config_watcher: Optional[ConfigWatcher] = None
        self._config_subscribers: list[Callable[[Path], None]] = []

        # ── subsystems ────────────────────────────────────────────────────
        self._cache = CacheManager()
        self._stats = StatsCollector()
        self._errors = ErrorManager(self._log)
        self._warnings = WarningManager(self._log)

        self._state_db = StateDB(self._paths["state"] / "fa_crab.sqlite")
        self._dedup = ShardedDedupSet(
            self._paths["state"] / "dedup" / "dedup.sqlite",
            shards=self._config.get("storage.dedup_shard_count", 16),
        )
        self._content_dedup = ContentHashDedup(
            self._paths["state"] / "dedup" / "content.sqlite"
        )
        self._checkpoint = CheckpointManager(
            self._paths["state"] / "checkpoints" / "checkpoint.json",
            keep=3,
        )
        self._frontier = FrontierStore(
            self._paths["state"] / "frontier.sqlite"
        )
        self._cookies = CookieJarStore(
            self._paths["state"] / "cookies" / "cookies.sqlite"
        )
        self._domain_state = DomainStateStore(
            self._paths["state"] / "domain_state.sqlite"
        )
        self._rate_state = RateLimitStateStore(
            self._paths["state"] / "rate_state.sqlite"
        )
        self._links = LinkManager(
            self._paths["state"] / "links.sqlite", self._cache, self._log
        )

        self._manifest = ManifestWriter(self._paths["output"] / "manifest.json")
        self._index = IndexWriter(self._paths["state"] / "index" / "index.sqlite")
        self._output_writer = OutputWriter(
            base_dir=self._paths["output"],
            pattern=output_pattern,
            max_bytes=self._config.get("output.output_rotate_mb", 256) * 1024 * 1024,
            max_records=self._config.get("output.output_rotate_records", 100000),
            compress=self._config.get("output.compress", True),
            compression_level=self._config.get("output.compression_level", 3),
            manifest=self._manifest,
            index=self._index,
            log=self._log,
        )
        self._retention = RetentionManager(
            self._paths["output"], self._paths["archive"], self._log
        )
        self._integrity = IntegrityChecker(self._manifest, self._index, self._log)

        self._loader = FastLoader(self._cache, self._log)
        self._export = ExportService(self._loader, self._log)
        self._query = QueryService(self._index, self._manifest)
        self._metrics = MetricsLogger(
            self._paths["logs"] / "metrics.jsonl"
        )
        self._locks = LockService(self._paths["state"] / "locks")
        self._secrets = SecretsResolver()
        self._optimizer = OptimizationCenter(
            stats=self._stats,
            cache=self._cache,
            config=self._config,
            log=self._log,
            interval=float(self._config.get("performance.optimizer_interval", 30)),
            auto_apply=False,
        )

        # ── boot ──────────────────────────────────────────────────────────
        if self._integration["auto_start_output_writer"]:
            self._output_writer.start(domain="crawl")
        if self._integration["auto_start_optimizer"]:
            self._optimizer.start()
        if self._integration["auto_start_config_watch"]:
            self._start_config_watcher()

        atexit.register(self.shutdown)

    # ─── public accessors ────────────────────────────────────────────────

    @property
    def config(self) -> ConfigAccessor: return self._config
    @property
    def agents(self) -> ConfigAccessor: return self._agents
    @property
    def cache(self) -> CacheManager: return self._cache
    @property
    def errors(self) -> ErrorManager: return self._errors
    @property
    def warnings(self) -> WarningManager: return self._warnings
    @property
    def stats(self) -> StatsCollector: return self._stats
    @property
    def state(self) -> StateDB: return self._state_db
    @property
    def dedup(self) -> ShardedDedupSet: return self._dedup
    @property
    def content_dedup(self) -> ContentHashDedup: return self._content_dedup
    @property
    def checkpoint(self) -> CheckpointManager: return self._checkpoint
    @property
    def frontier(self) -> FrontierStore: return self._frontier
    @property
    def cookies(self) -> CookieJarStore: return self._cookies
    @property
    def domain_state(self) -> DomainStateStore: return self._domain_state
    @property
    def rate_state(self) -> RateLimitStateStore: return self._rate_state
    @property
    def links(self) -> LinkManager: return self._links
    @property
    def manifest(self) -> ManifestWriter: return self._manifest
    @property
    def index(self) -> IndexWriter: return self._index
    @property
    def output(self) -> OutputWriter: return self._output_writer
    @property
    def retention(self) -> RetentionManager: return self._retention
    @property
    def integrity(self) -> IntegrityChecker: return self._integrity
    @property
    def loader(self) -> FastLoader: return self._loader
    @property
    def export(self) -> ExportService: return self._export
    @property
    def query(self) -> QueryService: return self._query
    @property
    def metrics(self) -> MetricsLogger: return self._metrics
    @property
    def locks(self) -> LockService: return self._locks
    @property
    def secrets(self) -> SecretsResolver: return self._secrets
    @property
    def optimizer(self) -> OptimizationCenter: return self._optimizer
    @property
    def paths(self) -> Mapping[str, Path]: return dict(self._paths)
    @property
    def logger(self) -> logging.Logger: return self._log

    # ─── high-level convenience methods ──────────────────────────────────

    def is_seen(self, url: str) -> bool:
        return self._dedup.contains(url)

    def mark_seen(self, url: str) -> bool:
        return self._dedup.add(url)

    def write_record(self, record: Mapping) -> None:
        self._output_writer.write(record)
        self._stats.bump("written")

    def load_frontier(self) -> list[tuple[str, int, float]]:
        return self._frontier.snapshot()

    def save_frontier(self, items: Iterable[tuple[str, int, float]]) -> int:
        return self._frontier.push_many(items)

    def save_checkpoint(self, state: Mapping) -> None:
        self._checkpoint.save(state)

    def load_checkpoint(self) -> Optional[dict]:
        return self._checkpoint.load()

    def subscribe_config_changes(self, cb: Callable[[Path], None]) -> None:
        self._config_subscribers.append(cb)

    def reload_config(self) -> None:
        """Hot-reload Config.json and Agents.json, notify subscribers."""
        with self._rlock:
            try:
                new_cfg = self._config_loader.load()
                new_agents = self._agents_loader.load()
            except ConfigError as e:
                self._errors.record_exception(
                    e, category=ErrorCategory.CONFIG)
                return
            self._backup.backup(self._paths["config"])
            self._config = new_cfg
            self._agents = new_agents
            self._log.info("Config reloaded")
            for cb in list(self._config_subscribers):
                try:
                    cb(self._paths["config"])
                except Exception as e:
                    self._errors.record_exception(
                        e, category=ErrorCategory.INTERNAL)

    def stats_snapshot(self) -> dict:
        """One consolidated snapshot for Terminal / GUI."""
        s = self._stats.snapshot()
        return {
            "stats": asdict(s),
            "errors": self._errors.stats(),
            "warnings": self._warnings.stats(),
            "cache": self._cache.stats(),
            "dedup_size": self._dedup.size(),
            "frontier_size": self._frontier.size(),
            "links": self._links.stats(),
            "manifest_records": self._manifest.total_records(),
            "index_records": self._index.total(),
            "optimizer": self._optimizer.stats(),
        }

    def record_metric(self, event: str, **fields) -> None:
        self._metrics.log(event, **fields)

    def flush_all(self) -> None:
        """Force every writer to flush. Used before checkpointing."""
        try:
            self._output_writer.flush()
        except Exception as e:
            self._errors.record_exception(
                e, category=ErrorCategory.OUTPUT)
        try:
            self._links.flush()
        except Exception as e:
            self._errors.record_exception(
                e, category=ErrorCategory.STORAGE)

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._log.info("Fa-Manager shutting down")
        with suppress(Exception):
            self.flush_all()
        with suppress(Exception):
            self._output_writer.close()
        with suppress(Exception):
            self._optimizer.stop()
        with suppress(Exception):
            self._config_watcher and self._config_watcher.stop()
        for closable in (
            self._links, self._dedup, self._content_dedup,
            self._frontier, self._cookies, self._domain_state,
            self._rate_state, self._state_db, self._index,
        ):
            with suppress(Exception):
                closable.close()

    # ─── internals ────────────────────────────────────────────────────────

    def _start_config_watcher(self) -> None:
        self._config_watcher = ConfigWatcher(
            [self._paths["config"], self._paths["agents"]],
            interval=2.0,
            callback=lambda _p: self.reload_config(),
        )
        self._config_watcher.start()


# ════════════════════════════════════════════════════════════════════════════
# 15. Singleton accessor
# ════════════════════════════════════════════════════════════════════════════

_manager: Optional[ManagerFacade] = None
_manager_lock = threading.Lock()


def get_manager(config_path: Union[str, Path] = "./Config.json",
                agents_path: Union[str, Path] = "./Agents.json",
                **kwargs) -> ManagerFacade:
    """Get or lazily create the process-wide Manager singleton."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = ManagerFacade(
                    config_path=config_path,
                    agents_path=agents_path,
                    **kwargs,
                )
    return _manager


def reset_manager() -> None:
    """Tear down the singleton. For tests and CLI `--fresh` runs."""
    global _manager
    with _manager_lock:
        if _manager is not None:
            with suppress(Exception):
                _manager.shutdown()
            _manager = None