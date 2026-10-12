#!/usr/bin/env python3
"""
scraper.py — Nexus Edition v3
The most optimized crawler to ever exist.

Dependencies:
    pip install curl-cffi lxml
Optional (Windows TUI):
    pip install windows-curses

Usage:
    python scraper.py            # interactive prompt
    python scraper.py --test     # run full test suite + benchmarks
    python scraper.py --debug    # verbose tracing
    python scraper.py --no-ui    # headless (log only)
"""

import asyncio
import collections
import functools
import hashlib
import json
import logging
import math
import mmap
import os
import random
import re
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

from curl_cffi.requests import AsyncSession
from lxml import html

# Optional curses — Windows needs `pip install windows-curses`
try:
    import curses
    HAS_CURSES = True
except ImportError:
    HAS_CURSES = False

# ===========================================================================
# CONFIGURATION
# ===========================================================================
MAX_DEPTH = 15
TIMEOUT = 12
MAX_RETRIES = 3
RETRY_BASE = 1.2
OUTPUT_FILE = "scraped_data.jsonl"
VISITED_BLOOM_FILE = "visited.bloom"
START_URLS_FILE = "start_urls.txt"
PROXY_FILE = "proxies_validated.txt"
BLOCK_COOLDOWN = 300
HEALTH_CHECK_INTERVAL = 45
DOMAIN_RATE_LIMIT = 0.25
MAX_TEXT_LENGTH = 2_000_000
BATCH_SIZE = 250
BLOOM_CAPACITY = 50_000_000
BLOOM_ERROR_RATE = 0.001
ADAPTIVE_MIN = 20
ADAPTIVE_MAX = 800
ADAPTIVE_INITIAL = 120
TARGET_LATENCY = 1.5

IMPERSONATE_PROFILES = [
    "chrome110", "chrome116", "chrome120", "chrome124",
    "firefox110", "firefox117", "firefox120", "safari15_5",
]

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt",
    "https://raw.githubusercontent.com/LoneKingCode/free-proxy-db/main/proxies/http.txt",
    "https://raw.githubusercontent.com/proxy-free/free-proxy-list/main/all.txt",
    "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&protocol=http&proxy_format=ipport&format=text",
    "https://raw.githubusercontent.com/komutan234/Proxy-List-Free/main/proxies/http.txt",
    "https://raw.githubusercontent.com/gfpcom/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
    "https://raw.githubusercontent.com/B4RC0DE-TM/proxy-list/main/HTTP.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/sunny9577/proxy-scraper/master/proxies.txt",
    "https://raw.githubusercontent.com/rdavydov/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/MuRongPIG/Proxy-Master/main/http.txt",
    "https://raw.githubusercontent.com/prxchk/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/http.txt",
    "https://raw.githubusercontent.com/yemixzy/proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/elliottophellia/proxylist/master/results.txt",
    "https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/http.txt",
    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",
    "https://raw.githubusercontent.com/Anonym0usWork1221/Free-Proxies/main/proxy_files/http_proxies.txt",
    "https://raw.githubusercontent.com/caliphdev/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ClearProxy/checked-proxy-list/main/http/raw.txt",
    "https://raw.githubusercontent.com/DenisD89/free-proxy-list/main/proxies/http.txt",
    "https://raw.githubusercontent.com/FirmansyahRizky/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Juvenal-Yescas/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Leviathan-00/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/MrMarble/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Nocturnal-Proxy/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/ObcbO/getproxy/master/http.txt",
    "https://raw.githubusercontent.com/ProxyScraper/ProxyScraper/main/http.txt",
    "https://raw.githubusercontent.com/RXWatcher/proxy-list/main/http.txt",
    "https://raw.githubusercontent.com/Skillter/proxy-list/main/http.txt",
]

# ===========================================================================
# LOGGING
# ===========================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-7s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("nexus")

DEBUG_MODE = False


# ===========================================================================
# MINI DEBUGGERS — tracing, timing, memory probes, atomic counters
# ===========================================================================
class MiniDebuggers:
    """Small, composable debugging primitives. Zero-cost when disabled."""

    enabled = False
    _timers: Dict[str, List[float]] = collections.defaultdict(list)
    _counters: Dict[str, int] = collections.Counter()
    _gauges: Dict[str, float] = {}
    _lock = threading.Lock()
    _mem_started = False

    # ---- decorators -------------------------------------------------------
    @staticmethod
    def timed(name: str):
        def deco(fn):
            if asyncio.iscoroutinefunction(fn):
                @functools.wraps(fn)
                async def aw(*a, **kw):
                    if not MiniDebuggers.enabled:
                        return await fn(*a, **kw)
                    t0 = time.perf_counter()
                    try:
                        return await fn(*a, **kw)
                    finally:
                        MiniDebuggers.record_time(name, time.perf_counter() - t0)
                return aw
            @functools.wraps(fn)
            def sw(*a, **kw):
                if not MiniDebuggers.enabled:
                    return fn(*a, **kw)
                t0 = time.perf_counter()
                try:
                    return fn(*a, **kw)
                finally:
                    MiniDebuggers.record_time(name, time.perf_counter() - t0)
            return sw
        return deco

    @staticmethod
    def traced(label: str = ""):
        def deco(fn):
            @functools.wraps(fn)
            def sw(*a, **kw):
                if MiniDebuggers.enabled:
                    log.debug("[trace] %s(%s) args=%s kw=%s",
                              label or fn.__name__, fn.__name__, a, kw)
                return fn(*a, **kw)
            return sw
        return deco

    # ---- counters ---------------------------------------------------------
    @staticmethod
    def bump(key: str, n: int = 1) -> None:
        if not MiniDebuggers.enabled:
            return
        with MiniDebuggers._lock:
            MiniDebuggers._counters[key] += n

    @staticmethod
    def gauge(key: str, value: float) -> None:
        if not MiniDebuggers.enabled:
            return
        with MiniDebuggers._lock:
            MiniDebuggers._gauges[key] = value

    @staticmethod
    def record_time(name: str, dt: float) -> None:
        with MiniDebuggers._lock:
            bucket = MiniDebuggers._timers[name]
            bucket.append(dt)
            if len(bucket) > 2048:
                del bucket[:1024]

    # ---- memory -----------------------------------------------------------
    @staticmethod
    def mem_start() -> None:
        if not MiniDebuggers._mem_started:
            import tracemalloc
            tracemalloc.start()
            MiniDebuggers._mem_started = True

    @staticmethod
    def mem_probe(label: str) -> None:
        if not (MiniDebuggers.enabled and MiniDebuggers._mem_started):
            return
        import tracemalloc
        cur, peak = tracemalloc.get_traced_memory()
        log.debug("[mem:%s] cur=%.2fMB peak=%.2fMB",
                  label, cur / 1e6, peak / 1e6)
        MiniDebuggers.gauge(f"mem.{label}.cur", cur / 1e6)
        MiniDebuggers.gauge(f"mem.{label}.peak", peak / 1e6)

    # ---- report -----------------------------------------------------------
    @staticmethod
    def report() -> dict:
        with MiniDebuggers._lock:
            timers = {}
            for k, v in MiniDebuggers._timers.items():
                if not v:
                    continue
                timers[k] = {
                    "n": len(v),
                    "mean_ms": (sum(v) / len(v)) * 1000,
                    "min_ms": min(v) * 1000,
                    "max_ms": max(v) * 1000,
                }
            return {
                "timers": timers,
                "counters": dict(MiniDebuggers._counters),
                "gauges": dict(MiniDebuggers._gauges),
            }

    @staticmethod
    def dump(path: str = "debug_report.json") -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(MiniDebuggers.report(), f, indent=2)
            log.info("Debug report → %s", path)
        except Exception as e:
            log.error("Debug dump failed: %s", e)


# ===========================================================================
# MINI HANDLERS — signals, exceptions, retries, circuit breakers, rate limit
# ===========================================================================
class MiniHandlers:
    """Atomic defensive primitives."""

    @staticmethod
    def install_signal_handlers(loop: asyncio.AbstractEventLoop, stop_cb) -> None:
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_cb)
            except (NotImplementedError, RuntimeError):
                # Windows: fall back to sync signal
                try:
                    signal.signal(sig, lambda s, f: stop_cb())
                except Exception:
                    pass

    @staticmethod
    def install_exception_hook() -> None:
        def hook(exc_type, exc, tb):
            if issubclass(exc_type, KeyboardInterrupt):
                sys.__excepthook__(exc_type, exc, tb)
                return
            log.error("UNCAUGHT %s: %s", exc_type.__name__, exc)
            log.debug("Traceback:\n%s", "".join(traceback.format_tb(tb)))
        sys.excepthook = hook

    @staticmethod
    def retry_async(max_attempts: int = MAX_RETRIES,
                    base: float = RETRY_BASE,
                    jitter: float = 0.25,
                    exceptions: Tuple = (Exception,)):
        def deco(fn):
            @functools.wraps(fn)
            async def wrap(*a, **kw):
                last = None
                for i in range(max_attempts):
                    try:
                        return await fn(*a, **kw)
                    except exceptions as e:
                        last = e
                        MiniDebuggers.bump(f"retry.{fn.__name__}")
                        if i < max_attempts - 1:
                            await asyncio.sleep(base ** i + random.random() * jitter)
                raise last
            return wrap
        return deco

    @staticmethod
    def sync_retry(max_attempts: int = MAX_RETRIES,
                   base: float = RETRY_BASE,
                   jitter: float = 0.25,
                   exceptions: Tuple = (Exception,)):
        def deco(fn):
            @functools.wraps(fn)
            def wrap(*a, **kw):
                last = None
                for i in range(max_attempts):
                    try:
                        return fn(*a, **kw)
                    except exceptions as e:
                        last = e
                        MiniDebuggers.bump(f"retry.{fn.__name__}")
                        if i < max_attempts - 1:
                            time.sleep(base ** i + random.random() * jitter)
                raise last
            return wrap
        return deco

    @staticmethod
    def safe(fn, *a, default=None, **kw):
        """Synchronous best-effort call — returns default on any exception."""
        try:
            return fn(*a, **kw)
        except Exception as e:
            log.debug("safe(%s) failed: %s", getattr(fn, "__name__", fn), e)
            return default

    @staticmethod
    async def safe_async(fn, *a, default=None, **kw):
        try:
            return await fn(*a, **kw)
        except Exception as e:
            log.debug("safe_async(%s) failed: %s", getattr(fn, "__name__", fn), e)
            return default


class CircuitBreaker:
    """Per-key failure gate — opens after N failures, resets after timeout."""

    def __init__(self, threshold: int = 5, timeout: float = 60.0):
        self.threshold = threshold
        self.timeout = timeout
        self._fails: Dict[str, int] = collections.defaultdict(int)
        self._opened_at: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def is_open(self, key: str) -> bool:
        async with self._lock:
            opened = self._opened_at.get(key)
            if opened is None:
                return False
            if time.time() - opened > self.timeout:
                self._opened_at.pop(key, None)
                self._fails[key] = 0
                return False
            return True

    async def record_failure(self, key: str) -> None:
        async with self._lock:
            self._fails[key] += 1
            if self._fails[key] >= self.threshold and key not in self._opened_at:
                self._opened_at[key] = time.time()
                log.debug("Circuit OPEN: %s", key)

    async def record_success(self, key: str) -> None:
        async with self._lock:
            self._fails[key] = 0
            self._opened_at.pop(key, None)


class TokenBucket:
    """Simple async token bucket rate limiter."""

    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens < n:
                wait = (n - self.tokens) / self.rate
            else:
                wait = 0.0
            self.tokens -= n
        if wait > 0:
            await asyncio.sleep(wait)


# ===========================================================================
# BLOOM FILTER
# ===========================================================================
class BloomFilter:
    def __init__(self, filepath: str,
                 capacity: int = BLOOM_CAPACITY,
                 error_rate: float = BLOOM_ERROR_RATE):
        self.filepath = filepath
        self.capacity = capacity
        self.error_rate = error_rate
        self.num_bits = self._optimal_bits(capacity, error_rate)
        self.num_hashes = self._optimal_hashes(capacity, error_rate)
        self.num_bytes = (self.num_bits + 7) // 8
        self._items = 0
        self._file = None
        self._mmap = None
        self._init_mmap()

    @staticmethod
    def _optimal_bits(n: int, p: float) -> int:
        return int(-n * math.log(p) / (math.log(2) ** 2))

    @staticmethod
    def _optimal_hashes(n: int, p: float) -> int:
        m = BloomFilter._optimal_bits(n, p)
        return max(1, int((m / n) * math.log(2)))

    def _init_mmap(self) -> None:
        if not (os.path.exists(self.filepath)
                and os.path.getsize(self.filepath) >= self.num_bytes):
            with open(self.filepath, "wb") as f:
                f.truncate(self.num_bytes)
        self._file = open(self.filepath, "r+b")
        self._mmap = mmap.mmap(self._file.fileno(), 0)
        # rough item estimate: bits set in first 4 KB, scaled
        sample = self._mmap[:4096]
        bits_set = sum(bin(b).count("1") for b in sample)
        self._items = int(bits_set * (self.num_bits / (4096 * 8)))
        log.info("Bloom: %d bits, %d hashes, %.1f MB, ~%d items",
                 self.num_bits, self.num_hashes,
                 self.num_bytes / 1e6, self._items)

    def _hashes(self, item: str):
        data = item.encode("utf-8")
        h1 = int.from_bytes(hashlib.md5(data).digest()[:8], "little")
        h2 = int.from_bytes(hashlib.sha1(data).digest()[:8], "little")
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.num_bits

    def add(self, item: str) -> None:
        for pos in self._hashes(item):
            byte_pos, bit_pos = pos >> 3, pos & 7
            self._mmap[byte_pos] = self._mmap[byte_pos] | (1 << bit_pos)
        self._items += 1

    def contains(self, item: str) -> bool:
        for pos in self._hashes(item):
            byte_pos, bit_pos = pos >> 3, pos & 7
            if not (self._mmap[byte_pos] & (1 << bit_pos)):
                return False
        return True

    @property
    def fill_ratio(self) -> float:
        if self._items == 0:
            return 0.0
        return 1 - math.exp(-self.num_hashes * self._items / self.num_bits)

    @property
    def estimated_fp_rate(self) -> float:
        return self.fill_ratio ** self.num_hashes

    def flush(self) -> None:
        if self._mmap:
            self._mmap.flush()

    def close(self) -> None:
        MiniHandlers.safe(self.flush)
        if self._mmap:
            MiniHandlers.safe(self._mmap.close)
        if self._file:
            MiniHandlers.safe(self._file.close)


# ===========================================================================
# ADAPTIVE CONCURRENCY — AIMD controller
# ===========================================================================
class AdaptiveConcurrency:
    def __init__(self, initial: int = ADAPTIVE_INITIAL,
                 min_cap: int = ADAPTIVE_MIN,
                 max_cap: int = ADAPTIVE_MAX,
                 target_latency: float = TARGET_LATENCY):
        self.current = initial
        self.min_cap = min_cap
        self.max_cap = max_cap
        self.target_latency = target_latency
        self.latency_ewma = target_latency
        self.error_ewma = 0.0
        self._lock = asyncio.Lock()
        self._inflight_lock = asyncio.Lock()
        self._adjust_interval = 4.0
        self._last_adjust = time.time()
        self._in_flight = 0

    async def record(self, latency: float, is_error: bool) -> None:
        async with self._lock:
            alpha = 0.15
            self.latency_ewma = alpha * latency + (1 - alpha) * self.latency_ewma
            self.error_ewma = alpha * (1.0 if is_error else 0.0) + (1 - alpha) * self.error_ewma
            now = time.time()
            if now - self._last_adjust >= self._adjust_interval:
                self._adjust()
                self._last_adjust = now

    def _adjust(self) -> None:
        latency_ratio = self.latency_ewma / self.target_latency
        err = self.error_ewma
        if latency_ratio > 1.3 or err > 0.15:
            new = int(self.current * 0.75)
        elif latency_ratio < 0.7 and err < 0.05:
            new = int(self.current * 1.08)
        else:
            new = self.current
        self.current = max(self.min_cap, min(self.max_cap, new))

    async def acquire(self) -> None:
        while True:
            async with self._inflight_lock:
                if self._in_flight < self.current:
                    self._in_flight += 1
                    return
            await asyncio.sleep(0.01)

    async def release(self) -> None:
        async with self._inflight_lock:
            if self._in_flight > 0:
                self._in_flight -= 1


# ===========================================================================
# MINI CLEANERS
# ===========================================================================
class MiniCleaners:
    _JUNK_TAGS = ("script", "style", "noscript", "iframe", "svg",
                  "canvas", "template", "object", "embed", "applet")

    @staticmethod
    def strip_junk_tags(tree) -> None:
        for tag in MiniCleaners._JUNK_TAGS:
            for elem in tree.iter(tag):
                p = elem.getparent()
                if p is not None:
                    p.remove(elem)

    @staticmethod
    def strip_comments(tree) -> None:
        for c in tree.xpath("//comment()"):
            p = c.getparent()
            if p is not None:
                p.remove(c)

    @staticmethod
    def extract_title(tree) -> str:
        t = tree.xpath("//title/text()")
        if t and t[0].strip():
            return t[0].strip()
        og = tree.xpath('//meta[@property="og:title"]/@content')
        if og:
            return og[0].strip()
        h1 = tree.xpath("//h1//text()")
        if h1:
            return " ".join(h1).strip()[:300]
        return ""

    @staticmethod
    def extract_text(tree) -> str:
        return MiniCleaners.normalize_whitespace(tree.text_content())

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()

    @staticmethod
    def cap_text(text: str, max_len: int = MAX_TEXT_LENGTH) -> str:
        return text[:max_len] if len(text) > max_len else text


# ===========================================================================
# MINI CHECKERS
# ===========================================================================
class MiniCheckers:
    _BLOCK_PATTERNS = [
        re.compile(r"Just a moment", re.IGNORECASE),
        re.compile(r"Attention Required! \| Cloudflare", re.IGNORECASE),
        re.compile(r"cf-browser-verification", re.IGNORECASE),
        re.compile(r"Please enable JavaScript", re.IGNORECASE),
        re.compile(r"Access denied", re.IGNORECASE),
        re.compile(r"Enable JavaScript and cookies to continue", re.IGNORECASE),
        re.compile(r"Checking your browser before accessing", re.IGNORECASE),
    ]

    _STOPWORDS = {
        "en": {"the", "and", "is", "in", "to", "of", "a", "that", "it", "for", "on", "with"},
        "es": {"el", "la", "de", "que", "y", "en", "un", "es", "se", "no", "por", "con"},
        "fr": {"le", "la", "de", "et", "les", "des", "en", "un", "une", "est", "pour", "dans"},
        "de": {"der", "die", "das", "und", "ist", "in", "den", "von", "zu", "mit", "auf"},
        "pt": {"o", "a", "de", "que", "e", "do", "da", "em", "um", "para", "com", "nao"},
        "it": {"il", "la", "di", "che", "e", "in", "un", "per", "con", "su", "una", "non"},
        "nl": {"de", "het", "een", "van", "en", "in", "is", "dat", "op", "te", "voor"},
    }

    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            p = urlparse(url)
            return p.scheme in ("http", "https") and bool(p.netloc)
        except Exception:
            return False

    @staticmethod
    def is_html(headers: dict) -> bool:
        ct = headers.get("Content-Type", headers.get("content-type", ""))
        return "text/html" in ct.lower() or "application/xhtml" in ct.lower()

    @staticmethod
    def is_blocked(html_text: str) -> bool:
        return any(p.search(html_text) for p in MiniCheckers._BLOCK_PATTERNS)

    @staticmethod
    def is_duplicate(bloom: BloomFilter, url: str) -> bool:
        return bloom.contains(url)

    @staticmethod
    def detect_language(text: str) -> str:
        if re.search(r"[\u0400-\u04FF]", text):
            return "ru"
        if re.search(r"[\u0600-\u06FF]", text):
            return "ar"
        if re.search(r"[\u4E00-\u9FFF]", text):
            return "zh"
        if re.search(r"[\u3040-\u309F\u30A0-\u30FF]", text):
            return "ja"
        if re.search(r"[\uAC00-\uD7AF]", text):
            return "ko"
        if re.search(r"[\u0900-\u097F]", text):
            return "hi"
        words = re.findall(r"\b\w+\b", text.lower())
        total = len(words) or 1
        scores = {}
        for lang, sw in MiniCheckers._STOPWORDS.items():
            scores[lang] = sum(1 for w in words if w in sw) / total
        return max(scores, key=scores.get) if scores else "en"

    @staticmethod
    def count_words(text: str) -> int:
        return len(re.findall(r"\b\w+\b", text))

    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ===========================================================================
# STATS
# ===========================================================================
class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.queued = 0
        self.fetched = 0
        self.errors = 0
        self.blocks = 0
        self.bytes_total = 0
        self.start_time = time.time()
        self.active_workers = 0
        self.concurrency = ADAPTIVE_INITIAL
        self.domains: Dict[str, dict] = {}
        self.log_lines: collections.deque = collections.deque(maxlen=200)
        self.paused = False
        self.running = True
        self.proxies_alive = 0
        self.fp_rate = 0.0

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            setattr(self, key, getattr(self, key) + n)

    def log(self, msg: str) -> None:
        with self._lock:
            self.log_lines.append((time.time(), msg))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "queued": self.queued,
                "fetched": self.fetched,
                "errors": self.errors,
                "blocks": self.blocks,
                "bytes": self.bytes_total,
                "uptime": time.time() - self.start_time,
                "active": self.active_workers,
                "concurrency": self.concurrency,
                "domains": dict(self.domains),
                "logs": list(self.log_lines),
                "paused": self.paused,
                "running": self.running,
                "proxies": self.proxies_alive,
                "fp_rate": self.fp_rate,
            }


# ===========================================================================
# BATCH WRITER
# ===========================================================================
class BatchWriter:
    def __init__(self, filepath: str, batch_size: int = BATCH_SIZE):
        self.filepath = filepath
        self.batch_size = batch_size
        self._buffer: List[str] = []
        self._lock = asyncio.Lock()

    async def write(self, line: str) -> None:
        async with self._lock:
            self._buffer.append(line)
            if len(self._buffer) >= self.batch_size:
                await self._flush_unlocked()

    async def _flush_unlocked(self) -> None:
        if not self._buffer:
            return
        data = "\n".join(self._buffer) + "\n"
        self._buffer.clear()
        await asyncio.to_thread(self._write_file, data)

    def _write_file(self, data: str) -> None:
        try:
            with open(self.filepath, "a", encoding="utf-8") as f:
                f.write(data)
        except Exception as e:
            log.error("Batch write failed: %s", e)

    async def close(self) -> None:
        async with self._lock:
            await self._flush_unlocked()


# ===========================================================================
# PROXY EXTRACTOR
# ===========================================================================
class ProxyExtractor:
    def __init__(self, filepath: str = PROXY_FILE):
        self.filepath = filepath
        self.valid: List[str] = []
        self._lock = asyncio.Lock()
        self._load_existing()

    def _load_existing(self) -> None:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.valid = [l.strip() for l in f if l.strip()]
                log.info("Loaded %d persisted proxies.", len(self.valid))
            except Exception as e:
                log.warning("Proxy file read failed: %s", e)

    async def extract_and_validate(self, max_per_source: int = 30) -> int:
        log.info("Extracting proxies from %d sources...", len(PROXY_SOURCES))
        candidates: Set[str] = set()
        async with AsyncSession() as session:
            tasks = [self._fetch_source(session, url, max_per_source)
                     for url in PROXY_SOURCES]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    candidates.update(r)
        log.info("Collected %d unique candidates.", len(candidates))
        if not candidates:
            return 0
        valid = await self._validate_all(candidates)
        async with self._lock:
            existing = set(self.valid)
            new = [p for p in valid if p not in existing]
            self.valid.extend(new)
            await asyncio.to_thread(self._persist)
        log.info("Proxies: %d valid (%d new, %d total)",
                 len(valid), len(new), len(self.valid))
        return len(new)

    async def _fetch_source(self, session, url, limit) -> List[str]:
        try:
            r = await session.get(url, timeout=10, impersonate="chrome120")
            if r.status_code != 200:
                return []
            found = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", line)
                if m:
                    found.append(m.group(1))
                if len(found) >= limit:
                    break
            return found
        except Exception:
            return []

    async def _validate_all(self, candidates: Set[str]) -> List[str]:
        sem = asyncio.Semaphore(200)
        valid: List[str] = []
        lock = asyncio.Lock()

        async def check(proxy: str):
            async with sem:
                try:
                    async with AsyncSession() as s:
                        r = await s.get(
                            "http://httpbin.org/ip",
                            proxies={"http": proxy, "https": proxy},
                            timeout=6,
                            impersonate="chrome120",
                        )
                        if r.status_code == 200 and "origin" in r.text:
                            async with lock:
                                valid.append(proxy)
                except Exception:
                    pass

        await asyncio.gather(*(check(p) for p in candidates),
                             return_exceptions=True)
        return valid

    def _persist(self) -> None:
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(self.valid))
        except Exception as e:
            log.error("Proxy persist failed: %s", e)

    def random_proxy(self) -> Optional[str]:
        return random.choice(self.valid) if self.valid else None


# ===========================================================================
# DOMAIN STATE & MANAGER
# ===========================================================================
@dataclass(slots=True)
class DomainState:
    domain: str
    healthy: bool = True
    blocked_until: float = 0.0
    last_access: float = 0.0
    consecutive_failures: int = 0
    impersonate: str = "chrome120"
    proxy: Optional[str] = None
    queue: collections.deque = field(default_factory=collections.deque)
    total_fetched: int = 0
    total_errors: int = 0


class DomainManager:
    def __init__(self, proxy_extractor: Optional[ProxyExtractor] = None):
        self.domains: Dict[str, DomainState] = {}
        self.proxy_extractor = proxy_extractor
        self._lock = asyncio.Lock()
        self.breaker = CircuitBreaker(threshold=5, timeout=BLOCK_COOLDOWN)

    async def get(self, domain: str) -> DomainState:
        async with self._lock:
            if domain not in self.domains:
                self.domains[domain] = DomainState(domain=domain)
            return self.domains[domain]

    async def wait_for_access(self, domain: str) -> None:
        state = await self.get(domain)
        now = time.time()
        if state.blocked_until > now:
            await asyncio.sleep(state.blocked_until - now)
        elapsed = now - state.last_access
        if elapsed < DOMAIN_RATE_LIMIT:
            await asyncio.sleep(DOMAIN_RATE_LIMIT - elapsed)
        state.last_access = time.time()

    async def mark_success(self, domain: str) -> None:
        state = await self.get(domain)
        state.consecutive_failures = 0
        state.healthy = True
        state.total_fetched += 1
        state.impersonate = random.choice(IMPERSONATE_PROFILES)
        if self.proxy_extractor:
            state.proxy = self.proxy_extractor.random_proxy()
        await self.breaker.record_success(domain)

    async def mark_failure(self, domain: str, blocked: bool = False) -> None:
        state = await self.get(domain)
        state.consecutive_failures += 1
        state.total_errors += 1
        await self.breaker.record_failure(domain)
        if blocked or state.consecutive_failures >= 3:
            state.blocked_until = time.time() + BLOCK_COOLDOWN
            state.healthy = False
        elif self.proxy_extractor:
            state.proxy = self.proxy_extractor.random_proxy()

    async def health_check_loop(self, stats: Stats) -> None:
        async with AsyncSession() as session:
            while stats.running:
                await asyncio.sleep(HEALTH_CHECK_INTERVAL)
                for domain, state in list(self.domains.items()):
                    if state.healthy and state.blocked_until <= time.time():
                        continue
                    try:
                        r = await session.get(
                            f"https://{domain}",
                            impersonate=state.impersonate,
                            timeout=8,
                        )
                        if r.status_code == 200:
                            state.healthy = True
                            state.blocked_until = 0
                            state.consecutive_failures = 0
                            stats.log(f"Health OK: {domain}")
                    except Exception:
                        pass


# ===========================================================================
# CRAWLER
# ===========================================================================
class Crawler:
    def __init__(self, start_urls: List[str], stats: Stats):
        self.start_urls = [u for u in start_urls if MiniCheckers.is_valid_url(u)]
        self.stats = stats
        self.bloom = BloomFilter(VISITED_BLOOM_FILE)
        self.proxy_extractor = ProxyExtractor()
        self.domain_manager = DomainManager(self.proxy_extractor)
        self.adaptive = AdaptiveConcurrency()
        self.output = BatchWriter(OUTPUT_FILE)
        self.session: Optional[AsyncSession] = None
        self.url_queue: asyncio.Queue = asyncio.Queue()
        self.running = True
        self._workers: List[asyncio.Task] = []

    async def run(self) -> None:
        if len(self.proxy_extractor.valid) < 10:
            asyncio.create_task(self.proxy_extractor.extract_and_validate())
            self.stats.log("Proxy extraction started in background")

        self.session = AsyncSession(max_clients=ADAPTIVE_MAX)
        asyncio.create_task(self.domain_manager.health_check_loop(self.stats))
        asyncio.create_task(self._bloom_flush_loop())
        asyncio.create_task(self._stats_sync_loop())

        for url in self.start_urls:
            if not self.bloom.contains(url):
                await self.url_queue.put((url, 0))
                self.stats.inc("queued")

        for i in range(ADAPTIVE_MAX):
            self._workers.append(asyncio.create_task(self._worker(i)))

        while self.running:
            await asyncio.sleep(2.0)
            if self.url_queue.empty() and self.stats.active_workers == 0:
                await asyncio.sleep(3.0)
                if self.url_queue.empty():
                    break

        self.running = False
        for w in self._workers:
            w.cancel()
        await asyncio.gather(*self._workers, return_exceptions=True)
        if self.session:
            MiniHandlers.safe_async_noop = None
            await self.session.close()
        self.bloom.close()
        await self.output.close()
        self.stats.running = False
        log.info("Crawler finished.")

    async def _bloom_flush_loop(self) -> None:
        while self.running:
            await asyncio.sleep(10.0)
            self.bloom.flush()

    async def _stats_sync_loop(self) -> None:
        """Keep the UI Stats in sync with crawler internals."""
        while self.running:
            await asyncio.sleep(1.0)
            self.stats.concurrency = self.adaptive.current
            self.stats.proxies_alive = len(self.proxy_extractor.valid)
            self.stats.fp_rate = self.bloom.estimated_fp_rate
            with self.stats._lock:
                for domain, state in self.domain_manager.domains.items():
                    self.stats.domains[domain] = {
                        "healthy": state.healthy,
                        "blocked_until": state.blocked_until,
                        "queue": len(state.queue),
                        "fetched": state.total_fetched,
                        "errors": state.total_errors,
                    }

    async def _worker(self, worker_id: int) -> None:
        while self.running:
            try:
                url, depth = await asyncio.wait_for(self.url_queue.get(), timeout=1.5)
            except asyncio.TimeoutError:
                continue

            if self.stats.paused:
                await self.url_queue.put((url, depth))
                await asyncio.sleep(0.5)
                continue

            await self.adaptive.acquire()
            self.stats.inc("active_workers")
            t0 = time.time()
            err = False
            try:
                await self._process(url, depth)
            except Exception as e:
                err = True
                log.debug("Worker error %s: %s", url, e)
                self.stats.inc("errors")
            finally:
                self.stats.inc("active_workers", -1)
                await self.adaptive.release()
                await self.adaptive.record(time.time() - t0, err)
                self.url_queue.task_done()

    async def _process(self, url: str, depth: int) -> None:
        if self.bloom.contains(url):
            return
        domain = urlparse(url).netloc
        state = await self.domain_manager.get(domain)
        await self.domain_manager.wait_for_access(domain)
        if await self.domain_manager.breaker.is_open(domain):
            return

        for attempt in range(MAX_RETRIES):
            try:
                r = await self.session.get(
                    url,
                    impersonate=state.impersonate,
                    proxies={"http": state.proxy, "https": state.proxy}
                    if state.proxy else None,
                    timeout=TIMEOUT,
                    allow_redirects=True,
                )
                if not MiniCheckers.is_html(r.headers):
                    return

                if r.status_code == 200:
                    if MiniCheckers.is_blocked(r.text):
                        await self.domain_manager.mark_failure(domain, blocked=True)
                        self.stats.inc("blocks")
                        self.stats.log(f"BLOCK: {domain}")
                        return
                    await self.domain_manager.mark_success(domain)
                    self.bloom.add(url)
                    self.stats.inc("fetched")
                    self.stats.inc("bytes", len(r.content))
                    self.stats.log(f"OK: {url[:80]}")
                    await self._parse(r.text, url, depth)
                    return

                elif r.status_code in (403, 429, 503):
                    await self.domain_manager.mark_failure(domain, blocked=True)
                    self.stats.inc("blocks")
                    self.stats.log(f"HTTP {r.status_code}: {domain}")
                    return
                else:
                    await self.domain_manager.mark_failure(domain)
            except Exception:
                if attempt < MAX_RETRIES - 1:
                    await asyncio.sleep(RETRY_BASE ** attempt)
        self.stats.inc("errors")

    async def _parse(self, html_text: str, url: str, depth: int) -> None:
        try:
            tree = html.fromstring(html_text)
        except Exception:
            return

        MiniCleaners.strip_junk_tags(tree)
        MiniCleaners.strip_comments(tree)

        title = MiniCleaners.extract_title(tree)
        text = MiniCleaners.cap_text(MiniCleaners.extract_text(tree))
        wc = MiniCheckers.count_words(text)
        lang = MiniCheckers.detect_language(text)
        chash = MiniCheckers.hash_text(text)

        record = {
            "text": text,
            "link": url,
            "title": title,
            "hash": chash,
            "word_count": wc,
            "language": lang,
        }
        await self.output.write(json.dumps(record, ensure_ascii=False))

        if depth < MAX_DEPTH:
            for href in tree.xpath("//a/@href"):
                absolute = urljoin(url, href)
                absolute, _ = urldefrag(absolute)
                if not MiniCheckers.is_valid_url(absolute):
                    continue
                if self.bloom.contains(absolute):
                    continue
                await self.url_queue.put((absolute, depth + 1))
                self.stats.inc("queued")


# ===========================================================================
# TERMINAL UI — curses with graceful ANSI fallback
# ===========================================================================
class TerminalUI:
    def __init__(self, stats: Stats):
        self.stats = stats
        self._running = True
        self._stdscr = None

    def run(self) -> None:
        if HAS_CURSES and not FORCE_NO_UI:
            try:
                curses.wrapper(self._loop)
                return
            except Exception as e:
                log.warning("curses failed (%s) — falling back to ANSI UI", e)
        self._fallback_loop()

    # ---------------- curses path -----------------------------------------
    def _loop(self, stdscr) -> None:
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)
        self._init_colors()
        while self._running:
            self._draw_curses()
            try:
                key = stdscr.getch()
            except Exception:
                break
            if key == ord("q"):
                self.stats.running = False
                self._running = False
            elif key == ord("p"):
                self.stats.paused = not self.stats.paused
                self.stats.log("PAUSED" if self.stats.paused else "RESUMED")
            elif key == ord("s"):
                self._snapshot()

    def _init_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)

    def _draw_curses(self) -> None:
        s = self.stats.snapshot()
        stdscr = self._stdscr
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        status = "PAUSED" if s["paused"] else ("RUNNING" if s["running"] else "STOPPED")
        header = f" NEXUS SCRAPER │ {status} │ Uptime: {self._fmt_time(s['uptime'])} "
        stdscr.addstr(0, 0, header.ljust(w - 1)[:w - 1], curses.A_REVERSE | curses.A_BOLD)
        stdscr.addstr(0, w - 20, "[q]uit [p]ause [s]nap", curses.A_REVERSE)

        row = 2
        stdscr.addstr(row, 2, "── STATS " + "─" * (w - 12), curses.color_pair(4)); row += 1
        pps = s["fetched"] / max(s["uptime"], 1)
        bps = s["bytes"] / max(s["uptime"], 1)
        stdscr.addstr(row, 2,
                      f"Queued: {s['queued']:<10} Fetched: {s['fetched']:<10} "
                      f"Errors: {s['errors']:<8} Blocks: {s['blocks']:<8}"); row += 1
        stdscr.addstr(row, 2,
                      f"Workers: {s['active']}/{s['concurrency']:<8} "
                      f"Pages/s: {pps:<8.1f} Bytes/s: {self._fmt_bytes(bps):<10} "
                      f"Proxies: {s['proxies']}"); row += 1
        stdscr.addstr(row, 2, f"Bloom FP: {s['fp_rate']:.6f}"); row += 2

        stdscr.addstr(row, 2, "── DOMAINS " + "─" * (w - 14), curses.color_pair(4)); row += 1
        for dom, st in sorted(s["domains"].items(),
                              key=lambda x: -x[1].get("queue", 0))[:h - row - 4]:
            blocked = st.get("blocked_until", 0) > time.time()
            if blocked:
                icon, color = "◐ BLOCKED", curses.color_pair(2)
            elif st.get("healthy", True):
                icon, color = "● HEALTHY", curses.color_pair(1)
            else:
                icon, color = "○ UNHEALTHY", curses.color_pair(3)
            stdscr.addstr(row, 2,
                          f"{dom[:30]:<30} {icon:<12} Q:{st.get('queue', 0):<6}", color)
            row += 1

        row = max(row, h - 10)
        stdscr.addstr(row, 2, "── LOG " + "─" * (w - 10), curses.color_pair(4)); row += 1
        for ts, msg in s["logs"][-8:]:
            if row >= h - 1:
                break
            stdscr.addstr(row, 2,
                          f"{time.strftime('%H:%M:%S', time.localtime(ts))}  {msg[:w-15]}",
                          curses.color_pair(5))
            row += 1
        stdscr.refresh()

    # ---------------- ANSI fallback path ----------------------------------
    def _fallback_loop(self) -> None:
        is_tty = sys.stdout.isatty()
        key_thread = threading.Thread(target=self._key_listener, daemon=True)
        key_thread.start()
        while self._running:
            s = self.stats.snapshot()
            if is_tty:
                self._draw_ansi(s)
            else:
                pps = s["fetched"] / max(s["uptime"], 1)
                log.info("queued=%d fetched=%d errors=%d blocks=%d workers=%d/%d "
                         "pps=%.1f bloom_fp=%.6f proxies=%d",
                         s["queued"], s["fetched"], s["errors"], s["blocks"],
                         s["active"], s["concurrency"], pps, s["fp_rate"], s["proxies"])
            time.sleep(2.0)

    def _draw_ansi(self, s: dict) -> None:
        w = 88
        out = []
        out.append("\033[2J\033[H")
        status = "PAUSED" if s["paused"] else ("RUNNING" if s["running"] else "STOPPED")
        out.append(f"\033[7m NEXUS SCRAPER │ {status} │ "
                   f"Uptime: {self._fmt_time(s['uptime'])} "
                   f"{'[q]uit [p]ause [s]nap':>32}\033[0m")
        out.append("")
        pps = s["fetched"] / max(s["uptime"], 1)
        bps = s["bytes"] / max(s["uptime"], 1)
        out.append(f"  Queued: {s['queued']:<10} Fetched: {s['fetched']:<10} "
                   f"Errors: {s['errors']:<8} Blocks: {s['blocks']:<8}")
        out.append(f"  Workers: {s['active']}/{s['concurrency']:<6} "
                   f"Pages/s: {pps:<6.1f} Bytes/s: {self._fmt_bytes(bps):<10} "
                   f"Proxies: {s['proxies']}")
        out.append(f"  Bloom FP rate: {s['fp_rate']:.6f}")
        out.append("")
        out.append("  ── DOMAINS " + "─" * (w - 12))
        for dom, st in sorted(s["domains"].items(),
                              key=lambda x: -x[1].get("queue", 0))[:12]:
            blocked = st.get("blocked_until", 0) > time.time()
            health = "BLOCKED" if blocked else ("OK" if st.get("healthy", True) else "BAD")
            out.append(f"  {dom[:32]:<32} {health:<8} "
                       f"Q:{st.get('queue', 0):<5} "
                       f"fetched:{st.get('fetched', 0)} errs:{st.get('errors', 0)}")
        out.append("")
        out.append("  ── LOG " + "─" * (w - 8))
        for ts, msg in s["logs"][-8:]:
            out.append(f"  {time.strftime('%H:%M:%S', time.localtime(ts))}  {msg[:w-12]}")
        sys.stdout.write("\n".join(out) + "\n")
        sys.stdout.flush()

    def _key_listener(self) -> None:
        """Cross-platform non-blocking keyboard read."""
        if sys.platform == "win32":
            try:
                import msvcrt
            except ImportError:
                return
            while self._running:
                try:
                    if msvcrt.kbhit():
                        k = msvcrt.getch().decode("utf-8", "ignore").lower()
                        self._handle_key(k)
                    time.sleep(0.1)
                except Exception:
                    return
        else:
            try:
                import select, tty, termios
            except ImportError:
                return
            try:
                fd = sys.stdin.fileno()
                old = termios.tcgetattr(fd)
                tty.setcbreak(fd)
            except Exception:
                return
            try:
                while self._running:
                    r, _, _ = select.select([sys.stdin], [], [], 0.2)
                    if r:
                        k = sys.stdin.read(1).lower()
                        self._handle_key(k)
            finally:
                try:
                    termios.tcsetattr(fd, termios.TCSADRAIN, old)
                except Exception:
                    pass

    def _handle_key(self, k: str) -> None:
        if k == "q":
            self.stats.running = False
            self._running = False
        elif k == "p":
            self.stats.paused = not self.stats.paused
            self.stats.log("PAUSED" if self.stats.paused else "RESUMED")
        elif k == "s":
            self._snapshot()

    def _snapshot(self) -> None:
        s = self.stats.snapshot()
        fn = f"snapshot_{int(time.time())}.json"
        try:
            with open(fn, "w", encoding="utf-8") as f:
                json.dump({k: v for k, v in s.items() if k != "logs"},
                          f, indent=2, default=str)
            self.stats.log(f"Snapshot saved: {fn}")
        except Exception as e:
            self.stats.log(f"Snapshot failed: {e}")

    @staticmethod
    def _fmt_time(seconds: float) -> str:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    @staticmethod
    def _fmt_bytes(b: float) -> str:
        for unit in ("B", "KB", "MB", "GB"):
            if b < 1024:
                return f"{b:.1f}{unit}"
            b /= 1024
        return f"{b:.1f}TB"


# ===========================================================================
# TESTING MACHINE — unit tests, integration tests, benchmarks
# ===========================================================================
class TestingMachine:
    """Huge built-in test harness. Run with --test."""

    def __init__(self):
        self.results: List[Tuple[str, bool, float, str]] = []

    def run_all(self) -> bool:
        print("\n" + "=" * 74)
        print("  NEXUS TESTING MACHINE")
        print("=" * 74)
        tests = sorted(
            (n for n in dir(self) if n.startswith("test_")),
            key=lambda x: x,
        )
        for name in tests:
            fn = getattr(self, name)
            t0 = time.perf_counter()
            try:
                if asyncio.iscoroutinefunction(fn):
                    asyncio.run(fn())
                else:
                    fn()
                self.results.append((name, True, time.perf_counter() - t0, ""))
            except AssertionError as e:
                self.results.append((name, False, time.perf_counter() - t0,
                                     f"ASSERT: {e}"))
            except Exception as e:
                self.results.append((name, False, time.perf_counter() - t0,
                                     f"{type(e).__name__}: {e}"))
        return self.report()

    def report(self) -> bool:
        passed = sum(1 for r in self.results if r[1])
        total = len(self.results)
        print("-" * 74)
        for name, ok, dt, msg in self.results:
            icon = "\033[92m✓\033[0m" if ok else "\033[91m✗\033[0m"
            print(f"  {icon} {name:<44} {dt*1000:>8.2f}ms  {msg}")
        print("-" * 74)
        color = "\033[92m" if passed == total else "\033[91m"
        print(f"  {color}{passed}/{total} passed\033[0m")
        print("=" * 74 + "\n")
        return passed == total

    # ---- BloomFilter ------------------------------------------------------
    def test_bloom_creation_and_persistence(self):
        fn = "test_visited.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        b.add("https://example.com")
        assert b.contains("https://example.com"), "must contain added item"
        b.close()
        # reload
        b2 = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        assert b2.contains("https://example.com"), "must persist across reopen"
        b2.close()
        os.remove(fn)

    def test_bloom_no_false_negatives(self):
        b = BloomFilter("test_bf2.bloom", capacity=100_000, error_rate=0.01)
        items = [f"https://site{i}.com/page" for i in range(5_000)]
        for it in items:
            b.add(it)
        for it in items:
            assert b.contains(it), f"false negative: {it}"
        b.close()
        os.remove("test_bf2.bloom")

    def test_bloom_fp_rate_sanity(self):
        b = BloomFilter("test_bf3.bloom", capacity=10_000, error_rate=0.01)
        for i in range(100):
            b.add(f"a{i}")
        fps = sum(1 for i in range(10_000) if b.contains(f"nope{i}"))
        # generous bound — should be nowhere near 100%
        assert fps < 1000, f"FP count too high: {fps}"
        b.close()
        os.remove("test_bf3.bloom")

    # ---- AdaptiveConcurrency ---------------------------------------------
    async def test_adaptive_increases_when_fast(self):
        ac = AdaptiveConcurrency(initial=100, min_cap=10, max_cap=1000,
                                 target_latency=1.0)
        for _ in range(200):
            await ac.record(0.2, False)
        assert ac.current > 100, f"should increase, got {ac.current}"

    async def test_adaptive_decreases_when_slow(self):
        ac = AdaptiveConcurrency(initial=200, min_cap=10, max_cap=1000,
                                 target_latency=1.0)
        for _ in range(200):
            await ac.record(5.0, False)
        assert ac.current < 200, f"should decrease, got {ac.current}"

    async def test_adaptive_respects_bounds(self):
        ac = AdaptiveConcurrency(initial=50, min_cap=20, max_cap=80,
                                 target_latency=1.0)
        for _ in range(400):
            await ac.record(0.1, False)
        assert ac.current <= 80
        for _ in range(400):
            await ac.record(10.0, True)
        assert ac.current >= 20

    # ---- MiniCleaners -----------------------------------------------------
    def test_normalize_whitespace(self):
        assert MiniCleaners.normalize_whitespace("a   b\tc") == "a b c"
        assert MiniCleaners.normalize_whitespace("x\n\n\ny") == "x\ny"
        assert MiniCleaners.normalize_whitespace("  hi  ") == "hi"

    def test_cap_text(self):
        assert MiniCleaners.cap_text("abc", 10) == "abc"
        assert MiniCleaners.cap_text("a" * 100, 10) == "a" * 10

    def test_extract_title_from_html(self):
        tree = html.fromstring("<html><head><title>Hello World</title></head></html>")
        assert MiniCleaners.extract_title(tree) == "Hello World"

    def test_extract_title_og_fallback(self):
        tree = html.fromstring(
            '<html><head><meta property="og:title" content="OG Title"></head></html>'
        )
        assert MiniCleaners.extract_title(tree) == "OG Title"

    def test_strip_junk_tags(self):
        src = "<html><body><p>keep</p><script>evil()</script><style>x{}</style></body></html>"
        tree = html.fromstring(src)
        MiniCleaners.strip_junk_tags(tree)
        text = MiniCleaners.extract_text(tree)
        assert "keep" in text
        assert "evil" not in text
        assert "x{}" not in text

    # ---- MiniCheckers -----------------------------------------------------
    def test_is_valid_url(self):
        assert MiniCheckers.is_valid_url("https://example.com")
        assert MiniCheckers.is_valid_url("http://a.b/c?x=1")
        assert not MiniCheckers.is_valid_url("ftp://x")
        assert not MiniCheckers.is_valid_url("javascript:void(0)")
        assert not MiniCheckers.is_valid_url("")

    def test_is_html(self):
        assert MiniCheckers.is_html({"Content-Type": "text/html; charset=utf-8"})
        assert MiniCheckers.is_html({"content-type": "application/xhtml+xml"})
        assert not MiniCheckers.is_html({"Content-Type": "image/png"})

    def test_is_blocked_detection(self):
        assert MiniCheckers.is_blocked("<html>Just a moment...</html>")
        assert MiniCheckers.is_blocked("Attention Required! | Cloudflare")
        assert not MiniCheckers.is_blocked("<html><body>hello</body></html>")

    def test_detect_language_english(self):
        assert MiniCheckers.detect_language(
            "the quick brown fox and the lazy dog is in the house"
        ) == "en"

    def test_detect_language_script_based(self):
        assert MiniCheckers.detect_language("Привет, мир") == "ru"
        assert MiniCheckers.detect_language("你好世界") == "zh"
        assert MiniCheckers.detect_language("こんにちは") == "ja"

    def test_count_words(self):
        assert MiniCheckers.count_words("one two three") == 3
        assert MiniCheckers.count_words("") == 0
        assert MiniCheckers.count_words("a-b c_d") >= 2

    def test_hash_text_deterministic(self):
        a = MiniCheckers.hash_text("hello")
        b = MiniCheckers.hash_text("hello")
        c = MiniCheckers.hash_text("world")
        assert a == b
        assert a != c
        assert len(a) == 64

    # ---- MiniHandlers -----------------------------------------------------
    async def test_retry_async_eventually_succeeds(self):
        attempts = {"n": 0}

        @MiniHandlers.retry_async(max_attempts=4, base=0.01)
        async def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise ValueError("not yet")
            return "ok"

        assert await flaky() == "ok"
        assert attempts["n"] == 3

    async def test_retry_async_raises_after_max(self):
        attempts = {"n": 0}

        @MiniHandlers.retry_async(max_attempts=3, base=0.01)
        async def always_fail():
            attempts["n"] += 1
            raise RuntimeError("nope")

        try:
            await always_fail()
            assert False, "should have raised"
        except RuntimeError:
            assert attempts["n"] == 3

    def test_sync_retry(self):
        state = {"n": 0}

        @MiniHandlers.sync_retry(max_attempts=3, base=0.01)
        def flaky():
            state["n"] += 1
            if state["n"] < 2:
                raise ValueError("no")
            return 42

        assert flaky() == 42

    def test_safe_returns_default(self):
        assert MiniHandlers.safe(lambda: 1 / 0, default=-1) == -1
        assert MiniHandlers.safe(lambda: 1 + 1) == 2

    async def test_circuit_breaker_opens(self):
        cb = CircuitBreaker(threshold=3, timeout=1.0)
        assert not await cb.is_open("k")
        for _ in range(3):
            await cb.record_failure("k")
        assert await cb.is_open("k")
        await asyncio.sleep(1.1)
        assert not await cb.is_open("k")

    async def test_circuit_breaker_success_resets(self):
        cb = CircuitBreaker(threshold=3, timeout=60)
        await cb.record_failure("k")
        await cb.record_failure("k")
        await cb.record_success("k")
        await cb.record_failure("k")
        assert not await cb.is_open("k")

    async def test_token_bucket(self):
        tb = TokenBucket(rate=10.0, capacity=2.0)
        t0 = time.monotonic()
        await tb.acquire()
        await tb.acquire()
        await tb.acquire()
        dt = time.monotonic() - t0
        assert dt >= 0.05, f"should have waited, got {dt}"

    # ---- MiniDebuggers ----------------------------------------------------
    def test_debuggers_report_shape(self):
        MiniDebuggers.enabled = True
        MiniDebuggers.bump("x")
        MiniDebuggers.bump("x", 5)
        MiniDebuggers.record_time("t", 0.1)
        MiniDebuggers.record_time("t", 0.3)
        r = MiniDebuggers.report()
        assert r["counters"]["x"] == 6
        assert r["timers"]["t"]["n"] == 2
        MiniDebuggers.enabled = False

    # ---- BatchWriter ------------------------------------------------------
    async def test_batch_writer_flush(self):
        fn = "test_batch.jsonl"
        MiniHandlers.safe(lambda: os.remove(fn))
        bw = BatchWriter(fn, batch_size=3)
        for i in range(7):
            await bw.write(f'{{"i":{i}}}')
        await bw.close()
        with open(fn, "r", encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 7, f"expected 7, got {len(lines)}"
        os.remove(fn)

    # ---- ProxyExtractor ---------------------------------------------------
    def test_proxy_regex_extraction(self):
        text = "http://1.2.3.4:8080\nsocks5://5.6.7.8:1080\n# comment\n9.9.9.9:3128"
        found = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", line)
            if m:
                found.append(m.group(1))
        assert found == ["1.2.3.4:8080", "5.6.7.8:1080", "9.9.9.9:3128"]

    # ---- End-to-end parse ------------------------------------------------
    async def test_end_to_end_parse(self):
        """Feed fake HTML through the parse pipeline (no network)."""
        fn_out = "test_e2e.jsonl"
        MiniHandlers.safe(lambda: os.remove(fn_out))

        stats = Stats()
        c = Crawler.__new__(Crawler)  # bypass __init__ network setup
        c.bloom = BloomFilter("test_e2e.bloom", capacity=1000, error_rate=0.01)
        c.output = BatchWriter(fn_out, batch_size=10)
        c.url_queue = asyncio.Queue()
        c.running = True
        c.stats = stats
        c.domain_manager = DomainManager(None)
        c.proxy_extractor = type("P", (), {"valid": [], "random_proxy": lambda s: None})()

        html_src = (
            "<html><head><title>Test Page</title></head>"
            "<body><h1>Hello</h1><p>the quick brown fox is in the house.</p>"
            "<a href='https://linked.example/page'>next</a>"
            "<script>ignore()</script></body></html>"
        )
        await c._parse(html_src, "https://root.example/", 0)
        await c.output.close()
        c.bloom.close()
        os.remove("test_e2e.bloom")

        with open(fn_out, "r", encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        rec = lines[0]
        for key in ("text", "link", "title", "hash", "word_count", "language"):
            assert key in rec, f"missing {key}"
        assert rec["title"] == "Test Page"
        assert rec["language"] == "en"
        assert rec["word_count"] > 0
        os.remove(fn_out)

    # ---- Benchmarks -------------------------------------------------------
    def test_bench_bloom(self):
        b = BloomFilter("bench.bloom", capacity=1_000_000, error_rate=0.01)
        items = [f"https://x.com/{i}" for i in range(50_000)]
        t0 = time.perf_counter()
        for it in items:
            b.add(it)
        add_dt = time.perf_counter() - t0
        t0 = time.perf_counter()
        for it in items:
            b.contains(it)
        has_dt = time.perf_counter() - t0
        print(f"\n    [bench] bloom add: {len(items)/add_dt:,.0f} ops/s, "
              f"has: {len(items)/has_dt:,.0f} ops/s", end="")
        b.close()
        os.remove("bench.bloom")

    def test_bench_checkers(self):
        text = "the quick brown fox " * 500
        t0 = time.perf_counter()
        for _ in range(1000):
            MiniCheckers.detect_language(text)
        dt = time.perf_counter() - t0
        print(f"\n    [bench] detect_language: {1000/dt:,.0f} ops/s", end="")

    def test_bench_parse(self):
        html_src = ("<html><head><title>x</title></head><body>"
                    + "<p>hello world</p>" * 200 + "</body></html>")
        t0 = time.perf_counter()
        for _ in range(500):
            tree = html.fromstring(html_src)
            MiniCleaners.strip_junk_tags(tree)
            MiniCleaners.extract_text(tree)
        dt = time.perf_counter() - t0
        print(f"\n    [bench] parse+clean: {500/dt:,.0f} pages/s", end="")


# ===========================================================================
# MAIN
# ===========================================================================
FORCE_NO_UI = False


def _run_asyncio(loop: asyncio.AbstractEventLoop, crawler: Crawler) -> None:
    asyncio.set_event_loop(loop)
    MiniHandlers.install_signal_handlers(loop, lambda: setattr(crawler, "running", False))
    try:
        loop.run_until_complete(crawler.run())
    except Exception as e:
        log.error("Crawler crashed: %s", e)
        log.debug("Traceback:\n%s", traceback.format_exc())
    finally:
        try:
            loop.close()
        except Exception:
            pass


def main() -> None:
    global DEBUG_MODE, FORCE_NO_UI

    args = set(sys.argv[1:])
    if "--test" in args:
        ok = TestingMachine().run_all()
        sys.exit(0 if ok else 1)
    if "--debug" in args:
        DEBUG_MODE = True
        log.setLevel(logging.DEBUG)
        MiniDebuggers.enabled = True
        MiniDebuggers.mem_start()
    if "--no-ui" in args:
        FORCE_NO_UI = True

    MiniHandlers.install_exception_hook()

    print("=" * 60)
    print("  NEXUS SCRAPER — The most optimized crawler to ever exist")
    print(f"  curses: {'yes' if HAS_CURSES else 'no (ANSI fallback)'} | "
          f"debug: {DEBUG_MODE}")
    print("=" * 60)

    raw = input("Enter start URL (or 'file' for start_urls.txt): ").strip()
    if raw.lower() == "file" or not raw:
        if not os.path.exists(START_URLS_FILE):
            print(f"ERROR: {START_URLS_FILE} not found.")
            return
        with open(START_URLS_FILE, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    else:
        urls = [raw]

    urls = [u for u in urls if MiniCheckers.is_valid_url(u)]
    if not urls:
        print("No valid URLs provided.")
        return

    stats = Stats()
    crawler = Crawler(urls, stats)

    loop = asyncio.new_event_loop()
    t = threading.Thread(target=_run_asyncio, args=(loop, crawler), daemon=True)
    t.start()

    try:
        ui = TerminalUI(stats)
        ui.run()
    except KeyboardInterrupt:
        pass
    finally:
        stats.running = False
        try:
            loop.call_soon_threadsafe(loop.stop)
        except Exception:
            pass
        t.join(timeout=5)
        if DEBUG_MODE:
            MiniDebuggers.dump("debug_report.json")
        print("Scraper stopped.")


if __name__ == "__main__":
    main()