#!/usr/bin/env python3
"""
scraper.py — Nexus Edition v4
Fixes: event-loop starvation, shutdown errors, slow proxy validation,
batch link insertion, per-domain concurrency, bloom counter accuracy.

Dependencies:
    pip install curl-cffi lxml

Usage:
    python scraper.py                # interactive
    python scraper.py --test         # test suite + benchmarks
    python scraper.py --debug        # verbose + tracemalloc
    python scraper.py --no-ui        # headless
    python scraper.py --refresh-proxies
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

# ===========================================================================
# CONFIG
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
DOMAIN_RATE_LIMIT = 0.10          # per-domain min gap between request starts
DOMAIN_CONCURRENCY = 8            # per-domain in-flight request cap
MAX_TEXT_LENGTH = 2_000_000
BATCH_SIZE = 250
BLOOM_CAPACITY = 50_000_000
BLOOM_ERROR_RATE = 0.001
ADAPTIVE_MIN = 20
ADAPTIVE_MAX = 400
ADAPTIVE_INITIAL = 200
TARGET_LATENCY = 1.5
QUEUE_MAXSIZE = 2_000_000

IMPERSONATE_PROFILES = [
    "chrome110", "chrome116", "chrome120", "chrome124",
    "firefox110", "firefox117", "firefox120", "safari15_5",
]

# 40 sources — same as before
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

PROXY_VALIDATE_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
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
FORCE_NO_UI = False
REFRESH_PROXIES = False

# Global stop flag (safe across signal handlers)
_STOP = threading.Event()


# ===========================================================================
# MINI DEBUGGERS
# ===========================================================================
class MiniDebuggers:
    enabled = False
    _timers: Dict[str, List[float]] = collections.defaultdict(list)
    _counters: Dict[str, int] = collections.Counter()
    _gauges: Dict[str, float] = {}
    _lock = threading.Lock()
    _mem_started = False

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
            b = MiniDebuggers._timers[name]
            b.append(dt)
            if len(b) > 2048:
                del b[:1024]

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
        MiniDebuggers.gauge(f"mem.{label}.cur", cur / 1e6)
        MiniDebuggers.gauge(f"mem.{label}.peak", peak / 1e6)

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
# MINI HANDLERS
# ===========================================================================
class MiniHandlers:
    @staticmethod
    def install_signal_handlers() -> None:
        def _handler(sig, frame):
            _STOP.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _handler)
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
                        if i < max_attempts - 1:
                            time.sleep(base ** i + random.random() * jitter)
                raise last
            return wrap
        return deco

    @staticmethod
    def safe(fn, *a, default=None, **kw):
        try:
            return fn(*a, **kw)
        except Exception as e:
            log.debug("safe(%s): %s", getattr(fn, "__name__", fn), e)
            return default

    @staticmethod
    async def safe_async(fn, *a, default=None, **kw):
        try:
            return await fn(*a, **kw)
        except Exception as e:
            log.debug("safe_async(%s): %s", getattr(fn, "__name__", fn), e)
            return default


class CircuitBreaker:
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

    async def record_success(self, key: str) -> None:
        async with self._lock:
            self._fails[key] = 0
            self._opened_at.pop(key, None)


class TokenBucket:
    def __init__(self, rate: float, capacity: float):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, n: float = 1.0) -> None:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity,
                              self.tokens + (now - self.last) * self.rate)
            self.last = now
            wait = 0.0
            if self.tokens < n:
                wait = (n - self.tokens) / self.rate
            self.tokens -= n
        if wait > 0:
            await asyncio.sleep(wait)


# ===========================================================================
# BLOOM FILTER (fixed counter)
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

    def add(self, item: str) -> bool:
        """Returns True if this item was actually new (bits changed)."""
        already = True
        for pos in self._hashes(item):
            bp, bit = pos >> 3, pos & 7
            cur = self._mmap[bp]
            if not (cur & (1 << bit)):
                already = False
                self._mmap[bp] = cur | (1 << bit)
        if not already:
            self._items += 1
            return True
        return False

    def contains(self, item: str) -> bool:
        for pos in self._hashes(item):
            bp, bit = pos >> 3, pos & 7
            if not (self._mmap[bp] & (1 << bit)):
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

    @property
    def items(self) -> int:
        return self._items

    def flush(self) -> None:
        if self._mmap:
            self._mmap.flush()

    def close(self) -> None:
        MiniHandlers.safe(self.flush)
        if self._mmap:
            MiniHandlers.safe(self._mmap.close)
            self._mmap = None
        if self._file:
            MiniHandlers.safe(self._file.close)
            self._file = None


# ===========================================================================
# ADAPTIVE CONCURRENCY
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
            a = 0.15
            self.latency_ewma = a * latency + (1 - a) * self.latency_ewma
            self.error_ewma = a * (1.0 if is_error else 0.0) + (1 - a) * self.error_ewma
            now = time.time()
            if now - self._last_adjust >= self._adjust_interval:
                self._adjust()
                self._last_adjust = now

    def _adjust(self) -> None:
        lr = self.latency_ewma / self.target_latency
        err = self.error_ewma
        if lr > 1.3 or err > 0.15:
            new = int(self.current * 0.75)
        elif lr < 0.7 and err < 0.05:
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
# MINI CLEANERS / CHECKERS
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
        self.domains: Dict[str, dict] = {}
        self.log_lines: collections.deque = collections.deque(maxlen=200)
        self.paused = False
        self.running = True

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
                "domains": dict(self.domains),
                "logs": list(self.log_lines),
                "paused": self.paused,
                "running": self.running,
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
# PROXY EXTRACTOR — REWRITTEN
# ===========================================================================
class ProxyExtractor:
    MAX_CANDIDATES = 300
    MAX_PER_SOURCE = 20
    VALIDATE_TIMEOUT = 2.0
    VALIDATE_SEMAPHORE = 60
    EARLY_EXIT_VALID = 50

    def __init__(self, filepath: str = PROXY_FILE):
        self.filepath = filepath
        self.valid: List[str] = []
        self._load_existing()

    def _load_existing(self) -> None:
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    self.valid = [l.strip() for l in f if l.strip()]
                log.info("Loaded %d persisted proxies.", len(self.valid))
            except Exception as e:
                log.warning("Proxy file read failed: %s", e)

    async def extract_and_validate(self, progress_cb=None) -> int:
        t0 = time.time()
        log.info("Proxy extraction: fetching from %d sources...",
                 len(PROXY_SOURCES))
        candidates = await self._gather_candidates()
        log.info("Got %d unique candidates in %.2fs.",
                 len(candidates), time.time() - t0)
        if not candidates:
            return 0
        valid = await self._validate_rolling(candidates, progress_cb)
        async with asyncio.Lock():  # trivial, keeps structure
            existing = set(self.valid)
            new = [p for p in valid if p not in existing]
            self.valid.extend(new)
            await asyncio.to_thread(self._persist)
        log.info("Proxy extraction done: %d valid (%d new, %d total) in %.2fs",
                 len(valid), len(new), len(self.valid), time.time() - t0)
        return len(new)

    async def _gather_candidates(self) -> List[str]:
        candidates: Set[str] = set()
        async with AsyncSession() as session:
            tasks = [
                asyncio.create_task(self._fetch_source(session, url,
                                                       self.MAX_PER_SOURCE))
                for url in PROXY_SOURCES
            ]
            try:
                for coro in asyncio.as_completed(tasks):
                    try:
                        chunk = await coro
                        if chunk:
                            candidates.update(chunk)
                    except Exception:
                        pass
                    if len(candidates) >= self.MAX_CANDIDATES:
                        break
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        return list(candidates)[:self.MAX_CANDIDATES]

    async def _fetch_source(self, session, url, limit) -> List[str]:
        try:
            r = await session.get(url, timeout=8, impersonate="chrome120")
            if r.status_code != 200:
                return []
            found = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})",
                              line)
                if m:
                    found.append(m.group(1))
                if len(found) >= limit:
                    break
            return found
        except Exception:
            return []

    async def _validate_rolling(self, candidates: List[str],
                                 progress_cb=None) -> List[str]:
        valid: List[str] = []
        total = len(candidates)
        done = 0
        sem = asyncio.Semaphore(self.VALIDATE_SEMAPHORE)
        lock = asyncio.Lock()

        async with AsyncSession() as session:
            async def check(proxy: str):
                nonlocal done
                async with sem:
                    if len(valid) >= self.EARLY_EXIT_VALID:
                        return
                    ok = await self._check_proxy(session, proxy)
                    async with lock:
                        done += 1
                        if ok:
                            valid.append(proxy)
                        if progress_cb:
                            progress_cb(done, total, len(valid))

            tasks = [asyncio.create_task(check(p)) for p in candidates]
            try:
                for coro in asyncio.as_completed(tasks):
                    if len(valid) >= self.EARLY_EXIT_VALID:
                        break
                    try:
                        await coro
                    except Exception:
                        pass
            finally:
                for t in tasks:
                    if not t.done():
                        t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        return valid

    async def _check_proxy(self, session, proxy: str) -> bool:
        endpoint = random.choice(PROXY_VALIDATE_ENDPOINTS)
        try:
            r = await session.get(
                endpoint,
                proxies={"http": proxy, "https": proxy},
                timeout=self.VALIDATE_TIMEOUT,
                impersonate="chrome120",
                verify=False,
            )
            return r.status_code == 200 and len(r.text) > 0
        except Exception:
            return False

    def _persist(self) -> None:
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(self.valid))
        except Exception as e:
            log.error("Proxy persist failed: %s", e)

    def random_proxy(self) -> Optional[str]:
        return random.choice(self.valid) if self.valid else None


# ===========================================================================
# DOMAIN STATE / MANAGER
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
    total_fetched: int = 0
    total_errors: int = 0


class DomainManager:
    def __init__(self, proxy_extractor: Optional[ProxyExtractor] = None):
        self.domains: Dict[str, DomainState] = {}
        self.semaphores: Dict[str, asyncio.Semaphore] = {}
        self.proxy_extractor = proxy_extractor
        self._lock = asyncio.Lock()
        self.breaker = CircuitBreaker(threshold=5, timeout=BLOCK_COOLDOWN)

    async def get(self, domain: str) -> DomainState:
        async with self._lock:
            if domain not in self.domains:
                self.domains[domain] = DomainState(domain=domain)
            return self.domains[domain]

    def get_semaphore(self, domain: str) -> asyncio.Semaphore:
        if domain not in self.semaphores:
            self.semaphores[domain] = asyncio.Semaphore(DOMAIN_CONCURRENCY)
        return self.semaphores[domain]

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

    async def health_check_loop(self, stats: Stats, crawler) -> None:
        while crawler.running:
            await asyncio.sleep(HEALTH_CHECK_INTERVAL)
            if not crawler.running:
                return
            for domain, state in list(self.domains.items()):
                if not crawler.running:
                    return
                if state.healthy and state.blocked_until <= time.time():
                    continue
                try:
                    r = await crawler.session.get(
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
        self.url_queue: asyncio.Queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        self.running = True
        self._workers: List[asyncio.Task] = []
        self._bg_tasks: List[asyncio.Task] = []

    # ---- task spawning (tracked, cancellable) ----------------------------
    def spawn_bg(self, coro) -> asyncio.Task:
        t = asyncio.create_task(coro)
        self._bg_tasks.append(t)
        return t

    # ---- main loop -------------------------------------------------------
    async def run(self) -> None:
        try:
            await self._run_inner()
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def _run_inner(self) -> None:
        # Proxy phase — blocking, before we start crawling
        if REFRESH_PROXIES or len(self.proxy_extractor.valid) < 5:
            self.stats.log("Proxy extraction phase started...")
            new = await self.proxy_extractor.extract_and_validate(
                progress_cb=lambda d, t, v: self.stats.log(
                    f"Proxies: {v} valid / {d} tried / {t} total"
                ) if d % 25 == 0 else None
            )
            self.stats.log(f"Proxy phase done: +{new} new")
        else:
            self.stats.log(
                f"Loaded {len(self.proxy_extractor.valid)} cached proxies."
            )

        # Shared session
        self.session = AsyncSession(
            max_clients=ADAPTIVE_MAX,
            max_concurrent=ADAPTIVE_MAX,
            http2=True,
        )

        # Background tasks
        self.spawn_bg(self.domain_manager.health_check_loop(self.stats, self))
        self.spawn_bg(self._bloom_flush_loop())
        self.spawn_bg(self._stats_sync_loop())

        # Seed queue
        seeded = 0
        for url in self.start_urls:
            if not self.bloom.contains(url):
                try:
                    self.url_queue.put_nowait((url, 0))
                    seeded += 1
                except asyncio.QueueFull:
                    break
        self.stats.inc("queued", seeded)

        # Workers
        for i in range(ADAPTIVE_MAX):
            self._workers.append(asyncio.create_task(self._worker(i)))

        # Idle detection + stop check
        idle_ticks = 0
        while self.running:
            if _STOP.is_set():
                self.stats.log("Stop signal received.")
                self.running = False
                break
            await asyncio.sleep(1.0)
            empty = self.url_queue.empty()
            no_active = self.stats.active_workers == 0
            if empty and no_active:
                idle_ticks += 1
                if idle_ticks >= 3:
                    log.info("All queues drained — shutting down.")
                    break
            else:
                idle_ticks = 0

    # ---- shutdown --------------------------------------------------------
    async def shutdown(self) -> None:
        self.running = False

        # 1. Cancel all background tasks
        for t in self._bg_tasks:
            if not t.done():
                t.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)

        # 2. Cancel workers
        for w in self._workers:
            if not w.done():
                w.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)

        # 3. Close session with timeout
        if self.session:
            try:
                await asyncio.wait_for(self.session.close(), timeout=3.0)
            except Exception:
                pass

        # 4. Flush bloom + output
        try:
            self.bloom.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(self.output.close(), timeout=3.0)
        except Exception:
            pass

        self.stats.running = False
        log.info("Shutdown complete.")

    # ---- background loops ------------------------------------------------
    async def _bloom_flush_loop(self) -> None:
        while self.running:
            await asyncio.sleep(10.0)
            if not self.running:
                return
            try:
                self.bloom.flush()
            except Exception:
                pass

    async def _stats_sync_loop(self) -> None:
        while self.running:
            await asyncio.sleep(1.0)
            if not self.running:
                return
            try:
                with self.stats._lock:
                    for domain, state in self.domain_manager.domains.items():
                        self.stats.domains[domain] = {
                            "healthy": state.healthy,
                            "blocked_until": state.blocked_until,
                            "queue": self.url_queue.qsize(),
                            "fetched": state.total_fetched,
                            "errors": state.total_errors,
                        }
            except Exception:
                pass

    # ---- workers ---------------------------------------------------------
    async def _worker(self, worker_id: int) -> None:
        while self.running:
            try:
                url, depth = await asyncio.wait_for(
                    self.url_queue.get(), timeout=1.5
                )
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            if self.stats.paused:
                try:
                    self.url_queue.put_nowait((url, depth))
                except asyncio.QueueFull:
                    pass
                await asyncio.sleep(0.5)
                continue

            await self.adaptive.acquire()
            self.stats.inc("active_workers")
            t0 = time.time()
            err = False
            try:
                await self._process(url, depth)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                err = True
                log.debug("Worker error %s: %s", url, e)
                self.stats.inc("errors")
            finally:
                self.stats.inc("active_workers", -1)
                await self.adaptive.release()
                await self.adaptive.record(time.time() - t0, err)
                try:
                    self.url_queue.task_done()
                except ValueError:
                    pass

    async def _process(self, url: str, depth: int) -> None:
        if self.bloom.contains(url):
            return
        domain = urlparse(url).netloc
        state = await self.domain_manager.get(domain)

        if await self.domain_manager.breaker.is_open(domain):
            return

        async with self.domain_manager.get_semaphore(domain):
            await self.domain_manager.wait_for_access(domain)
            if _STOP.is_set():
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
                            await self.domain_manager.mark_failure(domain, True)
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
                        await self.domain_manager.mark_failure(domain, True)
                        self.stats.inc("blocks")
                        self.stats.log(f"HTTP {r.status_code}: {domain}")
                        return
                    else:
                        await self.domain_manager.mark_failure(domain)
                        return

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    if attempt < MAX_RETRIES - 1:
                        await asyncio.sleep(RETRY_BASE ** attempt)
                    else:
                        log.debug("Give up %s: %s", url, e)

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

        # Batch link extraction — put_nowait, no per-link await
        if depth < MAX_DEPTH:
            new_urls: List[Tuple[str, int]] = []
            for href in tree.xpath("//a/@href"):
                try:
                    absolute = urljoin(url, href)
                    absolute, _ = urldefrag(absolute)
                except Exception:
                    continue
                if not MiniCheckers.is_valid_url(absolute):
                    continue
                if self.bloom.contains(absolute):
                    continue
                new_urls.append((absolute, depth + 1))

            pushed = 0
            for item in new_urls:
                try:
                    self.url_queue.put_nowait(item)
                    pushed += 1
                except asyncio.QueueFull:
                    break
            if pushed:
                self.stats.inc("queued", pushed)


# ===========================================================================
# TERMINAL UI (async, ANSI)
# ===========================================================================
class TerminalUI:
    def __init__(self, crawler: Crawler, stats: Stats):
        self.crawler = crawler
        self.stats = stats
        self.running = True
        self._is_tty = sys.stdout.isatty() and not FORCE_NO_UI
        self._win_kb = None
        if sys.platform == "win32":
            try:
                import msvcrt
                self._win_kb = msvcrt
            except ImportError:
                pass
        self._win_lock = threading.Lock()

    async def run(self) -> None:
        if not self._is_tty:
            # headless: just poll and log periodically
            while self.running and self.crawler.running:
                await asyncio.sleep(3.0)
                s = self.stats.snapshot()
                c = self.crawler
                log.info("queued=%d fetched=%d err=%d blk=%d workers=%d/%d "
                         "bloom=%d fp=%.6f proxies=%d",
                         s["queued"], s["fetched"], s["errors"], s["blocks"],
                         s["active"], c.adaptive.current,
                         c.bloom.items, c.bloom.estimated_fp_rate,
                         len(c.proxy_extractor.valid))
            return

        # Interactive TUI
        while self.running and self.crawler.running:
            self._draw()
            self._poll_keys()
            await asyncio.sleep(0.4)

    def stop(self) -> None:
        self.running = False

    def _poll_keys(self) -> None:
        if self._win_kb is not None:
            try:
                while self._win_kb.kbhit():
                    try:
                        ch = self._win_kb.getch().decode("utf-8", "ignore").lower()
                    except Exception:
                        break
                    self._handle_key(ch)
            except Exception:
                pass
        else:
            try:
                import select
                r, _, _ = select.select([sys.stdin], [], [], 0)
                if r:
                    ch = sys.stdin.read(1).lower()
                    self._handle_key(ch)
            except Exception:
                pass

    def _handle_key(self, k: str) -> None:
        if k == "q":
            self.stats.running = False
            self.running = False
            _STOP.set()
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
            self.stats.log(f"Snapshot: {fn}")
        except Exception as e:
            self.stats.log(f"Snapshot failed: {e}")

    def _draw(self) -> None:
        c = self.crawler
        s = self.stats.snapshot()
        w = max(90, min(140, self._term_width()))
        status = "PAUSED" if s["paused"] else ("RUNNING" if c.running else "STOPPED")
        header = f" NEXUS v4 │ {status} │ {self._fmt_time(s['uptime'])} "
        pps = s["fetched"] / max(s["uptime"], 1)
        bps = s["bytes"] / max(s["uptime"], 1)

        lines = []
        lines.append(f"\033[7m{header:<{w}}\033[0m")
        lines.append("")
        lines.append(f"  Queued: {s['queued']:<10} Fetched: {s['fetched']:<10} "
                     f"Errors: {s['errors']:<8} Blocks: {s['blocks']:<8}")
        lines.append(f"  Workers: {s['active']}/{c.adaptive.current:<6} "
                     f"Pages/s: {pps:<6.1f} Bytes/s: {self._fmt_bytes(bps):<10} "
                     f"Proxies: {len(c.proxy_extractor.valid)}")
        lines.append(f"  Bloom: {c.bloom.items} items  FP≈"
                     f"{c.bloom.estimated_fp_rate:.6f}  "
                     f"lat_ewma={c.adaptive.latency_ewma:.2f}s  "
                     f"err_ewma={c.adaptive.error_ewma:.3f}")
        lines.append("")
        lines.append("  ── DOMAINS " + "─" * (w - 12))
        dom_items = sorted(
            s["domains"].items(),
            key=lambda x: -x[1].get("fetched", 0),
        )[:10]
        if not dom_items:
            lines.append("  (none yet)")
        for dom, st in dom_items:
            blocked = st.get("blocked_until", 0) > time.time()
            health = "BLOCKED" if blocked else ("OK" if st.get("healthy", True) else "BAD")
            lines.append(
                f"  {dom[:40]:<40} {health:<8} "
                f"f:{st.get('fetched', 0):<6} e:{st.get('errors', 0):<5}"
            )
        lines.append("")
        lines.append("  ── LOG " + "─" * (w - 8))
        for ts, msg in s["logs"][-10:]:
            lines.append(
                f"  {time.strftime('%H:%M:%S', time.localtime(ts))}  {msg[:w-12]}"
            )
        lines.append(f"\n  [q]uit  [p]ause  [s]napshot")
        out = "\033[H" + "\n".join(lines) + "\033[J"
        sys.stdout.write(out)
        sys.stdout.flush()

    @staticmethod
    def _term_width() -> int:
        try:
            return os.get_terminal_size().columns
        except Exception:
            return 100

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
# TESTING MACHINE
# ===========================================================================
class TestingMachine:
    def __init__(self):
        self.results: List[Tuple[str, bool, float, str]] = []

    def run_all(self) -> bool:
        print("\n" + "=" * 74)
        print("  NEXUS v4 TESTING MACHINE")
        print("=" * 74)
        tests = sorted(n for n in dir(self) if n.startswith("test_"))
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
        return self._report()

    def _report(self) -> bool:
        passed = sum(1 for r in self.results if r[1])
        total = len(self.results)
        print("-" * 74)
        for name, ok, dt, msg in self.results:
            icon = "\033[92m✓\033[0m" if ok else "\033[91m✗\033[0m"
            print(f"  {icon} {name:<48} {dt*1000:>8.2f}ms  {msg}")
        print("-" * 74)
        color = "\033[92m" if passed == total else "\033[91m"
        print(f"  {color}{passed}/{total} passed\033[0m")
        print("=" * 74 + "\n")
        return passed == total

    # ---- Bloom ----------------------------------------------------------
    def test_bloom_add_returns_true_only_for_new(self):
        fn = "test_bloom_a.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        assert b.add("x") is True
        assert b.add("x") is False
        assert b.add("y") is True
        b.close()
        os.remove(fn)

    def test_bloom_counter_increments_only_on_new(self):
        fn = "test_bloom_b.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        for i in range(100):
            b.add(f"item{i}")
        assert b.items == 100, f"expected 100, got {b.items}"
        for i in range(100):
            b.add(f"item{i}")
        assert b.items == 100, f"double-add changed counter: {b.items}"
        b.close()
        os.remove(fn)

    def test_bloom_persistence(self):
        fn = "test_bloom_c.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        for i in range(50):
            b.add(f"k{i}")
        b.close()
        b2 = BloomFilter(fn, capacity=10_000, error_rate=0.01)
        for i in range(50):
            assert b2.contains(f"k{i}"), f"lost k{i}"
        b2.close()
        os.remove(fn)

    def test_bloom_no_false_negatives(self):
        fn = "test_bloom_d.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, capacity=100_000, error_rate=0.01)
        items = [f"https://site{i}.com/p" for i in range(5000)]
        for it in items:
            b.add(it)
        for it in items:
            assert b.contains(it)
        b.close()
        os.remove(fn)

    # ---- Adaptive -------------------------------------------------------
    async def test_adaptive_increases_when_fast(self):
        ac = AdaptiveConcurrency(initial=100, min_cap=10, max_cap=1000,
                                 target_latency=1.0)
        for _ in range(200):
            await ac.record(0.2, False)
        assert ac.current > 100

    async def test_adaptive_decreases_when_slow(self):
        ac = AdaptiveConcurrency(initial=200, min_cap=10, max_cap=1000,
                                 target_latency=1.0)
        for _ in range(200):
            await ac.record(5.0, False)
        assert ac.current < 200

    async def test_adaptive_respects_bounds(self):
        ac = AdaptiveConcurrency(initial=50, min_cap=20, max_cap=80,
                                 target_latency=1.0)
        for _ in range(400):
            await ac.record(0.1, False)
        assert ac.current <= 80
        for _ in range(400):
            await ac.record(10.0, True)
        assert ac.current >= 20

    # ---- Cleaners -------------------------------------------------------
    def test_normalize_whitespace(self):
        assert MiniCleaners.normalize_whitespace("a   b\tc") == "a b c"
        assert MiniCleaners.normalize_whitespace("x\n\n\ny") == "x\ny"
        assert MiniCleaners.normalize_whitespace("  hi  ") == "hi"

    def test_cap_text(self):
        assert MiniCleaners.cap_text("abc", 10) == "abc"
        assert MiniCleaners.cap_text("a" * 100, 10) == "a" * 10

    def test_extract_title_title_tag(self):
        tree = html.fromstring(
            "<html><head><title>Hello</title></head></html>")
        assert MiniCleaners.extract_title(tree) == "Hello"

    def test_extract_title_og_fallback(self):
        tree = html.fromstring(
            '<html><head><meta property="og:title" content="OG"></head></html>')
        assert MiniCleaners.extract_title(tree) == "OG"

    def test_strip_junk_tags(self):
        src = "<html><body><p>keep</p><script>evil()</script></body></html>"
        tree = html.fromstring(src)
        MiniCleaners.strip_junk_tags(tree)
        txt = MiniCleaners.extract_text(tree)
        assert "keep" in txt and "evil" not in txt

    # ---- Checkers -------------------------------------------------------
    def test_valid_url(self):
        assert MiniCheckers.is_valid_url("https://a.com")
        assert not MiniCheckers.is_valid_url("javascript:void")
        assert not MiniCheckers.is_valid_url("")

    def test_is_html(self):
        assert MiniCheckers.is_html({"Content-Type": "text/html; charset=utf-8"})
        assert MiniCheckers.is_html({"content-type": "application/xhtml+xml"})
        assert not MiniCheckers.is_html({"Content-Type": "image/png"})

    def test_blocked(self):
        assert MiniCheckers.is_blocked("Just a moment...")
        assert MiniCheckers.is_blocked("Attention Required! | Cloudflare")
        assert not MiniCheckers.is_blocked("<p>hello</p>")

    def test_language_script(self):
        assert MiniCheckers.detect_language("Привет, мир") == "ru"
        assert MiniCheckers.detect_language("你好世界") == "zh"
        assert MiniCheckers.detect_language("こんにちは") == "ja"

    def test_language_english(self):
        assert MiniCheckers.detect_language(
            "the quick brown fox is in the house and on the table"
        ) == "en"

    def test_count_words(self):
        assert MiniCheckers.count_words("one two three") == 3
        assert MiniCheckers.count_words("") == 0

    def test_hash_text(self):
        assert MiniCheckers.hash_text("a") == MiniCheckers.hash_text("a")
        assert MiniCheckers.hash_text("a") != MiniCheckers.hash_text("b")

    # ---- Handlers -------------------------------------------------------
    async def test_retry_async_succeeds(self):
        state = {"n": 0}

        @MiniHandlers.retry_async(max_attempts=4, base=0.01)
        async def flaky():
            state["n"] += 1
            if state["n"] < 3:
                raise ValueError("nope")
            return "ok"

        assert await flaky() == "ok"
        assert state["n"] == 3

    async def test_retry_async_raises(self):
        state = {"n": 0}

        @MiniHandlers.retry_async(max_attempts=3, base=0.01)
        async def fail():
            state["n"] += 1
            raise RuntimeError("nope")

        try:
            await fail()
            assert False
        except RuntimeError:
            assert state["n"] == 3

    async def test_circuit_breaker(self):
        cb = CircuitBreaker(threshold=3, timeout=0.5)
        assert not await cb.is_open("k")
        for _ in range(3):
            await cb.record_failure("k")
        assert await cb.is_open("k")
        await asyncio.sleep(0.6)
        assert not await cb.is_open("k")

    async def test_token_bucket(self):
        tb = TokenBucket(rate=20.0, capacity=2.0)
        t0 = time.monotonic()
        await tb.acquire()
        await tb.acquire()
        await tb.acquire()
        assert time.monotonic() - t0 >= 0.04

    # ---- BatchWriter ----------------------------------------------------
    async def test_batch_writer_flushes(self):
        fn = "test_batch.jsonl"
        MiniHandlers.safe(lambda: os.remove(fn))
        bw = BatchWriter(fn, batch_size=3)
        for i in range(7):
            await bw.write(f'{{"i":{i}}}')
        await bw.close()
        with open(fn, encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 7
        os.remove(fn)

    # ---- Per-domain concurrency ----------------------------------------
    async def test_domain_semaphore_limits_inflight(self):
        dm = DomainManager(None)
        sem = dm.get_semaphore("x.com")
        assert sem._value == DOMAIN_CONCURRENCY
        # acquire half
        for _ in range(4):
            await sem.acquire()
        assert sem._value == DOMAIN_CONCURRENCY - 4
        for _ in range(4):
            sem.release()

    # ---- Proxy extractor: rolling + early exit -------------------------
    async def test_proxy_extractor_caps_candidates(self):
        # We can't run network calls in tests, so verify constants are sane
        pe = ProxyExtractor(filepath="test_nonexistent.txt")
        assert pe.MAX_CANDIDATES <= 500
        assert pe.EARLY_EXIT_VALID <= pe.MAX_CANDIDATES
        assert pe.VALIDATE_TIMEOUT <= 3.0
        assert len(PROXY_VALIDATE_ENDPOINTS) >= 3

    # ---- Shutdown cleanliness ------------------------------------------
    async def test_shutdown_cancels_tasks(self):
        """Spin up a fake crawler with hanging bg tasks and verify shutdown."""
        # Use a minimal fake to avoid touching disk/network
        crawler = Crawler.__new__(Crawler)
        crawler.running = True
        crawler._workers = []
        crawler._bg_tasks = []
        crawler.stats = Stats()
        crawler.bloom = BloomFilter("test_shut.bloom", 1000, 0.01)
        crawler.output = BatchWriter("test_shut.jsonl", 10)
        crawler.session = None
        crawler.proxy_extractor = ProxyExtractor("test_noproxies.txt")
        crawler.domain_manager = DomainManager(None)
        crawler.adaptive = AdaptiveConcurrency()
        crawler.url_queue = asyncio.Queue()

        async def hanger():
            while True:
                await asyncio.sleep(10)

        t1 = crawler.spawn_bg(hanger())
        t2 = crawler.spawn_bg(hanger())
        crawler._workers = [asyncio.create_task(hanger()),
                            asyncio.create_task(hanger())]

        t0 = time.monotonic()
        await crawler.shutdown()
        dt = time.monotonic() - t0
        assert dt < 2.0, f"shutdown too slow: {dt:.2f}s"
        assert t1.done() and t2.done()
        assert all(w.done() for w in crawler._workers)
        assert not crawler.running

        MiniHandlers.safe(lambda: os.remove("test_shut.bloom"))
        MiniHandlers.safe(lambda: os.remove("test_shut.jsonl"))

    # ---- Batch link insertion ------------------------------------------
    async def test_batch_link_insertion(self):
        """Ensure _parse doesn't await per link — it batches."""
        fn_out = "test_batch_links.jsonl"
        MiniHandlers.safe(lambda: os.remove(fn_out))
        fn_bloom = "test_batch_links.bloom"
        MiniHandlers.safe(lambda: os.remove(fn_bloom))

        crawler = Crawler.__new__(Crawler)
        crawler.running = True
        crawler.stats = Stats()
        crawler.bloom = BloomFilter(fn_bloom, 100_000, 0.01)
        crawler.output = BatchWriter(fn_out, 100)
        crawler.url_queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)

        # Build HTML with 500 links
        links = "".join(f'<a href="/p{i}">x</a>' for i in range(500))
        html_src = f"<html><head><title>t</title></head><body>{links}</body></html>"

        await crawler._parse(html_src, "https://root.example/", 0)
        assert crawler.url_queue.qsize() == 500, \
            f"expected 500 in queue, got {crawler.url_queue.qsize()}"

        await crawler.output.close()
        crawler.bloom.close()
        MiniHandlers.safe(lambda: os.remove(fn_out))
        MiniHandlers.safe(lambda: os.remove(fn_bloom))

    # ---- End-to-end parse ----------------------------------------------
    async def test_end_to_end_parse(self):
        fn_out = "test_e2e.jsonl"
        fn_bloom = "test_e2e.bloom"
        MiniHandlers.safe(lambda: os.remove(fn_out))
        MiniHandlers.safe(lambda: os.remove(fn_bloom))

        crawler = Crawler.__new__(Crawler)
        crawler.running = True
        crawler.stats = Stats()
        crawler.bloom = BloomFilter(fn_bloom, 1000, 0.01)
        crawler.output = BatchWriter(fn_out, 10)
        crawler.url_queue = asyncio.Queue(maxsize=QUEUE_MAXSIZE)

        src = ("<html><head><title>Test</title></head>"
               "<body><h1>Hi</h1><p>the quick brown fox is in the house</p>"
               "<a href='https://link.example/'>n</a>"
               "<script>ignore()</script></body></html>")
        await crawler._parse(src, "https://root.example/", 0)
        await crawler.output.close()
        crawler.bloom.close()

        with open(fn_out, encoding="utf-8") as f:
            lines = [json.loads(l) for l in f if l.strip()]
        assert len(lines) == 1
        rec = lines[0]
        for k in ("text", "link", "title", "hash", "word_count", "language"):
            assert k in rec, f"missing {k}"
        assert rec["title"] == "Test"
        assert rec["language"] == "en"
        assert rec["word_count"] > 0

        os.remove(fn_out)
        os.remove(fn_bloom)

    # ---- Benchmarks -----------------------------------------------------
    def test_bench_bloom(self):
        fn = "bench.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, 1_000_000, 0.01)
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
        os.remove(fn)

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
async def main_async(urls: List[str]) -> None:
    stats = Stats()
    crawler = Crawler(urls, stats)
    ui = TerminalUI(crawler, stats)

    ui_task = asyncio.create_task(ui.run())
    try:
        await crawler.run()
    except asyncio.CancelledError:
        pass
    finally:
        crawler.running = False
        ui.stop()
        try:
            await asyncio.wait_for(ui_task, timeout=2.0)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            ui_task.cancel()
            MiniHandlers.safe_async.__self__ if False else None
            try:
                await ui_task
            except Exception:
                pass
        if DEBUG_MODE:
            MiniDebuggers.dump("debug_report.json")


def main() -> None:
    global DEBUG_MODE, FORCE_NO_UI, REFRESH_PROXIES

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
    if "--refresh-proxies" in args:
        REFRESH_PROXIES = True

    MiniHandlers.install_exception_hook()
    MiniHandlers.install_signal_handlers()

    print("=" * 60)
    print("  NEXUS SCRAPER v4")
    print(f"  debug={DEBUG_MODE}  ui={'off' if FORCE_NO_UI else 'on'}  "
          f"refresh_proxies={REFRESH_PROXIES}")
    print("=" * 60)

    raw = input("Enter start URL (or 'file' for start_urls.txt): ").strip()
    if raw.lower() == "file" or not raw:
        if not os.path.exists(START_URLS_FILE):
            print(f"ERROR: {START_URLS_FILE} not found.")
            return
        with open(START_URLS_FILE, encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    else:
        urls = [raw]

    urls = [u for u in urls if MiniCheckers.is_valid_url(u)]
    if not urls:
        print("No valid URLs.")
        return

    try:
        asyncio.run(main_async(urls))
    except KeyboardInterrupt:
        _STOP.set()
    finally:
        print("\nDone.")


if __name__ == "__main__":
    main()