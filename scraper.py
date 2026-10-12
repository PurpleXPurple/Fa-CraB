#!/usr/bin/env python3
"""
scraper.py — Nexus v6
Async crawler · PyQt6 GUI · 4-layer spoofing · immediate disk writes ·
optimization centers · bloom filter · adaptive concurrency · zero proxies.

Fixes: AsyncSession kwargs (uses only BaseSession-accepted params).
"""

# ===========================================================================
# IMPORTS — stdlib compressed, heavy deps lazy
# ===========================================================================
import asyncio, collections, functools, gc, hashlib, importlib, json, logging, math, mmap, os, random, re, signal, socket, sys, threading, time, traceback, weakref
from dataclasses import dataclass, field, fields as dc_fields
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag


class _Lazy:
    __slots__ = ("_mod", "_attr", "_obj")
    def __init__(self, mod: str, attr: Optional[str] = None):
        self._mod, self._attr, self._obj = mod, attr, None
    def _resolve(self):
        if self._obj is None:
            m = importlib.import_module(self._mod)
            self._obj = getattr(m, self._attr) if self._attr else m
        return self._obj
    def __call__(self, *a, **kw):
        return self._resolve()(*a, **kw)
    def __getattr__(self, name):
        return getattr(self._resolve(), name)


AsyncSession = _Lazy("curl_cffi.requests", "AsyncSession")
lxml_html    = _Lazy("lxml", "html")

HAS_QT = False
QtW = QtC = QtG = None


def _ensure_qt() -> bool:
    global HAS_QT, QtW, QtC, QtG
    if HAS_QT:
        return True
    try:
        import PyQt6.QtWidgets as _W
        import PyQt6.QtCore as _C
        import PyQt6.QtGui as _G
        QtW, QtC, QtG = _W, _C, _G
        HAS_QT = True
        return True
    except ImportError:
        return False


# ===========================================================================
# CONFIG
# ===========================================================================
@dataclass(slots=True)
class Config:
    max_depth: int = 15
    timeout: float = 12.0
    max_retries: int = 3
    retry_base: float = 1.2

    output_file: str = "scraped_data.jsonl"
    visited_file: str = "visited.bloom"
    start_urls_file: str = "start_urls.txt"
    config_file: str = "scraper_config.json"

    adaptive_min: int = 20
    adaptive_max: int = 400
    adaptive_initial: int = 200
    target_latency: float = 1.5

    domain_concurrency: int = 8
    domain_rate_limit: float = 0.10

    bloom_capacity: int = 50_000_000
    bloom_error_rate: float = 0.001

    block_cooldown: float = 300.0
    health_check_interval: float = 45.0
    max_text_length: int = 2_000_000

    queue_maxsize: int = 2_000_000
    write_queue_maxsize: int = 200_000

    write_batch_max: int = 256
    write_batch_max_bytes: int = 8 * 1024 * 1024
    fsync_every: int = 0

    # Connection caps (passed via curl_options, not BaseSession kwargs)
    max_total_connections: int = 512
    max_host_connections: int = 32

    spoof_profiles: Tuple[str, ...] = (
        "chrome124", "chrome120", "firefox120", "safari15_5",
    )

    @classmethod
    def load(cls, path: str) -> "Config":
        cfg = cls()
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                valid = {f.name for f in dc_fields(cls)}
                for k, v in data.items():
                    if k in valid:
                        setattr(cfg, k, v)
                if isinstance(cfg.spoof_profiles, list):
                    cfg.spoof_profiles = tuple(cfg.spoof_profiles)
            except Exception:
                pass
        return cfg


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
FORCE_HEADLESS = False
_STOP = threading.Event()


# ===========================================================================
# OPTIMIZATION CENTER
# ===========================================================================
class _LRU:
    __slots__ = ("_data", "_max", "_hits", "_miss")
    def __init__(self, maxsize: int = 100_000):
        self._data: Dict[Any, Any] = {}
        self._max = maxsize
        self._hits = self._miss = 0
    def get(self, k):
        v = self._data.get(k)
        if v is not None:
            self._hits += 1
            return v
        self._miss += 1
        return None
    def put(self, k, v):
        if len(self._data) >= self._max:
            drop = self._max // 10
            for _ in range(drop):
                try:
                    del self._data[next(iter(self._data))]
                except StopIteration:
                    break
        self._data[k] = v
    def clear(self):
        self._data.clear()
    @property
    def stats(self):
        total = self._hits + self._miss
        return {
            "size": len(self._data),
            "hits": self._hits,
            "misses": self._miss,
            "hit_rate": self._hits / total if total else 0.0,
        }


class OptimizationCenter:
    __slots__ = (
        "config", "url_cache", "domain_cache", "lang_cache", "hash_cache",
        "_gc_was_enabled", "_last_gc",
    )

    def __init__(self, config: Config):
        self.config = config
        self.url_cache: _LRU = _LRU(200_000)
        self.domain_cache: _LRU = _LRU(50_000)
        self.lang_cache: _LRU = _LRU(20_000)
        self.hash_cache: _LRU = _LRU(100_000)
        self._gc_was_enabled = gc.isenabled()
        self._last_gc = time.monotonic()
        gc.disable()
        try:
            socket.setdefaulttimeout(30.0)
        except Exception:
            pass

    async def tune_thread_pool(self, size: int = 96) -> None:
        try:
            from concurrent.futures import ThreadPoolExecutor
            loop = asyncio.get_running_loop()
            loop.set_default_executor(
                ThreadPoolExecutor(max_workers=size, thread_name_prefix="nx")
            )
        except Exception:
            pass

    def maybe_gc(self) -> None:
        now = time.monotonic()
        if now - self._last_gc >= 15.0:
            gc.collect(1)
            self._last_gc = now

    def parse_url(self, url: str):
        v = self.url_cache.get(url)
        if v is not None:
            return v
        v = urlparse(url)
        self.url_cache.put(url, v)
        return v

    def domain_of(self, url: str) -> str:
        v = self.domain_cache.get(url)
        if v is not None:
            return v
        v = urlparse(url).netloc
        self.domain_cache.put(url, v)
        return v

    def detect_language(self, text: str) -> str:
        key = text[:200]
        v = self.lang_cache.get(key)
        if v is not None:
            return v
        v = MiniCheckers._detect_language_uncached(text)
        self.lang_cache.put(key, v)
        return v

    def restore(self) -> None:
        if self._gc_was_enabled:
            gc.enable()


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
        def _h(sig, frame):
            _STOP.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, _h)
            except Exception:
                pass

    @staticmethod
    def install_exception_hook() -> None:
        def hook(et, exc, tb):
            if issubclass(et, KeyboardInterrupt):
                sys.__excepthook__(et, exc, tb)
                return
            log.error("UNCAUGHT %s: %s", et.__name__, exc)
            log.debug("Traceback:\n%s", "".join(traceback.format_tb(tb)))
        sys.excepthook = hook

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
    __slots__ = ("threshold", "timeout", "_fails", "_opened_at", "_lock")
    def __init__(self, threshold: int = 5, timeout: float = 60.0):
        self.threshold = threshold
        self.timeout = timeout
        self._fails: Dict[str, int] = collections.defaultdict(int)
        self._opened_at: Dict[str, float] = {}
        self._lock = asyncio.Lock()

    async def is_open(self, key: str) -> bool:
        async with self._lock:
            t = self._opened_at.get(key)
            if t is None:
                return False
            if time.time() - t > self.timeout:
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


# ===========================================================================
# SPOOF ENGINE — 4 layers
# ===========================================================================
class SpoofEngine:
    __slots__ = ("_profile_pool",)

    PROFILES: Dict[str, dict] = {
        "chrome124": {
            "impersonate": "chrome124",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "lang": "en-US,en;q=0.9",
            "platform": '"Windows"',
            "mobile": "?0",
            "brands": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
            "is_chrome": True,
        },
        "chrome120": {
            "impersonate": "chrome120",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "lang": "en-US,en;q=0.9",
            "platform": '"Windows"',
            "mobile": "?0",
            "brands": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "is_chrome": True,
        },
        "firefox120": {
            "impersonate": "firefox120",
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) "
                  "Gecko/20100101 Firefox/120.0",
            "lang": "en-US,en;q=0.5",
            "platform": "",
            "mobile": "",
            "brands": "",
            "is_chrome": False,
        },
        "safari15_5": {
            "impersonate": "safari15_5",
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
            "lang": "en-US,en;q=0.9",
            "platform": "",
            "mobile": "",
            "brands": "",
            "is_chrome": False,
        },
    }

    REGION_LANGS = (
        "en-US,en;q=0.9", "en-GB,en;q=0.9", "en-US,en;q=0.9,es;q=0.8",
        "en-US,en;q=0.9,fr;q=0.8", "en-US,en;q=0.9,de;q=0.7",
    )

    def __init__(self, allowed: Tuple[str, ...]):
        self._profile_pool = [p for p in allowed if p in self.PROFILES]
        if not self._profile_pool:
            self._profile_pool = ["chrome124"]

    def pick(self, rng: Optional[random.Random] = None) -> dict:
        r = rng or random
        return self.PROFILES[r.choice(self._profile_pool)]

    def build_headers(self, url: str, profile: dict,
                      referer: Optional[str] = None) -> dict:
        h = {
            "User-Agent": profile["ua"],
            "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8"),
            "Accept-Language": (random.choice(self.REGION_LANGS)
                                 if random.random() < 0.3 else profile["lang"]),
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin" if referer else "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
        }
        if profile["is_chrome"]:
            h["Sec-CH-UA"] = profile["brands"]
            h["Sec-CH-UA-Mobile"] = profile["mobile"]
            h["Sec-CH-UA-Platform"] = profile["platform"]
            h["Sec-CH-UA-Platform-Version"] = '"15.0.0"'
            h["Sec-CH-UA-Arch"] = '"x86"'
            h["Sec-CH-UA-Bitness"] = '"64"'
            h["Sec-CH-UA-Full-Version-List"] = profile["brands"]
            h["Sec-CH-UA-Model"] = '""'
        if referer:
            h["Referer"] = referer
        return h


# ===========================================================================
# BLOOM FILTER
# ===========================================================================
class BloomFilter:
    __slots__ = ("filepath", "capacity", "error_rate", "num_bits",
                 "num_hashes", "num_bytes", "_items", "_file", "_mmap")

    def __init__(self, filepath: str, capacity: int, error_rate: float):
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
        bits = sum(bin(b).count("1") for b in sample)
        self._items = int(bits * (self.num_bits / (4096 * 8)))
        log.info("Bloom: %d bits, %d hashes, %.1f MB, ~%d items",
                 self.num_bits, self.num_hashes, self.num_bytes / 1e6, self._items)

    def _hashes(self, item: str):
        data = item.encode("utf-8")
        h1 = int.from_bytes(hashlib.md5(data).digest()[:8], "little")
        h2 = int.from_bytes(hashlib.sha1(data).digest()[:8], "little")
        n = self.num_bits
        k = self.num_hashes
        for i in range(k):
            yield (h1 + i * h2) % n

    def add(self, item: str) -> bool:
        already = True
        mp = self._mmap
        for pos in self._hashes(item):
            bp, bit = pos >> 3, pos & 7
            cur = mp[bp]
            if not (cur & (1 << bit)):
                already = False
                mp[bp] = cur | (1 << bit)
        if not already:
            self._items += 1
            return True
        return False

    def contains(self, item: str) -> bool:
        mp = self._mmap
        for pos in self._hashes(item):
            bp, bit = pos >> 3, pos & 7
            if not (mp[bp] & (1 << bit)):
                return False
        return True

    @property
    def items(self) -> int:
        return self._items

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
            self._mmap = None
        if self._file:
            MiniHandlers.safe(self._file.close)
            self._file = None


# ===========================================================================
# ADAPTIVE CONCURRENCY
# ===========================================================================
class AdaptiveConcurrency:
    __slots__ = ("current", "min_cap", "max_cap", "target_latency",
                 "latency_ewma", "error_ewma", "_inflight", "_lock",
                 "_adjust_interval", "_last_adjust")

    def __init__(self, initial: int, min_cap: int, max_cap: int,
                 target_latency: float):
        self.current = initial
        self.min_cap = min_cap
        self.max_cap = max_cap
        self.target_latency = target_latency
        self.latency_ewma = target_latency
        self.error_ewma = 0.0
        self._inflight = 0
        self._lock = asyncio.Lock()
        self._adjust_interval = 4.0
        self._last_adjust = time.time()

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
            async with self._lock:
                if self._inflight < self.current:
                    self._inflight += 1
                    return
            await asyncio.sleep(0.008)

    async def release(self) -> None:
        async with self._lock:
            if self._inflight > 0:
                self._inflight -= 1


# ===========================================================================
# MINI CLEANERS / CHECKERS
# ===========================================================================
_WS_RE = re.compile(r"[ \t\r\f\v]+")
_NL_RE = re.compile(r"\n\s*\n+")


class MiniCleaners:
    JUNK = frozenset(("script", "style", "noscript", "iframe", "svg",
                      "canvas", "template", "object", "embed", "applet"))

    @staticmethod
    def clean_tree(tree) -> None:
        remove_set = set()
        for el in tree.iter():
            tag = el.tag
            if tag in MiniCleaners.JUNK:
                remove_set.add(el)
            elif not isinstance(tag, str):
                remove_set.add(el)
        for el in remove_set:
            p = el.getparent()
            if p is not None:
                p.remove(el)

    @staticmethod
    def extract_title(tree) -> str:
        el = tree.find(".//title")
        if el is not None and el.text:
            t = el.text.strip()
            if t:
                return t
        meta = tree.find('.//meta[@property="og:title"]')
        if meta is not None:
            c = meta.get("content")
            if c and c.strip():
                return c.strip()
        h1 = tree.find(".//h1")
        if h1 is not None:
            t = (h1.text_content() if hasattr(h1, "text_content") else h1.text) or ""
            if t.strip():
                return t.strip()[:300]
        return ""

    @staticmethod
    def extract_text(tree) -> str:
        raw = tree.text_content()
        return _NL_RE.sub("\n", _WS_RE.sub(" ", raw)).strip()

    @staticmethod
    def cap(text: str, max_len: int) -> str:
        return text[:max_len] if len(text) > max_len else text


_WORD_RE = re.compile(r"\b\w+\b")
_SCRIPT_TESTS = (
    (re.compile(r"[\u0400-\u04FF]"), "ru"),
    (re.compile(r"[\u0600-\u06FF]"), "ar"),
    (re.compile(r"[\u4E00-\u9FFF]"), "zh"),
    (re.compile(r"[\u3040-\u309F\u30A0-\u30FF]"), "ja"),
    (re.compile(r"[\uAC00-\uD7AF]"), "ko"),
    (re.compile(r"[\u0900-\u097F]"), "hi"),
)
_BLOCK_RE = tuple(re.compile(p, re.IGNORECASE) for p in (
    r"Just a moment", r"Attention Required! \| Cloudflare",
    r"cf-browser-verification", r"Please enable JavaScript",
    r"Access denied", r"Enable JavaScript and cookies to continue",
    r"Checking your browser before accessing",
))
_STOPWORDS: Dict[str, frozenset] = {
    "en": frozenset(("the", "and", "is", "in", "to", "of", "a", "that", "it", "for", "on", "with")),
    "es": frozenset(("el", "la", "de", "que", "y", "en", "un", "es", "se", "no", "por", "con")),
    "fr": frozenset(("le", "la", "de", "et", "les", "des", "en", "un", "une", "est", "pour", "dans")),
    "de": frozenset(("der", "die", "das", "und", "ist", "in", "den", "von", "zu", "mit", "auf")),
    "pt": frozenset(("o", "a", "de", "que", "e", "do", "da", "em", "um", "para", "com", "nao")),
    "it": frozenset(("il", "la", "di", "che", "e", "in", "un", "per", "con", "su", "una", "non")),
    "nl": frozenset(("de", "het", "een", "van", "en", "in", "is", "dat", "op", "te", "voor")),
}


class MiniCheckers:
    @staticmethod
    def is_valid_url(url: str) -> bool:
        try:
            p = urlparse(url)
            return p.scheme in ("http", "https") and bool(p.netloc)
        except Exception:
            return False

    @staticmethod
    def is_html(headers: dict) -> bool:
        ct = headers.get("Content-Type") or headers.get("content-type") or ""
        return "html" in ct.lower()

    @staticmethod
    def is_blocked(body: str) -> bool:
        for r in _BLOCK_RE:
            if r.search(body):
                return True
        return False

    @staticmethod
    def count_words(text: str) -> int:
        return len(_WORD_RE.findall(text))

    @staticmethod
    def hash_text(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()

    @staticmethod
    def _detect_language_uncached(text: str) -> str:
        for r, lang in _SCRIPT_TESTS:
            if r.search(text):
                return lang
        words = _WORD_RE.findall(text.lower())
        total = len(words) or 1
        best, best_score = "en", 0.0
        for lang, sw in _STOPWORDS.items():
            c = 0
            for w in words:
                if w in sw:
                    c += 1
            s = c / total
            if s > best_score:
                best, best_score = lang, s
        return best


# ===========================================================================
# STATS
# ===========================================================================
class Stats:
    __slots__ = ("_lock", "queued", "fetched", "errors", "blocks",
                 "bytes_total", "start_time", "active_workers", "domains",
                 "log_lines", "paused", "running")

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
# DISK WRITER
# ===========================================================================
class DiskWriter:
    __slots__ = ("path", "fd", "config", "_queue", "_task",
                 "_written", "_dirty", "_lock")

    def __init__(self, path: str, config: Config):
        self.path = path
        self.fd: Optional[int] = None
        self.config = config
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=config.write_queue_maxsize)
        self._task: Optional[asyncio.Task] = None
        self._written = 0
        self._dirty = 0
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
        self.fd = await asyncio.to_thread(os.open, self.path, flags, 0o644)
        try:
            os.posix_fadvise(self.fd, 0, 0, os.POSIX_FADV_SEQUENTIAL)
        except (AttributeError, OSError):
            pass
        self._task = asyncio.create_task(self._writer_loop(), name="disk-writer")

    async def write(self, record: dict) -> None:
        line = json.dumps(record, ensure_ascii=False)
        await self._queue.put(line)

    async def _writer_loop(self) -> None:
        try:
            while True:
                first = await self._queue.get()
                if first is None:
                    self._queue.task_done()
                    break

                batch: List[str] = [first]
                batch_bytes = len(first) + 1

                for _ in range(self.config.write_batch_max - 1):
                    try:
                        item = self._queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    if item is None:
                        self._queue.put_nowait(None)
                        break
                    sz = len(item) + 1
                    if batch_bytes + sz > self.config.write_batch_max_bytes:
                        self._queue.put_nowait(item)
                        break
                    batch.append(item)
                    batch_bytes += sz

                data = ("\n".join(batch) + "\n").encode("utf-8")
                try:
                    await asyncio.to_thread(os.write, self.fd, data)
                except Exception as e:
                    log.error("DiskWriter write failed: %s", e)

                self._written += len(batch)
                self._dirty += len(batch)
                for _ in batch:
                    self._queue.task_done()

                if self.config.fsync_every > 0 and self._dirty >= self.config.fsync_every:
                    try:
                        await asyncio.to_thread(os.fsync, self.fd)
                    except Exception:
                        pass
                    self._dirty = 0
        except asyncio.CancelledError:
            return

    async def stop(self) -> None:
        try:
            self._queue.put_nowait(None)
        except asyncio.QueueFull:
            pass
        if self._task:
            try:
                await asyncio.wait_for(self._task, timeout=5.0)
            except Exception:
                self._task.cancel()
                try:
                    await self._task
                except Exception:
                    pass
        if self.fd is not None:
            try:
                await asyncio.to_thread(os.fsync, self.fd)
            except Exception:
                pass
            try:
                await asyncio.to_thread(os.close, self.fd)
            except Exception:
                pass
            self.fd = None

    @property
    def written(self) -> int:
        return self._written

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()


# ===========================================================================
# DOMAIN STATE / MANAGER
# ===========================================================================
DOMAIN_CONCURRENCY = 8


@dataclass(slots=True)
class DomainState:
    domain: str
    healthy: bool = True
    blocked_until: float = 0.0
    last_access: float = 0.0
    consecutive_failures: int = 0
    profile_name: str = "chrome124"
    last_referer: Optional[str] = None
    total_fetched: int = 0
    total_errors: int = 0


class DomainManager:
    __slots__ = ("domains", "semaphores", "_lock", "breaker")

    def __init__(self):
        self.domains: Dict[str, DomainState] = {}
        self.semaphores: Dict[str, asyncio.Semaphore] = {}
        self._lock = asyncio.Lock()
        self.breaker = CircuitBreaker(threshold=5, timeout=300.0)

    async def get(self, domain: str) -> DomainState:
        d = self.domains.get(domain)
        if d is not None:
            return d
        async with self._lock:
            d = self.domains.get(domain)
            if d is None:
                d = DomainState(domain=domain)
                self.domains[domain] = d
            return d

    def get_semaphore(self, domain: str) -> asyncio.Semaphore:
        s = self.semaphores.get(domain)
        if s is None:
            s = asyncio.Semaphore(DOMAIN_CONCURRENCY)
            self.semaphores[domain] = s
        return s


# ===========================================================================
# SESSION FACTORY — handles curl_cffi version differences
# ===========================================================================
def _make_session(config: Config):
    """
    Create an AsyncSession that works across curl_cffi versions.
    Never passes kwargs that BaseSession doesn't accept.
    """
    # Only kwargs that BaseSession.__init__ accepts in all recent versions
    common_kwargs = {
        "timeout": config.timeout,
        "allow_redirects": True,
    }
    try:
        # Try with curl_options for connection caps (libcurl CURLMOPT_*)
        return AsyncSession(
            **common_kwargs,
            curl_options={
                2000: config.max_total_connections,   # CURLMOPT_MAX_TOTAL_CONNECTIONS
                2001: config.max_host_connections,    # CURLMOPT_MAX_HOST_CONNECTIONS
            },
        )
    except TypeError:
        # Fallback: bare session, no curl_options
        return AsyncSession(**common_kwargs)


# ===========================================================================
# CRAWLER
# ===========================================================================
class Crawler:
    def __init__(self, start_urls: List[str], config: Config, stats: Stats,
                 emit_stats: Optional[Callable] = None,
                 emit_log: Optional[Callable] = None):
        self.config = config
        self.stats = stats
        self.opt = OptimizationCenter(config)
        self.spoof = SpoofEngine(config.spoof_profiles)
        self.bloom = BloomFilter(config.visited_file,
                                  config.bloom_capacity,
                                  config.bloom_error_rate)
        self.domains = DomainManager()
        self.adaptive = AdaptiveConcurrency(
            config.adaptive_initial, config.adaptive_min,
            config.adaptive_max, config.target_latency,
        )
        self.writer = DiskWriter(config.output_file, config)
        self.session: Optional[Any] = None
        self.url_queue: asyncio.Queue = asyncio.Queue(maxsize=config.queue_maxsize)
        self.running = True
        self.start_urls = [u for u in start_urls if MiniCheckers.is_valid_url(u)]
        self._emit_stats = emit_stats
        self._emit_log = emit_log
        self._workers: List[asyncio.Task] = []
        self._bg_tasks: List[asyncio.Task] = []

    def spawn_bg(self, coro, name: str = "") -> asyncio.Task:
        t = asyncio.create_task(coro, name=name or None)
        self._bg_tasks.append(t)
        return t

    def _log(self, msg: str) -> None:
        self.stats.log(msg)
        if self._emit_log:
            MiniHandlers.safe(self._emit_log, msg, time.time())

    async def run(self) -> None:
        try:
            await self._run_inner()
        except asyncio.CancelledError:
            pass
        finally:
            await self.shutdown()

    async def _run_inner(self) -> None:
        await self.opt.tune_thread_pool(96)

        # ---- Session creation with version-tolerant kwargs ---------------
        self.session = _make_session(self.config)

        await self.writer.start()

        self.spawn_bg(self._stats_pump(), "stats-pump")
        self.spawn_bg(self._bloom_flush_loop(), "bloom-flush")
        self.spawn_bg(self._gc_loop(), "gc-loop")

        seeded = 0
        for url in self.start_urls:
            if not self.bloom.contains(url):
                try:
                    self.url_queue.put_nowait((url, 0))
                    seeded += 1
                except asyncio.QueueFull:
                    break
        self.stats.inc("queued", seeded)
        self._log(f"Seeded {seeded} URLs")

        for i in range(self.config.adaptive_max):
            self._workers.append(asyncio.create_task(self._worker(i)))

        idle_ticks = 0
        while self.running:
            if _STOP.is_set():
                self._log("Stop signal received")
                self.running = False
                break
            await asyncio.sleep(1.0)
            if self.url_queue.empty() and self.stats.active_workers == 0:
                idle_ticks += 1
                if idle_ticks >= 3:
                    self._log("Queues drained — shutting down")
                    break
            else:
                idle_ticks = 0

    async def shutdown(self) -> None:
        self.running = False
        for t in self._bg_tasks:
            if not t.done():
                t.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        for w in self._workers:
            if not w.done():
                w.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        if self.session:
            try:
                await asyncio.wait_for(self.session.close(), timeout=3.0)
            except Exception:
                pass
        try:
            self.bloom.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(self.writer.stop(), timeout=5.0)
        except Exception:
            pass
        self.opt.restore()
        self.stats.running = False

    async def _stats_pump(self) -> None:
        while self.running:
            await asyncio.sleep(0.5)
            if not self.running:
                return
            try:
                s = self.stats.snapshot()
                s["concurrency"] = self.adaptive.current
                s["latency_ewma"] = self.adaptive.latency_ewma
                s["error_ewma"] = self.adaptive.error_ewma
                s["bloom_items"] = self.bloom.items
                s["bloom_fp"] = self.bloom.estimated_fp_rate
                s["writer_written"] = self.writer.written
                s["writer_queue"] = self.writer.queue_depth
                if self._emit_stats:
                    self._emit_stats(s)
            except Exception:
                pass

    async def _bloom_flush_loop(self) -> None:
        while self.running:
            await asyncio.sleep(10.0)
            if not self.running:
                return
            try:
                self.bloom.flush()
            except Exception:
                pass

    async def _gc_loop(self) -> None:
        while self.running:
            await asyncio.sleep(15.0)
            if not self.running:
                return
            self.opt.maybe_gc()

    async def _worker(self, worker_id: int) -> None:
        while self.running:
            try:
                url, depth = await asyncio.wait_for(
                    self.url_queue.get(), timeout=1.5)
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
        domain = self.opt.domain_of(url)
        state = await self.domains.get(domain)
        if await self.domains.breaker.is_open(domain):
            return

        sem = self.domains.get_semaphore(domain)
        async with sem:
            now = time.time()
            if state.blocked_until > now:
                await asyncio.sleep(state.blocked_until - now)
            gap = now - state.last_access
            if gap < self.config.domain_rate_limit:
                await asyncio.sleep(self.config.domain_rate_limit - gap)
            state.last_access = time.time()

            if _STOP.is_set():
                return

            profile = self.spoof.pick()
            state.profile_name = self._profile_name(profile)
            headers = self.spoof.build_headers(url, profile, state.last_referer)

            for attempt in range(self.config.max_retries):
                try:
                    r = await self.session.get(
                        url,
                        impersonate=profile["impersonate"],
                        headers=headers,
                        timeout=self.config.timeout,
                        allow_redirects=True,
                    )
                    if not MiniCheckers.is_html(r.headers):
                        return

                    if r.status_code == 200:
                        if MiniCheckers.is_blocked(r.text):
                            state.consecutive_failures += 1
                            state.total_errors += 1
                            await self.domains.breaker.record_failure(domain)
                            state.blocked_until = time.time() + self.config.block_cooldown
                            state.healthy = False
                            self.stats.inc("blocks")
                            self._log(f"BLOCK: {domain}")
                            return
                        state.consecutive_failures = 0
                        state.healthy = True
                        state.total_fetched += 1
                        state.last_referer = url
                        await self.domains.breaker.record_success(domain)
                        if self.bloom.add(url):
                            self.stats.inc("fetched")
                        self.stats.inc("bytes", len(r.content))
                        self._log(f"OK: {url[:90]}")
                        await self._parse(r.content, url, depth)
                        return

                    elif r.status_code in (403, 429, 503):
                        state.consecutive_failures += 1
                        state.total_errors += 1
                        await self.domains.breaker.record_failure(domain)
                        state.blocked_until = time.time() + self.config.block_cooldown
                        state.healthy = False
                        self.stats.inc("blocks")
                        self._log(f"HTTP {r.status_code}: {domain}")
                        return
                    else:
                        state.total_errors += 1
                        await self.domains.breaker.record_failure(domain)
                        return

                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    if attempt < self.config.max_retries - 1:
                        await asyncio.sleep(self.config.retry_base ** attempt)
                    else:
                        log.debug("Give up %s: %s", url, e)
            self.stats.inc("errors")

    @staticmethod
    def _profile_name(profile: dict) -> str:
        for k, v in SpoofEngine.PROFILES.items():
            if v is profile:
                return k
        return "?"

    async def _parse(self, body: bytes, url: str, depth: int) -> None:
        try:
            tree = lxml_html.fromstring(body)
        except Exception:
            return

        MiniCleaners.clean_tree(tree)
        title = MiniCleaners.extract_title(tree)
        text = MiniCleaners.cap(MiniCleaners.extract_text(tree),
                                 self.config.max_text_length)
        wc = MiniCheckers.count_words(text)
        lang = self.opt.detect_language(text)
        chash = MiniCheckers.hash_text(text)

        await self.writer.write({
            "text": text,
            "link": url,
            "title": title,
            "hash": chash,
            "word_count": wc,
            "language": lang,
        })

        if depth < self.config.max_depth:
            new: List[Tuple[str, int]] = []
            contains = self.bloom.contains
            for a in tree.iter("a"):
                href = a.get("href")
                if not href:
                    continue
                try:
                    absolute = urljoin(url, href)
                    absolute, _ = urldefrag(absolute)
                except Exception:
                    continue
                if not MiniCheckers.is_valid_url(absolute):
                    continue
                if contains(absolute):
                    continue
                new.append((absolute, depth + 1))

            pushed = 0
            q = self.url_queue
            for item in new:
                try:
                    q.put_nowait(item)
                    pushed += 1
                except asyncio.QueueFull:
                    break
            if pushed:
                self.stats.inc("queued", pushed)


# ===========================================================================
# GUI (PyQt6)
# ===========================================================================
def _build_gui_classes():
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QPushButton, QLineEdit, QLabel, QTableWidget,
        QTableWidgetItem, QPlainTextEdit, QSplitter, QFileDialog,
        QMessageBox, QStatusBar,
    )
    from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt
    from PyQt6.QtGui import QFont, QAction

    class CrawlerThread(QThread):
        stats_ready = pyqtSignal(dict)
        log_ready = pyqtSignal(str, float)
        finished_cleanly = pyqtSignal()
        fatal_error = pyqtSignal(str)

        def __init__(self, urls, config):
            super().__init__()
            self.urls = urls
            self.config = config
            self.crawler: Optional[Crawler] = None
            self._loop: Optional[asyncio.AbstractEventLoop] = None

        def run(self):
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            try:
                self._loop.run_until_complete(self._run_async())
            except Exception as e:
                self.fatal_error.emit(f"{type(e).__name__}: {e}")
            finally:
                try:
                    self._loop.run_until_complete(
                        self._loop.shutdown_asyncgens())
                except Exception:
                    pass
                self._loop.close()
                self.finished_cleanly.emit()

        async def _run_async(self):
            stats = Stats()
            self.crawler = Crawler(
                self.urls, self.config, stats,
                emit_stats=self.stats_ready.emit,
                emit_log=self.log_ready.emit,
            )
            await self.crawler.run()

        def request_stop(self):
            if self.crawler:
                self.crawler.running = False

    DARK_QSS = """
        QMainWindow, QWidget { background: #1b1d22; color: #d8dee9; }
        QLineEdit { background: #232630; color: #d8dee9; border: 1px solid #343846;
                    border-radius: 4px; padding: 6px 8px; }
        QPushButton { background: #2b2f3a; color: #d8dee9; border: 1px solid #343846;
                      border-radius: 4px; padding: 6px 14px; }
        QPushButton:hover { background: #343946; }
        QPushButton:disabled { color: #6b7280; background: #232630; }
        QPushButton#primary { background: #3b82f6; color: #fff; border-color: #3b82f6; }
        QPushButton#primary:hover { background: #2563eb; }
        QPushButton#danger  { background: #dc2626; color: #fff; border-color: #dc2626; }
        QPushButton#danger:hover { background: #b91c1c; }
        QLabel { color: #d8dee9; }
        QTableWidget { background: #232630; color: #d8dee9;
                       gridline-color: #343846; border: 1px solid #343846; }
        QHeaderView::section { background: #2b2f3a; color: #d8dee9;
                               border: 0; padding: 6px; }
        QPlainTextEdit { background: #16181d; color: #d8dee9;
                         border: 1px solid #343846; font-family: Consolas, monospace; }
        QStatusBar { background: #16181d; color: #8892a0; }
        QMenuBar { background: #1b1d22; color: #d8dee9; }
        QMenuBar::item:selected { background: #2b2f3a; }
        QMenu { background: #232630; color: #d8dee9; border: 1px solid #343846; }
        QMenu::item:selected { background: #3b82f6; }
    """

    class NexusWindow(QMainWindow):
        def __init__(self, config: Config):
            super().__init__()
            self.config = config
            self._thread: Optional[CrawlerThread] = None
            self._latest: dict = {}
            self._domain_row: Dict[str, int] = {}
            self._pending_file: Optional[str] = None
            self._build_ui()
            self.setStyleSheet(DARK_QSS)
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._refresh)
            self._timer.start(500)

        def _build_ui(self):
            self.setWindowTitle("Nexus Scraper v6")
            self.resize(1440, 900)

            root = QWidget()
            layout = QVBoxLayout(root)

            top = QHBoxLayout()
            top.addWidget(QLabel("Start URL:"))
            self.url_input = QLineEdit()
            self.url_input.setPlaceholderText(
                "https://example.com  —  or click Load file")
            top.addWidget(self.url_input, 1)

            self.load_btn = QPushButton("Load file")
            self.start_btn = QPushButton("Start")
            self.start_btn.setObjectName("primary")
            self.pause_btn = QPushButton("Pause")
            self.pause_btn.setEnabled(False)
            self.stop_btn = QPushButton("Stop")
            self.stop_btn.setObjectName("danger")
            self.stop_btn.setEnabled(False)

            top.addWidget(self.load_btn)
            top.addWidget(self.start_btn)
            top.addWidget(self.pause_btn)
            top.addWidget(self.stop_btn)
            layout.addLayout(top)

            grid = QGridLayout()
            grid.setHorizontalSpacing(20)
            grid.setVerticalSpacing(4)
            self.stat_labels: Dict[str, QLabel] = {}
            fields = [
                ("queued", "Queued"), ("fetched", "Fetched"),
                ("active", "Workers"), ("concurrency", "Concurrency"),
                ("errors", "Errors"), ("blocks", "Blocks"),
                ("pps", "Pages/s"), ("wps", "Writes/s"),
                ("bytes_fmt", "Bytes"), ("bloom_items", "Bloom items"),
                ("bloom_fp", "Bloom FP"), ("writer_queue", "Disk queue"),
                ("uptime", "Uptime"),
            ]
            for i, (key, label) in enumerate(fields):
                r, c = divmod(i, 4)
                l = QLabel(f"{label}:")
                l.setStyleSheet("color: #8892a0;")
                grid.addWidget(l, r * 2, c)
                v = QLabel("—")
                v.setStyleSheet("color: #d8dee9; font-weight: 600;")
                self.stat_labels[key] = v
                grid.addWidget(v, r * 2 + 1, c)
            layout.addLayout(grid)

            splitter = QSplitter(Qt.Orientation.Horizontal)

            self.domains_table = QTableWidget(0, 6)
            self.domains_table.setHorizontalHeaderLabels(
                ["Domain", "Health", "Profile", "Fetched", "Errors", "Blocked"])
            self.domains_table.horizontalHeader().setStretchLastSection(True)
            self.domains_table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self.domains_table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self.domains_table.verticalHeader().setVisible(False)
            splitter.addWidget(self.domains_table)

            log_panel = QWidget()
            log_layout = QVBoxLayout(log_panel)
            log_layout.setContentsMargins(0, 0, 0, 0)
            header = QLabel("Live log")
            header.setStyleSheet("color: #8892a0; padding: 4px;")
            log_layout.addWidget(header)
            self.log_view = QPlainTextEdit()
            self.log_view.setReadOnly(True)
            self.log_view.setMaximumBlockCount(5000)
            log_layout.addWidget(self.log_view)
            splitter.addWidget(log_panel)

            splitter.setStretchFactor(0, 3)
            splitter.setStretchFactor(1, 2)
            layout.addWidget(splitter, 1)

            self.setCentralWidget(root)
            self.setStatusBar(QStatusBar())
            self.statusBar().showMessage("Idle")

            menu = self.menuBar()
            fm = menu.addMenu("File")
            fm.addAction(QAction("Load start URLs…", self, triggered=self._load_file))
            fm.addAction(QAction("Save snapshot…", self, triggered=self._snapshot))
            fm.addSeparator()
            fm.addAction(QAction("Exit", self, triggered=self.close))
            vm = menu.addMenu("View")
            vm.addAction(QAction("Clear log", self, triggered=self.log_view.clear))

            self.start_btn.clicked.connect(self._on_start)
            self.pause_btn.clicked.connect(self._on_pause)
            self.stop_btn.clicked.connect(self._on_stop)
            self.load_btn.clicked.connect(self._load_file)

        def _load_file(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Choose start URLs file", "",
                "Text (*.txt);;All files (*)")
            if not path:
                return
            try:
                with open(path, encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()
                             and not l.startswith("#")]
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))
                return
            self.url_input.setText(f"file:{path}")
            self.statusBar().showMessage(
                f"Loaded {len(lines)} URLs from {os.path.basename(path)}")
            self._pending_file = path

        def _on_start(self):
            raw = self.url_input.text().strip()
            urls: List[str] = []
            if raw.startswith("file:"):
                path = raw[5:]
                try:
                    with open(path, encoding="utf-8") as f:
                        urls = [l.strip() for l in f if l.strip()
                                and not l.startswith("#")]
                except Exception as e:
                    QMessageBox.warning(self, "Error", str(e))
                    return
            elif raw:
                urls = [raw]
            if not urls:
                QMessageBox.information(self, "Nexus",
                                        "Enter a URL or load a file.")
                return
            urls = [u for u in urls if MiniCheckers.is_valid_url(u)]
            if not urls:
                QMessageBox.warning(self, "Nexus", "No valid http(s) URLs.")
                return

            self.log_view.clear()
            self.domains_table.setRowCount(0)
            self._domain_row.clear()

            self._thread = CrawlerThread(urls, self.config)
            self._thread.stats_ready.connect(self._on_stats)
            self._thread.log_ready.connect(self._on_log)
            self._thread.finished_cleanly.connect(self._on_finished)
            self._thread.fatal_error.connect(self._on_fatal)
            self._thread.start()

            self.start_btn.setEnabled(False)
            self.pause_btn.setEnabled(True)
            self.pause_btn.setText("Pause")
            self.stop_btn.setEnabled(True)
            self.statusBar().showMessage(f"Running — {len(urls)} start URL(s)")

        def _on_pause(self):
            if not self._thread or not self._thread.crawler:
                return
            c = self._thread.crawler
            c.stats.paused = not c.stats.paused
            self.pause_btn.setText("Resume" if c.stats.paused else "Pause")

        def _on_stop(self):
            if self._thread:
                self._thread.request_stop()
                self.statusBar().showMessage("Stopping…")

        def _on_finished(self):
            self.start_btn.setEnabled(True)
            self.pause_btn.setEnabled(False)
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("Stopped")
            self._thread = None

        def _on_fatal(self, msg: str):
            self._append_log(f"FATAL: {msg}", time.time(), "#ef4444")
            QMessageBox.critical(self, "Crawler error", msg)

        def _on_stats(self, snap: dict):
            self._latest = snap

        def _on_log(self, msg: str, ts: float):
            color = "#8892a0"
            if msg.startswith("BLOCK"):
                color = "#f59e0b"
            elif msg.startswith("OK"):
                color = "#10b981"
            elif msg.startswith("HTTP"):
                color = "#ef4444"
            self._append_log(msg, ts, color)

        def _append_log(self, msg: str, ts: float, color: str = "#8892a0"):
            stamp = time.strftime("%H:%M:%S", time.localtime(ts))
            self.log_view.appendHtml(
                f'<span style="color:#5b6472">{stamp}</span> '
                f'<span style="color:{color}">{self._html_escape(msg)}</span>'
            )

        @staticmethod
        def _html_escape(s: str) -> str:
            return (s.replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;"))

        def _refresh(self):
            s = self._latest
            if not s:
                return
            up = s.get("uptime", 0.0)
            pps = s.get("fetched", 0) / max(up, 1)
            wps = s.get("writer_written", 0) / max(up, 1)

            def fmt_bytes(b):
                for u in ("B", "KB", "MB", "GB"):
                    if b < 1024:
                        return f"{b:.1f}{u}"
                    b /= 1024
                return f"{b:.1f}TB"

            L = self.stat_labels
            L["queued"].setText(f"{s.get('queued', 0):,}")
            L["fetched"].setText(f"{s.get('fetched', 0):,}")
            L["active"].setText(f"{s.get('active', 0)}/{s.get('concurrency', 0)}")
            L["concurrency"].setText(str(s.get("concurrency", 0)))
            L["errors"].setText(f"{s.get('errors', 0):,}")
            L["blocks"].setText(f"{s.get('blocks', 0):,}")
            L["pps"].setText(f"{pps:,.1f}")
            L["wps"].setText(f"{wps:,.1f}")
            L["bytes_fmt"].setText(fmt_bytes(s.get("bytes", 0)))
            L["bloom_items"].setText(f"{s.get('bloom_items', 0):,}")
            L["bloom_fp"].setText(f"{s.get('bloom_fp', 0):.6f}")
            L["writer_queue"].setText(f"{s.get('writer_queue', 0):,}")
            L["uptime"].setText(self._fmt_time(up))

            self._update_domains(s.get("domains", {}))

        @staticmethod
        def _fmt_time(secs: float) -> str:
            h = int(secs // 3600)
            m = int((secs % 3600) // 60)
            s = int(secs % 60)
            return f"{h:02d}:{m:02d}:{s:02d}"

        def _update_domains(self, domains: Dict[str, dict]):
            t = self.domains_table
            if t.rowCount() < len(domains):
                t.setRowCount(len(domains))
            for dom, st in sorted(domains.items(),
                                   key=lambda x: -x[1].get("fetched", 0)):
                row = self._domain_row.get(dom)
                if row is None:
                    row = len(self._domain_row)
                    self._domain_row[dom] = row
                    if row >= t.rowCount():
                        t.setRowCount(row + 1)

                blocked = st.get("blocked_until", 0) > time.time()
                healthy = st.get("healthy", True)
                if blocked:
                    health, hcolor = "BLOCKED", "#f59e0b"
                elif healthy:
                    health, hcolor = "OK", "#10b981"
                else:
                    health, hcolor = "UNHEALTHY", "#ef4444"

                cells = [
                    (dom, None),
                    (health, hcolor),
                    (st.get("profile", "-"), None),
                    (f"{st.get('fetched', 0)}", None),
                    (f"{st.get('errors', 0)}", None),
                    ("yes" if blocked else "no",
                     "#f59e0b" if blocked else "#6b7280"),
                ]
                for c, (text, color) in enumerate(cells):
                    item = t.item(row, c)
                    if item is None:
                        item = QTableWidgetItem()
                        t.setItem(row, c, item)
                    item.setText(text)
                    if color:
                        item.setForeground(QtG.QColor(color))
            if t.rowCount() > len(self._domain_row):
                t.setRowCount(len(self._domain_row))

        def _snapshot(self):
            if not self._latest:
                return
            fn, _ = QFileDialog.getSaveFileName(
                self, "Save snapshot", f"snapshot_{int(time.time())}.json",
                "JSON (*.json)")
            if not fn:
                return
            try:
                with open(fn, "w", encoding="utf-8") as f:
                    json.dump({k: v for k, v in self._latest.items()
                                if k != "logs"}, f, indent=2, default=str)
                self.statusBar().showMessage(f"Saved {fn}")
            except Exception as e:
                QMessageBox.warning(self, "Error", str(e))

        def closeEvent(self, ev):
            if self._thread and self._thread.isRunning():
                self._thread.request_stop()
                self._thread.wait(5000)
            ev.accept()

    return CrawlerThread, NexusWindow


def launch_gui(urls: Optional[List[str]], config: Config) -> int:
    if not _ensure_qt():
        print("PyQt6 is not installed. Run:  pip install PyQt6")
        print("Falling back to headless mode.")
        return 1
    QApplication = QtW.QApplication
    QFont = QtG.QFont
    CrawlerThread, NexusWindow = _build_gui_classes()
    app = QApplication(sys.argv)
    app.setApplicationName("Nexus Scraper")
    font = QFont("Segoe UI" if sys.platform == "win32" else "Sans", 10)
    app.setFont(font)
    win = NexusWindow(config)
    if urls:
        win.url_input.setText(urls[0])
    win.show()
    return app.exec()


# ===========================================================================
# TESTING MACHINE
# ===========================================================================
class TestingMachine:
    def __init__(self):
        self.results: List[Tuple[str, bool, float, str]] = []

    def run_all(self) -> bool:
        print("\n" + "=" * 74)
        print("  NEXUS v6 TESTING MACHINE")
        print("=" * 74)
        for name in sorted(n for n in dir(self) if n.startswith("test_")):
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

    def test_config_defaults(self):
        c = Config()
        assert c.max_depth > 0
        assert c.bloom_capacity > 1_000_000
        assert "chrome124" in c.spoof_profiles

    def test_config_roundtrip(self):
        path = "test_cfg.json"
        try:
            with open(path, "w") as f:
                json.dump({"max_depth": 7, "adaptive_max": 123}, f)
            c2 = Config.load(path)
            assert c2.max_depth == 7
            assert c2.adaptive_max == 123
        finally:
            MiniHandlers.safe(lambda: os.remove(path))

    def test_session_factory_no_kwarg_error(self):
        """The critical regression test — must not raise TypeError."""
        cfg = Config()
        s = _make_session(cfg)
        assert s is not None
        # close cleanly
        async def close():
            try:
                await s.close()
            except Exception:
                pass
        try:
            asyncio.get_running_loop()
            asyncio.ensure_future(close())
        except RuntimeError:
            asyncio.run(close())

    def test_lru_evicts(self):
        l = _LRU(10)
        for i in range(20):
            l.put(i, i)
        assert len(l._data) <= 10

    def test_opt_url_cache(self):
        oc = OptimizationCenter(Config())
        u = "https://example.com/path?q=1"
        p1 = oc.parse_url(u)
        p2 = oc.parse_url(u)
        assert p1 is p2
        oc.restore()

    def test_opt_domain_cache(self):
        oc = OptimizationCenter(Config())
        assert oc.domain_of("https://a.com/x") == "a.com"
        assert oc.domain_of("https://a.com/x") == "a.com"
        oc.restore()

    def test_opt_language_cache(self):
        oc = OptimizationCenter(Config())
        t = "the quick brown fox is in the house"
        assert oc.detect_language(t) == "en"
        assert oc.detect_language(t) == "en"
        oc.restore()

    def test_lazy_loader_resolves(self):
        j = _Lazy("json")
        assert j.dumps({"a": 1}) == '{"a": 1}'

    def test_bloom_new_vs_dup(self):
        fn = "test_bloom_a.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, 10_000, 0.01)
        assert b.add("x") is True
        assert b.add("x") is False
        b.close()
        os.remove(fn)

    def test_bloom_counter(self):
        fn = "test_bloom_b.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, 10_000, 0.01)
        for i in range(100):
            b.add(f"k{i}")
        assert b.items == 100
        for i in range(100):
            b.add(f"k{i}")
        assert b.items == 100
        b.close()
        os.remove(fn)

    def test_bloom_no_false_negatives(self):
        fn = "test_bloom_c.bloom"
        MiniHandlers.safe(lambda: os.remove(fn))
        b = BloomFilter(fn, 100_000, 0.01)
        items = [f"https://s{i}.c/p" for i in range(5000)]
        for it in items:
            b.add(it)
        for it in items:
            assert b.contains(it)
        b.close()
        os.remove(fn)

    def test_spoof_four_layers(self):
        se = SpoofEngine(("chrome124",))
        prof = se.pick()
        h = se.build_headers("https://x.com", prof, referer="https://x.com/a")
        assert h["User-Agent"] == prof["ua"]
        assert "Accept-Language" in h
        assert "Sec-CH-UA" in h
        assert "Sec-CH-UA-Mobile" in h
        assert "Sec-CH-UA-Platform" in h
        assert h["Referer"] == "https://x.com/a"

    def test_spoof_firefox_no_ch(self):
        se = SpoofEngine(("firefox120",))
        prof = se.pick()
        h = se.build_headers("https://x.com", prof)
        assert "Sec-CH-UA" not in h

    async def test_adaptive_up_and_down(self):
        ac = AdaptiveConcurrency(100, 10, 1000, 1.0)
        for _ in range(200):
            await ac.record(0.2, False)
        assert ac.current > 100
        ac2 = AdaptiveConcurrency(200, 10, 1000, 1.0)
        for _ in range(200):
            await ac2.record(5.0, False)
        assert ac2.current < 200

    def test_cleaner_junk_and_comment(self):
        src = "<html><body><p>keep</p><script>evil()</script><!--c--></body></html>"
        tree = lxml_html.fromstring(src)
        MiniCleaners.clean_tree(tree)
        txt = MiniCleaners.extract_text(tree)
        assert "keep" in txt
        assert "evil" not in txt

    def test_cleaner_title(self):
        t = lxml_html.fromstring("<html><head><title>Hi</title></head></html>")
        assert MiniCleaners.extract_title(t) == "Hi"

    def test_checkers_blocked(self):
        assert MiniCheckers.is_blocked("Just a moment...")
        assert not MiniCheckers.is_blocked("<p>hi</p>")

    def test_checkers_lang_script(self):
        assert MiniCheckers._detect_language_uncached("Привет") == "ru"
        assert MiniCheckers._detect_language_uncached("你好") == "zh"

    def test_checkers_lang_en(self):
        assert MiniCheckers._detect_language_uncached(
            "the quick brown fox is in the house") == "en"

    def test_checkers_words(self):
        assert MiniCheckers.count_words("one two three") == 3

    def test_checkers_valid_url(self):
        assert MiniCheckers.is_valid_url("https://a.com")
        assert not MiniCheckers.is_valid_url("javascript:void")

    async def test_disk_writer_writes(self):
        fn = "test_writer.jsonl"
        MiniHandlers.safe(lambda: os.remove(fn))
        cfg = Config()
        cfg.output_file = fn
        w = DiskWriter(fn, cfg)
        await w.start()
        for i in range(50):
            await w.write({"i": i, "link": f"https://x.com/{i}"})
        await w.stop()
        with open(fn, encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 50, f"expected 50, got {len(lines)}"
        for l in lines:
            assert "link" in json.loads(l)
        os.remove(fn)

    async def test_crawler_shutdown_clean(self):
        cfg = Config()
        cfg.visited_file = "test_shut.bloom"
        cfg.output_file = "test_shut.jsonl"
        MiniHandlers.safe(lambda: os.remove(cfg.visited_file))
        MiniHandlers.safe(lambda: os.remove(cfg.output_file))

        stats = Stats()
        crawler = Crawler(["https://example.invalid/"], cfg, stats)
        crawler.running = True

        async def hanger():
            while True:
                await asyncio.sleep(10)

        t = crawler.spawn_bg(hanger(), "hanger")
        crawler._workers = [asyncio.create_task(hanger()) for _ in range(4)]

        t0 = time.monotonic()
        await crawler.shutdown()
        dt = time.monotonic() - t0
        assert dt < 3.0, f"shutdown too slow: {dt:.2f}s"
        assert t.done()
        assert all(w.done() for w in crawler._workers)

        MiniHandlers.safe(lambda: os.remove(cfg.visited_file))
        MiniHandlers.safe(lambda: os.remove(cfg.output_file))

    async def test_parse_batches_links_and_writes(self):
        cfg = Config()
        cfg.visited_file = "test_parse.bloom"
        cfg.output_file = "test_parse.jsonl"
        MiniHandlers.safe(lambda: os.remove(cfg.visited_file))
        MiniHandlers.safe(lambda: os.remove(cfg.output_file))

        stats = Stats()
        crawler = Crawler([], cfg, stats)
        await crawler.writer.start()

        links = "".join(f'<a href="/p{i}">x</a>' for i in range(500))
        src = (f"<html><head><title>t</title></head><body>"
               f"<p>hello world foo bar</p>{links}</body></html>").encode()

        await crawler._parse(src, "https://root.example/", 0)
        assert crawler.url_queue.qsize() == 500

        await crawler.writer.stop()
        with open(cfg.output_file, encoding="utf-8") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        assert len(recs) == 1
        for k in ("text", "link", "title", "hash", "word_count", "language"):
            assert k in recs[0]
        assert recs[0]["language"] == "en"
        assert recs[0]["word_count"] >= 4

        crawler.bloom.close()
        MiniHandlers.safe(lambda: os.remove(cfg.visited_file))
        MiniHandlers.safe(lambda: os.remove(cfg.output_file))

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
        print(f"\n    [bench] bloom add: {len(items)/add_dt:,.0f}/s "
              f"has: {len(items)/has_dt:,.0f}/s", end="")
        b.close()
        os.remove(fn)

    def test_bench_parse(self):
        src = ("<html><head><title>x</title></head><body>"
               + "<p>hello world</p>" * 200 + "</body></html>").encode()
        t0 = time.perf_counter()
        for _ in range(500):
            tree = lxml_html.fromstring(src)
            MiniCleaners.clean_tree(tree)
            MiniCleaners.extract_text(tree)
        dt = time.perf_counter() - t0
        print(f"\n    [bench] parse+clean: {500/dt:,.0f} pages/s", end="")

    def test_bench_spoof(self):
        se = SpoofEngine(("chrome124", "firefox120"))
        t0 = time.perf_counter()
        for i in range(50_000):
            p = se.pick()
            se.build_headers("https://x.com", p, referer="https://x.com/r")
        dt = time.perf_counter() - t0
        print(f"\n    [bench] spoof headers: {50_000/dt:,.0f}/s", end="")


# ===========================================================================
# HEADLESS MODE
# ===========================================================================
async def _headless_async(urls: List[str], config: Config) -> None:
    stats = Stats()

    def on_stats(snap):
        pps = snap["fetched"] / max(snap["uptime"], 1)
        log.info("q=%d f=%d e=%d b=%d w=%d/%d pps=%.1f bloom=%d fp=%.6f dq=%d",
                 snap["queued"], snap["fetched"], snap["errors"],
                 snap["blocks"], snap["active"], snap["concurrency"],
                 pps, snap["bloom_items"], snap["bloom_fp"], snap["writer_queue"])

    def on_log(msg, ts):
        log.info("%s", msg)

    crawler = Crawler(urls, config, stats,
                      emit_stats=on_stats, emit_log=on_log)
    try:
        await crawler.run()
    except asyncio.CancelledError:
        pass


def run_headless(urls: List[str], config: Config) -> None:
    try:
        asyncio.run(_headless_async(urls, config))
    except KeyboardInterrupt:
        _STOP.set()


# ===========================================================================
# MAIN
# ===========================================================================
def main() -> None:
    global DEBUG_MODE, FORCE_HEADLESS

    args = sys.argv[1:]
    argset = set(args)

    if "--test" in argset:
        ok = TestingMachine().run_all()
        sys.exit(0 if ok else 1)

    if "--debug" in argset:
        DEBUG_MODE = True
        log.setLevel(logging.DEBUG)
        MiniDebuggers.enabled = True
        MiniDebuggers.mem_start()

    if "--headless" in argset:
        FORCE_HEADLESS = True

    MiniHandlers.install_exception_hook()
    MiniHandlers.install_signal_handlers()

    config = Config.load(Config().config_file)

    urls: List[str] = []
    for a in args:
        if a.startswith("http://") or a.startswith("https://"):
            urls.append(a)
    if not urls and os.path.exists(config.start_urls_file):
        try:
            with open(config.start_urls_file, encoding="utf-8") as f:
                urls = [l.strip() for l in f if l.strip()
                        and not l.startswith("#")]
        except Exception:
            urls = []

    urls = [u for u in urls if MiniCheckers.is_valid_url(u)]

    if FORCE_HEADLESS or not _ensure_qt():
        if not urls:
            print("No URLs. Pass one on the command line or create "
                  f"{config.start_urls_file}.")
            sys.exit(1)
        print(f"Headless mode: crawling {len(urls)} URL(s)")
        run_headless(urls, config)
        return

    sys.exit(launch_gui(urls or None, config))


if __name__ == "__main__":
    main()