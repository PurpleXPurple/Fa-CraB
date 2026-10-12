#!/usr/bin/env python3
"""
scraper.py — Nexus Edition.
The most optimized crawler to ever exist.

Dependencies:
    pip install curl-cffi lxml
"""

import asyncio
import collections
import concurrent.futures
import curses
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
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

from curl_cffi.requests import AsyncSession
from lxml import html

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

# 40 proxy sources — grab up to 30 each, validate, persist forever
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


# ===========================================================================
# BLOOM FILTER — mmap-backed, pure Python, Kirsch-Mitzenmacher double hashing
# ===========================================================================
class BloomFilter:
    """
    Space-efficient probabilistic set membership.
    m = -n * ln(p) / (ln2)^2   bits
    k = (m/n) * ln2            hash functions
    """

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
        exists = os.path.exists(self.filepath)
        if exists and os.path.getsize(self.filepath) >= self.num_bytes:
            # Already large enough — reuse
            pass
        else:
            with open(self.filepath, "wb") as f:
                f.write(b"\x00" * self.num_bytes)
        self._file = open(self.filepath, "r+b")
        self._mmap = mmap.mmap(self._file.fileno(), 0)
        # Count set bits (rough item estimate)
        self._items = sum(bin(b).count("1") for b in self._mmap[:4096]) * 1000
        log.info("Bloom: %d bits, %d hashes, %d bytes, ~%d items",
                 self.num_bits, self.num_hashes, self.num_bytes, self._items)

    def _hashes(self, item: str):
        """Kirsch-Mitzenmacher: h_i = h1 + i*h2."""
        data = item.encode("utf-8")
        h1 = int.from_bytes(hashlib.md5(data).digest()[:8], "little")
        h2 = int.from_bytes(hashlib.sha1(data).digest()[:8], "little")
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.num_bits

    def add(self, item: str) -> None:
        for pos in self._hashes(item):
            byte_pos, bit_pos = pos >> 3, pos & 7
            self._mmap[byte_pos] |= (1 << bit_pos)
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
        self.flush()
        if self._mmap:
            self._mmap.close()
        if self._file:
            self._file.close()


# ===========================================================================
# ADAPTIVE CONCURRENCY — AIMD controller
# ===========================================================================
class AdaptiveConcurrency:
    """
    Additive Increase / Multiplicative Decrease controller.
    Increases capacity when latency < target and errors are low.
    Decreases when latency > target or errors spike.
    """

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
        self._adjust_interval = 4.0
        self._last_adjust = time.time()
        self._in_flight = 0
        self._in_flight_lock = asyncio.Lock()

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
        error_penalty = self.error_ewma

        if latency_ratio > 1.3 or error_penalty > 0.15:
            # Multiplicative decrease
            new = int(self.current * 0.75)
        elif latency_ratio < 0.7 and error_penalty < 0.05:
            # Additive increase (+8%)
            new = int(self.current * 1.08)
        else:
            new = self.current  # hold

        new = max(self.min_cap, min(self.max_cap, new))
        if new != self.current:
            log.debug("Adaptive: %d -> %d (lat=%.2f err=%.3f)",
                      self.current, new, self.latency_ewma, self.error_ewma)
        self.current = new

    async def acquire(self) -> None:
        while True:
            async with self._in_flight_lock:
                if self._in_flight < self.current:
                    self._in_flight += 1
                    return
            await asyncio.sleep(0.01)

    async def release(self) -> None:
        async with self._in_flight_lock:
            if self._in_flight > 0:
                self._in_flight -= 1


# ===========================================================================
# MINI CLEANERS — fast HTML/ text sanitation
# ===========================================================================
class MiniCleaners:
    """Atomic cleaning operations — each does exactly one thing."""

    _JUNK_TAGS = {"script", "style", "noscript", "iframe", "svg",
                  "canvas", "template", "object", "embed", "applet"}

    @staticmethod
    def strip_junk_tags(tree) -> None:
        for tag in MiniCleaners._JUNK_TAGS:
            for elem in tree.iter(tag):
                parent = elem.getparent()
                if parent is not None:
                    parent.remove(elem)

    @staticmethod
    def strip_comments(tree) -> None:
        for comment in tree.xpath("//comment()"):
            parent = comment.getparent()
            if parent is not None:
                parent.remove(comment)

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
        raw = tree.text_content()
        return MiniCleaners.normalize_whitespace(raw)

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        text = re.sub(r"[ \t\r\f\v]+", " ", text)
        text = re.sub(r"\n\s*\n+", "\n", text)
        return text.strip()

    @staticmethod
    def cap_text(text: str, max_len: int = MAX_TEXT_LENGTH) -> str:
        return text[:max_len] if len(text) > max_len else text


# ===========================================================================
# MINI CHECKERS — atomic validation
# ===========================================================================
class MiniCheckers:
    """Atomic validation operations."""

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
        "de": {"der", "die", "das", "und", "ist", "in", "den", "von", "zu", "mit", "auf", "fur"},
        "pt": {"o", "a", "de", "que", "e", "do", "da", "em", "um", "para", "com", "nao"},
        "it": {"il", "la", "di", "che", "e", "in", "un", "per", "con", "su", "una", "non"},
        "nl": {"de", "het", "een", "van", "en", "in", "is", "dat", "op", "te", "voor"},
        "ru": {"и", "в", "не", "на", "что", "я", "с", "он", "как", "по", "но", "это"},
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
# STATS — thread-safe shared state for UI
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
            }


# ===========================================================================
# BATCH WRITER — async-safe buffered JSONL output
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
        with open(self.filepath, "a", encoding="utf-8") as f:
            f.write(data)

    async def close(self) -> None:
        async with self._lock:
            await self._flush_unlocked()


# ===========================================================================
# PROXY EXTRACTOR — 40 sources, 30 each, validate, persist forever
# ===========================================================================
class ProxyExtractor:
    def __init__(self, filepath: str = PROXY_FILE):
        self.filepath = filepath
        self.valid: List[str] = []
        self._lock = asyncio.Lock()
        self._load_existing()

    def _load_existing(self) -> None:
        if os.path.exists(self.filepath):
            with open(self.filepath, "r", encoding="utf-8") as f:
                self.valid = [l.strip() for l in f if l.strip()]
            log.info("Loaded %d persisted proxies.", len(self.valid))

    async def extract_and_validate(self, max_per_source: int = 30) -> int:
        """Fetch from 40 sources, grab up to 30 each, validate all."""
        log.info("Extracting proxies from %d sources...", len(PROXY_SOURCES))
        candidates: Set[str] = set()

        async with AsyncSession() as session:
            tasks = [self._fetch_source(session, url, max_per_source)
                     for url in PROXY_SOURCES]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    candidates.update(r)

        log.info("Collected %d unique proxy candidates.", len(candidates))
        if not candidates:
            return 0

        # Validate concurrently
        valid = await self._validate_all(candidates)
        async with self._lock:
            existing = set(self.valid)
            new = [p for p in valid if p not in existing]
            self.valid.extend(new)
            # Persist
            await asyncio.to_thread(self._persist)
        log.info("Proxy extraction done: %d valid (%d new, %d total)",
                 len(valid), len(new), len(self.valid))
        return len(new)

    async def _fetch_source(self, session: AsyncSession,
                            url: str, limit: int) -> List[str]:
        try:
            r = await session.get(url, timeout=10, impersonate="chrome120")
            if r.status_code != 200:
                return []
            found = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Match ip:port (with optional scheme prefix)
                m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5})", line)
                if m:
                    found.append(m.group(1))
                if len(found) >= limit:
                    break
            return found
        except Exception:
            return []

    async def _validate_all(self, candidates: Set[str]) -> List[str]:
        """Validate proxies concurrently against httpbin."""
        sem = asyncio.Semaphore(200)
        valid: List[str] = []
        lock = asyncio.Lock()

        async def check(proxy: str) -> None:
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

        tasks = [check(p) for p in candidates]
        await asyncio.gather(*tasks, return_exceptions=True)
        return valid

    def _persist(self) -> None:
        with open(self.filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(self.valid))

    def random_proxy(self) -> Optional[str]:
        return random.choice(self.valid) if self.valid else None


# ===========================================================================
# DOMAIN STATE — per-domain sub-crawler state
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

    async def mark_failure(self, domain: str, blocked: bool = False) -> None:
        state = await self.get(domain)
        state.consecutive_failures += 1
        state.total_errors += 1
        if blocked or state.consecutive_failures >= 3:
            state.blocked_until = time.time() + BLOCK_COOLDOWN
            state.healthy = False
        else:
            if self.proxy_extractor:
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
# CRAWLER — orchestrator + sub-crawler workers
# ===========================================================================
class Crawler:
    def __init__(self, start_urls: List[str], stats: Stats):
        self.start_urls = [urljoin(u, urlparse(u).path) or u for u in start_urls]
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
        self._tls_profiles: Dict[str, str] = {}

    async def run(self) -> None:
        # Extract proxies if pool is low
        if len(self.proxy_extractor.valid) < 10:
            asyncio.create_task(self.proxy_extractor.extract_and_validate())
            self.stats.log("Proxy extraction started in background")

        self.session = AsyncSession(max_clients=ADAPTIVE_MAX)
        asyncio.create_task(self.domain_manager.health_check_loop(self.stats))
        asyncio.create_task(self._bloom_flush_loop())

        # Seed queue
        for url in self.start_urls:
            if not self.bloom.contains(url):
                await self.url_queue.put((url, 0))
                self.stats.inc("queued")

        # Spawn workers
        for i in range(ADAPTIVE_MAX):
            self._workers.append(asyncio.create_task(self._worker(i)))

        # Wait until drained
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
            await self.session.close()
        self.bloom.close()
        await self.output.close()
        self.stats.running = False
        log.info("Crawler finished.")

    async def _bloom_flush_loop(self) -> None:
        while self.running:
            await asyncio.sleep(10.0)
            self.bloom.flush()

    async def _worker(self, worker_id: int) -> None:
        while self.running:
            try:
                url, depth = await asyncio.wait_for(self.url_queue.get(), timeout=1.5)
            except asyncio.TimeoutError:
                continue

            if self.stats.paused:
                await asyncio.sleep(0.5)
                await self.url_queue.put((url, depth))
                continue

            await self.adaptive.acquire()
            self.stats.inc("active_workers")
            t0 = time.time()
            try:
                await self._process(url, depth)
            except Exception as e:
                log.debug("Worker error %s: %s", url, e)
                self.stats.inc("errors")
            finally:
                self.stats.inc("active_workers", -1)
                await self.adaptive.release()
                latency = time.time() - t0
                await self.adaptive.record(latency, False)
                self.url_queue.task_done()

    async def _process(self, url: str, depth: int) -> None:
        if self.bloom.contains(url):
            return
        domain = urlparse(url).netloc
        state = await self.domain_manager.get(domain)
        await self.domain_manager.wait_for_access(domain)

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
        text = MiniCleaners.extract_text(tree)
        text = MiniCleaners.cap_text(text)
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

        # Deep link extraction
        if depth < MAX_DEPTH:
            for href in tree.xpath("//a/@href"):
                absolute = urljoin(url, href)
                absolute, _ = urldefrag(absolute)
                if not MiniCheckers.is_valid_url(absolute):
                    continue
                if self.bloom.contains(absolute):
                    continue
                if absolute in self._tls_profiles:
                    continue
                self._tls_profiles[absolute] = state.impersonate if 'state' in dir() else "chrome120"
                await self.url_queue.put((absolute, depth + 1))
                self.stats.inc("queued")


# ===========================================================================
# TERMINAL UI — curses dashboard
# ===========================================================================
class TerminalUI:
    def __init__(self, stats: Stats):
        self.stats = stats
        self._stdscr = None
        self._running = True

    def run(self) -> None:
        curses.wrapper(self._loop)

    def _loop(self, stdscr) -> None:
        self._stdscr = stdscr
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)
        self._init_colors()

        while self._running:
            self._draw()
            try:
                key = stdscr.getch()
            except Exception:
                break
            if key == ord("q"):
                self.stats.running = False
                self._running = False
            elif key == ord("p"):
                self.stats.paused = not self.stats.paused
                self.stats.log(f"{'PAUSED' if self.stats.paused else 'RESUMED'}")
            elif key == ord("a"):
                self._prompt_add_url()
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

    def _draw(self) -> None:
        s = self.stats.snapshot()
        stdscr = self._stdscr
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # Header
        status = "RUNNING" if s["running"] else "STOPPED"
        if s["paused"]:
            status = "PAUSED"
        header = f" NEXUS SCRAPER │ {status} │ Uptime: {self._fmt_time(s['uptime'])} "
        stdscr.addstr(0, 0, header.ljust(w - 1)[:w - 1], curses.A_REVERSE | curses.A_BOLD)
        stdscr.addstr(0, w - 20, "[q]uit [p]ause [a]dd [s]nap", curses.A_REVERSE)

        # Stats
        row = 2
        stdscr.addstr(row, 2, "── STATS " + "─" * (w - 12), curses.color_pair(4))
        row += 1
        pps = s["fetched"] / max(s["uptime"], 1)
        bps = s["bytes"] / max(s["uptime"], 1)
        stdscr.addstr(row, 2,
                      f"Queued: {s['queued']:<10} Fetched: {s['fetched']:<10} "
                      f"Errors: {s['errors']:<8} Blocks: {s['blocks']:<8}")
        row += 1
        stdscr.addstr(row, 2,
                      f"Workers: {s['active']}/{s['concurrency']:<8} "
                      f"Pages/s: {pps:<8.1f} Bytes/s: {self._fmt_bytes(bps):<10} "
                      f"Proxies: {s['proxies']}")
        row += 1
        stdscr.addstr(row, 2,
                      f"Bloom fill: {self.stats.estimated_fp_rate if hasattr(self.stats, 'estimated_fp_rate') else 'n/a'}")

        # Domains
        row += 2
        stdscr.addstr(row, 2, "── DOMAINS " + "─" * (w - 14), curses.color_pair(4))
        row += 1
        domains = s["domains"]
        shown = 0
        for dom, st in sorted(domains.items(),
                              key=lambda x: -x[1].get("queue", 0))[:h - row - 4]:
            if shown >= h - row - 4:
                break
            q = st.get("queue", 0)
            health = st.get("healthy", True)
            blocked = st.get("blocked_until", 0) > time.time()
            if blocked:
                icon, color = "◐ BLOCKED", curses.color_pair(2)
            elif health:
                icon, color = "● HEALTHY", curses.color_pair(1)
            else:
                icon, color = "○ UNHEALTHY", curses.color_pair(3)
            stdscr.addstr(row, 2, f"{dom[:30]:<30} {icon:<12} Q:{q:<6}", color)
            row += 1
            shown += 1

        # Log
        row = max(row, h - 10)
        stdscr.addstr(row, 2, "── LOG " + "─" * (w - 10), curses.color_pair(4))
        row += 1
        for ts, msg in s["logs"][-8:]:
            if row >= h - 1:
                break
            stdscr.addstr(row, 2, f"{time.strftime('%H:%M:%S', time.localtime(ts))}  {msg[:w-15]}",
                          curses.color_pair(5))
            row += 1

        stdscr.refresh()

    def _prompt_add_url(self) -> None:
        h, w = self._stdscr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        self._stdscr.addstr(h - 1, 0, "URL: ".ljust(w - 1)[:w - 1], curses.A_REVERSE)
        try:
            url = self._stdscr.getstr(h - 1, 5, w - 6).decode("utf-8", "ignore").strip()
        except Exception:
            url = ""
        curses.noecho()
        curses.curs_set(0)
        if url:
            self.stats.log(f"Add URL requested: {url}")
            # In a real impl, push to crawler's queue via thread-safe bridge

    def _snapshot(self) -> None:
        s = self.stats.snapshot()
        fn = f"snapshot_{int(time.time())}.json"
        with open(fn, "w") as f:
            json.dump({k: v for k, v in s.items() if k != "logs"}, f, indent=2, default=str)
        self.stats.log(f"Snapshot saved: {fn}")

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
# MAIN — input prompt + threaded event loop + curses UI
# ===========================================================================
def _run_asyncio(loop: asyncio.AbstractEventLoop, crawler: Crawler) -> None:
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(crawler.run())
    except Exception as e:
        log.error("Crawler crashed: %s", e)
    finally:
        loop.close()


def main() -> None:
    print("=" * 60)
    print("  NEXUS SCRAPER — The most optimized crawler to ever exist")
    print("=" * 60)

    # Input URL prompt
    raw = input("Enter start URL (or 'file' for start_urls.txt): ").strip()
    if raw.lower() == "file" or not raw:
        if not os.path.exists(START_URLS_FILE):
            print(f"ERROR: {START_URLS_FILE} not found.")
            return
        with open(START_URLS_FILE, "r", encoding="utf-8") as f:
            urls = [l.strip() for l in f if l.strip()]
    else:
        urls = [raw]

    if not urls:
        print("No URLs provided.")
        return

    stats = Stats()
    crawler = Crawler(urls, stats)

    # Start asyncio in background thread
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=_run_asyncio, args=(loop, crawler), daemon=True)
    t.start()

    # Run curses UI in main thread
    try:
        ui = TerminalUI(stats)
        ui.run()
    except KeyboardInterrupt:
        pass
    finally:
        stats.running = False
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)
        print("Scraper stopped.")


if __name__ == "__main__":
    main()