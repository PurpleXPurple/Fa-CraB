from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import heapq
import json
import logging
import math
import os
import re
import signal
import sys
import time
import zipfile
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

try:
    import tomllib
except ImportError:
    import tomli as tomllib

try:
    import orjson

    def _dumps(obj: object) -> bytes:
        return orjson.dumps(obj)
except ImportError:
    def _dumps(obj: object) -> bytes:
        return json.dumps(obj, ensure_ascii=False).encode("utf-8")

from curl_cffi.requests import AsyncSession
from curl_cffi.requests import exceptions as curl_exc
from selectolax.lexbor import LexborHTMLParser

log = logging.getLogger("scraper")

_ImpersonateError = getattr(curl_exc, "ImpersonateError", type("_NeverImpersonate", (Exception,), {}))
_CurlRequestError = curl_exc.RequestException

_posix_fadvise = None
if sys.platform != "win32":
    _libc = None
    for _name in ("libc.so.6", "libc.dylib", "libc.so"):
        try:
            _libc = ctypes.CDLL(_name, use_errno=True)
            break
        except OSError:
            continue
    if _libc is not None:
        try:
            _posix_fadvise = _libc.posix_fadvise
            _posix_fadvise.argtypes = [ctypes.c_int, ctypes.c_longlong, ctypes.c_longlong, ctypes.c_int]
            _posix_fadvise.restype = ctypes.c_int
        except AttributeError:
            _posix_fadvise = None

POSIX_FADV_SEQUENTIAL = 2
POSIX_FADV_DONTNEED = 4

_OPEN_FLAGS = getattr(os, "O_BINARY", 0)

BLOCK_STATUS = {403, 407, 451, 503}
CHALLENGE_MARKERS = (
    b"captcha-delivery.com", b"px-captcha", b"cf_chl_opt",
    b"/cdn-cgi/challenge-platform/", b"just a moment",
    b"attention required", b"verify you are human", b"enable javascript and cookies",
)
SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".mp3", ".mp4", ".avi",
    ".mov", ".webm", ".woff", ".woff2", ".ttf", ".eot", ".css", ".js",
    ".json", ".xml", ".rss", ".atom", ".exe", ".dmg", ".iso",
}
SKIP_PATH = (
    "/login", "/signin", "/signup", "/register", "/cart", "/checkout",
    "/wp-admin", "/wp-login", "/feed", "/rss", "/sitemap", "/robots.txt",
    "/cdn-cgi/", "/.well-known/", "/account", "/profile", "/settings",
)
DROP_TAGS = (
    "script", "style", "noscript", "svg", "iframe", "head", "nav",
    "footer", "aside", "form", "button", "input", "select", "textarea",
    "canvas", "template", "object", "embed", "video", "audio",
)
BOILERPLATE_PATTERNS = (
    "navbar", "nav-menu", "navigation", "site-nav", "menu", "footer",
    "sidebar", "comment", "share", "social", "cookie", "banner",
    "advert", "promo", "popup", "modal", "breadcrumb", "pagination",
)
TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source", "campaign",
}
STOP = set(
    "the a an and or of to in for on with is are was were be been "
    "this that these those it its as at by from not but if then than "
    "so we you they he she i".split()
)
CONTENT_TYPES = ("text/html", "application/xhtml", "text/plain")

_DROP_SELECTOR = ",".join(DROP_TAGS)
_BOILER_SELECTOR = ",".join(f'[class*="{p}"],[id*="{p}"]' for p in BOILERPLATE_PATTERNS)
_JS_RE = re.compile(r"\b(function|var|let|const)\s*[\(=]|\bdocument\.|\bwindow\.|=>\s*\{|addEventListener")
_SENT_RE = re.compile(r"(?<=[.!?。！？])\s+")
_TOKEN_RE = re.compile(r"[A-Za-z\u00C0-\u024F']+")
_WORD_RE = re.compile(r"[A-Za-z\u00C0-\u024F]{2,}")
_ZW_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")
_WS_RE = re.compile(r"\s+")
_MULTI_SLASH_RE = re.compile(r"/{2,}")


@dataclass
class Config:
    seed: str = ""
    output_dir: Path = Path("data")
    session_zip: Path = Path("session.zip")
    chunk_mb: float = 20.0
    max_text_chars: int = 2_000_000
    max_links_per_page: int = 80
    workers: int = 350
    concurrency: int = 250
    per_domain_concurrency: int = 12
    per_domain_rps: float = 20.0
    per_domain_burst: float = 20.0
    timeout: float = 10.0
    max_depth: int = 6
    max_pages: int = 0
    max_queue: int = 200_000
    max_domains: int = 20_000
    bloom_capacity: int = 1_000_000
    bloom_error: float = 0.01
    simhash_items: int = 20_000
    protect_after: int = 3
    rate_limit_cooldown: float = 60.0
    stats_interval: float = 5.0
    log_level: str = "INFO"
    proxies: list[str] = field(default_factory=list)
    http_version: str = ""
    impersonate: str = "chrome136"
    resume: bool = True
    parse_threads: int = 24
    fsync_chunks: bool = field(default_factory=lambda: sys.platform != "win32")

    @property
    def chunk_bytes(self) -> int:
        return int(self.chunk_mb * 1024 * 1024)

    @classmethod
    def load(cls) -> "Config":
        parser = argparse.ArgumentParser(prog="scraper")
        parser.add_argument("--config", default="scraper.toml")
        parser.add_argument("--seed")
        parser.add_argument("--output")
        parser.add_argument("--session")
        parser.add_argument("--workers", type=int)
        parser.add_argument("--concurrency", type=int)
        parser.add_argument("--per-domain-concurrency", type=int)
        parser.add_argument("--per-domain-rps", type=float)
        parser.add_argument("--timeout", type=float)
        parser.add_argument("--max-depth", type=int)
        parser.add_argument("--max-pages", type=int)
        parser.add_argument("--chunk-mb", type=float)
        parser.add_argument("--stats-interval", type=float)
        parser.add_argument("--proxy", action="append")
        parser.add_argument("--http-version")
        parser.add_argument("--impersonate")
        parser.add_argument("--log-level")
        parser.add_argument("--no-resume", action="store_true")
        parser.add_argument("--no-fsync", action="store_true")
        args = parser.parse_args()

        cfg = cls()
        path = Path(args.config)
        if path.exists():
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            for key, value in data.items():
                if hasattr(cfg, key):
                    setattr(cfg, key, _coerce(value, type(getattr(cfg, key))))

        for f in fields(cls):
            env = os.getenv("SCRAPER_" + f.name.upper())
            if env is not None:
                setattr(cfg, f.name, _coerce(env, type(getattr(cfg, f.name))))

        overrides = {
            "seed": args.seed, "output_dir": args.output, "session_zip": args.session,
            "workers": args.workers, "concurrency": args.concurrency,
            "per_domain_concurrency": args.per_domain_concurrency,
            "per_domain_rps": args.per_domain_rps, "timeout": args.timeout,
            "max_depth": args.max_depth, "max_pages": args.max_pages,
            "stats_interval": args.stats_interval, "log_level": args.log_level,
            "http_version": args.http_version, "impersonate": args.impersonate,
        }
        for name, value in overrides.items():
            if value is not None:
                if name in ("output_dir", "session_zip"):
                    setattr(cfg, name, Path(value))
                else:
                    setattr(cfg, name, value)
        if args.chunk_mb is not None:
            cfg.chunk_mb = args.chunk_mb
        if args.proxy:
            cfg.proxies = args.proxy
        if args.no_resume:
            cfg.resume = False
        if args.no_fsync:
            cfg.fsync_chunks = False

        cfg.workers = max(cfg.workers, cfg.concurrency + 50)
        return cfg


def _coerce(value: object, typ: type) -> object:
    if typ is bool:
        return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    if typ is Path:
        return Path(str(value))
    if typ is int:
        return int(value)
    if typ is float:
        return float(value)
    if typ is list:
        return [str(v) for v in value] if isinstance(value, list) else [v.strip() for v in str(value).split(",") if v.strip()]
    return str(value)


@dataclass
class Stats:
    ok: int = 0
    blocked: int = 0
    failed: int = 0
    rejected: int = 0
    dedup: int = 0
    bytes_in: int = 0
    fetch_ms: float = 0.0
    parse_ms: float = 0.0
    started: float = field(default_factory=time.monotonic)
    block_reasons: Counter = field(default_factory=Counter)
    quality_reasons: Counter = field(default_factory=Counter)

    def pages(self) -> int:
        return self.ok + self.blocked + self.failed + self.rejected

    def rate(self) -> float:
        return self.pages() / max(1e-9, time.monotonic() - self.started)

    def avg_fetch(self) -> float:
        return self.fetch_ms / max(1, self.pages())

    def avg_parse(self) -> float:
        return self.parse_ms / max(1, self.ok + self.rejected)


class BloomFilter:
    def __init__(self, capacity: int, error_rate: float) -> None:
        capacity = max(1, capacity)
        error_rate = min(max(error_rate, 1e-6), 0.5)
        bits = int(-(capacity * math.log(error_rate)) / (math.log(2) ** 2))
        self.bits = max(64, bits)
        self.data = bytearray((self.bits + 7) // 8)
        self.hashes = max(1, round((self.bits / capacity) * math.log(2)))

    def _positions(self, value: bytes):
        h1 = int.from_bytes(hashlib.blake2b(value, digest_size=8).digest(), "big")
        h2 = int.from_bytes(hashlib.blake2b(value, digest_size=8, key=b"nexus").digest(), "big") | 1
        for i in range(self.hashes):
            yield (h1 + i * h2) % self.bits

    def add(self, value: bytes) -> bool:
        positions = list(self._positions(value))
        if all(self.data[p >> 3] & (1 << (p & 7)) for p in positions):
            return False
        for p in positions:
            self.data[p >> 3] |= 1 << (p & 7)
        return True


class TokenBucket:
    def __init__(self, rate: float, burst: float) -> None:
        self.rate = max(1e-6, rate)
        self.burst = max(1.0, burst)
        self.tokens = self.burst
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(wait)


@dataclass
class DomainState:
    sem: asyncio.Semaphore
    bucket: TokenBucket
    consecutive: int = 0
    protected: bool = False
    cooldown_until: float = 0.0
    active: int = 0
    last_seen: float = field(default_factory=time.monotonic)


class DomainRegistry:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self._states: "OrderedDict[str, DomainState]" = OrderedDict()

    def get(self, domain: str) -> DomainState:
        state = self._states.get(domain)
        if state is None:
            state = DomainState(
                sem=asyncio.Semaphore(self.cfg.per_domain_concurrency),
                bucket=TokenBucket(self.cfg.per_domain_rps, self.cfg.per_domain_burst),
            )
            self._states[domain] = state
            if len(self._states) > self.cfg.max_domains:
                self._evict()
        else:
            self._states.move_to_end(domain)
        state.last_seen = time.monotonic()
        return state

    def peek(self, domain: str) -> Optional[DomainState]:
        return self._states.get(domain)

    def admit(self, domain: str) -> bool:
        state = self._states.get(domain)
        if state is None:
            return True
        if state.protected:
            return False
        return state.cooldown_until <= time.monotonic()

    def mark_blocked(self, domain: str) -> None:
        self.get(domain).protected = True

    def mark_rate_limited(self, domain: str) -> None:
        self.get(domain).cooldown_until = time.monotonic() + self.cfg.rate_limit_cooldown

    def mark_failure(self, domain: str) -> None:
        state = self.get(domain)
        state.consecutive += 1
        if state.consecutive >= self.cfg.protect_after:
            state.protected = True

    def mark_success(self, domain: str) -> None:
        self.get(domain).consecutive = 0

    def protected_count(self) -> int:
        return sum(1 for state in self._states.values() if state.protected)

    def size(self) -> int:
        return len(self._states)

    def _evict(self) -> None:
        for _ in range(max(1, self.cfg.max_domains // 10)):
            if not self._states:
                return
            domain, state = self._states.popitem(last=False)
            if state.active > 0 or state.protected:
                self._states[domain] = state
                continue


class BlockClassifier:
    def classify(self, status: int, headers: dict, body: bytes) -> tuple[bool, str]:
        lower = {k.lower(): v for k, v in headers.items()}
        sample = body[:16384].lower() if body else b""
        if b"captcha-delivery.com" in sample:
            return True, "datadome"
        if b"px-captcha" in sample:
            return True, "perimeterx"
        if lower.get("cf-mitigated") == "challenge" or b"cf_chl_opt" in sample or b"/cdn-cgi/challenge-platform/" in sample:
            return True, "cloudflare"
        if status in BLOCK_STATUS:
            return True, f"http_{status}"
        if status == 429:
            return True, "rate_limit"
        if any(marker in sample for marker in CHALLENGE_MARKERS):
            return True, "challenge_body"
        return False, ""


class ProxyPool:
    def __init__(self, proxies: list[str]) -> None:
        self._proxies = list(proxies)
        self._bad: set[str] = set()
        self._index = 0

    def next(self) -> Optional[str]:
        if not self._proxies:
            return None
        for _ in range(len(self._proxies)):
            self._index = (self._index + 1) % len(self._proxies)
            proxy = self._proxies[self._index]
            if proxy not in self._bad:
                return proxy
        return None

    def mark_bad(self, proxy: str) -> None:
        self._bad.add(proxy)


@dataclass
class FetchResult:
    url: str
    content: Optional[bytes]
    status: int
    headers: dict
    blocked: bool = False
    reason: str = ""
    error: str = ""
    elapsed_ms: float = 0.0


@dataclass
class PageData:
    title: str
    text: str
    links: list[str]
    link_chars: int
    html_len: int


class PageParser:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg

    def parse(self, html: bytes, base_url: str) -> PageData:
        tree = LexborHTMLParser(html)
        title_node = tree.css_first("title")
        title = title_node.text(strip=True) if title_node else ""
        if not title:
            for selector in ("h1", "h2"):
                node = tree.css_first(selector)
                if node:
                    title = node.text(strip=True)
                    break
        title = (title or "")[:300]

        links: list[str] = []
        seen: set[str] = set()
        link_chars = 0
        for anchor in tree.css("a[href]"):
            href = anchor.attributes.get("href")
            if not href:
                continue
            href = href.strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, href)
            if absolute in seen:
                continue
            seen.add(absolute)
            links.append(absolute)
            link_chars += len(anchor.text(strip=True))
            if len(links) >= self.cfg.max_links_per_page:
                break

        for node in tree.css(_DROP_SELECTOR):
            try:
                node.decompose()
            except Exception:
                pass
        for node in tree.css(_BOILER_SELECTOR):
            try:
                node.decompose()
            except Exception:
                pass

        body = tree.body or tree.root
        if body is None:
            return PageData(title=title, text="", links=links, link_chars=link_chars, html_len=len(html))
        raw = body.text(separator=" ", strip=True) or ""
        text = _clean_text(raw)[: self.cfg.max_text_chars]
        return PageData(title=title, text=text, links=links, link_chars=link_chars, html_len=len(html))


def _clean_text(text: str) -> str:
    if _ZW_RE.search(text):
        text = _ZW_RE.sub("", text)
    return _WS_RE.sub(" ", text).strip()


def _simhash32(text: str) -> int:
    tokens = _TOKEN_RE.findall(text[:6000].lower())
    if not tokens:
        return 0
    votes = [0] * 32
    for token in set(tokens):
        h = hash(token) & 0xFFFFFFFF
        for bit in range(32):
            votes[bit] += 1 if (h >> bit) & 1 else -1
    return sum(1 << bit for bit in range(32) if votes[bit] > 0)


class SimHashIndex:
    def __init__(self, maximum: int) -> None:
        self.maximum = max(1, maximum)
        self.alive: set[int] = set()
        self.order: deque[int] = deque()
        self.bands: list[dict[int, list[int]]] = [dict() for _ in range(4)]

    def add_if_unique(self, fingerprint: int, distance: int = 2) -> bool:
        for band in range(4):
            key = (fingerprint >> (band * 8)) & 0xFF
            for other in self.bands[band].get(key, ()):
                if other in self.alive and (fingerprint ^ other).bit_count() <= distance:
                    return False
        self.alive.add(fingerprint)
        self.order.append(fingerprint)
        for band in range(4):
            key = (fingerprint >> (band * 8)) & 0xFF
            self.bands[band].setdefault(key, []).append(fingerprint)
        if len(self.order) >= self.maximum * 2:
            self._rebuild()
        return True

    def _rebuild(self) -> None:
        keep = list(self.order)[-self.maximum:]
        self.alive = set(keep)
        self.bands = [dict() for _ in range(4)]
        for fingerprint in keep:
            for band in range(4):
                key = (fingerprint >> (band * 8)) & 0xFF
                self.bands[band].setdefault(key, []).append(fingerprint)
        self.order = deque(keep)


class QualityGate:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.simhash = SimHashIndex(cfg.simhash_items)

    def accept(self, page: PageData) -> tuple[bool, str]:
        ok, reason = self._layer_one(page)
        if not ok:
            return False, reason
        ok, reason = self._layer_two(page)
        if not ok:
            return False, reason
        if not self.simhash.add_if_unique(_simhash32(page.text)):
            return False, "near_duplicate"
        return True, ""

    def _layer_one(self, page: PageData) -> tuple[bool, str]:
        text = page.text
        n = len(text)
        if n < 300:
            return False, "too_short"
        sample = text[:10000]
        alnum = sum(1 for c in sample if c.isalnum())
        if alnum / len(sample) < 0.32:
            return False, "low_alnum"
        if _JS_RE.search(sample):
            return False, "js_residue"
        if sample.count("<") > 5 or sample.count("{") > 15:
            return False, "html_residue"
        words = _WORD_RE.findall(sample)
        if len(words) < 50:
            return False, "few_words"
        if len({w.lower() for w in words}) / len(words) < 0.16:
            return False, "low_unique"
        return True, ""

    def _layer_two(self, page: PageData) -> tuple[bool, str]:
        text = page.text
        sentences = [s for s in _SENT_RE.split(text) if len(s) > 10]
        if len(sentences) < 3:
            return False, "few_sentences"
        lengths = [len(s) for s in sentences]
        avg = sum(lengths) / len(lengths)
        if not 25 <= avg <= 350:
            return False, "sentence_length"
        tokens = _TOKEN_RE.findall(text.lower())
        if not tokens:
            return False, "no_tokens"
        stop_ratio = sum(1 for t in tokens if t in STOP) / len(tokens)
        if not 0.06 <= stop_ratio <= 0.45:
            return False, "stop_ratio"
        if page.link_chars / max(1, len(text)) > 0.25:
            return False, "link_density"
        if page.html_len and len(text) / page.html_len < 0.02:
            return False, "text_html_ratio"
        return True, ""


class Frontier:
    def __init__(self, cfg: Config, registry: DomainRegistry, stats: Stats) -> None:
        self.cfg = cfg
        self.registry = registry
        self.stats = stats
        self.bloom = BloomFilter(cfg.bloom_capacity, cfg.bloom_error)
        self.heap: list[tuple[int, int, str, int]] = []
        self.sequence = 0
        self.outstanding = 0
        self.closed = False
        self.condition = asyncio.Condition()
        self.tail: deque[str] = deque(maxlen=5)

    def _normalize(self, url: str) -> Optional[str]:
        try:
            parsed = urlparse(url.strip())
        except ValueError:
            return None
        if parsed.scheme not in ("http", "https"):
            return None
        host = (parsed.hostname or "").lower()
        if not host or "." not in host:
            return None
        if host.startswith("www."):
            host = host[4:]
        port = parsed.port
        if port and port not in (80, 443):
            host = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        path = _MULTI_SLASH_RE.sub("/", parsed.path) or "/"
        lower_path = path.lower()
        if any(lower_path.endswith(extension) for extension in SKIP_EXT):
            return None
        if any(lower_path.startswith(prefix) for prefix in SKIP_PATH):
            return None
        query_pairs = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=False)
            if key.lower() not in TRACKING_PARAMS
        ]
        query = urlencode(sorted(query_pairs))
        return urlunparse((parsed.scheme, host, path, "", query, ""))

    def _domain(self, url: str) -> str:
        return (urlparse(url).hostname or "").lower()

    def _priority(self, url: str, depth: int) -> int:
        parsed = urlparse(url)
        path = parsed.path.lower()
        score = depth * 10
        if any(key in path for key in ("article", "news", "blog", "post", "story", "docs", "wiki", "guide")):
            score -= 6
        if any(key in path for key in ("tag", "category", "archive", "page/", "?page=")):
            score += 4
        if len(path) > 100:
            score += 3
        if parsed.query:
            score += 2
        state = self.registry.peek(self._domain(url))
        if state:
            score += min(state.consecutive * 4, 40)
        return score

    async def push_many(self, urls: list[str], depth: int) -> int:
        if self.closed:
            return 0
        prepared: list[tuple[int, str, int]] = []
        for url in urls:
            normalized = self._normalize(url)
            if not normalized:
                continue
            domain = self._domain(normalized)
            if not self.registry.admit(domain):
                continue
            if not self.bloom.add(normalized.encode("utf-8")):
                self.stats.dedup += 1
                continue
            prepared.append((self._priority(normalized, depth), normalized, depth))
        if not prepared:
            return 0
        async with self.condition:
            pushed = 0
            for priority, normalized, d in prepared:
                if len(self.heap) >= self.cfg.max_queue:
                    break
                self.outstanding += 1
                self.sequence += 1
                heapq.heappush(self.heap, (priority, self.sequence, normalized, d))
                self.tail.append(normalized)
                pushed += 1
            if pushed:
                self.condition.notify(pushed)
        return pushed

    async def pop(self) -> Optional[tuple[int, int, str, int]]:
        async with self.condition:
            while True:
                if self.closed:
                    return None
                if self.heap:
                    return heapq.heappop(self.heap)
                await self.condition.wait()

    async def done(self) -> None:
        async with self.condition:
            self.outstanding = max(0, self.outstanding - 1)
            if self.outstanding == 0:
                self.condition.notify_all()

    async def join(self) -> None:
        async with self.condition:
            while self.outstanding > 0:
                await self.condition.wait()

    async def close(self) -> None:
        async with self.condition:
            self.closed = True
            dropped = len(self.heap)
            self.outstanding = max(0, self.outstanding - dropped)
            self.heap.clear()
            self.condition.notify_all()

    def qsize(self) -> int:
        return len(self.heap)


class ChunkWriter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.dir = cfg.output_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        for stale in self.dir.glob("*.tmp"):
            try:
                stale.unlink()
            except OSError:
                pass
        self.chunk_limit = cfg.chunk_bytes
        self.index = 0
        self.records = 0
        self.bytes_written = 0
        self._fd = -1
        self._path: Optional[Path] = None
        self._tmp_path: Optional[Path] = None
        self._file_bytes = 0
        self._record_count = 0
        self._open()

    def _advise(self, fd: int, advice: int) -> None:
        if _posix_fadvise is None:
            return
        try:
            _posix_fadvise(fd, 0, 0, advice)
        except OSError:
            pass

    def _open(self) -> None:
        path = self.dir / f"chunk_{self.index:05d}.json"
        tmp_path = self.dir / f"chunk_{self.index:05d}.json.tmp"
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _OPEN_FLAGS, 0o644)
        self._advise(fd, POSIX_FADV_SEQUENTIAL)
        os.write(fd, b"[")
        self._fd = fd
        self._path = path
        self._tmp_path = tmp_path
        self._file_bytes = 1
        self._record_count = 0

    def add(self, title: str, text: str) -> None:
        record = {"title": title[:300], "text": text}
        blob = _dumps(record)
        sep = b"," if self._record_count else b""
        record_bytes = len(sep) + len(blob)
        if self._file_bytes + record_bytes + 1 > self.chunk_limit:
            self._finalize()
            self._open()
            sep = b""
            record_bytes = len(blob)
            if self._file_bytes + record_bytes + 1 > self.chunk_limit:
                log.warning("record_exceeds_chunk_size bytes=%d", record_bytes)
                return
        if sep:
            os.write(self._fd, sep)
        os.write(self._fd, blob)
        self._file_bytes += record_bytes
        self._record_count += 1
        self.records += 1
        self.bytes_written += record_bytes

    def _finalize(self) -> None:
        if self._fd < 0:
            return
        if self._record_count == 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            try:
                os.unlink(self._tmp_path)
            except OSError:
                pass
            self._fd = -1
            return
        try:
            os.write(self._fd, b"]")
            if self.cfg.fsync_chunks:
                try:
                    os.fsync(self._fd)
                except OSError as exc:
                    log.warning("chunk_fsync_failed path=%s err=%s", self._path, exc)
            self._advise(self._fd, POSIX_FADV_DONTNEED)
        except OSError as exc:
            log.warning("chunk_write_close_failed path=%s err=%s", self._path, exc)
        finally:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1
        try:
            os.replace(self._tmp_path, self._path)
        except OSError as exc:
            log.warning("chunk_rename_failed path=%s err=%s", self._path, exc)
            return
        self.index += 1

    def close(self) -> None:
        self._finalize()


class Fetcher:
    def __init__(self, cfg: Config, classifier: BlockClassifier) -> None:
        self.cfg = cfg
        self.classifier = classifier
        self.session = AsyncSession(max_clients=cfg.concurrency, default_headers=True)
        self.impersonate = cfg.impersonate
        self.proxies = ProxyPool(cfg.proxies)

    async def close(self) -> None:
        try:
            await self.session.close()
        except Exception:
            pass

    async def fetch(self, url: str, state: DomainState) -> FetchResult:
        await state.bucket.acquire()
        async with state.sem:
            state.active += 1
            started = time.monotonic()
            proxy = self.proxies.next()
            kwargs = {
                "impersonate": self.impersonate,
                "timeout": self.cfg.timeout,
                "allow_redirects": True,
                "max_redirects": 5,
                "default_headers": True,
            }
            if proxy:
                kwargs["proxies"] = {"http": proxy, "https": proxy}
            if self.cfg.http_version:
                kwargs["http_version"] = self.cfg.http_version
            try:
                response = await asyncio.wait_for(
                    self.session.get(url, **kwargs),
                    timeout=self.cfg.timeout + 2.0,
                )
                status = response.status_code
                body = response.content or b""
                headers = dict(response.headers)
                elapsed = (time.monotonic() - started) * 1000
                blocked, reason = self.classifier.classify(status, headers, body)
                if blocked:
                    return FetchResult(url, None, status, headers, blocked=True, reason=reason, elapsed_ms=elapsed)
                if status >= 400:
                    return FetchResult(url, None, status, headers, error=f"http_{status}", elapsed_ms=elapsed)
                if len(body) < 200:
                    return FetchResult(url, None, status, headers, error="tiny_body", elapsed_ms=elapsed)
                return FetchResult(url, body, status, headers, elapsed_ms=elapsed)
            except asyncio.TimeoutError:
                return FetchResult(url, None, 0, {}, error="hard_timeout", elapsed_ms=(time.monotonic() - started) * 1000)
            except _ImpersonateError:
                return FetchResult(url, None, 0, {}, error="impersonate", elapsed_ms=(time.monotonic() - started) * 1000)
            except _CurlRequestError as exc:
                return FetchResult(url, None, 0, {}, error=type(exc).__name__, elapsed_ms=(time.monotonic() - started) * 1000)
            except Exception as exc:
                return FetchResult(url, None, 0, {}, error=type(exc).__name__, elapsed_ms=(time.monotonic() - started) * 1000)
            finally:
                state.active -= 1


class Scraper:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.stats = Stats()
        self.classifier = BlockClassifier()
        self.parser = PageParser(cfg)
        self.quality = QualityGate(cfg)
        self.registry = DomainRegistry(cfg)
        self.frontier = Frontier(cfg, self.registry, self.stats)
        self.writer = ChunkWriter(cfg)
        self.fetcher = Fetcher(cfg, self.classifier)

    async def run(self, seeds: list[str]) -> None:
        await self.frontier.push_many(seeds, 0)
        workers = [asyncio.create_task(self._worker()) for _ in range(self.cfg.workers)]
        stats_task = asyncio.create_task(self._stats_loop())
        try:
            await self.frontier.join()
        except asyncio.CancelledError:
            pass
        finally:
            await self.frontier.close()
            await asyncio.gather(*workers, return_exceptions=True)
            stats_task.cancel()
            try:
                await stats_task
            except (asyncio.CancelledError, Exception):
                pass
            self.writer.close()
            self._save_session()
            await self.fetcher.close()

    async def _worker(self) -> None:
        while True:
            item = await self.frontier.pop()
            if item is None:
                return
            _, _, url, depth = item
            try:
                await self._process(url, depth)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.stats.failed += 1
                log.debug("process_error %s %s", url, type(exc).__name__)
            finally:
                await self.frontier.done()

    def _parse_and_gate(self, content: bytes, url: str) -> tuple[PageData, bool, str]:
        page = self.parser.parse(content, url)
        ok, reason = self.quality.accept(page)
        return page, ok, reason

    async def _process(self, url: str, depth: int) -> None:
        domain = (urlparse(url).hostname or "").lower()
        state = self.registry.get(domain)
        if state.protected:
            self.stats.blocked += 1
            self.stats.block_reasons["protected"] += 1
            return
        result = await self.fetcher.fetch(url, state)
        self.stats.fetch_ms += result.elapsed_ms
        if result.blocked:
            if result.reason == "rate_limit":
                self.registry.mark_rate_limited(domain)
            else:
                self.registry.mark_blocked(domain)
            self.stats.blocked += 1
            self.stats.block_reasons[result.reason] += 1
            return
        if not result.content:
            if result.error in ("hard_timeout", "impersonate", "tiny_body") or (result.status and result.status >= 500):
                self.registry.mark_failure(domain)
            else:
                self.registry.mark_success(domain)
            self.stats.failed += 1
            return
        self.registry.mark_success(domain)
        self.stats.bytes_in += len(result.content)
        started = time.monotonic()
        page, accepted, reason = await asyncio.to_thread(self._parse_and_gate, result.content, url)
        self.stats.parse_ms += (time.monotonic() - started) * 1000
        if accepted:
            self.writer.add(page.title, page.text)
            self.stats.ok += 1
            await self.frontier.push_many(page.links, depth + 1)
        else:
            self.stats.rejected += 1
            self.stats.quality_reasons[reason] += 1
        if self.cfg.max_pages and self.stats.pages() >= self.cfg.max_pages:
            await self.frontier.close()

    async def _stats_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.cfg.stats_interval)
                log.info(
                    "ok=%d blocked=%d failed=%d rejected=%d dedup=%d queue=%d domains=%d protected=%d "
                    "chunks=%d records=%d rate=%.1f/s in=%.1fMB out=%.1fMB fetch=%.0fms parse=%.0fms",
                    self.stats.ok, self.stats.blocked, self.stats.failed, self.stats.rejected,
                    self.stats.dedup, self.frontier.qsize(), self.registry.size(),
                    self.registry.protected_count(),
                    self.writer.index, self.writer.records,
                    self.stats.rate(),
                    self.stats.bytes_in / 1_048_576,
                    self.writer.bytes_written / 1_048_576,
                    self.stats.avg_fetch(), self.stats.avg_parse(),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("stats_error")

    def _save_session(self) -> None:
        urls = list(self.frontier.tail)
        if not urls:
            return
        temporary = self.cfg.session_zip.with_suffix(".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("frontier.txt", "\n".join(urls))
            archive.writestr("meta.json", _dumps({"ts": time.time(), "version": 6}).decode("utf-8"))
        os.replace(temporary, self.cfg.session_zip)


def load_session(path: Path) -> list[str]:
    if not path.exists():
        return []
    try:
        with zipfile.ZipFile(path) as archive:
            if "frontier.txt" not in archive.namelist():
                return []
            text = archive.read("frontier.txt").decode("utf-8", errors="ignore")
            return [line.strip() for line in text.splitlines() if line.strip()][:5]
    except Exception:
        return []


async def main() -> None:
    cfg = Config.load()
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=cfg.parse_threads, thread_name_prefix="parse"))

    seeds = load_session(cfg.session_zip) if cfg.resume else []
    if seeds:
        log.info("resuming from %d queued URLs", len(seeds))
    elif cfg.seed:
        seeds = [cfg.seed]
    else:
        try:
            raw = input("start url: ").strip()
        except EOFError:
            raw = ""
        if not raw:
            print("no seed")
            return
        seeds = [raw]

    scraper = Scraper(cfg)
    shutdown_tasks: list[asyncio.Task] = []

    def _shutdown() -> None:
        shutdown_tasks.append(asyncio.create_task(scraper.frontier.close()))

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError, AttributeError):
            pass

    try:
        await scraper.run(seeds)
    finally:
        s = scraper.stats
        log.info(
            "final ok=%d blocked=%d failed=%d rejected=%d dedup=%d chunks=%d records=%d rate=%.1f/s in=%.1fMB out=%.1fMB",
            s.ok, s.blocked, s.failed, s.rejected, s.dedup,
            scraper.writer.index, scraper.writer.records, s.rate(),
            s.bytes_in / 1_048_576,
            scraper.writer.bytes_written / 1_048_576,
        )
        log.info("block_reasons=%s", dict(s.block_reasons.most_common(10)))
        log.info("quality_reasons=%s", dict(s.quality_reasons.most_common(12)))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass