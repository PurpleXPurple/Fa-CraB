from __future__ import annotations

import argparse
import asyncio
import hashlib
import heapq
import json
import logging
import math
import os
import random
import re
import signal
import time
import unicodedata
import zipfile
from collections import Counter, OrderedDict, deque
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

_Timeout = getattr(curl_exc, "Timeout", asyncio.TimeoutError)
_ProxyError = getattr(curl_exc, "ProxyError", type("_NeverProxy", (Exception,), {}))
_ImpersonateError = getattr(curl_exc, "ImpersonateError", type("_NeverImpersonate", (Exception,), {}))
_CurlRequestError = curl_exc.RequestException

BLOCK_STATUS = {401, 403, 407, 429, 451, 503}
CHALLENGE_MARKERS = (
    b"just a moment", b"cf-chl", b"attention required", b"access denied",
    b"enable javascript and cookies", b"px-captcha", b"checking your browser",
    b"verify you are human", b"request blocked",
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

PROFILES = (
    {
        "impersonate": "chrome",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "platform": '"Windows"',
    },
    {
        "impersonate": "chrome131",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "ch_ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "platform": '"macOS"',
    },
    {
        "impersonate": "safari",
        "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        "ch_ua": '"Safari";v="18", "Not_A Brand";v="99"',
        "platform": '"macOS"',
    },
    {
        "impersonate": "firefox",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
        "ch_ua": '"Firefox";v="133", "Not_A Brand";v="99"',
        "platform": '"Windows"',
    },
)
REFERERS = (
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://news.ycombinator.com/",
    "https://www.reddit.com/",
)
LANGUAGES = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.6",
    "en-US,en;q=0.9,de;q=0.5",
)


@dataclass
class Config:
    seed: str = ""
    output_dir: Path = Path("data")
    session_zip: Path = Path("session.zip")
    chunk_bytes: int = 20 * 1024 * 1024
    max_body_bytes: int = 8 * 1024 * 1024
    max_text_chars: int = 2_000_000
    max_links_per_page: int = 300
    workers: int = 400
    concurrency: int = 300
    min_concurrency: int = 32
    max_concurrency: int = 600
    per_domain_concurrency: int = 8
    per_domain_rps: float = 12.0
    per_domain_burst: float = 24.0
    timeout: float = 12.0
    retries: int = 2
    max_depth: int = 6
    max_pages: int = 0
    max_queue: int = 500_000
    max_domains: int = 50_000
    bloom_capacity: int = 2_000_000
    bloom_error: float = 0.01
    simhash_items: int = 30_000
    failure_cooldown: float = 30.0
    protect_after: int = 6
    stats_interval: float = 5.0
    log_level: str = "INFO"
    proxies: list[str] = field(default_factory=list)
    http_version: str = ""
    resume: bool = True

    @classmethod
    def load(cls) -> "Config":
        parser = argparse.ArgumentParser(prog="scraper")
        parser.add_argument("--config", default="scraper.toml")
        parser.add_argument("--seed")
        parser.add_argument("--output")
        parser.add_argument("--session")
        parser.add_argument("--workers", type=int)
        parser.add_argument("--concurrency", type=int)
        parser.add_argument("--min-concurrency", type=int)
        parser.add_argument("--max-concurrency", type=int)
        parser.add_argument("--per-domain-concurrency", type=int)
        parser.add_argument("--per-domain-rps", type=float)
        parser.add_argument("--per-domain-burst", type=float)
        parser.add_argument("--timeout", type=float)
        parser.add_argument("--retries", type=int)
        parser.add_argument("--max-depth", type=int)
        parser.add_argument("--max-pages", type=int)
        parser.add_argument("--chunk-mb", type=float)
        parser.add_argument("--stats-interval", type=float)
        parser.add_argument("--bloom-capacity", type=int)
        parser.add_argument("--proxy", action="append")
        parser.add_argument("--http-version")
        parser.add_argument("--log-level")
        parser.add_argument("--no-resume", action="store_true")
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
            "min_concurrency": args.min_concurrency, "max_concurrency": args.max_concurrency,
            "per_domain_concurrency": args.per_domain_concurrency,
            "per_domain_rps": args.per_domain_rps, "per_domain_burst": args.per_domain_burst,
            "timeout": args.timeout, "retries": args.retries, "max_depth": args.max_depth,
            "max_pages": args.max_pages, "stats_interval": args.stats_interval,
            "bloom_capacity": args.bloom_capacity, "log_level": args.log_level,
            "http_version": args.http_version,
        }
        for name, value in overrides.items():
            if value is not None:
                if name in ("output_dir", "session_zip"):
                    setattr(cfg, name, Path(value))
                else:
                    setattr(cfg, name, value)
        if args.chunk_mb is not None:
            cfg.chunk_bytes = int(args.chunk_mb * 1024 * 1024)
        if args.proxy:
            cfg.proxies = args.proxy
        if args.no_resume:
            cfg.resume = False

        cfg.workers = max(cfg.workers, cfg.concurrency)
        cfg.concurrency = max(cfg.min_concurrency, min(cfg.concurrency, cfg.max_concurrency))
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
    started: float = field(default_factory=time.monotonic)

    def processed(self) -> int:
        return self.ok + self.blocked + self.failed + self.rejected

    def rate(self) -> float:
        return self.processed() / max(1e-9, time.monotonic() - self.started)


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


class AdaptiveLimiter:
    def __init__(self, initial: int, minimum: int, maximum: int) -> None:
        self.limit = max(minimum, min(initial, maximum))
        self.minimum = minimum
        self.maximum = maximum
        self.active = 0
        self.successes = 0
        self.waiters: list[asyncio.Event] = []

    async def acquire(self) -> None:
        while True:
            if self.active < self.limit:
                self.active += 1
                return
            event = asyncio.Event()
            self.waiters.append(event)
            await event.wait()

    def release(self, healthy: bool) -> None:
        self.active = max(0, self.active - 1)
        if healthy:
            self.successes += 1
            if self.successes >= 64 and self.limit < self.maximum:
                self.limit += 1
                self.successes = 0
        else:
            self.limit = max(self.minimum, self.limit // 2)
            self.successes = 0
        if self.waiters and self.active < self.limit:
            self.waiters.pop(0).set()


@dataclass
class DomainState:
    sem: asyncio.Semaphore
    bucket: TokenBucket
    failures: int = 0
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

    def mark_failure(self, domain: str) -> None:
        state = self.get(domain)
        state.failures += 1
        state.consecutive += 1
        if state.consecutive >= 3:
            state.cooldown_until = time.monotonic() + min(300.0, self.cfg.failure_cooldown * (2 ** (state.consecutive - 3)))
        if state.failures >= self.cfg.protect_after:
            state.protected = True

    def mark_success(self, domain: str) -> None:
        state = self.get(domain)
        state.consecutive = 0

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


class SpoofEngine:
    def profile(self) -> dict:
        return random.choice(PROFILES)

    def headers(self, profile: dict) -> dict:
        pairs = [
            ("User-Agent", profile["ua"]),
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
            ("Accept-Language", random.choice(LANGUAGES)),
            ("Accept-Encoding", "gzip, deflate, br"),
            ("Sec-CH-UA", profile["ch_ua"]),
            ("Sec-CH-UA-Platform", profile["platform"]),
            ("Sec-CH-UA-Mobile", "?0"),
            ("Sec-Fetch-Site", random.choice(("none", "same-origin", "cross-site"))),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-User", "?1"),
            ("Upgrade-Insecure-Requests", "1"),
            ("Referer", random.choice(REFERERS)),
            ("Cache-Control", random.choice(("no-cache", "max-age=0"))),
            ("DNT", "1"),
        ]
        random.shuffle(pairs)
        return dict(pairs)

    def jitter(self, attempt: int) -> float:
        return min(1.5, random.uniform(0.01, 0.08) * (2 ** attempt))


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
    content_type: str = ""
    blocked: bool = False
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
        link_chars = 0
        for anchor in tree.css("a[href]"):
            href = anchor.attributes.get("href")
            if not href:
                continue
            href = href.strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, href)
            links.append(absolute)
            link_chars += len(anchor.text(strip=True))
            if len(links) >= self.cfg.max_links_per_page:
                break

        for tag in DROP_TAGS:
            for node in tree.css(tag):
                try:
                    node.decompose()
                except Exception:
                    pass

        for pattern in BOILERPLATE_PATTERNS:
            selector = f'[class*="{pattern}"],[id*="{pattern}"]'
            for node in tree.css(selector):
                try:
                    node.decompose()
                except Exception:
                    pass

        body = tree.body or tree.root
        raw = body.text(separator=" ", strip=True) if body else ""
        text = clean_text(raw)[: self.cfg.max_text_chars]
        return PageData(title=title, text=text, links=links, link_chars=link_chars, html_len=len(html))


def clean_text(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = re.sub(r"[\u200b-\u200f\u202a-\u202e\ufeff]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def simhash64(text: str) -> int:
    tokens = re.findall(r"[a-z0-9']+", text.lower())[:2000]
    if not tokens:
        return 0
    unique = list(dict.fromkeys(tokens))[:300]
    votes = [0] * 64
    for token in unique:
        value = int.from_bytes(hashlib.blake2b(token.encode("utf-8"), digest_size=8).digest(), "big")
        for bit in range(64):
            votes[bit] += 1 if (value >> bit) & 1 else -1
    return sum(1 << bit for bit in range(64) if votes[bit] > 0)


class SimHashIndex:
    def __init__(self, maximum: int) -> None:
        self.maximum = max(1, maximum)
        self.alive: set[int] = set()
        self.order: deque[int] = deque()
        self.bands: list[dict[int, list[int]]] = [dict() for _ in range(4)]

    def add_if_unique(self, fingerprint: int, distance: int = 3) -> bool:
        for band in range(4):
            key = (fingerprint >> (band * 16)) & 0xFFFF
            for other in self.bands[band].get(key, ()):
                if other in self.alive and (fingerprint ^ other).bit_count() <= distance:
                    return False
        self.alive.add(fingerprint)
        self.order.append(fingerprint)
        for band in range(4):
            key = (fingerprint >> (band * 16)) & 0xFFFF
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
                key = (fingerprint >> (band * 16)) & 0xFFFF
                self.bands[band].setdefault(key, []).append(fingerprint)
        self.order = deque(keep)


class QualityGate:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.simhash = SimHashIndex(cfg.simhash_items)
        self.reasons: Counter = Counter()

    def accept(self, page: PageData) -> bool:
        ok, reason = self._layer_one(page)
        if not ok:
            self.reasons[reason] += 1
            return False
        ok, reason = self._layer_two(page)
        if not ok:
            self.reasons[reason] += 1
            return False
        fingerprint = simhash64(page.text)
        if not self.simhash.add_if_unique(fingerprint):
            self.reasons["near_duplicate"] += 1
            return False
        return True

    def _layer_one(self, page: PageData):
        text = page.text
        size = len(text)
        if size < 250:
            return False, "too_short"
        if size > self.cfg.max_text_chars:
            return False, "too_long"
        sample = text[:12000]
        alnum = sum(1 for char in sample if char.isalnum())
        if alnum / max(1, len(sample)) < 0.30:
            return False, "low_alnum"
        words = re.findall(r"[A-Za-z\u00C0-\u024F]{2,}", sample)
        if len(words) < 40:
            return False, "few_words"
        if len({word.lower() for word in words}) / len(words) < 0.15:
            return False, "low_unique"
        if re.search(r"\b(function|var|let|const)\s*[\(=]|\bdocument\.|\bwindow\.|=>\s*\{|addEventListener", sample):
            return False, "js_residue"
        if sample.count("<") > 5 or sample.count("{") > 20:
            return False, "html_residue"
        digits = sum(1 for char in sample if char.isdigit())
        if digits / max(1, len(sample)) > 0.35:
            return False, "digit_heavy"
        letters = sum(1 for char in sample if char.isalpha())
        upper = sum(1 for char in sample if char.isupper())
        if letters and upper / letters > 0.45:
            return False, "upper_heavy"
        return True, ""

    def _layer_two(self, page: PageData):
        text = page.text
        sentences = [part for part in re.split(r"(?<=[.!?。！？])\s+", text) if len(part.strip()) > 10]
        if len(sentences) < 3:
            return False, "few_sentences"
        lengths = [len(sentence) for sentence in sentences]
        average = sum(lengths) / len(lengths)
        if not 20 <= average <= 400:
            return False, "sentence_length"
        if max(lengths) > 4000:
            return False, "long_sentence"
        tokens = re.findall(r"[A-Za-z\u00C0-\u024F']+", text.lower())
        if not tokens:
            return False, "no_tokens"
        stop_ratio = sum(1 for token in tokens if token in STOP) / len(tokens)
        if not 0.05 <= stop_ratio <= 0.50:
            return False, "stop_ratio"
        if page.link_chars / max(1, len(text)) > 0.20:
            return False, "link_density"
        if page.html_len and len(text) / page.html_len < 0.015:
            return False, "text_html_ratio"
        grams = [" ".join(tokens[index:index + 5]) for index in range(0, min(len(tokens) - 5, 2000))]
        if grams and 1 - len(set(grams)) / len(grams) > 0.35:
            return False, "repetition"
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
        path = re.sub(r"/{2,}", "/", parsed.path) or "/"
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
            score += min(state.failures * 4, 40)
        return score

    async def push(self, url: str, depth: int) -> bool:
        if self.closed:
            return False
        normalized = self._normalize(url)
        if not normalized:
            return False
        domain = self._domain(normalized)
        if not self.registry.admit(domain):
            return False
        if len(self.heap) >= self.cfg.max_queue:
            return False
        if not self.bloom.add(normalized.encode("utf-8")):
            self.stats.dedup += 1
            return False
        priority = self._priority(normalized, depth)
        async with self.condition:
            self.outstanding += 1
            self.sequence += 1
            heapq.heappush(self.heap, (priority, self.sequence, normalized, depth))
            self.tail.append(normalized)
            self.condition.notify()
        return True

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
            self.heap.clear()
            self.condition.notify_all()

    def qsize(self) -> int:
        return len(self.heap)


class ChunkWriter:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.output = cfg.output_dir
        self.output.mkdir(parents=True, exist_ok=True)
        for stale in self.output.glob("*.tmp"):
            try:
                stale.unlink()
            except OSError:
                pass
        self.buffer: list[dict] = []
        self.buffer_bytes = 0
        self.index = 0
        self.records = 0

    def add(self, title: str, text: str) -> None:
        record = {"title": title[:500], "text": text}
        size = len(_dumps(record))
        if self.buffer and self.buffer_bytes + size > self.cfg.chunk_bytes:
            self.flush()
        self.buffer.append(record)
        self.buffer_bytes += size
        self.records += 1

    def flush(self) -> None:
        if not self.buffer:
            return
        target = self.output / f"chunk_{self.index:05d}.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_bytes(_dumps(self.buffer))
        os.replace(temporary, target)
        self.buffer.clear()
        self.buffer_bytes = 0
        self.index += 1


class Fetcher:
    def __init__(self, cfg: Config, spoof: SpoofEngine) -> None:
        self.cfg = cfg
        self.spoof = spoof
        self.session = AsyncSession(max_clients=cfg.max_concurrency)
        self.limiter = AdaptiveLimiter(cfg.concurrency, cfg.min_concurrency, cfg.max_concurrency)
        self.proxies = ProxyPool(cfg.proxies)

    async def close(self) -> None:
        try:
            await self.session.close()
        except Exception:
            pass

    def _is_blocked(self, status: int, body: bytes) -> bool:
        if status in BLOCK_STATUS:
            return True
        if len(body) > 30000:
            return False
        sample = body[:8192].lower()
        return any(marker in sample for marker in CHALLENGE_MARKERS)

    async def fetch(self, url: str, state: DomainState) -> FetchResult:
        await state.bucket.acquire()
        async with state.sem:
            state.active += 1
            limiter_acquired = False
            healthy = False
            started = time.monotonic()
            try:
                await self.limiter.acquire()
                limiter_acquired = True
                for attempt in range(self.cfg.retries + 1):
                    profile = self.spoof.profile()
                    headers = self.spoof.headers(profile)
                    proxy = self.proxies.next()
                    kwargs = {
                        "headers": headers,
                        "impersonate": profile["impersonate"],
                        "timeout": self.cfg.timeout,
                        "allow_redirects": True,
                        "max_redirects": 5,
                    }
                    if proxy:
                        kwargs["proxies"] = {"http": proxy, "https": proxy}
                    if self.cfg.http_version:
                        kwargs["http_version"] = self.cfg.http_version
                    try:
                        response = await self.session.get(url, **kwargs)
                        status = response.status_code
                        body = response.content or b""
                        response_headers = dict(response.headers)
                        content_type = response_headers.get("content-type", "").split(";")[0].strip().lower()
                        elapsed = (time.monotonic() - started) * 1000
                        if self._is_blocked(status, body):
                            return FetchResult(url, None, status, response_headers, content_type, blocked=True, elapsed_ms=elapsed)
                        if status >= 500:
                            if attempt < self.cfg.retries:
                                await asyncio.sleep(self.spoof.jitter(attempt))
                                continue
                            return FetchResult(url, None, status, response_headers, content_type, error=f"http_{status}", elapsed_ms=elapsed)
                        if status >= 400:
                            healthy = True
                            return FetchResult(url, None, status, response_headers, content_type, error=f"http_{status}", elapsed_ms=elapsed)
                        if len(body) < 200:
                            return FetchResult(url, None, status, response_headers, content_type, error="tiny_body", elapsed_ms=elapsed)
                        if len(body) > self.cfg.max_body_bytes:
                            return FetchResult(url, None, status, response_headers, content_type, error="too_large", elapsed_ms=elapsed)
                        healthy = True
                        return FetchResult(url, body, status, response_headers, content_type, elapsed_ms=elapsed)
                    except _ImpersonateError:
                        if attempt < self.cfg.retries:
                            continue
                        return FetchResult(url, None, 0, {}, error="impersonate", elapsed_ms=(time.monotonic() - started) * 1000)
                    except (_Timeout, asyncio.TimeoutError):
                        if attempt < self.cfg.retries:
                            await asyncio.sleep(self.spoof.jitter(attempt))
                            continue
                        return FetchResult(url, None, 0, {}, error="timeout", elapsed_ms=(time.monotonic() - started) * 1000)
                    except _ProxyError as exc:
                        if proxy:
                            self.proxies.mark_bad(proxy)
                        if attempt < self.cfg.retries:
                            continue
                        return FetchResult(url, None, 0, {}, error=type(exc).__name__, elapsed_ms=(time.monotonic() - started) * 1000)
                    except _CurlRequestError as exc:
                        if attempt < self.cfg.retries:
                            await asyncio.sleep(self.spoof.jitter(attempt))
                            continue
                        return FetchResult(url, None, 0, {}, error=type(exc).__name__, elapsed_ms=(time.monotonic() - started) * 1000)
                    except OSError as exc:
                        if attempt < self.cfg.retries:
                            await asyncio.sleep(self.spoof.jitter(attempt))
                            continue
                        return FetchResult(url, None, 0, {}, error=f"os_{type(exc).__name__}", elapsed_ms=(time.monotonic() - started) * 1000)
                    except Exception as exc:
                        if attempt < self.cfg.retries:
                            await asyncio.sleep(self.spoof.jitter(attempt))
                            continue
                        return FetchResult(url, None, 0, {}, error=f"unknown_{type(exc).__name__}", elapsed_ms=(time.monotonic() - started) * 1000)
                return FetchResult(url, None, 0, {}, error="retries_exhausted", elapsed_ms=(time.monotonic() - started) * 1000)
            finally:
                if limiter_acquired:
                    self.limiter.release(healthy)
                state.active -= 1


class Scraper:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.stats = Stats()
        self.spoof = SpoofEngine()
        self.parser = PageParser(cfg)
        self.quality = QualityGate(cfg)
        self.registry = DomainRegistry(cfg)
        self.frontier = Frontier(cfg, self.registry, self.stats)
        self.writer = ChunkWriter(cfg)
        self.fetcher = Fetcher(cfg, self.spoof)

    async def run(self, seeds: list[str]) -> None:
        for seed in seeds:
            await self.frontier.push(seed, 0)
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
            self.writer.flush()
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

    async def _process(self, url: str, depth: int) -> None:
        domain = (urlparse(url).hostname or "").lower()
        state = self.registry.get(domain)
        if state.protected:
            self.stats.blocked += 1
            return
        result = await self.fetcher.fetch(url, state)
        if result.blocked:
            self.registry.mark_blocked(domain)
            self.stats.blocked += 1
            return
        if not result.content:
            if result.status == 0 or result.status >= 500:
                self.registry.mark_failure(domain)
            else:
                self.registry.mark_success(domain)
            self.stats.failed += 1
            return
        if result.content_type and not any(value in result.content_type for value in CONTENT_TYPES):
            self.registry.mark_success(domain)
            self.stats.rejected += 1
            return
        self.registry.mark_success(domain)
        self.stats.bytes_in += len(result.content)
        page = self.parser.parse(result.content, url)
        if self.quality.accept(page):
            self.writer.add(page.title, page.text)
            self.stats.ok += 1
        else:
            self.stats.rejected += 1
        for link in page.links:
            await self.frontier.push(link, depth + 1)
        if self.cfg.max_pages and self.stats.processed() >= self.cfg.max_pages:
            await self.frontier.close()

    async def _stats_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.cfg.stats_interval)
                log.info(
                    "ok=%d blocked=%d failed=%d rejected=%d dedup=%d queue=%d domains=%d chunks=%d records=%d rate=%.1f/s mb=%.1f",
                    self.stats.ok, self.stats.blocked, self.stats.failed, self.stats.rejected,
                    self.stats.dedup, self.frontier.qsize(), self.registry.size(),
                    self.writer.index, self.writer.records, self.stats.rate(),
                    self.stats.bytes_in / 1_048_576,
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
            archive.writestr("meta.json", _dumps({"ts": time.time(), "version": 3}).decode("utf-8"))
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

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await scraper.run(seeds)
    finally:
        s = scraper.stats
        log.info(
            "final ok=%d blocked=%d failed=%d rejected=%d dedup=%d chunks=%d records=%d rate=%.1f/s",
            s.ok, s.blocked, s.failed, s.rejected, s.dedup,
            scraper.writer.index, scraper.writer.records, s.rate(),
        )
        log.info("quality_rejections=%s", dict(scraper.quality.reasons.most_common(12)))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass