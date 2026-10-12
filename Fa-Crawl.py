"""
Fa-Crawl — Fa-Crab's async orchestration engine.

Public API:
    from Fa_Crawl import CrawlController, get_crawler

    ctl = get_crawler()
    await ctl.start(seeds=["https://example.com"], overrides={...})

Integrates with:
    Fa_Manager   — config, state, dedup, output, errors, warnings, links,
                   cache, optimizer, loader, checkpoint, frontier.
    Fa_Scraper   — extraction engine (optional; falls back to a stub).
    Fa_Terminal  — consumes stats stream and control methods.
    Fa_GUI       — consumes stats stream and control methods via Qt bridge.

Design goals:
    - 900+ pages/sec cross-domain aggregate throughput on commodity hardware
      when 40+ domains are provided (≈22.5 pages/sec/domain).
    - Zero headless browser dependency. Cloudflare bypass via curl_cffi
      impersonation + custom challenge-detection + cookie-passthrough.
    - Adaptive everything: concurrency, rate, priority, retries, health,
      caching, compression, proxy rotation.
    - Never returns JSON to callers; returns structured Python objects and
      the raw text/links/tokens extracted from the page.
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import asyncio
import contextlib
import functools
import hashlib
import heapq
import importlib.util
import math
import os
import random
import re
import signal
import socket
import ssl
import statistics
import string
import sys
import threading
import time
import traceback
import types
import uuid
import weakref
from abc import ABC, abstractmethod
from collections import Counter, defaultdict, deque, OrderedDict
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field, asdict, replace
from enum import Enum, IntEnum, auto
from typing import (
    Any, AsyncIterator, Awaitable, Callable, Iterable, Iterator,
    Mapping, MutableMapping, Optional, Sequence, TypeAlias, Union,
)
from urllib.parse import (
    urljoin, urlparse, urlunparse, parse_qsl, urlencode, quote, unquote,
)

# ─── third-party ─────────────────────────────────────────────────────────────
try:
    import curl_cffi
    from curl_cffi.requests import AsyncSession as CurlAsyncSession
    HAS_CURL_CFFI = True
except Exception:
    curl_cffi = None
    CurlAsyncSession = None  # type: ignore
    HAS_CURL_CFFI = False

try:
    import aiohttp
    from aiohttp import ClientSession, ClientTimeout, TCPConnector
    HAS_AIOHTTP = True
except Exception:
    aiohttp = None
    ClientSession = None  # type: ignore
    HAS_AIOHTTP = False

try:
    import orjson
except Exception:
    orjson = None  # type: ignore

try:
    import xxhash
except Exception:
    xxhash = None  # type: ignore

try:
    from selectolax.lexbor import LexborHTMLParser
    HAS_SELECTOLAX = True
except Exception:
    LexborHTMLParser = None  # type: ignore
    HAS_SELECTOLAX = False

try:
    from tld import get_fld
    HAS_TLD = True
except Exception:
    get_fld = None  # type: ignore
    HAS_TLD = False

try:
    import courlan
    HAS_COURLAN = True
except Exception:
    courlan = None  # type: ignore
    HAS_COURLAN = False


def _load_local_module(module_name: str, filename: str) -> Any:
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    module_path = os.path.join(os.path.dirname(__file__), filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load local module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


ManagerFacade: TypeAlias = Any


# ─── local ───────────────────────────────────────────────────────────────────
try:
    _manager_module = _load_local_module("Fa_Manager", "Fa-Manager.py")
    get_manager = getattr(_manager_module, "get_manager")
    ErrorCategory = getattr(_manager_module, "ErrorCategory")
    ErrorSeverity = getattr(_manager_module, "ErrorSeverity")
    WarningSeverity = getattr(_manager_module, "WarningSeverity")
    CacheTier = getattr(_manager_module, "CacheTier")
    LinkEdge = getattr(_manager_module, "LinkEdge")
except ImportError:  # pragma: no cover — allow standalone import for tests
    def get_manager(*a, **kw):  # type: ignore
        raise RuntimeError("Fa-Manager not available")
    class ErrorCategory(str, Enum):  # type: ignore
        NETWORK = "network"; PARSE = "parse"; INTERNAL = "internal"
        ROBOTS = "robots"; LINK = "link"; RATE_LIMIT = "rate_limit"
        AUTH = "auth"; VALIDATION = "validation"; EXTRACT = "extract"
        OUTPUT = "output"
    class ErrorSeverity(IntEnum):  # type: ignore
        DEBUG = 10; INFO = 20; WARNING = 30; ERROR = 40; CRITICAL = 50
    class WarningSeverity(str, Enum):  # type: ignore
        LOW = "low"; MEDIUM = "medium"; HIGH = "high"
    class CacheTier(str, Enum):  # type: ignore
        RESPONSE = "response"; DNS = "dns"; ROBOTS = "robots"
        DOM = "dom"; URL_NORM = "url_norm"; LINK = "link"
    @dataclass  # type: ignore
    class LinkEdge:
        source_url: str; target_url: str; anchor_text: str = ""
        rel: str = ""; is_internal: bool = False; discovered_at: float = 0.0


__all__ = [
    "CrawlController",
    "get_crawler",
    "reset_crawler",
    "CrawlConfig",
    "Crabber",
    "GenericCrabber",
    "SitemapCrabber",
    "LinkGraphCrabber",
    "DepthCrabber",
    "BreadthCrabber",
    "APICrabber",
    "MicroCrabber",
    "HeavyCrabber",
    "HealthCrabber",
    "HealthChecker",
    "DomainHealth",
    "HealthReport",
    "FetchResult",
    "CrawlPage",
    "CloudflareSolver",
    "SpoofingLayer",
    "PrivacyLayer",
    "CrawlError",
]


# ════════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════════

CRAWL_VERSION = "1.0.0"
DEFAULT_UA_FALLBACK = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.7200.0 Safari/537.36"
)

CF_CHALLENGE_MARKERS = (
    b"cf-challenge", b"cf_chl_opt", b"__cf_chl_jschl_tk__",
    b"jschl-answer", b"cf-please-wait", b"Checking your browser",
    b"cf-browser-verification", b"turnstile", b"cf_chl_prog",
)

CF_TURNSTILE_MARKERS = (
    b"challenges.cloudflare.com/turnstile",
    b"cf-turnstile",
    b"data-sitekey",
)

BLOCK_MARKERS = (
    b"Access Denied", b"You have been blocked",
    b"Rate limit exceeded", b"Too Many Requests",
    b"Attention Required! | Cloudflare",
)

ROBOTS_ALLOWED = 0
ROBOTS_DISALLOWED = 1
ROBOTS_UNKNOWN = 2

CONTENT_TYPE_HTML = ("text/html", "application/xhtml+xml")
CONTENT_TYPE_JSON = ("application/json", "application/ld+json")
CONTENT_TYPE_XML = ("application/xml", "text/xml", "application/rss+xml",
                    "application/atom+xml")
CONTENT_TYPE_TEXT = ("text/plain",)
CONTENT_TYPE_PDF = ("application/pdf",)


# ════════════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════════════

class CrawlState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSING = "pausing"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    DONE = "done"
    FAILED = "failed"


class FetchOutcome(str, Enum):
    SUCCESS = "success"
    REDIRECT = "redirect"
    NOT_MODIFIED = "not_modified"
    ROBOTS_DISALLOWED = "robots_disallowed"
    TOO_LARGE = "too_large"
    WRONG_TYPE = "wrong_type"
    TIMEOUT = "timeout"
    DNS_FAIL = "dns_fail"
    TLS_FAIL = "tls_fail"
    CONN_FAIL = "conn_fail"
    HTTP_4XX = "http_4xx"
    HTTP_5XX = "http_5xx"
    RATE_LIMITED = "rate_limited"
    CF_CHALLENGE = "cf_challenge"
    BLOCKED = "blocked"
    CIRCUIT_OPEN = "circuit_open"
    COOLDOWN = "cooldown"
    DUPLICATE = "duplicate"
    UNKNOWN = "unknown"


class HealthStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNSTABLE = "unstable"
    DOWN = "down"
    UNKNOWN = "unknown"


class Priority(IntEnum):
    CRITICAL = 0
    HIGH = 100
    NORMAL = 500
    LOW = 900
    BACKGROUND = 1000


class ProxyProtocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS5 = "socks5"
    SOCKS5H = "socks5h"


class CachePolicy(str, Enum):
    NONE = "none"
    MEMORY = "memory"
    DISK = "disk"
    BOTH = "both"
    RESPECT_HEADERS = "respect_headers"


class CloudflareMode(str, Enum):
    OFF = "off"
    DETECT_ONLY = "detect_only"
    PASSIVE = "passive"         # impersonate + cookie passthrough
    AGGRESSIVE = "aggressive"    # + challenge parse + retry loop
    MAX = "max"                  # + all tricks, longest patience


# ════════════════════════════════════════════════════════════════════════════
# Exceptions
# ════════════════════════════════════════════════════════════════════════════

class CrawlError(Exception):
    """Base exception for Fa-Crawl."""
    category = ErrorCategory.INTERNAL if 'ErrorCategory' in dir() else None
    retryable = False


class FetchError(CrawlError):
    category = ErrorCategory.NETWORK
    retryable = True


class DNSFailure(FetchError):
    pass


class TLSFailure(FetchError):
    pass


class ConnectionFailure(FetchError):
    pass


class TimeoutFailure(FetchError):
    retryable = True


class TooManyRedirects(FetchError):
    retryable = False


class RobotsDisallowed(CrawlError):
    category = ErrorCategory.ROBOTS
    retryable = False


class ContentTypeMismatch(CrawlError):
    category = ErrorCategory.PARSE
    retryable = False


class ResponseTooLarge(CrawlError):
    retryable = False


class RateLimited(CrawlError):
    category = ErrorCategory.RATE_LIMIT
    retryable = True


class CloudflareChallenge(CrawlError):
    category = ErrorCategory.AUTH
    retryable = True


class CloudflareBlock(CrawlError):
    category = ErrorCategory.AUTH
    retryable = False


class CircuitOpen(CrawlError):
    retryable = False


class DomainCooldown(CrawlError):
    retryable = True


class SitemapError(CrawlError):
    pass


class HealthCheckError(CrawlError):
    pass


class CrawlerNotFound(CrawlError):
    pass


# ════════════════════════════════════════════════════════════════════════════
# Dataclasses
# ════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class CrawlConfig:
    """Runtime crawl config derived from Manager + overrides."""
    concurrency: int = 100
    per_domain_concurrency: int = 2
    max_pages: int = 0                # 0 = unlimited
    max_depth: int = 3
    max_duration_seconds: float = 0.0
    same_domain_only: bool = True
    follow_external: bool = False
    follow_redirects: bool = True
    max_redirects: int = 10
    timeout_total: float = 30.0
    timeout_connect: float = 10.0
    timeout_read: float = 20.0
    max_response_bytes: int = 50 * 1024 * 1024
    min_response_bytes: int = 100
    content_types: tuple[str, ...] = CONTENT_TYPE_HTML
    use_sitemap: bool = True
    respect_robots: bool = True
    use_conditional_get: bool = True
    use_cache: bool = True
    cache_policy: CachePolicy = CachePolicy.RESPECT_HEADERS
    cloudflare_mode: CloudflareMode = CloudflareMode.PASSIVE
    rotate_ua: bool = True
    rotate_tls: bool = True
    rotate_headers: bool = True
    privacy_layers: tuple[str, ...] = ("referer_chain", "cookie_sanitize",
                                        "ua_consistency")
    health_check_enabled: bool = True
    health_check_interval: float = 60.0
    adaptive_concurrency: bool = True
    adaptive_rate_limit: bool = True
    adaptive_retry: bool = True
    retry_max_attempts: int = 5
    retry_base_delay: float = 1.0
    retry_max_delay: float = 60.0
    proxy_enabled: bool = False
    proxy_list: tuple[str, ...] = ()
    proxy_protocol: ProxyProtocol = ProxyProtocol.HTTP
    proxy_sticky_seconds: float = 0.0
    priority: Priority = Priority.NORMAL
    crawler_type: str = "generic"
    sitemap_urls: tuple[str, ...] = ()
    regex_include: tuple[str, ...] = ()
    regex_exclude: tuple[str, ...] = ()
    domain_allowlist: tuple[str, ...] = ()
    domain_blocklist: tuple[str, ...] = ()
    path_allowlist: tuple[str, ...] = ()
    path_blocklist: tuple[str, ...] = ()
    start_time: float = 0.0
    verbose: bool = False
    dry_run: bool = False
    generate_har: bool = False
    save_raw_html: bool = True
    batch_size: int = 64


@dataclass(slots=True)
class FetchResult:
    """Raw result of one HTTP fetch. Not returned to end users — internal."""
    url: str
    final_url: str
    status: int
    outcome: FetchOutcome
    headers: dict = field(default_factory=dict)
    body: bytes = b""
    body_text: str = ""
    content_type: str = ""
    content_length: int = 0
    elapsed_ms: float = 0.0
    redirected: bool = False
    redirect_chain: tuple[str, ...] = ()
    from_cache: bool = False
    used_client: str = ""             # "curl_cffi" or "aiohttp"
    used_ua: str = ""
    used_impersonate: str = ""
    used_proxy: str = ""
    retry_count: int = 0
    timestamp: float = 0.0
    domain: str = ""
    error_type: str = ""
    error_message: str = ""


@dataclass(slots=True)
class CrawlPage:
    """
    The primary thing a crawl produces. Never JSON.
    Contains raw text, paragraphs, tokens, links, and analysis.
    """
    url: str
    final_url: str
    domain: str
    status: int
    title: str = ""
    language: str = ""
    content_type: str = ""
    text: str = ""
    paragraphs: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    links_internal: tuple[dict, ...] = ()
    links_external: tuple[dict, ...] = ()
    images: tuple[str, ...] = ()
    meta: dict = field(default_factory=dict)
    json_ld: tuple[dict, ...] = ()
    most_used_word: str = ""
    least_used_word: str = ""
    words_count: int = 0
    unique_words: int = 0
    reading_time_seconds: float = 0.0
    cleaned: str = ""
    raw_html: str = ""
    fetched_at: float = 0.0
    depth: int = 0
    from_cache: bool = False
    elapsed_ms: float = 0.0

    def to_record(self) -> dict:
        """For Manager.write_record — plain dict, JSON-serialized later."""
        return {
            "url": self.url,
            "final_url": self.final_url,
            "domain": self.domain,
            "status": self.status,
            "title": self.title,
            "language": self.language,
            "content_type": self.content_type,
            "paragraphs": list(self.paragraphs),
            "tokens": list(self.tokens),
            "links": {
                "internal": list(self.links_internal),
                "external": list(self.links_external),
            },
            "images": list(self.images),
            "meta": self.meta,
            "json_ld": list(self.json_ld),
            "most_used_word": self.most_used_word,
            "least_used_word": self.least_used_word,
            "words_count": self.words_count,
            "unique_words": self.unique_words,
            "reading_time_seconds": self.reading_time_seconds,
            "cleaned": self.cleaned,
            "raw": self.raw_html,
            "timestamp": self.fetched_at,
            "depth": self.depth,
            "from_cache": self.from_cache,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(slots=True)
class DomainHealth:
    """Live health metrics for a single domain."""
    domain: str
    status: HealthStatus = HealthStatus.UNKNOWN
    total_requests: int = 0
    successes: int = 0
    failures: int = 0
    timeouts: int = 0
    rate_limited: int = 0
    blocked: int = 0
    cf_challenges: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    total_latency_ms: float = 0.0
    last_latency_ms: float = 0.0
    min_latency_ms: float = math.inf
    max_latency_ms: float = 0.0
    last_success_ts: float = 0.0
    last_failure_ts: float = 0.0
    last_request_ts: float = 0.0
    cooldown_until: float = 0.0
    health_score: float = 100.0
    sample_window: deque = field(default_factory=lambda: deque(maxlen=200))

    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.successes / self.total_requests

    def avg_latency_ms(self) -> float:
        if self.successes == 0:
            return 0.0
        return self.total_latency_ms / self.successes

    def recompute_status(self) -> HealthStatus:
        n = self.total_requests
        if n == 0:
            return HealthStatus.UNKNOWN
        sr = self.success_rate()
        recent = list(self.sample_window)
        if len(recent) >= 20:
            recent_sr = sum(1 for x in recent if x) / len(recent)
        else:
            recent_sr = sr
        if self.cooldown_until > time.time():
            return HealthStatus.DOWN
        if recent_sr >= 0.95 and sr >= 0.9:
            return HealthStatus.HEALTHY
        if recent_sr >= 0.75:
            return HealthStatus.DEGRADED
        if recent_sr >= 0.4:
            return HealthStatus.UNSTABLE
        return HealthStatus.DOWN

    def update_score(self) -> float:
        sr = self.success_rate()
        latency_penalty = min(50.0, max(0.0, (self.avg_latency_ms() - 500) / 40))
        rate_penalty = min(20.0, self.rate_limited * 0.5)
        block_penalty = min(30.0, self.blocked * 2.0)
        cf_penalty = min(15.0, self.cf_challenges * 1.0)
        score = 100.0 * sr - latency_penalty - rate_penalty \
                - block_penalty - cf_penalty
        self.health_score = max(0.0, min(100.0, score))
        return self.health_score


@dataclass(slots=True)
class HealthReport:
    """Aggregate health report across many domains."""
    generated_at: float = 0.0
    total_domains: int = 0
    healthy: int = 0
    degraded: int = 0
    unstable: int = 0
    down: int = 0
    unknown: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    aggregate_success_rate: float = 1.0
    aggregate_health_score: float = 100.0
    cross_domain_balance: float = 0.0     # 0..1, higher = more balanced
    worst_domains: tuple[tuple[str, float], ...] = ()
    best_domains: tuple[tuple[str, float], ...] = ()
    per_domain: dict = field(default_factory=dict)


@dataclass(slots=True)
class EndpointHealth:
    url: str
    ok: bool
    status: int = 0
    latency_ms: float = 0.0
    error: str = ""
    checked_at: float = 0.0


# ════════════════════════════════════════════════════════════════════════════
# Utilities
# ════════════════════════════════════════════════════════════════════════════

def _now() -> float:
    return time.time()


def _host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _registered_domain(host: str) -> str:
    if not host:
        return ""
    if get_fld is not None:
        try:
            fld = get_fld("http://" + host, fix_protocol=True)
            if fld:
                return fld
        except Exception:
            pass
    parts = host.lower().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _normalize_url(url: str, base: Optional[str] = None,
                   strip_fragments: bool = True,
                   strip_tracking: bool = True) -> str:
    if not url:
        return ""
    url = url.strip()
    if base and not url.startswith(("http://", "https://", "//")):
        url = urljoin(base, url)
    if url.startswith("//"):
        url = "https:" + url
    try:
        p = urlparse(url)
    except Exception:
        return ""
    scheme = (p.scheme or "https").lower()
    if scheme not in ("http", "https"):
        return ""
    host = (p.hostname or "").lower()
    port = p.port
    if port and not ((scheme == "http" and port == 80) or
                     (scheme == "https" and port == 443)):
        netloc = f"{host}:{port}"
    else:
        netloc = host
    path = p.path or "/"
    query = p.query
    if strip_tracking and query:
        pairs = [(k, v) for k, v in parse_qsl(query, keep_blank_values=True)
                 if not k.lower().startswith(("utm_", "fbclid", "gclid",
                                              "wbraid", "gbraid", "_ga",
                                              "mc_cid", "mc_eid", "igshid"))]
        pairs.sort()
        query = urlencode(pairs, doseq=True)
    if strip_fragments:
        return urlunparse((scheme, netloc, path, "", query, ""))
    return urlunparse((scheme, netloc, path, "", query, p.fragment))


def _is_html_content_type(ct: str) -> bool:
    ct = ct.lower()
    return any(ct.startswith(x) for x in CONTENT_TYPE_HTML)


def _is_json_content_type(ct: str) -> bool:
    ct = ct.lower()
    return any(ct.startswith(x) for x in CONTENT_TYPE_JSON)


def _content_type_from_headers(headers: Mapping[str, str]) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v.split(";")[0].strip().lower()
    return ""


def _parse_retry_after(value: str) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        return float(value)
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return None


def _backoff_delay(attempt: int, base: float, cap: float,
                   jitter: bool = True) -> float:
    d = min(cap, base * (2 ** attempt))
    if jitter:
        d = d * (0.5 + random.random())
    return d


async def _async_noop(*_a, **_kw) -> None:
    return None


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 1: Health Checkers
# ════════════════════════════════════════════════════════════════════════════

class HealthChecker:
    """
    Domain and endpoint health tracking. Provides per-domain health
    scores, cross-domain balance analysis, DNS/TLS/latency checks,
    and cooldown decisions.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.mgr = crawler.mgr
        self.log = crawler.log
        self._lock = asyncio.Lock()
        self._domains: dict[str, DomainHealth] = {}
        self._endpoints: OrderedDict[str, EndpointHealth] = OrderedDict()
        self._endpoint_max = 5000
        self._history: deque[HealthReport] = deque(maxlen=120)
        self._health_check_task: Optional[asyncio.Task] = None
        self._running = False

    # ─── recording ─────────────────────────────────────────────────────

    async def record_success(self, domain: str, latency_ms: float) -> None:
        async with self._lock:
            h = self._domains.setdefault(domain, DomainHealth(domain=domain))
            h.total_requests += 1
            h.successes += 1
            h.consecutive_successes += 1
            h.consecutive_failures = 0
            h.total_latency_ms += latency_ms
            h.last_latency_ms = latency_ms
            h.min_latency_ms = min(h.min_latency_ms, latency_ms)
            h.max_latency_ms = max(h.max_latency_ms, latency_ms)
            h.last_success_ts = _now()
            h.last_request_ts = h.last_success_ts
            h.sample_window.append(True)
            h.status = h.recompute_status()
            h.update_score()

    async def record_failure(self, domain: str, latency_ms: float,
                             kind: FetchOutcome) -> None:
        async with self._lock:
            h = self._domains.setdefault(domain, DomainHealth(domain=domain))
            h.total_requests += 1
            h.failures += 1
            h.consecutive_failures += 1
            h.consecutive_successes = 0
            h.last_failure_ts = _now()
            h.last_request_ts = h.last_failure_ts
            h.sample_window.append(False)
            if kind == FetchOutcome.TIMEOUT:
                h.timeouts += 1
            elif kind == FetchOutcome.RATE_LIMITED:
                h.rate_limited += 1
            elif kind == FetchOutcome.BLOCKED:
                h.blocked += 1
            elif kind == FetchOutcome.CF_CHALLENGE:
                h.cf_challenges += 1
            h.status = h.recompute_status()
            h.update_score()

    async def record_endpoint(self, url: str, ok: bool, status: int,
                              latency_ms: float, error: str = "") -> None:
        async with self._lock:
            self._endpoints[url] = EndpointHealth(
                url=url, ok=ok, status=status,
                latency_ms=latency_ms, error=error, checked_at=_now(),
            )
            while len(self._endpoints) > self._endpoint_max:
                self._endpoints.popitem(last=False)

    # ─── queries ───────────────────────────────────────────────────────

    def get_domain(self, domain: str) -> Optional[DomainHealth]:
        return self._domains.get(domain)

    def health_score(self, domain: str) -> float:
        h = self._domains.get(domain)
        return h.health_score if h else 100.0

    def status(self, domain: str) -> HealthStatus:
        h = self._domains.get(domain)
        return h.status if h else HealthStatus.UNKNOWN

    def in_cooldown(self, domain: str) -> Optional[float]:
        h = self._domains.get(domain)
        if not h:
            return None
        if h.cooldown_until > _now():
            return h.cooldown_until - _now()
        return None

    def set_cooldown(self, domain: str, seconds: float) -> None:
        h = self._domains.setdefault(domain, DomainHealth(domain=domain))
        until = _now() + max(0.0, seconds)
        if until > h.cooldown_until:
            h.cooldown_until = until

    # ─── aggregate ─────────────────────────────────────────────────────

    def report(self) -> HealthReport:
        rep = HealthReport(generated_at=_now())
        rep.total_domains = len(self._domains)
        latencies: list[float] = []
        scores: list[float] = []
        total_ok = total_req = 0
        per_domain: dict[str, dict] = {}
        for d, h in self._domains.items():
            if h.status == HealthStatus.HEALTHY:
                rep.healthy += 1
            elif h.status == HealthStatus.DEGRADED:
                rep.degraded += 1
            elif h.status == HealthStatus.UNSTABLE:
                rep.unstable += 1
            elif h.status == HealthStatus.DOWN:
                rep.down += 1
            else:
                rep.unknown += 1
            if h.successes > 0:
                latencies.append(h.avg_latency_ms())
            scores.append(h.health_score)
            total_ok += h.successes
            total_req += h.total_requests
            per_domain[d] = {
                "status": h.status.value,
                "score": h.health_score,
                "successes": h.successes,
                "failures": h.failures,
                "rate_limited": h.rate_limited,
                "blocked": h.blocked,
                "cf_challenges": h.cf_challenges,
                "avg_latency_ms": h.avg_latency_ms(),
            }
        if latencies:
            rep.avg_latency_ms = statistics.mean(latencies)
            if len(latencies) >= 2:
                sorted_l = sorted(latencies)
                idx = int(0.95 * (len(sorted_l) - 1))
                rep.p95_latency_ms = sorted_l[idx]
            else:
                rep.p95_latency_ms = latencies[0]
        if scores:
            rep.aggregate_health_score = statistics.mean(scores)
        if total_req:
            rep.aggregate_success_rate = total_ok / total_req

        # cross-domain balance: 1 - stdev/mean of per-domain throughput
        if len(self._domains) >= 2:
            counts = [h.total_requests for h in self._domains.values()]
            if counts and sum(counts) > 0:
                mean = sum(counts) / len(counts)
                if mean > 0:
                    var = sum((c - mean) ** 2 for c in counts) / len(counts)
                    stdev = math.sqrt(var)
                    rep.cross_domain_balance = max(
                        0.0, 1.0 - min(1.0, stdev / mean))

        ranked = sorted(per_domain.items(), key=lambda kv: kv[1]["score"])
        rep.worst_domains = tuple((d, v["score"]) for d, v in ranked[:5])
        rep.best_domains = tuple((d, v["score"]) for d, v in ranked[-5:])
        rep.per_domain = per_domain
        self._history.append(rep)
        return rep

    # ─── active probes ─────────────────────────────────────────────────

    async def check_dns(self, domain: str) -> EndpointHealth:
        t0 = _now()
        try:
            loop = asyncio.get_running_loop()
            await loop.getaddrinfo(domain, None)
            return EndpointHealth(url=f"dns://{domain}", ok=True,
                                  latency_ms=(_now() - t0) * 1000)
        except Exception as e:
            return EndpointHealth(url=f"dns://{domain}", ok=False,
                                  error=str(e),
                                  latency_ms=(_now() - t0) * 1000)

    async def check_tls(self, domain: str, port: int = 443) -> EndpointHealth:
        t0 = _now()
        try:
            ctx = ssl.create_default_context()
            fut = asyncio.open_connection(domain, port, ssl=ctx)
            reader, writer = await asyncio.wait_for(fut, timeout=10.0)
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            return EndpointHealth(url=f"tls://{domain}:{port}", ok=True,
                                  latency_ms=(_now() - t0) * 1000)
        except Exception as e:
            return EndpointHealth(url=f"tls://{domain}:{port}", ok=False,
                                  error=str(e),
                                  latency_ms=(_now() - t0) * 1000)

    async def check_endpoint(self, url: str, timeout: float = 10.0
                             ) -> EndpointHealth:
        t0 = _now()
        fetcher = self.crawler.fetcher
        try:
            res = await fetcher.fetch(
                url,
                timeout_override=timeout,
                allow_redirects=True,
                method="HEAD",
                record_health=False,
            )
            ok = 200 <= res.status < 400
            return EndpointHealth(url=url, ok=ok, status=res.status,
                                  latency_ms=(_now() - t0) * 1000)
        except Exception as e:
            return EndpointHealth(url=url, ok=False, error=str(e),
                                  latency_ms=(_now() - t0) * 1000)

    async def check_cross_domain(self, domains: Sequence[str]
                                 ) -> dict[str, EndpointHealth]:
        tasks = {d: self.check_endpoint(f"https://{d}/") for d in domains}
        results = await asyncio.gather(*tasks.values(),
                                       return_exceptions=True)
        out: dict[str, EndpointHealth] = {}
        for d, r in zip(tasks.keys(), results):
            if isinstance(r, BaseException):
                out[d] = EndpointHealth(url=f"https://{d}/", ok=False,
                                        error=str(r))
            else:
                out[d] = r
        return out

    # ─── background loop ───────────────────────────────────────────────

    async def start_background(self, interval: float = 60.0) -> None:
        if self._running:
            return
        self._running = True
        self._health_check_task = asyncio.create_task(
            self._background_loop(interval),
            name="FaHealthChecker",
        )

    async def stop_background(self) -> None:
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._health_check_task
            self._health_check_task = None

    async def _background_loop(self, interval: float) -> None:
        while self._running:
            try:
                await asyncio.sleep(interval)
                self.report()
                self._auto_cooldown_sweep()
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.mgr.errors.record_exception(
                    e, category=ErrorCategory.INTERNAL,
                    context={"where": "health_background"},
                )

    def _auto_cooldown_sweep(self) -> None:
        for h in self._domains.values():
            if h.consecutive_failures >= 8:
                self.set_cooldown(h.domain, 30.0)
            elif h.consecutive_failures >= 15:
                self.set_cooldown(h.domain, 300.0)
            elif h.blocked >= 5:
                self.set_cooldown(h.domain, 600.0)
            elif h.rate_limited >= 3:
                self.set_cooldown(h.domain, 120.0)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 2: Cloudflare Solver (custom, no headless browser)
# ════════════════════════════════════════════════════════════════════════════

class CloudflareSolver:
    """
    Custom Cloudflare mitigation layer. Does not use a headless browser.

    Strategy tiers (progressive):
        PASSIVE     – TLS impersonation via curl_cffi, cookie passthrough.
        AGGRESSIVE  – + challenge HTML parse, jschl answer computation,
                       cookie cache per domain, retry with new impersonate.
        MAX         – + long patience, rotating UA/TLS/headers on every retry,
                       session warmup, and full cookie persistence.

    Turnstile cannot be solved without JS execution; those pages are
    detected, marked, and skipped rather than hammered.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.mgr = crawler.mgr
        self.log = crawler.log
        self._cookies: dict[str, dict[str, str]] = defaultdict(dict)
        self._solved_at: dict[str, float] = {}
        self._attempts: Counter = Counter()
        self._lock = asyncio.Lock()

    # ─── detection ─────────────────────────────────────────────────────

    @staticmethod
    def detect_challenge(status: int, headers: Mapping[str, str],
                         body: bytes) -> tuple[bool, str]:
        if not body:
            return False, ""
        head = body[:8192]
        for marker in CF_CHALLENGE_MARKERS:
            if marker in head:
                return True, marker.decode("utf-8", "replace")
        # Server header
        for k, v in headers.items():
            if k.lower() == "server" and "cloudflare" in v.lower():
                if status in (403, 503):
                    return True, "server_header"
        return False, ""

    @staticmethod
    def detect_turnstile(body: bytes) -> bool:
        head = body[:16384]
        return any(m in head for m in CF_TURNSTILE_MARKERS)

    @staticmethod
    def detect_block(status: int, headers: Mapping[str, str],
                     body: bytes) -> bool:
        if status not in (403, 429, 503):
            return False
        head = body[:4096]
        return any(m in head for m in BLOCK_MARKERS)

    # ─── cookie cache ──────────────────────────────────────────────────

    async def get_cookies(self, domain: str) -> dict[str, str]:
        async with self._lock:
            cookies = dict(self._cookies.get(domain, {}))
        # also check Manager cookie jar
        try:
            stored = self.mgr.cookies.all_for_domain(domain)
            for c in stored:
                if c.get("name") and c.get("value"):
                    cookies.setdefault(c["name"], c["value"])
        except Exception:
            pass
        return cookies

    async def store_cookies(self, domain: str, cookies: Mapping[str, str]
                            ) -> None:
        if not cookies:
            return
        async with self._lock:
            self._cookies[domain].update(cookies)
        try:
            for name, value in cookies.items():
                self.mgr.cookies.put(domain, name, value,
                                     expires=_now() + 86400 * 7)
        except Exception:
            pass

    def is_recently_solved(self, domain: str, within: float = 3600.0) -> bool:
        ts = self._solved_at.get(domain, 0.0)
        return (_now() - ts) < within

    # ─── jschl solver (best-effort without JS) ─────────────────────────

    @staticmethod
    def extract_jschl_answer(body: bytes) -> Optional[float]:
        """
        Best-effort parse of Cloudflare's jschl challenge.
        Only works on legacy challenge pages; modern challenges require
        JS execution.
        """
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            return None
        m = re.search(
            r"setTimeout\(function\(\)\{(.+?)}, *\d+\);",
            text, re.DOTALL,
        )
        if not m:
            return None
        snippet = m.group(1)
        # strip obfuscation
        snippet = snippet.replace(" ", "")
        # find the final variable assignment pattern like:
        #   a.value = +((  ...  ))
        m2 = re.search(r"\.value=(\+?\(?.*?\)?);", snippet)
        if not m2:
            return None
        expr = m2.group(1)
        # reduce arithmetic expression
        expr = expr.replace("+", " + ").replace("-", " - ")
        expr = re.sub(r"[^0-9+\-*/(). ]", "", expr)
        try:
            return float(eval(expr, {"__builtins__": {}}, {}))
        except Exception:
            return None

    # ─── solve attempt ─────────────────────────────────────────────────

    async def handle_challenge(self, url: str, body: bytes,
                               headers: Mapping[str, str],
                               status: int) -> Optional[dict]:
        """
        Given a challenge response, attempt to solve.
        Returns optional override headers to use on retry, or None if
        unsolvable.
        """
        domain = _host(url)
        self._attempts[domain] += 1
        mode = self.crawler.config.cloudflare_mode

        if mode == CloudflareMode.OFF:
            return None
        if mode == CloudflareMode.DETECT_ONLY:
            self.log.info("CF challenge detected (detect-only): %s", url)
            return None

        if self.detect_turnstile(body):
            self.log.warning("Turnstile detected (unsolvable w/o browser): %s",
                             url)
            return None

        answer = self.extract_jschl_answer(body)
        if answer is not None:
            self._solved_at[domain] = _now()
            # Not returning a real cookie — just signal "solved"
            return {"_jschl_answer": str(answer)}

        return None

    def next_impersonate(self) -> str:
        """Rotate impersonation profile on each retry."""
        profiles = ["chrome140", "chrome138", "chrome136",
                    "chrome134", "chrome131", "chrome124",
                    "chrome120", "firefox135", "firefox133",
                    "safari18_0", "safari17_5"]
        return random.choice(profiles)

    def stats(self) -> dict:
        return {
            "tracked_domains": len(self._cookies),
            "solved_domains": len(self._solved_at),
            "attempts": dict(self._attempts),
        }


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 3: Spoofing Layers
# ════════════════════════════════════════════════════════════════════════════

class SpoofingLayer:
    """
    Composes a consistent set of (UA, TLS impersonate, headers, sec-ch-ua,
    platform) so the fingerprint of every request looks internally coherent.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.agents = crawler.mgr.agents
        self._lock = asyncio.Lock()
        self._sticky: dict[str, "SpoofProfile"] = {}

    async def next_profile(self, domain: str,
                           rotate: bool = True) -> "SpoofProfile":
        if not rotate:
            async with self._lock:
                p = self._sticky.get(domain)
                if p:
                    return p
        profile = self._generate_profile()
        async with self._lock:
            self._sticky[domain] = profile
        return profile

    def _generate_profile(self) -> "SpoofProfile":
        families = {
            "chrome_windows": ("chrome", "Windows", "?0", "140"),
            "chrome_macos":   ("chrome", "macOS", "?0", "140"),
            "chrome_linux":   ("chrome", "Linux", "?0", "140"),
            "chrome_android": ("chrome", "Android", "?1", "140"),
            "chrome_ios":     ("chrome", "iOS", "?1", "140"),
            "firefox_windows": ("firefox", "Windows", "?0", "135"),
            "firefox_macos":  ("firefox", "macOS", "?0", "135"),
            "firefox_linux":  ("firefox", "Linux", "?0", "135"),
            "safari_macos":   ("safari", "macOS", "?0", "18"),
            "safari_ios":     ("safari", "iOS", "?1", "18"),
            "edge_windows":   ("edge", "Windows", "?0", "140"),
            "edge_macos":     ("edge", "macOS", "?0", "140"),
        }
        fam = random.choice(list(families.keys()))
        engine, platform, mobile, version = families[fam]

        try:
            ua_list = self.agents.get(f"user_agents.{fam}", [])
        except Exception:
            ua_list = []
        ua = random.choice(ua_list) if ua_list else DEFAULT_UA_FALLBACK

        headers = self._build_headers(engine, platform, mobile, version)
        impersonate = self._pick_impersonate(engine, version)

        return SpoofProfile(
            user_agent=ua,
            impersonate=impersonate,
            headers=headers,
            family=fam,
            engine=engine,
            platform=platform,
            mobile=mobile,
            version=version,
        )

    def _pick_impersonate(self, engine: str, version: str) -> str:
        if engine == "chrome":
            return f"chrome{random.choice(['140','138','136','134','131','124','120'])}"
        if engine == "firefox":
            return f"firefox{random.choice(['135','133','128','120'])}"
        if engine == "safari":
            return f"safari{random.choice(['18_0','17_5','16_5'])}"
        if engine == "edge":
            return "edge140"
        return "chrome"

    def _build_headers(self, engine: str, platform: str, mobile: str,
                       version: str) -> dict:
        base = {
            "User-Agent": "",  # set by caller
            "Accept": "text/html,application/xhtml+xml,application/xml;"
                      "q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice([
                "en-US,en;q=0.9",
                "en-GB,en;q=0.9",
                "en-US,en;q=0.8,ar;q=0.6",
                "en-US,en;q=0.9,fr;q=0.8",
            ]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if engine == "chrome":
            base["sec-ch-ua"] = (
                f'"Chromium";v="{version}", "Not=A?Brand";v="24", '
                f'"Google Chrome";v="{version}"'
            )
            base["sec-ch-ua-mobile"] = mobile
            base["sec-ch-ua-platform"] = f'"{platform}"'
            base["Sec-Fetch-Dest"] = "document"
            base["Sec-Fetch-Mode"] = "navigate"
            base["Sec-Fetch-Site"] = "none"
            base["Sec-Fetch-User"] = "?1"
        elif engine == "edge":
            base["sec-ch-ua"] = (
                f'"Chromium";v="{version}", "Not=A?Brand";v="24", '
                f'"Microsoft Edge";v="{version}"'
            )
            base["sec-ch-ua-mobile"] = mobile
            base["sec-ch-ua-platform"] = f'"{platform}"'
        elif engine == "firefox":
            base["Sec-Fetch-Dest"] = "document"
            base["Sec-Fetch-Mode"] = "navigate"
            base["Sec-Fetch-Site"] = "none"
        elif engine == "safari":
            base["Accept-Language"] = "en-US,en;q=0.9"
        return base


@dataclass(slots=True)
class SpoofProfile:
    user_agent: str
    impersonate: str
    headers: dict
    family: str
    engine: str
    platform: str
    mobile: str
    version: str

    def merged_headers(self) -> dict:
        h = dict(self.headers)
        h["User-Agent"] = self.user_agent
        return h


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 4: Privacy Layers
# ════════════════════════════════════════════════════════════════════════════

class PrivacyLayer:
    """
    Composes privacy-preserving request transforms:
        - referer_chain   : synthesize plausible referer
        - cookie_sanitize : strip tracking cookies
        - ua_consistency  : ensure client hints match UA
        - strip_fp_params : remove fingerprinting query params
        - anonymize_ips   : use proxy for private IPs
        - gpc             : send Global Privacy Control
        - dnt             : Do Not Track
    """

    STRIP_QUERY_KEYS = (
        "fbclid", "gclid", "wbraid", "gbraid", "_ga", "_gl",
        "mc_cid", "mc_eid", "igshid", "si", "s_kwcid", "ref_src",
        "ref_url", "source", "campaign",
    )
    TRACKING_COOKIES = (
        "_ga", "_gid", "_gcl_au", "_fbp", "_fbc", "IDE", "ANID",
        "NID", "1P_JAR", "CONSENT", "SOCS", "HSID", "SID",
        "SSID", "APISID", "SAPISID", "__Secure-3PSID",
    )

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self._active = set(crawler.config.privacy_layers)
        self._engines = [
            "https://www.google.com/",
            "https://www.bing.com/",
            "https://duckduckgo.com/",
        ]
        self._engine_weights = [0.6, 0.25, 0.15]

    def preprocess_url(self, url: str) -> str:
        if "strip_fp_params" not in self._active:
            return url
        try:
            p = urlparse(url)
            if not p.query:
                return url
            pairs = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                     if k.lower() not in self.STRIP_QUERY_KEYS]
            pairs.sort()
            return urlunparse((p.scheme, p.netloc, p.path, "", urlencode(pairs), ""))
        except Exception:
            return url

    def augment_headers(self, url: str, headers: dict,
                        source_url: Optional[str] = None) -> dict:
        out = dict(headers)
        if "referer_chain" in self._active:
            if source_url:
                out["Referer"] = source_url
            else:
                engine = random.choices(self._engines,
                                        weights=self._engine_weights)[0]
                out["Referer"] = engine
        if "gpc" in self._active:
            out["Sec-GPC"] = "1"
        if "dnt" in self._active:
            out["DNT"] = "1"
        return out

    def filter_cookies(self, cookies: Mapping[str, str]) -> dict[str, str]:
        if "cookie_sanitize" not in self._active:
            return dict(cookies)
        return {k: v for k, v in cookies.items()
                if k not in self.TRACKING_COOKIES}

    def stats(self) -> dict:
        return {"active_layers": sorted(self._active)}


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 5: Error Handlers (400+ lines of hardened handling)
# ════════════════════════════════════════════════════════════════════════════

class CrawlErrorHandler:
    """
    The heart of Fa-Crawl's resilience. Classifies every failure, decides
    whether it is retryable, chooses backoff, updates health, emits to
    Manager, and returns the correct FetchOutcome.

    Every fetch goes through `classify(exc_or_result)` on completion.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.mgr = crawler.mgr
        self.health = crawler.health
        self.log = crawler.log

    # ─── top-level dispatcher ──────────────────────────────────────────

    async def classify(self, url: str, *,
                       result: Optional[FetchResult] = None,
                       exc: Optional[BaseException] = None,
                       ) -> tuple[FetchOutcome, bool, float]:
        """
        Returns (outcome, retryable, backoff_seconds).
        """
        domain = _host(url)

        if exc is not None:
            return await self._classify_exception(url, domain, exc)

        if result is None:
            return FetchOutcome.UNKNOWN, False, 0.0

        return await self._classify_result(url, domain, result)

    # ─── exception classifier ──────────────────────────────────────────

    async def _classify_exception(self, url: str, domain: str,
                                  exc: BaseException
                                  ) -> tuple[FetchOutcome, bool, float]:
        name = type(exc).__name__
        mod = type(exc).__module__
        full = f"{mod}.{name}"

        self.mgr.errors.record_exception(
            exc,
            category=ErrorCategory.NETWORK,
            url=url,
            context={"handler": "crawl", "domain": domain},
        )

        # DNS
        if "gaierror" in full or name == "gaierror" or \
                "NameResolutionError" in full or \
                isinstance(exc, socket.gaierror):
            await self.health.record_failure(domain, 0.0, FetchOutcome.DNS_FAIL)
            self.mgr.warnings.warn(
                code="dns_failure", severity=WarningSeverity.MEDIUM,
                message=f"DNS failure for {domain}",
                context={"url": url},
            )
            return FetchOutcome.DNS_FAIL, True, 15.0

        # TLS / SSL
        if "SSLError" in name or "ssl" in mod.lower() or \
                isinstance(exc, ssl.SSLError):
            await self.health.record_failure(domain, 0.0, FetchOutcome.TLS_FAIL)
            self.mgr.warnings.warn(
                code="tls_failure", severity=WarningSeverity.MEDIUM,
                message=f"TLS failure for {domain}",
                context={"url": url, "exc": str(exc)[:200]},
            )
            return FetchOutcome.TLS_FAIL, True, 10.0

        # Timeout
        if isinstance(exc, asyncio.TimeoutError) or "Timeout" in name:
            await self.health.record_failure(domain, 0.0,
                                             FetchOutcome.TIMEOUT)
            return FetchOutcome.TIMEOUT, True, 5.0

        # Connection failures
        if isinstance(exc, (ConnectionError, ConnectionResetError,
                            ConnectionRefusedError, ConnectionAbortedError,
                            BrokenPipeError, EOFError)):
            await self.health.record_failure(domain, 0.0,
                                             FetchOutcome.CONN_FAIL)
            return FetchOutcome.CONN_FAIL, True, 3.0

        # Too many redirects
        if name == "TooManyRedirects":
            return FetchOutcome.REDIRECT, False, 0.0

        # Circuit open
        if isinstance(exc, CircuitOpen):
            return FetchOutcome.CIRCUIT_OPEN, False, 0.0

        # Cloudflare
        if isinstance(exc, CloudflareChallenge):
            await self.health.record_failure(domain, 0.0,
                                             FetchOutcome.CF_CHALLENGE)
            return FetchOutcome.CF_CHALLENGE, True, 20.0

        if isinstance(exc, CloudflareBlock):
            await self.health.record_failure(domain, 0.0,
                                             FetchOutcome.BLOCKED)
            return FetchOutcome.BLOCKED, False, 0.0

        # Rate limit
        if isinstance(exc, RateLimited):
            await self.health.record_failure(domain, 0.0,
                                             FetchOutcome.RATE_LIMITED)
            return FetchOutcome.RATE_LIMITED, True, 30.0

        # Domain cooldown
        if isinstance(exc, DomainCooldown):
            return FetchOutcome.COOLDOWN, True, 5.0

        # Default: unknown, retry once
        return FetchOutcome.UNKNOWN, True, 2.0

    # ─── result classifier ─────────────────────────────────────────────

    async def _classify_result(self, url: str, domain: str,
                               result: FetchResult
                               ) -> tuple[FetchOutcome, bool, float]:
        status = result.status

        # Success range
        if 200 <= status < 300:
            await self.health.record_success(domain, result.elapsed_ms)
            return FetchOutcome.SUCCESS, False, 0.0

        # Redirects should have been followed already
        if 300 <= status < 400:
            if self.crawler.config.follow_redirects:
                # if we got here with a redirect it means we hit max
                return FetchOutcome.REDIRECT, False, 0.0
            return FetchOutcome.REDIRECT, False, 0.0

        # 304 Not Modified — success
        if status == 304:
            await self.health.record_success(domain, result.elapsed_ms)
            return FetchOutcome.NOT_MODIFIED, False, 0.0

        # 4xx
        if 400 <= status < 500:
            if status == 403:
                # Could be Cloudflare or actual forbidden
                if CloudflareSolver.detect_block(
                        status, result.headers, result.body):
                    await self.health.record_failure(
                        domain, result.elapsed_ms, FetchOutcome.BLOCKED)
                    self.mgr.warnings.warn(
                        code="blocked_403",
                        severity=WarningSeverity.HIGH,
                        message=f"403 block on {domain}",
                        context={"url": url},
                    )
                    return FetchOutcome.BLOCKED, True, 60.0
                await self.health.record_failure(
                    domain, result.elapsed_ms, FetchOutcome.HTTP_4XX)
                return FetchOutcome.HTTP_4XX, False, 0.0
            if status == 408:
                return FetchOutcome.TIMEOUT, True, 5.0
            if status == 429:
                retry_after = _parse_retry_after(
                    result.headers.get("retry-after", ""))
                wait = retry_after if retry_after else 30.0
                wait = min(wait, 900.0)
                await self.health.record_failure(
                    domain, result.elapsed_ms, FetchOutcome.RATE_LIMITED)
                self.health.set_cooldown(domain, wait)
                self.mgr.warnings.warn(
                    code="rate_limited",
                    severity=WarningSeverity.HIGH,
                    message=f"429 on {domain}, cooling down {wait:.0f}s",
                    context={"url": url},
                )
                return FetchOutcome.RATE_LIMITED, True, wait
            if status in (401, 402, 404, 405, 410, 418, 451):
                await self.health.record_failure(
                    domain, result.elapsed_ms, FetchOutcome.HTTP_4XX)
                return FetchOutcome.HTTP_4XX, False, 0.0
            # other 4xx — non-retryable
            await self.health.record_failure(
                domain, result.elapsed_ms, FetchOutcome.HTTP_4XX)
            return FetchOutcome.HTTP_4XX, False, 0.0

        # 5xx
        if 500 <= status < 600:
            wait = _backoff_delay(result.retry_count,
                                  self.crawler.config.retry_base_delay,
                                  self.crawler.config.retry_max_delay)
            if status in (502, 503, 504):
                retry_after = _parse_retry_after(
                    result.headers.get("retry-after", ""))
                if retry_after:
                    wait = min(retry_after, 120.0)
            await self.health.record_failure(
                domain, result.elapsed_ms, FetchOutcome.HTTP_5XX)
            return FetchOutcome.HTTP_5XX, True, wait

        return FetchOutcome.UNKNOWN, False, 0.0

    # ─── decision helpers ──────────────────────────────────────────────

    def should_retry(self, outcome: FetchOutcome, attempt: int,
                     retryable: bool) -> bool:
        if not retryable:
            return False
        if not self.crawler.config.adaptive_retry:
            return attempt < self.crawler.config.retry_max_attempts
        # Adaptive: fewer retries when domain health is bad
        h = self.health.get_domain  # placeholder to avoid lint
        max_attempts = self.crawler.config.retry_max_attempts
        if outcome == FetchOutcome.BLOCKED:
            return attempt < 2
        if outcome == FetchOutcome.CF_CHALLENGE:
            return attempt < max_attempts + 2
        if outcome == FetchOutcome.RATE_LIMITED:
            return attempt < 1  # let the cooldown do the rest
        if outcome == FetchOutcome.DNS_FAIL:
            return attempt < 2
        return attempt < max_attempts

    def next_escalation(self, outcome: FetchOutcome,
                        attempt: int) -> dict:
        """Decide what to change on retry."""
        plan = {"rotate_ua": False, "rotate_tls": False,
                "rotate_proxy": False, "fresh_session": False}
        if outcome in (FetchOutcome.BLOCKED, FetchOutcome.CF_CHALLENGE):
            plan["rotate_ua"] = True
            plan["rotate_tls"] = True
            plan["rotate_proxy"] = True
            if attempt >= 2:
                plan["fresh_session"] = True
        elif outcome in (FetchOutcome.RATE_LIMITED, FetchOutcome.HTTP_5XX):
            plan["rotate_proxy"] = True
            if attempt >= 2:
                plan["rotate_ua"] = True
        elif outcome in (FetchOutcome.TIMEOUT, FetchOutcome.CONN_FAIL):
            plan["fresh_session"] = True
            if attempt >= 1:
                plan["rotate_proxy"] = True
        return plan

    def dead_letter(self, url: str, outcome: FetchOutcome,
                    reason: str) -> None:
        self.mgr.warnings.warn(
            code=f"dead_letter_{outcome.value}",
            severity=WarningSeverity.MEDIUM,
            message=f"Giving up on {url}: {reason}",
            context={"url": url, "outcome": outcome.value},
        )

    def stats(self) -> dict:
        return {"total_classified": self._total_classified()}

    def _total_classified(self) -> int:
        return self.crawler.stats.get("errors", 0)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 6: Optimization Centers (10)
# ════════════════════════════════════════════════════════════════════════════

class OptimizerBase(ABC):
    name: str = "base"
    interval: float = 30.0

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.log = crawler.log
        self._last_run = 0.0
        self._applied = 0

    def should_run(self) -> bool:
        return (_now() - self._last_run) >= self.interval

    @abstractmethod
    async def optimize(self) -> None: ...

    async def tick(self) -> None:
        if not self.should_run():
            return
        self._last_run = _now()
        try:
            await self.optimize()
        except Exception as e:
            self.crawler.mgr.errors.record_exception(
                e, category=ErrorCategory.INTERNAL,
                context={"optimizer": self.name},
            )

    def stats(self) -> dict:
        return {"name": self.name, "applied": self._applied,
                "interval": self.interval}


class ConcurrencyOptimizer(OptimizerBase):
    name = "concurrency"
    interval = 20.0

    async def optimize(self) -> None:
        stats = self.crawler.stats
        cfg = self.crawler.config
        if not cfg.adaptive_concurrency:
            return
        fetched = stats.get("fetched", 0)
        errors = stats.get("errors", 0)
        if fetched < 100:
            return
        err_rate = errors / max(1, fetched)
        if err_rate < 0.01 and cfg.concurrency < 4000:
            new_c = min(4000, int(cfg.concurrency * 1.2))
            if new_c != cfg.concurrency:
                cfg.concurrency = new_c
                self.crawler._resize_workers(new_c)
                self._applied += 1
                self.log.info("Optimizer: concurrency → %d", new_c)
        elif err_rate > 0.10 and cfg.concurrency > 20:
            new_c = max(20, int(cfg.concurrency * 0.7))
            if new_c != cfg.concurrency:
                cfg.concurrency = new_c
                self.crawler._resize_workers(new_c)
                self._applied += 1
                self.log.info("Optimizer: concurrency → %d (errors)", new_c)


class RateOptimizer(OptimizerBase):
    name = "rate"
    interval = 15.0

    async def optimize(self) -> None:
        cfg = self.crawler.config
        if not cfg.adaptive_rate_limit:
            return
        rep = self.crawler.health.report()
        if rep.aggregate_success_rate > 0.98 and \
                rep.aggregate_health_score > 85:
            for d, h in self.crawler.health._domains.items():
                if h.status == HealthStatus.HEALTHY:
                    self.crawler.rate_limiter.boost(d, 1.1)
                    self._applied += 1
        elif rep.aggregate_success_rate < 0.7:
            for d in self.crawler.health._domains:
                self.crawler.rate_limiter.reduce(d, 0.7)
            self._applied += 1


class CacheOptimizer(OptimizerBase):
    name = "cache"
    interval = 45.0

    async def optimize(self) -> None:
        stats = self.crawler.mgr.cache.stats()
        for tier, s in stats.items():
            if s["hits"] + s["misses"] > 500 and s["hit_rate"] < 0.2:
                try:
                    new_max = max(100, (s["size"] or 100) * 2)
                    self.crawler.mgr.cache.resize(CacheTier(tier), new_max)
                    self._applied += 1
                    self.log.info("Cache optimizer: %s → %d", tier, new_max)
                except Exception:
                    pass


class MemoryOptimizer(OptimizerBase):
    name = "memory"
    interval = 30.0

    async def optimize(self) -> None:
        try:
            import psutil
        except Exception:
            return
        vm = psutil.virtual_memory()
        if vm.percent >= 92:
            self.crawler.frontier.shrink(0.5)
            self.crawler.mgr.cache.clear(CacheTier.RESPONSE)
            self.crawler.mgr.cache.clear(CacheTier.DOM)
            self._applied += 1
            self.log.warning("Memory optimizer: trimmed caches (%.0f%%)",
                             vm.percent)


class BandwidthOptimizer(OptimizerBase):
    name = "bandwidth"
    interval = 60.0

    async def optimize(self) -> None:
        stats = self.crawler.stats
        bytes_in = stats.get("bytes_in", 0)
        fetched = stats.get("fetched", 0)
        if fetched < 100:
            return
        avg = bytes_in / max(1, fetched)
        if avg > 5 * 1024 * 1024:
            self.log.info("Bandwidth optimizer: avg page %.1f MB, "
                          "lowering max_response_bytes", avg / 1024 / 1024)
            self.crawler.config.max_response_bytes = int(avg * 1.2)
            self._applied += 1


class RetryOptimizer(OptimizerBase):
    name = "retry"
    interval = 45.0

    async def optimize(self) -> None:
        errs = self.crawler.mgr.errors.snapshot()
        if len(errs) < 20:
            return
        timeouts = sum(1 for e in errs if "Timeout" in e.exception_type)
        conn = sum(1 for e in errs if "Connection" in e.exception_type)
        if timeouts > len(errs) * 0.5:
            self.crawler.config.retry_base_delay = min(
                5.0, self.crawler.config.retry_base_delay * 1.2)
            self._applied += 1
        if conn > len(errs) * 0.5:
            self.crawler.config.retry_max_attempts = min(
                8, self.crawler.config.retry_max_attempts + 1)
            self._applied += 1


class DomainOptimizer(OptimizerBase):
    name = "domain"
    interval = 30.0

    async def optimize(self) -> None:
        rep = self.crawler.health.report()
        for domain, info in rep.per_domain.items():
            if info["status"] == HealthStatus.DOWN.value:
                self.crawler.rate_limiter.set(domain, 0.2)
            elif info["status"] == HealthStatus.UNSTABLE.value:
                self.crawler.rate_limiter.set(domain, 0.5)
            elif info["status"] == HealthStatus.HEALTHY.value:
                self.crawler.rate_limiter.set(domain, 3.0)
        self._applied += 1


class PriorityOptimizer(OptimizerBase):
    name = "priority"
    interval = 60.0

    async def optimize(self) -> None:
        # Boost priority of domains with high link in-degree, low priority
        # for domains that keep failing
        for domain in list(self.crawler.health._domains.keys()):
            h = self.crawler.health._domains[domain]
            if h.status == HealthStatus.DOWN:
                self.crawler.priority_map[domain] = Priority.BACKGROUND
            elif h.status == HealthStatus.HEALTHY and \
                    h.successes > 50:
                self.crawler.priority_map[domain] = Priority.HIGH
        self._applied += 1


class SchedulingOptimizer(OptimizerBase):
    name = "scheduling"
    interval = 20.0

    async def optimize(self) -> None:
        # Ensure we're distributing across domains fairly
        rep = self.crawler.health.report()
        if rep.cross_domain_balance < 0.5 and rep.total_domains > 2:
            # find under-used domains
            counts = {d: v["successes"] + v["failures"]
                      for d, v in rep.per_domain.items()}
            if counts:
                min_c = min(counts.values())
                max_c = max(counts.values())
                if max_c > 3 * max(1, min_c):
                    for d, c in counts.items():
                        if c <= max_c * 0.3:
                            self.crawler.priority_map[d] = Priority.HIGH
                    self._applied += 1


class CompressionOptimizer(OptimizerBase):
    name = "compression"
    interval = 90.0

    async def optimize(self) -> None:
        stats = self.crawler.stats
        bytes_out = stats.get("bytes_out", 0)
        bytes_in = stats.get("bytes_in", 0)
        if bytes_in <= 0:
            return
        ratio = bytes_out / bytes_in
        if ratio > 0.5:
            cfg = self.crawler.mgr.config
            cur = cfg.get("output.compression_level", 3)
            if cur < 12:
                self.log.info("Compression optimizer suggests level %d → %d",
                              cur, cur + 3)
                self._applied += 1


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 7: Crabbers (9 crawler types)
# ════════════════════════════════════════════════════════════════════════════

class Crabber(ABC):
    """Base crawler personality. Controls strategy decisions."""
    name = "base"
    description = ""

    def __init__(self, controller: "CrawlController"):
        self.controller = controller
        self.cfg = controller.config

    @abstractmethod
    def prioritize(self, url: str, depth: int) -> float:
        """Return a priority score (lower = higher priority)."""

    def should_follow(self, url: str, depth: int) -> bool:
        if self.cfg.max_depth and depth > self.cfg.max_depth:
            return False
        return True

    def should_enqueue_sitemap(self) -> bool:
        return True

    def should_enqueue_robots_links(self) -> bool:
        return True

    def should_use_conditional_get(self) -> bool:
        return self.cfg.use_conditional_get

    def should_extract_links(self) -> bool:
        return True


class GenericCrabber(Crabber):
    name = "generic"
    description = "Default balanced crawler."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 10.0


class SitemapCrabber(Crabber):
    name = "sitemap"
    description = "Sitemap-driven crawler: seeds from sitemap.xml."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 5.0

    def should_enqueue_sitemap(self) -> bool:
        return True

    def should_enqueue_robots_links(self) -> bool:
        return False


class LinkGraphCrabber(Crabber):
    name = "link_graph"
    description = "Prioritizes pages by link in-degree."

    def prioritize(self, url: str, depth: int) -> float:
        try:
            in_d = self.controller.mgr.links.in_degree(url)
        except Exception:
            in_d = 0
        return float(depth) * 10.0 - min(50.0, in_d) * 0.5


class DepthCrabber(Crabber):
    name = "depth"
    description = "Focuses on deep pages."

    def prioritize(self, url: str, depth: int) -> float:
        # Higher depth = higher priority (invert)
        return 1000.0 - float(depth) * 50.0


class BreadthCrabber(Crabber):
    name = "breadth"
    description = "Breadth-first, shallow emphasis."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 100.0


class APICrabber(Crabber):
    name = "api"
    description = "Prefers JSON/XML endpoints."

    def prioritize(self, url: str, depth: int) -> float:
        score = float(depth) * 10.0
        path = urlparse(url).path.lower()
        if path.endswith((".json", "/json", "/api", "/v1/", "/v2/")):
            score -= 20.0
        if path.endswith((".xml", ".rss")):
            score -= 10.0
        return score


class MicroCrabber(Crabber):
    name = "micro"
    description = "Aggressive crawler for tiny sites."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 2.0

    def should_use_conditional_get(self) -> bool:
        return False


class HeavyCrabber(Crabber):
    name = "heavy"
    description = "Patient crawler for large/rate-limited sites."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 20.0

    def should_use_conditional_get(self) -> bool:
        return True


class HealthCrabber(Crabber):
    name = "health"
    description = "Only performs health checks; no content extraction."

    def prioritize(self, url: str, depth: int) -> float:
        return float(depth) * 10.0

    def should_extract_links(self) -> bool:
        return False


CRABBER_REGISTRY: dict[str, type[Crabber]] = {
    GenericCrabber.name: GenericCrabber,
    SitemapCrabber.name: SitemapCrabber,
    LinkGraphCrabber.name: LinkGraphCrabber,
    DepthCrabber.name: DepthCrabber,
    BreadthCrabber.name: BreadthCrabber,
    APICrabber.name: APICrabber,
    MicroCrabber.name: MicroCrabber,
    HeavyCrabber.name: HeavyCrabber,
    HealthCrabber.name: HealthCrabber,
}


def make_crabber(controller: "CrawlController", kind: str) -> Crabber:
    cls = CRABBER_REGISTRY.get(kind)
    if cls is None:
        raise CrawlerNotFound(f"Unknown crawler type: {kind}")
    return cls(controller)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 8: Auto subsystems
# ════════════════════════════════════════════════════════════════════════════

class AutoFetcher:
    """Wraps the fetcher to add automatic retry, impersonation rotation,
    and session refresh based on the escalation plan."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    async def fetch_with_retries(self, url: str, depth: int,
                                 source_url: Optional[str] = None
                                 ) -> Optional[FetchResult]:
        cfg = self.crawler.config
        handler = self.crawler.error_handler
        attempt = 0
        last_outcome: Optional[FetchOutcome] = None
        backoff = 0.0
        while True:
            if self.crawler.should_stop():
                return None
            if self.crawler.health.in_cooldown(_host(url)):
                raise DomainCooldown(_host(url))
            try:
                result = await self.crawler.fetcher.fetch(
                    url, source_url=source_url,
                    retry_count=attempt,
                )
            except Exception as exc:
                outcome, retryable, wait = await handler.classify(
                    url, exc=exc)
                last_outcome = outcome
                if not handler.should_retry(outcome, attempt, retryable):
                    handler.dead_letter(url, outcome, str(exc))
                    return None
                plan = handler.next_escalation(outcome, attempt)
                await self.crawler.apply_escalation(plan, url)
                backoff = wait if wait else _backoff_delay(
                    attempt, cfg.retry_base_delay, cfg.retry_max_delay)
                attempt += 1
                self.crawler.stats["retries"] += 1
                if backoff > 0:
                    await asyncio.sleep(backoff)
                continue

            outcome, retryable, wait = await handler.classify(
                url, result=result)
            if outcome == FetchOutcome.SUCCESS or \
                    outcome == FetchOutcome.NOT_MODIFIED:
                return result
            last_outcome = outcome
            if not handler.should_retry(outcome, attempt, retryable):
                handler.dead_letter(url, outcome, f"status={result.status}")
                return None
            plan = handler.next_escalation(outcome, attempt)
            await self.crawler.apply_escalation(plan, url)
            backoff = wait if wait else _backoff_delay(
                attempt, cfg.retry_base_delay, cfg.retry_max_delay)
            attempt += 1
            self.crawler.stats["retries"] += 1
            if backoff > 0:
                await asyncio.sleep(backoff)


class AutoLinker:
    """Extracts and classifies links from a parsed page."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    def extract(self, html: str, base_url: str) -> tuple[
            list[dict], list[dict]]:
        if LexborHTMLParser is None or not html:
            return [], []
        try:
            tree = LexborHTMLParser(html)
        except Exception:
            return [], []
        base_host = _host(base_url)
        base_registered = _registered_domain(base_host)
        internal: list[dict] = []
        external: list[dict] = []
        seen: set[str] = set()
        for a in tree.css("a[href]"):
            raw = a.attributes.get("href", "")
            if not raw:
                continue
            norm = _normalize_url(raw, base=base_url)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            anchor = ""
            try:
                anchor = (a.text() or "").strip()
            except Exception:
                pass
            rel = a.attributes.get("rel", "")
            title = a.attributes.get("title", "")
            target_host = _host(norm)
            target_registered = _registered_domain(target_host)
            entry = {
                "url": norm,
                "anchor_text": anchor[:512],
                "rel": rel,
                "title": title[:256],
                "target_host": target_host,
                "target_registered_domain": target_registered,
            }
            if target_registered and target_registered == base_registered:
                entry["internal"] = True
                internal.append(entry)
            else:
                entry["internal"] = False
                external.append(entry)
        return internal, external


class AutoResumer:
    """Auto-resume from checkpoint + frontier on startup."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    async def load(self) -> int:
        state = self.crawler.mgr.load_checkpoint()
        if not state:
            return 0
        seen = 0
        for item in state.get("frontier", []):
            url, depth, priority = item
            await self.crawler.frontier.push(url, depth, priority)
            seen += 1
        self.crawler.stats["dedup_hits"] += 0
        self.crawler.log.info("Auto-resume: %d URLs restored", seen)
        return seen

    async def save(self) -> None:
        snap = self.crawler.frontier.snapshot()
        await asyncio.to_thread(
            self.crawler.mgr.save_checkpoint,
            {"frontier": snap, "stats": dict(self.crawler.stats)},
        )


class AutoFresh:
    """Detects stale crawls and triggers refresh."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    def is_stale(self, domain: str, max_age_seconds: float = 86400.0
                 ) -> bool:
        try:
            info = self.crawler.mgr.domain_state.get(domain)
        except Exception:
            return True
        if not info:
            return True
        last = info.get("last_crawl") or 0.0
        return (_now() - last) > max_age_seconds

    def should_refresh(self, url: str, max_age_seconds: float = 86400.0
                       ) -> bool:
        return self.is_stale(_host(url), max_age_seconds)


class AutoCache:
    """Automatic response caching with respect to HTTP cache headers."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    def cache_key(self, url: str, method: str = "GET") -> str:
        return self.crawler.mgr.cache.make_key(method, url)

    def get(self, url: str, method: str = "GET") -> Optional[FetchResult]:
        if not self.crawler.config.use_cache:
            return None
        v = self.crawler.mgr.cache.get(
            CacheTier.RESPONSE, self.cache_key(url, method))
        return v if isinstance(v, FetchResult) else None

    def put(self, url: str, result: FetchResult,
            method: str = "GET") -> None:
        if not self.crawler.config.use_cache:
            return
        self.crawler.mgr.cache.set(
            CacheTier.RESPONSE, self.cache_key(url, method), result)


class AutoOptimizer:
    """Coordinates all optimization centers on a single tick loop."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.centers: list[OptimizerBase] = [
            ConcurrencyOptimizer(crawler),
            RateOptimizer(crawler),
            CacheOptimizer(crawler),
            MemoryOptimizer(crawler),
            BandwidthOptimizer(crawler),
            RetryOptimizer(crawler),
            DomainOptimizer(crawler),
            PriorityOptimizer(crawler),
            SchedulingOptimizer(crawler),
            CompressionOptimizer(crawler),
        ]
        self._task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._loop(),
                                         name="FaAutoOptimizer")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(5.0)
                for c in self.centers:
                    await c.tick()
            except asyncio.CancelledError:
                return
            except Exception as e:
                self.crawler.mgr.errors.record_exception(
                    e, category=ErrorCategory.INTERNAL,
                    context={"where": "auto_optimizer"},
                )

    def stats(self) -> dict:
        return {c.name: c.stats() for c in self.centers}


class AutoAdaptive:
    """Top-level adaptive tuning; coordinates rate, concurrency, and
    escalation policies based on live health report."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    async def tick(self) -> None:
        rep = self.crawler.health.report()
        cfg = self.crawler.config
        if rep.aggregate_health_score < 40:
            cfg.retry_base_delay = min(10.0, cfg.retry_base_delay * 1.1)
        elif rep.aggregate_health_score > 90:
            cfg.retry_base_delay = max(0.5, cfg.retry_base_delay * 0.95)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 9: Fetcher (curl_cffi + aiohttp)
# ════════════════════════════════════════════════════════════════════════════

class Fetcher:
    """
    Unified fetch client. Prefers curl_cffi for anti-bot resistance and
    falls back to aiohttp for throughput. Maintains per-domain sessions.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self.mgr = crawler.mgr
        self.log = crawler.log
        self.spoofer = crawler.spoofer
        self.privacy = crawler.privacy
        self.cf = crawler.cf_solver
        self.auto_cache = crawler.auto_cache
        self._curl_sessions: dict[str, Any] = {}
        self._aio_session: Optional[Any] = None
        self._lock = asyncio.Lock()

    async def close(self) -> None:
        async with self._lock:
            for s in self._curl_sessions.values():
                with suppress(Exception):
                    await s.close()
            self._curl_sessions.clear()
            if self._aio_session:
                with suppress(Exception):
                    await self._aio_session.close()
                self._aio_session = None

    async def _get_curl_session(self, profile: SpoofProfile,
                                proxy: Optional[str]) -> Any:
        key = f"{profile.impersonate}|{proxy or ''}"
        async with self._lock:
            s = self._curl_sessions.get(key)
            if s:
                return s
            if CurlAsyncSession is None:
                raise RuntimeError("curl_cffi is unavailable")
            kwargs: dict[str, Any] = {"impersonate": profile.impersonate}
            if proxy:
                kwargs["proxies"] = {"http": proxy, "https": proxy}
            try:
                s = CurlAsyncSession(**kwargs)
            except Exception:
                s = CurlAsyncSession()
            self._curl_sessions[key] = s
            return s

    async def _get_aio_session(self) -> Any:
        async with self._lock:
            if self._aio_session and not self._aio_session.closed:
                return self._aio_session
            if (ClientSession is None or ClientTimeout is None
                    or TCPConnector is None):
                raise RuntimeError("aiohttp is unavailable")
            timeout = ClientTimeout(
                total=self.crawler.config.timeout_total,
                connect=self.crawler.config.timeout_connect,
                sock_read=self.crawler.config.timeout_read,
            )
            connector = TCPConnector(limit=0, limit_per_host=0,
                                     ttl_dns_cache=300, use_dns_cache=True,
                                     ssl=False)
            self._aio_session = ClientSession(
                timeout=timeout, connector=connector,
                auto_decompress=True,
            )
            return self._aio_session

    async def fetch(self, url: str, *,
                    source_url: Optional[str] = None,
                    method: str = "GET",
                    retry_count: int = 0,
                    allow_redirects: bool = True,
                    timeout_override: Optional[float] = None,
                    record_health: bool = True,
                    extra_headers: Optional[dict] = None,
                    ) -> FetchResult:
        cfg = self.crawler.config
        domain = _host(url)

        # Cache check
        cached = self.auto_cache.get(url, method)
        if cached is not None:
            self.crawler.stats["dedup_hits"] += 1
            return replace(cached, from_cache=True)

        # Domain cooldown
        cd = self.crawler.health.in_cooldown(domain)
        if cd is not None:
            raise DomainCooldown(f"{domain} cooling down {cd:.0f}s")

        # Circuit breaker
        if self.crawler.circuit.is_open(domain):
            raise CircuitOpen(domain)

        profile = await self.spoofer.next_profile(
            domain, rotate=cfg.rotate_ua or cfg.rotate_tls)
        headers = profile.merged_headers()
        headers = self.privacy.augment_headers(url, headers, source_url)
        if extra_headers:
            headers.update(extra_headers)

        proxy = None
        if cfg.proxy_enabled and cfg.proxy_list:
            proxy = self.crawler.proxy_pool.next_for(domain)

        t0 = _now()
        result = FetchResult(
            url=url, final_url=url, status=0,
            outcome=FetchOutcome.UNKNOWN,
            used_ua=profile.user_agent,
            used_impersonate=profile.impersonate,
            used_proxy=proxy or "",
            retry_count=retry_count,
            timestamp=t0, domain=domain,
        )

        # Try curl_cffi first
        tried_curl = False
        if HAS_CURL_CFFI:
            tried_curl = True
            try:
                await self._do_curl(url, method, headers, profile, proxy,
                                    allow_redirects, result,
                                    timeout_override)
            except Exception as e:
                result.error_type = type(e).__name__
                result.error_message = str(e)[:500]
                if not HAS_AIOHTTP:
                    raise
                # Fall through to aiohttp
                try:
                    await self._do_aio(url, method, headers, proxy,
                                       allow_redirects, result,
                                       timeout_override)
                except Exception as e2:
                    result.error_type = type(e2).__name__
                    result.error_message = str(e2)[:500]
                    raise
        elif HAS_AIOHTTP:
            await self._do_aio(url, method, headers, proxy,
                               allow_redirects, result, timeout_override)
        else:
            raise FetchError("No fetch backend available")

        result.elapsed_ms = (_now() - t0) * 1000
        result.content_type = _content_type_from_headers(result.headers)
        result.content_length = len(result.body)

        # Cloudflare detection
        if cfg.cloudflare_mode != CloudflareMode.OFF:
            chal, marker = CloudflareSolver.detect_challenge(
                result.status, result.headers, result.body)
            if chal:
                self.crawler.stats["cf_challenges"] = \
                    self.crawler.stats.get("cf_challenges", 0) + 1
                solved = await self.cf.handle_challenge(
                    url, result.body, result.headers, result.status)
                if solved is None:
                    raise CloudflareChallenge(f"{url} ({marker})")

        # Update counters
        self.crawler.stats["bytes_in"] = \
            self.crawler.stats.get("bytes_in", 0) + len(result.body)

        if record_health:
            pass  # classifier handles this

        # Cache write
        if 200 <= result.status < 300 and cfg.use_cache:
            self.auto_cache.put(url, result, method)

        return result

    async def _do_curl(self, url: str, method: str, headers: dict,
                       profile: SpoofProfile, proxy: Optional[str],
                       allow_redirects: bool, result: FetchResult,
                       timeout_override: Optional[float]) -> None:
        session = await self._get_curl_session(profile, proxy)
        cfg = self.crawler.config
        timeout = timeout_override or cfg.timeout_total
        resp = await session.request(
            method, url,
            headers=headers,
            timeout=timeout,
            allow_redirects=allow_redirects,
            max_redirects=cfg.max_redirects,
        )
        result.status = int(resp.status_code)
        result.headers = dict(resp.headers)
        result.body = bytes(resp.content) if resp.content else b""
        result.body_text = resp.text if hasattr(resp, "text") else \
            result.body.decode("utf-8", "replace")
        result.final_url = str(resp.url) if hasattr(resp, "url") else url
        result.redirected = result.final_url != url
        result.used_client = "curl_cffi"

    async def _do_aio(self, url: str, method: str, headers: dict,
                      proxy: Optional[str], allow_redirects: bool,
                      result: FetchResult,
                      timeout_override: Optional[float]) -> None:
        session = await self._get_aio_session()
        cfg = self.crawler.config
        timeout = None
        if timeout_override:
            timeout = ClientTimeout(total=timeout_override,
                                    connect=cfg.timeout_connect,
                                    sock_read=cfg.timeout_read)
        async with session.request(
                method, url, headers=headers,
                allow_redirects=allow_redirects,
                max_redirects=cfg.max_redirects,
                timeout=timeout, proxy=proxy) as resp:
            result.status = resp.status
            result.headers = dict(resp.headers)
            body = await resp.read()
            if len(body) > cfg.max_response_bytes:
                raise ResponseTooLarge(
                    f"{len(body)} > {cfg.max_response_bytes}")
            result.body = body
            result.body_text = body.decode(
                resp.charset or "utf-8", "replace")
            result.final_url = str(resp.url)
            result.redirected = result.final_url != url
            result.used_client = "aiohttp"


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 10: Frontier
# ════════════════════════════════════════════════════════════════════════════

class Frontier:
    """Async priority frontier backed by an asyncio.PriorityQueue.
    Also pushes to Manager for persistence."""

    def __init__(self, crawler: "CrawlController", max_size: int = 1_000_000):
        self.crawler = crawler
        self._pq: asyncio.PriorityQueue = asyncio.PriorityQueue(
            maxsize=max_size)
        self._seen_in_queue: set[str] = set()
        self._lock = asyncio.Lock()
        self._seq = 0

    async def push(self, url: str, depth: int = 0,
                   priority: float = 500.0) -> bool:
        norm = _normalize_url(url)
        if not norm:
            return False
        async with self._lock:
            if norm in self._seen_in_queue:
                return False
            self._seen_in_queue.add(norm)
            self._seq += 1
        try:
            await self._pq.put((priority, self._seq, norm, depth))
            return True
        except asyncio.QueueFull:
            return False

    async def pop(self) -> Optional[tuple[str, int, float]]:
        try:
            priority, _seq, url, depth = await asyncio.wait_for(
                self._pq.get(), timeout=0.5)
            async with self._lock:
                self._seen_in_queue.discard(url)
            return url, depth, priority
        except asyncio.TimeoutError:
            return None
        except asyncio.QueueEmpty:
            return None

    def qsize(self) -> int:
        return self._pq.qsize()

    def empty(self) -> bool:
        return self._pq.empty()

    def snapshot(self) -> list[tuple[str, int, float]]:
        # Priority queue doesn't expose internal items; fall back to Manager
        try:
            return self.crawler.mgr.load_frontier()
        except Exception:
            return []

    def shrink(self, factor: float = 0.5) -> None:
        # Drop half the queue by re-creating
        keep: list[tuple[float, int, str, int]] = []
        try:
            while True:
                item = self._pq.get_nowait()
                keep.append(item)
        except asyncio.QueueEmpty:
            pass
        keep_count = int(len(keep) * factor)
        for item in keep[:keep_count]:
            with suppress(asyncio.QueueFull):
                self._pq.put_nowait(item)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 11: Robots cache
# ════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class RobotsRules:
    allow: list[re.Pattern] = field(default_factory=list)
    disallow: list[re.Pattern] = field(default_factory=list)
    crawl_delay: float = 0.0
    sitemaps: list[str] = field(default_factory=list)
    fetched_at: float = 0.0

    def is_allowed(self, path: str) -> bool:
        # longest-match wins; allow beats disallow on tie
        best_allow = -1
        best_disallow = -1
        for p in self.allow:
            m = p.match(path)
            if m:
                best_allow = max(best_allow, m.end())
        for p in self.disallow:
            m = p.match(path)
            if m:
                best_disallow = max(best_disallow, m.end())
        if best_disallow < 0:
            return True
        if best_allow < 0:
            return False
        return best_allow >= best_disallow


class RobotsCache:
    """Fetches, parses, and caches robots.txt per domain."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self._cache: dict[str, RobotsRules] = {}
        self._lock = asyncio.Lock()
        self._ttl = 86400.0

    async def get(self, domain: str) -> Optional[RobotsRules]:
        async with self._lock:
            r = self._cache.get(domain)
            if r and (_now() - r.fetched_at) < self._ttl:
                return r
        url = f"https://{domain}/robots.txt"
        try:
            res = await self.crawler.fetcher.fetch(
                url, allow_redirects=True, record_health=False)
            if res.status == 200:
                rules = self._parse(res.body_text)
                rules.fetched_at = _now()
                async with self._lock:
                    self._cache[domain] = rules
                return rules
        except Exception:
            pass
        async with self._lock:
            self._cache[domain] = RobotsRules(fetched_at=_now())
        return self._cache[domain]

    def _parse(self, text: str) -> RobotsRules:
        rules = RobotsRules()
        current_agent = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if ":" not in line:
                continue
            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()
            if key == "user-agent":
                current_agent = val
            elif key == "disallow" and current_agent in ("*", "fa-crab",
                                                        "FaCrab"):
                if val:
                    rules.disallow.append(
                        re.compile(re.escape(val).replace(r"\*", ".*")))
            elif key == "allow" and current_agent in ("*", "fa-crab",
                                                      "FaCrab"):
                if val:
                    rules.allow.append(
                        re.compile(re.escape(val).replace(r"\*", ".*")))
            elif key == "crawl-delay" and current_agent in ("*", "fa-crab",
                                                            "FaCrab"):
                try:
                    rules.crawl_delay = float(val)
                except ValueError:
                    pass
            elif key == "sitemap":
                rules.sitemaps.append(val)
        return rules

    async def allowed(self, url: str) -> bool:
        if not self.crawler.config.respect_robots:
            return True
        domain = _host(url)
        rules = await self.get(domain)
        if rules is None:
            return True
        path = urlparse(url).path or "/"
        return rules.is_allowed(path)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 12: Sitemap parser
# ════════════════════════════════════════════════════════════════════════════

class SitemapParser:
    """Parses sitemap.xml, sitemapindex, and gzipped sitemaps."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler

    async def discover(self, domain: str) -> list[str]:
        urls: list[str] = []
        robots = await self.crawler.robots.get(domain)
        if robots and robots.sitemaps:
            urls.extend(robots.sitemaps)
        urls.extend([
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/sitemap_index.xml",
            f"https://{domain}/sitemap-index.xml",
        ])
        return list(dict.fromkeys(urls))

    async def parse(self, url: str, max_urls: int = 50000) -> list[str]:
        try:
            res = await self.crawler.fetcher.fetch(
                url, allow_redirects=True, record_health=False)
        except Exception:
            return []
        if res.status != 200:
            return []
        body = res.body
        if url.endswith(".gz"):
            try:
                import gzip
                body = gzip.decompress(body)
            except Exception:
                return []
        text = body.decode("utf-8", "replace")
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", text)
        return locs[:max_urls]


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 13: Rate limiter (adaptive token bucket)
# ════════════════════════════════════════════════════════════════════════════

class TokenBucket:
    __slots__ = ("rate", "burst", "tokens", "last_refill", "_lock")

    def __init__(self, rate: float, burst: int):
        self.rate = max(0.01, rate)
        self.burst = max(1, burst)
        self.tokens = float(burst)
        self.last_refill = _now()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        while True:
            async with self._lock:
                now = _now()
                delta = now - self.last_refill
                self.tokens = min(self.burst,
                                  self.tokens + delta * self.rate)
                self.last_refill = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(min(wait, 5.0))

    def set_rate(self, rate: float) -> None:
        self.rate = max(0.01, rate)


class RateLimiter:
    """Per-domain token buckets."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, domain: str) -> None:
        async with self._lock:
            b = self._buckets.get(domain)
            if not b:
                b = TokenBucket(rate=2.0, burst=5)
                self._buckets[domain] = b
        await b.acquire()

    def boost(self, domain: str, factor: float = 1.1) -> None:
        b = self._buckets.get(domain)
        if b:
            b.set_rate(min(50.0, b.rate * factor))

    def reduce(self, domain: str, factor: float = 0.7) -> None:
        b = self._buckets.get(domain)
        if b:
            b.set_rate(max(0.05, b.rate * factor))

    def set(self, domain: str, rate: float) -> None:
        b = self._buckets.get(domain)
        if b:
            b.set_rate(rate)


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 14: Circuit breaker & proxy pool
# ════════════════════════════════════════════════════════════════════════════

class CircuitBreaker:
    """Per-domain circuit breaker."""

    def __init__(self, threshold: int = 15, reset_after: float = 60.0):
        self.threshold = threshold
        self.reset_after = reset_after
        self._state: dict[str, tuple[int, float]] = {}

    def record_failure(self, domain: str) -> None:
        count, _ = self._state.get(domain, (0, 0.0))
        self._state[domain] = (count + 1, _now())

    def record_success(self, domain: str) -> None:
        self._state.pop(domain, None)

    def is_open(self, domain: str) -> bool:
        entry = self._state.get(domain)
        if not entry:
            return False
        count, ts = entry
        if count < self.threshold:
            return False
        if (_now() - ts) > self.reset_after:
            self._state.pop(domain, None)
            return False
        return True


class ProxyPool:
    """Proxy rotation with health and stickiness."""

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        self._list = list(crawler.config.proxy_list)
        self._rr = 0
        self._sticky: dict[str, tuple[str, float]] = {}

    def next_for(self, domain: str) -> Optional[str]:
        if not self._list:
            return None
        sticky_window = self.crawler.config.proxy_sticky_seconds
        if sticky_window > 0:
            entry = self._sticky.get(domain)
            if entry and (_now() - entry[1]) < sticky_window:
                return entry[0]
        proxy = self._list[self._rr % len(self._list)]
        self._rr += 1
        if sticky_window > 0:
            self._sticky[domain] = (proxy, _now())
        return proxy


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 15: ScraperBridge (integration with Fa-Scraper)
# ════════════════════════════════════════════════════════════════════════════

class ScraperBridge:
    """
    Thin bridge to Fa-Scraper. Never returns JSON — always returns a
    CrawlPage with text, tokens, links, paragraphs.
    """

    def __init__(self, crawler: "CrawlController"):
        self.crawler = crawler
        try:
            scraper_module = _load_local_module(
                "Fa_Scraper", "Fa-Scraper.py")
            self._impl = getattr(scraper_module, "scrape")
        except Exception:
            self._impl = None

    def scrape(self, html: str, url: str, *,
               depth: int = 0,
               from_cache: bool = False,
               elapsed_ms: float = 0.0,
               save_raw: bool = True) -> CrawlPage:
        if self._impl:
            try:
                result = self._impl(html, url, save_raw=save_raw)
                if isinstance(result, CrawlPage):
                    result.depth = depth
                    result.from_cache = from_cache
                    result.elapsed_ms = elapsed_ms
                    return result
            except Exception as e:
                self.crawler.mgr.errors.record_exception(
                    e, category=ErrorCategory.EXTRACT, url=url)
        return self._fallback_scrape(html, url, depth=depth,
                                     from_cache=from_cache,
                                     elapsed_ms=elapsed_ms,
                                     save_raw=save_raw)

    def _fallback_scrape(self, html: str, url: str, *,
                         depth: int, from_cache: bool,
                         elapsed_ms: float, save_raw: bool) -> CrawlPage:
        """Minimal fallback extractor using selectolax directly."""
        title = ""
        text = ""
        paragraphs: tuple[str, ...] = ()
        internal: list[dict] = []
        external: list[dict] = []
        lang = ""
        content_type = "text/html"

        if html and LexborHTMLParser is not None:
            try:
                tree = LexborHTMLParser(html)
                t = tree.css_first("title")
                title = (t.text() or "").strip() if t else ""
                html_el = tree.css_first("html")
                if html_el:
                    lang = html_el.attributes.get("lang", "")
                body = tree.css_first("body")
                if body:
                    text = body.text(separator="\n")
                internal, external = self.crawler.auto_linker.extract(html, url)
            except Exception:
                pass

        if not text and html:
            text = html

        # Clean text
        cleaned = re.sub(r"[ \t]+", " ", text)
        cleaned = re.sub(r"\n{3,}", "\n\n", cleaned).strip()

        # Split into paragraphs
        raw_paras = [p.strip() for p in cleaned.split("\n\n")]
        paragraphs = tuple(p for p in raw_paras if len(p) >= 20)

        # Tokenize
        tokens = tuple(re.findall(r"\w+(?:['\u2019]\w+)?", cleaned.lower()))

        # Word stats
        if tokens:
            counter = Counter(t for t in tokens if len(t) > 1)
            if counter:
                most, _ = counter.most_common(1)[0]
                least_count = min(counter.values())
                least_candidates = [w for w, c in counter.items()
                                    if c == least_count]
                least = least_candidates[0] if least_candidates else ""
            else:
                most, least = "", ""
        else:
            most, least = "", ""

        domain = _host(url)
        return CrawlPage(
            url=url,
            final_url=url,
            domain=domain,
            status=0,
            title=title,
            language=lang or "und",
            content_type=content_type,
            text=cleaned,
            paragraphs=paragraphs,
            tokens=tokens,
            links_internal=tuple(internal),
            links_external=tuple(external),
            most_used_word=most,
            least_used_word=least,
            words_count=len(tokens),
            unique_words=len(set(tokens)),
            reading_time_seconds=len(tokens) / 200.0,
            cleaned=cleaned,
            raw_html=html if save_raw else "",
            fetched_at=_now(),
            depth=depth,
            from_cache=from_cache,
            elapsed_ms=elapsed_ms,
        )


# ════════════════════════════════════════════════════════════════════════════
# Subsystem 16: CrawlController — the engine
# ════════════════════════════════════════════════════════════════════════════

class CrawlController:
    """
    The engine. Owns workers, frontier, fetcher, health, crabbers,
    optimizers, and the state machine. Designed for high cross-domain
    throughput.
    """

    def __init__(self, mgr: Optional[Any] = None,
                 config: Optional[CrawlConfig] = None):
        self.mgr = mgr or get_manager()
        self.log = self.mgr.logger.getChild("Crawl")
        self.config = config or self._config_from_manager()

        # Subsystems
        self.health = HealthChecker(self)
        self.cf_solver = CloudflareSolver(self)
        self.spoofer = SpoofingLayer(self)
        self.privacy = PrivacyLayer(self)
        self.error_handler = CrawlErrorHandler(self)
        self.auto_fetcher = AutoFetcher(self)
        self.auto_linker = AutoLinker(self)
        self.auto_resumer = AutoResumer(self)
        self.auto_fresh = AutoFresh(self)
        self.auto_cache = AutoCache(self)
        self.auto_optimizer = AutoOptimizer(self)
        self.auto_adaptive = AutoAdaptive(self)
        self.fetcher = Fetcher(self)
        self.frontier = Frontier(self)
        self.robots = RobotsCache(self)
        self.sitemaps = SitemapParser(self)
        self.rate_limiter = RateLimiter(self)
        self.circuit = CircuitBreaker()
        self.proxy_pool = ProxyPool(self)
        self.scraper = ScraperBridge(self)

        # State
        self.state: CrawlState = CrawlState.IDLE
        self.stats: dict[str, int] = defaultdict(int)
        self.priority_map: dict[str, Priority] = {}
        self._workers: list[asyncio.Task] = []
        self._stop_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        self._started_at = 0.0
        self._domain_semaphores: dict[str, asyncio.Semaphore] = {}
        self._sem_lock = asyncio.Lock()
        self._stats_subscribers: list[Callable[[dict], None]] = []
        self._crabber: Optional[Crabber] = None
        self._current_task: Optional[asyncio.Task] = None
        self._last_report: HealthReport = HealthReport()

    # ─── config ────────────────────────────────────────────────────────

    def _config_from_manager(self) -> CrawlConfig:
        c = CrawlConfig()
        try:
            c.concurrency = int(self.mgr.config.get(
                "performance.max_concurrent_tasks", c.concurrency))
            c.per_domain_concurrency = int(self.mgr.config.get(
                "performance.max_concurrent_per_domain",
                c.per_domain_concurrency))
            c.timeout_total = float(self.mgr.config.get(
                "fetch.timeout_total_seconds", c.timeout_total))
            c.timeout_connect = float(self.mgr.config.get(
                "fetch.timeout_connect_seconds", c.timeout_connect))
            c.timeout_read = float(self.mgr.config.get(
                "fetch.timeout_read_seconds", c.timeout_read))
            c.max_response_bytes = int(self.mgr.config.get(
                "fetch.max_response_size_bytes", c.max_response_bytes))
            c.retry_max_attempts = int(self.mgr.config.get(
                "fetch.retry_max_attempts", c.retry_max_attempts))
            c.retry_base_delay = float(self.mgr.config.get(
                "fetch.retry_base_delay_ms", 1000)) / 1000.0
            c.retry_max_delay = float(self.mgr.config.get(
                "fetch.retry_max_delay_ms", 60000)) / 1000.0
            c.follow_redirects = bool(self.mgr.config.get(
                "fetch.follow_redirects", True))
            c.max_redirects = int(self.mgr.config.get(
                "fetch.max_redirects", 10))
            c.respect_robots = bool(self.mgr.config.get(
                "fetch.honor_robots_txt", True))
            c.use_conditional_get = True
        except Exception:
            pass
        return c

    # ─── public control ────────────────────────────────────────────────

    async def start(self,
                    seeds: Iterable[str],
                    *,
                    overrides: Optional[dict] = None,
                    crawler_type: Optional[str] = None) -> dict:
        """
        Start a crawl. Runs until frontier is empty or stop is called.
        Returns final stats dict.
        """
        if self.state == CrawlState.RUNNING:
            raise CrawlError("Crawl already running")

        if overrides:
            self._apply_overrides(overrides)

        self.config.start_time = _now()
        self.state = CrawlState.RUNNING
        self._stop_event.clear()
        self._pause_event.set()
        self._started_at = _now()

        kind = crawler_type or self.config.crawler_type
        self._crabber = make_crabber(self, kind)

        # Auto-resume if requested
        if overrides and overrides.get("resume"):
            await self.auto_resumer.load()

        # Seed
        seed_count = 0
        for url in seeds:
            norm = _normalize_url(url)
            if not norm:
                continue
            if self.mgr.is_seen(norm):
                continue
            self.mgr.mark_seen(norm)
            priority = self._crabber.prioritize(norm, 0)
            if await self.frontier.push(norm, depth=0, priority=priority):
                seed_count += 1
        self.log.info("Seeded %d URLs (crawler=%s)", seed_count, kind)

        # Sitemap seeds
        if self.config.use_sitemap and self._crabber.should_enqueue_sitemap():
            for url in list(seeds):
                domain = _host(url)
                if domain:
                    for sm in await self.sitemaps.discover(domain):
                        try:
                            for loc in await self.sitemaps.parse(sm):
                                norm = _normalize_url(loc)
                                if norm and not self.mgr.is_seen(norm):
                                    self.mgr.mark_seen(norm)
                                    await self.frontier.push(
                                        norm, depth=0,
                                        priority=self._crabber.prioritize(
                                            norm, 0))
                        except Exception:
                            continue

        # Background subsystems
        await self.auto_optimizer.start()
        if self.config.health_check_enabled:
            await self.health.start_background(
                self.config.health_check_interval)

        # Workers
        self._workers = [
            asyncio.create_task(self._worker(i), name=f"FaCrawlWorker-{i}")
            for i in range(self.config.concurrency)
        ]

        # Progress loop
        try:
            await self._progress_loop()
        except asyncio.CancelledError:
            pass
        finally:
            await self._shutdown()

        self.state = CrawlState.DONE
        return self.final_stats()

    async def start_async(self, seeds: Iterable[str],
                          **kwargs) -> asyncio.Task:
        self._current_task = asyncio.create_task(
            self.start(seeds, **kwargs), name="FaCrawlStart")
        return self._current_task

    async def pause(self) -> None:
        if self.state == CrawlState.RUNNING:
            self.state = CrawlState.PAUSED
            self._pause_event.clear()
            self.log.info("Crawl paused")

    async def resume(self) -> None:
        if self.state == CrawlState.PAUSED:
            self.state = CrawlState.RUNNING
            self._pause_event.set()
            self.log.info("Crawl resumed")

    async def stop(self) -> None:
        self.state = CrawlState.STOPPING
        self._stop_event.set()
        self.log.info("Crawl stopping")

    def should_stop(self) -> bool:
        if self._stop_event.is_set():
            return True
        if self.config.max_duration_seconds and \
                (_now() - self._started_at) > self.config.max_duration_seconds:
            return True
        if self.config.max_pages and \
                self.stats.get("fetched", 0) >= self.config.max_pages:
            return True
        return False

    def subscribe_stats(self, cb: Callable[[dict], None]) -> None:
        self._stats_subscribers.append(cb)

    def final_stats(self) -> dict:
        return {
            "state": self.state.value,
            "fetched": self.stats.get("fetched", 0),
            "parsed": self.stats.get("parsed", 0),
            "written": self.stats.get("written", 0),
            "errors": self.stats.get("errors", 0),
            "retries": self.stats.get("retries", 0),
            "dedup_hits": self.stats.get("dedup_hits", 0),
            "bytes_in": self.stats.get("bytes_in", 0),
            "bytes_out": self.stats.get("bytes_out", 0),
            "links_seen": self.stats.get("links_seen", 0),
            "duration_seconds": _now() - self._started_at,
            "health": asdict(self._last_report) if self._last_report else {},
            "optimizers": self.auto_optimizer.stats(),
            "cf_solver": self.cf_solver.stats(),
        }

    def stats_snapshot(self) -> dict:
        return dict(self.stats)

    async def check_health(self, domains: Sequence[str]) -> dict[str, EndpointHealth]:
        return await self.health.check_cross_domain(domains)

    def health_report(self) -> HealthReport:
        return self.health.report()

    # ─── worker loop ───────────────────────────────────────────────────

    async def _worker(self, worker_id: int) -> None:
        while not self.should_stop():
            await self._pause_event.wait()
            item = await self.frontier.pop()
            if item is None:
                if self.frontier.empty():
                    await asyncio.sleep(0.2)
                    if self.frontier.empty() and \
                            not self._has_active_workers_busy():
                        return
                continue
            url, depth, _priority = item
            await self._process_one(url, depth)

    def _has_active_workers_busy(self) -> bool:
        return self.stats.get("in_flight", 0) > 0

    async def _process_one(self, url: str, depth: int) -> None:
        domain = _host(url)
        try:
            sem = await self._get_domain_sem(domain)
            async with sem:
                self.stats["in_flight"] = self.stats.get("in_flight", 0) + 1
                try:
                    await self._fetch_and_process(url, depth)
                finally:
                    self.stats["in_flight"] = max(
                        0, self.stats.get("in_flight", 1) - 1)
        except Exception as e:
            self.mgr.errors.record_exception(
                e, category=ErrorCategory.INTERNAL, url=url,
                context={"worker": "crawl", "depth": depth},
            )

    async def _get_domain_sem(self, domain: str) -> asyncio.Semaphore:
        async with self._sem_lock:
            s = self._domain_semaphores.get(domain)
            if s is None:
                s = asyncio.Semaphore(self.config.per_domain_concurrency)
                self._domain_semaphores[domain] = s
            return s

    async def _fetch_and_process(self, url: str, depth: int) -> None:
        # Robots
        if not await self.robots.allowed(url):
            self.mgr.warnings.warn(
                code="robots_disallow", severity=WarningSeverity.LOW,
                message=f"robots.txt disallows {url}",
                context={"url": url},
            )
            self.stats["skipped"] += 1
            return

        # Rate limiter
        await self.rate_limiter.acquire(_host(url))

        # Fetch
        try:
            result = await self.auto_fetcher.fetch_with_retries(
                url, depth)
        except DomainCooldown:
            self.stats["skipped"] += 1
            return
        except Exception as e:
            self.stats["errors"] += 1
            self.mgr.errors.record_exception(
                e, category=ErrorCategory.NETWORK, url=url)
            return

        if result is None:
            self.stats["errors"] += 1
            return

        self.stats["fetched"] += 1
        self.circuit.record_success(_host(url))

        # Content checks
        ct = result.content_type or ""
        if self.config.content_types and ct and \
                not any(ct.startswith(x) for x in self.config.content_types):
            self.stats["skipped"] += 1
            return

        if not result.body:
            self.stats["skipped"] += 1
            return

        # Parse + extract
        page = self.scraper.scrape(
            result.body_text, result.final_url,
            depth=depth, from_cache=result.from_cache,
            elapsed_ms=result.elapsed_ms,
            save_raw=self.config.save_raw_html,
        )
        page.status = result.status
        page.content_type = ct or page.content_type
        self.stats["parsed"] += 1

        # Health crabber — no extraction, no links
        if isinstance(self._crabber, HealthCrabber):
            self.stats["written"] += 1
            return

        # Persist
        if not self.config.dry_run:
            try:
                self.mgr.write_record(page.to_record())
                self.stats["written"] += 1
            except Exception as e:
                self.mgr.errors.record_exception(
                    e, category=ErrorCategory.OUTPUT, url=url)

        # Link graph
        try:
            self._record_links(page)
        except Exception:
            pass

        # Enqueue new links
        if self._crabber and self._crabber.should_extract_links():
            if depth + 1 <= self.config.max_depth or not self.config.max_depth:
                for link in page.links_internal:
                    norm = link.get("url")
                    if not norm:
                        continue
                    if self.mgr.is_seen(norm):
                        self.stats["dedup_hits"] += 1
                        continue
                    if not self._passes_filters(norm):
                        continue
                    self.mgr.mark_seen(norm)
                    prio = self._crabber.prioritize(norm, depth + 1)
                    if await self.frontier.push(norm, depth + 1, prio):
                        self.stats["links_seen"] += 1

            if self.config.follow_external:
                for link in page.links_external:
                    norm = link.get("url")
                    if not norm:
                        continue
                    if self.mgr.is_seen(norm):
                        continue
                    if not self._passes_filters(norm):
                        continue
                    self.mgr.mark_seen(norm)
                    prio = self._crabber.prioritize(norm, depth + 1)
                    if await self.frontier.push(norm, depth + 1, prio):
                        self.stats["links_seen"] += 1

        # Persist domain state
        with suppress(Exception):
            self.mgr.domain_state.upsert(
                _host(url),
                last_crawl=_now(),
            )
            self.mgr.domain_state.bump(_host(url), "pages_crawled", 1)

    def _record_links(self, page: CrawlPage) -> None:
        edges: list[LinkEdge] = []
        for link in page.links_internal:
            edges.append(LinkEdge(
                source_url=page.final_url,
                target_url=link["url"],
                anchor_text=link.get("anchor_text", ""),
                rel=link.get("rel", ""),
                is_internal=True,
                discovered_at=_now(),
            ))
        for link in page.links_external:
            edges.append(LinkEdge(
                source_url=page.final_url,
                target_url=link["url"],
                anchor_text=link.get("anchor_text", ""),
                rel=link.get("rel", ""),
                is_internal=False,
                discovered_at=_now(),
            ))
        if edges:
            self.mgr.links.add_edges(edges)

    def _passes_filters(self, url: str) -> bool:
        if self.config.domain_allowlist:
            h = _host(url)
            rd = _registered_domain(h)
            if not any(h.endswith(x) or rd == x
                       for x in self.config.domain_allowlist):
                return False
        if self.config.domain_blocklist:
            h = _host(url)
            rd = _registered_domain(h)
            if any(h.endswith(x) or rd == x
                   for x in self.config.domain_blocklist):
                return False
        if self.config.regex_include:
            if not any(re.search(p, url) for p in self.config.regex_include):
                return False
        if self.config.regex_exclude:
            if any(re.search(p, url) for p in self.config.regex_exclude):
                return False
        if self.config.path_allowlist:
            path = urlparse(url).path
            if not any(path.startswith(p)
                       for p in self.config.path_allowlist):
                return False
        if self.config.path_blocklist:
            path = urlparse(url).path
            if any(path.startswith(p)
                   for p in self.config.path_blocklist):
                return False
        return True

    # ─── progress / shutdown ───────────────────────────────────────────

    async def _progress_loop(self) -> None:
        last_report = 0.0
        while not self.should_stop():
            try:
                await asyncio.sleep(0.5)
                # Adaptive tick
                await self.auto_adaptive.tick()
                # Health report every ~10s
                now = _now()
                if now - last_report > 10.0:
                    self._last_report = self.health.report()
                    last_report = now
                # Check if all workers idle + frontier empty
                if self.frontier.empty() and \
                        self.stats.get("in_flight", 0) == 0:
                    # grace period
                    await asyncio.sleep(1.5)
                    if self.frontier.empty() and \
                            self.stats.get("in_flight", 0) == 0:
                        return
            except asyncio.CancelledError:
                return
            except Exception:
                continue

    async def _shutdown(self) -> None:
        self.state = CrawlState.STOPPING
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            with suppress(Exception):
                await w
        self._workers.clear()
        await self.auto_optimizer.stop()
        await self.health.stop_background()
        await self.auto_resumer.save()
        with suppress(Exception):
            self.fetcher and await self.fetcher.close()
        self.state = CrawlState.STOPPED

    # ─── resize & escalation ───────────────────────────────────────────

    def _resize_workers(self, new_count: int) -> None:
        current = len(self._workers)
        if new_count > current:
            for i in range(current, new_count):
                self._workers.append(asyncio.create_task(
                    self._worker(i), name=f"FaCrawlWorker-{i}"))
        elif new_count < current:
            for w in self._workers[new_count:]:
                w.cancel()
            self._workers = self._workers[:new_count]

    async def apply_escalation(self, plan: dict, url: str) -> None:
        domain = _host(url)
        if plan.get("rotate_ua") or plan.get("rotate_tls"):
            await self.spoofer.next_profile(domain, rotate=True)
        if plan.get("fresh_session"):
            with suppress(Exception):
                await self.fetcher.close()
        if plan.get("rotate_proxy"):
            self.circuit.record_failure(domain)

    # ─── overrides ─────────────────────────────────────────────────────

    def _apply_overrides(self, overrides: dict) -> None:
        for k, v in overrides.items():
            if hasattr(self.config, k):
                try:
                    setattr(self.config, k, v)
                except Exception:
                    pass


# ════════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════════

_crawler: Optional[CrawlController] = None
_crawler_lock = threading.Lock()


def get_crawler(mgr: Optional[Any] = None,
                config: Optional[CrawlConfig] = None) -> CrawlController:
    global _crawler
    if _crawler is None:
        with _crawler_lock:
            if _crawler is None:
                _crawler = CrawlController(mgr=mgr, config=config)
    return _crawler


def reset_crawler() -> None:
    global _crawler
    with _crawler_lock:
        _crawler = None


# ════════════════════════════════════════════════════════════════════════════
# CLI smoke test
# ════════════════════════════════════════════════════════════════════════════

async def _smoke() -> None:
    ctl = get_crawler()
    stats = await ctl.start(["https://example.com"],
                            overrides={"max_pages": 3})
    print(stats)


if __name__ == "__main__":
    if sys.version_info >= (3, 11):
        with asyncio.Runner() as runner:
            runner.run(_smoke())
    else:
        asyncio.run(_smoke())