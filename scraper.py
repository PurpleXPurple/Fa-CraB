import asyncio
import ctypes
import functools
import hashlib
import json
import logging
import math
import os
import re
import signal
import sys
import threading
import time
import zipfile
from array import array
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse as _up, urlunparse

from curl_cffi.requests import AsyncSession
from selectolax.lexbor import LexborHTMLParser

try:
    import tomllib
except ImportError:
    tomllib = None

try:
    import orjson

    def _dumps(obj):
        return orjson.dumps(obj)
except ImportError:
    def _dumps(obj):
        return json.dumps(obj, ensure_ascii=False).encode()

try:
    threading.stack_size(512 * 1024)
except (ValueError, RuntimeError):
    pass


@functools.lru_cache(maxsize=4096)
def urlparse(url):
    return _up(url)


shutdown_tasks = []
_last_sigint = [0.0]


@dataclass
class Config:
    seed: str = ""
    output_dir: Path = Path("data")
    session_zip: Path = Path("session.zip")
    chunk_mb: float = 20.0
    max_text_chars: int = 2_000_000
    max_links_per_page: int = 80
    workers: int = 350
    concurrency: int = 100
    per_domain_concurrency: int = 12
    per_domain_rps: float = 20.0
    per_domain_burst: float = 20.0
    timeout: float = 10.0
    max_depth: int = 6
    max_pages: int = 0
    max_queue: int = 200_000
    max_domains: int = 20_000
    max_response_bytes: int = 5_000_000
    bloom_capacity: int = 1_000_000
    bloom_error: float = 0.01
    simhash_items: int = 20_000
    protect_after: int = 3
    rate_limit_cooldown: float = 60.0
    stats_interval: float = 5.0
    log_level: str = "INFO"
    proxies: list = field(default_factory=list)
    http_version: str = ""
    impersonate: str = "chrome136"
    resume: bool = True
    parse_threads: int = min(24, os.cpu_count() or 1)
    fsync_chunks: bool = sys.platform != "win32"


@dataclass
class FetchResult:
    content: bytes
    status: int
    headers: dict
    blocked: bool
    reason: str
    error: str
    elapsed_ms: float


@dataclass
class PageData:
    title: str
    text: str
    links: list
    link_chars: int
    html_len: int


@dataclass
class QualityVerdict:
    tier: str
    reasons: list
    near_dup_hash: int = 0


class TokenBucket:
    __slots__ = ("rate", "burst", "tokens", "last")

    def __init__(self, rate, burst):
        self.rate = rate
        self.burst = burst
        self.tokens = burst
        self.last = time.monotonic()

    async def acquire(self):
        while True:
            now = time.monotonic()
            elapsed = now - self.last
            self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
            self.last = now
            if self.tokens >= 1:
                self.tokens -= 1
                return
            await asyncio.sleep((1 - self.tokens) / self.rate)


class DomainState:
    __slots__ = ("sem", "bucket", "consecutive", "protected", "cooldown_until", "active", "last_seen", "seeded")

    def __init__(self, concurrency, rps, burst):
        self.sem = asyncio.Semaphore(concurrency)
        self.bucket = TokenBucket(rps, burst)
        self.consecutive = 0
        self.protected = False
        self.cooldown_until = 0.0
        self.active = 0
        self.last_seen = time.monotonic()
        self.seeded = False


class DomainRegistry:
    __slots__ = ("_domains", "_lock", "_max", "_c", "_r", "_b", "_protect_after", "_cooldown")

    def __init__(self, max_domains, concurrency, rps, burst, protect_after, cooldown):
        self._domains = OrderedDict()
        self._lock = asyncio.Lock()
        self._max = max_domains
        self._c = concurrency
        self._r = rps
        self._b = burst
        self._protect_after = protect_after
        self._cooldown = cooldown

    async def get(self, domain):
        async with self._lock:
            if domain in self._domains:
                st = self._domains[domain]
                self._domains.move_to_end(domain)
                st.last_seen = time.monotonic()
                return st
            st = DomainState(self._c, self._r, self._b)
            self._domains[domain] = st
            self._evict()
            return st

    async def mark_blocked(self, domain):
        async with self._lock:
            st = self._domains.get(domain)
            if st:
                st.protected = True
                st.active = max(0, st.active - 1)

    async def mark_rate_limited(self, domain):
        async with self._lock:
            st = self._domains.get(domain)
            if st:
                st.cooldown_until = time.monotonic() + self._cooldown
                st.active = max(0, st.active - 1)

    async def mark_failure(self, domain):
        async with self._lock:
            st = self._domains.get(domain)
            if st:
                st.consecutive += 1
                if st.consecutive >= self._protect_after:
                    st.protected = True
                st.active = max(0, st.active - 1)

    async def mark_success(self, domain):
        async with self._lock:
            st = self._domains.get(domain)
            if st:
                st.consecutive = 0
                st.active = max(0, st.active - 1)

    def protected_count(self):
        return sum(1 for s in self._domains.values() if s.protected)

    def blocked_domains(self):
        return [d for d, st in self._domains.items() if st.protected]

    def size(self):
        return len(self._domains)

    def _evict(self):
        if len(self._domains) <= self._max:
            return
        for k in list(self._domains.keys()):
            st = self._domains[k]
            if st.active == 0 and not st.protected:
                del self._domains[k]
                if len(self._domains) <= self._max:
                    return


class BlockClassifier:
    __slots__ = ()

    def classify(self, status, headers, body):
        sample = body[:16384].lower()
        if b"captcha-delivery.com" in sample:
            return True, "datadome"
        if b"px-captcha" in sample:
            return True, "perimeterx"
        cf_mit = headers.get("cf-mitigated", "").lower()
        if cf_mit == "challenge" or b"cf_chl_opt" in sample or b"/cdn-cgi/challenge-platform/" in sample:
            return True, "cloudflare"
        if status in (403, 407, 451, 503):
            return True, f"http_{status}"
        if status == 429:
            return True, "rate_limit"
        for phrase in (b"just a moment", b"attention required", b"verify you are human", b"enable javascript and cookies"):
            if phrase in sample:
                return True, "challenge_body"
        return False, ""


DROP_SELECTOR = (
    "script,style,noscript,svg,iframe,head,nav,footer,aside,form,button,input,"
    "select,textarea,canvas,template,object,embed,video,audio"
)

BOILER_SELECTOR = (
    '[class*="navbar"],[id*="navbar"],[class*="nav-menu"],[id*="nav-menu"],'
    '[class*="navigation"],[id*="navigation"],[class*="site-nav"],[id*="site-nav"],'
    '[class*="menu"],[id*="menu"],[class*="footer"],[id*="footer"],'
    '[class*="sidebar"],[id*="sidebar"],[class*="comment"],[id*="comment"],'
    '[class*="share"],[id*="share"],[class*="social"],[id*="social"],'
    '[class*="cookie"],[id*="cookie"],[class*="banner"],[id*="banner"],'
    '[class*="advert"],[id*="advert"],[class*="promo"],[id*="promo"],'
    '[class*="popup"],[id*="popup"],[class*="modal"],[id*="modal"],'
    '[class*="breadcrumb"],[id*="breadcrumb"],[class*="pagination"],[id*="pagination"]'
)

COMBINED_SELECTOR = DROP_SELECTOR + "," + BOILER_SELECTOR

WS_RE = re.compile(r"\s+")
JS_RESIDUE_RE = re.compile(r"function|var |let |const |document\.|window\.|=>\{|addEventListener", re.IGNORECASE)
WORD_RE = re.compile(r"[A-Za-z\u00C0-\u024F]{2,}")
TOKEN_RE = re.compile(r"[A-Za-z\u00C0-\u024F']+")
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?。！？])\s+")
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>")
ROBOTS_SITEMAP_RE = re.compile(r"^\s*sitemap:\s*(\S+)", re.IGNORECASE | re.MULTILINE)
ARCHIVE_HUB_RE = re.compile(r"/\d{4}/\d{2}/?$")

TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "mc_cid", "mc_eid", "ref", "source", "campaign",
}
SKIP_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".mp3", ".mp4", ".avi",
    ".mov", ".webm", ".woff", ".woff2", ".ttf", ".eot", ".css", ".js", ".json",
    ".xml", ".rss", ".atom", ".exe", ".dmg", ".iso",
}
SKIP_PATH = {
    "/login", "/signin", "/signup", "/register", "/cart", "/checkout",
    "/wp-admin", "/wp-login", "/feed", "/rss", "/sitemap", "/robots.txt",
    "/cdn-cgi/", "/.well-known/", "/account", "/profile", "/settings",
}
STOPWORDS = frozenset(
    "a an the and or but if while of to in on at by for with about against "
    "between into through during before after above below from up down out "
    "off over under again further then once here there when where why how all "
    "any both each few more most other some such no nor not only own same so "
    "than too very can will just should now is are was were be been being have "
    "has had having do does did doing i you he she it we they me him her us them "
    "my your his its our their this that these those".split()
)

_POSIX_ADVISE = None


def _init_fadvise():
    global _POSIX_ADVISE
    if sys.platform == "win32":
        return
    for lib in ("libc.so.6", "libc.dylib", "libc.so"):
        try:
            _POSIX_ADVISE = ctypes.CDLL(lib).posix_fadvise
            return
        except (OSError, AttributeError):
            continue


def _fadvise(fd, advice):
    if _POSIX_ADVISE is None:
        return
    try:
        _POSIX_ADVISE(fd, 0, 0, advice)
    except Exception:
        pass


def _open_fd_count():
    if sys.platform == "win32":
        return -1
    try:
        return len(os.listdir("/proc/self/fd"))
    except OSError:
        return -1


class PageParser:
    __slots__ = ("_max_links", "_max_text")

    def __init__(self, max_links, max_text):
        self._max_links = max_links
        self._max_text = max_text

    def parse(self, html, base_url):
        try:
            tree = LexborHTMLParser(html)
        except Exception:
            return PageData("", "", [], 0, len(html) if html else 0)

        title = ""
        for sel in ("title", "h1", "h2"):
            try:
                node = tree.css_first(sel)
            except Exception:
                continue
            if node:
                t = node.text(strip=True)
                if t:
                    title = t[:300]
                    break

        links = []
        seen = set()
        link_chars = 0

        try:
            if tree.root is not None:
                node_iter = tree.root.iter()
                filter_tag = True
            else:
                node_iter = tree.css("a[href]")
                filter_tag = False
        except (AttributeError, Exception):
            try:
                node_iter = tree.css("a[href]")
            except Exception:
                node_iter = []
            filter_tag = False

        for node in node_iter:
            if filter_tag and node.tag != "a":
                continue
            href = node.attributes.get("href") or ""
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            try:
                resolved = urljoin(base_url, href)
            except ValueError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            links.append(resolved)
            try:
                link_chars += len(node.text(strip=True))
            except Exception:
                pass
            if len(links) >= self._max_links:
                break

        try:
            for node in tree.css(COMBINED_SELECTOR):
                if node.parent is not None:
                    node.decompose()
        except Exception:
            pass

        body = tree.body
        if body is None:
            body = tree.root
        try:
            text = body.text(separator=" ", strip=True) if body is not None else ""
        except Exception:
            text = ""
        text = WS_RE.sub(" ", text).strip()
        if len(text) > self._max_text:
            text = text[: self._max_text]
        return PageData(title, text, links, link_chars, len(html))


class QualityGate:
    __slots__ = ("_simhash_index", "_simhash_bands", "_simhash_max", "_lock")

    def __init__(self, simhash_items):
        self._simhash_index = OrderedDict()
        self._simhash_bands = [{} for _ in range(4)]
        self._simhash_max = simhash_items
        self._lock = threading.Lock()

    def check(self, text, link_chars, html_len):
        if len(text) < 150:
            return QualityVerdict("rejected", ["empty"])

        reasons = []
        near_dup_hash = 0

        head = text[:10240]
        alnum = sum(1 for c in head if c.isalnum())
        if alnum / max(1, len(head)) < 0.32:
            reasons.append("low_alnum")
        if JS_RESIDUE_RE.search(head):
            reasons.append("js_residue")
        if head.count("<") > 5 or head.count("{") > 15:
            reasons.append("code_residue")

        words = WORD_RE.findall(head)
        if len(words) < 30:
            reasons.append("few_words")
        elif len(set(words)) / len(words) < 0.16:
            reasons.append("low_uniqueness")

        sentences = [s for s in SENTENCE_SPLIT_RE.split(text) if len(s) > 10]
        if len(sentences) < 2:
            reasons.append("few_sentences")
        else:
            mean_len = sum(len(s) for s in sentences) / len(sentences)
            if not (15 <= mean_len <= 500):
                reasons.append("sentence_len")

        token_count = 0
        stop_count = 0
        for m in TOKEN_RE.finditer(text):
            token_count += 1
            if m.group().lower() in STOPWORDS:
                stop_count += 1
        if token_count == 0:
            reasons.append("no_tokens")
        else:
            stop_ratio = stop_count / token_count
            if not (0.04 <= stop_ratio <= 0.55):
                reasons.append("stopword_ratio")

        if link_chars / max(1, len(text)) > 0.40:
            reasons.append("link_heavy")
        if len(text) / max(1, html_len) < 0.01:
            reasons.append("low_text_html")

        sh = self._simhash(text[:6000])
        match = self._near_dup(sh)
        if match is not None:
            reasons.append("near_duplicate")
            near_dup_hash = match

        hard = [r for r in reasons if r != "near_duplicate"]
        if len(hard) >= 4:
            return QualityVerdict("rejected", reasons, near_dup_hash)
        if reasons:
            return QualityVerdict("flagged", reasons, near_dup_hash)
        return QualityVerdict("good", [], 0)

    @staticmethod
    def _simhash(text):
        v = [0] * 32
        count = 0
        for m in TOKEN_RE.finditer(text.lower()):
            if count >= 2000:
                break
            count += 1
            token = m.group()
            h = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "little")
            for i in range(32):
                if h & (1 << i):
                    v[i] += 1
                else:
                    v[i] -= 1
        out = 0
        for i in range(32):
            if v[i] > 0:
                out |= 1 << i
        return out

    def _near_dup(self, sh):
        with self._lock:
            for band in range(4):
                key = (sh >> (band * 8)) & 0xFF
                bucket = self._simhash_bands[band].get(key)
                if bucket is not None:
                    for other in bucket:
                        if bin(sh ^ other).count("1") <= 2:
                            return other
            for band in range(4):
                key = (sh >> (band * 8)) & 0xFF
                if key not in self._simhash_bands[band]:
                    self._simhash_bands[band][key] = array("I")
                self._simhash_bands[band][key].append(sh)
            self._simhash_index[sh] = None
            if len(self._simhash_index) > self._simhash_max:
                old, _ = self._simhash_index.popitem(last=False)
                for band in range(4):
                    k = (old >> (band * 8)) & 0xFF
                    lst = self._simhash_bands[band].get(k)
                    if lst is not None:
                        try:
                            lst.remove(old)
                        except ValueError:
                            pass
                        if not lst:
                            del self._simhash_bands[band][k]
            return None


class BloomFilter:
    __slots__ = ("_bits", "_m", "_k")

    def __init__(self, capacity, error):
        m = max(64, int(-capacity * math.log(error) / (math.log(2) ** 2)))
        m = ((m + 63) // 64) * 64
        k = max(1, int(m / capacity * math.log(2)))
        self._bits = array("Q", [0]) * (m // 64)
        self._m = m
        self._k = k

    def _hashes(self, item):
        b = item.encode() if isinstance(item, str) else item
        h1 = int.from_bytes(hashlib.blake2b(b, digest_size=8).digest(), "little")
        h2 = int.from_bytes(hashlib.blake2b(b, digest_size=8, key=b"nexus").digest(), "little") | 1
        return h1, h2

    def add(self, item):
        h1, h2 = self._hashes(item)
        for i in range(self._k):
            pos = (h1 + i * h2) % self._m
            self._bits[pos >> 6] |= 1 << (pos & 63)

    def __contains__(self, item):
        h1, h2 = self._hashes(item)
        for i in range(self._k):
            pos = (h1 + i * h2) % self._m
            if not (self._bits[pos >> 6] & (1 << (pos & 63))):
                return False
        return True


class Frontier:
    __slots__ = ("_priorities", "_seqs", "_depths", "_urls", "_cond", "_bloom", "_outstanding", "_closed", "_registry", "_stats", "_max_queue")

    def __init__(self, capacity, error, registry, stats, max_queue):
        self._priorities = array("i")
        self._seqs = array("Q")
        self._depths = array("H")
        self._urls = []
        self._cond = asyncio.Condition()
        self._bloom = BloomFilter(capacity, error)
        self._outstanding = 0
        self._closed = False
        self._registry = registry
        self._stats = stats
        self._max_queue = max_queue

    def _less(self, i, j):
        pi = self._priorities[i]
        pj = self._priorities[j]
        if pi != pj:
            return pi < pj
        return self._seqs[i] < self._seqs[j]

    def _swap(self, i, j):
        self._priorities[i], self._priorities[j] = self._priorities[j], self._priorities[i]
        self._seqs[i], self._seqs[j] = self._seqs[j], self._seqs[i]
        self._depths[i], self._depths[j] = self._depths[j], self._depths[i]
        self._urls[i], self._urls[j] = self._urls[j], self._urls[i]

    def _sift_up(self, i):
        while i > 0:
            parent = (i - 1) // 2
            if self._less(i, parent):
                self._swap(i, parent)
                i = parent
            else:
                break

    def _sift_down(self, i):
        n = len(self._priorities)
        while True:
            left = 2 * i + 1
            right = 2 * i + 2
            smallest = i
            if left < n and self._less(left, smallest):
                smallest = left
            if right < n and self._less(right, smallest):
                smallest = right
            if smallest == i:
                break
            self._swap(i, smallest)
            i = smallest

    def _heap_push(self, priority, url, depth):
        self._priorities.append(priority)
        self._seqs.append(self._seq_counter())
        self._urls.append(url)
        self._depths.append(depth)
        self._sift_up(len(self._priorities) - 1)

    def _seq_counter(self):
        return self._seqs[-1] + 1 if len(self._seqs) else 0

    def _heap_pop(self):
        n = len(self._priorities)
        if n == 0:
            return None
        url = self._urls[0]
        depth = self._depths[0]
        if n > 1:
            self._priorities[0] = self._priorities[n - 1]
            self._seqs[0] = self._seqs[n - 1]
            self._urls[0] = self._urls[n - 1]
            self._depths[0] = self._depths[n - 1]
        self._priorities.pop()
        self._seqs.pop()
        self._urls.pop()
        self._depths.pop()
        if n > 1:
            self._sift_down(0)
        return url, depth

    def _heap_clear(self):
        n = len(self._priorities)
        self._priorities = array("i")
        self._seqs = array("Q")
        self._depths = array("H")
        self._urls = []
        return n

    async def push_many(self, urls, depth, discovery=False):
        if not urls:
            return
        normalized = []
        for url in urls:
            u = self._normalize(url, discovery)
            if not u:
                continue
            bloom_key = u.lower()
            if bloom_key in self._bloom:
                self._stats.dedup += 1
                continue
            host = (urlparse(u).hostname or "").removeprefix("www.")
            state = await self._registry.get(host)
            if state.protected or state.cooldown_until > time.monotonic():
                continue
            priority = depth * 10
            path = urlparse(u).path.lower()
            if any(p in path for p in ("article", "news", "blog", "post", "story", "docs", "wiki", "guide")):
                priority -= 6
            if any(p in path for p in ("tag", "category", "archive", "page/")) or "page=" in u:
                priority += 4
            if "/?p=" in u or "/index.php?p=" in u:
                priority += 8
            if len(path) < 20:
                priority -= 3
            if len(path) > 100:
                priority += 3
            if urlparse(u).query:
                priority += 2
            priority += min(state.consecutive * 4, 40)
            normalized.append((priority, u, bloom_key, depth))

        if not normalized:
            return
        async with self._cond:
            if self._closed:
                return
            pushed = 0
            for priority, u, bloom_key, d in normalized:
                if len(self._priorities) >= self._max_queue:
                    break
                self._bloom.add(bloom_key)
                self._heap_push(priority, u, d)
                self._outstanding += 1
                pushed += 1
            if pushed:
                self._cond.notify(pushed)

    def _normalize(self, url, discovery=False):
        try:
            p = urlparse(url.strip())
        except ValueError:
            return None
        if p.scheme not in ("http", "https"):
            return None
        host = (p.hostname or "").lower()
        if not host:
            return None
        host = sys.intern(host.removeprefix("www."))
        port = p.port
        if port and port not in (80, 443):
            netloc = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        else:
            netloc = f"[{host}]" if ":" in host else host
        path = re.sub(r"/{2,}", "/", p.path or "/")
        if not path:
            path = "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        if not discovery:
            if any(path.endswith(ext) for ext in SKIP_EXT):
                return None
            if any(path.startswith(sp) for sp in SKIP_PATH):
                return None
            if ARCHIVE_HUB_RE.search(path):
                return None
        q = [(k, v) for k, v in parse_qsl(p.query) if k not in TRACKING_PARAMS]
        q.sort()
        query = urlencode(q)
        return urlunparse((p.scheme, netloc, path, "", query, ""))

    async def pop(self):
        async with self._cond:
            while not self._priorities and not self._closed:
                await self._cond.wait()
            if not self._priorities:
                return None
            return self._heap_pop()

    async def done(self):
        async with self._cond:
            if self._outstanding > 0:
                self._outstanding -= 1
            if self._outstanding < 0:
                self._outstanding = 0
            if self._outstanding <= 0 and len(self._priorities) == 0:
                self._closed = True
                self._cond.notify_all()

    async def join(self):
        async with self._cond:
            while self._outstanding > 0 or len(self._priorities) > 0:
                await self._cond.wait()

    async def close(self):
        async with self._cond:
            if self._closed:
                return
            dropped = self._heap_clear()
            self._outstanding -= dropped
            if self._outstanding < 0:
                self._outstanding = 0
            self._closed = True
            self._cond.notify_all()

    def queue_size(self):
        return len(self._priorities)


class ChunkWriter:
    __slots__ = ("_dir", "_max_bytes", "_fsync", "_include_quality", "_lazy", "_opened", "_fd", "_tmp", "_final", "_file_bytes", "_count", "_total", "_index", "_lock", "_log")

    def __init__(self, output_dir, chunk_mb, fsync, include_quality=False, lazy=False):
        self._dir = Path(output_dir)
        self._max_bytes = int(chunk_mb * 1024 * 1024)
        self._fsync = fsync
        self._include_quality = include_quality
        self._lazy = lazy
        self._opened = False
        self._index = 0
        self._total = 0
        self._lock = threading.Lock()
        self._log = logging.getLogger("scraper")
        self._dir.mkdir(parents=True, exist_ok=True)
        for f in self._dir.glob("*.tmp"):
            try:
                f.unlink()
            except OSError:
                pass
        if not lazy:
            self._open_new()
        else:
            self._fd = -1
            self._tmp = None
            self._final = None
            self._file_bytes = 0
            self._count = 0

    def _open_new(self):
        self._tmp = self._dir / f"chunk_{self._index:05d}.json.tmp"
        self._final = self._dir / f"chunk_{self._index:05d}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        if sys.platform == "win32":
            flags |= os.O_BINARY
        self._fd = os.open(self._tmp, flags, 0o644)
        _fadvise(self._fd, 2)
        os.write(self._fd, b"[")
        self._file_bytes = 1
        self._count = 0
        self._opened = True

    def add(self, title, text, quality=None, near_dup_hash=None):
        if not self._opened:
            self._open_new()
        record = {"title": title[:300], "text": text}
        if self._include_quality:
            record["quality"] = quality or ""
            if near_dup_hash:
                record["near_dup_of"] = near_dup_hash
        blob = _dumps(record)
        sep = b"," if self._count > 0 else b""
        needed = len(blob) + len(sep) + 1
        if self._file_bytes + needed > self._max_bytes:
            self._finalize()
            self._open_new()
            sep = b""
            needed = len(blob) + 1
        with self._lock:
            try:
                os.write(self._fd, sep + blob)
            except OSError as e:
                self._log.error("chunk write failed: %s", e)
                return
            self._file_bytes += needed
            self._count += 1
            self._total += 1

    def _finalize(self):
        if not self._opened:
            return
        if self._count == 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            try:
                self._tmp.unlink()
            except OSError:
                pass
            self._opened = False
            self._index += 1
            return
        write_ok = True
        try:
            os.write(self._fd, b"]")
        except OSError as e:
            self._log.error("chunk close-bracket failed: %s", e)
            write_ok = False
        if self._fsync:
            try:
                os.fsync(self._fd)
            except OSError as e:
                self._log.error("chunk fsync failed: %s", e)
        try:
            os.close(self._fd)
        except OSError as e:
            self._log.error("chunk close failed: %s", e)
        if write_ok:
            try:
                os.replace(self._tmp, self._final)
            except OSError as e:
                self._log.error("chunk rename failed: %s", e)
                try:
                    self._tmp.unlink()
                except OSError:
                    pass
        else:
            try:
                self._tmp.unlink()
            except OSError:
                pass
        self._opened = False
        self._index += 1

    def close(self):
        self._finalize()


class Stats:
    __slots__ = ("ok", "flagged", "rejected", "blocked", "failed", "dedup", "bytes_in", "bytes_out", "bytes_out_flagged", "bytes_out_rejected", "fetch_ms", "parse_ms", "fetch_n", "parse_n", "start", "block_reasons", "quality_reasons")

    def __init__(self):
        self.ok = 0
        self.flagged = 0
        self.rejected = 0
        self.blocked = 0
        self.failed = 0
        self.dedup = 0
        self.bytes_in = 0
        self.bytes_out = 0
        self.bytes_out_flagged = 0
        self.bytes_out_rejected = 0
        self.fetch_ms = 0.0
        self.parse_ms = 0.0
        self.fetch_n = 0
        self.parse_n = 0
        self.start = time.monotonic()
        self.block_reasons = Counter()
        self.quality_reasons = Counter()

    def pages(self):
        return self.ok + self.flagged + self.rejected + self.blocked + self.failed


class Fetcher:
    __slots__ = ("_session", "_cfg")

    def __init__(self, cfg):
        self._session = AsyncSession(max_clients=cfg.concurrency, default_headers=True)
        self._cfg = cfg

    async def fetch(self, url):
        t0 = time.monotonic()
        kwargs = dict(
            impersonate=self._cfg.impersonate,
            timeout=self._cfg.timeout,
            allow_redirects=True,
            max_redirects=5,
            default_headers=True,
        )
        if self._cfg.proxies:
            kwargs["proxies"] = self._cfg.proxies
        if self._cfg.http_version:
            kwargs["http_version"] = self._cfg.http_version
        try:
            resp = await asyncio.wait_for(
                self._session.get(url, **kwargs),
                timeout=self._cfg.timeout + 2.0,
            )
            elapsed = (time.monotonic() - t0) * 1000
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cl_str = headers.get("content-length", "")
            if cl_str:
                try:
                    if int(cl_str) > self._cfg.max_response_bytes:
                        return FetchResult(b"", resp.status_code, headers, False, "", "oversize", elapsed)
                except ValueError:
                    pass
            content = resp.content
            if len(content) > self._cfg.max_response_bytes:
                content = content[: self._cfg.max_response_bytes]
            return FetchResult(content, resp.status_code, headers, False, "", "", elapsed)
        except asyncio.TimeoutError:
            return FetchResult(b"", 0, {}, False, "", "hard_timeout", (time.monotonic() - t0) * 1000)
        except Exception as e:
            return FetchResult(b"", 0, {}, False, "", str(e)[:200], (time.monotonic() - t0) * 1000)

    async def close(self):
        try:
            await self._session.close()
        except Exception:
            pass


class Scraper:
    __slots__ = ("cfg", "stats", "fetcher", "classifier", "parser", "gate", "registry", "frontier", "writer_good", "writer_flagged", "writer_rejected", "_log", "_recent", "_fetch_samples", "_domain_fetch", "_domain_block")

    def __init__(self, cfg):
        self.cfg = cfg
        self.stats = Stats()
        self.fetcher = Fetcher(cfg)
        self.classifier = BlockClassifier()
        self.parser = PageParser(cfg.max_links_per_page, cfg.max_text_chars)
        self.gate = QualityGate(cfg.simhash_items)
        self.registry = DomainRegistry(cfg.max_domains, cfg.per_domain_concurrency, cfg.per_domain_rps, cfg.per_domain_burst, cfg.protect_after, cfg.rate_limit_cooldown)
        self.frontier = Frontier(cfg.bloom_capacity, cfg.bloom_error, self.registry, self.stats, cfg.max_queue)
        self.writer_good = ChunkWriter(cfg.output_dir, cfg.chunk_mb, cfg.fsync_chunks, include_quality=False)
        self.writer_flagged = ChunkWriter(Path(cfg.output_dir) / "flagged", cfg.chunk_mb, cfg.fsync_chunks, include_quality=True)
        self.writer_rejected = ChunkWriter(Path(cfg.output_dir) / "rejected", cfg.chunk_mb, cfg.fsync_chunks, include_quality=True, lazy=True)
        self._log = logging.getLogger("scraper")
        self._recent = deque(maxlen=5)
        self._fetch_samples = deque(maxlen=1000)
        self._domain_fetch = Counter()
        self._domain_block = Counter()

    async def run(self, seeds):
        for u, d in seeds:
            await self.frontier.push_many([u], d)
        workers = [asyncio.create_task(self._worker()) for _ in range(max(self.cfg.workers, self.cfg.concurrency + 50))]
        stats_task = asyncio.create_task(self._stats_loop())
        try:
            await self.frontier.join()
        finally:
            await self.frontier.close()
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            stats_task.cancel()
            await asyncio.gather(stats_task, return_exceptions=True)
            self.writer_good.close()
            self.writer_flagged.close()
            self.writer_rejected.close()
            if self.cfg.resume:
                self._save_session()
            else:
                try:
                    if self.cfg.session_zip.exists():
                        self.cfg.session_zip.unlink()
                except OSError:
                    pass
            await self.fetcher.close()

    async def _worker(self):
        while True:
            item = await self.frontier.pop()
            if item is None:
                return
            url, depth = item
            try:
                await self._process(url, depth)
            except Exception as e:
                self._log.exception("worker error %s: %s", url, e)
                self.stats.failed += 1
            finally:
                await self.frontier.done()
            if self.cfg.max_pages and self.stats.pages() >= self.cfg.max_pages:
                await self.frontier.close()
                return

    def _parse_and_gate(self, html, url):
        page = self.parser.parse(html, url)
        verdict = self.gate.check(page.text, page.link_chars, page.html_len)
        return page, verdict

    async def _process_robots(self, content, url):
        text = content.decode("utf-8", errors="ignore")
        sitemaps = ROBOTS_SITEMAP_RE.findall(text)
        if sitemaps:
            await self.frontier.push_many(sitemaps[:20], 0, discovery=True)
        self.stats.ok += 1

    async def _process_sitemap(self, content, url, depth):
        text = content.decode("utf-8", errors="ignore")
        locs = SITEMAP_LOC_RE.findall(text)
        if locs:
            await self.frontier.push_many(locs[:1000], depth + 1, discovery=True)
        self.stats.ok += 1

    async def _process(self, url, depth):
        self._recent.append((depth, url))
        host = sys.intern((urlparse(url).hostname or "").removeprefix("www."))
        self._domain_fetch[host] += 1

        state = await self.registry.get(host)
        if state.protected:
            self.stats.blocked += 1
            self._domain_block[host] += 1
            return
        if state.cooldown_until > time.monotonic():
            self.stats.blocked += 1
            self._domain_block[host] += 1
            return

        if not state.seeded:
            state.seeded = True
            p = urlparse(url)
            base = f"{p.scheme}://{p.netloc}"
            await self.frontier.push_many([f"{base}/robots.txt", f"{base}/sitemap.xml"], 0, discovery=True)

        async with state.sem:
            await state.bucket.acquire()
            result = await self.fetcher.fetch(url)

        self.stats.fetch_ms += result.elapsed_ms
        self.stats.fetch_n += 1
        self._fetch_samples.append(result.elapsed_ms)

        if result.error:
            if result.error in ("hard_timeout", "impersonate", "oversize") or result.status >= 500:
                await self.registry.mark_failure(host)
            else:
                await self.registry.mark_success(host)
            self.stats.failed += 1
            return

        blocked, reason = self.classifier.classify(result.status, result.headers, result.content)
        if blocked:
            if reason == "rate_limit":
                await self.registry.mark_rate_limited(host)
            else:
                await self.registry.mark_blocked(host)
            self.stats.blocked += 1
            self._domain_block[host] += 1
            self.stats.block_reasons[reason] += 1
            return

        if not result.content or len(result.content) < 512:
            await self.registry.mark_failure(host)
            self.stats.failed += 1
            return

        await self.registry.mark_success(host)
        self.stats.bytes_in += len(result.content)

        ct = result.headers.get("content-type", "").lower()

        if url.endswith("/robots.txt"):
            await self._process_robots(result.content, url)
            return

        if "xml" in ct and "sitemap" in url.lower():
            await self._process_sitemap(result.content, url, depth)
            return

        if ct and "html" not in ct and "xhtml" not in ct:
            self.stats.failed += 1
            return

        t0 = time.monotonic()
        page, verdict = await asyncio.to_thread(self._parse_and_gate, result.content, url)
        self.stats.parse_ms += (time.monotonic() - t0) * 1000
        self.stats.parse_n += 1

        if verdict.tier == "good":
            self.writer_good.add(page.title, page.text)
            self.stats.ok += 1
            self.stats.bytes_out += len(page.text)
        elif verdict.tier == "flagged":
            self.writer_flagged.add(page.title, page.text, quality=",".join(verdict.reasons), near_dup_hash=verdict.near_dup_hash)
            self.stats.flagged += 1
            self.stats.bytes_out_flagged += len(page.text)
            for r in verdict.reasons:
                self.stats.quality_reasons[r] += 1
        else:
            self.writer_rejected.add(page.title, page.text, quality=",".join(verdict.reasons))
            self.stats.rejected += 1
            self.stats.bytes_out_rejected += len(page.text)
            for r in verdict.reasons:
                self.stats.quality_reasons[r] += 1

        if depth == 0 and len(page.links) < 5:
            p = urlparse(url)
            fallback = f"{p.scheme}://{p.netloc}/"
            if fallback != url:
                await self.frontier.push_many([fallback], depth, discovery=True)
            elif not page.links:
                self._log.warning("seed dead-end: %s produced zero links", url)

        if verdict.tier in ("good", "flagged") and depth < self.cfg.max_depth and page.links:
            await self.frontier.push_many(page.links, depth + 1)

        if self.cfg.max_pages and self.stats.pages() >= self.cfg.max_pages:
            await self.frontier.close()

    async def _stats_loop(self):
        while True:
            await asyncio.sleep(self.cfg.stats_interval)
            self._log_stats()

    def _log_stats(self):
        elapsed = max(0.001, time.monotonic() - self.stats.start)
        rate = self.stats.pages() / elapsed
        fetch_avg = self.stats.fetch_ms / max(1, self.stats.fetch_n)
        parse_avg = self.stats.parse_ms / max(1, self.stats.parse_n)
        p50 = p95 = 0.0
        if self._fetch_samples:
            sorted_samples = sorted(self._fetch_samples)
            n = len(sorted_samples)
            p50 = sorted_samples[n // 2]
            p95 = sorted_samples[min(n - 1, int(n * 0.95))]
        fds = _open_fd_count()
        self._log.info(
            "ok=%d flagged=%d rejected=%d blocked=%d failed=%d dedup=%d queue=%d domains=%d protected=%d "
            "good_chunks=%d good_records=%d flagged_chunks=%d flagged_records=%d rejected_chunks=%d rejected_records=%d "
            "rate=%.1f/s in=%.1fMB out=%.1fMB fetch=%.0fms p50_fetch=%.0fms p95_fetch=%.0fms parse=%.0fms fds=%d",
            self.stats.ok, self.stats.flagged, self.stats.rejected,
            self.stats.blocked, self.stats.failed, self.stats.dedup,
            self.frontier.queue_size(), self.registry.size(),
            self.registry.protected_count(),
            self.writer_good._index, self.writer_good._total,
            self.writer_flagged._index, self.writer_flagged._total,
            self.writer_rejected._index, self.writer_rejected._total,
            rate, self.stats.bytes_in / 1048576,
            (self.stats.bytes_out + self.stats.bytes_out_flagged + self.stats.bytes_out_rejected) / 1048576,
            fetch_avg, p50, p95, parse_avg, fds,
        )

    def _save_session(self):
        self._log_stats()
        self._log.info("block_reasons=%s", self.stats.block_reasons.most_common(10))
        self._log.info("quality_reasons=%s", self.stats.quality_reasons.most_common(12))
        self._log.info("top_domains_by_fetch=%s", self._domain_fetch.most_common(10))
        self._log.info("top_domains_by_block=%s", self._domain_block.most_common(10))
        seeds = list(self._recent)
        blocked = self.registry.blocked_domains()
        tmp = Path(str(self.cfg.session_zip) + ".tmp")
        try:
            with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr("frontier.txt", "\n".join(f"{d}\t{u}" for d, u in seeds))
                zf.writestr("meta.json", json.dumps({
                    "ok": self.stats.ok,
                    "flagged": self.stats.flagged,
                    "rejected": self.stats.rejected,
                    "blocked": self.stats.blocked,
                    "failed": self.stats.failed,
                    "pages": self.stats.pages(),
                    "blocked_domains": blocked,
                }))
            os.replace(tmp, self.cfg.session_zip)
        except Exception as e:
            self._log.error("session save failed: %s", e)
            try:
                tmp.unlink()
            except OSError:
                pass


def _load_config():
    cfg = Config()
    toml_path = Path("scraper.toml")
    if toml_path.exists() and tomllib:
        try:
            data = tomllib.loads(toml_path.read_text())
            for k, v in data.items():
                if hasattr(cfg, k):
                    if k in ("output_dir", "session_zip"):
                        v = Path(v)
                    setattr(cfg, k, v)
        except Exception as e:
            print(f"config parse error: {e}", file=sys.stderr)
    for f in Config.__dataclass_fields__:
        env = f"SCRAPER_{f.upper()}"
        if env in os.environ:
            val = os.environ[env]
            field_type = type(getattr(cfg, f))
            try:
                if field_type is bool:
                    setattr(cfg, f, val.lower() in ("1", "true", "yes"))
                elif field_type is int:
                    setattr(cfg, f, int(val))
                elif field_type is float:
                    setattr(cfg, f, float(val))
                elif field_type is Path:
                    setattr(cfg, f, Path(val))
                elif field_type is list:
                    setattr(cfg, f, [x.strip() for x in val.split(",") if x.strip()])
                else:
                    setattr(cfg, f, val)
            except (ValueError, TypeError):
                pass
    import argparse
    parser = argparse.ArgumentParser(add_help=False)
    for f in Config.__dataclass_fields__:
        flag = "--" + f.replace("_", "-")
        default = getattr(cfg, f)
        if isinstance(default, bool):
            parser.add_argument(flag, dest=f, action="store_true", default=default)
        elif isinstance(default, list):
            parser.add_argument(flag, dest=f, nargs="*", default=default)
        else:
            parser.add_argument(flag, dest=f, default=default)
    args, _ = parser.parse_known_args()
    for f in Config.__dataclass_fields__:
        v = getattr(args, f)
        if isinstance(getattr(cfg, f), Path):
            v = Path(v)
        setattr(cfg, f, v)
    cfg.concurrency = max(1, min(500, cfg.concurrency))
    if cfg.workers < cfg.concurrency + 50:
        cfg.workers = cfg.concurrency + 50
    cfg.parse_threads = max(1, min(64, cfg.parse_threads))
    return cfg


def _resolve_seeds(cfg):
    if cfg.resume and cfg.session_zip.exists():
        try:
            with zipfile.ZipFile(cfg.session_zip) as zf:
                lines = zf.read("frontier.txt").decode().splitlines()
                seeds = []
                for line in lines[:5]:
                    line = line.strip()
                    if not line:
                        continue
                    if "\t" in line:
                        d_str, u = line.split("\t", 1)
                        try:
                            d = int(d_str)
                        except ValueError:
                            d = 0
                        seeds.append((u, d))
                    else:
                        seeds.append((line, 0))
                if seeds:
                    return seeds
        except Exception:
            pass
    if cfg.seed:
        return [(cfg.seed, 0)]
    try:
        s = input("start url: ").strip()
        if s:
            return [(s, 0)]
    except EOFError:
        pass
    return []


async def main():
    cfg = _load_config()
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stderr,
    )
    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=cfg.parse_threads, thread_name_prefix="parse"))
    _init_fadvise()
    seeds = _resolve_seeds(cfg)
    if not seeds:
        print("no seed url provided", file=sys.stderr)
        return
    scraper = Scraper(cfg)
    def _shutdown():
        now = time.monotonic()
        if now - _last_sigint[0] < 2.0:
            os._exit(1)
        _last_sigint[0] = now
        shutdown_tasks.append(asyncio.create_task(scraper.frontier.close()))
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except (NotImplementedError, RuntimeError, AttributeError):
            pass
    try:
        await scraper.run(seeds)
    finally:
        for t in shutdown_tasks:
            if not t.done():
                t.cancel()
        if shutdown_tasks:
            await asyncio.gather(*shutdown_tasks, return_exceptions=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass