#!/usr/bin/env python3
"""
Fa-Crawl.py — Fa-Scrap discovery engine.

Responsibilities:
    - URL normalization and validation
    - Frontier management (global + per-domain, dedup by xxh3_64)
    - Link extraction from HTML (Selectolax Lexbor)
    - Follow policy (depth, external, category, per-domain rules)
    - Type-safe config access with sane fallbacks

Design principles:
    - Never raise on malformed input. Coerce, skip, log, continue.
    - Every config lookup validates type and clamps bounds.
    - Every URL goes through a single normalize() gate.
    - Frontier is O(1) push, O(1) pop, O(1) membership.
    - Memory bounded: seen-set can be capped, per-domain deques capped.

Import only. CLI is --help only.
"""

from __future__ import annotations

import argparse
import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit, quote, unquote

import xxhash
from selectolax.lexbor import LexborHTMLParser

from State import Config

log = logging.getLogger("fa.crawl")


# ══════════════════════════════════════════════════════════════════════════════
# TYPE-SAFE COERCION HELPERS
# ══════════════════════════════════════════════════════════════════════════════
def _as_str(v: Any, default: str = "") -> str:
    """Coerce anything to a str safely. None → default."""
    if v is None:
        return default
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return default
    try:
        return str(v)
    except Exception:
        return default


def _as_int(v: Any, default: int = 0, lo: Optional[int] = None,
            hi: Optional[int] = None) -> int:
    """Coerce to int with bounds. Rejects bool (which is an int subclass)."""
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        out = v
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):  # nan / inf
            return default
        out = int(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            out = int(s, 10)
        except ValueError:
            try:
                out = int(float(s))
            except (ValueError, OverflowError):
                return default
    else:
        return default
    if lo is not None and out < lo:
        out = lo
    if hi is not None and out > hi:
        out = hi
    return out


def _as_float(v: Any, default: float = 0.0,
              lo: Optional[float] = None,
              hi: Optional[float] = None) -> float:
    """Coerce to float with bounds. Rejects nan/inf."""
    if isinstance(v, bool):
        return float(int(v))
    if isinstance(v, (int, float)):
        out = float(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            out = float(s)
        except ValueError:
            return default
    else:
        return default
    if out != out or out in (float("inf"), float("-inf")):
        return default
    if lo is not None and out < lo:
        out = lo
    if hi is not None and out > hi:
        out = hi
    return out


def _as_bool(v: Any, default: bool = False) -> bool:
    """Coerce to bool. Handles strings like 'true'/'yes'/'1'/'on'."""
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "y", "on", "enabled"):
            return True
        if s in ("false", "0", "no", "n", "off", "disabled", ""):
            return False
        return default
    return default


def _as_list_str(v: Any) -> list[str]:
    """Coerce to list[str]. Handles comma-separated strings."""
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_as_str(x) for x in v if x is not None]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# URL NORMALIZATION & VALIDATION
# ══════════════════════════════════════════════════════════════════════════════
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*$")

# Private / loopback hosts we never crawl
_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "169.254.169.254",  # AWS metadata
    "metadata.google.internal",
})

_MAX_URL_LEN = 2048


class URLValidationError(ValueError):
    """Raised internally when a URL is definitely unparseable."""


@dataclass(slots=True, frozen=True)
class ParsedURL:
    scheme: str
    host: str       # netloc lowercase, default port stripped
    path: str
    query: str
    canonical: str  # full normalized URL


def normalize_url(url: Any,
                  *,
                  strip_fragments: bool = True,
                  lowercase_host: bool = True,
                  strip_default_port: bool = True,
                  follow_query_strings: bool = True) -> Optional[str]:
    """
    Normalize a URL for dedup and crawling.

    Returns None if the URL is invalid, too long, or a blocked host.
    Never raises.
    """
    s = _as_str(url).strip()
    if not s:
        return None
    if len(s) > _MAX_URL_LEN:
        return None
    # Strip control chars and common whitespace glue
    s = _CTRL_RE.sub("", s)
    s = s.replace(" ", "%20")
    # Reject obviously invalid schemes early
    if "://" not in s and not s.startswith("//"):
        return None
    try:
        p = urlsplit(s)
    except Exception:
        return None
    scheme = (p.scheme or "").lower()
    if scheme not in ("http", "https"):
        return None
    if not _SCHEME_RE.match(scheme):
        return None
    netloc = p.netloc
    if not netloc:
        return None
    if lowercase_host:
        netloc = netloc.lower()
    host = netloc
    if strip_default_port:
        if scheme == "http" and host.endswith(":80"):
            host = host[:-3]
        elif scheme == "https" and host.endswith(":443"):
            host = host[:-4]
    # Reject blocked hosts
    bare = host.split("@")[-1].split(":")[0]
    if bare in _BLOCKED_HOSTS:
        return None
    # Reject IP-like private ranges quickly (best-effort, no DNS)
    if _looks_like_private_ip(bare):
        return None
    path = p.path or "/"
    # Collapse duplicate slashes (except scheme://)
    path = re.sub(r"/{2,}", "/", path)
    query = p.query
    if not follow_query_strings:
        query = ""
    fragment = "" if strip_fragments else p.fragment
    try:
        return urlunsplit((scheme, host, path, query, fragment))
    except Exception:
        return None


def _looks_like_private_ip(host: str) -> bool:
    """Best-effort check for RFC1918 private IPs. No DNS resolution."""
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if not all(0 <= o <= 255 for o in octets):
        return False
    a, b = octets[0], octets[1]
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 169 and b == 254:
        return True
    return False


def parse_url(url: str) -> Optional[ParsedURL]:
    """Return structured view of a normalized URL, or None."""
    norm = normalize_url(url)
    if norm is None:
        return None
    try:
        p = urlsplit(norm)
    except Exception:
        return None
    return ParsedURL(
        scheme=p.scheme,
        host=p.netloc,
        path=p.path or "/",
        query=p.query,
        canonical=norm,
    )


# ══════════════════════════════════════════════════════════════════════════════
# FRONTIER
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(slots=True)
class FrontierStats:
    pushed: int = 0
    rejected_dup: int = 0
    rejected_invalid: int = 0
    popped: int = 0
    max_depth_seen: int = 0


class Frontier:
    """
    Deque-backed frontier.

    - Global FIFO for pop().
    - Per-domain deques for fairness-aware scheduling (future use).
    - Dedup via xxh3_64 intdigest — 8 bytes per URL.
    - Optional soft cap on seen-set to bound memory.
    """

    __slots__ = ("_global", "_seen", "_per_domain", "_max_seen",
                 "_per_domain_cap", "stats", "_hash_seed")

    def __init__(self,
                 max_seen: Optional[int] = None,
                 per_domain_cap: Optional[int] = None):
        self._global: deque[tuple[str, int]] = deque()
        self._seen: set[int] = set()
        self._per_domain: dict[str, deque[str]] = {}
        self._max_seen = _as_int(max_seen, 0, lo=0) or None
        self._per_domain_cap = _as_int(per_domain_cap, 0, lo=0) or None
        self.stats = FrontierStats()
        # Fixed seed keeps hashes stable across runs; stable across machines
        self._hash_seed = 0xFA5C4A70

    def _h(self, url: str) -> int:
        try:
            return xxhash.xxh3_64_intdigest(url.encode("utf-8"),
                                            seed=self._hash_seed)
        except Exception:
            # Extremely unlikely; fall back to Python hash truncated
            return hash(url) & 0xFFFFFFFFFFFFFFFF

    def push(self, url: str, depth: int = 0) -> bool:
        """Returns True if pushed, False if duplicate/invalid/rejected."""
        norm = normalize_url(url)
        if norm is None:
            self.stats.rejected_invalid += 1
            return False
        if self._max_seen is not None and len(self._seen) >= self._max_seen:
            # Cap reached: refuse new URLs (do NOT clear; dedup integrity matters)
            return False
        h = self._h(norm)
        if h in self._seen:
            self.stats.rejected_dup += 1
            return False
        self._seen.add(h)
        d = _as_int(depth, 0, lo=0)
        self._global.append((norm, d))
        host = ""
        try:
            host = urlsplit(norm).netloc
        except Exception:
            host = ""
        if host:
            q = self._per_domain.setdefault(host, deque())
            if self._per_domain_cap is None or len(q) < self._per_domain_cap:
                q.append(norm)
        if d > self.stats.max_depth_seen:
            self.stats.max_depth_seen = d
        self.stats.pushed += 1
        return True

    def pop(self) -> Optional[tuple[str, int]]:
        if not self._global:
            return None
        item = self._global.popleft()
        self.stats.popped += 1
        # Best-effort: mirror removal from per-domain queue
        try:
            host = urlsplit(item[0]).netloc
            dq = self._per_domain.get(host)
            if dq:
                # We don't guarantee strict order match; trim if head matches
                if dq and dq[0] == item[0]:
                    dq.popleft()
        except Exception:
            pass
        return item

    def peek(self) -> Optional[tuple[str, int]]:
        if not self._global:
            return None
        return self._global[0]

    def pop_domain(self, host: str) -> Optional[str]:
        dq = self._per_domain.get(host)
        if not dq:
            return None
        return dq.popleft()

    def __len__(self) -> int:
        return len(self._global)

    def __bool__(self) -> bool:
        return bool(self._global)

    @property
    def seen_count(self) -> int:
        return len(self._seen)

    @property
    def domain_count(self) -> int:
        return len(self._per_domain)

    def hosts(self) -> Iterator[str]:
        return iter(self._per_domain.keys())

    def clear(self) -> None:
        self._global.clear()
        self._seen.clear()
        self._per_domain.clear()
        self.stats = FrontierStats()


# ══════════════════════════════════════════════════════════════════════════════
# LINK EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
class Extractor:
    """
    Extracts links from HTML. Fully defensive: never raises on malformed HTML,
    weird attribute values, or unusual encodings.
    """

    @staticmethod
    def links(html: Any, base_url: str, cfg: Config) -> list[str]:
        html_s = _as_str(html)
        if not html_s:
            return []
        base = _as_str(base_url).strip()
        if not base:
            return []

        skip_schemes = set(s.lower() for s in _as_list_str(
            _safe_cfg(cfg, "discovery", "skip_schemes", [])))
        skip_exts = tuple(
            s.lower() for s in _as_list_str(
                _safe_cfg(cfg, "discovery", "skip_extensions", []))
            if s.startswith(".")
        )
        follow_qs = _as_bool(
            _safe_cfg(cfg, "discovery", "follow_query_strings", False))
        strip_frags = _as_bool(
            _safe_cfg(cfg, "discovery", "strip_fragments", True))
        max_per_page = _as_int(
            _safe_cfg(cfg, "discovery", "max_links_per_page", 2000),
            default=2000, lo=0, hi=50000)

        # Parse
        try:
            parser = LexborHTMLParser(html_s)
        except Exception as e:
            log.debug("extractor: lexbor parse failed: %s", e)
            return []

        seen_in_page: set[int] = set()
        out: list[str] = []
        try:
            nodes = parser.css("a[href]")
        except Exception as e:
            log.debug("extractor: css select failed: %s", e)
            try:
                del parser
            except Exception:
                pass
            return []

        for node in nodes:
            if max_per_page and len(out) >= max_per_page:
                break
            href = None
            try:
                attrs = node.attributes
                if isinstance(attrs, dict):
                    href = attrs.get("href")
                else:
                    href = None
            except Exception:
                href = None
            if href is None:
                continue
            href_s = _as_str(href).strip()
            if not href_s:
                continue
            # Cheap pre-filter before urljoin
            low = href_s.lower()
            if low.startswith(("javascript:", "mailto:", "tel:", "data:",
                               "blob:", "file:", "ftp:", "about:",
                               "chrome:", "view-source:")):
                continue
            scheme_guess = low.split(":", 1)[0] if ":" in low[:10] else ""
            if scheme_guess and scheme_guess in skip_schemes:
                continue

            # Resolve
            try:
                absolute = urljoin(base, href_s)
            except Exception:
                continue

            # Normalize with configured policy
            try:
                norm = normalize_url(
                    absolute,
                    strip_fragments=strip_frags,
                    follow_query_strings=follow_qs,
                )
            except Exception:
                norm = None
            if not norm:
                continue

            # Extension filter on the path
            try:
                path_low = urlsplit(norm).path.lower()
            except Exception:
                continue
            if skip_exts and path_low.endswith(skip_exts):
                continue
            # Reject if it looks like a file download we don't want
            if _looks_like_binary_extension(path_low):
                continue

            # Page-local dedup before hitting the frontier
            h = _fast_hash(norm)
            if h in seen_in_page:
                continue
            seen_in_page.add(h)
            out.append(norm)

        try:
            del parser
        except Exception:
            pass
        return out


# ══════════════════════════════════════════════════════════════════════════════
# FOLLOW POLICY
# ══════════════════════════════════════════════════════════════════════════════
_BINARY_HINTS = (
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico", ".bmp", ".tiff",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".mkv", ".webm", ".m4a",
    ".pdf", ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".zst",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods",
    ".exe", ".dll", ".so", ".dylib", ".dmg", ".iso", ".apk", ".deb", ".rpm",
    ".css", ".js", ".mjs", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
)


def _looks_like_binary_extension(path_low: str) -> bool:
    for ext in _BINARY_HINTS:
        if path_low.endswith(ext):
            return True
    return False


def _fast_hash(s: str) -> int:
    try:
        return xxhash.xxh3_64_intdigest(s.encode("utf-8"))
    except Exception:
        return hash(s) & 0xFFFFFFFFFFFFFFFF


class Policy:
    """
    Decides whether a link should be followed.

    Rules (in order):
        1. Same-domain: follow if depth <= max_depth_for(seed).
        2. Cross-domain: follow only if seed allows external AND
           depth <= max_depth_for(seed) AND target host isn't in a blocklist.
        3. Otherwise: reject.
    """

    __slots__ = ("_cfg", "_seed_domain", "_max_depth", "_allow_external",
                 "_external_blocklist", "_path_blocklist")

    def __init__(self, cfg: Config, seed_domain: str):
        self._cfg = cfg
        self._seed_domain = _as_str(seed_domain).lower()
        self._max_depth = _as_int(
            _safe_call(cfg.max_depth_for, seed_domain, default=3),
            default=3, lo=0, hi=32)
        self._allow_external = _as_bool(
            _safe_call(cfg.allow_external_for, seed_domain, default=False))
        # Optional blocklists pulled from discovery config
        self._external_blocklist = set(
            h.lower() for h in _as_list_str(
                _safe_cfg(cfg, "discovery", "external_blocklist", [])))
        self._path_blocklist = tuple(
            p for p in _as_list_str(
                _safe_cfg(cfg, "discovery", "path_blocklist", []))
            if p)

    def should_follow(self, url: str, depth: int) -> bool:
        d = _as_int(depth, 0, lo=0)
        if d > self._max_depth:
            return False
        try:
            host = urlsplit(url).netloc.lower()
        except Exception:
            return False
        if not host:
            return False
        if self._is_same_domain(host):
            return self._path_allowed(url)
        if not self._allow_external:
            return False
        if host in self._external_blocklist:
            return False
        if _looks_like_private_ip(host.split(":")[0]):
            return False
        return self._path_allowed(url)

    def _is_same_domain(self, host: str) -> bool:
        h = host.split(":")[0]
        s = self._seed_domain.split(":")[0]
        if h == s:
            return True
        # subdomain match: sub.example.com ~ example.com
        if h.endswith("." + s) or s.endswith("." + h):
            return True
        return False

    def _path_allowed(self, url: str) -> bool:
        if not self._path_blocklist:
            return True
        try:
            path = urlsplit(url).path.lower()
        except Exception:
            return False
        for blocked in self._path_blocklist:
            if blocked and blocked.lower() in path:
                return False
        return True

    @property
    def max_depth(self) -> int:
        return self._max_depth

    @property
    def allow_external(self) -> bool:
        return self._allow_external


# ══════════════════════════════════════════════════════════════════════════════
# CRAWLER
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(slots=True)
class CrawlerStats:
    pages_injected: int = 0
    links_seen: int = 0
    links_added: int = 0
    links_rejected_policy: int = 0
    errors: int = 0


class Crawler:
    """
    Public surface used by Fa-Scrap.py:

        crawler = Crawler(cfg, seed_url)
        crawler.inject(html, base_url, depth) -> int   # links added
        crawler.frontier                                # Frontier object

    Fully defensive: never raises. All failures logged at DEBUG.
    """

    __slots__ = ("cfg", "seed_url", "seed_domain", "frontier", "policy",
                 "stats", "_max_pages_hint")

    def __init__(self, cfg: Config, seed_url: str):
        self.cfg = cfg
        norm_seed = normalize_url(seed_url)
        if norm_seed is None:
            # Fallback to raw string; policy will reject bad follows
            norm_seed = _as_str(seed_url).strip()
        self.seed_url = norm_seed
        try:
            self.seed_domain = urlsplit(norm_seed).netloc.lower()
        except Exception:
            self.seed_domain = ""

        # Frontier caps from config (optional, best-effort)
        max_seen = _as_int(
            _safe_cfg(cfg, "discovery", "frontier_max_seen", 0), default=0)
        per_domain_cap = _as_int(
            _safe_cfg(cfg, "discovery", "frontier_per_domain_cap", 0), default=0)
        self.frontier = Frontier(
            max_seen=max_seen or None,
            per_domain_cap=per_domain_cap or None,
        )
        try:
            self.policy = Policy(cfg, self.seed_domain)
        except Exception as e:
            log.warning("crawler: policy init failed (%s); using safe defaults", e)
            self.policy = _NullPolicy()

        self.stats = CrawlerStats()
        self._max_pages_hint = _as_int(
            _safe_cfg(cfg, "discovery", "max_pages_hint", 0), default=0)

        # Seed the frontier
        if self.seed_url:
            self.frontier.push(self.seed_url, 0)

    # ── injection ────────────────────────────────────────────────────────────
    def inject(self, html: Any, base_url: str, depth: int) -> int:
        """
        Extract links from HTML and push the follow-worthy ones into the frontier.
        Returns the count of newly-added URLs.
        Never raises.
        """
        try:
            links = Extractor.links(html, base_url, self.cfg)
        except Exception as e:
            self.stats.errors += 1
            log.debug("crawler.inject: extractor failed: %s", e)
            return 0

        self.stats.links_seen += len(links)
        self.stats.pages_injected += 1
        added = 0
        next_depth = _as_int(depth, 0, lo=0) + 1

        for link in links:
            try:
                if not self.policy.should_follow(link, next_depth):
                    self.stats.links_rejected_policy += 1
                    continue
                if self.frontier.push(link, next_depth):
                    added += 1
            except Exception as e:
                self.stats.errors += 1
                log.debug("crawler.inject: push failed for %s: %s", link, e)
                continue

        self.stats.links_added += added
        return added

    # ── introspection ────────────────────────────────────────────────────────
    @property
    def pending(self) -> int:
        return len(self.frontier)

    @property
    def seen(self) -> int:
        return self.frontier.seen_count

    def summary(self) -> dict:
        return {
            "seed": self.seed_url,
            "seed_domain": self.seed_domain,
            "pending": self.pending,
            "seen": self.seen,
            "domains": self.frontier.domain_count,
            "max_depth": self.policy.max_depth,
            "allow_external": self.policy.allow_external,
            "pages_injected": self.stats.pages_injected,
            "links_seen": self.stats.links_seen,
            "links_added": self.stats.links_added,
            "links_rejected_policy": self.stats.links_rejected_policy,
            "errors": self.stats.errors,
        }


# ══════════════════════════════════════════════════════════════════════════════
# NULL POLICY (safe fallback)
# ══════════════════════════════════════════════════════════════════════════════
class _NullPolicy:
    __slots__ = ("max_depth", "allow_external")
    def __init__(self):
        self.max_depth = 0
        self.allow_external = False
    def should_follow(self, url: str, depth: int) -> bool:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG ACCESS SAFETY
# ══════════════════════════════════════════════════════════════════════════════
def _safe_cfg(cfg: Config, section: str, key: str, default: Any) -> Any:
    """Read cfg.<section> dict and return cfg[section][key], or default."""
    try:
        d = getattr(cfg, section, None)
        if d is None:
            return default
        if callable(d):
            d = d()
        if not isinstance(d, dict):
            return default
        return d.get(key, default)
    except Exception:
        return default


def _safe_call(fn, *args, default: Any = None, **kwargs) -> Any:
    """Call fn(*args); return default if it raises."""
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


# ══════════════════════════════════════════════════════════════════════════════
# CLI (--help only)
# ══════════════════════════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(
        prog="Fa-Crawl.py",
        description=(
            "Fa-Scrap discovery engine. Import only. CLI is --help only.\n\n"
            "Public API:\n"
            "    from Fa_Crawl import Crawler\n"
            "    crawler = Crawler(config, seed_url)\n"
            "    crawler.inject(html, base_url, depth)\n"
            "    url, depth = crawler.frontier.pop()"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.print_help()


if __name__ == "__main__":
    main()