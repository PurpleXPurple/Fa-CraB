#!/usr/bin/env python3
"""
Fa_Crawl.py — Fa-Scrap discovery engine.

Changes in this build:
    - Cross-domain follow is ON by default. Per-domain concurrency limits
      prevent hammering any single host while allowing parallel crawling
      across many domains.
    - Per-domain queues allow fair scheduling: the scheduler can pull from
      any domain, not just the seed domain.
    - Frontier caps are tuned for high throughput: 1M seen URLs, 10k per
      domain, no artificial depth limit beyond config.
"""

from __future__ import annotations

import argparse
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import xxhash
from selectolax.lexbor import LexborHTMLParser

from State import Config

log = logging.getLogger("fa.crawl")


# ══════════════════════════════════════════════════════════════════════════════
# TYPE COERCION
# ══════════════════════════════════════════════════════════════════════════════
def _as_str(v: Any, default: str = "") -> str:
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


def _as_int(v: Any, default: int = 0,
            lo: Optional[int] = None, hi: Optional[int] = None) -> int:
    if isinstance(v, bool):
        out = int(v)
    elif isinstance(v, int):
        out = v
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
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


def _as_bool(v: Any, default: bool = False) -> bool:
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
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    if isinstance(v, (list, tuple, set, frozenset)):
        return [_as_str(x) for x in v if x is not None]
    return []


# ══════════════════════════════════════════════════════════════════════════════
# URL NORMALIZATION
# ══════════════════════════════════════════════════════════════════════════════
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*$")

_BLOCKED_HOSTS = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    "169.254.169.254", "metadata.google.internal",
})

_MAX_URL_LEN = 2048


def normalize_url(url: Any, *,
                  strip_fragments: bool = True,
                  lowercase_host: bool = True,
                  strip_default_port: bool = True,
                  follow_query_strings: bool = True) -> Optional[str]:
    s = _as_str(url).strip()
    if not s or len(s) > _MAX_URL_LEN:
        return None
    s = _CTRL_RE.sub("", s).replace(" ", "%20")
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
    bare = host.split("@")[-1].split(":")[0]
    if bare in _BLOCKED_HOSTS:
        return None
    if _looks_like_private_ip(bare):
        return None
    path = p.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    query = p.query if follow_query_strings else ""
    fragment = "" if strip_fragments else p.fragment
    try:
        return urlunsplit((scheme, host, path, query, fragment))
    except Exception:
        return None


def _looks_like_private_ip(host: str) -> bool:
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
    return (a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168) or (a == 169 and b == 254))


# ══════════════════════════════════════════════════════════════════════════════
# FRONTIER — cross-domain with per-domain queues
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
    Cross-domain frontier.

    - Global FIFO for pop() — pulls from any domain.
    - Per-domain deques for fair scheduling: pop_domain() lets the
      scheduler pick from a specific host without blocking others.
    - Dedup via xxh3_64 intdigest.
    - Soft caps on seen-set and per-domain queue.
    """

    __slots__ = ("_global", "_seen", "_per_domain", "_max_seen",
                 "_per_domain_cap", "stats", "_hash_seed")

    def __init__(self, max_seen: Optional[int] = 1_000_000,
                 per_domain_cap: Optional[int] = 10_000):
        self._global: deque[tuple[str, int]] = deque()
        self._seen: set[int] = set()
        self._per_domain: dict[str, deque[str]] = {}
        self._max_seen = _as_int(max_seen, 0, lo=0) or None
        self._per_domain_cap = _as_int(per_domain_cap, 0, lo=0) or None
        self.stats = FrontierStats()
        self._hash_seed = 0xFA5C4A70

    def _h(self, url: str) -> int:
        try:
            return xxhash.xxh3_64_intdigest(url.encode("utf-8"),
                                            seed=self._hash_seed)
        except Exception:
            return hash(url) & 0xFFFFFFFFFFFFFFFF

    def push(self, url: str, depth: int = 0) -> bool:
        norm = normalize_url(url)
        if norm is None:
            self.stats.rejected_invalid += 1
            return False
        if self._max_seen is not None and len(self._seen) >= self._max_seen:
            return False
        h = self._h(norm)
        if h in self._seen:
            self.stats.rejected_dup += 1
            return False
        self._seen.add(h)
        d = _as_int(depth, 0, lo=0)
        self._global.append((norm, d))
        host = urlsplit(norm).netloc
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
        try:
            host = urlsplit(item[0]).netloc
            dq = self._per_domain.get(host)
            if dq and dq[0] == item[0]:
                dq.popleft()
        except Exception:
            pass
        return item

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
# EXTRACTOR
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


class Extractor:
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
            if s.startswith("."))
        follow_qs = _as_bool(
            _safe_cfg(cfg, "discovery", "follow_query_strings", True))
        strip_frags = _as_bool(
            _safe_cfg(cfg, "discovery", "strip_fragments", True))
        max_per_page = _as_int(
            _safe_cfg(cfg, "discovery", "max_links_per_page", 5000),
            default=5000, lo=0, hi=50000)

        try:
            parser = LexborHTMLParser(html_s)
        except Exception:
            return []

        seen_in_page: set[int] = set()
        out: list[str] = []
        try:
            nodes = parser.css("a[href]")
        except Exception:
            return []

        for node in nodes:
            if max_per_page and len(out) >= max_per_page:
                break
            href = None
            try:
                attrs = node.attributes
                if isinstance(attrs, dict):
                    href = attrs.get("href")
            except Exception:
                href = None
            if href is None:
                continue
            href_s = _as_str(href).strip()
            if not href_s:
                continue
            low = href_s.lower()
            if low.startswith(("javascript:", "mailto:", "tel:", "data:",
                               "blob:", "file:", "ftp:", "about:",
                               "chrome:", "view-source:")):
                continue
            scheme_guess = low.split(":", 1)[0] if ":" in low[:10] else ""
            if scheme_guess and scheme_guess in skip_schemes:
                continue
            try:
                absolute = urljoin(base, href_s)
            except Exception:
                continue
            try:
                norm = normalize_url(
                    absolute,
                    strip_fragments=strip_frags,
                    follow_query_strings=follow_qs)
            except Exception:
                norm = None
            if not norm:
                continue
            try:
                path_low = urlsplit(norm).path.lower()
            except Exception:
                continue
            if skip_exts and path_low.endswith(skip_exts):
                continue
            if _looks_like_binary_extension(path_low):
                continue
            h = _fast_hash(norm)
            if h in seen_in_page:
                continue
            seen_in_page.add(h)
            out.append(norm)
        return out


def _fast_hash(s: str) -> int:
    try:
        return xxhash.xxh3_64_intdigest(s.encode("utf-8"))
    except Exception:
        return hash(s) & 0xFFFFFFFFFFFFFFFF


def _safe_cfg(cfg: Config, section: str, key: str, default: Any) -> Any:
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


# ══════════════════════════════════════════════════════════════════════════════
# POLICY — cross-domain by default
# ══════════════════════════════════════════════════════════════════════════════
class Policy:
    """
    Follow policy. Cross-domain is ON by default; only the seed domain's
    explicit config can disable it.
    """

    __slots__ = ("_cfg", "_seed_domain", "_max_depth", "_allow_external",
                 "_external_blocklist", "_path_blocklist")

    def __init__(self, cfg: Config, seed_domain: str):
        self._cfg = cfg
        self._seed_domain = _as_str(seed_domain).lower()
        self._max_depth = _as_int(
            _safe_call(cfg.max_depth_for, seed_domain, default=3),
            default=3, lo=0, hi=64)
        # Cross-domain ON by default
        self._allow_external = _as_bool(
            _safe_call(cfg.allow_external_for, seed_domain, default=True),
            default=True)
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
        if not self._allow_external and not self._is_same_domain(host):
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


def _safe_call(fn, *args, default: Any = None, **kwargs) -> Any:
    try:
        return fn(*args, **kwargs)
    except Exception:
        return default


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
    __slots__ = ("cfg", "seed_url", "seed_domain", "frontier", "policy",
                 "stats")

    def __init__(self, cfg: Config, seed_url: str):
        self.cfg = cfg
        norm_seed = normalize_url(seed_url)
        if norm_seed is None:
            norm_seed = _as_str(seed_url).strip()
        self.seed_url = norm_seed
        try:
            self.seed_domain = urlsplit(norm_seed).netloc.lower()
        except Exception:
            self.seed_domain = ""
        max_seen = _as_int(
            _safe_cfg(cfg, "discovery", "frontier_max_seen", 1_000_000),
            default=1_000_000)
        per_domain_cap = _as_int(
            _safe_cfg(cfg, "discovery", "frontier_per_domain_cap", 10_000),
            default=10_000)
        self.frontier = Frontier(
            max_seen=max_seen or None,
            per_domain_cap=per_domain_cap or None)
        try:
            self.policy = Policy(cfg, self.seed_domain)
        except Exception:
            self.policy = _NullPolicy()
        self.stats = CrawlerStats()
        if self.seed_url:
            self.frontier.push(self.seed_url, 0)

    def inject(self, html: Any, base_url: str, depth: int) -> int:
        try:
            links = Extractor.links(html, base_url, self.cfg)
        except Exception:
            self.stats.errors += 1
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
            except Exception:
                self.stats.errors += 1
                continue
        self.stats.links_added += added
        return added

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


class _NullPolicy:
    __slots__ = ("max_depth", "allow_external")
    def __init__(self):
        self.max_depth = 0
        self.allow_external = False
    def should_follow(self, url: str, depth: int) -> bool:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(
        prog="Fa_Crawl.py",
        description="Fa-Scrap discovery engine. Import only. CLI is --help only.")
    p.print_help()


if __name__ == "__main__":
    main()