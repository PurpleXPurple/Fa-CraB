#!/usr/bin/env python3
"""
Fa-Crawl.py — Discovery engine. Frontier, extractor, and follow policy.
Import only. CLI is --help only.
"""

import argparse
from collections import deque
from urllib.parse import urljoin, urlparse

import xxhash
from selectolax.lexbor import LexborHTMLParser

from State import Config, normalize_url


class Frontier:
    """Deque-backed frontier with xxh3_64 dedup. Global + per-domain views."""

    def __init__(self):
        self._global: deque[tuple[str, int]] = deque()   # (url, depth)
        self._seen: set[int] = set()
        self._per_domain: dict[str, deque[str]] = {}

    def push(self, url: str, depth: int) -> bool:
        url = normalize_url(url)
        if not url:
            return False
        h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
        if h in self._seen:
            return False
        self._seen.add(h)
        self._global.append((url, depth))
        domain = urlparse(url).netloc
        self._per_domain.setdefault(domain, deque()).append(url)
        return True

    def pop(self) -> tuple[str, int] | None:
        if not self._global:
            return None
        return self._global.popleft()

    def __len__(self):
        return len(self._global)

    @property
    def seen_count(self):
        return len(self._seen)


class Extractor:
    @staticmethod
    def links(html: str, base_url: str, cfg: Config) -> list[str]:
        skip_schemes = set(cfg.discovery.get("skip_schemes", []))
        skip_exts = tuple(cfg.discovery.get("skip_extensions", []))
        try:
            parser = LexborHTMLParser(html)
        except Exception:
            return []
        out = []
        for node in parser.css("a[href]"):
            href = node.attributes.get("href")
            if not href:
                continue
            href = href.strip()
            if not href:
                continue
            scheme = href.split(":", 1)[0].lower() if ":" in href else ""
            if scheme in skip_schemes:
                continue
            absolute = urljoin(base_url, href)
            p = urlparse(absolute)
            if p.scheme not in ("http", "https"):
                continue
            if any(p.path.lower().endswith(e) for e in skip_exts):
                continue
            if not cfg.discovery.get("follow_query_strings", False) and p.query:
                continue
            out.append(absolute)
        del parser
        return out


class Policy:
    """Decides if a discovered link should be followed. Autonomous."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def should_follow(self, url: str, depth: int, seed_domain: str) -> bool:
        domain = urlparse(url).netloc
        if domain == seed_domain:
            return depth <= self.cfg.max_depth_for(seed_domain)
        if not self.cfg.allow_external_for(seed_domain):
            return False
        return depth <= self.cfg.max_depth_for(seed_domain)