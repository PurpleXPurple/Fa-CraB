"""
Fa-Scraper — Fa-Crab's extraction engine.

Public API:
    from Fa_Scraper import scrape, Scraper, get_scraper, reset_scraper

    result = scrape(html, "https://example.com")
    result.text          # cleaned text
    result.paragraphs    # tuple of paragraphs
    result.tokens        # tuple of tokens
    result.links         # {"internal": [...], "external": [...]}
    result.most_used_word
    result.least_used_word
    result.words_count
    result.cleaned       # aggressively normalized

Never returns JSON. Always returns a rich Python object.
If Fa_Crawl is importable, `scrape()` returns a `CrawlPage` for drop-in
compatibility. Otherwise it returns a `ScrapeResult`.

Integrates with:
    Fa_Manager  — config (special site profiles), cache, errors, warnings,
                  language lists, stopwords, URL helpers.
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import base64
import contextlib
import functools
import gzip
import hashlib
import html
import importlib.util
import io
import math
import os
import re
import statistics
import string
import sys
import threading
import time
import types
import unicodedata
import zlib
from abc import ABC, abstractmethod
from collections import Counter, OrderedDict, defaultdict
from contextlib import suppress
from dataclasses import dataclass, field, asdict, replace
from datetime import datetime, timezone
from enum import Enum, auto
from typing import (
    Any, Callable, Iterable, Iterator, Mapping, Optional, Sequence, TypeAlias,
    Union,
)
from urllib.parse import (
    urljoin, urlparse, urlunparse, parse_qsl, urlencode,
)

# ─── third-party ─────────────────────────────────────────────────────────────
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
    from lxml import html as lxml_html
    import lxml.etree as lxml_etree
    HAS_LXML = True
except Exception:
    lxml_html = None  # type: ignore
    lxml_etree = None  # type: ignore
    HAS_LXML = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except Exception:
    BeautifulSoup = None  # type: ignore
    HAS_BS4 = False

try:
    import trafilatura
    HAS_TRAFILATURA = True
except Exception:
    trafilatura = None  # type: ignore
    HAS_TRAFILATURA = False

try:
    import justext
    HAS_JUSTEXT = True
except Exception:
    justext = None  # type: ignore
    HAS_JUSTEXT = False

try:
    from charset_normalizer import from_bytes as _cn_from_bytes
    HAS_CHARSET_NORMALIZER = True
except Exception:
    _cn_from_bytes = None  # type: ignore
    HAS_CHARSET_NORMALIZER = False

try:
    import regex as regex_lib
    HAS_REGEX = True
except Exception:
    regex_lib = re  # type: ignore
    HAS_REGEX = False

try:
    from tld import get_fld
    HAS_TLD = True
except Exception:
    get_fld = None  # type: ignore
    HAS_TLD = False

try:
    import pymupdf  # PyMuPDF
    HAS_PYMUPDF = True
except Exception:
    try:
        import fitz as pymupdf  # type: ignore
        HAS_PYMUPDF = True
    except Exception:
        pymupdf = None  # type: ignore
        HAS_PYMUPDF = False

try:
    from courlan import normalize_url as courlan_normalize
    HAS_COURLAN = True
except Exception:
    courlan_normalize = None  # type: ignore
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
except ImportError:  # pragma: no cover
    def get_manager(*a, **kw):  # type: ignore
        raise RuntimeError("Fa-Manager not available")
    class ErrorCategory(str, Enum):  # type: ignore
        PARSE = "parse"; EXTRACT = "extract"; INTERNAL = "internal"
        VALIDATION = "validation"; LINK = "link"
    class ErrorSeverity(int, Enum):  # type: ignore
        ERROR = 40
    class WarningSeverity(str, Enum):  # type: ignore
        LOW = "low"; MEDIUM = "medium"; HIGH = "high"
    class CacheTier(str, Enum):  # type: ignore
        DOM = "dom"; EXTRACT = "extract"; URL_NORM = "url_norm"
        LINK = "link"


__all__ = [
    "scrape", "Scraper", "get_scraper", "reset_scraper",
    "ScraperConfig", "ScrapeResult", "Metadata", "QualityReport",
    "SiteProfile", "ExtractionCandidate", "ContentKind",
    "ExtractionStrategy", "QualityTier", "LinkKind", "ScraperError",
]


# ════════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════════

SCRAPER_VERSION = "1.0.0"

CONTENT_TYPE_HTML = ("text/html", "application/xhtml+xml",
                     "application/xhtml", "text/xhtml")
CONTENT_TYPE_XML = ("application/xml", "text/xml",
                    "application/rss+xml", "application/atom+xml")
CONTENT_TYPE_JSON = ("application/json", "application/ld+json",
                     "application/x-json")
CONTENT_TYPE_TEXT = ("text/plain", "text/markdown", "text/csv",
                     "text/tab-separated-values")
CONTENT_TYPE_PDF = ("application/pdf",)
CONTENT_TYPE_BINARY = ("application/octet-stream",)

CONTENT_TYPE_TO_KIND = {
    **{ct: "html" for ct in CONTENT_TYPE_HTML},
    **{ct: "xml" for ct in CONTENT_TYPE_XML},
    **{ct: "json" for ct in CONTENT_TYPE_JSON},
    **{ct: "plain" for ct in CONTENT_TYPE_TEXT},
    **{ct: "pdf" for ct in CONTENT_TYPE_PDF},
    **{ct: "binary" for ct in CONTENT_TYPE_BINARY},
}

BOILERPLATE_TAGS = (
    "script", "style", "noscript", "template", "iframe",
    "svg", "canvas", "form", "input", "button", "select",
    "option", "textarea",
)

BOILERPLATE_SELECTORS = (
    "nav", "header", "footer", "aside",
    "[role='navigation']", "[role='banner']", "[role='contentinfo']",
    "[role='complementary']", "[role='search']", "[role='form']",
    ".nav", ".navbar", ".navigation", ".menu",
    ".header", ".site-header", ".top-bar",
    ".footer", ".site-footer", ".bottom",
    ".sidebar", ".side-bar", ".widget",
    ".ad", ".ads", ".advert", ".advertisement", ".sponsor",
    ".cookie", ".cookie-banner", ".gdpr", ".consent",
    ".social", ".share", ".sharing",
    ".related", ".related-posts", ".recommended",
    ".comments", ".comment-section", ".disqus",
    ".breadcrumb", ".breadcrumbs",
    ".pagination", ".pager",
    ".modal", ".popup", ".overlay",
    ".newsletter", ".subscribe",
    ".author-bio", ".byline-box",
)

ZERO_WIDTH_CHARS = (
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
    "\u180e",  # mongolian vowel separator
)

CONTROL_CHAR_RE = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]"
)

TOKEN_RE = re.compile(r"\w+(?:['\u2019\u02bc]\w+)?", re.UNICODE)
SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z])", re.UNICODE)
PARAGRAPH_SPLIT_RE = re.compile(r"\n\s*\n", re.UNICODE)

VOWEL_GROUP_RE = re.compile(r"[aeiouy]+", re.IGNORECASE)

SOCIAL_DOMAINS = {
    "twitter.com", "x.com", "facebook.com", "instagram.com",
    "linkedin.com", "pinterest.com", "tumblr.com", "reddit.com",
    "youtube.com", "tiktok.com", "snapchat.com", "threads.net",
    "mastodon.social", "bsky.app", "vk.com", "weibo.com",
    "telegram.org", "whatsapp.com", "discord.com",
}

CDN_DOMAINS = {
    "cloudflare.com", "fastly.net", "akamai.net", "cloudfront.net",
    "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
    "googleapis.com", "gstatic.com", "bootstrapcdn.com",
}

DEFAULT_STOPWORDS_EN = frozenset({
    "a", "an", "the", "and", "or", "but", "if", "while", "of", "to",
    "in", "on", "at", "by", "for", "with", "about", "against",
    "between", "into", "through", "during", "before", "after",
    "above", "below", "from", "up", "down", "out", "off", "over",
    "under", "again", "further", "then", "once", "here", "there",
    "when", "where", "why", "how", "all", "any", "both", "each",
    "few", "more", "most", "other", "some", "such", "no", "nor",
    "not", "only", "own", "same", "so", "than", "too", "very",
    "can", "will", "just", "should", "now", "is", "am", "are",
    "was", "were", "be", "been", "being", "have", "has", "had",
    "do", "does", "did", "would", "could", "ought", "i", "you",
    "he", "she", "it", "we", "they", "them", "his", "her", "its",
    "our", "their", "this", "that", "these", "those", "as", "also",
})

MICRODATA_ITEMPROP_RE = re.compile(
    r'itemprop\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

META_LANG_PRIORITY = ("og:locale", "content-language",
                      "language", "lang")


# ════════════════════════════════════════════════════════════════════════════
# Enums
# ════════════════════════════════════════════════════════════════════════════

class ContentKind(str, Enum):
    HTML = "html"
    XML = "xml"
    RSS = "rss"
    ATOM = "atom"
    JSON = "json"
    JSON_LD = "json_ld"
    PLAIN = "plain"
    MARKDOWN = "markdown"
    CSV = "csv"
    PDF = "pdf"
    BINARY = "binary"
    UNKNOWN = "unknown"


class ExtractionStrategy(str, Enum):
    TRAFILATURA = "trafilatura"
    JUSTEXT = "justext"
    DUAL = "dual"
    SELECTOLAX = "selectolax"
    PROFILE_BASED = "profile_based"
    ADAPTIVE = "adaptive"
    FALLBACK = "fallback"


class QualityTier(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    ACCEPTABLE = "acceptable"
    POOR = "poor"
    USELESS = "useless"


class LinkKind(str, Enum):
    INTERNAL = "internal"
    SUBDOMAIN = "subdomain"
    EXTERNAL = "external"
    SOCIAL = "social"
    CDN = "cdn"
    ANCHOR = "anchor"
    MAILTO = "mailto"
    TEL = "tel"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


class TokenStrategy(str, Enum):
    REGEX = "regex"
    WHITESPACE = "whitespace"
    NLTK = "nltk"
    SPACY_LIKE = "spacy_like"


class ExtractionStatus(str, Enum):
    OK = "ok"
    EMPTY = "empty"
    TOO_SHORT = "too_short"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


# ════════════════════════════════════════════════════════════════════════════
# Exceptions
# ════════════════════════════════════════════════════════════════════════════

class ScraperError(Exception):
    category = getattr(ErrorCategory, "EXTRACT", None)
    retryable = False


class ParseFailure(ScraperError):
    category = getattr(ErrorCategory, "PARSE", None)


class ExtractionFailure(ScraperError):
    pass


class EncodingFailure(ScraperError):
    pass


class UnsupportedContentType(ScraperError):
    pass


class EmptyContent(ScraperError):
    pass


# ════════════════════════════════════════════════════════════════════════════
# Dataclasses
# ════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ScraperConfig:
    """Runtime scraper configuration."""
    # Extraction
    primary_extractor: ExtractionStrategy = ExtractionStrategy.ADAPTIVE
    enable_dual_extraction: bool = True
    dual_min_length: int = 200
    take_longer_on_dual: bool = True
    min_paragraph_length: int = 20
    max_paragraph_length: int = 100000
    min_paragraph_words: int = 3
    min_content_length: int = 100
    min_content_words: int = 20
    # Cleaning
    normalize_unicode: bool = True
    unicode_form: str = "NFKC"
    strip_control_chars: bool = True
    strip_zero_width: bool = True
    decode_html_entities: bool = True
    collapse_whitespace: bool = True
    trim_edges: bool = True
    line_ending: str = "\n"
    # Tokenization
    token_strategy: TokenStrategy = TokenStrategy.REGEX
    lowercase_tokens: bool = True
    strip_punctuation_from_tokens: bool = True
    strip_numbers: bool = False
    strip_urls_from_tokens: bool = True
    strip_emails_from_tokens: bool = True
    strip_stopwords: bool = False
    stem_tokens: bool = False
    lemmatize_tokens: bool = False
    min_token_length: int = 1
    max_token_length: int = 64
    # Dedup
    dedup_paragraphs: bool = True
    dedup_similarity_threshold: float = 0.95
    # Metadata
    extract_title: bool = True
    extract_author: bool = True
    extract_date: bool = True
    extract_sitename: bool = True
    extract_description: bool = True
    extract_categories: bool = True
    extract_tags: bool = True
    extract_language: bool = True
    extract_favicon: bool = True
    extract_canonical: bool = True
    extract_opengraph: bool = True
    extract_twitter_cards: bool = True
    extract_json_ld: bool = True
    extract_microdata: bool = True
    # Rich content
    extract_tables: bool = True
    extract_lists: bool = True
    extract_blockquotes: bool = True
    extract_code_blocks: bool = True
    extract_footnotes: bool = True
    extract_images: bool = False
    extract_videos: bool = False
    extract_iframes: bool = False
    # Boilerplate
    strip_boilerplate: bool = True
    strip_navigation: bool = True
    strip_footer: bool = True
    strip_header: bool = True
    strip_sidebar: bool = True
    strip_ads: bool = True
    strip_social_links: bool = True
    strip_related_posts: bool = True
    strip_comments: bool = True
    # Word analysis
    compute_most_used: bool = True
    compute_least_used: bool = True
    compute_word_count: bool = True
    compute_unique_count: bool = True
    compute_char_count: bool = True
    compute_sentence_count: bool = True
    compute_avg_word_length: bool = True
    compute_avg_sentence_length: bool = True
    compute_readability: bool = True
    compute_syllable_count: bool = True
    compute_lexical_density: bool = True
    # Quality
    quality_threshold_useless: float = 5.0
    quality_threshold_poor: float = 30.0
    quality_threshold_acceptable: float = 60.0
    quality_threshold_good: float = 80.0
    # Profile
    use_site_profiles: bool = True
    strict_profile_selectors: bool = False
    # General
    save_raw_html: bool = True
    raw_html_max_bytes: int = 5 * 1024 * 1024
    verbose: bool = False


@dataclass(slots=True)
class Metadata:
    title: str = ""
    description: str = ""
    author: str = ""
    published: str = ""
    modified: str = ""
    sitename: str = ""
    language: str = ""
    canonical_url: str = ""
    favicon: str = ""
    categories: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    opengraph: dict = field(default_factory=dict)
    twitter_cards: dict = field(default_factory=dict)
    json_ld: tuple[dict, ...] = ()
    microdata: tuple[dict, ...] = ()
    feed: dict = field(default_factory=dict)


@dataclass(slots=True)
class QualityReport:
    score: float = 0.0
    tier: QualityTier = QualityTier.USELESS
    content_length: int = 0
    word_count: int = 0
    paragraph_count: int = 0
    sentence_count: int = 0
    link_density: float = 0.0
    text_to_html_ratio: float = 0.0
    unique_word_ratio: float = 0.0
    reason: str = ""

    def classify(self, cfg: ScraperConfig) -> QualityTier:
        s = self.score
        if s >= cfg.quality_threshold_good:
            self.tier = QualityTier.EXCELLENT
        elif s >= cfg.quality_threshold_acceptable:
            self.tier = QualityTier.GOOD
        elif s >= cfg.quality_threshold_poor:
            self.tier = QualityTier.ACCEPTABLE
        elif s >= cfg.quality_threshold_useless:
            self.tier = QualityTier.POOR
        else:
            self.tier = QualityTier.USELESS
        return self.tier


@dataclass(slots=True)
class SiteProfile:
    domain: str
    profile_name: str = "generic"
    content_selector: str = ""
    title_selector: str = ""
    author_selector: str = ""
    date_selector: str = ""
    exclude_selectors: tuple[str, ...] = ()
    strip_paywall: bool = False
    strip_references: bool = False
    strip_edit_links: bool = False
    strip_infoboxes: bool = False
    strip_navboxes: bool = False
    strip_images: bool = False
    preserve_inline_links: bool = True
    preserve_paragraphs: bool = True
    extract_repo_metadata: bool = False
    extract_question: bool = False
    extract_answers: bool = False
    extract_byline: bool = False
    extract_full_text: bool = False
    language: str = ""


@dataclass(slots=True)
class ExtractionCandidate:
    strategy: ExtractionStrategy
    text: str
    paragraphs: tuple[str, ...]
    quality: QualityReport
    elapsed_ms: float = 0.0
    error: str = ""


@dataclass(slots=True)
class ScrapeResult:
    """The complete extraction output. Never JSON."""
    url: str
    domain: str
    status: int = 0
    content_kind: ContentKind = ContentKind.HTML
    title: str = ""
    text: str = ""
    paragraphs: tuple[str, ...] = ()
    tokens: tuple[str, ...] = ()
    links_internal: tuple[dict, ...] = ()
    links_external: tuple[dict, ...] = ()
    images: tuple[str, ...] = ()
    videos: tuple[str, ...] = ()
    tables: tuple[tuple[tuple[str, ...], ...], ...] = ()
    lists: tuple[tuple[str, ...], ...] = ()
    blockquotes: tuple[str, ...] = ()
    code_blocks: tuple[str, ...] = ()
    footnotes: tuple[str, ...] = ()
    metadata: Metadata = field(default_factory=Metadata)
    quality: QualityReport = field(default_factory=QualityReport)
    most_used_word: str = ""
    least_used_word: str = ""
    words_count: int = 0
    unique_words: int = 0
    char_count: int = 0
    sentence_count: int = 0
    paragraph_count: int = 0
    avg_word_length: float = 0.0
    avg_sentence_length: float = 0.0
    syllables: int = 0
    readability: dict = field(default_factory=dict)
    lexical_density: float = 0.0
    reading_time_seconds: float = 0.0
    language: str = ""
    cleaned: str = ""
    raw_html: str = ""
    extraction_strategy: str = ""
    profile_used: str = ""
    elapsed_ms: float = 0.0
    from_cache: bool = False
    depth: int = 0
    fetched_at: float = 0.0
    status_flag: ExtractionStatus = ExtractionStatus.OK

    def to_record(self) -> dict:
        """Serializable dict for Manager.write_record."""
        md = asdict(self.metadata)
        q = asdict(self.quality)
        return {
            "url": self.url,
            "final_url": self.url,
            "domain": self.domain,
            "status": self.status,
            "content_kind": self.content_kind.value,
            "title": self.title,
            "text": self.text,
            "paragraphs": list(self.paragraphs),
            "tokens": list(self.tokens),
            "links": {
                "internal": list(self.links_internal),
                "external": list(self.links_external),
            },
            "images": list(self.images),
            "videos": list(self.videos),
            "tables": [list(map(list, t)) for t in self.tables],
            "lists": [list(l) for l in self.lists],
            "blockquotes": list(self.blockquotes),
            "code_blocks": list(self.code_blocks),
            "footnotes": list(self.footnotes),
            "metadata": md,
            "quality": q,
            "most_used_word": self.most_used_word,
            "least_used_word": self.least_used_word,
            "words_count": self.words_count,
            "unique_words": self.unique_words,
            "char_count": self.char_count,
            "sentence_count": self.sentence_count,
            "paragraph_count": self.paragraph_count,
            "avg_word_length": self.avg_word_length,
            "avg_sentence_length": self.avg_sentence_length,
            "syllables": self.syllables,
            "readability": self.readability,
            "lexical_density": self.lexical_density,
            "reading_time_seconds": self.reading_time_seconds,
            "language": self.language,
            "cleaned": self.cleaned,
            "raw": self.raw_html,
            "extraction_strategy": self.extraction_strategy,
            "profile_used": self.profile_used,
            "elapsed_ms": self.elapsed_ms,
            "timestamp": self.fetched_at,
            "depth": self.depth,
            "from_cache": self.from_cache,
        }


# ════════════════════════════════════════════════════════════════════════════
# Utilities
# ════════════════════════════════════════════════════════════════════════════

def _now() -> float:
    return time.time()


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else ""


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
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


def _normalize_url(url: str, base: Optional[str] = None) -> str:
    if not url:
        return ""
    url = url.strip()
    if base and not url.startswith(("http://", "https://", "//")):
        url = urljoin(base, url)
    if url.startswith("//"):
        url = "https:" + url
    if courlan_normalize is not None:
        try:
            n = courlan_normalize(url)
            if n:
                return n
        except Exception:
            pass
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return ""
        return urlunparse((
            p.scheme,
            p.netloc,
            p.path or "/",
            "",
            p.query,
            "",
        ))
    except Exception:
        return ""


def _xxh64(data: Union[bytes, str]) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    if xxhash is not None:
        return xxhash.xxh64(data).hexdigest()
    return hashlib.blake2b(data, digest_size=8).hexdigest()


def _json_loads(data: Union[bytes, str]) -> Any:
    if orjson is not None:
        return orjson.loads(data)
    import json
    if isinstance(data, bytes):
        data = data.decode("utf-8", "replace")
    return json.loads(data)


def _decode_entities(text: str) -> str:
    if not text:
        return ""
    # Double pass to catch &amp;lt; → < cases
    for _ in range(2):
        decoded = html.unescape(text)
        if decoded == text:
            break
        text = decoded
    return text


def _strip_zero_width(text: str) -> str:
    for ch in ZERO_WIDTH_CHARS:
        text = text.replace(ch, "")
    return text


def _strip_control(text: str) -> str:
    return CONTROL_CHAR_RE.sub("", text)


def _normalize_unicode(text: str, form: str = "NFKC") -> str:
    try:
        if form == "NFC":
            return unicodedata.normalize("NFC", text)
        if form == "NFD":
            return unicodedata.normalize("NFD", text)
        if form == "NFKC":
            return unicodedata.normalize("NFKC", text)
        if form == "NFKD":
            return unicodedata.normalize("NFKD", text)
        return text
    except Exception:
        return text


def _collapse_whitespace(text: str) -> str:
    # Collapse runs of spaces/tabs
    text = re.sub(r"[ \t]+", " ", text)
    # Collapse runs of 3+ newlines into 2
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def _to_bytes(data: Union[bytes, str, bytearray]) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, bytearray):
        return bytes(data)
    return str(data).encode("utf-8", "replace")


def _count_syllables(word: str) -> int:
    word = word.lower().strip(".,!?;:'\"()[]{}")
    if not word:
        return 0
    if len(word) <= 3:
        return 1
    if word.endswith("es") or word.endswith("ed"):
        word = word[:-2]
    elif word.endswith("e"):
        word = word[:-1]
    groups = VOWEL_GROUP_RE.findall(word)
    return max(1, len(groups))


def _parse_iso_datetime(s: str) -> Optional[str]:
    if not s:
        return None
    candidates = [
        s,
        s.replace("Z", "+00:00"),
    ]
    for c in candidates:
        try:
            dt = datetime.fromisoformat(c)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except Exception:
            continue
    # RFC 2822
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except Exception:
        return None


# ════════════════════════════════════════════════════════════════════════════
# Encoding Detector
# ════════════════════════════════════════════════════════════════════════════

class EncodingDetector:
    """Detects and decodes HTML body bytes to text with a fallback chain."""

    CHARSET_RE = re.compile(
        br"""<meta[^>]+charset\s*=\s*["']?\s*([a-zA-Z0-9_\-]+)""",
        re.IGNORECASE,
    )
    HTTP_EQUIV_RE = re.compile(
        br"""<meta[^>]+http-equiv\s*=\s*["']?Content-Type["']?[^>]+content\s*=\s*["'][^"']*charset=([a-zA-Z0-9_\-]+)""",
        re.IGNORECASE,
    )

    FALLBACKS = (
        "utf-8", "utf-16", "utf-16-le", "utf-16-be",
        "latin-1", "cp1252", "cp1251", "cp1256",
        "gb2312", "gbk", "big5", "shift_jis", "euc-kr",
        "koi8-r", "iso-8859-1", "iso-8859-2", "iso-8859-15",
    )

    @classmethod
    def detect(cls, body: bytes,
               declared_charset: Optional[str] = None,
               headers: Optional[Mapping[str, str]] = None) -> str:
        # 1. BOM
        if body.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        if body.startswith(b"\xff\xfe"):
            return "utf-16-le"
        if body.startswith(b"\xfe\xff"):
            return "utf-16-be"

        # 2. Declared charset
        if declared_charset:
            c = cls._normalize_charset(declared_charset)
            if c:
                return c

        # 3. HTTP Content-Type header
        if headers:
            for k, v in headers.items():
                if k.lower() == "content-type" and "charset=" in v.lower():
                    c = v.lower().split("charset=", 1)[1]
                    c = c.split(";")[0].strip().strip("\"'")
                    nc = cls._normalize_charset(c)
                    if nc:
                        return nc

        # 4. HTML meta
        head = body[:4096]
        m = cls.CHARSET_RE.search(head)
        if m:
            c = m.group(1).decode("ascii", "ignore")
            nc = cls._normalize_charset(c)
            if nc:
                return nc
        m = cls.HTTP_EQUIV_RE.search(head)
        if m:
            c = m.group(1).decode("ascii", "ignore")
            nc = cls._normalize_charset(c)
            if nc:
                return nc

        # 5. charset-normalizer
        if _cn_from_bytes is not None and len(body) >= 16:
            try:
                from charset_normalizer import from_bytes
                best = from_bytes(body).best()
                if best and best.encoding:
                    c = cls._normalize_charset(best.encoding)
                    if c:
                        return c
            except Exception:
                pass

        # 6. Heuristic: try utf-8
        try:
            body.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            pass

        return "latin-1"

    @classmethod
    def decode(cls, body: bytes, charset: Optional[str] = None,
               headers: Optional[Mapping[str, str]] = None) -> tuple[str, str]:
        enc = cls.detect(body, charset, headers)
        try:
            return body.decode(enc, errors="strict"), enc
        except (UnicodeDecodeError, LookupError):
            pass
        for fb in cls.FALLBACKS:
            try:
                return body.decode(fb, errors="replace"), fb
            except Exception:
                continue
        return body.decode("utf-8", errors="replace"), "utf-8"

    @staticmethod
    def _normalize_charset(c: str) -> Optional[str]:
        if not c:
            return None
        c = c.strip().lower().strip("\"'")
        aliases = {
            "utf8": "utf-8",
            "utf-8-sig": "utf-8-sig",
            "ascii": "ascii",
            "us-ascii": "ascii",
            "iso8859-1": "iso-8859-1",
            "iso-8859-1": "iso-8859-1",
            "latin1": "latin-1",
            "latin-1": "latin-1",
            "cp-1252": "cp1252",
            "windows-1252": "cp1252",
            "gb2312": "gb2312",
            "gbk": "gbk",
            "gb18030": "gb18030",
            "big5": "big5",
            "shift-jis": "shift_jis",
            "shift_jis": "shift_jis",
            "sjis": "shift_jis",
            "euc-jp": "euc-jp",
            "euc-kr": "euc-kr",
            "koi8r": "koi8-r",
            "koi8-r": "koi8-r",
            "hebrew": "iso-8859-8",
        }
        c = aliases.get(c, c)
        try:
            "".encode(c)
            return c
        except LookupError:
            return None


# ════════════════════════════════════════════════════════════════════════════
# Parser Factory
# ════════════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ParsedDOM:
    kind: str  # "selectolax", "lxml", "bs4"
    tree: Any
    html: str
    url: str
    parse_ms: float = 0.0


class ParserFactory:
    """Multi-backend HTML parser with automatic fallback."""

    @staticmethod
    def parse(html: str, url: str = "") -> Optional[ParsedDOM]:
        t0 = time.time()
        # selectolax (fastest)
        if LexborHTMLParser is not None and html:
            try:
                tree = LexborHTMLParser(html)
                return ParsedDOM(
                    kind="selectolax", tree=tree, html=html, url=url,
                    parse_ms=(time.time() - t0) * 1000,
                )
            except Exception:
                pass
        # lxml
        if lxml_html is not None and html:
            try:
                tree = lxml_html.fromstring(html)
                return ParsedDOM(
                    kind="lxml", tree=tree, html=html, url=url,
                    parse_ms=(time.time() - t0) * 1000,
                )
            except Exception:
                pass
        # bs4 last resort
        if BeautifulSoup is not None and html:
            try:
                tree = BeautifulSoup(html, "lxml")
                return ParsedDOM(
                    kind="bs4", tree=tree, html=html, url=url,
                    parse_ms=(time.time() - t0) * 1000,
                )
            except Exception:
                try:
                    tree = BeautifulSoup(html, "html.parser")
                    return ParsedDOM(
                        kind="bs4", tree=tree, html=html, url=url,
                        parse_ms=(time.time() - t0) * 1000,
                    )
                except Exception:
                    pass
        return None


# ════════════════════════════════════════════════════════════════════════════
# HTML Sanitizer
# ════════════════════════════════════════════════════════════════════════════

class HTMLSanitizer:
    """Strips dangerous/irrelevant tags and normalizes common patterns."""

    STRIP_RE = re.compile(
        r"<(script|style|noscript|template|svg|canvas|iframe|object|embed)"
        r"\b[^>]*>.*?</\1\s*>",
        re.IGNORECASE | re.DOTALL,
    )
    COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
    DOCTYPE_RE = re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE)

    @classmethod
    def sanitize(cls, html: str, strip_scripts: bool = True,
                 strip_comments: bool = True) -> str:
        if not html:
            return ""
        if strip_comments:
            html = cls.COMMENT_RE.sub("", html)
        if strip_scripts:
            for _ in range(3):
                new = cls.STRIP_RE.sub("", html)
                if new == html:
                    break
                html = new
        return html


# ════════════════════════════════════════════════════════════════════════════
# Metadata Extractor
# ════════════════════════════════════════════════════════════════════════════

class MetadataExtractor:
    """Extracts title, description, author, dates, OG, Twitter, JSON-LD,
    microdata, canonical, favicon, categories, tags, language."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, dom: ParsedDOM) -> Metadata:
        md = Metadata()
        if not dom or not dom.tree:
            return md

        # Title
        if self.cfg.extract_title:
            md.title = self._title(dom)

        # Description
        if self.cfg.extract_description:
            md.description = self._meta_content(dom, (
                "description", "og:description", "twitter:description"))

        # Author
        if self.cfg.extract_author:
            md.author = self._author(dom)

        # Dates
        if self.cfg.extract_date:
            md.published, md.modified = self._dates(dom)

        # Site name
        if self.cfg.extract_sitename:
            md.sitename = self._meta_content(dom, (
                "og:site_name", "application-name", "twitter:site"))

        # Language
        if self.cfg.extract_language:
            md.language = self._language(dom)

        # Canonical
        if self.cfg.extract_canonical:
            md.canonical_url = self._canonical(dom)

        # Favicon
        if self.cfg.extract_favicon:
            md.favicon = self._favicon(dom, dom.url)

        # Keywords / categories / tags
        if self.cfg.extract_categories or self.cfg.extract_tags:
            md.keywords = self._keywords(dom)
            md.tags = self._tags(dom)
            md.categories = self._categories(dom)

        # OpenGraph
        if self.cfg.extract_opengraph:
            md.opengraph = self._opengraph(dom)

        # Twitter Cards
        if self.cfg.extract_twitter_cards:
            md.twitter_cards = self._twitter_cards(dom)

        # JSON-LD
        if self.cfg.extract_json_ld:
            md.json_ld = self._json_ld(dom)

        # Microdata
        if self.cfg.extract_microdata:
            md.microdata = self._microdata(dom)

        return md

    # ─── helpers ─────────────────────────────────────────────────────────

    def _css_first(self, dom: ParsedDOM, selector: str) -> Any:
        try:
            if dom.kind == "selectolax":
                return dom.tree.css_first(selector)
            if dom.kind == "lxml":
                r = dom.tree.cssselect(selector)
                return r[0] if r else None
            if dom.kind == "bs4":
                return dom.tree.select_one(selector)
        except Exception:
            return None
        return None

    def _css_all(self, dom: ParsedDOM, selector: str) -> list:
        try:
            if dom.kind == "selectolax":
                return dom.tree.css(selector)
            if dom.kind == "lxml":
                return dom.tree.cssselect(selector)
            if dom.kind == "bs4":
                return dom.tree.select(selector)
        except Exception:
            return []
        return []

    @staticmethod
    def _text(el: Any) -> str:
        if el is None:
            return ""
        try:
            if hasattr(el, "text") and callable(el.text):
                return _as_text(el.text()).strip()
            if hasattr(el, "text_content") and callable(el.text_content):
                return _as_text(el.text_content()).strip()
            if hasattr(el, "get_text"):
                return _as_text(el.get_text()).strip()
        except Exception:
            return ""
        return ""

    @staticmethod
    def _attr(el: Any, name: str, default: str = "") -> str:
        if el is None:
            return default
        try:
            if hasattr(el, "attributes"):
                return el.attributes.get(name, default) or default
            if hasattr(el, "get"):
                v = el.get(name)
                return v if v else default
        except Exception:
            pass
        return default

    def _title(self, dom: ParsedDOM) -> str:
        # og:title
        for sel in ('meta[property="og:title"]', 'meta[name="og:title"]',
                    'meta[name="twitter:title"]',
                    'meta[property="twitter:title"]'):
            el = self._css_first(dom, sel)
            if el:
                v = self._attr(el, "content")
                if v:
                    return v.strip()
        # <title>
        el = self._css_first(dom, "title")
        if el:
            v = self._text(el)
            if v:
                # strip site suffix " - SiteName" or " | SiteName"
                for sep in (" | ", " — ", " – ", " - "):
                    if sep in v and len(v.split(sep)[0]) > 10:
                        v = v.split(sep)[0]
                        break
                return v.strip()
        # <h1>
        el = self._css_first(dom, "h1")
        if el:
            return self._text(el)
        return ""

    def _meta_content(self, dom: ParsedDOM, keys: Sequence[str]) -> str:
        for key in keys:
            for prop in ("property", "name", "itemprop"):
                el = self._css_first(dom, f'meta[{prop}="{key}"]')
                if el:
                    v = self._attr(el, "content")
                    if v:
                        return v.strip()
        return ""

    def _author(self, dom: ParsedDOM) -> str:
        for sel in (
            'meta[name="author"]',
            'meta[property="article:author"]',
            'meta[property="og:article:author"]',
            'meta[name="twitter:creator"]',
            'meta[name="byl"]',
            '[rel="author"]',
            '[itemprop="author"]',
            '[itemprop="author"] [itemprop="name"]',
            ".author",
            ".byline",
            ".byline__name",
            ".article-author",
        ):
            el = self._css_first(dom, sel)
            if el:
                v = self._attr(el, "content") or self._text(el)
                if v:
                    return v.strip()[:200]
        return ""

    def _dates(self, dom: ParsedDOM) -> tuple[str, str]:
        published = modified = ""
        # Priority order
        pub_keys = (
            'meta[property="article:published_time"]',
            'meta[name="article:published_time"]',
            'meta[property="og:published_time"]',
            'meta[itemprop="datePublished"]',
            'meta[name="date"]',
            'meta[name="pubdate"]',
            'meta[name="publish-date"]',
            'meta[name="DC.date.issued"]',
            'meta[name="sailthru.date"]',
        )
        mod_keys = (
            'meta[property="article:modified_time"]',
            'meta[name="article:modified_time"]',
            'meta[itemprop="dateModified"]',
            'meta[name="last-modified"]',
        )
        for sel in pub_keys:
            el = self._css_first(dom, sel)
            if el:
                v = self._attr(el, "content") or self._attr(el, "datetime")
                iso = _parse_iso_datetime(v) if v else None
                if iso:
                    published = iso
                    break
        if not published:
            # <time> element
            el = self._css_first(dom, "time[datetime]")
            if el:
                v = self._attr(el, "datetime")
                iso = _parse_iso_datetime(v) if v else None
                if iso:
                    published = iso
        for sel in mod_keys:
            el = self._css_first(dom, sel)
            if el:
                v = self._attr(el, "content") or self._attr(el, "datetime")
                iso = _parse_iso_datetime(v) if v else None
                if iso:
                    modified = iso
                    break
        return published, modified

    def _language(self, dom: ParsedDOM) -> str:
        for key in META_LANG_PRIORITY:
            for prop in ("property", "name", "http-equiv"):
                el = self._css_first(dom, f'meta[{prop}="{key}"]')
                if el:
                    v = self._attr(el, "content")
                    if v:
                        return v.split("_")[0].split("-")[0].lower()
        el = self._css_first(dom, "html")
        if el:
            lang = self._attr(el, "lang") or self._attr(el, "xml:lang")
            if lang:
                return lang.split("-")[0].split("_")[0].lower()
        return ""

    def _canonical(self, dom: ParsedDOM) -> str:
        el = self._css_first(dom, 'link[rel="canonical"]')
        if el:
            return self._attr(el, "href")
        el = self._css_first(dom, 'meta[property="og:url"]')
        if el:
            return self._attr(el, "content")
        return dom.url

    def _favicon(self, dom: ParsedDOM, base: str) -> str:
        for rel in ("icon", "shortcut icon", "apple-touch-icon",
                    "apple-touch-icon-precomposed"):
            el = self._css_first(dom, f'link[rel="{rel}"]')
            if el:
                href = self._attr(el, "href")
                if href:
                    return _normalize_url(href, base=base)
        return _normalize_url("/favicon.ico", base=base)

    def _keywords(self, dom: ParsedDOM) -> tuple[str, ...]:
        el = self._css_first(dom, 'meta[name="keywords"]')
        if not el:
            return ()
        v = self._attr(el, "content")
        if not v:
            return ()
        return tuple(k.strip() for k in v.split(",") if k.strip())[:50]

    def _tags(self, dom: ParsedDOM) -> tuple[str, ...]:
        tags: list[str] = []
        for sel in (
            'a[rel="tag"]', 'a[href*="/tag/"]', 'a[href*="/tags/"]',
            'meta[property="article:tag"]',
            '[itemprop="keywords"]',
        ):
            for el in self._css_all(dom, sel)[:30]:
                v = self._attr(el, "content") or self._text(el)
                if v:
                    tags.append(v.strip()[:100])
        return tuple(dict.fromkeys(tags))[:50]

    def _categories(self, dom: ParsedDOM) -> tuple[str, ...]:
        cats: list[str] = []
        for sel in (
            'a[rel="category"]', 'a[href*="/category/"]',
            'meta[property="article:section"]',
            '[itemprop="articleSection"]',
        ):
            for el in self._css_all(dom, sel)[:20]:
                v = self._attr(el, "content") or self._text(el)
                if v:
                    cats.append(v.strip()[:100])
        return tuple(dict.fromkeys(cats))[:30]

    def _opengraph(self, dom: ParsedDOM) -> dict:
        og: dict[str, str] = {}
        for el in self._css_all(dom, 'meta[property^="og:"]'):
            prop = self._attr(el, "property")
            content = self._attr(el, "content")
            if prop and content:
                og[prop] = content
        return og

    def _twitter_cards(self, dom: ParsedDOM) -> dict:
        tc: dict[str, str] = {}
        for el in self._css_all(dom, 'meta[name^="twitter:"]'):
            name = self._attr(el, "name")
            content = self._attr(el, "content")
            if name and content:
                tc[name] = content
        return tc

    def _json_ld(self, dom: ParsedDOM) -> tuple[dict, ...]:
        out: list[dict] = []
        for el in self._css_all(dom, 'script[type="application/ld+json"]'):
            try:
                if hasattr(el, "text") and callable(el.text):
                    raw = el.text()
                elif hasattr(el, "string"):
                    raw = el.string
                else:
                    raw = ""
            except Exception:
                raw = ""
            if not isinstance(raw, (str, bytes)) or not raw:
                continue
            try:
                data = _json_loads(raw)
            except Exception:
                # sometimes JSON-LD has trailing commas or wrapped in CDATA
                cleaned = raw.strip().strip(";")
                try:
                    data = _json_loads(cleaned)
                except Exception:
                    continue
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        out.append(item)
            elif isinstance(data, dict):
                if "@graph" in data and isinstance(data["@graph"], list):
                    for item in data["@graph"]:
                        if isinstance(item, dict):
                            out.append(item)
                else:
                    out.append(data)
        return tuple(out[:50])

    def _microdata(self, dom: ParsedDOM) -> tuple[dict, ...]:
        items: list[dict] = []
        for el in self._css_all(dom, "[itemscope]"):
            try:
                item: dict[str, Any] = {}
                if hasattr(el, "attributes"):
                    itemtype = el.attributes.get("itemtype", "")
                else:
                    itemtype = el.get("itemtype", "") if hasattr(el, "get") else ""
                if itemtype:
                    item["@type"] = itemtype
                for prop_el in self._css_all(el, "[itemprop]"):
                    name = self._attr(prop_el, "itemprop")
                    if not name:
                        continue
                    v = (self._attr(prop_el, "content")
                         or self._attr(prop_el, "href")
                         or self._text(prop_el))
                    if v and name not in item:
                        item[name] = v[:500]
                if len(item) > 1:
                    items.append(item)
            except Exception:
                continue
            if len(items) >= 50:
                break
        return tuple(items)


# ════════════════════════════════════════════════════════════════════════════
# Link Extractor
# ════════════════════════════════════════════════════════════════════════════

class LinkExtractor:
    """Extracts and classifies links from a parsed DOM."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, dom: ParsedDOM) -> tuple[tuple[dict, ...],
                                                tuple[dict, ...]]:
        if not dom or not dom.tree:
            return (), ()
        base = dom.url
        base_host = _host(base)
        base_registered = _registered_domain(base_host)

        internal: list[dict] = []
        external: list[dict] = []
        seen: set[str] = set()

        try:
            if dom.kind == "selectolax":
                anchors = dom.tree.css("a[href]")
            elif dom.kind == "lxml":
                anchors = dom.tree.cssselect("a[href]")
            elif dom.kind == "bs4":
                anchors = dom.tree.select("a[href]")
            else:
                anchors = []
        except Exception:
            anchors = []

        for a in anchors:
            raw = self._attr(a, "href")
            if not raw:
                continue
            # Skip mailto/tel/js/data
            lowered = raw.lower().strip()
            if lowered.startswith(("mailto:", "tel:", "javascript:",
                                    "data:", "vbscript:", "#")):
                continue
            norm = _normalize_url(raw, base=base)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            anchor_text = self._text(a)[:512]
            rel = self._attr(a, "rel")
            title = self._attr(a, "title")[:256]
            target = self._attr(a, "target")
            norel = self._attr(a, "rel")
            if "nofollow" in norel.lower():
                nofollow = True
            else:
                nofollow = False
            target_host = _host(norm)
            target_registered = _registered_domain(target_host)
            kind = self._classify(base_host, base_registered,
                                   target_host, target_registered)
            entry = {
                "url": norm,
                "anchor_text": anchor_text,
                "rel": rel,
                "title": title,
                "target": target,
                "nofollow": nofollow,
                "target_host": target_host,
                "target_registered_domain": target_registered,
                "kind": kind.value,
            }
            if kind in (LinkKind.INTERNAL, LinkKind.SUBDOMAIN):
                entry["internal"] = True
                internal.append(entry)
            else:
                entry["internal"] = False
                external.append(entry)

        return tuple(internal), tuple(external)

    @staticmethod
    def _classify(base_host: str, base_reg: str,
                  tgt_host: str, tgt_reg: str) -> LinkKind:
        if not tgt_host:
            return LinkKind.UNKNOWN
        if tgt_host == base_host:
            return LinkKind.INTERNAL
        if base_reg and tgt_reg and base_reg == tgt_reg:
            return LinkKind.SUBDOMAIN
        if any(tgt_reg == s or tgt_reg.endswith("." + s)
               for s in SOCIAL_DOMAINS):
            return LinkKind.SOCIAL
        if any(tgt_reg == s or tgt_reg.endswith("." + s)
               for s in CDN_DOMAINS):
            return LinkKind.CDN
        return LinkKind.EXTERNAL

    @staticmethod
    def _text(el: Any) -> str:
        try:
            if hasattr(el, "text") and callable(el.text):
                return _as_text(el.text()).strip()
            if hasattr(el, "text_content") and callable(el.text_content):
                return _as_text(el.text_content()).strip()
            if hasattr(el, "get_text"):
                return _as_text(el.get_text()).strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _attr(el: Any, name: str) -> str:
        try:
            if hasattr(el, "attributes"):
                return el.attributes.get(name, "") or ""
            if hasattr(el, "get"):
                v = el.get(name)
                return v if v else ""
        except Exception:
            pass
        return ""


# ════════════════════════════════════════════════════════════════════════════
# Tokenizer
# ════════════════════════════════════════════════════════════════════════════

class Tokenizer:
    """Multiple tokenization strategies with stopwords, stemming, lemmas."""

    URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
    EMAIL_RE = re.compile(r"\S+@\S+\.\S+")

    def __init__(self, config: ScraperConfig):
        self.cfg = config
        self._stopwords = self._load_stopwords()
        self._stemmer = None
        self._lemmatizer = None

    def _load_stopwords(self) -> frozenset:
        if not self.cfg.strip_stopwords:
            return frozenset()
        try:
            from nltk.corpus import stopwords as nltk_stop
            words = nltk_stop.words("english")
            return frozenset(w.lower() for w in words)
        except Exception:
            return DEFAULT_STOPWORDS_EN

    def _get_stemmer(self):
        if self._stemmer is not None:
            return self._stemmer
        try:
            from nltk.stem import PorterStemmer
            self._stemmer = PorterStemmer()
        except Exception:
            self._stemmer = None
        return self._stemmer

    def _get_lemmatizer(self):
        if self._lemmatizer is not None:
            return self._lemmatizer
        try:
            from nltk.stem import WordNetLemmatizer
            self._lemmatizer = WordNetLemmatizer()
        except Exception:
            self._lemmatizer = None
        return self._lemmatizer

    def tokenize(self, text: str) -> tuple[str, ...]:
        if not text:
            return ()
        work = text
        if self.cfg.strip_urls_from_tokens:
            work = self.URL_RE.sub(" ", work)
        if self.cfg.strip_emails_from_tokens:
            work = self.EMAIL_RE.sub(" ", work)

        if self.cfg.token_strategy == TokenStrategy.WHITESPACE:
            tokens = work.split()
        elif self.cfg.token_strategy == TokenStrategy.NLTK:
            try:
                from nltk.tokenize import word_tokenize
                tokens = word_tokenize(work)
            except Exception:
                tokens = TOKEN_RE.findall(work)
        else:
            tokens = TOKEN_RE.findall(work)

        out: list[str] = []
        stop = self._stopwords
        for t in tokens:
            if self.cfg.lowercase_tokens:
                t = t.lower()
            if self.cfg.strip_punctuation_from_tokens:
                t = t.strip(string.punctuation + " \t\n")
            if not t:
                continue
            if self.cfg.strip_numbers and t.isdigit():
                continue
            if len(t) < self.cfg.min_token_length:
                continue
            if len(t) > self.cfg.max_token_length:
                continue
            if stop and t in stop:
                continue
            if self.cfg.stem_tokens:
                st = self._get_stemmer()
                if st:
                    with suppress(Exception):
                        t = st.stem(t)
            elif self.cfg.lemmatize_tokens:
                lm = self._get_lemmatizer()
                if lm:
                    with suppress(Exception):
                        t = lm.lemmatize(t)
            out.append(t)
        return tuple(out)


# ════════════════════════════════════════════════════════════════════════════
# Text Cleaner
# ════════════════════════════════════════════════════════════════════════════

class TextCleaner:
    """The pipeline that produces the `cleaned` field."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def clean(self, text: str) -> str:
        if not text:
            return ""
        if self.cfg.decode_html_entities:
            text = _decode_entities(text)
        if self.cfg.strip_zero_width:
            text = _strip_zero_width(text)
        if self.cfg.strip_control_chars:
            text = _strip_control(text)
        if self.cfg.normalize_unicode:
            text = _normalize_unicode(text, self.cfg.unicode_form)
        if self.cfg.line_ending != "\n":
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            if self.cfg.line_ending != "\n":
                text = text.replace("\n", self.cfg.line_ending)
        else:
            text = text.replace("\r\n", "\n").replace("\r", "\n")
        if self.cfg.collapse_whitespace:
            text = _collapse_whitespace(text)
        if self.cfg.trim_edges:
            text = text.strip()
        return text

    def paragraphs(self, text: str) -> tuple[str, ...]:
        if not text:
            return ()
        parts = PARAGRAPH_SPLIT_RE.split(text)
        out: list[str] = []
        for p in parts:
            p = p.strip()
            if not p:
                continue
            if len(p) < self.cfg.min_paragraph_length:
                continue
            if len(p) > self.cfg.max_paragraph_length:
                p = p[: self.cfg.max_paragraph_length]
            words = p.split()
            if len(words) < self.cfg.min_paragraph_words:
                continue
            out.append(p)
        return tuple(out)


# ════════════════════════════════════════════════════════════════════════════
# Language Detector
# ════════════════════════════════════════════════════════════════════════════

class LanguageDetector:
    """Lightweight language detector using script heuristics."""

    SCRIPTS = (
        ("ar", re.compile(r"[\u0600-\u06ff]")),
        ("he", re.compile(r"[\u0590-\u05ff]")),
        ("ru", re.compile(r"[\u0400-\u04ff]")),
        ("el", re.compile(r"[\u0370-\u03ff]")),
        ("hi", re.compile(r"[\u0900-\u097f]")),
        ("th", re.compile(r"[\u0e00-\u0e7f]")),
        ("ja", re.compile(r"[\u3040-\u309f\u30a0-\u30ff]")),
        ("ko", re.compile(r"[\uac00-\ud7af]")),
        ("zh", re.compile(r"[\u4e00-\u9fff]")),
    )

    @classmethod
    def detect(cls, text: str, fallback: str = "en") -> str:
        if not text:
            return fallback
        sample = text[:4000]
        counts: Counter = Counter()
        for name, pattern in cls.SCRIPTS:
            counts[name] = len(pattern.findall(sample))
        if counts:
            name, n = counts.most_common(1)[0]
            if n >= 10:
                return name
        # Simple English heuristics
        if re.search(r"\b(the|and|of|to|in|is|are|was)\b", sample.lower()):
            return "en"
        return fallback


# ════════════════════════════════════════════════════════════════════════════
# Paragraph Deduplicator
# ════════════════════════════════════════════════════════════════════════════

class ParagraphDeduplicator:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def dedup(self, paragraphs: Sequence[str]) -> tuple[str, ...]:
        if not self.cfg.dedup_paragraphs or not paragraphs:
            return tuple(paragraphs)
        seen_hashes: set[str] = set()
        out: list[str] = []
        for p in paragraphs:
            h = _xxh64(p.lower())
            if h in seen_hashes:
                continue
            seen_hashes.add(h)
            out.append(p)
        return tuple(out)

    @staticmethod
    def _shingles(text: str, n: int = 3) -> set[str]:
        words = text.lower().split()
        if len(words) < n:
            return set(words)
        return {" ".join(words[i:i + n]) for i in range(len(words) - n + 1)}

    def _jaccard(self, a: str, b: str) -> float:
        sa = self._shingles(a)
        sb = self._shingles(b)
        if not sa or not sb:
            return 0.0
        return len(sa & sb) / len(sa | sb)


# ════════════════════════════════════════════════════════════════════════════
# Word Analyzer
# ════════════════════════════════════════════════════════════════════════════

class WordAnalyzer:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def analyze(self, tokens: Sequence[str]) -> dict:
        if not tokens:
            return {
                "most_used_word": "", "least_used_word": "",
                "words_count": 0, "unique_words": 0,
                "char_count": 0, "avg_word_length": 0.0,
                "lexical_density": 0.0,
            }
        counter = Counter(tokens)
        most = ""
        least = ""
        if self.cfg.compute_most_used and counter:
            most, _ = counter.most_common(1)[0]
        if self.cfg.compute_least_used and counter:
            min_count = min(counter.values())
            candidates = [w for w, c in counter.items() if c == min_count]
            # prefer longest candidate for determinism
            candidates.sort(key=lambda w: (-len(w), w))
            least = candidates[0]
        unique = len(counter)
        char_count = sum(len(t) for t in tokens)
        avg_word_length = char_count / len(tokens)
        lex_density = unique / len(tokens)
        return {
            "most_used_word": most,
            "least_used_word": least,
            "words_count": len(tokens),
            "unique_words": unique,
            "char_count": char_count,
            "avg_word_length": round(avg_word_length, 3),
            "lexical_density": round(lex_density, 4),
        }


# ════════════════════════════════════════════════════════════════════════════
# Readability Analyzer
# ════════════════════════════════════════════════════════════════════════════

class ReadabilityAnalyzer:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def analyze(self, text: str) -> dict:
        if not text:
            return {}
        sentences = SENTENCE_SPLIT_RE.split(text)
        sentences = [s.strip() for s in sentences if s.strip()]
        words = TOKEN_RE.findall(text.lower())
        if not words or not sentences:
            return {}
        s_count = len(sentences)
        w_count = len(words)
        syllable_count = sum(_count_syllables(w) for w in words)
        complex_words = sum(1 for w in words if _count_syllables(w) >= 3)
        chars = sum(len(w) for w in words)
        asl = w_count / s_count
        asw = syllable_count / w_count
        fk = 206.835 - (1.015 * asl) - (84.6 * asw)
        fre = 206.835 - (1.015 * asl) - (84.6 * asw)
        fog = 0.4 * (asl + 100 * (complex_words / w_count))
        smog = (1.0430 * math.sqrt(complex_words * (30 / s_count)) + 3.1291) \
            if s_count > 0 else 0
        ari = (4.71 * (chars / w_count)) + (0.5 * asl) - 21.43
        return {
            "flesch_kincaid": round(fk, 2),
            "flesch_reading_ease": round(fre, 2),
            "gunning_fog": round(fog, 2),
            "smog": round(smog, 2),
            "ari": round(ari, 2),
            "avg_sentence_length": round(asl, 3),
            "avg_syllables_per_word": round(asw, 3),
            "complex_words": complex_words,
            "sentence_count": s_count,
            "word_count": w_count,
            "syllable_count": syllable_count,
        }


# ════════════════════════════════════════════════════════════════════════════
# Quality Scorer
# ════════════════════════════════════════════════════════════════════════════

class QualityScorer:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def score(self, text: str, paragraphs: Sequence[str],
              tokens: Sequence[str], html: str,
              links: Sequence[dict]) -> QualityReport:
        rep = QualityReport()
        rep.content_length = len(text)
        rep.word_count = len(tokens)
        rep.paragraph_count = len(paragraphs)
        rep.sentence_count = len(SENTENCE_SPLIT_RE.split(text)) if text else 0

        score = 0.0

        # 1. Content length (max 30)
        if rep.content_length >= 8000:
            score += 30.0
        elif rep.content_length >= 3000:
            score += 25.0
        elif rep.content_length >= 1000:
            score += 20.0
        elif rep.content_length >= 500:
            score += 12.0
        elif rep.content_length >= 200:
            score += 6.0

        # 2. Word count (max 20)
        if rep.word_count >= 1500:
            score += 20.0
        elif rep.word_count >= 500:
            score += 15.0
        elif rep.word_count >= 200:
            score += 10.0
        elif rep.word_count >= 50:
            score += 5.0

        # 3. Paragraph count (max 15)
        if rep.paragraph_count >= 20:
            score += 15.0
        elif rep.paragraph_count >= 10:
            score += 12.0
        elif rep.paragraph_count >= 5:
            score += 8.0
        elif rep.paragraph_count >= 2:
            score += 4.0

        # 4. Unique word ratio (max 10)
        if tokens:
            uniq = len(set(tokens)) / len(tokens)
            rep.unique_word_ratio = uniq
            if uniq >= 0.6:
                score += 10.0
            elif uniq >= 0.45:
                score += 7.0
            elif uniq >= 0.3:
                score += 4.0

        # 5. Link density penalty (max 10) — lower density is better
        if text:
            link_text_len = sum(len(l.get("anchor_text", "")) for l in links)
            rep.link_density = link_text_len / max(1, len(text))
            if rep.link_density <= 0.02:
                score += 10.0
            elif rep.link_density <= 0.05:
                score += 7.0
            elif rep.link_density <= 0.10:
                score += 3.0

        # 6. Text/HTML ratio (max 10)
        if html:
            rep.text_to_html_ratio = len(text) / max(1, len(html))
            if rep.text_to_html_ratio >= 0.30:
                score += 10.0
            elif rep.text_to_html_ratio >= 0.15:
                score += 7.0
            elif rep.text_to_html_ratio >= 0.05:
                score += 3.0

        # 7. Sentence quality (max 5)
        if rep.sentence_count >= 20:
            score += 5.0
        elif rep.sentence_count >= 5:
            score += 3.0

        rep.score = round(min(100.0, score), 2)
        rep.classify(self.cfg)
        return rep


# ════════════════════════════════════════════════════════════════════════════
# Extractors
# ════════════════════════════════════════════════════════════════════════════

class BaseExtractor(ABC):
    strategy: ExtractionStrategy = ExtractionStrategy.FALLBACK

    @abstractmethod
    def extract(self, dom: ParsedDOM) -> ExtractionCandidate: ...

    @staticmethod
    def _paragraphs_from_text(text: str, cfg: ScraperConfig) -> tuple[str, ...]:
        cleaner = TextCleaner(cfg)
        cleaned = cleaner.clean(text)
        return cleaner.paragraphs(cleaned)


class TrafilaturaExtractor(BaseExtractor):
    strategy = ExtractionStrategy.TRAFILATURA

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        if trafilatura is None:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(),
                error="trafilatura unavailable",
            )
        try:
            text = trafilatura.extract(
                dom.html,
                url=dom.url,
                include_comments=False,
                include_tables=self.cfg.extract_tables,
                include_links=False,
                include_formatting=False,
                favor_precision=True,
                deduplicate=True,
            ) or ""
        except Exception as e:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error=str(e)[:200],
            )
        paragraphs = self._paragraphs_from_text(text, self.cfg)
        return ExtractionCandidate(
            strategy=self.strategy, text=text, paragraphs=paragraphs,
            quality=QualityReport(),
            elapsed_ms=(time.time() - t0) * 1000,
        )


class JusTextExtractor(BaseExtractor):
    strategy = ExtractionStrategy.JUSTEXT

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        if justext is None:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(),
                error="justext unavailable",
            )
        try:
            stops = justext.get_stoplist("English")
            paragraphs_iter = justext.justext(dom.html.encode("utf-8"),
                                               stops)
            good_paras = [p.text for p in paragraphs_iter
                          if not p.is_boilerplate and p.text]
            text = "\n\n".join(good_paras)
        except Exception as e:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error=str(e)[:200],
            )
        paragraphs = self._paragraphs_from_text(text, self.cfg)
        return ExtractionCandidate(
            strategy=self.strategy, text=text, paragraphs=paragraphs,
            quality=QualityReport(),
            elapsed_ms=(time.time() - t0) * 1000,
        )


class SelectolaxExtractor(BaseExtractor):
    """Fast DOM-based extractor using CSS heuristics. Used as backup."""

    strategy = ExtractionStrategy.SELECTOLAX

    CONTENT_SELECTORS = (
        "article", "main", "[role='main']",
        ".article-body", ".article-content", ".article__body",
        ".post-content", ".post-body", ".entry-content",
        ".content", ".main-content",
        "#content", "#main", "#article",
        ".markdown-body", ".prose",
    )

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        if not dom or not dom.tree:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error="no dom",
            )

        best_node = None
        best_len = 0
        for sel in self.CONTENT_SELECTORS:
            try:
                nodes = dom.tree.css(sel) if dom.kind == "selectolax" \
                    else (dom.tree.cssselect(sel) if dom.kind == "lxml"
                          else dom.tree.select(sel))
            except Exception:
                continue
            for n in nodes[:5]:
                txt = self._node_text(n)
                if len(txt) > best_len:
                    best_len = len(txt)
                    best_node = n

        if best_node is None:
            # Fallback: whole body
            try:
                if dom.kind == "selectolax":
                    body = dom.tree.css_first("body")
                elif dom.kind == "lxml":
                    body = dom.tree.find("body")
                else:
                    body = dom.tree.find("body")
                if body is not None:
                    best_node = body
                    best_len = len(self._node_text(body))
            except Exception:
                pass

        if best_node is None:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error="no content node",
            )

        text = self._node_text(best_node)
        paragraphs = self._paragraphs_from_text(text, self.cfg)
        return ExtractionCandidate(
            strategy=self.strategy, text=text, paragraphs=paragraphs,
            quality=QualityReport(),
            elapsed_ms=(time.time() - t0) * 1000,
        )

    @staticmethod
    def _node_text(node: Any) -> str:
        try:
            if hasattr(node, "text") and callable(node.text):
                return _as_text(node.text(separator="\n\n"))
            if hasattr(node, "text_content"):
                return _as_text(node.text_content())
            if hasattr(node, "get_text"):
                return _as_text(node.get_text(separator="\n\n"))
        except Exception:
            pass
        return ""


class ProfileExtractor(BaseExtractor):
    """Uses a SiteProfile's CSS selectors."""

    strategy = ExtractionStrategy.PROFILE_BASED

    def __init__(self, config: ScraperConfig, profile: SiteProfile):
        self.cfg = config
        self.profile = profile

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        if not dom or not dom.tree or not self.profile.content_selector:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error="no profile",
            )
        text_parts: list[str] = []
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css(self.profile.content_selector)
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect(self.profile.content_selector)
            else:
                nodes = dom.tree.select(self.profile.content_selector)
        except Exception as e:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error=str(e)[:200],
            )
        for n in nodes:
            # exclude selectors
            for excl in self.profile.exclude_selectors:
                for e in self._css(n, excl):
                    with suppress(Exception):
                        e.decompose() if hasattr(e, "decompose") else None
            text_parts.append(self._node_text(n))
        text = "\n\n".join(text_parts)
        paragraphs = self._paragraphs_from_text(text, self.cfg)
        return ExtractionCandidate(
            strategy=self.strategy, text=text, paragraphs=paragraphs,
            quality=QualityReport(),
            elapsed_ms=(time.time() - t0) * 1000,
        )

    def _css(self, node: Any, sel: str) -> list:
        try:
            if hasattr(node, "css"):
                return node.css(sel)
            if hasattr(node, "cssselect"):
                return node.cssselect(sel)
            if hasattr(node, "select"):
                return node.select(sel)
        except Exception:
            return []
        return []

    @staticmethod
    def _node_text(node: Any) -> str:
        try:
            if hasattr(node, "text") and callable(node.text):
                return _as_text(node.text(separator="\n\n"))
            if hasattr(node, "text_content"):
                return _as_text(node.text_content())
            if hasattr(node, "get_text"):
                return _as_text(node.get_text(separator="\n\n"))
        except Exception:
            pass
        return ""


class DualExtractor(BaseExtractor):
    """Runs two extractors, picks the longer output."""

    strategy = ExtractionStrategy.DUAL

    def __init__(self, config: ScraperConfig):
        self.cfg = config
        self.primary = TrafilaturaExtractor(config)
        self.secondary = JusTextExtractor(config)
        self.fallback = SelectolaxExtractor(config)

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        candidates: list[ExtractionCandidate] = []
        for ex in (self.primary, self.secondary, self.fallback):
            try:
                c = ex.extract(dom)
                if c.text:
                    candidates.append(c)
            except Exception:
                continue
        if not candidates:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error="all failed",
            )
        if self.cfg.take_longer_on_dual:
            best = max(candidates, key=lambda c: len(c.text))
        else:
            best = candidates[0]
        best.elapsed_ms = (time.time() - t0) * 1000
        best.strategy = self.strategy
        return best


class AdaptiveExtractor(BaseExtractor):
    """Runs all available extractors, scores each, picks highest quality."""

    strategy = ExtractionStrategy.ADAPTIVE

    def __init__(self, config: ScraperConfig, scorer: QualityScorer):
        self.cfg = config
        self.scorer = scorer
        self.extractors: list[BaseExtractor] = []
        if HAS_TRAFILATURA:
            self.extractors.append(TrafilaturaExtractor(config))
        if HAS_JUSTEXT:
            self.extractors.append(JusTextExtractor(config))
        self.extractors.append(SelectolaxExtractor(config))

    def extract(self, dom: ParsedDOM) -> ExtractionCandidate:
        t0 = time.time()
        best: Optional[ExtractionCandidate] = None
        best_score = -1.0
        for ex in self.extractors:
            try:
                c = ex.extract(dom)
            except Exception:
                continue
            if not c.text or len(c.text) < 20:
                continue
            # quick score
            q = self.scorer.score(
                c.text, c.paragraphs,
                TOKEN_RE.findall(c.text.lower()),
                dom.html, (),
            )
            c.quality = q
            if q.score > best_score:
                best_score = q.score
                best = c
        if best is None:
            return ExtractionCandidate(
                strategy=self.strategy, text="", paragraphs=(),
                quality=QualityReport(), error="no candidate passed",
            )
        best.elapsed_ms = (time.time() - t0) * 1000
        return best


# ════════════════════════════════════════════════════════════════════════════
# Site Profile Resolver
# ════════════════════════════════════════════════════════════════════════════

class SiteProfileResolver:
    """Resolves a SiteProfile from Manager.special_sites."""

    def __init__(self, mgr: Any):
        self.mgr = mgr
        self._cache: dict[str, SiteProfile] = {}
        self._lock = threading.Lock()

    def resolve(self, url: str) -> Optional[SiteProfile]:
        host = _host(url)
        if not host:
            return None
        with self._lock:
            if host in self._cache:
                return self._cache[host]
        profile = self._lookup(host)
        with self._lock:
            self._cache[host] = profile  # type: ignore
        return profile

    def _lookup(self, host: str) -> Optional[SiteProfile]:
        try:
            special = self.mgr.config.get("special_sites", {})
        except Exception:
            return None
        if not special:
            return None
        # exact
        for domain_key in (host, host.lstrip("www.")):
            if domain_key in special:
                return self._to_profile(domain_key, special[domain_key])
        # registered-domain match
        rd = _registered_domain(host)
        if rd in special:
            return self._to_profile(rd, special[rd])
        # suffix match
        for key, val in special.items():
            if host.endswith("." + key) or host == key:
                return self._to_profile(key, val)
        return None

    @staticmethod
    def _to_profile(domain: str, raw: Mapping) -> SiteProfile:
        def s(*keys: str) -> str:
            for k in keys:
                v = raw.get(k)
                if v:
                    return str(v)
            return ""

        def b(key: str, default: bool = False) -> bool:
            return bool(raw.get(key, default))

        excludes = raw.get("exclude_selectors", []) or []
        if isinstance(excludes, str):
            excludes = [excludes]
        return SiteProfile(
            domain=domain,
            profile_name=s("extraction_profile") or "generic",
            content_selector=s("content_selector"),
            title_selector=s("title_selector"),
            author_selector=s("author_selector"),
            date_selector=s("date_selector"),
            exclude_selectors=tuple(excludes),
            strip_paywall=b("strip_paywall"),
            strip_references=b("strip_references"),
            strip_edit_links=b("strip_edit_links"),
            strip_infoboxes=b("strip_infoboxes"),
            strip_navboxes=b("strip_navboxes"),
            strip_images=b("strip_images"),
            preserve_inline_links=b("preserve_inline_links", True),
            preserve_paragraphs=b("preserve_paragraphs", True),
            extract_repo_metadata=b("extract_repo_metadata"),
            extract_question=b("extract_question"),
            extract_answers=b("extract_answers"),
            extract_byline=b("extract_byline"),
            extract_full_text=b("extract_full_text"),
            language=s("language"),
        )


# ════════════════════════════════════════════════════════════════════════════
# Rich Content Extractors
# ════════════════════════════════════════════════════════════════════════════

class TableExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[tuple[tuple[str, ...], ...], ...]:
        if not dom or not dom.tree:
            return ()
        try:
            if dom.kind == "selectolax":
                tables = dom.tree.css("table")
            elif dom.kind == "lxml":
                tables = dom.tree.cssselect("table")
            else:
                tables = dom.tree.select("table")
        except Exception:
            return ()
        out: list[tuple[tuple[str, ...], ...]] = []
        for table in tables[:30]:
            rows: list[tuple[str, ...]] = []
            try:
                if dom.kind == "selectolax":
                    trs = table.css("tr")
                elif dom.kind == "lxml":
                    trs = table.cssselect("tr")
                else:
                    trs = table.select("tr")
            except Exception:
                continue
            for tr in trs[:200]:
                cells: list[str] = []
                try:
                    if dom.kind == "selectolax":
                        tds = tr.css("th, td")
                    elif dom.kind == "lxml":
                        tds = tr.cssselect("th, td")
                    else:
                        tds = tr.select("th, td")
                except Exception:
                    continue
                for td in tds:
                    try:
                        t = td.text() if hasattr(td, "text") and callable(td.text) \
                            else (td.text_content() if hasattr(td, "text_content")
                                  else (td.get_text() if hasattr(td, "get_text")
                                        else ""))
                        cells.append(_as_text(t).strip()[:1000])
                    except Exception:
                        cells.append("")
                if cells:
                    rows.append(tuple(cells))
            if rows:
                out.append(tuple(rows))
        return tuple(out)


class ListExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[tuple[str, ...], ...]:
        if not dom or not dom.tree:
            return ()
        try:
            if dom.kind == "selectolax":
                lists = dom.tree.css("ul, ol")
            elif dom.kind == "lxml":
                lists = dom.tree.cssselect("ul, ol")
            else:
                lists = dom.tree.select("ul, ol")
        except Exception:
            return ()
        out: list[tuple[str, ...]] = []
        for ul in lists[:50]:
            items: list[str] = []
            try:
                if dom.kind == "selectolax":
                    lis = ul.css("li")
                elif dom.kind == "lxml":
                    lis = ul.cssselect("li")
                else:
                    lis = ul.select("li")
            except Exception:
                continue
            for li in lis[:200]:
                try:
                    t = li.text() if hasattr(li, "text") and callable(li.text) \
                        else (li.text_content() if hasattr(li, "text_content")
                              else (li.get_text() if hasattr(li, "get_text") else ""))
                    t = _as_text(t).strip()
                    if t:
                        items.append(t[:2000])
                except Exception:
                    continue
            if items:
                out.append(tuple(items))
        return tuple(out)


class BlockquoteExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[str, ...]:
        if not dom or not dom.tree:
            return ()
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css("blockquote, q")
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect("blockquote, q")
            else:
                nodes = dom.tree.select("blockquote, q")
        except Exception:
            return ()
        out: list[str] = []
        for n in nodes[:50]:
            try:
                t = n.text() if hasattr(n, "text") and callable(n.text) \
                    else (n.text_content() if hasattr(n, "text_content")
                          else (n.get_text() if hasattr(n, "get_text") else ""))
                t = _as_text(t).strip()
                if t and len(t) > 10:
                    out.append(t[:2000])
            except Exception:
                continue
        return tuple(out)


class CodeBlockExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[str, ...]:
        if not dom or not dom.tree:
            return ()
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css("pre, code")
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect("pre, code")
            else:
                nodes = dom.tree.select("pre, code")
        except Exception:
            return ()
        out: list[str] = []
        for n in nodes[:100]:
            try:
                t = n.text() if hasattr(n, "text") and callable(n.text) \
                    else (n.text_content() if hasattr(n, "text_content")
                          else (n.get_text() if hasattr(n, "get_text") else ""))
                t = _as_text(t).strip()
                if t and len(t) > 20:
                    out.append(t[:5000])
            except Exception:
                continue
        return tuple(out)


class ImageExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[str, ...]:
        if not dom or not dom.tree:
            return ()
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css("img[src]")
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect("img[src]")
            else:
                nodes = dom.tree.select("img[src]")
        except Exception:
            return ()
        out: list[str] = []
        for n in nodes[:500]:
            try:
                if hasattr(n, "attributes"):
                    src = n.attributes.get("src", "")
                    srcset = n.attributes.get("srcset", "")
                elif hasattr(n, "get"):
                    src = n.get("src", "")
                    srcset = n.get("srcset", "")
                else:
                    src = srcset = ""
                if src:
                    out.append(_normalize_url(src, base=dom.url))
                elif srcset:
                    first = srcset.split(",")[0].strip().split(" ")[0]
                    if first:
                        out.append(_normalize_url(first, base=dom.url))
            except Exception:
                continue
        return tuple(dict.fromkeys(out))

    @staticmethod
    def extract_videos(dom: ParsedDOM) -> tuple[str, ...]:
        if not dom or not dom.tree:
            return ()
        out: list[str] = []
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css("video[src], iframe[src], source[src]")
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect("video[src], iframe[src], source[src]")
            else:
                nodes = dom.tree.select("video[src], iframe[src], source[src]")
        except Exception:
            return ()
        for n in nodes[:100]:
            try:
                if hasattr(n, "attributes"):
                    src = n.attributes.get("src", "")
                elif hasattr(n, "get"):
                    src = n.get("src", "")
                else:
                    src = ""
                if src:
                    out.append(_normalize_url(src, base=dom.url))
            except Exception:
                continue
        return tuple(dict.fromkeys(out))


class FootnoteExtractor:
    @staticmethod
    def extract(dom: ParsedDOM) -> tuple[str, ...]:
        if not dom or not dom.tree:
            return ()
        out: list[str] = []
        try:
            if dom.kind == "selectolax":
                nodes = dom.tree.css(
                    "[role='doc-endnotes'] li, .footnotes li, .footnote")
            elif dom.kind == "lxml":
                nodes = dom.tree.cssselect(
                    "[role='doc-endnotes'] li, .footnotes li, .footnote")
            else:
                nodes = dom.tree.select(
                    "[role='doc-endnotes'] li, .footnotes li, .footnote")
        except Exception:
            return ()
        for n in nodes[:100]:
            try:
                t = n.text() if hasattr(n, "text") and callable(n.text) \
                    else (n.text_content() if hasattr(n, "text_content")
                          else (n.get_text() if hasattr(n, "get_text") else ""))
                t = _as_text(t).strip()
                if t:
                    out.append(t[:2000])
            except Exception:
                continue
        return tuple(out)


# ════════════════════════════════════════════════════════════════════════════
# Content Kind Dispatcher
# ════════════════════════════════════════════════════════════════════════════

class ContentKindDispatcher:
    """Determines content kind from Content-Type + body sniffing."""

    @staticmethod
    def detect(content_type: str, body: bytes, url: str = "") -> ContentKind:
        ct = (content_type or "").split(";")[0].strip().lower()
        # Explicit from header
        kind = CONTENT_TYPE_TO_KIND.get(ct)
        if kind == "html":
            return ContentKind.HTML
        if kind == "xml":
            # Differentiate RSS/Atom
            low = body[:1024].lower()
            if b"<rss" in low:
                return ContentKind.RSS
            if b"<feed" in low and b"atom" in low:
                return ContentKind.ATOM
            return ContentKind.XML
        if kind == "json":
            return ContentKind.JSON
        if kind == "pdf":
            return ContentKind.PDF
        if kind == "plain":
            # Could be markdown or csv or plain text
            if ct == "text/markdown":
                return ContentKind.MARKDOWN
            if ct == "text/csv" or ct == "text/tab-separated-values":
                return ContentKind.CSV
            return ContentKind.PLAIN
        if kind == "binary":
            return ContentKind.BINARY
        # Sniff
        head = body[:512].strip()
        if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
            return ContentKind.HTML
        if head.startswith(b"<?xml"):
            if b"<rss" in body[:2048].lower():
                return ContentKind.RSS
            if b"<feed" in body[:2048].lower():
                return ContentKind.ATOM
            return ContentKind.XML
        if head.startswith(b"{") or head.startswith(b"["):
            return ContentKind.JSON
        if head.startswith(b"%PDF-"):
            return ContentKind.PDF
        return ContentKind.UNKNOWN


# ════════════════════════════════════════════════════════════════════════════
# Format-specific extractors
# ════════════════════════════════════════════════════════════════════════════

class XMLExtractor:
    """Extracts text, links, and feed metadata from XML, RSS, or Atom."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, body: bytes, url: str,
                kind: ContentKind) -> ScrapeResult:
        result = ScrapeResult(
            url=url, domain=_host(url),
            content_kind=kind, fetched_at=_now(),
        )
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            text = ""
        if not text:
            return result

        # Extract RSS/Atom entries
        entries = re.findall(
            r"<(item|entry)\b.*?</\1>", text,
            re.DOTALL | re.IGNORECASE,
        )
        titles: list[str] = []
        links: list[dict] = []
        descs: list[str] = []
        for entry in entries[:500]:
            tm = re.search(r"<title[^>]*>(.*?)</title>",
                           entry, re.DOTALL | re.IGNORECASE)
            if tm:
                titles.append(_decode_entities(tm.group(1)).strip())
            lm = re.search(r"<link[^>]*href=[\"']([^\"']+)[\"']",
                           entry, re.IGNORECASE)
            if not lm:
                lm = re.search(r"<link[^>]*>(.*?)</link>",
                               entry, re.DOTALL | re.IGNORECASE)
            if lm:
                links.append({
                    "url": _normalize_url(lm.group(1), base=url),
                    "anchor_text": titles[-1] if titles else "",
                    "kind": "external",
                })
            dm = re.search(r"<(description|summary|content)[^>]*>(.*?)</\1>",
                           entry, re.DOTALL | re.IGNORECASE)
            if dm:
                descs.append(re.sub(r"<[^>]+>", " ",
                                     _decode_entities(dm.group(2))).strip())

        # Feed metadata
        feed_title_m = re.search(
            r"<channel[^>]*>.*?<title[^>]*>(.*?)</title>",
            text, re.DOTALL | re.IGNORECASE)
        if feed_title_m:
            result.title = _decode_entities(
                feed_title_m.group(1)).strip()
        elif titles:
            result.title = titles[0]

        # Combine into text
        combined = "\n\n".join(t + "\n" + d for t, d in zip(titles, descs))
        if not combined:
            combined = "\n\n".join(descs) or "\n\n".join(titles)
        cleaner = TextCleaner(self.cfg)
        result.text = cleaner.clean(combined)
        result.cleaned = result.text
        result.paragraphs = cleaner.paragraphs(result.text)
        result.links_external = tuple(links)
        result.metadata.feed = {"entries": len(entries)}
        return result


class JSONExtractor:
    """Extracts text from JSON or JSON-LD."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, body: bytes, url: str) -> ScrapeResult:
        result = ScrapeResult(
            url=url, domain=_host(url),
            content_kind=ContentKind.JSON, fetched_at=_now(),
        )
        try:
            data = _json_loads(body)
        except Exception:
            return result

        texts: list[str] = []
        def walk(node: Any, depth: int = 0) -> None:
            if depth > 20:
                return
            if isinstance(node, str):
                if len(node) >= 20:
                    texts.append(node)
            elif isinstance(node, dict):
                for k, v in node.items():
                    if k in ("text", "content", "body", "description",
                             "summary", "title", "headline", "abstract"):
                        if isinstance(v, str):
                            texts.append(v)
                    else:
                        walk(v, depth + 1)
            elif isinstance(node, list):
                for item in node[:500]:
                    walk(item, depth + 1)

        walk(data)
        combined = "\n\n".join(texts)
        cleaner = TextCleaner(self.cfg)
        result.text = cleaner.clean(combined)
        result.cleaned = result.text
        result.paragraphs = cleaner.paragraphs(result.text)

        # JSON-LD metadata
        if isinstance(data, dict):
            result.metadata.json_ld = (data,)
            if not result.title:
                result.title = str(data.get("headline")
                                    or data.get("name") or "")
            if not result.metadata.author:
                author = data.get("author")
                if isinstance(author, dict):
                    result.metadata.author = author.get("name", "")
                elif isinstance(author, str):
                    result.metadata.author = author
            if not result.metadata.published:
                result.metadata.published = str(
                    data.get("datePublished") or "")
        return result


class PlainTextExtractor:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, body: bytes, url: str,
                kind: ContentKind = ContentKind.PLAIN) -> ScrapeResult:
        result = ScrapeResult(
            url=url, domain=_host(url),
            content_kind=kind, fetched_at=_now(),
        )
        text, _enc = EncodingDetector.decode(body)
        cleaner = TextCleaner(self.cfg)
        result.text = cleaner.clean(text)
        result.cleaned = result.text
        result.paragraphs = cleaner.paragraphs(result.text)
        return result


class PDFExtractor:
    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def extract(self, body: bytes, url: str) -> ScrapeResult:
        result = ScrapeResult(
            url=url, domain=_host(url),
            content_kind=ContentKind.PDF, fetched_at=_now(),
        )
        if pymupdf is None:
            return result
        try:
            doc = pymupdf.open(stream=body, filetype="pdf")
            pages_text: list[str] = []
            for page in doc:
                pages_text.append(page.get_text())
            doc.close()
            combined = "\n\n".join(pages_text)
            cleaner = TextCleaner(self.cfg)
            result.text = cleaner.clean(combined)
            result.cleaned = result.text
            result.paragraphs = cleaner.paragraphs(result.text)
        except Exception:
            pass
        return result


# ════════════════════════════════════════════════════════════════════════════
# Boilerplate Remover
# ════════════════════════════════════════════════════════════════════════════

class BoilerplateRemover:
    """Removes common boilerplate elements from the DOM before extraction."""

    def __init__(self, config: ScraperConfig):
        self.cfg = config

    def remove(self, dom: ParsedDOM, profile: Optional[SiteProfile]) -> None:
        if not dom or not dom.tree:
            return
        selectors: list[str] = []
        if self.cfg.strip_navigation:
            selectors.extend(["nav", "[role='navigation']", ".nav", ".navbar"])
        if self.cfg.strip_header:
            selectors.extend(["header", "[role='banner']", ".site-header",
                              ".header", ".top-bar"])
        if self.cfg.strip_footer:
            selectors.extend(["footer", "[role='contentinfo']",
                              ".site-footer", ".footer"])
        if self.cfg.strip_sidebar:
            selectors.extend(["aside", "[role='complementary']",
                              ".sidebar", ".side-bar", ".widget"])
        if self.cfg.strip_ads:
            selectors.extend([".ad", ".ads", ".advert", ".advertisement",
                              "[class*='ad-']", "[id*='ad-']",
                              "[class*='sponsor']"])
        if self.cfg.strip_social_links:
            selectors.extend([".social", ".share", ".sharing",
                              "[class*='social-']"])
        if self.cfg.strip_related_posts:
            selectors.extend([".related", ".related-posts",
                              ".recommended", "[class*='related']"])
        if self.cfg.strip_comments:
            selectors.extend([".comments", ".comment-section",
                              "#comments", ".disqus", "[class*='comment']"])
        # Common cookie banners
        selectors.extend([".cookie", ".cookie-banner", ".gdpr",
                          ".consent", "[class*='cookie']"])
        if profile:
            selectors.extend(profile.exclude_selectors)

        for sel in selectors:
            try:
                if dom.kind == "selectolax":
                    nodes = dom.tree.css(sel)
                elif dom.kind == "lxml":
                    nodes = dom.tree.cssselect(sel)
                else:
                    nodes = dom.tree.select(sel)
            except Exception:
                continue
            for n in nodes:
                with suppress(Exception):
                    if hasattr(n, "decompose"):
                        n.decompose()
                    elif hasattr(n, "drop_tree"):
                        n.drop_tree()


# ════════════════════════════════════════════════════════════════════════════
# Scraper — orchestrator
# ════════════════════════════════════════════════════════════════════════════

class Scraper:
    """
    Main orchestrator. Wraps the full extraction pipeline:
        1. Detect content kind
        2. Decode with fallback chain
        3. Parse with multi-backend parser
        4. Resolve site profile
        5. Remove boilerplate
        6. Extract main content (adaptive)
        7. Extract rich content (tables, lists, links, etc.)
        8. Extract metadata
        9. Tokenize + clean
        10. Analyze (words, readability)
        11. Score quality
        12. Return rich result
    """

    def __init__(self, mgr: Optional[Any] = None,
                 config: Optional[ScraperConfig] = None):
        self.mgr = mgr or get_manager()
        self.log = self.mgr.logger.getChild("Scraper")
        self.config = config or self._config_from_manager()

        # Subsystems
        self.tokenizer = Tokenizer(self.config)
        self.cleaner = TextCleaner(self.config)
        self.scorer = QualityScorer(self.config)
        self.dedup = ParagraphDeduplicator(self.config)
        self.word_analyzer = WordAnalyzer(self.config)
        self.readability = ReadabilityAnalyzer(self.config)
        self.metadata_extractor = MetadataExtractor(self.config)
        self.link_extractor = LinkExtractor(self.config)
        self.profile_resolver = SiteProfileResolver(self.mgr)
        self.boilerplate = BoilerplateRemover(self.config)

        # Extractors
        self._adaptive = AdaptiveExtractor(self.config, self.scorer)
        self._dual = DualExtractor(self.config)
        self._selectolax = SelectolaxExtractor(self.config)
        self._trafilatura = TrafilaturaExtractor(self.config)
        self._justext = JusTextExtractor(self.config)

    # ─── config ────────────────────────────────────────────────────────

    def _config_from_manager(self) -> ScraperConfig:
        c = ScraperConfig()
        try:
            c.min_paragraph_length = int(self.mgr.config.get(
                "extract.min_paragraph_length", c.min_paragraph_length))
            c.max_paragraph_length = int(self.mgr.config.get(
                "extract.max_paragraph_length", c.max_paragraph_length))
            c.min_paragraph_words = int(self.mgr.config.get(
                "extract.min_paragraph_words", c.min_paragraph_words))
            c.min_content_length = int(self.mgr.config.get(
                "extract.min_content_length", c.min_content_length))
            c.min_content_words = int(self.mgr.config.get(
                "extract.min_content_words", c.min_content_words))
            c.dedup_paragraphs = bool(self.mgr.config.get(
                "extract.deduplicate_paragraphs", c.dedup_paragraphs))
            c.dedup_similarity_threshold = float(self.mgr.config.get(
                "extract.deduplicate_similarity_threshold",
                c.dedup_similarity_threshold))
            c.unicode_form = str(self.mgr.config.get(
                "global.unicode_form", c.unicode_form))
            c.line_ending = str(self.mgr.config.get(
                "global.line_ending", c.line_ending))
            c.strip_stopwords = bool(self.mgr.config.get(
                "tokenize.strip_stopwords", c.strip_stopwords))
            c.lowercase_tokens = bool(self.mgr.config.get(
                "tokenize.lowercase", c.lowercase_tokens))
            c.stem_tokens = bool(self.mgr.config.get(
                "tokenize.stemming_enabled", c.stem_tokens))
            c.lemmatize_tokens = bool(self.mgr.config.get(
                "tokenize.lemmatization_enabled", c.lemmatize_tokens))
            c.strip_numbers = bool(self.mgr.config.get(
                "tokenize.strip_numbers", c.strip_numbers))
            c.extract_tables = bool(self.mgr.config.get(
                "extract.extract_tables", c.extract_tables))
            c.extract_lists = bool(self.mgr.config.get(
                "extract.extract_lists", c.extract_lists))
            c.extract_blockquotes = bool(self.mgr.config.get(
                "extract.extract_blockquotes", c.extract_blockquotes))
            c.extract_code_blocks = bool(self.mgr.config.get(
                "extract.extract_code_blocks", c.extract_code_blocks))
            c.extract_footnotes = bool(self.mgr.config.get(
                "extract.extract_footnotes", c.extract_footnotes))
            c.extract_images = bool(self.mgr.config.get(
                "extract.extract_images", c.extract_images))
            c.extract_videos = bool(self.mgr.config.get(
                "extract.extract_videos", c.extract_videos))
            c.extract_json_ld = bool(self.mgr.config.get(
                "extract.keep_json_ld", c.extract_json_ld))
            c.extract_opengraph = bool(self.mgr.config.get(
                "extract.keep_opengraph", c.extract_opengraph))
            c.extract_twitter_cards = bool(self.mgr.config.get(
                "extract.keep_twitter_cards", c.extract_twitter_cards))
            c.extract_microdata = bool(self.mgr.config.get(
                "extract.keep_microdata", c.extract_microdata))
            c.strip_boilerplate = bool(self.mgr.config.get(
                "extract.strip_boilerplate", c.strip_boilerplate))
            c.save_raw_html = bool(self.mgr.config.get(
                "extract.save_raw_html", c.save_raw_html))
            c.raw_html_max_bytes = int(self.mgr.config.get(
                "extract.raw_html_max_size_bytes", c.raw_html_max_bytes))
        except Exception:
            pass
        return c

    # ─── public entry ──────────────────────────────────────────────────

    def scrape(self,
               body: Union[bytes, str],
               url: str,
               *,
               content_type: str = "",
               headers: Optional[Mapping[str, str]] = None,
               status: int = 200,
               depth: int = 0,
               from_cache: bool = False,
               elapsed_ms: float = 0.0,
               save_raw: Optional[bool] = None,
               ) -> ScrapeResult:
        t0 = time.time()
        body_bytes = _to_bytes(body)

        # Determine kind
        kind = ContentKindDispatcher.detect(content_type, body_bytes, url)

        # Dispatch to format-specific extractor
        if kind == ContentKind.HTML:
            result = self._scrape_html(body_bytes, url, content_type, headers,
                                       status)
        elif kind in (ContentKind.XML, ContentKind.RSS, ContentKind.ATOM):
            result = XMLExtractor(self.config).extract(body_bytes, url, kind)
        elif kind == ContentKind.JSON:
            result = JSONExtractor(self.config).extract(body_bytes, url)
        elif kind == ContentKind.PDF:
            result = PDFExtractor(self.config).extract(body_bytes, url)
        elif kind == ContentKind.PLAIN or kind == ContentKind.MARKDOWN \
                or kind == ContentKind.CSV:
            result = PlainTextExtractor(self.config).extract(
                body_bytes, url, kind)
        else:
            # Unknown — attempt HTML
            result = self._scrape_html(body_bytes, url, content_type, headers,
                                       status)

        result.url = url
        result.domain = _host(url)
        result.status = status
        result.depth = depth
        result.from_cache = from_cache
        result.elapsed_ms = elapsed_ms or (time.time() - t0) * 1000
        result.fetched_at = result.fetched_at or _now()

        # Fill derived fields
        self._finalize(result, body_bytes)

        return result

    # ─── HTML pipeline ────────────────────────────────────────────────

    def _scrape_html(self, body: bytes, url: str, content_type: str,
                     headers: Optional[Mapping[str, str]],
                     status: int) -> ScrapeResult:
        result = ScrapeResult(
            url=url, domain=_host(url), status=status,
            content_kind=ContentKind.HTML, fetched_at=_now(),
        )
        # Decode
        text, _enc = EncodingDetector.decode(body, None, headers)
        if not text:
            result.status_flag = ExtractionStatus.EMPTY
            return result

        # Save raw
        if self.config.save_raw_html:
            raw = text
            if len(raw) > self.config.raw_html_max_bytes:
                raw = raw[: self.config.raw_html_max_bytes] + \
                    "\n<!-- FA-CRAB-TRUNCATED -->"
            result.raw_html = raw

        # Sanitize
        sanitized = HTMLSanitizer.sanitize(text, strip_scripts=True,
                                            strip_comments=True)

        # Parse
        dom = ParserFactory.parse(sanitized, url)
        if dom is None:
            result.status_flag = ExtractionStatus.FAILED
            return result

        # Resolve site profile
        profile = None
        if self.config.use_site_profiles:
            try:
                profile = self.profile_resolver.resolve(url)
            except Exception:
                profile = None

        # Extract metadata BEFORE removing boilerplate (to still find meta)
        if self.config.extract_title or self.config.extract_author \
                or self.config.extract_date or self.config.extract_sitename \
                or self.config.extract_description \
                or self.config.extract_categories \
                or self.config.extract_tags \
                or self.config.extract_language \
                or self.config.extract_canonical \
                or self.config.extract_favicon \
                or self.config.extract_opengraph \
                or self.config.extract_twitter_cards \
                or self.config.extract_json_ld \
                or self.config.extract_microdata:
            result.metadata = self.metadata_extractor.extract(dom)
            result.title = result.metadata.title
            result.language = result.metadata.language

        # Extract links BEFORE boilerplate removal (to capture everything)
        try:
            internal, external = self.link_extractor.extract(dom)
            result.links_internal = internal
            result.links_external = external
        except Exception:
            pass

        # Rich content extraction
        try:
            if self.config.extract_tables:
                result.tables = TableExtractor.extract(dom)
            if self.config.extract_lists:
                result.lists = ListExtractor.extract(dom)
            if self.config.extract_blockquotes:
                result.blockquotes = BlockquoteExtractor.extract(dom)
            if self.config.extract_code_blocks:
                result.code_blocks = CodeBlockExtractor.extract(dom)
            if self.config.extract_footnotes:
                result.footnotes = FootnoteExtractor.extract(dom)
            if self.config.extract_images:
                result.images = ImageExtractor.extract(dom)
            if self.config.extract_videos:
                result.videos = ImageExtractor.extract_videos(dom)
        except Exception as e:
            self.mgr.errors.record_exception(
                e, category=ErrorCategory.EXTRACT, url=url)

        # Remove boilerplate (DOM mutation)
        if self.config.strip_boilerplate:
            try:
                self.boilerplate.remove(dom, profile)
            except Exception as e:
                self.mgr.errors.record_exception(
                    e, category=ErrorCategory.EXTRACT, url=url)

        # Main content extraction
        candidate = self._pick_extractor(dom, profile)
        result.extraction_strategy = candidate.strategy.value
        result.profile_used = profile.profile_name if profile else ""

        if not candidate.text:
            # Fallback to raw visible text
            candidate = self._selectolax.extract(dom)

        # Clean
        result.text = self.cleaner.clean(candidate.text)
        result.cleaned = result.text

        # Paragraphs
        paras = candidate.paragraphs or self.cleaner.paragraphs(result.text)
        if self.config.dedup_paragraphs:
            paras = self.dedup.dedup(paras)
        result.paragraphs = paras
        result.paragraph_count = len(paras)

        # If content too short, mark status
        if len(result.text) < self.config.min_content_length:
            result.status_flag = ExtractionStatus.TOO_SHORT
        elif not result.text:
            result.status_flag = ExtractionStatus.EMPTY
        else:
            result.status_flag = ExtractionStatus.OK

        # Profile-based title override
        if profile and profile.title_selector and not result.title:
            for n in self._css(dom, profile.title_selector)[:1]:
                t = self._node_text(n)
                if t:
                    result.title = t.strip()
                    break

        return result

    def _pick_extractor(self, dom: ParsedDOM,
                        profile: Optional[SiteProfile]) -> ExtractionCandidate:
        # 1. Profile-based
        if profile and profile.content_selector:
            try:
                c = ProfileExtractor(self.config, profile).extract(dom)
                if c.text and len(c.text) >= self.config.min_content_length:
                    return c
            except Exception:
                pass
        # 2. Adaptive
        if self.config.primary_extractor == ExtractionStrategy.ADAPTIVE:
            return self._adaptive.extract(dom)
        if self.config.primary_extractor == ExtractionStrategy.DUAL:
            return self._dual.extract(dom)
        if self.config.primary_extractor == ExtractionStrategy.TRAFILATURA:
            return self._trafilatura.extract(dom)
        if self.config.primary_extractor == ExtractionStrategy.JUSTEXT:
            return self._justext.extract(dom)
        if self.config.primary_extractor == ExtractionStrategy.SELECTOLAX:
            return self._selectolax.extract(dom)
        # default
        return self._adaptive.extract(dom)

    # ─── finalization ──────────────────────────────────────────────────

    def _finalize(self, result: ScrapeResult, body: bytes) -> None:
        # Language
        if not result.language and result.text:
            result.language = LanguageDetector.detect(result.text)
        if not result.metadata.language and result.language:
            result.metadata.language = result.language

        # Tokens
        try:
            result.tokens = self.tokenizer.tokenize(
                result.cleaned or result.text)
        except Exception:
            result.tokens = ()

        # Word analysis
        try:
            wa = self.word_analyzer.analyze(result.tokens)
            result.most_used_word = wa["most_used_word"]
            result.least_used_word = wa["least_used_word"]
            result.words_count = wa["words_count"]
            result.unique_words = wa["unique_words"]
            result.char_count = wa["char_count"]
            result.avg_word_length = wa["avg_word_length"]
            result.lexical_density = wa["lexical_density"]
        except Exception:
            pass

        # Sentences
        try:
            if result.text:
                result.sentence_count = len(
                    [s for s in SENTENCE_SPLIT_RE.split(result.text) if s.strip()])
        except Exception:
            pass

        # Readability
        if self.config.compute_readability and result.text:
            try:
                result.readability = self.readability.analyze(result.text)
                if result.readability:
                    result.syllables = result.readability.get(
                        "syllable_count", 0)
                    result.avg_sentence_length = result.readability.get(
                        "avg_sentence_length", 0.0)
            except Exception:
                pass

        # Reading time
        if result.words_count:
            result.reading_time_seconds = result.words_count / 200.0

        # Quality
        try:
            q = self.scorer.score(
                result.text, result.paragraphs, result.tokens,
                result.raw_html,
                list(result.links_internal) + list(result.links_external),
            )
            result.quality = q
        except Exception:
            pass

    # ─── helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _css(dom: ParsedDOM, sel: str) -> list:
        try:
            if dom.kind == "selectolax":
                return dom.tree.css(sel)
            if dom.kind == "lxml":
                return dom.tree.cssselect(sel)
            if dom.kind == "bs4":
                return dom.tree.select(sel)
        except Exception:
            pass
        return []

    @staticmethod
    def _node_text(node: Any) -> str:
        try:
            if hasattr(node, "text") and callable(node.text):
                return node.text() or ""
            if hasattr(node, "text_content"):
                return node.text_content() or ""
            if hasattr(node, "get_text"):
                return node.get_text() or ""
        except Exception:
            pass
        return ""


# ════════════════════════════════════════════════════════════════════════════
# Public API
# ════════════════════════════════════════════════════════════════════════════

_scraper: Optional[Scraper] = None
_scraper_lock = threading.Lock()


def get_scraper(mgr: Optional[Any] = None,
                config: Optional[ScraperConfig] = None) -> Scraper:
    global _scraper
    if _scraper is None:
        with _scraper_lock:
            if _scraper is None:
                _scraper = Scraper(mgr=mgr, config=config)
    return _scraper


def reset_scraper() -> None:
    global _scraper
    with _scraper_lock:
        _scraper = None


def _to_crawl_page(result: ScrapeResult) -> Any:
    """Try to convert to CrawlPage for drop-in compatibility with Fa-Crawl."""
    try:
        crawl_module = _load_local_module("Fa_Crawl", "Fa-Crawl.py")
        CrawlPage = getattr(crawl_module, "CrawlPage")
    except Exception:
        return None
    try:
        return CrawlPage(
            url=result.url,
            final_url=result.url,
            domain=result.domain,
            status=result.status,
            title=result.title,
            language=result.language,
            content_type=result.content_kind.value,
            text=result.text,
            paragraphs=result.paragraphs,
            tokens=result.tokens,
            links_internal=result.links_internal,
            links_external=result.links_external,
            images=result.images,
            meta=asdict(result.metadata),
            json_ld=result.metadata.json_ld,
            most_used_word=result.most_used_word,
            least_used_word=result.least_used_word,
            words_count=result.words_count,
            unique_words=result.unique_words,
            reading_time_seconds=result.reading_time_seconds,
            cleaned=result.cleaned,
            raw_html=result.raw_html,
            fetched_at=result.fetched_at,
            depth=result.depth,
            from_cache=result.from_cache,
            elapsed_ms=result.elapsed_ms,
        )
    except Exception:
        return None


def scrape(body: Union[bytes, str],
           url: str,
           *,
           content_type: str = "",
           headers: Optional[Mapping[str, str]] = None,
           status: int = 200,
           depth: int = 0,
           from_cache: bool = False,
           elapsed_ms: float = 0.0,
           save_raw: Optional[bool] = None,
           return_crawl_page: bool = True) -> Union[ScrapeResult, Any]:
    """
    Primary entry point. Returns a rich ScrapeResult, or a CrawlPage if
    Fa-Crawl is importable and return_crawl_page=True.
    """
    s = get_scraper()
    result = s.scrape(
        body, url,
        content_type=content_type,
        headers=headers,
        status=status,
        depth=depth,
        from_cache=from_cache,
        elapsed_ms=elapsed_ms,
        save_raw=save_raw,
    )
    if return_crawl_page:
        cp = _to_crawl_page(result)
        if cp is not None:
            return cp
    return result


# ════════════════════════════════════════════════════════════════════════════
# CLI smoke test
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    sample_html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <title>Hello World - Test Site</title>
        <meta name="description" content="A test page.">
        <meta name="author" content="Jane Doe">
        <meta property="og:title" content="Hello World">
        <meta property="article:published_time" content="2026-10-12T15:00:00Z">
        <link rel="canonical" href="https://example.com/hello">
    </head>
    <body>
        <header><nav><a href="/">Home</a> | <a href="/about">About</a></nav></header>
        <article>
            <h1>Hello World</h1>
            <p>This is the first paragraph of the article. It contains
            several sentences. The quick brown fox jumps over the lazy dog.</p>
            <p>Here is a second paragraph. It talks about the fox again.
            The quick brown fox jumps over the lazy dog once more.</p>
            <ul><li>Item one</li><li>Item two</li></ul>
            <a href="https://external.com/page">External link</a>
            <a href="/internal">Internal link</a>
        </article>
        <footer>© 2026 Test Site</footer>
    </body>
    </html>
    """
    r = scrape(sample_html, "https://example.com/hello")
    print("Title:", r.title)
    print("Words:", r.words_count)
    print("Most used:", r.most_used_word)
    print("Least used:", r.least_used_word)
    print("Paragraphs:", len(r.paragraphs))
    print("Internal links:", len(r.links_internal))
    print("External links:", len(r.links_external))
    print("Quality:", r.quality.score, r.quality.tier)