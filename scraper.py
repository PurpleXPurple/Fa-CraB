import asyncio
import json
import os
import re
import signal
import sys
import time
import random
import math
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode


CONFIG = {
    'initial_concurrency': 400,
    'min_concurrency': 128,
    'max_concurrency': 3000,
    'session_pool_size': 48,
    'rotate_min': 300,
    'rotate_max': 600,
    'request_timeout': 12,
    'max_html_bytes': 1_500_000,
    'max_binary_bytes': 10_000_000,
    'max_text_chars': 200_000,
    'max_redirects': 5,
    'queue_high_water': 1_000_000,
    'stats_interval': 3.0,
    'idle_sleep': 0.01,
    'output_file': 'output.json',
    'bloom_expected': 30_000_000,
    'bloom_error': 0.001,
    'parser_workers': max(8, (os.cpu_count() or 4) * 2),
    'ocr_workers': 4,
    'ocr_concurrency': 4,
    'ocr_enabled': True,
    'ocr_min_text_chars': 100,
    'ocr_max_chars': 400_000,
    'ocr_pdf_max_pages': 10,
    'per_host_base': 64,
    'per_host_max': 512,
    'per_host_min': 8,
    'sitemap_max_count': 50,
    'sitemap_max_pages': 5000,
    'host_403_blacklist_threshold': 5,
    'impersonate_retry_limit': 2,
    'drop_log_limit': 15,
    'min_text_chars': 20,
}

OUTPUT_FILE = Path(CONFIG['output_file'])
PARSER_POOL = ThreadPoolExecutor(max_workers=CONFIG['parser_workers'])
OCR_POOL = ThreadPoolExecutor(max_workers=CONFIG['ocr_workers'])


# ===========================================================================
# Lazy imports
# ===========================================================================

_curl_AsyncSession = None
_parser_cls = None
_parser_mode = None
_pdf_reader_cls = None
_pdf2image_conv = None
_pytesseract = None
_pil_image = None


def _load_session_cls():
    global _curl_AsyncSession
    if _curl_AsyncSession is None:
        from curl_cffi.requests import AsyncSession
        _curl_AsyncSession = AsyncSession
    return _curl_AsyncSession


def _load_parser():
    global _parser_cls, _parser_mode
    if _parser_mode is not None:
        return _parser_mode
    try:
        from selectolax.lexbor import LexborHTMLParser
        _parser_cls = LexborHTMLParser
        _parser_mode = 'lexbor'
    except ImportError:
        try:
            from lxml import html as _lxml_html
            _parser_cls = _lxml_html
            _parser_mode = 'lxml'
        except ImportError:
            _parser_mode = 'none'
    return _parser_mode


def _load_pdf():
    global _pdf_reader_cls
    if _pdf_reader_cls is None:
        try:
            import pypdf
            _pdf_reader_cls = pypdf.PdfReader
        except ImportError:
            try:
                import PyPDF2
                _pdf_reader_cls = PyPDF2.PdfReader
            except ImportError:
                _pdf_reader_cls = False
    return _pdf_reader_cls


def _load_pdf_render():
    global _pdf2image_conv
    if _pdf2image_conv is None:
        try:
            from pdf2image import convert_from_bytes
            _pdf2image_conv = convert_from_bytes
        except ImportError:
            _pdf2image_conv = False
    return _pdf2image_conv


def _load_ocr():
    global _pytesseract, _pil_image
    if _pytesseract is None:
        try:
            import pytesseract as _pyt
            from PIL import Image as _PILImage
            _pytesseract = _pyt
            _pil_image = _PILImage
        except ImportError:
            _pytesseract = False
            _pil_image = False
    return _pytesseract


# ===========================================================================
# Bloom filter
# ===========================================================================

class BloomFilter:
    __slots__ = ('bits', 'num_bits', 'num_hashes', 'mask')

    def __init__(self, expected, error_rate):
        raw_bits = int(-(expected * math.log(error_rate)) / (math.log(2) ** 2))
        self.num_bits = 1 << max(6, (raw_bits - 1).bit_length())
        self.mask = self.num_bits - 1
        self.num_hashes = max(1, int((self.num_bits / expected) * math.log(2)))
        self.bits = bytearray(self.num_bits >> 3)

    def _h(self, b):
        h1 = hash(b)
        if len(b) > 128:
            h2 = hash(b[:64] + b'\x9e' + b[-64:])
        else:
            h2 = hash(b[::-1] + b'\x9e')
        if h2 == 0:
            h2 = 0x9E3779B97F4A7C15
        return h1, h2

    def add(self, item):
        self.add_bytes(item.encode('utf-8', 'ignore'))

    def add_bytes(self, item_bytes):
        h1, h2 = self._h(item_bytes)
        bits = self.bits
        mask = self.mask
        for i in range(self.num_hashes):
            idx = (h1 + i * h2) & mask
            bits[idx >> 3] |= 1 << (idx & 7)

    def __contains__(self, item):
        h1, h2 = self._h(item.encode('utf-8', 'ignore'))
        bits = self.bits
        mask = self.mask
        for i in range(self.num_hashes):
            idx = (h1 + i * h2) & mask
            if not (bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True


# ===========================================================================
# Rate limiting — per-host state + adaptive limit
# ===========================================================================

class DomainState:
    __slots__ = ('delay', 'fails', 'last_hit', 'limit', 'success_run',
                 'consecutive_403', 'blacklisted')

    def __init__(self, base_limit):
        self.delay = 0.0
        self.fails = 0
        self.last_hit = 0.0
        self.limit = base_limit
        self.success_run = 0
        self.consecutive_403 = 0
        self.blacklisted = False


class RateLimitTracker:
    __slots__ = ('domains', '_lock', 'base_limit', 'min_limit', 'max_limit')

    def __init__(self):
        self.domains = {}
        self._lock = asyncio.Lock()
        self.base_limit = CONFIG['per_host_base']
        self.min_limit = CONFIG['per_host_min']
        self.max_limit = CONFIG['per_host_max']

    def limit_for(self, host):
        state = self.domains.get(host)
        return state.limit if state is not None else self.base_limit

    def is_blacklisted(self, host):
        state = self.domains.get(host)
        return state is not None and state.blacklisted

    async def wait(self, host):
        state = self.domains.get(host)
        if state is None or state.delay <= 0:
            return
        gap = state.delay - (time.monotonic() - state.last_hit)
        if gap > 0:
            await asyncio.sleep(gap)

    async def record(self, host, status, retry_after=0.0):
        state = self.domains.get(host)
        # Fast path: clean 200, no delay and no prior problems.
        if status == 200 and retry_after == 0.0 and (state is None or state.delay <= 0.0):
            if state is None:
                async with self._lock:
                    state = self.domains.get(host)
                    if state is None:
                        state = DomainState(self.base_limit)
                        self.domains[host] = state
            state.last_hit = time.monotonic()
            state.success_run += 1
            state.consecutive_403 = 0
            if state.success_run >= 20 and state.limit < self.max_limit:
                state.success_run = 0
                state.limit = min(self.max_limit, state.limit * 2)
            return
        async with self._lock:
            state = self.domains.get(host)
            if state is None:
                state = DomainState(self.base_limit)
                self.domains[host] = state
            state.last_hit = time.monotonic()
            if retry_after > 0:
                state.delay = max(state.delay, min(retry_after, 300.0))
            if status in (429, 503, 502, 520, 521, 522, 523, 524):
                state.fails += 1
                state.success_run = 0
                state.limit = max(self.min_limit, state.limit // 2)
                state.delay = min(180.0, max(0.5, state.delay * 2.0) * random.uniform(0.8, 1.2))
            elif status == 403:
                state.fails += 1
                state.success_run = 0
                state.limit = max(self.min_limit, state.limit // 2)
                state.consecutive_403 += 1
                if state.consecutive_403 >= CONFIG['host_403_blacklist_threshold']:
                    state.blacklisted = True
            elif status == 401:
                state.fails += 1
                state.success_run = 0
                state.limit = max(self.min_limit, state.limit // 2)
                state.delay = min(90.0, max(0.8, state.delay * 1.6))
            elif status == 200:
                state.fails = 0
                state.delay = max(0.0, state.delay * 0.7 - 0.1)


# ===========================================================================
# Per-host gate — condition-based, blocks cleanly instead of spin-looping
# ===========================================================================

class HostGate:
    __slots__ = ('limit', 'inflight', '_cond')

    def __init__(self, limit):
        self.limit = limit
        self.inflight = 0
        self._cond = asyncio.Condition()

    async def acquire(self):
        async with self._cond:
            while self.inflight >= self.limit:
                await self._cond.wait()
            self.inflight += 1

    async def release(self):
        async with self._cond:
            self.inflight -= 1
            self._cond.notify(1)


# ===========================================================================
# Global adaptive gate — backstop against mass failures
# ===========================================================================

class AdaptiveGate:
    __slots__ = ('limit', 'min_lim', 'max_lim', 'inflight',
                 '_cond', '_results', '_failures', '_releases')

    def __init__(self, initial, min_lim, max_lim):
        self.limit = initial
        self.min_lim = min_lim
        self.max_lim = max_lim
        self.inflight = 0
        self._cond = asyncio.Condition()
        self._results = deque()
        self._failures = 0
        self._releases = 0

    async def acquire(self):
        async with self._cond:
            while self.inflight >= self.limit:
                await self._cond.wait()
            self.inflight += 1

    async def release(self, status):
        async with self._cond:
            self.inflight -= 1
            if len(self._results) >= 256:
                if self._results.popleft() >= 400:
                    self._failures -= 1
            self._results.append(status)
            if status >= 400:
                self._failures += 1
            self._releases += 1
            if self._releases >= 64:
                self._releases = 0
                self._adjust()
            self._cond.notify(1)

    def _adjust(self):
        n = len(self._results)
        if n < 200:
            return
        rate = self._failures / n
        if rate > 0.25:
            self.limit = max(self.min_lim, int(self.limit * 0.75))
        elif rate > 0.15:
            self.limit = max(self.min_lim, int(self.limit * 0.90))
        elif rate < 0.03 and self.limit < self.max_lim:
            self.limit = min(self.max_lim, int(self.limit * 1.15))

    @property
    def current(self):
        return self.limit


# ===========================================================================
# Header spoofing
# ===========================================================================

_ACCEPT_LANGS = (
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.8,de;q=0.6',
)

_ACCEPTS = (
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
)

_REFERERS = (
    'https://www.google.com/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.brave.com/',
)


def build_headers(referer, target_host):
    o = random.choice
    if referer:
        ref_host = host_of(referer)
        sec_site = 'same-origin' if ref_host == target_host else 'cross-site'
    else:
        sec_site = 'none'
    return {
        'Accept': o(_ACCEPTS),
        'Accept-Language': o(_ACCEPT_LANGS),
        'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
        'DNT': '1',
        'Upgrade-Insecure-Requests': '1',
        'Connection': 'keep-alive',
        'Referer': referer or o(_REFERERS),
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': sec_site,
        'Sec-Fetch-User': '?1',
    }


# ===========================================================================
# Session pool
# ===========================================================================

def _available_impersonations():
    try:
        from curl_cffi.const import BrowserType
        keys = sorted({b.value for b in BrowserType if isinstance(b.value, str)})
        if keys:
            return keys
    except Exception:
        pass
    return [
        'chrome136', 'chrome131', 'chrome124', 'chrome120', 'chrome116',
        'chrome110', 'chrome107', 'chrome104', 'chrome101', 'chrome100',
        'chrome99', 'edge101', 'edge99', 'safari170', 'safari155',
        'safari153', 'firefox133', 'firefox128', 'firefox120',
    ]


class SessionPool:
    __slots__ = ('size', 'keys', 'sessions', 'hits', 'thresholds', 'locks')

    def __init__(self, size, keys):
        self.size = size
        self.keys = keys
        self.sessions = [None] * size
        self.hits = [0] * size
        self.thresholds = [0] * size
        self.locks = [asyncio.Lock() for _ in range(size)]

    async def start(self):
        SessionCls = _load_session_cls()
        for i in range(self.size):
            self.sessions[i] = self._make(SessionCls)
            self.thresholds[i] = random.randint(CONFIG['rotate_min'], CONFIG['rotate_max'])

    def _make(self, SessionCls):
        for _ in range(3):
            key = random.choice(self.keys)
            try:
                return SessionCls(impersonate=key, timeout=CONFIG['request_timeout'])
            except Exception:
                continue
        return None

    async def stop(self):
        await asyncio.gather(
            *(s.close() for s in self.sessions if s is not None),
            return_exceptions=True,
        )

    def pick(self):
        return random.randrange(self.size)

    def get(self, idx):
        return self.sessions[idx]

    def bump(self, idx):
        self.hits[idx] += 1

    def needs_rotation(self, idx):
        return self.hits[idx] >= self.thresholds[idx]

    def force_rotate(self, idx):
        self.hits[idx] = self.thresholds[idx]

    async def rotate(self, idx):
        async with self.locks[idx]:
            if self.hits[idx] < self.thresholds[idx]:
                return
            old = self.sessions[idx]
            if old is not None:
                try:
                    await old.close()
                except Exception:
                    pass
            SessionCls = _load_session_cls()
            self.sessions[idx] = self._make(SessionCls)
            self.hits[idx] = 0
            self.thresholds[idx] = random.randint(CONFIG['rotate_min'], CONFIG['rotate_max'])


# ===========================================================================
# URL normalization
# ===========================================================================

_BAD_SCHEMES = (
    'mailto:', 'tel:', 'sms:', 'callto:', 'skype:', 'whatsapp:',
    'javascript:', 'data:', 'blob:', 'about:', 'chrome:', 'moz-extension:',
    'ftp:', 'ftps:', 'sftp:', 'ssh:', 'file:', 'irc:', 'ircs:',
    'news:', 'nntp:', 'gopher:', 'ws:', 'wss:', 'view-source:',
    'intent:', 'market:', 'itms:', 'itms-apps:', 'bitcoin:', 'ethereum:',
)

_SKIP_EXT = re.compile(
    r'\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|heic|'
    r'css|js|mjs|jsx|ts|tsx|map|'
    r'woff2?|ttf|otf|eot|'
    r'mp[34]|m4a|m4v|aac|ogg|oga|ogv|wav|flac|opus|'
    r'avi|mkv|mov|webm|flv|wmv|mpg|mpeg|3gp|'
    r'docx?|xlsx?|pptx?|odt|ods|odp|rtf|'
    r'zip|tar|gz|tgz|bz2|xz|rar|7z|lz|lzma|zst|'
    r'exe|dmg|msi|apk|deb|rpm|iso|img|bin|jar|class|'
    r'rss|atom|jsonl|ndjson|csv|tsv|yaml|yml|toml|ini|conf|cfg|'
    r'psd|ai|eps|sketch|fig|xd|'
    r'torrent|magnet|wasm)(\?|#|$)',
    re.IGNORECASE,
)

_HARD_SKIP_PATH_RE = re.compile(
    r'/(wp-admin|wp-login\.php|wp-json|xmlrpc\.php|'
    r'cart|checkout|basket|order|payment|'
    r'admin|dashboard|account|settings|'
    r'cdn-cgi|wp-content/uploads|assets?|static)(/|$|\?)',
    re.IGNORECASE,
)

_TRACKING_KEYS = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'utm_id', 'utm_source_platform', 'utm_creative_format', 'utm_marketing_tactic',
    'gclid', 'gclsrc', 'dclid', 'gbraid', 'wbraid',
    'fbclid', 'fb_action_ids', 'fb_action_types', 'fb_source', 'fb_ref',
    'mc_cid', 'mc_eid', 'mkt_tok',
    'yclid', '_openstat', 'msclkid', 'twclid', 'ttclid', 'li_fat_id',
    'igshid', 'vero_id', 'vero_conv', 'wickedid', 'oly_anon_id', 'oly_enc_id',
    'ref', 'ref_src', 'ref_url', 'referrer', 'source', 'src',
    '_ga', '_gl', 'sc_cid', 'sc_uid',
    'spm', 'scm', 'from', 'from_source', 'share_source', 'share_medium',
})

_TRACKING_HINTS = ('utm_', 'fbclid', 'gclid', 'ref=', 'source=', 'mc_', '_ga', 'spm', 'scm')


def _strip_tracking(url):
    if '?' not in url:
        return url
    low = url.lower()
    if not any(h in low for h in _TRACKING_HINTS):
        return url
    try:
        p = urlparse(url)
    except Exception:
        return url
    if not p.query:
        return url
    all_q = parse_qsl(p.query, keep_blank_values=True)
    kept = [(k, v) for k, v in all_q if k.lower() not in _TRACKING_KEYS]
    if len(kept) == len(all_q):
        return url
    return p._replace(query=urlencode(kept, doseq=True)).geturl()


def normalize(url, base=''):
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url or url[0] == '#':
        return None
    low = url.lower()
    if low.startswith(_BAD_SCHEMES):
        return None
    if '#' in url:
        url = urldefrag(url)[0]
        if not url:
            return None
    if base:
        try:
            url = urljoin(base, url)
        except Exception:
            return None
    try:
        p = urlparse(url)
    except Exception:
        return None
    if p.scheme not in ('http', 'https'):
        return None
    netloc = p.netloc
    if not netloc or '.' not in netloc or len(netloc) > 253:
        return None
    path = p.path
    path_check = path if len(path) <= 100 else path[:60] + path[-40:]
    if '.' in path_check and _SKIP_EXT.search(path_check):
        return None
    if _HARD_SKIP_PATH_RE.search(path):
        return None
    return _strip_tracking(url)


def host_of(url):
    i = url.find('://')
    if i < 0:
        return ''
    i += 3
    j = url.find('/', i)
    if j < 0:
        return url[i:].lower()
    return url[i:j].lower()


# ===========================================================================
# HTML parsing
# ===========================================================================

_KILL_TAGS = (
    'script', 'style', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
    'audio', 'video', 'source', 'track', 'dialog', 'menu', 'menuitem',
    'nav', 'footer', 'header', 'aside',
)

_KILL_SELECTOR = ','.join(_KILL_TAGS)

_MAIN_SELECTORS = (
    'article', 'main', '[role="main"]', '#content',
    '.post-content', '.entry-content', '.article-content',
    '.article-body', '.story-body', '.content-body',
    '.md-content', '.md-main__inner',
)

_MAIN_XPATHS = (
    '//article', '//main', '//*[@role="main"]', '//*[@id="content"]',
    '//*[contains(@class, "post-content")]',
    '//*[contains(@class, "entry-content")]',
    '//*[contains(@class, "article-content")]',
    '//*[contains(@class, "article-body")]',
    '//*[contains(@class, "story-body")]',
    '//*[contains(@class, "content-body")]',
    '//*[contains(@class, "md-content")]',
)

_WS_RE = re.compile(r'[^\S\n]+')
_NL_RE = re.compile(r'\n{3,}')
_JUNK_RE = re.compile(r'[^\x20-\x7E\n\t]')
_META_REFRESH_RE = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.IGNORECASE)

_LINK_SELECTOR = (
    'a[href], area[href], iframe[src], frame[src], '
    'link[rel="next"], link[rel="prev"], link[rel="canonical"], '
    'link[rel="alternate"], link[rel="amphtml"], '
    'link[rel="sitemap"], meta[http-equiv="refresh"]'
)


def _finalize_text(text):
    text = _WS_RE.sub(' ', text)
    text = _NL_RE.sub('\n\n', text)
    text = _JUNK_RE.sub('', text)
    return text.strip()


def _extract_links_selectolax(tree, base_url):
    links = []
    seen = set()
    for node in tree.css(_LINK_SELECTOR):
        tag = node.tag
        val = None
        if tag in ('a', 'area'):
            val = node.attributes.get('href')
        elif tag in ('iframe', 'frame'):
            val = node.attributes.get('src')
        elif tag == 'link':
            val = node.attributes.get('href')
        elif tag == 'meta':
            content = node.attributes.get('content') or ''
            mr = _META_REFRESH_RE.search(content)
            if mr:
                val = mr.group(1)
        if not val:
            continue
        n = normalize(val, base_url)
        if n and n not in seen:
            seen.add(n)
            links.append(n)
            if len(links) >= 5000:
                return tuple(links)
    for el in tree.css('[data-href],[data-url],[data-link]'):
        for attr in ('data-href', 'data-url', 'data-link'):
            val = el.attributes.get(attr)
            if val:
                n = normalize(val, base_url)
                if n and n not in seen:
                    seen.add(n)
                    links.append(n)
                break
        if len(links) >= 5000:
            break
    return tuple(links)


def _extract_links_lxml(doc, base_url):
    links = []
    seen = set()
    for node in doc.iter():
        tag = node.tag
        val = None
        if tag in ('a', 'area'):
            val = node.get('href')
        elif tag in ('iframe', 'frame'):
            val = node.get('src')
        elif tag == 'link':
            val = node.get('href')
        elif tag == 'meta':
            he = (node.get('http-equiv') or '').lower()
            if he == 'refresh':
                content = node.get('content') or ''
                mr = _META_REFRESH_RE.search(content)
                if mr:
                    val = mr.group(1)
        elif tag is not None:
            for attr in ('data-href', 'data-url', 'data-link'):
                v = node.get(attr)
                if v:
                    val = v
                    break
        if not val:
            continue
        n = normalize(val, base_url)
        if n and n not in seen:
            seen.add(n)
            links.append(n)
            if len(links) >= 5000:
                return tuple(links)
    return tuple(links)


def _meta_text_fallback_selectolax(tree):
    """Pull og:description / twitter:description / meta description as fallback text."""
    parts = []
    for sel, attr in (
        ('meta[property="og:description"]', 'content'),
        ('meta[name="twitter:description"]', 'content'),
        ('meta[name="description"]', 'content'),
    ):
        node = tree.css_first(sel)
        if node:
            v = (node.attributes.get(attr) or '').strip()
            if v and v not in parts:
                parts.append(v)
    return ' '.join(parts)


def _meta_text_fallback_lxml(doc):
    parts = []
    for xp, attr in (
        ('//meta[@property="og:description"]', 'content'),
        ('//meta[@name="twitter:description"]', 'content'),
        ('//meta[@name="description"]', 'content'),
    ):
        r = doc.xpath(xp + '/@' + attr)
        if r:
            v = (r[0] or '').strip()
            if v and v not in parts:
                parts.append(v)
    return ' '.join(parts)


def _parse_selectolax(raw, base_url, cfg):
    try:
        tree = _parser_cls(raw)
    except Exception:
        return None, ()

    title = ''
    t = tree.css_first('title')
    if t:
        title = (t.text() or '').strip()
    if not title:
        h1 = tree.css_first('h1')
        if h1:
            title = (h1.text() or '').strip()[:200]
    if not title:
        og = tree.css_first('meta[property="og:title"]')
        if og:
            title = (og.attributes.get('content') or '')[:200]

    links = _extract_links_selectolax(tree, base_url)

    content = None
    for sel in _MAIN_SELECTORS:
        node = tree.css_first(sel)
        if node:
            content = node
            break
    source = content if content is not None else tree

    for tag in source.css(_KILL_SELECTOR):
        tag.decompose()

    try:
        text = source.text(separator='\n') or ''
    except Exception:
        text = ''
    if len(text) > cfg['max_text_chars']:
        text = text[:cfg['max_text_chars']]
    text = _finalize_text(text)

    # SPA fallback: if the main content was too thin, grab meta description.
    if len(text) < cfg['min_text_chars']:
        meta = _meta_text_fallback_selectolax(tree)
        if len(meta) > len(text):
            text = meta

    if not text and not title:
        return None, links
    if len(text) < cfg['min_text_chars'] and not title:
        return None, links

    return (title or '[untitled]', text), links


def _parse_lxml(raw, base_url, cfg):
    try:
        doc = _parser_cls.document_fromstring(raw, base_url=base_url)
    except Exception:
        return None, ()

    title = ''
    t = doc.find('.//title')
    if t is not None and t.text:
        title = t.text.strip()
    if not title:
        for h in doc.iter('h1'):
            txt = h.text_content()
            if txt and txt.strip():
                title = txt.strip()[:200]
                break
    if not title:
        og = doc.xpath('//meta[@property="og:title"]/@content')
        if og:
            title = og[0][:200]

    links = _extract_links_lxml(doc, base_url)

    content = None
    for xp in _MAIN_XPATHS:
        r = doc.xpath(xp)
        if r:
            content = r[0]
            break
    source = content if content is not None else doc

    for tag in list(source.iter(*_KILL_TAGS)):
        parent = tag.getparent()
        if parent is not None:
            parent.remove(tag)

    try:
        text = source.text_content()
    except Exception:
        text = ''
    if len(text) > cfg['max_text_chars']:
        text = text[:cfg['max_text_chars']]
    text = _finalize_text(text)

    if len(text) < cfg['min_text_chars']:
        meta = _meta_text_fallback_lxml(doc)
        if len(meta) > len(text):
            text = meta

    if not text and not title:
        return None, links
    if len(text) < cfg['min_text_chars'] and not title:
        return None, links

    return (title or '[untitled]', text), links


def _parse_and_extract(raw, base_url):
    cfg = CONFIG
    if _parser_mode == 'lexbor':
        return _parse_selectolax(raw, base_url, cfg)
    return _parse_lxml(raw, base_url, cfg)


# ===========================================================================
# Binary extraction (PDF + images)
# ===========================================================================

def _pdf_extract_text(content_bytes):
    PdfReader = _load_pdf()
    if not PdfReader:
        return None
    try:
        from io import BytesIO
        reader = PdfReader(BytesIO(content_bytes))
        title = ''
        try:
            meta = reader.metadata
            if meta:
                title = getattr(meta, 'title', '') or ''
        except Exception:
            pass
        parts = []
        for i, page in enumerate(reader.pages):
            if i > 500:
                break
            try:
                t = page.extract_text()
                if t:
                    parts.append(t)
            except Exception:
                continue
        return title, '\n\n'.join(parts)
    except Exception:
        return None


def _image_ocr_pil(img):
    if not _load_ocr():
        return None
    try:
        if img.mode not in ('L', 'RGB'):
            img = img.convert('RGB')
        text = _pytesseract.image_to_string(img)
        return text.strip() if text else None
    except Exception:
        return None


def _pdf_ocr(content_bytes):
    conv = _load_pdf_render()
    if not conv or not _load_ocr():
        return None
    try:
        images = conv(content_bytes, dpi=200, fmt='png')
        parts = []
        for i in range(min(len(images), CONFIG['ocr_pdf_max_pages'])):
            t = _image_ocr_pil(images[i])
            if t:
                parts.append(t)
        return '\n\n'.join(parts)
    except Exception:
        return None


def _image_ocr_bytes(content_bytes):
    if not _load_ocr():
        return None
    try:
        from io import BytesIO
        img = _pil_image.open(BytesIO(content_bytes))
        return _image_ocr_pil(img)
    except Exception:
        return None


def _extract_binary(content_bytes, content_type, url):
    if content_type == 'pdf':
        result = _pdf_extract_text(content_bytes)
        title, text = result if result else ('', '')
        if len(text) < CONFIG['ocr_min_text_chars'] and CONFIG['ocr_enabled']:
            ocr_text = _pdf_ocr(content_bytes)
            if ocr_text and len(ocr_text) > len(text):
                text = ocr_text
        if not title:
            tail = url.rsplit('/', 1)[-1] if '/' in url else url
            title = tail.rsplit('.', 1)[0][:200] if '.' in tail else tail[:200]
        text = _finalize_text(text)
        if len(text) > CONFIG['ocr_max_chars']:
            text = text[:CONFIG['ocr_max_chars']]
        if not text:
            return None
        return title or '[untitled]', text

    if content_type == 'image':
        if not CONFIG['ocr_enabled']:
            return None
        text = _image_ocr_bytes(content_bytes) or ''
        text = _finalize_text(text)
        if len(text) < 20:
            return None
        if len(text) > CONFIG['ocr_max_chars']:
            text = text[:CONFIG['ocr_max_chars']]
        first_line = text.split('\n', 1)[0].strip()[:200]
        return first_line or '[image]', text

    return None


# ===========================================================================
# Bloom prefill (resume-safe)
# ===========================================================================

def _prefill_bloom_from_output(bloom):
    if not OUTPUT_FILE.exists():
        return
    json_parse_limit = 5000
    try:
        with OUTPUT_FILE.open('rb') as f:
            count = 0
            for line in f:
                line = line.strip()
                if not line:
                    continue
                count += 1
                if count <= json_parse_limit:
                    try:
                        obj = json.loads(line)
                        u = obj.get('url')
                        if isinstance(u, str):
                            bloom.add(u)
                        continue
                    except Exception:
                        pass
                needle = b'"url":"'
                i = line.find(needle)
                if i < 0:
                    continue
                i += len(needle)
                j = line.find(b'"', i)
                if j < 0:
                    continue
                bloom.add_bytes(line[i:j])
    except Exception:
        pass


# ===========================================================================
# Challenge detection + retry-after + sitemaps
# ===========================================================================

_CHALLENGE_MARKERS = (
    b'<title>just a moment',
    b'<title>attention required',
    b'<title>checking your browser',
    b'<title>one more step',
    b'cf-chl-widget',
    b'__cf_chl_rt_tk',
    b'cf-please-wait',
)


def _is_challenge(raw_bytes, status, headers):
    if status not in (403, 429, 503):
        return False
    try:
        mitigated = headers.get('cf-mitigated') or headers.get('CF-Mitigated')
        if mitigated and 'challenge' in mitigated.lower():
            return True
    except Exception:
        pass
    if not raw_bytes:
        return False
    head = raw_bytes[:40000].lower()
    for m in _CHALLENGE_MARKERS:
        if m in head:
            return True
    return False


def _parse_retry_after(resp):
    try:
        ra = resp.headers.get('retry-after')
    except Exception:
        return 0.0
    if not ra:
        return 0.0
    try:
        return float(ra)
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(ra)
        return max(0.0, dt.timestamp() - time.time())
    except Exception:
        return 0.0


_SITEMAP_LOC_RE = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.IGNORECASE)


# ===========================================================================
# Crawler
# ===========================================================================

class Crawler:
    __slots__ = (
        'bloom', 'queue', 'host_gates', 'pool', 'gate', 'rate_limiter',
        'written', 'fetched', 'dropped', 'zero_link_pages', 'errors',
        'stop_flag', 'out_fd', 'stats_task', 'start_time',
        'last_report_time', 'last_report_written', 'seed', 'seed_host',
        'ocr_sem', 'challenges_total', 'blacklisted_hosts',
        'drop_log_count', 'drop_reasons', 'impersonate_errors',
        'queue_event',
    )

    def __init__(self):
        self.bloom = BloomFilter(CONFIG['bloom_expected'], CONFIG['bloom_error'])
        self.queue = deque()
        self.host_gates = {}
        self.pool = None
        self.gate = AdaptiveGate(
            CONFIG['initial_concurrency'],
            CONFIG['min_concurrency'],
            CONFIG['max_concurrency'],
        )
        self.rate_limiter = RateLimitTracker()
        self.written = 0
        self.fetched = 0
        self.dropped = 0
        self.zero_link_pages = 0
        self.errors = 0
        self.stop_flag = False
        self.out_fd = -1
        self.stats_task = None
        self.start_time = time.time()
        self.last_report_time = self.start_time
        self.last_report_written = 0
        self.seed = ''
        self.seed_host = ''
        self.ocr_sem = None
        self.challenges_total = 0
        self.blacklisted_hosts = set()
        self.drop_log_count = 0
        self.drop_reasons = {}
        self.impersonate_errors = 0
        self.queue_event = asyncio.Event()

    def _log_drop(self, reason, url):
        self.dropped += 1
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + 1
        if self.drop_log_count < CONFIG['drop_log_limit']:
            self.drop_log_count += 1
            print(f'[drop:{reason}] {url[:100]}', file=sys.stderr)

    def _host_gate(self, host):
        g = self.host_gates.get(host)
        if g is None:
            g = HostGate(self.rate_limiter.limit_for(host))
            self.host_gates[host] = g
        return g

    def _enqueue(self, items):
        self.queue.extend(items)
        self.queue_event.set()

    async def _standalone_fetch(self, url, timeout=15):
        SessionCls = _load_session_cls()
        key = random.choice(self.pool.keys) if self.pool and self.pool.keys else 'chrome136'
        try:
            async with SessionCls(impersonate=key, timeout=timeout) as sess:
                resp = await sess.get(url, allow_redirects=True, max_redirects=5)
                if resp.status_code == 200:
                    try:
                        return resp.text
                    except Exception:
                        try:
                            return (resp.content or b'').decode('utf-8', 'ignore')
                        except Exception:
                            return None
        except Exception:
            return None

    async def _seed_sitemaps(self, seed_url):
        parsed = urlparse(seed_url)
        base = f'{parsed.scheme}://{parsed.netloc}'

        robots = await self._standalone_fetch(f'{base}/robots.txt', timeout=15)

        sitemap_urls = []
        if robots:
            for line in robots.splitlines():
                line = line.strip()
                if line.lower().startswith('sitemap:'):
                    sm = line[8:].strip()
                    if sm.startswith(('http://', 'https://')):
                        sitemap_urls.append(sm)

        if not sitemap_urls:
            sitemap_urls = [f'{base}/sitemap.xml', f'{base}/sitemap_index.xml']

        seen_sitemaps = set()
        pages_added = 0
        pending = deque(sitemap_urls[:CONFIG['sitemap_max_count']])
        max_sitemaps = CONFIG['sitemap_max_count']
        max_pages = CONFIG['sitemap_max_pages']

        while pending and len(seen_sitemaps) < max_sitemaps and pages_added < max_pages:
            sm_url = pending.popleft()
            if sm_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sm_url)
            xml = await self._standalone_fetch(sm_url, timeout=20)
            if not xml:
                continue
            low_xml = xml[:3000].lower()
            locs = _SITEMAP_LOC_RE.findall(xml)
            if '<sitemapindex' in low_xml:
                for loc in locs[:20]:
                    if loc not in seen_sitemaps and len(seen_sitemaps) + len(pending) < max_sitemaps:
                        pending.append(loc)
            else:
                for loc in locs:
                    n = normalize(loc)
                    if n and n not in self.bloom:
                        self.bloom.add(n)
                        self.queue.append((n, seed_url, 1))
                        pages_added += 1
                        if pages_added >= max_pages:
                            break
        if pages_added:
            self.queue_event.set()
        print(f'[sitemaps] {len(seen_sitemaps)} sitemaps, {pages_added} pages queued', file=sys.stderr)

    async def run(self, seed):
        self.seed = seed
        self.seed_host = host_of(seed)

        mode = _load_parser()
        if mode == 'none':
            print('[!] no HTML parser available (pip install selectolax)', file=sys.stderr)
            return

        keys = _available_impersonations()
        if not keys:
            print('[!] no curl_cffi impersonation keys', file=sys.stderr)
            return

        _prefill_bloom_from_output(self.bloom)
        self.bloom.add(seed)
        self.queue.append((seed, '', 0))

        self.ocr_sem = asyncio.Semaphore(CONFIG['ocr_concurrency'])
        self.pool = SessionPool(CONFIG['session_pool_size'], keys)
        await self.pool.start()

        self.out_fd = os.open(
            str(OUTPUT_FILE),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o644,
        )

        ocr_ready = bool(_load_ocr() and CONFIG['ocr_enabled'])
        pdf_ready = bool(_load_pdf())
        engine = 'lexbor' if mode == 'lexbor' else 'lxml'

        print(f'[Nexus] seed:      {seed}', file=sys.stderr)
        print(f'[Nexus] output:    {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:    {engine}  parsers={CONFIG["parser_workers"]}', file=sys.stderr)
        print(f'[Nexus] workers:   {CONFIG["initial_concurrency"]}  gate={CONFIG["min_concurrency"]}-{CONFIG["max_concurrency"]}', file=sys.stderr)
        print(f'[Nexus] sessions:  {CONFIG["session_pool_size"]}  impersonate={len(keys)}', file=sys.stderr)
        print(f'[Nexus] per-host:  base={CONFIG["per_host_base"]}  max={CONFIG["per_host_max"]}', file=sys.stderr)
        print(f'[Nexus] pdf:       {"pypdf" if pdf_ready else "off"}   ocr: {"on" if ocr_ready else "off"}', file=sys.stderr)

        print('[Nexus] seeding sitemaps...', file=sys.stderr)
        try:
            await self._seed_sitemaps(seed)
        except Exception as e:
            print(f'[sitemaps] failed: {e}', file=sys.stderr)

        print('[Nexus] CTRL+C to stop.\n', file=sys.stderr)

        self.stats_task = asyncio.create_task(self._stats_loop())
        workers = [asyncio.create_task(self._worker(i)) for i in range(CONFIG['initial_concurrency'])]
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            pass
        finally:
            self.stop_flag = True
            self.stats_task.cancel()
            try:
                await self.stats_task
            except Exception:
                pass
            try:
                if self.out_fd >= 0:
                    os.fsync(self.out_fd)
            except Exception:
                pass
            PARSER_POOL.shutdown(wait=False)
            OCR_POOL.shutdown(wait=False)
            try:
                if self.out_fd >= 0:
                    os.close(self.out_fd)
            except Exception:
                pass
            await self.pool.stop()
            self._final_report()

    async def _stats_loop(self):
        interval = CONFIG['stats_interval']
        next_t = time.monotonic() + interval
        while not self.stop_flag:
            delay = next_t - time.monotonic()
            if delay > 0:
                await asyncio.sleep(delay)
            next_t += interval
            t = time.time()
            dt = t - self.last_report_time
            dw = self.written - self.last_report_written
            rate = dw / dt if dt > 0 else 0.0
            avg = self.written / (t - self.start_time) if t > self.start_time else 0.0
            err_pct = (self.dropped / self.fetched * 100.0) if self.fetched else 0.0
            print(
                f'[s] {rate:6.1f}/s avg {avg:6.1f}/s  '
                f'w={self.written} f={self.fetched} d={self.dropped}({err_pct:.0f}%)  '
                f'q={len(self.queue)} h={len(self.host_gates)}  '
                f'g={self.gate.current} zl={self.zero_link_pages}  '
                f'ch={self.challenges_total} im={self.impersonate_errors} bl={len(self.blacklisted_hosts)}',
                file=sys.stderr,
            )
            self.last_report_time = t
            self.last_report_written = self.written

    def _final_report(self):
        elapsed = time.time() - self.start_time
        avg = self.written / elapsed if elapsed > 0 else 0
        print(
            f'\n[Nexus] done. written={self.written}  fetched={self.fetched}  '
            f'dropped={self.dropped}  errors={self.errors}  '
            f'zerolink={self.zero_link_pages}  challenges={self.challenges_total}  '
            f'imp-errors={self.impersonate_errors}  '
            f'elapsed={elapsed:.1f}s  avg={avg:.1f}/s',
            file=sys.stderr,
        )
        if self.blacklisted_hosts:
            print(f'[blacklisted] {sorted(self.blacklisted_hosts)[:20]}', file=sys.stderr)
        if self.drop_reasons:
            top = sorted(self.drop_reasons.items(), key=lambda x: -x[1])[:10]
            print('[drops] ' + '  '.join(f'{r}={c}' for r, c in top), file=sys.stderr)

    async def _worker(self, wid):
        while not self.stop_flag:
            try:
                url, referer, depth = self.queue.popleft()
            except IndexError:
                self.queue_event.clear()
                try:
                    await asyncio.wait_for(self.queue_event.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    pass
                continue
            host = host_of(url)
            if not host:
                continue
            if host in self.blacklisted_hosts or self.rate_limiter.is_blacklisted(host):
                self.blacklisted_hosts.add(host)
                self.dropped += 1
                continue
            try:
                await self._process(url, referer, depth, host)
            except Exception as e:
                self.errors += 1
                if self.errors <= 20:
                    print(f'[w{wid}] {url[:80]}: {type(e).__name__}: {e}', file=sys.stderr)

    async def _process(self, url, referer, depth, host):
        self.fetched += 1
        status = 0
        retry_after = 0.0
        await self.rate_limiter.wait(host)
        await self.gate.acquire()
        host_gate = self._host_gate(host)
        host_gate.limit = self.rate_limiter.limit_for(host)
        await host_gate.acquire()
        try:
            resp = None
            body_bytes = b''
            raw = None
            resp_headers = {}

            for _ in range(CONFIG['impersonate_retry_limit'] + 1):
                idx = self.pool.pick()
                sess = self.pool.get(idx)
                if sess is None:
                    self.pool.force_rotate(idx)
                    await self.pool.rotate(idx)
                    continue
                headers = build_headers(referer, host)
                try:
                    resp = await sess.get(
                        url,
                        headers=headers,
                        timeout=CONFIG['request_timeout'],
                        allow_redirects=True,
                        max_redirects=CONFIG['max_redirects'],
                    )
                    status = resp.status_code
                    try:
                        body_bytes = resp.content or b''
                    except Exception:
                        body_bytes = b''
                    try:
                        raw = resp.text
                    except Exception:
                        try:
                            raw = body_bytes.decode('utf-8', 'ignore')
                        except Exception:
                            raw = None
                    self.pool.bump(idx)
                    if self.pool.needs_rotation(idx):
                        asyncio.create_task(self.pool.rotate(idx))
                    break
                except Exception as e:
                    err_name = type(e).__name__
                    self.pool.bump(idx)
                    if 'Impersonate' in err_name:
                        self.impersonate_errors += 1
                        self.pool.force_rotate(idx)
                        try:
                            await self.pool.rotate(idx)
                        except Exception:
                            pass
                        continue
                    if self.pool.needs_rotation(idx):
                        asyncio.create_task(self.pool.rotate(idx))
                    self._log_drop(f'fetch-{err_name}', url)
                    return
            else:
                self._log_drop('impersonate-retry-exhausted', url)
                return

            if resp is None:
                self._log_drop('no-response', url)
                return

            try:
                resp_headers = dict(resp.headers)
            except Exception:
                pass

            ctype = (resp_headers.get('content-type') or resp_headers.get('Content-Type') or '').lower()

            if _is_challenge(body_bytes, status, resp_headers):
                self.challenges_total += 1
                self._log_drop(f'challenge-{status}', url)
                return

            if status != 200:
                if status in (403, 429, 502, 503, 520, 521, 522, 523, 524):
                    self.pool.force_rotate(idx)
                    asyncio.create_task(self.pool.rotate(idx))
                if status in (429, 503):
                    retry_after = _parse_retry_after(resp)
                self._log_drop(f'status-{status}', url)
                return

            if 'text/html' in ctype or 'application/xhtml' in ctype or not ctype:
                content_type = 'html'
            elif 'application/pdf' in ctype:
                content_type = 'pdf'
            elif ctype.startswith('image/'):
                content_type = 'image'
            else:
                self._log_drop(f'ctype-{ctype[:30]}', url)
                return

            loop = asyncio.get_running_loop()

            if content_type == 'html':
                if not raw:
                    self._log_drop('empty-html', url)
                    return
                if len(raw) > CONFIG['max_html_bytes']:
                    raw = raw[:CONFIG['max_html_bytes']]
                try:
                    cleaned, links = await loop.run_in_executor(
                        PARSER_POOL, _parse_and_extract, raw, url
                    )
                except Exception as e:
                    self._log_drop(f'parse-{type(e).__name__}', url)
                    return
            else:
                if not body_bytes:
                    self._log_drop('empty-binary', url)
                    return
                if len(body_bytes) > CONFIG['max_binary_bytes']:
                    self._log_drop('binary-too-large', url)
                    return
                async with self.ocr_sem:
                    try:
                        cleaned = await loop.run_in_executor(
                            OCR_POOL, _extract_binary, body_bytes, content_type, url
                        )
                    except Exception as e:
                        self._log_drop(f'ocr-{type(e).__name__}', url)
                        return
                links = ()

            if cleaned is not None:
                title, text = cleaned
                record = {'url': url, 'title': title, 'text': text}
                if content_type != 'html':
                    record['content_type'] = content_type
                line = json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n'
                try:
                    os.write(self.out_fd, line)
                    self.written += 1
                except OSError as e:
                    print(f'[write] {e}', file=sys.stderr)
                    self.stop_flag = True
                    return
            else:
                if content_type == 'html':
                    self._log_drop('empty-text', url)

            if not links:
                self.zero_link_pages += 1
            else:
                misses = []
                bl = self.bloom
                for link in links:
                    if link not in bl:
                        bl.add(link)
                        misses.append(link)
                if misses and len(self.queue) < CONFIG['queue_high_water']:
                    self._enqueue((link, url, depth + 1) for link in misses)
        finally:
            await host_gate.release()
            await self.gate.release(status or 599)
            await self.rate_limiter.record(host, status, retry_after)


# ===========================================================================
# Entrypoint
# ===========================================================================

async def main():
    try:
        seed = input('url : ').strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not seed:
        return
    seed_n = normalize(seed)
    if not seed_n:
        print(f'[!] invalid seed url: {seed}', file=sys.stderr)
        return

    crawler = Crawler()
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _sig(*_):
        crawler.stop_flag = True
        stop_event.set()

    try:
        loop.add_signal_handler(signal.SIGINT, _sig)
        loop.add_signal_handler(signal.SIGTERM, _sig)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *a: (setattr(crawler, 'stop_flag', True), stop_event.set()))

    run_task = asyncio.create_task(crawler.run(seed_n))
    stop_wait = asyncio.create_task(stop_event.wait())
    await asyncio.wait({run_task, stop_wait}, return_when=asyncio.FIRST_COMPLETED)

    if stop_event.is_set():
        for t in asyncio.all_tasks():
            if t is not asyncio.current_task():
                t.cancel()
        try:
            await run_task
        except (asyncio.CancelledError, Exception):
            pass


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass