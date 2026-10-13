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
    'max_active_hosts': 64,
    'workers_per_host': 32,
    'max_concurrency': 4000,
    'min_concurrency': 128,
    'session_pool_size': 64,
    'rotate_min': 400,
    'rotate_max': 800,
    'request_timeout': 12,
    'max_html_bytes': 2_000_000,
    'max_binary_bytes': 10_000_000,
    'max_text_chars': 200_000,
    'max_redirects': 5,
    'queue_high_water': 2_000_000,
    'max_links_per_page': 20_000,
    'stats_interval': 3.0,
    'output_file': 'output.json',
    'bloom_expected': 50_000_000,
    'bloom_error': 0.001,
    'parser_workers': max(8, (os.cpu_count() or 4) * 2),
    'ocr_workers': 4,
    'ocr_concurrency': 8,
    'ocr_enabled': True,
    'ocr_min_text_chars': 100,
    'ocr_max_chars': 400_000,
    'ocr_pdf_max_pages': 10,
    'host_idle_timeout': 15.0,
    'dispatch_interval': 0.25,
    'host_403_blacklist_threshold': 5,
    'impersonate_retry_limit': 2,
    'drop_log_limit': 15,
    'min_text_chars': 20,
}

OUTPUT_FILE = Path(CONFIG['output_file'])
PARSER_POOL = ThreadPoolExecutor(max_workers=CONFIG['parser_workers'])
OCR_POOL = ThreadPoolExecutor(max_workers=CONFIG['ocr_workers'])


# ===========================================================================
# Lazy loaders
# ===========================================================================

_curl_AsyncSession = None
_parser_cls = None
_parser_mode = None
_pdf_module = None
_pdf_mode = None
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
    """Prefer PyMuPDF (10-30x faster than pypdf, renders pages for OCR natively)."""
    global _pdf_module, _pdf_mode
    if _pdf_mode is not None:
        return _pdf_mode
    for modname in ('pymupdf', 'fitz'):
        try:
            mod = __import__(modname)
            _pdf_module = mod
            _pdf_mode = 'pymupdf'
            return _pdf_mode
        except ImportError:
            continue
    try:
        import pypdf as _pypdf
        _pdf_module = _pypdf
        _pdf_mode = 'pypdf'
        return _pdf_mode
    except ImportError:
        pass
    try:
        import PyPDF2 as _pypdf2
        _pdf_module = _pypdf2
        _pdf_mode = 'pypdf'
        return _pdf_mode
    except ImportError:
        pass
    _pdf_mode = 'none'
    return _pdf_mode


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
# Rate limiting — delay + blacklist only (concurrency is worker-count bound)
# ===========================================================================

class DomainState:
    __slots__ = ('delay', 'fails', 'last_hit', 'consecutive_403', 'blacklisted')

    def __init__(self):
        self.delay = 0.0
        self.fails = 0
        self.last_hit = 0.0
        self.consecutive_403 = 0
        self.blacklisted = False


class RateLimitTracker:
    __slots__ = ('domains', '_lock')

    def __init__(self):
        self.domains = {}
        self._lock = asyncio.Lock()

    def is_blacklisted(self, host):
        st = self.domains.get(host)
        return st is not None and st.blacklisted

    async def wait(self, host):
        st = self.domains.get(host)
        if st is None or st.delay <= 0:
            return
        gap = st.delay - (time.monotonic() - st.last_hit)
        if gap > 0:
            await asyncio.sleep(gap)

    async def record(self, host, status, retry_after=0.0):
        st = self.domains.get(host)
        if status == 200 and retry_after == 0.0 and (st is None or st.delay <= 0.0):
            if st is None:
                async with self._lock:
                    st = self.domains.get(host)
                    if st is None:
                        st = DomainState()
                        self.domains[host] = st
            st.last_hit = time.monotonic()
            st.consecutive_403 = 0
            return
        async with self._lock:
            st = self.domains.get(host)
            if st is None:
                st = DomainState()
                self.domains[host] = st
            st.last_hit = time.monotonic()
            if retry_after > 0:
                st.delay = max(st.delay, min(retry_after, 300.0))
            if status in (429, 503, 502, 520, 521, 522, 523, 524):
                st.fails += 1
                st.delay = min(120.0, max(0.3, st.delay * 2.0) * random.uniform(0.8, 1.2))
            elif status == 403:
                st.fails += 1
                st.consecutive_403 += 1
                if st.consecutive_403 >= CONFIG['host_403_blacklist_threshold']:
                    st.blacklisted = True
            elif status == 401:
                st.fails += 1
                st.delay = min(60.0, max(0.5, st.delay * 1.6))
            elif status == 200:
                st.fails = 0
                st.delay = max(0.0, st.delay * 0.7 - 0.1)


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
# Headers
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
    'link[href], source[src], source[srcset], img[srcset], '
    'meta[http-equiv="refresh"], meta[property="og:url"], '
    'meta[name="twitter:url"], [data-href], [data-url], [data-link], '
    '[data-src], [data-lazy-src], [data-original]'
)

_SRCSET_SPLIT_RE = re.compile(r'\s*,\s*')

# Absolute-URL regex for scanning <script> payloads (Next.js / Nuxt / RSC / etc.)
_SCRIPT_BLOCK_RE = re.compile(rb'<script\b[^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL)
_ABS_URL_RE = re.compile(
    rb'https?://[a-zA-Z0-9][a-zA-Z0-9\-._]{1,253}\.[a-zA-Z]{2,}'
    rb'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{0,1000}',
    re.IGNORECASE,
)

# JSON-LD url-bearing keys
_JSONLD_RE = re.compile(
    rb'<script[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
_JSONLD_KEYS = frozenset({'url', '@id', 'sameAs', 'href', 'link', 'permalink', 'canonicalUrl'})


def _finalize_text(text):
    text = _WS_RE.sub(' ', text)
    text = _NL_RE.sub('\n\n', text)
    text = _JUNK_RE.sub('', text)
    return text.strip()


def _maybe_srcset(val):
    """Return first URL from a srcset or the value itself."""
    if not val:
        return None
    if ',' in val:
        best = None
        best_w = -1.0
        for part in _SRCSET_SPLIT_RE.split(val):
            part = part.strip()
            if not part:
                continue
            bits = part.split()
            u = bits[0]
            w = 1.0
            if len(bits) > 1:
                try:
                    w = float(bits[1].rstrip('wx'))
                except Exception:
                    w = 1.0
            if w > best_w:
                best_w = w
                best = u
        return best
    return val


def _scan_scripts_for_urls(raw_bytes, base_url, limit):
    """Bulk-extract absolute URLs from inside <script> blocks."""
    if b'<script' not in raw_bytes:
        return ()
    out = []
    seen = set()
    for m in _SCRIPT_BLOCK_RE.finditer(raw_bytes):
        block = m.group(1)
        if not block:
            continue
        for um in _ABS_URL_RE.finditer(block):
            try:
                cand = um.group(0).decode('ascii', 'ignore')
            except Exception:
                continue
            n = normalize(cand, base_url)
            if n and n not in seen:
                seen.add(n)
                out.append(n)
                if len(out) >= limit:
                    return tuple(out)
    return tuple(out)


def _scan_jsonld_for_urls(raw_bytes, base_url, limit):
    if b'ld+json' not in raw_bytes:
        return ()
    out = []
    seen = set()
    for m in _JSONLD_RE.finditer(raw_bytes):
        try:
            data = json.loads(m.group(1))
        except Exception:
            continue
        stack = [data]
        depth = 0
        while stack and depth < 200_000:
            depth += 1
            item = stack.pop()
            if isinstance(item, dict):
                for k, v in item.items():
                    if isinstance(v, str) and k in _JSONLD_KEYS:
                        if v.startswith(('http://', 'https://', '/')):
                            n = normalize(v, base_url)
                            if n and n not in seen:
                                seen.add(n)
                                out.append(n)
                                if len(out) >= limit:
                                    return tuple(out)
                    elif isinstance(v, (dict, list)):
                        stack.append(v)
            elif isinstance(item, list):
                stack.extend(item[:1000])
    return tuple(out)


def _extract_links_selectolax(tree, base_url, limit):
    links = []
    seen = set()
    for node in tree.css(_LINK_SELECTOR):
        tag = node.tag
        attrs = node.attributes
        candidates = []
        if tag in ('a', 'area'):
            candidates.append(attrs.get('href'))
        elif tag in ('iframe', 'frame'):
            candidates.append(attrs.get('src'))
        elif tag == 'link':
            candidates.append(attrs.get('href'))
        elif tag == 'source':
            candidates.append(attrs.get('src'))
            ss = attrs.get('srcset')
            if ss:
                candidates.append(_maybe_srcset(ss))
        elif tag == 'img':
            ss = attrs.get('srcset')
            if ss:
                candidates.append(_maybe_srcset(ss))
        elif tag == 'meta':
            he = (attrs.get('http-equiv') or '').lower()
            prop = (attrs.get('property') or attrs.get('name') or '').lower()
            content = attrs.get('content') or ''
            if he == 'refresh':
                mr = _META_REFRESH_RE.search(content)
                if mr:
                    candidates.append(mr.group(1))
            elif prop in ('og:url', 'twitter:url'):
                candidates.append(content)
        for attr in ('data-href', 'data-url', 'data-link',
                     'data-src', 'data-lazy-src', 'data-original'):
            v = attrs.get(attr)
            if v:
                candidates.append(v)
        for val in candidates:
            if not val:
                continue
            n = normalize(val, base_url)
            if n and n not in seen:
                seen.add(n)
                links.append(n)
                if len(links) >= limit:
                    return tuple(links)
    return tuple(links)


def _extract_links_lxml(doc, base_url, limit):
    links = []
    seen = set()
    for node in doc.iter():
        tag = node.tag
        if tag is None:
            continue
        candidates = []
        if tag in ('a', 'area'):
            candidates.append(node.get('href'))
        elif tag in ('iframe', 'frame'):
            candidates.append(node.get('src'))
        elif tag == 'link':
            candidates.append(node.get('href'))
        elif tag == 'source':
            candidates.append(node.get('src'))
            ss = node.get('srcset')
            if ss:
                candidates.append(_maybe_srcset(ss))
        elif tag == 'img':
            ss = node.get('srcset')
            if ss:
                candidates.append(_maybe_srcset(ss))
        elif tag == 'meta':
            he = (node.get('http-equiv') or '').lower()
            prop = (node.get('property') or node.get('name') or '').lower()
            content = node.get('content') or ''
            if he == 'refresh':
                mr = _META_REFRESH_RE.search(content)
                if mr:
                    candidates.append(mr.group(1))
            elif prop in ('og:url', 'twitter:url'):
                candidates.append(content)
        for attr in ('data-href', 'data-url', 'data-link',
                     'data-src', 'data-lazy-src', 'data-original'):
            v = node.get(attr)
            if v:
                candidates.append(v)
        for val in candidates:
            if not val:
                continue
            n = normalize(val, base_url)
            if n and n not in seen:
                seen.add(n)
                links.append(n)
                if len(links) >= limit:
                    return tuple(links)
    return tuple(links)


def _meta_text_fallback_selectolax(tree):
    parts = []
    for sel in ('meta[property="og:description"]',
                'meta[name="twitter:description"]',
                'meta[name="description"]'):
        node = tree.css_first(sel)
        if node:
            v = (node.attributes.get('content') or '').strip()
            if v and v not in parts:
                parts.append(v)
    return ' '.join(parts)


def _meta_text_fallback_lxml(doc):
    parts = []
    for xp in ('//meta[@property="og:description"]/@content',
               '//meta[@name="twitter:description"]/@content',
               '//meta[@name="description"]/@content'):
        r = doc.xpath(xp)
        if r:
            v = (r[0] or '').strip()
            if v and v not in parts:
                parts.append(v)
    return ' '.join(parts)


def _parse_selectolax(raw, raw_bytes, base_url, cfg):
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

    limit = cfg['max_links_per_page']
    links = list(_extract_links_selectolax(tree, base_url, limit))
    if len(links) < limit:
        seen = set(links)
        for extra in _scan_jsonld_for_urls(raw_bytes, base_url, limit - len(links)):
            if extra not in seen:
                seen.add(extra)
                links.append(extra)
    if len(links) < limit:
        seen = set(links)
        for extra in _scan_scripts_for_urls(raw_bytes, base_url, limit - len(links)):
            if extra not in seen:
                seen.add(extra)
                links.append(extra)

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

    if len(text) < cfg['min_text_chars']:
        meta = _meta_text_fallback_selectolax(tree)
        if len(meta) > len(text):
            text = meta

    if not text and not title:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)


def _parse_lxml(raw, raw_bytes, base_url, cfg):
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

    limit = cfg['max_links_per_page']
    links = list(_extract_links_lxml(doc, base_url, limit))
    if len(links) < limit:
        seen = set(links)
        for extra in _scan_jsonld_for_urls(raw_bytes, base_url, limit - len(links)):
            if extra not in seen:
                seen.add(extra)
                links.append(extra)
    if len(links) < limit:
        seen = set(links)
        for extra in _scan_scripts_for_urls(raw_bytes, base_url, limit - len(links)):
            if extra not in seen:
                seen.add(extra)
                links.append(extra)

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
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)


def _parse_and_extract(raw, base_url):
    cfg = CONFIG
    raw_bytes = raw.encode('utf-8', 'ignore') if isinstance(raw, str) else raw
    if _parser_mode == 'lexbor':
        return _parse_selectolax(raw, raw_bytes, base_url, cfg)
    return _parse_lxml(raw, raw_bytes, base_url, cfg)


# ===========================================================================
# Binary extraction — PyMuPDF first, pypdf fallback; native OCR rendering
# ===========================================================================

def _pdf_extract_text(content_bytes):
    mode = _load_pdf()
    if mode == 'none':
        return None
    if mode == 'pymupdf':
        try:
            doc = _pdf_module.open(stream=content_bytes, filetype='pdf')
            try:
                title = ''
                try:
                    meta = doc.metadata or {}
                    title = meta.get('title', '') or ''
                except Exception:
                    pass
                parts = []
                n = min(len(doc), 500)
                for i in range(n):
                    try:
                        t = doc[i].get_text()
                        if t:
                            parts.append(t)
                    except Exception:
                        continue
                return title, '\n\n'.join(parts)
            finally:
                try:
                    doc.close()
                except Exception:
                    pass
        except Exception:
            return None
    # pypdf / PyPDF2
    try:
        from io import BytesIO
        reader = _pdf_module.PdfReader(BytesIO(content_bytes))
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
    """Render PDF pages directly with PyMuPDF — no pdf2image/poppler needed."""
    if _load_pdf() != 'pymupdf' or not _load_ocr():
        return None
    try:
        from io import BytesIO
        doc = _pdf_module.open(stream=content_bytes, filetype='pdf')
        try:
            parts = []
            n = min(len(doc), CONFIG['ocr_pdf_max_pages'])
            for i in range(n):
                try:
                    pix = doc[i].get_pixmap(dpi=200)
                    png = pix.tobytes('png')
                    img = _pil_image.open(BytesIO(png))
                    t = _image_ocr_pil(img)
                    if t:
                        parts.append(t)
                except Exception:
                    continue
            return '\n\n'.join(parts)
        finally:
            try:
                doc.close()
            except Exception:
                pass
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
# Bloom prefill
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
# Challenge + retry-after + sitemap
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
# Crawler — domain-scoped worker groups with dynamic lifecycle
# ===========================================================================

class Crawler:
    __slots__ = (
        'bloom', 'host_queues', 'host_workers', 'host_inflight',
        'host_last_active', 'host_retire', 'active_hosts', 'dispatch_lock',
        'pool', 'gate', 'rate_limiter',
        'written', 'fetched', 'dropped', 'zero_link_pages', 'errors',
        'stop_flag', 'out_fd', 'stats_task', 'dispatcher_task',
        'start_time', 'last_report_time', 'last_report_written',
        'seed', 'seed_host', 'ocr_sem', 'challenges_total',
        'blacklisted_hosts', 'drop_log_count', 'drop_reasons',
        'impersonate_errors',
    )

    def __init__(self):
        self.bloom = BloomFilter(CONFIG['bloom_expected'], CONFIG['bloom_error'])
        # Domain-scoped queues and worker groups
        self.host_queues = {}          # host -> deque[(url, referer, depth)]
        self.host_workers = {}         # host -> list[Task]
        self.host_inflight = {}        # host -> int
        self.host_last_active = {}     # host -> monotonic
        self.host_retire = set()       # hosts marked for retirement
        self.active_hosts = 0
        self.dispatch_lock = asyncio.Lock()

        self.pool = None
        self.gate = AdaptiveGate(
            CONFIG['max_active_hosts'] * CONFIG['workers_per_host'],
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
        self.dispatcher_task = None
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

    # ------------------------------------------------------------------ utils

    def _log_drop(self, reason, url):
        self.dropped += 1
        self.drop_reasons[reason] = self.drop_reasons.get(reason, 0) + 1
        if self.drop_log_count < CONFIG['drop_log_limit']:
            self.drop_log_count += 1
            print(f'[drop:{reason}] {url[:100]}', file=sys.stderr)

    def _enqueue(self, url, referer, depth):
        h = host_of(url)
        if not h:
            return False
        q = self.host_queues.get(h)
        if q is None:
            q = deque()
            self.host_queues[h] = q
        q.append((url, referer, depth))
        return True

    def _enqueue_many(self, links, referer, depth):
        added = 0
        bl = self.bloom
        for link in links:
            if link in bl:
                continue
            bl.add(link)
            if self._enqueue(link, referer, depth):
                added += 1
                if len(self.host_queues) > 500_000:
                    break
        return added

    # ----------------------------------------------------- dispatcher / spawn

    async def _dispatcher(self):
        interval = CONFIG['dispatch_interval']
        while not self.stop_flag:
            async with self.dispatch_lock:
                now = time.monotonic()

                # Mark idle hosts for retirement
                for host in list(self.host_workers.keys()):
                    if host in self.host_retire:
                        continue
                    if self.host_inflight.get(host, 0) > 0:
                        continue
                    if self.host_queues.get(host):
                        continue
                    if now - self.host_last_active.get(host, now) > CONFIG['host_idle_timeout']:
                        self.host_retire.add(host)

                # Cleanup finished worker groups
                for host in list(self.host_retire):
                    workers = self.host_workers.get(host, [])
                    alive = [w for w in workers if not w.done()]
                    if not alive:
                        self.host_workers.pop(host, None)
                        self.host_retire.discard(host)
                        self.active_hosts -= 1
                    else:
                        self.host_workers[host] = alive

                # Spawn worker groups for hosts with pending work
                for host, q in list(self.host_queues.items()):
                    if not q or host in self.host_workers:
                        continue
                    if self.active_hosts >= CONFIG['max_active_hosts']:
                        break
                    self._spawn_host(host)

            await asyncio.sleep(interval)

    def _spawn_host(self, host):
        n = CONFIG['workers_per_host']
        workers = [asyncio.create_task(self._host_worker(host, i)) for i in range(n)]
        self.host_workers[host] = workers
        self.host_last_active[host] = time.monotonic()
        self.active_hosts += 1
        self.host_retire.discard(host)

    async def _host_worker(self, host, wid):
        empty_streak = 0
        while not self.stop_flag and host not in self.host_retire:
            q = self.host_queues.get(host)
            if not q:
                empty_streak += 1
                if empty_streak > 8:
                    return
                await asyncio.sleep(0.5)
                continue
            empty_streak = 0
            try:
                url, referer, depth = q.popleft()
            except IndexError:
                continue

            if self.rate_limiter.is_blacklisted(host):
                self.blacklisted_hosts.add(host)
                continue

            self.host_inflight[host] = self.host_inflight.get(host, 0) + 1
            try:
                await self._process(url, referer, depth, host)
            except Exception as e:
                self.errors += 1
                if self.errors <= 20:
                    print(f'[w{host}:{wid}] {url[:80]}: {type(e).__name__}: {e}', file=sys.stderr)
            finally:
                self.host_inflight[host] = self.host_inflight.get(host, 1) - 1
                self.host_last_active[host] = time.monotonic()

    # -------------------------------------------------------- standalone fetch

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
        pending = deque(sitemap_urls[:CONFIG.get('sitemap_max_count', 50)])
        max_sitemaps = CONFIG.get('sitemap_max_count', 50)
        max_pages = CONFIG.get('sitemap_max_pages', 5000)

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
                        self._enqueue(n, seed_url, 1)
                        pages_added += 1
                        if pages_added >= max_pages:
                            break
        print(f'[sitemaps] {len(seen_sitemaps)} sitemaps, {pages_added} pages queued', file=sys.stderr)

    # ------------------------------------------------------------- main loop

    async def run(self, seed):
        self.seed = seed
        self.seed_host = host_of(seed)

        mode = _load_parser()
        if mode == 'none':
            print('[!] no HTML parser (pip install selectolax)', file=sys.stderr)
            return

        keys = _available_impersonations()
        if not keys:
            print('[!] no curl_cffi impersonation keys', file=sys.stderr)
            return

        _prefill_bloom_from_output(self.bloom)
        self.bloom.add(seed)
        self._enqueue(seed, '', 0)

        self.ocr_sem = asyncio.Semaphore(CONFIG['ocr_concurrency'])
        self.pool = SessionPool(CONFIG['session_pool_size'], keys)
        await self.pool.start()

        self.out_fd = os.open(
            str(OUTPUT_FILE),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o644,
        )

        ocr_ready = bool(_load_ocr() and CONFIG['ocr_enabled'])
        pdf_mode = _load_pdf()
        engine = 'lexbor' if mode == 'lexbor' else 'lxml'

        print(f'[Nexus] seed:        {seed}', file=sys.stderr)
        print(f'[Nexus] output:      {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:      {engine}  parsers={CONFIG["parser_workers"]}', file=sys.stderr)
        print(f'[Nexus] host groups: max={CONFIG["max_active_hosts"]}  workers/host={CONFIG["workers_per_host"]}  global_cap={CONFIG["max_concurrency"]}', file=sys.stderr)
        print(f'[Nexus] sessions:    {CONFIG["session_pool_size"]}  impersonate={len(keys)}', file=sys.stderr)
        print(f'[Nexus] pdf:         {pdf_mode}   ocr: {"on" if ocr_ready else "off"}', file=sys.stderr)
        print(f'[Nexus] max links:   {CONFIG["max_links_per_page"]}/page', file=sys.stderr)

        print('[Nexus] seeding sitemaps...', file=sys.stderr)
        try:
            await self._seed_sitemaps(seed)
        except Exception as e:
            print(f'[sitemaps] failed: {e}', file=sys.stderr)

        print('[Nexus] CTRL+C to stop.\n', file=sys.stderr)

        self.stats_task = asyncio.create_task(self._stats_loop())
        self.dispatcher_task = asyncio.create_task(self._dispatcher())
        try:
            await self.dispatcher_task
        except asyncio.CancelledError:
            pass
        finally:
            self.stop_flag = True
            self.stats_task.cancel()
            self.dispatcher_task.cancel()
            for w in self.stats_task, self.dispatcher_task:
                try:
                    await w
                except Exception:
                    pass
            # Cancel remaining host workers
            for workers in list(self.host_workers.values()):
                for w in workers:
                    w.cancel()
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
            total_q = sum(len(q) for q in self.host_queues.values())
            print(
                f'[s] {rate:6.1f}/s avg {avg:6.1f}/s  '
                f'w={self.written} f={self.fetched} d={self.dropped}({err_pct:.0f}%)  '
                f'q={total_q} hosts={self.active_hosts}/{len(self.host_queues)}  '
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
            f'hosts_seen={len(self.host_queues)}  '
            f'elapsed={elapsed:.1f}s  avg={avg:.1f}/s',
            file=sys.stderr,
        )
        if self.blacklisted_hosts:
            print(f'[blacklisted] {sorted(self.blacklisted_hosts)[:20]}', file=sys.stderr)
        if self.drop_reasons:
            top = sorted(self.drop_reasons.items(), key=lambda x: -x[1])[:10]
            print('[drops] ' + '  '.join(f'{r}={c}' for r, c in top), file=sys.stderr)

    # ---------------------------------------------------------------- process

    async def _process(self, url, referer, depth, host):
        self.fetched += 1
        status = 0
        retry_after = 0.0
        await self.rate_limiter.wait(host)
        await self.gate.acquire()
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
                self._enqueue_many(links, url, depth + 1)
        finally:
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