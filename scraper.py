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

from curl_cffi.requests import AsyncSession

try:
    from selectolax.lexbor import LexborHTMLParser as _HTMLParser
    _HAS_LEXBOR = True
except ImportError:
    _HAS_LEXBOR = False
    from lxml import html as _lxml_html


CONFIG = {
    'initial_concurrency': 400,
    'min_concurrency': 120,
    'max_concurrency': 2000,
    'session_pool_size': 48,
    'rotate_min': 150,
    'rotate_max': 350,
    'request_timeout': 12,
    'max_html_bytes': 1_200_000,
    'max_redirects': 5,
    'queue_high_water': 500_000,
    'stats_interval': 2.0,
    'idle_sleep': 0.001,
    'idle_deep_sleep': 1.0,
    'output_file': 'output.json',
    'bloom_expected': 150_000_000,
    'bloom_error': 0.001,
    'parser_workers': max(8, (os.cpu_count() or 4) * 2),
    'batch_pop': 8,
    'batch_pop_small': 4,
    'per_host_limit': 6,
}

OUTPUT_FILE = Path(CONFIG['output_file'])
PARSER_POOL = ThreadPoolExecutor(max_workers=CONFIG['parser_workers'])


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
        h2 = hash(b[:64] + b'\x9e' + b[-64:]) if len(b) > 128 else hash(b[::-1] + b'\x9e')
        if h2 == 0:
            h2 = 0x9E3779B97F4A7C15
        return h1, h2

    def add(self, item):
        h1, h2 = self._h(item.encode('utf-8', 'ignore'))
        bits = self.bits
        mask = self.mask
        n = self.num_hashes
        for i in range(n):
            idx = (h1 + i * h2) & mask
            bits[idx >> 3] |= 1 << (idx & 7)

    def __contains__(self, item):
        h1, h2 = self._h(item.encode('utf-8', 'ignore'))
        bits = self.bits
        mask = self.mask
        n = self.num_hashes
        for i in range(n):
            idx = (h1 + i * h2) & mask
            if not (bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True


class DomainState:
    __slots__ = ('delay', 'fails', 'last_hit')
    def __init__(self):
        self.delay = 0.0
        self.fails = 0
        self.last_hit = 0.0


class RateLimitTracker:
    __slots__ = ('domains', '_lock')

    def __init__(self):
        self.domains = {}
        self._lock = asyncio.Lock()

    async def wait(self, host):
        state = self.domains.get(host)
        if state is None or state.delay <= 0:
            return
        gap = state.delay - (time.monotonic() - state.last_hit)
        if gap > 0:
            await asyncio.sleep(gap)

    async def record(self, host, status, retry_after=0.0):
        state = self.domains.get(host)
        if status == 200 and retry_after == 0.0 and (state is None or state.delay <= 0.0):
            if state is not None:
                state.last_hit = time.monotonic()
            return
        async with self._lock:
            state = self.domains.get(host)
            if state is None:
                state = DomainState()
                self.domains[host] = state
            state.last_hit = time.monotonic()
            if retry_after > 0:
                state.delay = max(state.delay, min(retry_after, 300.0))
            if status in (429, 503, 502, 520, 521, 522, 523, 524):
                state.fails += 1
                state.delay = min(180.0, max(0.5, state.delay * 2.0) * random.uniform(0.8, 1.2))
            elif status in (403, 401):
                state.fails += 1
                state.delay = min(90.0, max(0.8, state.delay * 1.6))
            elif status == 200:
                state.fails = 0
                state.delay = max(0.0, state.delay * 0.7 - 0.1)


class AdaptiveGate:
    __slots__ = ('limit', 'min_lim', 'max_lim', 'inflight', '_cond', '_results', '_releases')

    def __init__(self, initial, min_lim, max_lim):
        self.limit = initial
        self.min_lim = min_lim
        self.max_lim = max_lim
        self.inflight = 0
        self._cond = asyncio.Condition()
        self._results = deque(maxlen=128)
        self._releases = 0

    async def acquire(self):
        async with self._cond:
            while self.inflight >= self.limit:
                await self._cond.wait()
            self.inflight += 1

    async def release(self, status):
        async with self._cond:
            self.inflight -= 1
            self._results.append(status)
            self._releases += 1
            if self._releases >= 32:
                self._releases = 0
                self._adjust()
            self._cond.notify(1)

    def _adjust(self):
        n = len(self._results)
        if n < 96:
            return
        fails = sum(1 for s in self._results if s >= 400)
        rate = fails / n
        if rate > 0.20:
            self.limit = max(self.min_lim, int(self.limit * 0.75))
        elif rate < 0.04 and self.limit < self.max_lim:
            self.limit = min(self.max_lim, int(self.limit * 1.12))

    @property
    def current(self):
        return self.limit


_IP_POOL = [
    f'{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}'
    for _ in range(2048)
]

_ACCEPT_LANGS = (
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-US,en;q=0.9,es;q=0.7',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-CA,en;q=0.9,fr-CA;q=0.8',
    'en-US,en;q=0.8,de;q=0.6',
    'en-US,en;q=0.8,nl;q=0.6',
)

_ACCEPTS = (
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
)

_REFERERS = (
    'https://www.google.com/',
    'https://www.google.co.uk/',
    'https://www.google.de/',
    'https://www.google.fr/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.brave.com/',
    'https://www.startpage.com/',
    'https://www.ecosia.org/',
    'https://www.qwant.com/',
    'https://yandex.com/',
)

_SEC_CH_UA = (
    '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
    '"Chromium";v="136", "Not(A:Brand";v="24", "Google Chrome";v="136"',
    '"Google Chrome";v="136", "Chromium";v="136", "Not=A?Brand";v="24"',
    '"Google Chrome";v="136", "Not.A/Brand";v="8", "Chromium";v="136"',
)

_CACHE_CTRL = ('no-cache', 'max-age=0', 'no-store')
_DNT = ('1', '1', '0')
_SEC_FETCH_SITE = ('none', 'same-origin', 'cross-site')
_VIA = ('1.1 google', '1.1 cloudflare', '1.1 akamai')


def _make_ua_bundles():
    bundles = []
    for v, key in (
        ('136', 'chrome136'),
        ('133', 'chrome133a'),
        ('131', 'chrome131'),
        ('124', 'chrome124'),
        ('120', 'chrome120'),
        ('116', 'chrome116'),
    ):
        for plat, sec_plat, sec_ver in (
            ('Windows NT 10.0; Win64; x64', '"Windows"', '"10.0.0"'),
            ('Windows NT 11.0; Win64; x64', '"Windows"', '"11.0.0"'),
            ('Macintosh; Intel Mac OS X 14_7', '"macOS"', '"14.7.0"'),
            ('Macintosh; Intel Mac OS X 15_2', '"macOS"', '"15.2.0"'),
            ('X11; Linux x86_64', '"Linux"', '"6.5.0"'),
        ):
            bundles.append({
                'ua': f'Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36',
                'key': key,
                'sec_plat': sec_plat,
                'sec_plat_ver': sec_ver,
                'full_ver': f'"{v}.0.0.0"',
                'chromium': True,
            })
    for ver, key in (('18.4', 'safari184'), ('17.6', 'safari184'), ('18.2', 'safari184')):
        for plat in (
            'Macintosh; Intel Mac OS X 14_7',
            'Macintosh; Intel Mac OS X 13_6',
            'Macintosh; Intel Mac OS X 15_2',
        ):
            bundles.append({
                'ua': f'Mozilla/5.0 ({plat}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{ver} Safari/605.1.15',
                'key': key,
                'sec_plat': '"macOS"',
                'sec_plat_ver': '"14.7.0"',
                'full_ver': None,
                'chromium': False,
            })
    for ver, key in (('135', 'firefox135'), ('133', 'firefox133'), ('128', 'firefox128')):
        for plat, sec_plat in (
            ('Windows NT 10.0; Win64; x64', '"Windows"'),
            ('Macintosh; Intel Mac OS X 14.7', '"macOS"'),
            ('X11; Linux x86_64', '"Linux"'),
        ):
            bundles.append({
                'ua': f'Mozilla/5.0 ({plat}; rv:{ver}.0) Gecko/20100101 Firefox/{ver}.0',
                'key': key,
                'sec_plat': sec_plat,
                'sec_plat_ver': '"10.0.0"',
                'full_ver': None,
                'chromium': False,
            })
    return bundles


_UA_BUNDLES = _make_ua_bundles()
_IMPERSONATIONS = tuple({b['key'] for b in _UA_BUNDLES})


def _ua_for_key(key):
    for b in _UA_BUNDLES:
        if b['key'] == key:
            return b
    return _UA_BUNDLES[0]


class SpoofEngine:
    __slots__ = ()

    def build(self, bundle, referer):
        o = random.choice
        ip = _IP_POOL
        h = {
            'User-Agent': bundle['ua'],
            'Accept': o(_ACCEPTS),
            'Accept-Language': o(_ACCEPT_LANGS),
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Charset': 'utf-8, iso-8859-1;q=0.5, *;q=0.1',
            'Cache-Control': o(_CACHE_CTRL),
            'Pragma': 'no-cache',
            'DNT': o(_DNT),
            'Upgrade-Insecure-Requests': '1',
            'Connection': 'keep-alive',
            'Priority': 'u=0, i',
            'Referer': referer or o(_REFERERS),
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': o(_SEC_FETCH_SITE),
            'Sec-Fetch-User': '?1',
            'X-Forwarded-For': f'{o(ip)},{o(ip)}',
            'X-Real-IP': o(ip),
            'Forwarded': f'for={o(ip)};proto=https',
            'CF-Connecting-IP': o(ip),
            'True-Client-IP': o(ip),
            'X-Client-IP': o(ip),
            'X-Originating-IP': f'[{o(ip)}]',
            'X-Remote-IP': o(ip),
            'X-Remote-Addr': o(ip),
            'X-ProxyUser-Ip': o(ip),
            'Via': o(_VIA),
        }
        if bundle['chromium']:
            h['Sec-CH-UA'] = o(_SEC_CH_UA)
            h['Sec-CH-UA-Mobile'] = '?0'
            h['Sec-CH-UA-Platform'] = bundle['sec_plat']
            h['Sec-CH-UA-Platform-Version'] = bundle['sec_plat_ver']
            h['Sec-CH-UA-Arch'] = '"x86"'
            h['Sec-CH-UA-Bitness'] = '"64"'
            h['Sec-CH-UA-Full-Version'] = bundle['full_ver']
            h['Sec-CH-UA-Model'] = '""'
            h['Sec-CH-UA-WoW64'] = '?0'
        return h


class SessionPool:
    __slots__ = ('size', 'sessions', 'bundles', 'hits', 'thresholds', 'locks')

    def __init__(self, size):
        self.size = size
        self.sessions = [None] * size
        self.bundles = [None] * size
        self.hits = [0] * size
        self.thresholds = [0] * size
        self.locks = [asyncio.Lock() for _ in range(size)]

    async def start(self):
        for i in range(self.size):
            b = random.choice(_UA_BUNDLES)
            self.bundles[i] = b
            self.sessions[i] = self._make(b['key'])
            self.thresholds[i] = random.randint(CONFIG['rotate_min'], CONFIG['rotate_max'])

    @staticmethod
    def _make(key):
        try:
            return AsyncSession(impersonate=key, timeout=CONFIG['request_timeout'])
        except Exception:
            return AsyncSession(impersonate='chrome136', timeout=CONFIG['request_timeout'])

    async def stop(self):
        await asyncio.gather(
            *(s.close() for s in self.sessions if s is not None),
            return_exceptions=True,
        )

    def pick(self):
        return random.getrandbits(6) % self.size

    def get(self, idx):
        return self.sessions[idx]

    def bundle_of(self, idx):
        return self.bundles[idx]

    def bump(self, idx):
        self.hits[idx] += 1
        return self.hits[idx]

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
            b = random.choice(_UA_BUNDLES)
            self.bundles[idx] = b
            self.sessions[idx] = self._make(b['key'])
            self.hits[idx] = 0
            self.thresholds[idx] = random.randint(CONFIG['rotate_min'], CONFIG['rotate_max'])


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
    r'pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf|'
    r'zip|tar|gz|tgz|bz2|xz|rar|7z|lz|lzma|zst|'
    r'exe|dmg|msi|apk|deb|rpm|iso|img|bin|jar|class|'
    r'xml|rss|atom|json|jsonl|ndjson|csv|tsv|yaml|yml|toml|ini|conf|cfg|'
    r'psd|ai|eps|sketch|fig|xd|'
    r'torrent|magnet|wasm)(\?|#|$)',
    re.IGNORECASE,
)

_SKIP_PATH_RE = re.compile(
    r'/(wp-admin|wp-login\.php|wp-json|xmlrpc\.php|'
    r'login|logout|signin|sign-in|signup|sign-up|register|'
    r'cart|checkout|basket|order|payment|'
    r'admin|dashboard|account|profile|settings|'
    r'cdn-cgi|wp-content/uploads|assets?|static|media|'
    r'search|tag/|category/|author/)(/|$|\?)',
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
    if _SKIP_EXT.search(path):
        return None
    if _SKIP_PATH_RE.search(path):
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


_KILL_TAGS = (
    'script', 'style', 'code', 'pre', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
    'audio', 'video', 'source', 'track', 'dialog', 'menu', 'menuitem',
    'nav', 'footer', 'header', 'aside',
)

_KILL_SELECTOR = ','.join(_KILL_TAGS)

_MAIN_SELECTORS = (
    'article',
    'main',
    '[role="main"]',
    '#content',
    '.post-content',
    '.entry-content',
    '.article-content',
    '.article-body',
    '.story-body',
    '.content-body',
)

_MAIN_XPATHS = (
    '//article',
    '//main',
    '//*[@role="main"]',
    '//*[@id="content"]',
    '//*[contains(@class, "post-content")]',
    '//*[contains(@class, "entry-content")]',
    '//*[contains(@class, "article-content")]',
    '//*[contains(@class, "article-body")]',
    '//*[contains(@class, "story-body")]',
    '//*[contains(@class, "content-body")]',
)

_CLEAN_RE = re.compile(r'[^\S\n]+|\n{2,}|[^\x20-\x7E\n\t]')


def _clean_repl(m):
    s = m.group(0)
    c = s[0]
    if c == '\n':
        return '\n'
    if c <= ' ':
        return ' '
    return ''


_META_REFRESH_RE = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.IGNORECASE)


def _parse_selectolax(raw, base_url):
    try:
        tree = _HTMLParser(raw)
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

    links = []
    seen = set()
    add = seen.add
    for a in tree.css('a[href]'):
        href = a.attributes.get('href')
        if not href:
            continue
        n = normalize(href, base_url)
        if n and n not in seen:
            add(n)
            links.append(n)
        if len(links) > 5000:
            break

    if not links:
        for el in tree.css('[data-href],[data-url],[data-link]'):
            for attr in ('data-href', 'data-url', 'data-link'):
                val = el.attributes.get(attr)
                if val:
                    n = normalize(val, base_url)
                    if n and n not in seen:
                        add(n)
                        links.append(n)
                    break

    for m in tree.css('meta[http-equiv="refresh"]'):
        content = m.attributes.get('content') or ''
        mr = _META_REFRESH_RE.search(content)
        if mr:
            n = normalize(mr.group(1), base_url)
            if n and n not in seen:
                add(n)
                links.append(n)

    for lk in tree.css('link[rel="next"],link[rel="prev"],link[rel="canonical"]'):
        href = lk.attributes.get('href')
        if href:
            n = normalize(href, base_url)
            if n and n not in seen:
                add(n)
                links.append(n)

    content = None
    for sel in _MAIN_SELECTORS:
        node = tree.css_first(sel)
        if node:
            content = node
            break
    source = content if content is not None else tree

    for tag in source.css(_KILL_SELECTOR):
        tag.decompose()

    text = source.text(separator='\n') or ''
    text = _CLEAN_RE.sub(_clean_repl, text).strip()

    if not text or len(text) < 50:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)


def _parse_lxml(raw, base_url):
    try:
        doc = _lxml_html.document_fromstring(raw, base_url=base_url)
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

    links = []
    seen = set()
    add = seen.add
    for a in doc.iter('a'):
        href = a.get('href')
        if not href:
            continue
        n = normalize(href, base_url)
        if n and n not in seen:
            add(n)
            links.append(n)
        if len(links) > 5000:
            break

    if not links:
        for el in doc.iter():
            for attr in ('data-href', 'data-url', 'data-link'):
                val = el.get(attr)
                if val:
                    n = normalize(val, base_url)
                    if n and n not in seen:
                        add(n)
                        links.append(n)
                    break

    for m in doc.iter('meta'):
        if (m.get('http-equiv') or '').lower() == 'refresh':
            content = m.get('content') or ''
            mr = _META_REFRESH_RE.search(content)
            if mr:
                n = normalize(mr.group(1), base_url)
                if n and n not in seen:
                    add(n)
                    links.append(n)

    for lk in doc.iter('link'):
        rel = (lk.get('rel') or '').lower()
        if rel in ('next', 'prev', 'canonical'):
            href = lk.get('href')
            if href:
                n = normalize(href, base_url)
                if n and n not in seen:
                    add(n)
                    links.append(n)

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

    text = source.text_content()
    text = _CLEAN_RE.sub(_clean_repl, text).strip()

    if not text or len(text) < 50:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)


def _parse_and_extract(raw, base_url):
    if _HAS_LEXBOR:
        return _parse_selectolax(raw, base_url)
    return _parse_lxml(raw, base_url)


def load_existing_urls():
    seen = set()
    if not OUTPUT_FILE.exists():
        return seen
    try:
        with OUTPUT_FILE.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                u = obj.get('url')
                if isinstance(u, str):
                    seen.add(u)
    except Exception:
        pass
    return seen


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


class Crawler:
    __slots__ = (
        'bloom', 'queue', 'host_inflight', 'pool', 'spoof', 'gate',
        'rate_limiter', 'written', 'fetched', 'dropped', 'zero_link_pages',
        'errors', 'stop_flag', 'out_fd', 'stats_task', 'start_time',
        'last_report_time', 'last_report_written', 'seed',
    )

    def __init__(self):
        self.bloom = BloomFilter(CONFIG['bloom_expected'], CONFIG['bloom_error'])
        self.queue = deque()
        self.host_inflight = {}
        self.pool = None
        self.spoof = SpoofEngine()
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

    async def run(self, seed):
        self.seed = seed
        for u in load_existing_urls():
            self.bloom.add(u)
        self.bloom.add(seed)
        self.queue.append((seed, '', 0))

        self.pool = SessionPool(CONFIG['session_pool_size'])
        await self.pool.start()

        self.out_fd = os.open(
            str(OUTPUT_FILE),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT,
            0o644,
        )

        engine = 'lexbor' if _HAS_LEXBOR else 'lxml'
        print(f'[Nexus] seed:     {seed}', file=sys.stderr)
        print(f'[Nexus] output:   {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:   {engine}  parsers={CONFIG["parser_workers"]}', file=sys.stderr)
        print(f'[Nexus] adaptive: {CONFIG["min_concurrency"]}-{CONFIG["max_concurrency"]} (start {CONFIG["initial_concurrency"]})', file=sys.stderr)
        print(f'[Nexus] sessions: {CONFIG["session_pool_size"]}  rotate={CONFIG["rotate_min"]}-{CONFIG["rotate_max"]}', file=sys.stderr)
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
                    os.close(self.out_fd)
            except Exception:
                pass
            await self.pool.stop()
            PARSER_POOL.shutdown(wait=False)
            self._final_report()

    async def _stats_loop(self):
        interval = CONFIG['stats_interval']
        next_t = time.monotonic() + interval
        while not self.stop_flag:
            now = time.monotonic()
            delay = next_t - now
            if delay > 0:
                await asyncio.sleep(delay)
            next_t += interval
            t = time.time()
            dt = t - self.last_report_time
            dw = self.written - self.last_report_written
            rate = dw / dt if dt > 0 else 0.0
            avg = self.written / (t - self.start_time) if t > self.start_time else 0.0
            print(
                f'[stats] rate={rate:7.1f}/s  avg={avg:7.1f}/s  '
                f'written={self.written}  fetched={self.fetched}  '
                f'dropped={self.dropped}  errors={self.errors}  '
                f'queue={len(self.queue)}  hosts={len(self.host_inflight)}  '
                f'conc={self.gate.current}  zerolink={self.zero_link_pages}',
                file=sys.stderr,
            )
            self.last_report_time = t
            self.last_report_written = self.written

    def _final_report(self):
        elapsed = time.time() - self.start_time
        avg = self.written / elapsed if elapsed > 0 else 0
        print(
            f'\n[Nexus] stopped. written={self.written}  fetched={self.fetched}  '
            f'dropped={self.dropped}  errors={self.errors}  '
            f'zerolink={self.zero_link_pages}  '
            f'elapsed={elapsed:.1f}s  avg={avg:.1f}/s',
            file=sys.stderr,
        )

    async def _worker(self, wid):
        idle_rounds = 0
        while not self.stop_flag:
            qlen = len(self.queue)
            if qlen == 0:
                idle_rounds += 1
                if not self.host_inflight:
                    await asyncio.sleep(CONFIG['idle_deep_sleep'] if idle_rounds > 100 else CONFIG['idle_sleep'])
                else:
                    await asyncio.sleep(CONFIG['idle_sleep'])
                continue
            idle_rounds = 0

            batch_size = CONFIG['batch_pop'] if qlen >= 64 else CONFIG['batch_pop_small']
            batch = []
            popleft = self.queue.popleft
            try:
                for _ in range(batch_size):
                    batch.append(popleft())
            except IndexError:
                pass

            tasks = []
            for url, referer, depth in batch:
                host = host_of(url)
                if not host:
                    continue
                inflight = self.host_inflight.get(host, 0)
                if inflight >= CONFIG['per_host_limit']:
                    self.queue.append((url, referer, depth))
                    continue
                self.host_inflight[host] = inflight + 1
                tasks.append((url, referer, depth, host))

            if not tasks:
                await asyncio.sleep(0.005)
                continue

            results = await asyncio.gather(
                *(self._process(u, r, d, h) for u, r, d, h in tasks),
                return_exceptions=True,
            )

            for (url, referer, depth, host), res in zip(tasks, results):
                left = self.host_inflight.get(host, 1) - 1
                if left <= 0:
                    self.host_inflight.pop(host, None)
                else:
                    self.host_inflight[host] = left
                if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                    self.errors += 1
                    if self.errors <= 20:
                        print(f'[w{wid}] {url[:90]}: {type(res).__name__}: {res}', file=sys.stderr)

    async def _process(self, url, referer, depth, host):
        self.fetched += 1
        await self.rate_limiter.wait(host)
        await self.gate.acquire()
        status = 0
        retry_after = 0.0
        try:
            idx = self.pool.pick()
            sess = self.pool.get(idx)
            if sess is None:
                self.pool.force_rotate(idx)
                asyncio.create_task(self.pool.rotate(idx))
                self.dropped += 1
                return
            bundle = self.pool.bundle_of(idx)
            headers = self.spoof.build(bundle, referer)

            try:
                resp = await sess.get(
                    url,
                    headers=headers,
                    timeout=CONFIG['request_timeout'],
                    allow_redirects=True,
                    max_redirects=CONFIG['max_redirects'],
                )
                status = resp.status_code
            except Exception:
                status = 0
                self.pool.bump(idx)
                if self.pool.needs_rotation(idx):
                    asyncio.create_task(self.pool.rotate(idx))
                self.dropped += 1
                return

            self.pool.bump(idx)
            if self.pool.needs_rotation(idx):
                asyncio.create_task(self.pool.rotate(idx))

            if status != 200:
                if status in (403, 429, 502, 503, 520, 521, 522, 523, 524):
                    self.pool.force_rotate(idx)
                    asyncio.create_task(self.pool.rotate(idx))
                if status in (429, 503):
                    retry_after = _parse_retry_after(resp)
                self.dropped += 1
                return

            ctype = (resp.headers.get('content-type') or '').lower()
            if 'text/html' not in ctype and 'application/xhtml' not in ctype:
                self.dropped += 1
                return

            try:
                raw = resp.text
            except Exception:
                try:
                    raw = resp.content.decode('utf-8', 'ignore')
                except Exception:
                    self.dropped += 1
                    return

            if not raw:
                self.dropped += 1
                return

            if len(raw) > CONFIG['max_html_bytes']:
                raw = raw[:CONFIG['max_html_bytes']]

            loop = asyncio.get_running_loop()
            try:
                cleaned, links = await loop.run_in_executor(PARSER_POOL, _parse_and_extract, raw, url)
            except Exception:
                self.dropped += 1
                return

            if cleaned is not None:
                title, text = cleaned
                record = {'url': url, 'title': title, 'text': text}
                line = json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n'
                os.write(self.out_fd, line)
                self.written += 1

            if not links:
                self.zero_link_pages += 1
            else:
                misses = []
                bl = self.bloom
                for link in links:
                    if link not in bl:
                        bl.add(link)
                        misses.append(link)
                if misses:
                    if len(self.queue) < CONFIG['queue_high_water']:
                        self.queue.extend((link, url, depth + 1) for link in misses)
        finally:
            await self.gate.release(status or 599)
            await self.rate_limiter.record(host, status, retry_after)


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