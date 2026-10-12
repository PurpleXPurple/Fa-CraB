#!/usr/bin/env python3
import asyncio
import json
import re
import sys
import time
import random
import math
import signal
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html
from lxml.html.clean import Cleaner


# ═══════════════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════════════

CONFIG = {
    'concurrency':        300,
    'per_host_limit':     6,
    'session_pool_size':  40,
    'rotate_every_n':     400,
    'request_timeout':    15,
    'connect_timeout':    6,
    'max_html_bytes':     3_000_000,
    'queue_high_water':   800_000,
    'jitter_min':         0.3,
    'jitter_max':         0.9,
    'jitter_scale':       0.04,
    'stats_interval':     2.0,
    'idle_sleep':         0.002,
    'idle_deep_sleep':    1.5,
    'write_flush_every':  64,
    'dns_ttl':            300,
    'max_redirects':      10,
    'accept_zstd':        False,
    'output_file':        'output.json',
    'bloom_expected':     200_000_000,
    'bloom_error':        0.0005,
}

OUTPUT_FILE = Path(CONFIG['output_file'])


# ═══════════════════════════════════════════════════════════════════
# BLOOM
# ═══════════════════════════════════════════════════════════════════

class BloomFilter:
    __slots__ = ('bits', 'num_bits', 'num_hashes')

    def __init__(self, expected, error_rate):
        self.num_bits = max(64, int(-(expected * math.log(error_rate)) / (math.log(2) ** 2)))
        self.num_hashes = max(1, int((self.num_bits / expected) * math.log(2)))
        self.bits = bytearray((self.num_bits + 7) // 8)

    def _hashes(self, item):
        b = item.encode('utf-8', 'ignore')
        h1 = hash(b) & 0xFFFFFFFFFFFFFFFF
        h2 = hash(b[::-1] + b'\x9e') & 0xFFFFFFFFFFFFFFFF
        if h2 == 0:
            h2 = 0x9E3779B97F4A7C15
        n = self.num_bits
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % n

    def add(self, item):
        for idx in self._hashes(item):
            self.bits[idx >> 3] |= 1 << (idx & 7)

    def __contains__(self, item):
        for idx in self._hashes(item):
            if not (self.bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True


# ═══════════════════════════════════════════════════════════════════
# HTML CLEANER
# ═══════════════════════════════════════════════════════════════════

_kill_tags = frozenset({
    'script', 'style', 'code', 'pre', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
    'audio', 'video', 'source', 'track', 'dialog', 'menu', 'menuitem',
})

_cleaner = Cleaner(
    scripts=True, javascript=True, comments=True, style=True,
    inline_style=True, links=True, meta=True, page_structure=False,
    processing_instructions=True, embedded=True, frames=True,
    forms=True, annoying_tags=True, remove_unknown_tags=False,
    safe_attrs_only=False, kill_tags=_kill_tags,
)

_ws_re       = re.compile(r'[^\S\n]+')
_nl_re       = re.compile(r'\n{2,}')
_junk_re     = re.compile(r'[^\x20-\x7E\n\t]')
_has_junk_re = re.compile(r'<(script|style|code|pre)\b', re.IGNORECASE)


# ═══════════════════════════════════════════════════════════════════
# URL NORMALIZATION
# ═══════════════════════════════════════════════════════════════════

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
    r'torrent|magnet|'
    r'wasm|map)(\?|#|$)',
    re.IGNORECASE,
)

_BAD_SCHEMES = (
    'mailto:', 'tel:', 'sms:', 'callto:', 'skype:', 'whatsapp:',
    'javascript:', 'data:', 'blob:', 'about:', 'chrome:', 'moz-extension:',
    'ftp:', 'ftps:', 'sftp:', 'ssh:', 'file:', 'irc:', 'ircs:',
    'news:', 'nntp:', 'gopher:', 'ws:', 'wss:', 'view-source:',
    'intent:', 'market:', 'itms:', 'itms-apps:', 'bitcoin:', 'ethereum:',
)

# query keys that are pure tracking noise
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

# path segments that indicate non-content pages
_SKIP_PATH_RE = re.compile(
    r'/(wp-admin|wp-login\.php|wp-json|xmlrpc\.php|'
    r'login|logout|signin|sign-in|signup|sign-up|register|'
    r'cart|checkout|basket|order|payment|'
    r'admin|dashboard|account|profile|settings|'
    r'cdn-cgi|wp-content/uploads|assets?|static|media|'
    r'search|tag/|category/|author/)(/|$|\?)',
    re.IGNORECASE,
)


def _strip_tracking(url):
    try:
        p = urlparse(url)
    except Exception:
        return url
    if not p.query:
        return url
    kept = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
            if k.lower() not in _TRACKING_KEYS]
    new_query = urlencode(kept, doseq=True)
    return p._replace(query=new_query).geturl()


def normalize(url, base=''):
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url or url.startswith('#'):
        return None

    low = url[:24].lower()
    for s in _BAD_SCHEMES:
        if low.startswith(s):
            return None

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
    if not p.netloc or '.' not in p.netloc:
        return None
    if _SKIP_EXT.search(p.path):
        return None
    if _SKIP_PATH_RE.search(p.path):
        return None

    url = _strip_tracking(url)
    return url


def host_of(url):
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ''


# ═══════════════════════════════════════════════════════════════════
# SPOOF
# ═══════════════════════════════════════════════════════════════════

IMPERSONATE_POOL = [
    'chrome136', 'chrome133a', 'chrome131', 'chrome124',
    'chrome123', 'chrome120', 'chrome119', 'chrome116',
    'chrome110', 'chrome107', 'chrome104', 'chrome101',
    'chrome100', 'chrome99',
    'safari260', 'safari184', 'safari180', 'safari170',
    'safari155', 'safari153', 'safari15_5', 'safari15_3',
    'edge101', 'edge99',
]

_CHROME_VER = re.compile(r'chrome(\d+)')

_PLATFORMS = [
    'Windows NT 10.0; Win64; x64',
    'Windows NT 11.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7',
    'Macintosh; Intel Mac OS X 14_7',
    'Macintosh; Intel Mac OS X 15_2',
    'X11; Linux x86_64',
    'X11; Ubuntu; Linux x86_64',
]

_SAFARI_UAS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
]

_EDGE_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
]

_ACCEPT_LANGS = [
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-US,en;q=0.9,es;q=0.7',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-CA,en;q=0.9,fr-CA;q=0.8',
    'en-US,en;q=0.8,de;q=0.6',
]

_ACCEPTS = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
]

_REFERER_POOL = [
    'https://www.google.com/',
    'https://www.google.co.uk/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.brave.com/',
    'https://www.startpage.com/',
    'https://www.ecosia.org/',
    'https://www.qwant.com/',
    'https://yandex.com/',
]

_SEC_CH_UA = [
    '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
    '"Chromium";v="136", "Not(A:Brand";v="24", "Google Chrome";v="136"',
    '"Google Chrome";v="136", "Chromium";v="136", "Not=A?Brand";v="24"',
    '"Google Chrome";v="136", "Not.A/Brand";v="8", "Chromium";v="136"',
]

_SEC_CH_PLATFORM = ['"Windows"', '"macOS"', '"Linux"']


def _octet():
    return random.randint(1, 254)


def _random_ip_headers():
    o = lambda: f'{_octet()}.{_octet()}.{_octet()}.{_octet()}'
    return {
        'X-Forwarded-For':  ','.join(o() for _ in range(random.randint(1, 3))),
        'X-Real-IP':        o(),
        'Forwarded':        f'for={o()};proto=https',
        'CF-Connecting-IP': o(),
        'True-Client-IP':   o(),
        'X-Client-IP':      o(),
        'X-Originating-IP': f'[{o()}]',
        'X-Remote-IP':      o(),
        'X-Remote-Addr':    o(),
        'X-ProxyUser-Ip':   o(),
    }


def _ua_for(imp):
    if imp.startswith('chrome'):
        m = _CHROME_VER.search(imp)
        v = m.group(1) if m else '136'
        full = f'{v}.0.0.0' if len(v) <= 3 else v
        return f'Mozilla/5.0 ({random.choice(_PLATFORMS)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full} Safari/537.36'
    if imp.startswith('safari'):
        return random.choice(_SAFARI_UAS)
    if imp.startswith('edge'):
        return random.choice(_EDGE_UAS)
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'


def _build_headers(referer, imp):
    enc = 'gzip, deflate, br' + (', zstd' if CONFIG['accept_zstd'] else '')
    h = {
        'User-Agent':                  _ua_for(imp),
        'Accept':                      random.choice(_ACCEPTS),
        'Accept-Language':             random.choice(_ACCEPT_LANGS),
        'Accept-Encoding':             enc,
        'Cache-Control':               random.choice(['no-cache', 'max-age=0', 'no-store']),
        'Pragma':                      'no-cache',
        'DNT':                         random.choice(['1', '1', '0']),
        'Upgrade-Insecure-Requests':   '1',
        'Sec-Fetch-Dest':              'document',
        'Sec-Fetch-Mode':              'navigate',
        'Sec-Fetch-Site':              random.choice(['none', 'same-origin', 'cross-site']),
        'Sec-Fetch-User':              '?1',
        'Sec-CH-UA':                   random.choice(_SEC_CH_UA),
        'Sec-CH-UA-Mobile':            '?0',
        'Sec-CH-UA-Platform':          random.choice(_SEC_CH_PLATFORM),
        'Sec-CH-UA-Platform-Version':  random.choice(['"15.0.0"', '"14.7.0"', '"10.0.0"']),
        'Sec-CH-UA-Arch':              '"x86"',
        'Sec-CH-UA-Bitness':           '"64"',
        'Sec-CH-UA-Full-Version':      '"136.0.0.0"',
        'Sec-CH-UA-Model':             '""',
        'Connection':                  'keep-alive',
        'Referer':                     referer or random.choice(_REFERER_POOL),
    }
    h.update(_random_ip_headers())
    return h


# ═══════════════════════════════════════════════════════════════════
# SESSION POOL
# ═══════════════════════════════════════════════════════════════════

class SessionPool:
    def __init__(self, size):
        self.size = size
        self.sessions = [None] * size
        self.imps = [None] * size
        self.hits = [0] * size
        self.locks = [asyncio.Lock() for _ in range(size)]

    async def start(self):
        for i in range(self.size):
            imp = IMPERSONATE_POOL[i % len(IMPERSONATE_POOL)]
            self.sessions[i] = self._make(imp)
            self.imps[i] = imp

    @staticmethod
    def _make(imp):
        try:
            return AsyncSession(impersonate=imp, timeout=CONFIG['request_timeout'])
        except Exception:
            return AsyncSession(impersonate='chrome136', timeout=CONFIG['request_timeout'])

    async def stop(self):
        for s in self.sessions:
            if s is not None:
                try:
                    await s.close()
                except Exception:
                    pass

    def pick(self):
        return random.randrange(self.size)

    def get(self, idx):
        return self.sessions[idx]

    def imp_of(self, idx):
        return self.imps[idx]

    def bump(self, idx):
        self.hits[idx] += 1
        return self.hits[idx]

    def needs_rotation(self, idx):
        return self.hits[idx] >= CONFIG['rotate_every_n']

    def force_rotate(self, idx):
        self.hits[idx] = CONFIG['rotate_every_n']

    async def rotate(self, idx):
        if self.locks[idx].locked():
            return
        async with self.locks[idx]:
            if self.hits[idx] < CONFIG['rotate_every_n']:
                return
            old = self.sessions[idx]
            if old is not None:
                try:
                    await old.close()
                except Exception:
                    pass
            imp = random.choice(IMPERSONATE_POOL)
            self.sessions[idx] = self._make(imp)
            self.imps[idx] = imp
            self.hits[idx] = 0


# ═══════════════════════════════════════════════════════════════════
# OUTPUT PREFILL
# ═══════════════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════════════
# PARSER
# ═══════════════════════════════════════════════════════════════════

_META_REFRESH_RE = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.IGNORECASE)


def _parse_and_extract(raw, base_url):
    try:
        doc = lxml_html.document_fromstring(raw, base_url=base_url)
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
        if og and og[0].strip():
            title = og[0].strip()[:200]

    links = []
    seen_local = set()
    for a in doc.iter('a'):
        href = a.get('href')
        if not href:
            continue
        n = normalize(href, base=base_url)
        if n and n not in seen_local:
            seen_local.add(n)
            links.append(n)

    if not links:
        for el in doc.iter():
            attr = el.get('data-href') or el.get('data-url') or el.get('data-link')
            if attr:
                n = normalize(attr, base=base_url)
                if n and n not in seen_local:
                    seen_local.add(n)
                    links.append(n)

    for m in doc.iter('meta'):
        if (m.get('http-equiv') or '').lower() == 'refresh':
            content = m.get('content') or ''
            mr = _META_REFRESH_RE.search(content)
            if mr:
                n = normalize(mr.group(1), base=base_url)
                if n and n not in seen_local:
                    seen_local.add(n)
                    links.append(n)

    for lk in doc.iter('link'):
        rel = (lk.get('rel') or '').lower()
        if rel in ('next', 'prev', 'canonical', 'alternate'):
            href = lk.get('href')
            if href:
                n = normalize(href, base=base_url)
                if n and n not in seen_local:
                    seen_local.add(n)
                    links.append(n)

    for f in doc.iter('form'):
        action = f.get('action')
        if action:
            n = normalize(action, base=base_url)
            if n and n not in seen_local:
                seen_local.add(n)
                links.append(n)

    if _has_junk_re.search(raw):
        try:
            doc = _cleaner.clean_html(doc)
        except Exception:
            pass

    try:
        text = doc.text_content()
    except Exception:
        text = ''

    text = _ws_re.sub(' ', text)
    text = _nl_re.sub('\n', text)
    text = _junk_re.sub('', text)
    text = text.strip()

    if not text:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)


# ═══════════════════════════════════════════════════════════════════
# CRAWLER
# ═══════════════════════════════════════════════════════════════════

class Crawler:
    def __init__(self):
        self.bloom = BloomFilter(CONFIG['bloom_expected'], CONFIG['bloom_error'])
        self.queue = deque()
        self.host_inflight = {}
        self.pool = None
        self.written = 0
        self.fetched = 0
        self.dropped = 0
        self.zero_link_pages = 0
        self.errors = 0
        self.stop_flag = False
        self.out_fh = None
        self.stats_task = None
        self.start_time = time.time()
        self.last_report_time = self.start_time
        self.last_report_written = 0
        self.seed = ''
        self.write_lock = asyncio.Lock()

    async def run(self, seed):
        self.seed = seed
        for u in load_existing_urls():
            self.bloom.add(u)

        self.bloom.add(seed)
        self.queue.append((seed, '', 0))

        self.pool = SessionPool(CONFIG['session_pool_size'])
        await self.pool.start()

        self.out_fh = OUTPUT_FILE.open('a', encoding='utf-8')

        print(f'[Nexus] seed:     {seed}', file=sys.stderr)
        print(f'[Nexus] output:   {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] workers:  {CONFIG["concurrency"]}  per-host: {CONFIG["per_host_limit"]}  sessions: {CONFIG["session_pool_size"]}', file=sys.stderr)
        print('[Nexus] CTRL+C to stop.\n', file=sys.stderr)

        self.stats_task = asyncio.create_task(self._stats_loop())
        workers = [asyncio.create_task(self._worker(i)) for i in range(CONFIG['concurrency'])]

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
                self.out_fh.flush()
                self.out_fh.close()
            except Exception:
                pass
            await self.pool.stop()
            self._final_report()

    async def _stats_loop(self):
        while not self.stop_flag:
            await asyncio.sleep(CONFIG['stats_interval'])
            now = time.time()
            dt = now - self.last_report_time
            dw = self.written - self.last_report_written
            rate = dw / dt if dt > 0 else 0.0
            avg = self.written / (now - self.start_time) if now > self.start_time else 0.0
            print(
                f'[stats] rate={rate:6.1f}/s  avg={avg:6.1f}/s  '
                f'written={self.written}  fetched={self.fetched}  '
                f'dropped={self.dropped}  errors={self.errors}  '
                f'queue={len(self.queue)}  hosts={len(self.host_inflight)}  '
                f'zerolink={self.zero_link_pages}',
                file=sys.stderr,
            )
            self.last_report_time = now
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
            try:
                url, referer, depth = self.queue.popleft()
            except IndexError:
                idle_rounds += 1
                if len(self.host_inflight) == 0:
                    await asyncio.sleep(CONFIG['idle_deep_sleep'] if idle_rounds > 50 else CONFIG['idle_sleep'])
                else:
                    await asyncio.sleep(CONFIG['idle_sleep'])
                continue
            idle_rounds = 0

            host = host_of(url)
            if not host:
                continue

            inflight = self.host_inflight.get(host, 0)
            if inflight >= CONFIG['per_host_limit']:
                self.queue.append((url, referer, depth))
                await asyncio.sleep(0.02)
                continue
            self.host_inflight[host] = inflight + 1

            try:
                await self._process(url, referer, depth)
            except Exception as e:
                self.errors += 1
                if self.errors <= 20:
                    print(f'[w{wid}] err {url[:90]}: {type(e).__name__}: {e}', file=sys.stderr)
            finally:
                left = self.host_inflight.get(host, 1) - 1
                if left <= 0:
                    self.host_inflight.pop(host, None)
                else:
                    self.host_inflight[host] = left

            await asyncio.sleep((CONFIG['jitter_min'] + random.random() * (CONFIG['jitter_max'] - CONFIG['jitter_min'])) * CONFIG['jitter_scale'])

    async def _process(self, url, referer, depth):
        self.fetched += 1
        idx = self.pool.pick()
        sess = self.pool.get(idx)
        if sess is None:
            self.pool.force_rotate(idx)
            asyncio.create_task(self.pool.rotate(idx))
            self.dropped += 1
            return

        imp = self.pool.imp_of(idx)
        headers = _build_headers(referer, imp)

        try:
            resp = await sess.get(
                url,
                headers=headers,
                timeout=CONFIG['request_timeout'],
                allow_redirects=True,
                max_redirects=CONFIG['max_redirects'],
            )
        except Exception:
            self.pool.bump(idx)
            if self.pool.needs_rotation(idx):
                asyncio.create_task(self.pool.rotate(idx))
            self.dropped += 1
            return

        self.pool.bump(idx)
        if self.pool.needs_rotation(idx):
            asyncio.create_task(self.pool.rotate(idx))

        if resp.status_code != 200:
            if resp.status_code in (403, 429, 502, 503, 520, 521, 522, 523, 524):
                self.pool.force_rotate(idx)
                asyncio.create_task(self.pool.rotate(idx))
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
            cleaned, links = await loop.run_in_executor(None, _parse_and_extract, raw, url)
        except Exception:
            self.dropped += 1
            return

        if cleaned is not None:
            title, text = cleaned
            record = {'url': url, 'title': title, 'text': text}
            line = json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n'
            async with self.write_lock:
                self.out_fh.write(line)
                self.written += 1
                if self.written % CONFIG['write_flush_every'] == 0:
                    self.out_fh.flush()

        if not links:
            self.zero_link_pages += 1

        for link in links:
            if link not in self.bloom:
                self.bloom.add(link)
                if len(self.queue) < CONFIG['queue_high_water']:
                    self.queue.append((link, url, depth + 1))


# ═══════════════════════════════════════════════════════════════════
# ENTRY
# ═══════════════════════════════════════════════════════════════════

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
        pass

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