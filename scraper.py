#!/usr/bin/env python3
"""
Nexus Crawler — single-seed, unbounded, cross-domain HTML-to-text harvester.
Streams to output.json (JSONL). Bloom dedup. Max spoof.
"""

import json
import re
import sys
import time
import random
import string
import math
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag

from curl_cffi import requests
from lxml import html as lxml_html
from lxml.html.clean import Cleaner


# ═══════════════════════════════════════════════════════════════════
# BLOOM FILTER — zero-dep, double-hash, sized for a long run
# ═══════════════════════════════════════════════════════════════════

class BloomFilter:
    __slots__ = ('bits', 'num_bits', 'num_hashes')

    def __init__(self, expected: int = 50_000_000, error_rate: float = 0.001):
        self.num_bits = max(64, int(-(expected * math.log(error_rate)) / (math.log(2) ** 2)))
        self.num_hashes = max(1, int((self.num_bits / expected) * math.log(2)))
        self.bits = bytearray((self.num_bits + 7) // 8)

    def _hashes(self, item: str):
        # two independent 64-bit hashes -> Kirsch-Mitzenmacher double hashing
        b = item.encode('utf-8', 'ignore')
        h1 = hash(b) & 0xFFFFFFFFFFFFFFFF
        h2 = hash(b[::-1] + b'\x9e') & 0xFFFFFFFFFFFFFFFF
        if h2 == 0:
            h2 = 0x9E3779B97F4A7C15
        n = self.num_bits
        for i in range(self.num_hashes):
            yield (h1 + i * h2) % n

    def add(self, item: str):
        for idx in self._hashes(item):
            self.bits[idx >> 3] |= 1 << (idx & 7)

    def __contains__(self, item: str) -> bool:
        for idx in self._hashes(item):
            if not (self.bits[idx >> 3] & (1 << (idx & 7))):
                return False
        return True


# ═══════════════════════════════════════════════════════════════════
# HTML → TEXT CLEANER — kills code, scripts, styles, comments, embeds
# ═══════════════════════════════════════════════════════════════════

_kill_tags = frozenset({
    'script', 'style', 'code', 'pre', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
})

_cleaner = Cleaner(
    scripts=True,
    javascript=True,
    comments=True,
    style=True,
    inline_style=True,
    links=True,
    meta=True,
    page_structure=False,
    processing_instructions=True,
    embedded=True,
    frames=True,
    forms=True,
    annoying_tags=True,
    remove_unknown_tags=False,
    safe_attrs_only=False,
    kill_tags=_kill_tags,
)

_ws_re = re.compile(r'[^\S\n]+')
_nl_re = re.compile(r'\n{2,}')
_junk_re = re.compile(r'[^\x20-\x7E\n\t]')


def clean_page(raw_html: str):
    try:
        doc = lxml_html.document_fromstring(raw_html)
    except Exception:
        return None

    title = ''
    t = doc.find('.//title')
    if t is not None and t.text:
        title = t.text.strip()
    if not title:
        h1 = doc.find('.//h1')
        if h1 is not None:
            txt = h1.text_content()
            if txt:
                title = txt.strip()[:200]

    try:
        cleaned = _cleaner.clean_html(doc)
    except Exception:
        cleaned = doc

    text = cleaned.text_content()
    text = _ws_re.sub(' ', text)
    text = _nl_re.sub('\n', text)
    text = _junk_re.sub('', text)
    text = text.strip()

    if not text:
        return None
    return {'title': title or '[untitled]', 'text': text}


# ═══════════════════════════════════════════════════════════════════
# URL FILTER
# ═══════════════════════════════════════════════════════════════════

_SKIP_EXT = re.compile(
    r'\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|otf|eot|'
    r'mp[34]|m4a|aac|ogg|wav|flac|avi|mkv|mov|webm|flv|'
    r'pdf|docx?|xlsx?|pptx?|zip|tar|gz|tgz|bz2|xz|rar|7z|'
    r'exe|dmg|msi|apk|deb|rpm|iso|img|bin|'
    r'xml|rss|atom|json|jsonl|csv|tsv|yaml|yml|toml|ini|'
    r'zip|map)(\?|#|$)',
    re.IGNORECASE,
)

def normalize(url: str, base: str = ''):
    url = urldefrag(url)[0].strip()
    if not url:
        return None
    if url.startswith(('mailto:', 'tel:', 'javascript:', 'data:', 'ftp:', 'file:')):
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
    # strip fragments/pure tracking noise but keep query
    return url


# ═══════════════════════════════════════════════════════════════════
# MAXIMUM SPOOF LAYER
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
_SAFARI_VER = re.compile(r'safari(\d)')
_EDGE_VER = re.compile(r'edge(\d+)')


def _ua_for(imp: str) -> str:
    if imp.startswith('chrome'):
        m = _CHROME_VER.search(imp)
        v = m.group(1) if m else '136'
        full = f'{v}.0.0.0' if len(v) <= 3 else v
        plat = random.choice([
            'Windows NT 10.0; Win64; x64',
            'Windows NT 11.0; Win64; x64',
            'Macintosh; Intel Mac OS X 10_15_7',
            'Macintosh; Intel Mac OS X 14_7',
            'X11; Linux x86_64',
            'X11; Ubuntu; Linux x86_64',
        ])
        return f'Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full} Safari/537.36'
    if imp.startswith('safari'):
        return random.choice([
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
        ])
    if imp.startswith('edge'):
        return random.choice([
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
            'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
        ])
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'


_ACCEPT_LANGS = [
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.8,es;q=0.6',
    'en-CA,en;q=0.9,fr-CA;q=0.8',
]

_ACCEPT_CHARSETS = ['utf-8, iso-8859-1;q=0.5, *;q=0.1']

_REFERER_POOL = [
    'https://www.google.com/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.brave.com/',
    'https://www.startpage.com/',
    'https://www.ecosia.org/',
]


def _random_ip_spoof_headers() -> dict:
    # X-Forwarded-For chain — randomized, plausible
    octet = lambda: random.randint(1, 254)
    chain = ','.join(
        f'{octet()}.{octet()}.{octet()}.{octet()}'
        for _ in range(random.randint(1, 3))
    )
    return {
        'X-Forwarded-For': chain,
        'X-Real-IP': f'{octet()}.{octet()}.{octet()}.{octet()}',
        'Forwarded': f'for={octet()}.{octet()}.{octet()}.{octet()};proto=https',
        'CF-Connecting-IP': f'{octet()}.{octet()}.{octet()}.{octet()}',
        'True-Client-IP': f'{octet()}.{octet()}.{octet()}.{octet()}',
        'X-Client-IP': f'{octet()}.{octet()}.{octet()}.{octet()}',
        'X-Originating-IP': f'[{octet()}.{octet()}.{octet()}.{octet()}]',
        'X-Remote-IP': f'{octet()}.{octet()}.{octet()}.{octet()}',
        'X-Remote-Addr': f'{octet()}.{octet()}.{octet()}.{octet()}',
    }


def _build_headers(referer: str = '') -> dict:
    h = {
        'User-Agent': _ua_for(random.choice(IMPERSONATE_POOL).split('.')[0]),
        'Accept': random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ]),
        'Accept-Language': random.choice(_ACCEPT_LANGS),
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Accept-Charset': random.choice(_ACCEPT_CHARSETS),
        'Cache-Control': random.choice(['no-cache', 'max-age=0', 'no-store']),
        'Pragma': 'no-cache',
        'DNT': random.choice(['1', '1', '0']),
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),
        'Sec-Fetch-User': '?1',
        'Sec-CH-UA': random.choice([
            '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
            '"Chromium";v="136", "Not(A:Brand";v="24", "Google Chrome";v="136"',
            '"Google Chrome";v="136", "Chromium";v="136", "Not=A?Brand";v="24"',
        ]),
        'Sec-CH-UA-Mobile': '?0',
        'Sec-CH-UA-Platform': random.choice(['"Windows"', '"macOS"', '"Linux"']),
        'Sec-CH-UA-Platform-Version': random.choice(['"15.0.0"', '"14.7.0"', '"10.0.0"']),
        'Sec-CH-UA-Arch': '"x86"',
        'Sec-CH-UA-Bitness': '"64"',
        'Sec-CH-UA-Full-Version': '"136.0.0.0"',
        'Sec-CH-UA-Full-Version-List': '"Chromium";v="136.0.0.0", "Google Chrome";v="136.0.0.0", "Not-A.Brand";v="99.0.0.0"',
        'Sec-CH-UA-Model': '""',
        'Sec-CH-UA-WoW64': '?0',
        'Sec-Purpose': random.choice(['prefetch', 'prefetch;prerender', '']),
        'Connection': 'keep-alive',
        'Priority': 'u=0, i',
        'Origin': referer.rstrip('/') if referer and random.random() < 0.3 else '',
    }
    if referer:
        h['Referer'] = referer
    else:
        h['Referer'] = random.choice(_REFERER_POOL)
    h.update(_random_ip_spoof_headers())
    return {k: v for k, v in h.items() if v}


# Session pool — rotate fingerprint on every N requests and on any error
_SESSIONS: list = []
_SESSION_HITS = [0]
_SESSION_ROTATE_AFTER = 40


def _new_session():
    imp = random.choice(IMPERSONATE_POOL)
    try:
        s = requests.Session(impersonate=imp)
    except Exception:
        s = requests.Session(impersonate='chrome136')
    return s


def _session() -> requests.Session:
    if not _SESSIONS:
        _SESSIONS.append(_new_session())
        return _SESSIONS[0]
    if _SESSION_HITS[0] >= _SESSION_ROTATE_AFTER:
        _SESSIONS[0] = _new_session()
        _SESSION_HITS[0] = 0
    _SESSION_HITS[0] += 1
    return _SESSIONS[0]


def fetch(url: str, referer: str = '', timeout: int = 25):
    headers = _build_headers(referer)
    sess = _session()
    try:
        resp = sess.get(
            url,
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
            max_redirects=10,
        )
    except Exception:
        _SESSIONS[0] = _new_session()
        _SESSION_HITS[0] = 0
        return None

    if resp.status_code != 200:
        if resp.status_code in (403, 429, 503, 502, 520, 521, 522, 523, 524):
            _SESSIONS[0] = _new_session()
            _SESSION_HITS[0] = 0
        return None

    ctype = (resp.headers.get('content-type') or '').lower()
    if 'text/html' not in ctype and 'application/xhtml' not in ctype:
        return None

    try:
        return resp.text
    except Exception:
        try:
            return resp.content.decode('utf-8', 'ignore')
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════
# OUTPUT PREFILL — dedup against existing output.json lines
# ═══════════════════════════════════════════════════════════════════

OUTPUT_FILE = Path('output.json')


def load_existing_urls() -> set:
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
# CRAWL — unbounded, single seed, cross-domain
# ═══════════════════════════════════════════════════════════════════

def jitter_sleep():
    time.sleep(0.3 + random.random() * 0.6)  # 0.3 – 0.9s


def crawl(seed: str):
    seed_n = normalize(seed)
    if not seed_n:
        print('[!] invalid seed url', file=sys.stderr)
        return

    bloom = BloomFilter(expected=50_000_000, error_rate=0.001)
    for u in load_existing_urls():
        bloom.add(u)

    queue = deque([seed_n])
    bloom.add(seed_n)

    written = 0
    fetched = 0
    last_url = ''

    print(f'[Nexus] seed: {seed_n}', file=sys.stderr)
    print(f'[Nexus] output: {OUTPUT_FILE.resolve()}', file=sys.stderr)
    print('[Nexus] CTRL+C to stop.', file=sys.stderr)

    with OUTPUT_FILE.open('a', encoding='utf-8') as f:
        try:
            while True:
                if not queue:
                    # cross-domain: if queue empties, hold and wait briefly
                    time.sleep(1.0)
                    continue

                url = queue.popleft()
                fetched += 1

                print(f'[{written}] {url[:140]}', file=sys.stderr)

                raw = fetch(url, referer=last_url)
                if raw is None:
                    jitter_sleep()
                    continue

                page = clean_page(raw)
                if page is None:
                    jitter_sleep()
                    continue

                record = {
                    'url': url,
                    'title': page['title'],
                    'text': page['text'],
                }
                f.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
                f.flush()
                written += 1
                last_url = url

                # link extraction
                try:
                    doc = lxml_html.document_fromstring(raw)
                    for a in doc.iter('a'):
                        href = a.get('href')
                        if not href:
                            continue
                        n = normalize(href, base=url)
                        if n and n not in bloom:
                            bloom.add(n)
                            queue.append(n)
                except Exception:
                    pass

                jitter_sleep()
        except KeyboardInterrupt:
            print(f'\n[Nexus] stopped. written={written} fetched={fetched} queue={len(queue)}', file=sys.stderr)


# ═══════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    try:
        seed = input('url : ').strip()
    except (EOFError, KeyboardInterrupt):
        sys.exit(1)
    if not seed:
        sys.exit(1)
    crawl(seed)