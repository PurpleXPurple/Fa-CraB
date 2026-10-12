#!/usr/bin/env python3
"""
Nexus Crawler v2 — massively parallel, unbounded, cross-domain HTML harvester.
Target: 30–90 pages/sec sustained. Streams to output.json (JSONL). Bloom dedup. Max spoof.
"""

import asyncio
import json
import re
import sys
import time
import random
import math
import signal
import threading
from collections import deque
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag

from curl_cffi.requests import AsyncSession
from lxml import html as lxml_html
from lxml.html.clean import Cleaner


# ═══════════════════════════════════════════════════════════════════
# TUNABLES
# ═══════════════════════════════════════════════════════════════════

CONCURRENCY        = 200          # simultaneous in-flight requests
PER_HOST_LIMIT     = 4            # max parallel requests per hostname
SESSION_POOL_SIZE  = 32           # rotating AsyncSession fingerprints
ROTATE_EVERY_N     = 500          # requests per session before forced rotation
REQUEST_TIMEOUT    = 15           # seconds
MAX_HTML_BYTES     = 2_000_000    # hard cap on response body to parse
QUEUE_HIGH_WATER   = 400_000      # backpressure threshold
QUEUE_LOW_WATER    = 100_000      # resume threshold
JITTER_MIN         = 0.3
JITTER_MAX         = 0.9
STATS_INTERVAL     = 2.0

OUTPUT_FILE = Path('output.json')


# ═══════════════════════════════════════════════════════════════════
# BLOOM FILTER — lock-free single-writer, sized for tens of millions
# ═══════════════════════════════════════════════════════════════════

class BloomFilter:
    __slots__ = ('bits', 'num_bits', 'num_hashes')

    def __init__(self, expected: int = 100_000_000, error_rate: float = 0.0005):
        self.num_bits = max(64, int(-(expected * math.log(error_rate)) / (math.log(2) ** 2)))
        self.num_hashes = max(1, int((self.num_bits / expected) * math.log(2)))
        self.bits = bytearray((self.num_bits + 7) // 8)

    def _hashes(self, item: str):
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
# HTML → TEXT CLEANER
# ═══════════════════════════════════════════════════════════════════

_kill_tags = frozenset({
    'script', 'style', 'code', 'pre', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
})

_cleaner = Cleaner(
    scripts=True, javascript=True, comments=True, style=True,
    inline_style=True, links=True, meta=True, page_structure=False,
    processing_instructions=True, embedded=True, frames=True,
    forms=True, annoying_tags=True, remove_unknown_tags=False,
    safe_attrs_only=False, kill_tags=_kill_tags,
)

_ws_re  = re.compile(r'[^\S\n]+')
_nl_re  = re.compile(r'\n{2,}')
_junk_re = re.compile(r'[^\x20-\x7E\n\t]')

# fast path: does the body even have a <script> or <style>?
_has_junk_re = re.compile(r'<(script|style|code|pre)\b', re.IGNORECASE)


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

    # skip the cleaner entirely when there's nothing to clean
    if _has_junk_re.search(raw_html):
        try:
            doc = _cleaner.clean_html(doc)
        except Exception:
            pass

    text = doc.text_content()
    text = _ws_re.sub(' ', text)
    text = _nl_re.sub('\n', text)
    text = _junk_re.sub('', text)
    text = text.strip()

    if not text:
        return None
    return title or '[untitled]', text


# ═══════════════════════════════════════════════════════════════════
# URL FILTER
# ═══════════════════════════════════════════════════════════════════

_SKIP_EXT = re.compile(
    r'\.(png|jpe?g|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|otf|eot|'
    r'mp[34]|m4a|aac|ogg|wav|flac|avi|mkv|mov|webm|flv|'
    r'pdf|docx?|xlsx?|pptx?|zip|tar|gz|tgz|bz2|xz|rar|7z|'
    r'exe|dmg|msi|apk|deb|rpm|iso|img|bin|'
    r'xml|rss|atom|json|jsonl|csv|tsv|yaml|yml|toml|ini|map)(\?|#|$)',
    re.IGNORECASE,
)

_BAD_SCHEMES = ('mailto:', 'tel:', 'javascript:', 'data:', 'ftp:', 'file:', 'blob:')


def normalize(url: str, base: str = ''):
    url = urldefrag(url)[0].strip()
    if not url:
        return None
    if url[:12].lower().startswith(_BAD_SCHEMES):
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
    return url


def host_of(url: str) -> str:
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ''


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

_PLATFORMS = [
    'Windows NT 10.0; Win64; x64',
    'Windows NT 11.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7',
    'Macintosh; Intel Mac OS X 14_7',
    'X11; Linux x86_64',
    'X11; Ubuntu; Linux x86_64',
]

_SAFARI_UAS = [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Mobile/15E148 Safari/604.1',
]

_EDGE_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    'Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
]


def _ua_for(imp: str) -> str:
    if imp.startswith('chrome'):
        m = _CHROME_VER.search(imp)
        v = m.group(1) if m else '136'
        full = f'{v}.0.0.0' if len(v) <= 3 else v
        plat = random.choice(_PLATFORMS)
        return f'Mozilla/5.0 ({plat}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full} Safari/537.36'
    if imp.startswith('safari'):
        return random.choice(_SAFARI_UAS)
    if imp.startswith('edge'):
        return random.choice(_EDGE_UAS)
    return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'


_ACCEPT_LANGS = [
    'en-US,en;q=0.9',
    'en-US,en;q=0.9,fr;q=0.8',
    'en-GB,en;q=0.9,en-US;q=0.8',
    'en-US,en;q=0.8,es;q=0.6',
    'en-CA,en;q=0.9,fr-CA;q=0.8',
]

_ACCEPTS = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
]

_REFERER_POOL = [
    'https://www.google.com/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.brave.com/',
    'https://www.startpage.com/',
    'https://www.ecosia.org/',
]

_SEC_CH_UA = [
    '"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"',
    '"Chromium";v="136", "Not(A:Brand";v="24", "Google Chrome";v="136"',
    '"Google Chrome";v="136", "Chromium";v="136", "Not=A?Brand";v="24"',
]

_SEC_CH_PLATFORM = ['"Windows"', '"macOS"', '"Linux"']


def _octet():
    return random.randint(1, 254)


def _random_ip_headers() -> dict:
    return {
        'X-Forwarded-For':  ','.join(f'{_octet()}.{_octet()}.{_octet()}.{_octet()}' for _ in range(random.randint(1, 3))),
        'X-Real-IP':        f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
        'Forwarded':        f'for={_octet()}.{_octet()}.{_octet()}.{_octet()};proto=https',
        'CF-Connecting-IP': f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
        'True-Client-IP':   f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
        'X-Client-IP':      f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
        'X-Originating-IP': f'[{_octet()}.{_octet()}.{_octet()}.{_octet()}]',
        'X-Remote-IP':      f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
        'X-Remote-Addr':    f'{_octet()}.{_octet()}.{_octet()}.{_octet()}',
    }


def _build_headers(referer: str, imp: str) -> dict:
    h = {
        'User-Agent':                    _ua_for(imp),
        'Accept':                        random.choice(_ACCEPTS),
        'Accept-Language':               random.choice(_ACCEPT_LANGS),
        'Accept-Encoding':               'gzip, deflate, br, zstd',
        'Cache-Control':                 random.choice(['no-cache', 'max-age=0', 'no-store']),
        'Pragma':                        'no-cache',
        'DNT':                           random.choice(['1', '1', '0']),
        'Upgrade-Insecure-Requests':     '1',
        'Sec-Fetch-Dest':                'document',
        'Sec-Fetch-Mode':                'navigate',
        'Sec-Fetch-Site':                random.choice(['none', 'same-origin', 'cross-site']),
        'Sec-Fetch-User':                '?1',
        'Sec-CH-UA':                     random.choice(_SEC_CH_UA),
        'Sec-CH-UA-Mobile':              '?0',
        'Sec-CH-UA-Platform':            random.choice(_SEC_CH_PLATFORM),
        'Sec-CH-UA-Platform-Version':    random.choice(['"15.0.0"', '"14.7.0"', '"10.0.0"']),
        'Sec-CH-UA-Arch':                '"x86"',
        'Sec-CH-UA-Bitness':             '"64"',
        'Sec-CH-UA-Full-Version':        '"136.0.0.0"',
        'Sec-CH-UA-Full-Version-List':   '"Chromium";v="136.0.0.0", "Google Chrome";v="136.0.0.0", "Not-A.Brand";v="99.0.0.0"',
        'Sec-CH-UA-Model':               '""',
        'Sec-CH-UA-WoW64':               '?0',
        'Connection':                    'keep-alive',
        'Priority':                      'u=0, i',
        'Referer':                       referer or random.choice(_REFERER_POOL),
    }
    h.update(_random_ip_headers())
    return h


# ═══════════════════════════════════════════════════════════════════
# SESSION POOL — one AsyncSession per impersonation slot
# ═══════════════════════════════════════════════════════════════════

class SessionPool:
    """Rotating pool of AsyncSession fingerprints. Zero lock contention on hot path."""

    def __init__(self, size: int):
        self.size = size
        self.sessions: list = []
        self.hits: list = []
        self.impersonations: list = []

    async def start(self):
        for i in range(self.size):
            imp = IMPERSONATE_POOL[i % len(IMPERSONATE_POOL)]
            try:
                s = AsyncSession(impersonate=imp, timeout=REQUEST_TIMEOUT)
            except Exception:
                s = AsyncSession(impersonate='chrome136', timeout=REQUEST_TIMEOUT)
            self.sessions.append(s)
            self.hits.append(0)
            self.impersonations.append(imp)

    async def stop(self):
        for s in self.sessions:
            try:
                await s.close()
            except Exception:
                pass

    def pick(self) -> int:
        return random.randrange(self.size)

    def impersonation_of(self, idx: int) -> str:
        return self.impersonations[idx]

    async def rotate(self, idx: int):
        try:
            await self.sessions[idx].close()
        except Exception:
            pass
        imp = random.choice(IMPERSONATE_POOL)
        try:
            self.sessions[idx] = AsyncSession(impersonate=imp, timeout=REQUEST_TIMEOUT)
        except Exception:
            self.sessions[idx] = AsyncSession(impersonate='chrome136', timeout=REQUEST_TIMEOUT)
        self.impersonations[idx] = imp
        self.hits[idx] = 0

    def session(self, idx: int):
        return self.sessions[idx]


# ═══════════════════════════════════════════════════════════════════
# OUTPUT PREFILL — dedup against existing output.json
# ═══════════════════════════════════════════════════════════════════

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
# CRAWLER
# ═══════════════════════════════════════════════════════════════════

class Crawler:
    def __init__(self):
        self.bloom = BloomFilter(expected=100_000_000, error_rate=0.0005)
        self.queue: deque = deque()
        self.host_inflight: dict = {}
        self.pool: SessionPool = None
        self.written = 0
        self.fetched = 0
        self.dropped = 0
        self.lock = threading.Lock()
        self.stop_flag = False
        self.out_fh = None
        self.sem = None
        self.stats_task = None
        self.start_time = time.time()
        self.last_report_time = self.start_time
        self.last_report_written = 0

    # ---------------------------------------------------------------

    async def run(self, seed: str):
        seed_n = normalize(seed)
        if not seed_n:
            print('[!] invalid seed url', file=sys.stderr)
            return

        for u in load_existing_urls():
            self.bloom.add(u)

        self.bloom.add(seed_n)
        self.queue.append((seed_n, ''))

        self.pool = SessionPool(SESSION_POOL_SIZE)
        await self.pool.start()

        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.out_fh = OUTPUT_FILE.open('a', encoding='utf-8')

        print(f'[Nexus] seed:    {seed_n}', file=sys.stderr)
        print(f'[Nexus] output:  {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] workers: {CONCURRENCY}  per-host: {PER_HOST_LIMIT}  sessions: {SESSION_POOL_SIZE}', file=sys.stderr)
        print('[Nexus] CTRL+C to stop.\n', file=sys.stderr)

        self.stats_task = asyncio.create_task(self._stats_loop())

        workers = [asyncio.create_task(self._worker()) for _ in range(CONCURRENCY)]
        try:
            await asyncio.gather(*workers)
        except asyncio.CancelledError:
            pass
        finally:
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

    # ---------------------------------------------------------------

    async def _stats_loop(self):
        while not self.stop_flag:
            await asyncio.sleep(STATS_INTERVAL)
            now = time.time()
            dt = now - self.last_report_time
            dw = self.written - self.last_report_written
            rate = dw / dt if dt > 0 else 0.0
            avg = self.written / (now - self.start_time) if now > self.start_time else 0.0
            print(
                f'[stats] rate={rate:6.1f}/s  avg={avg:6.1f}/s  written={self.written}  '
                f'fetched={self.fetched}  queue={len(self.queue)}  '
                f'hosts={len(self.host_inflight)}',
                file=sys.stderr,
            )
            self.last_report_time = now
            self.last_report_written = self.written

    def _final_report(self):
        elapsed = time.time() - self.start_time
        avg = self.written / elapsed if elapsed > 0 else 0
        print(
            f'\n[Nexus] stopped. written={self.written}  fetched={self.fetched}  '
            f'dropped={self.dropped}  elapsed={elapsed:.1f}s  avg={avg:.1f}/s',
            file=sys.stderr,
        )

    # ---------------------------------------------------------------

    def _enqueue(self, url: str, referer: str):
        if len(self.queue) > QUEUE_HIGH_WATER:
            return
        self.queue.append((url, referer))

    # ---------------------------------------------------------------

    async def _worker(self):
        while not self.stop_flag:
            if not self.queue:
                # queue drained — hold and wait (unbounded crawl: seed keeps feeding us)
                await asyncio.sleep(0.05)
                continue
            try:
                url, referer = self.queue.popleft()
            except IndexError:
                continue

            host = host_of(url)
            if not host:
                continue

            # per-host throttle
            inflight = self.host_inflight.get(host, 0)
            if inflight >= PER_HOST_LIMIT:
                # re-queue at the back and yield
                self.queue.append((url, referer))
                await asyncio.sleep(0.01)
                continue
            self.host_inflight[host] = inflight + 1

            try:
                await self._process(url, referer)
            except Exception:
                pass
            finally:
                left = self.host_inflight.get(host, 1) - 1
                if left <= 0:
                    self.host_inflight.pop(host, None)
                else:
                    self.host_inflight[host] = left

            # global backpressure: when queue is too deep, breathe
            if len(self.queue) > QUEUE_HIGH_WATER and random.random() < 0.05:
                await asyncio.sleep(0.5)

            # per-request jitter — global 0.3–0.9s aggregated across 200 workers
            await asyncio.sleep(JITTER_MIN + random.random() * (JITTER_MAX - JITTER_MIN) * 0.05)

    # ---------------------------------------------------------------

    async def _process(self, url: str, referer: str):
        async with self.sem:
            self.fetched += 1
            idx = self.pool.pick()
            sess = self.pool.session(idx)
            imp = self.pool.impersonation_of(idx)
            headers = _build_headers(referer, imp)

            try:
                resp = await sess.get(
                    url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                    max_redirects=10,
                )
            except Exception:
                self.pool.hits[idx] += 1
                if self.pool.hits[idx] >= ROTATE_EVERY_N:
                    await self.pool.rotate(idx)
                self.dropped += 1
                return

            self.pool.hits[idx] += 1
            if self.pool.hits[idx] >= ROTATE_EVERY_N:
                asyncio.create_task(self.pool.rotate(idx))

            if resp.status_code != 200:
                if resp.status_code in (403, 429, 502, 503, 520, 521, 522, 523, 524):
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

            if len(raw) > MAX_HTML_BYTES:
                raw = raw[:MAX_HTML_BYTES]

            # parse + clean + extract links — off the event loop
            loop = asyncio.get_running_loop()
            cleaned, links = await loop.run_in_executor(None, self._parse_and_extract, raw, url)

            if cleaned is not None:
                title, text = cleaned
                record = {'url': url, 'title': title, 'text': text}
                self.out_fh.write(json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n')
                self.written += 1
                if self.written % 32 == 0:
                    self.out_fh.flush()

            # enqueue new links
            for link in links:
                if link not in self.bloom:
                    self.bloom.add(link)
                    self._enqueue(link, url)

    # ---------------------------------------------------------------

    @staticmethod
    def _parse_and_extract(raw: str, base_url: str):
        try:
            doc = lxml_html.document_fromstring(raw)
        except Exception:
            return None, ()

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

        # links first — before we mutate the tree
        links = []
        for a in doc.iter('a'):
            href = a.get('href')
            if not href:
                continue
            n = normalize(href, base=base_url)
            if n:
                links.append(n)

        if _has_junk_re.search(raw):
            try:
                doc = _cleaner.clean_html(doc)
            except Exception:
                pass

        text = doc.text_content()
        text = _ws_re.sub(' ', text)
        text = _nl_re.sub('\n', text)
        text = _junk_re.sub('', text)
        text = text.strip()

        if not text:
            return None, tuple(links)
        return (title or '[untitled]', text), tuple(links)


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

    run_task = asyncio.create_task(crawler.run(seed))
    stop_wait = asyncio.create_task(stop_event.wait())
    done, pending = await asyncio.wait({run_task, stop_wait}, return_when=asyncio.FIRST_COMPLETED)

    if stop_event.is_set():
        # cancel workers
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