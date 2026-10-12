import asyncio
import json
import re
import sys
import time
import random
import math
import signal
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode

from curl_cffi.requests import AsyncSession

try:
    from selectolax.lexbor import LexborHTMLParser
    _HAS_LEXBOR = True
except ImportError:
    _HAS_LEXBOR = False
    from lxml import html as _lxml_html


CONFIG = {
    'initial_concurrency': 400,
    'min_concurrency': 120,
    'max_concurrency': 2000,
    'session_pool_size': 48,
    'rotate_every_n': 250,
    'request_timeout': 12,
    'max_html_bytes': 2_500_000,
    'max_redirects': 8,
    'queue_high_water': 1_500_000,
    'stats_interval': 2.0,
    'idle_sleep': 0.001,
    'idle_deep_sleep': 1.0,
    'write_buffer_size': 64,
    'output_file': 'output.json',
    'bloom_expected': 150_000_000,
    'bloom_error': 0.001,
    'parser_workers': 8,
    'batch_pop': 8,
}

OUTPUT_FILE = Path(CONFIG['output_file'])
PARSER_POOL = ThreadPoolExecutor(max_workers=CONFIG['parser_workers'])

# ============================================================
# Bloom Filter (same as previous version, kept)
# ============================================================
class BloomFilter:
    __slots__ = ('bits', 'num_bits', 'num_hashes', 'mask')
    def __init__(self, expected, error_rate):
        raw_bits = int(-(expected * math.log(error_rate)) / (math.log(2) ** 2))
        self.num_bits = 1 << max(6, (raw_bits - 1).bit_length())
        self.mask = self.num_bits - 1
        self.num_hashes = max(1, int((self.num_bits / expected) * math.log(2)))
        self.bits = bytearray(self.num_bits >> 3)
    def _hashes(self, item):
        b = item.encode('utf-8', 'ignore')
        h1 = hash(b)
        h2 = hash(b[::-1] + b'\x9e')
        if h2 == 0: h2 = 0x9E3779B97F4A7C15
        mask = self.mask
        for i in range(self.num_hashes):
            yield (h1 + i * h2) & mask
    def add(self, item):
        bits = self.bits
        for idx in self._hashes(item): bits[idx >> 3] |= 1 << (idx & 7)
    def __contains__(self, item):
        bits = self.bits
        for idx in self._hashes(item):
            if not (bits[idx >> 3] & (1 << (idx & 7))): return False
        return True

# ============================================================
# Domain State + Rate Limit Tracker (same as previous version)
# ============================================================
class DomainState:
    __slots__ = ('delay', 'fails', 'last_hit')
    def __init__(self):
        self.delay = 0.0; self.fails = 0; self.last_hit = 0.0

class RateLimitTracker:
    __slots__ = ('domains', '_lock')
    def __init__(self):
        self.domains = {}; self._lock = asyncio.Lock()
    async def wait(self, host):
        state = self.domains.get(host)
        if state is None or state.delay <= 0: return
        gap = state.delay - (time.monotonic() - state.last_hit)
        if gap > 0: await asyncio.sleep(gap)
    async def record(self, host, status, retry_after=0.0):
        async with self._lock:
            state = self.domains.get(host)
            if state is None:
                state = DomainState(); self.domains[host] = state
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

# ============================================================
# Adaptive Gate (same as previous version)
# ============================================================
class AdaptiveGate:
    __slots__ = ('limit', 'min_lim', 'max_lim', 'inflight', '_cond', '_results')
    def __init__(self, initial, min_lim, max_lim):
        self.limit = initial; self.min_lim = min_lim; self.max_lim = max_lim
        self.inflight = 0; self._cond = asyncio.Condition()
        self._results = deque(maxlen=256)
    async def acquire(self):
        async with self._cond:
            while self.inflight >= self.limit:
                await self._cond.wait()
            self.inflight += 1
    async def release(self, status):
        async with self._cond:
            self.inflight -= 1
            self._results.append(status)
            self._adjust()
            self._cond.notify(1)
    def _adjust(self):
        n = len(self._results)
        if n < 128: return
        fails = sum(1 for s in self._results if s != 200)
        rate = fails / n
        if rate > 0.20:
            self.limit = max(self.min_lim, int(self.limit * 0.75))
        elif rate < 0.04 and self.limit < self.max_lim:
            self.limit = min(self.max_lim, int(self.limit * 1.12))
    @property
    def current(self): return self.limit

# ============================================================
# Spoofing (9 layers, same as previous version)
# ============================================================
_IMPERSONATIONS = [
    'chrome136', 'chrome133a', 'chrome131', 'chrome124',
    'chrome123', 'chrome120', 'chrome119', 'chrome116',
    'chrome110', 'chrome107', 'chrome104', 'chrome101',
    'chrome100', 'chrome99',
    'safari260', 'safari184', 'safari180', 'safari170',
    'safari155', 'safari153', 'safari15_5', 'safari15_3',
    'edge101', 'edge99',
    'firefox135', 'firefox133', 'firefox128',
]
_CHROME_VER_RE = re.compile(r'chrome(\d+)')
_PLATFORMS = [
    'Windows NT 10.0; Win64; x64', 'Windows NT 11.0; Win64; x64',
    'Macintosh; Intel Mac OS X 10_15_7', 'Macintosh; Intel Mac OS X 14_7',
    'Macintosh; Intel Mac OS X 15_2', 'X11; Linux x86_64', 'X11; Ubuntu; Linux x86_64',
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
_FIREFOX_UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
]
_ACCEPT_LANGS = ['en-US,en;q=0.9','en-US,en;q=0.9,fr;q=0.8','en-US,en;q=0.9,es;q=0.7','en-GB,en;q=0.9,en-US;q=0.8','en-CA,en;q=0.9,fr-CA;q=0.8','en-US,en;q=0.8,de;q=0.6','en-US,en;q=0.8,nl;q=0.6']
_ACCEPTS = ['text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7','text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8']
_REFERERS = ['https://www.google.com/','https://www.google.co.uk/','https://www.google.de/','https://www.google.fr/','https://duckduckgo.com/','https://www.bing.com/','https://search.brave.com/','https://www.startpage.com/','https://www.ecosia.org/','https://www.qwant.com/','https://yandex.com/']
_SEC_CH_UA = ['"Chromium";v="136", "Google Chrome";v="136", "Not-A.Brand";v="99"','"Chromium";v="136", "Not(A:Brand";v="24", "Google Chrome";v="136"','"Google Chrome";v="136", "Chromium";v="136", "Not=A?Brand";v="24"','"Google Chrome";v="136", "Not.A/Brand";v="8", "Chromium";v="136"']
_SEC_CH_PLATFORM = ['"Windows"', '"macOS"', '"Linux"']
_SEC_CH_PLATFORM_VER = ['"15.0.0"', '"14.7.0"', '"10.0.0"', '"11.0.0"']

def _octet(): return random.randint(1, 254)

class SpoofEngine:
    __slots__ = ()
    def layer_1_tls(self): return random.choice(_IMPERSONATIONS)
    def layer_2_http2(self, session): return session
    def layer_3_ua(self, imp):
        if imp.startswith('chrome'):
            m = _CHROME_VER_RE.search(imp)
            v = m.group(1) if m else '136'
            full = f'{v}.0.0.0' if len(v) <= 3 else v
            return f'Mozilla/5.0 ({random.choice(_PLATFORMS)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{full} Safari/537.36'
        if imp.startswith('safari'): return random.choice(_SAFARI_UAS)
        if imp.startswith('edge'): return random.choice(_EDGE_UAS)
        if imp.startswith('firefox'): return random.choice(_FIREFOX_UAS)
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36'
    def layer_4_client_hints(self):
        return {'Sec-CH-UA': random.choice(_SEC_CH_UA),'Sec-CH-UA-Mobile': '?0','Sec-CH-UA-Platform': random.choice(_SEC_CH_PLATFORM),'Sec-CH-UA-Platform-Version': random.choice(_SEC_CH_PLATFORM_VER),'Sec-CH-UA-Arch': '"x86"','Sec-CH-UA-Bitness': '"64"','Sec-CH-UA-Full-Version': '"136.0.0.0"','Sec-CH-UA-Full-Version-List':'"Chromium";v="136.0.0.0", "Google Chrome";v="136.0.0.0", "Not-A.Brand";v="99.0.0.0"','Sec-CH-UA-Model': '""','Sec-CH-UA-WoW64': '?0'}
    def layer_5_sec_fetch(self):
        return {'Sec-Fetch-Dest': 'document','Sec-Fetch-Mode': 'navigate','Sec-Fetch-Site': random.choice(['none', 'same-origin', 'cross-site']),'Sec-Fetch-User': '?1'}
    def layer_6_referer(self): return random.choice(_REFERERS)
    def layer_7_ip_chain(self):
        o = lambda: f'{_octet()}.{_octet()}.{_octet()}.{_octet()}'
        return {'X-Forwarded-For': ','.join(o() for _ in range(random.randint(1, 3))),'X-Real-IP': o(),'Forwarded': f'for={o()};proto=https','CF-Connecting-IP': o(),'True-Client-IP': o(),'X-Client-IP': o(),'X-Originating-IP': f'[{o()}]','X-Remote-IP': o(),'X-Remote-Addr': o(),'X-ProxyUser-Ip': o(),'Via': f'1.1 {random.choice(["google", "cloudflare", "akamai"])}'}
    def layer_8_accept(self):
        return {'Accept': random.choice(_ACCEPTS),'Accept-Language': random.choice(_ACCEPT_LANGS),'Accept-Encoding': 'gzip, deflate, br','Accept-Charset': 'utf-8, iso-8859-1;q=0.5, *;q=0.1','Cache-Control': random.choice(['no-cache', 'max-age=0', 'no-store']),'Pragma': 'no-cache','DNT': random.choice(['1', '1', '0']),'Upgrade-Insecure-Requests': '1','Connection': 'keep-alive','Priority': 'u=0, i'}
    def layer_9_cookie(self, session): return session
    def build(self, referer, imp):
        h = {'User-Agent': self.layer_3_ua(imp), 'Referer': referer or self.layer_6_referer()}
        h.update(self.layer_4_client_hints()); h.update(self.layer_5_sec_fetch())
        h.update(self.layer_7_ip_chain()); h.update(self.layer_8_accept())
        return h

# ============================================================
# Session Pool (same as previous version)
# ============================================================
class SessionPool:
    __slots__ = ('size', 'sessions', 'imps', 'hits', 'locks')
    def __init__(self, size):
        self.size = size; self.sessions = [None] * size; self.imps = [None] * size
        self.hits = [0] * size; self.locks = [asyncio.Lock() for _ in range(size)]
    async def start(self):
        for i in range(self.size):
            imp = _IMPERSONATIONS[i % len(_IMPERSONATIONS)]
            self.sessions[i] = self._make(imp); self.imps[i] = imp
    @staticmethod
    def _make(imp):
        try: return AsyncSession(impersonate=imp, timeout=CONFIG['request_timeout'])
        except Exception: return AsyncSession(impersonate='chrome136', timeout=CONFIG['request_timeout'])
    async def stop(self):
        for s in self.sessions:
            if s is not None:
                try: await s.close()
                except Exception: pass
    def pick(self): return random.randrange(self.size)
    def get(self, idx): return self.sessions[idx]
    def imp_of(self, idx): return self.imps[idx]
    def bump(self, idx):
        self.hits[idx] += 1; return self.hits[idx]
    def needs_rotation(self, idx): return self.hits[idx] >= CONFIG['rotate_every_n']
    def force_rotate(self, idx): self.hits[idx] = CONFIG['rotate_every_n']
    async def rotate(self, idx):
        lock = self.locks[idx]
        if lock.locked(): return
        async with lock:
            if self.hits[idx] < CONFIG['rotate_every_n']: return
            old = self.sessions[idx]
            if old is not None:
                try: await old.close()
                except Exception: pass
            imp = random.choice(_IMPERSONATIONS)
            self.sessions[idx] = self._make(imp); self.imps[idx] = imp; self.hits[idx] = 0

# ============================================================
# URL Normalization (same as previous version)
# ============================================================
_BAD_SCHEMES = ('mailto:','tel:','sms:','callto:','skype:','whatsapp:','javascript:','data:','blob:','about:','chrome:','moz-extension:','ftp:','ftps:','sftp:','ssh:','file:','irc:','ircs:','news:','nntp:','gopher:','ws:','wss:','view-source:','intent:','market:','itms:','itms-apps:','bitcoin:','ethereum:')
_SKIP_EXT = re.compile(r'\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|heic|css|js|mjs|jsx|ts|tsx|map|woff2?|ttf|otf|eot|mp[34]|m4a|m4v|aac|ogg|oga|ogv|wav|flac|opus|avi|mkv|mov|webm|flv|wmv|mpg|mpeg|3gp|pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf|zip|tar|gz|tgz|bz2|xz|rar|7z|lz|lzma|zst|exe|dmg|msi|apk|deb|rpm|iso|img|bin|jar|class|xml|rss|atom|json|jsonl|ndjson|csv|tsv|yaml|yml|toml|ini|conf|cfg|psd|ai|eps|sketch|fig|xd|torrent|magnet|wasm)(\?|#|$)', re.IGNORECASE)
_SKIP_PATH_RE = re.compile(r'/(wp-admin|wp-login\.php|wp-json|xmlrpc\.php|login|logout|signin|sign-in|signup|sign-up|register|cart|checkout|basket|order|payment|admin|dashboard|account|profile|settings|cdn-cgi|wp-content/uploads|assets?|static|media|search|tag/|category/|author/)(/|$|\?)', re.IGNORECASE)
_TRACKING_KEYS = frozenset({'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id','utm_source_platform','utm_creative_format','utm_marketing_tactic','gclid','gclsrc','dclid','gbraid','wbraid','fbclid','fb_action_ids','fb_action_types','fb_source','fb_ref','mc_cid','mc_eid','mkt_tok','yclid','_openstat','msclkid','twclid','ttclid','li_fat_id','igshid','vero_id','vero_conv','wickedid','oly_anon_id','oly_enc_id','ref','ref_src','ref_url','referrer','source','src','_ga','_gl','sc_cid','sc_uid','spm','scm','from','from_source','share_source','share_medium'})

def _strip_tracking(url):
    if '?' not in url: return url
    try: p = urlparse(url)
    except Exception: return url
    if not p.query: return url
    all_q = parse_qsl(p.query, keep_blank_values=True)
    kept = [(k, v) for k, v in all_q if k.lower() not in _TRACKING_KEYS]
    if len(kept) == len(all_q): return url
    return p._replace(query=urlencode(kept, doseq=True)).geturl()

def normalize(url, base=''):
    if not url or not isinstance(url, str): return None
    url = url.strip()
    if not url or url[0] == '#': return None
    low = url[:24].lower()
    for s in _BAD_SCHEMES:
        if low.startswith(s): return None
    url = urldefrag(url)[0]
    if not url: return None
    if base:
        try: url = urljoin(base, url)
        except Exception: return None
    try: p = urlparse(url)
    except Exception: return None
    if p.scheme not in ('http', 'https'): return None
    if not p.netloc or '.' not in p.netloc: return None
    if _SKIP_EXT.search(p.path): return None
    if _SKIP_PATH_RE.search(p.path): return None
    return _strip_tracking(url)

# ============================================================
# [Refactor] Text Cleaning and Link Extraction Separated
# ============================================================

# DOM elements completely removed (including content)
_KILL_TAGS = (
    'script', 'style', 'code', 'pre', 'noscript', 'svg', 'canvas',
    'iframe', 'template', 'object', 'embed', 'applet', 'form',
    'input', 'button', 'select', 'textarea', 'option', 'map', 'area',
    'audio', 'video', 'source', 'track', 'dialog', 'menu', 'menuitem',
    'nav', 'footer', 'header', 'aside',  # 新增：移除导航/页脚/侧边栏
)

# 优先提取内容的主体选择器（selectolax 可用时）
_MAIN_CONTENT_SELECTORS = [
    'article', 'main', '[role="main"]', '.post-content', '.entry-content',
    '.article-content', '.content-body', '#content', '.post', '.entry',
    '.story-body', '.article-body',
]

_ws_re = re.compile(r'[^\S\n]+')
_nl_re = re.compile(r'\n{2,}')
_junk_re = re.compile(r'[^\x20-\x7E\n\t]')
_META_REFRESH_RE = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.IGNORECASE)

def _extract_links_lexbor(tree, base_url):
    """从 Lexbor 树中提取所有候选链接，优先 a[href]，补充 data-* 和 meta refresh。"""
    links = []
    seen = set()
    
    # 主要：a[href]
    for a in tree.css('a[href]'):
        href = a.attributes.get('href')
        if not href: continue
        n = normalize(href, base_url)
        if n and n not in seen:
            seen.add(n); links.append(n)
    
    # 补充：data-href / data-url / data-link（JS 延迟加载）
    if not links:
        for attr in ('data-href', 'data-url', 'data-link'):
            for el in tree.css(f'[{attr}]'):
                val = el.attributes.get(attr)
                if val:
                    n = normalize(val, base_url)
                    if n and n not in seen:
                        seen.add(n); links.append(n)
    
    # 补充：meta refresh 重定向
    for m in tree.css('meta[http-equiv="refresh"]'):
        content = m.attributes.get('content') or ''
        mr = _META_REFRESH_RE.search(content)
        if mr:
            n = normalize(mr.group(1), base_url)
            if n and n not in seen:
                seen.add(n); links.append(n)
    
    # 补充：link rel=next/prev/canonical
    for rel in ('next', 'prev', 'canonical'):
        for lk in tree.css(f'link[rel="{rel}"]'):
            href = lk.attributes.get('href')
            if href:
                n = normalize(href, base_url)
                if n and n not in seen:
                    seen.add(n); links.append(n)
    
    return links

def _clean_text_lexbor(tree):
    """从 Lexbor 树中提取干净正文。优先主内容区，否则回退到全文。"""
    # 尝试主内容选择器
    content_node = None
    for sel in _MAIN_CONTENT_SELECTORS:
        node = tree.css_first(sel)
        if node:
            content_node = node
            break
    
    # 确定文本来源：主内容区或全树
    source = content_node if content_node else tree
    
    # 移除破坏性标签
    for tag in source.css(','.join(_KILL_TAGS)):
        tag.decompose()
    
    # 提取文本
    text = source.text(separator='\n') or ''
    
    # 规范化
    text = _ws_re.sub(' ', text)
    text = _nl_re.sub('\n', text)
    text = _junk_re.sub('', text)
    return text.strip()

def _clean_text_lxml(doc):
    """lxml 回退路径的正文提取。"""
    # 尝试主内容选择器
    content = None
    for sel in _MAIN_CONTENT_SELECTORS:
        try:
            node = doc.cssselect(sel)
            if node:
                content = node[0]
                break
        except Exception:
            continue
    
    source = content if content else doc
    
    # 移除破坏性标签
    for tag in source.iter(*_KILL_TAGS):
        parent = tag.getparent()
        if parent is not None:
            parent.remove(tag)
    
    text = source.text_content()
    text = _ws_re.sub(' ', text)
    text = _nl_re.sub('\n', text)
    text = _junk_re.sub('', text)
    return text.strip()

def _parse_lexbor(raw, base_url):
    """Lexbor 路径：先提链接，再清洗正文。"""
    try:
        tree = LexborHTMLParser(raw)
    except Exception:
        return None, ()
    
    # 标题：title -> h1 -> og:title
    title = ''
    t = tree.css_first('title')
    if t: title = (t.text() or '').strip()
    if not title:
        h1 = tree.css_first('h1')
        if h1: title = (h1.text() or '').strip()[:200]
    if not title:
        og = tree.css_first('meta[property="og:title"]')
        if og: title = (og.attributes.get('content') or '')[:200]
    
    # 链接提取（在清洗前）
    links = _extract_links_lexbor(tree, base_url)
    
    # 文本清洗
    text = _clean_text_lexbor(tree)
    
    if not text:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)

def _parse_lxml(raw, base_url):
    """lxml 回退路径。"""
    try:
        doc = _lxml_html.document_fromstring(raw, base_url=base_url)
    except Exception:
        return None, ()
    
    # 标题
    title = ''
    t = doc.find('.//title')
    if t is not None and t.text: title = t.text.strip()
    if not title:
        for h in doc.iter('h1'):
            txt = h.text_content()
            if txt and txt.strip():
                title = txt.strip()[:200]; break
    
    # 链接提取
    links = []
    seen = set()
    for a in doc.iter('a'):
        href = a.get('href')
        if not href: continue
        n = normalize(href, base_url)
        if n and n not in seen:
            seen.add(n); links.append(n)
    
    # 文本清洗
    text = _clean_text_lxml(doc)
    
    if not text:
        return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)

def _parse_and_extract(raw, base_url):
    """入口：根据可用库选择解析器。"""
    if _HAS_LEXBOR:
        return _parse_lexbor(raw, base_url)
    return _parse_lxml(raw, base_url)

# ============================================================
# Output Prefill (same as previous version)
# ============================================================
def load_existing_urls():
    seen = set()
    if not OUTPUT_FILE.exists(): return seen
    try:
        with OUTPUT_FILE.open('r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try: obj = json.loads(line)
                except Exception: continue
                u = obj.get('url')
                if isinstance(u, str): seen.add(u)
    except Exception: pass
    return seen

def _parse_retry_after(resp):
    ra = resp.headers.get('retry-after') or resp.headers.get('Retry-After')
    if not ra: return 0.0
    try: return float(ra)
    except ValueError:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(ra)
            return max(0.0, dt.timestamp() - time.time())
        except Exception: return 0.0

# ============================================================
# Crawler (main logic, mostly same, with write fix)
# ============================================================
class Crawler:
    __slots__ = ('bloom','queue','host_inflight','pool','spoof','gate','rate_limiter','written','fetched','dropped','zero_link_pages','errors','stop_flag','out_fh','stats_task','start_time','last_report_time','last_report_written','seed','write_lock')
    
    def __init__(self):
        self.bloom = BloomFilter(CONFIG['bloom_expected'], CONFIG['bloom_error'])
        self.queue = deque(); self.host_inflight = {}; self.pool = None
        self.spoof = SpoofEngine()
        self.gate = AdaptiveGate(CONFIG['initial_concurrency'], CONFIG['min_concurrency'], CONFIG['max_concurrency'])
        self.rate_limiter = RateLimitTracker()
        self.written = 0; self.fetched = 0; self.dropped = 0; self.zero_link_pages = 0; self.errors = 0
        self.stop_flag = False; self.out_fh = None; self.stats_task = None
        self.start_time = time.time(); self.last_report_time = self.start_time; self.last_report_written = 0
        self.seed = ''; self.write_lock = asyncio.Lock()
    
    async def run(self, seed):
        self.seed = seed
        for u in load_existing_urls(): self.bloom.add(u)
        self.bloom.add(seed); self.queue.append((seed, '', 0))
        self.pool = SessionPool(CONFIG['session_pool_size']); await self.pool.start()
        
        # 修复：文本模式打开，json.dumps 返回 str 直接写入
        self.out_fh = OUTPUT_FILE.open('a', encoding='utf-8')
        
        engine = 'lexbor' if _HAS_LEXBOR else 'lxml'
        print(f'[Nexus] seed:     {seed}', file=sys.stderr)
        print(f'[Nexus] output:   {OUTPUT_FILE.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:   {engine}  parsers={CONFIG["parser_workers"]}', file=sys.stderr)
        print(f'[Nexus] adaptive: {CONFIG["min_concurrency"]}-{CONFIG["max_concurrency"]} (start {CONFIG["initial_concurrency"]})', file=sys.stderr)
        print(f'[Nexus] sessions: {CONFIG["session_pool_size"]}  rotate@{CONFIG["rotate_every_n"]}', file=sys.stderr)
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
            try: await self.stats_task
            except Exception: pass
            try: self.out_fh.flush(); self.out_fh.close()
            except Exception: pass
            await self.pool.stop(); PARSER_POOL.shutdown(wait=False)
            self._final_report()
    
    async def _stats_loop(self):
        while not self.stop_flag:
            await asyncio.sleep(CONFIG['stats_interval'])
            now = time.time(); dt = now - self.last_report_time
            dw = self.written - self.last_report_written
            rate = dw / dt if dt > 0 else 0.0
            avg = self.written / (now - self.start_time) if now > self.start_time else 0.0
            print(f'[stats] rate={rate:7.1f}/s  avg={avg:7.1f}/s  written={self.written}  fetched={self.fetched}  dropped={self.dropped}  errors={self.errors}  queue={len(self.queue)}  hosts={len(self.host_inflight)}  conc={self.gate.current}  zerolink={self.zero_link_pages}', file=sys.stderr)
            self.last_report_time = now; self.last_report_written = self.written
    
    def _final_report(self):
        elapsed = time.time() - self.start_time
        avg = self.written / elapsed if elapsed > 0 else 0
        print(f'\n[Nexus] stopped. written={self.written}  fetched={self.fetched}  dropped={self.dropped}  errors={self.errors}  zerolink={self.zero_link_pages}  elapsed={elapsed:.1f}s  avg={avg:.1f}/s', file=sys.stderr)
    
    async def _worker(self, wid):
        idle_rounds = 0
        while not self.stop_flag:
            batch = []
            for _ in range(CONFIG['batch_pop']):
                try: batch.append(self.queue.popleft())
                except IndexError: break
            if not batch:
                idle_rounds += 1
                if not self.host_inflight:
                    await asyncio.sleep(CONFIG['idle_deep_sleep'] if idle_rounds > 100 else CONFIG['idle_sleep'])
                else: await asyncio.sleep(CONFIG['idle_sleep'])
                continue
            idle_rounds = 0
            tasks = []
            for url, referer, depth in batch:
                host = urlparse(url).netloc
                if not host: continue
                inflight = self.host_inflight.get(host, 0)
                if inflight >= 6:
                    self.queue.append((url, referer, depth)); continue
                self.host_inflight[host] = inflight + 1
                tasks.append((url, referer, depth, host))
            if not tasks:
                await asyncio.sleep(0.005); continue
            results = await asyncio.gather(*(self._process(u, r, d, h) for u, r, d, h in tasks), return_exceptions=True)
            for (url, referer, depth, host), res in zip(tasks, results):
                left = self.host_inflight.get(host, 1) - 1
                if left <= 0: self.host_inflight.pop(host, None)
                else: self.host_inflight[host] = left
                if isinstance(res, Exception):
                    self.errors += 1
                    if self.errors <= 20: print(f'[w{wid}] {url[:90]}: {type(res).__name__}: {res}', file=sys.stderr)
    
    async def _process(self, url, referer, depth, host):
        self.fetched += 1
        await self.rate_limiter.wait(host)
        await self.gate.acquire()
        status = 0; retry_after = 0.0
        try:
            idx = self.pool.pick(); sess = self.pool.get(idx)
            if sess is None:
                self.pool.force_rotate(idx); asyncio.create_task(self.pool.rotate(idx))
                self.dropped += 1; return
            imp = self.pool.imp_of(idx); headers = self.spoof.build(referer, imp)
            try:
                resp = await sess.get(url, headers=headers, timeout=CONFIG['request_timeout'], allow_redirects=True, max_redirects=CONFIG['max_redirects'])
                status = resp.status_code
            except Exception:
                status = 0; self.pool.bump(idx)
                if self.pool.needs_rotation(idx): asyncio.create_task(self.pool.rotate(idx))
                self.dropped += 1; return
            self.pool.bump(idx)
            if self.pool.needs_rotation(idx): asyncio.create_task(self.pool.rotate(idx))
            if status != 200:
                if status in (403, 429, 502, 503, 520, 521, 522, 523, 524):
                    self.pool.force_rotate(idx); asyncio.create_task(self.pool.rotate(idx))
                if status in (429, 503): retry_after = _parse_retry_after(resp)
                self.dropped += 1; return
            ctype = (resp.headers.get('content-type') or '').lower()
            if 'text/html' not in ctype and 'application/xhtml' not in ctype:
                self.dropped += 1; return
            try: raw = resp.text
            except Exception:
                try: raw = resp.content.decode('utf-8', 'ignore')
                except Exception: self.dropped += 1; return
            if not raw: self.dropped += 1; return
            if len(raw) > CONFIG['max_html_bytes']: raw = raw[:CONFIG['max_html_bytes']]
            loop = asyncio.get_running_loop()
            try: cleaned, links = await loop.run_in_executor(PARSER_POOL, _parse_and_extract, raw, url)
            except Exception: self.dropped += 1; return
            
            if cleaned is not None:
                title, text = cleaned
                record = {'url': url, 'title': title, 'text': text}
                # 修复：文本模式写入，无需 encode
                line = json.dumps(record, ensure_ascii=False, separators=(',', ':')) + '\n'
                async with self.write_lock:
                    self.out_fh.write(line)
                    self.written += 1
                    if self.written % CONFIG['write_buffer_size'] == 0:
                        self.out_fh.flush()
            
            if not links: self.zero_link_pages += 1
            for link in links:
                if link not in self.bloom:
                    self.bloom.add(link)
                    if len(self.queue) < CONFIG['queue_high_water']:
                        self.queue.append((link, url, depth + 1))
        finally:
            await self.gate.release(status or 599)
            await self.rate_limiter.record(host, status, retry_after)

# ============================================================
# Entry
# ============================================================
async def main():
    try: seed = input('url : ').strip()
    except (EOFError, KeyboardInterrupt): return
    if not seed: return
    seed_n = normalize(seed)
    if not seed_n:
        print(f'[!] invalid seed url: {seed}', file=sys.stderr); return
    crawler = Crawler(); loop = asyncio.get_running_loop(); stop_event = asyncio.Event()
    def _sig(*_):
        crawler.stop_flag = True; stop_event.set()
    try:
        loop.add_signal_handler(signal.SIGINT, _sig)
        loop.add_signal_handler(signal.SIGTERM, _sig)
    except (NotImplementedError, RuntimeError): pass
    run_task = asyncio.create_task(crawler.run(seed_n))
    stop_wait = asyncio.create_task(stop_event.wait())
    await asyncio.wait({run_task, stop_wait}, return_when=asyncio.FIRST_COMPLETED)
    if stop_event.is_set():
        for t in asyncio.all_tasks():
            if t is not asyncio.current_task(): t.cancel()
        try: await run_task
        except (asyncio.CancelledError, Exception): pass

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: pass