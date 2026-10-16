import asyncio, hashlib, ipaddress, json, os, re, signal, socket, sys, time, random, math
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode

C = SimpleNamespace(
    max_hosts=512, wph_min=2, wph_max=32, max_conc=1024, pool=96,
    rot_min=400, rot_max=800, timeout=12, redir_max=5,
    html_cap=500_000, xml_cap=2_000_000, bin_cap=2_000_000, img_cap=2_000_000,
    text_cap=200_000, links_cap=20_000, stats=3.0, out='output.json',
    bloom_n=50_000_000, bloom_e=0.001,
    pw=max(8, (os.cpu_count() or 4) * 2), ow=4, oc=8,
    ocr=True, ocr_min=100, ocr_max=400_000, ocr_pdf=10, pdf_pages=20,
    host_idle=5.0, dispatch=0.2, bl_403=5, bl_chal=3, imp_retry=2,
    drop_log=15, min_text=20, smap_n=50, smap_p=5000,
    dedup_window=10_000, dedup_thresh=3,
    cond_cache='cond_cache.json', cond_max=500_000, cond_flush=30.0,
    robots_ua='Nexus', robots_ttl=3600,
    ssrf_cache_max=100_000,
    wqs_accept=0.62, wqs_min_text=200, wqs_good_text=2000,
    wqs_min_stopratio=0.15, wqs_min_punct=0.005,
    wqs_max_qs=5, wqs_max_path=8, wqs_gpmk=5.0,
    wqs_langs=('en',), wqs_block=(),
    wqs_toml='wqs.toml',
)
OUT = Path(C.out)
PP = ThreadPoolExecutor(max_workers=C.pw)
OP = ThreadPoolExecutor(max_workers=C.ow)
RETRY = (429, 503, 502, 520, 521, 522, 523, 524)
ROTATE = (403,) + RETRY
_L = {}

def _session():
    if 'S' not in _L:
        from curl_cffi.requests import AsyncSession
        _L['S'] = AsyncSession
    return _L['S']

def _parser():
    if 'pm' in _L: return _L['pm']
    try:
        from selectolax.lexbor import LexborHTMLParser as P
        _L['P'], _L['pm'] = P, 'lexbor'
    except ImportError:
        try:
            from lxml import html as H
            _L['P'], _L['pm'] = H, 'lxml'
        except ImportError:
            _L['P'], _L['pm'] = None, 'none'
    return _L['pm']

def _pdf():
    if 'pm2' in _L: return _L['pm2']
    for m in ('pymupdf', 'fitz'):
        try:
            _L['PDF'], _L['pm2'] = __import__(m), 'pymupdf'
            return 'pymupdf'
        except ImportError: pass
    for m in ('pypdf', 'PyPDF2'):
        try:
            _L['PDF'], _L['pm2'] = __import__(m), 'pypdf'
            return 'pypdf'
        except ImportError: pass
    _L['PDF'], _L['pm2'] = None, 'none'
    return 'none'

def _ocr():
    if 'o' in _L: return _L['o']
    try:
        import pytesseract as t
        from PIL import Image as I
        _L['o'], _L['pil'] = t, I
    except ImportError:
        _L['o'], _L['pil'] = None, None
    return _L['o']

def _imps():
    try:
        from curl_cffi.const import BrowserType
        ks = sorted({b.value for b in BrowserType if isinstance(b.value, str)})
        if ks: return ks
    except: pass
    return ['chrome136','chrome131','chrome124','chrome120','chrome116','chrome110','chrome107',
        'chrome104','chrome101','chrome100','chrome99','edge101','edge99','safari170',
        'safari155','safari153','firefox133','firefox128','firefox120']

def _dh(b):
    if isinstance(b, str): b = b.encode('utf-8', 'ignore')
    return int.from_bytes(hashlib.blake2b(b, digest_size=8).digest(), 'big')

class Bloom:
    def __init__(s, n, e):
        nb = 1 << max(6, (int(-(n * math.log(e)) / (math.log(2) ** 2)) - 1).bit_length())
        s.m, s.b, s.k = nb - 1, bytearray(nb >> 3), max(1, int((nb / n) * math.log(2)))
    def _h(s, b):
        h1 = _dh(b)
        h2 = _dh(b[:64] + b'\x9e' + b[-64:]) if len(b) > 128 else _dh(b[::-1] + b'\x9e')
        return h1, h2 or 0x9E3779B97F4A7C15
    def add(s, t):
        if isinstance(t, str): t = t.encode('utf-8', 'ignore')
        h1, h2 = s._h(t)
        for i in range(s.k):
            x = (h1 + i * h2) & s.m
            s.b[x >> 3] |= 1 << (x & 7)
    def __contains__(s, t):
        if isinstance(t, str): t = t.encode('utf-8', 'ignore')
        h1, h2 = s._h(t)
        for i in range(s.k):
            x = (h1 + i * h2) & s.m
            if not s.b[x >> 3] & (1 << (x & 7)): return False
        return True

class Rate:
    def __init__(s):
        s.d = {}; s.lk = {}
    def _st(s, h): return s.d.setdefault(h, dict(d=0.0, f=0, t=0.0, c403=0, bl=False))
    def _l(s, h): return s.lk.setdefault(h, asyncio.Lock())
    def bl(s, h):
        st = s.d.get(h)
        return bool(st and st['bl'])
    async def wait(s, h):
        st = s.d.get(h)
        if not st or st['d'] <= 0: return
        async with s._l(h):
            gap = st['d'] - (time.monotonic() - st['t'])
            if gap > 0: await asyncio.sleep(gap)
    async def rec(s, h, status, ra=0.0):
        st = s._st(h)
        async with s._l(h):
            st['t'] = time.monotonic()
            if ra > 0: st['d'] = max(st['d'], min(ra, 60.0))
            if status in RETRY:
                st['f'] += 1
                st['d'] = min(60.0, max(0.3, st['d'] * 2.0) * random.uniform(0.8, 1.2))
            elif status == 403:
                st['f'] += 1; st['c403'] += 1
                if st['c403'] >= C.bl_403: st['bl'] = True
            elif status == 401:
                st['f'] += 1; st['d'] = min(30.0, max(0.5, st['d'] * 1.5))
            elif status == 200:
                st['f'] = 0; st['d'] = max(0.0, st['d'] * 0.5); st['c403'] = 0

_LANGS = ('en-US,en;q=0.9','en-US,en;q=0.9,fr;q=0.8','en-GB,en;q=0.9,en-US;q=0.8','en-US,en;q=0.8,de;q=0.6')
_ACCS = ('text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.5',)
_REFS = ('https://www.google.com/','https://duckduckgo.com/','https://www.bing.com/','https://search.brave.com/')

def build_headers(ref, host):
    o = random.choice
    ss = ('same-origin' if _host(ref) == host else 'cross-site') if ref else 'none'
    return {'Accept': o(_ACCS), 'Accept-Language': o(_LANGS), 'Accept-Encoding': 'gzip, deflate, br',
        'Cache-Control': 'no-cache', 'Pragma': 'no-cache', 'DNT': '1',
        'Upgrade-Insecure-Requests': '1', 'Connection': 'keep-alive',
        'Referer': ref or o(_REFS), 'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': ss, 'Sec-Fetch-User': '?1'}

class Pool:
    def __init__(s, n, keys):
        s.n, s.k = n, keys
        s.ss, s.h, s.th = [None] * n, [0] * n, [0] * n
        s.lk = [asyncio.Lock() for _ in range(n)]
    async def start(s):
        for i in range(s.n):
            s.ss[i] = s._mk()
            s.th[i] = random.randint(C.rot_min, C.rot_max)
    def _mk(s):
        Sc = _session()
        for _ in range(6):
            try: return Sc(impersonate=random.choice(s.k), timeout=C.timeout)
            except: continue
    async def stop(s):
        await asyncio.gather(*(x.close() for x in s.ss if x), return_exceptions=True)
    def pick(s): return random.randrange(s.n)
    def get(s, i): return s.ss[i]
    def bump(s, i): s.h[i] += 1
    def needs(s, i): return s.h[i] >= s.th[i]
    def force(s, i): s.h[i] = s.th[i]
    async def rotate(s, i):
        async with s.lk[i]:
            if s.h[i] < s.th[i]: return
            if s.ss[i] is not None:
                try: await s.ss[i].close()
                except: pass
            s.ss[i] = s._mk(); s.h[i] = 0
            s.th[i] = random.randint(C.rot_min, C.rot_max)

_BAD = ('mailto:','tel:','sms:','callto:','skype:','whatsapp:','javascript:','data:','blob:',
    'about:','chrome:','moz-extension:','ftp:','ftps:','sftp:','ssh:','file:','irc:','ircs:',
    'news:','nntp:','gopher:','ws:','wss:','view-source:','intent:','market:','itms:','itms-apps:',
    'bitcoin:','ethereum:')
_SKIP_HOSTS = re.compile(r'^(fonts\.googleapis\.com|fonts\.gstatic\.com|www\.gstatic\.com|ajax\.googleapis\.com|'
    r'maps\.googleapis\.com|cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|fastly\.jsdelivr\.net|unpkg\.com|esm\.sh|'
    r'cdn\.skypack\.dev|googletagmanager\.com|www\.googletagmanager\.com|google-analytics\.com|'
    r'www\.google-analytics\.com|ssl\.google-analytics\.com|doubleclick\.net|static\.doubleclick\.net|'
    r'googlesyndication\.com|connect\.facebook\.net|graph\.facebook\.com|platform\.twitter\.com|'
    r'syndication\.twitter\.com|analytics\.tiktok\.com|cdn\.segment\.com|api\.segment\.io|static\.hotjar\.com|'
    r'script\.hotjar\.com|bat\.bing\.com|clarity\.ms|cdn\.onesignal\.com|fonts\.bunny\.net|cdn\.tailwindcss\.com)$', re.I)
_SKIP_EXT = re.compile(r'\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|heic|css|js|mjs|jsx|ts|tsx|map|woff2?|ttf|otf|'
    r'eot|mp[34]|m4a|m4v|aac|ogg|oga|ogv|wav|flac|opus|avi|mkv|mov|webm|flv|wmv|mpg|mpeg|3gp|docx?|xlsx?|pptx?|'
    r'odt|ods|odp|rtf|zip|tar|gz|tgz|bz2|xz|rar|7z|lz|lzma|zst|exe|dmg|msi|apk|deb|rpm|iso|img|bin|jar|class|'
    r'rss|atom|jsonl|ndjson|csv|tsv|yaml|yml|toml|ini|conf|cfg|psd|ai|eps|sketch|fig|xd|torrent|magnet|wasm|'
    r'webmanifest)(\?|#|$)', re.I)
_SKIP_PATH = re.compile(r'/(wp-admin|wp-login\.php|wp-json|xmlrpc\.php|cart|checkout|basket|order|payment|admin|'
    r'dashboard|account|settings|cdn-cgi|wp-content/uploads|assets?|static)(/|$|\?)', re.I)
_TRACK = frozenset({'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id',
    'utm_source_platform','utm_creative_format','utm_marketing_tactic','gclid','gclsrc','dclid','gbraid',
    'wbraid','fbclid','fb_action_ids','fb_action_types','fb_source','fb_ref','mc_cid','mc_eid','mkt_tok',
    'yclid','_openstat','msclkid','twclid','ttclid','li_fat_id','igshid','vero_id','vero_conv','wickedid',
    'oly_anon_id','oly_enc_id','ref','ref_src','ref_url','referrer','source','src','_ga','_gl','sc_cid',
    'sc_uid','spm','scm','from','from_source','share_source','share_medium'})
_THINTS = ('utm_','fbclid','gclid','ref=','source=','mc_','_ga','spm','scm')

def _strip_track(url):
    if '?' not in url: return url
    low = url.lower()
    if not any(h in low for h in _THINTS): return url
    p = urlparse(url)
    if not p.query: return url
    allq = parse_qsl(p.query, keep_blank_values=True)
    kept = [(k, v) for k, v in allq if k.lower() not in _TRACK]
    if len(kept) == len(allq): return url
    return p._replace(query=urlencode(kept, doseq=True)).geturl()

def normalize(url, base=''):
    if not url or not isinstance(url, str): return None
    url = url.strip()
    if not url or url[0] == '#' or url.lower().startswith(_BAD): return None
    if '#' in url:
        url = urldefrag(url)[0]
        if not url: return None
    if base:
        try: url = urljoin(base, url)
        except: return None
    try: p = urlparse(url)
    except: return None
    if p.scheme not in ('http', 'https'): return None
    nl = p.netloc
    if not nl or '.' not in nl or len(nl) > 253 or _SKIP_HOSTS.match(nl): return None
    pc = p.path if len(p.path) <= 100 else p.path[:60] + p.path[-40:]
    if '.' in pc and _SKIP_EXT.search(pc): return None
    if _SKIP_PATH.search(p.path): return None
    return _strip_track(url)

def _host(url):
    i = url.find('://')
    if i < 0: return ''
    i += 3
    j = url.find('/', i)
    return (url[i:] if j < 0 else url[i:j]).lower()

def _parse_robots(text, ua='*'):
    groups, delays = {}, {}
    cur = []
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line or ':' not in line: continue
        k, _, v = line.partition(':')
        k = k.strip().lower(); v = v.strip()
        if k == 'user-agent': cur = [v.lower()]
        elif k == 'disallow' and cur:
            for a in cur: groups.setdefault(a, []).append((False, v))
        elif k == 'allow' and cur:
            for a in cur: groups.setdefault(a, []).append((True, v))
        elif k == 'crawl-delay' and cur:
            try:
                d = float(v)
                for a in cur: delays[a] = d
            except: pass
    ua_l = ua.lower()
    best, blen = None, 0
    for tok, rl in groups.items():
        if tok == '*' or tok not in ua_l: continue
        if len(tok) > blen: best, blen = rl, len(tok)
    if best is None: best = groups.get('*', [])
    return best, delays.get(ua_l, delays.get('*'))

def _robots_ok(rules, path):
    if not rules: return True
    path = path or '/'
    blen, ok = -1, True
    for a, pre in rules:
        if not pre: continue
        if path.startswith(pre):
            pl = len(pre)
            if pl > blen or (pl == blen and a): blen, ok = pl, a
    return ok

class Sev(IntEnum):
    PASS = 0; WARN = 1; REJECT = 2; VETO = 3

@dataclass
class Q:
    accept: bool; score: float; reason: str = ''

class Stub:
    __slots__ = ('url', 'title', 'text', 'ctype', 'headers')
    def __init__(s, url='', title='', text='', ctype='html', headers=None):
        s.url, s.title, s.text, s.ctype = url, title, text, ctype
        s.headers = headers or {}

_URLBAD = re.compile(r'/(login|signin|signup|register|logout|cart|checkout|account|admin|'
    r'wp-admin|wp-login|feed|rss|print|amp|share)(/|$|\?)', re.I)
_URLPAG = re.compile(r'[?&](page|p|pg|paged|offset|start)=\d+', re.I)
_PUNCT = re.compile(r'[.,;:!?]')
_STOP = frozenset('the a an and or but if then of to in on at for with by is are was were be been '
    'this that these those it its as from not have has had do does did will would can could'.split())
_GR = (
    (re.compile(r'\b(\w+)\s+\1\b', re.I), 'repeat-word'),
    (re.compile(r'\s[,;:!?]'), 'space-before-punct'),
    (re.compile(r'[.,;:!?][A-Za-z]'), 'missing-space'),
)

def _r_urlshape(p, c):
    if _URLBAD.search(p.url): return 0.0, Sev.VETO, 'auth/cart/feed'
    return 1.0, Sev.PASS, ''

def _r_query(p, c):
    q = parse_qsl(urlparse(p.url).query)
    if len(q) > c.wqs_max_qs: return 0.3, Sev.WARN, f'{len(q)}p'
    if _URLPAG.search(p.url): return 0.5, Sev.WARN, 'pag'
    return 1.0, Sev.PASS, ''

def _r_depth(p, c):
    n = len([s for s in urlparse(p.url).path.split('/') if s])
    if n > c.wqs_max_path: return 0.3, Sev.WARN, f'{n}s'
    return 1.0, Sev.PASS, ''

def _r_block(p, c):
    for pat in c.wqs_block:
        if re.search(pat, p.url, re.I): return 0.0, Sev.VETO, pat
    return 1.0, Sev.PASS, ''

def _r_ctype(p, c):
    if p.ctype not in ('html', 'xml'): return 0.0, Sev.VETO, p.ctype
    return 1.0, Sev.PASS, ''

def _r_minlen(p, c):
    n = len(p.text)
    if n < c.wqs_min_text: return 0.0, Sev.VETO, str(n)
    return min(1.0, n / c.wqs_good_text), Sev.PASS, ''

def _r_script(p, c):
    if not p.text: return 1.0, Sev.PASS, ''
    latin = sum(1 for ch in p.text if 'a' <= ch.lower() <= 'z')
    non = sum(1 for ch in p.text if ch.isalpha() and not ('a' <= ch.lower() <= 'z'))
    tot = latin + non
    if tot < 50: return 1.0, Sev.PASS, ''
    r = non / tot
    if 'en' in c.wqs_langs and r > 0.2: return 0.1, Sev.REJECT, f'non-latin-{r:.2f}'
    return 1.0, Sev.PASS, ''

def _r_stop(p, c):
    w = p.text.lower().split()
    if not w: return 0.0, Sev.VETO, 'no-words'
    r = sum(1 for x in w if x in _STOP) / len(w)
    if r < c.wqs_min_stopratio: return r / c.wqs_min_stopratio, Sev.REJECT, f'{r:.2f}'
    return min(1.0, r / 0.35), Sev.PASS, ''

def _r_punct(p, c):
    if not p.text: return 0.0, Sev.REJECT, 'empty'
    d = len(_PUNCT.findall(p.text)) / len(p.text)
    if d < c.wqs_min_punct: return d / c.wqs_min_punct, Sev.REJECT, f'{d:.4f}'
    return min(1.0, d / 0.02), Sev.PASS, ''

def _r_sent(p, c):
    s = [x.strip() for x in re.split(r'[.!?]+\s', p.text) if x.strip()]
    if not s: return 0.0, Sev.VETO, 'no-sentences'
    avg = sum(len(x) for x in s) / len(s)
    if avg < 25: return 0.3, Sev.WARN, f'avg{avg:.0f}'
    return min(1.0, avg / 100), Sev.PASS, ''

def _r_gram(p, c):
    hits = sum(len(rx.findall(p.text)) for rx, _ in _GR)
    pk = hits / max(1, len(p.text) / 1000)
    if pk > c.wqs_gpmk: return 0.2, Sev.REJECT, f'{hits}h'
    if pk > 2: return 0.5, Sev.WARN, f'{hits}h'
    return max(0.0, 1.0 - pk / c.wqs_gpmk), Sev.PASS, ''

def _r_title(p, c):
    if not p.title or p.title == '[untitled]': return 0.3, Sev.WARN, 'missing'
    if len(p.title) < 5: return 0.4, Sev.WARN, 'short'
    return 1.0, Sev.PASS, ''

def _r_rep(p, c):
    lines = [l.strip() for l in p.text.split('\n') if l.strip()]
    if len(lines) < 20: return 1.0, Sev.PASS, ''
    top = Counter(lines).most_common(1)[0][1]
    r = top / len(lines)
    if r > 0.3: return 0.2, Sev.REJECT, f'{r:.2f}'
    if r > 0.15: return 0.6, Sev.WARN, f'{r:.2f}'
    return 1.0, Sev.PASS, ''

def _r_read(p, c):
    words = p.text.split()
    if len(words) < 50: return 1.0, Sev.PASS, ''
    sents = max(1, len(re.findall(r'[.!?]', p.text)))
    syl = sum(max(1, len(re.findall(r'[aeiouy]+', w.lower()))) for w in words)
    fre = 206.835 - 1.015 * (len(words) / sents) - 84.6 * (syl / len(words))
    if fre < 10: return 0.4, Sev.WARN, f'fre{fre:.0f}'
    return min(1.0, (fre - 10) / 50), Sev.PASS, ''

_RULES = (
    ('url_shape', 2.5, 0, _r_urlshape),
    ('query_noise', 1.0, 0, _r_query),
    ('path_depth', 0.5, 0, _r_depth),
    ('blocklist', 3.0, 0, _r_block),
    ('content_type', 5.0, 1, _r_ctype),
    ('min_length', 3.0, 1, _r_minlen),
    ('script', 3.0, 1, _r_script),
    ('stopwords', 1.5, 1, _r_stop),
    ('punctuation', 1.0, 1, _r_punct),
    ('sentences', 1.0, 1, _r_sent),
    ('grammar', 1.5, 1, _r_gram),
    ('title', 0.8, 1, _r_title),
    ('repeated', 1.2, 1, _r_rep),
    ('readability', 0.8, 1, _r_read),
)

def _load_wqs_toml(path):
    try:
        import tomllib
    except ImportError:
        try: import tomli as tomllib
        except ImportError: return ()
    p = Path(path)
    if not p.exists(): return ()
    try:
        with p.open('rb') as f: data = tomllib.load(f)
    except: return ()
    out = []
    for r in data.get('rule', []):
        try:
            name = r['name']; wt = float(r.get('weight', 1.0)); tier = int(r.get('tier', 1))
            act = r.get('action', 'warn'); pat = r.get('pattern', '')
            rx = re.compile(pat, re.I)
            sev = {'pass': Sev.PASS, 'warn': Sev.WARN, 'reject': Sev.REJECT, 'veto': Sev.VETO}[act]
            def fn(p, c, rx=rx, sev=sev, name=name, tier=tier):
                if rx.search(p.url if tier == 0 else p.text):
                    sc = 0.0 if sev >= Sev.REJECT else 0.5
                    return sc, sev, f'toml:{name}'
                return 1.0, Sev.PASS, ''
            out.append((name, wt, tier, fn))
        except Exception: continue
    return tuple(out)

_WQS_ALL = _RULES + _load_wqs_toml(C.wqs_toml)

def wqs(p, c=None, max_tier=1):
    c = c or C
    num = den = 0.0; veto = None; rej = None
    for name, w, tier, fn in _WQS_ALL:
        if tier > max_tier: continue
        try: sc, sev, msg = fn(p, c)
        except Exception as e: sc, sev, msg = 1.0, Sev.WARN, f'err:{type(e).__name__}'
        num += sc * w; den += w
        if sev is Sev.VETO and veto is None: veto = f'{name}:{msg}'
        elif sev is Sev.REJECT and (rej is None or sc < rej[0]): rej = (sc, f'{name}:{msg}')
    s = num / den if den else 0.0
    if veto: return Q(False, s, veto)
    if rej and rej[0] < 0.3: return Q(False, s, rej[1])
    return Q(s >= c.wqs_accept, s, '')

def simhash(text, bits=64):
    toks = re.findall(r'\w+', text.lower())
    if not toks: return 0
    v = [0] * bits
    for t in toks:
        h = _dh(t)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    out = 0
    for i in range(bits):
        if v[i] > 0: out |= 1 << i
    return out

def hamming(a, b): return bin(a ^ b).count('1')

class Dedup:
    def __init__(s):
        s.t = C.dedup_thresh
        s.h = deque(maxlen=C.dedup_window)
    def seen(s, text):
        if not text: return False
        h = simhash(text)
        for x in s.h:
            if hamming(h, x) <= s.t: return True
        s.h.append(h)
        return False

class Cond:
    def __init__(s):
        s.p = Path(C.cond_cache); s.m = C.cond_max
        s.d = {}; s.dirty = False
        if s.p.exists():
            try: s.d = json.loads(s.p.read_text())
            except: s.d = {}
    def get(s, url): return s.d.get(url)
    def set(s, url, etag, lm):
        if etag or lm:
            s.d[url] = [etag or '', lm or '']; s.dirty = True
    def flush(s):
        if not s.dirty: return
        if len(s.d) > s.m: s.d = dict(list(s.d.items())[-s.m:])
        try: s.p.write_text(json.dumps(s.d)); s.dirty = False
        except: pass

_KILL_TAGS = ('script','style','noscript','svg','canvas','iframe','template','object','embed','applet','form',
    'input','button','select','textarea','option','map','area','audio','video','source','track','dialog','menu',
    'menuitem','nav','footer','header','aside')
_KILL_CSS = ','.join(_KILL_TAGS)
_MAIN_CSS = ('article','main','[role="main"]','#content','.post-content','.entry-content','.article-content',
    '.article-body','.story-body','.content-body','.md-content')
_MAIN_XP = ('//article','//main','//*[@role="main"]','//*[@id="content"]','//*[contains(@class, "post-content")]',
    '//*[contains(@class, "entry-content")]','//*[contains(@class, "article-content")]',
    '//*[contains(@class, "article-body")]','//*[contains(@class, "story-body")]',
    '//*[contains(@class, "content-body")]','//*[contains(@class, "md-content")]')
_WS = re.compile(r'[^\S\n]+')
_NL = re.compile(r'\n{3,}')
_META_REF = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.I)
_SCRIPT = re.compile(rb'<script\b[^>]*>(.*?)</script>', re.I | re.DOTALL)
_ABS = re.compile(rb'https?://[a-zA-Z0-9][a-zA-Z0-9\-._]{1,253}\.[a-zA-Z]{2,}'
    rb'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{0,1000}', re.I)
_JSONLD = re.compile(rb'<script[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.DOTALL)
_JSONLD_K = frozenset({'url','@id','sameAs','href','link','permalink','canonicalUrl'})
_XML_LOC = re.compile(rb'<(?:loc|link|url|id)[^>]*>\s*([^<\s]+)\s*</(?:loc|link|url|id)>', re.I)
_XML_HREF = re.compile(rb'<link[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.I)
_SMAP_LOC = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)

def _clean(t): return _NL.sub('\n\n', _WS.sub(' ', t)).strip()
def _lex(): return _L.get('pm') == 'lexbor'

def _first(doc, css, xp):
    if _lex(): return doc.css_first(css)
    r = doc.xpath(xp); return r[0] if r else None

def _text(n):
    if n is None: return ''
    if _lex():
        try: return n.text(separator='\n') or ''
        except: return ''
    return n.text_content() or ''

def _atr(n, k):
    if n is None: return None
    if _lex():
        a = n.attributes
        return a.get(k) if a else None
    return n.get(k)

def _tag(n):
    t = getattr(n, 'tag', None)
    return t if isinstance(t, str) else None

def _walk(doc):
    if _lex(): yield from doc.css('*')
    else: yield from doc.iter()

def _extract_links(doc, base, lim):
    out, seen = [], set()
    for n in _walk(doc):
        t = _tag(n)
        if not t: continue
        cands = []
        if t in ('a', 'area'): cands.append(_atr(n, 'href'))
        elif t in ('iframe', 'frame'): cands.append(_atr(n, 'src'))
        elif t == 'link': cands.append(_atr(n, 'href'))
        elif t == 'meta':
            he = (_atr(n, 'http-equiv') or '').lower()
            pr = (_atr(n, 'property') or _atr(n, 'name') or '').lower()
            ct = _atr(n, 'content') or ''
            if he == 'refresh':
                m = _META_REF.search(ct)
                if m: cands.append(m.group(1))
            elif pr in ('og:url', 'twitter:url'): cands.append(ct)
        for a in ('data-href','data-url','data-link','data-src','data-lazy-src','data-original'):
            v = _atr(n, a)
            if v: cands.append(v)
        for v in cands:
            if not v: continue
            n2 = normalize(v, base)
            if n2 and n2 not in seen:
                seen.add(n2); out.append(n2)
                if len(out) >= lim: return tuple(out)
    return tuple(out)

def _scan_scripts(rawb, base, lim):
    if b'<script' not in rawb: return ()
    out, seen = [], set()
    for m in _SCRIPT.finditer(rawb[:500_000]):
        for um in _ABS.finditer(m.group(1)):
            n = normalize(um.group(0).decode('ascii', 'ignore'), base)
            if n and n not in seen:
                seen.add(n); out.append(n)
                if len(out) >= lim: return tuple(out)
    return tuple(out)

def _scan_jsonld(rawb, base, lim):
    if b'ld+json' not in rawb: return ()
    out, seen = [], set()
    for m in _JSONLD.finditer(rawb):
        try: data = json.loads(m.group(1))
        except: continue
        stack, steps = [data], 0
        while stack and steps < 50_000:
            steps += 1
            it = stack.pop()
            if isinstance(it, dict):
                for k, v in it.items():
                    if isinstance(v, str) and k in _JSONLD_K and v.startswith(('http://','https://','/')):
                        n = normalize(v, base)
                        if n and n not in seen:
                            seen.add(n); out.append(n)
                            if len(out) >= lim: return tuple(out)
                    elif isinstance(v, (dict, list)): stack.append(v)
            elif isinstance(it, list): stack.extend(it[:500])
    return tuple(out)

def _meta_fb(doc):
    parts = []
    for c, x in (('meta[property="og:description"]', '//meta[@property="og:description"]/@content'),
                 ('meta[name="twitter:description"]', '//meta[@name="twitter:description"]/@content'),
                 ('meta[name="description"]', '//meta[@name="description"]/@content')):
        if _lex():
            n = doc.css_first(c)
            v = (_atr(n, 'content') or '').strip() if n else ''
        else:
            r = doc.xpath(x)
            v = (r[0] or '').strip() if r else ''
        if v and v not in parts: parts.append(v)
    return ' '.join(parts)

def _parse(raw, rawb, base):
    try: doc = _L['P'](raw) if _lex() else _L['P'].document_fromstring(raw, base_url=base)
    except: return None, ()
    title = _text(_first(doc, 'title', '//title')).strip()
    if not title: title = _text(_first(doc, 'h1', '//h1')).strip()[:200]
    if not title:
        og = _first(doc, 'meta[property="og:title"]', '//meta[@property="og:title"]')
        title = (_atr(og, 'content') or '')[:200]
    lim = C.links_cap
    links = list(_extract_links(doc, base, lim))
    for scan in (_scan_jsonld, _scan_scripts):
        if len(links) >= lim: break
        seen = set(links)
        for e in scan(rawb, base, lim - len(links)):
            if e not in seen: seen.add(e); links.append(e)
    content = None
    for c, x in zip(_MAIN_CSS, _MAIN_XP):
        content = _first(doc, c, x)
        if content: break
    src = content or doc
    if _lex():
        for t in src.css(_KILL_CSS): t.decompose()
    else:
        for t in list(src.iter(*_KILL_TAGS)):
            p = t.getparent()
            if p is not None: p.remove(t)
    text = _text(src)
    if len(text) > C.text_cap: text = text[:C.text_cap]
    text = _clean(text)
    if len(text) < C.min_text:
        meta = _meta_fb(doc)
        if len(meta) > len(text): text = meta
    if not text and not title: return None, tuple(links)
    return (title or '[untitled]', text), tuple(links)

def _parse_xml(rawb, base, lim):
    out, seen = [], set()
    for rgx in (_XML_LOC, _XML_HREF):
        for m in rgx.finditer(rawb):
            n = normalize(m.group(1).decode('utf-8', 'ignore'), base)
            if n and n not in seen:
                seen.add(n); out.append(n)
                if len(out) >= lim: return tuple(out)
    return tuple(out)

def _pdf_text(b):
    m = _pdf()
    if m == 'none': return None
    if m == 'pymupdf':
        try:
            doc = _L['PDF'].open(stream=b, filetype='pdf')
            try:
                title = (doc.metadata or {}).get('title', '') or ''
                n = min(len(doc), C.pdf_pages)
                parts = [doc[i].get_text() for i in range(n)]
                return title, '\n\n'.join(p for p in parts if p)
            finally:
                try: doc.close()
                except: pass
        except: return None
    try:
        from io import BytesIO
        r = _L['PDF'].PdfReader(BytesIO(b))
        title = getattr(r.metadata, 'title', '') if r.metadata else ''
        return title or '', '\n\n'.join(p.extract_text() or '' for p in r.pages[:C.pdf_pages])
    except: return None

def _ocr_img(img):
    if not _ocr(): return None
    try:
        if img.mode not in ('L', 'RGB'): img = img.convert('RGB')
        t = _L['o'].image_to_string(img)
        return t.strip() if t else None
    except: return None

def _pdf_ocr(b):
    if _pdf() != 'pymupdf' or not _ocr(): return None
    try:
        from io import BytesIO
        doc = _L['PDF'].open(stream=b, filetype='pdf')
        try:
            parts = []
            for i in range(min(len(doc), C.ocr_pdf)):
                try:
                    png = doc[i].get_pixmap(dpi=200).tobytes('png')
                    t = _ocr_img(_L['pil'].open(BytesIO(png)))
                    if t: parts.append(t)
                except: continue
            return '\n\n'.join(parts)
        finally:
            try: doc.close()
            except: pass
    except: return None

def _img_ocr(b):
    if not _ocr(): return None
    try:
        from io import BytesIO
        return _ocr_img(_L['pil'].open(BytesIO(b)))
    except: return None

def _binary(b, ct, url):
    if ct == 'pdf':
        r = _pdf_text(b)
        title, text = r if r else ('', '')
        if len(text) < C.ocr_min and C.ocr:
            o = _pdf_ocr(b)
            if o and len(o) > len(text): text = o
        if not title:
            tail = url.rsplit('/', 1)[-1] if '/' in url else url
            title = tail.rsplit('.', 1)[0][:200] if '.' in tail else tail[:200]
        text = _clean(text)
        if len(text) > C.ocr_max: text = text[:C.ocr_max]
        return (title or '[untitled]', text) if text else None
    if ct == 'image':
        if not C.ocr: return None
        text = _clean(_img_ocr(b) or '')
        if len(text) < 20: return None
        if len(text) > C.ocr_max: text = text[:C.ocr_max]
        return (text.split('\n', 1)[0].strip()[:200] or '[image]'), text
    return None

_CHAL = (b'<title>just a moment', b'<title>attention required', b'<title>checking your browser',
    b'<title>one more step', b'cf-chl-widget', b'__cf_chl_rt_tk', b'cf-please-wait')

def _is_chal(b, status, hdrs):
    if status not in (403, 429, 503): return False
    if 'challenge' in (hdrs.get('cf-mitigated') or '').lower(): return True
    if not b: return False
    head = b[:40000].lower()
    return any(m in head for m in _CHAL)

def _retry_after(resp):
    try: ra = resp.headers.get('retry-after')
    except: return 0.0
    if not ra: return 0.0
    try: return float(ra)
    except ValueError: pass
    try:
        from email.utils import parsedate_to_datetime
        return max(0.0, parsedate_to_datetime(ra).timestamp() - time.time())
    except: return 0.0

class Crawler:
    def __init__(s):
        s.bloom = Bloom(C.bloom_n, C.bloom_e)
        s.hosts = {}; s.pool = None; s.rate = Rate()
        s.sem = None
        s.written = s.fetched = s.dropped = s.zero = s.errors = 0
        s.stop = False; s.fd = -1
        s.stats = s.disp = None
        s.t0 = time.time(); s.last_t = s.t0; s.last_w = 0
        s.seed = ''; s.ocr_sem = None
        s.chal_total = 0; s.bl_hosts = set()
        s.dlog = 0; s.dreason = {}
        s.imp_err = 0; s.dlock = asyncio.Lock()
        s.robots = {}; s.robots_tasks = {}
        s.ssrf = {}
        s.dedup = Dedup(); s.cond = Cond()
        s.rot_tasks = set()
        s.wqs_pass = s.wqs_fail = 0
        s.wqs_pre = 0
        s.dedup_hits = s.cond_hits = 0
        s.robots_blocked = s.ssrf_blocked = 0
        s.bytes_in = s.cap_hits = 0
        s.last_flush = time.time()

    def _drop(s, r, url):
        s.dropped += 1
        s.dreason[r] = s.dreason.get(r, 0) + 1
        if s.dlog < C.drop_log:
            s.dlog += 1
            print(f'[drop:{r}] {url[:100]}', file=sys.stderr)

    def _hs(s, h):
        st = s.hosts.get(h)
        if st is None:
            st = s.hosts[h] = dict(q=deque(), w=[], ev=asyncio.Event(), infl=0,
                last=time.monotonic(), chal=0, bl=False)
        return st

    def _enq(s, url, ref, depth):
        h = _host(url)
        if not h: return False
        st = s._hs(h)
        st['q'].append((url, ref, depth)); st['ev'].set()
        return True

    def _enq_many(s, links, ref, depth):
        n = 0; bl = s.bloom
        for link in links:
            if not wqs(Stub(url=link), C, 0).accept:
                s.wqs_pre += 1; continue
            if link in bl: continue
            bl.add(link)
            if s._enq(link, ref, depth): n += 1
        return n

    def _sched_rot(s, idx):
        t = asyncio.create_task(s.pool.rotate(idx))
        s.rot_tasks.add(t); t.add_done_callback(s.rot_tasks.discard)

    async def _ssrf_check(s, h):
        hh = h.split(':')[0]
        try:
            ip = ipaddress.ip_address(hh)
            bad = ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
            return not bad
        except ValueError: pass
        def _res():
            try: infos = socket.getaddrinfo(hh, None)
            except socket.gaierror: return True
            for info in infos:
                try: ip = ipaddress.ip_address(info[4][0])
                except ValueError: continue
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                    return False
            return True
        return await asyncio.get_running_loop().run_in_executor(PP, _res)

    async def _robots_ensure(s, h):
        if h in s.robots_tasks:
            await s.robots_tasks[h]
            return s.robots.get(h, ([], None))
        if h in s.robots: return s.robots[h]
        async def _go():
            rules, delay = [], None
            for scheme in ('https', 'http'):
                text = await s._standalone(f'{scheme}://{h}/robots.txt')
                if text:
                    rules, delay = _parse_robots(text, C.robots_ua); break
            s.robots[h] = (rules, delay)
        t = asyncio.create_task(_go())
        s.robots_tasks[h] = t
        await t
        return s.robots.get(h, ([], None))

    async def _dispatcher(s):
        while not s.stop:
            async with s.dlock:
                for h, st in list(s.hosts.items()):
                    if st['w']: st['w'] = [w for w in st['w'] if not w.done()]
                active = sum(1 for st in s.hosts.values() if st['w'])
                if active < C.max_hosts:
                    for h, st in s.hosts.items():
                        if active >= C.max_hosts: break
                        if not st['q'] or st['w'] or st['bl'] or h in s.bl_hosts: continue
                        s._spawn(h, st); active += 1
            if time.time() - s.last_flush > C.cond_flush:
                s.cond.flush(); s.last_flush = time.time()
            await asyncio.sleep(C.dispatch)

    def _spawn(s, h, st):
        n = min(C.wph_max, max(C.wph_min, len(st['q']) // 8))
        st['w'] = [asyncio.create_task(s._worker(h, st, i)) for i in range(n)]
        st['last'] = time.monotonic()

    async def _worker(s, h, st, wid):
        while not s.stop:
            if st['bl'] or h in s.bl_hosts: return
            if not st['q']:
                st['ev'].clear()
                if st['q']: continue
                try: await asyncio.wait_for(st['ev'].wait(), timeout=C.host_idle)
                except (asyncio.TimeoutError, asyncio.CancelledError): return
                continue
            try: url, ref, depth = st['q'].popleft()
            except IndexError: continue
            st['infl'] += 1; st['last'] = time.monotonic()
            try: await s._process(url, ref, depth, h, st)
            except asyncio.CancelledError: raise
            except Exception as e:
                s.errors += 1
                if s.errors <= 20: print(f'[w{h}:{wid}] {url[:80]}: {type(e).__name__}: {e}', file=sys.stderr)
            finally:
                st['infl'] -= 1; st['last'] = time.monotonic()

    async def _standalone(s, url, timeout=15):
        idx = s.pool.pick(); sess = s.pool.get(idx)
        if sess is None: return None
        try:
            r = await sess.get(url, allow_redirects=True, max_redirects=5, timeout=timeout)
            if r.status_code == 200:
                try: return r.text
                except:
                    try: return (r.content or b'').decode('utf-8', 'ignore')
                    except: return None
        except: return None

    def _cap_for(s, h):
        ct = h.get('content-type', '')
        if 'html' in ct or 'xhtml' in ct: return C.html_cap
        if 'xml' in ct or 'rss' in ct or 'atom' in ct: return C.xml_cap
        if 'pdf' in ct: return C.bin_cap
        if ct.startswith('image/'): return C.img_cap
        return C.bin_cap

    async def _read_body(s, resp, hdr_only=False):
        status = resp.status_code
        h = {k.lower(): v for k, v in resp.headers.items()}
        cap = s._cap_for(h)
        cl = h.get('content-length')
        if cl:
            try:
                if int(cl) > cap: return status, h, b'', 'cl-too-big'
            except ValueError: pass
        if hdr_only: return status, h, b'', None
        if hasattr(resp, 'aiter_content'):
            chunks, total, hit = [], 0, False
            async for ck in resp.aiter_content():
                total += len(ck)
                if total > cap:
                    chunks.append(ck[:cap - (total - len(ck))]); hit = True; break
                chunks.append(ck)
            return status, h, b''.join(chunks), 'cap-hit' if hit else None
        body = resp.content or b''
        return status, h, body[:cap], None

    async def _fetch_once(s, idx, url, headers):
        sess = s.pool.get(idx)
        if sess is None: raise RuntimeError('no-session')
        try:
            cm = sess.stream('GET', url, headers=headers, timeout=C.timeout,
                             allow_redirects=True, max_redirects=C.redir_max)
        except (AttributeError, TypeError):
            cm = None
        if cm is not None:
            async with cm as resp:
                return await s._read_body(resp)
        resp = await sess.get(url, headers=headers, timeout=C.timeout,
                              allow_redirects=True, max_redirects=C.redir_max)
        return await s._read_body(resp)

    async def _seed_smaps(s, url):
        p = urlparse(url); base = f'{p.scheme}://{p.netloc}'
        robots = await s._standalone(f'{base}/robots.txt')
        smaps = []
        if robots:
            for line in robots.splitlines():
                line = line.strip()
                if line.lower().startswith('sitemap:'):
                    sm = line[8:].strip()
                    if sm.startswith(('http://', 'https://')): smaps.append(sm)
        if not smaps: smaps = [f'{base}/sitemap.xml', f'{base}/sitemap_index.xml']
        seen, added = set(), 0
        pend = deque(smaps[:C.smap_n])
        while pend and len(seen) < C.smap_n and added < C.smap_p:
            u = pend.popleft()
            if u in seen: continue
            seen.add(u)
            xml = await s._standalone(u, timeout=20)
            if not xml: continue
            low = xml[:3000].lower()
            locs = _SMAP_LOC.findall(xml)
            if '<sitemapindex' in low:
                for loc in locs[:20]:
                    if loc not in seen and len(seen) + len(pend) < C.smap_n: pend.append(loc)
            else:
                for loc in locs:
                    n = normalize(loc)
                    if n and n not in s.bloom:
                        s.bloom.add(n); s._enq(n, url, 1); added += 1
                        if added >= C.smap_p: break
        print(f'[sitemaps] {len(seen)} sitemaps, {added} pages queued', file=sys.stderr)

    async def run(s, seed):
        s.seed = seed
        if _parser() == 'none':
            print('[!] no HTML parser (pip install selectolax)', file=sys.stderr); return
        keys = _imps()
        if not keys:
            print('[!] no curl_cffi impersonation keys', file=sys.stderr); return
        if OUT.exists():
            try:
                with OUT.open('rb') as f:
                    for i, line in enumerate(f):
                        line = line.strip()
                        if not line: continue
                        if i < 5000:
                            try:
                                u = json.loads(line).get('url')
                                if isinstance(u, str): s.bloom.add(u)
                                continue
                            except: pass
                        needle = b'"url":"'; j = line.find(needle)
                        if j < 0: continue
                        j += len(needle); k = line.find(b'"', j)
                        if k > 0: s.bloom.add(line[j:k])
            except: pass
        if not wqs(Stub(url=seed), C, 0).accept:
            print('[!] seed rejected by WQS preflight', file=sys.stderr); return
        s.bloom.add(seed); s._enq(seed, '', 0)
        s.ocr_sem = asyncio.Semaphore(C.oc)
        s.sem = asyncio.Semaphore(C.max_conc)
        s.pool = Pool(C.pool, keys); await s.pool.start()
        s.fd = os.open(str(OUT), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        ocr_ready = bool(_ocr() and C.ocr)
        engine = 'lexbor' if _lex() else 'lxml'
        print(f'[Nexus] seed:     {seed}', file=sys.stderr)
        print(f'[Nexus] output:   {OUT.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:   {engine}  parsers={C.pw}', file=sys.stderr)
        print(f'[Nexus] hosts:    max={C.max_hosts}  workers/host={C.wph_min}-{C.wph_max}', file=sys.stderr)
        print(f'[Nexus] global:   concurrency_cap={C.max_conc}', file=sys.stderr)
        print(f'[Nexus] sessions: {C.pool}  impersonate={len(keys)}', file=sys.stderr)
        print(f'[Nexus] pdf:      {_pdf()}   ocr: {"on" if ocr_ready else "off"}', file=sys.stderr)
        print(f'[Nexus] wqs:      accept={C.wqs_accept}  rules={len(_WQS_ALL)}  toml={"yes" if _load_wqs_toml(C.wqs_toml) else "no"}', file=sys.stderr)
        print(f'[Nexus] caps:     html={C.html_cap//1024}K  xml={C.xml_cap//1024}K  bin={C.bin_cap//1024}K', file=sys.stderr)
        print('[Nexus] seeding sitemaps...', file=sys.stderr)
        try: await s._seed_smaps(seed)
        except Exception as e: print(f'[sitemaps] failed: {e}', file=sys.stderr)
        print('[Nexus] CTRL+C to stop.\n', file=sys.stderr)
        s.stats = asyncio.create_task(s._stats_loop())
        s.disp = asyncio.create_task(s._dispatcher())
        try: await s.disp
        except asyncio.CancelledError: pass
        finally:
            s.stop = True
            for t in (s.stats, s.disp):
                if t: t.cancel()
            for t in (s.stats, s.disp):
                try: await t
                except: pass
            for st in s.hosts.values():
                for w in st['w']: w.cancel()
            for t in list(s.rot_tasks): t.cancel()
            for t in s.robots_tasks.values(): t.cancel()
            try:
                if s.fd >= 0: os.fsync(s.fd)
            except: pass
            PP.shutdown(wait=False); OP.shutdown(wait=False)
            try:
                if s.fd >= 0: os.close(s.fd)
            except: pass
            s.cond.flush()
            await s.pool.stop()
            s._report()

    async def _stats_loop(s):
        nt = time.monotonic() + C.stats
        while not s.stop:
            d = nt - time.monotonic()
            if d > 0: await asyncio.sleep(d)
            nt += C.stats
            t = time.time(); dt = t - s.last_t; dw = s.written - s.last_w
            rate = dw / dt if dt > 0 else 0.0
            avg = s.written / (t - s.t0) if t > s.t0 else 0.0
            ep = (s.dropped / s.fetched * 100.0) if s.fetched else 0.0
            q = sum(len(st['q']) for st in s.hosts.values())
            a = sum(1 for st in s.hosts.values() if st['w'])
            w = sum(len(st['w']) for st in s.hosts.values())
            mb = s.bytes_in / 1_000_000
            print(f'[s] {rate:6.1f}/s avg {avg:6.1f}/s  w={s.written} f={s.fetched} '
                f'd={s.dropped}({ep:.0f}%)  q={q} hosts={a}/{len(s.hosts)} wrk={w}  '
                f'mb={mb:.1f}  wqs+{s.wqs_pass}/-{s.wqs_fail}/pre{s.wqs_pre}  '
                f'dedup={s.dedup_hits} cond={s.cond_hits} rb={s.robots_blocked} '
                f'ssrf={s.ssrf_blocked} cap={s.cap_hits}  ch={s.chal_total} bl={len(s.bl_hosts)}',
                file=sys.stderr)
            s.last_t = t; s.last_w = s.written

    def _report(s):
        el = time.time() - s.t0
        print(f'\n[Nexus] done. written={s.written}  fetched={s.fetched}  dropped={s.dropped}  '
            f'errors={s.errors}  zerolink={s.zero}  challenges={s.chal_total}  '
            f'imp-errors={s.imp_err}  hosts_seen={len(s.hosts)}  '
            f'bytes_in={s.bytes_in / 1_000_000:.1f}MB  '
            f'wqs_pass={s.wqs_pass} wqs_fail={s.wqs_fail} wqs_pre={s.wqs_pre}  '
            f'dedup_hits={s.dedup_hits} cond_304={s.cond_hits}  '
            f'robots_blocked={s.robots_blocked} ssrf_blocked={s.ssrf_blocked} cap_hits={s.cap_hits}  '
            f'elapsed={el:.1f}s  avg={s.written / el if el else 0:.1f}/s', file=sys.stderr)
        if s.bl_hosts: print(f'[blacklisted] {sorted(s.bl_hosts)[:20]}', file=sys.stderr)
        if s.dreason:
            top = sorted(s.dreason.items(), key=lambda x: -x[1])[:10]
            print('[drops] ' + '  '.join(f'{r}={c}' for r, c in top), file=sys.stderr)

    async def _process(s, url, ref, depth, host, st):
        s.fetched += 1
        status, ra = 0, 0.0
        if host not in s.ssrf:
            s.ssrf[host] = await s._ssrf_check(host)
            if len(s.ssrf) > C.ssrf_cache_max:
                for k in list(s.ssrf)[:1000]: s.ssrf.pop(k, None)
        if not s.ssrf[host]:
            s.ssrf_blocked += 1; st['bl'] = True
            return
        try: rules, delay = await s._robots_ensure(host)
        except: rules, delay = [], None
        path = urlparse(url).path or '/'
        if not _robots_ok(rules, path):
            s.robots_blocked += 1; return
        if delay: await asyncio.sleep(delay)
        await s.rate.wait(host)
        ck = s.cond.get(url)
        chdrs = {}
        if ck:
            if ck[0]: chdrs['If-None-Match'] = ck[0]
            if ck[1]: chdrs['If-Modified-Since'] = ck[1]
        try:
            resp_meta = None
            for attempt in range(C.imp_retry + 1):
                idx = s.pool.pick()
                if s.pool.get(idx) is None:
                    s.pool.force(idx); await s.pool.rotate(idx); continue
                hdrs_req = build_headers(ref, host); hdrs_req.update(chdrs)
                try:
                    async with s.sem:
                        status, hdrs, body, err = await s._fetch_once(idx, url, hdrs_req)
                except Exception as e:
                    en = type(e).__name__
                    s.pool.bump(idx)
                    if 'Impersonate' in en:
                        s.imp_err += 1; s.pool.force(idx)
                        try: await s.pool.rotate(idx)
                        except: pass
                        continue
                    s._drop(f'fetch-{en}', url); return
                s.pool.bump(idx)
                if s.pool.needs(idx): s._sched_rot(idx)
                s.bytes_in += len(body)
                if err == 'cap-hit': s.cap_hits += 1
                if err == 'cl-too-big': s.cap_hits += 1
                resp_meta = (status, hdrs, body, err)
                break
            else:
                s._drop('impersonate-retry-exhausted', url); return
            if resp_meta is None:
                s._drop('no-response', url); return
            status, hdrs, body, err = resp_meta
            if status == 304:
                s.cond_hits += 1; return
            ctype = (hdrs.get('content-type') or '').lower()
            if _is_chal(body, status, hdrs):
                s.chal_total += 1; st['chal'] += 1
                if st['chal'] >= C.bl_chal:
                    st['bl'] = True; s.bl_hosts.add(host)
                s._drop(f'challenge-{status}', url); return
            if status != 200:
                if status in ROTATE:
                    s.pool.force(idx); s._sched_rot(idx)
                if status in (429, 503): ra = _retry_after_headers(hdrs)
                s._drop(f'status-{status}', url); return
            etag = hdrs.get('etag'); lm = hdrs.get('last-modified')
            if etag or lm: s.cond.set(url, etag, lm)
            if 'text/html' in ctype or 'application/xhtml' in ctype or not ctype: ct = 'html'
            elif 'application/pdf' in ctype: ct = 'pdf'
            elif ctype.startswith('image/'): ct = 'image'
            elif 'xml' in ctype or 'rss' in ctype or 'atom' in ctype: ct = 'xml'
            else: s._drop(f'ctype-{ctype[:30]}', url); return
            loop = asyncio.get_running_loop()
            if ct == 'html':
                if not body: s._drop('empty-html', url); return
                raw = body.decode('utf-8', 'ignore')
                if len(raw) > C.text_cap * 2: raw = raw[:C.text_cap * 2]
                try: cleaned, links = await loop.run_in_executor(PP, _parse, raw, body, url)
                except Exception as e: s._drop(f'parse-{type(e).__name__}', url); return
            elif ct == 'xml':
                if not body: s._drop('empty-xml', url); return
                try: links = await loop.run_in_executor(PP, _parse_xml, body, url, C.links_cap)
                except Exception as e: s._drop(f'xml-{type(e).__name__}', url); return
                cleaned = None
            else:
                if not body: s._drop('empty-binary', url); return
                async with s.ocr_sem:
                    try: cleaned = await loop.run_in_executor(OP, _binary, body, ct, url)
                    except Exception as e: s._drop(f'ocr-{type(e).__name__}', url); return
                links = ()
            if cleaned is not None:
                title, text = cleaned
                v = wqs(Stub(url, title, text, ct, hdrs), C, 1)
                if not v.accept:
                    s.wqs_fail += 1
                    s._drop(f'wqs:{v.reason}', url)
                elif s.dedup.seen(text):
                    s.dedup_hits += 1
                    s._drop('dup', url)
                else:
                    s.wqs_pass += 1
                    rec = dict(url=url, title=title, text=text)
                    if ct != 'html': rec['content_type'] = ct
                    line = json.dumps(rec, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n'
                    try:
                        off, total = 0, len(line)
                        while off < total:
                            n = os.write(s.fd, line[off:])
                            if n <= 0: raise OSError('short-write')
                            off += n
                        s.written += 1
                    except OSError as e:
                        print(f'[write] {e}', file=sys.stderr)
                        s.stop = True; return
            elif ct == 'html':
                s._drop('empty-text', url)
            if not links: s.zero += 1
            else: s._enq_many(links, url, depth + 1)
        finally:
            await s.rate.rec(host, status, ra)

def _retry_after_headers(hdrs):
    ra = hdrs.get('retry-after')
    if not ra: return 0.0
    try: return float(ra)
    except ValueError: pass
    try:
        from email.utils import parsedate_to_datetime
        return max(0.0, parsedate_to_datetime(ra).timestamp() - time.time())
    except: return 0.0

async def main():
    try: seed = input('url : ').strip()
    except (EOFError, KeyboardInterrupt): return
    if not seed: return
    seed_n = normalize(seed)
    if not seed_n:
        print(f'[!] invalid seed url: {seed}', file=sys.stderr); return
    c = Crawler()
    loop = asyncio.get_running_loop()
    ev = asyncio.Event()
    def sig(*_): c.stop = True; ev.set()
    try:
        loop.add_signal_handler(signal.SIGINT, sig)
        loop.add_signal_handler(signal.SIGTERM, sig)
    except (NotImplementedError, RuntimeError):
        signal.signal(signal.SIGINT, lambda *a: (setattr(c, 'stop', True), ev.set()))
    rt = asyncio.create_task(c.run(seed_n))
    st = asyncio.create_task(ev.wait())
    await asyncio.wait({rt, st}, return_when=asyncio.FIRST_COMPLETED)
    if ev.is_set():
        for t in asyncio.all_tasks():
            if t is not asyncio.current_task(): t.cancel()
        try: await rt
        except: pass

if __name__ == '__main__':
    try: asyncio.run(main())
    except KeyboardInterrupt: pass