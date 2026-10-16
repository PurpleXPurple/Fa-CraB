import asyncio, json, os, re, signal, sys, time, random, math
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag, parse_qsl, urlencode

C = dict(max_hosts=512, wph_min=2, wph_max=32, max_conc=1024, pool=96, rot_min=400,
    rot_max=800, timeout=12, html_max=2_000_000, bin_max=10_000_000, text_max=200_000,
    redir_max=5, links_max=20_000, stats=3.0, out='output.json', bloom_n=50_000_000,
    bloom_e=0.001, pw=max(8, (os.cpu_count() or 4) * 2), ow=4, oc=8, ocr=True,
    ocr_min=100, ocr_max=400_000, ocr_pdf=10, host_idle=5.0, dispatch=0.2,
    bl_403=5, bl_chal=3, imp_retry=2, drop_log=15, min_text=20, smap_n=50, smap_p=5000)
OUT = Path(C['out'])
PP = ThreadPoolExecutor(max_workers=C['pw'])
OP = ThreadPoolExecutor(max_workers=C['ow'])
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

class Bloom:
    def __init__(s, n, e):
        nb = 1 << max(6, (int(-(n * math.log(e)) / (math.log(2) ** 2)) - 1).bit_length())
        s.m, s.b, s.k = nb - 1, bytearray(nb >> 3), max(1, int((nb / n) * math.log(2)))
    def _h(s, b):
        h1 = hash(b)
        h2 = hash(b[:64] + b'\x9e' + b[-64:]) if len(b) > 128 else hash(b[::-1] + b'\x9e')
        return h1, h2 or 0x9E3779B97F4A7C15
    def add(s, t):
        b = t.encode('utf-8', 'ignore') if isinstance(t, str) else t
        h1, h2 = s._h(b)
        for i in range(s.k):
            x = (h1 + i * h2) & s.m
            s.b[x >> 3] |= 1 << (x & 7)
    def __contains__(s, t):
        b = t.encode('utf-8', 'ignore') if isinstance(t, str) else t
        h1, h2 = s._h(b)
        for i in range(s.k):
            x = (h1 + i * h2) & s.m
            if not s.b[x >> 3] & (1 << (x & 7)): return False
        return True

class Rate:
    def __init__(s): s.d = {}; s.l = asyncio.Lock()
    def bl(s, h): st = s.d.get(h); return bool(st and st['bl'])
    async def wait(s, h):
        st = s.d.get(h)
        if not st or st['d'] <= 0: return
        g = st['d'] - (time.monotonic() - st['t'])
        if g > 0: await asyncio.sleep(g)
    async def rec(s, h, status, ra=0.0):
        if status == 200 and ra == 0.0:
            st = s.d.get(h)
            if st is None or st['d'] <= 0.0:
                if st is None:
                    async with s.l:
                        st = s.d.setdefault(h, dict(d=0.0, f=0, t=0.0, c403=0, bl=False))
                st['t'] = time.monotonic(); st['c403'] = 0; return
        async with s.l:
            st = s.d.setdefault(h, dict(d=0.0, f=0, t=0.0, c403=0, bl=False))
            st['t'] = time.monotonic()
            if ra > 0: st['d'] = max(st['d'], min(ra, 60.0))
            if status in RETRY:
                st['f'] += 1
                st['d'] = min(60.0, max(0.3, st['d'] * 2.0) * random.uniform(0.8, 1.2))
            elif status == 403:
                st['f'] += 1; st['c403'] += 1
                if st['c403'] >= C['bl_403']: st['bl'] = True
            elif status == 401:
                st['f'] += 1; st['d'] = min(30.0, max(0.5, st['d'] * 1.5))
            elif status == 200:
                st['f'] = 0; st['d'] = max(0.0, st['d'] * 0.5); st['c403'] = 0

_LANGS = ('en-US,en;q=0.9','en-US,en;q=0.9,fr;q=0.8','en-GB,en;q=0.9,en-US;q=0.8','en-US,en;q=0.8,de;q=0.6')
_ACCS = ('text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
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
            s.ss[i] = s._mk(); s.th[i] = random.randint(C['rot_min'], C['rot_max'])
    def _mk(s):
        Sc = _session()
        for _ in range(6):
            try: return Sc(impersonate=random.choice(s.k), timeout=C['timeout'])
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
            s.th[i] = random.randint(C['rot_min'], C['rot_max'])

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
_TRACK = frozenset({'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id','utm_source_platform',
    'utm_creative_format','utm_marketing_tactic','gclid','gclsrc','dclid','gbraid','wbraid','fbclid','fb_action_ids',
    'fb_action_types','fb_source','fb_ref','mc_cid','mc_eid','mkt_tok','yclid','_openstat','msclkid','twclid',
    'ttclid','li_fat_id','igshid','vero_id','vero_conv','wickedid','oly_anon_id','oly_enc_id','ref','ref_src',
    'ref_url','referrer','source','src','_ga','_gl','sc_cid','sc_uid','spm','scm','from','from_source',
    'share_source','share_medium'})
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
_WS = re.compile(r'[^\S\n]+'); _NL = re.compile(r'\n{3,}'); _JUNK = re.compile(r'[^\x20-\x7E\n\t]')
_META_REF = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.I)
_SCRIPT = re.compile(rb'<script\b[^>]*>(.*?)</script>', re.I | re.DOTALL)
_ABS = re.compile(rb'https?://[a-zA-Z0-9][a-zA-Z0-9\-._]{1,253}\.[a-zA-Z]{2,}'
    rb'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{0,1000}', re.I)
_JSONLD = re.compile(rb'<script[^>]*type\s*=\s*["\']application/ld\+json["\'][^>]*>(.*?)</script>', re.I | re.DOTALL)
_JSONLD_K = frozenset({'url','@id','sameAs','href','link','permalink','canonicalUrl'})
_XML_LOC = re.compile(rb'<(?:loc|link|url|id)[^>]*>\s*([^<\s]+)\s*</(?:loc|link|url|id)>', re.I)
_XML_HREF = re.compile(rb'<link[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', re.I)
_SMAP_LOC = re.compile(r'<loc>\s*([^<\s]+)\s*</loc>', re.I)

def _clean(t):
    return _JUNK.sub('', _NL.sub('\n\n', _WS.sub(' ', t))).strip()

def _lex(): return _L.get('pm') == 'lexbor'
def _first(doc, css, xp):
    if _lex(): return doc.css_first(css)
    r = doc.xpath(xp); return r[0] if r else None
def _text(n, sep='\n'):
    if n is None: return ''
    if _lex():
        try: return n.text(separator=sep) or ''
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
    for m in _SCRIPT.finditer(rawb):
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
        n = _first(doc, c, x)
        v = (n if isinstance(n, str) else _atr(n, 'content') or _text(n)) or ''
        v = v.strip()
        if v and v not in parts: parts.append(v)
    return ' '.join(parts)

def _parse(raw, rawb, base):
    try: doc = _L['P'](raw) if _lex() else _L['P'].document_fromstring(raw, base_url=base)
    except: return None, ()
    title = _text(_first(doc, 'title', '//title')).strip()
    if not title: title = _text(_first(doc, 'h1', '//h1')).strip()[:200]
    if not title: title = (_atr(_first(doc, 'meta[property="og:title"]', '//meta[@property="og:title"]'), 'content') or '')[:200]
    lim = C['links_max']
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
        for tag in src.css(_KILL_CSS): tag.decompose()
    else:
        for tag in list(src.iter(*_KILL_TAGS)):
            p = tag.getparent()
            if p is not None: p.remove(tag)
    text = _text(src)
    if len(text) > C['text_max']: text = text[:C['text_max']]
    text = _clean(text)
    if len(text) < C['min_text']:
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
                parts = [doc[i].get_text() for i in range(min(len(doc), 500))]
                return title, '\n\n'.join(p for p in parts if p)
            finally:
                try: doc.close()
                except: pass
        except: return None
    try:
        from io import BytesIO
        r = _L['PDF'].PdfReader(BytesIO(b))
        title = getattr(r.metadata, 'title', '') if r.metadata else ''
        return title or '', '\n\n'.join(p.extract_text() or '' for p in r.pages[:500])
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
            for i in range(min(len(doc), C['ocr_pdf'])):
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
        if len(text) < C['ocr_min'] and C['ocr']:
            o = _pdf_ocr(b)
            if o and len(o) > len(text): text = o
        if not title:
            tail = url.rsplit('/', 1)[-1] if '/' in url else url
            title = tail.rsplit('.', 1)[0][:200] if '.' in tail else tail[:200]
        text = _clean(text)
        if len(text) > C['ocr_max']: text = text[:C['ocr_max']]
        return (title or '[untitled]', text) if text else None
    if ct == 'image':
        if not C['ocr']: return None
        text = _clean(_img_ocr(b) or '')
        if len(text) < 20: return None
        if len(text) > C['ocr_max']: text = text[:C['ocr_max']]
        return (text.split('\n', 1)[0].strip()[:200] or '[image]'), text
    return None

_CHAL = (b'<title>just a moment', b'<title>attention required', b'<title>checking your browser',
    b'<title>one more step', b'cf-chl-widget', b'__cf_chl_rt_tk', b'cf-please-wait')

def _is_chal(b, status, hdrs):
    if status not in (403, 429, 503): return False
    try:
        if 'challenge' in (hdrs.get('cf-mitigated') or hdrs.get('CF-Mitigated') or '').lower():
            return True
    except: pass
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
        s.bloom = Bloom(C['bloom_n'], C['bloom_e'])
        s.hosts, s.pool, s.rate = {}, None, Rate()
        s.sem = None; s.written = s.fetched = s.dropped = s.zero = s.errors = 0
        s.stop = False; s.fd = -1
        s.stats = s.disp = None; s.t0 = time.time()
        s.last_t = s.t0; s.last_w = 0
        s.seed = s.seed_host = ''; s.ocr_sem = None
        s.chal_total = 0; s.bl_hosts = set(); s.dlog = 0; s.dreason = {}
        s.imp_err = 0; s.dlock = asyncio.Lock()
    def _drop(s, reason, url):
        s.dropped += 1
        s.dreason[reason] = s.dreason.get(reason, 0) + 1
        if s.dlog < C['drop_log']:
            s.dlog += 1
            print(f'[drop:{reason}] {url[:100]}', file=sys.stderr)
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
            if link in bl: continue
            bl.add(link)
            if s._enq(link, ref, depth): n += 1
        return n
    async def _dispatcher(s):
        while not s.stop:
            async with s.dlock:
                for h, st in list(s.hosts.items()):
                    if st['w']: st['w'] = [w for w in st['w'] if not w.done()]
                active = sum(1 for st in s.hosts.values() if st['w'])
                if active < C['max_hosts']:
                    for h, st in s.hosts.items():
                        if active >= C['max_hosts']: break
                        if not st['q'] or st['w'] or st['bl'] or h in s.bl_hosts: continue
                        s._spawn(h, st); active += 1
            await asyncio.sleep(C['dispatch'])
    def _spawn(s, h, st):
        n = min(C['wph_max'], max(C['wph_min'], len(st['q']) // 8))
        st['w'] = [asyncio.create_task(s._worker(h, st, i)) for i in range(n)]
        st['last'] = time.monotonic()
    async def _worker(s, h, st, wid):
        while not s.stop:
            if st['bl'] or h in s.bl_hosts: return
            if not st['q']:
                st['ev'].clear()
                if st['q']: continue
                try: await asyncio.wait_for(st['ev'].wait(), timeout=C['host_idle'])
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
        Sc = _session()
        key = random.choice(s.pool.k) if s.pool and s.pool.k else 'chrome136'
        try:
            async with Sc(impersonate=key, timeout=timeout) as sess:
                r = await sess.get(url, allow_redirects=True, max_redirects=5)
                if r.status_code == 200:
                    try: return r.text
                    except:
                        try: return (r.content or b'').decode('utf-8', 'ignore')
                        except: return None
        except: return None
    async def _seed_smaps(s, url):
        p = urlparse(url)
        base = f'{p.scheme}://{p.netloc}'
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
        pend = deque(smaps[:C['smap_n']])
        while pend and len(seen) < C['smap_n'] and added < C['smap_p']:
            u = pend.popleft()
            if u in seen: continue
            seen.add(u)
            xml = await s._standalone(u, timeout=20)
            if not xml: continue
            low = xml[:3000].lower()
            locs = _SMAP_LOC.findall(xml)
            if '<sitemapindex' in low:
                for loc in locs[:20]:
                    if loc not in seen and len(seen) + len(pend) < C['smap_n']: pend.append(loc)
            else:
                for loc in locs:
                    n = normalize(loc)
                    if n and n not in s.bloom:
                        s.bloom.add(n); s._enq(n, url, 1); added += 1
                        if added >= C['smap_p']: break
        print(f'[sitemaps] {len(seen)} sitemaps, {added} pages queued', file=sys.stderr)
    async def run(s, seed):
        s.seed, s.seed_host = seed, _host(seed)
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
                        n = b'"url":"'; j = line.find(n)
                        if j < 0: continue
                        j += len(n); k = line.find(b'"', j)
                        if k > 0: s.bloom.add(line[j:k])
            except: pass
        s.bloom.add(seed); s._enq(seed, '', 0)
        s.ocr_sem = asyncio.Semaphore(C['oc'])
        s.sem = asyncio.Semaphore(C['max_conc'])
        s.pool = Pool(C['pool'], keys); await s.pool.start()
        s.fd = os.open(str(OUT), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
        ocr_ready = bool(_ocr() and C['ocr'])
        engine = 'lexbor' if _lex() else 'lxml'
        print(f'[Nexus] seed:     {seed}', file=sys.stderr)
        print(f'[Nexus] output:   {OUT.resolve()}', file=sys.stderr)
        print(f'[Nexus] engine:   {engine}  parsers={C["pw"]}', file=sys.stderr)
        print(f'[Nexus] hosts:    max={C["max_hosts"]}  workers/host={C["wph_min"]}-{C["wph_max"]}', file=sys.stderr)
        print(f'[Nexus] global:   concurrency_cap={C["max_conc"]}', file=sys.stderr)
        print(f'[Nexus] sessions: {C["pool"]}  impersonate={len(keys)}', file=sys.stderr)
        print(f'[Nexus] pdf:      {_pdf()}   ocr: {"on" if ocr_ready else "off"}', file=sys.stderr)
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
            try:
                if s.fd >= 0: os.fsync(s.fd)
            except: pass
            PP.shutdown(wait=False); OP.shutdown(wait=False)
            try:
                if s.fd >= 0: os.close(s.fd)
            except: pass
            await s.pool.stop()
            s._report()
    async def _stats_loop(s):
        nt = time.monotonic() + C['stats']
        while not s.stop:
            d = nt - time.monotonic()
            if d > 0: await asyncio.sleep(d)
            nt += C['stats']
            t = time.time(); dt = t - s.last_t; dw = s.written - s.last_w
            rate = dw / dt if dt > 0 else 0.0
            avg = s.written / (t - s.t0) if t > s.t0 else 0.0
            ep = (s.dropped / s.fetched * 100.0) if s.fetched else 0.0
            q = sum(len(st['q']) for st in s.hosts.values())
            a = sum(1 for st in s.hosts.values() if st['w'])
            w = sum(len(st['w']) for st in s.hosts.values())
            print(f'[s] {rate:6.1f}/s avg {avg:6.1f}/s  w={s.written} f={s.fetched} '
                f'd={s.dropped}({ep:.0f}%)  q={q} hosts={a}/{len(s.hosts)} wrk={w}  '
                f'zl={s.zero} ch={s.chal_total} im={s.imp_err} bl={len(s.bl_hosts)}', file=sys.stderr)
            s.last_t = t; s.last_w = s.written
    def _report(s):
        el = time.time() - s.t0
        print(f'\n[Nexus] done. written={s.written}  fetched={s.fetched}  dropped={s.dropped}  '
            f'errors={s.errors}  zerolink={s.zero}  challenges={s.chal_total}  '
            f'imp-errors={s.imp_err}  hosts_seen={len(s.hosts)}  '
            f'elapsed={el:.1f}s  avg={s.written / el if el else 0:.1f}/s', file=sys.stderr)
        if s.bl_hosts: print(f'[blacklisted] {sorted(s.bl_hosts)[:20]}', file=sys.stderr)
        if s.dreason:
            top = sorted(s.dreason.items(), key=lambda x: -x[1])[:10]
            print('[drops] ' + '  '.join(f'{r}={c}' for r, c in top), file=sys.stderr)
    async def _process(s, url, ref, depth, host, st):
        s.fetched += 1
        status, ra = 0, 0.0
        await s.rate.wait(host)
        try:
            resp = body = raw = None; hdrs = {}; idx = -1
            for _ in range(C['imp_retry'] + 1):
                idx = s.pool.pick(); sess = s.pool.get(idx)
                if sess is None:
                    s.pool.force(idx); await s.pool.rotate(idx); continue
                try:
                    async with s.sem:
                        resp = await sess.get(url, headers=build_headers(ref, host), timeout=C['timeout'],
                            allow_redirects=True, max_redirects=C['redir_max'])
                    status = resp.status_code
                    body = resp.content or b''
                    try: raw = resp.text
                    except: raw = body.decode('utf-8', 'ignore')
                    s.pool.bump(idx)
                    if s.pool.needs(idx): asyncio.create_task(s.pool.rotate(idx))
                    break
                except Exception as e:
                    en = type(e).__name__; s.pool.bump(idx)
                    if 'Impersonate' in en:
                        s.imp_err += 1; s.pool.force(idx)
                        try: await s.pool.rotate(idx)
                        except: pass
                        continue
                    if s.pool.needs(idx): asyncio.create_task(s.pool.rotate(idx))
                    s._drop(f'fetch-{en}', url); return
            else:
                s._drop('impersonate-retry-exhausted', url); return
            if resp is None: s._drop('no-response', url); return
            try: hdrs = dict(resp.headers)
            except: pass
            ctype = (hdrs.get('content-type') or hdrs.get('Content-Type') or '').lower()
            if _is_chal(body, status, hdrs):
                s.chal_total += 1; st['chal'] += 1
                if st['chal'] >= C['bl_chal']:
                    st['bl'] = True; s.bl_hosts.add(host)
                s._drop(f'challenge-{status}', url); return
            if status != 200:
                if status in ROTATE:
                    s.pool.force(idx); asyncio.create_task(s.pool.rotate(idx))
                if status in (429, 503): ra = _retry_after(resp)
                s._drop(f'status-{status}', url); return
            if 'text/html' in ctype or 'application/xhtml' in ctype or not ctype: ct = 'html'
            elif 'application/pdf' in ctype: ct = 'pdf'
            elif ctype.startswith('image/'): ct = 'image'
            elif 'xml' in ctype or 'rss' in ctype or 'atom' in ctype: ct = 'xml'
            else: s._drop(f'ctype-{ctype[:30]}', url); return
            loop = asyncio.get_running_loop()
            if ct == 'html':
                if not raw: s._drop('empty-html', url); return
                if len(raw) > C['html_max']: raw = raw[:C['html_max']]
                try: cleaned, links = await loop.run_in_executor(PP, _parse, raw, raw.encode('utf-8', 'ignore'), url)
                except Exception as e: s._drop(f'parse-{type(e).__name__}', url); return
            elif ct == 'xml':
                if not body: s._drop('empty-xml', url); return
                try: links = await loop.run_in_executor(PP, _parse_xml, body, url, C['links_max'])
                except Exception as e: s._drop(f'xml-{type(e).__name__}', url); return
                cleaned = None
            else:
                if not body: s._drop('empty-binary', url); return
                if len(body) > C['bin_max']: s._drop('binary-too-large', url); return
                async with s.ocr_sem:
                    try: cleaned = await loop.run_in_executor(OP, _binary, body, ct, url)
                    except Exception as e: s._drop(f'ocr-{type(e).__name__}', url); return
                links = ()
            if cleaned is not None:
                title, text = cleaned
                rec = dict(url=url, title=title, text=text)
                if ct != 'html': rec['content_type'] = ct
                try:
                    os.write(s.fd, json.dumps(rec, ensure_ascii=False, separators=(',', ':')).encode('utf-8') + b'\n')
                    s.written += 1
                except OSError as e:
                    print(f'[write] {e}', file=sys.stderr); s.stop = True; return
            elif ct == 'html':
                s._drop('empty-text', url)
            if not links: s.zero += 1
            else: s._enq_many(links, url, depth + 1)
        finally:
            await s.rate.rec(host, status, ra)

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