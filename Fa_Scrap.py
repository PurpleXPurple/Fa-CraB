#!/usr/bin/env python3
"""
Fa-Scrap.py — The main engine.

Usage:
    python Fa-Scrap.py                 → GUI opens. Paste URL. Enter.
    python Fa-Scrap.py <url>           → GUI opens, prefilled, auto-starts.
    python Fa-Scrap.py -T              → Terminal. Prompts for URL.
    python Fa-Scrap.py -T <url>        → Terminal. Immediate start.
    python Fa-Scrap.py --help          → Help.

That is the entire user surface. Everything else is autonomous.
"""

import argparse
import asyncio
import gc
import logging
import re
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession
from selectolax.lexbor import LexborHTMLParser

from State import (
    AdaptiveSemaphore, Config, EWMA, Folders, Health, Platform, Resume,
    TokenBucket, Writer, normalize_url,
)
from Fa_Crawl import Crawler

log = logging.getLogger("fa.scrap")

_WORD_RE = re.compile(r"\S+")
_PARA_SPLIT = re.compile(r"\n\s*\n")
_HTML_TYPES = ("text/html", "application/xhtml+xml")


# ══════════════════════════════════════════════════════════════════════════════
# DATA
# ══════════════════════════════════════════════════════════════════════════════
@dataclass(slots=True)
class Item:
    url: str
    domain: str
    depth: int
    attempt: int = 0


# ══════════════════════════════════════════════════════════════════════════════
# EXTRACTION
# ══════════════════════════════════════════════════════════════════════════════
def extract(html: str) -> tuple[str, list[str], str]:
    parser = LexborHTMLParser(html)
    title_node = parser.css_first("title")
    title = title_node.text(strip=True) if title_node else ""
    body = parser.body
    text = (body.text(deep=True, separator="\n") if body is not None
            else parser.text(deep=True, separator="\n"))
    paragraphs = [p.strip() for p in _PARA_SPLIT.split(text) if p.strip()]
    del parser
    return text, paragraphs, title


def build_record(url, title, text, paragraphs, domain, depth, agent_name) -> dict:
    import xxhash as _xx
    tokens = _WORD_RE.findall(text)
    return {
        "link": url,
        "title": title,
        "hash": _xx.xxh3_64_hexdigest(url.encode("utf-8")),
        "text": text,
        "paragraphs": paragraphs,
        "word_count": len(tokens),
        "tokens": [f'"{t}"' for t in tokens],
        "domain": domain,
        "crawled_at": int(time.time()),
        "depth": depth,
        "agent": agent_name,
    }


# ══════════════════════════════════════════════════════════════════════════════
# SESSION POOL (one AsyncSession per impersonate target)
# ══════════════════════════════════════════════════════════════════════════════
class SessionPool:
    def __init__(self, max_clients: int = 64):
        self._max = max_clients
        self._sessions: dict[str, AsyncSession] = {}
        self._lock = asyncio.Lock()

    async def get(self, impersonate: str) -> AsyncSession:
        async with self._lock:
            s = self._sessions.get(impersonate)
            if s is None:
                s = AsyncSession(max_clients=self._max, impersonate=impersonate)
                self._sessions[impersonate] = s
            return s

    async def close(self):
        for s in self._sessions.values():
            try:
                await s.close()
            except Exception:
                pass
        self._sessions.clear()


# ══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ══════════════════════════════════════════════════════════════════════════════
class Engine:
    def __init__(self, config_path: str = "config.json", base_dir: str = "."):
        self.config = Config(config_path)
        Platform.apply_runtime_policy(self.config._raw)
        Platform.gc_freeze_long_lived()

        self.folders = Folders(base_dir, self.config)
        self.resume = Resume(base_dir, self.config)
        self.writer = Writer(self.folders, self.config)
        self.health = Health(self.config)

        r = self.config.runtime
        conc = r.get("concurrency", {})
        initial = int(conc.get("initial", 128))
        cmin = int(conc.get("min", 16))
        cmax = int(conc.get("max", 1024))
        self._sem = AdaptiveSemaphore(initial, min_cap=cmin, max_cap=cmax)

        self._sessions = SessionPool(max_clients=64)
        self._buckets: dict[str, TokenBucket] = {}
        self._pending: asyncio.Queue[Item] = asyncio.Queue(
            maxsize=int(r.get("queue_maxsize", 8192)))
        self._inflight = 0
        self._tasks: set[asyncio.Task] = set()
        self._shutdown = asyncio.Event()
        self.crawler: Crawler | None = None

        # metrics
        self.success = 0
        self.fail = 0
        self.skipped = 0
        self.bytes_out = 0
        self._pps = EWMA(alpha=0.25)
        self._pps_snap = 0.0
        self._peak = 0.0
        self._last_tick = time.time()
        self._tick_pages = 0
        self._start_time = time.time()
        self._recent: deque[int] = deque(maxlen=int(conc.get("probe_window", 200)))
        self._gc_counter = 0
        self._trim_last = time.time()
        self._loop_ref = None

    # ── helpers ──────────────────────────────────────────────────────────────
    def _bucket(self, domain: str) -> TokenBucket:
        b = self._buckets.get(domain)
        if b is None:
            b = TokenBucket(rate=self.config.rate_for(domain))
            self._buckets[domain] = b
        return b

    def _install_signals(self):
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        def _handler(*_):
            log.warning("shutdown requested")
            self._shutdown.set()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handler)
            except NotImplementedError:
                try:
                    signal.signal(sig, _handler)
                except Exception:
                    pass

    # ── fetch ────────────────────────────────────────────────────────────────
    async def _fetch(self, item: Item):
        domain = item.domain
        if not self.health.is_scrapeable(domain):
            self.skipped += 1
            return None
        agent_name = self.config.agent_for(domain)
        resolved = self.config.resolve_agent(agent_name)
        await self._bucket(domain).take(1.0)
        session = await self._sessions.get(resolved["impersonate"])
        try:
            r = await asyncio.wait_for(
                session.get(item.url, headers=resolved["headers"], timeout=15),
                timeout=20,
            )
        except Exception:
            self._record_fail(domain, agent_name)
            self.health.mark_unreachable(domain)
            return None

        ctype = (r.headers.get("content-type") or "").lower()
        if ctype and not any(t in ctype for t in _HTML_TYPES):
            self.skipped += 1
            return None

        body_text = r.text or ""
        if r.status_code in (403, 429, 503) or r.status_code >= 500:
            reason = self.health.detect_block(body_text) or f"http_{r.status_code}"
            self.health.mark_block(domain)
            self._record_fail(domain, agent_name)
            await self.config.record_failure(domain, agent_name)
            log.debug("block %s: %s", domain, reason)
            return None
        if r.status_code >= 400:
            self._record_fail(domain, agent_name)
            self.health.mark_unreachable(domain)
            return None
        if not body_text:
            self._record_fail(domain, agent_name)
            return None

        # soft block detection
        detected = self.health.detect_block(body_text)
        if detected:
            self.health.mark_block(domain)
            self._record_fail(domain, agent_name)
            await self.config.record_failure(domain, agent_name)
            log.debug("soft block %s: %s", domain, detected)
            return None

        self.health.mark_ok(domain)
        return body_text, agent_name

    def _record_fail(self, domain: str, agent_name: str):
        self.fail += 1
        self._recent.append(0)

    def _record_ok(self, domain: str, agent_name: str):
        self.success += 1
        self._tick_pages += 1
        self._recent.append(1)

    # ── process ──────────────────────────────────────────────────────────────
    async def _process(self, item: Item):
        if self.resume.is_known(item.url):
            self.skipped += 1
            return
        fetched = await self._fetch(item)
        if fetched is None:
            max_attempts = int(self.config.runtime.get("max_attempts", 3))
            if item.attempt + 1 < max_attempts:
                item.attempt += 1
                try:
                    self._pending.put_nowait(item)
                except asyncio.QueueFull:
                    pass
            return
        html, agent_name = fetched
        try:
            text, paragraphs, title = extract(html)
        except Exception as e:
            log.debug("parse fail %s: %s", item.url, e)
            self._record_fail(item.domain, agent_name)
            return
        rec = build_record(item.url, title, text, paragraphs,
                           item.domain, item.depth, agent_name)
        await self.writer.write(rec)
        await self.resume.add(item.url)
        await self.config.record_success(item.domain, agent_name)
        self._record_ok(item.domain, agent_name)
        self.bytes_out += len(text.encode("utf-8"))

        if self.crawler is not None:
            self.crawler.inject(html, item.url, item.depth)

        self._gc_counter += 1
        if self._gc_counter >= int(self.config.runtime.get("gc_collect_every_n_pages", 10000)):
            gc.collect()
            self._gc_counter = 0
        if time.time() - self._trim_last > float(
                self.config.runtime.get("memory_trim_interval_seconds", 30.0)):
            Platform.malloc_trim()
            self._trim_last = time.time()

    # ── scheduler ────────────────────────────────────────────────────────────
    async def _task_wrapper(self, item: Item):
        self._inflight += 1
        try:
            await self._sem.acquire()
            try:
                await self._process(item)
            finally:
                self._sem.release()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("task error %s: %s", item.url, e)
        finally:
            self._inflight -= 1

    async def _scheduler(self):
        while not self._shutdown.is_set():
            try:
                item = await asyncio.wait_for(self._pending.get(), timeout=0.25)
            except asyncio.TimeoutError:
                if self._inflight == 0 and (self.crawler is None or not self.crawler.frontier):
                    break
                continue
            t = asyncio.create_task(self._task_wrapper(item))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    async def _drain_frontier_loop(self):
        while not self._shutdown.is_set():
            if self.crawler is not None:
                while self.crawler.frontier and not self._shutdown.is_set():
                    if self._pending.qsize() > 512:
                        break
                    popped = self.crawler.frontier.pop()
                    if popped is None:
                        break
                    url, depth = popped
                    domain = urlparse(url).netloc
                    try:
                        self._pending.put_nowait(Item(url, domain, depth))
                    except asyncio.QueueFull:
                        break
            await asyncio.sleep(0.1)

    async def _adaptive_loop(self):
        conc = self.config.runtime.get("concurrency", {})
        up = float(conc.get("scale_up_threshold", 0.95))
        down = float(conc.get("scale_down_threshold", 0.75))
        interval = float(conc.get("interval_seconds", 3.0))
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            if len(self._recent) < 50:
                continue
            rate = sum(self._recent) / len(self._recent)
            cur = self._sem.capacity
            if rate > up and cur < self._sem._max:
                self._sem.resize(int(cur * 1.25))
                log.info("concurrency ↑ %d → %d (ok=%.2f)", cur, self._sem.capacity, rate)
            elif rate < down and cur > self._sem._min:
                self._sem.resize(int(cur * 0.80))
                log.info("concurrency ↓ %d → %d (ok=%.2f)", cur, self._sem.capacity, rate)

    async def _metrics_loop(self):
        interval = float(self.config.runtime.get("metrics_interval_seconds", 1.0))
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            now = time.time()
            dt = now - self._last_tick
            if dt > 0:
                inst = self._tick_pages / dt
                self._pps_snap = self._pps.update(inst)
                self._peak = max(self._peak, self._pps_snap)
            self._tick_pages = 0
            self._last_tick = now

    async def _flush_loop(self):
        interval = float(self.config.runtime.get("flush_interval_seconds", 5.0))
        last_snapshot = time.time()
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            try:
                await self.writer.flush_all()
                await self.resume.flush()
                if time.time() - last_snapshot > 60:
                    await self.resume.snapshot()
                    last_snapshot = time.time()
            except Exception as e:
                log.warning("flush loop: %s", e)

    async def _health_loop(self):
        interval = float(self.config.health_cfg.get("sweep_interval_seconds", 60))
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            stale = [d for d, s in self.health.states.items()
                     if s.status in ("BLOCKED", "UNREACHABLE") and time.time() >= s.retry_at]
            if stale:
                log.info("re-checking %d stale domains", len(stale))
                for d in stale[:50]:
                    self.health.state(d).status = "UNKNOWN"

    # ── run ──────────────────────────────────────────────────────────────────
    async def run(self, seed_urls: list[str]):
        self._install_signals()
        for u in seed_urls:
            norm = normalize_url(u)
            if not norm:
                continue
            try:
                self._pending.put_nowait(Item(norm, urlparse(norm).netloc, 0))
            except asyncio.QueueFull:
                log.warning("queue full at seed; dropping %s", norm)

        if self.crawler is None and seed_urls:
            self.crawler = Crawler(self.config, normalize_url(seed_urls[0]))

        loops = [
            asyncio.create_task(self._scheduler(), name="scheduler"),
            asyncio.create_task(self._adaptive_loop(), name="adaptive"),
            asyncio.create_task(self._metrics_loop(), name="metrics"),
            asyncio.create_task(self._flush_loop(), name="flush"),
            asyncio.create_task(self._health_loop(), name="health"),
            asyncio.create_task(self._drain_frontier_loop(), name="drain"),
        ]
        try:
            while not self._shutdown.is_set():
                if (self._pending.empty() and self._inflight == 0
                        and (self.crawler is None or not self.crawler.frontier)):
                    await asyncio.sleep(1.0)
                    if (self._pending.empty() and self._inflight == 0
                            and (self.crawler is None or not self.crawler.frontier)):
                        break
                await asyncio.sleep(0.25)
        finally:
            for lp in loops:
                lp.cancel()
            await asyncio.gather(*loops, return_exceptions=True)
            if self._tasks:
                log.info("draining %d inflight tasks", len(self._tasks))
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self._tasks, return_exceptions=True),
                        timeout=15.0,
                    )
                except asyncio.TimeoutError:
                    for t in self._tasks:
                        t.cancel()
            try:
                await self.writer.flush_all()
                await self.resume.flush()
                await self.resume.snapshot()
            except Exception as e:
                log.warning("final flush: %s", e)
            await self._sessions.close()
            self._log_summary()

    def metrics(self) -> dict:
        return {
            "success": self.success,
            "failures": self.fail,
            "skipped": self.skipped,
            "pages_per_sec": round(self._pps_snap, 2),
            "peak_pps": round(self._peak, 2),
            "data_size_mb": round(self.bytes_out / (1024 * 1024), 3),
            "known_urls": len(self.resume.known),
            "inflight": self._inflight,
            "queued": self._pending.qsize(),
            "concurrency": self._sem.capacity,
            "uptime": round(time.time() - self._start_time, 1),
        }

    def _log_summary(self):
        m = self.metrics()
        total = m["success"] + m["failures"]
        rate = (m["success"] / total * 100) if total else 0.0
        log.info("═" * 56)
        log.info("Fa-Scrap summary")
        log.info("  duration     : %ss", m["uptime"])
        log.info("  pages ok     : %d", m["success"])
        log.info("  failures     : %d", m["failures"])
        log.info("  skipped      : %d", m["skipped"])
        log.info("  success rate : %.2f%%", rate)
        log.info("  mean pps     : %.2f", m["pages_per_sec"])
        log.info("  peak pps     : %.2f", m["peak_pps"])
        log.info("  data written : %.2f MB", m["data_size_mb"])
        log.info("  unique URLs  : %d", m["known_urls"])
        log.info("═" * 56)


# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL MODE
# ══════════════════════════════════════════════════════════════════════════════
async def _run_terminal(engine: Engine, urls: list[str]):
    from tqdm import tqdm
    pbar = tqdm(total=None, desc="Fa-Scrap", unit="page",
                dynamic_ncols=True, smoothing=0.05)
    stop = asyncio.Event()

    async def monitor():
        while not stop.is_set():
            await asyncio.sleep(0.5)
            m = engine.metrics()
            pbar.set_postfix({
                "ok": m["success"], "fail": m["failures"],
                "pps": m["pages_per_sec"], "c": m["concurrency"],
                "MB": m["data_size_mb"],
            })
            pbar.n = m["success"]
            pbar.refresh()

    mon = asyncio.create_task(monitor())
    try:
        await engine.run(urls)
    finally:
        stop.set()
        await asyncio.sleep(0.6)
        mon.cancel()
        try:
            await mon
        except asyncio.CancelledError:
            pass
        pbar.close()


# ══════════════════════════════════════════════════════════════════════════════
# CLI — three parsers, per spec.
# ══════════════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    """Parser #1 — universal help parser."""
    p = argparse.ArgumentParser(
        prog="Fa-Scrap.py",
        description="Fa-Scrap — autonomous scraper/crawler. GUI by default.",
        epilog=(
            "Examples:\n"
            "  python Fa-Scrap.py                    GUI opens\n"
            "  python Fa-Scrap.py https://x.com      GUI, prefilled, autostarts\n"
            "  python Fa-Scrap.py -T                 Terminal, prompts for URL\n"
            "  python Fa-Scrap.py -T https://x.com   Terminal, immediate start\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="mode")
    # Parser #2 — terminal
    pt = sub.add_parser("T", help="Terminal interactive mode (tqdm)",
                       aliases=["-T"], add_help=True)
    pt.add_argument("url", nargs="?", default=None, help="Optional seed URL")
    # Parser #3 — GUI
    pg = sub.add_parser("G", help="GUI mode (default when no flag)",
                       aliases=["-G"], add_help=True)
    pg.add_argument("url", nargs="?", default=None, help="Optional seed URL")

    # Support `-T <url>` / `-G <url>` legacy shorthand too.
    p.add_argument("-T", "--terminal", dest="terminal_flag",
                   action="store_true", help=argparse.SUPPRESS)
    p.add_argument("-G", "--gui", dest="gui_flag",
                   action="store_true", help=argparse.SUPPRESS)
    p.add_argument("url_pos", nargs="?", default=None, help=argparse.SUPPRESS)
    return p


def _configure_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main():
    _configure_logging()
    parser = build_parser()
    args = parser.parse_args()

    # Resolve mode + url from the various accepted forms.
    mode = None
    url = None
    if args.mode in ("T", "-T") or args.terminal_flag:
        mode = "T"
        url = getattr(args, "url", None) or args.url_pos
    elif args.mode in ("G", "-G") or args.gui_flag:
        mode = "G"
        url = getattr(args, "url", None) or args.url_pos
    else:
        mode = "G"
        url = args.url_pos

    # Bare invocation with no args → GUI opens empty.
    config_path = Path(__file__).with_name("config.json")

    if mode == "T":
        if not url:
            try:
                url = input("URL: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(0)
        if not url:
            print("No URL given.", file=sys.stderr)
            sys.exit(2)
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        engine = Engine(str(config_path))
        try:
            asyncio.run(_run_terminal(engine, [url]))
        except KeyboardInterrupt:
            log.warning("interrupted")
        sys.exit(0)

    # GUI mode
    engine = Engine(str(config_path))
    try:
        from Fa_FUI import launch
    except Exception as e:
        log.error("GUI unavailable (%s). Falling back to terminal.", e)
        if not url:
            try:
                url = input("URL: ").strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)
        if not url:
            sys.exit(2)
        asyncio.run(_run_terminal(engine, [url]))
        sys.exit(0)
    autostart = bool(url)
    sys.exit(launch(engine, initial_url=url or "", autostart=autostart))


if __name__ == "__main__":
    main()