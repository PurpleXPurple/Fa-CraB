#!/usr/bin/env python3
"""
Fa_Scrap.py — Fa-Scrap main engine.

Usage:
    python Fa_Scrap.py                    GUI opens, paste a URL
    python Fa_Scrap.py <url>              GUI opens, prefilled, autostarts
    python Fa_Scrap.py -T                 Terminal, prompts for URL
    python Fa_Scrap.py -T <url>           Terminal, immediate start
    python Fa_Scrap.py -G <url>           GUI, explicit
    python Fa_Scrap.py --help             Help

That is the entire user surface. Everything else is autonomous.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import logging
import re
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession
from selectolax.lexbor import LexborHTMLParser

from State import (
    AdaptiveSemaphore, Config, EWMA, Folders, Health, Platform, Resume,
    TokenBucket, Writer, normalize_url,
)
from Fa_Crawl import Crawler

log = logging.getLogger("fa.scrap")


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════
_WORD_RE = re.compile(r"\S+")
_PARA_SPLIT = re.compile(r"\n\s*\n")
_HTML_TYPES = ("text/html", "application/xhtml+xml")
_IS_WINDOWS = sys.platform.startswith("win")


# ══════════════════════════════════════════════════════════════════════════════
# TYPE-SAFE CONFIG READERS
# ══════════════════════════════════════════════════════════════════════════════
def _safe_int(v: Any, default: int,
              lo: Optional[int] = None, hi: Optional[int] = None) -> int:
    if isinstance(v, bool):
        out = int(v)
    elif isinstance(v, int):
        out = v
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            return default
        out = int(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            out = int(s, 10)
        except ValueError:
            try:
                out = int(float(s))
            except (ValueError, OverflowError):
                return default
    else:
        return default
    if lo is not None and out < lo:
        out = lo
    if hi is not None and out > hi:
        out = hi
    return out


def _safe_float(v: Any, default: float,
                lo: Optional[float] = None,
                hi: Optional[float] = None) -> float:
    if isinstance(v, bool):
        out = float(int(v))
    elif isinstance(v, (int, float)):
        out = float(v)
    elif isinstance(v, str):
        s = v.strip()
        if not s:
            return default
        try:
            out = float(s)
        except ValueError:
            return default
    else:
        return default
    if out != out or out in (float("inf"), float("-inf")):
        return default
    if lo is not None and out < lo:
        out = lo
    if hi is not None and out > hi:
        out = hi
    return out


def _safe_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


def _cfg_get(cfg_obj: Any, section: str, key: str, default: Any) -> Any:
    """Read cfg.<section>[key] with full type safety."""
    try:
        d = getattr(cfg_obj, section, None)
        if callable(d):
            d = d()
        d = _safe_dict(d)
        return d.get(key, default)
    except Exception:
        return default


# ══════════════════════════════════════════════════════════════════════════════
# WORK ITEM
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
    """Return (text, paragraphs, title). Never raises."""
    if not html:
        return "", [], ""
    parser = None
    try:
        parser = LexborHTMLParser(html)
    except Exception:
        return "", [], ""
    try:
        title_node = parser.css_first("title")
        title = ""
        if title_node is not None:
            try:
                title = title_node.text(strip=True) or ""
            except Exception:
                title = ""
        body = parser.body
        if body is not None:
            text = body.text(deep=True, separator="\n") or ""
        else:
            text = parser.text(deep=True, separator="\n") or ""
        paragraphs = [p.strip() for p in _PARA_SPLIT.split(text) if p.strip()]
        return text, paragraphs, title
    except Exception:
        return "", [], ""
    finally:
        try:
            del parser
        except Exception:
            pass


def build_record(url: str, title: str, text: str, paragraphs: list[str],
                 domain: str, depth: int, agent_name: str) -> dict:
    import xxhash as _xx
    tokens = _WORD_RE.findall(text) if text else []
    try:
        h = _xx.xxh3_64_hexdigest(url.encode("utf-8"))
    except Exception:
        h = ""
    return {
        "link": url,
        "title": title,
        "hash": h,
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
# SESSION POOL
# ══════════════════════════════════════════════════════════════════════════════
class SessionPool:
    """
    One AsyncSession per impersonate target.

    Note: curl_cffi's AsyncSession does NOT accept `impersonate` in its
    constructor on any released version. Impersonation is passed per-request.
    This pool simply ensures separate cookie jars and connection pools per
    fingerprint identity.
    """

    def __init__(self, max_clients: int = 64):
        self._max = _safe_int(max_clients, 64, lo=1, hi=1024)
        self._sessions: dict[str, AsyncSession] = {}
        self._lock = asyncio.Lock()

    async def get(self, impersonate: str) -> AsyncSession:
        key = impersonate or "chrome"
        async with self._lock:
            s = self._sessions.get(key)
            if s is None:
                s = AsyncSession(max_clients=self._max)
                self._sessions[key] = s
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

        # Platform policy first — sets nice, scheduler, mallopt
        try:
            raw = getattr(self.config, "raw", None) or getattr(
                self.config, "_raw", None) or {}
            Platform.apply_runtime_policy(raw if isinstance(raw, dict) else {})
        except Exception as e:
            log.debug("platform policy skipped: %s", e)

        try:
            Platform.gc_freeze_long_lived()
        except Exception:
            pass

        # Subsystems
        self.folders = Folders(base_dir, self.config)
        self.resume = Resume(base_dir, self.config)
        self.writer = Writer(self.folders, self.config)
        self.health = Health(self.config)

        # Concurrency / runtime config (all reads type-safe)
        initial = _safe_int(_cfg_get(self.config, "runtime", "concurrency", {}),
                            0) if False else 0
        conc_cfg = _cfg_get(self.config, "runtime", "concurrency", {})
        conc_cfg = _safe_dict(conc_cfg)
        initial = _safe_int(conc_cfg.get("initial", 128), 128, lo=1, hi=8192)
        cmin = _safe_int(conc_cfg.get("min", 16), 16, lo=1, hi=8192)
        cmax = _safe_int(conc_cfg.get("max", 1024), 1024, lo=cmin, hi=16384)

        self._sem = AdaptiveSemaphore(initial, min_cap=cmin, max_cap=cmax)
        self._sessions = SessionPool(max_clients=64)
        self._buckets: dict[str, TokenBucket] = {}

        queue_max = _safe_int(
            _cfg_get(self.config, "runtime", "queue_maxsize", 8192),
            8192, lo=64, hi=1_000_000)
        self._pending: asyncio.Queue[Item] = asyncio.Queue(maxsize=queue_max)

        self._inflight = 0
        self._tasks: set[asyncio.Task] = set()
        self._shutdown = asyncio.Event()
        self._crawler: Optional[Crawler] = None
        self._loop_ref: Optional[asyncio.AbstractEventLoop] = None

        # Metrics
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
        probe_win = _safe_int(
            conc_cfg.get("probe_window", 200), 200, lo=10, hi=10000)
        self._recent: list[int] = []
        self._recent_cap = probe_win
        self._recent_head = 0

        self._gc_counter = 0
        self._gc_every = _safe_int(
            _cfg_get(self.config, "runtime", "gc_collect_every_n_pages", 10000),
            10000, lo=100, hi=1_000_000)
        self._trim_every = _safe_float(
            _cfg_get(self.config, "runtime", "memory_trim_interval_seconds", 30.0),
            30.0, lo=5.0, hi=600.0)
        self._trim_last = time.time()

        self._log_cfg_summary()

    # ── helpers ──────────────────────────────────────────────────────────────
    def _log_cfg_summary(self):
        try:
            log.info("config: %d sites, %d agents, resume known=%d",
                     len(self.config.site_names()),
                     len(self.config.agent_names()),
                     len(self.resume.known))
        except Exception:
            pass

    def _bucket(self, domain: str) -> TokenBucket:
        b = self._buckets.get(domain)
        if b is None:
            rate = 2.0
            try:
                rate = _safe_float(self.config.rate_for(domain), 2.0, lo=0.0, hi=1000.0)
            except Exception:
                pass
            b = TokenBucket(rate=rate)
            self._buckets[domain] = b
        return b

    def _pick_agent_for(self, item: Item) -> str:
        """First attempt uses config-specified agent. Retries rotate through
        the health.probe_agents_order fallback list."""
        if item.attempt <= 0:
            try:
                return self.config.agent_for(item.domain)
            except Exception:
                return "chrome146_win"
        try:
            order = self.config.health_cfg.get("probe_agents_order", [])
            if isinstance(order, list) and order:
                return str(order[(item.attempt - 1) % len(order)])
        except Exception:
            pass
        try:
            return self.config.agent_for(item.domain)
        except Exception:
            return "chrome146_win"

    def _record_fail(self, domain: str):
        self.fail += 1
        self._push_recent(0)

    def _record_ok(self, domain: str):
        self.success += 1
        self._tick_pages += 1
        self._push_recent(1)

    def _push_recent(self, v: int):
        if len(self._recent) < self._recent_cap:
            self._recent.append(v)
        else:
            self._recent[self._recent_head] = v
            self._recent_head = (self._recent_head + 1) % self._recent_cap

    # ── signal wiring ────────────────────────────────────────────────────────
    def _install_signals(self):
        """Signal handlers only on Unix; Windows relies on KeyboardInterrupt."""
        if _IS_WINDOWS:
            return
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
            except (NotImplementedError, RuntimeError, ValueError):
                pass

    # ── fetch ────────────────────────────────────────────────────────────────
    async def _fetch(self, item: Item) -> Optional[tuple[str, str]]:
        domain = item.domain
        if not self.health.is_scrapeable(domain):
            self.skipped += 1
            return None

        agent_name = self._pick_agent_for(item)
        try:
            resolved = self.config.resolve_agent(agent_name)
        except Exception:
            resolved = {
                "impersonate": "chrome146",
                "headers": {"User-Agent": "Mozilla/5.0"},
            }

        impersonate = resolved.get("impersonate") or "chrome146"
        headers = resolved.get("headers") or {}

        await self._bucket(domain).take(1.0)

        try:
            session = await self._sessions.get(impersonate)
        except Exception:
            self._record_fail(domain)
            return None

        timeout_s = _safe_float(
            _cfg_get(self.config, "runtime", "timeout_seconds", 15.0),
            15.0, lo=1.0, hi=120.0)

        try:
            r = await asyncio.wait_for(
                session.get(
                    item.url,
                    impersonate=impersonate,
                    headers=headers,
                    timeout=timeout_s,
                    allow_redirects=True,
                ),
                timeout=timeout_s + 5.0,
            )
        except Exception as e:
            log.debug("fetch error %s: %s", item.url, e)
            self._record_fail(domain)
            try:
                self.health.mark_unreachable(domain)
            except Exception:
                pass
            return None

        # content-type gate
        try:
            ctype = (r.headers.get("content-type") or "").lower()
        except Exception:
            ctype = ""
        if ctype and not any(t in ctype for t in _HTML_TYPES):
            self.skipped += 1
            return None

        body = r.text or ""

        # hard block signals
        if r.status_code in (403, 429, 503) or r.status_code >= 500:
            try:
                reason = self.health.detect_block(body) or f"http_{r.status_code}"
            except Exception:
                reason = f"http_{r.status_code}"
            try:
                self.health.mark_block(domain)
            except Exception:
                pass
            self._record_fail(domain)
            try:
                await self.config.record_failure(domain, agent_name)
            except Exception:
                pass
            log.debug("block %s: %s", domain, reason)
            return None

        if r.status_code >= 400:
            self._record_fail(domain)
            try:
                self.health.mark_unreachable(domain)
            except Exception:
                pass
            return None

        if not body:
            self._record_fail(domain)
            return None

        # soft block (body-level detection)
        try:
            detected = self.health.detect_block(body)
        except Exception:
            detected = None
        if detected:
            try:
                self.health.mark_block(domain)
            except Exception:
                pass
            self._record_fail(domain)
            try:
                await self.config.record_failure(domain, agent_name)
            except Exception:
                pass
            log.debug("soft block %s: %s", domain, detected)
            return None

        try:
            self.health.mark_ok(domain)
        except Exception:
            pass
        return body, agent_name

    # ── process ──────────────────────────────────────────────────────────────
    async def _process(self, item: Item):
        # Resume cache check
        try:
            if self.resume.is_known(item.url):
                self.skipped += 1
                return
        except Exception:
            pass

        result = await self._fetch(item)
        if result is None:
            max_attempts = _safe_int(
                _cfg_get(self.config, "runtime", "max_attempts", 3),
                3, lo=1, hi=10)
            if item.attempt + 1 < max_attempts:
                item.attempt += 1
                try:
                    self._pending.put_nowait(item)
                except asyncio.QueueFull:
                    pass
            return

        html, agent_name = result

        try:
            text, paragraphs, title = extract(html)
        except Exception as e:
            log.debug("parse fail %s: %s", item.url, e)
            self._record_fail(item.domain)
            return

        record = build_record(item.url, title, text, paragraphs,
                              item.domain, item.depth, agent_name)

        try:
            await self.writer.write(record)
        except Exception as e:
            log.debug("writer fail %s: %s", item.url, e)
            self._record_fail(item.domain)
            return

        try:
            await self.resume.add(item.url)
        except Exception:
            pass

        try:
            await self.config.record_success(item.domain, agent_name)
        except Exception:
            pass

        self._record_ok(item.domain)
        self.bytes_out += len(text.encode("utf-8", errors="ignore"))

        # Feed crawler
        if self._crawler is not None:
            try:
                self._crawler.inject(html, item.url, item.depth)
            except Exception as e:
                log.debug("crawler inject fail %s: %s", item.url, e)

        # GC / trim
        self._gc_counter += 1
        if self._gc_counter >= self._gc_every:
            try:
                gc.collect()
            except Exception:
                pass
            self._gc_counter = 0
        if time.time() - self._trim_last > self._trim_every:
            try:
                Platform.malloc_trim()
            except Exception:
                pass
            self._trim_last = time.time()

    # ── task wrapper ─────────────────────────────────────────────────────────
    async def _task_wrapper(self, item: Item):
        self._inflight += 1
        try:
            await self._sem.acquire()
            try:
                await self._process(item)
            finally:
                try:
                    self._sem.release()
                except Exception:
                    pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.debug("task error %s: %s", item.url, e)
        finally:
            self._inflight -= 1

    # ── scheduler ────────────────────────────────────────────────────────────
    async def _scheduler(self):
        """
        Single source of work dispatch. Priority:
            1. Retry queue (_pending).
            2. Crawler frontier.
        When neither has work, sleeps 50ms. Never exits on its own — the
        run loop decides when work is fully drained.
        """
        while not self._shutdown.is_set():
            item: Optional[Item] = None

            try:
                item = self._pending.get_nowait()
            except asyncio.QueueEmpty:
                pass
            except Exception:
                pass

            if item is None and self._crawler is not None:
                try:
                    popped = self._crawler.frontier.pop()
                except Exception:
                    popped = None
                if popped is not None:
                    url, depth = popped
                    try:
                        domain = urlparse(url).netloc
                    except Exception:
                        domain = ""
                    item = Item(url, domain, depth)

            if item is None:
                await asyncio.sleep(0.05)
                continue

            t = asyncio.create_task(self._task_wrapper(item))
            self._tasks.add(t)
            t.add_done_callback(self._tasks.discard)

    # ── background loops ─────────────────────────────────────────────────────
    async def _adaptive_loop(self):
        conc_cfg = _safe_dict(_cfg_get(self.config, "runtime", "concurrency", {}))
        up = _safe_float(conc_cfg.get("scale_up_threshold", 0.95), 0.95,
                         lo=0.5, hi=1.0)
        down = _safe_float(conc_cfg.get("scale_down_threshold", 0.75), 0.75,
                           lo=0.1, hi=0.95)
        interval = _safe_float(conc_cfg.get("interval_seconds", 3.0), 3.0,
                               lo=0.5, hi=60.0)
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            if len(self._recent) < 50:
                continue
            try:
                rate = sum(self._recent) / len(self._recent)
            except Exception:
                continue
            cur = self._sem.capacity
            if rate > up and cur < self._sem._max:
                try:
                    self._sem.resize(int(cur * 1.25))
                    log.info("concurrency up %d -> %d (ok=%.2f)",
                             cur, self._sem.capacity, rate)
                except Exception:
                    pass
            elif rate < down and cur > self._sem._min:
                try:
                    self._sem.resize(int(cur * 0.80))
                    log.info("concurrency down %d -> %d (ok=%.2f)",
                             cur, self._sem.capacity, rate)
                except Exception:
                    pass

    async def _metrics_loop(self):
        interval = _safe_float(
            _cfg_get(self.config, "runtime", "metrics_interval_seconds", 1.0),
            1.0, lo=0.1, hi=10.0)
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            now = time.time()
            dt = now - self._last_tick
            if dt > 0:
                inst = self._tick_pages / dt
                self._pps_snap = self._pps.update(inst)
                if self._pps_snap > self._peak:
                    self._peak = self._pps_snap
            self._tick_pages = 0
            self._last_tick = now

    async def _flush_loop(self):
        interval = _safe_float(
            _cfg_get(self.config, "runtime", "flush_interval_seconds", 5.0),
            5.0, lo=1.0, hi=120.0)
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
                log.debug("flush loop: %s", e)

    async def _health_loop(self):
        interval = _safe_float(
            self.config.health_cfg.get("sweep_interval_seconds", 60),
            60.0, lo=5.0, hi=3600.0)
        while not self._shutdown.is_set():
            await asyncio.sleep(interval)
            try:
                stale = [d for d, s in self.health.states.items()
                         if s.status in ("BLOCKED", "UNREACHABLE")
                         and time.time() >= s.retry_at]
            except Exception:
                continue
            if stale:
                log.info("re-checking %d stale domains", len(stale))
                for d in stale[:50]:
                    try:
                        self.health.state(d).status = "UNKNOWN"
                    except Exception:
                        pass

    # ── idle detection ───────────────────────────────────────────────────────
    def _is_idle(self) -> bool:
        if self._inflight > 0:
            return False
        try:
            if not self._pending.empty():
                return False
        except Exception:
            pass
        if self._crawler is not None:
            try:
                if self._crawler.frontier:
                    return False
            except Exception:
                pass
        return True

    # ── run ──────────────────────────────────────────────────────────────────
    async def run(self, seed_urls: list[str]):
        self._install_signals()

        # ── seed ─────────────────────────────────────────────────────────────
        cleaned = [u for u in (normalize_url(u) for u in seed_urls) if u]
        if not cleaned:
            log.warning("no valid seed URLs")
            return

        # First seed anchors the crawler (which itself seeds its frontier).
        if self._crawler is None:
            try:
                self._crawler = Crawler(self.config, cleaned[0])
            except Exception as e:
                log.warning("crawler init failed: %s", e)
                self._crawler = None

        # Extra seeds go through the retry queue so they get dispatched too.
        for u in cleaned[1:]:
            try:
                self._pending.put_nowait(Item(u, urlparse(u).netloc, 0))
            except asyncio.QueueFull:
                log.warning("queue full at seed; dropping %s", u)

        # ── background loops ─────────────────────────────────────────────────
        loops = [
            asyncio.create_task(self._scheduler(), name="scheduler"),
            asyncio.create_task(self._adaptive_loop(), name="adaptive"),
            asyncio.create_task(self._metrics_loop(), name="metrics"),
            asyncio.create_task(self._flush_loop(), name="flush"),
            asyncio.create_task(self._health_loop(), name="health"),
        ]

        # ── main wait ────────────────────────────────────────────────────────
        idle_streak = 0
        try:
            while not self._shutdown.is_set():
                if self._is_idle():
                    idle_streak += 1
                    if idle_streak >= 4:   # ~1s idle
                        break
                else:
                    idle_streak = 0
                await asyncio.sleep(0.25)
        finally:
            # ── shutdown ─────────────────────────────────────────────────────
            self._shutdown.set()
            for lp in loops:
                lp.cancel()
            try:
                await asyncio.gather(*loops, return_exceptions=True)
            except Exception:
                pass

            if self._tasks:
                log.info("draining %d inflight tasks", len(self._tasks))
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*self._tasks, return_exceptions=True),
                        timeout=15.0,
                    )
                except asyncio.TimeoutError:
                    for t in self._tasks:
                        try:
                            t.cancel()
                        except Exception:
                            pass
                except Exception:
                    pass

            try:
                await self.writer.flush_all()
                await self.resume.flush()
                await self.resume.snapshot()
            except Exception as e:
                log.warning("final flush: %s", e)

            try:
                await self._sessions.close()
            except Exception:
                pass

            try:
                self.config.save()
            except Exception:
                pass

            self._log_summary()

    # ── metrics / reporting ──────────────────────────────────────────────────
    def metrics(self) -> dict:
        try:
            known = len(self.resume.known)
        except Exception:
            known = 0
        return {
            "success": self.success,
            "failures": self.fail,
            "skipped": self.skipped,
            "pages_per_sec": round(self._pps_snap, 2),
            "peak_pps": round(self._peak, 2),
            "data_size_mb": round(self.bytes_out / (1024 * 1024), 3),
            "known_urls": known,
            "inflight": self._inflight,
            "queued": self._pending.qsize(),
            "concurrency": self._sem.capacity,
            "uptime": round(time.time() - self._start_time, 1),
        }

    def _log_summary(self):
        m = self.metrics()
        total = m["success"] + m["failures"]
        rate = (m["success"] / total * 100) if total else 0.0
        log.info("=" * 56)
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
        log.info("=" * 56)


# ══════════════════════════════════════════════════════════════════════════════
# TERMINAL MODE
# ══════════════════════════════════════════════════════════════════════════════
async def _run_terminal(engine: Engine, urls: list[str]):
    try:
        from tqdm import tqdm
    except Exception:
        # Fallback: no tqdm, just run
        await engine.run(urls)
        return

    pbar = tqdm(total=None, desc="Fa-Scrap", unit="page",
                dynamic_ncols=True, smoothing=0.05)
    stop = asyncio.Event()

    async def monitor():
        while not stop.is_set():
            try:
                await asyncio.sleep(0.5)
                m = engine.metrics()
                pbar.set_postfix({
                    "ok": m["success"],
                    "fail": m["failures"],
                    "pps": m["pages_per_sec"],
                    "c": m["concurrency"],
                    "MB": m["data_size_mb"],
                })
                if m["success"] > pbar.n:
                    pbar.n = m["success"]
                    pbar.refresh()
            except Exception:
                pass

    mon = asyncio.create_task(monitor())
    try:
        await engine.run(urls)
    finally:
        stop.set()
        await asyncio.sleep(0.6)
        mon.cancel()
        try:
            await mon
        except (asyncio.CancelledError, Exception):
            pass
        try:
            pbar.close()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# LOGGING
# ══════════════════════════════════════════════════════════════════════════════
def _configure_logging():
    try:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%H:%M:%S",
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="Fa_Scrap.py",
        description="Fa-Scrap — autonomous scraper/crawler. GUI by default.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python Fa_Scrap.py                       GUI opens, paste a URL\n"
            "  python Fa_Scrap.py https://example.com   GUI opens, prefilled\n"
            "  python Fa_Scrap.py -T                    Terminal prompt for URL\n"
            "  python Fa_Scrap.py -T https://example.com  Terminal, immediate\n"
            "  python Fa_Scrap.py -G https://example.com  GUI, explicit\n"
        ),
    )
    p.add_argument("-T", "--terminal", action="store_true",
                   help="Terminal interactive mode with tqdm")
    p.add_argument("-G", "--gui", action="store_true",
                   help="GUI mode (default when no flag)")
    p.add_argument("url", nargs="?", default=None,
                   help="Optional seed URL")
    return p


def _normalize_seed(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _config_path() -> str:
    try:
        here = Path(__file__).resolve().parent
    except Exception:
        here = Path.cwd()
    candidate = here / "config.json"
    if candidate.exists():
        return str(candidate)
    # Fall back to cwd
    cwd_candidate = Path.cwd() / "config.json"
    if cwd_candidate.exists():
        return str(cwd_candidate)
    return "config.json"


def _run_terminal_mode(url: Optional[str]) -> int:
    if not url:
        try:
            url = input("URL: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
    url = _normalize_seed(url)
    if not url:
        print("No URL given.", file=sys.stderr)
        return 2
    try:
        engine = Engine(_config_path())
    except Exception as e:
        log.error("engine init failed: %s", e)
        return 1
    try:
        asyncio.run(_run_terminal(engine, [url]))
    except KeyboardInterrupt:
        log.warning("interrupted")
    return 0


def _run_gui_mode(url: Optional[str]) -> int:
    try:
        engine = Engine(_config_path())
    except Exception as e:
        log.error("engine init failed: %s", e)
        return 1

    try:
        from Fa_FUI import launch
    except Exception as e:
        log.error("GUI unavailable (%s). Falling back to terminal.", e)
        return _run_terminal_mode(url)

    normalized = _normalize_seed(url) if url else ""
    autostart = bool(normalized)
    try:
        return launch(engine, initial_url=normalized, autostart=autostart)
    except Exception as e:
        log.error("GUI runtime error: %s", e)
        return _run_terminal_mode(url)


def main() -> int:
    _configure_logging()
    parser = build_parser()
    args = parser.parse_args()

    if args.terminal:
        return _run_terminal_mode(args.url)

    # Default: GUI (whether or not -G was passed explicitly)
    return _run_gui_mode(args.url)


if __name__ == "__main__":
    sys.exit(main())