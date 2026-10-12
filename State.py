#!/usr/bin/env python3
"""
State.py — Fa-Scrap substrate.

Writer now emits ONE file per batch: <domain>_<idx>.json.zst
    - Content: a JSON array of records.
    - Compression: zstd level 22.
    - No intermediate raw file, no ZIP wrapper.

Resume now uses ONE file: resume.jsonl.gz
    - Append-only gzip (multi-member) JSONL of {link, h}.
    - Reads back transparently across members.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import ctypes.util
import gc
import gzip
import logging
import os
import platform as _pyplatform
import re
import struct
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import msgspec
import orjson
import xxhash
import zstandard as zstd

log = logging.getLogger("fa.state")


# ══════════════════════════════════════════════════════════════════════════════
# REAL curl_cffi IMPERSONATE TARGETS
# ══════════════════════════════════════════════════════════════════════════════
REAL_IMPERSONATES = {
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107",
    "chrome110", "chrome116", "chrome119", "chrome120", "chrome123",
    "chrome124", "chrome131", "chrome133a", "chrome136",
    "chrome99_android", "chrome131_android",
    "edge99", "edge101",
    "safari153", "safari155", "safari170", "safari180", "safari184", "safari260",
    "safari172_ios", "safari180_ios", "safari184_ios", "safari260_ios",
    "firefox133",
    "tor145",
}

ROTATION_ORDER = [
    "chrome136", "chrome131", "chrome133a", "chrome124",
    "safari184", "safari260", "safari180", "safari170",
    "firefox133", "tor145",
    "chrome131_android", "safari184_ios",
    "edge101", "edge99",
]


def validate_impersonate(name: str) -> str:
    if not name:
        return "chrome136"
    if name in REAL_IMPERSONATES:
        return name
    stripped = re.sub(r"_(win|mac|linux|android|ios|ipad)$", "", name)
    for cand in (stripped, stripped.replace("firefox", "chrome")):
        if cand in REAL_IMPERSONATES:
            return cand
    if name.startswith("chrome"):
        return "chrome136"
    if name.startswith("safari"):
        return "safari184"
    if name.startswith("firefox"):
        return "firefox133"
    return "chrome136"


def rotate_impersonate(current: str = "") -> str:
    if current in ROTATION_ORDER:
        idx = (ROTATION_ORDER.index(current) + 1) % len(ROTATION_ORDER)
    else:
        idx = 0
    return ROTATION_ORDER[idx]


# ══════════════════════════════════════════════════════════════════════════════
# PLATFORM
# ══════════════════════════════════════════════════════════════════════════════
class Platform:
    _applied_once = False

    @staticmethod
    def apply_runtime_policy(cfg: dict):
        if Platform._applied_once:
            return
        Platform._applied_once = True
        if _pyplatform.system() != "Linux":
            return
        try:
            runtime = cfg.get("runtime", {}) if isinstance(cfg, dict) else {}
            pcfg = runtime.get("platform", {}) if isinstance(runtime, dict) else {}
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return
            libc = ctypes.CDLL(libc_path, use_errno=True)
            try:
                libc.nice(int(pcfg.get("nice", 19)))
            except Exception:
                pass
            try:
                if pcfg.get("scheduler", "SCHED_IDLE") == "SCHED_IDLE":
                    param = struct.pack("i", 0)
                    buf = ctypes.create_string_buffer(param)
                    libc.sched_setscheduler(0, 5, ctypes.byref(buf))
            except Exception:
                pass
            try:
                libc.mallopt(-8, int(pcfg.get("mallopt_arena_max", 2)))
            except Exception:
                pass
        except Exception as e:
            log.debug("platform policy apply failed: %s", e)

    @staticmethod
    def malloc_trim():
        if _pyplatform.system() != "Linux":
            return
        try:
            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                return
            libc = ctypes.CDLL(libc_path, use_errno=True)
            libc.malloc_trim(0)
        except Exception:
            pass

    @staticmethod
    def gc_freeze_long_lived():
        gc.collect()
        try:
            gc.freeze()
        except AttributeError:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════════════════
class Config:
    def __init__(self, path: str | Path = "config.json"):
        self.path = Path(path)
        if not self.path.exists():
            raise FileNotFoundError(f"config.json not found at {self.path}")
        raw = self.path.read_bytes()
        self._raw: dict = msgspec.json.decode(raw)
        self._agents: dict = self._raw.get("agents", {}) or {}
        self._profiles: dict = self._raw.get("profiles", {}) or {}
        self._sites: dict = self._raw.get("sites", {}) or {}
        self._learned: dict = self._raw.setdefault("learned", {})
        self._resolved: dict[str, dict] = {}
        self._lock = asyncio.Lock()
        self._dirty = False
        self._last_save = 0.0

    @property
    def raw(self) -> dict:
        return self._raw

    @property
    def runtime(self) -> dict:
        v = self._raw.get("runtime", {})
        return v if isinstance(v, dict) else {}

    @property
    def discovery(self) -> dict:
        v = self._raw.get("discovery", {})
        return v if isinstance(v, dict) else {}

    @property
    def health_cfg(self) -> dict:
        v = self._raw.get("health", {})
        return v if isinstance(v, dict) else {}

    @property
    def storage(self) -> dict:
        v = self._raw.get("storage", {})
        return v if isinstance(v, dict) else {}

    @property
    def block_patterns(self) -> list[str]:
        v = self._raw.get("block_patterns", [])
        return v if isinstance(v, list) else []

    def agent_names(self) -> list[str]:
        return list(self._agents.keys())

    def site_names(self) -> list[str]:
        return list(self._sites.keys())

    def resolve_agent(self, agent_name: str) -> dict:
        if agent_name in self._resolved:
            return self._resolved[agent_name]
        agent = self._agents.get(agent_name)
        if not agent:
            if not self._agents:
                return {"ua": "", "impersonate": "chrome136", "headers": {}}
            agent_name = next(iter(self._agents))
            agent = self._agents[agent_name]
        profile_name = agent.get("profile", "chrome")
        profile = self._profiles.get(profile_name, {})
        if not isinstance(profile, dict):
            profile = {}
        subs = {
            "version": str(agent.get("version", "")),
            "chromium": str(agent.get("chromium", agent.get("version", ""))),
            "platform": str(agent.get("platform", "Windows")),
            "mobile": str(agent.get("mobile", "?0")),
        }
        headers = {}
        for k, v in profile.items():
            if isinstance(v, str) and "${" in v:
                for sk, sv in subs.items():
                    v = v.replace("${" + sk + "}", sv)
            headers[k] = v
        headers["User-Agent"] = agent.get("ua", "")
        resolved = {
            "ua": agent.get("ua", ""),
            "impersonate": validate_impersonate(agent.get("impersonate", "")),
            "headers": headers,
        }
        self._resolved[agent_name] = resolved
        return resolved

    def site_entry(self, domain: str) -> dict:
        if domain in self._learned:
            return self._learned[domain]
        if domain in self._sites:
            return self._sites[domain]
        for d in list(self._sites.keys()) + list(self._learned.keys()):
            if domain == d or domain.endswith("." + d):
                return self._learned.get(d) or self._sites.get(d) or {}
        return {}

    def agent_for(self, domain: str) -> str:
        entry = self.site_entry(domain)
        return entry.get("agent", "chrome136_win")

    def rate_for(self, domain: str) -> float:
        entry = self.site_entry(domain)
        if "rate" in entry:
            try:
                return float(entry["rate"])
            except Exception:
                pass
        return 5.0

    def retry_after_for(self, domain: str) -> float:
        entry = self.site_entry(domain)
        default = self.health_cfg.get("retry_after_block_seconds", 300)
        try:
            return float(entry.get("retry_after", default))
        except Exception:
            return 300.0

    def allow_external_for(self, domain: str) -> bool:
        entry = self.site_entry(domain)
        if "allow_external" in entry:
            return bool(entry["allow_external"])
        return True

    def max_depth_for(self, domain: str) -> int:
        entry = self.site_entry(domain)
        cat = entry.get("category", "default")
        table = self.discovery.get("max_depth_by_authority", {})
        if not isinstance(table, dict):
            table = {}
        try:
            return int(table.get(cat, table.get("default",
                       self.discovery.get("max_depth_default", 3))))
        except Exception:
            return 3

    async def record_success(self, domain: str, agent_name: str):
        async with self._lock:
            entry = self._learned.get(domain)
            now = int(time.time())
            if entry is None:
                entry = {"agent": agent_name, "rate": 5.0,
                         "first_seen": now, "ok": 0, "fail": 0,
                         "promoted": False}
                self._learned[domain] = entry
            entry["ok"] = entry.get("ok", 0) + 1
            entry["last_ok"] = now
            entry["agent"] = agent_name
            self._dirty = True
            if not entry.get("promoted") and entry["ok"] >= 3:
                entry["promoted"] = True
                self._sites[domain] = {
                    "agent": agent_name,
                    "rate": entry.get("rate", 5.0),
                    "allow_external": True,
                    "category": "learned",
                    "retry_after": 300,
                }
                log.info("promoted learned domain: %s (agent=%s)", domain, agent_name)
            self._save_if_due()

    async def record_failure(self, domain: str, agent_name: str):
        async with self._lock:
            entry = self._learned.get(domain)
            if entry is None:
                entry = {"agent": agent_name, "rate": 5.0,
                         "first_seen": int(time.time()), "ok": 0, "fail": 0,
                         "promoted": False}
                self._learned[domain] = entry
            entry["fail"] = entry.get("fail", 0) + 1
            entry["last_fail"] = int(time.time())
            self._dirty = True
            self._save_if_due()

    def _save_if_due(self):
        now = time.time()
        if now - self._last_save < 5.0:
            return
        self._last_save = now
        self.save()

    def save(self):
        if not self._dirty:
            return
        tmp = self.path.with_suffix(".json.tmp")
        try:
            tmp.write_bytes(orjson.dumps(self._raw, option=orjson.OPT_INDENT_2))
            os.replace(tmp, self.path)
            self._dirty = False
        except Exception as e:
            log.warning("config save failed: %s", e)


# ══════════════════════════════════════════════════════════════════════════════
# FOLDERS
# ══════════════════════════════════════════════════════════════════════════════
class Folders:
    def __init__(self, base: str | Path, cfg: Config):
        s = cfg.storage
        self.base = Path(base)
        self.data = self.base / s.get("data_dir", "data")
        self.resume = self.base / s.get("resume_dir", "resume")
        self.partition_by_date = bool(s.get("domain_partition_by_date", True))
        self.data.mkdir(parents=True, exist_ok=True)
        self.resume.mkdir(parents=True, exist_ok=True)

    def domain_dir(self, domain: str) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", domain)
        d = self.data / safe
        if self.partition_by_date:
            d = d / time.strftime("%Y-%m-%d")
        d.mkdir(parents=True, exist_ok=True)
        return d


# ══════════════════════════════════════════════════════════════════════════════
# RESUME — single gzip-compressed append-only JSONL file
# ══════════════════════════════════════════════════════════════════════════════
class Resume:
    """
    File: resume/resume.jsonl.gz

    One file. Gzip-compressed. Append-only via multi-member gzip streams
    (Python's gzip module reads across members transparently).

    Each line: {"link": "https://...", "h": 12345678901234567890}
    """

    def __init__(self, base: str | Path, cfg: Config):
        s = cfg.storage
        self.base = Path(base)
        self.resume_dir = self.base / s.get("resume_dir", "resume")
        self.resume_dir.mkdir(parents=True, exist_ok=True)
        # Single file name. Falls back to old default if not in config.
        self.path = self.resume_dir / s.get("resume_file", "resume.jsonl.gz")
        self.known: set[int] = set()
        self._pending: list[tuple[str, int]] = []
        self._lock = asyncio.Lock()
        self._load()

    def _load(self):
        if not self.path.exists():
            return
        try:
            count = 0
            with gzip.open(self.path, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = orjson.loads(line)
                        h = rec.get("h")
                        if h is None:
                            url = rec.get("link", "")
                            h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
                        self.known.add(int(h))
                        count += 1
                    except Exception:
                        continue
            log.info("resume: loaded %d known URLs from %s",
                     count, self.path.name)
        except Exception as e:
            log.warning("resume load failed: %s", e)

    def is_known(self, url: str) -> bool:
        h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
        return h in self.known

    async def add(self, url: str):
        h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
        if h in self.known:
            return
        self.known.add(h)
        self._pending.append((url, h))
        if len(self._pending) >= 100:
            await self.flush()

    async def flush(self):
        async with self._lock:
            if not self._pending:
                return
            lines = [orjson.dumps({"link": url, "h": h}).decode("utf-8")
                     for url, h in self._pending]
            self._pending.clear()
            payload = ("\n".join(lines) + "\n").encode("utf-8")
            try:
                # Append new gzip member; read side stitches members together
                with gzip.open(self.path, "ab") as f:
                    f.write(payload)
            except Exception as e:
                log.warning("resume flush failed: %s", e)

    async def load_external(self, path: str | Path) -> int:
        """Import another resume.jsonl.gz and return count added."""
        p = Path(path)
        if not p.exists():
            return 0
        before = len(self.known)
        try:
            with gzip.open(p, "rt", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = orjson.loads(line)
                        h = rec.get("h")
                        if h is None:
                            url = rec.get("link", "")
                            h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
                        self.known.add(int(h))
                    except Exception:
                        continue
        except Exception as e:
            log.warning("external resume load failed: %s", e)
            return 0
        return len(self.known) - before


# ══════════════════════════════════════════════════════════════════════════════
# WRITER — single JSON-array file per batch, zstd compressed
# ══════════════════════════════════════════════════════════════════════════════
class Writer:
    """
    Emits ONE file per batch: <domain>_<idx>.json.zst

    Content: JSON array [ {...}, {...}, ... ]
    Compression: zstd level 22
    No raw intermediate, no ZIP wrapper.
    """

    def __init__(self, folders: Folders, cfg: Config):
        self.folders = folders
        self.cfg = cfg
        self.max_lines = int(cfg.storage.get("max_lines_per_file", 900))
        self.zstd_level = int(cfg.storage.get("zstd_level", 22))
        self.buffers: dict[str, list[dict]] = {}
        self.counters: dict[str, int] = {}
        self.total_written = 0
        self._lock = asyncio.Lock()

    async def write(self, record: dict):
        domain = record.get("domain", "unknown")
        async with self._lock:
            buf = self.buffers.setdefault(domain, [])
            buf.append(record)
            self.total_written += 1
            if len(buf) >= self.max_lines:
                await self._flush_domain_locked(domain)

    async def flush_all(self):
        async with self._lock:
            for d in list(self.buffers.keys()):
                await self._flush_domain_locked(d)

    async def _flush_domain_locked(self, domain: str):
        buf = self.buffers.get(domain) or []
        if not buf:
            return
        self.buffers[domain] = []
        idx = self.counters.get(domain, 0)
        self.counters[domain] = idx + 1

        ddir = self.folders.domain_dir(domain)
        safe = domain.replace(".", "_")
        out_path = ddir / f"{safe}_{idx:05d}.json.zst"

        try:
            payload = orjson.dumps(buf)  # JSON array
            compressed = zstd.ZstdCompressor(
                level=self.zstd_level).compress(payload)
            out_path.write_bytes(compressed)
            log.debug("wrote %s (%d records, %d bytes compressed)",
                      out_path.name, len(buf), len(compressed))
            gc.collect()
        except Exception as e:
            log.warning("writer flush failed for %s: %s", domain, e)


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════
_STRONG_BLOCK_PATTERNS = [
    "cf-browser-verification", "cf_chl_opt", "cf-please-wait",
    "challenge-platform", "checking your browser before accessing",
    "enable javascript and cookies to continue",
    "ddos protection by cloudflare", "please wait while we verify",
    "attention required! | cloudflare", "datadome", "perimeterx",
    "px-captcha", "kasada", "incapsula incident id", "_incapsula_",
    "are you a robot", "verify you are human", "access denied | cloudflare",
]

_WEAK_BLOCK_PATTERNS = [
    "just a moment", "ddos protection", "ray id", "cloudflare",
    "captcha", "bot detection", "unusual traffic",
]

_BLOCK_STATUS = frozenset({403, 429, 503})
_BLOCK_THRESHOLD = 3
_UNREACHABLE_THRESHOLD = 5


@dataclass(slots=True)
class DomainState:
    domain: str
    status: str = "UNKNOWN"
    fail_count: int = 0
    consec_fail: int = 0
    ok_count: int = 0
    last_seen: float = 0.0
    retry_at: float = 0.0
    agent: str = "chrome136_win"
    last_reason: str = ""


class Health:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.states: dict[str, DomainState] = {}
        self._strong_re = re.compile(
            "|".join(re.escape(p) for p in _STRONG_BLOCK_PATTERNS),
            re.IGNORECASE)
        self._weak_re = re.compile(
            "|".join(re.escape(p) for p in _WEAK_BLOCK_PATTERNS),
            re.IGNORECASE)

    def state(self, domain: str) -> DomainState:
        s = self.states.get(domain)
        if s is None:
            s = DomainState(domain=domain, agent=self.cfg.agent_for(domain))
            self.states[domain] = s
        return s

    def mark_ok(self, domain: str):
        s = self.state(domain)
        s.status = "HEALTHY"
        s.fail_count = 0
        s.consec_fail = 0
        s.ok_count += 1
        s.last_seen = time.time()
        s.last_reason = ""

    def mark_block(self, domain: str, reason: str = ""):
        s = self.state(domain)
        s.fail_count += 1
        s.consec_fail += 1
        s.last_seen = time.time()
        s.last_reason = reason or s.last_reason
        if s.consec_fail >= _BLOCK_THRESHOLD:
            s.status = "BLOCKED"
            s.retry_at = time.time() + self.cfg.retry_after_for(domain)

    def mark_unreachable(self, domain: str, reason: str = ""):
        s = self.state(domain)
        s.fail_count += 1
        s.consec_fail += 1
        s.last_seen = time.time()
        s.last_reason = reason or s.last_reason
        if s.consec_fail >= _UNREACHABLE_THRESHOLD:
            s.status = "UNREACHABLE"
            delay = float(self.cfg.health_cfg.get(
                "retry_after_unreachable_seconds", 600))
            s.retry_at = time.time() + delay

    def record_fetch_error(self, domain: str, reason: str = ""):
        s = self.state(domain)
        s.fail_count += 1
        s.consec_fail += 1
        s.last_seen = time.time()
        s.last_reason = reason or s.last_reason

    def is_scrapeable(self, domain: str) -> bool:
        s = self.state(domain)
        if s.status == "HEALTHY":
            return True
        if s.status == "DEAD":
            return False
        if s.status in ("BLOCKED", "UNREACHABLE"):
            if time.time() >= s.retry_at:
                s.status = "UNKNOWN"
                s.consec_fail = 0
                return True
            return False
        return True

    def detect_block(self, body: str, status_code: int = 200) -> Optional[str]:
        if not body:
            if status_code in _BLOCK_STATUS:
                return f"status_{status_code}_empty"
            return None
        sample = body[:16384]
        m = self._strong_re.search(sample)
        if m:
            return f"strong:{m.group(0)[:40]}"
        if status_code in _BLOCK_STATUS:
            m = self._weak_re.search(sample)
            if m:
                return f"weak+{status_code}:{m.group(0)[:40]}"
            return f"status_{status_code}"
        if len(body) < 20000:
            m = self._weak_re.search(sample)
            if m:
                return f"weak+small:{m.group(0)[:40]}"
        return None


# ══════════════════════════════════════════════════════════════════════════════
# PRIMITIVES
# ══════════════════════════════════════════════════════════════════════════════
class TokenBucket:
    __slots__ = ("rate", "burst", "tokens", "last")
    def __init__(self, rate: float, burst: float | None = None):
        self.rate = float(rate)
        self.burst = float(burst if burst is not None else max(1.0, rate * 2))
        self.tokens = self.burst
        self.last = time.monotonic()

    async def take(self, n: float = 1.0):
        while True:
            now = time.monotonic()
            self.tokens = min(self.burst,
                              self.tokens + (now - self.last) * self.rate)
            self.last = now
            if self.tokens >= n:
                self.tokens -= n
                return
            await asyncio.sleep((n - self.tokens) / self.rate)


class EWMA:
    __slots__ = ("alpha", "value", "_init")
    def __init__(self, alpha: float = 0.25):
        self.alpha = alpha
        self.value = 0.0
        self._init = False
    def update(self, x: float) -> float:
        if not self._init:
            self.value = x
            self._init = True
        else:
            self.value = self.alpha * x + (1.0 - self.alpha) * self.value
        return self.value


class AdaptiveSemaphore:
    __slots__ = ("_cap", "_min", "_max", "_in_use", "_waiters")
    def __init__(self, initial: int, min_cap: int = 1, max_cap: int = 4096):
        self._min = min_cap
        self._max = max_cap
        self._cap = max(min_cap, min(max_cap, initial))
        self._in_use = 0
        self._waiters: deque[asyncio.Future] = deque()
    @property
    def capacity(self) -> int: return self._cap
    @property
    def in_use(self) -> int: return self._in_use
    async def acquire(self):
        while self._in_use >= self._cap:
            fut = asyncio.get_running_loop().create_future()
            self._waiters.append(fut)
            try:
                await fut
            except asyncio.CancelledError:
                try:
                    self._waiters.remove(fut)
                except ValueError:
                    pass
                raise
        self._in_use += 1
    def release(self):
        if self._in_use > 0:
            self._in_use -= 1
        while self._waiters and self._in_use < self._cap:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)
    def resize(self, new_cap: int):
        new_cap = max(self._min, min(self._max, new_cap))
        if new_cap == self._cap:
            return
        self._cap = new_cap
        while self._waiters and self._in_use < self._cap:
            fut = self._waiters.popleft()
            if not fut.done():
                fut.set_result(None)
    async def __aenter__(self):
        await self.acquire()
        return self
    async def __aexit__(self, *_):
        self.release()


def normalize_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
    except Exception:
        return url
    scheme = p.scheme.lower()
    netloc = p.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    elif scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = p.path or "/"
    return urlunsplit((scheme, netloc, path, p.query, ""))


# ══════════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(
        prog="State.py",
        description="Fa-Scrap substrate. Import this module. CLI is --help only.")
    p.print_help()


if __name__ == "__main__":
    main()