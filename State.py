#!/usr/bin/env python3
"""
State.py — Fa-Scrap substrate.

Changes in this build:
    - Health.detect_block() now takes a status code, splits patterns into
      STRONG (only appear in real blocks) and WEAK (may appear normally),
      and only fires on a real signal.
    - Health.mark_block() and mark_unreachable() now require consecutive
      failures before locking a domain out.
    - DomainState tracks consecutive fails separately from total fails.
    - Added Health.record_fetch_error() for one-off errors that shouldn't
      trigger a lockout.
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import ctypes.util
import gc
import logging
import os
import platform as _pyplatform
import re
import struct
import sys
import time
import zipfile
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlsplit, urlunsplit

import msgspec
import orjson
import xxhash
import zstandard as zstd

log = logging.getLogger("fa.state")


# ══════════════════════════════════════════════════════════════════════════════
# PLATFORM LAYER
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

    @staticmethod
    def direct_write(path: str | Path, data: bytes) -> int:
        try:
            fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
            try:
                return os.write(fd, data)
            finally:
                os.close(fd)
        except Exception:
            try:
                with open(path, "ab") as f:
                    return f.write(data)
            except Exception:
                return 0


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
    def cookies(self) -> dict:
        v = self._raw.get("cookies", {})
        return v if isinstance(v, dict) else {}

    @property
    def legal(self) -> dict:
        v = self._raw.get("legal", {})
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
                return {"ua": "", "impersonate": "", "headers": {}}
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
            "impersonate": agent.get("impersonate", "chrome131"),
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
        return entry.get("agent", "chrome146_win")

    def rate_for(self, domain: str) -> float:
        entry = self.site_entry(domain)
        v = entry.get("rate", 2.0)
        try:
            return float(v)
        except Exception:
            return 2.0

    def retry_after_for(self, domain: str) -> float:
        entry = self.site_entry(domain)
        default = self.health_cfg.get("retry_after_block_seconds", 300)
        try:
            return float(entry.get("retry_after", default))
        except Exception:
            return 300.0

    def allow_external_for(self, domain: str) -> bool:
        entry = self.site_entry(domain)
        return bool(entry.get("allow_external", False))

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
                entry = {"agent": agent_name, "rate": 2.0,
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
                    "rate": entry.get("rate", 2.0),
                    "allow_external": False,
                    "category": "learned",
                    "retry_after": 300,
                }
                log.info("promoted learned domain: %s (agent=%s)", domain, agent_name)
            self._save_if_due()

    async def record_failure(self, domain: str, agent_name: str):
        async with self._lock:
            entry = self._learned.get(domain)
            if entry is None:
                entry = {"agent": agent_name, "rate": 2.0,
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
# RESUME
# ══════════════════════════════════════════════════════════════════════════════
class Resume:
    def __init__(self, base: str | Path, cfg: Config):
        s = cfg.storage
        self.base = Path(base)
        self.resume_dir = self.base / s.get("resume_dir", "resume")
        self.resume_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl = self.resume_dir / s.get("resume_jsonl", "resume.jsonl")
        self.zst = self.resume_dir / s.get("resume_zst", "resume.jsonl.zst")
        self.zip = self.resume_dir / s.get("resume_zip", "resume.zip")
        self.known: set[int] = set()
        self._pending: list[bytes] = []
        self._lock = asyncio.Lock()
        self._load()

    def _load(self):
        if self.jsonl.exists():
            try:
                with open(self.jsonl, "rb") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = orjson.loads(line)
                            h = rec.get("hash_int")
                            if h is None:
                                url = rec.get("link", "")
                                h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
                            self.known.add(int(h))
                        except Exception:
                            continue
                log.info("resume: loaded %d known URLs from jsonl", len(self.known))
                return
            except Exception as e:
                log.warning("resume jsonl read failed: %s", e)
        if self.zip.exists():
            try:
                self._load_from_zip()
                log.info("resume: loaded %d known URLs from zip", len(self.known))
            except Exception as e:
                log.warning("resume zip read failed: %s", e)

    def _load_from_zip(self):
        with zipfile.ZipFile(self.zip, "r") as zf:
            for name in zf.namelist():
                raw = zf.read(name)
                try:
                    data = zstd.ZstdDecompressor().decompress(raw)
                except Exception:
                    continue
                for line in data.split(b"\n"):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = orjson.loads(line)
                        h = rec.get("hash_int")
                        if h is None:
                            url = rec.get("link", "")
                            h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
                        self.known.add(int(h))
                    except Exception:
                        continue

    def is_known(self, url: str) -> bool:
        h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
        return h in self.known

    async def add(self, url: str):
        h = xxhash.xxh3_64_intdigest(url.encode("utf-8"))
        if h in self.known:
            return
        self.known.add(h)
        self._pending.append(orjson.dumps({"link": url, "hash_int": h}))
        if len(self._pending) >= 100:
            await self.flush()

    async def flush(self):
        async with self._lock:
            if not self._pending:
                return
            payload = b"\n".join(self._pending) + b"\n"
            self._pending.clear()
            Platform.direct_write(self.jsonl, payload)

    async def snapshot(self):
        async with self._lock:
            await self.flush()
            if not self.jsonl.exists():
                return
            try:
                raw = self.jsonl.read_bytes()
                compressed = zstd.ZstdCompressor(level=22).compress(raw)
                self.zst.write_bytes(compressed)
                with zipfile.ZipFile(self.zip, "w",
                                     compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("resume.jsonl.zst", compressed)
            except Exception as e:
                log.warning("resume snapshot failed: %s", e)

    async def load_external(self, path: str | Path) -> int:
        p = Path(path)
        if not p.exists():
            return 0
        before = len(self.known)
        try:
            with zipfile.ZipFile(p, "r") as zf:
                for name in zf.namelist():
                    raw = zf.read(name)
                    try:
                        data = zstd.ZstdDecompressor().decompress(raw)
                    except Exception:
                        data = raw
                    for line in data.split(b"\n"):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = orjson.loads(line)
                            h = rec.get("hash_int")
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
# WRITER
# ══════════════════════════════════════════════════════════════════════════════
class Writer:
    def __init__(self, folders: Folders, cfg: Config):
        self.folders = folders
        self.cfg = cfg
        self.max_lines = int(cfg.storage.get("max_lines_per_file", 900))
        self.zstd_level = int(cfg.storage.get("zstd_level", 22))
        self.buffers: dict[str, list[bytes]] = {}
        self.counters: dict[str, int] = {}
        self.total_written = 0
        self._lock = asyncio.Lock()

    async def write(self, record: dict):
        domain = record.get("domain", "unknown")
        async with self._lock:
            buf = self.buffers.setdefault(domain, [])
            buf.append(orjson.dumps(record))
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
        base_name = f"{domain.replace('.', '_')}_{idx:05d}.jsonl"
        jsonl_path = ddir / base_name
        zst_path = jsonl_path.with_suffix(".jsonl.zst")
        zip_path = jsonl_path.with_suffix(".jsonl.zst.zip")
        payload = b"\n".join(buf) + b"\n"
        try:
            Platform.direct_write(jsonl_path, payload)
            compressed = zstd.ZstdCompressor(level=self.zstd_level).compress(payload)
            zst_path.write_bytes(compressed)
            with zipfile.ZipFile(zip_path, "w",
                                 compression=zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(base_name + ".zst", compressed)
            gc.collect()
        except Exception as e:
            log.warning("writer flush failed for %s: %s", domain, e)


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH  — REWRITTEN
# ══════════════════════════════════════════════════════════════════════════════
# STRONG patterns: these only appear in real challenge/block pages.
_STRONG_BLOCK_PATTERNS = [
    "cf-browser-verification",
    "cf_chl_opt",
    "cf-please-wait",
    "challenge-platform",
    "checking your browser before accessing",
    "enable javascript and cookies to continue",
    "ddos protection by cloudflare",
    "please wait while we verify",
    "attention required! | cloudflare",
    "datadome",
    "perimeterx",
    "px-captcha",
    "kasada",
    "incapsula incident id",
    "_incapsula_",
    "are you a robot",
    "verify you are human",
    "access denied | cloudflare",
]

# WEAK patterns: only fire when status code is suspicious AND body is tiny.
_WEAK_BLOCK_PATTERNS = [
    "just a moment",
    "ddos protection",
    "ray id",
    "cloudflare",
    "captcha",
    "bot detection",
    "unusual traffic",
]

# Status codes that on their own suggest a block (not just an error).
_BLOCK_STATUS = frozenset({403, 429, 503})

# Minimum consecutive failures before locking a domain.
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
    agent: str = "chrome146_win"
    last_reason: str = ""


class Health:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.states: dict[str, DomainState] = {}
        self._strong_re = re.compile(
            "|".join(re.escape(p) for p in _STRONG_BLOCK_PATTERNS),
            re.IGNORECASE,
        )
        self._weak_re = re.compile(
            "|".join(re.escape(p) for p in _WEAK_BLOCK_PATTERNS),
            re.IGNORECASE,
        )

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
        """Increment fail. Only flip to BLOCKED after _BLOCK_THRESHOLD."""
        s = self.state(domain)
        s.fail_count += 1
        s.consec_fail += 1
        s.last_seen = time.time()
        s.last_reason = reason or s.last_reason
        if s.consec_fail >= _BLOCK_THRESHOLD:
            s.status = "BLOCKED"
            s.retry_at = time.time() + self.cfg.retry_after_for(domain)
        max_fails = int(self.cfg.health_cfg.get("dead_after_failures", 25))
        if s.fail_count >= max_fails:
            s.status = "DEAD"

    def mark_unreachable(self, domain: str, reason: str = ""):
        """Increment fail. Only flip to UNREACHABLE after _UNREACHABLE_THRESHOLD."""
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
        """One-off error: bump counters but do NOT change status."""
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

    def detect_block(self, body: str,
                     status_code: int = 200) -> Optional[str]:
        """
        Return a block reason string, or None.

        Logic:
            - Strong pattern in first 16 KB → block (with reason tag).
            - Else if status is 403/429/503 AND weak pattern → block.
            - Else if body < 20000 chars AND weak pattern → block.
            - Else → None.
        """
        if not body:
            # If body empty and status suggests a block, still flag it.
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
        self.burst = float(burst if burst is not None else max(1.0, rate))
        self.tokens = self.burst
        self.last = time.monotonic()

    async def take(self, n: float = 1.0):
        while True:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.last) * self.rate)
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
        description="Fa-Scrap substrate. Import this module. CLI is --help only.",
    )
    p.print_help()


if __name__ == "__main__":
    main()