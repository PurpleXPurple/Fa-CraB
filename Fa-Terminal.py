"""
Fa-Terminal — the full interactive CLI for Fa-Crab.

Public entry:
    python Fa-Terminal.py --help
    python Fa-Terminal.py crawl https://example.com
    python Fa-Terminal.py repl
    python Fa-Terminal.py scrape https://example.com
    python Fa-Terminal.py gui

Every subcommand uses Manager (config/state/output), Crawl (fetch engine),
Scraper (extraction), and optionally launches GUI. Nothing is stubbed.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import importlib.util
import io
import json
import logging
import os
import random
import re
import shutil
import signal
import statistics
import sys
import time
import uuid
import webbrowser
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence
from urllib.parse import urlparse

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.progress import (Progress, SpinnerColumn, TextColumn, BarColumn,
                            TimeElapsedColumn, TimeRemainingColumn,
                            TaskProgressColumn)
from rich.prompt import Prompt, Confirm
from rich.tree import Tree
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.text import Text
from rich.box import ROUNDED, SIMPLE, HEAVY

def _load_local_module(module_name: str, filename: str) -> Any:
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    module_path = os.path.join(os.path.dirname(__file__), filename)
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load local module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


_manager_module = _load_local_module("Fa_Manager", "Fa-Manager.py")
get_manager = getattr(_manager_module, "get_manager")
reset_manager = getattr(_manager_module, "reset_manager")
ErrorCategory = getattr(_manager_module, "ErrorCategory")
ErrorSeverity = getattr(_manager_module, "ErrorSeverity")
WarningSeverity = getattr(_manager_module, "WarningSeverity")
CacheTier = getattr(_manager_module, "CacheTier")

_crawl_module = _load_local_module("Fa_Crawl", "Fa-Crawl.py")
get_crawler = getattr(_crawl_module, "get_crawler")
reset_crawler = getattr(_crawl_module, "reset_crawler")
CrawlConfig = getattr(_crawl_module, "CrawlConfig")
CrawlController = getattr(_crawl_module, "CrawlController")
CrawlState = getattr(_crawl_module, "CrawlState")
make_crabber = getattr(_crawl_module, "make_crabber")
CRABBER_REGISTRY = getattr(_crawl_module, "CRABBER_REGISTRY")

_scraper_module = _load_local_module("Fa_Scraper", "Fa-Scraper.py")
get_scraper = getattr(_scraper_module, "get_scraper")
reset_scraper = getattr(_scraper_module, "reset_scraper")
ScraperConfig = getattr(_scraper_module, "ScraperConfig")
scrape = getattr(_scraper_module, "scrape")
ScrapeResult = getattr(_scraper_module, "ScrapeResult")


# ════════════════════════════════════════════════════════════════════════════
# Globals
# ════════════════════════════════════════════════════════════════════════════

VERSION = "1.0.0"
console = Console()
err_console = Console(stderr=True, style="bold red")

app = typer.Typer(
    name="fa-crab",
    help="Fa-Crab — universal scraper/crawler for AI datasets.",
    add_completion=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Shared mutable state across subcommands
_state: dict[str, Any] = {
    "config_path": "./Config.json",
    "agents_path": "./Agents.json",
    "output_dir": "./output",
    "state_dir": "./state",
    "verbose": False,
    "quiet": False,
    "no_color": False,
    "json": False,
}

# Exit codes
EXIT_OK = 0
EXIT_ERR = 1
EXIT_USAGE = 2
EXIT_CONFIG = 3
EXIT_NETWORK = 4
EXIT_PARTIAL = 5


# ════════════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════════════

def _mgr():
    """Get or build the Manager singleton with current overrides."""
    return get_manager(
        config_path=_state["config_path"],
        agents_path=_state["agents_path"],
        state_dir=_state["state_dir"],
        output_dir=_state["output_dir"],
    )


def _ctl(config: Optional[Any] = None) -> Any:
    reset_crawler()
    ctl = get_crawler(mgr=_mgr(), config=config or CrawlConfig())
    return ctl


def _scr(config: Optional[Any] = None):
    reset_scraper()
    return get_scraper(mgr=_mgr(), config=config or ScraperConfig())


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fmt_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_duration(sec: float) -> str:
    if sec < 60:
        return f"{sec:.1f}s"
    if sec < 3600:
        return f"{sec/60:.1f}m"
    return f"{sec/3600:.1f}h"


def _fmt_ms(ms: float) -> str:
    if ms < 1000:
        return f"{ms:.0f}ms"
    return f"{ms/1000:.2f}s"


def _truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


def _header(title: str, subtitle: str = "") -> None:
    console.rule(f"[bold cyan]{title}[/bold cyan]")
    if subtitle:
        console.print(f"[dim]{subtitle}[/dim]\n")


def _ok(msg: str) -> None:
    if not _state["quiet"]:
        console.print(f"[green]✓[/green] {msg}")


def _warn(msg: str) -> None:
    if not _state["quiet"]:
        console.print(f"[yellow]![/yellow] {msg}")


def _fail(msg: str, code: int = EXIT_ERR) -> None:
    err_console.print(f"[red]✗[/red] {msg}")
    raise typer.Exit(code)


def _info(msg: str) -> None:
    if not _state["quiet"]:
        console.print(f"[blue]ℹ[/blue] {msg}")


def _kv_table(rows: Sequence[tuple[str, Any]], title: str = "") -> Table:
    t = Table(title=title, box=ROUNDED, show_header=False, padding=(0, 1))
    t.add_column("Key", style="cyan")
    t.add_column("Value", style="white")
    for k, v in rows:
        t.add_row(str(k), str(v))
    return t


def _run(coro):
    """Run an async coroutine, handling existing loops gracefully."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # If a loop is already running, run on a new one in a thread
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def _apply_global_options() -> None:
    if _state["no_color"]:
        console._color_system = None  # type: ignore
    if _state["quiet"]:
        console.quiet = True  # type: ignore


# ════════════════════════════════════════════════════════════════════════════
# Signal handling
# ════════════════════════════════════════════════════════════════════════════

_active_crawl: Optional[Any] = None


def _install_signal_handlers() -> None:
    def _handler(signum, _frame):
        console.print(
            f"\n[yellow]Signal {signum} received — shutting down…[/yellow]")
        if _active_crawl is not None:
            with contextlib.suppress(Exception):
                _active_crawl._stop_event.set()
        raise typer.Exit(EXIT_PARTIAL)

    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(Exception):
            signal.signal(sig, _handler)


# ════════════════════════════════════════════════════════════════════════════
# Renderers
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class _ProgressState:
    fetched: int = 0
    parsed: int = 0
    written: int = 0
    errors: int = 0
    retries: int = 0
    bytes_in: int = 0
    in_flight: int = 0
    queue: int = 0
    started_at: float = field(default_factory=time.time)


class LiveDashboard:
    """Rich Live dashboard for the crawl subcommand."""

    def __init__(self, ctl: Any, max_pages: int = 0):
        self.ctl = ctl
        self.max_pages = max_pages
        self.state = _ProgressState()
        self._last_update = 0.0

    def on_stats(self, snapshot: dict) -> None:
        self.state.fetched = snapshot.get("fetched", 0)
        self.state.parsed = snapshot.get("parsed", 0)
        self.state.written = snapshot.get("written", 0)
        self.state.errors = snapshot.get("errors", 0)
        self.state.retries = snapshot.get("retries", 0)
        self.state.bytes_in = snapshot.get("bytes_in", 0)
        self.state.in_flight = snapshot.get("in_flight", 0)
        with contextlib.suppress(Exception):
            self.state.queue = self.ctl.frontier.qsize()

    def build(self) -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3),
        )
        layout["main"].split_row(
            Layout(name="stats", ratio=2),
            Layout(name="health", ratio=1),
        )

        # Header
        elapsed = time.time() - self.state.started_at
        rate = self.state.fetched / max(0.1, elapsed)
        header_text = Text.from_markup(
            f"[bold cyan]Fa-Crab[/bold cyan]  "
            f"[dim]elapsed[/dim] {_fmt_duration(elapsed)}  "
            f"[dim]rate[/dim] [bold]{rate:.1f}[/bold] pages/s  "
            f"[dim]state[/dim] {self.ctl.state.value}"
        )
        layout["header"].update(Panel(header_text, box=ROUNDED))

        # Stats
        stats_table = Table(box=SIMPLE, show_header=False, padding=(0, 1))
        stats_table.add_column("k", style="cyan")
        stats_table.add_column("v", style="bold")
        stats_table.add_row("Fetched", str(self.state.fetched))
        stats_table.add_row("Parsed", str(self.state.parsed))
        stats_table.add_row("Written", str(self.state.written))
        stats_table.add_row("Errors", f"[red]{self.state.errors}[/red]")
        stats_table.add_row("Retries", str(self.state.retries))
        stats_table.add_row("In-flight", str(self.state.in_flight))
        stats_table.add_row("Frontier", str(self.state.queue))
        stats_table.add_row("Bytes in", _fmt_bytes(self.state.bytes_in))
        if self.max_pages:
            stats_table.add_row(
                "Progress",
                f"{self.state.fetched}/{self.max_pages} "
                f"({100*self.state.fetched/max(1,self.max_pages):.1f}%)")
        layout["stats"].update(Panel(stats_table, title="Stats",
                                      border_style="cyan", box=ROUNDED))

        # Health
        try:
            rep = self.ctl.health.report()
            h = Table(box=SIMPLE, show_header=False, padding=(0, 1))
            h.add_column("k", style="cyan")
            h.add_column("v")
            h.add_row("Domains", str(rep.total_domains))
            h.add_row("Healthy", f"[green]{rep.healthy}[/green]")
            h.add_row("Degraded", f"[yellow]{rep.degraded}[/yellow]")
            h.add_row("Unstable", f"[orange3]{rep.unstable}[/orange3]")
            h.add_row("Down", f"[red]{rep.down}[/red]")
            h.add_row("Avg latency", _fmt_ms(rep.avg_latency_ms))
            h.add_row("P95 latency", _fmt_ms(rep.p95_latency_ms))
            h.add_row("Success rate",
                      f"{rep.aggregate_success_rate*100:.1f}%")
            h.add_row("Balance",
                      f"{rep.cross_domain_balance:.2f}")
            layout["health"].update(Panel(h, title="Health",
                                           border_style="magenta", box=ROUNDED))
        except Exception:
            layout["health"].update(Panel("health unavailable",
                                           box=ROUNDED))

        # Footer
        footer = Text.from_markup(
            "[dim]Ctrl+C to stop  •  output:[/dim] "
            f"{_state['output_dir']}"
        )
        layout["footer"].update(Panel(footer, box=ROUNDED))
        return layout


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: version
# ════════════════════════════════════════════════════════════════════════════

@app.command()
def version() -> None:
    """Show Fa-Crab version and component versions."""
    manager_module = _load_local_module("Fa_Manager", "Fa-Manager.py")
    crawl_module = _load_local_module("Fa_Crawl", "Fa-Crawl.py")
    scraper_module = _load_local_module("Fa_Scraper", "Fa-Scraper.py")
    MANAGER_VERSION = getattr(manager_module, "MANAGER_VERSION")
    CRAWL_VERSION = getattr(crawl_module, "CRAWL_VERSION")
    SCRAPER_VERSION = getattr(scraper_module, "SCRAPER_VERSION")
    rows = [
        ("Fa-Crab", VERSION),
        ("Fa-Manager", MANAGER_VERSION),
        ("Fa-Crawl", CRAWL_VERSION),
        ("Fa-Scraper", SCRAPER_VERSION),
        ("Python", sys.version.split()[0]),
    ]
    console.print(Panel(_kv_table(rows, "Versions"),
                        title="[bold cyan]Fa-Crab[/bold cyan]",
                        box=ROUNDED))


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: config
# ════════════════════════════════════════════════════════════════════════════

@app.command("config")
def config_cmd(
    action: str = typer.Argument("show",
                                 help="show | show-env | diff | path | validate"),
    path: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Inspect and validate the config."""
    if path:
        _state["config_path"] = path
    mgr = _mgr()
    if action == "path":
        console.print(str(mgr.paths["config"]))
        return
    if action == "show":
        data = mgr.config.as_dict()
        console.print_json(json.dumps(data, indent=2, default=str))
        return
    if action == "show-env":
        data = mgr.config.as_dict()
        envs = {k: v for k, v in os.environ.items()
                if k.startswith("FA_CRAB_")}
        console.print(Panel(_kv_table(sorted(envs.items()),
                                       "FA_CRAB_* environment"),
                            title="Env overrides", box=ROUNDED))
        console.print_json(json.dumps(data, indent=2, default=str))
        return
    if action == "validate":
        try:
            mgr.reload_config()
            _ok("Config valid.")
        except Exception as e:
            _fail(f"Config invalid: {e}", EXIT_CONFIG)
        return
    if action == "diff":
        manager_module = _load_local_module("Fa_Manager", "Fa-Manager.py")
        ConfigLoader = getattr(manager_module, "ConfigLoader")
        try:
            new_cfg = ConfigLoader(Path(_state["config_path"])).load()
        except Exception as e:
            _fail(f"Cannot load: {e}", EXIT_CONFIG)
        a = mgr.config.as_dict()
        b = new_cfg.as_dict()

        def diff(d1: dict, d2: dict, prefix: str = "") -> list[str]:
            out: list[str] = []
            keys = set(d1) | set(d2)
            for k in sorted(keys):
                kp = f"{prefix}.{k}" if prefix else k
                v1 = d1.get(k, "<missing>")
                v2 = d2.get(k, "<missing>")
                if isinstance(v1, dict) and isinstance(v2, dict):
                    out.extend(diff(v1, v2, kp))
                elif v1 != v2:
                    out.append(f"{kp}: {v1!r} → {v2!r}")
            return out

        changes = diff(a, b)
        if not changes:
            _ok("No differences.")
        else:
            for line in changes[:200]:
                console.print(f"  [yellow]{line}[/yellow]")
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: agents
# ════════════════════════════════════════════════════════════════════════════

@app.command("agents")
def agents_cmd(
    action: str = typer.Argument("list",
                                 help="list | show <group> | count"),
    group: Optional[str] = typer.Argument(None),
) -> None:
    """Inspect the agent pool."""
    mgr = _mgr()
    agents = mgr.agents.as_dict()
    if action == "list":
        rows = []
        for family, uas in agents.get("user_agents", {}).items():
            rows.append((family, len(uas)))
        t = Table(title="UA families", box=ROUNDED)
        t.add_column("Family", style="cyan")
        t.add_column("Count", justify="right")
        for fam, n in rows:
            t.add_row(fam, str(n))
        console.print(t)
        console.print(_kv_table([
            ("Header presets", len(agents.get("header_presets", {}))),
            ("Cookie acceptors", len(agents.get("cookie_acceptors", {}))),
            ("TLS fingerprints",
             len(agents.get("tls_fingerprints", {}).get("ja3", {}))),
            ("Impersonate profiles",
             len(agents.get("impersonation_profiles", {}))),
        ], "Agent inventory"))
        return
    if action == "count":
        total = sum(len(v) for v in
                    agents.get("user_agents", {}).values())
        console.print(f"[bold]Total UAs:[/bold] {total}")
        return
    if action == "show":
        if not group:
            _fail("Usage: agents show <group>", EXIT_USAGE)
        uas = agents.get("user_agents", {}).get(group)
        if not uas:
            _fail(f"Unknown group: {group}", EXIT_USAGE)
        for i, ua in enumerate(uas, 1):
            console.print(f"[dim]{i:>3}.[/dim] {ua}")
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: scrape
# ════════════════════════════════════════════════════════════════════════════

@app.command("scrape")
def scrape_cmd(
    url: str = typer.Argument(..., help="URL to scrape (single fetch)"),
    show: str = typer.Option(
        "summary",
        "--show", "-s",
        help="summary | full | tokens | links | paragraphs | json | raw",
    ),
    save_raw: bool = typer.Option(False, "--raw"),
    no_cache: bool = typer.Option(False, "--no-cache"),
) -> None:
    """Fetch and extract one URL."""
    _apply_global_options()
    mgr = _mgr()
    ctl = _ctl()
    ctl.config.max_pages = 1

    async def _run_one():
        ctl.stats["in_flight"] = 1
        try:
            return await ctl.fetcher.fetch(url)
        finally:
            ctl.stats["in_flight"] = 0

    try:
        with console.status(f"[cyan]Fetching {url}…"):
            res = _run(_run_one())
    except Exception as e:
        _fail(f"Fetch failed: {e}", EXIT_NETWORK)

    sc = _scr()
    page = sc.scrape(res.body, res.final_url,
                     content_type=res.content_type,
                     headers=res.headers,
                     status=res.status,
                     elapsed_ms=res.elapsed_ms,
                     save_raw=save_raw)

    if _state["json"] or show == "json":
        console.print_json(json.dumps(page.to_record(),
                                       default=str, indent=2))
        return

    if show == "summary":
        _print_scrape_summary(page)
    elif show == "full":
        _print_scrape_summary(page)
        console.rule("Text")
        console.print(page.text[:5000])
        console.rule("Links (internal)")
        for l in page.links_internal[:20]:
            console.print(f"  [cyan]→[/cyan] {l.get('url')}")
        console.rule("Links (external)")
        for l in page.links_external[:20]:
            console.print(f"  [magenta]→[/magenta] {l.get('url')}")
    elif show == "tokens":
        for tok in page.tokens[:500]:
            console.print(tok)
        if len(page.tokens) > 500:
            console.print(f"[dim]… {len(page.tokens) - 500} more[/dim]")
    elif show == "links":
        _print_links(page)
    elif show == "paragraphs":
        for i, p in enumerate(page.paragraphs, 1):
            console.print(f"[bold cyan]#{i}[/bold cyan] {p}\n")
    elif show == "raw":
        console.print(page.raw_html or "[dim](no raw stored)[/dim]")
    else:
        _fail(f"Unknown --show mode: {show}", EXIT_USAGE)

    _ = mgr  # touch manager to preserve singleton


def _print_scrape_summary(page: Any) -> None:
    rows = [
        ("URL", _truncate(page.url, 80)),
        ("Title", _truncate(page.title or "(none)", 80)),
        ("Status", page.status),
        ("Kind", page.content_kind.value),
        ("Language", page.language or "(unknown)"),
        ("Words", page.words_count),
        ("Unique words", page.unique_words),
        ("Characters", page.char_count),
        ("Sentences", page.sentence_count),
        ("Paragraphs", page.paragraph_count),
        ("Most used word", page.most_used_word or "-"),
        ("Least used word", page.least_used_word or "-"),
        ("Tokens", len(page.tokens)),
        ("Internal links", len(page.links_internal)),
        ("External links", len(page.links_external)),
        ("Tables", len(page.tables)),
        ("Lists", len(page.lists)),
        ("Images", len(page.images)),
        ("Code blocks", len(page.code_blocks)),
        ("Footnotes", len(page.footnotes)),
        ("Strategy", page.extraction_strategy or "-"),
        ("Profile", page.profile_used or "-"),
        ("Quality", f"{page.quality.score} ({page.quality.tier.value})"),
        ("Reading time",
         f"{page.reading_time_seconds:.1f}s"),
        ("Elapsed", _fmt_ms(page.elapsed_ms)),
    ]
    console.print(Panel(
        _kv_table(rows),
        title="[bold cyan]Scrape summary[/bold cyan]",
        box=ROUNDED))


def _print_links(page: Any) -> None:
    t = Table(title="Links", box=ROUNDED)
    t.add_column("Kind", style="cyan")
    t.add_column("URL", overflow="fold")
    t.add_column("Anchor", overflow="fold")
    for l in page.links_internal[:200]:
        t.add_row("internal", _truncate(l.get("url", ""), 80),
                  _truncate(l.get("anchor_text", ""), 40))
    for l in page.links_external[:200]:
        t.add_row("external", _truncate(l.get("url", ""), 80),
                  _truncate(l.get("anchor_text", ""), 40))
    console.print(t)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: crawl
# ════════════════════════════════════════════════════════════════════════════

@app.command("crawl")
def crawl_cmd(
    urls: Optional[list[str]] = typer.Argument(
        None, help="Seed URLs (or use --seed-file)"),
    seed_file: Optional[str] = typer.Option(
        None, "--seed-file", "-f",
        help="File containing seed URLs, one per line"),
    crawler_type: str = typer.Option(
        "generic", "--crawler", "-k",
        help="Crawler personality: " + ", ".join(CRABBER_REGISTRY.keys())),
    concurrency: int = typer.Option(100, "--concurrency"),
    per_domain: int = typer.Option(2, "--per-domain"),
    max_pages: int = typer.Option(0, "--max-pages"),
    max_depth: int = typer.Option(3, "--max-depth"),
    timeout: float = typer.Option(30.0, "--timeout"),
    cross_domain: bool = typer.Option(False, "--cross-domain"),
    sitemap: bool = typer.Option(True, "--sitemap/--no-sitemap"),
    robots: bool = typer.Option(True, "--robots/--no-robots"),
    cloudflare: str = typer.Option(
        "passive", "--cloudflare",
        help="off | detect_only | passive | aggressive | max"),
    resume: bool = typer.Option(False, "--resume"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    proxy: Optional[list[str]] = typer.Option(
        None, "--proxy", help="Proxy URL (repeatable)"),
    include: Optional[list[str]] = typer.Option(
        None, "--include", help="Include regex (repeatable)"),
    exclude: Optional[list[str]] = typer.Option(
        None, "--exclude", help="Exclude regex (repeatable)"),
    domain_allow: Optional[list[str]] = typer.Option(
        None, "--domain-allow"),
    domain_block: Optional[list[str]] = typer.Option(
        None, "--domain-block"),
    live: bool = typer.Option(True, "--live/--no-live"),
) -> None:
    """Run a crawl."""
    _apply_global_options()
    _install_signal_handlers()

    seeds: list[str] = list(urls or [])
    if seed_file:
        try:
            with open(seed_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        seeds.append(line)
        except OSError as e:
            _fail(f"Cannot read seed file: {e}", EXIT_USAGE)

    if not seeds:
        _fail("No seeds. Pass URLs or --seed-file.", EXIT_USAGE)

    config = CrawlConfig()
    config.concurrency = concurrency
    config.per_domain_concurrency = per_domain
    config.max_pages = max_pages
    config.max_depth = max_depth
    config.timeout_total = timeout
    config.same_domain_only = not cross_domain
    config.follow_external = cross_domain
    config.use_sitemap = sitemap
    config.respect_robots = robots
    config.proxy_enabled = bool(proxy)
    config.proxy_list = tuple(proxy or ())
    config.dry_run = dry_run
    if include:
        config.regex_include = tuple(include)
    if exclude:
        config.regex_exclude = tuple(exclude)
    if domain_allow:
        config.domain_allowlist = tuple(domain_allow)
    if domain_block:
        config.domain_blocklist = tuple(domain_block)
    crawl_module = _load_local_module("Fa_Crawl", "Fa-Crawl.py")
    CloudflareMode = getattr(crawl_module, "CloudflareMode")
    try:
        config.cloudflare_mode = CloudflareMode(cloudflare)
    except ValueError:
        _fail(f"Unknown cloudflare mode: {cloudflare}", EXIT_USAGE)

    ctl = _ctl(config)
    global _active_crawl
    _active_crawl = ctl

    dashboard = LiveDashboard(ctl, max_pages=max_pages)
    ctl.subscribe_stats(dashboard.on_stats)

    overrides = {"resume": resume}

    _header("Fa-Crab Crawl",
            f"crawler={crawler_type} seeds={len(seeds)} "
            f"concurrency={concurrency}")

    async def _go():
        if live and not _state["quiet"]:
            with Live(dashboard.build(), console=console,
                      refresh_per_second=4, screen=False) as lv:
                async def _refresher():
                    while ctl.state.value in ("running", "paused",
                                              "pausing", "stopping"):
                        await asyncio.sleep(0.25)
                        with contextlib.suppress(Exception):
                            lv.update(dashboard.build())

                task = asyncio.create_task(_refresher())
                try:
                    return await ctl.start(seeds, overrides=overrides,
                                            crawler_type=crawler_type)
                finally:
                    task.cancel()
                    with contextlib.suppress(Exception):
                        await task
        else:
            return await ctl.start(seeds, overrides=overrides,
                                    crawler_type=crawler_type)

    try:
        stats = _run(_go())
    except typer.Exit:
        raise
    except Exception as e:
        _fail(f"Crawl failed: {e}", EXIT_ERR)

    _print_crawl_summary(stats)
    if stats.get("errors", 0) and stats.get("fetched", 0) == 0:
        raise typer.Exit(EXIT_ERR)
    if stats.get("errors", 0) > 0 and stats.get("fetched", 0) > 0:
        raise typer.Exit(EXIT_PARTIAL)


def _print_crawl_summary(stats: dict) -> None:
    console.rule("[bold cyan]Crawl summary[/bold cyan]")
    rows = [
        ("State", stats.get("state", "-")),
        ("Fetched", stats.get("fetched", 0)),
        ("Parsed", stats.get("parsed", 0)),
        ("Written", stats.get("written", 0)),
        ("Errors", stats.get("errors", 0)),
        ("Retries", stats.get("retries", 0)),
        ("Dedup hits", stats.get("dedup_hits", 0)),
        ("Bytes in", _fmt_bytes(stats.get("bytes_in", 0))),
        ("Duration", _fmt_duration(stats.get("duration_seconds", 0.0))),
        ("Links seen", stats.get("links_seen", 0)),
    ]
    rate = stats.get("fetched", 0) / max(0.001,
                                          stats.get("duration_seconds", 1.0))
    rows.append(("Pages/sec", f"{rate:.2f}"))
    console.print(Panel(_kv_table(rows), box=ROUNDED))


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: health
# ════════════════════════════════════════════════════════════════════════════

@app.command("health")
def health_cmd(
    domains: list[str] = typer.Argument(..., help="Domains to check"),
    full: bool = typer.Option(False, "--full",
                               help="Also DNS + TLS checks"),
) -> None:
    """Run cross-domain health checks."""
    _apply_global_options()
    ctl = _ctl()

    async def _go():
        results = await ctl.check_health(domains)
        dns_map = {}
        tls_map = {}
        if full:
            dns_results = await asyncio.gather(
                *(ctl.health.check_dns(d) for d in domains),
                return_exceptions=True)
            tls_results = await asyncio.gather(
                *(ctl.health.check_tls(d) for d in domains),
                return_exceptions=True)
            dns_map = dict(zip(domains, dns_results))
            tls_map = dict(zip(domains, tls_results))
        return results, dns_map, tls_map

    try:
        with console.status("[cyan]Probing endpoints…"):
            results, dns_map, tls_map = _run(_go())
    except Exception as e:
        _fail(f"Health check failed: {e}", EXIT_NETWORK)

    t = Table(title="Health", box=ROUNDED)
    t.add_column("Domain", style="cyan")
    t.add_column("OK", justify="center")
    t.add_column("Status", justify="right")
    t.add_column("Latency", justify="right")
    if full:
        t.add_column("DNS", justify="center")
        t.add_column("TLS", justify="center")
    t.add_column("Error", overflow="fold")
    for d in domains:
        h = results.get(d)
        if h is None:
            continue
        row = [
            d,
            "[green]✓[/green]" if h.ok else "[red]✗[/red]",
            str(h.status),
            _fmt_ms(h.latency_ms),
        ]
        if full:
            dns_h = dns_map.get(d)
            tls_h = tls_map.get(d)
            row.append("[green]✓[/green]"
                       if dns_h and getattr(dns_h, "ok", False)
                       else "[red]✗[/red]")
            row.append("[green]✓[/green]"
                       if tls_h and getattr(tls_h, "ok", False)
                       else "[red]✗[/red]")
        row.append(_truncate(h.error, 60))
        t.add_row(*row)
    console.print(t)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: stats
# ════════════════════════════════════════════════════════════════════════════

@app.command("stats")
def stats_cmd(
    domain: Optional[str] = typer.Option(None, "--domain"),
    status: Optional[int] = typer.Option(None, "--status"),
    since: Optional[str] = typer.Option(None, "--since",
                                         help="ISO timestamp"),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Query the index and print record stats."""
    _apply_global_options()
    mgr = _mgr()

    console.rule("[bold cyan]Manager stats[/bold cyan]")
    snap = mgr.stats_snapshot()
    rows = [
        ("Dedup size", snap.get("dedup_size", 0)),
        ("Frontier size", snap.get("frontier_size", 0)),
        ("Manifest records", snap.get("manifest_records", 0)),
        ("Index records", snap.get("index_records", 0)),
    ]
    console.print(_kv_table(rows, "Storage"))

    console.rule("[bold cyan]Cache stats[/bold cyan]")
    cache_table = Table(box=SIMPLE)
    cache_table.add_column("Tier", style="cyan")
    cache_table.add_column("Size", justify="right")
    cache_table.add_column("Hits", justify="right")
    cache_table.add_column("Misses", justify="right")
    cache_table.add_column("Hit rate", justify="right")
    for tier, s in (snap.get("cache") or {}).items():
        cache_table.add_row(
            tier, str(s.get("size", 0)),
            str(s.get("hits", 0)), str(s.get("misses", 0)),
            f"{s.get('hit_rate', 0.0)*100:.1f}%")
    console.print(cache_table)

    console.rule("[bold cyan]Errors[/bold cyan]")
    err = snap.get("errors") or {}
    console.print(_kv_table([
        ("Total", err.get("total", 0)),
        ("Unique", err.get("unique", 0)),
    ], "Errors"))

    # Query results
    try:
        since_ts = None
        if since:
            from datetime import datetime as _dt
            since_ts = _dt.fromisoformat(since).timestamp()
        records = mgr.query.index.query(
            domain=domain, status=status, since=since_ts, limit=limit)
    except Exception as e:
        _warn(f"Index query failed: {e}")
        return
    if records:
        console.rule("[bold cyan]Recent records[/bold cyan]")
        t = Table(box=ROUNDED)
        t.add_column("URL", overflow="fold", max_width=60)
        t.add_column("Domain", style="cyan")
        t.add_column("Status", justify="right")
        t.add_column("Words", justify="right")
        for r in records:
            t.add_row(_truncate(r.get("url", ""), 60),
                      r.get("domain", ""),
                      str(r.get("status", 0)),
                      str(r.get("words", 0)))
        console.print(t)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: export
# ════════════════════════════════════════════════════════════════════════════

@app.command("export")
def export_cmd(
    src: str = typer.Argument(..., help="Input .jsonl or .jsonl.zst"),
    dst: str = typer.Argument(..., help="Output path"),
    fmt: str = typer.Option("csv", "--format", "-F",
                             help="csv | sqlite | jsonl"),
) -> None:
    """Export JSONL records to another format."""
    _apply_global_options()
    mgr = _mgr()
    src_p = Path(src)
    dst_p = Path(dst)
    if not src_p.exists():
        _fail(f"Source not found: {src_p}", EXIT_USAGE)

    try:
        with console.status(f"[cyan]Exporting {src} → {dst} ({fmt})…"):
            if fmt == "csv":
                n = mgr.export.to_csv(src_p, dst_p)
            elif fmt == "sqlite":
                n = mgr.export.to_sqlite(src_p, dst_p)
            elif fmt == "jsonl":
                n = 0
                with open(dst_p, "w", encoding="utf-8") as fh:
                    for rec in mgr.loader.iter_jsonl(src_p):
                        fh.write(json.dumps(rec, default=str) + "\n")
                        n += 1
            else:
                _fail(f"Unknown format: {fmt}", EXIT_USAGE)
    except Exception as e:
        _fail(f"Export failed: {e}", EXIT_ERR)
    _ok(f"Exported {n} records to {dst_p}")


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: verify
# ════════════════════════════════════════════════════════════════════════════

@app.command("verify")
def verify_cmd() -> None:
    """Verify manifest and index integrity."""
    _apply_global_options()
    mgr = _mgr()
    try:
        rep = mgr.integrity.verify()
    except Exception as e:
        _fail(f"Verify failed: {e}", EXIT_ERR)
    rows = [(k, v) for k, v in rep.items() if k != "missing_files"]
    console.print(Panel(_kv_table(rows), title="Integrity",
                        box=ROUNDED))
    missing = rep.get("missing_files") or []
    if missing:
        _warn(f"{len(missing)} missing chunk files")
        for m in missing[:20]:
            console.print(f"  [red]missing:[/red] {m}")
    else:
        _ok("All chunk files present.")


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: purge
# ════════════════════════════════════════════════════════════════════════════

@app.command("purge")
def purge_cmd(
    older_than_days: int = typer.Option(90, "--older-than-days"),
    dry_run: bool = typer.Option(False, "--dry-run"),
    archive: bool = typer.Option(True, "--archive/--delete"),
) -> None:
    """Delete or archive old output chunks."""
    _apply_global_options()
    mgr = _mgr()
    try:
        result = mgr.retention.enforce(
            max_age_days=older_than_days, archive=archive, dry_run=dry_run)
    except Exception as e:
        _fail(f"Purge failed: {e}", EXIT_ERR)
    if dry_run:
        _info(f"DRY RUN: would move {result['moved']}, "
              f"delete {result['deleted']}")
    else:
        _ok(f"Moved {result['moved']}, deleted {result['deleted']}")


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: robots
# ════════════════════════════════════════════════════════════════════════════

@app.command("robots")
def robots_cmd(
    url: str = typer.Argument(...),
) -> None:
    """Fetch and show parsed robots.txt rules."""
    _apply_global_options()
    ctl = _ctl()
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if not domain:
        _fail("Cannot parse domain from URL", EXIT_USAGE)

    async def _go():
        return await ctl.robots.get(domain)

    try:
        with console.status(f"[cyan]Fetching robots.txt for {domain}…"):
            rules = _run(_go())
    except Exception as e:
        _fail(f"Robots fetch failed: {e}", EXIT_NETWORK)
    if rules is None:
        _warn("No rules found.")
        return
    tree = Tree(f"[bold cyan]robots.txt: {domain}[/bold cyan]")
    disallow = tree.add(f"[red]Disallow[/red] ({len(rules.disallow)})")
    for r in rules.disallow[:50]:
        disallow.add(r.pattern)
    allow = tree.add(f"[green]Allow[/green] ({len(rules.allow)})")
    for r in rules.allow[:50]:
        allow.add(r.pattern)
    sm = tree.add(f"[blue]Sitemaps[/blue] ({len(rules.sitemaps)})")
    for s in rules.sitemaps[:20]:
        sm.add(s)
    tree.add(f"Crawl-delay: {rules.crawl_delay}s")
    console.print(tree)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: sitemap
# ════════════════════════════════════════════════════════════════════════════

@app.command("sitemap")
def sitemap_cmd(
    domain: str = typer.Argument(...),
    max_urls: int = typer.Option(1000, "--max"),
) -> None:
    """Discover and dump sitemap URLs for a domain."""
    _apply_global_options()
    ctl = _ctl()

    async def _go():
        urls = await ctl.sitemaps.discover(domain)
        collected: list[str] = []
        for sm in urls:
            try:
                collected.extend(await ctl.sitemaps.parse(
                    sm, max_urls=max_urls))
            except Exception:
                continue
        return urls, collected

    try:
        with console.status(f"[cyan]Discovering sitemaps for {domain}…"):
            sources, locs = _run(_go())
    except Exception as e:
        _fail(f"Sitemap discovery failed: {e}", EXIT_NETWORK)
    console.print(Panel(
        "\n".join(sources) if sources else "(none)",
        title="Sitemap sources", box=ROUNDED))
    console.print(f"[bold]URLs found:[/bold] {len(locs)}")
    for l in locs[:max_urls]:
        console.print(f"  {l}")


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: cookie
# ════════════════════════════════════════════════════════════════════════════

@app.command("cookie")
def cookie_cmd(
    action: str = typer.Argument("list", help="list | show | clear"),
    domain: Optional[str] = typer.Argument(None),
) -> None:
    """Manage the cookie jar."""
    _apply_global_options()
    mgr = _mgr()
    if action == "list":
        rows = []
        try:
            for d in list(mgr.cookies._domains or [])[:200]:  # noqa
                rows.append((d, "?"))
        except Exception:
            pass
        if not rows:
            _info("No cookie domains tracked.")
            return
        t = Table(box=ROUNDED)
        t.add_column("Domain", style="cyan")
        t.add_column("Cookies")
        for r in rows:
            t.add_row(*r)
        console.print(t)
        return
    if action == "show":
        if not domain:
            _fail("Usage: cookie show <domain>", EXIT_USAGE)
        cookies = mgr.cookies.all_for_domain(domain)
        if not cookies:
            _info(f"No cookies for {domain}.")
            return
        t = Table(title=f"Cookies: {domain}", box=ROUNDED)
        for c in ("name", "value", "path", "expires", "secure", "httponly"):
            t.add_column(c)
        for c in cookies:
            t.add_row(
                c.get("name", ""),
                _truncate(c.get("value", ""), 40),
                c.get("path", "/"),
                str(c.get("expires") or "session"),
                "✓" if c.get("secure") else "",
                "✓" if c.get("httponly") else "",
            )
        console.print(t)
        return
    if action == "clear":
        mgr.cookies.clear()
        _ok("Cookie jar cleared.")
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: dedup
# ════════════════════════════════════════════════════════════════════════════

@app.command("dedup")
def dedup_cmd(
    action: str = typer.Argument("stats", help="stats | check | clear"),
    url: Optional[str] = typer.Argument(None),
) -> None:
    """Inspect the URL dedup set."""
    _apply_global_options()
    mgr = _mgr()
    if action == "stats":
        console.print(_kv_table([
            ("Size", mgr.dedup.size()),
        ], "Dedup"))
        return
    if action == "check":
        if not url:
            _fail("Usage: dedup check <url>", EXIT_USAGE)
        seen = mgr.is_seen(url)
        console.print(
            f"[{'red' if seen else 'green'}]"
            f"{'SEEN' if seen else 'NOT SEEN'}[/]  {url}")
        return
    if action == "clear":
        if not Confirm.ask("Clear all seen URLs?"):
            return
        mgr.dedup.clear()
        _ok("Dedup set cleared.")
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: proxy
# ════════════════════════════════════════════════════════════════════════════

@app.command("proxy")
def proxy_cmd(
    action: str = typer.Argument("list", help="list | test"),
    proxy: Optional[list[str]] = typer.Option(None, "--proxy"),
    url: str = typer.Option("https://httpbin.org/ip", "--url"),
) -> None:
    """Inspect or test proxies."""
    _apply_global_options()
    if action == "list":
        if not proxy:
            _info("No proxies configured (use --proxy).")
            return
        for p in proxy:
            console.print(p)
        return
    if action == "test":
        if not proxy:
            _fail("Provide at least one --proxy", EXIT_USAGE)
            return
        ctl = _ctl()
        ctl.config.proxy_enabled = True
        ctl.config.proxy_list = tuple(proxy)
        async def _go():
            results = []
            for p in proxy:
                t0 = time.time()
                try:
                    # quick direct fetch through curl_cffi
                    session = await ctl.fetcher._get_curl_session(
                        await ctl.spoofer.next_profile("_proxy_test"),
                        p)
                    r = await session.get(url, timeout=10)
                    results.append((p, r.status_code,
                                    (time.time() - t0) * 1000))
                except Exception as e:
                    results.append((p, 0, (time.time() - t0) * 1000,
                                    str(e)[:80]))
            return results
        with console.status("[cyan]Testing proxies…"):
            rows = _run(_go())
        t = Table(box=ROUNDED)
        t.add_column("Proxy", style="cyan")
        t.add_column("Status", justify="right")
        t.add_column("Latency", justify="right")
        t.add_column("Error")
        for r in rows:
            if len(r) == 3:
                t.add_row(r[0], str(r[1]), _fmt_ms(r[2]), "")
            else:
                t.add_row(r[0], "[red]ERR[/red]", _fmt_ms(r[2]),
                          _truncate(r[3], 40))
        console.print(t)
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: queue
# ════════════════════════════════════════════════════════════════════════════

@app.command("queue")
def queue_cmd(
    action: str = typer.Argument("dump", help="dump | clear"),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    """Inspect the persisted frontier."""
    _apply_global_options()
    mgr = _mgr()
    if action == "dump":
        items = mgr.load_frontier()
        console.print(f"[bold]Frontier size:[/bold] {len(items)}")
        for item in items[:limit]:
            url, depth, priority = item
            console.print(f"  [dim]p={priority:.0f} d={depth}[/dim] {url}")
        return
    if action == "clear":
        if not Confirm.ask("Clear persisted frontier?"):
            return
        mgr.frontier.clear()
        _ok("Frontier cleared.")
        return
    _fail(f"Unknown action: {action}", EXIT_USAGE)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: resume
# ════════════════════════════════════════════════════════════════════════════

@app.command("resume")
def resume_cmd(
    crawler_type: str = typer.Option("generic", "--crawler", "-k"),
    live: bool = typer.Option(True, "--live/--no-live"),
) -> None:
    """Resume a crawl from the persisted frontier."""
    _apply_global_options()
    _install_signal_handlers()
    mgr = _mgr()
    snap = mgr.load_frontier()
    if not snap:
        _fail("No checkpoint frontier to resume from.", EXIT_USAGE)
    _info(f"Resuming with {len(snap)} queued URLs")

    ctl = _ctl()
    global _active_crawl
    _active_crawl = ctl
    dashboard = LiveDashboard(ctl)
    ctl.subscribe_stats(dashboard.on_stats)

    async def _go():
        if live:
            with Live(dashboard.build(), console=console,
                      refresh_per_second=4):
                async def _ref():
                    while ctl.state.value in ("running", "paused",
                                              "pausing", "stopping"):
                        await asyncio.sleep(0.25)
                        with contextlib.suppress(Exception):
                            lv.update(dashboard.build())
                return await ctl.start([], overrides={"resume": True},
                                        crawler_type=crawler_type)
        return await ctl.start([], overrides={"resume": True},
                                crawler_type=crawler_type)

    with Live(dashboard.build(), console=console,
              refresh_per_second=4) as lv:
        stats = _run(_go())
    _print_crawl_summary(stats)


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: gui
# ════════════════════════════════════════════════════════════════════════════

@app.command("gui")
def gui_cmd(
    background: bool = typer.Option(False, "--background"),
) -> None:
    """Launch the PyQt6 GUI (imports Fa-GUI lazily)."""
    _apply_global_options()
    try:
        gui_module = _load_local_module("Fa_GUI", "Fa-GUI.py")
        run_gui = getattr(gui_module, "run_gui")
    except Exception as e:
        _fail(f"GUI unavailable: {e}", EXIT_ERR)
    _info("Launching Fa-Crab GUI…")
    if background:
        import subprocess
        subprocess.Popen([sys.executable, "Fa-GUI.py"])
        return
    run_gui()


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: bench
# ════════════════════════════════════════════════════════════════════════════

@app.command("bench")
def bench_cmd(
    domains: list[str] = typer.Argument(
        ..., help="Domains to benchmark (e.g. example.com)"),
    pages_per_domain: int = typer.Option(5, "--pages"),
    concurrency: int = typer.Option(100, "--concurrency"),
) -> None:
    """Micro-benchmark cross-domain throughput."""
    _apply_global_options()
    ctl = _ctl()
    ctl.config.concurrency = concurrency
    ctl.config.max_pages = pages_per_domain * len(domains)

    seeds = [f"https://{d}/" for d in domains]
    _header("Benchmark",
            f"{len(seeds)} domains × {pages_per_domain} pages")

    async def _go():
        t0 = time.time()
        stats = await ctl.start(seeds, overrides={})
        return stats, time.time() - t0

    try:
        stats, elapsed = _run(_go())
    except Exception as e:
        _fail(f"Bench failed: {e}", EXIT_ERR)
    total = stats.get("fetched", 0)
    rate = total / max(0.001, elapsed)
    console.print(Panel(_kv_table([
        ("Total pages", total),
        ("Elapsed", _fmt_duration(elapsed)),
        ("Pages/sec", f"{rate:.2f}"),
        ("Per-domain rate",
         f"{rate / max(1, len(domains)):.2f} pages/s/domain"),
    ]), title="Benchmark result", box=ROUNDED))


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: repl — the interactive terminal scraper
# ════════════════════════════════════════════════════════════════════════════

def _repl_help() -> None:
    t = Table(title="REPL commands", box=ROUNDED)
    t.add_column("Command", style="cyan")
    t.add_column("Description")
    rows = [
        ("scrape <url>", "Fetch + extract a URL"),
        ("crawl <url> [url…]", "Start a crawl"),
        ("health <domain> […]", "Cross-domain health check"),
        ("robots <url>", "Show parsed robots.txt"),
        ("sitemap <domain>", "Discover sitemap URLs"),
        ("stats", "Show manager stats"),
        ("dedup <url>", "Check dedup set"),
        ("cache", "Show cache tier stats"),
        ("errors", "Show recent errors"),
        ("optimizer", "Show optimizer hints"),
        ("agents <family>", "Show UAs in a family"),
        ("config <path>", "Get a config value"),
        ("export <src> <dst> [fmt]", "Export JSONL"),
        ("verify", "Verify manifest/index"),
        ("browse <url>", "Open URL in browser"),
        ("clear", "Clear screen"),
        ("help", "Show this help"),
        ("quit / exit / q", "Leave REPL"),
    ]
    for cmd, desc in rows:
        t.add_row(cmd, desc)
    console.print(t)


def _repl_execute(line: str) -> bool:
    """
    Execute one REPL command.
    Returns True to keep running, False to exit.
    """
    line = line.strip()
    if not line:
        return True
    parts = line.split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd in ("quit", "exit", "q"):
        return False
    if cmd == "help":
        _repl_help()
        return True
    if cmd == "clear":
        console.clear()
        return True

    try:
        if cmd == "scrape":
            if not args:
                _warn("Usage: scrape <url>")
                return True
            scrape_cmd(args[0], show="summary")
        elif cmd == "crawl":
            if not args:
                _warn("Usage: crawl <url> [url…]")
                return True
            crawl_cmd(urls=args, seed_file=None, crawler_type="generic",
                      concurrency=100, per_domain=2, max_pages=0,
                      max_depth=3, timeout=30.0, cross_domain=False,
                      sitemap=True, robots=True, cloudflare="passive",
                      resume=False, dry_run=False, proxy=None,
                      include=None, exclude=None, domain_allow=None,
                      domain_block=None, live=True)
        elif cmd == "health":
            if not args:
                _warn("Usage: health <domain> […]")
                return True
            health_cmd(args, full=False)
        elif cmd == "robots":
            if not args:
                _warn("Usage: robots <url>")
                return True
            robots_cmd(args[0])
        elif cmd == "sitemap":
            if not args:
                _warn("Usage: sitemap <domain>")
                return True
            sitemap_cmd(args[0], max_urls=1000)
        elif cmd == "stats":
            stats_cmd()
        elif cmd == "dedup":
            if args:
                dedup_cmd("check", args[0])
            else:
                dedup_cmd("stats", None)
        elif cmd == "cache":
            mgr = _mgr()
            t = Table(box=ROUNDED)
            t.add_column("Tier", style="cyan")
            t.add_column("Size", justify="right")
            t.add_column("Hit rate", justify="right")
            for tier, s in mgr.cache.stats().items():
                t.add_row(tier, str(s.get("size", 0)),
                          f"{s.get('hit_rate', 0.0)*100:.1f}%")
            console.print(t)
        elif cmd == "errors":
            mgr = _mgr()
            records = mgr.errors.snapshot()
            if not records:
                _info("No errors recorded.")
            else:
                t = Table(box=ROUNDED)
                t.add_column("Sev", style="red")
                t.add_column("Category", style="cyan")
                t.add_column("Message", overflow="fold")
                for r in records[-30:]:
                    t.add_row(str(int(r.severity)),
                              r.category.value,
                              _truncate(r.message, 70))
                console.print(t)
        elif cmd == "optimizer":
            mgr = _mgr()
            hints = mgr.optimizer.hints()
            if not hints:
                _info("No optimizer hints yet.")
            else:
                t = Table(box=ROUNDED)
                t.add_column("Key", style="cyan")
                t.add_column("Current")
                t.add_column("Suggested")
                t.add_column("Confidence", justify="right")
                for h in hints[-20:]:
                    t.add_row(h.key, str(h.current_value),
                              str(h.suggested_value),
                              f"{h.confidence:.2f}")
                console.print(t)
        elif cmd == "agents":
            if not args:
                agents_cmd("list", None)
            else:
                agents_cmd("show", args[0])
        elif cmd == "config":
            if not args:
                _warn("Usage: config <path>")
                return True
            val = _mgr().config.get(args[0])
            console.print(f"[cyan]{args[0]}[/cyan] = {val!r}")
        elif cmd == "export":
            if len(args) < 2:
                _warn("Usage: export <src> <dst> [fmt]")
                return True
            export_cmd(args[0], args[1],
                       fmt=args[2] if len(args) > 2 else "csv")
        elif cmd == "verify":
            verify_cmd()
        elif cmd == "browse":
            if not args:
                _warn("Usage: browse <url>")
                return True
            webbrowser.open(args[0])
            _ok(f"Opened {args[0]} in default browser.")
        else:
            _warn(f"Unknown command: {cmd}. Type 'help' for commands.")
    except typer.Exit:
        pass
    except Exception as e:
        err_console.print(f"[red]Error:[/red] {e}")
    return True


@app.command("repl")
def repl_cmd() -> None:
    """Interactive Fa-Crab shell."""
    _apply_global_options()
    _install_signal_handlers()
    _header("Fa-Crab REPL",
            "Type 'help' for commands, 'quit' to exit.")
    history: deque[str] = deque(maxlen=500)
    try:
        while True:
            prompt = f"[bold cyan]fa-crab[/bold cyan] [{_now_iso()[11:19]}] > "
            try:
                line = Prompt.ask(prompt, default="")
            except (EOFError, KeyboardInterrupt):
                console.print()
                break
            if line:
                history.append(line)
            if not _repl_execute(line):
                break
    except Exception as e:
        err_console.print(f"[red]REPL crashed:[/red] {e}")
    console.print("[dim]Bye.[/dim]")


# ════════════════════════════════════════════════════════════════════════════
# Subcommand: interactive — first-run wizard
# ════════════════════════════════════════════════════════════════════════════

@app.command("interactive")
def interactive_cmd() -> None:
    """Step-by-step wizard for a new crawl."""
    _apply_global_options()
    _install_signal_handlers()
    console.rule("[bold cyan]Fa-Crab setup wizard[/bold cyan]")

    seed_text = Prompt.ask(
        "Seed URLs (comma-separated)", default="https://example.com")
    seeds = [s.strip() for s in seed_text.split(",") if s.strip()]

    crawler_type = Prompt.ask(
        "Crawler type",
        choices=list(CRABBER_REGISTRY.keys()),
        default="generic")
    concurrency = int(Prompt.ask("Concurrency", default="100"))
    max_pages = int(Prompt.ask("Max pages (0 = unlimited)", default="0"))
    max_depth = int(Prompt.ask("Max depth", default="3"))
    cross_domain = Confirm.ask("Follow external domains?", default=False)
    respect_robots = Confirm.ask("Respect robots.txt?", default=True)
    use_sitemap = Confirm.ask("Use sitemaps?", default=True)
    live = Confirm.ask("Show live dashboard?", default=True)

    console.print()
    console.print(Panel(_kv_table([
        ("Seeds", ", ".join(seeds)),
        ("Crawler", crawler_type),
        ("Concurrency", concurrency),
        ("Max pages", max_pages or "unlimited"),
        ("Max depth", max_depth),
        ("Cross-domain", cross_domain),
        ("Robots", respect_robots),
        ("Sitemap", use_sitemap),
    ]), title="Confirm", box=ROUNDED))

    if not Confirm.ask("Start crawl?", default=True):
        _info("Aborted.")
        return

    crawl_cmd(
        urls=seeds, seed_file=None, crawler_type=crawler_type,
        concurrency=concurrency, per_domain=2, max_pages=max_pages,
        max_depth=max_depth, timeout=30.0, cross_domain=cross_domain,
        sitemap=use_sitemap, robots=respect_robots,
        cloudflare="passive", resume=False, dry_run=False,
        proxy=None, include=None, exclude=None,
        domain_allow=None, domain_block=None, live=live,
    )


# ════════════════════════════════════════════════════════════════════════════
# Global options callback
# ════════════════════════════════════════════════════════════════════════════

@app.callback()
def _global_options(
    config_path: str = typer.Option("./Config.json", "--config", "-c",
                                     help="Path to Config.json"),
    agents_path: str = typer.Option("./Agents.json", "--agents", "-a",
                                     help="Path to Agents.json"),
    output_dir: str = typer.Option("./output", "--output", "-o"),
    state_dir: str = typer.Option("./state", "--state"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    no_color: bool = typer.Option(False, "--no-color"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """Global options applied to every subcommand."""
    _state["config_path"] = config_path
    _state["agents_path"] = agents_path
    _state["output_dir"] = output_dir
    _state["state_dir"] = state_dir
    _state["verbose"] = verbose
    _state["quiet"] = quiet
    _state["no_color"] = no_color
    _state["json"] = json_out
    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    if no_color:
        console._color_system = None  # type: ignore


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Entry point for `python Fa-Terminal.py`."""
    try:
        app()
    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted.[/yellow]")
        sys.exit(EXIT_PARTIAL)
    except Exception as e:
        err_console.print(f"[red]Fatal:[/red] {e}")
        if _state["verbose"]:
            import traceback
            traceback.print_exc()
        sys.exit(EXIT_ERR)


if __name__ == "__main__":
    main()