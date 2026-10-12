"""
Fa-GUI — PyQt6 desktop interface for Fa-Crab.

Run directly:
    python Fa-GUI.py

Integrates:
    Fa_Manager   — config, agents, stats, cache, errors, optimizer,
                   dedup, frontier, cookies, index, manifest.
    Fa_Crawl     — CrawlController, CrawlConfig, CloudflareMode,
                   CRABBER_REGISTRY, health checks.
    Fa_Scraper   — ScraperConfig, get_scraper.
    Fa_Terminal  — reused as console backend for the REPL tab.

Threading model:
    The GUI runs the Qt event loop on the main thread.
    A CrawlWorker (QThread) runs an asyncio event loop and drives a
    CrawlController instance. All GUI updates go through Qt signals.
"""

from __future__ import annotations

# ─── stdlib ──────────────────────────────────────────────────────────────────
import asyncio
import contextlib
import importlib.util
import json
import logging
import os
import queue
import re
import sys
import threading
import time
import traceback
import uuid
import webbrowser
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

# ─── PyQt6 ───────────────────────────────────────────────────────────────────
from PyQt6.QtCore import (
    QAbstractTableModel, QModelIndex, QObject, QSize, Qt, QThread,
    QTimer, pyqtSignal, pyqtSlot,
)
from PyQt6.QtGui import (
    QAction, QColor, QFont, QFontDatabase, QIcon, QKeySequence, QPalette,
    QPixmap, QShortcut, QSyntaxHighlighter, QTextCharFormat, QTextCursor,
)
from PyQt6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QDockWidget,
    QDoubleSpinBox, QFileDialog, QFrame, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMainWindow, QMenu, QMessageBox, QPlainTextEdit,
    QProgressBar, QPushButton, QRadioButton, QScrollArea, QSlider,
    QSpinBox, QSplitter, QStatusBar, QTabWidget, QTableView, QTextEdit,
    QToolBar, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

# ─── local ───────────────────────────────────────────────────────────────────
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
CRABBER_REGISTRY = getattr(_crawl_module, "CRABBER_REGISTRY")
CloudflareMode = getattr(_crawl_module, "CloudflareMode")

_scraper_module = _load_local_module("Fa_Scraper", "Fa-Scraper.py")
get_scraper = getattr(_scraper_module, "get_scraper")
reset_scraper = getattr(_scraper_module, "reset_scraper")
ScraperConfig = getattr(_scraper_module, "ScraperConfig")
scrape = getattr(_scraper_module, "scrape")
try:
    _terminal_module = _load_local_module("Fa_Terminal", "Fa-Terminal.py")
    terminal_repl_execute = getattr(_terminal_module, "_repl_execute")
    HAS_TERMINAL = True
except Exception:
    terminal_repl_execute = None  # type: ignore
    HAS_TERMINAL = False


__all__ = ["run_gui", "MainWindow", "CrawlWorker"]


# ════════════════════════════════════════════════════════════════════════════
# Constants
# ════════════════════════════════════════════════════════════════════════════

APP_NAME = "Fa-Crab"
APP_VERSION = "1.0.0"
STATE_DIR = Path("./state")
GUI_STATE_PATH = STATE_DIR / "gui_state.json"
GUI_LAYOUT_PATH = STATE_DIR / "gui_layout.json"

DARK_STYLESHEET = """
QMainWindow, QWidget { background: #1e1e2e; color: #cdd6f4;
    font-family: 'JetBrains Mono', 'Consolas', 'Menlo', monospace;
    font-size: 12px; }
QTabWidget::pane { border: 1px solid #313244; background: #1e1e2e; }
QTabBar::tab { background: #181825; color: #a6adc8;
    padding: 6px 14px; border: 1px solid #313244; border-bottom: none;
    border-top-left-radius: 6px; border-top-right-radius: 6px; }
QTabBar::tab:selected { background: #1e1e2e; color: #89b4fa; }
QTabBar::tab:hover { color: #cdd6f4; }
QLineEdit, QPlainTextEdit, QTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background: #181825; color: #cdd6f4; border: 1px solid #313244;
    border-radius: 4px; padding: 4px 6px; selection-background-color: #585b70; }
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QComboBox:focus { border-color: #89b4fa; }
QPushButton { background: #313244; color: #cdd6f4;
    border: 1px solid #45475a; border-radius: 4px; padding: 6px 14px; }
QPushButton:hover { background: #45475a; border-color: #89b4fa; }
QPushButton:pressed { background: #585b70; }
QPushButton:disabled { color: #6c7086; background: #232334; }
QPushButton#primary { background: #89b4fa; color: #1e1e2e; font-weight: bold; }
QPushButton#primary:hover { background: #b4befe; }
QPushButton#danger { background: #f38ba8; color: #1e1e2e; font-weight: bold; }
QPushButton#danger:hover { background: #eba0ac; }
QPushButton#warn { background: #f9e2af; color: #1e1e2e; font-weight: bold; }
QProgressBar { background: #181825; border: 1px solid #313244;
    border-radius: 4px; text-align: center; color: #cdd6f4; }
QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }
QTableView, QTreeWidget, QListWidget { background: #181825;
    alternate-background-color: #1e1e2e; color: #cdd6f4;
    border: 1px solid #313244; gridline-color: #313244; }
QHeaderView::section { background: #313244; color: #cdd6f4;
    padding: 4px 6px; border: none; }
QSlider::groove:horizontal { height: 6px; background: #313244;
    border-radius: 3px; }
QSlider::handle:horizontal { background: #89b4fa; width: 14px;
    margin: -5px 0; border-radius: 7px; }
QSlider::sub-page:horizontal { background: #89b4fa; border-radius: 3px; }
QGroupBox { border: 1px solid #313244; border-radius: 6px;
    margin-top: 12px; padding-top: 8px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; left: 10px;
    padding: 0 4px; color: #89b4fa; }
QMenuBar { background: #181825; color: #cdd6f4; }
QMenuBar::item:selected { background: #313244; }
QMenu { background: #181825; color: #cdd6f4; border: 1px solid #313244; }
QMenu::item:selected { background: #313244; }
QStatusBar { background: #181825; color: #a6adc8; }
QToolBar { background: #181825; border: none; spacing: 4px; }
QScrollBar:vertical { background: #181825; width: 10px; }
QScrollBar::handle:vertical { background: #45475a; border-radius: 5px;
    min-height: 20px; }
QScrollBar::handle:vertical:hover { background: #585b70; }
QScrollBar:horizontal { background: #181825; height: 10px; }
QScrollBar::handle:horizontal { background: #45475a; border-radius: 5px;
    min-width: 20px; }
QCheckBox { spacing: 6px; }
QCheckBox::indicator { width: 14px; height: 14px; }
QCheckBox::indicator:unchecked { border: 1px solid #45475a;
    background: #181825; border-radius: 3px; }
QCheckBox::indicator:checked { background: #89b4fa; border: 1px solid #89b4fa;
    border-radius: 3px; }
"""


# ════════════════════════════════════════════════════════════════════════════
# Signals — global bus for thread-to-GUI communication
# ════════════════════════════════════════════════════════════════════════════

class SignalBus(QObject):
    """Global signal bus for cross-tab communication."""
    stats_updated = pyqtSignal(dict)
    page_scraped = pyqtSignal(dict)
    log_line = pyqtSignal(str, str)          # level, message
    error_raised = pyqtSignal(str, str)      # category, message
    warning_raised = pyqtSignal(str, str)
    crawl_state = pyqtSignal(str)
    crawl_finished = pyqtSignal(dict)
    config_reloaded = pyqtSignal()
    record_written = pyqtSignal(dict)


BUS = SignalBus()


# ════════════════════════════════════════════════════════════════════════════
# Crawl Worker Thread
# ════════════════════════════════════════════════════════════════════════════

class CrawlWorker(QThread):
    """
    Runs a CrawlController on an asyncio loop in its own thread.
    Emits signals (thread-safe) that widgets subscribe to.
    """

    stats_tick = pyqtSignal(dict)
    page_done = pyqtSignal(dict)
    log_line = pyqtSignal(str, str)
    error = pyqtSignal(str, str)
    state = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, mgr, seeds: list[str], config: Any,
                 crawler_type: str, parent=None):
        super().__init__(parent)
        self.mgr = mgr
        self.seeds = list(seeds)
        self.config = config
        self.crawler_type = crawler_type
        self._controller: Optional[Any] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._stop_flag = False

    def run(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._controller = CrawlController(mgr=self.mgr, config=self.config)
            self._controller.subscribe_stats(self._on_stats)
            self.state.emit("running")
            stats = self._loop.run_until_complete(
                self._controller.start(self.seeds,
                                       crawler_type=self.crawler_type))
            self.state.emit("done")
            self.finished.emit(stats)
        except Exception as e:
            tb = traceback.format_exc()
            self.error.emit("internal", f"{e}\n{tb}")
            self.state.emit("failed")
        finally:
            with contextlib.suppress(Exception):
                self._loop.run_until_complete(
                    self._controller._shutdown())
            self._loop.close()
            self._loop = None

    def _on_stats(self, snapshot: dict) -> None:
        self.stats_tick.emit(dict(snapshot))

    def request_stop(self) -> None:
        self._stop_flag = True
        if self._controller and self._loop:
            self._loop.call_soon_threadsafe(
                self._controller._stop_event.set)

    def request_pause(self) -> None:
        if self._controller and self._loop:
            self._loop.call_soon_threadsafe(
                self._controller._pause_event.clear)

    def request_resume(self) -> None:
        if self._controller and self._loop:
            self._loop.call_soon_threadsafe(
                self._controller._pause_event.set)

    @property
    def controller(self) -> Optional[Any]:
        return self._controller


# ════════════════════════════════════════════════════════════════════════════
# JSON syntax highlighter for the config editor
# ════════════════════════════════════════════════════════════════════════════

class JsonHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self._rules: list[tuple[re.Pattern, QTextCharFormat]] = []
        self._build()

    def _build(self) -> None:
        def fmt(color: str, bold: bool = False, italic: bool = False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:
                f.setFontWeight(QFont.Weight.Bold)
            if italic:
                f.setFontItalic(True)
            return f

        self._rules.append((re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"(?=\s*:)'),
                            fmt("#89b4fa", bold=True)))
        self._rules.append((re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"'),
                            fmt("#a6e3a1")))
        self._rules.append((re.compile(r"\b(true|false|null)\b"),
                            fmt("#f38ba8", bold=True)))
        self._rules.append((re.compile(r"-?\b\d+(\.\d+)?([eE][+\-]?\d+)?\b"),
                            fmt("#fab387")))
        self._rules.append((re.compile(r"[{}\[\],:]"),
                            fmt("#cba6f7", bold=True)))

    def highlightBlock(self, text: str) -> None:
        for pattern, fmt in self._rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ════════════════════════════════════════════════════════════════════════════
# Data model for the results table
# ════════════════════════════════════════════════════════════════════════════

class ResultsModel(QAbstractTableModel):
    COLUMNS = ("URL", "Domain", "Status", "Title", "Words",
               "Most used", "Least used", "Links", "Quality", "Ms")

    def __init__(self, parent=None, cap: int = 50000):
        super().__init__(parent)
        self._rows: deque[dict] = deque(maxlen=cap)

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return self.COLUMNS[section]
        return str(section + 1)

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            key = self._key_for(col)
            v = row.get(key, "")
            if key == "title" and isinstance(v, str):
                return v[:120]
            return v
        if role == Qt.ItemDataRole.ToolTipRole:
            return json.dumps(row, default=str)[:1500]
        if role == Qt.ItemDataRole.ForegroundRole and col == 2:
            code = row.get("status", 0)
            if 200 <= code < 300:
                return QColor("#a6e3a1")
            if 300 <= code < 400:
                return QColor("#f9e2af")
            if code >= 400:
                return QColor("#f38ba8")
        return None

    @staticmethod
    def _key_for(col: int) -> str:
        return {
            0: "url", 1: "domain", 2: "status", 3: "title",
            4: "words_count", 5: "most_used_word", 6: "least_used_word",
            7: "links_count", 8: "quality_score", 9: "elapsed_ms",
        }[col]

    def append(self, record: dict) -> None:
        row = dict(record)
        row["links_count"] = (len(row.get("links", {}).get("internal", [])) +
                              len(row.get("links", {}).get("external", []))) \
            if isinstance(row.get("links"), dict) else 0
        q = row.get("quality") or {}
        row["quality_score"] = q.get("score", 0) if isinstance(q, dict) else 0
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(row)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def row_at(self, i: int) -> Optional[dict]:
        if 0 <= i < len(self._rows):
            return self._rows[i]
        return None

    def all_rows(self) -> list[dict]:
        return list(self._rows)


# ════════════════════════════════════════════════════════════════════════════
# Reusable widgets
# ════════════════════════════════════════════════════════════════════════════

class StatCard(QFrame):
    """Compact numeric stat widget."""

    def __init__(self, label: str, value: str = "0", color: str = "#89b4fa"):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setStyleSheet(
            f"QFrame {{ background: #181825; border: 1px solid #313244;"
            f" border-radius: 6px; }}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 6, 10, 6)
        lay.setSpacing(2)
        self.label = QLabel(label)
        self.label.setStyleSheet("color: #a6adc8; font-size: 10px;")
        self.value = QLabel(value)
        self.value.setStyleSheet(
            f"color: {color}; font-size: 18px; font-weight: bold;")
        lay.addWidget(self.label)
        lay.addWidget(self.value)

    def set_value(self, v: str) -> None:
        self.value.setText(v)


class Sparkline(QWidget):
    """Lightweight QPainter-based sparkline (no matplotlib needed)."""

    def __init__(self, max_points: int = 120, color: str = "#89b4fa"):
        super().__init__()
        self.setMinimumHeight(60)
        self._points: deque[float] = deque(maxlen=max_points)
        self._color = QColor(color)

    def push(self, v: float) -> None:
        self._points.append(v)
        self.update()

    def clear(self) -> None:
        self._points.clear()
        self.update()

    def paintEvent(self, event) -> None:
        from PyQt6.QtGui import QPainter, QPen
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QColor("#181825"))
        if len(self._points) < 2:
            p.end()
            return
        mx = max(self._points) or 1.0
        pen = QPen(self._color, 1.6)
        p.setPen(pen)
        n = len(self._points)
        step = w / (n - 1) if n > 1 else w
        prev = None
        for i, v in enumerate(self._points):
            x = i * step
            y = h - (v / mx) * (h - 4) - 2
            if prev is not None:
                p.drawLine(int(prev[0]), int(prev[1]), int(x), int(y))
            prev = (x, y)
        p.end()


# ════════════════════════════════════════════════════════════════════════════
# Tab: Dashboard
# ════════════════════════════════════════════════════════════════════════════

class DashboardTab(QWidget):
    """Main crawl configuration + live stats."""

    start_requested = pyqtSignal(dict)
    stop_requested = pyqtSignal()
    pause_requested = pyqtSignal()
    resume_requested = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Top splitter: config form | live stats
        splitter = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(splitter, 1)

        # ─── Left: config form ────────────────────────────────────────────
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(8)

        # URLs
        g_urls = QGroupBox("Target URLs (one per line)")
        v = QVBoxLayout(g_urls)
        self.urls_edit = QPlainTextEdit()
        self.urls_edit.setPlaceholderText(
            "https://example.com\nhttps://another.com")
        self.urls_edit.setPlainText("https://example.com")
        v.addWidget(self.urls_edit)
        left_lay.addWidget(g_urls, 2)

        # Request options row
        g_req = QGroupBox("Request")
        grid = QGridLayout(g_req)
        grid.addWidget(QLabel("Method:"), 0, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "HEAD",
                                     "OPTIONS", "PATCH"])
        grid.addWidget(self.method_combo, 0, 1)
        grid.addWidget(QLabel("Crawler:"), 0, 2)
        self.crawler_combo = QComboBox()
        self.crawler_combo.addItems(sorted(CRABBER_REGISTRY.keys()))
        grid.addWidget(self.crawler_combo, 0, 3)
        grid.addWidget(QLabel("CF Mode:"), 0, 4)
        self.cf_combo = QComboBox()
        self.cf_combo.addItems([m.value for m in CloudflareMode])
        self.cf_combo.setCurrentText("passive")
        grid.addWidget(self.cf_combo, 0, 5)
        left_lay.addWidget(g_req)

        # Headers
        g_headers = QGroupBox("Headers & Cookies")
        v = QVBoxLayout(g_headers)
        self.headers_edit = QPlainTextEdit()
        self.headers_edit.setPlaceholderText(
            '{"User-Agent": "...", "Cookie": "..."}')
        self.headers_edit.setMaximumHeight(80)
        v.addWidget(self.headers_edit)
        left_lay.addWidget(g_headers)

        # Payload
        g_payload = QGroupBox("Payload / Body")
        v = QVBoxLayout(g_payload)
        self.payload_edit = QPlainTextEdit()
        self.payload_edit.setPlaceholderText('{"key": "value"}')
        self.payload_edit.setMaximumHeight(70)
        v.addWidget(self.payload_edit)
        left_lay.addWidget(g_payload)

        # Selector
        g_sel = QGroupBox("Selector (CSS or XPath)")
        h = QHBoxLayout(g_sel)
        self.selector_edit = QLineEdit()
        self.selector_edit.setPlaceholderText(
            "e.g. article, div.content, //div[@id='main']")
        h.addWidget(self.selector_edit)
        left_lay.addWidget(g_sel)

        # Output
        g_out = QGroupBox("Output")
        grid = QGridLayout(g_out)
        grid.addWidget(QLabel("Format:"), 0, 0)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["jsonl", "csv", "xlsx", "parquet",
                                     "sqlite"])
        grid.addWidget(self.format_combo, 0, 1)
        grid.addWidget(QLabel("Directory:"), 0, 2)
        self.dir_edit = QLineEdit(str(Path("./output").resolve()))
        grid.addWidget(self.dir_edit, 0, 3)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._pick_dir)
        grid.addWidget(browse, 0, 4)
        left_lay.addWidget(g_out)

        # Concurrency / speed
        g_speed = QGroupBox("Concurrency & Limits")
        grid = QGridLayout(g_speed)
        grid.addWidget(QLabel("Concurrency:"), 0, 0)
        self.concurrency_slider = QSlider(Qt.Orientation.Horizontal)
        self.concurrency_slider.setRange(1, 2000)
        self.concurrency_slider.setValue(100)
        grid.addWidget(self.concurrency_slider, 0, 1)
        self.concurrency_lbl = QLabel("100")
        grid.addWidget(self.concurrency_lbl, 0, 2)
        self.concurrency_slider.valueChanged.connect(
            lambda v: self.concurrency_lbl.setText(str(v)))

        grid.addWidget(QLabel("Per-domain:"), 1, 0)
        self.per_domain_spin = QSpinBox()
        self.per_domain_spin.setRange(1, 100)
        self.per_domain_spin.setValue(2)
        grid.addWidget(self.per_domain_spin, 1, 1)

        grid.addWidget(QLabel("Max pages:"), 2, 0)
        self.max_pages_spin = QSpinBox()
        self.max_pages_spin.setRange(0, 10_000_000)
        self.max_pages_spin.setValue(0)
        self.max_pages_spin.setSpecialValueText("unlimited")
        grid.addWidget(self.max_pages_spin, 2, 1)

        grid.addWidget(QLabel("Max depth:"), 3, 0)
        self.max_depth_spin = QSpinBox()
        self.max_depth_spin.setRange(0, 20)
        self.max_depth_spin.setValue(3)
        grid.addWidget(self.max_depth_spin, 3, 1)

        grid.addWidget(QLabel("Timeout (s):"), 4, 0)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(1.0, 600.0)
        self.timeout_spin.setValue(30.0)
        grid.addWidget(self.timeout_spin, 4, 1)

        # Checkboxes
        self.robots_cb = QCheckBox("Respect robots.txt")
        self.robots_cb.setChecked(True)
        grid.addWidget(self.robots_cb, 5, 0)
        self.sitemap_cb = QCheckBox("Use sitemaps")
        self.sitemap_cb.setChecked(True)
        grid.addWidget(self.sitemap_cb, 5, 1)
        self.cross_domain_cb = QCheckBox("Cross-domain follow")
        grid.addWidget(self.cross_domain_cb, 6, 0)
        self.dry_run_cb = QCheckBox("Dry run")
        grid.addWidget(self.dry_run_cb, 6, 1)
        left_lay.addWidget(g_speed)

        # Buttons
        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("▶  Start")
        self.start_btn.setObjectName("primary")
        self.start_btn.clicked.connect(self._on_start)
        self.pause_btn = QPushButton("⏸  Pause")
        self.pause_btn.setObjectName("warn")
        self.pause_btn.setEnabled(False)
        self.pause_btn.clicked.connect(self._on_pause)
        self.stop_btn = QPushButton("■  Stop")
        self.stop_btn.setObjectName("danger")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.pause_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addStretch()
        left_lay.addLayout(btn_row)
        left_lay.addStretch()

        splitter.addWidget(left)

        # ─── Right: live stats ────────────────────────────────────────────
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(8)

        # Stat cards grid
        grid = QGridLayout()
        self.card_fetched = StatCard("Fetched", "0", "#89b4fa")
        self.card_written = StatCard("Written", "0", "#a6e3a1")
        self.card_errors = StatCard("Errors", "0", "#f38ba8")
        self.card_rate = StatCard("Pages/sec", "0.0", "#fab387")
        self.card_queue = StatCard("Frontier", "0", "#cba6f7")
        self.card_inflight = StatCard("In-flight", "0", "#94e2d5")
        self.card_bytes = StatCard("Bytes in", "0 B", "#f9e2af")
        self.card_health = StatCard("Health", "–", "#b4befe")
        for i, c in enumerate([
            self.card_fetched, self.card_written, self.card_errors,
            self.card_rate, self.card_queue, self.card_inflight,
            self.card_bytes, self.card_health,
        ]):
            grid.addWidget(c, i // 2, i % 2)
        right_lay.addLayout(grid)

        # Sparkline
        sp_box = QGroupBox("Throughput")
        v = QVBoxLayout(sp_box)
        self.sparkline = Sparkline()
        v.addWidget(self.sparkline)
        right_lay.addWidget(sp_box)

        # Progress
        prog_box = QGroupBox("Progress")
        v = QVBoxLayout(prog_box)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        v.addWidget(self.progress_bar)
        self.progress_lbl = QLabel("Idle")
        self.progress_lbl.setStyleSheet("color: #a6adc8;")
        v.addWidget(self.progress_lbl)
        right_lay.addWidget(prog_box)

        right_lay.addStretch()
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

    def _pick_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(
            self, "Choose output directory", self.dir_edit.text())
        if d:
            self.dir_edit.setText(d)

    def _on_start(self) -> None:
        raw = self.urls_edit.toPlainText().strip()
        urls = [u.strip() for u in raw.splitlines() if u.strip()]
        if not urls:
            QMessageBox.warning(self, "No URLs",
                                 "Please provide at least one URL.")
            return
        cfg = self._gather_config()
        self.start_requested.emit({
            "urls": urls, "config": cfg,
            "crawler_type": self.crawler_combo.currentText(),
        })

    def _on_pause(self) -> None:
        self.pause_requested.emit()

    def _on_stop(self) -> None:
        self.stop_requested.emit()

    def _gather_config(self) -> Any:
        c = CrawlConfig()
        c.concurrency = self.concurrency_slider.value()
        c.per_domain_concurrency = self.per_domain_spin.value()
        c.max_pages = self.max_pages_spin.value()
        c.max_depth = self.max_depth_spin.value()
        c.timeout_total = self.timeout_spin.value()
        c.respect_robots = self.robots_cb.isChecked()
        c.use_sitemap = self.sitemap_cb.isChecked()
        c.follow_external = self.cross_domain_cb.isChecked()
        c.same_domain_only = not self.cross_domain_cb.isChecked()
        c.dry_run = self.dry_run_cb.isChecked()
        try:
            c.cloudflare_mode = CloudflareMode(self.cf_combo.currentText())
        except Exception:
            pass
        return c

    def set_running(self, running: bool) -> None:
        self.start_btn.setEnabled(not running)
        self.pause_btn.setEnabled(running)
        self.stop_btn.setEnabled(running)

    def update_stats(self, snapshot: dict) -> None:
        self.card_fetched.set_value(str(snapshot.get("fetched", 0)))
        self.card_written.set_value(str(snapshot.get("written", 0)))
        self.card_errors.set_value(str(snapshot.get("errors", 0)))
        self.card_queue.set_value(str(snapshot.get("in_flight", 0)))
        self.card_inflight.set_value(str(snapshot.get("in_flight", 0)))
        b = snapshot.get("bytes_in", 0)
        self.card_bytes.set_value(self._fmt_bytes(b))
        elapsed = max(0.001, time.time() - snapshot.get("started_at",
                                                          time.time()))
        rate = snapshot.get("fetched", 0) / elapsed
        self.card_rate.set_value(f"{rate:.1f}")
        self.sparkline.push(rate)

    @staticmethod
    def _fmt_bytes(n: int) -> str:
        n = float(n)
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} PB"


# ════════════════════════════════════════════════════════════════════════════
# Tab: Live Crawl (data preview)
# ════════════════════════════════════════════════════════════════════════════

class LiveCrawlTab(QWidget):
    """Real-time preview table of scraped records."""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter (regex on URL/title)…")
        self.filter_edit.textChanged.connect(self._apply_filter)
        top.addWidget(QLabel("Filter:"))
        top.addWidget(self.filter_edit, 1)
        self.clear_btn = QPushButton("Clear table")
        self.clear_btn.clicked.connect(self._clear)
        top.addWidget(self.clear_btn)
        lay.addLayout(top)

        self.model = ResultsModel()
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.view.setSortingEnabled(False)
        header = self.view.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            header.setStretchLastSection(True)
        self.view.setColumnWidth(0, 320)
        self.view.setColumnWidth(1, 140)
        self.view.setColumnWidth(2, 60)
        self.view.setColumnWidth(3, 240)
        self.view.doubleClicked.connect(self._on_double_click)
        lay.addWidget(self.view, 1)

        self._filter = ""

    def append_record(self, record: dict) -> None:
        if self._filter:
            try:
                rx = re.compile(self._filter, re.IGNORECASE)
            except re.error:
                rx = None
            if rx:
                url = str(record.get("url", ""))
                title = str(record.get("title", ""))
                if not (rx.search(url) or rx.search(title)):
                    return
        self.model.append(record)

    def _apply_filter(self, text: str) -> None:
        self._filter = text.strip()

    def _clear(self) -> None:
        self.model.clear()

    def _on_double_click(self, index: QModelIndex) -> None:
        row = self.model.row_at(index.row())
        if not row:
            return
        url = row.get("url", "")
        if url:
            webbrowser.open(str(url))


# ════════════════════════════════════════════════════════════════════════════
# Tab: Results (with export)
# ════════════════════════════════════════════════════════════════════════════

class ResultsTab(QWidget):
    """Full results with manual export to CSV/JSONL/XLSX."""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.clicked.connect(lambda: self._export("csv"))
        self.export_jsonl_btn = QPushButton("Export JSONL")
        self.export_jsonl_btn.clicked.connect(lambda: self._export("jsonl"))
        self.export_xlsx_btn = QPushButton("Export XLSX")
        self.export_xlsx_btn.clicked.connect(lambda: self._export("xlsx"))
        self.load_btn = QPushButton("Load from disk…")
        self.load_btn.clicked.connect(self._load_from_disk)
        top.addWidget(self.export_csv_btn)
        top.addWidget(self.export_jsonl_btn)
        top.addWidget(self.export_xlsx_btn)
        top.addWidget(self.load_btn)
        top.addStretch()
        self.count_lbl = QLabel("0 rows")
        top.addWidget(self.count_lbl)
        lay.addLayout(top)

        self.model = ResultsModel()
        self.view = QTableView()
        self.view.setModel(self.model)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        header = self.view.horizontalHeader()
        if header is not None:
            header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.view.setColumnWidth(0, 320)
        self.view.setColumnWidth(3, 240)
        lay.addWidget(self.view, 1)

        self.model.rowsInserted.connect(
            lambda *_: self.count_lbl.setText(
                f"{self.model.rowCount()} rows"))
        self.model.modelReset.connect(
            lambda: self.count_lbl.setText(
                f"{self.model.rowCount()} rows"))

    def append_record(self, record: dict) -> None:
        self.model.append(record)

    def _export(self, fmt: str) -> None:
        rows = self.model.all_rows()
        if not rows:
            QMessageBox.information(self, "Empty",
                                     "No rows to export.")
            return
        ext = {"csv": ".csv", "jsonl": ".jsonl", "xlsx": ".xlsx"}[fmt]
        path, _ = QFileDialog.getSaveFileName(
            self, f"Save as {fmt.upper()}", str(Path.home() / f"fa-crab{ext}"),
            f"*{ext}")
        if not path:
            return
        try:
            if fmt == "csv":
                self._write_csv(rows, path)
            elif fmt == "jsonl":
                self._write_jsonl(rows, path)
            elif fmt == "xlsx":
                self._write_xlsx(rows, path)
            QMessageBox.information(self, "Exported",
                                     f"Wrote {len(rows)} rows to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))

    @staticmethod
    def _write_csv(rows: list[dict], path: str) -> None:
        import csv
        keys = ("url", "domain", "status", "title", "words_count",
                "most_used_word", "least_used_word", "cleaned",
                "elapsed_ms", "timestamp")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(keys), extrasaction="ignore")
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in keys})

    @staticmethod
    def _write_jsonl(rows: list[dict], path: str) -> None:
        import orjson
        with open(path, "wb") as fh:
            for r in rows:
                fh.write(orjson.dumps(r, option=orjson.OPT_NON_STR_KEYS))
                fh.write(b"\n")

    @staticmethod
    def _write_xlsx(rows: list[dict], path: str) -> None:
        try:
            Workbook = importlib.import_module("openpyxl").Workbook
        except Exception:
            # fallback: write CSV with xlsx extension
            ResultsTab._write_csv(rows, path)
            return
        wb = Workbook()
        ws = wb.active
        if ws is None:
            raise RuntimeError("Workbook has no active worksheet")
        ws.title = "Fa-Crab"
        keys = ("url", "domain", "status", "title", "words_count",
                "most_used_word", "least_used_word", "elapsed_ms",
                "timestamp")
        ws.append(list(keys))
        for r in rows:
            ws.append([str(r.get(k, ""))[:32000] for k in keys])
        wb.save(path)

    def _load_from_disk(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open JSONL", str(Path("./output").resolve()),
            "JSONL (*.jsonl *.jsonl.zst);;All files (*)")
        if not path:
            return
        try:
            mgr = get_manager()
            self.model.clear()
            n = 0
            if path.endswith(".zst"):
                it = mgr.loader.iter_jsonl_zst(path)
            else:
                it = mgr.loader.iter_jsonl(path)
            for rec in it:
                self.model.append(rec)
                n += 1
                if n >= 100_000:
                    break
            QMessageBox.information(self, "Loaded", f"Loaded {n} rows.")
        except Exception as e:
            QMessageBox.critical(self, "Load failed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# Tab: Config Editor
# ════════════════════════════════════════════════════════════════════════════

class ConfigEditorTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.path_lbl = QLabel("Path: –")
        top.addWidget(self.path_lbl, 1)
        reload_btn = QPushButton("Reload")
        reload_btn.clicked.connect(self.load)
        save_btn = QPushButton("Save")
        save_btn.setObjectName("primary")
        save_btn.clicked.connect(self.save)
        validate_btn = QPushButton("Validate")
        validate_btn.clicked.connect(self.validate)
        top.addWidget(reload_btn)
        top.addWidget(validate_btn)
        top.addWidget(save_btn)
        lay.addLayout(top)

        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("JetBrains Mono", 10))
        self.highlighter = JsonHighlighter(self.editor.document())
        lay.addWidget(self.editor, 1)

        self.status_lbl = QLabel("")
        lay.addWidget(self.status_lbl)

    def load(self) -> None:
        try:
            mgr = get_manager()
            path = mgr.paths["config"]
            self.path_lbl.setText(f"Path: {path}")
            text = path.read_text(encoding="utf-8")
            self.editor.setPlainText(text)
            self.status_lbl.setText("Loaded.")
            self.status_lbl.setStyleSheet("color: #a6e3a1;")
        except Exception as e:
            self.status_lbl.setText(f"Load failed: {e}")
            self.status_lbl.setStyleSheet("color: #f38ba8;")

    def save(self) -> None:
        try:
            text = self.editor.toPlainText()
            data = json.loads(text)  # validate
            mgr = get_manager()
            path = mgr.paths["config"]
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
            mgr.reload_config()
            self.status_lbl.setText("Saved + reloaded.")
            self.status_lbl.setStyleSheet("color: #a6e3a1;")
            BUS.config_reloaded.emit()
        except json.JSONDecodeError as e:
            self.status_lbl.setText(f"Invalid JSON: {e}")
            self.status_lbl.setStyleSheet("color: #f38ba8;")
        except Exception as e:
            self.status_lbl.setText(f"Save failed: {e}")
            self.status_lbl.setStyleSheet("color: #f38ba8;")

    def validate(self) -> None:
        try:
            json.loads(self.editor.toPlainText())
            self.status_lbl.setText("Valid JSON.")
            self.status_lbl.setStyleSheet("color: #a6e3a1;")
        except json.JSONDecodeError as e:
            self.status_lbl.setText(f"Invalid: {e}")
            self.status_lbl.setStyleSheet("color: #f38ba8;")


# ════════════════════════════════════════════════════════════════════════════
# Tab: Agents Viewer
# ════════════════════════════════════════════════════════════════════════════

class AgentsTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        # Left: tree of families
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Family", "Count"])
        self.tree.itemClicked.connect(self._on_select)
        lay.addWidget(self.tree, 1)

        # Right: details
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        self.title_lbl = QLabel("Select a family")
        self.title_lbl.setStyleSheet(
            "font-weight: bold; font-size: 14px; color: #89b4fa;")
        right_lay.addWidget(self.title_lbl)
        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setFont(QFont("JetBrains Mono", 10))
        right_lay.addWidget(self.detail, 1)
        lay.addWidget(right, 2)
        lay.setStretch(0, 1)
        lay.setStretch(1, 2)

        self._agents: dict = {}

    def load(self) -> None:
        self.tree.clear()
        try:
            mgr = get_manager()
            self._agents = mgr.agents.as_dict()
        except Exception:
            return
        uas = self._agents.get("user_agents", {})
        for fam, list_ in sorted(uas.items()):
            item = QTreeWidgetItem([fam, str(len(list_))])
            self.tree.addTopLevelItem(item)
        self.tree.resizeColumnToContents(0)

    def _on_select(self, item: QTreeWidgetItem, _col: int) -> None:
        fam = item.text(0)
        uas = self._agents.get("user_agents", {}).get(fam, [])
        self.title_lbl.setText(f"{fam}  ({len(uas)} UAs)")
        self.detail.setPlainText("\n\n".join(uas))


# ════════════════════════════════════════════════════════════════════════════
# Tab: Cache
# ════════════════════════════════════════════════════════════════════════════

class CacheTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        clear_sel = QPushButton("Clear selected")
        clear_sel.clicked.connect(self._clear_selected)
        clear_all = QPushButton("Clear all")
        clear_all.setObjectName("danger")
        clear_all.clicked.connect(self._clear_all)
        top.addWidget(refresh)
        top.addWidget(clear_sel)
        top.addWidget(clear_all)
        top.addStretch()
        lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Tier", "Size", "Max", "Hits", "Misses",
                                    "Evictions", "Hit rate"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def refresh(self) -> None:
        self.tree.clear()
        try:
            mgr = get_manager()
            stats = mgr.cache.stats()
        except Exception as e:
            return
        for tier, s in stats.items():
            QTreeWidgetItem(self.tree, [
                tier, str(s.get("size", 0)),
                str(s.get("maxsize", "-") or "-"),
                str(s.get("hits", 0)), str(s.get("misses", 0)),
                str(s.get("evictions", 0)),
                f"{s.get('hit_rate', 0.0)*100:.1f}%",
            ])
        for c in range(self.tree.columnCount()):
            self.tree.resizeColumnToContents(c)

    def _clear_selected(self) -> None:
        item = self.tree.currentItem()
        if not item:
            return
        try:
            tier = CacheTier(item.text(0))
            get_manager().cache.clear(tier)
            self.refresh()
        except Exception:
            pass

    def _clear_all(self) -> None:
        try:
            get_manager().cache.clear(None)
            self.refresh()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# Tab: Health
# ════════════════════════════════════════════════════════════════════════════

class HealthTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.domains_edit = QLineEdit()
        self.domains_edit.setPlaceholderText(
            "example.com, github.com, wikipedia.org")
        top.addWidget(QLabel("Domains:"))
        top.addWidget(self.domains_edit, 1)
        check_btn = QPushButton("Check")
        check_btn.setObjectName("primary")
        check_btn.clicked.connect(self._check)
        top.addWidget(check_btn)
        self.full_cb = QCheckBox("Include DNS + TLS")
        top.addWidget(self.full_cb)
        lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Domain", "Status", "OK", "HTTP",
                                    "Latency", "DNS", "TLS", "Error"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def _check(self) -> None:
        domains = [d.strip() for d in self.domains_edit.text().split(",")
                   if d.strip()]
        if not domains:
            return
        self.tree.clear()
        full = self.full_cb.isChecked()
        threading.Thread(target=self._run_check,
                         args=(domains, full),
                         daemon=True).start()

    def _run_check(self, domains: list[str], full: bool) -> None:
        try:
            ctl = get_crawler()
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                results = loop.run_until_complete(
                    ctl.check_health(domains))
                dns_map: dict = {}
                tls_map: dict = {}
                if full:
                    dns_list = loop.run_until_complete(
                        asyncio.gather(
                            *(ctl.health.check_dns(d) for d in domains),
                            return_exceptions=True))
                    tls_list = loop.run_until_complete(
                        asyncio.gather(
                            *(ctl.health.check_tls(d) for d in domains),
                            return_exceptions=True))
                    dns_map = dict(zip(domains, dns_list))
                    tls_map = dict(zip(domains, tls_list))
            finally:
                loop.close()
            # marshal to main thread
            QTimer.singleShot(0, lambda: self._populate(
                domains, results, dns_map, tls_map))
        except Exception as e:
            QTimer.singleShot(0, lambda: QMessageBox.critical(
                self, "Health check", str(e)))

    def _populate(self, domains, results, dns_map, tls_map) -> None:
        for d in domains:
            h = results.get(d)
            if h is None:
                continue
            dns_ok = "–"
            tls_ok = "–"
            if dns_map.get(d) is not None:
                dns_ok = "✓" if getattr(dns_map[d], "ok", False) else "✗"
            if tls_map.get(d) is not None:
                tls_ok = "✓" if getattr(tls_map[d], "ok", False) else "✗"
            QTreeWidgetItem(self.tree, [
                d,
                "healthy" if h.ok else "down",
                "✓" if h.ok else "✗",
                str(h.status),
                f"{h.latency_ms:.0f}ms",
                dns_ok, tls_ok,
                (h.error or "")[:60],
            ])


# ════════════════════════════════════════════════════════════════════════════
# Tab: Optimizer
# ════════════════════════════════════════════════════════════════════════════

class OptimizerTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        apply_btn = QPushButton("Apply hint")
        apply_btn.clicked.connect(self._apply_selected)
        top.addWidget(refresh)
        top.addWidget(apply_btn)
        top.addStretch()
        lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Key", "Current", "Suggested",
                                    "Confidence", "Reason", "Applied"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def refresh(self) -> None:
        self.tree.clear()
        try:
            mgr = get_manager()
            hints = mgr.optimizer.hints()
        except Exception:
            return
        for h in hints[-200:]:
            QTreeWidgetItem(self.tree, [
                h.key,
                str(h.current_value)[:40],
                str(h.suggested_value)[:40],
                f"{h.confidence:.2f}",
                h.reason[:80],
                "✓" if h.applied else "",
            ])

    def _apply_selected(self) -> None:
        item = self.tree.currentItem()
        if not item:
            return
        try:
            mgr = get_manager()
            key = item.text(0)
            for h in reversed(mgr.optimizer.hints()):
                if h.key == key and not h.applied:
                    mgr.optimizer.apply_hint(h)
                    break
            self.refresh()
        except Exception as e:
            QMessageBox.critical(self, "Apply failed", str(e))


# ════════════════════════════════════════════════════════════════════════════
# Tab: Queue (frontier)
# ════════════════════════════════════════════════════════════════════════════

class QueueTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        clear_btn = QPushButton("Clear persisted frontier")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self._clear)
        top.addWidget(refresh)
        top.addWidget(clear_btn)
        top.addStretch()
        self.count_lbl = QLabel("0 URLs")
        top.addWidget(self.count_lbl)
        lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Priority", "Depth", "URL"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def refresh(self) -> None:
        self.tree.clear()
        try:
            mgr = get_manager()
            items = mgr.load_frontier()
        except Exception:
            return
        for url, depth, priority in items[:5000]:
            QTreeWidgetItem(self.tree, [
                f"{priority:.0f}", str(depth), url])
        self.count_lbl.setText(f"{len(items)} URLs")

    def _clear(self) -> None:
        if QMessageBox.question(self, "Confirm",
                                 "Clear persisted frontier?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            get_manager().frontier.clear()
            self.refresh()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# Tab: Cookies
# ════════════════════════════════════════════════════════════════════════════

class CookiesTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.domain_edit = QLineEdit()
        self.domain_edit.setPlaceholderText("example.com")
        load_btn = QPushButton("Load")
        load_btn.clicked.connect(self._load)
        clear_btn = QPushButton("Clear all")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self._clear_all)
        top.addWidget(QLabel("Domain:"))
        top.addWidget(self.domain_edit, 1)
        top.addWidget(load_btn)
        top.addWidget(clear_btn)
        lay.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Value", "Path", "Expires",
                                    "Secure", "HTTPOnly"])
        self.tree.setRootIsDecorated(False)
        lay.addWidget(self.tree, 1)

    def _load(self) -> None:
        self.tree.clear()
        domain = self.domain_edit.text().strip()
        if not domain:
            return
        try:
            mgr = get_manager()
            cookies = mgr.cookies.all_for_domain(domain)
        except Exception:
            return
        for c in cookies:
            QTreeWidgetItem(self.tree, [
                c.get("name", ""),
                (c.get("value") or "")[:80],
                c.get("path", "/"),
                str(c.get("expires") or "session"),
                "✓" if c.get("secure") else "",
                "✓" if c.get("httponly") else "",
            ])

    def _clear_all(self) -> None:
        if QMessageBox.question(self, "Confirm",
                                 "Clear all cookies?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            get_manager().cookies.clear()
            self.tree.clear()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# Tab: Dedup
# ════════════════════════════════════════════════════════════════════════════

class DedupTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        box = QGroupBox("Check URL")
        h = QHBoxLayout(box)
        self.url_edit = QLineEdit()
        h.addWidget(self.url_edit, 1)
        check = QPushButton("Check")
        check.clicked.connect(self._check)
        h.addWidget(check)
        clear_btn = QPushButton("Clear set")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self._clear)
        h.addWidget(clear_btn)
        lay.addWidget(box)

        self.result_lbl = QLabel("–")
        self.result_lbl.setStyleSheet("font-size: 16px; padding: 12px;")
        lay.addWidget(self.result_lbl)

        self.stats_lbl = QLabel("")
        lay.addWidget(self.stats_lbl)
        lay.addStretch()
        self.refresh_stats()

    def refresh_stats(self) -> None:
        try:
            mgr = get_manager()
            n = mgr.dedup.size()
            self.stats_lbl.setText(f"Dedup set size: {n} URLs")
        except Exception:
            self.stats_lbl.setText("Stats unavailable.")

    def _check(self) -> None:
        url = self.url_edit.text().strip()
        if not url:
            return
        try:
            seen = get_manager().is_seen(url)
            if seen:
                self.result_lbl.setText("✓ SEEN")
                self.result_lbl.setStyleSheet(
                    "font-size: 16px; padding: 12px; color: #f38ba8;")
            else:
                self.result_lbl.setText("✗ NOT SEEN")
                self.result_lbl.setStyleSheet(
                    "font-size: 16px; padding: 12px; color: #a6e3a1;")
        except Exception as e:
            self.result_lbl.setText(f"Error: {e}")

    def _clear(self) -> None:
        if QMessageBox.question(self, "Confirm",
                                 "Clear dedup set?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            get_manager().dedup.clear()
            self.refresh_stats()
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════════════
# Tab: Logs
# ════════════════════════════════════════════════════════════════════════════

class LogsTab(QWidget):
    MAX_LINES = 5000

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.level_combo = QComboBox()
        self.level_combo.addItems(["DEBUG", "INFO", "WARNING", "ERROR",
                                    "CRITICAL"])
        self.level_combo.setCurrentText("INFO")
        top.addWidget(QLabel("Level:"))
        top.addWidget(self.level_combo)
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter text…")
        top.addWidget(self.filter_edit, 1)
        self.follow_cb = QCheckBox("Follow tail")
        self.follow_cb.setChecked(True)
        top.addWidget(self.follow_cb)
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(lambda: self.viewer.clear())
        top.addWidget(clear_btn)
        lay.addLayout(top)

        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setMaximumBlockCount(self.MAX_LINES)
        self.viewer.setFont(QFont("JetBrains Mono", 10))
        self.viewer.setStyleSheet(
            "background: #0f0f17; color: #cdd6f4; border: 1px solid #313244;")
        lay.addWidget(self.viewer, 1)

    def append(self, level: str, message: str) -> None:
        order = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        try:
            min_idx = order.index(self.level_combo.currentText())
            lvl_idx = order.index(level.upper()) if level.upper() in order \
                else 1
        except Exception:
            min_idx, lvl_idx = 1, 1
        if lvl_idx < min_idx:
            return
        filt = self.filter_edit.text().strip()
        if filt and filt.lower() not in message.lower():
            return
        color = {
            "DEBUG": "#6c7086", "INFO": "#89b4fa",
            "WARNING": "#f9e2af", "ERROR": "#f38ba8",
            "CRITICAL": "#f38ba8",
        }.get(level.upper(), "#cdd6f4")
        ts = datetime.now().strftime("%H:%M:%S")
        html = (f"<span style='color:#6c7086;'>{ts}</span> "
                f"<span style='color:{color};'>[{level.upper():8}]</span> "
                f"<span>{self._escape(message)}</span>")
        self.viewer.appendHtml(html)
        if self.follow_cb.isChecked():
            self.viewer.moveCursor(QTextCursor.MoveOperation.End)

    @staticmethod
    def _escape(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;")
                 .replace(">", "&gt;"))


# ════════════════════════════════════════════════════════════════════════════
# Tab: Console (REPL)
# ════════════════════════════════════════════════════════════════════════════

class ConsoleTab(QWidget):
    """Interactive Fa-Crab console — reuses Fa-Terminal's REPL executor."""

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        info = QLabel(
            "Commands: scrape, crawl, health, robots, sitemap, stats, "
            "dedup, cache, errors, optimizer, agents, config, export, "
            "verify, browse, clear, help, quit")
        info.setStyleSheet("color: #a6adc8; padding: 4px;")
        info.setWordWrap(True)
        lay.addWidget(info)

        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setFont(QFont("JetBrains Mono", 10))
        self.viewer.setStyleSheet(
            "background: #0f0f17; color: #cdd6f4; border: 1px solid #313244;")
        lay.addWidget(self.viewer, 1)

        h = QHBoxLayout()
        self.prompt_lbl = QLabel("fa-crab >")
        self.prompt_lbl.setStyleSheet("color: #89b4fa; font-weight: bold;")
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("type a command and press Enter")
        self.input_edit.returnPressed.connect(self._submit)
        h.addWidget(self.prompt_lbl)
        h.addWidget(self.input_edit, 1)
        lay.addLayout(h)

        self._append("Welcome to Fa-Crab console. Type 'help'.")

    def _append(self, msg: str) -> None:
        self.viewer.appendPlainText(msg)
        self.viewer.moveCursor(QTextCursor.MoveOperation.End)

    def _submit(self) -> None:
        line = self.input_edit.text().strip()
        self.input_edit.clear()
        if not line:
            return
        self._append(f"fa-crab > {line}")
        if not HAS_TERMINAL or terminal_repl_execute is None:
            self._append("[terminal backend unavailable]")
            return
        try:
            keep = terminal_repl_execute(line)
            if keep is False:
                self._append("Bye.")
        except SystemExit:
            pass
        except Exception as e:
            self._append(f"[error] {e}")


# ════════════════════════════════════════════════════════════════════════════
# Tab: Sessions
# ════════════════════════════════════════════════════════════════════════════

class SessionsTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)

        h = QHBoxLayout()
        save_btn = QPushButton("Save current session")
        save_btn.clicked.connect(self._save)
        load_btn = QPushButton("Load session")
        load_btn.clicked.connect(self._load)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self._refresh)
        h.addWidget(save_btn)
        h.addWidget(load_btn)
        h.addWidget(refresh)
        h.addStretch()
        lay.addLayout(h)

        self.list_widget = QListWidget()
        lay.addWidget(self.list_widget, 1)
        self._refresh()

    def _sessions_dir(self) -> Path:
        d = STATE_DIR / "sessions"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _refresh(self) -> None:
        self.list_widget.clear()
        for f in sorted(self._sessions_dir().glob("*.json")):
            item = QListWidgetItem(f.name)
            item.setData(Qt.ItemDataRole.UserRole, str(f))
            self.list_widget.addItem(item)

    def _save(self) -> None:
        name, ok = self._ask_name()
        if not ok or not name:
            return
        try:
            mgr = get_manager()
            snap = {
                "created": datetime.now(timezone.utc).isoformat(),
                "config": mgr.config.as_dict(),
                "stats": mgr.stats_snapshot(),
            }
            path = self._sessions_dir() / f"{name}.json"
            path.write_text(json.dumps(snap, indent=2, default=str),
                             encoding="utf-8")
            self._refresh()
            QMessageBox.information(self, "Saved", str(path))
        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))

    def _load(self) -> None:
        item = self.list_widget.currentItem()
        if not item:
            return
        path = item.data(Qt.ItemDataRole.UserRole)
        try:
            data = json.loads(Path(path).read_text())
            QMessageBox.information(
                self, "Loaded",
                f"Session loaded: {len(data.get('stats', {}))} fields.")
        except Exception as e:
            QMessageBox.critical(self, "Load failed", str(e))

    def _ask_name(self) -> tuple[str, bool]:
        from PyQt6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "Session name",
                                         "Name:")
        return name.strip(), ok


# ════════════════════════════════════════════════════════════════════════════
# Tab: About
# ════════════════════════════════════════════════════════════════════════════

class AboutTab(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        title = QLabel("Fa-Crab")
        title.setStyleSheet(
            "font-size: 32px; font-weight: bold; color: #89b4fa;")
        lay.addWidget(title)
        sub = QLabel("Universal scraper / crawler for AI datasets.")
        sub.setStyleSheet("color: #a6adc8; font-size: 14px;")
        lay.addWidget(sub)
        lay.addSpacing(20)
        try:
            manager_module = _load_local_module(
                "Fa_Manager", "Fa-Manager.py")
            crawl_module = _load_local_module("Fa_Crawl", "Fa-Crawl.py")
            scraper_module = _load_local_module(
                "Fa_Scraper", "Fa-Scraper.py")
            MANAGER_VERSION = getattr(manager_module, "MANAGER_VERSION")
            CRAWL_VERSION = getattr(crawl_module, "CRAWL_VERSION")
            SCRAPER_VERSION = getattr(scraper_module, "SCRAPER_VERSION")
        except Exception:
            MANAGER_VERSION = CRAWL_VERSION = SCRAPER_VERSION = "?"
        info = QLabel(
            f"<b>Fa-Manager:</b> {MANAGER_VERSION}<br>"
            f"<b>Fa-Crawl:</b> {CRAWL_VERSION}<br>"
            f"<b>Fa-Scraper:</b> {SCRAPER_VERSION}<br>"
            f"<b>Fa-GUI:</b> {APP_VERSION}<br>"
            f"<b>Python:</b> {sys.version.split()[0]}<br>"
            f"<b>PyQt6:</b> available"
        )
        info.setStyleSheet("color: #cdd6f4; font-size: 12px;")
        lay.addWidget(info)
        lay.addStretch()


# ════════════════════════════════════════════════════════════════════════════
# Main Window
# ════════════════════════════════════════════════════════════════════════════

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} — Universal Scraper")
        self.resize(1500, 950)
        self.mgr = get_manager()
        self._worker: Optional[CrawlWorker] = None
        self._session_start = time.time()

        self._build_central()
        self._build_menus()
        self._build_toolbar()
        self._build_statusbar()
        self._wire_signals()
        self._load_geometry()

        # First-load refresh of heavy tabs
        QTimer.singleShot(200, self._initial_refresh)

    # ─── UI construction ──────────────────────────────────────────────

    def _build_menus(self) -> None:
        bar = self.menuBar()
        if bar is None:
            raise RuntimeError("Main window has no menu bar")
        f = bar.addMenu("&File")
        self._add_menu_action(f, "&New session",
                              QKeySequence.StandardKey.New,
                              self._new_session)
        self._add_menu_action(f, "&Open…",
                              QKeySequence.StandardKey.Open,
                              self.tabs_results_load)
        self._add_menu_action(f, "&Save config",
                              QKeySequence.StandardKey.Save,
                              self.tabs_config_save)
        f.addSeparator()
        self._add_menu_action(f, "E&xit",
                              QKeySequence.StandardKey.Quit, self.close)

        e = bar.addMenu("&Edit")
        self._add_menu_action(
            e, "Clear results", slot=lambda: self.tab_live._clear())
        self._add_menu_action(
            e, "Clear logs", slot=lambda: self.tab_logs.viewer.clear())

        v = bar.addMenu("&View")
        for i in range(self._tab_count):
            self._add_menu_action(
                v, f"Go to tab {i+1}", f"Ctrl+{i+1}",
                lambda _=False, idx=i: self.tabs.setCurrentIndex(idx))
        v.addSeparator()
        self._add_menu_action(v, "Toggle statusbar",
                              slot=self._toggle_statusbar)

        c = bar.addMenu("&Crawl")
        self._add_menu_action(c, "Start", "F5", self._start_crawl)
        self._add_menu_action(
            c, "Pause / Resume", "F6", self._pause_resume)
        self._add_menu_action(c, "Stop", "F7", self._stop_crawl)

        t = bar.addMenu("&Tools")
        self._add_menu_action(t, "Reload config", slot=self.tabs_config_load)
        self._add_menu_action(t, "Reload agents", slot=self.tab_agents.load)
        self._add_menu_action(t, "Refresh health", slot=self.tab_health._check)
        self._add_menu_action(t, "Refresh cache", slot=self.tab_cache.refresh)
        self._add_menu_action(
            t, "Refresh optimizer", slot=self.tab_optimizer.refresh)
        self._add_menu_action(t, "Refresh queue", slot=self.tab_queue.refresh)

        h = bar.addMenu("&Help")
        self._add_menu_action(
            h, "Documentation",
            slot=lambda: webbrowser.open("https://github.com/"))
        self._add_menu_action(
            h, "About",
            slot=lambda: self.tabs.setCurrentWidget(self.tab_about))

    def _add_menu_action(self, menu: QMenu, text: str,
                         shortcut: Optional[Any] = None,
                         slot: Optional[Callable[..., Any]] = None) -> QAction:
        action = QAction(text, self)
        if shortcut is not None:
            action.setShortcut(QKeySequence(shortcut))
        if slot is not None:
            action.triggered.connect(slot)
        menu.addAction(action)
        return action

    def _build_toolbar(self) -> None:
        tb = QToolBar("Main")
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)

        def act(label: str, slot, shortcut: Optional[str] = None):
            a = QAction(label, self)
            a.triggered.connect(slot)
            if shortcut:
                a.setShortcut(QKeySequence(shortcut))
            tb.addAction(a)
            return a

        act("▶ Start", self._start_crawl)
        act("⏸ Pause", self._pause_resume)
        act("■ Stop", self._stop_crawl)
        tb.addSeparator()
        act("↻ Reload config", self.tabs_config_load)
        act("✕ Clear results", lambda: self.tab_live._clear())
        tb.addSeparator()
        act("⤓ Export JSONL",
            lambda: (self.tabs.setCurrentWidget(self.tab_results),
                     self.tab_results._export("jsonl")))
        act("⤓ Export CSV",
            lambda: (self.tabs.setCurrentWidget(self.tab_results),
                     self.tab_results._export("csv")))

    def _build_central(self) -> None:
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(False)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.setCentralWidget(self.tabs)

        self.tab_dashboard = DashboardTab()
        self.tab_live = LiveCrawlTab()
        self.tab_results = ResultsTab()
        self.tab_config = ConfigEditorTab()
        self.tab_agents = AgentsTab()
        self.tab_cache = CacheTab()
        self.tab_health = HealthTab()
        self.tab_optimizer = OptimizerTab()
        self.tab_queue = QueueTab()
        self.tab_cookies = CookiesTab()
        self.tab_dedup = DedupTab()
        self.tab_logs = LogsTab()
        self.tab_console = ConsoleTab()
        self.tab_sessions = SessionsTab()
        self.tab_about = AboutTab()

        tabs = [
            ("Dashboard", self.tab_dashboard),
            ("Live Crawl", self.tab_live),
            ("Results", self.tab_results),
            ("Config", self.tab_config),
            ("Agents", self.tab_agents),
            ("Cache", self.tab_cache),
            ("Health", self.tab_health),
            ("Optimizer", self.tab_optimizer),
            ("Queue", self.tab_queue),
            ("Cookies", self.tab_cookies),
            ("Dedup", self.tab_dedup),
            ("Logs", self.tab_logs),
            ("Console", self.tab_console),
            ("Sessions", self.tab_sessions),
            ("About", self.tab_about),
        ]
        self._tab_count = len(tabs)
        for name, w in tabs:
            self.tabs.addTab(w, name)

    def _build_statusbar(self) -> None:
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_url = QLabel("Ready.")
        self.status_pages = QLabel("Pages: 0")
        self.status_errors = QLabel("Errors: 0")
        self.status_rate = QLabel("Rate: 0.0/s")
        self.status_clock = QLabel(datetime.now().strftime("%H:%M:%S"))
        for w in (self.status_url, self.status_pages, self.status_errors,
                  self.status_rate, self.status_clock):
            sb.addPermanentWidget(w)
        sb.addWidget(self.status_url, 1)
        self._clock_timer = QTimer(self)
        self._clock_timer.timeout.connect(
            lambda: self.status_clock.setText(
                datetime.now().strftime("%H:%M:%S")))
        self._clock_timer.start(1000)

    def _wire_signals(self) -> None:
        self.tab_dashboard.start_requested.connect(self._start_crawl_from)
        self.tab_dashboard.stop_requested.connect(self._stop_crawl)
        self.tab_dashboard.pause_requested.connect(self._pause_resume)
        BUS.page_scraped.connect(self._on_page_scraped)
        BUS.log_line.connect(self._on_log)
        BUS.stats_updated.connect(self._on_stats)
        BUS.error_raised.connect(self._on_error)

    # ─── signal handlers ──────────────────────────────────────────────

    def _on_page_scraped(self, record: dict) -> None:
        self.tab_live.append_record(record)
        self.tab_results.append_record(record)

    def _on_log(self, level: str, message: str) -> None:
        self.tab_logs.append(level, message)

    def _on_stats(self, snapshot: dict) -> None:
        self.tab_dashboard.update_stats(snapshot)
        self.status_pages.setText(f"Pages: {snapshot.get('fetched', 0)}")
        self.status_errors.setText(f"Errors: {snapshot.get('errors', 0)}")
        elapsed = max(0.001, time.time() - self._session_start)
        rate = snapshot.get("fetched", 0) / elapsed
        self.status_rate.setText(f"Rate: {rate:.1f}/s")

    def _on_error(self, cat: str, msg: str) -> None:
        self.tab_logs.append("ERROR", f"[{cat}] {msg}")

    # ─── crawl control ─────────────────────────────────────────────────

    def _start_crawl(self) -> None:
        if self._worker and self._worker.isRunning():
            QMessageBox.information(self, "Crawl running",
                                     "A crawl is already in progress.")
            return
        self.tabs.setCurrentWidget(self.tab_live)
        self.tab_dashboard._on_start()

    def _start_crawl_from(self, payload: dict) -> None:
        urls = payload["urls"]
        config: Any = payload["config"]
        crawler_type = payload["crawler_type"]

        self._session_start = time.time()
        self.tab_live._clear()

        self._worker = CrawlWorker(self.mgr, urls, config, crawler_type)
        self._worker.stats_tick.connect(self._on_stats)
        self._worker.log_line.connect(
            lambda lvl, msg: self._on_log(lvl, msg))
        self._worker.error.connect(self._on_error)
        self._worker.state.connect(self._on_crawl_state)
        self._worker.finished.connect(self._on_crawl_finished)
        self._worker.page_done.connect(self._on_page_scraped)
        self._worker.start()

        self.tab_dashboard.set_running(True)
        self.status_url.setText(f"Crawling {len(urls)} seed(s)…")

    def _stop_crawl(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
            self.status_url.setText("Stopping…")

    def _pause_resume(self) -> None:
        if not self._worker:
            return
        if self._worker.isRunning():
            if self.tab_dashboard.pause_btn.text().startswith("⏸"):
                self._worker.request_pause()
                self.tab_dashboard.pause_btn.setText("▶  Resume")
                self.status_url.setText("Paused.")
            else:
                self._worker.request_resume()
                self.tab_dashboard.pause_btn.setText("⏸  Pause")
                self.status_url.setText("Running…")

    def _on_crawl_state(self, state: str) -> None:
        if state in ("done", "failed"):
            self.tab_dashboard.set_running(False)
            self.tab_dashboard.pause_btn.setText("⏸  Pause")

    def _on_crawl_finished(self, stats: dict) -> None:
        self.status_url.setText("Finished.")
        msg = (f"Crawl finished.\n\n"
               f"Fetched: {stats.get('fetched', 0)}\n"
               f"Written: {stats.get('written', 0)}\n"
               f"Errors: {stats.get('errors', 0)}\n"
               f"Duration: {stats.get('duration_seconds', 0):.1f}s")
        QMessageBox.information(self, "Crawl finished", msg)

    # ─── config helpers ────────────────────────────────────────────────

    def tabs_config_load(self) -> None:
        self.tab_config.load()

    def tabs_config_save(self) -> None:
        self.tab_config.save()

    def tabs_results_load(self) -> None:
        self.tabs.setCurrentWidget(self.tab_results)
        self.tab_results._load_from_disk()

    def _new_session(self) -> None:
        self.tab_live._clear()
        self.tab_dashboard.urls_edit.clear()
        self.tab_dashboard.urls_edit.setPlainText("https://example.com")
        self.status_url.setText("New session ready.")

    def _initial_refresh(self) -> None:
        self.tab_config.load()
        self.tab_agents.load()
        self.tab_cache.refresh()
        self.tab_optimizer.refresh()
        self.tab_queue.refresh()
        self.tab_dedup.refresh_stats()

    def _toggle_statusbar(self) -> None:
        sb = self.statusBar()
        if sb is not None:
            sb.setVisible(not sb.isVisible())

    # ─── geometry persistence ─────────────────────────────────────────

    def _load_geometry(self) -> None:
        try:
            if GUI_STATE_PATH.exists():
                data = json.loads(GUI_STATE_PATH.read_text())
                g = data.get("geometry")
                if g:
                    self.setGeometry(*g)
        except Exception:
            pass

    def _save_geometry(self) -> None:
        try:
            STATE_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "geometry": list(self.geometry().getRect()),
                "saved": datetime.now(timezone.utc).isoformat(),
            }
            GUI_STATE_PATH.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def closeEvent(self, event) -> None:
        if self._worker and self._worker.isRunning():
            reply = QMessageBox.question(
                self, "Crawl running",
                "A crawl is running. Stop and quit?")
            if reply != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._worker.request_stop()
            self._worker.wait(5000)
        self._save_geometry()
        with contextlib.suppress(Exception):
            self.mgr.shutdown()
        event.accept()


# ════════════════════════════════════════════════════════════════════════════
# Entry point
# ════════════════════════════════════════════════════════════════════════════

def run_gui() -> int:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_STYLESHEET)

    font = QFont("JetBrains Mono", 10)
    available_fonts = QFontDatabase.families()
    if "JetBrains Mono" not in available_fonts:
        for fallback in ("Cascadia Mono", "Consolas", "Menlo", "Monospace"):
            if fallback in available_fonts:
                font = QFont(fallback, 10)
                break
    app.setFont(font)

    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(run_gui())