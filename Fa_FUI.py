#!/usr/bin/env python3
"""
Fa-FUI.py — PyQt6 dashboard for Fa-Scrap.

Fixed:
    - pglive's LivePlotWidget uses addItem(), not add_plot().
    - Added _attach_plot() defensive helper: tries addItem, add_plot, and
      plotItem.addItem in that order.
    - Added HAVE_PGLIVE fallback so the dashboard still runs on a plain
      pyqtgraph if pglive ever breaks on this Python version.
    - Hardened thread shutdown and event-loop cleanup.

Zero browser engine. Import only when called by Fa-Scrap.py. CLI is --help only.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from collections import deque
from typing import Optional

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QGroupBox, QFileDialog,
    QStatusBar,
)

# ── Plot stack: prefer pglive, degrade gracefully to pyqtgraph ───────────────
try:
    from pglive.sources.data_connector import DataConnector
    from pglive.sources.live_plot import LiveLinePlot
    from pglive.sources.live_plot_widget import LivePlotWidget
    HAVE_PGLIVE = True
except Exception as _pglive_err:
    HAVE_PGLIVE = False
    _PGLIVE_ERR = _pglive_err
    import pyqtgraph as pg
    DataConnector = None       # type: ignore
    LiveLinePlot = None        # type: ignore
    LivePlotWidget = None      # type: ignore


def _attach_plot(widget, plot) -> bool:
    """
    Attach a plot to a pyqtgraph/pglive widget across API variants.

    Tries in order:
        1. widget.addItem(plot)        # pglive + pyqtgraph canonical
        2. widget.add_plot(plot)       # older/other pglive forks
        3. widget.plotItem.addItem(plot)
        4. widget.getPlotItem().addItem(plot)
    Returns True on success, False if every path failed.
    """
    for name in ("addItem", "add_plot"):
        method = getattr(widget, name, None)
        if callable(method):
            try:
                method(plot)
                return True
            except Exception:
                continue
    # Reach into the PlotItem directly
    plot_item = getattr(widget, "plotItem", None)
    if plot_item is None:
        getter = getattr(widget, "getPlotItem", None)
        if callable(getter):
            try:
                plot_item = getter()
            except Exception:
                plot_item = None
    if plot_item is not None:
        try:
            plot_item.addItem(plot)
            return True
        except Exception:
            pass
    return False


# ══════════════════════════════════════════════════════════════════════════════
# SCRAPER THREAD
# ══════════════════════════════════════════════════════════════════════════════
class ScraperThread(QThread):
    metrics_updated = pyqtSignal(dict)
    finished_run = pyqtSignal(dict)
    log_line = pyqtSignal(str)

    def __init__(self, engine, seeds: list[str]):
        super().__init__()
        self.engine = engine
        self.seeds = list(seeds or [])
        self._stop = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def stop(self):
        self._stop = True
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(self.engine._shutdown.set)
            except Exception:
                pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            self.engine._loop_ref = loop
        except Exception:
            pass
        try:
            loop.run_until_complete(self._loop_coro())
        except Exception as e:
            try:
                self.log_line.emit(f"engine error: {e}")
            except Exception:
                pass
        finally:
            try:
                pending = asyncio.all_tasks(loop)
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                pass
            try:
                loop.close()
            except Exception:
                pass
            self._loop = None

    async def _loop_coro(self):
        monitor = asyncio.create_task(self._monitor())
        try:
            await self.engine.run(self.seeds)
        finally:
            monitor.cancel()
            try:
                await monitor
            except asyncio.CancelledError:
                pass
            except Exception:
                pass
        try:
            self.finished_run.emit(self.engine.metrics())
        except Exception:
            pass

    async def _monitor(self):
        while not self._stop:
            await asyncio.sleep(0.25)
            try:
                self.metrics_updated.emit(self.engine.metrics())
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
class Dashboard(QMainWindow):
    def __init__(self, engine, initial_url: str = "", autostart: bool = False):
        super().__init__()
        self.engine = engine
        self.thread: Optional[ScraperThread] = None
        self.setWindowTitle("Fa-Scrap")
        self.resize(1200, 760)

        # Plain-pyqtgraph fallback state
        self._fb_x: deque[float] = deque(maxlen=600)
        self._fb_y: deque[float] = deque(maxlen=600)
        self._fb_plot = None
        self._fb_curve = None

        self._build_ui()

        if initial_url:
            self.url_input.setText(initial_url)
            if autostart:
                self._start()

    # ── UI construction ──────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # ── URL row ─────────────────────────────────────────────────────────
        url_row = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste a URL and press Enter…")
        self.url_input.returnPressed.connect(self._start)
        self.btn_go = QPushButton("GO")
        self.btn_go.clicked.connect(self._start)
        self.btn_resume = QPushButton("Resume")
        self.btn_resume.clicked.connect(self._resume_pick)
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.clicked.connect(self._stop)
        self.btn_stop.setEnabled(False)
        url_row.addWidget(QLabel("URL:"))
        url_row.addWidget(self.url_input, stretch=1)
        url_row.addWidget(self.btn_go)
        url_row.addWidget(self.btn_resume)
        url_row.addWidget(self.btn_stop)
        root.addLayout(url_row)

        # ── Body: graph + metrics ───────────────────────────────────────────
        body = QHBoxLayout()
        body.addWidget(self._build_graph(), stretch=2)
        body.addWidget(self._build_metrics(), stretch=1)
        root.addLayout(body, stretch=1)

        # ── Status bar ──────────────────────────────────────────────────────
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        if HAVE_PGLIVE:
            self.status.showMessage("Idle — paste a URL.")
        else:
            self.status.showMessage(
                f"Idle — pglive unavailable ({_PGLIVE_ERR!s:.60}); "
                f"using fallback plotter.")

    def _build_graph(self) -> QWidget:
        """Build the graph widget. pglive preferred, pyqtgraph fallback."""
        if HAVE_PGLIVE:
            try:
                self.graph = LivePlotWidget(title="Pages / second")
                try:
                    self.graph.setBackground("w")
                except Exception:
                    pass
                self.plot = LiveLinePlot()
                attached = _attach_plot(self.graph, self.plot)
                if not attached:
                    raise RuntimeError("could not attach plot to LivePlotWidget")
                try:
                    self.connector = DataConnector(
                        self.plot, max_points=600, update_rate=100)
                except TypeError:
                    # Older pglive signature
                    self.connector = DataConnector(self.plot)
                return self.graph
            except Exception as e:
                # Fall through to plain pyqtgraph
                self.status and None  # status not built yet; ignore
                print(f"[Fa-FUI] pglive setup failed ({e}); using pyqtgraph.",
                      file=sys.stderr)

        # Fallback: plain pyqtgraph
        self.graph = pg.PlotWidget(title="Pages / second")
        try:
            self.graph.setBackground("w")
        except Exception:
            pass
        try:
            self.graph.showGrid(x=True, y=True, alpha=0.3)
        except Exception:
            pass
        self._fb_plot = self.graph.plot([], [], pen=pg.mkPen("#1f77b4", width=2))
        self.connector = None
        self.plot = self._fb_plot
        return self.graph

    def _build_metrics(self) -> QGroupBox:
        box = QGroupBox("Metrics")
        grid = QGridLayout(box)

        self.lbl_success = QLabel("0")
        self.lbl_fail = QLabel("0")
        self.lbl_skip = QLabel("0")
        self.lbl_pps = QLabel("0.00")
        self.lbl_peak = QLabel("0.00")
        self.lbl_size = QLabel("0.00 MB")
        self.lbl_known = QLabel("0")
        self.lbl_conc = QLabel("0")
        self.lbl_queue = QLabel("0")
        self.lbl_uptime = QLabel("0s")

        rows = [
            ("Success", self.lbl_success),
            ("Failures", self.lbl_fail),
            ("Skipped", self.lbl_skip),
            ("Pages/s", self.lbl_pps),
            ("Peak pps", self.lbl_peak),
            ("Data", self.lbl_size),
            ("Known URLs", self.lbl_known),
            ("Concurrency", self.lbl_conc),
            ("Queued", self.lbl_queue),
            ("Uptime", self.lbl_uptime),
        ]
        font = QFont("Menlo", 11)
        for i, (name, w) in enumerate(rows):
            k = QLabel(f"<b>{name}:</b>")
            grid.addWidget(k, i, 0)
            grid.addWidget(w, i, 1)
            w.setFont(font)

        self.fail_bar = QProgressBar()
        self.fail_bar.setRange(0, 100)
        self.fail_bar.setValue(0)
        self.fail_bar.setFormat("Failure Rate: %p%")
        grid.addWidget(self.fail_bar, len(rows), 0, 1, 2)
        return box

    # ── Actions ──────────────────────────────────────────────────────────────
    def _start(self):
        if self.thread is not None and self.thread.isRunning():
            return
        url = self.url_input.text().strip()
        if not url:
            self.status.showMessage("Enter a URL first.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_input.setText(url)

        # Reset fallback buffers between runs
        self._fb_x.clear()
        self._fb_y.clear()

        self.thread = ScraperThread(self.engine, [url])
        self.thread.metrics_updated.connect(self._on_metrics)
        self.thread.finished_run.connect(self._on_finished)
        self.thread.log_line.connect(self._on_log)
        self.thread.start()

        self.btn_go.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.status.showMessage(f"Running: {url}")

    def _stop(self):
        if self.thread is not None:
            self.thread.stop()
            self.status.showMessage("Stopping…")

    def _resume_pick(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Choose a resume.zip", "", "ZIP files (*.zip)")
        if not path:
            return
        loop = asyncio.new_event_loop()
        try:
            added = loop.run_until_complete(
                self.engine.resume.load_external(path))
        except Exception as e:
            self.status.showMessage(f"Resume load failed: {e}")
            return
        finally:
            try:
                loop.close()
            except Exception:
                pass
        self.status.showMessage(f"Resume loaded: {added} new known URLs.")

    # ── Slots ────────────────────────────────────────────────────────────────
    def _on_metrics(self, m: dict):
        self.lbl_success.setText(str(m.get("success", 0)))
        self.lbl_fail.setText(str(m.get("failures", 0)))
        self.lbl_skip.setText(str(m.get("skipped", 0)))
        self.lbl_pps.setText(f"{m.get('pages_per_sec', 0):.2f}")
        self.lbl_peak.setText(f"{m.get('peak_pps', 0):.2f}")
        self.lbl_size.setText(f"{m.get('data_size_mb', 0):.2f} MB")
        self.lbl_known.setText(str(m.get("known_urls", 0)))
        self.lbl_conc.setText(str(m.get("concurrency", 0)))
        self.lbl_queue.setText(str(m.get("queued", 0)))
        self.lbl_uptime.setText(f"{m.get('uptime', 0):.0f}s")

        total = m.get("success", 0) + m.get("failures", 0)
        if total > 0:
            self.fail_bar.setValue(int(100 * m.get("failures", 0) / total))

        pps = float(m.get("pages_per_sec", 0.0))
        now = time.time()

        if self.connector is not None:
            try:
                self.connector.cb_append_data_point(pps, now)
            except Exception:
                pass
        elif self._fb_plot is not None:
            self._fb_x.append(now)
            self._fb_y.append(pps)
            try:
                self._fb_plot.setData(list(self._fb_x), list(self._fb_y))
            except Exception:
                pass

    def _on_finished(self, m: dict):
        self.status.showMessage(
            f"DONE — {m.get('success', 0)} pages, "
            f"{m.get('failures', 0)} failures, {m.get('data_size_mb', 0):.2f} MB"
        )
        self.btn_go.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.thread = None

    def _on_log(self, msg: str):
        self.status.showMessage(msg)

    def closeEvent(self, event):
        if self.thread is not None:
            try:
                self.thread.stop()
                self.thread.wait(3000)
            except Exception:
                pass
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
# LAUNCH
# ══════════════════════════════════════════════════════════════════════════════
def launch(engine, initial_url: str = "", autostart: bool = False) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    dash = Dashboard(engine, initial_url=initial_url, autostart=autostart)
    dash.show()
    return app.exec()


# ══════════════════════════════════════════════════════════════════════════════
# CLI (--help only)
# ══════════════════════════════════════════════════════════════════════════════
def main():
    p = argparse.ArgumentParser(
        prog="Fa-FUI.py",
        description=(
            "Fa-Scrap PyQt6 dashboard. Launched by Fa-Scrap.py. CLI is --help only."
        ),
    )
    p.print_help()


if __name__ == "__main__":
    main()