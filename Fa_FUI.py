#!/usr/bin/env python3
"""
Fa-FUI.py — PyQt6 dashboard. URL box, resume button, live graph, metrics.
Zero browser engine. Runs the asyncio engine in a QThread.
Import only when called by Fa-Scrap.py. CLI is --help only.
"""

import argparse
import asyncio
import sys
import time

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QGroupBox, QFileDialog,
    QStatusBar,
)
from pglive.sources.data_connector import DataConnector
from pglive.sources.live_plot import LiveLinePlot
from pglive.sources.live_plot_widget import LivePlotWidget


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
        self.seeds = seeds
        self._stop = False

    def stop(self):
        self._stop = True
        try:
            loop = self.engine._loop_ref  # type: ignore[attr-defined]
            if loop and loop.is_running():
                loop.call_soon_threadsafe(self.engine._shutdown.set)
        except Exception:
            pass

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self.engine._loop_ref = loop  # type: ignore[attr-defined]
        try:
            loop.run_until_complete(self._loop_coro())
        except Exception as e:
            self.log_line.emit(f"engine error: {e}")
        finally:
            try:
                loop.run_until_complete(asyncio.sleep(0))
            except Exception:
                pass
            loop.close()

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
        self.finished_run.emit(self.engine.metrics())

    async def _monitor(self):
        while not self._stop:
            await asyncio.sleep(0.25)
            self.metrics_updated.emit(self.engine.metrics())


# ══════════════════════════════════════════════════════════════════════════════
# DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
class Dashboard(QMainWindow):
    def __init__(self, engine, initial_url: str = "", autostart: bool = False):
        super().__init__()
        self.engine = engine
        self.thread: ScraperThread | None = None
        self.setWindowTitle("Fa-Scrap")
        self.resize(1200, 760)
        self._build_ui()
        if initial_url:
            self.url_input.setText(initial_url)
            if autostart:
                self._start()

    # ── UI ───────────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # URL row
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

        # Body: graph + metrics
        body = QHBoxLayout()
        self.graph = LivePlotWidget(title="Pages / second")
        self.graph.setBackground("w")
        self.plot = LiveLinePlot()
        self.graph.add_plot(self.plot)
        self.connector = DataConnector(self.plot, max_points=600, update_rate=100)
        body.addWidget(self.graph, stretch=2)
        body.addWidget(self._build_metrics(), stretch=1)
        root.addLayout(body, stretch=1)

        # Status
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Idle — paste a URL.")

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
        self.fail_bar.setFormat("Failure Rate: %p%")
        grid.addWidget(self.fail_bar, len(rows), 0, 1, 2)
        return box

    # ── Actions ──────────────────────────────────────────────────────────────
    def _start(self):
        if self.thread is not None:
            return
        url = self.url_input.text().strip()
        if not url:
            self.status.showMessage("Enter a URL first.")
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
            self.url_input.setText(url)
        self.thread = ScraperThread(self.engine, [url])
        self.thread.metrics_updated.connect(self._on_metrics)
        self.thread.finished_run.connect(self._on_finished)
        self.thread.log_line.connect(lambda m: self.status.showMessage(m))
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
            added = loop.run_until_complete(self.engine.resume.load_external(path))
        finally:
            loop.close()
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
        self.connector.cb_append_data_point(float(m.get("pages_per_sec", 0.0)), time.time())

    def _on_finished(self, m: dict):
        self.status.showMessage(
            f"DONE — {m.get('success', 0)} pages, "
            f"{m.get('failures', 0)} failures, {m.get('data_size_mb', 0):.2f} MB"
        )
        self.btn_go.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.thread = None

    def closeEvent(self, event):
        if self.thread is not None:
            self.thread.stop()
            self.thread.wait(3000)
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY (called by Fa-Scrap.py)
# ══════════════════════════════════════════════════════════════════════════════
def launch(engine, initial_url: str = "", autostart: bool = False) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    dash = Dashboard(engine, initial_url=initial_url, autostart=autostart)
    dash.show()
    return app.exec()


def main():
    p = argparse.ArgumentParser(
        prog="Fa-FUI.py",
        description="Fa-Scrap PyQt6 dashboard. Launched by Fa-Scrap.py. CLI is --help only.",
    )
    p.print_help()


if __name__ == "__main__":
    main()