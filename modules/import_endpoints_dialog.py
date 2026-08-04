"""
ImportEndpointsDialog — send a list of endpoints through the tool, record
them exactly like proxy traffic, and add them to HTTP History + Sitemap.
"""

import os
import json
import time
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode

import requests as _requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QFileDialog, QSpinBox, QComboBox, QGroupBox,
    QProgressBar, QCheckBox, QWidget, QTabWidget,
    QMessageBox, QAbstractItemView,
)

try:
    from modules.constants import (
        COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT,
        COLOR_TEXT_MUTED, COLOR_BORDER, COLOR_ELEVATED_BG, COLOR_ACCENT,
        COLOR_SUCCESS, COLOR_CRITICAL, COLOR_CARD_BG, COLOR_BORDER_BRIGHT,
        FONT_FAMILY, FONT_FAMILY_MONO, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
        COLOR_HOVER,
    )
except ImportError:
    COLOR_BACKGROUND = "#1e1e1e"
    COLOR_DARK_BG    = "#1a1a1a"
    COLOR_TEXT       = "#d4d4d4"
    COLOR_TEXT_BRIGHT= "#ffffff"
    COLOR_TEXT_MUTED = "#808080"
    COLOR_BORDER     = "#3a3a3a"
    COLOR_ELEVATED_BG= "#252526"
    COLOR_ACCENT     = "#0078d4"
    COLOR_SUCCESS    = "#4ec9b0"
    COLOR_CRITICAL   = "#f48771"
    COLOR_CARD_BG    = "#252526"
    COLOR_BORDER_BRIGHT = "#555"
    FONT_FAMILY      = "Segoe UI, Arial, sans-serif"
    FONT_FAMILY_MONO = "Consolas, monospace"
    FONT_SIZE_NORMAL = "12px"
    FONT_SIZE_SMALL  = "11px"
    COLOR_HOVER      = "#2a2d2e"


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread
# ─────────────────────────────────────────────────────────────────────────────

class _ImportWorker(QThread):
    """Sends HTTP requests to a list of endpoints and emits findings."""

    progress   = pyqtSignal(int, int, str)   # current, total, message
    new_finding = pyqtSignal(dict)            # one finding dict per request
    finished   = pyqtSignal(int, int)         # done_count, error_count
    cancelled  = pyqtSignal()

    def __init__(self, endpoints, method, headers, concurrency,
                 follow_redirects, timeout, project_paths, parent=None):
        super().__init__(parent)
        self.endpoints       = endpoints
        self.method          = method
        self.headers         = headers          # dict
        self.concurrency     = concurrency
        self.follow_redirects = follow_redirects
        self.timeout         = timeout
        self.project_paths   = project_paths    # may be None
        self._cancel_flag    = False
        self._counter_lock   = threading.Lock()
        self._counter        = 0

    def cancel(self):
        self._cancel_flag = True

    # ── helpers ──────────────────────────────────────────────────────────

    def _next_req_id(self):
        with self._counter_lock:
            self._counter += 1
            return f"import_{int(time.time())}_{self._counter}"

    def _requests_dir(self):
        if self.project_paths:
            return self.project_paths.get("requests_dir", "/tmp/hunt_requests")
        return "/tmp/hunt_requests"

    def _responses_dir(self):
        if self.project_paths:
            return self.project_paths.get("responses_dir", "/tmp/hunt_responses")
        return "/tmp/hunt_responses"

    def _jsonl_path(self):
        if self.project_paths:
            return self.project_paths.get("jsonl", "/tmp/hunt.jsonl")
        return "/tmp/hunt.jsonl"

    @staticmethod
    def _make_session(follow_redirects: bool, timeout: int):
        s = _requests.Session()
        retry = Retry(total=0)          # no retries — we want raw results
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.max_redirects = 10 if follow_redirects else 0
        return s

    @staticmethod
    def _build_raw_request(method: str, parsed, extra_headers: dict,
                           session_headers: dict) -> str:
        """Build a raw HTTP/1.1 request string similar to what the proxy saves."""
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{method} {path} HTTP/1.1"]
        host = parsed.hostname
        if parsed.port and parsed.port not in (80, 443):
            host += f":{parsed.port}"
        lines.append(f"Host: {host}")
        # extra headers first, then session defaults (lower priority)
        merged = {**session_headers, **extra_headers}
        for k, v in merged.items():
            if k.lower() != "host":
                lines.append(f"{k}: {v}")
        lines.append("")
        lines.append("")
        return "\r\n".join(lines)

    @staticmethod
    def _build_raw_response(resp: "_requests.Response") -> str:
        """Build a raw HTTP/1.1 response string."""
        try:
            reason = resp.reason or ""
        except Exception:
            reason = ""
        lines = [f"HTTP/1.1 {resp.status_code} {reason}"]
        for k, v in resp.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        header_part = "\r\n".join(lines)
        try:
            body = resp.content.decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return header_part + "\r\n" + body

    # ── per-request logic ─────────────────────────────────────────────────

    def _send_one(self, url: str) -> dict:
        """Send a single request; return a finding dict (or raise)."""
        req_id = self._next_req_id()
        parsed = urlparse(url)
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)

        session = self._make_session(self.follow_redirects, self.timeout)

        default_headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
        }
        merged_headers = {**default_headers, **self.headers}

        raw_req = self._build_raw_request(
            self.method, parsed, self.headers, default_headers
        )

        resp = session.request(
            self.method,
            url,
            headers=merged_headers,
            allow_redirects=self.follow_redirects,
            timeout=self.timeout,
            verify=False,
            stream=False,
        )

        raw_resp = self._build_raw_response(resp)

        # persist request file
        req_dir = self._requests_dir()
        os.makedirs(req_dir, exist_ok=True)
        req_file = os.path.join(req_dir, f"{req_id}.txt")
        with open(req_file, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(raw_req)

        # persist response file
        resp_dir = self._responses_dir()
        os.makedirs(resp_dir, exist_ok=True)
        resp_file = os.path.join(resp_dir, f"{req_id}.txt")
        with open(resp_file, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(raw_resp)

        content_type = resp.headers.get("Content-Type", "")
        finding = {
            "url":             url,
            "method":          self.method,
            "host":            parsed.hostname or "",
            "path":            parsed.path or "/",
            "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%S"),
            "seq":             self._counter,
            "request_file":    req_file,
            "response_file":   resp_file,
            "status":          resp.status_code,
            "content_type":    content_type,
            "response_length": len(resp.content or b""),
            "source":          "import",
        }

        # append to project JSONL
        try:
            with open(self._jsonl_path(), "a", encoding="utf-8") as fj:
                json.dump(finding, fj)
                fj.write("\n")
        except Exception:
            pass

        return finding

    # ── run ──────────────────────────────────────────────────────────────

    def run(self):
        total      = len(self.endpoints)
        done       = 0
        errors     = 0

        with ThreadPoolExecutor(max_workers=self.concurrency) as pool:
            futures = {
                pool.submit(self._send_one, url): url
                for url in self.endpoints
            }
            for future in as_completed(futures):
                if self._cancel_flag:
                    pool.shutdown(wait=False, cancel_futures=True)
                    self.cancelled.emit()
                    return
                done += 1
                url = futures[future]
                try:
                    finding = future.result()
                    self.new_finding.emit(finding)
                    self.progress.emit(
                        done, total,
                        f"[{done}/{total}] {resp_short(finding.get('status', 0))} {url}"
                    )
                except Exception as exc:
                    errors += 1
                    self.progress.emit(
                        done, total,
                        f"[{done}/{total}] ERROR: {url} → {exc}"
                    )

        self.finished.emit(done - errors, errors)


def resp_short(status: int) -> str:
    if status == 0:
        return "ERR"
    if 200 <= status < 300:
        return f"✓{status}"
    if 300 <= status < 400:
        return f"→{status}"
    return f"✗{status}"


# ─────────────────────────────────────────────────────────────────────────────
# Dialog
# ─────────────────────────────────────────────────────────────────────────────

class ImportEndpointsDialog(QDialog):
    """
    Dialog for importing and sending a list of endpoints.
    Findings are written to the project JSONL so FileMonitorThread picks them
    up automatically — no extra signal connection needed.
    """

    _DIALOG_SS = f"""
        QDialog       {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
        QGroupBox     {{ border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                         margin-top: 10px; padding-top: 12px;
                         background-color: {COLOR_CARD_BG}; color: {COLOR_ACCENT};
                         font-weight: 600; }}
        QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px;
                            background-color: {COLOR_CARD_BG}; }}
        QTextEdit     {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                         border: 1px solid {COLOR_BORDER}; font-family: {FONT_FAMILY_MONO};
                         font-size: {FONT_SIZE_SMALL}; }}
        QLineEdit     {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                         border: 1px solid {COLOR_BORDER}; border-radius: 3px;
                         padding: 3px 6px; }}
        QLineEdit:focus  {{ border-color: {COLOR_ACCENT}; }}
        QPushButton   {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT};
                         border: 1px solid {COLOR_BORDER}; border-radius: 3px;
                         padding: 5px 12px; font-weight: 500; }}
        QPushButton:hover {{ background-color: {COLOR_HOVER}; border-color: {COLOR_BORDER_BRIGHT}; }}
        QPushButton:disabled {{ color: {COLOR_TEXT_MUTED}; border-color: {COLOR_BORDER}; }}
        QTableWidget  {{ background-color: {COLOR_DARK_BG}; gridline-color: {COLOR_BORDER};
                         border: 1px solid {COLOR_BORDER}; color: {COLOR_TEXT}; }}
        QHeaderView::section {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT};
                                 border: 1px solid {COLOR_BORDER}; padding: 4px 6px;
                                 font-weight: 600; }}
        QComboBox     {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                         border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 3px 6px; }}
        QSpinBox      {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                         border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 3px 6px; }}
        QCheckBox     {{ color: {COLOR_TEXT}; spacing: 4px; }}
        QLabel        {{ background: transparent; color: {COLOR_TEXT}; }}
        QProgressBar  {{ border: 1px solid {COLOR_BORDER}; border-radius: 3px;
                         background-color: {COLOR_DARK_BG}; text-align: center;
                         color: {COLOR_TEXT_BRIGHT}; }}
        QProgressBar::chunk {{ background-color: {COLOR_ACCENT}; border-radius: 2px; }}
        QTabWidget::pane  {{ border: 1px solid {COLOR_BORDER}; background: {COLOR_BACKGROUND}; }}
        QTabBar::tab  {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_MUTED};
                         padding: 6px 16px; border: 1px solid {COLOR_BORDER};
                         border-bottom: none; border-top-left-radius: 4px;
                         border-top-right-radius: 4px; }}
        QTabBar::tab:selected {{ background: {COLOR_BACKGROUND}; color: {COLOR_TEXT_BRIGHT};
                                  font-weight: 600; }}
    """

    def __init__(self, project_paths=None, parent=None):
        super().__init__(parent)
        self.project_paths = project_paths
        self._worker: _ImportWorker | None = None

        self.setWindowTitle("Import Endpoints")
        self.setMinimumSize(900, 680)
        self.setStyleSheet(self._DIALOG_SS)

        self._build_ui()

    # ── UI ────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(10, 10, 10, 10)

        tabs = QTabWidget()
        root.addWidget(tabs, 1)

        # ── Tab 1: Endpoints ──────────────────────────────────────────────
        ep_tab = QWidget()
        ep_lay = QVBoxLayout(ep_tab)
        ep_lay.setSpacing(6)

        ep_lbl = QLabel("Endpoints (one URL per line — http/https prefix optional):")
        ep_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        ep_lay.addWidget(ep_lbl)

        self.endpoints_edit = QTextEdit()
        self.endpoints_edit.setPlaceholderText(
            "https://example.com/api/v1/users\n"
            "https://example.com/api/v1/products\n"
            "http://internal-host/admin\n"
        )
        self.endpoints_edit.setFont(self._mono_font())
        ep_lay.addWidget(self.endpoints_edit, 1)

        browse_row = QHBoxLayout()
        browse_btn = QPushButton("  Browse file…")
        browse_btn.clicked.connect(self._browse_file)
        self._ep_count_lbl = QLabel("0 endpoints")
        self._ep_count_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        browse_row.addWidget(browse_btn)
        browse_row.addWidget(self._ep_count_lbl)
        browse_row.addStretch()
        ep_lay.addLayout(browse_row)

        self.endpoints_edit.textChanged.connect(self._update_ep_count)
        tabs.addTab(ep_tab, "Endpoints")

        # ── Tab 2: HTTP Headers ───────────────────────────────────────────
        hdr_tab = QWidget()
        hdr_lay = QVBoxLayout(hdr_tab)
        hdr_lay.setSpacing(6)

        hdr_info = QLabel(
            "Headers added here will be sent with every request "
            "(e.g. Cookie, Authorization, X-Custom)."
        )
        hdr_info.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        hdr_info.setWordWrap(True)
        hdr_lay.addWidget(hdr_info)

        self.headers_table = QTableWidget(0, 2)
        self.headers_table.setHorizontalHeaderLabels(["Header Name", "Value"])
        self.headers_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeToContents
        )
        self.headers_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.Stretch
        )
        self.headers_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.headers_table.setAlternatingRowColors(True)
        self.headers_table.setStyleSheet(
            f"QTableWidget::item {{ padding: 3px 6px; }}"
            f"QTableWidget::item:alternate {{ background-color: {COLOR_ELEVATED_BG}; }}"
        )
        hdr_lay.addWidget(self.headers_table, 1)

        hdr_btn_row = QHBoxLayout()
        add_hdr_btn = QPushButton("＋  Add Header")
        add_hdr_btn.clicked.connect(self._add_header_row)
        del_hdr_btn = QPushButton("✕  Remove Selected")
        del_hdr_btn.clicked.connect(self._remove_header_row)

        # preset common headers
        preset_cb = QComboBox()
        preset_cb.setFixedWidth(220)
        preset_cb.addItem("— Quick Add —")
        for name in [
            "Cookie", "Authorization", "X-Forwarded-For",
            "Referer", "Origin", "User-Agent", "Accept",
            "Content-Type", "X-Api-Key", "X-Auth-Token",
        ]:
            preset_cb.addItem(name)
        preset_cb.currentTextChanged.connect(self._preset_header)

        hdr_btn_row.addWidget(add_hdr_btn)
        hdr_btn_row.addWidget(del_hdr_btn)
        hdr_btn_row.addStretch()
        hdr_btn_row.addWidget(QLabel("Preset:"))
        hdr_btn_row.addWidget(preset_cb)
        hdr_lay.addLayout(hdr_btn_row)

        tabs.addTab(hdr_tab, "HTTP Headers")

        # ── Tab 3: Settings ───────────────────────────────────────────────
        cfg_tab = QWidget()
        cfg_lay = QVBoxLayout(cfg_tab)
        cfg_lay.setSpacing(10)
        cfg_lay.setContentsMargins(12, 12, 12, 12)

        req_box = QGroupBox("Request Options")
        req_box_lay = QVBoxLayout(req_box)

        # Method
        row = QHBoxLayout()
        row.addWidget(QLabel("HTTP Method:"))
        self.method_combo = QComboBox()
        self.method_combo.setFixedWidth(120)
        for m in ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]:
            self.method_combo.addItem(m)
        row.addWidget(self.method_combo)
        row.addStretch()
        req_box_lay.addLayout(row)

        # Concurrency
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Concurrency (threads):"))
        self.conc_spin = QSpinBox()
        self.conc_spin.setRange(1, 50)
        self.conc_spin.setValue(5)
        self.conc_spin.setFixedWidth(80)
        row2.addWidget(self.conc_spin)
        row2.addWidget(QLabel("  (1 = sequential, higher = faster but noisier)"))
        row2.addStretch()
        req_box_lay.addLayout(row2)

        # Timeout
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Timeout per request (sec):"))
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(15)
        self.timeout_spin.setFixedWidth(80)
        row3.addWidget(self.timeout_spin)
        row3.addStretch()
        req_box_lay.addLayout(row3)

        # Follow redirects
        self.redirect_cb = QCheckBox("Follow redirects")
        self.redirect_cb.setChecked(True)
        req_box_lay.addWidget(self.redirect_cb)

        cfg_lay.addWidget(req_box)
        cfg_lay.addStretch()
        tabs.addTab(cfg_tab, "Settings")

        # ── Bottom: progress + log + buttons ─────────────────────────────
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(18)
        root.addWidget(self.progress_bar)

        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMaximumHeight(120)
        self.log_edit.setFont(self._mono_font())
        self.log_edit.setStyleSheet(
            f"QTextEdit {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_MUTED}; "
            f"border: 1px solid {COLOR_BORDER}; }}"
        )
        root.addWidget(self.log_edit)

        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("▶  Start Sending")
        self.start_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_SUCCESS}; "
            f"border: 1px solid {COLOR_SUCCESS}; border-radius: 4px; padding: 6px 20px; "
            f"font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {COLOR_SUCCESS}; color: #000; }}"
            f"QPushButton:disabled {{ color: {COLOR_TEXT_MUTED}; border-color: {COLOR_BORDER}; }}"
        )
        self.start_btn.clicked.connect(self._start)

        self.cancel_btn = QPushButton("⏹  Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_CRITICAL}; "
            f"border: 1px solid {COLOR_CRITICAL}; border-radius: 4px; padding: 6px 20px; "
            f"font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {COLOR_CRITICAL}; color: #000; }}"
            f"QPushButton:disabled {{ color: {COLOR_TEXT_MUTED}; border-color: {COLOR_BORDER}; }}"
        )
        self.cancel_btn.clicked.connect(self._cancel)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)

        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _mono_font():
        from PyQt5.QtGui import QFont
        f = QFont("Consolas")
        f.setPointSize(9)
        return f

    def _update_ep_count(self):
        eps = self._get_endpoints()
        self._ep_count_lbl.setText(f"{len(eps)} endpoint{'s' if len(eps) != 1 else ''}")

    def _get_endpoints(self) -> list[str]:
        raw = self.endpoints_edit.toPlainText()
        return [
            line.strip() for line in raw.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

    def _get_headers(self) -> dict:
        headers = {}
        for row in range(self.headers_table.rowCount()):
            name_item  = self.headers_table.item(row, 0)
            value_item = self.headers_table.item(row, 1)
            if name_item and value_item:
                name  = name_item.text().strip()
                value = value_item.text().strip()
                if name:
                    headers[name] = value
        return headers

    def _log(self, msg: str):
        self.log_edit.append(msg)
        sb = self.log_edit.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ── slots ─────────────────────────────────────────────────────────────

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Endpoints File", "",
            "Text files (*.txt *.text *.);;All files (*)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except Exception as exc:
            QMessageBox.warning(self, "Error", f"Cannot read file:\n{exc}")
            return

        lines = content.splitlines()
        # Load file contents into the editor so the user can verify before sending
        existing = set(self._get_endpoints())
        new_eps = [
            l.strip() for l in lines
            if l.strip() and not l.strip().startswith("#")
        ]
        to_add = [ep for ep in new_eps if ep not in existing]
        if to_add:
            current = self.endpoints_edit.toPlainText().rstrip()
            sep = "\n" if current else ""
            self.endpoints_edit.setPlainText(current + sep + "\n".join(to_add))
        self._update_ep_count()

    def _add_header_row(self, name: str = "", value: str = ""):
        row = self.headers_table.rowCount()
        self.headers_table.insertRow(row)
        self.headers_table.setItem(row, 0, QTableWidgetItem(name))
        self.headers_table.setItem(row, 1, QTableWidgetItem(value))
        self.headers_table.editItem(self.headers_table.item(row, 0))

    def _remove_header_row(self):
        rows = sorted(
            {idx.row() for idx in self.headers_table.selectedIndexes()},
            reverse=True
        )
        for r in rows:
            self.headers_table.removeRow(r)

    def _preset_header(self, name: str):
        if name.startswith("—"):
            return
        self._add_header_row(name, "")

    def _start(self):
        endpoints = self._get_endpoints()
        if not endpoints:
            QMessageBox.warning(self, "No Endpoints", "Please enter at least one endpoint URL.")
            return

        if not self.project_paths:
            QMessageBox.warning(
                self, "No Project",
                "Please open or create a project before importing endpoints.\n"
                "Findings need to be stored in a project directory."
            )
            return

        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setMaximum(len(endpoints))
        self.progress_bar.setValue(0)
        self.log_edit.clear()
        self._log(f"Starting: {len(endpoints)} endpoint(s), "
                  f"method={self.method_combo.currentText()}, "
                  f"concurrency={self.conc_spin.value()}")
        self._worker = _ImportWorker(
            endpoints       = endpoints,
            method          = self.method_combo.currentText(),
            headers         = self._get_headers(),
            concurrency     = self.conc_spin.value(),
            follow_redirects= self.redirect_cb.isChecked(),
            timeout         = self.timeout_spin.value(),
            project_paths   = self.project_paths,
            parent          = self,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.cancelled.connect(self._on_cancelled)
        self._worker.start()

    def _cancel(self):
        if self._worker:
            self._worker.cancel()
        self.cancel_btn.setEnabled(False)

    def _on_progress(self, current: int, total: int, msg: str):
        self.progress_bar.setValue(current)
        self._log(msg)

    def _on_finished(self, done: int, errors: int):
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self._log(
            f"\n✓ Done — {done} succeeded, {errors} failed."
        )

    def _on_cancelled(self):
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self._log("\n⏹ Cancelled.")

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)
        event.accept()
