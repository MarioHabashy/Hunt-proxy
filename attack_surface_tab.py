"""
attack_surface_tab.py — Attack Surface Tracker
═══════════════════════════════════════════════
A professional tab for tracking the application attack surface discovered during manual
web application analysis that exhibit interesting or unusual behaviour.

Features
────────
 ✔  Add attack surface entries manually with rich metadata
 ✔  Bulk-import from plaintext / JSON
 ✔  Per-entry status tracking (New / Testing / Confirmed Bug / False Positive / Done)
 ✔  Priority/severity tagging (P1-Critical … P4-Info)
 ✔  Behaviour tags (Rate-limited, Auth-bypass, IDOR, SSRF, etc.)
 ✔  Full-text notes field per entry
 ✔  Tag-based and status-based filtering
 ✔  Colour-coded rows and live badge counters
 ✔  Right-click context menu (edit, duplicate, delete, copy URL, send actions)
 ✔  Send to Repeater / Intruder / Scanner
 ✔  Export to JSON / CSV / Markdown
 ✔  Persistent storage per project (attack_surface.json in project dir)
 ✔  Quick-notes panel (no dialog needed for short annotations)
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QCheckBox, QLineEdit,
    QComboBox, QMenu, QDialog, QTextEdit, QFrame,
    QApplication, QFileDialog, QMessageBox, QAction,
    QFormLayout, QDialogButtonBox, QSizePolicy, QTabWidget,
    QScrollArea, QGroupBox, QToolButton, QPlainTextEdit,
    QAbstractScrollArea, QGridLayout, QListWidget, QListWidgetItem,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QSize
from PyQt5.QtGui import QColor, QFont, QIcon, QBrush, QKeySequence

try:
    from constants import (
        COLOR_BACKGROUND, COLOR_ELEVATED_BG, COLOR_CARD_BG,
        COLOR_DARK_BG, COLOR_BORDER, COLOR_TEXT, COLOR_TEXT_BRIGHT,
        COLOR_TEXT_MUTED, COLOR_ACCENT, COLOR_SUCCESS, COLOR_WARNING,
        COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_INFO,
        COLOR_HOVER, COLOR_LOW,
    )
except ImportError:
    COLOR_BACKGROUND  = "#2B2B2B"
    COLOR_ELEVATED_BG = "#2D2D2D"
    COLOR_CARD_BG     = "#252525"
    COLOR_DARK_BG     = "#1E1E1E"
    COLOR_BORDER      = "#3C3F41"
    COLOR_TEXT        = "#BBBBBB"
    COLOR_TEXT_BRIGHT = "#FFFFFF"
    COLOR_TEXT_MUTED  = "#888888"
    COLOR_ACCENT      = "#6A8759"
    COLOR_SUCCESS     = "#00E676"
    COLOR_WARNING     = "#FFA726"
    COLOR_CRITICAL    = "#FF6B6B"
    COLOR_HIGH        = "#FFA726"
    COLOR_MEDIUM      = "#FFEE58"
    COLOR_INFO        = "#64B5F6"
    COLOR_LOW         = "#64B5F6"
    COLOR_HOVER       = "#3C3F41"

import logging
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Domain constants
# ─────────────────────────────────────────────────────────────────────────────

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"]

STATUSES = ["New", "Testing", "Confirmed Bug", "False Positive", "Done"]
STATUS_COLOR = {
    "New":           ("#3a6baa", "#ffffff"),
    "Testing":       ("#8b6914", "#ffffff"),
    "Confirmed Bug": ("#8b1a1a", "#ffffff"),
    "False Positive":("#3a5a3a", "#aaaaaa"),
    "Done":          ("#2d4a2d", "#66bb6a"),
}

PRIORITIES = ["P1 - Critical", "P2 - High", "P3 - Medium", "P4 - Info"]
PRIORITY_COLOR = {
    "P1 - Critical": COLOR_CRITICAL,
    "P2 - High":     COLOR_HIGH,
    "P3 - Medium":   COLOR_MEDIUM,
    "P4 - Info":     COLOR_INFO,
}

BEHAVIOUR_TAGS = [
    "Rate-Limited",
    "Auth-Required",
    "Auth-Bypass",
    "IDOR",
    "SSRF",
    "SSTI",
    "SQLi",
    "XSS",
    "XXE",
    "CSRF",
    "Open-Redirect",
    "File-Upload",
    "GraphQL",
    "WebSocket",
    "Admin-Panel",
    "Debug-Endpoint",
    "Unauthenticated",
    "Weird-Response",
    "Error-Disclosed",
    "Outdated-Param",
    "Mass-Assignment",
    "Business-Logic",
    "Race-Condition",
    "Cache-Poisoning",
    "Prototype-Pollution",
]

TABLE_COLS = [
    "⚲", "#", "Priority", "Method", "URL / Path", "Status Code", "R",
    "Status", "Behaviour Tags", "Auth", "Note Preview", "Source", "Added", "↺",
]
COL_IDX = {h: i for i, h in enumerate(TABLE_COLS)}

# Auth roles that can be tracked per endpoint
AUTH_ROLES = ["Admin", "User", "Anon"]

# Per-source colour map — module-level constant (not rebuilt on every row render)
_SOURCE_COLORS = {
    "HTTP History": COLOR_INFO,
    "Repeater":     COLOR_ACCENT,
    "Intruder":     COLOR_WARNING,
    "Scanner":      COLOR_CRITICAL,
    "Intercept":    COLOR_MEDIUM,
    "Manual":       COLOR_TEXT_MUTED,
}

# Vulnerability flaw types shown in Flow dialogs
FLAW_TYPES = [
    "Authentication",
    "Authorization / IDOR",
    "Business Logic",
    "SSRF",
    "SQLi",
    "XSS",
    "CSRF",
    "File Upload",
    "Open Redirect",
    "Race Condition",
    "Mass Assignment",
    "Prototype Pollution",
    "Custom",
]

# Tint colours (bg, accent) for flow groups — cycles when more than 8 flows exist
_FLOW_TINTS = [
    ("#0d1a2e", "#3a8bdf"),   # blue
    ("#1a0d2e", "#8a3adf"),   # purple
    ("#0a2418", "#2aaa54"),   # green
    ("#2e0d0d", "#df3a3a"),   # red
    ("#2a1a04", "#df8a1a"),   # orange
    ("#04242a", "#1aaadf"),   # teal
    ("#1a0d18", "#df3aaa"),   # pink
    ("#041a1a", "#1adfdf"),   # cyan
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _badge(text: str, bg: str, fg: str = "#ffffff", radius: int = 4) -> str:
    """Return an HTML badge string (used only for display strings)."""
    return (
        f'<span style="background:{bg};color:{fg};border-radius:{radius}px;'
        f'padding:1px 6px;font-size:11px;font-weight:600;">{text}</span>'
    )


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def _short_url(url: str, max_len: int = 80) -> str:
    if len(url) <= max_len:
        return url
    return url[:max_len - 3] + "…"


def _extract_host(url: str) -> str:
    """Return just the hostname (no port/path) from a URL, or empty string."""
    try:
        from urllib.parse import urlparse as _up
        return _up(url).hostname or ""
    except Exception:
        return ""


def _heuristic_tags(url: str, method: str) -> List[str]:
    """Return auto-suggested behaviour tags based on URL patterns and HTTP method."""
    tags: List[str] = []
    u = url.lower()
    if any(x in u for x in ("/admin", "/console", "/panel", "/manage", "/management", "/cp/")):
        tags.append("Admin-Panel")
    if any(x in u for x in ("/debug", "/internal/", "/dev/", "/test/", "/.well-known")):
        tags.append("Debug-Endpoint")
    if any(x in u for x in ("redirect=", "url=", "next=", "return=", "goto=", "dest=")):
        tags.append("Open-Redirect")
    if method.upper() in ("PUT", "PATCH", "DELETE"):
        tags.append("IDOR")
    if any(x in u for x in ("upload", "file=", "attachment", "filename=", "/files/")):
        tags.append("File-Upload")
    if any(x in u for x in ("/graphql", "/graph", "/gql")):
        tags.append("GraphQL")
    if any(x in u for x in ("/ws/", "/websocket", "/socket.io")):
        tags.append("WebSocket")
    return tags


def _extract_request_params(request_snippet: str) -> List[str]:
    """
    Parse parameter names from a raw HTTP request snippet.
    Handles:
      - URL-encoded body  (key=value&key2=value2)
      - JSON body         ({"key": ..., "key2": ...})
      - Multipart field names  (Content-Disposition: form-data; name="field")
      - Query string on the request line  (GET /path?a=1&b=2 HTTP/1.1)
    Returns a deduplicated list of param names, max 12 entries.
    """
    if not request_snippet:
        return []
    params: List[str] = []
    lines = request_snippet.splitlines()

    # ── Query-string params from the request line  (GET /path?a=1&b=2 HTTP/...)
    if lines:
        try:
            from urllib.parse import urlparse as _up, parse_qs as _pqs
            first = lines[0].strip()
            parts = first.split()
            if len(parts) >= 2:
                path_part = parts[1]
                qs = _up(path_part).query
                if qs:
                    for k in _pqs(qs).keys():
                        if k and k not in params:
                            params.append(k)
        except Exception:
            pass

    # Locate the body — everything after the first blank line
    body = ""
    for i, line in enumerate(lines):
        if line.strip() == "":
            body = "\n".join(lines[i + 1:]).strip()
            break

    if not body:
        return params[:12]

    # ── JSON body
    if body.lstrip().startswith("{") or body.lstrip().startswith("["):
        try:
            import json as _json
            data = _json.loads(body)
            if isinstance(data, dict):
                for k in data.keys():
                    if isinstance(k, str) and k not in params:
                        params.append(k)
            elif isinstance(data, list) and data and isinstance(data[0], dict):
                for k in data[0].keys():
                    if isinstance(k, str) and k not in params:
                        params.append(k)
        except Exception:
            pass
        return params[:12]

    # ── Multipart  (Content-Disposition: form-data; name="fieldname")
    if 'content-disposition' in body.lower():
        import re as _re
        for m in _re.finditer(r'name=["\']([^"\']+)["\']', body, _re.IGNORECASE):
            k = m.group(1)
            if k not in params:
                params.append(k)
        if params:
            return params[:12]

    # ── URL-encoded body  (key=value&key2=value2)
    try:
        from urllib.parse import parse_qs as _pqs2
        # Only parse the first 2 KB to avoid huge bodies
        parsed = _pqs2(body[:2048], keep_blank_values=True)
        if parsed:
            for k in parsed.keys():
                if k and k not in params:
                    params.append(k)
    except Exception:
        pass

    return params[:12]


# ─────────────────────────────────────────────────────────────────────────────
# Add / Edit endpoint dialog
# ─────────────────────────────────────────────────────────────────────────────

class AttackSurfaceEntryDialog(QDialog):
    """Full-featured dialog to create or edit an attack surface entry."""

    def __init__(self, entry: Optional[Dict] = None, parent=None):
        super().__init__(parent)
        self._entry = entry or {}
        editing = bool(entry)
        self.setWindowTitle("Edit Entry" if editing else "Add Entry")
        self.setMinimumSize(960, 720)
        self.resize(1100, 820)
        self._apply_style()
        self._build_ui()
        if editing:
            self._populate(entry)

    # ── Style ──────────────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
            }}
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 11px;
            }}
            QLineEdit, QPlainTextEdit, QComboBox, QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 4px 6px;
                font-size: 11px;
            }}
            QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
                border: 1px solid {COLOR_ACCENT};
            }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton#save_btn {{
                background-color: {COLOR_ACCENT};
                border: none;
                font-weight: 600;
            }}
            QPushButton#save_btn:hover {{ background-color: #7a9a69; }}
            QCheckBox {{ color: {COLOR_TEXT}; font-size: 11px; }}
            QGroupBox {{
                color: {COLOR_TEXT_MUTED};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                margin-top: 8px;
                font-size: 11px;
            }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}
        """)

    # ── UI build ───────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        # ── URL / Path
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://target.com/api/v1/users  or  /api/v1/users")
        form.addRow("URL / Path *", self.url_edit)

        # ── Method + Status Code row
        row1 = QHBoxLayout()
        self.method_combo = QComboBox()
        self.method_combo.addItems(METHODS)
        self.method_combo.setMinimumWidth(100)
        row1.addWidget(self.method_combo)

        self.status_code_edit = QLineEdit()
        self.status_code_edit.setPlaceholderText("Status code  e.g. 200")
        self.status_code_edit.setMaximumWidth(130)
        row1.addWidget(QLabel("  Status Code:"))
        row1.addWidget(self.status_code_edit)
        row1.addStretch()
        form.addRow("Method", row1)

        # ── Priority
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(PRIORITIES)
        form.addRow("Priority", self.priority_combo)

        # ── Status
        self.status_combo = QComboBox()
        self.status_combo.addItems(STATUSES)
        form.addRow("Testing Status", self.status_combo)

        # ── Interesting Parameters
        self.params_edit = QLineEdit()
        self.params_edit.setPlaceholderText("redirect, user_id, file, id, token…  (comma-separated)")
        form.addRow("Interesting Params", self.params_edit)

        # ── Auth contexts tested
        auth_row = QHBoxLayout()
        self._auth_checks: Dict[str, QCheckBox] = {}
        for role in AUTH_ROLES:
            cb = QCheckBox(role)
            cb.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 11px;")
            self._auth_checks[role] = cb
            auth_row.addWidget(cb)
        auth_row.addStretch()
        form.addRow("Auth Tested", auth_row)

        # ── Flags row (pin + needs retest)
        flags_row = QHBoxLayout()
        self.pin_check = QCheckBox("⚲  Pin to top")
        self.pin_check.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 11px;")
        self.retest_check = QCheckBox("↺  Needs Retest")
        self.retest_check.setStyleSheet(f"color: {COLOR_WARNING}; font-size: 11px;")
        flags_row.addWidget(self.pin_check)
        flags_row.addSpacing(20)
        flags_row.addWidget(self.retest_check)
        flags_row.addStretch()
        form.addRow("Flags", flags_row)

        root.addLayout(form)

        # ── Behaviour tags grid
        tags_group = QGroupBox("Behaviour Tags  (select all that apply)")
        grid = QGridLayout(tags_group)
        grid.setSpacing(6)
        grid.setContentsMargins(8, 12, 8, 8)
        self._tag_checks: Dict[str, QCheckBox] = {}
        cols = 5
        for i, tag in enumerate(BEHAVIOUR_TAGS):
            cb = QCheckBox(tag)
            cb.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 11px;")
            self._tag_checks[tag] = cb
            grid.addWidget(cb, i // cols, i % cols)
        # Push everything to the left inside each column
        for c in range(cols):
            grid.setColumnStretch(c, 1)

        root.addWidget(tags_group)

        # ── Custom tag
        custom_row = QHBoxLayout()
        self.custom_tag_edit = QLineEdit()
        self.custom_tag_edit.setPlaceholderText("Add custom tags, comma-separated…")
        custom_row.addWidget(QLabel("Custom tags:"))
        custom_row.addWidget(self.custom_tag_edit)
        root.addLayout(custom_row)

        # ── Notes
        notes_label = QLabel("Notes / Observations:")
        notes_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        root.addWidget(notes_label)
        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText(
            "Describe the weird/interesting behaviour…\n"
            "e.g. Returns 500 when X-Custom-Header is present, "
            "leaks internal IPs in error body, etc."
        )
        self.notes_edit.setMinimumHeight(90)
        root.addWidget(self.notes_edit)

        # ── Request snippet (optional)
        req_label = QLabel("Request Snippet (optional):")
        req_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        root.addWidget(req_label)
        self.request_edit = QPlainTextEdit()
        self.request_edit.setPlaceholderText(
            "Paste the relevant request or cURL command here…"
        )
        self.request_edit.setFont(QFont("Monospace", 10))
        self.request_edit.setMinimumHeight(70)
        root.addWidget(self.request_edit)

        root.addStretch()

        # ── Buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        save_btn = QPushButton("Save Entry")
        save_btn.setObjectName("save_btn")
        save_btn.clicked.connect(self._validate_and_accept)
        save_btn.setDefault(True)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

    # ── Populate for edit mode ─────────────────────────────────────────────

    def _populate(self, e: Dict):
        self.url_edit.setText(e.get("url", ""))
        m = e.get("method", "GET")
        idx = self.method_combo.findText(m)
        if idx >= 0:
            self.method_combo.setCurrentIndex(idx)
        self.status_code_edit.setText(str(e.get("status_code", "")))
        p = e.get("priority", PRIORITIES[2])
        idx = self.priority_combo.findText(p)
        if idx >= 0:
            self.priority_combo.setCurrentIndex(idx)
        s = e.get("status", "New")
        idx = self.status_combo.findText(s)
        if idx >= 0:
            self.status_combo.setCurrentIndex(idx)
        for tag, cb in self._tag_checks.items():
            cb.setChecked(tag in e.get("tags", []))
        custom_tags = [t for t in e.get("tags", []) if t not in BEHAVIOUR_TAGS]
        self.custom_tag_edit.setText(", ".join(custom_tags))
        self.params_edit.setText(", ".join(e.get("params", [])))
        auth_tested = e.get("auth_tested", [])
        for role, cb in self._auth_checks.items():
            cb.setChecked(role in auth_tested)
        self.pin_check.setChecked(e.get("pinned", False))
        self.retest_check.setChecked(e.get("needs_retest", False))
        self.notes_edit.setPlainText(e.get("notes", ""))
        self.request_edit.setPlainText(e.get("request_snippet", ""))

    # ── Validate & collect ─────────────────────────────────────────────────

    def _validate_and_accept(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Validation", "URL / Path is required.")
            self.url_edit.setFocus()
            return
        if not (url.startswith("http://") or url.startswith("https://") or url.startswith("/")):
            QMessageBox.warning(
                self, "Validation",
                "URL must start with http://, https://, or / (for a relative path)."
            )
            self.url_edit.setFocus()
            return
        self.accept()

    def get_entry(self) -> Dict:
        tags = [t for t, cb in self._tag_checks.items() if cb.isChecked()]
        for ct in self.custom_tag_edit.text().split(","):
            ct = ct.strip()
            if ct and ct not in tags:
                tags.append(ct)
        params = [p.strip() for p in self.params_edit.text().split(",") if p.strip()]
        auth_tested = [r for r, cb in self._auth_checks.items() if cb.isChecked()]
        return {
            "id":               self._entry.get("id", str(uuid.uuid4())),
            "url":              self.url_edit.text().strip(),
            "method":           self.method_combo.currentText(),
            "status_code":      self.status_code_edit.text().strip(),
            "priority":         self.priority_combo.currentText(),
            "status":           self.status_combo.currentText(),
            "tags":             tags,
            "params":           params,
            "auth_tested":      auth_tested,
            "pinned":           self.pin_check.isChecked(),
            "needs_retest":     self.retest_check.isChecked(),
            "notes":            self.notes_edit.toPlainText().strip(),
            "request_snippet":  self.request_edit.toPlainText().strip(),
            "response_snippet": self._entry.get("response_snippet", ""),
            "has_response":     bool(self._entry.get("response_snippet", "")),
            "added":            self._entry.get("added", _now_str()),
            "updated":          _now_str(),
            "last_tested":      self._entry.get("last_tested", ""),
            "source":           self._entry.get("source", "Manual"),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Bulk-import dialog
# ─────────────────────────────────────────────────────────────────────────────

class BulkImportDialog(QDialog):
    """
    Paste a list of URLs (one per line) or a JSON array.
    All imported entries get default status = New and selected priority.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bulk Import Attack Surface Entries")
        self.setMinimumSize(560, 420)
        self.setStyleSheet(f"""
            QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
            QLabel {{ color: {COLOR_TEXT}; font-size: 11px; }}
            QPlainTextEdit {{
                background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                font-family: monospace; font-size: 11px;
            }}
            QComboBox, QLineEdit {{
                background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                padding: 4px;
            }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px; padding: 5px 12px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton#ok_btn {{
                background-color: {COLOR_ACCENT}; border: none; font-weight: 600;
            }}
        """)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(14, 14, 14, 14)

        layout.addWidget(QLabel(
            "Paste URLs (one per line) or a JSON array of objects with a 'url' key:"
        ))

        self.text_edit = QPlainTextEdit()
        self.text_edit.setPlaceholderText(
            "https://target.com/api/v1/admin\n"
            "https://target.com/api/v2/user/{id}\n"
            "…\n\n"
            "or JSON: [{\"url\": \"…\", \"method\": \"POST\"}, …]"
        )
        layout.addWidget(self.text_edit)

        row = QHBoxLayout()
        row.addWidget(QLabel("Default Priority:"))
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(PRIORITIES)
        self.priority_combo.setCurrentIndex(2)
        row.addWidget(self.priority_combo)
        row.addSpacing(20)
        row.addWidget(QLabel("Default Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(METHODS)
        row.addWidget(self.method_combo)
        row.addStretch()
        layout.addLayout(row)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.button(QDialogButtonBox.Ok).setObjectName("ok_btn")
        btns.button(QDialogButtonBox.Ok).setText("Import")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def get_entries(self) -> List[Dict]:
        text = self.text_edit.toPlainText().strip()
        priority = self.priority_combo.currentText()
        default_method = self.method_combo.currentText()
        entries: List[Dict] = []

        # Try JSON first
        if text.startswith("[") or text.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    if not isinstance(item, dict) or not item.get("url"):
                        continue
                    entries.append({
                        "id":              str(uuid.uuid4()),
                        "url":             item["url"].strip(),
                        "method":          item.get("method", default_method).upper(),
                        "status_code":     str(item.get("status_code", "")),
                        "priority":        item.get("priority", priority),
                        "status":          item.get("status", "New"),
                        "tags":            item.get("tags", []),
                        "notes":           item.get("notes", ""),
                        "request_snippet": item.get("request_snippet", ""),
                        "added":           _now_str(),
                        "updated":         _now_str(),
                    })
                return entries
            except json.JSONDecodeError:
                pass

        # Plain text — one URL per line
        for line in text.splitlines():
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            entries.append({
                "id":              str(uuid.uuid4()),
                "url":             url,
                "method":          default_method,
                "status_code":     "",
                "priority":        priority,
                "status":          "New",
                "tags":            [],
                "notes":           "",
                "request_snippet": "",
                "added":           _now_str(),
                "updated":         _now_str(),
            })
        return entries


# ─────────────────────────────────────────────────────────────────────────────
# Vulnerability Flow / Chain dialog
# ─────────────────────────────────────────────────────────────────────────────

class FlowDialog(QDialog):
    """
    Create or edit a vulnerability flow — an ordered chain of endpoints
    that together form a flaw (e.g. Authentication bypass, IDOR chain).
    """

    def __init__(self, flow: Optional[Dict] = None,
                 all_entries: Optional[List[Dict]] = None, parent=None):
        super().__init__(parent)
        self._flow = flow or {}
        self._all_entries = all_entries or []
        self._flow_entry_ids: List[str] = list(self._flow.get("entry_ids", []))
        editing = bool(flow)
        self.setWindowTitle("Edit Flow" if editing else "Create Vulnerability Flow")
        self.setMinimumSize(920, 640)
        self.resize(1060, 740)
        self._apply_style()
        self._build_ui()
        if editing:
            self._populate()

    # ── Style ──────────────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
            }}
            QLabel {{
                color: {COLOR_TEXT};
                font-size: 11px;
            }}
            QLineEdit, QPlainTextEdit, QComboBox {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 4px 6px;
                font-size: 11px;
            }}
            QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
                border: 1px solid {COLOR_ACCENT};
            }}
            QListWidget {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                font-size: 11px;
                outline: none;
            }}
            QListWidget::item {{ padding: 5px 8px; border-radius: 2px; }}
            QListWidget::item:selected {{
                background-color: #2a4a6b;
                color: #ffffff;
            }}
            QListWidget::item:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton#save_btn {{
                background-color: {COLOR_ACCENT};
                border: none;
                font-weight: 600;
            }}
            QPushButton#save_btn:hover {{ background-color: #7a9a69; }}
            QGroupBox {{
                color: {COLOR_TEXT_MUTED};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                margin-top: 8px;
                font-size: 11px;
            }}
            QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}
        """)

    # ── UI build ───────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        # ── Flow metadata form
        form = QFormLayout()
        form.setSpacing(8)
        form.setLabelAlignment(Qt.AlignRight | Qt.AlignVCenter)
        form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(
            "e.g.  Authentication Flaw,  IDOR on /users,  Password Reset Chain…"
        )
        form.addRow("Flow Name *", self.name_edit)

        type_row = QHBoxLayout()
        self.type_combo = QComboBox()
        self.type_combo.addItems(FLAW_TYPES)
        self.type_combo.setMinimumWidth(180)
        type_row.addWidget(self.type_combo)
        type_row.addStretch()
        form.addRow("Flaw Type", type_row)

        self.desc_edit = QPlainTextEdit()
        self.desc_edit.setPlaceholderText(
            "Describe the attack scenario or vulnerability chain…\n"
            "e.g. Step 1 = GET /login to grab CSRF token, Step 2 = POST /login to authenticate."
        )
        self.desc_edit.setMaximumHeight(72)
        form.addRow("Description", self.desc_edit)

        root.addLayout(form)

        # ── Two-pane endpoint selector
        panes_lbl = QHBoxLayout()
        lbl_avail = QLabel("Available Endpoints  (double-click or → to add)")
        lbl_avail.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 11px; font-weight: 600;"
        )
        panes_lbl.addWidget(lbl_avail, 1)

        lbl_flow = QLabel("Flow Sequence  (ordered chain — use ↑ ↓ to reorder)")
        lbl_flow.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 11px; font-weight: 600;"
        )
        panes_lbl.addWidget(lbl_flow, 1)
        root.addLayout(panes_lbl)

        pane = QHBoxLayout()
        pane.setSpacing(8)

        # ── Left: available entries not yet in flow
        left_w = QWidget()
        left_lay = QVBoxLayout(left_w)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(4)

        self.avail_filter = QLineEdit()
        self.avail_filter.setPlaceholderText("Filter by URL or method…")
        self.avail_filter.setFixedHeight(26)
        self.avail_filter.textChanged.connect(self._refresh_avail)
        left_lay.addWidget(self.avail_filter)

        self.avail_list = QListWidget()
        self.avail_list.setMinimumHeight(240)
        self.avail_list.itemDoubleClicked.connect(lambda item: self._add_selected(item))
        left_lay.addWidget(self.avail_list)
        pane.addWidget(left_w, 1)

        # ── Middle: move buttons
        mid = QVBoxLayout()
        mid.setSpacing(6)
        mid.addStretch()

        add_btn = QPushButton("→")
        add_btn.setFixedWidth(36)
        add_btn.setToolTip("Add to flow")
        add_btn.clicked.connect(lambda: self._add_selected())
        mid.addWidget(add_btn)

        rem_btn = QPushButton("←")
        rem_btn.setFixedWidth(36)
        rem_btn.setToolTip("Remove from flow")
        rem_btn.clicked.connect(lambda: self._remove_selected())
        mid.addWidget(rem_btn)

        mid.addSpacing(14)

        up_btn = QPushButton("↑")
        up_btn.setFixedWidth(36)
        up_btn.setToolTip("Move up in sequence (earlier in chain)")
        up_btn.clicked.connect(self._move_up)
        mid.addWidget(up_btn)

        dn_btn = QPushButton("↓")
        dn_btn.setFixedWidth(36)
        dn_btn.setToolTip("Move down in sequence (later in chain)")
        dn_btn.clicked.connect(self._move_down)
        mid.addWidget(dn_btn)

        mid.addStretch()
        pane.addLayout(mid)

        # ── Right: ordered flow list
        right_w = QWidget()
        right_lay = QVBoxLayout(right_w)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(4)

        seq_lbl = QLabel(f"Sequence ({0} steps)")
        seq_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        seq_lbl.setObjectName("seq_count_lbl")
        right_lay.addWidget(seq_lbl)
        self._seq_count_lbl = seq_lbl

        self.flow_list = QListWidget()
        self.flow_list.setMinimumHeight(240)
        self.flow_list.itemDoubleClicked.connect(lambda item: self._remove_selected(item))
        right_lay.addWidget(self.flow_list)
        pane.addWidget(right_w, 1)

        root.addLayout(pane)
        root.addStretch()

        # ── Dialog buttons
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)
        save_btn = QPushButton("💾  Save Flow")
        save_btn.setObjectName("save_btn")
        save_btn.clicked.connect(self._validate_and_accept)
        save_btn.setDefault(True)
        btn_row.addWidget(save_btn)
        root.addLayout(btn_row)

        # Initial population
        self._refresh_avail()
        self._refresh_flow_list()

    # ── Entry display helpers ─────────────────────────────────────────────

    _METH_COLORS = {
        "GET": "#6A8759", "POST": "#CC7832", "PUT": "#9876AA",
        "PATCH": "#FFC66D", "DELETE": "#FF6B6B",
        "HEAD": "#6897BB", "OPTIONS": "#808080",
    }

    def _entry_label(self, ep: Dict) -> str:
        method = ep.get('method', 'GET')
        url    = ep.get('url', '')
        params = ep.get('params', []) or []
        # Fall back to params auto-extracted from the request snippet
        if not params:
            params = _extract_request_params(ep.get('request_snippet', ''))
        notes  = ep.get('notes', '')
        param_str = ''
        if params:
            shown = params[:3]
            more  = f'  +{len(params)-3}' if len(params) > 3 else ''
            param_str = f"  ⚙ [{', '.join(shown)}{more}]"
        # Only show note preview when we have nothing else to distinguish the entry
        note_str = ''
        if notes and not param_str:
            note_str = f"  — {notes[:40].replace(chr(10), ' ')}"
        return f"[{method}]  {url}{param_str}{note_str}"

    def _make_list_item(self, ep: Dict, prefix: str = "") -> QListWidgetItem:
        item = QListWidgetItem(prefix + self._entry_label(ep))
        item.setData(Qt.UserRole, ep["id"])
        meth = ep.get("method", "GET")
        item.setForeground(QBrush(QColor(self._METH_COLORS.get(meth, COLOR_TEXT))))
        tags   = ", ".join(ep.get("tags", []))
        params = ", ".join(ep.get("params", []))
        notes  = ep.get('notes', '')
        tip_parts = [
            f"{ep.get('priority','')}  |  Status: {ep.get('status','New')}",
        ]
        if params:
            tip_parts.append(f"Params: {params}")
        if tags:
            tip_parts.append(f"Tags: {tags}")
        if notes:
            tip_parts.append(f"Notes: {notes[:160]}")
        item.setToolTip("\n".join(tip_parts))
        return item

    # ── List refresh ──────────────────────────────────────────────────────

    def _refresh_avail(self):
        q = self.avail_filter.text().strip().lower()
        self.avail_list.clear()
        for ep in self._all_entries:
            if ep["id"] in self._flow_entry_ids:
                continue
            label = self._entry_label(ep)
            # Also search within params and notes
            search_hay = " ".join([
                label,
                " ".join(ep.get("params", [])),
                ep.get("notes", "")[:200],
            ]).lower()
            if q and q not in search_hay:
                continue
            self.avail_list.addItem(self._make_list_item(ep))

    def _refresh_flow_list(self):
        self.flow_list.clear()
        entry_map = {ep["id"]: ep for ep in self._all_entries}
        for i, eid in enumerate(self._flow_entry_ids):
            ep = entry_map.get(eid)
            if ep is None:
                continue
            self.flow_list.addItem(self._make_list_item(ep, prefix=f"  {i + 1}.  "))
        n = len(self._flow_entry_ids)
        self._seq_count_lbl.setText(f"Sequence ({n} step{'s' if n != 1 else ''})") 

    # ── Move operations ───────────────────────────────────────────────────

    def _add_selected(self, item=None):
        """Add the given item (or the currently selected one) to the flow sequence."""
        if item is None:
            # Called from the → button: use the list's selected item
            selected = self.avail_list.selectedItems()
            if not selected:
                # Fall back to currentItem if nothing is explicitly selected
                item = self.avail_list.currentItem()
            else:
                item = selected[0]
        if item is None:
            return
        eid = item.data(Qt.UserRole)
        # Guard: the item must actually be in the available pool (not already in flow)
        if eid not in self._flow_entry_ids:
            self._flow_entry_ids.append(eid)
        # Remember where in the avail list the user was so we can restore nearby selection
        avail_row = self.avail_list.row(item)
        self._refresh_avail()
        self._refresh_flow_list()
        # Highlight the newly added step in the flow list
        self.flow_list.setCurrentRow(self.flow_list.count() - 1)
        # Restore a nearby selection in the available list for rapid multi-adds
        new_count = self.avail_list.count()
        if new_count > 0:
            self.avail_list.setCurrentRow(min(avail_row, new_count - 1))

    def _remove_selected(self, item=None):
        """Remove the given item (or the currently selected one) from the flow sequence."""
        if item is None:
            selected = self.flow_list.selectedItems()
            if not selected:
                item = self.flow_list.currentItem()
            else:
                item = selected[0]
        if item is None:
            return
        flow_row = self.flow_list.row(item)
        eid = item.data(Qt.UserRole)
        if eid in self._flow_entry_ids:
            self._flow_entry_ids.remove(eid)
        self._refresh_avail()
        self._refresh_flow_list()
        # Restore selection in flow list
        new_count = self.flow_list.count()
        if new_count > 0:
            self.flow_list.setCurrentRow(min(flow_row, new_count - 1))

    def _move_up(self):
        row = self.flow_list.currentRow()
        if row <= 0 or row >= len(self._flow_entry_ids):
            return
        self._flow_entry_ids[row], self._flow_entry_ids[row - 1] = (
            self._flow_entry_ids[row - 1], self._flow_entry_ids[row]
        )
        self._refresh_flow_list()
        self.flow_list.setCurrentRow(row - 1)

    def _move_down(self):
        row = self.flow_list.currentRow()
        if row < 0 or row >= len(self._flow_entry_ids) - 1:
            return
        self._flow_entry_ids[row], self._flow_entry_ids[row + 1] = (
            self._flow_entry_ids[row + 1], self._flow_entry_ids[row]
        )
        self._refresh_flow_list()
        self.flow_list.setCurrentRow(row + 1)

    # ── Populate for edit mode ────────────────────────────────────────────

    def _populate(self):
        self.name_edit.setText(self._flow.get("name", ""))
        t = self._flow.get("type", FLAW_TYPES[0])
        idx = self.type_combo.findText(t)
        if idx >= 0:
            self.type_combo.setCurrentIndex(idx)
        self.desc_edit.setPlainText(self._flow.get("description", ""))
        self._refresh_avail()
        self._refresh_flow_list()

    # ── Validate & collect ────────────────────────────────────────────────

    def _validate_and_accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Flow Name is required.")
            self.name_edit.setFocus()
            return
        if not self._flow_entry_ids:
            QMessageBox.warning(
                self, "Validation",
                "Add at least one endpoint to the flow sequence."
            )
            return
        self.accept()

    def get_flow(self) -> Dict:
        return {
            "id":          self._flow.get("id", str(uuid.uuid4())),
            "name":        self.name_edit.text().strip(),
            "type":        self.type_combo.currentText(),
            "description": self.desc_edit.toPlainText().strip(),
            "entry_ids":   list(self._flow_entry_ids),
            "added":       self._flow.get("added", _now_str()),
            "updated":     _now_str(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Detail / Notes side-panel widget
# ─────────────────────────────────────────────────────────────────────────────

class AttackSurfaceDetailPanel(QWidget):
    """Right-hand read/edit panel shown when an attack surface entry is selected."""

    save_requested = pyqtSignal(dict)   # emits updated entry

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_entry: Optional[Dict] = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(6)

        # ── Header
        self.header_lbl = QLabel("— No entry selected —")
        self.header_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-size: 12px; font-weight: 600;"
        )
        self.header_lbl.setWordWrap(True)
        layout.addWidget(self.header_lbl)

        # ── Meta row
        self.meta_lbl = QLabel("")
        self.meta_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        self.meta_lbl.setWordWrap(True)
        layout.addWidget(self.meta_lbl)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep)

        # ── Row 1: Status | Priority | Auth toggles | Pin/Retest indicators
        row1 = QHBoxLayout()
        row1.setSpacing(6)
        _st_lbl = QLabel("Status:")
        _st_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        row1.addWidget(_st_lbl)
        self.status_combo = QComboBox()
        self.status_combo.addItems(STATUSES)
        self.status_combo.setMaximumWidth(140)
        self.status_combo.currentIndexChanged.connect(self._on_save)
        row1.addWidget(self.status_combo)
        row1.addSpacing(10)
        _pri_lbl = QLabel("Priority:")
        _pri_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        row1.addWidget(_pri_lbl)
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(PRIORITIES)
        self.priority_combo.setMaximumWidth(120)
        self.priority_combo.currentIndexChanged.connect(self._on_save)
        row1.addWidget(self.priority_combo)
        row1.addSpacing(12)
        _auth_hdr = QLabel("Auth:")
        _auth_hdr.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 10px;")
        row1.addWidget(_auth_hdr)
        self._auth_role_lbls: Dict[str, QPushButton] = {}
        for role in AUTH_ROLES:
            btn = QPushButton(role)
            btn.setCheckable(True)
            btn.setFixedHeight(20)
            btn.setStyleSheet(f"""
                QPushButton {{
                    color: {COLOR_TEXT_MUTED}; font-size: 10px; padding: 1px 7px;
                    border: 1px solid {COLOR_BORDER}; border-radius: 3px;
                    background: transparent;
                }}
                QPushButton:checked {{
                    color: {COLOR_SUCCESS}; border: 1px solid {COLOR_SUCCESS};
                    background: transparent; font-weight: 600;
                }}
                QPushButton:hover {{ border-color: {COLOR_TEXT_MUTED}; }}
            """)
            btn.setToolTip(f"Click to toggle: {role} role tested")
            btn.toggled.connect(lambda checked, r=role: self._on_auth_toggled(r, checked))
            self._auth_role_lbls[role] = btn
            row1.addWidget(btn)
        row1.addStretch()
        self._pin_indicator = QLabel("⚲ Pinned")
        self._pin_indicator.setStyleSheet(
            f"color: {COLOR_WARNING}; font-size: 10px; font-weight: 600;"
        )
        self._pin_indicator.setVisible(False)
        row1.addWidget(self._pin_indicator)
        self._retest_indicator = QLabel("↺ Needs Retest")
        self._retest_indicator.setStyleSheet(
            f"color: {COLOR_CRITICAL}; font-size: 10px; font-weight: 600;"
        )
        self._retest_indicator.setVisible(False)
        row1.addWidget(self._retest_indicator)
        layout.addLayout(row1)

        # ── Row 2: Tags + Params (compact info line)
        row2 = QHBoxLayout()
        row2.setSpacing(16)
        self.tags_lbl = QLabel("")
        self.tags_lbl.setStyleSheet(f"color: {COLOR_ACCENT}; font-size: 11px;")
        row2.addWidget(self.tags_lbl)
        self.params_lbl = QLabel("")
        self.params_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        row2.addWidget(self.params_lbl)
        row2.addStretch()
        layout.addLayout(row2)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep2)

        # ── Horizontal splitter: Notes | Request Snippet | Response
        h_split = QSplitter(Qt.Horizontal)
        h_split.setHandleWidth(4)

        # Left pane – Notes
        notes_widget = QWidget()
        notes_layout = QVBoxLayout(notes_widget)
        notes_layout.setContentsMargins(0, 0, 4, 0)
        notes_layout.setSpacing(4)

        notes_hdr = QHBoxLayout()
        notes_hdr.addWidget(QLabel("Notes:"))
        notes_hdr.addStretch()
        self.save_note_btn = QPushButton(" Save")
        self.save_note_btn.setMaximumWidth(70)
        self.save_note_btn.setStyleSheet(
            f"background: {COLOR_ACCENT}; color: #fff; border: none; "
            f"border-radius: 3px; padding: 3px 8px; font-size: 11px;"
        )
        self.save_note_btn.clicked.connect(self._on_save)
        notes_hdr.addWidget(self.save_note_btn)
        notes_layout.addLayout(notes_hdr)

        self.notes_edit = QPlainTextEdit()
        self.notes_edit.setPlaceholderText("Write observations, payloads tried, results…")
        self.notes_edit.setStyleSheet(
            f"background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"font-size: 11px; padding: 4px;"
        )
        notes_layout.addWidget(self.notes_edit)
        h_split.addWidget(notes_widget)

        # Middle pane – Request Snippet
        req_widget = QWidget()
        req_layout = QVBoxLayout(req_widget)
        req_layout.setContentsMargins(4, 0, 4, 0)
        req_layout.setSpacing(4)

        req_lbl = QLabel("Request Snippet:")
        req_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        req_layout.addWidget(req_lbl)

        self.request_view = QPlainTextEdit()
        self.request_view.setReadOnly(True)
        self.request_view.setFont(QFont("Monospace", 10))
        self.request_view.setStyleSheet(
            f"background: {COLOR_DARK_BG}; color: #9cdcfe; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"font-size: 11px; padding: 4px;"
        )
        req_layout.addWidget(self.request_view)
        h_split.addWidget(req_widget)

        # Right pane – Response Snippet
        resp_widget = QWidget()
        resp_layout = QVBoxLayout(resp_widget)
        resp_layout.setContentsMargins(4, 0, 0, 0)
        resp_layout.setSpacing(4)

        resp_lbl = QLabel("Response Snippet:")
        resp_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        resp_layout.addWidget(resp_lbl)

        self.response_view = QPlainTextEdit()
        self.response_view.setReadOnly(True)
        self.response_view.setFont(QFont("Monospace", 10))
        self.response_view.setStyleSheet(
            f"background: {COLOR_DARK_BG}; color: #ce9178; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"font-size: 11px; padding: 4px;"
        )
        resp_layout.addWidget(self.response_view)
        h_split.addWidget(resp_widget)

        h_split.setSizes([360, 400, 400])
        layout.addWidget(h_split, stretch=1)

        self._set_enabled(False)

    def _set_enabled(self, on: bool):
        for w in (self.status_combo, self.priority_combo,
                  self.notes_edit, self.save_note_btn):
            w.setEnabled(on)

    def load_entry(self, entry: Dict):
        self._current_entry = entry
        url = entry.get("url", "")
        method = entry.get("method", "GET")
        self.header_lbl.setText(f"[{method}]  {url}")
        sc = entry.get("status_code", "")
        added = entry.get("added", "")
        updated = entry.get("updated", "")
        last_tested = entry.get("last_tested", "")
        tested_str = f"   |   Tested: {last_tested}" if last_tested else ""
        self.meta_lbl.setText(
            f"Status Code: {sc or '—'}   |   Added: {added}   |   Updated: {updated}{tested_str}"
        )

        s = entry.get("status", "New")
        self.status_combo.blockSignals(True)
        idx = self.status_combo.findText(s)
        if idx >= 0:
            self.status_combo.setCurrentIndex(idx)
        self.status_combo.blockSignals(False)

        p = entry.get("priority", PRIORITIES[2])
        self.priority_combo.blockSignals(True)
        idx = self.priority_combo.findText(p)
        if idx >= 0:
            self.priority_combo.setCurrentIndex(idx)
        self.priority_combo.blockSignals(False)

        tags = entry.get("tags", [])
        self.tags_lbl.setText("🏷  " + "  •  ".join(tags) if tags else "No tags")

        params = entry.get("params", [])
        self.params_lbl.setText("⚙  Params: " + ", ".join(params) if params else "")

        # Auth context toggles
        auth_tested = entry.get("auth_tested", [])
        for role, btn in self._auth_role_lbls.items():
            btn.blockSignals(True)
            btn.setChecked(role in auth_tested)
            btn.blockSignals(False)

        # Pin / Retest indicators
        self._pin_indicator.setVisible(entry.get("pinned", False))
        self._retest_indicator.setVisible(entry.get("needs_retest", False))

        self.notes_edit.setPlainText(entry.get("notes", ""))
        self.request_view.setPlainText(entry.get("request_snippet", ""))
        self.response_view.setPlainText(entry.get("response_snippet", ""))

        self._set_enabled(True)

    def clear(self):
        self._current_entry = None
        self.header_lbl.setText("— No entry selected —")
        self.meta_lbl.setText("")
        self.tags_lbl.setText("")
        self.params_lbl.setText("")
        for btn in self._auth_role_lbls.values():
            btn.blockSignals(True)
            btn.setChecked(False)
            btn.blockSignals(False)
        self._pin_indicator.setVisible(False)
        self._retest_indicator.setVisible(False)
        self.notes_edit.clear()
        self.request_view.clear()
        self.response_view.clear()
        self._set_enabled(False)

    def _on_auth_toggled(self, role: str, checked: bool):
        if self._current_entry is None:
            return
        auth_tested = list(self._current_entry.get("auth_tested", []))
        if checked and role not in auth_tested:
            auth_tested.append(role)
        elif not checked and role in auth_tested:
            auth_tested.remove(role)
        self._current_entry["auth_tested"] = auth_tested
        self._current_entry["updated"] = _now_str()
        self.save_requested.emit(dict(self._current_entry))

    def _on_save(self):
        if self._current_entry is None:
            return
        updated = dict(self._current_entry)
        new_status = self.status_combo.currentText()
        updated["status"]   = new_status
        updated["priority"] = self.priority_combo.currentText()
        updated["notes"]    = self.notes_edit.toPlainText().strip()
        updated["updated"]  = _now_str()
        if new_status in ("Testing", "Confirmed Bug"):
            updated["last_tested"] = _now_str()
        self.save_requested.emit(updated)


# ─────────────────────────────────────────────────────────────────────────────
# Main Attack Surface Tab
# ─────────────────────────────────────────────────────────────────────────────

class AttackSurfaceTab(QWidget):
    """
    Professional tab for tracking the attack surface
    discovered during manual web-application analysis.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._main_window = parent
        self._entries: List[Dict] = []          # in-memory list
        self._filtered: List[Dict] = []         # after filter
        self._flows: List[Dict] = []            # vulnerability flow chains
        self._flow_group_mode: bool = False     # group table rows by flow
        self._table_rows: List[Dict] = []       # rendered rows (entries + flow headers)
        self._project_dir: Optional[str] = None
        self._save_timer = QTimer()
        self._save_timer.setSingleShot(True)
        self._save_timer.timeout.connect(self._save)
        self._trash: List[Dict] = []            # undo buffer (last 20 deletes)
        self._focus_mode: bool = False          # hide Done/False Positive when True
        self._sort_col: int = -1
        self._sort_asc: bool = True
        self._known_hosts: List[str] = []       # for host filter
        self._build_ui()
        self._apply_style()

    # ── Persistence ────────────────────────────────────────────────────────

    @property
    def _storage_file(self) -> str:
        if self._project_dir:
            return os.path.join(self._project_dir, "attack_surface.json")
        return os.path.join(os.path.expanduser("~"), ".config", "HackRecon", "attack_surface.json")

    @property
    def _flows_file(self) -> str:
        if self._project_dir:
            return os.path.join(self._project_dir, "attack_surface_flows.json")
        return os.path.join(os.path.expanduser("~"), ".config", "HackRecon", "attack_surface_flows.json")

    def set_project_dir(self, project_dir: str):
        self._project_dir = project_dir
        os.makedirs(project_dir, exist_ok=True)
        self._load()
        self._load_flows()
        self._apply_filters()

    def _load(self):
        path = self._storage_file
        if not os.path.exists(path):
            return
        # Auto-backup before loading (protects against corruption / accidental clear)
        backup = path.replace(".json", ".backup.json")
        try:
            shutil.copy2(path, backup)
        except Exception:
            pass
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self._entries = data
                # Migrate: ensure every entry has a valid UUID
                for ep in self._entries:
                    if not ep.get("id"):
                        ep["id"] = str(uuid.uuid4())
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] load error: {e}")

    def _save(self):
        path = self._storage_file
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._entries, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] save error: {e}")
        self._save_flows()

    def _load_flows(self):
        path = self._flows_file
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                self._flows = data
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] load flows error: {e}")

    def _save_flows(self):
        path = self._flows_file
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._flows, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] save flows error: {e}")

    def _schedule_save(self):
        self._save_timer.start(800)

    def save(self):
        """Immediately flush any pending save (called on app close)."""
        if self._save_timer.isActive():
            self._save_timer.stop()
        self._save()

    # ── Style ──────────────────────────────────────────────────────────────

    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
            }}
            QLabel {{ color: {COLOR_TEXT}; font-size: 11px; }}
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                gridline-color: {COLOR_BORDER};
                border: none;
                font-size: 11px;
                selection-background-color: #2a4a6b;
            }}
            QTableWidget::item {{ padding: 4px 6px; }}
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {{
                background-color: #2a4a6b;
                color: {COLOR_TEXT_BRIGHT};
            }}
            QHeaderView::section {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT_MUTED};
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 5px 8px;
                font-size: 11px;
                font-weight: 600;
            }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 11px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton#add_btn {{
                background-color: {COLOR_ACCENT};
                border: none; font-weight: 600;
            }}
            QPushButton#add_btn:hover {{ background-color: #7a9a69; }}
            QLineEdit, QComboBox {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 4px 6px;
                font-size: 11px;
            }}
            QLineEdit:focus {{ border: 1px solid {COLOR_ACCENT}; }}
            QComboBox::drop-down {{ border: none; }}
            QFrame#sep {{
                color: {COLOR_BORDER};
            }}
        """)

    # ── UI build ───────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top toolbar
        toolbar = self._build_toolbar()
        root.addWidget(toolbar)

        # ── Filter bar
        filter_bar = self._build_filter_bar()
        root.addWidget(filter_bar)

        # ── Stats strip
        self.stats_bar = self._build_stats_bar()
        root.addWidget(self.stats_bar)

        # ── Splitter: table (top) | detail panel (bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(4)

        self.table = self._build_table()
        splitter.addWidget(self.table)

        self.detail_panel = AttackSurfaceDetailPanel()
        self.detail_panel.save_requested.connect(self._on_detail_save)
        self.detail_panel.setMinimumHeight(200)
        splitter.addWidget(self.detail_panel)

        splitter.setSizes([480, 260])
        root.addWidget(splitter, stretch=1)

    # ── Toolbar ────────────────────────────────────────────────────────────

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet(f"background-color: {COLOR_CARD_BG};")
        bar.setFixedHeight(48)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(8)

        title = QLabel(" Attack Surface")
        title.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-size: 14px; font-weight: 700;"
        )
        layout.addWidget(title)
        layout.addStretch()

        add_btn = QPushButton("＋  Add Entry")
        add_btn.setObjectName("add_btn")
        add_btn.setFixedHeight(32)
        add_btn.setToolTip("Add a new attack surface entry (Ctrl+N)")
        add_btn.clicked.connect(self.add_entry)
        add_btn.setShortcut(QKeySequence("Ctrl+N"))
        layout.addWidget(add_btn)

        bulk_btn = QPushButton("⬆  Bulk Import")
        bulk_btn.setFixedHeight(32)
        bulk_btn.setToolTip("Import multiple URLs at once")
        bulk_btn.clicked.connect(self.bulk_import)
        layout.addWidget(bulk_btn)

        # T1-2: bulk actions on selected rows
        self._bulk_act_btn = QPushButton("☰  Bulk Actions")
        self._bulk_act_btn.setFixedHeight(32)
        self._bulk_act_btn.setToolTip("Apply action to all selected rows")
        self._bulk_act_btn.clicked.connect(self._show_bulk_actions_menu)
        layout.addWidget(self._bulk_act_btn)

        export_btn = QPushButton("⤓  Export")
        export_btn.setFixedHeight(32)
        export_btn.setToolTip("Export attack surface entries")
        export_btn.clicked.connect(self._show_export_menu)
        layout.addWidget(export_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setFixedHeight(24)
        sep.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep)

        self._focus_btn = QPushButton("  Active Only")
        self._focus_btn.setFixedHeight(32)
        self._focus_btn.setCheckable(True)
        self._focus_btn.setToolTip("Hide Done and False Positive entries")
        self._focus_btn.toggled.connect(self._toggle_focus_mode)
        layout.addWidget(self._focus_btn)

        self._undo_btn = QPushButton("↩  Undo")
        self._undo_btn.setFixedHeight(32)
        self._undo_btn.setToolTip("Restore last deleted entry")
        self._undo_btn.setEnabled(False)
        self._undo_btn.clicked.connect(self._undo_delete)
        layout.addWidget(self._undo_btn)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.VLine)
        sep2.setFixedHeight(24)
        sep2.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep2)

        # ── Flow group toggle + manage
        self._flow_btn = QPushButton("⛓  Flow View")
        self._flow_btn.setFixedHeight(32)
        self._flow_btn.setCheckable(True)
        self._flow_btn.setToolTip(
            "Toggle flow grouping — endpoints grouped by vulnerability chain"
        )
        self._flow_btn.toggled.connect(self._toggle_flow_mode)
        layout.addWidget(self._flow_btn)

        manage_flows_btn = QPushButton("  Manage Flows")
        manage_flows_btn.setFixedHeight(32)
        manage_flows_btn.setToolTip("Create, edit, or delete vulnerability flows")
        manage_flows_btn.clicked.connect(self._manage_flows)
        layout.addWidget(manage_flows_btn)

        sep3 = QFrame()
        sep3.setFrameShape(QFrame.VLine)
        sep3.setFixedHeight(24)
        sep3.setStyleSheet(f"color: {COLOR_BORDER};")
        layout.addWidget(sep3)

        clear_btn = QPushButton("🗑  Clear All")
        clear_btn.setFixedHeight(32)
        clear_btn.setToolTip("Delete all entries")
        clear_btn.clicked.connect(self._clear_all)
        layout.addWidget(clear_btn)

        return bar

    # ── Filter bar ─────────────────────────────────────────────────────────

    def _build_filter_bar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; "
            f"border-bottom: 1px solid {COLOR_BORDER};"
        )
        bar.setFixedHeight(42)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(8)

        lbl = QLabel("Filter:")
        lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        layout.addWidget(lbl)

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Search URL, tags, notes…")
        self.search_edit.setFixedHeight(28)
        self.search_edit.setMinimumWidth(220)
        self.search_edit.textChanged.connect(self._apply_filters)
        layout.addWidget(self.search_edit)

        self.status_filter = QComboBox()
        self.status_filter.addItem("All Statuses")
        self.status_filter.addItems(STATUSES)
        self.status_filter.setFixedHeight(28)
        self.status_filter.currentIndexChanged.connect(self._apply_filters)
        layout.addWidget(self.status_filter)

        self.priority_filter = QComboBox()
        self.priority_filter.addItem("All Priorities")
        self.priority_filter.addItems(PRIORITIES)
        self.priority_filter.setFixedHeight(28)
        self.priority_filter.currentIndexChanged.connect(self._apply_filters)
        layout.addWidget(self.priority_filter)

        self.method_filter = QComboBox()
        self.method_filter.addItem("All Methods")
        self.method_filter.addItems(METHODS)
        self.method_filter.setFixedHeight(28)
        self.method_filter.currentIndexChanged.connect(self._apply_filters)
        layout.addWidget(self.method_filter)

        self.tag_filter = QComboBox()
        self.tag_filter.addItem("All Tags")
        self.tag_filter.addItems(BEHAVIOUR_TAGS)
        self.tag_filter.setFixedHeight(28)
        self.tag_filter.currentIndexChanged.connect(self._apply_filters)
        layout.addWidget(self.tag_filter)

        # T3-13: Host/domain filter
        self.host_filter = QComboBox()
        self.host_filter.addItem("All Hosts")
        self.host_filter.setFixedHeight(28)
        self.host_filter.setMinimumWidth(140)
        self.host_filter.currentIndexChanged.connect(self._apply_filters)
        layout.addWidget(self.host_filter)

        reset_btn = QPushButton("✕ Reset")
        reset_btn.setFixedHeight(26)
        reset_btn.setStyleSheet(
            f"background: transparent; color: {COLOR_TEXT_MUTED}; "
            f"border: none; font-size: 11px;"
        )
        reset_btn.clicked.connect(self._reset_filters)
        layout.addWidget(reset_btn)

        layout.addStretch()
        return bar

    # ── Stats bar ──────────────────────────────────────────────────────────

    def _build_stats_bar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet(
            f"background-color: {COLOR_DARK_BG}; "
            f"border-bottom: 1px solid {COLOR_BORDER};"
        )
        bar.setFixedHeight(32)
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 4, 14, 4)
        layout.setSpacing(18)

        self.stat_total   = QLabel("Total: 0")
        self.stat_new     = QLabel("New: 0")
        self.stat_testing = QLabel("Testing: 0")
        self.stat_bug     = QLabel("Confirmed Bug: 0")
        self.stat_done    = QLabel("Done: 0")
        self.stat_p1      = QLabel("P1: 0")
        self.stat_p2      = QLabel("P2: 0")
        self.stat_showing = QLabel("Showing: 0")

        for lbl, color in [
            (self.stat_total,   COLOR_TEXT_MUTED),
            (self.stat_new,     COLOR_INFO),
            (self.stat_testing, COLOR_WARNING),
            (self.stat_bug,     COLOR_CRITICAL),
            (self.stat_done,    COLOR_SUCCESS),
            (self.stat_p1,      COLOR_CRITICAL),
            (self.stat_p2,      COLOR_HIGH),
            (self.stat_showing, COLOR_TEXT_MUTED),
        ]:
            lbl.setStyleSheet(f"color: {color}; font-size: 11px;")
            layout.addWidget(lbl)

        layout.addStretch()
        return bar

    # ── Table ──────────────────────────────────────────────────────────────

    def _build_table(self) -> QTableWidget:
        t = QTableWidget()
        t.setColumnCount(len(TABLE_COLS))
        t.setHorizontalHeaderLabels(TABLE_COLS)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        hdr = t.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setSortIndicatorShown(True)
        hdr.sectionClicked.connect(self._on_sort)
        hdr.setSectionsMovable(False)
        hdr.setMinimumSectionSize(30)
        t.verticalHeader().setVisible(False)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        # Multi-row selection (T1-2)
        t.setSelectionMode(QAbstractItemView.ExtendedSelection)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setAlternatingRowColors(False)
        t.setShowGrid(True)
        t.setWordWrap(False)
        t.setSortingEnabled(False)
        # Never scroll horizontally — table always fits the window width
        t.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Default column widths
        col_widths = {
            "⚲":            28,
            "#":             36,
            "Priority":      110,
            "Method":        64,
            "Status Code":   86,
            "R":             28,
            "Status":        110,
            "Behaviour Tags":170,
            "Auth":          72,
            "Note Preview":  160,
            "Source":        90,
            "Added":         115,
            "↺":             28,
        }
        url_col = COL_IDX["URL / Path"]
        for col, name in enumerate(TABLE_COLS):
            if col == url_col:
                hdr.setSectionResizeMode(col, QHeaderView.Stretch)
            elif name in ("R", "⚲", "↺"):
                hdr.setSectionResizeMode(col, QHeaderView.Fixed)
                t.setColumnWidth(col, col_widths.get(name, 28))
            else:
                hdr.setSectionResizeMode(col, QHeaderView.Interactive)
                t.setColumnWidth(col, col_widths.get(name, 100))

        t.itemSelectionChanged.connect(self._on_selection_changed)
        t.cellClicked.connect(self._on_cell_clicked)
        t.doubleClicked.connect(self._on_double_click)
        t.setContextMenuPolicy(Qt.CustomContextMenu)
        t.customContextMenuRequested.connect(self._on_context_menu)

        return t

    # ── Table population ───────────────────────────────────────────────────

    def _apply_filters(self):
        """Single filter + sort + render pipeline. Source of truth for table state."""
        q           = self.search_edit.text().strip().lower()
        st_filter   = self.status_filter.currentText()
        pri_filter  = self.priority_filter.currentText()
        meth_filter = self.method_filter.currentText()
        tag_filter  = self.tag_filter.currentText()
        host_filter = self.host_filter.currentText()

        # Rebuild known-hosts list and sync dropdown (T3-13)
        hosts_seen: List[str] = []
        for ep in self._entries:
            h = _extract_host(ep.get("url", ""))
            if h and h not in hosts_seen:
                hosts_seen.append(h)
        hosts_seen.sort()
        if hosts_seen != self._known_hosts:
            self._known_hosts = hosts_seen
            self.host_filter.blockSignals(True)
            prev = self.host_filter.currentText()
            self.host_filter.clear()
            self.host_filter.addItem("All Hosts")
            self.host_filter.addItems(hosts_seen)
            idx = self.host_filter.findText(prev)
            self.host_filter.setCurrentIndex(max(0, idx))
            self.host_filter.blockSignals(False)
            host_filter = self.host_filter.currentText()

        filtered = []
        for ep in self._entries:
            # Focus mode: hide Done and False Positive
            if self._focus_mode and ep.get("status") in ("Done", "False Positive"):
                continue
            if st_filter  != "All Statuses"   and ep.get("status")   != st_filter:
                continue
            if pri_filter != "All Priorities" and ep.get("priority") != pri_filter:
                continue
            if meth_filter != "All Methods"   and ep.get("method")   != meth_filter:
                continue
            if tag_filter != "All Tags"       and tag_filter not in ep.get("tags", []):
                continue
            if host_filter != "All Hosts"     and _extract_host(ep.get("url","")) != host_filter:
                continue
            if q:
                haystack = " ".join([
                    ep.get("url", ""),
                    ep.get("notes", ""),
                    " ".join(ep.get("tags", [])),
                    ep.get("method", ""),
                    ep.get("status", ""),
                    " ".join(ep.get("params", [])),
                    " ".join(ep.get("auth_tested", [])),
                ]).lower()
                if q not in haystack:
                    continue
            filtered.append(ep)

        # Pinned entries always float to top (T3-11)
        pinned   = [e for e in filtered if e.get("pinned")]
        unpinned = [e for e in filtered if not e.get("pinned")]

        # Apply sort on the unpinned portion only (preserves pin-to-top)
        if self._sort_col >= 0:
            key_map = {
                COL_IDX["⚲"]:             lambda e: 0,
                COL_IDX["#"]:              lambda e: 0,
                COL_IDX["Priority"]:       lambda e: e.get("priority", ""),
                COL_IDX["Method"]:         lambda e: e.get("method", ""),
                COL_IDX["URL / Path"]:     lambda e: e.get("url", ""),
                COL_IDX["Status Code"]:    lambda e: str(e.get("status_code", "")),
                COL_IDX["R"]:              lambda e: (0 if e.get("has_response") else 1),
                COL_IDX["Status"]:         lambda e: e.get("status", ""),
                COL_IDX["Behaviour Tags"]: lambda e: " ".join(e.get("tags", [])),
                COL_IDX["Auth"]:           lambda e: " ".join(e.get("auth_tested", [])),
                COL_IDX["Note Preview"]:   lambda e: e.get("notes", ""),
                COL_IDX["Source"]:         lambda e: e.get("source", ""),
                COL_IDX["Added"]:          lambda e: e.get("added", ""),
                COL_IDX["↺"]:             lambda e: 0,
            }
            key_fn = key_map.get(self._sort_col, lambda e: "")
            unpinned.sort(key=key_fn, reverse=not self._sort_asc)

        self._filtered = pinned + unpinned

        # Build display rows (with optional flow-grouping headers)
        if self._flow_group_mode and self._flows:
            self._table_rows = self._build_flow_grouped_rows(self._filtered)
        else:
            self._table_rows = [{"type": "entry", "entry": ep} for ep in self._filtered]

        self.table.setRowCount(0)
        self.table.setRowCount(len(self._table_rows))

        meth_colors = {
            "GET": "#6A8759", "POST": "#CC7832", "PUT": "#9876AA",
            "PATCH": "#FFC66D", "DELETE": "#FF6B6B",
            "HEAD": "#6897BB", "OPTIONS": "#808080",
        }

        for row, tr in enumerate(self._table_rows):
            if tr["type"] == "flow_header":
                self._render_flow_header_row(row, tr)
                continue

            ep = tr["entry"]
            _flow_tint = tr.get("flow_tint")
            is_pinned    = ep.get("pinned", False)
            needs_retest = ep.get("needs_retest", False)

            # Pin indicator column (T3-11)
            pin_item = QTableWidgetItem("⚲" if is_pinned else "")
            pin_item.setTextAlignment(Qt.AlignCenter)
            pin_item.setToolTip("Pinned (click to toggle)" if is_pinned else "Click to pin")
            self.table.setItem(row, COL_IDX["⚲"], pin_item)

            # #
            num_item = QTableWidgetItem(str(row + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            num_item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
            self.table.setItem(row, COL_IDX["#"], num_item)

            # Priority
            pri = ep.get("priority", PRIORITIES[2])
            pri_item = QTableWidgetItem(pri)
            pri_item.setTextAlignment(Qt.AlignCenter)
            pri_color = PRIORITY_COLOR.get(pri, COLOR_TEXT)
            pri_item.setForeground(QBrush(QColor(pri_color)))
            pri_item.setFont(QFont("", -1, QFont.Bold))
            self.table.setItem(row, COL_IDX["Priority"], pri_item)

            # Method
            meth = ep.get("method", "GET")
            meth_item = QTableWidgetItem(meth)
            meth_item.setTextAlignment(Qt.AlignCenter)
            meth_item.setForeground(QBrush(QColor(meth_colors.get(meth, COLOR_TEXT))))
            meth_item.setFont(QFont("Monospace", 9, QFont.Bold))
            self.table.setItem(row, COL_IDX["Method"], meth_item)

            # URL — host colour-coded by domain (T3-13)
            host = _extract_host(ep.get("url", ""))
            host_hue_map = {}
            for i, h in enumerate(self._known_hosts):
                host_hue_map[h] = i
            url_item = QTableWidgetItem(_short_url(ep.get("url", ""), 90))
            url_item.setToolTip(ep.get("url", ""))
            url_item.setForeground(QBrush(QColor(COLOR_TEXT_BRIGHT)))
            url_item.setFont(QFont("Monospace", 9))
            self.table.setItem(row, COL_IDX["URL / Path"], url_item)

            # Status code
            sc = ep.get("status_code", "")
            sc_str = str(sc)
            sc_item = QTableWidgetItem(sc_str)
            sc_item.setTextAlignment(Qt.AlignCenter)
            sc_color = COLOR_SUCCESS  if sc_str.startswith("2") else \
                       COLOR_WARNING  if sc_str.startswith("3") else \
                       COLOR_CRITICAL if sc_str.startswith(("4", "5")) else COLOR_TEXT
            sc_item.setForeground(QBrush(QColor(sc_color)))
            self.table.setItem(row, COL_IDX["Status Code"], sc_item)

            # Response indicator
            has_resp = ep.get("has_response", False)
            r_item = QTableWidgetItem("●" if has_resp else "·")
            r_item.setTextAlignment(Qt.AlignCenter)
            r_item.setForeground(QBrush(QColor(COLOR_SUCCESS if has_resp else COLOR_TEXT_MUTED)))
            r_item.setToolTip("Response captured" if has_resp else "No response stored")
            self.table.setItem(row, COL_IDX["R"], r_item)

            # Status badge — T1-4: tooltip hints click-to-cycle
            status = ep.get("status", "New")
            st_item = QTableWidgetItem(f"  {status}  ")
            st_item.setTextAlignment(Qt.AlignCenter)
            bg, fg = STATUS_COLOR.get(status, ("#333", "#fff"))
            st_item.setBackground(QBrush(QColor(bg)))
            st_item.setForeground(QBrush(QColor(fg)))
            self.table.setItem(row, COL_IDX["Status"], st_item)

            # Tags
            tags = ep.get("tags", [])
            tags_str = " • ".join(tags[:4])
            if len(tags) > 4:
                tags_str += f"  +{len(tags)-4}"
            tags_item = QTableWidgetItem(tags_str)
            tags_item.setForeground(QBrush(QColor(COLOR_ACCENT)))
            tags_item.setToolTip(", ".join(tags))
            self.table.setItem(row, COL_IDX["Behaviour Tags"], tags_item)

            # Auth context (T1-3)
            auth_tested = ep.get("auth_tested", [])
            auth_str = "/".join(r[0] for r in auth_tested) if auth_tested else "—"
            auth_item = QTableWidgetItem(auth_str)
            auth_item.setTextAlignment(Qt.AlignCenter)
            auth_color = COLOR_SUCCESS if len(auth_tested) == len(AUTH_ROLES) else \
                         COLOR_WARNING if auth_tested else COLOR_TEXT_MUTED
            auth_item.setForeground(QBrush(QColor(auth_color)))
            auth_item.setToolTip("Tested: " + ", ".join(auth_tested) if auth_tested else "No auth contexts tested")
            self.table.setItem(row, COL_IDX["Auth"], auth_item)

            # Note preview
            note = ep.get("notes", "").replace("\n", " ")
            note_item = QTableWidgetItem(note[:80] + ("…" if len(note) > 80 else ""))
            note_item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
            note_item.setToolTip(ep.get("notes", ""))
            self.table.setItem(row, COL_IDX["Note Preview"], note_item)

            # Source
            source = ep.get("source", "Manual")
            src_item = QTableWidgetItem(source)
            src_item.setTextAlignment(Qt.AlignCenter)
            src_item.setForeground(QBrush(QColor(_SOURCE_COLORS.get(source, COLOR_TEXT_MUTED))))
            src_item.setToolTip(f"Added from: {source}")
            self.table.setItem(row, COL_IDX["Source"], src_item)

            # Added
            added_item = QTableWidgetItem(ep.get("added", ""))
            added_item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
            added_item.setTextAlignment(Qt.AlignCenter)
            self.table.setItem(row, COL_IDX["Added"], added_item)

            # Needs-Retest indicator (T3-12)
            rt_item = QTableWidgetItem("↺" if needs_retest else "")
            rt_item.setTextAlignment(Qt.AlignCenter)
            rt_item.setToolTip("Needs Retest (click to toggle)" if needs_retest else "Click to flag for retest")
            rt_item.setForeground(QBrush(QColor(COLOR_CRITICAL if needs_retest else COLOR_TEXT_MUTED)))
            self.table.setItem(row, COL_IDX["↺"], rt_item)

            self.table.setRowHeight(row, 28)

            # Flow group row tinting (applied before pin/retest overlays)
            if _flow_tint and not is_pinned and not needs_retest:
                for col in range(len(TABLE_COLS)):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(QBrush(QColor(_flow_tint)))

            # Highlight pinned row (T3-11)
            if is_pinned:
                for col in range(len(TABLE_COLS)):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(QBrush(QColor("#2a3a1a")))

            # Tint rows needing retest (T3-12)
            if needs_retest and not is_pinned:
                for col in range(len(TABLE_COLS)):
                    item = self.table.item(row, col)
                    if item:
                        item.setBackground(QBrush(QColor("#2a1a1a")))

        self._update_stats()

    def _update_stats(self):
        counts = {s: 0 for s in STATUSES}
        p1 = p2 = 0
        for ep in self._entries:
            s = ep.get("status", "New")
            counts[s] = counts.get(s, 0) + 1
            pri = ep.get("priority", "")
            if "P1" in pri:
                p1 += 1
            elif "P2" in pri:
                p2 += 1
        self.stat_total.setText(f"Total: {len(self._entries)}")
        self.stat_new.setText(f"New: {counts.get('New', 0)}")
        self.stat_testing.setText(f"Testing: {counts.get('Testing', 0)}")
        self.stat_bug.setText(f"Confirmed Bug: {counts.get('Confirmed Bug', 0)}")
        self.stat_done.setText(f"Done: {counts.get('Done', 0)}")
        self.stat_p1.setText(f"P1: {p1}")
        self.stat_p2.setText(f"P2: {p2}")
        self.stat_showing.setText(f"Showing: {len(self._filtered)}")

        self.stat_total.setText(f"Total: {len(self._entries)}")
        self.stat_new.setText(f"New: {counts.get('New', 0)}")
        self.stat_testing.setText(f"Testing: {counts.get('Testing', 0)}")
        self.stat_bug.setText(f"Confirmed Bug: {counts.get('Confirmed Bug', 0)}")
        self.stat_done.setText(f"Done: {counts.get('Done', 0)}")
        self.stat_p1.setText(f"P1: {p1}")
        self.stat_p2.setText(f"P2: {p2}")
        self.stat_showing.setText(f"Showing: {len(self._filtered)}")

    # ── Flow grouping helpers ───────────────────────────────────────────────

    def _build_flow_grouped_rows(self, filtered: List[Dict]) -> List[Dict]:
        """Return a mixed list of flow-header dicts and entry dicts for table rendering."""
        rows: List[Dict] = []
        entry_map = {ep["id"]: ep for ep in filtered}
        used_ids: set = set()

        for i, flow in enumerate(self._flows):
            flow_entries = []
            for eid in flow.get("entry_ids", []):
                ep = entry_map.get(eid)
                if ep:
                    flow_entries.append(ep)
                    used_ids.add(eid)
            if not flow_entries:
                continue  # skip flows with no visible entries after current filter

            tint, accent = _FLOW_TINTS[i % len(_FLOW_TINTS)]
            rows.append({
                "type":   "flow_header",
                "flow":   flow,
                "tint":   tint,
                "accent": accent,
            })
            for ep in flow_entries:
                rows.append({
                    "type":         "entry",
                    "entry":        ep,
                    "flow_tint":    tint,
                    "flow_accent":  accent,
                    "flow_id":      flow["id"],
                })

        # Entries not belonging to any flow
        ungrouped = [ep for ep in filtered if ep["id"] not in used_ids]
        if ungrouped:
            if rows:
                rows.append({
                    "type":   "flow_header",
                    "flow":   {"name": "Ungrouped Endpoints", "type": "", "entry_ids": []},
                    "tint":   COLOR_DARK_BG,
                    "accent": COLOR_TEXT_MUTED,
                })
            for ep in ungrouped:
                rows.append({"type": "entry", "entry": ep})

        return rows

    def _render_flow_header_row(self, row: int, tr: Dict):
        """Render a single flow-header row spanning all columns."""
        flow   = tr["flow"]
        tint   = tr["tint"]
        accent = tr["accent"]
        ftype  = flow.get("type", "")
        name   = flow.get("name", "")
        entry_ids = flow.get("entry_ids", [])
        n_ids  = len(entry_ids)
        type_str = f"  [{ftype}]" if ftype else ""
        desc = flow.get("description", "")
        desc_str = f"   —   {desc[:80]}" if desc else ""

        # Build compact inline step summary:  GET /login → POST /login
        entry_map = {ep["id"]: ep for ep in self._entries}
        step_parts = []
        for eid in entry_ids:
            ep = entry_map.get(eid)
            if ep:
                m = ep.get("method", "?")
                u = ep.get("url", "")
                # strip scheme+host for brevity
                try:
                    from urllib.parse import urlparse as _up2
                    _p = _up2(u)
                    short = (_p.path or u) + ("?" + _p.query[:30] if _p.query else "")
                except Exception:
                    short = u
                params = ep.get("params", [])
                param_hint = f" ⚙[{', '.join(params[:2])}]" if params else ""
                step_parts.append(f"{m} {short}{param_hint}")
        steps_inline = "  →  ".join(step_parts) if step_parts else ""
        if steps_inline:
            steps_inline = f"   |   {steps_inline}"

        text = f"  ⛓  {name}{type_str}   {n_ids} step{'s' if n_ids != 1 else ''}{desc_str}{steps_inline}"

        item = QTableWidgetItem(text)
        item.setBackground(QBrush(QColor(tint)))
        item.setForeground(QBrush(QColor(accent)))
        item.setFont(QFont("", -1, QFont.Bold))
        item.setFlags(Qt.ItemIsEnabled)          # not selectable / not editable

        # Rich tooltip: list each step on its own line
        tip_lines = [f"⛓  {name}  |  Type: {ftype or '—'}"]
        if flow.get("description"):
            tip_lines.append(flow["description"])
        tip_lines.append("")
        for i, eid in enumerate(entry_ids, 1):
            ep = entry_map.get(eid)
            if ep:
                m = ep.get("method", "?")
                u = ep.get("url", "")
                params = ep.get("params", [])
                notes  = ep.get("notes", "")
                p_str  = f"  ⚙ [{', '.join(params)}]" if params else ""
                n_str  = f"  — {notes[:80].replace(chr(10),' ')}" if notes else ""
                tip_lines.append(f"  {i}.  [{m}]  {u}{p_str}{n_str}")
        tip_lines.append("")
        tip_lines.append("Double-click to edit  ·  Right-click for options")
        item.setToolTip("\n".join(tip_lines))

        self.table.setItem(row, 0, item)
        self.table.setSpan(row, 0, 1, len(TABLE_COLS))
        self.table.setRowHeight(row, 30)

    def _entry_at_row(self, row: int) -> Optional[Dict]:
        """Return the entry dict for a table row, or None if it is a flow header."""
        if row < 0 or row >= len(self._table_rows):
            return None
        tr = self._table_rows[row]
        return tr["entry"] if tr["type"] == "entry" else None

    def _flow_at_row(self, row: int) -> Optional[Dict]:
        """Return the flow dict if the table row is a flow-header, else None."""
        if row < 0 or row >= len(self._table_rows):
            return None
        tr = self._table_rows[row]
        return tr.get("flow") if tr["type"] == "flow_header" else None

    # ── Flow mode toggle ───────────────────────────────────────────────────

    def _toggle_flow_mode(self, checked: bool):
        self._flow_group_mode = checked
        self._flow_btn.setStyleSheet(
            f"background: {COLOR_ACCENT}; color: #fff; border: none; font-weight: 600;"
            if checked else ""
        )
        self._apply_filters()

    # ── Flow management ────────────────────────────────────────────────────

    def _manage_flows(self):
        """Open a simple dialog listing all flows with options to create / edit / delete."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Manage Vulnerability Flows")
        dlg.setMinimumSize(640, 420)
        dlg.setStyleSheet(f"""
            QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
            QLabel  {{ color: {COLOR_TEXT}; font-size: 11px; }}
            QListWidget {{
                background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px; font-size: 11px;
            }}
            QListWidget::item {{ padding: 6px 8px; }}
            QListWidget::item:selected {{ background-color: #2a4a6b; color: white; }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                padding: 5px 14px; font-size: 11px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QPushButton#new_btn {{
                background-color: {COLOR_ACCENT}; border: none; font-weight: 600;
            }}
        """)

        lay = QVBoxLayout(dlg)
        lay.setContentsMargins(14, 14, 14, 14)
        lay.setSpacing(8)

        hdr = QLabel(
            f"<b>Vulnerability Flows</b> — {len(self._flows)} defined  "
            f"<span style='color:{COLOR_TEXT_MUTED};font-size:10px;'>"
            "(group endpoints together to describe a multi-step flaw)</span>"
        )
        hdr.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-size: 12px;")
        lay.addWidget(hdr)

        flow_list = QListWidget()
        for i, f in enumerate(self._flows):
            tint, accent = _FLOW_TINTS[i % len(_FLOW_TINTS)]
            n = len(f.get("entry_ids", []))
            item = QListWidgetItem(
                f"  ⛓  {f['name']}  [{f.get('type','')}]  —  {n} endpoint(s)"
            )
            item.setData(Qt.UserRole, f["id"])
            item.setForeground(QBrush(QColor(accent)))
            if f.get("description"):
                item.setToolTip(f.get("description"))
            flow_list.addItem(item)
        lay.addWidget(flow_list, stretch=1)

        btn_row = QHBoxLayout()
        new_btn  = QPushButton("＋  New Flow")
        new_btn.setObjectName("new_btn")
        edit_btn = QPushButton("  Edit")
        del_btn  = QPushButton("🗑  Delete")
        btn_row.addWidget(new_btn)
        btn_row.addWidget(edit_btn)
        btn_row.addWidget(del_btn)
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)

        def _new():
            subdlg = FlowDialog(all_entries=self._entries, parent=dlg)
            if subdlg.exec_() == QDialog.Accepted:
                flow = subdlg.get_flow()
                self._flows.append(flow)
                self._save_flows()
                self._apply_filters()
                item = QListWidgetItem(
                    f"  ⛓  {flow['name']}  [{flow.get('type','')}]  —  "
                    f"{len(flow.get('entry_ids',[]))} endpoint(s)"
                )
                item.setData(Qt.UserRole, flow["id"])
                tint, accent = _FLOW_TINTS[(flow_list.count()) % len(_FLOW_TINTS)]
                item.setForeground(QBrush(QColor(accent)))
                flow_list.addItem(item)

        def _edit():
            sel = flow_list.currentItem()
            if sel is None:
                QMessageBox.information(dlg, "Edit Flow", "Select a flow first.")
                return
            fid = sel.data(Qt.UserRole)
            flow = next((f for f in self._flows if f["id"] == fid), None)
            if not flow:
                return
            subdlg = FlowDialog(flow=flow, all_entries=self._entries, parent=dlg)
            if subdlg.exec_() == QDialog.Accepted:
                updated = subdlg.get_flow()
                for i, f in enumerate(self._flows):
                    if f["id"] == fid:
                        self._flows[i] = updated
                        break
                self._save_flows()
                self._apply_filters()
                sel.setText(
                    f"  ⛓  {updated['name']}  [{updated.get('type','')}]  —  "
                    f"{len(updated.get('entry_ids',[]))} endpoint(s)"
                )

        def _delete():
            sel = flow_list.currentItem()
            if sel is None:
                QMessageBox.information(dlg, "Delete Flow", "Select a flow first.")
                return
            fid = sel.data(Qt.UserRole)
            flow = next((f for f in self._flows if f["id"] == fid), None)
            if not flow:
                return
            if QMessageBox.question(
                dlg, "Delete Flow",
                f"Delete flow \"{flow['name']}\"?\n"
                "(Entries are kept — only the flow grouping is removed.)",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes:
                self._flows = [f for f in self._flows if f["id"] != fid]
                self._save_flows()
                self._apply_filters()
                flow_list.takeItem(flow_list.row(sel))

        new_btn.clicked.connect(_new)
        edit_btn.clicked.connect(_edit)
        del_btn.clicked.connect(_delete)

        dlg.exec_()

    def _edit_flow(self, flow: Dict):
        """Edit a flow directly (e.g. from double-click on flow header row)."""
        dlg = FlowDialog(flow=flow, all_entries=self._entries, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            updated = dlg.get_flow()
            for i, f in enumerate(self._flows):
                if f["id"] == flow["id"]:
                    self._flows[i] = updated
                    break
            self._save_flows()
            self._apply_filters()

    def _create_flow_from_selection(self, entries: List[Dict]):
        """Create a new flow pre-seeded with the given entries."""
        prefill_ids = [e["id"] for e in entries]
        prefill_flow = {
            "id":         "",
            "name":       "",
            "type":       FLAW_TYPES[0],
            "description":"",
            "entry_ids":  prefill_ids,
            "added":      _now_str(),
            "updated":    _now_str(),
        }
        dlg = FlowDialog(flow=prefill_flow, all_entries=self._entries, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            flow = dlg.get_flow()
            self._flows.append(flow)
            self._save_flows()
            # Auto-enable flow view so user sees the result
            if not self._flow_group_mode:
                self._flow_btn.setChecked(True)  # triggers _toggle_flow_mode
            else:
                self._apply_filters()

    def _add_entry_to_flow(self, entry: Dict, flow: Dict):
        eid = entry["id"]
        if eid not in flow.get("entry_ids", []):
            flow["entry_ids"].append(eid)
            flow["updated"] = _now_str()
            self._save_flows()
            self._apply_filters()

    def _remove_entry_from_flow(self, entry: Dict, flow: Dict):
        eid = entry["id"]
        if eid in flow.get("entry_ids", []):
            flow["entry_ids"].remove(eid)
            flow["updated"] = _now_str()
            self._save_flows()
            self._apply_filters()

    def _on_flow_header_context_menu(self, pos, flow: Dict):
        """Context menu shown when right-clicking on a flow header row."""
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLOR_CARD_BG}; color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER}; padding: 4px;
            }}
            QMenu::item {{ padding: 6px 20px 6px 10px; border-radius: 3px; }}
            QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #fff; }}
            QMenu::separator {{ height: 1px; background: {COLOR_BORDER}; margin: 2px 4px; }}
        """)
        lbl = menu.addAction(f"⛓  {flow['name']}")
        lbl.setEnabled(False)
        menu.addSeparator()
        edit_act = menu.addAction("  Edit Flow")
        del_act  = menu.addAction("🗑  Delete Flow")

        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen == edit_act:
            self._edit_flow(flow)
        elif chosen == del_act:
            if QMessageBox.question(
                self, "Delete Flow",
                f"Delete flow \"{flow['name']}\"?\n"
                "(Entries are kept — only the flow grouping is removed.)",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes:
                self._flows = [f for f in self._flows if f["id"] != flow.get("id")]
                self._save_flows()
                self._apply_filters()

    # ── Sort ───────────────────────────────────────────────────────────────

    def _on_sort(self, col: int):
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._apply_filters()

    # ── Selection ──────────────────────────────────────────────────────────

    def _on_selection_changed(self):
        rows = self.table.selectedItems()
        if not rows:
            self.detail_panel.clear()
            return
        row = self.table.currentRow()
        entry = self._entry_at_row(row)
        if entry:
            self.detail_panel.load_entry(entry)

    def _on_cell_clicked(self, row: int, col: int):
        """Handle single-cell clicks for pin/retest toggles (T3-11/12)."""
        entry = self._entry_at_row(row)
        if entry is None:
            return

        if col == COL_IDX["⚲"]:
            # T3-11: toggle pin
            updated = dict(entry)
            updated["pinned"] = not entry.get("pinned", False)
            updated["updated"] = _now_str()
            self._replace_entry(entry["id"], updated)

        elif col == COL_IDX["↺"]:
            # T3-12: toggle needs-retest
            updated = dict(entry)
            updated["needs_retest"] = not entry.get("needs_retest", False)
            updated["updated"] = _now_str()
            self._replace_entry(entry["id"], updated)

    def _on_double_click(self, index):
        row   = index.row()
        col   = index.column()
        # Double-click on a flow header → edit that flow
        flow = self._flow_at_row(row)
        if flow is not None:
            self._edit_flow(flow)
            return
        entry = self._entry_at_row(row)
        if entry is None:
            return
        # T2-10: double-click Note Preview column → inline note editor
        if col == COL_IDX["Note Preview"]:
            self._inline_edit_note(row, entry)
        else:
            self._edit_entry(entry)

    def _inline_edit_note(self, row: int, entry: Dict):
        """Replace the Note Preview cell with a live QLineEdit for quick note edits (T2-10)."""
        orig_note = entry.get("notes", "")
        editor = QLineEdit(orig_note)
        editor.setStyleSheet(
            f"background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_ACCENT}; font-size: 11px; padding: 2px 4px;"
        )

        def _commit():
            new_note = editor.text().strip()
            self.table.removeCellWidget(row, COL_IDX["Note Preview"])
            if new_note != orig_note:
                updated = dict(entry)
                updated["notes"]   = new_note
                updated["updated"] = _now_str()
                self._replace_entry(entry["id"], updated)

        editor.editingFinished.connect(_commit)
        editor.returnPressed.connect(_commit)
        self.table.setCellWidget(row, COL_IDX["Note Preview"], editor)
        editor.setFocus()
        editor.selectAll()

    # ── CRUD ───────────────────────────────────────────────────────────────

    @staticmethod
    def _entry_sig(e: Dict) -> tuple:
        """Unique signature for an entry — URL + method + sorted params."""
        return (
            e.get("url", "").strip(),
            e.get("method", "GET").upper(),
            tuple(sorted(p.strip().lower() for p in e.get("params", []) if p.strip())),
        )

    def add_entry(self):
        dlg = AttackSurfaceEntryDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            entry = dlg.get_entry()
            # Deduplication check — same URL + method + params
            sig = self._entry_sig(entry)
            existing = next(
                (e for e in self._entries if self._entry_sig(e) == sig),
                None
            )
            if existing:
                reply = QMessageBox.question(
                    self, "Duplicate Entry",
                    f"An entry for [{entry['method']}] {entry['url']}\n"
                    f"with the same parameters already exists. Add anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply != QMessageBox.Yes:
                    return
            self._entries.insert(0, entry)
            self._schedule_save()
            self._apply_filters()
            self.table.selectRow(0)

    def add_from_http_history(self, finding: Dict):
        """
        Add an attack surface entry pre-filled from an HTTP History finding.
        Opens the AttackSurfaceEntryDialog pre-populated so the user can review/edit
        before saving.
        """
        url    = finding.get("url", "").strip()
        method = finding.get("method", "GET").upper()
        sc     = str(finding.get("status", "")).strip()

        # Deduplication check — same URL + method + params
        _prefill_params: List[str] = []
        _prefill_sig = (url, method, tuple(sorted(_prefill_params)))
        existing = next(
            (e for e in self._entries if self._entry_sig(e) == _prefill_sig),
            None
        )
        if existing:
            reply = QMessageBox.question(
                self, "Duplicate Entry",
                f"An entry for [{method}] {url}\nalready exists.\n\n"
                "Add anyway (Yes) or jump to existing entry (No)?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel
            )
            if reply == QMessageBox.No:
                for i, ep in enumerate(self._filtered):
                    if ep.get("id") == existing.get("id"):
                        self.table.selectRow(i)
                        break
                self.detail_panel.load_entry(existing)
                return
            elif reply == QMessageBox.Cancel:
                return

        # Extract request snippet
        req_text = ""
        req_file = finding.get("request_file", "") or finding.get("request_path", "")
        if req_file and os.path.isfile(req_file):
            try:
                with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                    req_text = f.read(2000)
            except Exception:
                pass
        if not req_text:
            req_text = finding.get("request_text", "") or finding.get("request", "")
            if isinstance(req_text, bytes):
                req_text = req_text.decode("utf-8", errors="replace")
            req_text = str(req_text)[:2000]

        # Extract response snippet (Step 9)
        resp_text = ""
        resp_file = finding.get("response_file", "") or finding.get("response_path", "")
        if resp_file and os.path.isfile(resp_file):
            try:
                with open(resp_file, "r", encoding="utf-8", errors="replace") as f:
                    resp_text = f.read(4000)
            except Exception:
                pass
        if not resp_text:
            resp_text = finding.get("response_text", "") or finding.get("response", "")
            if isinstance(resp_text, bytes):
                resp_text = resp_text.decode("utf-8", errors="replace")
            resp_text = str(resp_text)[:4000]

        source = finding.get("source", "HTTP History")

        # Auto-suggest behaviour tags from URL/method heuristics (Step 8)
        suggested_tags = _heuristic_tags(url, method)

        prefill = {
            "id":               "",
            "url":              url,
            "method":           method,
            "status_code":      sc,
            "priority":         PRIORITIES[2],
            "status":           "New",
            "tags":             suggested_tags,
            "params":           [],
            "notes":            "",
            "request_snippet":  req_text,
            "response_snippet": resp_text,
            "has_response":     bool(resp_text),
            "added":            _now_str(),
            "last_tested":      "",
            "source":           source,
        }

        dlg = AttackSurfaceEntryDialog(entry=prefill, parent=self)
        dlg.setWindowTitle(f"Add Entry from {source}")
        if dlg.exec_() == QDialog.Accepted:
            entry = dlg.get_entry()
            entry["source"] = source
            self._entries.insert(0, entry)
            self._schedule_save()
            self._apply_filters()
            self.table.selectRow(0)

    def bulk_import(self):
        dlg = BulkImportDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            entries = dlg.get_entries()
            if not entries:
                QMessageBox.information(self, "Bulk Import", "No valid URLs found.")
                return
            skipped = 0
            for e in entries:
                exists = any(
                    x.get("url") == e["url"] and x.get("method") == e["method"]
                    for x in self._entries
                )
                if exists:
                    skipped += 1
                    continue
                self._entries.insert(0, e)
            self._schedule_save()
            self._apply_filters()
            added = len(entries) - skipped
            msg = f"Imported {added} entr(ies)."
            if skipped:
                msg += f"\nSkipped {skipped} duplicate(s)."
            QMessageBox.information(self, "Bulk Import", msg)

    def _edit_entry(self, entry: Dict):
        dlg = AttackSurfaceEntryDialog(entry=dict(entry), parent=self)
        if dlg.exec_() == QDialog.Accepted:
            updated = dlg.get_entry()
            self._replace_entry(entry["id"], updated)

    def _replace_entry(self, eid: str, updated: Dict):
        for i, ep in enumerate(self._entries):
            if ep.get("id") == eid:
                self._entries[i] = updated
                break
        self._schedule_save()
        self._apply_filters()
        # Refresh detail panel
        for ep in self._filtered:
            if ep.get("id") == eid:
                self.detail_panel.load_entry(ep)
                break

    def _delete_entry(self, entry: Dict):
        eid = entry.get("id")
        self._trash.append(entry)
        if len(self._trash) > 20:
            self._trash = self._trash[-20:]
        self._undo_btn.setEnabled(True)
        self._entries = [e for e in self._entries if e.get("id") != eid]
        self._schedule_save()
        self.detail_panel.clear()
        self._apply_filters()

    def _duplicate_entry(self, entry: Dict):
        new_entry = dict(entry)
        new_entry["id"]      = str(uuid.uuid4())
        new_entry["added"]   = _now_str()
        new_entry["updated"] = _now_str()
        new_entry["status"]  = "New"
        self._entries.insert(0, new_entry)
        self._schedule_save()
        self._apply_filters()

    def _on_detail_save(self, updated: Dict):
        self._replace_entry(updated["id"], updated)

    def _undo_delete(self):
        """Restore the last deleted entry from the undo buffer (Step 11)."""
        if not self._trash:
            return
        entry = self._trash.pop()
        self._entries.insert(0, entry)
        self._schedule_save()
        self._apply_filters()
        self.table.selectRow(0)
        self._undo_btn.setEnabled(bool(self._trash))

    def _toggle_focus_mode(self, checked: bool):
        """Hide Done and False Positive entries (Step 10)."""
        self._focus_mode = checked
        self._focus_btn.setStyleSheet(
            f"background: {COLOR_ACCENT}; color: #fff; border: none; font-weight: 600;"
            if checked else ""
        )
        self._apply_filters()

    # ── Filters reset ──────────────────────────────────────────────────────

    def _reset_filters(self):
        self.search_edit.clear()
        self.status_filter.setCurrentIndex(0)
        self.priority_filter.setCurrentIndex(0)
        self.method_filter.setCurrentIndex(0)
        self.tag_filter.setCurrentIndex(0)
        self.host_filter.setCurrentIndex(0)
        if self._focus_mode:
            self._focus_btn.setChecked(False)

    # ── Context menu ───────────────────────────────────────────────────────

    def _get_selected_entries(self) -> List[Dict]:
        """Return all entries for currently selected rows (T1-2)."""
        rows = sorted(set(idx.row() for idx in self.table.selectedIndexes()))
        result = []
        for r in rows:
            ep = self._entry_at_row(r)
            if ep:
                result.append(ep)
        return result

    def _show_bulk_actions_menu(self):
        """Popup for bulk status/priority/delete on multi-selected rows (T1-2)."""
        entries = self._get_selected_entries()
        if not entries:
            QMessageBox.information(self, "Bulk Actions", "Select rows first (Shift/Ctrl+click).")
            return

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLOR_CARD_BG}; color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER}; padding: 4px;
            }}
            QMenu::item {{ padding: 6px 20px 6px 10px; border-radius: 3px; }}
            QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #fff; }}
            QMenu::separator {{ height: 1px; background: {COLOR_BORDER}; margin: 2px 4px; }}
        """)
        lbl = menu.addAction(f"── {len(entries)} rows selected ──")
        lbl.setEnabled(False)
        menu.addSeparator()

        status_menu = menu.addMenu("↺  Set Status →")
        status_acts = {status_menu.addAction(s): s for s in STATUSES}

        pri_menu = menu.addMenu("🎯  Set Priority →")
        pri_acts = {pri_menu.addAction(p): p for p in PRIORITIES}

        menu.addSeparator()
        pin_act    = menu.addAction("⚲  Pin all")
        unpin_act  = menu.addAction("  Unpin all")
        menu.addSeparator()
        retest_act   = menu.addAction("↺  Mark all: Needs Retest")
        unretest_act = menu.addAction("  Clear Retest flag")
        menu.addSeparator()
        create_flow_act = menu.addAction("⛓  Create Flow from Selection")
        menu.addSeparator()
        del_act = menu.addAction(f"🗑️  Delete all {len(entries)}")

        chosen = menu.exec_(self._bulk_act_btn.mapToGlobal(
            self._bulk_act_btn.rect().bottomLeft()
        ))
        if chosen is None:
            return

        now = _now_str()
        if chosen in status_acts:
            new_status = status_acts[chosen]
            for e in entries:
                upd = dict(e)
                upd["status"]  = new_status
                upd["updated"] = now
                if new_status in ("Testing", "Confirmed Bug"):
                    upd["last_tested"] = now
                self._replace_entry(e["id"], upd)
        elif chosen in pri_acts:
            for e in entries:
                upd = dict(e); upd["priority"] = pri_acts[chosen]; upd["updated"] = now
                self._replace_entry(e["id"], upd)
        elif chosen == pin_act:
            for e in entries:
                upd = dict(e); upd["pinned"] = True; upd["updated"] = now
                self._replace_entry(e["id"], upd)
        elif chosen == unpin_act:
            for e in entries:
                upd = dict(e); upd["pinned"] = False; upd["updated"] = now
                self._replace_entry(e["id"], upd)
        elif chosen == retest_act:
            for e in entries:
                upd = dict(e); upd["needs_retest"] = True; upd["updated"] = now
                self._replace_entry(e["id"], upd)
        elif chosen == unretest_act:
            for e in entries:
                upd = dict(e); upd["needs_retest"] = False; upd["updated"] = now
                self._replace_entry(e["id"], upd)
        elif chosen == create_flow_act:
            self._create_flow_from_selection(entries)
        elif chosen == del_act:
            if QMessageBox.question(
                self, "Delete", f"Delete {len(entries)} selected entries?",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes:
                for e in entries:
                    self._delete_entry(e)

    def _on_context_menu(self, pos):
        row = self.table.rowAt(pos.y())
        if row < 0:
            return

        # Flow header rows have their own mini-menu
        flow_hdr = self._flow_at_row(row)
        if flow_hdr is not None:
            self._on_flow_header_context_menu(pos, flow_hdr)
            return

        entry = self._entry_at_row(row)
        if entry is None:
            return

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{ padding: 6px 20px 6px 10px; border-radius: 3px; }}
            QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #fff; }}
            QMenu::separator {{ height: 1px; background: {COLOR_BORDER}; margin: 2px 4px; }}
        """)

        edit_act   = menu.addAction("  Edit")
        dup_act    = menu.addAction("  Duplicate")
        menu.addSeparator()

        copy_url   = menu.addAction("  Copy URL")
        copy_req   = menu.addAction("  Copy Request Snippet")
        copy_row   = menu.addAction("  Copy Row as Markdown")
        menu.addSeparator()

        # Status submenu
        status_menu = menu.addMenu("  Set Status")
        status_acts = {}
        for s in STATUSES:
            a = status_menu.addAction(s)
            status_acts[a] = s

        # Priority submenu
        pri_menu = menu.addMenu("  Set Priority")
        pri_acts = {}
        for p in PRIORITIES:
            a = pri_menu.addAction(p)
            pri_acts[a] = p

        menu.addSeparator()
        pin_lbl  = "⚲  Unpin" if entry.get("pinned") else "⚲  Pin to Top"
        pin_act  = menu.addAction(pin_lbl)
        rt_lbl   = "↺  Clear Retest Flag" if entry.get("needs_retest") else "↺  Mark: Needs Retest"
        rt_act   = menu.addAction(rt_lbl)
        menu.addSeparator()

        # ── ⛓ Flow submenu
        flow_menu = menu.addMenu("⛓  Flow")
        new_flow_act = flow_menu.addAction("＋  Create new flow with this entry")
        flow_menu.addSeparator()
        flow_entry_acts: Dict = {}
        entry_flow_ids = {
            f["id"] for f in self._flows
            if entry.get("id") in f.get("entry_ids", [])
        }
        if entry_flow_ids:
            for f in self._flows:
                if f["id"] in entry_flow_ids:
                    a = flow_menu.addAction(f"✕  Remove from: {f['name']}")
                    flow_entry_acts[a] = ("remove", f)
            flow_menu.addSeparator()
        for f in self._flows:
            if f["id"] not in entry_flow_ids:
                a = flow_menu.addAction(f"  Add to: {f['name']}")
                flow_entry_acts[a] = ("add", f)
        if not self._flows:
            _na = flow_menu.addAction("(No flows — create one above)")
            _na.setEnabled(False)
        menu.addSeparator()

        # Send to …
        mw = self._main_window
        if mw and hasattr(mw, 'repeater_tab'):
            send_rep = menu.addAction("  Send to Repeater")
        else:
            send_rep = None
        if mw and hasattr(mw, 'intruder_tab'):
            send_int = menu.addAction("  Send to Intruder")
        else:
            send_int = None
        if mw and hasattr(mw, 'scanner_tab'):
            send_scan = menu.addAction("  Send to Scanner")
        else:
            send_scan = None
        if mw and hasattr(mw, 'report_tab'):
            send_report = menu.addAction("  Report Bug")
        else:
            send_report = None

        menu.addSeparator()
        del_act = menu.addAction("  Delete")

        chosen = menu.exec_(self.table.viewport().mapToGlobal(pos))
        if chosen is None:
            return

        now = _now_str()
        if chosen == edit_act:
            self._edit_entry(entry)
        elif chosen == dup_act:
            self._duplicate_entry(entry)
        elif chosen == copy_url:
            QApplication.clipboard().setText(entry.get("url", ""))
        elif chosen == copy_req:
            QApplication.clipboard().setText(entry.get("request_snippet", ""))
        elif chosen == copy_row:
            QApplication.clipboard().setText(self._entry_as_markdown(entry))
        elif chosen == pin_act:
            updated = dict(entry)
            updated["pinned"]  = not entry.get("pinned", False)
            updated["updated"] = now
            self._replace_entry(entry["id"], updated)
        elif chosen == rt_act:
            updated = dict(entry)
            updated["needs_retest"] = not entry.get("needs_retest", False)
            updated["updated"]      = now
            self._replace_entry(entry["id"], updated)
        elif chosen == new_flow_act:
            self._create_flow_from_selection([entry])
        elif chosen in flow_entry_acts:
            action, f = flow_entry_acts[chosen]
            if action == "add":
                self._add_entry_to_flow(entry, f)
            elif action == "remove":
                self._remove_entry_from_flow(entry, f)
        elif chosen == del_act:
            if QMessageBox.question(
                self, "Delete", f"Delete entry:\n{entry.get('url', '')}?",
                QMessageBox.Yes | QMessageBox.No
            ) == QMessageBox.Yes:
                self._delete_entry(entry)
        elif chosen in status_acts:
            updated = dict(entry)
            updated["status"]  = status_acts[chosen]
            updated["updated"] = now
            if updated["status"] in ("Testing", "Confirmed Bug"):
                updated["last_tested"] = now
            self._replace_entry(entry["id"], updated)
        elif chosen in pri_acts:
            updated = dict(entry)
            updated["priority"] = pri_acts[chosen]
            updated["updated"]  = now
            self._replace_entry(entry["id"], updated)
        elif send_rep and chosen == send_rep:
            self._send_to_repeater(entry)
        elif send_int and chosen == send_int:
            self._send_to_intruder(entry)
        elif send_scan and chosen == send_scan:
            self._send_to_scanner(entry)
        elif send_report and chosen == send_report:
            self._send_to_report(entry)

    # ── Send to / Integration ──────────────────────────────────────────────

    def _build_raw_request(self, entry: Dict) -> str:
        """Return a minimal raw HTTP request from the entry's snippet or metadata."""
        raw = entry.get("request_snippet", "").strip()
        if raw:
            return raw
        url   = entry.get("url", "/")
        meth  = entry.get("method", "GET")
        try:
            from urllib.parse import urlparse as _up
            p = _up(url)
            path = (p.path or "/") + ("?" + p.query if p.query else "")
            host = p.hostname or url
        except Exception:
            path, host = "/", url
        return f"{meth} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n"

    def _send_to_repeater(self, entry: Dict):
        mw = self._main_window
        if not mw or not hasattr(mw, 'repeater_tab'):
            return
        raw = self._build_raw_request(entry)
        try:
            mw.repeater_tab.add_request(raw)
            mw.tab_widget.setCurrentWidget(mw.repeater_tab)
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] send to repeater: {e}")

    def _send_to_intruder(self, entry: Dict):
        mw = self._main_window
        if not mw or not hasattr(mw, 'intruder_tab'):
            return
        raw = self._build_raw_request(entry)
        try:
            mw.intruder_tab.load_request(raw)
            mw.tab_widget.setCurrentWidget(mw.intruder_tab)
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] send to intruder: {e}")

    def _send_to_report(self, entry: Dict):
        """Open the Report Bug dialog pre-filled from an attack surface entry."""
        mw = self._main_window
        if not mw:
            return
        report_tab = getattr(mw, 'report_tab', None)
        if report_tab is None or not hasattr(report_tab, 'add_from_finding'):
            QMessageBox.warning(self, "Report Bug", "Reports tab not found.")
            return
        finding = {
            "url":         entry.get("url", ""),
            "method":      entry.get("method", "GET"),
            "parameter":   ", ".join(entry.get("params", [])),
            "severity":    entry.get("priority", "P3 - Medium").replace("P1 - ", "").replace("P2 - ", "").replace("P3 - ", "").replace("P4 - ", ""),
            "description": entry.get("notes", ""),
            "poc":         entry.get("request_snippet", ""),
            "source":      "Attack Surface",
        }
        report_tab.add_from_finding(finding)
        for i in range(mw.tab_widget.count()):
            if "Report" in mw.tab_widget.tabText(i):
                mw.tab_widget.setCurrentIndex(i)
                break

    def _send_to_scanner(self, entry: Dict):
        mw = self._main_window
        if not mw or not hasattr(mw, 'scanner_tab'):
            return
        raw = self._build_raw_request(entry)
        request_data = {
            "url":           entry.get("url", ""),
            "method":        entry.get("method", "GET"),
            "request_text":  raw,
            "response_text": "",
        }
        try:
            mw.scanner_tab.add_request_to_queue(request_data)
            for i in range(mw.tab_widget.count()):
                if "Scanner" in mw.tab_widget.tabText(i):
                    mw.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            logger.error(f"[AttackSurfaceTab] send to scanner: {e}")

    # ── Export ─────────────────────────────────────────────────────────────

    def _show_export_menu(self):
        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{ padding: 6px 20px 6px 10px; border-radius: 3px; }}
            QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #fff; }}
        """)
        json_act = menu.addAction("📄  Export as JSON")
        csv_act  = menu.addAction("📊  Export as CSV")
        md_act   = menu.addAction("📝  Export as Markdown")

        sender_widget = self.sender()
        if sender_widget:
            pos = sender_widget.mapToGlobal(sender_widget.rect().bottomLeft())
        else:
            pos = self.mapToGlobal(self.rect().center())

        chosen = menu.exec_(pos)
        data   = self._filtered if self._filtered else self._entries

        if chosen == json_act:
            self._export_json(data)
        elif chosen == csv_act:
            self._export_csv(data)
        elif chosen == md_act:
            self._export_markdown(data)

    def _export_json(self, data: List[Dict]):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON", "attack_surface.json", "JSON (*.json)"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        QMessageBox.information(self, "Export", f"Exported {len(data)} entries to JSON.")

    def _export_csv(self, data: List[Dict]):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV", "attack_surface.csv", "CSV (*.csv)"
        )
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=["url","method","status_code","priority",
                               "status","tags","notes","added","updated"],
                extrasaction="ignore"
            )
            writer.writeheader()
            for ep in data:
                row = dict(ep)
                row["tags"] = "; ".join(row.get("tags", []))
                writer.writerow(row)
        QMessageBox.information(self, "Export", f"Exported {len(data)} entries to CSV.")

    def _export_markdown(self, data: List[Dict]):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Markdown", "attack_surface.md", "Markdown (*.md)"
        )
        if not path:
            return
        lines = [
            "# Attack Surface", "",
            f"_Exported {_now_str()}  —  {len(data)} entries_", "",
            "| # | Priority | Method | URL | Status Code | Status | Tags | Notes |",
            "|---|----------|--------|-----|-------------|--------|------|-------|",
        ]
        for i, ep in enumerate(data, 1):
            tags = ", ".join(ep.get("tags", []))
            note = ep.get("notes", "").replace("\n", " ").replace("|", "\\|")[:80]
            lines.append(
                f"| {i} | {ep.get('priority','')} | {ep.get('method','')} "
                f"| `{ep.get('url','')}` | {ep.get('status_code','')} "
                f"| {ep.get('status','')} | {tags} | {note} |"
            )
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        QMessageBox.information(self, "Export", f"Exported {len(data)} entries to Markdown.")

    def _entry_as_markdown(self, ep: Dict) -> str:
        tags = ", ".join(ep.get("tags", []))
        return (
            f"**[{ep.get('method','')}]** `{ep.get('url','')}`\n"
            f"- Priority: {ep.get('priority','')}\n"
            f"- Status: {ep.get('status','')}\n"
            f"- Status Code: {ep.get('status_code','')}\n"
            f"- Tags: {tags}\n"
            f"- Notes: {ep.get('notes','')}\n"
        )

    # ── Clear all ──────────────────────────────────────────────────────────

    def _clear_all(self):
        if not self._entries:
            return
        reply = QMessageBox.question(
            self, "Clear All",
            f"Delete all {len(self._entries)} entr(ies)?\n(Use ↩ Undo to restore the last deletion.)",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            # Push to trash (last 20 survive for undo)
            self._trash.extend(self._entries)
            if len(self._trash) > 20:
                self._trash = self._trash[-20:]
            self._undo_btn.setEnabled(bool(self._trash))
            self._entries.clear()
            self.detail_panel.clear()
            self._schedule_save()
            self._apply_filters()
