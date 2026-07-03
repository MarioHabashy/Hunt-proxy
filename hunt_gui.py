#!/usr/bin/env python3
"""
hunt_gui.py  –  Main GUI window (updated)

Changes vs original:
  ✅  Standalone: no longer needs env vars from bash wrapper
  ✅  LaunchDialog shown on startup → picks/creates project
  ✅  Project data stored in ~/hackrecon_projects/<slug>/
  ✅  ScopeTab for program / domain / subdomain management
  ✅  InterceptTab with Burp-style forward/drop/edit
  ✅  HuntProxyAddon (inline mitmproxy class) replaces external hunt_script.py
  ✅  Proxy env vars set from project paths + scope before launching mitmdump
"""

import sys
import os
import json
import html
import re
import time
import threading
import subprocess
import signal
import queue
import atexit
from datetime import datetime
from collections import deque
from typing import Dict, Any, List, Set, Tuple, Optional
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from html import escape as html_escape
import logging

# ========================================================================
# PROXY CLEANUP & CRASH RECOVERY
# ========================================================================

# Global reference to the main GUI window for signal handlers
_main_window_ref = None

def _kill_orphaned_mitmdump():
    """Kill any orphaned mitmdump processes from previous crashes.

    Sends SIGTERM first, waits up to 3 s for graceful exit, then SIGKILL.
    This prevents the race where a slow-dying process keeps port 8888 busy
    when the new mitmdump tries to start a moment later.
    """
    try:
        import subprocess

        def _collect_pids():
            pids = []
            try:
                result = subprocess.run(['pgrep', '-f', 'mitmdump'],
                                        capture_output=True, text=True, timeout=5)
                for p in result.stdout.strip().split('\n'):
                    if p.isdigit():
                        pids.append(int(p))
            except FileNotFoundError:
                try:
                    result = subprocess.run(['ps', 'aux'],
                                            capture_output=True, text=True, timeout=5)
                    for line in result.stdout.split('\n'):
                        if 'mitmdump' in line and 'grep' not in line:
                            parts = line.split()
                            if len(parts) > 1 and parts[1].isdigit():
                                pids.append(int(parts[1]))
                except Exception:
                    pass
            return pids

        pids = _collect_pids()
        if not pids:
            return

        # Send SIGTERM to all found orphans
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
                logger.info(f"Sent SIGTERM to orphaned mitmdump: PID {pid}")
            except (ProcessLookupError, PermissionError):
                pass

        # Wait up to 3 s for graceful exit, then SIGKILL survivors
        deadline = time.time() + 3.0
        while time.time() < deadline:
            time.sleep(0.2)
            still_alive = []
            for pid in pids:
                try:
                    os.kill(pid, 0)   # signal 0: just checks existence
                    still_alive.append(pid)
                except ProcessLookupError:
                    pass
            pids = still_alive
            if not pids:
                break

        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
                logger.info(f"Sent SIGKILL to stubborn orphaned mitmdump: PID {pid}")
            except (ProcessLookupError, PermissionError):
                pass

    except Exception as e:
        logger.debug(f"Could not kill orphaned processes: {e}")

def _cleanup_on_exit():
    """
    Cleanup called by atexit — Qt widgets are already destroyed at this point
    so we must ONLY kill the OS-level proxy process.  Never call any method
    that touches QLabel, QAction, or any other Qt object here.
    """
    global _main_window_ref
    mw = _main_window_ref
    if mw is None:
        return
    try:
        # logger.info() is inside the try block because the logging module
        # may already be partially torn down at atexit time, which would
        # raise an AttributeError before reaching the kill code.
        logger.info("Running cleanup on exit...")
        # Only touch the subprocess — not any Qt widget
        proc = getattr(mw, 'proxy_process', None)
        if proc is not None and proc.poll() is None:
            try:
                if hasattr(os, 'killpg'):
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        proc.terminate()
                else:
                    proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception as e:
                logger.error(f"Error killing proxy process on exit: {e}")

        # Fallback: _force_stop_proxy() nullifies proxy_process even when the
        # kill fails.  Check the PID file so the process doesn't survive a
        # crashed or incomplete stop sequence.
        try:
            _project_paths = getattr(mw, '_project_paths', None)
            pid_file = (
                os.path.join(_project_paths["project_dir"], "mitm.pid")
                if _project_paths
                else "/tmp/mitm.pid"
            )
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as _f:
                    _stored = _f.read().strip()
                if _stored.isdigit():
                    _spid = int(_stored)
                    try:
                        os.kill(_spid, 0)   # alive check — raises ProcessLookupError if dead
                        if hasattr(os, 'killpg'):
                            try:
                                os.killpg(os.getpgid(_spid), signal.SIGKILL)
                            except (ProcessLookupError, OSError):
                                os.kill(_spid, signal.SIGKILL)
                        else:
                            os.kill(_spid, signal.SIGKILL)
                        logger.info(f"atexit: killed orphaned proxy PID {_spid} via PID file")
                    except ProcessLookupError:
                        pass   # already gone
        except Exception:
            pass   # best-effort only
    except Exception as e:
        try:
            logger.error(f"Error during proxy cleanup: {e}")
        except Exception:
            pass   # logging itself may have been torn down

def _signal_handler(signum, frame):
    """Handle signals like SIGINT and SIGTERM safely via the Qt event loop."""
    logger.info(f"Received signal {signum}, scheduling safe shutdown...")
    # Schedule quit through Qt's event loop instead of calling sys.exit()
    # directly — this ensures closeEvent runs and all threads are stopped cleanly.
    try:
        app = QApplication.instance()
        if app:
            app.quit()
        else:
            sys.exit(0)
    except Exception:
        sys.exit(0)

# Register cleanup handlers
atexit.register(_cleanup_on_exit)
signal.signal(signal.SIGINT,  _signal_handler)
signal.signal(signal.SIGTERM, _signal_handler)


# ── Global exception safety ───────────────────────────────────────────────────
# Catch any unhandled exception that reaches the top level so the tool never
# closes without explanation.  Shows an error dialog and logs the traceback.

def _global_exception_hook(exc_type, exc_value, exc_tb):
    """Catch unhandled exceptions in the main thread."""
    import traceback
    tb_text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
    logger.critical(f"Unhandled exception:\n{tb_text}")

    # Don't show a dialog for KeyboardInterrupt — just let the signal handler
    # deal with it.
    if issubclass(exc_type, KeyboardInterrupt):
        _signal_handler(signal.SIGINT, None)
        return

    try:
        app = QApplication.instance()
        if app:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Unexpected Error")
            msg.setText(
                "<b>An unexpected error occurred.</b><br>"
                "The tool will try to keep running. "
                "If it becomes unstable please restart."
            )
            msg.setDetailedText(tb_text)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()
    except Exception:
        pass   # last resort — don't let the error handler itself crash


def _thread_exception_hook(args):
    """Catch unhandled exceptions in worker threads (Python 3.8+)."""
    if args.exc_type is SystemExit:
        return
    import traceback
    tb_text = "".join(traceback.format_exception(
        args.exc_type, args.exc_value, args.exc_traceback))
    logger.error(f"Unhandled thread exception:\n{tb_text}")


sys.excepthook = _global_exception_hook
try:
    # threading.excepthook is available from Python 3.8 onwards
    import threading as _threading
    _threading.excepthook = _thread_exception_hook
except AttributeError:
    pass

# ========================================================================
# GLOBAL SETTINGS
# ========================================================================

HACKRECON_CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".config", "HackRecon")
HUNT_SETTINGS_FILE = os.path.join(HACKRECON_CONFIG_DIR, "settings.json")

def _load_global_settings() -> dict:
    """Loads global settings from the user's config directory."""
    if not os.path.exists(HUNT_SETTINGS_FILE):
        return {}
    try:
        with open(HUNT_SETTINGS_FILE, "r") as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError):
        return {}

def _save_global_settings(settings: dict):
    """Saves global settings to the user's config directory."""
    os.makedirs(HACKRECON_CONFIG_DIR, exist_ok=True)
    with open(HUNT_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

# ========================================================================
# PROXY OPTIONS DIALOGS
# ========================================================================

class RuleEditDialog(QDialog):
    """Dialog to add or edit a single Match & Replace rule."""
    def __init__(self, rule=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Rule" if rule else "Add Rule")
        self.setMinimumWidth(520)

        self.rule = rule or {
            "enabled": True, "type": "Response body",
            "match": "", "replace": "", "comment": ""
        }

        layout = QFormLayout(self)

        self.enabled_check = QCheckBox()
        self.enabled_check.setChecked(self.rule['enabled'])
        layout.addRow("Enabled:", self.enabled_check)

        self.type_combo = QComboBox()
        self.type_combo.addItems([
            "Response body", "Request body",
            "Response header", "Request header",
            "Request first line",
        ])
        self.type_combo.setCurrentText(self.rule.get('type', 'Response body'))
        layout.addRow("Type:", self.type_combo)

        self.match_edit = QLineEdit()
        self.match_edit.setPlaceholderText("Regex to match (leave empty to always replace)")
        self.match_edit.setText(self.rule.get('match', ''))
        layout.addRow("Match (regex):", self.match_edit)

        self.replace_edit = QTextEdit()
        self.replace_edit.setPlaceholderText("Replacement string (supports \\1 back-references)")
        self.replace_edit.setText(self.rule.get('replace', ''))
        self.replace_edit.setFixedHeight(100)
        layout.addRow("Replace:", self.replace_edit)

        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("Optional comment for this rule")
        self.comment_edit.setText(self.rule.get('comment', ''))
        layout.addRow("Comment:", self.comment_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_rule(self):
        return {
            "enabled":  self.enabled_check.isChecked(),
            "type":     self.type_combo.currentText(),
            "match":    self.match_edit.text(),
            "replace":  self.replace_edit.toPlainText(),
            "comment":  self.comment_edit.text(),
        }


class HeaderInjectDialog(QDialog):
    """Dialog to add or edit a header injection entry."""
    def __init__(self, entry=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Header" if entry else "Add Header")
        self.setMinimumWidth(460)

        self.entry = entry or {
            "enabled": True, "target": "Request",
            "name": "", "value": "", "comment": ""
        }

        layout = QFormLayout(self)

        self.enabled_check = QCheckBox()
        self.enabled_check.setChecked(self.entry.get('enabled', True))
        layout.addRow("Enabled:", self.enabled_check)

        self.target_combo = QComboBox()
        self.target_combo.addItems(["Request", "Response"])
        self.target_combo.setCurrentText(self.entry.get('target', 'Request'))
        layout.addRow("Target:", self.target_combo)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("e.g. X-Forwarded-For")
        self.name_edit.setText(self.entry.get('name', ''))
        layout.addRow("Header Name:", self.name_edit)

        self.value_edit = QLineEdit()
        self.value_edit.setPlaceholderText("e.g. 127.0.0.1")
        self.value_edit.setText(self.entry.get('value', ''))
        layout.addRow("Header Value:", self.value_edit)

        self.overwrite_check = QCheckBox("Overwrite if header already exists")
        self.overwrite_check.setChecked(self.entry.get('overwrite', True))
        layout.addRow("", self.overwrite_check)

        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("Optional note")
        self.comment_edit.setText(self.entry.get('comment', ''))
        layout.addRow("Comment:", self.comment_edit)

        # Quick-fill presets
        preset_layout = QHBoxLayout()
        preset_label = QLabel("Quick presets:")
        preset_layout.addWidget(preset_label)
        presets = [
            ("X-Forwarded-For: 127.0.0.1",  {"name": "X-Forwarded-For",  "value": "127.0.0.1"}),
            ("X-Real-IP: 127.0.0.1",         {"name": "X-Real-IP",         "value": "127.0.0.1"}),
            ("X-Custom-IP-Auth: 127.0.0.1",  {"name": "X-Custom-IP-Auth",  "value": "127.0.0.1"}),
            ("Authorization: Bearer TOKEN",  {"name": "Authorization",     "value": "Bearer TOKEN"}),
            ("X-Api-Key: YOUR_KEY",          {"name": "X-Api-Key",         "value": "YOUR_KEY"}),
            ("Origin: https://evil.com",     {"name": "Origin",            "value": "https://evil.com"}),
            ("Referer: https://evil.com",    {"name": "Referer",           "value": "https://evil.com"}),
            ("X-Request-ID: FUZZ",           {"name": "X-Request-ID",      "value": "FUZZ"}),
        ]
        preset_combo = QComboBox()
        preset_combo.addItem("— select —")
        for label, _ in presets:
            preset_combo.addItem(label)

        def _apply_preset(idx):
            if idx < 1:
                return
            d = presets[idx - 1][1]
            self.name_edit.setText(d["name"])
            self.value_edit.setText(d["value"])

        preset_combo.currentIndexChanged.connect(_apply_preset)
        preset_layout.addWidget(preset_combo)
        preset_layout.addStretch()
        layout.addRow("", preset_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def _validate_and_accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Header name cannot be empty.")
            return
        self.accept()

    def get_entry(self):
        return {
            "enabled":   self.enabled_check.isChecked(),
            "target":    self.target_combo.currentText(),
            "name":      self.name_edit.text().strip(),
            "value":     self.value_edit.text(),
            "overwrite": self.overwrite_check.isChecked(),
            "comment":   self.comment_edit.text(),
        }


class DropRuleDialog(QDialog):
    """Dialog to add or edit a request/response drop rule."""
    def __init__(self, rule=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Drop Rule" if rule else "Add Drop Rule")
        self.setMinimumWidth(460)

        self.rule = rule or {
            "enabled": True, "target": "Request",
            "field": "URL", "pattern": "", "comment": ""
        }

        layout = QFormLayout(self)

        self.enabled_check = QCheckBox()
        self.enabled_check.setChecked(self.rule.get('enabled', True))
        layout.addRow("Enabled:", self.enabled_check)

        self.target_combo = QComboBox()
        self.target_combo.addItems(["Request", "Response"])
        self.target_combo.setCurrentText(self.rule.get('target', 'Request'))
        layout.addRow("Drop:", self.target_combo)

        self.field_combo = QComboBox()
        self.field_combo.addItems(["URL", "Request header", "Request body",
                                   "Response header", "Response body",
                                   "Status code", "Method"])
        self.field_combo.setCurrentText(self.rule.get('field', 'URL'))
        layout.addRow("When field:", self.field_combo)

        self.pattern_edit = QLineEdit()
        self.pattern_edit.setPlaceholderText("Regex pattern to match")
        self.pattern_edit.setText(self.rule.get('pattern', ''))
        layout.addRow("Matches (regex):", self.pattern_edit)

        self.comment_edit = QLineEdit()
        self.comment_edit.setPlaceholderText("Optional note")
        self.comment_edit.setText(self.rule.get('comment', ''))
        layout.addRow("Comment:", self.comment_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def get_rule(self):
        return {
            "enabled": self.enabled_check.isChecked(),
            "target":  self.target_combo.currentText(),
            "field":   self.field_combo.currentText(),
            "pattern": self.pattern_edit.text(),
            "comment": self.comment_edit.text(),
        }


class ProxyOptionsDialog(QDialog):
    """
    Full proxy configuration dialog with multiple pentesting feature tabs:
      1. Match & Replace  – regex-based rewrite of req/resp headers and bodies
      2. Header Injection – inject/overwrite headers on every req or resp
      3. Drop Rules       – silently drop matching requests or responses
      4. SSL & Redirects  – HTTPS upgrade / HTTP downgrade toggles
      5. Rate Limiting    – throttle outgoing requests
    All config is persisted to proxy_config.json in the project directory.
    """

    def __init__(self, project_dir, parent=None):
        super().__init__(parent)
        self.project_dir = project_dir
        # Single unified config file
        self.config_file  = os.path.join(self.project_dir, "proxy_config.json")
        # Legacy rules file still supported for backward-compat
        self.rules_file   = os.path.join(self.project_dir, "proxy_rules.json")

        self.rules          = []   # Match & Replace
        self.header_entries = []   # Header Injection
        self.drop_rules     = []   # Drop Rules
        self.ssl_config     = {}   # SSL / redirect settings
        self.rate_config    = {}   # Rate limiting settings

        self.setWindowTitle("⚙️ Proxy Config")
        self.setMinimumSize(980, 660)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_match_replace_tab(),  "🔄 Match & Replace")
        self.tabs.addTab(self._create_header_inject_tab(),  "📌 Header Injection")
        self.tabs.addTab(self._create_drop_rules_tab(),     "🚫 Drop Rules")
        self.tabs.addTab(self._create_ssl_tab(),            "🔒 SSL & Redirects")
        self.tabs.addTab(self._create_rate_limit_tab(),     "⏱ Rate Limiting")
        layout.addWidget(self.tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save_all)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.load_all()

    # ── Tab builders ──────────────────────────────────────────────────────

    def _create_match_replace_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel(
            "Regex-based rewrite rules applied to requests and responses in transit. "
            "Rules are applied in order. Requires proxy restart to take effect."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.rules_table = QTableWidget()
        self.rules_table.setColumnCount(5)
        self.rules_table.setHorizontalHeaderLabels(
            ["✓", "Type", "Match (Regex)", "Replace", "Comment"]
        )
        self.rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.rules_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.rules_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.rules_table.doubleClicked.connect(self.edit_rule)
        layout.addWidget(self.rules_table)

        btn_layout = QHBoxLayout()
        for label, slot in [("Add", self.add_rule), ("Edit", self.edit_rule),
                             ("Remove", self.remove_rule)]:
            b = QPushButton(label); b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        for label, slot in [("▲ Up", self.move_rule_up), ("▼ Down", self.move_rule_down)]:
            b = QPushButton(label); b.clicked.connect(slot)
            btn_layout.addWidget(b)
        layout.addLayout(btn_layout)
        return widget

    def _create_header_inject_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel(
            "Inject or overwrite HTTP headers on every proxied request or response. "
            "Useful for authentication bypass, CORS testing, IP spoofing, and token injection."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.headers_table = QTableWidget()
        self.headers_table.setColumnCount(5)
        self.headers_table.setHorizontalHeaderLabels(
            ["✓", "Target", "Header Name", "Value", "Comment"]
        )
        self.headers_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.headers_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.headers_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.headers_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.headers_table.doubleClicked.connect(self.edit_header)
        layout.addWidget(self.headers_table)

        btn_layout = QHBoxLayout()
        for label, slot in [("Add", self.add_header), ("Edit", self.edit_header),
                             ("Remove", self.remove_header)]:
            b = QPushButton(label); b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()

        # Quick-add common pentest headers
        quick_label = QLabel("Quick add:")
        btn_layout.addWidget(quick_label)
        quick_combo = QComboBox()
        quick_combo.setMinimumWidth(200)
        quick_combo.addItem("— pentest presets —")
        _presets = [
            ("X-Forwarded-For: 127.0.0.1",    "Request",  "X-Forwarded-For",    "127.0.0.1"),
            ("X-Real-IP: 127.0.0.1",           "Request",  "X-Real-IP",           "127.0.0.1"),
            ("X-Originating-IP: 127.0.0.1",    "Request",  "X-Originating-IP",    "127.0.0.1"),
            ("X-Remote-IP: 127.0.0.1",         "Request",  "X-Remote-IP",         "127.0.0.1"),
            ("X-Client-IP: 127.0.0.1",         "Request",  "X-Client-IP",         "127.0.0.1"),
            ("X-Api-Key: FUZZ",                "Request",  "X-Api-Key",           "FUZZ"),
            ("Authorization: Bearer TOKEN",    "Request",  "Authorization",       "Bearer TOKEN"),
            ("Origin: https://evil.com",        "Request",  "Origin",              "https://evil.com"),
            ("Referer: https://evil.com",       "Request",  "Referer",             "https://evil.com"),
            ("X-HTTP-Method-Override: PUT",     "Request",  "X-HTTP-Method-Override", "PUT"),
            ("X-CSRF-Token: FUZZ",              "Request",  "X-CSRF-Token",        "FUZZ"),
            ("Access-Control-Allow-Origin: *", "Response", "Access-Control-Allow-Origin", "*"),
        ]
        self._header_presets = _presets
        for label, *_ in _presets:
            quick_combo.addItem(label)

        def _quick_add(idx):
            if idx < 1:
                return
            _, target, name, value = _presets[idx - 1]
            entry = {"enabled": True, "target": target, "name": name,
                     "value": value, "overwrite": True, "comment": ""}
            self.header_entries.append(entry)
            self._populate_headers_table()
            quick_combo.setCurrentIndex(0)

        quick_combo.currentIndexChanged.connect(_quick_add)
        btn_layout.addWidget(quick_combo)
        layout.addLayout(btn_layout)
        return widget

    def _create_drop_rules_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        info = QLabel(
            "Silently drop requests or responses whose fields match a regex pattern. "
            "Useful for filtering noise, blocking unwanted third-party requests, or simulating WAF behaviour."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        self.drop_table = QTableWidget()
        self.drop_table.setColumnCount(5)
        self.drop_table.setHorizontalHeaderLabels(
            ["✓", "Drop", "Field", "Pattern (Regex)", "Comment"]
        )
        self.drop_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.drop_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.drop_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.drop_table.doubleClicked.connect(self.edit_drop_rule)
        layout.addWidget(self.drop_table)

        btn_layout = QHBoxLayout()
        for label, slot in [("Add", self.add_drop_rule), ("Edit", self.edit_drop_rule),
                             ("Remove", self.remove_drop_rule)]:
            b = QPushButton(label); b.clicked.connect(slot)
            btn_layout.addWidget(b)
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        return widget

    def _create_ssl_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(16)

        info = QLabel(
            "Control how the proxy handles SSL/TLS and HTTP redirects. "
            "These options are applied globally to all proxied traffic."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        # HTTPS upgrade
        https_group = QGroupBox("HTTPS Upgrade")
        https_layout = QVBoxLayout(https_group)
        self.ssl_upgrade_cb = QCheckBox(
            "Upgrade all HTTP requests to HTTPS (rewrites http:// → https://)"
        )
        self.ssl_upgrade_cb.setToolTip(
            "Forces every outgoing plain-HTTP request to use HTTPS instead."
        )
        https_layout.addWidget(self.ssl_upgrade_cb)
        layout.addWidget(https_group)

        # HTTP downgrade
        http_group = QGroupBox("HTTP Downgrade (SSL Strip)")
        http_layout = QVBoxLayout(http_group)
        self.ssl_strip_cb = QCheckBox(
            "Strip HTTPS from Location redirects (downgrade to HTTP)"
        )
        self.ssl_strip_cb.setToolTip(
            "Rewrites Location headers in 3xx responses from https:// to http://, "
            "useful for testing SSL stripping vulnerabilities."
        )
        http_layout.addWidget(self.ssl_strip_cb)
        layout.addWidget(http_group)

        # Remove security headers
        sec_group = QGroupBox("Security Header Removal")
        sec_layout = QVBoxLayout(sec_group)
        self.remove_hsts_cb    = QCheckBox("Remove Strict-Transport-Security (HSTS)")
        self.remove_csp_cb     = QCheckBox("Remove Content-Security-Policy (CSP)")
        self.remove_xframe_cb  = QCheckBox("Remove X-Frame-Options")
        self.remove_xcto_cb    = QCheckBox("Remove X-Content-Type-Options")
        for cb in [self.remove_hsts_cb, self.remove_csp_cb,
                   self.remove_xframe_cb, self.remove_xcto_cb]:
            sec_layout.addWidget(cb)
        layout.addWidget(sec_group)

        # Remove CORS restrictions
        cors_group = QGroupBox("CORS Bypass")
        cors_layout = QVBoxLayout(cors_group)
        self.cors_bypass_cb = QCheckBox(
            "Inject permissive CORS headers on all responses "
            "(Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true)"
        )
        cors_layout.addWidget(self.cors_bypass_cb)
        layout.addWidget(cors_group)

        layout.addStretch()
        return widget

    def _create_rate_limit_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setAlignment(Qt.AlignTop)
        layout.setSpacing(16)

        info = QLabel(
            "Throttle outgoing requests to avoid triggering WAF rate limits or account lockouts "
            "during active testing. Delays are added between requests matching the filter."
        )
        info.setWordWrap(True)
        layout.addWidget(info)

        rate_group = QGroupBox("Request Throttling")
        rate_form  = QFormLayout(rate_group)

        self.rate_enable_cb = QCheckBox("Enable rate limiting")
        rate_form.addRow("", self.rate_enable_cb)

        self.rate_delay_spin = QDoubleSpinBox()
        self.rate_delay_spin.setRange(0.0, 60.0)
        self.rate_delay_spin.setSingleStep(0.1)
        self.rate_delay_spin.setDecimals(2)
        self.rate_delay_spin.setSuffix("  seconds")
        self.rate_delay_spin.setValue(0.5)
        self.rate_delay_spin.setToolTip("Minimum delay between consecutive requests.")
        rate_form.addRow("Delay between requests:", self.rate_delay_spin)

        self.rate_jitter_spin = QDoubleSpinBox()
        self.rate_jitter_spin.setRange(0.0, 10.0)
        self.rate_jitter_spin.setSingleStep(0.05)
        self.rate_jitter_spin.setDecimals(2)
        self.rate_jitter_spin.setSuffix("  seconds (random ±)")
        self.rate_jitter_spin.setValue(0.0)
        self.rate_jitter_spin.setToolTip(
            "Random jitter added to each delay to make traffic look more human."
        )
        rate_form.addRow("Jitter:", self.rate_jitter_spin)

        self.rate_filter_edit = QLineEdit()
        self.rate_filter_edit.setPlaceholderText(
            "Optional URL regex filter — limit only matching URLs (blank = all)"
        )
        rate_form.addRow("URL filter (regex):", self.rate_filter_edit)

        layout.addWidget(rate_group)
        layout.addStretch()
        return widget

    # ── Load / Save ───────────────────────────────────────────────────────

    def load_all(self):
        """Load unified config, with fallback to legacy proxy_rules.json."""
        config = {}
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
            except (json.JSONDecodeError, IOError):
                config = {}
        elif os.path.exists(self.rules_file):
            # Migrate legacy file
            try:
                with open(self.rules_file, 'r') as f:
                    config = {"match_replace": json.load(f)}
            except (json.JSONDecodeError, IOError):
                config = {}

        self.rules          = config.get("match_replace",  [])
        self.header_entries = config.get("header_inject",  [])
        self.drop_rules     = config.get("drop_rules",     [])
        self.ssl_config     = config.get("ssl",            {})
        self.rate_config    = config.get("rate_limit",     {})

        self.populate_table()
        self._populate_headers_table()
        self._populate_drop_table()
        self._populate_ssl_tab()
        self._populate_rate_tab()

    def save_all(self):
        """Persist all tabs to a single config file."""
        self._collect_ssl_settings()
        self._collect_rate_settings()
        config = {
            "match_replace": self.rules,
            "header_inject":  self.header_entries,
            "drop_rules":     self.drop_rules,
            "ssl":            self.ssl_config,
            "rate_limit":     self.rate_config,
        }
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            # Also keep legacy rules file in sync for backward compat
            with open(self.rules_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
            self.accept()
        except IOError as e:
            QMessageBox.critical(self, "Error", f"Could not save config: {e}")

    # ── Match & Replace helpers ───────────────────────────────────────────

    def populate_table(self):
        self.rules_table.setRowCount(0)
        for rule in self.rules:
            row = self.rules_table.rowCount()
            self.rules_table.insertRow(row)
            self._insert_checkbox(self.rules_table, row, 0,
                                  rule.get('enabled', True),
                                  lambda s, r=row: self._toggle_list_item(self.rules, r, s))
            self.rules_table.setItem(row, 1, QTableWidgetItem(rule.get('type', '')))
            self.rules_table.setItem(row, 2, QTableWidgetItem(rule.get('match', '')))
            self.rules_table.setItem(row, 3, QTableWidgetItem(rule.get('replace', '')))
            self.rules_table.setItem(row, 4, QTableWidgetItem(rule.get('comment', '')))
        self.rules_table.resizeColumnsToContents()

    def add_rule(self):
        dlg = RuleEditDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.rules.append(dlg.get_rule())
            self.populate_table()

    def edit_rule(self):
        row = self._selected_row(self.rules_table)
        if row is None: return
        dlg = RuleEditDialog(rule=self.rules[row], parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.rules[row] = dlg.get_rule()
            self.populate_table()
            self.rules_table.selectRow(row)

    def remove_rule(self):
        row = self._selected_row(self.rules_table)
        if row is None: return
        if self._confirm_remove("rule"):
            del self.rules[row]
            self.populate_table()

    def move_rule_up(self):
        row = self._selected_row(self.rules_table)
        if row and row > 0:
            self.rules.insert(row - 1, self.rules.pop(row))
            self.populate_table(); self.rules_table.selectRow(row - 1)

    def move_rule_down(self):
        row = self._selected_row(self.rules_table)
        if row is not None and row < len(self.rules) - 1:
            self.rules.insert(row + 1, self.rules.pop(row))
            self.populate_table(); self.rules_table.selectRow(row + 1)

    # ── Header Injection helpers ──────────────────────────────────────────

    def _populate_headers_table(self):
        self.headers_table.setRowCount(0)
        for entry in self.header_entries:
            row = self.headers_table.rowCount()
            self.headers_table.insertRow(row)
            self._insert_checkbox(self.headers_table, row, 0,
                                  entry.get('enabled', True),
                                  lambda s, r=row: self._toggle_list_item(self.header_entries, r, s))
            self.headers_table.setItem(row, 1, QTableWidgetItem(entry.get('target', 'Request')))
            self.headers_table.setItem(row, 2, QTableWidgetItem(entry.get('name', '')))
            self.headers_table.setItem(row, 3, QTableWidgetItem(entry.get('value', '')))
            self.headers_table.setItem(row, 4, QTableWidgetItem(entry.get('comment', '')))
        self.headers_table.resizeColumnsToContents()

    def add_header(self):
        dlg = HeaderInjectDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.header_entries.append(dlg.get_entry())
            self._populate_headers_table()

    def edit_header(self):
        row = self._selected_row(self.headers_table)
        if row is None: return
        dlg = HeaderInjectDialog(entry=self.header_entries[row], parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.header_entries[row] = dlg.get_entry()
            self._populate_headers_table()
            self.headers_table.selectRow(row)

    def remove_header(self):
        row = self._selected_row(self.headers_table)
        if row is None: return
        if self._confirm_remove("header injection entry"):
            del self.header_entries[row]
            self._populate_headers_table()

    # ── Drop Rules helpers ────────────────────────────────────────────────

    def _populate_drop_table(self):
        self.drop_table.setRowCount(0)
        for rule in self.drop_rules:
            row = self.drop_table.rowCount()
            self.drop_table.insertRow(row)
            self._insert_checkbox(self.drop_table, row, 0,
                                  rule.get('enabled', True),
                                  lambda s, r=row: self._toggle_list_item(self.drop_rules, r, s))
            self.drop_table.setItem(row, 1, QTableWidgetItem(rule.get('target', 'Request')))
            self.drop_table.setItem(row, 2, QTableWidgetItem(rule.get('field', 'URL')))
            self.drop_table.setItem(row, 3, QTableWidgetItem(rule.get('pattern', '')))
            self.drop_table.setItem(row, 4, QTableWidgetItem(rule.get('comment', '')))
        self.drop_table.resizeColumnsToContents()

    def add_drop_rule(self):
        dlg = DropRuleDialog(parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.drop_rules.append(dlg.get_rule())
            self._populate_drop_table()

    def edit_drop_rule(self):
        row = self._selected_row(self.drop_table)
        if row is None: return
        dlg = DropRuleDialog(rule=self.drop_rules[row], parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self.drop_rules[row] = dlg.get_rule()
            self._populate_drop_table()
            self.drop_table.selectRow(row)

    def remove_drop_rule(self):
        row = self._selected_row(self.drop_table)
        if row is None: return
        if self._confirm_remove("drop rule"):
            del self.drop_rules[row]
            self._populate_drop_table()

    # ── SSL tab helpers ───────────────────────────────────────────────────

    def _populate_ssl_tab(self):
        s = self.ssl_config
        self.ssl_upgrade_cb.setChecked(s.get("upgrade_to_https", False))
        self.ssl_strip_cb.setChecked(s.get("ssl_strip", False))
        self.remove_hsts_cb.setChecked(s.get("remove_hsts", False))
        self.remove_csp_cb.setChecked(s.get("remove_csp", False))
        self.remove_xframe_cb.setChecked(s.get("remove_xframe", False))
        self.remove_xcto_cb.setChecked(s.get("remove_xcto", False))
        self.cors_bypass_cb.setChecked(s.get("cors_bypass", False))

    def _collect_ssl_settings(self):
        self.ssl_config = {
            "upgrade_to_https": self.ssl_upgrade_cb.isChecked(),
            "ssl_strip":        self.ssl_strip_cb.isChecked(),
            "remove_hsts":      self.remove_hsts_cb.isChecked(),
            "remove_csp":       self.remove_csp_cb.isChecked(),
            "remove_xframe":    self.remove_xframe_cb.isChecked(),
            "remove_xcto":      self.remove_xcto_cb.isChecked(),
            "cors_bypass":      self.cors_bypass_cb.isChecked(),
        }

    # ── Rate-limit tab helpers ────────────────────────────────────────────

    def _populate_rate_tab(self):
        r = self.rate_config
        self.rate_enable_cb.setChecked(r.get("enabled", False))
        self.rate_delay_spin.setValue(float(r.get("delay", 0.5)))
        self.rate_jitter_spin.setValue(float(r.get("jitter", 0.0)))
        self.rate_filter_edit.setText(r.get("url_filter", ""))

    def _collect_rate_settings(self):
        self.rate_config = {
            "enabled":    self.rate_enable_cb.isChecked(),
            "delay":      self.rate_delay_spin.value(),
            "jitter":     self.rate_jitter_spin.value(),
            "url_filter": self.rate_filter_edit.text().strip(),
        }

    # ── Shared widget utilities ───────────────────────────────────────────

    @staticmethod
    def _insert_checkbox(table, row, col, checked, on_click):
        cb = QCheckBox()
        cb.setChecked(checked)
        cb.clicked.connect(on_click)
        container = QWidget()
        cbl = QHBoxLayout(container)
        cbl.addWidget(cb)
        cbl.setAlignment(Qt.AlignCenter)
        cbl.setContentsMargins(0, 0, 0, 0)
        table.setCellWidget(row, col, container)

    @staticmethod
    def _selected_row(table):
        rows = table.selectionModel().selectedRows()
        return rows[0].row() if rows else None

    @staticmethod
    def _toggle_list_item(lst, index, state):
        if 0 <= index < len(lst):
            lst[index]['enabled'] = bool(state)

    def _confirm_remove(self, item_label="item"):
        reply = QMessageBox.question(
            self, f"Remove {item_label}",
            f"Are you sure you want to remove this {item_label}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        return reply == QMessageBox.Yes

logger = logging.getLogger(__name__)

# ── Modular imports ──────────────────────────────────────────────────────────
from constants import *
from http_history_tab import FileMonitorThread, SearchHighlighter, HTTPHistoryTab
from decoder_tab import DecoderTab
from payloads_tab import PayloadsTab
from comparer_tab import ComparerTab
from mapping_tab import MappingTabPro as MappingTab
from js_miner_tab import JSMinerTab
from scanner_tab import add_scanner_tab as add_active_scanner_tab
from param_miner_tab import ParamMinerTab
from api_key_tab import add_api_key_tab

# ── New modules ──────────────────────────────────────────────────────────────
import project_manager as pm
from launch_dialog import LaunchDialog
from scope_tab import ScopeTab
from intercept_tab import InterceptTab
from repeater_tab import RepeaterTab
from intruder_tab import IntruderTab
from dashboard_tab import add_dashboard_tab
from attack_surface_tab import AttackSurfaceTab
from report_tab import ReportTab
from ws_history_tab import WSHistoryTab

# ── Path to the dedicated mitmproxy addon script (no PyQt5 deps) ────────────
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
INLINE_ADDON_SCRIPT = os.path.join(_THIS_DIR, "hunt_addon.py")


# ─────────────────────────────────────────────────────────────────────────────
# HTTPFormatter (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

class HTTPFormatter:
    output_received = pyqtSignal(str, str)

    def __init__(self, process: subprocess.Popen, parent=None):
        super().__init__(parent)
        self.process = process
        self._running = True

    def run(self):
        stdout_t = threading.Thread(target=self._read_stream,
                                    args=(self.process.stdout, "stdout"), daemon=True)
        stderr_t = threading.Thread(target=self._read_stream,
                                    args=(self.process.stderr, "stderr"), daemon=True)
        stdout_t.start(); stderr_t.start()
        while self._running and self.process.poll() is None:
            time.sleep(0.1)
        for t in (stdout_t, stderr_t):
            if t.is_alive():
                t.join(timeout=1.0)

    def _read_stream(self, stream, stream_type: str):
        try:
            for line in iter(stream.readline, b''):
                if not self._running:
                    break
                if line:
                    self.output_received.emit(stream_type,
                                              line.decode('utf-8', errors='replace').rstrip())
        except (ValueError, IOError, OSError):
            pass
        except Exception as e:
            logger.error(f"Proxy {stream_type} read error: {e}")

    def stop(self):
        self._running = False
        for attr in ('stdout', 'stderr'):
            try:
                stream = getattr(self.process, attr, None)
                if stream:
                    stream.close()
            except Exception:
                pass
        self.wait(2000)


class ProxyHealthMonitor(QThread):
    proxy_died = pyqtSignal(str)

    def __init__(self, parent_gui, check_interval: int = 10):
        super().__init__()
        self.parent_gui = parent_gui
        self.check_interval = check_interval
        self._running = True

    def run(self):
        while self._running:
            time.sleep(self.check_interval)
            try:
                if not self._running:
                    break
                if not self.parent_gui.proxy_running:
                    continue
                proc = self.parent_gui.proxy_process
                if proc is None:
                    continue
                if proc.poll() is not None:
                    exit_code = proc.poll()
                    self.proxy_died.emit(f"Process exited with code {exit_code}")
                    break
                if not self._test_proxy_connection():
                    time.sleep(2)
                    if (self._running
                            and self.parent_gui.proxy_running
                            and not self._test_proxy_connection()):
                        # Before declaring the proxy dead due to a socket
                        # failure, confirm the process is actually gone.
                        # A heavily loaded proxy can temporarily refuse new
                        # connections without having crashed.
                        _proc2 = self.parent_gui.proxy_process
                        if _proc2 is not None and _proc2.poll() is None:
                            logger.warning(
                                "ProxyHealthMonitor: port unresponsive but "
                                "process is alive — possible overload, skipping"
                            )
                        else:
                            self.proxy_died.emit("Port not responding")
                            break
            except RuntimeError:
                # parent_gui widget was deleted (app is shutting down)
                break
            except Exception as e:
                logger.error(f"ProxyHealthMonitor error: {e}")
                # Continue monitoring — a transient exception must not
                # permanently kill the health-check thread.
                time.sleep(self.check_interval)

    def _test_proxy_connection(self) -> bool:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            r = s.connect_ex(('127.0.0.1', self.parent_gui.proxy_port))
            s.close()
            return r == 0
        except Exception:
            return False

    def stop(self):
        self._running = False
        self.wait(1000)


def _lbl(text: str, bold: bool = False, color: str = COLOR_TEXT_BRIGHT) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(f"color: {color}; font-weight: {'600' if bold else 'normal'};")
    return l


class ClickableLabel(QLabel):
    """QLabel that emits a clicked signal on left mouse press."""

    clicked = pyqtSignal()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class MarkdownHighlighter(QSyntaxHighlighter):
    """Live in-editor markdown highlighting — headings, bold, italic, code, etc."""

    def __init__(self, document):
        super().__init__(document)
        import re as _re
        self._re = _re

        # Heading formats
        self._h_fmts = []
        for size, color in [(22, '#7eb8f7'), (18, '#89b4fa'), (15, '#a6e3a1')]:
            fmt = QTextCharFormat()
            fmt.setFontPointSize(size)
            fmt.setFontWeight(QFont.Bold)
            fmt.setForeground(QColor(color))
            self._h_fmts.append(fmt)

        # Dimmed hash/marker prefix
        self._dim_fmt = QTextCharFormat()
        self._dim_fmt.setForeground(QColor('#585b70'))

        # Invisible format for syntax markers — same colour as editor background
        self._invis_fmt = QTextCharFormat()
        self._invis_fmt.setForeground(QColor('#1e1e1e'))
        self._invis_fmt.setFontPointSize(1)

        # Inline bold **text**
        self._bold_fmt = QTextCharFormat()
        self._bold_fmt.setFontWeight(QFont.Bold)
        self._bold_fmt.setForeground(QColor('#ffffff'))
        self._bold_fmt.setFontPointSize(14)

        # Inline italic *text*
        self._italic_fmt = QTextCharFormat()
        self._italic_fmt.setFontItalic(True)
        self._italic_fmt.setForeground(QColor('#cdd6f4'))

        # Inline code `text`
        self._code_fmt = QTextCharFormat()
        self._code_fmt.setFontFamily('Fira Code')
        self._code_fmt.setBackground(QColor('#1e1e2e'))
        self._code_fmt.setForeground(QColor('#a6e3a1'))

        # Fenced code fence (```)
        self._fence_fmt = QTextCharFormat()
        self._fence_fmt.setForeground(QColor('#585b70'))
        self._fence_fmt.setBackground(QColor('#1e1e2e'))

        # Bullet / list marker
        self._bullet_fmt = QTextCharFormat()
        self._bullet_fmt.setForeground(QColor('#f9e2af'))
        self._bullet_fmt.setFontWeight(QFont.Bold)

        # Checkbox [ ] / [x]
        self._check_fmt = QTextCharFormat()
        self._check_fmt.setForeground(QColor('#89dceb'))

        # Horizontal rule ---
        self._hr_fmt = QTextCharFormat()
        self._hr_fmt.setForeground(QColor('#7eb8f7'))
        self._hr_fmt.setFontWeight(QFont.Bold)
        self._hr_fmt.setUnderlineStyle(QTextCharFormat.SingleUnderline)
        self._hr_fmt.setUnderlineColor(QColor('#7eb8f7'))

        # Blockquote text  (> ...)
        self._quote_fmt = QTextCharFormat()
        self._quote_fmt.setForeground(QColor('#a6b0d4'))
        self._quote_pfx_fmt = QTextCharFormat()
        self._quote_pfx_fmt.setForeground(QColor('#7eb8f7'))
        self._quote_pfx_fmt.setFontWeight(QFont.Bold)

        # Links [text](url)
        self._link_fmt = QTextCharFormat()
        self._link_fmt.setForeground(QColor('#89b4fa'))
        self._link_fmt.setFontUnderline(True)

        # Bare URL auto-detection  http(s)://...
        self._url_fmt = QTextCharFormat()
        self._url_fmt.setForeground(QColor('#89dceb'))
        self._url_fmt.setFontUnderline(True)

        # Scope-matched URL (bright green + bold)
        self._scope_url_fmt = QTextCharFormat()
        self._scope_url_fmt.setForeground(QColor('#a6e3a1'))
        self._scope_url_fmt.setFontWeight(QFont.Bold)
        self._scope_url_fmt.setFontUnderline(True)

        # Severity / priority keyword formats
        self._sev_fmts = [
            (_re.compile(r'\b(CRITICAL|P1)\b'), self._make_kw_fmt('#f38ba8', bold=True)),
            (_re.compile(r'\b(HIGH|P2)\b'),     self._make_kw_fmt('#fab387')),
            (_re.compile(r'\b(MEDIUM|P3)\b'),   self._make_kw_fmt('#f9e2af')),
            (_re.compile(r'\b(LOW|P4)\b'),      self._make_kw_fmt('#89b4fa')),
            (_re.compile(r'\bINFO\b'),           self._make_kw_fmt('#a6adc8')),
            (_re.compile(r'\bTODO\b'),           self._make_kw_fmt('#f9e2af', bold=True)),
            (_re.compile(r'\bNOTE\b'),           self._make_kw_fmt('#89dceb')),
            (_re.compile(r'\bFIXED\b'),          self._make_kw_fmt('#a6e3a1')),
        ]

        # URL regex (bare URLs not wrapped in markdown link syntax)
        self._url_re = _re.compile(r'https?://[^\s\)\]"\' <>\x00-\x1f]+')
        self._scope_domains: list = []

        # Inline patterns applied in order (bold before italic to avoid collision)
        # Tuple: (pattern, content_format, open_marker_len, close_marker_len)
        self._inline = [
            (_re.compile(r'\*\*(.+?)\*\*'),                              self._bold_fmt,   2, 2),
            (_re.compile(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)'),       self._italic_fmt, 1, 1),
            (_re.compile(r'`([^`]+)`'),                                    self._code_fmt,   1, 1),
            (_re.compile(r'\[([^\]]+)\]\([^)]+\)'),                   self._link_fmt, 0, 0),
        ]

    def highlightBlock(self, text: str):
        re = self._re

        # ── Fenced code block (multi-line state tracking) ─────────────────
        # State 0 = normal  |  State 1 = inside fenced block
        in_fence = self.previousBlockState() == 1

        if text.strip().startswith('```'):
            # This line is a fence delimiter (opening OR closing)
            self.setFormat(0, len(text), self._fence_fmt)
            # Find the position of the ``` within the line (may be indented)
            _fence_start = len(text) - len(text.lstrip())
            if in_fence:
                # Closing fence — hide the ``` (block is now complete)
                self.setFormat(_fence_start, 3, self._invis_fmt)
                self.setCurrentBlockState(0)
            else:
                # Opening fence — scan ahead to check if a closing ``` exists below
                _blk = self.currentBlock().next()
                _has_closing = False
                while _blk.isValid():
                    _t = _blk.text().strip()
                    if _t.startswith('```'):
                        _has_closing = True
                        break
                    _blk = _blk.next()
                if _has_closing:
                    # Paired — hide the opening ``` too
                    self.setFormat(_fence_start, 3, self._invis_fmt)
                else:
                    # No closing ``` yet — show dimmed so user can see it
                    self.setFormat(_fence_start, 3, self._dim_fmt)
                self.setCurrentBlockState(1)
            return

        if in_fence:
            # Interior line of a fenced code block — style it entirely
            self.setCurrentBlockState(1)
            self.setFormat(0, len(text), self._fence_fmt)
            return

        # Normal line — reset state
        self.setCurrentBlockState(0)

        # Headings — check ### before ## before #
        for i, prefix in enumerate(['### ', '## ', '# ']):
            level = 2 - i  # index into _h_fmts: 0=H1, 1=H2, 2=H3
            if text.startswith(prefix) or text == prefix.rstrip():
                self.setFormat(0, len(text), self._h_fmts[level])
                # Hide # prefix only when there's actual heading text after it;
                # while still typing (just "#" or "# " with nothing after), show dimmed
                prefix_fmt = self._invis_fmt if len(text) > len(prefix) else self._dim_fmt
                self.setFormat(0, len(prefix), prefix_fmt)
                return

        # Horizontal rule
        if re.match(r'^[-*]{3,}\s*$', text):
            self.setFormat(0, len(text), self._hr_fmt)
            # Add top/bottom block margin so the rule acts as a visual spacer
            try:
                _cur = QTextCursor(self.currentBlock())
                _bfmt = _cur.blockFormat()
                _bfmt.setTopMargin(10)
                _bfmt.setBottomMargin(10)
                _cur.setBlockFormat(_bfmt)
            except Exception:
                pass
            return

        # Blockquote
        m = re.match(r'^(> ?)', text)
        if m:
            self.setFormat(0, len(m.group(1)), self._quote_pfx_fmt)
            self.setFormat(len(m.group(1)), len(text) - len(m.group(1)), self._quote_fmt)
            return

        # Checkbox line  - [ ] or - [x]
        m = re.match(r'^(\s*[-*]\s+)(\[[ xX]\])', text)
        if m:
            self.setFormat(m.start(1), len(m.group(1)), self._bullet_fmt)
            self.setFormat(m.start(2), len(m.group(2)), self._check_fmt)
            # Pre-pass: dim bare/partial markers after the checkbox prefix
            _pfx = m.end()
            for _m in re.finditer(r'\*\*', text[_pfx:]):
                self.setFormat(_pfx + _m.start(), 2, self._dim_fmt)
            for _m in re.finditer(r'(?<!\*)\*(?!\*)', text[_pfx:]):
                self.setFormat(_pfx + _m.start(), 1, self._dim_fmt)
            for _m in re.finditer(r'`', text[_pfx:]):
                self.setFormat(_pfx + _m.start(), 1, self._dim_fmt)
            for pat, fmt, ms, me in self._inline:
                for im in pat.finditer(text, m.end()):
                    self.setFormat(im.start(), im.end() - im.start(), fmt)
                    if ms:
                        self.setFormat(im.start(), ms, self._invis_fmt)
                        self.setFormat(im.end() - me, me, self._invis_fmt)
            return

        # Bullet / numbered list
        m = re.match(r'^(\s*[-*+]\s)', text) or re.match(r'^(\s*\d+\.\s)', text)
        if m:
            self.setFormat(m.start(), len(m.group(1)), self._bullet_fmt)

        # Pre-pass: dim bare/partial inline markers so typing gives visual hint.
        # Skip the bullet/list prefix region so its leading * doesn't get dimmed.
        # Complete-match passes below will override these with proper styles.
        _pfx = len(m.group(1)) if m else 0
        for _m in re.finditer(r'\*\*', text[_pfx:]):
            self.setFormat(_pfx + _m.start(), 2, self._dim_fmt)
        for _m in re.finditer(r'(?<!\*)\*(?!\*)', text[_pfx:]):
            self.setFormat(_pfx + _m.start(), 1, self._dim_fmt)
        for _m in re.finditer(r'`', text[_pfx:]):
            self.setFormat(_pfx + _m.start(), 1, self._dim_fmt)

        # Inline: bold, italic, code, links
        for pat, fmt, ms, me in self._inline:
            for im in pat.finditer(text):
                self.setFormat(im.start(), im.end() - im.start(), fmt)
                if ms:
                    self.setFormat(im.start(), ms, self._invis_fmt)
                    self.setFormat(im.end() - me, me, self._invis_fmt)

        # Bare URL detection (applied after inline so URLs inside []() still get coloured)
        for m in self._url_re.finditer(text):
            url_lower = m.group(0).lower()
            fmt = (
                self._scope_url_fmt
                if self._scope_domains and any(d in url_lower for d in self._scope_domains)
                else self._url_fmt
            )
            self.setFormat(m.start(), m.end() - m.start(), fmt)

        # Severity / priority keywords
        for pat, fmt in self._sev_fmts:
            for m in pat.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)

    @staticmethod
    def _make_kw_fmt(color: str, bold: bool = False) -> QTextCharFormat:
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        if bold:
            fmt.setFontWeight(QFont.Bold)
        return fmt

    def set_scope_domains(self, domains: list):
        """Update the list of scope domains used for URL highlighting."""
        self._scope_domains = [d.lower().strip() for d in domains if d.strip()]
        self.rehighlight()


class _NotesDragHandle(QWidget):
    """Thin strip at the top of the floating notes panel — drag to resize."""

    def __init__(self, drag_callback, parent=None):
        super().__init__(parent)
        self._drag_cb  = drag_callback
        self._dragging = False
        self._last_y   = 0
        self.setFixedHeight(8)
        self.setCursor(Qt.SizeVerCursor)
        self.setToolTip("Drag up / down to resize notes panel")
        self.setStyleSheet(
            "background: #3a3a5c;"
            "border-top: 2px solid #7eb8f7;"
            "border-bottom: 1px solid #585b70;"
        )

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._last_y   = event.globalY()

    def mouseMoveEvent(self, event):
        if self._dragging:
            delta        = self._last_y - event.globalY()
            self._last_y = event.globalY()
            self._drag_cb(delta)

    def mouseReleaseEvent(self, event):
        self._dragging = False


class _NotesEditor(QTextEdit):
    """
    QTextEdit with smart list continuation, Ctrl+T timestamp, Ctrl+F search toggle,
    and Ctrl+Click URL opening.
      - Numbered lists  (1. 2. 3. …)
      - Bullet lists    (- / * / + )
      - Checkboxes      (- [ ] )
      Pressing Enter on an empty list item removes the prefix (exit the list).
    """

    search_toggled = pyqtSignal()   # emitted when user presses Ctrl+F

    import re as _cls_re  # class-level import so no module-level name pollution

    # Patterns: group 1 = leading spaces, group 2 = the list marker
    _ORDERED_RE   = _cls_re.compile(r'^(\s*)(\d+)(\.\s)')
    _CHECKBOX_RE  = _cls_re.compile(r'^(\s*)(- \[[ xX]\] )')
    _BULLET_RE    = _cls_re.compile(r'^(\s*)([-*+] )')
    _URL_RE_CLICK = _cls_re.compile(r'https?://[^\s\)\]"\' <>\x00-\x1f]+')

    def mouseMoveEvent(self, event):
        """Show pointing-hand cursor when Ctrl is held and pointer is over a URL."""
        if event.modifiers() == Qt.ControlModifier:
            cursor     = self.cursorForPosition(event.pos())
            text       = cursor.block().text()
            pos_in_blk = cursor.positionInBlock()
            on_url = any(
                m.start() <= pos_in_blk < m.end()
                for m in self._URL_RE_CLICK.finditer(text)
            )
            self.viewport().setCursor(
                Qt.PointingHandCursor if on_url else Qt.IBeamCursor
            )
        else:
            self.viewport().setCursor(Qt.IBeamCursor)
        super().mouseMoveEvent(event)

    def mousePressEvent(self, event):
        """Ctrl+Click on a URL opens it in the default browser."""
        if event.button() == Qt.LeftButton and event.modifiers() == Qt.ControlModifier:
            cursor     = self.cursorForPosition(event.pos())
            text       = cursor.block().text()
            pos_in_blk = cursor.positionInBlock()
            for m in self._URL_RE_CLICK.finditer(text):
                if m.start() <= pos_in_blk < m.end():
                    QDesktopServices.openUrl(QUrl(m.group(0)))
                    return
        super().mousePressEvent(event)

    def _show_slash_menu(self):
        """Show the slash-command popup menu at the cursor position."""
        from datetime import datetime

        # Each entry: (display label, callable that does the insertion)
        def _ins(text):
            c = self.textCursor()
            # Delete the '/' trigger character on the current line first
            c.select(QTextCursor.LineUnderCursor)
            c.removeSelectedText()
            c.insertText(text)
            self.setTextCursor(c)

        def _ins_wrap(open_mark, close_mark):
            """Insert open+close markers and place cursor between them."""
            c = self.textCursor()
            c.select(QTextCursor.LineUnderCursor)
            c.removeSelectedText()
            c.insertText(open_mark + close_mark)
            c.setPosition(c.position() - len(close_mark))
            self.setTextCursor(c)

        def _ins_wrap_sel(open_mark, close_mark, placeholder):
            """Insert markers with placeholder selected — user just types over it."""
            c = self.textCursor()
            c.select(QTextCursor.LineUnderCursor)
            c.removeSelectedText()
            start = c.position()
            c.insertText(open_mark + placeholder + close_mark)
            # Select the placeholder so typing replaces it
            c.setPosition(start + len(open_mark))
            c.setPosition(start + len(open_mark) + len(placeholder), QTextCursor.KeepAnchor)
            self.setTextCursor(c)

        def _ins_code_block():
            c = self.textCursor()
            c.select(QTextCursor.LineUnderCursor)
            c.removeSelectedText()
            c.insertText("\n```\n\n```")
            pos = c.position() - 4
            c.setPosition(pos)
            self.setTextCursor(c)

        def _ins_timestamp():
            c = self.textCursor()
            c.select(QTextCursor.LineUnderCursor)
            c.removeSelectedText()
            c.insertText(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] ")
            self.setTextCursor(c)

        entries = [
            # ── Time ──────────────────────────────────────────────────────
            ("📅  Timestamp             [YYYY-MM-DD HH:MM]",  _ins_timestamp),
            # ── Structure ─────────────────────────────────────────────────
            ("#   Heading 1",                                  lambda: _ins("# ")),
            ("##  Heading 2",                                  lambda: _ins("## ")),
            ("### Heading 3",                                  lambda: _ins("### ")),
            ("─── Horizontal rule",                           lambda: _ins("\n\n---\n\n")),
            # ── Lists ─────────────────────────────────────────────────────
            ("•   Bullet list",                               lambda: _ins("- ")),
            ("1.  Numbered list",                             lambda: _ins("1. ")),
            ("☐   Checkbox",                                  lambda: _ins("- [ ] ")),
            # ── Formatting ────────────────────────────────────────────────
            ("**  Bold",                                      lambda: _ins_wrap_sel("**", "**", "bold")),
            ("*   Italic",                                    lambda: _ins_wrap_sel("*", "*", "italic")),
            ("`   Inline code",                               lambda: _ins_wrap_sel("`", "`", "code")),
            ("{}  Code block",                                _ins_code_block),
            (">   Blockquote",                                lambda: _ins("> ")),
            # ── Severity / Priority ───────────────────────────────────────
            ("🔴  CRITICAL",                                   lambda: _ins("CRITICAL ")),
            ("🟠  HIGH",                                       lambda: _ins("HIGH ")),
            ("🟡  MEDIUM",                                     lambda: _ins("MEDIUM ")),
            ("🔵  LOW",                                        lambda: _ins("LOW ")),
            ("ℹ️   INFO",                                      lambda: _ins("INFO ")),
            ("📌  TODO",                                       lambda: _ins("TODO: ")),
            ("✅  FIXED",                                      lambda: _ins("FIXED ")),
            # ── Templates ─────────────────────────────────────────────────
            ("📋  Finding template",  lambda: _ins(
                "## Finding: [Title]\n"
                "**Severity:** HIGH\n"
                "**URL:** \n"
                "**Parameter:** \n"
                "**Description:** \n"
                "**Impact:** \n"
                "**PoC:**\n```\n\n```\n"
                "**Remediation:** \n"
            )),
        ]

        # Section grouping for separators
        _SECTIONS = [
            {"📅"},
            {"#", "##", "###", "───"},
            {"•", "1.", "☐"},
            {"**", "*", "`", "{}", ">"},
            {"🔴", "🟠", "🟡", "🔵", "ℹ️", "📌", "✅"},
            {"📋"},
        ]

        def _section_of(label):
            key = label.split()[0]
            for i, s in enumerate(_SECTIONS):
                if key in s:
                    return i
            return -1

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background: #1e1e2e; color: #cdd6f4;"
            "  border: 1px solid #45475a; border-radius: 6px; font-size: 13px;"
            "  font-family: 'Fira Code', 'Consolas', monospace; padding: 4px 0; }"
            "QMenu::item { padding: 5px 18px 5px 10px; }"
            "QMenu::item:selected { background: #313244; color: #cdd6f4; border-radius: 4px; }"
            "QMenu::separator { height: 1px; background: #45475a; margin: 3px 8px; }"
        )

        prev_sec = None
        for label, cb in entries:
            sec = _section_of(label)
            if prev_sec is not None and sec != prev_sec:
                menu.addSeparator()
            prev_sec = sec
            act = menu.addAction(label)
            act.triggered.connect(cb)

        rect      = self.cursorRect()
        global_pt = self.mapToGlobal(rect.bottomLeft())
        menu.exec_(global_pt)

    def keyPressEvent(self, event):
        # Ctrl+T — insert ISO timestamp
        if event.key() == Qt.Key_T and event.modifiers() == Qt.ControlModifier:
            from datetime import datetime
            self.textCursor().insertText(f"[{datetime.now().strftime('%Y-%m-%d %H:%M')}] ")
            return
        # Ctrl+F — toggle the inline search bar
        if event.key() == Qt.Key_F and event.modifiers() == Qt.ControlModifier:
            self.search_toggled.emit()
            return
        # Space after '/' at start of typed text → slash-command menu
        if event.key() == Qt.Key_Space:
            cursor = self.textCursor()
            line   = cursor.block().text()
            pos    = cursor.positionInBlock()
            # Trigger when the only text on the line so far is '/'
            if line[:pos].strip() == '/':
                self._show_slash_menu()
                return
        if event.key() not in (Qt.Key_Return, Qt.Key_Enter):
            super().keyPressEvent(event)
            return

        cursor   = self.textCursor()
        block    = cursor.block()
        line     = block.text()

        # Smart exit: if cursor is sitting on/inside a closing inline marker
        # (**bold|**  *italic|*  `code|`), jump past it before inserting newline
        # so the closing marker doesn't end up alone on the next line.
        if not cursor.hasSelection():
            _bpos = cursor.positionInBlock()
            for _span_pat, _clen in [
                (r'\*\*[^*\n]+?\*\*', 2),
                (r'(?<!\*)\*(?!\*)[^*\n]+?(?<!\*)\*(?!\*)', 1),
                (r'`[^`\n]+?`', 1),
            ]:
                for _sm in re.finditer(_span_pat, line):
                    if _sm.end() - _clen <= _bpos < _sm.end():
                        cursor.setPosition(cursor.position() + (_sm.end() - _bpos))
                        self.setTextCursor(cursor)
                        cursor = self.textCursor()
                        break

        # --- numbered list ---
        m = self._ORDERED_RE.match(line)
        if m:
            indent, num_str, dot_sp = m.group(1), m.group(2), m.group(3)
            content_after_marker = line[m.end():]
            if not content_after_marker.strip():
                # Empty item → exit list, remove marker
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.insertText('')
                cursor.insertBlock()
            else:
                next_num = int(num_str) + 1
                super().keyPressEvent(event)
                self.textCursor().insertText(f"{indent}{next_num}{dot_sp}")
            return

        # --- checkbox ---
        m = self._CHECKBOX_RE.match(line)
        if m:
            indent, marker = m.group(1), m.group(2)
            content_after_marker = line[m.end():]
            if not content_after_marker.strip():
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.insertText('')
                cursor.insertBlock()
            else:
                super().keyPressEvent(event)
                self.textCursor().insertText(f"{indent}- [ ] ")
            return

        # --- bullet list ---
        m = self._BULLET_RE.match(line)
        if m:
            indent, marker = m.group(1), m.group(2)
            content_after_marker = line[m.end():]
            if not content_after_marker.strip():
                cursor.select(QTextCursor.BlockUnderCursor)
                cursor.insertText('')
                cursor.insertBlock()
            else:
                super().keyPressEvent(event)
                self.textCursor().insertText(f"{indent}{marker}")
            return

        super().keyPressEvent(event)


class _CloseBtn(QLabel):
    """
    A ✕ label that behaves like a button with pixel-accurate hit area.
    Uses QLabel instead of QPushButton so that hover/enter/leave events are
    strictly confined to the widget's exact bounding rect — QPushButton's
    hover zone bleeds into surrounding layout space regardless of setFixedSize.
    """
    clicked = pyqtSignal()

    def __init__(self, normal_color: str, hover_color: str, size: int = 16, parent=None):
        super().__init__("\u2715", parent)
        self._normal = normal_color
        self._hover  = hover_color
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.setCursor(Qt.PointingHandCursor)
        self._set_color(False)

    def _set_color(self, hovered: bool):
        c = self._hover if hovered else self._normal
        self.setStyleSheet(
            f"QLabel {{ color: {c}; font-size: 11px; font-weight: bold;"
            f"  background: transparent; border: none; padding: 0; margin: 0; }}"
        )

    def enterEvent(self, event):
        self._set_color(True)
        super().enterEvent(event)

    def leaveEvent(self, event):
        self._set_color(False)
        super().leaveEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(event.pos()):
            self.clicked.emit()
        super().mousePressEvent(event)


class _NotesTabBar(QTabBar):
    """Tab bar with double-click-to-rename and double-click-empty-to-add-tab."""
    add_tab_requested = pyqtSignal()

    def mouseDoubleClickEvent(self, event):
        idx = self.tabAt(event.pos())
        if idx >= 0:
            new_name, ok = QInputDialog.getText(
                self, "Rename Tab", "Tab name:", text=self.tabText(idx)
            )
            if ok and new_name.strip():
                self.setTabText(idx, new_name.strip())
        else:
            # Double-click on empty bar area → new tab
            self.add_tab_requested.emit()
        super().mouseDoubleClickEvent(event)


class _NotesSearchBar(QWidget):
    """Compact inline find-bar for the notes panel."""

    def __init__(self, get_editor, parent=None):
        super().__init__(parent)
        self._get_editor = get_editor
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)

        find_lbl = QLabel("Find:")
        find_lbl.setStyleSheet("color: #a6adc8; font-size: 12px;")
        layout.addWidget(find_lbl)

        self._input = QLineEdit()
        self._input.setPlaceholderText("Search notes…  (Enter = next  Shift+Enter = prev  Esc = close)")
        self._input.setFixedHeight(24)
        self._input.setStyleSheet(
            "QLineEdit { background: #1e1e2e; color: #cdd6f4;"
            "  border: 1px solid #45475a; border-radius: 3px; padding: 0 4px; font-size: 12px; }"
            "QLineEdit:focus { border-color: #89b4fa; }"
        )
        self._input.textChanged.connect(self._on_changed)
        self._input.returnPressed.connect(self._find_next)
        layout.addWidget(self._input)

        self._count_lbl = QLabel()
        self._count_lbl.setStyleSheet("color: #a6adc8; font-size: 11px; min-width: 70px;")
        layout.addWidget(self._count_lbl)

        _btn_style = (
            "QPushButton { background: #313244; color: #cdd6f4;"
            "  border: 1px solid #45475a; border-radius: 3px; font-size: 12px; }"
            "QPushButton:hover { background: #89b4fa; color: #000; }"
        )
        for icon, tip, cb in [
            ("▲", "Previous match (Shift+Enter)", self._find_prev),
            ("▼", "Next match (Enter)",           self._find_next),
            ("✕", "Close search bar (Esc)",       self.hide_bar),
        ]:
            btn = QPushButton(icon)
            btn.setFixedSize(24, 24)
            btn.setToolTip(tip)
            btn.setStyleSheet(_btn_style)
            btn.clicked.connect(cb)
            layout.addWidget(btn)

        self.setStyleSheet("background: #181825; border-top: 1px solid #45475a;")
        self.setFixedHeight(34)
        self.hide()

    def show_bar(self):
        self.show()
        self._input.setFocus()
        self._input.selectAll()

    def hide_bar(self):
        self.hide()
        ed = self._get_editor()
        if ed:
            ed.setFocus()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            self.hide_bar()
        elif event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                self._find_prev()
            else:
                self._find_next()
        else:
            super().keyPressEvent(event)

    def _on_changed(self, text: str):
        ed = self._get_editor()
        if not ed:
            return
        if not text:
            self._count_lbl.setText("")
            return
        count = ed.toPlainText().lower().count(text.lower())
        if count == 0:
            self._count_lbl.setText("no match")
            self._count_lbl.setStyleSheet("color: #f38ba8; font-size: 11px; min-width: 70px;")
        else:
            self._count_lbl.setText(f"{count} match{'es' if count > 1 else ''}")
            self._count_lbl.setStyleSheet("color: #a6e3a1; font-size: 11px; min-width: 70px;")
        # jump to first occurrence from start
        c = ed.textCursor()
        c.movePosition(QTextCursor.Start)
        ed.setTextCursor(c)
        ed.find(text)

    def _find_next(self):
        text = self._input.text()
        if not text:
            return
        ed = self._get_editor()
        if not ed:
            return
        if not ed.find(text):
            # wrap around
            c = ed.textCursor()
            c.movePosition(QTextCursor.Start)
            ed.setTextCursor(c)
            ed.find(text)

    def _find_prev(self):
        text = self._input.text()
        if not text:
            return
        ed = self._get_editor()
        if ed:
            if not ed.find(text, QTextDocument.FindBackward):
                c = ed.textCursor()
                c.movePosition(QTextCursor.End)
                ed.setTextCursor(c)
                ed.find(text, QTextDocument.FindBackward)


class ToolsConfigDialog(QDialog):
    """Settings dialog organised into tabs: Tokens | AI Settings | Tools & Wordlists."""

    def __init__(self, current_settings: dict, parent=None, open_tab: int = 0):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(560)
        self.setMinimumHeight(520)
        self.setStyleSheet(f"QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}")

        root = QVBoxLayout(self)
        root.setSpacing(8)

        # ── Tab widget ────────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 1px solid {COLOR_BORDER}; "
            f"background: {COLOR_BACKGROUND}; }}"
            f"QTabBar::tab {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_MUTED}; "
            f"padding: 6px 18px; border: 1px solid {COLOR_BORDER}; border-bottom: none; "
            f"border-radius: 4px 4px 0 0; }}"
            f"QTabBar::tab:selected {{ background: {COLOR_BACKGROUND}; color: {COLOR_TEXT_BRIGHT}; "
            f"font-weight: bold; }}"
        )

        # ═══════════════════════════════════════════════════════════════════
        # TAB 1 — Tokens
        # ═══════════════════════════════════════════════════════════════════
        tokens_w = QWidget()
        tok_lay = QVBoxLayout(tokens_w)
        tok_lay.setContentsMargins(14, 14, 14, 14)
        tok_lay.setSpacing(10)
        tok_form = QFormLayout()
        tok_form.setSpacing(10)

        def _fedit(placeholder="", echo_password=True, value=""):
            e = QLineEdit()
            e.setPlaceholderText(placeholder)
            e.setText(value)
            if echo_password:
                e.setEchoMode(QLineEdit.Password)
            e.setStyleSheet(
                f"background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT}; "
                f"border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 4px 8px;"
            )
            return e

        # GitHub token
        self.github_token_edit = _fedit("ghp_…", value=current_settings.get("github_token", ""))
        tok_form.addRow(_lbl("GitHub Token:"), self.github_token_edit)

        # Ngrok authtoken
        self.ngrok_token_edit = _fedit(
            "Paste your ngrok authtoken (ngrok.com/signup)",
            value=current_settings.get("ngrok_authtoken", ""),
        )
        tok_form.addRow(_lbl("Ngrok Authtoken:"), self.ngrok_token_edit)

        ngrok_hint = QLabel(
            "Used in the JWT → Key Manager JWKS server to create public ngrok tunnels. "
            "Leave blank for anonymous (limited) tunnels.<br>"
            f"<a href='https://ngrok.com' style='color:{COLOR_ACCENT};'>https://ngrok.com</a>"
            " — sign up for a free authtoken."
        )
        ngrok_hint.setOpenExternalLinks(True)
        ngrok_hint.setTextFormat(Qt.RichText)
        ngrok_hint.setWordWrap(True)
        ngrok_hint.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 10px; "
            f"background: {COLOR_DARK_BG}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 4px; padding: 5px 10px;"
        )
        tok_form.addRow(ngrok_hint)

        tok_lay.addLayout(tok_form)
        tok_lay.addStretch()
        tabs.addTab(tokens_w, "  Tokens")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 2 — AI Settings  (all existing AI logic, unchanged)
        # ═══════════════════════════════════════════════════════════════════
        ai_w = QWidget()
        ai_outer = QVBoxLayout(ai_w)
        ai_outer.setContentsMargins(14, 14, 14, 14)
        ai_outer.setSpacing(8)

        ai_scroll = QScrollArea()
        ai_scroll.setWidgetResizable(True)
        ai_scroll.setFrameShape(QFrame.NoFrame)
        ai_scroll.setStyleSheet("background: transparent;")
        ai_inner = QWidget()
        ai_scroll.setWidget(ai_inner)
        ai_form = QFormLayout(ai_inner)
        ai_form.setSpacing(10)

        # ── Per-provider API key caches ───────────────────────────────────
        self._current_provider = current_settings.get("ai_provider", "openai")
        self._api_keys_cache   = dict(current_settings.get("ai_provider_keys", {}))
        _legacy_key = current_settings.get("ai_api_key", "")
        if _legacy_key and self._current_provider not in self._api_keys_cache:
            self._api_keys_cache[self._current_provider] = _legacy_key
        self._provider_last_models = dict(current_settings.get("ai_provider_last_models", {}))
        self._sec_current_provider = current_settings.get("ai_secondary_provider", "none") or "none"
        self._sec_api_keys_cache   = dict(current_settings.get("ai_secondary_provider_keys", {}))
        self._sec_provider_last_models = dict(current_settings.get("ai_secondary_provider_last_models", {}))

        _cb_style = (
            f"background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 4px 8px;"
        )

        self.ai_provider_combo = QComboBox()
        self.ai_provider_combo.addItems(["openai", "anthropic", "groq", "gemini", "openrouter", "ollama"])
        self.ai_provider_combo.setCurrentText(current_settings.get("ai_provider", "openai"))
        self.ai_provider_combo.setStyleSheet(_cb_style)
        self.ai_provider_combo.currentTextChanged.connect(self._on_ai_provider_changed)
        ai_form.addRow(_lbl("Provider:"), self.ai_provider_combo)

        self.ai_api_key_edit = QLineEdit()
        self.ai_api_key_edit.setPlaceholderText("API key (not required for Ollama)")
        self.ai_api_key_edit.setText(self._api_keys_cache.get(self._current_provider, ""))
        self.ai_api_key_edit.setEchoMode(QLineEdit.Password)
        ai_form.addRow(_lbl("API Key:"), self.ai_api_key_edit)

        self._ai_hint_lbl = QLabel()
        self._ai_hint_lbl.setOpenExternalLinks(True)
        self._ai_hint_lbl.setTextFormat(Qt.RichText)
        self._ai_hint_lbl.setWordWrap(True)
        self._ai_hint_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: 11px; "
            f"background: {COLOR_DARK_BG}; border: 1px solid {COLOR_BORDER}; "
            f"border-radius: 4px; padding: 6px 10px;"
        )
        ai_form.addRow(self._ai_hint_lbl)

        self.ai_model_combo = QComboBox()
        self.ai_model_combo.setEditable(True)
        self.ai_model_combo.setInsertPolicy(QComboBox.InsertAtTop)
        self.ai_model_combo.setStyleSheet(_cb_style)
        self.ai_model_combo.currentTextChanged.connect(self._on_ai_model_changed)
        ai_form.addRow(_lbl("Model:"), self.ai_model_combo)

        self._ai_cost_lbl = QLabel()
        self._ai_cost_lbl.setWordWrap(True)
        self._ai_cost_lbl.setTextFormat(Qt.RichText)
        self._ai_cost_lbl.setStyleSheet(f"font-size: 11px; padding: 5px 10px; border-radius: 4px;")
        ai_form.addRow(self._ai_cost_lbl)

        self.ai_base_url_edit = QLineEdit()
        self.ai_base_url_edit.setPlaceholderText("http://localhost:11434  (Ollama only)")
        self.ai_base_url_edit.setText(current_settings.get("ai_base_url", ""))
        ai_form.addRow(_lbl("Base URL:"), self.ai_base_url_edit)

        self._on_ai_provider_changed(self.ai_provider_combo.currentText())
        saved_model = current_settings.get("ai_model", "")
        if saved_model:
            self.ai_model_combo.setCurrentText(saved_model)

        # ── Secondary AI ──────────────────────────────────────────────────
        sec_sep = QFrame(); sec_sep.setFrameShape(QFrame.HLine)
        sec_sep.setStyleSheet(f"color: {COLOR_BORDER};")
        ai_form.addRow(sec_sep)

        sec_hdr = QLabel("  Secondary AI  (Auto-Fallback)")
        sec_hdr.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px; font-weight: bold; padding: 4px 0;")
        ai_form.addRow(sec_hdr)

        sec_desc = QLabel(
            "If the primary provider is unavailable or exhausts its token quota, "
            "Hunt automatically retries your request using this fallback provider."
        )
        sec_desc.setWordWrap(True)
        sec_desc.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 10px; padding: 2px 0 6px 0;")
        ai_form.addRow(sec_desc)

        self.ai_sec_provider_combo = QComboBox()
        self.ai_sec_provider_combo.addItems(["none", "openai", "anthropic", "groq", "gemini", "openrouter", "ollama"])
        self.ai_sec_provider_combo.setCurrentText(current_settings.get("ai_secondary_provider", "none") or "none")
        self.ai_sec_provider_combo.setStyleSheet(_cb_style)
        self.ai_sec_provider_combo.currentTextChanged.connect(self._on_ai_sec_provider_changed)
        ai_form.addRow(_lbl("Fallback Provider:"), self.ai_sec_provider_combo)

        self.ai_sec_api_key_edit = QLineEdit()
        self.ai_sec_api_key_edit.setPlaceholderText("API key for fallback provider")
        self.ai_sec_api_key_edit.setEchoMode(QLineEdit.Password)
        self.ai_sec_api_key_edit.setText(self._sec_api_keys_cache.get(self._sec_current_provider, ""))
        ai_form.addRow(_lbl("Fallback API Key:"), self.ai_sec_api_key_edit)

        self.ai_sec_model_combo = QComboBox()
        self.ai_sec_model_combo.setEditable(True)
        self.ai_sec_model_combo.setInsertPolicy(QComboBox.InsertAtTop)
        self.ai_sec_model_combo.setStyleSheet(_cb_style)
        ai_form.addRow(_lbl("Fallback Model:"), self.ai_sec_model_combo)

        self._on_ai_sec_provider_changed(self.ai_sec_provider_combo.currentText())
        saved_sec_model = current_settings.get("ai_secondary_model", "")
        if saved_sec_model:
            self.ai_sec_model_combo.setCurrentText(saved_sec_model)

        ai_outer.addWidget(ai_scroll)
        tabs.addTab(ai_w, "  AI Settings")

        # ═══════════════════════════════════════════════════════════════════
        # TAB 3 — Tools & Wordlists
        # ═══════════════════════════════════════════════════════════════════
        tools_w = QWidget()
        tools_lay = QVBoxLayout(tools_w)
        tools_lay.setContentsMargins(14, 14, 14, 14)
        tools_lay.setSpacing(10)
        tools_form = QFormLayout()
        tools_form.setSpacing(10)

        def _dir_row(label: str, setting_key: str, placeholder: str, browse_slot):
            edit = QLineEdit()
            edit.setText(current_settings.get(setting_key, ""))
            edit.setPlaceholderText(placeholder)
            edit.setStyleSheet(
                f"background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT}; "
                f"border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 4px 8px;"
            )
            row = QHBoxLayout()
            row.addWidget(edit)
            btn = QPushButton("Browse…")
            btn.setStyleSheet(
                f"background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT}; "
                f"border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 4px 8px;"
            )
            btn.clicked.connect(browse_slot)
            row.addWidget(btn)
            tools_form.addRow(_lbl(label), row)
            return edit

        self.tools_dir_edit = _dir_row(
            "Tools Directory:", "tools_dir",
            os.path.expanduser("~/tools"), self._browse_tools_dir,
        )
        self.tools_dir_edit.setText(current_settings.get("tools_dir", os.path.expanduser("~/tools")))

        self.seclists_dir_edit = _dir_row(
            "Seclists Directory:", "seclists_dir",
            "/usr/share/seclists", self._browse_seclists_dir,
        )

        self.patt_dir_edit = _dir_row(
            "PayloadsAllTheThings:", "patt_dir",
            "/opt/PayloadsAllTheThings", self._browse_patt_dir,
        )

        tools_lay.addLayout(tools_form)
        tools_lay.addStretch()
        tabs.addTab(tools_w, "  Tools & Wordlists")

        # ── Finalize ──────────────────────────────────────────────────────
        tabs.setCurrentIndex(open_tab)
        root.addWidget(tabs)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _browse_tools_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Tools Directory", self.tools_dir_edit.text())
        if d:
            self.tools_dir_edit.setText(d)

    def _browse_seclists_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select Seclists Directory", self.seclists_dir_edit.text())
        if d:
            self.seclists_dir_edit.setText(d)

    def _browse_patt_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Select PayloadsAllTheThings Directory", self.patt_dir_edit.text())
        if d:
            self.patt_dir_edit.setText(d)

    def _on_ai_provider_changed(self, provider: str):
        """Save current API key to cache, restore saved key for new provider, update model list & hints."""
        _MODELS = {
            "openai": [
                "gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-4",
                "gpt-3.5-turbo", "o1", "o1-mini", "o3-mini",
            ],
            "anthropic": [
                "claude-sonnet-4-5",
                "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022",
                "claude-3-opus-20240229", "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307",
            ],
            "groq": [
                "llama-3.3-70b-versatile", "llama-3.1-8b-instant",
                "llama3-70b-8192", "llama3-8b-8192",
                "mixtral-8x7b-32768", "gemma2-9b-it",
                "llama-3.2-3b-preview", "llama-3.2-90b-vision-preview",
            ],
            "gemini": [
                "gemini-2.0-flash", "gemini-2.0-flash-lite",
                "gemini-flash-latest",
                "gemini-1.5-flash", "gemini-1.5-flash-latest", "gemini-1.5-flash-8b", "gemini-1.5-pro",
            ],
            "openrouter": [
                "meta-llama/llama-3.3-70b-instruct:free",
                "google/gemini-flash-1.5:free",
                "mistralai/mistral-7b-instruct:free",
                "deepseek/deepseek-chat:free",
                "qwen/qwen-2.5-72b-instruct",
                "anthropic/claude-3.5-sonnet",
                "openai/gpt-4o",
                "microsoft/phi-4",
            ],
            "ollama": [
                "qwen2.5-coder:14b", "qwen2.5-coder:7b", "qwen2.5-coder:32b",
                "qwen2.5", "llama3", "llama3.1", "llama3.2",
                "mistral", "mistral-nemo", "gemma2", "gemma3",
                "phi3", "phi4", "deepseek-r1", "codellama", "llava",
            ],
        }

        # Save the current API key and model to caches before switching
        if hasattr(self, "_api_keys_cache") and hasattr(self, "_current_provider"):
            self._api_keys_cache[self._current_provider] = self.ai_api_key_edit.text().strip()
            self._provider_last_models[self._current_provider] = self.ai_model_combo.currentText().strip()
        self._current_provider = provider

        # Restore saved API key for the newly selected provider
        self.ai_api_key_edit.setText(self._api_keys_cache.get(provider, ""))

        # Rebuild model list — restore last-used model for this provider
        last_model = self._provider_last_models.get(provider, "")
        self.ai_model_combo.blockSignals(True)
        self.ai_model_combo.clear()
        models = _MODELS.get(provider, [])
        self.ai_model_combo.addItems(models)
        if last_model:
            self.ai_model_combo.setCurrentText(last_model)
        elif models:
            self.ai_model_combo.setCurrentIndex(0)
        self.ai_model_combo.blockSignals(False)
        self._on_ai_model_changed(self.ai_model_combo.currentText())

        # Base-URL field: only needed for Ollama
        self.ai_base_url_edit.setVisible(provider == "ollama")

        # Provider-specific hint text
        link_style = f"color: {COLOR_ACCENT};"
        if provider == "openai":
            hint = (
                "<b>OpenAI API key:</b> sign in at "
                f"<a href='https://platform.openai.com/api-keys' style='{link_style}'>platform.openai.com/api-keys</a> "
                "\u2192 <i>Create new secret key</i>. Key starts with <code>sk-</code>.<br>"
                f"<span style='color:{COLOR_WARNING};'>\u26a0 Key shown only once \u2014 save it securely.</span>"
            )
        elif provider == "anthropic":
            hint = (
                "<b>Anthropic API key:</b> sign in at "
                f"<a href='https://console.anthropic.com/settings/keys' style='{link_style}'>console.anthropic.com</a> "
                "\u2192 <i>Create Key</i>. Key starts with <code>sk-ant-</code>.<br>"
                f"<span style='color:{COLOR_WARNING};'>\u26a0 Key shown only once \u2014 save it securely.</span>"
            )
        elif provider == "groq":
            hint = (
                "<b>Groq API key \u2014 free tier available!</b> Sign in at "
                f"<a href='https://console.groq.com/keys' style='{link_style}'>console.groq.com/keys</a> "
                "\u2192 <i>Create API Key</i>. Key starts with <code>gsk_</code>.<br>"
                f"<span style='color:{COLOR_SUCCESS};'>\u2705 Generous free tier with very fast inference (great default!).</span>"
            )
        elif provider == "gemini":
            hint = (
                "<b>Google Gemini API key \u2014 free tier available!</b> Get yours at "
                f"<a href='https://aistudio.google.com/app/apikey' style='{link_style}'>aistudio.google.com/app/apikey</a>.<br>"
                f"<span style='color:{COLOR_SUCCESS};'>\u2705 Gemini Flash models have a free tier. Key starts with <code>AIza</code>.</span>"
            )
        elif provider == "openrouter":
            hint = (
                "<b>OpenRouter \u2014 100+ models via one key.</b> Sign up at "
                f"<a href='https://openrouter.ai/keys' style='{link_style}'>openrouter.ai/keys</a>. "
                "Key starts with <code>sk-or-</code>.<br>"
                f"<span style='color:{COLOR_SUCCESS};'>\u2705 Many free models available (suffix <code>:free</code>).</span>"
            )
        elif provider == "ollama":
            hint = (
                "<b>Ollama \u2014 runs locally, no API key needed.</b><br>"
                f"Install: <a href='https://ollama.com/download' style='{link_style}'>ollama.com/download</a> "
                "\u2192 <code>ollama pull qwen2.5-coder:14b</code> \u2192 <code>ollama serve</code>"
            )
        else:
            hint = ""

        self._ai_hint_lbl.setText(hint)
        self._ai_hint_lbl.setVisible(bool(hint))

    def _on_ai_sec_provider_changed(self, provider: str):
        """Save current secondary API key, restore for new provider, update secondary model list."""
        _SEC_MODELS = {
            "none":        [],
            "openai":      ["gpt-4o", "gpt-4o-mini", "gpt-3.5-turbo", "o1-mini", "o3-mini"],
            "anthropic":   ["claude-sonnet-4-5", "claude-3-5-haiku-20241022", "claude-3-haiku-20240307"],
            "groq":        ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "gemma2-9b-it"],
            "gemini":      ["gemini-2.0-flash", "gemini-2.0-flash-lite", "gemini-1.5-flash"],
            "openrouter":  ["meta-llama/llama-3.3-70b-instruct:free", "google/gemini-flash-1.5:free",
                            "mistralai/mistral-7b-instruct:free"],
            "ollama":      ["qwen2.5-coder:14b", "qwen2.5-coder:7b", "llama3.2", "mistral"],
        }

        # Save key and model before switching
        if hasattr(self, "_sec_api_keys_cache") and hasattr(self, "_sec_current_provider"):
            if self._sec_current_provider != "none":
                self._sec_api_keys_cache[self._sec_current_provider] = self.ai_sec_api_key_edit.text().strip()
                self._sec_provider_last_models[self._sec_current_provider] = self.ai_sec_model_combo.currentText().strip()
        self._sec_current_provider = provider

        # Restore saved key
        self.ai_sec_api_key_edit.setText(self._sec_api_keys_cache.get(provider, ""))

        # Enable/disable secondary fields
        is_active = provider != "none"
        self.ai_sec_api_key_edit.setEnabled(is_active)
        self.ai_sec_model_combo.setEnabled(is_active)

        # Rebuild model list — restore last-used model for this provider
        last_sec_model = self._sec_provider_last_models.get(provider, "")
        self.ai_sec_model_combo.blockSignals(True)
        self.ai_sec_model_combo.clear()
        models = _SEC_MODELS.get(provider, [])
        self.ai_sec_model_combo.addItems(models)
        if last_sec_model:
            self.ai_sec_model_combo.setCurrentText(last_sec_model)
        elif models:
            self.ai_sec_model_combo.setCurrentIndex(0)
        self.ai_sec_model_combo.blockSignals(False)

    def _on_ai_model_changed(self, model: str):
        """Update the cost warning label when a model is selected."""
        # Cost tiers: (tier_label, color, note)
        # free   = Ollama local
        # cheap  = low cost API
        # mid    = moderate cost
        # expensive = high cost
        _COST = {
            # OpenAI
            "gpt-4o":               ("\U0001f4b3 Paid",  "~$2.50/1M in \xb7 $10/1M out",  COLOR_WARNING),
            "gpt-4o-mini":          ("\U0001f4b3 Paid",  "~$0.15/1M in \xb7 $0.60/1M out (cheapest GPT-4 class)", COLOR_LOW),
            "gpt-4-turbo":          ("\U0001f4b3 Paid",  "~$10/1M in \xb7 $30/1M out",   COLOR_WARNING),
            "gpt-4":                ("\U0001f4b3 Paid",  "~$30/1M in \xb7 $60/1M out",   COLOR_CRITICAL),
            "gpt-3.5-turbo":        ("\U0001f4b3 Paid",  "~$0.50/1M in \xb7 $1.50/1M out (budget option)", COLOR_LOW),
            "o1":                   ("\U0001f4b3 Paid",  "~$15/1M in \xb7 $60/1M out",   COLOR_CRITICAL),
            "o1-mini":              ("\U0001f4b3 Paid",  "~$1.10/1M in \xb7 $4.40/1M out", COLOR_WARNING),
            "o3-mini":              ("\U0001f4b3 Paid",  "~$1.10/1M in \xb7 $4.40/1M out", COLOR_WARNING),
            # Anthropic
            "claude-sonnet-4-5":          ("\U0001f4b3 Paid", "~$3/1M in \xb7 $15/1M out",  COLOR_WARNING),
            "claude-3-5-sonnet-20241022": ("\U0001f4b3 Paid", "~$3/1M in \xb7 $15/1M out",  COLOR_WARNING),
            "claude-3-5-haiku-20241022":  ("\U0001f4b3 Paid", "~$0.80/1M in \xb7 $4/1M out (budget option)", COLOR_LOW),
            "claude-3-opus-20240229":     ("\U0001f4b3 Paid", "~$15/1M in \xb7 $75/1M out", COLOR_CRITICAL),
            "claude-3-sonnet-20240229":   ("\U0001f4b3 Paid", "~$3/1M in \xb7 $15/1M out",  COLOR_WARNING),
            "claude-3-haiku-20240307":    ("\U0001f4b3 Paid", "~$0.25/1M in \xb7 $1.25/1M out (cheapest Claude)", COLOR_LOW),
            # Groq (free tier with rate limits)
            "llama-3.3-70b-versatile":      ("\u26a1 Free tier", "Groq \u2014 fast inference, rate-limited free tier", COLOR_SUCCESS),
            "llama-3.1-8b-instant":         ("\u26a1 Free tier", "Groq \u2014 very fast, small model", COLOR_SUCCESS),
            "llama3-70b-8192":              ("\u26a1 Free tier", "Groq \u2014 free tier with rate limits", COLOR_SUCCESS),
            "llama3-8b-8192":               ("\u26a1 Free tier", "Groq \u2014 free tier, fastest option", COLOR_SUCCESS),
            "mixtral-8x7b-32768":           ("\u26a1 Free tier", "Groq \u2014 free tier, large context", COLOR_SUCCESS),
            "gemma2-9b-it":                 ("\u26a1 Free tier", "Groq \u2014 free tier", COLOR_SUCCESS),
            "llama-3.2-3b-preview":         ("\u26a1 Free tier", "Groq \u2014 free tier, ultra-fast", COLOR_SUCCESS),
            "llama-3.2-90b-vision-preview": ("\u26a1 Free tier", "Groq \u2014 vision capable, free tier", COLOR_SUCCESS),
            # Gemini (free tier for Flash models)
            "gemini-2.0-flash":        ("⚡ Free tier", "Google — free tier, very fast", COLOR_SUCCESS),
            "gemini-2.0-flash-lite":   ("⚡ Free tier", "Google — free tier, lightweight", COLOR_SUCCESS),
            "gemini-flash-latest":     ("⚡ Free tier", "Google — free tier, latest Flash model", COLOR_SUCCESS),
            "gemini-1.5-flash":        ("⚡ Free tier", "Google — free tier available", COLOR_SUCCESS),
            "gemini-1.5-flash-latest": ("⚡ Free tier", "Google — free tier, latest Flash 1.5", COLOR_SUCCESS),
            "gemini-1.5-flash-8b":     ("⚡ Free tier", "Google — free tier, smallest Flash", COLOR_SUCCESS),
            "gemini-1.5-pro":          ("💳 Paid",      "~$1.25/1M in · $5/1M out (after free quota)", COLOR_LOW),
            # OpenRouter (free models have :free suffix)
            "meta-llama/llama-3.3-70b-instruct:free": ("\U0001f49a Free", "OpenRouter \u2014 free model", COLOR_SUCCESS),
            "google/gemini-flash-1.5:free":            ("\U0001f49a Free", "OpenRouter \u2014 free model", COLOR_SUCCESS),
            "mistralai/mistral-7b-instruct:free":      ("\U0001f49a Free", "OpenRouter \u2014 free model", COLOR_SUCCESS),
            "deepseek/deepseek-chat:free":             ("\U0001f49a Free", "OpenRouter \u2014 free model", COLOR_SUCCESS),
        }

        provider = self.ai_provider_combo.currentText()

        if provider == "ollama":
            self._ai_cost_lbl.setText(
                f"<span style='color:{COLOR_SUCCESS};'>"
                "\u2705 Free \u2014 runs locally on your machine, no API charges."
                "</span>"
            )
            self._ai_cost_lbl.setStyleSheet(
                f"font-size: 11px; padding: 5px 10px; border-radius: 4px; "
                f"background: #1a3a1a; border: 1px solid {COLOR_SUCCESS};"
            )
            self._ai_cost_lbl.setVisible(True)
            return

        cost = _COST.get(model.strip())
        if cost:
            label, note, color = cost
            self._ai_cost_lbl.setText(
                f"<span style='color:{color};font-weight:bold;'>{label}</span> "
                f"<span style='color:{COLOR_TEXT_MUTED};'>{note}</span>"
            )
            bg = "#1a3a1a" if color == COLOR_SUCCESS else ("#3a2a10" if color == COLOR_WARNING else ("#3a1010" if color == COLOR_CRITICAL else "#1a2a10"))
            self._ai_cost_lbl.setStyleSheet(
                f"font-size: 11px; padding: 5px 10px; border-radius: 4px; "
                f"background: {bg}; border: 1px solid {color};"
            )
            self._ai_cost_lbl.setVisible(True)
        elif provider in ("groq", "gemini"):
            # Unknown groq/gemini model — likely free tier
            self._ai_cost_lbl.setText(
                f"<span style='color:{COLOR_SUCCESS};'>\u26a1 Likely free tier \u2014 check provider docs for limits.</span>"
            )
            self._ai_cost_lbl.setStyleSheet(
                f"font-size: 11px; padding: 5px 10px; border-radius: 4px; "
                f"background: #1a3a1a; border: 1px solid {COLOR_SUCCESS};"
            )
            self._ai_cost_lbl.setVisible(True)
        elif provider == "openrouter":
            is_free = ":free" in model
            color = COLOR_SUCCESS if is_free else COLOR_WARNING
            text = ("\U0001f49a Free model on OpenRouter" if is_free
                    else "\U0001f4b3 Paid model on OpenRouter \u2014 check openrouter.ai for pricing")
            bg = "#1a3a1a" if is_free else "#3a2a10"
            self._ai_cost_lbl.setText(f"<span style='color:{color};'>{text}</span>")
            self._ai_cost_lbl.setStyleSheet(
                f"font-size: 11px; padding: 5px 10px; border-radius: 4px; "
                f"background: {bg}; border: 1px solid {color};"
            )
            self._ai_cost_lbl.setVisible(True)
        else:
            # Unknown / custom model for openai/anthropic
            if provider in ("openai", "anthropic"):
                self._ai_cost_lbl.setText(
                    f"<span style='color:{COLOR_WARNING};'>\u26a0 Paid API \u2014 "
                    "pricing unknown for this model. Check provider docs."
                    "</span>"
                )
                self._ai_cost_lbl.setStyleSheet(
                    f"font-size: 11px; padding: 5px 10px; border-radius: 4px; "
                    f"background: #3a2a10; border: 1px solid {COLOR_WARNING};"
                )
                self._ai_cost_lbl.setVisible(True)
            else:
                self._ai_cost_lbl.setVisible(False)

    def get_settings(self) -> dict:
        # Flush current primary key and model to caches before reading
        self._api_keys_cache[self._current_provider] = self.ai_api_key_edit.text().strip()
        self._provider_last_models[self._current_provider] = self.ai_model_combo.currentText().strip()
        # Flush current secondary key and model to caches before reading
        sec_prov = self.ai_sec_provider_combo.currentText()
        if sec_prov and sec_prov != "none":
            self._sec_api_keys_cache[sec_prov] = self.ai_sec_api_key_edit.text().strip()
            self._sec_provider_last_models[sec_prov] = self.ai_sec_model_combo.currentText().strip()
        return {
            "github_token":    self.github_token_edit.text().strip(),
            "ngrok_authtoken": self.ngrok_token_edit.text().strip(),
            "tools_dir":       self.tools_dir_edit.text().strip(),
            "seclists_dir":    self.seclists_dir_edit.text().strip(),
            "patt_dir":        self.patt_dir_edit.text().strip(),
            # Primary AI settings
            "ai_provider":             self._current_provider,
            "ai_api_key":              self._api_keys_cache.get(self._current_provider, ""),
            "ai_model":                self.ai_model_combo.currentText().strip(),
            "ai_base_url":             self.ai_base_url_edit.text().strip(),
            "ai_provider_keys":        dict(self._api_keys_cache),
            "ai_provider_last_models": dict(self._provider_last_models),
            # Secondary AI (auto-fallback)
            "ai_secondary_provider":             sec_prov if sec_prov != "none" else "",
            "ai_secondary_model":                self.ai_sec_model_combo.currentText().strip(),
            "ai_secondary_provider_keys":        dict(self._sec_api_keys_cache),
            "ai_secondary_provider_last_models": dict(self._sec_provider_last_models),
        }

# ─────────────────────────────────────────────────────────────────────────────
# Tab pop-out support
# ─────────────────────────────────────────────────────────────────────────────

class TabPopoutWindow(QMainWindow):
    """
    A detached window hosting a single popped-out tab.
    Closing it re-docks the widget at its original position.
    """

    def __init__(self, widget: QWidget, tab_index: int,
                 tab_label: str, main_window, parent=None):
        super().__init__(parent)
        self._widget      = widget
        self._tab_index   = tab_index
        self._tab_label   = tab_label
        self._main_window = main_window

        clean_label = tab_label.replace("⨁ ", "")
        self.setWindowTitle(f"🔲  {clean_label}  —  HackRecon")
        self.resize(1200, 800)

        try:
            self.setStyleSheet(main_window.styleSheet())
        except Exception:
            pass

        self.setCentralWidget(widget)
        widget.show()

        self.statusBar().showMessage(
            "Close this window to dock the tab back into the main window."
        )
        self.statusBar().setStyleSheet(
            "QStatusBar { font-size: 11px; color: #808080; }"
        )

    def closeEvent(self, event):
        """Re-dock the widget back into the main tab_widget on window close."""
        try:
            mw = self._main_window
            if mw is None:
                event.accept()
                return
            tw = mw.tab_widget
            insert_at = min(self._tab_index, tw.count())
            tw.insertTab(insert_at, self._widget, self._tab_label)
            tw.setCurrentIndex(insert_at)
            self._widget.show()
            mw._popped_tabs.pop(id(self._widget), None)
        except Exception as exc:
            logger.error(f"[PopoutWindow] re-dock error: {exc}")
        event.accept()


class PopoutTabBar(QTabBar):
    """
    Custom tab bar:
      • Double-click → pop tab out into floating window
      • Right-click  → context menu with "Pop out" option
    """

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self._main_window = main_window

    def mouseDoubleClickEvent(self, event):
        idx = self.tabAt(event.pos())
        if idx >= 0:
            self._main_window.popout_tab(idx)
        else:
            super().mouseDoubleClickEvent(event)

    def contextMenuEvent(self, event):
        idx = self.tabAt(event.pos())
        if idx < 0:
            super().contextMenuEvent(event)
            return
        menu = QMenu(self)
        menu.setStyleSheet("""
            QMenu {
                background-color: #2d2d2d; color: #cccccc;
                border: 1px solid #3e3e3e; padding: 4px;
            }
            QMenu::item { padding: 6px 20px 6px 10px; border-radius: 3px; }
            QMenu::item:selected { background-color: #0e639c; color: #fff; }
        """)
        popout_act = menu.addAction("🔲  Pop out in window")
        if menu.exec_(event.globalPos()) == popout_act:
            self._main_window.popout_tab(idx)


# ─────────────────────────────────────────────────────────────────────────────
# Main window
# ─────────────────────────────────────────────────────────────────────────────

class HuntBurpGUI(
    QMainWindow,
    HTTPHistoryTab,
    DecoderTab,
    PayloadsTab,
    ComparerTab,
):
    """Main application window – Burp Suite style, now fully standalone."""

    def __init__(self, project_slug: str = "", project_domain: str = "",
                 project_subdomain: str = ""):
        super().__init__()

        # Set global reference for signal handlers
        global _main_window_ref
        _main_window_ref = self

        # NOTE: _kill_orphaned_mitmdump() is intentionally NOT called here.
        # main() runs it in a background thread (with the splash pumping events)
        # before constructing this window, so it is already done by this point.

        # ── Project / scope state ────────────────────────────────────────
        self._project_slug      = project_slug
        self._project_domain    = project_domain
        self._project_subdomain = project_subdomain
        self._project_paths: Optional[Dict[str, str]] = None

        if project_slug:
            pm.ensure_project_dirs(project_slug)
            self._project_paths = pm.get_project_paths(project_slug)

        # ── Data storage ────────────────────────────────────────────────
        self.findings = deque(maxlen=MAX_FINDINGS_IN_MEMORY)
        self.current_finding = None
        self.notes_storage = {}
        self.highlighted_rows = {}

        self.request_current_match  = 0
        self.request_total_matches  = 0
        self.response_current_match = 0
        self.response_total_matches = 0

        self.current_request_raw  = ""
        self.current_response_raw = ""
        self.current_vuln_params  = {}

        # ── Proxy state ─────────────────────────────────────────────────
        self.proxy_process        = None
        self.proxy_log_handle     = None
        self.proxy_port           = 8888
        self.proxy_upstream       = ""
        self.proxy_script_file    = INLINE_ADDON_SCRIPT
        self.proxy_running        = False
        self.proxy_status_label   = None
        self.proxy_output_reader  = None
        self.proxy_health_monitor = None
        self._proxy_lock          = threading.Lock()
        self._is_intercept_popup_open = False
        self._global_settings = _load_global_settings()

        # ── Build all widgets (must happen on main thread) ───────────────
        self.init_ui()

        # ── Load project notes SYNCHRONOUSLY so content is always ready
        #    before any close/save event fires (avoids empty-file race).
        self._notes_loaded = False
        self._load_project_notes()

        # ── Defer every blocking / IO-heavy call until after the event
        #    loop starts so the window appears immediately and responsive.
        #    Stagger the timers slightly so the UI stays smooth.
        QTimer.singleShot(0,    self.load_notes_from_file)
        QTimer.singleShot(50,   self.load_highlights_from_file)
        QTimer.singleShot(200,  self.start_monitoring)

        def _safe_start_proxy():
            try:
                self.start_proxy()
            except Exception as e:
                logger.error(f"Auto-start proxy failed: {e}")
                self.status_label.setText("⚠️ Proxy auto-start failed — start manually")

        QTimer.singleShot(1000, _safe_start_proxy)

    def show_tools_config_dialog(self, open_tab: int = 0):
        """Show settings dialog, optionally pre-selecting a tab (0=Tokens, 1=AI, 2=Tools)."""
        dialog = ToolsConfigDialog(self._global_settings, self, open_tab=open_tab)
        if dialog.exec_() == QDialog.Accepted:
            new_settings = dialog.get_settings()
            self._global_settings.update(new_settings)
            _save_global_settings(self._global_settings)
            self.status_label.setText("✅ Global settings saved.")
            QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def _edit_polyglot_payload(self):
        """Let the user view and edit the polyglot payload used by the Repeater."""
        try:
            from repeater_tab import _DEFAULT_POLYGLOT as _DP
        except Exception:
            _DP = (
                "'\"><script>alert(Inj3ct3d)</script>"
                "{{7*7}}${7*7}"
                "' OR '1'='1'-- "
                "; ls -la #"
                "/../../../etc/passwd"
            )
        current = self._global_settings.get("polyglot_payload", _DP)
        text, ok = QInputDialog.getMultiLineText(
            self, "Set Polyglot Payload",
            "Edit the polyglot payload.\n"
            "In the Repeater: select a value, right-click → Test Polyglot\n"
            "to replace it with this payload and send the request:",
            current,
        )
        if ok:
            self._global_settings["polyglot_payload"] = text
            _save_global_settings(self._global_settings)
            self.status_label.setText("🧬 Polyglot payload saved.")
            QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    # ── UI construction ────────────────────────────────────────────────────

    def init_ui(self):
        self.setWindowTitle("Hunt HackRecon – Security Testing Dashboard")
        self.setup_window_geometry()
        self.apply_dark_theme()

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self.create_menu_bar()

        # Project banner (slim bar between menu and tabs)
        self._build_project_banner(main_layout)

        self.tab_widget = QTabWidget()
        self.tab_widget.setDocumentMode(True)
        self.tab_widget.currentChanged.connect(self._on_tab_changed)
        # Custom tab bar: double-click or right-click → pop out
        self.tab_widget.setTabBar(PopoutTabBar(self))
        self._popped_tabs: dict = {}   # id(widget) -> TabPopoutWindow
        main_layout.addWidget(self.tab_widget)

        # Project Notes overlay panel (floats over the tab area)
        self._build_notes_panel(central)

        # The dashboard tab needs access to the main window for proxy/cookie info
        self.dashboard_tab = None 

        # ── Tabs ────────────────────────────────────────────────────────

        # Scope tab MUST be created first — DashboardTab.__init__ checks
        # hasattr(parent, "scope_tab") to wire the scope_changed signal.
        self.scope_tab = ScopeTab(self)
        self.scope_tab.scope_changed.connect(self._on_scope_changed)
        # Also feed scope changes into the HTTP history tab's scope filter
        self.scope_tab.scope_changed.connect(self._on_scope_changed_history)

        add_dashboard_tab(self)

        self.create_http_history_tab()

        # WS History tab — hidden until the first WebSocket message is captured
        self.ws_history_tab = WSHistoryTab(self)
        self._ws_tab_index = self.tab_widget.addTab(self.ws_history_tab, "WS History")
        self.tab_widget.setTabVisible(self._ws_tab_index, False)
        self.ws_history_tab.first_message_captured.connect(self._show_ws_history_tab)
        # Set the WS JSONL path immediately if project paths are already known
        self._update_ws_history_path()

        # Intercept tab (new)
        self.intercept_tab = InterceptTab(self)
        self.tab_widget.addTab(self.intercept_tab, "Intercept")
        self.intercept_tab.popup_requested.connect(self._handle_intercept_popup)
        self.intercept_tab.intercept_changed.connect(self._on_intercept_status_changed)
        if self._project_paths:
            self.intercept_tab.set_project_dir(self._project_paths["project_dir"])

        self.mapping_tab = MappingTab(self)
        self.tab_widget.addTab(self.mapping_tab, "Mapping")
        if self._project_paths:
            self.mapping_tab.set_project_dir(self._project_paths["project_dir"])

        # Attack Surface tab
        self.attack_surface_tab = AttackSurfaceTab(self)
        self.tab_widget.addTab(self.attack_surface_tab, "Attack Surface")
        if self._project_paths:
            self.attack_surface_tab.set_project_dir(self._project_paths["project_dir"])
        # Wire reference so http_history_tab can reach the attack surface tab
        self.attack_surface_tab_ref = self.attack_surface_tab

        # Repeater tab
        self.repeater_tab = RepeaterTab(self)
        self.tab_widget.addTab(self.repeater_tab, "Repeater")

        # Intruder tab
        self.intruder_tab = IntruderTab(self)
        self.tab_widget.addTab(self.intruder_tab, "Intruder")

        # Load project into relevant tabs
        if self._project_slug:
            self.scope_tab.load_project(self._project_slug)
            self.dashboard_tab.update_scope(self._project_slug, "", "")

        add_active_scanner_tab(self)

        self.param_miner = ParamMinerTab(self.tab_widget, http_history_tab=self)
        self.param_miner_ref = self.param_miner
        self.param_miner.set_http_history_tab(self)

        self.js_miner_tab = JSMinerTab(self)
        self.js_miner_ref = self.js_miner_tab

        if self._project_paths:
            self.js_miner_tab.set_project_dir(self._project_paths["project_dir"])
            self.param_miner.set_project_dir(self._project_paths["project_dir"])

        from bypass_tab import add_bypass_tab
        add_bypass_tab(self)
        self.bypass_ref = self.bypass_tab

        add_api_key_tab(self)

        # ── Group the 4 tool tabs under one "Tools" container tab ──────────
        self._build_tools_tab()

        self.create_decoder_tab()
        self.create_comparer_tab()

        # Report tab
        self.report_tab = ReportTab(self)
        self.tab_widget.addTab(self.report_tab, "Reports")
        if self._project_paths:
            self.report_tab.set_project_dir(self._project_paths["project_dir"])

        self.create_status_bar()
        # Sync the intercept status label with the real state now that it exists
        if hasattr(self, 'intercept_tab'):
            self._on_intercept_status_changed(self.intercept_tab._intercept_enabled)

    # ── Tools container tab ────────────────────────────────────────────────

    def _build_tools_tab(self):
        """
        Group Param Miner, JS Miner, Bypass and Key Tester into a single
        'Tools' tab with sub-tabs.  All _ref attributes remain unchanged so
        every send_to_* / flash_tab call still works via _switch_to_tools_subtab.
        """
        tools_container = QWidget()
        tools_layout = QVBoxLayout(tools_container)
        tools_layout.setContentsMargins(0, 0, 0, 0)
        tools_layout.setSpacing(0)

        self.tools_sub_tabs = QTabWidget()
        self.tools_sub_tabs.setDocumentMode(True)
        self.tools_sub_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {COLOR_BACKGROUND};
            }}
            QTabBar::tab {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_MUTED};
                padding: 6px 18px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
                font-size: 12px;
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT_BRIGHT};
                border-bottom: 2px solid {COLOR_ACCENT};
            }}
            QTabBar::tab:hover:!selected {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
            }}
        """)

        # Sub-tab index constants (stored so _switch_to_tools_subtab is fast)
        self._tools_subtab_map = {}

        # Sub-tab 0 : Param Miner
        self.tools_sub_tabs.addTab(self.param_miner.widget, "⚡ Param Miner")
        self._tools_subtab_map["Param Miner"] = 0

        # Sub-tab 1 : JS Miner
        self.tools_sub_tabs.addTab(self.js_miner_tab, "⛏️ JS Miner")
        self._tools_subtab_map["JS Miner"] = 1

        # Sub-tab 2 : Bypass
        bypass_widget = getattr(self, "bypass_tab", None)
        if bypass_widget is not None:
            self.tools_sub_tabs.addTab(bypass_widget, "🛡️ Bypass")
            self._tools_subtab_map["Bypass"] = 2

        # Sub-tab 3 : Key Tester  (api_key_tab is set by add_api_key_tab)
        api_key_widget = getattr(self, "api_key_tab", None)
        if api_key_widget is not None:
            idx = self.tools_sub_tabs.count()
            self.tools_sub_tabs.addTab(api_key_widget, "Key Tester")
            self._tools_subtab_map["Key Tester"] = idx
            self._tools_subtab_map["API Key"]    = idx
            self._tools_subtab_map["API Keys"]   = idx

        # Sub-tab 4 : PoC
        try:
            from poc_tab import POCTab
            self.poc_tab = POCTab(self)
            idx = self.tools_sub_tabs.count()
            self.tools_sub_tabs.addTab(self.poc_tab, "PoC Generator")
            self._tools_subtab_map["PoC"] = idx
        except Exception as e:
            import traceback
            print("[WARN] Could not load PoC tab:", e)
            print(traceback.format_exc())

        # Sub-tab 5 : JWT Analyzer
        try:
            from jwt_tab import JWTTab
            self.jwt_tab = JWTTab(self)
            idx = self.tools_sub_tabs.count()
            self.tools_sub_tabs.addTab(self.jwt_tab, " JWT")
            self._tools_subtab_map["JWT"] = idx
            self._tools_subtab_map["jwt"] = idx
        except Exception as e:
            import traceback
            print("[WARN] Could not load JWT tab:", e)
            print(traceback.format_exc())

        tools_layout.addWidget(self.tools_sub_tabs)
        self.tab_widget.addTab(tools_container, " Tools")

    def _switch_to_tools_subtab(self, subtab_name: str):
        """
        Activate the Tools main tab, then switch to the named sub-tab.
        Used by every send_to_* method and by flash_tab.
        """
        # Activate main Tools tab
        for i in range(self.tab_widget.count()):
            if "Tools" in self.tab_widget.tabText(i):
                self.tab_widget.setCurrentIndex(i)
                break
        # Activate correct sub-tab
        if hasattr(self, "tools_sub_tabs") and hasattr(self, "_tools_subtab_map"):
            idx = self._tools_subtab_map.get(subtab_name, -1)
            if idx >= 0:
                self.tools_sub_tabs.setCurrentIndex(idx)

    def _handle_intercept_popup(self, entry: dict):
        """Handle popup request from intercept tab"""
        # Only show if not currently on intercept tab
        if self.tab_widget.currentWidget() == self.intercept_tab:
            return
        
        if self._is_intercept_popup_open:
            return
            
        self._show_intercept_dialog(entry)

    def _show_intercept_dialog(self, entry: dict):
        """Show a popup dialog for the intercepted flow"""
        self._is_intercept_popup_open = True
        try:
            flow_id = entry.get("id")
            meta = entry.get("meta", {})
            flow_type = entry.get("type", "request")
            
            dialog = QDialog(self)
            dialog.setWindowTitle(f"Intercepted {flow_type.capitalize()}")
            dialog.setMinimumWidth(900)
            dialog.setMinimumHeight(600)
            
            # Apply theme
            dialog.setStyleSheet(f"""
                QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
                QLabel {{ color: {COLOR_TEXT}; }}
                QTextEdit {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; border: 1px solid {COLOR_BORDER}; font-family: {FONT_FAMILY_MONO}; }}
                QPushButton {{ padding: 6px 12px; border-radius: 4px; font-weight: bold; }}
            """)
            
            layout = QVBoxLayout(dialog)
            
            # Info
            info_text = f"{meta.get('method', '')} {meta.get('url', '')}"
            if flow_type == 'response':
                info_text = f"HTTP {meta.get('status', '')} - {info_text}"
                
            header = QLabel(info_text)
            header.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {COLOR_ACCENT};")
            header.setWordWrap(True)
            layout.addWidget(header)
            
            # Preview
            import base64
            raw = base64.b64decode(entry.get("data", ""))
            try:
                text = raw.decode('utf-8', errors='replace')
            except:
                text = repr(raw)
                
            preview = QTextEdit()
            preview.setPlainText(text)
            preview.highlighter = HttpSyntaxHighlighter(preview.document())
            layout.addWidget(preview)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            view_btn = QPushButton("👁 View in Tab")
            view_btn.setStyleSheet(f"background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT}; border: 1px solid {COLOR_BORDER};")
            view_btn.clicked.connect(lambda: self._switch_to_intercept(dialog))
            
            forward_btn = QPushButton("▶ Forward")
            forward_btn.setStyleSheet(f"background-color: {COLOR_SUCCESS}; color: black; border: none;")
            forward_btn.clicked.connect(lambda: self._popup_action(dialog, flow_id, "forward", preview))
            
            drop_btn = QPushButton("✕ Drop")
            drop_btn.setStyleSheet(f"background-color: {COLOR_CRITICAL}; color: black; border: none;")
            drop_btn.clicked.connect(lambda: self._popup_action(dialog, flow_id, "drop"))
            
            btn_layout.addWidget(view_btn)
            btn_layout.addStretch()
            btn_layout.addWidget(drop_btn)
            btn_layout.addWidget(forward_btn)
            
            layout.addLayout(btn_layout)
            
            dialog.exec_()
        finally:
            self._is_intercept_popup_open = False

    def _switch_to_intercept(self, dialog):
        dialog.accept()
        self.tab_widget.setCurrentWidget(self.intercept_tab)
        
    def _popup_action(self, dialog, flow_id, action, editor=None):
        data = None
        if action == "forward" and editor:
            data = editor.toPlainText().encode('utf-8')
        self.intercept_tab.resolve_flow(flow_id, action, data)
        dialog.accept()

    def _build_project_banner(self, main_layout):
        """Slim project info bar below menu, added directly to main_layout."""
        self._banner = QFrame()
        self._banner.setFixedHeight(28)
        self._banner.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_DARK_BG}; "
            f"border-bottom: 1px solid {COLOR_BORDER}; }}"
        )
        bl = QHBoxLayout(self._banner)
        bl.setContentsMargins(12, 0, 12, 0)
        bl.setSpacing(6)

        self._banner_prog_lbl = QLabel("—")
        self._banner_prog_lbl.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-weight: 600; font-size: {FONT_SIZE_SMALL};"
        )
        bl.addWidget(QLabel("◎"))
        bl.addWidget(self._banner_prog_lbl)

        sep = QLabel("▸")
        sep.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        bl.addWidget(sep)

        self._banner_domain_lbl = QLabel("all scope")
        self._banner_domain_lbl.setStyleSheet(
            f"color: {COLOR_SUCCESS}; font-size: {FONT_SIZE_SMALL};"
        )
        bl.addWidget(self._banner_domain_lbl)
        bl.addStretch()

        # Switch scope button
        switch_btn = QPushButton("⚙ Change Scope")
        switch_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {COLOR_TEXT_MUTED}; "
            f"border: none; font-size: {FONT_SIZE_SMALL}; }}"
            f"QPushButton:hover {{ color: {COLOR_ACCENT}; }}"
        )
        switch_btn.clicked.connect(self._show_scope_tab)
        bl.addWidget(switch_btn)

        # Add banner to main layout (called before tab_widget is added)
        main_layout.addWidget(self._banner)

        self._update_banner()

    def _update_banner(self):
        data = pm.get_program(self._project_slug) if self._project_slug else None
        prog_name = data["name"] if data else "No project"
        self._banner_prog_lbl.setText(prog_name)

        scope_text = self._project_subdomain or self._project_domain or "all scope"
        self._banner_domain_lbl.setText(scope_text)

    def _show_scope_tab(self):
        """Show scope configuration in a dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Scope Configuration")
        dialog.setMinimumSize(1000, 700)
        
        # Apply theme
        dialog.setStyleSheet(f"""
            QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
            QPushButton {{ padding: 6px 12px; border-radius: 4px; }}
        """)
        
        layout = QVBoxLayout(dialog)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Add the scope tab widget
        # We reparent it to the dialog temporarily
        self.scope_tab.setParent(dialog)
        self.scope_tab.show()
        layout.addWidget(self.scope_tab)
        
        # Close button area
        btn_container = QFrame()
        btn_container.setStyleSheet(f"background-color: {COLOR_ELEVATED_BG}; border-top: 1px solid {COLOR_BORDER};")
        btn_layout = QHBoxLayout(btn_container)
        btn_layout.setContentsMargins(10, 10, 10, 10)
        btn_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(f"background-color: {COLOR_ACCENT}; color: white; font-weight: bold;")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addWidget(btn_container)
        
        # Show dialog
        dialog.exec_()
        
        # Reparent back to main window so it persists
        self.scope_tab.setParent(self)
        self.scope_tab.hide()

    # ── Project management ─────────────────────────────────────────────────

    def _switch_project(self):
        """Show project selection dialog and relaunch with the chosen project."""
        from launch_dialog import LaunchDialog
        dlg = LaunchDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        result = dlg.get_result()
        if not result or not result.get("slug"):
            return

        new_slug = result["slug"]
        if new_slug == self._project_slug:
            QMessageBox.information(self, "Same Project",
                                    "That project is already open.")
            return

        # Stop proxy before relaunching
        if self.proxy_running:
            self._force_stop_proxy()

        # Relaunch the application with the new project
        import sys, subprocess
        args = [sys.executable] + sys.argv + []
        # Pass the new slug via environment so main() picks it up
        env = os.environ.copy()
        env["HACKR_PROJECT_SLUG"] = new_slug
        subprocess.Popen(args, env=env)
        QApplication.quit()

    def _delete_current_project(self):
        """Delete the current project after confirmation."""
        if not self._project_slug:
            QMessageBox.warning(self, "No Project", "No project is currently open.")
            return

        data = pm.get_program(self._project_slug)
        prog_name = data["name"] if data else self._project_slug

        # First confirmation
        reply = QMessageBox.question(
            self, "Delete Project",
            f"Delete project  '{prog_name}'?\n\n"
            f"This will remove it from the project list.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        # Second confirmation — ask whether to wipe data
        reply2 = QMessageBox.question(
            self, "Delete Project Data",
            f"Also permanently delete ALL captured data for  '{prog_name}'?\n\n"
            f"(requests, responses, JSONL, notes — cannot be undone)\n\n"
            f"• Yes = delete project AND all data\n"
            f"• No  = remove from list only (data kept on disk)",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.No
        )
        if reply2 == QMessageBox.Cancel:
            return

        delete_data = (reply2 == QMessageBox.Yes)

        # Stop proxy first
        if self.proxy_running:
            self._force_stop_proxy()

        # Delete
        try:
            pm.delete_program(self._project_slug, delete_data=delete_data)
        except Exception as exc:
            QMessageBox.critical(self, "Delete Failed", str(exc))
            return

        QMessageBox.information(
            self, "Deleted",
            f"Project '{prog_name}' has been deleted.\n"
            f"The application will now restart so you can select a new project."
        )

        # Relaunch without a project slug so LaunchDialog appears
        import sys, subprocess
        env = os.environ.copy()
        env.pop("HACKR_PROJECT_SLUG", None)
        subprocess.Popen([sys.executable] + sys.argv, env=env)
        QApplication.quit()

    # ── Scope change callbacks ─────────────────────────────────────────────

    def _on_scope_changed(self, slug: str, domain: str, subdomain: str):
        """Called when user changes scope in ScopeTab."""
        self._project_domain   = domain
        self._project_subdomain = subdomain
        self._update_banner()
        self._update_notes_scope_domains()  # re-colour scope URLs in notes

        # With Burp-style scope rules, the proxy addon auto-reloads scope_rules.json
        # via its file watcher — so we DON'T need a full proxy restart on every scope change.
        # We only restart if the proxy isn't running yet, or if HUNT_SCOPE_RULES_FILE wasn't
        # passed (i.e., the proxy was started without the rules file env var).
        if self.proxy_running:
            # Check if the proxy was started with scope rules file support
            if not hasattr(self, "_proxy_has_rules_file") or not self._proxy_has_rules_file:
                # Restart to pick up the rules file env var
                self.status_label.setText("🔄 Restarting proxy to apply scope rules…")
                self._force_stop_proxy()
                self._proxy_has_rules_file = True
                QTimer.singleShot(1500, self.start_proxy)
            else:
                # Rules will be auto-reloaded by the addon's file watcher
                self.status_label.setText("✅ Scope updated — rules auto-reloaded by proxy")
                QTimer.singleShot(3000, lambda: self._safe_status(""))

        if hasattr(self, "dashboard_tab"):
            self.dashboard_tab.update_scope(slug, domain, subdomain)

        # Update attack surface tab project dir when project changes
        if slug and hasattr(self, "attack_surface_tab"):
            import project_manager as _pm
            paths = _pm.get_project_paths(slug)
            if paths:
                self.attack_surface_tab.set_project_dir(paths["project_dir"])
                if hasattr(self, "mapping_tab"):
                    self.mapping_tab.set_project_dir(paths["project_dir"])
                if hasattr(self, "report_tab"):
                    self.report_tab.set_project_dir(paths["project_dir"])
                # Update WS history path for the new project
                self._update_ws_history_path()

    def _on_scope_changed_history(self, slug: str, domain: str, subdomain: str):
        """Forward scope changes to the HTTP History tab's scope filter."""
        if hasattr(self, "update_scope_hosts"):
            self.update_scope_hosts(slug, domain, subdomain)

    # ── WS History tab helpers ─────────────────────────────────────────────

    def _update_ws_history_path(self):
        """Point the WS monitor at the project-specific JSONL file."""
        if not hasattr(self, "ws_history_tab"):
            return
        if self._project_paths:
            ws_path = os.path.join(self._project_paths["project_dir"], "hunt_ws.jsonl")
        else:
            ws_path = "/tmp/hunt_ws.jsonl"
        self.ws_history_tab.set_ws_jsonl_path(ws_path)

    def _show_ws_history_tab(self):
        """Make the WS History tab visible the first time a message is captured."""
        if hasattr(self, "_ws_tab_index"):
            self.tab_widget.setTabVisible(self._ws_tab_index, True)

    # ── Status-bar navigation helpers ─────────────────────────────────────

    def _go_to_attack_surface_tab(self):
        """Switch to the Attack Surface tab."""
        if hasattr(self, "attack_surface_tab"):
            self.tab_widget.setCurrentWidget(self.attack_surface_tab)

    def _go_to_reports_tab(self):
        """Switch to the Reports tab."""
        if hasattr(self, "report_tab"):
            self.tab_widget.setCurrentWidget(self.report_tab)

    # ── Project Notes panel ───────────────────────────────────────────────

    @property
    def _notes_editor(self):
        """Return the currently active notes editor tab, or None."""
        if not hasattr(self, "_notes_tabs"):
            return None
        w = self._notes_tabs.currentWidget()
        return w if isinstance(w, _NotesEditor) else None

    def _build_notes_panel(self, central: QWidget):
        """Build the floating overlay Project Notes panel (parented to central widget)."""
        self._notes_panel_visible     = False
        self._notes_panel_height_frac = 0.50   # default 50 % of central widget height
        self._notes_autosave_timer    = QTimer(self)
        self._notes_autosave_timer.setSingleShot(True)
        self._notes_autosave_timer.timeout.connect(self._save_project_notes)

        # ── Outer frame — child of central, NOT part of the VBoxLayout ───
        self._notes_panel = QFrame(central)
        self._notes_panel.setObjectName("notesPanel")
        self._notes_panel.setVisible(False)
        self._notes_panel.setStyleSheet(
            f"QFrame#notesPanel {{ background-color: {COLOR_LIGHTER_BG}; }}"
        )

        panel_layout = QVBoxLayout(self._notes_panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)

        # ── Drag handle (top edge) ────────────────────────────────────────
        drag_handle = _NotesDragHandle(self._on_notes_drag, self._notes_panel)
        panel_layout.addWidget(drag_handle)

        # ── Inner container ───────────────────────────────────────────────
        inner = QWidget()
        inner.setStyleSheet(
            f"background-color: {COLOR_LIGHTER_BG};"
        )
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(6, 4, 6, 4)
        inner_layout.setSpacing(4)

        # ── Toolbar row ───────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(0, 0, 0, 0)
        toolbar_layout.setSpacing(6)

        title_lbl = QLabel(" Project Notes")
        title_lbl.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-weight: 700; font-size: 13px;"
        )
        toolbar_layout.addWidget(title_lbl)
        toolbar_layout.addSpacing(12)

        def _fmt_btn(icon: str, tip: str, callback) -> QPushButton:
            b = QPushButton(icon)
            b.setFixedSize(28, 22)
            b.setToolTip(tip)
            b.setStyleSheet(
                f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};"
                f"  border: 1px solid {COLOR_BORDER}; border-radius: 3px; font-weight: bold; }}"
                f"QPushButton:hover {{ background: {COLOR_ACCENT}; color: #000; }}"
            )
            b.clicked.connect(callback)
            return b

        toolbar_layout.addWidget(_fmt_btn("B",   "Bold",            lambda: self._wrap_selection("**", "**")))
        toolbar_layout.addWidget(_fmt_btn("I",   "Italic",          lambda: self._wrap_selection("*",  "*")))
        toolbar_layout.addWidget(_fmt_btn("`",   "Inline code",     lambda: self._wrap_selection("`",  "`")))
        toolbar_layout.addWidget(_fmt_btn("H1",  "Heading 1",       lambda: self._insert_line_prefix("# ")))
        toolbar_layout.addWidget(_fmt_btn("H2",  "Heading 2",       lambda: self._insert_line_prefix("## ")))
        toolbar_layout.addWidget(_fmt_btn("H3",  "Heading 3",       lambda: self._insert_line_prefix("### ")))
        toolbar_layout.addWidget(_fmt_btn("—",   "Horizontal rule", lambda: self._insert_at_cursor("\n\n---\n\n")))
        toolbar_layout.addWidget(_fmt_btn("• ",  "Bullet list",     lambda: self._insert_line_prefix("- ")))
        toolbar_layout.addWidget(_fmt_btn("1.",  "Numbered list",   lambda: self._insert_line_prefix("1. ")))
        toolbar_layout.addWidget(_fmt_btn("[ ]", "Checkbox",        lambda: self._insert_line_prefix("- [ ] ")))
        toolbar_layout.addWidget(_fmt_btn("```", "Code block",      lambda: self._insert_code_block()))

        toolbar_layout.addStretch()

        self._notes_save_indicator = QLabel("● saved")
        self._notes_save_indicator.setStyleSheet(
            f"color: {COLOR_SUCCESS}; font-size: 11px; padding: 0 6px;"
        )
        toolbar_layout.addWidget(self._notes_save_indicator)

        close_btn = _CloseBtn(COLOR_TEXT_MUTED, COLOR_CRITICAL, size=18)
        close_btn.setToolTip("Close notes panel  (Ctrl+Shift+N)")
        close_btn.clicked.connect(self._toggle_project_notes)
        toolbar_layout.addWidget(close_btn)

        inner_layout.addWidget(toolbar)

        # ── Notes tab widget ──────────────────────────────────────────────
        _tab_bar = _NotesTabBar()
        _tab_bar.add_tab_requested.connect(lambda: self._add_notes_tab("Note"))
        _tab_bar.setStyleSheet(
            f"QTabBar::tab {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_MUTED};"
            f"  border: 1px solid {COLOR_BORDER}; border-bottom: none;"
            f"  padding: 2px 6px; border-radius: 4px 4px 0 0; min-width: 50px; font-size: 12px; }}"
            f"QTabBar::tab:selected {{ background: {COLOR_LIGHTER_BG}; color: {COLOR_TEXT_BRIGHT};"
            f"  border-bottom: 2px solid {COLOR_ACCENT}; }}"
            f"QTabBar::tab:hover:!selected {{ background: {COLOR_ACCENT}; color: #000; }}"
            f"QTabBar::close-button {{ image: none; }}"
            f"QTabBar::close-button:hover {{ background: transparent; }}"
        )
        self._notes_tabs = QTabWidget()
        self._notes_tabs.setTabBar(_tab_bar)
        self._notes_tabs.setTabsClosable(True)
        self._notes_tabs.setMovable(True)
        self._notes_tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: none; background: {COLOR_DARK_BG}; }}"
            f"QTabWidget {{ background: {COLOR_DARK_BG}; }}"
        )
        self._notes_tabs.tabCloseRequested.connect(self._close_notes_tab)

        _add_tab_btn = QPushButton("+")
        _add_tab_btn.setFixedSize(18, 18)
        _add_tab_btn.setToolTip("New tab  (double-click tab name to rename)")
        _add_tab_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};"
            f"  border: 1px solid {COLOR_BORDER}; border-radius: 3px;"
            f"  font-weight: bold; font-size: 13px; padding: 0; }}"
            f"QPushButton:hover {{ background: {COLOR_ACCENT}; color: #000; }}"
        )
        _add_tab_btn.clicked.connect(lambda: self._add_notes_tab("Note"))
        self._notes_tabs.setCornerWidget(_add_tab_btn, Qt.TopRightCorner)

        # Start with a single General tab — _load_project_notes will restore saved tabs
        self._add_notes_tab("General")
        self._notes_tabs.setCurrentIndex(0)

        inner_layout.addWidget(self._notes_tabs)

        # ── Inline search bar (hidden by default, Ctrl+F to toggle) ──────
        self._notes_search_bar = _NotesSearchBar(lambda: self._notes_editor)
        inner_layout.addWidget(self._notes_search_bar)

        panel_layout.addWidget(inner)

        # ── Global shortcut: Ctrl+Shift+N toggles the notes panel ────────
        QShortcut(QKeySequence("Ctrl+Shift+N"), self).activated.connect(
            self._toggle_project_notes
        )

    def _toggle_project_notes(self):
        """Show or hide the floating notes overlay panel."""
        self._notes_panel_visible = not self._notes_panel_visible
        if self._notes_panel_visible:
            self._notes_panel.setVisible(True)
            self._reposition_notes_panel()
            self._notes_panel.raise_()
            self._update_notes_scope_domains()   # refresh scope on every open
            ed = self._notes_editor
            if ed:
                ed.setFocus()
            self.project_notes_btn.setText(" Project Notes ▲")
        else:
            # Save immediately when the panel is hidden so content is never lost.
            self._save_project_notes()
            self._notes_panel.setVisible(False)
            self.project_notes_btn.setText(" Project Notes ▼")

    def _add_notes_tab(self, name: str = "Note") -> '_NotesEditor':
        """Create a new notes tab with its own editor and highlighter."""
        editor = _NotesEditor()
        editor.setPlaceholderText(
            "Write notes — markdown highlights live as you type.\n"
            "# Heading 1   **bold**   *italic*   `code`\n"
            "- bullet   1. numbered   - [ ] checkbox\n"
            "http://... URLs auto-highlighted  •  Ctrl+T = timestamp  •  Ctrl+F = find"
        )
        editor.setStyleSheet(
            f"QTextEdit {{"
            f"  background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};"
            f"  border: none;"
            f"  font-family: 'Fira Code', 'Consolas', monospace; font-size: 13px;"
            f"  padding: 8px;"
            f"}}"
        )
        editor.setAcceptRichText(False)
        hl = MarkdownHighlighter(editor.document())
        hl.set_scope_domains(self._get_scope_domains())
        editor._md_hl = hl
        editor.textChanged.connect(self._on_notes_text_changed)
        editor.search_toggled.connect(self._toggle_notes_search)
        idx = self._notes_tabs.addTab(editor, name)
        # Wrap ✕ in a container with left gap so the gap doesn't trigger close
        _tab_btn_container = QWidget()
        _tab_btn_container.setStyleSheet("background: transparent; border: none;")
        _cbl = QHBoxLayout(_tab_btn_container)
        _cbl.setContentsMargins(5, 0, 0, 0)   # 5px gap between tab name and ✕
        _cbl.setSpacing(0)
        close_btn = _CloseBtn("#585b70", "#f38ba8", size=14)
        close_btn.clicked.connect(lambda: self._close_notes_tab(self._notes_tabs.indexOf(editor)))
        _cbl.addWidget(close_btn)
        _tab_btn_container.setFixedSize(14 + 5, 14)
        self._notes_tabs.tabBar().setTabButton(idx, QTabBar.RightSide, _tab_btn_container)
        return editor

    def _close_notes_tab(self, idx: int):
        """Close a notes tab; at least one tab must remain. Confirm if non-empty."""
        if self._notes_tabs.count() <= 1:
            return
        editor = self._notes_tabs.widget(idx)
        if isinstance(editor, _NotesEditor) and editor.toPlainText().strip():
            name = self._notes_tabs.tabText(idx)
            reply = QMessageBox.question(
                self,
                "Close tab?",
                f"Tab \u201c{name}\u201d has content.\nClose it and lose the content?",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if reply != QMessageBox.Yes:
                return
        self._notes_tabs.removeTab(idx)
        self._save_project_notes()

    def _toggle_notes_search(self):
        """Show or hide the inline search bar (Ctrl+F from any tab editor)."""
        if not hasattr(self, "_notes_search_bar"):
            return
        if self._notes_search_bar.isVisible():
            self._notes_search_bar.hide_bar()
        else:
            self._notes_search_bar.show_bar()

    def _get_scope_domains(self) -> list:
        """Return current project scope domain strings for URL highlighting."""
        domains = []
        d = getattr(self, "_project_domain", "")
        s = getattr(self, "_project_subdomain", "")
        if d:
            domains.append(d)
        if s and s != d:
            domains.append(s)
        return [x for x in domains if x]

    def _update_notes_scope_domains(self):
        """Push updated scope domains to every open notes tab highlighter."""
        if not hasattr(self, "_notes_tabs"):
            return
        domains = self._get_scope_domains()
        # Fallback: pull live values directly from scope_tab when our cache is empty
        if not domains and hasattr(self, "scope_tab"):
            try:
                sc = self.scope_tab.get_current_scope()
                d  = sc.get("domain", "").strip()
                s  = sc.get("subdomain", "").strip()
                if d:
                    self._project_domain    = d
                if s:
                    self._project_subdomain = s
                domains = self._get_scope_domains()
            except Exception:
                pass
        for i in range(self._notes_tabs.count()):
            w = self._notes_tabs.widget(i)
            if isinstance(w, _NotesEditor) and hasattr(w, "_md_hl"):
                w._md_hl.set_scope_domains(domains)


    def _reposition_notes_panel(self):
        """Geometry-manage the notes panel so it floats at the bottom of central."""
        if not hasattr(self, "_notes_panel"):
            return
        central = self.centralWidget()
        if not central:
            return
        ch = central.height()
        cw = central.width()
        panel_h = max(80, min(int(ch * self._notes_panel_height_frac), ch - 30))
        self._notes_panel.setGeometry(0, ch - panel_h, cw, panel_h)
        if self._notes_panel.isVisible():
            self._notes_panel.raise_()

    def _on_notes_drag(self, delta_y: int):
        """Called by _NotesDragHandle on mouse drag; delta_y > 0 means dragged up."""
        central = self.centralWidget()
        if not central:
            return
        ch = central.height()
        new_h = max(80, min(self._notes_panel.height() + delta_y, ch - 30))
        self._notes_panel_height_frac = new_h / ch
        self._reposition_notes_panel()

    def _on_notes_text_changed(self):
        """Debounce-save on every keystroke; highlighter handles live rendering."""
        # Ignore programmatic changes (loading from file, rehighlight).
        if not getattr(self, "_notes_loaded", True):
            return
        if hasattr(self, "_notes_save_indicator"):
            self._notes_save_indicator.setStyleSheet(
                f"color: {COLOR_WARNING}; font-size: 11px; padding: 0 6px;"
            )
            self._notes_save_indicator.setText("● unsaved")
        self._notes_autosave_timer.start(800)

    # ── Notes formatting helpers ──────────────────────────────────────────

    def _wrap_selection(self, prefix: str, suffix: str):
        """Wrap the current selection in editor with prefix/suffix."""
        cursor = self._notes_editor.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText()
            cursor.insertText(f"{prefix}{text}{suffix}")
        else:
            cursor.insertText(f"{prefix}{suffix}")
            # Move caret inside
            pos = cursor.position() - len(suffix)
            cursor.setPosition(pos)
            self._notes_editor.setTextCursor(cursor)
        self._notes_editor.setFocus()

    def _insert_line_prefix(self, prefix: str):
        """Prepend prefix to the line containing the cursor."""
        cursor = self._notes_editor.textCursor()
        cursor.movePosition(QTextCursor.StartOfLine)
        cursor.insertText(prefix)
        self._notes_editor.setFocus()

    def _insert_at_cursor(self, text: str):
        """Insert arbitrary text at the current cursor position."""
        self._notes_editor.textCursor().insertText(text)
        self._notes_editor.setFocus()

    def _insert_code_block(self):
        """Insert a fenced code block."""
        cursor = self._notes_editor.textCursor()
        if cursor.hasSelection():
            code = cursor.selectedText()
            cursor.insertText(f"\n```\n{code}\n```\n")
        else:
            cursor.insertText("\n```\n\n```\n")
            pos = cursor.position() - 4  # land inside the fences
            cursor.setPosition(pos)
            self._notes_editor.setTextCursor(cursor)
        self._notes_editor.setFocus()

    # ── Notes persistence ─────────────────────────────────────────────────

    def _notes_file_path_base(self) -> str:
        """Return the base path (no extension) for notes files, or ''."""
        if self._project_paths:
            return os.path.join(self._project_paths["project_dir"], "project_notes")
        return ""

    def _notes_file_path(self) -> str:
        """Return legacy single notes file path (used for migration only)."""
        base = self._notes_file_path_base()
        return base + ".md" if base else ""

    def _load_project_notes(self):
        """Load notes from the project directory into all tabs."""
        if not hasattr(self, "_notes_tabs"):
            return
        path_base = self._notes_file_path_base()
        if not path_base:
            self._notes_loaded = True
            return
        self._notes_loaded = False   # block autosave until load is complete

        # ── Load tab metadata ────────────────────────────────────────
        meta_path = path_base + "_meta.json"
        tab_names = ["Vuln Scope"]   # default: single tab
        panel_visible = False
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                tab_names = meta.get("tabs", tab_names)
                panel_visible = meta.get("panel_visible", False)
            except Exception as e:
                logger.warning(f"Could not read notes meta: {e}")

        # ── Recovery: scan for tab files that meta may have missed ────
        # (e.g. if a crash or startup-wipe left tab_N.md files without
        #  the corresponding meta entry)
        i = len(tab_names)
        while True:
            extra_path = path_base + f"_tab_{i}.md"
            if not os.path.exists(extra_path):
                break
            try:
                content = open(extra_path, "r", encoding="utf-8").read()
            except Exception:
                content = ""
            if content.strip():
                tab_names.append(f"Note {i + 1}")
            else:
                break
            i += 1

        # ── Sync tab count to saved tab list ───────────────────────────
        # Block all editor signals while we rebuild tabs to avoid spurious autosaves
        while self._notes_tabs.count() < len(tab_names):
            self._add_notes_tab("Note")
        while self._notes_tabs.count() > len(tab_names):
            self._notes_tabs.removeTab(self._notes_tabs.count() - 1)
        for i, name in enumerate(tab_names):
            self._notes_tabs.setTabText(i, name)

        # ── Load each tab's content ─────────────────────────────────
        old_single = path_base + ".md"  # migration: pre-tabs single file
        for i in range(self._notes_tabs.count()):
            editor = self._notes_tabs.widget(i)
            if not isinstance(editor, _NotesEditor):
                continue
            tab_path = path_base + f"_tab_{i}.md"
            content = ""
            if os.path.exists(tab_path):
                try:
                    with open(tab_path, "r", encoding="utf-8") as fh:
                        content = fh.read()
                except Exception as e:
                    logger.warning(f"Could not load notes tab {i}: {e}")
            elif i == 0 and os.path.exists(old_single):
                # Migrate legacy single-file notes into first tab
                try:
                    with open(old_single, "r", encoding="utf-8") as fh:
                        content = fh.read()
                except Exception:
                    pass
            editor.blockSignals(True)
            editor.setPlainText(content)
            editor.blockSignals(False)

        self._notes_tabs.setCurrentIndex(0)
        self._notes_loaded = True   # allow autosave from this point on
        self._update_notes_scope_domains()
        if hasattr(self, "_notes_save_indicator"):
            self._notes_save_indicator.setStyleSheet(
                f"color: {COLOR_SUCCESS}; font-size: 11px; padding: 0 6px;"
            )
            self._notes_save_indicator.setText("● saved")

        # Notes panel always starts collapsed — user opens it manually
        # (panel_visible from meta is intentionally ignored on load)

    def _save_project_notes(self):
        """Save all notes tabs to the project directory."""
        # Don't save before the initial load completes — avoids writing
        # empty content if the timer fires during startup.
        if not getattr(self, "_notes_loaded", True):
            return
        if not hasattr(self, "_notes_tabs"):
            return
        path_base = self._notes_file_path_base()
        if not path_base:
            return
        try:
            os.makedirs(os.path.dirname(path_base), exist_ok=True)
            # ── Save tab metadata ─────────────────────────────────
            tab_names = [
                self._notes_tabs.tabText(i)
                for i in range(self._notes_tabs.count())
            ]
            with open(path_base + "_meta.json", "w", encoding="utf-8") as fh:
                json.dump({
                    "tabs": tab_names,
                    "panel_visible": getattr(self, "_notes_panel_visible", False),
                }, fh, indent=2)
            # ── Save each tab's content ────────────────────────────
            n_tabs = self._notes_tabs.count()
            for i in range(n_tabs):
                editor = self._notes_tabs.widget(i)
                if isinstance(editor, _NotesEditor):
                    content = editor.toPlainText()
                    tab_path = path_base + f"_tab_{i}.md"
                    with open(tab_path, "w", encoding="utf-8") as fh:
                        fh.write(content)
            # ── Delete orphaned tab files beyond current count ─────────
            i = n_tabs
            while os.path.exists(path_base + f"_tab_{i}.md"):
                try:
                    os.remove(path_base + f"_tab_{i}.md")
                except Exception:
                    pass
                i += 1
            if hasattr(self, "_notes_save_indicator"):
                self._notes_save_indicator.setStyleSheet(
                    f"color: {COLOR_SUCCESS}; font-size: 11px; padding: 0 6px;"
                )
                self._notes_save_indicator.setText("● saved")
            logger.debug(f"Project notes saved to {path_base}")
        except Exception as e:
            logger.error(f"Could not save project notes: {e}")
            if hasattr(self, "_notes_save_indicator"):
                self._notes_save_indicator.setStyleSheet(
                    "color: #f38ba8; font-size: 11px; padding: 0 6px;"
                )
                self._notes_save_indicator.setText("● save failed")


    def _restart_monitoring(self):
        """Stop current monitor and start a new one pointing at the new project JSONL."""
        if hasattr(self, 'monitor_thread') and self.monitor_thread:
            self.monitor_thread.stop()
            self.monitor_thread.wait(2000)

        # Clear current findings
        self.findings.clear()
        if hasattr(self, 'history_table'):
            self.history_table.setRowCount(0)

        self.start_monitoring()

    # ── Monitoring ────────────────────────────────────────────────────────

    def start_monitoring(self):
        """Start file monitoring with progress."""
        # Determine JSONL path
        jsonl_path = (
            self._project_paths["jsonl"]
            if self._project_paths
            else os.environ.get("HUNT_MODE_JSONL", "/tmp/hunt.jsonl")
        )

        self.monitor_thread = FileMonitorThread(jsonl_path=jsonl_path)
        # Connect the batched live signal — main thread wakes once per poll cycle
        self.monitor_thread.new_findings.connect(self.on_new_findings_batch)
        # Keep legacy single-finding signal connected as fallback (no-op via shim)
        self.monitor_thread.stats_update.connect(self.on_stats_update)
        self.monitor_thread.load_progress.connect(self.on_load_progress)
        self.monitor_thread.load_complete.connect(self.on_load_complete)
        self.monitor_thread.batch_loaded.connect(self.on_batch_loaded)
        self.monitor_thread.start()

        QTimer.singleShot(1000, self.update_issue_filter_dropdown)

        if not hasattr(self, 'update_timer') or not self.update_timer.isActive():
            self.update_timer = QTimer()
            self.update_timer.timeout.connect(self.update_status_bar)
            self.update_timer.start(1000)

    # ── Proxy management ───────────────────────────────────────────────────

    def _build_proxy_env(self) -> Dict[str, str]:
        """Build environment variables for the mitmdump process."""
        env = os.environ.copy()

        if self._project_paths:
            env["HUNT_MODE_JSONL"]         = self._project_paths["jsonl"]
            env["HUNT_MODE_REQUESTS_DIR"]  = self._project_paths["requests_dir"]
            env["HUNT_MODE_RESPONSES_DIR"] = self._project_paths["responses_dir"]
            project_dir                     = self._project_paths["project_dir"]
            env["HUNT_WS_JSONL"]           = os.path.join(project_dir, "hunt_ws.jsonl")
            env["HUNT_INTERCEPT_QUEUE"]    = os.path.join(project_dir, "intercept_queue.jsonl")
            env["HUNT_INTERCEPT_ACTIONS"]  = os.path.join(project_dir, "intercept_actions")
            env["HUNT_INTERCEPT_ENABLED"]  = os.path.join(project_dir, "intercept_enabled")
            env["HUNT_INTERCEPT_RESPONSES"] = os.path.join(project_dir, "intercept_responses")
            env["HUNT_WS_INTERCEPT_ENABLED"] = os.path.join(project_dir, "ws_intercept_enabled")
            env["HUNT_PROXY_RULES"]        = os.path.join(project_dir, "proxy_rules.json")
            env["HUNT_PROXY_CONFIG"]       = os.path.join(project_dir, "proxy_config.json")
        else:
            env["HUNT_MODE_JSONL"]         = "/tmp/hunt.jsonl"
            env["HUNT_WS_JSONL"]           = "/tmp/hunt_ws.jsonl"
            env["HUNT_MODE_REQUESTS_DIR"]  = "/tmp/requests"
            env["HUNT_MODE_RESPONSES_DIR"] = "/tmp/responses"
            env["HUNT_INTERCEPT_QUEUE"]    = "/tmp/intercept_queue.jsonl"
            env["HUNT_INTERCEPT_ACTIONS"]  = "/tmp/intercept_actions"
            env["HUNT_INTERCEPT_ENABLED"]  = "/tmp/intercept_enabled"
            env["HUNT_INTERCEPT_RESPONSES"] = "/tmp/intercept_responses"
            env["HUNT_WS_INTERCEPT_ENABLED"] = "/tmp/ws_intercept_enabled"
            env["HUNT_PROXY_RULES"]        = "/tmp/proxy_rules.json"
            env["HUNT_PROXY_CONFIG"]       = "/tmp/proxy_config.json"

        # Scope hosts as JSON list (legacy fallback)
        scope_hosts = pm.get_scope_hosts(
            self._project_slug, self._project_domain, self._project_subdomain
        )
        env["HUNT_SCOPE_HOSTS"] = json.dumps(scope_hosts)

        # Burp-style scope rules file (preferred — auto-reloaded by addon without proxy restart)
        if self._project_paths:
            scope_rules_file = pm.get_project_paths(self._project_slug).get("scope_rules_file", "")
            if scope_rules_file:
                env["HUNT_SCOPE_RULES_FILE"] = scope_rules_file

        return env

    def start_proxy(self):
        """Start mitmdump proxy using the dedicated hunt_addon.py script."""
        with self._proxy_lock:
            if self.proxy_running:
                QMessageBox.information(self, "Proxy Running", "Proxy is already running!")
                return

            try:
                if not os.path.exists(self.proxy_script_file):
                    QMessageBox.critical(
                        self, "Addon Script Not Found",
                        f"Cannot find proxy addon script:\n{self.proxy_script_file}\n\n"
                        "Make sure hunt_addon.py is in the same directory as hunt_gui.py."
                    )
                    return

                # Create necessary directories first
                if self._project_paths:
                    os.makedirs(self._project_paths["requests_dir"], exist_ok=True)
                    os.makedirs(self._project_paths["responses_dir"], exist_ok=True)
                    
                    # Create intercept queue file if it doesn't exist
                    queue_file = os.path.join(self._project_paths["project_dir"], "intercept_queue.jsonl")
                    if not os.path.exists(queue_file):
                        open(queue_file, 'a').close()

                cmd = [
                    "mitmdump",
                    "-s", self.proxy_script_file,
                    "--listen-port", str(self.proxy_port),
                    "--set", "flow_detail=1",  # Increased for debugging
                    "--set", "termlog_verbosity=info",
                    "--set", "console_eventlog_verbosity=info",
                ]

                # Add upstream proxy if configured
                if self.proxy_upstream and self.proxy_upstream.strip():
                    cmd.extend(["--mode", f"upstream:{self.proxy_upstream}"])
                    cmd.append("--ssl-insecure")

                env = self._build_proxy_env()
                
                # Log all environment variables for debugging
                logger.info("Proxy environment variables:")
                for key, value in env.items():
                    if key.startswith("HUNT_"):
                        logger.info(f"  {key}={value}")

                # Create log file with full path
                log_path = (
                    os.path.join(self._project_paths["project_dir"], "mitmdump.log")
                    if self._project_paths else "/tmp/mitmdump.log"
                )
                
                # Open log file with write mode
                log_fh = open(log_path, "w")
                self.proxy_log_handle = log_fh  # Store for cleanup

                # Start the process
                self.proxy_process = subprocess.Popen(
                    cmd,
                    env=env,
                    stdout=log_fh,
                    stderr=subprocess.STDOUT,  # Combine stderr with stdout
                    stdin=subprocess.DEVNULL,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None,
                    creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP
                                if os.name == 'nt' else 0),
                )

                # Wait a moment to see if process starts successfully
                time.sleep(1)
                
                if self.proxy_process.poll() is not None:
                    # Process died immediately
                    try:
                        log_fh.close()
                    except Exception:
                        pass
                    self.proxy_log_handle = None
                    with open(log_path, 'r') as f:
                        error_log = f.read()
                    QMessageBox.critical(
                        self, "Proxy Failed",
                        f"Proxy failed to start. Check log:\n{log_path}\n\n{error_log[-500:]}"
                    )
                    return

                # Write PID file
                pid_file = (
                    os.path.join(self._project_paths["project_dir"], "mitm.pid")
                    if self._project_paths else "/tmp/mitm.pid"
                )
                with open(pid_file, 'w') as f:
                    f.write(str(self.proxy_process.pid))

                # Start health monitor
                self.proxy_health_monitor = ProxyHealthMonitor(self)
                self.proxy_health_monitor.proxy_died.connect(self._on_proxy_died)
                self.proxy_health_monitor.start()

                self.proxy_running = True
                self._proxy_has_rules_file = bool(
                    self._project_paths and
                    pm.get_project_paths(self._project_slug).get("scope_rules_file")
                )
                self.update_proxy_status()
                self.start_proxy_action.setEnabled(False)
                self.stop_proxy_action.setEnabled(True)

                # Success message
                scope_info = ""
                if self._project_slug:
                    prog = pm.get_program(self._project_slug)
                    pname = prog["name"] if prog else self._project_slug
                    scope_info = f" [{pname}"
                    if self._project_domain:
                        scope_info += f" / {self._project_domain}"
                    scope_info += "]"

                self.status_label.setText(
                    f"✅ Proxy started on port {self.proxy_port}{scope_info}"
                )
                logger.info(f"Proxy started on port {self.proxy_port}{scope_info}")
                logger.info(f"Proxy log: {log_path}")

            except FileNotFoundError:
                QMessageBox.critical(
                    self, "mitmdump Not Found",
                    "mitmdump command not found! Please install mitmproxy:\n"
                    "  pip install mitmproxy"
                )
            except Exception as e:
                QMessageBox.critical(self, "Proxy Start Failed", str(e))
                logger.error(f"Proxy start failed: {e}", exc_info=True)

    def _on_proxy_died(self, reason: str):
        # Guard against re-entrant calls — proxy_died can fire more than once
        # if the health monitor emits again while a QMessageBox is already open.
        # A second call here would corrupt Qt state and could close the window.
        if getattr(self, '_proxy_died_handling', False):
            logger.warning(f"_on_proxy_died re-entrant call ignored: {reason}")
            return
        self._proxy_died_handling = True
        try:
            logger.error(f"Proxy died: {reason}")
            self._safe_status(f"❌ Proxy died: {reason}")
            if not self.proxy_running:
                return
            reply = QMessageBox.question(
                self, "Proxy Died",
                f"The proxy stopped unexpectedly:\n{reason}\n\nRestart it?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
            )
            if reply == QMessageBox.Yes:
                self._force_stop_proxy()
                QTimer.singleShot(1000, self.start_proxy)
            else:
                self._force_stop_proxy()
        except Exception as e:
            logger.error(f"Error handling proxy death notification: {e}", exc_info=True)
        finally:
            self._proxy_died_handling = False

    def stop_proxy(self):
        with self._proxy_lock:
            if not self.proxy_running or not self.proxy_process:
                QMessageBox.information(self, "Proxy Not Running", "Proxy is not running!")
                return
            self._force_stop_proxy()
            self._safe_status("⏹ Proxy stopped")
            QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def _force_stop_proxy(self):
        """Forcefully stop the proxy process and all its children."""
        if self.proxy_health_monitor:
            self.proxy_health_monitor.stop()
            self.proxy_health_monitor = None
        if self.proxy_output_reader:
            self.proxy_output_reader.stop()
            self.proxy_output_reader = None
        
        # Close log file handle if open
        if self.proxy_log_handle:
            try:
                self.proxy_log_handle.close()
            except Exception:
                pass
            finally:
                self.proxy_log_handle = None
        
        proxy_pid = None
        if self.proxy_process:
            proxy_pid = self.proxy_process.pid
            try:
                if hasattr(os, 'killpg'):
                    # Use process group kill (Unix)
                    try:
                        os.killpg(os.getpgid(proxy_pid), signal.SIGTERM)
                    except (ProcessLookupError, OSError):
                        # Fallback to kill individual process
                        self.proxy_process.terminate()
                else:
                    # Windows
                    self.proxy_process.terminate()
                
                # Wait for graceful shutdown
                try:
                    self.proxy_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    # Force kill if graceful shutdown fails
                    if hasattr(os, 'killpg'):
                        try:
                            os.killpg(os.getpgid(proxy_pid), signal.SIGKILL)
                        except (ProcessLookupError, OSError):
                            self.proxy_process.kill()
                    else:
                        self.proxy_process.kill()
                    try:
                        self.proxy_process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            except ProcessLookupError:
                pass
            except OSError as e:
                logger.warning(f"OS error stopping proxy: {e}")
            except Exception as e:
                logger.error(f"Error stopping proxy: {e}")
            finally:
                self.proxy_process = None

        # Also try to kill any remaining mitmdump processes by PID from file
        pid_file = (
            os.path.join(self._project_paths["project_dir"], "mitm.pid")
            if self._project_paths
            else "/tmp/mitm.pid"
        )
        try:
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    stored_pid = f.read().strip()
                    if stored_pid.isdigit():
                        try:
                            stored_pid = int(stored_pid)
                            # Check if process still exists
                            os.kill(stored_pid, 0)  # Signal 0 just checks if alive
                            # Send SIGKILL to ensure it's dead
                            if hasattr(os, 'killpg'):
                                try:
                                    os.killpg(os.getpgid(stored_pid), signal.SIGKILL)
                                except (ProcessLookupError, OSError):
                                    os.kill(stored_pid, signal.SIGKILL)
                            else:
                                os.kill(stored_pid, signal.SIGKILL)
                            logger.info(f"Killed stored PID proxy process: {stored_pid}")
                        except ProcessLookupError:
                            # Process already dead
                            pass
                        except PermissionError:
                            logger.warning(f"Permission denied killing PID {stored_pid}")
                # Remove PID file
                os.remove(pid_file)
        except Exception as e:
            logger.debug(f"Error cleaning PID file: {e}")

        # Final attempt: kill any remaining mitmdump processes
        try:
            subprocess.run(['killall', '-9', 'mitmdump'], 
                         capture_output=True, timeout=2)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass
        except Exception:
            pass

        self.proxy_running = False

        # Only touch Qt widgets if they are still alive
        # (this method can be called from atexit / signal handler after Qt
        #  has already destroyed the UI)
        if self._qt_widgets_alive():
            self.update_proxy_status()
            try:
                self.start_proxy_action.setEnabled(True)
                self.stop_proxy_action.setEnabled(False)
            except RuntimeError:
                pass
        logger.info("Proxy stopped")

    def _qt_widgets_alive(self) -> bool:
        """
        Return True if the main Qt widgets are still alive (not yet destroyed
        by Qt's shutdown sequence).  Use this guard before calling setText(),
        setEnabled(), or any other method on a stored widget reference when
        the call might happen during or after window teardown.
        """
        try:
            lbl = self.proxy_status_label
            if lbl is None:
                return False
            _ = lbl.objectName()   # raises RuntimeError if C++ object deleted
            return True
        except RuntimeError:
            return False
        except Exception:
            return False

    def _safe_status(self, text: str):
        """
        Set the status bar label text safely.
        No-ops silently if the widget has already been destroyed by Qt.
        Use this instead of self.status_label.setText() wherever the call
        might happen inside a QTimer callback that could fire after close.
        """
        try:
            self.status_label.setText(text)
        except RuntimeError:
            pass   # widget already destroyed — safe to ignore
        except Exception:
            pass

    def update_proxy_status(self):
        if self.proxy_status_label is None:
            return
        try:
            if self.proxy_running:
                upstream_text = f" → {self.proxy_upstream}" if self.proxy_upstream else ""
                self.proxy_status_label.setText(
                    f"🟢 Proxy: :{self.proxy_port}{upstream_text}"
                )
                self.proxy_status_label.setStyleSheet(
                    f"QLabel {{ color: {COLOR_SUCCESS}; padding: 0 8px; "
                    f"border-left: 1px solid {COLOR_BORDER}; font-weight: 600; }}"
                )
            else:
                self.proxy_status_label.setText("🔴 Proxy: Stopped")
                self.proxy_status_label.setStyleSheet(
                    f"QLabel {{ color: {COLOR_TEXT_MUTED}; padding: 0 8px; "
                    f"border-left: 1px solid {COLOR_BORDER}; font-weight: 600; }}"
                )
        except RuntimeError:
            # Qt widget already destroyed — safe to ignore
            pass

    # ── Notes helpers (use project paths when available) ──────────────────

    def _on_intercept_status_changed(self, enabled: bool):
        """Update the status bar intercept indicator when intercept is toggled."""
        if not hasattr(self, 'intercept_status_label'):
            return
        try:
            if enabled:
                self.intercept_status_label.setText("🟢 Intercept: ON")
                self.intercept_status_label.setStyleSheet(
                    f"QLabel {{ color: {COLOR_HIGH}; padding: 0 8px; "
                    f"border-left: 1px solid {COLOR_BORDER}; font-weight: 600; }}"
                    f" QLabel:hover {{ color: #ffaa44; text-decoration: underline; }}"
                )
            else:
                self.intercept_status_label.setText("⏸ Intercept: OFF")
                self.intercept_status_label.setStyleSheet(
                    f"QLabel {{ color: {COLOR_TEXT_MUTED}; padding: 0 8px; "
                    f"border-left: 1px solid {COLOR_BORDER}; font-weight: 600; }}"
                    f" QLabel:hover {{ color: {COLOR_ACCENT}; text-decoration: underline; }}"
                )
        except RuntimeError:
            pass

    def _toggle_intercept_from_statusbar(self):
        """Toggle intercept on/off when the status bar label is clicked."""
        if not hasattr(self, 'intercept_tab'):
            return
        btn = self.intercept_tab.intercept_toggle_btn
        new_state = not btn.isChecked()
        btn.setChecked(new_state)
        self.intercept_tab._toggle_intercept(new_state)

    def _notes_file(self) -> str:
        if self._project_paths:
            return self._project_paths["notes_file"]
        return os.environ.get("HUNT_NOTES_FILE", "/tmp/hunt_notes.json")

    def save_notes_to_file(self):
        try:
            with open(self._notes_file(), "w", encoding="utf-8") as f:
                json.dump(self.notes_storage, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save notes: {e}")

    def load_notes_from_file(self):
        notes_file = self._notes_file()
        if not os.path.exists(notes_file):
            return
        try:
            with open(notes_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                self.notes_storage = {int(k): v for k, v in loaded.items()}
        except Exception as e:
            logger.error(f"Failed to load notes: {e}")
            self.notes_storage = {}

    # ── Highlights helpers ────────────────────────────────────────────────

    def _highlights_file(self) -> str:
        if self._project_paths:
            return self._project_paths["highlights_file"]
        return os.path.join(os.path.dirname(self._notes_file()), "highlights.json")

    def save_highlights_to_file(self):
        try:
            with open(self._highlights_file(), "w", encoding="utf-8") as f:
                json.dump(self.highlighted_rows, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save highlights: {e}")

    def load_highlights_from_file(self):
        hl_file = self._highlights_file()
        if not os.path.exists(hl_file):
            return
        try:
            with open(hl_file, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                self.highlighted_rows = {int(k): v for k, v in loaded.items()}
        except Exception as e:
            logger.error(f"Failed to load highlights: {e}")
            self.highlighted_rows = {}

    def show_proxy_options_dialog(self):
        """Show the dialog to configure all proxy options (Match & Replace, Header Injection, Drop Rules, SSL, Rate Limiting)."""
        if not hasattr(self, '_project_paths') or not self._project_paths:
            QMessageBox.warning(self, "No Project", "A project must be active to configure proxy options.")
            return

        dialog = ProxyOptionsDialog(self._project_paths['project_dir'], self)
        if dialog.exec_() == QDialog.Accepted:
            if self.proxy_running:
                reply = QMessageBox.question(
                    self, "Restart Proxy",
                    "Proxy must be restarted for the new configuration to take effect.\nRestart now?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    self._force_stop_proxy()
                    QTimer.singleShot(800, self.start_proxy)
            else:
                QMessageBox.information(self, "Config Saved",
                                        "Configuration saved. It will be applied when you start the proxy.")

    # ── Proxy config dialog (scope-aware extra info) ───────────────────────

    def show_proxy_config(self):
        """Show proxy configuration dialog with scope summary."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Proxy Configuration")
        dialog.setMinimumWidth(520)
        dialog.setStyleSheet(
            f"QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}"
        )
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)

        # Scope summary
        scope_box = QGroupBox("Current Scope")
        scope_box.setStyleSheet(
            f"QGroupBox {{ border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"margin-top: 10px; padding-top: 12px; color: {COLOR_ACCENT}; "
            f"font-weight: 600; background-color: {COLOR_CARD_BG}; }}"
        )
        sb_layout = QVBoxLayout(scope_box)
        if self._project_slug:
            data = pm.get_program(self._project_slug)
            pname = data["name"] if data else self._project_slug
            scope_lbl = QLabel(
                f"Program: {pname}\n"
                f"Domain:  {self._project_domain or 'all'}\n"
                f"Target:  {self._project_subdomain or self._project_domain or 'all'}"
            )
        else:
            scope_lbl = QLabel("No project selected — capturing all traffic")
        scope_lbl.setStyleSheet(
            f"color: {COLOR_TEXT}; font-family: {FONT_FAMILY_MONO}; "
            f"font-size: {FONT_SIZE_SMALL};"
        )
        sb_layout.addWidget(scope_lbl)
        layout.addWidget(scope_box)

        # Port
        port_layout = QHBoxLayout()
        port_label = QLabel("Listen Port:")
        port_label.setMinimumWidth(120)
        port_layout.addWidget(port_label)
        port_spin = QSpinBox()
        port_spin.setRange(1024, 65535)
        port_spin.setValue(self.proxy_port)
        port_layout.addWidget(port_spin)
        layout.addLayout(port_layout)

        # Upstream
        upstream_checkbox = QCheckBox("Enable Upstream Proxy")
        upstream_checkbox.setChecked(bool(self.proxy_upstream))
        layout.addWidget(upstream_checkbox)

        upstream_layout = QHBoxLayout()
        upstream_label = QLabel("Upstream Proxy:")
        upstream_label.setMinimumWidth(120)
        upstream_layout.addWidget(upstream_label)
        upstream_edit = QLineEdit()
        upstream_edit.setPlaceholderText("127.0.0.1:8080")
        upstream_edit.setText(self.proxy_upstream or "127.0.0.1:8080")
        upstream_edit.setEnabled(upstream_checkbox.isChecked())
        upstream_layout.addWidget(upstream_edit)
        layout.addLayout(upstream_layout)
        upstream_checkbox.toggled.connect(upstream_edit.setEnabled)

        # Buttons
        btn_layout = QHBoxLayout()
        apply_btn = QPushButton("Apply")
        apply_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_SUCCESS}; "
            f"border: 1px solid {COLOR_SUCCESS}; border-radius: 4px; padding: 5px 20px; "
            f"font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {COLOR_SUCCESS}; color: #000; }}"
        )
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)

        def _apply():
            self.proxy_port = port_spin.value()
            self.proxy_upstream = (
                upstream_edit.text().strip() if upstream_checkbox.isChecked() else ""
            )
            dialog.accept()
            if self.proxy_running:
                reply = QMessageBox.question(
                    self, "Restart Required",
                    "Restart proxy to apply settings?",
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes
                )
                if reply == QMessageBox.Yes:
                    self._force_stop_proxy()
                    QTimer.singleShot(500, self.start_proxy)

        apply_btn.clicked.connect(_apply)
        btn_layout.addStretch()
        btn_layout.addWidget(cancel_btn)
        btn_layout.addWidget(apply_btn)
        layout.addLayout(btn_layout)

        dialog.exec_()

    # ── Qt event overrides ─────────────────────────────────────────────────

    def resizeEvent(self, event):
        """Keep the floating notes panel correctly positioned on window resize."""
        super().resizeEvent(event)
        if getattr(self, "_notes_panel_visible", False):
            self._reposition_notes_panel()

    def closeEvent(self, event):
        # Guard: closeEvent can be called twice if QApplication.quit() fires
        # while the window is already closing.
        if getattr(self, "_closing", False):
            event.accept()
            return
        self._closing = True

        logger.info("Shutting down Hunt GUI")
        # Always flush project notes before teardown
        try:
            if hasattr(self, "_notes_autosave_timer"):
                self._notes_autosave_timer.stop()
            self._save_project_notes()
        except Exception as e:
            logger.error(f"Error saving project notes on close: {e}")

        try:
            if hasattr(self, 'monitor_thread') and self.monitor_thread:
                self.monitor_thread.stop()
                self.monitor_thread.wait()
        except Exception as e:
            logger.error(f"Error stopping monitor thread: {e}")

        try:
            if hasattr(self, "ws_history_tab"):
                self.ws_history_tab.stop_monitor()
        except Exception as e:
            logger.error(f"Error stopping WS monitor: {e}")
        
        try:
            if self.proxy_health_monitor:
                self.proxy_health_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping health monitor: {e}")
        
        try:
            if self.proxy_output_reader:
                self.proxy_output_reader.stop()
        except Exception as e:
            logger.error(f"Error stopping output reader: {e}")
        
        try:
            if self.proxy_running:
                with self._proxy_lock:
                    self._force_stop_proxy()
        except Exception as e:
            logger.error(f"Error stopping proxy: {e}")
        
        try:
            if hasattr(self, 'intercept_tab'):
                self.intercept_tab.stop()
        except Exception as e:
            logger.error(f"Error stopping intercept tab: {e}")

        # Close any popped-out tab windows so they don't linger
        try:
            for win in list(getattr(self, "_popped_tabs", {}).values()):
                try:
                    win._main_window = None   # prevent re-dock attempt
                    win.close()
                except Exception:
                    pass
        except Exception:
            pass

        # Final flush — ensure any in-memory notes/highlights are on disk
        try:
            self.save_notes_to_file()
            self.save_highlights_to_file()
        except Exception as e:
            logger.error(f"Final save failed on close: {e}")

        # Flush attack surface + flows immediately (timer may not have fired yet)
        try:
            if hasattr(self, 'attack_surface_tab'):
                self.attack_surface_tab.save()
        except Exception as e:
            logger.error(f"Error saving attack surface on close: {e}")

        # Stop JWT tab ngrok tunnel + local JWKS server
        try:
            if hasattr(self, 'jwt_tab'):
                jwt = self.jwt_tab
                if getattr(jwt, '_ngrok_tunnel', None):
                    jwt._ngrok_tunnel.stop()
                    jwt._ngrok_tunnel.wait(3000)
                    jwt._ngrok_tunnel = None
                if getattr(jwt, '_local_jwks_server', None):
                    jwt._local_jwks_server.stop()
                    jwt._local_jwks_server.wait(2000)
                    jwt._local_jwks_server = None
        except Exception as e:
            logger.error(f"Error stopping JWT ngrok/server on close: {e}")

        event.accept()

    # ── All original methods below are PRESERVED unchanged ────────────────
    # (setup_window_geometry, apply_dark_theme, create_menu_bar,
    #  create_status_bar, on_load_progress, on_batch_loaded, on_load_complete,
    #  on_new_finding, on_stats_update, update_status_bar,
    #  save_current_note, clear_current_note, quick_add_note,
    #  load_vulnerabilities_organized, render_vulnerabilities, etc.)
    # These are inherited or defined in the original file and remain unchanged.
    # Only the sections above have been modified.

    def setup_window_geometry(self):
        screen = QApplication.primaryScreen().geometry()
        sw, sh = screen.width(), screen.height()
        ww = min(1800, int(sw * 0.9))
        wh = min(900,  int(sh * 0.9))
        self.setGeometry(max(0, (sw - ww) // 2), max(0, (sh - wh) // 2), ww, wh)
        self.setMinimumSize(1024, 600)


    def apply_dark_theme(self):
        """Apply Burp Suite inspired dark theme"""
        self.setStyleSheet(
            f"""
            /* ========================================
            MAIN WINDOW - Burp Suite Inspired
            ======================================== */
            QMainWindow {{
                background-color: {COLOR_BACKGROUND};
                border: none;
            }}
            
            QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
                font-family: {FONT_FAMILY};
                font-size: {FONT_SIZE_NORMAL};
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
            }}
            
            /* ========================================
            TAB WIDGET - Professional Burp Style
            ======================================== */
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                background-color: {COLOR_BACKGROUND};
                border-radius: 0px;
                margin: 0px;
                padding: 0px;
            }}
            
            QTabWidget::tab-bar {{
                alignment: left;
            }}
            
            QTabBar::tab {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_MUTED};
                padding: 8px 20px;
                margin-right: 2px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                font-weight: 500;
                font-size: {FONT_SIZE_NORMAL};
                min-width: 100px;
                min-height: 24px;
            }}
            
            QTabBar::tab:selected {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT_BRIGHT};
                border-color: {COLOR_BORDER};
                border-bottom-color: {COLOR_BACKGROUND};
                font-weight: 600;
            }}
            
            QTabBar::tab:hover:!selected {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
            }}
            
            QTabBar::tab:first {{
                margin-left: 4px;
            }}
            
            /* ========================================
            TABLE WIDGET - Burp Grid Style
            ======================================== */
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                alternate-background-color: {COLOR_CARD_BG};
                gridline-color: {COLOR_BORDER};
                border: 1px solid {COLOR_BORDER};
                border-radius: 0px;
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                outline: none;
            }}
            
            QTableWidget::item {{
                padding: 4px 8px;
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
                font-weight: 500;
            }}
            
            QTableWidget::item:hover {{
                background-color: {COLOR_HOVER};
            }}
            
            /* ========================================
            HEADER VIEW - Burp Header Style
            ======================================== */
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 6px 8px;
                border: 1px solid {COLOR_BORDER};
                border-left: none;
                border-top: none;
                font-weight: 600;
                font-size: {FONT_SIZE_NORMAL};
                text-align: left;
            }}
            
            QHeaderView::section:first {{
                border-left: 1px solid {COLOR_BORDER};
            }}
            
            QHeaderView::section:hover {{
                background-color: {COLOR_HOVER};
            }}
            
            /* ========================================
            TEXT EDIT - Code Editor Style
            ======================================== */
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 0px;
                padding: 4px;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
            }}
            
            QTextEdit:focus {{
                border: 1px solid {COLOR_ACCENT};
            }}
            
            /* ========================================
            LINE EDIT - Input Fields
            ======================================== */
            QLineEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 4px 8px;
                font-family: {FONT_FAMILY};
                font-size: {FONT_SIZE_NORMAL};
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
                min-height: 24px;
            }}
            
            QLineEdit:focus {{
                border: 1px solid {COLOR_ACCENT};
                background-color: {COLOR_CARD_BG};
            }}
            
            QLineEdit:hover {{
                border-color: {COLOR_BORDER_BRIGHT};
            }}
            
            /* ========================================
            PUSH BUTTON - Burp Button Style
            ======================================== */
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 6px 12px;
                font-weight: 500;
                font-size: {FONT_SIZE_NORMAL};
                min-width: 70px;
                min-height: 24px;
            }}
            
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                border-color: {COLOR_BORDER_BRIGHT};
            }}
            
            QPushButton:pressed {{
                background-color: {COLOR_BORDER};
                padding-top: 7px;
                padding-bottom: 5px;
            }}
            
            QPushButton:disabled {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_MUTED};
                border-color: {COLOR_BORDER};
            }}
            
            /* ========================================
            COMBO BOX - Dropdowns
            ======================================== */
            QComboBox {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 4px 8px;
                min-width: 100px;
                min-height: 24px;
                font-size: {FONT_SIZE_NORMAL};
            }}
            
            QComboBox:hover {{
                border-color: {COLOR_BORDER_BRIGHT};
                background-color: {COLOR_HOVER};
            }}
            
            QComboBox:focus {{
                border: 1px solid {COLOR_ACCENT};
            }}
            
            QComboBox::drop-down {{
                border: none;
                padding-right: 6px;
                width: 20px;
            }}
            
            QComboBox::down-arrow {{
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 5px solid {COLOR_TEXT};
                width: 0;
                height: 0;
            }}
            
            QComboBox QAbstractItemView {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                selection-background-color: {COLOR_ACCENT};
                selection-color: white;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 2px;
                outline: none;
            }}
            
            QComboBox QAbstractItemView::item {{
                padding: 4px 8px;
                min-height: 22px;
            }}
            
            QComboBox QAbstractItemView::item:hover {{
                background-color: {COLOR_HOVER};
            }}
            
            /* ========================================
            TREE WIDGET - Burp Tree Style
            ======================================== */
            QTreeWidget {{
                background-color: {COLOR_DARK_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 0px;
                selection-background-color: {COLOR_ACCENT};
                outline: none;
                alternate-background-color: {COLOR_DARK_BG};
            }}

            QTreeWidget::item {{
                padding: 4px;
                border: none;
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
            }}

            QTreeWidget::item:alternate {{
                background-color: {COLOR_DARK_BG};
            }}

            QTreeWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}

            QTreeWidget::item:hover {{
                background-color: {COLOR_HOVER};
            }}

            QTreeWidget::branch {{
                background-color: {COLOR_DARK_BG};
            }}
            
            /* ========================================
            STATUS BAR - Slim Footer
            ======================================== */
            QStatusBar {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
                border-top: 1px solid {COLOR_BORDER};
                font-size: {FONT_SIZE_SMALL};
                padding: 2px 8px;
                min-height: 24px;
            }}
            
            QStatusBar::item {{
                border: none;
            }}
            
            /* ========================================
            LABEL - Text Labels
            ======================================== */
            QLabel {{
                background-color: transparent;
                color: {COLOR_TEXT};
                font-size: {FONT_SIZE_NORMAL};
                padding: 2px;
            }}
            
            /* ========================================
            GROUP BOX - Panel Containers
            ======================================== */
            QGroupBox {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 0px;
                margin-top: 12px;
                padding-top: 16px;
                background-color: {COLOR_CARD_BG};
                font-weight: 600;
                font-size: {FONT_SIZE_NORMAL};
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px;
                color: {COLOR_TEXT_BRIGHT};
                background-color: {COLOR_CARD_BG};
            }}
            
            /* ========================================
            SCROLL BAR - Slim Scrollbars
            ======================================== */
            QScrollBar:vertical {{
                background-color: {COLOR_DARK_BG};
                width: 10px;
                border-radius: 0px;
                border: none;
            }}
            
            QScrollBar::handle:vertical {{
                background-color: {COLOR_BORDER_BRIGHT};
                border-radius: 0px;
                min-height: 30px;
            }}
            
            QScrollBar::handle:vertical:hover {{
                background-color: {COLOR_ACCENT};
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            QScrollBar:horizontal {{
                background-color: {COLOR_DARK_BG};
                height: 10px;
                border-radius: 0px;
                border: none;
            }}
            
            QScrollBar::handle:horizontal {{
                background-color: {COLOR_BORDER_BRIGHT};
                border-radius: 0px;
                min-width: 30px;
            }}
            
            QScrollBar::handle:horizontal:hover {{
                background-color: {COLOR_ACCENT};
            }}
            
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
                width: 0px;
            }}
            
            /* ========================================
            MENU BAR - Professional Menu
            ======================================== */
            QMenuBar {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 2px;
            }}
            
            QMenuBar::item {{
                padding: 4px 8px;
                background-color: transparent;
                border-radius: 3px;
            }}
            
            QMenuBar::item:selected {{
                background-color: {COLOR_HOVER};
                color: {COLOR_TEXT_BRIGHT};
            }}
            
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 2px;
            }}
            
            QMenu::item {{
                padding: 6px 20px 6px 8px;
                border-radius: 3px;
            }}
            
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            
            /* ========================================
            SPLITTER - Professional Divider
            ======================================== */
            QSplitter::handle {{
                background-color: {COLOR_BORDER};
            }}
            
            QSplitter::handle:hover {{
                background-color: {COLOR_ACCENT};
            }}
            
            QSplitter::handle:vertical {{
                height: 3px;
            }}
            
            QSplitter::handle:horizontal {{
                width: 3px;
            }}
            
            /* ========================================
            TOOLBAR - Professional Toolbar
            ======================================== */
            QToolBar {{
                background-color: {COLOR_ELEVATED_BG};
                border: none;
                border-bottom: 1px solid {COLOR_BORDER};
                spacing: 4px;
                padding: 4px;
            }}
            
            /* ========================================
            CHECKBOX & RADIO BUTTON
            ======================================== */
            QCheckBox {{
                spacing: 4px;
                color: {COLOR_TEXT};
            }}
            
            QCheckBox::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                background-color: {COLOR_DARK_BG};
            }}
            
            QCheckBox::indicator:hover {{
                border-color: {COLOR_BORDER_BRIGHT};
            }}
            
            QCheckBox::indicator:checked {{
                background-color: {COLOR_ACCENT};
                border-color: {COLOR_ACCENT};
            }}
            
            QRadioButton {{
                spacing: 4px;
                color: {COLOR_TEXT};
            }}
            
            QRadioButton::indicator {{
                width: 16px;
                height: 16px;
                border: 1px solid {COLOR_BORDER};
                border-radius: 8px;
                background-color: {COLOR_DARK_BG};
            }}
            
            QRadioButton::indicator:hover {{
                border-color: {COLOR_BORDER_BRIGHT};
            }}
            
            QRadioButton::indicator:checked {{
                background-color: {COLOR_ACCENT};
                border-color: {COLOR_ACCENT};
            }}
            
            /* ========================================
            PROGRESS BAR
            ======================================== */
            QProgressBar {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                background-color: {COLOR_DARK_BG};
                text-align: center;
                color: {COLOR_TEXT};
            }}
            
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_SUCCESS}, stop:1 {COLOR_ACCENT});
                border-radius: 2px;
            }}
            """
        )

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet(
            f"QMenuBar {{ background-color: {COLOR_LIGHTER_BG}; color: {COLOR_TEXT}; "
            f"min-height: 28px; }}"
        )
        # Ensure menu bar is always on top of central widget
        menubar.raise_()

        # File menu
        file_menu = menubar.addMenu("File")

        export_action = QAction("Export Findings...", self)
        export_action.triggered.connect(self.export_findings)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Projects menu
        projects_menu = menubar.addMenu("Projects")

        switch_project_action = QAction("Switch Project…", self)
        switch_project_action.setShortcut("Ctrl+Shift+P")
        switch_project_action.triggered.connect(self._switch_project)
        projects_menu.addAction(switch_project_action)

        projects_menu.addSeparator()

        delete_project_action = QAction("🗑  Delete Current Project…", self)
        delete_project_action.triggered.connect(self._delete_current_project)
        projects_menu.addAction(delete_project_action)

        # View menu
        view_menu = menubar.addMenu("View")

        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_data)
        view_menu.addAction(refresh_action)

        clear_action = QAction("Clear Findings", self)
        clear_action.triggered.connect(self.clear_findings)
        view_menu.addAction(clear_action)

        view_menu.addSeparator()

        self.url_view_action = QAction("🔗 Switch to URL column view", self)
        self.url_view_action.triggered.connect(self._switch_url_view_mode)
        view_menu.addAction(self.url_view_action)
        
        # Proxy menu
        proxy_menu = menubar.addMenu("Proxy")

        self.start_proxy_action = QAction("▶ Start Proxy", self)
        self.start_proxy_action.triggered.connect(self.start_proxy)
        proxy_menu.addAction(self.start_proxy_action)

        self.stop_proxy_action = QAction("⏹ Stop Proxy", self)
        self.stop_proxy_action.triggered.connect(self.stop_proxy)
        self.stop_proxy_action.setEnabled(False)
        proxy_menu.addAction(self.stop_proxy_action)

        proxy_menu.addSeparator()

        configure_proxy_action = QAction("⚙ Configure Proxy...", self)
        configure_proxy_action.triggered.connect(self.show_proxy_config)
        proxy_menu.addAction(configure_proxy_action)

        proxy_menu.addSeparator()

        view_proxy_log_action = QAction("📋 View Proxy Log", self)
        view_proxy_log_action.triggered.connect(self.show_proxy_log)
        proxy_menu.addAction(view_proxy_log_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        settings_menu = tools_menu.addMenu("⚙️  Settings")

        tokens_action = QAction("  Tokens  (GitHub, Ngrok)", self)
        tokens_action.triggered.connect(lambda: self.show_tools_config_dialog(open_tab=0))
        settings_menu.addAction(tokens_action)

        ai_action = QAction("  AI Settings", self)
        ai_action.triggered.connect(lambda: self.show_tools_config_dialog(open_tab=1))
        settings_menu.addAction(ai_action)

        tw_action = QAction("  Tools & Wordlists", self)
        tw_action.triggered.connect(lambda: self.show_tools_config_dialog(open_tab=2))
        settings_menu.addAction(tw_action)

        polyglot_action = QAction(" Set Polyglot Payload", self)
        polyglot_action.setToolTip(
            "Configure the multi-vulnerability polyglot payload used by\n"
            "Repeater → right-click → Test Polyglot"
        )
        polyglot_action.triggered.connect(self._edit_polyglot_payload)
        tools_menu.addAction(polyglot_action)

        proxy_cert_action = QAction("🔒 Proxy Certificate", self)
        proxy_cert_action.triggered.connect(self.show_proxy_certificate)
        proxy_menu.addAction(proxy_cert_action)

        # Help menu
        help_menu = menubar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def create_status_bar(self):
        """Create status bar"""
        self.status_bar = QStatusBar()
        self.status_bar.setObjectName("statusBar")
        self.setStatusBar(self.status_bar)

        # Status labels
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")

        self.requests_label = QLabel("Requests: 0")
        self.requests_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                padding: 0 8px;
                border-right: 1px solid {COLOR_BORDER};
            }}
        """
        )

        self.attack_surface_label = ClickableLabel("Attack Surface: 0")
        self.attack_surface_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                padding: 0 8px;
                border-right: 1px solid {COLOR_BORDER};
            }}
            QLabel:hover {{ color: {COLOR_ACCENT}; text-decoration: underline; }}
        """
        )
        self.attack_surface_label.setCursor(Qt.PointingHandCursor)
        self.attack_surface_label.setToolTip("Click to open Attack Surface tab")
        self.attack_surface_label.clicked.connect(self._go_to_attack_surface_tab)

        self.bugs_reported_label = ClickableLabel("Bugs Reported: 0")
        self.bugs_reported_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CRITICAL};
                font-weight: 600;
                padding: 0 8px;
            }}
            QLabel:hover {{ color: #ff6b6b; text-decoration: underline; }}
        """
        )
        self.bugs_reported_label.setCursor(Qt.PointingHandCursor)
        self.bugs_reported_label.setToolTip("Click to open Reports tab")
        self.bugs_reported_label.clicked.connect(self._go_to_reports_tab)

        # Progress bar for loading
        self.load_progress_bar = QProgressBar()
        self.load_progress_bar.setMaximumWidth(300)
        self.load_progress_bar.setMaximumHeight(18)
        self.load_progress_bar.setTextVisible(True)
        self.load_progress_bar.setStyleSheet(
            f"""
            QProgressBar {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                background-color: {COLOR_DARK_BG};
                text-align: center;
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_SMALL};
            }}
            QProgressBar::chunk {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_SUCCESS}, stop:1 {COLOR_ACCENT});
                border-radius: 2px;
            }}
        """
        )
        self.load_progress_bar.hide()
        
        # Proxy status label
        self.proxy_status_label = QLabel(" Proxy: Stopped")
        self.proxy_status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_MUTED};
                padding: 0 8px;
                border-left: 1px solid {COLOR_BORDER};
                font-weight: 600;
            }}
        """
        )

        # Project Notes toggle button
        self.project_notes_btn = ClickableLabel(" Project Notes ▼")
        self.project_notes_btn.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_ACCENT};
                font-weight: 600;
                padding: 0 10px;
                border-right: 1px solid {COLOR_BORDER};
            }}
            QLabel:hover {{ color: #a0c8ff; text-decoration: underline; }}
        """
        )
        self.project_notes_btn.setCursor(Qt.PointingHandCursor)
        self.project_notes_btn.setToolTip("Click to expand / collapse Project Notes")
        self.project_notes_btn.clicked.connect(self._toggle_project_notes)

        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.load_progress_bar)
        self.status_bar.addPermanentWidget(self.project_notes_btn)
        self.status_bar.addPermanentWidget(self.requests_label)
        self.status_bar.addPermanentWidget(self.attack_surface_label)
        self.status_bar.addPermanentWidget(self.bugs_reported_label)

        # Intercept status indicator (clickable toggle)
        self.intercept_status_label = ClickableLabel("⏸ Intercept: OFF")
        self.intercept_status_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_MUTED};
                padding: 0 8px;
                border-left: 1px solid {COLOR_BORDER};
                font-weight: 600;
            }}
            QLabel:hover {{ color: {COLOR_ACCENT}; text-decoration: underline; }}
        """
        )
        self.intercept_status_label.setCursor(Qt.PointingHandCursor)
        self.intercept_status_label.setToolTip("Click to toggle intercept ON/OFF")
        self.intercept_status_label.clicked.connect(self._toggle_intercept_from_statusbar)
        self.status_bar.addPermanentWidget(self.intercept_status_label)

        self.status_bar.addPermanentWidget(self.proxy_status_label)

    def on_load_progress(self, current: int, total: int, status_text: str):
        """Update progress bar during loading"""
        if not self._qt_widgets_alive():
            return
        try:
            self.load_progress_bar.show()
            if total > 0:
                self.load_progress_bar.setMaximum(total)
                self.load_progress_bar.setValue(current)
                percentage = int((current / total) * 100)
                self.load_progress_bar.setFormat(f"{percentage}%")
            else:
                self.load_progress_bar.setMaximum(0)
                self.load_progress_bar.setFormat("Counting...")
            self.status_label.setText(status_text)
            QApplication.processEvents()
        except RuntimeError:
            pass

    def on_batch_loaded(self, findings: List[Dict[str, Any]]):
        """Handle a batch of findings loaded - optimized"""
        self.history_table.setUpdatesEnabled(False)
        # Suppress per-row sitemap debounce — on_load_complete does one rebuild
        self._bulk_loading = True
        try:
            for finding in findings:
                self.findings.append(finding)
                self.add_history_row(finding)
        finally:
            self._bulk_loading = False
            self.history_table.setUpdatesEnabled(True)
        
        self._sitemap_dirty = True
        self._issues_dirty = True
        
    def on_load_complete(self, total_count: int):
        """Handle completion of initial data load"""
        self.load_progress_bar.hide()
        
        # Stop any pending debounce timer that may have been queued during
        # the last batch (bulk_loading suppresses most, but one may have slipped
        # through between _bulk_loading=False and this handler running).
        if hasattr(self, '_sitemap_rebuild_timer'):
            self._sitemap_rebuild_timer.stop()
        # Ensure sitemap lock is clear so the rebuild shows all hosts
        self._sitemap_locked = False
        self._sitemap_selected_host = ""
        self._sitemap_pending_rebuild = False

        # Apply filters to ensure table state matches settings (scope, etc.)
        self.apply_filters()
        
        # Cancel debounce from apply_filters
        if hasattr(self, '_sitemap_rebuild_timer'):
            self._sitemap_rebuild_timer.stop()

        # Always rebuild sitemap to match the filtered table
        self.update_sitemap_tree()
        self._sitemap_dirty = False
        
        if self._issues_dirty:
            self._issues_dirty = False
        
        self.update_issue_filter_dropdown()
        
        logger.info(f"Initial data load complete: {total_count} findings")
        if self._qt_widgets_alive():
            try:
                self.status_label.setText(f"✅ Loaded {total_count:,} findings")
            except RuntimeError:
                pass
        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def on_new_finding(self, finding: Dict[str, Any]):
        """Single-finding shim — routes to batch handler."""
        self.on_new_findings_batch([finding])

    def on_new_findings_batch(self, findings: List[Dict[str, Any]]):
        """Handle a live batch of new findings from the monitor thread.

        All work that can be deferred is deferred; only the table rows are
        inserted immediately so the user sees new requests arrive promptly.
        Heavy views (sitemap, issue filter, mapping, js-miner) are updated
        via a coalescing timer so bursts of traffic don't block the UI.
        """
        if not findings:
            return

        # Insert rows with updates suppressed — vastly faster for bursts
        self.history_table.setUpdatesEnabled(False)
        self._bulk_loading = True
        try:
            for finding in findings:
                self.findings.append(finding)
                self.add_history_row(finding)
        finally:
            self._bulk_loading = False
            self.history_table.setUpdatesEnabled(True)

        # Queue findings for deferred heavy-view processing
        if not hasattr(self, '_pending_live_findings'):
            self._pending_live_findings: List[Dict[str, Any]] = []
        self._pending_live_findings.extend(findings)

        # Coalescing timer: deferred heavy work fires at most every 2 s
        if not hasattr(self, '_batch_update_timer'):
            self._batch_update_timer = QTimer()
            self._batch_update_timer.setSingleShot(True)
            self._batch_update_timer.timeout.connect(self._update_heavy_views)
        self._batch_update_timer.start(2000)

    def _update_heavy_views(self):
        """Flush deferred heavy view updates after a quiet period."""
        pending = getattr(self, '_pending_live_findings', [])
        self._pending_live_findings = []

        if hasattr(self, 'mapping_tab') and pending:
            for f in pending:
                self.mapping_tab.map_new_url(f)

        if hasattr(self, 'js_miner_tab') and pending:
            for f in pending:
                self.js_miner_tab.feed_finding(f)

        self.update_issue_filter_dropdown()
    
    def on_stats_update(self, stats: Dict[str, int]):
        """Handle stats update from monitor thread"""
        if not self._qt_widgets_alive():
            return
        try:
            req_count = (
                len(self.findings)
                if hasattr(self, 'findings') else stats.get('total', 0)
            )
            self.requests_label.setText(f"Requests: {req_count}")
            as_count = (
                len(self.attack_surface_tab._entries)
                if hasattr(self, 'attack_surface_tab') else 0
            )
            self.attack_surface_label.setText(f"Attack Surface: {as_count}")
            bugs_count = (
                len(self.report_tab._reports)
                if hasattr(self, 'report_tab') else 0
            )
            self.bugs_reported_label.setText(f"Bugs Reported: {bugs_count}")
        except RuntimeError:
            pass

    # Notes methods
    def quick_add_note(self, row: int, finding_index: int):
        """Open a popup dialog to add/edit the note for the selected request."""
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLabel
        from PyQt5.QtGui import QColor
        from constants import COLOR_ACCENT, COLOR_DARK_BG, COLOR_TEXT, COLOR_BORDER, COLOR_ELEVATED_BG, COLOR_TEXT_BRIGHT

        # Use seq as the stable persistence key (survives JSONL re-reads across restarts)
        finding = self.findings[finding_index] if finding_index < len(self.findings) else {}
        note_key = finding.get("seq", finding_index)

        existing_note = self.notes_storage.get(note_key, "")
        url = finding.get("url", "")
        url_short = url[:80] + ("..." if len(url) > 80 else "")

        dlg = QDialog(self)
        dlg.setWindowTitle(" Add / Edit Note")
        dlg.setMinimumWidth(520)
        dlg.setMinimumHeight(300)
        dlg.setStyleSheet(f"""
            QDialog {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; }}
            QLabel  {{ color: {COLOR_TEXT_BRIGHT}; }}
            QTextEdit {{
                background-color: {COLOR_ELEVATED_BG};
                color: #ffffff;
                border: 1px solid {COLOR_BORDER};
                font-family: Consolas, monospace;
                font-size: 12px;
            }}
            QPushButton {{
                padding: 5px 16px;
                border-radius: 4px;
                font-weight: 600;
            }}
        """)

        layout = QVBoxLayout(dlg)
        layout.setSpacing(8)

        if url_short:
            url_lbl = QLabel(url_short)
            url_lbl.setStyleSheet(f"color: {COLOR_ACCENT}; font-size: 11px;")
            url_lbl.setWordWrap(True)
            layout.addWidget(url_lbl)

        editor = QTextEdit()
        editor.setPlaceholderText("Add your notes here...")
        editor.setPlainText(existing_note)
        layout.addWidget(editor, 1)

        btn_row = QHBoxLayout()
        btn_row.addStretch()

        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.setStyleSheet(f"background:#3a3a3a;color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};")
        clear_btn.clicked.connect(editor.clear)
        btn_row.addWidget(clear_btn)

        save_btn = QPushButton("💾 Save")
        save_btn.setStyleSheet(f"background:{COLOR_ACCENT};color:white;border:none;")
        save_btn.setDefault(True)
        btn_row.addWidget(save_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"background:#3a3a3a;color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};")
        cancel_btn.clicked.connect(dlg.reject)
        btn_row.addWidget(cancel_btn)

        layout.addLayout(btn_row)

        def _save():
            note_text = editor.toPlainText().strip()
            if note_text:
                self.notes_storage[note_key] = note_text
                notes_item = self.history_table.item(row, 8)
                if notes_item:
                    notes_item.setText(note_text.split("\n")[0][:60])
                    notes_item.setForeground(QColor(COLOR_ACCENT))
                    notes_item.setToolTip(note_text)
                self.save_notes_to_file()
                self.status_label.setText("✅ Note saved")
            else:
                self.notes_storage.pop(note_key, None)
                notes_item = self.history_table.item(row, 8)
                if notes_item:
                    notes_item.setText("")
                    notes_item.setToolTip("")
                self.save_notes_to_file()
                self.status_label.setText("🗑️ Note removed")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))
            dlg.accept()

        save_btn.clicked.connect(_save)
        dlg.exec_()

    # ========================================================================
    # VULNERABILITY DISPLAY
    # ========================================================================
    def load_vulnerabilities_organized(self, finding: Dict[str, Any]):
        """Load and display vulnerabilities in organized format"""
        if not hasattr(self, 'vuln_text'):
            return
            
        params = finding.get("params", {})
        self.current_vuln_params = params

        if not params:
            self.vuln_text.setHtml(
                f"<p style='color: {COLOR_LOW};'>No vulnerabilities detected</p>"
            )
            if hasattr(self, 'vuln_stats_label'):
                self.vuln_stats_label.setText("0 findings")
            return

        total_findings = len(params)
        critical_count = sum(
            1
            for v in params.values()
            if any(
                "CRITICAL" in str(d) for d in (v if isinstance(v, (list, set)) else [v])
            )
        )
        if hasattr(self, 'vuln_stats_label'):
            self.vuln_stats_label.setText(
                f"{total_findings} findings ({critical_count} critical)"
            )

        if hasattr(self, 'vuln_view_combo') and self.vuln_view_combo.currentText() == "":
            self.vuln_view_combo.setCurrentText("Detailed")

        self.render_vulnerabilities()

    def render_vulnerabilities(self):
        """Render vulnerabilities based on current view mode and filters"""
        if not hasattr(self, 'vuln_text'):
            return
            
        if not self.current_vuln_params:
            self.vuln_text.setHtml(
                f"<p style='color: {COLOR_LOW};'>No vulnerabilities detected</p>"
            )
            return

        filtered_params = self.apply_vuln_filter(self.current_vuln_params)

        if not filtered_params:
            self.vuln_text.setHtml(
                f"<p style='color: {COLOR_MEDIUM};'>No vulnerabilities match the current filter</p>"
            )
            return

        view_mode = self.vuln_view_combo.currentText() if hasattr(self, 'vuln_view_combo') else "Detailed"

        if view_mode == "Compact":
            html = self.render_compact_view(filtered_params)
        else:
            html = self.render_detailed_view(filtered_params)

        self.vuln_text.setHtml(html)

    def apply_vuln_filter(self, params: Dict) -> Dict:
        """Apply severity/type filter to vulnerabilities"""
        filter_mode = self.vuln_severity_filter.currentText() if hasattr(self, 'vuln_severity_filter') else "All"

        if filter_mode == "All":
            return params

        filtered = {}
        for param_name, detections in params.items():
            det_list = (
                detections if isinstance(detections, (list, set)) else [detections]
            )
            det_str = " ".join(str(d) for d in det_list)

            if filter_mode == "Critical Only":
                if "CRITICAL" in det_str:
                    filtered[param_name] = detections
            elif filter_mode == "High+":
                if any(
                    term in det_str
                    for term in ["CRITICAL", "HIGH", "XSS", "SQLI", "RCE"]
                ):
                    filtered[param_name] = detections
            elif filter_mode == "XSS Only":
                if "XSS" in det_str:
                    filtered[param_name] = detections
            elif filter_mode == "SQL Only":
                if "SQL" in det_str:
                    filtered[param_name] = detections

        return filtered

    def render_professional_view(self, params: Dict) -> str:
        """Render ultra-premium view - maximum clarity and professionalism"""
        html = []
        html.append(
            f"""<html><head><style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{ 
                font-family: {FONT_FAMILY}; 
                font-size: {FONT_SIZE_NORMAL}; 
                background-color: {COLOR_DARK_BG}; 
                color: {COLOR_TEXT}; 
                padding: {SPACE_LG};
                line-height: 1.7;
            }}
            
            .category-section {{
                margin-bottom: {SPACE_XL};
            }}
            
            .category-header {{
                background: linear-gradient(135deg, {COLOR_ELEVATED_BG} 0%, {COLOR_LIGHTER_BG} 100%);
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_LARGE};
                font-weight: 700;
                padding: {SPACE_MD} {SPACE_LG};
                margin-bottom: {SPACE_MD};
                border-radius: {RADIUS_LARGE};
                border-left: 4px solid {COLOR_ACCENT};
                box-shadow: {SHADOW_MEDIUM};
                letter-spacing: 0.5px;
                display: flex;
                align-items: center;
            }}
            
            .category-icon {{
                font-size: {FONT_SIZE_XLARGE};
                margin-right: {SPACE_MD};
            }}
            
            .finding-card {{
                background: {COLOR_CARD_BG};
                border: 2px solid {COLOR_BORDER};
                border-left: 5px solid {COLOR_ACCENT};
                padding: 0;
                margin-bottom: {SPACE_MD};
                border-radius: {RADIUS_LARGE};
                box-shadow: {SHADOW_MEDIUM};
                overflow: hidden;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            
            .finding-card:hover {{
                box-shadow: {SHADOW_LARGE};
                transform: translateY(-4px);
                border-color: {COLOR_BORDER_BRIGHT};
            }}
            
            .finding-card.critical {{ 
                border-left-color: {COLOR_CRITICAL};
                background: linear-gradient(135deg, {COLOR_CARD_BG} 0%, {COLOR_CRITICAL_BG} 100%);
            }}
            
            .finding-card.critical:hover {{
                box-shadow: {SHADOW_GLOW_CRITICAL};
            }}
            
            .finding-card.high {{ 
                border-left-color: {COLOR_HIGH};
                background: linear-gradient(135deg, {COLOR_CARD_BG} 0%, {COLOR_HIGH_BG} 100%);
            }}
            
            .finding-card.high:hover {{
                box-shadow: {SHADOW_GLOW_HIGH};
            }}
            
            .finding-card.medium {{ 
                border-left-color: {COLOR_MEDIUM};
                background: linear-gradient(135deg, {COLOR_CARD_BG} 0%, {COLOR_MEDIUM_BG} 100%);
            }}
            
            .finding-card.low {{ 
                border-left-color: {COLOR_LOW};
                background: linear-gradient(135deg, {COLOR_CARD_BG} 0%, {COLOR_LOW_BG} 100%);
            }}
            
            .card-header {{
                background: {COLOR_ELEVATED_BG};
                padding: {SPACE_MD} {SPACE_LG};
                border-bottom: 1px solid {COLOR_BORDER};
                display: flex;
                align-items: center;
                justify-content: space-between;
            }}
            
            .param-section {{
                display: flex;
                align-items: center;
                gap: {SPACE_MD};
            }}
            
            .severity-icon {{
                font-size: {FONT_SIZE_XLARGE};
                line-height: 1;
            }}
            
            .param-name {{ 
                color: {COLOR_TEXT_BRIGHT};
                font-weight: 600; 
                font-size: {FONT_SIZE_LARGE};
                font-family: {FONT_FAMILY_MONO};
                letter-spacing: 0.3px;
            }}
            
            .severity-badge {{
                display: inline-flex;
                align-items: center;
                gap: {SPACE_XS};
                padding: {SPACE_XS} {SPACE_MD};
                border-radius: 16px;
                font-size: {FONT_SIZE_SMALL};
                font-weight: 700;
                letter-spacing: 1px;
                text-transform: uppercase;
                box-shadow: {SHADOW_SMALL};
                border: 1px solid transparent;
            }}
            
            .severity-critical {{ 
                background: linear-gradient(135deg, {COLOR_CRITICAL} 0%, #E63946 100%); 
                color: white;
                border-color: rgba(255, 255, 255, 0.3);
            }}
            
            .severity-high {{ 
                background: linear-gradient(135deg, {COLOR_HIGH} 0%, #FF8A65 100%); 
                color: white;
                border-color: rgba(255, 255, 255, 0.3);
            }}
            
            .severity-medium {{ 
                background: linear-gradient(135deg, {COLOR_MEDIUM} 0%, #FFD54F 100%); 
                color: {COLOR_DARK_BG}; 
                border-color: rgba(0, 0, 0, 0.2);
            }}
            
            .severity-low {{ 
                background: linear-gradient(135deg, {COLOR_LOW} 0%, #4DD0E1 100%); 
                color: {COLOR_DARK_BG}; 
                border-color: rgba(0, 0, 0, 0.2);
            }}
            
            .card-body {{
                padding: {SPACE_LG};
            }}
            
            .vuln-badge-container {{
                margin-bottom: {SPACE_MD};
                display: flex;
                flex-wrap: wrap;
                gap: {SPACE_SM};
            }}
            
            .vuln-badge {{ 
                background: {COLOR_CRITICAL_BG};
                color: {COLOR_CRITICAL};
                padding: {SPACE_SM} {SPACE_MD};
                border-radius: {RADIUS_SMALL};
                font-weight: 700;
                font-size: {FONT_SIZE_SMALL};
                border: 2px solid {COLOR_CRITICAL};
                display: inline-flex;
                align-items: center;
                gap: {SPACE_XS};
                box-shadow: {SHADOW_SMALL};
            }}
            
            .vuln-badge-icon {{
                font-size: {FONT_SIZE_NORMAL};
            }}
            
            .details-section {{
                margin-top: {SPACE_MD};
                padding-top: {SPACE_MD};
                border-top: 2px solid {COLOR_BORDER};
            }}
            
            .details-table {{
                width: 100%;
                border-collapse: separate;
                border-spacing: 0;
                margin-top: {SPACE_SM};
            }}
            
            .details-row {{
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            
            .details-row:last-child {{
                border-bottom: none;
            }}
            
            .detail-label {{
                padding: {SPACE_SM} {SPACE_MD};
                background: {COLOR_ELEVATED_BG};
                color: {COLOR_ACCENT};
                font-weight: 600;
                font-size: {FONT_SIZE_SMALL};
                text-transform: uppercase;
                letter-spacing: 0.5px;
                width: 140px;
                vertical-align: top;
                border-right: 2px solid {COLOR_BORDER};
            }}
            
            .detail-value {{
                padding: {SPACE_SM} {SPACE_MD};
                color: {COLOR_TEXT_BRIGHT};
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                word-break: break-word;
                line-height: 1.6;
            }}
            
            .detail-value code {{
                background: {COLOR_DARK_BG};
                padding: 2px {SPACE_XS};
                border-radius: 3px;
                color: {COLOR_ACCENT};
                font-size: {FONT_SIZE_TINY};
            }}
            
            .empty-state {{
                text-align: center;
                padding: {SPACE_XL};
                color: {COLOR_TEXT_MUTED};
                font-size: {FONT_SIZE_NORMAL};
            }}
            
            .section-divider {{
                height: 2px;
                background: linear-gradient(90deg, 
                    transparent 0%, 
                    {COLOR_BORDER} 50%, 
                    transparent 100%);
                margin: {SPACE_LG} 0;
            }}
        </style></head><body>"""
        )

        categorized = {}
        for param_name, detections in params.items():
            category = param_name.split()[0] if " " in param_name else param_name
            if category not in categorized:
                categorized[category] = []
            categorized[category].append((param_name, detections))

        for category in VulnerabilityCategories.CATEGORY_ORDER:
            if category not in categorized:
                continue

            category_name = VulnerabilityCategories.CATEGORY_HEADERS.get(
                category, category
            )

            parts = category_name.split(" ", 1)
            category_icon = parts[0] if len(parts) > 1 else "📊"
            category_text = parts[1] if len(parts) > 1 else category_name

            html.append(f"<div class='category-section'>")
            html.append(f"<div class='category-header'>")
            html.append(f"<span class='category-icon'>{category_icon}</span>")
            html.append(f"<span>{category_text}</span>")
            html.append(f"</div>")

            for param_name, detections in categorized[category]:
                det_list = (
                    detections if isinstance(detections, (list, set)) else [detections]
                )
                det_str = " ".join(str(d) for d in det_list)

                if "CRITICAL" in det_str:
                    severity_class = "critical"
                    dot_class = "dot-critical"
                elif any(term in det_str for term in ["HIGH", "XSS", "SQLI"]):
                    severity_class = "high"
                    dot_class = "dot-high"
                elif "MEDIUM" in det_str:
                    severity_class = "medium"
                    dot_class = "dot-medium"
                else:
                    severity_class = "low"
                    dot_class = "dot-low"

                display_name = (
                    param_name.split(" ", 1)[1] if " " in param_name else param_name
                )

                vulns = [
                    d
                    for d in det_list
                    if d in VulnerabilityCategories.VULNERABILITY_TYPES
                ]
                vuln_str = " | ".join(vulns) if vulns else "DETECTED"

                html.append(f"<div class='line {severity_class}'>")
                html.append(f"<span class='severity-dot {dot_class}'></span>")
                html.append(f"<span class='param'>{html_escape(display_name)}</span>")
                html.append(f"<span class='arrow'>→</span>")
                html.append(f"<span class='vuln'>{vuln_str}</span>")
                html.append(f"</div>")

        html.append("</div></body></html>")
        return "".join(html)

    def render_compact_view(self, params: Dict) -> str:
        """Render ultra-compact view - crystal clear one-line display"""
        html = []
        html.append(
            f"""<html><head><style>
            body {{ 
                font-family: {FONT_FAMILY_MONO}; 
                font-size: {FONT_SIZE_SMALL}; 
                background-color: {COLOR_DARK_BG}; 
                color: {COLOR_TEXT}; 
                padding: {SPACE_MD};
                line-height: 1.8;
            }}
            
            .compact-container {{
                background: {COLOR_CARD_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: {RADIUS_MEDIUM};
                padding: {SPACE_MD};
                box-shadow: {SHADOW_SMALL};
            }}
            
            .line {{ 
                padding: {SPACE_SM} {SPACE_MD};
                margin: {SPACE_XS} 0;
                border-radius: {RADIUS_SMALL};
                border-left: 3px solid transparent;
                transition: all 0.2s ease;
                display: flex;
                align-items: center;
                gap: {SPACE_MD};
            }}
            
            .line:hover {{
                background: {COLOR_ELEVATED_BG};
                transform: translateX(4px);
            }}
            
            .critical {{ 
                color: {COLOR_CRITICAL}; 
                font-weight: 700;
                border-left-color: {COLOR_CRITICAL};
                background: {COLOR_CRITICAL_BG};
            }}
            
            .high {{ 
                color: {COLOR_HIGH}; 
                font-weight: 700;
                border-left-color: {COLOR_HIGH};
                background: {COLOR_HIGH_BG};
            }}
            
            .medium {{ 
                color: {COLOR_MEDIUM};
                font-weight: 600;
                border-left-color: {COLOR_MEDIUM};
                background: {COLOR_MEDIUM_BG};
            }}
            
            .low {{ 
                color: {COLOR_LOW};
                border-left-color: {COLOR_LOW};
                background: {COLOR_LOW_BG};
            }}
            
            .severity-dot {{
                width: 10px;
                height: 10px;
                border-radius: 50%;
                display: inline-block;
                flex-shrink: 0;
            }}
            
            .dot-critical {{ background: {COLOR_CRITICAL}; box-shadow: 0 0 8px {COLOR_CRITICAL}; }}
            .dot-high {{ background: {COLOR_HIGH}; box-shadow: 0 0 8px {COLOR_HIGH}; }}
            .dot-medium {{ background: {COLOR_MEDIUM}; box-shadow: 0 0 6px {COLOR_MEDIUM}; }}
            .dot-low {{ background: {COLOR_LOW}; box-shadow: 0 0 6px {COLOR_LOW}; }}
            
            .param {{ 
                color: {COLOR_TEXT_BRIGHT}; 
                font-weight: 600;
                flex: 0 0 250px;
            }}
            
            .arrow {{
                color: {COLOR_TEXT_MUTED};
                flex-shrink: 0;
            }}
            
            .vuln {{ 
                color: {COLOR_CRITICAL};
                font-weight: 700;
                flex: 1;
            }}
            
            .category-divider {{
                height: 2px;
                background: linear-gradient(90deg, 
                    transparent 0%, 
                    {COLOR_BORDER} 50%, 
                    transparent 100%);
                margin: {SPACE_MD} 0;
            }}
            
            .category-label {{
                color: {COLOR_ACCENT};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                margin: {SPACE_MD} 0 {SPACE_SM} 0;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}
        </style></head><body>
        <div class='compact-container'>"""
        )

        categorized = {}
        for param_name, detections in params.items():
            category = param_name.split()[0] if " " in param_name else param_name
            if category not in categorized:
                categorized[category] = []
            categorized[category].append((param_name, detections))

        first_category = True
        for category in VulnerabilityCategories.CATEGORY_ORDER:
            if category not in categorized:
                continue

            if not first_category:
                html.append("<div class='category-divider'></div>")
            first_category = False

            category_name = VulnerabilityCategories.CATEGORY_HEADERS.get(
                category, f"📊 {category}"
            )
            html.append(f"<div class='category-label'>{category_name}</div>")

            for param_name, detections in categorized[category]:
                det_list = (
                    detections if isinstance(detections, (list, set)) else [detections]
                )
                det_str = " ".join(str(d) for d in det_list)

                if "CRITICAL" in det_str:
                    severity_class = "critical"
                    dot_class = "dot-critical"
                elif any(term in det_str for term in ["HIGH", "XSS", "SQLI"]):
                    severity_class = "high"
                    dot_class = "dot-high"
                elif "MEDIUM" in det_str:
                    severity_class = "medium"
                    dot_class = "dot-medium"
                else:
                    severity_class = "low"
                    dot_class = "dot-low"

                display_name = (
                    param_name.split(" ", 1)[1] if " " in param_name else param_name
                )

                vulns = [
                    d
                    for d in det_list
                    if d in VulnerabilityCategories.VULNERABILITY_TYPES
                ]
                vuln_str = " | ".join(vulns) if vulns else "DETECTED"

                html.append(f"<div class='line {severity_class}'>")
                html.append(f"<span class='severity-dot {dot_class}'></span>")
                html.append(f"<span class='param'>{html_escape(display_name)}</span>")
                html.append(f"<span class='arrow'>→</span>")
                html.append(f"<span class='vuln'>{vuln_str}</span>")
                html.append(f"</div>")

        html.append("</div></body></html>")
        return "".join(html)

    def render_detailed_view(self, params: Dict) -> str:
        """Render detailed view - full technical details (original format)"""
        html_output = []
        html_output.append("<html><head><style>")
        html_output.append(
            f"""
            body {{ 
                font-family: 'Consolas', 'Monaco', monospace; 
                font-size: 10pt; 
                background-color: {COLOR_DARK_BG}; 
                color: {COLOR_TEXT}; 
                padding: 10px; 
            }}
            .category {{ 
                color: {COLOR_ACCENT}; 
                font-weight: bold; 
                font-size: 11pt; 
                margin-top: 15px; 
                margin-bottom: 8px; 
            }}
            .param-line {{ 
                margin-left: 20px; 
                margin-bottom: 10px; 
                line-height: 1.8; 
            }}
            .param-name {{ color: #ffffff; font-weight: bold; }}
            .finding {{ 
                color: {COLOR_LOW}; 
                word-wrap: break-word; 
                overflow-wrap: break-word; 
            }}
            .critical {{ color: {COLOR_CRITICAL}; font-weight: bold; }}
            .high {{ color: {COLOR_HIGH}; font-weight: bold; }}
            .medium {{ color: {COLOR_MEDIUM}; }}
            .low {{ color: {COLOR_LOW}; }}
            .xss {{ color: {COLOR_CRITICAL}; font-weight: bold; }}
            .sqli {{ color: {COLOR_CRITICAL}; font-weight: bold; }}
            .exploitable {{ color: {COLOR_SUCCESS}; font-weight: bold; }}
            .sink {{ color: {COLOR_MEDIUM}; }}
            .source {{ color: #ff88ff; }}
            .flow {{ 
                color: #ffffff; 
                word-wrap: break-word; 
                overflow-wrap: break-word; 
                max-width: 800px; 
            }}
            .code {{ 
                color: #808080; 
                font-style: italic; 
                word-wrap: break-word; 
                overflow-wrap: break-word; 
                max-width: 800px; 
            }}
            .detail-line {{ 
                margin-left: 40px; 
                margin-bottom: 3px; 
                font-size: 9pt; 
                line-height: 1.6; 
            }}
            .arrow {{ color: {COLOR_LOW}; font-weight: bold; }}
        """
        )
        html_output.append("</style></head><body>")

        categorized_params: Dict[str, List[Tuple[str, Any]]] = {}

        for param_name, detections in params.items():
            category = param_name.split()[0] if " " in param_name else param_name

            if category not in categorized_params:
                categorized_params[category] = []

            categorized_params[category].append((param_name, detections))

        for category in VulnerabilityCategories.CATEGORY_ORDER:
            if category not in categorized_params:
                continue

            header = VulnerabilityCategories.CATEGORY_HEADERS.get(
                category, f"📊 {category}"
            )

            html_output.append(f"<div class='category'>{header}</div>")

            for param_name, detections in categorized_params[category]:
                display_name = (
                    param_name.split(" ", 1)[1] if " " in param_name else param_name
                )

                if isinstance(detections, set):
                    detections = list(detections)
                elif not isinstance(detections, list):
                    detections = [detections]

                if category in ["JQUERY_XSS", "DOM_XSS", "DOM_XSS_CONFIRMED"] and any(
                    "SINK:" in str(d) or "SOURCE:" in str(d) for d in detections
                ):
                    self._display_detailed_xss(html_output, display_name, detections)
                else:
                    self._display_regular_param_html(
                        html_output, display_name, detections
                    )

        for category, params_list in categorized_params.items():
            if category not in VulnerabilityCategories.CATEGORY_ORDER:
                header = VulnerabilityCategories.CATEGORY_HEADERS.get(
                    category, f"📊 {category}"
                )
                html_output.append(f"<div class='category'>{header}</div>")

                for param_name, detections in params_list:
                    display_name = (
                        param_name.split(" ", 1)[1] if " " in param_name else param_name
                    )

                    if isinstance(detections, set):
                        detections = list(detections)
                    elif not isinstance(detections, list):
                        detections = [detections]

                    self._display_regular_param_html(
                        html_output, display_name, detections
                    )

        html_output.append("</body></html>")
        return "".join(html_output)

    def _display_detailed_xss(
        self, html_output: List[str], param_name: str, detections: List[Any]
    ):
        """Display detailed XSS information (jQuery/DOM XSS)"""
        severity = ""
        exploitable = False
        sink = ""
        sources = []
        data_flows = []
        code = ""
        vuln_types = []

        for detection in detections:
            detection_str = str(detection)

            if "CRITICAL" in detection_str:
                severity = "CRITICAL"
            elif "HIGH" in detection_str and not severity:
                severity = "HIGH"
            elif "MEDIUM" in detection_str and not severity:
                severity = "MEDIUM"

            if "EXPLOITABLE" in detection_str:
                exploitable = True

            if "SINK:" in detection_str:
                match = RegexPatterns.SINK_PATTERN.search(detection_str)
                if match and not sink:
                    sink = match.group(1).strip()

            if "SOURCE:" in detection_str:
                for match in RegexPatterns.SOURCE_PATTERN.finditer(detection_str):
                    source = match.group(1).strip()
                    if source not in sources:
                        sources.append(source)

            if "DATA_FLOW:" in detection_str:
                for match in RegexPatterns.DATA_FLOW_PATTERN.finditer(detection_str):
                    flow = match.group(1).strip()
                    if flow not in data_flows:
                        data_flows.append(flow)

            if "CODE:" in detection_str and not code:
                match = RegexPatterns.CODE_PATTERN.search(detection_str)
                if match:
                    code = match.group(1).strip()
                    if len(code) > MAX_CODE_SNIPPET_LENGTH:
                        code = code[: MAX_CODE_SNIPPET_LENGTH - 3] + "..."

            for vuln in ["XSS", "SQLI", "RCE", "SSRF", "LFI", "IDOR"]:
                if vuln in detection_str and vuln not in vuln_types:
                    vuln_types.append(vuln)

        severity_class = severity.lower() if severity else ""

        html_output.append("<div class='param-line'>")
        html_output.append(f"<span class='param-name'>{param_name}</span>")

        if severity:
            html_output.append(f" <span class='{severity_class}'>[{severity}]</span>")

        if exploitable:
            html_output.append(" <span class='exploitable'>✓ EXPLOITABLE</span>")

        html_output.append("</div>")

        if sink:
            html_output.append(
                f"<div class='detail-line'><span class='arrow'>→ Sink:</span> "
                f"<span class='sink'>{sink}</span></div>"
            )

        if sources:
            primary_source = sources[0]
            for src in sources:
                if "decoded + sliced" in src:
                    primary_source = src
                    break
                elif "decoded" in src and "decoded" not in primary_source:
                    primary_source = src

            html_output.append(
                f"<div class='detail-line'><span class='arrow'>→ Source:</span> "
                f"<span class='source'>{primary_source}</span></div>"
            )

        if data_flows:
            primary_flow = max(data_flows, key=len) if data_flows else ""
            if len(primary_flow) > 80:
                primary_flow = primary_flow[:77] + "..."
            html_output.append(
                f"<div class='detail-line'><span class='arrow'>→ Flow:</span> "
                f"<span class='flow'>{primary_flow}</span></div>"
            )

        if code:
            html_output.append(
                f"<div class='detail-line'><span class='arrow'>→ Code:</span> "
                f"<span class='code'>{code}</span></div>"
            )

        if vuln_types:
            vulns_str = ", ".join(vuln_types)
            html_output.append(
                f"<div class='detail-line'><span class='arrow'>→ Type:</span> "
                f"<span class='xss'>{vulns_str}</span></div>"
            )

        html_output.append("<div style='margin-bottom: 10px;'></div>")

    def _display_regular_param_html(
        self, html_output: List[str], param_name: str, detections: List[Any]
    ):
        """Display regular parameter with findings"""
        findings_for_brackets = []
        vulnerabilities_found: Set[str] = set()

        for detection in detections:
            detection_str = str(detection).strip()

            is_pure_vuln = detection_str in VulnerabilityCategories.VULNERABILITY_TYPES

            if is_pure_vuln:
                vulnerabilities_found.add(detection_str)
            else:
                temp_detection = detection_str
                found_vuln_in_this = False

                for vuln in VulnerabilityCategories.VULNERABILITY_TYPES:
                    pattern = r"\b" + re.escape(vuln) + r"\b"
                    if re.search(pattern, temp_detection):
                        vulnerabilities_found.add(vuln)
                        found_vuln_in_this = True
                        temp_detection = re.sub(pattern, "", temp_detection)

                temp_detection = re.sub(r"\s*\|\s*", " | ", temp_detection)
                temp_detection = re.sub(r"\s+", " ", temp_detection)
                temp_detection = temp_detection.strip("|").strip()

                if temp_detection:
                    findings_for_brackets.append(temp_detection)
                elif not found_vuln_in_this:
                    findings_for_brackets.append(detection_str)

        html_output.append("<div class='param-line'>")
        html_output.append(f"<span class='param-name'>{param_name}</span>")

        if findings_for_brackets:
            findings_str = " | ".join(findings_for_brackets)

            if len(findings_str) > 100:
                html_output.append(
                    f" <span class='finding' style='word-break: break-word; "
                    f"display: inline-block; max-width: 800px;'>"
                    f"[{findings_str}]</span>"
                )
            else:
                html_output.append(f" <span class='finding'>[{findings_str}]</span>")

        if vulnerabilities_found:
            vuln_html_list = []
            for vuln in sorted(vulnerabilities_found):
                css_class = VulnerabilityCategories.VULN_CSS_CLASSES.get(vuln, "medium")
                vuln_html_list.append(f"<span class='{css_class}'>{vuln}</span>")

            html_output.append(
                f" <span class='arrow'>→</span> {' | '.join(vuln_html_list)}"
            )

        html_output.append("</div>")

    def toggle_vuln_view(self):
        """Toggle vulnerability view mode"""
        self.render_vulnerabilities()

    def filter_vuln_display(self):
        """Filter vulnerability display"""
        self.render_vulnerabilities()

    def copy_vulnerabilities_to_clipboard(self):
        """Copy all vulnerabilities to clipboard as text"""
        if not self.current_vuln_params:
            return

        text_output = []
        text_output.append("=" * 80)
        text_output.append("VULNERABILITY FINDINGS")
        text_output.append("=" * 80)
        text_output.append("")

        for param_name, detections in self.current_vuln_params.items():
            det_list = (
                detections if isinstance(detections, (list, set)) else [detections]
            )
            text_output.append(f"{param_name}:")
            for det in det_list:
                text_output.append(f"  - {det}")
            text_output.append("")

        clipboard = QApplication.clipboard()
        clipboard.setText("\n".join(text_output))

        self.status_label.setText("Vulnerabilities copied to clipboard!")
        QTimer.singleShot(2000, lambda: self._safe_status("Ready"))

    def show_vuln_context_menu(self, position):
        """Show context menu for vulnerability text"""
        cursor = self.vuln_text.cursorForPosition(position)

        cursor.select(QTextCursor.WordUnderCursor)
        selected_text = cursor.selectedText().strip()

        if len(selected_text) < 2:
            cursor = self.vuln_text.textCursor()
            selected_text = cursor.selectedText().strip()

        if not selected_text or len(selected_text) < 2:
            return

        param_name = selected_text.strip("[]():,|→ \n\r")

        menu = QMenu()
        menu.setStyleSheet(
            f"""
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
            }}
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
        """
        )

        show_in_request_action = menu.addAction(f"🔍 Show '{param_name}' in Request")
        show_in_response_action = menu.addAction(f"🔍 Show '{param_name}' in Response")
        menu.addSeparator()
        show_in_both_action = menu.addAction(f"🔍 Show '{param_name}' in Both")

        action = menu.exec_(self.vuln_text.mapToGlobal(position))

        if action == show_in_request_action:
            self.highlight_in_request(param_name)
        elif action == show_in_response_action:
            self.highlight_in_response(param_name)
        elif action == show_in_both_action:
            self.highlight_in_request(param_name)
            QTimer.singleShot(100, lambda: self.highlight_in_response(param_name))

    def highlight_in_request(self, param_name: str):
        """Highlight parameter in Request tab"""
        if not self.current_request_raw:
            self.status_label.setText(f"❌ No request loaded")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))
            return

        self.rr_tabs.setCurrentWidget(self.rr_tabs.widget(0))

        search_patterns = [
            f"{param_name}=",
            f"{param_name}:",
            f'"{param_name}"',
            f"'{param_name}'",
            f"&{param_name}",
            param_name,
        ]

        content_lower = self.current_request_raw.lower()
        param_lower = param_name.lower()

        found_pattern = None
        for pattern in search_patterns:
            if pattern.lower() in content_lower:
                found_pattern = pattern
                break

        if not found_pattern:
            found_pattern = param_name

        self.request_search_box.setText(found_pattern)
        self.search_in_request()

        if self.request_total_matches > 0:
            self.find_in_text(self.request_text, found_pattern)
            self.status_label.setText(
                f"✅ Found '{param_name}' in Request ({self.request_total_matches} matches)"
            )
        else:
            self.status_label.setText(f"⚠️ '{param_name}' not found in Request")

        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def highlight_in_response(self, param_name: str):
        """Highlight parameter in Response tab"""
        if not self.current_response_raw:
            self.status_label.setText(f"❌ No response loaded")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))
            return

        self.rr_tabs.setCurrentWidget(self.rr_tabs.widget(1))

        search_patterns = [
            f"var {param_name}",
            f"let {param_name}",
            f"const {param_name}",
            f"{param_name}:",
            f'"{param_name}"',
            f"'{param_name}'",
            f"{param_name}=",
            f"name='{param_name}'",
            f'name="{param_name}"',
            f"id='{param_name}'",
            f'id="{param_name}"',
            f"${param_name}",
            f"window.{param_name}",
            f"document.{param_name}",
            param_name,
        ]

        content_lower = self.current_response_raw.lower()
        param_lower = param_name.lower()

        found_pattern = None
        for pattern in search_patterns:
            if pattern.lower() in content_lower:
                found_pattern = pattern
                break

        if not found_pattern:
            found_pattern = param_name

        self.response_search_box.setText(found_pattern)
        self.search_in_response()

        if self.response_total_matches > 0:
            self.find_in_text(self.response_text, found_pattern)
            self.status_label.setText(
                f"✅ Found '{param_name}' in Response ({self.response_total_matches} matches)"
            )
        else:
            self.status_label.setText(f"⚠️ '{param_name}' not found in Response")

        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    # ========================================================================
    # SEARCH FUNCTIONALITY
    # ========================================================================

    def search_in_request(self):
        """Handle search in request text"""
        search_text = self.request_search_box.text()
        if not search_text:
            self.request_match_label.setText("0 matches")
            self.request_current_match = 0
            self.request_total_matches = 0
            SearchHighlighter.clear_highlights(self.request_text)
            return

        content = self.request_text.toPlainText()
        count = content.lower().count(search_text.lower())
        self.request_total_matches = count
        self.request_current_match = 0

        if count > 0:
            self.request_match_label.setText(f"0/{count} matches")
            SearchHighlighter.highlight_all_matches(self.request_text, search_text)
        else:
            self.request_match_label.setText("0 matches")
            SearchHighlighter.clear_highlights(self.request_text)

    def search_in_response(self):
        """Handle search in response text"""
        search_text = self.response_search_box.text()
        if not search_text:
            self.response_match_label.setText("0 matches")
            self.response_current_match = 0
            self.response_total_matches = 0
            SearchHighlighter.clear_highlights(self.response_text)
            return

        content = self.response_text.toPlainText()
        count = content.lower().count(search_text.lower())
        self.response_total_matches = count
        self.response_current_match = 0

        if count > 0:
            self.response_match_label.setText(f"0/{count} matches")
            SearchHighlighter.highlight_all_matches(self.response_text, search_text)
        else:
            self.response_match_label.setText("0 matches")
            SearchHighlighter.clear_highlights(self.response_text)

    def find_in_text(
        self, text_edit: QTextEdit, search_text: str, backward: bool = False
    ):
        """
        Find and highlight text in a QTextEdit widget

        Args:
            text_edit: The QTextEdit widget to search in
            search_text: Text to search for
            backward: If True, search backward
        """
        if not search_text:
            return

        is_request = text_edit == self.request_text
        is_response = text_edit == self.response_text

        flags = QTextDocument.FindFlags()
        if backward:
            flags |= QTextDocument.FindBackward

        cursor = text_edit.textCursor()

        if not cursor.hasSelection() or (cursor.atEnd() and not backward):
            if not backward:
                cursor.movePosition(QTextCursor.Start)
            else:
                cursor.movePosition(QTextCursor.End)
            text_edit.setTextCursor(cursor)

        found = text_edit.find(search_text, flags)

        if not found:
            if not backward:
                cursor.movePosition(QTextCursor.Start)
            else:
                cursor.movePosition(QTextCursor.End)
            text_edit.setTextCursor(cursor)
            found = text_edit.find(search_text, flags)

        if found:
            cursor = text_edit.textCursor()
            current_pos = cursor.selectionStart()
            content = text_edit.toPlainText().lower()
            search_lower = search_text.lower()

            position = 0
            index = 0
            while index < current_pos:
                index = content.find(search_lower, index)
                if index == -1 or index >= current_pos:
                    break
                position += 1
                index += len(search_lower)

            if is_request:
                self.request_current_match = position + 1
                if self.request_total_matches > 0:
                    self.request_match_label.setText(
                        f"{self.request_current_match}/{self.request_total_matches} matches"
                    )
            elif is_response:
                self.response_current_match = position + 1
                if self.response_total_matches > 0:
                    self.response_match_label.setText(
                        f"{self.response_current_match}/{self.response_total_matches} matches"
                    )

    def toggle_request_view(self):
        """Display request in Raw view"""
        if not self.current_request_raw:
            return
        self.request_text.setPlainText(self.current_request_raw)

    def toggle_response_view(self):
        """Display response in Raw view"""
        if not self.current_response_raw:
            return
        self.response_text.setPlainText(self.current_response_raw)

    # ========================================================================
    # MENU ACTIONS
    # ========================================================================

    def refresh_data(self):
        """Refresh all data and views"""
        self.status_label.setText("🔄 Refreshing all views...")
        QApplication.processEvents()

        try:
            self.history_table.setRowCount(0)

            # ── Suppress per-row sitemap scheduling during bulk reload ──────────
            # Without this, the debounce timer fires mid-load and builds a
            # partial sitemap from only the rows added so far.
            self._bulk_loading = True
            # Also cancel any pending debounce and unlock sitemap selection so
            # the rebuild at the end shows ALL hosts, not just the previously
            # selected one.
            if hasattr(self, '_sitemap_rebuild_timer'):
                self._sitemap_rebuild_timer.stop()
            self._sitemap_locked = False
            self._sitemap_selected_host = ""
            self._sitemap_pending_rebuild = False

            for i, finding in enumerate(self.findings):
                self.add_history_row(finding, i)

            self._bulk_loading = False

            self.update_issue_filter_dropdown()
            
            # Apply filters first (hides rows based on search/scope/etc)
            self.apply_filters()
            
            # Cancel any debounce scheduled by apply_filters
            if hasattr(self, '_sitemap_rebuild_timer'):
                self._sitemap_rebuild_timer.stop()
                
            # Rebuild sitemap from visible rows to match history view
            self.update_sitemap_tree()

            total_findings = len(self.findings)
            self.status_label.setText(f"✅ Refreshed {total_findings} findings")
            logger.info(f"Refreshed all views with {total_findings} findings")

        except Exception as e:
            self._bulk_loading = False
            logger.error(f"Error during refresh: {e}")
            self.status_label.setText(f"❌ Refresh error: {str(e)[:50]}")

        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def clear_findings(self):
        """Clear all findings"""
        reply = QMessageBox.question(
            self,
            "Clear Findings",
            "Are you sure you want to clear all findings?\n\n"
            "This will only clear the GUI, not the log files.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.findings.clear()
            self.history_table.setRowCount(0)
            self.status_label.setText("Findings cleared")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))
            logger.info("Findings cleared from GUI")

    def export_findings(self):
        """Export findings to JSON file"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Findings",
            f"hunt_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json)",
        )

        if filename:
            try:
                export_data = {
                    "exported_at": datetime.now().isoformat(),
                    "total_findings": len(self.findings),
                    "findings": list(self.findings),
                }

                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2)

                self.status_label.setText(
                    f"Exported {len(self.findings)} findings to {filename}"
                )
                QTimer.singleShot(3000, lambda: self._safe_status("Ready"))
                logger.info(f"Exported {len(self.findings)} findings to {filename}")

            except IOError as e:
                logger.error(f"Failed to export findings: {e}")
                QMessageBox.critical(
                    self, "Export Failed", f"Failed to export findings:\n{e}"
                )

    # (duplicate proxy management block removed — canonical versions are defined above)
    
    def update_proxy_status(self):
        """Update proxy status label"""
        if self.proxy_running:
            upstream_text = f" → {self.proxy_upstream}" if self.proxy_upstream else ""
            self.proxy_status_label.setText(f"🟢 Proxy: {self.proxy_port}{upstream_text}")
            self.proxy_status_label.setStyleSheet(
                f"""
                QLabel {{
                    color: {COLOR_SUCCESS};
                    padding: 0 8px;
                    border-left: 1px solid {COLOR_BORDER};
                    font-weight: 600;
                }}
            """
            )
        else:
            self.proxy_status_label.setText("🔴 Proxy: Stopped")
            self.proxy_status_label.setStyleSheet(
                f"""
                QLabel {{
                    color: {COLOR_TEXT_MUTED};
                    padding: 0 8px;
                    border-left: 1px solid {COLOR_BORDER};
                    font-weight: 600;
                }}
            """
            )
    
    def show_proxy_config(self):
        """Show proxy configuration dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Proxy Configuration")
        dialog.setMinimumWidth(500)
        
        layout = QVBoxLayout(dialog)
        layout.setSpacing(15)
        
        # Port setting
        port_layout = QHBoxLayout()
        port_label = QLabel("Listen Port:")
        port_label.setMinimumWidth(120)
        port_layout.addWidget(port_label)
        
        port_spin = QSpinBox()
        port_spin.setRange(1024, 65535)
        port_spin.setValue(self.proxy_port)
        port_layout.addWidget(port_spin)
        layout.addLayout(port_layout)
        
        # Upstream proxy checkbox
        upstream_checkbox = QCheckBox("Enable Upstream Proxy")
        upstream_checkbox.setChecked(bool(self.proxy_upstream))
        layout.addWidget(upstream_checkbox)
        
        # Upstream proxy setting
        upstream_layout = QHBoxLayout()
        upstream_label = QLabel("Upstream Proxy:")
        upstream_label.setMinimumWidth(120)
        upstream_layout.addWidget(upstream_label)
        
        upstream_edit = QLineEdit()
        upstream_edit.setPlaceholderText("127.0.0.1:8080")
        upstream_edit.setText(self.proxy_upstream if self.proxy_upstream else "127.0.0.1:8080")
        upstream_edit.setEnabled(upstream_checkbox.isChecked())
        upstream_layout.addWidget(upstream_edit)
        layout.addLayout(upstream_layout)
        
        upstream_checkbox.toggled.connect(upstream_edit.setEnabled)
        
        # Script file setting
        script_layout = QHBoxLayout()
        script_label = QLabel("Script File:")
        script_label.setMinimumWidth(120)
        script_layout.addWidget(script_label)
        
        script_edit = QLineEdit()
        script_edit.setText(self.proxy_script_file)
        script_layout.addWidget(script_edit)
        
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(lambda: self.browse_script_file(script_edit))
        script_layout.addWidget(browse_btn)
        layout.addLayout(script_layout)
        
        # Info label
        info_label = QLabel(
            "• Proxy will auto-restart to make changes will take effect.\n\n"
            "• Upstream proxy is typically Burp Suite (127.0.0.1:8080)\n"
            "• The script file should be the mitmproxy addon script (e.g., hunt_script.py)"
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; padding: 10px; background-color: {COLOR_ELEVATED_BG}; border-radius: 4px;")
        layout.addWidget(info_label)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        save_btn = QPushButton("Save")
        save_btn.setDefault(True)
        save_btn.clicked.connect(lambda: self.save_proxy_config(
            dialog, 
            port_spin.value(), 
            upstream_edit.text() if upstream_checkbox.isChecked() else "",
            script_edit.text()
        ))
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec_()
    
    def browse_script_file(self, edit_widget):
        """Browse for proxy script file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Proxy Script",
            os.path.dirname(self.proxy_script_file),
            "Python Files (*.py);;All Files (*)"
        )
        if file_path:
            edit_widget.setText(file_path)
    
    def save_proxy_config(self, dialog, port, upstream, script_file):
        """Save proxy configuration"""
        if port < 1024 or port > 65535:
            QMessageBox.warning(self, "Invalid Port", "Port must be between 1024 and 65535")
            return
        
        if not os.path.exists(script_file):
            reply = QMessageBox.question(
                self,
                "Script Not Found",
                f"Script file does not exist:\n{script_file}\n\nSave anyway?",
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                return
        
        self.proxy_port = port
        self.proxy_upstream = upstream.strip()
        self.proxy_script_file = script_file
        
        if self.proxy_running:
            self.status_label.setText("🔄 Restarting proxy with new configuration...")
            QTimer.singleShot(100, self._restart_proxy_after_config)
        else:
            self.status_label.setText("✅ Proxy configuration saved")
            QTimer.singleShot(3000, lambda: self._safe_status("Ready"))
        
        dialog.accept()

    def _restart_proxy_after_config(self):
        """Helper method to restart proxy after configuration change"""
        self._force_stop_proxy()
        QTimer.singleShot(1000, self._start_proxy_after_stop)

    def _start_proxy_after_stop(self):
        """Helper method to start proxy after stopping"""
        self.start_proxy()
        self.status_label.setText("✅ Proxy restarted with new configuration")
        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))
    
    def show_proxy_log(self):
        """Show proxy log/status dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Proxy Status")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout(dialog)
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        
        status_info = []
        status_info.append("=" * 60)
        status_info.append("PROXY STATUS")
        status_info.append("=" * 60)
        status_info.append("")
        status_info.append(f"Status: {'🟢 Running' if self.proxy_running else '🔴 Stopped'}")
        status_info.append(f"Port: {self.proxy_port}")
        status_info.append(f"Upstream: {self.proxy_upstream if self.proxy_upstream else 'None'}")
        status_info.append(f"Script: {self.proxy_script_file}")
        
        if self.proxy_running and self.proxy_process:
            status_info.append(f"PID: {self.proxy_process.pid}")
        
        status_info.append("")
        status_info.append("=" * 60)
        status_info.append("CONFIGURATION")
        status_info.append("=" * 60)
        status_info.append("")
        status_info.append("To use this proxy, configure your browser or application:")
        status_info.append(f"  HTTP Proxy: localhost:{self.proxy_port}")
        status_info.append(f"  HTTPS Proxy: localhost:{self.proxy_port}")
        status_info.append("")
        status_info.append("For HTTPS traffic, you'll need to install mitmproxy's CA certificate.")
        status_info.append("See: https://docs.mitmproxy.org/stable/concepts-certificates/")
        
        info_text.setPlainText("\n".join(status_info))
        layout.addWidget(info_text)
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.exec_()

    def show_proxy_certificate(self):
        """Show proxy certificate installation instructions"""
        dialog = QDialog(self)
        dialog.setWindowTitle("mitmproxy CA Certificate")
        dialog.setMinimumSize(700, 500)
        
        layout = QVBoxLayout(dialog)
        
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        
        cert_info = []
        cert_info.append("=" * 70)
        cert_info.append("MITMPROXY CA CERTIFICATE INSTALLATION")
        cert_info.append("=" * 70)
        cert_info.append("")
        cert_info.append("To intercept HTTPS traffic, you need to install mitmproxy's")
        cert_info.append("CA certificate in your browser or operating system.")
        cert_info.append("")
        cert_info.append("=" * 70)
        cert_info.append("INSTALLATION STEPS")
        cert_info.append("=" * 70)
        cert_info.append("")
        cert_info.append("1. Start the proxy (if not already running)")
        cert_info.append(f"   Status: {'🟢 Running' if self.proxy_running else '🔴 Stopped'}")
        cert_info.append("")
        cert_info.append("2. Configure your browser to use the proxy")
        cert_info.append(f"   HTTP/HTTPS Proxy: localhost:{self.proxy_port}")
        cert_info.append("")
        cert_info.append("3. Visit this URL in your browser:")
        cert_info.append("   http://mitm.it")
        cert_info.append("")
        cert_info.append("4. Click on your platform to download the certificate:")
        cert_info.append("   • Windows")
        cert_info.append("   • macOS")
        cert_info.append("   • Linux")
        cert_info.append("   • iOS")
        cert_info.append("   • Android")
        cert_info.append("")
        cert_info.append("5. Install the downloaded certificate")
        cert_info.append("")
        cert_info.append("=" * 70)
        cert_info.append("PLATFORM-SPECIFIC INSTRUCTIONS")
        cert_info.append("=" * 70)
        cert_info.append("")
        cert_info.append("Windows:")
        cert_info.append("  • Double-click mitmproxy-ca-cert.p12")
        cert_info.append("  • Import to 'Trusted Root Certification Authorities'")
        cert_info.append("  • No password required")
        cert_info.append("")
        cert_info.append("macOS:")
        cert_info.append("  • Double-click mitmproxy-ca-cert.pem")
        cert_info.append("  • Add to Keychain")
        cert_info.append("  • Open Keychain Access → Find mitmproxy → Trust → Always Trust")
        cert_info.append("")
        cert_info.append("Linux (Debian/Ubuntu):")
        cert_info.append("  sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt")
        cert_info.append("  sudo update-ca-certificates")
        cert_info.append("")
        cert_info.append("Firefox (all platforms):")
        cert_info.append("  • Settings → Privacy & Security → Certificates → View Certificates")
        cert_info.append("  • Authorities tab → Import → Select mitmproxy-ca-cert.pem")
        cert_info.append("  • Check 'Trust this CA to identify websites'")
        cert_info.append("")
        cert_info.append("=" * 70)
        cert_info.append("VERIFICATION")
        cert_info.append("=" * 70)
        cert_info.append("")
        cert_info.append("After installation:")
        cert_info.append("  1. Restart your browser")
        cert_info.append("  2. Visit any HTTPS website")
        cert_info.append("  3. Check if you see traffic in Hunt GUI")
        cert_info.append("  4. No certificate warnings = SUCCESS! ✅")
        cert_info.append("")
        cert_info.append("=" * 70)
        cert_info.append("TROUBLESHOOTING")
        cert_info.append("=" * 70)
        cert_info.append("")
        cert_info.append("If HTTPS sites show certificate errors:")
        cert_info.append("  • Make sure proxy is running")
        cert_info.append("  • Verify certificate is installed in correct location")
        cert_info.append("  • Try restarting browser")
        cert_info.append("  • Check browser trust settings for the certificate")
        cert_info.append("")
        cert_info.append("More info: https://docs.mitmproxy.org/stable/concepts-certificates/")
        
        info_text.setPlainText("\n".join(cert_info))
        layout.addWidget(info_text)
        
        button_layout = QHBoxLayout()
        
        open_mitm_btn = QPushButton("🌐 Open http://mitm.it")
        open_mitm_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("http://mitm.it")))
        button_layout.addWidget(open_mitm_btn)
        
        button_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec_()

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Hunt",
            "Hunt - Security Testing Dashboard From HackRecon\n\n"
            "GUI for real-time vulnerability detection.\n\n"
            f"Monitoring: {HUNT_JSONL}\n\n"
        )

    def update_status_bar(self):
        """Update status bar periodically"""
        if not self._qt_widgets_alive():
            return
        try:
            if hasattr(self, 'findings') and hasattr(self, 'requests_label'):
                self.requests_label.setText(
                    f"Requests: {len(self.findings)}"
                )
            if hasattr(self, 'attack_surface_tab') and hasattr(self, 'attack_surface_label'):
                self.attack_surface_label.setText(
                    f"Attack Surface: {len(self.attack_surface_tab._entries)}"
                )
            if hasattr(self, 'report_tab') and hasattr(self, 'bugs_reported_label'):
                self.bugs_reported_label.setText(
                    f"Bugs Reported: {len(self.report_tab._reports)}"
                )
        except RuntimeError:
            pass

    # ========================================================================
    # EVENT HANDLERS
    # ========================================================================

    def keyPressEvent(self, event):
        """Handle keyboard shortcuts"""
        if (event.key() == Qt.Key_S and 
            event.modifiers() == (Qt.ControlModifier | Qt.ShiftModifier)):
            
            if hasattr(self, 'history_table'):
                selected_rows = self.history_table.selectionModel().selectedRows()
                if selected_rows:
                    row = selected_rows[0].row()
                    item = self.history_table.item(row, 0)
                    if item:
                        finding_index = item.data(Qt.UserRole)
                        if finding_index is not None and hasattr(self, 'send_to_scanner'):
                            self.send_to_scanner(finding_index)
                            return
                        else:
                            print(f"Invalid finding index: {finding_index}")
                            return
            
            print("No finding selected. Please select a finding first in the HTTP History table.")
            QMessageBox.warning(
                self,
                "No Selection",
                "Please select a request in the HTTP History table first."
            )
            return
        
        super().keyPressEvent(event)

    def prepare_comparison_from_selection(self, finding_index: int):
        """Prepare to add selected request to comparer"""
        if finding_index >= len(self.findings):
            return
        
        finding = self.findings[finding_index]
        
        if not hasattr(self, '_comparer_first_selection'):
            self._comparer_first_selection = finding_index
            self.status_label.setText(
                "✓ First request selected. Select another request and use 'Send to Comparer' again."
            )
            self.flash_tab("Comparer")
            QTimer.singleShot(4000, lambda: self._safe_status("Ready"))
        else:
            first_index = self._comparer_first_selection
            second_index = finding_index
            
            finding1 = self.findings[first_index]
            finding2 = self.findings[second_index]
            
            from PyQt5.QtWidgets import QInputDialog
            items = ["Requests", "Responses"]
            item, ok = QInputDialog.getItem(
                self, "Compare Type", 
                "What do you want to compare?", 
                items, 0, False
            )
            
            if ok and item:
                if item == "Requests":
                    text1 = self._load_request_text(finding1)
                    text2 = self._load_request_text(finding2)
                else:
                    text1 = self._load_response_text(finding1)
                    text2 = self._load_response_text(finding2)
                
                name = f"{item}: {finding1.get('url', 'Unknown')[:40]} vs {finding2.get('url', 'Unknown')[:40]}"
                
                self.add_comparison(name, text1, text2, item)
                
                del self._comparer_first_selection
                
                self.status_label.setText("✅ Comparison created!")
                QTimer.singleShot(2000, lambda: self._safe_status("Ready"))

    # ── Tab pop-out ───────────────────────────────────────────────────

    def popout_tab(self, index: int):
        """
        Detach the tab at `index` into a floating window.
        Closing that window re-docks the tab at its original position.
        """
        if index < 0 or index >= self.tab_widget.count():
            return

        widget    = self.tab_widget.widget(index)
        label     = self.tab_widget.tabText(index)
        clean_lbl = label.replace("⨁ ", "")

        if widget is None:
            return

        # If already popped out, raise the existing window
        if id(widget) in self._popped_tabs:
            win = self._popped_tabs[id(widget)]
            win.raise_()
            win.activateWindow()
            return

        self.tab_widget.removeTab(index)

        win = TabPopoutWindow(
            widget      = widget,
            tab_index   = index,
            tab_label   = clean_lbl,
            main_window = self,
        )
        self._popped_tabs[id(widget)] = win
        win.show()
        win.raise_()

        self.status_label.setText(
            f"🔲  '{clean_lbl}' popped out — close its window to re-dock"
        )
        QTimer.singleShot(3000, lambda: self._safe_status("Ready"))

    def flash_tab(self, tab_name_fragment: str):
        """Highlight a tab to indicate activity until opened.
        For the 4 tool sub-tabs (Param Miner, JS Miner, Bypass, Key Tester /
        API Key) flash the parent Tools tab and pre-select the sub-tab.
        """
        _tools_fragments = {"Param Miner", "JS Miner", "Bypass",
                            "Key Tester", "API Key", "API Keys"}
        if tab_name_fragment in _tools_fragments:
            # Pre-select sub-tab so it is ready when the user clicks Tools
            if hasattr(self, "_tools_subtab_map") and hasattr(self, "tools_sub_tabs"):
                idx = self._tools_subtab_map.get(tab_name_fragment, -1)
                if idx >= 0:
                    self.tools_sub_tabs.setCurrentIndex(idx)
            tab_name_fragment = "Tools"

        for i in range(self.tab_widget.count()):
            original_text = self.tab_widget.tabText(i)
            if tab_name_fragment in original_text and "⨁" not in original_text:
                self.tab_widget.setTabText(i, f"⨁ {original_text}")
                self.tab_widget.tabBar().setTabTextColor(i, QColor(COLOR_ACCENT))
                break

    def _on_tab_changed(self, index: int):
        """Clear highlight when tab is selected."""
        if index < 0: return
        text = self.tab_widget.tabText(index)
        if "⨁" in text:
            clean_text = text.replace("⨁ ", "")
            self.tab_widget.setTabText(index, clean_text)
            self.tab_widget.tabBar().setTabTextColor(index, QColor())

    def send_to_repeater(self, finding_index: int, switch_tab: bool = True):
        if finding_index >= len(self.findings): return
        finding = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if req_text:
            self.repeater_tab.add_request(req_text, finding.get("host", ""), finding.get("port", 0), finding.get("scheme", "https") == "https")
            if switch_tab:
                self.tab_widget.setCurrentWidget(self.repeater_tab)
            else:
                self.flash_tab("Repeater")
            self.status_label.setText("✓ Sent to Repeater")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))

    def send_to_intruder(self, finding_index: int, switch_tab: bool = True):
        if finding_index >= len(self.findings): return
        finding = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if req_text:
            self.intruder_tab.load_request(req_text, finding.get("host", ""), finding.get("port", 0), finding.get("scheme", "https") == "https")
            if switch_tab:
                self.tab_widget.setCurrentWidget(self.intruder_tab)
            else:
                self.flash_tab("Intruder")
            self.status_label.setText("✓ Sent to Intruder")
            QTimer.singleShot(2000, lambda: self._safe_status("Ready"))

    def send_to_waf_bypass(self, finding_index: int, switch_tab: bool = True):
        """Send a full raw HTTP request to the Bypass tab inside Tools."""
        if finding_index >= len(self.findings):
            return
        finding  = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if not req_text:
            return
        tab = getattr(self, "bypass_tab", None) or getattr(self, "waf_bypass_tab", None)
        if tab is None:
            QMessageBox.warning(self, "Bypass Tab Not Available",
                                "Bypass tab is not loaded.")
            return
        tab.load_request(
            req_text,
            host     = finding.get("host", ""),
            port     = finding.get("port", 443),
            is_https = finding.get("scheme", "https") == "https",
        )
        if switch_tab:
            self._switch_to_tools_subtab("Bypass")
        else:
            self.flash_tab("Bypass")
        self.status_label.setText("✓ Sent to Bypass")
        QTimer.singleShot(2000, lambda: self._safe_status("Ready"))

    # (apply_dark_theme, create_menu_bar, create_status_bar etc. are identical
    #  to the original — copy them verbatim from the original file here)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def _make_loading_splash() -> QSplashScreen:
    """Build a dark-themed splash screen shown while the main window loads."""
    W, H = 520, 220
    pix = QPixmap(W, H)
    pix.fill(QColor("#1e1e2e"))

    p = QPainter(pix)
    try:
        p.setPen(QPen(QColor("#89b4fa"), 2))
        p.drawRect(1, 1, W - 2, H - 2)

        f_title = QFont("Segoe UI", 22, QFont.Bold)
        p.setFont(f_title)
        p.setPen(QColor("#89b4fa"))
        p.drawText(QRect(0, 24, W, 50), Qt.AlignHCenter | Qt.AlignVCenter, "HackRecon Hunt")

        f_sub = QFont("Segoe UI", 11)
        p.setFont(f_sub)
        p.setPen(QColor("#cdd6f4"))
        p.drawText(QRect(0, 80, W, 36), Qt.AlignHCenter | Qt.AlignVCenter,
                   "Initialising, please wait…")

    finally:
        p.end()

    splash = QSplashScreen(pix, Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    # Style the dynamic showMessage text to match the dark palette
    splash.setStyleSheet("color: #6c7086; font-family: 'Segoe UI'; font-size: 9pt;")
    return splash


def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Apply a dark palette at the QApplication level so every widget starts
    # with a dark background from the very first paint — prevents the white
    # frame flash that occurs before apply_dark_theme() sets the stylesheet.
    _dark_pal = QPalette()
    _dark_pal.setColor(QPalette.Window,          QColor("#2B2B2B"))
    _dark_pal.setColor(QPalette.WindowText,      QColor("#BBBBBB"))
    _dark_pal.setColor(QPalette.Base,            QColor("#1E1E1E"))
    _dark_pal.setColor(QPalette.AlternateBase,   QColor("#252525"))
    _dark_pal.setColor(QPalette.ToolTipBase,     QColor("#2B2B2B"))
    _dark_pal.setColor(QPalette.ToolTipText,     QColor("#BBBBBB"))
    _dark_pal.setColor(QPalette.Text,            QColor("#BBBBBB"))
    _dark_pal.setColor(QPalette.BrightText,      QColor("#FFFFFF"))
    _dark_pal.setColor(QPalette.Button,          QColor("#2D2D2D"))
    _dark_pal.setColor(QPalette.ButtonText,      QColor("#BBBBBB"))
    _dark_pal.setColor(QPalette.Link,            QColor("#6A8759"))
    _dark_pal.setColor(QPalette.Highlight,       QColor("#6A8759"))
    _dark_pal.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
    _dark_pal.setColor(QPalette.Dark,            QColor("#1A1A1A"))
    _dark_pal.setColor(QPalette.Mid,             QColor("#323232"))
    _dark_pal.setColor(QPalette.Shadow,          QColor("#141414"))
    app.setPalette(_dark_pal)

    # If we were relaunched by _switch_project or _delete_current_project,
    # a project slug may already be set in the environment — skip the dialog.
    env_slug = os.environ.get("HACKR_PROJECT_SLUG", "").strip()

    if env_slug:
        if pm.get_program(env_slug):
            slug = env_slug
        else:
            env_slug = ""

    if not env_slug:
        launch_dlg = LaunchDialog()
        if launch_dlg.exec_() != QDialog.Accepted:
            sys.exit(0)
        result = launch_dlg.get_result()
        slug = result.get("slug", "") if result else ""

    # ── Show splash immediately after the dialog closes ───────────────────
    splash = _make_loading_splash()
    splash.show()
    app.processEvents()
    # Center after processEvents() so the pixmap size is fully resolved.
    # Use availableGeometry() + screen x/y offset for multi-monitor safety.
    _sg = QApplication.primaryScreen().availableGeometry()
    splash.move(
        _sg.x() + (_sg.width()  - splash.width())  // 2,
        _sg.y() + (_sg.height() - splash.height()) // 2,
    )
    splash.showMessage("  Checking for orphaned proxy processes…",
                       Qt.AlignBottom | Qt.AlignLeft, QColor("#6c7086"))
    app.processEvents()

    # ── Kill orphaned mitmdump in a background thread so the splash stays
    #    responsive.  We pump processEvents() in a short loop while waiting.
    _kill_done = threading.Event()

    def _bg_kill():
        try:
            _kill_orphaned_mitmdump()
        finally:
            _kill_done.set()

    threading.Thread(target=_bg_kill, daemon=True).start()

    # Pump Qt events every 50 ms while the background kill is in progress.
    # This keeps the splash painted and the OS from marking the app as
    # "not responding".
    while not _kill_done.wait(timeout=0.05):
        app.processEvents()

    # ── Ensure project dirs, build the main window ────────────────────────
    if slug:
        pm.ensure_project_dirs(slug)

    # Update the splash — show both lines so the user sees the progression
    splash.showMessage(
        "  Checking for orphaned proxy processes…\n  Building interface…",
        Qt.AlignBottom | Qt.AlignLeft, QColor("#6c7086")
    )
    app.processEvents()

    window = HuntBurpGUI(project_slug=slug)

    # Make the window fully painted before dismissing the splash
    window.show()
    app.processEvents()
    splash.finish(window)

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()