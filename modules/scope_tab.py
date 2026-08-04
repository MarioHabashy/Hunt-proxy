#!/usr/bin/env python3
"""
scope_tab.py - Target Scope management tab

Features:
  • Include / Exclude scope rules table  (protocol · host · all subdomains · port · comment)
  • Each rule has: Enabled checkbox, Type (Include/Exclude), Protocol, Host, ☑ All Subdomains, Port, Comment
  • Add domain or subdomain via one combined input with "Include all subdomains" checkbox
  • Domain / Subdomain lists auto-updated from scope rules
  • "Set as Target" button to focus scope for proxy / dashboard
  • Proxy auto-restart on any scope change
  • Signals so HuntGUI can react when scope changes
"""

import os
import webbrowser
from functools import partial
from typing import List, Optional, Dict, Any

from PyQt5.QtWidgets import (
    QCheckBox, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QLineEdit, QListWidget, QListWidgetItem, QGroupBox,
    QSplitter, QTextEdit, QDialog, QDialogButtonBox, QFormLayout,
    QMessageBox, QTabWidget, QFrame, QMenu, QAction, QInputDialog,
    QSizePolicy, QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QToolButton, QStyledItemDelegate,
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QIcon, QBrush

from . import project_manager as pm

try:
    from modules.constants import (
        COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_ELEVATED_BG,
        COLOR_LIGHTER_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED,
        COLOR_BORDER, COLOR_BORDER_BRIGHT, COLOR_ACCENT, COLOR_SUCCESS,
        COLOR_MEDIUM, COLOR_HIGH, COLOR_CRITICAL, COLOR_LOW,
        COLOR_HOVER, FONT_FAMILY, FONT_FAMILY_MONO,
        FONT_SIZE_NORMAL, FONT_SIZE_SMALL, FONT_SIZE_LARGE,
    )
except ImportError:
    COLOR_BACKGROUND = "#1e1e2e"
    COLOR_DARK_BG = "#181825"
    COLOR_CARD_BG = "#24273a"
    COLOR_ELEVATED_BG = "#2a2d3e"
    COLOR_LIGHTER_BG = "#313244"
    COLOR_TEXT = "#cdd6f4"
    COLOR_TEXT_BRIGHT = "#ffffff"
    COLOR_TEXT_MUTED = "#6c7086"
    COLOR_BORDER = "#45475a"
    COLOR_BORDER_BRIGHT = "#585b70"
    COLOR_ACCENT = "#89b4fa"
    COLOR_SUCCESS = "#a6e3a1"
    COLOR_MEDIUM = "#fab387"
    COLOR_HIGH = "#fe640b"
    COLOR_CRITICAL = "#f38ba8"
    COLOR_LOW = "#89dceb"
    COLOR_HOVER = "#313244"
    FONT_FAMILY = "Segoe UI, Arial, sans-serif"
    FONT_FAMILY_MONO = "Consolas, Courier New, monospace"
    FONT_SIZE_NORMAL = "12px"
    FONT_SIZE_SMALL = "11px"
    FONT_SIZE_LARGE = "14px"


# ─────────────────────────────────────────────────────────────────────────────
# Helper widgets
# ─────────────────────────────────────────────────────────────────────────────

def _btn(label: str, color: str = COLOR_ACCENT, min_w: int = 80) -> QPushButton:
    b = QPushButton(label)
    b.setMinimumWidth(min_w)
    b.setStyleSheet(
        f"""
        QPushButton {{
            background-color: {COLOR_ELEVATED_BG};
            color: {color};
            border: 1px solid {color};
            border-radius: 4px;
            padding: 5px 12px;
            font-size: {FONT_SIZE_SMALL};
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {color};
            color: #000000;
        }}
        QPushButton:disabled {{
            color: {COLOR_TEXT_MUTED};
            border-color: {COLOR_BORDER};
        }}
        """
    )
    return b


def _label(text: str, bold: bool = False, color: str = COLOR_TEXT_BRIGHT) -> QLabel:
    lb = QLabel(text)
    lb.setStyleSheet(
        f"color: {color}; font-size: {FONT_SIZE_NORMAL};"
        + (" font-weight: 600;" if bold else "")
    )
    return lb


def _list_widget() -> QListWidget:
    lw = QListWidget()
    lw.setStyleSheet(
        f"""
        QListWidget {{
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            border: 1px solid {COLOR_BORDER};
            border-radius: 4px;
            font-family: {FONT_FAMILY_MONO};
            font-size: {FONT_SIZE_SMALL};
            outline: none;
        }}
        QListWidget::item {{
            padding: 4px 8px;
        }}
        QListWidget::item:selected {{
            background-color: {COLOR_ACCENT};
            color: #000000;
        }}
        QListWidget::item:hover {{
            background-color: {COLOR_HOVER};
        }}
        """
    )
    return lw


def _input(placeholder: str = "") -> QLineEdit:
    le = QLineEdit()
    le.setPlaceholderText(placeholder)
    le.setStyleSheet(
        f"""
        QLineEdit {{
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT_BRIGHT};
            border: 1px solid {COLOR_BORDER};
            border-radius: 4px;
            padding: 5px 8px;
            font-size: {FONT_SIZE_NORMAL};
        }}
        QLineEdit:focus {{
            border-color: {COLOR_ACCENT};
        }}
        """
    )
    return le


def _combo(items: list = None) -> QComboBox:
    cb = QComboBox()
    cb.setStyleSheet(
        f"""
        QComboBox {{
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT_BRIGHT};
            border: 1px solid {COLOR_BORDER};
            border-radius: 4px;
            padding: 5px 8px;
            font-size: {FONT_SIZE_NORMAL};
            min-width: 90px;
        }}
        QComboBox:focus {{ border-color: {COLOR_ACCENT}; }}
        QComboBox::drop-down {{ border: none; width: 20px; }}
        QComboBox QAbstractItemView {{
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            border: 1px solid {COLOR_BORDER};
            selection-background-color: {COLOR_ACCENT};
            selection-color: #000;
        }}
        """
    )
    if items:
        cb.addItems(items)
    return cb


# ─────────────────────────────────────────────────────────────────────────────
# Program creation / edit dialog
# ─────────────────────────────────────────────────────────────────────────────

class ProgramDialog(QDialog):
    """Dialog to create or edit a bug-bounty program."""

    PLATFORMS = ["HackerOne", "Bugcrowd", "Intigriti", "Synack", "YesWeHack",
                 "Open Bug Bounty", "Private", "Other"]

    def __init__(self, parent=None, program_data: dict = None):
        super().__init__(parent)
        self.setWindowTitle("Program" if program_data else "New Program")
        self.setMinimumWidth(480)
        self.setStyleSheet(
            f"QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}"
            f"QLabel  {{ color: {COLOR_TEXT}; font-size: {FONT_SIZE_NORMAL}; }}"
        )
        self._build_ui(program_data or {})

    def _build_ui(self, data: dict):
        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setSpacing(10)

        self.name_edit = _input("e.g. Acme Bug Bounty")
        self.name_edit.setText(data.get("name", ""))
        form.addRow(_label("Program Name *"), self.name_edit)

        self.platform_combo = _combo([""] + self.PLATFORMS)
        idx = self.platform_combo.findText(data.get("platform", ""))
        self.platform_combo.setCurrentIndex(max(0, idx))
        form.addRow(_label("Platform"), self.platform_combo)

        self.url_edit = _input("https://hackerone.com/...")
        self.url_edit.setText(data.get("platform_url", ""))
        form.addRow(_label("Program URL"), self.url_edit)

        layout.addLayout(form)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        bb.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_ACCENT};
                border: 1px solid {COLOR_ACCENT};
                border-radius: 4px;
                padding: 5px 20px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: #000; }}
            """
        )
        layout.addWidget(bb)

    def _accept(self):
        if not self.name_edit.text().strip():
            QMessageBox.warning(self, "Validation", "Program name is required.")
            return
        self.accept()

    def get_data(self) -> dict:
        return {
            "name": self.name_edit.text().strip(),
            "platform": self.platform_combo.currentText(),
            "platform_url": self.url_edit.text().strip(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Bulk subdomain import dialog
# ─────────────────────────────────────────────────────────────────────────────

class BulkSubdomainDialog(QDialog):
    def __init__(self, domain: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Bulk Add Subdomains — {domain}")
        self.setMinimumSize(500, 400)
        self.setStyleSheet(
            f"QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}"
        )
        layout = QVBoxLayout(self)
        layout.addWidget(_label("Paste subdomains (one per line):", bold=True))

        self.text_edit = QTextEdit()
        self.text_edit.setPlaceholderText(
            "api.example.com\nstaging.example.com\ndev.example.com"
        )
        self.text_edit.setStyleSheet(
            f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                padding: 6px;
            }}
            """
        )
        layout.addWidget(self.text_edit)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        bb.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_ACCENT};
                border: 1px solid {COLOR_ACCENT};
                border-radius: 4px;
                padding: 5px 20px;
                font-weight: 600;
            }}
            QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: #000; }}
            """
        )
        layout.addWidget(bb)

    def get_subdomains(self) -> List[str]:
        lines = self.text_edit.toPlainText().splitlines()
        return [l.strip().lower() for l in lines if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Add Scope Entry dialog
# ─────────────────────────────────────────────────────────────────────────────

class AddScopeEntryDialog(QDialog):
    """
    Dialog for adding a scope entry.
    Supports: protocol, host (with optional wildcard), all-subdomains checkbox, port.
    """

    def __init__(self, parent=None, rule_type: str = "include", prefill_host: str = ""):
        super().__init__(parent)
        self.setWindowTitle(f"Add {'Include' if rule_type == 'include' else 'Exclude'} Rule")
        self.setMinimumWidth(520)
        self._rule_type = rule_type
        self.setStyleSheet(
            f"QDialog {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; "
            f"font-family: {FONT_FAMILY}; font-size: {FONT_SIZE_NORMAL}; }}"
            f"QLabel {{ color: {COLOR_TEXT}; }}"
        )
        self._build_ui(prefill_host)

    def _build_ui(self, prefill_host: str):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(20, 16, 20, 16)

        # Type indicator banner
        type_color = COLOR_SUCCESS if self._rule_type == "include" else COLOR_CRITICAL
        type_label = QLabel(f"{'✅ Include' if self._rule_type == 'include' else '🚫 Exclude'} Rule")
        type_label.setStyleSheet(
            f"background-color: {type_color}22; color: {type_color}; font-weight: bold; "
            f"padding: 8px 12px; border-radius: 4px; font-size: {FONT_SIZE_NORMAL};"
        )
        layout.addWidget(type_label)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignRight)
        form.setSpacing(10)

        # Protocol
        self.protocol_combo = _combo(["Any", "http", "https"])
        form.addRow(_label("Protocol:"), self.protocol_combo)

        # Host
        host_row = QHBoxLayout()
        self.host_edit = _input("example.com  or  *.example.com")
        self.host_edit.setText(prefill_host)
        host_row.addWidget(self.host_edit)
        form.addRow(_label("Host:"), host_row)

        # All subdomains checkbox
        self.all_sub_cb = QCheckBox("Include all subdomains  (*.host)")
        self.all_sub_cb.setChecked(True)
        self.all_sub_cb.setStyleSheet(f"color: {COLOR_TEXT}; padding: 4px 0;")
        self.host_edit.textChanged.connect(self._on_host_changed)
        form.addRow("", self.all_sub_cb)

        # Port
        self.port_edit = _input("(any)  or  443")
        self.port_edit.setMaximumWidth(120)
        form.addRow(_label("Port:"), self.port_edit)

        # Comment
        self.comment_edit = _input("Optional note…")
        form.addRow(_label("Comment:"), self.comment_edit)

        layout.addLayout(form)

        # Hint
        hint = _label(
            "Tip: Leave Host empty to match all hosts. Use *.example.com to match\n"
            "all subdomains explicitly, or check the 'Include all subdomains' box.",
            color=COLOR_TEXT_MUTED,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # Buttons
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._validate_and_accept)
        bb.rejected.connect(self.reject)
        bb.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {COLOR_ACCENT}; "
            f"border: 1px solid {COLOR_ACCENT}; border-radius: 4px; padding: 5px 20px; font-weight:600;}}"
            f"QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: #000; }}"
        )
        layout.addWidget(bb)

    def _on_host_changed(self, text: str):
        # If user typed a wildcard, uncheck "all subdomains" since it's implied
        if text.startswith("*."):
            self.all_sub_cb.setChecked(False)
            self.all_sub_cb.setEnabled(False)
        else:
            self.all_sub_cb.setEnabled(True)

    def _validate_and_accept(self):
        host = self.host_edit.text().strip().lower()
        # basic validation
        if host and not all(c.isalnum() or c in "-.*_:" for c in host):
            QMessageBox.warning(self, "Invalid Host",
                                "Host contains invalid characters.\nExample: example.com or *.example.com")
            return
        self.accept()

    def get_rule(self) -> Dict[str, Any]:
        protocol_text = self.protocol_combo.currentText().lower()
        protocol = "any" if protocol_text == "any" else protocol_text

        host = self.host_edit.text().strip().lower()
        all_sub = self.all_sub_cb.isChecked() and not host.startswith("*.")

        return {
            "enabled": True,
            "type": self._rule_type,
            "protocol": protocol,
            "host": host,
            "all_subdomains": all_sub,
            "port": self.port_edit.text().strip(),
            "comment": self.comment_edit.text().strip(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scope Rules Table Widget
# ─────────────────────────────────────────────────────────────────────────────

# Column indices
COL_ENABLED   = 0
COL_TYPE      = 1
COL_PROTOCOL  = 2
COL_HOST      = 3
COL_ALL_SUBS  = 4
COL_PORT      = 5
COL_COMMENT   = 6
NUM_COLS      = 7

COLUMN_HEADERS = ["✓", "Type", "Protocol", "Host", "All Subs", "Port", "Comment"]
COLUMN_WIDTHS  = [30, 80, 80, 250, 70, 60, 200]


class ScopeRulesTable(QTableWidget):
    """
    Scope rules table.
    Shows include (green) and exclude (red) rules.
    """
    rule_changed = pyqtSignal()

    _INCLUDE_BG = QColor("#1a3a1a")
    _EXCLUDE_BG = QColor("#3a1a1a")

    def __init__(self, parent=None):
        super().__init__(0, NUM_COLS, parent)
        self._current_slug = ""
        self._loading = False
        self._setup_ui()

    def _setup_ui(self):
        self.setHorizontalHeaderLabels(COLUMN_HEADERS)
        self.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                gridline-color: {COLOR_BORDER};
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                outline: none;
            }}
            QTableWidget::item {{ padding: 4px 6px; }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT}44;
                color: {COLOR_TEXT_BRIGHT};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_ACCENT};
                border: 1px solid {COLOR_BORDER};
                padding: 5px 8px;
                font-weight: 600;
                font-size: {FONT_SIZE_SMALL};
            }}
            """
        )
        hdr = self.horizontalHeader()
        for i, w in enumerate(COLUMN_WIDTHS):
            self.setColumnWidth(i, w)
        hdr.setSectionResizeMode(COL_HOST, QHeaderView.Stretch)
        hdr.setSectionResizeMode(COL_COMMENT, QHeaderView.Stretch)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.SelectedClicked)
        self.verticalHeader().setVisible(False)
        self.setAlternatingRowColors(False)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._context_menu)

    def load_rules(self, slug: str):
        self._current_slug = slug
        self._loading = True
        self.clearContents()
        self.setRowCount(0)

        rules = pm.load_scope_rules(slug)
        for rule in rules:
            self._append_rule_row(rule)

        self._loading = False

    def _append_rule_row(self, rule: Dict[str, Any]):
        row = self.rowCount()
        self.insertRow(row)
        self._set_row(row, rule)

    def _set_row(self, row: int, rule: Dict[str, Any]):
        rule_type = rule.get("type", "include")
        bg = self._INCLUDE_BG if rule_type == "include" else self._EXCLUDE_BG
        type_color = COLOR_SUCCESS if rule_type == "include" else COLOR_CRITICAL

        # Col 0: Enabled checkbox
        enabled_item = QTableWidgetItem()
        enabled_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        enabled_item.setCheckState(Qt.Checked if rule.get("enabled", True) else Qt.Unchecked)
        enabled_item.setBackground(QBrush(bg))
        self.setItem(row, COL_ENABLED, enabled_item)

        # Col 1: Type
        type_item = QTableWidgetItem(rule_type.upper())
        type_item.setForeground(QBrush(QColor(type_color)))
        type_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        type_item.setBackground(QBrush(bg))
        type_item.setTextAlignment(Qt.AlignCenter)
        self.setItem(row, COL_TYPE, type_item)

        def _cell(text: str, editable: bool = True):
            item = QTableWidgetItem(str(text))
            if not editable:
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            item.setBackground(QBrush(bg))
            return item

        self.setItem(row, COL_PROTOCOL, _cell(rule.get("protocol", "any"), editable=False))
        self.setItem(row, COL_HOST, _cell(rule.get("host", "")))

        # Col 4: All subdomains checkbox
        all_sub_item = QTableWidgetItem()
        all_sub_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        all_sub_item.setCheckState(Qt.Checked if rule.get("all_subdomains", False) else Qt.Unchecked)
        all_sub_item.setBackground(QBrush(bg))
        self.setItem(row, COL_ALL_SUBS, all_sub_item)

        self.setItem(row, COL_PORT, _cell(rule.get("port", "")))
        self.setItem(row, COL_COMMENT, _cell(rule.get("comment", "")))

        self.setRowHeight(row, 28)

    def _get_rule_at_row(self, row: int) -> Dict[str, Any]:
        def _text(col):
            item = self.item(row, col)
            return item.text() if item else ""

        def _checked(col):
            item = self.item(row, col)
            return item.checkState() == Qt.Checked if item else False

        return {
            "enabled": _checked(COL_ENABLED),
            "type": _text(COL_TYPE).lower(),
            "protocol": _text(COL_PROTOCOL).lower() or "any",
            "host": _text(COL_HOST).lower(),
            "all_subdomains": _checked(COL_ALL_SUBS),
            "port": _text(COL_PORT),
            "comment": _text(COL_COMMENT),
        }

    def save_current_rules(self):
        if not self._current_slug or self._loading:
            return
        rules = []
        for row in range(self.rowCount()):
            rules.append(self._get_rule_at_row(row))
        pm.save_scope_rules(self._current_slug, rules)
        self.rule_changed.emit()

    def add_rule(self, rule: Dict[str, Any]):
        self._append_rule_row(rule)
        self.save_current_rules()

    def remove_selected_rows(self):
        rows = sorted(set(idx.row() for idx in self.selectedIndexes()), reverse=True)
        for row in rows:
            self.removeRow(row)
        self.save_current_rules()

    def move_row_up(self):
        rows = sorted(set(idx.row() for idx in self.selectedIndexes()))
        if not rows or rows[0] == 0:
            return
        for row in rows:
            rule = self._get_rule_at_row(row)
            above = self._get_rule_at_row(row - 1)
            self._set_row(row - 1, rule)
            self._set_row(row, above)
        self.save_current_rules()

    def move_row_down(self):
        rows = sorted(set(idx.row() for idx in self.selectedIndexes()), reverse=True)
        if not rows or rows[-1] >= self.rowCount() - 1:
            return
        for row in rows:
            rule = self._get_rule_at_row(row)
            below = self._get_rule_at_row(row + 1)
            self._set_row(row + 1, rule)
            self._set_row(row, below)
        self.save_current_rules()

    def _context_menu(self, pos):
        row = self.rowAt(pos.y())
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; }}"
            f"QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #000; }}"
        )
        if row >= 0:
            rule = self._get_rule_at_row(row)
            toggle_text = "☑ Disable" if rule.get("enabled") else "☐ Enable"
            menu.addAction(toggle_text).triggered.connect(lambda: self._toggle_enabled(row))
            menu.addSeparator()
            menu.addAction("⬆ Move Up").triggered.connect(self.move_row_up)
            menu.addAction("⬇ Move Down").triggered.connect(self.move_row_down)
            menu.addSeparator()
            menu.addAction("✕ Remove").triggered.connect(self.remove_selected_rows)
        menu.exec_(self.viewport().mapToGlobal(pos))

    def _toggle_enabled(self, row: int):
        item = self.item(row, COL_ENABLED)
        if item:
            new_state = Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
            item.setCheckState(new_state)
        self.save_current_rules()


# ─────────────────────────────────────────────────────────────────────────────
# Main ScopeTab widget
# ─────────────────────────────────────────────────────────────────────────────

class ScopeTab(QWidget):
    """
    Scope management tab.

    Left side: Scope rules table (Include + Exclude sections)
    Right side: Domain + Subdomain lists derived from project data

    Emits `scope_changed(slug, domain, subdomain)` when the user sets a specific
    target for other tools like the Dashboard and HTTP History.
    """

    scope_changed = pyqtSignal(str, str, str)   # slug, domain, subdomain

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_slug = ""
        self._current_domain = ""
        self._current_subdomain = ""
        self._build_ui()

    def load_project(self, slug: str):
        """Called by the main window on startup."""
        self._current_slug = slug
        self._refresh_all()
        self.scope_changed.emit(self._current_slug, "", "")

    # ── UI construction ────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Active target banner ─────────────────────────────────────────────
        banner = QFrame()
        banner.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_ELEVATED_BG}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 6px; padding: 6px; }}"
        )
        banner_layout = QHBoxLayout(banner)
        banner_layout.setContentsMargins(10, 6, 10, 6)

        banner_layout.addWidget(_label("Project:", bold=True))
        self.active_program_lbl = _label("—", color=COLOR_ACCENT, bold=True)
        banner_layout.addWidget(self.active_program_lbl)

        self._scope_summary_lbl = _label("", color=COLOR_TEXT_MUTED)
        banner_layout.addWidget(self._scope_summary_lbl)

        banner_layout.addStretch()

        self.open_url_btn = _btn("🌐 Open Platform", COLOR_ACCENT)
        self.open_url_btn.clicked.connect(self._open_platform_url)
        self.open_url_btn.setVisible(False)
        banner_layout.addWidget(self.open_url_btn)

        self.set_program_target_btn = _btn("Target All", COLOR_SUCCESS)
        self.set_program_target_btn.setToolTip("Set the entire program scope as the active target")
        self.set_program_target_btn.clicked.connect(self._set_program_target)
        banner_layout.addWidget(self.set_program_target_btn)

        root.addWidget(banner)

        # ── Main horizontal splitter ─────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background-color: {COLOR_BORDER}; width: 4px; }}"
            f"QSplitter::handle:hover {{ background-color: {COLOR_ACCENT}; }}"
        )

        # Left: Scope Rules 
        splitter.addWidget(self._build_scope_rules_panel())

        # Right: Domains + Subdomains lists
        splitter.addWidget(self._build_targets_panel())

        splitter.setSizes([600, 350])
        root.addWidget(splitter, stretch=1)

    def _build_scope_rules_panel(self) -> QWidget:
        """Left panel: Include/Exclude rules table."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 4, 0)
        layout.setSpacing(8)

        # Header with quick-add input
        hdr = QWidget()
        hdr.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; border-radius: 4px; padding: 4px;"
        )
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(8, 6, 8, 6)
        hl.setSpacing(6)

        hl.addWidget(_label("Scope Rules", bold=True, color=COLOR_ACCENT))
        hl.addStretch()

        self._quick_host_input = _input("example.com  or  *.example.com")
        self._quick_host_input.setMinimumWidth(200)
        hl.addWidget(self._quick_host_input)

        self._quick_all_sub_cb = QCheckBox("All Subs")
        self._quick_all_sub_cb.setChecked(True)
        self._quick_all_sub_cb.setStyleSheet(f"color: {COLOR_TEXT}; font-size: {FONT_SIZE_SMALL};")
        hl.addWidget(self._quick_all_sub_cb)

        add_include_btn = _btn("Include", COLOR_SUCCESS, 80)
        add_include_btn.clicked.connect(self._quick_add_include)
        self._quick_host_input.returnPressed.connect(self._quick_add_include)
        hl.addWidget(add_include_btn)

        add_exclude_btn = _btn("Exclude", COLOR_CRITICAL, 80)
        add_exclude_btn.clicked.connect(self._quick_add_exclude)
        hl.addWidget(add_exclude_btn)

        layout.addWidget(hdr)

        # Rules table
        self._rules_table = ScopeRulesTable()
        self._rules_table.rule_changed.connect(self._on_scope_rules_changed)
        self._rules_table.itemChanged.connect(self._on_table_item_changed)
        layout.addWidget(self._rules_table, stretch=1)

        # Table action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        add_adv_include = _btn("＋ Add Include…", COLOR_SUCCESS, 100)
        add_adv_include.clicked.connect(lambda: self._open_add_rule_dialog("include"))
        btn_row.addWidget(add_adv_include)

        add_adv_exclude = _btn("＋ Add Exclude…", COLOR_CRITICAL, 100)
        add_adv_exclude.clicked.connect(lambda: self._open_add_rule_dialog("exclude"))
        btn_row.addWidget(add_adv_exclude)

        btn_row.addStretch()

        move_up_btn = _btn("⬆", COLOR_ACCENT, 36)
        move_up_btn.setMaximumWidth(36)
        move_up_btn.clicked.connect(self._rules_table.move_row_up)
        btn_row.addWidget(move_up_btn)

        move_down_btn = _btn("⬇", COLOR_ACCENT, 36)
        move_down_btn.setMaximumWidth(36)
        move_down_btn.clicked.connect(self._rules_table.move_row_down)
        btn_row.addWidget(move_down_btn)

        remove_btn = _btn("✕ Remove", COLOR_CRITICAL, 70)
        remove_btn.clicked.connect(self._rules_table.remove_selected_rows)
        btn_row.addWidget(remove_btn)

        layout.addLayout(btn_row)

        # Scope test widget
        test_row = QHBoxLayout()
        test_row.setSpacing(6)
        self._test_url_input = _input("Test: paste URL to check if in scope…")
        self._test_url_input.setMinimumWidth(300)
        test_row.addWidget(self._test_url_input)
        test_btn = _btn("🔍 Test", COLOR_ACCENT, 60)
        test_btn.clicked.connect(self._test_scope)
        self._test_url_input.returnPressed.connect(self._test_scope)
        test_row.addWidget(test_btn)
        self._test_result_lbl = _label("", color=COLOR_TEXT_MUTED)
        test_row.addWidget(self._test_result_lbl)
        layout.addLayout(test_row)

        return panel

    def _build_targets_panel(self) -> QWidget:
        """Right panel: Domains + Subdomains lists."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(4, 0, 0, 0)
        layout.setSpacing(8)

        # ── Domains ──────────────────────────────────────────────────────────
        dom_box = self._groupbox("Domains")
        dom_layout = QVBoxLayout(dom_box)
        dom_layout.setSpacing(6)

        dom_add_row = QHBoxLayout()
        self.domain_input = _input("example.com")
        dom_add_row.addWidget(self.domain_input)
        self._domain_all_sub_cb = QCheckBox("All Subs")
        self._domain_all_sub_cb.setChecked(True)
        self._domain_all_sub_cb.setStyleSheet(f"color: {COLOR_TEXT}; font-size: {FONT_SIZE_SMALL};")
        dom_add_row.addWidget(self._domain_all_sub_cb)
        add_dom_btn = _btn("Add", COLOR_SUCCESS, 50)
        add_dom_btn.clicked.connect(self._add_domain_from_input)
        self.domain_input.returnPressed.connect(self._add_domain_from_input)
        dom_add_row.addWidget(add_dom_btn)
        dom_layout.addLayout(dom_add_row)

        self.domain_list = _list_widget()
        self.domain_list.currentRowChanged.connect(self._on_domain_selected)
        self.domain_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.domain_list.customContextMenuRequested.connect(self._domain_context_menu)
        dom_layout.addWidget(self.domain_list, stretch=1)

        self.domain_info = _label("No program loaded", color=COLOR_TEXT_MUTED)
        dom_layout.addWidget(self.domain_info)

        dom_btn_row = QHBoxLayout()
        self.use_domain_btn = _btn("Set as Target", COLOR_SUCCESS)
        self.use_domain_btn.clicked.connect(self._set_domain_target)
        self.use_domain_btn.setEnabled(False)
        del_domain_btn = _btn("✕ Remove", COLOR_CRITICAL, 70)
        del_domain_btn.clicked.connect(self._remove_domain)
        dom_btn_row.addWidget(self.use_domain_btn)
        dom_btn_row.addWidget(del_domain_btn)
        dom_layout.addLayout(dom_btn_row)

        layout.addWidget(dom_box, stretch=1)

        # ── Subdomains ────────────────────────────────────────────────────────
        sub_box = self._groupbox("Subdomains")
        sub_layout = QVBoxLayout(sub_box)
        sub_layout.setSpacing(6)

        sub_add_row = QHBoxLayout()
        self.sub_input = _input("api.example.com")
        sub_add_row.addWidget(self.sub_input)
        add_sub_btn = _btn("Add", COLOR_SUCCESS, 50)
        add_sub_btn.clicked.connect(self._add_subdomain)
        self.sub_input.returnPressed.connect(self._add_subdomain)
        sub_add_row.addWidget(add_sub_btn)
        sub_layout.addLayout(sub_add_row)

        self.sub_list = _list_widget()
        self.sub_list.currentRowChanged.connect(self._on_subdomain_selected)
        self.sub_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.sub_list.customContextMenuRequested.connect(self._sub_context_menu)
        sub_layout.addWidget(self.sub_list, stretch=1)

        self.sub_count_lbl = _label("", color=COLOR_TEXT_MUTED)
        sub_layout.addWidget(self.sub_count_lbl)

        sub_btn_row = QHBoxLayout()
        self.use_sub_btn = _btn("Set as Target", COLOR_SUCCESS)
        self.use_sub_btn.clicked.connect(self._set_subdomain_target)
        self.use_sub_btn.setEnabled(False)

        bulk_btn = _btn("⬇ Bulk Import", COLOR_ACCENT)
        bulk_btn.clicked.connect(self._bulk_import_subdomains)

        del_sub_btn = _btn("✕ Remove", COLOR_CRITICAL, 70)
        del_sub_btn.clicked.connect(self._remove_subdomain)

        sub_btn_row.addWidget(self.use_sub_btn)
        sub_btn_row.addWidget(bulk_btn)
        sub_btn_row.addWidget(del_sub_btn)
        sub_layout.addLayout(sub_btn_row)

        layout.addWidget(sub_box, stretch=1)

        return panel

    def _groupbox(self, title: str) -> QGroupBox:
        box = QGroupBox(title)
        box.setStyleSheet(
            f"QGroupBox {{ border: 1px solid {COLOR_BORDER}; border-radius: 6px; "
            f"margin-top: 10px; padding-top: 14px; background-color: {COLOR_CARD_BG}; "
            f"font-weight: 600; font-size: {FONT_SIZE_NORMAL}; color: {COLOR_TEXT_BRIGHT}; }}"
            f"QGroupBox::title {{ subcontrol-origin: margin; left: 12px; "
            f"padding: 0 8px; color: {COLOR_ACCENT}; background-color: {COLOR_CARD_BG}; }}"
        )
        return box

    # ── Data refresh ───────────────────────────────────────────────────────

    def _refresh_all(self):
        self._refresh_scope_rules()
        self._refresh_domains()
        self._update_banner()

    def _refresh_scope_rules(self):
        if not self._current_slug:
            return
        self._rules_table.load_rules(self._current_slug)
        self._update_scope_summary()

    def _refresh_domains(self):
        self.domain_list.clear()
        self.sub_list.clear()
        self.sub_count_lbl.setText("")
        if not self._current_slug:
            self.domain_info.setText("No program loaded")
            return
        domains = pm.list_domains(self._current_slug)
        for d in domains:
            item = QListWidgetItem()
            settings = pm.get_domain_settings(self._current_slug, d)
            all_sub = settings and settings.get("all_subdomains_in_scope", False)
            item.setText(d + ("  [*]" if all_sub else ""))
            item.setData(Qt.UserRole, d)
            item.setForeground(QBrush(QColor(COLOR_SUCCESS if all_sub else COLOR_TEXT)))
            item.setToolTip(
                "All subdomains in scope" if all_sub else "Only explicit subdomains in scope"
            )
            self.domain_list.addItem(item)
        self.domain_info.setText(f"{len(domains)} domain(s)")
        self.use_domain_btn.setEnabled(bool(domains))

    def _refresh_subdomains(self):
        self.sub_list.clear()
        if not self._current_slug or not self._current_domain:
            self.sub_count_lbl.setText("")
            return
        subs = pm.list_subdomains(self._current_slug, self._current_domain)
        for s in subs:
            self.sub_list.addItem(QListWidgetItem(s))
        self.sub_count_lbl.setText(f"{len(subs)} subdomain(s)")
        self.use_sub_btn.setEnabled(bool(subs))

    def _update_scope_summary(self):
        rules = pm.load_scope_rules(self._current_slug) if self._current_slug else []
        inc = sum(1 for r in rules if r.get("type") == "include" and r.get("enabled", True))
        exc = sum(1 for r in rules if r.get("type") == "exclude" and r.get("enabled", True))
        self._scope_summary_lbl.setText(
            f"  ✅ {inc} include  🚫 {exc} exclude"
        )

    # ── Scope rules actions ────────────────────────────────────────────────

    def _quick_add_include(self):
        host = self._quick_host_input.text().strip().lower()
        if not host:
            return
        all_sub = self._quick_all_sub_cb.isChecked()
        rule = {
            "enabled": True, "type": "include", "protocol": "any",
            "host": host, "all_subdomains": all_sub, "port": "", "comment": "",
        }
        self._rules_table.add_rule(rule)
        self._quick_host_input.clear()
        self._on_scope_rules_changed()

    def _quick_add_exclude(self):
        host = self._quick_host_input.text().strip().lower()
        if not host:
            return
        rule = {
            "enabled": True, "type": "exclude", "protocol": "any",
            "host": host, "all_subdomains": False, "port": "", "comment": "",
        }
        self._rules_table.add_rule(rule)
        self._quick_host_input.clear()
        self._on_scope_rules_changed()

    def _open_add_rule_dialog(self, rule_type: str):
        dlg = AddScopeEntryDialog(self, rule_type=rule_type)
        if dlg.exec_() == QDialog.Accepted:
            rule = dlg.get_rule()
            self._rules_table.add_rule(rule)
            self._on_scope_rules_changed()

    def _on_table_item_changed(self, item):
        """Triggered when any cell is edited - auto-save and emit scope changed."""
        if not self._rules_table._loading:
            self._rules_table.save_current_rules()

    def _on_scope_rules_changed(self):
        """Called whenever scope rules are saved to disk. Re-emits scope signal."""
        self._update_scope_summary()
        # Debounce via QTimer to avoid rapid-fire
        if not hasattr(self, "_scope_debounce_timer"):
            self._scope_debounce_timer = QTimer(self)
            self._scope_debounce_timer.setSingleShot(True)
            self._scope_debounce_timer.timeout.connect(self._emit_scope)
        self._scope_debounce_timer.start(300)

    def _test_scope(self):
        url = self._test_url_input.text().strip()
        if not url or not self._current_slug:
            return
        in_scope = pm.is_in_scope(self._current_slug, url)
        if in_scope:
            self._test_result_lbl.setText("✅ IN SCOPE")
            self._test_result_lbl.setStyleSheet(f"color: {COLOR_SUCCESS}; font-weight: bold;")
        else:
            self._test_result_lbl.setText("🚫 OUT OF SCOPE")
            self._test_result_lbl.setStyleSheet(f"color: {COLOR_CRITICAL}; font-weight: bold;")
        QTimer.singleShot(4000, lambda: self._test_result_lbl.setText(""))

    # ── Domain actions ─────────────────────────────────────────────────────

    def _add_domain_from_input(self):
        domain = self.domain_input.text().strip().lower()
        if not domain:
            return
        all_sub = self._domain_all_sub_cb.isChecked()
        self._add_domain(domain, all_sub)
        self.domain_input.clear()

    def _add_domain(self, domain: str, all_subdomains_in_scope: bool = False):
        if not self._current_slug:
            QMessageBox.information(self, "Info", "No program loaded.")
            return
        try:
            pm.add_domain(self._current_slug, domain, all_subdomains_in_scope)
            self._refresh_all()
            self._on_scope_rules_changed()
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))

    def _remove_domain(self):
        item = self.domain_list.currentItem()
        if not item:
            return
        domain = item.data(Qt.UserRole) or item.text().split("  ")[0]
        reply = QMessageBox.question(
            self, "Remove Domain",
            f"Remove domain '{domain}' and all its subdomains?\n"
            f"This will also remove the associated 'Include' scope rule.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            pm.remove_domain(self._current_slug, domain)
            
            # Remove associated scope rule
            rules = pm.load_scope_rules(self._current_slug)
            new_rules = [r for r in rules if not (r.get("host") == domain and r.get("type") == "include")]
            if len(new_rules) < len(rules):
                pm.save_scope_rules(self._current_slug, new_rules)
            
            self._current_domain = ""
            self._current_subdomain = ""
            self._refresh_domains()
            self._update_banner()

    def _set_program_target(self):
        if not self._current_slug:
            return
        self._current_domain = ""
        self._current_subdomain = ""
        self._update_banner()
        self._emit_scope()

    def _set_domain_target(self):
        item = self.domain_list.currentItem()
        if not item:
            return
        self._current_domain = item.data(Qt.UserRole) or item.text().split("  ")[0]
        self._current_subdomain = ""
        self._update_banner()
        self._emit_scope()

    def _toggle_auto_scope(self, domain: str, checked: bool):
        if not self._current_slug:
            return
        pm.add_domain(self._current_slug, domain, all_subdomains_in_scope=checked)
        self._refresh_all()
        self._on_scope_rules_changed()

    def _domain_context_menu(self, pos):
        item = self.domain_list.itemAt(pos)
        if not item:
            return
        domain = item.data(Qt.UserRole) or item.text().split("  ")[0]
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; }}"
            f"QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #000; }}"
        )
        settings = pm.get_domain_settings(self._current_slug, domain)
        is_auto_scoped = settings and settings.get("all_subdomains_in_scope", False)
        auto_scope_action = menu.addAction("☑ All subdomains in scope")
        auto_scope_action.setCheckable(True)
        auto_scope_action.setChecked(is_auto_scoped)
        auto_scope_action.triggered.connect(partial(self._toggle_auto_scope, domain))
        menu.addSeparator()
        menu.addAction("Set as Target").triggered.connect(self._set_domain_target)

        # Add to scope rules quick actions
        menu.addSeparator()
        menu.addAction("✅ Add to Include rules").triggered.connect(
            lambda: self._add_domain_to_scope_rules(domain, "include")
        )
        menu.addAction("🚫 Add to Exclude rules").triggered.connect(
            lambda: self._add_domain_to_scope_rules(domain, "exclude")
        )
        menu.addSeparator()
        menu.addAction("✕ Remove").triggered.connect(self._remove_domain)
        menu.exec_(self.domain_list.viewport().mapToGlobal(pos))

    def _add_domain_to_scope_rules(self, domain: str, rule_type: str):
        dlg = AddScopeEntryDialog(self, rule_type=rule_type, prefill_host=domain)
        if dlg.exec_() == QDialog.Accepted:
            rule = dlg.get_rule()
            self._rules_table.add_rule(rule)
            self._on_scope_rules_changed()

    # ── Subdomain actions ──────────────────────────────────────────────────

    def _add_subdomain(self):
        if not self._current_domain:
            QMessageBox.information(self, "Info", "Select a domain first.")
            return
        sub = self.sub_input.text().strip().lower()
        if not sub:
            return
        try:
            pm.add_subdomain(self._current_slug, self._current_domain, sub)
            self.sub_input.clear()
            self._refresh_subdomains()
            self._on_scope_rules_changed()
        except ValueError as e:
            QMessageBox.warning(self, "Error", str(e))

    def _remove_subdomain(self):
        item = self.sub_list.currentItem()
        if not item:
            return
        sub = item.text()
        pm.remove_subdomain(self._current_slug, self._current_domain, sub)
        if self._current_subdomain == sub:
            self._current_subdomain = ""
            
        # Remove associated scope rule
        rules = pm.load_scope_rules(self._current_slug)
        new_rules = [r for r in rules if not (r.get("host") == sub and r.get("type") == "include")]
        if len(new_rules) < len(rules):
            pm.save_scope_rules(self._current_slug, new_rules)
            
        self._refresh_subdomains()
        self._update_banner()
        self._on_scope_rules_changed()

    def _set_subdomain_target(self):
        item = self.sub_list.currentItem()
        if not item:
            return
        self._current_subdomain = item.text()
        self._update_banner()
        self._emit_scope()

    def _bulk_import_subdomains(self):
        if not self._current_domain:
            QMessageBox.information(self, "Info", "Select a domain first.")
            return
        dlg = BulkSubdomainDialog(self._current_domain, self)
        if dlg.exec_() != QDialog.Accepted:
            return
        subs = dlg.get_subdomains()
        if subs:
            pm.bulk_add_subdomains(self._current_slug, self._current_domain, subs)
            self._refresh_subdomains()
            self._on_scope_rules_changed()
            QMessageBox.information(
                self, "Done", f"Imported {len(subs)} subdomains into {self._current_domain}"
            )

    def _sub_context_menu(self, pos):
        item = self.sub_list.itemAt(pos)
        if not item:
            return
        sub = item.text()
        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; }}"
            f"QMenu::item:selected {{ background-color: {COLOR_ACCENT}; color: #000; }}"
        )
        menu.addAction("Set as Target").triggered.connect(self._set_subdomain_target)
        menu.addSeparator()
        menu.addAction("✅ Add to Include rules").triggered.connect(
            lambda: self._add_domain_to_scope_rules(sub, "include")
        )
        menu.addAction("🚫 Add to Exclude rules").triggered.connect(
            lambda: self._add_domain_to_scope_rules(sub, "exclude")
        )
        menu.addSeparator()
        menu.addAction("✕ Remove").triggered.connect(self._remove_subdomain)
        menu.exec_(self.sub_list.viewport().mapToGlobal(pos))

    # ── Signal handlers ────────────────────────────────────────────────────

    def _on_domain_selected(self, row: int):
        if row < 0:
            self._current_domain = ""
            self._refresh_subdomains()
            return
        item = self.domain_list.item(row)
        if item is None:
            return
        self._current_domain = item.data(Qt.UserRole) or item.text().split("  ")[0]
        self._current_subdomain = ""
        self._refresh_subdomains()
        self._update_banner()

    def _on_subdomain_selected(self, row: int):
        if row < 0:
            self._current_subdomain = ""
            return
        item = self.sub_list.item(row)
        if item is None:
            return
        self._current_subdomain = item.text()
        self._update_banner()

    # ── Misc ───────────────────────────────────────────────────────────────

    def _open_platform_url(self):
        if not self._current_slug:
            return
        data = pm.get_program(self._current_slug)
        if data and data.get("platform_url"):
            webbrowser.open(data["platform_url"])

    def _update_banner(self):
        prog_data = pm.get_program(self._current_slug) if self._current_slug else None
        prog_name = prog_data["name"] if prog_data else "—"
        self.active_program_lbl.setText(prog_name)
        self.open_url_btn.setVisible(bool(prog_data and prog_data.get("platform_url")))

    def _emit_scope(self):
        self.scope_changed.emit(
            self._current_slug,
            self._current_domain,
            self._current_subdomain,
        )

    # ── Public API ────────────────────────────────────────────────────────

    def get_current_scope(self) -> dict:
        """Return current scope selection as dict."""
        return {
            "slug": self._current_slug,
            "domain": self._current_domain,
            "subdomain": self._current_subdomain,
            "scope_hosts": pm.get_scope_hosts(
                self._current_slug, self._current_domain, self._current_subdomain
            ),
            "scope_rules": pm.load_scope_rules(self._current_slug) if self._current_slug else [],
        }

    def get_project_paths(self) -> Optional[dict]:
        """Return project paths for current slug, or None if no project selected."""
        if not self._current_slug:
            return None
        return pm.get_project_paths(self._current_slug)

    # need to be accessible from hunt_gui.py for refreshing
    def _refresh_domains_public(self):
        self._refresh_domains()

    def _refresh_subdomains_public(self):
        self._refresh_subdomains()