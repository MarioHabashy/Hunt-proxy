#!/usr/bin/env python3
"""
launch_dialog.py  –  Project selection dialog shown on Hunt GUI startup.

User picks (or creates) a project before the main window opens,
so every session is scoped from the start.
"""

import os
import json
from typing import Optional

from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QLineEdit, QFormLayout, QFrame, QGroupBox,
    QDialogButtonBox, QMessageBox, QTabWidget, QWidget,
    QSizePolicy,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

from . import project_manager as pm

try:
    from modules.constants import (
        COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_ELEVATED_BG,
        COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED,
        COLOR_BORDER, COLOR_ACCENT, COLOR_SUCCESS, COLOR_CRITICAL,
        COLOR_MEDIUM, COLOR_LOW, FONT_FAMILY, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
        FONT_SIZE_LARGE,
    )
except ImportError:
    COLOR_BACKGROUND = "#1e1e2e"; COLOR_DARK_BG = "#181825"
    COLOR_CARD_BG = "#24273a"; COLOR_ELEVATED_BG = "#2a2d3e"
    COLOR_TEXT = "#cdd6f4"; COLOR_TEXT_BRIGHT = "#ffffff"; COLOR_TEXT_MUTED = "#6c7086"
    COLOR_BORDER = "#45475a"; COLOR_ACCENT = "#89b4fa"
    COLOR_SUCCESS = "#a6e3a1"; COLOR_CRITICAL = "#f38ba8"
    COLOR_MEDIUM = "#fab387"; COLOR_LOW = "#89dceb"
    FONT_FAMILY = "Segoe UI"; FONT_SIZE_NORMAL = "12px"
    FONT_SIZE_SMALL = "11px"; FONT_SIZE_LARGE = "14px"

PLATFORMS = ["", "HackerOne", "Bugcrowd", "Intigriti", "Synack",
             "YesWeHack", "Open Bug Bounty", "Private", "Other"]

# ── Persist last-opened project slug ─────────────────────────────────────────
_SETTINGS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "hunt-proxy", "settings.json"
)

def _load_last_slug() -> str:
    try:
        with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("last_slug", "")
    except Exception:
        return ""

def _save_last_slug(slug: str):
    try:
        os.makedirs(os.path.dirname(_SETTINGS_FILE), exist_ok=True)
        data = {}
        try:
            with open(_SETTINGS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
        data["last_slug"] = slug
        with open(_SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

_BASE_STYLE = f"""
QDialog, QWidget {{
    background-color: {COLOR_BACKGROUND};
    color: {COLOR_TEXT};
    font-family: {FONT_FAMILY};
    font-size: {FONT_SIZE_NORMAL};
}}
QLabel {{ color: {COLOR_TEXT}; background: transparent; }}
QLineEdit {{
    background-color: {COLOR_DARK_BG};
    color: {COLOR_TEXT_BRIGHT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 4px;
    padding: 5px 8px;
}}
QLineEdit:focus {{ border-color: {COLOR_ACCENT}; }}
QComboBox {{
    background-color: {COLOR_DARK_BG};
    color: {COLOR_TEXT_BRIGHT};
    border: 1px solid {COLOR_BORDER};
    border-radius: 4px;
    padding: 5px 8px;
    min-width: 220px;
}}
QComboBox QAbstractItemView {{
    background-color: {COLOR_DARK_BG};
    color: {COLOR_TEXT};
    selection-background-color: {COLOR_ACCENT};
    selection-color: #000;
    border: 1px solid {COLOR_BORDER};
}}
QPushButton {{
    background-color: {COLOR_ELEVATED_BG};
    color: {COLOR_ACCENT};
    border: 1px solid {COLOR_ACCENT};
    border-radius: 4px;
    padding: 5px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: #000; }}
QPushButton[danger="true"] {{
    color: {COLOR_CRITICAL};
    border-color: {COLOR_CRITICAL};
}}
QPushButton[danger="true"]:hover {{ background-color: {COLOR_CRITICAL}; color: #000; }}
QGroupBox {{
    border: 1px solid {COLOR_BORDER};
    border-radius: 6px;
    margin-top: 10px;
    padding-top: 14px;
    background-color: {COLOR_CARD_BG};
    font-weight: 600;
    color: {COLOR_TEXT_BRIGHT};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 8px;
    color: {COLOR_ACCENT};
    background-color: {COLOR_CARD_BG};
}}
QTabWidget::pane {{
    border: 1px solid {COLOR_BORDER};
    background-color: {COLOR_BACKGROUND};
}}
QTabBar::tab {{
    background-color: {COLOR_DARK_BG};
    color: {COLOR_TEXT_MUTED};
    padding: 7px 18px;
    border: 1px solid {COLOR_BORDER};
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    font-weight: 500;
}}
QTabBar::tab:selected {{
    background-color: {COLOR_BACKGROUND};
    color: {COLOR_TEXT_BRIGHT};
    font-weight: 700;
}}
"""


def _lbl(text: str, bold: bool = False, color: str = COLOR_TEXT_BRIGHT) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(f"color: {color}; font-weight: {'600' if bold else 'normal'};")
    return l


class LaunchDialog(QDialog):
    """
    Shown once at startup.
    User selects or creates a project, then launches.
    Returns a dict with {slug, domain, subdomain} on accept.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Hunt Proxy — Select Project")
        self.setMinimumSize(600, 540)
        self.setModal(True)
        self.setStyleSheet(_BASE_STYLE)
        self._result: Optional[dict] = None
        self._build_ui()
        self._refresh_projects()
        self.launch_btn.setFocus()

    def showEvent(self, event):
        """Center on screen after the window is actually mapped."""
        super().showEvent(event)
        from PyQt5.QtWidgets import QApplication
        screen_geo = QApplication.primaryScreen().availableGeometry()
        self.adjustSize()
        self.move(
            screen_geo.x() + (screen_geo.width()  - self.width())  // 2,
            screen_geo.y() + (screen_geo.height() - self.height()) // 2,
        )

    # ── UI ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(20, 20, 20, 20)

        # Header
        header = QLabel("Hunt Proxy")
        header.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-size: 18px; font-weight: 700;"
        )
        root.addWidget(header, alignment=Qt.AlignCenter)

        sub = QLabel("Select a project to resume, or create a new one")
        sub.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        root.addWidget(sub, alignment=Qt.AlignCenter)

        # Tabs: Resume | New
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_resume_tab(), " ➔  Resume Project")
        self.tabs.addTab(self._build_new_tab(), " ✚  New Project")
        root.addWidget(self.tabs, stretch=1)

        # Buttons
        btn_row = QHBoxLayout()
        self.launch_btn = QPushButton("⏻  Launch")
        self.launch_btn.setMinimumHeight(36)
        self.launch_btn.setDefault(True)
        self.launch_btn.setAutoDefault(True)
        self.launch_btn.setStyleSheet(
            f"QPushButton {{ background-color: {COLOR_ACCENT}; color: #000; "
            f"border: none; border-radius: 4px; font-size: 13px; font-weight: 700; "
            f"padding: 8px 28px; }}"
            f"QPushButton:hover {{ background-color: #a6c4fc; }}"
        )
        self.launch_btn.clicked.connect(self._on_launch)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)

        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self.launch_btn)
        root.addLayout(btn_row)

    # ── Resume tab ─────────────────────────────────────────────────────────

    def _build_resume_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 8)

        # Project selector
        proj_box = QGroupBox("Project")
        proj_layout = QFormLayout(proj_box)
        proj_layout.setSpacing(8)

        self.project_combo = QComboBox()
        self.project_combo.currentIndexChanged.connect(self._on_project_changed)
        proj_layout.addRow(_lbl("Project:"), self.project_combo)

        self.proj_info_lbl = _lbl("", color=COLOR_TEXT_MUTED)
        self.proj_info_lbl.setWordWrap(True)
        proj_layout.addRow("", self.proj_info_lbl)

        layout.addWidget(proj_box)

        # Stats card
        self.stats_frame = QFrame()
        self.stats_frame.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_CARD_BG}; border: none; border-radius: 6px; }}"
        )
        stats_layout = QVBoxLayout(self.stats_frame)
        stats_layout.setContentsMargins(12, 10, 12, 10)
        stats_layout.setSpacing(6)

        self.stats_created_lbl  = _lbl("", color=COLOR_TEXT_MUTED)
        self.stats_updated_lbl  = _lbl("", color=COLOR_TEXT_MUTED)
        self.stats_domains_lbl  = _lbl("", color=COLOR_TEXT_MUTED)
        self.stats_requests_lbl = _lbl("", color=COLOR_TEXT_MUTED)

        for lbl in (self.stats_created_lbl, self.stats_updated_lbl,
                    self.stats_domains_lbl, self.stats_requests_lbl):
            lbl.setWordWrap(True)
            stats_layout.addWidget(lbl)

        layout.addWidget(self.stats_frame)
        layout.addStretch()

        # Delete project button
        delete_btn = QPushButton("🗑  Delete Selected Project…")
        delete_btn.setProperty("danger", "true")
        delete_btn.setStyleSheet(
            f"QPushButton {{ background-color: transparent; color: {COLOR_CRITICAL}; "
            f"border: 1px solid {COLOR_CRITICAL}; border-radius: 4px; "
            f"padding: 5px 14px; font-weight: 600; }}"
            f"QPushButton:hover {{ background-color: {COLOR_CRITICAL}; color: #000; }}"
        )
        delete_btn.clicked.connect(self._on_delete_project)
        layout.addWidget(delete_btn, alignment=Qt.AlignRight)

        return tab

    # ── New project tab ────────────────────────────────────────────────────

    def _build_new_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 8)

        proj_box = QGroupBox("New Project")
        form = QFormLayout(proj_box)
        form.setSpacing(10)

        self.new_name_edit = QLineEdit()
        self.new_name_edit.setPlaceholderText("Acme Bug Bounty")
        form.addRow(_lbl("Name *:"), self.new_name_edit)

        self.new_platform_combo = QComboBox()
        self.new_platform_combo.addItems(PLATFORMS)
        form.addRow(_lbl("Platform:"), self.new_platform_combo)

        self.new_url_edit = QLineEdit()
        self.new_url_edit.setPlaceholderText("https://hackerone.com/acme")
        form.addRow(_lbl("Project URL:"), self.new_url_edit)

        self.new_domain_edit = QLineEdit()
        self.new_domain_edit.setPlaceholderText("acme.com  (optional, can add later)")
        form.addRow(_lbl("First domain:"), self.new_domain_edit)

        layout.addWidget(proj_box)

        hint = _lbl(
            "You can add more domains and subdomains from the Scope tab after launch.",
            color=COLOR_TEXT_MUTED,
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

        layout.addStretch()
        return tab

    # ── Data helpers ───────────────────────────────────────────────────────

    def _refresh_projects(self):
        self.project_combo.blockSignals(True)
        self.project_combo.clear()
        projects = pm.list_programs()
        if not projects:
            self.project_combo.addItem("(no projects yet)", "")
            self.project_combo.blockSignals(False)
            self.tabs.setCurrentIndex(1)   # switch to New tab
            self._clear_stats()
            return

        # Sort newest-first by created_at
        projects.sort(
            key=lambda p: p.get("created_at", ""),
            reverse=True,
        )

        last_slug = _load_last_slug()
        select_idx = 0
        for i, p in enumerate(projects):
            label = p["name"]
            if p.get("platform"):
                label += f"  [{p['platform']}]"
            self.project_combo.addItem(label, p["slug"])
            if p["slug"] == last_slug:
                select_idx = i

        self.project_combo.blockSignals(False)
        self.project_combo.setCurrentIndex(select_idx)
        self._on_project_changed(select_idx)
        self.tabs.setCurrentIndex(0)

    def _on_project_changed(self, idx: int):
        slug = self.project_combo.itemData(idx)
        if not slug:
            self._clear_stats()
            return

        data = pm.get_program(slug)

        # Platform / URL info line
        if data:
            info_parts = []
            if data.get("platform"):
                info_parts.append(data["platform"])
            if data.get("platform_url"):
                info_parts.append(data["platform_url"])
            self.proj_info_lbl.setText("  ".join(info_parts))
        else:
            self.proj_info_lbl.setText("")

        # ── Stats card ────────────────────────────────────────────────────
        def _fmt_dt(iso: str) -> str:
            if not iso:
                return "—"
            try:
                from datetime import datetime as _dt
                return _dt.fromisoformat(iso).strftime("%Y-%m-%d  %H:%M")
            except Exception:
                return iso[:16]

        created_at  = _fmt_dt(data.get("created_at",  "") if data else "")
        updated_at  = _fmt_dt(data.get("updated_at",  "") if data else "")
        domain_count = len(data.get("domains", {})) if data else 0

        self.stats_created_lbl.setText(f"    Created:       {created_at}")
        self.stats_updated_lbl.setText(f"    Last updated:  {updated_at}")
        self.stats_domains_lbl.setText(f"    Domains:       {domain_count}")

        paths = pm.get_project_paths(slug)
        jsonl = paths["jsonl"]
        if os.path.exists(jsonl):
            try:
                with open(jsonl, "r", encoding="utf-8") as f:
                    count = sum(1 for line in f if line.strip())
                self.stats_requests_lbl.setText(f"    Requests:      {count:,} captured")
            except Exception:
                self.stats_requests_lbl.setText("    Requests:      —")
        else:
            self.stats_requests_lbl.setText("    Requests:      no traffic yet")

    def _clear_stats(self):
        self.proj_info_lbl.setText("")
        for lbl in (self.stats_created_lbl, self.stats_updated_lbl,
                    self.stats_domains_lbl, self.stats_requests_lbl):
            lbl.setText("")

    # ── Delete project ─────────────────────────────────────────────────────

    def _on_delete_project(self):
        """Delete the currently selected project."""
        slug = self.project_combo.currentData()
        if not slug:
            QMessageBox.warning(self, "No Selection", "Please select a project first.")
            return

        data = pm.get_program(slug)
        proj_name = data["name"] if data else slug

        reply = QMessageBox.question(
            self, "Delete Project",
            f"Delete project  '{proj_name}'?\n\nThis will remove it from the project list.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        reply2 = QMessageBox.question(
            self, "Delete Project Data",
            f"Also permanently delete ALL captured data for  '{proj_name}'?\n\n"
            f"(requests, responses, JSONL, notes — cannot be undone)\n\n"
            f"• Yes = delete project AND all data\n"
            f"• No  = remove from list only (data kept on disk)",
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.No
        )
        if reply2 == QMessageBox.Cancel:
            return

        try:
            pm.delete_program(slug, delete_data=(reply2 == QMessageBox.Yes))
        except Exception as exc:
            QMessageBox.critical(self, "Delete Failed", str(exc))
            return

        QMessageBox.information(self, "Deleted", f"Project '{proj_name}' has been deleted.")
        self._refresh_projects()

    # ── Launch ─────────────────────────────────────────────────────────────

    def _on_launch(self):
        if self.tabs.currentIndex() == 1:
            # Creating new project
            name = self.new_name_edit.text().strip()
            if not name:
                QMessageBox.warning(self, "Validation", "Project name is required.")
                return
            try:
                slug = pm.create_program(
                    name,
                    self.new_platform_combo.currentText(),
                    self.new_url_edit.text().strip(),
                )
                first_domain = self.new_domain_edit.text().strip().lower()
                if first_domain:
                    pm.add_domain(slug, first_domain)
            except ValueError as e:
                QMessageBox.warning(self, "Error", str(e))
                return
        else:
            # Resuming existing project
            slug = self.project_combo.currentData()
            if not slug:
                QMessageBox.warning(
                    self, "No Project",
                    "Please select a project or create a new one."
                )
                return

        _save_last_slug(slug)
        self._result = {"slug": slug, "domain": "", "subdomain": ""}

        # Show loading state so the user sees feedback while the main window
        # initialises (which can take a few seconds on first launch).
        self._set_loading_state()

        # Accept on the next event-loop tick so the loading state renders first.
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(50, self.accept)

    def _set_loading_state(self):
        """Disable all interactive widgets and show a loading message."""
        self.launch_btn.setText("⏳  Loading…")
        self.launch_btn.setEnabled(False)
        # Disable every other button in the dialog
        from PyQt5.QtWidgets import QPushButton
        for btn in self.findChildren(QPushButton):
            btn.setEnabled(False)
        # Grey-out the tab widget so it's obvious the dialog is busy
        self.tabs.setEnabled(False)
        self.repaint()

    def get_result(self) -> Optional[dict]:
        """Returns {slug, domain, subdomain} or None if cancelled."""
        return self._result