"""
finding_tab.py
──────────────
"Findings" sub-tab for the Attack Surface panel.

Displays findings that were auto-saved by the Analysis Tab, grouped by
vulnerability category.  Each row shows:
    • Severity badge    • Method    • Status
    • Host              • URL       • Parameter
    • Detections summary

Features
────────
 ✔  Live reload whenever the sub-tab becomes visible
 ✔  Category selector (left sidebar)
 ✔  Severity filter bar (CRITICAL / HIGH / MEDIUM / LOW)
 ✔  Full-text search
 ✔  Right-click → copy URL / copy parameter / delete entry
 ✔  Double-click row → detail dialog
 ✔  Export selected / all to JSON/CSV
 ✔  Stats header card
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QCheckBox, QLineEdit,
    QMenu, QDialog, QTextEdit, QFrame, QApplication,
    QFileDialog, QMessageBox, QListWidget, QListWidgetItem,
    QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QFont, QIcon

try:
    from modules.constants import (
        COLOR_BACKGROUND, COLOR_ELEVATED_BG, COLOR_CARD_BG,
        COLOR_DARK_BG, COLOR_BORDER, COLOR_TEXT, COLOR_TEXT_BRIGHT,
        COLOR_TEXT_MUTED, COLOR_ACCENT, COLOR_SUCCESS, COLOR_WARNING,
        COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_INFO, COLOR_HOVER,
    )
except ImportError:
    COLOR_BACKGROUND  = "#1e1e1e"
    COLOR_ELEVATED_BG = "#252525"
    COLOR_CARD_BG     = "#2d2d2d"
    COLOR_DARK_BG     = "#181818"
    COLOR_BORDER      = "#3e3e3e"
    COLOR_TEXT        = "#cccccc"
    COLOR_TEXT_BRIGHT = "#ffffff"
    COLOR_TEXT_MUTED  = "#808080"
    COLOR_ACCENT      = "#0e639c"
    COLOR_SUCCESS     = "#4ec9b0"
    COLOR_WARNING     = "#ce9178"
    COLOR_CRITICAL    = "#f48771"
    COLOR_HIGH        = "#ff6b6b"
    COLOR_MEDIUM      = "#feca57"
    COLOR_INFO        = "#48dbfb"
    COLOR_HOVER       = "#2a2d2e"

from modules.analysis_recordings import RecordingManager, CATEGORIES

# ── Severity palette ────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": ("#f44336", "#ffffff"),
    "HIGH":     ("#ff7043", "#ffffff"),
    "MEDIUM":   ("#ffc107", "#000000"),
    "LOW":      ("#66bb6a", "#000000"),
}
SEV_ICON = {
    "CRITICAL": "Ⓒ",
    "HIGH":     "Ⓗ",
    "MEDIUM":   "Ⓜ",
    "LOW":      "Ⓛ",
}

METHOD_COLOR = {
    "GET":    "#4ec9b0",
    "POST":   "#569cd6",
    "PUT":    "#dcdcaa",
    "PATCH":  "#c586c0",
    "DELETE": "#f48771",
}

# ── Table column indices ─────────────────────────────────────────────────────
COL_METHOD   = 0
COL_STATUS   = 1
COL_URL      = 2
COL_LOCATION = 3
COL_PARAM    = 4
COL_DETECT   = 5
_COLUMNS     = ["Method", "Status", "URL", "Location", "Parameter", "Detections"]


# ══════════════════════════════════════════════════════════════════════════════

class _DetailDialog(QDialog):
    """Full-detail popup for a single recorded entry."""

    def __init__(self, entry: dict, parent=None, show_in_history_cb=None):
        super().__init__(parent)
        self.entry = entry
        self._show_in_history_cb = show_in_history_cb
        cat_key  = entry.get("category", "other")
        cat_info = CATEGORIES.get(cat_key, ("Other", "🔍", 99))
        self.setWindowTitle(f"{cat_info[1]}  {cat_info[0]}  — Detail")
        self.setMinimumSize(780, 520)
        self._build_ui()

    def _build_ui(self):
        sev   = self.entry.get("severity", "LOW").upper()
        color = SEV_COLOR.get(sev, ("#888", "#fff"))[0]

        self.setStyleSheet(f"""
            QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
            QLabel    {{ color:{COLOR_TEXT}; }}
            QTextEdit {{ background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                         border:1px solid {COLOR_BORDER};
                         font-family: 'Consolas','Courier New',monospace;
                         font-size:12px; padding:6px; }}
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:5px 14px; font-weight:bold; }}
            QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # ── Severity badge header ─────────────────────────────────────────
        header = QLabel(
            f"<b style='color:{color};font-size:15px;'>"
            f"{SEV_ICON.get(sev, '🞅')} {sev}</b>"
            f"  <span style='font-size:13px;color:{COLOR_TEXT_MUTED};'>"
            f"{self.entry.get('method','GET')}  {self.entry.get('status','')}  "
            f"{self.entry.get('timestamp','')}</span>"
        )
        header.setStyleSheet("padding:8px; border-bottom:1px solid #3e3e3e;")
        layout.addWidget(header)

        # ── Fields grid ──────────────────────────────────────────────────
        grid_style = (
            f"color:{COLOR_TEXT_BRIGHT}; background:{COLOR_CARD_BG};"
            f"border:1px solid {COLOR_BORDER}; border-radius:4px; padding:6px;"
            f"font-family:'Consolas','Courier New',monospace; font-size:12px;"
        )

        def _field(label, value, copyable=False):
            row = QHBoxLayout()
            lbl = QLabel(f"<b style='color:{COLOR_TEXT_MUTED};'>{label}</b>")
            lbl.setFixedWidth(120)
            val = QLabel(value or "—")
            val.setStyleSheet(grid_style)
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            row.addWidget(lbl)
            row.addWidget(val, 1)
            return row

        layout.addLayout(_field("URL",       self.entry.get("url", "")))
        layout.addLayout(_field("Host",      self.entry.get("host", "")))
        layout.addLayout(_field("Method",    self.entry.get("method", "")))
        layout.addLayout(_field("Status",    self.entry.get("status", "")))
        layout.addLayout(_field("Location",  self.entry.get("location", "")))
        layout.addLayout(_field("Parameter", self.entry.get("parameter", "")))

        reflected = self.entry.get("reflected_params", [])
        if reflected:
            layout.addLayout(_field("Reflected", ", ".join(reflected)))

        # ── Detections box ────────────────────────────────────────────────
        det_label = QLabel(f"<b style='color:{COLOR_TEXT_MUTED};'>Detections</b>")
        layout.addWidget(det_label)
        det_box = QTextEdit()
        det_box.setPlainText(self.entry.get("detections", ""))
        det_box.setReadOnly(True)
        det_box.setMaximumHeight(120)
        layout.addWidget(det_box)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()

        history_btn = QPushButton("🖳 Show in HTTP History")
        history_btn.setStyleSheet(f"""
            QPushButton {{
                background:{COLOR_ACCENT}; color:#fff;
                border:none; border-radius:4px;
                padding:5px 14px; font-weight:bold;
            }}
            QPushButton:hover {{ background:#1e7ac0; }}
        """)
        def _go_history():
            self.accept()   # close dialog first
            if self._show_in_history_cb:
                self._show_in_history_cb(self.entry)
        history_btn.clicked.connect(_go_history)

        copy_url_btn = QPushButton("🗉 Copy URL")
        copy_url_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.entry.get("url", ""))
        )
        copy_param_btn = QPushButton("🗉 Copy Parameter")
        copy_param_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.entry.get("parameter", ""))
        )
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)

        btn_row.addWidget(history_btn)
        btn_row.addWidget(copy_url_btn)
        btn_row.addWidget(copy_param_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)


# ══════════════════════════════════════════════════════════════════════════════

class RecordedTab(QWidget):
    """
    The "Recorded" sub-tab.  Instantiated once by MappingTabPro and
    added as ``self.sub_tabs.addTab(self.finding_tab, "🗠  Findings")``.
    """

    def __init__(self, mapping_tab, parent=None):
        super().__init__(parent)
        self.mapping_tab = mapping_tab
        self._project_dir: Optional[str] = None
        self._all_entries: List[dict]    = []   # flat list, current category
        self._current_category: str      = "__all__"
        self._init_ui()
        # Poll for project_dir every second until found, then load data
        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._try_init_project)
        self._poll_timer.start(1000)

    # ── Project dir discovery ──────────────────────────────────────────────

    def _try_init_project(self):
        try:
            pp = self.mapping_tab.parent_gui._project_paths
            if pp and pp.get("project_dir"):
                self._project_dir = pp["project_dir"]
                self._poll_timer.stop()
                self._refresh()
        except AttributeError:
            pass  # not ready yet

    def set_project_dir(self, project_dir: str):
        """Called externally when project dir is known."""
        self._project_dir = project_dir
        self._poll_timer.stop()
        self._refresh()

    # ── UI construction ────────────────────────────────────────────────────

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Stats header ─────────────────────────────────────────────────
        self._stats_bar = QLabel("  Loading…")
        self._stats_bar.setFixedHeight(38)
        self._stats_bar.setStyleSheet(f"""
            QLabel {{
                background:{COLOR_ELEVATED_BG};
                color:{COLOR_TEXT_MUTED};
                font-size:12px;
                padding:0 14px;
                border-bottom:1px solid {COLOR_BORDER};
            }}
        """)
        root.addWidget(self._stats_bar)

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = self._build_toolbar()
        root.addWidget(toolbar)

        # ── Main splitter (category list | table) ─────────────────────────
        splitter = QSplitter(Qt.Horizontal)

        # Left: category list
        self._cat_list = QListWidget()
        self._cat_list.setFixedWidth(210)
        self._cat_list.setStyleSheet(f"""
            QListWidget {{
                background:{COLOR_DARK_BG};
                border:none;
                border-right:1px solid {COLOR_BORDER};
                font-size:13px;
                outline:none;
            }}
            QListWidget::item {{
                padding:10px 12px;
                border-bottom:1px solid {COLOR_BORDER};
            }}
            QListWidget::item:selected {{
                background:{COLOR_ACCENT};
                color:#fff;
                font-weight:bold;
            }}
            QListWidget::item:hover:!selected {{
                background:{COLOR_ELEVATED_BG};
            }}
        """)
        self._cat_list.currentRowChanged.connect(self._on_category_changed)
        splitter.addWidget(self._cat_list)

        # Right: table + detail splitter
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        self._table = self._build_table()
        right_layout.addWidget(self._table)

        splitter.addWidget(right_widget)
        splitter.setSizes([210, 900])
        splitter.setChildrenCollapsible(False)

        root.addWidget(splitter)

    def _build_toolbar(self) -> QWidget:
        toolbar = QWidget()
        toolbar.setFixedHeight(44)
        toolbar.setStyleSheet(f"""
            QWidget {{
                background:{COLOR_ELEVATED_BG};
                border-bottom:1px solid {COLOR_BORDER};
            }}
        """)
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)

        btn_style = f"""
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 12px; font-weight:bold; font-size:12px;
            }}
            QPushButton:hover {{
                background:{COLOR_ELEVATED_BG}; border-color:{COLOR_ACCENT};
                color:{COLOR_TEXT_BRIGHT};
            }}
        """

        refresh_btn = QPushButton("⟳ Refresh")
        refresh_btn.setStyleSheet(btn_style)
        refresh_btn.setToolTip("Reload recordings from disk")
        refresh_btn.clicked.connect(self._refresh)
        layout.addWidget(refresh_btn)

        # Severity filters
        sep = QFrame(); sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color:{COLOR_BORDER}; max-width:1px;")
        layout.addWidget(sep)

        self._sev_checks: Dict[str, QCheckBox] = {}
        for sev, (bg, fg) in SEV_COLOR.items():
            cb = QCheckBox(f"{SEV_ICON[sev]} {sev.title()}")
            cb.setChecked(True)
            cb.setStyleSheet(f"""
                QCheckBox {{ color:{bg}; font-weight:bold; font-size:12px; padding:0 4px; }}
                QCheckBox::indicator {{ width:14px; height:14px; border-radius:3px; border:1px solid {COLOR_BORDER}; }}
                QCheckBox::indicator:checked {{ background:{bg}; border:1px solid {bg}; }}
            """)
            cb.stateChanged.connect(self._apply_filters)
            self._sev_checks[sev] = cb
            layout.addWidget(cb)

        sep2 = QFrame(); sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"color:{COLOR_BORDER}; max-width:1px;")
        layout.addWidget(sep2)

        # Search box
        self._search = QLineEdit()
        self._search.setPlaceholderText("⌕  Filter by URL, parameter, detection…")
        self._search.setFixedWidth(260)
        self._search.setStyleSheet(f"""
            QLineEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 10px; font-size:12px;
            }}
            QLineEdit:focus {{ border-color:{COLOR_ACCENT}; }}
        """)
        self._search.textChanged.connect(self._apply_filters)
        layout.addWidget(self._search)

        layout.addStretch()

        # Export / Clear buttons
        export_btn = QPushButton("🠉 Export")
        export_btn.setStyleSheet(btn_style)
        export_btn.setToolTip("Export current view to JSON or CSV")
        export_btn.clicked.connect(self._export)
        layout.addWidget(export_btn)

        clear_btn = QPushButton("🗑 Clear Category")
        clear_btn.setStyleSheet(btn_style)
        clear_btn.setToolTip("Delete all entries in the selected category")
        clear_btn.clicked.connect(self._clear_category)
        layout.addWidget(clear_btn)

        return toolbar

    def _build_table(self) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(_COLUMNS))
        table.setHorizontalHeaderLabels(_COLUMNS)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setContextMenuPolicy(Qt.CustomContextMenu)
        table.customContextMenuRequested.connect(self._context_menu)
        table.doubleClicked.connect(self._open_detail)
        table.setSortingEnabled(True)

        hh = table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(False)

        # Sensible default widths — user can drag to adjust any column
        table.setColumnWidth(COL_METHOD,   70)
        table.setColumnWidth(COL_STATUS,   60)
        table.setColumnWidth(COL_URL,      420)
        table.setColumnWidth(COL_LOCATION, 80)
        table.setColumnWidth(COL_PARAM,    160)
        table.setColumnWidth(COL_DETECT,   300)

        # URL column stretches to fill remaining space by default,
        # but user can still drag it to a fixed width.
        hh.setSectionResizeMode(COL_URL, QHeaderView.Stretch)

        table.verticalHeader().setDefaultSectionSize(28)
        table.verticalHeader().hide()

        table.setStyleSheet(f"""
            QTableWidget {{
                background:{COLOR_DARK_BG};
                alternate-background-color:{COLOR_CARD_BG};
                gridline-color:{COLOR_BORDER};
                border:none;
                color:{COLOR_TEXT};
                font-size:12px;
                selection-background-color:{COLOR_ACCENT};
                selection-color:#fff;
                outline:none;
            }}
            QTableWidget::item {{ padding:4px 8px; border:none; }}
            QTableWidget::item:hover {{ background:{COLOR_HOVER}; }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT};
                padding:5px 8px; border:1px solid {COLOR_BORDER};
                border-left:none; border-top:none; font-weight:bold;
                font-size:12px;
            }}
            QHeaderView::section:first {{ border-left:1px solid {COLOR_BORDER}; }}
        """)
        return table

    # ── Data loading ──────────────────────────────────────────────────────

    def _refresh(self):
        if not self._project_dir:
            return
        data = RecordingManager.load(self._project_dir)
        self._build_category_list(data)
        self._update_stats(data)
        # Re-select current category
        self._load_category(data, self._current_category)

    def _build_category_list(self, data: Dict):
        self._cat_list.blockSignals(True)
        self._cat_list.clear()

        # "All" entry
        total = sum(len(v) for v in data.values())
        all_item = QListWidgetItem(f"  🗠  All Findings  ({total})")
        all_item.setData(Qt.UserRole, "__all__")
        all_item.setFont(QFont("Segoe UI", 11, QFont.Bold))
        all_item.setForeground(QColor(COLOR_TEXT_BRIGHT))
        self._cat_list.addItem(all_item)

        # One row per category, sorted by priority
        sorted_cats = sorted(
            CATEGORIES.items(), key=lambda kv: kv[1][2]
        )
        for key, (name, icon, _) in sorted_cats:
            entries = data.get(key, [])
            if not entries:
                continue
            # Count by severity
            crits = sum(1 for e in entries if e.get("severity") == "CRITICAL")
            highs = sum(1 for e in entries if e.get("severity") == "HIGH")

            badge = ""
            if crits:
                badge = f"  Ⓒ{crits}"
            elif highs:
                badge = f"  Ⓗ{highs}"

            item = QListWidgetItem(f"  {icon}  {name}  ({len(entries)}){badge}")
            item.setData(Qt.UserRole, key)
            item.setFont(QFont("Segoe UI", 11))
            item.setForeground(QColor(COLOR_TEXT))
            self._cat_list.addItem(item)

        self._cat_list.blockSignals(False)

        # Restore selection
        for i in range(self._cat_list.count()):
            if self._cat_list.item(i).data(Qt.UserRole) == self._current_category:
                self._cat_list.setCurrentRow(i)
                return
        self._cat_list.setCurrentRow(0)

    def _on_category_changed(self, row: int):
        item = self._cat_list.item(row)
        if not item:
            return
        self._current_category = item.data(Qt.UserRole) or "__all__"
        if not self._project_dir:
            return
        data = RecordingManager.load(self._project_dir)
        self._load_category(data, self._current_category)

    def _load_category(self, data: Dict, category: str):
        if category == "__all__":
            flat: List[dict] = []
            for entries in data.values():
                flat.extend(entries)
        else:
            flat = data.get(category, [])

        # Sort: most severe first, then newest first
        from modules.analysis_recordings import _severity_order
        flat.sort(
            key=lambda e: (
                _severity_order(e.get("severity", "LOW")),
                -(datetime.fromisoformat(e["timestamp"]).timestamp()
                  if e.get("timestamp") else 0)
            )
        )
        self._all_entries = flat
        self._apply_filters()

    def _apply_filters(self):
        sev_show = {sev for sev, cb in self._sev_checks.items() if cb.isChecked()}
        query    = self._search.text().strip().lower()

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        for entry in self._all_entries:
            sev = entry.get("severity", "LOW").upper()
            if sev not in sev_show:
                continue

            if query:
                haystack = (
                    entry.get("url", "") + " " +
                    entry.get("parameter", "") + " " +
                    entry.get("detections", "") + " " +
                    entry.get("host", "")
                ).lower()
                if query not in haystack:
                    continue

            self._add_row(entry)

        self._table.setSortingEnabled(True)
        visible = self._table.rowCount()
        total   = len(self._all_entries)
        self._stats_bar.setText(
            f"  Showing {visible} / {total} entries"
            + (f"  ·  filtered by: {query}" if query else "")
        )

    def _add_row(self, entry: dict):
        sev    = entry.get("severity", "LOW").upper()
        method = entry.get("method", "GET").upper()
        status = entry.get("status", "")
        url    = entry.get("url", "")
        loc    = entry.get("location", "")
        param  = entry.get("parameter", "")
        detect = entry.get("detections", "")

        # Truncate detections for display
        det_display = (detect[:80] + "…") if len(detect) > 80 else detect

        row = self._table.rowCount()
        self._table.insertRow(row)

        def _item(text: str, align=Qt.AlignVCenter | Qt.AlignLeft) -> QTableWidgetItem:
            it = QTableWidgetItem(text)
            it.setTextAlignment(align)
            it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            return it

        # Method badge with color
        meth_item = _item(method, Qt.AlignCenter | Qt.AlignVCenter)
        meth_item.setForeground(QColor(METHOD_COLOR.get(method, COLOR_TEXT)))
        meth_item.setFont(QFont("Consolas", 10, QFont.Bold))

        # Status code with color
        stat_item = _item(str(status), Qt.AlignCenter | Qt.AlignVCenter)
        try:
            code = int(status)
            if code < 300:
                stat_item.setForeground(QColor(COLOR_SUCCESS))
            elif code < 400:
                stat_item.setForeground(QColor(COLOR_INFO))
            elif code < 500:
                stat_item.setForeground(QColor(COLOR_WARNING))
            else:
                stat_item.setForeground(QColor(COLOR_CRITICAL))
        except (ValueError, TypeError):
            pass

        # URL item — also stores the full entry for retrieval
        url_item = _item(url)
        url_item.setData(Qt.UserRole, entry)

        # Parameter item — color-coded by severity
        param_item = _item(param)
        sev_bg = SEV_COLOR.get(sev, ("#888", "#fff"))[0]
        param_item.setForeground(QColor(sev_bg))
        param_item.setFont(QFont("Consolas", 10, QFont.Bold))

        self._table.setItem(row, COL_METHOD,   meth_item)
        self._table.setItem(row, COL_STATUS,   stat_item)
        self._table.setItem(row, COL_URL,      url_item)
        self._table.setItem(row, COL_LOCATION, _item(loc))
        self._table.setItem(row, COL_PARAM,    param_item)
        self._table.setItem(row, COL_DETECT,   _item(det_display))

    def _update_stats(self, data: Dict):
        stats = RecordingManager.get_stats(
            self._project_dir or ""
        ) if self._project_dir else {"total": 0, "by_severity": {}}

        sev = stats.get("by_severity", {})
        parts = []
        for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = sev.get(s, 0)
            if n:
                parts.append(f"{SEV_ICON[s]} {s.title()}: {n}")

        total = stats.get("total", 0)
        cats  = stats.get("categories", 0)
        self._stats_bar.setText(
            f"  🞋  {total} findings  ·  "
            f"{cats} categories  ·  "
            + ("  ".join(parts) if parts else "No critical findings")
        )

    # ── Context menu & actions ────────────────────────────────────────────

    def _context_menu(self, pos):
        row_item = self._table.itemAt(pos)
        if not row_item:
            return
        row = row_item.row()
        entry = self._table.item(row, COL_URL).data(Qt.UserRole)
        if not entry:
            return

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background:{COLOR_CARD_BG}; color:{COLOR_TEXT}; border:1px solid {COLOR_BORDER}; padding:4px; }}
            QMenu::item {{ padding:6px 18px; border-radius:3px; }}
            QMenu::item:selected {{ background:{COLOR_ACCENT}; color:#fff; }}
            QMenu::separator {{ height:1px; background:{COLOR_BORDER}; margin:4px 0; }}
        """)

        detail_act   = menu.addAction("🗊  View Full Detail")
        history_act  = menu.addAction("🖳  Show in HTTP History")
        surface_act  = menu.addAction("🞋  Send to Attack Surface")
        menu.addSeparator()
        copy_url_act = menu.addAction("🗉  Copy URL")
        copy_par_act = menu.addAction("🗉  Copy Parameter")
        copy_det_act = menu.addAction("🗉  Copy Detections")
        menu.addSeparator()
        del_act      = menu.addAction("🗑  Delete This Entry")

        action = menu.exec_(self._table.viewport().mapToGlobal(pos))

        if action == detail_act:
            self._show_detail(entry)
        elif action == history_act:
            self._show_in_http_history(entry)
        elif action == surface_act:
            self._send_to_attack_surface(entry)
        elif action == copy_url_act:
            QApplication.clipboard().setText(entry.get("url", ""))
        elif action == copy_par_act:
            QApplication.clipboard().setText(entry.get("parameter", ""))
        elif action == copy_det_act:
            QApplication.clipboard().setText(entry.get("detections", ""))
        elif action == del_act:
            self._delete_entry(entry)

    def _open_detail(self, index):
        row   = index.row()
        entry = self._table.item(row, COL_URL).data(Qt.UserRole)
        if entry:
            self._show_detail(entry)

    def _show_detail(self, entry: dict):
        dlg = _DetailDialog(entry, self, show_in_history_cb=self._show_in_http_history)
        dlg.setStyleSheet(f"QDialog {{ background:{COLOR_BACKGROUND}; }}")
        dlg.exec_()

    def _delete_entry(self, entry: dict):
        if not self._project_dir:
            return
        reply = QMessageBox.question(
            self, "Delete Entry",
            f"Delete recorded entry for:\n{entry.get('url', '')}\n"
            f"Parameter: {entry.get('parameter', '')}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            RecordingManager.delete_entry(
                self._project_dir,
                entry.get("category", "other"),
                entry.get("id", "")
            )
            self._refresh()

    def _clear_category(self):
        if not self._project_dir:
            return
        cat  = self._current_category
        name = "All Findings" if cat == "__all__" else CATEGORIES.get(cat, ("Unknown",))[0]
        reply = QMessageBox.question(
            self, "Clear Category",
            f"Delete ALL entries in '{name}'?\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return
        if cat == "__all__":
            RecordingManager.clear_all(self._project_dir)
        else:
            RecordingManager.clear_category(self._project_dir, cat)
        self._refresh()

    # ── Export ────────────────────────────────────────────────────────────

    def _export(self):
        visible_entries = []
        for row in range(self._table.rowCount()):
            entry = self._table.item(row, COL_URL).data(Qt.UserRole)
            if entry:
                visible_entries.append(entry)

        if not visible_entries:
            QMessageBox.information(self, "Export", "No entries to export.")
            return

        path, _filter = QFileDialog.getSaveFileName(
            self, "Export Recordings",
            os.path.join(self._project_dir or "", "recordings_export"),
            "JSON Files (*.json);;CSV Files (*.csv)"
        )
        if not path:
            return

        try:
            if path.endswith(".csv"):
                with open(path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(
                        f,
                        fieldnames=["timestamp","severity","method","status",
                                    "host","url","location","parameter",
                                    "detections","category"]
                    )
                    writer.writeheader()
                    writer.writerows(visible_entries)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(visible_entries, f, indent=2, ensure_ascii=False)

            QMessageBox.information(
                self, "Export Complete",
                f"✓ Exported {len(visible_entries)} entries to:\n{path}"
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Error", str(exc))

    # ── HTTP History navigation ───────────────────────────────────────────

    def _show_in_http_history(self, entry: dict):
        """Switch to HTTP History tab and select the matching request."""
        try:
            parent_gui = self.mapping_tab.parent_gui
        except AttributeError:
            return

        tab_widget = getattr(parent_gui, 'tab_widget', None)
        if not tab_widget:
            return

        # Find and activate the HTTP History tab
        for i in range(tab_widget.count()):
            tab_text = tab_widget.tabText(i)
            if 'HTTP' in tab_text or 'History' in tab_text:
                tab_widget.setCurrentIndex(i)
                # Give UI time to fully switch before searching
                QTimer.singleShot(
                    120,
                    lambda e=entry: self._highlight_in_history(e)
                )
                return

    def _highlight_in_history(self, entry: dict):
        """Find and select the row in the HTTP History table that matches the entry."""
        try:
            parent_gui = self.mapping_tab.parent_gui
        except AttributeError:
            return

        # Locate the history table
        table = None
        for attr in ('history_table', 'table', 'findings_table',
                     'http_table', 'httpHistoryTable'):
            if hasattr(parent_gui, attr):
                table = getattr(parent_gui, attr)
                break

        if table is None:
            QMessageBox.warning(self, "Not Found", "HTTP History table not found.")
            return

        target_url    = entry.get("url", "")
        target_method = entry.get("method", "GET").upper()
        found_row     = -1

        # ── Determine method and URL columns from headers ─────────────────
        # Column 3 always holds the full URL in Qt.UserRole+2 regardless of
        # whether the table is in URL mode (header="URL") or Host/Path mode
        # (header="Host").  Prefer that stored value over displayed text so
        # both views work identically.
        method_col = -1
        url_col    = 3   # default: column 3 always carries the full URL data

        if hasattr(table, 'horizontalHeaderItem'):
            for col in range(table.columnCount()):
                hdr = table.horizontalHeaderItem(col)
                if hdr and 'method' in hdr.text().lower():
                    method_col = col
                    break

        # Fall back to the fixed layout (col 2 = Method)
        if method_col == -1:
            method_col = 2

        norm_target = self._normalize_url(target_url)

        def _get_row_url(r: int) -> str:
            item = table.item(r, url_col)
            if item is None:
                return ""
            # UserRole+2 stores the full URL in both Host/Path and URL views
            full_url = item.data(Qt.UserRole + 2)
            return full_url if full_url else item.text()

        for row in range(table.rowCount()):
            if table.isRowHidden(row):
                continue

            url_match = self._normalize_url(_get_row_url(row)) == norm_target
            method_match = False

            if 0 <= method_col < table.columnCount():
                item = table.item(row, method_col)
                if item and item.text().upper() == target_method:
                    method_match = True

            if url_match and method_match:
                found_row = row
                break

        # ── Also search hidden rows if not found in visible ones ──────────
        if found_row == -1:
            for row in range(table.rowCount()):
                if not table.isRowHidden(row):
                    continue
                url_match    = self._normalize_url(_get_row_url(row)) == norm_target
                method_match = False
                if 0 <= method_col < table.columnCount():
                    item = table.item(row, method_col)
                    if item and item.text().upper() == target_method:
                        method_match = True
                if url_match and method_match:
                    table.setRowHidden(row, False)
                    found_row = row
                    break

        if found_row >= 0:
            table.selectRow(found_row)
            table.scrollToItem(table.item(found_row, 0))
            self._flash_row(table, found_row)
        else:
            QMessageBox.information(
                self,
                "Not Found",
                f"Could not find this request in HTTP History.\n\n"
                f"Method: {target_method}\nURL: {target_url}"
            )

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Normalize URL for comparison — sort query params, strip trailing slash."""
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_q = "&".join(
                    f"{k}={v[0]}"
                    for k in sorted(params)
                    for v in [params[k]]
                )
                query = f"?{sorted_q}"
            else:
                query = ""
            path = parsed.path.rstrip("/") or "/"
            return f"{parsed.scheme}://{parsed.netloc}{path}{query}"
        except Exception:
            return url.strip()

    def _send_to_attack_surface(self, entry: dict):
        """Send a recorded finding to the Attack Surface tab."""
        try:
            mw = self.mapping_tab.parent_gui
        except AttributeError:
            return
        as_tab = getattr(mw, 'attack_surface_tab', None)
        if as_tab is None:
            QMessageBox.warning(self, "Not Available", "Attack Surface tab not found.")
            return
        finding = {
            'url':          entry.get('url', ''),
            'method':       entry.get('method', 'GET'),
            'status':       entry.get('status', ''),
            'request_file': entry.get('request_file', ''),
            'response_file': entry.get('response_file', ''),
        }
        as_tab.add_from_http_history(finding)
        tab_widget = getattr(mw, 'tab_widget', None)
        if tab_widget:
            for i in range(tab_widget.count()):
                if "Attack Surface" in tab_widget.tabText(i):
                    tab_widget.setCurrentIndex(i)
                    break

    def _flash_row(self, table, row: int):
        """Briefly highlight a row in the history table to draw attention."""
        original = []
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item:
                original.append((col, item.background()))

        flash = QColor(COLOR_ACCENT)
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item:
                item.setBackground(flash)

        def _restore():
            for col, bg in original:
                item = table.item(row, col)
                if item:
                    item.setBackground(bg)

        QTimer.singleShot(1500, _restore)

    # ── Called when sub-tab becomes visible ───────────────────────────────

    def on_tab_shown(self):
        """Refresh data every time the user switches to this tab."""
        # Re-sync project dir in case user opened a different project since last visit
        try:
            pp = self.mapping_tab.parent_gui._project_paths
            if pp and pp.get("project_dir") and pp["project_dir"] != self._project_dir:
                self._project_dir = pp["project_dir"]
                self._poll_timer.stop()
        except AttributeError:
            pass
        self._refresh()