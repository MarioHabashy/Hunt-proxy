"""
ws_history_tab.py – WebSocket History Tab for Hunt GUI

Monitors a JSONL file written by hunt_addon.py (websocket_message hook) and
displays every captured WebSocket message in a table.

Layout:
  ┌─ toolbar ─────────────────────────────────────────────────────────────────┐
  │  Filter  [search]  Direction [All/↑/↓]  Type [All/text/binary]  [Clear]  │
  ├─ table ────────────────────────────────────────────────────────────────────┤
  │  # | Time | Host | Path | Direction | Type | Length | Preview             │
  ├─ detail panel ─────────────────────────────────────────────────────────────┤
  │  Full message payload (selectable, monospace)                             │
  └────────────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import json
import os
import time
import threading
import logging
from typing import List, Dict, Any, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTableWidget,
    QTableWidgetItem, QHeaderView, QTextEdit, QLineEdit, QComboBox,
    QPushButton, QLabel, QFrame, QMenu, QApplication, QAction,
    QInputDialog, QColorDialog, QMessageBox, QStyledItemDelegate,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QColor, QFont, QBrush, QTextCursor, QPalette

from modules.constants import (
    COLOR_DARK_BG, COLOR_ELEVATED_BG, COLOR_BORDER, COLOR_TEXT,
    COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED, COLOR_ACCENT, COLOR_HOVER,
    COLOR_SUCCESS, COLOR_HIGH, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
    COLOR_CARD_BG,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Background file-monitor thread
# ─────────────────────────────────────────────────────────────────────────────

class WSMonitorThread(QThread):
    """Tails hunt_ws.jsonl and emits one signal per new message."""

    new_message = pyqtSignal(dict)

    def __init__(self, jsonl_path: str = ""):
        super().__init__()
        self._running = True
        self._jsonl_path = jsonl_path or "/tmp/hunt_ws.jsonl"
        self._last_pos = 0

    def set_path(self, path: str):
        self._jsonl_path = path
        self._last_pos = 0

    def run(self):
        # Load any existing entries on startup then tail for new ones
        if os.path.exists(self._jsonl_path):
            self._load_existing()

        while self._running:
            try:
                if os.path.exists(self._jsonl_path):
                    with open(self._jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(self._last_pos)
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                self.new_message.emit(entry)
                            except json.JSONDecodeError:
                                pass
                        self._last_pos = f.tell()
            except Exception as e:
                logger.error(f"WS monitor error: {e}")
            time.sleep(1)

    def _load_existing(self):
        try:
            with open(self._jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        self.new_message.emit(entry)
                    except json.JSONDecodeError:
                        pass
                self._last_pos = f.tell()
        except Exception as e:
            logger.error(f"WS load_existing error: {e}")

    def stop(self):
        self._running = False


# ─────────────────────────────────────────────────────────────────────────────
# Numeric sort item
# ─────────────────────────────────────────────────────────────────────────────

class _NumItem(QTableWidgetItem):
    def __init__(self, text: str, value: float):
        super().__init__(text)
        self._v = value

    def __lt__(self, other):
        if isinstance(other, _NumItem):
            return self._v < other._v
        return super().__lt__(other)


# ─────────────────────────────────────────────────────────────────────────────
# Highlight delegate – makes setBackground() work even under QSS stylesheets
# ─────────────────────────────────────────────────────────────────────────────

class _HighlightDelegate(QStyledItemDelegate):
    """
    When a QSS stylesheet is applied to a QTableWidget, Qt's style engine
    ignores Qt.BackgroundRole on individual items.  This delegate patches
    option.palette.Base / AlternateBase to force our highlight colour
    through to the final paint step.
    """
    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        bg = index.data(Qt.BackgroundRole)
        if bg and isinstance(bg, QBrush) and bg.color().isValid() and bg.color().alpha() > 0:
            option.backgroundBrush = bg
            pal = QPalette(option.palette)
            c = bg.color()
            pal.setColor(QPalette.All, QPalette.Base,          c)
            pal.setColor(QPalette.All, QPalette.AlternateBase, c)
            pal.setColor(QPalette.All, QPalette.Window,        c)
            option.palette = pal


# ─────────────────────────────────────────────────────────────────────────────
# Main widget
# ─────────────────────────────────────────────────────────────────────────────

class WSHistoryTab(QWidget):
    """
    WebSocket History tab.

    Automatically starts/stops monitoring based on the path set via
    set_ws_jsonl_path().  The parent (HuntGUI) calls this method
    after building proxy env vars so the path is always project-specific.
    """

    # Emitted the very first time a WS message is captured so the parent
    # can make the tab visible in the tab-bar.
    first_message_captured = pyqtSignal()

    COL_NUM  = 0
    COL_TIME = 1
    COL_HOST = 2
    COL_PATH = 3
    COL_DIR  = 4
    COL_TYPE = 5
    COL_LEN  = 6
    COL_PRE  = 7
    COL_NOTE = 8

    _DIR_COLORS = {
        "client→server": "#61dafb",   # blue  – outgoing
        "server→client": "#98c379",   # green – incoming
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._messages: List[Dict[str, Any]] = []   # master list (unfiltered)
        self._visible_rows: List[int] = []           # indices into _messages
        self._monitor: Optional[WSMonitorThread] = None
        self._first_emitted = False
        self._ws_jsonl_path = ""
        # Per-message highlight colours and notes keyed by message index
        self._highlights: Dict[int, str]  = {}   # msg_index -> hex color
        self._notes:      Dict[int, str]  = {}   # msg_index -> note text
        # Track which table row maps back to which message index
        self._row_to_msg_idx: List[int]   = []
        # For comparer: accumulate selected rows
        self._comparer_selection: List[int] = []

        self._build_ui()
        self._apply_style()

    # ── Public API ────────────────────────────────────────────────────────

    def set_ws_jsonl_path(self, path: str):
        """Set the WS JSONL file path and (re)start the monitor thread."""
        if path == self._ws_jsonl_path:
            return
        self._ws_jsonl_path = path

        # Stop old monitor if running
        if self._monitor and self._monitor.isRunning():
            self._monitor.stop()
            self._monitor.wait(2000)

        self._monitor = WSMonitorThread(path)
        self._monitor.new_message.connect(self._on_new_message)
        self._monitor.start()

    def stop_monitor(self):
        if self._monitor and self._monitor.isRunning():
            self._monitor.stop()
            self._monitor.wait(2000)

    # ── UI construction ───────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setMaximumHeight(42)
        tb_lay = QHBoxLayout(toolbar)
        tb_lay.setContentsMargins(8, 4, 8, 4)
        tb_lay.setSpacing(8)

        tb_lay.addWidget(QLabel("🔍"))
        self._search = QLineEdit()
        self._search.setPlaceholderText("Filter by host, path, or payload…")
        self._search.setMinimumWidth(180)
        self._search.setMaximumWidth(420)
        self._search.textChanged.connect(self._apply_filter)
        tb_lay.addWidget(self._search)

        tb_lay.addWidget(self._vsep())

        tb_lay.addWidget(QLabel("Direction:"))
        self._dir_combo = QComboBox()
        self._dir_combo.addItems(["All", "↑ client→server", "↓ server→client"])
        self._dir_combo.setMinimumWidth(160)
        self._dir_combo.currentTextChanged.connect(self._apply_filter)
        tb_lay.addWidget(self._dir_combo)

        tb_lay.addWidget(self._vsep())

        tb_lay.addWidget(QLabel("Type:"))
        self._type_combo = QComboBox()
        self._type_combo.addItems(["All", "text", "binary"])
        self._type_combo.setMinimumWidth(80)
        self._type_combo.currentTextChanged.connect(self._apply_filter)
        tb_lay.addWidget(self._type_combo)

        tb_lay.addWidget(self._vsep())

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.setToolTip("Clear all captured WebSocket messages from the view")
        clear_btn.clicked.connect(self._clear)
        tb_lay.addWidget(clear_btn)

        tb_lay.addStretch()

        self._status_lbl = QLabel("No WebSocket traffic captured yet")
        self._status_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        tb_lay.addWidget(self._status_lbl)

        root.addWidget(toolbar)

        # ── Splitter: table (top) + detail (bottom) ───────────────────────
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(4)
        splitter.setChildrenCollapsible(False)
        splitter.setStyleSheet(
            f"QSplitter::handle:vertical {{ background-color: {COLOR_BORDER}; }}"
            f"QSplitter::handle:vertical:hover {{ background-color: {COLOR_ACCENT}; }}"
        )

        # ── Message table ─────────────────────────────────────────────────
        self._table = QTableWidget()
        self._table.setColumnCount(9)
        self._table.setHorizontalHeaderLabels(
            ["#", "Time", "Host", "Path", "Direction", "Type", "Length", "Preview", "Note"]
        )
        self._table.setAlternatingRowColors(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().hide()
        self._table.verticalHeader().setDefaultSectionSize(24)
        self._table.setSortingEnabled(False)
        self._table.setContextMenuPolicy(Qt.CustomContextMenu)
        self._table.customContextMenuRequested.connect(self._show_context_menu)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        # Delegate ensures setBackground() is visible even with an active QSS
        self._table.setItemDelegate(_HighlightDelegate(self._table))

        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.resizeSection(self.COL_NUM,  45)
        hdr.resizeSection(self.COL_TIME, 85)
        hdr.resizeSection(self.COL_HOST, 180)
        hdr.resizeSection(self.COL_PATH, 200)
        hdr.resizeSection(self.COL_DIR,  140)
        hdr.resizeSection(self.COL_TYPE, 60)
        hdr.resizeSection(self.COL_LEN,  75)
        hdr.setSectionResizeMode(self.COL_PRE, QHeaderView.Stretch)
        hdr.resizeSection(self.COL_NOTE, 160)
        hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hdr.sectionClicked.connect(self._on_header_clicked)
        hdr.setSortIndicatorShown(True)
        hdr.setSortIndicator(self.COL_NUM, Qt.AscendingOrder)
        self._sort_col   = self.COL_NUM
        self._sort_order = Qt.AscendingOrder

        splitter.addWidget(self._table)

        # ── Detail panel ──────────────────────────────────────────────────
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setSpacing(0)

        detail_hdr = QWidget()
        detail_hdr.setMaximumHeight(30)
        detail_hdr.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};"
        )
        dh_lay = QHBoxLayout(detail_hdr)
        dh_lay.setContentsMargins(8, 3, 8, 3)
        self._detail_title = QLabel("🖅 WebSocket Message")
        self._detail_title.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-weight: 700; font-size: 11px;"
        )
        dh_lay.addWidget(self._detail_title)

        copy_btn = QPushButton("🗉 Copy")
        copy_btn.setMaximumWidth(60)
        copy_btn.setToolTip("Copy message payload to clipboard")
        copy_btn.clicked.connect(self._copy_payload)
        dh_lay.addStretch()
        dh_lay.addWidget(copy_btn)

        # Note button in detail header
        note_btn = QPushButton("🗈 Note")
        note_btn.setMaximumWidth(60)
        note_btn.setToolTip("Add / edit note for this message")
        note_btn.clicked.connect(self._add_note_current)
        dh_lay.addWidget(note_btn)

        detail_layout.addWidget(detail_hdr)

        self._detail_text = QTextEdit()
        self._detail_text.setReadOnly(True)
        self._detail_text.setFont(QFont("Consolas", 10))
        self._detail_text.setLineWrapMode(QTextEdit.WidgetWidth)
        detail_layout.addWidget(self._detail_text)

        splitter.addWidget(detail_widget)
        splitter.setSizes([320, 200])
        root.addWidget(splitter)

    @staticmethod
    def _vsep() -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"background-color: {COLOR_BORDER};")
        return sep

    def _apply_style(self):
        self.setStyleSheet(
            f"""
            QWidget {{ background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT}; }}
            QLabel  {{ color: {COLOR_TEXT}; }}
            QTableWidget {{
                background-color: {COLOR_DARK_BG};

                gridline-color: {COLOR_BORDER};
                border: none;
                color: {COLOR_TEXT};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                selection-background-color: {COLOR_ACCENT};
                selection-color: #ffffff;
                outline: none;
            }}
            QTableWidget::item {{
                padding: 2px 6px;
                border: none;
                border-bottom: 1px solid #2a2a2a;
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: #ffffff;
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 4px 8px;
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 2px solid {COLOR_ACCENT};
                font-weight: bold;
                font-size: 12px;
            }}
            QToolBar, QWidget#toolbar {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            QLineEdit {{
                background-color: #3a3a3a;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                color: {COLOR_TEXT_BRIGHT};
                padding: 3px 6px;
            }}
            QComboBox {{
                background-color: #3a3a3a;
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                color: {COLOR_TEXT_BRIGHT};
                padding: 2px 6px;
            }}
            QComboBox::drop-down {{ border: none; }}
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                padding: 3px 10px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: {COLOR_HOVER}; }}
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                border: none;
                color: {COLOR_TEXT};
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
            }}
            QSplitter::handle:vertical {{ background-color: {COLOR_BORDER}; }}
        """
        )

    # ── Slot: new WS message from monitor ────────────────────────────────

    def _on_new_message(self, entry: Dict[str, Any]):
        self._messages.append(entry)
        idx = len(self._messages) - 1

        if not self._first_emitted:
            self._first_emitted = True
            self.first_message_captured.emit()

        if self._matches_filter(entry):
            self._visible_rows.append(idx)
            self._insert_table_row(entry, len(self._visible_rows))

        self._status_lbl.setText(
            f"{len(self._messages)} message{'s' if len(self._messages) != 1 else ''} captured"
        )

    # ── Table helpers ─────────────────────────────────────────────────────

    def _insert_table_row(self, entry: Dict[str, Any], seq: int):
        row = self._table.rowCount()
        self._table.insertRow(row)

        direction = entry.get("direction", "")
        opcode    = entry.get("opcode", "text")
        length    = entry.get("length", 0)
        payload   = entry.get("payload", "")
        preview   = payload[:120].replace("\n", " ").replace("\r", "")

        # Direction arrow label
        dir_label = "↑ client→server" if direction.startswith("client") else "↓ server→client"
        dir_color = self._DIR_COLORS.get(direction, COLOR_TEXT_MUTED)

        # Determine message index (position in self._messages)
        msg_idx = len(self._messages) - 1
        for i, m in enumerate(self._messages):
            if m is entry:
                msg_idx = i
                break

        note_text  = self._notes.get(msg_idx, "")
        row_color  = self._highlights.get(msg_idx, "")

        items = [
            _NumItem(str(seq), seq),
            QTableWidgetItem(entry.get("timestamp", "").split("T")[-1]),
            QTableWidgetItem(entry.get("host", "")),
            QTableWidgetItem(entry.get("path", "/")),
            QTableWidgetItem(dir_label),
            QTableWidgetItem(opcode),
            _NumItem(self._fmt_size(length), length),
            QTableWidgetItem(preview),
            QTableWidgetItem(note_text),
        ]

        # Alternating row colours handled manually (QSS alt-bg overrides setBackground)
        alt_color = "#232323" if row % 2 == 0 else "#1c1c1c"
        default_bg = QBrush(QColor(row_color if row_color else alt_color))

        for col, item in enumerate(items):
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            if col == self.COL_DIR:
                item.setForeground(QBrush(QColor(dir_color)))
                item.setFont(QFont("Consolas", 10, QFont.Bold))
            elif col == self.COL_TYPE:
                clr = "#bd93f9" if opcode == "binary" else "#50fa7b"
                item.setForeground(QBrush(QColor(clr)))
            elif col == self.COL_NOTE:
                item.setForeground(QBrush(QColor("#f1fa8c")))
            item.setBackground(default_bg)
            self._table.setItem(row, col, item)

        # Store full entry + msg_idx on the row
        self._table.item(row, 0).setData(Qt.UserRole, entry)
        self._table.item(row, 0).setData(Qt.UserRole + 1, msg_idx)
        self._row_to_msg_idx.append(msg_idx)

    @staticmethod
    def _fmt_size(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n/1024:.1f} KB"
        return f"{n/1024/1024:.1f} MB"

    # ── Filter logic ──────────────────────────────────────────────────────

    def _matches_filter(self, entry: Dict[str, Any]) -> bool:
        text     = self._search.text().lower()
        dir_flt  = self._dir_combo.currentText()
        type_flt = self._type_combo.currentText()

        if dir_flt == "↑ client→server" and not entry.get("direction", "").startswith("client"):
            return False
        if dir_flt == "↓ server→client" and "server→" not in entry.get("direction", ""):
            return False
        if type_flt != "All" and entry.get("opcode", "text") != type_flt:
            return False
        if text and text not in (
            entry.get("host", "").lower() +
            entry.get("path", "").lower() +
            entry.get("payload", "").lower()
        ):
            return False
        return True

    def _apply_filter(self):
        self._table.setRowCount(0)
        self._visible_rows = []
        self._row_to_msg_idx = []
        seq = 0
        for i, entry in enumerate(self._messages):
            if self._matches_filter(entry):
                self._visible_rows.append(i)
                seq += 1
                self._insert_table_row(entry, seq)
        self._on_row_selected()

    # ── Detail panel ──────────────────────────────────────────────────────

    def _on_row_selected(self):
        rows = self._table.selectedItems()
        if not rows:
            return
        row = self._table.currentRow()
        first_item = self._table.item(row, 0)
        if not first_item:
            return
        entry = first_item.data(Qt.UserRole)
        if not entry:
            return

        direction = entry.get("direction", "")
        opcode    = entry.get("opcode", "text")
        host      = entry.get("host", "")
        path      = entry.get("path", "/")
        length    = entry.get("length", 0)
        payload   = entry.get("payload", "")

        arrow = "↑" if direction.startswith("client") else "↓"
        self._detail_title.setText(
            f"🖅 {arrow} {host}{path}  [{opcode}  {self._fmt_size(length)}]"
        )

        if opcode == "text":
            # Pretty-print JSON if possible
            try:
                parsed = json.loads(payload)
                display = json.dumps(parsed, indent=2, ensure_ascii=False)
            except Exception:
                display = payload
        else:
            # Binary data: show hex dump
            try:
                raw_bytes = bytes.fromhex(payload)
                display = self._hex_dump(raw_bytes)
            except Exception:
                display = payload

        self._detail_text.setPlainText(display)

    @staticmethod
    def _hex_dump(data: bytes, width: int = 16) -> str:
        lines = []
        for i in range(0, len(data), width):
            chunk = data[i:i + width]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hex_part:<{width*3}}  |{asc_part}|")
        return "\n".join(lines)

    # ── Sorting ───────────────────────────────────────────────────────────

    def _on_header_clicked(self, col: int):
        if self._sort_col == col:
            self._sort_order = (
                Qt.DescendingOrder if self._sort_order == Qt.AscendingOrder
                else Qt.AscendingOrder
            )
        else:
            self._sort_col   = col
            self._sort_order = Qt.AscendingOrder

        self._table.horizontalHeader().setSortIndicator(self._sort_col, self._sort_order)
        self._table.sortItems(self._sort_col, self._sort_order)

    # ── Context menu ──────────────────────────────────────────────────────

    def _show_context_menu(self, pos):
        row = self._table.rowAt(pos.y())
        if row < 0:
            return
        first_item = self._table.item(row, 0)
        if not first_item:
            return
        entry = first_item.data(Qt.UserRole)
        if not entry:
            return
        msg_idx = first_item.data(Qt.UserRole + 1)

        menu = QMenu(self)

        # ── Copy actions
        cp_payload = menu.addAction("🗉 Copy payload")
        cp_host    = menu.addAction("🗉 Copy host")
        cp_url     = menu.addAction("🗉 Copy URL")
        menu.addSeparator()
        cp_all     = menu.addAction("🗉 Copy all as JSON")
        menu.addSeparator()

        # ── Send to tools
        rpt_act  = menu.addAction("➣ Send to Repeater")
        cmp_act  = menu.addAction("➣ Send to Comparer")
        menu.addSeparator()

        # ── Highlight
        hl_menu = menu.addMenu(" Highlight row")
        hl_colors = [
            ("Red",    "#5a1e1e"),
            ("Orange", "#4a2e10"),
            ("Yellow", "#3a3a10"),
            ("Green",  "#1a3a1e"),
            ("Blue",   "#1a2a4a"),
            ("Purple", "#2e1a4a"),
            ("None",   ""),
        ]
        hl_actions = []
        for label, color in hl_colors:
            a = hl_menu.addAction(label)
            hl_actions.append((a, color))

        # Custom colour
        custom_hl = hl_menu.addAction("✨ Custom colour…")
        menu.addSeparator()

        # ── Note
        note_act = menu.addAction("🗈 Add / edit note")

        action = menu.exec_(self._table.viewport().mapToGlobal(pos))

        if action == cp_payload:
            QApplication.clipboard().setText(entry.get("payload", ""))
        elif action == cp_host:
            QApplication.clipboard().setText(entry.get("host", ""))
        elif action == cp_url:
            QApplication.clipboard().setText(entry.get("url", ""))
        elif action == cp_all:
            QApplication.clipboard().setText(json.dumps(entry, indent=2, ensure_ascii=False))
        elif action == rpt_act:
            self._send_to_repeater(entry)
        elif action == cmp_act:
            self._send_to_comparer(entry, msg_idx)
        elif action == note_act:
            self._add_note_for(msg_idx, row)
        elif action == custom_hl:
            self._pick_custom_highlight(msg_idx, row)
        else:
            for (a, color) in hl_actions:
                if action == a:
                    self._set_row_highlight(msg_idx, row, color)
                    break

    def _copy_payload(self):
        row = self._table.currentRow()
        if row < 0:
            return
        first_item = self._table.item(row, 0)
        if not first_item:
            return
        entry = first_item.data(Qt.UserRole)
        if entry:
            QApplication.clipboard().setText(entry.get("payload", ""))

    # ── Clear ─────────────────────────────────────────────────────────────

    def _clear(self):
        self._messages.clear()
        self._visible_rows.clear()
        self._row_to_msg_idx.clear()
        self._highlights.clear()
        self._notes.clear()
        self._comparer_selection.clear()
        self._table.setRowCount(0)
        self._detail_text.clear()
        self._detail_title.setText("🖅 WebSocket Message")
        self._status_lbl.setText("No WebSocket traffic captured yet")

    # ── Send to Repeater (WS Sender tab in Repeater) ─────────────────────────────────

    def _send_to_repeater(self, entry: Dict[str, Any]):
        """Open a WebSocket sender tab inside the Repeater tab."""
        import urllib.parse as _up
        main_win = self.window()
        if not hasattr(main_win, "repeater_tab"):
            return

        url       = entry.get("url", "")
        payload   = entry.get("payload", "")
        opcode    = entry.get("opcode", "text")
        direction = entry.get("direction", "")
        host      = entry.get("host", "")

        # Pass original captured headers (Cookie, Origin, etc.) so the repeater
        # can replay the request in the same authenticated session.
        # IMPORTANT: strip WebSocket protocol-level headers that websocket-client
        # manages internally — sending them again causes:
        #   {"error":"Duplicate header names are not allowed"}
        _WS_INTERNAL = {
            "upgrade", "connection", "host",
            "sec-websocket-key", "sec-websocket-version",
            "sec-websocket-extensions", "sec-websocket-protocol",
        }
        raw_hdrs = entry.get("headers", {})
        if isinstance(raw_hdrs, list):
            # Handle ["Key: Value", ...] list format
            extra_headers: dict = {}
            for item in raw_hdrs:
                if ":" in item:
                    k, _, v = item.partition(":")
                    k = k.strip()
                    if k.lower() not in _WS_INTERNAL:
                        extra_headers[k] = v.strip()
        elif isinstance(raw_hdrs, dict):
            extra_headers = {
                k: v for k, v in raw_hdrs.items()
                if k.lower() not in _WS_INTERNAL
            }
        else:
            extra_headers = {}

        parsed   = _up.urlparse(url.replace("wss://", "https://").replace("ws://", "http://"))
        tab_name = f"{direction[:1].upper()} {host}{parsed.path or '/'}"

        main_win.repeater_tab.add_ws_request(
            url, payload, opcode, tab_name=tab_name, extra_headers=extra_headers
        )
        # Switch to Repeater tab
        tw = main_win.tab_widget
        for i in range(tw.count()):
            if tw.tabText(i).strip() == "Repeater":
                tw.setCurrentIndex(i)
                break

    # ── Send to Comparer ────────────────────────────────────────────────────────

    def _send_to_comparer(self, entry: Dict[str, Any], msg_idx: int):
        """Buffer selected payloads; when 2 are selected, send both to Comparer."""
        main_win = self.window()
        # add_comparison is a mixin method directly on the main window
        if not hasattr(main_win, "add_comparison"):
            self._status_lbl.setText("⚠ Comparer not available")
            return

        # Add to selection buffer (avoid duplicates)
        if msg_idx in self._comparer_selection:
            self._comparer_selection.remove(msg_idx)
        self._comparer_selection.append(msg_idx)

        if len(self._comparer_selection) == 1:
            self._status_lbl.setText(
                "⽐ Comparer: 1st message queued – right-click another row to compare"
            )
            return

        # Two items ready – send to comparer
        idx_a = self._comparer_selection[-2]
        idx_b = self._comparer_selection[-1]
        e_a   = self._messages[idx_a]
        e_b   = self._messages[idx_b]

        pay_a = e_a.get("payload", "")
        pay_b = e_b.get("payload", "")

        def _pretty(p):
            try:
                return json.dumps(json.loads(p), indent=2, ensure_ascii=False)
            except Exception:
                return p

        pay_a = _pretty(pay_a)
        pay_b = _pretty(pay_b)

        name = f"WS #{idx_a+1} vs #{idx_b+1}"
        main_win.add_comparison(name, pay_a, pay_b, "text")
        self._comparer_selection.clear()
        self._status_lbl.setText(f"➣ Sent to Comparer: {name}")
        if hasattr(main_win, "flash_tab"):
            main_win.flash_tab("Comparer")

    # ── Highlight ──────────────────────────────────────────────────────────────────

    def _set_row_highlight(self, msg_idx: int, row: int, color: str):
        """Apply (or clear) a background colour to every cell in the given table row."""
        if not color:
            self._highlights.pop(msg_idx, None)
            # Restore default alternating colour
            alt_color = "#232323" if row % 2 == 0 else "#1c1c1c"
            bg = QBrush(QColor(alt_color))
        else:
            self._highlights[msg_idx] = color
            bg = QBrush(QColor(color))

        for col in range(self._table.columnCount()):
            item = self._table.item(row, col)
            if item:
                item.setBackground(bg)

        self._table.viewport().update()

    def _pick_custom_highlight(self, msg_idx: int, row: int):
        init = QColor(self._highlights.get(msg_idx, "#3a3a10"))
        color = QColorDialog.getColor(init, self, "Pick row highlight colour")
        if color.isValid():
            self._set_row_highlight(msg_idx, row, color.name())

    # ── Notes ───────────────────────────────────────────────────────────────────────

    def _add_note_current(self):
        """Called from the detail-panel Note button."""
        row = self._table.currentRow()
        if row < 0:
            return
        first_item = self._table.item(row, 0)
        if not first_item:
            return
        msg_idx = first_item.data(Qt.UserRole + 1)
        if msg_idx is None:
            return
        self._add_note_for(msg_idx, row)

    def _add_note_for(self, msg_idx: int, row: int):
        existing = self._notes.get(msg_idx, "")
        text, ok = QInputDialog.getMultiLineText(
            self, "Add / Edit Note",
            f"Note for message #{msg_idx + 1}:",
            existing
        )
        if not ok:
            return
        if text.strip():
            self._notes[msg_idx] = text.strip()
        else:
            self._notes.pop(msg_idx, None)

        # Update the Note cell in the table
        note_item = self._table.item(row, self.COL_NOTE)
        if note_item:
            note_item.setText(text.strip())
            note_item.setToolTip(text.strip())