import os
import json
import re
import threading
import time
import logging
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit, QComboBox, QPushButton,
    QLabel, QFrame, QSplitter, QTabWidget, QStyle, QMessageBox, QMenu,
    QHeaderView, QStyledItemDelegate, QApplication, QAction, QCheckBox, QShortcut,
    QTreeWidgetItemIterator, QScrollArea, QStackedWidget, QSizePolicy, QDialog
)
from PyQt5.QtCore import (
    QThread, Qt, pyqtSignal, QTimer, QRect, QEvent
)
from PyQt5.QtGui import (
    QColor, QFont, QPen, QBrush, QTextCursor, QTextCharFormat, QTextDocument, QKeySequence
)
from modules.analysis_tab import AnalysisTabMixin, AIChatPanel as _AIChatPanel, _AI_TRAFFIC_AVAILABLE as _AI_TRAFFIC_AVAILABLE
from . import project_manager as pm
from modules.inspector_card import _InspectorCard, analyze_selection as _analyze_selection_shared

from modules.constants import (
    HUNT_JSONL,
    COLOR_ELEVATED_BG, COLOR_URL_BASE_SELECTED, COLOR_URL_PARAM_SELECTED,
    COLOR_URL_BASE, COLOR_URL_PARAM, COLOR_DARK_BG, COLOR_TEXT,
    COLOR_TEXT_BRIGHT, COLOR_BORDER, COLOR_ACCENT, COLOR_HOVER,
    COLOR_SUCCESS, COLOR_MEDIUM, COLOR_HIGH, COLOR_CRITICAL, COLOR_LOW,
    COLOR_TEXT_MUTED, COLOR_CARD_BG, COLOR_ACCENT_SECONDARY,
    FONT_SIZE_NORMAL, FONT_SIZE_SMALL, FONT_SIZE_LARGE,
    SitemapIcons, VulnerabilityCategories, HTTPFormatter, HttpSyntaxHighlighter,
    GQLSyntaxHighlighter, JSONSyntaxHighlighter
)

logger = logging.getLogger(__name__)


def _pretty_response(resp_text: str) -> str:
    """Pretty-print a JSON body in an HTTP response string."""
    sep = "\r\n\r\n" if "\r\n\r\n" in resp_text else "\n\n"
    if sep not in resp_text:
        return resp_text
    headers_part, body_part = resp_text.split(sep, 1)
    try:
        stripped = body_part.strip()
        if stripped.startswith(("{", "[")):
            return headers_part + sep + json.dumps(json.loads(stripped), indent=2)
    except Exception:
        pass
    return resp_text


def _pretty_request(req_text: str) -> str:
    """Pretty-print a JSON body in an HTTP request string and update Content-Length."""
    sep = "\r\n\r\n" if "\r\n\r\n" in req_text else "\n\n"
    if sep not in req_text:
        return req_text
    headers_part, body_part = req_text.split(sep, 1)
    try:
        stripped = body_part.strip()
        if stripped.startswith(("{", "[")):
            pretty_body = json.dumps(json.loads(stripped), indent=2)
            new_len = len(pretty_body.encode("utf-8"))
            headers_part = re.sub(
                r'(?im)^(content-length:\s*)(\d+)',
                lambda m: m.group(1) + str(new_len),
                headers_part,
            )
            return headers_part + sep + pretty_body
    except Exception:
        pass
    return req_text


class FileMonitorThread(QThread):
    # Use new_findings (plural) for live batches so the main thread is only
    # woken once per poll cycle regardless of how many requests arrived.
    new_findings = pyqtSignal(list)   # list[dict] – live batch
    new_finding  = pyqtSignal(dict)   # kept for backward-compat; not used internally
    stats_update = pyqtSignal(dict)
    load_progress = pyqtSignal(int, int, str)
    load_complete = pyqtSignal(int)
    batch_loaded = pyqtSignal(list)

    def __init__(self, jsonl_path: str = ""):
        super().__init__()
        self.running = True
        self.last_position = 0
        self.stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        self._lock = threading.Lock()
        self.batch_size = 500
        self.all_findings = []
        self._jsonl_path = jsonl_path if jsonl_path else HUNT_JSONL
        # Maximum findings emitted in one live-batch signal; limits main-thread work
        self._live_batch_cap = 50

    def run(self):
        if os.path.exists(self._jsonl_path):
            self._load_existing_data_fast()

        while self.running:
            try:
                if os.path.exists(self._jsonl_path):
                    with open(self._jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()

                        if new_lines:
                            live_batch = []
                            for line in new_lines:
                                if line.strip():
                                    finding = self._parse_line(line)
                                    if finding is not None:
                                        live_batch.append(finding)

                            if live_batch:
                                # Emit in capped sub-batches so the main thread
                                # is never handed thousands of rows at once.
                                for i in range(0, len(live_batch), self._live_batch_cap):
                                    self.new_findings.emit(live_batch[i:i + self._live_batch_cap])

                            self.last_position = f.tell()

                            with self._lock:
                                self.stats_update.emit(self.stats.copy())

                time.sleep(1)

            except IOError as e:
                logger.error(f"Monitor I/O error: {e}")
                time.sleep(5)
            except Exception as e:
                logger.error(f"Monitor error: {e}")
                time.sleep(5)

    def _load_existing_data_fast(self):
        try:
            import time
            start_time = time.time()

            self.load_progress.emit(0, 0, "𝍸 Counting findings...")
            QThread.msleep(10)

            total_lines = 0
            with open(self._jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.strip():
                        total_lines += 1

            logger.info(f"Found {total_lines} findings in {time.time() - start_time:.2f}s")

            if total_lines == 0:
                self.load_complete.emit(0)
                return

            self.load_progress.emit(0, total_lines, "⥁ Loading findings...")

            with open(self._jsonl_path, "r", encoding="utf-8", errors="replace") as f:
                batch = []
                current_line = 0

                for line in f:
                    if not line.strip():
                        continue

                    try:
                        finding = json.loads(line.strip())
                        self.all_findings.append(finding)
                        batch.append(finding)
                        current_line += 1

                        self._update_stats(finding)

                        if len(batch) >= self.batch_size:
                            self.batch_loaded.emit(batch.copy())
                            batch = []

                            percentage = int((current_line / total_lines) * 100)
                            self.load_progress.emit(
                                current_line,
                                total_lines,
                                f"⥁ Loading... {percentage}% ({current_line}/{total_lines})"
                            )

                            QThread.msleep(5)

                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse JSON: {e}")
                        continue

                if batch:
                    self.batch_loaded.emit(batch.copy())

                self.last_position = f.tell()

            elapsed = time.time() - start_time
            logger.info(f"Loaded {total_lines} findings in {elapsed:.2f}s ({total_lines/elapsed:.0f} findings/sec)")

            self.load_complete.emit(total_lines)

        except IOError as e:
            logger.error(f"Error loading initial data: {e}")
            self.load_complete.emit(0)
        except Exception as e:
            logger.error(f"Unexpected error loading initial data: {e}")
            self.load_complete.emit(0)

    def _parse_line(self, line: str):
        """Parse a JSONL line, update stats, and return the finding dict or None."""
        try:
            finding = json.loads(line.strip())
            self.all_findings.append(finding)
            self._update_stats(finding)
            return finding
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON: {e} - Line: {line[:100]}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error processing finding: {e}")
            return None

    # Keep old name for any external callers
    def _process_line(self, line: str):
        self._parse_line(line)

    def _update_stats(self, finding: Dict[str, Any]):
        with self._lock:
            self.stats["total"] += 1

            severity = finding.get("severity", "LOW").upper()
            params = finding.get("params", {})

            has_critical = any("CRITICAL" in str(v) for v in params.values())

            if severity == "CRITICAL" or has_critical:
                self.stats["critical"] += 1
            elif severity == "HIGH":
                self.stats["high"] += 1
            elif severity == "MEDIUM":
                self.stats["medium"] += 1
            else:
                self.stats["low"] += 1

    def get_finding_at_index(self, index: int) -> Optional[Dict[str, Any]]:
        if 0 <= index < len(self.all_findings):
            return self.all_findings[index]
        return None

    def stop(self):
        self.running = False

    def reset_position(self):
        """Reset read position to 0 so next poll cycle sees the file as empty."""
        with self._lock:
            self.last_position = 0


class URLItemDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        url_data = index.data(Qt.UserRole + 1)

        if not url_data or not isinstance(url_data, dict):
            url_text = index.data(Qt.DisplayRole)
            if url_text:
                if "?" in url_text:
                    base, params = url_text.split("?", 1)
                    url_data = {"base": base, "params": params}
                else:
                    url_data = {"base": url_text, "params": ""}
            else:
                super().paint(painter, option, index)
                return

        painter.save()

        base_url = url_data.get("base", "")
        params = url_data.get("params", "")

        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, option.palette.highlight())
        else:
            bg_data = index.data(Qt.BackgroundRole)
            if bg_data:
                painter.fillRect(option.rect, QBrush(bg_data))
            elif option.backgroundBrush.style() != Qt.NoBrush:
                painter.fillRect(option.rect, option.backgroundBrush)

        if option.state & QStyle.State_Selected:
            base_color = option.palette.highlightedText().color()
            param_color = QColor(base_color)
            param_color.setAlpha(180)
        else:
            base_color = QColor(COLOR_URL_BASE)
            param_color = QColor(COLOR_URL_PARAM)

        painter.setFont(option.font)

        text_rect = option.rect.adjusted(5, 0, -5, 0)

        base_text = base_url
        if params:
            base_text += "?"

        fm = painter.fontMetrics()

        available_width = text_rect.width()
        base_width = fm.width(base_text)

        painter.setPen(QPen(base_color))

        if base_width > available_width:
            elided_base = fm.elidedText(base_text, Qt.ElideRight, available_width)
            painter.drawText(text_rect, Qt.AlignLeft | Qt.AlignVCenter, elided_base)
        else:
            painter.drawText(text_rect, Qt.AlignLeft | Qt.AlignVCenter, base_text)

            if params:
                param_rect = QRect(text_rect)
                param_rect.setLeft(text_rect.left() + base_width)

                remaining_width = available_width - base_width
                param_width = fm.width(params)

                painter.setPen(QPen(param_color))

                if param_width > remaining_width:
                    elided_params = fm.elidedText(params, Qt.ElideRight, remaining_width)
                    painter.drawText(param_rect, Qt.AlignLeft | Qt.AlignVCenter, elided_params)
                else:
                    painter.drawText(param_rect, Qt.AlignLeft | Qt.AlignVCenter, params)

        painter.restore()


# Maximum plain-text size (bytes) for which expensive full-document
# character-format operations (SearchHighlighter, syntax highlighting) are
# performed on the main thread.  Above this limit:
#   • The QSyntaxHighlighter is detached before setPlainText() so Qt does
#     not run ~40k regex ops per load on the main thread.
#   • SearchHighlighter skips the blocking full-document format pass and
#     falls back to fast built-in QTextDocument.find() for navigation.
# The full content is ALWAYS loaded and displayed; nothing is truncated.
_MAX_HIGHLIGHT_SIZE = 180_000   # 180 KB


class SearchHighlighter:
    @staticmethod
    def clear_highlights(text_edit: QTextEdit):
        # Skip the expensive full-document format reset for large documents.
        doc_len = text_edit.document().characterCount()
        if doc_len > _MAX_HIGHLIGHT_SIZE:
            return

        text_edit.blockSignals(True)
        try:
            cursor = QTextCursor(text_edit.document())
            cursor.select(QTextCursor.Document)

            format_clear = QTextCharFormat()
            format_clear.setBackground(QBrush(QColor(COLOR_DARK_BG)))
            format_clear.setForeground(QBrush(QColor(COLOR_TEXT)))

            cursor.setCharFormat(format_clear)
            cursor.clearSelection()
        finally:
            text_edit.blockSignals(False)

    @staticmethod
    def highlight_all_matches(
        text_edit: QTextEdit, search_text: str, case_sensitive: bool = False
    ) -> int:
        if not search_text:
            SearchHighlighter.clear_highlights(text_edit)
            return 0

        # For large documents, avoid the blocking full-document format pass.
        # Just count matches and let the caller use QTextEdit.find() to navigate.
        doc_len = text_edit.document().characterCount()
        if doc_len > _MAX_HIGHLIGHT_SIZE:
            plain = text_edit.toPlainText()
            needle = search_text if case_sensitive else search_text.lower()
            haystack = plain if case_sensitive else plain.lower()
            return haystack.count(needle)

        text_edit.blockSignals(True)
        match_count = 0

        try:
            cursor = QTextCursor(text_edit.document())
            cursor.select(QTextCursor.Document)

            default_format = QTextCharFormat()
            default_format.setBackground(QBrush(QColor(COLOR_DARK_BG)))
            default_format.setForeground(QBrush(QColor(COLOR_TEXT)))
            cursor.setCharFormat(default_format)
            cursor.clearSelection()

            highlight_format = QTextCharFormat()
            highlight_format.setBackground(QBrush(QColor("#4d4d1a")))
            highlight_format.setForeground(QBrush(QColor(COLOR_TEXT_BRIGHT)))

            search_flags = QTextDocument.FindFlags()
            if case_sensitive:
                search_flags = QTextDocument.FindCaseSensitively

            cursor = text_edit.document().find(search_text, 0, search_flags)
            while not cursor.isNull():
                cursor.mergeCharFormat(highlight_format)
                match_count += 1
                cursor = text_edit.document().find(search_text, cursor, search_flags)

        finally:
            text_edit.blockSignals(False)

        return match_count

    @staticmethod
    def highlight_current_match(
        text_edit: QTextEdit,
        search_text: str,
        match_index: int,
        case_sensitive: bool = False,
    ):
        if not search_text:
            return

        # For large documents skip the full-document format pass; just scroll
        # to the requested match using the fast built-in find.
        doc_len = text_edit.document().characterCount()
        if doc_len > _MAX_HIGHLIGHT_SIZE:
            flags = QTextDocument.FindFlags()
            if case_sensitive:
                flags |= QTextDocument.FindCaseSensitively
            # Move to document start, then advance to the desired match index.
            cur = QTextCursor(text_edit.document())
            cur.movePosition(QTextCursor.Start)
            text_edit.setTextCursor(cur)
            for _ in range(match_index + 1):
                found = text_edit.document().find(search_text, text_edit.textCursor(), flags)
                if found.isNull():
                    break
                text_edit.setTextCursor(found)
            text_edit.ensureCursorVisible()
            return

        text_edit.blockSignals(True)

        try:
            cursor = QTextCursor(text_edit.document())
            cursor.select(QTextCursor.Document)

            default_format = QTextCharFormat()
            default_format.setBackground(QBrush(QColor(COLOR_DARK_BG)))
            default_format.setForeground(QBrush(QColor(COLOR_TEXT)))
            cursor.setCharFormat(default_format)
            cursor.clearSelection()

            dark_yellow_format = QTextCharFormat()
            dark_yellow_format.setBackground(QBrush(QColor("#4d4d1a")))
            dark_yellow_format.setForeground(QBrush(QColor(COLOR_TEXT_BRIGHT)))

            search_flags = QTextDocument.FindFlags()
            if case_sensitive:
                search_flags = QTextDocument.FindCaseSensitively

            matches = []
            cursor = text_edit.document().find(search_text, 0, search_flags)
            while not cursor.isNull():
                matches.append((cursor.selectionStart(), cursor.selectionEnd()))
                cursor.mergeCharFormat(dark_yellow_format)
                cursor = text_edit.document().find(search_text, cursor, search_flags)

            if 0 <= match_index < len(matches):
                start_pos, end_pos = matches[match_index]

                bright_yellow_format = QTextCharFormat()
                bright_yellow_format.setBackground(QBrush(QColor("#FFEE58")))
                bright_yellow_format.setForeground(QBrush(QColor("#000000")))

                cursor = QTextCursor(text_edit.document())
                cursor.setPosition(start_pos)
                cursor.setPosition(end_pos, QTextCursor.KeepAnchor)
                cursor.mergeCharFormat(bright_yellow_format)

                text_edit.setTextCursor(cursor)
                text_edit.ensureCursorVisible()

        finally:
            text_edit.blockSignals(False)

    @staticmethod
    def find_matches(text: str, search_text: str, case_sensitive: bool = False) -> list:
        matches = []

        if not search_text:
            return matches

        if case_sensitive:
            search_str = search_text
            content = text
        else:
            search_str = search_text.lower()
            content = text.lower()

        pos = 0
        while True:
            pos = content.find(search_str, pos)
            if pos == -1:
                break
            matches.append((pos, pos + len(search_text)))
            pos += len(search_text)

        return matches


# ── Sortable item helpers ─────────────────────────────────────────────────────

class _NumericItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically instead of lexicographically.
    Use for integer columns: #, Status, Params."""

    def __init__(self, display_text: str, sort_value: float = 0):
        super().__init__(display_text)
        self._sort_value = sort_value

    def __lt__(self, other):
        if isinstance(other, _NumericItem):
            return self._sort_value < other._sort_value
        return super().__lt__(other)


class _SizeItem(QTableWidgetItem):
    """QTableWidgetItem that sorts by raw byte count, displays human-readable size."""

    def __init__(self, display_text: str, byte_count: int = 0):
        super().__init__(display_text)
        self._byte_count = byte_count

    def __lt__(self, other):
        if isinstance(other, _SizeItem):
            return self._byte_count < other._byte_count
        return super().__lt__(other)


# ─────────────────────────────────────────────────────────────────────────────
# _InspectorCard is imported from inspector_card.py
# ─────────────────────────────────────────────────────────────────────────────


class InspectorSection(QWidget):
    """Collapsible section widget for the Inspector panel."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self._expanded = True
        self._title = title

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        self._header_btn = QPushButton("▼  " + title)
        self._header_btn.setCursor(Qt.PointingHandCursor)
        self._header_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: none;
                border-top: 1px solid {COLOR_BORDER};
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 7px 10px;
                text-align: left;
                font-weight: 600;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                color: #ffffff;
            }}
        """
        )
        self._header_btn.clicked.connect(self._toggle)
        main_layout.addWidget(self._header_btn)

        self._content_widget = QWidget()
        main_layout.addWidget(self._content_widget, 1)

    def set_content(self, widget: QWidget):
        layout = QVBoxLayout(self._content_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(widget)

    def _toggle(self):
        self._expanded = not self._expanded
        self._content_widget.setVisible(self._expanded)
        arrow = "▼" if self._expanded else "▶"
        self._header_btn.setText(f"{arrow}  {self._title}")

    def expand(self):
        if not self._expanded:
            self._toggle()

    def collapse(self):
        if self._expanded:
            self._toggle()


class HTTPHistoryTab(AnalysisTabMixin):
    def create_http_history_tab(self):
        history_widget = QWidget()
        layout = QVBoxLayout(history_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setStyleSheet(
            f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
                padding: 4px 8px;
            }}
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-weight: 500;
            }}
        """
        )
        toolbar.setMaximumHeight(40)

        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)
        toolbar_layout.setSpacing(8)

        toolbar_layout.addWidget(QLabel("🔍"))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Filter by URL, vulnerability...")
        self.search_box.setMinimumWidth(150)
        self.search_box.setMaximumWidth(400)
        self.search_box.textChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.search_box)

        separator = QFrame()
        separator.setFrameShape(QFrame.VLine)
        separator.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator)

        toolbar_layout.addWidget(QLabel("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(
            ["All", "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
        )
        self.method_combo.setMinimumWidth(70)
        self.method_combo.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.method_combo)

        separator2 = QFrame()
        separator2.setFrameShape(QFrame.VLine)
        separator2.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator2)

        toolbar_layout.addWidget(QLabel("Status:"))
        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "2xx", "3xx", "4xx", "5xx"])
        self.status_combo.setMinimumWidth(70)
        self.status_combo.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.status_combo)

        separator3 = QFrame()
        separator3.setFrameShape(QFrame.VLine)
        separator3.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator3)

        toolbar_layout.addWidget(QLabel("MIME:"))
        self.mime_combo = QComboBox()
        self.mime_combo.addItems(
            ["All", "HTML", "JSON", "JavaScript", "CSS", "XML", "Images", "Other"]
        )
        self.mime_combo.setMinimumWidth(100)
        self.mime_combo.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.mime_combo)

        separator4 = QFrame()
        separator4.setFrameShape(QFrame.VLine)
        separator4.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator4)

        toolbar_layout.addWidget(QLabel("Params:"))
        self.param_filter = QComboBox()
        self.param_filter.addItems(
            ["All", "With Params", "Without Params", "In URL", "In Body"]
        )
        self.param_filter.setMinimumWidth(110)
        self.param_filter.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.param_filter)

        separator5 = QFrame()
        separator5.setFrameShape(QFrame.VLine)
        separator5.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator5)

        toolbar_layout.addWidget(QLabel("Notes:"))
        self.notes_filter = QComboBox()
        self.notes_filter.addItems(["All", "With Notes", "Without Notes"])
        self.notes_filter.setMinimumWidth(110)
        self.notes_filter.currentTextChanged.connect(self.apply_filters)
        toolbar_layout.addWidget(self.notes_filter)

        separator_scope = QFrame()
        separator_scope.setFrameShape(QFrame.VLine)
        separator_scope.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(separator_scope)

        self.scope_filter_cb = QCheckBox("Scope Only")
        self.scope_filter_cb.setChecked(False)
        self.scope_filter_cb.setToolTip(
            "Show only requests whose host matches the current target scope.\n"
            "Scope is set in the Scope tab or Launch dialog."
        )
        self.scope_filter_cb.setStyleSheet(
            f"QCheckBox {{ color: {COLOR_ACCENT}; font-weight: 600; }}"
        )
        self.scope_filter_cb.toggled.connect(self.apply_filters)
        toolbar_layout.addWidget(self.scope_filter_cb)

        self._scope_hosts: set = set()
        self._scope_hosts_previously_set: bool = False
        self._scope_rules: list = []
        self._scope_rules: list = []
        self._scope_slug: str = ""
        self._scope_domain: str = ""
        self._scope_subdomain: str = ""

        self._sitemap_pending_rebuild: bool = False
        self._sitemap_locked: bool = False
        self._sitemap_selected_host: str = ""
        self._sitemap_target_indices: set = set()
        self._sitemap_rebuild_timer = QTimer()
        self._sitemap_rebuild_timer.setSingleShot(True)
        self._sitemap_rebuild_timer.setInterval(1500)
        self._sitemap_rebuild_timer.timeout.connect(self._do_rebuild_sitemap)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh_data)
        refresh_btn.setToolTip("Refresh all data")
        toolbar_layout.addWidget(refresh_btn)

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_findings)
        clear_btn.setToolTip("Clear all findings from GUI")
        toolbar_layout.addWidget(clear_btn)

        proxy_options_btn = QPushButton("⚙ Config")
        proxy_options_btn.clicked.connect(self.show_proxy_options_dialog)
        proxy_options_btn.setToolTip("Configure proxy: Match & Replace, Header Injection, Drop Rules, and more")
        toolbar_layout.addWidget(proxy_options_btn)

        toolbar_layout.addStretch()

        self.toolbar_status = QLabel("Ready")
        self.toolbar_status.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        toolbar_layout.addWidget(self.toolbar_status)

        layout.addWidget(toolbar)

        # ── Main Splitter ─────────────────────────────────────────────────
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(4)
        main_splitter.setChildrenCollapsible(True)
        main_splitter.setStyleSheet(
            f"""
            QSplitter::handle:horizontal {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:horizontal:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """
        )

        # ── Sitemap ───────────────────────────────────────────────────────
        sitemap_widget = QWidget()
        sitemap_layout = QVBoxLayout(sitemap_widget)
        sitemap_layout.setContentsMargins(0, 0, 0, 0)
        sitemap_layout.setSpacing(0)

        sitemap_header = QWidget()
        sitemap_header.setStyleSheet(
            f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """
        )
        sitemap_header.setMaximumHeight(32)

        header_layout = QHBoxLayout(sitemap_header)
        header_layout.setContentsMargins(8, 4, 8, 4)

        title = QLabel("🗺️ Site Map")
        title.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-weight: 600; font-size: {FONT_SIZE_NORMAL};"
        )
        header_layout.addWidget(title)

        header_layout.addSpacing(10)
        self.sitemap_filter_cb = QCheckBox("Filter Using Sitemap")
        self.sitemap_filter_cb.setChecked(True)
        self.sitemap_filter_cb.setToolTip("Filter history by sitemap selection")
        self.sitemap_filter_cb.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        self.sitemap_filter_cb.toggled.connect(self._on_sitemap_filter_toggled)
        header_layout.addWidget(self.sitemap_filter_cb)

        self.sitemap_stats = QLabel("0 hosts")
        self.sitemap_stats.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};"
        )
        header_layout.addStretch()
        header_layout.addWidget(self.sitemap_stats)

        sitemap_layout.addWidget(sitemap_header)

        self.sitemap_tree = QTreeWidget()
        self.sitemap_tree.setHeaderLabels(["Target"])
        self.sitemap_tree.setColumnWidth(0, 250)
        self.sitemap_tree.setAlternatingRowColors(False)
        self.sitemap_tree.setAnimated(True)
        self.sitemap_tree.setIndentation(20)
        self.sitemap_tree.setStyleSheet(
            f"""
            QTreeWidget {{
                background-color: {COLOR_DARK_BG};
                border: none;
                border-right: 1px solid {COLOR_BORDER};
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
        """
        )

        self.sitemap_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.sitemap_tree.customContextMenuRequested.connect(self.show_sitemap_context_menu)
        self.sitemap_tree.itemClicked.connect(self.on_sitemap_selection)
        self.sitemap_tree.itemExpanded.connect(self.on_sitemap_item_expanded)
        self.sitemap_tree.itemCollapsed.connect(self.on_sitemap_item_collapsed)

        sitemap_layout.addWidget(self.sitemap_tree)

        sitemap_widget.setMinimumWidth(150)
        main_splitter.addWidget(sitemap_widget)

        # ── Right Splitter ────────────────────────────────────────────────
        right_splitter = QSplitter(Qt.Vertical)
        right_splitter.setHandleWidth(3)
        right_splitter.setStyleSheet(
            f"""
            QSplitter::handle:vertical {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:vertical:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """
        )

        # ── History Table ─────────────────────────────────────────────────
        self.history_table = QTableWidget()
        # URL-column view mode: False = Host/Path (default), True = single URL column
        self._url_view = False

        self.history_table.setColumnCount(10)
        self.history_table.setHorizontalHeaderLabels(
            ["#", "Time", "Method", "Host", "Path", "Status", "Length", "MIME", "Notes", "Params"]
        )
        self.history_table.setAlternatingRowColors(True)
        self.history_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.history_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.history_table.itemSelectionChanged.connect(self.on_history_selection_changed)
        self.history_table.cellDoubleClicked.connect(self._on_history_cell_double_clicked)
        self.history_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self.show_history_context_menu)
        self.history_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                alternate-background-color: #202020;
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
                padding: 3px 7px;
                border: none;
                border-bottom: 1px solid #2a2a2a;
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: #ffffff;
            }}
            QTableWidget::item:hover {{
                background-color: {COLOR_HOVER};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 5px 8px;
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                border-bottom: 2px solid {COLOR_ACCENT};
                font-weight: bold;
                font-size: 12px;
                font-family: 'Segoe UI', sans-serif;
            }}
            QHeaderView::section:hover {{
                background-color: {COLOR_HOVER};
            }}
        """)

        self.setup_column_context_menu()

        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.resizeSection(0, 50)
        header.resizeSection(1, 80)
        header.resizeSection(2, 60)
        header.resizeSection(3, 200)
        header.resizeSection(4, 300)
        header.resizeSection(5, 60)
        header.resizeSection(6, 80)
        header.resizeSection(7, 120)
        header.resizeSection(8, 150)
        header.resizeSection(9, 60)
        header.setSectionResizeMode(4, QHeaderView.Stretch)
        header.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)

        self.history_table.verticalHeader().setDefaultSectionSize(26)
        self.history_table.verticalHeader().hide()

        # Sorting: managed manually so ascending/descending toggle works correctly.
        # Qt's built-in setSortingEnabled intercepts sectionClicked and pre-sorts
        # before our handler fires, making the direction always one step behind.
        # Instead we keep sorting disabled at the table level and call sortItems()
        # ourselves inside _on_header_clicked.
        self.history_table.setSortingEnabled(False)
        self.history_table.horizontalHeader().setSortIndicatorShown(True)
        self.history_table.horizontalHeader().setSortIndicator(0, Qt.AscendingOrder)
        self.history_table.horizontalHeader().sectionClicked.connect(
            self._on_header_clicked
        )
        # Track last sort state manually
        self._sort_col   = 0
        self._sort_order = Qt.AscendingOrder

        # In default Host/Path mode: col 4 (Path) uses URLItemDelegate for colorised path/params
        self.history_table.setItemDelegateForColumn(4, URLItemDelegate(self.history_table))

        # Shortcuts
        self.sc_scan = QShortcut(QKeySequence("Ctrl+S"), self.history_table)
        self.sc_scan.activated.connect(self._shortcut_send_to_scanner)
        self.sc_scan_tab = QShortcut(QKeySequence("Ctrl+Shift+S"), self.history_table)
        self.sc_scan_tab.activated.connect(self._shortcut_switch_to_scanner)

        self.sc_rep = QShortcut(QKeySequence("Ctrl+R"), self.history_table)
        self.sc_rep.activated.connect(self._shortcut_send_to_repeater)
        self.sc_rep_tab = QShortcut(QKeySequence("Ctrl+Shift+R"), self.history_table)
        self.sc_rep_tab.activated.connect(self._shortcut_switch_to_repeater)

        self.sc_int = QShortcut(QKeySequence("Ctrl+I"), self.history_table)
        self.sc_int.activated.connect(self._shortcut_send_to_intruder)
        self.sc_int_tab = QShortcut(QKeySequence("Ctrl+Shift+I"), self.history_table)
        self.sc_int_tab.activated.connect(self._shortcut_switch_to_intruder)

        # self.sc_cmp = QShortcut(QKeySequence("Ctrl+C"), self.history_table)
        # self.sc_cmp.activated.connect(self._shortcut_send_to_comparer)
        # self.sc_cmp_tab = QShortcut(QKeySequence("Ctrl+Shift+C"), self.history_table)
        # self.sc_cmp_tab.activated.connect(self._shortcut_switch_to_comparer)

        # ── AI Chat toggle (Ctrl+Shift+C) ────────────────────────────────
        self.sc_ai_toggle = QShortcut(QKeySequence("Ctrl+Shift+C"), history_widget)
        self.sc_ai_toggle.activated.connect(self._toggle_ai_panel)

        # ── Param Miner shortcut ──────────────────────────────────────────
        self.sc_pm = QShortcut(QKeySequence("Ctrl+P"), self.history_table)
        self.sc_pm.activated.connect(self._shortcut_send_to_param_miner)

        right_splitter.addWidget(self.history_table)

        # ── Bottom Area: Request / Response / Inspector (single flat splitter) ──
        # All three panels live in ONE QSplitter so any panel can steal or donate
        # width freely from/to any other panel without nested-splitter constraints.
        bottom_splitter = QSplitter(Qt.Horizontal)
        bottom_splitter.setHandleWidth(4)
        bottom_splitter.setChildrenCollapsible(True)
        bottom_splitter.setStyleSheet(
            f"""
            QSplitter::handle:horizontal {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:horizontal:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """
        )

        # Inner splitter for Request and Response panels (left section).
        rr_splitter = QSplitter(Qt.Horizontal)
        rr_splitter.setHandleWidth(4)
        rr_splitter.setChildrenCollapsible(False)
        rr_splitter.setStyleSheet(
            f"""
            QSplitter::handle:horizontal {{
                background-color: {COLOR_BORDER};
            }}
            QSplitter::handle:horizontal:hover {{
                background-color: {COLOR_ACCENT};
            }}
        """
        )

        # ── Request Panel ─────────────────────────────────────────────────
        request_container = QWidget()
        request_layout = QVBoxLayout(request_container)
        request_layout.setContentsMargins(0, 0, 0, 0)
        request_layout.setSpacing(0)

        req_header = QWidget()
        req_header.setMaximumHeight(32)
        req_header.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};"
        )
        req_header_layout = QHBoxLayout(req_header)
        req_header_layout.setContentsMargins(8, 3, 8, 3)
        req_header_layout.setSpacing(6)

        self.req_title = QLabel(" Request")
        self.req_title.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-weight: 700; font-size: 11px;"
        )
        req_header_layout.addWidget(self.req_title)

        _gql_btn_style = (
            f"QPushButton {{ background-color: transparent; color: {COLOR_ACCENT};"
            f" border: 1px solid {COLOR_ACCENT}; border-radius: 3px;"
            f" padding: 1px 7px; font-size: 10px; font-weight: 600; }}"
            f" QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
            f" QPushButton:checked {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
        )
        self.req_graphql_btn = QPushButton("⬡ GraphQL")
        self.req_graphql_btn.setCheckable(True)
        self.req_graphql_btn.setStyleSheet(_gql_btn_style)
        self.req_graphql_btn.setToolTip("Switch between Raw and GraphQL pretty-print view")
        self.req_graphql_btn.setVisible(False)
        self.req_graphql_btn.clicked.connect(self._toggle_graphql_req)
        req_header_layout.addWidget(self.req_graphql_btn)

        req_sep1 = QFrame()
        req_sep1.setFrameShape(QFrame.VLine)
        req_sep1.setStyleSheet(f"background-color: {COLOR_BORDER};")
        req_header_layout.addWidget(req_sep1)

        req_header_layout.addWidget(QLabel("Search:"))
        self.request_search_box = QLineEdit()
        self.request_search_box.setPlaceholderText("Search in request...")
        self.request_search_box.textChanged.connect(self.search_in_request)
        self.request_search_box.returnPressed.connect(
            lambda: self.find_in_text(self.request_text, self.request_search_box.text())
        )
        req_header_layout.addWidget(self.request_search_box)

        self.request_search_prev_btn = QPushButton("◀")
        self.request_search_prev_btn.setFixedSize(18, 18)
        self.request_search_prev_btn.setToolTip("Previous match")
        self.request_search_prev_btn.setStyleSheet("padding: 0px; font-size: 9px;")
        self.request_search_prev_btn.clicked.connect(
            lambda: self.find_in_text(
                self.request_text, self.request_search_box.text(), backward=True
            )
        )
        req_header_layout.addWidget(self.request_search_prev_btn)

        self.request_search_next_btn = QPushButton("▶")
        self.request_search_next_btn.setFixedSize(18, 18)
        self.request_search_next_btn.setToolTip("Next match")
        self.request_search_next_btn.setStyleSheet("padding: 0px; font-size: 9px;")
        self.request_search_next_btn.clicked.connect(
            lambda: self.find_in_text(self.request_text, self.request_search_box.text())
        )
        req_header_layout.addWidget(self.request_search_next_btn)

        self.request_match_label = QLabel("0 matches")
        self.request_match_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        req_header_layout.addWidget(self.request_match_label)

        req_header_layout.addStretch()
        request_layout.addWidget(req_header)

        self.request_text = QTextEdit()
        self.request_text.setReadOnly(True)
        self.request_text.setFont(QFont("Consolas", 9))
        self.request_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.request_highlighter = HttpSyntaxHighlighter(self.request_text.document())
        self.request_text.selectionChanged.connect(
            lambda: self._on_selection_changed("REQUEST"))
        self.request_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.request_text.customContextMenuRequested.connect(self._show_request_context_menu)

        # GraphQL section splitter (shown on page 1 of req_stack)
        _gql_spl_style = (
            f"QSplitter::handle:vertical {{ background-color: {COLOR_BORDER}; min-height: 4px; }}"
            f" QSplitter::handle:vertical:hover {{ background-color: {COLOR_ACCENT}; }}"
        )
        self.req_gql_splitter = QSplitter(Qt.Vertical)
        self.req_gql_splitter.setHandleWidth(5)
        self.req_gql_splitter.setChildrenCollapsible(False)
        self.req_gql_splitter.setStyleSheet(_gql_spl_style)
        (self.req_gql_query_panel,
         self.req_gql_query_text)  = self._make_gql_panel("⬡  QUERY",          COLOR_TEXT_BRIGHT, highlight="gql")
        (self.req_gql_vars_panel,
         self.req_gql_vars_text)   = self._make_gql_panel("⬡  VARIABLES",      COLOR_ACCENT,      highlight="json")
        (self.req_gql_opname_panel,
         self.req_gql_opname_text) = self._make_gql_panel("⬡  OPERATION NAME", COLOR_TEXT_MUTED)
        self.req_gql_splitter.addWidget(self.req_gql_query_panel)
        self.req_gql_splitter.addWidget(self.req_gql_vars_panel)
        self.req_gql_splitter.addWidget(self.req_gql_opname_panel)

        self.req_stack = QStackedWidget()
        self.req_stack.addWidget(self.request_text)    # page 0: raw HTTP
        self.req_stack.addWidget(self.req_gql_splitter) # page 1: GraphQL panels
        request_layout.addWidget(self.req_stack)

        self.current_request_raw = ""
        rr_splitter.addWidget(request_container)

        # ── Response Panel ────────────────────────────────────────────────
        response_container = QWidget()
        response_layout = QVBoxLayout(response_container)
        response_layout.setContentsMargins(0, 0, 0, 0)
        response_layout.setSpacing(0)

        resp_header = QWidget()
        resp_header.setMaximumHeight(32)
        resp_header.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};"
        )
        resp_header_layout = QHBoxLayout(resp_header)
        resp_header_layout.setContentsMargins(8, 3, 8, 3)
        resp_header_layout.setSpacing(6)

        self.resp_title = QLabel(" Response")
        self.resp_title.setStyleSheet(
            f"color: {COLOR_SUCCESS}; font-weight: 700; font-size: 11px;"
        )
        resp_header_layout.addWidget(self.resp_title)

        self.resp_graphql_btn = QPushButton("⬡ GraphQL")
        self.resp_graphql_btn.setCheckable(True)
        self.resp_graphql_btn.setStyleSheet(_gql_btn_style)
        self.resp_graphql_btn.setToolTip("Switch between Raw and GraphQL pretty-print view")
        self.resp_graphql_btn.setVisible(False)
        self.resp_graphql_btn.clicked.connect(self._toggle_graphql_resp)
        resp_header_layout.addWidget(self.resp_graphql_btn)

        resp_sep1 = QFrame()
        resp_sep1.setFrameShape(QFrame.VLine)
        resp_sep1.setStyleSheet(f"background-color: {COLOR_BORDER};")
        resp_header_layout.addWidget(resp_sep1)

        resp_header_layout.addWidget(QLabel("Search:"))
        self.response_search_box = QLineEdit()
        self.response_search_box.setPlaceholderText("Search in response...")
        self.response_search_box.textChanged.connect(self.search_in_response)
        self.response_search_box.returnPressed.connect(
            lambda: self.find_in_text(self.response_text, self.response_search_box.text())
        )
        resp_header_layout.addWidget(self.response_search_box)

        self.response_search_prev_btn = QPushButton("◀")
        self.response_search_prev_btn.setFixedSize(18, 18)
        self.response_search_prev_btn.setToolTip("Previous match")
        self.response_search_prev_btn.setStyleSheet("padding: 0px; font-size: 9px;")
        self.response_search_prev_btn.clicked.connect(
            lambda: self.find_in_text(
                self.response_text, self.response_search_box.text(), backward=True
            )
        )
        resp_header_layout.addWidget(self.response_search_prev_btn)

        self.response_search_next_btn = QPushButton("▶")
        self.response_search_next_btn.setFixedSize(18, 18)
        self.response_search_next_btn.setToolTip("Next match")
        self.response_search_next_btn.setStyleSheet("padding: 0px; font-size: 9px;")
        self.response_search_next_btn.clicked.connect(
            lambda: self.find_in_text(
                self.response_text, self.response_search_box.text()
            )
        )
        resp_header_layout.addWidget(self.response_search_next_btn)

        self.response_match_label = QLabel("0 matches")
        self.response_match_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        resp_header_layout.addWidget(self.response_match_label)

        resp_header_layout.addStretch()
        response_layout.addWidget(resp_header)

        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setFont(QFont("Consolas", 9))
        self.response_text.setLineWrapMode(QTextEdit.WidgetWidth)
        self.response_highlighter = HttpSyntaxHighlighter(self.response_text.document())
        self.response_text.selectionChanged.connect(
            lambda: self._on_selection_changed("RESPONSE"))
        self.response_text.setContextMenuPolicy(Qt.CustomContextMenu)
        self.response_text.customContextMenuRequested.connect(self._show_response_context_menu)

        # GraphQL section splitter (shown on page 1 of resp_stack)
        self.resp_gql_splitter = QSplitter(Qt.Vertical)
        self.resp_gql_splitter.setHandleWidth(5)
        self.resp_gql_splitter.setChildrenCollapsible(False)
        self.resp_gql_splitter.setStyleSheet(_gql_spl_style)
        (self.resp_gql_errors_panel,
         self.resp_gql_errors_text) = self._make_gql_panel("⬡  ERRORS",     "#e05c5c")
        (self.resp_gql_data_panel,
         self.resp_gql_data_text)   = self._make_gql_panel("⬡  DATA",       COLOR_SUCCESS,   highlight="json")
        (self.resp_gql_exts_panel,
         self.resp_gql_exts_text)   = self._make_gql_panel("⬡  EXTENSIONS", COLOR_TEXT_MUTED, highlight="json")
        self.resp_gql_splitter.addWidget(self.resp_gql_errors_panel)
        self.resp_gql_splitter.addWidget(self.resp_gql_data_panel)
        self.resp_gql_splitter.addWidget(self.resp_gql_exts_panel)

        self.resp_stack = QStackedWidget()
        self.resp_stack.addWidget(self.response_text)     # page 0: raw HTTP
        self.resp_stack.addWidget(self.resp_gql_splitter) # page 1: GraphQL panels
        response_layout.addWidget(self.resp_stack)

        self.current_response_raw = ""
        # GraphQL view state
        self._graphql_req_mode   = False
        self._graphql_resp_mode  = False
        self._current_graphql    = {}   # populated by _update_graphql_state
        rr_splitter.addWidget(response_container)
        rr_splitter.setSizes([400, 400])
        bottom_splitter.addWidget(rr_splitter)

        # ── Right: Inspector Panel ────────────────────────────────────────
        inspector_panel = QWidget()
        # No minimum width – let the splitter distribute freely.
        inspector_panel_layout = QVBoxLayout(inspector_panel)
        inspector_panel_layout.setContentsMargins(0, 0, 0, 0)
        inspector_panel_layout.setSpacing(0)

        inspector_header = QWidget()
        inspector_header.setMaximumHeight(34)
        inspector_header.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG}; border-bottom: 2px solid {COLOR_ACCENT};"
        )
        _insp_hdr_layout = QHBoxLayout(inspector_header)
        _insp_hdr_layout.setContentsMargins(10, 4, 8, 4)
        _insp_hdr_layout.setSpacing(6)

        _insp_title = QLabel("⌕ Analysis")
        _insp_title.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-weight: 700; font-size: 12px;"
        )
        _insp_hdr_layout.addWidget(_insp_title)
        _insp_hdr_layout.addStretch()

        self._inspector_swap_btn = QPushButton("⇄ Swap")
        self._inspector_swap_btn.setToolTip("Hide Inspector (req/resp full width)")
        self._inspector_swap_btn.setMaximumWidth(72)
        self._inspector_swap_btn.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_MUTED};
                border: 1px solid {COLOR_BORDER};
                padding: 2px 6px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                color: {COLOR_TEXT_BRIGHT};
            }}
        """
        )
        self._inspector_swap_btn.clicked.connect(self._swap_inspector_side)
        _insp_hdr_layout.addWidget(self._inspector_swap_btn)

        inspector_panel_layout.addWidget(inspector_header)

        inspector_scroll = QScrollArea()
        inspector_scroll.setWidgetResizable(True)
        inspector_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        inspector_scroll.setStyleSheet(
            f"""
            QScrollArea {{
                border: none;
                background-color: {COLOR_DARK_BG};
            }}
        """
        )

        inspector_scroll_widget = QWidget()
        inspector_scroll_layout = QVBoxLayout(inspector_scroll_widget)
        inspector_scroll_layout.setContentsMargins(0, 0, 0, 0)
        inspector_scroll_layout.setSpacing(0)

        # ── Selection Inspector (hidden until text is selected) ───────────
        self._sel_current_text = ""
        self._sel_pending_text = ""
        self._sel_pending_source = ""
        self._sel_last_text = ""
        self._sel_last_source = ""
        self._sel_last_cards = None
        self._sel_debounce_timer = QTimer(self)
        self._sel_debounce_timer.setSingleShot(True)
        self._sel_debounce_timer.setInterval(110)
        self._sel_debounce_timer.timeout.connect(self._process_selection_inspector)
        self._inspector_selection_section = InspectorSection(" Selection Inspector")

        _sel_wrapper = QWidget()
        _sel_wrapper.setStyleSheet("background:transparent;")
        _sel_wl = QVBoxLayout(_sel_wrapper)
        _sel_wl.setContentsMargins(0, 0, 0, 0)
        _sel_wl.setSpacing(0)

        # Mini toolbar inside the section
        _sel_tb = QWidget()
        _sel_tb.setFixedHeight(28)
        _sel_tb.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        _sel_tb_l = QHBoxLayout(_sel_tb)
        _sel_tb_l.setContentsMargins(8, 3, 8, 3)
        _sel_tb_l.setSpacing(6)
        self._sel_source_badge = QLabel("")
        self._sel_source_badge.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;font-weight:600;")
        _sel_tb_l.addWidget(self._sel_source_badge)
        _sel_tb_l.addStretch()

        _sel_copy_btn = QPushButton("🗉 Copy")
        _sel_copy_btn.setFixedHeight(20)
        _sel_copy_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 6px;")
        _sel_copy_btn.setToolTip("Copy raw selected text")
        _sel_copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(
                getattr(self, '_sel_current_text', '')))

        _sel_dec_btn = QPushButton("🗁 Open in Decoder")
        _sel_dec_btn.setFixedHeight(20)
        _sel_dec_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 6px;")
        _sel_dec_btn.setToolTip("Send selected text to Decoder tab")
        _sel_dec_btn.clicked.connect(self._send_selection_to_decoder)

        _sel_tb_l.addWidget(_sel_copy_btn)
        _sel_tb_l.addWidget(_sel_dec_btn)
        _sel_wl.addWidget(_sel_tb)

        self._sel_result_view = QTextEdit()
        self._sel_result_view.setReadOnly(True)
        self._sel_result_view.setMinimumHeight(200)
        self._sel_result_view.setStyleSheet(
            f"background:{COLOR_DARK_BG};border:none;"
            f"font-family:Consolas,monospace;font-size:11px;")
        # Hidden — superseded by card scroll area
        self._sel_result_view.setVisible(False)

        # ── Card scroll area for inspector results ─────────────────────────
        self._sel_card_scroll = QScrollArea()
        self._sel_card_scroll.setWidgetResizable(True)
        self._sel_card_scroll.setFrameShape(QFrame.NoFrame)
        self._sel_card_scroll.setStyleSheet(
            f"QScrollArea {{background:{COLOR_DARK_BG};border:none;}}"
            f"QScrollBar:vertical {{background:#1a1a2a;width:8px;border-radius:4px;}}"
            f"QScrollBar::handle:vertical {{background:#3a3a5a;border-radius:4px;}}"
        )
        self._sel_card_container = QWidget()
        self._sel_card_container.setStyleSheet(f"background:{COLOR_DARK_BG};")
        self._sel_card_layout = QVBoxLayout(self._sel_card_container)
        self._sel_card_layout.setContentsMargins(6, 6, 6, 6)
        self._sel_card_layout.setSpacing(6)
        self._sel_card_layout.addStretch()
        self._sel_card_scroll.setWidget(self._sel_card_container)
        _sel_wl.addWidget(self._sel_card_scroll)

        self._inspector_selection_section.set_content(_sel_wrapper)
        self._inspector_selection_section.setVisible(False)
        inspector_scroll_layout.addWidget(self._inspector_selection_section, 1)

        # ── Analysis section ──────────────────────────────────────────────
        self._inspector_analysis_section = self.create_analysis_tab_in_rr_tabs()
        inspector_scroll_layout.addWidget(self._inspector_analysis_section, 1)

        inspector_scroll.setWidget(inspector_scroll_widget)
        inspector_panel_layout.addWidget(inspector_scroll)

        bottom_splitter.addWidget(inspector_panel)
        # Left: req/resp section (~70%) | Right: inspector (~30%)
        bottom_splitter.setSizes([700, 300])

        # Store references for swap logic
        self._bottom_splitter = bottom_splitter
        self._inspector_panel = inspector_panel
        self._rr_splitter = rr_splitter
        # 0 = normal (inspector right ~30%), 1 = hidden (req/resp full), 2 = full (inspector full)
        self._inspector_state = 0

        # Compatibility stubs
        self.request_container = request_container
        self.response_container = response_container
        self.in_split_view_mode = False

        right_splitter.addWidget(bottom_splitter)
        right_splitter.setSizes([400, 400])

        self.main_vertical_splitter = right_splitter
        right_splitter.setMinimumWidth(400)
        main_splitter.addWidget(right_splitter)
        main_splitter.setSizes([300, 900])

        # ── AI Chat panel: full-height right side, collapsible via Ctrl+Shift+C ──
        self._ai_outer_splitter = QSplitter(Qt.Horizontal)
        self._ai_outer_splitter.setHandleWidth(1)
        self._ai_outer_splitter.setChildrenCollapsible(True)
        self._ai_outer_splitter.setStyleSheet(
            f"QSplitter::handle:horizontal {{ background-color: {COLOR_ACCENT}; }}"
        )
        self._ai_outer_splitter.addWidget(main_splitter)

        self._ai_chat_panel = _AIChatPanel()
        self._ai_chat_panel.close_requested.connect(self._on_ai_chat_close)
        self._ai_chat_panel._parent_tab = self   # live settings back-reference
        self._ai_outer_splitter.addWidget(self._ai_chat_panel)
        self._ai_outer_splitter.setSizes([10000, 0])   # hidden initially

        layout.addWidget(self._ai_outer_splitter)

        self.tab_widget.addTab(history_widget, "HTTP History")
        self.sitemap_data = {}

    def create_toolbar(self, parent_layout):
        toolbar = QWidget()
        toolbar.setStyleSheet(
            """
            QWidget {
                background-color: #2D2D2D;
                border-bottom: 1px solid #3C3F41;
                padding: 4px 8px;
            }
        """
        )

        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)

        self.send_btn = QPushButton("🖅 Send")
        self.send_btn.setStyleSheet(
            """
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00E676, stop:1 #00C853);
                color: white;
                font-weight: 700;
                padding: 8px 24px;
                border-radius: 4px;
                border: none;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00C853, stop:1 #00E676);
            }
        """
        )
        self.send_btn.clicked.connect(self.send_request)
        toolbar_layout.addWidget(self.send_btn)

        toolbar_layout.addWidget(self._create_separator())

        toolbar_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://example.com")
        self.target_input.setText("https://")
        self.target_input.setMinimumWidth(300)
        toolbar_layout.addWidget(self.target_input)

        toolbar_layout.addWidget(self._create_separator())

        templates_btn = QPushButton("䷓ Templates")
        templates_btn.clicked.connect(self.show_templates)
        toolbar_layout.addWidget(templates_btn)

        save_btn = QPushButton("🖫 Save")
        save_btn.clicked.connect(self.save_as_template)
        toolbar_layout.addWidget(save_btn)

        compare_btn = QPushButton("⽐ Compare")
        compare_btn.clicked.connect(self.compare_responses)
        toolbar_layout.addWidget(compare_btn)

        clear_btn = QPushButton("🗑 Clear")
        clear_btn.clicked.connect(self.clear_all)
        toolbar_layout.addWidget(clear_btn)

        toolbar_layout.addStretch()

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #888888;")
        toolbar_layout.addWidget(self.status_label)

        parent_layout.addWidget(toolbar)

    def add_history_row(self, finding: Dict[str, Any], finding_index: int = -1):
        # ── Method → color map (matches recorded tab) ─────────────────────
        METHOD_COLORS = {
            "GET":     "#4ec9b0",
            "POST":    "#569cd6",
            "PUT":     "#dcdcaa",
            "PATCH":   "#c586c0",
            "DELETE":  "#f48771",
            "OPTIONS": "#9cdcfe",
            "HEAD":    "#b5cea8",
        }

        row = self.history_table.rowCount()
        self.history_table.insertRow(row)

        if finding_index == -1:
            finding_index = len(self.findings) - 1

        # ── Col 0: Sequence # ─────────────────────────────────────────────
        seq_num = finding.get("seq", row + 1)
        seq_item = _NumericItem(str(seq_num), float(seq_num))
        seq_item.setData(Qt.UserRole, finding_index)
        seq_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        seq_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 0, seq_item)

        # ── Col 1: Time ───────────────────────────────────────────────────
        timestamp = finding.get("timestamp", "")
        if timestamp:
            try:
                time_obj = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                time_str = time_obj.strftime("%H:%M:%S")
            except (ValueError, AttributeError):
                time_str = ""
        else:
            time_str = ""
        time_item = QTableWidgetItem(time_str)
        time_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        time_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 1, time_item)

        # ── Col 2: Method ─────────────────────────────────────────────────
        method = finding.get("method", "GET").upper()
        method_item = QTableWidgetItem(method)
        method_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        method_color = METHOD_COLORS.get(method, COLOR_TEXT)
        method_item.setForeground(QColor(method_color))
        method_item.setFont(QFont("Consolas", 10, QFont.Bold))
        self.history_table.setItem(row, 2, method_item)

        # ── Col 3: Host / URL ─────────────────────────────────────────────
        url = finding.get("url", "")
        try:
            _parsed = urlparse(url)
            _host = _parsed.netloc or _parsed.hostname or ""
            _path = _parsed.path or "/"
            if _parsed.query:
                _path_and_query = _path + "?" + _parsed.query
            else:
                _path_and_query = _path
        except Exception:
            _host = ""
            _path_and_query = url

        if self._url_view:
            # URL mode: show full URL in col 3
            url_item = QTableWidgetItem(url)
        else:
            # Host/Path mode (default): show host in col 3
            url_item = QTableWidgetItem(_host)

        # Store full URL data for URLItemDelegate and mode switching
        if "?" in url:
            _base_url, _query_string = url.split("?", 1)
            url_item.setData(Qt.UserRole + 1, {"base": _base_url, "params": _query_string})
        else:
            url_item.setData(Qt.UserRole + 1, {"base": url, "params": ""})
        url_item.setData(Qt.UserRole + 2, url)   # full URL for switching
        url_item.setForeground(QColor(COLOR_TEXT_BRIGHT))
        self.history_table.setItem(row, 3, url_item)

        # ── Col 4: Path ───────────────────────────────────────────────────
        path_item = QTableWidgetItem(_path_and_query)
        path_item.setForeground(QColor(COLOR_TEXT))
        self.history_table.setItem(row, 4, path_item)

        # ── Col 5: Status ─────────────────────────────────────────────────
        status = finding.get("status", 0)
        status_item = _NumericItem(str(status), float(status))
        status_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        status_item.setFont(QFont("Consolas", 10, QFont.Bold))
        if 200 <= status < 300:
            status_item.setForeground(QColor(COLOR_SUCCESS))
        elif 300 <= status < 400:
            status_item.setForeground(QColor(COLOR_MEDIUM))
        elif 400 <= status < 500:
            status_item.setForeground(QColor(COLOR_HIGH))
        elif status >= 500:
            status_item.setForeground(QColor(COLOR_CRITICAL))
        else:
            status_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 5, status_item)

        # ── Col 6: Length ─────────────────────────────────────────────────
        response_file = finding.get("response_file")
        length_str = "0 B"
        raw_bytes = 0
        if response_file and os.path.exists(response_file):
            try:
                raw_bytes = os.path.getsize(response_file)
                if raw_bytes < 1024:
                    length_str = f"{raw_bytes} B"
                elif raw_bytes < 1024 * 1024:
                    length_str = f"{raw_bytes/1024:.1f} KB"
                else:
                    length_str = f"{raw_bytes/(1024*1024):.1f} MB"
            except:
                length_str = "?"
        length_item = _SizeItem(length_str, raw_bytes)
        length_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
        length_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 6, length_item)

        # ── Col 7: MIME ───────────────────────────────────────────────────
        mime_type = self.detect_mime_type(finding)
        _ml = mime_type.lower()
        if "json" in _ml:
            mime_display = "JSON"
        elif "html" in _ml:
            mime_display = "HTML"
        elif "javascript" in _ml:
            mime_display = "JS"
        elif "css" in _ml:
            mime_display = "CSS"
        elif "xml" in _ml:
            mime_display = "XML"
        else:
            mime_display = mime_type
        mime_item = QTableWidgetItem(mime_display)
        mime_item.setToolTip(mime_type)
        mime_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        if "json" in _ml:
            mime_item.setForeground(QColor(COLOR_SUCCESS))
        elif "html" in _ml:
            mime_item.setForeground(QColor(COLOR_ACCENT))
        elif "javascript" in _ml:
            mime_item.setForeground(QColor(COLOR_MEDIUM))
        elif "xml" in _ml:
            mime_item.setForeground(QColor(COLOR_LOW))
        else:
            mime_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 7, mime_item)

        # ── Col 8: Notes (text preview) ─────────────────────────────────────
        note_key = finding.get("seq", finding_index)
        note_text = self.notes_storage.get(note_key, "")
        note_preview = note_text.split("\n")[0][:60] if note_text else ""
        notes_item = QTableWidgetItem(note_preview)
        notes_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        if note_text:
            notes_item.setForeground(QColor(COLOR_ACCENT))
        notes_item.setToolTip(note_text)
        self.history_table.setItem(row, 8, notes_item)

        # ── Col 9: Params (URL + body) ────────────────────────────────────
        url = finding.get("url", "")
        method = finding.get("method", "GET").upper()

        # URL params — fast, no I/O
        url_params = 0
        if "?" in url:
            query = url.split("?", 1)[1]
            url_params = len(query.split("&")) if "&" in query else (1 if query else 0)

        # Body params — file I/O: skip during bulk/live ingestion to avoid
        # stalling the main thread; the column can be lazily refreshed later.
        body_params = 0
        if method in ("POST", "PUT", "PATCH", "DELETE") and not getattr(self, "_bulk_loading", False):
            request_file = finding.get("request_file")
            if request_file and os.path.exists(request_file):
                try:
                    with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()

                    # Split headers from body
                    body = ""
                    if "\r\n\r\n" in content:
                        body = content.split("\r\n\r\n", 1)[1].strip()
                    elif "\n\n" in content:
                        body = content.split("\n\n", 1)[1].strip()

                    if body:
                        # JSON body — count top-level keys
                        if body.startswith("{"):
                            try:
                                data = json.loads(body)
                                body_params = len(data) if isinstance(data, dict) else 1
                            except Exception:
                                body_params = 1
                        # JSON array
                        elif body.startswith("["):
                            try:
                                data = json.loads(body)
                                body_params = len(data) if isinstance(data, list) else 1
                            except Exception:
                                body_params = 1
                        # Form-urlencoded  key=val&key2=val2
                        elif "=" in body and not body.startswith("<"):
                            pairs = [p for p in body.split("&") if "=" in p]
                            body_params = len(pairs) if pairs else 1
                        # Multipart form-data
                        elif "Content-Disposition: form-data" in body or "content-disposition: form-data" in body.lower():
                            body_params = body.lower().count("content-disposition: form-data")
                        # Raw body with any content
                        elif len(body) > 0:
                            body_params = 1
                except Exception:
                    pass

        params_count = url_params + body_params

        # Build display string — show breakdown when both sources have params
        if url_params > 0 and body_params > 0:
            display = f"{params_count} ({url_params}+{body_params})"
        else:
            display = str(params_count) if params_count else ""

        params_item = _NumericItem(display, float(params_count))
        params_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
        if params_count > 0:
            params_item.setForeground(QColor(COLOR_ACCENT))
            params_item.setFont(QFont("Consolas", 10, QFont.Bold))
        else:
            params_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.history_table.setItem(row, 9, params_item)

        # ── Apply highlight overlay if row is marked ──────────────────────
        hl_key = finding.get("seq", finding_index)
        if hl_key in self.highlighted_rows:
            color = self.highlighted_rows[hl_key]
            for col in range(self.history_table.columnCount()):
                item = self.history_table.item(row, col)
                if item:
                    bg_color = QColor(color)
                    bg_color.setAlpha(50)
                    item.setBackground(QBrush(bg_color))

        if row % 100 == 0:
            self.history_table.scrollToBottom()

        if getattr(self, "scope_filter_cb", None) and self.scope_filter_cb.isChecked():
            finding_data = self.findings[finding_index] if finding_index < len(self.findings) else {}
            url = finding_data.get("url", "")
            if not self._is_in_scope(url):
                self.history_table.setRowHidden(row, True)

        if not getattr(self, "_bulk_loading", False):
            self._schedule_sitemap_rebuild()

    def _schedule_sitemap_rebuild(self):
        if self._sitemap_locked:
            self._sitemap_pending_rebuild = True
            return
        self._sitemap_rebuild_timer.start()

    def _do_rebuild_sitemap(self):
        self._sitemap_pending_rebuild = False
        self.update_sitemap_tree()

    def update_sitemap_tree(self):
        self.sitemap_tree.blockSignals(True)

        expanded_dirs = set()
        try:
            iterator = QTreeWidgetItemIterator(self.sitemap_tree)
            while iterator.value():
                item = iterator.value()
                if item.isExpanded():
                    data = item.data(0, Qt.UserRole)
                    if data and data.get("type") == "directory":
                        host = data.get("host", "")
                        path = data.get("path", "")
                        expanded_dirs.add(f"{host}|{path}")
                iterator += 1
        except Exception:
            pass

        try:
            self.sitemap_tree.clear()
            self.sitemap_data = {}

            hosts_data = {}

            for row in range(self.history_table.rowCount()):
                if self.history_table.isRowHidden(row):
                    continue

                finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
                if finding_index is None or finding_index >= len(self.findings):
                    continue

                finding = self.findings[finding_index]
                url = finding.get("url", "")
                method = finding.get("method", "GET")

                if not url:
                    continue

                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    scheme = parsed.scheme or "http"
                    host = parsed.netloc or "unknown"
                    path = parsed.path or "/"

                    if path != "/" and path.endswith("/"):
                        path = path.rstrip("/")

                    full_host = f"{scheme}://{host}"
                    has_params = bool(parsed.query)

                    if full_host not in hosts_data:
                        hosts_data[full_host] = {}

                    if path not in hosts_data[full_host]:
                        hosts_data[full_host][path] = []

                    hosts_data[full_host][path].append(
                        {
                            "index": finding_index,
                            "method": method,
                            "has_params": has_params,
                            "has_issues": bool(finding.get("params")),
                        }
                    )

                except Exception as e:
                    logger.error(f"Error parsing URL {url}: {e}")
                    continue

            for full_host in sorted(hosts_data.keys()):
                host_item = QTreeWidgetItem([full_host])
                host_item.setData(0, Qt.UserRole, {"type": "host", "host": full_host})
                host_item.setForeground(0, QColor(COLOR_TEXT_BRIGHT))
                host_item.setFont(0, QFont("Consolas", 10, QFont.Bold))

                paths_dict = hosts_data[full_host]
                path_tree = {}
                direct_path_requests = {}

                for path, findings_data in sorted(paths_dict.items()):
                    direct_path_requests[path] = findings_data
                    segments = [s for s in path.split("/") if s]
                    if not segments:
                        segments = [""]

                    current = path_tree
                    for i, segment in enumerate(segments):
                        if segment not in current:
                            current[segment] = {}
                        current = current[segment]
                        partial_path = "/" + "/".join(segments[: i + 1])
                        if "partial_path" not in current:
                            current["partial_path"] = partial_path

                    if "items" not in current:
                        current["items"] = []
                    current["items"].extend(findings_data)

                def build_tree_items(parent_item, tree_dict, current_path="", parent_full_path=""):
                    for segment, children in sorted(tree_dict.items()):
                        if segment in ["items", "partial_path"]:
                            continue

                        display_name = segment if segment else "/"
                        item_path = f"{current_path}/{segment}" if current_path else segment
                        full_path = f"/{item_path}" if item_path else "/"

                        path_has_direct_requests = full_path in direct_path_requests
                        has_children = children and any(
                            k not in ["items", "partial_path"] for k in children.keys()
                        )
                        findings_data = children.get("items", [])

                        if has_children:
                            dir_display = f"{SitemapIcons.FOLDER} {display_name}"
                            dir_item = QTreeWidgetItem(parent_item, [dir_display])
                            dir_item.setData(
                                0, Qt.UserRole,
                                {
                                    "type": "directory",
                                    "host": full_host,
                                    "path": full_path,
                                    "has_direct_requests": path_has_direct_requests,
                                },
                            )
                            dir_item.setForeground(0, QColor(COLOR_TEXT_BRIGHT))
                            dir_item.setFont(0, QFont("Consolas", 9, QFont.Bold))

                            if f"{full_host}|{full_path}" in expanded_dirs:
                                dir_item.setExpanded(True)

                            if path_has_direct_requests and direct_path_requests[full_path]:
                                self_findings = direct_path_requests[full_path]
                                method_counts = {}
                                has_any_params = False
                                has_any_issues = False

                                for finding_data in self_findings:
                                    method = finding_data["method"]
                                    method_counts[method] = method_counts.get(method, 0) + 1
                                    if finding_data["has_params"]:
                                        has_any_params = True
                                    if finding_data["has_issues"]:
                                        has_any_issues = True

                                primary_method = max(method_counts.items(), key=lambda x: x[1])[0]
                                endpoint_display, method_color = SitemapIcons.format_endpoint_display(
                                    f"{display_name} (self)", primary_method, has_any_params, has_any_issues,
                                )

                                self_item = QTreeWidgetItem(dir_item, [endpoint_display])
                                finding_indices = [fd["index"] for fd in self_findings]
                                self_item.setData(
                                    0, Qt.UserRole,
                                    {
                                        "type": "endpoint",
                                        "host": full_host,
                                        "path": full_path,
                                        "finding_indices": finding_indices,
                                        "method": primary_method,
                                        "has_params": has_any_params,
                                        "is_self": True,
                                    },
                                )
                                self_item.setForeground(0, QColor(method_color))
                                self_item.setFont(0, QFont("Consolas", 9))

                            build_tree_items(dir_item, children, item_path, full_path)

                        else:
                            if findings_data:
                                method_counts = {}
                                has_any_params = False
                                has_any_issues = False

                                for finding_data in findings_data:
                                    method = finding_data["method"]
                                    method_counts[method] = method_counts.get(method, 0) + 1
                                    if finding_data["has_params"]:
                                        has_any_params = True
                                    if finding_data["has_issues"]:
                                        has_any_issues = True

                                primary_method = max(method_counts.items(), key=lambda x: x[1])[0]
                                endpoint_display, method_color = SitemapIcons.format_endpoint_display(
                                    display_name, primary_method, has_any_params, has_any_issues,
                                )

                                endpoint_item = QTreeWidgetItem(parent_item, [endpoint_display])
                                finding_indices = [fd["index"] for fd in findings_data]
                                endpoint_item.setData(
                                    0, Qt.UserRole,
                                    {
                                        "type": "endpoint",
                                        "host": full_host,
                                        "path": full_path,
                                        "finding_indices": finding_indices,
                                        "method": primary_method,
                                        "has_params": has_any_params,
                                        "is_self": False,
                                    },
                                )
                                endpoint_item.setForeground(0, QColor(method_color))
                                endpoint_item.setFont(0, QFont("Consolas", 9))

                build_tree_items(host_item, path_tree)
                host_item.setExpanded(True)
                self.sitemap_tree.addTopLevelItem(host_item)

            host_count = len(hosts_data)
            total_endpoints = sum(len(paths_dict) for paths_dict in hosts_data.values())
            self.sitemap_stats.setText(f"{host_count} hosts • {total_endpoints} endpoints")

        finally:
            self.sitemap_tree.blockSignals(False)

    def _on_sitemap_filter_toggled(self, checked: bool):
        if not checked:
            self._sitemap_locked = False
            self._sitemap_selected_host = ""
            self.clear_sitemap_filter()

    def on_sitemap_selection(self, item, column):
        if not self.sitemap_filter_cb.isChecked():
            return

        data = item.data(0, Qt.UserRole)
        if not data:
            return

        item_type = data.get("type")

        if item_type == "endpoint":
            target_indices = set(data.get("finding_indices", []))
        elif item_type == "directory":
            target_indices = set(self._collect_directory_findings(item))
        elif item_type == "host":
            target_indices = set()
            for i in range(item.childCount()):
                target_indices.update(self._collect_directory_findings(item.child(i)))
            host = data.get("host", "")
            if not target_indices and host:
                for row in range(self.history_table.rowCount()):
                    fi = self.history_table.item(row, 0)
                    if fi is None:
                        continue
                    idx = fi.data(Qt.UserRole)
                    if idx is not None and idx < len(self.findings):
                        url = self.findings[idx].get("url", "")
                        try:
                            parsed = urlparse(url)
                            fh = f"{parsed.scheme}://{parsed.netloc}"
                            if fh == host:
                                target_indices.add(idx)
                        except Exception:
                            pass
        else:
            return

        if not target_indices:
            return

        self._sitemap_locked = True
        self._sitemap_selected_host = data.get("host", "")
        self._sitemap_target_indices = target_indices

        self.apply_filters()

        visible = sum(
            1 for row in range(self.history_table.rowCount())
            if not self.history_table.isRowHidden(row)
        )
        host = data.get("host", "")
        path = data.get("path", "")
        label = {
            "endpoint":  f"Viewing: {host}{path}",
            "directory": f"Viewing: {host}{path}/* ({visible} requests)",
            "host":      f"Viewing: {host} ({visible} requests)",
        }.get(item_type, "")
        self.toolbar_status.setText(label)

    def on_sitemap_item_expanded(self, item):
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "directory":
            text = item.text(0)
            if SitemapIcons.FOLDER in text:
                new_text = text.replace(SitemapIcons.FOLDER, SitemapIcons.FOLDER_OPEN, 1)
                item.setText(0, new_text)

    def on_sitemap_item_collapsed(self, item):
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "directory":
            text = item.text(0)
            if SitemapIcons.FOLDER_OPEN in text:
                new_text = text.replace(SitemapIcons.FOLDER_OPEN, SitemapIcons.FOLDER, 1)
                item.setText(0, new_text)

    def clear_sitemap_filter(self):
        self._sitemap_locked = False
        self._sitemap_selected_host = ""
        self._sitemap_target_indices = set()
        self.apply_filters()
        self.toolbar_status.setText("Showing all requests")

    def on_history_selection_changed(self):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)

        if finding_index is None or finding_index >= len(self.findings):
            logger.warning(f"Invalid finding index: {finding_index}")
            return

        finding = self.findings[finding_index]
        self.current_finding = finding

        request_file = finding.get("request_file")
        if request_file and os.path.exists(request_file):
            try:
                with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                    request_text = f.read()

                self.current_request_raw = request_text
                display_request = _pretty_request(request_text)

                # Detach syntax highlighter before loading large content so Qt
                # does not run per-line regex on the main thread and freeze the
                # UI.  The full content is always displayed — nothing is truncated.
                if len(display_request) > _MAX_HIGHLIGHT_SIZE:
                    self.request_highlighter.setDocument(None)
                else:
                    self.request_highlighter.setDocument(self.request_text.document())
                self.request_text.setPlainText(display_request)

            except IOError as e:
                logger.error(f"Failed to read request file: {e}")
                self.current_request_raw = ""
                self.request_text.setHtml(
                    f"<p style='color: {COLOR_CRITICAL};'>Failed to load request file</p>"
                )
        else:
            fallback_request = (
                f"{finding.get('method', 'GET')} {finding.get('url', '')} HTTP/1.1\n\n"
                f"(Request file not available)"
            )
            self.current_request_raw = fallback_request

            self.request_highlighter.setDocument(self.request_text.document())
            self.request_text.setPlainText(fallback_request)

        response_file = finding.get("response_file")
        if response_file and os.path.exists(response_file):
            try:
                with open(response_file, "r", encoding="utf-8", errors="replace") as f:
                    response_text = f.read()

                self.current_response_raw = response_text
                display_response = _pretty_response(response_text)

                # Detach syntax highlighter before loading large content so Qt
                # does not run per-line regex on the main thread.  The full
                # response is always loaded so analysis, search, and all tools
                # work on the complete content.
                if len(display_response) > _MAX_HIGHLIGHT_SIZE:
                    self.response_highlighter.setDocument(None)
                else:
                    self.response_highlighter.setDocument(self.response_text.document())
                self.response_text.setPlainText(display_response)

                if hasattr(self, 'perform_automatic_highlighting'):
                    self.perform_automatic_highlighting(response_text)

            except IOError as e:
                logger.error(f"Failed to read response file: {e}")
                self.current_response_raw = ""
                self.response_text.setHtml(
                    f"<p style='color: {COLOR_CRITICAL};'>Failed to load response file</p>"
                )
        else:
            self.current_response_raw = ""
            self.response_text.setHtml(
                f"<p style='color: #808080;'>(Response file not available)</p>"
            )

        if hasattr(self, 'perform_automatic_analysis'):
            # Analysis now runs in a background thread (SelectionAnalysisWorker).
            # _on_selection_analysis_finished handles load_vulnerabilities_organized
            # once the worker finishes, so we no longer use the return value here.
            self.perform_automatic_analysis(finding)

        # Update split view with current request/response
        self._update_split_view_texts()
        # GraphQL view — detect and update title buttons
        self._update_graphql_state(
            finding,
            self.current_request_raw,
            self.current_response_raw,
        )

        # Re-run search against the freshly loaded content so highlights and
        # match counts are always accurate for the current request/response.
        if hasattr(self, '_do_search_in_request'):
            if self.request_search_box.text():
                self._do_search_in_request()
            else:
                SearchHighlighter.clear_highlights(self.request_text)
                self.request_match_label.setText("0 matches")
        if hasattr(self, '_do_search_in_response'):
            if self.response_search_box.text():
                self._do_search_in_response()
            else:
                SearchHighlighter.clear_highlights(self.response_text)
                self.response_match_label.setText("0 matches")

    # ─────────────────────────────────────────────────────────────────────────
    # GraphQL detection and pretty-print view
    # ─────────────────────────────────────────────────────────────────────────

    def _detect_graphql(self, url: str, request_text: str, response_text: str) -> dict:
        """
        Return a dict describing a GraphQL transaction, or {} if not GraphQL.
        Keys: query, variables, operation_name, operation_type, introspection.
        """
        import json, re

        url_lower = (url or "").lower()
        gql_url_patterns = (
            "/graphql", "/gql", "/graphiql", "/playground",
            "graphql.json", "graphql.php", "graphql.asp",
        )
        url_hint = any(p in url_lower for p in gql_url_patterns)

        # Parse headers + body from raw request text
        req_headers: dict = {}
        body = ""
        if request_text:
            lines = request_text.split("\n")
            in_body = False
            for line in lines[1:]:
                stripped = line.rstrip("\r")
                if not in_body:
                    if stripped == "":
                        in_body = True
                    elif ":" in stripped:
                        k, _, v = stripped.partition(":")
                        req_headers[k.strip().lower()] = v.strip()
                else:
                    body += stripped + "\n"
            body = body.strip()

        ct = req_headers.get("content-type", "")
        ct_graphql = "application/graphql" in ct
        ct_json    = "application/json" in ct or ct == ""

        # Try to parse body as JSON to find query/variables
        query = ""
        variables: dict = {}
        operation_name = ""
        operation_type = "query"
        introspection  = False

        if body and ct_json:
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    raw_query = parsed.get("query", "")
                    if raw_query and isinstance(raw_query, str):
                        query = raw_query
                    variables   = parsed.get("variables") or {}
                    operation_name = parsed.get("operationName") or ""
            except (json.JSONDecodeError, ValueError):
                pass

        if not query and ct_graphql and body:
            query = body

        # Detect operation type
        q_stripped = query.lstrip()
        if q_stripped.startswith("mutation"):
            operation_type = "mutation"
        elif q_stripped.startswith("subscription"):
            operation_type = "subscription"
        else:
            operation_type = "query"

        # Introspection check
        introspection = "__schema" in query or "__type" in query or "IntrospectionQuery" in (operation_name or query)

        # Response side: look for GraphQL JSON shape
        resp_json_hint = False
        if response_text:
            # Extract JSON body from HTTP response
            try:
                resp_body_start = response_text.find("\n\n")
                if resp_body_start == -1:
                    resp_body_start = response_text.find("\r\n\r\n")
                resp_body = response_text[resp_body_start:].strip() if resp_body_start != -1 else response_text
                if resp_body.startswith("{"):
                    resp_parsed = json.loads(resp_body)
                    if isinstance(resp_parsed, dict) and ("data" in resp_parsed or "errors" in resp_parsed):
                        resp_json_hint = True
            except Exception:
                # Crude string test
                rb = response_text.lower()
                if ('"data"' in rb or '"errors"' in rb) and '"data":' in rb.replace(' ', ''):
                    resp_json_hint = True

        is_graphql = bool(url_hint or (query and (ct_graphql or ct_json)) or resp_json_hint)

        if not is_graphql:
            return {}

        return {
            "is_graphql":      True,
            "query":           query,
            "variables":       variables,
            "operation_name":  operation_name,
            "operation_type":  operation_type,
            "introspection":   introspection,
            "url_hint":        url_hint,
            "resp_json_hint":  resp_json_hint,
        }

    def _update_graphql_state(self, finding: dict, request_text: str, response_text: str) -> None:
        """Detect GraphQL and update header buttons accordingly."""
        url = finding.get("url", "") if finding else ""
        gql = self._detect_graphql(url, request_text, response_text)
        self._current_graphql = gql

        # Reset to raw mode whenever a new request is selected
        self._graphql_req_mode  = False
        self._graphql_resp_mode = False
        # Always return stacked widgets to raw view
        self.req_stack.setCurrentIndex(0)
        self.resp_stack.setCurrentIndex(0)
        self.req_graphql_btn.blockSignals(True)
        self.resp_graphql_btn.blockSignals(True)
        self.req_graphql_btn.setChecked(False)
        self.resp_graphql_btn.setChecked(False)
        self.req_graphql_btn.blockSignals(False)
        self.resp_graphql_btn.blockSignals(False)

        if gql:
            self.req_graphql_btn.setText("⬡ GraphQL")
            self.resp_graphql_btn.setText("⬡ GraphQL")
            # Only show req btn when there is an actual query body
            self.req_graphql_btn.setVisible(bool(gql.get("query") or gql.get("url_hint")))
            self.resp_graphql_btn.setVisible(bool(gql.get("resp_json_hint")))
        else:
            self.req_graphql_btn.setVisible(False)
            self.resp_graphql_btn.setVisible(False)

    def _toggle_graphql_req(self) -> None:
        """Toggle request panel between raw HTTP view and GraphQL section panels."""
        self._graphql_req_mode = self.req_graphql_btn.isChecked()
        if self._graphql_req_mode:
            self._populate_gql_req_panels(self._current_graphql)
            self.req_stack.setCurrentIndex(1)
            self.req_graphql_btn.setText("◎ Raw")
        else:
            self.req_stack.setCurrentIndex(0)
            raw = self.current_request_raw
            display = _pretty_request(raw)
            if len(display) <= _MAX_HIGHLIGHT_SIZE:
                self.request_highlighter.setDocument(self.request_text.document())
            self.request_text.setPlainText(display)
            self.req_graphql_btn.setText("⬡ GraphQL")

    def _toggle_graphql_resp(self) -> None:
        """Toggle response panel between raw HTTP view and GraphQL section panels."""
        self._graphql_resp_mode = self.resp_graphql_btn.isChecked()
        if self._graphql_resp_mode:
            self._populate_gql_resp_panels(self.current_response_raw, self._current_graphql)
            self.resp_stack.setCurrentIndex(1)
            self.resp_graphql_btn.setText("◎ Raw")
        else:
            self.resp_stack.setCurrentIndex(0)
            raw = self.current_response_raw
            display = _pretty_response(raw)
            if len(display) <= _MAX_HIGHLIGHT_SIZE:
                self.response_highlighter.setDocument(self.response_text.document())
            self.response_text.setPlainText(display)
            self.resp_graphql_btn.setText("⬡ GraphQL")

    # ── GraphQL panel helpers ─────────────────────────────────────────────

    def _make_gql_panel(self, title: str, title_color: str, highlight: str = None):
        """
        Create a titled collapsible section panel used inside the GraphQL splitter.
        Returns (panel_widget, QTextEdit).
        highlight: "gql" for GraphQL syntax coloring, "json" for JSON, None for plain text.
        """
        panel = QWidget()
        panel.setMinimumHeight(50)
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(0)

        hdr = QWidget()
        hdr.setFixedHeight(22)
        hdr.setStyleSheet(
            f"background-color: {COLOR_ELEVATED_BG};"
            f" border-bottom: 1px solid {COLOR_BORDER};"
        )
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(10, 0, 8, 0)
        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"color: {title_color}; font-weight: 700;"
            f" font-size: 10px; letter-spacing: 1px;"
        )
        hl.addWidget(lbl)
        hl.addStretch()
        pl.addWidget(hdr)

        te = QTextEdit()
        te.setReadOnly(True)
        te.setFont(QFont("Consolas", 9))
        te.setLineWrapMode(QTextEdit.WidgetWidth)
        te.setStyleSheet(
            f"QTextEdit {{ background-color: {COLOR_DARK_BG};"
            f" border: none; color: {COLOR_TEXT}; padding: 4px; }}"
        )
        if highlight == "gql":
            te._hl = GQLSyntaxHighlighter(te.document())
        elif highlight == "json":
            te._hl = JSONSyntaxHighlighter(te.document())
        pl.addWidget(te)
        return panel, te

    def _populate_gql_req_panels(self, gql: dict) -> None:
        """Fill the request GraphQL section panels with content from `gql`."""
        import json

        query     = gql.get("query", "")
        variables = gql.get("variables") or {}
        op_name   = gql.get("operation_name", "")
        op_type   = gql.get("operation_type", "query")
        is_intro  = gql.get("introspection", False)

        # QUERY
        self.req_gql_query_text.setPlainText(query.strip() if query else "(no query body)")
        self.req_gql_query_panel.setVisible(True)

        # VARIABLES
        if variables:
            self.req_gql_vars_text.setPlainText(json.dumps(variables, indent=2))
        else:
            self.req_gql_vars_text.setPlainText("")
        self.req_gql_vars_panel.setVisible(True)

        # OPERATION NAME
        if op_name:
            info_lines = [f"Name :  {op_name}", f"Type :  {op_type}"]
            if is_intro:
                info_lines.append("")
                info_lines.append("⬡ Introspection query")
            self.req_gql_opname_text.setPlainText("\n".join(info_lines))
            self.req_gql_opname_panel.setVisible(True)
        else:
            self.req_gql_opname_panel.setVisible(False)

        # Size the splitter: query ~57%, vars ~30%, opname ~13%
        panels = [
            self.req_gql_query_panel,
            self.req_gql_vars_panel,
            self.req_gql_opname_panel,
        ]
        # Proportional weights per panel (visible panels share the total)
        weights = [700, 250, 50]
        sizes = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self.req_gql_splitter.setSizes(sizes)

    def _populate_gql_resp_panels(self, response_text: str, gql: dict) -> None:
        """Fill the response GraphQL section panels with content parsed from the HTTP response."""
        import json

        # Extract body
        resp_body = ""
        if response_text:
            pos = response_text.find("\n\n")
            if pos == -1:
                pos = response_text.find("\r\n\r\n")
            resp_body = response_text[pos:].strip() if pos != -1 else response_text.strip()

        parsed = None
        if resp_body:
            try:
                parsed = json.loads(resp_body)
            except (json.JSONDecodeError, ValueError):
                pass

        data   = parsed.get("data")       if isinstance(parsed, dict) else None
        errors = parsed.get("errors")     if isinstance(parsed, dict) else None
        exts   = parsed.get("extensions") if isinstance(parsed, dict) else None

        # ERRORS
        if errors:
            if isinstance(errors, list):
                lines: list = []
                for idx, err in enumerate(errors, 1):
                    msg  = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    locs = err.get("locations", [])     if isinstance(err, dict) else []
                    path = err.get("path", [])           if isinstance(err, dict) else []
                    lines.append(f"[{idx}]  {msg}")
                    for loc in locs:
                        lines.append(f"       at line {loc.get('line','?')}, column {loc.get('column','?')}")
                    if path:
                        lines.append(f"       path: {' → '.join(str(p) for p in path)}")
                    lines.append("")
                self.resp_gql_errors_text.setPlainText("\n".join(lines).rstrip())
            else:
                self.resp_gql_errors_text.setPlainText(json.dumps(errors, indent=2))
            self.resp_gql_errors_panel.setVisible(True)
        else:
            self.resp_gql_errors_panel.setVisible(False)

        # DATA
        if parsed is not None:
            if data is None:
                self.resp_gql_data_text.setPlainText("(null)")
            else:
                self.resp_gql_data_text.setPlainText(json.dumps(data, indent=2))
            self.resp_gql_data_panel.setVisible(True)
        else:
            self.resp_gql_data_text.setPlainText("(could not parse response body as JSON)")
            self.resp_gql_data_panel.setVisible(True)

        # EXTENSIONS
        if exts:
            self.resp_gql_exts_text.setPlainText(json.dumps(exts, indent=2))
            self.resp_gql_exts_panel.setVisible(True)
        else:
            self.resp_gql_exts_panel.setVisible(False)

        # Size: errors ~15%, data ~70%, extensions ~15%
        panels = [
            self.resp_gql_errors_panel,
            self.resp_gql_data_panel,
            self.resp_gql_exts_panel,
        ]
        weights = [150, 700, 150]
        sizes = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self.resp_gql_splitter.setSizes(sizes)

    def update_scope_hosts(self, slug: str, domain: str, subdomain: str):
        from . import project_manager as pm

        self._scope_slug = slug
        self._scope_domain = domain
        self._scope_subdomain = subdomain

        self._scope_rules = pm.load_scope_rules(slug) if slug else []

        all_hosts = pm.get_scope_hosts(slug, "", "")
        normalised = set()
        for h in all_hosts:
            h = h.lower().strip()
            for scheme in ("https://", "http://"):
                if h.startswith(scheme):
                    h = h[len(scheme):]
            h = h.split("/")[0]
            if h:
                normalised.add(h)
        self._scope_hosts = normalised

        if self._scope_rules:
            active_includes = sum(
                1 for r in self._scope_rules
                if r.get("type") == "include" and r.get("enabled", True)
            )
            count = active_includes
        else:
            count = len(normalised)

        if hasattr(self, "scope_filter_cb"):
            self.scope_filter_cb.setText(
                f"In Scope Only"
            )
            if count > 0 and not self._scope_hosts_previously_set:
                self.scope_filter_cb.setChecked(True)
            self._scope_hosts_previously_set = True

        if hasattr(self, "history_table"):
            self._sitemap_locked = False
            self._sitemap_selected_host = ""
            self._sitemap_target_indices = set()
            self._sitemap_pending_rebuild = False
            self.apply_filters()

    def _on_header_clicked(self, logical_index: int):
        """Toggle sort direction when a column header is clicked.
        Uses manually tracked sort state so ascending/descending always flips correctly."""
        header = self.history_table.horizontalHeader()

        if self._sort_col == logical_index:
            # Same column — flip direction
            new_order = (
                Qt.DescendingOrder
                if self._sort_order == Qt.AscendingOrder
                else Qt.AscendingOrder
            )
        else:
            # New column — always start ascending
            new_order = Qt.AscendingOrder

        # Disable sorting during the sort call to protect UserRole data,
        # then do the sort, then re-disable (we manage sorting entirely manually).
        self.history_table.setSortingEnabled(True)
        self.history_table.sortItems(logical_index, new_order)
        self.history_table.setSortingEnabled(False)

        # Update tracked state and show indicator
        self._sort_col   = logical_index
        self._sort_order = new_order
        header.setSortIndicator(logical_index, new_order)

    def apply_filters(self):
        search_text = self.search_box.text().lower()
        param_filter = self.param_filter.currentText()
        method_filter = self.method_combo.currentText()
        status_filter = self.status_combo.currentText()
        mime_filter = self.mime_combo.currentText()
        notes_filter = self.notes_filter.currentText()
        issue_filter_text = (
            self.issue_filter.currentText()
            if hasattr(self, "issue_filter")
            else "All Issues"
        )

        issue_filter_key = None
        if hasattr(self, "issue_filter") and self.issue_filter.currentIndex() >= 0:
            issue_filter_key = self.issue_filter.itemData(
                self.issue_filter.currentIndex(), Qt.UserRole
            )

        issue_filter = issue_filter_key if issue_filter_key else issue_filter_text

        visible_count = 0

        for row in range(self.history_table.rowCount()):
            finding_index = self.history_table.item(row, 0).data(Qt.UserRole)

            if finding_index is None or finding_index >= len(self.findings):
                self.history_table.setRowHidden(row, True)
                continue

            finding = self.findings[finding_index]
            should_show = self._matches_filters(
                finding, finding_index,
                search_text, param_filter, method_filter,
                status_filter, mime_filter, notes_filter, issue_filter, row,
            )

            # Enforce active sitemap selection alongside toolbar filters
            if should_show and self._sitemap_locked and self.sitemap_filter_cb.isChecked():
                if finding_index not in self._sitemap_target_indices:
                    should_show = False

            self.history_table.setRowHidden(row, not should_show)

            if should_show:
                visible_count += 1

        self._schedule_sitemap_rebuild()

        total_rows = self.history_table.rowCount()
        if visible_count < total_rows:
            self.toolbar_status.setText(f"Showing {visible_count} of {total_rows} requests")
        else:
            self.toolbar_status.setText(f"Showing all {total_rows} requests")

    def _matches_filters(
        self,
        finding: Dict[str, Any],
        finding_index: int,
        search_text: str,
        param_filter: str,
        method_filter: str,
        status_filter: str,
        mime_filter: str,
        notes_filter: str,
        issue_filter: str,
        row: int,
    ) -> bool:
        if getattr(self, "scope_filter_cb", None) and self.scope_filter_cb.isChecked():
            url = finding.get("url", "")
            if not self._is_in_scope(url):
                return False

        if search_text:
            url = finding.get("url", "").lower()
            params = str(finding.get("params", {})).lower()
            method = finding.get("method", "").lower()
            if search_text not in url and search_text not in params and search_text not in method:
                return False

        if method_filter != "All":
            finding_method = finding.get("method", "").upper()
            if finding_method != method_filter.upper():
                return False

        if status_filter != "All":
            status = finding.get("status", 0)
            if status_filter == "2xx" and not (200 <= status < 300):
                return False
            elif status_filter == "3xx" and not (300 <= status < 400):
                return False
            elif status_filter == "4xx" and not (400 <= status < 500):
                return False
            elif status_filter == "5xx" and not (500 <= status < 600):
                return False

        if mime_filter != "All":
            mime_type = self.detect_mime_type(finding).lower()
            if mime_filter == "HTML" and "html" not in mime_type:
                return False
            elif mime_filter == "JSON" and "json" not in mime_type:
                return False
            elif mime_filter == "JavaScript" and "javascript" not in mime_type:
                return False
            elif mime_filter == "CSS" and "css" not in mime_type:
                return False
            elif mime_filter == "XML" and "xml" not in mime_type:
                return False
            elif mime_filter == "Images" and not any(
                img in mime_type for img in ["image", "png", "jpg", "jpeg", "gif", "webp"]
            ):
                return False
            elif mime_filter == "Other":
                common_types = ["html", "json", "javascript", "css", "xml",
                                "image", "png", "jpg", "jpeg", "gif", "webp"]
                if any(t in mime_type for t in common_types):
                    return False

        if notes_filter != "All":
            note_key = finding.get("seq", finding_index)
            has_note = note_key in self.notes_storage
            if notes_filter == "With Notes" and not has_note:
                return False
            elif notes_filter == "Without Notes" and has_note:
                return False

        if param_filter != "All":
            url = finding.get("url", "")
            method = finding.get("method", "").upper()
            has_url_params = "?" in url and len(url.split("?", 1)[1]) > 0
            has_body_params = False
            if method in ["POST", "PUT", "PATCH"]:
                request_file = finding.get("request_file")
                if request_file and os.path.exists(request_file):
                    try:
                        with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                            if "\n\n" in content:
                                body = content.split("\n\n", 1)[1].strip()
                                has_body_params = len(body) > 0
                    except:
                        pass

            if param_filter == "With Params" and not (has_url_params or has_body_params):
                return False
            elif param_filter == "Without Params" and (has_url_params or has_body_params):
                return False
            elif param_filter == "In URL" and not has_url_params:
                return False
            elif param_filter == "In Body" and not has_body_params:
                return False

        if issue_filter and issue_filter != "All Issues":
            if issue_filter.startswith("───"):
                return True

            filter_text = issue_filter.strip()
            params = finding.get("params", {})
            if not params:
                return False

            has_issue = False
            for param_name, detections in params.items():
                category = param_name.split()[0] if " " in param_name else param_name
                category_display = VulnerabilityCategories.CATEGORY_HEADERS.get(category, category)
                if " " in category_display:
                    category_display = category_display.split(" ", 1)[1]

                if (filter_text.lower() in category.lower()
                        or filter_text.lower() in category_display.lower()):
                    has_issue = True
                    break

                det_list = detections if isinstance(detections, (list, set)) else [detections]
                det_str = " ".join(str(d) for d in det_list)
                if filter_text.lower() in det_str.lower():
                    has_issue = True
                    break

            if not has_issue:
                return False

        return True

    def _is_in_scope(self, url: str) -> bool:
        has_rules = hasattr(self, "_scope_rules") and self._scope_rules
        has_hosts = hasattr(self, "_scope_hosts") and self._scope_hosts

        if not has_rules and not has_hosts:
            return True

        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            scheme = parsed.scheme.lower() or "http"
            host = (parsed.hostname or "").lower()
            if not host:
                return False
            port = str(parsed.port or ("443" if scheme == "https" else "80"))
        except Exception:
            return False

        if has_rules:
            include_rules = [r for r in self._scope_rules if r.get("enabled", True) and r.get("type") == "include"]
            exclude_rules = [r for r in self._scope_rules if r.get("enabled", True) and r.get("type") == "exclude"]

            if include_rules:
                matched_include = False
                for rule in include_rules:
                    if self._match_rule(rule, host, scheme, port):
                        matched_include = True
                        break
                if not matched_include:
                    return False

            for rule in exclude_rules:
                if self._match_rule(rule, host, scheme, port):
                    return False

            return True

        if has_hosts:
            for sh in self._scope_hosts:
                if host == sh or host.endswith("." + sh):
                    return True
            return False

        return True

    def _match_rule(self, rule, host, scheme, port):
        r_proto = rule.get("protocol", "any")
        if r_proto not in ("any", "") and r_proto != scheme:
            return False
        r_port = rule.get("port", "")
        if r_port and str(r_port) != port:
            return False
        r_host = rule.get("host", "").lower()
        if not r_host:
            return True
        if r_host.startswith("*."):
            base = r_host[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == r_host:
            return True
        if rule.get("all_subdomains", False) and host.endswith("." + r_host):
            return True
        return False

    def update_issue_filter_dropdown(self):
        if not hasattr(self, 'issue_filter'):
            return

        self.issue_filter.blockSignals(True)
        current_selection = self.issue_filter.currentText()
        self.issue_filter.clear()
        self.issue_filter.addItem("All Issues")

        all_issues = set()

        for finding in self.findings:
            params = finding.get("params", {})
            if not params:
                continue

            for param_name, detections in params.items():
                category = param_name.split()[0] if " " in param_name else param_name
                if category:
                    all_issues.add(category)

                det_list = detections if isinstance(detections, (list, set)) else [detections]
                for detection in det_list:
                    detection_str = str(detection)
                    for vuln_type in VulnerabilityCategories.VULNERABILITY_TYPES:
                        if vuln_type in detection_str:
                            all_issues.add(vuln_type)

        sorted_issues = sorted(all_issues)

        categories = {
            "XSS Issues": [],
            "SQL Issues": [],
            "Injection Issues": [],
            "Authentication": [],
            "Sensitive Data": [],
            "Other": [],
        }

        for issue in sorted_issues:
            if "XSS" in issue or "DOM" in issue or "JQUERY" in issue:
                categories["XSS Issues"].append(issue)
            elif "SQL" in issue:
                categories["SQL Issues"].append(issue)
            elif any(x in issue for x in ["RCE", "COMMAND", "CODE", "INJECTION",
                                           "XXE", "SSRF", "LFI", "RFI", "SSTI"]):
                categories["Injection Issues"].append(issue)
            elif any(x in issue for x in ["AUTH", "SESSION", "CSRF", "IDOR"]):
                categories["Authentication"].append(issue)
            elif any(x in issue for x in ["API_KEY", "PASSWORD", "SENSITIVE",
                                           "EMAIL", "INTERNAL_IP"]):
                categories["Sensitive Data"].append(issue)
            else:
                categories["Other"].append(issue)

        for category_name, issues_list in categories.items():
            if issues_list:
                self.issue_filter.addItem(f"─── {category_name} ───")
                model = self.issue_filter.model()
                index = self.issue_filter.count() - 1
                item = model.item(index)
                if item:
                    item.setEnabled(False)
                    item.setForeground(QColor(COLOR_ACCENT))

                for issue in issues_list:
                    display_name = VulnerabilityCategories.CATEGORY_HEADERS.get(issue, issue)
                    display_text = display_name
                    if " " in display_name:
                        display_text = display_name.split(" ", 1)[1]

                    self.issue_filter.addItem(f"  {display_text}")
                    item_index = self.issue_filter.count() - 1
                    self.issue_filter.setItemData(item_index, issue, Qt.UserRole)

        index = self.issue_filter.findText(current_selection)
        if index >= 0:
            self.issue_filter.setCurrentIndex(index)
        else:
            self.issue_filter.setCurrentIndex(0)

        self.issue_filter.blockSignals(False)

        total_issues = len(sorted_issues)
        if total_issues > 0:
            logger.info(f"Issue filter updated: {total_issues} unique issue types found")

    def detect_mime_type(self, finding: Dict[str, Any]) -> str:
        # Fast path: content_type is already stored in the finding dict by the addon
        ct = (finding.get("content_type") or "").strip()
        if ct:
            return ct.split(";")[0].strip()

        # No content-type header → blank for bodyless responses (redirects, 204, etc.)
        if not (finding.get("response_length") or 0):
            return ""
        # The column shows a best-guess and the file-based check is cheap enough
        # for the single-row case (selection) but too expensive per-row in bursts.
        if not getattr(self, "_bulk_loading", False):
            response_file = finding.get("response_file")
            if response_file and os.path.exists(response_file):
                try:
                    with open(response_file, "rb") as f:
                        # Read enough to capture all headers (responses can have many)
                        content = f.read(4096)

                    text = content.decode("utf-8", errors="ignore")

                    # Priority 1: Content-Type response header (most authoritative)
                    for line in text.split("\n"):
                        if line.lower().startswith("content-type:"):
                            ct = line.split(":", 1)[1].strip().split(";")[0].strip()
                            if ct:
                                return ct
                            break

                    # Priority 2: body magic bytes (when Content-Type header is absent)
                    sep = "\r\n\r\n" if "\r\n\r\n" in text else "\n\n"
                    body = text.split(sep, 1)[1].lstrip() if sep in text else ""
                    if body.startswith("{") or body.startswith("["):
                        return "application/json"
                    elif body.lower().startswith("<!doctype") or "<html" in body[:200].lower():
                        return "text/html"
                    elif body.startswith("<?xml"):
                        return "application/xml"
                except Exception:
                    pass

        url = finding.get("url", "").lower()
        if url.endswith(".js"):
            return "application/javascript"
        elif url.endswith(".css"):
            return "text/css"
        elif url.endswith(".json"):
            return "application/json"
        elif url.endswith(".xml"):
            return "application/xml"
        elif url.endswith(".png"):
            return "image/png"
        elif url.endswith(".jpg") or url.endswith(".jpeg"):
            return "image/jpeg"
        elif url.endswith(".gif"):
            return "image/gif"

        return "text/plain"

    def extract_url_parameters(self, url: str) -> List[Dict[str, str]]:
        params = []
        if "?" in url:
            query_string = url.split("?")[1]
            param_pairs = query_string.split("&")

            for pair in param_pairs:
                if "=" in pair:
                    key, value = pair.split("=", 1)
                    params.append({
                        "key": key,
                        "value": value,
                        "encoded": urllib.parse.unquote(value) != value,
                    })
                else:
                    params.append({"key": pair, "value": "", "encoded": False})

        return params

    def display_request_with_highlighted_params(self, request_text: str) -> str:
        if not request_text:
            return request_text

        lines = request_text.split("\n")
        if not lines:
            return request_text

        first_line = lines[0]
        if "?" in first_line:
            parts = first_line.split("?", 1)
            if len(parts) == 2:
                base_url, query = parts
                highlighted = f'<span style="color: {COLOR_TEXT_BRIGHT};">{base_url}</span>'
                highlighted += f'<span style="color: {COLOR_ACCENT};">?</span>'

                params = query.split("&")
                colored_params = []
                for param in params:
                    if "=" in param:
                        key, value = param.split("=", 1)
                        colored_params.append(
                            f'<span style="color: {COLOR_SUCCESS};">{key}</span>='
                            f'<span style="color: {COLOR_MEDIUM};">{value}</span>'
                        )
                    else:
                        colored_params.append(
                            f'<span style="color: {COLOR_SUCCESS};">{param}</span>'
                        )

                highlighted += f'<span style="color: {COLOR_ACCENT};">&</span>'.join(colored_params)
                lines[0] = highlighted

        html = f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 10px;
        }}
        </style>
        </head>
        <body>
        <div class="request-line">{lines[0]}</div>
        """

        for line in lines[1:]:
            if line.strip() == "":
                html += '<hr style="border: 1px dashed #444; margin: 10px 0;">'
                break
            if ":" in line:
                key, value = line.split(":", 1)
                html += f'<div><span style="color: {COLOR_LOW};">{key}</span>: <span style="color: {COLOR_TEXT_BRIGHT};">{value}</span></div>'
            else:
                html += f"<div>{line}</div>"

        html += "</body></html>"
        return html

    # =========================================================================
    # ⚡ CONTEXT MENU — show_history_context_menu
    # CHANGE: Added "⚡ Send to Param Miner" action after Send to Intruder
    # =========================================================================
    def show_history_context_menu(self, position):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)

        if finding_index is None or finding_index >= len(self.findings):
            return

        finding = self.findings[finding_index]

        menu = QMenu()
        menu.setStyleSheet(
            f"""
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {COLOR_BORDER};
                margin: 4px 0;
            }}
        """
        )

        # Collect all selected rows for multi-select actions
        selected_rows = sorted(set(
            self.history_table.item(i.row(), 0).row()
            for i in self.history_table.selectedItems()
            if self.history_table.item(i.row(), 0) is not None
        ))
        _multi_select = len(selected_rows) > 1

        copy_url_action      = menu.addAction(" Copy URL")
        copy_request_action  = menu.addAction(" Copy Request (Raw)")
        copy_response_action = menu.addAction(" Copy Response (Raw)")

        copy_selected_urls_action = menu.addAction(f"📋 Copy Selected URLs ({len(selected_rows)})")
        copy_selected_urls_action.setToolTip("Copy all selected URLs to clipboard, one per line")
        copy_selected_urls_action.setVisible(_multi_select)

        menu.addSeparator()

        send_to_comparer_action = menu.addAction(" Send to Comparer")
        send_to_scanner_action  = menu.addAction("  Send to Scanner")
        send_to_repeater_action = menu.addAction(" Send to Repeater")
        send_to_intruder_action = menu.addAction(" Send to Intruder")

        menu.addSeparator()
        send_to_param_miner_action = menu.addAction(" Send to Param Miner")
        send_to_param_miner_action.setToolTip("Discover hidden parameters for this URL  (Ctrl+P)")
        send_to_js_miner_action = menu.addAction(" Send to JS Miner")
        send_to_js_miner_action.setToolTip("Analyse this JS file for secrets, endpoints and vulnerabilities")
        send_to_api_key_action = menu.addAction(" Send to API Keys")
        send_to_api_key_action.setToolTip("Send URL to API Key scanner (Fetch mode)")
        send_to_bypass_action = menu.addAction(" Send to Bypass")
        send_to_bypass_action.setToolTip("Send full HTTP request to WAF Bypass tab for evasion testing")
        send_to_poc_action = menu.addAction(" Send to PoC Generator")
        send_to_poc_action.setToolTip("Generate a proof-of-concept exploit for this request")
        send_to_jwt_action = menu.addAction(" Send to JWT Analyzer")
        send_to_jwt_action.setToolTip("Test JWT tokens in this request for alg:none, confusion attacks, weak secrets and more")
        send_to_bruteforce_action = menu.addAction(" Content Bruteforce")
        send_to_bruteforce_action.setToolTip("Run feroxbuster content discovery on this URL's host (Dashboard task)")

        menu.addSeparator()
        send_to_endpoints_action = menu.addAction(" Send to Attack Surface")
        send_to_endpoints_action.setToolTip("Record this entry in the Attack Surface tab")
        send_to_report_action = menu.addAction(" Report Bug")
        send_to_report_action.setToolTip("Create a bug report from this request in the Reports tab")
        # ─────────────────────────────────────────────────────────────────

        menu.addSeparator()

        analyze_action = menu.addAction(" Analyze Request")
        ai_analyze_action = menu.addAction("✨ AI Analyze")
        ai_analyze_action.setToolTip("Open AI security chat to analyze this request/response  (Ctrl+Shift+C)")
        send_to_ai_action = menu.addAction("✨ Send to AI")
        send_to_ai_action.setToolTip("Pin this request/response in AI chat — ask anything about it")

        menu.addSeparator()

        highlight_menu   = menu.addMenu(" Highlight")
        highlight_red    = highlight_menu.addAction(" Red")
        highlight_orange = highlight_menu.addAction(" Orange")
        highlight_yellow = highlight_menu.addAction(" Yellow")
        highlight_green  = highlight_menu.addAction(" Green")
        highlight_blue   = highlight_menu.addAction(" Blue")
        highlight_purple = highlight_menu.addAction(" Purple")
        highlight_clear  = highlight_menu.addAction(" Clear Highlight")

        menu.addSeparator()

        delete_action   = menu.addAction("🗑 Delete Request")

        menu.addSeparator()

        add_note_action = menu.addAction("Add/Edit Note")

        action = menu.exec_(self.history_table.viewport().mapToGlobal(position))

        if action == copy_url_action:
            self.copy_url(finding)
        elif action == copy_selected_urls_action:
            self._copy_selected_urls(selected_rows)
        elif action == copy_request_action:
            self.copy_request_raw(finding)
        elif action == copy_response_action:
            self.copy_response_raw(finding)
        elif action == send_to_comparer_action:
            self.prepare_comparison_from_selection(finding_index)
        elif action == send_to_scanner_action:
            self.send_to_scanner(finding_index)
        elif action == send_to_repeater_action:
            self.send_to_repeater(finding_index)
        elif action == send_to_intruder_action:
            self.send_to_intruder(finding_index)
        # ── NEW handler ───────────────────────────────────────────────────
        elif action == send_to_param_miner_action:
            self._send_to_param_miner(finding_index)
        elif action == send_to_api_key_action:
            self._send_to_api_key(finding_index)
        elif action == send_to_js_miner_action:
            self._send_to_js_miner(finding)
        elif action == send_to_bypass_action:
            self._send_to_bypass(finding_index)
        elif action == send_to_poc_action:
            self._send_to_poc(finding_index)
        elif action == send_to_jwt_action:
            self._send_to_jwt(finding_index)
        elif action == send_to_bruteforce_action:
            self._send_to_content_bruteforce(finding_index)
        elif action == send_to_endpoints_action:
            self._send_to_endpoints(finding_index)
        elif action == send_to_report_action:
            self._send_to_report(finding_index)
        # ─────────────────────────────────────────────────────────────────
        elif action == analyze_action:
            # Analysis is always visible in the Inspector panel on the right
            self.current_analysis_request  = self._load_request_text(finding)
            self.current_analysis_response = self._load_response_text(finding)
            self.refresh_analysis()
        elif action == ai_analyze_action:
            self._ai_analyze_from_finding(finding)
        elif action == send_to_ai_action:
            self._send_to_ai_from_finding(finding)
        elif action == delete_action:
            self.delete_request(row, finding_index)
        elif action == add_note_action:
            self.quick_add_note(row, finding_index)
        elif action == highlight_red:
            self.highlight_row(row, COLOR_CRITICAL)
        elif action == highlight_orange:
            self.highlight_row(row, COLOR_HIGH)
        elif action == highlight_yellow:
            self.highlight_row(row, COLOR_MEDIUM)
        elif action == highlight_green:
            self.highlight_row(row, COLOR_SUCCESS)
        elif action == highlight_blue:
            self.highlight_row(row, COLOR_LOW)
        elif action == highlight_purple:
            self.highlight_row(row, COLOR_ACCENT_SECONDARY)
        elif action == highlight_clear:
            self.clear_row_highlight(row)

    def _send_to_report(self, finding_index: int = None):
        """Open the Report Bug dialog pre-filled from this HTTP history entry."""
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return
        finding = self.findings[finding_index]
        parent_gui = getattr(self, "parent_gui", self)
        report_tab = getattr(parent_gui, "report_tab", None)
        if report_tab is None or not hasattr(report_tab, "add_from_finding"):
            QMessageBox.warning(self, "Report Bug", "Reports tab not found.")
            return
        report_tab.add_from_finding(finding)
        # Switch to Reports tab so the user lands there after saving
        tab_widget = getattr(parent_gui, "tab_widget", None)
        if tab_widget:
            for i in range(tab_widget.count()):
                if "Report" in tab_widget.tabText(i):
                    tab_widget.setCurrentIndex(i)
                    break

    # =========================================================================
    # =========================================================================
    # ⚡ _send_to_param_miner
    # =========================================================================
    def _send_to_param_miner(self, finding_index: int = None):
        """
        Send the selected request's URL to the Param Miner tab.
        Switches focus to Param Miner inside the Tools tab and auto-starts the scan.
        Called from right-click menu and Ctrl+P shortcut.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None:
            return

        if finding_index >= len(self.findings):
            return

        url = self.findings[finding_index].get("url", "").strip()
        if not url:
            QMessageBox.warning(self, "Param Miner", "No URL found for this request.")
            return

        param_miner_ref = getattr(self, "param_miner_ref", None)
        if param_miner_ref is None:
            QMessageBox.warning(
                self, "Param Miner",
                "Param Miner reference not found. "
                "Check that param_miner_ref is set in hunt_gui.py."
            )
            return

        # Switch to Tools → Param Miner sub-tab
        parent_gui = getattr(self, "parent_gui", self)
        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("Param Miner")

        # Extract Cookie header
        cookies = ""
        finding = self.findings[finding_index]
        req_file = finding.get("request_file", "") or finding.get("request_path", "")
        if req_file and os.path.isfile(req_file):
            try:
                with open(req_file, "r", encoding="utf-8", errors="replace") as _rf:
                    for _line in _rf:
                        if _line.strip().lower().startswith("cookie:"):
                            cookies = _line.strip()[7:].strip()
                            break
            except Exception:
                pass
        if not cookies:
            req_text = finding.get("request_text", "") or finding.get("request", "")
            for _line in req_text.splitlines():
                if _line.strip().lower().startswith("cookie:"):
                    cookies = _line.strip()[7:].strip()
                    break
        if not cookies:
            hdrs = finding.get("headers", finding.get("request_headers", {}))
            if isinstance(hdrs, dict):
                for _k, _v in hdrs.items():
                    if _k.lower() == "cookie":
                        cookies = _v; break

        param_miner_ref.send_url(url, cookies=cookies)
        self.toolbar_status.setText(f"⚡ Sent to Param Miner → {url[:60]}{'...' if len(url) > 60 else ''}")
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    def _send_to_api_key(self, finding_index: int = None):
        """Send the selected request's URL to the Key Tester (API Key) tab inside Tools."""
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None:
            return
        if finding_index >= len(self.findings):
            return

        url    = self.findings[finding_index].get("url", "").strip()
        method = self.findings[finding_index].get("method", "GET")
        if not url:
            QMessageBox.warning(self, "Key Tester", "No URL found for this request.")
            return

        api_key_tab = getattr(self, "api_key_tab_ref", None)
        if api_key_tab is None:
            api_key_tab = getattr(self, "api_key_tab", None)

        if api_key_tab is None or not hasattr(api_key_tab, "add_from_history"):
            QMessageBox.warning(self, "Key Tester",
                                "Key Tester tab not found.")
            return

        # Switch to Tools → Key Tester sub-tab
        parent_gui = getattr(self, "parent_gui", self)
        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("Key Tester")

        api_key_tab.add_from_history(url, method)
        self.toolbar_status.setText(f"⚿ Sent to Key Tester → {url[:60]}{'...' if len(url) > 60 else ''}")
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    def _send_to_js_miner(self, finding: dict = None):
        """Send selected request to JS Miner sub-tab inside Tools."""
        if finding is None:
            idx = self._get_selected_finding_index()
            if idx is None or idx >= len(self.findings):
                return
            finding = self.findings[idx]

        url = finding.get("url", "").strip()
        if not url:
            QMessageBox.warning(self, "JS Miner", "No URL found for this request.")
            return

        js_miner = getattr(self, "js_miner_ref", None)
        if js_miner is None or not hasattr(js_miner, "send_finding"):
            QMessageBox.warning(self, "JS Miner", "JS Miner tab not found.")
            return

        # Switch to Tools → JS Miner sub-tab
        parent_gui = getattr(self, "parent_gui", self)
        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("JS Miner")

        js_miner.send_finding(finding)
        self.toolbar_status.setText(f"⛏️ Sent to JS Miner → {url[:60]}{'...' if len(url) > 60 else ''}")
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # =========================================================================
    # 🧪 _send_to_poc
    # =========================================================================
    def _send_to_poc(self, finding_index: int = None):
        """
        Send the selected request to the PoC Generator sub-tab inside Tools.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return

        finding  = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if not req_text:
            QMessageBox.warning(self, "PoC Generator", "Could not load request data for this entry.")
            return

        parent_gui = getattr(self, "parent_gui", self)
        poc_tab = getattr(parent_gui, "poc_tab", None)
        if poc_tab is None or not hasattr(poc_tab, "load_request"):
            QMessageBox.warning(self, "PoC Generator", "PoC Generator tab not found.")
            return

        poc_tab.load_request(
            req_text,
            host     = finding.get("host", ""),
            port     = finding.get("port", 443),
            is_https = finding.get("scheme", "https") == "https",
        )

        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("PoC")

        url = finding.get("url", "")
        self.toolbar_status.setText(
            f" Sent to PoC Generator → {url[:60]}{'...' if len(url) > 60 else ''}"
        )
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # =========================================================================
    # 🔐 _send_to_jwt
    # =========================================================================
    def _send_to_jwt(self, finding_index: int = None):
        """
        Send the selected request to the JWT Analyzer & Attack Lab sub-tab inside Tools.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return

        finding  = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if not req_text:
            QMessageBox.warning(self, "JWT Analyzer", "Could not load request data for this entry.")
            return

        parent_gui = getattr(self, "parent_gui", self)
        jwt_tab = getattr(parent_gui, "jwt_tab", None)
        if jwt_tab is None or not hasattr(jwt_tab, "load_request"):
            QMessageBox.warning(self, "JWT Analyzer",
                                "JWT tab not found. Make sure it is enabled in Tools.")
            return

        jwt_tab.load_request(
            req_text,
            host     = finding.get("host", ""),
            port     = int(finding.get("port", 443)),
            is_https = finding.get("scheme", "https") == "https",
        )

        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("JWT")

        url = finding.get("url", "")
        self.toolbar_status.setText(
            f" Sent to JWT Analyzer → {url[:60]}{'...' if len(url) > 60 else ''}"
        )
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # =========================================================================
    # 📂 _send_to_content_bruteforce
    # =========================================================================
    def _send_to_content_bruteforce(self, finding_index: int = None):
        """
        Launch a feroxbuster content-bruteforce Dashboard task for this URL's host.
        Opens TaskInputDialog pre-configured for "bruteforce", then adds the task
        to the Dashboard and switches to it.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return

        url = self.findings[finding_index].get("url", "").strip()
        if not url:
            QMessageBox.warning(self, "Content Bruteforce", "No URL found for this request.")
            return

        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.netloc
        if not hostname:
            QMessageBox.warning(self, "Content Bruteforce",
                                "Could not extract host from URL.")
            return

        # Build the bruteforce target as host+path (no scheme) so feroxbuster
        # scans under the exact path selected, not just the root of the host.
        # Normalize: strip query/fragment, ensure trailing slash.
        path = parsed.path or "/"
        if not path.endswith("/"):
            path = path + "/"
        # bruteforce_target is what feroxbuster will receive as https://<target>
        bruteforce_target = hostname + path  # e.g. "www.ex.com/dir/"

        parent_gui = getattr(self, "parent_gui", self)
        dashboard = getattr(parent_gui, "dashboard_tab", None)
        if dashboard is None:
            QMessageBox.warning(self, "Content Bruteforce",
                                "Dashboard tab not available.")
            return

        try:
            from modules.dashboard_tab import TaskInputDialog
        except ImportError:
            QMessageBox.warning(self, "Content Bruteforce",
                                "Could not load task configuration dialog.")
            return

        # Pre-fill cookie from dashboard auto-detect or from the request itself
        prefill = getattr(dashboard, "_last_detected_cookie", "")
        if not prefill:
            finding = self.findings[finding_index]
            req_file = finding.get("request_file", "") or finding.get("request_path", "")
            if req_file and os.path.isfile(req_file):
                try:
                    with open(req_file, "r", encoding="utf-8", errors="replace") as rf:
                        for line in rf:
                            if line.strip().lower().startswith("cookie:"):
                                prefill = line.strip()[7:].strip()
                                break
                except Exception:
                    pass
            if not prefill:
                raw = (finding.get("request_text", "") or finding.get("request", ""))
                for line in raw.splitlines():
                    if line.strip().lower().startswith("cookie:"):
                        prefill = line.strip()[7:].strip()
                        break

        # Dialog title shows the full target path; domain field drives the task ID
        dlg = TaskInputDialog(bruteforce_target, "bruteforce", parent_gui,
                              main_window=parent_gui, prefill_cookie=prefill)
        if dlg.exec_() == QDialog.Accepted:
            config = dlg.get_config()
            # domain = host+path so the task ID is unique per path and feroxbuster
            # receives https://www.ex.com/dir/ as its -u target
            config["domain"] = bruteforce_target
            # Scope tags point at the hostname so the task appears under the
            # correct subdomain row in the Dashboard
            config["scope_subdomain"] = hostname
            config["scope_slug"]      = getattr(dashboard, "_current_slug", "")
            config["scope_domain"]    = getattr(dashboard, "_current_domain", "")
            # Ensure a subdomain widget exists for this host so the badge updates
            if hasattr(dashboard, "_add_subdomain_widget"):
                dashboard._add_subdomain_widget(hostname)
            dashboard.add_task(config)
            # Switch to the Dashboard tab
            tab_widget = getattr(parent_gui, "tab_widget", None)
            if tab_widget:
                for i in range(tab_widget.count()):
                    if "Dashboard" in tab_widget.tabText(i):
                        tab_widget.setCurrentIndex(i)
                        break
            self.toolbar_status.setText(
                f" Content Bruteforce queued → https://{bruteforce_target}"
            )
            QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # 📍 _send_to_attack_surface
    # =========================================================================
    def _send_to_endpoints(self, finding_index: int = None):
        """
        Send the selected request to the Attack Surface tab.
        Opens the AttackSurfaceEntryDialog pre-filled so the user can review/edit.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return

        finding = self.findings[finding_index]

        attack_surface_tab = getattr(self, "attack_surface_tab_ref", None)
        if attack_surface_tab is None:
            parent_gui = getattr(self, "parent_gui", self)
            attack_surface_tab = getattr(parent_gui, "attack_surface_tab", None)
        if attack_surface_tab is None or not hasattr(attack_surface_tab, "add_from_http_history"):
            QMessageBox.warning(self, "Attack Surface", "Attack Surface tab not found.")
            return

        attack_surface_tab.add_from_http_history(finding)

        url = finding.get("url", "")
        self.toolbar_status.setText(
            f" Sent to Attack Surface → {url[:60]}{'...' if len(url) > 60 else ''}"
        )
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # �🛡 _send_to_bypass
    # =========================================================================
    def _send_to_bypass(self, finding_index: int = None):
        """
        Send the selected request's full HTTP text to the Bypass sub-tab inside Tools.
        """
        if finding_index is None:
            finding_index = self._get_selected_finding_index()
        if finding_index is None or finding_index >= len(self.findings):
            return

        finding  = self.findings[finding_index]
        req_text = self._load_request_text(finding)
        if not req_text:
            QMessageBox.warning(self, "Bypass", "Could not load request data for this entry.")
            return

        waf_bypass = getattr(self, "bypass_ref", None)
        if waf_bypass is None or not hasattr(waf_bypass, "load_request"):
            QMessageBox.warning(self, "Bypass", "Bypass tab not found.")
            return

        waf_bypass.load_request(
            req_text,
            host     = finding.get("host", ""),
            port     = finding.get("port", 443),
            is_https = finding.get("scheme", "https") == "https",
        )

        # Switch to Tools → Bypass sub-tab
        parent_gui = getattr(self, "parent_gui", self)
        if hasattr(parent_gui, "_switch_to_tools_subtab"):
            parent_gui._switch_to_tools_subtab("Bypass")

        url = finding.get("url", "")
        self.toolbar_status.setText(
            f" Sent to Bypass → {url[:60]}{'...' if len(url) > 60 else ''}"
        )
        QTimer.singleShot(3000, lambda: self.toolbar_status.setText("Ready"))

    # =========================================================================
    # ⚡ NEW: Shortcut handler for Ctrl+P
    # =========================================================================
    def _shortcut_send_to_param_miner(self):
        """Ctrl+P shortcut — send selected row to Param Miner."""
        self._send_to_param_miner()

    # =========================================================================
    # 📝 Double-click on Notes cell → open Add/Edit Note dialog
    # =========================================================================
    def _on_history_cell_double_clicked(self, row: int, column: int):
        """Open the Add/Edit Note dialog when the Notes column (8) is double-clicked."""
        _NOTES_COL = 8
        if column != _NOTES_COL:
            return
        seq_item = self.history_table.item(row, 0)
        if seq_item is None:
            return
        finding_index = seq_item.data(Qt.UserRole)
        if finding_index is None:
            return
        self.quick_add_note(row, finding_index)

    def show_sitemap_context_menu(self, position):
        item = self.sitemap_tree.itemAt(position)
        menu = QMenu()

        add_domain_action    = None
        add_subdomain_action = None

        if item:
            data = item.data(0, Qt.UserRole)
            if data and data.get("host"):
                add_domain_action    = menu.addAction(" Add to Domain Scope")
                add_subdomain_action = menu.addAction(" Add to Subdomain Scope")
                menu.addSeparator()

        clear_filter_action = menu.addAction("🗑 Clear Sitemap Filter")
        menu.addSeparator()
        expand_all_action   = menu.addAction("Expand All")
        collapse_all_action = menu.addAction("Collapse All")

        action = menu.exec_(self.sitemap_tree.mapToGlobal(position))

        if add_domain_action and action == add_domain_action:
            self._add_domain_from_sitemap(data["host"])
        elif add_subdomain_action and action == add_subdomain_action:
            self._add_subdomain_from_sitemap(data["host"])
        elif action == clear_filter_action:
            self.clear_sitemap_filter()
        elif action == expand_all_action:
            self.sitemap_tree.expandAll()
        elif action == collapse_all_action:
            self.sitemap_tree.collapseAll()

    def _add_domain_from_sitemap(self, host_url):
        if not hasattr(self, "_project_slug") or not self._project_slug:
            QMessageBox.warning(self, "No Project", "No active project found.")
            return

        try:
            from urllib.parse import urlparse
            domain = urlparse(host_url).hostname
            if not domain:
                return

            pm.add_domain(self._project_slug, domain)

            if hasattr(self, "scope_tab"):
                self.scope_tab._refresh_domains()

            self.toolbar_status.setText(f"✓ Added domain to scope: {domain}")

        except ValueError as e:
            self.toolbar_status.setText(f"ℹ {e}")
        except Exception as e:
            logger.error(f"Error adding domain: {e}")
            QMessageBox.warning(self, "Error", str(e))

    def _add_subdomain_from_sitemap(self, host_url):
        if not hasattr(self, "_project_slug") or not self._project_slug:
            QMessageBox.warning(self, "No Project", "No active project found.")
            return

        try:
            from urllib.parse import urlparse
            hostname = urlparse(host_url).hostname
            if not hostname:
                return

            domains = pm.list_domains(self._project_slug)
            domains.sort(key=len, reverse=True)

            parent = None
            for d in domains:
                if hostname == d or hostname.endswith("." + d):
                    parent = d
                    break

            if parent:
                pm.add_subdomain(self._project_slug, parent, hostname)
                if hasattr(self, "scope_tab"):
                    self.scope_tab._refresh_subdomains()
                self.toolbar_status.setText(f"✓ Added subdomain {hostname} to {parent}")
            else:
                reply = QMessageBox.question(
                    self, "No Parent Domain",
                    f"No matching parent domain found for '{hostname}'.\n\n"
                    "Add it as a new Root Domain instead?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    self._add_domain_from_sitemap(host_url)

        except ValueError as e:
            self.toolbar_status.setText(f"ℹ {e}")
        except Exception as e:
            logger.error(f"Error adding subdomain: {e}")
            QMessageBox.warning(self, "Error", str(e))

    def setup_column_context_menu(self):
        self.history_table.horizontalHeader().setContextMenuPolicy(Qt.CustomContextMenu)
        self.history_table.horizontalHeader().customContextMenuRequested.connect(
            self.show_column_context_menu
        )

    def show_column_context_menu(self, position):
        menu = QMenu()
        column = self.history_table.horizontalHeader().logicalIndexAt(position)
        resize_contents = menu.addAction(" Fit to Contents")
        menu.addSeparator()
        reset_all = menu.addAction(" Reset All Widths")
        menu.addSeparator()
        if getattr(self, "_url_view", False):
            toggle_view = menu.addAction("⬡ Switch to Host / Path view")
        else:
            toggle_view = menu.addAction(" Switch to URL view")
        action = menu.exec_(self.history_table.horizontalHeader().mapToGlobal(position))
        if action == resize_contents and column >= 0:
            self.history_table.resizeColumnToContents(column)
        elif action == reset_all:
            self.reset_column_widths()
        elif action == toggle_view:
            self._switch_url_view_mode()

    def reset_column_widths(self):
        header = self.history_table.horizontalHeader()
        header.resizeSection(0, 50)
        header.resizeSection(1, 80)
        header.resizeSection(2, 60)
        if getattr(self, "_url_view", False):
            # URL mode: single URL column stretched
            header.resizeSection(3, 500)
        else:
            # Host/Path mode
            header.resizeSection(3, 200)
            header.resizeSection(4, 300)
        header.resizeSection(5, 60)
        header.resizeSection(6, 80)
        header.resizeSection(7, 120)
        header.resizeSection(8, 150)
        header.resizeSection(9, 60)
        self.status_label.setText("✓ Column widths reset")
        QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def _switch_url_view_mode(self):
        """Toggle between Host/Path view (default) and single URL view."""
        self._url_view = not getattr(self, "_url_view", False)
        header = self.history_table.horizontalHeader()

        if self._url_view:
            # ── Switch TO URL mode ─────────────────────────────────────
            header.model().setHeaderData(3, Qt.Horizontal, "URL")
            self.history_table.setColumnHidden(4, True)
            header.setSectionResizeMode(3, QHeaderView.Stretch)
            # Install URLItemDelegate for colorised base/params rendering on col 3
            self.history_table.setItemDelegateForColumn(3, URLItemDelegate(self.history_table))
            # Remove Path delegate (col 4 is hidden in URL mode)
            self.history_table.setItemDelegateForColumn(4, QStyledItemDelegate(self.history_table))
            # Rebuild col 3 text to full URL for every row
            for row in range(self.history_table.rowCount()):
                item3 = self.history_table.item(row, 3)
                if item3 is not None:
                    full_url = item3.data(Qt.UserRole + 2) or ""
                    item3.setText(full_url)
                    item3.setForeground(QColor(COLOR_URL_BASE))
        else:
            # ── Switch TO Host/Path mode ───────────────────────────────
            header.model().setHeaderData(3, Qt.Horizontal, "Host")
            header.model().setHeaderData(4, Qt.Horizontal, "Path")
            self.history_table.setColumnHidden(4, False)
            header.setSectionResizeMode(3, QHeaderView.Interactive)
            header.setSectionResizeMode(4, QHeaderView.Stretch)
            header.resizeSection(3, 200)
            # Remove URLItemDelegate from col 3 (host column uses plain text)
            self.history_table.setItemDelegateForColumn(3, QStyledItemDelegate(self.history_table))
            # Reinstall URLItemDelegate on col 4 for colorised path/params
            self.history_table.setItemDelegateForColumn(4, URLItemDelegate(self.history_table))
            # Rebuild col 3 text to host for every row
            for row in range(self.history_table.rowCount()):
                item3 = self.history_table.item(row, 3)
                if item3 is not None:
                    full_url = item3.data(Qt.UserRole + 2) or ""
                    try:
                        _p = urlparse(full_url)
                        _host = _p.netloc or _p.hostname or ""
                    except Exception:
                        _host = ""
                    item3.setText(_host)
                    item3.setForeground(QColor(COLOR_TEXT_BRIGHT))

        self.history_table.viewport().update()

        # Sync the View menu action label if it exists
        view_action = getattr(self, "url_view_action", None)
        if view_action is not None:
            if self._url_view:
                view_action.setText("\u2b21 Switch to Host / Path view")
            else:
                view_action.setText("\ud83d\udd17 Switch to URL column view")

    def copy_url(self, finding: Dict[str, Any]):
        url = finding.get("url", "")
        if url:
            QApplication.clipboard().setText(url)
            self.status_label.setText("✓ Copied URL")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def _copy_selected_urls(self, selected_rows: list):
        """Copy the URLs of all selected rows to the clipboard, one per line."""
        urls = []
        for row in selected_rows:
            idx_item = self.history_table.item(row, 0)
            if idx_item is None:
                continue
            finding_index = idx_item.data(Qt.UserRole)
            if finding_index is None or finding_index >= len(self.findings):
                continue
            url = self.findings[finding_index].get("url", "").strip()
            if url:
                urls.append(url)
        if urls:
            QApplication.clipboard().setText("\n".join(urls))
            self.status_label.setText(f"✓ Copied {len(urls)} URLs")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def copy_request_raw(self, finding: Dict[str, Any]):
        request_file = finding.get("request_file")
        if request_file and os.path.exists(request_file):
            try:
                with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                    request_text = f.read()
                QApplication.clipboard().setText(request_text)
                self.status_label.setText("✓ Copied raw request")
                QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to copy request: {e}")
        else:
            QMessageBox.warning(self, "Error", "Request file not found")

    def copy_response_raw(self, finding: Dict[str, Any]):
        response_file = finding.get("response_file")
        if response_file and os.path.exists(response_file):
            try:
                with open(response_file, "r", encoding="utf-8", errors="replace") as f:
                    response_text = f.read()
                QApplication.clipboard().setText(response_text)
                self.status_label.setText("✓ Copied raw response")
                QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to copy response: {e}")
        else:
            QMessageBox.warning(self, "Error", "Response file not found")

    def delete_request(self, row: int, finding_index: int):
        reply = QMessageBox.question(
            self, "Delete Request",
            "Are you sure you want to delete this request?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )

        if reply == QMessageBox.Yes:
            self.history_table.removeRow(row)
            self.status_label.setText("🗑 Request deleted from view")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
            self.update_sitemap_tree()

    def highlight_row(self, row: int, color: str):
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
        if finding_index is None:
            return

        # Use seq as stable key (survives JSONL re-reads in any order)
        finding = self.findings[finding_index] if finding_index < len(self.findings) else {}
        key = finding.get("seq", finding_index)
        self.highlighted_rows[key] = color
        self.save_highlights_to_file()

        for col in range(self.history_table.columnCount()):
            item = self.history_table.item(row, col)
            if item:
                bg_color = QColor(color)
                bg_color.setAlpha(50)
                item.setBackground(QBrush(bg_color))
                item.setForeground(QBrush(QColor(COLOR_TEXT_BRIGHT)))

        self.history_table.viewport().update()
        self.status_label.setText("✓ Row highlighted")
        QTimer.singleShot(1500, lambda: self.status_label.setText("Ready"))

    def clear_row_highlight(self, row: int):
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
        if finding_index is None:
            return

        finding = self.findings[finding_index] if finding_index < len(self.findings) else {}
        key = finding.get("seq", finding_index)
        if key in self.highlighted_rows:
            del self.highlighted_rows[key]
            self.save_highlights_to_file()

        for col in range(self.history_table.columnCount()):
            item = self.history_table.item(row, col)
            if item:
                item.setBackground(QBrush(Qt.transparent))
                if col == 4:
                    status = item.text()
                    if status:
                        try:
                            status_int = int(status)
                            if 200 <= status_int < 300:
                                item.setForeground(QBrush(QColor(COLOR_SUCCESS)))
                            elif 300 <= status_int < 400:
                                item.setForeground(QBrush(QColor(COLOR_MEDIUM)))
                            elif 400 <= status_int < 500:
                                item.setForeground(QBrush(QColor(COLOR_HIGH)))
                            elif status_int >= 500:
                                item.setForeground(QBrush(QColor(COLOR_CRITICAL)))
                        except:
                            item.setForeground(QBrush(QColor(COLOR_TEXT)))
                else:
                    item.setForeground(QBrush(QColor(COLOR_TEXT)))

        self.history_table.viewport().update()
        self.status_label.setText("✓ Highlight cleared")
        QTimer.singleShot(1500, lambda: self.status_label.setText("Ready"))

    def _collect_directory_findings(self, item: QTreeWidgetItem) -> list:
        all_indices = []
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "endpoint":
            all_indices.extend(data.get("finding_indices", []))

        for i in range(item.childCount()):
            all_indices.extend(self._collect_directory_findings(item.child(i)))

        return all_indices

    def _count_tree_requests(self, item: QTreeWidgetItem) -> int:
        count = 0
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "endpoint":
            count += len(data.get("finding_indices", []))

        for i in range(item.childCount()):
            count += self._count_tree_requests(item.child(i))

        return count

    def _count_tree_issues(self, item: QTreeWidgetItem) -> int:
        count = 0
        data = item.data(0, Qt.UserRole)
        if data and data.get("type") == "endpoint":
            finding_indices = data.get("finding_indices", [])
            count += sum(
                1 for idx in finding_indices
                if idx < len(self.findings) and self.findings[idx].get("params")
            )

        for i in range(item.childCount()):
            count += self._count_tree_issues(item.child(i))

        return count

    def _get_selected_finding_index(self):
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return None
        row = selected_items[0].row()
        return self.history_table.item(row, 0).data(Qt.UserRole)

    def _shortcut_send_to_scanner(self):
        idx = self._get_selected_finding_index()
        if idx is not None:
            self.send_to_scanner(idx, switch_tab=False)

    def _shortcut_switch_to_scanner(self):
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i).strip().endswith("Scanner"):
                self.tab_widget.setCurrentIndex(i)
                break

    def _shortcut_send_to_repeater(self):
        idx = self._get_selected_finding_index()
        if idx is not None and hasattr(self, 'send_to_repeater'):
            self.send_to_repeater(idx, switch_tab=False)

    def _shortcut_switch_to_repeater(self):
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i).strip().endswith("Repeater"):
                self.tab_widget.setCurrentIndex(i)
                break

    def _shortcut_send_to_intruder(self):
        idx = self._get_selected_finding_index()
        if idx is not None and hasattr(self, 'send_to_intruder'):
            self.send_to_intruder(idx, switch_tab=False)

    def _shortcut_switch_to_intruder(self):
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i).strip().endswith("Intruder"):
                self.tab_widget.setCurrentIndex(i)
                break

    def _shortcut_send_to_comparer(self):
        idx = self._get_selected_finding_index()
        if idx is not None and hasattr(self, 'prepare_comparison_from_selection'):
            self.prepare_comparison_from_selection(idx)

    def _shortcut_switch_to_comparer(self):
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i).strip().endswith("Comparer"):
                self.tab_widget.setCurrentIndex(i)
                break

    def _update_split_view_texts(self):
        """Sync split view texts with main request/response texts."""
        try:
            # Copy request text — share the already-truncated display text so
            # split-view highlighters are not triggered on full large content.
            if hasattr(self, 'request_text_split'):
                src = self.request_text.toPlainText()
                self.request_text_split.blockSignals(True)
                # Detach split-view highlighter for large content to avoid
                # re-running the syntax pass a second time on the same text.
                if len(src) > _MAX_HIGHLIGHT_SIZE:
                    if hasattr(self, 'request_highlighter_split'):
                        self.request_highlighter_split.setDocument(None)
                self.request_text_split.setPlainText(src)
                self.request_text_split.blockSignals(False)

            # Copy response text
            if hasattr(self, 'response_text_split'):
                src = self.response_text.toPlainText()
                self.response_text_split.blockSignals(True)
                if len(src) > _MAX_HIGHLIGHT_SIZE:
                    if hasattr(self, 'response_highlighter_split'):
                        self.response_highlighter_split.setDocument(None)
                self.response_text_split.setPlainText(src)
                self.response_text_split.blockSignals(False)
        except Exception as e:
            logger.debug(f"Error updating split view texts: {e}")

    def _toggle_split_view(self):
        """Switch to merged Request/Response tab, hiding Request and Response tabs."""
        try:
            if self.in_split_view_mode:
                return  # Already in split view

            # Request and Response are always both visible in the new split layout.
            # Nothing to toggle.
            pass
        except Exception as e:
            logger.error(f"Error toggling split view: {e}")

    def _go_back_to_tabs(self):
        """Return from merged tab to Request/Response tabs."""
        try:
            if not self.in_split_view_mode:
                return  # Already in normal view

            # Request and Response are always both visible in the new layout.
            # Nothing to restore.
            pass
        except Exception as e:
            logger.error(f"Error going back to tabs: {e}")

    def _swap_inspector_side(self):
        """Cycle the Inspector panel through three states:
          0 → normal  (inspector right, ~30%)
          1 → hidden  (inspector collapsed, req/resp full width)
          2 → full    (inspector full width, req/resp collapsed)
        """
        try:
            bs = self._bottom_splitter
            total = sum(bs.sizes()) or 1000

            # Advance to the next state
            self._inspector_state = (self._inspector_state + 1) % 3

            if self._inspector_state == 0:
                # Normal: req/resp ~70%, inspector ~30% (inspector on right)
                if bs.indexOf(self._inspector_panel) != 1:
                    self._inspector_panel.setParent(None)
                    bs.addWidget(self._inspector_panel)
                bs.setSizes([int(total * 0.7), int(total * 0.3)])
                self._inspector_swap_btn.setText("⇄ Swap")
                self._inspector_swap_btn.setToolTip("Hide Inspector (req/resp full width)")

            elif self._inspector_state == 1:
                # Hidden: inspector collapsed to 0, req/resp takes full width
                if bs.indexOf(self._inspector_panel) != 1:
                    self._inspector_panel.setParent(None)
                    bs.addWidget(self._inspector_panel)
                bs.setSizes([total, 0])
                self._inspector_swap_btn.setText("■ Full")
                self._inspector_swap_btn.setToolTip("Expand Inspector to full width")

            else:
                # Full: inspector takes full width, req/resp collapsed to 0
                if bs.indexOf(self._inspector_panel) != 1:
                    self._inspector_panel.setParent(None)
                    bs.addWidget(self._inspector_panel)
                bs.setSizes([0, total])
                self._inspector_swap_btn.setText("↺ Reset")
                self._inspector_swap_btn.setToolTip("Restore normal layout")

        except Exception as e:
            logger.error(f"Error swapping inspector: {e}")

    def _close_merged_tab(self):
        """Close/remove the merged Request/Response tab."""
        # Just call _go_back_to_tabs to restore normal view
        self._go_back_to_tabs()

    def _search_merged_request(self, text):
        """Highlight all matches in merged request view."""
        if text:
            SearchHighlighter.highlight_all_matches(self.request_text_split, text, False)
        else:
            SearchHighlighter.clear_highlights(self.request_text_split)

    def _search_merged_response(self, text):
        """Highlight all matches in merged response view."""
        if text:
            SearchHighlighter.highlight_all_matches(self.response_text_split, text, False)
        else:
            SearchHighlighter.clear_highlights(self.response_text_split)

    def _find_merged_text(self, text_edit, search_text, backward=False):
        """Find text in merged view and navigate to it."""
        if not search_text:
            return
        
        from PyQt5.QtGui import QTextDocument
        
        doc = text_edit.document()
        cursor = text_edit.textCursor()
        
        # Move cursor past current selection to find next/previous match
        if cursor.hasSelection():
            if backward:
                # Move to start of selection when searching backward
                cursor.setPosition(cursor.selectionStart())
            else:
                # Move to end of selection when searching forward
                cursor.setPosition(cursor.selectionEnd())
        
        # Build find options with correct QTextDocument.FindFlags
        options = QTextDocument.FindFlags()
        if backward:
            options |= QTextDocument.FindBackward
        
        # Find the text with correct API signature
        found_cursor = doc.find(search_text, cursor, options)
        
        if not found_cursor.isNull():
            # Highlight and position at found text
            text_edit.setTextCursor(found_cursor)
            # Scroll to make visible
            text_edit.ensureCursorVisible()

    # =========================================================================
    # 🔬 Selection Inspector
    # =========================================================================

    def _on_selection_changed(self, source: str):
        """Called on selectionChanged – debounce analysis while user drags selection."""
        editor = self.request_text if source == "REQUEST" else self.response_text
        other  = self.response_text if source == "REQUEST" else self.request_text
        cursor = editor.textCursor()
        if cursor.hasSelection():
            # Normalise Qt paragraph separator (U+2029) back to newline
            text = cursor.selectedText().replace('\u2029', '\n').replace('\u2028', '\n')
            if text and len(text.strip()) >= 2:
                self._sel_pending_text = text
                self._sel_pending_source = source
                self._sel_current_text = text
                self._inspector_analysis_section.setVisible(False)
                self._inspector_selection_section.setVisible(True)
                self._sel_source_badge.setText(
                    f"FROM {source}  \u2022  {len(text)} chars  \u2022  "
                    f"{len(text.encode('utf-8'))} bytes")
                self._sel_debounce_timer.start()
                return
        # This editor lost its selection – but the other may still have one
        if other.textCursor().hasSelection():
            return
        # No selection anywhere – restore normal inspector
        self._sel_debounce_timer.stop()
        self._sel_pending_text = ""
        self._sel_pending_source = ""
        self._sel_current_text = ""
        self._inspector_selection_section.setVisible(False)
        self._inspector_analysis_section.setVisible(True)

    def _process_selection_inspector(self):
        """Run selection analysis after a short debounce interval."""
        text = self._sel_pending_text
        source = self._sel_pending_source
        if not text or len(text.strip()) < 2:
            return

        if (
            text == self._sel_last_text
            and source == self._sel_last_source
            and self._sel_last_cards is not None
        ):
            cards = self._sel_last_cards
        else:
            cards = self._analyze_selection(text, source)
            self._sel_last_text = text
            self._sel_last_source = source
            self._sel_last_cards = cards

        self._build_inspector_cards(cards)

    def _send_selection_to_decoder(self):
        """Send the raw selected text (no formatting) to the active Decoder sub-tab input."""
        # _sel_current_text is already normalised plain text (U+2029 replaced with \n)
        text = getattr(self, '_sel_current_text', '')
        if not text:
            return
        # Switch the main tab to the Decoder tab first
        main_win = self.window()
        if hasattr(main_win, 'tab_widget'):
            tw = main_win.tab_widget
            for i in range(tw.count()):
                if 'Decoder' in tw.tabText(i):
                    tw.setCurrentIndex(i)
                    break
        # Locate the decoder_input via object name (set in decoder_tab.py line 469)
        if hasattr(self, 'decoder_tabs'):
            sub = self.decoder_tabs.currentWidget()
            if sub:
                inp = sub.findChild(QTextEdit, 'decoder_input')
                if inp:
                    inp.setPlainText(text)
                    inp.setFocus()
                    return
        # Fallback: find the first writable QTextEdit named decoder_input on the window
        for te in main_win.findChildren(QTextEdit):
            if te.objectName() == 'decoder_input' and not te.isReadOnly():
                te.setPlainText(text)
                te.setFocus()
                break

    def _build_inspector_cards(self, card_data: list):
        """Clear and rebuild the inspector card scroll area from a list of card tuples.

        Each item: (label, color, body, warn, crit, is_html)
        """
        lay = self._sel_card_layout
        # Remove all existing card widgets (skip the trailing stretch)
        while lay.count() > 0:
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for entry in card_data:
            label, color, body, warn, crit, is_html = entry
            card = _InspectorCard(label, color, body,
                                  warn=warn, crit=crit, is_html=is_html)
            lay.addWidget(card)

        lay.addStretch()

        # Scroll back to top
        QApplication.processEvents()
        self._sel_card_scroll.verticalScrollBar().setValue(0)

    def _analyze_selection(self, text: str, source: str) -> list:
        """Return inspector cards via the shared inspector_card module."""
        cards, _enc, _dec = _analyze_selection_shared(text, source)
        return cards


    def send_to_scanner(self, finding_index: int, switch_tab: bool = True):
        if finding_index >= len(self.findings):
            return

        finding = self.findings[finding_index]

        if not hasattr(self, 'scanner_tab'):
            QMessageBox.warning(
                self, "Scanner Not Available",
                "Scanner tab is not available. Please ensure it's properly loaded."
            )
            return

        request_text  = self._load_request_text(finding)
        response_text = self._load_response_text(finding)

        if not request_text:
            QMessageBox.warning(self, "No Request Data",
                                "Could not load request data for this entry.")
            return

        request_data = {
            "url":           finding.get("url", ""),
            "method":        finding.get("method", "GET"),
            "request_text":  request_text,
            "response_text": response_text,
            "finding":       finding,
        }

        self.scanner_tab.add_request_to_queue(request_data)

        if switch_tab:
            for i in range(self.tab_widget.count()):
                if "Scanner" in self.tab_widget.tabText(i):
                    self.tab_widget.setCurrentIndex(i)
                    break
        elif hasattr(self, 'flash_tab'):
            self.flash_tab("Scanner")

        msg = "✓ Request sent to Scanner"
        if switch_tab:
            msg += " - Switched to Scanner tab"
        self.status_label.setText(msg)

    # ── AI Chat panel helpers ──────────────────────────────────────────────────

    def _toggle_ai_panel(self):
        """Toggle AI chat panel visibility — Ctrl+Shift+C."""
        panel = getattr(self, '_ai_chat_panel', None)
        if panel is None or not hasattr(self, '_ai_outer_splitter'):
            return
        # If panel was moved to another tab's splitter, pull it back here
        if panel.parent() is not self._ai_outer_splitter:
            self._ai_outer_splitter.addWidget(panel)
        sizes = self._ai_outer_splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            self._ai_outer_splitter.setSizes([
                max(300, int(total * 0.55)),
                max(350, int(total * 0.45)),
            ])
            settings = self._ai_traffic_settings()
            if settings and not panel._last_settings:
                panel._last_settings = settings
        else:
            self._ai_outer_splitter.setSizes([total, 0])

    def _open_ai_chat(self, settings, request_text, response_text, url):
        """Ensure AI chat panel is visible in HTTP History, then start analysis."""
        panel = getattr(self, '_ai_chat_panel', None)
        if panel is None or not hasattr(self, '_ai_outer_splitter'):
            return
        if panel.parent() is not self._ai_outer_splitter:
            self._ai_outer_splitter.addWidget(panel)
        sizes = self._ai_outer_splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            self._ai_outer_splitter.setSizes([
                max(300, int(total * 0.55)),
                max(350, int(total * 0.45)),
            ])
        panel.start_analysis(settings, request_text, response_text, url)

    def _send_to_ai_from_finding(self, finding):
        """Pin request/response context in AI chat — called from URL table context menu."""
        if not _AI_TRAFFIC_AVAILABLE:
            QMessageBox.warning(self, "AI Not Available", "ai_client.py could not be loaded.")
            return
        settings = self._ai_traffic_settings()
        provider = settings.get("ai_provider", "openai")
        if provider != "ollama" and not settings.get("ai_api_key", "").strip():
            QMessageBox.warning(
                self, "AI Not Configured",
                f"No API key configured for provider '{provider}'.\n"
                "Go to Edit \u2192 Tool Settings \u2192 AI Settings."
            )
            return
        request_text  = self._load_request_text(finding)
        response_text = self._load_response_text(finding)
        url = finding.get('url', '')
        self._pin_context_ai_chat(settings, request_text, response_text, url)

    def _pin_context_ai_chat(self, settings, request_text, response_text, url):
        """Open AI panel and pin traffic context for free-form chat — no auto-analysis."""
        if not _AI_TRAFFIC_AVAILABLE:
            QMessageBox.warning(self, "AI Not Available", "ai_client.py could not be loaded.")
            return
        provider = settings.get("ai_provider", "openai")
        if provider != "ollama" and not settings.get("ai_api_key", "").strip():
            QMessageBox.warning(
                self, "AI Not Configured",
                f"No API key configured for provider '{provider}'.\n"
                "Go to Edit \u2192 Tool Settings \u2192 AI Settings."
            )
            return
        panel = getattr(self, '_ai_chat_panel', None)
        if panel is None or not hasattr(self, '_ai_outer_splitter'):
            return
        if panel.parent() is not self._ai_outer_splitter:
            self._ai_outer_splitter.addWidget(panel)
        sizes = self._ai_outer_splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            self._ai_outer_splitter.setSizes([
                max(300, int(total * 0.55)),
                max(350, int(total * 0.45)),
            ])
        panel.set_context(settings, request_text, response_text, url)

    def _ai_analyze_from_finding(self, finding):
        """AI Analyze a specific finding — called from URL table context menu."""
        if not _AI_TRAFFIC_AVAILABLE:
            QMessageBox.warning(self, "AI Not Available",
                                "ai_client.py could not be loaded.")
            return
        settings = self._ai_traffic_settings()
        provider = settings.get("ai_provider", "openai")
        if provider != "ollama" and not settings.get("ai_api_key", "").strip():
            QMessageBox.warning(
                self, "AI Not Configured",
                f"No API key configured for provider '{provider}'.\n"
                "Go to Edit \u2192 Tool Settings \u2192 AI Settings."
            )
            return
        request_text  = self._load_request_text(finding)
        response_text = self._load_response_text(finding)
        url = finding.get('url', '')
        self._open_ai_chat(settings, request_text, response_text, url)

    def _ai_analyze_text(self, request_text="", response_text=""):
        """AI Analyze with explicit request/response strings (from textarea context menus)."""
        if not _AI_TRAFFIC_AVAILABLE:
            QMessageBox.warning(self, "AI Not Available",
                                "ai_client.py could not be loaded.")
            return
        settings = self._ai_traffic_settings()
        provider = settings.get("ai_provider", "openai")
        if provider != "ollama" and not settings.get("ai_api_key", "").strip():
            QMessageBox.warning(
                self, "AI Not Configured",
                f"No API key configured for provider '{provider}'.\n"
                "Go to Edit \u2192 Tool Settings \u2192 AI Settings."
            )
            return
        finding = getattr(self, 'current_finding', None)
        url = finding.get('url', '') if finding else ''
        self._open_ai_chat(settings, request_text, response_text, url)

    def _show_request_context_menu(self, pos):
        """Right-click context menu for the request text area."""
        _menu_style = f"""
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {COLOR_BORDER};
                margin: 4px 0;
            }}
        """
        menu = QMenu(self)
        menu.setStyleSheet(_menu_style)
        copy_action       = menu.addAction("Copy")
        select_all_action = menu.addAction("Select All")
        menu.addSeparator()
        ai_action = menu.addAction("\u2728 AI Analyze Request")
        ai_action.setToolTip("Run full AI security analysis on this request  (Ctrl+Shift+C to toggle panel)")
        send_to_ai_req_action = menu.addAction("\U0001f4ce Send to AI")
        send_to_ai_req_action.setToolTip("Pin request in AI chat — ask anything about it")
        copy_action.setEnabled(self.request_text.textCursor().hasSelection())
        action = menu.exec_(self.request_text.viewport().mapToGlobal(pos))
        if action == copy_action:
            self.request_text.copy()
        elif action == select_all_action:
            self.request_text.selectAll()
        elif action == ai_action:
            self._ai_analyze_text(
                request_text=getattr(self, 'current_request_raw',
                                     self.request_text.toPlainText()),
                response_text="",
            )
        elif action == send_to_ai_req_action:
            self._pin_context_ai_chat(
                self._ai_traffic_settings(),
                request_text=getattr(self, 'current_request_raw',
                                     self.request_text.toPlainText()),
                response_text="",
                url=getattr(self, 'current_finding', {}).get('url', ''),
            )

    def _show_response_context_menu(self, pos):
        """Right-click context menu for the response text area."""
        _menu_style = f"""
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {COLOR_BORDER};
                margin: 4px 0;
            }}
        """
        menu = QMenu(self)
        menu.setStyleSheet(_menu_style)
        copy_action       = menu.addAction("Copy")
        select_all_action = menu.addAction("Select All")
        menu.addSeparator()
        ai_action = menu.addAction("\u2728 AI Analyze Response")
        ai_action.setToolTip("Run full AI security analysis on this response  (Ctrl+Shift+C to toggle panel)")
        send_to_ai_resp_action = menu.addAction("\U0001f4ce Send to AI")
        send_to_ai_resp_action.setToolTip("Pin response in AI chat — ask anything about it")
        copy_action.setEnabled(self.response_text.textCursor().hasSelection())
        action = menu.exec_(self.response_text.viewport().mapToGlobal(pos))
        if action == copy_action:
            self.response_text.copy()
        elif action == select_all_action:
            self.response_text.selectAll()
        elif action == ai_action:
            self._ai_analyze_text(
                request_text="",
                response_text=getattr(self, 'current_response_raw',
                                      self.response_text.toPlainText()),
            )
        elif action == send_to_ai_resp_action:
            self._pin_context_ai_chat(
                self._ai_traffic_settings(),
                request_text="",
                response_text=getattr(self, 'current_response_raw',
                                      self.response_text.toPlainText()),
                url=getattr(self, 'current_finding', {}).get('url', ''),
            )
        QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))