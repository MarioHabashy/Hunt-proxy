"""
Comparer Tab - Advanced HTTP Request/Response Comparison for Bug Hunting

Features:
- Side-by-side diff comparison
- Word-level and character-level diff
- Automatic vulnerability pattern detection
- Request comparison for testing bypasses
- Response comparison for finding differences
- JSON/XML intelligent comparison
- Parameter fuzzing comparison
- Baseline/deviation detection for authentication/authorization testing
"""

import os
import re
import json
import difflib
from typing import Dict, Any, List, Tuple, Optional
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, QLineEdit, 
    QPushButton, QLabel, QComboBox, QSplitter, QTabWidget,
    QListWidget, QListWidgetItem, QMessageBox, QMenu, QFileDialog,
    QCheckBox, QGroupBox, QRadioButton, QButtonGroup, QFrame, QApplication,
    QDialog, QDialogButtonBox, QInputDialog
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QColor, QTextCharFormat, QTextCursor, QBrush

from modules.constants import (
    COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT,
    COLOR_BORDER, COLOR_ACCENT, COLOR_ELEVATED_BG, COLOR_CRITICAL,
    COLOR_SUCCESS, COLOR_MEDIUM, COLOR_HIGH, COLOR_LOW, COLOR_HOVER,
    FONT_SIZE_NORMAL, FONT_SIZE_SMALL, FONT_SIZE_LARGE,
    COLOR_TEXT_MUTED, COLOR_CARD_BG
)

import logging
logger = logging.getLogger(__name__)


class DiffEngine:
    """Advanced diff engine with security-focused comparison"""
    
    @staticmethod
    def get_unified_diff(text1: str, text2: str, context_lines: int = 3) -> List[str]:
        """Get unified diff format"""
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)
        
        diff = difflib.unified_diff(
            lines1, lines2,
            fromfile='Request/Response 1',
            tofile='Request/Response 2',
            lineterm='',
            n=context_lines
        )
        
        return list(diff)
    
    @staticmethod
    def get_side_by_side_diff(text1: str, text2: str) -> Tuple[List[Tuple[str, str, str]], Dict[str, int]]:
        """
        Get side-by-side diff with change types
        
        Returns:
            Tuple of (diff_lines, stats)
            diff_lines: List of (left_line, right_line, change_type)
            stats: Dict with counts of additions, deletions, changes
        """
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()
        
        diff = difflib.SequenceMatcher(None, lines1, lines2)
        
        result = []
        stats = {'additions': 0, 'deletions': 0, 'changes': 0, 'unchanged': 0}
        
        for tag, i1, i2, j1, j2 in diff.get_opcodes():
            if tag == 'equal':
                for i in range(i1, i2):
                    result.append((lines1[i], lines2[j1 + (i - i1)], 'equal'))
                    stats['unchanged'] += 1
                    
            elif tag == 'delete':
                for i in range(i1, i2):
                    result.append((lines1[i], '', 'delete'))
                    stats['deletions'] += 1
                    
            elif tag == 'insert':
                for j in range(j1, j2):
                    result.append(('', lines2[j], 'insert'))
                    stats['additions'] += 1
                    
            elif tag == 'replace':
                # Handle replacements
                for i in range(i1, i2):
                    if i - i1 < j2 - j1:
                        result.append((lines1[i], lines2[j1 + (i - i1)], 'replace'))
                    else:
                        result.append((lines1[i], '', 'delete'))
                    stats['changes'] += 1
                
                # Add any extra insertions
                if j2 - j1 > i2 - i1:
                    for j in range(j1 + (i2 - i1), j2):
                        result.append(('', lines2[j], 'insert'))
                        stats['additions'] += 1
        
        return result, stats
    
    @staticmethod
    def get_word_diff(text1: str, text2: str) -> str:
        """Get word-level diff with inline highlighting"""
        words1 = re.findall(r'\S+|\s+', text1)
        words2 = re.findall(r'\S+|\s+', text2)
        
        diff = difflib.SequenceMatcher(None, words1, words2)
        
        result = []
        
        for tag, i1, i2, j1, j2 in diff.get_opcodes():
            if tag == 'equal':
                result.append(''.join(words1[i1:i2]))
            elif tag == 'delete':
                result.append(f"<span style='background-color: #4d1a1a; color: {COLOR_CRITICAL};'>{' '.join(words1[i1:i2])}</span>")
            elif tag == 'insert':
                result.append(f"<span style='background-color: #1a4d1a; color: {COLOR_SUCCESS};'>{' '.join(words2[j1:j2])}</span>")
            elif tag == 'replace':
                result.append(f"<span style='background-color: #4d1a1a; color: {COLOR_CRITICAL};'>{' '.join(words1[i1:i2])}</span>")
                result.append(f"<span style='background-color: #1a4d1a; color: {COLOR_SUCCESS};'>{' '.join(words2[j1:j2])}</span>")
        
        return ''.join(result)
    
    @staticmethod
    def compare_json(json1_str: str, json2_str: str) -> Tuple[bool, List[str]]:
        """
        Intelligent JSON comparison
        
        Returns:
            Tuple of (are_equal, differences)
        """
        try:
            obj1 = json.loads(json1_str)
            obj2 = json.loads(json2_str)
            
            differences = []
            DiffEngine._compare_json_objects(obj1, obj2, '', differences)
            
            return len(differences) == 0, differences
            
        except json.JSONDecodeError as e:
            return False, [f"JSON Parse Error: {e}"]
    
    @staticmethod
    def _compare_json_objects(obj1, obj2, path: str, differences: List[str]):
        """Recursively compare JSON objects"""
        if type(obj1) != type(obj2):
            differences.append(f"{path}: Type mismatch ({type(obj1).__name__} vs {type(obj2).__name__})")
            return
        
        if isinstance(obj1, dict):
            # Check keys
            keys1 = set(obj1.keys())
            keys2 = set(obj2.keys())
            
            only_in_1 = keys1 - keys2
            only_in_2 = keys2 - keys1
            
            for key in only_in_1:
                differences.append(f"{path}.{key}: Only in first object")
            
            for key in only_in_2:
                differences.append(f"{path}.{key}: Only in second object")
            
            # Compare common keys
            for key in keys1 & keys2:
                new_path = f"{path}.{key}" if path else key
                DiffEngine._compare_json_objects(obj1[key], obj2[key], new_path, differences)
        
        elif isinstance(obj1, list):
            if len(obj1) != len(obj2):
                differences.append(f"{path}: Array length differs ({len(obj1)} vs {len(obj2)})")
            
            for i, (item1, item2) in enumerate(zip(obj1, obj2)):
                DiffEngine._compare_json_objects(item1, item2, f"{path}[{i}]", differences)
        
        else:
            if obj1 != obj2:
                differences.append(f"{path}: Value differs ('{obj1}' vs '{obj2}')")
    
    @staticmethod
    def detect_security_differences(text1: str, text2: str) -> List[Dict[str, str]]:
        """
        Detect security-relevant differences between two texts
        
        Returns:
            List of security findings with category, description, severity
        """
        findings = []
        
        # Check for authentication/authorization differences
        auth_patterns = {
            'auth_header': r'Authorization:\s*(.+)',
            'session': r'(?:Session|PHPSESSID|JSESSIONID):\s*(.+)',
            'cookie': r'Cookie:\s*(.+)',
            'api_key': r'(?:api[_-]?key|apikey):\s*(.+)',
            'token': r'(?:token|access_token):\s*(.+)',
        }
        
        for pattern_name, pattern in auth_patterns.items():
            matches1 = re.findall(pattern, text1, re.IGNORECASE)
            matches2 = re.findall(pattern, text2, re.IGNORECASE)
            
            if matches1 != matches2:
                findings.append({
                    'category': 'Authentication',
                    'description': f'{pattern_name.replace("_", " ").title()} differs between requests',
                    'severity': 'HIGH',
                    'value1': matches1[0] if matches1 else 'None',
                    'value2': matches2[0] if matches2 else 'None'
                })
        
        # Check for parameter tampering indicators
        param_patterns = {
            'user_id': r'(?:user[_-]?id|uid)=(\w+)',
            'role': r'(?:role|permission|access)=(\w+)',
            'admin': r'(?:admin|is[_-]?admin)=(\w+)',
            'price': r'(?:price|amount|cost)=(\d+\.?\d*)',
        }
        
        for param_name, pattern in param_patterns.items():
            matches1 = re.findall(pattern, text1, re.IGNORECASE)
            matches2 = re.findall(pattern, text2, re.IGNORECASE)
            
            if matches1 != matches2:
                findings.append({
                    'category': 'Parameter Tampering',
                    'description': f'{param_name.replace("_", " ").title()} parameter differs',
                    'severity': 'MEDIUM',
                    'value1': matches1[0] if matches1 else 'None',
                    'value2': matches2[0] if matches2 else 'None'
                })
        
        # Check for status code differences in responses
        status1 = re.search(r'HTTP/\d\.\d\s+(\d{3})', text1)
        status2 = re.search(r'HTTP/\d\.\d\s+(\d{3})', text2)
        
        if status1 and status2 and status1.group(1) != status2.group(1):
            s1, s2 = int(status1.group(1)), int(status2.group(1))
            
            # Security-relevant status changes
            if (s1 in [401, 403] and s2 in [200, 302]) or (s2 in [401, 403] and s1 in [200, 302]):
                findings.append({
                    'category': 'Authorization Bypass',
                    'description': f'Status code changed from {s1} to {s2} - potential bypass',
                    'severity': 'CRITICAL',
                    'value1': str(s1),
                    'value2': str(s2)
                })
        
        # Check for error message differences (information disclosure)
        error_patterns = [
            r'error["\']?\s*:\s*["\']?([^"\'}\n]+)',
            r'exception["\']?\s*:\s*["\']?([^"\'}\n]+)',
            r'stack[_-]?trace["\']?\s*:\s*["\']?([^"\'}\n]+)',
        ]
        
        for pattern in error_patterns:
            errors1 = set(re.findall(pattern, text1, re.IGNORECASE))
            errors2 = set(re.findall(pattern, text2, re.IGNORECASE))
            
            diff_errors = errors1.symmetric_difference(errors2)
            if diff_errors:
                findings.append({
                    'category': 'Information Disclosure',
                    'description': 'Different error messages revealed',
                    'severity': 'LOW',
                    'value1': ', '.join(list(errors1)[:2]),
                    'value2': ', '.join(list(errors2)[:2])
                })
                break
        
        return findings


class ComparerTab:
    """Advanced HTTP Comparer for Bug Bounty Hunting"""
    
    def create_comparer_tab(self):
        """Create the Comparer tab interface"""
        comparer_widget = QWidget()
        layout = QVBoxLayout(comparer_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # ====================================================================
        # TOOLBAR
        # ====================================================================
        toolbar = self._create_comparer_toolbar()
        layout.addWidget(toolbar)
        
        # ====================================================================
        # MAIN CONTENT - Horizontal Splitter (List | Comparison)
        # ====================================================================
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(4)
        
        # LEFT: Comparison History List
        history_panel = self._create_history_panel()
        main_splitter.addWidget(history_panel)
        
        # RIGHT: Comparison View
        comparison_panel = self._create_comparison_panel()
        main_splitter.addWidget(comparison_panel)
        
        main_splitter.setSizes([250, 950])
        layout.addWidget(main_splitter)
        
        # Initialize data
        self.comparison_items = []  # List of (name, text1, text2, type)
        self.current_comparison = None
        self.clipboard_history = []  # Track clipboard items for quick compare
        
        # Setup clipboard monitoring
        self._setup_clipboard_monitoring()
        
        # Add to main tab widget
        self.tab_widget.addTab(comparer_widget, "Comparer")
    
    def _create_comparer_toolbar(self) -> QWidget:
        """Create toolbar for comparer"""
        toolbar = QWidget()
        toolbar.setObjectName("comparer_toolbar")  # Add object name for later reference
        toolbar.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)
        toolbar.setMaximumHeight(48)
        
        toolbar_layout = QHBoxLayout(toolbar)
        toolbar_layout.setContentsMargins(8, 4, 8, 4)
        toolbar_layout.setSpacing(8)
        
        # Add comparison button
        add_btn = QPushButton("✚ New Comparison")
        add_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                font-weight: 600;
                padding: 6px 16px;
            }}
            QPushButton:hover {{
                background-color: #7A9669;
            }}
        """)
        add_btn.clicked.connect(self.add_comparison_from_history)
        toolbar_layout.addWidget(add_btn)
        
        # Manual paste button
        paste_btn = QPushButton("🗈 Paste to Compare")
        paste_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_HIGH};
                color: white;
                font-weight: 600;
                padding: 6px 16px;
            }}
            QPushButton:hover {{
                background-color: #FF9A4D;
            }}
        """)
        paste_btn.clicked.connect(self.open_manual_paste_dialog)
        toolbar_layout.addWidget(paste_btn)
        
        # Load from file button
        load_btn = QPushButton("Load Files")
        load_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_LOW};
                color: white;
                font-weight: 600;
                padding: 6px 16px;
            }}
            QPushButton:hover {{
                background-color: #7AC5F6;
            }}
        """)
        load_btn.clicked.connect(self.load_files_to_compare)
        toolbar_layout.addWidget(load_btn)
        
        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(sep1)
        
        # Quick compare from clipboard
        quick_compare_btn = QPushButton("⚡ Quick Compare")
        quick_compare_btn.setToolTip("Compare last 2 items in clipboard history")
        quick_compare_btn.clicked.connect(self.quick_compare_clipboard)
        toolbar_layout.addWidget(quick_compare_btn)
        
        # Clear all comparisons
        clear_all_btn = QPushButton("🗑 Clear All")
        clear_all_btn.clicked.connect(self.clear_all_comparisons)
        toolbar_layout.addWidget(clear_all_btn)
        
        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(sep1)
        
        # Comparison mode
        toolbar_layout.addWidget(QLabel("Mode:"))
        self.comparison_mode = QComboBox()
        self.comparison_mode.addItems([
            "Side-by-Side",
            "Unified Diff",
            "Word Diff",
            "JSON Smart Compare"
        ])
        self.comparison_mode.setMinimumWidth(150)
        self.comparison_mode.currentTextChanged.connect(self.update_comparison_view)
        toolbar_layout.addWidget(self.comparison_mode)
        
        # Edit mode toggle
        self.edit_mode_checkbox = QCheckBox("✎ Edit Mode")
        self.edit_mode_checkbox.setToolTip("Enable editing of comparison texts")
        self.edit_mode_checkbox.stateChanged.connect(self.toggle_edit_mode)
        toolbar_layout.addWidget(self.edit_mode_checkbox)
        
        # Separator
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(sep2)
        
        # Ignore options
        self.ignore_whitespace = QCheckBox("Ignore Whitespace")
        self.ignore_whitespace.stateChanged.connect(self.update_comparison_view)
        toolbar_layout.addWidget(self.ignore_whitespace)
        
        self.ignore_case = QCheckBox("Ignore Case")
        self.ignore_case.stateChanged.connect(self.update_comparison_view)
        toolbar_layout.addWidget(self.ignore_case)
        
        # Separator
        sep3 = QFrame()
        sep3.setFrameShape(QFrame.VLine)
        sep3.setStyleSheet(f"background-color: {COLOR_BORDER};")
        toolbar_layout.addWidget(sep3)
        
        # Security analysis toggle
        self.show_security_findings = QCheckBox("🔍 Security Analysis")
        self.show_security_findings.setChecked(True)
        self.show_security_findings.stateChanged.connect(self.update_comparison_view)
        toolbar_layout.addWidget(self.show_security_findings)
        
        toolbar_layout.addStretch()
        
        # Stats label
        self.comparison_stats_label = QLabel("No comparison")
        self.comparison_stats_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        toolbar_layout.addWidget(self.comparison_stats_label)
        
        return toolbar
    
    def _create_history_panel(self) -> QWidget:
        """Create comparison history panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QWidget()
        header.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)
        header.setMaximumHeight(32)
        
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(8, 4, 8, 4)
        
        title = QLabel("🗈 Comparisons")
        title.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-weight: 600;")
        header_layout.addWidget(title)
        
        self.comparison_count_label = QLabel("0 items")
        self.comparison_count_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        header_layout.addStretch()
        header_layout.addWidget(self.comparison_count_label)
        
        layout.addWidget(header)
        
        # List
        self.comparison_list = QListWidget()
        self.comparison_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLOR_DARK_BG};
                border: none;
                border-right: 1px solid {COLOR_BORDER};
                outline: none;
            }}
            QListWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {COLOR_BORDER};
                color: {COLOR_TEXT};
            }}
            QListWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
            QListWidget::item:hover {{
                background-color: {COLOR_HOVER};
            }}
        """)
        self.comparison_list.itemClicked.connect(self.on_comparison_selected)
        self.comparison_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.comparison_list.customContextMenuRequested.connect(self.show_comparison_context_menu)
        
        layout.addWidget(self.comparison_list)
        
        panel.setMinimumWidth(200)
        return panel
    
    def _create_comparison_panel(self) -> QWidget:
        """Create main comparison panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Tabs for different views
        self.comparison_tabs = QTabWidget()
        
        # Side-by-side view
        side_by_side = self._create_side_by_side_view()
        self.comparison_tabs.addTab(side_by_side, "Side-by-Side Diff")
        
        # Security findings view
        security_view = self._create_security_findings_view()
        self.comparison_tabs.addTab(security_view, "Security Analysis")
        
        # Statistics view
        stats_view = self._create_statistics_view()
        self.comparison_tabs.addTab(stats_view, "Statistics")
        
        layout.addWidget(self.comparison_tabs)
        
        return panel
    
    def _create_side_by_side_view(self) -> QWidget:
        """Create side-by-side comparison view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        
        # Splitter for two text areas
        splitter = QSplitter(Qt.Horizontal)
        
        # Left text
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(2)
        
        left_label = QLabel("Request/Response 1")
        left_label.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-weight: 600; padding: 4px;")
        left_layout.addWidget(left_label)
        
        self.left_text = QTextEdit()
        self.left_text.setReadOnly(True)
        self.left_text.setFont(QFont("Consolas", 9))
        self.left_text.setLineWrapMode(QTextEdit.NoWrap)
        self.left_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
            }}
        """)
        left_layout.addWidget(self.left_text)
        
        splitter.addWidget(left_container)
        
        # Right text
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)
        
        right_label = QLabel("Request/Response 2")
        right_label.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-weight: 600; padding: 4px;")
        right_layout.addWidget(right_label)
        
        self.right_text = QTextEdit()
        self.right_text.setReadOnly(True)
        self.right_text.setFont(QFont("Consolas", 9))
        self.right_text.setLineWrapMode(QTextEdit.NoWrap)
        self.right_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
            }}
        """)
        right_layout.addWidget(self.right_text)
        
        splitter.addWidget(right_container)
        splitter.setSizes([500, 500])
        
        layout.addWidget(splitter)
        
        return widget
    
    def _create_security_findings_view(self) -> QWidget:
        """Create security findings view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(5)
        
        # Header
        header = QLabel("※ Security-Relevant Differences")
        header.setStyleSheet(f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_LARGE};
                font-weight: 700;
                padding: 8px;
                background-color: {COLOR_ELEVATED_BG};
                border-radius: 4px;
            }}
        """)
        layout.addWidget(header)
        
        # Findings text
        self.security_findings_text = QTextEdit()
        self.security_findings_text.setReadOnly(True)
        self.security_findings_text.setFont(QFont("Consolas", 10))
        layout.addWidget(self.security_findings_text)
        
        return widget
    
    def _create_statistics_view(self) -> QWidget:
        """Create statistics view"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        
        # Stats display
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setFont(QFont("Segoe UI", 10))
        layout.addWidget(self.stats_text)
        
        return widget
    
    # ========================================================================
    # MANUAL INPUT METHODS
    # ========================================================================
    
    def open_manual_paste_dialog(self):
        """Open dialog for manual paste comparison"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Manual Paste Comparison")
        dialog.setModal(True)
        dialog.resize(900, 600)
        
        layout = QVBoxLayout(dialog)
        
        # Instructions
        instructions = QLabel(
            "🗈 Paste any text to compare - HTTP requests/responses, JSON, code, logs, etc."
        )
        instructions.setStyleSheet(f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_NORMAL};
                padding: 10px;
                background-color: {COLOR_ELEVATED_BG};
                border-radius: 4px;
                margin-bottom: 10px;
            }}
        """)
        layout.addWidget(instructions)
        
        # Tabs for two inputs
        input_tabs = QTabWidget()
        
        # Text 1
        text1_container = QWidget()
        text1_layout = QVBoxLayout(text1_container)
        text1_layout.setContentsMargins(5, 5, 5, 5)
        
        text1_label = QLabel("🗈 First Text/Request/Response:")
        text1_label.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_BRIGHT};")
        text1_layout.addWidget(text1_label)
        
        self.paste_text1 = QTextEdit()
        self.paste_text1.setPlaceholderText(
            "Paste your first text here...\n\n"
            "Examples:\n"
            "• HTTP Request/Response\n"
            "• JSON API response\n"
            "• HTML source code\n"
            "• Any text content\n"
            "• Log files\n"
            "• Configuration files"
        )
        self.paste_text1.setFont(QFont("Consolas", 10))
        self.paste_text1.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 2px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
            }}
            QTextEdit:focus {{
                border: 2px solid {COLOR_ACCENT};
            }}
        """)
        text1_layout.addWidget(self.paste_text1)
        
        # Quick paste from clipboard button
        paste1_btn = QPushButton("🗈 Paste from Clipboard")
        paste1_btn.clicked.connect(lambda: self.paste_text1.setText(QApplication.clipboard().text()))
        text1_layout.addWidget(paste1_btn)
        
        input_tabs.addTab(text1_container, "Text 1")
        
        # Text 2
        text2_container = QWidget()
        text2_layout = QVBoxLayout(text2_container)
        text2_layout.setContentsMargins(5, 5, 5, 5)
        
        text2_label = QLabel("🗈 Second Text/Request/Response:")
        text2_label.setStyleSheet(f"font-weight: 600; color: {COLOR_TEXT_BRIGHT};")
        text2_layout.addWidget(text2_label)
        
        self.paste_text2 = QTextEdit()
        self.paste_text2.setPlaceholderText(
            "Paste your second text here...\n\n"
            "Make sure it's related to the first text for meaningful comparison."
        )
        self.paste_text2.setFont(QFont("Consolas", 10))
        self.paste_text2.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 2px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 8px;
            }}
            QTextEdit:focus {{
                border: 2px solid {COLOR_ACCENT};
            }}
        """)
        text2_layout.addWidget(self.paste_text2)
        
        # Quick paste from clipboard button
        paste2_btn = QPushButton("🗈 Paste from Clipboard")
        paste2_btn.clicked.connect(lambda: self.paste_text2.setText(QApplication.clipboard().text()))
        text2_layout.addWidget(paste2_btn)
        
        input_tabs.addTab(text2_container, "Text 2")
        
        layout.addWidget(input_tabs)
        
        # Comparison name
        name_layout = QHBoxLayout()
        name_label = QLabel("Name:")
        name_label.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-weight: 600;")
        name_layout.addWidget(name_label)
        
        self.paste_comparison_name = QLineEdit()
        self.paste_comparison_name.setPlaceholderText("Enter comparison name (optional)")
        self.paste_comparison_name.setText(f"Manual Comparison {len(self.comparison_items) + 1}")
        name_layout.addWidget(self.paste_comparison_name)
        
        layout.addLayout(name_layout)
        
        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        buttons.button(QDialogButtonBox.Ok).setText("Compare")
        buttons.button(QDialogButtonBox.Ok).setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: white;
                font-weight: 600;
                padding: 6px 20px;
            }}
        """)
        layout.addWidget(buttons)
        
        # Show dialog
        result = dialog.exec_()
        
        if result == QDialog.Accepted:
            text1 = self.paste_text1.toPlainText()
            text2 = self.paste_text2.toPlainText()
            name = self.paste_comparison_name.text() or f"Manual Comparison {len(self.comparison_items) + 1}"
            
            if not text1.strip() or not text2.strip():
                QMessageBox.warning(
                    self,
                    "Empty Input",
                    "Please paste text in both fields."
                )
                return
            
            # Add comparison
            self.add_comparison(name, text1, text2, "Manual")
            
            # Switch to Comparer tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Comparer":
                    self.tab_widget.setCurrentIndex(i)
                    break
    
    def load_files_to_compare(self):
        """Load two files from disk to compare"""
        # Get first file
        file1, _ = QFileDialog.getOpenFileName(
            self,
            "Select First File",
            "",
            "All Files (*);;Text Files (*.txt);;HTTP Files (*.http);;JSON Files (*.json);;XML Files (*.xml);;HTML Files (*.html)"
        )
        
        if not file1:
            return
        
        # Get second file
        file2, _ = QFileDialog.getOpenFileName(
            self,
            "Select Second File",
            "",
            "All Files (*);;Text Files (*.txt);;HTTP Files (*.http);;JSON Files (*.json);;XML Files (*.xml);;HTML Files (*.html)"
        )
        
        if not file2:
            return
        
        try:
            # Read files
            with open(file1, 'r', encoding='utf-8', errors='replace') as f:
                text1 = f.read()
            
            with open(file2, 'r', encoding='utf-8', errors='replace') as f:
                text2 = f.read()
            
            # Get file names
            import os
            name1 = os.path.basename(file1)
            name2 = os.path.basename(file2)
            
            comparison_name = f"Files: {name1} vs {name2}"
            
            # Add comparison
            self.add_comparison(comparison_name, text1, text2, "Files")
            
            # Switch to Comparer tab
            for i in range(self.tab_widget.count()):
                if self.tab_widget.tabText(i) == "Comparer":
                    self.tab_widget.setCurrentIndex(i)
                    break
            
            self.status_label.setText(f"✓ Loaded files: {name1} vs {name2}")
            QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))
            
        except Exception as e:
            QMessageBox.critical(
                self,
                "Error Loading Files",
                f"Failed to load files:\n{e}"
            )
    
    def _setup_clipboard_monitoring(self):
        """Setup clipboard monitoring for quick compare"""
        clipboard = QApplication.clipboard()
        clipboard.dataChanged.connect(self._on_clipboard_changed)
    
    def _on_clipboard_changed(self):
        """Handle clipboard changes"""
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        
        if text and len(text.strip()) > 0:
            # Add to history (keep last 10 items)
            if text not in self.clipboard_history:
                self.clipboard_history.insert(0, text)
                self.clipboard_history = self.clipboard_history[:10]  # Keep last 10
    
    def quick_compare_clipboard(self):
        """Quick compare the last two clipboard items"""
        if len(self.clipboard_history) < 2:
            QMessageBox.information(
                self,
                "Clipboard History",
                "Need at least 2 items in clipboard history.\n\n"
                "Copy two different texts to clipboard, then use Quick Compare.\n\n"
                f"Current clipboard items: {len(self.clipboard_history)}"
            )
            return
        
        # Get last two items
        text1 = self.clipboard_history[1]  # Second most recent
        text2 = self.clipboard_history[0]  # Most recent
        
        # Create comparison
        name = f"Clipboard: Item 1 vs Item 2"
        self.add_comparison(name, text1, text2, "Clipboard")
        
        self.status_label.setText("⚡ Quick compare from clipboard history!")
        QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
    
    def clear_all_comparisons(self):
        """Clear all comparisons"""
        if len(self.comparison_items) == 0:
            return
        
        reply = QMessageBox.question(
            self,
            "Clear All Comparisons",
            f"Are you sure you want to delete all {len(self.comparison_items)} comparisons?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.comparison_items.clear()
            self.comparison_list.clear()
            self.current_comparison = None
            self.comparison_count_label.setText("0 items")
            
            # Clear displays
            self.left_text.clear()
            self.right_text.clear()
            self.security_findings_text.clear()
            self.stats_text.clear()
            
            self.status_label.setText("🗑 All comparisons cleared")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
    
    def toggle_edit_mode(self, state):
        """Toggle edit mode for comparison texts"""
        is_enabled = state == Qt.Checked
        
        # Toggle read-only state
        self.left_text.setReadOnly(not is_enabled)
        self.right_text.setReadOnly(not is_enabled)
        
        if is_enabled:
            # Enable editing
            self.left_text.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {COLOR_CARD_BG};
                    border: 2px solid {COLOR_ACCENT};
                    border-radius: 3px;
                }}
            """)
            self.right_text.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {COLOR_CARD_BG};
                    border: 2px solid {COLOR_ACCENT};
                    border-radius: 3px;
                }}
            """)
            
            # Show save button
            if not hasattr(self, 'save_edits_btn'):
                self.save_edits_btn = QPushButton("🖫 Save Edits")
                self.save_edits_btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {COLOR_SUCCESS};
                        color: white;
                        font-weight: 600;
                        padding: 6px 16px;
                    }}
                """)
                self.save_edits_btn.clicked.connect(self.save_edited_comparison)
            
            # Add to toolbar (find toolbar widget)
            for child in self.findChildren(QWidget):
                if child.objectName() == "comparer_toolbar":
                    toolbar_layout = child.layout()
                    if toolbar_layout and self.save_edits_btn not in [toolbar_layout.itemAt(i).widget() for i in range(toolbar_layout.count())]:
                        toolbar_layout.insertWidget(toolbar_layout.count() - 1, self.save_edits_btn)
                    break
            
            self.status_label.setText("✎ Edit mode enabled - Modify texts and click 'Save Edits'")
        else:
            # Disable editing
            self.left_text.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {COLOR_DARK_BG};
                    border: 1px solid {COLOR_BORDER};
                    border-radius: 3px;
                }}
            """)
            self.right_text.setStyleSheet(f"""
                QTextEdit {{
                    background-color: {COLOR_DARK_BG};
                    border: 1px solid {COLOR_BORDER};
                    border-radius: 3px;
                }}
            """)
            
            # Hide save button
            if hasattr(self, 'save_edits_btn'):
                self.save_edits_btn.hide()
            
            self.status_label.setText("Edit mode disabled")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
    
    def save_edited_comparison(self):
        """Save edited comparison texts"""
        if not self.current_comparison:
            return
        
        # Get edited texts
        edited_text1 = self.left_text.toPlainText()
        edited_text2 = self.right_text.toPlainText()
        
        # Update current comparison
        self.current_comparison['text1'] = edited_text1
        self.current_comparison['text2'] = edited_text2
        
        # Find and update in list
        for i, comp in enumerate(self.comparison_items):
            if comp == self.current_comparison:
                self.comparison_items[i] = self.current_comparison
                break
        
        # Refresh comparison view
        self.update_comparison_view()
        
        self.status_label.setText("🖫 Edits saved! Comparison updated.")
        QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
    
    # ========================================================================
    # COMPARISON OPERATIONS
    # ========================================================================
    
    def add_comparison_from_history(self):
        """Add comparison from HTTP history - select two requests"""
        # Get selected items from history table
        selected_items = self.history_table.selectedItems()
        
        if not selected_items:
            QMessageBox.information(
                self,
                "No Selection",
                "Please select 1 or 2 requests from HTTP History to compare."
            )
            return
        
        # Get unique rows
        selected_rows = list(set(item.row() for item in selected_items))
        
        if len(selected_rows) == 1:
            # Ask user what to compare
            QMessageBox.information(
                self,
                "Single Selection",
                "Please select 2 requests to compare.\n\n"
                "Tip: Hold Ctrl and click to select multiple requests."
            )
            return
        
        if len(selected_rows) > 2:
            # Take first two
            selected_rows = selected_rows[:2]
            QMessageBox.information(
                self,
                "Multiple Selections",
                f"Selected {len(selected_rows)} requests. Using first 2 for comparison."
            )
        
        # Get findings for selected rows
        finding_indices = []
        for row in selected_rows[:2]:
            finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
            if finding_index is not None and finding_index < len(self.findings):
                finding_indices.append(finding_index)
        
        if len(finding_indices) < 2:
            QMessageBox.warning(self, "Error", "Could not load selected requests.")
            return
        
        # Load request/response data
        finding1 = self.findings[finding_indices[0]]
        finding2 = self.findings[finding_indices[1]]
        
        # Ask what to compare
        compare_type, ok = self._show_comparison_type_dialog()
        if not ok:
            return
        
        # Get text based on type
        if compare_type == "Requests":
            text1 = self._load_request_text(finding1)
            text2 = self._load_request_text(finding2)
            name = f"Requests: {finding1.get('url', 'Unknown')[:50]} vs {finding2.get('url', 'Unknown')[:50]}"
        else:  # Responses
            text1 = self._load_response_text(finding1)
            text2 = self._load_response_text(finding2)
            name = f"Responses: {finding1.get('url', 'Unknown')[:50]} vs {finding2.get('url', 'Unknown')[:50]}"
        
        # Add to comparison list
        self.add_comparison(name, text1, text2, compare_type)
    
    def _show_comparison_type_dialog(self) -> Tuple[str, bool]:
        """Show dialog to select comparison type"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Comparison Type")
        dialog.setModal(True)
        
        layout = QVBoxLayout(dialog)
        
        label = QLabel("What do you want to compare?")
        label.setStyleSheet(f"font-size: {FONT_SIZE_NORMAL}; margin-bottom: 10px;")
        layout.addWidget(label)
        
        # Radio buttons
        self.compare_requests_radio = QRadioButton("Requests")
        self.compare_requests_radio.setChecked(True)
        self.compare_responses_radio = QRadioButton("Responses")
        
        layout.addWidget(self.compare_requests_radio)
        layout.addWidget(self.compare_responses_radio)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        
        dialog.setMinimumWidth(300)
        
        result = dialog.exec_()
        compare_type = "Requests" if self.compare_requests_radio.isChecked() else "Responses"
        
        return compare_type, result == QDialog.Accepted
    
    def _load_request_text(self, finding: Dict[str, Any]) -> str:
        """Load request text from finding"""
        request_file = finding.get("request_file")
        if request_file and os.path.exists(request_file):
            try:
                with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read request: {e}")
                return f"Error loading request: {e}"
        return f"{finding.get('method', 'GET')} {finding.get('url', '')} HTTP/1.1\n\n(Request file not available)"
    
    def _load_response_text(self, finding: Dict[str, Any]) -> str:
        """Load response text from finding"""
        response_file = finding.get("response_file")
        if response_file and os.path.exists(response_file):
            try:
                with open(response_file, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception as e:
                logger.error(f"Failed to read response: {e}")
                return f"Error loading response: {e}"
        return "(Response file not available)"
    
    def add_comparison(self, name: str, text1: str, text2: str, compare_type: str):
        """Add a new comparison to the list"""
        # Store comparison
        self.comparison_items.append({
            'name': name,
            'text1': text1,
            'text2': text2,
            'type': compare_type
        })
        
        # Add to list widget
        item = QListWidgetItem(f"🗠 {name}")
        item.setData(Qt.UserRole, len(self.comparison_items) - 1)
        self.comparison_list.addItem(item)
        
        # Update count
        self.comparison_count_label.setText(f"{len(self.comparison_items)} items")
        
        # Auto-select and display
        self.comparison_list.setCurrentItem(item)
        self.on_comparison_selected(item)
        
        # Switch to comparer tab
        for i in range(self.tab_widget.count()):
            if self.tab_widget.tabText(i) == "Comparer":
                self.tab_widget.setCurrentIndex(i)
                break
    
    def on_comparison_selected(self, item: QListWidgetItem):
        """Handle comparison selection"""
        index = item.data(Qt.UserRole)
        if index is None or index >= len(self.comparison_items):
            return
        
        self.current_comparison = self.comparison_items[index]
        self.update_comparison_view()
    
    def update_comparison_view(self):
        """Update the comparison display"""
        if not self.current_comparison:
            return
        
        text1 = self.current_comparison['text1']
        text2 = self.current_comparison['text2']
        
        # Apply ignore options
        if self.ignore_whitespace.isChecked():
            text1 = '\n'.join(line.strip() for line in text1.splitlines())
            text2 = '\n'.join(line.strip() for line in text2.splitlines())
        
        if self.ignore_case.isChecked():
            text1 = text1.lower()
            text2 = text2.lower()
        
        # Get comparison mode
        mode = self.comparison_mode.currentText()
        
        if mode == "Side-by-Side":
            self._display_side_by_side(text1, text2)
        elif mode == "Unified Diff":
            self._display_unified_diff(text1, text2)
        elif mode == "Word Diff":
            self._display_word_diff(text1, text2)
        elif mode == "JSON Smart Compare":
            self._display_json_comparison(text1, text2)
        
        # Update security findings
        if self.show_security_findings.isChecked():
            self._display_security_findings(
                self.current_comparison['text1'],  # Use original text
                self.current_comparison['text2']
            )
        
        # Update statistics
        self._display_statistics(text1, text2)
    
    def _display_side_by_side(self, text1: str, text2: str):
        """Display side-by-side diff"""
        diff_lines, stats = DiffEngine.get_side_by_side_diff(text1, text2)
        
        # Build HTML for left and right
        left_html = []
        right_html = []
        
        left_html.append(f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 9pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 5px;
            line-height: 1.4;
        }}
        .line {{
            padding: 2px 5px;
            margin: 0;
            white-space: pre;
        }}
        .equal {{ background-color: transparent; }}
        .delete {{ background-color: #4d1a1a; color: {COLOR_CRITICAL}; }}
        .insert {{ background-color: #1a4d1a; color: {COLOR_SUCCESS}; }}
        .replace {{ background-color: #4d4d1a; color: {COLOR_MEDIUM}; }}
        </style>
        </head>
        <body>
        """)
        
        right_html.append(left_html[0])  # Same header
        
        line_num = 1
        for left_line, right_line, change_type in diff_lines:
            # Left side
            if left_line:
                left_html.append(f"<div class='line {change_type}'>{self._escape_html(left_line)}</div>")
            else:
                left_html.append(f"<div class='line equal'></div>")
            
            # Right side
            if right_line:
                right_html.append(f"<div class='line {change_type}'>{self._escape_html(right_line)}</div>")
            else:
                right_html.append(f"<div class='line equal'></div>")
            
            line_num += 1
        
        left_html.append("</body></html>")
        right_html.append("</body></html>")
        
        self.left_text.setHtml(''.join(left_html))
        self.right_text.setHtml(''.join(right_html))
        
        # Sync scrolling
        self._sync_scroll_bars()
        
        # Update stats
        self.comparison_stats_label.setText(
            f"🞥{stats['additions']} ―{stats['deletions']} ⤮{stats['changes']} ✓{stats['unchanged']}"
        )
    
    def _display_unified_diff(self, text1: str, text2: str):
        """Display unified diff format"""
        diff_lines = DiffEngine.get_unified_diff(text1, text2)
        
        html = [f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 9pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 10px;
            line-height: 1.6;
        }}
        .line {{
            white-space: pre;
            margin: 0;
            padding: 2px 5px;
        }}
        .add {{ background-color: #1a4d1a; color: {COLOR_SUCCESS}; }}
        .remove {{ background-color: #4d1a1a; color: {COLOR_CRITICAL}; }}
        .context {{ color: {COLOR_TEXT_MUTED}; }}
        .header {{ color: {COLOR_ACCENT}; font-weight: bold; }}
        </style>
        </head>
        <body>
        """]
        
        for line in diff_lines:
            if line.startswith('+++') or line.startswith('---') or line.startswith('@@'):
                html.append(f"<div class='line header'>{self._escape_html(line)}</div>")
            elif line.startswith('+'):
                html.append(f"<div class='line add'>{self._escape_html(line)}</div>")
            elif line.startswith('-'):
                html.append(f"<div class='line remove'>{self._escape_html(line)}</div>")
            else:
                html.append(f"<div class='line context'>{self._escape_html(line)}</div>")
        
        html.append("</body></html>")
        
        unified_html = ''.join(html)
        self.left_text.setHtml(unified_html)
        self.right_text.setPlainText("")  # Clear right pane in unified mode
    
    def _display_word_diff(self, text1: str, text2: str):
        """Display word-level diff"""
        word_diff = DiffEngine.get_word_diff(text1, text2)
        
        html = f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 10pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 10px;
            line-height: 1.8;
        }}
        </style>
        </head>
        <body>
        {word_diff}
        </body>
        </html>
        """
        
        self.left_text.setHtml(html)
        self.right_text.setPlainText("")
    
    def _display_json_comparison(self, text1: str, text2: str):
        """Display intelligent JSON comparison"""
        are_equal, differences = DiffEngine.compare_json(text1, text2)
        
        html = [f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            font-size: 10pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 15px;
            line-height: 1.8;
        }}
        .title {{
            font-size: 14pt;
            font-weight: bold;
            color: {COLOR_TEXT_BRIGHT};
            margin-bottom: 15px;
        }}
        .equal {{
            color: {COLOR_SUCCESS};
            font-weight: bold;
            font-size: 12pt;
        }}
        .different {{
            color: {COLOR_CRITICAL};
            font-weight: bold;
            font-size: 12pt;
        }}
        .diff-item {{
            background-color: {COLOR_CARD_BG};
            padding: 8px 12px;
            margin: 5px 0;
            border-left: 3px solid {COLOR_MEDIUM};
            border-radius: 4px;
        }}
        .path {{
            color: {COLOR_ACCENT};
            font-weight: bold;
            font-family: 'Consolas', monospace;
        }}
        .description {{
            color: {COLOR_TEXT};
            margin-top: 4px;
        }}
        </style>
        </head>
        <body>
        """]
        
        html.append("<div class='title'>🗠 JSON Structure Comparison</div>")
        
        if are_equal:
            html.append("<div class='equal'>✓ JSON objects are identical</div>")
        else:
            html.append(f"<div class='different'>✘ Found {len(differences)} difference(s)</div>")
            html.append("<div style='margin-top: 20px;'>")
            
            for diff in differences:
                html.append(f"""
                <div class='diff-item'>
                    <div class='path'>{self._escape_html(diff)}</div>
                </div>
                """)
            
            html.append("</div>")
        
        html.append("</body></html>")
        
        self.left_text.setHtml(''.join(html))
        self.right_text.setPlainText("")
    
    def _display_security_findings(self, text1: str, text2: str):
        """Display security-relevant differences"""
        findings = DiffEngine.detect_security_differences(text1, text2)
        
        html = [f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            font-size: 10pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 15px;
            line-height: 1.8;
        }}
        .finding {{
            background-color: {COLOR_CARD_BG};
            padding: 12px;
            margin: 10px 0;
            border-radius: 6px;
            border-left: 4px solid;
        }}
        .critical {{
            border-left-color: {COLOR_CRITICAL};
            background-color: rgba(255, 107, 107, 0.1);
        }}
        .high {{
            border-left-color: {COLOR_HIGH};
            background-color: rgba(255, 167, 38, 0.1);
        }}
        .medium {{
            border-left-color: {COLOR_MEDIUM};
            background-color: rgba(255, 238, 88, 0.1);
        }}
        .low {{
            border-left-color: {COLOR_LOW};
            background-color: rgba(100, 181, 246, 0.1);
        }}
        .category {{
            font-weight: bold;
            font-size: 11pt;
            color: {COLOR_TEXT_BRIGHT};
            margin-bottom: 5px;
        }}
        .severity {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 8pt;
            font-weight: bold;
            margin-left: 8px;
        }}
        .severity-CRITICAL {{
            background-color: {COLOR_CRITICAL};
            color: white;
        }}
        .severity-HIGH {{
            background-color: {COLOR_HIGH};
            color: white;
        }}
        .severity-MEDIUM {{
            background-color: {COLOR_MEDIUM};
            color: black;
        }}
        .severity-LOW {{
            background-color: {COLOR_LOW};
            color: black;
        }}
        .description {{
            color: {COLOR_TEXT};
            margin: 8px 0;
        }}
        .value {{
            background-color: {COLOR_DARK_BG};
            padding: 4px 8px;
            border-radius: 3px;
            font-family: 'Consolas', monospace;
            font-size: 9pt;
            margin: 4px 0;
        }}
        .label {{
            color: {COLOR_ACCENT};
            font-weight: 600;
            margin-right: 5px;
        }}
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: {COLOR_TEXT_MUTED};
            font-size: 12pt;
        }}
        </style>
        </head>
        <body>
        """]
        
        if not findings:
            html.append("""
            <div class='no-findings'>
                ✓ No security-relevant differences detected<br>
                <span style='font-size: 9pt;'>Requests/Responses appear functionally similar from a security perspective</span>
            </div>
            """)
        else:
            for finding in findings:
                severity = finding['severity']
                severity_class = severity.lower()
                
                html.append(f"""
                <div class='finding {severity_class}'>
                    <div class='category'>
                        {finding['category']}
                        <span class='severity severity-{severity}'>{severity}</span>
                    </div>
                    <div class='description'>{self._escape_html(finding['description'])}</div>
                    <div class='value'>
                        <span class='label'>Value 1:</span>{self._escape_html(finding.get('value1', 'N/A'))}
                    </div>
                    <div class='value'>
                        <span class='label'>Value 2:</span>{self._escape_html(finding.get('value2', 'N/A'))}
                    </div>
                </div>
                """)
        
        html.append("</body></html>")
        
        self.security_findings_text.setHtml(''.join(html))
    
    def _display_statistics(self, text1: str, text2: str):
        """Display comparison statistics"""
        lines1 = text1.splitlines()
        lines2 = text2.splitlines()
        
        _, stats = DiffEngine.get_side_by_side_diff(text1, text2)
        
        # Calculate similarity percentage
        total_lines = max(len(lines1), len(lines2))
        if total_lines > 0:
            similarity = (stats['unchanged'] / total_lines) * 100
        else:
            similarity = 100.0
        
        html = f"""
        <html>
        <head>
        <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            font-size: 11pt;
            background-color: {COLOR_DARK_BG};
            color: {COLOR_TEXT};
            padding: 20px;
            line-height: 1.8;
        }}
        .stat-card {{
            background-color: {COLOR_CARD_BG};
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid {COLOR_ACCENT};
        }}
        .stat-label {{
            color: {COLOR_TEXT_MUTED};
            font-size: 9pt;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 5px;
        }}
        .stat-value {{
            color: {COLOR_TEXT_BRIGHT};
            font-size: 18pt;
            font-weight: bold;
        }}
        .similarity-bar {{
            width: 100%;
            height: 30px;
            background-color: {COLOR_DARK_BG};
            border-radius: 15px;
            overflow: hidden;
            margin-top: 10px;
        }}
        .similarity-fill {{
            height: 100%;
            background: linear-gradient(90deg, {COLOR_SUCCESS}, {COLOR_ACCENT});
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }}
        </style>
        </head>
        <body>
        
        <div class='stat-card'>
            <div class='stat-label'>Similarity</div>
            <div class='stat-value'>{similarity:.1f}%</div>
            <div class='similarity-bar'>
                <div class='similarity-fill' style='width: {similarity}%;'>{similarity:.1f}%</div>
            </div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Lines Added</div>
            <div class='stat-value' style='color: {COLOR_SUCCESS};'>+{stats['additions']}</div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Lines Deleted</div>
            <div class='stat-value' style='color: {COLOR_CRITICAL};'>-{stats['deletions']}</div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Lines Changed</div>
            <div class='stat-value' style='color: {COLOR_MEDIUM};'>~{stats['changes']}</div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Lines Unchanged</div>
            <div class='stat-value' style='color: {COLOR_LOW};'>={stats['unchanged']}</div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Total Lines (Doc 1)</div>
            <div class='stat-value'>{len(lines1)}</div>
        </div>
        
        <div class='stat-card'>
            <div class='stat-label'>Total Lines (Doc 2)</div>
            <div class='stat-value'>{len(lines2)}</div>
        </div>
        
        </body>
        </html>
        """
        
        self.stats_text.setHtml(html)
    
    def _sync_scroll_bars(self):
        """Sync scroll bars between left and right text edits"""
        # Connect vertical scroll bars
        left_vbar = self.left_text.verticalScrollBar()
        right_vbar = self.right_text.verticalScrollBar()
        
        left_vbar.valueChanged.connect(right_vbar.setValue)
        right_vbar.valueChanged.connect(left_vbar.setValue)
        
        # Connect horizontal scroll bars
        left_hbar = self.left_text.horizontalScrollBar()
        right_hbar = self.right_text.horizontalScrollBar()
        
        left_hbar.valueChanged.connect(right_hbar.setValue)
        right_hbar.valueChanged.connect(left_hbar.setValue)
    
    def _escape_html(self, text: str) -> str:
        """Escape HTML special characters"""
        return (text
                .replace('&', '&amp;')
                .replace('<', '&lt;')
                .replace('>', '&gt;')
                .replace('"', '&quot;')
                .replace("'", '&#39;'))
    
    def show_comparison_context_menu(self, position):
        """Show context menu for comparison items"""
        item = self.comparison_list.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
            }}
            QMenu::item:selected {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
        """)
        
        rename_action = menu.addAction("✎ Rename")
        export_action = menu.addAction("🖫 Export Diff")
        menu.addSeparator()
        delete_action = menu.addAction("🗑 Delete")
        
        action = menu.exec_(self.comparison_list.mapToGlobal(position))
        
        if action == delete_action:
            self.delete_comparison(item)
        elif action == export_action:
            self.export_comparison(item)
        elif action == rename_action:
            self.rename_comparison(item)
    
    def delete_comparison(self, item: QListWidgetItem):
        """Delete a comparison"""
        index = item.data(Qt.UserRole)
        if index is not None:
            # Remove from list
            del self.comparison_items[index]
            
            # Remove from UI
            row = self.comparison_list.row(item)
            self.comparison_list.takeItem(row)
            
            # Update indices
            for i in range(self.comparison_list.count()):
                self.comparison_list.item(i).setData(Qt.UserRole, i)
            
            # Update count
            self.comparison_count_label.setText(f"{len(self.comparison_items)} items")
            
            # Clear display if this was selected
            if self.current_comparison and self.current_comparison == self.comparison_items[index] if index < len(self.comparison_items) else None:
                self.left_text.clear()
                self.right_text.clear()
    
    def export_comparison(self, item: QListWidgetItem):
        """Export comparison to file"""
        index = item.data(Qt.UserRole)
        if index is None or index >= len(self.comparison_items):
            return
        
        comparison = self.comparison_items[index]
        
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Comparison",
            f"comparison_{comparison['name'][:30]}.txt",
            "Text Files (*.txt);;HTML Files (*.html)"
        )
        
        if filename:
            try:
                diff_lines = DiffEngine.get_unified_diff(
                    comparison['text1'],
                    comparison['text2']
                )
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(diff_lines))
                
                QMessageBox.information(self, "Success", f"Comparison exported to:\n{filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export:\n{e}")
    
    def rename_comparison(self, item: QListWidgetItem):
        """Rename a comparison"""
        index = item.data(Qt.UserRole)
        if index is None or index >= len(self.comparison_items):
            return
        
        current_name = self.comparison_items[index]['name']
        
        new_name, ok = QInputDialog.getText(
            self,
            "Rename Comparison",
            "Enter new name:",
            QLineEdit.Normal,
            current_name
        )
        
        if ok and new_name:
            self.comparison_items[index]['name'] = new_name
            item.setText(f"🗠 {new_name}")
    
    # ========================================================================
    # HELPER: Send to Comparer from other tabs
    # ========================================================================
    
    def send_to_comparer(self, text1: str, text2: str, name: str = "Manual Comparison", compare_type: str = "Custom"):
        """
        Public method to add comparison from other tabs
        
        Usage:
            self.send_to_comparer(request1, request2, "Parameter Fuzzing", "Requests")
        """
        self.add_comparison(name, text1, text2, compare_type)