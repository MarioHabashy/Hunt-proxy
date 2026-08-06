import base64
import html
import json
import hashlib
import binascii
import re
import math
import codecs
import gzip
import ipaddress
import xml.dom.minidom
from collections import Counter
from datetime import datetime
import urllib.parse
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

from modules.constants import *


class DecoderTab:

    def create_decoder_tab(self):
        """Create ultra-advanced Decoder tab for pentesting and bug bounty"""
        decoder_widget = QWidget()
        decoder_layout = QVBoxLayout(decoder_widget)
        decoder_layout.setContentsMargins(8, 8, 8, 8)
        decoder_layout.setSpacing(8)

        # ========================================================================
        # HEADER with Quick Actions - COMPACT VERSION
        # ========================================================================

        header_container = QWidget()
        header_container.setMaximumHeight(50)  # ✓ LIMIT HEADER HEIGHT
        header_layout = QHBoxLayout(header_container)
        header_layout.setContentsMargins(0, 0, 0, 0)  # ✓ REMOVE MARGINS
        header_layout.setSpacing(8)

        header = QLabel("DECODER & ANALYZER")  # ✓ SHORTER TEXT
        header.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_NORMAL};  /* ✓ SMALLER FONT */
                font-weight: 700;
                padding: 8px 16px;  /* ✓ LESS PADDING */
                background: linear-gradient(135deg, {COLOR_ELEVATED_BG} 0%, {COLOR_CARD_BG} 100%);
                border-radius: 6px;  /* ✓ SMALLER RADIUS */
                border-left: 3px solid {COLOR_ACCENT};  /* ✓ THINNER BORDER */
            }}
        """
        )
        header_layout.addWidget(header)

        # Quick action: Smart Decode - COMPACT
        smart_decode_btn = QPushButton("Smart Decode")
        smart_decode_btn.setToolTip("Auto-detect and decode multiple layers")
        smart_decode_btn.clicked.connect(self.smart_decode_advanced)
        smart_decode_btn.setMaximumHeight(36)  # ✓ LIMIT BUTTON HEIGHT
        smart_decode_btn.setStyleSheet(
            f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_ACCENT}, stop:1 {COLOR_ACCENT_SECONDARY});
                padding: 6px 16px;  /* ✓ LESS PADDING */
                font-weight: 600;
                font-size: {FONT_SIZE_SMALL};  /* ✓ SMALLER FONT */
                color: white;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_ACCENT_SECONDARY}, stop:1 {COLOR_ACCENT});
            }}
        """
        )
        header_layout.addWidget(smart_decode_btn)

        # Quick action: Encode All (dencode-style)
        encode_all_btn = QPushButton("⚡ Encode All")
        encode_all_btn.setToolTip("Show every encoding, hash and format for this input — dencode.com style")
        encode_all_btn.clicked.connect(self.encode_all_formats)
        encode_all_btn.setMaximumHeight(36)
        encode_all_btn.setStyleSheet(
            f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #b8600a, stop:1 #e07b1a);
                padding: 6px 16px;
                font-weight: 600;
                font-size: {FONT_SIZE_SMALL};
                color: white;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #e07b1a, stop:1 #b8600a);
            }}
        """
        )
        header_layout.addWidget(encode_all_btn)

        # Quick action: Analyze - COMPACT
        analyze_btn = QPushButton("🗠 Analyze")
        analyze_btn.setToolTip("Deep analysis: entropy, patterns, signatures")
        analyze_btn.clicked.connect(self.analyze_input)
        analyze_btn.setMaximumHeight(36)  # ✓ LIMIT BUTTON HEIGHT
        analyze_btn.setStyleSheet(
            f"""
            QPushButton {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_LOW}, stop:1 {COLOR_SUCCESS});
                padding: 6px 16px;  /* ✓ LESS PADDING */
                font-weight: 600;
                font-size: {FONT_SIZE_SMALL};  /* ✓ SMALLER FONT */
                color: white;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 {COLOR_SUCCESS}, stop:1 {COLOR_LOW});
            }}
        """
        )
        header_layout.addWidget(analyze_btn)

        header_layout.addStretch()
        decoder_layout.addWidget(header_container)

        # ========================================================================
        # MAIN CONTENT - Horizontal Splitter (Operations | I/O)
        # ========================================================================

        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setHandleWidth(4)

        # ========================================================================
        # LEFT PANEL: Operations Sidebar
        # ========================================================================

        operations_panel = QWidget()
        operations_panel.setMaximumWidth(300)
        operations_panel.setStyleSheet(
            f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-radius: {RADIUS_MEDIUM};
            }}
        """
        )

        ops_layout = QVBoxLayout(operations_panel)
        ops_layout.setContentsMargins(8, 8, 8, 8)
        ops_layout.setSpacing(4)

        # Operations scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        ops_container = QWidget()
        ops_container_layout = QVBoxLayout(ops_container)
        ops_container_layout.setSpacing(2)

        # ========================================================================
        # ENCODING OPERATIONS
        # ========================================================================

        encoding_label = QLabel(" ENCODING")
        encoding_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_SUCCESS};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 4px;
            }}
        """
        )
        ops_container_layout.addWidget(encoding_label)

        encoding_ops = [
            ("Base64 Encode", self.encode_base64),
            ("Base32 Encode", self.encode_base32),
            ("Base85 Encode", self.encode_base85),
            ("URL Encode", self.encode_url),
            ("URL Encode (All)", self.encode_url_all),
            ("HTML Entity Encode", self.encode_html),
            ("Hex Encode", self.encode_hex),
            ("Binary Encode", self.encode_binary),
            ("Unicode Encode", self.encode_unicode),
            ("ROT13", self.encode_rot13),
            ("ASCII Hex", self.encode_ascii_hex),
        ]

        for label, handler in encoding_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        # ========================================================================
        # DECODING OPERATIONS
        # ========================================================================

        decoding_label = QLabel(" DECODING")
        decoding_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_CRITICAL};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 8px;
            }}
        """
        )
        ops_container_layout.addWidget(decoding_label)

        decoding_ops = [
            ("Base64 Decode", self.decode_base64),
            ("Base32 Decode", self.decode_base32),
            ("Base85 Decode", self.decode_base85),
            ("URL Decode", self.decode_url),
            ("HTML Entity Decode", self.decode_html),
            ("Hex Decode", self.decode_hex),
            ("Binary Decode", self.decode_binary),
            ("Unicode Decode", self.decode_unicode),
            ("JWT Decode", self.decode_jwt),
            ("Cookie Decode", self.decode_cookie),
        ]

        for label, handler in decoding_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        # ========================================================================
        # HASHING OPERATIONS
        # ========================================================================

        hash_label = QLabel(" HASHING")
        hash_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_MEDIUM};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 8px;
            }}
        """
        )
        ops_container_layout.addWidget(hash_label)

        hash_ops = [
            ("MD5", self.hash_md5),
            ("SHA1", self.hash_sha1),
            ("SHA256", self.hash_sha256),
            ("SHA512", self.hash_sha512),
            ("SHA3-256", self.hash_sha3_256),
            ("BLAKE2b", self.hash_blake2b),
            ("NTLM Hash", self.hash_ntlm),
        ]

        for label, handler in hash_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        # ========================================================================
        # PENTESTING UTILITIES
        # ========================================================================

        pentest_label = QLabel(" PENTESTING")
        pentest_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_HIGH};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 8px;
            }}
        """
        )
        ops_container_layout.addWidget(pentest_label)

        pentest_ops = [
            ("XSS Payload Encoder", self.encode_xss_payload),
            ("SQL Injection Encoder", self.encode_sql_payload),
            ("Command Injection Encoder", self.encode_cmd_payload),
        ]

        for label, handler in pentest_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        # ========================================================================
        # FORMAT & ANALYSIS
        # ========================================================================

        format_label = QLabel("FORMAT & ANALYSIS")
        format_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_LOW};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 8px;
            }}
        """
        )
        ops_container_layout.addWidget(format_label)

        format_ops = [
            ("JSON Prettify", self.prettify_json),
            ("JSON Minify", self.minify_json),
            ("XML Prettify", self.prettify_xml),
            ("Detect File Type", self.detect_file_type),
            ("Calculate Entropy", self.calculate_entropy),
            ("Character Frequency", self.character_frequency),
            ("Extract URLs", self.extract_urls),
            ("Extract IPs", self.extract_ips),
            ("Extract Emails", self.extract_emails),
            ("Extract Hashes", self.extract_hashes),
        ]

        for label, handler in format_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        # ========================================================================
        # CONVERSION UTILITIES
        # ========================================================================

        convert_label = QLabel("CONVERSIONS")
        convert_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_ACCENT_SECONDARY};
                font-weight: 700;
                font-size: {FONT_SIZE_NORMAL};
                padding: 6px;
                background-color: {COLOR_CARD_BG};
                border-radius: 4px;
                margin-top: 8px;
            }}
        """
        )
        ops_container_layout.addWidget(convert_label)

        convert_ops = [
            ("Timestamp to Date", self.timestamp_to_date),
            ("Date to Timestamp", self.date_to_timestamp),
            ("IP to Decimal", self.ip_to_decimal),
            ("Decimal to IP", self.decimal_to_ip),
            ("Reverse String", self.reverse_string),
            ("To Uppercase", self.to_uppercase),
            ("To Lowercase", self.to_lowercase),
            ("Swap Case", self.swap_case),
            ("Remove Whitespace", self.remove_whitespace),
            ("String Length", self.show_length),
        ]

        for label, handler in convert_ops:
            btn = self.create_operation_button(label, handler)
            ops_container_layout.addWidget(btn)

        ops_container_layout.addStretch()

        scroll.setWidget(ops_container)
        ops_layout.addWidget(scroll)

        main_splitter.addWidget(operations_panel)

        # ========================================================================
        # RIGHT PANEL: Input/Output with Tabs
        # ========================================================================

        io_panel = QWidget()
        io_layout = QVBoxLayout(io_panel)
        io_layout.setContentsMargins(0, 0, 0, 0)
        io_layout.setSpacing(8)

        # Create tabs for multiple operations
        self.decoder_tabs = QTabWidget()
        self.decoder_tabs.setTabsClosable(True)
        self.decoder_tabs.tabCloseRequested.connect(self.close_decoder_tab)

        # Add first default tab
        self.add_decoder_io_tab()

        # Add new tab button
        new_tab_btn = QPushButton("✚ New Tab")
        new_tab_btn.clicked.connect(self.add_decoder_io_tab)
        new_tab_btn.setMaximumWidth(100)
        self.decoder_tabs.setCornerWidget(new_tab_btn)

        io_layout.addWidget(self.decoder_tabs)

        main_splitter.addWidget(io_panel)

        # Set splitter sizes
        main_splitter.setSizes([300, 900])

        decoder_layout.addWidget(main_splitter)

        self.tab_widget.addTab(decoder_widget, "Decoder")

    def add_decoder_io_tab(self, name="Operation"):
        """Add a new input/output tab"""
        tab_widget = QWidget()
        tab_layout = QVBoxLayout(tab_widget)
        tab_layout.setContentsMargins(5, 5, 5, 5)
        tab_layout.setSpacing(8)

        # Vertical splitter for input/output
        io_splitter = QSplitter(Qt.Vertical)
        io_splitter.setHandleWidth(3)

        # ========================================================================
        # INPUT SECTION
        # ========================================================================

        input_container = QWidget()
        input_layout = QVBoxLayout(input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(4)

        # Input header
        input_header = QWidget()
        input_header_layout = QHBoxLayout(input_header)
        input_header_layout.setContentsMargins(0, 0, 0, 0)

        input_label = QLabel("INPUT")
        input_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_LARGE};
                font-weight: 700;
                padding: {SPACE_SM};
                background: {COLOR_ELEVATED_BG};
                border-radius: {RADIUS_MEDIUM};
                border-left: 4px solid {COLOR_ACCENT};
            }}
        """
        )
        input_header_layout.addWidget(input_label)

        # Input actions
        load_file_btn = QPushButton("Load File")
        load_file_btn.clicked.connect(lambda: self.load_file_to_decoder(tab_widget))
        input_header_layout.addWidget(load_file_btn)

        paste_btn = QPushButton("🗈 Paste")
        paste_btn.clicked.connect(lambda: self.paste_to_decoder(tab_widget))
        input_header_layout.addWidget(paste_btn)

        clear_input_btn = QPushButton("🗑 Clear")
        clear_input_btn.clicked.connect(lambda: self.clear_decoder_input(tab_widget))
        input_header_layout.addWidget(clear_input_btn)

        input_header_layout.addStretch()

        # Input stats
        input_stats = QLabel("0 bytes")
        input_stats.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};"
        )
        input_stats.setObjectName("input_stats")
        input_header_layout.addWidget(input_stats)

        input_layout.addWidget(input_header)

        # Input text area
        input_text = QTextEdit()
        input_text.setPlaceholderText("Enter data to encode/decode/analyze...")
        input_text.setStyleSheet(
            f"font-family: {FONT_FAMILY_MONO}; font-size: {FONT_SIZE_NORMAL};"
        )
        input_text.setObjectName("decoder_input")
        input_text.textChanged.connect(lambda: self.update_decoder_stats(tab_widget))
        input_layout.addWidget(input_text)

        io_splitter.addWidget(input_container)

        # ========================================================================
        # OUTPUT SECTION
        # ========================================================================

        output_container = QWidget()
        output_layout = QVBoxLayout(output_container)
        output_layout.setContentsMargins(0, 0, 0, 0)
        output_layout.setSpacing(4)

        # Output header
        output_header = QWidget()
        output_header_layout = QHBoxLayout(output_header)
        output_header_layout.setContentsMargins(0, 0, 0, 0)

        output_label = QLabel("OUTPUT")
        output_label.setStyleSheet(
            f"""
            QLabel {{
                color: {COLOR_TEXT_BRIGHT};
                font-size: {FONT_SIZE_LARGE};
                font-weight: 700;
                padding: {SPACE_SM};
                background: {COLOR_ELEVATED_BG};
                border-radius: {RADIUS_MEDIUM};
                border-left: 4px solid {COLOR_SUCCESS};
            }}
        """
        )
        output_header_layout.addWidget(output_label)

        # Output actions
        copy_output_btn = QPushButton("🗈 Copy")
        copy_output_btn.clicked.connect(lambda: self.copy_decoder_output(tab_widget))
        output_header_layout.addWidget(copy_output_btn)

        save_output_btn = QPushButton("Save")
        save_output_btn.clicked.connect(lambda: self.save_decoder_output(tab_widget))
        output_header_layout.addWidget(save_output_btn)

        send_to_input_btn = QPushButton("⮌ To Input")
        send_to_input_btn.setToolTip(
            "Send output back to input for chaining operations"
        )
        send_to_input_btn.clicked.connect(lambda: self.output_to_input(tab_widget))
        output_header_layout.addWidget(send_to_input_btn)

        clear_output_btn = QPushButton("🗑 Clear")
        clear_output_btn.clicked.connect(lambda: self.clear_decoder_output(tab_widget))
        output_header_layout.addWidget(clear_output_btn)

        output_header_layout.addStretch()

        # Output stats
        output_stats = QLabel("0 bytes")
        output_stats.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};"
        )
        output_stats.setObjectName("output_stats")
        output_header_layout.addWidget(output_stats)

        output_layout.addWidget(output_header)

        # Output text area
        output_text = QTextEdit()
        output_text.setReadOnly(True)
        output_text.setStyleSheet(
            f"font-family: {FONT_FAMILY_MONO}; font-size: {FONT_SIZE_NORMAL};"
        )
        output_text.setObjectName("decoder_output")
        output_text.textChanged.connect(lambda: self.update_decoder_stats(tab_widget))
        output_layout.addWidget(output_text)

        io_splitter.addWidget(output_container)

        # Set splitter sizes
        io_splitter.setSizes([400, 400])

        tab_layout.addWidget(io_splitter)

        # Add tab
        tab_index = self.decoder_tabs.addTab(tab_widget, name)
        self.decoder_tabs.setCurrentIndex(tab_index)

    def close_decoder_tab(self, index):
        """Close a decoder tab"""
        if self.decoder_tabs.count() > 1:
            self.decoder_tabs.removeTab(index)

    def create_operation_button(self, label, handler):
        """Create a styled operation button"""
        btn = QPushButton(label)
        btn.clicked.connect(handler)
        btn.setStyleSheet(
            f"""
            QPushButton {{
                text-align: left;
                padding: 8px 12px;
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                font-size: {FONT_SIZE_SMALL};
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                border-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
            }}
            QPushButton:pressed {{
                background-color: {COLOR_ACCENT};
                color: white;
            }}
        """
        )
        return btn

    def get_current_decoder_tab(self):
        """Get current decoder tab widget"""
        return self.decoder_tabs.currentWidget()

    def get_decoder_input(self, tab_widget=None, strip=False):
        """Get input text from decoder tab.

        strip=False (default) preserves exact content including trailing newlines,
        which matters for encoding operations (e.g. PEM blocks).
        Pass strip=True in decode/hash-parse operations where surrounding
        whitespace would cause a parse error.
        """
        if tab_widget is None:
            tab_widget = self.get_current_decoder_tab()

        if tab_widget:
            input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
            if input_widget:
                text = input_widget.toPlainText()
                return text.strip() if strip else text
        return ""

    def set_decoder_output(self, text, status="", tab_widget=None):
        """Set output text in decoder tab"""
        if tab_widget is None:
            tab_widget = self.get_current_decoder_tab()

        if tab_widget:
            output_widget = tab_widget.findChild(QTextEdit, "decoder_output")
            if output_widget:
                output_widget.setPlainText(text)

        if status:
            self.status_label.setText(status)
            QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))

    def update_decoder_stats(self, tab_widget):
        """Update byte count stats"""
        input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
        output_widget = tab_widget.findChild(QTextEdit, "decoder_output")
        input_stats = tab_widget.findChild(QLabel, "input_stats")
        output_stats = tab_widget.findChild(QLabel, "output_stats")

        if input_widget and input_stats:
            text = input_widget.toPlainText()
            byte_count = len(text.encode("utf-8"))
            char_count = len(text)
            input_stats.setText(f"{byte_count} bytes • {char_count} chars")

        if output_widget and output_stats:
            text = output_widget.toPlainText()
            byte_count = len(text.encode("utf-8"))
            char_count = len(text)
            output_stats.setText(f"{byte_count} bytes • {char_count} chars")

    # Encoding methods
    def encode_base64(self):
        """Encode to Base64"""
        text = self.get_decoder_input()
        if text:
            # QTextEdit.toPlainText() always strips the final trailing newline.
            # PEM blocks (and many other formats) are defined to end with \n,
            # so restore it when the last non-whitespace content is a PEM footer.
            if text.rstrip().endswith("-----") and not text.endswith("\n"):
                text += "\n"
            encoded = base64.b64encode(text.encode("utf-8")).decode("utf-8")
            self.set_decoder_output(encoded, "✓ Base64 encoded")

    def encode_url(self):
        """URL encode"""
        text = self.get_decoder_input()
        if text:
            encoded = urllib.parse.quote(text)
            self.set_decoder_output(encoded, "✓ URL encoded")

    def encode_html(self):
        """HTML entity encode"""
        text = self.get_decoder_input()
        if text:
            encoded = html.escape(text)
            self.set_decoder_output(encoded, "✓ HTML encoded")

    def encode_hex(self):
        """Encode to hex"""
        text = self.get_decoder_input()
        if text:
            encoded = text.encode("utf-8").hex()
            self.set_decoder_output(encoded, "✓ Hex encoded")

    def encode_unicode(self):
        """Encode to Unicode escape"""
        text = self.get_decoder_input()
        if text:
            encoded = text.encode("unicode_escape").decode("utf-8")
            self.set_decoder_output(encoded, "✓ Unicode encoded")

    def encode_base32(self):
        """Encode to Base32"""
        text = self.get_decoder_input()
        if text:
            try:
                encoded = base64.b32encode(text.encode("utf-8")).decode("utf-8")
                self.set_decoder_output(encoded, "✓ Base32 encoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Encoding failed")

    def encode_base85(self):
        """Encode to Base85 (ASCII85)"""
        text = self.get_decoder_input()
        if text:
            try:
                encoded = base64.b85encode(text.encode("utf-8")).decode("utf-8")
                self.set_decoder_output(encoded, "✓ Base85 encoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Encoding failed")

    def encode_url_all(self):
        """URL encode all characters"""
        text = self.get_decoder_input()
        if text:
            encoded = "".join(f"%{ord(c):02X}" for c in text)
            self.set_decoder_output(encoded, "✓ URL encoded (all chars)")

    def encode_binary(self):
        """Encode to binary (UTF-8 byte-level, 8 bits per byte)"""
        text = self.get_decoder_input()
        if text:
            binary = " ".join(format(b, "08b") for b in text.encode("utf-8"))
            self.set_decoder_output(binary, "✓ Binary encoded")

    def encode_rot13(self):
        """ROT13 encoding"""
        text = self.get_decoder_input()
        if text:
            import codecs

            encoded = codecs.encode(text, "rot_13")
            self.set_decoder_output(encoded, "✓ ROT13 encoded")

    def encode_ascii_hex(self):
        """Encode each character as \\xHH"""
        text = self.get_decoder_input()
        if text:
            encoded = "".join(f"\\x{ord(c):02x}" for c in text)
            self.set_decoder_output(encoded, "✓ ASCII Hex encoded")

    # Decoding methods
    def decode_base32(self):
        """Decode from Base32"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                # casefold=True accepts both upper and lowercase base32
                decoded = base64.b32decode(text, casefold=True).decode("utf-8", errors="replace")
                self.set_decoder_output(decoded, "✓ Base32 decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_base85(self):
        """Decode from Base85"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                decoded = base64.b85decode(text).decode("utf-8", errors="replace")
                self.set_decoder_output(decoded, "✓ Base85 decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_binary(self):
        """Decode from binary (UTF-8 byte-level, 8 bits per byte)"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                # Remove spaces/newlines and split into 8-bit chunks
                binary = text.replace(" ", "").replace("\n", "")
                if len(binary) % 8 != 0:
                    self.set_decoder_output(
                        f"Error: binary length ({len(binary)}) is not a multiple of 8",
                        "✘ Decode failed",
                    )
                    return
                raw_bytes = bytes(
                    int(binary[i : i + 8], 2) for i in range(0, len(binary), 8)
                )
                decoded = raw_bytes.decode("utf-8", errors="replace")
                self.set_decoder_output(decoded, "✓ Binary decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_cookie(self):
        """Parse and decode cookies"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                result = "=== COOKIE PARSER ===\n\n"

                # Split cookies
                cookies = text.split(";")
                for cookie in cookies:
                    if "=" in cookie:
                        name, value = cookie.split("=", 1)
                        name = name.strip()
                        value = value.strip()

                        result += f"Name: {name}\n"
                        result += f"Value: {value}\n"

                        # Try to decode common encodings
                        try:
                            url_decoded = urllib.parse.unquote(value)
                            if url_decoded != value:
                                result += f"URL Decoded: {url_decoded}\n"
                        except:
                            pass

                        try:
                            b64_decoded = base64.b64decode(value).decode(
                                "utf-8", errors="replace"
                            )
                            if b64_decoded.isprintable():
                                result += f"Base64 Decoded: {b64_decoded}\n"
                        except:
                            pass

                        result += "\n"

                self.set_decoder_output(result, "✓ Cookie parsed")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Parse failed")

    def decode_base64(self):
        """Decode from Base64"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                decoded = base64.b64decode(text).decode("utf-8", errors="replace")
                self.set_decoder_output(decoded, "✓ Base64 decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_url(self):
        """URL decode"""
        text = self.get_decoder_input(strip=True)
        if text:
            decoded = urllib.parse.unquote(text)
            self.set_decoder_output(decoded, "✓ URL decoded")

    def decode_html(self):
        """HTML entity decode"""
        text = self.get_decoder_input(strip=True)
        if text:
            decoded = html.unescape(text)
            self.set_decoder_output(decoded, "✓ HTML decoded")

    def decode_hex(self):
        """Decode from hex"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                # Strip common hex formats: 0xAB, \xAB, AB:CD, AB-CD
                clean = re.sub(r'(0x|\\x)', '', text)
                clean = clean.replace(':', '').replace('-', '').replace(' ', '')
                decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
                self.set_decoder_output(decoded, "✓ Hex decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_unicode(self):
        """Decode Unicode escape sequences (\\uXXXX, \\xXX)"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                # raw_unicode_escape correctly preserves non-ASCII chars before
                # unicode_escape decodes the \uXXXX / \xXX sequences
                decoded = text.encode("raw_unicode_escape").decode("unicode_escape")
                self.set_decoder_output(decoded, "✓ Unicode decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Decode failed")

    def decode_jwt(self):
        """Decode JWT token"""
        text = self.get_decoder_input(strip=True)
        if text:
            try:
                parts = text.split(".")
                if len(parts) != 3:
                    self.set_decoder_output(
                        "Invalid JWT format (should have 3 parts)", "✘ Invalid JWT"
                    )
                    return

                # Decode header and payload
                header = json.loads(
                    base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8")
                )
                payload = json.loads(
                    base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8")
                )

                result = "=== JWT HEADER ===\n"
                result += json.dumps(header, indent=2)
                result += "\n\n=== JWT PAYLOAD ===\n"
                result += json.dumps(payload, indent=2)
                result += "\n\n=== JWT SIGNATURE ===\n"
                result += parts[2]

                self.set_decoder_output(result, "✓ JWT decoded")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ JWT decode failed")

    # Hash methods
    def hash_md5(self):
        """Calculate MD5 hash"""
        text = self.get_decoder_input()
        if text:
            hashed = hashlib.md5(text.encode("utf-8")).hexdigest()
            self.set_decoder_output(hashed, "✓ MD5 hash calculated")

    def hash_sha1(self):
        """Calculate SHA1 hash"""
        text = self.get_decoder_input()
        if text:
            hashed = hashlib.sha1(text.encode("utf-8")).hexdigest()
            self.set_decoder_output(hashed, "✓ SHA1 hash calculated")

    def hash_sha256(self):
        """Calculate SHA256 hash"""
        text = self.get_decoder_input()
        if text:
            hashed = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self.set_decoder_output(hashed, "✓ SHA256 hash calculated")

    def hash_sha512(self):
        """Calculate SHA512 hash"""
        text = self.get_decoder_input()
        if text:
            hashed = hashlib.sha512(text.encode("utf-8")).hexdigest()
            self.set_decoder_output(hashed, "✓ SHA512 hash calculated")

    def hash_sha3_256(self):
        """Calculate SHA3-256 hash"""
        text = self.get_decoder_input()
        if text:
            try:
                import hashlib

                hashed = hashlib.sha3_256(text.encode("utf-8")).hexdigest()
                self.set_decoder_output(hashed, "✓ SHA3-256 hash calculated")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Hash failed")

    def hash_blake2b(self):
        """Calculate BLAKE2b hash"""
        text = self.get_decoder_input()
        if text:
            try:
                import hashlib

                hashed = hashlib.blake2b(text.encode("utf-8")).hexdigest()
                self.set_decoder_output(hashed, "✓ BLAKE2b hash calculated")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Hash failed")

    def hash_ntlm(self):
        """Calculate NTLM hash (for Windows passwords)"""
        text = self.get_decoder_input()
        if text:
            try:
                import hashlib

                ntlm = hashlib.new("md4", text.encode("utf-16le")).hexdigest()
                self.set_decoder_output(ntlm.upper(), "✓ NTLM hash calculated")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Hash failed")

    # PENTESTING UTILITIES
    def encode_xss_payload(self):
        """Generate XSS payload variants"""
        text = self.get_decoder_input()
        if not text:
            text = "<script>alert('XSS')</script>"

        result = "=== XSS PAYLOAD VARIANTS ===\n\n"

        # Standard
        result += f"Standard:\n{text}\n\n"

        # URL encoded
        result += f"URL Encoded:\n{urllib.parse.quote(text)}\n\n"

        # Double URL encoded
        result += (
            f"Double URL Encoded:\n{urllib.parse.quote(urllib.parse.quote(text))}\n\n"
        )

        # HTML entity encoded
        result += f"HTML Entity:\n{html.escape(text)}\n\n"

        # Unicode encoded
        result += f"Unicode:\n{''.join(f'\\u{ord(c):04x}' for c in text)}\n\n"

        # Hex encoded
        result += f"Hex:\n{''.join(f'&#x{ord(c):x};' for c in text)}\n\n"

        # Common bypasses
        result += "Common Bypasses:\n"
        result += f"<sCrIpT>alert('XSS')</sCrIpT>\n"
        result += f"<script/src=//⑮.₨></script>\n"
        result += f"<svg onload=alert('XSS')>\n"
        result += f"<img src=x onerror=alert('XSS')>\n"
        result += f"<iframe src=javascript:alert('XSS')>\n"

        self.set_decoder_output(result, "✓ XSS payloads generated")

    def encode_sql_payload(self):
        """Generate SQL injection payload variants"""
        text = self.get_decoder_input()
        if not text:
            text = "' OR '1'='1"

        result = "=== SQL INJECTION VARIANTS ===\n\n"

        # Standard
        result += f"Standard:\n{text}\n\n"

        # URL encoded
        result += f"URL Encoded:\n{urllib.parse.quote(text)}\n\n"

        # Double URL encoded
        result += (
            f"Double URL Encoded:\n{urllib.parse.quote(urllib.parse.quote(text))}\n\n"
        )

        # Hex encoded
        result += f"Hex Encoded:\n{''.join(f'%{ord(c):02x}' for c in text)}\n\n"

        # Common payloads
        result += "Common Payloads:\n"
        result += "' OR '1'='1' --\n"
        result += "' OR '1'='1' /*\n"
        result += "admin' --\n"
        result += "admin' #\n"
        result += "' UNION SELECT NULL--\n"
        result += "' AND 1=1--\n"
        result += "' AND '1'='1\n"

        self.set_decoder_output(result, "✓ SQL payloads generated")

    def encode_cmd_payload(self):
        """Generate command injection payload variants"""
        text = self.get_decoder_input()
        if not text:
            text = "; ls -la"

        result = "=== COMMAND INJECTION VARIANTS ===\n\n"

        # Standard
        result += f"Standard:\n{text}\n\n"

        # Different separators
        result += "Separators:\n"
        result += f"; {text}\n"
        result += f"| {text}\n"
        result += f"|| {text}\n"
        result += f"& {text}\n"
        result += f"&& {text}\n"
        result += f"`{text}`\n"
        result += f"$({text})\n\n"

        # URL encoded
        result += f"URL Encoded:\n{urllib.parse.quote(text)}\n\n"

        # Common bypasses
        result += "Bypass Techniques:\n"
        result += f";{text}\n"
        result += f"\\n{text}\n"
        result += f"%0a{text}\n"
        result += f"|{text}|\n"

        self.set_decoder_output(result, "✓ Command injection payloads generated")

    # Format methods
    def prettify_json(self):
        """Prettify JSON"""
        text = self.get_decoder_input()
        if text:
            try:
                parsed = json.loads(text)
                pretty = json.dumps(parsed, indent=2)
                self.set_decoder_output(pretty, "✨ JSON prettified")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Invalid JSON")

    def minify_json(self):
        """Minify JSON"""
        text = self.get_decoder_input()
        if text:
            try:
                parsed = json.loads(text)
                minified = json.dumps(parsed, separators=(",", ":"))
                self.set_decoder_output(minified, "✓ JSON minified")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Invalid JSON")

    def prettify_xml(self):
        """Prettify XML"""
        text = self.get_decoder_input()
        if text:
            try:
                dom = xml.dom.minidom.parseString(text)
                pretty = dom.toprettyxml(indent="  ")
                self.set_decoder_output(pretty, "✨ XML prettified")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Invalid XML")

    # Analysis methods
    def detect_file_type(self):
        """Detect file type from magic bytes"""
        text = self.get_decoder_input()
        if text:
            try:
                # Try to decode if base64
                try:
                    data = base64.b64decode(text)
                except:
                    data = text.encode("utf-8")

                # Check magic bytes
                signatures = {
                    b"\xff\xd8\xff": "JPEG Image",
                    b"\x89PNG\r\n\x1a\n": "PNG Image",
                    b"GIF87a": "GIF Image (87a)",
                    b"GIF89a": "GIF Image (89a)",
                    b"%PDF": "PDF Document",
                    b"PK\x03\x04": "ZIP Archive (or DOCX/XLSX/JAR)",
                    b"\x1f\x8b": "GZIP Archive",
                    b"BZh": "BZIP2 Archive",
                    b"Rar!\x1a\x07": "RAR Archive",
                    b"\x7fELF": "ELF Executable (Linux)",
                    b"MZ": "PE Executable (Windows)",
                    b"\xca\xfe\xba\xbe": "Java Class File",
                    b"<?xml": "XML Document",
                    b"<html": "HTML Document",
                    b"{": "JSON Data (likely)",
                }

                result = "=== FILE TYPE DETECTION ===\n\n"
                detected = False

                for magic, file_type in signatures.items():
                    if data.startswith(magic):
                        result += f"Detected: {file_type}\n"
                        result += f"Magic Bytes: {magic.hex()}\n"
                        detected = True
                        break

                if not detected:
                    result += "Unknown file type\n"

                result += f"\nFirst 32 bytes (hex):\n{data[:32].hex()}\n"
                result += f"\nFirst 32 bytes (ascii):\n{data[:32].decode('ascii', errors='replace')}\n"

                self.set_decoder_output(result, "✓ File type analyzed")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Analysis failed")

    def calculate_entropy(self):
        """Calculate Shannon entropy"""
        text = self.get_decoder_input()
        if text:
            try:
                import math
                from collections import Counter

                # Calculate entropy
                counter = Counter(text)
                length = len(text)
                entropy = -sum(
                    (count / length) * math.log2(count / length)
                    for count in counter.values()
                )

                result = "=== ENTROPY ANALYSIS ===\n\n"
                result += f"Shannon Entropy: {entropy:.4f} bits/char\n"
                result += f"Length: {length} characters\n"
                result += f"Unique characters: {len(counter)}\n\n"

                # Interpretation
                if entropy < 3.5:
                    result += "Assessment: Low entropy (likely plain text)\n"
                elif entropy < 5.0:
                    result += "Assessment: Medium entropy (compressed/encoded data)\n"
                else:
                    result += "Assessment: High entropy (encrypted/random data)\n"

                result += f"\nNote: Maximum entropy for ASCII is ~6.57 bits/char\n"

                self.set_decoder_output(result, "✓ Entropy calculated")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Calculation failed")

    def character_frequency(self):
        """Analyze character frequency"""
        text = self.get_decoder_input()
        if text:
            try:
                from collections import Counter

                counter = Counter(text)
                total = len(text)

                result = "=== CHARACTER FREQUENCY ANALYSIS ===\n\n"
                result += f"Total characters: {total}\n"
                result += f"Unique characters: {len(counter)}\n\n"
                result += "Top 20 characters:\n"
                result += f"{'Char':<10} {'Count':<10} {'Frequency':<15} {'Bar'}\n"
                result += "-" * 60 + "\n"

                for char, count in counter.most_common(20):
                    freq = (count / total) * 100
                    bar = "█" * int(freq * 2)  # Visual bar
                    char_display = repr(char) if char in "\n\r\t" else char
                    result += (
                        f"{char_display:<10} {count:<10} {freq:>6.2f}%        {bar}\n"
                    )

                self.set_decoder_output(result, "✓ Frequency analyzed")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Analysis failed")

    def extract_urls(self):
        """Extract all URLs from text"""
        text = self.get_decoder_input()
        if text:
            import re

            url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
            urls = re.findall(url_pattern, text)

            result = f"=== EXTRACTED URLs ({len(urls)}) ===\n\n"
            for url in urls:
                result += f"{url}\n"

            if not urls:
                result += "No URLs found\n"

            self.set_decoder_output(result, f"✓ Found {len(urls)} URLs")

    def extract_ips(self):
        """Extract all IP addresses from text"""
        text = self.get_decoder_input()
        if text:
            import re

            ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
            ips = re.findall(ip_pattern, text)

            result = f"=== EXTRACTED IPs ({len(ips)}) ===\n\n"
            for ip in ips:
                result += f"{ip}\n"

            if not ips:
                result += "No IP addresses found\n"

            self.set_decoder_output(result, f"✓ Found {len(ips)} IPs")

    def extract_emails(self):
        """Extract all email addresses from text"""
        text = self.get_decoder_input()
        if text:
            import re

            email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            emails = re.findall(email_pattern, text)

            result = f"=== EXTRACTED Emails ({len(emails)}) ===\n\n"
            for email in emails:
                result += f"{email}\n"

            if not emails:
                result += "No email addresses found\n"

            self.set_decoder_output(result, f"✓ Found {len(emails)} emails")

    def extract_hashes(self):
        """Extract potential hashes from text"""
        text = self.get_decoder_input()
        if text:
            import re

            result = "=== EXTRACTED HASHES ===\n\n"

            # MD5 (32 hex chars)
            md5_pattern = r"\b[a-fA-F0-9]{32}\b"
            md5s = re.findall(md5_pattern, text)
            result += f"MD5 ({len(md5s)}):\n"
            for h in md5s[:10]:
                result += f"  {h}\n"
            if len(md5s) > 10:
                result += f"  ... and {len(md5s)-10} more\n"
            result += "\n"

            # SHA1 (40 hex chars)
            sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
            sha1s = re.findall(sha1_pattern, text)
            result += f"SHA1 ({len(sha1s)}):\n"
            for h in sha1s[:10]:
                result += f"  {h}\n"
            if len(sha1s) > 10:
                result += f"  ... and {len(sha1s)-10} more\n"
            result += "\n"

            # SHA256 (64 hex chars)
            sha256_pattern = r"\b[a-fA-F0-9]{64}\b"
            sha256s = re.findall(sha256_pattern, text)
            result += f"SHA256 ({len(sha256s)}):\n"
            for h in sha256s[:10]:
                result += f"  {h}\n"
            if len(sha256s) > 10:
                result += f"  ... and {len(sha256s)-10} more\n"

            total = len(md5s) + len(sha1s) + len(sha256s)
            self.set_decoder_output(result, f"✓ Found {total} hashes")

    # CONVERSION UTILITIES
    def timestamp_to_date(self):
        """Convert Unix timestamp to readable date"""
        text = self.get_decoder_input()
        if text:
            try:
                from datetime import datetime

                # Try as integer timestamp
                timestamp = int(text.strip())

                result = "=== TIMESTAMP CONVERSION ===\n\n"

                # Unix timestamp (seconds)
                dt = datetime.fromtimestamp(timestamp)
                result += (
                    f"Unix timestamp (seconds):\n{dt.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                )

                # Unix timestamp (milliseconds)
                dt_ms = datetime.fromtimestamp(timestamp / 1000)
                result += f"Unix timestamp (milliseconds):\n{dt_ms.strftime('%Y-%m-%d %H:%M:%S.%f')}\n\n"

                # ISO format
                result += f"ISO 8601:\n{dt.isoformat()}\n\n"

                # UTC
                from datetime import timezone

                dt_utc = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                result += f"UTC:\n{dt_utc.strftime('%Y-%m-%d %H:%M:%S %Z')}\n"

                self.set_decoder_output(result, "✓ Timestamp converted")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Conversion failed")

    def date_to_timestamp(self):
        """Convert date to Unix timestamp"""
        text = self.get_decoder_input()
        if text:
            try:
                from datetime import datetime

                # Try common date formats
                formats = [
                    "%Y-%m-%d %H:%M:%S",
                    "%Y-%m-%d",
                    "%d/%m/%Y %H:%M:%S",
                    "%d/%m/%Y",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%SZ",
                ]

                dt = None
                for fmt in formats:
                    try:
                        dt = datetime.strptime(text.strip(), fmt)
                        break
                    except:
                        continue

                if dt:
                    timestamp = int(dt.timestamp())

                    result = "=== DATE TO TIMESTAMP ===\n\n"
                    result += f"Unix timestamp (seconds):\n{timestamp}\n\n"
                    result += f"Unix timestamp (milliseconds):\n{timestamp * 1000}\n\n"
                    result += f"Parsed date:\n{dt.strftime('%Y-%m-%d %H:%M:%S')}\n"

                    self.set_decoder_output(result, "✓ Date converted")
                else:
                    self.set_decoder_output(
                        "Could not parse date. Try: YYYY-MM-DD HH:MM:SS",
                        "✘ Parse failed",
                    )
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Conversion failed")

    def ip_to_decimal(self):
        """Convert IP address to decimal"""
        text = self.get_decoder_input()
        if text:
            try:
                import ipaddress

                ip = ipaddress.IPv4Address(text.strip())
                decimal = int(ip)

                result = "=== IP TO DECIMAL ===\n\n"
                result += f"IP Address: {text.strip()}\n"
                result += f"Decimal: {decimal}\n"
                result += f"Hex: 0x{decimal:08X}\n"
                result += f"Binary: {bin(decimal)}\n"

                self.set_decoder_output(result, "✓ IP converted")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Conversion failed")

    def decimal_to_ip(self):
        """Convert decimal to IP address"""
        text = self.get_decoder_input()
        if text:
            try:
                import ipaddress

                decimal = int(text.strip())
                ip = ipaddress.IPv4Address(decimal)

                result = "=== DECIMAL TO IP ===\n\n"
                result += f"Decimal: {decimal}\n"
                result += f"IP Address: {ip}\n"
                result += f"Hex: 0x{decimal:08X}\n"

                self.set_decoder_output(result, "✓ Decimal converted")
            except Exception as e:
                self.set_decoder_output(f"Error: {str(e)}", "✘ Conversion failed")

    def to_uppercase(self):
        """Convert to uppercase"""
        text = self.get_decoder_input()
        if text:
            self.set_decoder_output(text.upper(), "✓ Converted to uppercase")

    def to_lowercase(self):
        """Convert to lowercase"""
        text = self.get_decoder_input()
        if text:
            self.set_decoder_output(text.lower(), "✓ Converted to lowercase")

    def swap_case(self):
        """Swap case"""
        text = self.get_decoder_input()
        if text:
            self.set_decoder_output(text.swapcase(), "✓ Case swapped")

    def remove_whitespace(self):
        """Remove all whitespace"""
        text = self.get_decoder_input()
        if text:
            result = "".join(text.split())
            self.set_decoder_output(result, "✓ Whitespace removed")

    def show_length(self):
        """Show string length"""
        text = self.get_decoder_input()
        if text:
            result = f"Length: {len(text)} characters\n"
            result += f"Bytes: {len(text.encode('utf-8'))} bytes\n"
            result += f"Lines: {len(text.splitlines())} lines\n"
            result += f"Words: {len(text.split())} words"
            self.set_decoder_output(result, "🗠 Length calculated")

    def reverse_string(self):
        """Reverse string"""
        text = self.get_decoder_input()
        if text:
            reversed_text = text[::-1]
            self.set_decoder_output(reversed_text, "↤ String reversed")

    def smart_decode_advanced(self):
        """Advanced smart decode with AI-like detection and multiple layers"""
        text = self.get_decoder_input()
        if not text:
            self.set_decoder_output("No input provided", "⚠ Empty input")
            return

        import re

        result = (
            "╔══════════════════════════════════════════════════════════════════╗\n"
        )
        result += "║           🧠 SMART MULTI-LAYER DECODER - ADVANCED              ║\n"
        result += (
            "╚══════════════════════════════════════════════════════════════════╝\n\n"
        )

        current = text.strip()
        layer = 0
        max_layers = 15
        history = []

        result += f"📥 INPUT ({len(current)} chars):\n"
        result += f"{current[:150]}\n"
        if len(current) > 150:
            result += "... (truncated)\n"
        result += "\n" + "=" * 70 + "\n\n"

        while layer < max_layers:
            decoded = None
            encoding_type = None
            confidence = 0

            # Detect encoding type with confidence scoring
            detections = []

            # ================================================================
            # JWT Detection
            # ================================================================
            jwt_pattern = r"^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$"
            if re.match(jwt_pattern, current):
                try:
                    parts = current.split(".")
                    header = base64.b64decode(parts[0] + "==").decode(
                        "utf-8", errors="replace"
                    )
                    payload = base64.b64decode(parts[1] + "==").decode(
                        "utf-8", errors="replace"
                    )

                    decoded = f"=== JWT TOKEN ===\n\nHeader:\n{header}\n\nPayload:\n{payload}\n\nSignature:\n{parts[2]}"
                    encoding_type = "JWT"
                    confidence = 99
                    detections.append(("JWT", 99))
                except:
                    pass

            # ================================================================
            # Base64 Detection (with validation)
            # ================================================================
            if not decoded:
                # Base64 regex: only valid base64 chars and proper padding
                base64_pattern = r"^[A-Za-z0-9+/]*={0,2}$"
                if len(current) % 4 == 0 and re.match(base64_pattern, current):
                    try:
                        temp = base64.b64decode(current)
                        # Try UTF-8 decode
                        try:
                            text_decoded = temp.decode("utf-8")
                            if text_decoded.isprintable() or any(
                                c in text_decoded for c in "\n\r\t"
                            ):
                                decoded = text_decoded
                                encoding_type = "Base64"
                                confidence = 95
                                detections.append(("Base64 (UTF-8)", 95))
                        except:
                            # If not UTF-8, show hex
                            if len(temp) < 500:
                                decoded = f"[Binary data - {len(temp)} bytes]\nHex: {temp.hex()}"
                                encoding_type = "Base64 (Binary)"
                                confidence = 90
                                detections.append(("Base64 (Binary)", 90))
                    except:
                        pass

            # ================================================================
            # Base32 Detection
            # ================================================================
            if not decoded:
                base32_pattern = r"^[A-Z2-7]+=*$"
                if re.match(base32_pattern, current.upper()):
                    try:
                        temp = base64.b32decode(current.upper()).decode(
                            "utf-8", errors="replace"
                        )
                        if temp.isprintable():
                            decoded = temp
                            encoding_type = "Base32"
                            confidence = 85
                            detections.append(("Base32", 85))
                    except:
                        pass

            # ================================================================
            # Hex Detection (with and without spaces/delimiters)
            # ================================================================
            if not decoded:
                # Check for hex with various formats
                hex_patterns = [
                    (r"^[0-9a-fA-F]+$", ""),  # Pure hex
                    (r"^(?:[0-9a-fA-F]{2}\s*)+$", " "),  # Hex with spaces
                    (r"^(?:0x[0-9a-fA-F]{2}\s*)+$", "0x"),  # 0x prefix
                    (r"^(?:\\x[0-9a-fA-F]{2})+$", "\\x"),  # \x prefix
                ]

                for pattern, prefix in hex_patterns:
                    if re.match(pattern, current):
                        try:
                            hex_clean = (
                                current.replace(" ", "")
                                .replace("0x", "")
                                .replace("\\x", "")
                            )
                            if len(hex_clean) % 2 == 0:
                                temp = bytes.fromhex(hex_clean).decode(
                                    "utf-8", errors="replace"
                                )
                                if temp.isprintable():
                                    decoded = temp
                                    encoding_type = "Hexadecimal"
                                    confidence = 90
                                    detections.append(("Hexadecimal", 90))
                                    break
                        except:
                            pass

            # ================================================================
            # URL Encoding Detection
            # ================================================================
            if not decoded:
                if "%" in current:
                    try:
                        temp = urllib.parse.unquote(current)
                        if temp != current:
                            # Check if significantly decoded
                            decode_ratio = (
                                len(temp) / len(current) if len(current) > 0 else 0
                            )
                            if decode_ratio < 0.95:  # At least 5% reduction
                                decoded = temp
                                encoding_type = "URL Encoded"
                                confidence = 85
                                detections.append(("URL Encoded", 85))
                    except:
                        pass

            # ================================================================
            # HTML Entity Detection
            # ================================================================
            if not decoded:
                if "&" in current and ";" in current:
                    try:
                        temp = html.unescape(current)
                        if temp != current:
                            decoded = temp
                            encoding_type = "HTML Entities"
                            confidence = 80
                            detections.append(("HTML Entities", 80))
                    except:
                        pass

            # ================================================================
            # Unicode Escape Detection (\uXXXX or \xXX)
            # ================================================================
            if not decoded:
                if "\\u" in current or "\\x" in current:
                    try:
                        # raw_unicode_escape correctly handles the codec chain
                        temp = current.encode("raw_unicode_escape").decode("unicode_escape")
                        if temp != current:
                            decoded = temp
                            encoding_type = "Unicode Escape"
                            confidence = 85
                            detections.append(("Unicode Escape", 85))
                    except:
                        pass

            # ================================================================
            # Binary String Detection (01010101...)
            # ================================================================
            if not decoded:
                if all(c in "01 " for c in current):
                    try:
                        binary_clean = current.replace(" ", "")
                        if len(binary_clean) % 8 == 0:
                            temp = "".join(
                                chr(int(binary_clean[i : i + 8], 2))
                                for i in range(0, len(binary_clean), 8)
                            )
                            if temp.isprintable():
                                decoded = temp
                                encoding_type = "Binary"
                                confidence = 95
                                detections.append(("Binary", 95))
                    except:
                        pass

            # ================================================================
            # ROT13 Detection (heuristic)
            # ================================================================
            if not decoded and current.isalpha():
                try:
                    import codecs

                    temp = codecs.decode(current, "rot_13")
                    # Check if result looks more like English
                    common_words = ["the", "and", "is", "in", "to", "of", "a"]
                    score = sum(1 for word in common_words if word in temp.lower())
                    if score >= 2:
                        decoded = temp
                        encoding_type = "ROT13"
                        confidence = 60
                        detections.append(("ROT13", 60))
                except:
                    pass

            # ================================================================
            # Gzip Detection (magic bytes)
            # ================================================================
            if not decoded:
                try:
                    # Try base64 decode first, then check for gzip
                    try:
                        data = base64.b64decode(current)
                    except:
                        data = current.encode("latin1")

                    if data.startswith(b"\x1f\x8b"):
                        import gzip

                        temp = gzip.decompress(data).decode("utf-8", errors="replace")
                        decoded = temp
                        encoding_type = "Gzip Compressed"
                        confidence = 95
                        detections.append(("Gzip", 95))
                except:
                    pass

            # ================================================================
            # Show detection results and proceed
            # ================================================================
            if decoded and decoded != current:
                layer += 1

                result += (
                    f"🔍 LAYER {layer} - {encoding_type} (Confidence: {confidence}%)\n"
                )
                result += "-" * 70 + "\n"

                # Show alternative detections if any
                if len(detections) > 1:
                    result += "Other possible encodings:\n"
                    for enc_type, conf in sorted(
                        detections, key=lambda x: x[1], reverse=True
                    )[1:4]:
                        result += f"  • {enc_type} ({conf}%)\n"
                    result += "\n"

                # Show decoded content (with truncation for long text)
                preview_length = 300
                if len(decoded) <= preview_length:
                    result += f"Decoded:\n{decoded}\n"
                else:
                    result += (
                        f"Decoded ({len(decoded)} chars):\n{decoded[:preview_length]}\n"
                    )
                    result += f"... [truncated, showing first {preview_length} chars]\n"

                result += "\n" + "=" * 70 + "\n\n"

                # Store in history
                history.append(
                    {
                        "layer": layer,
                        "type": encoding_type,
                        "confidence": confidence,
                        "length": len(decoded),
                    }
                )

                # Move to next layer
                current = decoded
            else:
                # No more encoding detected
                break

        # ================================================================
        # FINAL SUMMARY
        # ================================================================
        result += (
            "╔══════════════════════════════════════════════════════════════════╗\n"
        )
        result += (
            "║                        🗠 DECODE SUMMARY                         ║\n"
        )
        result += (
            "╚══════════════════════════════════════════════════════════════════╝\n\n"
        )

        if layer == 0:
            result += "✘ No encoding detected or unable to decode.\n\n"
            result += "🞉 Tips:\n"
            result += "  • Make sure input is properly formatted\n"
            result += "  • Try manual decode operations from the sidebar\n"
            result += "  • Check for custom/proprietary encodings\n"
        else:
            result += f"✓ Successfully decoded {layer} layer(s)\n\n"
            result += "Decoding chain:\n"
            for i, h in enumerate(history, 1):
                result += f"  {i}. {h['type']} (Confidence: {h['confidence']}%) → {h['length']} chars\n"

            result += f"\n📤 FINAL OUTPUT ({len(current)} chars):\n"
            result += "=" * 70 + "\n"
            result += current
            result += "\n" + "=" * 70 + "\n"

        self.set_decoder_output(result, f"✓ Smart decode complete - {layer} layers")

    # =========================================================================
    # ⚡ ENCODE ALL — dencode.com style
    # =========================================================================
    def encode_all_formats(self):
        """Encode/hash/transform input in every format at once (dencode.com style)."""
        text = self.get_decoder_input()
        if not text:
            self.set_decoder_output("No input provided", "⚠ Empty input")
            return

        raw = text
        raw_bytes = raw.encode("utf-8")
        stripped = raw.strip()

        SEP  = "─" * 72
        SEP2 = "═" * 72

        def section(title: str, color_char="") -> str:
            return f"\n{SEP2}\n  {color_char}{title}\n{SEP2}\n"

        def row(label: str, value: str) -> str:
            return f"  {label:<32}  {value}\n"

        out = ""
        out += SEP2 + "\n"
        out += "  ⚡ ENCODE ALL — every format at a glance\n"
        out += f"  Input: {len(raw)} chars · {len(raw_bytes)} bytes\n"
        out += SEP2 + "\n"

        # ── BASE ENCODINGS ────────────────────────────────────────────────────
        out += section("BASE ENCODINGS", "  ")
        try:
            out += row("Base64",    base64.b64encode(raw_bytes).decode())
        except Exception as e:
            out += row("Base64",    f"[error: {e}]")
        try:
            out += row("Base64 URL-safe", base64.urlsafe_b64encode(raw_bytes).decode())
        except Exception as e:
            out += row("Base64 URL-safe", f"[error: {e}]")
        try:
            out += row("Base32",    base64.b32encode(raw_bytes).decode())
        except Exception as e:
            out += row("Base32",    f"[error: {e}]")
        try:
            out += row("Base32 Hex", base64.b32hexencode(raw_bytes).decode())
        except Exception:
            try:
                import base64 as _b64
                alphabet = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
                b32 = base64.b32encode(raw_bytes).decode()
                mapping = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "0123456789ABCDEFGHIJKLMNOPQRSTUV")
                out += row("Base32 Hex", b32.translate(mapping))
            except Exception as e:
                out += row("Base32 Hex", f"[error: {e}]")
        try:
            out += row("Base85 (ASCII85)", base64.b85encode(raw_bytes).decode())
        except Exception as e:
            out += row("Base85 (ASCII85)", f"[error: {e}]")
        try:
            import base64 as _b
            out += row("Base16 (Hex)", raw_bytes.hex().upper())
        except Exception as e:
            out += row("Base16 (Hex)", f"[error: {e}]")

        # ── URL / PERCENT ENCODING ────────────────────────────────────────────
        out += section("URL / PERCENT ENCODING", "  ")
        try:
            out += row("URL Encode (RFC 3986)",    urllib.parse.quote(raw, safe=""))
        except Exception as e:
            out += row("URL Encode (RFC 3986)",    f"[error: {e}]")
        try:
            out += row("URL Encode (keep /)",      urllib.parse.quote(raw, safe="/"))
        except Exception as e:
            out += row("URL Encode (keep /)",      f"[error: {e}]")
        try:
            out += row("URL Encode ALL chars",     "".join(f"%{b:02X}" for b in raw_bytes))
        except Exception as e:
            out += row("URL Encode ALL chars",     f"[error: {e}]")
        try:
            out += row("Double URL Encode",        urllib.parse.quote(urllib.parse.quote(raw, safe=""), safe=""))
        except Exception as e:
            out += row("Double URL Encode",        f"[error: {e}]")
        try:
            out += row("Form Encoded (+spaces)",   urllib.parse.quote_plus(raw))
        except Exception as e:
            out += row("Form Encoded (+spaces)",   f"[error: {e}]")

        # ── HTML ENCODING ─────────────────────────────────────────────────────
        out += section("HTML ENCODING", "  ")
        try:
            out += row("HTML Entities",            html.escape(raw))
        except Exception as e:
            out += row("HTML Entities",            f"[error: {e}]")
        try:
            out += row("HTML Entities (quotes)",   html.escape(raw, quote=True))
        except Exception as e:
            out += row("HTML Entities (quotes)",   f"[error: {e}]")
        try:
            out += row("HTML Decimal (&#XX;)",     "".join(f"&#{ord(c)};" for c in raw))
        except Exception as e:
            out += row("HTML Decimal (&#XX;)",     f"[error: {e}]")
        try:
            out += row("HTML Hex (&#xXX;)",        "".join(f"&#x{ord(c):x};" for c in raw))
        except Exception as e:
            out += row("HTML Hex (&#xXX;)",        f"[error: {e}]")

        # ── UNICODE / ESCAPE SEQUENCES ────────────────────────────────────────
        out += section("UNICODE & ESCAPE SEQUENCES", "  ")
        try:
            out += row("Unicode Escape (\\uXXXX)",  "".join(f"\\u{ord(c):04x}" for c in raw))
        except Exception as e:
            out += row("Unicode Escape (\\uXXXX)",  f"[error: {e}]")
        try:
            out += row("Unicode Escape (\\UXXXXXXXX)", "".join(f"\\U{ord(c):08x}" for c in raw))
        except Exception as e:
            out += row("Unicode Escape (\\UXXXXXXXX)", f"[error: {e}]")
        try:
            out += row("Unicode Named (\\N{name})",
                       raw.encode("unicode_escape").decode("utf-8"))
        except Exception as e:
            out += row("Unicode Named (\\N{name})",  f"[error: {e}]")
        try:
            out += row("Hex Bytes (\\xHH)",         "".join(f"\\x{b:02x}" for b in raw_bytes))
        except Exception as e:
            out += row("Hex Bytes (\\xHH)",         f"[error: {e}]")
        try:
            out += row("Octal Bytes (\\OOO)",       "".join(f"\\{b:03o}" for b in raw_bytes))
        except Exception as e:
            out += row("Octal Bytes (\\OOO)",       f"[error: {e}]")
        try:
            out += row("Python repr()",             repr(raw))
        except Exception as e:
            out += row("Python repr()",             f"[error: {e}]")

        # ── HEX / BINARY ──────────────────────────────────────────────────────
        out += section("HEX & BINARY", "  ")
        try:
            out += row("Hex (lowercase)",          raw_bytes.hex())
        except Exception as e:
            out += row("Hex (lowercase)",          f"[error: {e}]")
        try:
            out += row("Hex (uppercase)",          raw_bytes.hex().upper())
        except Exception as e:
            out += row("Hex (uppercase)",          f"[error: {e}]")
        try:
            out += row("Hex (0x prefix)",          " ".join(f"0x{b:02x}" for b in raw_bytes))
        except Exception as e:
            out += row("Hex (0x prefix)",          f"[error: {e}]")
        try:
            out += row("Hex (spaced)",             " ".join(f"{b:02x}" for b in raw_bytes))
        except Exception as e:
            out += row("Hex (spaced)",             f"[error: {e}]")
        try:
            out += row("Binary (8-bit bytes)",     " ".join(f"{b:08b}" for b in raw_bytes))
        except Exception as e:
            out += row("Binary (8-bit bytes)",     f"[error: {e}]")
        try:
            out += row("Octal",                    " ".join(f"{b:03o}" for b in raw_bytes))
        except Exception as e:
            out += row("Octal",                    f"[error: {e}]")
        try:
            out += row("Decimal (bytes)",          " ".join(str(b) for b in raw_bytes))
        except Exception as e:
            out += row("Decimal (bytes)",          f"[error: {e}]")

        # ── CHARACTER CASING ──────────────────────────────────────────────────
        out += section("CHARACTER CASING", "  ")
        out += row("Uppercase",                 raw.upper())
        out += row("Lowercase",                 raw.lower())
        out += row("Title Case",                raw.title())
        out += row("Swap Case",                 raw.swapcase())
        out += row("Capitalize",               raw.capitalize())
        try:
            out += row("Camel Case",
                       "".join(w.capitalize() for w in re.split(r"[\s_\-]+", raw)))
        except Exception as e:
            out += row("Camel Case",            f"[error: {e}]")
        try:
            out += row("Snake Case",
                       re.sub(r"[\s\-]+", "_", stripped).lower())
        except Exception as e:
            out += row("Snake Case",            f"[error: {e}]")
        try:
            out += row("Kebab Case",
                       re.sub(r"[\s_]+", "-", stripped).lower())
        except Exception as e:
            out += row("Kebab Case",            f"[error: {e}]")

        # ── CLASSIC CIPHERS ───────────────────────────────────────────────────
        out += section("CLASSIC CIPHERS", "  ")
        try:
            out += row("ROT13",                 codecs.encode(raw, "rot_13"))
        except Exception as e:
            out += row("ROT13",                 f"[error: {e}]")
        try:
            rot47 = "".join(
                chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
                for c in raw
            )
            out += row("ROT47",                 rot47)
        except Exception as e:
            out += row("ROT47",                 f"[error: {e}]")
        try:
            out += row("Reverse",               raw[::-1])
        except Exception as e:
            out += row("Reverse",               f"[error: {e}]")
        try:
            morse = {
                "A":".-","B":"-...","C":"-.-.","D":"-..","E":".",
                "F":"..-.","G":"--.","H":"....","I":"..","J":".---",
                "K":"-.-","L":".-..","M":"--","N":"-.","O":"---",
                "P":".--.","Q":"--.-","R":".-.","S":"...","T":"-",
                "U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--",
                "Z":"--..",
                "0":"-----","1":".----","2":"..---","3":"...--",
                "4":"....-","5":".....","6":"-....","7":"--...",
                "8":"---..","9":"----.",
                " ":"/"
            }
            morse_out = " ".join(morse.get(c.upper(), "?") for c in raw)
            out += row("Morse Code",            morse_out)
        except Exception as e:
            out += row("Morse Code",            f"[error: {e}]")

        # ── HASHES ────────────────────────────────────────────────────────────
        out += section("CRYPTOGRAPHIC HASHES", "  ")
        hash_algos = [
            ("MD5",        hashlib.md5),
            ("SHA-1",      hashlib.sha1),
            ("SHA-224",    hashlib.sha224),
            ("SHA-256",    hashlib.sha256),
            ("SHA-384",    hashlib.sha384),
            ("SHA-512",    hashlib.sha512),
        ]
        for name, fn in hash_algos:
            try:
                out += row(name, fn(raw_bytes).hexdigest())
            except Exception as e:
                out += row(name, f"[error: {e}]")
        try:
            out += row("SHA3-256",  hashlib.sha3_256(raw_bytes).hexdigest())
            out += row("SHA3-512",  hashlib.sha3_512(raw_bytes).hexdigest())
        except Exception as e:
            out += row("SHA3-256/512", f"[error: {e}]")
        try:
            out += row("BLAKE2b",   hashlib.blake2b(raw_bytes).hexdigest())
            out += row("BLAKE2s",   hashlib.blake2s(raw_bytes).hexdigest())
        except Exception as e:
            out += row("BLAKE2b/s", f"[error: {e}]")
        try:
            ntlm = hashlib.new("md4", raw.encode("utf-16-le")).hexdigest()
            out += row("NTLM (MD4/UTF-16LE)", ntlm)
        except Exception:
            try:
                import struct
                # Pure-Python MD4 approximation for NTLM
                out += row("NTLM", "[MD4 not available on this platform]")
            except Exception as e:
                out += row("NTLM", f"[error: {e}]")

        # ── COMPRESSION ───────────────────────────────────────────────────────
        out += section("COMPRESSION (base64-wrapped)", "  ")
        try:
            gz = gzip.compress(raw_bytes, compresslevel=9)
            out += row("Gzip", base64.b64encode(gz).decode())
            out += row("Gzip size", f"{len(gz)} bytes ({100*len(gz)//max(1,len(raw_bytes))}% of original)")
        except Exception as e:
            out += row("Gzip", f"[error: {e}]")
        try:
            import zlib
            zl = zlib.compress(raw_bytes, level=9)
            out += row("Zlib", base64.b64encode(zl).decode())
        except Exception as e:
            out += row("Zlib", f"[error: {e}]")

        # ── NUMBER BASES ──────────────────────────────────────────────────────
        out += section("NUMBER BASE CONVERSIONS  (first code-point)", "  ")
        try:
            cp = ord(stripped[0]) if stripped else 0
            out += row("Code-point", str(cp))
            out += row("Decimal",    str(cp))
            out += row("Binary",     bin(cp))
            out += row("Octal",      oct(cp))
            out += row("Hex",        hex(cp))
        except Exception as e:
            out += row("Code-point", f"[error: {e}]")

        # ── MISC ──────────────────────────────────────────────────────────────
        out += section("MISCELLANEOUS", "  ")
        try:
            out += row("Length (chars)",         str(len(raw)))
            out += row("Length (bytes UTF-8)",   str(len(raw_bytes)))
            out += row("Lines",                  str(len(raw.splitlines())))
            out += row("Words",                  str(len(raw.split())))
        except Exception as e:
            out += row("Stats", f"[error: {e}]")
        try:
            import math as _math
            counter = Counter(raw)
            entropy = -sum(
                (c / len(raw)) * _math.log2(c / len(raw))
                for c in counter.values()
            )
            out += row("Shannon Entropy (bits)", f"{entropy:.4f}")
        except Exception as e:
            out += row("Shannon Entropy",        f"[error: {e}]")
        try:
            ascii_art_note = "(non-ASCII chars present)" if any(ord(c) > 127 for c in raw) else "(all ASCII)"
            out += row("ASCII check", ascii_art_note)
        except Exception as e:
            out += row("ASCII check", f"[error: {e}]")

        out += "\n" + SEP2 + "\n"
        out += f"  ✓ All formats generated for {len(raw)}-char input\n"
        out += SEP2 + "\n"

        self.set_decoder_output(out, "⚡ All formats encoded")

    def analyze_input(self):
        """Deep analysis of input"""
        text = self.get_decoder_input()
        if not text:
            return

        import math
        from collections import Counter

        result = "=== DEEP ANALYSIS ===\n\n"

        # Basic stats
        result += "🗠 BASIC STATISTICS\n"
        result += f"Length: {len(text)} characters\n"
        result += f"Bytes: {len(text.encode('utf-8'))} bytes\n"
        result += f"Lines: {len(text.splitlines())}\n"
        result += f"Words: {len(text.split())}\n\n"

        # Character analysis
        counter = Counter(text)
        result += " CHARACTER ANALYSIS\n"
        result += f"Unique characters: {len(counter)}\n"
        result += f"Alphabetic: {sum(1 for c in text if c.isalpha())}\n"
        result += f"Numeric: {sum(1 for c in text if c.isdigit())}\n"
        result += f"Whitespace: {sum(1 for c in text if c.isspace())}\n"
        result += f"Special: {sum(1 for c in text if not c.isalnum() and not c.isspace())}\n\n"

        # Entropy
        length = len(text)
        entropy = -sum(
            (count / length) * math.log2(count / length) for count in counter.values()
        )
        result += " ENTROPY ANALYSIS\n"
        result += f"Shannon Entropy: {entropy:.4f} bits/char\n"
        if entropy < 3.5:
            result += "Assessment: Low entropy (plain text likely)\n"
        elif entropy < 5.0:
            result += "Assessment: Medium entropy (encoded/compressed)\n"
        else:
            result += "Assessment: High entropy (encrypted/random)\n"
        result += "\n"

        # Encoding detection
        result += "🔍 ENCODING DETECTION\n"

        # Check Base64
        try:
            base64.b64decode(text)
            result += "✓ Valid Base64\n"
        except:
            result += "✗ Not Base64\n"

        # Check Hex
        try:
            bytes.fromhex(text.replace(" ", ""))
            result += "✓ Valid Hexadecimal\n"
        except:
            result += "✗ Not Hexadecimal\n"

        # Check JSON
        try:
            json.loads(text)
            result += "✓ Valid JSON\n"
        except:
            result += "✗ Not JSON\n"

        # Check XML
        if text.strip().startswith("<"):
            result += "✓ Possibly XML/HTML\n"
        else:
            result += "✗ Not XML/HTML\n"

        result += "\n"

        # Pattern detection
        import re

        result += " PATTERN DETECTION\n"

        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        result += f"URLs found: {len(urls)}\n"

        ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", text)
        result += f"IP addresses found: {len(ips)}\n"

        emails = re.findall(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text
        )
        result += f"Email addresses found: {len(emails)}\n"

        hashes_md5 = re.findall(r"\b[a-fA-F0-9]{32}\b", text)
        result += f"MD5 hashes found: {len(hashes_md5)}\n"

        hashes_sha256 = re.findall(r"\b[a-fA-F0-9]{64}\b", text)
        result += f"SHA256 hashes found: {len(hashes_sha256)}\n"

        self.set_decoder_output(result, "✓ Analysis complete")

    # Tab Management
    def load_file_to_decoder(self, tab_widget):
        """Load file into decoder input"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load File", "", "All Files (*)"
        )
        if filename:
            try:
                with open(filename, "rb") as f:
                    data = f.read()

                # Try to decode as text
                try:
                    text = data.decode("utf-8")
                except:
                    # If binary, show as base64
                    text = base64.b64encode(data).decode("utf-8")

                input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
                if input_widget:
                    input_widget.setPlainText(text)

                self.status_label.setText(f"✓ Loaded {len(data)} bytes from file")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to load file: {e}")

    def paste_to_decoder(self, tab_widget):
        """Paste from clipboard to input"""
        clipboard = QApplication.clipboard()
        text = clipboard.text()

        input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
        if input_widget:
            input_widget.setPlainText(text)

        self.status_label.setText("✓ Pasted from clipboard")

    def clear_decoder_input(self, tab_widget):
        """Clear decoder input"""
        input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
        if input_widget:
            input_widget.clear()

    def copy_decoder_output(self, tab_widget):
        """Copy decoder output to clipboard"""
        output_widget = tab_widget.findChild(QTextEdit, "decoder_output")
        if output_widget:
            text = output_widget.toPlainText()
            if text:
                clipboard = QApplication.clipboard()
                clipboard.setText(text)
                self.status_label.setText("🗈 Output copied to clipboard!")
                QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def save_decoder_output(self, tab_widget):
        """Save decoder output to file"""
        output_widget = tab_widget.findChild(QTextEdit, "decoder_output")
        if output_widget:
            text = output_widget.toPlainText()
            if text:
                filename, _ = QFileDialog.getSaveFileName(
                    self, "Save Output", "", "Text Files (*.txt);;All Files (*)"
                )
                if filename:
                    try:
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(text)
                        self.status_label.setText(f"✓ Saved to {filename}")
                        QTimer.singleShot(
                            2000, lambda: self.status_label.setText("Ready")
                        )
                    except Exception as e:
                        QMessageBox.warning(self, "Error", f"Failed to save: {e}")

    def output_to_input(self, tab_widget):
        """Send output back to input for chaining operations"""
        input_widget = tab_widget.findChild(QTextEdit, "decoder_input")
        output_widget = tab_widget.findChild(QTextEdit, "decoder_output")

        if input_widget and output_widget:
            output_text = output_widget.toPlainText()
            input_widget.setPlainText(output_text)
            self.status_label.setText("⮌ Output sent to input")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def clear_decoder_output(self, tab_widget):
        """Clear decoder output"""
        output_widget = tab_widget.findChild(QTextEdit, "decoder_output")
        if output_widget:
            output_widget.clear()

    def clear_decoder(self):
        """Clear current decoder tab"""
        tab_widget = self.get_current_decoder_tab()
        if tab_widget:
            self.clear_decoder_input(tab_widget)
            self.clear_decoder_output(tab_widget)
