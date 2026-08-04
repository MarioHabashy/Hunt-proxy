"""
chatbox.py — AI Security Chat Panel widget.

This module is intentionally kept separate from analysis_tab.py so that
the large analysis engine code is not mixed with the chat UI widget.

Imports:
    • ai_client  — AIChatWorker, system prompt templates
    • constants  — COLORS palette
    • PyQt5      — widget building blocks
"""
import re
import html as _html

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit,
)
from PyQt5.QtCore import Qt, pyqtSignal, QEvent

try:
    from modules.ai_client import AIChatWorker as _AIChatWorker
    from modules.ai_client import _AI_CHAT_SYSTEM_TMPL as _AI_CHAT_SYSTEM_TMPL
    from modules.ai_client import _GENERAL_CHAT_SYSTEM as _GENERAL_CHAT_SYSTEM
except ImportError:
    _AIChatWorker = None
    _AI_CHAT_SYSTEM_TMPL = ""
    _GENERAL_CHAT_SYSTEM = (
        "Your name is Hunt Assistant — an elite AI security co-pilot. "
        "The user is a web app pentester and bug bounty hunter. "
        "Help them detect and exploit vulnerabilities. Be concise and technical."
    )

try:
    from modules.constants import COLORS
except ImportError:
    COLORS = {
        'bg_darker': '#1E1E1E',
    }

def _inline_md(text: str) -> str:
    """Apply inline Markdown to an already HTML-escaped string (bold, italic, code)."""
    text = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)', r'<i>\1</i>', text)
    text = re.sub(
        r'`(.+?)`',
        r"<code style='background:#1e1e2e;color:#c8a0ff;padding:1px 5px;"
        r"border-radius:3px;font-family:monospace;font-size:11px;'>\1</code>",
        text,
    )
    return text


def _md_to_html(text: str) -> str:
    """
    Convert an AI Markdown response to safe HTML for the chat panel.
    Escapes all user data before applying Markdown substitutions.
    """
    lines = text.split('\n')
    parts = []
    in_code = False
    code_buf: list = []
    code_lang = ""

    for line in lines:
        if line.startswith('```'):
            if in_code:
                code_content = _html.escape('\n'.join(code_buf))
                lang_label = (
                    f"<div style='color:#555;font-size:10px;padding:2px 8px 0;"
                    f"font-family:monospace;'>{_html.escape(code_lang)}</div>"
                    if code_lang else ""
                )
                parts.append(
                    f"<div style='background:#0d1117;border-radius:6px;margin:6px 0;'>"
                    f"{lang_label}"
                    f"<pre style='color:#79c0ff;padding:8px 12px;margin:0;font-size:11px;"
                    f"white-space:pre-wrap;word-wrap:break-word;font-family:monospace;'>"
                    f"{code_content}</pre></div>"
                )
                code_buf = []
                code_lang = ""
                in_code = False
            else:
                in_code = True
                code_lang = line[3:].strip()
            continue

        if in_code:
            code_buf.append(line)
            continue

        e = _html.escape(line)

        if e.startswith('### '):
            parts.append(f"<div style='color:#c8a0ff;font-weight:bold;font-size:12px;"
                         f"margin:10px 0 3px;'>{_inline_md(e[4:])}</div>")
        elif e.startswith('## '):
            parts.append(f"<div style='color:#d0a0ff;font-weight:bold;font-size:13px;"
                         f"margin:12px 0 4px;border-bottom:1px solid #2a1a4a;"
                         f"padding-bottom:3px;'>{_inline_md(e[3:])}</div>")
        elif e.startswith('# '):
            parts.append(f"<div style='color:#e8b0ff;font-weight:bold;font-size:14px;"
                         f"margin:14px 0 5px;'>{_inline_md(e[2:])}</div>")
        elif re.match(r'^\d+\. ', e):
            num, rest = e.split('. ', 1)
            parts.append(f"<div style='margin:2px 0 2px 16px;'>"
                         f"<span style='color:#888;font-weight:bold;'>{num}.</span>"
                         f" {_inline_md(rest)}</div>")
        elif re.match(r'^[-*] ', e):
            parts.append(f"<div style='margin:2px 0 2px 16px;'>"
                         f"\u2022 {_inline_md(e[2:])}</div>")
        elif re.match(r'^  [-*] ', e):
            parts.append(f"<div style='margin:2px 0 2px 32px;'>"
                         f"\u25e6 {_inline_md(e[4:])}</div>")
        elif re.match(r'^[-*_]{3,}$', e.strip()):
            parts.append("<hr style='border:none;border-top:1px solid #2a2a3a;margin:8px 0;'>")
        elif e.strip() == '':
            parts.append("<div style='height:5px;'></div>")
        else:
            parts.append(f"<div style='line-height:1.6;color:#ccc;'>{_inline_md(e)}</div>")

    if in_code and code_buf:
        code_content = _html.escape('\n'.join(code_buf))
        parts.append(
            f"<pre style='background:#0d1117;color:#79c0ff;padding:8px 12px;"
            f"border-radius:6px;font-size:11px;margin:4px 0;"
            f"white-space:pre-wrap;'>{code_content}</pre>"
        )

    return ''.join(parts)


# ── AI Security Chat Panel ────────────────────────────────────────────────────

class AIChatPanel(QWidget):
    """
    Persistent right-side AI Security Chat Panel.
    • Starts a full analysis when start_analysis() is called.
    • Maintains conversation history for follow-up questions.
    • Emits close_requested when the × button is clicked.
    """

    close_requested = pyqtSignal()

    _BG_PANEL = "#16102a"
    _BG_INPUT = "#0f0f1e"
    _BG_MSGA  = "#1c1c2c"
    _BG_MSGU  = "#2a1a4a"
    _COL_ACC  = "#c8a0ff"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._messages     : list = []
        self._display_msgs : list = []
        self._worker       = None
        self._last_settings: dict = {}
        self._last_request : str  = ""
        self._last_response: str  = ""
        self._last_url     : str  = ""
        self._setup_ui()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        self.setMinimumWidth(300)
        bg = COLORS.get("bg_darker", "#1E1E1E")
        self.setStyleSheet(f"QWidget {{ background: {bg}; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        hdr = QWidget()
        hdr.setFixedHeight(38)
        hdr.setStyleSheet(
            f"background:{self._BG_PANEL};"
            f"border-bottom:1px solid #2a1a4a;"
        )
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(12, 0, 8, 0)
        hl.setSpacing(6)

        ttl = QLabel("  AI Security Chat")
        ttl.setStyleSheet(
            f"color:{self._COL_ACC};font-size:12px;"
            f"font-weight:bold;background:transparent;"
        )
        hl.addWidget(ttl)
        hl.addStretch()

        self._new_btn = QPushButton("\u21ba  Re-analyze")
        self._new_btn.setFixedHeight(22)
        self._new_btn.setToolTip("Re-run analysis on the current traffic")
        self._new_btn.setEnabled(False)
        self._new_btn.setStyleSheet(
            f"QPushButton{{background:transparent;color:#555;"
            f"border:1px solid #2a1a4a;"
            f"border-radius:4px;font-size:10px;padding:0 10px;}}"
            f"QPushButton:hover{{color:{self._COL_ACC};border-color:#5a3ea8;"
            f"background:#1a1530;}}"
            f"QPushButton:disabled{{color:#383060;border-color:#1e1530;}}"
        )
        self._new_btn.clicked.connect(self._on_reanalyze)
        hl.addWidget(self._new_btn)

        close_btn = QPushButton("\u00d7")
        close_btn.setFixedSize(24, 24)
        close_btn.setToolTip("Close panel  (Ctrl+Shift+C)")
        close_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#444;border:none;"
            "font-size:15px;font-weight:bold;border-radius:4px;}"
            "QPushButton:hover{color:#ff7070;background:#2a1020;}"
        )
        close_btn.clicked.connect(self.close_requested.emit)
        hl.addWidget(close_btn)
        layout.addWidget(hdr)

        # Chat output
        self._chat_output = QTextEdit()
        self._chat_output.setReadOnly(True)
        self._chat_output.setStyleSheet(
            f"QTextEdit{{background:{bg};color:#ccc;border:none;font-size:12px;padding:6px;}}"
        )
        self._reset_placeholder()
        layout.addWidget(self._chat_output, 1)

        # Input area
        input_wrap = QWidget()
        input_wrap.setStyleSheet(
            f"background:{self._BG_PANEL};"
            f"border-top:1px solid #2a1a4a;"
        )
        il = QVBoxLayout(input_wrap)
        il.setContentsMargins(10, 8, 10, 10)
        il.setSpacing(6)

        self._input = QTextEdit()
        self._input.setFixedHeight(80)
        self._input.setPlaceholderText("Ask anything security-related\u2026")
        self._input.setStyleSheet(
            f"QTextEdit{{background:{self._BG_INPUT};color:#ddd;"
            f"border:1px solid #3a2060;border-radius:6px;font-size:12px;padding:6px;}}"
            f"QTextEdit:focus{{border:1px solid #7a50d8;background:#12102a;}}"
        )
        self._input.installEventFilter(self)
        il.addWidget(self._input)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(6)

        self._clear_btn = QPushButton("\u239a  Clear")
        self._clear_btn.setFixedHeight(26)
        self._clear_btn.setToolTip("Clear the chat display\nAI still remembers this conversation")
        self._clear_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#555;border:1px solid #2a2040;"
            "border-radius:5px;font-size:11px;padding:0 10px;}"
            "QPushButton:hover{color:#aaa;border-color:#555;background:#1a1530;}"
        )
        self._clear_btn.clicked.connect(self._on_clear)
        btn_row.addWidget(self._clear_btn)

        self._new_chat_btn = QPushButton("\u2795  New Chat")
        self._new_chat_btn.setFixedHeight(26)
        self._new_chat_btn.setToolTip("Start a completely new conversation\nClears display AND resets AI memory")
        self._new_chat_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#555;border:1px solid #2a2040;"
            "border-radius:5px;font-size:11px;padding:0 10px;}"
            "QPushButton:hover{color:#c8a0ff;border-color:#5a3ea8;background:#1a1530;}"
        )
        self._new_chat_btn.clicked.connect(self._on_new_chat)
        btn_row.addWidget(self._new_chat_btn)
        btn_row.addStretch()

        self._model_lbl = QLabel()
        self._model_lbl.setStyleSheet(
            "color:#4a3870;font-size:10px;background:transparent;"
        )
        self._model_lbl.setToolTip("Current AI provider and model")
        btn_row.addWidget(self._model_lbl)
        btn_row.addSpacing(6)

        self._stop_btn = QPushButton("\u23f9  Stop")
        self._stop_btn.setFixedHeight(26)
        self._stop_btn.setToolTip("Stop the current AI response")
        self._stop_btn.setVisible(False)
        self._stop_btn.setStyleSheet(
            "QPushButton{background:#3a1010;color:#ff7070;"
            "border:1px solid #7a2020;border-radius:5px;font-size:11px;"
            "font-weight:bold;padding:0 18px;}"
            "QPushButton:hover{background:#5a1515;border-color:#aa3030;}"
        )
        self._stop_btn.clicked.connect(self._on_stop)
        btn_row.addWidget(self._stop_btn)

        self._send_btn = QPushButton("\u23ce  Send")
        self._send_btn.setFixedHeight(26)
        self._send_btn.setToolTip("Send message")
        self._send_btn.setStyleSheet(
            f"QPushButton{{background:#3a1a7a;color:{self._COL_ACC};"
            f"border:1px solid #5a3ea8;border-radius:5px;font-size:11px;"
            f"font-weight:bold;padding:0 18px;}}"
            f"QPushButton:hover{{background:#4a2a9a;border-color:#8060cc;}}"
            f"QPushButton:disabled{{color:#444;border-color:#2a1a4a;background:#14102a;}}"
        )
        self._send_btn.clicked.connect(self.send_message)
        btn_row.addWidget(self._send_btn)
        il.addLayout(btn_row)
        layout.addWidget(input_wrap)

    def _reset_placeholder(self):
        self._chat_output.setHtml(
            "<div style='font-family:sans-serif;padding:28px 20px 20px;'>"
            "<div style='text-align:center;margin-bottom:22px;'>"
            "<span style='font-size:26px;'></span><br>"
            "<span style='color:#c8a0ff;font-size:15px;font-weight:bold;"
            "letter-spacing:0.5px;'>AI Security Chat</span><br>"
            "<span style='color:#504870;font-size:11px;'>Powered by your configured AI provider</span>"
            "</div>"
            "<div style='background:#13102a;border-radius:8px;padding:14px 16px;"
            "border:1px solid #2a1a4a;margin-bottom:14px;'>"
            "<div style='color:#7a60aa;font-size:10px;font-weight:bold;"
            "letter-spacing:1px;margin-bottom:10px;'>QUICK START</div>"
            "<div style='color:#888;font-size:11px;line-height:2;'>"
            "&#x2022; Type any security question and press Enter to send<br>"
            "&#x2022; Right-click a URL \u2192 "
            "<span style='color:#c8a0ff;'> AI Analyze</span>"
            " for full traffic analysis<br>"
            "&#x2022; Right-click request/response \u2192 analyze specific content"
            "</div></div>"
            "<div style='background:#13102a;border-radius:8px;padding:14px 16px;"
            "border:1px solid #2a1a4a;'>"
            "<div style='color:#7a60aa;font-size:10px;font-weight:bold;"
            "letter-spacing:1px;margin-bottom:10px;'>EXAMPLE QUESTIONS</div>"
            "<div style='color:#666;font-size:11px;line-height:2;'>"
            "\u2022 What payloads should I try for this endpoint?<br>"
            "\u2022 How do I test for SSRF in this parameter?<br>"
            "\u2022 Can you write a PoC for this XSS?<br>"
            "\u2022 What does this JWT token contain?<br>"
            "\u2022 Explain this error message and how to exploit it"
            "</div></div>"
            "</div>"
        )

    # ── Event filter: Enter sends / Shift+Enter new line ──────────────────────

    def eventFilter(self, obj, event):
        if (obj is self._input and
                event.type() == QEvent.KeyPress and
                event.key() in (Qt.Key_Return, Qt.Key_Enter)):
            if event.modifiers() & Qt.ShiftModifier:
                # Shift+Enter → insert a real newline
                self._input.insertPlainText("\n")
                return True
            elif not (event.modifiers() & Qt.ControlModifier):
                # Plain Enter (no modifier) → send
                self.send_message()
                return True
        return super().eventFilter(obj, event)

    # ── Public API ────────────────────────────────────────────────────────────

    def start_analysis(self, settings: dict, request_text: str,
                       response_text: str, url: str):
        """Store context and begin a fresh analysis conversation."""
        self._last_settings = settings
        self._update_model_label(settings)
        self._last_request  = request_text
        self._last_response = response_text
        self._last_url      = url
        self._begin_session()

    def set_context(self, settings: dict, request_text: str,
                    response_text: str, url: str):
        """Pin traffic context for free-form Q&A — no auto-analysis is triggered."""
        self._dismiss_worker()
        self._last_settings = settings
        self._update_model_label(settings)
        self._last_request  = request_text
        self._last_response = response_text
        self._last_url      = url

        if self._messages:
            # Conversation already running — update system prompt in-place, keep history
            self._update_system_message()
            self._append_context_switch_card(url, request_text, response_text)
        else:
            self._messages     = []
            self._display_msgs = []
            self._show_context_pinned(url, request_text, response_text)

        self._new_btn.setEnabled(True)
        self._stop_btn.setVisible(False)
        self._send_btn.setVisible(True)
        self._send_btn.setEnabled(True)
        self._input.setEnabled(True)
        self._input.setFocus()

    def _show_context_pinned(self, url: str, request_text: str, response_text: str):
        """Render a context-pinned card — awaiting user question, no analysis running."""
        display_url = _html.escape(
            (url[:70] + '\u2026') if len(url) > 70 else (url or '(unknown URL)')
        )
        # Extract HTTP method from first request line
        method = ""
        first_line = request_text.strip().split('\n')[0] if request_text else ""
        if first_line:
            parts = first_line.split(' ')
            method = _html.escape(parts[0]) if parts else ""

        has_req  = bool(request_text.strip())
        has_resp = bool(response_text.strip())
        req_size  = f"{len(request_text):,} bytes"  if has_req  else None
        resp_size = f"{len(response_text):,} bytes" if has_resp else None

        avail_parts = []
        if has_req:  avail_parts.append(f"<b style='color:#a080d0;'>Request</b> {req_size}")
        if has_resp: avail_parts.append(f"<b style='color:#a080d0;'>Response</b> {resp_size}")
        avail_html = " &nbsp;\u00b7&nbsp; ".join(avail_parts) if avail_parts else "No content"

        method_badge = (
            f"<span style='background:#2a1a5a;color:#c8a0ff;padding:1px 7px;"
            f"border-radius:3px;font-size:10px;font-weight:bold;'>{method}</span>&nbsp;"
        ) if method else ""

        self._chat_output.setHtml(
            "<div style='font-family:sans-serif;padding:16px 14px;'>"
            # Context badge
            "<div style='background:#1c1430;border:1px solid #4a2a8a;"
            "border-radius:10px;padding:14px 16px;margin-bottom:14px;'>"
            "<div style='margin-bottom:10px;'>"
            "<span style='font-size:15px;margin-right:7px;'>&#128206;</span>"
            "<span style='color:#c8a0ff;font-size:12px;font-weight:bold;"
            "letter-spacing:0.3px;'>Context Loaded</span>"
            "</div>"
            f"<div style='color:#999;font-size:11px;margin-bottom:6px;'>"
            f"{method_badge}"
            f"<span style='color:#bbb;'>{display_url}</span></div>"
            f"<div style='color:#555;font-size:10px;'>{avail_html}</div>"
            "</div>"
            # Suggestions card
            "<div style='background:#13102a;border-radius:8px;padding:14px 16px;"
            "border:1px solid #2a1a4a;'>"
            "<div style='color:#7a60aa;font-size:10px;font-weight:bold;"
            "letter-spacing:1px;margin-bottom:10px;'>ASK ANYTHING ABOUT THIS TRAFFIC</div>"
            "<div style='color:#666;font-size:11px;line-height:1.9;'>"
            "&#x2022; What vulnerabilities could this endpoint have?<br>"
            "&#x2022; Is there anything unusual in the response headers?<br>"
            "&#x2022; Write a PoC for the most likely issue<br>"
            "&#x2022; Explain this response and suggest test cases<br>"
            "&#x2022; Check the authentication / session handling"
            "</div></div>"
            "</div>"
        )

    # ── Session management ────────────────────────────────────────────────────

    def _build_system_content(self) -> str:
        """Build the system prompt string from current stored context."""
        req = (self._last_request  or "(empty)").strip()[:3000]
        resp = (self._last_response or "(empty)").strip()[:3000]
        src  = (self._last_response or "(empty)").strip()[:5000]
        return _AI_CHAT_SYSTEM_TMPL.format(
            url=self._last_url or "(unknown)",
            request=req, response=resp, source=src,
        )

    def _update_system_message(self):
        """Replace the system message in the existing messages list with updated traffic context."""
        new_sys = self._build_system_content()
        if self._messages and self._messages[0]["role"] == "system":
            self._messages[0]["content"] = new_sys
        else:
            self._messages.insert(0, {"role": "system", "content": new_sys})

    def _append_context_switch_card(self, url: str, request_text: str, response_text: str):
        """Add a visual separator card to the display when traffic context is switched."""
        display_url = _html.escape(
            (url[:70] + '\u2026') if len(url) > 70 else (url or '(unknown URL)')
        )
        method = ""
        first_line = request_text.strip().split('\n')[0] if request_text else ""
        if first_line:
            parts = first_line.split(' ')
            method = _html.escape(parts[0]) if parts else ""
        method_badge = (
            f"<span style='background:#1a3a1a;color:#80d080;padding:1px 7px;"
            f"border-radius:3px;font-size:10px;font-weight:bold;'>{method}</span>&nbsp;"
        ) if method else ""
        self._display_msgs.append({"role": "context_switch", "content":
            f"<div style='margin:10px 0;padding:10px 14px;background:#131a13;"
            f"border:1px solid #1e3a1e;border-radius:8px;'>"
            f"<span style='color:#508850;font-size:10px;font-weight:bold;"
            f"letter-spacing:0.5px;'>&#128204; NEW CONTEXT LOADED</span>"
            f"<div style='color:#666;font-size:11px;margin-top:5px;'>"
            f"{method_badge}<span style='color:#888;'>{display_url}</span></div></div>"
        })
        self._render_chat()

    def _begin_session(self):
        """Start or continue an analysis — preserves history if a conversation is already active."""
        self._dismiss_worker()

        self._input.setEnabled(False)
        self._send_btn.setEnabled(False)
        self._send_btn.setVisible(False)
        self._stop_btn.setVisible(True)
        self._new_btn.setEnabled(False)

        req  = (self._last_request  or "(empty)").strip()[:3000]
        resp = (self._last_response or "(empty)").strip()[:3000]
        src  = (self._last_response or "(empty)").strip()[:5000]

        sys_content = _AI_CHAT_SYSTEM_TMPL.format(
            url=self._last_url or "(unknown)",
            request=req, response=resp, source=src,
        )

        first_user = (
            "Perform a comprehensive security analysis of this HTTP traffic and page source code. "
            "Cover all applicable bug bounty and pentest categories: broken access control, IDOR, "
            "injection (SQL, NoSQL, XSS, SSTI, SSRF, XXE, command injection), "
            "authentication & session flaws, JWT attacks, CORS misconfiguration, "
            "Host Header injection, GraphQL issues, file upload bypass, "
            "information disclosure, security headers, OAuth/SSO flaws, "
            "cache poisoning, DOM XSS, hardcoded secrets, prototype pollution, "
            "CSP weaknesses, SRI, CSRF, clickjacking, and vulnerable libraries. "
            "Be thorough, cite specific evidence, and suggest concrete PoC payloads."
        )

        if self._messages:
            # Existing conversation — update system prompt in-place and append new analysis
            self._update_system_message()
            self._append_context_switch_card(
                self._last_url or "", self._last_request or "", self._last_response or ""
            )
            self._messages.append({"role": "user", "content": first_user})
            self._display_msgs.append({"role": "user",    "content": first_user})
            self._display_msgs.append({"role": "loading"})
        else:
            self._messages = [
                {"role": "system", "content": sys_content},
                {"role": "user",   "content": first_user},
            ]
            self._display_msgs = [
                {"role": "user",    "content": first_user},
                {"role": "loading"},
            ]

        self._render_chat()
        self._run_worker()

    def _on_reanalyze(self):
        if self._last_request or self._last_response:
            self._begin_session()

    def _on_clear(self):
        """Clear the visual display only — AI message history is preserved."""
        self._display_msgs = []
        self._chat_output.setHtml(
            "<div style='font-family:sans-serif;padding:16px 14px;'>"
            "<div style='text-align:center;padding:20px 0;'>"
            "<span style='color:#383060;font-size:11px;font-style:italic;'>"
            "\u239a Chat display cleared \u2014 AI still remembers this conversation."
            "</span></div></div>"
        )

    def _on_new_chat(self):
        """Full reset — clears display AND resets AI memory for a completely fresh start."""
        self._dismiss_worker()
        self._messages       = []
        self._display_msgs   = []
        self._last_request   = ""
        self._last_response  = ""
        self._last_url       = ""
        self._reset_placeholder()
        self._new_btn.setEnabled(False)
        self._stop_btn.setVisible(False)
        self._send_btn.setVisible(True)
        self._send_btn.setEnabled(True)
        self._input.setEnabled(True)
        self._input.setFocus()

    def _on_stop(self):
        """Stop the currently running AI response."""
        self._dismiss_worker()
        # Drop the last user message from history so the user can resend
        if self._messages and self._messages[-1]["role"] == "user":
            self._messages.pop()
        # Remove loading bubble
        self._display_msgs = [m for m in self._display_msgs if m.get("role") != "loading"]
        self._display_msgs.append({"role": "stopped"})
        self._render_chat()
        self._stop_btn.setVisible(False)
        self._send_btn.setVisible(True)
        self._send_btn.setEnabled(True)
        self._input.setEnabled(True)
        self._input.setFocus()

    # ── Sending messages ──────────────────────────────────────────────────────

    def send_message(self):
        text = self._input.toPlainText().strip()
        if not text:
            return
        self._input.clear()
        self._input.setEnabled(False)
        self._send_btn.setVisible(False)
        self._stop_btn.setVisible(True)
        # If no session started yet, bootstrap with the appropriate system prompt
        if not self._messages:
            if self._last_request or self._last_response:
                # Has traffic context — build full security analysis system prompt
                req  = (self._last_request  or "(empty)").strip()[:3000]
                resp = (self._last_response or "(empty)").strip()[:3000]
                src  = (self._last_response or "(empty)").strip()[:5000]
                sys_content = _AI_CHAT_SYSTEM_TMPL.format(
                    url=self._last_url or "(unknown)",
                    request=req, response=resp, source=src,
                )
            else:
                # No traffic — use general security assistant persona
                sys_content = _GENERAL_CHAT_SYSTEM
            self._messages = [{"role": "system", "content": sys_content}]
        self._messages.append({"role": "user", "content": text})
        self._display_msgs.append({"role": "user", "content": text})
        self._display_msgs.append({"role": "loading"})
        self._render_chat()
        self._run_worker()

    def _update_model_label(self, settings: dict):
        """Refresh the provider/model badge from the given settings dict."""
        provider = settings.get("ai_provider", "").strip()
        model    = settings.get("ai_model", "").strip()
        if not provider and not model:
            self._model_lbl.setText("")
            return
        # Shorten long model names (e.g. openrouter paths)
        short = model.split("/")[-1] if "/" in model else model
        if len(short) > 22:
            short = short[:20] + "\u2026"
        self._model_lbl.setText(f"{provider}  ·  {short}")
        self._model_lbl.setToolTip(f"Provider: {provider}\nModel: {model}")

    def _get_live_settings(self) -> dict:
        """Return the freshest available settings (picks up provider/model changes instantly)."""
        parent_tab = getattr(self, '_parent_tab', None)
        if parent_tab and hasattr(parent_tab, '_ai_traffic_settings'):
            try:
                fresh = parent_tab._ai_traffic_settings()
                if fresh:
                    self._last_settings = fresh   # keep in sync for start_analysis path
                    self._update_model_label(fresh)
                    return fresh
            except Exception:
                pass
        self._update_model_label(self._last_settings)
        return self._last_settings

    def _run_worker(self):
        if not _AIChatWorker:
            self._on_error("AIChatWorker unavailable (ai_client import failed).")
            return
        self._dismiss_worker()   # always cleanly discard any prior instance
        self._worker = _AIChatWorker(self._get_live_settings(), list(self._messages), self)
        self._worker.finished.connect(self._on_reply)
        self._worker.error.connect(self._on_error)
        self._worker.start()
        self._stop_btn.setVisible(True)
        self._send_btn.setVisible(False)

    def _dismiss_worker(self):
        """Disconnect signals and terminate any in-flight worker.
        Prevents a stale response from a previous session from appearing
        in the current chat.
        """
        if self._worker:
            try:
                self._worker.finished.disconnect(self._on_reply)
            except Exception:
                pass
            try:
                self._worker.error.disconnect(self._on_error)
            except Exception:
                pass
            if self._worker.isRunning():
                self._worker.terminate()
                self._worker.wait(400)
            self._worker = None

    # ── Response handlers ─────────────────────────────────────────────────────

    def _on_reply(self, text: str):
        self._display_msgs = [m for m in self._display_msgs if m.get("role") != "loading"]
        self._messages.append({"role": "assistant", "content": text})
        self._display_msgs.append({"role": "assistant", "content": text})
        self._render_chat()
        self._stop_btn.setVisible(False)
        self._send_btn.setVisible(True)
        self._send_btn.setEnabled(True)
        self._new_btn.setEnabled(True)
        self._input.setEnabled(True)
        self._input.setFocus()

    def _on_error(self, msg: str):
        self._display_msgs = [m for m in self._display_msgs if m.get("role") != "loading"]
        self._display_msgs.append({"role": "error", "content": msg})
        self._render_chat()
        self._stop_btn.setVisible(False)
        self._send_btn.setVisible(True)
        self._send_btn.setEnabled(True)
        self._new_btn.setEnabled(True)
        self._input.setEnabled(True)

    # ── Chat renderer ─────────────────────────────────────────────────────────

    def _render_chat(self):
        """Rebuild full chat HTML from _display_msgs and scroll to bottom."""
        bg = COLORS.get("bg_darker", "#1E1E1E")
        parts = [
            f"<div style='font-family:sans-serif;font-size:12px;"
            f"background:{bg};padding:8px 6px;'>"
        ]

        for i, msg in enumerate(self._display_msgs):
            role = msg.get("role", "")

            if role == "loading":
                parts.append(
                    "<div style='display:flex;align-items:center;padding:10px 12px;"
                    "margin:4px 0;'>"
                    "<span style='background:#2a1a5a;border-radius:50%;width:24px;"
                    "height:24px;display:inline-flex;align-items:center;"
                    "justify-content:center;font-size:11px;margin-right:8px;'></span>"
                    "<span style='color:#6a5090;font-size:12px;font-style:italic;'>"
                    "AI is thinking\u2026</span></div>"
                )

            elif role == "user":
                escaped = _html.escape(msg["content"])
                escaped = escaped.replace('\n', '<br>')
                parts.append(
                    "<div style='margin:10px 0 4px;'>"
                    "<div style='text-align:right;margin-bottom:2px;'>"
                    "<span style='color:#504870;font-size:10px;"
                    "letter-spacing:0.5px;'>You</span></div>"
                    f"<div style='text-align:right;'>"
                    f"<span style='background:{self._BG_MSGU};color:#d8bfff;"
                    f"border-radius:12px 12px 2px 12px;padding:8px 14px;"
                    f"display:inline-block;font-size:12px;max-width:88%;"
                    f"line-height:1.5;word-wrap:break-word;'>"
                    f"{escaped}</span></div></div>"
                )

            elif role == "assistant":
                ai_html = _md_to_html(msg["content"])
                provider_label = " AI"
                parts.append(
                    "<div style='margin:10px 0 4px;'>"
                    "<div style='margin-bottom:4px;'>"
                    f"<span style='background:#2a1a5a;border-radius:50%;"
                    f"width:20px;height:20px;display:inline-flex;align-items:center;"
                    f"justify-content:center;font-size:10px;margin-right:6px;'></span>"
                    f"<span style='color:{self._COL_ACC};font-size:10px;"
                    f"font-weight:bold;letter-spacing:0.5px;'>AI</span>"
                    "</div>"
                    f"<div style='background:{self._BG_MSGA};"
                    f"border:1px solid #2a1a4a;"
                    f"border-radius:2px 12px 12px 12px;"
                    f"padding:12px 16px;margin-left:4px;'"
                    f">" + ai_html + "</div></div>"
                )

            elif role == "error":
                escaped = _html.escape(str(msg.get("content", "")))
                escaped = escaped.replace('\n', '<br>')
                parts.append(
                    "<div style='margin:10px 0;'>"
                    "<div style='background:#1f0808;border:1px solid #5a1a1a;"
                    "border-radius:8px;padding:12px 16px;'>"
                    "<div style='color:#ff7070;font-size:11px;font-weight:bold;"
                    "margin-bottom:5px;'>\u26a0\ufe0f Error</div>"
                    f"<div style='color:#cc5555;font-size:11px;line-height:1.6;'>"
                    f"{escaped}</div></div></div>"
                )

            elif role == "stopped":
                parts.append(
                    "<div style='margin:8px 0;text-align:center;'>"
                    "<span style='color:#555;font-size:10px;font-style:italic;"
                    "background:#1a1428;border:1px solid #2a2040;"
                    "border-radius:10px;padding:3px 12px;'>"
                    "\u23f9 Response stopped</span></div>"
                )

            elif role == "context_switch":
                parts.append(msg.get("content", ""))

        parts.append("</div>")
        self._chat_output.setHtml("".join(parts))
        sb = self._chat_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def closeEvent(self, event):
        self._dismiss_worker()
        super().closeEvent(event)


# ============================================================================
# ANALYSIS TAB MIXIN - PyQt5 UI
# ============================================================================
