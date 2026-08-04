"""inspector_card.py
Shared Selection Inspector widgets for the Hunt GUI.

Exports
-------
_InspectorCard        – collapsible card widget (text body OR custom body_widget)
analyze_selection     – returns (cards, encoding_str, decoded_val)
"""

import re
import math
import base64
import urllib.parse
import html as _html_mod
import json
from typing import Optional, List, Tuple

from PyQt5.QtWidgets import (
    QWidget, QFrame, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QSizePolicy,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QTextOption


# ─────────────────────────────────────────────────────────────────────────────
# _InspectorCard
# ─────────────────────────────────────────────────────────────────────────────

class _InspectorCard(QWidget):
    """Collapsible card for the Selection Inspector.

    Visual:
      ┌─[colored left border]──────────────────────┐
      │  LABEL                            [▾ / ▸]  │  ← header (click to toggle)
      ├────────────────────────────────────────────┤
      │  body                                      │  ← collapsible
      └────────────────────────────────────────────┘

    Parameters
    ----------
    label       : card header text (may contain emoji / rich text)
    color       : accent colour for left border + label text
    body        : plain-text or HTML string shown in the body QTextEdit
    warn        : amber tint background
    crit        : red tint background (overrides warn)
    is_html     : treat *body* as HTML
    body_widget : if provided, use this QWidget as the body instead of a QTextEdit
    """

    _C_CARD_BG   = "#252535"
    _C_HDR_BG    = "#1e1e2e"
    _C_WARN_BG   = "#241e10"
    _C_CRIT_BG   = "#221515"
    _C_BODY_TEXT = "#d8dce8"

    def __init__(self, label: str, color: str, body: str = "",
                 warn: bool = False, crit: bool = False,
                 is_html: bool = False, body_widget: Optional[QWidget] = None,
                 parent=None):
        super().__init__(parent)
        self.setObjectName("InspCtCard")
        self._collapsed = False

        bg = self._C_CRIT_BG if crit else (self._C_WARN_BG if warn else self._C_CARD_BG)

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        self._frame = QFrame()
        self._frame.setObjectName("InspCtFrame")
        self._frame.setStyleSheet(
            f"QFrame#InspCtFrame {{"
            f"  background: {bg};"
            f"  border: 1px solid {color}44;"
            f"  border-left: 3px solid {color};"
            f"  border-radius: 6px;"
            f"}}"
        )
        frame_layout = QVBoxLayout(self._frame)
        frame_layout.setContentsMargins(0, 0, 0, 0)
        frame_layout.setSpacing(0)
        outer_layout.addWidget(self._frame)

        # ── Header ──────────────────────────────────────────────────────────
        hdr = QWidget()
        hdr.setObjectName("InspCtHdr")
        hdr.setStyleSheet(
            f"QWidget#InspCtHdr {{"
            f"  background: {self._C_HDR_BG};"
            f"  border-bottom: 1px solid {color}33;"
            f"  border-top-left-radius: 6px;"
            f"  border-top-right-radius: 6px;"
            f"}}"
        )
        hdr.setCursor(Qt.PointingHandCursor)
        hdr_l = QHBoxLayout(hdr)
        hdr_l.setContentsMargins(10, 6, 10, 6)
        hdr_l.setSpacing(6)

        self._lbl_w = QLabel(label)
        self._lbl_w.setStyleSheet(
            f"color: {color}; font-weight: 700; font-size: 11px;"
            f" background: transparent; border: none;"
        )
        self._lbl_w.setWordWrap(False)
        hdr_l.addWidget(self._lbl_w, stretch=1)

        self._arrow = QLabel("▾")
        self._arrow.setStyleSheet(
            f"color: {color}88; font-size: 11px; background: transparent; border: none;"
        )
        hdr_l.addWidget(self._arrow)

        frame_layout.addWidget(hdr)

        # ── Body ─────────────────────────────────────────────────────────────
        self._body_w = QWidget()
        self._body_w.setStyleSheet("background: transparent; border: none;")
        body_inner = QVBoxLayout(self._body_w)
        body_inner.setContentsMargins(12, 10, 12, 10)
        body_inner.setSpacing(0)

        if body_widget is not None:
            # Custom interactive widget as body (e.g. re-encode panel)
            self._body_edit = None
            body_inner.addWidget(body_widget)
        else:
            self._body_edit = QTextEdit()
            self._body_edit.setReadOnly(True)
            self._body_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self._body_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            self._body_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            self._body_edit.setWordWrapMode(QTextOption.WrapAnywhere)
            if is_html:
                self._body_edit.setHtml(body)
            else:
                self._body_edit.setPlainText(body)
            self._body_edit.setStyleSheet(
                f"QTextEdit {{"
                f"  background: transparent; border: none;"
                f"  color: {self._C_BODY_TEXT};"
                f"  font-family: Consolas, 'Cascadia Code', monospace;"
                f"  font-size: 11px;"
                f"  padding: 0;"
                f"}}"
            )
            self._body_edit.document().setDocumentMargin(2)
            self._body_edit.document().contentsChanged.connect(self._fit_height)
            self._fit_height()
            body_inner.addWidget(self._body_edit)

        frame_layout.addWidget(self._body_w)
        hdr.mousePressEvent = lambda _e: self._toggle()

    # ── Public helpers ───────────────────────────────────────────────────────

    def update_label(self, text: str) -> None:
        """Update the header label text (e.g. to change encoding type)."""
        self._lbl_w.setText(text)

    def set_collapsed(self, collapsed: bool) -> None:
        if self._collapsed != collapsed:
            self._toggle()

    # ── Internal ─────────────────────────────────────────────────────────────

    def _fit_height(self):
        if self._body_edit is None:
            return
        doc = self._body_edit.document()
        vw = self._body_edit.viewport().width()
        if vw <= 0:
            vw = max(self.width() - 48, 80)
        doc.setTextWidth(max(vw, 60))
        h = int(doc.documentLayout().documentSize().height())
        margin = int(doc.documentMargin())
        self._body_edit.setFixedHeight(max(h + margin * 2 + 4, 20))

    def showEvent(self, event):
        super().showEvent(event)
        if self._body_edit is not None:
            QTimer.singleShot(0, self._fit_height)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit_height()

    def _toggle(self):
        self._collapsed = not self._collapsed
        self._body_w.setVisible(not self._collapsed)
        self._arrow.setText("▸" if self._collapsed else "▾")


def _url_safe_chars_from_original(original: str) -> str:
    """Return chars that were literal in the original URL-encoded string."""
    safe = set()
    index = 0
    while index < len(original):
        if (original[index] == '%' and index + 2 < len(original)
                and original[index + 1] in '0123456789ABCDEFabcdef'
                and original[index + 2] in '0123456789ABCDEFabcdef'):
            index += 3
            continue
        if original[index] != '%':
            safe.add(original[index])
        index += 1
    return ''.join(sorted(safe))


def _decode_one_by_encoding(value: str, encoding: str) -> str:
    """Decode one layer for a supported inspector encoding."""
    if encoding == "url":
        return urllib.parse.unquote(value)
    if encoding == "html":
        return _html_mod.unescape(value)
    if encoding == "base64":
        return base64.b64decode(value + '==').decode('utf-8', errors='replace')
    if encoding == "base64_urlsafe":
        return base64.urlsafe_b64decode(value + '==').decode('utf-8', errors='replace')
    raise ValueError(f"Unsupported decode encoding: {encoding}")


def _try_url_mixed(value: str, allow_plus: bool = False) -> Optional[str]:
    has_pct = bool(re.search(r'%[0-9A-Fa-f]{2}', value))
    has_plus = allow_plus and '+' in value
    if not has_pct and not has_plus:
        return None
    try:
        decoded = urllib.parse.unquote_plus(value) if has_plus else urllib.parse.unquote(value)
        if decoded != value:
            return decoded
    except Exception:
        pass
    return None


def _try_html_mixed(value: str) -> Optional[str]:
    if '&' in value and ';' in value:
        decoded = _html_mod.unescape(value)
        if decoded != value:
            return decoded
    return None


def _try_b64_mixed(value: str) -> Optional[str]:
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decode(value + '==')
            decoded = raw.decode('utf-8')
            if len(decoded) >= 3 and any(char.isprintable() for char in decoded):
                return decoded.strip()
        except Exception:
            pass
    return None


def _decode_chain_mixed(value: str, depth: int = 0) -> list:
    if depth > 6 or len(value) > 20000:
        return []
    decoded = _try_url_mixed(value, allow_plus=False)
    if decoded:
        return [("URL", decoded)] + _decode_chain_mixed(decoded, depth + 1)
    decoded = _try_html_mixed(value)
    if decoded:
        return [("HTML", decoded)] + _decode_chain_mixed(decoded, depth + 1)
    clean = value.strip().replace('\n', '').replace(' ', '')
    if re.match(r'^[A-Za-z0-9+/=_-]{8,}$', clean):
        decoded = _try_b64_mixed(clean)
        if decoded and decoded != value:
            return [("Base64", decoded)] + _decode_chain_mixed(decoded, depth + 1)
    return []


def _scan_subtokens_mixed(value: str) -> list:
    patterns = [
        ("JWT", r'eyJ[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]*'),
        ("URL-enc", r'(?:%[0-9A-Fa-f]{2})+(?:[^%\s]*(?:%[0-9A-Fa-f]{2})+)*'),
        ("Base64", r'[A-Za-z0-9+/]{20,}={0,2}'),
        ("HTML-ent", r'(?:&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);){2,}'),
        ("\\uXXXX", r'(?:\\u[0-9A-Fa-f]{4}){2,}'),
        ("Hex", r'\b[0-9a-fA-F]{16,}\b'),
    ]
    findings = []
    claimed = set()
    for sub_type, pattern in patterns:
        for match in re.finditer(pattern, value):
            if any(index in claimed for index in range(match.start(), match.end())):
                continue
            raw = match.group(0)
            decoded = None
            try:
                if sub_type == "JWT":
                    parts = raw.split('.')

                    def _jwt_dec(part):
                        part = part.replace('-', '+').replace('_', '/') + '==' * 3
                        return base64.b64decode(part).decode('utf-8', errors='replace')

                    decoded = (
                        f"Header: {json.dumps(json.loads(_jwt_dec(parts[0])))}\n"
                        f"Payload: {json.dumps(json.loads(_jwt_dec(parts[1])), indent=2)}"
                    )
                elif sub_type == "URL-enc":
                    decoded = _try_url_mixed(raw, allow_plus=False)
                elif sub_type == "Base64":
                    decoded = _try_b64_mixed(raw)
                elif sub_type == "HTML-ent":
                    decoded = _try_html_mixed(raw)
                elif sub_type == "\\uXXXX":
                    decoded = raw.encode('raw_unicode_escape').decode('unicode_escape')
                elif sub_type == "Hex":
                    hex_clean = raw.replace(':', '').replace(' ', '')
                    if len(hex_clean) % 2 == 0:
                        raw_bytes = bytes.fromhex(hex_clean)
                        decoded = (
                            raw_bytes.decode('utf-8')
                            if all(32 <= byte < 127 for byte in raw_bytes)
                            else raw_bytes.hex()
                        )
            except Exception:
                pass
            if decoded:
                findings.append((sub_type, raw, decoded, match.start(), match.end()))
                claimed.update(range(match.start(), match.end()))
    return findings


def _apply_subtoken_decodes_mixed(value: str, depth: int = 0) -> str:
    if depth > 3:
        return value
    findings = _scan_subtokens_mixed(value)
    if not findings:
        return value
    rebuilt = []
    cursor = 0
    changed = False
    for _sub_type, raw, decoded, start, end in sorted(findings, key=lambda item: item[3]):
        rebuilt.append(value[cursor:start])
        final_piece_chain = _decode_chain_mixed(decoded)
        final_piece = final_piece_chain[-1][1] if final_piece_chain else decoded
        rebuilt.append(final_piece)
        changed = changed or (final_piece != raw)
        cursor = end
    rebuilt.append(value[cursor:])
    merged = ''.join(rebuilt)
    if changed and merged != value:
        return _apply_subtoken_decodes_mixed(merged, depth + 1)
    return merged


def _jwt_reencode(edited: str, original_jwt: str) -> str:
    """Re-encode edited JWT decoded text back into a compact JWT token string.

    The *edited* text must be in the format that _scan_subtokens_mixed produces:
        Header: {header_json}
        Payload: {\n  "key": "value"\n}

    The original signature is preserved verbatim (it will be cryptographically
    invalid after editing, which is expected for fuzzing / testing purposes).
    """
    orig_parts = original_jwt.split('.')
    orig_sig = orig_parts[2] if len(orig_parts) == 3 else ''
    orig_header_b64 = orig_parts[0] if orig_parts else ''

    def _b64url_decode(s: str) -> str:
        s = s.replace('-', '+').replace('_', '/')
        s += '=' * ((4 - len(s) % 4) % 4)
        try:
            return base64.b64decode(s).decode('utf-8', errors='replace')
        except Exception:
            return '{}'

    def _b64url_encode(data) -> str:
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    edited = edited.strip()
    header_dict = None
    payload_dict = None

    # Try to match the canonical inspector format:
    #   Header: {single-line json}\nPayload: {possibly-multi-line json}
    m = re.match(
        r'^Header:\s*(\{[^\n]*?\})\s*Payload:\s*(\{.*\})\s*$',
        edited, re.DOTALL
    )
    if m:
        try:
            header_dict = json.loads(m.group(1))
            payload_dict = json.loads(m.group(2))
        except Exception:
            header_dict = None
            payload_dict = None

    if payload_dict is None:
        # Fallback: treat the whole edited text as just the payload JSON
        try:
            payload_dict = json.loads(edited)
        except Exception:
            raise ValueError(f"Cannot parse JWT edited text as JSON: {edited[:200]}")

    if header_dict is None:
        # Recover original header from the JWT
        try:
            header_dict = json.loads(_b64url_decode(orig_header_b64))
        except Exception:
            header_dict = {"alg": "none"}

    new_header_b64 = _b64url_encode(json.dumps(header_dict, separators=(',', ':')))
    new_payload_b64 = _b64url_encode(json.dumps(payload_dict, separators=(',', ':')))
    return f"{new_header_b64}.{new_payload_b64}.{orig_sig}"


def _build_mixed_reencode_plan(original_text: str) -> tuple:
    findings = _scan_subtokens_mixed(original_text)
    literals: List[str] = []
    tokens: List[dict] = []
    cursor = 0
    enc_map = {
        "URL": "url",
        "HTML": "html",
        "Base64": "base64",
        "Base64 URL-safe": "base64_urlsafe",
    }
    for sub_type, raw, decoded, start, end in sorted(findings, key=lambda item: item[3]):
        if len(raw) < 8:
            continue
        # ── JWT: special encoding that cannot be expressed as a simple chain ──
        if sub_type == "JWT":
            literals.append(original_text[cursor:start])
            tokens.append({
                "raw": raw,
                "enc_chain": "jwt",
                "final": decoded,
            })
            cursor = end
            continue
        step_name = {
            "URL-enc": "URL",
            "HTML-ent": "HTML",
            "Base64": "Base64",
            "JWT": "JWT",
            "\\uXXXX": "Unicode",
            "Hex": "Hex",
        }.get(sub_type, sub_type)
        step_chain = [(step_name, decoded)] + _decode_chain_mixed(decoded)
        enc_chain = [enc_map[name] for name, _ in step_chain if name in enc_map]
        if not enc_chain:
            continue
        final_piece = _apply_subtoken_decodes_mixed(step_chain[-1][1])
        if final_piece == raw:
            continue
        literals.append(original_text[cursor:start])
        tokens.append({
            "raw": raw,
            "enc_chain": '|'.join(enc_chain),
            "final": final_piece,
        })
        cursor = end
    literals.append(original_text[cursor:])
    final_text_parts: List[str] = []
    for index, token in enumerate(tokens):
        final_text_parts.append(literals[index])
        final_text_parts.append(token["final"])
    final_text_parts.append(literals[-1])
    return literals, tokens, ''.join(final_text_parts)


def _reencode_mixed_final_decoded(edited: str, original_text: str) -> str:
    literals, tokens, _final_text = _build_mixed_reencode_plan(original_text)
    if not tokens:
        return edited
    cursor = 0
    rebuilt: List[str] = []
    for index, token in enumerate(tokens):
        literal_before = literals[index]
        literal_after = literals[index + 1]
        if not edited.startswith(literal_before, cursor):
            raise ValueError(
                "Mixed final decoded editing requires keeping the surrounding text structure unchanged."
            )
        rebuilt.append(literal_before)
        cursor += len(literal_before)
        if literal_after:
            next_pos = edited.find(literal_after, cursor)
            if next_pos == -1:
                raise ValueError(
                    "Mixed final decoded editing requires keeping the surrounding text structure unchanged."
                )
            token_decoded = edited[cursor:next_pos]
            cursor = next_pos
        else:
            token_decoded = edited[cursor:]
            cursor = len(edited)
        rebuilt.append(reencode_decoded_value(token_decoded, token["enc_chain"], token["raw"]))
    rebuilt.append(literals[-1])
    return ''.join(rebuilt)


def reencode_decoded_value(edited: str, encoding_chain: str, original_text: str) -> str:
    """Re-encode edited final text back through the detected encoding chain."""
    if encoding_chain == "final_decoded":
        return _reencode_mixed_final_decoded(edited, original_text)
    if encoding_chain == "jwt":
        return _jwt_reencode(edited, original_text)

    encodings = [part for part in encoding_chain.split('|') if part]
    if not encodings:
        return edited

    layer_inputs = [original_text]
    current = original_text
    for encoding in encodings:
        current = _decode_one_by_encoding(current, encoding)
        layer_inputs.append(current)

    value = edited
    for index in range(len(encodings) - 1, -1, -1):
        encoding = encodings[index]
        layer_original = layer_inputs[index]
        if encoding == "url":
            safe = _url_safe_chars_from_original(layer_original)
            value = urllib.parse.quote(value, safe=safe)
        elif encoding == "html":
            value = _html_mod.escape(value)
        elif encoding == "base64":
            value = base64.b64encode(value.encode('utf-8')).decode('ascii')
        elif encoding == "base64_urlsafe":
            value = base64.urlsafe_b64encode(value.encode('utf-8')).decode('ascii')
        else:
            raise ValueError(f"Unsupported encode encoding: {encoding}")
    return value


# ─────────────────────────────────────────────────────────────────────────────
# analyze_selection
# ─────────────────────────────────────────────────────────────────────────────

def analyze_selection(text: str, source: str = "") -> Tuple[list, str, Optional[str]]:
    """Analyse *text* and return inspector card data plus re-encode metadata.

    Returns
    -------
    cards      : list of ``(label, color, body_html, warn, crit, is_html)`` tuples
    encoding   : reversible whole-selection encoding chain, e.g. ``url|base64``
    decoded_val: final whole-selection decoded value for re-encode, or None
    """
    t = text.replace('\u2029', '\n').replace('\u2028', '\n')
    ts = t.strip()
    byte_len = len(t.encode('utf-8'))
    line_count = t.count('\n') + 1
    freq: dict = {}
    for char in t:
        freq[char] = freq.get(char, 0) + 1
    entropy = (-sum((count / len(t)) * math.log2(count / len(t))
                    for count in freq.values())) if t else 0.0

    CL_TEAL = "#4ecdc4"
    CL_BLUE = "#6db3e8"
    CL_GREEN = "#7ec87e"
    CL_PURPLE = "#b09ae8"
    CL_ORANGE = "#e8a862"
    CL_PINK = "#e07890"
    CL_YELLOW = "#d4b85a"
    CL_LAVEND = "#b8a8e8"
    CL_CYAN = "#56c8c8"
    CL_WARN = "#e89840"
    CL_MUTED = "#9090aa"
    CL_BODY = "#d8dce8"

    TYPE_DISPLAY = {
        "JWT": ("JWT", CL_PINK),
        "URL-enc": ("URL", CL_BLUE),
        "Base64": ("Base64", CL_GREEN),
        "Base64 URL-safe": ("Base64 URL-safe", CL_TEAL),
        "HTML-ent": ("HTML", CL_ORANGE),
        "\\uXXXX": ("Unicode", CL_LAVEND),
        "Hex": ("Hex", CL_YELLOW),
    }
    LAYER_COLORS = {
        "URL": CL_BLUE,
        "HTML": CL_ORANGE,
        "Base64": CL_GREEN,
        "Base64 URL-safe": CL_TEAL,
        "Gzip": CL_CYAN,
        "Unicode": CL_LAVEND,
        "Hex": CL_YELLOW,
        "Binary": CL_TEAL,
    }

    def _esc(value: str, limit: int = 4000) -> str:
        return _html_mod.escape(str(value)[:limit])

    def _try_b64(value: str):
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decode(value + '==')
                decoded = raw.decode('utf-8')
                if len(decoded) >= 3 and any(char.isprintable() for char in decoded):
                    return decoded.strip()
            except Exception:
                pass
        return None

    def _try_b64_raw(value: str):
        try:
            raw = base64.b64decode(value + '==')
            try:
                return raw.decode('utf-8'), None
            except UnicodeDecodeError:
                return None, raw.hex()
        except Exception:
            return None, None

    def _try_url(value: str, allow_plus: bool = False):
        has_pct = bool(re.search(r'%[0-9A-Fa-f]{2}', value))
        has_plus = allow_plus and '+' in value
        if not has_pct and not has_plus:
            return None
        try:
            decoded = urllib.parse.unquote_plus(value) if has_plus else urllib.parse.unquote(value)
            if decoded != value:
                return decoded
        except Exception:
            pass
        return None

    def _try_html_ent(value: str):
        if '&' in value and ';' in value:
            decoded = _html_mod.unescape(value)
            if decoded != value:
                return decoded
        return None

    def _try_json(value: str):
        try:
            return json.dumps(json.loads(value), indent=2, ensure_ascii=False)
        except Exception:
            return None

    def _format_decoded(value: str, limit: int = 4000) -> str:
        pretty = _try_json(value.strip()) if isinstance(value, str) else None
        return (pretty if pretty else value)[:limit]

    def _decode_chain(value: str, depth: int = 0) -> list:
        if depth > 6 or len(value) > 20000:
            return []
        decoded = _try_url(value, allow_plus=False)
        if decoded:
            return [("URL", decoded)] + _decode_chain(decoded, depth + 1)
        decoded = _try_html_ent(value)
        if decoded:
            return [("HTML", decoded)] + _decode_chain(decoded, depth + 1)
        clean = value.strip().replace('\n', '').replace(' ', '')
        if re.match(r'^[A-Za-z0-9+/=_-]{8,}$', clean):
            decoded = _try_b64(clean)
            if decoded and decoded != value:
                return [("Base64", decoded)] + _decode_chain(decoded, depth + 1)
        return []

    def _is_single_blob(value: str) -> bool:
        stripped = value.strip()
        if not stripped or any(char.isspace() for char in stripped):
            return False
        if any(char in stripped for char in ';:,'):
            return False
        if '&' in stripped:
            return False
        if '=' in stripped and not re.match(r'^[^=]+={0,2}$', stripped):
            return False
        return True

    def _scan_subtokens(value: str) -> list:
        patterns = [
            ("JWT", r'eyJ[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]+\.[A-Za-z0-9+/=_-]*', CL_PINK),
            ("URL-enc", r'(?:%[0-9A-Fa-f]{2})+(?:[^%\s]*(?:%[0-9A-Fa-f]{2})+)*', CL_BLUE),
            ("Base64", r'[A-Za-z0-9+/]{20,}={0,2}', CL_GREEN),
            ("HTML-ent", r'(?:&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);){2,}', CL_ORANGE),
            ("\\uXXXX", r'(?:\\u[0-9A-Fa-f]{4}){2,}', CL_LAVEND),
            ("Hex", r'\b[0-9a-fA-F]{16,}\b', CL_YELLOW),
        ]
        findings = []
        claimed = set()
        for sub_type, pattern, color in patterns:
            for match in re.finditer(pattern, value):
                if any(index in claimed for index in range(match.start(), match.end())):
                    continue
                raw = match.group(0)
                decoded = None
                try:
                    if sub_type == "JWT":
                        parts = raw.split('.')
                        def _jwt_dec(part):
                            part = part.replace('-', '+').replace('_', '/') + '==' * 3
                            return base64.b64decode(part).decode('utf-8', errors='replace')
                        decoded = (
                            f"Header: {json.dumps(json.loads(_jwt_dec(parts[0])))}\n"
                            f"Payload: {json.dumps(json.loads(_jwt_dec(parts[1])), indent=2)}"
                        )
                    elif sub_type == "URL-enc":
                        decoded = _try_url(raw, allow_plus=False)
                    elif sub_type == "Base64":
                        decoded = _try_b64(raw)
                    elif sub_type == "HTML-ent":
                        decoded = _try_html_ent(raw)
                    elif sub_type == "\\uXXXX":
                        decoded = raw.encode('raw_unicode_escape').decode('unicode_escape')
                    elif sub_type == "Hex":
                        hex_clean = raw.replace(':', '').replace(' ', '')
                        if len(hex_clean) % 2 == 0:
                            raw_bytes = bytes.fromhex(hex_clean)
                            decoded = (
                                raw_bytes.decode('utf-8')
                                if all(32 <= byte < 127 for byte in raw_bytes)
                                else raw_bytes.hex()
                            )
                except Exception:
                    pass
                if decoded:
                    findings.append((sub_type, raw, decoded, color, match.start(), match.end()))
                    claimed.update(range(match.start(), match.end()))
        return findings

    def _apply_subtoken_decodes(value: str, depth: int = 0) -> str:
        if depth > 3:
            return value
        findings = _scan_subtokens(value)
        if not findings:
            return value
        rebuilt = []
        cursor = 0
        changed = False
        for sub_type, raw, decoded, _color, start, end in sorted(findings, key=lambda item: item[4]):
            rebuilt.append(value[cursor:start])
            final_piece_chain = _decode_chain(decoded)
            final_piece = final_piece_chain[-1][1] if final_piece_chain else decoded
            rebuilt.append(final_piece)
            changed = changed or (final_piece != raw)
            cursor = end
        rebuilt.append(value[cursor:])
        merged = ''.join(rebuilt)
        if changed and merged != value:
            return _apply_subtoken_decodes(merged, depth + 1)
        return merged

    sub_findings = _scan_subtokens(t)
    seen_enc = {}
    for sub_type, _, _, color, _, _ in sub_findings:
        if sub_type not in seen_enc:
            seen_enc[sub_type] = TYPE_DISPLAY.get(sub_type, (sub_type, color))

    entropy_color = CL_WARN if entropy > 4.0 else CL_TEAL
    stats_str = (
        f"\U0001f50d Preview  \u2502  "
        f"{len(t):,} chars \u00b7 {byte_len:,} bytes"
        + (f" \u00b7 {line_count} lines" if line_count > 1 else "")
        + f"  \u2502  entropy {entropy:.2f}"
    )
    if seen_enc:
        badges = "  ".join(
            f'<span style="background:{display[1]}33;border:1px solid {display[1]}99;'
            f'border-radius:3px;padding:0px 6px;color:{display[1]};'
            f'font-size:10px;font-weight:700;">{display[0]}</span>'
            for display in seen_enc.values()
        )
        preview_label = f'{_html_mod.escape(stats_str)}&nbsp; &nbsp;{badges}'
    else:
        preview_label = stats_str

    prev_max = 6000
    display_t = t.strip()
    strip_offset = len(t) - len(t.lstrip())
    preview_parts: list = []
    cursor = 0
    for _, original, decoded, color, start, end in sorted(sub_findings, key=lambda item: item[4]):
        adj_start = max(0, start - strip_offset)
        adj_end = max(0, end - strip_offset)
        if adj_start > len(display_t) or adj_end <= 0:
            continue
        if adj_start > cursor and cursor < prev_max:
            preview_parts.append(_esc(display_t[cursor:adj_start][:prev_max - cursor]))
        if cursor < prev_max:
            preview_parts.append(
                f'<span style="background:{color}33;border-bottom:1px solid {color};'
                f'color:{CL_BODY};" title="{_esc(decoded[:120])}">'
                f'{_esc(original[:200])}{"…" if len(original) > 200 else ""}</span>'
            )
        cursor = adj_end
    if cursor < len(display_t) and cursor < prev_max:
        preview_parts.append(_esc(display_t[cursor:prev_max]) + ('…' if len(display_t) > prev_max else ''))
    elif cursor >= prev_max:
        preview_parts.append('…')
    preview_html_body = (
        f'<span style="font-family:Consolas,monospace;font-size:11px;'
        f'color:{CL_BODY};word-break:break-all;white-space:pre-wrap;">'
        + ''.join(preview_parts) + '</span>'
    )
    results: list = [(preview_label, entropy_color, preview_html_body, False, False, True)]

    found_any = False
    CL_KV_KEY = "#79b8ff"
    CL_KV_SEP = "#8b949e"
    CL_KV_VAL = "#ff7b72"

    def _colorize_json_keys(value: str) -> str:
        parts: list = []
        last = 0
        for match in re.finditer(r'("(?:[^"\\]|\\.)*")(\s*:\s*)', value):
            if match.start() > last:
                parts.append(f'<span style="color:{CL_KV_VAL}">{_esc(value[last:match.start()])}</span>')
            parts.append(
                f'<span style="color:{CL_KV_KEY};font-weight:600">{_esc(match.group(1))}</span>'
                f'<span style="color:{CL_KV_SEP}">{_esc(match.group(2))}</span>'
            )
            last = match.end()
        if last < len(value):
            parts.append(f'<span style="color:{CL_KV_VAL}">{_esc(value[last:])}</span>')
        return ''.join(parts)

    def _colorize_value(value: str) -> str:
        if '{' in value or ('"' in value and ':' in value):
            return _colorize_json_keys(value)
        return f'<span style="color:{CL_KV_VAL}">{_esc(value)}</span>'

    def _colorize_body(body_text: str) -> str:
        out_lines: list = []
        for line in body_text.split('\n'):
            if re.match(r'^\s*https?://', line):
                out_lines.append(f'<span style="color:{CL_KV_VAL}">{_esc(line)}</span>')
                continue
            if '=' in line and (';' in line or '&' in line):
                raw_segments = re.split(r'(;\s*|&)', line)
                seg_html: list = []
                for segment in raw_segments:
                    if re.match(r'^(;\s*|&)$', segment):
                        seg_html.append(
                            f'<span style="color:{CL_KV_SEP}">{_esc(segment.rstrip())}</span>'
                            f'<span style="color:{CL_KV_SEP}"> </span>'
                        )
                        continue
                    segment = segment.strip()
                    if not segment:
                        continue
                    eq_index = segment.find('=')
                    if eq_index > 0:
                        key, value = segment[:eq_index], segment[eq_index + 1:]
                        seg_html.append(
                            f'<span style="color:{CL_KV_KEY};font-weight:600">{_esc(key)}</span>'
                            f'<span style="color:{CL_KV_SEP}">=</span>'
                            + _colorize_value(value)
                        )
                    else:
                        seg_html.append(f'<span style="color:{CL_KV_VAL}">{_esc(segment)}</span>')
                out_lines.append(''.join(seg_html))
                continue
            match = re.match(r'^(\s*)("(?:[^"\\]|\\.)*")(\s*:\s*)(.*)$', line)
            if match:
                indent, key, sep, value = match.groups()
                out_lines.append(
                    f'{_esc(indent)}'
                    f'<span style="color:{CL_KV_KEY};font-weight:600">{_esc(key)}</span>'
                    f'<span style="color:{CL_KV_SEP}">{_esc(sep)}</span>'
                    + _colorize_value(value)
                )
                continue
            match = re.match(r'^(\s*)([A-Za-z0-9_.\-\[\]%@]+)(\s*[=:]+\s*)(.*)$', line)
            if match:
                indent, key, sep, value = match.groups()
                out_lines.append(
                    f'{_esc(indent)}'
                    f'<span style="color:{CL_KV_KEY};font-weight:600">{_esc(key)}</span>'
                    f'<span style="color:{CL_KV_SEP}">{_esc(sep)}</span>'
                    + _colorize_value(value)
                )
                continue
            out_lines.append(f'<span style="color:{CL_KV_VAL}">{_esc(line)}</span>')
        return (
            f'<span style="font-family:Consolas,monospace;font-size:11px;'
            f'color:{CL_KV_VAL};white-space:pre-wrap;">'
            + '<br>'.join(out_lines) + '</span>'
        )

    def _add(label, color, body_text):
        nonlocal found_any
        results.append((label, color, _colorize_body(body_text), False, False, True))
        found_any = True

    full_chain: list = []
    jwt_m = re.match(r'^(eyJ[A-Za-z0-9+/=_-]+)\.(eyJ[A-Za-z0-9+/=_-]+)\.([A-Za-z0-9+/=_-]*)$', ts)
    if jwt_m:
        try:
            from datetime import datetime as _dt, timezone as _tz

            def _jwt_dec(part):
                part = part.replace('-', '+').replace('_', '/') + '==' * 3
                return base64.b64decode(part).decode('utf-8', errors='replace')

            header = json.loads(_jwt_dec(jwt_m.group(1)))
            payload = json.loads(_jwt_dec(jwt_m.group(2)))
            alg = header.get('alg', '?')
            lines_jwt = [f"Algorithm : {alg}"]
            if 'exp' in payload:
                try:
                    exp_dt = _dt.fromtimestamp(payload['exp'], tz=_tz.utc)
                    expired = exp_dt < _dt.now(tz=_tz.utc)
                    lines_jwt.append(("EXPIRED   : " if expired else "Expires  : ")
                                     + exp_dt.strftime('%Y-%m-%d %H:%M UTC'))
                except Exception:
                    pass
            if 'iat' in payload:
                try:
                    lines_jwt.append("Issued   : " + _dt.fromtimestamp(
                        payload['iat'], tz=_tz.utc).strftime('%Y-%m-%d %H:%M UTC'))
                except Exception:
                    pass
            lines_jwt += [
                f"\nHeader:\n{json.dumps(header, indent=2)}",
                f"\nPayload:\n{json.dumps(payload, indent=2)}",
            ]
            _add(f"\U0001f511 JWT  \u00b7  alg\u202f=\u202f{alg}", CL_PINK, '\n'.join(lines_jwt))
        except Exception:
            pass
    else:
        is_single_blob = _is_single_blob(ts)
        full_chain = _decode_chain(ts) if is_single_blob else []
        clean = ts.replace('\n', '').replace(' ', '')
        if is_single_blob and not full_chain and re.match(r'^[A-Za-z0-9+/]{8,}={0,2}$', clean):
            txt, hx = _try_b64_raw(clean)
            if txt is not None:
                full_chain = [("Base64", txt)] + _decode_chain(txt)
            elif hx is not None:
                _add("\U0001f513 Decoded  \u00b7  Base64 \u2192 Hex", CL_GREEN, hx[:600])
        if is_single_blob and not full_chain and re.match(r'^[A-Za-z0-9_-]{8,}$', clean):
            try:
                raw = base64.urlsafe_b64decode(clean + '==')
                dec_s = raw.decode('utf-8')
                if any(char.isalpha() for char in dec_s):
                    full_chain = [("Base64 URL-safe", dec_s)] + _decode_chain(dec_s)
            except Exception:
                pass
        if is_single_blob and not full_chain and re.match(r'^H4sI[A-Za-z0-9+/=_-]+$', clean):
            try:
                import gzip as _gzip
                gz_dec = _gzip.decompress(base64.b64decode(clean + '==')).decode('utf-8', errors='replace')
                full_chain = [("Gzip", gz_dec)] + _decode_chain(gz_dec)
            except Exception:
                pass

        if full_chain:
            for layer_name, decoded_value in full_chain:
                _add(
                    f"\U0001f513 Decoded  \u00b7  {layer_name}",
                    LAYER_COLORS.get(layer_name, CL_CYAN),
                    _format_decoded(decoded_value, 4000),
                )
        else:
            if '\\u' in t or '\\x' in t:
                try:
                    decoded = t.encode('raw_unicode_escape').decode('unicode_escape')
                    if decoded != t:
                        _add("\U0001f513 Decoded  \u00b7  Unicode", CL_LAVEND, decoded[:2000])
                except Exception:
                    pass

            hex_clean = ts.replace(' ', '').replace(':', '')
            if (re.match(r'^[0-9a-fA-F]+$', hex_clean)
                    and len(hex_clean) % 2 == 0 and len(hex_clean) >= 8):
                try:
                    raw_bytes = bytes.fromhex(hex_clean)
                    try:
                        _add("\U0001f513 Decoded  \u00b7  Hex", CL_YELLOW, raw_bytes.decode('utf-8'))
                    except UnicodeDecodeError:
                        _add(
                            "\U0001f513 Decoded  \u00b7  Hex \u2192 Bytes",
                            CL_YELLOW,
                            f"bytes  : {len(raw_bytes)}\nhex    : {raw_bytes[:64].hex()}",
                        )
                except Exception:
                    pass

            bin_clean = ts.replace(' ', '').replace('\n', '')
            if (re.match(r'^[01]+$', bin_clean)
                    and len(bin_clean) % 8 == 0
                    and 8 <= len(bin_clean) <= 8000):
                try:
                    bin_text = ''.join(chr(int(bin_clean[index:index + 8], 2))
                                       for index in range(0, len(bin_clean), 8))
                    if bin_text.isprintable():
                        _add("\U0001f513 Decoded  \u00b7  Binary", CL_TEAL, bin_text)
                except Exception:
                    pass

    chain_values = {value.strip()[:200] for _, value in full_chain}
    for sub_type, original, decoded, color, _start, _end in sub_findings:
        if len(original.strip()) >= len(ts) - 2 or len(original) < 8:
            continue
        if decoded.strip()[:200] in chain_values:
            continue
        short_token = original[:60] + ('\u2026' if len(original) > 60 else '')
        token_steps = [(TYPE_DISPLAY.get(sub_type, (sub_type, color))[0], decoded)] + _decode_chain(decoded)
        token_input = original
        for step_name, step_value in token_steps:
            _add(
                f"\U0001f513 Decoded  \u00b7  {step_name}  \u00b7  {short_token}",
                LAYER_COLORS.get(step_name, color),
                f"Token   : {token_input[:300]}\nDecoded :\n{_format_decoded(step_value, 2500)}",
            )
            token_input = step_value

    final_text = ts
    if full_chain:
        final_text = full_chain[-1][1]
    final_text = _apply_subtoken_decodes(final_text)
    if final_text != ts:
        _add("\u2728 Final Decoded", CL_TEAL, _format_decoded(final_text, 4000))

    if ts.startswith(('{', '[')):
        pretty = _try_json(ts)
        if pretty:
            _add("\U0001f4cb JSON", CL_PURPLE, pretty)

    auth_m = re.match(r'^(Bearer|Basic|Digest|NTLM|AWS\d*)\s+(.+)$', ts, re.IGNORECASE)
    if auth_m:
        atype, aval = auth_m.group(1), auth_m.group(2).strip()
        body_auth = f"Type  : {atype}\nValue : {aval[:300]}"
        if atype.lower() == 'basic':
            try:
                dec_basic = base64.b64decode(aval + '==').decode('utf-8', errors='replace')
                body_auth += f"\n\nDecoded : {dec_basic}"
                if ':' in dec_basic:
                    user, password = dec_basic.split(':', 1)
                    body_auth += f"\nuser    : {user}\npass    : {password}"
            except Exception:
                pass
        _add("\U0001f510 Authorization", CL_PINK, body_auth)

    if re.match(r'^(\d{10}|\d{13})$', ts):
        try:
            from datetime import datetime as _dt, timezone as _tz
            num = int(ts)
            mul = 1 if len(ts) == 10 else 1000
            dt = _dt.fromtimestamp(num / mul, tz=_tz.utc)
            _add(
                "\u23f0 Timestamp",
                CL_TEAL,
                f"UTC    : {dt.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Format : {'Unix seconds' if mul == 1 else 'Unix milliseconds'}",
            )
        except Exception:
            pass

    if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
                r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', ts):
        version = int(ts.replace('-', '')[12], 16)
        _add(f"\U0001f194 UUID v{version}", CL_PURPLE, f"Version : {version}\nValue   : {ts}")

    if re.match(r'^\d{1,20}$', ts) and not re.match(r'^\d{10}$|\d{13}$', ts):
        try:
            num = int(ts)
            _add(
                "\U0001f522 Integer",
                CL_BLUE,
                f"Decimal : {num}\nHex     : 0x{num:X}\nOctal   : 0o{num:o}\nBinary  : {bin(num)}",
            )
        except Exception:
            pass

    if not found_any:
        results.append((
            "\u2139 No Encoding Detected",
            CL_MUTED,
            "Plain text — no known encoding or format recognised.",
            False,
            False,
            False,
        ))

    encoding_map = {
        "URL": "url",
        "HTML": "html",
        "Base64": "base64",
        "Base64 URL-safe": "base64_urlsafe",
    }
    encoding_parts: list = []
    decoded_plain: Optional[str] = None
    if full_chain:
        for layer_name, _decoded in full_chain:
            mapped = encoding_map.get(layer_name)
            if not mapped:
                encoding_parts = []
                break
            encoding_parts.append(mapped)
        if encoding_parts:
            decoded_plain = full_chain[-1][1]

    if not encoding_parts and final_text != ts:
        return results, 'final_decoded', final_text

    return results, '|'.join(encoding_parts), decoded_plain
