"""
analysis_tab_enhanced.py - Complete Security Analysis Tab with Full Analysis Engine

This is a COMPLETE implementation that includes:
1. All analyzer classes moved from hunt_script.py
2. Full PyQt5 UI for the Analysis tab
3. On-demand analysis triggering
4. Parameter markers and auto-highlighting

Author: Hunt Team
Version: 2.0 (Enhanced)
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTextEdit, QComboBox, QCheckBox, QGroupBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QSplitter, QProgressBar,
    QMessageBox, QScrollArea, QFrame, QApplication, QGridLayout, QMenu,
    QTabWidget, QDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QEvent
from PyQt5.QtGui import QTextCharFormat, QColor, QFont, QTextCursor

try:
    import regex as re   # pip install regex  — faster engine, same API
except ImportError:
    import re
import os
import json
import html as _html
import base64
import time as _time_mod
import logging
from typing import Dict, List, Tuple, Set, Any, Optional
from datetime import datetime
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from collections import deque

try:
    from modules.http_history_tab import SearchHighlighter
except ImportError:
    # Fallback if not available
    class SearchHighlighter:
        @staticmethod
        def clear_highlights(text_edit):
            pass
        
        @staticmethod
        def highlight_all_matches(text_edit, search_text, case_sensitive=False):
            return 0

# ── Recording manager (auto-save detections to project dir) ──────────────────
try:
    from modules.analysis_recordings import RecordingManager
except ImportError:
    RecordingManager = None  # Graceful fallback if file not present

# ── AI traffic analysis worker ─────────────────────────────────────────────────
try:
    from modules.ai_client import AITrafficWorker as _AITrafficWorker
    from modules.ai_client import AISourceCodeWorker as _AISourceCodeWorker
    from modules.ai_client import AIChatWorker as _AIChatWorker
    from modules.ai_client import _AI_CHAT_SYSTEM_TMPL as _AI_CHAT_SYSTEM_TMPL
    from modules.ai_client import _GENERAL_CHAT_SYSTEM as _GENERAL_CHAT_SYSTEM
    _AI_TRAFFIC_AVAILABLE = True
except ImportError:
    _AITrafficWorker = None
    _AISourceCodeWorker = None
    _AIChatWorker = None
    _AI_CHAT_SYSTEM_TMPL = ""
    _GENERAL_CHAT_SYSTEM = (
        "Your name is Hunt Assistant — an elite AI security co-pilot. "
        "The user is a web app pentester and bug bounty hunter. "
        "Help them detect and exploit vulnerabilities. Be concise and technical."
    )
    _AI_TRAFFIC_AVAILABLE = False

# Import constants from constants.py if available
try:
    from modules.constants import COLORS
except ImportError:
    # Fallback colors
    COLORS = {
        'bg_dark': '#2B2B2B',
        'bg_darker': '#1E1E1E',
        'bg_lighter': '#323232',
        'text_normal': '#BBBBBB',
        'text_bright': '#FFFFFF',
        'accent_green': '#6A8759',
        'severity_critical': '#FF6B6B',
        'severity_high': '#FFA726',
        'severity_medium': '#FFEE58',
        'severity_low': '#64B5F6',
    }

logger = logging.getLogger(__name__)


# ============================================================================
# CONSTANTS & PATTERNS
# ============================================================================

# --- GF Patterns (enhanced for bug bounty) ---
GF_PATTERNS = {
    "xss": [
        "q=",
        "s=",
        "search=",
        "lang=",
        "keyword=",
        "query=",
        "page=",
        "keywords=",
        "year=",
        "view=",
        "email=",
        "type=",
        "name=",
        "p=",
        "callback=",
        "jsonp=",
        "api_key=",
        "api=",
        "password=",
        "email=",
        "emailto=",
        "token=",
        "username=",
        "csrf_token=",
        "unsubscribe_token=",
        "id=",
        "item=",
        "page_id=",
        "month=",
        "immagine=",
        "list_type=",
        "url=",
        "terms=",
        "categoryid=",
        "key=",
        "l=",
        "begindate=",
        "enddate=",
        "searchterm=",
        "title=",
        "message=",
        "comment=",
        "description=",
        "text=",
        "html=",
        "data=",
        "input=",
        "output=",
        "content=",
    ],
    "sqli": [
        "id=",
        "select=",
        "report=",
        "role=",
        "update=",
        "query=",
        "user=",
        "name=",
        "sort=",
        "where=",
        "search=",
        "params=",
        "process=",
        "row=",
        "view=",
        "table=",
        "from=",
        "sel=",
        "results=",
        "sleep=",
        "fetch=",
        "order=",
        "keyword=",
        "column=",
        "field=",
        "delete=",
        "string=",
        "number=",
        "filter=",
        "category=",
        "limit=",
        "offset=",
        "group=",
        "having=",
        "union=",
        "distinct=",
        "count=",
        "sum=",
        "avg=",
        "max=",
        "min=",
    ],
    "lfi": [
        "\\.\\.\\/",
        "\\.\\.\\\\",
        "\\/etc\\/passwd",
        "\\/etc\\/hosts",
        "\\/proc\\/self\\/environ",
        "\\/proc\\/version",
        "\\/windows\\/win\\.ini",
        "\\/boot\\.ini",
        "file:\\/\\/",
        "php:\\/\\/filter",
        "file=",
        "document=",
        "folder=",
        "root=",
        "path=",
        "pg=",
        "style=",
        "pdf=",
        "template=",
        "php_path=",
        "doc=",
        "page=",
        "name=",
        "cat=",
        "dir=",
        "action=",
        "board=",
        "date=",
        "detail=",
        "download=",
        "prefix=",
        "include=",
        "inc=",
        "locate=",
        "show=",
        "site=",
        "type=",
        "view=",
        "content=",
        "layout=",
        "mod=",
        "conf=",
        "url=",
        "lang=",
        "language=",
        "img=",
        "image=",
        "load=",
        "resource=",
        "src=",
        "source=",
    ],
    "ssrf": [
        "url\\=",
        "path\\=",
        "dest\\=",
        "redirect\\=",
        "uri\\=",
        "next\\=",
        "continue\\=",
        "link\\=",
        "file\\=",
        "document\\=",
        "feed\\=",
        "host\\=",
        "port\\=",
        "callback\\=",
        "api\\=",
        "webhook\\=",
        "proxy\\=",
        "fetch\\=",
        "stock\\=",  # Added for stockApi detection
        "remote\\=",
        "target\\=",
        "source\\=",
        "admin",
        "internal",
        "localhost",
        "127\\.0\\.0\\.1",
        "access=",
        "admin=",
        "dbg=",
        "debug=",
        "edit=",
        "grant=",
        "test=",
        "alter=",
        "clone=",
        "create=",
        "delete=",
        "disable=",
        "enable=",
        "exec=",
        "execute=",
        "load=",
        "make=",
        "modify=",
        "rename=",
        "reset=",
        "shell=",
        "toggle=",
        "adm=",
        "root=",
        "cfg=",
        "dest=",
        "redirect=",
        "uri=",
        "path=",
        "continue=",
        "url=",
        "window=",
        "next=",
        "data=",
        "reference=",
        "site=",
        "html=",
        "val=",
        "validate=",
        "domain=",
        "callback=",
        "return=",
        "page=",
        "feed=",
        "host=",
        "port=",
        "to=",
        "out=",
        "view=",
        "dir=",
        "show=",
        "navigation=",
        "open=",
        "file=",
        "document=",
        "folder=",
        "pg=",
        "php_path=",
        "style=",
        "doc=",
        "img=",
        "filename=",
        "target=",
        "proxy=",
        "server=",
        "endpoint=",
        "service=",
        "api_url=",
        "fetch=",
    ],
    "idor": [
        "id\\=",
        "user\\=",
        "account\\=",
        "customer\\=",
        "client\\=",
        "profile\\=",
        "order\\=",
        "invoice\\=",
        "document\\=",
        "file\\=",
        "uid\\=",
        "uuid\\=",
        "guid\\=",
        "id=",
        "user=",
        "account=",
        "number=",
        "order=",
        "no=",
        "doc=",
        "key=",
        "email=",
        "group=",
        "profile=",
        "edit=",
        "report=",
        "userid=",
        "username=",
        "user_id=",
        "account_id=",
        "customer_id=",
        "member=",
        "member_id=",
        "object_id=",
        "resource_id=",
    ],
    "ssti": [
        "template=",
        "preview=",
        "id=",
        "view=",
        "activity=",
        "name=",
        "content=",
        "redirect=",
        "render=",
        "layout=",
        "theme=",
        "format=",
        "output=",
    ],
    "rce": [
        "cmd\\=",
        "command\\=",
        "exec\\=",
        "execute\\=",
        "ping\\=",
        "nslookup\\=",
        "whoami\\=",
        "ls\\=",
        "dir\\=",
        "cat\\=",
        "type\\=",
        "ps\\=",
        "kill\\=",
        "rm\\=",
        "del\\=",
        "daemon=",
        "upload=",
        "dir=",
        "download=",
        "log=",
        "ip=",
        "cli=",
        "cmd=",
        "exec=",
        "command=",
        "execute=",
        "ping=",
        "query=",
        "jump=",
        "code=",
        "reg=",
        "do=",
        "func=",
        "arg=",
        "option=",
        "load=",
        "process=",
        "step=",
        "read=",
        "function",
        "req=",
        "feature=",
        "exe=",
        "module=",
        "payload=",
        "run=",
        "print=",
        "email=",
        "system=",
        "shell=",
        "script=",
    ],
    "upload": [
        "upload\\=",
        "file\\=",
        "attachment\\=",
        "image\\=",
        "picture\\=",
        "photo\\=",
        "document\\=",
        "fileupload\\=",
        "uploadfile\\=",
        "multipart\\/form-data",
        "avatar=",
        "logo=",
        "import=",
        "backup=",
        "restore=",
    ],
    "oauth": [
        "client_id=",
        "client_secret=",
        "redirect_uri=",
        "code=",
        "grant_type=",
        "access_token=",
        "refresh_token=",
        "state=",
        "scope=",
        "response_type=",
        "nonce=",
    ],
    "open_redirect": [
        "return=",
        "returnTo=",
        "redirect=",
        "redirect_uri=",
        "next=",
        "continue=",
        "url=",
        "target=",
        "rurl=",
        "destination=",
        "forward=",
        "goto=",
        "out=",
        "view=",
        "to=",
        "link=",
        "checkout_url=",
        "success_url=",
        "failure_url=",
        "callback_url=",
    ],
    "xxe": [
        "xml=",
        "data=",
        "body=",
        "content=",
        "request=",
        "DOCTYPE",
        "ENTITY",
        "SYSTEM",
        "PUBLIC",
    ],
    "sensitive": [
        "password=",
        "passwd=",
        "pwd=",
        "secret=",
        "token=",
        "key=",
        "auth=",
        "credential=",
        "private=",
        "api_key=",
        "apikey=",
        "access_token=",
        "session=",
        "sess=",
        "sessionid=",
        "auth_token=",
        "bearer=",
        "private_key=",
        "priv_key=",
        "encryption_key=",
        "decrypt=",
        "encrypt=",
    ],
    "jwt": [
        "eyJhbGciOiJ",
        "eyJ0eXAiOiJ",
        "eyJraWQiOiJ",
        "\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+",
        "jwt=",
        "token=",
        "authorization.*bearer",
        "auth_token=",
        "id_token=",
    ],
    "crlf": ["%0d", "%0a", "\\r", "\\n", "%0D%0A", "\\r\\n"],
    "nosql": [
        "[$ne]=",
        "[$gt]=",
        "[$lt]=",
        "[$regex]=",
        "[$where]=",
        "[$eq]=",
        "[$in]=",
        "[$nin]=",
        "query=",
        "filter=",
    ],
    "prototype_pollution": [
        "__proto__",
        "constructor",
        "prototype",
        "constructor[prototype]",
    ],
}

SENSITIVE_ENDPOINTS = [
    "admin",
    "login",
    "auth",
    "secure",
    "dashboard",
    "panel",
    "console",
    "api/v",
    "internal",
    "debug",
    "test",
    "dev",
    "development",
    "staging",
    "backup",
    "config",
    "settings",
    "account",
    "user",
    "profile",
    "private",
    "secret",
    "key",
    "token",
    "oauth",
    "sso",
    "saml",
    "payment",
    "billing",
    "transaction",
    "order",
    "invoice",
    "upload",
    "download",
    "export",
    "import",
]

API_ENDPOINTS = [
    "/api/",
    "/graphql",
    "/rest/",
    "/v1/",
    "/v2/",
    "/v3/",
    "/v4/",
    "/jsonrpc",
    "/soap/",
    "/wsdl",
    "/swagger",
    "/openapi",
    "/api-docs",
    "/docs/api",
    "/.well-known/",
]

SENSITIVE_METHODS = ["PUT", "DELETE", "PATCH", "TRACE", "CONNECT", "OPTIONS"]

COMMON_REQUEST_HEADERS = {
    "host",
    "user-agent",
    "accept",
    "accept-encoding",
    "accept-language",
    "accept-charset",
    "connection",
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "cookie",
    "date",
    "expect",
    "from",
    "referer",
    "origin",
    "cache-control",
    "pragma",
    "if-modified-since",
    "if-none-match",
    "if-match",
    "if-range",
    "if-unmodified-since",
    "authorization",
    "proxy-authorization",
    "range",
    "if-range",
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-proto",
    "x-forwarded-host",
    "x-real-ip",
    "via",
    "proxy-connection",
    "access-control-request-method",
    "access-control-request-headers",
    "upgrade-insecure-requests",
    "dnt",
    "sec-fetch-site",
    "sec-fetch-mode",
    "sec-fetch-user",
    "sec-fetch-dest",
    "sec-fetch-storage-access",
    "sec-ch-ua",
    "sec-ch-ua-mobile",
    "sec-ch-ua-platform",
    "sec-ch-ua-arch",
    "sec-ch-ua-bitness",
    "sec-ch-ua-full-version",
    "sec-ch-ua-full-version-list",
    "sec-ch-ua-model",
    "sec-ch-ua-platform-version",
    "sec-ch-ua-wow64",
    "sec-ch-prefers-color-scheme",
    "sec-ch-prefers-reduced-motion",
    "sec-ch-prefers-reduced-transparency",
    "sec-ch-viewport-width",
    "device-memory",
    "downlink",
    "ect",
    "rtt",
    "save-data",
    "viewport-width",
    "width",
    "dpr",
    "content-dpr",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "max-forwards",
    "x-requested-with",
    "purpose",
    "early-data",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "x-span-id",
    "traceparent",
    "tracestate",
    "accept-datetime",
    "accept-language",
    "warning",
    "content-md5",
    "x-http-method-override",
    "x-method-override",
    "cloudfront-viewer-country",
    "cf-ray",
    "cf-connecting-ip",
    "cf-ipcountry",
    "x-akamai-edgescape",
    "akamai-origin-hop",
    "true-client-ip",
    "x-requested-with",
    "x-csrf-token",
    "x-xsrf-token",
    "x-csrftoken",
    "priority",
    "importance",
}

COMMON_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "content-encoding",
    "content-language",
    "content-location",
    "content-range",
    "content-disposition",
    "content-md5",
    "server",
    "date",
    "location",
    "connection",
    "cache-control",
    "pragma",
    "expires",
    "last-modified",
    "etag",
    "age",
    "vary",
    "accept-ranges",
    "set-cookie",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-max-age",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "permissions-policy-report-only",
    "cross-origin-embedder-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "expect-ct",
    "feature-policy",
    "www-authenticate",
    "proxy-authenticate",
    "retry-after",
    "refresh",
    "transfer-encoding",
    "trailer",
    "upgrade",
    "via",
    "alt-svc",
    "accept-ranges",
    "content-range",
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "report-to",
    "nel",
    "timing-allow-origin",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "cf-ray",
    "cf-cache-status",
    "x-cache",
    "x-cache-hits",
    "x-served-by",
    "x-timer",
    "x-amz-cf-pop",
    "x-amz-cf-id",
    "x-edge-location",
    "x-akamai-request-id",
    "x-cdn",
    "x-varnish",
    "link",
    "digest",
    "want-digest",
    "deprecation",
    "sunset",
    "warning",
    "accept-patch",
    "accept-post",
    "allow",
    "public-key-pins",
    "status",
    "x-ua-compatible",
    "x-webkit-csp",
    "x-content-security-policy",
    "x-dns-prefetch-control",
    "x-download-options",
    "x-permitted-cross-domain-policies",
    "clear-site-data",
    "sourcemap",
    "x-sourcemap",
    "tk",
    "p3p",
    "delta-base",
    "im",
    "x-content-duration",
}

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

DOM_XSS_PAYLOADS = {
    "document.write": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        '"><script>alert(document.domain)</script>',
        "<body onload=alert(1)>",
    ],
    "document.writeln": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "innerHTML": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe src=javascript:alert(1)>",
    ],
    "outerHTML": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "insertAdjacentHTML": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "eval": [
        "alert(1)",
        "alert(document.domain)",
        "alert(document.cookie)",
    ],
    "Function constructor": [
        "alert(1)",
        "alert(document.domain)",
    ],
    "setTimeout": [
        "alert(1)",
    ],
    "setInterval": [
        "alert(1)",
    ],
    "jQuery.html()": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        '"><script>alert(1)</script>',
    ],
    "jQuery.append()": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
    "jQuery.prepend()": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
    ],
}


# ============================================================================
# CLASS: UTILITIES - General helper functions
# ============================================================================


class Utilities:
    """Helper utilities for JSON parsing and manipulation"""
    
    @staticmethod
    def safe_json_loads(text):
        """Safely parse JSON text, return None on failure"""
        if not text:
            return None
        try:
            return json.loads(text)
        except Exception:
            return None
    
    @staticmethod
    def walk_json(obj, path=""):
        """Recursively walk JSON object yielding (path, value) tuples"""
        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                if isinstance(value, (dict, list)):
                    yield from Utilities.walk_json(value, new_path)
                else:
                    yield (new_path, value)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                new_path = f"{path}[{idx}]"
                if isinstance(item, (dict, list)):
                    yield from Utilities.walk_json(item, new_path)
                else:
                    yield (new_path, item)
    
    @staticmethod
    def json_contains_value(obj, search_value):
        """Check if a JSON object contains a specific value"""
        if obj == search_value:
            return True
        if isinstance(obj, dict):
            return any(Utilities.json_contains_value(v, search_value) for v in obj.values())
        elif isinstance(obj, list):
            return any(Utilities.json_contains_value(item, search_value) for item in obj)
        return False


# ============================================================================
# ANALYZER CLASSES (Moved from hunt_script.py)
# ============================================================================

class ParameterDetector:
    """Handles parameter detection, pattern matching, and vulnerability classification"""

    @staticmethod
    def detect_param_patterns(param_name, param_value, source):
        detected = set()

        if source.startswith("HTML"):
            html_detected = ParameterDetector.detect_html_parameter_patterns(
                param_name, source
            )
            detected.update(html_detected)

        # Check if parameter value contains a URL (potential SSRF)
        if param_value:
            value_str = str(param_value)
            # URL patterns (including URL-encoded)
            url_patterns = [
                r'https?://',  # http:// or https://
                r'http%3A%2F%2F',  # URL-encoded http://
                r'https%3A%2F%2F',  # URL-encoded https://
                r'file://',
                r'ftp://',
                r'gopher://',
            ]
            for url_pat in url_patterns:
                if re.search(url_pat, value_str, re.IGNORECASE):
                    detected.add("SSRF")
                    detected.add("HIGH")
                    break
        
        for vuln_type, patterns in GF_PATTERNS.items():
            for pat in patterns:
                small = pat.rstrip("=").replace("\\", "").lower()
                if small == "":
                    continue
                if small in (param_name or "").lower() or (
                    param_value and small in str(param_value).lower()
                ):
                    detected.add(vuln_type.upper())
                    break

        return detected

    @staticmethod
    def detect_html_parameter_patterns(
        param_name: str, context: str = "HTML"
    ) -> Set[str]:
        """Detect specific patterns for HTML-discovered parameters"""
        detected = set()

        html_param_patterns = {
            "category": ["XSS", "SQLI", "IDOR", "LFI"],
            "filter": ["XSS", "SQLI", "LFI", "SSRF"],
            "sort": ["XSS", "SQLI", "RCE"],
            "page": ["XSS", "SQLI", "LFI"],
            "limit": ["XSS", "SQLI"],
            "offset": ["XSS", "SQLI"],
            "search": ["XSS", "SQLI", "RCE"],
            "q": ["XSS", "SQLI", "RCE"],
            "id": ["XSS", "SQLI", "IDOR"],
            "user": ["XSS", "SQLI", "IDOR"],
            "order": ["XSS", "SQLI", "IDOR"],
            "file": ["XSS", "LFI", "RCE"],
            "path": ["XSS", "LFI", "RCE"],
            "template": ["XSS", "SSTI", "LFI"],
            "view": ["XSS", "LFI", "RCE"],
            "action": ["XSS", "RCE", "SSRF"],
            "redirect": ["XSS", "OPEN_REDIRECT", "SSRF"],
            "url": ["XSS", "OPEN_REDIRECT", "SSRF"],
            "callback": ["XSS", "JSONP", "SSRF"],
            "jsonp": ["XSS", "JSONP", "SSRF"],
            "upload": ["UPLOAD", "RCE"],
            "download": ["LFI", "RCE"],
            "export": ["LFI", "RCE", "SSRF"],
            "import": ["UPLOAD", "RCE"],
        }

        param_lower = param_name.lower()

        for pattern, vulns in html_param_patterns.items():
            if param_lower == pattern:
                detected.update(vulns)
                break

        for pattern, vulns in html_param_patterns.items():
            if pattern in param_lower:
                detected.update(vulns)

        return detected

    @staticmethod
    def detect_interesting_params(url_params, body_params):
        """Detect interesting parameter names"""
        findings = []
        interesting = {
            "debug": "DEBUG_PARAM",
            "test": "TEST_PARAM",
            "admin": "ADMIN_PARAM",
            "internal": "INTERNAL_PARAM",
            "dev": "DEV_PARAM",
            "staging": "STAGING_PARAM",
            "role": "ROLE_PARAM",
            "privilege": "PRIVILEGE_PARAM",
            "permission": "PERMISSION_PARAM",
        }

        all_params = list(url_params.keys()) + list(body_params.keys())
        for param in all_params:
            param_lower = param.lower()
            for keyword, finding in interesting.items():
                if keyword in param_lower and finding not in findings:
                    findings.append(finding)

        return findings

    @staticmethod
    def detect_parameters_in_html(content: str, url: str) -> Dict[str, Set[str]]:
        """Detect parameter patterns in HTML source code"""
        findings = {}

        if not content:
            return findings

        try:
            soup = BeautifulSoup(content, "html.parser")

            # 1. Find all href attributes with query strings
            for tag in soup.find_all(True):
                href = tag.get("href", "")
                if href and "?" in href:
                    query_part = href.split("?", 1)[1].split("#")[0]
                    params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                    for param_name, param_value in params:
                        if param_name:
                            detected = ParameterDetector.detect_param_patterns(
                                param_name, param_value, "HTML_HREF"
                            )
                            if detected:
                                # Add the source href as context
                                detected.add(f"SOURCE:{href}")
                                key = f"HTML_HREF {param_name}"
                                findings.setdefault(key, set()).update(detected)

                # 2. Check form action attributes
                action = tag.get("action", "")
                if action and "?" in action:
                    query_part = action.split("?", 1)[1].split("#")[0]
                    params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                    for param_name, param_value in params:
                        if param_name:
                            detected = ParameterDetector.detect_param_patterns(
                                param_name, param_value, "HTML_FORM_ACTION"
                            )
                            if detected:
                                # Add the source action as context
                                detected.add(f"ACTION:{action}")
                                key = f"HTML_FORM {param_name}"
                                findings.setdefault(key, set()).update(detected)

                # 3. Check src attributes
                src = tag.get("src", "")
                if src and "?" in src:
                    query_part = src.split("?", 1)[1].split("#")[0]
                    params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                    for param_name, param_value in params:
                        if param_name:
                            detected = ParameterDetector.detect_param_patterns(
                                param_name, param_value, "HTML_SRC"
                            )
                            if detected:
                                # Add the source src as context
                                detected.add(f"SRC:{src}")
                                key = f"HTML_SRC {param_name}"
                                findings.setdefault(key, set()).update(detected)

                # 4. Check data-* attributes
                for attr_name, attr_value in tag.attrs.items():
                    if attr_name.startswith("data-") and isinstance(attr_value, str):
                        if "?" in attr_value:
                            query_part = attr_value.split("?", 1)[1].split("#")[0]
                            params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                            for param_name, param_value in params:
                                if param_name:
                                    detected = ParameterDetector.detect_param_patterns(
                                        param_name, param_value, "HTML_DATA_ATTR"
                                    )
                                    if detected:
                                        # Add the data attribute context
                                        detected.add(f"ATTR:{attr_name}={attr_value[:100]}")
                                        key = f"HTML_DATA {param_name}"
                                        findings.setdefault(key, set()).update(detected)

            # 5. Find JavaScript event handlers
            for tag in soup.find_all(True):
                for attr_name, attr_value in tag.attrs.items():
                    if attr_name.startswith("on") and isinstance(attr_value, str):
                        url_patterns = re.findall(
                            r'["\'](https?://[^"\']*\?[^"\']*)["\']', attr_value
                        )

                        for url_with_params in url_patterns:
                            if "?" in url_with_params:
                                query_part = url_with_params.split("?", 1)[1].split(
                                    "#"
                                )[0]
                                params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                                for param_name, param_value in params:
                                    if param_name:
                                        detected = (
                                            ParameterDetector.detect_param_patterns(
                                                param_name,
                                                param_value,
                                                "HTML_EVENT_HANDLER",
                                            )
                                        )
                                        if detected:
                                            key = f"HTML_EVENT {param_name}"
                                            findings.setdefault(key, set()).update(
                                                detected
                                            )

                        # 5a. Detect URL parameters extracted via regex/URLSearchParams
                        # from `location` — these are invisible to the URL-string-only check above.
                        #
                        # Covers patterns like:
                        #   /url=(https?:\/\/.+)/.exec(location)          → param: url
                        #   location.search.match(/next=/)                → param: next
                        #   new URLSearchParams(location.search).get('r') → param: r
                        #   location.search.split('redirect=')[1]         → param: redirect
                        #   location.href.indexOf('token=')               → param: token

                        _regex_param_patterns = [
                            # /paramname=(...)/.exec(location)  or  /paramname=/.exec(location)
                            r'/(\w[\w.-]*)\s*=.*?/[gim]*\.exec\s*\(\s*(?:window\.)?location',
                            # location[.search/.href/.hash].match(/paramname=/)
                            r'(?:window\.)?location(?:\.(?:search|href|hash))?\s*\.match\s*\(\s*/(\w+)\s*=',
                            # new RegExp("paramname=") / new RegExp('paramname=')
                            r'new\s+RegExp\s*\(\s*["\'](\w[\w.-]*)\s*[="\']',
                            # URLSearchParams(...).get('paramname')
                            r'URLSearchParams\s*\([^)]*\)\s*\.get\s*\(\s*["\'](\w+)["\']',
                            # location.search.split('paramname=')
                            r'(?:location\.(?:search|href|hash))\s*\.split\s*\(\s*["\'](\w+)=["\']',
                            # location.href.indexOf('paramname=') / location.search.indexOf('paramname=')
                            r'(?:location\.(?:search|href|hash))\s*\.indexOf\s*\(\s*["\'](\w+)=["\']',
                        ]

                        # Check whether there is a redirect sink in this handler
                        _has_redirect_sink = bool(re.search(
                            r'(?:window\.)?location(?:\.href)?\s*='
                            r'|(?:window\.)?location\.(?:assign|replace)\s*\(',
                            attr_value,
                            re.IGNORECASE,
                        ))

                        for _rpat in _regex_param_patterns:
                            for _m in re.finditer(_rpat, attr_value, re.IGNORECASE):
                                _param_name = _m.group(1)
                                if not _param_name or len(_param_name) < 2:
                                    continue
                                _detected = ParameterDetector.detect_param_patterns(
                                    _param_name, "", "HTML_EVENT_HANDLER"
                                )
                                # A URL param read from location + redirect sink = open redirect
                                _detected.add("OPEN_REDIRECT")
                                _detected.add("SSRF")
                                _detected.add("HIGH")
                                if _has_redirect_sink:
                                    _detected.add("DOM_OPEN_REDIRECT")
                                    _detected.add("URL_REDIRECT_SINK")
                                key = f"HTML_EVENT {_param_name}"
                                findings.setdefault(key, set()).update(_detected)

            # 6. Find meta tags with URL content
            for meta in soup.find_all("meta"):
                content = meta.get("content", "")
                if content and "?" in content:
                    query_part = content.split("?", 1)[1].split("#")[0]
                    params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                    for param_name, param_value in params:
                        if param_name:
                            detected = ParameterDetector.detect_param_patterns(
                                param_name, param_value, "HTML_META"
                            )
                            if detected:
                                # Add meta tag context
                                detected.add(f"META:{content[:100]}")
                                key = f"HTML_META {param_name}"
                                findings.setdefault(key, set()).update(detected)

            # 7. Find links in JavaScript strings
            script_tags = soup.find_all("script", string=True)
            for script in script_tags:
                script_content = script.string
                if script_content:
                    url_patterns = re.findall(
                        r'["\'](/\w[^"\']*\?[^"\']*)["\']', script_content
                    )
                    url_patterns += re.findall(
                        r'["\'](https?://[^"\']*\?[^"\']*)["\']', script_content
                    )

                    for url_with_params in url_patterns:
                        if "?" in url_with_params:
                            query_part = url_with_params.split("?", 1)[1].split("#")[0]
                            params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                            for param_name, param_value in params:
                                if param_name:
                                    detected = ParameterDetector.detect_param_patterns(
                                        param_name, param_value, "HTML_JS_STRING"
                                    )
                                    if detected:
                                        key = f"HTML_JS_STR {param_name}"
                                        findings.setdefault(key, set()).update(detected)

            # 7a. Detect URL parameters extracted via regex/URLSearchParams in inline <script>s.
            #
            # Handles patterns like:
            #   /paramname=(https?:\/\/.+)/.exec(location)
            #   location.search.match(/redirect=/)
            #   new URLSearchParams(location.search).get('next')
            #   location.href.split('token=')[1]

            _script_regex_param_pats = [
                r'/(\w[\w.-]*)\s*=.*?/[gim]*\.exec\s*\(\s*(?:window\.)?location',
                r'(?:window\.)?location(?:\.(?:search|href|hash))?\s*\.match\s*\(\s*/(\w+)\s*=',
                r'new\s+RegExp\s*\(\s*["\'](\w[\w.-]*)\s*[="\']',
                r'URLSearchParams\s*\([^)]*\)\s*\.get\s*\(\s*["\'](\w+)["\']',
                r'(?:location\.(?:search|href|hash))\s*\.split\s*\(\s*["\'](\w+)=["\']',
                r'(?:location\.(?:search|href|hash))\s*\.indexOf\s*\(\s*["\'](\w+)=["\']',
            ]

            for script in script_tags:
                script_content = script.string
                if not script_content:
                    continue

                _script_has_redirect_sink = bool(re.search(
                    r'(?:window\.)?location(?:\.href)?\s*='
                    r'|(?:window\.)?location\.(?:assign|replace)\s*\(',
                    script_content,
                    re.IGNORECASE,
                ))

                for _rpat in _script_regex_param_pats:
                    for _m in re.finditer(_rpat, script_content, re.IGNORECASE):
                        _param_name = _m.group(1)
                        if not _param_name or len(_param_name) < 2:
                            continue
                        _detected = ParameterDetector.detect_param_patterns(
                            _param_name, "", "HTML_JS_STRING"
                        )
                        _detected.add("OPEN_REDIRECT")
                        _detected.add("SSRF")
                        _detected.add("HIGH")
                        if _script_has_redirect_sink:
                            _detected.add("DOM_OPEN_REDIRECT")
                            _detected.add("URL_REDIRECT_SINK")
                        key = f"HTML_JS_STR {_param_name}"
                        findings.setdefault(key, set()).update(_detected)

            # 8. Find AJAX/fetch URLs
            ajax_patterns = [
                r'fetch\s*\(\s*["\']([^"\']*\?[^"\']+)["\']',
                r'\.ajax\s*\(\s*\{\s*["\']url["\']\s*:\s*["\']([^"\']*\?[^"\']+)["\']',
                r'axios\.(?:get|post|put|delete)\s*\(\s*["\']([^"\']*\?[^"\']+)["\']',
                r'XMLHttpRequest\s*\(\)[^;]*\.open\s*\([^,]+,\s*["\']([^"\']*\?[^"\']+)["\']',
            ]

            for script in script_tags:
                script_content = script.string
                if script_content:
                    for pattern in ajax_patterns:
                        matches = re.findall(
                            pattern, script_content, re.IGNORECASE | re.DOTALL
                        )
                        for url_with_params in matches:
                            if "?" in url_with_params:
                                query_part = url_with_params.split("?", 1)[1].split(
                                    "#"
                                )[0]
                                params = re.findall(r"([^=&]+)=([^&]*)", query_part)

                                for param_name, param_value in params:
                                    if param_name:
                                        detected = (
                                            ParameterDetector.detect_param_patterns(
                                                param_name, param_value, "HTML_AJAX"
                                            )
                                        )
                                        if detected:
                                            key = f"HTML_AJAX {param_name}"
                                            findings.setdefault(key, set()).update(
                                                detected
                                            )

            # ==============================================
            # NEW: Detect JavaScript variable assignments
            # ==============================================

            # Pattern for JavaScript variable assignments
            # Use [^\'"]*  (0-or-more) so empty strings like var x = '' are matched too
            js_var_patterns = [
                # var c1 = 'value1';  or  var c1 = '';
                r'(?:var|let|const)\s+(\w+)\s*=\s*[\'"]([^\'"]*)[\'"];?',
                # c1 = 'value1';  or  c1 = '';
                r'(\w+)\s*=\s*[\'"]([^\'"]*)[\'"];?',
                # Object properties: obj.c1 = 'value1'  or  obj.c1 = ''
                r'\w+\.(\w+)\s*=\s*[\'"]([^\'"]*)[\'"];?',
                # Array assignments: arr[0] = 'value1'  or  arr[0] = ''
                r'\w+\[[^\]]+\]\s*=\s*[\'"]([^\'"]*)[\'"];?',
            ]

            # Pattern for boolean/numeric JS variable assignments (no quotes)
            # e.g. var isAdmin = false; let count = 0; const debug = true;
            js_bool_pattern = r'(?:var|let|const)\s+(\w+)\s*=\s*(true|false|null|undefined|\d+)\s*;?'

            for script in soup.find_all("script", string=True):
                script_content = script.string
                if script_content:
                    for pattern in js_var_patterns:
                        matches = re.findall(pattern, script_content, re.IGNORECASE)
                        for var_name, var_value in matches:
                            # Always process — even empty-value vars (var x = '') are
                            # injectable parameters; name-based GF matching still applies.
                            detected = ParameterDetector.detect_param_patterns(
                                var_name, var_value, "HTML_JS_VAR"
                            )
                            key = f"HTML_JS_VAR {var_name}"
                            if detected:
                                findings.setdefault(key, set()).update(detected)
                            else:
                                # Register with a bare marker so empty-value vars still
                                # appear in the parameter table.
                                findings.setdefault(key, set()).add("INLINE_JS_VAR")

                    # Extract boolean/numeric variables separately
                    bool_matches = re.findall(js_bool_pattern, script_content, re.IGNORECASE)
                    for var_name, var_value in bool_matches:
                        key = f"HTML_JS_BOOL {var_name}"
                        findings.setdefault(key, set()).add(
                            f"JS_BOOL:{var_name}={var_value}"
                        )
                        # Flag boolean false as potentially security-relevant (e.g. isAdmin=false)
                        security_keywords = [
                            "admin", "auth", "debug", "isadmin", "isauth", "isloggedin",
                            "isstaff", "issuperuser", "ismod", "isModerator", "enabled",
                            "allowed", "verified", "trusted", "privileged", "canEdit",
                            "canDelete", "canUpload", "canAdmin", "hasAccess", "isRoot",
                        ]
                        if any(kw in var_name.lower() for kw in security_keywords):
                            findings.setdefault(key, set()).add(
                                f"SECURITY_RELEVANT_BOOL:{var_name}={var_value}"
                            )
                            # Add a severity tag so the risk column shows MEDIUM
                            findings[key].add("MEDIUM")

            # Also check for variables that look like they could be parameters.
            # Use [^\'"&?=]* (0-or-more) so var company = '' is still captured.
            js_param_like_pattern = (
                r'(?:var|let|const)\s+(\w+)\s*=\s*[\'"]([^\'"&?=]*)[\'"]'
            )

            for script in soup.find_all("script", string=True):
                script_content = script.string
                if script_content:
                    matches = re.findall(
                        js_param_like_pattern, script_content, re.IGNORECASE
                    )
                    for var_name, var_value in matches:
                        # Check if variable name looks like a parameter
                        param_like_names = [
                            "id",
                            "name",
                            "value",
                            "token",
                            "key",
                            "page",
                            "limit",
                            "offset",
                            "search",
                            "query",
                            "sort",
                            "filter",
                        ]

                        if var_name.lower() in param_like_names:
                            detected = ParameterDetector.detect_param_patterns(
                                var_name, var_value, "HTML_JS_PARAM"
                            )
                            key = f"HTML_JS_PARAM {var_name}"
                            if detected:
                                findings.setdefault(key, set()).update(detected)
                            else:
                                findings.setdefault(key, set()).add("INLINE_JS_VAR")

            # ==============================================
            # NEW: Detect function parameters in JS
            # ==============================================

            # Pattern: function calls with string parameters
            js_func_patterns = [
                r'\.get\([\'"](\w+)[\'"]\)',  # .get('param')
                r'\.post\([\'"](\w+)[\'"]\)',  # .post('param')
                r'fetch\([\'"][^\'"]*[\'"],\s*\{[^}]*data:\s*[\'"](\w+)[\'"]',
                r'XMLHttpRequest[^;]*\.send\([\'"](\w+)[\'"]\)',
            ]

            for script in soup.find_all("script", string=True):
                script_content = script.string
                if script_content:
                    for pattern in js_func_patterns:
                        matches = re.findall(pattern, script_content, re.IGNORECASE)
                        for param_value in matches:
                            if param_value and len(param_value) > 2:
                                # Try to infer parameter name from context
                                detected = ParameterDetector.detect_param_patterns(
                                    "js_func_param", param_value, "HTML_JS_FUNC"
                                )
                                if detected:
                                    key = f"HTML_JS_FUNC {param_value}"
                                    findings.setdefault(key, set()).update(detected)

            return findings

        except Exception as e:
            logger.error(f"Error in HTML parameter detection: {e}")
            return findings

    @staticmethod
    def detect_html_forms_and_inputs(content: str, url: str) -> Dict[str, Set[str]]:
        """
        Comprehensive detection of HTML forms and input fields
        
        Detects:
        - Complete forms with all fields
        - Standalone inputs (outside forms)
        - Hidden inputs (marked with HIDDEN)
        - Input types and attributes
        """
        findings = {}
        
        if not content:
            return findings
        
        try:
            soup = BeautifulSoup(content, "html.parser")
            
            # PHASE 1: DETECT ALL FORMS
            forms = soup.find_all('form')
            
            for form_idx, form in enumerate(forms):
                form_action = form.get('action', '')
                form_method = form.get('method', 'GET').upper()
                form_id = form.get('id', f'form_{form_idx}')
                form_name = form.get('name', form_id)
                
                inputs = form.find_all(['input', 'textarea', 'select'])
                
                for input_tag in inputs:
                    field_name = input_tag.get('name', '')
                    if not field_name:
                        field_name = input_tag.get('id', '')
                    
                    if not field_name:
                        continue
                    
                    input_type = input_tag.get('type', 'text').lower()
                    input_value = input_tag.get('value', '')
                    is_required = input_tag.has_attr('required')
                    
                    detected = ParameterDetector.detect_param_patterns(
                        field_name, input_value, "HTML_FORM"
                    )
                    
                    detected.add(f"FORM:{form_name}")
                    detected.add(f"METHOD:{form_method}")
                    detected.add(f"TYPE:{input_type}")
                    
                    # Mark hidden inputs
                    if input_type == 'hidden':
                        detected.add("HIDDEN")
                    
                    if is_required:
                        detected.add("REQUIRED")
                    
                    # Special field types
                    if input_type == 'password':
                        detected.add("PASSWORD_FIELD")
                    elif input_type == 'email':
                        detected.add("EMAIL_FIELD")
                    elif input_type == 'file':
                        detected.add("FILE_UPLOAD")
                    
                    # CSRF detection
                    if any(csrf in field_name.lower() for csrf in ['csrf', 'token', '_token', 'xsrf']):
                        detected.add("CSRF_TOKEN")
                        if input_type == 'hidden':
                            detected.add("CSRF_HIDDEN")
                    
                    key = f"HTML_FORM {field_name}"
                    findings.setdefault(key, set()).update(detected)
            
            # PHASE 2: DETECT STANDALONE INPUTS (not in forms)
            all_inputs = soup.find_all(['input', 'textarea', 'select'])
            
            for input_tag in all_inputs:
                if input_tag.find_parent('form'):
                    continue  # Skip - already in form
                
                field_name = input_tag.get('name', '')
                if not field_name:
                    field_name = input_tag.get('id', '')
                
                if not field_name:
                    continue
                
                input_type = input_tag.get('type', 'text').lower()
                input_value = input_tag.get('value', '')
                
                detected = ParameterDetector.detect_param_patterns(
                    field_name, input_value, "HTML_INPUT"
                )
                
                detected.add("STANDALONE")
                detected.add(f"TYPE:{input_type}")
                
                # Mark hidden inputs
                if input_type == 'hidden':
                    detected.add("HIDDEN")
                
                if input_type == 'password':
                    detected.add("PASSWORD_FIELD")
                elif input_type == 'email':
                    detected.add("EMAIL_FIELD")
                
                # CSRF detection
                if any(csrf in field_name.lower() for csrf in ['csrf', 'token', '_token', 'xsrf']):
                    detected.add("CSRF_TOKEN")
                    if input_type == 'hidden':
                        detected.add("CSRF_HIDDEN")
                
                key = f"HTML_INPUT {field_name}"
                findings.setdefault(key, set()).update(detected)
        
        except Exception as e:
            logger.error(f"Error detecting HTML forms/inputs: {e}")
        
        return findings


class DOMAnalyzer:
    """Handles all DOM structure analysis, HTML parsing, and DOM-based XSS detection"""

    @staticmethod
    def extract_javascript_sources(html_content, url):
        """Extract JavaScript sources from HTML content"""
        js_sources = []

        if not html_content:
            return js_sources

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Find inline scripts
            inline_scripts = soup.find_all("script", string=True)
            for script in inline_scripts:
                if script.string and len(script.string.strip()) > 10:
                    js_sources.append(
                        {
                            "type": "inline",
                            "content": script.string.strip(),
                            "url": url,
                            "line": Utilities.get_approximate_line(
                                html_content, script.string
                            ) if hasattr(globals().get('Utilities'), 'get_approximate_line') else 0,
                        }
                    )

            # Find external script tags
            external_scripts = soup.find_all("script", src=True)
            for script in external_scripts:
                src = script.get("src", "")
                if src:
                    js_sources.append({"type": "external", "src": src, "url": url})

            # Find event handlers
            event_handlers = []
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if attr.startswith("on") and tag[attr]:
                        event_handlers.append(
                            {
                                "tag": tag.name,
                                "event": attr,
                                "handler": tag[attr],
                                "url": url,
                            }
                        )

            # Find JavaScript in href attributes
            javascript_links = soup.find_all(href=re.compile(r"^javascript:"))
            for link in javascript_links:
                href = link.get("href", "")
                if href.startswith("javascript:"):
                    js_sources.append(
                        {
                            "type": "href",
                            "content": href[11:],
                            "url": url,
                            "tag": link.name,
                        }
                    )

            return js_sources
        except Exception as e:
            return js_sources

    @staticmethod
    def analyze_dom_structure(html_content, url):
        """Analyze DOM structure for input fields, forms, and dynamic content"""
        findings = []

        if not html_content:
            return findings

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            # Find all forms and their parameters
            forms = soup.find_all("form")
            for form in forms:
                form_action = form.get("action", "")
                form_method = form.get("method", "GET").upper()

                inputs = form.find_all(["input", "textarea", "select"])
                form_params = []

                for input_elem in inputs:
                    param_name = input_elem.get("name") or input_elem.get("id") or ""
                    if param_name:
                        param_type = input_elem.get("type", "text")
                        form_params.append(
                            {
                                "name": param_name,
                                "type": param_type,
                                "tag": input_elem.name,
                            }
                        )

                if form_params:
                    findings.append(
                        {
                            "type": "FORM_PARAMETERS",
                            "action": form_action,
                            "method": form_method,
                            "params": form_params,
                            "form_count": len(form_params),
                        }
                    )

            # Find all input fields outside forms
            all_inputs = soup.find_all(["input", "textarea", "select"])
            standalone_inputs = []

            for input_elem in all_inputs:
                if not input_elem.find_parent("form"):
                    param_name = input_elem.get("name") or input_elem.get("id") or ""
                    if param_name:
                        standalone_inputs.append(
                            {
                                "name": param_name,
                                "type": input_elem.get("type", "text"),
                                "tag": input_elem.name,
                            }
                        )

            if standalone_inputs:
                findings.append(
                    {
                        "type": "STANDALONE_INPUTS",
                        "params": standalone_inputs,
                        "count": len(standalone_inputs),
                    }
                )

            # Find data-* attributes
            data_attrs = []
            for tag in soup.find_all(True):
                for attr_name, attr_value in tag.attrs.items():
                    if attr_name.startswith("data-") and attr_value:
                        data_attrs.append(
                            {
                                "tag": tag.name,
                                "attribute": attr_name,
                                "value": attr_value[:100] if isinstance(attr_value, str) else str(attr_value)[:100],
                            }
                        )

            if data_attrs:
                findings.append(
                    {
                        "type": "DATA_ATTRIBUTES",
                        "attributes": data_attrs[:10],
                        "count": len(data_attrs),
                    }
                )

            # Find JavaScript event handlers
            event_handlers = []
            for tag in soup.find_all(True):
                for attr_name, attr_value in tag.attrs.items():
                    if attr_name.startswith("on") and attr_value:
                        if isinstance(attr_value, str) and re.search(r"\b\w+\b", attr_value):
                            event_handlers.append(
                                {
                                    "tag": tag.name,
                                    "event": attr_name,
                                    "handler": attr_value[:200],
                                }
                            )

            if event_handlers:
                findings.append(
                    {
                        "type": "EVENT_HANDLERS",
                        "handlers": event_handlers[:5],
                        "count": len(event_handlers),
                    }
                )

            # Find meta tags
            meta_tags = []
            for meta in soup.find_all("meta"):
                name = meta.get("name") or meta.get("property") or ""
                content = meta.get("content", "")
                if name and content:
                    meta_tags.append({"name": name, "content": content[:100]})

            if meta_tags:
                findings.append(
                    {"type": "META_TAGS", "tags": meta_tags, "count": len(meta_tags)}
                )

            # Find links with parameters
            param_links = []
            for link in soup.find_all("a", href=True):
                href = link.get("href", "")
                if "?" in href:
                    query_string = href.split("?", 1)[1].split("#")[0]
                    params = re.findall(r"([^=&]+)=([^&]*)", query_string)
                    if params:
                        param_links.append(
                            {
                                "text": link.get_text(strip=True)[:50],
                                "href": href,
                                "params": params,
                            }
                        )

            if param_links:
                findings.append(
                    {
                        "type": "PARAMETERIZED_LINKS",
                        "links": param_links[:5],
                        "count": len(param_links),
                    }
                )

            return findings

        except Exception as e:
            return findings

    @staticmethod
    def detect_dom_xss_patterns(js_findings, dom_findings, html_content):
        """
        Detect potential DOM-based XSS patterns with comprehensive jQuery sink coverage.

        Now detects:
        1. ALL jQuery XSS sinks (add, after, append, animate, etc.)
        2. Variable-based usage: .html(userVar)
        3. Direct usage: .html(location.hash)
        4. Complex patterns: .html('x' + decodeURIComponent(location.hash.slice(1)))
        5. Chained methods: $('#el').find('.x').html(userInput)
        6. jQuery constructor: $(userInput) or $(location.hash)
        7. jQuery.parseHTML() and $.parseHTML()
        8. .attr() with dangerous attributes
        """
        xss_patterns = []

        if not html_content:
            return xss_patterns

        logger.info("⊙ Starting comprehensive jQuery XSS detection...")

        # ========================================
        # PHASE 1: BUILD TAINTED VARIABLES MAP
        # ========================================
        tainted_vars = {}
        extracted_params = set()

        # Extract parameters from js_findings
        for finding in js_findings:
            if finding.get("type") == "PARAM_EXTRACTION":
                param = finding.get("param", "")
                if param:
                    extracted_params.add(param)

        # Extract parameters from dom_findings
        for finding in dom_findings:
            if finding["type"] == "FORM_PARAMETERS":
                for param in finding["params"]:
                    extracted_params.add(param["name"])
            elif finding["type"] == "STANDALONE_INPUTS":
                for param in finding["params"]:
                    extracted_params.add(param["name"])

        # ========================================
        # Track variable assignments from tainted sources
        # ========================================

        taint_source_patterns = [
            # URLSearchParams
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:new\s+)?URLSearchParams\([^)]*\)\.get\s*\(\s*['\"](\w+)['\"]\s*\)",
                "URLSearchParams.get()",
                "param_from_pattern",
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*\([^)]*URLSearchParams[^)]*\)\.get\s*\(\s*['\"](\w+)['\"]\s*\)",
                "URLSearchParams.get()",
                "param_from_pattern",
            ),
            # location.search
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.search",
                "location.search",
                "query_string",
            ),
            # location.hash
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.hash",
                "location.hash",
                "hash",
            ),
            # document.URL
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*document\.(URL|documentURI|baseURI)",
                "document.URL",
                "document_url",
            ),
            # document.referrer
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*document\.referrer",
                "document.referrer",
                "referrer",
            ),
            # location.href
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.href",
                "location.href",
                "href",
            ),
        ]

        for pattern_tuple in taint_source_patterns:
            if len(pattern_tuple) == 3:
                pattern, source_name, param_type = pattern_tuple
                for match in re.finditer(pattern, html_content, re.IGNORECASE):
                    var_name = match.group(1)
                    if param_type == "param_from_pattern" and len(match.groups()) >= 2:
                        param_name = match.group(2)
                    else:
                        param_name = param_type

                    tainted_vars[var_name] = {
                        "source": source_name,
                        "param": param_name,
                        "method": source_name,
                        "line": match.group(0),
                    }

        logger.info(f"   Found {len(tainted_vars)} tainted variables")

        # ========================================
        # PHASE 2: DEFINE ALL DANGEROUS SINKS
        # ========================================

        # Classic DOM sinks
        dangerous_sinks = {
            "document.write": [
                r"document\.write\s*\(\s*[^)]*\b({var})\b[^)]*\)",
                r"document\.write\s*\(\s*[^)]*[+]\s*({var})\s*[+]?[^)]*\)",
            ],
            "document.writeln": [
                r"document\.writeln\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "innerHTML": [
                r"\.innerHTML\s*=\s*[^;]*\b({var})\b[^;]*",
                r"\.innerHTML\s*=\s*[^;]*[+]\s*({var})\s*[+]?[^;]*",
            ],
            "outerHTML": [
                r"\.outerHTML\s*=\s*[^;]*\b({var})\b[^;]*",
            ],
            "insertAdjacentHTML": [
                r"\.insertAdjacentHTML\s*\([^,]*,\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "eval": [
                r"\beval\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "Function": [
                r"new\s+Function\s*\(\s*[^)]*\b({var})\b[^)]*\)",
                r"Function\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "setTimeout": [
                r"setTimeout\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "setInterval": [
                r"setInterval\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
            "execScript": [
                r"execScript\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            ],
        }

        # ========================================
        # + COMPLETE jQuery XSS SINKS
        # ========================================

        # All jQuery methods that can cause XSS
        jquery_xss_methods = [
            "add",
            "after",
            "append",
            "animate",
            "insertAfter",
            "insertBefore",
            "before",
            "html",
            "prepend",
            "replaceAll",
            "replaceWith",
            "wrap",
            "wrapInner",
            "wrapAll",
            "has",
            "constructor",
            "init",
            "index",
        ]

        jquery_sinks = {}

        # Generate patterns for each jQuery method
        for method in jquery_xss_methods:
            jquery_sinks[f"jQuery.{method}()"] = [
                # Pattern 1: $(...).method(variable)
                rf"\$\([^)]+\)\.{method}\s*\(\s*[^)]*\b({{var}})\b[^)]*\)",
                # Pattern 2: jQuery(...).method(variable)
                rf"jQuery\([^)]+\)\.{method}\s*\(\s*[^)]*\b({{var}})\b[^)]*\)",
                # Pattern 3: Chained - $(...).find(...).method(variable)
                rf"\$\([^)]+\)(?:\.[a-zA-Z]+\([^)]*\))*\.{method}\s*\(\s*[^)]*\b({{var}})\b[^)]*\)",
            ]

        # Special case: jQuery.parseHTML() and $.parseHTML()
        jquery_sinks["jQuery.parseHTML()"] = [
            r"\$\.parseHTML\s*\(\s*[^)]*\b({var})\b[^)]*\)",
            r"jQuery\.parseHTML\s*\(\s*[^)]*\b({var})\b[^)]*\)",
        ]

        # Special case: jQuery constructor $(user_input)
        jquery_sinks["jQuery.constructor()"] = [
            r"\$\s*\(\s*({var})\s*\)",
            r"jQuery\s*\(\s*({var})\s*\)",
        ]

        # Combine all sinks
        all_sinks = {**dangerous_sinks, **jquery_sinks}

        logger.info(f"   Checking against {len(all_sinks)} different sink types")

        # ========================================
        # PHASE 3: DETECT TAINTED VARIABLES IN SINKS
        # ========================================

        logger.info("⊙ Phase 3: Checking tainted variables in sinks...")

        detected_count = 0
        for var_name, var_info in tainted_vars.items():
            for sink_name, patterns in all_sinks.items():
                for pattern in patterns:
                    # Replace {var} placeholder with actual variable name
                    actual_pattern = pattern.replace("{var}", re.escape(var_name))

                    match = re.search(actual_pattern, html_content, re.IGNORECASE)
                    if match:
                        is_jquery = "jQuery" in sink_name or sink_name.startswith("$")

                        detected_count += 1
                        logger.warning(f"   ✓ Found: {var_name} → {sink_name}")

                        xss_patterns.append(
                            {
                                "type": (
                                    "JQUERY_XSS_SINK" if is_jquery else "DOM_XSS_SINK"
                                ),
                                "sink": sink_name,
                                "parameter": var_info["param"],
                                "variable": var_name,
                                "source": var_info["source"],
                                "method": var_info["method"],
                                "severity": "CRITICAL",
                                "exploitable": True,
                                "data_flow": f"{var_info['source']}('{var_info['param']}') → {var_name} → {sink_name}",
                                "matched_code": match.group(0)[:150],
                            }
                        )
                        break

        # ========================================
        # PHASE 4: DETECT DIRECT USAGE (NO VARIABLE)
        # ========================================

        logger.info("⊙ Phase 4: Checking direct location source usage...")

        direct_source_patterns = [
            (r"window\.location\.search", "location.search", "query_string"),
            (r"location\.search", "location.search", "query_string"),
            (r"window\.location\.hash", "location.hash", "hash"),
            (r"location\.hash", "location.hash", "hash"),
            (r"document\.URL", "document.URL", "url"),
            (r"document\.documentURI", "document.documentURI", "uri"),
            (r"document\.referrer", "document.referrer", "referrer"),
            (r"window\.location\.href", "location.href", "href"),
            (r"location\.href", "location.href", "href"),
        ]

        for source_pattern, source_name, param_name in direct_source_patterns:
            for sink_name, patterns in all_sinks.items():
                for pattern in patterns:
                    # Replace {var} with source pattern
                    actual_pattern = pattern.replace(
                        r"\b({var})\b", f"({source_pattern})"
                    )

                    match = re.search(actual_pattern, html_content, re.IGNORECASE)
                    if match:
                        is_jquery = "jQuery" in sink_name or sink_name.startswith("$")

                        detected_count += 1
                        logger.warning(
                            f"   ✓ Found: {source_name} → {sink_name} (direct)"
                        )

                        xss_patterns.append(
                            {
                                "type": (
                                    "JQUERY_XSS_SINK" if is_jquery else "DOM_XSS_SINK"
                                ),
                                "sink": sink_name,
                                "parameter": param_name,
                                "variable": None,
                                "source": source_name,
                                "method": "direct",
                                "severity": "CRITICAL",
                                "exploitable": True,
                                "data_flow": f"{source_name} → {sink_name} (direct)",
                                "matched_code": match.group(0)[:150],
                            }
                        )
                        break

        # ========================================
        # + PHASE 5: JQUERY COMPLEX PATTERNS
        # ========================================

        logger.info("⊙ Phase 5: Checking jQuery complex patterns...")

        # For each jQuery XSS method, check complex usage patterns
        for method in jquery_xss_methods:

            # Define patterns with explicit parameter extraction
            complex_patterns = [
                # Pattern 1: .method() with location.hash
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*(?:window\.)?location\.hash[^)]*\)",
                    "description": f"jQuery.{method}() with location.hash",
                    "param": "hash",
                    "source": "location.hash",
                },
                # Pattern 2: .method() with location.search
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*(?:window\.)?location\.search[^)]*\)",
                    "description": f"jQuery.{method}() with location.search",
                    "param": "search",
                    "source": "location.search",
                },
                # Pattern 3: .method() with URLSearchParams
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*URLSearchParams[^)]*\.get\s*\(\s*['\"](\w+)['\"]\s*\)[^)]*\)",
                    "description": f"jQuery.{method}() with URLSearchParams.get()",
                    "param": "extract",  # Will be extracted from regex
                    "source": "URLSearchParams.get()",
                },
                # Pattern 4: .method() with location.hash.slice()
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*(?:window\.)?location\.hash\.(?:slice|substring|substr)\s*\([^)]*\)[^)]*\)",
                    "description": f"jQuery.{method}() with location.hash.slice()",
                    "param": "hash",
                    "source": "location.hash.slice()",
                },
                # Pattern 5: .method() with decodeURIComponent(location.hash)
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.hash[^)]*\)[^)]*\)",
                    "description": f"jQuery.{method}() with decodeURIComponent(location.hash)",
                    "param": "hash",
                    "source": "location.hash (decoded)",
                },
                # Pattern 6: .method() with decodeURIComponent(location.search)
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.search[^)]*\)[^)]*\)",
                    "description": f"jQuery.{method}() with decodeURIComponent(location.search)",
                    "param": "search",
                    "source": "location.search (decoded)",
                },
                # Pattern 7: .method() with string concatenation + location.hash
                {
                    "pattern": rf"\.{method}\s*\(\s*['\"][^'\"]*['\"]?\s*\+\s*[^)]*(?:window\.)?location\.hash",
                    "description": f"jQuery.{method}() with string concat + location.hash",
                    "param": "hash",
                    "source": "location.hash (concatenated)",
                },
                # Pattern 8: .method() with both decode AND slice (most complex) - HASH
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.hash\.(?:slice|substring|substr)\s*\([^)]*\)[^)]*\)[^)]*\)",
                    "description": f"jQuery.{method}() with decodeURIComponent(location.hash.slice())",
                    "param": "hash",
                    "source": "location.hash (decoded + sliced)",
                },
                # Pattern 9: .method() with both decode AND slice - SEARCH
                {
                    "pattern": rf"\.{method}\s*\(\s*[^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.search\.(?:slice|substring|substr)\s*\([^)]*\)[^)]*\)[^)]*\)",
                    "description": f"jQuery.{method}() with decodeURIComponent(location.search.slice())",
                    "param": "search",
                    "source": "location.search (decoded + sliced)",
                },
            ]

            for pattern_dict in complex_patterns:
                pattern = pattern_dict["pattern"]
                description = pattern_dict["description"]
                param_name = pattern_dict["param"]
                source_name = pattern_dict["source"]

                matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)

                for match in matches:
                    matched_code = match.group(0)

                    # Try to extract parameter name from URLSearchParams.get('paramName')
                    if param_name == "extract":
                        param_match = re.search(
                            r"\.get\s*\(\s*['\"](\w+)['\"]\s*\)", matched_code
                        )
                        param_name = (
                            param_match.group(1) if param_match else "url_param"
                        )

                    detected_count += 1
                    logger.warning(f"   ✓ Found: {description}")
                    logger.warning(f"      Code: {matched_code[:80]}...")

                    xss_patterns.append(
                        {
                            "type": "JQUERY_XSS_SINK",
                            "sink": f"jQuery.{method}()",
                            "parameter": param_name,  # ✓ Now correct
                            "variable": None,
                            "source": source_name,  # ✓ Now correct
                            "method": "complex_pattern",
                            "severity": "CRITICAL",
                            "exploitable": True,
                            "data_flow": f"{source_name} → jQuery.{method}()",  # ✓ Clear flow
                            "matched_code": matched_code[:150],
                        }
                    )

        # ========================================
        # + PHASE 6: JQUERY CONSTRUCTOR PATTERNS
        # ========================================

        logger.info("⊙ Phase 6: Checking jQuery constructor patterns...")

        constructor_patterns = [
            # Simple: $(location.hash)
            {
                "pattern": r"\$\s*\(\s*(?:window\.)?location\.hash\s*\)",
                "description": "jQuery constructor with location.hash (simple)",
                "param": "hash",
                "source": "location.hash",
            },
            {
                "pattern": r"\$\s*\(\s*(?:window\.)?location\.search\s*\)",
                "description": "jQuery constructor with location.search (simple)",
                "param": "search",
                "source": "location.search",
            },
            {
                "pattern": r"\$\s*\(\s*(?:window\.)?location\.href\s*\)",
                "description": "jQuery constructor with location.href (simple)",
                "param": "href",
                "source": "location.href",
            },
            # With .slice(): $(location.hash.slice(1))
            {
                "pattern": r"\$\s*\(\s*(?:window\.)?location\.hash\.(?:slice|substring|substr)\s*\([^)]*\)\s*\)",
                "description": "jQuery constructor with location.hash.slice()",
                "param": "hash",
                "source": "location.hash.slice()",
            },
            {
                "pattern": r"\$\s*\(\s*(?:window\.)?location\.search\.(?:slice|substring|substr)\s*\([^)]*\)\s*\)",
                "description": "jQuery constructor with location.search.slice()",
                "param": "search",
                "source": "location.search.slice()",
            },
            # With decode: $(decodeURIComponent(location.hash))
            {
                "pattern": r"\$\s*\(\s*decodeURIComponent\s*\(\s*(?:window\.)?location\.hash[^)]*\)\s*\)",
                "description": "jQuery constructor with decodeURIComponent(location.hash)",
                "param": "hash",
                "source": "location.hash (decoded)",
            },
            {
                "pattern": r"\$\s*\(\s*decodeURIComponent\s*\(\s*(?:window\.)?location\.search[^)]*\)\s*\)",
                "description": "jQuery constructor with decodeURIComponent(location.search)",
                "param": "search",
                "source": "location.search (decoded)",
            },
            # String concat: $('selector' + location.hash)
            {
                "pattern": r"\$\s*\(\s*['\"][^'\"]*['\"]?\s*\+\s*[^)]*(?:window\.)?location\.hash",
                "description": "jQuery constructor with string concat + location.hash",
                "param": "hash",
                "source": "location.hash (concatenated)",
            },
            {
                "pattern": r"\$\s*\(\s*['\"][^'\"]*['\"]?\s*\+\s*[^)]*(?:window\.)?location\.search",
                "description": "jQuery constructor with string concat + location.search",
                "param": "search",
                "source": "location.search (concatenated)",
            },
            # Ultimate complex: $('x' + decodeURIComponent(location.hash.slice(1)))
            {
                "pattern": r"\$\s*\([^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.hash\.(?:slice|substring|substr)\s*\([^)]*\)[^)]*\)[^)]*\)",
                "description": "jQuery constructor with decodeURIComponent(location.hash.slice()) - COMPLEX",
                "param": "hash",
                "source": "location.hash (decoded + sliced)",
            },
            {
                "pattern": r"\$\s*\([^)]*decodeURIComponent\s*\([^)]*(?:window\.)?location\.search\.(?:slice|substring|substr)\s*\([^)]*\)[^)]*\)[^)]*\)",
                "description": "jQuery constructor with decodeURIComponent(location.search.slice()) - COMPLEX",
                "param": "search",
                "source": "location.search (decoded + sliced)",
            },
            # Generic fallback: Any location inside $()
            {
                "pattern": r"\$\s*\([^)]*(?:window\.)?location\.hash[^)]*\)",
                "description": "jQuery constructor with location.hash (any pattern)",
                "param": "hash",
                "source": "location.hash",
            },
            {
                "pattern": r"\$\s*\([^)]*(?:window\.)?location\.search[^)]*\)",
                "description": "jQuery constructor with location.search (any pattern)",
                "param": "search",
                "source": "location.search",
            },
            {
                "pattern": r"\$\s*\([^)]*(?:window\.)?location\.href[^)]*\)",
                "description": "jQuery constructor with location.href (any pattern)",
                "param": "href",
                "source": "location.href",
            },
        ]

        for pattern_dict in constructor_patterns:
            pattern = pattern_dict["pattern"]
            description = pattern_dict["description"]
            param_name = pattern_dict["param"]
            source_name = pattern_dict["source"]

            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)

            for match in matches:
                matched_code = match.group(0)

                detected_count += 1
                logger.warning(f"   ✓ Found: {description}")
                logger.warning(f"      Code: {matched_code[:80]}...")

                xss_patterns.append(
                    {
                        "type": "JQUERY_XSS_SINK",
                        "sink": "jQuery.constructor()",
                        "parameter": param_name,  # ✓ Now uses actual parameter name
                        "variable": None,
                        "source": source_name,  # ✓ Now uses actual source
                        "method": "constructor_pattern",
                        "severity": "CRITICAL",
                        "exploitable": True,
                        "data_flow": f"{source_name} → jQuery.$() constructor",  # ✓ Clear data flow
                        "matched_code": matched_code[:150],
                    }
                )

        # ========================================
        # + PHASE 7: JQUERY .attr() WITH DANGEROUS ATTRIBUTES
        # ========================================

        logger.info("⊙ Phase 7: Checking jQuery .attr() patterns...")

        dangerous_attrs = [
            "href",
            "src",
            "action",
            "formaction",
            "data",
            "poster",
            "background",
            "dynsrc",
            "lowsrc",
        ]

        for attr in dangerous_attrs:
            attr_patterns = [
                # With variable
                (
                    rf"\.attr\s*\(\s*['\"]?{attr}['\"]?\s*,\s*[^)]*\b({{var}})\b[^)]*\)",
                    f'jQuery.attr("{attr}") with variable',
                    "attr_variable",
                ),
                # With URLSearchParams
                (
                    rf"\.attr\s*\(\s*['\"]?{attr}['\"]?\s*,\s*[^)]*URLSearchParams[^)]*\.get\s*\(",
                    f'jQuery.attr("{attr}") with URLSearchParams.get()',
                    "attr_urlsearch",
                ),
                # With location.search
                (
                    rf"\.attr\s*\(\s*['\"]?{attr}['\"]?\s*,\s*[^)]*(?:window\.)?location\.search",
                    f'jQuery.attr("{attr}") with location.search',
                    "attr_location_search",
                ),
                # With location.hash
                (
                    rf"\.attr\s*\(\s*['\"]?{attr}['\"]?\s*,\s*[^)]*(?:window\.)?location\.hash",
                    f'jQuery.attr("{attr}") with location.hash',
                    "attr_location_hash",
                ),
                # With location.href
                (
                    rf"\.attr\s*\(\s*['\"]?{attr}['\"]?\s*,\s*[^)]*(?:window\.)?location\.href",
                    f'jQuery.attr("{attr}") with location.href',
                    "attr_location_href",
                ),
            ]

            # Check variable-based patterns
            for var_name in tainted_vars.keys():
                var_pattern = attr_patterns[0][0].replace("{var}", re.escape(var_name))
                match = re.search(var_pattern, html_content, re.IGNORECASE)

                if match:
                    detected_count += 1
                    logger.warning(
                        f"   ✓ Found: jQuery.attr('{attr}') with variable {var_name}"
                    )

                    xss_patterns.append(
                        {
                            "type": "JQUERY_XSS_SINK",
                            "sink": f'jQuery.attr("{attr}")',
                            "parameter": tainted_vars[var_name]["param"],
                            "variable": var_name,
                            "source": tainted_vars[var_name]["source"],
                            "method": "attr_variable",
                            "severity": (
                                "CRITICAL"
                                if attr in ["href", "src", "action"]
                                else "HIGH"
                            ),
                            "exploitable": True,
                            "data_flow": f"{tainted_vars[var_name]['source']} → {var_name} → jQuery.attr('{attr}')",
                            "matched_code": match.group(0)[:150],
                        }
                    )

            # Check direct patterns
            for pattern, description, param_type in attr_patterns[1:]:
                matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)

                for match in matches:
                    matched_code = match.group(0)

                    # Try to extract parameter name
                    param_match = re.search(
                        r"\.get\s*\(\s*['\"](\w+)['\"]\s*\)", matched_code
                    )
                    param_name = param_match.group(1) if param_match else param_type

                    detected_count += 1
                    logger.warning(f"   ✓ Found: {description}")

                    xss_patterns.append(
                        {
                            "type": "JQUERY_XSS_SINK",
                            "sink": f'jQuery.attr("{attr}")',
                            "parameter": param_name,
                            "variable": None,
                            "source": description,
                            "method": "attr_direct",
                            "severity": (
                                "CRITICAL"
                                if attr in ["href", "src", "action"]
                                else "HIGH"
                            ),
                            "exploitable": True,
                            "data_flow": f"{description}",
                            "matched_code": matched_code[:150],
                        }
                    )

        # ========================================
        # + PHASE 8: JQUERY.parseHTML() PATTERNS
        # ========================================

        logger.info("⊙ Phase 8: Checking jQuery.parseHTML() patterns...")

        parsehtml_patterns = [
            # $.parseHTML(location.hash)
            (
                r"\$\.parseHTML\s*\(\s*[^)]*(?:window\.)?location\.(?:hash|search|href)[^)]*\)",
                "$.parseHTML() with location",
                "parsehtml_location",
            ),
            # jQuery.parseHTML(URLSearchParams.get())
            (
                r"jQuery\.parseHTML\s*\(\s*[^)]*URLSearchParams[^)]*\.get\s*\([^)]*\)[^)]*\)",
                "jQuery.parseHTML() with URLSearchParams",
                "parsehtml_urlsearch",
            ),
            # $.parseHTML(variable)
            (
                r"\$\.parseHTML\s*\(\s*[^)]*\b({var})\b[^)]*\)",
                "$.parseHTML() with variable",
                "parsehtml_var",
            ),
        ]

        # Check variable patterns
        for var_name in tainted_vars.keys():
            var_pattern = parsehtml_patterns[2][0].replace("{var}", re.escape(var_name))
            match = re.search(var_pattern, html_content, re.IGNORECASE)

            if match:
                detected_count += 1
                logger.warning(f"   ✓ Found: $.parseHTML() with variable {var_name}")

                xss_patterns.append(
                    {
                        "type": "JQUERY_XSS_SINK",
                        "sink": "jQuery.parseHTML()",
                        "parameter": tainted_vars[var_name]["param"],
                        "variable": var_name,
                        "source": tainted_vars[var_name]["source"],
                        "method": "parsehtml_variable",
                        "severity": "CRITICAL",
                        "exploitable": True,
                        "data_flow": f"{tainted_vars[var_name]['source']} → {var_name} → jQuery.parseHTML()",
                        "matched_code": match.group(0)[:150],
                    }
                )

        # Check direct patterns
        for pattern, description, param_type in parsehtml_patterns[:2]:
            matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)

            for match in matches:
                matched_code = match.group(0)

                detected_count += 1
                logger.warning(f"   ✓ Found: {description}")

                xss_patterns.append(
                    {
                        "type": "JQUERY_XSS_SINK",
                        "sink": "jQuery.parseHTML()",
                        "parameter": param_type,
                        "variable": None,
                        "source": description,
                        "method": "parsehtml_direct",
                        "severity": "CRITICAL",
                        "exploitable": True,
                        "data_flow": f"{description}",
                        "matched_code": matched_code[:150],
                    }
                )

        # ========================================
        # PHASE 9: PARAMETERS IN SCRIPT TAGS
        # ========================================

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            for param in extracted_params:
                inline_scripts = soup.find_all("script", src=False, string=True)

                for script_tag in inline_scripts:
                    script_content = script_tag.string
                    if script_content:
                        param_pattern = rf"\b{re.escape(param)}\b"
                        if re.search(param_pattern, script_content, re.IGNORECASE):
                            xss_patterns.append(
                                {
                                    "type": "SCRIPT_PARAMETER",
                                    "parameter": param,
                                    "context": "inline_script",
                                    "severity": "HIGH",
                                    "description": f"Parameter '{param}' found in inline <script> tag",
                                    "script_preview": script_content[:100],
                                }
                            )
                            break

        except Exception as e:
            logger.error(f"Error in inline script parameter detection: {e}")

        # ========================================
        # PHASE 10: STRING CONCATENATION
        # ========================================

        for var_name, var_info in tainted_vars.items():
            concat_patterns = [
                rf"['\"]<[^>]+>['\"]?\s*\+\s*{re.escape(var_name)}\s*\+\s*['\"]?</",
                rf"['\"]<[^>]+\s*=\s*['\"]?\s*\+\s*{re.escape(var_name)}",
                rf"{re.escape(var_name)}\s*\+\s*['\"]<[^>]+>",
            ]

            for pattern in concat_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    xss_patterns.append(
                        {
                            "type": "STRING_CONCAT_XSS",
                            "parameter": var_info["param"],
                            "variable": var_name,
                            "source": var_info["source"],
                            "severity": "HIGH",
                            "description": "User input concatenated into HTML string",
                            "data_flow": f"{var_info['source']}('{var_info['param']}') → {var_name} → HTML concatenation",
                        }
                    )
                    break

        # ========================================
        # FINAL SUMMARY
        # ========================================

        logger.info("=" * 60)
        logger.info(f"✓ DOM XSS Detection Complete!")
        logger.info(f"   Total patterns found: {len(xss_patterns)}")
        logger.info(f"   Tainted variables tracked: {len(tainted_vars)}")
        logger.info(f"   Sink detections: {detected_count}")
        logger.info("=" * 60)

        return xss_patterns


def detect_dom_xss_vulnerability(js_content: str, html_content: str) -> List[Dict]:
    """
    Comprehensive DOM XSS vulnerability detection with proof of concept.

    This function:
    1. Identifies complete XSS vulnerabilities (not just components)
    2. Provides proof-of-concept payloads
    3. Rates exploitability
    4. Returns actionable findings
    """
    findings = []

    if not js_content and not html_content:
        return findings

    combined_content = (js_content or "") + "\n" + (html_content or "")

    # ========================================
    # DETECTION 1: URLSearchParams → Variable → Sink
    # ========================================

    # Pattern: var X = URLSearchParams.get('param')
    urlsearch_pattern = r"(?:var|let|const)\s+(\w+)\s*=\s*[^;]*URLSearchParams[^;]*\.get\s*\(\s*['\"](\w+)['\"]\s*\)"

    for match in re.finditer(urlsearch_pattern, combined_content, re.IGNORECASE):
        var_name = match.group(1)
        param_name = match.group(2)

        # Check if this variable is used in dangerous sinks
        sinks_to_check = {
            "document.write": {
                "pattern": rf"document\.write\s*\([^)]*\b{re.escape(var_name)}\b",
                "severity": "CRITICAL",
                "impact": "RCE/XSS",
                "payloads": [
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                    '"><script>alert(document.domain)</script>',
                ],
            },
            "innerHTML": {
                "pattern": rf"\.innerHTML\s*=\s*[^;]*\b{re.escape(var_name)}\b",
                "severity": "CRITICAL",
                "impact": "XSS",
                "payloads": [
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                ],
            },
            "eval": {
                "pattern": rf"\beval\s*\([^)]*\b{re.escape(var_name)}\b",
                "severity": "CRITICAL",
                "impact": "RCE",
                "payloads": [
                    "alert(1)",
                    "alert(document.domain)",
                ],
            },
            "jQuery.html": {
                "pattern": rf"\$\([^)]+\)\.html\s*\([^)]*\b{re.escape(var_name)}\b",
                "severity": "CRITICAL",
                "impact": "XSS",
                "payloads": [
                    "<img src=x onerror=alert(1)>",
                    "<svg/onload=alert(1)>",
                ],
            },
            "location.href": {
                "pattern": rf"location\.href\s*=\s*[^;]*\b{re.escape(var_name)}\b",
                "severity": "HIGH",
                "impact": "Open Redirect / XSS",
                "payloads": [
                    "javascript:alert(1)",
                    "data:text/html,<script>alert(1)</script>",
                ],
            },
        }

        for sink_name, sink_info in sinks_to_check.items():
            sink_match = re.search(
                sink_info["pattern"], combined_content, re.IGNORECASE
            )
            if sink_match:
                findings.append(
                    {
                        "type": "DOM_XSS_CONFIRMED",
                        "vulnerability": "DOM-based Cross-Site Scripting",
                        "severity": sink_info["severity"],
                        "confidence": "HIGH",
                        "exploitable": True,
                        # Data flow
                        "source": f"URLSearchParams.get('{param_name}')",
                        "source_type": "URLSearchParams",
                        "parameter": param_name,
                        "variable": var_name,
                        "sink": sink_name,
                        "impact": sink_info["impact"],
                        # Flow visualization
                        "data_flow": f"URL param '{param_name}' → var '{var_name}' → {sink_name}",
                        "flow_steps": [
                            f"1. User input extracted from URL parameter '{param_name}'",
                            f"2. Stored in variable '{var_name}'",
                            f"3. Passed to dangerous sink '{sink_name}' without sanitization",
                        ],
                        # Exploitation
                        "payloads": sink_info["payloads"],
                        "exploitation_url": f"?{param_name}={sink_info['payloads'][0]}",
                        # Evidence
                        "source_code": match.group(0),
                        "sink_code": sink_match.group(0),
                        # Remediation
                        "remediation": [
                            "Sanitize user input before using in DOM manipulation",
                            "Use textContent instead of innerHTML where possible",
                            "Implement Content Security Policy (CSP)",
                            "Use DOMPurify or similar sanitization library",
                        ],
                    }
                )

    # ========================================
    # DETECTION 2: Direct location.search → Sink
    # ========================================

    direct_sources = [
        ("window.location.search", "location.search"),
        ("location.search", "location.search"),
        ("window.location.hash", "location.hash"),
        ("location.hash", "location.hash"),
    ]

    for source_pattern, source_name in direct_sources:
        # Check if used directly in sinks
        direct_sinks = [
            (
                rf"document\.write\s*\([^)]*{re.escape(source_pattern)}",
                "document.write",
                "CRITICAL",
            ),
            (
                rf"\.innerHTML\s*=\s*[^;]*{re.escape(source_pattern)}",
                "innerHTML",
                "CRITICAL",
            ),
            (rf"\beval\s*\([^)]*{re.escape(source_pattern)}", "eval", "CRITICAL"),
        ]

        for pattern, sink_name, severity in direct_sinks:
            match = re.search(pattern, combined_content, re.IGNORECASE)
            if match:
                findings.append(
                    {
                        "type": "DOM_XSS_CONFIRMED",
                        "vulnerability": "DOM-based Cross-Site Scripting (Direct)",
                        "severity": severity,
                        "confidence": "HIGH",
                        "exploitable": True,
                        "source": source_name,
                        "source_type": "Direct",
                        "parameter": "query_string",
                        "variable": None,
                        "sink": sink_name,
                        "impact": "XSS/RCE",
                        "data_flow": f"{source_name} → {sink_name} (DIRECT - no intermediate variable)",
                        "flow_steps": [
                            f"1. User input from {source_name}",
                            f"2. Directly passed to {sink_name} without sanitization",
                        ],
                        "payloads": [
                            "<img src=x onerror=alert(1)>",
                            "<svg/onload=alert(1)>",
                        ],
                        "source_code": match.group(0),
                        "remediation": [
                            "NEVER use location.search/hash directly in DOM sinks",
                            "Always sanitize user input",
                            "Use safe APIs like textContent",
                        ],
                    }
                )

    # ========================================
    # DETECTION 3: String Concatenation XSS
    # ========================================

    # Pattern: document.write('<tag attr="' + userInput + '">')
    concat_pattern = r"document\.write\s*\(\s*['\"]<[^>]+>['\"]?\s*\+\s*(\w+)"

    for match in re.finditer(concat_pattern, combined_content, re.IGNORECASE):
        var_name = match.group(1)

        # Check if this variable comes from user input
        user_input_check = [
            rf"(?:var|let|const)\s+{re.escape(var_name)}\s*=\s*[^;]*(?:location|URLSearchParams|document\.referrer)",
            rf"{re.escape(var_name)}\s*=\s*[^;]*(?:location|URLSearchParams|document\.referrer)",
        ]

        is_user_controlled = False
        for check_pattern in user_input_check:
            if re.search(check_pattern, combined_content, re.IGNORECASE):
                is_user_controlled = True
                break

        if is_user_controlled:
            findings.append(
                {
                    "type": "DOM_XSS_CONFIRMED",
                    "vulnerability": "DOM XSS via String Concatenation",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "exploitable": True,
                    "source": "User Input",
                    "variable": var_name,
                    "sink": "document.write + string concatenation",
                    "impact": "XSS",
                    "data_flow": f"User input → var '{var_name}' → String concat → document.write",
                    "payloads": [
                        '"><img src=x onerror=alert(1)>',
                        "' onerror=alert(1) x='",
                    ],
                    "source_code": match.group(0),
                    "remediation": [
                        "Never concatenate user input into HTML strings",
                        "Use template engines with auto-escaping",
                        "Use DOM methods like createElement() instead",
                    ],
                }
            )

    return findings


class JavaScriptAnalyzer:
    """Handles JavaScript file analysis, vulnerability detection, and data flow analysis"""

    @staticmethod
    def analyze_javascript_for_parameters(js_content, url):
        """Analyze JavaScript content for parameter extraction and usage"""
        findings = []

        if not js_content:
            return findings

        js_clean = js_content.replace("\n", " ").replace("\r", " ")

        # Pattern 1: URLSearchParams extraction
        urlsearch_patterns = [
            r"new\s+URLSearchParams\s*\(\s*window\.location\.search\s*\)",
            r"new\s+URLSearchParams\s*\(\s*location\.search\s*\)",
            r"new\s+URLSearchParams\s*\(\s*document\.location\.search\s*\)",
            r"URLSearchParams\s*\(\s*window\.location\.search\s*\)",
        ]

        for pattern in urlsearch_patterns:
            if re.search(pattern, js_clean, re.IGNORECASE):
                findings.append({"type": "URL_SEARCH_PARAMS", "pattern": pattern})

        # Pattern 2: Parameter extraction using .get()
        param_get_pattern = r'\.get\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
        param_matches = re.findall(param_get_pattern, js_clean, re.IGNORECASE)

        for param in param_matches:
            findings.append(
                {
                    "type": "PARAM_EXTRACTION",
                    "param": param,
                    "method": ".get()",
                }
            )

        # Pattern 3: window.location.search parsing
        search_patterns = [
            r"window\.location\.search\s*\.?\s*(?:match|split|indexOf|substring|replace)",
            r"location\.search\s*\.?\s*(?:match|split|indexOf|substring|replace)",
            r"document\.location\.search\s*\.?\s*(?:match|split|indexOf|substring|replace)",
        ]

        for pattern in search_patterns:
            if re.search(pattern, js_clean, re.IGNORECASE):
                findings.append({"type": "LOCATION_SEARCH_PARSING", "pattern": pattern})

        # Pattern 4: Query string parsing with regex
        query_regex_patterns = [
            r"[?&]([^&=#]+)=([^&#]*)",
            r"[?&](\w+)=([^&]*)",
            r"(\w+)=([^&]*)",
        ]

        for pattern in query_regex_patterns:
            if re.search(pattern, js_clean):
                findings.append({"type": "QUERY_REGEX_PARSING", "pattern": pattern})

        # Pattern 5: Parameter usage in DOM manipulation
        dom_usage_patterns = [
            (
                r"document\.(?:write|writeln)\s*\(\s*[^)]*\b(\w+)\b[^)]*\)",
                "document.write/writeln",
            ),
            (r"\.innerHTML\s*=\s*[^;]*\b(\w+)\b[^;]*", ".innerHTML"),
            (r"\.outerHTML\s*=\s*[^;]*\b(\w+)\b[^;]*", ".outerHTML"),
            (r"\.textContent\s*=\s*[^;]*\b(\w+)\b[^;]*", ".textContent"),
            (r"\.innerText\s*=\s*[^;]*\b(\w+)\b[^;]*", ".innerText"),
            (
                r"\.(?:append|prepend|insertBefore|replaceWith)\s*\(\s*[^)]*\b(\w+)\b[^)]*\)",
                "DOM append/prepend",
            ),
            (
                r"createElement\s*\(\s*[^)]*\)[^;]*\.(?:appendChild|insertBefore)[^;]*\b(\w+)\b",
                "createElement",
            ),
        ]

        for pattern, manipulation_type in dom_usage_patterns:
            matches = re.finditer(pattern, js_clean, re.IGNORECASE)
            for match in matches:
                param = match.group(1)
                matched_code = match.group(0)
                if len(param) > 2:
                    findings.append(
                        {
                            "type": "DOM_PARAM_USAGE",
                            "param": param,
                            "manipulation": manipulation_type,
                            "pattern": matched_code,
                        }
                    )

        # Pattern 6: String concatenation
        string_concat_pattern = r'[\'"`]\s*\+\s*\b(\w+)\b\s*\+\s*[\'"`]'
        concat_matches = re.findall(string_concat_pattern, js_clean)

        for param in concat_matches:
            findings.append({"type": "STRING_CONCAT_PARAM", "param": param})

        # Pattern 7: Dangerous functions
        dangerous_functions = [
            "eval",
            "setTimeout",
            "setInterval",
            "Function",
            "execScript",
            "document.write",
            "document.writeln",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
        ]

        for func in dangerous_functions:
            pattern = rf"{func}\s*\(\s*[^)]*\b(\w+)\b[^)]*\)"
            matches = re.findall(pattern, js_clean, re.IGNORECASE)
            for param in matches:
                findings.append(
                    {
                        "type": "DANGEROUS_FUNCTION_PARAM",
                        "function": func,
                        "param": param,
                    }
                )

        # Pattern 8: Template literals
        template_pattern = r"\$\{\s*(\w+)\s*\}"
        template_matches = re.findall(template_pattern, js_clean)

        for param in template_matches:
            findings.append({"type": "TEMPLATE_LITERAL_PARAM", "param": param})

        # Pattern 9: Attribute values
        attr_pattern = r'=\s*[\'"`]?\s*\+\s*(\w+)\s*\+\s*[\'"`]?'
        attr_matches = re.findall(attr_pattern, js_clean)

        for param in attr_matches:
            findings.append({"type": "ATTRIBUTE_PARAM", "param": param})

        # Pattern 10: Variable assignments from URL
        var_assignment_patterns = [
            r"var\s+(\w+)\s*=\s*.*[?&](\w+)=",
            r"let\s+(\w+)\s*=\s*.*[?&](\w+)=",
            r"const\s+(\w+)\s*=\s*.*[?&](\w+)=",
            r"(\w+)\s*=\s*.*[?&](\w+)=",
        ]

        for pattern in var_assignment_patterns:
            matches = re.findall(pattern, js_clean)
            for var_match, param_match in matches:
                if var_match and param_match:
                    findings.append(
                        {
                            "type": "VAR_FROM_URL_PARAM",
                            "variable": var_match,
                            "param": param_match,
                        }
                    )

        return findings

    @staticmethod
    def analyze_js_file_for_vulnerabilities(
        js_content: str, url: str
    ) -> Dict[str, Set[str]]:
        """Analyze JavaScript file and return detected vulnerabilities including jQuery sinks"""
        detections: Dict[str, Set[str]] = {}

        if not js_content or len(js_content) < 10:
            return detections

        # Define helper function FIRST
        def detect_secret_type(var_name: str, value: str) -> str:
            """Smart detection of secret type"""
            var_lower = var_name.lower() if var_name else ""

            # 1. Check value patterns first (most reliable)
            if value.startswith("AKIA"):
                return "AWS_KEY"
            elif value.startswith(("sk_", "pk_", "rk_", "live_", "test_")):
                return "API_KEY"
            elif value.startswith("eyJ"):
                return "SECRET"

            # 2. Check variable name patterns
            if var_name:
                if any(keyword in var_lower for keyword in ["api", "key", "apikey"]):
                    return "API_KEY"
                elif any(keyword in var_lower for keyword in ["pass", "pwd", "cred"]):
                    return "PASSWORD"
                elif any(keyword in var_lower for keyword in ["aws", "access"]):
                    return "AWS_KEY"
                elif any(
                    keyword in var_lower
                    for keyword in ["secret", "token", "jwt", "auth"]
                ):
                    return "SECRET"

            # 3. Default based on length/pattern
            if len(value) >= 20:
                return "API_KEY"
            elif len(value) >= 8:
                return "PASSWORD"

            return "SENSITIVE_DATA"

        # 1. Dangerous JS execution functions
        dangerous_functions = {
            r"(\beval\s*\([^)]*\))": ("eval()", {"RCE", "XSS"}),
            r"(\bFunction\s*\([^)]*\))": ("Function constructor", {"RCE", "XSS"}),
            r"(\bsetTimeout\s*\([^)]*\))": ("setTimeout()", {"XSS", "RCE"}),
            r"(\bsetInterval\s*\([^)]*\))": ("setInterval()", {"XSS", "RCE"}),
            r"(\bexecScript\s*\([^)]*\))": ("execScript()", {"RCE", "XSS"}),
        }

        for pattern, (func_name, vulns) in dangerous_functions.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for matched_code in matches:
                clean_code = " ".join(matched_code.split())[:80]
                finding = f"{func_name}: {clean_code}"
                detections.setdefault(func_name, set()).add(finding)
                detections[func_name].update(vulns)

                if JavaScriptAnalyzer.has_user_input_source(js_content):
                    detections[func_name].add("REFLECTED")

        # 2. DOM XSS sinks (including jQuery)
        dom_sinks = {
            # ── PortSwigger cat 1: DOM-XSS — native ─────────────────────────
            r"(document\.write\s*\([^)]*\))":           ("document.write()", {"XSS"}),
            r"(document\.writeln\s*\([^)]*\))":         ("document.writeln()", {"XSS"}),
            r"(document\.domain\s*=[^;]*)":             ("document.domain=", {"XSS", "DOMAIN_MANIPULATION"}),
            r"(\.innerHTML\s*=[^;]*)":                   (".innerHTML", {"XSS"}),
            r"(\.outerHTML\s*=[^;]*)":                   (".outerHTML", {"XSS"}),
            r"(\.insertAdjacentHTML\s*\([^)]*\))":      (".insertAdjacentHTML()", {"XSS"}),
            r"(\.on\w+\s*=[^;]*)":                       ("element.onevent", {"XSS"}),
            r"(\.setAttribute\s*\(\s*[\"']on\w+[\"'][^)]*\))": (".setAttribute(on*)", {"XSS"}),
            # ── PortSwigger cat 1: DOM-XSS — jQuery ─────────────────────────
            r"(\.add\s*\([^)]*\))":                      ("jQuery.add()", {"XSS"}),
            r"(\.after\s*\([^)]*\))":                    ("jQuery.after()", {"XSS"}),
            r"(\.append\s*\([^)]*\))":                   ("jQuery.append()", {"XSS"}),
            r'(\.animate\s*\(\s*["\'][^)]*\))':          ("jQuery.animate()", {"XSS"}),
            r"(\.insertAfter\s*\([^)]*\))":              ("jQuery.insertAfter()", {"XSS"}),
            r"(\.insertBefore\s*\([^)]*\))":             ("jQuery.insertBefore()", {"XSS"}),
            r"(\.before\s*\([^)]*\))":                   ("jQuery.before()", {"XSS"}),
            r"(\.html\s*\([^)]*\))":                     ("jQuery.html()", {"XSS"}),
            r"(\.prepend\s*\([^)]*\))":                  ("jQuery.prepend()", {"XSS"}),
            r"(\.replaceAll\s*\([^)]*\))":               ("jQuery.replaceAll()", {"XSS"}),
            r"(\.replaceWith\s*\([^)]*\))":              ("jQuery.replaceWith()", {"XSS"}),
            r"(\.wrap\s*\([^)]*\))":                     ("jQuery.wrap()", {"XSS"}),
            r"(\.wrapInner\s*\([^)]*\))":                ("jQuery.wrapInner()", {"XSS"}),
            r"(\.wrapAll\s*\([^)]*\))":                  ("jQuery.wrapAll()", {"XSS"}),
            r"(\.has\s*\([^)]*\))":                      ("jQuery.has()", {"XSS"}),
            r"(\.constructor\s*\([^)]*\))":              ("jQuery.constructor()", {"XSS"}),
            r"(\.init\s*\([^)]*\))":                     ("jQuery.init()", {"XSS"}),
            r"(\.index\s*\([^)]*\))":                    ("jQuery.index()", {"XSS"}),
            r"(jQuery\.parseHTML\s*\([^)]*\))":          ("jQuery.parseHTML()", {"XSS"}),
            r"(\$\.parseHTML\s*\([^)]*\))":              ("$.parseHTML()", {"XSS"}),
            # ── PortSwigger cat 2: Open redirect ────────────────────────────
            r"((?:window\.)?location\.host\s*=[^;]*)":     ("location.host=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.hostname\s*=[^;]*)": ("location.hostname=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.href\s*=[^;]*)":     ("location.href=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.pathname\s*=[^;]*)": ("location.pathname=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.search\s*=[^;]*)":   ("location.search=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.protocol\s*=[^;]*)": ("location.protocol=", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.assign\s*\([^)]*\))":  ("location.assign()", {"OPEN_REDIRECT"}),
            r"((?:window\.)?location\.replace\s*\([^)]*\))": ("location.replace()", {"OPEN_REDIRECT"}),
            r"(\bopen\s*\([^)]*\))":                         ("open()", {"OPEN_REDIRECT"}),
            r"(\.srcdoc\s*=[^;]*)":                          ("element.srcdoc=", {"OPEN_REDIRECT", "XSS"}),
            r"(XMLHttpRequest[^;]*\.open\s*\([^)]*\))":      ("XMLHttpRequest.open()", {"OPEN_REDIRECT", "SSRF"}),
            r"(XMLHttpRequest[^;]*\.send\s*\([^)]*\))":      ("XMLHttpRequest.send()", {"OPEN_REDIRECT", "SSRF"}),
            r"(jQuery\.ajax\s*\([^)]*\))":                   ("jQuery.ajax()", {"OPEN_REDIRECT", "SSRF"}),
            r"(\$\.ajax\s*\([^)]*\))":                       ("$.ajax()", {"OPEN_REDIRECT", "SSRF"}),
            # ── PortSwigger cat 3: Cookie manipulation ───────────────────────
            r"(document\.cookie\s*=[^;]*)":                  ("document.cookie=", {"COOKIE_MANIPULATION"}),
            # ── PortSwigger cat 4: JS injection ─────────────────────────────
            r"(\beval\s*\([^)]*\))":                         ("eval()", {"JS_INJECTION"}),
            r"(\bFunction\s*\([^)]*\))":                     ("Function()", {"JS_INJECTION"}),
            r"(setTimeout\s*\([^)]*\))":                     ("setTimeout()", {"JS_INJECTION"}),
            r"(setInterval\s*\([^)]*\))":                    ("setInterval()", {"JS_INJECTION"}),
            r"(setImmediate\s*\([^)]*\))":                   ("setImmediate()", {"JS_INJECTION"}),
            r"(document\.execCommand\s*\([^)]*\))":          ("execCommand()", {"JS_INJECTION"}),
            r"(\bexecScript\s*\([^)]*\))":                   ("execScript()", {"JS_INJECTION"}),
            r"(\bmsSetImmediate\s*\([^)]*\))":               ("msSetImmediate()", {"JS_INJECTION"}),
            r"(\.createContextualFragment\s*\([^)]*\))":     ("range.createContextualFragment()", {"JS_INJECTION"}),
            r"(crypto\.generateCRMFRequest\s*\([^)]*\))":    ("crypto.generateCRMFRequest()", {"JS_INJECTION"}),
            # ── PortSwigger cat 6: WebSocket-URL poisoning ───────────────────
            r"(new\s+WebSocket\s*\([^)]*\))":                ("WebSocket constructor", {"WEBSOCKET_URL_POISONING"}),
            # ── PortSwigger cat 7: Link manipulation ─────────────────────────
            r"(\.href\s*=[^;]*)":      ("element.href=", {"LINK_MANIPULATION"}),
            r"(\.src\s*=[^;]*)":       ("element.src=", {"LINK_MANIPULATION"}),
            r"(\.action\s*=[^;]*)":    ("element.action=", {"LINK_MANIPULATION"}),
            # ── PortSwigger cat 8: Web-message manipulation ──────────────────
            r"(\.postMessage\s*\([^)]*\))":                  ("postMessage()", {"WEB_MESSAGE_MANIPULATION"}),
            # ── PortSwigger cat 9: Ajax header manipulation ──────────────────
            r"(\.setRequestHeader\s*\([^)]*\))":             ("XMLHttpRequest.setRequestHeader()", {"AJAX_HEADER_MANIPULATION"}),
            r"(jQuery\.globalEval\s*\([^)]*\))":             ("jQuery.globalEval()", {"AJAX_HEADER_MANIPULATION"}),
            r"(\$\.globalEval\s*\([^)]*\))":                 ("$.globalEval()", {"AJAX_HEADER_MANIPULATION"}),
            # ── PortSwigger cat 10: Local file-path manipulation ─────────────
            r"(\.readAsArrayBuffer\s*\([^)]*\))":            ("FileReader.readAsArrayBuffer()", {"FILE_PATH_MANIPULATION"}),
            r"(\.readAsBinaryString\s*\([^)]*\))":           ("FileReader.readAsBinaryString()", {"FILE_PATH_MANIPULATION"}),
            r"(\.readAsDataURL\s*\([^)]*\))":                ("FileReader.readAsDataURL()", {"FILE_PATH_MANIPULATION"}),
            r"(\.readAsText\s*\([^)]*\))":                   ("FileReader.readAsText()", {"FILE_PATH_MANIPULATION"}),
            r"(\.readAsFile\s*\([^)]*\))":                   ("FileReader.readAsFile()", {"FILE_PATH_MANIPULATION"}),
            r"(\.root\.getFile\s*\([^)]*\))":                ("FileReader.root.getFile()", {"FILE_PATH_MANIPULATION"}),
            # ── PortSwigger cat 11: Client-side SQL injection ────────────────
            r"(\.executeSql\s*\([^)]*\))":                   ("executeSql()", {"CLIENT_SIDE_SQLI"}),
            # ── PortSwigger cat 12: HTML5 storage manipulation ───────────────
            r"(sessionStorage\.setItem\s*\([^)]*\))":        ("sessionStorage.setItem()", {"STORAGE_MANIPULATION"}),
            r"(localStorage\.setItem\s*\([^)]*\))":          ("localStorage.setItem()", {"STORAGE_MANIPULATION"}),
            # ── PortSwigger cat 13: XPath injection ─────────────────────────
            r"(document\.evaluate\s*\([^)]*\))":             ("document.evaluate()", {"XPATH_INJECTION"}),
            r"((?<!document)\.evaluate\s*\([^)]*\))":        ("element.evaluate()", {"XPATH_INJECTION"}),
            # ── PortSwigger cat 14: JSON injection ──────────────────────────
            r"(JSON\.parse\s*\([^)]*\))":                    ("JSON.parse()", {"JSON_INJECTION"}),
            r"(jQuery\.parseJSON\s*\([^)]*\))":              ("jQuery.parseJSON()", {"JSON_INJECTION"}),
            r"(\$\.parseJSON\s*\([^)]*\))":                  ("$.parseJSON()", {"JSON_INJECTION"}),
            # ── PortSwigger cat 15: DOM data manipulation ────────────────────
            r"(\.textContent\s*=[^;]*)":                     ("element.textContent=", {"DOM_DATA_MANIPULATION"}),
            r"(\.innerText\s*=[^;]*)":                       ("element.innerText=", {"DOM_DATA_MANIPULATION"}),
            r"(\.outerText\s*=[^;]*)":                       ("element.outerText=", {"DOM_DATA_MANIPULATION"}),
            r"(\.cssText\s*=[^;]*)":                         ("element.cssText=", {"DOM_DATA_MANIPULATION"}),
            r"(\.backgroundImage\s*=[^;]*)":                 ("element.backgroundImage=", {"DOM_DATA_MANIPULATION"}),
            r"(\.codebase\s*=[^;]*)":                        ("element.codebase=", {"DOM_DATA_MANIPULATION"}),
            r"(document\.title\s*=[^;]*)":                   ("document.title=", {"DOM_DATA_MANIPULATION"}),
            r"(document\.implementation\.createHTMLDocument\s*\([^)]*\))": ("document.implementation.createHTMLDocument()", {"DOM_DATA_MANIPULATION"}),
            r"(history\.pushState\s*\([^)]*\))":             ("history.pushState()", {"DOM_DATA_MANIPULATION"}),
            r"(history\.replaceState\s*\([^)]*\))":          ("history.replaceState()", {"DOM_DATA_MANIPULATION"}),
            # ── PortSwigger cat 16: DOM-based DoS ───────────────────────────
            r"(\brequestFileSystem\s*\([^)]*\))":            ("requestFileSystem()", {"DOM_DOS"}),
            r"(new\s+RegExp\s*\([^)]*\))":                   ("RegExp()", {"DOM_DOS"}),
        }

        for pattern, (sink_name, vulns) in dom_sinks.items():
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for matched_code in matches:
                clean_code = " ".join(matched_code.split())[:100]
                finding = f"{sink_name}: {clean_code}"
                detections.setdefault(sink_name, set()).add(finding)
                detections[sink_name].update(vulns)

                if JavaScriptAnalyzer.has_user_input_source(js_content):
                    detections[sink_name].add("REFLECTED")
                    if "jQuery" in sink_name or "$" in sink_name:
                        detections[sink_name].add("JQUERY_USER_INPUT")

        # 3. jQuery-specific dangerous patterns
        jquery_input_patterns = [
            (
                r"(\$\([^)]+\)\.(?:html|append|prepend|after|before|replaceWith|wrap|wrapInner)\s*\([^)]*(?:location\.search|window\.location\.search|URLSearchParams)[^)]*\))",
                "JQUERY_DOM_XSS",
            ),
            (
                r"(\.(?:html|append|prepend|after|before|replaceWith)\s*\([^)]*\$\.[^)]+\))",
                "JQUERY_PARAM_XSS",
            ),
            (
                r"(\$\(\s*(?:location\.search|window\.location\.search|URLSearchParams)[^)]*\))",
                "JQUERY_CONSTRUCTOR_XSS",
            ),
        ]

        for pattern, finding_type in jquery_input_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for matched_text in matches:
                clean_match = " ".join(matched_text.split())[:100]
                finding = f"{finding_type}: {clean_match}"
                detections.setdefault("JQUERY_XSS", set()).add(finding)

        # 4. AJAX / Fetch with user input
        ajax_patterns = [
            (r"(XMLHttpRequest[^;]*\.open\s*\([^)]*\))", "XMLHttpRequest.open()"),
            (r"(fetch\s*\([^)]*\))", "fetch()"),
            (r"(\$\.(?:ajax|get|post)\s*\([^)]*\))", "jQuery.ajax()"),
        ]

        for pattern, func_name in ajax_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE | re.DOTALL)
            for matched_text in matches:
                if JavaScriptAnalyzer.has_user_input_in_ajax(js_content):
                    clean_match = " ".join(matched_text.split())[:100]
                    finding = f"{func_name}: {clean_match}"
                    detections.setdefault("AJAX/fetch", set()).add(finding)
                    detections["AJAX/fetch"].update({"SSRF", "REFLECTED"})

        # 5. Hardcoded secrets
        secret_patterns = [
            (
                r'(?:const|let|var)\s+(\w+)\s*=\s*["\']([a-zA-Z0-9]{20,})["\']',
                "detect_type",
            ),
            (r'(\w+)\s*:\s*["\']([a-zA-Z0-9]{20,})["\']', "detect_type"),
            (r'(?:const|let|var)\s+(\w+)\s*=\s*["\']([^"\']{8,})["\']', "PASSWORD"),
            (
                r'(?:const|let|var)\s+(\w+)\s*=\s*["\'](AKIA[0-9A-Z]{16})["\']',
                "AWS_KEY",
            ),
            (
                r'(?:const|let|var)\s+(\w+)\s*=\s*["\'](eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})["\']',
                "SECRET",
            ),
            (
                r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
                "API_KEY",
            ),
            (r'(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{8,})["\']', "PASSWORD"),
            (r'(?:secret|token)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']', "SECRET"),
            (
                r'(?:access[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9._-]{20,})["\']',
                "ACCESS_TOKEN",
            ),
            (r"(AKIA[0-9A-Z]{16})", "AWS_KEY"),
        ]

        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                groups = match.groups()

                if len(groups) == 2:
                    var_name = groups[0]
                    secret_value = groups[1]

                    if secret_type == "detect_type":
                        detection_key = detect_secret_type(var_name, secret_value)
                    else:
                        detection_key = secret_type

                    if len(secret_value) > 12:
                        display = f"{secret_value[:8]}...{secret_value[-4:]}"
                    else:
                        display = secret_value

                    finding = f"{var_name}: {display}"

                else:
                    secret_value = groups[0]
                    var_name = secret_type.lower()
                    detection_key = secret_type

                    if len(secret_value) > 12:
                        display = f"{secret_value[:8]}...{secret_value[-4:]}"
                    else:
                        display = secret_value

                    finding = f"{var_name}: {display}"

                detections.setdefault(detection_key, set()).add(finding)
                detections[detection_key].add("EXPOSED")

        # 6. Prototype pollution
        proto_matches = re.findall(
            r"(__proto__|constructor\[.*?\]|\.prototype\.\w+)", js_content
        )
        for matched in proto_matches:
            detections.setdefault("__proto__", set()).add(
                f"PROTOTYPE_POLLUTION: {matched[:50]}"
            )

        # 7. postMessage without origin check
        postmsg_matches = re.findall(
            r'(addEventListener\s*\(\s*["\']message["\'][^)]*\))',
            js_content,
            re.IGNORECASE,
        )
        for matched in postmsg_matches:
            if not re.search(r"(event|e|msg)\.origin", matched, re.IGNORECASE):
                detections.setdefault("postMessage", set()).add(
                    f"POSTMESSAGE_NO_ORIGIN: {matched[:80]}"
                )

        # 8. Critical source → sink flow
        if JavaScriptAnalyzer.has_user_input_source(js_content):
            flows = JavaScriptAnalyzer.detect_critical_flow(js_content)
            for sink, flow_tags in flows.items():
                detections.setdefault(sink, set()).update({"CRITICAL_FLOW"})
                detections[sink].update(flow_tags)

            jquery_flows = JavaScriptAnalyzer.detect_jquery_critical_flow(js_content)
            for sink, flow_tags in jquery_flows.items():
                detections.setdefault(sink, set()).update({"JQUERY_CRITICAL_FLOW"})
                detections[sink].update(flow_tags)

        return detections

    @staticmethod
    def detect_jquery_critical_flow(js_content: str) -> Dict[str, Set[str]]:
        """Detect jQuery-specific critical flows from user input to dangerous sinks"""
        flows = {}

        jquery_selectors_with_input = re.findall(
            r'\$\(\s*["\']?[^"\']*(location\.search|window\.location\.search|URLSearchParams|location\.hash)',
            js_content,
            re.IGNORECASE,
        )

        if jquery_selectors_with_input:
            jquery_dangerous_methods = [
                "html",
                "append",
                "prepend",
                "after",
                "before",
                "replaceWith",
                "wrap",
                "wrapInner",
                "replaceAll",
            ]

            for method in jquery_dangerous_methods:
                pattern = rf"\$\([^)]+\)\.{method}\s*\("
                if re.search(pattern, js_content, re.IGNORECASE):
                    flows[f"jQuery.{method}()"] = {"XSS", "JQUERY", "USER_INPUT"}

        return flows

    @staticmethod
    def has_user_input_source(js_content: str) -> bool:
        """Check if JavaScript extracts user input from URL/location"""
        source_patterns = [
            r"window\.location\.search",
            r"location\.search",
            r"document\.location\.search",
            r"window\.location\.hash",
            r"location\.hash",
            r"document\.referrer",
            r"document\.URL",
            r"URLSearchParams",
        ]

        for pattern in source_patterns:
            if re.search(pattern, js_content, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def has_user_input_in_ajax(js_content: str) -> bool:
        """Check if AJAX request includes user input"""
        ajax_with_input_patterns = [
            r"\.open\s*\([^)]*(?:location\.search|window\.location\.search)",
            r"fetch\s*\([^)]*(?:location\.search|window\.location\.search)",
            r"\$\.(?:ajax|get|post)\s*\([^)]*(?:location\.search|window\.location\.search)",
        ]

        for pattern in ajax_with_input_patterns:
            if re.search(pattern, js_content, re.IGNORECASE | re.DOTALL):
                return True
        return False

    @staticmethod
    def detect_critical_flow(js_content: str) -> Dict[str, Set[str]]:
        """
        Detect critical data flows from user input sources to dangerous sinks.

        This enhanced version:
        1. Tracks ALL user input sources
        2. Follows variable assignments and transformations
        3. Detects when tainted data reaches dangerous sinks
        4. Handles multi-step flows (var1 → var2 → var3 → sink)
        5. Returns detailed flow information
        """
        flows = {}

        if not js_content or len(js_content) < 10:
            return flows

        # ========================================
        # PHASE 1: IDENTIFY ALL TAINTED SOURCES
        # ========================================

        tainted_vars = {}  # {var_name: {source, confidence, chain}}

        # Source patterns with confidence scores
        source_patterns = [
            # High confidence sources (user-controlled)
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:new\s+)?URLSearchParams\([^)]*\)\.get\s*\(",
                "URLSearchParams.get()",
                10,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*\([^)]*URLSearchParams[^)]*\)\.get\s*\(",
                "URLSearchParams.get()",
                10,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.search",
                "location.search",
                10,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.hash",
                "location.hash",
                10,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*document\.referrer",
                "document.referrer",
                9,
            ),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*document\.URL", "document.URL", 9),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*document\.documentURI",
                "document.documentURI",
                9,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.href",
                "location.href",
                9,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.pathname",
                "location.pathname",
                8,
            ),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?name", "window.name", 8),
            # Medium confidence sources (potentially user-controlled)
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*localStorage\.getItem\s*\(",
                "localStorage",
                7,
            ),
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*sessionStorage\.getItem\s*\(",
                "sessionStorage",
                7,
            ),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*document\.cookie", "document.cookie", 7),
            # AJAX/XHR responses (medium confidence)
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:\w+)\.responseText",
                "XHR.responseText",
                6,
            ),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:\w+)\.response", "XHR.response", 6),
            # postMessage (high confidence if origin not checked)
            (
                r"(?:var|let|const)\s+(\w+)\s*=\s*(?:event|e|msg)\.data",
                "postMessage.data",
                8,
            ),
        ]

        # Find all tainted variables
        for pattern, source_name, confidence in source_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                var_name = match.group(1)
                if (
                    var_name not in tainted_vars
                    or tainted_vars[var_name]["confidence"] < confidence
                ):
                    tainted_vars[var_name] = {
                        "source": source_name,
                        "confidence": confidence,
                        "chain": [source_name],
                        "line": match.group(0),
                    }

        # ========================================
        # PHASE 2: TRACK VARIABLE ASSIGNMENTS (TAINT PROPAGATION)
        # ========================================

        # Pattern: var2 = var1 (or var2 = var1.something)
        assignment_patterns = [
            r"(?:var|let|const)\s+(\w+)\s*=\s*(\w+)",  # var b = a
            r"(\w+)\s*=\s*(\w+)",  # b = a
            r"(?:var|let|const)\s+(\w+)\s*=\s*(\w+)\.\w+",  # var b = a.property
            r"(\w+)\s*=\s*(\w+)\.\w+",  # b = a.property
            r"(?:var|let|const)\s+(\w+)\s*=\s*(\w+)\[",  # var b = a[...]
            r"(\w+)\s*=\s*(\w+)\[",  # b = a[...]
        ]

        # Propagate taint through assignments (max 5 iterations to avoid infinite loops)
        for iteration in range(5):
            new_taints = {}

            for pattern in assignment_patterns:
                for match in re.finditer(pattern, js_content):
                    target_var = match.group(1)
                    source_var = match.group(2)

                    # If source is tainted, taint the target
                    if source_var in tainted_vars:
                        source_info = tainted_vars[source_var]

                        # Propagate with slightly reduced confidence
                        new_confidence = max(source_info["confidence"] - 1, 5)

                        if (
                            target_var not in tainted_vars
                            or tainted_vars[target_var]["confidence"] < new_confidence
                        ):
                            new_taints[target_var] = {
                                "source": source_info["source"],
                                "confidence": new_confidence,
                                "chain": source_info["chain"] + [target_var],
                                "propagated_from": source_var,
                            }

            # Add new taints
            if new_taints:
                tainted_vars.update(new_taints)
            else:
                break  # No new taints found, stop iterating

        # ========================================
        # PHASE 3: DETECT TAINTED DATA IN SINKS
        # ========================================

        # Define dangerous sinks with severity
        dangerous_sinks = {
            "eval()": {
                "patterns": [
                    r"\beval\s*\(\s*[^)]*\b({var})\b",
                    r"\beval\s*\([^)]*[+\s]+({var})",
                ],
                "severity": {"RCE", "XSS", "CRITICAL_FLOW"},
            },
            "Function()": {
                "patterns": [
                    r"new\s+Function\s*\([^)]*\b({var})\b",
                    r"Function\s*\([^)]*\b({var})\b",
                ],
                "severity": {"RCE", "XSS", "CRITICAL_FLOW"},
            },
            "setTimeout()": {
                "patterns": [
                    r"setTimeout\s*\(\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "RCE", "CRITICAL_FLOW"},
            },
            "setInterval()": {
                "patterns": [
                    r"setInterval\s*\(\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "RCE", "CRITICAL_FLOW"},
            },
            "document.write()": {
                "patterns": [
                    r"document\.write\s*\(\s*[^)]*\b({var})\b",
                    r"document\.write\s*\([^)]*[+\s]+({var})",
                ],
                "severity": {"XSS", "CRITICAL_FLOW"},
            },
            "document.writeln()": {
                "patterns": [
                    r"document\.writeln\s*\(\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "CRITICAL_FLOW"},
            },
            "innerHTML": {
                "patterns": [
                    r"\.innerHTML\s*=\s*[^;]*\b({var})\b",
                    r"\.innerHTML\s*=\s*[^;]*[+\s]+({var})",
                ],
                "severity": {"XSS", "CRITICAL_FLOW"},
            },
            "outerHTML": {
                "patterns": [
                    r"\.outerHTML\s*=\s*[^;]*\b({var})\b",
                ],
                "severity": {"XSS", "CRITICAL_FLOW"},
            },
            "insertAdjacentHTML()": {
                "patterns": [
                    r"\.insertAdjacentHTML\s*\([^,]*,\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "CRITICAL_FLOW"},
            },
            "location.href": {
                "patterns": [
                    r"(?:window\.)?location\.href\s*=\s*[^;]*\b({var})\b",
                    r"(?:window\.)?location\s*=\s*[^;]*\b({var})\b",
                ],
                "severity": {"OPEN_REDIRECT", "XSS", "CRITICAL_FLOW"},
            },
            "jQuery.html()": {
                "patterns": [
                    r"\$\([^)]+\)\.html\s*\(\s*[^)]*\b({var})\b",
                    r"jQuery\([^)]+\)\.html\s*\(\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "JQUERY", "CRITICAL_FLOW"},
            },
            "jQuery.append()": {
                "patterns": [
                    r"\$\([^)]+\)\.append\s*\(\s*[^)]*\b({var})\b",
                ],
                "severity": {"XSS", "JQUERY", "CRITICAL_FLOW"},
            },
            "jQuery.$(selector)": {
                "patterns": [
                    r"\$\s*\(\s*({var})\s*\)",
                    r"jQuery\s*\(\s*({var})\s*\)",
                ],
                "severity": {"XSS", "JQUERY", "CRITICAL_FLOW"},
            },
        }

        # Check each tainted variable against each sink
        for var_name, var_info in tainted_vars.items():
            for sink_name, sink_info in dangerous_sinks.items():
                for pattern in sink_info["patterns"]:
                    actual_pattern = pattern.replace("{var}", re.escape(var_name))

                    match = re.search(actual_pattern, js_content, re.IGNORECASE)
                    if match:
                        # Build detailed flow information
                        flow_key = f"{sink_name}[{var_name}]"

                        flows[flow_key] = sink_info["severity"].copy()
                        flows[flow_key].add("USER_INPUT")
                        flows[flow_key].add(f"SOURCE:{var_info['source']}")
                        flows[flow_key].add(f"CONFIDENCE:{var_info['confidence']}")
                        flows[flow_key].add(f"CHAIN:{' → '.join(var_info['chain'])}")
                        flows[flow_key].add(f"TAINTED_VAR:{var_name}")

                        # If high confidence, mark as confirmed
                        if var_info["confidence"] >= 8:
                            flows[flow_key].add("CONFIRMED")

                        break  # Only match once per variable-sink pair

        # ========================================
        # PHASE 4: SPECIAL CASE - AJAX WITH USER INPUT (SSRF)
        # ========================================

        ajax_patterns = [
            r"XMLHttpRequest\s*\(\s*\).*\.open\s*\(",
            r"fetch\s*\(",
            r"\$\.(?:ajax|get|post)\s*\(",
            r"axios\.(?:get|post|put|delete)\s*\(",
        ]

        for pattern in ajax_patterns:
            match = re.search(pattern, js_content, re.IGNORECASE | re.DOTALL)
            if match:
                # Check if any tainted variable is in the AJAX call context
                ajax_context = js_content[
                    match.start() : min(match.end() + 200, len(js_content))
                ]

                for var_name, var_info in tainted_vars.items():
                    if re.search(rf"\b{re.escape(var_name)}\b", ajax_context):
                        flow_key = f"AJAX[{var_name}]"
                        flows[flow_key] = {"SSRF", "CRITICAL_FLOW", "USER_INPUT"}
                        flows[flow_key].add(f"SOURCE:{var_info['source']}")
                        flows[flow_key].add(f"TAINTED_VAR:{var_name}")
                        break

        # ========================================
        # PHASE 5: TEMPLATE LITERAL INJECTION
        # ========================================

        # Pattern: `<tag>${var}</tag>`
        for var_name, var_info in tainted_vars.items():
            template_pattern = rf"`[^`]*\$\{{\s*{re.escape(var_name)}\s*\}}[^`]*`"
            match = re.search(template_pattern, js_content)
            if match:
                # Check if it's in HTML context
                if re.search(r"<[^>]+>", match.group(0)):
                    flow_key = f"TEMPLATE_LITERAL_XSS[{var_name}]"
                    flows[flow_key] = {
                        "XSS",
                        "CRITICAL_FLOW",
                        "USER_INPUT",
                        "TEMPLATE_LITERAL",
                    }
                    flows[flow_key].add(f"SOURCE:{var_info['source']}")
                    flows[flow_key].add(f"TAINTED_VAR:{var_name}")

        return flows

    @staticmethod
    def extract_endpoints(js_content: str) -> List[Dict]:
        """Extract hardcoded API endpoints, paths, and URLs from JS"""
        findings = []
        if not js_content:
            return findings

        seen = set()

        # Quoted path strings that look like API routes
        path_patterns = [
            r'["\`](\/?(?:api|v\d+|rest|graphql|gql|internal|admin|auth|user|account|payment|upload|download|webhook|callback|oauth|token|search|config|settings|dashboard|manage|report|export|import|debug|test|dev|staging)[\/\w\-\.%{}:]*)["\`]',
            r'["\`](\/[\w\-]+\/[\w\-\/\.%{}:]{3,})["\`]',
            r'fetch\s*\(\s*["\`]([^"\'`\s]{5,})["\`]',
            r'axios\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*["\`]([^"\'`\s]{5,})["\`]',
            r'\$\.(?:ajax|get|post)\s*\(\s*["\`]([^"\'`\s]{5,})["\`]',
            r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*["\`]([^"\'`\s]{5,})["\`]',
            r'(?:url|endpoint|path|route|baseUrl|baseURL|API_URL|apiUrl|apiEndpoint)\s*[:=]\s*["\`]([^"\'`\s]{5,})["\`]',
        ]

        for pattern in path_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                path = match.group(1).strip()
                if path in seen or len(path) > 200:
                    continue
                # Filter noise: skip single words without slash or dot
                if '/' not in path and '.' not in path:
                    continue
                seen.add(path)
                findings.append({
                    'type': 'ENDPOINT',
                    'value': path,
                    'context': match.group(0)[:120]
                })

        return findings

    @staticmethod
    def extract_cloud_infrastructure(js_content: str) -> List[Dict]:
        """Extract cloud service URLs, bucket names, Firebase, Cognito, etc."""
        findings = []
        if not js_content:
            return findings

        cloud_patterns = [
            # S3 buckets
            (r'([\w\-]+\.s3(?:[\.\-][\w\-]+)?\.amazonaws\.com)', 'S3_BUCKET'),
            (r's3://([^\s"\'`<>]+)', 'S3_BUCKET_URI'),
            # Firebase
            (r'([\w\-]+\.firebaseio\.com)', 'FIREBASE_DB'),
            (r'([\w\-]+\.firebaseapp\.com)', 'FIREBASE_APP'),
            (r'([\w\-]+\.web\.app)', 'FIREBASE_HOSTING'),
            # Google Cloud
            (r'(storage\.googleapis\.com\/[\w\-]+)', 'GCS_BUCKET'),
            (r'["\']project["\']?\s*:\s*["\']([a-z][\w\-]{4,30})["\']', 'GCP_PROJECT_ID'),
            # Azure
            (r'([\w\-]+\.blob\.core\.windows\.net)', 'AZURE_BLOB'),
            (r'([\w\-]+\.azurewebsites\.net)', 'AZURE_WEBAPP'),
            # AWS Cognito
            (r'([\w\-]+\.auth\.[\w\-]+\.amazoncognito\.com)', 'COGNITO_DOMAIN'),
            (r'(us[\-\w]+_[A-Za-z0-9]+)', 'COGNITO_USER_POOL'),
            # Generic cloud API keys patterns
            (r'(AIza[0-9A-Za-z\-_]{35})', 'GOOGLE_API_KEY'),
            (r'(AKIA[0-9A-Z]{16})', 'AWS_ACCESS_KEY'),
            # Internal/staging hostnames
            (r'["\`](https?://(?:internal|intranet|staging|dev|test|uat|preprod|localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\'`<>]{0,100})["\`]', 'INTERNAL_URL'),
        ]

        seen = set()
        for pattern, cloud_type in cloud_patterns:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                val = match.group(1)
                key = f"{cloud_type}:{val}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    'type': cloud_type,
                    'value': val,
                    'context': match.group(0)[:120]
                })

        return findings

    @staticmethod
    def detect_source_maps(js_content: str, url: str) -> List[Dict]:
        """Detect source map references that expose original source code"""
        findings = []
        if not js_content:
            return findings

        # Inline sourceMappingURL comment (end of minified JS)
        map_comment = re.search(
            r'//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)', js_content)
        if map_comment:
            map_url = map_comment.group(1).strip()
            findings.append({
                'type': 'SOURCE_MAP_REF',
                'value': map_url,
                'severity': 'HIGH',
                'context': f'sourceMappingURL={map_url}',
                'note': 'Download this .map file to recover original unminified source'
            })

        # Inline base64 source map
        if 'sourceMappingURL=data:application/json;base64,' in js_content:
            findings.append({
                'type': 'INLINE_SOURCE_MAP',
                'value': 'base64 encoded',
                'severity': 'HIGH',
                'context': 'Inline base64 source map detected',
                'note': 'Inline source map exposes original source code directly'
            })

        # URL is itself a .map file
        if url and url.endswith('.map'):
            findings.append({
                'type': 'IS_SOURCE_MAP',
                'value': url,
                'severity': 'HIGH',
                'context': f'Response is a source map file: {url}',
                'note': 'Source map file directly accessible - original source exposed'
            })

        # Webpack-specific: references to chunk files
        webpack_chunks = re.findall(
            r'["\`]([\w\.\-]+\.chunk\.js)["\`]', js_content)
        seen_chunks = set()
        for chunk in webpack_chunks:
            if chunk not in seen_chunks:
                seen_chunks.add(chunk)
                findings.append({
                    'type': 'WEBPACK_CHUNK',
                    'value': chunk,
                    'severity': 'MEDIUM',
                    'context': f'Webpack chunk reference: {chunk}',
                    'note': 'Fetch chunk files for broader endpoint/secret coverage'
                })

        return findings

    @staticmethod
    def detect_open_redirects(js_content: str) -> List[Dict]:
        """Detect open redirect sinks driven by user-controlled input"""
        findings = []
        if not js_content:
            return findings

        redirect_sinks = [
            (r'(?:window\.)?location\.href\s*=\s*([^;]{5,80})', 'location.href='),
            (r'(?:window\.)?location\.replace\s*\(\s*([^)]{5,80})\)', 'location.replace()'),
            (r'(?:window\.)?location\.assign\s*\(\s*([^)]{5,80})\)', 'location.assign()'),
            (r'window\.open\s*\(\s*([^,)]{5,80})', 'window.open()'),
            (r'(?:window\.)?navigate\s*\(\s*([^)]{5,80})\)', 'navigate()'),
        ]

        user_input_indicators = [
            'location.search', 'location.hash', 'URLSearchParams',
            'getParam', 'getParameter', '.get(', 'document.referrer',
            'location.href', 'document.URL', 'window.name'
        ]

        for pattern, sink_name in redirect_sinks:
            for match in re.finditer(pattern, js_content, re.IGNORECASE):
                value = match.group(1).strip()
                # Check if value contains or is derived from user input
                has_user_input = any(ind.lower() in value.lower() for ind in user_input_indicators)
                # Or if a variable name (not a plain string literal) is assigned
                is_variable = not re.match(r'^["\`\']', value.strip())

                if has_user_input or is_variable:
                    severity = 'HIGH' if has_user_input else 'MEDIUM'
                    findings.append({
                        'type': 'OPEN_REDIRECT',
                        'sink': sink_name,
                        'value': value[:100],
                        'severity': severity,
                        'user_input': has_user_input,
                        'context': match.group(0)[:150]
                    })

        return findings

    @staticmethod
    def detect_cors_issues(js_content: str) -> List[Dict]:
        """Detect CORS misconfigurations in fetch/XHR calls"""
        findings = []
        if not js_content:
            return findings

        # fetch() with credentials: 'include' or credentials: true
        cred_fetch = re.findall(
            r'fetch\s*\([^)]*\)\s*\.then|fetch\s*\([^{]*\{[^}]*credentials\s*:\s*["\']include["\']',
            js_content, re.IGNORECASE | re.DOTALL)
        if cred_fetch or re.search(r'credentials\s*:\s*["\']include["\']', js_content, re.IGNORECASE):
            findings.append({
                'type': 'CORS_CREDENTIALS_INCLUDE',
                'severity': 'HIGH',
                'context': 'fetch() with credentials: include detected',
                'note': 'If server reflects Origin with ACAO, this enables cross-origin session theft'
            })

        # XMLHttpRequest withCredentials = true
        if re.search(r'withCredentials\s*=\s*true', js_content, re.IGNORECASE):
            findings.append({
                'type': 'XHR_WITH_CREDENTIALS',
                'severity': 'HIGH',
                'context': 'XMLHttpRequest.withCredentials = true',
                'note': 'XHR with credentials - test CORS policy on target endpoints'
            })

        # Dynamic origin reflection pattern
        dynamic_origin = re.findall(
            r'(?:origin|Origin)\s*[:=]\s*(?:request\.headers|req\.headers|event\.origin|\w+\.origin)',
            js_content, re.IGNORECASE)
        if dynamic_origin:
            findings.append({
                'type': 'DYNAMIC_ORIGIN',
                'severity': 'HIGH',
                'context': str(dynamic_origin[0])[:120],
                'note': 'Dynamic origin reflection - potential CORS misconfiguration'
            })

        return findings

    @staticmethod
    def detect_graphql(js_content: str) -> List[Dict]:
        """Detect GraphQL usage, introspection queries, and exposed operations"""
        findings = []
        if not js_content:
            return findings

        # Introspection query
        if re.search(r'__schema|__type|IntrospectionQuery', js_content, re.IGNORECASE):
            findings.append({
                'type': 'GRAPHQL_INTROSPECTION',
                'severity': 'MEDIUM',
                'context': 'GraphQL introspection query found in JS',
                'note': 'Test if introspection is enabled on the GraphQL endpoint'
            })

        # GraphQL endpoint references
        gql_endpoints = re.findall(
            r'["\`](\/graphql[^\s"\'`<>]*)["\`]', js_content, re.IGNORECASE)
        seen = set()
        for ep in gql_endpoints:
            if ep not in seen:
                seen.add(ep)
                findings.append({
                    'type': 'GRAPHQL_ENDPOINT',
                    'severity': 'MEDIUM',
                    'value': ep,
                    'context': f'GraphQL endpoint reference: {ep}'
                })

        # Hardcoded GraphQL queries/mutations (potential info disclosure)
        mutations = re.findall(
            r'mutation\s+(\w+)\s*[({]', js_content, re.IGNORECASE)
        for mut in set(mutations[:10]):
            findings.append({
                'type': 'GRAPHQL_MUTATION',
                'severity': 'MEDIUM',
                'value': mut,
                'context': f'GraphQL mutation: {mut}',
                'note': 'Test this mutation for authorization bypass and mass assignment'
            })

        queries = re.findall(
            r'query\s+(\w+)\s*[({]', js_content, re.IGNORECASE)
        for q in set(queries[:10]):
            findings.append({
                'type': 'GRAPHQL_QUERY',
                'severity': 'LOW',
                'value': q,
                'context': f'GraphQL query: {q}'
            })

        return findings

    @staticmethod
    def detect_websocket_issues(js_content: str) -> List[Dict]:
        """Detect WebSocket usage and potential security issues"""
        findings = []
        if not js_content:
            return findings

        # WebSocket instantiation
        ws_matches = re.finditer(
            r'new\s+WebSocket\s*\(\s*([^)]{5,150})\)', js_content, re.IGNORECASE)
        for match in ws_matches:
            url_arg = match.group(1).strip()
            is_dynamic = not re.match(r'^["\`\']', url_arg)
            user_input_indicators = ['location', 'param', 'URLSearchParams', '.get(', 'document.URL']
            has_user_input = any(ind.lower() in url_arg.lower() for ind in user_input_indicators)

            severity = 'HIGH' if has_user_input else 'MEDIUM'
            note = 'WebSocket URL is user-controlled - test for WebSocket hijacking/SSRF' if has_user_input \
                else 'WebSocket found - check origin validation and authentication'

            findings.append({
                'type': 'WEBSOCKET',
                'severity': severity,
                'value': url_arg[:100],
                'user_controlled': has_user_input,
                'context': match.group(0)[:150],
                'note': note
            })

        # postMessage without origin check (already in analyze_js_file but add detail)
        on_message = re.findall(
            r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(\w+)', js_content, re.IGNORECASE)
        for handler in on_message:
            # Check if handler function verifies event.origin
            handler_body_match = re.search(
                rf'(?:function\s+{re.escape(handler)}\s*\(|{re.escape(handler)}\s*=\s*function\s*\()'
                r'[^{{]*\{{([^}}]{{0,500}})',
                js_content, re.IGNORECASE | re.DOTALL)
            if handler_body_match:
                body = handler_body_match.group(1)
                if not re.search(r'event\.origin|e\.origin|origin\s*===|origin\s*!==', body, re.IGNORECASE):
                    findings.append({
                        'type': 'POSTMESSAGE_NO_ORIGIN_CHECK',
                        'severity': 'HIGH',
                        'value': handler,
                        'context': f'Message handler "{handler}" has no origin validation',
                        'note': 'Handler accepts postMessage from any origin - test for cross-origin message injection'
                    })

        # ── WebSocket authentication check ────────────────────────────────
        # Re-scan for WebSocket instantiations to flag missing auth signals
        for ws_match in re.finditer(
                r'new\s+WebSocket\s*\(\s*([^)]{5,150})\)', js_content, re.IGNORECASE):
            ws_url_arg = ws_match.group(1).lower()
            if not any(t in ws_url_arg for t in
                       ['token=', 'auth=', 'key=', 'session=', 'api_key=']):
                # Check surrounding context for auth signals
                ctx_start = max(0, ws_match.start() - 300)
                ctx_end   = min(len(js_content), ws_match.end() + 400)
                ctx_snip  = js_content[ctx_start:ctx_end]
                if not re.search(
                        r'cookie|Bearer|Authorization|[Aa]ccess[Tt]oken|auth[Tt]oken',
                        ctx_snip, re.IGNORECASE):
                    findings.append({
                        'type': 'WEBSOCKET_NO_AUTH',
                        'severity': 'MEDIUM',
                        'value': ws_match.group(1)[:80],
                        'context': ws_match.group(0)[:150],
                        'note': 'WebSocket connection has no visible auth token — test for unauthenticated access',
                    })

        return findings

    @staticmethod
    def extract_subdomains_and_hosts(js_content: str) -> List[Dict]:
        """Extract hardcoded hostnames, subdomains, and internal URLs"""
        findings = []
        if not js_content:
            return findings

        seen = set()

        # Full URLs
        url_pattern = r'["\`](https?://[\w\-\.]+\.[\w]{2,}(?:/[^\s"\'`<>]{0,100})?)["\`]'
        for match in re.finditer(url_pattern, js_content, re.IGNORECASE):
            url = match.group(1)
            if url in seen or len(url) > 200:
                continue
            seen.add(url)

            from urllib.parse import urlparse as _urlparse
            try:
                host = _urlparse(url).netloc
            except Exception:
                host = url

            is_internal = bool(re.search(
                r'(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|'
                r'internal|intranet|staging|dev\.|test\.|uat\.|preprod\.)', host, re.IGNORECASE))

            findings.append({
                'type': 'INTERNAL_HOST' if is_internal else 'HARDCODED_URL',
                'severity': 'HIGH' if is_internal else 'INFO',
                'value': url,
                'host': host,
                'context': match.group(0)[:120]
            })

        return findings

    @staticmethod
    def detect_token_storage(js_content: str) -> List[Dict]:
        """Detect where tokens/JWTs are stored and how they are sent"""
        findings = []
        if not js_content:
            return findings

        # localStorage storing tokens
        ls_store = re.findall(
            r'localStorage\s*\.\s*setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]{0,80})\)',
            js_content, re.IGNORECASE)
        for key, value in ls_store:
            if any(t in key.lower() for t in ['token', 'jwt', 'auth', 'session', 'key', 'secret', 'pass']):
                findings.append({
                    'type': 'TOKEN_IN_LOCALSTORAGE',
                    'severity': 'MEDIUM',
                    'key': key,
                    'value': value.strip()[:80],
                    'context': f'localStorage.setItem("{key}", ...)',
                    'note': 'Token in localStorage is accessible to any JS - XSS leads to full token theft'
                })

        # sessionStorage storing tokens
        ss_store = re.findall(
            r'sessionStorage\s*\.\s*setItem\s*\(\s*["\']([^"\']+)["\']\s*,\s*([^)]{0,80})\)',
            js_content, re.IGNORECASE)
        for key, value in ss_store:
            if any(t in key.lower() for t in ['token', 'jwt', 'auth', 'session', 'key']):
                findings.append({
                    'type': 'TOKEN_IN_SESSIONSTORAGE',
                    'severity': 'LOW',
                    'key': key,
                    'value': value.strip()[:80],
                    'context': f'sessionStorage.setItem("{key}", ...)',
                    'note': 'Token in sessionStorage - cleared on tab close but still XSS-accessible'
                })

        # Authorization header construction
        auth_header = re.findall(
            r'["\']Authorization["\']\s*:\s*([^,}\n]{5,120})', js_content, re.IGNORECASE)
        for val in auth_header[:5]:
            findings.append({
                'type': 'AUTH_HEADER_CONSTRUCTION',
                'severity': 'INFO',
                'value': val.strip()[:120],
                'context': f'Authorization: {val.strip()[:80]}',
                'note': 'Check where this token comes from and how long it lives'
            })

        # JWT decode without verification (atob on eyJ)
        jwt_decode = re.findall(
            r'atob\s*\(\s*([^)]{3,80})\)', js_content, re.IGNORECASE)
        for arg in jwt_decode:
            if 'eyJ' in arg or 'token' in arg.lower() or 'jwt' in arg.lower() or 'split' in arg.lower():
                findings.append({
                    'type': 'JWT_CLIENT_DECODE',
                    'severity': 'LOW',
                    'value': arg.strip()[:80],
                    'context': f'atob({arg.strip()[:60]})',
                    'note': 'JWT decoded client-side - check claims for privilege/role info'
                })

        return findings

    @staticmethod
    def integrate_js_detection(flow, all_param_detected):
        """Add this call in response() to detect JS file vulnerabilities"""
        if not flow.response or not flow.response.content:
            return

        url = flow.request.pretty_url
        content_type = flow.response.headers.get("content-type", "").lower()

        is_js_file = (
            url.endswith(".js")
            or "application/javascript" in content_type
            or "text/javascript" in content_type
            or "application/x-javascript" in content_type
        )

        if is_js_file:
            try:
                js_content = flow.response.content.decode("utf-8", errors="ignore")

                if len(js_content) > 1024 * 512:
                    logger.info(f"Skipping large JS file: {len(js_content)} bytes")
                    return

                js_detections = JavaScriptAnalyzer.analyze_js_file_for_vulnerabilities(
                    js_content, url
                )

                for func_or_var, vulns in js_detections.items():
                    key = f"JS_FILE {func_or_var}"
                    all_param_detected[key] = vulns

            except Exception as e:
                logger.error(f"Error analyzing JS file {url}: {e}")



class FrameworkDetector:
    """Detects JavaScript frameworks and framework-specific XSS vulnerabilities"""

    @staticmethod
    def detect_javascript_frameworks(
        html_content: str, js_content: str = None
    ) -> Dict[str, List[str]]:
        """Detect JavaScript frameworks with improved accuracy"""
        frameworks = {}

        if not html_content and not js_content:
            return frameworks

        html_lower = html_content.lower() if html_content else ""
        js_lower = js_content.lower() if js_content else ""

        # AngularJS Detection
        angular_score = 0
        angular_evidence = []

        strong_angular = [
            (r"\bng-app\b", "ng-app directive"),
            (r"\bdata-ng-app\b", "data-ng-app directive"),
            (r"\bx-ng-app\b", "x-ng-app directive"),
            (r"angular\.module\s*\(", "angular.module() call"),
            (r"//ajax\.googleapis\.com/ajax/libs/angularjs/", "AngularJS CDN"),
            (r"/angular(?:\.min)?\.js", "angular.js file"),
        ]

        for pattern, desc in strong_angular:
            if re.search(pattern, html_lower, re.IGNORECASE):
                angular_score += 5
                angular_evidence.append(desc)
                # Don't break - continue checking for more evidence

        if js_content and re.search(r"angular\.module\s*\(", js_content, re.IGNORECASE):
            angular_score += 5
            angular_evidence.append("JS: angular.module()")

        medium_angular = [
            (r"\bng-controller\b", "ng-controller"),
            (r"\bng-model\b", "ng-model"),
            (r"\bng-bind\b", "ng-bind"),
            (r"\bng-repeat\b", "ng-repeat"),
            (r"\bng-show\b", "ng-show"),
            (r"\bng-hide\b", "ng-hide"),
            (r"\bng-if\b", "ng-if"),
            (r"\bng-click\b", "ng-click"),
            (r"\bng-submit\b", "ng-submit"),
            (r"\bng-bind-html\b", "ng-bind-html"),
        ]

        directive_count = 0
        for pattern, desc in medium_angular:
            if re.search(pattern, html_lower):
                directive_count += 1
                if len(angular_evidence) < 10:
                    angular_evidence.append(desc)

        angular_score += directive_count * 3

        if html_content:
            expr_matches = re.findall(r"\{\{[^}]+\}\}", html_content)
            valid_exprs = [e for e in expr_matches if len(e.strip("{}").strip()) > 2]
            if len(valid_exprs) >= 2:
                angular_score += 2
                angular_evidence.append(f"Angular expressions (x{len(valid_exprs)})")

        if js_content:
            angular_services = [
                (r"\$scope\b", "$scope"),
                (r"\$rootScope\b", "$rootScope"),
                (r"\$http\b", "$http"),
                (r"\$compile\b", "$compile"),
                (r"\$sce\b", "$sce"),
            ]

            for pattern, service in angular_services:
                if re.search(pattern, js_content):
                    angular_score += 2
                    angular_evidence.append(f"JS: {service}")
                    break

        if angular_score >= 5:  # Lowered threshold - single strong indicator is enough
            frameworks["AngularJS"] = angular_evidence[:15]

        # React Detection
        react_score = 0
        react_evidence = []

        strong_react = [
            (r"ReactDOM\.render\b", "ReactDOM.render()"),
            (r"ReactDOM\.createRoot\b", "ReactDOM.createRoot()"),
            (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
            (r"/react(?:\.min)?\.js", "React library"),
            (r"/react-dom(?:\.min)?\.js", "ReactDOM library"),
            (r"React\.createElement\b", "React.createElement()"),
        ]

        for pattern, desc in strong_react:
            if re.search(pattern, html_lower, re.IGNORECASE):
                react_score += 5
                react_evidence.append(desc)

        if js_content:
            if re.search(r'from\s+["\']react["\']', js_content, re.IGNORECASE):
                react_score += 5
                react_evidence.append("JS: import from React")
            if re.search(r'require\s*\(\s*["\']react["\']', js_content, re.IGNORECASE):
                react_score += 5
                react_evidence.append("JS: require React")

        if html_content:
            if re.search(r"\bclassName\s*=", html_content):
                react_score += 3
                react_evidence.append("className attributes")
            if re.search(r"\bonClick\s*=\s*\{", html_content):
                react_score += 2
                react_evidence.append("JSX event handlers")

        if js_content:
            hooks = ["useState", "useEffect", "useContext", "useReducer"]
            for hook in hooks:
                if re.search(rf"\b{hook}\b", js_content):
                    react_score += 2
                    react_evidence.append(f"JS: {hook}()")
                    break

        if react_score >= 5:
            frameworks["React"] = react_evidence[:10]

        # Vue.js Detection
        vue_score = 0
        vue_evidence = []

        strong_vue = [
            (r"\bv-html\b", "v-html directive"),
            (r"\bv-model\b", "v-model directive"),
            (r"\bv-bind\b", "v-bind directive"),
            (r"\bv-on\b", "v-on directive"),
            (r"\bv-if\b", "v-if directive"),
            (r"\bv-for\b", "v-for directive"),
            (r"/vue(?:\.min)?\.js", "Vue.js library"),
            (r"new Vue\s*\(", "new Vue()"),
            (r"Vue\.createApp\b", "Vue.createApp()"),
        ]

        for pattern, desc in strong_vue:
            if re.search(pattern, html_lower, re.IGNORECASE):
                vue_score += 5  # Increased from 4 to match other frameworks
                vue_evidence.append(desc)

        if html_content:
            if re.search(r"@click\b", html_content):
                vue_score += 3
                vue_evidence.append("@click binding")
            if re.search(r":href\b", html_content):
                vue_score += 2
                vue_evidence.append(":href binding")
            if re.search(r":src\b", html_content):
                vue_score += 2
                vue_evidence.append(":src binding")

        if js_content:
            if re.search(r"Vue\.component\b", js_content, re.IGNORECASE):
                vue_score += 4
                vue_evidence.append("JS: Vue.component()")
            if re.search(r'from\s+["\']vue["\']', js_content, re.IGNORECASE):
                vue_score += 5
                vue_evidence.append("JS: import from Vue")

        if vue_score >= 5:
            frameworks["Vue.js"] = vue_evidence[:10]

        # jQuery Detection
        jquery_score = 0
        jquery_evidence = []

        if html_content:
            if re.search(r"/jquery(?:[-.][\d.]+)?(?:\.min)?\.js", html_lower):
                jquery_score += 10
                jquery_evidence.append("jQuery library file")

        if js_content:
            jquery_patterns = [
                (r'\$\s*\(\s*["\']', "$(selector)"),
                (r"jQuery\s*\(", "jQuery()"),
                (r"\$\.ajax\b", "$.ajax()"),
                (r"\$\.get\b", "$.get()"),
                (r"\$\.post\b", "$.post()"),
                (r"\.html\s*\(", ".html()"),
                (r"\.append\s*\(", ".append()"),
                (r"\.prepend\s*\(", ".prepend()"),
            ]

            for pattern, desc in jquery_patterns:
                if re.search(pattern, js_content):
                    jquery_score += 2
                    if len(jquery_evidence) < 10:
                        jquery_evidence.append(f"JS: {desc}")

        if jquery_score >= 5:
            frameworks["jQuery"] = jquery_evidence[:10]

        # Other Frameworks
        other_frameworks = {
            "Backbone.js": [
                (r"Backbone\.Model\b", "Backbone.Model"),
                (r"Backbone\.View\b", "Backbone.View"),
                (r"/backbone(?:\.min)?\.js", "Backbone.js library"),
            ],
            "Ember.js": [
                (r"Ember\.Component\b", "Ember.Component"),
                (r"/ember(?:\.min)?\.js", "Ember.js library"),
            ],
            "Alpine.js": [
                (r"\bx-data\b", "x-data"),
                (r"\bx-show\b", "x-show"),
                (r"/alpine(?:\.min)?\.js", "Alpine.js library"),
            ],
            "Svelte": [
                (r'from\s+["\']svelte["\']', "import from Svelte"),
                (r"SvelteComponent", "SvelteComponent"),
            ],
        }

        for fw_name, patterns in other_frameworks.items():
            evidence = []
            for pattern, desc in patterns:
                if re.search(pattern, html_lower, re.IGNORECASE):
                    evidence.append(desc)
                if js_content and re.search(pattern, js_lower, re.IGNORECASE):
                    evidence.append(f"JS: {desc}")

            if len(evidence) >= 1:
                frameworks[fw_name] = evidence[:5]

        return frameworks

    @staticmethod
    def detect_angularjs_directives(html_content: str) -> List[str]:
        """Detect AngularJS directives with improved accuracy using BeautifulSoup"""
        findings = []

        if not html_content:
            return findings

        try:
            soup = BeautifulSoup(html_content, "html.parser")

            found_directives = set()

            for tag in soup.find_all(True):
                for attr_name in tag.attrs.keys():
                    attr_lower = attr_name.lower()

                    if (
                        attr_lower.startswith("ng-")
                        or attr_lower.startswith("data-ng-")
                        or attr_lower.startswith("x-ng-")
                    ):
                        found_directives.add(f"{tag.name}[{attr_name}]")

                    elif re.match(r"^ng[A-Z]", attr_name):
                        found_directives.add(f"{tag.name}[{attr_name}] (camelCase)")

            text_content = soup.get_text()
            expressions = re.findall(r"\{\{([^}]+)\}\}", text_content)

            valid_exprs = []
            for expr in expressions:
                content = expr.strip()
                if content and len(content) > 1 and not content.startswith("!"):
                    valid_exprs.append(expr)

            if len(valid_exprs) >= 2:
                found_directives.add(f"Angular expressions (x{len(valid_exprs)})")

            for script in soup.find_all("script", src=True):
                src = script.get("src", "").lower()
                if "angular" in src and ".js" in src:
                    found_directives.add(f"AngularJS script: {src.split('/')[-1]}")

            for script in soup.find_all("script", string=True):
                if script.string:
                    if re.search(r"angular\.module\s*\(", script.string, re.IGNORECASE):
                        found_directives.add("angular.module() in inline script")
                        break

            common_directives = [
                "ng-app",
                "ng-controller",
                "ng-model",
                "ng-repeat",
                "ng-show",
                "ng-hide",
                "ng-if",
                "ng-click",
                "ng-submit",
                "ng-bind",
                "ng-bind-html",
                "ng-src",
                "ng-href",
            ]

            html_lower = html_content.lower()
            for directive in common_directives:
                if re.search(rf'\b{directive}\s*=\s*["\']', html_lower):
                    found_directives.add(directive)

            findings = list(found_directives)
            return findings[:20]

        except Exception as e:
            logger.error(f"Error in AngularJS directive detection: {e}")
            return findings

    @staticmethod
    def detect_angularjs_xss_sinks(
        html_content: str, js_content: str = None
    ) -> List[Dict]:
        """Detect AngularJS-specific XSS vectors"""
        findings = []

        if not html_content and not js_content:
            return findings

        html_lower = html_content.lower() if html_content else ""

        try:
            # 1. ng-bind-html directive
            if html_content:
                ng_bind_html = re.findall(
                    r'ng-bind-html\s*=\s*["\']([^"\']+)["\']',
                    html_content,
                    re.IGNORECASE,
                )
                for expr in ng_bind_html:
                    findings.append(
                        {
                            "type": "ANGULAR_BIND_HTML",
                            "expression": expr.strip(),
                            "severity": "HIGH",
                            "description": "ng-bind-html renders raw HTML",
                        }
                    )

            # 2. $sce.trustAsHtml() usage
            if js_content:
                sce_patterns = [
                    (r"\$sce\.trustAsHtml\s*\(\s*([^)]+)\)", "$sce.trustAsHtml()"),
                    (
                        r"\$sce\.getTrustedHtml\s*\(\s*([^)]+)\)",
                        "$sce.getTrustedHtml()",
                    ),
                    (
                        r"\$sce\.trustAsResourceUrl\s*\(\s*([^)]+)\)",
                        "$sce.trustAsResourceUrl()",
                    ),
                ]

                for pattern, desc in sce_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE)
                    for expr in matches:
                        findings.append(
                            {
                                "type": "ANGULAR_SCE_TRUST",
                                "expression": expr.strip()[:100],
                                "severity": "CRITICAL",
                                "description": f"{desc} - explicitly trusts content",
                            }
                        )

            # 3. $compile service
            if js_content:
                compile_matches = re.findall(
                    r"\$compile\s*\(\s*([^)]+)\)", js_content, re.IGNORECASE
                )
                for expr in compile_matches:
                    findings.append(
                        {
                            "type": "ANGULAR_COMPILE",
                            "expression": expr.strip()[:100],
                            "severity": "CRITICAL",
                            "description": "$compile() can execute arbitrary HTML/Angular",
                        }
                    )

            # 4. ng-href with javascript: or data:
            if html_content:
                dangerous_href = re.findall(
                    r'ng-href\s*=\s*["\']([^"\']*(?:javascript:|data:)[^"\']*)["\']',
                    html_content,
                    re.IGNORECASE,
                )
                for href in dangerous_href:
                    findings.append(
                        {
                            "type": "ANGULAR_HREF_XSS",
                            "expression": href[:100],
                            "severity": "HIGH",
                            "description": "ng-href with dangerous URL scheme",
                        }
                    )

            # 5. ng-src with expressions
            if html_content:
                ng_src = re.findall(
                    r'ng-src\s*=\s*["\']([^"\']+)["\']', html_content, re.IGNORECASE
                )
                for src in ng_src:
                    if "{{" in src:
                        findings.append(
                            {
                                "type": "ANGULAR_SRC_XSS",
                                "expression": src[:100],
                                "severity": "MEDIUM",
                                "description": "ng-src with dynamic expression",
                            }
                        )

            # 6. ng-style with expressions
            if html_content:
                ng_style = re.findall(
                    r'ng-style\s*=\s*["\']([^"\']+)["\']', html_content, re.IGNORECASE
                )
                for style in ng_style:
                    findings.append(
                        {
                            "type": "ANGULAR_STYLE_XSS",
                            "expression": style[:100],
                            "severity": "MEDIUM",
                            "description": "ng-style can inject CSS",
                        }
                    )

            # 7. Unsafe expressions in {{ }}
            if html_content:
                expressions = re.findall(r"\{\{([^}]+)\}\}", html_content)
                for expr in expressions:
                    if any(
                        danger in expr.lower()
                        for danger in ["html", "trust", "unsafe", "compile"]
                    ):
                        findings.append(
                            {
                                "type": "ANGULAR_EXPRESSION",
                                "expression": expr.strip()[:100],
                                "severity": "MEDIUM",
                                "description": "Angular expression with potentially dangerous content",
                            }
                        )

        except Exception as e:
            logger.error(f"Error in AngularJS XSS sink detection: {e}")

        return findings

    @staticmethod
    def detect_react_xss_sinks(html_content: str, js_content: str = None) -> List[Dict]:
        """Detect React-specific XSS vectors"""
        findings = []

        if not js_content and not html_content:
            return findings

        try:
            combined_content = (js_content or "") + (html_content or "")

            # 1. dangerouslySetInnerHTML
            dangerous_html_patterns = [
                r"dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*([^}]+)\}\}",
                r"dangerouslySetInnerHTML\s*:\s*\{\s*__html\s*:\s*([^,}]+)",
            ]

            for pattern in dangerous_html_patterns:
                matches = re.findall(
                    pattern, combined_content, re.IGNORECASE | re.DOTALL
                )
                for match in matches:
                    findings.append(
                        {
                            "type": "REACT_DANGEROUS_HTML",
                            "expression": match.strip()[:100],
                            "severity": "CRITICAL",
                            "description": "dangerouslySetInnerHTML bypasses React XSS protection",
                        }
                    )

            # 2. React.createElement with dangerous props
            if js_content:
                create_element = re.findall(
                    r"React\.createElement\s*\([^,]+,\s*\{[^}]*dangerouslySetInnerHTML[^}]*\}",
                    js_content,
                    re.IGNORECASE | re.DOTALL,
                )
                if create_element:
                    findings.append(
                        {
                            "type": "REACT_CREATE_ELEMENT_UNSAFE",
                            "expression": "React.createElement with dangerouslySetInnerHTML",
                            "severity": "CRITICAL",
                            "description": "React.createElement() bypassing XSS protection",
                        }
                    )

            # 3. href with javascript:
            if html_content or js_content:
                href_js = re.findall(
                    r'href\s*=\s*[{"].*?javascript:', combined_content, re.IGNORECASE
                )
                if href_js:
                    findings.append(
                        {
                            "type": "REACT_HREF_XSS",
                            "expression": "href with javascript: scheme",
                            "severity": "MEDIUM",
                            "description": "javascript: URL in href attribute",
                        }
                    )

        except Exception as e:
            logger.error(f"Error in React XSS sink detection: {e}")

        return findings

    @staticmethod
    def detect_vue_xss_sinks(html_content: str, js_content: str = None) -> List[Dict]:
        """Detect Vue.js-specific XSS vectors"""
        findings = []

        if not html_content and not js_content:
            return findings

        try:
            # 1. v-html directive
            if html_content:
                v_html_matches = re.findall(
                    r'v-html\s*=\s*["\']([^"\']+)["\']', html_content, re.IGNORECASE
                )
                for expr in v_html_matches:
                    findings.append(
                        {
                            "type": "VUE_V_HTML",
                            "expression": expr.strip()[:100],
                            "severity": "CRITICAL",
                            "description": "v-html directly sets innerHTML without sanitization",
                        }
                    )

            # 2. Vue component templates with v-html
            if js_content:
                template_patterns = [
                    r'template\s*:\s*["\']([^"\']*v-html[^"\']*)["\']',
                    r"template\s*:\s*`([^`]*v-html[^`]*)`",
                ]

                for pattern in template_patterns:
                    matches = re.findall(pattern, js_content, re.IGNORECASE | re.DOTALL)
                    for template in matches:
                        findings.append(
                            {
                                "type": "VUE_UNSAFE_TEMPLATE",
                                "expression": template[:100],
                                "severity": "HIGH",
                                "description": "Vue template with v-html directive",
                            }
                        )

            # 3. v-bind:href with expressions
            if html_content:
                v_bind_href = re.findall(
                    r'v-bind:href\s*=\s*["\']([^"\']+)["\']',
                    html_content,
                    re.IGNORECASE,
                )
                for expr in v_bind_href:
                    if "javascript:" in expr.lower():
                        findings.append(
                            {
                                "type": "VUE_HREF_XSS",
                                "expression": expr[:100],
                                "severity": "MEDIUM",
                                "description": "v-bind:href with javascript: scheme",
                            }
                        )

        except Exception as e:
            logger.error(f"Error in Vue XSS sink detection: {e}")

        return findings


class SecurityDetector:
    """Handles security header analysis, misconfigurations, SSL/TLS, cookies, CORS"""

    @staticmethod
    def detect_uncommon_headers(req_headers, resp_headers):
        """Return uncommon header names"""
        uncommon = {"request": [], "response": []}

        def norm(hdrs):
            out = {}
            try:
                items = hdrs.items()
            except Exception:
                items = hdrs
            for k, v in items:
                if k is None:
                    continue
                kl = k.lower()
                out[kl] = (k, v)
            return out

        rreq = norm(req_headers or {})
        rres = norm(resp_headers or {})

        for kl, (orig, _) in rreq.items():
            if kl in HOP_BY_HOP:
                continue
            if kl not in COMMON_REQUEST_HEADERS:
                uncommon["request"].append(orig)

        for kl, (orig, _) in rres.items():
            if kl in HOP_BY_HOP:
                continue
            if kl not in COMMON_RESPONSE_HEADERS:
                uncommon["response"].append(orig)

        return uncommon

    @staticmethod
    def detect_jwt(headers, body):
        findings = []
        token_regex = (
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
        )
        for k, v in headers.items():
            try:
                if re.search(token_regex, v):
                    findings.append(f"JWT_HEADER:{k}")
            except Exception:
                continue
        if body and re.search(token_regex, body):
            findings.append("JWT_BODY")
        return findings

    @staticmethod
    def check_cors(headers, request_headers):
        cors_issues = []
        origin = request_headers.get("Origin", "")
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if origin and acao == origin and acac == "true":
            cors_issues.append("CORS_ALLOW_CREDENTIALS")
        elif origin and acao == "*" and acac == "true":
            cors_issues.append("CORS_WILDCARD_CREDENTIALS")
        elif origin and acao == "*":
            cors_issues.append("CORS_WILDCARD")
        elif origin and acao == "null":
            cors_issues.append("CORS_NULL")

        return cors_issues

    # -------------------------------------------------------------------------
    # CORS HEADER INDICATORS  (comprehensive detection)
    # -------------------------------------------------------------------------
    @staticmethod
    def analyze_cors_headers(resp_headers: dict, req_headers: dict) -> List[Dict]:
        """
        Comprehensive CORS header indicator analysis.

        Examines every CORS-related header in both the request and the response,
        classifies each one by risk level, and returns actionable findings that
        are distinct from the high-level misconfig flags produced by check_cors().

        Returns a list of finding dicts:
            {
                'indicator':  str   – short key used for the param-table row
                'header':     str   – the actual header name
                'value':      str   – the header value (truncated to 200 chars)
                'severity':   str   – CRITICAL / HIGH / MEDIUM / LOW / INFO
                'risk':       str   – human-readable risk description
                'location':   str   – 'request' | 'response'
                'tags':       list  – machine-readable tags, e.g. ['CORS','WILDCARD']
            }
        """
        findings: List[Dict] = []

        # Normalise header dicts to lowercase keys for case-insensitive lookup
        def norm(hdrs):
            if not hdrs:
                return {}
            try:
                return {k.lower(): str(v) for k, v in hdrs.items()}
            except Exception:
                return {}

        resp = norm(resp_headers)
        req  = norm(req_headers)

        # ── Helper ──────────────────────────────────────────────────────────
        def add(indicator, header, value, severity, risk, location, tags):
            findings.append({
                'indicator': indicator,
                'header':    header,
                'value':     str(value)[:200],
                'severity':  severity,
                'risk':      risk,
                'location':  location,
                'tags':      tags,
            })

        # ════════════════════════════════════════════════════════════════════
        # 1. REQUEST-SIDE: Origin header presence & value
        # ════════════════════════════════════════════════════════════════════
        origin_val = req.get('origin', '')
        if origin_val:
            if origin_val.lower() == 'null':
                add('CORS_REQ_ORIGIN_NULL',
                    'Origin', origin_val,
                    'HIGH',
                    'Request Origin is "null" – sandbox/iframe origin. '
                    'If ACAO echoes "null", cross-origin reads from sandboxed iframes are allowed.',
                    'request',
                    ['CORS', 'NULL_ORIGIN', 'HIGH'])
            else:
                add('CORS_REQ_ORIGIN',
                    'Origin', origin_val,
                    'INFO',
                    f'Cross-origin request from: {origin_val}',
                    'request',
                    ['CORS', 'ORIGIN_PRESENT'])

        # ════════════════════════════════════════════════════════════════════
        # 2. RESPONSE: Access-Control-Allow-Origin (ACAO)
        # ════════════════════════════════════════════════════════════════════
        acao = resp.get('access-control-allow-origin', '')
        acac = resp.get('access-control-allow-credentials', '')
        creds_true = acac.strip().lower() == 'true'

        if acao:
            if acao.strip() == '*':
                if creds_true:
                    # Technically invalid (browsers reject it), but flag it anyway
                    add('CORS_ACAO_WILDCARD_CREDS',
                        'Access-Control-Allow-Origin', acao,
                        'CRITICAL',
                        'Wildcard ACAO + Allow-Credentials:true. '
                        'Browsers block this combination, but some non-browser clients honour it.',
                        'response',
                        ['CORS', 'WILDCARD', 'CREDENTIALS', 'CRITICAL'])
                else:
                    add('CORS_ACAO_WILDCARD',
                        'Access-Control-Allow-Origin', acao,
                        'HIGH',
                        'Wildcard ACAO (*) allows any origin to read non-credentialed responses. '
                        'Sensitive data in these responses is exposed to all origins.',
                        'response',
                        ['CORS', 'WILDCARD', 'HIGH'])

            elif acao.strip().lower() == 'null':
                add('CORS_ACAO_NULL',
                    'Access-Control-Allow-Origin', acao,
                    'HIGH',
                    'ACAO: null allows sandboxed iframes and local files to read the response. '
                    'Can be abused with a sandboxed iframe to exfiltrate data.',
                    'response',
                    ['CORS', 'NULL_ORIGIN', 'HIGH'])

            elif origin_val and acao.strip() == origin_val.strip():
                if creds_true:
                    add('CORS_ACAO_REFLECTED_CREDS',
                        'Access-Control-Allow-Origin', acao,
                        'CRITICAL',
                        f'ACAO reflects the request Origin ({origin_val}) AND '
                        'Access-Control-Allow-Credentials is true. '
                        'Any origin can read credentialed (cookie/session) responses. '
                        'Classic CORS misconfiguration – test for account takeover.',
                        'response',
                        ['CORS', 'REFLECTED_ORIGIN', 'CREDENTIALS', 'CRITICAL'])
                else:
                    add('CORS_ACAO_REFLECTED',
                        'Access-Control-Allow-Origin', acao,
                        'MEDIUM',
                        f'ACAO dynamically reflects the request Origin ({origin_val}). '
                        'Non-credentialed cross-origin reads are possible from any origin.',
                        'response',
                        ['CORS', 'REFLECTED_ORIGIN', 'MEDIUM'])

            elif re.search(r'https?://', acao):
                # Specific whitelisted origin
                if creds_true:
                    add('CORS_ACAO_SPECIFIC_CREDS',
                        'Access-Control-Allow-Origin', acao,
                        'MEDIUM',
                        f'ACAO grants a specific trusted origin ({acao}) with credentials. '
                        'Verify the whitelisted origin cannot be compromised (subdomain takeover, etc.).',
                        'response',
                        ['CORS', 'SPECIFIC_ORIGIN', 'CREDENTIALS', 'MEDIUM'])
                else:
                    add('CORS_ACAO_SPECIFIC',
                        'Access-Control-Allow-Origin', acao,
                        'LOW',
                        f'ACAO allows specific origin: {acao}',
                        'response',
                        ['CORS', 'SPECIFIC_ORIGIN', 'LOW'])

                # Subdomain wildcard abuse patterns  e.g. *.evil.com
                if re.search(r'\*\.', acao):
                    add('CORS_ACAO_SUBDOMAIN_WILDCARD',
                        'Access-Control-Allow-Origin', acao,
                        'HIGH',
                        f'ACAO contains a subdomain wildcard: {acao}. '
                        'A compromised/registered subdomain could exploit this.',
                        'response',
                        ['CORS', 'SUBDOMAIN_WILDCARD', 'HIGH'])
            else:
                add('CORS_ACAO_PRESENT',
                    'Access-Control-Allow-Origin', acao,
                    'INFO',
                    f'ACAO header present: {acao}',
                    'response',
                    ['CORS', 'ACAO_PRESENT'])

        # ════════════════════════════════════════════════════════════════════
        # 3. RESPONSE: Access-Control-Allow-Credentials
        # ════════════════════════════════════════════════════════════════════
        if acac:
            if creds_true:
                sev = 'HIGH' if not acao else ('CRITICAL' if (acao.strip() == '*' or acao.strip() == origin_val) else 'MEDIUM')
                add('CORS_ACAC_TRUE',
                    'Access-Control-Allow-Credentials', acac,
                    sev,
                    'Allow-Credentials: true means cookies, HTTP auth, and TLS client certs '
                    'are included in cross-origin requests. '
                    'Combined with a permissive ACAO, this enables session theft.',
                    'response',
                    ['CORS', 'CREDENTIALS', sev])
            else:
                add('CORS_ACAC_FALSE',
                    'Access-Control-Allow-Credentials', acac,
                    'INFO',
                    'Allow-Credentials explicitly set to false.',
                    'response',
                    ['CORS', 'CREDENTIALS'])

        # ════════════════════════════════════════════════════════════════════
        # 4. RESPONSE: Access-Control-Allow-Methods (ACAM)
        # ════════════════════════════════════════════════════════════════════
        acam = resp.get('access-control-allow-methods', '')
        if acam:
            dangerous_methods = [m for m in ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']
                                 if m.upper() in acam.upper()]
            if dangerous_methods:
                add('CORS_ACAM_DANGEROUS',
                    'Access-Control-Allow-Methods', acam,
                    'HIGH',
                    f'Dangerous HTTP methods allowed cross-origin: {", ".join(dangerous_methods)}. '
                    'Combined with a permissive ACAO, this may allow state-changing cross-origin requests.',
                    'response',
                    ['CORS', 'DANGEROUS_METHODS', 'HIGH'])
            elif '*' in acam:
                add('CORS_ACAM_WILDCARD',
                    'Access-Control-Allow-Methods', acam,
                    'MEDIUM',
                    'Access-Control-Allow-Methods is a wildcard (*), allowing any HTTP method cross-origin.',
                    'response',
                    ['CORS', 'WILDCARD_METHODS', 'MEDIUM'])
            else:
                add('CORS_ACAM_PRESENT',
                    'Access-Control-Allow-Methods', acam,
                    'INFO',
                    f'Allowed cross-origin methods: {acam}',
                    'response',
                    ['CORS', 'ACAM_PRESENT'])

        # ════════════════════════════════════════════════════════════════════
        # 5. RESPONSE: Access-Control-Allow-Headers (ACAH)
        # ════════════════════════════════════════════════════════════════════
        acah = resp.get('access-control-allow-headers', '')
        if acah:
            sensitive_headers = ['authorization', 'x-auth-token', 'x-api-key',
                                 'x-access-token', 'x-csrf-token', 'cookie']
            exposed_sensitive = [h for h in sensitive_headers if h in acah.lower()]
            if '*' in acah:
                add('CORS_ACAH_WILDCARD',
                    'Access-Control-Allow-Headers', acah,
                    'MEDIUM',
                    'Any request header is allowed cross-origin (wildcard). '
                    'Enables sending Authorization or custom auth headers from any origin.',
                    'response',
                    ['CORS', 'WILDCARD_HEADERS', 'MEDIUM'])
            elif exposed_sensitive:
                add('CORS_ACAH_SENSITIVE',
                    'Access-Control-Allow-Headers', acah,
                    'HIGH',
                    f'Sensitive headers allowed cross-origin: {", ".join(exposed_sensitive)}. '
                    'May allow cross-origin requests to carry auth credentials.',
                    'response',
                    ['CORS', 'SENSITIVE_HEADERS', 'HIGH'])
            else:
                add('CORS_ACAH_PRESENT',
                    'Access-Control-Allow-Headers', acah,
                    'INFO',
                    f'Allowed cross-origin request headers: {acah}',
                    'response',
                    ['CORS', 'ACAH_PRESENT'])

        # ════════════════════════════════════════════════════════════════════
        # 6. RESPONSE: Access-Control-Expose-Headers (ACEH)
        # ════════════════════════════════════════════════════════════════════
        aceh = resp.get('access-control-expose-headers', '')
        if aceh:
            exposed_sensitive = [h for h in
                                  ['authorization', 'set-cookie', 'x-auth-token', 'x-api-key']
                                  if h in aceh.lower()]
            if '*' in aceh:
                add('CORS_ACEH_WILDCARD',
                    'Access-Control-Expose-Headers', aceh,
                    'MEDIUM',
                    'All response headers are exposed cross-origin (wildcard). '
                    'Any header including sensitive ones will be readable by cross-origin JS.',
                    'response',
                    ['CORS', 'WILDCARD_EXPOSE', 'MEDIUM'])
            elif exposed_sensitive:
                add('CORS_ACEH_SENSITIVE',
                    'Access-Control-Expose-Headers', aceh,
                    'HIGH',
                    f'Sensitive response headers exposed cross-origin: {", ".join(exposed_sensitive)}.',
                    'response',
                    ['CORS', 'SENSITIVE_EXPOSE', 'HIGH'])
            else:
                add('CORS_ACEH_PRESENT',
                    'Access-Control-Expose-Headers', aceh,
                    'LOW',
                    f'Response headers exposed to cross-origin JS: {aceh}',
                    'response',
                    ['CORS', 'ACEH_PRESENT'])

        # ════════════════════════════════════════════════════════════════════
        # 7. RESPONSE: Access-Control-Max-Age (ACMA)
        # ════════════════════════════════════════════════════════════════════
        acma = resp.get('access-control-max-age', '')
        if acma:
            try:
                max_age_secs = int(acma.strip())
                if max_age_secs > 86400:          # > 24 hours
                    add('CORS_ACMA_LONG',
                        'Access-Control-Max-Age', acma,
                        'LOW',
                        f'Preflight cache set to {max_age_secs}s (>{max_age_secs//3600}h). '
                        'Long-lived preflight caches can delay detection of CORS policy changes.',
                        'response',
                        ['CORS', 'MAX_AGE_LONG', 'LOW'])
                else:
                    add('CORS_ACMA_PRESENT',
                        'Access-Control-Max-Age', acma,
                        'INFO',
                        f'Preflight cache max-age: {acma}s',
                        'response',
                        ['CORS', 'MAX_AGE'])
            except ValueError:
                add('CORS_ACMA_INVALID',
                    'Access-Control-Max-Age', acma,
                    'LOW',
                    f'Non-numeric Access-Control-Max-Age value: {acma}',
                    'response',
                    ['CORS', 'MAX_AGE_INVALID'])

        # ════════════════════════════════════════════════════════════════════
        # 8. RESPONSE: Vary header – should include "Origin" when CORS active
        # ════════════════════════════════════════════════════════════════════
        vary = resp.get('vary', '')
        if acao and vary:
            if 'origin' not in vary.lower():
                add('CORS_VARY_MISSING_ORIGIN',
                    'Vary', vary,
                    'MEDIUM',
                    'ACAO is present but Vary does not include "Origin". '
                    'This can cause intermediate caches to serve the wrong CORS headers, '
                    'potentially bypassing CORS restrictions or poisoning caches.',
                    'response',
                    ['CORS', 'CACHE_POISONING', 'VARY_MISCONFIGURATION', 'MEDIUM'])
            else:
                add('CORS_VARY_ORIGIN',
                    'Vary', vary,
                    'INFO',
                    'Vary: Origin is correctly set – caches will store separate responses per origin.',
                    'response',
                    ['CORS', 'VARY_OK'])
        elif acao and not vary:
            add('CORS_VARY_ABSENT',
                'Vary', '(absent)',
                'MEDIUM',
                'ACAO is present but no Vary header exists. '
                'Caches may serve CORS responses to unintended origins.',
                'response',
                ['CORS', 'CACHE_POISONING', 'VARY_MISSING', 'MEDIUM'])

        # ════════════════════════════════════════════════════════════════════
        # 9. REQUEST-SIDE: Access-Control-Request-Method / Headers (preflight)
        # ════════════════════════════════════════════════════════════════════
        acrm = req.get('access-control-request-method', '')
        if acrm:
            dangerous = [m for m in ['PUT', 'DELETE', 'PATCH', 'TRACE'] if m.upper() == acrm.upper()]
            add('CORS_PREFLIGHT_METHOD',
                'Access-Control-Request-Method', acrm,
                'HIGH' if dangerous else 'INFO',
                f'Preflight requesting method: {acrm}' +
                (f' – potentially dangerous state-changing method.' if dangerous else ''),
                'request',
                ['CORS', 'PREFLIGHT', 'DANGEROUS_METHOD' if dangerous else 'METHOD_OK'])

        acrh = req.get('access-control-request-headers', '')
        if acrh:
            sensitive = [h for h in ['authorization', 'x-api-key', 'x-auth-token', 'cookie']
                         if h in acrh.lower()]
            add('CORS_PREFLIGHT_HEADERS',
                'Access-Control-Request-Headers', acrh,
                'HIGH' if sensitive else 'INFO',
                f'Preflight requesting headers: {acrh}' +
                (f' – includes sensitive header(s): {", ".join(sensitive)}.' if sensitive else ''),
                'request',
                ['CORS', 'PREFLIGHT', 'SENSITIVE_HEADERS' if sensitive else 'HEADERS_OK'])

        # ════════════════════════════════════════════════════════════════════
        # 10. RESPONSE: Cross-Origin-* policy headers (COEP / COOP / CORP)
        # ════════════════════════════════════════════════════════════════════
        coep = resp.get('cross-origin-embedder-policy', '')
        coop = resp.get('cross-origin-opener-policy', '')
        corp = resp.get('cross-origin-resource-policy', '')

        if not coep and acao:
            add('CORS_COEP_MISSING',
                'Cross-Origin-Embedder-Policy', '(absent)',
                'INFO',
                'COEP not set. Without COEP+COOP, SharedArrayBuffer and high-res timers '
                'are unavailable, but there is no active isolation enforced.',
                'response',
                ['CORS', 'COEP_MISSING'])

        if coep:
            add('CORS_COEP_PRESENT',
                'Cross-Origin-Embedder-Policy', coep,
                'INFO',
                f'COEP: {coep} – controls whether the document can embed cross-origin resources.',
                'response',
                ['CORS', 'COEP'])

        if coop:
            add('CORS_COOP_PRESENT',
                'Cross-Origin-Opener-Policy', coop,
                'INFO',
                f'COOP: {coop} – isolates the browsing context from cross-origin openers.',
                'response',
                ['CORS', 'COOP'])

        if corp:
            if corp.strip().lower() == 'cross-origin':
                add('CORS_CORP_CROSS_ORIGIN',
                    'Cross-Origin-Resource-Policy', corp,
                    'MEDIUM',
                    'CORP: cross-origin allows any site to embed this resource. '
                    'Consider "same-site" or "same-origin" for sensitive assets.',
                    'response',
                    ['CORS', 'CORP', 'MEDIUM'])
            else:
                add('CORS_CORP_PRESENT',
                    'Cross-Origin-Resource-Policy', corp,
                    'INFO',
                    f'CORP: {corp}',
                    'response',
                    ['CORS', 'CORP'])

        # ════════════════════════════════════════════════════════════════════
        # 11. RESPONSE: Timing-Allow-Origin (TAO) – exposes Resource Timing API
        # ════════════════════════════════════════════════════════════════════
        tao = resp.get('timing-allow-origin', '')
        if tao:
            if tao.strip() == '*':
                add('CORS_TAO_WILDCARD',
                    'Timing-Allow-Origin', tao,
                    'MEDIUM',
                    'Timing-Allow-Origin: * exposes granular resource-timing data to all origins. '
                    'Can be abused for timing-based side-channel attacks (XSSI, cache probing).',
                    'response',
                    ['CORS', 'TIMING', 'WILDCARD', 'MEDIUM'])
            else:
                add('CORS_TAO_PRESENT',
                    'Timing-Allow-Origin', tao,
                    'LOW',
                    f'Timing-Allow-Origin allows timing data to: {tao}',
                    'response',
                    ['CORS', 'TIMING'])

        # ════════════════════════════════════════════════════════════════════
        # 12. No CORS headers at all – note it if an Origin was sent
        # ════════════════════════════════════════════════════════════════════
        cors_response_headers = [
            'access-control-allow-origin',
            'access-control-allow-credentials',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-expose-headers',
            'access-control-max-age',
        ]
        has_cors_resp = any(h in resp for h in cors_response_headers)
        if origin_val and not has_cors_resp:
            add('CORS_NO_RESPONSE_HEADERS',
                'CORS Response Headers', '(none)',
                'INFO',
                'An Origin header was sent in the request but the server returned no CORS headers. '
                'The request is blocked by browser SOP – but the server still processed it. '
                'Test with non-preflighted methods for potential CSRF.',
                'request',
                ['CORS', 'NO_CORS_RESPONSE', 'CSRF_POTENTIAL'])

        return findings

    @staticmethod
    def detect_ssl_tls_issues(flow) -> List[str]:
        """Detect SSL/TLS related issues"""
        findings = []

        try:
            if flow.request.scheme == "http":
                sensitive_param_names = [
                    "password",
                    "passwd",
                    "pwd",
                    "token",
                    "secret",
                    "api_key",
                    "apikey",
                    "auth",
                    "session",
                    "credit",
                    "card",
                    "ssn",
                    "pin",
                ]

                url_lower = flow.request.pretty_url.lower() if hasattr(flow.request, 'pretty_url') else str(flow.request.url).lower()
                for param in sensitive_param_names:
                    if param in url_lower:
                        findings.append(f"SENSITIVE_DATA_HTTP:{param}")
                        break

            if (
                flow.request.scheme == "https"
                and flow.response
                and flow.response.content
            ):
                body = flow.response.content.decode("utf-8", errors="ignore")

                http_resource_patterns = [
                    r'src\s*=\s*["\']http://',
                    r'href\s*=\s*["\']http://',
                    r'action\s*=\s*["\']http://',
                ]

                for pattern in http_resource_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append("MIXED_CONTENT_WARNING")
                        break

        except Exception as e:
            logger.error(f"Error in SSL/TLS detection: {e}")

        return findings

    @staticmethod
    def detect_cookie_issues(flow) -> List[str]:
        """Detect insecure cookie configurations"""
        findings = []

        try:
            if not flow.response:
                return findings

            set_cookies = flow.response.headers.get_all("set-cookie") if hasattr(flow.response.headers, 'get_all') else [flow.response.headers.get("set-cookie", "")]

            if set_cookies:
                for cookie in set_cookies:
                    if not cookie:
                        continue
                    cookie_lower = cookie.lower()

                    sensitive_names = [
                        "session",
                        "auth",
                        "token",
                        "jwt",
                        "login",
                        "user",
                    ]
                    is_sensitive = any(name in cookie_lower for name in sensitive_names)

                    if is_sensitive:
                        if "secure" not in cookie_lower:
                            findings.append("COOKIE_WITHOUT_SECURE")
                        if "httponly" not in cookie_lower:
                            findings.append("COOKIE_WITHOUT_HTTPONLY")
                        if "samesite" not in cookie_lower:
                            findings.append("COOKIE_WITHOUT_SAMESITE")

        except Exception as e:
            logger.error(f"Error in cookie detection: {e}")

        return findings

    @staticmethod
    def detect_websocket_upgrade(flow) -> List[str]:
        """Detect WebSocket upgrade requests"""
        findings = []

        try:
            upgrade = flow.request.headers.get("upgrade", "").lower()
            connection = flow.request.headers.get("connection", "").lower()

            if upgrade == "websocket" and "upgrade" in connection:
                findings.append("WEBSOCKET_DETECTED")

                if "origin" not in [h.lower() for h in flow.request.headers.keys()]:
                    findings.append("WEBSOCKET_NO_ORIGIN")

        except Exception as e:
            logger.error(f"Error in WebSocket detection: {e}")

        return findings

    @staticmethod
    def detect_clickjacking_protection(flow) -> List[str]:
        """Detect missing clickjacking protection"""
        findings = []

        try:
            if not flow.response:
                return findings

            headers_lower = {k.lower(): v for k, v in flow.response.headers.items()}

            has_xfo = "x-frame-options" in headers_lower

            csp = headers_lower.get("content-security-policy", "")
            has_frame_ancestors = "frame-ancestors" in csp.lower()

            if not has_xfo and not has_frame_ancestors:
                if flow.response.content:
                    body = flow.response.content.decode("utf-8", errors="ignore")
                    if "<form" in body.lower():
                        findings.append("CLICKJACKING_POSSIBLE")

        except Exception as e:
            logger.error(f"Error in clickjacking detection: {e}")

        return findings

    @staticmethod
    def detect_security_misconfig(headers, body):
        """Detect security misconfigurations"""
        findings = []

        security_headers = {
            "x-frame-options": "MISSING_X_FRAME_OPTIONS",
            "x-content-type-options": "MISSING_X_CONTENT_TYPE_OPTIONS",
            "strict-transport-security": "MISSING_HSTS",
            "content-security-policy": "MISSING_CSP",
        }

        for header, finding in security_headers.items():
            if header not in {k.lower() for k in headers.keys()}:
                findings.append(finding)

        csp = headers.get("Content-Security-Policy", "")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append("WEAK_CSP")

        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")
        if acao and acao != "null" and acac == "true":
            findings.append("CORS_MISCONFIGURATION")

        if body and re.search(r"<title>Index of /", body):
            findings.append("DIRECTORY_LISTING")

        server = headers.get("Server", "")
        if server and not server.lower() in ["cloudflare", "cloudfront"]:
            findings.append("SERVER_DISCLOSURE")

        return findings


class VulnerabilityScanner:
    """Handles detection of SQL injection, XXE, API keys, debug mode, etc."""

    @staticmethod
    def detect_sql_injection_errors(flow) -> List[str]:
        """Enhanced SQL injection error detection"""
        findings = []

        if not flow.response or not flow.response.content:
            return findings

        try:
            content_type = flow.response.headers.get("content-type", "").lower()

            body = None
            encodings_to_try = [
                "utf-8",
                "iso-8859-1",
                "iso-8859-2",
                "cp1252",
                "latin-1",
                "windows-1252",
            ]

            if "charset=" in content_type:
                charset_match = re.search(r"charset=([^;\s]+)", content_type)
                if charset_match:
                    detected_encoding = charset_match.group(1).strip().lower()
                    if detected_encoding not in encodings_to_try:
                        encodings_to_try.insert(0, detected_encoding)

            for enc in encodings_to_try:
                try:
                    body = flow.response.content.decode(enc, errors="replace")
                    if len(body) > 10:
                        break
                except Exception:
                    continue

            if not body:
                body = flow.response.content.decode("utf-8", errors="replace")

            sql_errors = {
                "MYSQL": [
                    r"You have an error in your SQL syntax",
                    r"check the manual that corresponds to your MySQL server version",
                    r"SQL syntax.*MySQL",
                    r"Warning.*mysql_",
                    r"valid MySQL result",
                    r"MySqlClient\.",
                    r"com\.mysql\.jdbc\.exceptions",
                    r"MySQL server version",
                    r"Unknown column.*in.*clause",
                    r"mysql_fetch",
                    r"mysql_num_rows",
                    r"mysql_query",
                    r"mysql_error",
                    r"supplied argument is not a valid MySQL",
                    r"Column count doesn't match",
                    r"mysqld got signal",
                    r"MySQL Error",
                    r"[MySQL][ODBC",
                ],
                "MSSQL": [
                    r"Driver.*SQL[\-\_\ ]*Server",
                    r"OLE DB.*SQL Server",
                    r"(\W|\A)SQL Server.*Driver",
                    r"Warning.*mssql_",
                    r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                    r"System\.Data\.SqlClient\.SqlException",
                    r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
                    r"Unclosed quotation mark after the character string",
                    r"Microsoft SQL Native Client error",
                    r"ODBC SQL Server Driver",
                    r"SQLServer JDBC Driver",
                    r"Incorrect syntax near",
                ],
                "ORACLE": [
                    r"\bORA-[0-9][0-9][0-9][0-9]",
                    r"Oracle error",
                    r"Oracle.*Driver",
                    r"Warning.*oci_",
                    r"Warning.*ora_",
                    r"oracle\.jdbc",
                    r"OracleException",
                ],
                "POSTGRES": [
                    r"PostgreSQL.*ERROR",
                    r"Warning.*\Wpg_",
                    r"valid PostgreSQL result",
                    r"Npgsql\.",
                    r"PG::SyntaxError:",
                    r"org\.postgresql\.util\.PSQLException",
                    r"PSQLException",
                    r"org\.postgresql\.jdbc",
                ],
                "SQLITE": [
                    r"SQLite/JDBCDriver",
                    r"SQLite\.Exception",
                    r"System\.Data\.SQLite\.SQLiteException",
                    r"Warning.*sqlite_",
                    r"Warning.*SQLite3::",
                    r"\[SQLITE_ERROR\]",
                    r"sqlite3.OperationalError:",
                    r"SQLite error",
                ],
                "GENERIC": [
                    r"SQL\s+syntax.*error",
                    r"syntax\s+error.*SQL",
                    r"unclosed quotation mark",
                    r"quoted string not properly terminated",
                    r"SQL command not properly ended",
                    r"unterminated string literal",
                    r"unexpected end of SQL command",
                    r"near\s+['\"].*['\"]",
                    r"at line \d+",
                    r"column.*does not exist",
                    r"relation.*does not exist",
                    r"table.*doesn't exist",
                    r"Unknown column",
                    r"Unknown table",
                    r"ambiguous column",
                    r"division by zero",
                    r"operand should contain",
                    r"syntax error at or near",
                    r"unterminated quoted string",
                    r"unexpected end of statement",
                ],
            }

            for db_type, patterns in sql_errors.items():
                for pattern in patterns:
                    try:
                        match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
                        if match:
                            # Extract the actual error message (up to 200 chars)
                            error_msg = match.group()[:200].strip()
                            findings.append((f"SQL_ERROR:{db_type}", error_msg))
                            logger.warning(
                                f"SQL error detected: {db_type} in {flow.request.pretty_url}"
                            )
                            logger.info(f"Matched pattern: {pattern}")
                            logger.info(f"Matched text: {error_msg}")
                            break
                    except Exception as e:
                        logger.error(f"Regex error with pattern {pattern}: {e}")

                if findings:
                    break

            if not findings:
                common_errors = [
                    "You have an error in your SQL syntax",
                    "Unknown column",
                    "check the manual that corresponds to your MySQL",
                    "SQL syntax",
                    "mysql_fetch",
                    "ORA-",
                    "PostgreSQL",
                    "SQLite error",
                    "SQLSTATE",
                ]

                body_lower = body.lower()
                for error in common_errors:
                    if error.lower() in body_lower:
                        # Find the actual error message in the body
                        idx = body_lower.find(error.lower())
                        if idx != -1:
                            # Extract context around the error (100 chars)
                            start = max(0, idx - 50)
                            end = min(len(body), idx + 150)
                            error_msg = body[start:end].strip()
                        else:
                            error_msg = error
                        findings.append(("SQL_ERROR:DETECTED", error_msg))
                        logger.warning(
                            f"SQL error detected (fallback) in {flow.request.pretty_url}"
                        )
                        break

        except Exception as e:
            logger.error(f"Error in SQL error detection: {e}")

        return findings

    @staticmethod
    def detect_xml_external_entity(flow) -> List[str]:
        findings = []

        try:
            if not flow.request.content:
                return findings

            content_type = flow.request.headers.get("content-type", "").lower()
            url = flow.request.pretty_url

            is_xml = False

            # Check Content-Type
            if any(
                xml_type in content_type
                for xml_type in [
                    "xml",
                    "application/xml",
                    "text/xml",
                    "application/soap+xml",
                ]
            ):
                is_xml = True
                findings.append("XML_ENDPOINT:content_type")

            # Check URL
            url_lower = url.lower()
            if any(
                pattern in url_lower
                for pattern in [".xml", ".wsdl", ".xsd", "/xml", "/soap"]
            ):
                is_xml = True
                findings.append("XML_ENDPOINT:url")

            if is_xml:
                body = flow.request.content.decode("utf-8", errors="ignore")

                # Check for XML declaration
                if body.strip().startswith("<?xml"):
                    findings.append("XML_ENDPOINT:declaration")

                    # Mark as XXE testing candidate
                    findings.append("XXE_TESTING_CANDIDATE")

                # Check for XXE PAYLOAD patterns (active exploitation)
                xxe_payload_patterns = [
                    (r"<!DOCTYPE[^>]*\[", "DOCTYPE_WITH_DTD"),
                    (r"<!ENTITY\s+\w+\s+SYSTEM", "ENTITY_SYSTEM"),
                    (r"<!ENTITY\s+\w+\s+PUBLIC", "ENTITY_PUBLIC"),
                    (r'SYSTEM\s+["\']file:///', "FILE_PROTOCOL"),
                    (r'SYSTEM\s+["\']http://', "HTTP_PROTOCOL"),
                    (r'SYSTEM\s+["\']ftp://', "FTP_PROTOCOL"),
                    (r"%\w+;", "PARAMETER_ENTITY"),  # External parameter entity
                ]

                for pattern, desc in xxe_payload_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(f"XXE_PAYLOAD:{desc}")
                        findings.append("XXE_EXPLOITATION_ATTEMPT")
                        break

                # Check for common XXE-vulnerable parsers
                vulnerable_patterns = [
                    (r"<soap:Envelope", "SOAP_ENDPOINT"),
                    (r"<SOAP-ENV:Envelope", "SOAP_ENVELOPE"),
                    (r"xmlns:xsi=", "XML_SCHEMA_INSTANCE"),
                ]

                for pattern, desc in vulnerable_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(f"XXE_RISK:{desc}")

        except Exception as e:
            logger.error(f"Error in XML/XXE detection: {e}")

        return findings

    @staticmethod
    def detect_error_messages(body, status_code):
        """Detect error messages that might leak information"""
        if not body or status_code < 400:
            return []

        findings = []
        error_patterns = [
            (r"SQL syntax.*?MySQL", "SQL_ERROR_MYSQL"),
            (r"ORA-\d{5}", "SQL_ERROR_ORACLE"),
            (r"Microsoft SQL Server", "SQL_ERROR_MSSQL"),
            (r"PostgreSQL.*?ERROR", "SQL_ERROR_POSTGRES"),
            (r"Warning.*?\sin\s.*?\.php", "PHP_ERROR"),
            (r"Fatal error.*?in.*?\.php", "PHP_FATAL_ERROR"),
            (r"Traceback \(most recent call last\)", "PYTHON_TRACEBACK"),
            (r"java\.lang\.\w+Exception", "JAVA_EXCEPTION"),
            (r"at\s+[\w.]+\([\w.]+\.java:\d+\)", "JAVA_STACK_TRACE"),
            (r"Microsoft .NET Framework Version:\d", "DOTNET_ERROR"),
            (r"<title>.*?Exception.*?</title>", "EXCEPTION_IN_TITLE"),
        ]

        for pattern, finding in error_patterns:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                # Extract the actual error message (up to 200 chars)
                error_msg = match.group()[:200].strip()
                # Return as tuple (error_type, error_message)
                findings.append((finding, error_msg))

        return findings

    @staticmethod
    def detect_api_keys_in_response(flow) -> List[str]:
        """Detect exposed API keys and secrets in response"""
        findings = []

        if not flow.response or not flow.response.content:
            return findings

        try:
            content = flow.response.content.decode("utf-8", errors="ignore")

            patterns = {
                "AWS_ACCESS_KEY": r"AKIA[0-9A-Z]{16}",
                "AWS_SECRET": r'aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
                "GOOGLE_API": r"AIza[0-9A-Za-z\\-_]{35}",
                "GOOGLE_OAUTH": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
                "GITHUB_TOKEN": r"ghp_[0-9a-zA-Z]{36}",
                "GITHUB_OAUTH": r"gho_[0-9a-zA-Z]{36}",
                "SLACK_TOKEN": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}",
                "SLACK_WEBHOOK": r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9a-zA-Z]{24}",
                "STRIPE_KEY": r"sk_live_[0-9a-zA-Z]{24,}",
                "STRIPE_RESTRICTED": r"rk_live_[0-9a-zA-Z]{24,}",
                "TWILIO_API": r"SK[0-9a-fA-F]{32}",
                "PAYPAL_BRAINTREE": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
                "SQUARE_ACCESS": r"sq0atp-[0-9A-Za-z\\-_]{22}",
                "SQUARE_OAUTH": r"sq0csp-[0-9A-Za-z\\-_]{43}",
                "MAILGUN_API": r"key-[0-9a-zA-Z]{32}",
                "MAILCHIMP_API": r"[0-9a-f]{32}-us[0-9]{1,2}",
                "FACEBOOK_ACCESS": r"EAACEdEose0cBA[0-9A-Za-z]+",
                "TWITTER_OAUTH": r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
                "HEROKU_API": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
                "GENERIC_API_KEY": r'api[_-]?key[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,}',
                "GENERIC_SECRET": r'secret[\'"\s]*[:=][\'"\s]*[0-9a-zA-Z]{32,}',
                "PRIVATE_KEY_HEADER": r"-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----",
            }

            for key_type, pattern in patterns.items():
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    for match in matches:
                        cleaned_match = match.strip("'\"").strip()

                        # Truncate for safety
                        if len(cleaned_match) > 12:
                            display = f"{cleaned_match[:8]}...{cleaned_match[-4:]}"
                        else:
                            display = cleaned_match

                        # Improved finding format
                        findings.append(f"{key_type}: {display}")

                        logger.warning(
                            f"Exposed {key_type} found in response from {flow.request.pretty_url}"
                        )
                        preview = (
                            cleaned_match[:10] + "..."
                            if len(cleaned_match) > 10
                            else cleaned_match
                        )
                        logger.info(f"  Preview: {preview}")

        except Exception as e:
            logger.error(f"Error in API key detection: {e}")

        return findings

    @staticmethod
    def detect_graphql_introspection(flow) -> List[str]:
        """Enhanced GraphQL introspection and schema disclosure detection"""
        findings = []

        try:
            # Check if this is a GraphQL endpoint
            is_graphql = False
            content_type = ""

            if flow.request:
                req_ct = flow.request.headers.get("content-type", "").lower()
                if "application/json" in req_ct or "application/graphql" in req_ct:
                    is_graphql = True
                if (
                    "/graphql" in flow.request.path.lower()
                    or "/graphql" in flow.request.pretty_url.lower()
                ):
                    is_graphql = True
                    findings.append("GRAPHQL_ENDPOINT_DETECTED")

            if flow.response:
                resp_ct = flow.response.headers.get("content-type", "").lower()
                if "application/json" in resp_ct:
                    is_graphql = True

            if not is_graphql:
                return findings

            # Check request for introspection queries
            if flow.request.content:
                try:
                    req_body = flow.request.content.decode("utf-8", errors="ignore")

                    # Enhanced introspection patterns
                    introspection_patterns = {
                        r"__schema": "GRAPHQL_INTROSPECTION:__schema - Schema introspection query",
                        r"__type": "GRAPHQL_INTROSPECTION:__type - Type introspection query",
                        r"IntrospectionQuery": "GRAPHQL_INTROSPECTION:IntrospectionQuery - Full introspection query",
                        r"query\s*{\s*__schema": "GRAPHQL_INTROSPECTION:query__schema - Schema query",
                        r"query\s*{\s*__type": "GRAPHQL_INTROSPECTION:query__type - Type query",
                        r"fragment\s+FullType": "GRAPHQL_INTROSPECTION:FullType - FullType fragment",
                        r"fragment\s+TypeRef": "GRAPHQL_INTROSPECTION:TypeRef - TypeRef fragment",
                    }

                    for pattern, description in introspection_patterns.items():
                        if re.search(pattern, req_body, re.IGNORECASE):
                            findings.append(description)
                            break  # Only report one per request

                    # Check for query batching/aliasing attempts
                    if re.search(
                        r"\[.*__schema.*\]", req_body, re.IGNORECASE | re.DOTALL
                    ):
                        findings.append(
                            "GRAPHQL_INTROSPECTION:BATCHED - Batched introspection query"
                        )

                    # Check for introspection via mutations
                    if re.search(r"mutation.*__schema", req_body, re.IGNORECASE):
                        findings.append(
                            "GRAPHQL_INTROSPECTION:MUTATION - Introspection via mutation"
                        )

                except:
                    pass

            # Check response for schema disclosure
            if flow.response and flow.response.content:
                try:
                    resp_body = flow.response.content.decode("utf-8", errors="ignore")

                    # Check for schema in response
                    if "__schema" in resp_body:
                        findings.append(
                            "GRAPHQL_SCHEMA_DISCLOSED:full_schema - Full GraphQL schema exposed"
                        )

                        # Analyze schema exposure level
                        if '"types":[' in resp_body:
                            # Count types
                            type_matches = re.findall(r'"name":"([^"]+)"', resp_body)
                            if type_matches:
                                unique_types = len(set(type_matches))
                                if unique_types > 10:
                                    findings.append(
                                        f"GRAPHQL_SCHEMA_DETAILS:{unique_types}_types - {unique_types} GraphQL types exposed"
                                    )

                        # Check for sensitive information
                        sensitive_patterns = [
                            (
                                r'"name":"(User|Account|Customer)"',
                                "GRAPHQL_SENSITIVE_DATA:user_data - User/Account types exposed",
                            ),
                            (
                                r'"name":"(Password|Secret|Token|Key)"',
                                "GRAPHQL_SENSITIVE_DATA:secrets - Secret/Token types exposed",
                            ),
                            (
                                r'"name":"(Payment|CreditCard|Bank)"',
                                "GRAPHQL_SENSITIVE_DATA:financial - Financial types exposed",
                            ),
                            (
                                r'"name":"(Email|Phone|Address)"',
                                "GRAPHQL_SENSITIVE_DATA:pii - PII types exposed",
                            ),
                        ]

                        for pattern, finding_text in sensitive_patterns:
                            if re.search(pattern, resp_body, re.IGNORECASE):
                                findings.append(finding_text)
                                break

                    elif '"kind":"' in resp_body:
                        findings.append(
                            "GRAPHQL_SCHEMA_DISCLOSED:kind_fields - GraphQL type kinds exposed"
                        )

                        # Count different kinds
                        kinds = re.findall(r'"kind":"([^"]+)"', resp_body)
                        if kinds:
                            unique_kinds = set(kinds)
                            findings.append(
                                f"GRAPHQL_KINDS_EXPOSED:{len(unique_kinds)} - {', '.join(sorted(unique_kinds))}"
                            )

                    # Check for GraphQL errors that leak schema info
                    if '"errors":[' in resp_body and (
                        "__schema" in resp_body or "__type" in resp_body
                    ):
                        findings.append(
                            "GRAPHQL_ERROR_LEAKAGE:errors - Schema info in error response"
                        )

                except:
                    pass

            # Check for disabled introspection attempts
            if (
                flow.response
                and flow.response.status_code == 400
                or flow.response.status_code == 403
            ):
                if flow.request.content:
                    req_body = flow.request.content.decode("utf-8", errors="ignore")
                    if (
                        "__schema" in req_body
                        or "__type" in req_body
                        or "IntrospectionQuery" in req_body
                    ):
                        findings.append(
                            "GRAPHQL_INTROSPECTION_BLOCKED:blocked - Introspection attempted but blocked"
                        )

        except Exception as e:
            logger.error(f"Error in GraphQL introspection detection: {e}")

        return findings

    @staticmethod
    def detect_debug_mode(flow) -> List[str]:
        """Detect if application is running in debug mode"""
        findings = []

        try:
            if flow.response:
                headers_str = " ".join(
                    [f"{k}:{v}" for k, v in flow.response.headers.items()]
                ).lower()

                # Enhanced debug header detection
                debug_headers = {
                    "x-debug": "DEBUG_HEADER:x-debug detected",
                    "x-debug-token": "DEBUG_HEADER:x-debug-token detected",
                    "x-debug-token-link": "DEBUG_HEADER:x-debug-token-link detected",
                    "x-drupal-cache": "DEBUG_HEADER:x-drupal-cache detected",
                    "x-generator: drupal": "DEBUG_HEADER:x-generator detected",
                    "x-powered-by: express": "DEBUG_HEADER:x-powered-by detected",
                    "x-aspnet-version": "DEBUG_HEADER:x-aspnet-version detected",
                    "x-aspnetmvc-version": "DEBUG_HEADER:x-aspnetmvc-version detected",
                }

                for header, finding in debug_headers.items():
                    if header in headers_str:
                        findings.append(finding)

                if flow.response.content:
                    try:
                        body = flow.response.content.decode("utf-8", errors="ignore")

                        # Enhanced debug patterns with descriptions
                        debug_patterns = [
                            (r"Debugbar", "DEBUG_MODE_ENABLED: Debugbar detected"),
                            (r"XDEBUG", "DEBUG_MODE_ENABLED: Xdebug detected"),
                            (r"var_dump\(", "DEBUG_MODE_ENABLED: var_dump() detected"),
                            (r"print_r\(", "DEBUG_MODE_ENABLED: print_r() detected"),
                            (
                                r"<pre>.*Array.*\(.*\[.*\]",
                                "DEBUG_MODE_ENABLED: PHP array dump detected",
                            ),
                            (
                                r"DEBUG\s*=\s*True",
                                "DEBUG_MODE_ENABLED: DEBUG=True setting detected",
                            ),
                            (
                                r"debug\s*:\s*true",
                                "DEBUG_MODE_ENABLED: debug:true setting detected",
                            ),
                            (
                                r"__DEBUG__",
                                "DEBUG_MODE_ENABLED: __DEBUG__ constant detected",
                            ),
                            (
                                r"[Dd]ebug [Mm]ode",
                                "DEBUG_MODE_ENABLED: Debug mode text detected",
                            ),
                            (
                                r"SQL\s*Query\s*:",
                                "DEBUG_MODE_ENABLED: SQL query debug detected",
                            ),
                            (
                                r"Traceback \(most recent call last\)",
                                "DEBUG_MODE_ENABLED: Python traceback detected",
                            ),
                            (
                                r"Exception\s+in\s+thread",
                                "DEBUG_MODE_ENABLED: Java exception detected",
                            ),
                            (
                                r"Fatal error:.*in.*on line",
                                "DEBUG_MODE_ENABLED: PHP fatal error detected",
                            ),
                        ]

                        for pattern, description in debug_patterns:
                            if re.search(pattern, body):
                                findings.append(description)
                                break

                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Error in debug mode detection: {e}")

        return findings

    @staticmethod
    def detect_admin_panels(url: str) -> List[str]:
        """Enhanced admin panel detection with detailed findings"""
        findings = []

        # Define admin paths with their descriptions
        admin_paths = {
            "/admin": "ADMIN_PANEL:/admin - Generic admin panel detected",
            "/administrator": "ADMIN_PANEL:/administrator - Administrator interface detected",
            "/wp-admin": "ADMIN_PANEL:/wp-admin - WordPress admin panel detected",
            "/cpanel": "ADMIN_PANEL:/cpanel - cPanel hosting control panel detected",
            "/controlpanel": "ADMIN_PANEL:/controlpanel - Control panel detected",
            "/webadmin": "ADMIN_PANEL:/webadmin - Web admin interface detected",
            "/phpmyadmin": "ADMIN_PANEL:/phpmyadmin - phpMyAdmin database admin detected",
            "/pma": "ADMIN_PANEL:/pma - phpMyAdmin alias detected",
            "/adminer": "ADMIN_PANEL:/adminer - Adminer database tool detected",
            "/dbadmin": "ADMIN_PANEL:/dbadmin - Database admin interface detected",
            "/manager": "ADMIN_PANEL:/manager - Management interface detected",
            "/management": "ADMIN_PANEL:/management - Management panel detected",
            "/console": "ADMIN_PANEL:/console - Admin console detected",
            "/dashboard": "ADMIN_PANEL:/dashboard - User dashboard detected",
            "/backend": "ADMIN_PANEL:/backend - Backend admin interface detected",
            "/backoffice": "ADMIN_PANEL:/backoffice - Backoffice admin detected",
            "/adminpanel": "ADMIN_PANEL:/adminpanel - Admin panel detected",
            "/moderator": "ADMIN_PANEL:/moderator - Moderator panel detected",
            "/webmaster": "ADMIN_PANEL:/webmaster - Webmaster panel detected",
            "/root": "ADMIN_PANEL:/root - Root access panel detected",
            "/superuser": "ADMIN_PANEL:/superuser - Superuser panel detected",
            "/supervisor": "ADMIN_PANEL:/supervisor - Supervisor panel detected",
            "/grafana": "ADMIN_PANEL:/grafana - Grafana monitoring panel detected",
            "/kibana": "ADMIN_PANEL:/kibana - Kibana dashboard detected",
            "/jenkins": "ADMIN_PANEL:/jenkins - Jenkins CI/CD panel detected",
            "/portainer": "ADMIN_PANEL:/portainer - Portainer container management detected",
            "/elasticsearch": "ADMIN_PANEL:/elasticsearch - Elasticsearch admin detected",
            "/prometheus": "ADMIN_PANEL:/prometheus - Prometheus monitoring detected",
            "/sonarqube": "ADMIN_PANEL:/sonarqube - SonarQube code quality detected",
            "/redmine": "ADMIN_PANEL:/redmine - Redmine project management detected",
            "/gitlab": "ADMIN_PANEL:/gitlab - GitLab admin detected",
            "/rancher": "ADMIN_PANEL:/rancher - Rancher container management detected",
        }

        url_lower = url.lower()

        # Check for ALL matches (remove the break)
        for admin_path, finding_description in admin_paths.items():
            if admin_path in url_lower:
                findings.append(finding_description)
                # Don't break - allow multiple matches

        # Also check for common patterns
        common_patterns = [
            (r"/admin/\w+", "ADMIN_PANEL:/admin/* - Admin subdirectory detected"),
            (
                r"/wp-admin/\w+",
                "ADMIN_PANEL:/wp-admin/* - WordPress admin subdirectory detected",
            ),
            (r"/cpanel/\w+", "ADMIN_PANEL:/cpanel/* - cPanel subdirectory detected"),
            (
                r"phpmyadmin/\w+",
                "ADMIN_PANEL:phpmyadmin/* - phpMyAdmin subdirectory detected",
            ),
            (
                r"/dashboard/\w+",
                "ADMIN_PANEL:/dashboard/* - Dashboard subdirectory detected",
            ),
            (r"/console/\w+", "ADMIN_PANEL:/console/* - Console subdirectory detected"),
        ]

        for pattern, description in common_patterns:
            if re.search(pattern, url_lower):
                findings.append(description)

        return findings

    @staticmethod
    def detect_default_credentials_endpoints(url: str) -> List[str]:
        """Enhanced default credentials endpoint detection"""
        findings = []

        # Expanded list of services with default credentials
        default_cred_services = {
            # Database Admin Tools
            "/phpmyadmin": "DEFAULT_CREDS_PHPMYADMIN - Default: root/root, admin/admin",
            "/adminer": "DEFAULT_CREDS_ADMINER - Default: admin/(blank)",
            "/pma": "DEFAULT_CREDS_PHPMYADMIN_ALIAS - phpMyAdmin alias",
            "/dbadmin": "DEFAULT_CREDS_DBADMIN - Database admin interface",
            # Monitoring & Analytics
            "/grafana": "DEFAULT_CREDS_GRAFANA - Default: admin/admin",
            "/kibana": "DEFAULT_CREDS_KIBANA - Default: elastic/elastic, kibana/kibana",
            "/prometheus": "DEFAULT_CREDS_PROMETHEUS - Often no auth by default",
            "/solr": "DEFAULT_CREDS_SOLR - Default: solr/solr",
            "/elasticsearch": "DEFAULT_CREDS_ELASTICSEARCH - Default: elastic/elastic",
            # DevOps & CI/CD
            "/jenkins": "DEFAULT_CREDS_JENKINS - Often no auth on install",
            "/tomcat": "DEFAULT_CREDS_TOMCAT - Default: tomcat/tomcat, admin/admin",
            "/jmx-console": "DEFAULT_CREDS_JBOSS - JBoss default console",
            "/web-console": "DEFAULT_CREDS_JBOSS - JBoss web console",
            "/gitlab": "DEFAULT_CREDS_GITLAB - Default: root/5iveL!fe",
            "/rancher": "DEFAULT_CREDS_RANCHER - Often no auth initially",
            # Message Queues
            "/rabbitmq": "DEFAULT_CREDS_RABBITMQ - Default: guest/guest",
            "/activemq": "DEFAULT_CREDS_ACTIVEMQ - Default: admin/admin",
            # Frameworks
            "/actuator": "DEFAULT_CREDS_SPRING - Spring Boot Actuator endpoints",
            "/console": "DEFAULT_CREDS_HIBERNATE - Hibernate console",
            "/admin": "DEFAULT_CREDS_GENERIC_ADMIN - Common default admin",
            # Network Devices (common paths)
            "/router": "DEFAULT_CREDS_ROUTER - Network device admin",
            "/firewall": "DEFAULT_CREDS_FIREWALL - Firewall admin",
            "/switch": "DEFAULT_CREDS_SWITCH - Network switch admin",
            # CMS & Web Apps
            "/wp-admin": "DEFAULT_CREDS_WORDPRESS - WordPress admin (common weak creds)",
            "/administrator": "DEFAULT_CREDS_JOOMLA - Joomla admin",
            "/user/login": "DEFAULT_CREDS_DRUPAL - Drupal login",
            # Virtualization & Container
            "/portainer": "DEFAULT_CREDS_PORTAINER - Portainer container management",
            "/vsphere": "DEFAULT_CREDS_VSPHERE - VMware vSphere",
            "/proxmox": "DEFAULT_CREDS_PROXMOX - Proxmox VE",
            # IoT & Embedded
            "/cgi-bin": "DEFAULT_CREDS_CGI_BIN - Common in embedded devices",
            "/config": "DEFAULT_CREDS_CONFIG - Configuration interfaces",
            "/setup": "DEFAULT_CREDS_SETUP - Setup wizards",
        }

        url_lower = url.lower()

        # Check for exact path matches
        for path, finding in default_cred_services.items():
            if path in url_lower:
                findings.append(finding)

        # Also check for common patterns
        common_patterns = [
            (
                r"/\d+/phpmyadmin",
                "DEFAULT_CREDS_PHPMYADMIN_PORT - phpMyAdmin on non-standard port",
            ),
            (r"/mysql/admin", "DEFAULT_CREDS_MYSQL_ADMIN - MySQL admin interface"),
            (r"/pgadmin", "DEFAULT_CREDS_PGADMIN - PostgreSQL admin"),
            (r"/oracle", "DEFAULT_CREDS_ORACLE - Oracle admin interfaces"),
            (r"/sqlserver", "DEFAULT_CREDS_SQLSERVER - SQL Server admin"),
            (r"/weblogic", "DEFAULT_CREDS_WEBLOGIC - Oracle WebLogic"),
            (r"/websphere", "DEFAULT_CREDS_WEBSPHERE - IBM WebSphere"),
        ]

        for pattern, description in common_patterns:
            if re.search(pattern, url_lower):
                findings.append(description)

        return findings

    @staticmethod
    def detect_cache_poisoning_potential(flow) -> List[str]:
        """Enhanced cache poisoning potential detection"""
        findings = []

        try:
            if flow.response:
                # Check for cache headers
                cache_headers_present = []
                cache_header_types = {
                    "cache-control": "standard_cache",
                    "x-cache": "custom_cache",
                    "cf-cache-status": "cloudflare_cache",
                    "x-varnish": "varnish_cache",
                    "x-cache-hits": "cache_hits",
                    "age": "cache_age",
                    "etag": "etag_cache",
                    "last-modified": "last_modified",
                    "expires": "expires_header",
                    "pragma": "pragma_cache",
                }

                for header, header_type in cache_header_types.items():
                    if header in [h.lower() for h in flow.response.headers.keys()]:
                        cache_headers_present.append(header_type)

                if cache_headers_present:
                    # Check for dangerous request headers
                    dangerous_headers = {
                        "x-forwarded-host": "CACHE_POISONING_POTENTIAL:x-forwarded-host - Host header injection risk",
                        "x-forwarded-server": "CACHE_POISONING_POTENTIAL:x-forwarded-server - Server header injection",
                        "x-host": "CACHE_POISONING_POTENTIAL:x-host - Alternate host header",
                        "x-original-url": "CACHE_POISONING_POTENTIAL:x-original-url - URL rewrite header",
                        "x-rewrite-url": "CACHE_POISONING_POTENTIAL:x-rewrite-url - URL rewrite alternative",
                        "forwarded": "CACHE_POISONING_POTENTIAL:forwarded - Standard proxy header",
                        "x-forwarded-for": "CACHE_POISONING_POTENTIAL:x-forwarded-for - IP forwarding header",
                        "x-real-ip": "CACHE_POISONING_POTENTIAL:x-real-ip - Real IP header",
                        "x-forwarded-proto": "CACHE_POISONING_POTENTIAL:x-forwarded-proto - Protocol header",
                        "x-forwarded-port": "CACHE_POISONING_POTENTIAL:x-forwarded-port - Port header",
                        "x-scheme": "CACHE_POISONING_POTENTIAL:x-scheme - Scheme header",
                        "x-originating-ip": "CACHE_POISONING_POTENTIAL:x-originating-ip - Originating IP",
                        "x-remote-ip": "CACHE_POISONING_POTENTIAL:x-remote-ip - Remote IP header",
                        "x-remote-addr": "CACHE_POISONING_POTENTIAL:x-remote-addr - Remote address",
                    }

                    for header, finding in dangerous_headers.items():
                        if header in [h.lower() for h in flow.request.headers.keys()]:
                            findings.append(finding)

                    # Add cache context
                    if cache_headers_present:
                        cache_context = (
                            f"CACHE_DETECTED:{','.join(cache_headers_present[:3])}"
                        )
                        findings.append(cache_context)

                    # Check for specific dangerous patterns
                    request_headers = {
                        k.lower(): v for k, v in flow.request.headers.items()
                    }

                    # Check for reflected headers in response
                    if flow.response.content:
                        try:
                            body = flow.response.content.decode(
                                "utf-8", errors="ignore"
                            )
                            for header_name in dangerous_headers.keys():
                                if header_name in request_headers:
                                    header_value = request_headers[header_name]
                                    if header_value and header_value in body:
                                        findings.append(
                                            f"REFLECTED_HEADER:{header_name} - Header value reflected in response"
                                        )
                        except:
                            pass

        except Exception as e:
            logger.error(f"Error in cache poisoning detection: {e}")

        return findings
    
    # Legacy method for backwards compatibility
    @staticmethod
    def detect_sql_injection_errors_text(body: str) -> List[str]:
        """Detect SQL injection errors (legacy method)"""
        findings = []
        
        sql_error_patterns = {
            'MYSQL': [
                r'You have an error in your SQL syntax',
                r'check the manual that corresponds to your MySQL',
                r'mysql_fetch',
                r'MySQL server version',
            ],
            'POSTGRES': [
                r'PostgreSQL.*ERROR',
                r'org\.postgresql',
                r'PSQLException',
            ],
            'MSSQL': [
                r'Microsoft SQL Server',
                r'Unclosed quotation mark',
                r'System\.Data\.SqlClient',
            ],
            'ORACLE': [
                r'ORA-\d{5}',
                r'Oracle error',
            ],
            'SQLITE': [
                r'SQLite.*Exception',
                r'sqlite3\.OperationalError',
            ],
        }
        
        for db_type, patterns in sql_error_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    # Extract the actual error message
                    error_msg = match.group()[:200].strip()
                    findings.append((db_type, error_msg))
                    break
        
        return findings
    
    @staticmethod
    def detect_api_keys_in_text(body: str) -> List[Tuple[str, str]]:
        """Detect exposed API keys (legacy method)"""
        findings = []
        
        patterns = {
            'AWS_ACCESS_KEY': r'AKIA[0-9A-Z]{16}',
            'GITHUB_TOKEN': r'ghp_[0-9a-zA-Z]{36}',
            'SLACK_TOKEN': r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
            'STRIPE_KEY': r'sk_live_[0-9a-zA-Z]{24,}',
            'GOOGLE_API': r'AIza[0-9A-Za-z\\-_]{35}',
        }
        
        for key_type, pattern in patterns.items():
            matches = re.findall(pattern, body)
            for match in matches[:3]:
                if len(match) > 12:
                    display = f"{match[:8]}...{match[-4:]}"
                else:
                    display = match
                findings.append((key_type, display))
        
        return findings
    
    @staticmethod
    def detect_graphql_introspection_text(body: str) -> List[str]:
        """Detect GraphQL introspection (legacy method)"""
        findings = []
        
        if '__schema' in body:
            findings.append('SCHEMA_INTROSPECTION')
        
        if '"types":[' in body:
            # Count types
            type_matches = re.findall(r'"name":"([^"]+)"', body)
            if type_matches:
                unique_types = len(set(type_matches))
                findings.append(f'TYPES_EXPOSED:{unique_types}')
        
        return findings


class JSONAPIAnalyzer:
    """Handles JSON, GraphQL, and API endpoint analysis"""

    @staticmethod
    def is_likely_json_request(flow):
        h = {k.lower(): v for k, v in flow.request.headers.items()}
        ct = h.get("content-type", "").lower()
        if (
            "application/json" in ct
            or "application/graphql" in ct
            or "application/ld+json" in ct
        ):
            return True
        if (
            "/graphql" in flow.request.path.lower()
            or "/graphql" in flow.request.pretty_url.lower()
        ):
            return True
        b = flow.request.content or b""
        s = b.lstrip()[:2] if b else b""
        if s in (b"{", b"["):
            return True
        return False

    @staticmethod
    def analyze_json_request_response(flow, all_param_detected):
        req_json = None
        req_text = None
        try:
            if flow.request.content:
                req_text = None
                try:
                    req_text = flow.request.content.decode("utf-8", errors="ignore")
                except:
                    req_text = None
                req_json = Utilities.safe_json_loads(req_text) if req_text else None
                if req_json is None and flow.request.urlencoded_form:
                    form = {}
                    for k, v in flow.request.urlencoded_form.items():
                        form[k] = v
                    if "variables" in form:
                        parsed_vars = Utilities.safe_json_loads(form["variables"])
                        if parsed_vars is not None:
                            req_json = {
                                "graphql": {
                                    "query": form.get("query"),
                                    "variables": parsed_vars,
                                }
                            }
                    elif "query" in form:
                        req_json = {"graphql": {"query": form.get("query")}}
                    else:
                        req_json = form
        except Exception:
            req_json = None

        resp_json = None
        resp_text = None
        try:
            if flow.response and flow.response.content:
                try:
                    resp_text = flow.response.content.decode("utf-8", errors="ignore")
                except:
                    resp_text = None
                resp_json = Utilities.safe_json_loads(resp_text) if resp_text else None
        except Exception:
            resp_json = None

        is_graphql = False
        if req_json and (
            "graphql" in str(req_json).lower()
            or "/graphql" in flow.request.path.lower()
            or "query" in (req_json if isinstance(req_json, dict) else {})
        ):
            is_graphql = True
            all_param_detected.setdefault("GRAPHQL", set()).add("GRAPHQL")

        if req_json:
            for jpath, jval in Utilities.walk_json(req_json):
                sval = None
                try:
                    if jval is None:
                        sval = ""
                    else:
                        sval = str(jval)
                except Exception:
                    sval = None

                detected = ParameterDetector.detect_param_patterns(jpath, sval, "JSON")
                if sval:
                    jwt_found = SecurityDetector.detect_jwt({jpath: sval}, None)
                    if jwt_found:
                        detected.update(set(["JWT"]))

                reflected = False
                if sval:
                    if resp_json and Utilities.json_contains_value(resp_json, sval):
                        detected.add("REFLECTED")
                        reflected = True
                    elif resp_text and sval in resp_text:
                        detected.add("REFLECTED")
                        reflected = True

                if detected:
                    keyname = f"JSON {jpath}"
                    all_param_detected.setdefault(keyname, set()).update(detected)
                    if is_graphql:
                        all_param_detected.setdefault("GRAPHQL_FIELDS", set()).add(
                            jpath
                        )

        if resp_json:
            for rpath, rval in Utilities.walk_json(resp_json):
                sval = None
                try:
                    sval = "" if rval is None else str(rval)
                except Exception:
                    sval = None
                if sval:
                    jwt_found = SecurityDetector.detect_jwt({rpath: sval}, None)
                    if jwt_found:
                        all_param_detected.setdefault(f"RESPONSE {rpath}", set()).add(
                            "JWT"
                        )
                    detected = ParameterDetector.detect_param_patterns(
                        rpath, sval, "RESP_JSON"
                    )
                    if detected:
                        all_param_detected.setdefault(
                            f"RESPONSE {rpath}", set()
                        ).update(detected)

        return

    @staticmethod
    def detect_api_endpoints(url):
        """Detect API endpoints and return the matched pattern"""
        url_lower = url.lower()

        for endpoint in API_ENDPOINTS:
            if endpoint in url_lower:
                return endpoint  # Return the matched pattern

        return None  # Return None if no match


class TemplateLiteralDetector:
    """Detects XSS vulnerabilities in JavaScript template literals"""

    @staticmethod
    def detect_template_literal_xss(js_content: str, url: str = None) -> List[Dict]:
        """
        Comprehensive template literal XSS detection

        Detects patterns like:
        - var html = `<div>${userInput}</div>`
        - element.innerHTML = `<span>${param}</span>`
        - document.write(`Hello ${name}`)
        - var msg = `static text`; elem.innerHTML = msg;

        Returns list of findings
        """
        findings = []

        if not js_content or len(js_content) < 10:
            return findings

        logger.info("⊙ Starting Template Literal XSS Detection...")

        # PHASE 1: IDENTIFY USER-CONTROLLED VARIABLES
        tainted_vars = {}

        # User input sources
        taint_source_patterns = [
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:new\s+)?URLSearchParams\([^)]*\)\.get\s*\(\s*['\"](\w+)['\"]\s*\)", "URLSearchParams.get()", "url_param"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.search", "location.search", "query_string"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.hash", "location.hash", "hash"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*document\.(URL|documentURI|baseURI)", "document.URL", "url"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*document\.referrer", "document.referrer", "referrer"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*req\.(?:query|params|body)\.(\w+)", "req.query/params/body", "request_param"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:localStorage|sessionStorage)\.getItem\s*\(\s*['\"](\w+)['\"]\s*\)", "localStorage/sessionStorage", "storage"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*document\.cookie", "document.cookie", "cookie"),
        ]

        for pattern, source_name, param_type in taint_source_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                var_name = match.group(1)
                if len(match.groups()) >= 2 and param_type in ["url_param", "request_param", "storage"]:
                    param_name = match.group(2)
                else:
                    param_name = param_type
                tainted_vars[var_name] = {"source": source_name, "param": param_name, "line": match.group(0)}

        logger.info(f"   ✓ Found {len(tainted_vars)} tainted variables")

        # PHASE 2: TRACK VARIABLE PROPAGATION
        assignment_patterns = [
            r"(?:var|let|const)\s+(\w+)\s*=\s*(\w+)",
            r"(\w+)\s*=\s*(\w+)",
            r"(?:var|let|const)\s+(\w+)\s*=\s*(\w+)\.\w+",
            r"(\w+)\s*=\s*(\w+)\.\w+",
        ]

        for iteration in range(3):
            new_taints = {}
            for pattern in assignment_patterns:
                matches = re.finditer(pattern, js_content)
                for match in matches:
                    target_var = match.group(1)
                    source_var = match.group(2)
                    if source_var in tainted_vars and target_var not in tainted_vars:
                        new_taints[target_var] = {
                            "source": tainted_vars[source_var]["source"],
                            "param": tainted_vars[source_var]["param"],
                            "propagated_from": source_var,
                        }
            if new_taints:
                tainted_vars.update(new_taints)
            else:
                break

        logger.info(f"   ✓ Total tainted variables after propagation: {len(tainted_vars)}")

        # PHASE 2.5: TRACK TEMPLATE LITERAL VARIABLES
        template_literal_vars = {}
        template_var_pattern = r"(?:var|let|const)\s+(\w+)\s*=\s*(`[^`]*`)"
        matches = re.finditer(template_var_pattern, js_content, re.DOTALL)
        for match in matches:
            var_name = match.group(1)
            template_content = match.group(2)
            template_literal_vars[var_name] = {
                "template": template_content,
                "has_expressions": "${" in template_content,
            }

        logger.info(f"   ✓ Found {len(template_literal_vars)} variables containing template literals")

        # PHASE 3: DETECT TEMPLATE LITERALS WITH TAINTED DATA
        template_literal_pattern = r"`([^`]*\$\{[^}]+\}[^`]*)`"
        template_matches = list(re.finditer(template_literal_pattern, js_content, re.DOTALL))
        logger.info(f"   ✓ Found {len(template_matches)} template literals with expressions")

        for template_match in template_matches:
            template_string = template_match.group(1)
            expressions = re.findall(r"\$\{([^}]+)\}", template_string)

            for expression in expressions:
                clean_expr = expression.strip()
                tainted_var_in_expr = None
                for var_name in tainted_vars.keys():
                    if re.search(rf"\b{re.escape(var_name)}\b", clean_expr):
                        tainted_var_in_expr = var_name
                        break

                if not tainted_var_in_expr:
                    continue

                var_info = tainted_vars[tainted_var_in_expr]
                start = max(0, template_match.start() - 100)
                end = min(len(js_content), template_match.end() + 100)
                context = js_content[start:end]

                severity = "HIGH"
                sink_type = "unknown"
                
                dangerous_sinks = {
                    r"\.innerHTML\s*=\s*`": ("innerHTML", "CRITICAL"),
                    r"\.outerHTML\s*=\s*`": ("outerHTML", "CRITICAL"),
                    r"document\.write\s*\(\s*`": ("document.write()", "CRITICAL"),
                    r"\.insertAdjacentHTML\s*\([^,]+,\s*`": ("insertAdjacentHTML()", "CRITICAL"),
                    r"\$\([^)]*\)\.html\s*\(\s*`": ("jQuery.html()", "CRITICAL"),
                    r"eval\s*\(\s*`": ("eval()", "CRITICAL"),
                }

                for sink_pattern, (sink_name, sink_severity) in dangerous_sinks.items():
                    if re.search(sink_pattern, context):
                        sink_type = sink_name
                        severity = sink_severity
                        break

                has_html = bool(re.search(r"<[a-zA-Z][^>]*>", template_string))
                payload = "${alert(document.domain)}"

                finding = {
                    "type": "template_literal_xss",
                    "severity": severity,
                    "variable": tainted_var_in_expr,
                    "source": var_info["source"],
                    "parameter": var_info["param"],
                    "sink": sink_type,
                    "template": template_string[:200],
                    "expression": clean_expr,
                    "exploitable": True,
                    "has_html": has_html,
                    "payload": payload,
                    "context": context[:200],
                }

                findings.append(finding)
                logger.warning(f"! TEMPLATE LITERAL XSS: {sink_type} - {tainted_var_in_expr}")

        logger.info(f"✓ Template Literal Detection Complete: {len(findings)} findings")
        return findings


class SanitizationDetector:
    """Detects sanitization, validation, and security functions in JavaScript code"""

    # Sanitization function patterns
    SANITIZATION_FUNCTIONS = {
        "html_escape": [
            r"\.escape\s*\(", r"\.escapeHtml\s*\(", r"\.htmlEscape\s*\(",
            r"escapeHTML\s*\(", r"sanitizeHtml\s*\(", r"DOMPurify\.sanitize\s*\(",
            r"xssFilters\.", r"\.stripTags\s*\(", r"\.removeTags\s*\(",
        ],
        "string_replace": [
            r"\.replace\s*\(\s*['\"]?[<>\"'&]\s*['\"]?\s*,",
            r"\.replace\s*\(\s*/[<>\"'&]/g?\s*,", r"\.replaceAll\s*\(",
            r"\.replace\s*\(\s*/[\\\/]/g?\s*,", r"\.replace\s*\(\s*/\.\./g?\s*,",
            r"\.replace\s*\(\s*/[;\(\)\[\]]/g?\s*,",
        ],
        "url_encode": [
            r"encodeURI\s*\(", r"encodeURIComponent\s*\(", r"escape\s*\(",
            r"\.urlEncode\s*\(", r"querystring\.escape\s*\(",
        ],
        "validation": [
            r"validator\.is", r"\.validate\s*\(", r"\.isValid\s*\(",
            r"\.test\s*\(", r"\.match\s*\(", r"typeof\s+\w+\s*===\s*['\"]",
            r"instanceof\s+", r"Array\.isArray\s*\(",
        ],
        "sql_escape": [
            r"\.escape\s*\(", r"connection\.escape\s*\(",
            r"mysql\.escape\s*\(", r"\.escapeId\s*\(", r"pg\.escape\s*\(",
        ],
        "safe_dom": [
            r"\.textContent\s*=", r"\.innerText\s*=", r"\.setAttribute\s*\(",
            r"document\.createTextNode\s*\(", r"createElement\s*\(",
        ],
    }

    # Dangerous unsanitized patterns
    DANGEROUS_UNSANITIZED_PATTERNS = {
        "direct_dom_injection": [
            (r"\.innerHTML\s*=\s*(?:location\.|window\.location\.|params\.|req\.)", "innerHTML with user input"),
            (r"document\.write\s*\(\s*(?:location\.|window\.location\.|params\.|req\.)", "document.write with user input"),
        ],
        "sql_concatenation": [
            (r"['\"]SELECT.*\+\s*\w+", "SQL query with string concatenation"),
            (r"`SELECT.*\$\{", "SQL query with template literal"),
        ],
        "eval_injection": [
            (r"eval\s*\(\s*(?:req\.|params\.|query\.|location\.)", "eval() with user input"),
            (r"Function\s*\(\s*(?:req\.|params\.|query\.)", "Function() with user input"),
        ],
    }

    # Weak sanitization patterns
    WEAK_SANITIZATION_PATTERNS = {
        "incomplete_replace": [
            (r"\.replace\s*\(\s*['\"]<script>['\"]", "Only replaces <script>, not all tags"),
            (r"\.replace\s*\(\s*['\"][<>]['\"]", "Only replaces < or >, not both"),
        ],
        "non_global_replace": [
            (r"\.replace\s*\(\s*/[^/]+/\s*,", "Non-global regex (missing /g flag)"),
        ],
        "wrong_context_encoding": [
            (r"['\"]<[^'\"]*\+\s*encodeURIComponent\s*\([^)]+\)", "encodeURIComponent in HTML context"),
        ],
    }

    @staticmethod
    def analyze_sanitization(js_content: str, url: str = None) -> Dict[str, Any]:
        """Comprehensive sanitization analysis"""
        findings = {
            "sanitization_found": [],
            "missing_sanitization": [],
            "weak_sanitization": [],
            "security_score": 0,
        }

        if not js_content or len(js_content) < 10:
            return findings

        sanitization_count = 0

        # Detect sanitization functions
        for category, patterns in SanitizationDetector.SANITIZATION_FUNCTIONS.items():
            for pattern in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end].replace("\n", " ").strip()
                    findings["sanitization_found"].append({
                        "type": category,
                        "matched": match.group(0),
                        "context": context[:100],
                        "severity": "GOOD",
                    })
                    sanitization_count += 1

        # Detect dangerous patterns
        for category, patterns in SanitizationDetector.DANGEROUS_UNSANITIZED_PATTERNS.items():
            for pattern, description in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end].replace("\n", " ").strip()
                    findings["missing_sanitization"].append({
                        "type": category,
                        "description": description,
                        "matched": match.group(0),
                        "context": context[:100],
                        "severity": "CRITICAL",
                    })

        # Detect weak sanitization
        for category, patterns in SanitizationDetector.WEAK_SANITIZATION_PATTERNS.items():
            for pattern, description in patterns:
                matches = re.finditer(pattern, js_content, re.IGNORECASE)
                for match in matches:
                    start = max(0, match.start() - 50)
                    end = min(len(js_content), match.end() + 50)
                    context = js_content[start:end].replace("\n", " ").strip()
                    findings["weak_sanitization"].append({
                        "type": category,
                        "description": description,
                        "matched": match.group(0),
                        "context": context[:100],
                        "severity": "HIGH",
                    })

        # Calculate security score
        score = 50
        score += min(sanitization_count * 2, 40)
        score -= min(len(findings["missing_sanitization"]) * 10, 40)
        score -= min(len(findings["weak_sanitization"]) * 5, 20)
        findings["security_score"] = max(0, min(100, score))

        return findings

    @staticmethod
    def detect_validation_bypass(js_content: str) -> List[Dict]:
        """Detect validation bypass patterns"""
        findings = []
        bypass_patterns = [
            (r"if\s*\(\s*!.*\.test\s*\(", "Client-side only validation"),
            (r"//\s*if\s*\(.*validate", "Validation commented out"),
            (r"if\s*\(\s*true\s*\)", "Always true condition"),
            (r"if\s*\(\s*debug\s*\)", "Debug bypass"),
        ]

        for pattern, description in bypass_patterns:
            matches = re.finditer(pattern, js_content, re.IGNORECASE)
            for match in matches:
                findings.append({
                    "type": "validation_bypass",
                    "description": description,
                    "matched": match.group(0),
                    "severity": "HIGH",
                })

        return findings

    @staticmethod
    def analyze_input_handling(js_content: str) -> Dict[str, List[Dict]]:
        """Analyze user input handling"""
        findings = {
            "raw_input_usage": [],
            "sanitized_input_usage": [],
            "validated_input_usage": [],
        }

        input_sources = [
            r"req\.body\.\w+", r"req\.query\.\w+", r"req\.params\.\w+",
            r"location\.search", r"location\.hash", r"document\.cookie",
        ]

        for source_pattern in input_sources:
            matches = re.finditer(source_pattern, js_content, re.IGNORECASE)
            for match in matches:
                input_var = match.group(0)
                start = max(0, match.start() - 100)
                end = min(len(js_content), match.end() + 100)
                context = js_content[start:end]

                has_sanitization = any(
                    re.search(rf"{re.escape(input_var)}[^;{{]*{san_pattern}", context)
                    for san_patterns in SanitizationDetector.SANITIZATION_FUNCTIONS.values()
                    for san_pattern in san_patterns
                )

                has_validation = any([
                    re.search(rf"if\s*\([^)]*{re.escape(input_var)}", context),
                    re.search(rf"{re.escape(input_var)}\.test\(", context),
                ])

                if has_sanitization:
                    findings["sanitized_input_usage"].append({
                        "input": input_var,
                        "context": context[:150].replace("\n", " ").strip(),
                    })
                elif has_validation:
                    findings["validated_input_usage"].append({
                        "input": input_var,
                        "context": context[:150].replace("\n", " ").strip(),
                    })
                else:
                    findings["raw_input_usage"].append({
                        "input": input_var,
                        "context": context[:150].replace("\n", " ").strip(),
                        "severity": "HIGH",
                    })

        return findings


class DataLeakageDetector:
    """Handles detection of data leakage, internal IPs, emails, version disclosure"""

    @staticmethod
    def detect_internal_ip_disclosure(flow) -> List[str]:
        """Detect internal IP addresses in responses and headers"""
        findings = []

        try:
            internal_patterns = [
                r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # 10.0.0.0/8
                r"\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b",  # 172.16.0.0/12
                r"\b192\.168\.\d{1,3}\.\d{1,3}\b",  # 192.168.0.0/16
                r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",  # 127.0.0.0/8 (localhost)
                r"\blocalhost\b",
                r"\b0\.0\.0\.0\b",
            ]

            if flow.response:
                # Check HEADERS
                header_str = " ".join(
                    [f"{k}:{v}" for k, v in flow.response.headers.items()]
                )
                all_header_ips = []
                for pattern in internal_patterns:
                    matches = re.findall(pattern, header_str, re.IGNORECASE)
                    if matches:
                        all_header_ips.extend(matches)

                if all_header_ips:
                    unique_ips = list(set(all_header_ips))[:5]  # Limit to 5
                    findings.append(f"INTERNAL_IP_IN_HEADERS[{','.join(unique_ips)}]")

                # Check BODY
                if flow.response.content:
                    try:
                        body = flow.response.content.decode("utf-8", errors="ignore")
                        all_body_ips = []
                        for pattern in internal_patterns:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                all_body_ips.extend(matches)

                        if all_body_ips:
                            unique_ips = list(set(all_body_ips))[:5]
                            findings.append(
                                f"INTERNAL_IP_IN_BODY[{','.join(unique_ips)}]"
                            )
                    except Exception:
                        pass

        except Exception as e:
            logger.error(f"Error in internal IP detection: {e}")

        return findings

    @staticmethod
    def detect_email_disclosure(flow) -> List[str]:
        """Detect email addresses in responses"""
        findings = []

        if not flow.response or not flow.response.content:
            return findings

        try:
            content = flow.response.content.decode("utf-8", errors="ignore")

            email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            emails = re.findall(email_pattern, content)

            if emails and len(emails) > 5:  # Only report if 5+ emails
                unique_emails = list(set(emails))

                sample_emails = unique_emails[:3]
                findings.append(
                    f"EMAIL_DISCLOSURE:COUNT={len(unique_emails)}[{','.join(sample_emails)}]"
                )

                # Check for internal domains
                internal_domains = [
                    "internal",
                    "corp",
                    "local",
                    "test",
                    "dev",
                    "staging",
                ]
                internal_emails_found = []

                for email in unique_emails:
                    if "@" in email:
                        domain = email.split("@")[1].lower()
                        for internal in internal_domains:
                            if internal in domain:
                                internal_emails_found.append(email)
                                break

                if internal_emails_found:
                    sample_internal = internal_emails_found[:5]
                    findings.append(
                        f"INTERNAL_EMAIL_DISCLOSED[{','.join(sample_internal)}]"
                    )

        except Exception as e:
            logger.error(f"Error in email disclosure detection: {e}")

        return findings

    @staticmethod
    def detect_sensitive_data_exposure(headers, body, url):
        """Detect potential sensitive data exposure"""
        findings = []

        # 1. CHECK URL FOR SENSITIVE PARAMETERS
        sensitive_url_patterns = [
            (r"api[_-]?key=([a-zA-Z0-9_-]+)", "API_KEY_IN_URL"),
            (r"access[_-]?token=([a-zA-Z0-9_.-]+)", "ACCESS_TOKEN_IN_URL"),
            (r"password=([^&\s]+)", "PASSWORD_IN_URL"),
            (r"secret=([a-zA-Z0-9_-]+)", "SECRET_IN_URL"),
            (r"token=([a-zA-Z0-9_.-]+)", "TOKEN_IN_URL"),
            (r"auth=([a-zA-Z0-9_.-]+)", "AUTH_IN_URL"),
        ]

        for pattern, finding_type in sensitive_url_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                value = match.group(1)
                # Truncate for safety
                if len(value) > 20:
                    display = f"{value[:12]}...{value[-4:]}"
                else:
                    display = value
                findings.append(f"{finding_type}[{display}]")

        if not body:
            return findings

        # 2. AWS ACCESS KEYS
        aws_access_keys = re.findall(r"(AKIA[0-9A-Z]{16})", body)
        for key in aws_access_keys:
            findings.append(f"AWS_ACCESS_KEY[{key}]")

        # 3. AWS SECRET KEYS (40 chars base64-like in quotes)
        aws_secret_pattern = r'["\']([0-9a-zA-Z/+]{40})["\']'
        aws_secrets = re.findall(aws_secret_pattern, body)
        for secret in aws_secrets:
            # Only report if looks like AWS secret (has mix of chars)
            if (
                re.search(r"[A-Z]", secret)
                and re.search(r"[a-z]", secret)
                and re.search(r"[0-9]", secret)
            ):
                display = f"{secret[:8]}...{secret[-4:]}"
                findings.append(f"AWS_SECRET[{display}]")

        # 4. PRIVATE KEYS
        if (
            "BEGIN PRIVATE KEY" in body
            or "BEGIN RSA PRIVATE KEY" in body
            or "BEGIN DSA PRIVATE KEY" in body
            or "BEGIN EC PRIVATE KEY" in body
        ):
            lines = body.split("\n")
            for i, line in enumerate(lines, 1):
                if "BEGIN PRIVATE" in line or "BEGIN RSA PRIVATE" in line:
                    # Get context around the key
                    start = max(0, i - 2)
                    end = min(len(lines), i + 3)
                    snippet = "\n".join(lines[start:end])
                    findings.append(f"PRIVATE_KEY_EXPOSED[LINE_{i}:{snippet[:50]}...]")
                    break

        # 5. DATABASE CONNECTION STRINGS
        db_patterns = [
            (r'(mongodb(\+srv)?://[^\s\'"]+)', "MONGODB"),
            (r'(mysql://[^\s\'"]+)', "MYSQL"),
            (r'(postgres://[^\s\'"]+)', "POSTGRES"),
            (r'(postgresql://[^\s\'"]+)', "POSTGRESQL"),
            (r'(Server\s*=\s*[^;]+;.*Database\s*=\s*[^;]+;[^"\'\s]*)', "SQL_SERVER"),
            (r'(redis://[^\s\'"]+)', "REDIS"),
        ]

        for pattern, db_type in db_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for match in matches:
                conn_str = match[0] if isinstance(match, tuple) else match
                # Mask passwords in connection string
                masked = re.sub(r":[^/@]+@", ":****@", conn_str)
                # Truncate if too long
                if len(masked) > 80:
                    masked = masked[:77] + "..."
                findings.append(f"DATABASE_CONNECTION_STRING[{db_type}:{masked}]")

        # 6. GOOGLE API KEYS
        google_api_keys = re.findall(r"AIza[0-9A-Za-z\-_]{35}", body)
        for key in google_api_keys:
            display = f"{key[:12]}...{key[-4:]}"
            findings.append(f"GOOGLE_API_KEY[{display}]")

        # 7. GITHUB TOKENS
        github_patterns = [
            (r"ghp_[0-9a-zA-Z]{36}", "GITHUB_PAT"),
            (r"gho_[0-9a-zA-Z]{36}", "GITHUB_OAUTH"),
            (r"ghs_[0-9a-zA-Z]{36}", "GITHUB_SECRET"),
            (r"ghr_[0-9a-zA-Z]{36}", "GITHUB_REFRESH"),
        ]

        for pattern, token_type in github_patterns:
            matches = re.findall(pattern, body)
            for token in matches:
                display = f"{token[:12]}...{token[-4:]}"
                findings.append(f"{token_type}[{display}]")

        # 8. SLACK TOKENS
        slack_patterns = [
            (r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}", "SLACK_TOKEN"),
            (
                r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,10}/B[0-9A-Z]{8,10}/[0-9a-zA-Z]{24}",
                "SLACK_WEBHOOK",
            ),
        ]

        for pattern, token_type in slack_patterns:
            matches = re.findall(pattern, body)
            for token in matches:
                if len(token) > 30:
                    display = f"{token[:15]}...{token[-4:]}"
                else:
                    display = token
                findings.append(f"{token_type}[{display}]")

        # 9. STRIPE KEYS
        stripe_patterns = [
            (r"sk_live_[0-9a-zA-Z]{24,}", "STRIPE_SECRET"),
            (r"pk_live_[0-9a-zA-Z]{24,}", "STRIPE_PUBLIC"),
            (r"rk_live_[0-9a-zA-Z]{24,}", "STRIPE_RESTRICTED"),
        ]

        for pattern, key_type in stripe_patterns:
            matches = re.findall(pattern, body)
            for key in matches:
                display = f"{key[:15]}...{key[-4:]}" if len(key) > 20 else key
                findings.append(f"{key_type}[{display}]")

        # 10. JWT TOKENS (already handled by SecurityDetector, but double-check in body)
        jwt_pattern = (
            r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
        )
        jwt_tokens = re.findall(jwt_pattern, body)
        for token in jwt_tokens:
            # Only first 30 chars
            display = f"{token[:30]}..." if len(token) > 30 else token
            findings.append(f"JWT_TOKEN_IN_BODY[{display}]")

        # 11. GENERIC API KEYS (various patterns)
        generic_api_patterns = [
            (
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                "API_KEY",
            ),
            (r'["\']?apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', "API_KEY"),
            (
                r'["\']?api[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                "API_SECRET",
            ),
            (
                r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                "SECRET_KEY",
            ),
        ]

        for pattern, finding_type in generic_api_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for key in matches:
                if len(key) >= 20:  # Only report if substantial
                    display = f"{key[:12]}...{key[-4:]}" if len(key) > 20 else key
                    findings.append(f"{finding_type}_IN_BODY[{display}]")

        # 12. PASSWORDS IN CODE/CONFIG
        password_patterns = [
            (r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "PASSWORD"),
            (r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "PASSWORD"),
            (r'["\']?pwd["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', "PASSWORD"),
        ]

        for pattern, finding_type in password_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for pwd in matches:
                # Don't report if it's a placeholder
                if pwd.lower() not in [
                    "password",
                    "your_password",
                    "changeme",
                    "********",
                    "xxxx",
                ]:
                    display = f"{pwd[:4]}***{pwd[-2:]}" if len(pwd) > 8 else "***"
                    findings.append(f"{finding_type}_IN_BODY[{display}]")

        # 13. SENSITIVE COMMENTS
        comment_findings = DataLeakageDetector.detect_sensitive_comments(body, url)
        findings.extend(comment_findings)

        return findings

    @staticmethod
    def detect_sensitive_comments(content, url=None):
        """Detect sensitive information in comments - compact version"""
        findings = []

        if not content:
            return findings

        # Unified comment patterns for both HTML and JS
        comment_patterns = [
            # 1. Comment types regex
            (r"<!--(.*?)-->", "HTML"),  # HTML comments
            (r"//(.*?)$", "JS_SINGLE"),  # JS single-line comments
            (r"/\*(.*?)\*/", "JS_MULTI", re.DOTALL),  # JS multi-line comments
        ]

        # 2. Sensitive content patterns to look for in comments
        sensitive_patterns = [
            # Credentials
            (
                r'(?:user|username|login|email)\s*[:=]\s*[\'"]([^\'"]{3,})[\'"]',
                "CREDENTIAL",
            ),
            (
                r'(?:pass|password|pwd|passwd)\s*[:=]\s*[\'"]([^\'"]{4,})[\'"]',
                "PASSWORD",
            ),
            # Secrets and API keys
            (
                r'(?:api[_-]?key|apikey|key)\s*[:=]\s*[\'"]([a-zA-Z0-9_-]{8,})[\'"]',
                "API_KEY",
            ),
            (
                r'(?:secret|token|auth[_-]?token)\s*[:=]\s*[\'"]([a-zA-Z0-9._-]{8,})[\'"]',
                "SECRET_TOKEN",
            ),
            (
                r'(?:access[_-]?key|access[_-]?secret)\s*[:=]\s*[\'"]([^\'"]{8,})[\'"]',
                "ACCESS_KEY",
            ),
            # Database connections
            (
                r'(?:database|db|mysql|postgres|mongodb)[^:]*[:=]\s*[\'"]([^\'"]{10,})[\'"]',
                "DB_CONNECTION",
            ),
            (r'(?:host|server|endpoint)[^:]*[:=]\s*[\'"]([^\'"]{5,})[\'"]', "ENDPOINT"),
            # Security-related TODO/FIXME
            (
                r"(TODO|FIXME|XXX|HACK|NOTE|WARNING)\s*:.*?(?:password|secret|key|token|auth)",
                "SECURITY_TODO",
            ),
            (
                r"(TODO|FIXME|XXX)\s*:.*?(?:remove|delete|change).*?(?:in\s+prod|production)",
                "PROD_TODO",
            ),
            # Debug/test credentials
            (
                r'(?:test|debug|dev|staging).*?(?:user|pass)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                "TEST_CREDS",
            ),
            (
                r'(?:sample|example|demo).*?(?:password|key)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                "SAMPLE_CREDS",
            ),
            # Security bypass/disable
            (
                r"(?:bypass|disable|skip|ignore).*?(?:auth|security|validation|check|sanitize)",
                "SECURITY_BYPASS",
            ),
            (
                r"(?:unsafe|dangerous|insecure).*?(?:method|function|code|practice)",
                "INSECURE_CODE",
            ),
            # Admin/privileged access
            (r'admin.*?[:=].*?[\'"]([^\'"]+)[\'"]', "ADMIN_INFO"),
            (
                r'root.*?(?:pass|password|creds)\s*[:=]\s*[\'"]([^\'"]+)[\'"]',
                "ROOT_CREDS",
            ),
            # Internal/hidden endpoints
            (
                r"(?:internal|private|hidden|secret).*?(?:url|endpoint|api|route)",
                "INTERNAL_ENDPOINT",
            ),
            # Hardcoded values warning
            (r"hardcoded.*?(?:value|string|credential|key)", "HARDCODED_VALUE"),
            (
                r"(?:don\'?t\s+commit|do\s+not\s+commit|remove\s+before).*?(?:commit|push)",
                "DO_NOT_COMMIT",
            ),
        ]

        # Extract all comments
        all_comments = []

        for pattern_data in comment_patterns:
            if len(pattern_data) == 3:
                pattern, comment_type, flags = pattern_data
                regex_flags = re.IGNORECASE | flags
            else:
                pattern, comment_type = pattern_data
                regex_flags = re.IGNORECASE | re.MULTILINE

            matches = re.findall(pattern, content, regex_flags)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]  # Get the comment content
                all_comments.append({"content": match.strip(), "type": comment_type})

        # Analyze each comment
        for comment in all_comments:
            comment_text = comment["content"]
            comment_type = comment["type"]

            if not comment_text or len(comment_text) < 3:
                continue

            # Check for sensitive patterns
            for pattern, finding_type in sensitive_patterns:
                match = re.search(pattern, comment_text, re.IGNORECASE)
                if match:
                    # Extract the sensitive value
                    if len(match.groups()) > 0 and match.group(1):
                        value = match.group(1)
                    else:
                        value = comment_text[:50]

                    # Truncate for safety
                    safe_value = value[:20] + "..." if len(value) > 20 else value

                    # Create finding with context
                    finding = f"{comment_type}_COMMENT_{finding_type}[{safe_value}]"

                    # Add URL context if available
                    if url:
                        if url.endswith(".js"):
                            finding = finding.replace("JS_", "JS_FILE_")
                        elif url.endswith(".html") or url.endswith(".htm"):
                            finding = finding.replace("HTML_", "HTML_FILE_")

                    findings.append(finding)
                    break  # Only report first finding per comment

        return findings

    @staticmethod
    def detect_version_disclosure(headers, response_body=None) -> List[str]:
        """Universal version disclosure detector"""
        findings = set()

        if not headers and not response_body:
            return []

        try:
            headers_lower = (
                {k.lower(): str(v) for k, v in headers.items()} if headers else {}
            )

            # Header version detection
            for header, value in headers_lower.items():
                matches = re.findall(
                    r"([a-zA-Z][a-zA-Z0-9\-_\.]{2,30})[\/\s]v?(\d+\.\d+(?:\.\d+)?(?:[-_a-zA-Z0-9]+)?)",
                    value,
                )

                for tech, version in matches:
                    findings.add(f"VERSION_INFO:HEADER[{header} => {tech} {version}]")

            # Body version detection
            if response_body:
                body = response_body
                if isinstance(body, bytes):
                    body = body.decode("utf-8", errors="ignore")

                body = body[:200_000]
                body_lower = body.lower()

                body_patterns = [
                    r"([A-Za-z][A-Za-z0-9\-_\.]{2,30})/(\d+\.\d+(?:\.\d+)?)",
                    r"([A-Za-z][A-Za-z0-9\-_\.]{2,30})\s+v?(\d+\.\d+(?:\.\d+)?)",
                    r"(?:version|ver|release)\s*[:=]\s*(\d+\.\d+(?:\.\d+)?)",
                    r'<meta[^>]+generator[^>]+content=["\']([^"\']+)["\']',
                ]

                max_findings = 5
                for pattern in body_patterns:
                    # Check before processing each pattern
                    if len(findings) >= max_findings:
                        break

                    for match in re.findall(pattern, body, re.IGNORECASE):
                        # Check before processing each match
                        if len(findings) >= max_findings:
                            break

                        if isinstance(match, tuple):
                            tech, version = match
                            findings.add(
                                f"VERSION_INFO:BODY[{tech.strip()} {version.strip()}]"
                            )
                        else:
                            findings.add(f"VERSION_INFO:BODY[version {match}]")

                # High-risk tech detection
                high_risk_tech = [
                    "apache struts",
                    "spring boot",
                    "jboss",
                    "weblogic",
                    "websphere",
                    "wordpress",
                    "drupal",
                    "joomla",
                    "laravel",
                    "django",
                ]

                for tech in high_risk_tech:
                    if tech in body_lower:
                        version_match = re.search(
                            rf"{tech}.*?(\d+\.\d+(?:\.\d+)?)", body_lower
                        )
                        version = version_match.group(1) if version_match else "unknown"
                        findings.add(
                            f'VERSION_HIGH:{tech.upper().replace(" ", "_")}[{version}]'
                        )

                # Stack trace detection
                stack_keywords = [
                    "exception in thread",
                    "traceback (most recent call last)",
                    "fatal error",
                    "uncaught exception",
                    "at java.",
                    "at org.",
                    "system.nullreferenceexception",
                ]

                if any(k in body_lower for k in stack_keywords):
                    findings.add("VERSION_HIGH:STACK_TRACE_DISCLOSED")

        except Exception:
            pass

        return sorted(findings)
    
    # Legacy methods for backwards compatibility
    @staticmethod
    def detect_internal_ips(text: str) -> List[str]:
        """Detect internal IP addresses (legacy method)"""
        ips = []
        
        patterns = [
            r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            r'\b172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b',
            r'\b192\.168\.\d{1,3}\.\d{1,3}\b',
            r'\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text)
            ips.extend(matches[:5])
        
        return list(set(ips))[:10]
    
    @staticmethod
    def detect_emails(text: str) -> List[str]:
        """Detect email addresses (legacy method)"""
        pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        emails = re.findall(pattern, text)
        return list(set(emails))[:10]


# ============================================================================
# MAIN SECURITY ANALYZER
# ============================================================================

class SecurityAnalyzer:
    """
    Main security analysis orchestrator.
    Coordinates all analyzer classes to produce complete results.
    """
    
    @staticmethod
    def analyze_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Complete security analysis of a finding.
        
        Args:
            finding: Raw finding from hunt.jsonl with request_file and response_file
            
        Returns:
            Complete analysis results with all vulnerabilities detected
        """
        results = {
            'params': {},
            'severity': 'LOW',
            'issues_found': [],
            'analysis_timestamp': datetime.now().isoformat(),
            'cookies': [],        # NEW: parsed Set-Cookie entries with security flags
            'tech_stack': {},     # NEW: detected technologies {name: [evidence]}
            'response_headers': {},  # NEW: raw parsed response headers
            '_response_text': '',    # raw response text (for regex fallback in UI panels)
            'weird': [],          # NEW: anomalous / weird findings
        }
        
        try:
            # Load request and response
            request_text = SecurityAnalyzer._load_file(finding.get('request_file'))
            response_text = SecurityAnalyzer._load_file(finding.get('response_file'))
            
            if not request_text and not response_text:
                logger.warning(f"No content to analyze for {finding.get('url')}")
                return results
            
            # Extract metadata
            url = finding.get('url', '')
            method = finding.get('method', 'GET')
            status = finding.get('status', 0)
            
            # Cache response headers for panels
            results['response_headers'] = SecurityAnalyzer._parse_headers(response_text) if response_text else {}
            results['_response_text']   = response_text or ''
            results['_request_text']    = request_text or ''

            # Run all analyzers
            SecurityAnalyzer._analyze_url_parameters(url, results, response_text)
            SecurityAnalyzer._analyze_request_body(request_text, method, results, response_text)
            SecurityAnalyzer._analyze_response_content(response_text, url, results)
            SecurityAnalyzer._analyze_javascript(response_text, url, results)
            SecurityAnalyzer._analyze_security_headers(request_text, response_text, results)
            SecurityAnalyzer._analyze_vulnerabilities(response_text, url, status, results)
            SecurityAnalyzer._analyze_data_leakage(response_text, results)
            SecurityAnalyzer._analyze_cookies(response_text, results, request_text)
            SecurityAnalyzer._analyze_tech_stack(response_text, url, results)  # NEW
            SecurityAnalyzer._analyze_weird(request_text, response_text, url, status, results)  # NEW
            
            # Calculate overall severity
            SecurityAnalyzer._calculate_severity(results)
            
        except Exception as e:
            logger.error(f"Analysis error: {e}", exc_info=True)
        
        return results
    
    @staticmethod
    def _load_file(filepath: str) -> str:
        """Load file content"""
        if not filepath or not os.path.exists(filepath):
            return ""
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to load {filepath}: {e}")
            return ""
    
    @staticmethod
    def _analyze_url_parameters(url: str, results: Dict, response_text: str = ""):
        """Analyze URL parameters"""
        if '?' not in url:
            return
        
        query = url.split('?', 1)[1]
        for param_pair in query.split('&'):
            if '=' in param_pair:
                key, value = param_pair.split('=', 1)
                detected = ParameterDetector.detect_param_patterns(key, value, "URL")
                
                # Check if value is reflected in response
                if response_text and SecurityAnalyzer._check_reflection(value, response_text):
                    detected.add("REFLECTED")
                
                if detected:
                    param_key = f'URL {key}'
                    results['params'][param_key] = list(detected)
                    results['issues_found'].extend(detected)

                # ── JSONP endpoint confirmation ────────────────────────────
                if key.lower() in ('callback', 'jsonp', 'cb', 'jscallback', 'jsonpcallback'):
                    if response_text and value:
                        escaped_cb = re.escape(value)
                        if re.search(rf'{escaped_cb}\s*\(', response_text[:800]):
                            rkey = f'URL JSONP_ENDPOINT {key}'
                            if rkey not in results['params']:
                                results['params'][rkey] = [
                                    'HIGH', 'JSONP_ENDPOINT',
                                    f'CALLBACK:{value}',
                                    'NOTE:Response wraps JSON in callback function — test for cross-origin data theft via CSRF',
                                ]
                                results['issues_found'].append('JSONP_ENDPOINT')

        # ── OAuth without state parameter (CSRF via OAuth) ────────────────
        url_lower = url.lower()
        if ('redirect_uri=' in url_lower or 'client_id=' in url_lower or 'response_type=' in url_lower):
            if 'state=' not in url_lower:
                results['params']['URL OAUTH_STATE_MISSING'] = [
                    'HIGH', 'OAUTH', 'CSRF_VIA_OAUTH',
                    'NOTE:OAuth request missing state parameter — an attacker can force account linking via CSRF',
                ]
                results['issues_found'].append('OAUTH_STATE_MISSING')

        # ── Web Cache Deception — sensitive path with static-file suffix ──
        url_path = url.split('?')[0].lower()
        _wcd_sensitive = ('/account', '/profile', '/user', '/dashboard', '/cart',
                          '/order', '/payment', '/admin', '/settings', '/billing')
        _wcd_suffixes  = ('.css', '.js', '.png', '.jpg', '.gif', '.ico', '.html',
                          '.txt', '.xml', '.woff', '.ttf')
        if (any(sp in url_path for sp in _wcd_sensitive)
                and any(url_path.endswith(cs) for cs in _wcd_suffixes)):
            if 'URL WEB_CACHE_DECEPTION' not in results['params']:
                results['params']['URL WEB_CACHE_DECEPTION'] = [
                    'HIGH', 'WEB_CACHE_DECEPTION',
                    f'PATH:{url_path}',
                    'NOTE:Sensitive path with static-file suffix — CDN may cache and serve response to other users',
                ]
                results['issues_found'].append('WEB_CACHE_DECEPTION')
    
    @staticmethod
    def _analyze_request_body(request_text: str, method: str, results: Dict, response_text: str = ""):
        """Analyze request body parameters"""
        if not request_text or method not in ['POST', 'PUT', 'PATCH']:
            return
        
        if '\n\n' in request_text:
            body = request_text.split('\n\n', 1)[1].strip()
            
            if not body:
                return
            
            # JSON body
            if body.strip().startswith('{'):
                try:
                    data = json.loads(body)
                    for key, value in SecurityAnalyzer._flatten_json(data).items():
                        detected = ParameterDetector.detect_param_patterns(key, str(value), "JSON")
                        
                        # Check if value is reflected in response
                        if response_text and SecurityAnalyzer._check_reflection(str(value), response_text):
                            detected.add("REFLECTED")
                        
                        if detected:
                            results['params'][f'JSON {key}'] = list(detected)
                            results['issues_found'].extend(detected)
                except:
                    pass
            
            # Form data (application/x-www-form-urlencoded)
            elif '=' in body:
                # Split by & to get parameters
                params = body.split('&')
                
                for param_pair in params:
                    if '=' in param_pair:
                        # Split only on first = to handle values with =
                        key, value = param_pair.split('=', 1)
                        
                        # URL decode key and value
                        try:
                            from urllib.parse import unquote
                            decoded_key = unquote(key)
                            decoded_value = unquote(value)
                        except:
                            decoded_key = key
                            decoded_value = value
                        
                        # Detect patterns in both key and value
                        detected = ParameterDetector.detect_param_patterns(decoded_key, decoded_value, "BODY")
                        
                        # Check if the decoded value is reflected
                        if response_text and SecurityAnalyzer._check_reflection(decoded_value, response_text):
                            detected.add("REFLECTED")
                        
                        # Also check if original encoded value is reflected
                        if response_text and value != decoded_value and SecurityAnalyzer._check_reflection(value, response_text):
                            detected.add("REFLECTED")
                        
                        if detected:
                            results['params'][f'BODY {decoded_key}'] = list(detected)
                            results['issues_found'].extend(detected)
                        
                        # ALWAYS add body parameters to show them in the table
                        # even if no specific vulnerability pattern detected
                        if f'BODY {decoded_key}' not in results['params']:
                            # Check if it looks interesting
                            interesting_keywords = ['api', 'url', 'path', 'file', 'redirect', 'callback', 
                                                   'next', 'return', 'uri', 'link', 'src', 'dest']
                            
                            is_interesting = any(keyword in decoded_key.lower() for keyword in interesting_keywords)

                            # Never expose raw secret values in the param table — route to data leakage
                            _cred_keywords = [
                                'api_key', 'apikey', 'secret', 'password', 'passwd', 'pwd',
                                'token', 'auth', 'bearer', 'credential', 'private_key', 'jwt',
                            ]
                            _is_cred_name = any(kw in decoded_key.lower() for kw in _cred_keywords)

                            if _is_cred_name and len(decoded_value) > 10:
                                # Show as attack surface only — value scanned separately in data leakage
                                results['params'][f'BODY {decoded_key}'] = ['SENSITIVE_PARAM', 'REQUEST_CREDENTIAL']
                            elif is_interesting or len(decoded_value) > 10:
                                results['params'][f'BODY {decoded_key}'] = ['INTERESTING', f'VALUE:{decoded_value[:100]}']
    
    @staticmethod
    def _flatten_json(data: Any, prefix: str = '') -> Dict[str, Any]:
        """Flatten nested JSON"""
        result = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    result.update(SecurityAnalyzer._flatten_json(value, new_key))
                else:
                    result[new_key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    result.update(SecurityAnalyzer._flatten_json(item, new_key))
                else:
                    result[new_key] = item
        
        return result

    @staticmethod
    def _check_reflection(param_value: str, response_text: str) -> bool:
        """
        Check if a parameter value is reflected in the response
        
        Args:
            param_value: The parameter value to check
            response_text: The full response text (headers + body)
        
        Returns:
            True if value is reflected, False otherwise
        """
        if not param_value or not response_text or len(param_value) < 3:
            return False
        
        # Extract response body (skip headers)
        if '\n\n' in response_text:
            response_body = response_text.split('\n\n', 1)[1]
        else:
            response_body = response_text
        
        # URL decode the parameter value for better matching
        try:
            from urllib.parse import unquote
            decoded_value = unquote(param_value)
        except:
            decoded_value = param_value
        
        # Check both original and decoded values
        if param_value in response_body or decoded_value in response_body:
            return True
        
        # Also check case-insensitive for better detection
        if param_value.lower() in response_body.lower() or decoded_value.lower() in response_body.lower():
            return True
        
        return False
    
    @staticmethod
    def _analyze_response_content(response_text: str, url: str, results: Dict):
        """Analyze response content"""
        if not response_text:
            return
        
        body = response_text.split('\n\n', 1)[1] if '\n\n' in response_text else response_text
        
        # HTML parameter detection
        if '<html' in body.lower() or '<!doctype' in body.lower():
            html_params = ParameterDetector.detect_parameters_in_html(body, url)
            for param_name, detections in html_params.items():
                results['params'][param_name] = list(detections)
                results['issues_found'].extend(detections)
            
            # Detect forms and input fields (with HIDDEN detection)
            form_inputs = ParameterDetector.detect_html_forms_and_inputs(body, url)
            for param_name, detections in form_inputs.items():
                results['params'][param_name] = list(detections)
                results['issues_found'].extend(detections)
            
            # Extract HTML endpoints (href, src attributes)
            endpoints = SecurityAnalyzer._extract_html_endpoints(body, url)
            for endpoint_path, metadata in endpoints.items():
                results['params'][endpoint_path] = metadata
    
    @staticmethod
    def _extract_html_endpoints(html: str, base_url: str) -> Dict[str, List[str]]:
        """Extract endpoints from HTML href and src attributes"""
        endpoints = {}
        
        # Patterns to extract endpoints
        endpoint_patterns = [
            r'<link[^>]+href\s*=\s*["\']([^"\']+)["\']',  # <link href="">
            r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', # <script src="">
            r'<img[^>]+src\s*=\s*["\']([^"\']+)["\']',    # <img src="">
            r'<a[^>]+href\s*=\s*["\']([^"\']+)["\']',     # <a href="">
            r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', # <iframe src="">
            r'<form[^>]+action\s*=\s*["\']([^"\']+)["\']', # <form action="">
        ]

        # Also scan inline <script> blocks for dynamically built hrefs/srcs
        # Catches patterns like: element.setAttribute('href', '/admin-secret')
        # and: element.href = '/hidden-path';
        js_endpoint_patterns = [
            # .setAttribute('href', '/path') or .setAttribute("href", '/path')
            (r'''\.setAttribute\s*\(\s*['"]href['"]\s*,\s*['"]([^'"]+)['"]\s*\)''', 'JS_SET_HREF'),
            # .setAttribute('src', '/path')
            (r'''\.setAttribute\s*\(\s*['"]src['"]\s*,\s*['"]([^'"]+)['"]\s*\)''', 'JS_SET_SRC'),
            # .setAttribute('action', '/path')
            (r'''\.setAttribute\s*\(\s*['"]action['"]\s*,\s*['"]([^'"]+)['"]\s*\)''', 'JS_SET_ACTION'),
            # element.href = '/path'  (direct property assignment)
            (r'''\.href\s*=\s*['"]([^'"]+)['"]''', 'JS_HREF_ASSIGN'),
            # window.location = '/path'  or  window.location.href = '/path'
            (r'''window\.location(?:\.href)?\s*=\s*['"]([^'"]+)['"]''', 'JS_REDIRECT'),
            # location.href = '/path'
            (r'''location\.href\s*=\s*['"]([^'"]+)['"]''', 'JS_REDIRECT'),
        ]

        # Extract all inline script content for JS endpoint scanning
        script_blocks = re.findall(
            r'<script(?:[^>]*)>(.*?)</script>',
            html, re.IGNORECASE | re.DOTALL
        )
        inline_js = '\n'.join(script_blocks)

        # Filters: Exclude common uninteresting patterns
        exclude_patterns = [
            r'https?://[^/]*\.css',           # External CSS
            r'https?://[^/]*\.js',            # External JS
            r'https?://[^/]*googleapis\.com', # Google APIs
            r'https?://[^/]*cloudflare\.com', # Cloudflare
            r'https?://[^/]*jquery',          # jQuery CDN
            r'https?://[^/]*bootstrap',       # Bootstrap CDN
            r'^https?://',                    # External URLs (keep relative)
            r'^#',                            # Anchors
            r'^javascript:',                  # JavaScript URLs
            r'^mailto:',                      # Email links
            r'^data:',                        # Data URIs
        ]
        
        seen_paths = set()
        
        for pattern in endpoint_patterns:
            matches = re.finditer(pattern, html, re.IGNORECASE)
            for match in matches:
                endpoint = match.group(1).strip()
                
                # Skip empty
                if not endpoint:
                    continue
                
                # Check exclusions
                if any(re.match(ex, endpoint, re.IGNORECASE) for ex in exclude_patterns):
                    continue
                
                # Smart path extraction
                # For img/script/link with file extensions, extract parent directory
                smart_path = endpoint
                
                # If it's an image/asset with no parameters
                if re.search(r'\.(png|jpg|jpeg|gif|svg|ico|webp)$', endpoint, re.IGNORECASE) and '?' not in endpoint:
                    # Extract directory: files/pixel.png → files/
                    if '/' in endpoint:
                        smart_path = '/'.join(endpoint.split('/')[:-1]) + '/'
                    else:
                        continue  # Skip root-level images
                
                # If it's a CSS/JS file (local) with no parameters
                elif re.search(r'\.(css|js)$', endpoint, re.IGNORECASE) and '?' not in endpoint:
                    # Extract directory: js/app.js → js/
                    if '/' in endpoint:
                        smart_path = '/'.join(endpoint.split('/')[:-1]) + '/'
                    else:
                        continue  # Skip root-level CSS/JS
                
                # Deduplicate
                if smart_path in seen_paths:
                    continue
                seen_paths.add(smart_path)
                
                # Determine type
                endpoint_type = 'ENDPOINT'
                if '<img' in pattern:
                    endpoint_type = 'IMG_DIR' if smart_path != endpoint else 'IMG'
                elif '<script' in pattern:
                    endpoint_type = 'SCRIPT_DIR' if smart_path != endpoint else 'SCRIPT'
                elif '<link' in pattern:
                    endpoint_type = 'LINK_DIR' if smart_path != endpoint else 'LINK'
                elif '<a' in pattern:
                    endpoint_type = 'LINK'
                elif '<form' in pattern:
                    endpoint_type = 'FORM_ACTION'
                
                # Add to results
                key = f'ENDPOINT {smart_path}'
                endpoints[key] = ['INTERESTING', f'TYPE:{endpoint_type}', f'ORIGINAL:{endpoint}']

        # ── Scan inline JS for dynamically built endpoints ────────────────
        # e.g. element.setAttribute('href', '/admin-secret')
        # These are invisible to the static HTML attribute scan above
        if inline_js.strip():
            for js_pattern, js_type in js_endpoint_patterns:
                for match in re.finditer(js_pattern, inline_js, re.IGNORECASE | re.DOTALL):
                    endpoint = match.group(1).strip()
                    if not endpoint:
                        continue
                    # Apply same exclusion filters
                    if any(re.match(ex, endpoint, re.IGNORECASE) for ex in exclude_patterns):
                        continue
                    # Skip empty fragments and data URIs
                    if endpoint in ('#', '') or endpoint.startswith('data:'):
                        continue
                    if endpoint in seen_paths:
                        continue
                    seen_paths.add(endpoint)
                    key = f'ENDPOINT {endpoint}'
                    endpoints[key] = ['INTERESTING', f'TYPE:{js_type}', f'ORIGINAL:{endpoint}']

        return endpoints
    @staticmethod
    def _analyze_javascript(response_text: str, url: str, results: Dict):
        """
        Analyze JavaScript code found in HTML responses:
        - Inline <script> blocks
        - Event handler attributes (onclick, onload, etc.)
        - javascript: URLs in href/src/action
        """
        if not response_text:
            return

        body = response_text.split('\n\n', 1)[1] if '\n\n' in response_text else response_text

        # Only run on HTML responses – skip pure .js file responses
        is_html = ('<html' in body.lower() or '<!doctype' in body.lower()
                or '<script' in body.lower())
        is_js_file = (url.rstrip('/').endswith('.js')
                    or url.rstrip('/').endswith('.mjs')
                    or url.rstrip('/').endswith('.jsx'))
        if is_js_file and not is_html:
            return  # Delegate entirely to JS Miner

        # --- NEW: Extract ALL inline JS (script tags + attributes) ---
        all_inline_js = SecurityAnalyzer._extract_all_inline_js(body)

        if not all_inline_js.strip():
            return

        # 1. DOM sinks — all vuln types (XSS, SSRF, RCE, open redirect, etc.)
        dom_sinks = SecurityAnalyzer._detect_dom_sinks(all_inline_js)
        for sink_info in dom_sinks:
            key = f"INLINE_DOM {sink_info['sink']}"
            results['params'][key] = [
                sink_info['severity'],
                f"TYPE:{sink_info['type']}",
                f"VULN:{sink_info.get('vuln_type', 'DOM_XSS')}",
                f"SINK:{sink_info['sink']}",
                f"CODE:{sink_info['context']}"
            ]
            results['issues_found'].append(sink_info.get('vuln_type', 'DOM_XSS'))

        # 2. Parameter extraction (URLSearchParams, location.search, etc.)
        #    Still run on the merged JS
        js_var_patterns = [
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:new\s+)?URLSearchParams\([^)]*\)\.get\s*\(\s*['\"](\w+)['\"]\s*\)",
            "URLSearchParams.get"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*(?:window\.)?location\.search\.split\s*\(",
            "location.search.split"),
            (r"(?:var|let|const)\s+(\w+)\s*=\s*getParameter\s*\(\s*['\"](\w+)['\"]\s*\)",
            "getParameter"),
        ]
        for pattern, source_method in js_var_patterns:
            for match in re.finditer(pattern, all_inline_js, re.IGNORECASE):
                var_name = match.group(1)
                param_name = match.group(2) if len(match.groups()) >= 2 else "query_string"
                key = f"INLINE_JS_VAR {param_name}"
                results['params'][key] = [
                    'INTERESTING', 'JS_PARAMETER_EXTRACTION',
                    f'VAR:{var_name}', f'SOURCE:{source_method}',
                    f'CODE:{match.group(0)[:150].strip()}'
                ]
                results['issues_found'].append('JS_PARAMETER_EXTRACTION')

        # 3. Secrets in inline JS (hardcoded keys, etc.)
        js_secrets = SecurityAnalyzer._detect_javascript_secrets(all_inline_js)
        for secret_info in js_secrets:
            key = f"INLINE_SECRET {secret_info['var_name']}"
            results['params'][key] = [
                'CRITICAL', 'SECRET_IN_INLINE_JS',
                f"TYPE:{secret_info['type']}",
                f"VAR:{secret_info['var_name']}",
                f"VALUE:{secret_info['value'][:100]}",
                f"CODE:{secret_info['context'][:150]}"
            ]
            results['issues_found'].append('JS_SECRET')

        # 4. Framework detection (from the merged JS and the HTML body)
        frameworks = FrameworkDetector.detect_javascript_frameworks(body, all_inline_js)
        for framework_name, evidence_list in frameworks.items():
            key = f"FRAMEWORK {framework_name}"
            details = ['TECHNOLOGY_DETECTED', 'INFO']
            for evidence in evidence_list[:5]:
                details.append(f"EVIDENCE:{evidence}")
            results['params'][key] = details
            results['issues_found'].append('FRAMEWORK_DETECTED')

        # 5. WebSocket issues (new WebSocket(), postMessage without origin)
        ws_issues = JavaScriptAnalyzer.detect_websocket_issues(all_inline_js)
        for issue in ws_issues:
            _ws_type = issue.get('type', 'WEBSOCKET')
            _ws_key = f"JS {_ws_type} {issue.get('value', '')[:60]}".strip()
            results['params'][_ws_key] = [
                issue.get('severity', 'MEDIUM'),
                f"TYPE:{_ws_type}",
                f"NOTE:{issue.get('note', '')}",
                f"CODE:{issue.get('context', '')[:150]}",
            ]
            results['issues_found'].append(_ws_type)

        # 6. GraphQL usage in inline JS (introspection, mutations, endpoints)
        gql_issues = JavaScriptAnalyzer.detect_graphql(all_inline_js)
        for issue in gql_issues:
            _gql_type = issue.get('type', 'GRAPHQL')
            _gql_val  = issue.get('value', issue.get('context', ''))[:60]
            _gql_key  = f"JS {_gql_type} {_gql_val}".strip()
            results['params'][_gql_key] = [
                issue.get('severity', 'MEDIUM'),
                f"TYPE:{_gql_type}",
                f"NOTE:{issue.get('note', issue.get('context', ''))}",
            ]
            results['issues_found'].append(_gql_type)

        # 7. Open redirect sinks (window.location = user_input, location.href, etc.)
        # Dedup: _detect_dom_sinks (section 1) already captures the standard redirect
        # sinks (location.href=, location.assign(), location.replace()) as
        # INLINE_DOM {sink} entries with vuln_type OPEN_REDIRECT.  Only add a
        # JS OPEN_REDIRECT entry for sinks that _detect_dom_sinks didn't cover
        # (e.g. window.open(), navigate()).
        redirect_issues = JavaScriptAnalyzer.detect_open_redirects(all_inline_js)
        for issue in redirect_issues:
            _sink_name = issue.get('sink', '')
            _dom_key   = f"INLINE_DOM {_sink_name}"
            # If _detect_dom_sinks already has this sink, don't create a duplicate row
            if _dom_key in results['params']:
                results['issues_found'].append('OPEN_REDIRECT')
                continue
            _key = f"JS OPEN_REDIRECT {_sink_name[:40]}".strip()
            if _key not in results['params']:
                results['params'][_key] = [
                    issue.get('severity', 'HIGH'),
                    f"SINK:{_sink_name}",
                    f"VALUE:{issue.get('value', '')[:100]}",
                    f"CODE:{issue.get('context', '')[:150]}",
                    'OPEN_REDIRECT',
                ]
            results['issues_found'].append('OPEN_REDIRECT')

        # 8. Token/JWT storage in localStorage or sessionStorage
        token_issues = JavaScriptAnalyzer.detect_token_storage(all_inline_js)
        for issue in token_issues:
            _ts_type = issue.get('type', 'TOKEN_STORAGE')
            _key = f"JS {_ts_type} {issue.get('key', '')[:50]}".strip()
            results['params'][_key] = [
                issue.get('severity', 'MEDIUM'),
                f"TYPE:{_ts_type}",
                f"NOTE:{issue.get('note', '')}",
                f"VALUE:{issue.get('value', '')[:80]}",
            ]
            results['issues_found'].append(_ts_type)

        # 9. Source map references — expose original unminified source code
        src_map_issues = JavaScriptAnalyzer.detect_source_maps(all_inline_js, url)
        for issue in src_map_issues:
            _sm_type = issue.get('type', 'SOURCE_MAP')
            _key = f"JS {_sm_type} {issue.get('value', '')[:60]}".strip()
            results['params'][_key] = [
                issue.get('severity', 'HIGH'),
                f"TYPE:{_sm_type}",
                f"NOTE:{issue.get('note', '')}",
                f"VALUE:{issue.get('value', '')[:120]}",
            ]
            results['issues_found'].append('SOURCE_MAP')

        # 10. Hardcoded internal hosts / URLs (staging, dev, RFC-1918 hosts in JS)
        # Written to ENDPOINT * so they appear only in the Endpoints tab, not the param table.
        host_issues = JavaScriptAnalyzer.extract_subdomains_and_hosts(all_inline_js)
        for issue in host_issues:
            if issue.get('type') == 'INTERNAL_HOST':
                _host = issue.get('host', issue.get('value', ''))[:60]
                _ep_key = f'ENDPOINT INTERNAL_HOST {_host}'.strip()
                if _ep_key not in results['params']:
                    results['params'][_ep_key] = [
                        'TYPE:INTERNAL_HOST',
                        f"HREF:{issue.get('value', '')[:150]}",
                    ]
                    results['issues_found'].append('INTERNAL_HOST')

        # 11. JS-level CORS issues (fetch/XHR with credentials, dynamic origin reflection)
        # Written to HEADER CORS:* so they appear only in the CORS tab, not the param table.
        cors_js_issues = JavaScriptAnalyzer.detect_cors_issues(all_inline_js)
        for issue in cors_js_issues:
            _cj_type = issue.get('type', 'CORS_JS')
            results['params'][f'HEADER CORS:{_cj_type}'] = [
                'CORS_INDICATOR',
                issue.get('severity', 'HIGH'),
                'HEADER:JavaScript (inline)',
                f"VALUE:{issue.get('context', '')[:80]}",
                f"RISK:{issue.get('note', '')}",
                'LOC:JS',
                'TAG:JS_CORS',
            ]
            results['issues_found'].append(_cj_type)

        # 12. Framework-specific XSS sinks (only when framework detected)
        detected_fw = set(frameworks.keys())
        if any('angular' in fw.lower() for fw in detected_fw):
            for sink in FrameworkDetector.detect_angularjs_xss_sinks(body, all_inline_js):
                _key = f"JS {sink.get('type','ANGULAR_XSS')} {sink.get('expression','')[:50]}".strip()
                results['params'][_key] = [
                    sink.get('severity', 'HIGH'),
                    f"TYPE:{sink.get('type','ANGULAR_XSS')}",
                    f"NOTE:{sink.get('description','')}",
                    f"EXPR:{sink.get('expression','')[:100]}",
                    'XSS',
                ]
                results['issues_found'].append('ANGULAR_XSS')

        if any('react' in fw.lower() for fw in detected_fw):
            for sink in FrameworkDetector.detect_react_xss_sinks(body, all_inline_js):
                _key = f"JS {sink.get('type','REACT_XSS')} {sink.get('expression','')[:50]}".strip()
                results['params'][_key] = [
                    sink.get('severity', 'CRITICAL'),
                    f"TYPE:{sink.get('type','REACT_XSS')}",
                    f"NOTE:{sink.get('description','')}",
                    f"EXPR:{sink.get('expression','')[:100]}",
                    'XSS',
                ]
                results['issues_found'].append('REACT_XSS')

        if any('vue' in fw.lower() for fw in detected_fw):
            for sink in FrameworkDetector.detect_vue_xss_sinks(body, all_inline_js):
                _key = f"JS {sink.get('type','VUE_XSS')} {sink.get('expression','')[:50]}".strip()
                results['params'][_key] = [
                    sink.get('severity', 'HIGH'),
                    f"TYPE:{sink.get('type','VUE_XSS')}",
                    f"NOTE:{sink.get('description','')}",
                    f"EXPR:{sink.get('expression','')[:100]}",
                    'XSS',
                ]
                results['issues_found'].append('VUE_XSS')
    
    @staticmethod
    def _detect_javascript_secrets(text: str) -> List[Dict]:
        """Detect hardcoded secrets in JavaScript code"""
        secrets_found = []
        
        # Patterns for secrets in JavaScript
        secret_patterns = [
            # var config = { "apiKey": "...", "secret": "..." }
            (r'(\w+)\s*[=:]\s*[{\[]\s*["\']?(?:api[_-]?key|apikey|api|key|secret|password|pass|token|auth)["\']?\s*[:\s]\s*["\']([^"\']{10,})["\']',
             'API_KEY_IN_CONFIG'),
            
            # var apiKey = "...";
            (r'(?:var|let|const)\s+(\w*(?:api|key|secret|password|pass|token|auth)\w*)\s*=\s*["\']([^"\']{10,})["\']',
             'HARDCODED_SECRET'),
            
            # Simple object property: password: "value"
            (r'["\']?(password|pass|pwd|secret|token|apiKey|api_key|auth)["\']?\s*:\s*["\']([^"\']{6,})["\']',
             'SECRET_IN_OBJECT'),
            
            # Looking for specific patterns like wechallinfo
            (r'var\s+(\w+)\s*=\s*{\s*[^}]*["\'](?:pass|password|secret|key)["\']?\s*:\s*["\']([^"\']+)["\']',
             'PASSWORD_IN_VAR'),
        ]
        
        for pattern, secret_type in secret_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                var_name = match.group(1)
                value = match.group(2)
                
                # Skip common false positives
                if any(fp in value.lower() for fp in ['placeholder', 'example', 'test', 'demo', 'xxx', '****', '....']):
                    continue
                
                # Skip very long values (likely not real secrets)
                if len(value) > 200:
                    continue
                
                # Extract context
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace('\n', ' ').strip()
                
                secrets_found.append({
                    'type': secret_type,
                    'var_name': var_name,
                    'value': value,
                    'context': context
                })
        
        return secrets_found
    
    @staticmethod
    def _detect_dom_sinks(text: str) -> List[Dict]:
        """
        Detect DOM-level sinks for ALL vulnerability classes:
        XSS, Open Redirect, SSRF, RCE/eval, Prototype Pollution,
        XXE, SSTI, IDOR (API path injection), Auth/Token storage.
        Each returned dict has keys: type, vuln_type, sink, context, severity.
        """
        sinks_found = []

        is_minified = (
            text.count('\n') < 10 and len(text) > 1000
            or text.count(';') > len(text) / 50
        )

        # Dangerous user-reachable sources (DOM)
        dangerous_sources = [
            'location.search', 'location.hash', 'location.href',
            'window.location.search', 'window.location.hash',
            'document.URL', 'document.documentURI', 'document.referrer',
            'window.name', 'URLSearchParams',
        ]

        def _nearby(match, radius=250):
            s = max(0, match.start() - radius)
            e = min(len(text), match.end() + radius)
            return text[s:e]

        def _context(match, radius=110):
            s = max(0, match.start() - radius)
            e = min(len(text), match.end() + radius)
            return text[s:e].replace('\n', ' ').strip()[:120]

        def _has_source(nearby):
            for src in dangerous_sources:
                if re.search(src.replace('.', r'\.'), nearby, re.IGNORECASE):
                    return src
            return None

        def _add(sink_name, match, vuln_type, js_type, base_sev):
            nb   = _nearby(match)
            ctx  = _context(match)
            src  = _has_source(nb)
            sev  = base_sev
            if src:
                ctx += f" | SOURCE:{src}"
                # taint-flow confirmed → escalate one level
                if sev == 'MEDIUM':
                    sev = 'HIGH'
            if is_minified and ctx.count(';') > 5:
                return  # likely library code
            sinks_found.append({
                'type': js_type,
                'vuln_type': vuln_type,
                'sink': sink_name,
                'context': ctx,
                'severity': sev,
            })

        # ── 1. XSS — native JS sinks (PortSwigger cat 1) ───────────────────
        xss_native = [
            ('document.write()',        r'document\.write\s*\(',                     'CRITICAL'),
            ('document.writeln()',      r'document\.writeln\s*\(',                   'CRITICAL'),
            ('document.domain',         r'document\.domain\s*=',                     'HIGH'),
            ('.innerHTML',              r'\.innerHTML\s*=',                           'CRITICAL'),
            ('.outerHTML',              r'\.outerHTML\s*=',                           'CRITICAL'),
            ('.insertAdjacentHTML()',   r'\.insertAdjacentHTML\s*\(',                'CRITICAL'),
            ('.setAttribute(on*)',      r'\.setAttribute\s*\(\s*["\']on\w+["\']',   'HIGH'),
            # element.onevent handlers
            ('.onclick',                r'\.onclick\s*=',                             'HIGH'),
            ('.onerror',                r'\.onerror\s*=',                             'HIGH'),
            ('.onload',                 r'\.onload\s*=',                              'HIGH'),
            ('.onmouseover',            r'\.onmouseover\s*=',                         'HIGH'),
            ('.onmouseout',             r'\.onmouseout\s*=',                          'HIGH'),
            ('.onfocus',                r'\.onfocus\s*=',                             'HIGH'),
            ('.onblur',                 r'\.onblur\s*=',                              'HIGH'),
            ('.onkeydown',              r'\.onkeydown\s*=',                           'HIGH'),
            ('.onkeyup',                r'\.onkeyup\s*=',                             'HIGH'),
            ('.onchange',               r'\.onchange\s*=',                            'HIGH'),
            ('.onsubmit',               r'\.onsubmit\s*=',                            'HIGH'),
            ('window.open()',           r'window\.open\s*\(',                        'HIGH'),
            ('document.write(concat)',  r'document\.write\s*\([\s\S]{0,60}\+',      'CRITICAL'),
        ]
        for sink_name, pat, sev in xss_native:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'XSS', 'JavaScript', sev)

        # ── 2. XSS — jQuery / DOM-library sinks (PortSwigger cat 1) ────────
        xss_jquery = [
            # All jQuery sinks listed by PortSwigger
            ('.add()',             r'\.add\s*\(',                                           'HIGH'),
            ('.after()',          r'\.after\s*\(',                                          'HIGH'),
            ('.append()',         r'\.append\s*\(',                                         'HIGH'),
            ('.animate()',        r'\.animate\s*\(',                                        'HIGH'),
            ('.insertAfter()',    r'\.insertAfter\s*\(',                                    'HIGH'),
            ('.insertBefore()',   r'\.insertBefore\s*\(',                                   'HIGH'),
            ('.before()',         r'\.before\s*\(',                                         'HIGH'),
            ('.html()',           r'\.html\s*\(',                                           'CRITICAL'),
            ('.prepend()',        r'\.prepend\s*\(',                                        'HIGH'),
            ('.replaceAll()',     r'\.replaceAll\s*\(',                                     'HIGH'),
            ('.replaceWith()',    r'\.replaceWith\s*\(',                                    'HIGH'),
            ('.wrap()',           r'\.wrap\s*\(',                                           'HIGH'),
            ('.wrapInner()',      r'\.wrapInner\s*\(',                                      'HIGH'),
            ('.wrapAll()',        r'\.wrapAll\s*\(',                                        'HIGH'),
            ('.has()',            r'\.has\s*\(',                                            'HIGH'),
            ('.constructor()',    r'\.constructor\s*\(',                                    'HIGH'),
            ('.init()',           r'\.init\s*\(',                                           'HIGH'),
            ('.index()',          r'\.index\s*\(',                                          'HIGH'),
            ('jQuery.parseHTML()', r'jQuery\.parseHTML\s*\(',                             'CRITICAL'),
            ('$.parseHTML()',     r'\$\.parseHTML\s*\(',                                   'CRITICAL'),
            # jQuery attribute sinks for link manipulation
            ('.attr(href)',       r'\.attr\s*\(\s*["\']href["\']',                         'HIGH'),
            ('.attr(src)',        r'\.attr\s*\(\s*["\']src["\']',                          'HIGH'),
            ('.attr(action)',     r'\.attr\s*\(\s*["\']action["\']',                       'HIGH'),
            ('$() location src', r'\$\s*\([^)]*(?:location\.(?:hash|search)|window\.location)', 'CRITICAL'),
        ]
        for sink_name, pat, sev in xss_jquery:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'XSS', 'jQuery', sev)

        # ── 3. Open Redirect sinks (PortSwigger cat 2) ──────────────────────
        redirect_sinks = [
            ('location=',                r'(?:window\.)?location\s*=\s*(?!location)',   'HIGH'),
            ('location.host=',           r'(?:window\.)?location\.host\s*=',            'HIGH'),
            ('location.hostname=',       r'(?:window\.)?location\.hostname\s*=',        'HIGH'),
            ('location.href=',           r'(?:window\.)?location\.href\s*=',            'HIGH'),
            ('location.pathname=',       r'(?:window\.)?location\.pathname\s*=',        'HIGH'),
            ('location.search=',         r'(?:window\.)?location\.search\s*=',          'MEDIUM'),
            ('location.protocol=',       r'(?:window\.)?location\.protocol\s*=',        'HIGH'),
            ('location.assign()',        r'(?:window\.)?location\.assign\s*\(',          'HIGH'),
            ('location.replace()',       r'(?:window\.)?location\.replace\s*\(',         'HIGH'),
            ('open()',                   r'\bopen\s*\(\s*(?:["\']https?|["\']//|\w+\s*[+,])', 'HIGH'),
            ('element.srcdoc=',          r'\.srcdoc\s*=',                                'CRITICAL'),
            ('XMLHttpRequest.open()',    r'new\s+XMLHttpRequest[\s\S]{0,200}?\.open\s*\(', 'MEDIUM'),
            ('XMLHttpRequest.send()',    r'\.send\s*\(\s*(?!\s*null|\s*\))',              'MEDIUM'),
            ('jQuery.ajax()',            r'jQuery\.ajax\s*\(',                           'HIGH'),
            ('$.ajax()',                 r'\$\.ajax\s*\(',                               'HIGH'),
            ('history.pushState()',      r'history\.pushState\s*\(',                     'MEDIUM'),
            ('history.replaceState()',   r'history\.replaceState\s*\(',                  'MEDIUM'),
            ('meta refresh redirect',    r'(?:content|value)\s*=\s*["\'][\d;\s]*url\s*=', 'MEDIUM'),
        ]
        for sink_name, pat, sev in redirect_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'OPEN_REDIRECT', 'JavaScript', sev)

        # ── 4. Cookie manipulation sinks (PortSwigger cat 3) ────────────────
        cookie_sinks = [
            ('document.cookie=',         r'document\.cookie\s*=',                       'HIGH'),
        ]
        for sink_name, pat, sev in cookie_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'COOKIE_MANIPULATION', 'JavaScript', sev)

        # ── 5. JS Injection / RCE sinks (PortSwigger cat 4) ─────────────────
        rce_sinks = [
            ('eval()',                   r'\beval\s*\(',                                'CRITICAL'),
            ('Function()',              r'(?<!\w)Function\s*\(',                         'CRITICAL'),
            ('new Function()',           r'new\s+Function\s*\(',                        'CRITICAL'),
            ('setTimeout(string)',       r'setTimeout\s*\(\s*(?:["\`]|\w+\s*\+)',       'CRITICAL'),
            ('setInterval(string)',      r'setInterval\s*\(\s*(?:["\`]|\w+\s*\+)',      'CRITICAL'),
            ('setImmediate(string)',     r'setImmediate\s*\(\s*(?:["\`]|\w+\s*\+)',     'CRITICAL'),
            ('execCommand()',            r'document\.execCommand\s*\(',                  'HIGH'),
            ('execScript()',             r'\bexecScript\s*\(',                           'CRITICAL'),
            ('msSetImmediate()',         r'\bmsSetImmediate\s*\(',                       'CRITICAL'),
            ('range.createContextualFragment()', r'\.createContextualFragment\s*\(',    'CRITICAL'),
            ('crypto.generateCRMFRequest()', r'crypto\.generateCRMFRequest\s*\(',       'HIGH'),
            ('importScripts()',          r'\bimportScripts\s*\(',                        'HIGH'),
            ('ScriptElement.src=',      r'(?:script|s)\.src\s*=',                       'HIGH'),
            ('script.text=',            r'\.text\s*=\s*(?:location|\w+\s*\+)',          'HIGH'),
        ]
        for sink_name, pat, sev in rce_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                if is_minified:
                    continue
                _add(sink_name, m, 'JS_INJECTION', 'JavaScript', sev)

        # ── 6. Document-domain manipulation (PortSwigger cat 5) ─────────────
        domain_sinks = [
            ('document.domain=',        r'document\.domain\s*=',                       'HIGH'),
        ]
        for sink_name, pat, sev in domain_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'DOMAIN_MANIPULATION', 'JavaScript', sev)

        # ── 7. WebSocket-URL poisoning (PortSwigger cat 6) ──────────────────
        ws_sinks = [
            ('new WebSocket()',          r'new\s+WebSocket\s*\(',                       'HIGH'),
        ]
        for sink_name, pat, sev in ws_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'WEBSOCKET_URL_POISONING', 'JavaScript', sev)

        # ── 8. Link manipulation sinks (PortSwigger cat 7) ──────────────────
        link_sinks = [
            ('element.href=',            r'(?<!\w)\.href\s*=',                         'HIGH'),
            ('element.src=',             r'(?<!\w)\.src\s*=',                           'HIGH'),
            ('element.action=',          r'(?<!\w)\.action\s*=',                        'HIGH'),
        ]
        for sink_name, pat, sev in link_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'LINK_MANIPULATION', 'JavaScript', sev)

        # ── 9. Web-message manipulation (PortSwigger cat 8) ─────────────────
        postmsg_sinks = [
            ('postMessage()',            r'\.postMessage\s*\(',                         'MEDIUM'),
            ('addEventListener(message)', r'addEventListener\s*\(\s*["\']message["\']', 'MEDIUM'),
            ('window.onmessage=',        r'(?:window\.)?onmessage\s*=',                'MEDIUM'),
        ]
        for sink_name, pat, sev in postmsg_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'WEB_MESSAGE_MANIPULATION', 'JavaScript', sev)

        # ── 10. Ajax request-header manipulation (PortSwigger cat 9) ────────
        ajax_header_sinks = [
            ('XMLHttpRequest.setRequestHeader()', r'\.setRequestHeader\s*\(',           'HIGH'),
            ('XMLHttpRequest.open()',             r'(?:xhr|xmlhttp|request|req)\s*\.open\s*\(', 'HIGH'),
            ('XMLHttpRequest.send(data)',         r'(?:xhr|xmlhttp|request|req)\s*\.send\s*\(', 'MEDIUM'),
            ('jQuery.globalEval()',               r'jQuery\.globalEval\s*\(',            'CRITICAL'),
            ('$.globalEval()',                    r'\$\.globalEval\s*\(',                'CRITICAL'),
        ]
        for sink_name, pat, sev in ajax_header_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'AJAX_HEADER_MANIPULATION', 'JavaScript', sev)

        # ── 11. Local file-path manipulation (PortSwigger cat 10) ───────────
        filereader_sinks = [
            ('FileReader.readAsArrayBuffer()',  r'\.readAsArrayBuffer\s*\(',             'HIGH'),
            ('FileReader.readAsBinaryString()', r'\.readAsBinaryString\s*\(',            'HIGH'),
            ('FileReader.readAsDataURL()',      r'\.readAsDataURL\s*\(',                 'HIGH'),
            ('FileReader.readAsText()',         r'\.readAsText\s*\(',                    'HIGH'),
            ('FileReader.readAsFile()',         r'\.readAsFile\s*\(',                    'HIGH'),
            ('FileReader.root.getFile()',       r'\.root\.getFile\s*\(',                 'HIGH'),
        ]
        for sink_name, pat, sev in filereader_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'FILE_PATH_MANIPULATION', 'JavaScript', sev)

        # ── 12. Client-side SQL injection (PortSwigger cat 11) ──────────────
        sql_sinks = [
            ('executeSql()',             r'\.executeSql\s*\(',                          'CRITICAL'),
        ]
        for sink_name, pat, sev in sql_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'CLIENT_SIDE_SQLI', 'JavaScript', sev)

        # ── 13. HTML5 storage manipulation (PortSwigger cat 12) ─────────────
        storage_sinks = [
            ('sessionStorage.setItem()',  r'sessionStorage\.setItem\s*\(',              'MEDIUM'),
            ('localStorage.setItem()',    r'localStorage\.setItem\s*\(',                 'MEDIUM'),
        ]
        for sink_name, pat, sev in storage_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'STORAGE_MANIPULATION', 'JavaScript', sev)

        # ── 14. XPath injection (PortSwigger cat 13) ────────────────────────
        xpath_sinks = [
            ('document.evaluate()',      r'document\.evaluate\s*\(',                   'HIGH'),
            ('element.evaluate()',       r'(?<!\bdocument)\.evaluate\s*\(',             'HIGH'),
        ]
        for sink_name, pat, sev in xpath_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'XPATH_INJECTION', 'JavaScript', sev)

        # ── 15. JSON injection (PortSwigger cat 14) ─────────────────────────
        json_sinks = [
            ('JSON.parse()',             r'JSON\.parse\s*\(',                           'MEDIUM'),
            ('jQuery.parseJSON()',       r'jQuery\.parseJSON\s*\(',                     'MEDIUM'),
            ('$.parseJSON()',            r'\$\.parseJSON\s*\(',                          'MEDIUM'),
        ]
        for sink_name, pat, sev in json_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'JSON_INJECTION', 'JavaScript', sev)

        # ── 16. DOM data manipulation (PortSwigger cat 15) ──────────────────
        dom_data_sinks = [
            ('script.src=',                           r'(?:script)\s*(?:\[[^\]]+\])?\s*\.\s*src\s*=',        'CRITICAL'),
            ('script.text=',                          r'(?:script)\s*(?:\[[^\]]+\])?\s*\.\s*text\s*=',       'HIGH'),
            ('script.textContent=',                   r'(?:script)\s*(?:\[[^\]]+\])?\s*\.\s*textContent\s*=', 'HIGH'),
            ('script.innerText=',                     r'(?:script)\s*(?:\[[^\]]+\])?\s*\.\s*innerText\s*=',  'HIGH'),
            ('element.setAttribute()',                r'\.setAttribute\s*\(',                                 'MEDIUM'),
            ('element.search=',                       r'(?<!\blocation)\.search\s*=',                        'MEDIUM'),
            ('element.text=',                         r'(?<!\.)\.text\s*=',                                   'MEDIUM'),
            ('element.textContent=',                  r'\.textContent\s*=',                                   'MEDIUM'),
            ('element.innerText=',                    r'\.innerText\s*=',                                     'MEDIUM'),
            ('element.outerText=',                    r'\.outerText\s*=',                                     'MEDIUM'),
            ('element.value=',                        r'\.value\s*=',                                         'LOW'),
            ('element.name=',                         r'\.name\s*=',                                          'LOW'),
            ('element.target=',                       r'\.target\s*=',                                        'MEDIUM'),
            ('element.method=',                       r'\.method\s*=',                                        'MEDIUM'),
            ('element.type=',                         r'\.type\s*=',                                          'LOW'),
            ('element.backgroundImage=',              r'\.backgroundImage\s*=',                               'MEDIUM'),
            ('element.cssText=',                      r'\.cssText\s*=',                                       'MEDIUM'),
            ('element.codebase=',                     r'\.codebase\s*=',                                      'HIGH'),
            ('document.title=',                       r'document\.title\s*=',                                 'LOW'),
            ('document.implementation.createHTMLDocument()', r'document\.implementation\.createHTMLDocument\s*\(', 'MEDIUM'),
            ('history.pushState()',                   r'history\.pushState\s*\(',                             'MEDIUM'),
            ('history.replaceState()',                r'history\.replaceState\s*\(',                          'MEDIUM'),
        ]
        for sink_name, pat, sev in dom_data_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'DOM_DATA_MANIPULATION', 'JavaScript', sev)

        # ── 17. DOM-based DoS (PortSwigger cat 16) ──────────────────────────
        dos_sinks = [
            ('requestFileSystem()',      r'\brequestFileSystem\s*\(',                   'MEDIUM'),
            ('RegExp()',                 r'new\s+RegExp\s*\(',                          'MEDIUM'),
        ]
        for sink_name, pat, sev in dos_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'DOM_DOS', 'JavaScript', sev)

        # ── 18. SSRF sinks ───────────────────────────────────────────────────
        ssrf_sinks = [
            ('fetch()',                  r'\bfetch\s*\(',                               'HIGH'),
            ('$.get()',                  r'\$\.get\s*\(',                               'HIGH'),
            ('$.post()',                 r'\$\.post\s*\(',                              'HIGH'),
            ('axios.get()',              r'axios\.get\s*\(',                            'HIGH'),
            ('axios.post()',             r'axios\.post\s*\(',                           'HIGH'),
            ('axios.request()',          r'axios\.request\s*\(',                        'HIGH'),
            ('new XMLHttpRequest()',     r'new\s+XMLHttpRequest\s*\(',                  'MEDIUM'),
            ('navigator.sendBeacon()',   r'navigator\.sendBeacon\s*\(',                'MEDIUM'),
        ]
        for sink_name, pat, sev in ssrf_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'SSRF', 'JavaScript', sev)

        # ── 19. Prototype Pollution sinks ────────────────────────────────────
        pp_sinks = [
            ('Object.assign()',         r'Object\.assign\s*\(',                        'HIGH'),
            ('jQuery.extend(deep)',     r'\$\.extend\s*\(\s*true',                     'HIGH'),
            ('_.merge()',               r'_\.merge\s*\(',                               'HIGH'),
            ('_.defaultsDeep()',        r'_\.defaultsDeep\s*\(',                        'HIGH'),
            ('Object.defineProperty()', r'Object\.defineProperty\s*\(',                'MEDIUM'),
            ('__proto__ assignment',    r'__proto__\s*[=[]',                            'CRITICAL'),
            ('constructor.prototype',   r'constructor\s*\.\s*prototype\s*[=[]',        'CRITICAL'),
            ('Object spread {…user}',  r'=\s*\{[^}]*\.\.\.[^}]{0,30}(?:input|data|body|params|query|req|user)', 'MEDIUM'),
        ]
        for sink_name, pat, sev in pp_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'PROTOTYPE_POLLUTION', 'JavaScript', sev)

        # ── 20. XXE / XML parsing sinks ──────────────────────────────────────
        xxe_sinks = [
            ('DOMParser.parseFromString()', r'(?:new\s+)?DOMParser\s*\(\s*\)\.parseFromString\s*\(', 'HIGH'),
            ('XMLSerializer',              r'new\s+XMLSerializer\s*\(',                               'MEDIUM'),
            ('ActiveXObject(MSXML)',       r'new\s+ActiveXObject\s*\(\s*["\']MSXML',               'HIGH'),
            ('responseXML',               r'\.responseXML\b',                                         'MEDIUM'),
            ('xmlDoc.loadXML()',           r'\.loadXML\s*\(',                                         'HIGH'),
        ]
        for sink_name, pat, sev in xxe_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'XXE', 'JavaScript', sev)

        # ── 21. SSTI / Template injection sinks ─────────────────────────────
        ssti_sinks = [
            ('ejs.render()',             r'ejs\.render(?:File)?\s*\(',                 'CRITICAL'),
            ('Handlebars.compile()',     r'Handlebars\.compile\s*\(',                  'HIGH'),
            ('_.template()',             r'_\.template\s*\(',                           'HIGH'),
            ('Mustache.render()',        r'Mustache\.render\s*\(',                      'HIGH'),
            ('nunjucks.renderString()',  r'nunjucks\.renderString\s*\(',               'CRITICAL'),
            ('Pug/Jade compile()',       r'(?:pug|jade)\.compile\s*\(',                'HIGH'),
            ('template literal eval',   r'`[^`]*\$\{[^}]*(?:location|input|data|req|query)[^}]*\}[^`]*`', 'MEDIUM'),
        ]
        for sink_name, pat, sev in ssti_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'SSTI', 'JavaScript', sev)

        # ── 22. IDOR — API path built from user-controlled IDs ───────────────
        idor_sinks = [
            ('fetch(path+id)',          r'fetch\s*\([^)]*["\`][^"\`]*/[^"\`]*\+',     'HIGH'),
            ('$.ajax url concat',       r'url\s*:\s*[^,}]*["\`][^"\`]*/[^"\`]*\+',    'HIGH'),
            ('location.pathname split', r'location\.pathname\.split\s*\(',              'MEDIUM'),
            ('path segment var',        r'(?:userId|accountId|customerId|orderId|docId|fileId)\s*=', 'MEDIUM'),
        ]
        for sink_name, pat, sev in idor_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'IDOR', 'JavaScript', sev)

        # ── 23. Auth / Token storage sinks ──────────────────────────────────
        auth_sinks = [
            ('localStorage.setItem(token)', r'localStorage\.setItem\s*\([^)]*(?:token|auth|key|secret|jwt|sess)', 'MEDIUM'),
            ('localStorage.getItem()',      r'localStorage\.getItem\s*\(',               'LOW'),
            ('sessionStorage.getItem()',    r'sessionStorage\.getItem\s*\(',             'LOW'),
        ]
        for sink_name, pat, sev in auth_sinks:
            for m in re.finditer(pat, text, re.IGNORECASE):
                _add(sink_name, m, 'AUTH_STORAGE', 'JavaScript', sev)

        # De-duplicate: keep highest-severity entry per sink name
        deduped = {}
        _sev_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        for entry in sinks_found:
            k = entry['sink']
            if k not in deduped or _sev_rank.get(entry['severity'], 5) < _sev_rank.get(deduped[k]['severity'], 5):
                deduped[k] = entry

        return list(deduped.values())

    # Keep legacy alias so any existing callers outside this file don't break
    _detect_dom_xss_sinks = _detect_dom_sinks
    
    @staticmethod
    def _analyze_security_headers(request_text: str, response_text: str, results: Dict):
        """Analyze security headers"""
        if not response_text:
            return
        
        resp_headers = SecurityAnalyzer._parse_headers(response_text)
        req_headers = SecurityAnalyzer._parse_headers(request_text) if request_text else {}
        
        # ── Legacy high-level CORS misconfig flags ────────────────────────
        cors_issues = SecurityDetector.check_cors(resp_headers, req_headers)
        for issue in cors_issues:
            results['params'][f'HEADER {issue}'] = ['SECURITY_MISCONFIGURATION', 'HIGH']
            results['issues_found'].append(issue)

        # ── Comprehensive CORS header indicator analysis ───────────────────
        cors_indicators = SecurityDetector.analyze_cors_headers(resp_headers, req_headers)
        for finding in cors_indicators:
            indicator = finding['indicator']
            severity  = finding['severity']
            header    = finding['header']
            value     = finding['value']
            risk      = finding['risk']
            location  = finding['location']
            tags      = finding['tags']

            # Build a rich param-table entry
            param_key  = f'HEADER CORS:{indicator}'
            param_data = [
                f'CORS_INDICATOR',
                severity,
                f'HEADER:{header}',
                f'VALUE:{value}',
                f'RISK:{risk}',
                f'LOC:{location}',
            ] + [f'TAG:{t}' for t in tags]

            results['params'][param_key] = param_data

            # Propagate actionable severities into issues_found
            if severity in ('CRITICAL', 'HIGH'):
                results['issues_found'].append(indicator)
            elif severity == 'MEDIUM':
                results['issues_found'].append(f'CORS_MEDIUM:{indicator}')

        # ── Missing security headers ──────────────────────────────────────
        misconfig = SecurityDetector.detect_security_misconfig(resp_headers, "")
        for issue in misconfig:
            if issue.startswith('MISSING_'):
                results['params'][f'HEADER {issue}'] = ['SECURITY_MISCONFIGURATION', 'MEDIUM']
            else:
                results['params'][f'HEADER {issue}'] = ['SECURITY_MISCONFIGURATION', 'HIGH']
            results['issues_found'].append(issue)

        # ── Uncommon / non-standard response headers (reveal internal tooling) ─
        uncommon = SecurityDetector.detect_uncommon_headers(req_headers, resp_headers)
        for hdr in uncommon.get('response', []):
            _key = f'HEADER UNCOMMON:{hdr}'
            if _key not in results['params']:
                results['params'][_key] = ['INFO', 'UNCOMMON_HEADER', f'HEADER:{hdr}']

        # ── Debug/tech-disclosure headers ─────────────────────────────────
        _debug_hdrs = {
            'x-debug':              'X-Debug header — application in debug mode',
            'x-debug-token':        'Symfony debug token — profiler available',
            'x-debug-token-link':   'Symfony profiler URL exposed',
            'x-drupal-cache':       'Drupal cache debug header',
            'x-aspnet-version':     'ASP.NET version disclosed',
            'x-aspnetmvc-version':  'ASP.NET MVC version disclosed',
            'x-generator':          'Generator/framework fingerprint disclosed',
            'x-powered-by':         'Technology fingerprint via X-Powered-By',
            'x-cf-powered-by':      'ColdFusion version fingerprint',
            'x-fw-version':         'Firewall/framework version fingerprint',
        }
        resp_lower_keys = {k.lower(): (k, v) for k, v in resp_headers.items()}
        for _dh, _note in _debug_hdrs.items():
            if _dh in resp_lower_keys:
                _orig, _val = resp_lower_keys[_dh]
                _key = f'HEADER DEBUG:{_dh}'
                results['params'][_key] = [
                    'MEDIUM', 'DEBUG_HEADER',
                    f'HEADER:{_orig}', f'VALUE:{_val[:120]}', f'NOTE:{_note}',
                ]
                results['issues_found'].append('DEBUG_HEADER')

        # ── Clickjacking protection ───────────────────────────────────────
        _has_xfo           = 'x-frame-options' in resp_lower_keys
        _csp_val           = resp_lower_keys.get('content-security-policy', ('', ''))[1].lower()
        _has_frame_ancestors = 'frame-ancestors' in _csp_val
        if not _has_xfo and not _has_frame_ancestors:
            # Key does NOT start with MISSING_ so it shows in the param table
            results['params']['HEADER CLICKJACKING_PROTECTION_ABSENT'] = [
                'MEDIUM', 'SECURITY_MISCONFIGURATION',
                'NOTE:No X-Frame-Options and no CSP frame-ancestors — page may be iframed',
            ]
            results['issues_found'].append('CLICKJACKING_POSSIBLE')

        # ── Host Header Injection ─────────────────────────────────────────
        req_lower_keys = {k.lower(): v for k, v in req_headers.items()}
        host_val = req_lower_keys.get('host', '')
        if host_val:
            location_val = resp_lower_keys.get('location', ('', ''))[1] if isinstance(
                resp_lower_keys.get('location'), tuple) else resp_headers.get('location', '')
            set_cookie_val = resp_headers.get('set-cookie', '') or resp_headers.get('Set-Cookie', '')
            body_sample = (response_text.split('\n\n', 1)[1][:1000]
                           if '\n\n' in response_text else response_text[:1000])
            if location_val and host_val in location_val:
                results['params']['HEADER HOST_HEADER_INJECTION'] = [
                    'HIGH', 'HOST_HEADER_INJECTION',
                    f'HOST:{host_val}',
                    f'REFLECTED_IN:Location: {location_val[:80]}',
                    'NOTE:Host header value appears in redirect Location — test with arbitrary Host value',
                ]
                results['issues_found'].append('HOST_HEADER_INJECTION')
            elif host_val in body_sample:
                results['params']['HEADER HOST_HEADER_IN_BODY'] = [
                    'MEDIUM', 'HOST_HEADER_INJECTION',
                    f'HOST:{host_val}',
                    'NOTE:Host header value reflected in response body — potential Host header injection',
                ]
                results['issues_found'].append('HOST_HEADER_INJECTION')

        # ── HTTP Request Smuggling indicators (CL + TE on same request) ───
        has_cl = 'content-length' in req_lower_keys
        has_te = 'transfer-encoding' in req_lower_keys
        if has_cl and has_te:
            cl_val = req_lower_keys.get('content-length', '')
            te_val = req_lower_keys.get('transfer-encoding', '')
            results['params']['HEADER REQUEST_SMUGGLING_POTENTIAL'] = [
                'CRITICAL', 'REQUEST_SMUGGLING',
                f'CL:{cl_val}', f'TE:{te_val}',
                'NOTE:Both Content-Length and Transfer-Encoding present — test for CL.TE / TE.CL desync',
            ]
            results['issues_found'].append('REQUEST_SMUGGLING')

        # ── HTTP Method Override headers ──────────────────────────────────
        _override_headers = [
            'x-http-method-override', 'x-method-override',
            'x-http-method', '_method',
        ]
        for _oh in _override_headers:
            if _oh in req_lower_keys:
                _ov = req_lower_keys[_oh].upper()
                results['params'][f'HEADER METHOD_OVERRIDE {_ov}'] = [
                    'MEDIUM', 'METHOD_OVERRIDE',
                    f'HEADER:{_oh}', f'VALUE:{_ov}',
                    'NOTE:Method override header tunnels restricted HTTP verb — verify server-side enforcement',
                ]
                results['issues_found'].append('METHOD_OVERRIDE')
                break
    
    @staticmethod
    def _parse_headers(text: str) -> Dict[str, str]:
        """Parse HTTP headers from a raw HTTP request/response string.

        Robust against:
        - CRLF or LF line endings
        - Binary bodies (stops before body region)
        - Responses that start without a status line
        - Extra blank lines before the first header
        """
        headers: Dict[str, str] = {}
        if not text:
            return headers

        # ── 1. Isolate the header section (everything before the double newline) ──
        text_norm = text.replace('\r\n', '\n').replace('\r', '\n')
        if '\n\n' in text_norm:
            header_block = text_norm.split('\n\n', 1)[0]
        else:
            header_block = text_norm

        lines = header_block.split('\n')

        # ── 2. Skip the request/status line ────────────────────────────────
        skip_first = False
        if lines:
            first = lines[0].strip()
            # HTTP response: "HTTP/1.1 200 OK"  |  request: "GET /path HTTP/1.1"
            if (first.startswith('HTTP/') or
                    any(first.upper().startswith(m + ' ')
                        for m in ('GET', 'POST', 'PUT', 'DELETE', 'PATCH',
                                  'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'))):
                skip_first = True

        for line in (lines[1:] if skip_first else lines):
            stripped = line.strip()
            if not stripped or stripped == '---':
                continue           # allow blank lines inside header block
            if ':' in stripped:
                key, _, value = stripped.partition(':')
                k = key.strip()
                if k:
                    headers[k] = value.strip()

        return headers
    
    @staticmethod
    def _analyze_vulnerabilities(response_text: str, url: str, status: int, results: Dict):
        """Scan for vulnerabilities"""
        if not response_text:
            return
        
        body = response_text.split('\n\n', 1)[1] if '\n\n' in response_text else response_text
        
        # SQL injection
        sql_errors = VulnerabilityScanner.detect_sql_injection_errors_text(body)
        for error_info in sql_errors:
            # Handle both tuple (type, message) and string formats
            if isinstance(error_info, tuple):
                error_type, error_msg = error_info
                # Add error message as metadata with ERROR_MSG: prefix
                results['params'][f'RESPONSE SQL_ERROR {error_type}'] = [
                    'CRITICAL', 'SQLI', f'ERROR_MSG:{error_msg}'
                ]
            else:
                # Fallback for old format
                results['params'][f'RESPONSE SQL_ERROR {error_info}'] = ['CRITICAL', 'SQLI']
            results['issues_found'].append('SQLI')
        
        # Generic error messages (PHP, Python, Java, etc.)
        error_patterns = [
            (r"Warning.*?\sin\s.*?\.php.*?on line \d+", "PHP_WARNING"),
            (r"Fatal error.*?in.*?\.php.*?on line \d+", "PHP_FATAL"),
            (r"Parse error.*?in.*?\.php.*?on line \d+", "PHP_PARSE"),
            (r"Traceback \(most recent call last\):.*?(?=\n\n|$)", "PYTHON_TRACEBACK"),
            (r"Exception in thread.*?at .*?\.java:\d+", "JAVA_EXCEPTION"),
            (r"System\.\w+Exception:.*?at .*?line \d+", "DOTNET_EXCEPTION"),
            (r"RuntimeError:.*?(?=\n\n|$)", "RUNTIME_ERROR"),
            (r"TypeError:.*?(?=\n\n|$)", "TYPE_ERROR"),
            (r"ValueError:.*?(?=\n\n|$)", "VALUE_ERROR"),
        ]
        
        for pattern, error_type in error_patterns:
            match = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
            if match:
                error_msg = match.group()[:300].strip()  # Capture more for stack traces
                results['params'][f'RESPONSE ERROR {error_type}'] = [
                    'HIGH', 'ERROR_DISCLOSURE', f'ERROR_MSG:{error_msg}'
                ]
                results['issues_found'].append('ERROR_DISCLOSURE')
                break  # Only report first error type found
        
        # GraphQL
        if '/graphql' in url.lower():
            graphql = VulnerabilityScanner.detect_graphql_introspection_text(body)
            for finding in graphql:
                results['params'][f'RESPONSE GRAPHQL {finding}'] = ['HIGH']
                results['issues_found'].append('GRAPHQL')

        # Admin panel paths in URL
        for _adm in VulnerabilityScanner.detect_admin_panels(url):
            # e.g. "ADMIN_PANEL:/admin - Generic admin panel detected"
            _ap_path = _adm.split(' - ')[0].replace('ADMIN_PANEL:', '').strip()
            _ap_key  = f'URL ADMIN_PANEL {_ap_path}'
            if _ap_key not in results['params']:
                results['params'][_ap_key] = [
                    'HIGH', 'ADMIN_PANEL',
                    f'PATH:{_ap_path}', f'URL:{url}',
                    'NOTE:Admin interface Found — test for authentication bypass and default credentials',
                ]
                results['issues_found'].append('ADMIN_PANEL')

        # Default credential endpoints in URL
        for _dc in VulnerabilityScanner.detect_default_credentials_endpoints(url):
            _dc_svc = _dc.split(' - ')[0].replace('DEFAULT_CREDS_', '').strip()
            _dc_key = f'URL DEFAULT_CREDS {_dc_svc}'
            if _dc_key not in results['params']:
                results['params'][_dc_key] = [
                    'HIGH', 'DEFAULT_CREDENTIALS',
                    f'SERVICE:{_dc_svc}', f'URL:{url}',
                    f'NOTE:{_dc}',
                ]
                results['issues_found'].append('DEFAULT_CREDENTIALS')

        # Sensitive data in response body — shown in Info Leakage tab only.
        # Only feed issues_found (for severity); do NOT write to results['params']
        # to avoid duplicating what the Info Leakage scanner already shows.
        _sensitive = DataLeakageDetector.detect_sensitive_data_exposure({}, body, url)
        for _finding in _sensitive:
            _ftype = _finding.partition('[')[0] if '[' in _finding else _finding
            results['issues_found'].append(_ftype)

        # ── Reflected File Download ───────────────────────────────────────
        _resp_headers = SecurityAnalyzer._parse_headers(response_text)
        _cd = (_resp_headers.get('content-disposition') or
               _resp_headers.get('Content-Disposition') or '').lower()
        if 'attachment' in _cd and '?' in url:
            from urllib.parse import unquote as _uq
            for _pp in url.split('?', 1)[1].split('&'):
                if '=' in _pp:
                    _pk, _pv = _pp.split('=', 1)
                    _pv_dec = _uq(_pv)
                    if _pv_dec and len(_pv_dec) > 1 and _pv_dec.lower() in _cd:
                        _rfd_key = f'URL RFD_{_pk}'
                        if _rfd_key not in results['params']:
                            results['params'][_rfd_key] = [
                                'HIGH', 'REFLECTED_FILE_DOWNLOAD',
                                f'PARAM:{_pk}', f'VALUE:{_pv_dec[:60]}',
                                'NOTE:URL param reflected in Content-Disposition filename — Reflected File Download (RFD)',
                            ]
                            results['issues_found'].append('REFLECTED_FILE_DOWNLOAD')

        # ── Subdomain Takeover fingerprints in response body ──────────────
        _TAKEOVER_FP = [
            (r"There isn't a GitHub Pages site here",       'GITHUB_PAGES'),
            (r"The specified bucket does not exist",         'S3_BUCKET'),
            (r'<Code>NoSuchBucket</Code>',                   'S3_BUCKET'),
            (r"Repository not found",                        'BITBUCKET'),
            (r"Sorry, We Couldn't Find That Page",           'SHOPIFY'),
            (r"The thing you were looking for is no longer", 'TUMBLR'),
            (r"herokucdn\.com/error-pages/no-such-app",      'HEROKU'),
            (r"is not a valid Zendesk subdomain",            'ZENDESK'),
            (r'does not exist.*?Firebase|Firebase.*?not found', 'FIREBASE'),
            (r"This UserVoice subdomain is currently available", 'USERVOICE'),
            (r"project not found",                           'GITLAB_PAGES'),
            (r"Unrecognized domain",                         'FASTLY'),
            (r"is not a registered InCloud YouTrack",        'YOUTRACK'),
            (r"No settings were found for this company",     'HELPSCOUT'),
        ]
        for _fp_pat, _fp_svc in _TAKEOVER_FP:
            if re.search(_fp_pat, body, re.IGNORECASE):
                _tk_key = f'RESPONSE SUBDOMAIN_TAKEOVER_{_fp_svc}'
                if _tk_key not in results['params']:
                    results['params'][_tk_key] = [
                        'CRITICAL', 'SUBDOMAIN_TAKEOVER',
                        f'SERVICE:{_fp_svc}',
                        f'NOTE:Response matches unclaimed {_fp_svc} CNAME fingerprint — subdomain may be claimable',
                    ]
                    results['issues_found'].append('SUBDOMAIN_TAKEOVER')
                break
    
    @staticmethod
    def _analyze_data_leakage(response_text: str, results: Dict):
        """Detect data leakage"""
        if not response_text:
            return
        
        body = response_text.split('\n\n', 1)[1] if '\n\n' in response_text else response_text
        
        # Internal IPs - MOVED to Information Leakage Scanner (Pattern Highlighting)
        # Removed from Parameters Table to avoid duplicates
        # IPs are detected in Pattern Highlighting section only
        
        # Emails - MOVED to Information Leakage Scanner (Pattern Highlighting)
        # Removed from Parameters Table to avoid duplicates
        # Emails are detected in Pattern Highlighting section only
    
    @staticmethod
    def _calculate_severity(results: Dict):
        """Calculate overall severity"""
        critical_keywords = ['CRITICAL', 'RCE', 'SQLI', 'XSS_SINK', 'AWS_KEY']
        high_keywords = ['HIGH', 'XSS', 'DOM_XSS', 'API_KEY', 'GITHUB_TOKEN']
        
        all_findings = ' '.join(str(results['issues_found']))
        
        if any(kw in all_findings for kw in critical_keywords):
            results['severity'] = 'CRITICAL'
        elif any(kw in all_findings for kw in high_keywords):
            results['severity'] = 'HIGH'
        elif results['issues_found']:
            results['severity'] = 'MEDIUM'
        else:
            results['severity'] = 'LOW'
            
    @staticmethod
    def _analyze_cookies(response_text: str, results: Dict, request_text: str = ''):
        """Parse Cookie from request header and Set-Cookie from response; check security flags."""
        cookie_entries = []

        # ── Request cookies (Cookie: header) ────────────────────────────
        if request_text:
            req_hdr_section = request_text.split('\n\n')[0] if '\n\n' in request_text else request_text
            for line in req_hdr_section.split('\n'):
                stripped = line.strip()
                if stripped.lower().startswith('cookie:'):
                    raw = stripped[len('cookie:'):].strip()
                    for pair in raw.split(';'):
                        pair = pair.strip()
                        if not pair:
                            continue
                        name = pair.split('=')[0].strip() if '=' in pair else pair
                        value_raw = pair.split('=', 1)[1].strip() if '=' in pair else ''
                        value_preview = (value_raw[:24] + '…') if len(value_raw) > 24 else value_raw
                        cookie_entries.append({
                            'source':     'REQ',
                            'name':       name,
                            'value':      value_preview,
                            'secure':     None,
                            'httponly':   None,
                            'samesite':   '—',
                            'is_session': None,
                            'issues':     [],
                        })

        # ── Response Set-Cookie headers ──────────────────────────────────
        if response_text:
            resp_hdr_section = response_text.split('\n\n')[0] if '\n\n' in response_text else response_text
            for line in resp_hdr_section.split('\n'):
                stripped = line.strip()
                if stripped.lower().startswith('set-cookie:'):
                    raw = stripped[len('set-cookie:'):].strip()
                    parts = [p.strip() for p in raw.split(';')]
                    if not parts:
                        continue
                    name_val = parts[0]
                    name = name_val.split('=')[0].strip() if '=' in name_val else name_val
                    value_raw = name_val.split('=', 1)[1] if '=' in name_val else ''
                    value_preview = (value_raw[:24] + '…') if len(value_raw) > 24 else value_raw

                    attrs = {}
                    for p in parts[1:]:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            attrs[k.strip().lower()] = v.strip()
                        else:
                            attrs[p.strip().lower()] = True

                    has_secure   = 'secure'   in attrs
                    has_httponly = 'httponly' in attrs
                    samesite_val = attrs.get('samesite', '')
                    max_age      = attrs.get('max-age', '')
                    expires      = attrs.get('expires', '')
                    is_session   = not max_age and not expires

                    issues = []
                    if not has_secure:
                        issues.append(('MISSING_SECURE', 'HIGH', 'Cookie sent over HTTP — intercept risk'))
                    if not has_httponly:
                        issues.append(('MISSING_HTTPONLY', 'MEDIUM', 'Readable by JavaScript — XSS risk'))
                    if not samesite_val:
                        issues.append(('MISSING_SAMESITE', 'MEDIUM', 'No CSRF protection via SameSite'))
                    elif samesite_val.lower() == 'none' and not has_secure:
                        issues.append(('SAMESITE_NONE_NO_SECURE', 'HIGH', 'SameSite=None requires Secure flag'))

                    cookie_entries.append({
                        'source':     'RESP',
                        'name':       name,
                        'value':      value_preview,
                        'secure':     has_secure,
                        'httponly':   has_httponly,
                        'samesite':   samesite_val if samesite_val else '—',
                        'is_session': is_session,
                        'domain':     attrs.get('domain', '—'),
                        'path':       attrs.get('path', '/'),
                        'issues':     issues,
                    })

        results['cookies'] = cookie_entries

    @staticmethod
    def _analyze_tech_stack(response_text: str, url: str, results: Dict):
        """Detect frameworks, server tech, and CDN/WAF from response headers and body."""
        if not response_text:
            results['tech_stack'] = {}
            return
        try:
            headers = SecurityAnalyzer._parse_headers(response_text)
            headers_lower = {k.lower(): v for k, v in headers.items()}
            body = response_text.split('\n\n', 1)[1] if '\n\n' in response_text else ''
            tech: Dict[str, List[str]] = {}

            # Server/X-Powered-By disclosure
            server = headers_lower.get('server', '')
            if server:
                tech['Server'] = [server]
            xpb = headers_lower.get('x-powered-by', '')
            if xpb:
                tech['X-Powered-By'] = [xpb]
            aspnet = headers_lower.get('x-aspnet-version', '') or headers_lower.get('x-aspnetmvc-version', '')
            if aspnet:
                tech['ASP.NET'] = [f'Version: {aspnet}']

            # CDN / WAF fingerprinting
            cdn_map = {
                'cf-ray':               ('Cloudflare', 'CDN/WAF'),
                'x-amz-cf-id':          ('AWS CloudFront', 'CDN'),
                'x-amz-cf-pop':         ('AWS CloudFront PoP', 'CDN'),
                'x-azure-ref':          ('Azure CDN', 'CDN'),
                'x-varnish':            ('Varnish Cache', 'Cache'),
                'x-cache':              ('Caching Proxy', 'Cache'),
                'x-akamai-request-id':  ('Akamai CDN', 'CDN'),
                'x-sucuri-id':          ('Sucuri WAF', 'WAF'),
                'x-fw-hash':            ('Fastly CDN', 'CDN'),
                'x-cdn':                ('Generic CDN', 'CDN'),
                'server-timing':        ('Server Timing (perf leak)', 'Info'),
            }
            for hdr, (name, cat) in cdn_map.items():
                val = headers_lower.get(hdr, '')
                if val:
                    tech[name] = [f'[{cat}] via {hdr}: {str(val)[:50]}']

            # JavaScript frameworks from inline HTML + JS
            if body:
                js_inline = SecurityAnalyzer._extract_all_inline_js(body)
                fw = FrameworkDetector.detect_javascript_frameworks(body, js_inline)
                for fw_name, evidence in fw.items():
                    tech[fw_name] = evidence[:8]

            # Cookie-based tech (PHP session, ASP session, etc.)
            cookie_tech = {
                'phpsessid':  'PHP Session',
                'asp.net_sessionid': 'ASP.NET Session',
                'jsessionid': 'Java/JVM App Server',
                'laravel_session': 'Laravel Framework',
                'ci_session':  'CodeIgniter Framework',
                '_rails_':     'Ruby on Rails',
            }
            set_cookie_vals = headers_lower.get('set-cookie', '').lower()
            for ck, tech_name in cookie_tech.items():
                if ck in set_cookie_vals:
                    tech.setdefault(tech_name, []).append(f'Detected via cookie: {ck}')

            results['tech_stack'] = tech
        except Exception as e:
            logger.debug(f"_analyze_tech_stack: {e}")
            results['tech_stack'] = {}

    # ──────────────────────────────────────────────────────────────────────
    # WEIRD ANALYZER — catches anomalous, protocol-oddity, and behavioural
    # issues that standard scanners usually miss.
    # ──────────────────────────────────────────────────────────────────────
    @staticmethod
    def _analyze_weird(request_text: str, response_text: str, url: str,
                       status: int, results: Dict):
        """Detect anomalous / 'weird' signals across request+response."""
        weird = results.setdefault('weird', [])

        def _add(severity, category, title, detail, evidence=''):
            weird.append({
                'severity': severity,
                'category': category,
                'title':    title,
                'detail':   detail,
                'evidence': evidence,
            })

        try:
            from urllib.parse import urlparse, unquote

            resp_text    = response_text or ''
            req_text     = request_text  or ''
            resp_lower   = resp_text.lower()
            resp_body    = ''
            resp_headers_raw = ''
            if '\r\n\r\n' in resp_text:
                resp_headers_raw, resp_body = resp_text.split('\r\n\r\n', 1)
            elif '\n\n' in resp_text:
                resp_headers_raw, resp_body = resp_text.split('\n\n', 1)
            else:
                resp_headers_raw = resp_text
                resp_body = ''

            # Parse response headers into a dict (lower-key → list of values)
            resp_hdr_map: Dict[str, List[str]] = {}
            for line in resp_headers_raw.splitlines()[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    resp_hdr_map.setdefault(k.strip().lower(), []).append(v.strip())

            resp_ct = resp_hdr_map.get('content-type', [''])[0].lower()

            # ── Parse request headers ─────────────────────────────────────
            req_hdr_map: Dict[str, List[str]] = {}
            req_body_text = ''
            req_lines = req_text.splitlines()
            in_req_body = False
            for i, line in enumerate(req_lines):
                if line == '' and not in_req_body and i > 0:
                    req_body_text = '\n'.join(req_lines[i+1:])
                    in_req_body = True
                    break
                if ':' in line and i > 0:
                    k, v = line.split(':', 1)
                    req_hdr_map.setdefault(k.strip().lower(), []).append(v.strip())

            url_lower = url.lower()
            url_path  = urlparse(url).path.lower() if url else ''

            # ─────────────────────────────────────────────────────────────
            # 1. Soft 403 — 200 OK but body says forbidden/denied
            # ─────────────────────────────────────────────────────────────
            if status == 200 and resp_body:
                _soft403_patterns = [
                    'access denied', 'access forbidden', 'not authorized',
                    'you are not allowed', 'permission denied', 'forbidden resource',
                    'insufficient privileges', 'unauthorized access',
                    'you do not have permission', 'authentication required',
                ]
                for pat in _soft403_patterns:
                    if pat in resp_lower:
                        _snip = resp_body[max(0, resp_lower.find(pat)-30):resp_lower.find(pat)+60]
                        _add('HIGH', 'Soft Error',
                             '200 OK but body contains denial message',
                             f'Status is 200 but body says "{pat}" — possible status spoofing or misconfigured error handler.',
                             _snip.strip())
                        break

            # ─────────────────────────────────────────────────────────────
            # 2. Content-Type mismatch
            # ─────────────────────────────────────────────────────────────
            if resp_body:
                _body_strip = resp_body.lstrip()
                _ct_mismatch = None
                if 'application/json' in resp_ct and _body_strip.startswith('<'):
                    _ct_mismatch = ('CT declares JSON but body starts with HTML/XML',
                                    resp_ct, _body_strip[:80])
                elif 'text/html' in resp_ct and _body_strip.startswith('{') or \
                     ('text/html' in resp_ct and _body_strip.startswith('[')):
                    _ct_mismatch = ('CT declares HTML but body is JSON',
                                    resp_ct, _body_strip[:80])
                elif 'text/plain' in resp_ct and '<html' in _body_strip[:200].lower():
                    _ct_mismatch = ('CT declares text/plain but body is HTML',
                                    resp_ct, _body_strip[:80])
                if _ct_mismatch:
                    _add('MEDIUM', 'Type Confusion',
                         'Content-Type mismatch',
                         f'{_ct_mismatch[0]}. Content-Type: {_ct_mismatch[1]}',
                         _ct_mismatch[2])

            # ─────────────────────────────────────────────────────────────
            # 3. Input reflection — URL params reflected in response
            # ─────────────────────────────────────────────────────────────
            if resp_body and url:
                from urllib.parse import urlparse, parse_qs
                _parsed = urlparse(url)
                _qs = parse_qs(_parsed.query)
                for _pk, _pvlist in _qs.items():
                    for _pv in _pvlist:
                        if len(_pv) >= 4 and _pv.lower() in resp_body.lower():
                            _add('HIGH', 'Reflection',
                                 f'Input reflected: param "{_pk}"',
                                 f'URL parameter value "{_pv}" appears verbatim in response body — possible XSS/injection entry point.',
                                 f'{_pk}={_pv}')

            # ─────────────────────────────────────────────────────────────
            # 4. Cache-Control mismatch on sensitive paths
            # ─────────────────────────────────────────────────────────────
            _sensitive_paths = ['/account', '/profile', '/dashboard', '/admin',
                                 '/settings', '/billing', '/payment', '/order',
                                 '/invoice', '/user/', '/private', '/secure']
            _cache_ctrl = resp_hdr_map.get('cache-control', [''])[0].lower()
            if any(sp in url_path for sp in _sensitive_paths):
                if 'public' in _cache_ctrl or (not _cache_ctrl and 'no-store' not in _cache_ctrl):
                    _add('HIGH', 'Cache Exposure',
                         'Sensitive path with cacheable response',
                         f'Path "{url_path}" appears sensitive but Cache-Control is "{_cache_ctrl or "(absent)"}". '
                         'Cached responses may expose user data to shared-cache attacks.',
                         f'Cache-Control: {_cache_ctrl or "(absent)"}')

            # ─────────────────────────────────────────────────────────────
            # 5. 204 No Content with a body
            # ─────────────────────────────────────────────────────────────
            if status == 204 and resp_body.strip():
                _add('MEDIUM', 'Protocol Violation',
                     '204 No Content but response has a body',
                     'RFC 7231 forbids a body on 204 responses. Intermediaries may behave unpredictably.',
                     resp_body.strip()[:120])

            # ─────────────────────────────────────────────────────────────
            # 6. HTTPS→HTTP redirect
            # ─────────────────────────────────────────────────────────────
            if status in (301, 302, 303, 307, 308):
                _location = resp_hdr_map.get('location', [''])[0]
                if url.startswith('https://') and _location.startswith('http://'):
                    _add('HIGH', 'Downgrade',
                         'HTTPS → HTTP redirect (protocol downgrade)',
                         f'Request was HTTPS but Location: {_location} downgrades to HTTP — MITM intercept surface.',
                         f'Location: {_location}')

            # ─────────────────────────────────────────────────────────────
            # 7. CORS null origin
            # ─────────────────────────────────────────────────────────────
            _acao = resp_hdr_map.get('access-control-allow-origin', [''])[0].strip()
            if _acao == 'null':
                _add('HIGH', 'CORS',
                     'Access-Control-Allow-Origin: null',
                     'null origin is accepted. Can be exploited from sandboxed iframes (file:// or data: origins).',
                     'Access-Control-Allow-Origin: null')

            # ─────────────────────────────────────────────────────────────
            # 8. X-XSS-Protection: 0
            # ─────────────────────────────────────────────────────────────
            _xxp = resp_hdr_map.get('x-xss-protection', [''])[0].strip()
            if _xxp.startswith('0'):
                _add('MEDIUM', 'Security Header',
                     'X-XSS-Protection: 0 — browser filter disabled',
                     'The legacy browser XSS auditor is explicitly turned off. Although modern browsers '
                     'removed this filter, older browsers are unprotected.',
                     'X-XSS-Protection: 0')

            # ─────────────────────────────────────────────────────────────
            # 9. Duplicate response headers
            # ─────────────────────────────────────────────────────────────
            for _hk, _hvals in resp_hdr_map.items():
                if len(_hvals) > 1 and _hk not in ('set-cookie', 'www-authenticate'):
                    _add('MEDIUM', 'Header Anomaly',
                         f'Duplicate header: {_hk}',
                         f'Header "{_hk}" appears {len(_hvals)} times with values: '
                         + ' | '.join(_hvals[:4]) +
                         '. Can cause header injection / parser confusion.',
                         ' | '.join(_hvals[:4]))

            # ─────────────────────────────────────────────────────────────
            # 10. Hop-by-hop headers in response
            # ─────────────────────────────────────────────────────────────
            _hop_by_hop = {'transfer-encoding', 'connection', 'keep-alive',
                           'proxy-authenticate', 'proxy-authorization',
                           'te', 'trailers', 'upgrade'}
            for _hbh in _hop_by_hop:
                if _hbh in resp_hdr_map and _hbh != 'transfer-encoding':
                    _add('LOW', 'Header Anomaly',
                         f'Hop-by-hop header in response: {_hbh}',
                         f'"{_hbh}" is a hop-by-hop header that should have been stripped by '
                         'intermediary proxies. Its presence may indicate a direct connection or misconfigured proxy.',
                         f'{_hbh}: {resp_hdr_map[_hbh][0]}')

            # ─────────────────────────────────────────────────────────────
            # 11. Multiple Set-Cookie for same cookie name
            # ─────────────────────────────────────────────────────────────
            _sc_vals = resp_hdr_map.get('set-cookie', [])
            _sc_names: List[str] = []
            for _sc in _sc_vals:
                _sc_name = _sc.split('=', 1)[0].strip().lower()
                _sc_names.append(_sc_name)
            _seen_ck: set = set()
            for _n in _sc_names:
                if _sc_names.count(_n) > 1 and _n not in _seen_ck:
                    _seen_ck.add(_n)
                    _add('MEDIUM', 'Cookie Anomaly',
                         f'Duplicate Set-Cookie for name "{_n}"',
                         f'Cookie "{_n}" is set {_sc_names.count(_n)} times. '
                         'Different browsers will keep different values — cookie jar poisoning vector.',
                         f'set-cookie: {_n}=... (x{_sc_names.count(_n)})')

            # ─────────────────────────────────────────────────────────────
            # 12. 401 without WWW-Authenticate
            # ─────────────────────────────────────────────────────────────
            if status == 401 and 'www-authenticate' not in resp_hdr_map:
                _add('MEDIUM', 'Auth Anomaly',
                     '401 Unauthorized with no WWW-Authenticate header',
                     'RFC 7235 §3.1 requires WWW-Authenticate on 401 responses. Missing header '
                     'suggests custom/broken authentication logic.',
                     'Status: 401, WWW-Authenticate: (absent)')

            # ─────────────────────────────────────────────────────────────
            # 13. 3xx with no Location header
            # ─────────────────────────────────────────────────────────────
            if status in (301, 302, 303, 307, 308) and 'location' not in resp_hdr_map:
                _add('MEDIUM', 'Protocol Violation',
                     f'{status} redirect with no Location header',
                     'A redirect response without Location is invalid per RFC 7231. '
                     'May indicate a broken or hand-rolled redirect handler.',
                     f'Status: {status}, Location: (absent)')

            # ─────────────────────────────────────────────────────────────
            # 14. Internal proxy chain leaked (Via / Forwarded)
            # ─────────────────────────────────────────────────────────────
            for _h in ('via', 'forwarded', 'x-forwarded-for', 'x-real-ip'):
                if _h in resp_hdr_map:
                    _add('LOW', 'Info Disclosure',
                         f'Internal proxy info leaked: {_h}',
                         f'Response contains "{_h}" header which reveals internal network topology.',
                         f'{_h}: {resp_hdr_map[_h][0]}')

            # ─────────────────────────────────────────────────────────────
            # 15. Null bytes in response body
            # ─────────────────────────────────────────────────────────────
            if '\x00' in resp_body:
                _cnt = resp_body.count('\x00')
                _add('HIGH', 'Encoding Anomaly',
                     'Null bytes (\\x00) in response body',
                     f'Found {_cnt} null byte(s) in the response body. Can cause truncation in C-based parsers, '
                     'bypass filters, or indicate binary injection.',
                     f'\\x00 appears {_cnt} time(s)')

            # ─────────────────────────────────────────────────────────────
            # 16. Unicode direction override characters
            # ─────────────────────────────────────────────────────────────
            _bidi_chars = {'\u202e': 'RIGHT-TO-LEFT OVERRIDE (U+202E)',
                           '\u202d': 'LEFT-TO-RIGHT OVERRIDE (U+202D)',
                           '\u200f': 'RIGHT-TO-LEFT MARK (U+200F)',
                           '\u200e': 'LEFT-TO-RIGHT MARK (U+200E)',
                           '\u2066': 'LEFT-TO-RIGHT ISOLATE (U+2066)',
                           '\u2067': 'RIGHT-TO-LEFT ISOLATE (U+2067)'}
            for _ch, _ch_name in _bidi_chars.items():
                if _ch in resp_body:
                    _add('HIGH', 'Encoding Anomaly',
                         f'Unicode direction override in response: {_ch_name}',
                         'Bidirectional control characters can be used for visual spoofing attacks. '
                         'Filenames or code shown containing these may deceive users.',
                         repr(_ch))

            # ─────────────────────────────────────────────────────────────
            # 17. Double URL-encoded characters in request URL
            # ─────────────────────────────────────────────────────────────
            if url:
                _double_enc = re.findall(r'%25[0-9A-Fa-f]{2}', url)
                if _double_enc:
                    _add('HIGH', 'Encoding Anomaly',
                         'Double URL-encoding in request URL',
                         'Patterns like %2520 (%25 + hex) indicate double-encoding — commonly used to '
                         'bypass WAF filters or path traversal checks.',
                         ', '.join(set(_double_enc[:5])))

            # ─────────────────────────────────────────────────────────────
            # 18. UTF-8 BOM marker in response
            # ─────────────────────────────────────────────────────────────
            if resp_text.startswith('\xef\xbb\xbf') or resp_body.startswith('\xef\xbb\xbf'):
                _add('LOW', 'Encoding Anomaly',
                     'UTF-8 BOM at start of response',
                     'A UTF-8 byte order mark (BOM: 0xEF 0xBB 0xBF) was found. '
                     'Some parsers mis-handle this, leading to XSS or header injection in certain contexts.',
                     'BOM: \\xef\\xbb\\xbf')

            # ─────────────────────────────────────────────────────────────
            # 19. HTML comments containing sensitive data
            # ─────────────────────────────────────────────────────────────
            _comment_re = re.compile(r'<!--(.*?)-->', re.DOTALL)
            _sensitive_comment_kw = ['todo', 'fixme', 'hack', 'password', 'passwd',
                                     'secret', 'key', 'token', 'credential', 'api',
                                     'debug', 'internal', 'staging', 'dev ', 'remove',
                                     'sql', 'database', 'db:', 'user:', 'admin', 'backdoor']
            for _cm in _comment_re.finditer(resp_body):
                _cm_text = _cm.group(1).lower()
                for _kw in _sensitive_comment_kw:
                    if _kw in _cm_text:
                        _snip = _cm.group(0)[:120]
                        _add('MEDIUM', 'Info Disclosure',
                             f'HTML comment contains sensitive keyword: "{_kw}"',
                             'Developer comment left in HTML may reveal architecture, credentials, or hints for attackers.',
                             _snip)
                        break

            # ─────────────────────────────────────────────────────────────
            # 20. Large base64 blobs in response (not JWT)
            # ─────────────────────────────────────────────────────────────
            _b64_re = re.compile(r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{60,}={0,2})(?![A-Za-z0-9+/=])')
            _jwt_prefix = re.compile(r'^eyJ')
            for _b64m in _b64_re.finditer(resp_body):
                _b64v = _b64m.group(1)
                if not _jwt_prefix.match(_b64v):
                    try:
                        import base64
                        _decoded = base64.b64decode(_b64v + '==').decode('utf-8', errors='replace')
                        _add('LOW', 'Encoding Anomaly',
                             'Large base64 blob in response (non-JWT)',
                             f'Base64 string of length {len(_b64v)} found. May contain hidden embedded data or credentials.',
                             _b64v[:60] + '…')
                        break  # one report per response is enough
                    except Exception:
                        pass

            # ─────────────────────────────────────────────────────────────
            # 21. Debug/test params that change behaviour
            # ─────────────────────────────────────────────────────────────
            if url:
                _debug_params = ['debug', 'test', 'dev', 'trace', 'verbose',
                                 'admin', 'superuser', 'god', 'root', 'bypass',
                                 'internal', 'preview', 'staging', 'qa', 'demo']
                from urllib.parse import parse_qs, urlparse as _up2
                _q = parse_qs(_up2(url).query)
                for _dp in _debug_params:
                    if _dp in {k.lower() for k in _q}:
                        _add('HIGH', 'Logic Anomaly',
                             f'Debug/test parameter present: "{_dp}"',
                             f'URL contains parameter "{_dp}" which may activate debug modes, '
                             'bypass authorization, or expose internal functionality.',
                             f'{_dp}={list(_q.get(_dp, _q.get(_dp.upper(), ["?"])))[0]}')

            # ─────────────────────────────────────────────────────────────
            # 22. Business logic params (negative/zero prices/quantities)
            # ─────────────────────────────────────────────────────────────
            _bl_params = {'price', 'amount', 'qty', 'quantity', 'discount',
                          'total', 'cost', 'fee', 'tax', 'credit', 'debit'}
            _bl_body   = req_body_text or ''
            _bl_re     = re.compile(
                r'["\']?(' + '|'.join(_bl_params) + r')["\']?\s*[=:]\s*(-?\d+\.?\d*)',
                re.IGNORECASE)
            for _blm in _bl_re.finditer(_bl_body):
                _bp_name = _blm.group(1)
                _bp_val  = float(_blm.group(2))
                if _bp_val <= 0:
                    _add('HIGH', 'Logic Anomaly',
                         f'Business logic param with suspicious value: {_bp_name}={_blm.group(2)}',
                         f'Parameter "{_bp_name}" has value {_blm.group(2)} (≤ 0). '
                         'Negative or zero values for financial/quantity fields may indicate a business logic bypass.',
                         _blm.group(0))

            # ─────────────────────────────────────────────────────────────
            # 23. Double-slash path normalization bypass
            # ─────────────────────────────────────────────────────────────
            if url:
                from urllib.parse import urlparse as _up3
                _path3 = _up3(url).path
                if re.search(r'//+', _path3):
                    _add('MEDIUM', 'Path Anomaly',
                         'Double-slash in URL path',
                         f'Path "{_path3}" contains consecutive slashes. Some servers/frameworks '
                         'interpret this differently from a clean path — path auth bypass vector.',
                         _path3)
                # Also: ..;/ Tomcat bypass
                if '..;/' in _path3 or '%2e%2e%3b' in _path3.lower():
                    _add('HIGH', 'Path Anomaly',
                         'Tomcat path traversal bypass pattern (..;/)',
                         f'Path contains "..;/" which bypasses Tomcat/Spring security filters.',
                         _path3)

            # ─────────────────────────────────────────────────────────────
            # 24. Serialized objects in body or response
            # ─────────────────────────────────────────────────────────────
            _serial_sigs = [
                (r'rO0AB',                         'Java serialized object (base64 encoded)'),
                (r'O:\d+:"[^"]+":\d+:\{',          'PHP serialized object'),
                (r'\x80\x04\x95|\x80\x03\x7d',    'Python pickle stream'),
                (r'<java\.object',                  'Java XML serialization'),
                (r'[Tt]ypeNameHandling|__type\s*:', '.NET JSON type name serialization'),
                (r'YWN0aW9uPW',                    'Java ViewState / Action (base64)'),
            ]
            for _combined in (_bl_body, resp_body[:4000]):
                for _spat, _slabel in _serial_sigs:
                    if re.search(_spat, _combined):
                        _add('CRITICAL', 'Deserialization',
                             f'Serialized object detected: {_slabel}',
                             f'Serialized data found. If the server deserializes untrusted input this is a '
                             f'CRITICAL deserialization RCE vector ({_slabel}).',
                             _spat)
                        break

            # ─────────────────────────────────────────────────────────────
            # 25. TODO / FIXME / HACK comments in JS/HTML source
            # ─────────────────────────────────────────────────────────────
            _dev_comment_re = re.compile(
                r'(?://|/\*|#)\s*(TODO|FIXME|HACK|XXX|BUG|NOSONAR|HARDCODED|REMOVE\s+BEFORE)'
                r'[^\n]{0,200}',
                re.IGNORECASE)
            _seen_dev: set = set()
            for _dcm in _dev_comment_re.finditer(resp_body):
                _key = _dcm.group(0)[:60]
                if _key not in _seen_dev:
                    _seen_dev.add(_key)
                    _add('LOW', 'Developer Note',
                         f'Developer comment: {_dcm.group(1).upper()}',
                         'Developer annotation left in production code. May reveal endpoints, credentials, or logic flaws.',
                         _dcm.group(0)[:120])

            # ─────────────────────────────────────────────────────────────
            # 26. Hash-like strings in request/response (MD5/SHA/bcrypt/etc.)
            # ─────────────────────────────────────────────────────────────
            _hash_patterns = [
                # bcrypt / argon2 / scrypt (password hashes — highest interest)
                (r'\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}',           'bcrypt hash',           'CRITICAL'),
                (r'\$argon2(?:i|d|id)\$[^\s"\'<>]{30,}',           'Argon2 hash',           'CRITICAL'),
                (r'\$s0\$[0-9a-f]+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+', 'scrypt hash',      'CRITICAL'),
                # SHA-512 crypt
                (r'\$6\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{86}',  'SHA-512 crypt hash',    'HIGH'),
                # SHA-256 crypt
                (r'\$5\$[./A-Za-z0-9]{8,16}\$[./A-Za-z0-9]{43}',  'SHA-256 crypt hash',    'HIGH'),
                # MD5 crypt
                (r'\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}',   'MD5 crypt hash',        'HIGH'),
                # Raw hex hashes by length
                (r'\b[0-9a-fA-F]{128}\b',                          'SHA-512 hex hash (512-bit)', 'MEDIUM'),
                (r'\b[0-9a-fA-F]{64}\b',                           'SHA-256 hex hash (256-bit)', 'MEDIUM'),
                (r'\b[0-9a-fA-F]{56}\b',                           'SHA-224 hex hash',      'MEDIUM'),
                (r'\b[0-9a-fA-F]{40}\b',                           'SHA-1 hex hash (160-bit)', 'LOW'),
                (r'\b[0-9a-fA-F]{32}\b',                           'MD5 hex hash (128-bit)', 'LOW'),
                # HMAC prefix hints
                (r'(?i)(?:hmac[-_]?(?:sha(?:1|224|256|384|512)|md5))[=:\s]+[0-9a-fA-F]{32,}',
                                                                    'HMAC hash',             'MEDIUM'),
            ]
            for _combined_src, _src_label in (
                    (req_text,         'request'),
                    (resp_body[:8000], 'response body')):
                _seen_hashes: set = set()
                for _hpat, _hlabel, _hsev in _hash_patterns:
                    for _hm in re.finditer(_hpat, _combined_src):
                        _hval = _hm.group(0)
                        _key  = (_hlabel, _hval[:32])
                        if _key not in _seen_hashes:
                            _seen_hashes.add(_key)
                            _add(_hsev, 'Hash Exposure',
                                 f'{_hlabel} detected in {_src_label}',
                                 f'A {_hlabel} was found in the {_src_label}. '
                                 'Exposed password hashes can be cracked offline. '
                                 'Verify whether this is intentional (e.g. an API response) or leaked.',
                                 _hval[:80])

            # ─────────────────────────────────────────────────────────────
            # 27. Hex-encoded data blobs (potential obfuscation / bypass)
            # ─────────────────────────────────────────────────────────────
            # Long pure-hex strings that are NOT hash-length (> 64 chars, even length)
            _hex_blob_re = re.compile(r'(?<![0-9a-fA-F])([0-9a-fA-F]{66,})(?![0-9a-fA-F])')
            for _combined_src, _src_label in (
                    (req_text,         'request'),
                    (resp_body[:8000], 'response body')):
                for _hbm in _hex_blob_re.finditer(_combined_src):
                    _hbv = _hbm.group(1)
                    if len(_hbv) % 2 == 0:  # valid hex must be even length
                        _add('LOW', 'Encoding Anomaly',
                             f'Large hex-encoded blob in {_src_label}',
                             f'Hex string of {len(_hbv)} characters found. May encode binary payloads, '
                             'shellcode, or obfuscated data used to bypass content filters.',
                             _hbv[:80] + ('…' if len(_hbv) > 80 else ''))
                        break  # one per source per response

            # ─────────────────────────────────────────────────────────────
            # 28. URL-encoded sequences in request body / response body
            # ─────────────────────────────────────────────────────────────
            _pct_re = re.compile(r'(?:%[0-9A-Fa-f]{2}){6,}')  # 6+ consecutive %-encoded bytes
            for _combined_src, _src_label in (
                    (_bl_body,         'request body'),
                    (resp_body[:4000], 'response body')):
                for _pm in _pct_re.finditer(_combined_src):
                    _pv = _pm.group(0)
                    _add('MEDIUM', 'Encoding Anomaly',
                         f'Heavily URL-encoded sequence in {_src_label}',
                         f'Found {len(_pv)//3} consecutive percent-encoded bytes. '
                         'Dense URL encoding is frequently used to bypass WAF rules or smuggle payloads.',
                         _pv[:80])
                    break  # one per source

            # ─────────────────────────────────────────────────────────────
            # 29. HTML entity encoding clusters (possible XSS obfuscation)
            # ─────────────────────────────────────────────────────────────
            _ent_re = re.compile(r'(?:&#x?[0-9a-fA-F]{1,6};){4,}')
            for _em in _ent_re.finditer(resp_body):
                _ev = _em.group(0)
                _add('MEDIUM', 'Encoding Anomaly',
                     'HTML entity cluster in response body',
                     'Sequences of HTML entity-encoded characters can be used to obfuscate script '
                     'payloads and bypass pattern-based XSS filters.',
                     _ev[:80])
                break

            # ─────────────────────────────────────────────────────────────
            # 30. Unicode escape sequences (\uXXXX / \UXXXXXXXX) in JSON/JS
            # ─────────────────────────────────────────────────────────────
            _uni_re = re.compile(r'(?:\\u[0-9a-fA-F]{4}){4,}')
            for _combined_src, _src_label in (
                    (req_text,         'request'),
                    (resp_body[:4000], 'response body')):
                for _um in _uni_re.finditer(_combined_src):
                    _uv = _um.group(0)
                    _add('MEDIUM', 'Encoding Anomaly',
                         f'Dense Unicode escape sequences in {_src_label}',
                         'Multiple consecutive \\uXXXX escapes may obfuscate JavaScript payloads '
                         'to evade WAF/CSP string matching.',
                         _uv[:80])
                    break

            # ─────────────────────────────────────────────────────────────
            # 31. ROT13 / Caesar-shifted strings (trivial obfuscation)
            # ─────────────────────────────────────────────────────────────
            import codecs as _codecs
            _rot13_kw = ['frphevgl', 'cnffjbeq', 'nqzva', 'frperg', 'gbxra',
                         'pernqragvnyf', 'rkcybvg', 'cnlybnq', 'injrenoyr']
            for _combined_src, _src_label in (
                    (req_text,         'request'),
                    (resp_body[:4000], 'response body')):
                _src_lower = _combined_src.lower()
                for _rk in _rot13_kw:
                    if _rk in _src_lower:
                        _decoded_rot13 = _codecs.decode(_rk, 'rot_13')
                        _add('LOW', 'Encoding Anomaly',
                             f'ROT13-encoded sensitive keyword in {_src_label}',
                             f'Found ROT13 encoding of "{_decoded_rot13}" ("{_rk}"). '
                             'Trivial obfuscation is sometimes used to hide credentials or bypass naive scanners.',
                             _rk)
                        break

            # ─────────────────────────────────────────────────────────────
            # 32. Gzip / Deflate / Brotli magic bytes in body
            # ─────────────────────────────────────────────────────────────
            _compress_sigs = [
                ('\x1f\x8b',         'Gzip magic bytes (\\x1f\\x8b)'),
                ('\x78\x9c',         'Zlib/Deflate magic bytes (\\x78\\x9c)'),
                ('\x78\x01',         'Zlib low-compression magic bytes (\\x78\\x01)'),
                ('\x78\xda',         'Zlib best-compression magic bytes (\\x78\\xda)'),
                ('\xce\xb2\xcf\x81', 'Brotli magic bytes'),
            ]
            for _combined_src, _src_label in (
                    (_bl_body,   'request body'),
                    (resp_body,  'response body')):
                for _magic, _label in _compress_sigs:
                    if _magic in _combined_src:
                        _add('LOW', 'Encoding Anomaly',
                             f'{_label} found in {_src_label}',
                             f'Compressed data signature ({_label}) detected. '
                             'Sending compressed payloads can bypass content-inspection filters '
                             'if the server decompresses before processing.',
                             repr(_magic))
                        break

            # ─────────────────────────────────────────────────────────────
            # 33. JWT algorithm confusion indicators
            # ─────────────────────────────────────────────────────────────
            _jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*')
            for _combined_src, _src_label in (
                    (req_text,         'request'),
                    (resp_body[:4000], 'response body')):
                for _jm in _jwt_re.finditer(_combined_src):
                    _jv = _jm.group(0)
                    try:
                        import base64 as _b64
                        _hdr_raw = _jv.split('.')[0]
                        _pad     = _hdr_raw + '=' * (-len(_hdr_raw) % 4)
                        _hdr_dec = _b64.urlsafe_b64decode(_pad).decode('utf-8', errors='replace')
                        _alg_lower = _hdr_dec.lower()
                        if '"alg":"none"' in _alg_lower or '"alg": "none"' in _alg_lower:
                            _add('CRITICAL', 'JWT',
                                 f'JWT with "alg":"none" in {_src_label}',
                                 'Algorithm set to "none" disables signature verification — trivially forgeable.',
                                 _jv[:80] + '…')
                        elif '"hs256"' in _alg_lower and 'rs' in _alg_lower:
                            _add('HIGH', 'JWT',
                                 f'JWT header has mixed algorithm hint in {_src_label}',
                                 'Potential RS256→HS256 algorithm confusion attack indicator.',
                                 _jv[:80] + '…')
                        else:
                            # Report generic JWT presence if not already flagged elsewhere
                            _add('INFO', 'JWT',
                                 f'JWT token present in {_src_label}',
                                 f'Header: {_hdr_dec[:120]}',
                                 _jv[:80] + '…')
                    except Exception:
                        pass
                    break  # one JWT report per source

            # ─────────────────────────────────────────────────────────────
            # 34. Mixed encoding in a single parameter value
            #     (e.g. part URL-encoded + part base64 + part hex)
            # ─────────────────────────────────────────────────────────────
            if req_text or _bl_body:
                _mixed_enc_re = re.compile(
                    r'(?:[0-9a-fA-F]{32,}|%[0-9A-Fa-f]{2}|&#x?[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4}|[A-Za-z0-9+/]{40,}={0,2})'
                    r'.{0,20}'
                    r'(?:[0-9a-fA-F]{32,}|%[0-9A-Fa-f]{2}|&#x?[0-9a-fA-F]+;|\\u[0-9a-fA-F]{4}|[A-Za-z0-9+/]{40,}={0,2})',
                    re.IGNORECASE)
                _check_src = req_text + '\n' + _bl_body
                for _mm in _mixed_enc_re.finditer(_check_src):
                    _mv = _mm.group(0)
                    if len(_mv) >= 50:
                        _add('MEDIUM', 'Encoding Anomaly',
                             'Mixed encoding in request (possible WAF bypass)',
                             'A value appears to combine multiple encoding schemes (hex + percent + base64 / entity). '
                             'Layered encoding is a classic WAF evasion technique.',
                             _mv[:100])
                        break

        except Exception as e:
            logger.debug(f"_analyze_weird: {e}", exc_info=True)

    @staticmethod
    def _extract_all_inline_js(html: str) -> str:
        """
        Extract JavaScript code from:
        1. Inline <script> tag contents
        2. Event handler attributes (onclick, onload, etc.)
        3. javascript: URLs in href, src, action, etc.
        Returns a single string of concatenated JS snippets.
        """
        js_parts = []

        # 1. Inline script blocks
        script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', html, re.IGNORECASE | re.DOTALL)
        js_parts.extend(script_blocks)

        # 2. Event handler attributes (onclick, onload, onerror, etc.)
        # Pattern: on\w+="...JS code..." or on\w+='...JS code...'
        event_handlers = re.findall(r'\s(on\w+)\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE)
        for _, code in event_handlers:
            js_parts.append(code)

        # 3. javascript: URLs in href, src, action, data-*, etc.
        # Capture the whole URL, then extract the part after 'javascript:'
        js_urls = re.findall(r'(?:href|src|action|data-[\w-]+)\s*=\s*["\']javascript:([^"\']+)["\']', html, re.IGNORECASE)
        for code in js_urls:
            js_parts.append(code)

        # 4. Also check for standalone javascript: in attribute values (e.g., onclick="javascript:...")
        # This is already covered by #2, but we add a catch-all for any attribute containing 'javascript:'
        js_in_attrs = re.findall(r'=\s*["\'][^"\']*javascript:([^"\']+)["\']', html, re.IGNORECASE)
        for code in js_in_attrs:
            js_parts.append(code)

        return '\n'.join(js_parts)

"""
Part 2: PyQt5 Analysis Tab UI Components
"""


# ============================================================================
# AI TRAFFIC ANALYSIS DIALOG
# ============================================================================

class AITrafficDialog(QDialog):
    """
    Two-tab AI Security Analysis dialog:
      Tab 1 — Traffic Analysis  : finds IDOR, auth bypass, business-logic, injection (request+response)
      Tab 2 — Source Code Review: finds DOM XSS, hardcoded secrets, dangerous JS patterns, etc.
    Both workers start in parallel when the dialog opens.
    """

    _SEV_COLORS = {
        "CRITICAL": "#FF6B6B",
        "HIGH":     "#FFA726",
        "MEDIUM":   "#FFEE58",
        "LOW":      "#64B5F6",
        "INFO":     "#90A4AE",
    }

    def __init__(self, settings: dict, request_text: str, response_text: str,
                 url: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("\u2728 AI Security Analysis")
        self.resize(880, 680)
        self.setModal(True)
        bg = COLORS.get("bg_dark", "#2B2B2B")
        self.setStyleSheet(f"QDialog {{ background:{bg}; color:#ccc; }}")

        root = QVBoxLayout(self)
        root.setSpacing(6)
        root.setContentsMargins(12, 10, 12, 10)

        # Header
        hdr = QLabel(
            f"<b style='color:#c8a0ff;font-size:13px;'>\u2728 AI Security Analysis</b>"
            f"<span style='color:#555;font-size:11px;'> \u2014 {url[:90]}</span>"
        )
        hdr.setTextFormat(Qt.RichText)
        root.addWidget(hdr)

        # Two-tab container
        self._tabs = QTabWidget()
        self._tabs.setStyleSheet(
            f"QTabWidget::pane {{ border:none; background:{COLORS.get('bg_darker','#1E1E1E')}; }}"
            "QTabBar::tab { background:#1a1a2a; color:#888; padding:5px 18px;"
            "               border:none; border-right:1px solid #222; font-size:11px; }"
            "QTabBar::tab:selected { background:#2a1a4a; color:#c8a0ff;"
            "                        border-bottom:2px solid #8a50e8; }"
            "QTabBar::tab:hover { color:#ddd; }"
        )

        # Tab 1: Traffic Analysis
        self._traffic_out, self._traffic_copy = self._add_result_tab(
            "\U0001f512  Traffic Analysis",
            "\u23f3  Analyzing request/response with AI \u2014 this may take 15\u201330 s\u2026"
        )

        # Tab 2: Source Code Review
        self._code_out, self._code_copy = self._add_result_tab(
            "\U0001f50d  Source Code Review",
            "\u23f3  Reviewing HTML/JS source code with AI \u2014 this may take 15\u201330 s\u2026"
        )

        root.addWidget(self._tabs)

        # Close button
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_btn.setStyleSheet(
            "QPushButton{background:#2a2a2a;color:#aaa;border:1px solid #555;"
            "border-radius:3px;padding:4px 18px;}"
            "QPushButton:hover{background:#383838;}"
        )
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

        self._workers = []

        # Start Traffic Analysis worker
        if _AITrafficWorker:
            w1 = _AITrafficWorker(settings, request_text, response_text, self)
            w1.finished.connect(
                lambda findings: self._on_findings(
                    self._traffic_out, self._traffic_copy, findings, code_review=False
                )
            )
            w1.error.connect(lambda e: self._on_error(self._traffic_out, e))
            w1.start()
            self._workers.append(w1)

        # Start Source Code Review worker (uses response body = HTML+JS)
        if _AISourceCodeWorker:
            w2 = _AISourceCodeWorker(settings, response_text, url, self)
            w2.finished.connect(
                lambda findings: self._on_findings(
                    self._code_out, self._code_copy, findings, code_review=True
                )
            )
            w2.error.connect(lambda e: self._on_error(self._code_out, e))
            w2.start()
            self._workers.append(w2)

    # ── helpers ────────────────────────────────────────────────────────────

    def _add_result_tab(self, title: str, loading_msg: str):
        """Create one result tab. Returns (output QTextEdit, copy QPushButton)."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 4, 0, 4)
        layout.setSpacing(4)

        output = QTextEdit()
        output.setReadOnly(True)
        output.setStyleSheet(
            f"background:{COLORS.get('bg_darker','#1E1E1E')};"
            "color:#ccc; border:none; font-size:12px;"
        )
        output.setHtml(
            f"<div style='color:#888;padding:24px;font-size:13px;'>{loading_msg}</div>"
        )
        layout.addWidget(output)

        copy_btn = QPushButton("\u2398  Copy Results")
        copy_btn.setEnabled(False)
        copy_btn.setFixedHeight(24)
        copy_btn.setStyleSheet(
            "QPushButton{background:#1e2e1e;color:#8bc;border:1px solid #4a6;"
            "border-radius:3px;padding:0 14px;font-size:11px;}"
            "QPushButton:hover{background:#2a3e2a;}"
            "QPushButton:disabled{color:#555;border-color:#333;background:#1a1a1a;}"
        )
        layout.addWidget(copy_btn)

        self._tabs.addTab(container, title)
        return output, copy_btn

    def _on_findings(self, output: QTextEdit, copy_btn: QPushButton,
                     findings: list, code_review: bool = False):
        """Shared renderer for both tabs. code_review=True adds evidence + category fields."""
        if not findings:
            output.setHtml(
                "<div style='color:#6a9;padding:20px;font-size:13px;'>"
                "\u2705 No security findings identified.</div>"
            )
            plain = "No security findings identified."
            copy_btn.setEnabled(True)
            copy_btn.clicked.connect(lambda: self._do_copy(copy_btn, plain))
            return

        html_parts  = []
        plain_parts = []

        for f in findings:
            sev      = str(f.get("severity",  "INFO")).upper()
            color    = self._SEV_COLORS.get(sev, "#90A4AE")
            conf     = max(0, min(100, int(f.get("confidence", 0))))
            title    = _html.escape(str(f.get("title",     "Unknown Finding")))
            reason   = _html.escape(str(f.get("reasoning", "")))
            payloads = f.get("payloads",  [])
            category = _html.escape(str(f.get("category",  "")))   # source code review
            evidence = _html.escape(str(f.get("evidence",  "")))   # source code review

            bar_fill = round(conf / 5)
            bar = "\u2588" * bar_fill + "\u2591" * (20 - bar_fill)

            cat_html = (
                f" <span style='color:#666;font-size:10px;'>[{category}]</span>"
            ) if category else ""

            html_parts.append(
                f"<div style='border-left:4px solid {color};"
                f"background:#1c1c1c;margin:8px 0;padding:10px 14px;border-radius:2px;'>"
                f"<div style='font-size:13px;font-weight:bold;color:{color};'>"
                f"{sev} &nbsp;\u00b7&nbsp; {title}{cat_html}</div>"
                f"<div style='color:#777;font-size:10px;margin:3px 0 6px;font-family:monospace;'>"
                f"Confidence: <span style='color:{color};'>{bar}</span> {conf}%</div>"
            )

            # Evidence block (quoted vulnerable code) — source code tab only
            if evidence:
                html_parts.append(
                    f"<div style='font-family:monospace;font-size:11px;"
                    f"background:#0d1117;color:#e0a060;padding:6px 10px;"
                    f"margin:4px 0 6px;border-radius:2px;white-space:pre-wrap;"
                    f"border-left:3px solid #5a3a10;'>{evidence}</div>"
                )

            html_parts.append(
                f"<div style='color:#bbb;font-size:11px;line-height:1.6;'>{reason}</div>"
            )

            if payloads:
                html_parts.append(
                    "<div style='margin-top:8px;'>"
                    "<span style='color:#666;font-size:10px;letter-spacing:0.5px;'>"
                    "PAYLOADS / PoC</span>"
                )
                for p in payloads:
                    p_escaped = _html.escape(str(p))
                    html_parts.append(
                        f"<div style='font-family:monospace;font-size:11px;"
                        f"background:#111;color:#c8a0ff;padding:4px 10px;"
                        f"margin:2px 0;border-radius:2px;white-space:pre;'>{p_escaped}</div>"
                    )
                html_parts.append("</div>")

            html_parts.append("</div>")

            plain_parts.append(
                f"[{sev}] {title}" + (f" [{category}]" if category else "") +
                f" (confidence: {conf}%)"
            )
            if evidence:
                plain_parts.append(f"Evidence: {evidence}")
            plain_parts.append(reason)
            if payloads:
                plain_parts.append("Payloads: " + " | ".join(payloads))
            plain_parts.append("")

        output.setHtml("".join(html_parts))
        plain_text = "\n".join(plain_parts)
        copy_btn.setEnabled(True)
        copy_btn.clicked.connect(lambda: self._do_copy(copy_btn, plain_text))

    def _on_error(self, output: QTextEdit, msg: str):
        output.setHtml(
            f"<div style='color:#ff6b6b;padding:16px;font-size:12px;'>"
            f"<b>Error:</b><br><pre style='white-space:pre-wrap;'>{_html.escape(str(msg))}</pre></div>"
        )

    def _do_copy(self, btn: QPushButton, text: str):
        QApplication.clipboard().setText(text)
        original = btn.text()
        btn.setText("\u2713 Copied")
        QTimer.singleShot(2000, lambda: btn.setText(original))

    def closeEvent(self, event):
        for w in self._workers:
            if w.isRunning():
                w.quit()
                w.wait(3000)
        super().closeEvent(event)



# ── Markdown helpers for AI chat output ──────────────────────────────────────


# ── AI Security Chat Panel ────────────────────────────────────────────────────
# Moved to ai_chatbox.py to keep this analysis engine file focused.
from modules.ai_chatbox import AIChatPanel, _md_to_html, _inline_md  # noqa: F401


class AnalysisTabMixin:
    """
    Complete Analysis Tab with Parameter Markers and Auto-Highlighting.
    This class is designed to be used as a mixin in HTTPHistoryTab.
    """
    
    def create_analysis_tab_in_rr_tabs(self):
        """Create the Analysis tab inside rr_tabs (Request/Response tabs container)"""
        analysis_tab = QWidget()
        layout = QVBoxLayout(analysis_tab)
        layout.setContentsMargins(2, 2, 2, 2)
        layout.setSpacing(2)
        
        # Main splitter (vertical)
        main_splitter = QSplitter(Qt.Vertical)
        
        # Top section: Parameter Markers (unchanged)
        param_section = self._create_parameter_markers_section()
        main_splitter.addWidget(param_section)
        
        # Bottom section: tabbed security panels
        bottom_tabs = QTabWidget()
        bottom_tabs.setTabPosition(QTabWidget.North)
        bottom_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {COLORS.get('bg_dark', '#2B2B2B')};
                margin: 0px;
            }}
            QTabBar {{
                alignment: left;
            }}
            QTabBar::tab {{
                background-color: {COLORS.get('bg_darker', '#1E1E1E')};
                color: #888888;
                padding: 3px 7px;
                border: none;
                border-right: 1px solid #2a2a2a;
                font-size: 10px;
                min-width: 10px;
                max-width: 90px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS.get('bg_lighter', '#323232')};
                color: {COLORS.get('text_bright', '#FFFFFF')};
                border-bottom: 2px solid {COLORS.get('accent_green', '#6A8759')};
            }}
            QTabBar::tab:hover {{
                color: {COLORS.get('text_bright', '#FFFFFF')};
                background-color: {COLORS.get('bg_lighter', '#323232')};
            }}
            QTabBar QToolButton {{
                background-color: {COLORS.get('bg_darker', '#1E1E1E')};
                color: {COLORS.get('text_bright', '#FFFFFF')};
                border: 1px solid #3a3a3a;
                border-radius: 2px;
                padding: 2px 4px;
                min-width: 16px;
                min-height: 16px;
            }}
            QTabBar QToolButton:hover {{
                background-color: {COLORS.get('accent_green', '#6A8759')};
                color: #ffffff;
            }}
            QTabBar QToolButton:pressed {{
                background-color: {COLORS.get('bg_lighter', '#323232')};
            }}
        """)
        # Enable scroll arrows when tabs overflow the available width
        bottom_tabs.setUsesScrollButtons(True)
        bottom_tabs.tabBar().setUsesScrollButtons(True)
        bottom_tabs.tabBar().setElideMode(Qt.ElideRight)
        self._analysis_bottom_tabs = bottom_tabs

        # Tab 0: Info Leakage (existing)
        highlight_section = self._create_auto_highlighting_section()
        bottom_tabs.addTab(highlight_section, "🔍 Leakage")

        # Tab 1: Security Headers (NEW)
        self._sec_headers_panel = self._create_security_headers_panel()
        bottom_tabs.addTab(self._sec_headers_panel, "🛡 Headers")

        # Tab 2: Cookie Security (NEW)
        self._cookie_panel = self._create_cookie_panel()
        bottom_tabs.addTab(self._cookie_panel, "🤀 Cookies")

        # Tab 3: CORS Analysis (NEW)
        self._cors_panel = self._create_cors_panel()
        bottom_tabs.addTab(self._cors_panel, "🌐 CORS")

        # Tab 4: Technology Stack (NEW)
        self._tech_panel = self._create_tech_stack_panel()
        bottom_tabs.addTab(self._tech_panel, "⊞ Tech")

        # Tab 5: JWT Deep Analysis (NEW)
        self._jwt_panel = self._create_jwt_panel()
        bottom_tabs.addTab(self._jwt_panel, "⚿ JWT")

        # Tab 6: Cache Poisoning Indicators (NEW)
        self._cache_panel = self._create_cache_panel()
        bottom_tabs.addTab(self._cache_panel, "↺ Cache")

        # Tab 7: Discovered Endpoints (NEW)
        self._endpoints_panel = self._create_endpoints_panel()
        bottom_tabs.addTab(self._endpoints_panel, "⊃ Endpoints")

        # Tab 8: Weird / Anomaly findings (NEW)
        self._weird_panel = self._create_weird_panel()
        bottom_tabs.addTab(self._weird_panel, "△ Weird")

        # Tab 9: JS / DOM Analysis (NEW)
        self._js_dom_panel = self._create_js_dom_panel()
        bottom_tabs.addTab(self._js_dom_panel, "⚡ JS/DOM")

        # Hide data-driven tabs initially; they become visible once a request
        # is selected and _display_security_panels finds real results.
        for _idx in (2, 3, 4, 5, 6, 7, 8, 9):
            bottom_tabs.setTabVisible(_idx, False)

        main_splitter.addWidget(bottom_tabs)
        
        # Set splitter proportions (50/50)
        main_splitter.setSizes([330, 330])

        layout.addWidget(main_splitter)

        return analysis_tab
    
    def _create_parameter_markers_section(self):
        """Create parameter position markers section - NO STATUS BAR, MAXIMIZED TABLE"""
        group = QGroupBox()
        group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['bg_lighter']};
                border: 1px solid #3a3a3a;
                border-left: 3px solid {COLORS.get('accent_green', '#6A8759')};
                border-radius: 0px;
                margin-top: 0px;
                padding-top: 0px;
            }}
        """)

        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Styled header bar ──────────────────────────
        header_bar = QWidget()
        header_bar.setFixedHeight(26)
        header_bar.setStyleSheet(
            f"background-color: {COLORS['bg_darker']};"
            f"border-bottom: 1px solid #444;"
        )
        header_layout = QHBoxLayout(header_bar)
        header_layout.setContentsMargins(8, 0, 8, 0)
        header_layout.setSpacing(6)

        section_icon = QLabel("</>")
        section_icon.setStyleSheet("font-size: 11px;")
        header_layout.addWidget(section_icon)

        section_title = QLabel("Parameter Analysis")
        section_title.setStyleSheet(
            f"color: {COLORS.get('text_bright', '#FFFFFF')};"
            f"font-weight: 600; font-size: 11px; letter-spacing: 0.3px;"
        )
        header_layout.addWidget(section_title)

        header_layout.addStretch()

        self.param_count_badge = QLabel("0 params")
        self.param_count_badge.setStyleSheet(
            "color: #888; font-size: 10px; "
            "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
        )
        header_layout.addWidget(self.param_count_badge)

        # Toggle arrow
        self._param_filter_arrow = QLabel("▶")
        self._param_filter_arrow.setStyleSheet("color: #666; font-size: 9px; padding-left: 4px;")
        header_layout.addWidget(self._param_filter_arrow)

        layout.addWidget(header_bar)

        # ── Filter container (toggled by header click) ────────────────────
        self.param_filter_container = QWidget()
        self.param_filter_container.setFixedHeight(28)
        self.param_filter_container.setStyleSheet(
            f"background-color: {COLORS['bg_darker']};"
            f"border-bottom: 1px solid #2e2e2e;"
        )
        self.param_filter_container.setVisible(False)
        # param_title_btn shim (kept for any legacy callers)
        self.param_title_btn = QPushButton()
        self.param_title_btn.setVisible(False)

        def _toggle_param_filter():
            visible = not self.param_filter_container.isVisible()
            self.param_filter_container.setVisible(visible)
            self._param_filter_arrow.setText("▼" if visible else "▶")

        header_bar.setCursor(Qt.PointingHandCursor)
        header_bar.mousePressEvent = lambda e: _toggle_param_filter()
        
        # ==================== COMPACT FILTER ROW ====================
        filter_row = QHBoxLayout(self.param_filter_container)
        filter_row.setSpacing(6)
        filter_row.setContentsMargins(8, 2, 8, 2)
        
        # Auto-analyze checkbox
        self.auto_analyze = QCheckBox("↺ Auto")
        self.auto_analyze.setChecked(True)
        self.auto_analyze.setToolTip("Automatically analyze when request is selected")
        filter_row.addWidget(self.auto_analyze)
        
        # Add separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet("background-color: #555;")
        sep1.setMaximumWidth(1)
        filter_row.addWidget(sep1)
        
        # Filter label
        filter_label = QLabel("Show:")
        filter_label.setStyleSheet(f"color: {COLORS.get('text_muted', '#888888')};")
        filter_row.addWidget(filter_label)
        
        # Compact filter checkboxes - Updated for current locations
        # Note: JS / DOM findings moved to the ⚡ JS / DOM tab — no checkbox needed here.
        self.filter_url = QCheckBox("URL")
        self.filter_url.setChecked(True)
        self.filter_url.stateChanged.connect(self.filter_parameters_by_checkbox)
        filter_row.addWidget(self.filter_url)

        # HDR (Security Headers) → shown in dedicated Headers tab — no checkbox needed
        # COOK (Cookie Security) → shown in dedicated Cookies tab — no checkbox needed
        # JS / DOM sinks     → shown in dedicated ⚡ JS / DOM tab — no checkbox needed

        self.filter_body = QCheckBox("Body")
        self.filter_body.setChecked(True)
        self.filter_body.stateChanged.connect(self.filter_parameters_by_checkbox)
        filter_row.addWidget(self.filter_body)
        
        self.filter_json = QCheckBox("JSON")
        self.filter_json.setChecked(True)
        self.filter_json.stateChanged.connect(self.filter_parameters_by_checkbox)
        filter_row.addWidget(self.filter_json)
        
        self.filter_html = QCheckBox("HTML")
        self.filter_html.setChecked(True)
        self.filter_html.stateChanged.connect(self.filter_parameters_by_checkbox)
        filter_row.addWidget(self.filter_html)
        
        self.filter_response = QCheckBox("RESP")
        self.filter_response.setChecked(True)
        self.filter_response.stateChanged.connect(self.filter_parameters_by_checkbox)
        filter_row.addWidget(self.filter_response)
        
        filter_row.addStretch()
        
        # "All" checkbox
        self.filter_all = QCheckBox("All")
        self.filter_all.setChecked(True)
        self.filter_all.stateChanged.connect(self.toggle_all_filters)
        filter_row.addWidget(self.filter_all)
        
        layout.addWidget(self.param_filter_container)
        
        # ==================== MAXIMIZED PARAMETER TABLE ====================
        _accent = COLORS.get('accent_green', '#6A8759')
        self.param_table = QTableWidget()
        self.param_table.setColumnCount(6)
        self.param_table.setHorizontalHeaderLabels([
            "Location", "Parameter", "Value", "Risk", "Vulnerabilities", "Metadata"
        ])
        self._setup_table_double_click_copy(self.param_table)
        _phdr = self.param_table.horizontalHeader()
        _phdr.setStretchLastSection(False)
        _phdr.setMinimumSectionSize(38)
        _phdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        _phdr.setHighlightSections(False)
        # Column resize modes:
        #   0 Location    — ResizeToContents (short badge: URL / BODY / JSON …)
        #   1 Parameter   — Interactive, capped after populate so long names don't dominate
        #   2 Value       — Interactive, reasonable default
        #   3 Risk        — ResizeToContents (HIGH / MEDIUM / LOW / INFO)
        #   4 Vulnerabilities — Interactive
        #   5 Metadata    — Stretch (fills remaining space)
        _phdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        _phdr.setSectionResizeMode(1, QHeaderView.Interactive)
        _phdr.setSectionResizeMode(2, QHeaderView.Interactive)
        _phdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        _phdr.setSectionResizeMode(4, QHeaderView.Interactive)
        _phdr.setSectionResizeMode(5, QHeaderView.Stretch)
        self.param_table.setColumnWidth(1, 160)
        self.param_table.setColumnWidth(2, 130)
        self.param_table.setColumnWidth(4, 185)
        self.param_table.setAlternatingRowColors(True)
        self.param_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.param_table.setSelectionMode(QTableWidget.SingleSelection)
        self.param_table.setWordWrap(False)
        self.param_table.setShowGrid(True)
        bg     = COLORS.get('bg_dark',    '#2B2B2B')
        bg_alt = COLORS.get('bg_lighter', '#323232')
        bg_hdr = COLORS.get('bg_darker',  '#1E1E1E')
        fg     = COLORS.get('text_normal','#BBBBBB')
        fg_hdr = COLORS.get('text_bright','#FFFFFF')
        self.param_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {bg};
                color: {fg};
                gridline-color: #333333;
                border: none;
                selection-background-color: {_accent};
                selection-color: #ffffff;
                outline: none;
            }}
            QTableWidget::item {{
                padding: 3px 7px;
                border: none;
            }}
            QTableWidget::item:alternate {{
                background-color: {bg_alt};
            }}
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {{
                background-color: {_accent};
                color: #ffffff;
            }}
            QHeaderView::section {{
                background-color: {bg_hdr};
                color: {fg_hdr};
                padding: 3px 8px;
                border: none;
                border-bottom: 2px solid {_accent};
                border-right: 1px solid #3d3d3d;
                font-weight: bold;
                font-size: 11px;
                letter-spacing: 0.3px;
            }}
            QHeaderView::section:last {{
                border-right: none;
            }}
        """)

        self.param_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.param_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.param_table.customContextMenuRequested.connect(self.show_param_table_context_menu)
        self.param_table.verticalHeader().setDefaultSectionSize(24)
        self.param_table.verticalHeader().hide()

        layout.addWidget(self.param_table)

        group.setLayout(layout)
        return group

    # =========================================================================
    # NEW SECURITY PANELS
    # =========================================================================

    def _make_panel_table(self, headers: list, accent_color: str = '#6A8759') -> QWidget:
        """Factory: returns a QWidget with a styled QTableWidget inside."""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        tbl = QTableWidget()
        tbl.setColumnCount(len(headers))
        tbl.setHorizontalHeaderLabels(headers)
        # Each panel sets its own per-column resize modes — no global stretch here
        hdr = tbl.horizontalHeader()
        hdr.setStretchLastSection(False)
        hdr.setMinimumSectionSize(38)          # badge columns never collapse below 38 px
        hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hdr.setHighlightSections(False)        # no bold-on-click for header
        tbl.setAlternatingRowColors(True)
        tbl.setSelectionBehavior(QTableWidget.SelectRows)
        tbl.setSelectionMode(QTableWidget.SingleSelection)
        tbl.verticalHeader().setDefaultSectionSize(24)
        tbl.verticalHeader().hide()
        tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        tbl.setShowGrid(True)
        tbl.setWordWrap(False)
        bg      = COLORS.get('bg_dark',    '#2B2B2B')
        bg_alt  = COLORS.get('bg_lighter', '#323232')
        bg_hdr  = COLORS.get('bg_darker',  '#1E1E1E')
        fg      = COLORS.get('text_normal','#BBBBBB')
        fg_hdr  = COLORS.get('text_bright','#FFFFFF')
        tbl.setStyleSheet(f"""
            QTableWidget {{
                background-color: {bg};
                color: {fg};
                gridline-color: #333333;
                border: none;
                selection-background-color: {accent_color};
                selection-color: #ffffff;
                outline: none;
            }}
            QTableWidget::item {{
                padding: 3px 7px;
                border: none;
            }}
            QTableWidget::item:alternate {{
                background-color: {bg_alt};
            }}
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {{
                background-color: {accent_color};
                color: #ffffff;
            }}
            QHeaderView::section {{
                background-color: {bg_hdr};
                color: {fg_hdr};
                padding: 3px 8px;
                border: none;
                border-bottom: 2px solid {accent_color};
                border-right: 1px solid #3d3d3d;
                font-weight: bold;
                font-size: 11px;
                letter-spacing: 0.3px;
            }}
            QHeaderView::section:last {{
                border-right: none;
            }}
            QTableCornerButton::section {{
                background-color: {bg_hdr};
                border: none;
            }}
        """)
        layout.addWidget(tbl)
        
        # Enable double-click copy on this table
        self._setup_table_double_click_copy(tbl)
        
        return container, tbl

    def _create_security_headers_panel(self) -> QWidget:
        """Panel: shows all important security headers with present/missing/misconfigured status."""
        container, tbl = self._make_panel_table(
            ["Header", "Value", "Status", "Risk", "Description"],
            accent_color='#5a7d5a'
        )
        self.sec_headers_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive);  tbl.setColumnWidth(0, 185)  # Header
        hdr.setSectionResizeMode(1, QHeaderView.Interactive);  tbl.setColumnWidth(1, 195)  # Value
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)                           # Status
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)                           # Risk
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Description
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        # populate with empty/placeholder rows so table is self-documenting
        self._populate_security_headers_table({})
        return container

    def _create_cookie_panel(self) -> QWidget:
        """Panel: request Cookie header + response Set-Cookie headers with security flag analysis."""
        container, tbl = self._make_panel_table(
            ["Src", "Cookie Name", "Value", "Secure", "HttpOnly", "SameSite", "Type", "Issues"],
            accent_color='#7a5c3a'
        )
        self.cookie_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)                           # Src
        hdr.setSectionResizeMode(1, QHeaderView.Interactive);  tbl.setColumnWidth(1, 148)  # Cookie Name
        hdr.setSectionResizeMode(2, QHeaderView.Interactive);  tbl.setColumnWidth(2, 100)  # Value
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)                           # Secure
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)                           # HttpOnly
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)                           # SameSite
        hdr.setSectionResizeMode(6, QHeaderView.ResizeToContents)                           # Type
        hdr.setSectionResizeMode(7, QHeaderView.Stretch)                                    # Issues
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_cors_panel(self) -> QWidget:
        """Panel: shows CORS findings extracted from the analysis results."""
        container, tbl = self._make_panel_table(
            ["Severity", "Indicator", "Header", "Value", "Risk Description"],
            accent_color='#6b4a8a'
        )
        self.cors_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)                           # Severity
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Indicator
        hdr.setSectionResizeMode(2, QHeaderView.Interactive);  tbl.setColumnWidth(2, 220)  # Header
        hdr.setSectionResizeMode(3, QHeaderView.Interactive);  tbl.setColumnWidth(3, 165)  # Value
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Risk Description
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_tech_stack_panel(self) -> QWidget:
        """Panel: shows detected technologies, frameworks, CDN/WAF, and server info."""
        container, tbl = self._make_panel_table(
            ["Technology", "Category", "Evidence"],
            accent_color='#3a6a8a'
        )
        self.tech_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive);  tbl.setColumnWidth(0, 160)  # Technology
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Category
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)                                    # Evidence
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_jwt_panel(self) -> QWidget:
        """Panel: JWT deep analysis — algorithm, expiry, sensitive claims, signature status."""
        container, tbl = self._make_panel_table(
            ["Token (prefix)", "Algorithm", "Signature", "Expiry", "Findings / Claims"],
            accent_color='#4a6fa5'
        )
        self.jwt_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive);  tbl.setColumnWidth(0, 155)  # Token (prefix)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Algorithm
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)                           # Signature
        hdr.setSectionResizeMode(3, QHeaderView.Interactive);  tbl.setColumnWidth(3, 170)  # Expiry
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Findings / Claims
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_cache_panel(self) -> QWidget:
        """Panel: cache poisoning indicator analysis."""
        container, tbl = self._make_panel_table(
            ["Severity", "Indicator", "Header / Input", "Value", "Description"],
            accent_color='#8a5a2a'
        )
        self.cache_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)                           # Severity
        hdr.setSectionResizeMode(1, QHeaderView.Interactive);  tbl.setColumnWidth(1, 180)  # Indicator
        hdr.setSectionResizeMode(2, QHeaderView.Interactive);  tbl.setColumnWidth(2, 165)  # Header / Input
        hdr.setSectionResizeMode(3, QHeaderView.Interactive);  tbl.setColumnWidth(3, 125)  # Value
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Description
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_endpoints_panel(self) -> QWidget:
        """Panel: endpoints discovered in HTML attributes and inline JS."""
        container, tbl = self._make_panel_table(
            ["Path", "Type", "Original URL", "Risk"],
            accent_color='#2a6a4a'
        )
        self.endpoints_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive);  tbl.setColumnWidth(0, 225)  # Path
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Type
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)                                    # Original URL
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)                           # Risk
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_weird_panel(self) -> QWidget:
        """Panel: anomalous / weird signals — protocol violations, encoding oddities, logic issues."""
        container, tbl = self._make_panel_table(
            ["Severity", "Category", "Title", "Detail", "Evidence"],
            accent_color='#7a4a7a'
        )
        self.weird_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)                           # Severity
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Category
        hdr.setSectionResizeMode(2, QHeaderView.Interactive);  tbl.setColumnWidth(2, 215)  # Title
        hdr.setSectionResizeMode(3, QHeaderView.Interactive);  tbl.setColumnWidth(3, 245)  # Detail
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Evidence
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    def _create_js_dom_panel(self) -> QWidget:
        """Panel: JavaScript and DOM-based findings (sinks, open redirects, secrets, WebSocket, GraphQL)."""
        container, tbl = self._make_panel_table(
            ["Severity", "Vuln Type", "JS Type", "Sink / Name", "Context / Code"],
            accent_color='#4a7aab'
        )
        self.js_dom_table = tbl
        hdr = tbl.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)                           # Severity
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)                           # Vuln Type
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)                           # JS Type
        hdr.setSectionResizeMode(3, QHeaderView.Interactive);  tbl.setColumnWidth(3, 205)  # Sink / Name
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)                                    # Context / Code
        tbl.setContextMenuPolicy(Qt.CustomContextMenu)
        tbl.customContextMenuRequested.connect(
            lambda pos, t=tbl: self._show_table_context_menu(pos, t))
        return container

    # Prefixes that route a params key to the JS/DOM tab
    _JS_DOM_KEY_PREFIXES = (
        'INLINE_DOM ', 'INLINE_SECRET ',
        'JS OPEN_REDIRECT', 'JS WEBSOCKET', 'JS POSTMESSAGE',
        'JS TOKEN_STORAGE', 'JS LOCALSTORAGE', 'JS SOURCE_MAP',
        'JS GRAPHQL_', 'JS GRAPHQL ',
    )

    def _populate_js_dom_table(self, results: dict):
        """Populate the JS/DOM tab from results['params'] entries whose key matches JS/DOM prefixes."""
        tbl = self.js_dom_table
        tbl.setRowCount(0)

        params = results.get('params', {})

        # Collect relevant entries
        entries = [
            (k, v) for k, v in params.items()
            if any(k.startswith(p) for p in self._JS_DOM_KEY_PREFIXES)
        ]

        if not entries:
            tbl.insertRow(0)
            item = QTableWidgetItem('No JS / DOM issues detected')
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        # Determine display type/name from key prefix
        # Map key prefix → (display vuln_type fallback, display js_type fallback)
        _PREFIX_META = [
            ('INLINE_DOM ',       None,             'DOM Sink'),
            ('INLINE_SECRET ',    'SECRET',         'Inline JS'),
            ('JS OPEN_REDIRECT',  'OPEN_REDIRECT',  'JS'),
            ('JS WEBSOCKET',      'WEBSOCKET',      'JS'),
            ('JS POSTMESSAGE',    'POSTMESSAGE',    'JS'),
            ('JS TOKEN_STORAGE',  'AUTH_STORAGE',   'JS'),
            ('JS LOCALSTORAGE',   'AUTH_STORAGE',   'JS'),
            ('JS SOURCE_MAP',     'SOURCE_MAP',     'JS'),
            ('JS GRAPHQL_',       'GRAPHQL',        'JS'),
            ('JS GRAPHQL ',       'GRAPHQL',        'JS'),
        ]

        _risk_ord = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}

        def _sev_from_tags(tags):
            for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
                if lvl in tags:
                    return lvl
            return 'INFO'

        def _tag_value(tags, prefix):
            for t in tags:
                if isinstance(t, str) and t.startswith(prefix):
                    return t[len(prefix):]
            return ''

        entries.sort(key=lambda kv: _risk_ord.get(_sev_from_tags(kv[1]), 5))

        for key, tags in entries:
            sev = _sev_from_tags(tags)

            # Resolve vuln_type and js_type
            vuln_type_fallback = 'DOM_SINK'
            js_type_fallback   = 'JavaScript'
            for prefix, vt, jt in _PREFIX_META:
                if key.startswith(prefix):
                    vuln_type_fallback = vt or vuln_type_fallback
                    js_type_fallback   = jt
                    break

            # Prefer explicit VULN: tag from the params dict (set by _detect_dom_sinks)
            vuln_type = _tag_value(tags, 'VULN:') or vuln_type_fallback
            js_type   = _tag_value(tags, 'TYPE:') or js_type_fallback

            # The part after the prefix is the sink/name
            name = key
            for prefix, _, _ in _PREFIX_META:
                if key.startswith(prefix):
                    name = key[len(prefix):].strip()
                    break

            # Code/context snippet
            code = _tag_value(tags, 'CODE:')

            row = tbl.rowCount()
            tbl.insertRow(row)

            sev_col = self._SEVERITY_COLORS.get(sev, '#BBBBBB')
            tbl.setItem(row, 0, self._color_item(sev, sev_col))

            vt_item = QTableWidgetItem(vuln_type)
            vt_item.setForeground(QColor({
                'XSS':               '#e05252',
                'OPEN_REDIRECT':     '#e07a27',
                'SSRF':              '#e07a27',
                'RCE':               '#c0392b',
                'PROTOTYPE_POLLUTION': '#9b59b6',
                'XXE':               '#d35400',
                'SSTI':              '#c0392b',
                'IDOR':              '#2980b9',
                'AUTH_STORAGE':      '#f39c12',
                'GRAPHQL':           '#1abc9c',
                'WEBSOCKET':         '#1abc9c',
                'SECRET':            '#e74c3c',
            }.get(vuln_type, '#BBBBBB')))
            tbl.setItem(row, 1, vt_item)

            tbl.setItem(row, 2, QTableWidgetItem(js_type))

            name_item = QTableWidgetItem(name)
            name_item.setToolTip(key)
            tbl.setItem(row, 3, name_item)

            code_preview = (code[:110] + '…') if len(code) > 110 else code
            code_item = QTableWidgetItem(code_preview)
            code_item.setToolTip(code)
            tbl.setItem(row, 4, code_item)

            # Tint critical/high rows
            if sev == 'CRITICAL':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 0, 0, 50))
            elif sev == 'HIGH':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 30, 0, 40))

    def _populate_weird_table(self, results: dict):
        """Populate the Weird tab from results['weird'] list."""
        tbl = self.weird_table
        tbl.setRowCount(0)

        weird = results.get('weird', [])
        if not weird:
            tbl.insertRow(0)
            item = QTableWidgetItem('No anomalies detected')
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        _risk_ord = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        sorted_weird = sorted(weird, key=lambda w: _risk_ord.get(w.get('severity', 'INFO'), 5))

        for w in sorted_weird:
            sev      = w.get('severity', 'INFO')
            category = w.get('category', '')
            title    = w.get('title', '')
            detail   = w.get('detail', '')
            evidence = w.get('evidence', '')

            row = tbl.rowCount()
            tbl.insertRow(row)

            sev_col = self._SEVERITY_COLORS.get(sev, '#BBBBBB')
            tbl.setItem(row, 0, self._color_item(sev, sev_col))
            tbl.setItem(row, 1, QTableWidgetItem(category))

            title_item = QTableWidgetItem(title)
            title_item.setToolTip(title)
            tbl.setItem(row, 2, title_item)

            detail_preview = (detail[:100] + '…') if len(detail) > 100 else detail
            detail_item = QTableWidgetItem(detail_preview)
            detail_item.setToolTip(detail)
            tbl.setItem(row, 3, detail_item)

            ev_preview = (evidence[:80] + '…') if len(evidence) > 80 else evidence
            ev_item = QTableWidgetItem(ev_preview)
            ev_item.setToolTip(evidence)
            tbl.setItem(row, 4, ev_item)

            # Row background tint for critical/high
            if sev == 'CRITICAL':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 0, 0, 50))
            elif sev == 'HIGH':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 30, 0, 40))

    # ── Panel population helpers ─────────────────────────────────────────────

    # Known security headers manifest: (header, display_name, description, ideal_value, severity_if_missing)
    _SEC_HEADERS_MANIFEST = [
        ('Content-Security-Policy',        'CSP',          'Prevents XSS & injection',         "default-src 'self'",               'HIGH'),
        ('Strict-Transport-Security',      'HSTS',         'Forces HTTPS connections',          'max-age=31536000; includeSubDomains', 'HIGH'),
        ('X-Frame-Options',                'Clickjacking', 'Prevents iframe embedding',         'DENY or SAMEORIGIN',               'MEDIUM'),
        ('X-Content-Type-Options',         'MIME Sniff',   'Prevents MIME-type confusion',      'nosniff',                          'MEDIUM'),
        ('Referrer-Policy',                'Referrer',     'Controls referrer information',     'strict-origin-when-cross-origin',  'LOW'),
        ('Permissions-Policy',             'Feat. Policy', 'Controls browser feature access',   'camera=(), microphone=()',         'LOW'),
        ('Cross-Origin-Opener-Policy',     'COOP',         'Isolates browsing context group',   'same-origin',                      'LOW'),
        ('Cross-Origin-Resource-Policy',   'CORP',         'Restricts cross-origin loading',    'same-origin',                      'LOW'),
        ('Cross-Origin-Embedder-Policy',   'COEP',         'Requires CORP on sub-resources',    'require-corp',                     'LOW'),
    ]

    _SEVERITY_COLORS = {
        'CRITICAL': '#c0392b',
        'HIGH':     '#e67e22',
        'MEDIUM':   '#f1c40f',
        'LOW':      '#3498db',
        'INFO':     '#7f8c8d',
        'OK':       '#27ae60',
    }

    def _color_item(self, text: str, color: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setForeground(QColor(color))
        item.setFlags(item.flags() & ~Qt.ItemIsEditable)
        return item

    def _populate_security_headers_table(self, resp_headers: dict):
        """Fill the security headers table given a {header_name: value} dict."""
        tbl = self.sec_headers_table
        tbl.setRowCount(0)
        h_lower = {k.lower(): v for k, v in resp_headers.items()}

        for header, display, desc, ideal, sev_missing in self._SEC_HEADERS_MANIFEST:
            row = tbl.rowCount()
            tbl.insertRow(row)
            value = h_lower.get(header.lower(), '')

            if not value:
                status_txt = '✗ Missing'
                status_col = self._SEVERITY_COLORS.get(sev_missing, '#7f8c8d')
                risk_txt   = sev_missing
                risk_col   = status_col
            else:
                # Check for common misconfigurations
                val_lower = value.lower()
                issues = []
                if header == 'Content-Security-Policy':
                    if 'unsafe-inline' in val_lower:
                        issues.append("unsafe-inline")
                    if 'unsafe-eval' in val_lower:
                        issues.append("unsafe-eval")
                    if val_lower.strip() in ("*", "default-src *"):
                        issues.append("wildcard")
                elif header == 'Strict-Transport-Security':
                    m = re.search(r'max-age=(\d+)', val_lower)
                    if m and int(m.group(1)) < 15768000:
                        issues.append("max-age too short")
                elif header == 'X-Frame-Options':
                    if val_lower not in ('deny', 'sameorigin'):
                        issues.append(f"non-standard value: {value}")
                elif header == 'X-Content-Type-Options':
                    if val_lower != 'nosniff':
                        issues.append(f"value should be 'nosniff'")

                if issues:
                    status_txt = '△ Weak'
                    status_col = self._SEVERITY_COLORS['MEDIUM']
                    risk_txt   = 'MEDIUM'
                    risk_col   = status_col
                else:
                    status_txt = '✓ Present'
                    status_col = self._SEVERITY_COLORS['OK']
                    risk_txt   = 'OK'
                    risk_col   = status_col

            tbl.setItem(row, 0, QTableWidgetItem(f"{display} ({header})"))
            val_item = QTableWidgetItem(value[:80] + ('…' if len(value) > 80 else '') if value else f'— hint: {ideal}')
            if not value:
                val_item.setForeground(QColor('#666666'))
            tbl.setItem(row, 1, val_item)
            tbl.setItem(row, 2, self._color_item(status_txt, status_col))
            tbl.setItem(row, 3, self._color_item(risk_txt, risk_col))
            tbl.setItem(row, 4, QTableWidgetItem(desc))

    def _populate_cookie_table(self, cookie_entries: list):
        """Fill the cookie security table (request Cookie + response Set-Cookie)."""
        tbl = self.cookie_table
        tbl.setRowCount(0)
        if not cookie_entries:
            tbl.insertRow(0)
            item = QTableWidgetItem("No cookies found in request or response")
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        for entry in cookie_entries:
            row = tbl.rowCount()
            tbl.insertRow(row)

            is_req = entry.get('source', 'RESP') == 'REQ'

            # col 0 — Src badge
            src_item = self._color_item(
                '→ REQ' if is_req else '← RESP',
                '#6ab0de' if is_req else '#a0c88a'
            )
            tbl.setItem(row, 0, src_item)

            tbl.setItem(row, 1, QTableWidgetItem(entry.get('name', '?')))
            tbl.setItem(row, 2, QTableWidgetItem(entry.get('value', '')))

            if is_req:
                # Security flags are unknown for cookies sent in the request
                for c in (3, 4, 5, 6):
                    tbl.setItem(row, c, self._color_item('—', '#555555'))
                tbl.setItem(row, 7, self._color_item('Sent in request', '#6ab0de'))
            else:
                secure_ok = entry.get('secure', False)
                tbl.setItem(row, 3, self._color_item(
                    '✓' if secure_ok else '✗',
                    self._SEVERITY_COLORS['OK'] if secure_ok else self._SEVERITY_COLORS['HIGH']
                ))

                httponly_ok = entry.get('httponly', False)
                tbl.setItem(row, 4, self._color_item(
                    '✓' if httponly_ok else '✗',
                    self._SEVERITY_COLORS['OK'] if httponly_ok else self._SEVERITY_COLORS['MEDIUM']
                ))

                ss = entry.get('samesite', '—')
                ss_col = (self._SEVERITY_COLORS['OK'] if ss.lower() in ('strict', 'lax')
                          else self._SEVERITY_COLORS['MEDIUM'] if ss.lower() == 'none'
                          else self._SEVERITY_COLORS['MEDIUM'] if ss == '—'
                          else '#BBBBBB')
                tbl.setItem(row, 5, self._color_item(ss, ss_col))

                typ = '○ Session' if entry.get('is_session') else '· Persistent'
                tbl.setItem(row, 6, QTableWidgetItem(typ))

                issues = entry.get('issues', [])
                if issues:
                    issues_str = '; '.join(f"{i[0]}({i[1]})" for i in issues)
                    worst_sev  = max((i[1] for i in issues), key=lambda s: {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1,'INFO':0}.get(s, 0))
                    tbl.setItem(row, 7, self._color_item(issues_str, self._SEVERITY_COLORS.get(worst_sev, '#BBBBBB')))
                else:
                    tbl.setItem(row, 7, self._color_item('✓ OK', self._SEVERITY_COLORS['OK']))

                # Row tint by worst issue
                if issues:
                    worst = max((i[1] for i in issues), key=lambda s: {'CRITICAL':4,'HIGH':3,'MEDIUM':2,'LOW':1}.get(s, 0))
                    tint = {'HIGH': QColor(80, 30, 10, 40), 'MEDIUM': QColor(80, 70, 0, 30), 'CRITICAL': QColor(100, 0, 0, 50)}.get(worst)
                    if tint:
                        for c in range(tbl.columnCount()):
                            it = tbl.item(row, c)
                            if it:
                                it.setBackground(tint)

    def _populate_cors_table(self, results: dict):
        """Fill the CORS table.

        Two sources combined:
        1. Direct scan of response_headers for any CORS-related header (always
           shown, even when no Origin was sent in the request).
        2. Risk-assessment entries produced by analyze_cors_headers() and stored
           under HEADER CORS:* / HEADER CORS_* keys in results['params'].
        """
        tbl = self.cors_table
        tbl.setRowCount(0)

        # ── CORS headers we recognize + per-value risk rules ────────────────
        CORS_HEADERS = {
            'access-control-allow-origin': 'Access-Control-Allow-Origin',
            'access-control-allow-credentials': 'Access-Control-Allow-Credentials',
            'access-control-allow-methods': 'Access-Control-Allow-Methods',
            'access-control-allow-headers': 'Access-Control-Allow-Headers',
            'access-control-expose-headers': 'Access-Control-Expose-Headers',
            'access-control-max-age': 'Access-Control-Max-Age',
            'access-control-request-method': 'Access-Control-Request-Method',
            'access-control-request-headers': 'Access-Control-Request-Headers',
            'vary': 'Vary',
        }

        def _cors_risk(name_lower: str, value: str):
            """Return (severity, risk_description) for a CORS header value."""
            v = value.strip()
            vl = v.lower()
            if name_lower == 'access-control-allow-origin':
                if v == '*':
                    return 'HIGH', 'Wildcard – any origin can read the response'
                if vl == 'null':
                    return 'HIGH', 'Null origin – sandboxed iframes can exploit this'
                return 'INFO', f'Specific origin whitelisted: {v}'
            if name_lower == 'access-control-allow-credentials':
                if vl == 'true':
                    return 'HIGH', 'Credentials (cookies/auth) sent cross-origin – check ACAO'
                return 'INFO', 'Credentials not forwarded'
            if name_lower == 'access-control-allow-methods':
                dangerous = [m for m in ['DELETE', 'PUT', 'PATCH'] if m in v.upper()]
                if dangerous:
                    return 'MEDIUM', f'Dangerous methods allowed: {", ".join(dangerous)}'
                return 'INFO', f'Methods: {v}'
            if name_lower == 'access-control-allow-headers':
                sensitive = [h for h in ['authorization', 'cookie', 'x-api-key'] if h in vl]
                if sensitive:
                    return 'MEDIUM', f'Sensitive headers exposed: {", ".join(sensitive)}'
                return 'INFO', f'Allowed headers: {v[:60]}'
            if name_lower == 'vary':
                if 'origin' in vl:
                    return 'INFO', 'Vary: Origin present – server is origin-aware'
                return None, None  # not CORS-relevant
            return 'INFO', v[:80]

        cors_rows = []  # (severity, source_label, header_display, value, risk)

        # ── SOURCE 1: direct header scan ─────────────────────────────────
        resp_headers = results.get('response_headers', {})

        # Regex fallback: if resp_headers is empty, scan the raw response text
        # (guards against any edge-case in _parse_headers)
        if not resp_headers:
            raw_text = results.get('_response_text', '')
            if raw_text:
                # Only look at the header section (before blank line)
                raw_norm = raw_text.replace('\r\n', '\n').replace('\r', '\n')
                hdr_block = raw_norm.split('\n\n', 1)[0] if '\n\n' in raw_norm else raw_norm
                for line in hdr_block.split('\n'):
                    line = line.strip()
                    if ':' in line and not line.startswith('HTTP/'):
                        k, _, v = line.partition(':')
                        resp_headers[k.strip()] = v.strip()

        hdrs_lower = {k.lower(): (k, v) for k, v in resp_headers.items()}
        for name_lower, display_name in CORS_HEADERS.items():
            if name_lower not in hdrs_lower:
                continue
            orig_key, value = hdrs_lower[name_lower]
            severity, risk = _cors_risk(name_lower, value)
            if severity is None:
                continue  # Skip Vary without Origin
            cors_rows.append((severity, '◎ Header', display_name, value, risk))

        # ── SOURCE 2: analysis engine entries (HEADER CORS:* / HEADER CORS_*) ──
        params = results.get('params', {})
        seen_indicators = set()
        for key, data in params.items():
            if not key.startswith('HEADER '):
                continue
            suffix = key[7:]
            if not (suffix.startswith('CORS:') or suffix.startswith('CORS_')):
                continue
            indicator = suffix
            severity = 'INFO'
            header   = ''
            value    = ''
            risk     = ''
            if isinstance(data, (list, tuple)):
                for token in data:
                    t = str(token)
                    if t in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'):
                        severity = t
                    elif t.startswith('HEADER:'):
                        header = t[7:]
                    elif t.startswith('VALUE:'):
                        value = t[6:]
                    elif t.startswith('RISK:'):
                        risk = t[5:]
            # Avoid duplicating what source-1 already shows
            dedup_key = (header.lower(), value[:30])
            if dedup_key in seen_indicators:
                continue
            seen_indicators.add(dedup_key)
            cors_rows.append((severity, '⊙ Analysis', header or indicator, value, risk))

        if not cors_rows:
            tbl.insertRow(0)
            item = QTableWidgetItem("No CORS headers found in response")
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        # Sort: source-1 first, then by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        cors_rows.sort(key=lambda r: (0 if r[1] == '◎ Header' else 1, sev_order.get(r[0], 5)))

        for severity, source, header, value, risk in cors_rows:
            row = tbl.rowCount()
            tbl.insertRow(row)
            sev_col = self._SEVERITY_COLORS.get(severity, '#BBBBBB')
            tbl.setItem(row, 0, self._color_item(severity, sev_col))
            ind_item = QTableWidgetItem(source)
            ind_item.setForeground(QColor('#888888' if source == '⊙ Analysis' else '#aaaaaa'))
            tbl.setItem(row, 1, ind_item)
            tbl.setItem(row, 2, QTableWidgetItem(header))
            val_preview = (value[:60] + '…') if len(value) > 60 else value
            val_item = QTableWidgetItem(val_preview)
            val_item.setToolTip(value)
            tbl.setItem(row, 3, val_item)
            tbl.setItem(row, 4, QTableWidgetItem(risk))
            # Row background tint for high/critical
            if severity in ('CRITICAL', 'HIGH'):
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 20, 20, 50))

    def _populate_tech_table(self, tech_stack: dict):
        """Fill the technology stack table from _analyze_tech_stack results."""
        tbl = self.tech_table
        tbl.setRowCount(0)
        if not tech_stack:
            tbl.insertRow(0)
            item = QTableWidgetItem("No technologies detected")
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        category_map = {
            'Server':          'Server', 'X-Powered-By': 'Server', 'ASP.NET': 'Server',
            'Cloudflare':      'CDN/WAF', 'AWS CloudFront': 'CDN', 'AWS CloudFront PoP': 'CDN',
            'Azure CDN':       'CDN', 'Varnish Cache': 'Cache', 'Caching Proxy': 'Cache',
            'Akamai CDN':      'CDN', 'Sucuri WAF': 'WAF', 'Fastly CDN': 'CDN',
            'Generic CDN':     'CDN', 'Server Timing (perf leak)': 'Info Leak',
            'AngularJS':       'JS Framework', 'React': 'JS Framework', 'Vue.js': 'JS Framework',
            'jQuery':          'JS Library', 'Backbone.js': 'JS Framework',
            'Ember.js':        'JS Framework', 'Alpine.js': 'JS Framework', 'Svelte': 'JS Framework',
            'PHP Session':     'Backend', 'ASP.NET Session': 'Backend',
            'Java/JVM App Server': 'Backend', 'Laravel Framework': 'Backend',
            'CodeIgniter Framework': 'Backend', 'Ruby on Rails': 'Backend',
        }

        # Sort: Server first, then alphabetical
        def sort_key(item):
            cat = category_map.get(item[0], 'Other')
            order = {'Server': 0, 'Backend': 1, 'WAF': 2, 'CDN': 3, 'Cache': 4,
                     'CDN/WAF': 2, 'JS Framework': 5, 'JS Library': 6, 'Info Leak': 7, 'Other': 8}
            return (order.get(cat, 8), item[0].lower())

        for name, evidence_list in sorted(tech_stack.items(), key=sort_key):
            row = tbl.rowCount()
            tbl.insertRow(row)
            cat = category_map.get(name, 'Other')
            tbl.setItem(row, 0, QTableWidgetItem(name))
            cat_item = QTableWidgetItem(cat)
            cat_colors = {
                'Server': '#e67e22', 'Backend': '#e67e22', 'WAF': '#c0392b',
                'CDN': '#3498db', 'CDN/WAF': '#c0392b', 'Cache': '#16a085',
                'JS Framework': '#8e44ad', 'JS Library': '#8e44ad',
                'Info Leak': '#c0392b', 'Other': '#888888',
            }
            cat_item.setForeground(QColor(cat_colors.get(cat, '#888888')))
            tbl.setItem(row, 1, cat_item)
            evidence_str = '; '.join(str(e) for e in evidence_list[:5])
            tbl.setItem(row, 2, QTableWidgetItem(evidence_str))

    def _populate_jwt_table(self, results: dict):
        """Parse every JWT in request+response; show algorithm, expiry, sensitive claims."""
        tbl = self.jwt_table
        tbl.setRowCount(0)

        combined = ((results.get('_response_text') or '') + '\n' +
                    (results.get('_request_text') or ''))
        jwt_re = re.compile(
            r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*'
        )
        tokens = list(dict.fromkeys(jwt_re.findall(combined)))[:20]

        if not tokens:
            tbl.insertRow(0)
            item = QTableWidgetItem("No JWT tokens found in request or response")
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        now = _time_mod.time()

        def _b64d(segment: str) -> dict:
            """URL-safe base64-decode a JWT segment and JSON-parse it."""
            s = segment.replace('-', '+').replace('_', '/')
            s += '=' * (-len(s) % 4)
            try:
                return json.loads(base64.b64decode(s).decode('utf-8', errors='replace'))
            except Exception:
                return {}

        for token in tokens:
            parts = token.split('.')
            if len(parts) < 2:
                continue

            header  = _b64d(parts[0])
            payload = _b64d(parts[1])
            has_sig = len(parts) == 3 and bool(parts[2])

            alg    = header.get('alg', '?')
            issues = []

            if alg.lower() == 'none':
                issues.append('\u26d4 alg:none \u2014 signature bypassed!')
            elif alg.upper() in ('HS256', 'HS384', 'HS512'):
                issues.append('\U0001f511 HMAC \u2014 secret may be brute-forced')
            elif alg.upper() in ('RS256', 'RS384', 'RS512',
                                  'ES256', 'ES384', 'ES512',
                                  'PS256', 'PS384', 'PS512'):
                issues.append(f'\u26a0\ufe0f Asymmetric ({alg}) \u2014 test RS256\u2192HS256 confusion (use public key as HMAC secret)')
            if not has_sig:
                issues.append('\u26a0\ufe0f Missing signature segment')

            exp = payload.get('exp')
            iat = payload.get('iat')
            if exp:
                if now > exp:
                    dt_str = f'\u274c Expired {int((now - exp) // 60)}m ago'
                else:
                    dt_str = f'\u2705 Valid \u2014 {int((exp - now) // 60)}m left'
            elif iat:
                dt_str = '\u2139\ufe0f No exp (iat present)'
            else:
                dt_str = '\u2014 No exp/iat'

            _sensitive_claims = {
                'email', 'password', 'secret', 'ssn', 'role', 'admin',
                'permissions', 'groups', 'scope', 'sub', 'phone', 'dob', 'address'
            }
            found_claims = [k for k in payload if k.lower() in _sensitive_claims]
            if found_claims:
                issues.append(f'\U0001f4cb Claims: {", ".join(found_claims[:5])}')

            row = tbl.rowCount()
            tbl.insertRow(row)

            tbl.setItem(row, 0, QTableWidgetItem(token[:32] + '\u2026'))

            alg_col = (
                self._SEVERITY_COLORS['CRITICAL'] if alg.lower() == 'none'
                else self._SEVERITY_COLORS['MEDIUM'] if alg.upper().startswith('HS')
                else self._SEVERITY_COLORS['OK']
            )
            tbl.setItem(row, 1, self._color_item(alg, alg_col))

            sig_txt = '\u2705 Signed' if has_sig else '\u274c Unsigned'
            sig_col = self._SEVERITY_COLORS['OK'] if has_sig else self._SEVERITY_COLORS['CRITICAL']
            tbl.setItem(row, 2, self._color_item(sig_txt, sig_col))

            exp_col = self._SEVERITY_COLORS['HIGH'] if '\u274c' in dt_str else self._SEVERITY_COLORS['OK']
            tbl.setItem(row, 3, self._color_item(dt_str, exp_col))

            iss_txt = '  '.join(issues) if issues else '\u2705 No obvious issues'
            iss_col = (
                self._SEVERITY_COLORS['CRITICAL'] if '\u26d4' in iss_txt
                else self._SEVERITY_COLORS['HIGH']   if '\u26a0' in iss_txt
                else self._SEVERITY_COLORS['MEDIUM']  if '\U0001f511' in iss_txt
                else self._SEVERITY_COLORS['OK']
            )
            tbl.setItem(row, 4, self._color_item(iss_txt, iss_col))

            if '\u26d4' in iss_txt or not has_sig:
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(100, 0, 0, 60))

    def _populate_cache_panel(self, results: dict):
        """Analyze cache-related headers and request inputs for poisoning indicators."""
        tbl = self.cache_table
        tbl.setRowCount(0)

        resp_headers = results.get('response_headers', {})
        h = {k.lower(): v for k, v in resp_headers.items()}
        req_text = (results.get('_request_text') or '').lower()

        findings = []  # (severity, indicator, header/input, value, description)

        # CDN / proxy cache status headers
        for cdnh in ['x-cache', 'cf-cache-status', 'x-proxy-cache', 'x-varnish', 'x-cdn']:
            val = h.get(cdnh, '')
            if val:
                is_hit = 'hit' in val.lower()
                lbl = 'Cache HIT' if is_hit else 'Cache Layer'
                desc = ('HIT — cached response served; prior response may be poisoned'
                        if is_hit else 'Intermediate caching layer detected')
                findings.append(('INFO', f'\U0001f504 {lbl}', cdnh.title(), val, desc))

        # Age: how long the cached response has been stored
        age_val = h.get('age', '')
        if age_val:
            try:
                findings.append(('INFO', '\u23f1\ufe0f Cached Age', 'Age', f'{int(age_val)}s',
                                 f'Response has been cached for {int(age_val)} seconds'))
            except ValueError:
                pass

        # Via: discloses proxy/CDN
        via = h.get('via', '')
        if via:
            findings.append(('INFO', '\U0001f310 Via Proxy', 'Via', via[:60],
                             'Intermediate proxy/CDN disclosed — response may be cached there'))

        # Cache-Control analysis
        cc = h.get('cache-control', '')
        if cc:
            ccl = cc.lower()
            if 'no-store' in ccl:
                findings.append(('INFO', '\u2705 No-Store', 'Cache-Control', cc,
                                 'Not stored — low cache poisoning risk'))
            elif 'private' in ccl:
                findings.append(('INFO', '\u2705 Private', 'Cache-Control', cc,
                                 'Marked private — should not be stored by shared caches'))
            else:
                if 'public' in ccl:
                    findings.append(('HIGH', '\u26a0\ufe0f Public Cache', 'Cache-Control', cc,
                                     'Publicly cacheable — user-specific data may be poisoned into shared cache'))
                elif 'no-cache' not in ccl:
                    findings.append(('MEDIUM', '\u26a0\ufe0f Weak Control', 'Cache-Control', cc,
                                     'No strong caching restriction — poisoned response may be cached'))

        # Vary header: check for unkeyed poisoning-friendly inputs
        vary = h.get('vary', '')
        if vary:
            vl = vary.lower()
            if vary.strip() == '*':
                findings.append(('INFO', '\u2705 Vary: *', 'Vary', vary, 'Not cacheable (Vary: *)'))
            elif 'origin' in vl:
                findings.append(('INFO', '\u2139\ufe0f Vary: Origin', 'Vary', vary,
                                 'CORS-aware cache — Origin manipulation may cause cache deception'))
            unkeyed_in_req = [
                uh for uh in ['x-forwarded-host', 'x-original-url', 'x-rewrite-url', 'x-host']
                if uh in req_text
            ]
            if unkeyed_in_req and 'x-forwarded-host' not in vl and 'host' not in vl:
                findings.append(('HIGH', '\U0001f3af Unkeyed Header',
                                 f'Vary (missing: {", ".join(unkeyed_in_req)})', vary,
                                 f'Request uses {unkeyed_in_req[0]} but Vary excludes it — cache poisoning likely'))

        # Poisoning-friendly headers sent in the request
        poison_hdrs = [
            'x-forwarded-host', 'x-original-url', 'x-rewrite-url',
            'x-forwarded-prefix', 'x-host', 'x-forwarded-server'
        ]
        for ph in poison_hdrs:
            if ph in req_text:
                findings.append(('HIGH', '\U0001f3af Injection Vector', ph.title(), '(in request)',
                                 f'User-controlled header "{ph}" may influence a cacheable response'))

        if not findings:
            tbl.insertRow(0)
            item = QTableWidgetItem('No cache poisoning indicators detected')
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        findings.sort(key=lambda r: {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}.get(r[0], 3))

        for sev, indicator, header, value, desc in findings:
            row = tbl.rowCount()
            tbl.insertRow(row)
            sev_col = self._SEVERITY_COLORS.get(sev, '#BBBBBB')
            tbl.setItem(row, 0, self._color_item(sev, sev_col))
            tbl.setItem(row, 1, QTableWidgetItem(indicator))
            tbl.setItem(row, 2, QTableWidgetItem(header))
            tbl.setItem(row, 3, QTableWidgetItem(value[:60]))
            tbl.setItem(row, 4, QTableWidgetItem(desc))
            if sev == 'HIGH':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 30, 0, 50))

    @staticmethod
    def _tab_has_results(tbl) -> bool:
        """Return True if the table has real data (not just a placeholder 'No … found' row)."""
        if tbl is None or tbl.rowCount() == 0:
            return False
        first = tbl.item(0, 0)
        if first is None:
            return False
        txt = first.text().strip()
        # Placeholder rows always start with "No " (e.g. "No CORS headers found …")
        return not txt.startswith('No ')

    def _populate_endpoints_table(self, results: dict):
        """Fill the Endpoints panel from ENDPOINT * keys in results['params']."""
        tbl = self.endpoints_table
        tbl.setRowCount(0)

        # Type → (friendly label, risk)
        _type_risk = {
            'LINK':          ('⊃ Link (href)',        'INFO'),
            'FORM_ACTION':   ('· Form Action',         'MEDIUM'),
            'SCRIPT_DIR':    ('· Script Dir',          'LOW'),
            'SCRIPT':        ('· Script',              'LOW'),
            'LINK_DIR':      ('□ Link Dir',            'INFO'),
            'IMG_DIR':       ('□ Image Dir',           'INFO'),
            'IMG':           ('□ Image',               'INFO'),
            'JS_SET_HREF':   ('! JS href assign',      'MEDIUM'),
            'JS_SET_SRC':    ('! JS src assign',       'MEDIUM'),
            'JS_SET_ACTION': ('! JS action assign',    'HIGH'),
            'JS_HREF_ASSIGN':('! JS href=',            'MEDIUM'),
            'JS_REDIRECT':   ('! JS redirect',         'HIGH'),
        }

        # Sensitive path patterns → bump risk to HIGH
        _sensitive_re = re.compile(
            r'(?:admin|login|logout|signup|register|password|reset|token|auth|'
            r'internal|debug|config|backup|api/v|graphql|\.git|\.env|swagger|upload)',
            re.IGNORECASE
        )

        rows = []
        for key, data in results.get('params', {}).items():
            if not key.startswith('ENDPOINT '):
                continue
            path = key[9:]  # strip 'ENDPOINT '
            ep_type = 'ENDPOINT'
            original = path
            for token in (data if isinstance(data, (list, set)) else [data]):
                t = str(token)
                if t.startswith('TYPE:'):
                    ep_type = t[5:]
                elif t.startswith('ORIGINAL:'):
                    original = t[9:]

            type_label, base_risk = _type_risk.get(ep_type, (ep_type, 'INFO'))
            if _sensitive_re.search(path) and base_risk in ('INFO', 'LOW'):
                base_risk = 'HIGH'
            rows.append((path, type_label, original, base_risk))

        if not rows:
            tbl.insertRow(0)
            item = QTableWidgetItem('No endpoints discovered in this response')
            item.setForeground(QColor('#666666'))
            tbl.setItem(0, 0, item)
            return

        _risk_ord = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'INFO': 3}
        rows.sort(key=lambda r: (_risk_ord.get(r[3], 4), r[0].lower()))

        for path, type_label, original, risk in rows:
            row = tbl.rowCount()
            tbl.insertRow(row)
            tbl.setItem(row, 0, QTableWidgetItem(path))
            tbl.setItem(row, 1, QTableWidgetItem(type_label))
            orig_preview = (original[:80] + '…') if len(original) > 80 else original
            orig_item = QTableWidgetItem(orig_preview)
            orig_item.setToolTip(original)
            tbl.setItem(row, 2, orig_item)
            risk_col = self._SEVERITY_COLORS.get(risk, '#BBBBBB')
            tbl.setItem(row, 3, self._color_item(risk, risk_col))
            if risk == 'HIGH':
                for c in range(tbl.columnCount()):
                    it = tbl.item(row, c)
                    if it:
                        it.setBackground(QColor(80, 30, 0, 40))

    def _apply_tooltips(self, tbl):
        """Set each cell's tooltip to its full text so long values are readable on hover.
        Preserves any tooltip that was already explicitly set (e.g. to the untruncated value)."""
        for r in range(tbl.rowCount()):
            for c in range(tbl.columnCount()):
                it = tbl.item(r, c)
                if it and it.text():
                    # Only fill in a tooltip when none is set yet — avoids clobbering
                    # full-content tooltips that populate functions set before truncating
                    # the display text.
                    if not it.toolTip():
                        it.setToolTip(it.text())

    def _snap_resize_to_contents_cols(self, tbl: QTableWidget):
        """For every column that is in ResizeToContents mode, call resizeColumnToContents()
        so the width reflects the populated data rather than just the header label.
        Interactive/Stretch columns are left untouched."""
        hdr = tbl.horizontalHeader()
        for c in range(tbl.columnCount()):
            if hdr.sectionResizeMode(c) == QHeaderView.ResizeToContents:
                tbl.resizeColumnToContents(c)

    def _display_security_panels(self, results: dict):
        """Populate all security panels and show/hide tabs based on whether each has results."""
        _tab_tables = [
            ('Headers',   lambda: self._populate_security_headers_table(results.get('response_headers', {})), 'sec_headers_table'),
            ('Cookies',   lambda: self._populate_cookie_table(results.get('cookies', [])),                    'cookie_table'),
            ('CORS',      lambda: self._populate_cors_table(results),                                         'cors_table'),
            ('Tech',      lambda: self._populate_tech_table(results.get('tech_stack', {})),                   'tech_table'),
            ('JWT',       lambda: self._populate_jwt_table(results),                                           'jwt_table'),
            ('Cache',     lambda: self._populate_cache_panel(results),                                         'cache_table'),
            ('Endpoints', lambda: self._populate_endpoints_table(results),                                     'endpoints_table'),
            ('Weird',     lambda: self._populate_weird_table(results),                                         'weird_table'),
            ('JS/DOM',    lambda: self._populate_js_dom_table(results),                                        'js_dom_table'),
        ]
        for label, fn, tbl_attr in _tab_tables:
            try:
                fn()
                tbl = getattr(self, tbl_attr, None)
                if tbl:
                    self._apply_tooltips(tbl)
                    # Flush ResizeToContents columns so badge/status widths snap
                    # to actual content rather than the placeholder header width.
                    self._snap_resize_to_contents_cols(tbl)
            except Exception as e:
                logger.error(f"_display_security_panels [{label}]: {e}", exc_info=True)

        if not hasattr(self, '_analysis_bottom_tabs'):
            return

        try:
            bt = self._analysis_bottom_tabs

            # ── compute counts ────────────────────────────────────────────
            n_cookies = len(results.get('cookies', []))

            resp_hdrs_lower = {k.lower() for k in results.get('response_headers', {})}
            cors_direct = sum(
                1 for h in (
                    'access-control-allow-origin', 'access-control-allow-credentials',
                    'access-control-allow-methods', 'access-control-allow-headers',
                    'access-control-expose-headers', 'access-control-max-age',
                ) if h in resp_hdrs_lower
            )
            cors_params = sum(
                1 for k in results.get('params', {})
                if k.startswith('HEADER ') and 'CORS' in k
            )
            n_cors = cors_direct + cors_params
            n_tech = len(results.get('tech_stack', {}))

            _jwt_re = re.compile(r'eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+')
            _combined_jwt = ((results.get('_response_text') or '') +
                             (results.get('_request_text') or ''))
            n_jwt = len(set(_jwt_re.findall(_combined_jwt)))

            # has_cache: cache table has at least one real row
            has_cache = self._tab_has_results(
                getattr(self, 'cache_table', None)
            )
            n_endpoints = sum(
                1 for k in results.get('params', {}) if k.startswith('ENDPOINT ')
            )

            # ── tab definitions: (index, label, has_results, count_or_None) ──
            n_weird = len(results.get('weird', []))

            # JS/DOM tab: count all INLINE_DOM, INLINE_SECRET,
            # JS OPEN_REDIRECT, JS WEBSOCKET, JS TOKEN_STORAGE, JS SOURCE_MAP,
            # JS GRAPHQL_ prefixes
            # Note: INLINE_JS_VAR are actual URL params — counted in param table instead.
            _JS_DOM_PREFIXES = (
                'INLINE_DOM ', 'INLINE_SECRET ',
                'JS OPEN_REDIRECT', 'JS WEBSOCKET', 'JS POSTMESSAGE',
                'JS TOKEN_STORAGE', 'JS LOCALSTORAGE', 'JS SOURCE_MAP',
                'JS GRAPHQL_', 'JS GRAPHQL ',
            )
            n_js_dom = sum(
                1 for k in results.get('params', {})
                if any(k.startswith(p) for p in _JS_DOM_PREFIXES)
            )

            tab_specs = [
                # idx  base_label            has_results              badge_n
                (1,  "🛡 Headers",    True,               None),   # always visible
                (2,  "≈ Cookies",    n_cookies > 0,      n_cookies),
                (3,  "🌐 CORS",       n_cors > 0,         n_cors),
                (4,  "⊞ Tech Stack", n_tech > 0,         n_tech),
                (5,  "⚿ JWT",        n_jwt > 0,          n_jwt),
                (6,  "↺ Cache",      has_cache,          None),
                (7,  "⊃ Endpoints",  n_endpoints > 0,    n_endpoints),
                (8,  "△ Weird",      n_weird > 0,        n_weird),
                (9,  "⚡ JS / DOM",   n_js_dom > 0,       n_js_dom),
            ]

            for idx, base_label, has_results, badge_n in tab_specs:
                if idx >= bt.count():
                    continue
                if has_results:
                    label_txt = (f"{base_label} ({badge_n})"
                                 if badge_n else base_label)
                    bt.setTabText(idx, label_txt)
                    bt.setTabVisible(idx, True)
                else:
                    bt.setTabText(idx, base_label)
                    bt.setTabVisible(idx, False)

            # Make sure a visible tab is selected (in case current was hidden)
            if not bt.isTabVisible(bt.currentIndex()):
                for i in range(bt.count()):
                    if bt.isTabVisible(i):
                        bt.setCurrentIndex(i)
                        break

        except Exception as e:
            logger.error(f"_display_security_panels [badges]: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Generic context menu shared by ALL bottom-section tables
    # ------------------------------------------------------------------
    def _show_table_context_menu(self, position, table):
        """Right-click context menu for any security-panel table (headers, cookies, CORS, etc.)."""
        item = table.itemAt(position)
        if not item:
            return

        row = item.row()
        ncols = table.columnCount()

        # Collect all cell texts for this row, paired with their header label
        col_headers = [
            table.horizontalHeaderItem(c).text() if table.horizontalHeaderItem(c) else f"Col {c}"
            for c in range(ncols)
        ]
        col_values = []
        for c in range(ncols):
            it = table.item(row, c)
            col_values.append(it.text().strip() if it else "")

        # Identify the "primary" column (first non-empty text that isn't a severity badge)
        _severity_words = {"HIGH", "MEDIUM", "LOW", "INFO", "CRITICAL",
                           "✓", "✗", "✓", "△", "●", "▲", "◆", "○"}
        primary_col = 0
        for c, v in enumerate(col_values):
            if v and v not in _severity_words and not all(ch in "✓✗✓△●▲◆○ " for ch in v):
                primary_col = c
                break

        primary_val = col_values[primary_col]
        primary_hdr = col_headers[primary_col]

        # "Value" column: prefer a column whose header contains "value" or is the 2nd/3rd col
        value_col = None
        for c, h in enumerate(col_headers):
            if "value" in h.lower() and c != primary_col:
                value_col = c
                break
        if value_col is None and ncols > primary_col + 1:
            value_col = primary_col + 1
        value_val = col_values[value_col] if value_col is not None else ""

        # Full row as tab-separated
        full_row = "\t".join(col_values)

        def _copy(text):
            if text:
                QApplication.clipboard().setText(text)

        def _clip(text, n=45):
            return (text[:n] + "…") if len(text) > n else text

        # ── Build menu ────────────────────────────────────────────────────
        menu = QMenu(table)
        menu.setStyleSheet("""
            QMenu {
                background-color: #252526;
                color: #cccccc;
                border: 1px solid #3c3c3c;
                padding: 4px 0;
            }
            QMenu::item { padding: 5px 20px 5px 10px; font-size: 12px; }
            QMenu::item:selected { background-color: #094771; color: #ffffff; }
            QMenu::separator { height: 1px; background: #3c3c3c; margin: 3px 6px; }
            QMenu::item:disabled { color: #555555; }
        """)

        # ── Copy section ──────────────────────────────────────────────────
        lbl = menu.addAction("── Copy ──")
        lbl.setEnabled(False)

        act_copy_primary = menu.addAction(f"⊏  Copy {primary_hdr}  \"{_clip(primary_val)}\"")
        act_copy_value   = None
        if value_val and value_val != primary_val:
            vh = col_headers[value_col] if value_col is not None else "Value"
            act_copy_value = menu.addAction(f"⊏  Copy {vh}  \"{_clip(value_val)}\"")
        act_copy_row = menu.addAction("⊏  Copy Full Row")
        menu.addSeparator()

        # ── Search section — only if panes are available ──────────────────
        has_req  = bool(getattr(self, 'current_request_raw',  None))
        has_resp = bool(getattr(self, 'current_response_raw', None))

        act_sp_req = act_sv_req = act_sp_resp = act_sv_resp = None

        if has_req or has_resp:
            lbl2 = menu.addAction("── Search in Request / Response ──")
            lbl2.setEnabled(False)

            loc = self._guess_location_from_header(col_headers)

            if has_req:
                act_sp_req = menu.addAction(
                    f"🔍  Search  \"{_clip(primary_val)}\"  in Request")
            if has_req and value_val and value_val != primary_val:
                act_sv_req = menu.addAction(
                    f"🔍  Search value  \"{_clip(value_val)}\"  in Request")
            if has_resp:
                act_sp_resp = menu.addAction(
                    f"🔍  Search  \"{_clip(primary_val)}\"  in Response")
            if has_resp and value_val and value_val != primary_val:
                act_sv_resp = menu.addAction(
                    f"🔍  Search value  \"{_clip(value_val)}\"  in Response")

        # ── Execute ───────────────────────────────────────────────────────
        action = menu.exec_(table.viewport().mapToGlobal(position))
        if action is None:
            return

        if action == act_copy_primary:
            _copy(primary_val)
        elif action == act_copy_value:
            _copy(value_val)
        elif action == act_copy_row:
            _copy(full_row)
        elif action == act_sp_req:
            self._search_text_in_pane(primary_val, loc, "request")
        elif action == act_sv_req:
            self._search_text_in_pane(value_val, loc, "request")
        elif action == act_sp_resp:
            self._search_text_in_pane(primary_val, loc, "response")
        elif action == act_sv_resp:
            self._search_text_in_pane(value_val, loc, "response")

    def _guess_location_from_header(self, col_headers: list) -> str:
        """Guess the location hint (HEADER/COOKIE/URL/…) from a table's column headers."""
        joined = " ".join(col_headers).lower()
        if "cookie" in joined:
            return "COOKIE"
        if "header" in joined or "cors" in joined or "hsts" in joined:
            return "HEADER"
        if "path" in joined or "endpoint" in joined or "url" in joined:
            return "URL"
        return ""

    def show_param_table_context_menu(self, position):
        """Rich right-click context menu for the parameter analysis table."""
        item = self.param_table.itemAt(position)
        if not item:
            return

        row = item.row()

        # ── Pull all columns for this row ────────────────────────────────
        def _cell(col):
            it = self.param_table.item(row, col)
            return it.text().strip() if it else ""

        location   = _cell(0)   # BODY / URL / HEADER / …
        param_name = _cell(1)   # parameter name
        param_val  = _cell(2)   # detected value (may be truncated display)
        risk       = _cell(3)   # ● CRITICAL / ▲ HIGH / …
        vulns      = _cell(4)   # XSS, SQLI, …
        meta       = _cell(5)   # metadata

        # Strip VALUE: prefix that we write into the column for display
        raw_value = param_val
        if raw_value.startswith("VALUE:"):
            raw_value = raw_value[6:]

        # Full row as plain text
        full_row = "\t".join(filter(None, [location, param_name, raw_value, risk, vulns, meta]))

        # ── Helper: clip to clipboard ─────────────────────────────────────
        def _copy(text):
            if text:
                QApplication.clipboard().setText(text)

        # ── Build menu ────────────────────────────────────────────────────
        menu = QMenu(self.param_table)
        menu.setStyleSheet("""
            QMenu {
                background-color: #252526;
                color: #cccccc;
                border: 1px solid #3c3c3c;
                padding: 4px 0;
            }
            QMenu::item {
                padding: 5px 20px 5px 10px;
                font-size: 12px;
            }
            QMenu::item:selected {
                background-color: #094771;
                color: #ffffff;
            }
            QMenu::separator {
                height: 1px;
                background: #3c3c3c;
                margin: 3px 6px;
            }
            QMenu::item:disabled {
                color: #555555;
            }
        """)

        # ── Section: Copy ─────────────────────────────────────────────────
        lbl_copy = menu.addAction("── Copy ──")
        lbl_copy.setEnabled(False)

        act_copy_name  = menu.addAction(f"⊏  Copy Param Name  \"{param_name[:50]}\"")
        act_copy_val   = menu.addAction(f"⊏  Copy Value  \"{raw_value[:50]}\"") if raw_value else None
        act_copy_vulns = menu.addAction(f"⊏  Copy Vulnerabilities  \"{vulns[:60]}\"") if vulns else None
        act_copy_row   = menu.addAction("⊏  Copy Full Row")
        menu.addSeparator()

        # ── Section: Search in Request ────────────────────────────────────
        lbl_req = menu.addAction("── Search in Request ──")
        lbl_req.setEnabled(False)

        display_name = param_name[:30] + "…" if len(param_name) > 30 else param_name
        display_val  = raw_value[:30] + "…" if len(raw_value) > 30 else raw_value

        act_search_name_req = menu.addAction(f"🔍  Search name  \"{display_name}\"  in Request")
        act_search_val_req  = menu.addAction(f"🔍  Search value  \"{display_val}\"  in Request") if raw_value else None
        menu.addSeparator()

        # ── Section: Search in Response ───────────────────────────────────
        lbl_resp = menu.addAction("── Search in Response ──")
        lbl_resp.setEnabled(False)

        act_search_name_resp = menu.addAction(f"🔍  Search name  \"{display_name}\"  in Response")
        act_search_val_resp  = menu.addAction(f"🔍  Search value  \"{display_val}\"  in Response") if raw_value else None

        # ── Execute ───────────────────────────────────────────────────────
        action = menu.exec_(self.param_table.viewport().mapToGlobal(position))
        if action is None:
            return

        if action == act_copy_name:
            _copy(param_name)
        elif action == act_copy_val:
            _copy(raw_value)
        elif action == act_copy_vulns:
            _copy(vulns)
        elif action == act_copy_row:
            _copy(full_row)
        elif action == act_search_name_req:
            self._search_text_in_pane(param_name, location, "request")
        elif action == act_search_val_req and raw_value:
            self._search_text_in_pane(raw_value, location, "request")
        elif action == act_search_name_resp:
            self._search_text_in_pane(param_name, location, "response")
        elif action == act_search_val_resp and raw_value:
            self._search_text_in_pane(raw_value, location, "response")

    # ------------------------------------------------------------------
    # Unified search helper — switches to the right pane then highlights
    # ------------------------------------------------------------------
    def _search_text_in_pane(self, search_text: str, location: str, pane: str):
        """Switch to request or response pane and highlight search_text."""
        if not search_text:
            return

        is_request = (pane == "request")

        # Check we have the raw text
        raw_attr = 'current_request_raw' if is_request else 'current_response_raw'
        tab_label = "Request" if is_request else "Response"

        raw = getattr(self, raw_attr, None)
        if not raw:
            QMessageBox.information(
                self, f"No {tab_label}",
                f"No {tab_label.lower()} loaded to search in."
            )
            return

        # Switch to the correct tab in rr_tabs
        if hasattr(self, 'rr_tabs'):
            for i in range(self.rr_tabs.count()):
                if tab_label.lower() in self.rr_tabs.tabText(i).lower():
                    self.rr_tabs.setCurrentIndex(i)
                    break

        # Build candidate search strings (try the most specific first)
        candidates = self._build_search_candidates(search_text, location, is_request)

        # Pick the first candidate that actually appears in the raw text
        raw_lower = raw.lower()
        chosen = next(
            (c for c in candidates if c.lower() in raw_lower),
            search_text          # fall back to raw search_text
        )

        # Push into the right search box and trigger highlighting
        if is_request:
            box = getattr(self, 'request_search_box', None)
            trigger = getattr(self, 'search_in_request', None)
            text_widget = getattr(self, 'request_text', None)
        else:
            box = getattr(self, 'response_search_box', None)
            trigger = getattr(self, 'search_in_response', None)
            text_widget = getattr(self, 'response_text', None)

        if box:
            box.setText(chosen)
        if trigger:
            trigger()
        if text_widget and hasattr(self, 'find_in_text'):
            self.find_in_text(text_widget, chosen)

        # Status feedback
        if hasattr(self, 'status_label'):
            disp = chosen[:40] + ('…' if len(chosen) > 40 else '')
            self.status_label.setText(f"🔍 Searching  \"{disp}\"  in {tab_label}")
            QTimer.singleShot(3000, lambda: self.status_label.setText("Ready"))

    def _build_search_candidates(self, text: str, location: str, is_request: bool) -> list:
        """Return an ordered list of search strings to try, most-specific first."""
        cands = []
        t = text.strip()

        if location == "HEADER":
            cands += [f"{t}:", t.lower() + ":", t]
        elif location in ("BODY", "JSON"):
            # Look for JSON key: "text": or form key=
            cands += [f'"{t}":', f"'{t}':", f"{t}=", t]
        elif location == "URL":
            cands += [f"{t}=", f"?{t}", f"&{t}", t]
        elif location == "COOKIE":
            cands += [f"{t}=", t]
        else:
            # Fallback: JSON, form, and plain
            cands += [f'"{t}":', f"{t}=", t]

        # Always include the plain form as last resort
        if t not in cands:
            cands.append(t)

        # Remove exact duplicates, preserve order
        seen = set()
        out = []
        for c in cands:
            if c not in seen:
                seen.add(c)
                out.append(c)
        return out

    # ------------------------------------------------------------------
    # Legacy wrappers kept so existing code that calls them still works
    # ------------------------------------------------------------------
    def search_value_in_response(self, value: str, param_name: str = ""):
        self._search_text_in_pane(value, "", "response")

    def search_param_in_response(self, param_name: str, location: str):
        self._search_text_in_pane(param_name, location, "response")

    def search_param_in_request(self, param_name: str, location: str):
        self._search_text_in_pane(param_name, location, "request")

    def _generate_search_patterns(self, param_name: str, location: str, param_value: str = "") -> list:
        """Legacy helper — delegates to _build_search_candidates."""
        return self._build_search_candidates(param_name, location, False)

    def _create_auto_highlighting_section(self):
        """Create auto-highlighting section - NO STATUS BAR, MAXIMIZED TABLE"""
        group = QGroupBox()
        group.setStyleSheet(f"""
            QGroupBox {{
                background-color: {COLORS['bg_lighter']};
                border: 1px solid #3a3a3a;
                border-left: 3px solid {COLORS.get('severity_critical', '#FF6B6B')};
                border-radius: 0px;
                margin-top: 0px;
                padding-top: 0px;
            }}
        """)

        layout = QVBoxLayout()
        layout.setSpacing(0)
        layout.setContentsMargins(0, 0, 0, 0)

        # ── Styled header bar ─────────────────────────────────────────────
        header_bar2 = QWidget()
        header_bar2.setFixedHeight(26)
        header_bar2.setStyleSheet(
            f"background-color: {COLORS['bg_darker']};"
            "border-bottom: 1px solid #444;"
        )
        header_layout2 = QHBoxLayout(header_bar2)
        header_layout2.setContentsMargins(8, 0, 8, 0)
        header_layout2.setSpacing(6)

        section_icon2 = QLabel("🔍")
        section_icon2.setStyleSheet("font-size: 11px;")
        header_layout2.addWidget(section_icon2)

        section_title2 = QLabel("Information Leakage Scanner")
        section_title2.setStyleSheet(
            f"color: {COLORS.get('text_bright', '#FFFFFF')};"
            f"font-weight: 600; font-size: 11px; letter-spacing: 0.3px;"
        )
        header_layout2.addWidget(section_title2)

        header_layout2.addStretch()

        self.leak_count_badge = QLabel("0 findings")
        self.leak_count_badge.setStyleSheet(
            "color: #888; font-size: 10px; "
            "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
        )
        header_layout2.addWidget(self.leak_count_badge)

        # Toggle arrow
        self._leak_filter_arrow = QLabel("▼")
        self._leak_filter_arrow.setStyleSheet("color: #666; font-size: 9px; padding-left: 4px;")
        header_layout2.addWidget(self._leak_filter_arrow)

        layout.addWidget(header_bar2)

        # ── Filter container (toggled by header click) ────────────────────
        self.highlight_filter_container = QWidget()
        self.highlight_filter_container.setFixedHeight(28)
        self.highlight_filter_container.setStyleSheet(
            f"background-color: {COLORS['bg_darker']};"
            f"border-bottom: 1px solid #2e2e2e;"
        )
        self.highlight_filter_container.setVisible(False)
        # shim so existing toggle-lambda still works without error
        self.leak_title_btn = QPushButton()
        self.leak_title_btn.setVisible(False)

        def _toggle_leak_filter():
            visible = not self.highlight_filter_container.isVisible()
            self.highlight_filter_container.setVisible(visible)
            self._leak_filter_arrow.setText("▼" if visible else "▶")

        header_bar2.setCursor(Qt.PointingHandCursor)
        header_bar2.mousePressEvent = lambda e: _toggle_leak_filter()
        
        # ==================== COMPACT PATTERN ROW ====================
        pattern_row = QHBoxLayout(self.highlight_filter_container)
        pattern_row.setSpacing(6)
        pattern_row.setContentsMargins(8, 2, 8, 2)
        
        # Auto-highlight checkbox
        self.auto_highlight = QCheckBox("· Auto")
        self.auto_highlight.setChecked(True)
        self.auto_highlight.setToolTip("Automatically highlight when response loads")
        pattern_row.addWidget(self.auto_highlight)
        
        # Add separator
        sep1 = QFrame()
        sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet("background-color: #555;")
        sep1.setMaximumWidth(1)
        pattern_row.addWidget(sep1)
        
        # Severity label
        severity_label = QLabel("Severity:")
        severity_label.setStyleSheet(f"color: {COLORS.get('text_muted', '#888888')};")
        pattern_row.addWidget(severity_label)
        
        # Severity filters
        self.filter_critical = QCheckBox("● Critical")
        self.filter_critical.setChecked(True)
        self.filter_critical.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_critical)
        
        self.filter_high = QCheckBox("▲ High")
        self.filter_high.setChecked(True)
        self.filter_high.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_high)
        
        self.filter_medium = QCheckBox("◆ Medium")
        self.filter_medium.setChecked(True)
        self.filter_medium.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_medium)
        
        # Add separator
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet("background-color: #555;")
        sep2.setMaximumWidth(1)
        pattern_row.addWidget(sep2)
        
        # Category label
        category_label = QLabel("Type:")
        category_label.setStyleSheet(f"color: {COLORS.get('text_muted', '#888888')};")
        pattern_row.addWidget(category_label)
        
        # Category filters (most important)
        self.filter_secrets = QCheckBox("⚿ Secrets")
        self.filter_secrets.setChecked(True)
        self.filter_secrets.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_secrets)
        
        self.filter_network = QCheckBox("🌐 Network")
        self.filter_network.setChecked(True)
        self.filter_network.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_network)
        
        self.filter_versions = QCheckBox("⊞ Versions")
        self.filter_versions.setChecked(True)
        self.filter_versions.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_versions)
        
        self.filter_paths = QCheckBox("□ Paths")
        self.filter_paths.setChecked(True)
        self.filter_paths.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_paths)
        
        self.filter_errors = QCheckBox("△ Errors")
        self.filter_errors.setChecked(True)
        self.filter_errors.stateChanged.connect(self.filter_highlight_table)
        pattern_row.addWidget(self.filter_errors)
        
        pattern_row.addStretch()
        
        # "All" checkbox
        self.pattern_all = QCheckBox("All")
        self.pattern_all.setChecked(True)
        self.pattern_all.stateChanged.connect(self.toggle_all_patterns)
        pattern_row.addWidget(self.pattern_all)
        
        layout.addWidget(self.highlight_filter_container)
        
        # ==================== MAXIMIZED HIGHLIGHT TABLE ====================
        self.highlight_table = QTableWidget()
        self.highlight_table.setColumnCount(4)
        self.highlight_table.setHorizontalHeaderLabels([
            "Pattern Type", "Matches", "Severity", "Preview"
        ])
        self.highlight_table.horizontalHeader().setStretchLastSection(True)
        self.highlight_table.setAlternatingRowColors(True)
        self.highlight_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS['bg_dark']};
                color: {COLORS.get('text_normal', '#BBBBBB')};
                gridline-color: #444;
                border: none;
            }}
            QTableWidget::item:selected {{
                background-color: {COLORS.get('accent_green', '#6A8759')};
            }}
            QHeaderView::section {{
                background-color: {COLORS['bg_darker']};
                color: {COLORS.get('text_bright', '#FFFFFF')};
                padding: 2px 4px;
                border: none;
                font-weight: bold;
            }}
        """)
        
        self.highlight_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._setup_table_double_click_copy(self.highlight_table)
        self.highlight_table.verticalHeader().setDefaultSectionSize(22)
        self.highlight_table.verticalHeader().hide()
        
        layout.addWidget(self.highlight_table)
        
        group.setLayout(layout)
        return group
    
    def show_highlight_table_context_menu(self, position):
        """Show context menu for highlight table"""
        # Get the clicked item
        item = self.highlight_table.itemAt(position)
        if not item:
            return
        
        row = item.row()
        
        # Get pattern type from column 0
        pattern_item = self.highlight_table.item(row, 0)
        if not pattern_item:
            return
        
        pattern_type = pattern_item.text()
        
        # Get preview from column 3
        preview_item = self.highlight_table.item(row, 3)
        preview = preview_item.text() if preview_item else ""
        
        # Extract actual text to search for (from preview)
        search_text = preview.split("...")[0] if "..." in preview else preview
        if len(search_text) > 30:
            search_text = search_text[:30]
        
        # Create context menu
        menu = QMenu()
        
        # Add action to search in response
        if search_text:
            search_action = menu.addAction(f"🔍earch '{search_text}' in Response")
            search_action.setData({"pattern": pattern_type, "text": search_text})
        
        # Add action to copy pattern
        copy_action = menu.addAction(f"⊏ Copy '{pattern_type}'")
        
        # Execute menu
        action = menu.exec_(self.highlight_table.viewport().mapToGlobal(position))
        
        if action == search_action and search_text:
            self.search_text_in_response(search_text, pattern_type)
        elif action == copy_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(pattern_type)
            
            if hasattr(self, 'status_label'):
                self.status_label.setText(f"⊏ Copied '{pattern_type}'")
                QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))

    def search_text_in_response(self, search_text: str, pattern_type: str):
        """Search for text in response tab"""
        if not hasattr(self, 'current_response_raw') or not self.current_response_raw:
            QMessageBox.information(self, "No Response", "No response loaded to search in.")
            return
        
        # Switch to Response tab
        if hasattr(self, 'rr_tabs'):
            # Find the Response tab index (usually index 1)
            for i in range(self.rr_tabs.count()):
                if self.rr_tabs.tabText(i) == "Response":
                    self.rr_tabs.setCurrentIndex(i)
                    break
        
        # Set search text in response search box
        if hasattr(self, 'response_search_box'):
            self.response_search_box.setText(search_text)
            
            # Trigger search
            if hasattr(self, 'search_in_response'):
                self.search_in_response()
            
            # Show first match
            if hasattr(self, 'find_in_text'):
                self.find_in_text(self.response_text, search_text)
        
        # Update status
        if hasattr(self, 'status_label'):
            self.status_label.setText(f"🔍 Searching '{pattern_type}' pattern in response...")
            QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
            
    def _setup_table_double_click_copy(self, table: QTableWidget):
        """Set up double-click to copy cell text to clipboard"""
        table.cellDoubleClicked.connect(
            lambda row, col: self._copy_cell_text(table, row, col)
        )

    def _copy_cell_text(self, table: QTableWidget, row: int, col: int):
        """Copy the cell's text to clipboard and show feedback"""
        item = table.item(row, col)
        if item and item.text():
            text = item.text().strip()
            if text:
                QApplication.clipboard().setText(text)
                
                # Show brief feedback
                if hasattr(self, 'status_label'):
                    display = text[:40] + ('…' if len(text) > 40 else '')
                    self.status_label.setText(f"📋 Copied: \"{display}\"")
                    QTimer.singleShot(2000, lambda: self.status_label.setText("Ready"))
    # ========================================================================
    # ANALYSIS LOGIC
    # ========================================================================

    # ── Recording helper ─────────────────────────────────────────────────────
    def _auto_save_recording(self, finding: dict, analysis_results: dict):
        """
        Persist noteworthy analysis results to the project's
        analysis_recordings.json so the Recorded tab can display them.
        Silently skips when no project is open or RecordingManager is unavailable.
        """
        if RecordingManager is None:
            return

        project_dir = None
        try:
            # Try direct attribute first
            project_dir = getattr(self, '_project_dir', None)
            if not project_dir:
                pp = getattr(self, '_project_paths', None)
                if pp:
                    project_dir = pp.get('project_dir')
            if not project_dir:
                # Walk up to parent_gui
                gui = getattr(self, 'parent_gui', None) or self
                pp  = getattr(gui, '_project_paths', None)
                if pp:
                    project_dir = pp.get('project_dir')
        except Exception:
            pass

        if not project_dir:
            return

        try:
            RecordingManager.save_finding(project_dir, finding, analysis_results)
            # Flash status bar confirmation
            if hasattr(self, 'analysis_status'):
                self.analysis_status.setText("⊟ Saved to Recorded")
                QTimer.singleShot(2000, lambda: self.analysis_status.setText("Ready"))
            elif hasattr(self, 'param_stats'):
                # Briefly show save confirmation alongside existing stats
                current = self.param_stats.text()
                self.param_stats.setText(current + "  ⊟")
                QTimer.singleShot(1500, lambda: self.param_stats.setText(current))
        except Exception as exc:
            logger.debug(f"_auto_save_recording: {exc}")

    def analyze_current_request(self):
        """Analyze the currently selected request"""
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a request to analyze")
            return
        
        row = selected_items[0].row()
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
        
        if finding_index is None or finding_index >= len(self.findings):
            return
        
        finding = self.findings[finding_index]
        
        # Show progress
        self.param_stats.setText("↺ Analyzing...")
        QApplication.processEvents()
        
        # Run analysis
        analysis_results = SecurityAnalyzer.analyze_finding(finding)
        
        # Update finding
        finding['params'] = analysis_results['params']
        finding['severity'] = analysis_results['severity']
        finding['analyzed'] = True
        
        # Auto-save detections to project recordings
        self._auto_save_recording(finding, analysis_results)
        
        # Display results
        self._display_parameter_analysis(analysis_results)
        if hasattr(self, '_display_security_panels'):
            self._display_security_panels(analysis_results)
        
        # Update stats
        total = len(analysis_results['params'])
        critical = sum(1 for v in analysis_results['params'].values() 
                      if 'CRITICAL' in str(v))
        
        self.param_stats.setText(
            f"✓ {total} parameters found ({critical} critical, "
            f"severity: {analysis_results['severity']})"
        )
    
    def refresh_analysis(self):
        """
        Refresh analysis with current request/response data.
        Called from http_history_tab.py when auto-analyze is enabled.
        """
        # Check if we have the necessary attributes
        if not hasattr(self, 'current_analysis_request') or not hasattr(self, 'current_analysis_response'):
            return
        
        # Get current finding from selection
        if not hasattr(self, 'history_table'):
            return
            
        selected_items = self.history_table.selectedItems()
        if not selected_items:
            return
        
        row = selected_items[0].row()
        finding_index = self.history_table.item(row, 0).data(Qt.UserRole)
        
        if finding_index is None or finding_index >= len(self.findings):
            return
        
        finding = self.findings[finding_index]
        
        # Show progress
        if hasattr(self, 'param_stats'):
            self.param_stats.setText("↺ Auto-analyzing...")
            QApplication.processEvents()
        
        # Run analysis
        analysis_results = SecurityAnalyzer.analyze_finding(finding)
        
        # Update finding
        finding['params'] = analysis_results['params']
        finding['severity'] = analysis_results['severity']
        finding['analyzed'] = True
        
        # Auto-save detections to project recordings
        self._auto_save_recording(finding, analysis_results)
        
        # Display results
        self._display_parameter_analysis(analysis_results)
        if hasattr(self, '_display_security_panels'):
            self._display_security_panels(analysis_results)
        
        # Update stats
        total = len(analysis_results['params'])
        critical = sum(1 for v in analysis_results['params'].values() 
                      if 'CRITICAL' in str(v))
        
        if hasattr(self, 'param_stats'):
            self.param_stats.setText(
                f"✓ {total} findings ({critical} critical, severity: {analysis_results['severity']})"
            )
    
    def _display_parameter_analysis(self, results: Dict, finding: Dict = None):
        """Display parameter analysis results WITH VALUES"""
        self.param_table.setRowCount(0)
        
        # Extract values from the finding
        param_values = self._extract_parameter_values(finding) if finding else {}

        # Prefixes/substrings that are now shown in dedicated bottom panels
        # (Headers tab and CORS tab) — skip them from the parameter table to
        # avoid duplication.
        _HEADER_PANEL_SKIP = (
            'MISSING_', 'WEAK_', 'CORS:', 'CORS_', 'SECURITY_MISCONFIGURATION',
            'SERVER_DISCLOSURE', 'DIRECTORY_LISTING',
        )

        # RESPONSE entries that carry data-leakage type names belong in the
        # Info Leakage tab (its own scanner), not the param table.
        _LEAKAGE_TYPE_SKIP = (
            'API_KEY', 'AWS_', 'GITHUB_', 'STRIPE_', 'SLACK_', 'GOOGLE_API',
            'PRIVATE_KEY', 'JWT_TOKEN', 'DATABASE_CONNECTION', 'PASSWORD_IN',
            'SECRET_IN', 'TOKEN_IN', 'AUTH_IN', 'ACCESS_TOKEN', 'MONGODB',
            'MYSQL', 'POSTGRES', 'REDIS', 'SQL_SERVER', 'CREDENTIAL_IN',
            'REQUEST_CREDENTIAL',
        )

        # JS/DOM entries belong exclusively in the ⚡ JS / DOM tab.
        # Note: INLINE_JS_VAR entries are actual URL parameters — NOT skipped here.
        _JS_DOM_TABLE_SKIP = (
            'INLINE_DOM ', 'INLINE_SECRET ',
            'JS OPEN_REDIRECT', 'JS WEBSOCKET', 'JS POSTMESSAGE',
            'JS TOKEN_STORAGE', 'JS LOCALSTORAGE', 'JS SOURCE_MAP',
            'JS GRAPHQL_', 'JS GRAPHQL ',
        )
        
        for param_name, detections in results['params'].items():
            # Skip entries that belong to the dedicated security panels
            if param_name.startswith('HEADER '):
                suffix = param_name[7:]  # text after "HEADER "
                if any(suffix.startswith(s) for s in _HEADER_PANEL_SKIP):
                    continue

            # Skip data-leakage entries that are shown in the Info Leakage tab
            if param_name.startswith('RESPONSE '):
                suffix = param_name[9:]  # text after "RESPONSE "
                if any(suffix.startswith(s) for s in _LEAKAGE_TYPE_SKIP):
                    continue

            # Skip JS/DOM entries — these live in the ⚡ JS / DOM tab
            if any(param_name.startswith(p) for p in _JS_DOM_TABLE_SKIP):
                continue

            row = self.param_table.rowCount()
            self.param_table.insertRow(row)
            
            # Parse location and name
            parts = param_name.split(' ', 1)
            location = parts[0] if len(parts) > 1 else "UNKNOWN"
            name = parts[1] if len(parts) > 1 else param_name
            
            # Map RESPONSE to BODY for filtering purposes
            display_location = location
            if location == "RESPONSE":
                display_location = "BODY"
            
            # Determine risk level
            det_str = ' '.join(str(d) for d in detections) if isinstance(detections, (list, set)) else str(detections)
            
            if 'CRITICAL' in det_str:
                risk = "● CRITICAL"
            elif 'HIGH' in det_str or any(term in det_str for term in ['XSS', 'SQLI', 'RCE']):
                risk = "▲ HIGH"
            elif 'MEDIUM' in det_str:
                risk = "◆ MEDIUM"
            elif 'LOW' in det_str:
                risk = "▼ LOW"
            else:
                risk = "○ INFO"
            
            # ✓ EXTRACT VALUE for this parameter
            value = self._get_parameter_value(param_name, name, location, param_values, finding)
            
            # Check if this parameter is reflected
            is_reflected = 'REFLECTED' in det_str
            
            # Check if this is a hidden input
            is_hidden = 'HIDDEN' in det_str
            
            # Truncate long values for display
            if value and len(value) > 50:
                display_value = value[:47] + "..."
            else:
                display_value = value or ""
            
            # Add tags to value
            tags = []
            if is_hidden:
                tags.append("[HIDDEN]")
            if is_reflected:
                tags.append("[REFLECTED]")
            
            if tags:
                if display_value:
                    display_value = f"{display_value} {' '.join(tags)}"
                else:
                    display_value = ' '.join(tags)
            
            # Separate vulnerabilities from metadata
            vulnerabilities = []
            metadata = []
            
            # Define vulnerability patterns
            vuln_keywords = {
                'XSS', 'SQLI', 'CRLF', 'RCE', 'IDOR', 'SSRF', 'XXE', 'LFI', 'RFI', 'SSTI', 'NOSQL',
                'COMMAND_INJECTION', 'SQL_INJECTION', 'PATH_TRAVERSAL', 'OPEN_REDIRECT',
                'REDIRECT', 'BYPASS', 'PRIVILEGE_ESCALATION', 'PRIVILEGE_ESC',
                'AUTHENTICATION_BYPASS', 'AUTHORIZATION_BYPASS', 'CRITICAL', 'HIGH',
                'MEDIUM', 'LOW', 'SENSITIVE', 'PASSWORD', 'API_KEY', 'SECRET',
                'TOKEN_LEAK', 'CSRF', 'CLICKJACKING', 'INSECURE', 'WEAK',
                'DANGEROUS', 'EXPLOITABLE', 'VULNERABLE', 'REFLECTED',
                'PASSWORD_FIELD', 'EMAIL_FIELD', 'FILE_UPLOAD', 'CSRF_TOKEN',
                'CSRF_HIDDEN', 'SECURITY_RELEVANT_BOOL', 'WEBSOCKET', 'POSTMESSAGE_NO_ORIGIN',
                'GRAPHQL_INTROSPECTION', 'GRAPHQL_MUTATION',
            }
            
            # Metadata patterns (not vulnerabilities)
            metadata_keywords = {
                'TYPE:', 'FORM:', 'METHOD:', 'STANDALONE', 'REQUIRED', 'READONLY',
                'DISABLED', 'HIDDEN', 'NUMERIC', 'BOOLEAN', 'STRING', 'ARRAY',
                'OBJECT', 'NULL', 'INTERESTING', 'OPTIONS:', 'SOURCE:', 'ACTION:',
                'SRC:', 'ATTR:', 'EVENT:', 'META:', 'ERROR_MSG:', 'VAR:', 'CODE:',
                'JS_PARAMETER_EXTRACTION', 'EVIDENCE:', 'TECHNOLOGY_DETECTED',
                'FRAMEWORK_DETECTED'
            }
            
            for detection in detections:
                det_str = str(detection)
                det_str_upper = det_str.upper()
                
                # Check if it's a JavaScript sink pattern (code snippet with colon)
                # Examples: "document.write: ...", "innerHTML: ...", "eval(): ..."
                is_js_sink = False
                js_sink_patterns = [
                    'document.write:', 'document.writeln:', 'innerHTML:', 'outerHTML:',
                    'insertAdjacentHTML:', 'eval():', 'Function constructor:',
                    'setTimeout():', 'setInterval():', 'jQuery.', '$.parseHTML:',
                    '.html:', '.append:', '.prepend:', '.after:', '.before:',
                    '.replaceWith:', '.wrap:', 'onevent:'
                ]
                
                for sink_pattern in js_sink_patterns:
                    if sink_pattern in det_str:
                        # This is a code snippet, put it in metadata
                        metadata.append(det_str)
                        is_js_sink = True
                        break
                
                if is_js_sink:
                    continue
                
                # Check if it's metadata
                is_metadata = False
                for meta_key in metadata_keywords:
                    if meta_key in det_str_upper or det_str.startswith(meta_key):
                        metadata.append(det_str)
                        is_metadata = True
                        break
                
                # If not metadata, check if it's a vulnerability
                if not is_metadata:
                    is_vuln = False
                    for vuln_key in vuln_keywords:
                        if vuln_key in det_str_upper:
                            vulnerabilities.append(det_str)
                            is_vuln = True
                            break
                    
                    # If neither, default to metadata
                    if not is_vuln:
                        metadata.append(det_str)
            
            # Format for display
            vuln_display = ', '.join(vulnerabilities) if vulnerabilities else ''
            meta_display = ', '.join(metadata) if metadata else ''
            
            # Add items WITH VALUE, REFLECTION, and SEPARATED COLUMNS
            self.param_table.setItem(row, 0, QTableWidgetItem(display_location))
            self.param_table.setItem(row, 1, QTableWidgetItem(name))
            self.param_table.setItem(row, 2, QTableWidgetItem(display_value))
            self.param_table.setItem(row, 3, QTableWidgetItem(risk))
            self.param_table.setItem(row, 4, QTableWidgetItem(vuln_display))  # Vulnerabilities
            self.param_table.setItem(row, 5, QTableWidgetItem(meta_display))   # Metadata
            
        # Snap badge/fixed columns to content; cap Parameter to avoid over-wide column
        self.param_table.resizeColumnToContents(0)   # Location badge
        self.param_table.resizeColumnToContents(3)   # Risk badge
        # Cap Parameter (col 1): use content width but never exceed 200 px
        self.param_table.resizeColumnToContents(1)
        if self.param_table.columnWidth(1) > 200:
            self.param_table.setColumnWidth(1, 200)
        # Clamp Value (col 2) similarly
        self.param_table.resizeColumnToContents(2)
        if self.param_table.columnWidth(2) > 180:
            self.param_table.setColumnWidth(2, 180)
        # Clamp Vulnerabilities (col 4)
        self.param_table.resizeColumnToContents(4)
        if self.param_table.columnWidth(4) > 220:
            self.param_table.setColumnWidth(4, 220)
        # Sort rows: URL first, then ENDPOINT, then others, then HEADER last
        _loc_order = {"URL": 0, "BODY": 1, "JSON": 2,
                      "COOKIE": 3, "COOK": 3, "HTML": 4, "JS": 5, "RESP": 6,
                      "RESPONSE": 6, "FRM": 7, "FRAMEWORK": 7,
                      "END": 8, "ENDPOINT": 8, "HEADER": 9, "HDR": 9}
        rows_data = []
        for r in range(self.param_table.rowCount()):
            loc = (self.param_table.item(r, 0) or QTableWidgetItem("")).text()
            rows_data.append((_loc_order.get(loc.upper(), 5), r))
        rows_data.sort(key=lambda x: x[0])
        # Only re-insert if order differs
        if [x[1] for x in rows_data] != list(range(self.param_table.rowCount())):
            # Collect all row data
            all_rows = []
            for _, old_r in rows_data:
                row_items = [self.param_table.takeItem(old_r, c)
                             for c in range(self.param_table.columnCount())]
                all_rows.append(row_items)
            self.param_table.setRowCount(0)
            for row_items in all_rows:
                nr = self.param_table.rowCount()
                self.param_table.insertRow(nr)
                for c, item in enumerate(row_items):
                    if item:
                        self.param_table.setItem(nr, c, item)
    def _extract_parameter_values(self, finding: Dict) -> Dict:
        """Extract all parameter values from a finding"""
        values = {}
        
        if not finding:
            return values
        
        # Extract URL parameters
        url = finding.get('url', '')
        if '?' in url:
            query = url.split('?', 1)[1]
            params = query.split('&')
            for param in params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    values[f'URL {key}'] = value
                else:
                    values[f'URL {param}'] = ''
        
        # Try to extract from request file
        request_file = finding.get('request_file')
        if request_file and os.path.exists(request_file):
            try:
                with open(request_file, 'r', encoding='utf-8', errors='replace') as f:
                    request_text = f.read()
                    
                    # Extract headers
                    lines = request_text.split('\n')
                    for line in lines[1:]:  # Skip request line
                        if not line.strip() or line.strip() == '---':
                            break
                        if ':' in line:
                            key, value = line.split(':', 1)
                            values[f'HEADER {key.strip()}'] = value.strip()
                    
                    # Extract body parameters
                    if '\n\n' in request_text:
                        body = request_text.split('\n\n', 1)[1]
                        
                        # JSON body
                        if body.strip().startswith('{'):
                            try:
                                data = json.loads(body)
                                flat_data = self._flatten_json(data)
                                for key, value in flat_data.items():
                                    values[f'JSON {key}'] = str(value)
                            except:
                                pass
                        
                        # Form data (x-www-form-urlencoded)
                        elif '&' in body and '=' in body:
                            params = body.split('&')
                            for param in params:
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    values[f'BODY {key}'] = value
                        
                        # Multipart form data
                        elif 'Content-Disposition: form-data' in body:
                            # Simple extraction for multipart
                            parts = body.split('Content-Disposition: form-data')
                            for part in parts[1:]:  # Skip first empty
                                if 'name="' in part:
                                    start = part.find('name="') + 6
                                    end = part.find('"', start)
                                    if start > 5 and end > start:
                                        key = part[start:end]
                                        # Get value (after blank line)
                                        value_part = part.split('\n\n', 1)[1] if '\n\n' in part else ''
                                        value = value_part.split('\n')[0] if value_part else ''
                                        values[f'BODY {key}'] = value
            except:
                pass
        
        return values

    def _flatten_json(self, data: Any, prefix: str = '') -> Dict[str, Any]:
        """Flatten nested JSON structure"""
        result = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{prefix}.{key}" if prefix else key
                if isinstance(value, (dict, list)):
                    result.update(self._flatten_json(value, new_key))
                else:
                    result[new_key] = value
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{prefix}[{i}]"
                if isinstance(item, (dict, list)):
                    result.update(self._flatten_json(item, new_key))
                else:
                    result[new_key] = item
        
        return result

    def _get_parameter_value(self, full_param_name: str, param_name: str, location: str, param_values: Dict, finding: Dict = None):
        """Get the actual value for a parameter"""
        # Try exact match first
        if full_param_name in param_values:
            return param_values[full_param_name]
        
        # Try location + name
        location_key = f"{location} {param_name}"
        if location_key in param_values:
            return param_values[location_key]
        
        # Try just the name (without location prefix)
        if param_name in param_values:
            return param_values[param_name]
        
        # For RESPONSE location, check if it's in the detections
        if location == "RESPONSE":
            # Some response findings have values in the detections
            if finding and 'params' in finding:
                detections = finding['params'].get(full_param_name, [])
                for detection in detections:
                    if isinstance(detection, str) and ':' in detection:
                        # Check for value patterns like "VALUE: actual_value"
                        parts = detection.split(':', 1)
                        if len(parts) == 2 and parts[0].strip() in ['VALUE', 'KEY', 'DATA']:
                            return parts[1].strip()
        
        # For HEADER issues (like MISSING_CSP), show informational value
        if location == "HEADER" and param_name.startswith('MISSING_'):
            return "Header not present"
        elif location == "HEADER" and param_name.startswith('CORS_'):
            return "CORS misconfiguration"
        
        # For SQL errors, show sample
        if "SQL_ERROR" in param_name:
            return "SQL error message detected"
        
        # For API keys, show masked value
        if "EXPOSED" in param_name and finding and 'params' in finding:
            detections = finding['params'].get(full_param_name, [])
            for detection in detections:
                if isinstance(detection, str) and len(detection) > 10:
                    # Mask API keys for security
                    if detection.startswith('AKIA') or detection.startswith('ghp_'):
                        return f"{detection[:8]}...{detection[-4:]}"
                    return detection[:50] + "..." if len(detection) > 50 else detection
        
        return ""  # No value found

    def _get_full_parameter_value(self, param_name: str, location: str) -> str:
        """Get the full (non-truncated) value for a parameter"""
        if not hasattr(self, 'current_analysis_finding'):
            return ""
        
        finding = self.current_analysis_finding
        param_values = self._extract_parameter_values(finding)
        
        # Try different key formats
        keys_to_try = [
            f"{location} {param_name}",
            param_name,
            f"URL {param_name}" if "=" in param_name else param_name.split("=")[0] if "=" in param_name else param_name,
        ]
        
        for key in keys_to_try:
            if key in param_values:
                value = param_values[key]
                if value and value != "Header not present" and value != "CORS misconfiguration":
                    return value
        
        # Check in response findings
        if location == "RESPONSE" and 'params' in finding:
            for full_param, detections in finding['params'].items():
                if param_name in full_param:
                    for detection in detections:
                        if isinstance(detection, str) and ':' in detection:
                            parts = detection.split(':', 1)
                            if len(parts) == 2 and parts[1].strip():
                                return parts[1].strip()
        
        return ""

    def apply_smart_highlighting(self):
        """Apply smart highlighting to response"""
        # Check if we have a response text widget (from HTTP History tab)
        if not hasattr(self, 'response_text') or not self.response_text:
            QMessageBox.warning(self, "No Response", "Please select a request with a response")
            return
        
        # Get response text
        response_text = self.response_text.toPlainText()
        if not response_text:
            # Clear table if response is empty
            if hasattr(self, 'highlight_table'):
                self.highlight_table.setRowCount(0)
            self.highlight_stats.setText("○ Response is empty")
            return
        
        # Show progress
        self.highlight_stats.setText("↺ Detecting patterns...")
        QApplication.processEvents()
        
        # Detect patterns
        patterns_found = self._detect_highlight_patterns(response_text)
        
        if not patterns_found:
            # Clear table when no patterns detected
            if hasattr(self, 'highlight_table'):
                self.highlight_table.setRowCount(0)
            self.highlight_stats.setText("○ No patterns detected")
            return
        
        # Apply highlighting
        self._apply_highlighting_to_response_text(response_text, patterns_found)
        
        # Display results
        self._display_highlight_results(patterns_found)
        
        # Update stats
        total_matches = sum(len(matches) for matches in patterns_found.values())
        self.highlight_stats.setText(f"✓ {total_matches} patterns highlighted across {len(patterns_found)} types")

    def _apply_highlighting_to_response_text(self, response_text: str, patterns: Dict):
        """
        Apply highlighting to the response text widget
        """
        if not hasattr(self, 'response_text'):
            # Try to get it from parent
            if hasattr(self, 'rr_tabs'):
                # Get the response tab
                response_tab_index = 1  # Assuming Response tab is index 1
                response_widget = self.rr_tabs.widget(response_tab_index)
                if response_widget:
                    # Find the QTextEdit in response widget
                    text_edits = response_widget.findChildren(QTextEdit)
                    for te in text_edits:
                        if te.objectName() == "response_text" or "response" in te.objectName().lower():
                            self.response_text = te
                            break
            
            if not hasattr(self, 'response_text'):
                return  # Can't find response text widget
        
        cursor = self.response_text.textCursor()
        cursor.beginEditBlock()
        
        # Clear existing formatting first
        cursor.select(QTextCursor.Document)
        default_format = QTextCharFormat()
        default_format.setBackground(Qt.transparent)
        default_format.setForeground(QColor(COLORS.get('text_normal', '#BBBBBB')))
        cursor.setCharFormat(default_format)
        cursor.clearSelection()
        
        # Comprehensive color map for all pattern types
        color_map = {
            # CRITICAL - Red
            'AWS_KEY': QColor("#FF6B6B"),
            'GITHUB_TOKEN': QColor("#FF6B6B"),
            'SLACK_TOKEN': QColor("#FF6B6B"),
            'STRIPE_KEY': QColor("#FF6B6B"),
            'GOOGLE_API': QColor("#FF6B6B"),
            'MAILGUN_KEY': QColor("#FF6B6B"),
            'SENDGRID_KEY': QColor("#FF6B6B"),
            'TWILIO_KEY': QColor("#FF6B6B"),
            'FIREBASE_KEY': QColor("#FF6B6B"),
            'HEROKU_KEY': QColor("#FF6B6B"),
            'GENERIC_SECRETS': QColor("#FF6B6B"),
            'BEARER_TOKENS': QColor("#FF6B6B"),
            'SQL_ERRORS': QColor("#FF6B6B"),
            'RSA_PRIVATE_KEY': QColor("#FF6B6B"),
            'SSH_PRIVATE_KEY': QColor("#FF6B6B"),
            'PEM_PRIVATE_KEY': QColor("#FF6B6B"),
            'DSA_PRIVATE_KEY': QColor("#FF6B6B"),
            'EC_PRIVATE_KEY': QColor("#FF6B6B"),
            'MYSQL_CONN': QColor("#FF6B6B"),
            'POSTGRES_CONN': QColor("#FF6B6B"),
            'MONGODB_CONN': QColor("#FF6B6B"),
            'MSSQL_CONN': QColor("#FF6B6B"),
            
            # HIGH - Orange
            'INTERNAL_IPS': QColor("#FFA726"),
            'PUBLIC_IPS': QColor("#FFA726"),
            'PORTS': QColor("#FFA726"),
            'JWT_TOKENS': QColor("#FFA726"),
            'SESSION_IDS': QColor("#FFA726"),
            'FILE_PATHS': QColor("#FFA726"),
            'STACK_TRACES': QColor("#FFA726"),
            'URLS_WITH_CREDS': QColor("#FFA726"),
            'EXCEPTION_TYPES': QColor("#FFA726"),
            'S3_BUCKET': QColor("#FFA726"),
            'EC2_INSTANCE': QColor("#FFA726"),
            'AWS_ACCOUNT_ID': QColor("#FFA726"),
            'AWS_REGION': QColor("#FFA726"),
            'LAMBDA_ARN': QColor("#FFA726"),
            'DEBUG_INDICATORS': QColor("#FFA726"),
            'DEV_DOMAINS': QColor("#FFA726"),
            'SOURCE_MAPS': QColor("#FFA726"),
            'BACKUP_FILES': QColor("#FFA726"),
            'API_ENDPOINTS': QColor("#FFA726"),
            'DATABASE_NAMES': QColor("#FFA726"),
            'TABLE_NAMES': QColor("#FFA726"),
            
            # MEDIUM - Yellow
            'EMAILS': QColor("#FFEE58"),
            'PHONE_NUMBERS': QColor("#FFEE58"),
            'USERNAMES': QColor("#FFEE58"),
            'SOFTWARE_VERSIONS': QColor("#FFEE58"),
            'SERVER_HEADERS': QColor("#FFEE58"),
            'CREDIT_CARDS': QColor("#FFEE58"),
            'SENSITIVE_COMMENTS': QColor("#FFEE58"),
            'CONFIG_VALUES': QColor("#FFEE58"),
            'INTERNAL_HOSTS': QColor("#FFEE58"),
            'SUBDOMAINS': QColor("#FFEE58"),
        }
        
        # Get the full text
        full_text = self.response_text.toPlainText()
        
        for pattern_type, matches in patterns.items():
            color = color_map.get(pattern_type, QColor('#FFFF00'))
            
            for match in matches:
                # Find all occurrences
                start_pos = 0
                while True:
                    # Find the match (case insensitive)
                    idx = full_text.lower().find(match.lower(), start_pos)
                    if idx == -1:
                        break
                    
                    # Create format
                    fmt = QTextCharFormat()
                    fmt.setBackground(color)
                    # Use contrasting text color
                    if color.lightness() > 150:
                        fmt.setForeground(QColor('#000000'))
                    else:
                        fmt.setForeground(QColor('#FFFFFF'))
                    
                    # Apply to this occurrence
                    cursor.setPosition(idx)
                    cursor.setPosition(idx + len(match), QTextCursor.KeepAnchor)
                    cursor.mergeCharFormat(fmt)
                    
                    start_pos = idx + len(match)
        
        cursor.endEditBlock()
        self.response_text.setTextCursor(cursor)
    
    @staticmethod
    def _detect_highlight_patterns(text: str) -> Dict[str, List[str]]:
        """Detect comprehensive information leakage patterns"""
        patterns = {}
        
        # ========== CRITICAL PATTERNS ==========
        
        # API Keys (Expanded)
        api_patterns = {
            'AWS_KEY': r'AKIA[0-9A-Z]{16}',
            'GITHUB_TOKEN': r'ghp_[0-9a-zA-Z]{36}',
            'SLACK_TOKEN': r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
            'STRIPE_KEY': r'sk_live_[0-9a-zA-Z]{24,}',
            'GOOGLE_API': r'AIza[0-9A-Za-z\-_]{35}',
        }
        
        for name, pattern in api_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                patterns[name] = matches
        
        # Private Keys
        private_key_patterns = {
            'RSA_PRIVATE_KEY': r'-----BEGIN RSA PRIVATE KEY-----',
            'SSH_PRIVATE_KEY': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'PEM_PRIVATE_KEY': r'-----BEGIN PRIVATE KEY-----',
            'DSA_PRIVATE_KEY': r'-----BEGIN DSA PRIVATE KEY-----',
            'EC_PRIVATE_KEY': r'-----BEGIN EC PRIVATE KEY-----',
        }
        
        for name, pattern in private_key_patterns.items():
            if re.search(pattern, text):
                # Find the full key block
                key_match = re.search(pattern + r'.*?-----END[^-]+-----', text, re.DOTALL)
                if key_match:
                    patterns[name] = [key_match.group(0)[:100] + '...']
        
        # JWT Tokens
        jwt_matches = re.findall(r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*', text)
        if jwt_matches:
            patterns['JWT_TOKENS'] = jwt_matches
        
        # Database Connection Strings
        db_patterns = {
            'MYSQL_CONN': r'mysql://[^:]+:[^@]+@[\w.-]+',
            'POSTGRES_CONN': r'postgres://[^:]+:[^@]+@[\w.-]+',
            'MONGODB_CONN': r'mongodb://[^:]+:[^@]+@[\w.-]+',
            'MSSQL_CONN': r'Server=[\w.-]+.*?Password=[^;]+',
        }
        
        for name, pattern in db_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # Mask passwords
                masked = [m[:30] + '...[CREDENTIALS]...' for m in matches]
                patterns[name] = masked
        
        # SQL Errors
        sql_patterns = [
            r'You have an error in your SQL syntax',
            r'mysql_fetch',
            r'ORA-\d{5}',
            r'PostgreSQL.*?ERROR',
            r'SQLite.*?Exception',
        ]
        
        sql_matches = []
        for pattern in sql_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            sql_matches.extend(found)
        
        if sql_matches:
            patterns['SQL_ERRORS'] = sql_matches
        
        # ========== HIGH SEVERITY PATTERNS ==========
        
        # Internal IPs
        internal_ips = DataLeakageDetector.detect_internal_ips(text)
        if internal_ips:
            patterns['INTERNAL_IPS'] = internal_ips
        
        # File Paths (Unix & Windows) - Enhanced to catch more paths
        path_patterns = [
            # Unix absolute paths (more flexible)
            r'/(?:var|etc|usr|home|root|opt|tmp|bin|sbin|lib|srv)/[/\w.-]+',
            # Configuration files
            r'/etc/[/\w.-]+\.(?:ini|conf|cfg|yaml|yml|json|xml)',
            # Common executable paths
            r'/usr/(?:bin|sbin|local/bin|local/sbin)/[\w.-]+',
            # Windows paths
            r'[C-Z]:\\\\(?:Windows|Program Files|Users|inetpub)\\\\[\\w\\\\.-]+',
        ]
        
        all_paths = []
        for pattern in path_patterns:
            matches = re.findall(pattern, text)
            all_paths.extend(matches)
        
        # Remove duplicates and limit
        if all_paths:
            unique_paths = list(set(all_paths))
            # Sort by length (longer paths first, more specific)
            unique_paths.sort(key=len, reverse=True)
            patterns['FILE_PATHS'] = unique_paths[:15]  # Show top 15 paths
        
        # Stack Traces with Paths (Enhanced for Java, PHP, Python, .NET, etc.)
        stack_patterns = [
            # Java stack traces
            r'at [\w.$]+\.[\w]+\([^)]*\)',  # at package.Class.method(File.java:123) or (Unknown Source)
            r'Caused by:.*?Exception.*',     # Caused by: java.lang.Exception
            r'Exception in thread.*',        # Exception in thread "main"
            
            # Python stack traces
            r'File "[^"]+\.py", line \d+.*',
            r'Traceback \(most recent call last\):',
            
            # PHP stack traces  
            r'#\d+\s+[^\n]+\.php\(\d+\):.*',
            r'in [^:]+\.php on line \d+',
            
            # .NET stack traces
            r'at [^\n]+\.cs:line \d+',
            r'at [^\n]+in [^\n]+\.cs:line \d+',
            
            # Node.js stack traces
            r'at [^\n]+\.js:\d+:\d+',
            
            # Ruby stack traces
            r'from [^\n]+\.rb:\d+:',
        ]
        
        stack_matches = []
        for pattern in stack_patterns:
            found = re.findall(pattern, text)
            stack_matches.extend(found)
        
        # Also detect complete Java stack trace blocks
        if 'at java.' in text or 'at javax.' in text or '(Unknown Source)' in text:
            # Count lines that look like Java stack trace
            java_stack_lines = re.findall(r'^\s*at [\w.$]+\.[\w]+\([^)]*\)', text, re.MULTILINE)
            if len(java_stack_lines) >= 3:  # If 3+ lines, it's definitely a stack trace
                stack_matches.append(f"Java Stack Trace ({len(java_stack_lines)} lines)")
        
        if stack_matches:
            # Remove duplicates and limit
            unique_stacks = list(set(stack_matches))[:10]  # Increased limit to 10
            patterns['STACK_TRACES'] = unique_stacks
        
        # Error Messages (5xx, Exceptions, Internal Errors)
        error_patterns = [
            r'(?:Internal Server Error|500 Internal Server Error)',
            r'(?:java\.lang\.\w+Exception):.*',
            r'(?:System\.\w+Exception):.*',
            r'(?:Fatal error|Warning|Parse error):.*',
            r'(?:RuntimeError|TypeError|ValueError|AttributeError):.*',
            r'(?:Error|Exception):\s+[^\n]+',
        ]
        
        error_matches = []
        for pattern in error_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            error_matches.extend(found[:3])  # Limit to 3 per pattern type
        
        if error_matches:
            patterns['ERROR_MESSAGES'] = list(set(error_matches))[:5]  # Limit to 5 total
        
        # Software Versions (Comprehensive - includes Apache Struts)
        version_patterns = {
            # Web Servers
            'PHP': r'PHP[/\s]?\d+\.\d+\.\d+(?:-\d+ubuntu\d+\.\d+)?',
            'APACHE_HTTPD': r'Apache[/\s]?\d+\.\d+(?:\.\d+)?(?:\s+\([^)]+\))?',
            'NGINX': r'nginx[/\s]?\d+\.\d+(?:\.\d+)?',
            'IIS': r'IIS[/\s]?\d+\.\d+(?:\.\d+)?',
            
            # Databases
            'MYSQL': r'MySQL\s+\d+\.\d+(?:\.\d+)?',
            'POSTGRESQL': r'PostgreSQL\s+\d+\.\d+(?:\.\d+)?',
            'MONGODB': r'MongoDB\s+\d+\.\d+(?:\.\d+)?',
            'ORACLE': r'Oracle\s+Database\s+\d+c?',
            
            # Java Frameworks & Servers (ENHANCED)
            'TOMCAT': r'(?:Apache\s+)?Tomcat[/\s]?\d+\.\d+(?:\.\d+)?',
            'STRUTS': r'(?:Apache\s+)?Struts\s+\d+(?:\s+\d+\.\d+(?:\.\d+)?)?',
            'SPRING': r'Spring\s+(?:Framework\s+)?\d+\.\d+(?:\.\d+)?',
            'JBOSS': r'JBoss[/\s]?\d+\.\d+(?:\.\d+)?',
            'WEBLOGIC': r'WebLogic\s+(?:Server\s+)?\d+\.\d+(?:\.\d+)?(?:c)?',
            'WILDFLY': r'WildFly\s+\d+\.\d+(?:\.\d+)?',
            'JETTY': r'Jetty[/\s]?\d+\.\d+(?:\.\d+)?',
            'GLASSFISH': r'GlassFish\s+(?:Server\s+)?\d+\.\d+(?:\.\d+)?',
            
            # Python Frameworks
            'DJANGO': r'Django[/\s]?\d+\.\d+(?:\.\d+)?',
            'FLASK': r'Flask[/\s]?\d+\.\d+(?:\.\d+)?',
            'PYRAMID': r'Pyramid\s+\d+\.\d+(?:\.\d+)?',
            
            # Ruby/Rails
            'RAILS': r'Rails\s+\d+\.\d+(?:\.\d+)?',
            'RUBY': r'Ruby\s+\d+\.\d+(?:\.\d+)?',
            
            # JavaScript/Node
            'EXPRESS': r'Express[/\s]?\d+\.\d+(?:\.\d+)?',
            'NODEJS': r'Node\.js[/\s]?v?\d+\.\d+(?:\.\d+)?',
            
            # .NET
            'ASPNET': r'ASP\.NET\s+(?:Core\s+)?\d+\.\d+(?:\.\d+)?',
            'DOTNET': r'\.NET\s+(?:Framework\s+|Core\s+)?\d+\.\d+(?:\.\d+)?',
            
            # CMS/Platforms
            'WORDPRESS': r'WordPress\s+\d+\.\d+(?:\.\d+)?',
            'JOOMLA': r'Joomla!\s+\d+\.\d+(?:\.\d+)?',
            'DRUPAL': r'Drupal\s+\d+\.\d+(?:\.\d+)?',
            
            # Libraries (flexible patterns for phpinfo, error messages, etc.)
            'OPENSSL': r'OpenSSL(?:\s+Library Version|\s+Header Version)?[:\s]+\d+\.\d+\.\d+[a-z]?',
            'LIBXML': r'libxml(?:\s+Version|\s+Compiled Version|\s+Loaded Version)?[:\s]+\d+\.\d+\.\d+',
            'ZLIB': r'zlib(?:\s+Version)?[:\s]+\d+\.\d+\.\d+',
            'CURL': r'cURL(?:\s+Version)?[/\s:]+\d+\.\d+\.\d+',
            'PCRE': r'PCRE(?:\s+Library Version)?[:\s]+\d+\.\d+',
            'ZEND_ENGINE': r'Zend\s+Engine\s+v?\d+\.\d+\.\d+',
            'LINUX_KERNEL': r'Linux\s+[\w.-]+\s+\d+\.\d+\.\d+[\w.-]*',
            'IIS_VERSION': r'Microsoft-IIS[/\s]?\d+\.\d+',
            'ASPNET_VERSION': r'ASP\.NET\s+\d+\.\d+(?:\.\d+)?',
        }
        
        all_versions = []
        for name, pattern in version_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            # Clean up matches - extract just the key part
            for match in matches:
                # Keep the full match but normalize it
                cleaned = match.strip()
                all_versions.append(cleaned)
        
        if all_versions:
            # Remove duplicates while preserving order
            seen = set()
            unique_versions = []
            for v in all_versions:
                if v not in seen:
                    seen.add(v)
                    unique_versions.append(v)
            patterns['SOFTWARE_VERSIONS'] = unique_versions
        
        # ========== MEDIUM SEVERITY PATTERNS ==========
        
        # Emails
        emails = DataLeakageDetector.detect_emails(text)
        if emails:
            patterns['EMAILS'] = emails
        
        # Credit Card Numbers (Basic validation)
        cc_matches = re.findall(r'(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', text)
        if cc_matches:
            # Mask most digits
            masked_cc = [cc[:4] + ' **** **** ' + cc[-4:] for cc in cc_matches]
            patterns['CREDIT_CARDS'] = masked_cc
        
        # Session IDs
        session_patterns = {
            'PHPSESSID': r'PHPSESSID=[a-zA-Z0-9]{26,}',
            'ASP_SESSION': r'ASP\.NET_SessionId=[a-zA-Z0-9]{24,}',
            'JSESSIONID': r'JSESSIONID=[A-Z0-9]{32,}',
        }
        
        all_sessions = []
        for name, pattern in session_patterns.items():
            matches = re.findall(pattern, text)
            all_sessions.extend(matches)
        
        if all_sessions:
            patterns['SESSION_IDS'] = all_sessions[:5]  # Limit to 5
        
        # URLs with Credentials
        url_cred_matches = re.findall(r'https?://[^:]+:[^@]+@[\w.-]+', text)
        if url_cred_matches:
            # Mask credentials
            masked_urls = [re.sub(r'://[^:]+:[^@]+@', '://[USER]:[PASS]@', url) for url in url_cred_matches]
            patterns['URLS_WITH_CREDS'] = masked_urls
        
        # Sensitive Comments
        comment_patterns = [
            r'(?://|#|\*)\s*(?:TODO|FIXME|HACK|XXX|BUG):\s*[^\n]{10,}',
            r'(?://|#|\*)\s*(?:password|passwd|pwd|secret|key):\s*[^\n]{5,}',
        ]
        
        comment_matches = []
        for pattern in comment_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            comment_matches.extend(found)
        
        if comment_matches:
            patterns['SENSITIVE_COMMENTS'] = comment_matches[:5]  # Limit to 5
        
        # Internal Hostnames
        hostname_matches = re.findall(r'(?:dev|test|stage|staging|internal|admin|backend)[\w-]*\.[\w.-]+', text, re.IGNORECASE)
        if hostname_matches:
            patterns['INTERNAL_HOSTS'] = list(set(hostname_matches))[:10]
        

        # ========== SERVER & TECHNOLOGY HEADERS (NEW) ==========
        
        # Server Headers
        server_headers = {
            'X-POWERED-BY': r'X-Powered-By:\s*([^\r\n]+)',
            'SERVER_HEADER': r'Server:\s*([^\r\n]+)',
            'X-ASPNET-VERSION': r'X-AspNet-Version:\s*([^\r\n]+)',
            'X-ASPNETMVC-VERSION': r'X-AspNetMvc-Version:\s*([^\r\n]+)',
            'X-GENERATOR': r'X-Generator:\s*([^\r\n]+)',
        }
        
        header_matches = []
        for name, pattern in server_headers.items():
            found = re.findall(pattern, text, re.IGNORECASE)
            header_matches.extend(found)
        
        if header_matches:
            patterns['SERVER_HEADERS'] = list(set(header_matches))
        
        # ========== DEVELOPMENT ARTIFACTS (NEW) ==========
        
        # Debug Mode Indicators
        debug_patterns = [
            r'debug[=:]\s*(?:true|1|on|yes|enabled)',
            r'DEBUG_MODE\s*=\s*(?:true|1|on)',
            r'development\s+mode',
            r'RAILS_ENV\s*=\s*development',
            r'NODE_ENV\s*=\s*development',
        ]
        
        debug_matches = []
        for pattern in debug_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            debug_matches.extend(found)
        
        if debug_matches:
            patterns['DEBUG_INDICATORS'] = list(set(debug_matches))[:5]
        
        # Development/Staging Domains
        dev_domains = re.findall(r'(?:dev|staging|test|qa|uat|preprod)[\w-]*\.[\w.-]+\.\w{2,}', text, re.IGNORECASE)
        if dev_domains:
            patterns['DEV_DOMAINS'] = list(set(dev_domains))[:10]
        
        # Source Maps
        sourcemap_matches = re.findall(r'[/\w.-]+\.(?:js|css)\.map', text)
        if sourcemap_matches:
            patterns['SOURCE_MAPS'] = list(set(sourcemap_matches))[:10]
        
        # Backup Files
        backup_files = re.findall(r'[/\w.-]+\.(?:bak|backup|old|tmp|save|copy|orig)(?:["\s]|$)', text, re.IGNORECASE)
        if backup_files:
            patterns['BACKUP_FILES'] = list(set(backup_files))[:10]
        
        # ========== CLOUD RESOURCES (NEW) ==========
        
        # AWS Resources
        aws_resources = {
            'S3_BUCKET': r's3://[\w.-]+',
            'EC2_INSTANCE': r'i-[0-9a-f]{8,17}',
            'AWS_ACCOUNT_ID': r'\b\d{12}\b',
            'AWS_REGION': r'(?:us|eu|ap|sa|ca|me|af)-(?:east|west|central|south|north|northeast|southeast)-\d',
            'LAMBDA_ARN': r'arn:aws:lambda:[\w-]+:\d+:function:[\w-]+',
        }
        
        for name, pattern in aws_resources.items():
            matches = re.findall(pattern, text)
            if matches:
                patterns[name] = list(set(matches))[:10]
        
        # ========== API ENDPOINTS & ROUTES (NEW) ==========
        
        # API Endpoints
        api_endpoints = re.findall(r'(?:/api/v?\d+/[\w/-]+|/graphql|/rest/[\w/-]+)', text, re.IGNORECASE)
        if api_endpoints:
            patterns['API_ENDPOINTS'] = list(set(api_endpoints))[:20]
        
        # ========== MORE API KEYS (EXPAND) ==========
        
        # Additional API Key Patterns
        more_api_keys = {
            'MAILGUN_KEY': r'key-[0-9a-zA-Z]{32}',
            'SENDGRID_KEY': r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
            'TWILIO_KEY': r'SK[0-9a-fA-F]{32}',
            'FIREBASE_KEY': r'AIza[0-9A-Za-z\-_]{35}',
            'HEROKU_KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        }
        
        for name, pattern in more_api_keys.items():
            matches = re.findall(pattern, text)
            if matches:
                patterns[name] = matches
        
        # Generic Secret Patterns
        generic_secrets = re.findall(r'(?:api_key|apikey|secret|token|password|passwd|pwd)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,})["\']?', text, re.IGNORECASE)
        if generic_secrets:
            patterns['GENERIC_SECRETS'] = list(set(generic_secrets))[:10]
        
        # Bearer Tokens
        bearer_tokens = re.findall(r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', text, re.IGNORECASE)
        if bearer_tokens:
            patterns['BEARER_TOKENS'] = list(set(bearer_tokens))[:5]
        
        # ========== DATABASE REFERENCES (NEW) ==========
        
        # Database Names
        db_names = re.findall(r'(?:database|db|schema)\s*[=:]\s*["\']?(\w+)["\']?', text, re.IGNORECASE)
        if db_names:
            # Filter out common words
            filtered_dbs = [db for db in db_names if db.lower() not in ['true', 'false', 'null', 'none', 'default', 'test']]
            if filtered_dbs:
                patterns['DATABASE_NAMES'] = list(set(filtered_dbs))[:10]
        
        # Table Names (SQL queries)
        table_names = re.findall(r'(?:FROM|JOIN|INTO|UPDATE)\s+`?(\w+)`?', text, re.IGNORECASE)
        if table_names:
            filtered_tables = [t for t in table_names if len(t) > 3]
            if filtered_tables:
                patterns['TABLE_NAMES'] = list(set(filtered_tables))[:15]
        
        # ========== PHONE NUMBERS (NEW) ==========
        
        # International phone numbers
        phone_patterns = [
            r'\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}',
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
        ]
        
        phone_matches = []
        for pattern in phone_patterns:
            found = re.findall(pattern, text)
            phone_matches.extend(found)
        
        if phone_matches:
            patterns['PHONE_NUMBERS'] = list(set(phone_matches))[:10]
        
        # ========== USERNAMES (NEW) ==========
        
        # Username patterns
        username_patterns = re.findall(r'(?:username|user|login|account)\s*[=:]\s*["\']?(\w{3,20})["\']?', text, re.IGNORECASE)
        if username_patterns:
            patterns['USERNAMES'] = list(set(username_patterns))[:10]
        
        # ========== SENSITIVE COMMENTS (EXPANDED) ==========
        
        # More comprehensive comment patterns
        enhanced_comments = [
            r'(?://|#|/\*|\*)\s*(?:TODO|FIXME|HACK|XXX|BUG|NOTE):\s*[^\n]{10,}',
            r'(?://|#|/\*|\*)\s*(?:password|passwd|pwd|secret|key|token)\s*[=:]\s*[^\n]{5,}',
            r'(?://|#|/\*|\*)\s*(?:remove|delete|disable|temporary|temp|test)\s+(?:before|in)\s+(?:production|prod)[^\n]*',
            r'(?://|#|/\*|\*)\s*(?:admin|root|default)\s+(?:password|pwd|credentials)[^\n]*',
            r'(?://|#|/\*|\*)\s*(?:hardcoded|hard-coded|hard coded)[^\n]*',
        ]
        
        enhanced_comment_matches = []
        for pattern in enhanced_comments:
            found = re.findall(pattern, text, re.IGNORECASE)
            enhanced_comment_matches.extend(found)
        
        if enhanced_comment_matches:
            patterns['SENSITIVE_COMMENTS'] = list(set(enhanced_comment_matches))[:10]
        
        # ========== CONFIGURATION VALUES (NEW) ==========
        
        # Timeout and limit configurations
        config_patterns = re.findall(r'(?:timeout|max_|min_|limit)\w*\s*[=:]\s*(\d+)', text, re.IGNORECASE)
        if config_patterns:
            patterns['CONFIG_VALUES'] = list(set(config_patterns))[:10]
        
        # ========== SUBDOMAINS (NEW) ==========
        
        # Extract subdomains
        subdomain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,}[a-z]{2,}\b'
        subdomains = re.findall(subdomain_pattern, text, re.IGNORECASE)
        if subdomains:
            # Filter out common public domains
            filtered_subs = [s for s in subdomains if not any(x in s.lower() for x in ['google.com', 'facebook.com', 'twitter.com', 'github.com', 'w3.org'])]
            if filtered_subs:
                patterns['SUBDOMAINS'] = list(set(filtered_subs))[:15]
        
        # ========== IP ADDRESSES (EXPAND) ==========
        
        # Public IP addresses (in addition to internal)
        public_ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', text)
        if public_ips:
            # Filter out internal IPs (they're in INTERNAL_IPS)
            filtered_public = [ip for ip in public_ips if not any(ip.startswith(prefix) for prefix in ['10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.'])]
            if filtered_public:
                patterns['PUBLIC_IPS'] = list(set(filtered_public))[:10]
        
        # ========== PORTS (NEW) ==========
        
        # Port numbers in URLs or configs
        port_patterns = re.findall(r':(\d{2,5})(?:/|\\s|$)', text)
        if port_patterns:
            # Filter common ports, keep interesting ones
            interesting_ports = [p for p in port_patterns if p not in ['80', '443', '22', '21']]
            if interesting_ports:
                patterns['PORTS'] = list(set(interesting_ports))[:10]

        # ========== SENSITIVE API RESPONSE DATA (JSON body) ==========

        # Generic API key / token field names found in a JSON response body
        _api_key_re = [
            r'"api[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"apikey"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"app[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"secret[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"client[_-]?secret"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"private[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"access[_-]?key"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
        ]
        _api_key_vals = []
        for _p in _api_key_re:
            for _m in re.findall(_p, text, re.IGNORECASE):
                _api_key_vals.append(_m[:80])
        if _api_key_vals:
            patterns['GENERIC_API_KEY'] = _api_key_vals[:10]

        # OAuth / access / auth / id tokens in JSON
        _token_re = [
            r'"access[_-]?token"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
            r'"refresh[_-]?token"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
            r'"auth(?:orization)?[_-]?token"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
            r'"id[_-]?token"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
            r'"bearer"\s*:\s*"([a-zA-Z0-9_\-\.]{20,})"',
        ]
        _auth_vals = []
        for _p in _token_re:
            for _m in re.findall(_p, text, re.IGNORECASE):
                _auth_vals.append(_m[:80])
        if _auth_vals:
            patterns['AUTH_TOKENS'] = _auth_vals[:10]

        # Session tokens — array form ("sessions": [...]) and field form
        _session_vals = []
        for _arr in re.findall(r'"sessions?"\s*:\s*\[([^\]]*)\]', text, re.IGNORECASE | re.DOTALL):
            for _tok in re.findall(r'"([a-zA-Z0-9_\-]{16,})"', _arr):
                _session_vals.append(_tok[:80])
        for _p in [
            r'"session[_-]?(?:token|id|key)"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"sessionId"\s*:\s*"([a-zA-Z0-9_\-]{16,})"',
            r'"[Ss]id"\s*:\s*"([a-zA-Z0-9_\-]{20,})"',
        ]:
            _session_vals.extend(re.findall(_p, text, re.IGNORECASE))
        if _session_vals:
            patterns['SESSION_TOKENS'] = list(dict.fromkeys(_session_vals))[:10]

        # Sensitive user / account fields in JSON API responses
        _user_field_re = re.compile(
            r'"(username|user_name|email|account_id|phone|address|full_name|displayname)"'
            r'\s*:\s*"([^"]{1,100})"',
            re.IGNORECASE,
        )
        _user_vals = []
        for _m in _user_field_re.finditer(text):
            _val = _m.group(2).strip()
            if _val:
                _user_vals.append(f'{_m.group(1)}: {_val[:60]}')
        if _user_vals:
            patterns['SENSITIVE_USER_DATA'] = _user_vals

        # ========== EXPRESSION LANGUAGE / TEMPLATE INJECTION ==========
        # Detect SSTI/EL patterns: ${...}, #{...}, %{...}, {{...}}, Freemarker, Velocity, SpEL, OGNL
        _el_regexes = [
            r'\$\{[^}]{1,100}\}',                  # ${7*7} -- EL, SpEL, Freemarker, JSP
            r'#\{[^}]{1,100}\}',                   # #{7*7} -- SpEL, Thymeleaf
            r'%\{[^}]{1,100}\}',                   # %{7*7} -- OGNL (Struts 2)
            r'\{\{[^}]{1,100}\}\}',               # {{7*7}} -- Twig/Jinja2/Angular/Mustache
            r'<#[a-z][^>]{0,60}>',                 # <#if ...> -- Freemarker directives
            r'#set\s*\(\s*\$\w+\s*=',            # #set($var = ...) -- Velocity
            r'T\s*\(\s*java\.',                    # T(java.lang.Runtime) -- SpEL type expr
            r'@java\.lang\.',                      # @java.lang.Runtime@ -- OGNL static
        ]
        _el_vals = []
        for _p in _el_regexes:
            for _m in re.findall(_p, text, re.IGNORECASE | re.DOTALL):
                _clean = str(_m).strip()
                if _clean not in _el_vals:
                    _el_vals.append(_clean[:100])
        if _el_vals:
            patterns['EL_INJECTION'] = _el_vals[:15]

        # ========== INSECURE DESERIALIZATION SIGNATURES ==========
        _deser_sigs = []
        # Java serialized object: rO0 (base64 prefix for \xac\xed\x00\x05)
        if re.search(r'rO0AB[A-Za-z0-9+/=]{4,}', text):
            _deser_sigs.append('Java serialized object (rO0 base64 prefix detected)')
        # Java raw hex magic
        if re.search(r'aced0005', text, re.IGNORECASE):
            _deser_sigs.append('Java serialized bytes (ac ed 00 05 magic header)')
        # PHP serialized objects: O:4:"User":1:{...}
        for _pm in re.findall(r'O:\d+:"[^"]{1,40}":\d+:\{', text)[:3]:
            _deser_sigs.append(f'PHP serialized object: {_pm[:60]}')
        # PHP serialized arrays: a:2:{i:0;s:5:"hello";}
        if re.search(r'\ba:\d+:\{(?:i:\d+;|s:\d+:)', text):
            _deser_sigs.append('PHP serialized array (a:N:{...} pattern)')
        # Python pickle protocol markers (escaped in HTTP contexts)
        if re.search(r'\\x80\\x0[2-5]', text):
            _deser_sigs.append('Python pickle protocol marker')
        # Known Java gadget chain references (ysoserial etc.)
        if re.search(
            r'ysoserial|CommonsCollections|CommonsBeanutils|Spring(?:Hibernate)?4Shell',
            text, re.IGNORECASE
        ):
            _deser_sigs.append('Java deser gadget chain reference (ysoserial/CommonsCollections)')
        if _deser_sigs:
            patterns['INSECURE_DESER'] = _deser_sigs[:10]

        # ========== PROTOTYPE POLLUTION ==========
        # __proto__, constructor.prototype, etc. in POST body / JSON
        _proto_vals = []
        for _p in [
            r'__proto__',
            r'constructor\.prototype',
            r'__defineGetter__',
            r'__defineSetter__',
            r'__lookupGetter__',
            r'\["__proto__"\]',
            r"prototype\[['\"]]\w+['\"]\]",
        ]:
            for _m in re.findall(_p, text, re.IGNORECASE):
                if _m not in _proto_vals:
                    _proto_vals.append(_m[:80])
        if _proto_vals:
            patterns['PROTO_POLLUTION'] = _proto_vals[:10]

        # ========== CACHE POISONING INDICATORS ==========
        # Surface caching-layer headers and unkeyed input headers in one place
        _cache_indicators = []
        for _ch, _rx in [
            ('X-Cache',         r'X-Cache:\s*([^\r\n]+)'),
            ('CF-Cache-Status', r'CF-Cache-Status:\s*([^\r\n]+)'),
            ('X-Varnish',       r'X-Varnish:\s*([^\r\n]+)'),
            ('X-Proxy-Cache',   r'X-Proxy-Cache:\s*([^\r\n]+)'),
            ('Age',             r'\bAge:\s*(\d+)'),
            ('Via',             r'Via:\s*([^\r\n]+)'),
        ]:
            _m2 = re.search(_rx, text, re.IGNORECASE)
            if _m2:
                _cache_indicators.append(f'{_ch}: {_m2.group(1)[:60]}')
        for _uh in [
            'x-forwarded-host', 'x-original-url', 'x-rewrite-url',
            'x-forwarded-prefix', 'x-host'
        ]:
            if re.search(rf'(?i){re.escape(_uh)}\s*:', text):
                _cache_indicators.append(f'Unkeyed request header: {_uh}')
        if _cache_indicators:
            patterns['CACHE_POISONING'] = _cache_indicators[:10]

        return patterns

    def _display_highlight_results(self, patterns: Dict):
        """Display highlighting results - ONE ROW PER INDIVIDUAL ITEM"""
        self.highlight_table.setRowCount(0)
        
        # Comprehensive severity mapping
        critical_patterns = [
            'AWS_KEY', 'GITHUB_TOKEN', 'SLACK_TOKEN', 'STRIPE_KEY', 'GOOGLE_API',
            'MAILGUN_KEY', 'SENDGRID_KEY', 'TWILIO_KEY', 'FIREBASE_KEY', 'HEROKU_KEY',
            'GENERIC_SECRETS', 'BEARER_TOKENS', 'ENV_SECRETS',
            'RSA_PRIVATE_KEY', 'SSH_PRIVATE_KEY', 'PEM_PRIVATE_KEY',
            'DSA_PRIVATE_KEY', 'EC_PRIVATE_KEY',
            'MYSQL_CONN', 'POSTGRES_CONN', 'MONGODB_CONN', 'MSSQL_CONN',
            'SQL_ERRORS',
            'GENERIC_API_KEY', 'AUTH_TOKENS',
            'INSECURE_DESER',                           # NEW: critical RCE risk
        ]

        high_patterns = [
            'INTERNAL_IPS', 'PUBLIC_IPS', 'PORTS',
            'JWT_TOKENS', 'SESSION_IDS', 'URLS_WITH_CREDS',
            'FILE_PATHS', 'STACK_TRACES', 'EXCEPTION_TYPES',
            'S3_BUCKET', 'EC2_INSTANCE', 'AWS_ACCOUNT_ID', 'AWS_REGION', 'LAMBDA_ARN',
            'DEBUG_INDICATORS', 'DEV_DOMAINS', 'SOURCE_MAPS', 'BACKUP_FILES',
            'API_ENDPOINTS', 'DATABASE_NAMES', 'TABLE_NAMES',
            'SESSION_TOKENS',
            'EL_INJECTION', 'PROTO_POLLUTION',          # NEW: injection findings
        ]

        medium_patterns = [
            'SOFTWARE_VERSIONS', 'SERVER_HEADERS',
            'EMAILS', 'PHONE_NUMBERS', 'USERNAMES', 'CREDIT_CARDS',
            'SENSITIVE_COMMENTS', 'CONFIG_VALUES',
            'INTERNAL_HOSTS', 'SUBDOMAINS',
            'SENSITIVE_USER_DATA',
            'CACHE_POISONING',                          # NEW: cache indicators
        ]

        # Display EACH individual finding as a separate row
        for pattern_type, matches in patterns.items():
            # Determine severity
            if pattern_type in critical_patterns:
                severity = "● CRITICAL"
            elif pattern_type in high_patterns:
                severity = "▲ HIGH"
            elif pattern_type in medium_patterns:
                severity = "◆ MEDIUM"
            else:
                severity = "○ INFO"
            
            # Add a row for EACH individual match
            for match in matches:
                row = self.highlight_table.rowCount()
                self.highlight_table.insertRow(row)
                
                # Truncate long values for display
                display_value = match[:80] if len(match) > 80 else match
                
                self.highlight_table.setItem(row, 0, QTableWidgetItem(pattern_type))
                self.highlight_table.setItem(row, 1, QTableWidgetItem("1"))  # Count is always 1 per row
                self.highlight_table.setItem(row, 2, QTableWidgetItem(severity))
                self.highlight_table.setItem(row, 3, QTableWidgetItem(display_value))
        
        self.highlight_table.resizeColumnsToContents()
        # update badge
        hcount = self.highlight_table.rowCount()
        if hasattr(self, 'leak_count_badge'):
            self.leak_count_badge.setText(f"{hcount} finding{'s' if hcount != 1 else ''}")
            self.leak_count_badge.setStyleSheet(
                f"color: {'#e05858' if hcount else '#888'}; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )
    
    def filter_parameters(self, filter_text: str):
        """Filter parameter table"""
        for row in range(self.param_table.rowCount()):
            location = self.param_table.item(row, 0).text()
            
            if filter_text == "All Locations":
                self.param_table.setRowHidden(row, False)
            elif filter_text == "URL Only":
                self.param_table.setRowHidden(row, location != "URL")
            elif filter_text == "Headers Only":
                self.param_table.setRowHidden(row, location != "HEADER")
            elif filter_text == "Body Only":
                self.param_table.setRowHidden(row, location not in ["BODY", "JSON"])
            elif filter_text == "Cookies Only":
                self.param_table.setRowHidden(row, location != "COOKIE")
    
    def _load_request_text(self, finding: Dict) -> str:
        """Load request text from finding"""
        request_file = finding.get('request_file')
        if request_file and os.path.exists(request_file):
            try:
                with open(request_file, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            except:
                pass
        return ""
    
    def _load_response_text(self, finding: Dict) -> str:
        """Load response text from finding"""
        response_file = finding.get('response_file')
        if response_file and os.path.exists(response_file):
            try:
                with open(response_file, 'r', encoding='utf-8', errors='replace') as f:
                    return f.read()
            except:
                pass
        return ""


    def _clear_analysis_display(self):
        """Wipe all analysis UI panels so no stale data from the previous request shows."""
        if hasattr(self, 'param_table'):
            self.param_table.setRowCount(0)
        if hasattr(self, 'param_count_badge'):
            self.param_count_badge.setText("…")
            self.param_count_badge.setStyleSheet(
                "color: #888; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )
        if hasattr(self, 'vuln_text'):
            self.vuln_text.setHtml("")
        if hasattr(self, 'vuln_stats_label'):
            self.vuln_stats_label.setText("")
        if hasattr(self, 'current_vuln_params'):
            self.current_vuln_params = {}
        if hasattr(self, 'highlight_table'):
            self.highlight_table.setRowCount(0)
        if hasattr(self, 'leak_count_badge'):
            self.leak_count_badge.setText("…")
            self.leak_count_badge.setStyleSheet(
                "color: #888; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )

    def perform_automatic_analysis(self, finding: Dict):
        """
        Perform automatic analysis when a request is selected.
        Debounced (400 ms) so rapid row-clicks don't spawn multiple workers.
        """
        if not hasattr(self, 'auto_analyze') or not self.auto_analyze.isChecked():
            return None

        # Always update pending finding immediately so stale checks work
        self._pending_analysis_finding = finding
        self.current_analysis_finding  = finding

        # Clear stale data from the previous request immediately
        self._clear_analysis_display()

        # Debounce: restart a single-shot timer; the actual worker launch
        # happens in _do_launch_analysis_worker 400 ms after the last call.
        if not hasattr(self, '_analysis_debounce_timer'):
            self._analysis_debounce_timer = QTimer(self)
            self._analysis_debounce_timer.setSingleShot(True)
            self._analysis_debounce_timer.timeout.connect(self._do_launch_analysis_worker)
        self._analysis_debounce_timer.start(400)

        return None

    def _do_launch_analysis_worker(self):
        """Actual worker launch — called by the debounce timer."""
        finding = getattr(self, '_pending_analysis_finding', None)
        if finding is None:
            return
        if not hasattr(self, 'auto_analyze') or not self.auto_analyze.isChecked():
            return

        # Skip auto-analysis for very large responses to avoid long regex runs
        _MAX_AUTO_BYTES = 3 * 1024 * 1024  # 3 MB
        resp_file = finding.get('response_file', '')
        if resp_file and os.path.exists(resp_file):
            size = os.path.getsize(resp_file)
            if size > _MAX_AUTO_BYTES:
                mb = size / 1024 / 1024
                self.auto_analyze.setText(f"↺ Auto (skip >{mb:.1f} MB)")
                return
        # Cancel any previous worker still running
        prev = getattr(self, '_selection_analysis_worker', None)
        if prev is not None and prev.isRunning():
            try:
                prev.finished.disconnect()
            except Exception:
                pass
            prev.cancel_flag = True
            prev.quit()  # signal thread loop; cancel_flag drops the result

        # Reset param badge + table immediately so stale counts don't linger
        if hasattr(self, 'param_count_badge'):
            self.param_count_badge.setText("…")
            self.param_count_badge.setStyleSheet(
                "color: #888; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )
        if hasattr(self, 'param_table'):
            self.param_table.setRowCount(0)

        self.auto_analyze.setText("↺ Analyzing…")

        worker = SelectionAnalysisWorker(finding)
        worker.finished.connect(self._on_selection_analysis_finished)
        worker.error.connect(lambda msg: self.auto_analyze.setText("↺ Auto"))
        worker.start()
        self._selection_analysis_worker = worker

    def _on_selection_analysis_finished(self, finding: dict, analysis_results: dict):
        """
        Called on the main thread when SelectionAnalysisWorker is done.
        Performs all UI updates that were previously inside
        perform_automatic_analysis.
        """
        # Discard stale results if the user already selected a different row
        if getattr(self, '_pending_analysis_finding', None) is not finding:
            return

        # Store results
        self.last_analysis_results = analysis_results

        # Update finding in-place so the rest of the UI sees the results
        finding['params']   = analysis_results['params']
        finding['severity'] = analysis_results['severity']
        finding['analyzed'] = True

        # Auto-save detections to project recordings
        self._auto_save_recording(finding, analysis_results)

        # Display results WITH VALUES
        self._display_parameter_analysis(analysis_results, finding)

        # Populate CORS / Headers / Cookie / Tech panels
        if hasattr(self, '_display_security_panels'):
            self._display_security_panels(analysis_results)

        # Apply filters
        self.filter_parameters_by_checkbox()

        # Update the vulnerability panel (was previously done by the caller
        # in on_history_selection_changed using the synchronous return value)
        if analysis_results.get('params') and hasattr(self, 'load_vulnerabilities_organized'):
            self.load_vulnerabilities_organized(finding)

        # Update auto-analyze label to show count
        total = len(analysis_results['params'])
        if total > 0:
            self.auto_analyze.setText(f"↺ Auto ({total})")
        else:
            self.auto_analyze.setText("↺ Auto")

    def perform_automatic_highlighting(self, response_text: str):
        """
        Populate the Information Leakage Scanner table when a response is loaded.
        Detection results are shown in the leakage scanner below only —
        the response text widget is NOT coloured automatically.
        (Manual highlighting is still available via the Apply button.)
        Called from HTTP History tab.

        Pattern detection runs in a background thread so large responses do
        not freeze the UI.  Results are delivered via
        _on_selection_highlight_finished.
        """
        if not hasattr(self, 'auto_highlight') or not self.auto_highlight.isChecked():
            return

        if not response_text:
            # Clear table even if response is empty (fix data persistence bug)
            if hasattr(self, 'highlight_table'):
                self.highlight_table.setRowCount(0)
            self.auto_highlight.setText("· Auto")
            return

        # Store for stale-result detection
        self.last_response_text      = response_text
        self._pending_highlight_text = response_text

        # Debounce: restart timer; actual launch happens 400 ms after last call
        if not hasattr(self, '_highlight_debounce_timer'):
            self._highlight_debounce_timer = QTimer(self)
            self._highlight_debounce_timer.setSingleShot(True)
            self._highlight_debounce_timer.timeout.connect(self._do_launch_highlight_worker)
        self._highlight_debounce_timer.start(400)

    def _do_launch_highlight_worker(self):
        """Actual worker launch — called by the debounce timer."""
        response_text = getattr(self, '_pending_highlight_text', None)
        if not response_text:
            return
        if not hasattr(self, 'auto_highlight') or not self.auto_highlight.isChecked():
            return

        # Cancel any previous worker still running
        prev = getattr(self, '_selection_highlight_worker', None)
        if prev is not None and prev.isRunning():
            try:
                prev.finished.disconnect()
            except Exception:
                pass
            prev.cancel_flag = True
            prev.quit()  # signal thread loop; cancel_flag drops the result

        # Reset leak badge + table so stale counts don't linger
        if hasattr(self, 'leak_count_badge'):
            self.leak_count_badge.setText("…")
            self.leak_count_badge.setStyleSheet(
                "color: #888; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )
        if hasattr(self, 'highlight_table'):
            self.highlight_table.setRowCount(0)

        self.auto_highlight.setText("· Scanning…")

        worker = SelectionHighlightWorker(response_text)
        worker.finished.connect(self._on_selection_highlight_finished)
        worker.error.connect(lambda msg: self.auto_highlight.setText("· Auto"))
        worker.start()
        self._selection_highlight_worker = worker

    def _on_selection_highlight_finished(self, patterns_found):
        """
        Called on the main thread when SelectionHighlightWorker is done.
        """
        # Discard stale results if a newer response was already loaded
        if getattr(self, '_pending_highlight_text', None) is not self.last_response_text:
            return

        if not patterns_found:
            if hasattr(self, 'highlight_table'):
                self.highlight_table.setRowCount(0)
            if hasattr(self, 'highlight_stats'):
                self.highlight_stats.setText("○ No patterns detected")
            self.auto_highlight.setText("· Auto")
            if hasattr(self, 'leak_count_badge'):
                self.leak_count_badge.setText("0 findings")
                self.leak_count_badge.setStyleSheet(
                    "color: #888; font-size: 10px; "
                    "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
                )
            return

        # Pass every detected pattern to the table; per-row visibility is
        # managed by filter_highlight_table (severity / category checkboxes).
        filtered_patterns = dict(patterns_found)

        if not filtered_patterns:
            self.auto_highlight.setText("· Auto")
            if hasattr(self, 'leak_count_badge'):
                self.leak_count_badge.setText("0 findings")
                self.leak_count_badge.setStyleSheet(
                    "color: #888; font-size: 10px; "
                    "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
                )
            return

        # ── Removed: _apply_highlighting_to_response_text ──
        # Response text is no longer coloured automatically on load.
        # Users can still trigger it manually via the Apply / highlight button.

        # Display results in leakage scanner table
        self._display_highlight_results(filtered_patterns)

        # Update auto-highlight label to show count
        total_matches = sum(len(matches) for matches in filtered_patterns.values())
        if total_matches > 0:
            self.auto_highlight.setText(f"· Auto ({total_matches})")
        else:
            self.auto_highlight.setText("· Auto")
    
    def filter_parameters_by_checkbox(self):
        """Filter parameter table based on checkbox selections - UPDATED for all locations"""
        for row in range(self.param_table.rowCount()):
            if row >= self.param_table.rowCount():
                continue
                
            location_item = self.param_table.item(row, 0)
            if not location_item:
                continue
                
            location = location_item.text()
            should_show = False
            
            # Check which checkboxes are checked - COMPREHENSIVE MAPPING
            if location in ["URL", "URL_PARAM"]:
                should_show = hasattr(self, 'filter_url') and self.filter_url.isChecked()
            
            elif location in ["HEADER", "HEADERS"]:
                # Security header entries are all shown in the dedicated Headers tab;
                # they are pre-filtered by _HEADER_PANEL_SKIP before reaching here.
                should_show = False

            elif location == "COOKIE":
                # Cookie security data lives in results['cookies'] → Cookie Security tab.
                should_show = False

            elif location == "JSON":
                should_show = hasattr(self, 'filter_json') and self.filter_json.isChecked()
            
            elif location in ["BODY", "FORM_DATA"]:
                should_show = hasattr(self, 'filter_body') and self.filter_body.isChecked()
            
            elif location.startswith("HTML"):
                # HTML_HREF, HTML_FORM, HTML_SRC, HTML_DATA, HTML_EVENT, HTML_META,
                # HTML_INPUT, HTML_JS_VAR, HTML_JS_BOOL, etc.
                should_show = hasattr(self, 'filter_html') and self.filter_html.isChecked()
            
            elif location in ["INLINE_DOM", "INLINE_SECRET"]:
                # DOM sinks and hardcoded secrets — exclusively shown in the ⚡ JS / DOM tab
                should_show = False

            elif location == "INLINE_JS_VAR":
                # URL parameters extracted from inline JavaScript — shown in param table
                # (e.g. URLSearchParams.get('redirect') → param 'redirect' is testable)
                should_show = hasattr(self, 'filter_html') and self.filter_html.isChecked()

            elif location in ["JS", "JS_VAR", "DOM_XSS", "JS_FILE",
                               "WEBSOCKET", "POSTMESSAGE_NO_ORIGIN_CHECK",
                               "GRAPHQL_INTROSPECTION", "GRAPHQL_ENDPOINT",
                               "GRAPHQL_MUTATION", "GRAPHQL_QUERY"]:
                # JS-family locations — all live in the ⚡ JS / DOM tab
                should_show = False
            
            elif location == "RESPONSE":
                # RESPONSE location (for SQL errors, API keys, etc.)
                should_show = hasattr(self, 'filter_response') and self.filter_response.isChecked()
            
            elif location == "FRAMEWORK":
                # Framework detection — shown in Tech Stack panel, hidden here
                should_show = False

            elif location == "ENDPOINT":
                # Endpoint detection — shown in Endpoints panel, hidden here
                should_show = False
            
            elif location == "JS_SECRET":
                # JavaScript secrets — shown in the ⚡ JS / DOM tab
                should_show = False
            
            else:
                # Unknown location - show if any filter is checked (default visible)
                should_show = True
            
            self.param_table.setRowHidden(row, not should_show)

        # Update badge to reflect only visible rows
        visible = sum(
            1 for r in range(self.param_table.rowCount())
            if not self.param_table.isRowHidden(r)
        )
        if hasattr(self, 'param_count_badge'):
            self.param_count_badge.setText(f"{visible} param{'s' if visible != 1 else ''}")
            self.param_count_badge.setStyleSheet(
                f"color: {'#7ec87e' if visible else '#888'}; font-size: 10px; "
                "background: #1a1a1a; border-radius: 3px; padding: 1px 6px;"
            )

    def toggle_all_filters(self):
        """Toggle all location filters"""
        is_checked = self.filter_all.isChecked()
        
        self.filter_url.setChecked(is_checked)
        self.filter_body.setChecked(is_checked)
        self.filter_json.setChecked(is_checked)
        self.filter_html.setChecked(is_checked)
        self.filter_response.setChecked(is_checked)
        # filter_js removed — JS/DOM entries moved to the ⚡ JS / DOM tab

        self.filter_parameters_by_checkbox()

    def filter_highlight_table(self):
        """Filter highlight table based on severity and category checkboxes"""
        if not hasattr(self, 'highlight_table'):
            return
        
        # Define pattern categories
        secrets_patterns = [
            'AWS_KEY', 'GITHUB_TOKEN', 'SLACK_TOKEN', 'STRIPE_KEY', 'GOOGLE_API',
            'MAILGUN_KEY', 'SENDGRID_KEY', 'TWILIO_KEY', 'FIREBASE_KEY', 'HEROKU_KEY',
            'GENERIC_SECRETS', 'BEARER_TOKENS', 'ENV_SECRETS',
            'RSA_PRIVATE_KEY', 'SSH_PRIVATE_KEY', 'PEM_PRIVATE_KEY',
            'DSA_PRIVATE_KEY', 'EC_PRIVATE_KEY', 'JWT_TOKENS', 'SESSION_IDS',
            'MYSQL_CONN', 'POSTGRES_CONN', 'MONGODB_CONN', 'MSSQL_CONN',
            'GENERIC_API_KEY', 'AUTH_TOKENS', 'SESSION_TOKENS', 'SENSITIVE_USER_DATA',
        ]

        network_patterns = [
            'INTERNAL_IPS', 'PUBLIC_IPS', 'PORTS', 'URLS_WITH_CREDS',
            'INTERNAL_HOSTS', 'SUBDOMAINS',
            'CACHE_POISONING',                          # NEW: network/CDN category
        ]

        version_patterns = [
            'SOFTWARE_VERSIONS', 'SERVER_HEADERS', 'CONFIG_VALUES',
        ]

        path_patterns = [
            'FILE_PATHS',
        ]

        error_patterns = [
            'SQL_ERRORS', 'STACK_TRACES', 'EXCEPTION_TYPES',
            'EL_INJECTION', 'INSECURE_DESER', 'PROTO_POLLUTION',  # NEW: injection/vuln
        ]

        # Comprehensive severity mapping
        critical_patterns = [
            'AWS_KEY', 'GITHUB_TOKEN', 'SLACK_TOKEN', 'STRIPE_KEY', 'GOOGLE_API',
            'MAILGUN_KEY', 'SENDGRID_KEY', 'TWILIO_KEY', 'FIREBASE_KEY', 'HEROKU_KEY',
            'GENERIC_SECRETS', 'BEARER_TOKENS', 'ENV_SECRETS',
            'RSA_PRIVATE_KEY', 'SSH_PRIVATE_KEY', 'PEM_PRIVATE_KEY',
            'DSA_PRIVATE_KEY', 'EC_PRIVATE_KEY',
            'MYSQL_CONN', 'POSTGRES_CONN', 'MONGODB_CONN', 'MSSQL_CONN',
            'SQL_ERRORS',
            'GENERIC_API_KEY', 'AUTH_TOKENS',
            'INSECURE_DESER',                           # NEW: critical RCE risk
        ]

        high_patterns = [
            'INTERNAL_IPS', 'PUBLIC_IPS', 'PORTS',
            'JWT_TOKENS', 'SESSION_IDS', 'URLS_WITH_CREDS',
            'FILE_PATHS', 'STACK_TRACES', 'EXCEPTION_TYPES',
            'S3_BUCKET', 'EC2_INSTANCE', 'AWS_ACCOUNT_ID', 'AWS_REGION', 'LAMBDA_ARN',
            'DEBUG_INDICATORS', 'DEV_DOMAINS', 'SOURCE_MAPS', 'BACKUP_FILES',
            'API_ENDPOINTS', 'DATABASE_NAMES', 'TABLE_NAMES',
            'SESSION_TOKENS',
            'EL_INJECTION', 'PROTO_POLLUTION',          # NEW: injection findings
        ]

        medium_patterns = [
            'SOFTWARE_VERSIONS', 'SERVER_HEADERS',
            'EMAILS', 'PHONE_NUMBERS', 'USERNAMES', 'CREDIT_CARDS',
            'SENSITIVE_COMMENTS', 'CONFIG_VALUES',
            'INTERNAL_HOSTS', 'SUBDOMAINS',
            'SENSITIVE_USER_DATA',
            'CACHE_POISONING',                          # NEW: cache indicators
        ]

        # Get filter states
        show_critical = self.filter_critical.isChecked() if hasattr(self, 'filter_critical') else True
        show_high = self.filter_high.isChecked() if hasattr(self, 'filter_high') else True
        show_medium = self.filter_medium.isChecked() if hasattr(self, 'filter_medium') else True
        
        show_secrets = self.filter_secrets.isChecked() if hasattr(self, 'filter_secrets') else True
        show_network = self.filter_network.isChecked() if hasattr(self, 'filter_network') else True
        show_versions = self.filter_versions.isChecked() if hasattr(self, 'filter_versions') else True
        show_paths = self.filter_paths.isChecked() if hasattr(self, 'filter_paths') else True
        show_errors = self.filter_errors.isChecked() if hasattr(self, 'filter_errors') else True
        
        # Filter each row
        for row in range(self.highlight_table.rowCount()):
            pattern_type_item = self.highlight_table.item(row, 0)
            severity_item = self.highlight_table.item(row, 2)
            
            if not pattern_type_item or not severity_item:
                continue
            
            pattern_type = pattern_type_item.text()
            severity = severity_item.text()
            
            # Check severity filter
            severity_match = False
            if show_critical and '●' in severity:
                severity_match = True
            if show_high and '▲' in severity:
                severity_match = True
            if show_medium and '◆' in severity:
                severity_match = True
            
            # Check category filter
            category_match = False
            if show_secrets and pattern_type in secrets_patterns:
                category_match = True
            if show_network and pattern_type in network_patterns:
                category_match = True
            if show_versions and pattern_type in version_patterns:
                category_match = True
            if show_paths and pattern_type in path_patterns:
                category_match = True
            if show_errors and pattern_type in error_patterns:
                category_match = True
            
            # Handle patterns not in any category (show if "All" or if they match severity)
            if pattern_type not in (secrets_patterns + network_patterns + version_patterns + path_patterns + error_patterns):
                category_match = True  # Always show uncategorized items
            
            # Show row if both filters match
            should_show = severity_match and category_match
            self.highlight_table.setRowHidden(row, not should_show)
        
        # Update stats to show visible count
        visible_count = sum(1 for row in range(self.highlight_table.rowCount()) 
                          if not self.highlight_table.isRowHidden(row))
        total_count = self.highlight_table.rowCount()
        
        if hasattr(self, 'highlight_stats'):
            if visible_count == total_count:
                self.highlight_stats.setText(f"✓ {total_count} patterns detected")
            else:
                self.highlight_stats.setText(f"✓ Showing {visible_count} of {total_count} patterns (filtered)")

    def toggle_all_patterns(self):
        """Toggle all pattern filters"""
        is_checked = self.pattern_all.isChecked()
        
        # Toggle severity filters
        if hasattr(self, 'filter_critical'):
            self.filter_critical.setChecked(is_checked)
        if hasattr(self, 'filter_high'):
            self.filter_high.setChecked(is_checked)
        if hasattr(self, 'filter_medium'):
            self.filter_medium.setChecked(is_checked)
        
        # Toggle category filters
        if hasattr(self, 'filter_secrets'):
            self.filter_secrets.setChecked(is_checked)
        if hasattr(self, 'filter_network'):
            self.filter_network.setChecked(is_checked)
        if hasattr(self, 'filter_versions'):
            self.filter_versions.setChecked(is_checked)
        if hasattr(self, 'filter_paths'):
            self.filter_paths.setChecked(is_checked)
        if hasattr(self, 'filter_errors'):
            self.filter_errors.setChecked(is_checked)
        
        # Apply filters
        self.filter_highlight_table()
    
    def update_highlighting(self):
        """Update highlighting based on pattern checkboxes (legacy - now uses filter_highlight_table)"""
        # This method is kept for backward compatibility
        self.filter_highlight_table()

    def refresh_current_analysis(self):
        """Re-analyze the current request"""
        if hasattr(self, 'current_finding') and self.current_finding:
            self.perform_automatic_analysis(self.current_finding)
            self.analysis_status.setText("↺ Re-analyzed")
            QTimer.singleShot(2000, lambda: self.analysis_status.setText("Ready"))

    def refresh_highlighting(self):
        """Re-apply highlighting to current response"""
        if hasattr(self, 'current_response_raw') and self.current_response_raw:
            self.perform_automatic_highlighting(self.current_response_raw)
            self.highlight_status.setText("· Re-highlighted")
            QTimer.singleShot(2000, lambda: self.highlight_status.setText("Ready"))

    # ── AI Traffic Analysis ────────────────────────────────────────────────────

    def _on_ai_traffic_analyze(self):
        """Open the AI Traffic Analysis dialog for the currently selected request."""
        if not _AI_TRAFFIC_AVAILABLE:
            QMessageBox.warning(self, "AI Not Available",
                                "ai_client.py could not be loaded.")
            return

        # Prefer cached text from the last regex analysis run
        request_text  = ""
        response_text = ""
        if hasattr(self, 'last_analysis_results'):
            request_text  = self.last_analysis_results.get('_request_text',  '')
            response_text = self.last_analysis_results.get('_response_text', '')

        # Fall back to reading from the current finding's files
        if not request_text and not response_text:
            finding = getattr(self, 'current_analysis_finding', None)
            if finding:
                for attr, key in (('request_text', 'request_file'),
                                  ('response_text', 'response_file')):
                    path = finding.get(key, '')
                    if path and os.path.exists(path):
                        try:
                            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                                if key == 'request_file':
                                    request_text = fh.read()
                                else:
                                    response_text = fh.read()
                        except Exception:
                            pass

        if not request_text and not response_text:
            QMessageBox.information(
                self, "No Traffic Selected",
                "Select a request in HTTP History first, then click \u2728 AI."
            )
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

        finding = getattr(self, 'current_analysis_finding', None)
        url = finding.get('url', '') if finding else ''

        # Show / expand the embedded right-side chat panel
        if hasattr(self, '_ai_outer_splitter'):
            total = sum(self._ai_outer_splitter.sizes())
            if self._ai_outer_splitter.sizes()[1] < 200:
                self._ai_outer_splitter.setSizes([
                    max(300, int(total * 0.55)),
                    max(350, int(total * 0.45)),
                ])
        if hasattr(self, '_ai_chat_panel'):
            self._ai_chat_panel.start_analysis(settings, request_text, response_text, url)
        else:
            dlg = AITrafficDialog(settings, request_text, response_text, url, parent=self)
            dlg.exec_()

    def _ai_traffic_settings(self) -> dict:
        """Return AI settings dict, walking up to the parent GUI if available."""
        try:
            gui = getattr(self, 'parent_gui', None) or self
            gs  = getattr(gui, '_global_settings', None)
            if gs:
                return gs
        except Exception:
            pass
        # Fall back to reading from the settings file
        try:
            cfg = os.path.join(
                os.path.expanduser("~"), ".config", "hunt-proxy", "settings.json"
            )
            if os.path.exists(cfg):
                with open(cfg, 'r', encoding='utf-8') as fh:
                    return json.load(fh)
        except Exception:
            pass
        return {}

    def _on_ai_chat_close(self):
        """Collapse the AI chat panel back to zero width in whichever splitter it lives."""
        panel = getattr(self, '_ai_chat_panel', None)
        if panel is None:
            return
        from PyQt5.QtWidgets import QSplitter
        parent = panel.parent()
        if isinstance(parent, QSplitter):
            total = sum(parent.sizes())
            parent.setSizes([total, 0])
        elif hasattr(self, '_ai_outer_splitter'):
            total = sum(self._ai_outer_splitter.sizes())
            self._ai_outer_splitter.setSizes([total, 0])

# ============================================================================
# BATCH ANALYSIS WORKER THREAD
# ============================================================================

class BatchAnalysisWorker(QThread):
    """Worker thread for batch analysis"""
    
    progress = pyqtSignal(int, int, str)  # current, total, status
    finished = pyqtSignal(dict)  # results
    
    def __init__(self, findings: List[Dict]):
        super().__init__()
        self.findings = findings
        self.running = True
    
    def run(self):
        """Run batch analysis"""
        results = {
            'analyzed': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        total = len(self.findings)
        
        for i, finding in enumerate(self.findings):
            if not self.running:
                break
            
            # Analyze
            analysis = SecurityAnalyzer.analyze_finding(finding)
            
            # Update finding
            finding['params'] = analysis['params']
            finding['severity'] = analysis['severity']
            finding['analyzed'] = True
            
            # Update results
            results['analyzed'] += 1
            severity = analysis['severity']
            if severity == 'CRITICAL':
                results['critical'] += 1
            elif severity == 'HIGH':
                results['high'] += 1
            elif severity == 'MEDIUM':
                results['medium'] += 1
            else:
                results['low'] += 1
            
            # Emit progress
            self.progress.emit(i + 1, total, f"Analyzing {finding.get('url', 'unknown')[:50]}...")
        
        self.finished.emit(results)
    
    def stop(self):
        """Stop the worker"""
        self.running = False


# ── Module-level picklable functions for ProcessPoolExecutor ─────────────────
# Must be top-level so pickle can serialize them by name.
# On Linux the default 'fork' start method means the worker process already
# has the full module in memory — no Qt import happens in the child.

def _mp_run_analysis(finding_dict: dict) -> dict:
    """Subprocess entry-point: runs SecurityAnalyzer.analyze_finding()."""
    return SecurityAnalyzer.analyze_finding(finding_dict)


def _mp_run_highlight(text: str) -> dict:
    """Subprocess entry-point: runs highlight pattern detection."""
    return AnalysisTabMixin._detect_highlight_patterns(text)


class SelectionAnalysisWorker(QThread):
    """
    Runs SecurityAnalyzer.analyze_finding() directly in this QThread.
    No subprocess is spawned — ProcessPoolExecutor caused zombie process
    accumulation when workers were cancelled faster than they could complete.
    """
    finished = pyqtSignal(dict, dict)   # (finding, analysis_results)
    error    = pyqtSignal(str)

    def __init__(self, finding: dict):
        super().__init__()
        self._finding = dict(finding)       # shallow-copy; only basic types
        self._original_finding = finding    # live reference updated on main thread
        self.cancel_flag = False

    def run(self):
        try:
            if self.cancel_flag:
                return
            results = _mp_run_analysis(self._finding)
            if not self.cancel_flag:
                self.finished.emit(self._original_finding, results)
        except Exception as e:
            logger.error(f"SelectionAnalysisWorker error: {e}", exc_info=True)
            if not self.cancel_flag:
                self.error.emit(str(e))


class SelectionHighlightWorker(QThread):
    """
    Runs _detect_highlight_patterns() directly in this QThread.
    No subprocess is spawned — avoids the same zombie-process issue.
    """
    finished = pyqtSignal(object)
    error    = pyqtSignal(str)

    def __init__(self, text: str):
        super().__init__()
        self._text = text
        self.cancel_flag = False

    def run(self):
        try:
            if self.cancel_flag:
                return
            patterns = _mp_run_highlight(self._text)
            if not self.cancel_flag:
                self.finished.emit(patterns)
        except Exception as e:
            logger.error(f"SelectionHighlightWorker error: {e}", exc_info=True)
            if not self.cancel_flag:
                self.error.emit(str(e))