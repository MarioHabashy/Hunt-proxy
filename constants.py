"""
Constants - All configuration constants for the Hunt Mode GUI
"""

import json
import os
import re
from html import escape as html_escape
# Setup logger
import logging
from typing import Optional
logger = logging.getLogger(__name__)

try:
    from PyQt5.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
    from PyQt5.QtCore import QRegularExpression
    _PYQT_AVAILABLE = True
except ImportError:
    _PYQT_AVAILABLE = False

# ============================================================================
# FILE PATHS
# ============================================================================

# File paths
HUNT_JSONL = os.environ.get("HUNT_MODE_JSONL", "/tmp/hunt.jsonl")
REQUESTS_DIR = os.environ.get("HUNT_MODE_REQUESTS_DIR", "/tmp/requests")
RESPONSES_DIR = os.environ.get("HUNT_MODE_RESPONSES_DIR", "/tmp/responses")
NOTES_FILE = os.environ.get("HUNT_MODE_NOTES_FILE", "/tmp/hunt_notes.json")
HUNT_SCRIPT_FILE = os.environ.get("HUNT_SCRIPT_FILE", "../hunt_script.py")

# Create directories if they don't exist
for directory in [REQUESTS_DIR, RESPONSES_DIR]:
    os.makedirs(directory, exist_ok=True)

# ============================================================================
# DISPLAY LIMITS
# ============================================================================

MAX_FINDINGS_IN_MEMORY = 1000000
MAX_HTML_DISPLAY_LENGTH = 20000
MAX_CODE_SNIPPET_LENGTH = 75
MAX_BODY_LENGTH = 10000
PRETTIFY_SIZE_LIMIT = 50000
MAX_ACTIVITY_LOG_LINES = 10000

# ============================================================================
# COLOR PALETTE - Burp Suite Style
# ============================================================================

# Ultra-Premium Color Palette (Maximum Clarity & Professionalism)
COLOR_SUCCESS = "#00E676"  # Pure Green

# URL Highlighting Colors
COLOR_URL_BASE = "#FFFFFF"  # White for base URL (normal)
COLOR_URL_BASE_SELECTED = "#00D9FF"  # Bright cyan for base URL (selected)
COLOR_URL_PARAM = "#6A8759"  # Green for parameters (normal)
COLOR_URL_PARAM_SELECTED = "#FFD700"  # Gold for parameters (selected)

# Premium UI Colors (Burp Suite Dark Theme Inspired)
COLOR_BACKGROUND = "#2B2B2B"  # Burp's main background
COLOR_DARK_BG = "#1E1E1E"  # Darker panels
COLOR_DARKER_BG = "#1A1A1A"  # Even darker panels
COLOR_LIGHTER_BG = "#323232"  # Elevated surfaces
COLOR_CARD_BG = "#252525"  # Card backgrounds
COLOR_ELEVATED_BG = "#2D2D2D"  # Elevated elements
COLOR_BORDER = "#3C3F41"  # Burp's border color
COLOR_BORDER_BRIGHT = "#4E5254"  # Brighter border
COLOR_TEXT = "#BBBBBB"  # Burp's primary text
COLOR_TEXT_BRIGHT = "#FFFFFF"  # Pure White
COLOR_TEXT_MUTED = "#888888"  # Muted text
COLOR_ACCENT = "#6A8759"  # Burp's green accent
COLOR_ACCENT_SECONDARY = "#9876AA"  # Purple accent (like in Intruder)
COLOR_HOVER = "#3C3F41"  # Hover state

# Burp-style Severity Colors
COLOR_CRITICAL = "#FF6B6B"  # Red for critical
COLOR_HIGH = "#FFA726"  # Orange for high
COLOR_MEDIUM = "#FFEE58"  # Yellow for medium
COLOR_LOW = "#64B5F6"  # Blue for low
COLOR_INFO = "#81C784"  # Green for info
COLOR_WARNING = "#ce9178"

# Severity Backgrounds with Burp's subtle transparency
COLOR_CRITICAL_BG = "rgba(255, 107, 107, 0.15)"
COLOR_HIGH_BG = "rgba(255, 167, 38, 0.15)"
COLOR_MEDIUM_BG = "rgba(255, 238, 88, 0.15)"
COLOR_LOW_BG = "rgba(100, 181, 246, 0.15)"

# ============================================================================
# TYPOGRAPHY
# ============================================================================

FONT_FAMILY = "'Segoe UI', 'Roboto', 'Helvetica Neue', Arial, sans-serif"
FONT_FAMILY_MONO = "'Consolas', 'Monaco', 'Courier New', monospace"
FONT_SIZE_XLARGE = "14pt"
FONT_SIZE_LARGE = "12pt"
FONT_SIZE_NORMAL = "10pt"
FONT_SIZE_SMALL = "9pt"
FONT_SIZE_TINY = "8pt"

# ============================================================================
# SHADOWS
# ============================================================================

SHADOW_SMALL = "0 1px 3px rgba(0, 0, 0, 0.3)"
SHADOW_MEDIUM = "0 4px 12px rgba(0, 0, 0, 0.4)"
SHADOW_LARGE = "0 8px 24px rgba(0, 0, 0, 0.5)"
SHADOW_GLOW_CRITICAL = "0 0 20px rgba(255, 59, 63, 0.3)"
SHADOW_GLOW_HIGH = "0 0 20px rgba(255, 107, 53, 0.3)"

# ============================================================================
# BORDER RADIUS
# ============================================================================

RADIUS_SMALL = "6px"
RADIUS_MEDIUM = "8px"
RADIUS_LARGE = "12px"

# ============================================================================
# SPACING SCALE (8pt grid)
# ============================================================================

SPACE_XS = "4px"
SPACE_SM = "8px"
SPACE_MD = "16px"
SPACE_LG = "24px"
SPACE_XL = "32px"

# ============================================================================
# HTTP METHODS
# ============================================================================

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# ============================================================================
# STATUS CODE FILTERS
# ============================================================================

STATUS_FILTERS = ["All", "2xx", "3xx", "4xx", "5xx"]

# ============================================================================
# MIME TYPE FILTERS
# ============================================================================

MIME_FILTERS = ["All", "HTML", "JSON", "JavaScript", "CSS", "XML", "Images", "Other"]

# ============================================================================
# PARAMETER FILTERS
# ============================================================================

PARAM_FILTERS = ["All", "With Params", "Without Params", "In URL", "In Body"]

# ============================================================================
# NOTES FILTERS
# ============================================================================

NOTES_FILTERS = ["All", "With Notes", "Without Notes"]


class SitemapIcons:
    """Icons for sitemap tree items - using reliable Unicode characters"""
    
    # Directory icons (using Unicode symbols that render reliably)
    FOLDER = "▶"  # Triangle for closed folders
    FOLDER_OPEN = "▼"  # Triangle for open folders
    
    # Simple indicators
    HAS_PARAMS = "?"  # Question mark for params
    HAS_ISSUES = "!"  # Exclamation for issues
    
    # HTTP method colors (Burp Suite style)
    METHOD_COLORS = {
        "GET": COLOR_SUCCESS,      # Green
        "POST": COLOR_MEDIUM,      # Yellow/Orange
        "PUT": COLOR_LOW,          # Blue
        "DELETE": COLOR_CRITICAL,  # Red
        "PATCH": COLOR_HIGH,       # Orange
        "OPTIONS": COLOR_TEXT_MUTED,
        "HEAD": COLOR_TEXT_MUTED,
    }
    
    @staticmethod
    def format_endpoint_display(name: str, method: str, has_params: bool, has_issues: bool) -> tuple:
        """
        Format endpoint display with method badge and indicators
        
        Args:
            name: Endpoint name
            method: HTTP method (GET, POST, etc.)
            has_params: Whether endpoint has parameters
            has_issues: Whether endpoint has security issues
            
        Returns:
            Tuple of (display_text, color)
        """
        # Get color for this method
        color = SitemapIcons.METHOD_COLORS.get(method.upper(), COLOR_TEXT)
        
        # Override color if there are issues (critical takes precedence)
        if has_issues:
            color = COLOR_CRITICAL
        
        # Build display text with method badge
        method_badge = f"[{method.upper()}]"
        
        # Add indicators
        param_indicator = " ?" if has_params else ""
        issue_indicator = " !" if has_issues else ""
        
        display_text = f"{method_badge} {name}{param_indicator}{issue_indicator}"
        
        return (display_text, color)
    
    @staticmethod
    def get_method_color(method: str, has_issues: bool = False) -> str:
        """
        Get color for HTTP method
        
        Args:
            method: HTTP method
            has_issues: Whether there are security issues
            
        Returns:
            Color code
        """
        if has_issues:
            return COLOR_CRITICAL
        return SitemapIcons.METHOD_COLORS.get(method.upper(), COLOR_TEXT)

class VulnerabilityCategories:
    """Centralized vulnerability type definitions"""

    # Define what counts as actual VULNERABILITIES
    VULNERABILITY_TYPES = {
        # Critical vulnerabilities
        "RCE",
        "COMMAND_INJECTION",
        "CODE_INJECTION",
        # High severity vulnerabilities
        "XSS",
        "SQLI",
        "XXE",
        "SSRF",
        "LFI",
        "RFI",
        "PATH_TRAVERSAL",
        "SSTI",
        "NOSQL",
        "LDAP_INJECTION",
        "XML_INJECTION",
        # Medium severity vulnerabilities
        "IDOR",
        "CRLF",
        "OPEN_REDIRECT",
        "CSRF",
        "SESSION_FIXATION",
        "INSECURE_DESERIALIZATION",
        "UPLOAD",
    }

    # CSS classes for vulnerabilities
    VULN_CSS_CLASSES = {
        "RCE": "critical",
        "COMMAND_INJECTION": "critical",
        "CODE_INJECTION": "critical",
        "XSS": "xss",
        "SQLI": "sqli",
        "XXE": "high",
        "SSRF": "high",
        "LFI": "high",
        "RFI": "high",
        "PATH_TRAVERSAL": "high",
        "SSTI": "high",
        "NOSQL": "high",
        "LDAP_INJECTION": "high",
        "XML_INJECTION": "high",
        "IDOR": "medium",
        "CRLF": "medium",
        "OPEN_REDIRECT": "medium",
        "CSRF": "medium",
        "SESSION_FIXATION": "medium",
        "INSECURE_DESERIALIZATION": "medium",
        "UPLOAD": "medium",
    }

    # Category headers with emojis
    CATEGORY_HEADERS = {
        # PARAMETERS
        "URL": "🌐 URL Parameters",
        "BODY": "📝 Body Parameters",
        "FORM_PARAM": "📋 Form Parameters",
        "INPUT_PARAM": "⌨️  Standalone Input Fields",
        # JAVASCRIPT
        "SCRIPT_PARAM": "📜 Script Parameters",
        "JS_FILE": "📄 JavaScript Files",
        "JS_PARAM": "⚙️  JavaScript Parameter Extraction",
        "JS_DOM_USAGE": "⚙️  JavaScript DOM Usage",
        "JS_DANGEROUS": "⚠️  JavaScript Dangerous Functions",
        # XSS VULNERABILITIES
        "DOM_XSS_CONFIRMED": "🚨 DOM XSS CONFIRMED",
        "TEMPLATE_LITERAL_XSS": "⚠️ XSS JavaScript template literals",
        "DOM_XSS": "🎯 DOM XSS Sinks",
        "JQUERY_XSS": "💰 jQuery XSS Vulnerabilities",
        "XSS": "⚠️  XSS Vulnerabilities",
        "STRING_CONCAT": "🔗 String Concatenation XSS",
        # HTML PARAMETERS
        "HTML_HREF": "🔗 HTML HREF Parameters",
        "HTML_FORM": "📋 HTML Form Parameters",
        "HTML_SRC": "🖼️  HTML Resource Parameters",
        "HTML_DATA": "💾 HTML Data Attributes",
        "HTML_EVENT": "🎯 HTML Event Handlers",
        "HTML_JS_STR": "💬 HTML Script Tag Parameters",
        # CRITICAL
        "CRITICAL": "🚨 CRITICAL VULNERABILITIES",
        # SQL INJECTION
        "SQL_CRITICAL": "🚨 Critical SQL Errors",
        "SQL_ERRORS": "💉 SQL Injection Errors",
        "SQL_MYSQL": "💉 MySQL SQL Errors",
        "SQL_MSSQL": "💉 MSSQL SQL Errors",
        "SQL_ORACLE": "💉 Oracle SQL Errors",
        "SQL_POSTGRES": "💉 PostgreSQL SQL Errors",
        # API KEYS
        "API_KEYS_EXPOSED": "🔑 Exposed API Keys",
        "EXPOSED_AWS_ACCESS_KEY": "🔑 AWS Access Keys",
        "EXPOSED_AWS_SECRET": "🔑 AWS Secret Keys",
        "EXPOSED_GITHUB_TOKEN": "🔑 GitHub Tokens",
        "EXPOSED_SLACK_TOKEN": "🔑 Slack Tokens",
        # SENSITIVE DATA
        "SENSITIVE_DATA": "💾 Sensitive Data Exposure",
        "API_KEY_EXPOSED": "💾 API Keys Exposed",
        "PASSWORD_EXPOSED": "💾 Passwords Exposed",
        # INTERNAL IP
        "INTERNAL_IP": "🌐 Internal IP Disclosure",
        "INTERNAL_IP_IN_HEADERS": "🌐 Internal IP in Headers",
        # EMAIL
        "EMAIL_DISCLOSURE": "📧 Email Disclosure",
        # DEBUG MODE
        "DEBUG_MODE": "🐛 Debug Mode Enabled",
        # ADMIN PANELS
        "ADMIN_PANEL": "👑 Admin Panels",
        "HIGH_RISK_ADMIN": "👑 High Risk Admin Panels",
        "CRITICAL_ADMIN": "👑 Critical Admin Panels",
        # DEFAULT CREDENTIALS
        "DEFAULT_CREDS": "🔓 Default Credentials",
        # CACHE POISONING
        "CACHE_POISONING": "💉 Cache Poisoning",
        # XXE
        "XXE": "📄 XXE Potential",
        "XXE_EXPLOITATION": "🚨 XXE Exploitation",
        # OTHER SECURITY
        "CLICKJACKING": "🖱️  Clickjacking",
        "SSL_TLS_ISSUES": "🔒 SSL/TLS Issues",
        "COOKIE_ISSUES": "🍪 Cookie Issues",
        "WEBSOCKET": "🔌 WebSocket",
        # JWT & CORS
        "JWT": "🎫 JWT Tokens",
        "CORS": "🌍 CORS Issues",
        # API & GRAPHQL
        "API_ENDPOINT": "🔗 API Endpoint",
        "GRAPHQL": "📊 GraphQL",
        "GRAPHQL_CRITICAL": "📊 Critical GraphQL Issues",
        # JSON
        "JSON": "📋 JSON Parameters",
        "RESPONSE": "📤 Response Parameters",
        # FRAMEWORKS
        "FRAMEWORK_AngularJS": "⚡ AngularJS Framework",
        "FRAMEWORK_React": "⚛️  React Framework",
        "FRAMEWORK_Vue.js": "🟢 Vue.js Framework",
        "FRAMEWORK_jQuery": "💰 jQuery Framework",
        # FRAMEWORK XSS
        "CRITICAL_ANGULAR_XSS": "⚡ CRITICAL AngularJS XSS",
        "ANGULAR_XSS": "⚡ AngularJS XSS",
        "CRITICAL_REACT_XSS": "⚛️  CRITICAL React XSS",
        "REACT_XSS": "⚛️  React XSS",
        # VERSION
        "VERSION_CRITICAL": "📌 CRITICAL Version Disclosure",
        "VERSION_HIGH": "📌 HIGH Version Disclosure",
        "VERSION_INFO": "📌 Version Information",
        # SECURITY MISCONFIG
        "SECURITY_MISCONFIG": "⚙️  Security Misconfiguration",
        # ERROR MESSAGES
        "ERROR_MESSAGES": "💥 Error Messages",
        # INTERESTING PARAMETERS
        "DEBUG_PARAM": "🔍 Debug Parameter",
        "TEST_PARAM": "🔍 Test Parameter",
        "ADMIN_PARAM": "🔍 Admin Parameter",
        "INTERNAL_PARAM": "🔍 Internal Parameter",
        # SANITIZATION
        "SANITIZATION_HTML_ESCAPE": "✅ HTML Sanitization/Escaping",
        "SANITIZATION_STRING_REPLACE": "✅ String Replacement/Cleaning",
        "MISSING_SANITIZATION_DIRECT_DOM_INJECTION": "🚨 MISSING: DOM Sanitization",
        "WEAK_SANITIZATION_INCOMPLETE_REPLACE": "⚠️  WEAK: Incomplete Sanitization",
    }

    # Category display order
    CATEGORY_ORDER = [
        # Parameters
        "URL",
        "BODY",
        "FORM_PARAM",
        "INPUT_PARAM",
        # JavaScript
        "SCRIPT_PARAM",
        "JS_FILE",
        "JS_PARAM",
        "JS_DOM_USAGE",
        "JS_DANGEROUS",
        # XSS (High Priority)
        "DOM_XSS_CONFIRMED",
        "TEMPLATE_LITERAL_XSS",
        "DOM_XSS",
        "JQUERY_XSS",
        "XSS",
        "STRING_CONCAT",
        # HTML Parameters
        "HTML_HREF",
        "HTML_FORM",
        "HTML_SRC",
        "HTML_DATA",
        "HTML_EVENT",
        "HTML_JS_STR",
        # Critical
        "CRITICAL",
        # SQL Injection
        "SQL_CRITICAL",
        "SQL_ERRORS",
        "SQL_MYSQL",
        "SQL_MSSQL",
        "SQL_ORACLE",
        "SQL_POSTGRES",
        # API Keys
        "API_KEYS_EXPOSED",
        "EXPOSED_AWS_ACCESS_KEY",
        "EXPOSED_AWS_SECRET",
        "EXPOSED_GITHUB_TOKEN",
        "EXPOSED_SLACK_TOKEN",
        # Sensitive Data
        "SENSITIVE_DATA",
        "API_KEY_EXPOSED",
        "PASSWORD_EXPOSED",
        # Internal IP
        "INTERNAL_IP",
        "INTERNAL_IP_IN_HEADERS",
        # Email
        "EMAIL_DISCLOSURE",
        # Debug Mode
        "DEBUG_MODE",
        # Admin Panels
        "HIGH_RISK_ADMIN",
        "CRITICAL_ADMIN",
        "ADMIN_PANEL",
        # Default Credentials
        "DEFAULT_CREDS",
        # Cache Poisoning
        "CACHE_POISONING",
        # XXE
        "XXE_EXPLOITATION",
        "XXE",
        # Other Security
        "CLICKJACKING",
        "SSL_TLS_ISSUES",
        "COOKIE_ISSUES",
        "WEBSOCKET",
        # JWT & CORS
        "JWT",
        "CORS",
        # API & GraphQL
        "API_ENDPOINT",
        "GRAPHQL_CRITICAL",
        "GRAPHQL",
        # JSON
        "JSON",
        "RESPONSE",
        # Frameworks
        "FRAMEWORK_AngularJS",
        "FRAMEWORK_React",
        "FRAMEWORK_Vue.js",
        "FRAMEWORK_jQuery",
        # Framework XSS
        "CRITICAL_ANGULAR_XSS",
        "ANGULAR_XSS",
        "CRITICAL_REACT_XSS",
        "REACT_XSS",
        # Version
        "VERSION_CRITICAL",
        "VERSION_HIGH",
        "VERSION_INFO",
        # Security Misconfig
        "SECURITY_MISCONFIG",
        # Error Messages
        "ERROR_MESSAGES",
        # Interesting Parameters
        "DEBUG_PARAM",
        "TEST_PARAM",
        "ADMIN_PARAM",
        "INTERNAL_PARAM",
    ]


class HTTPFormatter:
    """Utility class for formatting HTTP messages with syntax highlighting"""

    @staticmethod
    def escape_html(text: Optional[str]) -> str:
        """Escape HTML special characters using stdlib"""
        if not text:
            return ""
        return html_escape(str(text), quote=True)

    @staticmethod
    def get_common_css() -> str:
        """Get common CSS for HTTP message display"""
        return f"""
            body {{ 
                font-family: 'Consolas', 'Monaco', monospace; 
                font-size: 10pt; 
                background-color: #1e1e1e; 
                color: #d4d4d4; 
                padding: 10px; 
                line-height: 1.6; 
            }}
            .request-line, .status-line {{ 
                margin-bottom: 10px; 
                font-weight: bold;
            }}
            .method, .http-version {{ color: #569cd6; font-weight: bold; }}
            .url {{ color: #ce9178; }}
            .status-code-2xx {{ color: #4ec9b0; font-weight: bold; }}
            .status-code-3xx {{ color: #569cd6; font-weight: bold; }}
            .status-code-4xx {{ color: #ce9178; font-weight: bold; }}
            .status-code-5xx {{ color: #f48771; font-weight: bold; }}
            .status-message {{ color: #d4d4d4; }}
            .header-name {{ color: #9cdcfe; font-weight: bold; }}
            .header-value {{ color: #ce9178; }}
            .header-separator {{ color: #d4d4d4; }}
            .body-separator {{ color: #808080; margin: 10px 0; }}
            .body-content {{ 
                color: #dcdcaa; 
                background-color: #252525; 
                padding: 10px; 
                border-left: 3px solid #569cd6; 
                margin-top: 10px; 
                white-space: pre-wrap; 
                word-wrap: break-word; 
                font-family: 'Consolas', 'Monaco', monospace; 
                font-size: 9pt; 
            }}
            .json-key {{ color: #9cdcfe; }}
            .json-string {{ color: #ce9178; }}
            .json-number {{ color: #b5cea8; }}
            .json-boolean {{ color: #569cd6; }}
            .json-null {{ color: #569cd6; }}
            .html-tag {{ color: #569cd6; }}
            .html-attr {{ color: #9cdcfe; }}
            .html-attr-value {{ color: #ce9178; }}
        """

    @staticmethod
    def format_request_line(line: str) -> str:
        """Format HTTP request line (METHOD URL HTTP/VERSION)"""
        if not line.strip():
            return ""

        parts = line.split(" ", 2)
        if len(parts) < 2:
            return f"<div class='request-line'>{HTTPFormatter.escape_html(line)}</div>"

        method = parts[0]
        url = parts[1] if len(parts) > 1 else ""
        http_ver = parts[2] if len(parts) > 2 else ""

        return f"""<div class='request-line'>
            <span class='method'>{HTTPFormatter.escape_html(method)}</span> 
            <span class='url'>{HTTPFormatter.escape_html(url)}</span> 
            <span class='http-version'>{HTTPFormatter.escape_html(http_ver)}</span>
        </div>"""

    @staticmethod
    def format_status_line(line: str) -> str:
        """Format HTTP status line (HTTP/VERSION STATUS_CODE MESSAGE)"""
        if not line.strip():
            return ""

        parts = line.split(" ", 2)
        if len(parts) < 2:
            return f"<div class='status-line'>{HTTPFormatter.escape_html(line)}</div>"

        http_ver = parts[0]
        status_code = parts[1] if len(parts) > 1 else ""
        status_msg = parts[2] if len(parts) > 2 else ""

        # Determine status code color
        status_class = "status-code-2xx"
        if status_code.startswith("3"):
            status_class = "status-code-3xx"
        elif status_code.startswith("4"):
            status_class = "status-code-4xx"
        elif status_code.startswith("5"):
            status_class = "status-code-5xx"

        return f"""<div class='status-line'>
            <span class='http-version'>{HTTPFormatter.escape_html(http_ver)}</span> 
            <span class='{status_class}'>{HTTPFormatter.escape_html(status_code)}</span> 
            <span class='status-message'>{HTTPFormatter.escape_html(status_msg)}</span>
        </div>"""

    @staticmethod
    def format_header(line: str) -> str:
        """Format a single HTTP header line"""
        if ":" not in line:
            return f"<div>{HTTPFormatter.escape_html(line)}</div>"

        header_parts = line.split(":", 1)
        header_name = header_parts[0].strip()
        header_value = header_parts[1].strip() if len(header_parts) > 1 else ""

        return f"""<div>
            <span class='header-name'>{HTTPFormatter.escape_html(header_name)}</span>
            <span class='header-separator'>: </span>
            <span class='header-value'>{HTTPFormatter.escape_html(header_value)}</span>
        </div>"""

    @staticmethod
    def format_body_content(body_text: str) -> str:
        """Format body content with syntax highlighting for JSON, HTML, etc."""
        body_text = body_text.strip()

        if not body_text:
            return (
                "<span style='color: #808080; font-style: italic;'>(empty body)</span>"
            )

        # Try to detect and format JSON
        if (body_text.startswith("{") or body_text.startswith("[")) and len(
            body_text
        ) < PRETTIFY_SIZE_LIMIT:
            try:
                parsed = json.loads(body_text)
                formatted_json = json.dumps(parsed, indent=4)
                return HTTPFormatter.highlight_json(formatted_json)
            except (json.JSONDecodeError, ValueError):
                pass

        # Try to format HTML
        if (
            "<html" in body_text.lower()
            or "<!doctype" in body_text.lower()
            or body_text.strip().startswith("<")
        ):
            try:
                return HTTPFormatter.highlight_html(body_text[:MAX_HTML_DISPLAY_LENGTH])
            except Exception as e:
                logger.debug(f"HTML highlighting failed: {e}")

        # URL-encoded data
        if "&" in body_text and "=" in body_text and "<" not in body_text:
            return HTTPFormatter.highlight_urlencoded(body_text)

        # Plain text - escape and return
        return HTTPFormatter.escape_html(body_text[:MAX_BODY_LENGTH])

    @staticmethod
    def highlight_json(json_text: str) -> str:
        """Highlight JSON syntax with preserved formatting"""
        # Escape HTML first
        json_text = HTTPFormatter.escape_html(json_text)

        # Highlight JSON keys
        json_text = RegexPatterns.JSON_KEY.sub(
            r'<span class="json-key">"\1"</span><span class="header-separator">:</span>',
            json_text,
        )

        # Highlight string values
        json_text = RegexPatterns.JSON_STRING_VALUE.sub(
            r': <span class="json-string">"\1"</span>', json_text
        )

        # Highlight numbers
        json_text = RegexPatterns.JSON_NUMBER.sub(
            r'<span class="json-number">\1</span>', json_text
        )

        # Highlight booleans and null
        json_text = RegexPatterns.JSON_BOOLEAN.sub(
            r'<span class="json-boolean">\1</span>', json_text
        )
        json_text = RegexPatterns.JSON_NULL.sub(
            r'<span class="json-null">null</span>', json_text
        )

        # Preserve whitespace and newlines
        json_text = json_text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

        return json_text

    @staticmethod
    def highlight_html(html_text: str) -> str:
        """Highlight HTML syntax with preserved formatting"""
        # Escape HTML first
        html_text = HTTPFormatter.escape_html(html_text)

        # Highlight opening tags with attributes
        html_text = RegexPatterns.HTML_TAG_WITH_ATTRS.sub(
            lambda m: HTTPFormatter._highlight_tag_with_attrs(m.group(1), m.group(2)),
            html_text,
        )

        # Highlight self-closing tags
        html_text = RegexPatterns.HTML_SELF_CLOSING.sub(
            lambda m: HTTPFormatter._highlight_tag_with_attrs(
                m.group(1), m.group(2), self_closing=True
            ),
            html_text,
        )

        # Highlight closing tags
        html_text = RegexPatterns.HTML_CLOSING_TAG.sub(
            r'<span class="html-tag">&lt;/\1&gt;</span>', html_text
        )

        # Preserve whitespace and newlines
        html_text = html_text.replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;")

        return html_text

    @staticmethod
    def _highlight_tag_with_attrs(
        tag_name: str, attrs_str: str, self_closing: bool = False
    ) -> str:
        """Helper to highlight a tag with its attributes"""
        result = '<span class="html-tag">&lt;' + tag_name + "</span>"

        if attrs_str:
            matches = RegexPatterns.HTML_ATTR_PATTERN.finditer(attrs_str)
            last_end = 0
            highlighted_attrs = []

            for match in matches:
                # Add any whitespace before this attribute
                if match.start() > last_end:
                    highlighted_attrs.append(attrs_str[last_end : match.start()])

                attr_name = match.group(1)
                attr_value = match.group(2)

                # Highlight attribute name and value
                highlighted_attrs.append(
                    f'<span class="html-attr">{attr_name}</span>='
                    f'<span class="html-attr-value">{attr_value}</span>'
                )

                last_end = match.end()

            # Add any remaining whitespace
            if last_end < len(attrs_str):
                highlighted_attrs.append(attrs_str[last_end:])

            result += "".join(highlighted_attrs)

        if self_closing:
            result += '<span class="html-tag"> /&gt;</span>'
        else:
            result += '<span class="html-tag">&gt;</span>'

        return result

    @staticmethod
    def highlight_urlencoded(text: str) -> str:
        """Highlight URL-encoded data"""
        pairs = text.split("&")
        formatted_pairs = []

        for pair in pairs:
            if "=" in pair:
                key, value = pair.split("=", 1)
                formatted_pairs.append(
                    f'<span class="json-key">{HTTPFormatter.escape_html(key)}</span>'
                    f'<span class="header-separator">=</span>'
                    f'<span class="json-string">{HTTPFormatter.escape_html(value)}</span>'
                )
            else:
                formatted_pairs.append(HTTPFormatter.escape_html(pair))

        return "<br>".join(formatted_pairs)

    @staticmethod
    def format_http_message(text: str, message_type: str = "request") -> str:
        """
        Unified HTTP message formatter

        Args:
            text: Raw HTTP message
            message_type: "request" or "response"

        Returns:
            HTML formatted message
        """
        if not text or not text.strip():
            return f"<p style='color: #808080;'>Empty {message_type}</p>"

        lines = text.split("\n")
        if not lines or not lines[0].strip():
            return f"<p style='color: #ff6633;'>Invalid HTTP {message_type}</p>"

        html_output = []
        html_output.append("<html><head><style>")
        html_output.append(HTTPFormatter.get_common_css())
        html_output.append("</style></head><body>")

        # Parse first line
        if message_type == "request":
            html_output.append(HTTPFormatter.format_request_line(lines[0]))
        else:
            html_output.append(HTTPFormatter.format_status_line(lines[0]))

        # Parse headers and body
        in_body = False
        body_lines = []

        for i, line in enumerate(lines[1:], 1):
            # Empty line indicates start of body
            if not line.strip() and not in_body:
                in_body = True
                html_output.append("<div class='body-separator'>---</div>")
                continue

            # Body content
            if in_body:
                body_lines.append(line)
                continue

            # Header lines
            html_output.append(HTTPFormatter.format_header(line))

        # Format body content
        if body_lines:
            body_text = "\n".join(body_lines)
            formatted_body = HTTPFormatter.format_body_content(body_text)
            html_output.append(f"<div class='body-content'>{formatted_body}</div>")

        html_output.append("</body></html>")
        return "".join(html_output)

class RegexPatterns:
    """Pre-compiled regex patterns for performance"""

    # JSON highlighting
    JSON_KEY = re.compile(r'"([^"]+)"\s*:')
    JSON_STRING_VALUE = re.compile(r':\s*"([^"]*)"')
    JSON_NUMBER = re.compile(r"\b(\d+\.?\d*)\b")
    JSON_BOOLEAN = re.compile(r"\b(true|false)\b")
    JSON_NULL = re.compile(r"\bnull\b")

    # HTML highlighting
    HTML_TAG_WITH_ATTRS = re.compile(
        r'&lt;(\w+)((?:\s+[\w-]+=(?:"[^"]*"|\'[^\']*\'))*)\s*&gt;'
    )
    HTML_SELF_CLOSING = re.compile(
        r'&lt;(\w+)((?:\s+[\w-]+=(?:"[^"]*"|\'[^\']*\'))*)\s*/&gt;'
    )
    HTML_CLOSING_TAG = re.compile(r"&lt;/(\w+)&gt;")
    HTML_ATTR_PATTERN = re.compile(r'([\w-]+)=((?:"[^"]*"|\'[^\']*\'))')

    # Detection patterns
    SINK_PATTERN = re.compile(r"SINK:([^\|]+)")
    SOURCE_PATTERN = re.compile(r"SOURCE:([^\|]+)")
    DATA_FLOW_PATTERN = re.compile(r"DATA_FLOW:([^\|]+)")
    CODE_PATTERN = re.compile(r"CODE:([^\|]+)")
    VULN_WORD_BOUNDARY = re.compile(r"\b({})\b")

    # URL parameter parsing
    URL_PARAM_PATTERN = re.compile(r"([^&=]+)=([^&]*)")

if _PYQT_AVAILABLE:
    class HttpSyntaxHighlighter(QSyntaxHighlighter):
        def __init__(self, parent=None):
            super().__init__(parent)

            # Request line: method
            self.method_fmt = QTextCharFormat()
            self.method_fmt.setForeground(QColor("#569cd6"))   # blue
            self.method_fmt.setFontWeight(QFont.Bold)

            # Request line: path / URL
            self.url_fmt = QTextCharFormat()
            self.url_fmt.setForeground(QColor("#dcdcaa"))       # yellow

            # Request line: HTTP version  /  response reason phrase
            self.ver_fmt = QTextCharFormat()
            self.ver_fmt.setForeground(QColor("#b5cea8"))       # muted green

            # Response status codes
            self.status_ok_fmt = QTextCharFormat()
            self.status_ok_fmt.setForeground(QColor("#4ec994"))
            self.status_ok_fmt.setFontWeight(QFont.Bold)

            self.status_err_fmt = QTextCharFormat()
            self.status_err_fmt.setForeground(QColor("#f48771"))
            self.status_err_fmt.setFontWeight(QFont.Bold)

            # Header name  (Cookie, Content-Type, …)
            self.header_key_fmt = QTextCharFormat()
            self.header_key_fmt.setForeground(QColor("#9cdcfe"))  # light blue
            self.header_key_fmt.setFontWeight(QFont.Bold)

            # Header value – generic fallback colour
            self.header_val_fmt = QTextCharFormat()
            self.header_val_fmt.setForeground(QColor("#ce9178"))  # orange

            # Sub-token KEY  (e.g. "session" in  session=abc123)
            self.sub_key_fmt = QTextCharFormat()
            self.sub_key_fmt.setForeground(QColor("#9cdcfe"))     # light blue

            # Sub-token VALUE  (e.g. "abc123" in  session=abc123)
            self.sub_val_fmt = QTextCharFormat()
            self.sub_val_fmt.setForeground(QColor("#ce9178"))     # orange

            # Separators: = ; &  inside header values
            self.sep_fmt = QTextCharFormat()
            self.sep_fmt.setForeground(QColor("#808080"))         # grey

            # Pre-compiled Python regex for %XX sequences (used in all states)
            self._pct_re = re.compile(r'%[0-9A-Fa-f]{2}')

            # Body – JSON
            self.json_key_fmt = QTextCharFormat()
            self.json_key_fmt.setForeground(QColor("#9cdcfe"))

            self.json_val_fmt = QTextCharFormat()
            self.json_val_fmt.setForeground(QColor("#ce9178"))

            self.json_kw_fmt = QTextCharFormat()
            self.json_kw_fmt.setForeground(QColor("#569cd6"))     # true/false/null

            self.json_num_fmt = QTextCharFormat()
            self.json_num_fmt.setForeground(QColor("#b5cea8"))    # numbers

            # Body – HTML
            self.html_tag_fmt = QTextCharFormat()
            self.html_tag_fmt.setForeground(QColor("#569cd6"))

            self.html_attr_fmt = QTextCharFormat()
            self.html_attr_fmt.setForeground(QColor("#9cdcfe"))

            # URL-encoded percent sequences (%2F, %20, %3D …)
            self.url_enc_fmt = QTextCharFormat()
            self.url_enc_fmt.setForeground(QColor("#4ec9b0"))   # teal
            self.url_enc_fmt.setFontWeight(QFont.Bold)

            # ── pre-compiled patterns ───────────────────────────────────
            # Matches:  key=value  or  key  (no value) separated by ; or &
            self._kv_re = re.compile(r'([^=;&\s][^=;&]*)(?:(=)([^;&]*))?')

            # Body rules applied in order (later rules override earlier for same range)
            self.body_rules = [
                (QRegularExpression(r'"[^"]*"\s*:'),              self.json_key_fmt),
                (QRegularExpression(r':\s*"[^"]*"'),              self.json_val_fmt),
                (QRegularExpression(r':\s*-?\d+(\.\d+)?'),        self.json_num_fmt),
                (QRegularExpression(r'\b(true|false|null)\b'),    self.json_kw_fmt),
                (QRegularExpression(r'</?[a-zA-Z][a-zA-Z0-9]*'), self.html_tag_fmt),
                (QRegularExpression(r'\s[a-zA-Z_][\w-]+='),      self.html_attr_fmt),
                (QRegularExpression(r'="[^"]*"'),                 self.json_val_fmt),
                (QRegularExpression(r'%[0-9A-Fa-f]{2}'),          self.url_enc_fmt),
            ]

        # Headers whose values contain key=value token streams
        _KV_HDRS = frozenset({
            'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
            'www-authenticate', 'proxy-authenticate',
        })

        def _apply_kv(self, value_text, offset):
            """Colour key=value tokens inside a header value string."""
            pos = 0
            n = len(value_text)
            while pos < n:
                # skip leading spaces / separators
                while pos < n and value_text[pos] in ' \t':
                    self.setFormat(offset + pos, 1, self.sep_fmt)
                    pos += 1
                m = self._kv_re.match(value_text, pos)
                if not m:
                    pos += 1
                    continue
                # key part
                self.setFormat(offset + m.start(1), len(m.group(1)), self.sub_key_fmt)
                if m.group(2):  # '='
                    self.setFormat(offset + m.start(2), 1, self.sep_fmt)
                if m.group(3):  # value part
                    self.setFormat(offset + m.start(3), len(m.group(3)), self.sub_val_fmt)
                pos = m.end()
                # separator (; or &) right after the token
                if pos < n and value_text[pos] in ';&':
                    self.setFormat(offset + pos, 1, self.sep_fmt)
                    pos += 1

        def highlightBlock(self, text):
            state = self.previousBlockState()
            if state == -1:
                state = 0   # 0 = request/status line, 1 = headers, 2 = body

            if state == 0:
                if text.strip():
                    if text.startswith('HTTP/'):
                        # Response line: HTTP/1.1 200 OK
                        parts = text.split(' ', 2)
                        self.setFormat(0, len(parts[0]), self.ver_fmt)
                        if len(parts) >= 2:
                            code_off = len(parts[0]) + 1
                            try:
                                code = int(parts[1])
                                fmt = self.status_ok_fmt if 200 <= code < 400 else self.status_err_fmt
                            except ValueError:
                                fmt = self.ver_fmt
                            self.setFormat(code_off, len(parts[1]), fmt)
                            if len(parts) >= 3:
                                self.setFormat(code_off + len(parts[1]) + 1,
                                               len(parts[2]), fmt)
                    else:
                        # Request line: METHOD /path HTTP/1.1
                        parts = text.split(' ', 2)
                        self.setFormat(0, len(parts[0]), self.method_fmt)
                        if len(parts) >= 2:
                            p_off = len(parts[0]) + 1
                            self.setFormat(p_off, len(parts[1]), self.url_fmt)
                            # Highlight %XX sequences within the URL path
                            for m in self._pct_re.finditer(parts[1]):
                                self.setFormat(p_off + m.start(), m.end() - m.start(),
                                               self.url_enc_fmt)
                            # Highlight + (encoded space) in the query string only
                            q_idx = parts[1].find('?')
                            if q_idx != -1:
                                for m in re.finditer(r'\+', parts[1][q_idx:]):
                                    self.setFormat(p_off + q_idx + m.start(), 1,
                                                   self.url_enc_fmt)
                        if len(parts) >= 3:
                            v_off = len(parts[0]) + 1 + len(parts[1]) + 1
                            self.setFormat(v_off, len(parts[2]), self.ver_fmt)
                    self.setCurrentBlockState(1)
                else:
                    self.setCurrentBlockState(0)

            elif state == 1:
                if not text.strip():
                    self.setCurrentBlockState(2)
                else:
                    colon = text.find(':')
                    if colon != -1:
                        # Header name
                        self.setFormat(0, colon, self.header_key_fmt)
                        # Whole value – base colour first
                        val_off  = colon + 1
                        val_text = text[val_off:]
                        self.setFormat(val_off, len(val_text), self.header_val_fmt)
                        # Sub-token pass for headers that carry key=value payloads
                        hdr_name = text[:colon].strip().lower()
                        if hdr_name in self._KV_HDRS:
                            self._apply_kv(val_text, val_off)
                        # Highlight %XX in any header value
                        for m in self._pct_re.finditer(val_text):
                            self.setFormat(val_off + m.start(), m.end() - m.start(),
                                           self.url_enc_fmt)
                    self.setCurrentBlockState(1)

            elif state == 2:
                for pattern, fmt in self.body_rules:
                    it = pattern.globalMatch(text)
                    while it.hasNext():
                        m = it.next()
                        self.setFormat(m.capturedStart(), m.capturedLength(), fmt)
                # URL-encoded form body: key=value&key2=value2
                stripped = text.strip()
                if stripped and '=' in stripped and stripped[0] not in '{[<':
                    lead = len(text) - len(text.lstrip())
                    self._apply_kv(stripped, lead)
                    # Highlight %XX and + (encoded space) in form body
                    for m in self._pct_re.finditer(text):
                        self.setFormat(m.start(), m.end() - m.start(), self.url_enc_fmt)
                    for m in re.finditer(r'\+', text):
                        self.setFormat(m.start(), 1, self.url_enc_fmt)
                self.setCurrentBlockState(2)


    # ─────────────────────────────────────────────────────────────────────────
    # GraphQL syntax highlighter
    # ─────────────────────────────────────────────────────────────────────────
    class GQLSyntaxHighlighter(QSyntaxHighlighter):
        """Simple GraphQL syntax highlighter for the GQL query/mutation panels."""

        def __init__(self, parent=None):
            super().__init__(parent)

            # operation keywords: query mutation subscription fragment on
            kw_fmt = QTextCharFormat()
            kw_fmt.setForeground(QColor("#c586c0"))   # purple
            kw_fmt.setFontWeight(QFont.Bold)

            # type / directive names (CapitalCase identifiers or @directive)
            type_fmt = QTextCharFormat()
            type_fmt.setForeground(QColor("#4ec9b0"))  # teal

            # field / argument names (lowerCase identifiers)
            field_fmt = QTextCharFormat()
            field_fmt.setForeground(QColor("#9cdcfe"))  # light blue

            # argument values / strings
            str_fmt = QTextCharFormat()
            str_fmt.setForeground(QColor("#ce9178"))   # orange

            # numbers
            num_fmt = QTextCharFormat()
            num_fmt.setForeground(QColor("#b5cea8"))   # muted green

            # boolean / null literals
            bool_fmt = QTextCharFormat()
            bool_fmt.setForeground(QColor("#569cd6"))  # blue

            # variables: $varName
            var_fmt = QTextCharFormat()
            var_fmt.setForeground(QColor("#dcdcaa"))   # yellow

            # braces / brackets / parens  { } [ ] ( )
            brace_fmt = QTextCharFormat()
            brace_fmt.setForeground(QColor("#ffd700"))  # gold
            brace_fmt.setFontWeight(QFont.Bold)

            # comments  # ...
            comment_fmt = QTextCharFormat()
            comment_fmt.setForeground(QColor("#6a9955"))  # green
            comment_fmt.setFontItalic(True)

            # directives  @skip  @include  @deprecated ...
            directive_fmt = QTextCharFormat()
            directive_fmt.setForeground(QColor("#c586c0"))  # purple
            directive_fmt.setFontItalic(True)

            # colon :
            colon_fmt = QTextCharFormat()
            colon_fmt.setForeground(QColor("#808080"))

            self._rules = [
                (QRegularExpression(r'\b(query|mutation|subscription|fragment|on|type|input|enum|interface|union|schema|extend|implements|scalar)\b'), kw_fmt),
                (QRegularExpression(r'\b(true|false|null)\b'), bool_fmt),
                (QRegularExpression(r'\$[A-Za-z_]\w*'), var_fmt),
                (QRegularExpression(r'@[A-Za-z_]\w*'), directive_fmt),
                (QRegularExpression(r'\b[A-Z][A-Za-z0-9_]*\b'), type_fmt),
                (QRegularExpression(r'\b[a-z_]\w*(?=\s*[:({\[]|\s*\))'), field_fmt),
                (QRegularExpression(r'"(?:[^"\\]|\\.)*"'), str_fmt),
                (QRegularExpression(r"-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b"), num_fmt),
                (QRegularExpression(r"[{}()\[\]]"), brace_fmt),
                (QRegularExpression(r':'), colon_fmt),
                (QRegularExpression(r'#[^\n]*'), comment_fmt),
            ]

        def highlightBlock(self, text):
            for pattern, fmt in self._rules:
                it = pattern.globalMatch(text)
                while it.hasNext():
                    m = it.next()
                    self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


    # ─────────────────────────────────────────────────────────────────────────
    # JSON syntax highlighter
    # ─────────────────────────────────────────────────────────────────────────
    class JSONSyntaxHighlighter(QSyntaxHighlighter):
        """JSON highlighter used for Variables / Data / Errors / Extensions panels."""

        def __init__(self, parent=None):
            super().__init__(parent)

            key_fmt = QTextCharFormat()
            key_fmt.setForeground(QColor("#9cdcfe"))   # light blue

            str_val_fmt = QTextCharFormat()
            str_val_fmt.setForeground(QColor("#ce9178"))  # orange

            num_fmt = QTextCharFormat()
            num_fmt.setForeground(QColor("#b5cea8"))   # muted green

            kw_fmt = QTextCharFormat()
            kw_fmt.setForeground(QColor("#569cd6"))    # blue  (true/false/null)

            brace_fmt = QTextCharFormat()
            brace_fmt.setForeground(QColor("#ffd700")) # gold
            brace_fmt.setFontWeight(QFont.Bold)

            colon_fmt = QTextCharFormat()
            colon_fmt.setForeground(QColor("#808080"))

            self._rules = [
                # JSON object key + colon must come before generic strings
                (QRegularExpression(r'"(?:[^"\\]|\\.)*"\s*:'), key_fmt),
                # values that are strings
                (QRegularExpression(r':\s*"(?:[^"\\]|\\.)*"'), str_val_fmt),
                # bare strings (array elements)
                (QRegularExpression(r'(?<!["\w])"(?:[^"\\]|\\.)*"'), str_val_fmt),
                (QRegularExpression(r'\b(true|false|null)\b'), kw_fmt),
                (QRegularExpression(r"-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b"), num_fmt),
                (QRegularExpression(r'[{}()\[\]]'), brace_fmt),
                (QRegularExpression(r':'), colon_fmt),
            ]

        def highlightBlock(self, text):
            for pattern, fmt in self._rules:
                it = pattern.globalMatch(text)
                while it.hasNext():
                    m = it.next()
                    self.setFormat(m.capturedStart(), m.capturedLength(), fmt)
