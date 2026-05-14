"""
js_miner_tab.py — JS Miner Tab
Deep security analysis of JavaScript and JSX files collected from HTTP traffic.

Features:
  • Live queue that auto-populates from HTTP History (.js / .jsx / .mjs / .ts / .tsx traffic)
  • Per-file analysis worker thread (non-blocking)
  • 9 detection engines: endpoints, secrets, DOM XSS, open redirects,
    CORS, GraphQL, WebSocket, cloud infrastructure, token storage,
    source maps, taint flows, prototype pollution, postMessage
  • Findings tree organised by category with severity colouring
  • Raw JS viewer with syntax-keyword highlighting
  • Export per-file or full session
"""

try:
    import regex as re   # pip install regex  — faster engine, same API
except ImportError:
    import re
import os
import json
import math
import logging
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlparse
import urllib.request
import urllib.error

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget,
    QTreeWidgetItem, QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QCheckBox, QLineEdit, QTextEdit,
    QAbstractItemView, QMenu, QAction, QApplication, QTabWidget,
    QProgressBar, QFrame, QMessageBox, QFileDialog
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QMutex, QMutexLocker
from PyQt5.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QBrush, QTextCursor

try:
    from constants import *
except ImportError:
    COLOR_BACKGROUND   = "#1e1e1e"
    COLOR_ELEVATED_BG  = "#252525"
    COLOR_CARD_BG      = "#2d2d2d"
    COLOR_DARK_BG      = "#181818"
    COLOR_BORDER       = "#3e3e3e"
    COLOR_TEXT         = "#cccccc"
    COLOR_TEXT_BRIGHT  = "#ffffff"
    COLOR_TEXT_MUTED   = "#808080"
    COLOR_ACCENT       = "#0e639c"
    COLOR_SUCCESS      = "#4ec9b0"
    COLOR_WARNING      = "#ce9178"
    COLOR_CRITICAL     = "#f48771"
    COLOR_HIGH         = "#ff6b6b"
    COLOR_MEDIUM       = "#feca57"
    COLOR_INFO         = "#48dbfb"

# Safety fallbacks — constants.py may not define every color
try:
    COLOR_WARNING
except NameError:
    COLOR_WARNING = "#ce9178"
try:
    COLOR_HIGH
except NameError:
    COLOR_HIGH = "#ff6b6b"
try:
    COLOR_MEDIUM
except NameError:
    COLOR_MEDIUM = "#feca57"
try:
    COLOR_INFO
except NameError:
    COLOR_INFO = "#48dbfb"
try:
    COLOR_CRITICAL
except NameError:
    COLOR_CRITICAL = "#f48771"
try:
    COLOR_TEXT_MUTED
except NameError:
    COLOR_TEXT_MUTED = "#808080"
try:
    COLOR_DARK_BG
except NameError:
    COLOR_DARK_BG = "#181818"

try:
    from analysis_tab import JavaScriptAnalyzer, FrameworkDetector
except ImportError:
    JavaScriptAnalyzer = None
    FrameworkDetector  = None

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ─────────────────────────────────────────────────────────────────────────────
SEV_COLOR = {
    "CRITICAL": COLOR_CRITICAL,
    "HIGH":     COLOR_HIGH,
    "MEDIUM":   COLOR_MEDIUM,
    "LOW":      COLOR_INFO,
    "INFO":     COLOR_TEXT_MUTED,
}
SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

CATEGORY_META = {
    "🔑 Secrets & Keys":         {"sev": "CRITICAL", "desc": "Hardcoded API keys, passwords, tokens found in JS"},
    "☁️ Cloud Infrastructure":   {"sev": "HIGH",     "desc": "S3 buckets, Firebase URLs, AWS/GCP/Azure identifiers"},
    "🗺️ Endpoints & Paths":      {"sev": "HIGH",     "desc": "Hidden API routes and internal paths extracted from JS"},
    "🌐 Hosts & Subdomains":     {"sev": "HIGH",     "desc": "Hardcoded hostnames, internal/staging URLs"},
    "💥 DOM XSS Sinks":          {"sev": "HIGH",     "desc": "innerHTML, eval, document.write, jQuery sinks"},
    "🔀 Open Redirects":         {"sev": "HIGH",     "desc": "User-controlled location.href, window.open()"},
    "🌊 Taint Flows":            {"sev": "HIGH",     "desc": "User input → dangerous sink data flow chains"},
    "📨 postMessage / WS":       {"sev": "HIGH",     "desc": "WebSocket usage and postMessage without origin check"},
    "🔗 CORS Issues":            {"sev": "HIGH",     "desc": "credentials:include, withCredentials, dynamic origins"},
    "🧬 GraphQL":                {"sev": "MEDIUM",   "desc": "GraphQL endpoints, introspection, mutations"},
    "🗄️ Token Storage":          {"sev": "MEDIUM",   "desc": "JWT/token in localStorage, Authorization headers"},
    "🗃️ Source Maps":            {"sev": "HIGH",     "desc": "sourceMappingURL, webpack chunks exposing source"},
    "🧩 Prototype Pollution":    {"sev": "HIGH",     "desc": "__proto__, .prototype manipulation"},
    "📦 Frameworks & Libraries": {"sev": "INFO",     "desc": "Detected JS frameworks and library versions"},
    "📦 Dependency Confusion":   {"sev": "CRITICAL", "desc": "NPM package names missing from registry — supply chain risk"},
    "🗺️ Source Map Files":       {"sev": "HIGH",     "desc": "Fetched/reconstructed source from .map files"},
}


# ─────────────────────────────────────────────────────────────────────────────
# JS Syntax Highlighter
# ─────────────────────────────────────────────────────────────────────────────
class JSSyntaxHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = []

        def fmt(color, bold=False, italic=False):
            f = QTextCharFormat()
            f.setForeground(QColor(color))
            if bold:   f.setFontWeight(QFont.Bold)
            if italic: f.setFontItalic(True)
            return f

        kw = fmt("#569cd6", bold=True)
        for word in ["var","let","const","function","return","if","else","for",
                     "while","do","switch","case","break","continue","new","delete",
                     "typeof","instanceof","in","of","class","extends","import",
                     "export","default","async","await","try","catch","finally",
                     "throw","this","super","null","undefined","true","false"]:
            self.rules.append((re.compile(rf'\b{word}\b'), kw))

        self.rules.append((re.compile(r'//[^\n]*'),              fmt("#6a9955", italic=True)))
        self.rules.append((re.compile(r'/\*.*?\*/', re.DOTALL),  fmt("#6a9955", italic=True)))
        self.rules.append((re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"'), fmt("#ce9178")))
        self.rules.append((re.compile(r"'[^'\\]*(?:\\.[^'\\]*)*'"), fmt("#ce9178")))
        self.rules.append((re.compile(r'`[^`]*`', re.DOTALL),    fmt("#ce9178")))
        self.rules.append((re.compile(r'\b\d+\.?\d*\b'),          fmt("#b5cea8")))

        danger = fmt(COLOR_CRITICAL, bold=True)
        for d in ["eval","innerHTML","outerHTML",r"document\.write","setTimeout",
                  "setInterval","Function","execScript","insertAdjacentHTML"]:
            self.rules.append((re.compile(rf'\b{d}\b'), danger))

        self.rules.append((re.compile(r'\b(fetch|XMLHttpRequest|axios)\b'), fmt(COLOR_WARNING, bold=True)))
        self.rules.append((re.compile(r'\b(localStorage|sessionStorage|document\.cookie)\b'), fmt(COLOR_MEDIUM, bold=True)))

    def highlightBlock(self, text):
        for pattern, fmt in self.rules:
            for m in pattern.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ─────────────────────────────────────────────────────────────────────────────
# Analysis Worker
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────────────────
# Helper functions: Shannon entropy, NPM dependency confusion, .map fetching
# ─────────────────────────────────────────────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character).
    High entropy (>3.5) suggests a random/cryptographic value — reduces false positives.
    """
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


# Minimum entropy thresholds per secret type — tuned to match real credentials
_ENTROPY_THRESHOLDS = {
    "AWS_ACCESS_KEY":   3.5,
    "AWS_SECRET_KEY":   4.0,
    "GOOGLE_API_KEY":   3.5,
    "GITHUB_TOKEN":     3.8,
    "SLACK_TOKEN":      3.8,
    "STRIPE_KEY":       3.8,
    "GENERIC_SECRET":   3.5,
    "BEARER_TOKEN":     3.5,
    "PRIVATE_KEY":      3.0,
    "PASSWORD":         2.5,   # passwords can be low-entropy but still interesting
    "DEFAULT":          3.4,
}

# Common placeholder strings that look like secrets but are not
_SECRET_PLACEHOLDERS = {
    "your_api_key", "your-api-key", "api_key_here", "api-key-here",
    "your_secret", "your-secret", "secret_here", "replace_me",
    "insert_key", "enter_key", "xxx", "yyy", "zzz", "todo",
    "changeme", "change_me", "example", "placeholder", "dummy",
    "test_key", "fake_key", "sample_key", "my_api_key",
    "your_token", "your-token", "token_here", "<api_key>", "<token>",
}

def _entropy_ok(value: str, secret_type: str = "DEFAULT") -> bool:
    """Return True if value entropy meets the threshold for its type
    AND the value is not an obvious placeholder."""
    clean = value.strip().strip('"\'')
    if clean.lower() in _SECRET_PLACEHOLDERS:
        return False
    # Also reject anything that is ALL_CAPS_WITH_UNDERSCORES — usually a template var
    if re.fullmatch(r'[A-Z_]{4,}', clean):
        return False
    threshold = _ENTROPY_THRESHOLDS.get(secret_type,
                    _ENTROPY_THRESHOLDS["DEFAULT"])
    return _shannon_entropy(clean) >= threshold


# Regex patterns for NPM dependencies in JS/JSON
_NPM_DEP_PATTERNS = [
    # package.json style: "name": "version"
    re.compile(r'"(@?[a-z0-9][\w\-\.\/]{1,100})":\s*"[\^~]?\d+[\.\d\-\w]*"', re.IGNORECASE),
    # require("package")
    re.compile(r'require\(["\'](@?[\w\-\.\/]{2,80})["\']\)', re.IGNORECASE),
    # import ... from "package"
    re.compile(r'from\s+["\'](@?[\w\-\.\/]{2,80})["\']', re.IGNORECASE),
    # import("package")
    re.compile(r'import\(["\'](@?[\w\-\.\/]{2,80})["\']\)', re.IGNORECASE),
]

# Scoped org patterns for detecting missing orgs (higher risk)
_NPM_SCOPED_RE = re.compile(r'^@([\w\-]+)/')

_NPM_BUILTIN = {
    "fs", "path", "http", "https", "os", "util", "crypto", "events",
    "stream", "buffer", "url", "querystring", "net", "tls", "dns",
    "child_process", "cluster", "worker_threads", "readline", "zlib",
    "assert", "v8", "vm", "module", "process", "console", "timers",
}

_NPM_REGISTRY_CACHE: dict = {}   # url -> bool (exists)
_NPM_REGISTRY_TIMEOUT = 2        # seconds


def _check_npm_exists(package: str) -> Optional[bool]:
    """Check if a package name exists on the NPM registry.
    Returns True (exists), False (missing = vuln!), None (network error).
    Caches results to avoid hammering the registry.
    """
    if package in _NPM_REGISTRY_CACHE:
        return _NPM_REGISTRY_CACHE[package]
    try:
        # Use the scoped org name if present to check the org itself too
        check_name = package.split("/")[0] if package.startswith("@") else package
        url = f"https://registry.npmjs.org/{urllib.parse.quote(check_name, safe='@')}"
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "js-miner-checker/1.0"})
        with urllib.request.urlopen(req, timeout=_NPM_REGISTRY_TIMEOUT) as resp:
            result = resp.status == 200
    except urllib.error.HTTPError as e:
        result = e.code != 404
    except Exception:
        result = None
    if result is not None:
        _NPM_REGISTRY_CACHE[package] = result
    return result


def _extract_npm_packages(js: str) -> List[str]:
    """Extract candidate NPM package names from JS/JSON content."""
    seen: Set[str] = set()
    pkgs: List[str] = []
    for pat in _NPM_DEP_PATTERNS:
        for m in pat.finditer(js):
            name = m.group(1).strip()
            # Filter out relative paths, built-ins, and noise
            if (name.startswith((".", "/", "http", "//"))
                    or name in _NPM_BUILTIN
                    or len(name) < 2
                    or len(name) > 120):
                continue
            # Normalise: keep only the package root (strip deep paths like pkg/sub/file)
            root = "/".join(name.split("/")[:2]) if name.startswith("@") else name.split("/")[0]
            if root not in seen:
                seen.add(root)
                pkgs.append(root)
    return pkgs


def _fetch_map_file(map_url: str, timeout: int = 8) -> Optional[str]:
    """Try to fetch a .map file URL. Returns content string or None."""
    try:
        req = urllib.request.Request(
            map_url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; js-miner/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                raw = resp.read(5 * 1024 * 1024)  # cap at 5 MB
                return raw.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _candidate_map_urls(js_url: str, js_content: str) -> List[str]:
    """Build a list of .map URLs to try: inline comment + common guesses."""
    candidates: List[str] = []
    p = urlparse(js_url)
    base = js_url.rstrip("/")

    # 1. sourceMappingURL comment in the JS itself
    for m in re.finditer(r'//[#@]\s*sourceMappingURL=([^\s]+)', js_content):
        ref = m.group(1).strip()
        if ref.startswith("data:"):
            continue   # inline base64 — already handled by existing engine
        if ref.startswith("http"):
            candidates.append(ref)
        else:
            # relative path — resolve against JS URL
            base_dir = base.rsplit("/", 1)[0]
            candidates.append(f"{base_dir}/{ref.lstrip('/')}")

    # 2. Active guessing: common patterns
    js_name = p.path.split("/")[-1]  # e.g. app.abc123.js
    base_url = f"{p.scheme}://{p.netloc}"
    path_dir = "/".join(p.path.split("/")[:-1])

    for suffix in [".map", ".js.map", ".jsx.map"]:
        candidates.append(f"{base_url}{path_dir}/{js_name}{suffix}")
        candidates.append(f"{base_url}{path_dir}/{js_name.replace('.min.js', '.js')}{suffix}")
        candidates.append(f"{base_url}{path_dir}/{js_name.replace('.min.jsx', '.jsx')}{suffix}")
        # webpack chunk pattern: strip hash
        no_hash = re.sub(r'\.[a-f0-9]{8,20}\.(js|jsx)$', r'.\1', js_name)
        if no_hash != js_name:
            candidates.append(f"{base_url}{path_dir}/{no_hash}{suffix}")

    # Deduplicate preserving order
    seen: Set[str] = set()
    return [c for c in candidates if not (c in seen or seen.add(c))]


# ─────────────────────────────────────────────────────────────────────────────
# Parallel chunk analysis helpers
# ─────────────────────────────────────────────────────────────────────────────

# Chunk size: 300 KB gives ~4 chunks for a 1.2 MB file.
# Overlap: 2 KB so patterns that straddle a boundary are never missed.
_JS_CHUNK_SIZE    = 300_000
_JS_CHUNK_OVERLAP = 2_000


def _split_js_chunks(text: str,
                     chunk_size: int = _JS_CHUNK_SIZE,
                     overlap: int = _JS_CHUNK_OVERLAP) -> List[str]:
    """Split *text* into overlapping chunks for parallel analysis.
    Returns [text] unchanged when the file fits in a single chunk."""
    if len(text) <= chunk_size:
        return [text]
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = end - overlap        # step back so boundary patterns are covered
    return chunks


def _mp_run_js_chunk(url: str, js_chunk: str) -> dict:
    """
    Subprocess entry-point — regex/AST engines only (engines 1–12).
    Safe to run on any substring of the full JS (chunk-safe with overlap).
    Network I/O and whole-file heuristics live in _mp_run_js_wholefile.
    """
    from collections import defaultdict
    cats: dict = defaultdict(list)

    try:
        from analysis_tab import JavaScriptAnalyzer, SecurityAnalyzer
    except ImportError:
        return {"categories": cats}
    if JavaScriptAnalyzer is None:
        return {"categories": cats}

    # 1. Secrets & Keys
    for item in JavaScriptAnalyzer.extract_cloud_infrastructure(js_chunk):
        sev   = "CRITICAL" if item["type"] in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY") else "HIGH"
        value = item["value"]
        entropy = _shannon_entropy(value)
        if item["type"] in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY", "FIREBASE_DB",
                            "FIREBASE_APP", "S3_BUCKET", "S3_BUCKET_URI"):
            if not _entropy_ok(value, item["type"]):
                continue
            cats["🔑 Secrets & Keys"].append({
                "sev": sev, "title": item["type"],
                "value": value, "context": item["context"],
                "note": f"Entropy: {entropy:.2f} — verify credential is active"
            })
        else:
            cats["☁️ Cloud Infrastructure"].append({
                "sev": "HIGH", "title": item["type"],
                "value": value, "context": item["context"]
            })

    try:
        for s in SecurityAnalyzer._detect_javascript_secrets(js_chunk):
            value = s.get("value", "")[:120]
            stype = s.get("type", "GENERIC_SECRET")
            if not _entropy_ok(value, stype):
                continue
            cats["🔑 Secrets & Keys"].append({
                "sev": "CRITICAL", "title": stype, "value": value,
                "context": s.get("context", "")[:200],
                "note": f"Entropy: {_shannon_entropy(value):.2f} — Variable: {s.get('var_name','?')}"
            })
    except Exception:
        pass

    # 2. Endpoints & Paths
    for ep in JavaScriptAnalyzer.extract_endpoints(js_chunk):
        cats["🗺️ Endpoints & Paths"].append({
            "sev": "HIGH", "title": ep["value"],
            "value": ep["value"], "context": ep["context"],
            "note": "Probe this endpoint: auth bypass, IDOR, hidden functionality"
        })

    # 3. Hosts & Subdomains
    for h in JavaScriptAnalyzer.extract_subdomains_and_hosts(js_chunk):
        cats["🌐 Hosts & Subdomains"].append({
            "sev": h["severity"], "title": h["type"],
            "value": h["value"], "context": h["context"],
            "note": f"Host: {h['host']}"
        })

    # 4. DOM XSS Sinks
    try:
        for sink in SecurityAnalyzer._detect_dom_xss_sinks(js_chunk):
            cats["💥 DOM XSS Sinks"].append({
                "sev": sink["severity"], "title": sink["sink"],
                "value": sink["context"][:120], "context": sink["context"],
                "note": f"Type: {sink['type']} — trace user input to this sink"
            })
    except Exception:
        pass

    # 5. Taint Flows
    for flow_key, tags in JavaScriptAnalyzer.detect_critical_flow(js_chunk).items():
        sev    = "CRITICAL" if "CONFIRMED" in tags else "HIGH"
        chain  = next((t for t in tags if t.startswith("CHAIN:")),  "")
        source = next((t for t in tags if t.startswith("SOURCE:")), "")
        cats["🌊 Taint Flows"].append({
            "sev": sev, "title": flow_key,
            "value": chain.replace("CHAIN:", ""),
            "context": source.replace("SOURCE:", ""),
            "note": "Confirmed taint flow — high confidence XSS/RCE/redirect"
                    if sev == "CRITICAL" else "Possible taint flow — verify manually"
        })

    # 6. Open Redirects
    for rd in JavaScriptAnalyzer.detect_open_redirects(js_chunk):
        cats["🔀 Open Redirects"].append({
            "sev": rd["severity"], "title": rd["sink"],
            "value": rd["value"], "context": rd["context"],
            "note": "User-controlled redirect — test with external URL"
                    if rd["user_input"] else "Variable redirect — trace origin"
        })

    # 7. WebSocket & postMessage
    for wf in JavaScriptAnalyzer.detect_websocket_issues(js_chunk):
        cats["📨 postMessage / WS"].append({
            "sev": wf["severity"], "title": wf["type"],
            "value": wf.get("value", ""), "context": wf["context"], "note": wf["note"]
        })

    # 8. CORS
    for ci in JavaScriptAnalyzer.detect_cors_issues(js_chunk):
        cats["🔗 CORS Issues"].append({
            "sev": ci["severity"], "title": ci["type"],
            "value": ci["context"], "context": ci["context"], "note": ci["note"]
        })

    # 9. GraphQL
    for gf in JavaScriptAnalyzer.detect_graphql(js_chunk):
        cats["🧬 GraphQL"].append({
            "sev": gf["severity"], "title": gf["type"],
            "value": gf.get("value", ""), "context": gf["context"],
            "note": gf.get("note", "")
        })

    # 10. Token Storage
    for tf in JavaScriptAnalyzer.detect_token_storage(js_chunk):
        cats["🗄️ Token Storage"].append({
            "sev": tf["severity"], "title": tf["type"],
            "value": tf.get("key", tf.get("value", ""))[:80],
            "context": tf["context"], "note": tf["note"]
        })

    # 11. Source Maps — passive detection
    for sm in JavaScriptAnalyzer.detect_source_maps(js_chunk, url):
        cats["🗃️ Source Maps"].append({
            "sev": sm["severity"], "title": sm["type"],
            "value": sm["value"], "context": sm["context"], "note": sm["note"]
        })

    # 12. Prototype Pollution
    for p in set(re.findall(r'(__proto__|constructor\[.*?\]|\.prototype\.\w+)', js_chunk)):
        cats["🧩 Prototype Pollution"].append({
            "sev": "HIGH", "title": "PROTOTYPE_POLLUTION",
            "value": p[:100], "context": p[:200],
            "note": "Test for prototype pollution via controllable keys"
        })

    return {"categories": cats}


def _mp_run_js_wholefile(url: str, js: str, existing_cache: dict = None) -> dict:
    """
    Subprocess entry-point — whole-file / network engines (11b, 13, 14).
    Runs concurrently with chunk workers so network latency overlaps with
    the regex work in the chunk processes.
    """
    from collections import defaultdict
    from concurrent.futures import ThreadPoolExecutor as _TPool
    cats: dict = defaultdict(list)

    # Pre-populate the local npm cache with results from previous analyses
    # so already-known packages skip the network round trip entirely.
    if existing_cache:
        _NPM_REGISTRY_CACHE.update(existing_cache)

    try:
        from analysis_tab import FrameworkDetector
    except ImportError:
        FrameworkDetector = None

    # 11b. Active .map file fetching — cap to 3 candidates to avoid long waits
    map_candidates = _candidate_map_urls(url, js)[:3]
    for map_url in map_candidates:
        map_content = _fetch_map_file(map_url)
        if not map_content:
            continue
        try:
            sm_data = json.loads(map_content)
            sources = sm_data.get("sources", [])
            interesting = [s for s in sources if any(
                kw in s.lower() for kw in
                ("secret", "config", "auth", "token", "api", "key", "admin", "internal",
                 "password", "credential", "private", "env")
            )]
            note_parts = [f"{len(sources)} source files recovered"]
            if interesting:
                note_parts.append(f"⚠️ Sensitive paths: {', '.join(interesting[:5])}")
            cats["🗺️ Source Map Files"].append({
                "sev": "CRITICAL" if interesting else "HIGH",
                "title": "SOURCE_MAP_FETCHED", "value": map_url,
                "context": f"Sources: {', '.join(sources[:10])}{'…' if len(sources) > 10 else ''}",
                "note": " | ".join(note_parts)
            })
        except (json.JSONDecodeError, KeyError):
            cats["🗺️ Source Map Files"].append({
                "sev": "HIGH", "title": "SOURCE_MAP_ACCESSIBLE",
                "value": map_url, "context": map_content[:200],
                "note": "Map file is accessible (non-standard format)"
            })
        break   # only first fetchable map per file

    # 13. Frameworks (needs full/large sample for accuracy)
    if FrameworkDetector:
        try:
            for fw_name, evidence in FrameworkDetector.detect_javascript_frameworks("", js).items():
                cats["📦 Frameworks & Libraries"].append({
                    "sev": "INFO", "title": fw_name, "value": fw_name,
                    "context": " | ".join(evidence[:4]),
                    "note": "Check for framework-specific vulnerabilities"
                })
        except Exception:
            pass

    # 14. Dependency Confusion — parallel npm registry checks
    # Cap at 20 packages; cache pre-populated above to skip known ones.
    pkg_list = _extract_npm_packages(js)[:20]

    def _check_one(pkg):
        return pkg, _check_npm_exists(pkg)

    with _TPool(max_workers=10) as pool:
        for pkg, exists in pool.map(_check_one, pkg_list):
            is_scoped = pkg.startswith("@")
            if exists is False:
                cats["📦 Dependency Confusion"].append({
                    "sev": "CRITICAL", "title": "DEP_CONFUSION_MISSING", "value": pkg,
                    "context": f"Package '{pkg}' not found on NPM registry",
                    "note": f"{'Scoped org' if is_scoped else 'Package'} '{pkg}' is not on NPM — "
                            "register it before an attacker does (supply chain risk)"
                })
            else:
                cats["📦 Dependency Confusion"].append({
                    "sev": "INFO", "title": "DEP_FOUND", "value": pkg,
                    "context": f"Package '{pkg}' found on NPM registry",
                    "note": "Verify this is the intended package version"
                })

    # Return the updated cache so the parent process can persist it
    return {"categories": cats, "npm_cache": dict(_NPM_REGISTRY_CACHE)}


def _merge_js_results(url: str, js: str, results_list: list) -> dict:
    """
    Merge per-chunk and wholefile result dicts into one final result dict.
    Deduplicates findings by (category, title, value[:80]) so overlapping
    chunks never produce duplicate entries.
    """
    from collections import defaultdict
    from datetime import datetime

    merged_cats: dict = defaultdict(list)
    seen: set = set()

    for partial in results_list:
        for cat, items in partial.get("categories", {}).items():
            for item in items:
                key = (cat, item.get("title", ""), item.get("value", "")[:80])
                if key in seen:
                    continue
                seen.add(key)
                merged_cats[cat].append(item)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}
    for cat_items in merged_cats.values():
        for item in cat_items:
            sev = item.get("sev", "INFO").upper()
            summary[sev.lower()] = summary.get(sev.lower(), 0) + 1
            summary["total"] += 1

    return {
        "url":        url,
        "size":       len(js),
        "analysed":   datetime.now().isoformat(),
        "js_content": js[:500_000],
        "categories": merged_cats,
        "summary":    summary,
    }


class JSAnalysisWorker(QThread):
    """
    Background worker: loads JS content (fast I/O on the QThread) then runs
    all detection engines in a *separate process* via ProcessPoolExecutor so
    that CPU/regex work never shares the main thread's GIL and the UI stays
    fully responsive even on large minified JS files.
    """
    finished  = pyqtSignal(str, dict)   # url, results_dict
    progress  = pyqtSignal(str, str)    # url, status_message
    error     = pyqtSignal(str, str)    # url, error_message

    def __init__(self, url: str, response_file: str = None, js_content: str = None, npm_cache: dict = None):
        super().__init__()
        self.url           = url
        self.response_file = response_file
        self._js_content   = js_content
        self._npm_cache    = dict(npm_cache) if npm_cache else {}

    def run(self):
        from concurrent.futures import ProcessPoolExecutor, as_completed
        try:
            self.progress.emit(self.url, "⏳ Loading content…")
            js = self._load_content()
            if not js:
                self.error.emit(self.url, "Empty or unreadable JS content")
                return

            chunks   = _split_js_chunks(js)
            n_chunks = len(chunks)
            # +1 worker for the wholefile task (frameworks + npm + map fetch)
            n_workers = min(n_chunks + 1, 6)
            self.progress.emit(
                self.url,
                f"🔬 Analysing {n_chunks} chunk{'s' if n_chunks > 1 else ''} "
                f"across {n_workers} parallel processes…"
            )

            all_partial: list = []
            with ProcessPoolExecutor(max_workers=n_workers) as executor:
                # Submit all chunk jobs + the wholefile job simultaneously
                futures = {
                    executor.submit(_mp_run_js_chunk, self.url, chunk): f"chunk-{i}"
                    for i, chunk in enumerate(chunks)
                }
                futures[executor.submit(_mp_run_js_wholefile, self.url, js[:600_000], self._npm_cache)] = "wholefile"

                done = 0
                for future in as_completed(futures, timeout=300):
                    done += 1
                    self.progress.emit(
                        self.url,
                        f"🔬 {done}/{len(futures)} tasks done…"
                    )
                    partial = future.result()
                    # Extract updated npm cache from the wholefile worker
                    if "npm_cache" in partial:
                        self._npm_cache.update(partial["npm_cache"])
                    all_partial.append(partial)

            results = _merge_js_results(self.url, js, all_partial)
            results["_npm_cache"] = self._npm_cache  # carry back to JSMinerTab
            self.finished.emit(self.url, results)

        except Exception as exc:
            logger.exception(f"JSAnalysisWorker error for {self.url}")
            self.error.emit(self.url, str(exc))

    def _load_content(self) -> str:
        if self._js_content:
            return self._js_content
        if self.response_file and os.path.exists(self.response_file):
            try:
                with open(self.response_file, 'r', encoding='utf-8', errors='replace') as f:
                    raw = f.read()
                # Strip HTTP response headers if present
                if '\n\n' in raw:
                    raw = raw.split('\n\n', 1)[1]
                return raw
            except Exception as e:
                logger.error(f"Failed to read {self.response_file}: {e}")
        return ""

    def _run_all_engines(self, js: str) -> dict:
        """Run every detection engine and return structured results."""
        results = {
            "url":       self.url,
            "size":      len(js),
            "analysed":  datetime.now().isoformat(),
            "js_content": js[:500_000],   # cap stored content
            "categories": defaultdict(list),
            "summary": {
                "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
                "total": 0
            }
        }
        cats = results["categories"]

        if JavaScriptAnalyzer is None:
            results["error"] = "JavaScriptAnalyzer not available"
            return results

        # 1. Secrets & Keys — with Shannon entropy filtering
        for item in JavaScriptAnalyzer.extract_cloud_infrastructure(js):
            sev = "CRITICAL" if item["type"] in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY") else "HIGH"
            value = item["value"]
            entropy = _shannon_entropy(value)
            if item["type"] in ("AWS_ACCESS_KEY", "GOOGLE_API_KEY", "FIREBASE_DB",
                                "FIREBASE_APP", "S3_BUCKET", "S3_BUCKET_URI"):
                # entropy gate: skip obvious placeholders / low-entropy strings
                if not _entropy_ok(value, item["type"]):
                    continue
                cats["🔑 Secrets & Keys"].append({
                    "sev": sev, "title": item["type"],
                    "value": value, "context": item["context"],
                    "note": f"Entropy: {entropy:.2f} — verify credential is active"
                })
            else:
                cats["☁️ Cloud Infrastructure"].append({
                    "sev": "HIGH", "title": item["type"],
                    "value": value, "context": item["context"]
                })

        # Hardcoded secrets via SecurityAnalyzer — entropy filtered
        try:
            from analysis_tab import SecurityAnalyzer
            for s in SecurityAnalyzer._detect_javascript_secrets(js):
                value = s.get("value", "")[:120]
                stype = s.get("type", "GENERIC_SECRET")
                entropy = _shannon_entropy(value)
                if not _entropy_ok(value, stype):
                    continue
                cats["🔑 Secrets & Keys"].append({
                    "sev": "CRITICAL",
                    "title": stype,
                    "value": value,
                    "context": s.get("context", "")[:200],
                    "note": f"Entropy: {entropy:.2f} — Variable: {s.get('var_name','?')}"
                })
        except Exception:
            pass

        # 2. Endpoints & Paths
        for ep in JavaScriptAnalyzer.extract_endpoints(js):
            cats["🗺️ Endpoints & Paths"].append({
                "sev": "HIGH", "title": ep["value"],
                "value": ep["value"], "context": ep["context"],
                "note": "Probe this endpoint: auth bypass, IDOR, hidden functionality"
            })

        # 3. Hosts & Subdomains
        for h in JavaScriptAnalyzer.extract_subdomains_and_hosts(js):
            cats["🌐 Hosts & Subdomains"].append({
                "sev": h["severity"], "title": h["type"],
                "value": h["value"], "context": h["context"],
                "note": f"Host: {h['host']}"
            })

        # 4. DOM XSS Sinks
        try:
            from analysis_tab import SecurityAnalyzer
            for sink in SecurityAnalyzer._detect_dom_xss_sinks(js):
                cats["💥 DOM XSS Sinks"].append({
                    "sev": sink["severity"],
                    "title": sink["sink"],
                    "value": sink["context"][:120],
                    "context": sink["context"],
                    "note": f"Type: {sink['type']} — trace user input to this sink"
                })
        except Exception:
            pass

        # 5. Taint Flows (source → sink)
        flows = JavaScriptAnalyzer.detect_critical_flow(js)
        for flow_key, tags in flows.items():
            sev = "CRITICAL" if "CONFIRMED" in tags else "HIGH"
            chain = next((t for t in tags if t.startswith("CHAIN:")), "")
            source = next((t for t in tags if t.startswith("SOURCE:")), "")
            cats["🌊 Taint Flows"].append({
                "sev": sev, "title": flow_key,
                "value": chain.replace("CHAIN:", ""),
                "context": source.replace("SOURCE:", ""),
                "note": "Confirmed taint flow — high confidence XSS/RCE/redirect"
                        if sev == "CRITICAL" else "Possible taint flow — verify manually"
            })

        # 6. Open Redirects
        for rd in JavaScriptAnalyzer.detect_open_redirects(js):
            cats["🔀 Open Redirects"].append({
                "sev": rd["severity"], "title": rd["sink"],
                "value": rd["value"], "context": rd["context"],
                "note": "User-controlled redirect — test with external URL"
                        if rd["user_input"] else "Variable redirect — trace origin"
            })

        # 7. WebSocket & postMessage
        for wf in JavaScriptAnalyzer.detect_websocket_issues(js):
            cats["📨 postMessage / WS"].append({
                "sev": wf["severity"], "title": wf["type"],
                "value": wf.get("value", ""),
                "context": wf["context"], "note": wf["note"]
            })

        # 8. CORS
        for ci in JavaScriptAnalyzer.detect_cors_issues(js):
            cats["🔗 CORS Issues"].append({
                "sev": ci["severity"], "title": ci["type"],
                "value": ci["context"], "context": ci["context"],
                "note": ci["note"]
            })

        # 9. GraphQL
        for gf in JavaScriptAnalyzer.detect_graphql(js):
            cats["🧬 GraphQL"].append({
                "sev": gf["severity"], "title": gf["type"],
                "value": gf.get("value", ""),
                "context": gf["context"],
                "note": gf.get("note", "")
            })

        # 10. Token Storage
        for tf in JavaScriptAnalyzer.detect_token_storage(js):
            cats["🗄️ Token Storage"].append({
                "sev": tf["severity"], "title": tf["type"],
                "value": tf.get("key", tf.get("value", ""))[:80],
                "context": tf["context"], "note": tf["note"]
            })

        # 11. Source Maps — passive detection
        for sm in JavaScriptAnalyzer.detect_source_maps(js, self.url):
            cats["🗃️ Source Maps"].append({
                "sev": sm["severity"], "title": sm["type"],
                "value": sm["value"], "context": sm["context"],
                "note": sm["note"]
            })

        # 11b. Active .map file fetching — try to retrieve and inspect content
        self.progress.emit(self.url, "🗺️ Probing .map files…")
        map_candidates = _candidate_map_urls(self.url, js)
        for map_url in map_candidates:
            map_content = _fetch_map_file(map_url)
            if not map_content:
                continue
            # Parse the sourcemap JSON to get original source file list
            try:
                sm_data = json.loads(map_content)
                sources = sm_data.get("sources", [])
                sources_count = len(sources)
                # Sample of interesting-looking source paths
                interesting = [s for s in sources if any(
                    kw in s.lower() for kw in
                    ("secret","config","auth","token","api","key","admin","internal",
                     "password","credential","private","env")
                )]
                note_parts = [f"{sources_count} source files recovered"]
                if interesting:
                    note_parts.append(f"⚠️ Sensitive paths: {', '.join(interesting[:5])}")
                cats["🗺️ Source Map Files"].append({
                    "sev": "CRITICAL" if interesting else "HIGH",
                    "title": "SOURCE_MAP_FETCHED",
                    "value": map_url,
                    "context": f"Sources: {', '.join(sources[:10])}{'…' if sources_count > 10 else ''}",
                    "note": " | ".join(note_parts)
                })
            except (json.JSONDecodeError, KeyError):
                # Not valid JSON sourcemap but file exists — still flag it
                cats["🗺️ Source Map Files"].append({
                    "sev": "HIGH",
                    "title": "SOURCE_MAP_ACCESSIBLE",
                    "value": map_url,
                    "context": map_content[:200],
                    "note": "Map file is accessible (non-standard format)"
                })
            # Only process first fetchable map per file to avoid slow scans
            break

        # 12. Prototype Pollution
        proto = re.findall(r'(__proto__|constructor\[.*?\]|\.prototype\.\w+)', js)
        for p in set(proto):
            cats["🧩 Prototype Pollution"].append({
                "sev": "HIGH", "title": "PROTOTYPE_POLLUTION",
                "value": p[:100], "context": p[:200],
                "note": "Test for prototype pollution via controllable keys"
            })

        # 13. Frameworks
        if FrameworkDetector:
            try:
                fws = FrameworkDetector.detect_javascript_frameworks("", js)
                for fw_name, evidence in fws.items():
                    cats["📦 Frameworks & Libraries"].append({
                        "sev": "INFO", "title": fw_name,
                        "value": fw_name,
                        "context": " | ".join(evidence[:4]),
                        "note": "Check for framework-specific vulnerabilities"
                    })
            except Exception:
                pass

        # 14. Dependency Confusion — extract NPM packages and verify against registry
        self.progress.emit(self.url, "📦 Checking dependencies…")
        packages = _extract_npm_packages(js)
        checked = 0
        for pkg in packages[:40]:   # cap at 40 per file to keep scan fast
            exists = _check_npm_exists(pkg)
            checked += 1
            is_scoped = pkg.startswith("@")
            if exists is False:
                # CRITICAL — package name is available on NPM, supply chain attack possible
                cats["📦 Dependency Confusion"].append({
                    "sev": "CRITICAL",
                    "title": "DEP_CONFUSION_MISSING",
                    "value": pkg,
                    "context": f"Package '{pkg}' not found on NPM registry",
                    "note": f"{'Scoped org' if is_scoped else 'Package'} '{pkg}' is not on NPM — "
                            f"register it before an attacker does (supply chain risk)"
                })
            else:
                # INFO — package found, just informational
                cats["📦 Dependency Confusion"].append({
                    "sev": "INFO",
                    "title": "DEP_FOUND",
                    "value": pkg,
                    "context": f"Package '{pkg}' found on NPM registry",
                    "note": "Verify this is the intended package version"
                })

        # Compute summary
        for cat_items in cats.values():
            for item in cat_items:
                sev = item.get("sev", "INFO").upper()
                results["summary"][sev.lower()] = results["summary"].get(sev.lower(), 0) + 1
                results["summary"]["total"] += 1

        return results


# ─────────────────────────────────────────────────────────────────────────────
# Main JS Miner Tab
# ─────────────────────────────────────────────────────────────────────────────
class JSMinerTab(QWidget):
    """Standalone JS Miner Tab widget."""

    def __init__(self, parent_gui=None):
        super().__init__()
        self.parent_gui    = parent_gui
        self._queue        = {}          # url → {"state", "finding", "results"}
        self._seen_urls    = set()
        self._workers      = {}          # url → JSAnalysisWorker
        self._mutex        = QMutex()
        self._live         = True
        self._selected_url = None
        self._project_dir  = None       # set by set_project_dir()
        self._npm_cache    = {}          # persistent npm registry cache across all analyses
        self.init_ui()

    # ─────────────────────────────────────────────────────────────────────
    # UI BUILD
    # ─────────────────────────────────────────────────────────────────────
    def init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Toolbar
        root.addWidget(self._build_toolbar())

        # Main splitter: left queue | right detail
        main_split = QSplitter(Qt.Horizontal)

        main_split.addWidget(self._build_left_panel())
        main_split.addWidget(self._build_right_panel())
        main_split.setSizes([340, 760])

        root.addWidget(main_split)
        self.setStyleSheet(f"QWidget {{ background-color: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}")

    # ── Toolbar ───────────────────────────────────────────────────────────
    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(48)
        bar.setStyleSheet(f"background-color:{COLOR_ELEVATED_BG}; border-bottom:1px solid {COLOR_BORDER};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 6, 12, 6)
        lay.setSpacing(10)

        # Title
        title = QLabel("⛏️  JS Miner")
        title.setStyleSheet(f"font-size:14px; font-weight:bold; color:{COLOR_TEXT_BRIGHT};")
        lay.addWidget(title)

        sep = self._vsep(); lay.addWidget(sep)

        # Live toggle — ON by default
        self.live_btn = QPushButton("🟢  Live: ON")
        self.live_btn.setCheckable(True)
        self.live_btn.setChecked(True)
        self.live_btn.setFixedWidth(120)
        self.live_btn.clicked.connect(self._toggle_live)
        self.live_btn.setStyleSheet(self._btn_style(COLOR_SUCCESS))
        lay.addWidget(self.live_btn)

        # Manual URL add
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Paste .js URL or drop a finding…")
        self.url_input.setStyleSheet(f"""
            QLineEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:4px 8px;
            }}
        """)
        self.url_input.returnPressed.connect(self._add_manual_url)
        lay.addWidget(self.url_input, 1)

        add_btn = QPushButton("➕ Add")
        add_btn.clicked.connect(self._add_manual_url)
        add_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        lay.addWidget(add_btn)

        sep2 = self._vsep(); lay.addWidget(sep2)

        scan_all_btn = QPushButton("🔬 Analyse All")
        scan_all_btn.clicked.connect(self._analyse_all_pending)
        scan_all_btn.setStyleSheet(self._btn_style(COLOR_SUCCESS))
        lay.addWidget(scan_all_btn)

        clear_btn = QPushButton("🗑️ Clear")
        clear_btn.clicked.connect(self._clear_queue)
        clear_btn.setStyleSheet(self._btn_style(COLOR_CARD_BG))
        lay.addWidget(clear_btn)

        export_btn = QPushButton("📤 Export")
        export_btn.clicked.connect(self._export_all)
        export_btn.setStyleSheet(self._btn_style(COLOR_CARD_BG))
        lay.addWidget(export_btn)

        lay.addStretch()

        # Stats bar
        self.stats_label = QLabel("0 files queued")
        self.stats_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        lay.addWidget(self.stats_label)

        return bar

    # ── Left panel: queue table ───────────────────────────────────────────
    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(8, 8, 4, 8)
        lay.setSpacing(6)

        hdr = QLabel("📋  JS File Queue")
        hdr.setStyleSheet(f"font-weight:bold; color:{COLOR_TEXT_BRIGHT}; font-size:12px;")
        lay.addWidget(hdr)

        # Search box
        search = QLineEdit()
        search.setPlaceholderText("🔍 Filter queue…")
        search.textChanged.connect(self._filter_queue)
        search.setStyleSheet(f"""
            QLineEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:3px 7px; font-size:11px;
            }}
        """)
        lay.addWidget(search)

        # Queue table
        self.queue_table = QTableWidget()
        self.queue_table.setColumnCount(4)
        self.queue_table.setHorizontalHeaderLabels(["", "File", "Findings", "Status"])
        self.queue_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.queue_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.queue_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.queue_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.queue_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.queue_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.queue_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.queue_table.customContextMenuRequested.connect(self._queue_context_menu)
        self.queue_table.itemSelectionChanged.connect(self._on_queue_select)
        self.queue_table.setStyleSheet(self._table_style())
        lay.addWidget(self.queue_table)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{ background:{COLOR_CARD_BG}; border:none; border-radius:2px; }}
            QProgressBar::chunk {{ background:{COLOR_ACCENT}; border-radius:2px; }}
        """)
        lay.addWidget(self.progress_bar)

        # Mini summary
        self.queue_summary = QLabel("")
        self.queue_summary.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:10px;")
        lay.addWidget(self.queue_summary)

        return panel

    # ── Right panel: findings + viewer ────────────────────────────────────
    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(4, 8, 8, 8)
        lay.setSpacing(0)

        # File header bar
        self.file_header = QLabel("← Select a JS file from the queue")
        self.file_header.setStyleSheet(f"""
            QLabel {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                font-size:12px; font-weight:bold;
                padding:8px 12px;
                border:1px solid {COLOR_BORDER}; border-radius:6px;
                margin-bottom:6px;
            }}
        """)
        lay.addWidget(self.file_header)

        # Summary badges row
        self.badge_bar = QWidget()
        bb_lay = QHBoxLayout(self.badge_bar)
        bb_lay.setContentsMargins(0, 0, 0, 6)
        bb_lay.setSpacing(8)
        self._badges = {}
        for sev, color in [("CRITICAL", COLOR_CRITICAL), ("HIGH", COLOR_HIGH),
                            ("MEDIUM", COLOR_MEDIUM), ("LOW", COLOR_INFO), ("INFO", COLOR_TEXT_MUTED)]:
            lbl = QLabel(f"{SEV_ICON[sev]} {sev}: 0")
            lbl.setStyleSheet(f"color:{color}; font-size:11px; font-weight:bold;")
            self._badges[sev] = lbl
            bb_lay.addWidget(lbl)
        bb_lay.addStretch()
        self.size_label = QLabel("")
        self.size_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:10px;")
        bb_lay.addWidget(self.size_label)
        lay.addWidget(self.badge_bar)

        # Vertical splitter: findings tree top | JS viewer bottom
        v_split = QSplitter(Qt.Vertical)

        # Findings area (horizontal split: tree | detail)
        findings_widget = QWidget()
        f_lay = QVBoxLayout(findings_widget)
        f_lay.setContentsMargins(0, 0, 0, 0)
        f_lay.setSpacing(4)

        # Category filter row — compact, fixed height
        cat_filter = QWidget()
        cat_filter.setFixedHeight(28)
        cf_lay = QHBoxLayout(cat_filter)
        cf_lay.setContentsMargins(0, 0, 0, 0)
        cf_lay.setSpacing(4)
        filter_lbl = QLabel("Filter:")
        filter_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        cf_lay.addWidget(filter_lbl)
        self.sev_filter = QLineEdit()
        self.sev_filter.setPlaceholderText("Type to filter findings…")
        self.sev_filter.setFixedHeight(22)
        self.sev_filter.textChanged.connect(self._filter_findings_tree)
        self.sev_filter.setStyleSheet(f"""
            QLineEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px; padding:1px 6px; font-size:11px;
            }}
        """)
        cf_lay.addWidget(self.sev_filter, 1)

        for label, slot in [("⤢", lambda: self.findings_tree.expandAll()),
                             ("⤡", lambda: self.findings_tree.collapseAll()),
                             ("📋", self._copy_all_findings)]:
            btn = QPushButton(label)
            btn.setFixedSize(22, 22)
            btn.clicked.connect(slot)
            btn.setStyleSheet(self._btn_style(COLOR_CARD_BG, small=True))
            cf_lay.addWidget(btn)

        f_lay.addWidget(cat_filter)

        # Findings tree + detail splitter
        h_split = QSplitter(Qt.Horizontal)

        self.findings_tree = QTreeWidget()
        self.findings_tree.setHeaderHidden(True)
        self.findings_tree.setStyleSheet(self._tree_style())
        self.findings_tree.itemClicked.connect(self._on_finding_clicked)
        self.findings_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.findings_tree.customContextMenuRequested.connect(self._findings_context_menu)
        h_split.addWidget(self.findings_tree)

        # Finding detail panel
        detail_panel = QWidget()
        dp_lay = QVBoxLayout(detail_panel)
        dp_lay.setContentsMargins(0, 0, 0, 0)

        detail_tabs = QTabWidget()
        detail_tabs.setStyleSheet(self._tab_style())

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setStyleSheet(f"QTextEdit {{ background:{COLOR_DARK_BG}; border:none; padding:8px; font-size:12px; }}")
        detail_tabs.addTab(self.detail_text, "📄 Detail")

        self.note_text = QTextEdit()
        self.note_text.setReadOnly(True)
        self.note_text.setStyleSheet(f"QTextEdit {{ background:{COLOR_DARK_BG}; border:none; padding:8px; font-size:12px; }}")
        detail_tabs.addTab(self.note_text, "💡 Hints")

        dp_lay.addWidget(detail_tabs)
        h_split.addWidget(detail_panel)
        h_split.setSizes([420, 340])

        f_lay.addWidget(h_split)
        v_split.addWidget(findings_widget)

        # Raw JS viewer
        viewer_widget = QWidget()
        vw_lay = QVBoxLayout(viewer_widget)
        vw_lay.setContentsMargins(0, 2, 0, 0)
        vw_lay.setSpacing(2)

        vw_hdr = QWidget()
        vw_hdr.setFixedHeight(24)
        vw_hdr_lay = QHBoxLayout(vw_hdr)
        vw_hdr_lay.setContentsMargins(0, 0, 0, 0)
        vw_hdr_lay.setSpacing(6)
        src_lbl = QLabel("🔎 Raw JS Source")
        src_lbl.setStyleSheet(f"font-size:11px; color:{COLOR_TEXT_MUTED};")
        vw_hdr_lay.addWidget(src_lbl)
        vw_hdr_lay.addStretch()
        self.js_search = QLineEdit()
        self.js_search.setPlaceholderText("Search in JS…")
        self.js_search.setFixedWidth(180)
        self.js_search.setFixedHeight(20)
        self.js_search.setStyleSheet(f"""
            QLineEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:3px; padding:1px 5px; font-size:11px;
            }}
        """)
        self.js_search.returnPressed.connect(self._search_in_js)
        vw_hdr_lay.addWidget(self.js_search)
        self.js_match_label = QLabel("")
        self.js_match_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:10px;")
        vw_hdr_lay.addWidget(self.js_match_label)
        vw_lay.addWidget(vw_hdr)

        self.js_viewer = QTextEdit()
        self.js_viewer.setReadOnly(True)
        self.js_viewer.setFont(QFont("Consolas, Courier New", 10))
        self.js_viewer.setStyleSheet(f"QTextEdit {{ background:{COLOR_DARK_BG}; border:1px solid {COLOR_BORDER}; padding:6px; }}")
        self._js_highlighter = JSSyntaxHighlighter(self.js_viewer.document())
        vw_lay.addWidget(self.js_viewer)

        v_split.addWidget(viewer_widget)
        v_split.setSizes([620, 160])

        lay.addWidget(v_split, 1)
        return panel

    # ─────────────────────────────────────────────────────────────────────
    # LIVE MODE
    # ─────────────────────────────────────────────────────────────────────
    def _toggle_live(self, checked: bool):
        self._live = checked
        if checked:
            self.live_btn.setText("🟢  Live: ON")
            self.live_btn.setStyleSheet(self._btn_style(COLOR_SUCCESS))
        else:
            self.live_btn.setText("🔴  Live: OFF")
            self.live_btn.setStyleSheet(self._btn_style(COLOR_CARD_BG))

    # ─────────────────────────────────────────────────────────────────────
    # PERSISTENCE
    # ─────────────────────────────────────────────────────────────────────
    def set_project_dir(self, project_dir: str):
        """Called by hunt_gui after project is loaded. Loads saved queue."""
        self._project_dir = project_dir
        self._load_queue()

    def _queue_file(self) -> Optional[str]:
        if self._project_dir:
            return os.path.join(self._project_dir, "js_miner_queue.json")
        return None

    def _save_queue(self):
        """Persist queue + results to project dir. Called after every state change."""
        path = self._queue_file()
        if not path:
            return
        try:
            serialisable = {}
            for url, entry in self._queue.items():
                results = entry.get("results")
                save_entry = {
                    "state":   entry.get("state", "queued"),
                    "added":   entry.get("added", ""),
                    "finding": {
                        k: v for k, v in (entry.get("finding") or {}).items()
                        if k in ("url", "method", "status", "response_file",
                                 "request_file", "host")
                    },
                }
                if results:
                    # Store everything except raw JS content (can be MB)
                    r = {k: v for k, v in results.items() if k != "js_content"}
                    # Convert defaultdicts / sets for JSON
                    r["categories"] = {
                        cat: items
                        for cat, items in results.get("categories", {}).items()
                    }
                    save_entry["results"] = r
                serialisable[url] = save_entry

            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(serialisable, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"JSMiner _save_queue failed: {e}")

    def _load_queue(self):
        """Load persisted queue from project dir on startup."""
        path = self._queue_file()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            loaded = 0
            for url, entry in data.items():
                key = self._js_dedup_key(url)
                if key in self._seen_urls:
                    continue
                self._seen_urls.add(key)

                state   = entry.get("state", "queued")
                results = entry.get("results")

                # Restore summary counts if results present
                if results and "summary" not in results:
                    results["summary"] = {
                        "critical": 0, "high": 0, "medium": 0,
                        "low": 0, "info": 0, "total": 0
                    }

                self._queue[url] = {
                    "state":   state,
                    "finding": entry.get("finding"),
                    "results": results,
                    "added":   entry.get("added", ""),
                }
                loaded += 1

            if loaded:
                self._refresh_queue_table()
                self._update_stats()
                logger.info(f"JSMiner: loaded {loaded} entries from {path}")
        except Exception as e:
            logger.error(f"JSMiner _load_queue failed: {e}")

    def feed_finding(self, finding: Dict[str, Any]):
        """Called by HTTP History tab for every new finding when live is ON."""
        if not self._live:
            return
        url = finding.get("url", "")
        # Accept by URL extension OR by response content-type
        if not self._is_js_url(url) and not self._is_js_content_type(finding):
            return
        # Only accept successful responses — skip redirects, errors, not-found
        status = finding.get("status", 0)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = 0
        if status != 200:
            return
        self._enqueue(url, finding=finding, auto_analyse=True)

    def send_finding(self, finding: Dict[str, Any]):
        """Called directly from HTTP History right-click → Send to JS Miner.
        Always enqueues regardless of live mode, then switches to this tab.
        """
        url = finding.get("url", "")
        if not url:
            return
        self._enqueue(url, finding=finding, auto_analyse=True)
        # Switch focus to this tab
        if self.parent_gui and hasattr(self.parent_gui, "tab_widget"):
            self.parent_gui.tab_widget.setCurrentWidget(self)

    def _is_js_url(self, url: str) -> bool:
        if not url:
            return False
        path = urlparse(url).path.lower().rstrip('/')
        return path.endswith(('.js', '.mjs', '.jsx', '.ts', '.tsx', '.json'))

    def _is_js_content_type(self, finding: dict) -> bool:
        """Return True when the response content-type indicates JavaScript/JSX
        even if the URL extension doesn't match."""
        ct = ""
        # content_type may be stored directly or inside response_headers
        for key in ("content_type", "Content-Type", "content-type"):
            ct = finding.get(key, "")
            if ct:
                break
        if not ct:
            headers = finding.get("response_headers") or finding.get("headers") or {}
            if isinstance(headers, dict):
                ct = headers.get("Content-Type") or headers.get("content-type", "")
        ct = ct.lower().split(";")[0].strip()
        return ct in (
            "application/javascript",
            "text/javascript",
            "application/x-javascript",
            "text/jsx",
            "application/jsx",
            "text/typescript",
            "application/typescript",
        )

    @staticmethod
    def _js_dedup_key(url: str) -> str:
        """Normalised dedup key: scheme + host (lower) + path (lower, no trailing slash)
        + query string (kept exactly as-is, order matters).
        Two URLs are the same JS file only when ALL of these match.
        Examples treated as SAME:
            https://example.com/app.js   ==  https://example.com/APP.JS
        Examples treated as DIFFERENT:
            https://example.com/app.js?v=1  !=  https://example.com/app.js?v=2
        """
        try:
            p = urlparse(url)
            path = p.path.rstrip('/').lower()
            host = p.netloc.lower()
            query = p.query   # kept verbatim — ?v=1 != ?v=2
            if query:
                return f"{p.scheme}://{host}{path}?{query}"
            return f"{p.scheme}://{host}{path}"
        except Exception:
            return url.lower()

    # ─────────────────────────────────────────────────────────────────────
    # QUEUE MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────
    def _add_manual_url(self):
        url = self.url_input.text().strip()
        if not url:
            return
        self.url_input.clear()
        self._enqueue(url, auto_analyse=True)

    def _enqueue(self, url: str, finding: dict = None, auto_analyse: bool = False):
        key = self._js_dedup_key(url)
        with QMutexLocker(self._mutex):
            if key in self._seen_urls:
                return
            self._seen_urls.add(key)
            self._queue[url] = {
                "state": "queued",
                "finding": finding,
                "results": None,
                "added": datetime.now().strftime("%H:%M:%S")
            }

        self._refresh_queue_table()
        self._update_stats()
        self._save_queue()

        if auto_analyse:
            QTimer.singleShot(50, lambda u=url: self._start_analysis(u))

    def _start_analysis(self, url: str):
        entry = self._queue.get(url)
        if not entry or url in self._workers:
            return

        finding = entry.get("finding") or {}
        response_file = finding.get("response_file", "")

        entry["state"] = "analysing"
        self._refresh_queue_row(url)

        worker = JSAnalysisWorker(url, response_file=response_file, npm_cache=self._npm_cache)
        worker.finished.connect(self._on_analysis_done)
        worker.progress.connect(self._on_analysis_progress)
        worker.error.connect(self._on_analysis_error)
        self._workers[url] = worker
        worker.start()

    def _on_analysis_done(self, url: str, results: dict):
        # Persist any new npm registry results so future analyses skip those checks
        npm_cache_update = results.pop("_npm_cache", None)
        if npm_cache_update:
            self._npm_cache.update(npm_cache_update)

        entry = self._queue.get(url)
        if entry:
            entry["state"]   = "done"
            entry["results"] = results
        self._workers.pop(url, None)
        self._refresh_queue_row(url)
        self._update_stats()
        self._save_queue()
        # Auto-select if it's the first or only done file
        if self._selected_url == url:
            self._display_results(url)

    def _on_analysis_progress(self, url: str, msg: str):
        entry = self._queue.get(url)
        if entry:
            entry["_status_msg"] = msg
        self._refresh_queue_row(url)

    def _on_analysis_error(self, url: str, error: str):
        entry = self._queue.get(url)
        if entry:
            entry["state"] = "error"
            entry["_error"] = error
        self._workers.pop(url, None)
        self._refresh_queue_row(url)
        self._save_queue()

    def _analyse_all_pending(self):
        for url, entry in list(self._queue.items()):
            if entry["state"] in ("queued", "error"):
                self._start_analysis(url)

    def _clear_queue(self):
        # Stop running workers
        for w in list(self._workers.values()):
            w.quit()
        self._workers.clear()
        self._queue.clear()
        self._seen_urls.clear()
        self._selected_url = None
        self.queue_table.setRowCount(0)
        self._clear_right_panel()
        self._update_stats()
        self._save_queue()

    # ─────────────────────────────────────────────────────────────────────
    # QUEUE TABLE RENDERING
    # ─────────────────────────────────────────────────────────────────────
    def _refresh_queue_table(self):
        """Full rebuild of queue table."""
        self.queue_table.setRowCount(0)
        for url, entry in self._queue.items():
            self._insert_queue_row(url, entry)

    def _insert_queue_row(self, url: str, entry: dict):
        row = self.queue_table.rowCount()
        self.queue_table.insertRow(row)
        self._populate_queue_row(row, url, entry)

    def _refresh_queue_row(self, url: str):
        """Update just the row for this url."""
        for row in range(self.queue_table.rowCount()):
            item = self.queue_table.item(row, 1)
            if item and item.data(Qt.UserRole) == url:
                entry = self._queue.get(url, {})
                self._populate_queue_row(row, url, entry)
                return
        # Not found — do full refresh
        self._refresh_queue_table()

    def _populate_queue_row(self, row: int, url: str, entry: dict):
        state   = entry.get("state", "queued")
        results = entry.get("results")

        # Col 0: severity dot
        total = results["summary"]["total"] if results else 0
        crit  = results["summary"].get("critical", 0) if results else 0
        high  = results["summary"].get("high", 0) if results else 0
        dot   = "🔴" if crit else ("🟠" if high else ("🟢" if total else "⚪"))
        dot_item = QTableWidgetItem(dot if state == "done" else ("⏳" if state == "analysing" else "·"))
        dot_item.setTextAlignment(Qt.AlignCenter)
        self.queue_table.setItem(row, 0, dot_item)

        # Col 1: filename
        fname = urlparse(url).path.split('/')[-1] or url
        fname_item = QTableWidgetItem(fname)
        fname_item.setData(Qt.UserRole, url)
        fname_item.setToolTip(url)
        if state == "done":
            fname_item.setForeground(QColor(COLOR_TEXT_BRIGHT))
        elif state == "error":
            fname_item.setForeground(QColor(COLOR_CRITICAL))
        else:
            fname_item.setForeground(QColor(COLOR_TEXT_MUTED))
        self.queue_table.setItem(row, 1, fname_item)

        # Col 2: findings count
        count_str = str(total) if state == "done" else ""
        count_item = QTableWidgetItem(count_str)
        count_item.setTextAlignment(Qt.AlignCenter)
        if crit:
            count_item.setForeground(QColor(COLOR_CRITICAL))
        elif high:
            count_item.setForeground(QColor(COLOR_HIGH))
        elif total:
            count_item.setForeground(QColor(COLOR_SUCCESS))
        self.queue_table.setItem(row, 2, count_item)

        # Col 3: status
        state_map = {
            "queued":    ("⏸ Queued",    COLOR_TEXT_MUTED),
            "analysing": ("⏳ Scanning…", COLOR_ACCENT),
            "done":      ("✅ Done",      COLOR_SUCCESS),
            "error":     ("❌ Error",     COLOR_CRITICAL),
        }
        label, color = state_map.get(state, ("?", COLOR_TEXT_MUTED))
        if state == "analysing":
            label = entry.get("_status_msg", label)
        st_item = QTableWidgetItem(label)
        st_item.setForeground(QColor(color))
        self.queue_table.setItem(row, 3, st_item)

    def _filter_queue(self, text: str):
        text = text.lower()
        for row in range(self.queue_table.rowCount()):
            item = self.queue_table.item(row, 1)
            hidden = text != "" and item and text not in item.toolTip().lower()
            self.queue_table.setRowHidden(row, hidden)

    # ─────────────────────────────────────────────────────────────────────
    # SELECTION & DISPLAY
    # ─────────────────────────────────────────────────────────────────────
    def _on_queue_select(self):
        rows = self.queue_table.selectedItems()
        if not rows:
            return
        row   = rows[0].row()
        item  = self.queue_table.item(row, 1)
        if not item:
            return
        url = item.data(Qt.UserRole)
        if not url:
            return
        self._selected_url = url
        entry = self._queue.get(url, {})
        if entry.get("state") == "done" and entry.get("results"):
            self._display_results(url)
        elif entry.get("state") == "queued":
            self._start_analysis(url)
            self._clear_right_panel()
        elif entry.get("state") == "analysing":
            self._clear_right_panel()
            self.file_header.setText(f"⏳ Analysing: {url}")

    def _display_results(self, url: str):
        results = self._queue.get(url, {}).get("results")
        if not results:
            return

        # Header
        fname = urlparse(url).path.split('/')[-1] or url
        total = results["summary"]["total"]
        self.file_header.setText(f"⛏️  {fname}   —   {total} findings   |   {url}")

        # Badges
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            cnt = results["summary"].get(sev.lower(), 0)
            self._badges[sev].setText(f"{SEV_ICON[sev]} {sev}: {cnt}")

        # Size
        size = results.get("size", 0)
        self.size_label.setText(f"Size: {size:,} bytes")

        # Findings tree
        self._populate_findings_tree(results)

        # JS viewer
        js = results.get("js_content", "")
        self.js_viewer.setExtraSelections([])
        self.js_match_label.setText("")
        self.js_viewer.setPlainText(js)

        # Queue summary
        self._update_queue_summary()

    def _populate_findings_tree(self, results: dict):
        self.findings_tree.clear()
        cats = results.get("categories", {})

        # Sort categories by worst severity
        def cat_sev(cat_name):
            items = cats.get(cat_name, [])
            if not items:
                return 99
            worst = min(SEV_ORDER.get(i.get("sev", "INFO").upper(), 99) for i in items)
            return worst

        sorted_cats = sorted(cats.keys(), key=cat_sev)

        for cat_name in sorted_cats:
            items = cats[cat_name]
            if not items:
                continue

            worst_sev = min(SEV_ORDER.get(i.get("sev", "INFO").upper(), 99) for i in items)
            worst_key = [k for k, v in SEV_ORDER.items() if v == worst_sev]
            worst_key = worst_key[0] if worst_key else "INFO"

            cat_item = QTreeWidgetItem([
                f"{cat_name}  ({len(items)})"
            ])
            cat_item.setForeground(0, QColor(SEV_COLOR.get(worst_key, COLOR_TEXT)))
            cat_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            cat_item.setData(0, Qt.UserRole, {"_is_category": True, "name": cat_name})

            # Sort findings by severity desc
            sorted_items = sorted(items, key=lambda x: SEV_ORDER.get(x.get("sev","INFO").upper(), 99))

            for finding in sorted_items:
                sev   = finding.get("sev", "INFO").upper()
                title = finding.get("title", "?")
                value = finding.get("value", "")

                display = f"{SEV_ICON.get(sev,'•')} {title}"
                if value and len(value) < 80:
                    display += f"  ›  {value}"

                child = QTreeWidgetItem([display])
                child.setForeground(0, QColor(SEV_COLOR.get(sev, COLOR_TEXT)))
                child.setData(0, Qt.UserRole, finding)
                child.setToolTip(0, finding.get("context", "")[:300])
                cat_item.addChild(child)

            self.findings_tree.addTopLevelItem(cat_item)

        self.findings_tree.expandAll()

    def _on_finding_clicked(self, item: QTreeWidgetItem, col: int):
        data = item.data(0, Qt.UserRole)
        if not data or data.get("_is_category"):
            return

        sev     = data.get("sev", "INFO").upper()
        title   = data.get("title", "")
        value   = data.get("value", "")
        context = data.get("context", "")
        note    = data.get("note", "")

        sev_color = SEV_COLOR.get(sev, COLOR_TEXT)

        detail_html = f"""
<div style='font-family:Consolas,monospace; font-size:12px; color:{COLOR_TEXT};'>
<p style='margin:0 0 6px 0;'>
  <span style='color:{sev_color}; font-weight:bold; font-size:14px;'>
    {SEV_ICON.get(sev,'')} {sev}
  </span>
  &nbsp;—&nbsp;
  <span style='color:{COLOR_TEXT_BRIGHT}; font-weight:bold;'>{title}</span>
</p>
"""
        if value:
            detail_html += f"""
<p style='margin:6px 0 2px 0; color:{COLOR_TEXT_MUTED}; font-size:11px;'>VALUE</p>
<pre style='background:{COLOR_DARK_BG}; padding:8px; border-radius:4px;
            border-left:3px solid {sev_color}; white-space:pre-wrap; word-break:break-all;
            color:{COLOR_TEXT_BRIGHT};'>{self._esc(value)}</pre>
"""
        if context:
            detail_html += f"""
<p style='margin:6px 0 2px 0; color:{COLOR_TEXT_MUTED}; font-size:11px;'>CONTEXT</p>
<pre style='background:{COLOR_DARK_BG}; padding:8px; border-radius:4px;
            border-left:3px solid {COLOR_BORDER}; white-space:pre-wrap; word-break:break-all;
            color:{COLOR_TEXT};'>{self._esc(context)}</pre>
"""
        detail_html += "</div>"
        self.detail_text.setHtml(detail_html)

        hints_html = f"""
<div style='font-family:Segoe UI,sans-serif; font-size:12px; color:{COLOR_TEXT};'>
<h3 style='color:{sev_color}; margin:0 0 8px 0;'>💡 Testing Hints</h3>
"""
        if note:
            hints_html += f"<p style='margin:4px 0;'>{self._esc(note)}</p>"

        # Generic hints per category
        generic = self._generic_hints(title, sev)
        if generic:
            hints_html += "<ul style='margin:8px 0 0 0; padding-left:18px;'>"
            for h in generic:
                hints_html += f"<li style='margin:4px 0;'>{h}</li>"
            hints_html += "</ul>"

        hints_html += "</div>"
        self.note_text.setHtml(hints_html)

        # Highlight in JS viewer
        if value or context:
            search_term = (value or context)[:60].strip()
            self._highlight_in_viewer(search_term)

    def _generic_hints(self, title: str, sev: str) -> List[str]:
        t = title.upper()
        hints_map = {
            "SECRET":    ["Verify secret is still active", "Check git history for earlier exposure",
                          "Test scope of the credential", "Report immediately if active"],
            "API_KEY":   ["Test the key in Postman/curl", "Check what APIs/scopes it grants",
                          "Look for rate limiting bypass with the key"],
            "AWS":       ["aws sts get-caller-identity to verify", "Check S3 bucket permissions",
                          "Look for IAM role privilege escalation"],
            "ENDPOINT":  ["Probe with GET/POST/PUT/DELETE", "Test for IDOR by changing IDs",
                          "Check authentication requirements", "Fuzz path parameters"],
            "DOM_XSS":   ["Trace user input to this sink", "Try: <img src=x onerror=alert(1)>",
                          "Test with encoded payloads", "Check CSP bypass opportunities"],
            "REDIRECT":  ["Test with: //evil.com", "Try URL-encoded variants",
                          "Check if victim needs to be logged in"],
            "WEBSOCKET": ["Intercept with Burp WebSocket tab",
                          "Test Cross-Site WebSocket Hijacking (CSWSH)",
                          "Check if auth token in URL or header"],
            "CORS":      ["Test with: Origin: https://evil.com",
                          "Check ACAO + ACAC header combination",
                          "Try null origin: Origin: null"],
            "GRAPHQL":   ["Run introspection: {__schema{types{name}}}",
                          "Test for batch queries / alias overloading",
                          "Check field-level authorization"],
            "TOKEN":     ["XSS in any input → steal from localStorage",
                          "Check token expiry and refresh logic",
                          "Look for token in URL parameters (logs)"],
            "PROTO":     ["Test: {\"__proto__\":{\"isAdmin\":true}}",
                          "Try in JSON body of POST requests",
                          "Look for Object.assign() / merge patterns"],
            "SOURCE_MAP": ["Download .map file to recover original source",
                           "Look for comments, todos, credentials in source",
                           "Use source-map library to deobfuscate"],
        }
        for key, hints in hints_map.items():
            if key in t:
                return hints
        if sev == "CRITICAL":
            return ["Prioritise this finding immediately",
                    "Document evidence and reproduce",
                    "Assess blast radius before reporting"]
        return []

    # ─────────────────────────────────────────────────────────────────────
    # FILTERING
    # ─────────────────────────────────────────────────────────────────────
    def _filter_findings_tree(self, text: str):
        text = text.lower()
        for i in range(self.findings_tree.topLevelItemCount()):
            cat = self.findings_tree.topLevelItem(i)
            cat_visible = False
            for j in range(cat.childCount()):
                child = cat.child(j)
                show = not text or text in child.text(0).lower() or text in (child.toolTip(0) or "").lower()
                child.setHidden(not show)
                if show:
                    cat_visible = True
            cat.setHidden(not cat_visible and bool(text))

    # ─────────────────────────────────────────────────────────────────────
    # JS VIEWER SEARCH
    # ─────────────────────────────────────────────────────────────────────
    def _search_in_js(self):
        self._highlight_in_viewer(self.js_search.text())

    def _highlight_in_viewer(self, term: str):
        # Always clear previous extra selections first
        self.js_viewer.setExtraSelections([])
        self.js_match_label.setText("")

        if not term or not term.strip():
            return

        doc        = self.js_viewer.document()
        highlight  = QTextCharFormat()
        highlight.setBackground(QColor("#7a5200"))
        highlight.setForeground(QColor("#ffffff"))

        selections = []
        cursor     = doc.find(term)
        first      = None
        while not cursor.isNull():
            sel = QTextEdit.ExtraSelection()
            sel.format   = highlight
            sel.cursor   = cursor
            selections.append(sel)
            if first is None:
                first = QTextCursor(cursor)
            cursor = doc.find(term, cursor)

        self.js_viewer.setExtraSelections(selections)
        count = len(selections)
        self.js_match_label.setText(f"{count} match{'es' if count != 1 else ''}")
        if first:
            self.js_viewer.setTextCursor(first)
            self.js_viewer.ensureCursorVisible()

    # ─────────────────────────────────────────────────────────────────────
    # CONTEXT MENUS
    # ─────────────────────────────────────────────────────────────────────
    def _queue_context_menu(self, pos):
        item = self.queue_table.itemAt(pos)
        if not item:
            return
        row = item.row()
        url_item = self.queue_table.item(row, 1)
        if not url_item:
            return
        url   = url_item.data(Qt.UserRole)
        entry = self._queue.get(url, {})
        state = entry.get("state", "queued")

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; padding:4px;
            }}
            QMenu::item {{ padding:6px 20px; border-radius:3px; }}
            QMenu::item:selected {{ background:{COLOR_ACCENT}; color:#fff; }}
            QMenu::separator {{ height:1px; background:{COLOR_BORDER}; margin:4px 0; }}
        """)

        # ── Analyse actions ───────────────────────────────────────────────
        if state in ("queued", "error"):
            a_analyse = menu.addAction("🔬 Analyse Now")
            a_analyse.triggered.connect(lambda checked=False, u=url: self._start_analysis(u))
        else:
            a_analyse = None

        # Re-analyse always available (resets results and re-fetches JS source)
        a_reanalyse = menu.addAction("🔄 Re-Analyse")
        a_reanalyse.setToolTip("Clear current results, reload JS source and re-run all detection engines")
        a_reanalyse.triggered.connect(lambda checked=False, u=url: self._reanalyse(u))

        menu.addSeparator()

        # ── Navigation ────────────────────────────────────────────────────
        a_view_history = menu.addAction("📜 View in HTTP History")
        a_view_history.setToolTip("Switch to HTTP History tab and select this request")
        a_view_history.triggered.connect(lambda checked=False, u=url: self._view_in_http_history(u))

        menu.addSeparator()

        # ── Clipboard / export ────────────────────────────────────────────
        a_copy = menu.addAction("📋 Copy URL")
        a_copy.triggered.connect(lambda checked=False, u=url: QApplication.clipboard().setText(u))

        if state == "done":
            a_export = menu.addAction("📤 Export This File")
            a_export.triggered.connect(lambda checked=False, u=url: self._export_file(u))

        menu.addSeparator()

        # ── Destructive ───────────────────────────────────────────────────
        a_remove = menu.addAction("🗑️ Remove")
        a_remove.triggered.connect(lambda checked=False, u=url: self._remove_from_queue(u))

        menu.exec_(self.queue_table.viewport().mapToGlobal(pos))

    def _reanalyse(self, url: str):
        """Clear existing results for url and start a fresh analysis.
        Re-reads JS source from the original response_file so raw content
        is restored even after a session reload.
        """
        # Stop any running worker for this url
        w = self._workers.pop(url, None)
        if w:
            w.quit()
            w.wait(500)

        entry = self._queue.get(url)
        if not entry:
            return

        # Reset state — keep finding/response_file pointer intact
        entry["state"]   = "queued"
        entry["results"] = None
        entry.pop("_error", None)
        entry.pop("_status_msg", None)

        self._refresh_queue_row(url)

        # If this file is currently displayed, clear the right panel
        if self._selected_url == url:
            self._clear_right_panel()
            self.file_header.setText(f"⏳ Re-analysing: {url}")

        # Kick off fresh analysis
        self._start_analysis(url)

    def _view_in_http_history(self, url: str):
        """Switch to HTTP History tab and auto-select the row matching url."""
        gui = self.parent_gui
        if not gui or not hasattr(gui, "tab_widget"):
            return

        # Find and switch to HTTP History tab
        tab_widget = gui.tab_widget
        for i in range(tab_widget.count()):
            tab_text = tab_widget.tabText(i)
            if "HTTP" in tab_text or "History" in tab_text:
                tab_widget.setCurrentIndex(i)
                # Delay row selection slightly to let the tab render
                QTimer.singleShot(120, lambda u=url: self._select_history_row(u))
                return

    def _select_history_row(self, url: str):
        """Find and select the row in history_table whose URL matches url."""
        gui = self.parent_gui
        if not gui or not hasattr(gui, "history_table"):
            return

        table = gui.history_table
        url_lower = url.lower().rstrip("/")

        for row in range(table.rowCount()):
            url_item = table.item(row, 3)   # column 3 = URL
            if not url_item:
                continue
            cell_url = url_item.text().lower().rstrip("/")
            # Match on full URL or just the path portion
            if cell_url == url_lower or cell_url.split("?")[0] == url_lower.split("?")[0]:
                table.clearSelection()
                table.selectRow(row)
                table.scrollTo(table.model().index(row, 0))
                return

    def _findings_context_menu(self, pos):
        item = self.findings_tree.itemAt(pos)
        if not item:
            return
        data = item.data(0, Qt.UserRole)
        menu = QMenu(self)
        a1 = menu.addAction("📋 Copy Value")
        a1.triggered.connect(lambda: QApplication.clipboard().setText(
            data.get("value", "") if data else item.text(0)))
        a2 = menu.addAction("📋 Copy Context")
        a2.triggered.connect(lambda: QApplication.clipboard().setText(
            data.get("context", "") if data else ""))
        menu.exec_(self.findings_tree.viewport().mapToGlobal(pos))

    # ─────────────────────────────────────────────────────────────────────
    # COPY / EXPORT
    # ─────────────────────────────────────────────────────────────────────
    def _copy_all_findings(self):
        if not self._selected_url:
            return
        results = self._queue.get(self._selected_url, {}).get("results")
        if not results:
            return
        lines = [f"JS Miner Results: {self._selected_url}",
                 f"Analysed: {results.get('analysed','')}",
                 f"Total findings: {results['summary']['total']}", ""]
        for cat, items in results.get("categories", {}).items():
            if not items:
                continue
            lines.append(f"\n{'='*60}")
            lines.append(f"{cat}  ({len(items)} findings)")
            lines.append('='*60)
            for itm in items:
                lines.append(f"  [{itm.get('sev','?')}] {itm.get('title','')}")
                if itm.get('value'):
                    lines.append(f"    Value: {itm['value']}")
                if itm.get('note'):
                    lines.append(f"    Note: {itm['note']}")
        QApplication.clipboard().setText('\n'.join(lines))

    def _export_file(self, url: str):
        results = self._queue.get(url, {}).get("results")
        if not results:
            return
        fname_default = urlparse(url).path.split('/')[-1].replace('.js', '_findings.json')
        path, _ = QFileDialog.getSaveFileName(self, "Export Findings", fname_default,
                                              "JSON (*.json);;All (*)")
        if path:
            export = {k: v for k, v in results.items() if k != "js_content"}
            # Convert sets to lists for JSON
            export["categories"] = {
                cat: items for cat, items in results.get("categories", {}).items()
            }
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(export, f, indent=2, default=str)

    def _export_all(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export All Findings",
                                              "js_miner_results.json",
                                              "JSON (*.json);;All (*)")
        if not path:
            return
        out = {}
        for url, entry in self._queue.items():
            if entry.get("results"):
                r = {k: v for k, v in entry["results"].items() if k != "js_content"}
                out[url] = r
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2, default=str)

    def _remove_from_queue(self, url: str):
        w = self._workers.pop(url, None)
        if w:
            w.quit()
        self._queue.pop(url, None)
        self._seen_urls.discard(self._js_dedup_key(url))
        if self._selected_url == url:
            self._selected_url = None
            self._clear_right_panel()
        self._refresh_queue_table()
        self._update_stats()
        self._save_queue()

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────
    def _clear_right_panel(self):
        self.file_header.setText("← Select a JS file from the queue")
        for lbl in self._badges.values():
            sev = lbl.text().split()[1].rstrip(':')
            lbl.setText(f"{SEV_ICON.get(sev,'•')} {sev}: 0")
        self.findings_tree.clear()
        self.detail_text.clear()
        self.note_text.clear()
        self.js_viewer.clear()
        self.size_label.setText("")

    def _update_stats(self):
        total   = len(self._queue)
        done    = sum(1 for e in self._queue.values() if e["state"] == "done")
        pending = sum(1 for e in self._queue.values() if e["state"] in ("queued", "analysing"))
        self.stats_label.setText(
            f"{total} file{'s' if total!=1 else ''} queued  ·  {done} done  ·  {pending} pending"
        )

    def _update_queue_summary(self):
        if not self._selected_url:
            return
        results = self._queue.get(self._selected_url, {}).get("results")
        if not results:
            return
        s = results["summary"]
        self.queue_summary.setText(
            f"🔴 {s.get('critical',0)}  🟠 {s.get('high',0)}  "
            f"🟡 {s.get('medium',0)}  🔵 {s.get('low',0)}  ⚪ {s.get('info',0)}"
        )

    @staticmethod
    def _esc(text: str) -> str:
        return (text.replace('&', '&amp;').replace('<', '&lt;')
                    .replace('>', '&gt;').replace('"', '&quot;'))

    @staticmethod
    def _vsep() -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"background:{COLOR_BORDER};")
        sep.setMaximumWidth(1)
        sep.setMaximumHeight(28)
        return sep

    @staticmethod
    def _btn_style(bg: str, small: bool = False) -> str:
        pad = "2px 8px" if small else "5px 14px"
        return f"""
            QPushButton {{
                background:{bg}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:{pad};
            }}
            QPushButton:hover {{ border-color:{COLOR_ACCENT}; }}
            QPushButton:checked {{ background:{COLOR_SUCCESS}; color:#000; border-color:{COLOR_SUCCESS}; }}
        """

    @staticmethod
    def _table_style() -> str:
        return f"""
            QTableWidget {{
                background:{COLOR_CARD_BG}; border:1px solid {COLOR_BORDER};
                border-radius:6px; gridline-color:{COLOR_BORDER};
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; padding:3px; font-size:11px;
            }}
            QTableWidget::item {{ padding:3px; }}
            QTableWidget::item:selected {{ background:{COLOR_ACCENT}; }}
        """

    @staticmethod
    def _tree_style() -> str:
        return f"""
            QTreeWidget {{
                background:{COLOR_CARD_BG}; border:1px solid {COLOR_BORDER}; border-radius:6px;
            }}
            QTreeWidget::item {{ padding:4px 2px; }}
            QTreeWidget::item:selected {{ background:{COLOR_ACCENT}; color:{COLOR_TEXT_BRIGHT}; }}
            QTreeWidget::item:hover {{ background:{COLOR_ELEVATED_BG}; }}
        """

    @staticmethod
    def _tab_style() -> str:
        return f"""
            QTabWidget::pane {{
                border:1px solid {COLOR_BORDER}; border-radius:4px; background:{COLOR_CARD_BG};
            }}
            QTabBar::tab {{
                background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; padding:5px 12px;
                border:1px solid {COLOR_BORDER}; border-bottom:none;
                border-top-left-radius:4px; border-top-right-radius:4px; margin-right:2px;
            }}
            QTabBar::tab:selected {{ background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT}; }}
        """