# param_miner_tab.py  ─  Param Miner  v6  (PyQt5)
# ═══════════════════════════════════════════════════════════════════════════════
#  v6 — Full rewrite
#
#  LAYOUT:
#   • Left panel  : top = URL Queue | bottom = Results tab + Terminal tab
#   • Right panel : Tool controls & options (scrollable)
#
#  KEY FEATURES:
#   • Arjun runs by default (full -c chunk control)
#   • x8 runs only when its checkbox is enabled
#   • Terminal tab shows raw cmd + output exactly as in real terminal (no wrapping)
#   • Live mode ON by default — auto-populates URLs with params from HTTP History
#   • Binary Search Bucketing, Cache Buster, Dynamic Word Harvest
# ═══════════════════════════════════════════════════════════════════════════════

import os, re, json, shutil, html, tempfile, time, statistics, random, string
import urllib.parse, urllib.request, subprocess
from datetime import datetime
from typing   import Dict, List, Optional, Set, Tuple
from queue    import Queue

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel, QPushButton,
    QLineEdit, QTextEdit, QComboBox, QCheckBox, QSpinBox, QDoubleSpinBox,
    QTabWidget, QTreeWidget, QTreeWidgetItem, QHeaderView, QMenu,
    QFileDialog, QMessageBox, QFrame, QScrollArea, QProgressBar,
    QListWidget, QListWidgetItem, QApplication, QAbstractItemView,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject
from PyQt5.QtGui  import QColor, QFont, QBrush, QTextCharFormat, QTextCursor

# ── Colour palette ──────────────────────────────────────────────────────────────
try:
    from constants import (
        COLOR_DARK_BG, COLOR_ELEVATED_BG, COLOR_BORDER, COLOR_ACCENT,
        COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED, COLOR_SUCCESS,
        COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW,
        FONT_FAMILY_MONO, FONT_SIZE_SMALL, FONT_SIZE_NORMAL,
    )
except ImportError:
    COLOR_DARK_BG      = "#1e1e2e"
    COLOR_ELEVATED_BG  = "#2a2a3d"
    COLOR_BORDER       = "#444466"
    COLOR_ACCENT       = "#bd93f9"
    COLOR_TEXT         = "#cdd6f4"
    COLOR_TEXT_BRIGHT  = "#f8f8f2"
    COLOR_TEXT_MUTED   = "#6272a4"
    COLOR_SUCCESS      = "#50fa7b"
    COLOR_CRITICAL     = "#ff5555"
    COLOR_HIGH         = "#ffb86c"
    COLOR_MEDIUM       = "#f1fa8c"
    COLOR_LOW          = "#8be9fd"
    FONT_FAMILY_MONO   = "Consolas"
    FONT_SIZE_SMALL    = "9pt"
    FONT_SIZE_NORMAL   = "10pt"

# ── Risk / noise patterns ────────────────────────────────────────────────────────
_HIGH_RISK = re.compile(
    r'\b(admin|debug|token|secret|key|pass(?:word)?|auth|cmd|exec|shell|'
    r'upload|file|path|redirect|url|sql|query|id|uid|user_?id|account|role|'
    r'priv|api[_\-]?key|access[_\-]?token|session|cookie|callback|next|return|'
    r'dest(?:ination)?|config|setting|env|internal|test|dump|backup|'
    r'export|import|redir|include|require|load|src|href)\b', re.IGNORECASE)

_MEDIUM_RISK = re.compile(
    r'\b(page|limit|offset|sort|order|filter|format|type|mode|lang|locale|'
    r'theme|view|layout|template|ref|source|from|search|q|term|keyword|'
    r'category|tag|action|do|op|method|func|handler|endpoint)\b', re.IGNORECASE)

_JS_NOISE: Set[str] = {
    "function","return","var","let","const","true","false","null","undefined",
    "class","new","this","if","else","for","while","switch","case","break",
    "continue","try","catch","throw","typeof","instanceof","delete","void",
    "async","await","import","export","default","from","of","in","do",
    "get","set","has","map","then","data","res","req","err","error","ok",
    "length","index","value","name","type","text","html","body","head",
    "window","document","console","log","style","color","size","response",
    "request","status","message","code","info","detail","result","output",
    "input","form","field","label","button","submit","click","load","ready",
    *list("abcdefghijklmnopqrstuvwxyz"),
}

_ERROR_RE = re.compile(
    r'(error|exception|warning|fatal|stack.?trace|undefined.?variable|'
    r'syntax.?error|invalid|illegal|not.?found|forbidden|unauthori[sz]ed|'
    r'sql|mysql|postgresql|ora-\d|sqlite|internal.?server)',
    re.IGNORECASE)

_HARVEST_RE = re.compile(r'["\']([a-zA-Z_][a-zA-Z0-9_\-]{2,40})["\']', re.MULTILINE)

_PROBE_A = "PMPROBE7731z"
_PROBE_B = "9182PMCHECK"

_HEADER_WORDLIST = [
    "X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Proto","X-Forwarded-Scheme",
    "X-Forwarded-Port","X-Real-IP","X-Host","X-Custom-IP-Authorization",
    "X-Original-URL","X-Rewrite-URL","X-Override-URL","X-HTTP-Method-Override",
    "X-Method-Override","X-Requested-With","X-Request-ID","X-Correlation-ID",
    "X-Debug","X-Debug-Token","X-Debug-Mode","X-Debug-Options",
    "X-Cache","X-Cache-Status","X-Cache-Key","X-Cache-Lookup",
    "X-Backend","X-Backend-Server","X-Upstream","X-Origin",
    "X-API-Key","X-API-Version","X-Access-Token","X-Auth-Token",
    "X-CSRF-Token","X-Requested-Token","X-Security-Token",
    "X-Tenant","X-Tenant-ID","X-Account","X-Account-ID","X-Org","X-Org-ID",
    "X-User","X-User-ID","X-User-Role","X-Admin","X-Bypass","X-Internal",
    "X-Custom","X-Special","X-Feature","X-Feature-Flag","X-Experiment",
    "X-AB-Test","X-Test","X-Dev","X-Staging","X-Environment",
    "X-Frame-Options","X-Content-Type","X-Override","X-Proxy",
    "X-Originating-IP","X-Remote-Addr","X-Client-IP","X-Cluster-Client-IP",
    "Forwarded","Via","True-Client-IP","CF-Connecting-IP","Fastly-Client-IP",
    "X-Azure-SocketIP","X-WP-Nonce","X-Shopify-Access-Token",
    "Authorization","Bearer","Origin","Referer","Host",
    "X-Original-Host","X-Forwarded-Server",
]

_COOKIE_WORDLIST = [
    "session","sess","sid","token","auth","auth_token","access_token",
    "refresh_token","jwt","api_key","apikey","user","userid","user_id",
    "username","uid","account","role","admin","debug","test","csrf",
    "xsrf","nonce","remember","remember_me","keep_logged_in","lang",
    "locale","theme","view","pref","preferences","cart","cart_id",
    "checkout","order","order_id","affiliate","ref","referral","utm_source",
    "tracking","ga","_ga","_gid","fbp","fr","visitor_id","device_id",
    "fingerprint","consent","gdpr","ab_test","experiment","variant",
    "feature_flag","beta","preview","draft","impersonate","su","sudo",
    "override","bypass","internal","secret","key","priv","privilege",
]

_VULN_MAP = [
    (r"(redirect|url|dest|next|return|callback|redir|href|forward)", "Open Redirect / SSRF"),
    (r"(file|path|dir|folder|include|require|load)",                 "Path Traversal / LFI"),
    (r"(cmd|exec|shell|command|run|system|ping|eval)",               "Command Injection"),
    (r"(sql|query|where|select|from|table|insert|update)",           "SQL Injection"),
    (r"(token|secret|key|api_?key|bearer|jwt)",                      "API Key / Secret Exposure"),
    (r"(admin|debug|internal|config|setting|env|backup)",            "Privilege Escalation"),
    (r"(id|uid|user_?id|account_?id|object_?id|ref)",                "IDOR"),
    (r"(upload|attach|import|file|multipart)",                        "File Upload / RCE"),
    (r"(csrf|nonce|xsrf|state|verify|_token)",                       "CSRF Token Exposure"),
    (r"(template|tpl|tmpl|render|view)",                             "SSTI"),
    (r"(x-forwarded|x-host|x-real|x-origin|host|forwarded)",        "Host Header / Cache Poison"),
    (r"(x-debug|x-test|x-bypass|x-internal|x-admin|x-override)",    "Debug Header Bypass"),
]


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _parse_headers(raw: str) -> dict:
    out = {}
    for line in raw.splitlines():
        line = line.strip()
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def _cache_buster() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _bust(url: str) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}_cb={_cache_buster()}"


def _make_request(url, extra_headers, cookies, method="GET",
                  body=None, timeout=15):
    hdrs = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/124.0 Safari/537.36"),
        "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection":      "close",
    }
    hdrs.update(extra_headers)
    if cookies:
        hdrs["Cookie"] = cookies
    try:
        t0  = time.monotonic()
        req = urllib.request.Request(url, headers=hdrs, method=method, data=body)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            resp_body = r.read().decode(errors="replace")
            status    = r.status
            cl        = int(r.headers.get("Content-Length", len(resp_body)))
            resp_hdrs = dict(r.headers)
        elapsed = int((time.monotonic() - t0) * 1000)
        return status, resp_body, cl, elapsed, resp_hdrs
    except urllib.request.HTTPError as e:
        try:    resp_body = e.read().decode(errors="replace")
        except: resp_body = ""
        return e.code, resp_body, len(resp_body), 0, {}
    except Exception:
        return None, None, 0, 0, {}


def _fetch(base_headers, cookies, url, timeout=15, use_cache_buster=True):
    target = _bust(url) if use_cache_buster else url
    return _make_request(target, base_headers, cookies, timeout=timeout)


def _risk(p: str) -> str:
    if _HIGH_RISK.search(p):   return "HIGH"
    if _MEDIUM_RISK.search(p): return "MEDIUM"
    if len(p) <= 2 or p.isdigit(): return "INFO"
    return "LOW"


def _classify(p: str) -> str:
    pl = p.lower()
    if any(x in pl for x in ("token","key","secret","auth","bearer","jwt")):        return "Auth"
    if any(x in pl for x in ("id","uid","uuid","user","account","object")):          return "Identity"
    if any(x in pl for x in ("page","limit","offset","sort","per_page")):            return "Pagination"
    if any(x in pl for x in ("file","path","url","redirect","dest","src","href")):   return "Path/URL"
    if any(x in pl for x in ("cmd","exec","shell","query","sql","eval","expr")):     return "Injection"
    if any(x in pl for x in ("debug","test","internal","admin","config","env")):     return "Debug/Admin"
    if any(x in pl for x in ("search","q","term","keyword","find")):                 return "Search"
    if any(x in pl for x in ("csrf","nonce","xsrf","state","_token")):               return "CSRF/State"
    if any(x in pl for x in ("callback","next","return","redir","forward")):         return "Redirect"
    if p.startswith(("X-","x-")):                                                    return "Header"
    return "Generic"


def _vuln_hint(param: str) -> str:
    for pat, hint in _VULN_MAP:
        if re.search(pat, param.lower()):
            return hint
    return ""


def _harvest_words(body: str, resp_headers: dict) -> Set[str]:
    words: Set[str] = set()
    for m in _HARVEST_RE.finditer(body):
        w = m.group(1)
        if 3 <= len(w) <= 40 and w.lower() not in _JS_NOISE:
            words.add(w)
    return words


# ══════════════════════════════════════════════════════════════════════════════
#  QueueEntry
# ══════════════════════════════════════════════════════════════════════════════

class QueueEntry:
    STATUS_PENDING = "pending"
    STATUS_RUNNING = "running"
    STATUS_DONE    = "done"
    STATUS_ERROR   = "error"
    STATUS_STOPPED = "stopped"

    _ICONS  = {"pending":"⏳","running":"🔄","done":"✅","error":"❌","stopped":"⏹"}
    _COLORS = {"pending":COLOR_TEXT_MUTED,"running":COLOR_MEDIUM,
               "done":COLOR_SUCCESS,"error":COLOR_CRITICAL,"stopped":COLOR_HIGH}

    def __init__(self, url: str, config: dict):
        self.url         = url
        self.config      = config
        self.status      = self.STATUS_PENDING
        self.results     : List[dict] = []
        self.added_at    = datetime.now().strftime("%H:%M:%S")
        self.finished_at : Optional[str] = None
        self._retry_count: int = 0

    @property
    def display(self) -> str:
        icon  = self._ICONS.get(self.status, "?")
        badge = f"  [{len(self.results)} hits]" if self.results else ""
        return f"{icon}  {self.url}{badge}  {self.added_at}"

    @property
    def color(self) -> str:
        return self._COLORS.get(self.status, COLOR_TEXT_MUTED)


# ══════════════════════════════════════════════════════════════════════════════
#  DiscoveryWorker  –  runs Arjun and/or x8
# ══════════════════════════════════════════════════════════════════════════════

class DiscoveryWorker(QThread):
    """
    Runs Arjun (always) and optionally x8 (if use_x8=True in config).
    Emits raw terminal lines exactly as the tool prints them.
    """
    param_signal   = pyqtSignal(str)          # discovered param name
    terminal_signal= pyqtSignal(str)          # raw output line (no decoration added here)
    done_signal    = pyqtSignal()

    def __init__(self, url: str, config: dict,
                 on_param=None, on_terminal=None):
        super().__init__()
        self.url           = url
        self.config        = config
        self._stop         = False
        self._seen         : Set[str] = set()
        self._all_found    : Set[str] = set()
        self._on_param     = on_param    or (lambda p: None)
        self._on_terminal  = on_terminal or (lambda l: None)

    def stop(self): self._stop = True

    def _emit_param(self, p: str):
        p = p.strip()
        if not p or len(p) < 2 or len(p) > 60: return
        if p.lower() in _JS_NOISE: return
        if re.fullmatch(r'[\d_\-]+', p): return
        if p in self._seen: return
        self._seen.add(p)
        self._all_found.add(p)
        self._on_param(p)           # direct callback — no Qt event loop needed
        self.param_signal.emit(p)   # also emit Qt signal (for any external listeners)

    def _raw(self, line: str):
        """Emit a raw terminal line via direct callback AND Qt signal."""
        self._on_terminal(line)        # direct — always delivered
        self.terminal_signal.emit(line)  # Qt signal — may be queued

    def _parse_params_from_line(self, line: str, found: set):
        """Extract parameter names mentioned in a tool output line."""
        # Match: "[+] Extracted N parameters ... : a, b, c"
        m = re.search(r'Extracted \d+ parameters[^:]*:\s*(.+)', line, re.IGNORECASE)
        if m:
            for p in re.split(r'[,\s]+', m.group(1)):
                p = p.strip().strip('"\'')
                if p: found.add(p); self._emit_param(p)
            return
        # Match: "Parameters found: a, b, c"
        m = re.search(r'[Pp]arameters? (?:found|detected)[:\s]+(.+)', line)
        if m:
            for p in re.split(r'[,\s]+', m.group(1)):
                p = p.strip().strip('"\'')
                if p: found.add(p); self._emit_param(p)

    def _run_subprocess(self, cmd: List[str], out_file: str) -> Set[str]:
        """
        Run cmd via PTY so tools using rich/tqdm output live progress.
        Falls back to plain PIPE on Windows or if pty unavailable.
        """
        found: Set[str] = set()
        self._raw("$ " + " ".join(cmd) + "\n")

        _ANSI = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKSThlsu]')

        def _clean(raw: str) -> str:
            return re.sub(r'\r', '', _ANSI.sub('', raw))

        ran_ok = False
        try:
            import pty, select, errno as _errno

            master_fd, slave_fd = pty.openpty()
            process = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)
            ran_ok = True

            buf = b""
            while True:
                if self._stop:
                    process.terminate()
                    break
                try:
                    rlist, _, _ = select.select([master_fd], [], [], 0.05)
                except (ValueError, OSError):
                    break
                if rlist:
                    try:
                        chunk = os.read(master_fd, 4096)
                    except OSError as e:
                        if e.errno in (_errno.EIO, _errno.EBADF):
                            break
                        raise
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        raw_line, buf = buf.split(b"\n", 1)
                        line = _clean(raw_line.decode("utf-8", errors="replace"))
                        if line.strip():
                            self._raw(line + "\n")
                            self._parse_params_from_line(line, found)
                elif process.poll() is not None:
                    if buf:
                        line = _clean(buf.decode("utf-8", errors="replace"))
                        if line.strip():
                            self._raw(line + "\n")
                            self._parse_params_from_line(line, found)
                    break
            try:
                os.close(master_fd)
            except OSError:
                pass
            process.wait()

        except ImportError:
            pass  # fall through to PIPE fallback below

        except FileNotFoundError:
            self._raw(f"[ERROR] Binary not found: {cmd[0]}\n")
            ran_ok = True  # don't double-report

        except Exception as e:
            self._raw(f"[ERROR] PTY error: {e}\n")
            ran_ok = True

        if not ran_ok:
            # PIPE fallback (Windows / no pty module)
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True, bufsize=1, universal_newlines=True,
                )
                while True:
                    if self._stop:
                        process.terminate(); break
                    line = process.stdout.readline()
                    if not line and process.poll() is not None:
                        break
                    if line:
                        line = _clean(line)
                        if line.strip():
                            self._raw(line + "\n")
                            self._parse_params_from_line(line, found)
                process.wait()
            except FileNotFoundError:
                self._raw(f"[ERROR] Binary not found: {cmd[0]}\n")
            except Exception as e:
                self._raw(f"[ERROR] {e}\n")

        # Parse output file for any params Arjun/x8 wrote there
        if os.path.exists(out_file):
            try:
                with open(out_file, 'r', encoding='utf-8', errors='ignore') as fh:
                    for line in fh:
                        line = line.strip()
                        if not line: continue
                        if 'parameters found:' in line.lower():
                            part = line.split(':', 1)[1]
                            for p in part.split(','):
                                p = p.strip()
                                if p: found.add(p); self._emit_param(p)
                        elif ' ' not in line and '=' not in line:
                            found.add(line); self._emit_param(line)
                        elif '=' in line:
                            p = line.split('=')[0].strip()
                            if p: found.add(p); self._emit_param(p)
            except Exception:
                pass

        return found

    def _run_arjun(self) -> Set[str]:
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        tmp.close()

        arjun_bin = shutil.which("arjun")
        module_mode = arjun_bin is None
        base = ["python", "-m", "arjun"] if module_mode else [arjun_bin]

        meth = self.config.get("method", "GET")
        if meth in ("JSON", "XML"):
            meth = "POST"

        chunk_size = self.config.get("chunk", 100)

        cmd = base + [
            "-u", self.url,
            "-m", meth,
            "-t", str(self.config.get("threads", 5)),
            "-c", str(chunk_size),
            "-T", str(self.config.get("timeout", 15)),
            "-oT", tmp.name,
        ]

        # --stable only when explicitly enabled (slows scan ~3x)
        if self.config.get("stable", False):
            cmd.append("--stable")

        delay = self.config.get("delay", 0)
        if delay > 0:
            cmd += ["-d", str(delay)]

        cookies = self.config.get("cookies", "")
        if cookies:
            cmd += ["--headers", f"Cookie: {cookies}"]

        headers_raw = self.config.get("raw_headers", "")
        if headers_raw:
            for hline in headers_raw.splitlines():
                hline = hline.strip()
                if ":" in hline:
                    cmd += ["--headers", hline]

        wl = self.config.get("wordlist", "")
        if wl and os.path.isfile(wl):
            cmd += ["-w", wl]

        try:
            found = self._run_subprocess(cmd, tmp.name)
        finally:
            try: os.unlink(tmp.name)
            except: pass

        return found

    def _run_x8(self) -> Set[str]:
        tmp = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        tmp.close()

        x8_bin = shutil.which("x8")
        if not x8_bin:
            self._raw("[ERROR] x8 not found in PATH. Install: https://github.com/Sh1Yo/x8\n")
            return set()

        meth = self.config.get("method", "GET")

        cmd = [x8_bin, "-u", self.url, "-O", tmp.name]

        if meth == "POST":
            cmd.extend(["-X", "POST"])

        headers_raw = self.config.get("raw_headers", "")
        if headers_raw:
            for hline in headers_raw.splitlines():
                hline = hline.strip()
                if ":" in hline:
                    key, val = hline.split(":", 1)
                    cmd.extend(["-H", f"{key.strip()}: {val.strip()}"])

        cookies = self.config.get("cookies", "")
        if cookies:
            cmd.extend(["-b", cookies])

        wl = self.config.get("wordlist", "")
        if wl and os.path.isfile(wl):
            cmd.extend(["-w", wl])

        cmd.extend(["-t", str(self.config.get("threads", 5))])
        cmd.extend(["-T", str(self.config.get("timeout", 15))])

        try:
            found = self._run_subprocess(cmd, tmp.name)
        finally:
            try: os.unlink(tmp.name)
            except: pass

        return found

    def run(self):
        # ── Arjun (always) ─────────────────────────────────────────────────────
        self._raw("\n" + "─"*60 + "\n")
        self._raw(f"[ARJUN] Starting discovery: {self.url}\n")
        self._raw("─"*60 + "\n")
        arjun_found = self._run_arjun()
        self._raw(f"\n[ARJUN] Done — {len(arjun_found)} parameters found\n")

        if self._stop:
            self.done_signal.emit()
            return

        # ── x8 (optional) ──────────────────────────────────────────────────────
        if self.config.get("use_x8", False):
            self._raw("\n" + "─"*60 + "\n")
            self._raw(f"[X8] Starting discovery: {self.url}\n")
            self._raw("─"*60 + "\n")
            x8_found = self._run_x8()
            self._raw(f"\n[X8] Done — {len(x8_found)} parameters found\n")

        self.done_signal.emit()


# ══════════════════════════════════════════════════════════════════════════════
#  SourceAnalysisWorker  –  extracts params from HTTP response HTML/JS source
# ══════════════════════════════════════════════════════════════════════════════

class SourceAnalysisWorker(QThread):
    """
    Fetches the target URL and mines HTTP response source for parameter candidates:
      • HTML form fields  : <input name>, <select name>, <textarea name>
      • data-* attributes : data-param="..." → "param"
      • URL query params  : href/action/src containing ?a=1&b=2
      • Inline event handlers (onclick, onsubmit, …) — full JS analysis applied
      • Inline <script>   :
          – URLSearchParams .get/.set/.append/.has calls
          – FormData .append/.set calls
          – JS regex URL-capture patterns  /param=(https?…)/
          – Quoted JSON/object keys  "key":
          – ?param= / &param= in URL string literals
          – data/params/body/payload blocks  { key: val }
    All found parameters are reported directly to the Results tab.
    """
    param_signal    = pyqtSignal(str)
    terminal_signal = pyqtSignal(str)
    done_signal     = pyqtSignal()

    # ── Compiled patterns for <script> analysis ───────────────────────────────
    _JS_URLSP    = re.compile(
        r'\.(?:get|set|append|has|delete|getAll)\(\s*["\']'
        r'([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']',
        re.MULTILINE)
    _JS_FORMDATA = re.compile(
        r'\.(?:append|set)\(\s*["\']([a-zA-Z_][a-zA-Z0-9_\-]{1,50})["\']',
        re.MULTILINE)
    _JS_JSONKEY  = re.compile(
        r'["\']([a-zA-Z_][a-zA-Z0-9_\-]{2,40})["\'][ \t]*:',
        re.MULTILINE)
    _JS_URLQS    = re.compile(
        r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=',
        re.MULTILINE)
    _JS_DATABLOCK = re.compile(
        r'(?:data|params|body|payload|query)\s*[=:]\s*\{([^}]{0,600})\}',
        re.MULTILINE | re.DOTALL)
    _JS_DATAKEY  = re.compile(
        r'["\']?([a-zA-Z_][a-zA-Z0-9_\-]{2,40})["\']?\s*:',
        re.MULTILINE)
    # JS regex literal URL-capture patterns: e.g. /param=(https?...) / → param
    _JS_REGEX_PARAM = re.compile(
        r'/([a-zA-Z_][a-zA-Z0-9_\-]{1,40})=\(',
        re.MULTILINE)
    # Inline HTML event handler attributes (onclick="...", onsubmit='...', etc.)
    _HTML_HANDLER_RE = re.compile(
        r'\bon(?:click|submit|change|input|load|focus|blur|keyup|keydown|keypress'
        r'|mousedown|mouseup|mouseover|mouseleave|mouseenter|reset|select'
        r'|dblclick|hashchange|popstate)\s*='
        r'\s*(?:"([^"]{0,2000})"|\'([^\']{0,2000})\')',
        re.IGNORECASE | re.MULTILINE | re.DOTALL)

    # data-* prefixes (kept for potential future use)
    _SKIP_DATA = ()

    def __init__(self, url: str, config: dict, on_param=None, on_terminal=None, on_hit=None):
        super().__init__()
        self.url          = url
        self.config       = config
        self._stop        = False
        self._seen        : Set[str] = set()
        self._on_param    = on_param    or (lambda p: None)
        self._on_terminal = on_terminal or (lambda l: None)
        self._on_hit      = on_hit      or (lambda h: None)

    def stop(self): self._stop = True

    def _raw(self, line: str):
        self._on_terminal(line)
        self.terminal_signal.emit(line)

    def _emit(self, p: str):
        p = p.strip()
        if not p or len(p) < 2 or len(p) > 60: return
        if p.lower() in _JS_NOISE: return
        if re.fullmatch(r'[\d_\-\.]+', p): return
        if p in self._seen: return
        self._seen.add(p)
        self._on_param(p)
        self.param_signal.emit(p)

    def _analyze_js(self, js: str, found: Set[str]) -> None:
        """Apply all JS analysis patterns to a block of JavaScript text."""
        for m in self._JS_URLSP.finditer(js):        found.add(m.group(1))
        for m in self._JS_FORMDATA.finditer(js):     found.add(m.group(1))
        for m in self._JS_URLQS.finditer(js):        found.add(m.group(1))
        for m in self._JS_REGEX_PARAM.finditer(js):  found.add(m.group(1))
        for m in self._JS_JSONKEY.finditer(js):      found.add(m.group(1))
        for bm in self._JS_DATABLOCK.finditer(js):
            for km in self._JS_DATAKEY.finditer(bm.group(1)):
                found.add(km.group(1))
        for m in re.finditer(
                r'["\'](?:https?://[^"\']{0,400}|/[^"\']{0,400})'
                r'\?([^"\']{1,300})["\']', js):
            try:
                for k in urllib.parse.parse_qs(m.group(1), keep_blank_values=True):
                    found.add(k)
            except Exception:
                pass

    def run(self):
        self._raw("\n" + "─"*60 + "\n")
        self._raw(f"[SOURCE] Fetching & analyzing: {self.url}\n")
        self._raw("─"*60 + "\n")

        base_hdrs = _parse_headers(self.config.get("raw_headers", ""))
        cookies   = self.config.get("cookies", "")
        timeout   = self.config.get("timeout", 15)

        st, body, cl, ms, rh = _fetch(base_hdrs, cookies, self.url,
                                       timeout=timeout, use_cache_buster=False)
        if body is None:
            self._raw("[SOURCE] Failed to fetch page\n")
            self.done_signal.emit()
            return

        ct = rh.get("Content-Type", rh.get("content-type", ""))
        is_html = "html" in ct or body.lstrip()[:20].lower().startswith(("<!doctype", "<html", "<!-"))
        is_js   = "javascript" in ct or "json" in ct
        if not is_html and not is_js:
            self._raw(f"[SOURCE] Skipping (Content-Type: {ct[:60]})\n")
            self.done_signal.emit()
            return

        self._raw(f"[SOURCE] HTTP {st}  {cl}B  {ms}ms\n")

        # ── 1. Query params in href / action / src / data-url attributes ─────
        url_attr_found: Set[str] = set()
        for m in re.finditer(
                r'(?:href|action|src|data-url|data-href|data-action)'
                r'\s*=\s*["\']([^"\'#]{1,500})["\']', body, re.IGNORECASE):
            val = m.group(1)
            if '?' in val:
                try:
                    qs = urllib.parse.urlparse(val).query
                    for k in urllib.parse.parse_qs(qs, keep_blank_values=True):
                        url_attr_found.add(k)
                except Exception:
                    pass

        if url_attr_found:
            preview = ', '.join(sorted(url_attr_found)[:8])
            suffix  = '…' if len(url_attr_found) > 8 else ''
            self._raw(f"[SOURCE] URL attrs     → {len(url_attr_found):3d} candidates"
                      f"  [{preview}{suffix}]\n")
        else:
            self._raw("[SOURCE] URL attrs     →   0 candidates\n")

        for p in url_attr_found:
            if self._stop: break
            self._emit(p)

        if self._stop:
            self.done_signal.emit(); return

        # ── 2. Inline event handler JS (onclick, onsubmit, …) ────────────────
        handler_found: Set[str] = set()
        handler_count = 0
        for hm in self._HTML_HANDLER_RE.finditer(body):
            js = hm.group(1) or hm.group(2) or ""
            # Unescape common HTML entities that browsers encode inside attributes
            js = (js.replace("&amp;", "&").replace("&quot;", '"')
                    .replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">"))
            if js.strip():
                handler_count += 1
                self._analyze_js(js, handler_found)

        if handler_found:
            preview = ', '.join(sorted(handler_found)[:8])
            suffix  = '…' if len(handler_found) > 8 else ''
            self._raw(f"[SOURCE] Handlers×{handler_count:<3d}  → {len(handler_found):3d} candidates"
                      f"  [{preview}{suffix}]\n")
        else:
            self._raw(f"[SOURCE] Handlers×{handler_count:<3d}  →   0 candidates\n")

        for p in handler_found:
            if self._stop: break
            self._emit(p)

        if self._stop:
            self.done_signal.emit(); return

        # ── 3. Inline <script> JS analysis ──────────────────────────────────
        js_found: Set[str] = set()
        script_count = 0
        for sm in re.finditer(
                r'<script\b[^>]*>(.*?)</script>', body,
                re.IGNORECASE | re.DOTALL):
            js = sm.group(1)
            if not js.strip():
                continue
            script_count += 1
            self._analyze_js(js, js_found)

        if js_found:
            preview = ', '.join(sorted(js_found)[:8])
            suffix  = '…' if len(js_found) > 8 else ''
            self._raw(f"[SOURCE] <script>×{script_count:<3d}  → {len(js_found):3d} candidates"
                      f"  [{preview}{suffix}]\n")
        else:
            self._raw(f"[SOURCE] <script>×{script_count:<3d}  →   0 candidates\n")

        for p in js_found:
            if self._stop: break
            self._emit(p)

        # ── 4. Report all source-found params directly to the Results tab ────
        now = datetime.now().strftime("%H:%M:%S")
        all_source = (url_attr_found | handler_found | js_found)
        for p in sorted(all_source):
            if self._stop: break
            p = p.strip()
            if not p or len(p) < 2 or len(p) > 60: continue
            if p.lower() in _JS_NOISE: continue
            if re.fullmatch(r'[\d_\-\.]+', p): continue
            risk = _risk(p)
            self._on_hit({
                "param":        p,
                "probe_mode":   "source",
                "source":       "Source/HTML+JS",
                "method":       self.config.get("method", "GET"),
                "risk":         risk,
                "type":         _classify(p),
                "url":          self.url,
                "probe_repr":   f"[Found in page source]  {self.url}",
                "effect":       "FOUND_IN_SOURCE",
                "effects_list": ["FOUND_IN_SOURCE"],
                "size_delta":   0,
                "reflected":    False,
                "status_diff":  False,
                "probe_status": 0,
                "baseline_cl":  0,
                "probed_cl":    0,
                "elapsed_ms":   0,
                "vuln_hint":    _vuln_hint(p),
                "timestamp":    now,
            })

        self._raw(f"[SOURCE] Done — {len(self._seen)} unique candidates extracted\n")
        self.done_signal.emit()


# ══════════════════════════════════════════════════════════════════════════════
#  ProbeWorker  –  verifies candidates, emits confirmed hits
# ══════════════════════════════════════════════════════════════════════════════

class ProbeWorker(QThread):
    hit_signal    = pyqtSignal(dict)
    harvest_signal= pyqtSignal(str)
    terminal_signal = pyqtSignal(str)
    done_signal   = pyqtSignal()

    CL_DELTA_THRESHOLD  = 30
    TIMING_SIGMA_FACTOR = 3.0
    BASELINE_SAMPLES    = 3
    BUCKET_SIZE         = 32

    def __init__(self, url: str, candidates: List[str], config: dict,
                 on_hit=None, on_harvest=None, on_terminal=None):
        """
        Direct Python callbacks replace Qt signals for intra-thread comms.
        on_hit(hit_dict), on_harvest(word), on_terminal(line)
        """
        super().__init__()
        self.url          = url
        self.candidates   = candidates
        self.config       = config
        self._stop        = False
        self._on_hit      = on_hit      or (lambda h: None)
        self._on_harvest  = on_harvest  or (lambda w: None)
        self._on_terminal = on_terminal or (lambda l: None)
        self._base_hdrs = _parse_headers(config.get("raw_headers",""))
        self._cookies   = config.get("cookies","")
        self._timeout   = config.get("timeout", 15)
        self._mode      = config.get("probe_mode", "query")
        self._use_bsearch = config.get("binary_search", True)
        self._harvest   = config.get("dynamic_harvest", True)

    def stop(self): self._stop = True

    def _raw(self, line: str):
        self.terminal_signal.emit(line)

    def _baseline(self):
        samples = []
        for _ in range(self.BASELINE_SAMPLES):
            st, bd, cl, ms, rh = _fetch(self._base_hdrs, self._cookies,
                                         self.url, self._timeout)
            if bd is None:
                return None
            samples.append({"status":st,"body":bd,"cl":cl,"ms":ms,"rh":rh})
            time.sleep(0.15)
        return samples

    def _probe_single(self, param: str, value: str):
        mode = self._mode
        if mode == "header":
            hdrs = dict(self._base_hdrs); hdrs[param] = value
            return _make_request(_bust(self.url), hdrs, self._cookies, timeout=self._timeout)
        elif mode == "cookie":
            existing = self._cookies.strip()
            combined = f"{existing}; {param}={value}" if existing else f"{param}={value}"
            return _make_request(_bust(self.url), self._base_hdrs, combined, timeout=self._timeout)
        elif mode == "fat_get":
            body_str = urllib.parse.urlencode({param: value})
            hdrs = dict(self._base_hdrs)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            return _make_request(_bust(self.url), hdrs, self._cookies,
                                 method="GET", body=body_str.encode(), timeout=self._timeout)
        else:
            sep = "&" if "?" in self.url else "?"
            probe_url = _bust(f"{self.url}{sep}{param}={value}")
            return _make_request(probe_url, self._base_hdrs, self._cookies, timeout=self._timeout)

    def _probe_bucket(self, params: List[str], value: str) -> bool:
        mode = self._mode
        if mode == "header":
            hdrs = dict(self._base_hdrs)
            for p in params: hdrs[p] = value
            st, bd, cl, ms, rh = _make_request(_bust(self.url), hdrs, self._cookies,
                                                timeout=self._timeout)
        elif mode == "cookie":
            existing = self._cookies.strip()
            pairs = "; ".join(f"{p}={value}" for p in params)
            combined = f"{existing}; {pairs}" if existing else pairs
            st, bd, cl, ms, rh = _make_request(_bust(self.url), self._base_hdrs, combined,
                                                timeout=self._timeout)
        elif mode == "fat_get":
            body_str = urllib.parse.urlencode({p: value for p in params})
            hdrs = dict(self._base_hdrs)
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
            st, bd, cl, ms, rh = _make_request(_bust(self.url), hdrs, self._cookies,
                                                method="GET", body=body_str.encode(),
                                                timeout=self._timeout)
        else:
            sep = "&" if "?" in self.url else "?"
            qs  = "&".join(f"{p}={value}" for p in params)
            probe_url = _bust(f"{self.url}{sep}{qs}")
            st, bd, cl, ms, rh = _make_request(probe_url, self._base_hdrs, self._cookies,
                                                timeout=self._timeout)
        if bd is None: return False
        cl_delta = cl - self._b_cl_mean
        return (st != self._b_status or abs(cl_delta) > self._noise_floor or
                value in bd or bool(_ERROR_RE.search(bd) and not self._b_has_err))

    def _binary_search(self, params: List[str], value: str) -> List[str]:
        if len(params) == 1:
            return params
        mid = len(params) // 2
        left, right = params[:mid], params[mid:]
        hits = []
        if self._probe_bucket(left, value):  hits.extend(self._binary_search(left, value))
        if self._probe_bucket(right, value): hits.extend(self._binary_search(right, value))
        return hits

    def _detect_effects(self, st, bd, cl, ms) -> List[str]:
        effects = []
        cl_delta = cl - self._b_cl_mean
        if st != self._b_status:                        effects.append(f"SC:{self._b_status}→{st}")
        if abs(cl_delta) > self._noise_floor:           effects.append(f"ΔCL:{cl_delta:+.0f}B")
        if _PROBE_A in bd:                              effects.append("REFLECTED")
        if _ERROR_RE.search(bd) and not self._b_has_err: effects.append("ERROR_TRIGGERED")
        if st in (301,302,303,307,308) and self._b_status not in (301,302,303,307,308):
            effects.append("REDIRECT")
        if self._b_time_std > 0:
            z = (ms - self._b_time_mean) / self._b_time_std
            if z > self.TIMING_SIGMA_FACTOR and ms > 2000:
                effects.append(f"TIMING:{ms}ms")
        return effects

    def run(self):
        mode = self._mode
        lbl  = {"query":"Query","header":"Header","cookie":"Cookie","fat_get":"FatGET"}.get(mode,mode)

        self._raw(f"\n[PROBE:{lbl}] Testing {len(self.candidates)} candidates\n")

        if not self.candidates:
            self.done_signal.emit(); return

        samples = self._baseline()
        if samples is None:
            self._raw("[PROBE] Baseline failed — target may be down\n")
            self.done_signal.emit(); return

        self._b_status   = samples[0]["status"]
        self._b_body     = samples[-1]["body"]
        b_lengths        = [s["cl"] for s in samples]
        self._b_cl_mean  = statistics.mean(b_lengths)
        b_cl_std         = statistics.stdev(b_lengths) if len(b_lengths)>1 else 0
        b_times          = [s["ms"] for s in samples]
        self._b_time_mean= statistics.mean(b_times)
        self._b_time_std = statistics.stdev(b_times) if len(b_times)>1 else 1
        self._noise_floor= max(self.CL_DELTA_THRESHOLD, b_cl_std * 2.5)
        self._b_has_err  = bool(_ERROR_RE.search(self._b_body))

        self._raw(f"[PROBE] Baseline HTTP {self._b_status} | "
                  f"Size {self._b_cl_mean:.0f}±{b_cl_std:.0f}B | "
                  f"Noise floor {self._noise_floor:.0f}B\n")

        # Phase A – binary search bucketing
        if self._use_bsearch and len(self.candidates) > self.BUCKET_SIZE:
            narrowed = []
            chunks = [self.candidates[i:i+self.BUCKET_SIZE]
                      for i in range(0, len(self.candidates), self.BUCKET_SIZE)]
            self._raw(f"[PROBE] Binary search: {len(chunks)} buckets\n")
            for i, chunk in enumerate(chunks, 1):
                if self._stop: break
                hits = self._binary_search(chunk, _PROBE_A)
                self._raw(f"[PROBE] Bucket {i}/{len(chunks)} → {len(hits)} hits\n")
                narrowed.extend(hits)
            to_verify = narrowed
        else:
            to_verify = self.candidates

        # Phase B – individual probe + double verify
        confirmed = 0
        for idx, param in enumerate(to_verify):
            if self._stop: break
            st, bd, cl, ms, rh = self._probe_single(param, _PROBE_A)
            if bd is None: continue

            if self._harvest:
                for w in _harvest_words(bd, rh):
                    self._on_harvest(w)            # direct
                    self.harvest_signal.emit(w)    # Qt signal

            effects = self._detect_effects(st, bd, cl, ms)
            if not effects: continue

            # Double verify
            st2, bd2, cl2, ms2, _ = self._probe_single(param, _PROBE_B)
            if bd2 is None: continue
            cl_delta2 = cl2 - self._b_cl_mean
            verify = (st2 != self._b_status or abs(cl_delta2) > self._noise_floor or
                      _PROBE_B in bd2 or bool(_ERROR_RE.search(bd2) and not self._b_has_err))
            if not verify and "REFLECTED" not in effects: continue

            confirmed += 1
            self._raw(f"[FOUND] {param} — {' | '.join(effects)}\n")

            if mode == "header":
                probe_repr = f"{param}: {_PROBE_A}  (header)"
            elif mode == "cookie":
                probe_repr = f"Cookie: {param}={_PROBE_A}"
            elif mode == "fat_get":
                probe_repr = f"[body] {param}={_PROBE_A}  (Fat GET)"
            else:
                sep = "&" if "?" in self.url else "?"
                probe_repr = f"{self.url}{sep}{param}={_PROBE_A}"

            hit = {
                "param":        param,
                "probe_mode":   mode,
                "source":       f"Probe/{lbl}",
                "method":       self.config.get("method","GET"),
                "risk":         _risk(param),
                "type":         _classify(param),
                "url":          self.url,
                "probe_repr":   probe_repr,
                "effect":       " | ".join(effects),
                "effects_list": effects,
                "size_delta":   int(cl - self._b_cl_mean),
                "reflected":    "REFLECTED" in effects,
                "status_diff":  st != self._b_status,
                "probe_status": st,
                "baseline_cl":  int(self._b_cl_mean),
                "probed_cl":    cl,
                "elapsed_ms":   ms,
                "vuln_hint":    _vuln_hint(param),
                "timestamp":    datetime.now().strftime("%H:%M:%S"),
            }
            self._on_hit(hit)           # direct callback — always delivered
            self.hit_signal.emit(hit)  # Qt signal

            delay = self.config.get("delay",0)
            if delay > 0: time.sleep(float(delay))

        self._raw(f"[PROBE:{lbl}] Complete — {confirmed} confirmed hits\n")
        self.done_signal.emit()


# ══════════════════════════════════════════════════════════════════════════════
#  ScanOrchestrator
# ══════════════════════════════════════════════════════════════════════════════

class ScanOrchestrator(QThread):
    hit_signal      = pyqtSignal(str, dict)   # (url, hit)
    terminal_signal = pyqtSignal(str, str)    # (url, raw_line)
    done_signal     = pyqtSignal(str, str)    # (url, status)

    def __init__(self, entry: QueueEntry):
        super().__init__()
        self.entry   = entry
        self._stop   = False
        self._workers: List[QThread] = []

    def stop(self):
        self._stop = True
        for w in self._workers:
            if hasattr(w, "stop"): w.stop()

    def _fwd(self, line: str):
        self.terminal_signal.emit(self.entry.url, line)

    def run(self):
        url    = self.entry.url
        config = self.entry.config
        self._fwd(f"\n{'='*60}\n")
        self._fwd(f"[PARAM MINER] {url}\n")
        self._fwd(f"[STARTED]  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self._fwd(f"{'='*60}\n\n")

        # ── Direct-callback collectors ────────────────────────────────────────
        # Qt signals between non-main threads require the receiving thread's
        # event loop — but .wait() blocks it. Direct Python callbacks always deliver.
        base_candidates : List[str] = []
        harvest_words   : List[str] = []
        hits            : List[dict] = []

        def _on_param(p: str):
            if p not in base_candidates:
                base_candidates.append(p)

        def _on_hit(h: dict):
            hits.append(h)
            self.entry.results.append(h)
            self.hit_signal.emit(url, h)   # UI is in main thread — safe

        def _on_harvest(w: str):
            harvest_words.append(w)

        # ── Phase 1 : Discovery ───────────────────────────────────────────────
        disc = DiscoveryWorker(url, config,
                               on_param=_on_param,
                               on_terminal=self._fwd)
        self._workers.append(disc)
        disc.start(); disc.wait()

        if self._stop:
            self.done_signal.emit(url, QueueEntry.STATUS_STOPPED); return

        # ── Phase 1b : Source Analysis (HTML/JS) ────────────────────────────
        if config.get("source_analysis", True):
            src = SourceAnalysisWorker(url, config,
                                       on_param=_on_param,
                                       on_terminal=self._fwd,
                                       on_hit=_on_hit)
            self._workers.append(src)
            src.start(); src.wait()

            if self._stop:
                self.done_signal.emit(url, QueueEntry.STATUS_STOPPED); return

        self._fwd(f"\n[DISCOVERY] {len(base_candidates)} unique candidates\n")

        # ── Phase 2 : Probing ─────────────────────────────────────────────────
        probe_modes = config.get("probe_modes", ["query"])

        mode_candidates = {
            "query":   list(base_candidates),
            "fat_get": list(base_candidates),
            "header":  list(dict.fromkeys(
                           _HEADER_WORDLIST +
                           [p for p in base_candidates if p.startswith(("X-","x-"))])),
            "cookie":  list(dict.fromkeys(_COOKIE_WORDLIST + base_candidates)),
        }

        for mode in probe_modes:
            if self._stop: break
            cands = mode_candidates.get(mode, list(base_candidates))
            if not cands: continue

            harvest_words.clear()

            mode_config = dict(config)
            mode_config["probe_mode"]      = mode
            mode_config["binary_search"]   = config.get("binary_search", True)
            mode_config["dynamic_harvest"] = config.get("dynamic_harvest", True)

            probe = ProbeWorker(url, cands, mode_config,
                                on_hit=_on_hit,
                                on_harvest=_on_harvest,
                                on_terminal=self._fwd)
            self._workers.append(probe)
            probe.start(); probe.wait()

            for w in harvest_words:
                if w not in cands:
                    cands.append(w)
                    base_candidates.append(w)
                    self._fwd(f"[HARVEST] New word: {w}\n")

        self._fwd(f"\n{'='*60}\n")
        self._fwd(f"[DONE] {len(hits)} hits | "
                  f"{datetime.now().strftime('%H:%M:%S')}\n")
        self._fwd(f"{'='*60}\n")

        self.done_signal.emit(url, QueueEntry.STATUS_DONE
                              if not self._stop else QueueEntry.STATUS_STOPPED)


# ══════════════════════════════════════════════════════════════════════════════
#  ParamMinerTab  –  main UI
# ══════════════════════════════════════════════════════════════════════════════

class ParamMinerTab:
    """
    Layout
    ──────
    ┌─────────────────────────────────────────┬──────────────────────────┐
    │  LEFT                                   │  RIGHT (controls)        │
    │  ┌── TOP: URL Queue ───────────────────┐│                          │
    │  │  list of queued URLs               ││  Arjun options           │
    │  └─────────────────────────────────────┘│  x8 checkbox + options   │
    │  ┌── BOTTOM: tabs ─────────────────────┐│  Request config          │
    │  │  Results | Terminal                 ││  Probe modes             │
    │  └─────────────────────────────────────┘│  Advanced                │
    └─────────────────────────────────────────┴──────────────────────────┘
    """

    RISK_COLORS = {
        "HIGH":   COLOR_CRITICAL,
        "MEDIUM": COLOR_MEDIUM,
        "LOW":    COLOR_LOW,
        "INFO":   COLOR_SUCCESS,
    }

    # ANSI-like colour mapping for terminal output keywords
    TERMINAL_KEYWORD_COLORS = {
        "[FOUND]":    "#50fa7b",
        "[ERROR]":    "#ff5555",
        "[PROBE]":    "#8be9fd",
        "[ARJUN]":    "#bd93f9",
        "[X8]":       "#ff79c6",
        "[HARVEST]":  "#50fa7b",
        "[DONE]":     "#50fa7b",
        "[STARTED]":  "#bd93f9",
        "[PARAM":     "#bd93f9",
        "[DISCOVERY]":"#8be9fd",
        "[SOURCE]":   "#ffb86c",
        "$ ":         "#f1fa8c",   # command line
    }

    def __init__(self, parent_tab_widget, http_history_tab=None):
        self.parent            = parent_tab_widget
        self.http_history_tab  = http_history_tab
        self._queue            : Dict[str, QueueEntry]       = {}
        self._queue_order      : List[str]                   = []
        self._orchestrators    : Dict[str, ScanOrchestrator] = {}
        self._selected_url     : Optional[str]               = None
        self._live_mode        : bool = True
        self._live_timer       : Optional[QTimer] = None
        self._processed_urls   : Set[str] = set()
        # Per-URL terminal buffer: url -> list of (raw_line, color) tuples
        self._terminal_buffers : Dict[str, List[tuple]] = {}
        # Per-URL base-path set for dedup: base_path -> url
        self._queued_bases     : Dict[str, str] = {}
        # Per-URL cookies extracted from HTTP history: url -> cookie_str
        self._url_cookies      : Dict[str, str] = {}
        # Index into findings deque — only findings[_snapshot_index:] are "new"
        # -1 means not yet snapshotted (will snapshot on first check)
        self._snapshot_index   : int = -1
        # Queue concurrency / rate-limit state
        self._queue_paused     : bool = False
        self._max_concurrent   : int  = 1   # updated from spin
        self._scan_delay       : float = 2.0 # seconds between scans
        # Project dir for persistence
        self._project_dir      : Optional[str] = None

        self.widget = QWidget()
        self.widget.setStyleSheet(
            f"QWidget {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT}; }}")
        self._build_ui()

        # Start live mode by default
        QTimer.singleShot(500, lambda: self._toggle_live_mode(False))

    # ══════════════════════════════════════════════════════════════════════════
    #  UI construction
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        root = QVBoxLayout(self.widget)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._toolbar())

        main_split = QSplitter(Qt.Horizontal)
        main_split.setHandleWidth(4)
        main_split.addWidget(self._left_panel())
        main_split.addWidget(self._right_panel())
        main_split.setSizes([700, 340])
        root.addWidget(main_split)

    # ── Toolbar ───────────────────────────────────────────────────────────────
    def _toolbar(self) -> QWidget:
        tb = QWidget()
        tb.setFixedHeight(44)
        tb.setStyleSheet(
            f"QWidget {{ background: {COLOR_ELEVATED_BG}; "
            f"border-bottom: 2px solid {COLOR_ACCENT}; }}")
        ly = QHBoxLayout(tb)
        ly.setContentsMargins(10, 4, 10, 4)
        ly.setSpacing(8)

        lbl = QLabel("⛏  PARAM MINER")
        lbl.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-weight: 900; font-size: 13pt;")
        ly.addWidget(lbl)

        ly.addWidget(self._vsep())

        ly.addWidget(self._lbl("URL:"))
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://target.example.com/path?existing=val")
        self.url_input.setMinimumWidth(340)
        self._style_input(self.url_input)
        self.url_input.returnPressed.connect(self._enqueue_url)
        ly.addWidget(self.url_input)

        self.add_btn = self._btn("➕ Add", COLOR_ACCENT, self._enqueue_url)
        ly.addWidget(self.add_btn)

        ly.addWidget(self._vsep())

        self.run_btn  = self._btn("▶ Run",  COLOR_SUCCESS, self._start_queue)
        self.stop_btn = self._btn("⏹ Stop", COLOR_CRITICAL, self._stop_current)
        self.stop_btn.setEnabled(False)
        ly.addWidget(self.run_btn)
        ly.addWidget(self.stop_btn)

        ly.addWidget(self._vsep())

        # Live mode toggle (ON by default)
        self.live_mode_cb = QCheckBox("⚡ Live Mode")
        self.live_mode_cb.setChecked(True)
        self.live_mode_cb.setStyleSheet(
            f"QCheckBox {{ color: {COLOR_SUCCESS}; font-weight: bold; }}")
        self.live_mode_cb.stateChanged.connect(
            lambda s: self._toggle_live_mode(s == Qt.Checked))
        ly.addWidget(self.live_mode_cb)

        self.live_status_lbl = QLabel("● LIVE")
        self.live_status_lbl.setStyleSheet(
            f"color: {COLOR_SUCCESS}; font-weight: bold; font-size: 9pt;")
        ly.addWidget(self.live_status_lbl)

        ly.addStretch()

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setFixedWidth(120)
        self._progress.setFixedHeight(14)
        self._progress.setVisible(False)
        self._progress.setStyleSheet(
            f"QProgressBar {{ border: 1px solid {COLOR_BORDER}; background: {COLOR_DARK_BG}; }} "
            f"QProgressBar::chunk {{ background: {COLOR_ACCENT}; }}")
        ly.addWidget(self._progress)

        self._global_status = QLabel("Ready")
        self._global_status.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        ly.addWidget(self._global_status)

        return tb

    # ── Left panel: queue (top) + results/terminal tabs (bottom) ─────────────
    def _left_panel(self) -> QWidget:
        lp = QWidget()
        lp_ly = QVBoxLayout(lp)
        lp_ly.setContentsMargins(0, 0, 0, 0)
        lp_ly.setSpacing(0)

        left_split = QSplitter(Qt.Vertical)
        left_split.setHandleWidth(5)
        left_split.addWidget(self._queue_panel())
        left_split.addWidget(self._bottom_tabs())
        left_split.setSizes([180, 560])

        lp_ly.addWidget(left_split)
        return lp

    # ── Queue panel ───────────────────────────────────────────────────────────
    def _queue_panel(self) -> QWidget:
        qw = QWidget()
        qw.setStyleSheet(
            f"QWidget {{ background: {COLOR_ELEVATED_BG}; "
            f"border-bottom: 1px solid {COLOR_BORDER}; }}")
        qly = QVBoxLayout(qw)
        qly.setContentsMargins(6, 4, 6, 4)
        qly.setSpacing(3)

        hdr = QHBoxLayout()
        qlbl = QLabel("📋  URL QUEUE")
        qlbl.setStyleSheet(f"color: {COLOR_ACCENT}; font-weight: 700; font-size: 10pt;")
        hdr.addWidget(qlbl)
        hdr.addStretch()
        self._queue_count_lbl = QLabel("0 URLs")
        self._queue_count_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        hdr.addWidget(self._queue_count_lbl)

        self._pause_btn = QPushButton("⏸ Pause")
        self._pause_btn.setFixedHeight(20)
        self._pause_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT};"
            f" border: 1px solid {COLOR_BORDER}; border-radius: 3px;"
            f" font-size: 8pt; padding: 0 6px; }}"
            f" QPushButton:hover {{ border-color: {COLOR_MEDIUM}; color: {COLOR_MEDIUM}; }}")
        self._pause_btn.clicked.connect(self._toggle_pause)
        hdr.addWidget(self._pause_btn)

        clr_all = QPushButton("🗑 Clear All")
        clr_all.setFixedHeight(20)
        clr_all.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_CRITICAL}; "
            f"border: 1px solid {COLOR_BORDER}; font-size: 8pt; padding: 0 6px; }}")
        clr_all.clicked.connect(self._clear_all_queue)
        hdr.addWidget(clr_all)
        qly.addLayout(hdr)

        # Stats bar
        self._queue_stats_lbl = QLabel("  Queue empty")
        self._queue_stats_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}; padding: 2px 4px;"
            f" background: {COLOR_DARK_BG};")
        qly.addWidget(self._queue_stats_lbl)

        self.queue_list = QListWidget()
        self.queue_list.setSelectionMode(QAbstractItemView.SingleSelection)
        self.queue_list.setStyleSheet(f"""
            QListWidget {{
                background: {COLOR_DARK_BG};
                border: none;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
            }}
            QListWidget::item {{
                padding: 4px 8px;
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            QListWidget::item:selected {{
                background: {COLOR_ACCENT};
                color: white;
            }}
            QListWidget::item:hover:!selected {{
                background: {COLOR_ELEVATED_BG};
            }}
        """)
        self.queue_list.currentItemChanged.connect(self._on_queue_selection)
        self.queue_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.queue_list.customContextMenuRequested.connect(self._queue_ctx_menu)
        qly.addWidget(self.queue_list)
        return qw

    # ── Bottom tabs: Results + Terminal ───────────────────────────────────────
    def _bottom_tabs(self) -> QWidget:
        bw = QWidget()
        bw_ly = QVBoxLayout(bw)
        bw_ly.setContentsMargins(0, 0, 0, 0)
        bw_ly.setSpacing(0)

        self._url_ctx_lbl = QLabel("  ☝  Select a URL in the queue above")
        self._url_ctx_lbl.setStyleSheet(
            f"QLabel {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_ACCENT}; "
            f"font-weight: 700; font-size: 9pt; padding: 4px 10px; "
            f"border-bottom: 1px solid {COLOR_BORDER}; }}")
        bw_ly.addWidget(self._url_ctx_lbl)

        self._inner_tabs = QTabWidget()
        self._inner_tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: none; }} "
            f"QTabBar::tab {{ background: {COLOR_ELEVATED_BG}; "
            f"color: {COLOR_TEXT_MUTED}; padding: 5px 14px; }} "
            f"QTabBar::tab:selected {{ background: {COLOR_DARK_BG}; "
            f"color: {COLOR_ACCENT}; border-bottom: 2px solid {COLOR_ACCENT}; }}")
        self._inner_tabs.addTab(self._hits_tab(),     "🎯 Results")
        self._inner_tabs.addTab(self._terminal_tab(), "💻 Terminal")
        bw_ly.addWidget(self._inner_tabs)
        return bw

    # ── Results tab ───────────────────────────────────────────────────────────
    def _hits_tab(self) -> QWidget:
        w = QWidget()
        ly = QVBoxLayout(w)
        ly.setContentsMargins(4, 4, 4, 4)
        ly.setSpacing(3)

        # Filter bar
        fbar = QHBoxLayout()
        fbar.addWidget(self._lbl("Filter:"))
        self.filter_input = QLineEdit()
        self.filter_input.setMaximumWidth(180)
        self.filter_input.setPlaceholderText("Search…")
        self.filter_input.textChanged.connect(self._apply_filter)
        self._style_input(self.filter_input)
        fbar.addWidget(self.filter_input)

        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["ALL RISK","HIGH","MEDIUM","LOW","INFO"])
        self.risk_combo.currentTextChanged.connect(self._apply_filter)
        self._style_combo(self.risk_combo)
        fbar.addWidget(self.risk_combo)

        self.effect_combo = QComboBox()
        self.effect_combo.addItems(
            ["ALL EFFECTS","REFLECTED","ΔCL","SC CHANGE","ERROR","REDIRECT","TIMING","FOUND_IN_SOURCE"])
        self.effect_combo.currentTextChanged.connect(self._apply_filter)
        self._style_combo(self.effect_combo)
        fbar.addWidget(self.effect_combo)

        fbar.addStretch()
        self._hits_count = QLabel("0 hits")
        self._hits_count.setStyleSheet(
            f"color: {COLOR_SUCCESS}; font-weight: 700; font-size: {FONT_SIZE_SMALL};")
        fbar.addWidget(self._hits_count)

        exp_btn = QPushButton("📤 Export JSON")
        exp_btn.setFixedHeight(22)
        exp_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_ACCENT}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 0 8px; font-size: 8pt; }}")
        exp_btn.clicked.connect(self._export_json)
        fbar.addWidget(exp_btn)
        ly.addLayout(fbar)

        self.hits_tree = self._make_tree(8, [
            "Parameter", "Mode", "Type", "Risk", "Effect", "ΔCL", "Refl", "SC Δ"])
        hdr = self.hits_tree.header()
        for ci, cw in [(0,180),(1,80),(2,90),(3,85),(4,200),(5,60),(6,50),(7,50)]:
            hdr.resizeSection(ci, cw)
        self.hits_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hits_tree.customContextMenuRequested.connect(self._hits_ctx_menu)
        self.hits_tree.itemDoubleClicked.connect(
            lambda item, _col: self._analyze_item(item.data(0, Qt.UserRole)))
        ly.addWidget(self.hits_tree)

        self.detail_lbl = QLabel("  Select a parameter for details")
        self.detail_lbl.setStyleSheet(
            f"QLabel {{ color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}; "
            f"padding: 3px 8px; background: {COLOR_ELEVATED_BG}; "
            f"border-top: 1px solid {COLOR_BORDER}; }}")
        ly.addWidget(self.detail_lbl)
        return w

    # ── Terminal tab ──────────────────────────────────────────────────────────
    def _terminal_tab(self) -> QWidget:
        """
        Raw terminal output — cmd + stdout exactly as if run in a real terminal.
        No timestamps, no emoji decorations added by us.
        """
        w = QWidget()
        ly = QVBoxLayout(w)
        ly.setContentsMargins(0, 0, 0, 0)
        ly.setSpacing(0)

        # Thin control bar
        ctrl = QWidget()
        ctrl.setFixedHeight(28)
        ctrl.setStyleSheet(f"background: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};")
        ctrl_ly = QHBoxLayout(ctrl)
        ctrl_ly.setContentsMargins(6, 2, 6, 2)
        ctrl_ly.setSpacing(6)

        lbl = QLabel("💻  TERMINAL")
        lbl.setStyleSheet(f"color: {COLOR_ACCENT}; font-weight: bold; font-size: 9pt;")
        ctrl_ly.addWidget(lbl)
        ctrl_ly.addStretch()

        self.term_auto_scroll = QCheckBox("Auto-scroll")
        self.term_auto_scroll.setChecked(True)
        self.term_auto_scroll.setStyleSheet(f"color: {COLOR_TEXT}; font-size: 9pt;")
        ctrl_ly.addWidget(self.term_auto_scroll)

        clr_btn = QPushButton("Clear")
        clr_btn.setFixedHeight(20)
        clr_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_CRITICAL}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 0 8px; font-size: 8pt; }}")
        clr_btn.clicked.connect(lambda: self.terminal_output.clear())
        ctrl_ly.addWidget(clr_btn)

        cpy_btn = QPushButton("Copy")
        cpy_btn.setFixedHeight(20)
        cpy_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 0 8px; font-size: 8pt; }}")
        cpy_btn.clicked.connect(self._copy_terminal)
        ctrl_ly.addWidget(cpy_btn)

        ly.addWidget(ctrl)

        self.terminal_output = QTextEdit()
        self.terminal_output.setReadOnly(True)
        self.terminal_output.setFont(QFont("Courier New", 9))
        self.terminal_output.setLineWrapMode(QTextEdit.NoWrap)
        self.terminal_output.setStyleSheet(f"""
            QTextEdit {{
                background: #0d0d0d;
                color: #c8c8c8;
                border: none;
                font-family: 'Courier New', 'Consolas', monospace;
                font-size: 9pt;
                selection-background-color: {COLOR_ACCENT};
            }}
        """)
        ly.addWidget(self.terminal_output)
        return w

    # ── Right panel: tool controls ────────────────────────────────────────────
    def _right_panel(self) -> QWidget:
        outer = QWidget()
        outer.setFixedWidth(450)
        outer.setStyleSheet(
            f"QWidget {{ background: {COLOR_ELEVATED_BG}; "
            f"border-left: 1px solid {COLOR_BORDER}; }}")

        sc = QScrollArea()
        sc.setWidgetResizable(True)
        sc.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        sc.setStyleSheet("QScrollArea { border: none; }")

        inner = QWidget()
        ly = QVBoxLayout(inner)
        ly.setContentsMargins(10, 8, 10, 12)
        ly.setSpacing(4)

        # ── ARJUN ─────────────────────────────────────────────────────────────
        self._section(ly, "🔴  ARJUN  (always active)")

        ly.addWidget(self._lbl("Chunk size  (-c):"))
        chunk_row = QHBoxLayout()
        self.chunk_spin = QSpinBox()
        self.chunk_spin.setRange(10, 5000)
        self.chunk_spin.setValue(100)
        self.chunk_spin.setSuffix(" params / request")
        self.chunk_spin.setToolTip(
            "Arjun -c: how many params to test per HTTP request.\n"
            "Lower = more accurate but slower. Higher = faster but may miss params.")
        self._style_spin(self.chunk_spin)
        chunk_row.addWidget(self.chunk_spin)
        chunk_row.addStretch()
        ly.addLayout(chunk_row)

        # Preset buttons for chunk
        preset_row = QHBoxLayout()
        for label, val in [("Fast\n500", 500), ("Balanced\n100", 100),
                            ("Stealth\n50", 50), ("Micro\n10", 10)]:
            pb = QPushButton(label)
            pb.setFixedHeight(34)
            pb.setStyleSheet(
                f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
                f"border: 1px solid {COLOR_BORDER}; font-size: 8pt; border-radius: 3px; }} "
                f"QPushButton:hover {{ border-color: {COLOR_ACCENT}; color: {COLOR_ACCENT}; }}")
            pb.clicked.connect(lambda _, v=val: self.chunk_spin.setValue(v))
            preset_row.addWidget(pb)
        ly.addLayout(preset_row)

        self.stable_cb = QCheckBox("🐢  Stable mode  (Arjun --stable, ~3× slower)")
        self.stable_cb.setChecked(False)
        self.stable_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_TEXT_MUTED}; }}")
        self.stable_cb.setToolTip(
            "Passes --stable to Arjun: triple-verifies each hit.\n"
            "Much more accurate but roughly 3× slower. Off by default.")
        ly.addWidget(self.stable_cb)

        # ── X8 ────────────────────────────────────────────────────────────────
        self._section(ly, "🟣  X8  (optional)")

        x8_hdr = QHBoxLayout()
        self.x8_cb = QCheckBox("Enable x8")
        self.x8_cb.setChecked(False)
        self.x8_cb.setStyleSheet(
            f"QCheckBox {{ color: {COLOR_ACCENT}; font-weight: bold; }}")
        self.x8_cb.stateChanged.connect(self._on_x8_toggle)
        x8_hdr.addWidget(self.x8_cb)
        x8_hdr.addStretch()
        ly.addLayout(x8_hdr)

        self.x8_options_widget = QWidget()
        x8_ly = QVBoxLayout(self.x8_options_widget)
        x8_ly.setContentsMargins(0, 2, 0, 0)
        x8_ly.setSpacing(3)
        x8_ly.addWidget(self._lbl("(x8 uses threads/timeout/wordlist/cookies from below)"))
        self.x8_options_widget.setVisible(False)
        ly.addWidget(self.x8_options_widget)

        # ── REQUEST CONFIG ─────────────────────────────────────────────────────
        self._section(ly, "🔧  REQUEST CONFIG")

        rr = QHBoxLayout()
        rr.addWidget(self._lbl("Method:"))
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET","POST","JSON","XML"])
        self._style_combo(self.method_combo)
        rr.addWidget(self.method_combo)
        rr.addStretch()
        ly.addLayout(rr)

        ly.addWidget(self._lbl("Custom Headers (key: value, one per line):"))
        self.headers_edit = QTextEdit()
        self.headers_edit.setMaximumHeight(58)
        self.headers_edit.setPlaceholderText("Authorization: Bearer …\nX-Custom: value")
        self.headers_edit.setStyleSheet(
            f"QTextEdit {{ background: {COLOR_DARK_BG}; color: {COLOR_MEDIUM}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 3px; "
            f"font-family: {FONT_FAMILY_MONO}; font-size: {FONT_SIZE_SMALL}; }}")
        ly.addWidget(self.headers_edit)

        ly.addWidget(self._lbl("Cookies:"))
        self.cookies_input = QLineEdit()
        self.cookies_input.setPlaceholderText("session=abc; csrf=xyz")
        self._style_input(self.cookies_input, COLOR_MEDIUM)
        ly.addWidget(self.cookies_input)

        # Wordlist
        wlr = QHBoxLayout()
        self.wordlist_input = QLineEdit()
        self.wordlist_input.setPlaceholderText("Wordlist path (optional)")
        self._style_input(self.wordlist_input)
        wl_btn = QPushButton("📂")
        wl_btn.setMaximumWidth(30)
        wl_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {COLOR_ACCENT}; "
            f"border: 1px solid {COLOR_BORDER}; }}")
        wl_btn.clicked.connect(self._browse_wordlist)
        wlr.addWidget(self.wordlist_input); wlr.addWidget(wl_btn)
        ly.addLayout(wlr)

        # ── PROBE MODES ────────────────────────────────────────────────────────
        self._section(ly, "🎯  PROBE MODES")
        self.probe_mode_checks: dict = {}
        for key, lbl_txt, on in [
            ("query",   "🔗  Query Params  (?param=val)",  True),
            ("header",  "📨  HTTP Headers",                 True),
            ("cookie",  "🍪  Cookie Params",                True),
            ("fat_get", "🐘  Fat GET  (GET + body)",        False),
        ]:
            cb = QCheckBox(lbl_txt)
            cb.setChecked(on)
            cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_TEXT}; }}")
            self.probe_mode_checks[key] = cb
            ly.addWidget(cb)

        # ── ADVANCED ──────────────────────────────────────────────────────────
        self._section(ly, "⚙  ADVANCED")

        self.binary_search_cb = QCheckBox("⚡  Binary Search Bucketing")
        self.binary_search_cb.setChecked(True)
        self.binary_search_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_SUCCESS}; }}")
        ly.addWidget(self.binary_search_cb)

        self.cache_buster_cb = QCheckBox("🛡  Cache Buster  (_cb=random)")
        self.cache_buster_cb.setChecked(True)
        self.cache_buster_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_SUCCESS}; }}")
        ly.addWidget(self.cache_buster_cb)

        self.dynamic_harvest_cb = QCheckBox("🌱  Dynamic Word Harvest")
        self.dynamic_harvest_cb.setChecked(True)
        self.dynamic_harvest_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_SUCCESS}; }}")
        ly.addWidget(self.dynamic_harvest_cb)

        self.source_analysis_cb = QCheckBox("🔍  HTML/JS Source Analysis")
        self.source_analysis_cb.setChecked(True)
        self.source_analysis_cb.setToolTip(
            "Fetch and analyze the response body to extract parameter candidates from:\n"
            "  • HTML form fields  (<input name>, <select name>, <textarea name>)\n"
            "  • data-* attributes\n"
            "  • Query params in href / action / src attributes\n"
            "  • Inline <script> blocks: URLSearchParams, FormData, JSON keys, URL strings")
        self.source_analysis_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_SUCCESS}; }}")
        ly.addWidget(self.source_analysis_cb)

        # Queue concurrency & delay
        q_grid = QHBoxLayout()
        for lbl_txt, attr, default, mn, mx, step, tip in [
            ("Concurrent", "_concurrent_spin", 1, 1, 5, 1,
             "Max simultaneous scans (1 = safe, sequential)"),
            ("Scan delay", "_scan_delay_spin", 2, 0, 60, 1,
             "Seconds to wait between finishing one scan and starting the next"),
        ]:
            vb = QVBoxLayout()
            vb.addWidget(self._lbl(lbl_txt))
            sp = QSpinBox()
            sp.setMinimum(mn); sp.setMaximum(mx); sp.setValue(default)
            sp.setToolTip(tip)
            self._style_spin(sp)
            setattr(self, attr, sp)
            vb.addWidget(sp)
            q_grid.addLayout(vb)
        ly.addLayout(q_grid)

        def _on_concurrent_change(v):
            self._max_concurrent = v
        def _on_delay_change(v):
            self._scan_delay = float(v)
        self._concurrent_spin.valueChanged.connect(_on_concurrent_change)
        self._scan_delay_spin.valueChanged.connect(_on_delay_change)

        # Numeric opts
        grid = QHBoxLayout()
        for lbl_txt, attr, default, mn, mx, step in [
            ("Threads",  "_threads_spin",  5,   1, 50,   1),
            ("Delay(s)", "_delay_spin",    0,   0, 10,   0.5),
            ("Timeout",  "_timeout_spin",  15,  5, 120,  1),
        ]:
            vb = QVBoxLayout()
            vb.addWidget(self._lbl(lbl_txt))
            sp = QDoubleSpinBox() if step < 1 else QSpinBox()
            if step < 1: sp.setSingleStep(step)
            sp.setMinimum(mn); sp.setMaximum(mx); sp.setValue(default)
            self._style_spin(sp)
            setattr(self, attr, sp)
            vb.addWidget(sp)
            grid.addLayout(vb)
        ly.addLayout(grid)

        # ── LIVE MODE OPTIONS ─────────────────────────────────────────────────
        self._section(ly, "⚡  LIVE MODE OPTIONS")

        live_row = QHBoxLayout()
        live_row.addWidget(self._lbl("Check interval:"))
        self.live_interval_spin = QSpinBox()
        self.live_interval_spin.setRange(5, 300)
        self.live_interval_spin.setValue(10)
        self.live_interval_spin.setSuffix(" sec")
        self._style_spin(self.live_interval_spin)
        live_row.addWidget(self.live_interval_spin)
        live_row.addStretch()
        ly.addLayout(live_row)

        self.live_filter_params_cb = QCheckBox("Only URLs with existing params (?)")
        self.live_filter_params_cb.setChecked(True)
        self.live_filter_params_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_TEXT}; }}")
        ly.addWidget(self.live_filter_params_cb)

        self.live_auto_run_cb = QCheckBox("Auto-run scan on new URLs")
        self.live_auto_run_cb.setChecked(True)
        self.live_auto_run_cb.setStyleSheet(f"QCheckBox {{ color: {COLOR_TEXT}; }}")
        ly.addWidget(self.live_auto_run_cb)

        self.live_info_lbl = QLabel("Status: OFF")
        self.live_info_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
        ly.addWidget(self.live_info_lbl)

        ly.addStretch()
        sc.setWidget(inner)

        outer_ly = QVBoxLayout(outer)
        outer_ly.setContentsMargins(0, 0, 0, 0)
        outer_ly.setSpacing(0)
        outer_ly.addWidget(sc)
        return outer

    # ══════════════════════════════════════════════════════════════════════════
    #  Terminal output
    # ══════════════════════════════════════════════════════════════════════════

    def _append_terminal(self, url: str, raw_line: str):
        """Buffer terminal line per URL; render only when that URL is selected."""
        color = "#c8c8c8"
        for kw, kw_color in self.TERMINAL_KEYWORD_COLORS.items():
            if kw in raw_line:
                color = kw_color
                break

        # Always buffer
        if url not in self._terminal_buffers:
            self._terminal_buffers[url] = []
        self._terminal_buffers[url].append((raw_line, color))

        # Only write to widget if this URL is the one currently displayed
        if url != self._selected_url:
            return
        self._write_terminal_line(raw_line, color)

    def _write_terminal_line(self, raw_line: str, color: str):
        escaped   = html.escape(raw_line)
        formatted = f'<span style="color:{color};white-space:pre;">{escaped}</span>'
        self.terminal_output.moveCursor(QTextCursor.End)
        self.terminal_output.insertHtml(formatted)
        if self.term_auto_scroll.isChecked():
            self.terminal_output.moveCursor(QTextCursor.End)
            self.terminal_output.ensureCursorVisible()

    def _copy_terminal(self):
        text = self.terminal_output.toPlainText()
        QApplication.clipboard().setText(text)

    # ══════════════════════════════════════════════════════════════════════════
    #  Live mode
    # ══════════════════════════════════════════════════════════════════════════

    def _toggle_live_mode(self, enabled: bool):
        self._live_mode = enabled
        self.live_mode_cb.setChecked(enabled)

        if enabled:
            self.live_status_lbl.setText("● LIVE")
            self.live_status_lbl.setStyleSheet(
                f"color: {COLOR_SUCCESS}; font-weight: bold; font-size: 9pt;")
            self.live_info_lbl.setText("Status: ON  — taking snapshot of existing history…")
            self.live_info_lbl.setStyleSheet(
                f"color: {COLOR_SUCCESS}; font-size: {FONT_SIZE_SMALL};")

            # Reset snapshot index so first check re-baselines against current history
            self._snapshot_index = -1

            self._live_timer = QTimer()
            self._live_timer.timeout.connect(self._check_for_new_urls)
            self._live_timer.start(self.live_interval_spin.value() * 1000)
            # First check runs immediately to set the baseline
            QTimer.singleShot(200, self._check_for_new_urls)
        else:
            self.live_status_lbl.setText("○ OFF")
            self.live_status_lbl.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: 9pt;")
            self.live_info_lbl.setText("Status: OFF")
            self.live_info_lbl.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};")
            if self._live_timer:
                self._live_timer.stop()
                self._live_timer = None

    def _extract_cookies_from_finding(self, finding: dict) -> str:
        """
        Extract Cookie header value from a finding dict.
        Tries request_file first, then inline finding fields.
        """
        # 1. Try to read from the raw request file
        req_file = finding.get("request_file", "") or finding.get("request_path", "")
        if req_file and os.path.isfile(req_file):
            try:
                with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line.lower().startswith("cookie:"):
                            return line[7:].strip()
            except Exception:
                pass

        # 2. Try inline request_text field
        req_text = finding.get("request_text", "") or finding.get("request", "")
        if req_text:
            for line in req_text.splitlines():
                if line.lower().startswith("cookie:"):
                    return line[7:].strip()

        # 3. Try headers dict
        headers = finding.get("headers", finding.get("request_headers", {}))
        if isinstance(headers, dict):
            for k, v in headers.items():
                if k.lower() == "cookie":
                    return v

        return ""

    def _check_for_new_urls(self):
        """Poll HTTP History for URLs added AFTER the startup snapshot."""
        if not self.http_history_tab:
            return

        try:
            findings = getattr(self.http_history_tab, 'findings', [])
            findings_list = list(findings)  # snapshot the deque to a list once

            # On first check: take the baseline snapshot now (loading may be done)
            if self._snapshot_index == -1:
                self._snapshot_index = len(findings_list)
                count = self._snapshot_index
                self.live_info_lbl.setText(
                    f"Status: ON  — baseline: {count} existing URLs frozen "
                    f"(watching for new traffic)")
                return  # nothing to queue yet — next tick will catch new ones

            # Only look at findings appended AFTER the snapshot
            new_findings = findings_list[self._snapshot_index:]
            if not new_findings:
                self.live_info_lbl.setText(
                    f"Status: ON  — watching  [{len(self._queue_order)} queued]")
                return

            only_params = self.live_filter_params_cb.isChecked()
            new_count = 0

            for finding in new_findings:
                url = finding.get("url", "")
                if not url:
                    continue

                # Skip static assets
                if re.search(r'\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)(\?|$)',
                             url, re.IGNORECASE):
                    continue

                # Only mine responses worth probing:
                #   2xx — real content with a working baseline
                #   400/422 — endpoint exists and already validates params (great target)
                # Skip: 3xx (redirects), 401/403 (blocked), 404 (not found), 5xx (unstable)
                status = finding.get("status", 0)
                try:
                    status = int(status)
                except (TypeError, ValueError):
                    status = 0
                if not (200 <= status < 300 or status in (400, 422)):
                    continue

                if only_params and "?" not in url:
                    continue

                if url in self._processed_urls:
                    continue

                base = url.split("?")[0]
                if base in self._queued_bases:
                    self._processed_urls.add(url)
                    continue

                # New unique base path — extract cookies and queue it
                cookies = self._extract_cookies_from_finding(finding)
                cfg = self._build_config()
                if cookies:
                    cfg['cookies'] = cookies

                entry = QueueEntry(url, cfg)
                self._queue[url] = entry
                self._queue_order.append(url)
                self._processed_urls.add(url)
                self._queued_bases[base] = url
                new_count += 1

            # Advance the snapshot index so we don't re-scan these next tick
            self._snapshot_index = len(findings_list)

            if new_count > 0:
                self._refresh_queue_list()
                self.live_info_lbl.setText(
                    f"Status: ON  — added {new_count} URL(s)  "
                    f"[total: {len(self._queue_order)}]")
                if self.live_auto_run_cb.isChecked():
                    self._start_queue()
            else:
                self.live_info_lbl.setText(
                    f"Status: ON  — watching  [{len(self._queue_order)} queued]")

        except Exception as e:
            self.live_info_lbl.setText(f"Status: Error — {str(e)[:60]}")

    # ══════════════════════════════════════════════════════════════════════════
    #  x8 toggle
    # ══════════════════════════════════════════════════════════════════════════

    def _on_x8_toggle(self, state: int):
        enabled = state == Qt.Checked
        self.x8_options_widget.setVisible(enabled)

    # ══════════════════════════════════════════════════════════════════════════
    #  Queue management
    # ══════════════════════════════════════════════════════════════════════════

    def _build_config(self) -> dict:
        return {
            "method":          self.method_combo.currentText(),
            "threads":         self._threads_spin.value(),
            "delay":           float(self._delay_spin.value()),
            "timeout":         self._timeout_spin.value(),
            "chunk":           self.chunk_spin.value(),
            "stable":          self.stable_cb.isChecked(),
            "wordlist":        self.wordlist_input.text(),
            "cookies":         self.cookies_input.text().strip(),
            "raw_headers":     self.headers_edit.toPlainText(),
            "use_x8":          self.x8_cb.isChecked(),
            "probe_modes":     [k for k, cb in self.probe_mode_checks.items()
                                if cb.isChecked()],
            "binary_search":   self.binary_search_cb.isChecked(),
            "cache_buster":    self.cache_buster_cb.isChecked(),
            "dynamic_harvest":  self.dynamic_harvest_cb.isChecked(),
            "source_analysis":  self.source_analysis_cb.isChecked(),
        }

    def _enqueue_url(self):
        url = self.url_input.text().strip()
        if not url.startswith(("http://","https://")):
            QMessageBox.warning(self.widget, "Param Miner",
                "Please enter a valid URL (http:// or https://)"); return
        if url in self._queue:
            QMessageBox.information(self.widget, "Param Miner",
                "This URL is already in the queue."); return
        entry = QueueEntry(url, self._build_config())
        self._queue[url] = entry
        self._queue_order.append(url)
        self._processed_urls.add(url)
        self._queued_bases[url.split("?")[0]] = url
        self._refresh_queue_list()
        self.url_input.clear()
        self._save_queue()

    def _toggle_pause(self):
        """Pause or resume the auto-queue."""
        self._queue_paused = not self._queue_paused
        if self._queue_paused:
            self._pause_btn.setText("▶ Resume")
            self._pause_btn.setStyleSheet(
                f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_MEDIUM};"
                f" border: 1px solid {COLOR_MEDIUM}; border-radius: 3px;"
                f" font-size: 8pt; padding: 0 6px; }}"
                f" QPushButton:hover {{ background: {COLOR_MEDIUM}; color: black; }}")
            self._global_status.setText("⏸  Queue paused")
        else:
            self._pause_btn.setText("⏸ Pause")
            self._pause_btn.setStyleSheet(
                f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT};"
                f" border: 1px solid {COLOR_BORDER}; border-radius: 3px;"
                f" font-size: 8pt; padding: 0 6px; }}"
                f" QPushButton:hover {{ border-color: {COLOR_MEDIUM}; color: {COLOR_MEDIUM}; }}")
            self._global_status.setText("▶  Queue resumed")
            QTimer.singleShot(100, self._start_queue)
        self._update_queue_stats()

    def _update_queue_stats(self):
        """Update the queue status label with pending/running/done/error counts."""
        pending = running = done = error = stopped = 0
        for url in self._queue_order:
            s = self._queue[url].status
            if s == QueueEntry.STATUS_PENDING:  pending  += 1
            elif s == QueueEntry.STATUS_RUNNING: running  += 1
            elif s == QueueEntry.STATUS_DONE:    done     += 1
            elif s == QueueEntry.STATUS_ERROR:   error    += 1
            elif s == QueueEntry.STATUS_STOPPED: stopped  += 1
        parts = []
        if running:  parts.append(f"🔄 {running} running")
        if pending:  parts.append(f"⏳ {pending} pending")
        if done:     parts.append(f"✅ {done} done")
        if error:    parts.append(f"❌ {error} error")
        if stopped:  parts.append(f"⏹ {stopped} stopped")
        paused_txt = "  [PAUSED]" if self._queue_paused else ""
        self._queue_stats_lbl.setText("  " + "  │  ".join(parts) + paused_txt
                                      if parts else "  Queue empty")

    def _start_queue(self):
        """Start up to _max_concurrent pending scans, respecting pause state."""
        if self._queue_paused:
            return
        running = sum(
            1 for orc in self._orchestrators.values() if orc.isRunning())
        slots = max(0, self._max_concurrent - running)
        started = 0
        for url in self._queue_order:
            if started >= slots:
                break
            entry = self._queue[url]
            if entry.status == QueueEntry.STATUS_PENDING:
                self._start_entry(entry)
                started += 1
        self._update_queue_stats()

    def _start_entry(self, entry: QueueEntry):
        url = entry.url
        orc = self._orchestrators.get(url)
        if orc and orc.isRunning(): return

        entry.status = QueueEntry.STATUS_RUNNING
        self._refresh_queue_list()
        self._select_url(url)

        self._progress.setVisible(True)
        self.stop_btn.setEnabled(True)
        self.run_btn.setEnabled(False)
        self._global_status.setText("🔄  Scanning…")

        # Clear terminal buffer for fresh scan on this URL
        self._terminal_buffers[url] = []
        if url == self._selected_url:
            self.terminal_output.clear()

        orc = ScanOrchestrator(entry)
        orc.hit_signal.connect(self._on_scan_hit)
        orc.terminal_signal.connect(self._append_terminal)
        orc.done_signal.connect(self._on_scan_done)
        orc.start()
        self._orchestrators[url] = orc

    def _stop_current(self):
        for url, orc in self._orchestrators.items():
            if orc.isRunning():
                orc.stop()
                self._queue[url].status = QueueEntry.STATUS_STOPPED
                self._refresh_queue_list()
                self._append_terminal(url, "\n[STOPPED] Scan stopped by user\n")
                break
        self.stop_btn.setEnabled(False)
        self.run_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._global_status.setText("⏹  Stopped")
        self._save_queue()

    def _clear_all_queue(self):
        for url, orc in list(self._orchestrators.items()):
            if orc.isRunning():
                orc.stop()
        self._orchestrators.clear()
        self._queue.clear()
        self._queue_order.clear()
        self._processed_urls.clear()
        self._queued_bases.clear()
        self._terminal_buffers.clear()
        self._selected_url = None
        self.queue_list.clear()
        self.hits_tree.clear()
        self.terminal_output.clear()
        self._queue_count_lbl.setText("0 URLs")
        self._hits_count.setText("0 hits")
        self._url_ctx_lbl.setText("  ☝  Select a URL in the queue above")
        self.stop_btn.setEnabled(False)
        self.run_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._global_status.setText("Ready")
        self._save_queue()

    def _refresh_queue_list(self):
        self.queue_list.blockSignals(True)
        self.queue_list.clear()
        for url in self._queue_order:
            entry = self._queue[url]
            item = QListWidgetItem(entry.display)
            item.setData(Qt.UserRole, url)
            item.setForeground(QBrush(QColor(entry.color)))
            self.queue_list.addItem(item)
        self._queue_count_lbl.setText(f"{len(self._queue_order)} URLs")
        self.queue_list.blockSignals(False)

        # Restore selection
        if self._selected_url:
            for i in range(self.queue_list.count()):
                if self.queue_list.item(i).data(Qt.UserRole) == self._selected_url:
                    self.queue_list.setCurrentRow(i)
                    break

    def _select_url(self, url: str):
        self._selected_url = url
        short = url[:80] + "…" if len(url) > 81 else url
        self._url_ctx_lbl.setText(f"  🔎  {short}")
        self._refresh_hits_for(url)
        # Restore buffered terminal output for this URL (do NOT clear if running)
        self.terminal_output.clear()
        for raw_line, color in self._terminal_buffers.get(url, []):
            self._write_terminal_line(raw_line, color)
        if self.term_auto_scroll.isChecked():
            self.terminal_output.moveCursor(QTextCursor.End)
            self.terminal_output.ensureCursorVisible()

    def _on_queue_selection(self, current, _prev):
        if current is None: return
        url = current.data(Qt.UserRole)
        if url: self._select_url(url)

    def _queue_ctx_menu(self, pos):
        item = self.queue_list.itemAt(pos)
        if not item: return
        url = item.data(Qt.UserRole)
        entry = self._queue.get(url)
        if not entry: return

        menu = QMenu(self.queue_list)
        menu.setStyleSheet(
            f"QMenu {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 4px; }} "
            f"QMenu::item {{ padding: 6px 20px; border-radius: 3px; }} "
            f"QMenu::item:selected {{ background: {COLOR_ACCENT}; color: white; }} "
            f"QMenu::separator {{ height: 1px; background: {COLOR_BORDER}; margin: 4px 0; }}")

        # ── Run / stop ────────────────────────────────────────────────────
        if entry.status == QueueEntry.STATUS_PENDING:
            act_run = menu.addAction("▶ Run this URL")
            act_run.triggered.connect(lambda checked=False, e=entry: self._start_entry(e))

        if entry.status == QueueEntry.STATUS_RUNNING:
            act_stop = menu.addAction("⏹ Stop")
            act_stop.triggered.connect(self._stop_current)

        # Re-run: available for done / error / stopped entries
        if entry.status in (QueueEntry.STATUS_DONE,
                            QueueEntry.STATUS_ERROR,
                            QueueEntry.STATUS_STOPPED):
            act_rerun = menu.addAction("🔄 Re-run")
            act_rerun.setToolTip("Clear results and run this URL again with the same config")
            act_rerun.triggered.connect(lambda checked=False, u=url: self._rerun_entry(u))

        menu.addSeparator()

        # ── Remove / export ───────────────────────────────────────────────
        act_rm = menu.addAction("🗑 Remove from queue")
        act_rm.triggered.connect(lambda checked=False, u=url: self._remove_url(u))

        if entry.results:
            act_exp = menu.addAction("📤 Export JSON")
            act_exp.triggered.connect(lambda checked=False, u=url: self._export_entry(u))

        menu.exec_(self.queue_list.mapToGlobal(pos))

    def _remove_url(self, url: str):
        orc = self._orchestrators.get(url)
        if orc and orc.isRunning():
            orc.stop()
        self._orchestrators.pop(url, None)
        self._queue.pop(url, None)
        if url in self._queue_order:
            self._queue_order.remove(url)
        if self._selected_url == url:
            self._selected_url = None
            self.hits_tree.clear()
            self.terminal_output.clear()
        self._refresh_queue_list()
        self._save_queue()

    def _rerun_entry(self, url: str):
        """Reset a finished/errored/stopped entry and run it again."""
        # Stop any lingering orchestrator
        orc = self._orchestrators.get(url)
        if orc and orc.isRunning():
            orc.stop()
            orc.wait(500)
        self._orchestrators.pop(url, None)

        entry = self._queue.get(url)
        if not entry:
            return

        # Reset state — keep config and url, wipe results
        entry.status      = QueueEntry.STATUS_PENDING
        entry.results     = []
        entry.finished_at = None
        entry._retry_count = 0

        # Clear terminal buffer for this url
        self._terminal_buffers.pop(url, None)

        self._refresh_queue_list()
        self._update_queue_stats()
        self._save_queue()

        # Select it so the user sees the cleared results panel
        self._select_url(url)

        # Immediately start scanning
        self._start_entry(entry)

    _RISK_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

    def _on_scan_hit(self, url: str, hit: dict):
        entry = self._queue.get(url)
        merged = False
        if entry:
            param = hit.get("param", "")
            existing = next((h for h in entry.results if h.get("param") == param), None)
            if existing:
                merged = True
                # Merge effects — append new effect only if not already present
                old_eff = existing.get("effect", "")
                new_eff = hit.get("effect", "")
                if new_eff and new_eff not in old_eff:
                    existing["effect"] = f"{old_eff} | {new_eff}" if old_eff else new_eff
                # Escalate risk to the highest seen
                if self._RISK_ORDER.get(hit.get("risk", ""), 0) > self._RISK_ORDER.get(existing.get("risk", ""), 0):
                    existing["risk"] = hit["risk"]
                # Accumulate boolean flags
                if hit.get("reflected"):   existing["reflected"]   = True
                if hit.get("status_diff"): existing["status_diff"] = True
                # Keep the largest size delta
                if abs(hit.get("size_delta", 0)) > abs(existing.get("size_delta", 0)):
                    existing["size_delta"] = hit["size_delta"]
            else:
                entry.results.append(hit)
        if url == self._selected_url:
            if merged:
                self._refresh_hits_for(url)   # re-render the updated row in place
            else:
                self._add_hit_row(hit)
            self._hits_count.setText(f"{len(entry.results)} hits" if entry else "? hits")

    def _on_scan_done(self, url: str, status: str):
        entry = self._queue.get(url)
        if entry:
            entry.status = status
            entry.finished_at = datetime.now().strftime("%H:%M:%S")
            # Auto-retry once on error
            if status == QueueEntry.STATUS_ERROR and entry._retry_count < 1:
                entry._retry_count += 1
                entry.status = QueueEntry.STATUS_PENDING
                self._append_terminal(url,
                    f"\n[RETRY] Retrying {url} (attempt {entry._retry_count})\n")
        self._refresh_queue_list()
        # Only disable stop/run if nothing else running
        running = sum(1 for orc in self._orchestrators.values() if orc.isRunning())
        if running == 0:
            self.stop_btn.setEnabled(False)
            self.run_btn.setEnabled(True)
            self._progress.setVisible(False)
        n = len(entry.results) if entry else 0
        self._global_status.setText(
            f"✅  Done — {n} hit(s)" if status == QueueEntry.STATUS_DONE
            else "🔄  Queue running…" if running > 0
            else "⏹  Stopped")
        self._update_queue_stats()
        self._save_queue()

        # Chain next pending entry after configurable delay
        delay_ms = max(200, int(self._scan_delay * 1000))
        if not self._queue_paused:
            QTimer.singleShot(delay_ms, self._start_queue)

    # ══════════════════════════════════════════════════════════════════════════
    #  Hits display
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_hits_for(self, url: str):
        self.hits_tree.clear()
        entry = self._queue.get(url)
        if not entry: return
        for hit in entry.results:
            self._add_hit_row(hit)
        self._hits_count.setText(f"{len(entry.results)} hits")

    def _add_hit_row(self, hit: dict):
        risk  = hit.get("risk","LOW")
        color = self.RISK_COLORS.get(risk, COLOR_TEXT)
        cols  = [
            hit.get("param",""),
            hit.get("probe_mode",""),
            hit.get("type",""),
            self._risk_icon(risk),
            hit.get("effect",""),
            f"{hit.get('size_delta',0):+d}",
            "✓" if hit.get("reflected") else "",
            "✓" if hit.get("status_diff") else "",
        ]
        item = QTreeWidgetItem(cols)
        item.setData(0, Qt.UserRole, hit)
        for i in range(len(cols)):
            item.setForeground(i, QBrush(QColor(color)))
        self.hits_tree.addTopLevelItem(item)

    def _apply_filter(self):
        url = self._selected_url
        entry = self._queue.get(url) if url else None
        if not entry: return

        text  = self.filter_input.text().lower()
        risk  = self.risk_combo.currentText()
        eff   = self.effect_combo.currentText()
        mode  = self.mode_filter_combo.currentText() if hasattr(self, 'mode_filter_combo') else "ALL MODES"

        self.hits_tree.clear()
        visible = 0
        for hit in entry.results:
            if text and text not in hit.get("param","").lower(): continue
            if risk != "ALL RISK" and hit.get("risk","") != risk: continue
            if eff not in ("ALL EFFECTS","") and eff.lower() not in hit.get("effect","").lower(): continue
            if mode not in ("ALL MODES","") and mode.lower() not in hit.get("probe_mode","").lower(): continue
            self._add_hit_row(hit)
            visible += 1
        self._hits_count.setText(f"{visible} hits")

    def _hits_ctx_menu(self, pos):
        item = self.hits_tree.itemAt(pos)
        if not item: return
        hit = item.data(0, Qt.UserRole)
        if not hit: return

        menu = QMenu(self.hits_tree)
        menu.setStyleSheet(
            f"QMenu {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; }} "
            f"QMenu::item:selected {{ background: {COLOR_ACCENT}; }}")

        copy_param = menu.addAction("📋 Copy param name")
        copy_param.triggered.connect(
            lambda: QApplication.clipboard().setText(hit.get("param","")))

        copy_url = menu.addAction("🔗 Copy probe URL")
        copy_url.triggered.connect(
            lambda: QApplication.clipboard().setText(hit.get("probe_repr","")))

        menu.addSeparator()
        analyze = menu.addAction("🔬 Analyze…")
        analyze.triggered.connect(lambda: self._analyze_item(hit))

        menu.exec_(self.hits_tree.mapToGlobal(pos))

    def _analyze_item(self, hit: Optional[dict]):
        if not hit: return
        url   = hit.get("url","")
        param = hit.get("param","")
        mode  = hit.get("probe_mode","query")
        sep   = "&" if "?" in url else "?"

        if mode == "header":
            follow_up = (
                f"  curl -sv -H '{param}: <payload>' '{url}'\n"
                f"  # Test for cache poisoning / host header injection")
        elif mode == "cookie":
            follow_up = (
                f"  curl -sv -H 'Cookie: {param}=<payload>' '{url}'\n"
                f"  # Test session fixation, auth bypass, privilege escalation")
        elif mode == "fat_get":
            follow_up = (
                f"  curl -sv -X GET '{url}' -d '{param}=<payload>'\n"
                f"  # Fat GET — may bypass WAF/cache rules")
        else:
            follow_up = (
                f"  sqlmap -u '{url}{sep}{param}=1'\n"
                f"  dalfox url '{url}{sep}{param}=xss'\n"
                f"  ffuf -u '{url}{sep}{param}=FUZZ' -w wordlist.txt\n"
                f"  nuclei -u '{url}' -t fuzzing/")

        msg = (
            f"{'━'*50}\n EFFECTIVE PARAMETER  [{mode.upper()}]\n{'━'*50}\n"
            f" Parameter : {param}\n"
            f" Type      : {hit.get('type','')}\n"
            f" Risk      : {hit.get('risk','')}\n"
            f" Effect    : {hit.get('effect','')}\n"
            f" ΔCL       : {hit.get('size_delta',0):+d} bytes\n"
            f" Reflected : {'YES ⚠' if hit.get('reflected') else 'No'}\n"
            f" Status Δ  : {'YES → '+str(hit.get('probe_status','')) if hit.get('status_diff') else 'No'}\n"
            f" Vuln Hint : {hit.get('vuln_hint','') or 'None'}\n"
            f" Probe     : {hit.get('probe_repr','')}\n\n"
            f"{'━'*50}\n FOLLOW-UP\n{'━'*50}\n{follow_up}\n"
        )
        QMessageBox.information(self.widget, "Parameter Analysis", msg)

    # ══════════════════════════════════════════════════════════════════════════
    #  Export
    # ══════════════════════════════════════════════════════════════════════════

    def _export_json(self):
        url   = self._selected_url
        entry = self._queue.get(url) if url else None
        if not entry or not entry.results:
            QMessageBox.information(self.widget, "Export", "No results to export."); return
        self._export_entry(url)

    def _export_entry(self, url: str):
        entry = self._queue.get(url)
        if not entry or not entry.results:
            QMessageBox.information(self.widget, "Export", "No results."); return
        path, _ = QFileDialog.getSaveFileName(
            self.widget, "Export JSON", filter="JSON (*.json);;All (*)")
        if path:
            with open(path, "w") as f:
                json.dump({"url": url, "results": entry.results}, f, indent=2)
            QMessageBox.information(self.widget, "Export", f"Saved → {path}")

    # ══════════════════════════════════════════════════════════════════════════
    #  Utilities
    # ══════════════════════════════════════════════════════════════════════════

    def _make_tree(self, cols: int, headers: list) -> QTreeWidget:
        t = QTreeWidget()
        t.setColumnCount(cols)
        t.setHeaderLabels(headers)
        t.setAlternatingRowColors(False)
        t.setAnimated(True)
        t.setStyleSheet(f"""
            QTreeWidget {{
                background: {COLOR_DARK_BG};
                border: none;
            }}
            QTreeWidget::item {{
                padding: 3px 2px;
                border-bottom: 1px solid {COLOR_BORDER};
            }}
            QTreeWidget::item:selected {{
                background: {COLOR_ACCENT};
                color: white;
            }}
            QTreeWidget::item:hover:!selected {{
                background: {COLOR_ELEVATED_BG};
            }}
        """)
        t.header().setStyleSheet(f"""
            QHeaderView::section {{
                background: {COLOR_ELEVATED_BG};
                color: {COLOR_ACCENT};
                font-weight: 700;
                padding: 5px 8px;
                border: none;
                border-bottom: 2px solid {COLOR_ACCENT};
                border-right: 1px solid {COLOR_BORDER};
            }}
        """)
        return t

    def _section(self, layout, text: str):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"QLabel {{ color: {COLOR_ACCENT}; font-weight: 700; margin-top: 8px; }}")
        layout.addWidget(lbl)
        ln = QFrame(); ln.setFrameShape(QFrame.HLine)
        ln.setStyleSheet(f"QFrame {{ color: {COLOR_BORDER}; }}")
        layout.addWidget(ln)

    def _lbl(self, text: str) -> QLabel:
        l = QLabel(text)
        l.setStyleSheet(
            f"QLabel {{ color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}; }}")
        return l

    def _btn(self, text: str, color: str, slot) -> QPushButton:
        b = QPushButton(text)
        b.setFixedHeight(28)
        b.setStyleSheet(
            f"QPushButton {{ background: {COLOR_DARK_BG}; color: {color}; "
            f"border: 1px solid {color}; padding: 2px 12px; border-radius: 3px; font-weight: bold; }} "
            f"QPushButton:hover {{ background: {color}; color: {COLOR_DARK_BG}; }} "
            f"QPushButton:disabled {{ color: {COLOR_BORDER}; border-color: {COLOR_BORDER}; }}")
        b.clicked.connect(slot)
        return b

    def _vsep(self) -> QFrame:
        f = QFrame(); f.setFrameShape(QFrame.VLine)
        f.setFixedHeight(24)
        f.setStyleSheet(f"QFrame {{ color: {COLOR_BORDER}; }}")
        return f

    def _style_input(self, w: QLineEdit, color: str = None):
        c = color or COLOR_TEXT
        w.setStyleSheet(
            f"QLineEdit {{ background: {COLOR_DARK_BG}; color: {c}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 4px; border-radius: 2px; }} "
            f"QLineEdit:focus {{ border-color: {COLOR_ACCENT}; }}")

    def _style_combo(self, w: QComboBox):
        w.setStyleSheet(
            f"QComboBox {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 3px 6px; }} "
            f"QComboBox::drop-down {{ border: none; }} "
            f"QComboBox QAbstractItemView {{ background: {COLOR_DARK_BG}; "
            f"color: {COLOR_TEXT}; selection-background-color: {COLOR_ACCENT}; }}")

    def _style_spin(self, w):
        w.setStyleSheet(
            f"QSpinBox, QDoubleSpinBox {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; padding: 2px; }} "
            f"QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {COLOR_ACCENT}; }}")

    @staticmethod
    def _risk_icon(r: str) -> str:
        return {"HIGH":"🔴 HIGH","MEDIUM":"🟠 MEDIUM",
                "LOW":"🟡 LOW","INFO":"🔵 INFO"}.get(r, r)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self.widget, "Select Wordlist",
            filter="Text Files (*.txt);;All Files (*)")
        if path: self.wordlist_input.setText(path)

    # ── Public API ────────────────────────────────────────────────────────────

    def set_project_dir(self, project_dir: str):
        """Called by hunt_gui after project loads. Triggers queue restore."""
        self._project_dir = project_dir
        self._load_queue()

    def _queue_file(self) -> Optional[str]:
        if self._project_dir:
            return os.path.join(self._project_dir, "param_miner_queue.json")
        return None

    def _save_queue(self):
        """Persist queue entries + results to project dir."""
        path = self._queue_file()
        if not path:
            return
        try:
            data = {
                "order": self._queue_order,
                "entries": {}
            }
            for url in self._queue_order:
                entry = self._queue[url]
                data["entries"][url] = {
                    "url":         entry.url,
                    "status":      entry.status,
                    "added_at":    entry.added_at,
                    "finished_at": entry.finished_at,
                    "config":      entry.config,
                    "results":     entry.results,
                }
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"ParamMiner _save_queue: {e}")

    def _load_queue(self):
        """Restore queue from project dir on startup."""
        path = self._queue_file()
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            order   = data.get("order", [])
            entries = data.get("entries", {})
            loaded  = 0

            for url in order:
                if url in self._queue or url not in entries:
                    continue
                raw = entries[url]

                entry = QueueEntry(url, raw.get("config", {}))
                entry.results     = raw.get("results", [])
                entry.added_at    = raw.get("added_at", "")
                entry.finished_at = raw.get("finished_at")

                # Running jobs can't be restored — mark them as stopped
                saved_status = raw.get("status", QueueEntry.STATUS_PENDING)
                if saved_status == QueueEntry.STATUS_RUNNING:
                    saved_status = QueueEntry.STATUS_STOPPED
                entry.status = saved_status

                self._queue[url]       = entry
                self._queue_order.append(url)
                self._processed_urls.add(url)
                self._queued_bases[url.split("?")[0]] = url
                loaded += 1

            if loaded:
                self._refresh_queue_list()
                self._update_queue_stats()
                import logging
                logging.getLogger(__name__).info(
                    f"ParamMiner: restored {loaded} entries from {path}")
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"ParamMiner _load_queue: {e}")

    def set_http_history_tab(self, tab):
        """Wire the HTTP History tab reference after construction."""
        self.http_history_tab = tab
        # Reset snapshot so _check_for_new_urls takes a fresh baseline
        self._snapshot_index = -1  # -1 = not yet snapshotted

    def _snapshot_existing_history(self):
        """
        Record the CURRENT size of findings as the baseline index.
        Everything at index < baseline is 'old traffic' and will be skipped.
        Everything appended after this call is 'new traffic' and will be picked up.
        Returns the number of existing findings that were frozen out.
        """
        if not self.http_history_tab:
            return 0
        try:
            findings = getattr(self.http_history_tab, 'findings', [])
            self._snapshot_index = len(findings)
            return self._snapshot_index
        except Exception:
            return 0

    def send_url(self, url: str, cookies: str = ""):
        """
        Called by HTTP History 'Send to Param Miner'.
        cookies: Cookie header value extracted from the HTTP request.
        """
        if cookies:
            self._url_cookies[url] = cookies
            self.cookies_input.setText(cookies)
        self.url_input.setText(url)
        self._enqueue_url()
        if self._live_mode:
            self._start_queue()