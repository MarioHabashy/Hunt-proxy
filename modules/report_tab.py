"""
report_tab.py – Bug Report Manager

A dedicated tab for creating, editing, and exporting confirmed vulnerability
reports.  Each report represents one confirmed bug and stores:

  • Title, severity, CVSS score, status
  • Target URL, parameter, endpoint description
  • Steps to reproduce (numbered list)
  • Proof-of-concept (payload / screenshot notes)
  • Impact description
  • Remediation recommendation
  • Timestamps (created / updated)

Reports are saved as individual JSON files inside:
  <project_dir>/reports/<report_id>.json

and can be exported to Markdown or plain text.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime
from typing import List, Dict, Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QLabel,
    QPushButton, QLineEdit, QTextEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView, QFrame,
    QFormLayout, QDialog, QDialogButtonBox, QMessageBox,
    QFileDialog, QScrollArea, QSizePolicy, QApplication, QMenu,
    QAction,
)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QColor, QFont, QIcon

from modules.constants import (
    COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_ELEVATED_BG, COLOR_CARD_BG,
    COLOR_BORDER, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED,
    COLOR_ACCENT, COLOR_CRITICAL, COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW,
    COLOR_INFO, COLOR_WARNING, COLOR_SUCCESS, COLOR_HOVER,
    COLOR_ACCENT_SECONDARY,
)

try:
    from modules.ai_client import AIWorker
    _AI_AVAILABLE = True
except ImportError:
    _AI_AVAILABLE = False

# ── Constants ─────────────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "Critical": COLOR_CRITICAL,
    "High":     COLOR_HIGH,
    "Medium":   COLOR_MEDIUM,
    "Low":      COLOR_LOW,
    "Info":     COLOR_INFO,
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

STATUS_OPTIONS = ["Draft", "In Review", "Confirmed", "Submitted", "Accepted", "Duplicate", "Informative", "NA"]

STATUS_COLORS = {
    "Draft":       COLOR_TEXT_MUTED,
    "In Review":   COLOR_WARNING,
    "Confirmed":   COLOR_ACCENT,
    "Submitted":   COLOR_ACCENT_SECONDARY,
    "Accepted":    COLOR_SUCCESS,
    "Duplicate":   COLOR_TEXT_MUTED,
    "Informative": COLOR_LOW,
    "NA":          COLOR_TEXT_MUTED,
}

COL_SEV   = 0
COL_TITLE = 1
COL_URL   = 2
COL_PARAM = 3
COL_STAT  = 4
COL_DATE  = 5
_COLUMNS  = ["Sev", "Title", "Target URL", "Parameter", "Status", "Created"]


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _btn(label: str, color: str = COLOR_ACCENT, hover: str = "") -> QPushButton:
    hover = hover or color
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: {color}; color: {COLOR_TEXT_BRIGHT};
            border: none; border-radius: 4px;
            padding: 5px 14px; font-weight: bold; font-size: 12px;
        }}
        QPushButton:hover {{ background: {hover}; }}
        QPushButton:disabled {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_MUTED}; }}
    """)
    return b


def _sec_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {COLOR_TEXT_MUTED}; font-size: 10px; font-weight: bold; "
        f"text-transform: uppercase; letter-spacing: 1px; padding-top: 10px;"
    )
    return lbl


# ── Report persistence ────────────────────────────────────────────────────────

class ReportStore:
    """Read / write reports as individual JSON files inside <project_dir>/reports/."""

    @staticmethod
    def reports_dir(project_dir: str) -> str:
        d = os.path.join(project_dir, "reports")
        os.makedirs(d, exist_ok=True)
        return d

    @staticmethod
    def load_all(project_dir: str) -> List[Dict]:
        d = ReportStore.reports_dir(project_dir)
        reports = []
        for fname in sorted(os.listdir(d)):
            if fname.endswith(".json"):
                try:
                    with open(os.path.join(d, fname), "r", encoding="utf-8") as f:
                        reports.append(json.load(f))
                except Exception:
                    pass
        # Sort by severity then creation date
        sev_key = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        reports.sort(key=lambda r: (
            sev_key.get(r.get("severity", "Info"), 99),
            r.get("created", ""),
        ))
        return reports

    @staticmethod
    def save(project_dir: str, report: Dict) -> bool:
        d = ReportStore.reports_dir(project_dir)
        path = os.path.join(d, f"{report['id']}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            return True
        except Exception:
            return False

    @staticmethod
    def delete(project_dir: str, report_id: str):
        d = ReportStore.reports_dir(project_dir)
        path = os.path.join(d, f"{report_id}.json")
        if os.path.exists(path):
            os.remove(path)


# ── Export helpers ────────────────────────────────────────────────────────────

def _to_markdown(report: Dict) -> str:
    sev = report.get("severity", "")
    title = report.get("title", "Untitled")
    lines = [
        f"# {title}",
        "",
        f"**Severity:** {sev}  ",
        f"**Status:** {report.get('status', '')}  ",
        f"**CVSS Score:** {report.get('cvss', 'N/A')}  ",
        f"**Created:** {report.get('created', '')}  ",
        f"**Updated:** {report.get('updated', '')}  ",
        "",
        "---",
        "",
        "## Target",
        "",
        f"- **Method:** `{report.get('method', '')}`",
        f"- **URL:** `{report.get('url', '')}`",
        f"- **Parameter:** `{report.get('parameter', '')}`",
        f"- **Endpoint:** {report.get('endpoint', '')}",
        "",
        "## Description",
        "",
        report.get("description", ""),
        "",
        "## Steps to Reproduce",
        "",
        report.get("steps", ""),
        "",
        "## Proof of Concept",
        "",
        report.get("poc", ""),
        "",
        "## Impact",
        "",
        report.get("impact", ""),
        "",
        "## Remediation",
        "",
        report.get("remediation", ""),
        "",
    ]
    return "\n".join(lines)


def _to_text(report: Dict) -> str:
    return (
        f"{'='*60}\n"
        f"TITLE    : {report.get('title', '')}\n"
        f"SEVERITY : {report.get('severity', '')}  |  CVSS: {report.get('cvss', 'N/A')}\n"
        f"STATUS   : {report.get('status', '')}\n"
        f"CREATED  : {report.get('created', '')}  UPDATED: {report.get('updated', '')}\n"
        f"{'='*60}\n\n"
        f"METHOD      : {report.get('method', '')}\n"
        f"TARGET URL  : {report.get('url', '')}\n"
        f"PARAMETER   : {report.get('parameter', '')}\n"
        f"ENDPOINT    : {report.get('endpoint', '')}\n\n"
        f"DESCRIPTION\n{'-'*40}\n{report.get('description', '')}\n\n"
        f"STEPS TO REPRODUCE\n{'-'*40}\n{report.get('steps', '')}\n\n"
        f"PROOF OF CONCEPT\n{'-'*40}\n{report.get('poc', '')}\n\n"
        f"IMPACT\n{'-'*40}\n{report.get('impact', '')}\n\n"
        f"REMEDIATION\n{'-'*40}\n{report.get('remediation', '')}\n"
    )


# ── AI Report Draft dialog ────────────────────────────────────────────────────

class AIReportDraftDialog(QDialog):
    """
    Progress dialog that calls the AI in a background thread and
    shows a preview of the generated report fields.
    Click 'Apply' to fill the parent ReportEditDialog's text fields.
    """

    def __init__(self, settings: dict, report: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(" AI Report Draft")
        self.setMinimumSize(560, 340)
        self.resize(620, 400)
        self.fields: dict = None   # populated on success
        self._worker = None
        self._settings = settings
        self._report   = report
        self._build_ui()
        self._apply_style()
        self._start()

    def _apply_style(self):
        self.setStyleSheet(f"""
            QDialog  {{ background: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
            QLabel   {{ color: {COLOR_TEXT_BRIGHT}; }}
            QTextEdit {{
                background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                padding: 6px; font-size: 12px;
            }}
        """)

    def _build_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 14)
        lay.setSpacing(12)

        # Header row
        hdr = QHBoxLayout()
        self._icon_lbl = QLabel("")
        self._icon_lbl.setStyleSheet("font-size: 30px;")
        hdr.addWidget(self._icon_lbl)

        meta = QVBoxLayout()
        title_lbl = QLabel("AI Report Draft")
        title_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-size: 15px; font-weight: bold;"
        )
        self._status_lbl = QLabel("Connecting to AI provider…")
        self._status_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 12px;")
        meta.addWidget(title_lbl)
        meta.addWidget(self._status_lbl)
        hdr.addLayout(meta)
        hdr.addStretch()
        lay.addLayout(hdr)

        # Output preview
        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setPlaceholderText("Waiting for AI response…")
        lay.addWidget(self._output, 1)

        # Buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self._apply_btn = _btn(" Apply to Report", COLOR_SUCCESS)
        self._apply_btn.setEnabled(False)
        self._apply_btn.clicked.connect(self.accept)
        btn_row.addWidget(self._apply_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"padding: 5px 14px; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {COLOR_HOVER}; }}"
        )
        cancel_btn.clicked.connect(self._on_cancel)
        btn_row.addWidget(cancel_btn)
        btn_row.addStretch()
        lay.addLayout(btn_row)

    def _start(self):
        if not _AI_AVAILABLE:
            self._on_error("ai_client module not found. Ensure ai_client.py is in the same directory.")
            return
        self._worker = AIWorker(self._settings, self._report, self)
        self._worker.finished.connect(self._on_success)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_success(self, fields: dict):
        self.fields = fields
        lines = []
        for label, key in [
            ("Description",        "description"),
            ("Steps to Reproduce", "steps"),
            ("Impact",             "impact"),
            ("Remediation",        "remediation"),
        ]:
            lines.append(f"── {label} ──")
            lines.append(fields.get(key, ""))
            lines.append("")
        self._output.setPlainText("\n".join(lines).strip())
        self._status_lbl.setText("  Draft ready — review and click Apply.")
        self._status_lbl.setStyleSheet(f"color: {COLOR_SUCCESS}; font-size: 12px;")
        self._apply_btn.setEnabled(True)
        self._icon_lbl.setText("")

    def _on_error(self, msg: str):
        self._status_lbl.setText("  Generation failed.")
        self._status_lbl.setStyleSheet(f"color: {COLOR_CRITICAL}; font-size: 12px;")
        self._output.setPlainText(f"Error:\n{msg}")
        self._icon_lbl.setText("")

    def _on_cancel(self):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
        self.reject()

    def closeEvent(self, event):
        if self._worker and self._worker.isRunning():
            self._worker.terminate()
        super().closeEvent(event)


# ── Edit / Create dialog ──────────────────────────────────────────────────────

class ReportEditDialog(QDialog):
    """Full-featured dialog to create or edit a bug report."""

    def __init__(self, report: Optional[Dict] = None, parent=None, settings: dict = None):
        super().__init__(parent)
        self._settings = settings or {}
        self._report = dict(report) if report else {
            "id":          str(uuid.uuid4()),
            "title":       "",
            "severity":    "High",
            "status":      "Draft",
            "cvss":        "",
            "method":      "GET",
            "url":         "",
            "parameter":   "",
            "endpoint":    "",
            "description": "",
            "steps":       "1. \n2. \n3. ",
            "poc":         "",
            "impact":      "",
            "remediation": "",
            "created":     _now(),
            "updated":     _now(),
        }
        self.setWindowTitle("📝 Edit Report" if report else "📝 New Bug Report")
        self.setMinimumSize(820, 700)
        self.resize(960, 780)
        self._build_ui()
        self._load_fields()
        self._apply_style()

    def _apply_style(self):
        self.setStyleSheet(f"""
            QDialog {{ background: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
            QLabel  {{ color: {COLOR_TEXT_BRIGHT}; font-size: 12px; }}
            QLineEdit, QComboBox, QTextEdit {{
                background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER}; border-radius: 4px;
                padding: 5px 8px; font-size: 12px;
            }}
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {{
                border-color: {COLOR_ACCENT};
            }}
            QComboBox QAbstractItemView {{
                background: {COLOR_CARD_BG}; color: {COLOR_TEXT_BRIGHT};
                selection-background-color: {COLOR_ACCENT};
            }}
            QScrollBar:vertical {{
                background: {COLOR_DARK_BG}; width: 8px; border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {COLOR_BORDER}; border-radius: 4px; min-height: 20px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

    def _build_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # ── Header bar ────────────────────────────────────────────────────
        header = QWidget()
        header.setFixedHeight(50)
        header.setStyleSheet(f"background: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(18, 0, 18, 0)
        title_lbl = QLabel("Bug Report")
        title_lbl.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT}; font-size: 16px; font-weight: bold;")
        hl.addWidget(title_lbl)
        hl.addStretch()
        outer.addWidget(header)

        # ── Scroll area for form ───────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {COLOR_BACKGROUND}; }}")
        content = QWidget()
        scroll.setWidget(content)
        form = QVBoxLayout(content)
        form.setContentsMargins(20, 14, 20, 14)
        form.setSpacing(8)
        outer.addWidget(scroll, 1)

        # ── Row 1: Title ──────────────────────────────────────────────────
        form.addWidget(_sec_label("Title"))
        self._title = QLineEdit()
        self._title.setPlaceholderText("Short, descriptive bug title…")
        form.addWidget(self._title)

        # ── Row 2: Severity / Status / CVSS ──────────────────────────────
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        sev_col = QVBoxLayout()
        sev_col.addWidget(_sec_label("Severity"))
        self._severity = QComboBox()
        self._severity.addItems(SEVERITY_ORDER)
        sev_col.addWidget(self._severity)
        row2.addLayout(sev_col)

        stat_col = QVBoxLayout()
        stat_col.addWidget(_sec_label("Status"))
        self._status = QComboBox()
        self._status.addItems(STATUS_OPTIONS)
        stat_col.addWidget(self._status)
        row2.addLayout(stat_col)

        cvss_col = QVBoxLayout()
        cvss_col.addWidget(_sec_label("CVSS Score"))
        self._cvss = QLineEdit()
        self._cvss.setPlaceholderText("e.g. 8.5")
        self._cvss.setMaximumWidth(120)
        cvss_col.addWidget(self._cvss)
        row2.addLayout(cvss_col)

        row2.addStretch()
        form.addLayout(row2)

        # ── Row 3: Method / Target URL / Parameter ─────────────────────────
        row3 = QHBoxLayout()
        row3.setSpacing(12)

        meth_col = QVBoxLayout()
        meth_col.addWidget(_sec_label("Method"))
        self._method = QComboBox()
        self._method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "OTHER"])
        self._method.setFixedWidth(110)
        meth_col.addWidget(self._method)
        row3.addLayout(meth_col)

        url_col = QVBoxLayout()
        url_col.addWidget(_sec_label("Target URL"))
        self._url = QLineEdit()
        self._url.setPlaceholderText("https://target.com/api/endpoint")
        url_col.addWidget(self._url)
        row3.addLayout(url_col, 3)

        par_col = QVBoxLayout()
        par_col.addWidget(_sec_label("Parameter"))
        self._parameter = QLineEdit()
        self._parameter.setPlaceholderText("e.g. id, token, file")
        par_col.addWidget(self._parameter)
        row3.addLayout(par_col, 1)

        form.addLayout(row3)

        # ── Endpoint description ──────────────────────────────────────────
        form.addWidget(_sec_label("Endpoint / Functionality"))
        self._endpoint = QLineEdit()
        self._endpoint.setPlaceholderText("Brief description of the endpoint (e.g. 'User profile update')")
        form.addWidget(self._endpoint)

        # ── Description ───────────────────────────────────────────────────
        form.addWidget(_sec_label("Vulnerability Description"))
        self._description = QTextEdit()
        self._description.setPlaceholderText("Describe the vulnerability in detail…")
        self._description.setFixedHeight(90)
        form.addWidget(self._description)

        # ── Steps to Reproduce ────────────────────────────────────────────
        form.addWidget(_sec_label("Steps to Reproduce"))
        self._steps = QTextEdit()
        self._steps.setPlaceholderText("1. Log in as a normal user\n2. Navigate to…\n3. Observe…")
        self._steps.setFixedHeight(110)
        form.addWidget(self._steps)

        # ── PoC ───────────────────────────────────────────────────────────
        form.addWidget(_sec_label("Proof of Concept (Payload / Request / Notes)"))
        self._poc = QTextEdit()
        self._poc.setPlaceholderText("Paste the PoC payload, HTTP request, or attach screenshot notes here…")
        self._poc.setFixedHeight(110)
        self._poc.setStyleSheet(
            f"font-family: Consolas, monospace; font-size: 12px; "
            f"background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; padding: 6px;"
        )
        form.addWidget(self._poc)

        # ── Impact ────────────────────────────────────────────────────────
        form.addWidget(_sec_label("Impact"))
        self._impact = QTextEdit()
        self._impact.setPlaceholderText("What can an attacker achieve? What data/systems are at risk?")
        self._impact.setFixedHeight(80)
        form.addWidget(self._impact)

        # ── Remediation ───────────────────────────────────────────────────
        form.addWidget(_sec_label("Remediation Recommendation"))
        self._remediation = QTextEdit()
        self._remediation.setPlaceholderText("How should the developer fix this vulnerability?")
        self._remediation.setFixedHeight(80)
        form.addWidget(self._remediation)

        # ── Button bar ────────────────────────────────────────────────────
        btn_bar = QWidget()
        btn_bar.setFixedHeight(56)
        btn_bar.setStyleSheet(f"background: {COLOR_ELEVATED_BG}; border-top: 1px solid {COLOR_BORDER};")
        bl = QHBoxLayout(btn_bar)
        bl.setContentsMargins(18, 8, 18, 8)
        bl.setSpacing(10)

        self._save_btn = _btn("  Save Report", COLOR_ACCENT)
        self._save_btn.clicked.connect(self._on_save)
        bl.addWidget(self._save_btn)

        cancel_btn = _btn("Cancel", COLOR_ELEVATED_BG)
        cancel_btn.setStyleSheet(
            f"QPushButton {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
            f"padding: 5px 14px; font-size: 12px; }}"
            f"QPushButton:hover {{ background: {COLOR_HOVER}; }}"
        )
        cancel_btn.clicked.connect(self.reject)
        bl.addWidget(cancel_btn)

        # AI Draft button — always visible; warns if not configured
        self._ai_btn = _btn("  AI Draft", "#5a3ea8", "#7050c8")
        self._ai_btn.setToolTip("Generate Description, Steps, Impact & Remediation with AI")
        self._ai_btn.clicked.connect(self._on_ai_draft)
        bl.addWidget(self._ai_btn)

        bl.addStretch()

        outer.addWidget(btn_bar)

    def _load_fields(self):
        r = self._report
        self._title.setText(r.get("title", ""))
        self._severity.setCurrentText(r.get("severity", "High"))
        self._status.setCurrentText(r.get("status", "Draft"))
        self._cvss.setText(r.get("cvss", ""))
        self._method.setCurrentText(r.get("method", "GET"))
        self._url.setText(r.get("url", ""))
        self._parameter.setText(r.get("parameter", ""))
        self._endpoint.setText(r.get("endpoint", ""))
        self._description.setPlainText(r.get("description", ""))
        self._steps.setPlainText(r.get("steps", "1. \n2. \n3. "))
        self._poc.setPlainText(r.get("poc", ""))
        self._impact.setPlainText(r.get("impact", ""))
        self._remediation.setPlainText(r.get("remediation", ""))

    def _collect_fields(self) -> Dict:
        r = dict(self._report)
        r["title"]       = self._title.text().strip()
        r["severity"]    = self._severity.currentText()
        r["status"]      = self._status.currentText()
        r["cvss"]        = self._cvss.text().strip()
        r["method"]      = self._method.currentText()
        r["url"]         = self._url.text().strip()
        r["parameter"]   = self._parameter.text().strip()
        r["endpoint"]    = self._endpoint.text().strip()
        r["description"] = self._description.toPlainText().strip()
        r["steps"]       = self._steps.toPlainText()
        r["poc"]         = self._poc.toPlainText()
        r["impact"]      = self._impact.toPlainText().strip()
        r["remediation"] = self._remediation.toPlainText().strip()
        r["updated"]     = _now()
        return r

    def _on_save(self):
        if not self._title.text().strip():
            QMessageBox.warning(self, "Validation", "Title is required.")
            return
        self._report = self._collect_fields()
        self.accept()

    def _on_ai_draft(self):
        """Open the AI draft dialog and apply generated fields on success."""
        settings = self._settings
        provider = settings.get("ai_provider", "")
        api_key  = settings.get("ai_api_key",  "")

        if not provider:
            QMessageBox.information(
                self, "AI Not Configured",
                "Configure your AI provider in:\n  Edit → Tool Settings → AI Settings"
            )
            return

        if provider in ("openai", "anthropic") and not api_key:
            QMessageBox.warning(
                self, "API Key Missing",
                f"An API key is required for {provider}.\n"
                "Add it in Edit → Tool Settings → AI Settings."
            )
            return

        # Pass current form values as context for the prompt
        partial = self._collect_fields()
        dlg = AIReportDraftDialog(settings, partial, self)
        if dlg.exec_() == QDialog.Accepted and dlg.fields:
            self._apply_ai_fields(dlg.fields)

    def _apply_ai_fields(self, fields: dict):
        """Fill the Description, Steps, Impact, and Remediation fields from AI output."""
        if fields.get("description"):
            self._description.setPlainText(fields["description"])
        if fields.get("steps"):
            self._steps.setPlainText(fields["steps"])
        if fields.get("impact"):
            self._impact.setPlainText(fields["impact"])
        if fields.get("remediation"):
            self._remediation.setPlainText(fields["remediation"])

    def get_report(self) -> Dict:
        return self._report


# ── Main Report Tab ───────────────────────────────────────────────────────────

class ReportTab(QWidget):
    """Bug report manager tab — create, edit, export confirmed findings."""

    def __init__(self, parent_gui, parent=None):
        super().__init__(parent)
        self.parent_gui   = parent_gui
        self._project_dir: Optional[str] = None
        self._reports:     List[Dict]    = []
        self._init_ui()
        self._apply_style()

    # ── Public API ────────────────────────────────────────────────────────

    def set_project_dir(self, project_dir: str):
        self._project_dir = project_dir
        self._refresh()

    def add_from_finding(self, finding: Dict):
        """Pre-populate a new report from an HTTP finding / attack-surface entry."""
        report = {
            "id":          str(uuid.uuid4()),
            "title":       finding.get("title", ""),
            "severity":    finding.get("severity", finding.get("risk", "High")),
            "status":      "Draft",
            "cvss":        finding.get("cvss", ""),
            "method":      finding.get("method", "GET"),
            "url":         finding.get("url", ""),
            "parameter":   finding.get("parameter", finding.get("param", "")),
            "endpoint":    "",
            "description": finding.get("description", finding.get("notes", "")),
            "steps":       "1. \n2. \n3. ",
            "poc":         finding.get("poc", ""),
            "impact":      finding.get("impact", ""),
            "remediation": finding.get("remediation", ""),
            "created":     _now(),
            "updated":     _now(),
        }
        dlg = ReportEditDialog(report, self, settings=self._ai_settings())
        if dlg.exec_() == QDialog.Accepted and self._project_dir:
            saved = dlg.get_report()
            ReportStore.save(self._project_dir, saved)
            self._refresh()
            self._navigate_to_attack_surface()  # stay in Reports after save

    # ── UI construction ────────────────────────────────────────────────────

    def _init_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Stats / header bar ─────────────────────────────────────────────
        self._stats_bar = QLabel("  No project loaded")
        self._stats_bar.setFixedHeight(38)
        root.addWidget(self._stats_bar)

        # ── Toolbar ───────────────────────────────────────────────────────
        root.addWidget(self._build_toolbar())

        # ── Main splitter: table | detail panel ───────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(4)
        splitter.setStyleSheet(f"QSplitter::handle {{ background: {COLOR_BORDER}; }}")

        # Left: reports table
        self._table = self._build_table()
        splitter.addWidget(self._table)

        # Right: read-only detail panel
        self._detail_panel = self._build_detail_panel()
        splitter.addWidget(self._detail_panel)

        splitter.setSizes([560, 500])
        splitter.setChildrenCollapsible(False)
        root.addWidget(splitter, 1)

    def _build_toolbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(46)
        bar.setStyleSheet(
            f"QWidget {{ background: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER}; }}"
        )
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(10, 5, 10, 5)
        bl.setSpacing(8)

        new_btn = _btn("➕  New Report", COLOR_ACCENT)
        new_btn.setToolTip("Create a new bug report")
        new_btn.clicked.connect(self._on_new)
        bl.addWidget(new_btn)

        edit_btn = _btn("  Edit", "#4a6a8a")
        edit_btn.setToolTip("Edit the selected report")
        edit_btn.clicked.connect(self._on_edit)
        bl.addWidget(edit_btn)

        dup_btn = _btn("  Duplicate", "#4a6a8a")
        dup_btn.setToolTip("Duplicate selected report")
        dup_btn.clicked.connect(self._on_duplicate)
        bl.addWidget(dup_btn)

        sep = QFrame()
        sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color: {COLOR_BORDER}; max-width: 1px;")
        bl.addWidget(sep)

        export_md   = _btn("⬇  Export MD",   "#5a3ea8")
        export_txt  = _btn("⬇  Export TXT",  "#5a3ea8")
        export_all  = _btn("⬇  Export All",  "#5a3ea8")
        export_md.setToolTip("Export selected report as Markdown")
        export_txt.setToolTip("Export selected report as plain text")
        export_all.setToolTip("Export all reports as Markdown files")
        export_md.clicked.connect(lambda: self._export_selected("md"))
        export_txt.clicked.connect(lambda: self._export_selected("txt"))
        export_all.clicked.connect(self._export_all)
        for b in (export_md, export_txt, export_all):
            bl.addWidget(b)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"color: {COLOR_BORDER}; max-width: 1px;")
        bl.addWidget(sep2)

        # Severity filter
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All Severities"] + SEVERITY_ORDER)
        self._sev_filter.setFixedWidth(140)
        self._sev_filter.setStyleSheet(
            f"QComboBox {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; padding: 3px 8px; font-size: 12px; }}"
            f"QComboBox QAbstractItemView {{ background: {COLOR_CARD_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"selection-background-color: {COLOR_ACCENT}; }}"
        )
        self._sev_filter.currentIndexChanged.connect(self._apply_filters)
        bl.addWidget(self._sev_filter)

        # Status filter
        self._stat_filter = QComboBox()
        self._stat_filter.addItems(["All Statuses"] + STATUS_OPTIONS)
        self._stat_filter.setFixedWidth(140)
        self._stat_filter.setStyleSheet(self._sev_filter.styleSheet())
        self._stat_filter.currentIndexChanged.connect(self._apply_filters)
        bl.addWidget(self._stat_filter)

        # Search
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Search reports…")
        self._search.setFixedWidth(220)
        self._search.setStyleSheet(
            f"QLineEdit {{ background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; padding: 4px 10px; font-size: 12px; }}"
            f"QLineEdit:focus {{ border-color: {COLOR_ACCENT}; }}"
        )
        self._search.textChanged.connect(self._apply_filters)
        bl.addWidget(self._search)

        bl.addStretch()

        del_btn = _btn("🗑  Delete", COLOR_CRITICAL, "#cc3333")
        del_btn.setToolTip("Delete selected report")
        del_btn.clicked.connect(self._on_delete)
        bl.addWidget(del_btn)

        return bar

    def _build_table(self) -> QTableWidget:
        t = QTableWidget()
        t.setColumnCount(len(_COLUMNS))
        t.setHorizontalHeaderLabels(_COLUMNS)
        t.setAlternatingRowColors(True)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setContextMenuPolicy(Qt.CustomContextMenu)
        t.customContextMenuRequested.connect(self._context_menu)
        t.doubleClicked.connect(self._on_edit)
        t.setSortingEnabled(True)
        t.verticalHeader().setDefaultSectionSize(30)
        t.verticalHeader().hide()

        hh = t.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.Interactive)
        hh.setStretchLastSection(False)
        t.setColumnWidth(COL_SEV,   70)
        t.setColumnWidth(COL_TITLE, 260)
        t.setColumnWidth(COL_URL,   220)
        t.setColumnWidth(COL_PARAM, 120)
        t.setColumnWidth(COL_STAT,  100)
        t.setColumnWidth(COL_DATE,  150)
        hh.setSectionResizeMode(COL_TITLE, QHeaderView.Stretch)

        t.itemSelectionChanged.connect(lambda: self._on_row_changed(self._table.currentRow()))
        return t

    def _build_detail_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(340)
        panel.setStyleSheet(
            f"QWidget {{ background: {COLOR_CARD_BG}; border-left: 1px solid {COLOR_BORDER}; }}"
        )
        pv = QVBoxLayout(panel)
        pv.setContentsMargins(0, 0, 0, 0)
        pv.setSpacing(0)

        # Header
        hdr = QLabel("  Report Details")
        hdr.setFixedHeight(38)
        hdr.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-weight: bold; font-size: 13px; "
            f"background: {COLOR_ELEVATED_BG}; border-bottom: 1px solid {COLOR_BORDER}; "
            f"padding-left: 14px;"
        )
        pv.addWidget(hdr)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"QScrollArea {{ border: none; background: {COLOR_CARD_BG}; }}")
        self._detail_content = QWidget()
        self._detail_content.setStyleSheet(f"background: {COLOR_CARD_BG};")
        self._detail_layout = QVBoxLayout(self._detail_content)
        self._detail_layout.setContentsMargins(14, 10, 14, 14)
        self._detail_layout.setSpacing(6)
        self._detail_layout.addStretch()
        scroll.setWidget(self._detail_content)
        pv.addWidget(scroll, 1)

        # Quick-action buttons at bottom of detail panel
        qa_bar = QWidget()
        qa_bar.setFixedHeight(46)
        qa_bar.setStyleSheet(
            f"background: {COLOR_ELEVATED_BG}; border-top: 1px solid {COLOR_BORDER};"
        )
        ql = QHBoxLayout(qa_bar)
        ql.setContentsMargins(10, 5, 10, 5)
        ql.setSpacing(8)

        quick_edit = _btn("✏️ Edit", "#4a6a8a")
        quick_edit.clicked.connect(self._on_edit)
        ql.addWidget(quick_edit)

        quick_md = _btn("⬇️ MD", "#5a3ea8")
        quick_md.clicked.connect(lambda: self._export_selected("md"))
        ql.addWidget(quick_md)

        self._copy_md_btn = _btn(" Copy as MD", "#5a3ea8")
        self._copy_md_btn.setToolTip("Copy report as Markdown to clipboard")
        self._copy_md_btn.clicked.connect(self._copy_as_md)
        ql.addWidget(self._copy_md_btn)

        ql.addStretch()

        pv.addWidget(qa_bar)
        return panel

    def _apply_style(self):
        self.setStyleSheet(f"""
            QWidget {{ background: {COLOR_BACKGROUND}; color: {COLOR_TEXT}; }}
        """)
        self._stats_bar.setStyleSheet(f"""
            QLabel {{
                background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_MUTED};
                font-size: 12px; padding: 0 14px;
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background: {COLOR_DARK_BG};
                alternate-background-color: {COLOR_CARD_BG};
                gridline-color: {COLOR_BORDER};
                border: none; color: {COLOR_TEXT}; font-size: 12px;
                selection-background-color: #2a4a6b;
                selection-color: {COLOR_TEXT_BRIGHT};
                outline: none;
            }}
            QTableWidget::item {{ padding: 4px 8px; border: none; }}
            QTableWidget::item:hover {{ background: {COLOR_HOVER}; }}
            QTableWidget::item:selected,
            QTableWidget::item:selected:active,
            QTableWidget::item:selected:!active {{
                background: #2a4a6b; color: {COLOR_TEXT_BRIGHT};
            }}
            QHeaderView::section {{
                background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT_BRIGHT};
                padding: 5px 8px; border: 1px solid {COLOR_BORDER};
                border-left: none; border-top: none;
                font-weight: bold; font-size: 12px;
            }}
            QHeaderView::section:first {{ border-left: 1px solid {COLOR_BORDER}; }}
        """)

    # ── Data operations ────────────────────────────────────────────────────

    def _refresh(self):
        if not self._project_dir:
            return
        self._reports = ReportStore.load_all(self._project_dir)
        self._populate_table(self._reports)
        self._update_stats()

    def _populate_table(self, reports: List[Dict]):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)
        self._table.setRowCount(len(reports))

        for row, r in enumerate(reports):
            sev   = r.get("severity", "Info")
            color = SEVERITY_COLORS.get(sev, COLOR_TEXT_MUTED)

            sev_item = QTableWidgetItem(sev)
            sev_item.setForeground(QColor(color))
            sev_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            sev_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)
            sev_item.setData(Qt.UserRole, r)

            title_item = QTableWidgetItem(r.get("title", ""))
            title_item.setForeground(QColor(COLOR_TEXT_BRIGHT))

            url_item = QTableWidgetItem(r.get("url", ""))
            url_item.setForeground(QColor(COLOR_TEXT_MUTED))

            param_item = QTableWidgetItem(r.get("parameter", ""))
            param_item.setForeground(QColor(COLOR_ACCENT))

            stat = r.get("status", "Draft")
            stat_item = QTableWidgetItem(stat)
            stat_item.setForeground(QColor(STATUS_COLORS.get(stat, COLOR_TEXT_MUTED)))
            stat_item.setFont(QFont("Segoe UI", 10, QFont.Bold))
            stat_item.setTextAlignment(Qt.AlignCenter | Qt.AlignVCenter)

            date_item = QTableWidgetItem(r.get("created", "")[:19])
            date_item.setForeground(QColor(COLOR_TEXT_MUTED))

            self._table.setItem(row, COL_SEV,   sev_item)
            self._table.setItem(row, COL_TITLE, title_item)
            self._table.setItem(row, COL_URL,   url_item)
            self._table.setItem(row, COL_PARAM, param_item)
            self._table.setItem(row, COL_STAT,  stat_item)
            self._table.setItem(row, COL_DATE,  date_item)

        self._table.setSortingEnabled(True)

    def _apply_filters(self):
        sev_filter  = self._sev_filter.currentText()
        stat_filter = self._stat_filter.currentText()
        q = self._search.text().lower()

        filtered = []
        for r in self._reports:
            if sev_filter != "All Severities" and r.get("severity") != sev_filter:
                continue
            if stat_filter != "All Statuses" and r.get("status") != stat_filter:
                continue
            if q and q not in (r.get("title", "") + r.get("url", "") +
                               r.get("parameter", "") + r.get("description", "")).lower():
                continue
            filtered.append(r)

        self._populate_table(filtered)

    def _update_stats(self):
        total = len(self._reports)
        by_sev = {}
        for r in self._reports:
            s = r.get("severity", "Info")
            by_sev[s] = by_sev.get(s, 0) + 1

        parts = []
        for s in ("Critical", "High", "Medium", "Low"):
            n = by_sev.get(s, 0)
            if n:
                color = SEVERITY_COLORS.get(s, COLOR_TEXT)
                parts.append(f'<span style="color:{color};font-weight:bold;">{s}: {n}</span>')

        accepted = sum(1 for r in self._reports if r.get("status") == "Accepted")
        submitted = sum(1 for r in self._reports if r.get("status") == "Submitted")

        txt = (
            f"  📋 {total} Reports  ·  "
            f"{'  ·  '.join(parts) if parts else '—'}  ·  "
            f"<span style='color:{COLOR_SUCCESS};'>Accepted: {accepted}</span>  ·  "
            f"Submitted: {submitted}"
        )
        self._stats_bar.setText(txt)
        self._stats_bar.setTextFormat(Qt.RichText)

    # ── Table row selection → detail panel ────────────────────────────────

    def _on_row_changed(self, row: int):
        report = self._get_report_at(row)
        self._render_detail(report)

    def _get_report_at(self, row: int) -> Optional[Dict]:
        if row < 0 or row >= self._table.rowCount():
            return None
        item = self._table.item(row, COL_SEV)
        return item.data(Qt.UserRole) if item else None

    def _render_detail(self, report: Optional[Dict]):
        # Clear existing widgets
        while self._detail_layout.count():
            item = self._detail_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not report:
            lbl = QLabel("Select a report to view details")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 13px; padding: 40px;")
            self._detail_layout.addWidget(lbl)
            self._detail_layout.addStretch()
            return

        def _row(label: str, value: str, mono: bool = False):
            w = QWidget()
            w.setStyleSheet(f"background: {COLOR_CARD_BG};")
            rl = QVBoxLayout(w)
            rl.setContentsMargins(0, 4, 0, 4)
            rl.setSpacing(2)
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: 10px; font-weight: bold; "
                f"text-transform: uppercase; letter-spacing: 1px;"
            )
            val = QLabel(value or "—")
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextSelectableByMouse)
            style = f"color: {COLOR_TEXT_BRIGHT}; font-size: 12px;"
            if mono:
                style += f" font-family: Consolas, monospace;"
            val.setStyleSheet(style)
            rl.addWidget(lbl)
            rl.addWidget(val)
            return w

        def _divider():
            f = QFrame()
            f.setFrameShape(QFrame.HLine)
            f.setStyleSheet(f"color: {COLOR_BORDER};")
            return f

        def _text_block(label: str, text: str, mono: bool = False):
            if not text:
                return None
            w = QWidget()
            w.setStyleSheet(f"background: {COLOR_CARD_BG};")
            wl = QVBoxLayout(w)
            wl.setContentsMargins(0, 6, 0, 6)
            wl.setSpacing(4)
            lbl = QLabel(label)
            lbl.setStyleSheet(
                f"color: {COLOR_TEXT_MUTED}; font-size: 10px; font-weight: bold; "
                f"text-transform: uppercase; letter-spacing: 1px;"
            )
            txt = QTextEdit()
            txt.setPlainText(text)
            txt.setReadOnly(True)
            txt.setMaximumHeight(120)
            base = (
                f"background: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; "
                f"border: 1px solid {COLOR_BORDER}; border-radius: 4px; "
                f"padding: 6px; font-size: 12px;"
            )
            if mono:
                base += " font-family: Consolas, monospace;"
            txt.setStyleSheet(base)
            wl.addWidget(lbl)
            wl.addWidget(txt)
            return w

        sev   = report.get("severity", "Info")
        stat  = report.get("status", "Draft")
        scol  = SEVERITY_COLORS.get(sev, COLOR_TEXT)
        stcol = STATUS_COLORS.get(stat, COLOR_TEXT_MUTED)

        # Title
        title_lbl = QLabel(report.get("title", "Untitled"))
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT}; font-size: 15px; font-weight: bold; padding: 6px 0;"
        )
        self._detail_layout.addWidget(title_lbl)

        # Severity + status badges
        badge_row = QHBoxLayout()
        badge_row.setSpacing(8)
        sev_badge = QLabel(f"  {sev}  ")
        sev_badge.setStyleSheet(
            f"background: transparent; color: {scol}; font-weight: bold; "
            f"border: 1px solid {scol}; border-radius: 10px; padding: 2px 8px; font-size: 11px;"
        )
        stat_badge = QLabel(f"  {stat}  ")
        stat_badge.setStyleSheet(
            f"background: transparent; color: {stcol}; font-weight: bold; "
            f"border: 1px solid {stcol}; border-radius: 10px; padding: 2px 8px; font-size: 11px;"
        )
        cvss = report.get("cvss", "")
        if cvss:
            cvss_badge = QLabel(f"  CVSS: {cvss}  ")
            cvss_badge.setStyleSheet(
                f"background: transparent; color: {COLOR_TEXT_MUTED}; "
                f"border: 1px solid {COLOR_BORDER}; border-radius: 10px; "
                f"padding: 2px 8px; font-size: 11px;"
            )
            badge_row.addWidget(cvss_badge)
        badge_row.addWidget(sev_badge)
        badge_row.addWidget(stat_badge)
        badge_row.addStretch()
        self._detail_layout.addLayout(badge_row)

        self._detail_layout.addWidget(_divider())
        self._detail_layout.addWidget(_row("Method", report.get("method", "")))
        self._detail_layout.addWidget(_row("Target URL", report.get("url", ""), mono=True))
        self._detail_layout.addWidget(_row("Parameter", report.get("parameter", "")))
        self._detail_layout.addWidget(_row("Endpoint", report.get("endpoint", "")))
        self._detail_layout.addWidget(_divider())

        for label, key, mono in [
            ("Description",    "description",  False),
            ("Steps to Reproduce", "steps",    False),
            ("Proof of Concept",   "poc",       True),
            ("Impact",         "impact",        False),
            ("Remediation",    "remediation",   False),
        ]:
            w = _text_block(label, report.get(key, ""), mono=mono)
            if w:
                self._detail_layout.addWidget(w)

        # Dates
        self._detail_layout.addWidget(_divider())
        self._detail_layout.addWidget(
            _row("Created", report.get("created", "")[:19])
        )
        self._detail_layout.addWidget(
            _row("Last Updated", report.get("updated", "")[:19])
        )
        self._detail_layout.addStretch()

    # ── CRUD actions ──────────────────────────────────────────────────────

    def _ai_settings(self) -> dict:
        """Return global AI settings from the parent GUI, falling back gracefully."""
        pg = getattr(self, "parent_gui", None)
        if pg and hasattr(pg, "_global_settings"):
            return pg._global_settings
        # Fallback: load directly from config file
        try:
            from ..main import _load_global_settings
            return _load_global_settings()
        except Exception:
            return {}

    def _on_new(self):
        dlg = ReportEditDialog(parent=self, settings=self._ai_settings())
        if dlg.exec_() == QDialog.Accepted and self._project_dir:
            ReportStore.save(self._project_dir, dlg.get_report())
            self._refresh()

    def _on_edit(self):
        row     = self._table.currentRow()
        report  = self._get_report_at(row)
        if not report:
            QMessageBox.information(self, "No Selection", "Select a report to edit.")
            return
        dlg = ReportEditDialog(report, self, settings=self._ai_settings())
        if dlg.exec_() == QDialog.Accepted and self._project_dir:
            ReportStore.save(self._project_dir, dlg.get_report())
            self._refresh()

    def _on_duplicate(self):
        row    = self._table.currentRow()
        report = self._get_report_at(row if row >= 0 else self._table.currentRow())
        if not report:
            return
        import copy
        copy_r = copy.deepcopy(report)
        copy_r["id"]      = str(uuid.uuid4())
        copy_r["title"]   = report.get("title", "") + " (copy)"
        copy_r["status"]  = "Draft"
        copy_r["created"] = _now()
        copy_r["updated"] = _now()
        if self._project_dir:
            ReportStore.save(self._project_dir, copy_r)
            self._refresh()

    def _on_delete(self):
        row    = self._table.currentRow()
        report = self._get_report_at(row)
        if not report:
            return
        reply = QMessageBox.question(
            self, "Delete Report",
            f"Delete report:\n{report.get('title', '')}\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        )
        if reply == QMessageBox.Yes and self._project_dir:
            ReportStore.delete(self._project_dir, report["id"])
            self._refresh()

    # ── Export ────────────────────────────────────────────────────────────

    def _export_selected(self, fmt: str):
        row    = self._table.currentRow()
        report = self._get_report_at(row)
        if not report:
            QMessageBox.information(self, "No Selection", "Select a report to export.")
            return
        ext   = "md" if fmt == "md" else "txt"
        name  = report.get("title", "report").replace(" ", "_").replace("/", "_")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report", f"{name}.{ext}",
            f"{'Markdown (*.md)' if fmt == 'md' else 'Text (*.txt)'}"
        )
        if not path:
            return
        content = _to_markdown(report) if fmt == "md" else _to_text(report)
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            QMessageBox.information(self, "Exported", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "Export Error", str(e))

    def _export_all(self):
        if not self._reports:
            QMessageBox.information(self, "No Reports", "No reports to export.")
            return
        folder = QFileDialog.getExistingDirectory(self, "Select Export Folder")
        if not folder:
            return
        count = 0
        for r in self._reports:
            name = r.get("title", r["id"]).replace(" ", "_").replace("/", "_")[:60]
            path = os.path.join(folder, f"{name}.md")
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_to_markdown(r))
                count += 1
            except Exception:
                pass
        QMessageBox.information(self, "Export Complete", f"Exported {count} reports to:\n{folder}")

    def _copy_as_md(self):
        row    = self._table.currentRow()
        report = self._get_report_at(row)
        if not report:
            QMessageBox.information(self, "No Selection", "Select a report to copy.")
            return
        QApplication.clipboard().setText(_to_markdown(report))
        btn = self._copy_md_btn
        btn.setText(" Copied!")
        btn.setStyleSheet(
            f"QPushButton {{ background: #2d6a2d; color: #ffffff; "
            f"border: none; border-radius: 4px; "
            f"padding: 5px 14px; font-weight: bold; font-size: 12px; }}"
        )
        QTimer.singleShot(2000, lambda: (
            btn.setText(" Copy as MD"),
            btn.setStyleSheet(
                f"QPushButton {{ background: #5a3ea8; color: #ffffff; "
                f"border: none; border-radius: 4px; "
                f"padding: 5px 14px; font-weight: bold; font-size: 12px; }}"
                f"QPushButton:hover {{ background: #5a3ea8; }}"
            ),
        ))

    # ── Context menu ──────────────────────────────────────────────────────

    def _context_menu(self, pos):
        row    = self._table.rowAt(pos.y())
        report = self._get_report_at(row)
        if not report:
            return

        menu = QMenu(self)
        menu.setStyleSheet(f"""
            QMenu {{ background: {COLOR_CARD_BG}; color: {COLOR_TEXT};
                    border: 1px solid {COLOR_BORDER}; padding: 4px; }}
            QMenu::item {{ padding: 6px 18px; border-radius: 3px; }}
            QMenu::item:selected {{ background: {COLOR_ACCENT}; color: #fff; }}
            QMenu::separator {{ height: 1px; background: {COLOR_BORDER}; margin: 4px 0; }}
        """)

        menu.addAction("✏️  Edit Report").triggered.connect(self._on_edit)
        menu.addAction("📋  Duplicate").triggered.connect(self._on_duplicate)

        # Quick status change submenu
        status_menu = menu.addMenu("⚡  Set Status")
        status_menu.setStyleSheet(menu.styleSheet())
        for s in STATUS_OPTIONS:
            act = status_menu.addAction(s)
            act.triggered.connect(lambda _, st=s, rpt=report: self._set_status(rpt, st))

        menu.addSeparator()
        menu.addAction("⬇️  Export as Markdown").triggered.connect(lambda: self._export_selected("md"))
        menu.addAction("⬇️  Export as Text").triggered.connect(lambda: self._export_selected("txt"))
        menu.addAction("📋  Copy URL").triggered.connect(
            lambda: QApplication.clipboard().setText(report.get("url", ""))
        )
        menu.addSeparator()
        menu.addAction("🗑  Delete").triggered.connect(self._on_delete)

        menu.exec_(self._table.viewport().mapToGlobal(pos))

    def _set_status(self, report: Dict, status: str):
        report["status"]  = status
        report["updated"] = _now()
        if self._project_dir:
            ReportStore.save(self._project_dir, report)
            self._refresh()

    def _navigate_to_attack_surface(self):
        """Keep focus on the Reports tab after saving via add_from_finding."""
        mw = self.parent_gui
        if hasattr(mw, "tab_widget"):
            for i in range(mw.tab_widget.count()):
                if "Report" in mw.tab_widget.tabText(i):
                    mw.tab_widget.setCurrentIndex(i)
                    break
