"""
analysis_recordings.py
──────────────────────
Persistent storage layer for Analysis Tab detections.

Every time the Analysis tab finishes analysing a request it calls
``RecordingManager.save_finding(project_dir, finding, analysis_results)``.
Results are grouped into *categories* (Reflected, SQLi, XSS, SSRF, LFI,
Secrets, CORS, Headers, Errors, Other) and written to a single JSON file:

    <project_dir>/analysis_recordings.json

The Recorded sub-tab in Attack Surface reads this file and displays the
data in a professional, filterable table.
"""

from __future__ import annotations

import json
import os
import re
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── File name ─────────────────────────────────────────────────────────────────
RECORDINGS_FILE = "analysis_recordings.json"

# ── Category definitions ───────────────────────────────────────────────────────
# Each entry maps (category_key) → (display_name, icon, priority)
CATEGORIES: Dict[str, tuple] = {
    "reflected":     ("Reflected Parameters",  "</>", 1),
    "xss":           ("XSS Candidates",        "⚡", 2),
    "sqli":          ("SQL Injection",          "⛏", 3),
    "ssrf":          ("SSRF",                   "🌐", 4),
    "lfi":           ("LFI / Path Traversal",  "🗁", 5),
    "idor":          ("IDOR Candidates",        "🞋", 6),
    "cors":          ("CORS Issues",            "🛈", 7),
    "secrets":       ("Secrets / API Keys",    "⚿", 8),
    "headers":       ("Security Headers",      "🛡", 9),
    "errors":        ("Error Disclosure",      "⚠", 10),
    "open_redirect": ("Open Redirect",         "⮌", 11),
    "csrf":          ("CSRF",                  "🤃", 12),
    "other":         ("Other Findings",        "🔍", 99),
}

# ── Keyword → category mapping ─────────────────────────────────────────────────
# Checked against the *vulnerabilities* column string of each param row.
_CATEGORY_RULES: List[tuple] = [
    # (regex_pattern, category_key)
    (r"\bREFLECTED\b",                                     "reflected"),
    (r"\bXSS\b|\bDOM_XSS\b|\bXSS_SINK\b",                "xss"),
    (r"\bSQLI\b|\bSQL_INJECT\b|\bSQL_ERROR\b",            "sqli"),
    (r"\bSSRF\b",                                         "ssrf"),
    (r"\bLFI\b|\bPATH_TRAVERSAL\b|\bRFI\b",              "lfi"),
    (r"\bIDOR\b|\bBOLA\b",                                "idor"),
    # CORS_ prefix covers CORS_INDICATOR, CORS_MISCONFIGURATION, etc.
    (r"CORS",                                             "cors"),
    (r"\bAPI_KEY\b|\bSECRET\b|\bTOKEN_LEAK\b|"
     r"\bAWS_KEY\b|\bGITHUB_TOKEN\b",                    "secrets"),
    # MISSING_ prefix + SECURITY_MISC prefix + DEBUG_HEADER + CLICKJACKING
    (r"MISSING_|SECURITY_MISC|\bDEBUG_HEADER\b|\bCLICKJACKING\b|\bHOST_HEADER\b",
                                                          "headers"),
    (r"\bSQL_ERROR\b|\bERROR_DISCLOS\b|"
     r"\bSTACK_TRACE\b|\bEXCEPTION\b",                   "errors"),
    (r"\bOPEN_REDIRECT\b|\bREDIRECT\b",                  "open_redirect"),
    (r"\bCSRF\b",                                         "csrf"),
]


# ══════════════════════════════════════════════════════════════════════════════
# Internal helpers
# ══════════════════════════════════════════════════════════════════════════════

def _classify(vuln_string: str) -> str:
    """Return the best category key for a vulnerability string."""
    upper = vuln_string.upper()
    for pattern, key in _CATEGORY_RULES:
        if re.search(pattern, upper):
            return key
    return "other"


def _severity_order(sev: str) -> int:
    """Lower = more severe."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev.upper(), 4)


def _extract_reflected_params(analysis_results: Dict) -> List[str]:
    """Return list of parameter names that are marked REFLECTED."""
    reflected = []
    for param_name, detections in analysis_results.get("params", {}).items():
        det_str = " ".join(str(d) for d in detections) if isinstance(detections, (list, set)) else str(detections)
        if "REFLECTED" in det_str.upper():
            # Strip location prefix (URL, BODY, JSON…)
            parts = param_name.split(" ", 1)
            reflected.append(parts[1] if len(parts) > 1 else param_name)
    return reflected


# ══════════════════════════════════════════════════════════════════════════════
# Public API
# ══════════════════════════════════════════════════════════════════════════════

class RecordingManager:
    """Static helpers for persisting/loading analysis recordings."""

    # ── Save ──────────────────────────────────────────────────────────────────

    @staticmethod
    def save_finding(
        project_dir: str,
        finding: Dict,
        analysis_results: Dict,
    ) -> bool:
        """
        Extract noteworthy detections from *analysis_results* and append them
        to the project's recordings file, grouped by category.

        Returns True on success.
        """
        if not project_dir:
            return False

        try:
            recordings = RecordingManager._load_raw(project_dir)

            url     = finding.get("url", "")
            method  = finding.get("method", "GET").upper()
            status  = str(finding.get("status", ""))
            host    = finding.get("host", urlparse(url).netloc)
            ts      = datetime.now().isoformat(timespec="seconds")
            severity_overall = analysis_results.get("severity", "LOW")

            # ── Iterate every detected parameter ──────────────────────────
            for param_full, detections in analysis_results.get("params", {}).items():
                det_str = (
                    " ".join(str(d) for d in detections)
                    if isinstance(detections, (list, set))
                    else str(detections)
                )

                # Skip boring INFO-only rows that have no real vulnerability flag.
                # Note: no trailing \b so CORS_INDICATOR, MISSING_X_FRAME_OPTIONS,
                # MISCONFIGURATION, CORS_INDICATOR etc. are all captured.
                if not re.search(
                    r"REFLECTED|\bXSS\b|SQLI|SQL_ERROR|\bSSRF\b|\bLFI\b|\bRFI\b|"
                    r"\bIDOR\b|CORS|API_KEY|\bSECRET\b|\bTOKEN\b|"
                    r"MISSING_|MISCONFIG|ERROR_DISCLOS|"
                    r"REDIRECT|\bCSRF\b|PATH_TRAVERSAL|\bRCE\b|COMMAND_INJ|"
                    r"DEBUG_HEADER|CLICKJACKING|HOST_HEADER|SUBDOMAIN_TAKEOVER",
                    det_str.upper()
                ):
                    continue

                category = _classify(det_str)

                # Determine individual severity
                if "CRITICAL" in det_str.upper():
                    sev = "CRITICAL"
                elif "HIGH" in det_str.upper() or any(
                    k in det_str.upper() for k in ["XSS", "SQLI", "RCE", "SSRF", "API_KEY"]
                ):
                    sev = "HIGH"
                elif "MEDIUM" in det_str.upper():
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

                # Parse location / param name
                parts = param_full.split(" ", 1)
                location = parts[0] if len(parts) > 1 else "UNKNOWN"
                param_name = parts[1] if len(parts) > 1 else param_full

                # Reflected params list
                reflected_params = _extract_reflected_params(analysis_results)

                entry = {
                    "id":         f"{ts}_{hash(url + param_full) & 0xFFFFFF:06x}",
                    "timestamp":  ts,
                    "url":        url,
                    "host":       host,
                    "method":     method,
                    "status":     status,
                    "severity":   sev,
                    "category":   category,
                    "location":   location,
                    "parameter":  param_name,
                    "detections": det_str,
                    "reflected_params": reflected_params,
                    "overall_severity": severity_overall,
                }

                # Avoid duplicate (same url + param + category already recorded today)
                bucket = recordings.setdefault(category, [])
                dup = any(
                    e.get("url") == url
                    and e.get("parameter") == param_name
                    and e.get("category") == category
                    for e in bucket
                )
                if not dup:
                    bucket.append(entry)

            RecordingManager._save_raw(project_dir, recordings)
            return True

        except Exception as exc:
            logger.error(f"RecordingManager.save_finding error: {exc}", exc_info=True)
            return False

    # ── Load ──────────────────────────────────────────────────────────────────

    @staticmethod
    def load(project_dir: str) -> Dict[str, List[Dict]]:
        """
        Return the full recordings dict  { category_key: [entry, …] }.
        Returns empty dict on any error.
        """
        try:
            return RecordingManager._load_raw(project_dir)
        except Exception as exc:
            logger.error(f"RecordingManager.load error: {exc}")
            return {}

    @staticmethod
    def get_stats(project_dir: str) -> Dict:
        """Return quick summary statistics."""
        data = RecordingManager.load(project_dir)
        total = sum(len(v) for v in data.values())
        by_sev: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for entries in data.values():
            for e in entries:
                sev = e.get("severity", "LOW").upper()
                by_sev[sev] = by_sev.get(sev, 0) + 1
        return {
            "total":      total,
            "categories": len(data),
            "by_severity": by_sev,
            "by_category": {k: len(v) for k, v in data.items()},
        }

    @staticmethod
    def delete_entry(project_dir: str, category: str, entry_id: str) -> bool:
        """Delete a single entry by id."""
        try:
            data = RecordingManager._load_raw(project_dir)
            if category in data:
                data[category] = [e for e in data[category] if e.get("id") != entry_id]
                RecordingManager._save_raw(project_dir, data)
            return True
        except Exception as exc:
            logger.error(f"RecordingManager.delete_entry error: {exc}")
            return False

    @staticmethod
    def clear_category(project_dir: str, category: str) -> bool:
        """Clear all entries in a category."""
        try:
            data = RecordingManager._load_raw(project_dir)
            data[category] = []
            RecordingManager._save_raw(project_dir, data)
            return True
        except Exception as exc:
            logger.error(f"RecordingManager.clear_category error: {exc}")
            return False

    @staticmethod
    def clear_all(project_dir: str) -> bool:
        """Clear all recordings."""
        try:
            RecordingManager._save_raw(project_dir, {})
            return True
        except Exception as exc:
            logger.error(f"RecordingManager.clear_all error: {exc}")
            return False

    # ── Private I/O ───────────────────────────────────────────────────────────

    @staticmethod
    def _recordings_path(project_dir: str) -> str:
        return os.path.join(project_dir, RECORDINGS_FILE)

    @staticmethod
    def _load_raw(project_dir: str) -> Dict:
        path = RecordingManager._recordings_path(project_dir)
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def _save_raw(project_dir: str, data: Dict):
        path = RecordingManager._recordings_path(project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)