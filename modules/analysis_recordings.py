"""
analysis_recordings.py
──────────────────────
Persistent storage layer for Analysis Tab detections.

Every time the Analysis tab finishes analysing a request it calls
``RecordingManager.save_finding(project_dir, finding, analysis_results)``.
Results are grouped into *categories* (Reflected, SQLi, XSS, SSRF, LFI,
Secrets, CORS, Headers, Errors, Other, ...) and written to a single JSON file:

    <project_dir>/analysis_recordings.json

The Recorded sub-tab in Attack Surface reads this file and displays the
data in a professional, filterable table.

── Design note (2024 rewrite) ─────────────────────────────────────────────
The original version of this module filtered `analysis_results["params"]`
through an *allow-list* of keyword substrings before deciding whether a
detection was worth persisting. That approach silently dropped a large
number of real (often HIGH/CRITICAL) findings produced by analysis_tab.py
because their exact tag text didn't happen to contain one of the coded
keywords (e.g. "SECRET_IN_INLINE_JS" doesn't contain a word-bounded
"SECRET", "RESPONSE GRAPHQL ..." wasn't covered at all, etc.), and it never
looked at `results['weird']`, `results['cookies']`, or `results['tech_stack']`
at all — three entire detection buckets produced by SecurityAnalyzer.

This version instead records everything by default and only excludes a
short, explicit list of "pure noise" tags used purely to populate the
attack-surface parameter table (not real detections). It also ingests the
weird/cookies/tech_stack buckets. This makes the recorder resilient to new
detection tags being added to analysis_tab.py in the future — anything not
explicitly marked as noise gets captured.
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
    "ssti":          ("Template Injection",    "🤅", 13),
    "xxe":           ("XXE",                    "🗉", 14),
    "graphql":       ("GraphQL Issues",        "⬡", 15),
    "websocket":     ("WebSocket Issues",      "◈", 16),
    "jsonp":         ("JSONP Endpoints",       "🖈", 17),
    "exposure":      ("Sensitive Exposure",    "🕳", 18),
    "cookies":       ("Cookie Security",       "🤀", 19),
    "recon":         ("Recon / Tech Stack",    "🄬", 20),
    "anomalies":     ("Anomalies",             "?", 21),
    "other":         ("Other Findings",        "🔍", 99),
}

# ── Keyword → category mapping ─────────────────────────────────────────────────
# Checked against the *vulnerabilities* column string of each param row.
# NOTE: patterns here are deliberately permissive (no forced trailing \b in
# most cases) so that compound tags like "SECRET_IN_INLINE_JS" or
# "CSRF_VIA_OAUTH" still classify correctly.
_CATEGORY_RULES: List[tuple] = [
    # (regex_pattern, category_key)
    (r"\bREFLECTED\b",                                     "reflected"),
    (r"\bXSS\b|XSS_SINK|_XSS\b|\bXSS_",                    "xss"),
    (r"\bSQLI\b|SQL_INJECT|SQL_ERROR|CLIENT_SIDE_SQLI",     "sqli"),
    (r"\bSSRF\b",                                           "ssrf"),
    (r"\bLFI\b|PATH_TRAVERSAL|\bRFI\b",                     "lfi"),
    (r"\bIDOR\b|\bBOLA\b",                                  "idor"),
    (r"\bCORS",                                             "cors"),
    (r"SECRET|API_KEY|AWS_KEY|GITHUB_TOKEN|_TOKEN\b|TOKEN_STORAGE|"
     r"STRIPE_KEY|GENERIC_API_KEY|PRIVATE_KEY|HARDCODED_SECRET",
                                                             "secrets"),
    (r"MISSING_|SECURITY_MISC|\bDEBUG_HEADER\b|\bCLICKJACKING\b|"
     r"\bHOST_HEADER\b|WEAK_CSP|UNCOMMON_HEADER",
                                                             "headers"),
    (r"ERROR_DISCLOS|STACK_TRACE|\bEXCEPTION\b|PHP_FATAL|PHP_WARNING|"
     r"PHP_PARSE|PYTHON_TRACEBACK|JAVA_EXCEPTION|DOTNET_EXCEPTION|"
     r"RUNTIME_ERROR|TYPE_ERROR|VALUE_ERROR",
                                                             "errors"),
    (r"\bOPEN_REDIRECT\b|\bREDIRECT\b",                    "open_redirect"),
    (r"\bCSRF\b|CSRF_VIA_OAUTH|CSRF_HIDDEN",                "csrf"),
    (r"\bSSTI\b|TEMPLATE_INJECT",                           "ssti"),
    (r"\bXXE\b|ENTITY_SYSTEM|ENTITY_PUBLIC|DOCTYPE_WITH_DTD|"
     r"XXE_TESTING_CANDIDATE|XXE_EXPLOITATION_ATTEMPT",
                                                             "xxe"),
    (r"GRAPHQL",                                            "graphql"),
    (r"WEBSOCKET",                                          "websocket"),
    (r"JSONP",                                              "jsonp"),
    (r"ADMIN_PANEL|DEFAULT_CRED|WEB_CACHE_DECEPTION|"
     r"REFLECTED_FILE_DOWNLOAD|\bRFD\b|SOURCE_MAP|INTERNAL_HOST|"
     r"SUBDOMAIN_TAKEOVER|OAUTH_STATE_MISSING|DIRECTORY_LISTING",
                                                             "exposure"),
]

# Tags that are pure "attack surface" noise — used to populate the
# parameter table but not, by themselves, a security detection. An entry
# is skipped ONLY if every one of its non-metadata tokens falls in this set.
_NOISE_TAGS = {
    "INFO", "INTERESTING", "TECHNOLOGY_DETECTED", "GOOD", "REQUIRED",
    "UNKNOWN", "STANDALONE", "HIDDEN",
}

# Prefixes used for metadata tokens (e.g. "VALUE:foo", "NOTE:bar") — these
# carry detail, not a signal of their own, so they never make an entry
# "noisy" or "meaningful" on their own.
_METADATA_PREFIXES = (
    "VALUE:", "EVIDENCE:", "NOTE:", "CODE:", "TYPE:", "SOURCE:", "SINK:",
    "VAR:", "EXPR:", "PATH:", "URL:", "HREF:", "PARAM:", "SERVICE:",
    "CALLBACK:", "ERROR_MSG:", "HEADER:", "RISK:", "LOC:", "TAG:",
)

_SEVERITY_WORDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


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


def _is_pure_noise(tokens: List[str]) -> bool:
    """
    Return True if *tokens* contains nothing but noise markers and/or
    metadata-prefixed detail (i.e. there is no real detection signal here).
    """
    for tok in tokens:
        tok_upper = str(tok).upper().strip()
        if not tok_upper:
            continue
        if tok_upper in _SEVERITY_WORDS:
            # A bare severity word alone isn't a signal, but keep scanning —
            # other tokens decide.
            continue
        if tok_upper in _NOISE_TAGS:
            continue
        if any(tok_upper.startswith(p) for p in _METADATA_PREFIXES):
            continue
        # Anything else (a bare tag like "SECRET_IN_INLINE_JS", "GRAPHQL_QUERY",
        # "ADMIN_PANEL", "SSTI", etc.) counts as real signal.
        return False
    return True


def _severity_order(sev: str) -> int:
    """Lower = more severe."""
    return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(sev.upper(), 4)


def _explicit_severity(tokens: List[str]) -> Optional[str]:
    """Return CRITICAL/HIGH/MEDIUM/LOW if a bare severity token is present, else None."""
    upper_tokens = [str(t).upper() for t in tokens]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in upper_tokens:
            return sev
    return None


def _severity_from_tokens(tokens: List[str], default: str = "LOW") -> str:
    explicit = _explicit_severity(tokens)
    if explicit:
        return explicit
    joined = " ".join(str(t).upper() for t in tokens)
    if any(k in joined for k in ["XSS", "SQLI", "RCE", "SSRF", "SECRET"]):
        return "HIGH"
    return default


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


def _make_id(seed: str) -> str:
    return f"{hash(seed) & 0xFFFFFFFF:08x}"


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
        Extract every noteworthy detection from *analysis_results* — params,
        weird-analyzer anomalies, cookie security issues, and tech-stack
        recon — and append them to the project's recordings file, grouped
        by category.

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

            reflected_params = _extract_reflected_params(analysis_results)

            def _add_entry(category: str, severity: str, location: str,
                            parameter: str, det_str: str, extra: Optional[Dict] = None):
                entry = {
                    "id":         _make_id(f"{ts}|{url}|{category}|{parameter}|{det_str}"),
                    "timestamp":  ts,
                    "url":        url,
                    "host":       host,
                    "method":     method,
                    "status":     status,
                    "severity":   severity,
                    "category":   category,
                    "location":   location,
                    "parameter":  parameter,
                    "detections": det_str,
                    "reflected_params": reflected_params,
                    "overall_severity": severity_overall,
                }
                if extra:
                    entry.update(extra)

                bucket = recordings.setdefault(category, [])
                dup = any(
                    e.get("url") == url
                    and e.get("parameter") == parameter
                    and e.get("category") == category
                    and e.get("detections") == det_str
                    for e in bucket
                )
                if not dup:
                    bucket.append(entry)

            # ── 1. Iterate every detected parameter ───────────────────────
            for param_full, detections in analysis_results.get("params", {}).items():
                tokens = list(detections) if isinstance(detections, (list, set)) else [detections]
                det_str = " ".join(str(d) for d in tokens)

                # An explicit CRITICAL/HIGH/MEDIUM severity is always a real
                # detection signal — record it even if the identifying tag
                # is only embedded inside a "TYPE:" token or inside the key
                # itself (e.g. "RESPONSE GRAPHQL introspection" -> ['HIGH']).
                # Only fall back to the noise-tag check when there is no
                # explicit elevated severity at all.
                explicit_sev = _explicit_severity(tokens)
                if explicit_sev in (None, "LOW") and _is_pure_noise(tokens):
                    continue

                # Classify using the key (which often carries the actual
                # detection type, e.g. "JS SOURCE_MAP ...", "URL ADMIN_PANEL
                # ...") together with the values, not values alone.
                category = _classify(f"{param_full} {det_str}")
                sev = explicit_sev or _severity_from_tokens(tokens)

                # Parse location / param name
                parts = param_full.split(" ", 1)
                location = parts[0] if len(parts) > 1 else "UNKNOWN"
                param_name = parts[1] if len(parts) > 1 else param_full

                _add_entry(category, sev, location, param_name, det_str)

            # ── 2. Weird-analyzer anomalies ────────────────────────────────
            for weird in analysis_results.get("weird", []):
                if not isinstance(weird, dict):
                    continue
                sev = str(weird.get("severity", "LOW")).upper()
                title = weird.get("title", "Anomaly")
                detail = weird.get("detail", "")
                evidence = weird.get("evidence", "")
                sub_category = weird.get("category", "Anomaly")
                det_str = " | ".join(
                    p for p in [sub_category, title, detail, evidence] if p
                )
                _add_entry(
                    "anomalies", sev, "WEIRD", title, det_str,
                    extra={"weird_category": sub_category},
                )

            # ── 3. Cookie security issues ──────────────────────────────────
            for cookie in analysis_results.get("cookies", []):
                if not isinstance(cookie, dict):
                    continue
                issues = cookie.get("issues") or []
                if not issues:
                    continue
                name = cookie.get("name", "cookie")
                source = cookie.get("source", "")
                for issue in issues:
                    # issue is (code, severity, message)
                    if isinstance(issue, (list, tuple)) and len(issue) == 3:
                        code, sev, msg = issue
                    else:
                        code, sev, msg = str(issue), "MEDIUM", ""
                    det_str = f"{code} {msg}".strip()
                    _add_entry(
                        "cookies", str(sev).upper(), source or "COOKIE",
                        name, det_str,
                    )

            # ── 4. Tech stack / recon fingerprints ───────────────────────
            tech_stack = analysis_results.get("tech_stack", {})
            if isinstance(tech_stack, dict) and tech_stack:
                for tech_name, evidence_list in tech_stack.items():
                    evidence = evidence_list if isinstance(evidence_list, (list, tuple)) else [evidence_list]
                    det_str = "; ".join(str(e) for e in evidence[:5])
                    _add_entry("recon", "LOW", "TECH", tech_name, det_str)

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