"""
Open Redirect scan mixin — accurate detection of URL redirection vulnerabilities.

Detection strategy:
  Phase 1 — Parameter-based: inject canary URL into redirect-relevant parameters
             (url, redirect, next, return, goto, dest, target, …)
             Send with allow_redirects=False and inspect:
               a) Location header pointing to canary host
               b) JavaScript redirect in response body (window.location, location.href)
               c) Meta-refresh redirect in HTML pointing to canary

  Phase 2 — Header-based: inject canary into Referer / Host-override headers

  Phase 3 — Bypass payloads: protocol-relative, URL-encoded, double-slash,
             backslash, CRLF, @ tricks, scheme confusion, null-byte, fragment tricks,
             whitelisted-domain prefix/suffix bypass

  Accuracy measures:
    • allow_redirects=False on all probe requests — examine raw Location header
    • Two independent canary domains: both must resolve to canary during double-check
    • Case-insensitive header comparison
    • Minimum match: complete scheme+host of canary must appear in Location or body
    • Baseline check — confirm parameter actually influences redirect before flagging
    • JS/meta-body scan limited to response content-type text/html or text/javascript
"""

import base64
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Canary domains — clearly fake, unlikely to appear in legitimate responses
# ─────────────────────────────────────────────────────────────────────────────
_CANARY_HOST     = "canary-openredirect-test.evil.io"
_CANARY_URL      = f"https://{_CANARY_HOST}"
_CANARY_PROTO    = f"//{_CANARY_HOST}"       # protocol-relative
_CANARY_DATA_B64 = base64.b64encode(         # base64 data-URL redirect payload
    f'<script>location="{_CANARY_URL}"</script>'.encode()
).decode()

# ─────────────────────────────────────────────────────────────────────────────
# Parameter names that commonly control server-side or client-side redirects
# ─────────────────────────────────────────────────────────────────────────────
_REDIRECT_PARAM_NAMES: set = {
    # Standard
    "url", "uri",
    "redirect", "redirecturl", "redirect_url", "redirecturi", "redirect_uri",
    "return", "returnurl", "return_url", "returnto", "return_to",
    "next", "nexturl", "next_url",
    "goto", "go",
    "dest", "destination",
    "target", "targeturl", "target_url",
    "link", "href",
    "forward", "forwardurl", "forward_url",
    "continue", "continueto", "continue_to",
    "location",
    "out",
    "path",
    "to",
    "open",
    "success_url", "success",
    "cancel_url", "cancel",
    "callback", "callbackurl", "callback_url",
    "origin",
    "checkout_url",
    "logout_redirect", "login_redirect",
    "signup_redirect",
    "redir", "rurl", "r", "l",
    "page", "view",
    "ref",
    "referer",
    "from",
    "action",
}

# Header names that can influence redirect destination
_REDIRECT_HEADERS = [
    "Referer",
    "X-Forwarded-For",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Host",
]


# ─────────────────────────────────────────────────────────────────────────────
# Payload table
# Each tuple: (label, value_template)
# {canary} is replaced by the canary URL, {host} by canary host, {proto} by //host
# ─────────────────────────────────────────────────────────────────────────────
_BASIC_PAYLOADS: List[Tuple[str, str]] = [
    # ── Direct ─────────────────────────────────────────────────────────────
    ("absolute-https",        "{canary}"),
    ("protocol-relative",     "{proto}"),
    ("absolute-http",         "http://{host}"),
    ("no-scheme",             "{host}"),

    # ── Slash tricks ────────────────────────────────────────────────────────
    ("double-slash",          "https://{host}"),
    ("triple-slash",          "https:///{host}"),
    ("backslash",             "https:\\\\{host}"),
    ("backslash-single",      "https:\\{host}"),
    ("proto-backslash",       "//{host}"),
    ("leading-slash",         "/{host}"),
    ("double-lead-slash",     "//{host}"),

    # ── URL-encoding ────────────────────────────────────────────────────────
    ("url-encoded",           "https%3A%2F%2F{host}"),
    ("double-url-encoded",    "https%253A%252F%252F{host}"),
    ("proto-encoded",         "%2F%2F{host}"),
    ("partial-encoded",       "https://{host}%2Fpath"),

    # ── @ separator tricks ───────────────────────────────────────────────────
    ("at-sign",               "https://trusted.example.com@{host}"),
    ("at-sign-cred",          "https://user:pass@{host}"),
    ("at-encoded",            "https://trusted.example.com%40{host}"),

    # ── Fragment tricks ──────────────────────────────────────────────────────
    ("fragment",              "{canary}#"),
    ("fragment-trusted",      "{canary}#trusted.example.com"),
    ("appended-fragment",     "https://trusted.example.com#{canary}"),

    # ── Null-byte ───────────────────────────────────────────────────────────
    ("null-byte-append",      "{canary}%00.trusted.example.com"),
    ("null-byte-url",         "https://trusted.example.com%00.{host}"),

    # ── CRLF + redirect ─────────────────────────────────────────────────────
    ("crlf-location",         "%0d%0aLocation:%20{canary}"),
    ("crlf-location-2",       "%0a%0dLocation:%20{canary}"),

    # ── Scheme confusion ─────────────────────────────────────────────────────
    ("javascript-scheme",     "javascript:window.location='{canary}'"),
    ("data-scheme",           "data:text/html,<script>location='{canary}'</script>"),

    # ── Whitelist prefix/suffix bypass ──────────────────────────────────────
    ("whitelist-suffix",      "https://{host}.trusted.example.com"),
    ("whitelist-prefix",      "https://trusted.example.com.{host}"),
    ("whitelist-sub",         "https://sub.{host}"),

    # ── Browser Autocorrect ──────────────────────────────────────────────────
    # Chrome/Edge normalise these malformed schemes into valid redirect URLs.
    ("autocorrect-colon",          "https:{host}"),
    ("autocorrect-semicolon",      "https;{host}"),
    ("autocorrect-backslash-esc",  "https:\\/\\/{host}"),
    ("autocorrect-mixed-slash",    "https:/\\/\\{host}"),

    # ── Data URL (base64-encoded redirect) ────────────────────────────────────
    ("data-b64",                   "data:text/html;base64,{b64}"),

    # ── Parameter pollution ──────────────────────────────────────────────────
    # These are handled separately — appended as second redirect param values.
]

# ─────────────────────────────────────────────────────────────────────────────
# Target-domain-aware payloads — {target} is replaced at scan time with the
# target application's own hostname, extracted from the request URL.
# These bypass validators that check whether the redirect URL contains,
# starts with, or ends with the application's own domain name.
# ─────────────────────────────────────────────────────────────────────────────
_TARGET_AWARE_PAYLOADS: List[Tuple[str, str]] = [
    # ── @ separator with real target domain ──────────────────────────────────
    # Validator: {target} = hostname (safe). Browser follows {host} (canary).
    ("at-real-target",             "https://{target}@{host}"),
    ("at-real-target-encoded",     "https://{target}%40{host}"),
    ("at-real-target-dbl-enc",     "https://{target}%2540{host}"),

    # ── Path contains target domain (ends-with bypass) ────────────────────────
    ("canary-path-target",         "https://{host}/{target}"),

    # ── Starts AND ends with target domain ────────────────────────────────────
    # Satisfies validators checking both start and end of the redirect URL.
    ("start-end-subdomain",        "https://{target}.{host}/{target}"),
    ("start-end-at",               "https://{target}@{host}/{target}"),

    # ── Backslash @ trick (browser autocorrects \ → /) ───────────────────────
    # Validator: {target} = hostname. Browser: {host} = hostname.
    ("backslash-at-target",        "https://{host}\\@{target}"),

    # ── Double / triple URL-encoded slash before @ ────────────────────────────
    # Validator (over-decodes): {target} = hostname.
    # Browser (partial-decode): {target}%252f treated as username → goes to {host}.
    ("double-enc-slash-at",        "https://{target}%252f@{host}"),
    ("triple-enc-slash-at",        "https://{target}%25252f@{host}"),

    # ── Combined: double-encoded + starts+ends with target ────────────────────
    ("combined-enc",               "https://{target}%252f@{host}/{target}"),

    # ── Malformed credential URL with port ────────────────────────────────────
    # Some browsers route this to the segment after the last @, i.e. {host}.
    ("malformed-cred-port",        "https://user:password:8080/{target}@{host}"),

    # ── Non-ASCII host confusion ──────────────────────────────────────────────
    # Validator: {target} = hostname. Browser may strip %ff (\xc3\xbf) → {host} wins.
    ("non-ascii-ff",               "https://{host}%ff.{target}"),

    # ── Slash look-alike \u2571 (\u2571 = %E2%95%B1) ─────────────────────────
    # Browser normalises \u2571 → / making https://{host}/.{target} → {host} wins.
    ("slash-lookalike",            "https://{host}\u2571.{target}"),
    ("slash-lookalike-encoded",    "https://{host}%E2%95%B1.{target}"),
]


def _make_payload(template: str, target_host: str = "") -> str:
    """Expand placeholder tokens in a payload template."""
    result = (template
              .replace("{canary}", _CANARY_URL)
              .replace("{proto}",  _CANARY_PROTO)
              .replace("{host}",   _CANARY_HOST)
              .replace("{b64}",    _CANARY_DATA_B64))
    if target_host:
        result = result.replace("{target}", target_host)
    return result


def _is_redirect_to_canary(location: str) -> bool:
    """
    Return True when the given Location header value points to our canary host.
    Performs scheme-agnostic, case-insensitive host comparison so we don't
    trigger on partial substring matches.
    """
    if not location:
        return False
    loc = location.strip()
    # Prepend // so urlparse handles protocol-relative URLs
    if loc.startswith("//"):
        loc = "https:" + loc
    elif not re.match(r'^https?://', loc, re.I):
        # relative or unknown — not a redirect to canary
        return False
    try:
        parsed = urllib.parse.urlparse(loc)
        host = parsed.hostname or ""
        return host.lower() == _CANARY_HOST.lower()
    except Exception:
        return False


def _body_contains_redirect_to_canary(body: str) -> Tuple[bool, str]:
    """
    Scan a response body for JavaScript or meta-refresh redirects that point
    to the canary host.  Returns (found, description).
    """
    if not body or _CANARY_HOST.lower() not in body.lower():
        return False, ""

    # JS patterns
    js_patterns = [
        r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']*)',
        r'location\.replace\s*\(\s*["\']([^"\']*)',
        r'location\.assign\s*\(\s*["\']([^"\']*)',
        r'window\.open\s*\(\s*["\']([^"\']*)',
    ]
    for pat in js_patterns:
        for m in re.finditer(pat, body, re.IGNORECASE):
            target = m.group(1)
            if _CANARY_HOST.lower() in target.lower():
                return True, f"JS redirect → {target[:80]}"

    # Meta refresh
    for m in re.finditer(
        r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]+content\s*=\s*["\']([^"\']*)',
        body, re.IGNORECASE
    ):
        content = m.group(1)
        if _CANARY_HOST.lower() in content.lower():
            return True, f"meta-refresh → {content[:80]}"

    return False, ""


class OpenRedirectScanMixin:
    """Mixin methods for open redirect vulnerability scanning."""

    # ──────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────────

    def scan_open_redirect(self) -> Dict[str, Any]:
        """
        Scan for open redirect vulnerabilities.
        Returns a result dict with keys:
          vulnerable (bool), summary (str), details (list), stats (dict).
        """
        results: Dict[str, Any] = {
            "scan_type":  "OpenRedirect",
            "vulnerable": False,
            "summary":    "",
            "details":    [],
            "stats": {
                "params_tested":     0,
                "payloads_sent":     0,
                "findings":          0,
            },
        }

        try:
            self._scan_open_redirect_params(results)
        except Exception as exc:
            logger.error("open_redirect scan error: %s", exc, exc_info=True)
            results["summary"] = f"Scan error: {exc}"

        stats = results["stats"]
        vuln_count = stats["findings"]
        results["vulnerable"] = vuln_count > 0
        results["summary"] = (
            f"{'VULNERABLE' if results['vulnerable'] else 'Not vulnerable'} — "
            f"{stats['params_tested']} parameter(s) tested, "
            f"{stats['payloads_sent']} request(s) sent, "
            f"{vuln_count} finding(s)"
        )
        return results

    # ──────────────────────────────────────────────────────────────────────────
    # Phase 1 + 3: parameter injection
    # ──────────────────────────────────────────────────────────────────────────

    def _scan_open_redirect_params(self, results: Dict[str, Any]) -> None:
        request_data  = self.request_data
        base_url      = request_data.get("url", "")
        request_text  = request_data.get("request_text", "")
        stats         = results["stats"]

        if not base_url:
            return

        parsed_url = urllib.parse.urlparse(base_url)
        target_host = parsed_url.hostname or ""
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        method = "GET"
        body_content = ""
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

        # Parse raw request text
        lines = request_text.split("\n") if request_text else []
        if lines:
            first = lines[0].split()
            if first:
                method = first[0].upper()
        in_body = False
        for line in lines[1:]:
            stripped = line.rstrip("\r")
            if stripped == "":
                in_body = True
                continue
            if in_body:
                body_content += stripped + "\n"
            else:
                if ":" in stripped:
                    k, _, v = stripped.partition(":")
                    k = k.strip()
                    v = v.strip()
                    if k.lower() == "cookie":
                        for pair in v.split(";"):
                            pair = pair.strip()
                            if "=" in pair:
                                ck, _, cv = pair.partition("=")
                                cookies[ck.strip()] = cv.strip()
                    else:
                        headers[k] = v

        body_content = body_content.strip()

        # Parse body params
        body_params: Dict[str, str] = {}
        content_type = headers.get("Content-Type", headers.get("content-type", ""))
        if method in ("POST", "PUT", "PATCH") and body_content:
            if "application/x-www-form-urlencoded" in content_type or not content_type.startswith("application/json"):
                try:
                    bp = urllib.parse.parse_qs(body_content, keep_blank_values=True)
                    body_params = {k: v[0] if v else "" for k, v in bp.items()}
                except Exception:
                    pass

        # Collect candidate injection points
        candidates: List[Dict[str, Any]] = []

        for pname, vals in query_params.items():
            val = vals[0] if vals else ""
            if self._is_redirect_param(pname, val) and self._is_forced_point("url", pname):
                candidates.append({"type": "url", "name": pname, "value": val})

        for pname, val in body_params.items():
            if self._is_redirect_param(pname, val) and self._is_forced_point("body", pname):
                candidates.append({"type": "body", "name": pname, "value": val})

        if not candidates:
            # Fallback: test ALL query/body params when none match redirect heuristics
            for pname, vals in query_params.items():
                val = vals[0] if vals else ""
                if self._is_forced_point("url", pname):
                    candidates.append({"type": "url", "name": pname, "value": val})
            for pname, val in body_params.items():
                if self._is_forced_point("body", pname):
                    candidates.append({"type": "body", "name": pname, "value": val})

        # Always collect forced header / cookie injection points
        _SKIP_HDR = {"host", "content-length", "transfer-encoding",
                     "connection", "accept-encoding", "cookie"}
        for hname, hval in headers.items():
            if hname.lower() not in _SKIP_HDR and self._is_forced_point("header", hname):
                candidates.append({"type": "header", "name": hname, "value": hval})

        for cname, cval in cookies.items():
            if self._is_forced_point("cookie", cname):
                candidates.append({"type": "cookie", "name": cname, "value": cval})

        if not candidates:
            results["summary"] = "No redirect parameters found to test."
            return

        stats["params_tested"] = len(candidates)

        # Build base request headers (copy original, drop infra headers)
        req_headers = {k: v for k, v in headers.items()
                       if k.lower() not in ("host", "content-length", "transfer-encoding")}
        # Reconstruct Cookie header so every probe carries the original session cookies
        if cookies:
            req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # Baseline: one request to get baseline status/location
        baseline_status, baseline_location = self._redirect_baseline(
            base_url, parsed_url, query_params, method, body_content, req_headers, cookies
        )

        for candidate in candidates:
            if not self.running:
                break
            self._probe_param(
                results=results,
                base_url=base_url,
                parsed_url=parsed_url,
                query_params=query_params,
                body_params=body_params,
                method=method,
                body_content=body_content,
                req_headers=req_headers,
                cookies=cookies,
                candidate=candidate,
                baseline_status=baseline_status,
                baseline_location=baseline_location,
                target_host=target_host,
            )
            if self.scan_stop_on_first and results["stats"]["findings"] > 0:
                break

    # ──────────────────────────────────────────────────────────────────────────
    # Baseline request
    # ──────────────────────────────────────────────────────────────────────────

    def _redirect_baseline(self, base_url, parsed_url, query_params, method,
                           body_content, req_headers, cookies) -> Tuple[int, str]:
        """Fire the original unmodified request; return (status_code, location_header)."""
        try:
            resp = self.send_request_with_traffic(
                url=base_url,
                headers=req_headers,
                method=method,
                body=body_content,
                payload="",
                payload_type="baseline",
                allow_redirects=False,
            )
            if resp and hasattr(resp, 'status_code') and resp.status_code != 0:
                loc = resp.headers.get("Location", "")
                return resp.status_code, loc
        except Exception:
            pass
        return 0, ""

    # ──────────────────────────────────────────────────────────────────────────
    # Per-parameter probing
    # ──────────────────────────────────────────────────────────────────────────

    def _probe_param(self, results, base_url, parsed_url, query_params, body_params,
                     method, body_content, req_headers, cookies,
                     candidate, baseline_status, baseline_location,
                     target_host: str = "") -> None:
        stats    = results["stats"]
        found_ids: set = set()  # track which payloads already flagged this param

        all_payloads = list(_BASIC_PAYLOADS)
        if target_host:
            all_payloads.extend(_TARGET_AWARE_PAYLOADS)

        for label, template in all_payloads:
            if not self.running:
                return

            payload_val = _make_payload(template, target_host=target_host)
            probe_url, probe_body = self._inject_payload(
                base_url=base_url,
                parsed_url=parsed_url,
                query_params=query_params,
                body_params=body_params,
                body_content=body_content,
                candidate=candidate,
                payload_val=payload_val,
            )

            # Build per-probe headers — inject into header/cookie if selected
            probe_headers = dict(req_headers)
            if candidate["type"] == "header":
                probe_headers[candidate["name"]] = payload_val
            elif candidate["type"] == "cookie":
                cookie_copy = dict(cookies)
                cookie_copy[candidate["name"]] = payload_val
                probe_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookie_copy.items())

            stats["payloads_sent"] += 1

            if self.scan_req_delay:
                time.sleep(self.scan_req_delay)

            try:
                resp = self.send_request_with_traffic(
                    url=probe_url,
                    headers=probe_headers,
                    method=method,
                    body=probe_body,
                    payload=payload_val,
                    payload_type=f"open-redirect:{label}",
                    allow_redirects=False,
                )
            except Exception as exc:
                logger.debug("open_redirect probe error: %s", exc)
                continue

            if not resp or not hasattr(resp, 'status_code') or resp.status_code == 0:
                continue

            # ── Accurate detection ────────────────────────────────────────────

            finding, confidence, method_desc = self._evaluate_response(
                resp=resp,
                payload_val=payload_val,
                label=label,
                baseline_status=baseline_status,
                baseline_location=baseline_location,
            )

            if not finding:
                continue

            # Deduplicate: one finding per (param, canary_base) — collect best evidence
            finding_key = f"{candidate['name']}:{confidence}"
            if finding_key in found_ids:
                continue
            found_ids.add(finding_key)

            stats["findings"] += 1
            results["details"].append({
                "parameter":        candidate["name"],
                "param_type":       candidate["type"],
                "payload":          payload_val,
                "payload_label":    label,
                "status_code":      resp.status_code if hasattr(resp, 'status_code') else "?",
                "location":         resp.headers.get("Location", "") if hasattr(resp, 'headers') else "",
                "method":           method_desc,
                "confidence":       confidence,
                "note":             f"Redirect to canary via {method_desc} [{label}]",
                "url":              probe_url,
                "baseline_status":  baseline_status,
                "baseline_location": baseline_location,
            })

            self.scan_progress.emit(
                f"🔴 OPEN REDIRECT [{confidence}]: {candidate['name']} "
                f"→ {label} (HTTP {resp.status_code if hasattr(resp, 'status_code') else '?'})"
            )

            if self.scan_stop_on_first:
                return

    # ──────────────────────────────────────────────────────────────────────────
    # Inject payload into URL or body
    # ──────────────────────────────────────────────────────────────────────────

    def _inject_payload(self, base_url, parsed_url, query_params, body_params,
                        body_content, candidate, payload_val) -> Tuple[str, str]:
        """Return (probe_url, probe_body) with the candidate param replaced by payload."""
        if candidate["type"] == "url":
            new_params = dict(query_params)
            new_params[candidate["name"]] = [payload_val]
            new_qs   = urllib.parse.urlencode(new_params, doseq=True)
            probe_url = urllib.parse.urlunparse(
                parsed_url._replace(query=new_qs)
            )
            return probe_url, body_content

        elif candidate["type"] in ("header", "cookie"):
            # Injection is handled via probe_headers in _probe_param; URL/body unchanged
            return base_url, body_content

        else:  # body param
            probe_url = base_url
            new_bp = dict(body_params)
            new_bp[candidate["name"]] = payload_val
            return probe_url, urllib.parse.urlencode(new_bp)

    # ──────────────────────────────────────────────────────────────────────────
    # Response evaluation
    # ──────────────────────────────────────────────────────────────────────────

    def _evaluate_response(self, resp, payload_val, label,
                           baseline_status, baseline_location) -> Tuple[bool, str, str]:
        """
        Return (is_finding, confidence, detection_method).
        Confidence: HIGH | MEDIUM | LOW
        """
        status = getattr(resp, 'status_code', 0)
        all_headers = getattr(resp, 'headers', {})
        location = all_headers.get("Location", all_headers.get("location", ""))
        resp_body = getattr(resp, 'text', "") or ""

        # ── Check 1: HTTP 3xx + Location contains canary host ─────────────────
        if status in (301, 302, 303, 307, 308):
            if _is_redirect_to_canary(location):
                # Confirm it's not the same as baseline (avoid false-positive on pre-existing redirect)
                if baseline_location != location:
                    confidence = "HIGH"
                    return True, confidence, f"HTTP {status} Location header"
                else:
                    # baseline already redirects to same place — not caused by payload
                    pass

        # ── Check 2: HTTP 200 + body JS/meta redirect to canary ───────────────
        content_type = all_headers.get("Content-Type", all_headers.get("content-type", ""))
        is_html_or_js = any(t in content_type.lower() for t in ("text/html", "text/javascript", "application/javascript", "application/xhtml"))
        if is_html_or_js and resp_body:
            body_found, body_desc = _body_contains_redirect_to_canary(resp_body)
            if body_found:
                confidence = "MEDIUM"
                return True, confidence, f"Body JS/meta-refresh → {body_desc}"

        # ── Check 3: Open redirect via parameter that changes Location ─────────
        # For payloads that inject CRLF into Location, check raw response text
        # (some servers reflect the injected header in the body or partial headers)
        if label.startswith("crlf") and _CANARY_HOST.lower() in resp_body.lower():
            confidence = "LOW"
            return True, confidence, "CRLF header injection (canary in body)"

        # ── Check 4: Any non-3xx but Location header appears (some frameworks) ──
        if location and _is_redirect_to_canary(location):
            confidence = "MEDIUM"
            return True, confidence, f"Location header (HTTP {status})"

        return False, "", ""

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _is_redirect_param(name: str, value: str) -> bool:
        """
        Return True when the parameter name or value suggests it controls a redirect.
        """
        name_lower = name.lower().replace("-", "").replace("_", "")

        # Direct name match
        if name_lower in _REDIRECT_PARAM_NAMES:
            return True

        # Substring match on name
        redirect_substrings = (
            "url", "uri", "redirect", "return", "next", "goto",
            "dest", "target", "forward", "continue", "link",
            "href", "location", "back", "ref",
        )
        for sub in redirect_substrings:
            if sub in name_lower:
                return True

        # Value looks like a URL
        if value and re.match(r'^https?://', value, re.I):
            return True
        if value and value.startswith("//"):
            return True
        if value and re.match(r'^/[a-zA-Z0-9]', value):
            return True

        return False
