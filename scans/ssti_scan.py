"""
SSTI (Server-Side Template Injection) scan mixin.

Detection strategy (PortSwigger methodology):
  Phase 1 — Polyglot math probes
      Inject arithmetic expressions valid in multiple engines and look for
      the evaluated result (49, 7777777, etc.) appearing in the response.
      Uses a baseline comparison so pre-existing numbers in the page do not
      cause false positives.

  Phase 2 — Engine fingerprinting
      Once a parameter tests positive, fire engine-specific differentiator
      payloads to narrow down the underlying template engine:
        • {{7*'7'}} → 7777777 (Jinja2) vs 49 (Twig)
        • ${7*7}    → 49 confirms Freemarker / Mako / Velocity / Spring-EL
        • <%= 7*7 %> → 49 confirms ERB (Ruby) / EJS (Node)
        • #{7*7}   → 49 confirms Thymeleaf / Pebble
        • *{7*7}   → 49 confirms Spring Thymeleaf OGNL

  Phase 3 — Error-based detection
      Inject obviously malformed template syntax (e.g. ${{<%[%'"}}%\\).
      Template engines almost always raise a syntax error whose stack-trace
      or error class reveals the engine name in the response body.

  Phase 4 — Code-context probing
      Inject }}{{7*7}} to break out of a surrounding expression and re-enter
      a fresh one — catches parameters used inside template expressions.

Injection points tested (controlled by the forced-point selector):
  • URL query parameters
  • POST/PUT body parameters (form-urlencoded, JSON)
  • JSON body first-level fields
  • Cookie values
  • HTTP headers (User-Agent, Referer, X-Custom-*)

Accuracy measures:
  • Baseline comparison: the calculated result must NOT appear before injection
  • HTML-decode the result before number-searching (e.g. &#52;&#57; → 49)
  • Require ≥2 distinct probe hits OR 1 hit + engine error to flag HIGH confidence
  • Engine error detection without math confirmation → MEDIUM confidence
  • Single numeric hit (no error, no second probe) → LOW confidence
"""

import html as html_module
import json
import logging
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Expected math results
# ─────────────────────────────────────────────────────────────────────────────

_MATH_RESULTS = {
    "49",       # 7*7
    "7777777",  # "7"*7 in Jinja2 / Python (string multiplication)
}

# Regex to find the numeric result allowing for surrounding word characters
_RESULT_RE = re.compile(r'(?<![0-9])(49|7777777)(?![0-9])')

# ─────────────────────────────────────────────────────────────────────────────
# Probe payload table
# ─────────────────────────────────────────────────────────────────────────────
# (label, payload, expected_result, engines)
_PROBE_PAYLOADS: List[Tuple[str, str, str, str]] = [
    # ── Double-brace engines: Jinja2, Twig, Nunjucks, Pebble, Tornado ─────────
    ("double-brace",            "{{7*7}}",              "49",      "Jinja2/Twig/Nunjucks/Pebble/Tornado"),
    ("jinja2-str-mul",          "{{7*'7'}}",            "7777777", "Jinja2/Tornado (Python str-mul)"),

    # ── Dollar-brace engines: Freemarker, Mako, Velocity, Spring EL ──────────
    ("dollar-brace",            "${7*7}",               "49",      "Freemarker/Mako/Velocity/Spring-EL"),
    ("spring-double-brace",     "${{7*7}}",             "49",      "Spring EL"),

    # ── ERB-style: Ruby ERB, Node EJS, ASP, Mojolicious ──────────────────────
    ("erb-ejs",                 "<%= 7*7 %>",           "49",      "ERB/EJS/ASP/Mojolicious"),

    # ── Razor (.NET / ASP.NET MVC) ────────────────────────────────────────────
    ("razor",                   "@(7*7)",               "49",      "Razor/.NET"),

    # ── Hash-based: Thymeleaf, Pebble-EL, Jade/Pug ──────────────────────────
    ("hash-expr",               "#{7*7}",               "49",      "Thymeleaf/Pebble-EL/Jade"),
    ("thymeleaf-ognl",          "*{7*7}",               "49",      "Thymeleaf/Spring OGNL"),

    # ── Inline bracket syntax ─────────────────────────────────────────────────
    ("thymeleaf-inline",        "[[${7*7}]]",           "49",      "Thymeleaf inline"),
    ("jinjava-inline",          "[[7*7]]",              "49",      "Jinjava/HuBL"),

    # ── Velocity (Java) ───────────────────────────────────────────────────────
    ("velocity-set",            "#set($x=7*7)${x}",     "49",      "Velocity"),

    # ── JsRender (Node.js) ───────────────────────────────────────────────────
    ("jsrender",                "{{:7*7}}",             "49",      "JsRender"),

    # ── Smarty (PHP) ─────────────────────────────────────────────────────────
    ("smarty-math",             "{math equation='7*7'}", "49",     "Smarty"),
    ("smarty-expr",             "{7*7}",               "49",       "Smarty"),

    # ── Code-context break-outs (param used inside a template expression) ─────
    ("breakout-close",          "}}{{7*7}}",            "49",      "Jinja2/Twig (close-breakout)"),
    ("breakout-full",           "}}{{7*7}}{{",          "49",      "Jinja2/Twig (full-breakout)"),
    ("breakout-strmul",         "}}{{7*'7'}}{{",        "7777777", "Jinja2 (str-mul breakout)"),
    ("breakout-el",             "}${7*7}{",             "49",      "EL/Freemarker (close-breakout)"),
    ("breakout-erb",            "%><%= 7*7 %><%",       "49",      "ERB (close-breakout)"),
    ("breakout-hash",           "}}#{7*7}{{",           "49",      "Thymeleaf/EL (hash-breakout)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Engine fingerprinting table
# (label, payload, contains_result, engine_name)
# Sent only after a positive polyglot hit to narrow down the engine.
# ─────────────────────────────────────────────────────────────────────────────
_FINGERPRINT_PAYLOADS: List[Tuple[str, str, str, str]] = [
    # Jinja2 vs Twig key differentiator: Python str-mul → 7777777, PHP → 49
    ("fp-jinja2",       "{{7*'7'}}",            "7777777", "Jinja2"),
    ("fp-twig",         "{{7*'7'}}",            "49",      "Twig"),
    # ERB / EJS (Ruby / Node)
    ("fp-erb",          "<%= 7*7 %>",           "49",      "ERB"),
    # Freemarker / EL / Mako / Spring
    ("fp-el",           "${7*7}",               "49",      "Freemarker/EL"),
    # Thymeleaf inline EL
    ("fp-thymeleaf",    "[[${7*7}]]",           "49",      "Thymeleaf"),
    # Spring OGNL
    ("fp-spring",       "*{7*7}",               "49",      "Spring Thymeleaf"),
    # Smarty (PHP)
    ("fp-smarty",       "{math equation='7*7'}", "49",     "Smarty"),
    # Pebble (Java)
    ("fp-pebble",       "{{7*7}}",              "49",      "Pebble"),
    # Razor (.NET)
    ("fp-razor",        "@(7*7)",               "49",      "Razor/.NET"),
    # Velocity (Java)
    ("fp-velocity",     "#set($x=7*7)${x}",     "49",      "Velocity"),
    # JsRender (Node.js)
    ("fp-jsrender",     "{{:7*7}}",             "49",      "JsRender"),
    # Jinjava/HuBL (Hubspot Java)
    ("fp-jinjava",      "[[7*7]]",              "49",      "Jinjava/HuBL"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Error patterns that reveal the template engine even without math evaluation
# ─────────────────────────────────────────────────────────────────────────────
_ERROR_PATTERNS: List[Tuple[str, str]] = [
    # ── Python ────────────────────────────────────────────────────────────────
    (r"TemplateSyntaxError|UndefinedError|jinja2\.",                        "Jinja2"),
    (r"mako\.exceptions|MakoException|mako\.",                             "Mako"),
    (r"tornado\.template|tornado\.",                                       "Tornado"),
    # ── PHP ───────────────────────────────────────────────────────────────────
    (r"Twig[_\\]Error|Twig\\Template|twig\.error",                         "Twig"),
    (r"Smarty error|smarty_compiler|SmartyException",                      "Smarty"),
    # ── Java ──────────────────────────────────────────────────────────────────
    (r"freemarker\.template|FreeMarker|freemarker\.",                      "Freemarker"),
    (r"org\.thymeleaf|ThymeleafException",                                 "Thymeleaf"),
    (r"org\.apache\.velocity|VelocityException",                           "Velocity"),
    (r"com\.github\.jknack\.handlebars|HandlebarsException",               "Handlebars"),
    (r"pebble\.error|PebbleException|io\.pebbletemplates|com\.mitchellbosecke\.pebble", "Pebble"),
    (r"groovy\.lang\.GroovyRuntimeException|groovy\.",                     "Groovy"),
    (r"javax\.el\.|jakarta\.el\.|ELException",                             "Java-EL"),
    (r"com\.hubspot\.jinjava|JinjavaException",                            "Jinjava/HuBL"),
    # ── Node.js ───────────────────────────────────────────────────────────────
    (r"ejs[:\s]+|EJS error",                                               "EJS"),
    (r"nunjucks error|nunjucks\.",                                         "Nunjucks"),
    (r"Syntax error.*template|@jsrender|jsrender\.error",                  "JsRender"),
    (r"jade.+error|pug.+error|\.pug:|pug compilation error",              "Pug/Jade"),
    # ── Ruby ──────────────────────────────────────────────────────────────────
    (r"ActionView::Template::Error|ERB::Compiler",                         "ERB"),
    (r"Slim::Parser|SlimError|slim.+error",                                "Slim"),
    # ── .NET ──────────────────────────────────────────────────────────────────
    (r"Microsoft\.CSharp|Compiler Error Message|System\.Web\.HttpException", "Razor/.NET"),
    # ── Go ────────────────────────────────────────────────────────────────────
    (r"template: .+at .+|executing .+template|template.*parse.*error",     "Go/text-template"),
    # ── Generic ───────────────────────────────────────────────────────────────
    (r"Template render error|Liquid syntax error|liquid error",            "Liquid"),
    (r"template engine|TemplateError|render_template",                     "Generic"),
]

# Error-triggering polyglots — cause syntax exceptions in most engines
_ERROR_PROBES: List[str] = [
    "${{<%[%'\"}}%\\",  # Classic tplmap polyglot — triggers most engines
    "${7/0}",            # Division by zero: Freemarker, Spring EL, Mako
    "{{7/0}}",           # Division by zero: Jinja2, Twig, Nunjucks
    "#{7/0}",            # Division by zero: Thymeleaf, EL
    "@(1/0)",            # Division by zero: Razor/.NET
]

# ─────────────────────────────────────────────────────────────────────────────
# Headers worth testing even when not in the original request
# ─────────────────────────────────────────────────────────────────────────────
_SSTI_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Custom-Header",
]


def _html_decode(text: str) -> str:
    """HTML-decode text so &#52;&#57; → 49 won't be missed."""
    try:
        return html_module.unescape(text)
    except Exception:
        return text


def _contains_result(body: str, expected: str) -> bool:
    """Return True if the decoded body contains the expected numeric result."""
    decoded = _html_decode(body)
    return bool(_RESULT_RE.search(decoded)) if expected in _MATH_RESULTS else (expected in decoded)


def _detect_engine_from_error(body: str) -> Optional[str]:
    """Scan the response body for template-engine error signatures."""
    for pattern, engine in _ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            return engine
    return None


class SstiScanMixin:
    """Mixin that adds Server-Side Template Injection scanning to ScanWorker."""

    # ──────────────────────────────────────────────────────────────────────────
    # Public entry point
    # ──────────────────────────────────────────────────────────────────────────

    def scan_ssti(self) -> Dict[str, Any]:
        """
        Scan for SSTI vulnerabilities.

        Returns a result dict::

            {
                "scan_type":  "SSTI",
                "vulnerable": bool,
                "summary":    str,
                "details":    [...],
                "stats":      {"params_tested": int, "payloads_sent": int, "findings": int},
            }
        """
        self.scan_progress.emit("🧩 [SSTI] Starting Server-Side Template Injection scan...")
        self.scan_progress.emit(
            f"  Probes: {len(_PROBE_PAYLOADS)} polyglot math probes + "
            f"{len(_FINGERPRINT_PAYLOADS)} fingerprint probes + "
            f"{len(_ERROR_PROBES)} error probes"
        )
        self.scan_progress.emit(
            "  Engines: Jinja2, Twig, Nunjucks, Pebble, Tornado, Freemarker, Mako, "
            "Velocity, Spring-EL, Thymeleaf, Smarty, ERB, EJS, Razor/.NET, "
            "JsRender, Jinjava/HuBL, Handlebars, Groovy, Liquid, Pug/Jade, Slim"
        )

        results: Dict[str, Any] = {
            "scan_type":  "SSTI",
            "vulnerable": False,
            "summary":    "",
            "details":    [],
            "stats": {
                "params_tested": 0,
                "payloads_sent": 0,
                "findings":      0,
            },
        }

        try:
            self._ssti_scan_params(results)
        except Exception as exc:
            logger.error("SSTI scan error: %s", exc, exc_info=True)
            results["summary"] = f"Scan error: {exc}"
            self.scan_progress.emit(f"  ❌ [SSTI] Scan error: {exc}")
            return results

        stats = results["stats"]
        n = stats["findings"]
        results["vulnerable"] = n > 0
        results["summary"] = (
            f"{'VULNERABLE' if results['vulnerable'] else 'Not vulnerable'} — "
            f"{stats['params_tested']} parameter(s) tested, "
            f"{stats['payloads_sent']} request(s) sent, "
            f"{n} finding(s)"
        )
        if n > 0:
            self.scan_progress.emit(
                f"  ✅ [SSTI] Done — {n} finding(s) confirmed "
                f"({stats['payloads_sent']} requests sent)"
            )
        else:
            self.scan_progress.emit(
                f"  ✓  [SSTI] Done — no SSTI found "
                f"({stats['params_tested']} param(s), {stats['payloads_sent']} requests)"
            )
        return results

    # ──────────────────────────────────────────────────────────────────────────
    # Core scan loop
    # ──────────────────────────────────────────────────────────────────────────

    def _ssti_scan_params(self, results: Dict[str, Any]) -> None:
        request_data = self.request_data
        base_url     = request_data.get("url", "")
        request_text = request_data.get("request_text", "")
        stats        = results["stats"]

        if not base_url:
            return

        # ── Parse raw request ─────────────────────────────────────────────────
        parsed_url   = urllib.parse.urlparse(base_url)
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)
        method       = "GET"
        body_content = ""
        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}

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
                    k, v = k.strip(), v.strip()
                    if k.lower() == "cookie":
                        for pair in v.split(";"):
                            pair = pair.strip()
                            if "=" in pair:
                                ck, _, cv = pair.partition("=")
                                cookies[ck.strip()] = cv.strip()
                    else:
                        headers[k] = v
        body_content = body_content.strip()

        # ── Parse body parameters ─────────────────────────────────────────────
        body_params: Dict[str, str] = {}
        json_body:   Dict[str, Any] = {}
        content_type = headers.get("Content-Type", headers.get("content-type", ""))

        if method in ("POST", "PUT", "PATCH") and body_content:
            if "application/json" in content_type:
                try:
                    parsed_json = json.loads(body_content)
                    if isinstance(parsed_json, dict):
                        json_body = {k: str(v) for k, v in parsed_json.items()
                                     if isinstance(v, (str, int, float))}
                except Exception:
                    pass
            else:
                try:
                    bp = urllib.parse.parse_qs(body_content, keep_blank_values=True)
                    body_params = {k: (v[0] if v else "") for k, v in bp.items()}
                except Exception:
                    pass

        # ── Build candidate injection points ──────────────────────────────────
        candidates: List[Dict[str, Any]] = []

        for pname, vals in query_params.items():
            if self._is_forced_point("url", pname):
                candidates.append({
                    "type":  "url",
                    "name":  pname,
                    "value": vals[0] if vals else "",
                })

        for pname, val in body_params.items():
            if self._is_forced_point("body", pname):
                candidates.append({"type": "body",       "name": pname, "value": val})

        for pname, val in json_body.items():
            if self._is_forced_point("body", pname):
                candidates.append({"type": "json",       "name": pname, "value": val})

        for cname, cval in cookies.items():
            if self._is_forced_point("cookie", cname):
                candidates.append({"type": "cookie",     "name": cname, "value": cval})

        # Selected HTTP headers
        for hname in _SSTI_HEADERS:
            if self._is_forced_point("header", hname):
                hval = headers.get(hname, "")
                candidates.append({"type": "header",     "name": hname, "value": hval})

        if not candidates:
            results["summary"] = "No injection points found to test."
            self.scan_progress.emit("  ⚠️  [SSTI] No injection points found to test.")
            return

        stats["params_tested"] = len(candidates)

        self.scan_progress.emit(
            f"  [SSTI] Found {len(candidates)} injection point(s) to test:"
        )
        for c in candidates:
            self.scan_progress.emit(
                f"    • [{c['type']}] {c['name']} = {str(c['value'])[:60]}"
            )

        # Shared request headers (drop infra headers)
        req_headers = {k: v for k, v in headers.items()
                       if k.lower() not in
                       ("host", "content-length", "transfer-encoding")}
        # Reconstruct Cookie header so probes carry the original session cookies
        if cookies:
            req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

        # ── Per-candidate scanning ─────────────────────────────────────────────
        for idx, candidate in enumerate(candidates, 1):
            if not self.running:
                break
            self.scan_progress.emit(
                f"\n  [SSTI] Testing [{idx}/{len(candidates)}] "
                f"{candidate['type']}:{candidate['name']}"
            )
            self._ssti_probe_candidate(
                results       = results,
                base_url      = base_url,
                parsed_url    = parsed_url,
                query_params  = query_params,
                body_params   = body_params,
                json_body     = json_body,
                method        = method,
                body_content  = body_content,
                req_headers   = req_headers,
                cookies       = cookies,
                content_type  = content_type,
                candidate     = candidate,
            )
            if getattr(self, "scan_stop_on_first", False) and results["stats"]["findings"] > 0:
                self.scan_progress.emit("  ⏭️  [SSTI] Stop-on-first: SSTI confirmed — cancelling remaining parameters")
                break

    # ──────────────────────────────────────────────────────────────────────────
    # Per-candidate probing
    # ──────────────────────────────────────────────────────────────────────────

    def _ssti_probe_candidate(
        self,
        results:      Dict[str, Any],
        base_url:     str,
        parsed_url,
        query_params: Dict[str, List[str]],
        body_params:  Dict[str, str],
        json_body:    Dict[str, Any],
        method:       str,
        body_content: str,
        req_headers:  Dict[str, str],
        cookies:      Dict[str, str],
        content_type: str,
        candidate:    Dict[str, Any],
    ) -> None:
        ptype = candidate["type"]
        pname = candidate["name"]
        pval  = candidate["value"]
        stats = results["stats"]

        # ── Baseline ──────────────────────────────────────────────────────────
        self.scan_progress.emit(f"    [Phase 0] Baseline request for {ptype}:{pname}")
        baseline_body = self._ssti_fire(
            base_url=base_url, parsed_url=parsed_url,
            query_params=query_params, body_params=body_params,
            json_body=json_body, method=method, body_content=body_content,
            req_headers=req_headers, cookies=cookies, content_type=content_type,
            ptype=ptype, pname=pname, payload=pval,
            payload_label="baseline", stats=stats,
        )
        if baseline_body is None:
            self.scan_progress.emit(f"    ⚠️  Baseline request failed — skipping {pname}")
            return

        baseline_has_result = bool(_RESULT_RE.search(_html_decode(baseline_body)))
        if baseline_has_result:
            self.scan_progress.emit(
                f"    ⚠️  Baseline already contains math result (49/7777777) — "
                "false-positive guard active"
            )

        # ── Phase 1: Polyglot math probes ─────────────────────────────────────
        self.scan_progress.emit(
            f"    [Phase 1] Polyglot math probes ({len(_PROBE_PAYLOADS)} payloads) — "
            "looking for evaluated 7*7=49 or 7*'7'=7777777"
        )
        hit_payloads: List[Dict[str, str]] = []  # payloads that returned the result

        for label, payload, expected, engines in _PROBE_PAYLOADS:
            if not self.running:
                return

            modified_val = pval + payload if pval else payload
            self.scan_progress.emit(
                f"      → [{label}]  {payload!r}  (expect {expected!r}, {engines})"
            )
            resp_body = self._ssti_fire(
                base_url=base_url, parsed_url=parsed_url,
                query_params=query_params, body_params=body_params,
                json_body=json_body, method=method, body_content=body_content,
                req_headers=req_headers, cookies=cookies, content_type=content_type,
                ptype=ptype, pname=pname, payload=modified_val,
                payload_label=label, stats=stats,
            )
            if resp_body is None:
                self.scan_progress.emit(f"        ✗ No response")
                continue

            # Reflection check — payload text reflected as-is (informational)
            if payload in resp_body:
                self.scan_progress.emit(
                    "        ↩  Payload reflected as-is (template may not evaluate it)"
                )

            # Check for math result NOT present in baseline
            if _contains_result(resp_body, expected) and not baseline_has_result:
                snippet = self._ssti_snippet(resp_body, expected)
                self.scan_progress.emit(
                    f"        ✅ HIT! Response contains '{expected}' — "
                    f"possible {engines}"
                )
                if snippet:
                    self.scan_progress.emit(f"        Context: {snippet[:120]}")
                hit_payloads.append({
                    "label":    label,
                    "payload":  payload,
                    "expected": expected,
                    "engines":  engines,
                    "resp_snippet": snippet,
                })
            else:
                self.scan_progress.emit(
                    f"        ✗ '{expected}' not found in response"
                    + (" (baseline collision — skipped)" if baseline_has_result else "")
                )

        # ── Phase 2: Error-based probes ───────────────────────────────────────
        self.scan_progress.emit(
            f"    [Phase 2] Error-based detection — {len(_ERROR_PROBES)} polyglot fuzz strings"
        )
        engine_from_error: Optional[str] = None
        for _ep_idx, _error_probe in enumerate(_ERROR_PROBES):
            if not self.running:
                break
            self.scan_progress.emit(
                f"      → [error-{_ep_idx + 1}]  {_error_probe!r}"
            )
            _error_body = self._ssti_fire(
                base_url=base_url, parsed_url=parsed_url,
                query_params=query_params, body_params=body_params,
                json_body=json_body, method=method, body_content=body_content,
                req_headers=req_headers, cookies=cookies, content_type=content_type,
                ptype=ptype, pname=pname, payload=pval + _error_probe,
                payload_label=f"error-{_ep_idx + 1}", stats=stats,
            )
            if _error_body:
                _detected = _detect_engine_from_error(_error_body)
                if _detected:
                    engine_from_error = _detected
                    self.scan_progress.emit(
                        f"        ✅ Engine error signature: {_detected}"
                    )
                    break  # Engine identified — no need for further error probes
                else:
                    self.scan_progress.emit("        ✗ No engine error signature")
            else:
                self.scan_progress.emit("        ✗ No response")
        if not engine_from_error:
            self.scan_progress.emit(
                "        No engine errors detected across all error probes"
            )

        # ── Determine confidence & engine ─────────────────────────────────────
        if not hit_payloads and not engine_from_error:
            self.scan_progress.emit(
                f"    ✓  {ptype}:{pname} — no SSTI indicators found"
            )
            return  # nothing found

        if len(hit_payloads) >= 2:
            confidence = "HIGH"
        elif len(hit_payloads) == 1 and engine_from_error:
            confidence = "HIGH"
        elif len(hit_payloads) == 1:
            confidence = "MEDIUM"
        else:
            # Only error-based detection
            confidence = "MEDIUM"

        # ── Phase 3: Engine fingerprinting ────────────────────────────────────
        self.scan_progress.emit(
            f"    [Phase 3] Engine fingerprinting "
            f"({len(_FINGERPRINT_PAYLOADS)} differentiator payloads)..."
        )
        identified_engine = engine_from_error  # start with error-based guess
        if hit_payloads:
            fp_engine = self._ssti_fingerprint(
                base_url=base_url, parsed_url=parsed_url,
                query_params=query_params, body_params=body_params,
                json_body=json_body, method=method, body_content=body_content,
                req_headers=req_headers, cookies=cookies, content_type=content_type,
                ptype=ptype, pname=pname, pval=pval, stats=stats,
            )
            if fp_engine:
                identified_engine = fp_engine
                self.scan_progress.emit(
                    f"        Engine identified: {fp_engine}"
                )
            else:
                self.scan_progress.emit(
                    "        Engine inconclusive from fingerprinting "
                    + (f"(using error hint: {engine_from_error})" if engine_from_error else "")
                )

        if not identified_engine and hit_payloads:
            # Derive a best-guess from the winning payload's engine list
            engines_sets = [p["engines"] for p in hit_payloads]
            identified_engine = engines_sets[0] if engines_sets else "Unknown"

        # ── Record finding ────────────────────────────────────────────────────
        stats["findings"] += 1
        _conf_icon = {"HIGH": "🔴", "MEDIUM": "⚠️", "LOW": "🔵"}.get(confidence, "•")
        self.scan_progress.emit(
            f"\n    {_conf_icon} [{confidence}] SSTI CONFIRMED — "
            f"{ptype}:{pname}  engine={identified_engine or 'Unknown'}  "
            f"hits={len(hit_payloads)}"
        )
        finding: Dict[str, Any] = {
            "parameter":        pname,
            "param_type":       ptype,
            "confidence":       confidence,
            "engine":           identified_engine or "Unknown",
            "hit_payloads":     hit_payloads,
            "error_engine":     engine_from_error,
            "original_value":   pval,
            "url":              base_url,
            "method":           method,
        }
        results["details"].append(finding)
        logger.info(
            "SSTI %s [%s] param=%s engine=%s confidence=%s",
            base_url, ptype, pname, identified_engine, confidence,
        )

    # ──────────────────────────────────────────────────────────────────────────
    # Engine fingerprinting
    # ──────────────────────────────────────────────────────────────────────────

    def _ssti_fingerprint(
        self,
        base_url, parsed_url, query_params, body_params, json_body,
        method, body_content, req_headers, cookies, content_type,
        ptype, pname, pval, stats,
    ) -> Optional[str]:
        """
        Fire engine-specific differentiator payloads and return the best-
        matching engine name, or None if inconclusive.
        """
        engine_votes: Dict[str, int] = {}

        for label, payload, expected, engine_name in _FINGERPRINT_PAYLOADS:
            if not self.running:
                break
            modified_val = pval + payload if pval else payload
            self.scan_progress.emit(
                f"      → [fp:{label}]  {payload!r}  → '{expected}' ({engine_name})"
            )
            resp_body = self._ssti_fire(
                base_url=base_url, parsed_url=parsed_url,
                query_params=query_params, body_params=body_params,
                json_body=json_body, method=method, body_content=body_content,
                req_headers=req_headers, cookies=cookies, content_type=content_type,
                ptype=ptype, pname=pname, payload=modified_val,
                payload_label=label, stats=stats,
            )
            if resp_body and _contains_result(resp_body, expected):
                self.scan_progress.emit(
                    f"        ✅ '{expected}' found — vote for {engine_name}"
                )
                engine_votes[engine_name] = engine_votes.get(engine_name, 0) + 1
            else:
                self.scan_progress.emit(f"        ✗ '{expected}' not found")

        if not engine_votes:
            return None
        winner = max(engine_votes, key=lambda k: engine_votes[k])
        return winner

    # ──────────────────────────────────────────────────────────────────────────
    # Request helper
    # ──────────────────────────────────────────────────────────────────────────

    def _ssti_fire(
        self,
        base_url:     str,
        parsed_url,
        query_params: Dict[str, List[str]],
        body_params:  Dict[str, str],
        json_body:    Dict[str, Any],
        method:       str,
        body_content: str,
        req_headers:  Dict[str, str],
        cookies:      Dict[str, str],
        content_type: str,
        ptype:        str,
        pname:        str,
        payload:      str,
        payload_label: str,
        stats:        Dict[str, Any],
    ) -> Optional[str]:
        """
        Build and fire a single request with *payload* injected into the
        injection point identified by (ptype, pname).

        Returns the decoded response body string, or None on error / timeout.
        """
        send_url     = base_url
        send_body    = body_content
        send_headers = dict(req_headers)
        send_cookies = dict(cookies)

        # ── Inject the payload ────────────────────────────────────────────────
        if ptype == "url":
            qp = dict(query_params)
            qp[pname] = [payload]
            new_qs  = urllib.parse.urlencode(qp, doseq=True)
            send_url = urllib.parse.urlunparse(
                parsed_url._replace(query=new_qs)
            )

        elif ptype in ("body", "form"):
            # Encode other params normally but keep the injection payload raw
            # so template engines receive {{7*7}} instead of %7B%7B7%2A7%7D%7D
            parts = []
            for k, v in body_params.items():
                enc_k = urllib.parse.quote_plus(str(k))
                if k == pname:
                    parts.append(f"{enc_k}={payload}")
                else:
                    parts.append(f"{enc_k}={urllib.parse.quote_plus(str(v))}")
            send_body = "&".join(parts)

        elif ptype == "json":
            try:
                obj = json.loads(body_content) if body_content else {}
            except Exception:
                obj = dict(json_body)
            obj[pname] = payload
            send_body  = json.dumps(obj)
            if "content-type" not in {k.lower() for k in send_headers}:
                send_headers["Content-Type"] = "application/json"

        elif ptype == "cookie":
            send_cookies[pname] = payload
            cookie_str = "; ".join(f"{k}={v}" for k, v in send_cookies.items())
            send_headers["Cookie"] = cookie_str

        elif ptype == "header":
            send_headers[pname] = payload

        # ── Fire ──────────────────────────────────────────────────────────────
        try:
            resp = self.send_request_with_traffic(
                url            = send_url,
                headers        = send_headers,
                method         = method,
                body           = send_body,
                payload        = payload,
                payload_type   = f"SSTI-{payload_label}",
                allow_redirects= True,
            )
            stats["payloads_sent"] += 1

            if resp is None or getattr(resp, "status_code", 0) == 0:
                return None

            # Prefer text; fall back to binary decode
            try:
                return resp.text
            except Exception:
                try:
                    return resp.content.decode("utf-8", errors="replace")
                except Exception:
                    return None

        except Exception as exc:
            logger.debug("SSTI request error (%s): %s", payload_label, exc)
            return None

    # ──────────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _ssti_snippet(body: str, result: str, context: int = 60) -> str:
        """Return a short excerpt of the body around *result* for the report."""
        decoded = _html_decode(body)
        idx = decoded.find(result)
        if idx == -1:
            idx = decoded.lower().find(result.lower())
        if idx == -1:
            return ""
        start = max(0, idx - context)
        end   = min(len(decoded), idx + len(result) + context)
        snippet = decoded[start:end].replace("\n", " ").replace("\r", "")
        if start > 0:
            snippet = "…" + snippet
        if end < len(decoded):
            snippet += "…"
        return snippet.strip()
