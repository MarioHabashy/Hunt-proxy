"""
Local File Inclusion scan methods
"""
"""
Shared imports for scan mixin modules.
"""
import os
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

# Path to the global settings file written by hunt_gui.py
_HUNT_SETTINGS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "HackRecon", "settings.json"
)

# SecLists-relative path for the LFI wordlist
_LFI_WORDLIST_REL = os.path.join("Fuzzing", "LFI", "LFI-Jhaddix.txt")


def _load_lfi_wordlist() -> List[str]:
    """
    Resolve the LFI wordlist as:
        <seclists_dir>/Fuzzing/LFI/LFI-Jhaddix.txt

    where <seclists_dir> is read from the global settings.json saved by
    hunt_gui.py (Tools -> Settings -> Seclists Directory).

    Returns an empty list on any error so the caller can handle gracefully.
    """
    # 1. Read seclists_dir from settings.json
    seclists_dir = ""
    try:
        with open(_HUNT_SETTINGS_FILE, "r") as f:
            settings = json.load(f)
        seclists_dir = settings.get("seclists_dir", "").strip()
    except FileNotFoundError:
        logger.warning(f"Hunt settings file not found: {_HUNT_SETTINGS_FILE}")
        return []
    except Exception as e:
        logger.warning(f"Error reading Hunt settings: {e}")
        return []

    if not seclists_dir:
        logger.warning(
            "seclists_dir is not configured. "
            "Set it in Hunt GUI -> Tools -> Settings -> Seclists Directory."
        )
        return []

    # 2. Build the full wordlist path
    wordlist_path = os.path.join(os.path.expanduser(seclists_dir), _LFI_WORDLIST_REL)

    # 3. Read payloads
    try:
        with open(wordlist_path, "r", errors="replace") as wl:
            payloads = [
                line.strip()
                for line in wl
                if line.strip() and not line.strip().startswith("#")
            ]
        if not payloads:
            logger.warning(f"LFI wordlist is empty: {wordlist_path}")
        return payloads
    except FileNotFoundError:
        logger.warning(f"LFI wordlist not found: {wordlist_path}")
        return []
    except Exception as e:
        logger.warning(f"Error reading LFI wordlist ({wordlist_path}): {e}")
        return []
    

class LfiScanMixin:
    """Mixin providing Local File Inclusion scan methods."""

    def scan_lfi(self) -> Dict[str, Any]:
        """
        Scan for LFI / Path Traversal vulnerabilities using a configurable wordlist.

        Supports all injection point types honoured via forced_injection_points:
          • URL query parameters  (default — all params)
          • POST / PUT body parameters  (default when present)
          • URL path segments     (opt-in via dialog)
          • Cookies               (opt-in via dialog)
          • HTTP headers          (opt-in via dialog)

        Each fuzz target is a dict:
            label     – display string shown in progress
            param     – parameter name (or None for bare-path fuzz)
            make_req  – callable(payload) → (url, headers_dict, body_str_or_None, http_method)
        """
        import posixpath
        import threading as _threading

        self.scan_progress.emit("🔍 Scanning for LFI / Path Traversal...")

        # Signatures that indicate successful file inclusion
        LFI_SIGNATURES = [
            # Unix /etc/passwd
            "root:x:0:0",
            "root:*:0:0",
            "/bin/bash",
            "/bin/sh",
            "nobody:x:",
            # Windows boot.ini / win.ini
            "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS",
            "[boot loader]",
            "[fonts]",
            # Apache / Nginx config leaks
            "AccessFileName",
            "RewriteEngine",
            "DirectoryIndex",
            "AuthUserFile",
            # Localhost loop (common in PHP include errors)
            "127.0.0.1",
        ]

        results: Dict[str, Any] = {
            "scan_type": "LFI",
            "vulnerable": False,
            "details": [],
            "fuzz_target": "",
            "summary": "",
            "stats": {"payloads_tested": 0, "matches": 0},
        }

        # ── Load wordlist ────────────────────────────────────────────────
        lfi_wordlist = _load_lfi_wordlist()
        if not lfi_wordlist:
            wordlist_path = os.path.join(
                os.path.expanduser("~"), "SecLists", _LFI_WORDLIST_REL
            )
            msg = (
                "LFI wordlist could not be loaded.\n"
                f"    Settings file : {_HUNT_SETTINGS_FILE}\n"
                f"    Expected path : <seclists_dir>/{_LFI_WORDLIST_REL}\n"
                "    Set 'Seclists Directory' in Hunt GUI -> Tools -> Settings."
            )
            self.scan_progress.emit(msg)
            results["summary"] = "LFI scan skipped — wordlist not loaded."
            results["error"] = (
                f"Wordlist missing. Configure seclists_dir in {_HUNT_SETTINGS_FILE}"
            )
            return results

        self.scan_progress.emit(f"📂 Loaded LFI wordlist: {len(lfi_wordlist)} payloads")

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                return {"scan_type": "LFI", "error": "No URL provided"}

            # ── Parse request ────────────────────────────────────────────
            request_text = self.request_data.get("request_text", "")
            lines = request_text.split("\n")
            headers: Dict[str, str] = {}
            cookies: Dict[str, str] = {}
            body_content = ""
            seen_cookie_key = None

            body_started = False
            for idx, line in enumerate(lines[1:], 1):
                if body_started:
                    break
                stripped = line.strip()
                if not stripped or stripped == "\r\n":
                    body_started = True
                    body_content = "\n".join(lines[idx + 1:])
                    break
                if ":" in line:
                    key, value = line.split(":", 1)
                    key, value = key.strip(), value.strip()
                    if key.lower() == "cookie":
                        if seen_cookie_key is not None:
                            continue          # skip duplicate Cookie header
                        seen_cookie_key = key
                        # Split on '; ' (RFC standard), then also on ', ' before next name=
                        raw_pairs = re.split(r';\s*', value)
                        expanded = []
                        for piece in raw_pairs:
                            sub = re.split(r',\s+(?=\w[^=]*=)', piece)
                            expanded.extend(s.strip() for s in sub if s.strip())
                        for pair in expanded:
                            if "=" in pair:
                                cname, cval = pair.split("=", 1)
                                cookies[cname.strip()] = cval.strip()
                    headers[key] = value

            # Detect HTTP method
            method = "GET"
            if lines:
                fl = lines[0].strip().upper()
                for m in ("POST", "PUT", "PATCH"):
                    if fl.startswith(m):
                        method = m
                        break

            # Parse body parameters
            body_params: Dict[str, str] = {}
            if method in ("POST", "PUT", "PATCH") and body_content.strip():
                ct = headers.get("Content-Type", "").lower()
                if "application/json" in ct:
                    try:
                        jdata = json.loads(body_content.strip())
                        if isinstance(jdata, dict):
                            body_params = {k: str(v) for k, v in jdata.items()}
                    except Exception:
                        pass
                elif "multipart/form-data" not in ct:
                    try:
                        parsed_body = urllib.parse.parse_qs(
                            body_content.strip(), keep_blank_values=True
                        )
                        body_params = {k: v[0] if v else "" for k, v in parsed_body.items()}
                    except Exception:
                        pass

            # Base headers — no Host, no Cookie (rebuilt per-request when needed)
            base_headers = {k: v for k, v in headers.items()
                            if k.lower() not in ("host", "cookie")}

            # Cookie header string for requests that don't inject into cookies
            def _cookie_hdr(ck: Dict[str, str]) -> Dict[str, str]:
                """Return a copy of base_headers with the Cookie header re-attached."""
                h = dict(base_headers)
                if ck:
                    h["Cookie"] = "; ".join(f"{k}={v}" for k, v in ck.items())
                return h

            # Headers with cookies attached (used for URL/body/header targets)
            full_headers = _cookie_hdr(cookies)

            # ── Parse URL ────────────────────────────────────────────────
            parsed   = urllib.parse.urlparse(full_url)
            params   = urllib.parse.parse_qs(parsed.query)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

            # ── Build fuzz targets ───────────────────────────────────────
            # Each entry: {"label": str, "param": str|None, "make_req": callable}
            # make_req(payload) → (url, headers_dict, body_or_None, method_str)
            fuzz_targets: List[Dict] = []

            # ── 1. URL query parameters ──────────────────────────────────
            if params:
                for param_name, param_values in params.items():
                    if not self._is_forced_point("url", param_name):
                        self.scan_progress.emit(f"⏭️  Skipping URL param '{param_name}' (not selected)")
                        continue
                    param_value = param_values[0]

                    if param_value.startswith("/"):
                        # Path-like value — preserve directory prefix
                        dir_path    = posixpath.dirname(param_value)
                        fuzz_prefix = "/" if dir_path == "/" else dir_path + "/"
                        self.scan_progress.emit(
                            f"[+] Path-aware fuzzing for '{param_name}': {fuzz_prefix}FUZZ"
                        )
                        def _make_path_url(pl, pn=param_name, fp=fuzz_prefix,
                                           ps=params.copy(), bu=base_url, fh=full_headers):
                            other = {k: v for k, v in ps.items() if k != pn}
                            qs    = urllib.parse.urlencode(other, doseq=True)
                            raw   = f"{pn}={fp}{pl}"
                            url   = f"{bu}?{raw}&{qs}" if qs else f"{bu}?{raw}"
                            return url, fh, None, "GET"
                        fuzz_targets.append({
                            "label": f"📍 URL param: {param_name} (path-aware)",
                            "param": param_name,
                            "make_req": _make_path_url,
                        })
                    else:
                        self.scan_progress.emit(f"[+] Standard fuzzing for '{param_name}'")
                        def _make_param_url(pl, pn=param_name,
                                            ps=params.copy(), bu=base_url, fh=full_headers):
                            other = {k: v for k, v in ps.items() if k != pn}
                            qs    = urllib.parse.urlencode(other, doseq=True)
                            raw   = f"{pn}={pl}"
                            url   = f"{bu}?{raw}&{qs}" if qs else f"{bu}?{raw}"
                            return url, fh, None, "GET"
                        fuzz_targets.append({
                            "label": f"📍 URL param: {param_name}",
                            "param": param_name,
                            "make_req": _make_param_url,
                        })
            else:
                # No query params — fuzz path directly (always, no forced_injection_points gate)
                self.scan_progress.emit("[+] No URL parameters — fuzzing path directly")
                def _make_path_fuzz(pl, bu=base_url, fh=full_headers):
                    return f"{bu.rstrip('/')}/{pl}", fh, None, "GET"
                fuzz_targets.append({
                    "label": "🛣️  Path fuzz",
                    "param": None,
                    "make_req": _make_path_fuzz,
                })

            # ── 2. POST / body parameters (default when present) ─────────
            for param_name, param_value in body_params.items():
                if not self._is_forced_point("body", param_name):
                    self.scan_progress.emit(f"⏭️  Skipping body param '{param_name}' (not selected)")
                    continue
                self.scan_progress.emit(f"[+] Body param fuzzing for '{param_name}'")
                ct      = headers.get("Content-Type", "").lower()
                is_json = "application/json" in ct

                def _make_body_req(pl, pn=param_name, bp=dict(body_params),
                                   fu=full_url, fh=full_headers,
                                   json_mode=is_json, meth=method):
                    test_bp = dict(bp)
                    test_bp[pn] = pl
                    body_str = (
                        json.dumps(test_bp) if json_mode
                        else urllib.parse.urlencode(test_bp)
                    )
                    return fu, fh, body_str, meth
                fuzz_targets.append({
                    "label": f"📮 Body param: {param_name}",
                    "param": param_name,
                    "make_req": _make_body_req,
                })

            # ── 3. URL path segments (opt-in only) ───────────────────────
            _ID_RE_LFI = re.compile(
                r'^(?:'
                r'\d+'
                r'|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                r'|[0-9a-fA-F]{24,}'
                r'|[A-Za-z0-9_-]{8,}'
                r'|v\d+(?:\.\d+)*'
                r')$'
            )
            path_segs = [s for s in parsed.path.split("/") if s]
            for seg_idx, seg_val in enumerate(path_segs):
                if not _ID_RE_LFI.match(seg_val):
                    continue
                if not self._is_forced_point("path", f"{seg_idx}:{seg_val}"):
                    continue  # path segments never tested by default — opt-in only
                self.scan_progress.emit(f"[+] Path segment fuzzing: [{seg_idx}] = {seg_val}")
                def _make_seg_req(pl, segs=list(path_segs), sidx=seg_idx,
                                  ps_obj=parsed, fh=full_headers):
                    new_segs = list(segs)
                    new_segs[sidx] = urllib.parse.quote(pl, safe='')
                    new_path = "/" + "/".join(new_segs)
                    url = urllib.parse.urlunparse((
                        ps_obj.scheme, ps_obj.netloc, new_path,
                        ps_obj.params, ps_obj.query, ps_obj.fragment
                    ))
                    return url, fh, None, "GET"
                fuzz_targets.append({
                    "label": f"🛣️  Path segment [{seg_idx}]: {seg_val}",
                    "param": f"path[{seg_idx}]",
                    "make_req": _make_seg_req,
                })

            # ── 4. Cookies (opt-in only) ─────────────────────────────────
            for cookie_name, cookie_value in cookies.items():
                if not self._is_forced_point("cookie", cookie_name):
                    continue  # cookies never tested by default for LFI — opt-in only
                self.scan_progress.emit(f"[+] Cookie fuzzing: {cookie_name}")
                def _make_cookie_req(pl, cn=cookie_name, ck=dict(cookies),
                                     bh=base_headers, fu=full_url, meth=method):
                    test_ck = dict(ck)
                    test_ck[cn] = pl
                    req_headers = dict(bh)
                    req_headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in test_ck.items())
                    return fu, req_headers, None, meth
                fuzz_targets.append({
                    "label": f"🍪 Cookie: {cookie_name}",
                    "param": cookie_name,
                    "make_req": _make_cookie_req,
                })

            # ── 5. HTTP headers (opt-in only) ────────────────────────────
            for header_name, header_value in headers.items():
                if header_name.lower() in ("host", "cookie", "content-length",
                                           "transfer-encoding", "connection"):
                    continue
                if not self._is_forced_point("header", header_name):
                    continue  # headers never tested by default for LFI — opt-in only
                self.scan_progress.emit(f"[+] Header fuzzing: {header_name}")
                def _make_header_req(pl, hn=header_name, fh=full_headers, fu=full_url, meth=method):
                    req_headers = dict(fh)
                    req_headers[hn] = pl
                    return fu, req_headers, None, meth
                fuzz_targets.append({
                    "label": f"📋 Header: {header_name}",
                    "param": header_name,
                    "make_req": _make_header_req,
                })

            if not fuzz_targets:
                self.scan_progress.emit("⚠️  No injection points to test — check your selection.")
                results["summary"] = "LFI scan skipped — no testable injection points."
                return results

            results["fuzz_target"] = ", ".join(ft["label"] for ft in fuzz_targets)
            total_requests = len(fuzz_targets) * len(lfi_wordlist)

            self.scan_progress.emit(
                f"[*] LFI scan started | Targets: {len(fuzz_targets)} point(s) "
                f"| Payloads: {len(lfi_wordlist)} | Total requests: {total_requests}"
                + (" | ⚡ Boost mode" if self.boost_mode else "")
            )

            # ── Fire requests ────────────────────────────────────────────
            for t_idx, fuzz_target in enumerate(fuzz_targets, 1):
                target_label = fuzz_target["label"]
                target_param = fuzz_target["param"]
                make_req     = fuzz_target["make_req"]

                self.scan_progress.emit(
                    f"\n📂 Fuzzing target {t_idx}/{len(fuzz_targets)}: {target_label}"
                )

                if self.boost_mode:
                    _cancel_evt = _threading.Event()

                    def _lfi_worker(payload, _cancel=_cancel_evt,
                                    _mk=make_req, _lbl=target_label):
                        if _cancel.is_set():
                            return None
                        url, hdrs, body, meth = _mk(payload)
                        return self._send_lfi_payload(
                            url, hdrs, payload, _lbl, LFI_SIGNATURES,
                            body=body, method=meth
                        )

                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=getattr(self, "scan_max_workers", 8)
                    ) as executor:
                        future_map = {}
                        for payload in lfi_wordlist:
                            if not self.running or _cancel_evt.is_set():
                                break
                            future_map[executor.submit(_lfi_worker, payload)] = payload

                        for future in concurrent.futures.as_completed(future_map):
                            if not self.running:
                                _cancel_evt.set()
                                break
                            if results["vulnerable"] and self.scan_stop_on_first:
                                _cancel_evt.set()
                                self.scan_progress.emit(
                                    "  ⏭️  Stop-on-first: LFI confirmed — cancelling remaining payloads"
                                )
                                break
                            try:
                                hit = future.result(timeout=30)
                                results["stats"]["payloads_tested"] += 1
                                if hit:
                                    results["vulnerable"] = True
                                    results["stats"]["matches"] += 1
                                    results["details"].append({
                                        "target":            target_label,
                                        "parameter":         target_param or "path",
                                        "payload":           hit["payload"],
                                        "matched_signature": hit["matched_sig"],
                                        "status_code":       hit["status_code"],
                                        "response_length":   hit["response_length"],
                                        "test_url":          hit["test_url"],
                                    })
                                    self.scan_progress.emit(
                                        f"  ⚠️  LFI FOUND! Matched: '{hit['matched_sig']}' | "
                                        f"Payload: {hit['payload']}"
                                    )
                                    if self.scan_stop_on_first:
                                        _cancel_evt.set()
                            except Exception as e:
                                self.scan_progress.emit(f"  ✗ Error: {str(e)[:60]}")

                else:
                    # ── Sequential ────────────────────────────────────────
                    for payload in lfi_wordlist:
                        if not self.running:
                            break
                        if results["vulnerable"] and self.scan_stop_on_first:
                            self.scan_progress.emit(
                                "  ⏭️  Stop-on-first: LFI confirmed — stopping payload loop"
                            )
                            break

                        results["stats"]["payloads_tested"] += 1
                        url, hdrs, body, meth = make_req(payload)

                        hit = self._send_lfi_payload(
                            url, hdrs, payload, target_label, LFI_SIGNATURES,
                            body=body, method=meth
                        )
                        if hit:
                            results["vulnerable"] = True
                            results["stats"]["matches"] += 1
                            results["details"].append({
                                "target":            target_label,
                                "parameter":         target_param or "path",
                                "payload":           hit["payload"],
                                "matched_signature": hit["matched_sig"],
                                "status_code":       hit["status_code"],
                                "response_length":   hit["response_length"],
                                "test_url":          hit["test_url"],
                            })
                            self.scan_progress.emit(
                                f"  ⚠️  LFI FOUND! Matched: '{hit['matched_sig']}' | "
                                f"Payload: {payload}"
                            )

        except Exception as e:
            logger.error(f"LFI scan error: {e}")
            results["error"] = str(e)

        if results["vulnerable"]:
            n = len(results["details"])
            results["summary"] = f"LFI/Path Traversal detected! {n} payload(s) confirmed."
        else:
            results["summary"] = "No LFI/Path Traversal vulnerabilities detected."

        return results

    def _send_lfi_payload(self, test_url: str, headers: dict,
                          payload: str, target_label: str,
                          signatures: List[str],
                          body: Optional[str] = None,
                          method: str = "GET") -> Optional[Dict[str, Any]]:
        """
        Send a single LFI payload and check the response for file-inclusion
        signatures.  Returns a hit-dict on match, None otherwise.

        Uses raw_url=True so pre-encoded traversal payloads are sent verbatim.
        Supports GET, POST, PUT, PATCH via the method/body parameters.
        Safe to call from a ThreadPoolExecutor.
        """
        try:
            kwargs: Dict[str, Any] = dict(
                headers=headers,
                method=method,
                payload=payload,
                payload_type=f"LFI-{target_label}",
                raw_url=True,
            )
            if body is not None:
                kwargs["body"] = body

            response = self.send_request_with_traffic(test_url, **kwargs)
            if response and hasattr(response, "text"):
                matched_sig = next(
                    (sig for sig in signatures if sig in response.text),
                    None
                )
                if matched_sig:
                    return {
                        "payload":         payload,
                        "matched_sig":     matched_sig,
                        "status_code":     getattr(response, "status_code", "?"),
                        "response_length": len(getattr(response, "content", b"")),
                        "test_url":        test_url,
                    }
        except Exception as e:
            logger.debug(f"LFI payload error ({payload[:40]}): {e}")
        return None