"""
Insecure Direct Object Reference scan methods
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



class IdorScanMixin:
    """Mixin providing Insecure Direct Object Reference scan methods."""

    def scan_idor(self) -> Dict[str, Any]:
        """
        Scan for Insecure Direct Object Reference (IDOR) vulnerabilities.

        Detection strategy
        ──────────────────
        For each injection point (URL param, POST body, path segment, cookie):
          1. Send a BASELINE request — record status, length, body fingerprint.
          2. Generate CANDIDATES — type-aware mutations of the original value.
          3. Send each candidate using the SAME session cookies / auth headers
             (horizontal IDOR: your account accessing another account's object).
          4. Send multiple candidates with auth headers STRIPPED
             (vertical / unauthenticated IDOR: no-auth access to any object).
          5. COMPARE responses:
               • 4xx/5xx → 2xx  ................................ HIGH   (access gained)
               • 200 → 200 + length Δ ≥ 10%  .................. MEDIUM (different data)
               • 200 → 200 + ID value reflected & changed  ..... MEDIUM (own-vs-other)
               • 200 → 200 + JSON fields changed  .............. MEDIUM (data swap)
               • Unauth 2xx when authed baseline was 4xx  ...... HIGH   (missing auth)
               • Unauth 2xx when authed baseline was 2xx  ...... MEDIUM (auth not enforced)

        Additional test cases (from OWASP / real-world methodology)
        ─────────────────────────────────────────────────────────────
          TC-1   Inject absent ID params  — try common id param names not in original request
          TC-2   Alternative param names  — swap param name with synonyms (album_id→account_id)
          TC-3   HTTP Parameter Pollution — duplicate param: ?id=<yours>&id=<other>
          TC-3b  HPP array-style          — ?id[]=<yours>&id[]=<other> (PHP/Rails)
          TC-4   Active method switching  — replay with PUT / DELETE / PATCH
          TC-5   Content-Type switching   — replay POST with json↔xml↔form-urlencoded
          TC-6   File extension appending — append .json/.xml/.config to path
          TC-7   Numeric ID substitution  — already handled via integer/uuid vtype
          TC-8   Array wrapping           — {"id":19} → {"id":[19]}
          TC-9   Wildcard ID              — /api/users/* and null/undefined sentinels
          TC-10  JSON nested object wrap  — {"id":111} → {"id":{"id":111}}
          TC-11  JSON Parameter Pollution — {"user_id":<legit>,"user_id":<victim>}
          TC-12  Outdated API version     — /v3/users/123 → /v1/users/123
          TC-13  Admin path segment swap  — /api/users/myinfo → /api/admins/myinfo

        Supported value types
        ─────────────────────
          integer    — ±1…20, boundary values (0, 1, -1, 99999, MAX_INT)
          uuid       — increment last octet, nil UUID, sequential variants
          base64     — decode → mutate interior integer / user field → re-encode
          composite  — structured IDs like ACC-00123, ORD_456 (numeric component mutated)
          slug/name  — common admin / test usernames + wildcard probes
          path seg   — path components extracted and mutated
        """

        self.scan_progress.emit("🔑 Scanning for IDOR vulnerabilities...")

        results: Dict[str, Any] = {
            "scan_type":  "IDOR",
            "vulnerable": False,
            "details":    [],
            "summary":    "",
            "stats": {
                "points_tested":    0,
                "candidates_sent":  0,
                "high_confidence":  0,
                "medium_confidence": 0,
            },
        }

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                results["summary"] = "No URL provided."
                return results

            # ── Parse raw request ─────────────────────────────────────────
            request_text = self.request_data.get("request_text", "")
            req_lines    = request_text.split("\n")
            method       = "GET"
            headers: Dict[str, str] = {}
            cookies: Dict[str, str] = {}
            body_content = ""
            body_params: Dict[str, List[str]] = {}
            seen_cookie  = None

            # Detect HTTP method from first request line (GET/POST/PUT/DELETE/PATCH)
            if req_lines:
                first = req_lines[0].strip().upper()
                for _m in ("POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                    if first.startswith(_m):
                        method = _m
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
            ct = headers.get("Content-Type", "").lower()
            if method in ("POST", "PUT", "PATCH") and body_content:
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

            # base_headers — no Host, no Cookie (Cookie rebuilt per-request)
            base_headers = {k: v for k, v in headers.items()
                            if k.lower() not in ("host", "cookie")}

            # clean_headers — base + Cookie header re-attached (used for non-cookie targets)
            clean_headers = dict(base_headers)
            if cookies:
                clean_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in cookies.items()
                )

            # Auth-stripped headers — remove Cookie + Authorization + token headers
            AUTH_STRIP = {"cookie", "authorization", "x-auth-token",
                          "x-api-key", "token", "bearer"}
            unauth_headers = {k: v for k, v in base_headers.items()
                              if k.lower() not in AUTH_STRIP}

            # ── Build injection points ────────────────────────────────────
            points: List[Dict[str, Any]] = []

            # 1. URL query params
            for name, vals in params.items():
                val = vals[0] if vals else ""
                vtype = self._idor_value_type(val)
                
                is_forced = self._is_forced_point("url", name)
                should_test = False
                if self.forced_injection_points is not None:
                    should_test = is_forced
                else:
                    should_test = (vtype != "skip")

                if should_test:
                    points.append({
                        "name": name, "value": val, "type": "url_param",
                        "vtype": vtype if vtype != "skip" else "forced",
                    })

            # 2. POST body params (skip CSRF / token fields)
            for name, vals in body_params.items():
                val = vals[0] if vals else ""
                vtype = self._idor_value_type(val)
                
                is_forced = self._is_forced_point("body", name)
                heuristic_ok, _ = self._should_test_body_param(name, val)
                
                should_test = False
                if self.forced_injection_points is not None:
                    should_test = is_forced
                else:
                    should_test = heuristic_ok and (vtype != "skip")

                if should_test:
                    points.append({
                        "name": name, "value": val, "type": "post_param",
                        "vtype": vtype if vtype != "skip" else "forced",
                    })

            # 3. Path segments — honour forced_injection_points; auto-detect when no override
            path_parts = [p for p in parsed.path.split("/") if p]
            for idx, part in enumerate(path_parts):
                vtype = self._idor_value_type(part)
                is_forced    = self._is_forced_point("path", f"{idx}:{part}")
                # When user has made a selection, only include forced points.
                # When no override, use heuristic (non-skip vtypes).
                if self.forced_injection_points is not None:
                    should_test = is_forced
                else:
                    should_test = (vtype != "skip")
                if should_test:
                    points.append({
                        "name": f"path[{idx}]", "value": part,
                        "type": "path_seg", "path_index": idx,
                        "vtype": vtype if vtype != "skip" else "forced",
                        "path_parts": path_parts,
                    })

            # 4. Cookies (skip session / CSRF tokens via _should_test_cookie)
            for name, val in cookies.items():
                vtype = self._idor_value_type(val)
                
                is_forced = self._is_forced_point("cookie", name)
                heuristic_ok, _ = self._should_test_cookie(name, val)
                
                should_test = False
                if self.forced_injection_points is not None:
                    should_test = is_forced
                else:
                    should_test = heuristic_ok and (vtype != "skip")

                if should_test:
                    points.append({
                        "name": name, "value": val, "type": "cookie",
                        "vtype": vtype if vtype != "skip" else "forced",
                    })

            # 5. Custom ID headers — e.g. X-Client-ID, X-User-ID, X-Account-ID
            _ID_HEADER_PATTERNS = re.compile(
                r"(^|[-_])(id|uid|user|account|client|customer|member|owner|"
                r"profile|record|object|resource|tenant|org|session_user)s?$",
                re.IGNORECASE,
            )
            _SKIP_HEADERS_LC = {
                "authorization", "x-auth-token", "x-api-key", "x-csrf-token",
                "x-xsrf-token", "x-forwarded-for", "x-forwarded-host",
                "x-forwarded-proto", "x-real-ip", "x-request-id",
                "x-correlation-id", "x-trace-id", "x-b3-traceid",
                "content-type", "content-length", "accept", "accept-encoding",
                "accept-language", "cache-control", "connection", "host",
                "origin", "referer", "user-agent", "cookie", "transfer-encoding",
            }
            existing_header_names_lc = set()

            # 5a. Scan headers already present in the request
            for hname, hval in headers.items():
                hname_lc = hname.lower()
                vtype = self._idor_value_type(hval)
                
                is_forced = self._is_forced_point("header", hname)
                
                should_test = False
                if self.forced_injection_points is not None:
                    should_test = is_forced
                else:
                    # Auto heuristics
                    if hname_lc not in _SKIP_HEADERS_LC and \
                       _ID_HEADER_PATTERNS.search(hname_lc) and \
                       vtype != "skip":
                        should_test = True

                if should_test:
                    existing_header_names_lc.add(hname_lc)
                    points.append({
                        "name":       hname,
                        "value":      hval,
                        "type":       "req_header",
                        "vtype":      vtype if vtype != "skip" else "forced",
                        "orig_headers": headers,
                    })

            # 5b. Inject common ID header names not present in the request
            # Only inject phantom headers when no forced_injection_points override —
            # injected headers were never in the dialog selection so they must not
            # be added when the user has made an explicit choice.
            if self.forced_injection_points is None:
                _COMMON_ID_HEADERS = [
                    "X-User-ID",    "X-UserId",      "X-Account-ID",  "X-AccountId",
                    "X-Client-ID",  "X-ClientId",    "X-Customer-ID", "X-CustomerId",
                    "X-Member-ID",  "X-MemberId",    "X-Owner-ID",    "X-OwnerId",
                    "X-Profile-ID", "X-ProfileId",   "X-Tenant-ID",   "X-TenantId",
                    "X-Org-ID",     "X-OrgId",       "X-Resource-ID", "X-ResourceId",
                    "X-Object-ID",  "X-ObjectId",    "X-Entity-ID",   "X-EntityId",
                ]
                for inj_hdr in _COMMON_ID_HEADERS:
                    if inj_hdr.lower() not in existing_header_names_lc:
                        points.append({
                            "name":         inj_hdr,
                            "value":        "1",
                            "type":         "req_header",
                            "vtype":        "integer",
                            "injected":     True,
                            "orig_headers": headers,
                        })

            # ── TC-1: Inject common ID params absent from the original request ──
            # Only inject phantom params in default (no-override) mode — the user's
            # explicit selection in the dialog cannot include params that don't exist.
            if self.forced_injection_points is None:
                COMMON_INJECT_PARAMS = [
                    "id", "user_id", "uid", "userId", "account_id", "accountId",
                    "profile_id", "profileId", "object_id", "objectId",
                    "record_id", "recordId", "item_id", "itemId",
                    "resource_id", "resourceId", "owner_id", "ownerId",
                    "member_id", "memberId", "customer_id", "customerId",
                    "order_id", "orderId", "invoice_id", "invoiceId",
                    "doc_id", "docId", "file_id", "fileId",
                ]
                existing_param_names_lc = {p["name"].lower() for p in points}
                existing_url_params_lc  = {k.lower() for k in params}
                for inj_name in COMMON_INJECT_PARAMS:
                    if (inj_name.lower() not in existing_param_names_lc
                            and inj_name.lower() not in existing_url_params_lc):
                        points.append({
                            "name": inj_name, "value": "1",
                            "type": "url_param", "vtype": "integer",
                            "injected": True,
                        })

            # ── TC-2: Alternative parameter name substitution ─────────────────
            # Only in default mode — synonyms are phantom params the dialog can't show.
            if self.forced_injection_points is None:
                PARAM_SYNONYMS: Dict[str, List[str]] = {
                    "id":          ["user_id", "account_id", "uid", "object_id", "record_id"],
                    "user_id":     ["id", "uid", "account_id", "userId", "member_id", "profile_id"],
                    "account_id":  ["id", "user_id", "uid", "profile_id", "owner_id"],
                    "album_id":    ["id", "collection_id", "resource_id", "object_id"],
                    "profile_id":  ["id", "user_id", "uid", "account_id"],
                    "order_id":    ["id", "invoice_id", "transaction_id", "record_id"],
                    "invoice_id":  ["id", "order_id", "doc_id", "record_id"],
                    "file_id":     ["id", "doc_id", "resource_id", "object_id"],
                    "item_id":     ["id", "product_id", "object_id", "resource_id"],
                    "customer_id": ["id", "user_id", "account_id", "client_id"],
                    "post_id":     ["id", "article_id", "entry_id", "resource_id"],
                    "message_id":  ["id", "chat_id", "thread_id", "conversation_id"],
                }
                all_existing_names_lc = {p["name"].lower() for p in points}
                for name_key, vals in params.items():
                    val = vals[0] if vals else ""
                    vtype = self._idor_value_type(val)
                    if vtype == "skip":
                        continue
                    for synonym in PARAM_SYNONYMS.get(name_key.lower(), []):
                        if (synonym.lower() not in all_existing_names_lc
                                and synonym not in params):
                            points.append({
                                "name": synonym, "value": val,
                                "type": "url_param", "vtype": vtype,
                                "synonym_of": name_key,
                            })
                            all_existing_names_lc.add(synonym.lower())

            if not points:
                results["summary"] = (
                    "No testable IDOR parameters found "
                    "(no integers, UUIDs, base64 IDs, or slugs detected)."
                )
                self.scan_progress.emit(f"  ℹ️  {results['summary']}")
                return results

            self.scan_progress.emit(
                f"[*] IDOR scan | Points: {len(points)} | "
                f"Boost: {'ON' if self.boost_mode else 'OFF'}"
            )
            for p in points:
                tag = ""
                if p.get("injected"):
                    tag = " [TC-1:injected]"
                elif p.get("synonym_of"):
                    tag = f" [TC-2:synonym of {p['synonym_of']}]"
                self.scan_progress.emit(
                    f"  → [{p['type']}] {p['name']} = '{p['value']}' ({p['vtype']}){tag}"
                )

            # ── Helper: build URL / body for a given substitution ─────────
            def _build(point: Dict, new_val: str) -> Tuple[str, str, dict]:
                """Return (url, body, headers_to_use) with new_val substituted.
                Handles: url_param, post_param, path_seg, req_header, cookie.
                """
                if point["type"] == "url_param":
                    tp = params.copy()
                    tp[point["name"]] = [new_val]
                    qs = urllib.parse.urlencode(tp, doseq=True)
                    return f"{base_url}?{qs}", "", clean_headers

                elif point["type"] == "post_param":
                    tb = body_params.copy()
                    tb[point["name"]] = [new_val]
                    if "application/json" in ct:
                        body = json.dumps({k: v[0] for k, v in tb.items()})
                    else:
                        body = urllib.parse.urlencode(tb, doseq=True)
                    return full_url, body, clean_headers

                elif point["type"] == "path_seg":
                    parts = list(point["path_parts"])
                    parts[point["path_index"]] = new_val
                    new_path = "/" + "/".join(parts)
                    rebuilt = urllib.parse.urlunparse((
                        parsed.scheme, parsed.netloc, new_path,
                        parsed.params, parsed.query, ""
                    ))
                    return rebuilt, "", clean_headers

                elif point["type"] == "req_header":
                    # Replace the named header with new_val (inject if absent)
                    h = clean_headers.copy()
                    h[point["name"]] = new_val
                    return full_url, body_content, h

                else:  # cookie — use base_headers (no Cookie) then rebuild cleanly
                    test_cookies = dict(cookies)
                    test_cookies[point["name"]] = new_val
                    h = dict(base_headers)
                    h["Cookie"] = "; ".join(
                        f"{k}={v}" for k, v in test_cookies.items()
                    )
                    return full_url, "", h

            def _structural_diff(baseline_text: str, resp_text: str) -> Optional[str]:
                """
                Detect data-swap IDOR where response length stays similar
                but underlying data changed (e.g. different user's email/name).
                Returns a reason string on detection, None otherwise.
                """
                # JSON structural diff
                try:
                    b_json = json.loads(baseline_text)
                    r_json = json.loads(resp_text)
                    if isinstance(b_json, dict) and isinstance(r_json, dict):
                        # Normalise key to snake_case for noise filtering
                        def _normalise(k: str) -> str:
                            # camelCase → lower snake: requestId → requestid
                            return re.sub(r'[_\-]', '', k.lower())

                        _NOISE_KEYS_NORM = {
                            "timestamp", "token", "nonce", "csrf",
                            "expires", "expiry", "date", "time",
                            "requestid", "traceid", "session",
                            "lastmodified", "updatedat", "createdat",
                            "lastseen", "accessedat",
                        }
                        changed = [
                            k for k in b_json
                            if (k in r_json
                                and str(b_json[k]) != str(r_json[k])
                                and _normalise(k) not in _NOISE_KEYS_NORM
                                and b_json[k] not in (None, "", [], {}))
                        ]
                        if changed:
                            return (
                                f"JSON fields changed with mutated ID "
                                f"(fields: {changed[:5]})"
                            )
                except (json.JSONDecodeError, TypeError, ValueError):
                    pass
                return None

            # ── Detection helper ──────────────────────────────────────────
            def _compare(baseline: Dict, resp, candidate: str,
                         original: str, unauth: bool = False,
                         probe_tag: str = "") -> Optional[Dict]:
                """
                Compare resp against baseline.
                Returns a finding dict or None.
                """
                if not resp or not hasattr(resp, "status_code"):
                    return None

                sc    = getattr(resp, "status_code", 0) or 0
                bsc   = baseline["status"]
                blen  = baseline["length"]
                rlen  = len(getattr(resp, "content", b""))
                rtext = getattr(resp, "text", "") or ""
                b_text = baseline["text"]

                # Ignore rate-limit responses — don't flag as findings
                if sc == 429:
                    self.scan_progress.emit(
                        "  ⚠️  Rate-limited (429) — slow down or pause"
                    )
                    return None

                # Identical response — definitely not IDOR (saves false positives)
                if sc == bsc and rlen == blen and rtext == b_text:
                    return None

                confidence = None
                reason     = ""
                prefix     = f"[{probe_tag}] " if probe_tag else ""

                if unauth:
                    # Unauthenticated probe
                    if bsc in (401, 403) and 200 <= sc < 300:
                        confidence = "HIGH"
                        reason = (
                            f"{prefix}Unauthenticated access granted "
                            f"(baseline={bsc} → unauth={sc})"
                        )
                    elif bsc < 400 and 200 <= sc < 300:
                        confidence = "MEDIUM"
                        reason = (
                            f"{prefix}Endpoint accessible without auth "
                            f"(unauth={sc}, authed={bsc})"
                        )
                else:
                    # Authenticated probe with different ID
                    if bsc in (401, 403, 404) and 200 <= sc < 300:
                        confidence = "HIGH"
                        reason = (
                            f"{prefix}Access state changed: baseline={bsc} "
                            f"→ candidate={sc} for value '{candidate}'"
                        )
                    elif bsc == sc == 200 and blen > 0:
                        len_delta = abs(rlen - blen)
                        pct_delta = len_delta / blen * 100
                        if pct_delta >= 10 and len_delta >= 50:
                            confidence = "MEDIUM"
                            reason = (
                                f"{prefix}Response length changed significantly "
                                f"({blen}b → {rlen}b, Δ{len_delta}b / {pct_delta:.1f}%) "
                                f"for value '{candidate}'"
                            )
                        elif len_delta >= 200:
                            confidence = "MEDIUM"
                            reason = (
                                f"{prefix}Large response length delta "
                                f"({blen}b → {rlen}b, Δ{len_delta}b) "
                                f"for value '{candidate}'"
                            )

                    # Structural / JSON semantic diff
                    if confidence is None and bsc == sc == 200:
                        sdiff = _structural_diff(b_text, rtext)
                        if sdiff:
                            confidence = "MEDIUM"
                            reason = f"{prefix}{sdiff} for value '{candidate}'"

                    # Reflected value changed in body
                    if confidence is None and bsc == sc == 200:
                        orig_in_base = original in b_text
                        cand_in_resp = candidate in rtext
                        orig_in_resp = original in rtext
                        if orig_in_base and cand_in_resp and not orig_in_resp:
                            confidence = "MEDIUM"
                            reason = (
                                f"{prefix}Original value '{original}' replaced by "
                                f"'{candidate}' in response body"
                            )

                if confidence:
                    return {
                        "confidence":      confidence,
                        "reason":          reason,
                        "candidate":       candidate,
                        "original":        original,
                        "unauth":          unauth,
                        "status_code":     sc,
                        "baseline_status": bsc,
                        "length":          rlen,
                        "baseline_length": blen,
                        "probe_tag":       probe_tag,
                    }
                return None

            # ── Helper: record a finding ──────────────────────────────────
            def _record(finding: Dict, param_name: str,
                        param_type: str, url: str):
                finding.update({
                    "parameter":  param_name,
                    "param_type": param_type,
                    "url":        url,
                })
                results["vulnerable"] = True
                conf = finding["confidence"]
                results["stats"][
                    "high_confidence" if conf == "HIGH"
                    else "medium_confidence"
                ] += 1
                results["details"].append(finding)
                tag = finding.get("probe_tag", "")
                label = f"[{tag}] " if tag else ""
                self.scan_progress.emit(
                    f"  ⚠️  [{conf}] {label}{finding['reason']}"
                )

            # ─────────────────────────────────────────────────────────────
            # Dedup guards for scan-level probes that must run once only.
            # TC-6 / TC-12 / TC-13 are URL-structural probes — they produce
            # the same requests regardless of which injection point triggered
            # them.  Without dedup they fire N×probes times (once per point).
            # ─────────────────────────────────────────────────────────────
            _tc6_done   = False   # file extension appending
            _tc12_done  = False   # API version downgrade
            _tc13_done  = False   # admin path segment swap

            # ─────────────────────────────────────────────────────────────
            # Main scan loop — one point at a time
            # ─────────────────────────────────────────────────────────────
            for point in points:
                if not self.running:
                    break

                results["stats"]["points_tested"] += 1
                name  = point["name"]
                orig  = point["value"]
                vtype = point["vtype"]
                ptype = point["type"]

                inject_tag  = " [injected]"  if point.get("injected")    else ""
                synonym_tag = f" [synonym of {point['synonym_of']}]" \
                              if point.get("synonym_of") else ""
                self.scan_progress.emit(
                    f"\n🎯 [{ptype}] {name} = '{orig}' ({vtype})"
                    f"{inject_tag}{synonym_tag}"
                )

                # ── Baseline ──────────────────────────────────────────────
                b_url, b_body, b_hdrs = _build(point, orig)
                b_resp = self.send_request_with_traffic(
                    b_url, b_hdrs, method=method, body=b_body,
                    payload_type="IDOR-Baseline"
                )
                if not b_resp or not hasattr(b_resp, "status_code"):
                    self.scan_progress.emit("  ⚠️  Baseline failed — skipping point")
                    continue

                baseline = {
                    "status": getattr(b_resp, "status_code", 0) or 0,
                    "length": len(getattr(b_resp, "content", b"")),
                    "text":   getattr(b_resp, "text", "") or "",
                }
                self.scan_progress.emit(
                    f"  📈 Baseline: HTTP {baseline['status']} | "
                    f"{baseline['length']}b"
                )

                # ── Generate candidates ───────────────────────────────────
                candidates = self._idor_generate_candidates(orig, vtype)
                self.scan_progress.emit(
                    f"  📋 Generated {len(candidates)} candidates"
                )

                # ── TC-9: Wildcard / null sentinels are already in candidates
                # (added in _idor_generate_candidates for integer/uuid/slug)

                # ── Unauthenticated probes (multiple sample points) ───────
                # Use first, middle, and last candidate for better coverage
                unauth_indices: List[int] = [0]
                if len(candidates) > 5:
                    unauth_indices.append(len(candidates) // 2)
                if len(candidates) > 10:
                    unauth_indices.append(len(candidates) - 1)
                unauth_sample = [
                    candidates[i] for i in unauth_indices
                    if i < len(candidates)
                ]

                for unauth_val in unauth_sample:
                    if not self.running:
                        break
                    ua_url, ua_body, _ = _build(point, unauth_val)
                    ua_resp = self.send_request_with_traffic(
                        ua_url, unauth_headers, method=method, body=ua_body,
                        payload=unauth_val,
                        payload_type=f"IDOR-Unauth-{name}"
                    )
                    results["stats"]["candidates_sent"] += 1
                    finding = _compare(
                        baseline, ua_resp, unauth_val, orig,
                        unauth=True, probe_tag="Unauth"
                    )
                    if finding:
                        _record(finding, name, ptype, ua_url)

                # ── TC-3: HTTP Parameter Pollution ────────────────────────
                # Send ?param=<orig>&param=<other> — some servers use last value
                if ptype == "url_param" and candidates:
                    hpp_val = candidates[0]
                    # Build query string with the original params minus the
                    # target param, then manually append both values
                    other_params = {
                        k: v for k, v in params.items() if k != name
                    }
                    base_qs = urllib.parse.urlencode(other_params, doseq=True)
                    dup_qs  = (
                        (base_qs + "&" if base_qs else "")
                        + f"{urllib.parse.quote(name)}={urllib.parse.quote(str(orig))}"
                        + f"&{urllib.parse.quote(name)}={urllib.parse.quote(str(hpp_val))}"
                    )
                    hpp_url = f"{base_url}?{dup_qs}"
                    self.scan_progress.emit(
                        f"  🔀 TC-3 HPP probe: {name}={orig}&{name}={hpp_val}"
                    )
                    hpp_resp = self.send_request_with_traffic(
                        hpp_url, clean_headers, method=method,
                        payload=f"HPP:{hpp_val}",
                        payload_type=f"IDOR-HPP-{name}"
                    )
                    results["stats"]["candidates_sent"] += 1
                    finding = _compare(
                        baseline, hpp_resp, hpp_val, orig,
                        probe_tag="TC-3:HPP"
                    )
                    if finding:
                        _record(finding, name, "HPP", hpp_url)

                # ── TC-4: Active HTTP method switching ────────────────────
                # Replay the mutated request with alternate verbs.
                # Only do this once per point (first candidate) to limit noise.
                if candidates:
                    _METHOD_ALTS: Dict[str, List[str]] = {
                        "GET":    ["POST", "PUT", "DELETE"],
                        "POST":   ["PUT", "PATCH", "DELETE"],
                        "PUT":    ["POST", "PATCH"],
                        "PATCH":  ["POST", "PUT"],
                        "DELETE": ["GET", "POST"],
                    }
                    alt_methods = _METHOD_ALTS.get(method, [])[:2]
                    for alt_method in alt_methods:
                        if not self.running:
                            break
                        m_val = candidates[0]
                        m_url, m_body, m_hdrs = _build(point, m_val)
                        self.scan_progress.emit(
                            f"  🔀 TC-4 method switch: {alt_method} {m_url}"
                        )
                        m_resp = self.send_request_with_traffic(
                            m_url, m_hdrs,
                            method=alt_method,
                            body=m_body if alt_method not in ("GET", "DELETE") else "",
                            payload=m_val,
                            payload_type=f"IDOR-Method-{alt_method}-{name}"
                        )
                        results["stats"]["candidates_sent"] += 1
                        finding = _compare(
                            baseline, m_resp, m_val, orig,
                            probe_tag=f"TC-4:{alt_method}"
                        )
                        if finding:
                            _record(finding, name, f"method:{alt_method}", m_url)

                # ── TC-5: Content-Type switching (POST/PUT/PATCH only) ─────
                # Replay the request with the first candidate value but with a
                # different Content-Type header. Only applies to body-bearing methods.
                if (method in ("POST", "PUT", "PATCH") and body_content
                        and ptype == "post_param" and candidates):
                    _CT_VARIANTS: Dict[str, List[str]] = {
                        "application/json": [
                            "application/xml",
                            "text/xml",
                            "application/x-www-form-urlencoded",
                            "text/x-json",
                        ],
                        "application/x-www-form-urlencoded": [
                            "application/json",
                            "application/xml",
                            "text/xml",
                        ],
                        "application/xml": [
                            "application/json",
                            "application/x-www-form-urlencoded",
                        ],
                        "text/xml": [
                            "application/json",
                            "application/x-www-form-urlencoded",
                        ],
                    }
                    current_ct_key = next(
                        (k for k in _CT_VARIANTS if k in ct), None
                    )
                    if current_ct_key:
                        # Use the first candidate value in the body
                        ct5_cand = candidates[0]
                        ct5_url, ct5_base_body, _ = _build(point, ct5_cand)
                        for alt_ct in _CT_VARIANTS[current_ct_key][:2]:
                            if not self.running:
                                break
                            switched_hdrs = clean_headers.copy()
                            switched_hdrs["Content-Type"] = alt_ct
                            self.scan_progress.emit(
                                f"  🔀 TC-5 content-type switch: {alt_ct} "
                                f"(candidate={ct5_cand})"
                            )
                            ct_resp = self.send_request_with_traffic(
                                ct5_url, switched_hdrs,
                                method=method,
                                body=ct5_base_body,
                                payload=ct5_cand,
                                payload_type=f"IDOR-CT-{alt_ct.split('/')[-1]}-{name}"
                            )
                            results["stats"]["candidates_sent"] += 1
                            finding = _compare(
                                baseline, ct_resp,
                                candidate=ct5_cand, original=orig,
                                probe_tag=f"TC-5:CT-{alt_ct.split('/')[-1]}"
                            )
                            if finding:
                                _record(finding, name, "content-type", ct5_url)

                # ── TC-6: File extension appending ────────────────────────
                # e.g. /user_data/2341 → /user_data/2341.json (200 bypass)
                # Run once per scan — the probe is URL-structural, not per-param.
                if not _tc6_done:
                    _tc6_done = True
                    _EXT_PROBES = [".json", ".xml", ".config", ".txt", ".csv", ".yaml"]
                    path_only = parsed.path
                    if not any(path_only.endswith(ext) for ext in _EXT_PROBES):
                        self.scan_progress.emit("  🔀 TC-6 file extension probes (once per scan)")
                        for ext in _EXT_PROBES:
                            if not self.running:
                                break
                            ext_path = path_only + ext
                            ext_url  = urllib.parse.urlunparse((
                                parsed.scheme, parsed.netloc, ext_path,
                                parsed.params, parsed.query, ""
                            ))
                            self.scan_progress.emit(
                                f"    TC-6 extension probe: {ext_url}"
                            )
                            ext_resp = self.send_request_with_traffic(
                                ext_url, unauth_headers, method="GET",
                                payload_type=f"IDOR-Ext-{ext[1:]}"
                            )
                            results["stats"]["candidates_sent"] += 1
                            if ext_resp and getattr(ext_resp, "status_code", 0) == 200:
                                finding = _compare(
                                    baseline, ext_resp,
                                    candidate=ext, original="no-ext",
                                    unauth=True,
                                    probe_tag=f"TC-6:ext{ext}"
                                )
                                if finding:
                                    _record(finding, f"path+{ext}", "ext-append", ext_url)

                # ── TC-8: Array wrapping (JSON POST/PUT bodies only) ───────
                if (method in ("POST", "PUT", "PATCH")
                        and "application/json" in ct
                        and ptype == "post_param"
                        and vtype in ("integer", "uuid", "slug")):
                    try:
                        orig_json = json.loads(body_content)
                        if isinstance(orig_json, dict) and name in orig_json:
                            arr_payload = orig_json.copy()
                            raw_val = orig_json[name]
                            arr_payload[name] = [raw_val]
                            arr_body = json.dumps(arr_payload)
                            arr_hdrs = clean_headers.copy()
                            arr_hdrs["Content-Type"] = "application/json"
                            self.scan_progress.emit(
                                f"  🔀 TC-8 array wrap: {name}=[{raw_val}]"
                            )
                            arr_resp = self.send_request_with_traffic(
                                full_url, arr_hdrs,
                                method=method,
                                body=arr_body,
                                payload=f"[{raw_val}]",
                                payload_type=f"IDOR-Array-{name}"
                            )
                            results["stats"]["candidates_sent"] += 1
                            finding = _compare(
                                baseline, arr_resp,
                                candidate=f"[{raw_val}]", original=str(raw_val),
                                probe_tag="TC-8:array"
                            )
                            if finding:
                                _record(finding, name, "array-wrap", full_url)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # ── TC-10: JSON nested object wrap — {"id":{"id":111}} ────
                # Some servers unwrap nested objects differently than scalars,
                # bypassing type-level access control checks.
                if (method in ("POST", "PUT", "PATCH")
                        and "application/json" in ct
                        and ptype == "post_param"
                        and vtype in ("integer", "uuid", "slug", "composite")):
                    try:
                        orig_json = json.loads(body_content)
                        if isinstance(orig_json, dict) and name in orig_json:
                            raw_val   = orig_json[name]
                            nest_payload = orig_json.copy()
                            nest_payload[name] = {name: raw_val}
                            nest_body = json.dumps(nest_payload)
                            nest_hdrs = clean_headers.copy()
                            nest_hdrs["Content-Type"] = "application/json"
                            self.scan_progress.emit(
                                f"  🔀 TC-10 nested JSON wrap: "
                                f"{name}={{\"{name}\":{raw_val}}}"
                            )
                            nest_resp = self.send_request_with_traffic(
                                full_url, nest_hdrs,
                                method=method,
                                body=nest_body,
                                payload=f"{{{name}:{raw_val}}}",
                                payload_type=f"IDOR-NestedObj-{name}"
                            )
                            results["stats"]["candidates_sent"] += 1
                            finding = _compare(
                                baseline, nest_resp,
                                candidate=f"{{{name}:{raw_val}}}",
                                original=str(raw_val),
                                probe_tag="TC-10:nested-obj"
                            )
                            if finding:
                                _record(finding, name, "nested-obj-wrap", full_url)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # ── TC-11: JSON Parameter Pollution (duplicate key in body) ─
                # POST body: {"user_id":<legit>,"user_id":<victim>}
                # Some JSON parsers use the last key; others use the first.
                # We send two versions: legit-first and victim-first.
                if (method in ("POST", "PUT", "PATCH")
                        and "application/json" in ct
                        and ptype == "post_param"
                        and candidates
                        and vtype in ("integer", "uuid", "slug", "composite")):
                    try:
                        orig_json = json.loads(body_content)
                        if isinstance(orig_json, dict) and name in orig_json:
                            raw_val  = orig_json[name]
                            cand_val = candidates[0]
                            # Build raw JSON strings with intentional duplicate keys
                            other_fields = ", ".join(
                                f'"{k}": {json.dumps(v)}'
                                for k, v in orig_json.items()
                                if k != name
                            )
                            sep = ", " if other_fields else ""
                            # Version A: legit first, victim second
                            jpp_a = (
                                "{" + other_fields + sep
                                + f'"{name}": {json.dumps(raw_val)}, '
                                + f'"{name}": {json.dumps(cand_val)}'
                                + "}"
                            )
                            # Version B: victim first, legit second
                            jpp_b = (
                                "{" + other_fields + sep
                                + f'"{name}": {json.dumps(cand_val)}, '
                                + f'"{name}": {json.dumps(raw_val)}'
                                + "}"
                            )
                            jpp_hdrs = clean_headers.copy()
                            jpp_hdrs["Content-Type"] = "application/json"

                            for variant_label, jpp_body in (
                                ("TC-11:JPP-last",  jpp_a),
                                ("TC-11:JPP-first", jpp_b),
                            ):
                                if not self.running:
                                    break
                                self.scan_progress.emit(
                                    f"  🔀 {variant_label}: "
                                    f"{name}={raw_val} + {name}={cand_val}"
                                )
                                jpp_resp = self.send_request_with_traffic(
                                    full_url, jpp_hdrs,
                                    method=method,
                                    body=jpp_body,
                                    payload=f"JPP:{cand_val}",
                                    payload_type=f"IDOR-JPP-{name}-{variant_label[-4:]}"
                                )
                                results["stats"]["candidates_sent"] += 1
                                finding = _compare(
                                    baseline, jpp_resp,
                                    candidate=str(cand_val),
                                    original=str(raw_val),
                                    probe_tag=variant_label
                                )
                                if finding:
                                    _record(finding, name, "json-param-pollution", full_url)
                    except (json.JSONDecodeError, TypeError):
                        pass

                # ── TC-12: Outdated API version probing ───────────────────
                # /v3/users/123 → try /v1/, /v2/, /v0/ variants.
                # Run once per scan — the probe is URL-structural, not per-param.
                if not _tc12_done:
                    _tc12_done = True
                    _API_VER_RE = re.compile(r"/(v\d+)/", re.IGNORECASE)
                    ver_match = _API_VER_RE.search(parsed.path)
                    if ver_match:
                        current_ver = ver_match.group(1)
                        try:
                            current_num = int(current_ver[1:])
                        except ValueError:
                            current_num = None

                        if current_num is not None:
                            older_nums = [
                                n for n in range(max(0, current_num - 3), current_num)
                            ]
                            if 1 not in older_nums and current_num != 1:
                                older_nums.insert(0, 1)
                            self.scan_progress.emit(
                                f"  🔀 TC-12 API version downgrade probes (once per scan): "
                                f"{current_ver} → {[f'v{n}' for n in older_nums]}"
                            )
                            for old_num in older_nums:
                                if not self.running:
                                    break
                                old_ver  = f"v{old_num}"
                                old_path = _API_VER_RE.sub(
                                    f"/{old_ver}/", parsed.path, count=1
                                )
                                old_url  = urllib.parse.urlunparse((
                                    parsed.scheme, parsed.netloc, old_path,
                                    parsed.params, parsed.query, ""
                                ))
                                self.scan_progress.emit(
                                    f"    TC-12: {current_ver} → {old_ver}"
                                )
                                ver_resp = self.send_request_with_traffic(
                                    old_url, unauth_headers, method="GET",
                                    payload_type=f"IDOR-APIVer-{old_ver}"
                                )
                                results["stats"]["candidates_sent"] += 1
                                if ver_resp and getattr(ver_resp, "status_code", 0) == 200:
                                    finding = _compare(
                                        baseline, ver_resp,
                                        candidate=old_ver,
                                        original=current_ver,
                                        unauth=True,
                                        probe_tag=f"TC-12:{old_ver}"
                                    )
                                    if finding:
                                        _record(
                                            finding,
                                            f"api-version:{old_ver}",
                                            "api-version",
                                            old_url
                                        )

                # ── TC-13: Admin/privilege path segment swap ───────────────
                # /api/users/myinfo → /api/admins/myinfo
                # Run once per scan — purely URL-structural, not per-param.
                if not _tc13_done:
                    _tc13_done = True
                    _PRIV_SWAPS: Dict[str, List[str]] = {
                        "users":    ["admins", "admin", "staff", "superusers", "managers"],
                        "user":     ["admin", "admins", "staff", "superuser", "manager"],
                        "members":  ["admins", "staff", "managers"],
                        "member":   ["admin", "staff", "manager"],
                        "accounts": ["admins", "staff"],
                        "account":  ["admin", "staff"],
                        "customer": ["admin", "staff", "support"],
                        "customers":["admins", "staff", "support"],
                        "profile":  ["admin", "staff"],
                        "profiles": ["admins", "staff"],
                        "me":       ["admin", "any", "all"],
                        "myinfo":   ["admininfo", "allinfo"],
                    }
                    path_segs_scan = [s for s in parsed.path.split("/") if s]
                    for seg_idx, seg in enumerate(path_segs_scan):
                        if seg.lower() not in _PRIV_SWAPS:
                            continue
                        self.scan_progress.emit(
                            f"  🔀 TC-13 admin path swap probes (once per scan): /{seg}/"
                        )
                        for swap_seg in _PRIV_SWAPS[seg.lower()]:
                            if not self.running:
                                break
                            new_segs  = list(path_segs_scan)
                            new_segs[seg_idx] = swap_seg
                            swap_path = "/" + "/".join(new_segs)
                            swap_url  = urllib.parse.urlunparse((
                                parsed.scheme, parsed.netloc, swap_path,
                                parsed.params, parsed.query, ""
                            ))
                            self.scan_progress.emit(
                                f"    TC-13: /{seg}/ → /{swap_seg}/"
                            )
                            swap_resp = self.send_request_with_traffic(
                                swap_url, clean_headers, method="GET",
                                payload_type=f"IDOR-PathSwap-{seg}-{swap_seg}"
                            )
                            results["stats"]["candidates_sent"] += 1
                            if swap_resp and getattr(swap_resp, "status_code", 0) == 200:
                                finding = _compare(
                                    baseline, swap_resp,
                                    candidate=swap_seg,
                                    original=seg,
                                    probe_tag=f"TC-13:/{swap_seg}/"
                                )
                                if finding:
                                    _record(
                                        finding,
                                        f"path-seg:{seg}",
                                        "path-swap",
                                        swap_url
                                    )
                        break  # only swap the first matching segment

                # ── TC-3b: HPP array-style ?id=A[]&id=B[] ────────────────
                # Some frameworks (PHP/Rails) parse foo[]=A&foo[]=B as an
                # array, bypassing scalar-only access control checks.
                if ptype == "url_param" and candidates:
                    hpp_arr_val = candidates[0]
                    other_params = {
                        k: v for k, v in params.items() if k != name
                    }
                    base_qs = urllib.parse.urlencode(other_params, doseq=True)
                    arr_key = urllib.parse.quote(f"{name}[]")
                    arr_qs  = (
                        (base_qs + "&" if base_qs else "")
                        + f"{arr_key}={urllib.parse.quote(str(orig))}"
                        + f"&{arr_key}={urllib.parse.quote(str(hpp_arr_val))}"
                    )
                    hpp_arr_url = f"{base_url}?{arr_qs}"
                    self.scan_progress.emit(
                        f"  🔀 TC-3b HPP array: "
                        f"{name}[]={orig}&{name}[]={hpp_arr_val}"
                    )
                    hpp_arr_resp = self.send_request_with_traffic(
                        hpp_arr_url, clean_headers, method=method,
                        payload=f"HPP-arr:{hpp_arr_val}",
                        payload_type=f"IDOR-HPP-Arr-{name}"
                    )
                    results["stats"]["candidates_sent"] += 1
                    finding = _compare(
                        baseline, hpp_arr_resp,
                        candidate=hpp_arr_val, original=orig,
                        probe_tag="TC-3b:HPP-array"
                    )
                    if finding:
                        _record(finding, name, "HPP-array", hpp_arr_url)

                # ── Authenticated candidates (core horizontal IDOR) ────────
                def _test_candidate(cand: str) -> Optional[Dict]:
                    t_url, t_body, t_hdrs = _build(point, cand)
                    resp = self.send_request_with_traffic(
                        t_url, t_hdrs, method=method, body=t_body,
                        payload=cand,
                        payload_type=f"IDOR-{ptype}-{name}-{cand[:20]}"
                    )
                    return _compare(baseline, resp, cand, orig, unauth=False)

                if self.boost_mode:
                    import threading as _threading
                    _idor_cancel = _threading.Event()

                    def _idor_worker(c, _cancel=_idor_cancel):
                        if _cancel.is_set():
                            return None
                        return _test_candidate(c)

                    with concurrent.futures.ThreadPoolExecutor(
                            max_workers=getattr(self, "scan_max_workers", 8)) as ex:
                        fmap = {}
                        for c in candidates:
                            if not self.running or _idor_cancel.is_set():
                                break
                            fmap[ex.submit(_idor_worker, c)] = c
                        for fut in concurrent.futures.as_completed(fmap):
                            if results["vulnerable"] and self.scan_stop_on_first:
                                _idor_cancel.set()
                                break
                            results["stats"]["candidates_sent"] += 1
                            try:
                                finding = fut.result(timeout=30)
                            except Exception:
                                finding = None
                            if finding:
                                cand  = fmap[fut]
                                t_url, _, _ = _build(point, cand)
                                _record(finding, name, ptype, t_url)
                                if self.scan_stop_on_first:
                                    _idor_cancel.set()
                                    self.scan_progress.emit("  ⏭️  Stop-on-first: IDOR confirmed — cancelling remaining candidates")
                else:
                    for cand in candidates:
                        if not self.running:
                            break
                        if results["vulnerable"] and self.scan_stop_on_first:
                            self.scan_progress.emit("  ⏭️  Stop-on-first: IDOR confirmed — stopping")
                            break
                        results["stats"]["candidates_sent"] += 1
                        finding = _test_candidate(cand)
                        if finding:
                            t_url, _, _ = _build(point, cand)
                            _record(finding, name, ptype, t_url)

        except Exception as e:
            logger.error(f"IDOR scan error: {e}")
            results["error"] = str(e)

        # ── Summary ───────────────────────────────────────────────────────
        hi  = results["stats"]["high_confidence"]
        med = results["stats"]["medium_confidence"]
        if results["vulnerable"]:
            results["summary"] = (
                f"IDOR CONFIRMED — {len(results['details'])} finding(s): "
                f"{hi} HIGH, {med} MEDIUM "
                f"({results['stats']['candidates_sent']} candidates tested)"
            )
        else:
            results["summary"] = (
                f"No IDOR vulnerabilities detected "
                f"({results['stats']['candidates_sent']} candidates tested across "
                f"{results['stats']['points_tested']} point(s))."
            )

        self.scan_progress.emit(f"\n{'='*60}")
        self.scan_progress.emit(f"📋 IDOR SCAN COMPLETE: {results['summary']}")
        self.scan_progress.emit(f"{'='*60}")
        return results

    # ── IDOR helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _idor_value_type(value: str) -> str:
        """
        Classify a parameter value into a type for candidate generation.

        Returns one of:
            "integer"       — pure decimal integer (positive or negative)
            "uuid"          — 8-4-4-4-12 UUID format
            "base64"        — base64-encoded string that decodes without error
            "numbered_file" — integer stem + file extension (e.g. 2.txt, report_5.csv)
            "composite"     — structured ID like ACC-00123 or ORD_456 (has digits)
            "slug"          — short alphabetic word (likely a username / resource name)
            "skip"          — random token / hash / too short — not worth testing
        """
        v = value.strip()
        if not v:
            return "skip"

        # Integer
        if re.fullmatch(r"-?\d+", v) and len(v) <= 15:
            return "integer"

        # UUID  (case-insensitive)
        if re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            v, re.IGNORECASE
        ):
            return "uuid"

        # Base64 — must decode cleanly AND contain a printable interior
        if re.fullmatch(r"[A-Za-z0-9+/=_-]{8,128}", v):
            try:
                # Support both standard and URL-safe base64
                padded = v + "=" * (-len(v) % 4)
                decoded = __import__("base64").b64decode(
                    padded.replace("-", "+").replace("_", "/")
                ).decode("utf-8")
                # Only treat as base64 if decoded text is printable and
                # contains a digit (likely encodes an id)
                if any(c.isdigit() for c in decoded) and decoded.isprintable():
                    return "base64"
            except Exception:
                pass

        # Numbered file — integer stem + file extension
        # e.g. 2.txt, 14.pdf, 003.json, report_5.csv, invoice-12.pdf
        # Covers the common pattern: /download-transcript/2.txt
        if re.fullmatch(r"[a-zA-Z0-9_-]*\d+[a-zA-Z0-9_-]*\.[a-zA-Z0-9]{1,10}", v):
            # Must contain at least one digit before the extension
            stem = v.rsplit(".", 1)[0]
            if re.search(r"\d+", stem):
                return "numbered_file"

        # Composite — structured ID with uppercase prefix and numeric component
        # e.g. ACC-00123, ORD_456, INV-2024-001, USR00042
        if (len(v) <= 30
                and re.search(r"\d{2,}", v)
                and re.search(r"[A-Z_-]", v)
                and not re.fullmatch(r"[0-9a-fA-F\-]{32,}", v)):
            return "composite"

        # Slug — short lowercase/hyphen word, ≥2 and ≤40 chars
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_-]{1,39}", v):
            return "slug"

        return "skip"

    @staticmethod
    def _idor_generate_candidates(value: str, vtype: str) -> List[str]:
        """
        Generate a list of candidate values to test for IDOR.

        integer       → ±1…20 from original, boundaries, large sentinel values,
                         wildcard / null sentinels (TC-9)
        uuid          → incremented last octets, nil UUID, sequential variants,
                         wildcard sentinels (TC-9)
        base64        → decode, mutate integer inside, re-encode (both ± variants)
        numbered_file → preserve extension, mutate stem integer ±1…20 + boundaries
                         e.g. 2.txt → 1.txt, 3.txt … 22.txt, 0.txt, 99.txt
        composite     → extract numeric component, increment ±1…10, rebuild string
        slug          → common admin/test usernames, wildcard sentinels (TC-9)

        Case-folded deduplication against the original value prevents wasted
        requests on case-insensitive servers (e.g. ALICE vs alice vs Alice).
        """
        import base64 as _b64

        candidates: List[str] = []
        seen:       set        = set()
        orig_cf = value.casefold()

        def _add(v: str):
            sv = str(v).strip()
            # Skip empty, exact match to original (any case), or already seen
            if sv and sv.casefold() != orig_cf and sv not in seen:
                seen.add(sv)
                candidates.append(sv)

        if vtype == "integer":
            n = int(value)
            # ± 1…20 around original
            for delta in range(1, 21):
                _add(n + delta)
                _add(n - delta)
            # Boundary / sentinel values
            for sentinel in (0, 1, -1, 2, 100, 1000, 9999, 99999,
                             1000000, 2147483647, -2147483648):
                _add(sentinel)
            # Double / half
            if n > 0:
                _add(n * 2)
                _add(max(1, n // 2))
            # TC-9: wildcard / null sentinels
            for wild in ("*", "null", "undefined", "none"):
                _add(wild)

        elif vtype == "uuid":
            # Parse into parts
            parts = value.lower().split("-")
            if len(parts) == 5:
                last = parts[4]  # 12-char node
                try:
                    node_int = int(last, 16)
                    for delta in range(1, 11):
                        new_node = format(max(0, node_int + delta), "012x")
                        _add("-".join(parts[:4] + [new_node]))
                        new_node = format(max(0, node_int - delta), "012x")
                        _add("-".join(parts[:4] + [new_node]))
                except ValueError:
                    pass
                # Nil UUID
                _add("00000000-0000-0000-0000-000000000000")
                # Common test UUIDs
                for i in range(1, 6):
                    _add(f"00000000-0000-0000-0000-{i:012d}")
            # TC-9: wildcard
            _add("*")

        elif vtype == "base64":
            try:
                padded   = value + "=" * (-len(value) % 4)
                url_safe = "-" in value or "_" in value
                decoded  = _b64.b64decode(
                    padded.replace("-", "+").replace("_", "/")
                ).decode("utf-8")
                # Find integer inside decoded string and mutate it
                m = re.search(r"(\d+)", decoded)
                if m:
                    orig_int = int(m.group(1))
                    for delta in range(1, 21):
                        for new_int in (orig_int + delta, max(0, orig_int - delta)):
                            mutated = (
                                decoded[:m.start(1)]
                                + str(new_int)
                                + decoded[m.end(1):]
                            )
                            encoded = _b64.b64encode(mutated.encode()).decode()
                            if url_safe:
                                encoded = (
                                    encoded.replace("+", "-")
                                           .replace("/", "_")
                                           .rstrip("=")
                                )
                            _add(encoded)
                    # Common admin ID patterns
                    for prefix in ("user:", "admin:", "account:", ""):
                        for admin_id in (1, 0, 2, "admin", "administrator"):
                            raw     = f"{prefix}{admin_id}"
                            encoded = _b64.b64encode(raw.encode()).decode()
                            if url_safe:
                                encoded = (
                                    encoded.replace("+", "-")
                                           .replace("/", "_")
                                           .rstrip("=")
                                )
                            _add(encoded)
            except Exception:
                pass

        elif vtype == "composite":
            # e.g. "ACC-00123" → extract "00123", mutate, rebuild "ACC-00124"
            m = re.search(r"(\d+)", value)
            if m:
                orig_int   = int(m.group(1))
                num_str    = m.group(1)
                pad_width  = len(num_str) if num_str.startswith("0") else 0
                prefix_str = value[:m.start(1)]
                suffix_str = value[m.end(1):]
                for delta in range(1, 11):
                    for new_int in (orig_int + delta, max(0, orig_int - delta)):
                        new_num = (
                            str(new_int).zfill(pad_width)
                            if pad_width else str(new_int)
                        )
                        _add(f"{prefix_str}{new_num}{suffix_str}")
                # Sentinel composites
                for sent in (0, 1, 99999):
                    new_num = str(sent).zfill(pad_width) if pad_width else str(sent)
                    _add(f"{prefix_str}{new_num}{suffix_str}")

        elif vtype == "numbered_file":
            # e.g. "2.txt" → "1.txt", "3.txt", "4.txt" ...
            # e.g. "report_5.csv" → "report_4.csv", "report_6.csv" ...
            # e.g. "003.json" → "002.json", "004.json" (zero-padded)
            #
            # Strategy: split on the last dot to get stem + ext,
            # find the LAST integer run in the stem, mutate only that,
            # preserve zero-padding and any prefix/suffix text in the stem.
            if "." in value:
                stem, ext = value.rsplit(".", 1)
                ext = "." + ext          # restore dot: ".txt"
                m   = None
                # Find the last digit group in the stem
                for m in re.finditer(r"(\d+)", stem):
                    pass                 # walk to the last match
                if m:
                    orig_int   = int(m.group(1))
                    num_str    = m.group(1)
                    pad_width  = len(num_str) if num_str.startswith("0") else 0
                    pre        = stem[:m.start(1)]
                    suf        = stem[m.end(1):]

                    # ± 1…20 around original (keep extension intact)
                    for delta in range(1, 21):
                        for new_int in (orig_int + delta, max(0, orig_int - delta)):
                            new_num = (
                                str(new_int).zfill(pad_width)
                                if pad_width else str(new_int)
                            )
                            _add(f"{pre}{new_num}{suf}{ext}")

                    # Boundary sentinels
                    for sent in (0, 1, 99, 100, 999, 9999):
                        new_num = (
                            str(sent).zfill(pad_width)
                            if pad_width else str(sent)
                        )
                        _add(f"{pre}{new_num}{suf}{ext}")

        elif vtype == "slug":
            v_lower = value.lower()
            # Common admin / test / privileged account names
            common = [
                "admin", "administrator", "root", "superuser", "superadmin",
                "test", "testuser", "test_user", "guest", "demo",
                "user", "user1", "user2", "user123",
                "support", "helpdesk", "operator",
                "moderator", "mod", "manager",
                "api", "service", "system", "sysadmin",
                "dev", "developer", "staff",
                "owner", "webmaster", "info",
            ]
            # Case variants (dedup via casefold check in _add)
            _add(v_lower)
            _add(value.upper())
            _add(value.capitalize())
            for c in common:
                _add(c)
            # TC-9: wildcard / null sentinels
            for wild in ("*", "null", "undefined"):
                _add(wild)

        return candidates