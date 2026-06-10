
"""
Professional Mapping Tab
Complete rewrite with advanced features and clean architecture
"""

import json
import re
import os
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Any
from datetime import datetime
from urllib.parse import urlparse, parse_qs

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *

# Import constants - these should match your theme
try:
    from constants import *
    # Ensure COLOR_WARNING exists even if constants.py doesn't export it
    try:
        COLOR_WARNING
    except NameError:
        COLOR_WARNING = "#ce9178"
except ImportError:
    # Fallback dark theme colors
    COLOR_BACKGROUND = "#1e1e1e"
    COLOR_ELEVATED_BG = "#252525"
    COLOR_CARD_BG = "#2d2d2d"
    COLOR_DARK_BG = "#181818"
    COLOR_BORDER = "#3e3e3e"
    COLOR_TEXT = "#cccccc"
    COLOR_TEXT_BRIGHT = "#ffffff"
    COLOR_TEXT_MUTED = "#808080"
    COLOR_ACCENT = "#0e639c"
    COLOR_SUCCESS = "#4ec9b0"
    COLOR_WARNING = "#ce9178"
    COLOR_CRITICAL = "#f48771"
    COLOR_HIGH = "#ff6b6b"
    COLOR_MEDIUM = "#feca57"
    COLOR_INFO = "#48dbfb"
    COLOR_HOVER = "#2a2d2e"

# ── Recorded tab (auto-saved analysis detections) ─────────────────────────────
try:
    from finding_tab import RecordedTab
except ImportError:
    RecordedTab = None  # Graceful fallback if file not present


class CategoryDefinitions:
    """Centralized category definitions with priority-based smart categorization."""

    # Evaluation order: most specific / highest risk first.
    # smart_categorize() stops at the first match so this order determines
    # which category wins when a URL could fit multiple categories.
    CATEGORY_PRIORITY = [
        "Admin & Management",
        "Debug & Development",
        "Commerce & Payment",
        "Authentication & Access",
        "IDOR Candidates",
        "File Operations",
        "API Endpoints",
        "WebSocket & Real-time",
        "Search & Discovery",
        "Redirects & Forwards",
        "Data Export",
        "User Functions",
        "Documentation & Info",
        "Static Resources",
    ]

    # Each category carries:
    #   path_patterns  – regexes tested against urlparse(url).path ONLY
    #   query_patterns – regexes tested against the raw query string ONLY
    #   icon / risk / hints – display / risk metadata
    RISK_CATEGORIES = {
        "Admin & Management": {
            "icon": "👑",
            "risk": "CRITICAL",
            "path_patterns": [
                r"(?:^|/)(?:admin|administrator)(?:/|$)",
                r"(?:^|/)(?:management|backend|console|controlpanel|control[-_]panel)(?:/|$)",
                r"(?:^|/)(?:wp-admin|phpmyadmin|cpanel|webmin|plesk|adminer)(?:/|$)",
                r"(?:^|/)(?:superuser|sysadmin|system[-_]admin)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test for default credentials",
                "Check authentication bypass",
                "Test privilege escalation",
                "Look for exposed admin functions",
                "Test IDOR on user management",
            ],
        },
        "Debug & Development": {
            "icon": "🐛",
            "risk": "CRITICAL",
            "path_patterns": [
                r"(?:^|/)(?:debug|phpinfo|phpdebug|trace|heap[-_]dump|thread[-_]dump)(?:/|$|\?)",
                r"(?:^|/)(?:dev|develop|development)(?:/|$)",
                r"(?:^|/)(?:staging|stage|testenv|test[-_]env)(?:/|$)",
                r"(?:^|/)(?:sandbox|beta)(?:/|$)",
                r"(?:^|/)(?:actuator|prometheus)(?:/|$)",
                r"(?:^|/)(?:metrics|health[-_]?check|liveness|readiness)(?:/|$)",
                r"(?:^|/)(?:test|tests|testing|testbed)(?:/|$)",
                r"\.(?:git|env|bak|bkp|old|orig|backup|swp|tmp|temp)(?:/|$|\?|#|$|\Z)",
            ],
            "query_patterns": [
                r"[?&]debug=",
                r"[?&]XDEBUG_SESSION",
            ],
            "hints": [
                "Check for exposed .git directories",
                "Test for verbose error messages",
                "Look for debug parameters",
                "Check for stack traces",
                "Test development endpoints",
            ],
        },
        "Commerce & Payment": {
            "icon": "💳",
            "risk": "CRITICAL",
            "path_patterns": [
                r"(?:^|/)(?:payment|payments)(?:/|$)",
                r"(?:^|/)(?:checkout|billing|invoice|invoices)(?:/|$)",
                r"(?:^|/)(?:order|orders|purchase|purchases|buy)(?:/|$)",
                r"(?:^|/)(?:cart|basket|transaction|transactions|wallet)(?:/|$)",
                r"(?:^|/)(?:stripe|paypal|braintree|mollie|razorpay|klarna)(?:/|$)",
                r"(?:^|/)pay(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test price manipulation",
                "Check for race conditions",
                "Test discount code abuse",
                "Look for payment bypass",
                "Test negative quantities",
            ],
        },
        "Authentication & Access": {
            "icon": "🔐",
            "risk": "HIGH",
            "path_patterns": [
                r"(?:^|/)(?:login|signin|sign[-_]in)(?:/|$|\?|\.\w)",
                r"(?:^|/)(?:logout|signout|sign[-_]out)(?:/|$|\?|\.\w)",
                r"(?:^|/)(?:auth|authenticate|authentication|authorize|authorization)(?:/|$|\?)",
                r"(?:^|/)(?:register|signup|sign[-_]up|registration)(?:/|$)",
                r"(?:^|/)(?:password|passwd|pwd)(?:/|$)",
                r"(?:^|/)(?:reset|forgot|recover|recovery)(?:/|$)",
                r"(?:^|/)(?:oauth|saml|sso|openid|oidc|cas)(?:/|$)",
                r"(?:^|/)(?:token|tokens|refresh[-_]?token)(?:/|$)",
                r"(?:^|/)(?:session|sessions)(?:/|$)",
                r"(?:^|/)(?:verify|verification|2fa|mfa|otp|totp)(?:/|$)",
                r"(?:^|/)(?:jwt|bearer|apikey|api[-_]key)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test SQL injection in login",
                "Check for user enumeration",
                "Test password reset logic",
                "Check session management",
                "Test MFA bypass",
            ],
        },
        "IDOR Candidates": {
            "icon": "🎯",
            "risk": "HIGH",
            "path_patterns": [
                r"(?:^|/)(?:user|users)/\d[\w\-]*(?:/|$)",
                r"(?:^|/)(?:account|accounts)/\d[\w\-]*(?:/|$)",
                r"(?:^|/)(?:order|orders)/\d[\w\-]*(?:/|$)",
                r"(?:^|/)(?:profile|profiles)/\d[\w\-]*(?:/|$)",
                r"(?:^|/)(?:invoice|invoices)/\d[\w\-]*(?:/|$)",
                r"(?:^|/)\d{2,}(?:/|$)",
            ],
            "query_patterns": [
                r"[?&](?:id|user_id|account_id|order_id|profile_id|invoice_id|uuid|guid)=[\w\-]+",
            ],
            "hints": [
                "Test horizontal privilege escalation",
                "Try sequential ID enumeration",
                "Test with negative IDs",
                "Check UUID predictability",
                "Test bulk ID requests",
            ],
        },
        "File Operations": {
            "icon": "📁",
            "risk": "HIGH",
            "path_patterns": [
                r"(?:^|/)(?:upload|uploads|uploader)(?:/|$)",
                r"(?:^|/)(?:download|downloads)(?:/|$)",
                r"(?:^|/)(?:file|files|filemanager)(?:/|$)",
                r"(?:^|/)(?:import|imports)(?:/|$)",
                r"(?:^|/)(?:attach|attachments?)(?:/|$)",
                r"(?:^|/)(?:document|documents)(?:/|$)",
                r"(?:^|/)(?:media|image|images|photo|photos|avatar|avatars|gallery|galleries)(?:/|$)",
            ],
            "query_patterns": [
                r"[?&](?:file|filename|filepath|path|document)=",
            ],
            "hints": [
                "Test unrestricted file upload",
                "Check for path traversal",
                "Test arbitrary file read",
                "Look for XXE in file parsing",
                "Test ZIP slip vulnerability",
            ],
        },
        "API Endpoints": {
            "icon": "🔌",
            "risk": "HIGH",
            "path_patterns": [
                r"(?:^|/)api(?:/|$)",
                r"(?:^|/)(?:rest|graphql|gql|soap|grpc)(?:/|$)",
                r"(?:^|/)v\d+(?:\.\d+)?(?:/|$)",
                r"(?:^|/)(?:swagger|openapi|api[-_]docs|redoc)(?:/|$|\.)",
                r"(?:^|/)(?:webhook|webhooks|callback|callbacks)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test mass assignment",
                "Check for BOLA/IDOR",
                "Test rate limiting",
                "Check API versioning",
                "Test for XXE/SSRF",
            ],
        },
        "WebSocket & Real-time": {
            "icon": "⚡",
            "risk": "MEDIUM",
            "path_patterns": [
                r"(?:^|/)(?:ws|wss|websocket|socket(?:\.io)?)(?:/|$)",
                r"(?:^|/)(?:realtime|real[-_]time|live)(?:/|$)",
                r"(?:^|/)(?:chat|chatroom|channel|channels)(?:/|$)",
                r"(?:^|/)(?:sse|stream|streaming)(?:/|$)",
                r"(?:^|/)(?:push|poll|polling|longpoll|long[-_]poll)(?:/|$)",
                r"(?:^|/)(?:events?|notify|notification|notifications)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test WebSocket hijacking",
                "Check origin validation",
                "Test message injection",
                "Look for authentication bypass",
                "Test DoS via flooding",
            ],
        },
        "Search & Discovery": {
            "icon": "🔍",
            "risk": "MEDIUM",
            "path_patterns": [
                r"(?:^|/)(?:search|find|lookup|discover)(?:/|$)",
            ],
            "query_patterns": [
                r"[?&](?:q|query|search|keyword|searchTerm|s|find|term)=",
            ],
            "hints": [
                "Test SQL injection",
                "Check for LDAP injection",
                "Test XSS in search results",
                "Look for sensitive data exposure",
                "Test NoSQL injection",
            ],
        },
        "Redirects & Forwards": {
            "icon": "↪️",
            "risk": "MEDIUM",
            "path_patterns": [
                r"(?:^|/)(?:redirect|forward|goto|out|exit)(?:/|$)",
            ],
            "query_patterns": [
                r"[?&](?:redirect|url|next|return|goto|target|dest(?:ination)?|return_url|callback_url)=",
            ],
            "hints": [
                "Test open redirect",
                "Check for SSRF",
                "Test URL validation bypass",
                "Look for header injection",
                "Test protocol smuggling",
            ],
        },
        "Data Export": {
            "icon": "📤",
            "risk": "MEDIUM",
            "path_patterns": [
                r"(?:^|/)(?:export|exports)(?:/|$)",
                r"(?:^|/)(?:report|reports)(?:/|$)",
                r"(?:^|/)(?:generate|print|prints)(?:/|$)",
                r"\.(?:csv|xls|xlsx|pdf|xml)(?:\?|#|$|\Z)",
            ],
            "query_patterns": [
                r"[?&](?:format|output|export)=(?:csv|xls|xlsx|pdf|xml|json)",
            ],
            "hints": [
                "Test for data exposure",
                "Check for IDOR in exports",
                "Test export injection",
                "Look for sensitive data",
                "Test bulk data extraction",
            ],
        },
        "User Functions": {
            "icon": "👤",
            "risk": "MEDIUM",
            "path_patterns": [
                r"(?:^|/)(?:profile|profiles)(?:/|$)",
                r"(?:^|/)(?:account|accounts)(?:/|$)",
                r"(?:^|/)(?:user|users)(?:/|$)",
                r"(?:^|/)(?:settings|preferences)(?:/|$)",
                r"(?:^|/)(?:dashboard)(?:/|$)",
                r"(?:^|/)(?:myaccount|my[-_]account|my[-_]profile)(?:/|$)",
                r"(?:^|/)me(?:/|$)",
                r"(?:^|/)(?:personal|member|members)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Test account takeover",
                "Check for IDOR",
                "Test email change logic",
                "Check password requirements",
                "Test account deletion",
            ],
        },
        "Documentation & Info": {
            "icon": "📖",
            "risk": "LOW",
            "path_patterns": [
                r"(?:^|/)(?:docs|documentation)(?:/|$)",
                r"(?:^|/)(?:help|faq|manual|guide|guides|tutorial)(?:/|$)",
                r"(?:^|/)(?:readme|changelog|release[-_]?notes|version|about|info|contact|status)(?:/|$|\.\w|\Z)",
            ],
            "query_patterns": [],
            "hints": [
                "Check for sensitive info",
                "Look for API endpoints",
                "Find technology stack",
                "Discover hidden features",
                "Map application structure",
            ],
        },
        "Static Resources": {
            "icon": "📦",
            "risk": "LOW",
            "path_patterns": [
                r"\.(?:css|js|jsx|tsx|jpg|jpeg|png|gif|svg|ico|woff|woff2|ttf|eot|map|webp)(?:\?|#|$|\Z)",
                r"(?:^|/)(?:static|assets|public|resources|lib|vendor|cdn)(?:/|$)",
                r"(?:^|/)(?:fonts?|images?|img|icons?|css|js[-_]src)(?:/|$)",
            ],
            "query_patterns": [],
            "hints": [
                "Check for exposed source maps",
                "Look for API keys in JS",
                "Find commented code",
                "Check file permissions",
                "Look for sensitive comments",
            ],
        },
    }

    @staticmethod
    def smart_categorize(url: str, method: str = "GET") -> tuple:
        """
        Priority-based URL categorization.

        Returns (category_name, definition_dict).

        Path patterns are matched against urlparse(url).path ONLY, so a
        pattern like `(?:^|/)dev(?:/|$)` will not accidentally fire on
        query-string values.  Query patterns are matched against the raw
        query string only.

        Categories are checked in CATEGORY_PRIORITY order, so the most
        specific / highest-risk category always wins when multiple could match.
        """
        try:
            parsed = urlparse(url)
            path   = parsed.path or "/"
            query  = parsed.query or ""
        except Exception:
            path, query = url, ""

        for cat_name in CategoryDefinitions.CATEGORY_PRIORITY:
            defn = CategoryDefinitions.RISK_CATEGORIES.get(cat_name)
            if not defn:
                continue
            for pat in defn.get("path_patterns", []):
                if re.search(pat, path, re.IGNORECASE):
                    return cat_name, defn
            for pat in defn.get("query_patterns", []):
                if re.search(pat, query, re.IGNORECASE):
                    return cat_name, defn

        return "Uncategorized", {"icon": "📋", "risk": "INFO", "hints": ["Review manually"]}


# ─────────────────────────────────────────────────────────────────────────────
# Hybrid Approach: Function Layer Definitions
# Maps each security category to a semantic BUSINESS FUNCTION + sub-functions.
# This is the "function skeleton" that sits between category and endpoint nodes.
# ─────────────────────────────────────────────────────────────────────────────

class FunctionDefinitions:
    """
    Hybrid Approach: path skeleton + function context + vuln hypotheses.
    Each category maps to:
      - function_group:  top-level business function name
      - sub_functions:   list of atomic operations within that function
      - vuln_matrix:     specific vuln checks ordered by likelihood
      - attack_flows:    multi-step attack scenarios unique to this function
      - test_checklist:  ordered checklist items for the hunt
    """

    FUNCTION_MAP = {
        "Admin & Management": {
            "function_group": "🏛️ Administration",
            "sub_functions": [
                "User Management (CRUD)",
                "Role & Permission Assignment",
                "System Configuration",
                "Audit Log Access",
                "Bulk Operations",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Default / Weak Credentials",        "Try admin:admin, root:root, vendor defaults"),
                ("🔴 CRITICAL", "Authentication Bypass",              "Try direct object access without session"),
                ("🔴 CRITICAL", "Privilege Escalation (Vertical)",    "Low-priv token → admin endpoint"),
                ("🟠 HIGH",     "IDOR on User Management",           "Modify user_id param to target other accounts"),
                ("🟠 HIGH",     "Mass Assignment / Parameter Pollution","Inject role=admin in update requests"),
                ("🟡 MEDIUM",   "Audit Log Tampering",               "Test if actions are logged; test log injection"),
                ("🟡 MEDIUM",   "Insecure Direct Function Reference", "Enumerate functions via JS source"),
            ],
            "attack_flows": [
                "Unauthenticated → /admin → Default creds → Full compromise",
                "Low-priv user → Role=admin injection → Account takeover",
                "Admin IDOR → Enumerate all user IDs → Mass data exposure",
            ],
            "test_checklist": [
                "[ ] Attempt unauthenticated access",
                "[ ] Try default credentials (admin:admin, admin:password)",
                "[ ] Test session token replay on admin endpoints",
                "[ ] Fuzz user_id / account_id params for IDOR",
                "[ ] Inject role/permission params in POST body",
                "[ ] Check if non-admin JWT can access admin routes",
                "[ ] Verify audit log entries are created for all actions",
            ],
        },

        "Debug & Development": {
            "function_group": "🐛 Dev/Debug Surface",
            "sub_functions": [
                "Error Reporting & Stack Traces",
                "Debug Endpoints / Feature Flags",
                "Exposed Config / Environment Files",
                "Backup & Temp Files",
                "Version Control Artifacts (.git)",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Exposed .git / .env / .bak",        "Download /.git/HEAD, /.env, /backup.zip"),
                ("🔴 CRITICAL", "Verbose Error → Stack Trace Leak",   "Trigger 500 errors; look for file paths, DB creds"),
                ("🟠 HIGH",     "Debug Parameter Activation",         "Append ?debug=1, ?trace=true, X-Debug:1"),
                ("🟠 HIGH",     "Actuator / Metrics Endpoints",       "Test /actuator/env, /actuator/beans (Spring)"),
                ("🟠 HIGH",     "PHP Info / Server Status",           "Access /phpinfo.php, /server-status"),
                ("🟡 MEDIUM",   "Development Backdoors",              "Test /test.php, /dev/login, /_dev"),
            ],
            "attack_flows": [
                "/.git/HEAD → git clone via GitDumper → Full source code",
                "Trigger 500 → Stack trace → DB host + schema leak → SQLi",
                "/actuator/env → API keys + DB credentials → RCE chain",
            ],
            "test_checklist": [
                "[ ] Test /.git/HEAD for git repo exposure",
                "[ ] Test /.env, /.env.local, /.env.production",
                "[ ] Append ?debug=1, debug=true to all endpoints",
                "[ ] Request /phpinfo.php, /info.php, /test.php",
                "[ ] Test Spring /actuator/* endpoints",
                "[ ] Try X-Debug-Token and similar debug headers",
                "[ ] Check for backup files: .bak, .old, .orig, .swp",
            ],
        },

        "Authentication & Access": {
            "function_group": "🔐 Identity & Access",
            "sub_functions": [
                "Login / Sign-in Flow",
                "Registration / Sign-up",
                "Password Reset / Recovery",
                "Session Management",
                "MFA / 2FA Verification",
                "OAuth / SSO / SAML",
                "Token Issuance & Refresh",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Account Takeover via Password Reset", "Weak/guessable token, host header injection"),
                ("🔴 CRITICAL", "MFA Bypass",                         "Test skip-step, reuse old OTP, brute force OTP"),
                ("🟠 HIGH",     "SQL Injection in Login",              "' OR 1=1--, admin'--  in username/password"),
                ("🟠 HIGH",     "User Enumeration",                   "Compare responses for valid vs invalid users"),
                ("🟠 HIGH",     "Broken Session Management",          "Test session fixation, missing invalidation on logout"),
                ("🟠 HIGH",     "OAuth State Fixation / Redirect",    "Missing state param, open redirect_uri"),
                ("🟡 MEDIUM",   "JWT Algorithm Confusion (none/RS→HS)","Change alg to none or RS256→HS256"),
                ("🟡 MEDIUM",   "Brute Force (No Lockout)",           "Test rate limits on login endpoint"),
            ],
            "attack_flows": [
                "Password reset → Host header injection → Token to attacker → ATO",
                "Login → SQL injection → Bypass auth → Admin session",
                "OAuth → Missing state → CSRF → Account linking hijack",
            ],
            "test_checklist": [
                "[ ] Test SQLi in all login fields",
                "[ ] Test user enumeration via timing/response diff",
                "[ ] Initiate password reset → intercept token → analyze entropy",
                "[ ] Test Host header injection in password reset",
                "[ ] Attempt MFA bypass (skip step, expired OTP reuse)",
                "[ ] Check OAuth state parameter presence and validation",
                "[ ] Decode JWT and test alg:none, HS/RS confusion",
                "[ ] Test session token after logout (session invalidation)",
                "[ ] Brute force login — check lockout after N attempts",
            ],
        },

        "Commerce & Payment": {
            "function_group": "💳 Commerce & Payments",
            "sub_functions": [
                "Product Catalog & Pricing",
                "Shopping Cart Management",
                "Checkout & Payment Processing",
                "Order Management",
                "Discount / Coupon Application",
                "Refund / Reversal",
                "Subscription Billing",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Price Manipulation",                  "Modify price/amount in request body/cart"),
                ("🔴 CRITICAL", "Payment Bypass",                      "Skip payment step, set total=0, set paid=true"),
                ("🔴 CRITICAL", "Race Condition on Coupons/Stock",     "Concurrent requests to apply coupon / checkout"),
                ("🟠 HIGH",     "Negative Quantity / Amount",          "Set quantity=-1, amount=-100 for refund abuse"),
                ("🟠 HIGH",     "IDOR on Order/Invoice",               "Access orders of other users via order_id"),
                ("🟠 HIGH",     "Coupon Code Brute Force",             "Enumerate discount codes via response timing"),
                ("🟡 MEDIUM",   "Integer Overflow in Cart",            "Very large quantities → overflow to 0 / negative"),
            ],
            "attack_flows": [
                "Add to cart → Intercept checkout → price=0.01 → Free product",
                "POST /checkout with paid=true → Skip payment gateway entirely",
                "Parallel requests to /apply-coupon → Coupon used N×",
            ],
            "test_checklist": [
                "[ ] Intercept checkout and modify price/total fields",
                "[ ] Set paid=true / status=completed before payment",
                "[ ] Test negative quantities in cart",
                "[ ] Send concurrent POST /apply-coupon (race condition)",
                "[ ] Enumerate order_id / invoice_id for IDOR",
                "[ ] Test coupon code brute force (4–8 char alphanumeric)",
                "[ ] Test integer overflow with quantity=999999999",
                "[ ] Attempt to reuse single-use coupons",
            ],
        },

        "API Endpoints": {
            "function_group": "🔌 API Layer",
            "sub_functions": [
                "CRUD Operations (GET/POST/PUT/DELETE)",
                "API Versioning (v1/v2/v3)",
                "GraphQL Queries & Mutations",
                "Batch / Bulk API",
                "Rate Limiting & Throttling",
                "API Authentication (keys/tokens)",
                "WebHooks",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "BOLA / IDOR",                        "Change resource ID to access other users' data"),
                ("🟠 HIGH",     "Mass Assignment",                    "POST extra fields: role, is_admin, verified=true"),
                ("🟠 HIGH",     "GraphQL Introspection",              "POST {__schema{types{name}}} → schema leak"),
                ("🟠 HIGH",     "GraphQL Batching / DoS",             "Array of 1000 identical queries in one request"),
                ("🟠 HIGH",     "Old API Version Bypass",             "v1 endpoint missing auth checks added in v3"),
                ("🟡 MEDIUM",   "Missing Rate Limiting",              "Rapid-fire requests → DoS or brute force"),
                ("🟡 MEDIUM",   "HTTP Method Override",               "X-HTTP-Method-Override: DELETE on GET endpoint"),
                ("🟡 MEDIUM",   "SSRF via webhook URL",               "Register webhook pointing to internal metadata service"),
            ],
            "attack_flows": [
                "GET /api/v1/users/1 → change to /users/2,3,4 → BOLA mass dump",
                "POST /api/user/update with role:admin → privilege escalation",
                "Old /api/v1/admin endpoint without auth added in v2",
            ],
            "test_checklist": [
                "[ ] Enumerate all HTTP methods on each endpoint (OPTIONS)",
                "[ ] Replace resource IDs with other users' IDs (BOLA)",
                "[ ] Inject extra params in POST body (mass assignment)",
                "[ ] Test all API versions for missing auth on older versions",
                "[ ] Send GraphQL introspection query",
                "[ ] Test GraphQL batching with 50+ identical queries",
                "[ ] Test webhook endpoints with internal SSRF URLs",
                "[ ] Verify rate limiting on sensitive operations",
            ],
        },

        "File Operations": {
            "function_group": "📁 File Management",
            "sub_functions": [
                "File Upload (single/bulk)",
                "File Download / Retrieval",
                "Document Parsing (PDF/XML/XLSX)",
                "Image Processing",
                "Archive Handling (ZIP/TAR)",
                "File Deletion",
                "File Sharing / Permissions",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Unrestricted File Upload → RCE",     "Upload .php/.jsp/.aspx shell; bypass MIME check"),
                ("🔴 CRITICAL", "Path Traversal on Download",         "filename=../../../../etc/passwd"),
                ("🟠 HIGH",     "XXE via XML/SVG Upload",              "Upload SVG with XXE payload to read /etc/passwd"),
                ("🟠 HIGH",     "ZIP Slip",                           "Craft malicious ZIP with ../../ paths"),
                ("🟠 HIGH",     "IDOR on File Download",              "Change file_id / user_id to access other files"),
                ("🟡 MEDIUM",   "Client-Side Bypass of Extension",    "Rename shell.php → shell.jpg, double extension"),
                ("🟡 MEDIUM",   "SSRF via URL-based Import",          "Import-from-URL field pointing to internal services"),
            ],
            "attack_flows": [
                "Upload .php.jpg → Server strips .jpg → Executes PHP → RCE",
                "Download?file=../../../etc/shadow → Credential dump",
                "Upload SVG with XXE → Read /etc/passwd → Internal port scan",
            ],
            "test_checklist": [
                "[ ] Upload .php, .php5, .phtml, .pHp (bypass filters)",
                "[ ] Test MIME type bypass (Content-Type: image/jpeg with PHP body)",
                "[ ] Test path traversal in filename param: ../../../etc/passwd",
                "[ ] Upload SVG with XXE payload",
                "[ ] Create ZIP with symlink to /etc/passwd (ZIP slip)",
                "[ ] Test IDOR: access uploaded files of other users",
                "[ ] Test URL import field for SSRF to 169.254.169.254",
                "[ ] Check if file extension is validated server-side vs client-side",
            ],
        },

        "IDOR Candidates": {
            "function_group": "🎯 Object Reference",
            "sub_functions": [
                "Direct Object Access by ID",
                "Relationship-based Object Access",
                "Bulk ID Operations",
                "UUID / GUID Enumeration",
                "Indirect Object References",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Horizontal Privilege Escalation",    "User A accesses User B's data via ID change"),
                ("🟠 HIGH",     "Sequential ID Enumeration",          "id=1001 → 1002 → 1003 → mass data dump"),
                ("🟠 HIGH",     "Negative / Special Value IDs",       "id=0, id=-1, id=null, id=undefined"),
                ("🟠 HIGH",     "UUID Predictability",                "v1 UUIDs are time-based and enumerable"),
                ("🟡 MEDIUM",   "Second-Order IDOR",                  "Store IDOR payload → trigger later in async job"),
                ("🟡 MEDIUM",   "Parameter Pollution for IDOR",       "id[]=1&id[]=2 or id=1;2 or id=1,2"),
            ],
            "attack_flows": [
                "GET /api/orders?id=1001 → id=1002 → Competitor order data",
                "PATCH /user/profile with id changed → Update other user's email",
                "Batch API: ids=[1,2,3...1000] → Mass account dump",
            ],
            "test_checklist": [
                "[ ] Identify all numeric/UUID parameters",
                "[ ] Increment/decrement IDs by 1 to access adjacent records",
                "[ ] Create two accounts; test cross-account object access",
                "[ ] Test id=0, id=-1, id=null",
                "[ ] Test array-based IDs: id[]=self&id[]=target",
                "[ ] Test parameter pollution: id=own&id=target",
                "[ ] Test IDOR in response body (check if full object returned)",
                "[ ] Test IDOR in POST/PUT not just GET",
            ],
        },

        "User Functions": {
            "function_group": "👤 User Account",
            "sub_functions": [
                "Profile View / Edit",
                "Account Settings",
                "Email / Phone Change",
                "Password Change",
                "Account Deletion",
                "Notification Preferences",
                "Privacy Settings",
            ],
            "vuln_matrix": [
                ("🔴 CRITICAL", "Account Takeover via Email Change",  "Change email without re-auth → reset password"),
                ("🟠 HIGH",     "IDOR on Profile Update",             "PUT /user/123/profile with different 123"),
                ("🟠 HIGH",     "Missing Re-auth on Sensitive Change","No password required to change email/phone"),
                ("🟡 MEDIUM",   "Stored XSS in Profile Fields",      "Inject <script> in bio/name → reflected to admins"),
                ("🟡 MEDIUM",   "Mass Assignment on User Update",     "Inject verified=true, role=admin in profile update"),
                ("🟡 MEDIUM",   "Account Deletion without Confirmation","No email/OTP required → social engineering ATO"),
            ],
            "attack_flows": [
                "Change email (no re-auth) → Reset password to new email → ATO",
                "Stored XSS in bio → Admin views profile → Admin cookie stolen",
            ],
            "test_checklist": [
                "[ ] Test IDOR on profile update (change user_id in URL/body)",
                "[ ] Test email change without current password re-auth",
                "[ ] Inject XSS payload in all profile fields",
                "[ ] Test mass assignment (role=admin in profile update body)",
                "[ ] Test account deletion flow for missing confirmation",
                "[ ] Verify password change requires old password",
            ],
        },

        "Search & Discovery": {
            "function_group": "🔍 Search & Query",
            "sub_functions": [
                "Full-Text Search",
                "Filtered / Faceted Search",
                "Auto-complete / Suggestions",
                "Advanced Query Builder",
                "Search History",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "SQL Injection in Search",            "' OR 1=1-- in search/query/filter params"),
                ("🟠 HIGH",     "NoSQL Injection",                    "{'$gt':''} in JSON search body"),
                ("🟠 HIGH",     "LDAP Injection",                     ")(|(uid=*) in search if LDAP-backed"),
                ("🟠 HIGH",     "Reflected XSS in Search Results",   "<script>alert(1)</script> in q= param"),
                ("🟡 MEDIUM",   "Search-Based IDOR (Data Leak)",      "Search for other users' private data by ID"),
                ("🟡 MEDIUM",   "ReDoS via Regex Search",             "Long input with repetition: a+a+a+a+$"),
                ("🟡 MEDIUM",   "Wildcard Injection",                 "* in search to retrieve all records"),
            ],
            "attack_flows": [
                "q=' OR 1=1-- → SQLi → DB dump via search results",
                "Autocomplete API leaks private usernames → Username enumeration",
            ],
            "test_checklist": [
                "[ ] Test SQLi payloads in all search params",
                "[ ] Test NoSQL injection: {$gt:''}, {$ne:null}",
                "[ ] Test XSS in search term (reflected in results page)",
                "[ ] Test wildcard: *, %, _, ?",
                "[ ] Test LDAP injection: *, )(&(uid=*))",
                "[ ] Search for other users' private content (data visibility)",
                "[ ] Test ReDoS with: aaaaaaaaaaaaaaaaaaaaX",
            ],
        },

        "Data Export": {
            "function_group": "📤 Data Export",
            "sub_functions": [
                "Report Generation (PDF/CSV/XLSX)",
                "Data Dump / Bulk Export",
                "Scheduled / Async Export",
                "Export Filter Bypass",
                "Template-based Export",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "IDOR on Export",                     "Change user_id/report_id to export other data"),
                ("🟠 HIGH",     "CSV Injection (Formula Injection)",  "=CMD|'/c calc'!A1 in exported field"),
                ("🟠 HIGH",     "SSRF via Export URL Field",          "Pass internal URL as export source"),
                ("🟡 MEDIUM",   "Sensitive Data in Export",           "Export contains fields not visible in UI"),
                ("🟡 MEDIUM",   "Missing Auth on Export Endpoint",    "Direct GET to /export?token=xxx without session"),
                ("🟡 MEDIUM",   "Async Job IDOR",                     "Poll job_id of other users' export jobs"),
            ],
            "attack_flows": [
                "POST /export with user_id changed → Download other user's data",
                "CSV field injection → Victim opens CSV → Formula executes",
            ],
            "test_checklist": [
                "[ ] Test IDOR: change report/user ID in export request",
                "[ ] Inject CSV formula: =HYPERLINK('http://evil.com','click')",
                "[ ] Check if export contains more fields than UI shows",
                "[ ] Test unauthenticated access to export endpoints",
                "[ ] Poll async export job IDs of other users",
                "[ ] Test export filters for bypass (export all vs filtered)",
            ],
        },

        "Redirects & Forwards": {
            "function_group": "↪️ Redirects & Navigation",
            "sub_functions": [
                "Post-Login Redirect",
                "External Link Handler",
                "URL Shortener",
                "API Proxy / Forward",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "Open Redirect",                      "?next=https://evil.com after login"),
                ("🟠 HIGH",     "SSRF via Redirect Chain",            "redirect=http://169.254.169.254/"),
                ("🟡 MEDIUM",   "Header Injection via Redirect",      "Inject CRLF in redirect URL"),
                ("🟡 MEDIUM",   "OAuth Redirect_URI Bypass",          "redirect_uri=https://evil.com/oauth"),
                ("🟡 MEDIUM",   "Protocol Smuggling",                 "Use file://, gopher://, dict:// in redirect"),
            ],
            "attack_flows": [
                "Login → ?next=https://phishing.com → Trusted redirect → Creds stolen",
                "?url=http://internal-service → SSRF → Internal AWS metadata",
            ],
            "test_checklist": [
                "[ ] Test all redirect params with external URL",
                "[ ] Test SSRF: redirect to http://169.254.169.254/latest/meta-data/",
                "[ ] Test protocol bypass: file:///etc/passwd",
                "[ ] Test CRLF injection in redirect URL",
                "[ ] Test OAuth redirect_uri with open redirect",
                "[ ] Test URL with @: https://legit.com@evil.com/",
            ],
        },

        "WebSocket & Real-time": {
            "function_group": "⚡ Real-time & WebSocket",
            "sub_functions": [
                "WebSocket Connection",
                "Message Broadcasting",
                "Event Subscription",
                "Server-Sent Events (SSE)",
                "Long Polling",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "Cross-Site WebSocket Hijacking",     "Missing Origin check → attacker page connects"),
                ("🟠 HIGH",     "WebSocket Auth Bypass",              "Upgrade without session → access WS as unauth"),
                ("🟠 HIGH",     "Message Injection",                  "Inject commands in WS messages (SQLi, XSS)"),
                ("🟡 MEDIUM",   "Missing Origin Validation",          "Any origin can connect to WS endpoint"),
                ("🟡 MEDIUM",   "DoS via Message Flooding",           "Send thousands of WS messages/second"),
                ("🟡 MEDIUM",   "Privilege Escalation via WS Channel","Switch channel/room to access other users' stream"),
            ],
            "attack_flows": [
                "Missing Origin → CSWSH → Attacker reads victim's real-time data",
                "WS message with SQL payload → Injection through real-time query",
            ],
            "test_checklist": [
                "[ ] Test WebSocket connection from different Origin",
                "[ ] Test WS connection without authentication token",
                "[ ] Inject SQLi/XSS in WS message payloads",
                "[ ] Test channel/room ID for IDOR",
                "[ ] Flood WS with messages (rate limit check)",
                "[ ] Test if WS allows subscribing to other users' events",
            ],
        },

        "Documentation & Info": {
            "function_group": "📖 Info Disclosure",
            "sub_functions": [
                "API Documentation (Swagger/OpenAPI)",
                "Version / Health Endpoints",
                "Changelog / Release Notes",
                "About / Technology Stack",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "Swagger/OpenAPI Endpoint Enumeration","Parse /swagger.json → full endpoint list"),
                ("🟡 MEDIUM",   "Technology Stack Disclosure",        "X-Powered-By, Server headers, error messages"),
                ("🟡 MEDIUM",   "Internal Endpoint Disclosure",       "Docs expose internal /internal/* endpoints"),
                ("🟡 MEDIUM",   "API Key in Documentation",           "Hard-coded sample keys that may be real"),
                ("⬜ LOW",      "Version Disclosure",                 "Server version → CVE lookup"),
            ],
            "attack_flows": [
                "/swagger.json → Parse all endpoints → Test each for auth issues",
                "X-Powered-By: PHP/5.6.40 → Known CVE → Exploit",
            ],
            "test_checklist": [
                "[ ] Download and parse /swagger.json or /openapi.json",
                "[ ] Check /api-docs, /v2/api-docs, /docs",
                "[ ] Extract all endpoints from API spec and test auth",
                "[ ] Check response headers for technology disclosure",
                "[ ] Look for sample API keys in documentation",
                "[ ] Cross-reference disclosed versions with CVE database",
            ],
        },

        "Static Resources": {
            "function_group": "📦 Static Assets",
            "sub_functions": [
                "JavaScript Bundle Analysis",
                "Source Map Extraction",
                "CDN Asset Audit",
                "Font / Image Resource Audit",
            ],
            "vuln_matrix": [
                ("🟠 HIGH",     "Source Map Exposure (.map files)",   "Download .js.map → Reconstruct full source"),
                ("🟠 HIGH",     "API Keys in JavaScript",             "Search JS bundles for keys/tokens/secrets"),
                ("🟡 MEDIUM",   "Endpoint Discovery via JS",          "Extract hardcoded API paths from JS bundles"),
                ("🟡 MEDIUM",   "Subresource Integrity Missing",      "CDN JS without SRI → supply chain risk"),
                ("⬜ LOW",      "CORS on Static Assets",              "Check CORS headers on CDN resources"),
            ],
            "attack_flows": [
                "Download main.js.map → Reconstruct source → Find hidden endpoints + API keys",
                "JS analysis → Found internal API token → Directly call internal API",
            ],
            "test_checklist": [
                "[ ] Check for .js.map files (append .map to all JS URLs)",
                "[ ] Search JS files for: api_key, secret, token, password, auth",
                "[ ] Extract all URLs/endpoints hardcoded in JS bundles",
                "[ ] Check CDN assets for missing SRI (integrity attribute)",
                "[ ] Check CORS headers on static resources",
                "[ ] Look for commented-out code with sensitive logic",
            ],
        },
    }

    # Tech stack signatures for endpoint node annotations
    TECH_STACK_PATTERNS = {
        "PHP":        (r"\.php[0-9]?$|\.phtml$",     "🐘", "#8892BF"),
        "ASP.NET":    (r"\.aspx?$|\.ashx$|\.asmx$",  "🪟", "#512BD4"),
        "Java/JSP":   (r"\.jsp$|\.do$|\.action$",     "☕", "#ED8B00"),
        "Python":     (r"\.py$|/django/|/flask/",     "🐍", "#3776AB"),
        "Ruby":       (r"\.rb$|/rails/",              "💎", "#CC342D"),
        "GraphQL":    (r"graphql|/gql$",              "◈",  "#E535AB"),
        "REST API":   (r"/api/v[0-9]+/",              "🔌", "#00B4D8"),
        "WordPress":  (r"/wp-admin|/wp-json|/wp-content","🔵","#21759B"),
        "Spring":     (r"/actuator|\.spring\.",        "🌱", "#6DB33F"),
        "Node.js":    (r"/node_modules|\.js$",         "🟩", "#339933"),
    }

    @classmethod
    def get_function_info(cls, category: str) -> dict:
        return cls.FUNCTION_MAP.get(category, {
            "function_group":  f"📋 {category}",
            "sub_functions":   ["Generic endpoint handling"],
            "vuln_matrix":     [("🟡 MEDIUM", "Manual Review", "Inspect request/response manually")],
            "attack_flows":    ["Inspect manually for business logic flaws"],
            "test_checklist":  ["[ ] Review manually"],
        })

    @classmethod
    def detect_tech(cls, url: str) -> list:
        """Return list of (icon, name, color) tuples for detected tech in URL."""
        detected = []
        for name, (pattern, icon, color) in cls.TECH_STACK_PATTERNS.items():
            if re.search(pattern, url, re.IGNORECASE):
                detected.append((icon, name, color))
        return detected


# ─────────────────────────────────────────────────────────────────────────────
# Persistent per-endpoint function assignments
# Saved as  mindmap_func_assignments.json  in the project directory.
# Schema: { "<url>": {"func_group": "...", "sub_func": "...", "notes": "..."} }
# ─────────────────────────────────────────────────────────────────────────────

class FunctionAssignmentManager:
    """
    Persists user-defined function assignments for individual endpoints.
    Assignments override the auto-detected FunctionDefinitions mapping.
    """
    ASSIGN_FILE = "mindmap_func_assignments.json"

    @staticmethod
    def _path(project_dir: str) -> str:
        # If project_dir is a file (shouldn't happen) use its parent
        if os.path.isfile(project_dir):
            project_dir = os.path.dirname(project_dir)
        return os.path.join(project_dir, FunctionAssignmentManager.ASSIGN_FILE)

    @staticmethod
    def load(project_dir: str) -> dict:
        if not project_dir:
            return {}
        p = FunctionAssignmentManager._path(project_dir)
        if not os.path.exists(p):
            return {}
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def save_assignment(project_dir: str, url: str,
                        func_group: str, sub_func: str, notes: str):
        if not project_dir:
            return
        data = FunctionAssignmentManager.load(project_dir)
        data[url] = {"func_group": func_group, "sub_func": sub_func, "notes": notes}
        p = FunctionAssignmentManager._path(project_dir)
        parent = os.path.dirname(p)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def remove(project_dir: str, url: str):
        if not project_dir:
            return
        data = FunctionAssignmentManager.load(project_dir)
        data.pop(url, None)
        p = FunctionAssignmentManager._path(project_dir)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def get(project_dir: str, url: str) -> dict:
        return FunctionAssignmentManager.load(project_dir).get(url, {})


# ─────────────────────────────────────────────────────────────────────────────
# Category override + custom-category persistence
# ─────────────────────────────────────────────────────────────────────────────

class CategoryOverrideManager:
    """
    Persists two files in the project directory:

      mindmap_category_overrides.json
        { "<url>": "<category_name>", ... }
        Maps a specific endpoint URL to a user-chosen category, overriding
        the auto-categorisation done by process_url().

      mindmap_custom_categories.json
        [ {"name": "My Cat", "icon": "🔧", "risk": "HIGH", "hints": [...]}, ... ]
        Extra categories the user defined. They appear in every category picker.
    """

    OVERRIDES_FILE     = "mindmap_category_overrides.json"
    CUSTOM_CAT_FILE    = "mindmap_custom_categories.json"
    MANUAL_EP_FILE     = "mindmap_manual_endpoints.json"

    @staticmethod
    def _overrides_path(project_dir: str) -> str:
        return os.path.join(project_dir, CategoryOverrideManager.OVERRIDES_FILE)

    @staticmethod
    def _custom_path(project_dir: str) -> str:
        return os.path.join(project_dir, CategoryOverrideManager.CUSTOM_CAT_FILE)

    @staticmethod
    def load_overrides(project_dir: str) -> dict:
        path = CategoryOverrideManager._overrides_path(project_dir)
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    @staticmethod
    def save_override(project_dir: str, url: str, category_name: str):
        overrides = CategoryOverrideManager.load_overrides(project_dir)
        overrides[url] = category_name
        path = CategoryOverrideManager._overrides_path(project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2)

    @staticmethod
    def remove_override(project_dir: str, url: str):
        overrides = CategoryOverrideManager.load_overrides(project_dir)
        overrides.pop(url, None)
        path = CategoryOverrideManager._overrides_path(project_dir)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(overrides, f, indent=2)

    @staticmethod
    def load_custom_categories(project_dir: str) -> list:
        path = CategoryOverrideManager._custom_path(project_dir)
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @staticmethod
    def save_custom_category(project_dir: str, name: str,
                              icon: str = "🔧", risk: str = "MEDIUM",
                              hints: list = None):
        cats = CategoryOverrideManager.load_custom_categories(project_dir)
        if any(c.get("name") == name for c in cats):
            return   # already exists
        cats.append({"name": name, "icon": icon, "risk": risk, "hints": hints or []})
        path = CategoryOverrideManager._custom_path(project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cats, f, indent=2)

    @staticmethod
    def all_category_names(project_dir: str) -> list:
        """Sorted list of ALL category names: built-in + custom."""
        built_in = sorted(CategoryDefinitions.RISK_CATEGORIES.keys())
        custom   = [c["name"] for c in
                    CategoryOverrideManager.load_custom_categories(project_dir)]
        seen  = set(built_in)
        extra = [n for n in custom if n not in seen]
        return built_in + extra

    @staticmethod
    def get_category_def(project_dir: str, name: str) -> dict:
        """Return definition dict for a category (built-in or custom)."""
        if name in CategoryDefinitions.RISK_CATEGORIES:
            return CategoryDefinitions.RISK_CATEGORIES[name]
        for c in CategoryOverrideManager.load_custom_categories(project_dir):
            if c.get("name") == name:
                return {"icon": c.get("icon", "🔧"),
                        "risk": c.get("risk", "MEDIUM"),
                        "hints": c.get("hints", [])}
        return {"icon": "📋", "risk": "INFO", "hints": []}

    # ── Manual endpoints ──────────────────────────────────────────────

    @staticmethod
    def _manual_ep_path(project_dir: str) -> str:
        return os.path.join(project_dir, CategoryOverrideManager.MANUAL_EP_FILE)

    @staticmethod
    def load_manual_endpoints(project_dir: str) -> list:
        """
        Return list of manually added endpoint dicts:
          { url, method, body_params, category, host, status }
        """
        path = CategoryOverrideManager._manual_ep_path(project_dir)
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    @staticmethod
    def save_manual_endpoint(project_dir: str, url: str, method: str,
                              body_params: str, category: str, host: str) -> bool:
        """
        Persist a manually-added endpoint.
        Returns False if an endpoint with the same (url, method) already exists
        in this category (dedup check), True if saved successfully.
        """
        eps = CategoryOverrideManager.load_manual_endpoints(project_dir)
        # Normalise for dedup
        try:
            parsed = urlparse(url)
            norm_path = parsed.path.rstrip("/") or "/"
        except Exception:
            norm_path = url
        for ep in eps:
            try:
                existing_path = urlparse(ep.get("url", "")).path.rstrip("/") or "/"
            except Exception:
                existing_path = ep.get("url", "")
            if (existing_path == norm_path
                    and ep.get("method", "GET").upper() == method.upper()
                    and ep.get("category") == category):
                return False   # already exists

        eps.append({
            "url":         url,
            "method":      method.upper(),
            "body_params": body_params,
            "category":    category,
            "host":        host,
            "status":      0,
        })
        path = CategoryOverrideManager._manual_ep_path(project_dir)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(eps, f, indent=2)
        return True

    @staticmethod
    def remove_manual_endpoint(project_dir: str, url: str,
                                method: str, category: str):
        """Remove a specific manual endpoint by url + method + category."""
        eps = CategoryOverrideManager.load_manual_endpoints(project_dir)
        eps = [e for e in eps
               if not (e.get("url") == url
                       and e.get("method", "").upper() == method.upper()
                       and e.get("category") == category)]
        path = CategoryOverrideManager._manual_ep_path(project_dir)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(eps, f, indent=2)


class ExtensionDefinitions:
    """Extension groups for security-relevant file type detection"""

    EXTENSION_GROUPS = {
        "JavaScript": {
            "icon": "📜", "risk": "HIGH",
            "extensions": ["js", "jsx", "ts", "tsx", "mjs", "cjs"],
            "hints": ["Search for hardcoded API keys/secrets", "Extract internal endpoints", "Look for DOM XSS sinks", "Check sensitive comments", "Extract param names for fuzzing"]
        },
        "Backup & Old Files": {
            "icon": "💾", "risk": "CRITICAL",
            "extensions": ["bak", "old", "orig", "backup", "copy", "tmp", "temp", "save", "swp", "swo"],
            "hints": ["Download and inspect for source code", "May contain credentials or config", "Check for database dumps", "Compare with current version", "Look for decommissioned logic"]
        },
        "Config & Environment": {
            "icon": "⚙️", "risk": "CRITICAL",
            "extensions": ["env", "config", "cfg", "conf", "ini", "yaml", "yml", "toml", "properties"],
            "hints": ["Look for database credentials", "Check for API keys and tokens", "Look for internal hostnames", "Check for encryption keys", "Identify third-party integrations"]
        },
        "Source Code": {
            "icon": "💻", "risk": "CRITICAL",
            "extensions": ["php", "php3", "php4", "php5", "asp", "aspx", "jsp", "py", "rb", "go", "java", "cs", "pl", "cgi"],
            "hints": ["Analyze for injection vulnerabilities", "Look for authentication logic", "Check for file inclusion", "Identify dangerous functions", "Look for hardcoded secrets"]
        },
        "Archives": {
            "icon": "🗜️", "risk": "HIGH",
            "extensions": ["zip", "tar", "gz", "tgz", "rar", "7z", "war", "jar", "ear"],
            "hints": ["Download and extract for source code", "Look for config files inside", "Check for credential files", "Analyze for path traversal", "Look for sensitive backup data"]
        },
        "Data & Exports": {
            "icon": "📊", "risk": "HIGH",
            "extensions": ["json", "xml", "csv", "xls", "xlsx", "sql", "db", "sqlite", "dump"],
            "hints": ["Check for sensitive data exposure", "Look for PII or internal data", "Test for XXE if XML", "Check access controls", "Look for unauthenticated data access"]
        },
        "Logs & Debug": {
            "icon": "🪵", "risk": "HIGH",
            "extensions": ["log", "logs", "debug", "err", "error", "trace", "out"],
            "hints": ["Look for stack traces and paths", "Check for credentials in logs", "Identify internal IPs/hostnames", "Look for session tokens", "Extract usernames from auth logs"]
        },
        "Documents": {
            "icon": "📄", "risk": "MEDIUM",
            "extensions": ["pdf", "doc", "docx", "ppt", "pptx", "txt", "rtf", "odt"],
            "hints": ["Check document metadata", "Look for internal usernames", "Identify internal paths", "Check for sensitive content", "Extract embedded links"]
        },
        "Web & Templates": {
            "icon": "🌐", "risk": "MEDIUM",
            "extensions": ["html", "htm", "xhtml", "tpl", "tmpl", "twig", "blade", "ejs", "hbs"],
            "hints": ["Check for SSTI", "Look for exposed admin templates", "Check sensitive HTML comments", "Look for debug parameters", "Test XSS in rendered output"]
        },
        "Style & Media": {
            "icon": "🎨", "risk": "LOW",
            "extensions": ["css", "scss", "sass", "less", "map", "jpg", "jpeg", "png", "gif", "svg", "ico", "webp", "woff", "woff2", "ttf", "eot"],
            "hints": ["Check .map files for source code", "Look for sensitive SVG content", "Check image metadata", "Review exposed font paths", "Look for CSS injection"]
        },
    }

    EXT_TO_GROUP = {}
    for _g, _i in EXTENSION_GROUPS.items():
        for _e in _i["extensions"]:
            EXT_TO_GROUP[_e] = _g

    @classmethod
    def get_group(cls, ext: str):
        group_name = cls.EXT_TO_GROUP.get(ext.lower())
        if group_name:
            return group_name, cls.EXTENSION_GROUPS[group_name]
        return None, None


class URLAnalyzer:
    """Analyze individual URLs for security characteristics"""
    
    @staticmethod
    def analyze(url: str, method: str, status: int, params: Dict) -> Dict[str, Any]:
        """Comprehensive URL analysis"""
        try:
            parsed = urlparse(url)
        except Exception:
            # Handle invalid URLs (e.g. Invalid IPv6 URL)
            from urllib.parse import ParseResult
            parsed = ParseResult(scheme="", netloc="", path="", params="", query="", fragment="")

        # Use provided params (which includes body params) or fallback to URL query params
        try:
            query_params = params if params else parse_qs(parsed.query)
        except Exception:
            query_params = {}
        
        analysis = {
            # Basic info
            "has_params": bool(query_params),
            "param_count": len(query_params),
            "param_names": list(query_params.keys()),
            "method": method,
            "status": status,
            "url_depth": len([p for p in parsed.path.split('/') if p]),
            
            # File extension
            "has_extension": False,
            "extension": None,
            
            # Security indicators
            "auth_required": status in [401, 403],
            "is_error": status >= 400,
            "is_redirect": 300 <= status < 400,
            
            # Vulnerability indicators
            "potential_injection_points": [],
            "suspicious_params": [],
            "numeric_ids": [],
            "technology_hints": []
        }
        
        # Extension analysis
        if '.' in parsed.path:
            try:
                ext = parsed.path.split('.')[-1].split('?')[0].split('#')[0].lower()
                if ext and len(ext) <= 5:
                    analysis["has_extension"] = True
                    analysis["extension"] = ext
            except Exception:
                pass
        
        # Parameter analysis
        injection_keywords = ['id', 'user', 'file', 'path', 'url', 'redirect', 'query', 'search', 'cmd', 'exec']
        suspicious_keywords = ['admin', 'debug', 'test', 'key', 'token', 'password', 'secret', 'auth', 'role']
        
        for param in query_params.keys():
            param_lower = param.lower()
            
            # Injection points
            if any(keyword in param_lower for keyword in injection_keywords):
                analysis["potential_injection_points"].append(param)
            
            # Suspicious params
            if any(keyword in param_lower for keyword in suspicious_keywords):
                analysis["suspicious_params"].append(param)
            
            # Numeric IDs (IDOR candidates)
            for value in query_params[param]:
                if isinstance(value, str) and value.isdigit():
                    analysis["numeric_ids"].append(f"{param}={value}")
        
        # Technology detection
        if '.php' in url:
            analysis["technology_hints"].append("PHP")
        if '.aspx' in url or '.asp' in url:
            analysis["technology_hints"].append("ASP.NET")
        if '.jsp' in url or '.do' in url or '.action' in url:
            analysis["technology_hints"].append("Java/JSP")
        if '/api/' in url:
            analysis["technology_hints"].append("REST API")
        if 'graphql' in url.lower():
            analysis["technology_hints"].append("GraphQL")
        if '.py' in url:
            analysis["technology_hints"].append("Python")
        if '.rb' in url:
            analysis["technology_hints"].append("Ruby")
        
        return analysis



# ============================================================================
# Mind Map Widget
# ============================================================================

class MindMapNodeItem(QGraphicsRectItem):
    """
    A single interactive node in the auto-generated mind map.
    Supports: done (fade), marked (star), comment (always-visible label),
    copy path via right-click context menu. State is persisted externally.
    """

    def __init__(self, label: str, x: float, y: float, w: float, h: float,
                 color: QColor, font: QFont, url: str = "", node_id: str = ""):
        super().__init__(x, y, w, h)
        self.label    = label
        self.url      = url
        self.node_id  = node_id          # stable key for persistence (url-based)
        self._color   = color
        self._font    = font

        # ── Mutable state ────────────────────────────────────────────
        self.state_done    = False
        self.state_marked  = False
        self.state_comment = ""

        # ── Child items created in build() / _apply_state() ──────────
        self._shadow_item   = None
        self._text_item     = None
        self._star_item     = None
        self._comment_item  = None

        # ── Hierarchy links (set by scene after creation) ────────────
        self.node_type     = "ep"      # "root" | "host" | "cat" | "func" | "ep"
        self.node_subtype  = ""        # extra classifier (e.g. tech stack name)
        self.host_name     = ""        # which host this belongs to
        self.full_path     = ""        # cumulative path for Copy Path (dir nodes)
        self.children      = []        # direct children MindMapNodeItems

        self.setAcceptHoverEvents(True)
        self.setFlag(QGraphicsItem.ItemIsSelectable, True)
        self.setCursor(Qt.ArrowCursor)

    # ── Visual refresh ────────────────────────────────────────────────
    def apply_state(self):
        """Re-render the node according to current state flags."""
        x, y, w, h = self.rect().x(), self.rect().y(), self.rect().width(), self.rect().height()

        if self.state_done:
            self.setBrush(QBrush(QColor(40, 40, 40, 60)))
            self.setPen(QPen(QColor(80, 80, 80, 100), 1))
            if self._text_item:
                self._text_item.setBrush(QBrush(QColor(90, 90, 90, 150)))
            if self._shadow_item:
                self._shadow_item.setOpacity(0.0)
        else:
            self.setBrush(QBrush(self._color))
            border = self._color.lighter(150)
            self.setPen(QPen(border, 1.5))
            if self._text_item:
                self._text_item.setBrush(QBrush(QColor("#ffffff")))
            if self._shadow_item:
                self._shadow_item.setOpacity(1.0)

        # ── Star ──────────────────────────────────────────────────────
        if self._star_item:
            self.scene().removeItem(self._star_item)
            self._star_item = None

        if self.state_marked:
            star = QGraphicsSimpleTextItem("★")
            star.setFont(QFont("Segoe UI", 11, QFont.Bold))
            star.setBrush(QBrush(QColor("#f0c040")))
            star.setPos(x + w - 18, y - 2)
            star.setZValue(10)
            if self.scene():
                self.scene().addItem(star)
            self._star_item = star

        # ── Comment bubble ────────────────────────────────────────────
        if self._comment_item:
            self.scene().removeItem(self._comment_item)
            self._comment_item = None

        if self.state_comment.strip():
            cmt_font = QFont("Segoe UI", 7)
            cmt = QGraphicsSimpleTextItem(self.state_comment[:60])
            cmt.setFont(cmt_font)
            cmt.setBrush(QBrush(QColor("#f0e68c")))
            cmt.setPos(x, y + h + 3)
            cmt.setZValue(10)
            if self.scene():
                self.scene().addItem(cmt)
            self._comment_item = cmt

    # ── Interaction ───────────────────────────────────────────────────
    def hoverEnterEvent(self, e):
        if not self.state_done:
            self.setPen(QPen(QColor("#ffffff"), 2))
        super().hoverEnterEvent(e)

    def hoverLeaveEvent(self, e):
        self.apply_state()
        super().hoverLeaveEvent(e)

    def contextMenuEvent(self, e):
        # Guard against the Qt "wrapped C/C++ object deleted" crash.
        # This happens when the scene clears/rebuilds while a context menu
        # is being processed. We accept the event first so Qt doesn't try
        # to propagate it through a potentially-deleted parent chain.
        try:
            scene = self.scene()
            if scene and self.scene():
                # Store the data we need BEFORE the menu is shown
                # (showing a modal dialog can trigger a rebuild)
                node_url      = self.url
                node_label    = self.label
                node_type     = self.node_type
                node_id       = self.node_id
                state_done    = self.state_done
                state_marked  = self.state_marked
                state_comment = self.state_comment
                scene.show_node_menu(self, e.screenPos())
            e.accept()
        except RuntimeError:
            e.accept()


# ─────────────────────────────────────────────────────────────────────────────

class MindMapScene(QGraphicsScene):
    """Interactive mind-map scene — nodes support right-click actions + persistence."""

    RISK_COLORS = {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f39c12",
        "LOW":      "#27ae60",
        "INFO":     "#2980b9",
        "ROOT":     "#6c3483",
        "HOST":     "#1a5276",
        "METHOD":   "#117864",
        "FUNC":     "#2c3e6b",   # Hybrid: function-layer nodes (dark indigo)
    }

    # Signal emitted whenever a node state changes (triggers save)
    state_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackgroundBrush(QBrush(QColor("#181818")))
        self._node_items: list  = []   # list of MindMapNodeItem
        self._edges:      list  = []
        # Persistence: node_id -> {done, marked, comment}
        self._node_states: dict = {}
        self._save_path: str    = ""
        # Hierarchy maps — populated during build()
        self._host_nodes: dict  = {}   # host_label -> MindMapNodeItem
        self._cat_nodes:  dict  = {}   # (host_label, cat_label) -> MindMapNodeItem
        # Full data stored for re-filtering without re-extracting
        self._last_data:  dict  = {}
        # Category override support
        self._project_dir: str  = ""       # set by MindMapWidget
        self._rebuild_callback = None      # callable → triggers full map rebuild

    # ── Persistence ───────────────────────────────────────────────────
    def set_save_path(self, path: str):
        self._save_path = path
        self._load_states()

    def _load_states(self):
        if not self._save_path or not os.path.exists(self._save_path):
            return
        try:
            with open(self._save_path, "r", encoding="utf-8") as f:
                self._node_states = json.load(f)
        except Exception:
            self._node_states = {}

    def save_states(self):
        if not self._save_path:
            return
        try:
            os.makedirs(os.path.dirname(self._save_path), exist_ok=True)
            with open(self._save_path, "w", encoding="utf-8") as f:
                json.dump(self._node_states, f, indent=2)
        except Exception:
            pass

    def _restore_node_state(self, item: MindMapNodeItem):
        """Apply persisted state to a freshly created node."""
        st = self._node_states.get(item.node_id)
        if st:
            item.state_done    = st.get("done",    False)
            item.state_marked  = st.get("marked",  False)
            item.state_comment = st.get("comment", "")
        item.apply_state()

    def _persist_node(self, item: MindMapNodeItem):
        self._node_states[item.node_id] = {
            "done":    item.state_done,
            "marked":  item.state_marked,
            "comment": item.state_comment,
        }
        self.save_states()
        self.state_changed.emit()

    # ── Build ─────────────────────────────────────────────────────────
    def clear_map(self):
        self.clear()
        self._node_items.clear()
        self._edges.clear()
        self._host_nodes.clear()
        self._cat_nodes.clear()

    def _make_node(self, label: str, x: float, y: float,
                   role: str = "INFO", tooltip: str = "",
                   node_id: str = "", method: str = "",
                   func_assign: dict = None, tech: list = None,
                   vuln_count: int = 0) -> tuple:
        """
        Draw a single mind-map node.
        method      : HTTP method — renders a coloured pill badge before the label
        func_assign : persisted function assignment — shown as an arrow annotation
                      pointing right from the endpoint node (not a separate tree node)
        tech        : list of (icon, name, color) — shown in tooltip only
        vuln_count  : shows a ⚠N badge on the node when > 0
        """
        METHOD_COLORS = {
            "GET":     "#27ae60",
            "POST":    "#2980b9",
            "PUT":     "#d35400",
            "PATCH":   "#8e44ad",
            "DELETE":  "#c0392b",
            "HEAD":    "#7f8c8d",
            "OPTIONS": "#16a085",
        }

        # ── Function annotation arrow (drawn to the right of node) ───────
        # Only rendered for endpoint nodes that have a func_assign set
        has_annot  = bool(func_assign and (func_assign.get("func_group") or func_assign.get("sub_func")))

        color_hex       = self.RISK_COLORS.get(role, "#2c3e50")
        color           = QColor(color_hex)
        is_root_or_host = role in ("ROOT", "HOST")
        font     = QFont("Segoe UI", 9, QFont.Bold if is_root_or_host else QFont.Normal)
        fm       = QFontMetrics(font)
        badge_font = QFont("Segoe UI", 8, QFont.Bold)
        badge_fm   = QFontMetrics(badge_font)

        # Method badge width
        method_w  = (badge_fm.horizontalAdvance(method) + 10) if method else 0
        gap       = 6 if method else 0

        tw = fm.horizontalAdvance(label)
        th = fm.height()
        pad_x, pad_y = 12, 7
        w = method_w + gap + tw + pad_x * 2
        h = th + pad_y * 2

        # Actual node y (no vertical offset — annotation is to the right)
        node_y = y

        # ── Rich tooltip ──────────────────────────────────────────────
        tip_parts = [tooltip or label]
        if func_assign:
            if func_assign.get("func_group"): tip_parts.append(f"⚙ {func_assign['func_group']}")
            if func_assign.get("sub_func"):   tip_parts.append(f"   ↳ {func_assign['sub_func']}")
            if func_assign.get("notes"):      tip_parts.append(f"   📝 {func_assign['notes']}")
        if tech:
            tip_parts.append("Tech: " + "  ".join(f"{ic}{nm}" for ic,nm,_ in tech[:4]))
        rich_tip = "\n".join(tip_parts)

        # ── Function annotation arrow (drawn to the RIGHT of node) ──────
        if has_annot:
            fg    = func_assign.get("func_group","")
            sf    = func_assign.get("sub_func","")
            is_auto = func_assign.get("_auto", False)
            annot_text = f"⚙ {fg}" + (f"  ›  {sf}" if sf else "")

            annot_font = QFont("Segoe UI", 7)
            afm = QFontMetrics(annot_font)
            # Auto-derived → dimmer style; user-set → bright teal
            if is_auto:
                arrow_color = QColor("#3a6a8a")
                text_color  = QColor("#6a9ab0")
            else:
                arrow_color = QColor("#48dbfb")
                text_color  = QColor("#48dbfb")

            ARROW_LEN = 40    # shaft length
            ARROW_TIP_W = 7   # arrowhead depth
            ARROW_TIP_H = 5   # arrowhead half-height

            ax0 = x + w          # start of arrow shaft (right edge of node)
            ax1 = ax0 + ARROW_LEN  # tip of arrow
            ay  = node_y + h / 2   # vertical centre of node

            # Arrow shaft
            shaft = QGraphicsLineItem(ax0, ay, ax1, ay)
            shaft_pen = QPen(arrow_color, 1.2)
            shaft.setPen(shaft_pen)
            shaft.setZValue(3)
            self.addItem(shaft)

            # Arrowhead triangle (pointing right)
            tip = QPolygonF([
                QPointF(ax1,             ay),
                QPointF(ax1 - ARROW_TIP_W, ay - ARROW_TIP_H),
                QPointF(ax1 - ARROW_TIP_W, ay + ARROW_TIP_H),
            ])
            arrow_head = QGraphicsPolygonItem(tip)
            arrow_head.setBrush(QBrush(arrow_color))
            arrow_head.setPen(QPen(Qt.NoPen))
            arrow_head.setZValue(3)
            self.addItem(arrow_head)

            # Annotation label text to the right of the arrowhead
            annot_lbl = QGraphicsSimpleTextItem(annot_text)
            annot_lbl.setFont(annot_font)
            annot_lbl.setBrush(QBrush(text_color))
            lbl_h = afm.height()
            annot_lbl.setPos(ax1 + 4, ay - lbl_h / 2)
            annot_lbl.setZValue(4)
            self.addItem(annot_lbl)

        # Shadow
        shadow = QGraphicsRectItem(x + 3, node_y + 3, w, h)
        shadow.setBrush(QBrush(QColor(0, 0, 0, 80)))
        shadow.setPen(QPen(Qt.NoPen))
        shadow.setZValue(0)
        self.addItem(shadow)

        # Node rect
        node_item = MindMapNodeItem(label, x, node_y, w, h, color, font,
                                    url=tooltip, node_id=node_id or tooltip or label)
        node_item.setBrush(QBrush(color))
        node_item.setPen(QPen(color.lighter(150), 1.5))
        node_item.setToolTip(rich_tip)
        node_item.setZValue(1)
        node_item._shadow_item = shadow
        self.addItem(node_item)
        self._node_items.append(node_item)

        # ── Method badge pill ─────────────────────────────────────────
        if method:
            badge_color = QColor(METHOD_COLORS.get(method, "#555555"))
            pill = QGraphicsRectItem(x + pad_x, node_y + pad_y - 1, method_w, th + 2)
            pill.setBrush(QBrush(badge_color))
            pill.setPen(QPen(Qt.NoPen))
            pill.setZValue(3)
            pill.setParentItem(node_item)

            pill_txt = QGraphicsSimpleTextItem(method)
            pill_txt.setFont(badge_font)
            pill_txt.setBrush(QBrush(QColor("#ffffff")))
            pill_txt.setPos(x + pad_x + 5, node_y + pad_y)
            pill_txt.setZValue(4)
            pill_txt.setParentItem(node_item)
            label_x = x + pad_x + method_w + gap
        else:
            label_x = x + pad_x

        # Text label
        txt = QGraphicsSimpleTextItem(label)
        txt.setFont(font)
        txt.setBrush(QBrush(QColor("#ffffff")))
        txt.setPos(label_x, node_y + pad_y)
        txt.setZValue(2)
        txt.setParentItem(node_item)
        node_item._text_item = txt

        # ── Vuln count badge ──────────────────────────────────────────
        if vuln_count > 0 and not is_root_or_host:
            vb = QGraphicsSimpleTextItem(f"⚠{vuln_count}")
            vb.setFont(QFont("Segoe UI", 7, QFont.Bold))
            vb.setBrush(QBrush(QColor("#ff4444")))
            vb.setPos(x + w - 28, node_y - 12)
            vb.setZValue(12)
            self.addItem(vb)

        self._restore_node_state(node_item)
        cx, cy = x + w / 2, node_y + h / 2
        return cx, cy, w, h

    def _draw_edge(self, x1, y1, x2, y2, color_hex="#4a4a6a"):
        path = QPainterPath()
        path.moveTo(x1, y1)
        mid_x = (x1 + x2) / 2
        path.cubicTo(mid_x, y1, mid_x, y2, x2, y2)
        pen = QPen(QColor(color_hex), 1.5)
        pen.setStyle(Qt.SolidLine)
        item = QGraphicsPathItem(path)
        item.setPen(pen)
        item.setZValue(0)
        self.addItem(item)

    def build(self, data: dict,
              host_filter: str = "",
              starred_only: bool = False,
              status_filter: str = "",
              show_func_annot: bool = True,
              func_filter: str = ""):
        """
        Render the path-tree mind map.

        Hierarchy:  ROOT → HOST → /seg0 → /seg1 → endpoint-leaf

        Endpoint nodes show:
          • Coloured METHOD pill (GET=green, POST=blue, etc.)
          • Path label + params
          • Optional ⚙ annotation arrow to the right of node (when func_assign set + show_func_annot=True)
          • Hover tooltip: URL + function assignment + tech stack
          • ⚠N vuln count badge on path nodes
        """
        self._last_data = data
        self.clear_map()
        if not data:
            return

        def _status_ok(code: int, filt: str) -> bool:
            if not filt: return True
            if filt == "2xx": return 200 <= code <= 299
            if filt == "3xx": return 300 <= code <= 399
            if filt == "4xx": return 400 <= code <= 499
            if filt == "5xx": return 500 <= code <= 599
            return True

        ROOT_X, ROOT_Y  = 40, 40
        HOST_OFF_X      = 240
        SEG0_OFF_X      = 200
        SEG1_OFF_X      = 180
        EP_OFF_X        = 180
        VERT_GAP        = 16
        HOST_BLOCK_PAD  = 36

        starred_ids: set = set()
        if starred_only:
            for nid, st in self._node_states.items():
                if st.get("marked"): starred_ids.add(nid)

        _seen_nids: set = set()

        # ROOT
        root_info = data.get("root", {})
        rx, ry, rw, rh = self._make_node(
            root_info.get("label","Target"), ROOT_X, ROOT_Y, "ROOT",
            tooltip=root_info.get("url",""), node_id="__root__")
        root_node = self._node_items[-1]
        root_node.node_type = "root"
        root_cx, root_cy = rx, ry
        host_x    = ROOT_X + rw + HOST_OFF_X
        current_y = ROOT_Y

        for host in data.get("hosts", []):
            host_label = host.get("label","?")
            if host_filter and host_label != host_filter:
                continue

            path_nodes         = host.get("path_nodes", [])
            host_block_start_y = current_y

            # ── Build layout plan ──────────────────────────────────────
            layout_plan = []

            def _filter_eps(eps):
                out = []
                for ep in eps:
                    if status_filter and not _status_ok(ep.get("status",0), status_filter):
                        continue
                    if starred_only and f"ep::{ep.get('url','')}" not in starred_ids:
                        continue
                    if func_filter:
                        if func_filter.startswith("cat::"):
                            if ep.get("cat_name", "") != func_filter[5:]:
                                continue
                        elif func_filter.startswith("sf::"):
                            ep_sf = ep.get("func_assign", {}).get("sub_func", "")
                            if ep_sf != func_filter[4:]:
                                continue
                    out.append(ep)
                return out

            for pn0 in path_nodes:
                direct_eps = _filter_eps(pn0.get("endpoints", []))
                children   = []
                for pn1 in pn0.get("children", []):
                    pn1_eps = _filter_eps(pn1.get("endpoints", []))
                    if (starred_only or func_filter) and not pn1_eps:
                        continue
                    children.append((pn1, pn1_eps))
                if (starred_only or func_filter) and not direct_eps and not children:
                    continue
                layout_plan.append({"pn0": pn0, "direct": direct_eps, "children": children})

            # ── Assign y to every endpoint leaf ────────────────────────
            y = current_y
            for plan in layout_plan:
                plan["y_start"] = y
                for ep in plan["direct"]:
                    ep["_y"] = y;  y += 34 + VERT_GAP
                for (pn1, pn1_eps) in plan["children"]:
                    pn1["_y_start"] = y
                    for ep in pn1_eps:
                        ep["_y"] = y;  y += 34 + VERT_GAP
                    if not pn1_eps:
                        y += 34 + VERT_GAP
                    pn1["_y_end"] = y - VERT_GAP
                if not plan["direct"] and not plan["children"]:
                    y += 34 + VERT_GAP
                plan["y_end"] = y - VERT_GAP

            host_block_end_y = y + HOST_BLOCK_PAD if layout_plan else current_y + 34 + HOST_BLOCK_PAD
            host_mid_y       = (host_block_start_y + host_block_end_y) / 2 - 17

            # HOST node
            hcx, hcy, hw, hh = self._make_node(
                host_label, host_x, host_mid_y, "HOST",
                tooltip=host_label, node_id=f"host::{host_label}")
            h_item = self._node_items[-1]
            h_item.node_type = "host"
            h_item.host_name = host_label
            self._host_nodes[host_label] = h_item
            root_node.children.append(h_item)
            self._draw_edge(root_cx + rw/2, root_cy, hcx - hw/2, hcy, "#4a4a8a")

            seg0_x = host_x + hw + SEG0_OFF_X

            for plan in layout_plan:
                pn0      = plan["pn0"]
                direct   = plan["direct"]
                children = plan["children"]
                y_start  = plan["y_start"]
                y_end    = plan["y_end"]

                seg0_label   = pn0.get("label","?")    # already /seg0 (short)
                seg0_risk    = pn0.get("risk","INFO")
                seg0_func    = pn0.get("func_info",{})
                seg0_cat     = pn0.get("cat_name","")
                seg0_nid     = f"seg0::{host_label}::{seg0_label}"
                seg0_mid_y   = (y_start + y_end) / 2 - 17

                s0cx, s0cy, s0w, s0h = self._make_node(
                    seg0_label, seg0_x, seg0_mid_y, seg0_risk,
                    node_id=seg0_nid,
                    vuln_count=len(seg0_func.get("vuln_matrix",[])))
                s0_item = self._node_items[-1]
                s0_item.node_type    = "cat"
                s0_item.host_name    = host_label
                s0_item.node_subtype = seg0_cat
                s0_item.full_path    = pn0.get("path", seg0_label)
                self._cat_nodes[(host_label, seg0_label)] = s0_item
                h_item.children.append(s0_item)
                self._draw_edge(hcx + hw/2, hcy, s0cx - s0w/2, s0cy, "#3a6a8a")

                seg1_x = seg0_x + s0w + SEG1_OFF_X

                # Direct endpoints at seg0
                if direct:
                    ep_x = seg1_x
                    for ep in direct:
                        _ep_nid = f"ep::{ep['url']}::{ep.get('method','')}"
                        if _ep_nid in _seen_nids:
                            continue
                        _seen_nids.add(_ep_nid)
                        short = ep["label"][:46] + ("…" if len(ep["label"]) > 46 else "")
                        ecx, ecy, ew, eh = self._make_node(
                            short, ep_x, ep["_y"], ep.get("risk","INFO"),
                            tooltip=ep.get("url",""),
                            node_id=f"ep::{ep['url']}",
                            method=ep.get("method",""),
                            func_assign=ep.get("func_assign") if show_func_annot else None,
                            tech=ep.get("tech") or None)
                        e_item = self._node_items[-1]
                        e_item.node_type = "ep"
                        e_item.host_name = host_label
                        s0_item.children.append(e_item)
                        self._draw_edge(s0cx + s0w/2, s0cy, ecx - ew/2, ecy, "#2a5a4a")

                # Level-1 child segments
                for (pn1, pn1_eps) in children:
                    seg1_label = pn1.get("label","?")    # short /seg1
                    seg1_risk  = pn1.get("risk","INFO")
                    seg1_func  = pn1.get("func_info",{})
                    seg1_cat   = pn1.get("cat_name","")
                    seg1_nid   = f"seg1::{host_label}::{pn1.get('path','')}"
                    pn1_ys     = pn1.get("_y_start", current_y)
                    pn1_ye     = pn1.get("_y_end", pn1_ys)
                    seg1_mid_y = (pn1_ys + pn1_ye) / 2 - 17

                    s1cx, s1cy, s1w, s1h = self._make_node(
                        seg1_label, seg1_x, seg1_mid_y, seg1_risk,
                        node_id=seg1_nid,
                        vuln_count=len(seg1_func.get("vuln_matrix",[])))
                    s1_item = self._node_items[-1]
                    s1_item.node_type    = "cat"
                    s1_item.host_name    = host_label
                    s1_item.node_subtype = seg1_cat
                    s1_item.full_path    = pn1.get("path", seg1_label)
                    self._cat_nodes[(host_label, seg1_label)] = s1_item
                    s0_item.children.append(s1_item)
                    self._draw_edge(s0cx + s0w/2, s0cy, s1cx - s1w/2, s1cy, "#2a5a6a")

                    ep_x2 = seg1_x + s1w + EP_OFF_X
                    for ep in pn1_eps:
                        _ep_nid = f"ep::{ep['url']}::{ep.get('method','')}"
                        if _ep_nid in _seen_nids:
                            continue
                        _seen_nids.add(_ep_nid)
                        short = ep["label"][:46] + ("…" if len(ep["label"]) > 46 else "")
                        ecx, ecy, ew, eh = self._make_node(
                            short, ep_x2, ep["_y"], ep.get("risk","INFO"),
                            tooltip=ep.get("url",""),
                            node_id=f"ep::{ep['url']}",
                            method=ep.get("method",""),
                            func_assign=ep.get("func_assign") if show_func_annot else None,
                            tech=ep.get("tech") or None)
                        e_item = self._node_items[-1]
                        e_item.node_type = "ep"
                        e_item.host_name = host_label
                        s1_item.children.append(e_item)
                        self._draw_edge(s1cx + s1w/2, s1cy, ecx - ew/2, ecy, "#2a5a4a")

            current_y = host_block_end_y

    # ── Cascade state to children ────────────────────────────────────
    def _set_state_cascade(self, item: MindMapNodeItem,
                           done: bool = None, marked: bool = None):
        """Apply done/marked state to item and recursively all its children."""
        def apply_to(node: MindMapNodeItem):
            if done is not None:
                node.state_done = done
            if marked is not None:
                node.state_marked = marked
            node.apply_state()
            self._persist_node(node)
            for child in node.children:
                apply_to(child)
        apply_to(item)

    # ── Right-click context menu ──────────────────────────────────────
    def show_node_menu(self, item: MindMapNodeItem, screen_pos):
        menu = QMenu()
        menu.setStyleSheet(f"""
            QMenu {{
                background: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QMenu::item {{
                padding: 6px 20px 6px 10px;
                border-radius: 3px;
            }}
            QMenu::item:selected {{
                background: {COLOR_ACCENT};
                color: #ffffff;
            }}
            QMenu::separator {{
                height: 1px;
                background: {COLOR_BORDER};
                margin: 3px 6px;
            }}
        """)

        # ── What to copy ──────────────────────────────────────────────
        # For endpoint nodes use the full URL path; for directory nodes use
        # the stored cumulative full_path (e.g. /dir/dir2 not just /dir2).
        if item.url:
            try:
                path_only = urlparse(item.url).path or item.url
            except Exception:
                path_only = item.url
        elif item.full_path:
            path_only = item.full_path
        else:
            path_only = item.label

        copy_act = menu.addAction("📋  Copy Path")
        copy_act.setToolTip(path_only)

        menu.addSeparator()

        done_act = menu.addAction(
            "✅  Mark as Done  (fade out)" if not item.state_done
            else "↩️  Unmark Done  (restore)"
        )

        mark_act = menu.addAction(
            "⭐  Star  (highlight)" if not item.state_marked
            else "★  Remove Star"
        )

        menu.addSeparator()

        cmt_label = "💬  Add Comment…" if not item.state_comment else "💬  Edit Comment…"
        comment_act = menu.addAction(cmt_label)

        # ── Hybrid: Hunt Checklist + Vuln Matrix for cat/func nodes ──
        checklist_act = None
        vuln_matrix_act = None
        if item.node_type in ("cat", "func"):
            menu.addSeparator()
            checklist_act   = menu.addAction("📋  Show Hunt Checklist…")
            vuln_matrix_act = menu.addAction("🎯  Show Vuln Matrix…")

        # ── Endpoint actions ───────────────────────────────────────────
        assign_func_act = None
        if item.node_type == "ep" and item.url:
            menu.addSeparator()
            assign_func_act = menu.addAction("⚙  Assign Function…")

        # ── Add Endpoint — category nodes only ────────────────────────
        add_ep_act = None
        if item.node_type == "cat":
            menu.addSeparator()
            add_ep_act = menu.addAction("➕  Add Endpoint…")

        # Snapshot mutable state NOW — the rebuild triggered by "Apply"
        # will delete this item before Python finishes running the handler
        item_url      = item.url
        item_done     = item.state_done
        item_marked   = item.state_marked
        item_comment  = item.state_comment
        item_type     = item.node_type
        item_host     = item.host_name
        item_label    = item.label      # cat label e.g. "📁 File Operations"

        act = menu.exec_(screen_pos)

        # Guard: item may have been deleted by a rebuild inside the dialog
        def _item_alive():
            try:
                _ = item.node_id   # access any attribute to test
                return True
            except RuntimeError:
                return False

        if act == copy_act:
            QApplication.clipboard().setText(path_only)

        elif act == done_act:
            if _item_alive():
                self._set_state_cascade(item, done=not item_done)

        elif act == mark_act:
            if _item_alive():
                self._set_state_cascade(item, marked=not item_marked)

        elif act == comment_act:
            dlg = QInputDialog()
            dlg.setWindowTitle("Node Comment")
            dlg.setLabelText("Comment (always visible on node):")
            dlg.setTextValue(item_comment)
            dlg.resize(420, 120)
            dlg.setStyleSheet(f"""
                QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
                QLabel    {{ color:{COLOR_TEXT}; }}
                QLineEdit {{
                    background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                    border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px;
                }}
                QPushButton {{
                    background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                    border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px 14px;
                }}
                QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
            """)
            if dlg.exec_() == QDialog.Accepted:
                if _item_alive():
                    item.state_comment = dlg.textValue().strip()
                    item.apply_state()
                    self._persist_node(item)

        elif assign_func_act and act == assign_func_act:
            self._show_assign_function_dialog(item_url)

        elif add_ep_act and act == add_ep_act:
            # item_label is built as f"{icon} {cat_name}" with a SINGLE space.
            # e.g. "📁 File Operations"  or  "🔌 API Endpoints"
            # Strip the leading icon character(s) and whitespace to get the raw name.
            raw_cat = item_label.strip()
            # Split on the first space after the icon — the icon is always one
            # grapheme cluster (possibly multi-codepoint emoji) followed by a space.
            # Using split(" ", 1) on the stripped string is reliable here.
            if " " in raw_cat:
                cat_name_clean = raw_cat.split(" ", 1)[1].strip()
            else:
                cat_name_clean = raw_cat
            self._show_add_endpoint_dialog(cat_name_clean, item_host)

        elif checklist_act and act == checklist_act:
            self._show_hunt_checklist(item_label, item_type)

        elif vuln_matrix_act and act == vuln_matrix_act:
            self._show_vuln_matrix(item_label, item_type)

    # ── Assign Function dialog ────────────────────────────────────────
    def _show_assign_function_dialog(self, endpoint_url: str):
        """
        Let the user assign a function group + sub-function + notes to any
        endpoint. Saved to mindmap_func_assignments.json in the project dir
        (or ~/.hunt_func_assignments.json if no project is open).
        The annotation box appears above the endpoint node immediately after saving.
        """
        project_dir = self._project_dir or os.path.expanduser("~")

        # Load existing assignment for this URL
        existing = FunctionAssignmentManager.get(project_dir, endpoint_url)

        # Build lists of all function groups and sub-functions
        all_groups = sorted(FunctionDefinitions.FUNCTION_MAP.keys())
        # For display: show short path of endpoint
        try:
            display_path = urlparse(endpoint_url).path or endpoint_url
        except Exception:
            display_path = endpoint_url

        DLG_STYLE = f"""
            QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
            QLabel    {{ color:{COLOR_TEXT}; }}
            QComboBox {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px 8px;
            }}
            QComboBox QAbstractItemView {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                selection-background-color:{COLOR_ACCENT};
            }}
            QLineEdit, QTextEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px 8px;
            }}
            QLineEdit:focus, QTextEdit:focus {{ border-color:{COLOR_ACCENT}; }}
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:5px 16px; font-weight:bold;
            }}
            QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
        """

        dlg = QDialog()
        dlg.setWindowTitle("⚙  Assign Function")
        dlg.setMinimumWidth(560)
        dlg.setStyleSheet(DLG_STYLE)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)
        lay.setContentsMargins(18, 14, 18, 14)

        # Endpoint display
        ep_lbl = QLabel(f"<b style='color:{COLOR_TEXT_MUTED};'>Endpoint:</b>  "
                        f"<span style='color:{COLOR_TEXT_BRIGHT};'>{display_path}</span>")
        ep_lbl.setWordWrap(True)
        lay.addWidget(ep_lbl)

        sep = QFrame(); sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet(f"color:{COLOR_BORDER};")
        lay.addWidget(sep)

        # Function group dropdown
        grp_lbl = QLabel("Function Group:")
        grp_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        lay.addWidget(grp_lbl)

        grp_combo = QComboBox()
        grp_combo.addItem("— None / Auto-detect —", "")
        for g in all_groups:
            fi = FunctionDefinitions.FUNCTION_MAP[g]
            grp_combo.addItem(f"{fi.get('function_group', g)}", g)
        # Restore existing selection
        cur_grp = existing.get("func_group","")
        if cur_grp:
            idx = grp_combo.findData(cur_grp)
            if idx >= 0: grp_combo.setCurrentIndex(idx)
        lay.addWidget(grp_combo)

        # Custom group name (shown when "None/Auto" selected)
        custom_grp_edit = QLineEdit()
        custom_grp_edit.setPlaceholderText("Or type a custom function group name…")
        if cur_grp and cur_grp not in all_groups:
            custom_grp_edit.setText(cur_grp)
        lay.addWidget(custom_grp_edit)

        # Sub-function dropdown (updates when group changes)
        sf_lbl = QLabel("Sub-Function / Operation:")
        sf_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        lay.addWidget(sf_lbl)

        sf_combo = QComboBox()
        lay.addWidget(sf_combo)

        def _populate_sf(cat_key: str):
            sf_combo.clear()
            sf_combo.addItem("— General —", "")
            if cat_key and cat_key in FunctionDefinitions.FUNCTION_MAP:
                for sf in FunctionDefinitions.FUNCTION_MAP[cat_key].get("sub_functions",[]):
                    sf_combo.addItem(sf, sf)
            cur_sf = existing.get("sub_func","")
            if cur_sf:
                idx = sf_combo.findData(cur_sf)
                if idx >= 0: sf_combo.setCurrentIndex(idx)

        _populate_sf(grp_combo.currentData())
        grp_combo.currentIndexChanged.connect(lambda: _populate_sf(grp_combo.currentData()))

        # Custom sub-func
        custom_sf_edit = QLineEdit()
        custom_sf_edit.setPlaceholderText("Or type a custom sub-function name…")
        cur_sf = existing.get("sub_func","")
        fi_sfs = FunctionDefinitions.FUNCTION_MAP.get(cur_grp,{}).get("sub_functions",[])
        if cur_sf and cur_sf not in fi_sfs:
            custom_sf_edit.setText(cur_sf)
        lay.addWidget(custom_sf_edit)

        # Notes
        notes_lbl = QLabel("Testing Notes:")
        notes_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        lay.addWidget(notes_lbl)

        notes_edit = QTextEdit()
        notes_edit.setPlaceholderText("e.g. Tested for IDOR — confirmed, waiting for triage…")
        notes_edit.setMaximumHeight(80)
        notes_edit.setPlainText(existing.get("notes",""))
        lay.addWidget(notes_edit)

        # Vuln matrix preview
        def _show_preview():
            cat_key = grp_combo.currentData()
            if not cat_key: return
            fi = FunctionDefinitions.FUNCTION_MAP.get(cat_key,{})
            vmatrix = fi.get("vuln_matrix",[])
            if not vmatrix: return
            lines = [f"  • [{sev}] {vuln}" for sev,vuln,_ in vmatrix[:5]]
            QMessageBox.information(dlg, "Vuln Matrix Preview",
                                    "\n".join(lines) + ("\n  …" if len(vmatrix)>5 else ""))
        preview_btn = QPushButton("👁  Preview Vuln Matrix")
        preview_btn.clicked.connect(_show_preview)
        lay.addWidget(preview_btn)

        # Buttons
        btn_row = QHBoxLayout()
        if existing:
            clear_btn = QPushButton("🗑  Remove Assignment")
            clear_btn.setStyleSheet(
                f"QPushButton {{ background:{COLOR_CRITICAL}; color:#fff; border:none; "
                f"border-radius:4px; padding:5px 14px; font-weight:bold; }}"
                f"QPushButton:hover {{ background:#ff7b7b; }}"
            )
            def _clear():
                FunctionAssignmentManager.remove(project_dir, endpoint_url)
                dlg.accept()
                self._request_rebuild()
            clear_btn.clicked.connect(_clear)
            btn_row.addWidget(clear_btn)

        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(dlg.reject)
        save_btn = QPushButton("💾  Save")
        save_btn.setStyleSheet(
            f"QPushButton {{ background:{COLOR_ACCENT}; color:#fff; border:none; "
            f"border-radius:4px; padding:5px 20px; font-weight:bold; }}"
            f"QPushButton:hover {{ background:#1e7ac0; }}"
        )
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        lay.addLayout(btn_row)

        def _save():
            grp = grp_combo.currentData() or custom_grp_edit.text().strip()
            sf  = sf_combo.currentData()  or custom_sf_edit.text().strip()
            notes = notes_edit.toPlainText().strip()
            if not grp and not sf and not notes:
                dlg.reject(); return
            FunctionAssignmentManager.save_assignment(project_dir, endpoint_url, grp, sf, notes)
            dlg.accept()
            self._request_rebuild()

        save_btn.clicked.connect(_save)
        dlg.exec_()

    # ── Hunt Checklist dialog ─────────────────────────────────────────
    def _show_hunt_checklist(self, node_label: str, node_type: str):
        """Show the ordered hunt checklist for a category or function node."""
        # Resolve category name from label (strip leading icon)
        cat_name = node_label.strip()
        if " " in cat_name:
            cat_name = cat_name.split(" ", 1)[1].strip()
        # For func nodes the node_subtype holds the sub-function name —
        # but we still pull checklist from the parent category definition.
        func_info   = FunctionDefinitions.get_function_info(cat_name)
        checklist   = func_info.get("test_checklist", ["[ ] Review manually"])
        func_group  = func_info.get("function_group", cat_name)
        attack_flows= func_info.get("attack_flows", [])

        dlg = QDialog()
        dlg.setWindowTitle(f"📋 Hunt Checklist — {func_group}")
        dlg.setMinimumSize(640, 520)
        dlg.setStyleSheet(f"""
            QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
            QLabel    {{ color:{COLOR_TEXT}; }}
            QTextEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                font-family:'Consolas','Courier New',monospace; font-size:12px;
                padding: 8px;
            }}
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:6px 20px; font-weight:bold;
            }}
            QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
        """)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)
        lay.setContentsMargins(18, 14, 18, 14)

        title = QLabel(f"<h3 style='color:#ffffff;margin:0;'>{func_group}</h3>"
                       f"<p style='color:{COLOR_TEXT_MUTED};margin:4px 0 0 0;font-size:11px;'>"
                       f"Category: {cat_name}</p>")
        title.setWordWrap(True)
        lay.addWidget(title)

        if attack_flows:
            sep = QFrame(); sep.setFrameShape(QFrame.HLine)
            sep.setStyleSheet(f"color:{COLOR_BORDER};")
            lay.addWidget(sep)
            af_lbl = QLabel("<b style='color:#f39c12;'>⚡ Attack Flows (multi-step scenarios)</b>")
            lay.addWidget(af_lbl)
            for af in attack_flows:
                af_item = QLabel(f"  → {af}")
                af_item.setStyleSheet(f"color:{COLOR_TEXT}; font-size:11px; padding-left:8px;")
                af_item.setWordWrap(True)
                lay.addWidget(af_item)

        sep2 = QFrame(); sep2.setFrameShape(QFrame.HLine)
        sep2.setStyleSheet(f"color:{COLOR_BORDER};")
        lay.addWidget(sep2)

        cl_lbl = QLabel("<b style='color:#4ec9b0;'>✅ Ordered Test Checklist (copy to notes)</b>")
        lay.addWidget(cl_lbl)

        cl_text = QTextEdit()
        cl_text.setReadOnly(False)   # editable so hunter can tick off items
        cl_text.setPlainText("\n".join(checklist))
        lay.addWidget(cl_text)

        copy_btn = QPushButton("📋  Copy Checklist")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(cl_text.toPlainText()))
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)

        btn_row = QHBoxLayout()
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)

        dlg.exec_()

    # ── Vuln Matrix dialog ────────────────────────────────────────────
    def _show_vuln_matrix(self, node_label: str, node_type: str):
        """Show the vulnerability hypothesis matrix for a category or function node."""
        cat_name = node_label.strip()
        if " " in cat_name:
            cat_name = cat_name.split(" ", 1)[1].strip()

        func_info   = FunctionDefinitions.get_function_info(cat_name)
        vuln_matrix = func_info.get("vuln_matrix", [])
        func_group  = func_info.get("function_group", cat_name)
        sub_funcs   = func_info.get("sub_functions", [])

        dlg = QDialog()
        dlg.setWindowTitle(f"🎯 Vuln Matrix — {func_group}")
        dlg.setMinimumSize(760, 540)
        dlg.setStyleSheet(f"""
            QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
            QLabel    {{ color:{COLOR_TEXT}; }}
            QTableWidget {{
                background:{COLOR_BACKGROUND}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                gridline-color:{COLOR_BORDER};
                font-size:12px;
            }}
            QHeaderView::section {{
                background:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; padding:6px;
                font-weight:bold;
            }}
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:6px 20px; font-weight:bold;
            }}
            QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
        """)
        lay = QVBoxLayout(dlg)
        lay.setSpacing(10)
        lay.setContentsMargins(18, 14, 18, 14)

        title = QLabel(f"<h3 style='color:#ffffff;margin:0;'>{func_group}</h3>"
                       f"<p style='color:{COLOR_TEXT_MUTED};margin:4px 0 0 0;font-size:11px;'>"
                       f"Vulnerability hypotheses ordered by likelihood — {cat_name}</p>")
        title.setWordWrap(True)
        lay.addWidget(title)

        if sub_funcs:
            sf_lbl = QLabel("<b style='color:#0e639c;'>⚙ Sub-Functions: </b>"
                            + "  ·  ".join(sub_funcs))
            sf_lbl.setWordWrap(True)
            sf_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px; padding:4px 0;")
            lay.addWidget(sf_lbl)

        tbl = QTableWidget(len(vuln_matrix), 3)
        tbl.setHorizontalHeaderLabels(["Severity", "Vulnerability", "How to Test"])
        tbl.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        tbl.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        tbl.setSelectionBehavior(QAbstractItemView.SelectRows)
        tbl.setEditTriggers(QAbstractItemView.NoEditTriggers)
        tbl.verticalHeader().setVisible(False)

        sev_colors = {
            "🔴 CRITICAL": "#c0392b",
            "🟠 HIGH":     "#e67e22",
            "🟡 MEDIUM":   "#f39c12",
            "⬜ LOW":      "#27ae60",
        }
        for row, (sev, vuln_name, how_to) in enumerate(vuln_matrix):
            sev_item  = QTableWidgetItem(sev)
            vuln_item = QTableWidgetItem(vuln_name)
            how_item  = QTableWidgetItem(how_to)
            color_hex = sev_colors.get(sev.split()[0] + " " + sev.split()[1] if len(sev.split()) > 1 else sev, "#cccccc")
            sev_item.setForeground(QColor(color_hex))
            for it in (sev_item, vuln_item, how_item):
                it.setBackground(QColor("#1e1e1e"))
            tbl.setItem(row, 0, sev_item)
            tbl.setItem(row, 1, vuln_item)
            tbl.setItem(row, 2, how_item)
        tbl.resizeRowsToContents()
        lay.addWidget(tbl)

        copy_btn = QPushButton("📋  Copy as Text")
        def _copy_matrix():
            lines = ["Severity\tVulnerability\tHow to Test"]
            for sev, vuln_name, how_to in vuln_matrix:
                lines.append(f"{sev}\t{vuln_name}\t{how_to}")
            QApplication.clipboard().setText("\n".join(lines))
        copy_btn.clicked.connect(_copy_matrix)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dlg.accept)
        btn_row = QHBoxLayout()
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        lay.addLayout(btn_row)

        dlg.exec_()

    # ── Add Endpoint dialog ───────────────────────────────────────────
    def _show_add_endpoint_dialog(self, category_name: str, host_name: str):
        """
        Dialog to manually add an endpoint to a category.
        Accepts path, path+query, or full URL.
        Auto-normalises the input and deduplicates against existing entries.
        """
        project_dir = self._project_dir
        if not project_dir:
            QMessageBox.warning(None, "No Project",
                                "Open a project first to save manual endpoints.")
            return

        DLG_STYLE = f"""
            QDialog   {{ background:{COLOR_BACKGROUND}; color:{COLOR_TEXT}; }}
            QLabel    {{ color:{COLOR_TEXT}; }}
            QLineEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px 8px;
            }}
            QLineEdit:focus {{ border-color:{COLOR_ACCENT}; }}
            QComboBox {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:5px 8px;
            }}
            QComboBox QAbstractItemView {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                selection-background-color:{COLOR_ACCENT};
            }}
            QTextEdit {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:4px 6px;
                font-family:'Consolas','Courier New',monospace; font-size:11px;
            }}
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; border-radius:4px;
                padding:5px 16px; font-weight:bold;
            }}
            QPushButton:hover {{ background:{COLOR_ACCENT}; color:#fff; border:none; }}
        """

        dlg = QDialog()
        dlg.setWindowTitle(f"➕  Add Endpoint  →  {category_name}")
        dlg.setMinimumWidth(540)
        dlg.setStyleSheet(DLG_STYLE)

        layout = QVBoxLayout(dlg)
        layout.setSpacing(10)
        layout.setContentsMargins(18, 16, 18, 14)

        # ── Header ────────────────────────────────────────────────────
        hdr = QLabel(
            f"<b style='color:{COLOR_ACCENT};'>Category:</b>  "
            f"<span style='color:{COLOR_TEXT_BRIGHT};'>{category_name}</span>  "
            f"<span style='color:{COLOR_TEXT_MUTED};'>| Host: {host_name or '(any)'}</span>"
        )
        hdr.setWordWrap(True)
        layout.addWidget(hdr)

        sep0 = QFrame(); sep0.setFrameShape(QFrame.HLine)
        sep0.setStyleSheet(f"color:{COLOR_BORDER};")
        layout.addWidget(sep0)

        # ── URL input ─────────────────────────────────────────────────
        url_lbl = QLabel("Endpoint  <span style='color:#888;'>(path / path?query / full URL)</span>:")
        url_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        layout.addWidget(url_lbl)

        url_edit = QLineEdit()
        url_edit.setPlaceholderText("/api/v1/users  or  /upload?type=img  or  https://host/path")
        layout.addWidget(url_edit)

        # Preview label — shows normalised form as user types
        preview_lbl = QLabel("")
        preview_lbl.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED}; font-size:11px; "
            f"font-family:'Consolas','Courier New',monospace;"
        )
        layout.addWidget(preview_lbl)

        # ── Method row ────────────────────────────────────────────────
        method_row = QHBoxLayout()
        method_lbl = QLabel("Method:")
        method_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        method_lbl.setFixedWidth(70)
        method_row.addWidget(method_lbl)

        METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        method_combo = QComboBox()
        method_combo.addItems(METHODS)
        method_combo.setFixedWidth(110)
        method_row.addWidget(method_combo)
        method_row.addStretch()
        layout.addLayout(method_row)

        # ── Body parameters (shown only for non-GET methods) ──────────
        body_container = QWidget()
        body_layout    = QVBoxLayout(body_container)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(4)

        body_lbl = QLabel(
            "Body Parameters  "
            "<span style='color:#888;'>(one per line: name=value  or  JSON  or  free text)</span>:"
        )
        body_lbl.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; font-weight:bold;")
        body_layout.addWidget(body_lbl)

        body_edit = QTextEdit()
        body_edit.setPlaceholderText("username=admin\npassword=\ntoken=")
        body_edit.setFixedHeight(90)
        body_layout.addWidget(body_edit)

        layout.addWidget(body_container)

        # Show/hide body section based on method
        def _on_method_changed(txt):
            body_container.setVisible(txt.upper() in ("POST", "PUT", "PATCH", "DELETE"))

        method_combo.currentTextChanged.connect(_on_method_changed)
        _on_method_changed(method_combo.currentText())

        # ── Live normalised preview ───────────────────────────────────
        def _normalise_input(raw: str) -> tuple:
            """
            Accept any of:
              /path
              /path?key=val
              https://host/path?key=val
              host/path
            Returns (full_url, display_path, detected_host)
            """
            raw = raw.strip()
            if not raw:
                return "", "", ""

            # If it starts with http:// or https:// treat as full URL
            if raw.startswith("http://") or raw.startswith("https://"):
                try:
                    p   = urlparse(raw)
                    h   = p.netloc or host_name or "unknown"
                    pth = p.path.rstrip("/") or "/"
                    q   = f"?{p.query}" if p.query else ""
                    full_url = f"{p.scheme}://{h}{pth}{q}"
                    return full_url, f"{pth}{q}", h
                except Exception:
                    pass

            # Treat as path (with or without leading slash)
            if not raw.startswith("/"):
                # Could be "host/path" — split on first /
                if "/" in raw:
                    maybe_host, rest = raw.split("/", 1)
                    if "." in maybe_host:   # looks like a hostname
                        pth = "/" + rest.rstrip("/") or "/"
                        q_sep = "?" if "?" in rest else ""
                        if q_sep:
                            pth, qs = pth.split("?", 1)
                            pth = pth.rstrip("/") or "/"
                            display = f"{pth}?{qs}"
                        else:
                            display = pth
                        full_url = f"https://{maybe_host}{display}"
                        return full_url, display, maybe_host
                raw = "/" + raw

            # Plain path (possibly with query string)
            try:
                p   = urlparse(raw)
                pth = p.path.rstrip("/") or "/"
                q   = f"?{p.query}" if p.query else ""
                display  = f"{pth}{q}"
                h = host_name or "unknown"
                full_url = f"https://{h}{display}"
                return full_url, display, h
            except Exception:
                return raw, raw, host_name or "unknown"

        def _update_preview():
            raw = url_edit.text().strip()
            if not raw:
                preview_lbl.setText("")
                return
            full_url, display, det_host = _normalise_input(raw)
            preview_lbl.setText(
                f"→  <b style='color:{COLOR_TEXT_BRIGHT};'>{display}</b>"
                f"  <span style='color:{COLOR_TEXT_MUTED};'>(host: {det_host})</span>"
            )

        url_edit.textChanged.connect(_update_preview)

        # ── Duplicate info label ──────────────────────────────────────
        dup_lbl = QLabel("")
        dup_lbl.setStyleSheet(f"color:{COLOR_WARNING}; font-size:11px;")
        layout.addWidget(dup_lbl)

        # ── Buttons ───────────────────────────────────────────────────
        sep1 = QFrame(); sep1.setFrameShape(QFrame.HLine)
        sep1.setStyleSheet(f"color:{COLOR_BORDER};")
        layout.addWidget(sep1)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("➕  Add Endpoint")
        add_btn.setStyleSheet(
            f"QPushButton {{ background:{COLOR_ACCENT}; color:#fff; border:none; "
            f"border-radius:4px; padding:6px 20px; font-weight:bold; }}"
            f"QPushButton:hover {{ background:#1e7ac0; }}"
        )
        cancel_btn = QPushButton("Cancel")
        btn_row.addStretch()
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(add_btn)
        layout.addLayout(btn_row)

        cancel_btn.clicked.connect(dlg.reject)

        def _do_add():
            raw = url_edit.text().strip()
            if not raw:
                url_edit.setStyleSheet(url_edit.styleSheet() +
                                       "border-color:#f48771;")
                return

            full_url, display, det_host = _normalise_input(raw)
            method      = method_combo.currentText().upper()
            body_params = body_edit.toPlainText().strip()
            eff_host    = det_host or host_name or "unknown"

            saved = CategoryOverrideManager.save_manual_endpoint(
                project_dir, full_url, method, body_params,
                category_name, eff_host
            )
            if not saved:
                dup_lbl.setText(
                    f"⚠️  {method} {display} already exists in {category_name}"
                )
                return

            dlg.accept()

        add_btn.clicked.connect(_do_add)
        url_edit.returnPressed.connect(_do_add)

        if dlg.exec_() == QDialog.Accepted:
            self._request_rebuild()

    def _request_rebuild(self):
        """Ask the parent MindMapWidget to rebuild the map from scratch."""
        if callable(self._rebuild_callback):
            self._rebuild_callback()


# ============================================================================

class MindMapWidget(QWidget):
    """Mind-map sub-tab for the Mapping tab"""

    def __init__(self, mapping_tab, parent=None):
        super().__init__(parent)
        self.mapping_tab = mapping_tab
        self._built = False
        self._init_ui()

    def _get_state_path(self) -> str:
        """Return the path to the node-states JSON for the current project."""
        try:
            pp = self.mapping_tab.parent_gui._project_paths
            if pp and pp.get("project_dir"):
                d = os.path.join(pp["project_dir"], "mindmap_states.json")
                return d
        except Exception:
            pass
        return os.path.expanduser("~/.hunt_mindmap_states.json")

    def _get_project_dir(self) -> str:
        """Return the current project directory, or empty string if none."""
        try:
            pp = self.mapping_tab.parent_gui._project_paths
            if pp and pp.get("project_dir"):
                return pp["project_dir"]
        except Exception:
            pass
        return ""

    # ------------------------------------------------------------------
    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Toolbar ───────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setMaximumHeight(45)
        toolbar.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(10, 5, 10, 5)

        btn_style = f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 5px 14px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                border-color: {COLOR_ACCENT};
            }}
        """

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(btn_style)
        refresh_btn.clicked.connect(lambda: self.build_from_surface(self.mapping_tab))
        tb_layout.addWidget(refresh_btn)

        fit_btn = QPushButton("⊡ Fit to View")
        fit_btn.setStyleSheet(btn_style)
        fit_btn.clicked.connect(self._fit_view)
        tb_layout.addWidget(fit_btn)

        # ── Host filter dropdown ──────────────────────────────────────
        sep1 = QFrame(); sep1.setFrameShape(QFrame.VLine)
        sep1.setStyleSheet(f"color:{COLOR_BORDER}; max-width:2px;")
        tb_layout.addWidget(sep1)

        tb_layout.addWidget(QLabel("  🖥 Host:"))
        self.host_filter_combo = QComboBox()
        self.host_filter_combo.setMinimumWidth(160)
        self.host_filter_combo.setStyleSheet(f"""
            QComboBox {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:3px 8px;
                font-size: 12px;
            }}
            QComboBox::drop-down {{ border:none; width:18px; }}
            QComboBox QAbstractItemView {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                selection-background-color:{COLOR_ACCENT};
            }}
        """)
        self.host_filter_combo.addItem("🌐  All Hosts", "")
        self.host_filter_combo.currentIndexChanged.connect(self._apply_filters)
        tb_layout.addWidget(self.host_filter_combo)

        # ── Response code filter ─────────────────────────────────────
        sep2 = QFrame(); sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"color:{COLOR_BORDER}; max-width:2px;")
        tb_layout.addWidget(sep2)

        tb_layout.addWidget(QLabel(" Status:"))

        combo_style = f"""
            QComboBox {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT_BRIGHT};
                border:1px solid {COLOR_BORDER}; border-radius:4px; padding:3px 8px;
                font-size: 12px;
            }}
            QComboBox::drop-down {{ border:none; width:18px; }}
            QComboBox QAbstractItemView {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                selection-background-color:{COLOR_ACCENT};
            }}
        """

        self.status_filter_combo = QComboBox()
        self.status_filter_combo.setMinimumWidth(130)
        self.status_filter_combo.setStyleSheet(combo_style)
        self.status_filter_combo.addItem("All Codes",  "")
        self.status_filter_combo.addItem("2xx Success", "2xx")
        self.status_filter_combo.addItem("3xx Redirect", "3xx")
        self.status_filter_combo.addItem("4xx Client Err", "4xx")
        self.status_filter_combo.addItem("5xx Server Err", "5xx")
        self.status_filter_combo.currentIndexChanged.connect(self._apply_filters)
        tb_layout.addWidget(self.status_filter_combo)

        # ── Starred only toggle ───────────────────────────────────────
        self.starred_only_btn = QPushButton("⭐ Starred Only")
        self.starred_only_btn.setCheckable(True)
        self.starred_only_btn.setChecked(False)
        self.starred_only_btn.setStyleSheet(f"""
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; padding:4px 12px;
                border-radius:4px; font-weight:bold;
            }}
            QPushButton:checked {{
                background:#7d6608; color:#f0c040;
                border:1px solid #f0c040;
            }}
            QPushButton:hover {{ background:{COLOR_HOVER}; border-color:{COLOR_ACCENT}; }}
        """)
        self.starred_only_btn.toggled.connect(self._apply_filters)
        tb_layout.addWidget(self.starred_only_btn)

        # ── Function annotations toggle ───────────────────────────────
        # Shows a compact ⚙ box above endpoint nodes that have a function
        # assignment — ON by default. Toggle OFF to reduce visual noise.
        self.func_annot_btn = QPushButton("⚙ Func Labels")
        self.func_annot_btn.setCheckable(True)
        self.func_annot_btn.setChecked(True)
        self.func_annot_btn.setToolTip(
            "Show/hide function annotation boxes above endpoint nodes.\n"
            "Right-click any endpoint → Assign Function… to set one.\n"
            "Assignments are saved per-project."
        )
        self.func_annot_btn.setStyleSheet(f"""
            QPushButton {{
                background:{COLOR_CARD_BG}; color:{COLOR_TEXT};
                border:1px solid {COLOR_BORDER}; padding:4px 12px;
                border-radius:4px; font-weight:bold;
            }}
            QPushButton:checked {{
                background:#1a3a6b; color:#48dbfb;
                border:1px solid #48dbfb;
            }}
            QPushButton:hover {{ background:{COLOR_HOVER}; border-color:{COLOR_ACCENT}; }}
        """)
        self.func_annot_btn.toggled.connect(self._apply_filters)
        tb_layout.addWidget(self.func_annot_btn)

        # ── Function label filter ─────────────────────────────────────
        sep3 = QFrame(); sep3.setFrameShape(QFrame.VLine)
        sep3.setStyleSheet(f"color:{COLOR_BORDER}; max-width:2px;")
        tb_layout.addWidget(sep3)

        tb_layout.addWidget(QLabel(" ⚙ Func:"))
        self.func_filter_combo = QComboBox()
        self.func_filter_combo.setMinimumWidth(190)
        self.func_filter_combo.setToolTip(
            "Filter endpoints by category or sub-function.\n"
            "Select a category to show all its endpoints,\n"
            "or a ↳ sub-function to narrow down further."
        )
        self.func_filter_combo.setStyleSheet(combo_style)
        self.func_filter_combo.addItem("⚙ All Categories", "")
        self.func_filter_combo.currentIndexChanged.connect(self._apply_filters)
        tb_layout.addWidget(self.func_filter_combo)

        tb_layout.addStretch()

        # Hunt progress label
        self.hunt_progress_lbl = QLabel(" 0/0 done")
        self.hunt_progress_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
        tb_layout.addWidget(self.hunt_progress_lbl)

        tb_layout.addStretch()

        # Legend
        legend_label = QLabel(
            "  Legend: "
            "<span style='color:#c0392b'>■</span> CRITICAL  "
            "<span style='color:#e67e22'>■</span> HIGH  "
            "<span style='color:#f39c12'>■</span> MEDIUM  "
            "<span style='color:#27ae60'>■</span> LOW  "
            "<span style='color:#6c3483'>■</span> Root  "
            "<span style='color:#1a5276'>■</span> Host  "
            "  Method: <span style='color:#27ae60'>■</span>GET "
            "<span style='color:#2980b9'>■</span>POST "
            "<span style='color:#d35400'>■</span>PUT "
            "<span style='color:#c0392b'>■</span>DELETE  "
            "<span style='color:#48dbfb'>▬</span> Func Annotation"
        )
        legend_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        tb_layout.addWidget(legend_label)

        layout.addWidget(toolbar)

        # ── Graphics view ─────────────────────────────────────────────
        self.scene = MindMapScene(self)
        self.scene.state_changed.connect(self._update_hunt_progress)
        self.view  = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setRenderHint(QPainter.TextAntialiasing)
        self.view.setDragMode(QGraphicsView.ScrollHandDrag)
        self.view.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setResizeAnchor(QGraphicsView.AnchorUnderMouse)
        self.view.setStyleSheet(f"background-color: #181818; border: none;")
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)

        # Mouse-wheel zoom
        self.view.wheelEvent = self._wheel_event

        layout.addWidget(self.view)

        # ── Placeholder text ──────────────────────────────────────────
        self._placeholder = QGraphicsTextItem(
            "No data yet.\nStart Mapping in the 🗺️ Mapping tab first,\nthen switch here to see the Mind Map."
        )
        self._placeholder.setDefaultTextColor(QColor(COLOR_TEXT_MUTED))
        font = QFont("Segoe UI", 14)
        self._placeholder.setFont(font)
        self._placeholder.setPos(80, 80)
        self.scene.addItem(self._placeholder)

    # ------------------------------------------------------------------
    def _fit_view(self):
        self.view.fitInView(self.scene.itemsBoundingRect(), Qt.KeepAspectRatio)

    def _on_zoom(self, value):
        scale = value / 100.0
        self.view.resetTransform()
        self.view.scale(scale, scale)

    def _wheel_event(self, event):
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.view.scale(factor, factor)

    # ------------------------------------------------------------------
    def _update_hunt_progress(self):
        """Refresh the hunt-progress label: X/Y endpoint nodes marked done."""
        if not hasattr(self, 'hunt_progress_lbl'):
            return
        total = 0
        done  = 0
        for item in self.scene._node_items:
            if item.node_type == "ep":
                total += 1
                if item.state_done:
                    done += 1
        if total == 0:
            self.hunt_progress_lbl.setText("  0/0 done")
            self.hunt_progress_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:11px;")
            return
        pct = int(done / total * 100)
        color = COLOR_SUCCESS if pct == 100 else COLOR_MEDIUM if pct > 50 else COLOR_TEXT_MUTED
        self.hunt_progress_lbl.setText(f"  {done}/{total} done ({pct}%)")
        self.hunt_progress_lbl.setStyleSheet(f"color:{color}; font-size:11px; font-weight:bold;")

    # ------------------------------------------------------------------
    def build_from_surface(self, surface_tab):
        """Extract data from MappingTabPro and render the mind-map."""
        data = self._extract_data(surface_tab)

        # Set / refresh the persistence path before building
        self.scene.set_save_path(self._get_state_path())

        # Wire project dir so category overrides can be loaded/saved
        self.scene._project_dir = self._get_project_dir()

        # Wire rebuild callback so "Assign Function → Save" triggers a fresh build
        self.scene._rebuild_callback = lambda: self.build_from_surface(surface_tab)

        self.scene.clear_map()

        if not data["hosts"]:
            self._placeholder = QGraphicsTextItem(
                "No endpoints mapped yet.\nStart Mapping in the 🗺️ Mapping tab first."
            )
            self._placeholder.setDefaultTextColor(QColor(COLOR_TEXT_MUTED))
            self._placeholder.setFont(QFont("Segoe UI", 14))
            self._placeholder.setPos(80, 80)
            self.scene.addItem(self._placeholder)
            return

        # Populate host filter dropdown (preserve current selection)
        current_host = self.host_filter_combo.currentData() or ""
        self.host_filter_combo.blockSignals(True)
        self.host_filter_combo.clear()
        self.host_filter_combo.addItem("🌐  All Hosts", "")
        for h in data.get("hosts", []):
            label = h.get("label", "")
            self.host_filter_combo.addItem(f"🖥  {label}", label)
        # Restore previous selection if still exists
        idx = self.host_filter_combo.findData(current_host)
        self.host_filter_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self.host_filter_combo.blockSignals(False)

        # Populate func/category filter dropdown (preserve current selection)
        current_func = self.func_filter_combo.currentData() or ""
        # Collect which categories have endpoints, and which sub-funcs per category
        from collections import defaultdict as _dd
        _cat_to_sfs: dict = _dd(set)
        for _h in data.get("hosts", []):
            for _pn0 in _h.get("path_nodes", []):
                _all_eps = list(_pn0.get("endpoints", []))
                for _pn1 in _pn0.get("children", []):
                    _all_eps += _pn1.get("endpoints", [])
                for _ep in _all_eps:
                    _cn = _ep.get("cat_name", "")
                    _sf = _ep.get("func_assign", {}).get("sub_func", "")
                    if _cn and _cn != "Uncategorized":
                        _cat_to_sfs[_cn].add(_sf)
        self.func_filter_combo.blockSignals(True)
        self.func_filter_combo.clear()
        self.func_filter_combo.addItem("⚙ All Categories", "")
        for _cat in CategoryDefinitions.CATEGORY_PRIORITY:
            if _cat not in _cat_to_sfs:
                continue
            _defn = CategoryDefinitions.RISK_CATEGORIES.get(_cat, {})
            _icon = _defn.get("icon", "📋")
            # Category-level item
            self.func_filter_combo.addItem(f"{_icon} {_cat}", f"cat::{_cat}")
            # Sub-function items indented under the category
            for _sf in sorted(_cat_to_sfs[_cat] - {"", None}):
                self.func_filter_combo.addItem(f"   ↳ {_sf}", f"sf::{_sf}")
        idx2 = self.func_filter_combo.findData(current_func)
        self.func_filter_combo.setCurrentIndex(idx2 if idx2 >= 0 else 0)
        self.func_filter_combo.blockSignals(False)

        # Build with current filters
        host_filter      = self.host_filter_combo.currentData() or ""
        starred_only     = self.starred_only_btn.isChecked()
        status_filter    = self.status_filter_combo.currentData() or ""
        show_func_annot  = self.func_annot_btn.isChecked()
        func_filter      = self.func_filter_combo.currentData() or ""
        self.scene.build(data, host_filter=host_filter, starred_only=starred_only,
                         status_filter=status_filter, show_func_annot=show_func_annot,
                         func_filter=func_filter)
        self._fit_view()
        self._built = True
        self._update_hunt_progress()

    def _apply_filters(self, *_):
        """Re-render the scene applying current host + status + starred + func-annot filters."""
        data = self.scene._last_data
        if not data:
            return
        host_filter      = self.host_filter_combo.currentData() or ""
        starred_only     = self.starred_only_btn.isChecked()
        status_filter    = self.status_filter_combo.currentData() or ""
        show_func_annot  = self.func_annot_btn.isChecked()
        func_filter      = self.func_filter_combo.currentData() or ""
        self.scene.build(data, host_filter=host_filter, starred_only=starred_only,
                         status_filter=status_filter, show_func_annot=show_func_annot,
                         func_filter=func_filter)
        self._fit_view()
        self._update_hunt_progress()

    # ------------------------------------------------------------------
    def _extract_data(self, surface_tab) -> dict:
        """
        Build a PATH-TREE from the live MappingTabPro data.

        New structure (Hybrid Approach):
          ROOT
          └── HOST (api.example.com)
               ├── /api              ← path-segment node
               │    ├── /api/v1      ← path-segment node
               │    │    ├── /api/v1/users    ← path-segment node
               │    │    │    ├── GET  /api/v1/users        ← endpoint leaf
               │    │    │    └── POST /api/v1/users ❰name,email❱
               │    │    └── /api/v1/orders
               │    │         └── GET  /api/v1/orders?id
               │    └── /api/v2
               │         └── ...
               └── /auth
                    └── /auth/login
                         └── POST /auth/login ❰username,password❱

        Each path node carries:
          - risk / icon   → from security-category match (for colour coding)
          - hints         → attack hints for that path cluster
          - func_info     → FunctionDefinitions entry for the matched category
          - endpoints     → leaf endpoint dicts
        """
        all_hosts = list(surface_tab.subdomain_map.keys())
        root_label = all_hosts[0] if len(all_hosts) == 1 else "Web Application"
        if hasattr(surface_tab, 'parent_gui') and hasattr(surface_tab.parent_gui, 'project'):
            proj = surface_tab.parent_gui.project
            if isinstance(proj, dict):
                root_label = proj.get("name", root_label) or root_label

        data = {"root": {"label": root_label, "url": ""}, "hosts": []}

        cat_defs    = CategoryDefinitions.RISK_CATEGORIES
        project_dir = self._get_project_dir()

        # Load manually-added endpoints keyed by host → category
        manual_eps: dict = defaultdict(lambda: defaultdict(list))
        if project_dir:
            for mep in CategoryOverrideManager.load_manual_endpoints(project_dir):
                manual_eps[mep.get("host","unknown")][mep.get("category","Uncategorized")].append(mep)

        # ── Collect every url_data across ALL categories for each host ──
        # We discard the category grouping and re-group by path tree.
        # The category is kept as metadata on each endpoint for risk/hints.
        for host, cat_map in surface_tab.subdomain_map.items():
            all_url_data = []
            for cat_name, url_data_list in cat_map.items():
                for ud in url_data_list:
                    all_url_data.append((cat_name, ud))

            # Inject manual endpoints too
            for mep_cat, mep_list in manual_eps.get(host, {}).items():
                for mep in mep_list:
                    murl   = mep.get("url","")
                    mmethod= mep.get("method","GET").upper()
                    if project_dir:
                        defn = CategoryOverrideManager.get_category_def(project_dir, mep_cat)
                    else:
                        defn = cat_defs.get(mep_cat, {})
                    synthetic_ud = {
                        "url":      murl,
                        "method":   mmethod,
                        "status":   mep.get("status", 0),
                        "risk":     defn.get("risk", "INFO"),
                        "icon":     defn.get("icon", "📂"),
                        "hints":    defn.get("hints", []),
                        "analysis": {"param_names": []},
                        "finding":  {},
                    }
                    all_url_data.append((mep_cat, synthetic_ud))

            if not all_url_data:
                continue

            # ── Build path tree ───────────────────────────────────────
            # path_tree: dict of { path_prefix: { endpoints:[], children:{} } }
            # We keep max 2 levels of prefix nodes to avoid over-deep trees.
            #   Level 0: /segment1
            #   Level 1: /segment1/segment2
            #   Endpoints that are deeper attach at level 1.

            # Helper: normalise path
            def _norm_path(url: str) -> str:
                try:
                    p = urlparse(url).path.rstrip("/") or "/"
                    return p
                except Exception:
                    return "/"

            def _path_segments(url: str) -> list:
                try:
                    return [s for s in urlparse(url).path.split("/") if s]
                except Exception:
                    return []

            def _risk_sort_key(risk: str) -> int:
                return {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(risk, 5)

            # Two-level path tree:
            # tree[seg0][seg1] = list of endpoint dicts
            # tree[seg0]["_endpoints"] = endpoints that live directly at /seg0 (depth==1)
            tree: dict = {}   # seg0 -> { "_endpoints": [...], seg1: [...], ... }

            seen_eps: set = set()

            # Load category overrides once so every endpoint can be
            # re-mapped to its user-chosen category on-the-fly.
            _cat_overrides: dict = CategoryOverrideManager.load_overrides(project_dir) if project_dir else {}

            for (cat_name, ud) in all_url_data:
                url    = ud.get("url","")
                method = ud.get("method","GET")
                if not url:
                    continue

                path   = _norm_path(url)
                segs   = _path_segments(url)
                key    = (method.upper(), path)
                if key in seen_eps:
                    continue
                seen_eps.add(key)

                # Apply user category override if present
                effective_cat = _cat_overrides.get(url, cat_name)

                # Resolve risk/icon/hints/func from the effective category
                if project_dir:
                    defn = CategoryOverrideManager.get_category_def(project_dir, effective_cat)
                    risk = defn.get("risk", ud.get("risk","INFO"))
                    icon = defn.get("icon", ud.get("icon","📋"))
                    hints= defn.get("hints", ud.get("hints",[]))
                else:
                    risk = ud.get("risk","INFO")
                    icon = ud.get("icon","📋")
                    hints= ud.get("hints",[])

                analysis    = ud.get("analysis", {})
                param_names = analysis.get("param_names", [])

                # Build display label.
                # depth 1-2 → show /last_segment (the seg-dir node gives context).
                # depth 3+  → show /seg2/.../segN so endpoints grouped under the
                #              same /seg1 directory stay distinguishable.
                if len(segs) >= 3:
                    tail = "/".join(segs[2:])
                    short_label = f"/{tail[:44]}" + ("…" if len(tail) > 44 else "")
                elif segs:
                    short_label = f"/{segs[-1][:44]}" + ("…" if len(segs[-1]) > 44 else "")
                else:
                    short_label = path[:44] + ("…" if len(path) > 44 else "")
                if param_names:
                    pstr = ", ".join(param_names[:6])
                    if len(param_names) > 6: pstr += f" +{len(param_names)-6}"
                    param_display = f"  ❰{pstr}❱" if method.upper() in ("POST","PUT","PATCH") else f"  ?{pstr}"
                    label = short_label + param_display
                else:
                    label = short_label

                # Load any persisted function assignment for this endpoint.
                # Fall back to the auto-derived function info from the
                # effective category so the "Func Labels" button always
                # shows something meaningful even without a manual assignment.
                fa_dir      = project_dir or os.path.expanduser("~")
                func_assign = FunctionAssignmentManager.get(fa_dir, url)
                if not (func_assign.get("func_group") or func_assign.get("sub_func")):
                    if effective_cat != "Uncategorized":
                        _fi = FunctionDefinitions.get_function_info(effective_cat)
                        _fg = _fi.get("function_group", "")
                        _subs = _fi.get("sub_functions", [])
                        func_assign = {
                            "func_group": _fg,
                            "sub_func":   _subs[0] if _subs else "",
                            "notes":      "",
                            "_auto":      True,   # flag: auto-derived, not user-set
                        }

                ep = {
                    "label":       label,
                    "method":      method.upper(),
                    "risk":        risk,
                    "icon":        icon,
                    "hints":       hints,
                    "url":         url,
                    "status":      ud.get("status", 0),
                    "cat_name":    effective_cat,
                    "_path":       path,
                    "_segs":       segs,
                    "func_assign": func_assign,   # persisted user assignment
                    "tech":        FunctionDefinitions.detect_tech(url),
                }

                seg0 = segs[0] if segs else "__root__"
                if seg0 not in tree:
                    tree[seg0] = {"_endpoints": []}

                if len(segs) <= 1:
                    tree[seg0]["_endpoints"].append(ep)
                else:
                    seg1 = segs[1]
                    if seg1 not in tree[seg0]:
                        tree[seg0][seg1] = []
                    tree[seg0][seg1].append(ep)

            # ── Convert tree → list of path_node dicts ─────────────────
            # path_node: { label, path, risk, icon, hints, func_info,
            #              endpoints: [...], children: [...path_node...] }
            def _best_risk(eps: list) -> str:
                order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
                best  = "INFO"
                for ep in eps:
                    if order.get(ep.get("risk","INFO"),5) < order.get(best,5):
                        best = ep.get("risk","INFO")
                return best

            def _best_cat(eps: list) -> str:
                """Pick the highest-risk category name from a list of endpoints."""
                order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
                best_risk = "INFO"
                best_cat  = "Uncategorized"
                for ep in eps:
                    r = ep.get("risk","INFO")
                    if order.get(r,5) < order.get(best_risk,5):
                        best_risk = r
                        best_cat  = ep.get("cat_name","Uncategorized")
                return best_cat

            def _sort_eps(eps: list) -> list:
                return sorted(eps, key=lambda ep: (
                    len(ep.get("_segs",[])),
                    "/".join(
                        "~" if (s.isdigit() or (len(s)==36 and s.count("-")==4))
                        else s.lower()
                        for s in ep.get("_segs",[])
                    ),
                    ep.get("method","GET")
                ))

            path_nodes = []

            for seg0, subtree in sorted(tree.items()):
                # Collect all eps under seg0 (direct + all children)
                direct_eps   = subtree.get("_endpoints", [])
                child_keys   = [k for k in subtree if k != "_endpoints"]

                all_seg0_eps = list(direct_eps)
                for ck in child_keys:
                    all_seg0_eps.extend(subtree[ck])

                seg0_risk    = _best_risk(all_seg0_eps)
                seg0_cat     = _best_cat(all_seg0_eps)
                seg0_defn    = cat_defs.get(seg0_cat, {})
                seg0_icon    = seg0_defn.get("icon","📂")
                seg0_hints   = seg0_defn.get("hints",[])
                seg0_func    = FunctionDefinitions.get_function_info(seg0_cat)

                seg0_node = {
                    "label":     f"/{seg0}",          # SHORT: just /seg0
                    "path":      f"/{seg0}",
                    "risk":      seg0_risk,
                    "icon":      seg0_icon,
                    "hints":     seg0_hints,
                    "func_info": seg0_func,
                    "cat_name":  seg0_cat,
                    "endpoints": _sort_eps(direct_eps),
                    "children":  [],
                }

                # Build level-1 children — label is SHORT /seg1 only
                for seg1 in sorted(child_keys):
                    seg1_eps  = subtree[seg1]
                    seg1_risk = _best_risk(seg1_eps)
                    seg1_cat  = _best_cat(seg1_eps)
                    seg1_defn = cat_defs.get(seg1_cat, {})
                    seg1_func = FunctionDefinitions.get_function_info(seg1_cat)

                    seg0_node["children"].append({
                        "label":     f"/{seg1}",      # SHORT: just /seg1
                        "path":      f"/{seg0}/{seg1}",
                        "risk":      seg1_risk,
                        "icon":      seg1_defn.get("icon","📂"),
                        "hints":     seg1_defn.get("hints",[]),
                        "func_info": seg1_func,
                        "cat_name":  seg1_cat,
                        "endpoints": _sort_eps(seg1_eps),
                        "children":  [],
                    })

                path_nodes.append(seg0_node)

            # Sort top-level path nodes: highest risk first, then alpha
            path_nodes.sort(key=lambda n: (_risk_sort_key(n["risk"]), n["label"]))

            if path_nodes:
                data["hosts"].append({"label": host, "path_nodes": path_nodes})

        # ── Add manual-only hosts (never seen by proxy) ────────────────
        existing_hosts = {h["label"] for h in data["hosts"]}
        for mep_host, mep_cats in manual_eps.items():
            if mep_host in existing_hosts:
                continue
            all_url_data = []
            for mep_cat, mep_list in mep_cats.items():
                for mep in mep_list:
                    murl   = mep.get("url","")
                    mmethod= mep.get("method","GET").upper()
                    if project_dir:
                        defn = CategoryOverrideManager.get_category_def(project_dir, mep_cat)
                    else:
                        defn = cat_defs.get(mep_cat, {})
                    all_url_data.append((mep_cat, {
                        "url": murl, "method": mmethod, "status": 0,
                        "risk": defn.get("risk","INFO"), "icon": defn.get("icon","📂"),
                        "hints": defn.get("hints",[]), "analysis": {"param_names":[]},
                    }))
            # Reuse same tree-building logic (simplified single-pass)
            mini_tree: dict = {}
            mini_seen: set = set()
            for (cat_name, ud) in all_url_data:
                url  = ud.get("url","")
                segs = [s for s in urlparse(url).path.split("/") if s] if url else []
                _mkey = (ud.get("method","GET").upper(), "/".join(segs))
                if _mkey in mini_seen:
                    continue
                mini_seen.add(_mkey)
                if len(segs) >= 3:
                    ep_label = f"/{'/'.join(segs[2:])}"
                elif segs:
                    ep_label = f"/{segs[-1]}"
                else:
                    ep_label = url
                ep   = {"label": ep_label, "method": ud["method"],
                        "risk": ud["risk"], "icon": ud["icon"], "hints": ud["hints"],
                        "url": url, "status": 0, "cat_name": cat_name,
                        "_path": "/".join(segs), "_segs": segs}
                seg0 = segs[0] if segs else "__root__"
                mini_tree.setdefault(seg0, {"_endpoints": []})
                if len(segs) <= 1:
                    mini_tree[seg0]["_endpoints"].append(ep)
                else:
                    mini_tree[seg0].setdefault(segs[1], []).append(ep)

            path_nodes = []
            for seg0, subtree in sorted(mini_tree.items()):
                direct_eps = subtree.get("_endpoints",[])
                child_keys = [k for k in subtree if k != "_endpoints"]
                all_eps    = list(direct_eps) + [e for ck in child_keys for e in subtree[ck]]
                seg0_node  = {"label": f"/{seg0}", "path": f"/{seg0}",
                               "risk": _best_risk(all_eps), "icon":"📂", "hints":[],
                               "func_info": {}, "cat_name": _best_cat(all_eps),
                               "endpoints": direct_eps, "children": []}
                for seg1 in sorted(child_keys):
                    eps = subtree[seg1]
                    seg0_node["children"].append({
                        "label": f"/{seg1}", "path": f"/{seg0}/{seg1}",
                        "risk": _best_risk(eps), "icon":"📂", "hints":[],
                        "func_info": {}, "cat_name": _best_cat(eps),
                        "endpoints": eps, "children": []})
                path_nodes.append(seg0_node)
            path_nodes.sort(key=lambda n: (_risk_sort_key(n["risk"]), n["label"]))
            if path_nodes:
                data["hosts"].append({"label": mep_host, "path_nodes": path_nodes})

        return data


# ============================================================================

class MappingTabPro(QWidget):
    """Professional Mapping Tab"""
    
    def __init__(self, parent_gui):
        super().__init__()
        self.parent_gui = parent_gui
        self.subdomain_map = defaultdict(lambda: defaultdict(list))
        self.extension_map = defaultdict(lambda: defaultdict(list))  # host -> ext_group -> [url_data]
        self.seen_urls = set()
        self.mapping_active = False
        self.init_ui()
    
    def init_ui(self):
        """Initialize the professional UI with Mapping + Mind Map sub-tabs"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ── Sub-tab container ──────────────────────────────────────────────
        self.sub_tabs = QTabWidget()
        self.sub_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
                background-color: {COLOR_BACKGROUND};
            }}
            QTabBar::tab {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                padding: 8px 22px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                margin-right: 3px;
                font-size: 13px;
                font-weight: bold;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border-bottom: 2px solid {COLOR_ACCENT};
            }}
            QTabBar::tab:hover {{
                background-color: {COLOR_HOVER};
            }}
        """)

        # ── Sub-tab 1: Mapping (the original content) ──────────────────────
        mapping_widget = QWidget()
        mapping_layout = QVBoxLayout(mapping_widget)
        mapping_layout.setContentsMargins(0, 0, 0, 0)
        mapping_layout.setSpacing(0)

        toolbar = self.create_toolbar()
        mapping_layout.addWidget(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        splitter.setSizes([350, 650])
        mapping_layout.addWidget(splitter)

        self.sub_tabs.addTab(mapping_widget, "🗺️  Mapping")

        # ── Sub-tab 2: Mind Map ────────────────────────────────────────────
        self.mind_map_widget = MindMapWidget(self)
        self.sub_tabs.addTab(self.mind_map_widget, "Mind Map")

        # ── Sub-tab 3: Findings ───────────────────────────────────────────
        if RecordedTab is not None:
            self.recorded_tab = RecordedTab(self)
            self.sub_tabs.addTab(self.recorded_tab, "Findings")
        else:
            self.recorded_tab = None

        # Refresh sub-tabs when activated
        self.sub_tabs.currentChanged.connect(self._on_subtab_changed)

        layout.addWidget(self.sub_tabs)

        self.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_BACKGROUND};
                color: {COLOR_TEXT};
            }}
        """)

        # Auto-start: connect to monitor_thread.load_complete so mapping
        # begins only after all existing findings are fully loaded.
        # We defer the connection because monitor_thread is created after us.
        QTimer.singleShot(500, self._connect_autostart)

    def _on_subtab_changed(self, index):
        """Refresh sub-tabs when activated"""
        if index == 1:
            self.mind_map_widget.build_from_surface(self)
        elif index == 2:
            # Index 2 is the Recorded tab (when no custom_mind_map_widget present)
            if hasattr(self, 'recorded_tab') and self.recorded_tab is not None:
                self.recorded_tab.on_tab_shown()
            elif hasattr(self, 'custom_mind_map_widget'):
                self.custom_mind_map_widget.refresh_project()
        elif index == 3:
            # Index 3 is the Recorded tab when custom_mind_map_widget also exists
            if hasattr(self, 'recorded_tab') and self.recorded_tab is not None:
                self.recorded_tab.on_tab_shown()

    def _connect_autostart(self):
        """
        Connect to monitor_thread.load_complete so start_mapping fires only
        after all existing findings are fully loaded into parent_gui.findings.
        Retries every 500 ms until the thread exists.
        """
        try:
            thread = self.parent_gui.monitor_thread
            if thread is not None:
                try:
                    thread.load_complete.disconnect(self._autostart_on_load)
                except Exception:
                    pass
                thread.load_complete.connect(self._autostart_on_load)
                # Already loaded before we connected?
                if hasattr(self.parent_gui, 'findings') and len(self.parent_gui.findings) > 0:
                    if not self.mapping_active:
                        self.start_mapping()
            else:
                QTimer.singleShot(500, self._connect_autostart)
        except AttributeError:
            QTimer.singleShot(500, self._connect_autostart)

    def _autostart_on_load(self, total_count: int = 0):
        """Slot called when monitor_thread finishes loading — start mapping."""
        if not self.mapping_active:
            self.start_mapping()

    def create_toolbar(self):
        """Create professional toolbar"""
        toolbar = QWidget()
        toolbar.setMaximumHeight(45)
        toolbar.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border-bottom: 1px solid {COLOR_BORDER};
            }}
        """)
        
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(10, 5, 10, 5)
        
        # Control buttons
        self.start_btn = QPushButton("▶ Start Mapping")
        self.start_btn.clicked.connect(self.start_mapping)
        self.start_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_SUCCESS};
                color: {COLOR_TEXT_BRIGHT};
                border: none;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #5dd9c0;
            }}
        """)
        layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.clicked.connect(self.stop_mapping)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CRITICAL};
                color: {COLOR_TEXT_BRIGHT};
                border: none;
                padding: 6px 16px;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background-color: #ff7b7b;
            }}
            QPushButton:disabled {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_MUTED};
            }}
        """)
        layout.addWidget(self.stop_btn)
        
        # Status indicator
        self.status_label = QLabel("🔴 Mapping Stopped")
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {COLOR_TEXT_MUTED};
                font-weight: bold;
                padding: 0 20px;
            }}
        """)
        layout.addWidget(self.status_label)
        
        # Scope Filter
        self.scope_filter_cb = QCheckBox("In Scope Only")
        self.scope_filter_cb.setChecked(False)
        self.scope_filter_cb.toggled.connect(self.refresh_display)
        self.scope_filter_cb.setStyleSheet(f"""
            QCheckBox {{
                color: {COLOR_TEXT};
                font-weight: bold;
                padding: 0 10px;
            }}
        """)
        layout.addWidget(self.scope_filter_cb)
        
        layout.addStretch()
        
        # Action buttons
        btn_style = f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 6px 14px;
                border-radius: 4px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_ELEVATED_BG};
                border-color: {COLOR_ACCENT};
            }}
        """
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setStyleSheet(btn_style)
        refresh_btn.clicked.connect(self.refresh_display)
        layout.addWidget(refresh_btn)
        
        export_btn = QPushButton("📤 Export")
        export_btn.setStyleSheet(btn_style)
        export_btn.clicked.connect(self.export_surface)
        layout.addWidget(export_btn)
        
        advanced_btn = QPushButton("Advanced")
        advanced_btn.setStyleSheet(btn_style)
        advanced_btn.clicked.connect(self.show_advanced_menu)
        layout.addWidget(advanced_btn)
        
        return toolbar
    
    def create_left_panel(self):
        """Left panel: stats card on top, tabbed filter trees below"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        # ── Statistics card ───────────────────────────────────────────────
        self.stats_card = QLabel()
        self.stats_card.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.stats_card.setWordWrap(True)
        self.stats_card.setFixedHeight(170)
        self.stats_card.setStyleSheet(f"""
            QLabel {{
                background-color: {COLOR_CARD_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                padding: 12px;
                font-size: 12px;
            }}
        """)
        self.update_stats()
        layout.addWidget(self.stats_card)

        # ── Tabbed filter section ─────────────────────────────────────────
        self.filter_tabs = QTabWidget()
        self.filter_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
            }}
            QTabBar::tab {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                padding: 6px 14px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
                font-size: 12px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT_BRIGHT};
                font-weight: bold;
            }}
        """)

        tree_style = f"""
            QTreeWidget {{
                background-color: {COLOR_CARD_BG};
                border: none;
                padding: 4px;
            }}
            QTreeWidget::item {{
                padding: 5px 3px;
                border-radius: 3px;
            }}
            QTreeWidget::item:selected {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
            }}
            QTreeWidget::item:hover {{
                background-color: {COLOR_ELEVATED_BG};
            }}
        """

        # Tab 1 – Functions (category tree)
        self.category_tree = QTreeWidget()
        self.category_tree.setHeaderHidden(True)
        self.category_tree.setStyleSheet(tree_style)
        self.category_tree.itemClicked.connect(self.on_category_selected)
        self.category_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.category_tree.customContextMenuRequested.connect(self.show_category_context_menu)
        self.filter_tabs.addTab(self.category_tree, "Functions")

        # Tab 2 – Extensions tree
        self.ext_tree = QTreeWidget()
        self.ext_tree.setHeaderHidden(True)
        self.ext_tree.setStyleSheet(tree_style)
        self.ext_tree.itemClicked.connect(self.on_ext_tree_selected)
        self.filter_tabs.addTab(self.ext_tree, "Extensions")

        # ── Collapse / Expand buttons beside the tab bar ───────────────
        tree_btn_style = f"""
            QPushButton {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_MUTED};
                border: 1px solid {COLOR_BORDER};
                padding: 2px 8px;
                border-radius: 3px;
                font-size: 11px;
            }}
            QPushButton:hover {{
                background-color: {COLOR_HOVER};
                color: {COLOR_TEXT_BRIGHT};
                border-color: {COLOR_ACCENT};
            }}
        """

        collapse_btn = QPushButton("⊟ Collapse")
        collapse_btn.setStyleSheet(tree_btn_style)
        collapse_btn.setToolTip("Collapse all items in the active tree")
        collapse_btn.clicked.connect(self._collapse_active_tree)

        expand_btn = QPushButton("⊞ Expand")
        expand_btn.setStyleSheet(tree_btn_style)
        expand_btn.setToolTip("Expand all items in the active tree")
        expand_btn.clicked.connect(self._expand_active_tree)

        self.filter_tabs.setCornerWidget(
            self._make_tree_btn_widget(collapse_btn, expand_btn),
            Qt.TopRightCorner
        )

        layout.addWidget(self.filter_tabs)
        return panel

    def _make_tree_btn_widget(self, collapse_btn, expand_btn):
        """Small widget holding the two tree action buttons."""
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 4, 0)
        h.setSpacing(3)
        h.addWidget(collapse_btn)
        h.addWidget(expand_btn)
        return w

    def _active_tree(self):
        """Return the QTreeWidget that is currently visible."""
        idx = self.filter_tabs.currentIndex()
        if idx == 0:
            return self.category_tree
        elif idx == 1:
            return self.ext_tree
        return None

    def _collapse_active_tree(self):
        tree = self._active_tree()
        if tree:
            tree.collapseAll()

    def _expand_active_tree(self):
        tree = self._active_tree()
        if tree:
            tree.expandAll()
    
    def create_right_panel(self):
        """Right panel: search bar + shared results table + hints/analysis tabs"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(6)

        # ── Search / filter bar ───────────────────────────────────────────
        search_bar = QWidget()
        search_bar.setStyleSheet(f"""
            QWidget {{
                background-color: {COLOR_ELEVATED_BG};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
            }}
        """)
        search_bar.setMaximumHeight(38)
        sb_layout = QHBoxLayout(search_bar)
        sb_layout.setContentsMargins(8, 4, 8, 4)
        sb_layout.setSpacing(8)

        sb_layout.addWidget(QLabel("🔍"))
        self.results_search = QLineEdit()
        self.results_search.setPlaceholderText("Filter results by URL, method, status...")
        self.results_search.setStyleSheet(f"""
            QLineEdit {{
                background-color: transparent;
                color: {COLOR_TEXT};
                border: none;
            }}
        """)
        self.results_search.textChanged.connect(self._refilter_results_table)
        sb_layout.addWidget(self.results_search)

        self.results_count_label = QLabel("0 results")
        self.results_count_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px;")
        sb_layout.addWidget(self.results_count_label)

        copy_btn = QPushButton("📋 Copy URLs")
        copy_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                padding: 3px 10px;
                border-radius: 3px;
            }}
            QPushButton:hover {{ border-color: {COLOR_ACCENT}; }}
        """)
        copy_btn.clicked.connect(self._copy_results_urls)
        sb_layout.addWidget(copy_btn)

        layout.addWidget(search_bar)

        # ── Results splitter: table on top, detail tabs below ─────────────
        results_splitter = QSplitter(Qt.Vertical)

        # Shared URL results table
        self.urls_table = QTableWidget()
        self.urls_table.setColumnCount(5)
        self.urls_table.setHorizontalHeaderLabels(["Method", "Status", "URL", "Params", "Ext"])
        self.urls_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.urls_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.urls_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.urls_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.urls_table.customContextMenuRequested.connect(self.show_url_context_menu)
        self.urls_table.itemDoubleClicked.connect(self.on_url_double_clicked)
        self.urls_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLOR_BACKGROUND};
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                gridline-color: {COLOR_BORDER};
            }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                padding: 4px;
            }}
            QTableWidget::item {{ padding: 4px; }}
            QTableWidget::item:selected {{ background-color: {COLOR_ACCENT}; }}
        """)
        results_splitter.addWidget(self.urls_table)

        # Detail tabs (hints + analysis)
        self.detail_tabs = QTabWidget()
        self.detail_tabs.setStyleSheet(f"""
            QTabWidget::pane {{
                border: 1px solid {COLOR_BORDER};
                border-radius: 6px;
                background-color: {COLOR_CARD_BG};
            }}
            QTabBar::tab {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT};
                padding: 6px 14px;
                border: 1px solid {COLOR_BORDER};
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                margin-right: 2px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT_BRIGHT};
            }}
        """)

        self.hints_display = QTextEdit()
        self.hints_display.setReadOnly(True)
        self.hints_display.setStyleSheet(f"QTextEdit {{ background-color: {COLOR_BACKGROUND}; border: none; padding: 10px; font-size: 12px; }}")
        self.detail_tabs.addTab(self.hints_display, "Attack Hints")

        self.analysis_display = QTextEdit()
        self.analysis_display.setReadOnly(True)
        self.analysis_display.setStyleSheet(f"QTextEdit {{ background-color: {COLOR_BACKGROUND}; border: none; padding: 10px; font-family: 'Consolas', monospace; font-size: 11px; }}")
        self.detail_tabs.addTab(self.analysis_display, "📊 Analysis")

        results_splitter.addWidget(self.detail_tabs)
        results_splitter.setSizes([400, 200])

        layout.addWidget(results_splitter)

        # Store current url list for re-filtering
        self._current_urls = []

        return panel
    
    def start_mapping(self):
        """Start mapping"""
        self.mapping_active = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("🟢 Mapping Active")
        self.status_label.setStyleSheet(f"color: {COLOR_SUCCESS}; font-weight: bold; padding: 0 20px;")
        
        # Map existing URLs
        self.map_existing_urls()
        self.update_display()
    
    def stop_mapping(self):
        """Stop mapping"""
        self.mapping_active = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("🔴 Mapping Stopped")
        self.status_label.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: bold; padding: 0 20px;")
    
    def map_existing_urls(self):
        """Map all existing URLs"""
        if not hasattr(self.parent_gui, 'findings'):
            return
        
        self.subdomain_map.clear()
        self.extension_map.clear()
        self.seen_urls.clear()
        
        for finding in self.parent_gui.findings:
            self.process_url(finding)
    
    def _extract_request_params(self, finding: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract parameters from URL and Body"""
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        request_file = finding.get("request_file", "")
        
        params = {}
        
        # 1. URL Parameters
        try:
            parsed = urlparse(url)
            params.update(parse_qs(parsed.query))
        except:
            pass
            
        # 2. Body Parameters (if POST/PUT/PATCH)
        if method in ["POST", "PUT", "PATCH"] and request_file and os.path.exists(request_file):
            try:
                with open(request_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    
                # Split headers and body
                parts = []
                if "\n\n" in content:
                    parts = content.split("\n\n", 1)
                elif "\r\n\r\n" in content:
                    parts = content.split("\r\n\r\n", 1)

                if len(parts) > 1:
                    body = parts[1]
                    # Try JSON
                    if body.strip().startswith("{"):
                        try:
                            json_data = json.loads(body)
                            # Flatten simple JSON
                            for k, v in json_data.items():
                                if isinstance(v, (str, int, float, bool)):
                                    params[k] = [str(v)]
                                elif isinstance(v, list):
                                    params[k] = [str(i) for i in v]
                                elif isinstance(v, dict):
                                    params[k] = ["{object}"]
                        except:
                            pass
                    # Try Form Data
                    elif "=" in body:
                        try:
                            body_params = parse_qs(body)
                            params.update(body_params)
                        except:
                            pass
            except Exception:
                pass
                
        return params

    def process_url(self, finding: Dict[str, Any]):
        """Process and categorize a single URL"""
        url = finding.get("url", "")
        method = finding.get("method", "GET")
        status = finding.get("status", 0)
        
        if not url:
            return
        
        # Scope Filter
        if hasattr(self, 'scope_filter_cb') and self.scope_filter_cb.isChecked():
            if hasattr(self.parent_gui, '_is_in_scope') and not self.parent_gui._is_in_scope(url):
                return
        
        # Extract all parameters (URL + Body)
        all_params = self._extract_request_params(finding)
        
        # Check for duplicates (same URL base + same method + same param keys)
        try:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            param_keys = tuple(sorted(all_params.keys()))
            identifier = (method, base_url, param_keys)
        except:
            identifier = (method, url, tuple())

        if identifier in self.seen_urls:
            return
        self.seen_urls.add(identifier)
        
        # Extract host
        try:
            parsed = urlparse(url)
            host = parsed.netloc.split(':')[0]
            if not host:
                host = "Unknown"
        except:
            host = "Unknown"

        # Analyze URL
        analysis = URLAnalyzer.analyze(url, method, status, all_params)
        
        # ── Categorize ────────────────────────────────────────────────
        # Check for a persisted user override first, then fall back to
        # the priority-based smart categorizer (path- and query-aware).
        _project_dir = ""
        try:
            pp = self.parent_gui._project_paths
            if pp and pp.get("project_dir"):
                _project_dir = pp["project_dir"]
        except Exception:
            pass

        target_category = ""
        matched_def     = None
        if _project_dir:
            _overrides = CategoryOverrideManager.load_overrides(_project_dir)
            if url in _overrides:
                target_category = _overrides[url]
                matched_def = CategoryOverrideManager.get_category_def(_project_dir, target_category)

        if not target_category:
            target_category, matched_def = CategoryDefinitions.smart_categorize(url, method)

        # Prepare data object
        url_data = {
            "url":     url,
            "method":  method,
            "status":  status,
            "risk":    matched_def.get("risk", "INFO") if matched_def else "INFO",
            "icon":    matched_def.get("icon", "📋") if matched_def else "📋",
            "hints":   matched_def.get("hints", ["Review manually"]) if matched_def else ["Review manually"],
            "analysis": analysis,
            "finding":  finding,
        }

        # Store in subdomain map
        self.subdomain_map[host][target_category].append(url_data)

        # Store in extension map if URL has a known extension
        if analysis.get("has_extension") and analysis.get("extension"):
            ext = analysis["extension"].lower()
            group_name, group_info = ExtensionDefinitions.get_group(ext)
            if group_name:
                ext_url_data = dict(url_data)
                ext_url_data["extension"] = ext
                ext_url_data["ext_group"] = group_name
                ext_url_data["risk"] = group_info["risk"]
                ext_url_data["icon"] = group_info["icon"]
                ext_url_data["hints"] = group_info["hints"]
                self.extension_map[host][group_name].append(ext_url_data)
    
    def set_project_dir(self, project_dir: str):
        """Propagate project directory change to the Findings sub-tab."""
        if hasattr(self, 'recorded_tab') and self.recorded_tab is not None:
            self.recorded_tab.set_project_dir(project_dir)

    def map_new_url(self, finding: Dict[str, Any]):
        """Map new URL in real-time — display updates are throttled."""
        if not self.mapping_active:
            return
        self.process_url(finding)
        # Throttle display rebuilds: start/restart a 2-second coalescing timer
        # so rapid bursts of traffic don't call update_display() per-request.
        if not hasattr(self, '_map_display_timer'):
            from PyQt5.QtCore import QTimer
            self._map_display_timer = QTimer()
            self._map_display_timer.setSingleShot(True)
            self._map_display_timer.timeout.connect(self.update_display)
        self._map_display_timer.start(2000)
    
    def update_display(self):
        """Update all display elements"""
        self.update_stats()
        self.update_category_tree()
        self.update_extension_tree()
    
    def update_stats(self):
        """Update statistics display"""
        total_urls = 0
        total_categories = 0
        critical_count = 0
        high_count = 0
        medium_count = 0

        for host, categories in self.subdomain_map.items():
            total_categories += len(categories)
            for urls in categories.values():
                total_urls += len(urls)
                for u in urls:
                    if u["risk"] == "CRITICAL": critical_count += 1
                    elif u["risk"] == "HIGH": high_count += 1
                    elif u["risk"] == "MEDIUM": medium_count += 1

        ext_total = sum(len(v) for hg in self.extension_map.values() for v in hg.values())
        ext_critical = sum(
            len(v) for hg in self.extension_map.values()
            for g, v in hg.items()
            if ExtensionDefinitions.EXTENSION_GROUPS.get(g, {}).get("risk") == "CRITICAL"
        )

        stats_html = f"""
<div style='line-height: 1.6;'>
<h3 style='margin: 0 0 8px 0; color: {COLOR_TEXT_BRIGHT};'>📊 Statistics</h3>
<p style='margin: 3px 0 3px 10px;'>• Total URLs: <b>{total_urls}</b></p>
<p style='margin: 3px 0 3px 10px;'>• Categories: <b>{total_categories}</b></p>
<p style='margin: 3px 0 3px 10px;'>• 📎 Files w/ Extensions: <b>{ext_total}</b></p>
<p style='margin: 3px 0 3px 10px; color: {COLOR_CRITICAL};'>• ⚠️ Critical Ext Files: <b>{ext_critical}</b></p>
<p style='margin: 8px 0 4px 0;'><b>Risk Distribution:</b></p>
<p style='margin: 3px 0 3px 10px; color: {COLOR_CRITICAL};'>🔴 Critical: <b>{critical_count}</b></p>
<p style='margin: 3px 0 3px 10px; color: {COLOR_HIGH};'>🟠 High: <b>{high_count}</b></p>
<p style='margin: 3px 0 3px 10px; color: {COLOR_MEDIUM};'>🟡 Medium: <b>{medium_count}</b></p>
</div>
        """
        self.stats_card.setText(stats_html)
    
    def update_category_tree(self):
        """Update category tree"""
        self.category_tree.clear()
        
        # Sort hosts alphabetically
        sorted_hosts = sorted(self.subdomain_map.keys())
        
        for host in sorted_hosts:
            categories = self.subdomain_map[host]
            total_host_urls = sum(len(urls) for urls in categories.values())
            
            # Create Host Item (Top Level)
            host_item = QTreeWidgetItem([f"🌐 {host} ({total_host_urls})"])
            host_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            host_item.setForeground(0, QColor(COLOR_TEXT_BRIGHT))
            host_item.setData(0, Qt.UserRole, f"HOST:{host}")
            
            # Sort categories by risk
            risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            sorted_categories = sorted(
                categories.items(),
                key=lambda x: risk_order.get(x[1][0]["risk"] if x[1] else "INFO", 5)
            )
            
            for category, urls in sorted_categories:
                if not urls:
                    continue
                
                icon = urls[0]["icon"]
                risk = urls[0]["risk"]
                count = len(urls)
                
                item = QTreeWidgetItem([f"{icon} {category} ({count})"])
                
                # Set color by risk
                colors = {
                    "CRITICAL": COLOR_CRITICAL,
                    "HIGH": COLOR_HIGH,
                    "MEDIUM": COLOR_MEDIUM,
                    "LOW": COLOR_INFO,
                    "INFO": COLOR_TEXT_MUTED
                }
                item.setForeground(0, QColor(colors.get(risk, COLOR_TEXT)))
                
                if risk in ["CRITICAL", "HIGH"]:
                    font = item.font(0)
                    font.setBold(True)
                    item.setFont(0, font)
                
                item.setData(0, Qt.UserRole, f"CAT:{host}|{category}")
                host_item.addChild(item)
            
            self.category_tree.addTopLevelItem(host_item)
        
        self.category_tree.expandAll()
    
    def on_category_selected(self, item, column):
        """Handle category/host selection → populate shared results table"""
        data = item.data(0, Qt.UserRole)
        if not data:
            return

        urls = []
        category_name = ""
        hints_html = ""
        analysis_label = ""

        if data.startswith("HOST:"):
            host = data.split(":", 1)[1]
            category_name = f"All endpoints — {host}"
            for cat_urls in self.subdomain_map[host].values():
                urls.extend(cat_urls)
            hints_html = f"<h3>🌐 {host}</h3><p>Select a specific category to see attack hints.</p>"
            analysis_label = category_name

        elif data.startswith("CAT:"):
            host, category = data.split(":", 1)[1].split("|", 1)
            category_name = f"{category} — {host}"
            urls = list(self.subdomain_map[host][category])
            if urls:
                risk_color = {
                    "CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                    "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_INFO
                }.get(urls[0]["risk"], COLOR_TEXT)
                hints_html  = f"<h3>💡 {category}</h3>"
                hints_html += f"<p><b>Risk:</b> <span style='color:{risk_color};'>{urls[0]['risk']}</span></p><br>"
                hints_html += "<p><b>Recommended Tests:</b></p><ul>"
                for hint in urls[0]["hints"]:
                    hints_html += f"<li style='margin:5px 0;'>{hint}</li>"
                hints_html += "</ul>"
            analysis_label = category_name

        self._show_results(urls, analysis_label, hints_html)
    
    def update_extension_tree(self):
        """Rebuild the Extensions filter tree"""
        self.ext_tree.clear()
        risk_order  = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        risk_colors = {"CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                       "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_INFO, "INFO": COLOR_TEXT_MUTED}

        for host in sorted(self.extension_map.keys()):
            groups = self.extension_map[host]
            total  = sum(len(v) for v in groups.values())

            host_item = QTreeWidgetItem([f"🌐 {host} ({total})"])
            host_item.setFont(0, QFont("Segoe UI", 10, QFont.Bold))
            host_item.setForeground(0, QColor(COLOR_TEXT_BRIGHT))
            host_item.setData(0, Qt.UserRole, f"EXTHOST:{host}")

            sorted_groups = sorted(
                groups.items(),
                key=lambda x: risk_order.get(
                    ExtensionDefinitions.EXTENSION_GROUPS.get(x[0], {}).get("risk", "INFO"), 5)
            )

            for group_name, urls in sorted_groups:
                if not urls:
                    continue
                ginfo = ExtensionDefinitions.EXTENSION_GROUPS.get(group_name, {})
                icon  = ginfo.get("icon", "📎")
                risk  = ginfo.get("risk", "INFO")

                grp_item = QTreeWidgetItem([f"{icon} {group_name} ({len(urls)})"])
                grp_item.setForeground(0, QColor(risk_colors.get(risk, COLOR_TEXT)))
                if risk in ("CRITICAL", "HIGH"):
                    f = grp_item.font(0); f.setBold(True); grp_item.setFont(0, f)
                grp_item.setData(0, Qt.UserRole, f"EXTCAT:{host}|{group_name}")

                # Sub-items per unique extension
                ext_buckets = defaultdict(list)
                for u in urls:
                    ext_buckets[u.get("extension", "?")].append(u)
                for ext, ext_urls in sorted(ext_buckets.items()):
                    sub = QTreeWidgetItem([f"    .{ext}  ({len(ext_urls)})"])
                    sub.setForeground(0, QColor(COLOR_TEXT_MUTED))
                    sub.setData(0, Qt.UserRole, f"EXT:{host}|{group_name}|{ext}")
                    grp_item.addChild(sub)

                host_item.addChild(grp_item)
            self.ext_tree.addTopLevelItem(host_item)

        self.ext_tree.expandAll()

    def on_ext_tree_selected(self, item, column):
        """Handle extension tree selection → populate shared results table"""
        data = item.data(0, Qt.UserRole)
        if not data:
            return

        urls = []
        label = ""
        hints_html = ""

        if data.startswith("EXTHOST:"):
            host  = data.split(":", 1)[1]
            for gv in self.extension_map[host].values():
                urls.extend(gv)
            label = f"All extension files — {host}"
            hints_html = f"<h3>🌐 {host}</h3><p>Select an extension group to see testing hints.</p>"

        elif data.startswith("EXTCAT:"):
            host, group_name = data.split(":", 1)[1].split("|", 1)
            urls  = list(self.extension_map[host][group_name])
            label = f"{group_name} — {host}"
            ginfo = ExtensionDefinitions.EXTENSION_GROUPS.get(group_name, {})
            risk  = ginfo.get("risk", "INFO")
            rc    = {"CRITICAL": COLOR_CRITICAL, "HIGH": COLOR_HIGH,
                     "MEDIUM": COLOR_MEDIUM, "LOW": COLOR_INFO}.get(risk, COLOR_TEXT)
            hints_html  = f"<h3>{ginfo.get('icon','')} {group_name}</h3>"
            hints_html += f"<p><b>Risk:</b> <span style='color:{rc};'>{risk}</span></p><br>"
            hints_html += "<p><b>Testing Hints:</b></p><ul>"
            for h in ginfo.get("hints", []):
                hints_html += f"<li style='margin:5px 0;'>{h}</li>"
            hints_html += "</ul>"

        elif data.startswith("EXT:"):
            host, group_name, ext = data.split(":", 1)[1].split("|", 2)
            urls  = [u for u in self.extension_map[host][group_name] if u.get("extension") == ext]
            label = f".{ext} files — {host}"
            ginfo = ExtensionDefinitions.EXTENSION_GROUPS.get(group_name, {})
            hints_html  = f"<h3>.{ext} files</h3><p>Group: {group_name}</p><br>"
            hints_html += "<ul>"
            for h in ginfo.get("hints", []):
                hints_html += f"<li style='margin:5px 0;'>{h}</li>"
            hints_html += "</ul>"

        self._show_results(urls, label, hints_html)

    # ── Shared results helpers ─────────────────────────────────────────────

    def _show_results(self, urls: list, label: str, hints_html: str):
        """Store url list and render into shared table + hints/analysis"""
        self._current_urls = urls
        self._current_label = label
        self._current_hints_html = hints_html
        self.results_search.clear()
        self._populate_results_table(urls)
        self.hints_display.setHtml(hints_html)
        self._update_analysis(urls, label)

    def _populate_results_table(self, urls: list):
        """Fill the shared results table"""
        search = self.results_search.text().lower()
        filtered = [
            u for u in urls
            if not search or search in u["url"].lower()
            or search in u["method"].lower()
            or search in str(u["status"])
            or search in u.get("extension", "").lower()
        ]

        self.urls_table.setRowCount(0)
        self.urls_table.setRowCount(len(filtered))

        for i, url_data in enumerate(filtered):
            # Method
            m = QTableWidgetItem(url_data["method"])
            m.setTextAlignment(Qt.AlignCenter)
            self.urls_table.setItem(i, 0, m)

            # Status
            status = url_data["status"]
            s = QTableWidgetItem(str(status))
            s.setTextAlignment(Qt.AlignCenter)
            if   200 <= status < 300: s.setForeground(QColor(COLOR_SUCCESS))
            elif 300 <= status < 400: s.setForeground(QColor(COLOR_MEDIUM))
            elif 400 <= status < 500: s.setForeground(QColor(COLOR_HIGH))
            elif status >= 500:       s.setForeground(QColor(COLOR_CRITICAL))
            self.urls_table.setItem(i, 1, s)

            # URL
            u_item = QTableWidgetItem(url_data["url"])
            u_item.setData(Qt.UserRole, url_data)
            self.urls_table.setItem(i, 2, u_item)

            # Params
            pc = url_data["analysis"]["param_count"]
            self.urls_table.setItem(i, 3, QTableWidgetItem(f"{pc}" if pc else ""))

            # Extension
            ext = url_data.get("extension", "")
            e_item = QTableWidgetItem(f".{ext}" if ext else "")
            e_item.setTextAlignment(Qt.AlignCenter)
            if ext:
                e_item.setForeground(QColor(COLOR_ACCENT))
            self.urls_table.setItem(i, 4, e_item)

        self.urls_table.resizeColumnsToContents()
        self.urls_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.results_count_label.setText(f"{len(filtered)} result{'s' if len(filtered) != 1 else ''}")

    def _refilter_results_table(self):
        """Re-filter whenever search text changes"""
        if hasattr(self, "_current_urls"):
            self._populate_results_table(self._current_urls)

    def _copy_results_urls(self):
        """Copy all visible URLs to clipboard"""
        urls = []
        for row in range(self.urls_table.rowCount()):
            item = self.urls_table.item(row, 2)
            if item:
                urls.append(item.text())
        if urls:
            QApplication.clipboard().setText("\n".join(urls))
            self.results_count_label.setText(f"✅ Copied {len(urls)} URLs")
            QTimer.singleShot(2000, lambda: self._refilter_results_table())

    def _update_analysis(self, urls: list, label: str):
        """Update the Analysis tab text"""
        text  = f"ANALYSIS: {label}\n"
        text += "=" * 70 + "\n\n"
        text += f"Total Endpoints: {len(urls)}\n"

        methods = defaultdict(int)
        statuses = defaultdict(int)
        exts = defaultdict(int)
        for u in urls:
            methods[u["method"]] += 1
            statuses[str(u["status"])] += 1
            ext = u.get("extension")
            if ext:
                exts[ext] += 1

        text += "\nHTTP Methods:\n"
        for m, c in sorted(methods.items(), key=lambda x: x[1], reverse=True):
            text += f"  {m}: {c}\n"

        text += "\nStatus Codes:\n"
        for st, c in sorted(statuses.items(), key=lambda x: x[1], reverse=True):
            text += f"  {st}: {c}\n"

        if exts:
            text += "\nExtensions Found:\n"
            for ext, c in sorted(exts.items(), key=lambda x: x[1], reverse=True):
                text += f"  .{ext}: {c}\n"

        text += "\n" + "=" * 70 + "\n"
        text += "Sample URLs (first 20):\n\n"
        for i, u in enumerate(urls[:20], 1):
            text += f"{i}. {u['method']} {u['url']}\n"
            text += f"   Status: {u['status']}"
            if u["analysis"]["param_names"]:
                text += f"  Params: {', '.join(u['analysis']['param_names'])}"
            if u.get("extension"):
                text += f"  Ext: .{u['extension']}"
            text += "\n\n"

        self.analysis_display.setPlainText(text)

    def show_category_context_menu(self, position):
        """Show context menu for category"""
        item = self.category_tree.itemAt(position)
        if not item:
            return
        
        menu = QMenu()
        
        export_action = QAction("📤 Export Category", self)
        export_action.triggered.connect(lambda: self.export_category(item))
        menu.addAction(export_action)
        
        copy_action = QAction("📋 Copy URLs", self)
        copy_action.triggered.connect(lambda: self.copy_category_urls(item))
        menu.addAction(copy_action)
        
        menu.exec_(self.category_tree.viewport().mapToGlobal(position))
    
    def export_category(self, item):
        """Export specific category"""
        data = item.data(0, Qt.UserRole)
        if not data or not data.startswith("CAT:"):
            return
        
        host, category = data.split(":", 1)[1].split("|", 1)
        filename, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {category} ({host})",
            f"{host}_{category.replace(' ', '_').lower()}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            data = {
                "category": category,
                "host": host,
                "exported": datetime.now().isoformat(),
                "count": len(self.subdomain_map[host][category]),
                "urls": [
                    {
                        "url": u["url"],
                        "method": u["method"],
                        "status": u["status"],
                        "risk": u["risk"]
                    }
                    for u in self.subdomain_map[host][category]
                ]
            }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            QMessageBox.information(self, "Export Complete", f"Exported to {filename}")
    
    def copy_category_urls(self, item):
        """Copy URLs to clipboard"""
        data = item.data(0, Qt.UserRole)
        if not data or not data.startswith("CAT:"):
            return
        
        host, category = data.split(":", 1)[1].split("|", 1)
        urls = '\n'.join(u['url'] for u in self.subdomain_map[host][category])
        QApplication.clipboard().setText(urls)
        
        QMessageBox.information(self, "Copied", f"Copied {len(self.subdomain_map[host][category])} URLs")
    
    def refresh_display(self):
        """Refresh the display"""
        self.map_existing_urls()
        self.update_display()
    
    def export_surface(self):
        """Export entire mapping data"""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Export Mapping",
            f"mapping_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            data = {
                "exported": datetime.now().isoformat(),
                "total_urls": sum(len(urls) for cats in self.subdomain_map.values() for urls in cats.values()),
                "hosts": {}
            }
            
            for host, categories in self.subdomain_map.items():
                data["hosts"][host] = {
                    cat: {
                        "risk": urls[0]["risk"],
                        "count": len(urls),
                        "urls": [{"url": u["url"], "method": u["method"], "status": u["status"]} for u in urls]
                    }
                    for cat, urls in categories.items() if urls
                }
            
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            
            QMessageBox.information(self, "Export Complete", f"Exported to {filename}")
    
    def show_advanced_menu(self):
        """Show advanced features menu"""
        menu = QMenu(self)
        
        # Add advanced features here
        info_action = QAction("ℹ️ Advanced features coming soon", self)
        info_action.setEnabled(False)
        menu.addAction(info_action)
        
        menu.exec_(QCursor.pos())

    def show_url_context_menu(self, position):
        """Show context menu for URL table"""
        item = self.urls_table.itemAt(position)
        if not item:
            return
            
        row = item.row()
        url_item = self.urls_table.item(row, 2)
        if not url_item:
            return
            
        url_data = url_item.data(Qt.UserRole)
        if not url_data:
            return
            
        menu = QMenu()
        
        copy_url = menu.addAction("📋 Copy URL")
        copy_url.triggered.connect(lambda: QApplication.clipboard().setText(url_data['url']))
        
        menu.addSeparator()
        
        view_history = menu.addAction("📜 View in HTTP History")
        view_history.triggered.connect(lambda: self.view_in_http_history(url_data))
        
        send_surface = menu.addAction("🎯 Send to Attack Surface")
        send_surface.triggered.connect(lambda: self._send_to_attack_surface(url_data))
        
        menu.exec_(self.urls_table.viewport().mapToGlobal(position))

    def on_url_double_clicked(self, item):
        """Handle double click on URL table"""
        row = item.row()
        url_item = self.urls_table.item(row, 2)
        if url_item:
            url_data = url_item.data(Qt.UserRole)
            if url_data:
                self.show_url_details_dialog(url_data)

    def show_url_details_dialog(self, url_data):
        """Show detailed popup for selected URL"""
        dialog = QDialog(self)
        dialog.setWindowTitle(f"🔬 URL Details")
        dialog.setMinimumSize(900, 700)
        
        layout = QVBoxLayout(dialog)
        
        # Header
        header_html = f"""
<div style='background-color: {COLOR_CARD_BG}; padding: 15px; border-radius: 6px; border-left: 4px solid {COLOR_ACCENT};'>
<h3 style='margin: 0; color: {COLOR_TEXT_BRIGHT};'>{url_data.get('method', 'GET')} {url_data['url']}</h3>
<p style='margin: 5px 0 0 0;'>Risk: <span style='color: {COLOR_CRITICAL if url_data["risk"] == "CRITICAL" else COLOR_HIGH};'><b>{url_data['risk']}</b></span> | Status: <b>{url_data['status']}</b></p>
</div>
        """
        header_label = QLabel(header_html)
        header_label.setWordWrap(True)
        layout.addWidget(header_label)
        
        # Create Tabs
        tabs = QTabWidget()
        tabs.setStyleSheet(f"""
            QTabWidget::pane {{ border: 1px solid {COLOR_BORDER}; background-color: {COLOR_BACKGROUND}; }}
            QTabBar::tab {{ background: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; padding: 8px 12px; border: 1px solid {COLOR_BORDER}; margin-right: 2px; }}
            QTabBar::tab:selected {{ background: {COLOR_ACCENT}; color: white; }}
        """)
        
        # Tab 1: Analysis / Details
        info_text = QTextEdit()
        info_text.setReadOnly(True)
        info_text.setStyleSheet(f"background-color: {COLOR_BACKGROUND}; border: none; padding: 10px; color: {COLOR_TEXT};")
        
        info_content = f"""
ENDPOINT DETAILS
{'=' * 80}

URL: {url_data['url']}
Method: {url_data['method']}
Status: {url_data['status']}
Risk Level: {url_data['risk']}

ANALYSIS:
- Parameters: {url_data['analysis']['param_count']}
"""
        if url_data['analysis']['param_names']:
            info_content += f"- Parameter Names: {', '.join(url_data['analysis']['param_names'])}\n"
        
        if url_data['analysis']['potential_injection_points']:
            info_content += f"\n⚠️ INJECTION POINTS: {', '.join(url_data['analysis']['potential_injection_points'])}\n"
        
        if url_data['analysis']['suspicious_params']:
            info_content += f"\n🚨 SUSPICIOUS PARAMS: {', '.join(url_data['analysis']['suspicious_params'])}\n"
        
        if url_data['analysis']['numeric_ids']:
            info_content += f"\n🎯 IDOR CANDIDATES: {', '.join(url_data['analysis']['numeric_ids'])}\n"
        
        info_content += f"\n\nTESTING HINTS:\n"
        for i, hint in enumerate(url_data['hints'], 1):
            info_content += f"{i}. {hint}\n"
        
        info_text.setPlainText(info_content)
        tabs.addTab(info_text, "📊 Analysis")

        # Tab 2: Request
        req_text = QTextEdit()
        req_text.setReadOnly(True)
        req_text.setFont(QFont("Consolas", 10))
        req_text.setStyleSheet(f"background-color: {COLOR_BACKGROUND}; border: none; padding: 10px; color: {COLOR_TEXT_BRIGHT};")
        
        # Load request content
        finding = url_data.get('finding', {})
        request_content = ""
        req_file = finding.get('request_file')
        if req_file and os.path.exists(req_file):
            try:
                with open(req_file, 'r', encoding='utf-8', errors='replace') as f:
                    request_content = f.read()
            except Exception as e:
                request_content = f"[Error reading request file: {e}]"
        else:
            request_content = "[Request file not found]"
            
        req_text.setPlainText(request_content)
        tabs.addTab(req_text, "📤 Request")

        # Tab 3: Response
        resp_text = QTextEdit()
        resp_text.setReadOnly(True)
        resp_text.setFont(QFont("Consolas", 10))
        resp_text.setStyleSheet(f"background-color: {COLOR_BACKGROUND}; border: none; padding: 10px; color: {COLOR_TEXT_BRIGHT};")
        
        # Load response content
        response_content = ""
        resp_file = finding.get('response_file')
        if resp_file and os.path.exists(resp_file):
            try:
                with open(resp_file, 'r', encoding='utf-8', errors='replace') as f:
                    response_content = f.read()
            except Exception as e:
                response_content = f"[Error reading response file: {e}]"
        else:
            response_content = "[Response file not found]"
            
        resp_text.setPlainText(response_content)
        tabs.addTab(resp_text, "📥 Response")

        layout.addWidget(tabs)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        http_history_btn = QPushButton("📜 View in HTTP History")
        http_history_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLOR_ACCENT};
                color: {COLOR_TEXT_BRIGHT};
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #1e7ac0; }}
        """)
        http_history_btn.clicked.connect(lambda: self.view_in_http_history(url_data, dialog))
        btn_layout.addWidget(http_history_btn)

        surface_btn = QPushButton("🎯 Send to Attack Surface")
        surface_btn.setStyleSheet(f"""
            QPushButton {{
                background-color: #5a3ea8;
                color: {COLOR_TEXT_BRIGHT};
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background-color: #7b5cc8; }}
        """)
        surface_btn.clicked.connect(lambda: self._send_to_attack_surface(url_data, dialog))
        btn_layout.addWidget(surface_btn)
        
        copy_btn = QPushButton("📋 Copy URL")
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(url_data['url']))
        btn_layout.addWidget(copy_btn)
        
        btn_layout.addStretch()
        
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        btn_layout.addWidget(close_btn)
        
        layout.addLayout(btn_layout)
        dialog.exec_()
    
    def view_in_http_history(self, url_data, dialog=None):
        """Switch to HTTP History tab and highlight the URL"""
        if dialog:
            dialog.accept()
        
        # Switch to HTTP History tab
        if hasattr(self.parent_gui, 'tab_widget'):
            for i in range(self.parent_gui.tab_widget.count()):
                tab_text = self.parent_gui.tab_widget.tabText(i)
                if 'HTTP' in tab_text or 'History' in tab_text:
                    self.parent_gui.tab_widget.setCurrentIndex(i)
                    
                    # Give UI time to switch tabs
                    QTimer.singleShot(100, lambda url_data=url_data: self.highlight_in_history(url_data))
                    break

    def highlight_in_history(self, url_data):
        """Highlight URL in HTTP History table with visual feedback"""
        # Find the HTTP history table
        table = None
        table_names = ['history_table', 'table', 'findings_table', 'http_table', 'httpHistoryTable']
        
        for attr in table_names:
            if hasattr(self.parent_gui, attr):
                table = getattr(self.parent_gui, attr)
                break
        
        if not table:
            QMessageBox.warning(self, "Not Found", "HTTP History table not found.")
            return
        
        # Try to find by Sequence Number (Exact Match)
        finding = url_data.get('finding')
        target_seq = str(finding.get('seq', '')) if finding else ''
        
        found_row = -1
        
        if target_seq:
            for row in range(table.rowCount()):
                seq_item = table.item(row, 0)
                if seq_item and seq_item.text() == target_seq:
                    found_row = row
                    break
        
        # Fallback: Search by URL and Method if sequence not found
        if found_row == -1:
            # Get the target URL and method
            target_url = url_data['url']
            target_method = url_data['method']
            
            # Try to find URL and method columns
            url_col = -1
            method_col = -1
            
            # Look for column headers that indicate URL and Method
            if hasattr(table, 'horizontalHeaderItem'):
                for col in range(table.columnCount()):
                    header = table.horizontalHeaderItem(col)
                    if header:
                        header_text = header.text().lower()
                        if 'url' in header_text:
                            url_col = col
                        elif 'method' in header_text:
                            method_col = col
            
            # If columns not found, try default positions
            if url_col == -1:
                # Common column orders: [ID, Method, URL, Status] or [Method, URL, Status]
                if table.columnCount() >= 2:
                    method_col = 0 if 'method' in table.horizontalHeaderItem(0).text().lower() else 1
                    url_col = 1 if method_col == 0 else 2 if table.columnCount() > 2 else 1
            
            # Search through all rows
            for row in range(table.rowCount()):
                url_match = False
                method_match = False
                
                # Check URL column
                if url_col >= 0 and url_col < table.columnCount():
                    url_item = table.item(row, url_col)
                    if url_item and self.normalize_url(url_item.text()) == self.normalize_url(target_url):
                        url_match = True
                
                # Check method column
                if method_col >= 0 and method_col < table.columnCount():
                    method_item = table.item(row, method_col)
                    if method_item and method_item.text().upper() == target_method.upper():
                        method_match = True
                
                # If both match, we found the exact request
                if url_match and method_match:
                    found_row = row
                    break
        
        if found_row >= 0:
            # Ensure row is visible (in case it was filtered out)
            if table.isRowHidden(found_row):
                table.setRowHidden(found_row, False)
                
            # Select and scroll to the row
            table.selectRow(found_row)
            table.scrollToItem(table.item(found_row, 0))
            
            # Flash the row for visual feedback
            self.flash_row_highlight(table, found_row)
        else:
            QMessageBox.information(
                self, 
                "Not Found", 
                f"Could not find this exact request in HTTP History."
            )

    def normalize_url(self, url):
        """Normalize URL for comparison (remove trailing slash, sort query params)"""
        try:
            parsed = urlparse(url)
            
            # Sort query parameters alphabetically
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                sorted_params = '&'.join(f'{k}={v[0]}' for k in sorted(params.keys()) 
                                    for v in params[k])
                new_query = f'?{sorted_params}' if sorted_params else ''
            else:
                new_query = ''
            
            # Remove trailing slash from path (unless it's just "/")
            path = parsed.path
            if path.endswith('/') and len(path) > 1:
                path = path.rstrip('/')
            
            # Reconstruct URL
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}{new_query}"
            return normalized
        except:
            return url.strip()
    
    def _send_to_attack_surface(self, url_data: dict, dialog=None):
        """Send a url_data entry to the Attack Surface tab."""
        if dialog:
            dialog.accept()
        mw = self.parent_gui
        as_tab = getattr(mw, 'attack_surface_tab', None)
        if as_tab is None:
            QMessageBox.warning(self, "Not Available", "Attack Surface tab not found.")
            return
        finding = url_data.get('finding') or {}
        if not finding:
            finding = {
                'url':    url_data.get('url', ''),
                'method': url_data.get('method', 'GET'),
                'status': url_data.get('status', ''),
            }
        as_tab.add_from_http_history(finding)
        if hasattr(mw, 'tab_widget'):
            for i in range(mw.tab_widget.count()):
                if "Attack Surface" in mw.tab_widget.tabText(i):
                    mw.tab_widget.setCurrentIndex(i)
                    break

    def flash_row_highlight(self, table, row):
        """Flash row with color to draw attention"""
        # Store original colors
        original_colors = []
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item:
                original_colors.append((col, item.background()))
        
        # Flash with accent color
        flash_color = QColor(COLOR_ACCENT)
        for col in range(table.columnCount()):
            item = table.item(row, col)
            if item:
                item.setBackground(flash_color)
        
        # Reset after delay
        def reset_colors():
            for col, color in original_colors:
                item = table.item(row, col)
                if item:
                    item.setBackground(color)
        
        QTimer.singleShot(1500, reset_colors)



# Compatibility alias
MappingTab = MappingTabPro
