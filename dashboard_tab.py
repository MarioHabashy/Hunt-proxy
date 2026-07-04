#!/usr/bin/env python3
"""
dashboard_tab.py - Task management dashboard for security tools

Features:
- Auto-populates subdomains from selected scope (program/domain/subdomain)
- Task execution with persistent output files named by task/target
- Tasks & outputs reload when same target is re-selected
- Inline output viewer below task list (no popup needed)
- Auto-detects cookies from successful login requests with prompt
- Auto-sets proxy to tool's running proxy
- Per-domain task history shown based on selected scope target
- Pretty formatted output for better readability
"""

import os
import json
import time
import re
import threading
import subprocess
import shlex
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import queue
from urllib.parse import urlparse

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
try:
    from PyQt5.QtSvg import QSvgRenderer as _QSvgRenderer
    _HAS_SVG = True
except ImportError:
    _HAS_SVG = False

try:
    from constants import (
        COLOR_BACKGROUND, COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED,
        COLOR_BORDER, COLOR_ACCENT, COLOR_SUCCESS, COLOR_CRITICAL,
        COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_DARK_BG, COLOR_ELEVATED_BG,
        COLOR_CARD_BG, COLOR_HOVER, COLOR_ACCENT_SECONDARY,
        FONT_FAMILY, FONT_FAMILY_MONO, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
        FONT_SIZE_LARGE
    )
except ImportError:
    COLOR_BACKGROUND = "#1E1E1E"
    COLOR_TEXT = "#CCCCCC"
    COLOR_TEXT_BRIGHT = "#FFFFFF"
    COLOR_TEXT_MUTED = "#888888"
    COLOR_BORDER = "#3C3F41"
    COLOR_ACCENT = "#66CC66"
    COLOR_SUCCESS = "#00E676"
    COLOR_CRITICAL = "#FF4444"
    COLOR_HIGH = "#FF8800"
    COLOR_MEDIUM = "#FFBB33"
    COLOR_LOW = "#00C851"
    COLOR_DARK_BG = "#252525"
    COLOR_ELEVATED_BG = "#2D2D2D"
    COLOR_CARD_BG = "#2A2A2A"
    COLOR_HOVER = "#3A3A3A"
    COLOR_ACCENT_SECONDARY = "#AA80FF"
    FONT_FAMILY = "Segoe UI, Arial, sans-serif"
    FONT_FAMILY_MONO = "Consolas, Monaco, monospace"
    FONT_SIZE_NORMAL = "10pt"
    FONT_SIZE_SMALL = "9pt"
    FONT_SIZE_LARGE = "12pt"

import logging
logger = logging.getLogger(__name__)


def _read_file(path: str) -> str:
    """Safely read a text file."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""


def _safe_urlparse_host(url: str) -> str:
    """Parse hostname from URL, returning empty string on any parse error (e.g. invalid IPv6)."""
    try:
        return urlparse(url).netloc.split(":")[0].lower().strip()
    except Exception:
        return ""



# ─────────────────────────────────────────────────────────────────────────────
# Cookie Validator
# ─────────────────────────────────────────────────────────────────────────────

def validate_cookie(cookie: str) -> str:
    """
    Sanitise and validate a cookie string before passing it to any tool.
    - Strips leading/trailing whitespace.
    - Removes embedded newlines (header-injection guard).
    - Warns (logs) if the string looks malformed.
    Returns the cleaned cookie string (may be empty if input was empty).
    """
    if not cookie:
        return ""
    # Strip outer whitespace and collapse any internal newlines/carriage-returns
    cleaned = cookie.strip().replace("\r", "").replace("\n", "")
    if cleaned != cookie.strip():
        logger.warning("Cookie contained newline characters — stripped before use.")
    # Basic sanity: a valid cookie should have at least one key=value pair
    if cleaned and "=" not in cleaned:
        logger.warning(f"Cookie string looks malformed (no '=' found): {cleaned[:80]}")
    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# Output Formatter - Pretty Print Results
# ─────────────────────────────────────────────────────────────────────────────

class OutputFormatter:
    """Format tool output for pretty display in the viewer."""
    
    @staticmethod
    def format_nmap_output(content: str) -> str:
        """Format nmap output with colors and sections."""
        lines = content.split('\n')
        formatted = []
        in_script_section = False
        
        for line in lines:
            # Port scanning results
            if re.match(r'^\d+/\w+\s+\w+\s+\w+', line):
                formatted.append(f"🔌 {line}")
            # Open ports
            elif 'open' in line.lower():
                formatted.append(f"✅ {line}")
            # Service versions
            elif re.search(r'\d+\.\d+\.\d+', line):
                formatted.append(f"📦 {line}")
            # Vulnerabilities
            elif 'vuln' in line.lower() or 'cve-' in line.lower():
                formatted.append(f"⚠️  {line}")
            # Script output
            elif line.startswith('|'):
                if not in_script_section:
                    formatted.append("📋 Script Output:")
                    in_script_section = True
                formatted.append(f"  {line}")
            else:
                formatted.append(line)
                in_script_section = False
        
        return '\n'.join(formatted)

    @staticmethod
    def format_feroxbuster_output(content: str) -> str:
        """Format feroxbuster output with pretty directory listing."""
        lines = content.split('\n')
        formatted = []
        
        for line in lines:
            # Match feroxbuster output format: STATUS SIZE URL
            match = re.match(r'^(\d{3})\s+(\S+)\s+(https?://\S+)', line)
            if match:
                status, size, url = match.groups()
                status_color = {
                    '200': '✅',
                    '301': '↪️',
                    '302': '↪️',
                    '403': '🔒',
                    '404': '❌',
                    '500': '💥'
                }.get(status, '📄')
                
                formatted.append(f"{status_color} [{status}] {size:<8} {url}")
            else:
                formatted.append(line)
        
        return '\n'.join(formatted)

    @staticmethod
    def format_nuclei_output(content: str) -> str:
        """Format nuclei findings with severity indicators."""
        lines = content.split('\n')
        formatted = []
        
        severity_icons = {
            'critical': '🔥',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️',
            'info': '📌'
        }
        
        for line in lines:
            # Match nuclei output format: [critical] [CVE-2023-1234] url
            severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line.lower())
            if severity_match:
                severity = severity_match.group(1).lower()
                icon = severity_icons.get(severity, '🔍')
                formatted.append(f"{icon} {line}")
            else:
                formatted.append(line)
        
        return '\n'.join(formatted)

    @staticmethod
    def format_subdomain_output(content: str) -> str:
        """Format subdomain enumeration results."""
        lines = content.split('\n')
        formatted = []
        
        for i, line in enumerate(lines, 1):
            if line.strip():
                formatted.append(f"🌐 [{i:4d}] {line}")
        
        return '\n'.join(formatted)

    @staticmethod
    def format_wayback_output(content: str) -> str:
        """Format wayback/gau results with URL categorization."""
        lines = content.split('\n')
        formatted = []
        
        categories = {
            'js': '📜 JavaScript',
            'css': '🎨 CSS',
            'jpg|jpeg|png|gif|svg': '🖼️ Images',
            'php': '🐘 PHP',
            'asp|aspx': '🔷 ASP.NET',
            'json': '📦 JSON',
            'xml': '📄 XML',
            'pdf': '📑 PDF',
            'zip|tar|gz': '🗜️ Archives'
        }
        
        for line in lines:
            if not line.strip():
                continue
                
            # Categorize URLs
            categorized = False
            for pattern, category in categories.items():
                if re.search(pattern, line, re.I):
                    formatted.append(f"{category}: {line}")
                    categorized = True
                    break
            
            if not categorized:
                formatted.append(f"📎 {line}")
        
        return '\n'.join(formatted)

    @staticmethod
    def format_general_output(content: str, tool: str) -> str:
        """Apply appropriate formatter based on tool type."""
        if 'nmap' in tool.lower():
            return OutputFormatter.format_nmap_output(content)
        elif 'bruteforce' in tool.lower() or 'feroxbuster' in tool.lower():
            return OutputFormatter.format_feroxbuster_output(content)
        elif 'nuclei' in tool.lower():
            return OutputFormatter.format_nuclei_output(content)
        elif 'subdomain' in tool.lower():
            return OutputFormatter.format_subdomain_output(content)
        elif 'archive' in tool.lower() or 'wayback' in tool.lower():
            return OutputFormatter.format_wayback_output(content)
        else:
            return content


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _safe_slug(text: str) -> str:
    """Convert text to filesystem-safe slug."""
    return re.sub(r"[^a-z0-9_\-]", "_", text.lower().strip()).strip("_") or "task"

def check_tool_available(tool_name: str) -> bool:
    """Check if a required tool is available in PATH."""
    try:
        subprocess.run([tool_name, "--version"], 
                      capture_output=True, 
                      timeout=5,
                      check=False)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

TOOL_INSTALL_GUIDES = {
    "katana":      "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "httpx":       "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "gau":         "go install github.com/lc/gau/v2/cmd/gau@latest",
    "gauplus":     "go install github.com/bp0lr/gauplus@latest",
    "waymore":     "pip install waymore",
    "uro":         "pip install uro",
    "hakrawler":   "go install github.com/hakluke/hakrawler@latest",
    "feroxbuster": "sudo apt install feroxbuster",
    "nuclei":      "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "nmap":        "sudo apt install nmap",
    "wafw00f":     "pip install wafw00f",
    "cmseek":      "git clone https://github.com/Tuhinshubhra/CMSeeK",
    "nikto":       "sudo apt install nikto",
    # Spider enhancement tools
    "gospider":    "go install github.com/jaeles-project/gospider@latest",
    "cariddi":     "go install github.com/edoardottt/cariddi/cmd/cariddi@latest",
    "linkfinder":  "git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder && pip3 install -r ~/tools/LinkFinder/requirements.txt",
    "paramspider": "pip3 install paramspider",
    "roboxtractor": "go install github.com/Josue87/roboxtractor@latest",
}


# ─────────────────────────────────────────────────────────────────────────────
# Cookie Detection Thread
# ─────────────────────────────────────────────────────────────────────────────

class CookieDetectorThread(QThread):
    """
    Scans HTTP history for session cookies set after a successful login.
    """
    cookie_found = pyqtSignal(str, str)   # cookie_value, source_url

    LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "session",
                      "token", "oauth", "sso", "account/enter", "api/v", "user/login")

    def __init__(self, findings, scope_hosts=None, parent=None):
        super().__init__(parent)
        self.findings    = list(findings)   # snapshot so we don't race the main thread
        self.scope_hosts = set(scope_hosts or [])
        # For Pass 1 (login POST Set-Cookie), also include parent domains.
        # e.g. a login to example.com sets a cookie that propagates to api.example.com
        self._broad_scope = self._add_parent_domains(self.scope_hosts)

    @staticmethod
    def _add_parent_domains(hosts: set) -> set:
        """Return hosts extended with their parent domains (last two labels)."""
        result = set(hosts)
        for host in hosts:
            parts = host.split(".")
            if len(parts) > 2:
                result.add(".".join(parts[-2:]))
        return result

    def run(self):
        # ── Pass 1: Set-Cookie from successful login POSTs ────────────────
        # Use broad scope (includes parent domains) so cookies set on example.com
        # are detected even when a subdomain like api.example.com is selected.
        for finding in reversed(self.findings):
            method = finding.get("method", "").upper()
            status = finding.get("status", finding.get("status_code", 0))
            url    = finding.get("url", "")

            if method != "POST":
                continue
            if status not in (200, 201, 302, 303):
                continue
            if not any(kw in url.lower() for kw in self.LOGIN_KEYWORDS):
                continue

            if self._broad_scope:
                host = _safe_urlparse_host(url)
                if host not in self._broad_scope:
                    continue

            # Collect cookies from both request (existing) and response (new/updated)
            resp_cookie_str = self._read_set_cookie(finding)
            req_cookie_str = self._read_request_cookie(finding)
            
            # Merge: response overrides request
            cookie_map = {}
            
            # 1. Add request cookies (only split by semicolon, preserve commas in values)
            if req_cookie_str:
                parts = req_cookie_str.split(';')
                for part in parts:
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookie_map[k.strip()] = v.strip()
            
            # 2. Update with response cookies (Set-Cookie overrides)
            if resp_cookie_str:
                # Set-Cookie headers are typically separate lines, joined by "; " in helper
                parts = resp_cookie_str.split(';')
                for part in parts:
                    part = part.strip()
                    if "=" in part:
                        k, v = part.split("=", 1)
                        cookie_map[k.strip()] = v.strip()
            
            if cookie_map:
                final_cookie = "; ".join(f"{k}={v}" for k, v in cookie_map.items())
                self.cookie_found.emit(final_cookie, url)
                return

        # ── Pass 2: Fallback — Cookie header from any in-scope request ────
        for finding in reversed(self.findings):
            url = finding.get("url", "")
            if self.scope_hosts:
                host = _safe_urlparse_host(url)
                if host not in self.scope_hosts:
                    continue

            cookie = self._read_request_cookie(finding)
            if cookie:
                # Normalize to semicolon separated
                parts = cookie.split(';')
                norm_parts = []
                for part in parts:
                    part = part.strip()
                    if "=" in part:
                        norm_parts.append(part)
                if norm_parts:
                    self.cookie_found.emit("; ".join(norm_parts), url)
                    return

    # ── helpers ───────────────────────────────────────────────────────────

    def _read_set_cookie(self, finding: dict) -> str:
        """Read Set-Cookie header value from the response file."""
        resp_file = finding.get("response_file", "")
        if not resp_file or not os.path.exists(resp_file):
            return ""
        try:
            cookies = []
            with open(resp_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\r\n")
                    if not line:
                        break   # end of headers
                    if line.lower().startswith("set-cookie:"):
                        val = line.split(":", 1)[1].strip()
                        # Take only the name=value part (before first semicolon)
                        # Preserve the entire value even if it contains commas
                        name_val = val.split(';')[0].strip()
                        if name_val:
                            cookies.append(name_val)
            return "; ".join(cookies) if cookies else ""
        except Exception:
            return ""

    def _read_request_cookie(self, finding: dict) -> str:
        """Read Cookie header value from the request file."""
        req_file = finding.get("request_file", "")
        if not req_file or not os.path.exists(req_file):
            return ""
        cookies = []
        try:
            with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.rstrip("\r\n")
                    if not line:
                        break
                    if line.lower().startswith("cookie:"):
                        val = line.split(":", 1)[1].strip()
                        if val:
                            # Fix: Only split by semicolon, preserve commas in values
                            # Cookie headers should use semicolon as separator
                            parts = val.split(';')
                            for part in parts:
                                part = part.strip()
                                if part and '=' in part:
                                    cookies.append(part)
        except Exception:
            pass
        return "; ".join(cookies)


# ─────────────────────────────────────────────────────────────────────────────
# Pure Runner Classes  (no Qt, no threads — fully unit-testable)
#
# Each runner owns exactly two responsibilities for its tool:
#   1. build_command()  → returns the argv list, no side-effects
#   2. parse_output()   → transforms raw text to pretty text, no side-effects
#
# TaskWorker is reduced to a thin Qt wrapper that calls these, fires signals,
# and manages subprocesses. Nothing domain-specific lives in TaskWorker anymore.
# ─────────────────────────────────────────────────────────────────────────────

class IpinfoRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["ipinfo", domain]

    def parse_output(self, content: str) -> str:
        return content  # ipinfo output is already readable


class HeadersRunner:
    def build_command(self, domain: str, cookie: str = "", proxy: str = "",
                       extra_headers: list = None) -> List[str]:
        cmd = ["curl", "-I", f"https://{domain}", "-s", "-k", "--max-time", "30"]
        if cookie:
            cmd.extend(["--cookie", cookie])
        if extra_headers:
            cmd.extend(extra_headers)
        if proxy:
            cmd.extend(["--proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        return content  # raw HTTP headers are readable as-is


class TechRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["wad", "-u", f"https://{domain}", "-f", "txt"]

    def parse_output(self, content: str) -> str:
        return content


class WafRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["wafw00f", domain]

    def parse_output(self, content: str) -> str:
        return content


class CmsRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["cmseek", "-u", domain, "--batch", "-r"]

    def parse_output(self, content: str) -> str:
        return content


class NmapRunner:
    def build_command(self, domain: str, output_file: str) -> List[str]:
        return [
            "nmap", "-sV", "-sC", "--top-ports", "1000",
            "-T4", "--open", "-oN", output_file, domain
        ]

    def parse_output(self, content: str) -> str:
        formatted = "🔍 NMAP SCAN RESULTS\n" + "═" * 50 + "\n\n"
        for line in content.split('\n'):
            if 'open' in line.lower() and '/' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port, protocol, service = parts[0], parts[1], parts[2]
                    formatted += f"✅ Port {port:<6} {protocol:<8} {service}\n"
                else:
                    formatted += f"✅ {line}\n"
            elif 'cve-' in line.lower():
                formatted += f"⚠️  {line}\n"
            elif line.strip():
                formatted += line + '\n'
        return formatted


class ArchiveRunner:
    """Builds commands for each archive sub-tool and parses the merged output."""

    def build_waybackurls_cmd(self, domain: str) -> List[str]:
        return ["waybackurls", domain]

    def build_waymore_cmd(self, domain: str, output_file: str) -> List[str]:
        return ["waymore", "-i", domain, "-mode", "U", "-oU", output_file]

    def build_gau_cmd(self, domain: str) -> List[str]:
        return ["gau", "--fc", "404", domain]

    def build_gauplus_cmd(self, domain: str) -> List[str]:
        return ["gauplus", domain]

    def build_github_endpoints_cmd(self, domain: str, token: str) -> List[str]:
        return ["github-endpoints", "-q", "-k", "-d", domain, "-t", token]

    def build_httpx_cmd(self, cookie: str = "", proxy: str = "",
                        extra_headers: list = None) -> List[str]:
        cmd = ["httpx", "-silent", "-fc", "404", "-mc", "200", "-td"]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
        if extra_headers:
            cmd.extend(extra_headers)
        if proxy:
            cmd.extend(["-http-proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        js_urls, css_urls, img_urls, other_urls = [], [], [], []
        for line in content.split('\n'):
            if not line.strip():
                continue
            ll = line.lower()
            if '.js' in ll:
                js_urls.append(line)
            elif '.css' in ll:
                css_urls.append(line)
            elif any(ext in ll for ext in ['.jpg', '.png', '.gif', '.svg']):
                img_urls.append(line)
            else:
                other_urls.append(line)

        formatted = "📚 ARCHIVE URLS BY TYPE\n" + "═" * 50 + "\n\n"
        if js_urls:
            formatted += f"📜 JavaScript Files ({len(js_urls)}):\n"
            for u in js_urls[:20]:
                formatted += f"  {u}\n"
            if len(js_urls) > 20:
                formatted += f"  ... and {len(js_urls)-20} more\n"
            formatted += "\n"
        if css_urls:
            formatted += f"🎨 CSS Files ({len(css_urls)}):\n"
            for u in css_urls[:10]:
                formatted += f"  {u}\n"
            if len(css_urls) > 10:
                formatted += f"  ... and {len(css_urls)-10} more\n"
            formatted += "\n"
        if img_urls:
            formatted += f"🖼️ Images ({len(img_urls)}):\n"
            for u in img_urls[:10]:
                formatted += f"  {u}\n"
            if len(img_urls) > 10:
                formatted += f"  ... and {len(img_urls)-10} more\n"
            formatted += "\n"
        if other_urls:
            formatted += f"📎 Other URLs ({len(other_urls)}):\n"
            for u in other_urls[:20]:
                formatted += f"  {u}\n"
            if len(other_urls) > 20:
                formatted += f"  ... and {len(other_urls)-20} more\n"
        return formatted


class BruteforceRunner:
    """Builds the feroxbuster command and parses its raw output."""

    GITHUB_WORDLIST_URL = (
        "https://raw.githubusercontent.com/MarioHabashy/Wordlists"
        "/refs/heads/main/Additional-wordlist"
    )

    # Seclists discovery — checked once at class level, cached as class attribute
    _SECLISTS_CANDIDATES = [
        "/usr/share/seclists",
        "/usr/share/SecLists",
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/seclists"),
        "/opt/seclists",
        "/opt/SecLists",
    ]

    TECH_KEYWORDS = {
        "wordpress":  r"wordpress|wp-content|wp-admin|wp-json|wp-login",
        "joomla":     r"joomla",
        "drupal":     r"drupal",
        "magento":    r"magento|magentovisitor",
        "sharepoint": r"sharepoint",
        "apache":     r"apache|litespeed",
        "nginx":      r"nginx",
        "tomcat":     r"tomcat|jsessionid",
        "iis":        r"iis|asp\.net|x-aspnet-version|asp\.net_sessionid",
        "graphql":    r"graphql",
        "api":        r"\bapi\b|rest|swagger|express",
        "coldfusion": r"coldfusion|adobe",
        "cgi":        r"\bcgi\b|perl",
        "oracle":     r"oracle",
        "php":        r"\bphp\b|phpsessid|\.php",
    }

    def find_seclists(self) -> Optional[str]:
        return next((p for p in self._SECLISTS_CANDIDATES if os.path.isdir(p)), None)

    def detect_technologies(self, text: str) -> List[str]:
        """Return list of technology names detected in text."""
        detected = []
        for tech, pattern in self.TECH_KEYWORDS.items():
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(tech)
        return detected

    def search_wordlists_for_tech(self, seclists: str, tech: str) -> List[str]:
        """Use find to discover all wordlists under seclists/Discovery/Web-Content matching tech."""
        base_path = os.path.join(seclists, "Discovery", "Web-Content")
        try:
            result = subprocess.run(
                ["find", base_path, "-type", "f"],
                capture_output=True, text=True, timeout=20
            )
            paths = [
                p.strip() for p in result.stdout.splitlines()
                if tech.lower() in p.lower() and p.strip()
            ]
            return [p for p in paths if os.path.exists(p)]
        except Exception:
            return []

    def fetch_github_wordlist_to_file(self, dest_path: str) -> bool:
        """Fetch the GitHub additional wordlist via curl. Returns True on success."""
        try:
            result = subprocess.run(
                ["curl", "-fsSL", "--max-time", "30", self.GITHUB_WORDLIST_URL],
                capture_output=True, text=True, timeout=35
            )
            if result.returncode == 0 and result.stdout.strip():
                with open(dest_path, "w") as f:
                    f.write(result.stdout)
                return True
        except Exception:
            pass
        return False

    def select_wordlists(self, seclists: Optional[str], tech_content: str,
                         extra: str = "") -> Dict[str, List[str]]:
        """Return dict mapping category -> list of existing wordlist paths."""
        plan: Dict[str, List[str]] = {}

        # Base wordlists always used
        base = []
        if seclists:
            base = [
                os.path.join(seclists, "Discovery/Web-Content/common.txt"),
                os.path.join(seclists, "Discovery/Web-Content/quickhits.txt"),
                os.path.join(seclists, "Discovery/Web-Content/raft-medium-directories.txt"),
            ]
        base.append("/usr/lib/python3/dist-packages/dirsearch/db/dicc.txt")
        plan["base"] = [p for p in base if os.path.exists(p)]

        if extra and os.path.exists(extra):
            plan["custom"] = [extra]

        # Tech-specific wordlists — dynamic discovery via find
        if seclists and tech_content:
            detected = self.detect_technologies(tech_content)
            for tech in detected:
                found = self.search_wordlists_for_tech(seclists, tech)
                if found:
                    plan[tech] = found

        return plan

    def build_command(self, domain: str, wordlist: str,
                      output_file: str, cookie: str = "", proxy: str = "",
                      extra_headers: list = None,
                      filter_codes: list = None) -> List[str]:
        _filter = filter_codes if filter_codes is not None else [400, 404, 429]
        filter_args: list = []
        for code in _filter:
            filter_args.extend(["-C", str(code)])
        cmd = [
            "feroxbuster", "-u", f"https://{domain}",
            "-n", *filter_args,
            "--dont-extract-links", "--no-state", "-k",
            "-w", wordlist, "-o", output_file
        ]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
        if extra_headers:
            cmd.extend(extra_headers)
        if proxy:
            cmd.extend(["--proxy", proxy])
        return cmd

    def parse_output(self, raw_content: str) -> str:
        clean_lines = []
        status_counts: Dict[str, int] = {}
        for ln in raw_content.splitlines():
            # Feroxbuster format: STATUS  METHOD  LINES  WORDS  BYTES  URL
            # Use flexible match: status code at start, URL anywhere on the line
            m = re.match(r'^(\d{3})\s+.*?(https?://\S+)', ln)
            if m:
                status, url = m.group(1), m.group(2)
                status_counts[status] = status_counts.get(status, 0) + 1
                size_m = re.search(r'\b(\d+)c\b', ln)
                if size_m:
                    b = int(size_m.group(1))
                    size = f"{b//1024}KB" if b >= 1024 else f"{b}B"
                else:
                    size = ""
                clean_lines.append(f"{status:<6} {size:<8} {url}")

        icons = {'200': '✅', '301': '↪️', '302': '↪️', '403': '🔒', '500': '💥'}
        formatted = "📂 CONTENT BRUTEFORCE RESULTS\n" + "═" * 50 + "\n\n"
        formatted += "📊 Summary by Status:\n"
        for status in sorted(status_counts):
            formatted += f"  {icons.get(status, '📄')} HTTP {status}: {status_counts[status]} endpoints\n"
        formatted += "\n📋 Discovered Endpoints:\n" + "-" * 60 + "\n"
        for line in sorted(set(clean_lines)):
            formatted += f"  {line}\n"
        return formatted


class NucleiRunner:
    def build_command(self, domain: str, output_file: str,
                      cookie: str = "", proxy: str = "",
                      extra_headers: list = None) -> List[str]:
        cmd = ["nuclei", "-u", domain, "-nh", "-o", output_file]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
        if extra_headers:
            cmd.extend(extra_headers)
        if proxy:
            cmd.extend(["-proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        buckets: Dict[str, List[str]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for line in content.split('\n'):
            ll = line.lower()
            for sev in buckets:
                if f'[{sev}]' in ll:
                    buckets[sev].append(line)
                    break

        icons = {"critical": "🔥", "high": "⚠️", "medium": "⚡", "low": "ℹ️", "info": "📌"}
        formatted = "☢️ NUCLEI SCAN RESULTS\n" + "═" * 50 + "\n\n"
        any_findings = False
        for sev, lines in buckets.items():
            if not lines:
                continue
            any_findings = True
            formatted += f"{icons[sev]} {sev.upper()} FINDINGS\n"
            for finding in lines[:10]:
                formatted += f"  {finding}\n"
            if len(lines) > 10:
                formatted += f"  ... and {len(lines)-10} more\n"
            formatted += "\n"
        if not any_findings:
            formatted += "✅ No findings detected.\n"
        return formatted


class NiktoRunner:
    def build_command(self, domain: str, output_file: str,
                      proxy: str = "") -> List[str]:
        cmd = ["nikto", "-h", domain, "-maxtime", "600", "-nointeractive"]
        if proxy:
            cmd.extend(["-useproxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        return content  # nikto output is already well-structured


class WpscanRunner:
    def build_command(self, domain: str, output_file: str,
                      cookie: str = "", proxy: str = "",
                      extra_headers: list = None) -> List[str]:
        cmd = ["wpscan", "--url", domain, "-o", output_file]
        if cookie:
            cmd.extend(["--cookie", cookie])
        if extra_headers:
            # wpscan supports --additional-headers for extra HTTP headers
            for i in range(0, len(extra_headers), 2):
                cmd.extend(["--additional-headers", extra_headers[i + 1]])
        if proxy:
            cmd.extend(["--proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        formatted = "🔷 WORDPRESS SCAN RESULTS\n" + "═" * 50 + "\n\n"
        version_match = re.search(r'WordPress version (\d+\.\d+(\.\d+)?)', content)
        if version_match:
            formatted += f"📌 Version: {version_match.group(1)}\n\n"
        vulns = re.findall(r'\[\!\] (.*?CVE.*?)\n', content)
        if vulns:
            formatted += "⚠️ Vulnerabilities Found:\n"
            for v in vulns[:20]:
                formatted += f"  • {v}\n"
            formatted += "\n"
        users = re.findall(r'\[i\] (.*?)\n', content)
        if users:
            formatted += "👤 Users Found:\n"
            for u in users[:20]:
                formatted += f"  • {u}\n"
        if not vulns and not users:
            formatted += "✅ No critical findings detected.\n"
        return formatted


class JoomscanRunner:
    def build_command(self, domain: str, cookie: str = "",
                      extra_headers: list = None) -> List[str]:
        cmd = ["joomscan", "-u", domain]
        if cookie:
            cmd.extend(["--cookie", cookie])
        # joomscan doesn't support arbitrary headers natively; log a note if extra headers are used
        return cmd

    def parse_output(self, content: str) -> str:
        return content


class DroopescanRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["droopescan", "scan", "drupal", "-u", domain]

    def parse_output(self, content: str) -> str:
        return content


class SubdomainRunner:
    """Builds commands for each passive subdomain sub-tool and formats results."""

    def build_amass_cmd(self, domain: str, output_file: str) -> List[str]:
        return ["amass", "enum", "-passive", "-d", domain, "-o", output_file]

    def build_subfinder_cmd(self, domain: str, output_file: str) -> List[str]:
        return ["subfinder", "-all", "-d", domain, "-o", output_file]

    def build_findomain_cmd(self, domain: str, output_file: str) -> List[str]:
        return ["findomain", "-t", domain, "-u", output_file]

    def build_github_subdomains_cmd(self, domain: str, token: str,
                                     output_file: str) -> List[str]:
        return ["github-subdomains", "-d", domain, "-k", "-q",
                "-t", token, "-o", output_file]

    def fetch_crtsh(self, domain: str) -> List[str]:
        """Fetch subdomains from crt.sh. Returns list of subdomain strings."""
        import urllib.request, json as _json
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = _json.loads(resp.read())
        subs = set()
        for entry in data:
            for s in entry.get("name_value", "").split("\n"):
                s = s.strip().lstrip("*.")
                if s.endswith(f".{domain}"):
                    subs.add(s)
        return sorted(subs)

    def parse_output(self, subdomains: List[str]) -> str:
        level2, level3, level4, others = [], [], [], []
        for sub in sorted(subdomains):
            dots = sub.count('.')
            if dots == 1:   level2.append(sub)
            elif dots == 2: level3.append(sub)
            elif dots == 3: level4.append(sub)
            else:           others.append(sub)

        formatted = "🌿 SUBDOMAIN ENUMERATION RESULTS\n" + "═" * 50 + "\n\n"
        for label, icon, lst, limit in [
            ("2nd Level", "🌐", level2, 20),
            ("3rd Level", "🌍", level3, 30),
            ("4th Level", "🌏", level4, 30),
            ("Other",     "📌", others, 20),
        ]:
            if not lst:
                continue
            formatted += f"{icon} {label} ({len(lst)}):\n"
            for sub in lst[:limit]:
                formatted += f"  {sub}\n"
            if len(lst) > limit:
                formatted += f"  ... and {len(lst)-limit} more\n"
            formatted += "\n"
        return formatted


# ─────────────────────────────────────────────────────────────────────────────
# Task Worker
# ─────────────────────────────────────────────────────────────────────────────

class TaskWorker(QThread):
    """Worker thread for executing security tools."""

    output_received = pyqtSignal(str, str)     # task_id, output_line
    status_changed  = pyqtSignal(str, str, str) # task_id, status, message
    task_completed  = pyqtSignal(str, bool, str) # task_id, success, output_file

    def __init__(self, task_data: Dict[str, Any], project_dir: str):
        super().__init__()
        self.task_id   = task_data["id"]
        self.task_data = task_data
        self.project_dir = project_dir
        self._is_running = True

        # FIX 1: Replace single self.process with a list + lock to avoid
        # race conditions when stop() is called while multiple sub-processes
        # run sequentially (e.g. spider = katana → hakrawler → httpx).
        self._processes: List[subprocess.Popen] = []
        self._process_lock = threading.Lock()

        # Fork subprocess IPC: set in run(), consumed by _emit()/_status()/_done()
        self._ipc_queue = None      # multiprocessing.Queue (child writes, parent reads)
        self._fork_process = None   # multiprocessing.Process handle

        # Create task output directory FIRST (before setting output_file)
        self.task_dir = os.path.join(project_dir, "tasks", self.task_id)
        os.makedirs(self.task_dir, exist_ok=True)
        self.output_file = os.path.join(self.task_dir, "output.log")
        self.raw_output_file = os.path.join(self.task_dir, "output.raw.log")  # Store raw output

    def run(self):
        """Fork a child process to execute the tool, then relay its output as Qt signals."""
        import multiprocessing as _mp
        import queue as _stdlib_queue

        ctx = _mp.get_context('fork')
        q = ctx.Queue()
        # Set queue BEFORE start() so the forked child inherits it via os.fork()
        self._ipc_queue = q
        self._fork_process = ctx.Process(target=self._execute_task, daemon=True)
        self._fork_process.start()
        # Parent must NOT use _ipc_queue — clear it so signals go through Qt normally
        self._ipc_queue = None

        _got_done = False
        while True:
            try:
                msg = q.get(timeout=0.1)
                if msg is None:  # sentinel from _done()
                    break
                kind = msg[0]
                if kind == 'output':
                    self._emit(msg[1])
                elif kind == 'status':
                    self._status(msg[1], msg[2])
                elif kind == 'done':
                    self._done_complete(msg[1], msg[2])
                    _got_done = True
                    # Drain the sentinel that _done() puts after 'done'
                    try:
                        q.get(timeout=0.5)
                    except _stdlib_queue.Empty:
                        pass
                    break
            except _stdlib_queue.Empty:
                if not self._fork_process.is_alive():
                    # Child exited without a clean _done() — drain leftovers
                    while True:
                        try:
                            msg = q.get_nowait()
                            if msg is None:
                                break
                            kind = msg[0]
                            if kind == 'output':
                                self._emit(msg[1])
                            elif kind == 'status':
                                self._status(msg[1], msg[2])
                            elif kind == 'done':
                                self._done_complete(msg[1], msg[2])
                                _got_done = True
                        except _stdlib_queue.Empty:
                            break
                    break

        if not _got_done:
            self._done_complete(False, "")

        if self._fork_process.is_alive():
            self._fork_process.terminate()
            self._fork_process.join(timeout=5)

    def _execute_task(self):
        """Runs inside the forked child process — no Qt signal calls allowed here."""
        try:
            os.setsid()  # New session so stop() can kill the whole process group
        except OSError:
            pass
        try:
            tool = self.task_data["tool"]
            dispatch = {
                "spider":      self._run_spider,
                "archive":     self._run_archive,
                "ipinfo":      self._run_ipinfo,
                "headers":     self._run_headers,
                "tech":        self._run_tech,
                "waf":         self._run_waf,
                "cms":         self._run_cms,
                "ports":       self._run_ports,
                "bruteforce":  self._run_bruteforce,
                "nuclei":      self._run_nuclei,
                "nikto":       self._run_nikto,
                "wpscan":      self._run_wpscan,
                "joomscan":    self._run_joomscan,
                "droopescan":  self._run_droopescan,
                "subdomains4":        self._run_subdomains4,
                # ── Domain-level tasks ──────────────────────────────────────
                "whois":              self._run_whois,
                "google_dorks":       self._run_google_dorks,
                "github_dorks":       self._run_github_dorks,
                "github_secrets":     self._run_github_secrets,
                "emails":             self._run_emails,
                "metadata":           self._run_metadata,
                "passive_subdomains": self._run_passive_subdomains,
                "active_subdomains":  self._run_active_subdomains,
                "guess_subdomains":   self._run_guess_subdomains,
                "live_subdomains":    self._run_live_subdomains,
                "vhost":              self._run_vhost,
                "bypass_40x":         self._run_bypass_40x,
                "takeover":           self._run_takeover,
                "service_scan":       self._run_service_scan,
                "cloud_enum":         self._run_cloud_enum,
                "screenshot":         self._run_screenshot,
            }
            fn = dispatch.get(tool)
            if fn:
                fn(self.output_file)
            else:
                self._done(False, "", f"Unknown tool: {tool}")
        except Exception as e:
            logger.error(f"Task execution error: {e}", exc_info=True)
            self._done(False, "", str(e))

    def stop(self):
        self._is_running = False
        # Kill the forked process and its entire process group (tool subprocesses)
        if self._fork_process is not None and self._fork_process.is_alive():
            try:
                import signal as _signal
                os.killpg(os.getpgid(self._fork_process.pid), _signal.SIGTERM)
            except Exception:
                try:
                    self._fork_process.terminate()
                except Exception:
                    pass
        # Safety net: also terminate any directly registered subprocesses
        with self._process_lock:
            procs = list(self._processes)
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def _register_process(self, proc: subprocess.Popen) -> subprocess.Popen:
        """Register a subprocess so stop() can terminate it. Returns the proc for chaining."""
        with self._process_lock:
            self._processes.append(proc)
        return proc

    def _unregister_process(self, proc: subprocess.Popen):
        """Remove a finished process from the tracked list."""
        with self._process_lock:
            try:
                self._processes.remove(proc)
            except ValueError:
                pass

    # ── Tool runners ──────────────────────────────────────────────────────────

    def _run_spider(self, output_file: str):
        """
        Spider = gospider + cariddi + katana (opt) + hakrawler (opt)
                + sitemap.xml (pure-Python) + linkfinder (JS endpoints)
                + paramspider (parameters) + httpx liveness check.

        Proxy handling:
          • ALL crawl tools run WITHOUT proxy (zero proxy noise during discovery).
          • httpx liveness check also runs WITHOUT proxy (pure dedup/validation).
          • If proxy is configured AND proxy_replay=True, a single selective
            replay step is run at the very end — only URLs matching the user-
            chosen status codes are sent through the proxy.  This prevents the
            tool from freezing and avoids double-proxying.
        """
        self._status("running", "Starting spider…")
        domain       = self.task_data["domain"]
        cookie       = validate_cookie(self.task_data.get("cookie", ""))
        extra_h      = self._extra_h_args(skip_names={"cookie"})
        proxy        = self.task_data.get("proxy", "")
        tools_dir    = self.task_data.get("tools_dir", os.path.expanduser("~/tools"))
        proxy_replay = self.task_data.get("proxy_replay", False)
        # Custom SC codes from dialog; None → use class default PROXY_REPLAY_CODES
        replay_codes_raw = self.task_data.get("proxy_replay_codes", None)
        replay_codes = frozenset(replay_codes_raw) if replay_codes_raw else None

        raw_urls:   set = set()   # all discovered URLs before httpx
        final_urls: set = set()   # httpx-validated or raw when httpx absent

        temp_gospider_dir = os.path.join(self.task_dir, "gospider_out")
        temp_cariddi      = os.path.join(self.task_dir, "cariddi_raw.txt")
        temp_katana       = os.path.join(self.task_dir, "katana_raw.txt")
        temp_hakrawler    = os.path.join(self.task_dir, "hakrawler_raw.txt")
        temp_robots       = os.path.join(self.task_dir, "robots_raw.txt")
        temp_validated    = os.path.join(self.task_dir, "validated.txt")
        temp_js_list      = os.path.join(self.task_dir, "js_urls.txt")
        temp_params       = os.path.join(self.task_dir, "paramspider.txt")
        os.makedirs(temp_gospider_dir, exist_ok=True)

        # ── Step 1: sitemap.xml (pure Python) ──────────────────────────────
        if self._is_running:
            self._status("running", "Fetching sitemap.xml…")
            sitemap_urls = self._fetch_sitemap_urls(domain)
            if sitemap_urls:
                raw_urls.update(sitemap_urls)
                self._emit(f"[✓] sitemap.xml: {len(sitemap_urls)} URLs"
                )

        # ── Step 2: gospider (no proxy — discovery only) ───────────────────
        if self._is_running:
            self._status("running", "Running gospider…")
            gs_urls = self._run_gospider_tool(domain, temp_gospider_dir, cookie, "")
            if gs_urls:
                raw_urls.update(gs_urls)
                self._emit(f"[✓] gospider: {len(gs_urls)} URLs"
                )

        # ── Step 3: katana (no proxy — optional) ──────────────────────────
        if self._is_running and check_tool_available("katana"):
            self._status("running", "Running katana…")
            ok = self._run_katana_tool(domain, cookie, "", temp_katana)
            if ok and os.path.exists(temp_katana):
                with open(temp_katana) as f:
                    kt_urls = {l.strip() for l in f if l.strip()}
                raw_urls.update(kt_urls)
                self._emit(f"[✓] katana: {len(kt_urls)} URLs"
                )

        # ── Step 4: hakrawler (no proxy — optional) ────────────────────────
        if self._is_running and check_tool_available("hakrawler"):
            self._status("running", "Running hakrawler…")
            hak_urls = self._run_hakrawler_tool(domain, cookie, "")
            if hak_urls:
                with open(temp_hakrawler, "w") as f:
                    f.write("\n".join(hak_urls))
                raw_urls.update(hak_urls)
                self._emit(f"[✓] hakrawler: {len(hak_urls)} URLs"
                )

        # ── Step 5: cariddi (no proxy — headless SPA) ─────────────────────
        if self._is_running:
            self._status("running", "Running cariddi (SPA crawl)…")
            ca_urls = self._run_cariddi_tool(domain, temp_cariddi, cookie, "")
            if ca_urls:
                raw_urls.update(ca_urls)
                self._emit(f"[✓] cariddi: {len(ca_urls)} URLs"
                )

        # ── Step 6: roboxtractor (optional fallback) ───────────────────────
        if self._is_running and check_tool_available("roboxtractor"):
            self._status("running", "Checking robots.txt…")
            robots_urls = self._run_roboxtractor(domain, temp_robots)
            if robots_urls:
                raw_urls.update(robots_urls)
                self._emit(f"[✓] roboxtractor: {len(robots_urls)} URLs"
                )

        self._emit(f"[*] Raw collected: {len(raw_urls)} unique URLs"
        )

        # ── Step 7: linkfinder on .js files ───────────────────────────────
        if self._is_running:
            js_urls = [u for u in raw_urls if ".js" in u.lower() and u.startswith("http")]
            if js_urls:
                with open(temp_js_list, "w") as f:
                    f.write("\n".join(js_urls))
                self._status("running",
                    f"Running linkfinder on {len(js_urls)} JS files…"
                )
                lf_endpoints = self._run_linkfinder_tool(js_urls, tools_dir, domain)
                if lf_endpoints:
                    raw_urls.update(lf_endpoints)
                    self._emit(f"[✓] linkfinder: {len(lf_endpoints)} endpoints from JS files"
                    )

        # ── Step 8: httpx liveness check (NO proxy — pure dedup) ─────────
        if self._is_running and raw_urls:
            if check_tool_available("httpx"):
                self._status("running", "Validating with httpx (no proxy)…")
                self._run_httpx_validation_from_list(
                    list(raw_urls), temp_validated, cookie, ""   # no proxy here
                )
                if os.path.exists(temp_validated) and os.path.getsize(temp_validated) > 0:
                    with open(temp_validated) as f:
                        for line in f:
                            u = line.strip()
                            if u:
                                final_urls.add(u)
                    self._emit(f"[✓] httpx validated: {len(final_urls)} live URLs"
                    )
                else:
                    final_urls = raw_urls
            else:
                # httpx not installed — use raw results
                self._emit("[!] httpx not found — skipping validation, using raw URLs"
                )
                self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('httpx', '')}"
                )
                final_urls = raw_urls

        # ── Step 9: paramspider ────────────────────────────────────────────
        if self._is_running and check_tool_available("paramspider"):
            self._status("running", "Running paramspider…")
            param_urls = self._run_paramspider_tool(domain, temp_params)
            if param_urls:
                final_urls.update(param_urls)
                self._emit(f"[✓] paramspider: {len(param_urls)} parameterised URLs"
                )

        # ── Final: write output ────────────────────────────────────────────
        if self._is_running and final_urls:
            with open(output_file, "w") as f:
                for u in sorted(final_urls):
                    f.write(f"{u}\n")
            self._emit(f"[✓] {len(final_urls)} unique URLs total"
            )
            for u in sorted(final_urls)[:10]:
                self._emit(u)
            if len(final_urls) > 10:
                self._emit(f"… and {len(final_urls) - 10} more"
                )

        # ── Step 10 (optional): single proxy replay with SC filter ─────────
        #  • Crawl tools already ran WITHOUT proxy — no double-proxying.
        #  • This is the ONE and ONLY pass through the proxy.
        #  • Only done when user explicitly enabled proxy_replay in the dialog.
        if self._is_running and proxy and proxy_replay and final_urls:
            self._status("running", "Proxy replay — filtering discovered URLs…")
            replayed = self._proxy_replay(
                list(final_urls), proxy, cookie,
                label="spider proxy-replay",
                codes=replay_codes,
            )
            self._emit(f"[✓] Proxy replay complete — {len(replayed)} URLs sent through proxy")
            # Save replayed list alongside main output for reference
            replay_out = os.path.join(self.task_dir, "proxy_replayed.txt")
            with open(replay_out, "w") as f:
                f.write("\n".join(replayed))
        elif proxy and not proxy_replay:
            self._emit("[i] Proxy configured but proxy replay is disabled — URLs NOT sent through proxy")
            self._emit("[i] Enable 'Proxy Replay' in task config to selectively send URLs to proxy")

        if self._is_running and final_urls:
            if self._is_running:
                self._status("completed", f"Found {len(final_urls)} URLs")
            self._done_complete(True, output_file)
        else:
            self._emit("[!] No URLs found")
            if self._is_running:
                self._status("completed", "No URLs found")
            self._done_complete(True, "")

    def _run_katana_tool(self, domain: str, cookie: str, proxy: str, output_file: str,
                         extra_headers: list = None) -> bool:
        cookie = validate_cookie(cookie)  # FIX 6
        try:
            # Fixed: Removed invalid -kf all flag
            cmd = ["katana", "-u", domain, "-jc"]
            if cookie:
                cmd.extend(["-H", f"Cookie: {cookie}"])
            if extra_headers:
                cmd.extend(extra_headers)
            if proxy:
                cmd.extend(["-proxy", proxy])
            
            with open(output_file, "w") as outfile:
                proc = subprocess.Popen(
                    cmd, 
                    stdout=outfile, 
                    stderr=subprocess.PIPE, 
                    text=True, 
                    bufsize=1
                )
                self._register_process(proc)  # FIX 1
                try:
                    for line in proc.stderr:
                        if line.strip():
                            self._emit(f"[katana] {line.strip()}")
                        if not self._is_running:
                            proc.terminate()
                            return False
                    proc.wait()
                    return proc.returncode == 0
                finally:
                    self._unregister_process(proc)  # FIX 1
        except FileNotFoundError:
            self._emit(f"[!] katana not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('katana', 'go install')}")
            return False
        except Exception as e:
            self._emit(f"[!] Katana error: {e}")
            return False

    def _run_hakrawler_tool(self, domain: str, cookie: str, proxy: str,
                            extra_headers: list = None) -> List[str]:
        cookie = validate_cookie(cookie)  # FIX 6
        try:
            cmd = ["hakrawler"]
            if cookie:
                cmd.extend(["-h", f"Cookie: {cookie}"])
            if extra_headers:
                # hakrawler uses -h for headers (can be repeated)
                for i in range(0, len(extra_headers), 2):
                    cmd.extend(["-h", extra_headers[i + 1]])
            if proxy:  
                cmd.extend(["-proxy", proxy])
            
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1
            )
            self._register_process(proc)  # FIX 1
            try:
                stdout, stderr = proc.communicate(
                    input=f"https://{domain}\nhttp://{domain}\n", timeout=60
                )
            finally:
                self._unregister_process(proc)  # FIX 1
            if proc.returncode == 0 and stdout:
                urls = [l.strip() for l in stdout.split("\n") if l.strip() and domain in l]
                self._emit(f"[✓] Hakrawler found {len(urls)} URLs")
                return urls
            if stderr:
                self._emit(f"[hakrawler] {stderr.strip()}")
            return []
        except FileNotFoundError:
            self._emit(f"[!] hakrawler not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('hakrawler', 'go install')}")
            return []
        except subprocess.TimeoutExpired:
            self._emit("[!] hakrawler timeout")
            return []
        except Exception as e:
            self._emit(f"[!] Hakrawler error: {e}")
            return []

    def _fetch_sitemap_urls(self, domain: str) -> List[str]:
        """Pure-Python sitemap.xml + sitemap index parser. No external tool needed."""
        import urllib.request as _req
        import xml.etree.ElementTree as ET
        urls: set = set()
        to_fetch = [
            f"https://{domain}/sitemap.xml",
            f"https://{domain}/sitemap_index.xml",
            f"https://{domain}/sitemap-index.xml",
        ]
        visited: set = set()
        while to_fetch:
            url = to_fetch.pop(0)
            if url in visited:
                continue
            visited.add(url)
            try:
                req = _req.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with _req.urlopen(req, timeout=10) as resp:
                    content = resp.read()
                root = ET.fromstring(content)
                ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                # sitemap index — contains <sitemap><loc>…</loc></sitemap>
                for loc in root.findall(".//sm:sitemap/sm:loc", ns):
                    if loc.text and loc.text.strip() not in visited:
                        to_fetch.append(loc.text.strip())
                # regular sitemap — contains <url><loc>…</loc></url>
                for loc in root.findall(".//sm:url/sm:loc", ns):
                    if loc.text:
                        urls.add(loc.text.strip())
            except Exception:
                pass
        return list(urls)

    def _run_gospider_tool(self, domain: str, output_dir: str,
                           cookie: str, proxy: str,
                           extra_headers: list = None) -> List[str]:
        """Run gospider and return list of discovered URLs."""
        cookie = validate_cookie(cookie)
        try:
            from tool_runners import GospiderRunner
            runner = GospiderRunner()
            cmd = runner.build_command(domain, output_dir, cookie, proxy)
            if extra_headers:
                cmd.extend(extra_headers)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self._register_process(proc)
            try:
                stdout, stderr = proc.communicate(timeout=300)
            finally:
                self._unregister_process(proc)
            # gospider writes one file per domain in output_dir; also stdout has hits
            urls: set = set()
            for line in (stdout or "").splitlines():
                m = re.search(r'https?://\S+', line)
                if m:
                    urls.add(m.group(0).rstrip("]\"'"))
            # also scan any files written to output_dir
            if os.path.isdir(output_dir):
                for fname in os.listdir(output_dir):
                    fpath = os.path.join(output_dir, fname)
                    try:
                        with open(fpath) as fh:
                            for line in fh:
                                m = re.search(r'https?://\S+', line)
                                if m:
                                    urls.add(m.group(0).rstrip("]\"'"))
                    except Exception:
                        pass
            return list(urls)
        except FileNotFoundError:
            self._emit("[!] gospider not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('gospider', '')}")
            return []
        except subprocess.TimeoutExpired:
            self._emit("[!] gospider timeout")
            return []
        except Exception as e:
            self._emit(f"[!] gospider error: {e}")
            return []

    def _run_cariddi_tool(self, domain: str, output_file: str,
                          cookie: str, proxy: str,
                          extra_headers: list = None) -> List[str]:
        """Run cariddi (headless SPA crawl) and return discovered URLs."""
        cookie = validate_cookie(cookie)
        try:
            from tool_runners import CariddiRunner
            runner = CariddiRunner()
            cmd = runner.build_command(domain, output_file, cookie, proxy)
            if extra_headers:
                cmd.extend(extra_headers)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self._register_process(proc)
            try:
                stdout, stderr = proc.communicate(timeout=300)
            finally:
                self._unregister_process(proc)
            urls: set = set()
            # collect from stdout
            for line in (stdout or "").splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.add(line)
            # collect from output file if cariddi wrote it
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("http"):
                            urls.add(line)
            return list(urls)
        except FileNotFoundError:
            self._emit("[!] cariddi not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('cariddi', '')}")
            return []
        except subprocess.TimeoutExpired:
            self._emit("[!] cariddi timeout")
            return []
        except Exception as e:
            self._emit(f"[!] cariddi error: {e}")
            return []

    def _run_linkfinder_tool(self, js_urls: List[str], tools_dir: str,
                              domain: str) -> List[str]:
        """Run linkfinder on each .js URL and return discovered endpoint strings."""
        from tool_runners import LinkFinderRunner
        runner = LinkFinderRunner()
        endpoints: set = set()
        for js_url in js_urls[:50]:   # cap at 50 JS files to avoid runaway
            if not self._is_running:
                break
            try:
                cmd = runner.build_command(js_url, tools_dir)
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                self._register_process(proc)
                try:
                    stdout, _ = proc.communicate(timeout=30)
                finally:
                    self._unregister_process(proc)
                for line in (stdout or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("<!") or line.startswith("<"):
                        continue
                    # Absolute URL — keep as-is
                    if line.startswith("http"):
                        endpoints.add(line)
                    # Relative path — make absolute using domain
                    elif line.startswith("/"):
                        endpoints.add(f"https://{domain}{line}")
            except Exception:
                continue
        return list(endpoints)

    def _run_paramspider_tool(self, domain: str, output_file: str) -> List[str]:
        """Run paramspider and return discovered parameterised URLs."""
        try:
            from tool_runners import ParamSpiderRunner
            runner = ParamSpiderRunner()
            cmd = runner.build_command(domain, output_file)
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self._register_process(proc)
            try:
                stdout, stderr = proc.communicate(timeout=120)
            finally:
                self._unregister_process(proc)
            urls: set = set()
            # paramspider writes to -o file
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("http"):
                            urls.add(line)
            # also check stdout in case -o wasn't honoured
            for line in (stdout or "").splitlines():
                line = line.strip()
                if line.startswith("http"):
                    urls.add(line)
            return list(urls)
        except FileNotFoundError:
            self._emit("[!] paramspider not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('paramspider', '')}")
            return []
        except subprocess.TimeoutExpired:
            self._emit("[!] paramspider timeout")
            return []
        except Exception as e:
            self._emit(f"[!] paramspider error: {e}")
            return []

    def _run_httpx_validation(self, input_file: str, output_file: str, cookie: str, proxy: str):
        cookie = validate_cookie(cookie)  # FIX 6
        if not os.path.exists(input_file) or os.path.getsize(input_file) == 0:
            return
        try:
            cmd = ["httpx", "-silent"]
            if cookie: 
                cmd.extend(["-H", f"Cookie: {cookie}"])
            if proxy:  
                cmd.extend(["-http-proxy", proxy])
            
            with open(input_file) as infile, open(output_file, "a") as outfile:
                proc = subprocess.Popen(
                    cmd, stdin=infile, stdout=outfile, stderr=subprocess.PIPE
                )
                self._register_process(proc)  # FIX 1
                try:
                    for line in proc.stderr:
                        if line.strip():
                            self._emit(f"[httpx] {line.strip()}")
                        if not self._is_running:
                            proc.terminate()
                            return
                    proc.wait()
                finally:
                    self._unregister_process(proc)  # FIX 1
        except FileNotFoundError:
            self._emit(f"[!] httpx not found in PATH")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get('httpx', 'go install')}")
        except Exception as e:
            self._emit(f"[!] httpx error: {e}")

    def _run_httpx_validation_from_list(self, urls: List[str], output_file: str, cookie: str, proxy: str):
        cookie = validate_cookie(cookie)  # FIX 6
        if not urls:
            return
        try:
            cmd = ["httpx", "-silent"]
            if cookie: 
                cmd.extend(["-H", f"Cookie: {cookie}"])
            if proxy:  
                cmd.extend(["-http-proxy", proxy])
            
            proc = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True
            )
            self._register_process(proc)  # FIX 1
            try:
                stdout, stderr = proc.communicate(input="\n".join(urls), timeout=60)
            finally:
                self._unregister_process(proc)  # FIX 1
            if stdout:
                with open(output_file, "a") as f:
                    f.write(stdout)
            if stderr:
                for line in stderr.split("\n"):
                    if line.strip():
                        self._emit(f"[httpx] {line.strip()}")
        except Exception as e:
            self._emit(f"[!] httpx error: {e}")

    def _run_roboxtractor(self, domain: str, temp_file: str) -> List[str]:
        """Run roboxtractor to extract URLs from robots.txt. Returns list of raw URLs."""
        try:
            self._emit(f"[*] Extracting URLs from robots.txt for {domain}…")
            cmd = ["roboxtractor", "-u", domain, "-s", "-m", "0"]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            self._register_process(proc)  # FIX 1
            try:
                stdout, stderr = proc.communicate(timeout=30)
            finally:
                self._unregister_process(proc)  # FIX 1
            if proc.returncode == 0 and stdout.strip():
                urls = [l.strip() for l in stdout.strip().split("\n") if l.strip()]
                with open(temp_file, "w") as f:
                    f.write("\n".join(urls))
                return urls
            if stderr and "not found" not in stderr.lower():
                self._emit(f"[!] roboxtractor: {stderr.strip()[:200]}")
            return []
        except FileNotFoundError:
            self._emit("[!] roboxtractor not found in PATH — skipping robots.txt")
            return []
        except subprocess.TimeoutExpired:
            self._emit("[!] roboxtractor timeout")
            return []
        except Exception as e:
            self._emit(f"[!] roboxtractor error: {e}")
            return []

    # ─────────────────────────────────────────────────────────────────────────
    # Generic helpers shared by all runners
    # ─────────────────────────────────────────────────────────────────────────

    def _extra_h_args(self, skip_names: set = None) -> list:
        """Return ['-H', 'Name: Value', ...] for all enabled auth_headers.

        Args:
            skip_names: lowercase header names to skip (e.g. {'cookie'} when the
                        tool already handles cookies via its own --cookie flag).
        Returns a flat list ready to extend() onto a command.
        """
        auth_headers = self.task_data.get("auth_headers", [])
        if not auth_headers:
            return []
        skip = {n.lower() for n in (skip_names or set())}
        args = []
        for h in auth_headers:
            name  = h.get("name", "").strip()
            value = h.get("value", "").strip()
            if name and value and name.lower() not in skip:
                # Guard against header injection (no newlines)
                safe_name  = name.replace("\r", "").replace("\n", "")
                safe_value = value.replace("\r", "").replace("\n", "")
                args.extend(["-H", f"{safe_name}: {safe_value}"])
        return args

    def _emit(self, line: str):
        """Emit an output line — uses IPC queue in forked child, Qt signal in parent."""
        if self._ipc_queue is not None:
            self._ipc_queue.put(('output', line))
        else:
            self.output_received.emit(self.task_id, line)

    def _status(self, status: str, msg: str):
        """Emit a status update — uses IPC queue in forked child, Qt signal in parent."""
        if self._ipc_queue is not None:
            self._ipc_queue.put(('status', status, msg))
        else:
            self.status_changed.emit(self.task_id, status, msg)

    def _done_complete(self, success: bool, file_path: str = ""):
        """Emit task_completed — works in both forked child and parent QThread."""
        if self._ipc_queue is not None:
            self._ipc_queue.put(('done', success, file_path))
            self._ipc_queue.put(None)  # sentinel
        else:
            self.task_completed.emit(self.task_id, success, file_path)

    @staticmethod
    def _read_file_static(path: str) -> str:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return ""

    def _done(self, success: bool, file_path: str = "", msg: str = ""):
        status = "completed" if success else "error"
        msg_final = msg or ("Done" if success else "Failed")
        if self._ipc_queue is not None:
            # Running inside the forked child — send via IPC queue; None is sentinel
            self._ipc_queue.put(('status', status, msg_final))
            self._ipc_queue.put(('done', success, file_path))
            self._ipc_queue.put(None)
        else:
            self.status_changed.emit(self.task_id, status, msg_final)
            self.task_completed.emit(self.task_id, success, file_path)

    def _run_cmd_to_file(self, cmd: List[str], output_file: str,
                         strip_ansi: bool = True, timeout: int = 600) -> bool:
        """Run a command, stream its combined output to output_file and to the live viewer.
        Returns True on success. Strips ANSI codes if strip_ansi=True."""
        import re as _re
        ansi_re = _re.compile(r'\x1B\[[0-9;]*[mGKA-Z]')
        try:
            # Save raw output separately
            with open(self.raw_output_file, "a", encoding="utf-8") as raw_f:
                raw_f.write(f"\n--- Running: {' '.join(cmd)} ---\n")
            
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, errors="replace"
            )
            self._register_process(proc)  # FIX 1
            try:
                with open(output_file, "w", encoding="utf-8") as fout:
                    for raw_line in proc.stdout:
                        if not self._is_running:
                            proc.terminate()
                            return False
                        
                        # Save raw
                        with open(self.raw_output_file, "a", encoding="utf-8") as raw_f:
                            raw_f.write(raw_line)
                        
                        clean = ansi_re.sub("", raw_line).rstrip("\n")
                        if clean:
                            fout.write(clean + "\n")
                            self._emit(clean)
                            
                proc.wait()
                return proc.returncode == 0
            finally:
                self._unregister_process(proc)  # FIX 1
            
        except FileNotFoundError:
            tool_name = cmd[0] if cmd else "unknown"
            self._emit(f"[!] Command not found: {tool_name}")
            self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get(tool_name, 'Check documentation')}")
            return False
        except Exception as exc:
            self._emit(f"[!] Error running {cmd[0] if cmd else 'command'}: {exc}")
            return False

    def _count_lines(self, path: str) -> int:
        try:
            with open(path) as f:
                return sum(1 for l in f if l.strip())
        except Exception:
            return 0

    def _has_output(self, path: str) -> bool:
        return os.path.exists(path) and os.path.getsize(path) > 0

    def _get_task_output_file(self, tool_name: str, domain: str, filename: str = "output.log") -> Optional[str]:
        """Get the path to an output file for a given tool and domain."""
        safe_domain = _safe_slug(domain)
        safe_tool = _safe_slug(tool_name)
        task_id = f"{safe_tool}_{safe_domain}"
        output_path = os.path.join(self.project_dir, "tasks", task_id, filename)
        
        if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
            return output_path
        return None

    def _shared_subdomains_dir(self, domain: str) -> str:
        """
        Return (and create) the shared subdomain directory for a domain.
        Both passive_subdomains and active_subdomains tasks write their
        raw results here so they can always find each other's output.

        Layout:
            tasks/subdomains_<slug>/
                passive_raw.txt       ← raw list from passive task
                active_raw.txt        ← raw list from active/brute-force task
                all_subdomains.txt    ← merged + sort-u dedup
                live_subdomains.txt   ← httpx-verified live hosts  ← used by report
        """
        shared = os.path.join(self.project_dir, "tasks",
                              f"subdomains_{_safe_slug(domain)}")
        os.makedirs(shared, exist_ok=True)
        return shared

    def _find_final_subdomain_list(self, domain: str) -> Optional[str]:
        """
        Return final_subdomains.txt — plain hostnames only, no httpx metadata.
        Used by tasks that need a clean host list: subjack, smap, eyewitness.

        Falls back to _find_best_subdomain_list() if final file doesn't exist yet.
        """
        shared = os.path.join(self.project_dir, "tasks",
                              f"subdomains_{_safe_slug(domain)}")
        final = os.path.join(shared, "final_subdomains.txt")
        if os.path.isfile(final) and os.path.getsize(final) > 0:
            self._emit(f"[*] Using final_subdomains.txt ({self._count_lines(final)} hosts)")
            return final
        # Fallback — live or merged list (may contain httpx metadata)
        self._emit("[!] final_subdomains.txt not found yet — falling back to best available list")
        return self._find_best_subdomain_list(domain)

    def _find_best_subdomain_list(self, domain: str) -> Optional[str]:
        """
        Return the best available subdomain list for downstream tasks.
        Priority:
          1. Shared dir live_subdomains.txt  (merged + httpx-verified)
          2. Shared dir all_subdomains.txt   (merged, not yet verified)
          3. Shared dir passive_raw.txt / active_raw.txt
          4. Legacy per-task output files (backwards compat)
        """
        shared = os.path.join(self.project_dir, "tasks",
                              f"subdomains_{_safe_slug(domain)}")

        # Priority 1 – shared live list (best)
        live = os.path.join(shared, "live_subdomains.txt")
        if os.path.isfile(live) and os.path.getsize(live) > 0:
            self._emit(f"[*] Using shared live subdomain list: {live}")
            return live

        # Priority 2 – shared merged list
        merged = os.path.join(shared, "all_subdomains.txt")
        if os.path.isfile(merged) and os.path.getsize(merged) > 0:
            self._emit(f"[*] Using shared merged subdomain list: {merged}")
            return merged

        # Priority 3 – individual raw files in shared dir
        for fname in ("passive_raw.txt", "active_raw.txt"):
            p = os.path.join(shared, fname)
            if os.path.isfile(p) and os.path.getsize(p) > 0:
                self._emit(f"[*] Using {fname} from shared subdomains dir")
                return p

        # Priority 4 – legacy per-task dirs (backwards compat)
        legacy_candidates = [
            ("passive_subdomains", "live_subdomains.txt"),
            ("active_subdomains",  "live_subdomains.txt"),
            ("live_subdomains",    "output.log"),
            ("passive_subdomains", "all_subdomains.txt"),
            ("active_subdomains",  "all_subdomains.txt"),
            ("passive_subdomains", "output.log"),
            ("active_subdomains",  "output.log"),
        ]
        for tool, filename in legacy_candidates:
            path = self._get_task_output_file(domain=domain, tool_name=tool, filename=filename)
            if path:
                self._emit(f"[*] Using subdomain list from {tool} (legacy): {os.path.basename(path)}")
                return path
        return None

    def _find_latest_task_output(self, tool_name: str, domain: str) -> Optional[str]:
        """Find the most recent completed task output file for tool+domain."""
        safe_domain = _safe_slug(domain)
        best_ts = 0
        best_path = None
        tasks_dir = os.path.join(self.project_dir, "tasks")
        if not os.path.exists(tasks_dir):
            return None
        try:
            for name in os.listdir(tasks_dir):
                if not name.startswith(tool_name):
                    continue
                # Ensure it matches the domain slug (surrounded by underscores)
                if f"_{safe_domain}_" not in name:
                    continue
                
                out = os.path.join(tasks_dir, name, "output.log")
                if not os.path.isfile(out):
                    continue
                    
                try:
                    parts = name.rsplit("_", 1)
                    ts = int(parts[-1])
                except ValueError:
                    ts = int(os.path.getmtime(out) * 1000)
                
                if ts > best_ts:
                    best_ts = ts
                    best_path = out
        except Exception:
            pass
        return best_path

    def _merge_and_check_live(self, this_raw_file: str, other_raw_label: str):
        """
        Merge this task's raw subdomain list with the other task's raw list
        (passive ↔ active), deduplicate with sort -u, check live with httpx,
        and save everything to the shared subdomain directory.

        shared_dir/
            passive_raw.txt   — written by _run_passive_subdomains
            active_raw.txt    — written by _run_active_subdomains
            all_subdomains.txt — merged + sort -u
            live_subdomains.txt — httpx-verified (used by all downstream tasks + report)
        """
        domain = self.task_data["domain"]
        shared = self._shared_subdomains_dir(domain)

        combined_file = os.path.join(shared, "all_subdomains.txt")
        live_file     = os.path.join(shared, "live_subdomains.txt")

        # ── Determine the other raw file path in the shared dir ───────────────
        other_raw_file = os.path.join(shared, f"{other_raw_label}_raw.txt")

        self._emit("─" * 55)
        self._emit(f"[*] Merging subdomain results into shared dir…")
        self._emit(f"    This  : {os.path.basename(this_raw_file)}")
        if os.path.isfile(other_raw_file) and os.path.getsize(other_raw_file) > 0:
            other_count = self._count_lines(other_raw_file)
            self._emit(f"    Other : {os.path.basename(other_raw_file)} ({other_count} entries)")
        else:
            self._emit(f"    Other : {other_raw_label}_raw.txt not found yet — merging solo")

        # ── Collect all lines from both raw files ─────────────────────────────
        source_files = [this_raw_file, other_raw_file]
        # Also pull in the formatted output.log for this task (contains parsed subs)
        source_files.append(self.output_file)

        raw_combined = os.path.join(shared, ".merge_input.txt")
        total_lines = 0
        try:
            with open(raw_combined, "w") as out:
                for src in source_files:
                    if not src or not os.path.isfile(src):
                        continue
                    try:
                        with open(src, "r", encoding="utf-8", errors="replace") as f:
                            for line in f:
                                s = line.strip()
                                # Skip formatted header lines (emoji, ═, empty)
                                if not s:
                                    continue
                                if s.startswith(("🌐", "🌍", "🌏", "📌", "🌿", "═", "─", "Total", "...")):
                                    continue
                                # Keep only lines that look like a hostname
                                if "." in s and " " not in s and not s.startswith("#"):
                                    out.write(s.lstrip("*.") + "\n")
                                    total_lines += 1
                    except Exception as e:
                        self._emit(f"    [!] Could not read {src}: {e}")
        except Exception as e:
            self._emit(f"[!] Error building merge input: {e}")
            return

        self._emit(f"[*] Raw combined lines before dedup: {total_lines}")

        # ── sort -u deduplication ─────────────────────────────────────────────
        try:
            result = subprocess.run(
                ["sort", "-u", raw_combined],
                capture_output=True, text=True, timeout=60
            )
            deduped_lines = [l for l in result.stdout.splitlines() if l.strip()]
            with open(combined_file, "w") as f:
                f.write("\n".join(deduped_lines) + "\n")
            self._emit(f"[✓] After sort -u: {len(deduped_lines)} unique subdomains")
            # Clean up temp file
            try:
                os.remove(raw_combined)
            except Exception:
                pass
        except Exception as e:
            self._emit(f"[!] sort -u failed ({e}), falling back to Python dedup")
            unique = sorted({l.strip() for l in open(raw_combined)
                             if l.strip() and "." in l.strip()})
            with open(combined_file, "w") as f:
                f.write("\n".join(unique) + "\n")
            deduped_lines = unique
            self._emit(f"[✓] After Python dedup: {len(deduped_lines)} unique subdomains")

        if not deduped_lines:
            self._emit("[!] No subdomains to check — skipping httpx")
            return

        # ── httpx live check ──────────────────────────────────────────────────
        self._emit(f"[*] Checking {len(deduped_lines)} subdomains with httpx…")
        from tool_runners import HttpxLiveRunner
        runner = HttpxLiveRunner()
        httpx_cmd = runner.build_command(combined_file, live_file)
        self._run_cmd_to_file(httpx_cmd, live_file + ".log", timeout=1800)

        if os.path.isfile(live_file) and os.path.getsize(live_file) > 0:
            live_count = self._count_lines(live_file)
            self._emit(f"[✓] Live subdomains: {live_count}  →  {live_file}")
        else:
            self._emit("[!] httpx produced no live results")

        # ── Build final_subdomains.txt — plain hostnames only ─────────────────
        # Strips everything httpx adds (status code, title, IP, tech, etc.)
        # so downstream tools (subjack, smap, eyewitness) get a clean host list.
        #
        # httpx output line example:
        #   https://app.ex.com [301] [Title] [1.2.3.4] [CloudFront]
        # final_subdomains.txt line:
        #   app.ex.com
        final_file = os.path.join(shared, "final_subdomains.txt")
        if os.path.isfile(live_file) and os.path.getsize(live_file) > 0:
            try:
                hostnames = []
                with open(live_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        # Strip ANSI codes first
                        line = re.sub(r'\x1B\[[0-9;]*[mGK]', '', line)
                        # Extract hostname from URL at start of line
                        m = re.match(r'https?://([a-zA-Z0-9._:-]+)', line)
                        if m:
                            host = m.group(1).split(":")[0]  # drop port if present
                        else:
                            # Fallback: first token if it looks like a hostname
                            first = line.split()[0] if line.split() else ""
                            if "." in first and not first.startswith("["):
                                host = first.lstrip("*.")
                            else:
                                continue
                        if host:
                            hostnames.append(host)

                # Sort and deduplicate
                hostnames = sorted(set(hostnames))
                with open(final_file, "w") as f:
                    f.write("\n".join(hostnames) + "\n")
                self._emit(f"[✓] final_subdomains.txt: {len(hostnames)} clean hostnames  →  {final_file}")
            except Exception as e:
                self._emit(f"[!] Could not build final_subdomains.txt: {e}")
        else:
            self._emit("[!] Skipping final_subdomains.txt — no live results")

        self._emit("─" * 55)

    # ─────────────────────────────────────────────────────────────────────────
    # Recon tasks  (thin Qt wrappers — all logic lives in runner classes above)
    # ─────────────────────────────────────────────────────────────────────────

    def _run_ipinfo(self, output_file: str):
        domain = self.task_data["domain"]
        self._status("running", "Querying ipinfo…")
        runner = IpinfoRunner()
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if ok else "ipinfo failed")

    def _run_headers(self, output_file: str):
        domain = self.task_data["domain"]
        cookie = validate_cookie(self.task_data.get("cookie", ""))
        proxy  = self.task_data.get("proxy", "")
        extra  = self._extra_h_args(skip_names={"cookie"})
        self._status("running", "Fetching HTTP headers…")
        runner = HeadersRunner()
        cmd = runner.build_command(domain, cookie, proxy, extra_headers=extra)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   "Headers captured" if ok else "curl failed")

    def _run_tech(self, output_file: str):
        domain = self.task_data["domain"]
        self._status("running", "Detecting technologies…")
        runner = TechRunner()
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   "Tech detected" if ok else "wad failed")

    def _run_waf(self, output_file: str):
        domain = self.task_data["domain"]
        self._status("running", "Detecting WAF…")
        runner = WafRunner()
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   "WAF check done" if ok else "wafw00f failed")

    def _run_cms(self, output_file: str):
        domain = self.task_data["domain"]
        self._status("running", "Detecting CMS…")
        runner = CmsRunner()
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file, strip_ansi=True)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   "CMS detected" if ok else "cmseek failed")

    def _run_ports(self, output_file: str):
        domain = self.task_data["domain"]
        self._status("running", "Port scanning…")
        runner = NmapRunner()
        cmd = runner.build_command(domain, output_file)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        self._emit("[*] This may take a few minutes...")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
            if result.returncode == 0:
                with open(output_file, 'r') as f:
                    content = f.read()
                with open(output_file, 'w') as f:
                    f.write(runner.parse_output(content))
                n = self._count_lines(output_file)
                self._done(True, output_file, f"Found {n} open ports/services")
            else:
                self._emit(f"[!] nmap error: {result.stderr}")
                self._done(False, "", "nmap failed")
        except FileNotFoundError:
            self._emit("[!] nmap not found in PATH — Install: sudo apt install nmap")
            self._done(False, "", "nmap not installed")
        except subprocess.TimeoutExpired:
            self._emit("[!] nmap timeout (15 minutes exceeded)")
            self._done(False, "", "nmap timeout")
        except Exception as e:
            self._emit(f"[!] nmap error: {e}")
            self._done(False, "", "nmap failed")

    # ─────────────────────────────────────────────────────────────────────────
    # Proxy replay helper — Idea 1
    #
    # When proxy_replay=True:
    #   Step 1 — Run discovery tools WITHOUT proxy (fast, zero noise)
    #   Step 2 — Probe all results with httpx (no proxy) to collect status codes
    #   Step 3 — Keep only PROXY_REPLAY_CODES (drop 404 / 400 / 429 noise)
    #   Step 4 — Replay the filtered set through the proxy with httpx
    #
    # When proxy_replay=False:
    #   Tools run normally, proxy is passed to every tool as before.
    # ─────────────────────────────────────────────────────────────────────────

    PROXY_REPLAY_CODES: frozenset = frozenset({
        200, 201,
        301, 302, 307, 308,
        401, 403, 405,
        500, 502, 503,
    })

    def _proxy_replay(self, urls: list, proxy: str, cookie: str,
                      label: str = "proxy-replay",
                      codes: Optional[frozenset] = None) -> list:
        """
        Probe *urls* without proxy to collect status codes, drop noise,
        then replay only interesting URLs through *proxy* using httpx.

        *codes* — frozenset of integer SC to keep; defaults to PROXY_REPLAY_CODES.
        Returns the list of "url [SC]" lines that came back from the proxy run,
        or the filtered URL list if no proxy is set.
        """
        active_codes = codes if codes is not None else self.PROXY_REPLAY_CODES
        extra_h = self._extra_h_args(skip_names={"cookie"})
        if not urls:
            return []

        # ── Step 1 + 2: probe without proxy ──────────────────────────────
        self._emit(f"[*] {label}: probing {len(urls)} URLs for status codes (no proxy)…")
        sc_map: dict = {}   # url → int status code
        try:
            probe_cmd = ["httpx", "-silent", "-sc", "-no-color"]
            if cookie:
                probe_cmd.extend(["-H", f"Cookie: {cookie}"])
            if extra_h:
                probe_cmd.extend(extra_h)

            proc = subprocess.Popen(
                probe_cmd,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            self._register_process(proc)
            try:
                stdout, _ = proc.communicate(input="\n".join(urls), timeout=600)
            finally:
                self._unregister_process(proc)

            # httpx -sc format: "https://example.com/path [200]"
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                m = re.search(r"\[(\d{3})\]\s*$", line)
                if m:
                    url_part = line[:m.start()].strip()
                    sc_map[url_part] = int(m.group(1))
                else:
                    sc_map[line] = 0   # no code → keep for safety

        except FileNotFoundError:
            self._emit(f"[!] {label}: httpx not found — replay skipped, proxy used as-is")
            return urls
        except subprocess.TimeoutExpired:
            self._emit(f"[!] {label}: httpx probe timed out — replay skipped")
            return urls
        except Exception as exc:
            self._emit(f"[!] {label}: probe error ({exc}) — replay skipped")
            return urls

        # ── Step 3: filter to interesting status codes ────────────────────
        interesting = [
            url for url, sc in sc_map.items()
            if sc in active_codes or sc == 0
        ]
        dropped = len(sc_map) - len(interesting)
        self._emit(
            f"[✓] {label}: {len(sc_map)} probed → "
            f"{len(interesting)} interesting, {dropped} dropped (404/400/429 noise)"
        )

        if not interesting:
            return []

        if not proxy:
            # No proxy configured — return filtered list, nothing to replay
            return interesting

        # ── Step 4: replay interesting URLs through the proxy ─────────────
        self._emit(f"[*] {label}: replaying {len(interesting)} URLs through proxy {proxy}…")
        mc_arg = ",".join(str(c) for c in sorted(active_codes))
        replay_cmd = [
            "httpx", "-silent", "-sc", "-no-color",
            "-http-proxy", proxy,
            "-mc", mc_arg,
        ]
        if cookie:
            replay_cmd.extend(["-H", f"Cookie: {cookie}"])
        if extra_h:
            replay_cmd.extend(extra_h)

        replayed: list = []
        try:
            proc = subprocess.Popen(
                replay_cmd,
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True,
            )
            self._register_process(proc)
            try:
                stdout, _ = proc.communicate(input="\n".join(interesting), timeout=300)
            finally:
                self._unregister_process(proc)

            for line in stdout.splitlines():
                if line.strip():
                    replayed.append(line.strip())

        except Exception as exc:
            self._emit(f"[!] {label}: replay error ({exc}) — returning unproxied list")
            return interesting

        self._emit(f"[✓] {label}: proxy replay done — {len(replayed)} URLs sent through proxy")
        return replayed

    def _run_archive(self, output_file: str):
        """Wayback + waymore + gau + gauplus + github-endpoints → uro → httpx.

        When proxy_replay=True (user opted in):
          - All discovery tools run WITHOUT proxy for full speed
          - Results are filtered to interesting status codes
          - Only interesting URLs are replayed through the proxy via httpx
        When proxy_replay=False (default):
          - Behaviour unchanged — proxy passed to httpx as before
        """
        domain        = self.task_data["domain"]
        cookie        = validate_cookie(self.task_data.get("cookie", ""))
        extra_h       = self._extra_h_args(skip_names={"cookie"})
        proxy         = self.task_data.get("proxy", "")
        github_token  = self.task_data.get("github_token", "")
        proxy_replay  = self.task_data.get("proxy_replay", False)
        runner        = ArchiveRunner()

        # When filtering is on, tools run without proxy; proxy only used in replay step
        tool_proxy = "" if proxy_replay else proxy

        if proxy_replay and proxy:
            self._emit(f"[*] Proxy filter enabled — tools will run without proxy")
            self._emit(f"[*] Only interesting status codes will be replayed through {proxy}")

        self._status("running", "Collecting archive URLs…")

        d          = self.task_dir
        wayback_f  = os.path.join(d, ".wayback.txt")
        waymore_f  = os.path.join(d, ".waymore.txt")
        gau_f      = os.path.join(d, ".gau.txt")
        gauplus_f  = os.path.join(d, ".gauplus.txt")
        github_f   = os.path.join(d, ".github_ep.txt")
        merged_f   = os.path.join(d, ".merged.txt")
        uro_f      = os.path.join(d, ".uro.txt")

        def _run_tool(label: str, cmd: List[str], out: str):
            if not self._is_running:
                return
            self._emit(f"[*] {label}…")
            try:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, text=True, errors="replace")
                self._register_process(proc)
                try:
                    stdout, stderr = proc.communicate(timeout=2400)
                finally:
                    self._unregister_process(proc)
                with open(out, "w") as f:
                    f.write(stdout)
                self._emit(f"[✓] {label}: {stdout.count(chr(10))} URLs")
                if stderr:
                    self._emit(f"[{label} stderr] {stderr[:200]}")
            except FileNotFoundError:
                self._emit(f"[!] {label} not found in PATH — skipping")
                self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get(label.split()[0].lower(), 'Check docs')}")
                open(out, "w").close()
            except subprocess.TimeoutExpired:
                self._emit(f"[!] {label} timed out")
                open(out, "w").close()
            except Exception as exc:
                self._emit(f"[!] {label} error: {exc}")
                open(out, "w").close()

        # All archive tools always run without proxy (either because proxy_replay
        # is enabled, or because they never accepted a proxy flag to begin with)
        _run_tool("waybackurls", runner.build_waybackurls_cmd(domain), wayback_f)
        _run_tool("waymore",     runner.build_waymore_cmd(domain, waymore_f), waymore_f)
        _run_tool("gau",         runner.build_gau_cmd(domain), gau_f)
        _run_tool("gauplus",     runner.build_gauplus_cmd(domain), gauplus_f)
        if github_token and self._is_running:
            _run_tool("github-endpoints",
                      runner.build_github_endpoints_cmd(domain, github_token), github_f)
        else:
            open(github_f, "w").close()

        if not self._is_running:
            self._done(False, "", "Stopped")
            return

        # ── Merge ────────────────────────────────────────────────────────────
        self._emit("[*] Merging & deduplicating…")
        all_urls: set = set()
        for fp in [wayback_f, waymore_f, gau_f, gauplus_f, github_f]:
            try:
                with open(fp) as f:
                    all_urls.update(ln.strip() for ln in f if ln.strip())
            except Exception:
                pass
        with open(merged_f, "w") as f:
            f.write("\n".join(sorted(all_urls)))
        self._emit(f"[✓] Total unique: {len(all_urls)} URLs")

        # ── uro dedup ────────────────────────────────────────────────────────
        self._emit("[*] Running uro…")
        try:
            with open(merged_f) as inp, open(uro_f, "w") as out:
                proc = subprocess.Popen(["uro"], stdin=inp, stdout=out,
                                        stderr=subprocess.DEVNULL, text=True)
                self._register_process(proc)
                try:
                    proc.wait(timeout=300)
                finally:
                    self._unregister_process(proc)
            self._emit(f"[✓] uro reduced to {self._count_lines(uro_f)} URLs")
        except FileNotFoundError:
            self._emit("[!] uro not found — using merged output directly (pip install uro)")
            uro_f = merged_f

        if not self._is_running:
            self._done(False, "", "Stopped")
            return

        # ── httpx / proxy-replay step ─────────────────────────────────────────
        try:
            with open(uro_f) as inp:
                domain_urls = [l.strip() for l in inp if domain in l and l.strip()]
        except Exception as exc:
            self._emit(f"[!] Could not read uro output: {exc}")
            domain_urls = []

        if domain_urls:
            if proxy_replay and proxy:
                # ── Idea 1: probe without proxy → filter → replay through proxy ──
                self._status("running",
                                         "Filtering status codes + proxy replay…")
                live_lines = self._proxy_replay(domain_urls, proxy, cookie,
                                                label="archive proxy-replay")
                with open(output_file, "w") as fout:
                    fout.write("\n".join(live_lines))
            else:
                # ── Normal path: all URLs through httpx with proxy ───────────────
                self._status("running",
                                         "Validating live URLs with httpx…")
                self._emit("[*] Running httpx to filter live URLs…")
                try:
                    with open(output_file, "w") as fout:
                        proc = subprocess.Popen(
                            runner.build_httpx_cmd(cookie, tool_proxy, extra_headers=extra_h),
                            stdin=subprocess.PIPE, stdout=fout,
                            stderr=subprocess.PIPE, text=True)
                        self._register_process(proc)
                        try:
                            proc.communicate(input="\n".join(domain_urls), timeout=600)
                        finally:
                            self._unregister_process(proc)
                except Exception as exc:
                    self._emit(f"[!] httpx error: {exc}")

        n = self._count_lines(output_file)
        if self._has_output(output_file):
            with open(output_file, "r") as f:
                raw = f.read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))

        self._emit(f"[✓] {n} live archive URLs saved")
        self._done(True, output_file if self._has_output(output_file) else "",
                   f"{n} live URLs from archives")

    def _run_bruteforce(self, output_file: str):
        domain         = self.task_data["domain"]
        cookie         = validate_cookie(self.task_data.get("cookie", ""))
        extra_h        = self._extra_h_args(skip_names={"cookie"})
        proxy          = self.task_data.get("proxy", "")
        wordlist_extra = self.task_data.get("wordlist", "")
        runner         = BruteforceRunner()

        self._status("running", "Building wordlist…")
        self._emit(f"[*] Content bruteforce starting for https://{domain}")

        # Use configured Seclists path if available, otherwise auto-detect
        seclists = self.task_data.get("seclists_dir")
        if not seclists or not os.path.exists(seclists):
            seclists = runner.find_seclists()

        if seclists is None:
            self._emit("[!] WARNING: SecLists not found in any standard location.")
            self._emit("    Checked: " + ", ".join(runner._SECLISTS_CANDIDATES))
            self._emit("    Install: sudo apt install seclists  OR  git clone https://github.com/danielmiessler/SecLists ~/SecLists")
            self._emit("    Bruteforce will proceed with dirsearch wordlist only — results may be limited.")

        # ── Step 1: Collect existing tech + header outputs ─────────────────
        tasks_root = os.path.normpath(os.path.join(self.task_dir, "..", ".."))

        tech_content = ""
        header_content = ""

        tech_file = os.path.join(tasks_root, "tasks",
                                 f"tech_{_safe_slug(domain)}", "output.log")
        if os.path.exists(tech_file):
            try:
                with open(tech_file) as tf:
                    tech_content = tf.read().lower()
                self._emit(f"[+] Found existing tech (wad) output")
            except Exception:
                pass

        headers_file = os.path.join(tasks_root, "tasks",
                                    f"headers_{_safe_slug(domain)}", "output.log")
        if os.path.exists(headers_file):
            try:
                with open(headers_file) as hf:
                    header_content = hf.read().lower()
                self._emit(f"[+] Found existing headers output")
            except Exception:
                pass

        # ── Step 2: Run wad/headers in-line if outputs not available ───────
        if not tech_content:
            self._emit("[*] No tech (wad) output found — running technology detection…")
            tech_tmp = os.path.join(self.task_dir, "tech_scan.tmp")
            wad_cmd = TechRunner().build_command(domain)
            self._run_cmd_to_file(wad_cmd, tech_tmp, timeout=90)
            if self._has_output(tech_tmp):
                try:
                    with open(tech_tmp) as tf:
                        tech_content = tf.read().lower()
                    self._emit("[+] Technology detection complete")
                except Exception:
                    pass

        if not header_content:
            self._emit("[*] No headers output found — fetching HTTP headers…")
            headers_tmp = os.path.join(self.task_dir, "headers_scan.tmp")
            headers_cmd = HeadersRunner().build_command(domain, cookie, proxy)
            self._run_cmd_to_file(headers_cmd, headers_tmp, timeout=45)
            if self._has_output(headers_tmp):
                try:
                    with open(headers_tmp) as hf:
                        header_content = hf.read().lower()
                    self._emit("[+] Headers fetch complete")
                except Exception:
                    pass

        # ── Step 3: Detect technologies from combined output ────────────────
        combined_content = tech_content + "\n" + header_content
        detected_techs = runner.detect_technologies(combined_content)

        # Merge manually-selected technologies from dialog config
        manual_techs = self.task_data.get("manual_techs", [])
        if manual_techs:
            for mt in manual_techs:
                if mt not in detected_techs:
                    detected_techs.append(mt)

        self._emit("\n" + "─" * 50)
        if manual_techs:
            self._emit(f"[✓] Manually specified: {', '.join(manual_techs)}")
        if detected_techs:
            self._emit(f"[✓] Technologies (combined): {', '.join(detected_techs)}")
        else:
            self._emit("[*] No specific technologies detected — using base wordlists only")

        # ── Step 4: Build wordlist plan (base + dynamic tech search) ────────
        wordlist_plan = runner.select_wordlists(seclists, combined_content, wordlist_extra)

        # Add wordlists for manually-selected technologies that weren't auto-detected
        if seclists and manual_techs:
            for tech in manual_techs:
                if tech not in wordlist_plan:
                    found = runner.search_wordlists_for_tech(seclists, tech)
                    if found:
                        wordlist_plan[tech] = found
                        self._emit(f"[+] Added wordlists for manual tech: {tech} ({len(found)} list(s))")
                    else:
                        # Still mark it so it appears in the plan as " no wordlists"
                        wordlist_plan[f"{tech} (no wordlists found)"] = []
                        self._emit(f"[!] No SecLists wordlists found for: {tech}")

        # ── Step 5: Fetch GitHub additional wordlist (always) ───────────────
        github_wl = os.path.join(self.task_dir, "github_wordlist.tmp")
        self._emit("[*] Fetching GitHub additional wordlist…")
        if runner.fetch_github_wordlist_to_file(github_wl):
            self._emit("[+] GitHub wordlist fetched successfully")
            wordlist_plan["github"] = [github_wl]
        else:
            self._emit("[!] Could not fetch GitHub wordlist (offline or unreachable)")

        # ── Step 6: Display wordlist plan by technology ──────────────────────
        self._emit("\n📋 WORDLIST PLAN:")
        for category, paths in wordlist_plan.items():
            if not paths:
                self._emit(f"  [⚠ {category.upper()}] — no matching wordlists in SecLists")
                continue
            self._emit(f"  [{category.upper()}] — {len(paths)} wordlist(s):")
            for p in paths:
                self._emit(f"    • {os.path.basename(p)}")
        self._emit("─" * 50 + "\n")

        all_wordlists = [p for paths in wordlist_plan.values() for p in paths]
        if not all_wordlists:
            self._emit("[!] No wordlists found — cannot run bruteforce.")
            self._done(False, "", "No wordlists available")
            return

        custom_wl = os.path.join(self.task_dir, "combined_wordlist.txt")
        self._emit(f"[*] Merging {len(all_wordlists)} wordlist source(s)…")
        with open(custom_wl, "w") as fout:
            for wl in all_wordlists:
                try:
                    with open(wl) as fin:
                        fout.write(fin.read())
                except Exception:
                    pass
        subprocess.run(["sort", "-u", "-o", custom_wl, custom_wl], capture_output=True)
        self._emit(f"[✓] Combined wordlist: {self._count_lines(custom_wl)} entries")

        ferox_out  = os.path.join(self.task_dir, "feroxbuster_raw.txt")
        proxy_replay = self.task_data.get("proxy_replay", False)

        # When proxy filter is on, feroxbuster runs WITHOUT proxy so it isn't
        # throttled/noisy; interesting results are replayed through proxy afterwards.
        ferox_proxy = "" if proxy_replay else proxy

        if proxy_replay and proxy:
            self._emit(f"[*] Proxy filter enabled — feroxbuster runs without proxy")
            self._emit(f"[*] Interesting status codes will be replayed through {proxy}")

        filter_codes = self.task_data.get("filter_codes")  # None → runner uses defaults
        self._status("running", "Running feroxbuster…")
        cmd = runner.build_command(domain, custom_wl, ferox_out, cookie, ferox_proxy,
                                  extra_headers=extra_h, filter_codes=filter_codes)
        if filter_codes is not None:
            self._emit(f"[*] Filter codes: {', '.join(str(c) for c in filter_codes)}")
        self._emit(f"[*] Running: feroxbuster -u https://{domain} ...")
        self._run_cmd_to_file(cmd, output_file, timeout=7200)

        if os.path.exists(ferox_out):
            with open(ferox_out) as f:
                raw = f.read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
            try:
                os.remove(ferox_out)
            except Exception:
                pass

        # ── Proxy-replay step (only when opted in and proxy is set) ──────────
        if proxy_replay and proxy and self._has_output(output_file):
            self._status("running",
                                     "Filtering status codes + proxy replay…")
            # Parse URLs out of the formatted feroxbuster output
            raw_urls: list = []
            with open(output_file) as f:
                for line in f:
                    # Formatted lines look like: "200    1.2KB  https://example.com/path"
                    m = re.search(r"(https?://\S+)", line)
                    if m:
                        raw_urls.append(m.group(1))
            if raw_urls:
                live_lines = self._proxy_replay(raw_urls, proxy, cookie,
                                                label="bruteforce proxy-replay")
                # Append replay results to the output file as a new section
                with open(output_file, "a") as f:
                    f.write("\n\n── Proxy Replay Results ──\n")
                    f.write("\n".join(live_lines))

        n = self._count_lines(output_file)
        self._emit(f"[✓] {n} unique endpoints found")
        self._done(True, output_file if self._has_output(output_file) else "",
                   f"{n} endpoints")

    def _run_nuclei(self, output_file: str):
        domain = self.task_data["domain"]
        cookie = validate_cookie(self.task_data.get("cookie", ""))
        proxy  = self.task_data.get("proxy", "")
        extra  = self._extra_h_args(skip_names={"cookie"})
        runner = NucleiRunner()
        self._status("running", "Running nuclei…")

        # nuclei -o writes raw findings to raw_file.
        # _run_cmd_to_file streams stdout (progress/errors) to a separate .live file
        # so the two outputs never mix.
        raw_file = output_file + ".raw"
        cmd = runner.build_command(domain, raw_file, cookie, proxy, extra_headers=extra)
        self._emit(f"[*] Running: nuclei -u {domain} ...")
        ok = self._run_cmd_to_file(cmd, output_file + ".live", timeout=1800)

        # Read the raw -o file (complete, never truncated) and format it
        raw_content = ""
        if os.path.exists(raw_file) and os.path.getsize(raw_file) > 0:
            try:
                with open(raw_file, "r", encoding="utf-8", errors="replace") as f:
                    raw_content = f.read()
            except Exception as exc:
                self._emit(f"[!] Could not read nuclei output: {exc}")

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(runner.parse_output(raw_content))

        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} findings" if ok else "nuclei failed")

    def _run_nikto(self, output_file: str):
        domain = self.task_data["domain"]
        proxy  = self.task_data.get("proxy", "")
        runner = NiktoRunner()
        self._status("running", "Running nikto…")

        # build_command no longer takes output_file — stdout is captured directly
        # by _run_cmd_to_file so nikto never sees a .log extension it would reject
        cmd = runner.build_command(domain, proxy)
        self._emit(f"[*] Running: nikto -h {domain} ...")
        ok = self._run_cmd_to_file(cmd, output_file, timeout=700)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} findings" if ok else "nikto failed")

    def _run_wpscan(self, output_file: str):
        domain = self.task_data["domain"]
        cookie = validate_cookie(self.task_data.get("cookie", ""))
        proxy  = self.task_data.get("proxy", "")
        extra  = self._extra_h_args(skip_names={"cookie"})
        runner = WpscanRunner()
        self._status("running", "Running wpscan…")

        cmd = runner.build_command(domain, output_file, cookie, proxy, extra_headers=extra)
        self._emit(f"[*] Running: wpscan --url {domain} ...")
        self._run_cmd_to_file(cmd, output_file + ".live", strip_ansi=True, timeout=600)

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                content = f.read()
            with open(output_file, 'w') as f:
                f.write(runner.parse_output(content))
        else:
            with open(output_file, 'w') as f:
                f.write(runner.parse_output(""))

        n = self._count_lines(output_file)
        self._done(True, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if n else "No WP findings")

    def _run_joomscan(self, output_file: str):
        domain = self.task_data["domain"]
        cookie = validate_cookie(self.task_data.get("cookie", ""))
        extra  = self._extra_h_args(skip_names={"cookie"})
        runner = JoomscanRunner()
        self._status("running", "Running joomscan…")
        if extra:
            self._emit("[!] Note: joomscan does not support arbitrary custom headers natively — only Cookie is passed.")

        cmd = runner.build_command(domain, cookie, extra_headers=extra)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file, strip_ansi=True, timeout=600)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if ok else "joomscan failed")

    def _run_droopescan(self, output_file: str):
        domain = self.task_data["domain"]
        runner = DroopescanRunner()
        self._status("running", "Running droopescan…")

        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, output_file, strip_ansi=True, timeout=600)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if ok else "droopescan failed")

    def _run_subdomains4(self, output_file: str):
        """Passive 4th-level subdomain enumeration."""
        domain       = self.task_data["domain"]
        github_token = self.task_data.get("github_token", "")
        runner       = SubdomainRunner()
        self._status("running", "Enumerating 4th-level subdomains…")

        d           = self.task_dir
        amass_f     = os.path.join(d, ".amass4.txt")
        subfinder_f = os.path.join(d, ".subfinder4.txt")
        github_f    = os.path.join(d, ".github4.txt")
        crt_f       = os.path.join(d, ".crt4.txt")
        findomain_f = os.path.join(d, ".findomain4.txt")

        def _run_tool4(label: str, cmd: List[str], out: str):
            if not self._is_running:
                return
            self._emit(f"[*] {label}…")
            try:
                with open(out, "w") as outfile:
                    proc = subprocess.Popen(cmd, stdout=outfile,
                                            stderr=subprocess.DEVNULL, text=True)
                    self._register_process(proc)
                    try:
                        proc.wait(timeout=300)
                    finally:
                        self._unregister_process(proc)
                self._emit(f"[✓] {label}: {self._count_lines(out)} results")
            except FileNotFoundError:
                self._emit(f"[!] {label} not found — skipping")
                self._emit(f"    Install: {TOOL_INSTALL_GUIDES.get(label.split()[0].lower(), 'Check docs')}")
                open(out, "w").close()
            except subprocess.TimeoutExpired:
                self._emit(f"[!] {label} timed out")
                proc.terminate()
                open(out, "w").close()
            except Exception as exc:
                self._emit(f"[!] {label} error: {exc}")
                open(out, "w").close()

        _run_tool4("amass",     runner.build_amass_cmd(domain, amass_f),         amass_f)
        _run_tool4("subfinder", runner.build_subfinder_cmd(domain, subfinder_f), subfinder_f)
        _run_tool4("findomain", runner.build_findomain_cmd(domain, findomain_f), findomain_f)

        if github_token:
            _run_tool4("github-subdomains",
                       runner.build_github_subdomains_cmd(domain, github_token, github_f),
                       github_f)
        else:
            self._emit("[!] No GitHub token — skipping github-subdomains")
            open(github_f, "w").close()

        # crt.sh
        self._emit("[*] crt.sh passive enum…")
        try:
            subs = runner.fetch_crtsh(domain)
            with open(crt_f, "w") as f:
                f.write("\n".join(subs))
            self._emit(f"[✓] crt.sh: {len(subs)} subdomains")
        except Exception as exc:
            self._emit(f"[!] crt.sh error: {exc}")
            open(crt_f, "w").close()

        # Merge & dedupe
        all_subs: set = set()
        for fp in [amass_f, subfinder_f, github_f, crt_f, findomain_f]:
            try:
                with open(fp) as f:
                    all_subs.update(
                        s.strip() for s in f if s.strip() and domain in s
                    )
            except Exception:
                pass

        with open(output_file, "w") as f:
            f.write(runner.parse_output(list(all_subs)))

        n = len(all_subs)
        self._emit(f"[✓] Total unique subdomains: {n}")
        self._done(True, output_file if self._has_output(output_file) else "",
                   f"{n} subdomains")


# ─────────────────────────────────────────────────────────────────────────────

    # ─────────────────────────────────────────────────────────────────────────
    # Domain-level task runners
    # ─────────────────────────────────────────────────────────────────────────

    def _regenerate_domain_report(self):
        """Regenerate HTML report for the domain after a task finishes."""
        try:
            import importlib.util, sys as _sys
            # Try loading domain_report from same dir as this file
            this_dir = os.path.dirname(os.path.abspath(__file__))
            spec = importlib.util.spec_from_file_location(
                "domain_report",
                os.path.join(this_dir, "domain_report.py")
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                domain = self.task_data["domain"]
                # Pass the shared live_subdomains.txt path so the report always
                # uses the merged + httpx-verified list from both passive & active tasks
                shared_live = os.path.join(
                    self.project_dir, "tasks",
                    f"subdomains_{_safe_slug(domain)}",
                    "live_subdomains.txt"
                )
                kwargs = {}
                import inspect
                sig = inspect.signature(mod.generate)
                if "live_subdomains_file" in sig.parameters:
                    kwargs["live_subdomains_file"] = shared_live if os.path.isfile(shared_live) else None
                report_path = mod.generate(domain, self.project_dir, **kwargs)
                self._emit(f"[📊] Report updated: {report_path}")
        except Exception as exc:
            self._emit(f"[!] Could not update domain report: {exc}")

    def _run_whois(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import WhoisRunner
        runner = WhoisRunner()
        self._status("running", "Running whois…")
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: whois {domain}")
        ok = self._run_cmd_to_file(cmd, output_file)
        if ok and os.path.exists(output_file):
            raw = open(output_file).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if ok else "whois failed")
        self._regenerate_domain_report()

    def _run_google_dorks(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import GoogleDorksRunner
        runner = GoogleDorksRunner()
        self._status("running", "Running Google dorks…")
        # dorks_hunter writes directly to output_file
        tools_dir = self.task_data.get("tools_dir", os.path.expanduser("~/tools"))
        cmd = runner.build_command(domain, tools_dir, output_file)
        self._emit(f"[*] Running: dorks_hunter.py -d {domain}")
        ok = self._run_cmd_to_file(cmd, output_file + ".live", timeout=300)
        # The script writes its own output_file; parse it
        if os.path.exists(output_file):
            raw = open(output_file).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} dork URLs" if ok else "dorks_hunter failed")
        self._regenerate_domain_report()

    def _run_github_dorks(self, output_file: str):
        domain = self.task_data["domain"]
        github_token = self.task_data.get("github_token", "")
        from tool_runners import GithubDorksRunner
        runner = GithubDorksRunner()
        self._status("running", "Running GitHub dorks…")
        if not github_token:
            self._emit("[!] No GitHub token provided — skipping github dorks")
            with open(output_file, "w") as f:
                f.write("No GitHub token provided.\n")
            self._done(False, "", "no github token")
            return
        tools_dir = self.task_data.get("tools_dir", os.path.expanduser("~/tools"))
        default_dorks = os.path.join(tools_dir, "gitdorks_go/Dorks/medium_dorks.txt")
        dorks_file = self.task_data.get("wordlist") or default_dorks
        full_out = output_file + ".full"
        cmd = runner.build_command(domain, github_token, dorks_file)
        self._emit(f"[*] Running: {' '.join(cmd)}")
        ok = self._run_cmd_to_file(cmd, full_out, timeout=600)
        # Filter (0) result lines
        if os.path.exists(full_out):
            raw = open(full_out).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} dork results" if ok else "gitdorks_go failed")
        self._regenerate_domain_report()

    def _run_github_secrets(self, output_file: str):
        domain = self.task_data["domain"]
        github_token = self.task_data.get("github_token", "")
        from tool_runners import TrufflehogRunner
        runner = TrufflehogRunner()
        self._status("running", "Scanning GitHub secrets (trufflehog)…")
        if not github_token:
            self._emit("[!] No GitHub token — skipping trufflehog")
            with open(output_file, "w") as f:
                f.write("No GitHub token provided.\n")
            self._done(False, "", "no github token")
            return
        cmd = runner.build_command(domain, github_token)
        self._emit(f"[*] Running: trufflehog github --org={domain.split('.')[0]}")
        ok = self._run_cmd_to_file(cmd, output_file, timeout=900)
        if ok and os.path.exists(output_file):
            raw = open(output_file).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} secrets found" if ok else "trufflehog failed")
        self._regenerate_domain_report()

    def _run_emails(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import EmailfinderRunner
        runner = EmailfinderRunner()
        self._status("running", "Discovering emails…")
        cmd = runner.build_command(domain)
        self._emit(f"[*] Running: emailfinder -d {domain}")
        ok = self._run_cmd_to_file(cmd, output_file + ".raw", timeout=300)
        raw = ""
        if os.path.exists(output_file + ".raw"):
            raw = open(output_file + ".raw").read()
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} emails found" if ok else "emailfinder failed")
        self._regenerate_domain_report()

    def _run_metadata(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import MetafinderRunner
        runner = MetafinderRunner()
        self._status("running", "Extracting metadata…")
        meta_dir = os.path.join(self.task_dir, "metadata")
        os.makedirs(meta_dir, exist_ok=True)
        cmd = runner.build_command(domain, meta_dir)
        self._emit(f"[*] Running: metafinder -d {domain}")
        ok = self._run_cmd_to_file(cmd, output_file, timeout=600)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} metadata entries" if ok else "metafinder failed")
        self._regenerate_domain_report()

    def _run_passive_subdomains(self, output_file: str):
        domain = self.task_data["domain"]
        github_token = self.task_data.get("github_token", "")
        censys_id = self.task_data.get("censys_id", "")
        censys_secret = self.task_data.get("censys_secret", "")
        from tool_runners import PassiveSubdomainsRunner
        runner = PassiveSubdomainsRunner()
        self._status("running", "Passive subdomain enumeration…")

        d = self.task_dir
        amass_f     = os.path.join(d, ".amass_passive.txt")
        subfinder_f = os.path.join(d, ".subfinder.txt")
        github_f    = os.path.join(d, ".github_subs.txt")
        findomain_f = os.path.join(d, ".findomain.txt")
        crt_f       = os.path.join(d, ".crtsh.txt")
        hackertarget_f = os.path.join(d, ".hackertarget.txt")

        def _run_tool(label, cmd, out, timeout=300):
            if not self._is_running:
                return
            self._emit(f"[*] {label}…")
            try:
                with open(out, "w") as outfile:
                    proc = subprocess.Popen(cmd, stdout=outfile, stderr=subprocess.DEVNULL, text=True)
                    self._register_process(proc)
                    try:
                        proc.wait(timeout=timeout)
                    finally:
                        self._unregister_process(proc)
                self._emit(f"[✓] {label}: {self._count_lines(out)} results")
            except FileNotFoundError:
                self._emit(f"[!] {label} not found — skipping")
                open(out, "w").close()
            except subprocess.TimeoutExpired:
                self._emit(f"[!] {label} timed out")
                proc.terminate()
                open(out, "w").close()
            except Exception as exc:
                self._emit(f"[!] {label} error: {exc}")
                open(out, "w").close()

        _run_tool("amass passive", runner.build_amass_cmd(domain, amass_f), amass_f, timeout=600)
        _run_tool("subfinder",     runner.build_subfinder_cmd(domain, subfinder_f), subfinder_f, timeout=300)
        _run_tool("findomain",     runner.build_findomain_cmd(domain, findomain_f), findomain_f, timeout=300)

        if github_token:
            _run_tool("github-subdomains",
                      runner.build_github_subs_cmd(domain, github_token, github_f), github_f, timeout=300)
        else:
            self._emit("[!] No GitHub token — skipping github-subdomains")
            open(github_f, "w").close()

        # hackertarget (HTTP)
        self._emit("[*] hackertarget API…")
        try:
            subs = runner.fetch_hackertarget(domain)
            with open(hackertarget_f, "w") as f:
                f.write("\n".join(subs))
            self._emit(f"[✓] hackertarget: {len(subs)} subdomains")
        except Exception as exc:
            self._emit(f"[!] hackertarget error: {exc}")
            open(hackertarget_f, "w").close()

        # crt.sh (HTTP)
        self._emit("[*] crt.sh…")
        try:
            subs = runner.fetch_crtsh(domain)
            with open(crt_f, "w") as f:
                f.write("\n".join(subs))
            self._emit(f"[✓] crt.sh: {len(subs)} subdomains")
        except Exception as exc:
            self._emit(f"[!] crt.sh error: {exc}")
            open(crt_f, "w").close()

        # Merge all sources
        all_subs: set = set()
        for fp in [amass_f, subfinder_f, github_f, findomain_f, crt_f, hackertarget_f]:
            try:
                with open(fp) as f:
                    for line in f:
                        s = line.strip()
                        if s and (domain in s):
                            all_subs.add(s.lstrip("*."))
            except Exception:
                pass

        with open(output_file, "w") as f:
            f.write(runner.parse_output(sorted(all_subs), domain))

        # ── Write raw list to shared subdomain dir ────────────────────────────
        shared = self._shared_subdomains_dir(domain)
        passive_raw = os.path.join(shared, "passive_raw.txt")
        try:
            with open(passive_raw, "w") as f:
                for s in sorted(all_subs):
                    f.write(s + "\n")
            self._emit(f"[*] Saved {len(all_subs)} passive subs → {passive_raw}")
        except Exception as e:
            self._emit(f"[!] Could not write passive_raw.txt: {e}")

        self._emit(f"[✓] Total passive subdomains: {len(all_subs)}")
        self._done(True, output_file if self._has_output(output_file) else "",
                   f"{len(all_subs)} subdomains")
        self._merge_and_check_live(passive_raw, "active")
        self._regenerate_domain_report()

    def _run_active_subdomains(self, output_file: str):
        domain = self.task_data["domain"]
        extra_wordlist = self.task_data.get("wordlist", "").strip()

        from tool_runners import ActiveSubdomainsRunner
        runner = ActiveSubdomainsRunner()
        self._status("running", "Brute-forcing subdomains (gobuster dns)…")

        # ── Resolve seclists dir ──────────────────────────────────────────────
        seclists = self.task_data.get("seclists_dir", "")
        if not seclists or not os.path.isdir(seclists):
            seclists = runner.find_seclists()

        default_wl = runner.get_default_wordlist(seclists)
        if not default_wl:
            self._emit("[!] WARNING: Default DNS wordlist not found in SecLists.")
            self._emit(f"    Checked: {runner._SECLISTS_CANDIDATES}")

        # ── Merge wordlists if user supplied an extra one ─────────────────────
        extra_valid = bool(extra_wordlist and os.path.exists(extra_wordlist))
        default_valid = bool(default_wl and os.path.exists(default_wl))

        if extra_valid and default_valid:
            merged_path = os.path.join(self.task_dir, "combined_dns_wordlist.txt")
            self._emit(f"[*] Merging default DNS wordlist with: {extra_wordlist}")
            entries: set = set()
            for wl_path in [default_wl, extra_wordlist]:
                try:
                    with open(wl_path, "r", errors="replace") as f:
                        entries.update(line.strip() for line in f if line.strip())
                except Exception as exc:
                    self._emit(f"[!] Could not read {wl_path}: {exc}")
            with open(merged_path, "w") as f:
                for entry in sorted(entries):
                    f.write(entry + "\n")
            wordlist = merged_path
            self._emit(f"[✓] Combined wordlist: {len(entries)} entries → {merged_path}")
        elif extra_valid:
            wordlist = extra_wordlist
            self._emit(f"[*] Using extra wordlist: {extra_wordlist}")
        elif default_valid:
            wordlist = default_wl
            self._emit(f"[*] Using default DNS wordlist: {default_wl}")
        else:
            wordlist = ""
            self._emit("[!] No wordlist found — gobuster may fail.")

        cmd = runner.build_command(domain, wordlist)
        self._emit(f"[*] Running: gobuster dns -d {domain}")
        ok = self._run_cmd_to_file(cmd, output_file + ".raw", timeout=7200)
        raw = _read_file(output_file + ".raw") if os.path.exists(output_file + ".raw") else ""

        # Extract plain hostnames from gobuster output for the shared raw file
        active_subs = []
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Found:"):
                sub = line.split("Found:", 1)[1].strip()
                if sub:
                    active_subs.append(sub)
            elif line and not line.startswith("["):
                active_subs.append(line)

        # Write formatted output for the task viewer
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))

        # ── Write raw list to shared subdomain dir ────────────────────────────
        shared = self._shared_subdomains_dir(domain)
        active_raw = os.path.join(shared, "active_raw.txt")
        try:
            with open(active_raw, "w") as f:
                for s in sorted(set(active_subs)):
                    f.write(s + "\n")
            self._emit(f"[*] Saved {len(active_subs)} active subs → {active_raw}")
        except Exception as e:
            self._emit(f"[!] Could not write active_raw.txt: {e}")

        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} subdomains found" if ok else "gobuster failed")
        self._merge_and_check_live(active_raw, "passive")
        self._regenerate_domain_report()

    def _run_guess_subdomains(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import AltdnsRunner
        runner = AltdnsRunner()
        self._status("running", "Guessing subdomains (altdns)…")
        # Need a base subdomain list from a previous passive/active task
        passive_out = self._find_best_subdomain_list(domain)
        if not passive_out:
            self._emit("[!] No base subdomain list found — run Passive or Active Subdomains first")
            with open(output_file, "w") as f:
                f.write("No input subdomains — run Passive or Active Subdomains task first.\n")
            self._done(False, "", "no input file")
            return
        tools_dir = self.task_data.get("tools_dir", os.path.expanduser("~/tools"))
        default_words = os.path.join(tools_dir, "altdns-words.txt")
        words_file = self.task_data.get("wordlist") or default_words
        cmd = runner.build_command(domain, passive_out, output_file, words_file)
        self._emit(f"[*] Running: altdns -i {passive_out}")
        ok = self._run_cmd_to_file(cmd, output_file + ".live", timeout=5400)
        if ok and os.path.exists(output_file):
            raw = open(output_file).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} guessed subdomains" if ok else "altdns failed")
        self._regenerate_domain_report()

    def _run_live_subdomains(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import HttpxLiveRunner
        runner = HttpxLiveRunner()
        self._status("running", "Checking live subdomains (httpx)…")
        # Find best available subdomain list
        input_file = self._find_best_subdomain_list(domain)
        if not input_file:
            self._emit("[!] No subdomain list found — run Passive or Active Subdomains first")
            with open(output_file, "w") as f:
                f.write("Run Passive or Active Subdomains task first.\n")
            self._done(False, "", "no input file")
            return
        raw_out = output_file + ".raw"
        cmd = runner.build_command(input_file, raw_out)
        self._emit(f"[*] Running: httpx -l {input_file}")
        ok = self._run_cmd_to_file(cmd, output_file + ".live", timeout=1800)
        raw = open(raw_out).read() if os.path.exists(raw_out) else ""
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} live subdomains" if ok else "httpx failed")
        self._regenerate_domain_report()

    def _run_vhost(self, output_file: str):
        domain = self.task_data["domain"]
        wordlist = self.task_data.get("wordlist", "")
        
        if not wordlist:
            seclists = self.task_data.get("seclists_dir", "")
            if seclists and os.path.exists(seclists):
                wordlist = os.path.join(seclists, "Discovery/DNS/subdomains-top1million-5000.txt")

        from tool_runners import VhostRunner
        runner = VhostRunner()
        self._status("running", "VHost discovery (ffuf)…")
        # Resolve IP first
        try:
            import socket
            ip = socket.gethostbyname(domain)
        except Exception:
            ip = domain
        cmd = runner.build_command(domain, ip, wordlist)
        self._emit(f"[*] Running: ffuf vhost scan for {domain} ({ip})")
        ok = self._run_cmd_to_file(cmd, output_file + ".raw", timeout=5400)
        raw = open(output_file + ".raw").read() if os.path.exists(output_file + ".raw") else ""
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} vhosts found" if ok else "ffuf failed")
        self._regenerate_domain_report()

    def _run_bypass_40x(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import Byp4xxRunner
        runner = Byp4xxRunner()
        self._status("running", "Running 40x bypass (byp4xx)…")
        live_out = self._find_best_subdomain_list(domain)
        if not live_out:
            self._emit("[!] No live subdomains found — run a subdomain enumeration task first")
            with open(output_file, "w") as f:
                f.write("Run a subdomain enumeration task first.\n")
            self._done(False, "", "no input")
            return
        # Extract 40x URLs into a temp file
        import tempfile, re as _re
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tmp:
            with open(live_out) as f:
                for line in f:
                    if _re.search(r'\b40[13]\b', line):
                        url = line.split()[0]
                        tmp.write(url + "\n")
            tmp_path = tmp.name
        cmd = runner.build_command(tmp_path)
        self._emit(f"[*] Running: byp4xx {tmp_path}")
        ok = self._run_cmd_to_file(cmd, output_file + ".raw", timeout=1800)
        raw = open(output_file + ".raw").read() if os.path.exists(output_file + ".raw") else ""
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} bypass results" if ok else "byp4xx failed")
        self._regenerate_domain_report()

    def _run_takeover(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import SubjackRunner
        runner = SubjackRunner()
        self._status("running", "Scanning for subdomain takeovers (subjack)…")
        live_out = self._find_final_subdomain_list(domain)
        if not live_out:
            self._emit("[!] No subdomain list found to check for takeovers")
            with open(output_file, "w") as f:
                f.write("Run a subdomain enumeration task first.\n")
            self._done(False, "", "no input")
            return
        cmd = runner.build_command(live_out)
        self._emit(f"[*] Running: subjack -w {live_out}")
        ok = self._run_cmd_to_file(cmd, output_file + ".raw", timeout=1800)
        raw = open(output_file + ".raw").read() if os.path.exists(output_file + ".raw") else ""
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} results (check output)" if ok else "subjack failed")
        self._regenerate_domain_report()

    def _run_service_scan(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import SmapRunner
        runner = SmapRunner()
        self._status("running", "Port scanning all subdomains (smap)…")
        live_out = self._find_final_subdomain_list(domain)
        if not live_out:
            self._emit("[!] No subdomain list found to scan")
            with open(output_file, "w") as f:
                f.write("Run a subdomain enumeration task first.\n")
            self._done(False, "", "no input")
            return
        out_base = os.path.join(self.task_dir, "smap")
        cmd = runner.build_command(live_out, out_base)
        self._emit(f"[*] Running: smap -iL {live_out}")
        ok = self._run_cmd_to_file(cmd, output_file, timeout=1800)
        nmap_file = out_base + ".nmap"
        if os.path.exists(nmap_file):
            raw = open(nmap_file).read()
            with open(output_file, "w") as f:
                f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} lines" if ok else "smap failed")
        self._regenerate_domain_report()

    def _run_cloud_enum(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import CloudEnumRunner
        runner = CloudEnumRunner()
        self._status("running", "Enumerating cloud assets (cloud_enum)…")
        cmd = runner.build_command(domain, output_file + ".raw")
        self._emit(f"[*] Running: cloud_enum -k {domain.split('.')[0]}")
        ok = self._run_cmd_to_file(cmd, output_file + ".live", timeout=600)
        raw = open(output_file + ".raw").read() if os.path.exists(output_file + ".raw") else ""
        with open(output_file, "w") as f:
            f.write(runner.parse_output(raw))
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   f"{n} cloud assets" if ok else "cloud_enum failed")
        self._regenerate_domain_report()

    def _run_screenshot(self, output_file: str):
        domain = self.task_data["domain"]
        from tool_runners import EyewitnessRunner
        runner = EyewitnessRunner()
        self._status("running", "Taking screenshots (eyewitness)…")
        live_out = self._find_final_subdomain_list(domain)
        if not live_out:
            self._emit("[!] No subdomain list found to screenshot")
            with open(output_file, "w") as f:
                f.write("Run a subdomain enumeration task first.\n")
            self._done(False, "", "no input")
            return
        scr_dir = os.path.join(self.task_dir, "screenshot_report")
        os.makedirs(scr_dir, exist_ok=True)
        cmd = runner.build_command(live_out, scr_dir)
        self._emit(f"[*] Running: eyewitness -f {live_out} -d {scr_dir}")
        ok = self._run_cmd_to_file(cmd, output_file, timeout=1800)
        n = self._count_lines(output_file)
        self._done(ok, output_file if self._has_output(output_file) else "",
                   "Screenshots done" if ok else "eyewitness failed")
        self._regenerate_domain_report()

# ─────────────────────────────────────────────────────────────────────────────
# Task Input Dialog
# ─────────────────────────────────────────────────────────────────────────────

# Cookie Prompt Dialog
# ─────────────────────────────────────────────────────────────────────────────

class CookiePromptDialog(QDialog):
    """Prompt user when a login cookie is auto-detected."""

    USE_COOKIE  = 1
    CHANGE      = 2
    NO_COOKIE   = 3

    def __init__(self, cookie_value: str, source_url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🍪 Login Cookie Detected")
        self.setMinimumWidth(580)
        self.choice = self.NO_COOKIE
        self.final_cookie = cookie_value

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        info = QLabel(
            f"<b>A session cookie was detected from a successful login request.</b><br>"
            f"<span style='color:{COLOR_TEXT_MUTED};font-size:{FONT_SIZE_SMALL};'>Source: {source_url[:80]}</span>"
        )
        info.setWordWrap(True)
        info.setStyleSheet(f"color:{COLOR_TEXT_BRIGHT}; padding:8px; "
                           f"background-color:{COLOR_CARD_BG}; border-radius:4px;")
        layout.addWidget(info)

        cookie_label = QLabel("Detected Cookie:")
        cookie_label.setStyleSheet(f"color:{COLOR_ACCENT}; font-weight:bold;")
        layout.addWidget(cookie_label)

        self.cookie_edit = QTextEdit()
        self.cookie_edit.setPlainText(cookie_value)
        self.cookie_edit.setMaximumHeight(80)
        self.cookie_edit.setFont(QFont(FONT_FAMILY_MONO, 9))
        self.cookie_edit.setStyleSheet(
            f"background-color:{COLOR_DARK_BG}; color:{COLOR_TEXT_BRIGHT}; "
            f"border:1px solid {COLOR_BORDER}; font-family:{FONT_FAMILY_MONO};"
        )
        layout.addWidget(self.cookie_edit)

        btn_layout = QHBoxLayout()

        use_btn = QPushButton("✅ Use this Cookie")
        use_btn.setStyleSheet(f"background-color:{COLOR_SUCCESS}; color:black; font-weight:bold; padding:6px 14px;")
        use_btn.clicked.connect(lambda: self._done(self.USE_COOKIE))
        btn_layout.addWidget(use_btn)

        change_btn = QPushButton("✏️ Edit & Use")
        change_btn.setStyleSheet(f"background-color:{COLOR_ELEVATED_BG}; color:{COLOR_TEXT_BRIGHT}; "
                                 f"border:1px solid {COLOR_BORDER}; padding:6px 14px;")
        change_btn.clicked.connect(lambda: self._done(self.CHANGE))
        btn_layout.addWidget(change_btn)

        skip_btn = QPushButton("🚫 Don't Use Cookie")
        skip_btn.setStyleSheet(f"background-color:{COLOR_ELEVATED_BG}; color:{COLOR_CRITICAL}; "
                               f"border:1px solid {COLOR_CRITICAL}; padding:6px 14px;")
        skip_btn.clicked.connect(lambda: self._done(self.NO_COOKIE))
        btn_layout.addWidget(skip_btn)

        layout.addLayout(btn_layout)

    def _done(self, choice: int):
        self.choice = choice
        self.final_cookie = self.cookie_edit.toPlainText().strip()
        self.accept()



# ─────────────────────────────────────────────────────────────────────────────
# Multi-Task Orchestrator
# Runs groups of tasks in sequence; tasks within a group run in parallel.
# ─────────────────────────────────────────────────────────────────────────────

class MultiTaskOrchestrator(QObject):
    """
    Executes a multi-task plan:
      plan = {
        "id":     str,
        "name":   str,
        "target": str,       # domain / subdomain label (informational)
        "groups": [          # ordered list of groups
          [task_config, ...]  # each config is passed straight to DashboardTab.add_task()
        ]
      }

    Lifecycle signals:
      plan_started(plan_id)
      group_started(plan_id, group_index, total_groups)
      task_launched(plan_id, task_id)
      group_done(plan_id, group_index)
      plan_done(plan_id, success)
      log(plan_id, message)
    """

    plan_started   = pyqtSignal(str)
    group_started  = pyqtSignal(str, int, int)   # plan_id, gi, total
    task_launched  = pyqtSignal(str, str)         # plan_id, task_id
    group_done     = pyqtSignal(str, int)         # plan_id, gi
    plan_done      = pyqtSignal(str, bool)        # plan_id, success
    log            = pyqtSignal(str, str)         # plan_id, message

    def __init__(self, plan: dict, dashboard_tab, parent=None):
        super().__init__(parent)
        self._plan      = plan
        self._tab       = dashboard_tab
        self._plan_id   = plan["id"]
        self._groups    = plan["groups"]           # list[list[config]]
        self._gi        = 0                        # current group index
        self._pending   = set()                    # task_ids still running in current group
        self._stopped   = False
        self._any_error = False

    # ── public ──────────────────────────────────────────────────────────────

    def start(self):
        self.plan_started.emit(self._plan_id)
        self.log.emit(self._plan_id,
            f"▶ Plan '{self._plan['name']}' started — "
            f"{len(self._groups)} group(s), "
            f"{sum(len(g) for g in self._groups)} task(s) total")
        self._launch_group(0)

    def stop(self):
        self._stopped = True

    # ── private ─────────────────────────────────────────────────────────────

    def _launch_group(self, gi: int):
        if self._stopped:
            self.plan_done.emit(self._plan_id, False)
            return
        if gi >= len(self._groups):
            self.log.emit(self._plan_id,
                f"✅ Plan '{self._plan['name']}' complete — all {len(self._groups)} group(s) done")
            self.plan_done.emit(self._plan_id, not self._any_error)
            return

        self._gi = gi
        group    = self._groups[gi]
        total    = len(self._groups)
        self.group_started.emit(self._plan_id, gi, total)
        self.log.emit(self._plan_id,
            f"⚡ Group {gi+1}/{total}: launching {len(group)} task(s) in parallel")

        if not group:
            # empty group — skip immediately
            self.group_done.emit(self._plan_id, gi)
            self._launch_group(gi + 1)
            return

        self._pending.clear()

        for config in group:
            task_id = self._tab.add_task(config, return_id=True)
            if task_id:
                self._pending.add(task_id)
                self.task_launched.emit(self._plan_id, task_id)
                # Hook into completion — use a closure to capture task_id
                self._hook_task(task_id)

    def _hook_task(self, task_id: str):
        """Connect to the worker's task_completed signal for this task."""
        worker = self._tab.task_workers.get(task_id)
        if worker:
            worker.task_completed.connect(
                lambda tid, ok, f, _tid=task_id: self._on_task_done(_tid, ok)
            )
        else:
            # Worker not found (shouldn't happen) — treat as done
            QTimer.singleShot(100, lambda: self._on_task_done(task_id, False))

    def _on_task_done(self, task_id: str, success: bool):
        if not success:
            self._any_error = True
        self._pending.discard(task_id)
        self.log.emit(self._plan_id,
            f"  {'✓' if success else '✗'} task {task_id[:32]} {'done' if success else 'failed'}")
        if not self._pending:
            # All tasks in group done → advance
            gi = self._gi
            self.group_done.emit(self._plan_id, gi)
            self.log.emit(self._plan_id,
                f"  Group {gi+1} complete — {'proceeding to next group' if gi+1 < len(self._groups) else 'final group done'}")
            QTimer.singleShot(200, lambda: self._launch_group(gi + 1))


# ─────────────────────────────────────────────────────────────────────────────
# Multi-Task Plan Builder Dialog
# ─────────────────────────────────────────────────────────────────────────────

# All domain-level tool options (label → tool_key)
_DOMAIN_TOOLS = [
    (" Whois Lookup",                                       "whois"),
    (" Google Dorks (dorks_hunter)",                        "google_dorks"),
    (" GitHub Dorks (gitdorks_go)",                        "github_dorks"),
    (" GitHub Secrets (trufflehog)",                       "github_secrets"),
    (" Email Discovery (emailfinder)",                     "emails"),
    (" Metadata Finder (metafinder)",                      "metadata"),
    (" Passive Subdomains (amass+subfinder+crt.sh)",       "passive_subdomains"),
    (" Active Brute-Force (gobuster dns)",                 "active_subdomains"),
    (" Guess Subdomains (altdns)",                         "guess_subdomains"),
    (" VHost Discovery (ffuf)",                            "vhost"),
    (" 40x Bypass (byp4xx)",                              "bypass_40x"),
    (" Subdomain Takeover (subjack)",                     "takeover"),
    (" Service Scan (smap)",                              "service_scan"),
    (" Cloud Enum (cloud_enum)",                          "cloud_enum"),
    (" Screenshots (eyewitness)",                         "screenshot"),
]

# All subdomain-level tool options (label → tool_key)
_SUBDOMAIN_TOOLS = [
    (" Spider (gospider+cariddi+katana+linkfinder+paramspider)", "spider"),
    (" Web Archive (wayback+gau+waymore)",                 "archive"),
    (" IP Info",                                           "ipinfo"),
    (" HTTP Headers",                                      "headers"),
    (" Tech Detection (wad)",                             "tech"),
    (" WAF Detection (wafw00f)",                          "waf"),
    (" CMS Detection (cmseek)",                           "cms"),
    (" Port Scan (nmap)",                                 "ports"),
    (" Content Bruteforce (feroxbuster)",                 "bruteforce"),
    (" Nuclei (all templates)",                           "nuclei"),
    (" Nikto",                                            "nikto"),
    (" WPScan (WordPress)",                               "wpscan"),
    (" JoomScan (Joomla)",                               "joomscan"),
    (" Droopescan (Drupal)",                             "droopescan"),
    (" 4th-Level Subdomains",                            "subdomains4"),
]

_PLAN_COUNTER = [0]   # mutable counter to give unique plan ids


class MultiTaskDialog(QDialog):
    """
    Visual plan builder.

    Layout:
    ┌──────────────────────────────────────────────────────────────────┐
    │  Plan name: [_________]    Target: [combo]                       │
    ├──────────────────────────────────────────────────────────────────┤
    │  Available Tasks          │  Groups (drag to reorder)            │
    │  [search filter]          │  [+ Add Group]  [▲][▼] [✕]          │
    │  ┌─────────────┐          │  ┌───────────────────────────────┐   │
    │  │ □ Task A    │ ──Add──► │  │  GROUP 1        [rename][del] │   │
    │  │ □ Task B    │          │  │    ◉ Task A                   │   │
    │  │ □ Task C    │          │  │    ◉ Task B      [✕]          │   │
    │  │  ...        │          │  ├───────────────────────────────┤   │
    │  └─────────────┘          │  │  GROUP 2                      │   │
    │                           │  │    ◉ Task C      [✕]          │   │
    │                           │  └───────────────────────────────┘   │
    ├──────────────────────────────────────────────────────────────────┤
    │              [Cancel]  [▶ Run Plan]                              │
    └──────────────────────────────────────────────────────────────────┘
    """

    MENU_STYLE = (
        f"QMenu{{background-color:{COLOR_DARK_BG};color:{COLOR_TEXT};"
        f"border:1px solid {COLOR_BORDER};padding:4px;}}"
        f"QMenu::item{{padding:5px 16px;}}"
        f"QMenu::item:selected{{background-color:{COLOR_ACCENT};color:black;}}"
    )

    def __init__(self, dashboard_tab, default_target: str = "", parent=None):
        super().__init__(parent)
        self._tab = dashboard_tab
        self.setWindowTitle("⚡ Multi-Task Plan Builder")
        self.setMinimumSize(900, 640)
        self.setStyleSheet(
            f"QDialog{{background-color:{COLOR_DARK_BG};color:{COLOR_TEXT};}}"
            f"QLabel{{color:{COLOR_TEXT};}}"
            f"QGroupBox{{color:{COLOR_ACCENT};border:1px solid {COLOR_BORDER};border-radius:4px;margin-top:8px;padding-top:8px;}}"
            f"QGroupBox::title{{subcontrol-origin:margin;left:8px;}}"
            f"QScrollArea{{border:none;background:{COLOR_BACKGROUND};}}"
            f"QListWidget{{background:{COLOR_BACKGROUND};border:1px solid {COLOR_BORDER};color:{COLOR_TEXT};}}"
            f"QListWidget::item{{padding:4px 6px;}}"
            f"QListWidget::item:selected{{background:{COLOR_ACCENT};color:black;}}"
            f"QLineEdit{{background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};color:{COLOR_TEXT};padding:4px;}}"
            f"QComboBox{{background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};color:{COLOR_TEXT};padding:4px;}}"
            f"QPushButton{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};border:1px solid {COLOR_BORDER};padding:5px 10px;border-radius:3px;}}"
            f"QPushButton:hover{{background:{COLOR_HOVER};}}"
        )

        # groups: list of { "name": str, "tasks": [{"label":str,"tool":str}] }
        self._groups: List[Dict] = []
        self._selected_group: int = -1

        self._setup_ui(default_target)

    # ── UI ──────────────────────────────────────────────────────────────────

    def _setup_ui(self, default_target: str):
        root = QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(14, 14, 14, 14)

        # ── top bar: plan name + target ──────────────────────────────────────
        top = QHBoxLayout()
        top.addWidget(QLabel("Plan name:"))
        self._plan_name = QLineEdit("My Plan")
        self._plan_name.setMaximumWidth(200)
        top.addWidget(self._plan_name)
        top.addSpacing(20)
        top.addWidget(QLabel("Target:"))
        self._target_combo = QComboBox()
        self._target_combo.setEditable(True)
        self._target_combo.setMinimumWidth(220)
        # populate from dashboard domains + subdomains
        all_targets = (
            list(self._tab.domain_widgets.keys()) +
            list(self._tab.subdomain_widgets.keys())
        )
        for t in sorted(set(all_targets)):
            self._target_combo.addItem(t)
        if default_target:
            idx = self._target_combo.findText(default_target)
            if idx >= 0:
                self._target_combo.setCurrentIndex(idx)
            else:
                self._target_combo.setCurrentText(default_target)
        self._target_combo.currentTextChanged.connect(self._on_target_changed)
        top.addWidget(self._target_combo)
        top.addStretch()
        root.addLayout(top)

        # ── main splitter ────────────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setHandleWidth(6)
        splitter.setStyleSheet(
            f"QSplitter::handle{{background:{COLOR_BORDER};}}"
            f"QSplitter::handle:hover{{background:{COLOR_ACCENT};}}"
        )

        # ── LEFT: task palette ───────────────────────────────────────────────
        left_w = QWidget()
        left_l = QVBoxLayout(left_w)
        left_l.setContentsMargins(0, 0, 0, 0)

        pal_grp = QGroupBox("Available Tasks")
        pal_grp.setMinimumWidth(310)
        pal_l = QVBoxLayout(pal_grp)

        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍 Filter tasks…")
        self._search.textChanged.connect(self._filter_palette)
        pal_l.addWidget(self._search)

        # Target-type toggle
        type_row = QHBoxLayout()
        self._type_domain_btn = QPushButton("🌍 Domain Tasks")
        self._type_subdomain_btn = QPushButton("🌐 Subdomain Tasks")
        for btn in (self._type_domain_btn, self._type_subdomain_btn):
            btn.setCheckable(True)
            btn.setStyleSheet(
                f"QPushButton{{background:{COLOR_ELEVATED_BG};border:1px solid {COLOR_BORDER};padding:4px 8px;}}"
                f"QPushButton:checked{{background:{COLOR_ACCENT};color:black;border-color:{COLOR_ACCENT};}}"
            )
            type_row.addWidget(btn)
        self._type_domain_btn.setChecked(True)
        self._type_domain_btn.clicked.connect(lambda: self._set_task_type("domain"))
        self._type_subdomain_btn.clicked.connect(lambda: self._set_task_type("subdomain"))
        pal_l.addLayout(type_row)

        self._palette_list = QListWidget()
        self._palette_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self._palette_list.setDragEnabled(False)
        pal_l.addWidget(self._palette_list)

        # add-to-group button row
        add_row = QHBoxLayout()
        self._add_to_group_btn = QPushButton("➕ Add to Selected Group")
        self._add_to_group_btn.clicked.connect(self._add_selected_to_group)
        self._add_to_group_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:black;font-weight:bold;padding:6px 12px;}}"
            f"QPushButton:hover{{background:#00FF8C;}}"
        )
        add_row.addWidget(self._add_to_group_btn)
        pal_l.addLayout(add_row)

        left_l.addWidget(pal_grp)
        splitter.addWidget(left_w)

        # ── RIGHT: groups builder ────────────────────────────────────────────
        right_w = QWidget()
        right_l = QVBoxLayout(right_w)
        right_l.setContentsMargins(0, 0, 0, 0)

        grp_top = QHBoxLayout()
        grp_top.addWidget(QLabel("Execution Groups"))
        grp_top.addStretch()

        self._add_group_btn = QPushButton("➕ Add Group")
        self._add_group_btn.clicked.connect(self._add_group)
        self._add_group_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_ACCENT};color:black;font-weight:bold;padding:5px 10px;}}"
            f"QPushButton:hover{{background:#88ee88;}}"
        )
        grp_top.addWidget(self._add_group_btn)

        self._move_up_btn = QPushButton("▲")
        self._move_up_btn.setMaximumWidth(32)
        self._move_up_btn.setToolTip("Move selected group up")
        self._move_up_btn.clicked.connect(lambda: self._move_group(-1))
        grp_top.addWidget(self._move_up_btn)

        self._move_dn_btn = QPushButton("▼")
        self._move_dn_btn.setMaximumWidth(32)
        self._move_dn_btn.setToolTip("Move selected group down")
        self._move_dn_btn.clicked.connect(lambda: self._move_group(1))
        grp_top.addWidget(self._move_dn_btn)

        self._del_group_btn = QPushButton("✕ Del Group")
        self._del_group_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_CRITICAL};color:white;padding:5px 8px;}}"
            f"QPushButton:hover{{background:#cc2222;}}"
        )
        self._del_group_btn.clicked.connect(self._delete_selected_group)
        grp_top.addWidget(self._del_group_btn)

        right_l.addLayout(grp_top)

        # Scroll area for group panels
        self._groups_scroll = QScrollArea()
        self._groups_scroll.setWidgetResizable(True)
        self._groups_container = QWidget()
        self._groups_container.setStyleSheet(f"background:{COLOR_BACKGROUND};")
        self._groups_vbox = QVBoxLayout(self._groups_container)
        self._groups_vbox.setContentsMargins(6, 6, 6, 6)
        self._groups_vbox.setSpacing(8)
        self._groups_vbox.addStretch()
        self._groups_scroll.setWidget(self._groups_container)
        right_l.addWidget(self._groups_scroll)

        # execution info label
        self._info_label = QLabel("")
        self._info_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:{FONT_SIZE_SMALL};")
        right_l.addWidget(self._info_label)

        splitter.addWidget(right_w)
        splitter.setSizes([340, 540])
        root.addWidget(splitter, 1)

        # ── buttons ──────────────────────────────────────────────────────────
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        self._run_btn = QPushButton("▶ Run Plan")
        self._run_btn.setStyleSheet(
            f"QPushButton{{background:{COLOR_SUCCESS};color:black;font-weight:bold;padding:7px 20px;font-size:11pt;}}"
            f"QPushButton:hover{{background:#00FF8C;}}"
        )
        self._run_btn.clicked.connect(self._on_run)
        btn_row.addWidget(self._run_btn)
        root.addLayout(btn_row)

        # Init palette with domain tasks
        self._current_task_type = "domain"
        self._rebuild_palette()

        # Start with one group
        self._add_group()

    # ── palette ─────────────────────────────────────────────────────────────

    def _set_task_type(self, t: str):
        self._current_task_type = t
        self._type_domain_btn.setChecked(t == "domain")
        self._type_subdomain_btn.setChecked(t == "subdomain")
        self._rebuild_palette()

    def _rebuild_palette(self):
        self._palette_list.clear()
        tools = _DOMAIN_TOOLS if self._current_task_type == "domain" else _SUBDOMAIN_TOOLS
        q = self._search.text().strip().lower()
        for label, key in tools:
            if q and q not in label.lower() and q not in key.lower():
                continue
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            self._palette_list.addItem(item)

    def _filter_palette(self, _=None):
        self._rebuild_palette()

    def _on_target_changed(self, target: str):
        # Auto-switch task type based on whether target is a domain or subdomain
        if target in self._tab.domain_widgets:
            self._set_task_type("domain")
        elif target in self._tab.subdomain_widgets:
            self._set_task_type("subdomain")

    # ── groups ───────────────────────────────────────────────────────────────

    def _add_group(self):
        idx = len(self._groups)
        name = f"Group {idx + 1}"
        self._groups.append({"name": name, "tasks": []})
        self._rebuild_groups_ui()
        self._select_group(idx)

    def _select_group(self, idx: int):
        self._selected_group = idx
        self._rebuild_groups_ui()

    def _move_group(self, direction: int):
        gi = self._selected_group
        new_gi = gi + direction
        if gi < 0 or new_gi < 0 or new_gi >= len(self._groups):
            return
        self._groups[gi], self._groups[new_gi] = self._groups[new_gi], self._groups[gi]
        self._selected_group = new_gi
        self._rebuild_groups_ui()

    def _delete_selected_group(self):
        gi = self._selected_group
        if gi < 0 or gi >= len(self._groups):
            return
        del self._groups[gi]
        self._selected_group = max(0, gi - 1) if self._groups else -1
        self._rebuild_groups_ui()

    def _add_selected_to_group(self):
        gi = self._selected_group
        if gi < 0 or gi >= len(self._groups):
            QMessageBox.warning(self, "No Group", "Select a group first (click its header).")
            return
        selected = self._palette_list.selectedItems()
        if not selected:
            QMessageBox.warning(self, "Nothing Selected", "Select one or more tasks from the list.")
            return
        for item in selected:
            label = item.text()
            tool  = item.data(Qt.UserRole)
            # Allow duplicates (user may want same tool for different reasons)
            self._groups[gi]["tasks"].append({
                "label": label,
                "tool": tool,
                "task_type": self._current_task_type,
            })
        self._rebuild_groups_ui()
        self._update_info()

    def _remove_task_from_group(self, gi: int, ti: int):
        if 0 <= gi < len(self._groups) and 0 <= ti < len(self._groups[gi]["tasks"]):
            del self._groups[gi]["tasks"][ti]
            self._rebuild_groups_ui()
            self._update_info()

    def _move_task_in_group(self, gi: int, ti: int, direction: int):
        tasks = self._groups[gi]["tasks"]
        new_ti = ti + direction
        if 0 <= new_ti < len(tasks):
            tasks[ti], tasks[new_ti] = tasks[new_ti], tasks[ti]
            self._rebuild_groups_ui()

    def _rebuild_groups_ui(self):
        """Tear down and rebuild all group panels."""
        # Remove all widgets except the stretch at the end
        while self._groups_vbox.count() > 1:
            item = self._groups_vbox.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        for gi, grp in enumerate(self._groups):
            panel = self._build_group_panel(gi, grp)
            self._groups_vbox.insertWidget(gi, panel)

        self._update_info()

    def _build_group_panel(self, gi: int, grp: dict) -> QWidget:
        is_selected = gi == self._selected_group

        panel = QFrame()
        panel.setFrameShape(QFrame.StyledPanel)
        accent = COLOR_ACCENT if is_selected else COLOR_BORDER
        panel.setStyleSheet(
            f"QFrame{{background:{COLOR_CARD_BG};border:2px solid {accent};border-radius:6px;}}"
        )

        pl = QVBoxLayout(panel)
        pl.setContentsMargins(8, 6, 8, 6)
        pl.setSpacing(4)

        # Header row
        hdr = QHBoxLayout()

        # Click on panel to select it
        panel.mousePressEvent = lambda e, g=gi: self._select_group(g)

        sel_indicator = QLabel("●" if is_selected else "○")
        sel_indicator.setStyleSheet(f"color:{COLOR_ACCENT};font-size:14pt;")
        hdr.addWidget(sel_indicator)

        # Editable group name
        name_edit = QLineEdit(grp["name"])
        name_edit.setStyleSheet(
            f"QLineEdit{{background:transparent;border:none;color:{COLOR_TEXT_BRIGHT};"
            f"font-weight:bold;font-size:11pt;padding:0;}}"
        )
        name_edit.setMaximumWidth(200)
        name_edit.editingFinished.connect(
            lambda g=gi, e=name_edit: self._rename_group(g, e.text())
        )
        hdr.addWidget(name_edit)

        badge_lbl = QLabel(f"({len(grp['tasks'])} task{'s' if len(grp['tasks'])!=1 else ''})")
        badge_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:{FONT_SIZE_SMALL};")
        hdr.addWidget(badge_lbl)

        parallel_lbl = QLabel("⚡ parallel")
        parallel_lbl.setStyleSheet(f"color:{COLOR_SUCCESS};font-size:{FONT_SIZE_SMALL};")
        hdr.addWidget(parallel_lbl)

        hdr.addStretch()
        pl.addLayout(hdr)

        # Task rows
        if not grp["tasks"]:
            empty = QLabel("  (drop tasks here — select group then click ➕ Add)")
            empty.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-style:italic;font-size:{FONT_SIZE_SMALL};padding:4px;")
            pl.addWidget(empty)
        else:
            for ti, task in enumerate(grp["tasks"]):
                trow = QHBoxLayout()
                trow.setSpacing(4)

                order_lbl = QLabel(f"{ti+1}.")
                order_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED};min-width:18px;")
                trow.addWidget(order_lbl)

                task_lbl = QLabel(task["label"])
                task_lbl.setStyleSheet(f"color:{COLOR_TEXT};")
                trow.addWidget(task_lbl, 1)

                # move up/down within group
                up_btn = QPushButton("↑")
                up_btn.setMaximumWidth(24)
                up_btn.setMaximumHeight(22)
                up_btn.setStyleSheet(f"QPushButton{{padding:0;font-size:10pt;border:1px solid {COLOR_BORDER};}}")
                up_btn.clicked.connect(
                    lambda _, g=gi, t=ti: self._move_task_in_group(g, t, -1)
                )
                trow.addWidget(up_btn)

                dn_btn = QPushButton("↓")
                dn_btn.setMaximumWidth(24)
                dn_btn.setMaximumHeight(22)
                dn_btn.setStyleSheet(f"QPushButton{{padding:0;font-size:10pt;border:1px solid {COLOR_BORDER};}}")
                dn_btn.clicked.connect(
                    lambda _, g=gi, t=ti: self._move_task_in_group(g, t, 1)
                )
                trow.addWidget(dn_btn)

                rm_btn = QPushButton("✕")
                rm_btn.setMaximumWidth(24)
                rm_btn.setMaximumHeight(22)
                rm_btn.setStyleSheet(
                    f"QPushButton{{padding:0;color:{COLOR_CRITICAL};border:1px solid {COLOR_BORDER};}}"
                    f"QPushButton:hover{{background:{COLOR_CRITICAL};color:white;}}"
                )
                rm_btn.clicked.connect(
                    lambda _, g=gi, t=ti: self._remove_task_from_group(g, t)
                )
                trow.addWidget(rm_btn)

                pl.addLayout(trow)

        return panel

    def _rename_group(self, gi: int, name: str):
        if 0 <= gi < len(self._groups):
            self._groups[gi]["name"] = name or f"Group {gi+1}"

    def _update_info(self):
        total_tasks  = sum(len(g["tasks"]) for g in self._groups)
        total_groups = len(self._groups)
        if total_groups == 0:
            self._info_label.setText("No groups yet.")
        else:
            self._info_label.setText(
                f"{total_groups} group(s) · {total_tasks} task(s) total  "
                f"| Groups run sequentially, tasks within each group run in parallel"
            )

    # ── run ──────────────────────────────────────────────────────────────────

    def _on_run(self):
        target = self._target_combo.currentText().strip()
        if not target:
            QMessageBox.warning(self, "No Target", "Please select or enter a target.")
            return
        if not self._groups or all(not g["tasks"] for g in self._groups):
            QMessageBox.warning(self, "No Tasks", "Add at least one task to a group.")
            return

        plan_name = self._plan_name.text().strip() or "Plan"
        _PLAN_COUNTER[0] += 1
        plan_id = f"plan_{_PLAN_COUNTER[0]}_{int(time.time())}"

        # Build groups of task configs
        groups_configs = []
        for grp in self._groups:
            group_cfgs = []
            for task in grp["tasks"]:
                cfg = {
                    "domain": target,
                    "tool":   task["tool"],
                }
                group_cfgs.append(cfg)
            if group_cfgs:
                groups_configs.append(group_cfgs)

        plan = {
            "id":     plan_id,
            "name":   plan_name,
            "target": target,
            "groups": groups_configs,
        }

        self.accept()
        self._tab.run_multi_task_plan(plan)

    def get_plan(self) -> Optional[dict]:
        """Returns the built plan (used if caller wants it instead of auto-run)."""
        return None  # auto-run via _on_run


class TaskInputDialog(QDialog):
    """Dialog for task configuration (cookie, proxy, etc.)"""

    def __init__(self, domain: str, tool_name: str, parent=None, main_window=None,
                 prefill_cookie: str = ""):
        super().__init__(parent)
        self.domain = domain
        self.tool_name = tool_name
        self.main_window = main_window
        self._sc_checkboxes: Dict[int, QCheckBox] = {}   # populated in _setup_ui for spider/archive/bruteforce
        self.setWindowTitle(f"Configure {tool_name} — {domain}")
        self.setMinimumWidth(540)
        # Cap height so the dialog never exceeds the available screen space
        screen = QApplication.primaryScreen()
        if screen:
            avail_h = screen.availableGeometry().height()
            self.setMaximumHeight(int(avail_h * 0.90))
        self._setup_ui(prefill_cookie)

    def _setup_ui(self, prefill_cookie: str):
        # Outer layout: scroll area on top, fixed button row at the bottom
        outer_layout = QVBoxLayout(self)
        outer_layout.setSpacing(0)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        scroll_content = QWidget()
        scroll_content.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(scroll_content)
        layout.setSpacing(12)
        layout.setContentsMargins(12, 12, 12, 4)

        scroll.setWidget(scroll_content)
        outer_layout.addWidget(scroll, stretch=1)

        # ── Tool info banner ─────────────────────────────────────────────────
        TOOL_INFO = {
            "spider":      ("🕷️", "gospider + cariddi + katana + linkfinder + paramspider → sitemap.xml → httpx validation"),
            "archive":     ("🗄️", "waybackurls + waymore + gau + gauplus + github-endpoints → uro → httpx"),
            "ipinfo":      ("📍", "IP geolocation & ASN info via ipinfo CLI"),
            "headers":     ("📋", "HTTP response headers via curl -I"),
            "tech":        ("🔬", "Technology fingerprinting via wad"),
            "waf":         ("🛡️", "WAF detection via wafw00f"),
            "cms":         ("📰", "CMS detection via cmseek"),
            "ports":       ("🔌", "Top-1000 port scan with service/version detection (nmap)"),
            "bruteforce":  ("📂", "Smart content bruteforce with tech-aware wordlists (feroxbuster)"),
            "nuclei":      ("☢️", "Vulnerability scan with Nuclei templates"),
            "nikto":       ("🔎", "Web server misconfiguration scanner (nikto)"),
            # Domain-level tools
            "whois":             ("📋", "Whois domain registration info"),
            "google_dorks":      ("🔎", "Google dork search URLs (dorks_hunter)"),
            "github_dorks":      ("🐙", "GitHub secret/code search (gitdorks_go)"),
            "github_secrets":    ("🔑", "Verified secrets scanner (trufflehog)"),
            "emails":            ("📧", "Email discovery (emailfinder)"),
            "metadata":          ("📄", "Document metadata extraction (metafinder)"),
            "passive_subdomains":("🌿", "Passive enum: amass+subfinder+crt.sh+findomain+hackertarget"),
            "active_subdomains": ("💥", "DNS brute-force (gobuster dns)"),
            "guess_subdomains":  ("🔀", "Permutation guessing (altdns) — needs passive subs first"),
            "vhost":             ("🏠", "Virtual host discovery (ffuf)"),
            "bypass_40x":        ("🔓", "Bypass 401/403 responses (byp4xx)"),
            "takeover":          ("🎯", "Subdomain takeover detection (subjack)"),
            "service_scan":      ("🔌", "Port + service scan across all subdomains (smap)"),
            "cloud_enum":        ("☁️", "Cloud asset enumeration (cloud_enum)"),
            "screenshot":        ("📸", "Screenshot all live subdomains (eyewitness)"),
            "wpscan":      ("🔷", "WordPress vulnerability scanner"),
            "joomscan":    ("🟠", "Joomla vulnerability scanner"),
            "droopescan":  ("🟣", "Drupal vulnerability scanner"),
            "subdomains4": ("🌿", "Passive 4th-level subdomain enum: amass + subfinder + crt.sh + findomain + github"),
        }
        tool_lc = self.tool_name.lower()
        icon, desc = TOOL_INFO.get(tool_lc, ("🔧", self.tool_name))
        banner = QLabel(
            f"<b style='font-size:12pt'>{icon} {self.tool_name.title()}</b><br>"
            f"<span style='color:{COLOR_TEXT_MUTED}'>{desc}</span><br>"
            f"<span style='color:{COLOR_ACCENT}'>Target: {self.domain}</span>"
        )
        banner.setStyleSheet(
            f"color:{COLOR_TEXT_BRIGHT}; padding:10px; background-color:{COLOR_CARD_BG}; border-radius:6px;"
        )
        banner.setWordWrap(True)
        layout.addWidget(banner)

        # ── Authentication Headers ────────────────────────────────────────────
        NEEDS_COOKIE = {"spider","archive","headers","bruteforce","nuclei","wpscan","joomscan"}
        NEEDS_GITHUB_TOKEN = {"github_dorks","github_secrets","passive_subdomains"}

        # Presets: (label, header_name, header_value_template)
        _AUTH_PRESETS = [
            ("Cookie",                        "Cookie",          ""),
            ("Authorization: Bearer <token>", "Authorization",   "Bearer "),
            ("Authorization: Basic <base64>", "Authorization",   "Basic "),
            ("X-API-Key",                     "X-Api-Key",       ""),
            ("X-Auth-Token",                  "X-Auth-Token",    ""),
            ("X-Access-Token",                "X-Access-Token",  ""),
            ("X-Forwarded-For: 127.0.0.1",   "X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP: 127.0.0.1",         "X-Real-IP",       "127.0.0.1"),
            ("Referer",                       "Referer",         f"https://{self.domain}/"),
            ("Origin",                        "Origin",          f"https://{self.domain}"),
            ("Custom header…",               "",                ""),
        ]

        if tool_lc in NEEDS_COOKIE:
            auth_group = QGroupBox("Authentication Headers (optional)")
            auth_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            auth_layout = QVBoxLayout(auth_group)

            # Info label
            info_lbl = QLabel(
                "Add any HTTP headers sent with each request — Cookie, Authorization, "
                "X-API-Key, or any custom header your target requires."
            )
            info_lbl.setWordWrap(True)
            info_lbl.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
            auth_layout.addWidget(info_lbl)

            # ── Header table ──────────────────────────────────────────────
            self._auth_table = QTableWidget(0, 3)
            self._auth_table.setHorizontalHeaderLabels(["✓", "Header Name", "Value"])
            self._auth_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Fixed)
            self._auth_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
            self._auth_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            self._auth_table.setColumnWidth(0, 28)
            self._auth_table.setAlternatingRowColors(False)
            self._auth_table.setSelectionBehavior(QAbstractItemView.SelectRows)
            self._auth_table.setMinimumHeight(90)
            self._auth_table.setMaximumHeight(160)
            self._auth_table.verticalHeader().hide()
            self._auth_table.setStyleSheet(
                f"QTableWidget{{background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
                f"gridline-color:{COLOR_BORDER};border:1px solid {COLOR_BORDER};}}"
                f"QHeaderView::section{{background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
                f"border:none;padding:3px;}}"
            )
            auth_layout.addWidget(self._auth_table)

            def _add_auth_row(enabled=True, name="", value=""):
                row = self._auth_table.rowCount()
                self._auth_table.insertRow(row)
                cb = QCheckBox()
                cb.setChecked(enabled)
                cb_widget = QWidget()
                cb_layout = QHBoxLayout(cb_widget)
                cb_layout.setContentsMargins(4, 0, 0, 0)
                cb_layout.addWidget(cb)
                self._auth_table.setCellWidget(row, 0, cb_widget)
                name_item = QTableWidgetItem(name)
                name_item.setFlags(name_item.flags() | Qt.ItemIsEditable)
                self._auth_table.setItem(row, 1, name_item)
                val_item = QTableWidgetItem(value)
                val_item.setFlags(val_item.flags() | Qt.ItemIsEditable)
                self._auth_table.setItem(row, 2, val_item)
                self._auth_table.scrollToBottom()
                return row

            self._add_auth_row = _add_auth_row

            # Pre-populate with cookie if supplied, otherwise empty Cookie row
            if prefill_cookie:
                _add_auth_row(True, "Cookie", prefill_cookie)
            else:
                _add_auth_row(False, "Cookie", "")

            # ── Buttons row ───────────────────────────────────────────────
            btn_row_auth = QHBoxLayout()

            preset_combo = QComboBox()
            preset_combo.setMinimumWidth(180)
            preset_combo.addItem("＋ Add preset…")
            for lbl, _, _ in _AUTH_PRESETS:
                preset_combo.addItem(lbl)

            def _on_preset(idx):
                if idx < 1:
                    return
                _, hname, hval = _AUTH_PRESETS[idx - 1]
                _add_auth_row(True, hname, hval)
                preset_combo.setCurrentIndex(0)

            preset_combo.currentIndexChanged.connect(_on_preset)
            btn_row_auth.addWidget(preset_combo)

            add_row_btn = QPushButton("+ Row")
            add_row_btn.setFixedWidth(60)
            add_row_btn.clicked.connect(lambda: _add_auth_row(True, "", ""))
            btn_row_auth.addWidget(add_row_btn)

            del_row_btn = QPushButton("✕ Del")
            del_row_btn.setFixedWidth(60)
            def _del_selected():
                rows = sorted(set(i.row() for i in self._auth_table.selectedItems()), reverse=True)
                for r in rows:
                    self._auth_table.removeRow(r)
            del_row_btn.clicked.connect(_del_selected)
            btn_row_auth.addWidget(del_row_btn)

            btn_row_auth.addSpacing(12)

            get_cookie_btn = QPushButton("📜 Cookie from History")
            get_cookie_btn.setToolTip("Grab the latest session cookie from HTTP history")
            get_cookie_btn.clicked.connect(self._get_cookie_from_history)
            btn_row_auth.addWidget(get_cookie_btn)

            detect_btn = QPushButton("🔍 Auto-detect Cookie")
            detect_btn.setToolTip("Scan HTTP history for a login session cookie")
            detect_btn.setStyleSheet(f"color:{COLOR_ACCENT_SECONDARY};")
            detect_btn.clicked.connect(self._auto_detect_cookie)
            btn_row_auth.addWidget(detect_btn)

            btn_row_auth.addStretch()
            auth_layout.addLayout(btn_row_auth)
            layout.addWidget(auth_group)

            # Legacy compat refs (used by _get_cookie_from_history / _auto_detect_cookie)
            self.cookie_checkbox = None
            self.cookie_input = None
        else:
            self._auth_table = None
            self.cookie_checkbox = None
            self.cookie_input = None

        # ── Proxy ────────────────────────────────────────────────────────────
        NO_PROXY = {"ipinfo","subdomains4"}
        if tool_lc not in NO_PROXY:
            proxy_group = QGroupBox("Proxy (optional)")
            proxy_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            proxy_layout = QVBoxLayout(proxy_group)

            self.proxy_checkbox = QCheckBox("Use Proxy")
            proxy_layout.addWidget(self.proxy_checkbox)

            self.proxy_input = QLineEdit()
            self.proxy_input.setPlaceholderText("http://127.0.0.1:8080")
            self.proxy_input.setEnabled(False)
            proxy_layout.addWidget(self.proxy_input)
            self.proxy_checkbox.toggled.connect(self.proxy_input.setEnabled)

            if self.main_window and getattr(self.main_window, "proxy_running", False):
                proxy_url = f"http://127.0.0.1:{self.main_window.proxy_port}"
                self.proxy_input.setText(proxy_url)
                self.proxy_checkbox.setChecked(True)
                self.proxy_input.setEnabled(True)
            layout.addWidget(proxy_group)
        else:
            self.proxy_checkbox = None
            self.proxy_input = None

        # ── GitHub Token ─────────────────────────────────────────────────────
        self.github_token_input = None
        if tool_lc in NEEDS_GITHUB_TOKEN:
            gh_group = QGroupBox("GitHub Token (optional)")
            gh_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            gh_layout = QVBoxLayout(gh_group)
            self.github_token_input = QLineEdit()
            self.github_token_input.setPlaceholderText("ghp_xxxxxxxxxxxxxxxxxxxx")
            self.github_token_input.setEchoMode(QLineEdit.Password)

            # Pre-fill from global settings first, then environment
            global_token = ""
            if self.main_window and hasattr(self.main_window, "_global_settings"):
                global_token = self.main_window._global_settings.get("github_token", "")

            self.github_token_input.setText(global_token or os.environ.get("GITHUB_TOKEN", ""))

            gh_layout.addWidget(self.github_token_input)
            layout.addWidget(gh_group)

        # ── Censys credentials ────────────────────────────────────────────────
        self.censys_id_input = None
        self.censys_secret_input = None
        if tool_lc == "subdomains4":
            cx_group = QGroupBox("Censys API Credentials (optional)")
            cx_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            cx_layout = QFormLayout(cx_group)
            self.censys_id_input = QLineEdit()
            self.censys_id_input.setPlaceholderText("API ID")
            self.censys_id_input.setText(os.environ.get("CENSYS_API_ID", ""))
            self.censys_secret_input = QLineEdit()
            self.censys_secret_input.setPlaceholderText("API Secret")
            self.censys_secret_input.setEchoMode(QLineEdit.Password)
            self.censys_secret_input.setText(os.environ.get("CENSYS_API_SECRET", ""))
            cx_layout.addRow("API ID:", self.censys_id_input)
            cx_layout.addRow("Secret:", self.censys_secret_input)
            layout.addWidget(cx_group)

        # ── Custom wordlist (bruteforce / active_subdomains) ─────────────────
        self.wordlist_input = None
        if tool_lc in {"bruteforce", "active_subdomains"}:
            if tool_lc == "active_subdomains":
                wl_label = "Extra DNS Wordlist (optional — sorted & merged with default SecLists DNS wordlist)"
                wl_placeholder = "Path to extra DNS wordlist…"
            else:
                wl_label = "Extra Wordlist (optional — merged with auto-selected lists)"
                wl_placeholder = "Path to additional wordlist…"
            wl_group = QGroupBox(wl_label)
            wl_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            wl_layout = QHBoxLayout(wl_group)
            self.wordlist_input = QLineEdit()
            self.wordlist_input.setPlaceholderText(wl_placeholder)
            wl_layout.addWidget(self.wordlist_input)
            browse_btn = QPushButton("Browse")
            browse_btn.clicked.connect(self._browse_wordlist)
            wl_layout.addWidget(browse_btn)
            layout.addWidget(wl_group)

        # ── Known Technologies (bruteforce only) ─────────────────────────────
        self._tech_checkboxes: Dict[str, QCheckBox] = {}
        if tool_lc == "bruteforce":
            from tool_runners import BruteforceRunner as _BFR
            tech_group = QGroupBox("Known Technologies (optional — adds tech-specific wordlists)")
            tech_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            tech_layout = QVBoxLayout(tech_group)
            tech_hint = QLabel(
                "Check any technologies you know the target uses. "
                "These are merged with auto-detected technologies."
            )
            tech_hint.setWordWrap(True)
            tech_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
            tech_layout.addWidget(tech_hint)
            tech_grid = QGridLayout()
            tech_grid.setSpacing(4)
            _all_techs = sorted(_BFR.TECH_KEYWORDS.keys())
            for i, tech in enumerate(_all_techs):
                cb = QCheckBox(tech)
                cb.setStyleSheet(f"color:{COLOR_TEXT}; font-size:9pt;")
                self._tech_checkboxes[tech] = cb
                tech_grid.addWidget(cb, i // 4, i % 4)
            tech_layout.addLayout(tech_grid)
            layout.addWidget(tech_group)

        # ── Feroxbuster Filter Status Codes (bruteforce only) ────────────────
        self._filter_codes_list: Optional[QListWidget] = None
        self._filter_code_input: Optional[QSpinBox] = None
        if tool_lc == "bruteforce":
            fc_group = QGroupBox("Filter Status Codes (feroxbuster -C — responses to skip)")
            fc_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            fc_layout = QVBoxLayout(fc_group)
            fc_hint = QLabel(
                "Feroxbuster will ignore responses with these status codes. "
                "Select an item and press Remove to delete it."
            )
            fc_hint.setWordWrap(True)
            fc_hint.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
            fc_layout.addWidget(fc_hint)

            self._filter_codes_list = QListWidget()
            self._filter_codes_list.setFixedHeight(80)
            self._filter_codes_list.setStyleSheet(
                f"QListWidget{{background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
                f"border:1px solid {COLOR_BORDER};border-radius:4px;}}"
            )
            for _default_code in [400, 404, 429]:
                self._filter_codes_list.addItem(str(_default_code))
            fc_layout.addWidget(self._filter_codes_list)

            fc_input_row = QHBoxLayout()
            self._filter_code_input = QSpinBox()
            self._filter_code_input.setRange(100, 599)
            self._filter_code_input.setValue(403)
            self._filter_code_input.setFixedWidth(80)
            fc_input_row.addWidget(QLabel("Code:"))
            fc_input_row.addWidget(self._filter_code_input)

            def _add_filter_code():
                code = str(self._filter_code_input.value())
                existing = [self._filter_codes_list.item(i).text()
                            for i in range(self._filter_codes_list.count())]
                if code not in existing:
                    self._filter_codes_list.addItem(code)

            add_fc_btn = QPushButton("+ Add")
            add_fc_btn.setFixedWidth(60)
            add_fc_btn.clicked.connect(_add_filter_code)
            fc_input_row.addWidget(add_fc_btn)

            def _remove_filter_code():
                for item in self._filter_codes_list.selectedItems():
                    self._filter_codes_list.takeItem(self._filter_codes_list.row(item))

            remove_fc_btn = QPushButton("✕ Remove")
            remove_fc_btn.setFixedWidth(80)
            remove_fc_btn.clicked.connect(_remove_filter_code)
            fc_input_row.addWidget(remove_fc_btn)
            fc_input_row.addStretch()
            fc_layout.addLayout(fc_input_row)
            layout.addWidget(fc_group)

        # ── Proxy SC filter option (spider + bruteforce + archive) ──────────
        self.proxy_replay_checkbox = None
        self._sc_checkboxes: Dict[int, QCheckBox] = {}   # sc → checkbox
        if tool_lc in {"spider", "bruteforce", "archive"}:
            replay_group = QGroupBox("Proxy Traffic Filter (optional)")
            replay_group.setStyleSheet(f"QGroupBox {{ color:{COLOR_ACCENT}; }}")
            replay_layout = QVBoxLayout(replay_group)

            if tool_lc == "spider":
                replay_desc = (
                    "Send discovered URLs through proxy — crawl tools run WITHOUT proxy\n"
                    "(no freezing, no double-proxying), then replay selected status codes."
                )
                replay_tip = (
                    "Spider mode:\n"
                    "  • ALL crawl tools (gospider/katana/hakrawler/cariddi) run WITHOUT proxy\n"
                    "  • httpx liveness check also runs WITHOUT proxy\n"
                    "  • At the end, discovered live URLs are probed for status codes\n"
                    "  • Only URLs matching selected codes are sent through the proxy\n"
                    "  • This prevents UI freezing and double-proxying"
                )
            else:
                replay_desc = (
                    "Filter proxy traffic — run tools without proxy, then replay only\n"
                    "interesting status codes through proxy"
                )
                replay_tip = (
                    "When enabled:\n"
                    "  • Discovery tools run at full speed without proxy (no noise)\n"
                    "  • Results are probed with httpx to collect status codes\n"
                    "  • Only interesting codes are replayed through the proxy\n"
                    "  • 404, 400, 429 etc. are silently dropped\n\n"
                    "When disabled:\n"
                    "  • All requests pass through the proxy as normal"
                )
            self.proxy_replay_checkbox = QCheckBox(replay_desc)
            self.proxy_replay_checkbox.setToolTip(replay_tip)
            replay_layout.addWidget(self.proxy_replay_checkbox)

            # ── Status Code selector (shown when replay is enabled) ───────────
            sc_group_widget = QWidget()
            sc_group_widget.setEnabled(False)
            sc_layout = QVBoxLayout(sc_group_widget)
            sc_layout.setContentsMargins(16, 4, 4, 4)
            sc_layout.setSpacing(4)
            sc_label = QLabel("Status codes to replay through proxy:")
            sc_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED}; font-size:9pt;")
            sc_layout.addWidget(sc_label)
            sc_grid = QGridLayout()
            sc_grid.setSpacing(4)
            # Default codes from PROXY_REPLAY_CODES
            _SC_LABELS = [
                (200, "200 OK"),       (201, "201 Created"),
                (301, "301 Moved"),    (302, "302 Found"),
                (307, "307 Temp"),     (308, "308 Perm"),
                (401, "401 Auth"),     (403, "403 Forbidden"),
                (405, "405 Method"),   (500, "500 Internal"),
                (502, "502 Gateway"),  (503, "503 Unavailable"),
            ]
            _ALL_DEFAULT = {sc for sc, _ in _SC_LABELS}
            for i, (sc, lbl) in enumerate(_SC_LABELS):
                cb = QCheckBox(lbl)
                cb.setChecked(True)
                cb.setStyleSheet(f"color:{COLOR_TEXT}; font-size:9pt;")
                self._sc_checkboxes[sc] = cb
                sc_grid.addWidget(cb, i // 4, i % 4)
            sc_layout.addLayout(sc_grid)
            replay_layout.addWidget(sc_group_widget)

            self.proxy_replay_checkbox.toggled.connect(sc_group_widget.setEnabled)
            layout.addWidget(replay_group)

        layout.addStretch()

        # ── Buttons — fixed outside the scroll area ───────────────────────────
        btn_container = QWidget()
        btn_container.setStyleSheet(
            f"border-top: 1px solid {COLOR_BORDER}; background: {COLOR_DARK_BG};"
        )
        btn_row = QHBoxLayout(btn_container)
        btn_row.setContentsMargins(12, 8, 12, 8)
        btn_row.addStretch()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        btn_row.addWidget(cancel_btn)

        run_btn = QPushButton("▶ Run Task")
        run_btn.setStyleSheet(
            f"background-color:{COLOR_SUCCESS}; color:black; font-weight:bold; padding:6px 16px;"
        )
        run_btn.clicked.connect(self.accept)
        btn_row.addWidget(run_btn)
        outer_layout.addWidget(btn_container)

    def _browse_wordlist(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select Wordlist", "", "Text Files (*.txt);;All Files (*)")
        if path and self.wordlist_input:
            self.wordlist_input.setText(path)

    def _get_cookie_from_history(self):
        """
        Grab the most recent session cookie from HTTP history.
        Preference order:
          1. Set-Cookie from a successful login POST to a scope domain
          2. Cookie header from any in-scope request (session already established)
          3. Cookie header from any request at all (last resort)
        """
        if not self.main_window or not hasattr(self.main_window, "findings") or not self.main_window.findings:
            QMessageBox.information(self, "No History", "No requests in HTTP History.")
            return

        findings = self.main_window.findings

        # Build scope host set: the task domain + all other in-scope hosts
        # because cookies are often set on auth.example.com and used everywhere
        import project_manager as pm
        scope_hosts: set = set()
        if self.main_window:
            slug = getattr(self.main_window, "_project_slug", "")
            if slug:
                scope_hosts = set(pm.get_scope_hosts(
                    slug,
                    getattr(self.main_window, "_project_domain", ""),
                    getattr(self.main_window, "_project_subdomain", ""),
                ))
        # Always include the task's own domain as a fallback
        scope_hosts.add(self.domain.lower())

        def host_of(url):
            from urllib.parse import urlparse
            return _safe_urlparse_host(url)

        def read_set_cookie(finding):
            resp_file = finding.get("response_file", "")
            if not resp_file or not os.path.exists(resp_file):
                return ""
            try:
                cookies = []
                with open(resp_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.rstrip("\r\n")
                        if not line:
                            break
                        if line.lower().startswith("set-cookie:"):
                            nv = line.split(":", 1)[1].strip().split(';')[0].strip()
                            if nv:
                                cookies.append(nv)
                return "; ".join(cookies)
            except Exception:
                return ""

        def read_request_cookie(finding):
            req_file = finding.get("request_file", "")
            if not req_file or not os.path.exists(req_file):
                return ""
            cookies = []
            try:
                with open(req_file, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        line = line.rstrip("\r\n")
                        if not line:
                            break
                        if line.lower().startswith("cookie:"):
                            val = line.split(":", 1)[1].strip()
                            if val:
                                # Fix: Only split by semicolon, preserve commas in values
                                parts = val.split(';')
                                cookies.extend([p.strip() for p in parts if p.strip() and '=' in p])
            except Exception:
                pass
            return "; ".join(cookies)

        LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "session",
                          "token", "oauth", "sso")

        cookie = ""

        # Pass 1: Set-Cookie from successful login POST to any in-scope host
        for finding in reversed(findings):
            if finding.get("method", "").upper() != "POST":
                continue
            status = finding.get("status", finding.get("status_code", 0))
            if status not in (200, 201, 302, 303):
                continue
            url = finding.get("url", "")
            if scope_hosts and host_of(url) not in scope_hosts:
                continue
            if not any(kw in url.lower() for kw in LOGIN_KEYWORDS):
                continue
            cookie = read_set_cookie(finding)
            if cookie:
                break

        # Pass 2: Cookie header from any in-scope request
        if not cookie:
            for finding in reversed(findings):
                if scope_hosts and host_of(finding.get("url", "")) not in scope_hosts:
                    continue
                cookie = read_request_cookie(finding)
                if cookie:
                    break

        # Pass 3: Last resort — any Cookie header from any recent request
        # findings may not support slicing directly, so convert to list first
        if not cookie:
            recent = list(findings)[-200:]
            for finding in reversed(recent):
                cookie = read_request_cookie(finding)
                if cookie:
                    break

        if cookie:
            self._set_cookie_in_table(cookie)
        else:
            QMessageBox.information(self, "Not Found",
                                    "No session cookie found in HTTP history.\n"
                                    "Try logging in through the proxy first.")

    def _set_cookie_in_table(self, cookie: str):
        """Find or create a Cookie row in the auth table and populate it."""
        if not hasattr(self, "_auth_table") or self._auth_table is None:
            return
        for row in range(self._auth_table.rowCount()):
            name_item = self._auth_table.item(row, 1)
            if name_item and name_item.text().strip().lower() == "cookie":
                val_item = self._auth_table.item(row, 2)
                if val_item:
                    val_item.setText(cookie)
                cb_widget = self._auth_table.cellWidget(row, 0)
                if cb_widget:
                    cb = cb_widget.findChild(QCheckBox)
                    if cb:
                        cb.setChecked(True)
                return
        # No Cookie row yet — add one
        self._add_auth_row(True, "Cookie", cookie)

    def _auto_detect_cookie(self):
        """Run smart login cookie detection with user confirmation dialog."""
        if not self.main_window or not hasattr(self.main_window, "findings") or not self.main_window.findings:
            QMessageBox.information(self, "No History", "No requests in HTTP History.")
            return
        
        # Restrict detection to the current domain only
        scope_hosts = [self.domain.lower()]
        self._detector = CookieDetectorThread(
            self.main_window.findings, scope_hosts=scope_hosts, parent=self
        )
        self._detector.cookie_found.connect(self._on_cookie_detected)
        self._detector.finished.connect(self._on_auto_detect_done)
        self._auto_detect_found = False
        self._detector.start()

    def _on_cookie_detected(self, cookie_val: str, url: str):
        self._auto_detect_found = True
        dlg = CookiePromptDialog(cookie_val, url, self)
        if dlg.exec_() == QDialog.Accepted:
            if dlg.choice in (CookiePromptDialog.USE_COOKIE, CookiePromptDialog.CHANGE):
                self._set_cookie_in_table(dlg.final_cookie)
        # If no match found the signal simply won't fire

    def _on_auto_detect_done(self):
        if not self._auto_detect_found:
            QMessageBox.information(
                self, "Not Found",
                "No login cookie detected in HTTP history.\n\n"
                "Make sure you:\n"
                "• Have the proxy running\n"
                "• Logged in through the proxy so the login POST was captured\n\n"
                "You can also use 'Get from HTTP History' to grab any existing cookie."
            )

    def get_config(self) -> Dict[str, Any]:
        config = {"domain": self.domain, "tool": self.tool_name.lower()}

        # ── Collect auth headers from the table ──────────────────────────
        if hasattr(self, "_auth_table") and self._auth_table is not None:
            auth_headers = []
            for row in range(self._auth_table.rowCount()):
                cb_widget = self._auth_table.cellWidget(row, 0)
                enabled = True
                if cb_widget:
                    cb = cb_widget.findChild(QCheckBox)
                    enabled = cb.isChecked() if cb else True
                name_item  = self._auth_table.item(row, 1)
                value_item = self._auth_table.item(row, 2)
                name  = name_item.text().strip()  if name_item  else ""
                value = value_item.text().strip() if value_item else ""
                if enabled and name and value:
                    auth_headers.append({"name": name, "value": value})
            if auth_headers:
                config["auth_headers"] = auth_headers
                # Backward-compat: extract Cookie header value
                for h in auth_headers:
                    if h["name"].lower() == "cookie":
                        config["cookie"] = validate_cookie(h["value"])
                        break
        elif self.cookie_checkbox and self.cookie_checkbox.isChecked() and self.cookie_input:
            # Fallback for tools without the auth table (shouldn't happen but safe)
            config["cookie"] = self.cookie_input.toPlainText().strip()
        if self.proxy_checkbox is not None:
            # Always write the key so add_task knows the user's explicit intent.
            # Empty string = user unchecked → do NOT auto-inject proxy.
            if self.proxy_checkbox.isChecked() and self.proxy_input:
                config["proxy"] = self.proxy_input.text().strip()
            else:
                config["proxy"] = ""   # explicit "no proxy"
        if self.github_token_input:
            val = self.github_token_input.text().strip()
            if val:
                config["github_token"] = val
        if self.censys_id_input:
            val = self.censys_id_input.text().strip()
            if val:
                config["censys_id"] = val
        if self.censys_secret_input:
            val = self.censys_secret_input.text().strip()
            if val:
                config["censys_secret"] = val
        if self.wordlist_input:
            val = self.wordlist_input.text().strip()
            if val:
                config["wordlist"] = val
        if self.proxy_replay_checkbox is not None:
            config["proxy_replay"] = self.proxy_replay_checkbox.isChecked()
            if self.proxy_replay_checkbox.isChecked() and self._sc_checkboxes:
                # Collect which SC codes are selected
                selected_codes = [sc for sc, cb in self._sc_checkboxes.items() if cb.isChecked()]
                if selected_codes:
                    config["proxy_replay_codes"] = selected_codes
        # ── Manual technologies (bruteforce) ──────────────────────────────────
        if hasattr(self, "_tech_checkboxes") and self._tech_checkboxes:
            manual_techs = [t for t, cb in self._tech_checkboxes.items() if cb.isChecked()]
            if manual_techs:
                config["manual_techs"] = manual_techs
        # ── Filter status codes (bruteforce) ─────────────────────────────────
        if hasattr(self, "_filter_codes_list") and self._filter_codes_list is not None:
            codes = []
            for i in range(self._filter_codes_list.count()):
                try:
                    codes.append(int(self._filter_codes_list.item(i).text()))
                except ValueError:
                    pass
            config["filter_codes"] = codes  # may be empty list = no filtering
        return config


# ─────────────────────────────────────────────────────────────────────────────
# Task Widget
# ─────────────────────────────────────────────────────────────────────────────

class TaskWidget(QWidget):
    """Widget representing a single task."""

    remove_requested      = pyqtSignal(str)   # task_id
    show_output_requested = pyqtSignal(str)   # task_id

    # Tool → (display name, category label, category color)
    TOOL_META = {
        "spider":      ("Spider / Crawl",          "recon",       "blue"),
        "archive":     ("Archive Lookup",            "recon",       "blue"),
        "ipinfo":      ("IP Info",                   "network",     "cyan"),
        "headers":     ("HTTP Headers",              "fingerprint", "cyan"),
        "tech":        ("Tech Fingerprint",          "fingerprint", "cyan"),
        "waf":         ("WAF Detection",             "security",    "amber"),
        "cms":         ("CMS Detection",             "fingerprint", "cyan"),
        "ports":       ("Port Scan",                 "network",     "cyan"),
        "bruteforce":  ("Directory Bruteforce",      "fuzzing",     "blue"),
        "nuclei":      ("Nuclei Scan",               "security",    "amber"),
        "nikto":       ("Nikto Scan",                "security",    "amber"),
        "wpscan":      ("WordPress Scan",            "security",    "amber"),
        "joomscan":    ("Joomla Scan",               "security",    "amber"),
        "droopescan":  ("Drupal Scan",               "security",    "amber"),
        "subdomains4": ("Subdomain Enum",            "recon",       "blue"),
    }

    _CATEGORY_STYLE = {
        "blue":  "background:#0f2b3c;color:#6bb5ff;",
        "cyan":  "background:#0c2e3a;color:#6fd4f5;",
        "amber": "background:#3a2a0c;color:#f5b042;",
    }

    def __init__(self, task_data: Dict[str, Any], project_dir: str):
        super().__init__()
        self.task_id     = task_data["id"]
        self.task_data   = task_data
        self.project_dir = project_dir
        self._setup_ui()
        self.update_status(task_data["status"], task_data.get("status_message", ""))

    # ── helpers ────────────────────────────────────────────────────────────
    @staticmethod
    def _pill(text: str, style: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"{style}font-size:9px;font-weight:600;"
            f"padding:2px 8px;border-radius:100px;border:none;"
        )
        return lbl

    @staticmethod
    def _meta_chip(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(
            "background:#1e1e1e;color:#888888;font-size:10px;"
            "padding:2px 8px;border-radius:14px;border:none;"
        )
        return lbl

    def _setup_ui(self):
        _lb = "border:none;background:transparent;"
        tool   = self.task_data.get("tool", "")
        domain = self.task_data.get("domain", "")
        ts_raw = self.task_data.get("timestamp", "")
        try:
            ts_str = datetime.fromisoformat(ts_raw).strftime("%H:%M:%S")
        except Exception:
            ts_str = ts_raw

        name, category, cat_color = self.TOOL_META.get(
            tool, (tool.replace("_"," ").title(), "recon", "blue")
        )

        # ── outer card wrapper ──────────────────────────────────────────────
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        card = QWidget()
        card.setObjectName("TaskCard")
        card.setStyleSheet(
            "#TaskCard{background:#2d2d2d;border-radius:10px;"
            "border:1px solid #4e5254;}"
            "#TaskCard:hover{background:#323232;border-color:#5e6264;}"
        )
        card_layout = QHBoxLayout(card)
        card_layout.setContentsMargins(14, 8, 14, 8)
        card_layout.setSpacing(12)
        outer.addWidget(card, stretch=1)

        # ── LEFT: 30×30 status icon box ────────────────────────────────────
        self._icon_box = QWidget()
        self._icon_box.setFixedSize(30, 30)
        self._icon_box.setStyleSheet(
            "background:rgba(255,255,255,0.05);border-radius:10px;border:none;"
        )
        icon_box_l = QHBoxLayout(self._icon_box)
        icon_box_l.setContentsMargins(0, 0, 0, 0)
        icon_box_l.setAlignment(Qt.AlignCenter)

        # Spinner (running) — indeterminate QProgressBar as circular look via stylesheet
        self._spinner = QProgressBar()
        self._spinner.setFixedSize(18, 18)
        self._spinner.setRange(0, 0)
        self._spinner.setTextVisible(False)
        self._spinner.setStyleSheet(
            "QProgressBar{border:2px solid rgba(255,255,255,0.18);border-radius:9px;"
            "background:transparent;}"
            "QProgressBar::chunk{background:#2b7de9;border-radius:9px;}"
        )
        icon_box_l.addWidget(self._spinner)
        self._spinner.hide()

        self._status_icon = QLabel("⏳")
        self._status_icon.setAlignment(Qt.AlignCenter)
        self._status_icon.setStyleSheet(f"font-size:14px;{_lb}")
        icon_box_l.addWidget(self._status_icon)

        card_layout.addWidget(self._icon_box)

        # ── CENTER: content ─────────────────────────────────────────────────
        center = QWidget()
        center.setStyleSheet("background:transparent;border:none;")
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(3)
        card_layout.addWidget(center, stretch=1)

        # Task name row: name + result label inline
        name_row = QHBoxLayout()
        name_row.setContentsMargins(0, 0, 0, 0)
        name_row.setSpacing(8)

        self._name_label = QLabel(name)
        self._name_label.setStyleSheet(
            f"color:#f0f0f0;font-weight:700;font-size:12px;{_lb}"
        )
        name_row.addWidget(self._name_label)

        self._result_label = QLabel("")
        self._result_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._result_label.setWordWrap(False)
        self._result_label.setStyleSheet(
            f"color:#f0f0f0;font-size:11px;font-weight:500;{_lb}"
        )
        name_row.addWidget(self._result_label)
        name_row.addStretch()
        cl.addLayout(name_row)

        # Target (cyan)
        self._target_label = QLabel(f"target: {domain}")
        self._target_label.setStyleSheet(
            f"color:#6bc2f0;font-size:11px;{_lb}"
        )
        cl.addWidget(self._target_label)

        # Metadata row: elapsed chip + tool chip + category badge
        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(8)

        self._time_chip = self._meta_chip(f"🕐 {ts_str}")
        meta_row.addWidget(self._time_chip)

        out = self.task_data.get("output_file", "")
        tool_chip_text = f"🔧 {tool}"
        if out:
            tool_chip_text += f" · {os.path.basename(out)}"
        self._tool_chip = self._meta_chip(tool_chip_text)
        meta_row.addWidget(self._tool_chip)

        self._cat_badge = self._pill(category, self._CATEGORY_STYLE.get(cat_color, ""))
        meta_row.addWidget(self._cat_badge)
        meta_row.addStretch()
        cl.addLayout(meta_row)

        # Progress bar (thin, 4px)
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet(
            "QProgressBar{border:none;background:#3c3f41;border-radius:2px;}"
            "QProgressBar::chunk{background:#2b7de9;border-radius:2px;}"
        )
        self.progress_bar.hide()
        cl.addWidget(self.progress_bar)

        # ── RIGHT: timestamp + result/error + action buttons ────────────────
        right_col = QWidget()
        right_col.setStyleSheet("background:transparent;border:none;")
        right_col.setMinimumWidth(90)
        rl = QVBoxLayout(right_col)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)
        rl.setAlignment(Qt.AlignTop | Qt.AlignRight)

        self._ts_label = QLabel(ts_str)
        self._ts_label.setAlignment(Qt.AlignRight)
        self._ts_label.setStyleSheet(f"color:#888888;font-size:10px;{_lb}")
        rl.addWidget(self._ts_label)

        rl.addStretch()

        # Action buttons (view + remove)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(4)
        btn_row.setContentsMargins(0, 0, 0, 0)

        view_btn = QPushButton("☰")
        view_btn.setFixedSize(26, 26)
        view_btn.setToolTip("View Output")
        view_btn.setStyleSheet(
            "QPushButton{background:#2d2d2d;border:1px solid #3c3f41;"
            "border-radius:6px;font-size:12px;padding:0;}"
            "QPushButton:hover{background:#3c3f41;border-color:#2b7de9;}"
        )
        view_btn.clicked.connect(lambda: self.show_output_requested.emit(self.task_id))
        btn_row.addWidget(view_btn)

        rm_btn = QPushButton("✕")
        rm_btn.setFixedSize(26, 26)
        rm_btn.setToolTip("Remove task")
        rm_btn.setStyleSheet(
            "QPushButton{background:transparent;color:#f86f6f;border:1px solid #f86f6f;"
            "border-radius:6px;font-size:11px;font-weight:bold;padding:0;}"
            "QPushButton:hover{background:transparent;color:#ff9090;border-color:#ff9090;}"
        )
        def _confirm_remove():
            tool = self.task_data.get("tool", "task")
            domain = self.task_data.get("domain", "")
            reply = QMessageBox.question(
                self,
                "Remove Task",
                f"Remove the <b>{tool}</b> task for <b>{domain}</b>?",
                QMessageBox.Yes | QMessageBox.Cancel,
                QMessageBox.Cancel,
            )
            if reply == QMessageBox.Yes:
                self.remove_requested.emit(self.task_id)

        rm_btn.clicked.connect(_confirm_remove)
        btn_row.addWidget(rm_btn)

        rl.addLayout(btn_row)
        card_layout.addWidget(right_col)

        # outer card‑level margins (gives the 12px 16px card margin from mockup)
        self.setContentsMargins(16, 4, 16, 4)
        self.setFixedHeight(82)

    def update_status(self, status: str, message: str = ""):
        self.task_data["status"] = status
        self.task_data["status_message"] = message

        out = self.task_data.get("output_file", "")
        if out and hasattr(self, '_tool_chip'):
            tool = self.task_data.get("tool", "")
            self._tool_chip.setText(
                f"🔧 {tool} · {os.path.basename(out)}"
            )

        # Status → (icon, icon-box bg, accent color, show-spinner, progress-mode)
        # progress-mode: None=hide, 'indeterminate', 'full', 'error-partial'
        _CFG = {
            "pending":   ("⏳", "rgba(255,255,255,0.05)", "#888888",  False, None),
            "running":   (None,  "rgba(43,125,233,0.18)",  "#2b7de9",  True,  "indeterminate"),
            "completed": ("✓",   "rgba(43,158,90,0.18)",   "#2b9e5a",  False, "full"),
            "error":     ("✗",   "rgba(229,72,77,0.18)",   "#e5484d",  False, "error"),
        }
        icon_ch, box_bg, accent, spin, prog = _CFG.get(
            status, ("?", "rgba(255,255,255,0.05)", "#888888", False, None)
        )

        # Icon box bg
        self._icon_box.setStyleSheet(
            f"background:{box_bg};border-radius:10px;border:none;"
        )

        # Spinner vs static icon
        if spin:
            self._spinner.show()
            self._status_icon.hide()
        else:
            self._spinner.hide()
            self._status_icon.show()
            ch = icon_ch or "?"
            if status == "completed":
                self._status_icon.setStyleSheet(
                    f"font-size:16px;font-weight:bold;color:#6fdc9c;"
                    "border:none;background:transparent;"
                )
            elif status == "error":
                self._status_icon.setStyleSheet(
                    f"font-size:16px;font-weight:bold;color:#f86f6f;"
                    "border:none;background:transparent;"
                )
            else:
                self._status_icon.setStyleSheet(
                    "font-size:14px;border:none;background:transparent;"
                )
            self._status_icon.setText(ch)

        # Result / error label
        status_text = message or status.title()
        if status == "error":
            self._result_label.setStyleSheet(
                "color:#f86f6f;font-size:10px;border:none;background:transparent;"
            )
        elif status == "completed":
            self._result_label.setStyleSheet(
                "color:#6fdc9c;font-size:11px;font-weight:500;"
                "border:none;background:transparent;"
            )
        else:
            self._result_label.setStyleSheet(
                "color:#f0f0f0;font-size:11px;font-weight:500;"
                "border:none;background:transparent;"
            )
        self._result_label.setText(status_text)

        # Progress bar
        if prog is None:
            self.progress_bar.hide()
        elif prog == "indeterminate":
            self.progress_bar.setStyleSheet(
                "QProgressBar{border:none;background:#3c3f41;border-radius:2px;}"
                "QProgressBar::chunk{background:#2b7de9;border-radius:2px;}"
            )
            self.progress_bar.setRange(0, 0)
            self.progress_bar.show()
        elif prog == "full":
            self.progress_bar.setStyleSheet(
                "QProgressBar{border:none;background:#3c3f41;border-radius:2px;}"
                "QProgressBar::chunk{background:#2b9e5a;border-radius:2px;}"
            )
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(100)
            self.progress_bar.show()
        elif prog == "error":
            self.progress_bar.setStyleSheet(
                "QProgressBar{border:none;background:#3c3f41;border-radius:2px;}"
                "QProgressBar::chunk{background:#e5484d;border-radius:2px;}"
            )
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(30)
            self.progress_bar.show()

    def get_task_data(self) -> Dict[str, Any]:
        return self.task_data


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Widget helpers
# ─────────────────────────────────────────────────────────────────────────────

_DOTS_SVG = (
    b'<svg width="14" height="14" viewBox="0 0 14 14" fill="none"'
    b' xmlns="http://www.w3.org/2000/svg">'
    b'<circle cx="7" cy="2.5" r="1.3" fill="white"/>'
    b'<circle cx="7" cy="7" r="1.3" fill="white"/>'
    b'<circle cx="7" cy="11.5" r="1.3" fill="white"/>'
    b'</svg>'
)


def _make_dots_btn(parent=None) -> QPushButton:
    """Return a small square QPushButton showing a vertical 3-dot (ellipsis) icon."""
    btn = QPushButton(parent)
    if _HAS_SVG:
        from PyQt5.QtCore import QByteArray
        renderer = _QSvgRenderer(QByteArray(_DOTS_SVG))
        pixmap = QPixmap(14, 14)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        renderer.render(painter)
        painter.end()
        btn.setIcon(QIcon(pixmap))
        btn.setIconSize(QSize(14, 14))
    else:
        btn.setText("\u22ee")  # ⋮ fallback
        btn.setStyleSheet(btn.styleSheet() + "font-size:16px;")
    btn.setFixedSize(28, 28)
    return btn


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain Widget
# ─────────────────────────────────────────────────────────────────────────────

class SubdomainWidget(QWidget):
    """Widget for a single subdomain (or domain) with task menu."""

    clicked = pyqtSignal(str)
    expand_toggled = pyqtSignal(str, bool)   # domain, is_expanded

    # Status → (icon-bg, icon-fg)
    _STATUS_COLORS = {
        "idle":    ("#2d2d2d", "#888888"),
        "active":  ("#0f3a2a", "#6fdc9c"),
        "running": ("#3a2a0c", "#f5b042"),
        "error":   ("#3b1a1a", "#f86f6f"),
    }

    def __init__(self, subdomain: str, project_dir: str, parent_tab=None, main_window=None,
                 is_domain: bool = False):
        super().__init__()
        self.subdomain = subdomain
        self.project_dir = project_dir
        self.parent_tab = parent_tab
        self.main_window = main_window
        self.is_domain = is_domain
        self._domain_status = "idle"
        self._subdomain_count = 0
        self._expanded = False
        self._setup_ui()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.subdomain)
            event.accept()   # prevent event bubbling to parent domain widget
            return
        super().mousePressEvent(event)

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            if self.is_domain:
                self.toggle_expand()
            # Consume the event so it never bubbles up to the parent domain widget
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def toggle_expand(self):
        """Show/hide the subdomain rows underneath this domain card."""
        if not self.is_domain:
            return
        self._expanded = not self._expanded
        self._sub_container.setVisible(self._expanded)
        self._chevron.setText("▾" if self._expanded else "▸")
        self.expand_toggled.emit(self.subdomain, self._expanded)

    def set_selected(self, selected: bool):
        if self.is_domain:
            if selected:
                self._card.setStyleSheet(
                    f"#DomainCard{{background:#2d2d2d;"
                    f"border:1px solid #3c3f41;"
                    f"border-radius:8px;}}"
                )
                self._accent_bar.show()
            else:
                self._card.setStyleSheet(
                    f"#DomainCard{{background:#252525;"
                    f"border:1px solid #3c3f41;"
                    f"border-radius:8px;}}"
                    f"#DomainCard:hover{{background:#2d2d2d;}}"
                )
                self._accent_bar.hide()
        else:
            if selected:
                self._card.setStyleSheet(
                    "#SubCard{background:#2d2d2d;"
                    "border-left:none;border-right:none;border-top:none;"
                    "border-bottom:1px solid #3c3f41;}"
                )
                self._accent_bar.show()
            else:
                self._card.setStyleSheet(
                    "#SubCard{background:#1e1e1e;"
                    "border-left:none;border-right:none;border-top:none;"
                    "border-bottom:1px solid #3c3f41;}"
                    "#SubCard:hover{background:#2d2d2d;}"
                )
                self._accent_bar.hide()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._card = QFrame()
        if self.is_domain:
            self._card.setObjectName("DomainCard")
            self._build_domain_card()
        else:
            self._card.setObjectName("SubCard")
            self._build_sub_card()

        outer.addWidget(self._card)

        if self.is_domain:
            # Hidden container that holds inline subdomain rows
            # Indented 18px on the left so subdomains look like a narrower droplist
            self._sub_container = QWidget()
            self._sub_container.setStyleSheet("background:#1e1e1e;")
            self._sub_layout = QVBoxLayout(self._sub_container)
            self._sub_layout.setContentsMargins(18, 0, 0, 0)  # 18px left indent
            self._sub_layout.setSpacing(0)
            self._sub_container.setVisible(False)
            outer.addWidget(self._sub_container)

        self.set_selected(False)

    def _build_domain_card(self):
        """Domain row: initials icon | name+meta | status badge + counter | chevron | dots."""
        _lb = "border:none;background:transparent;"

        # Outer wrapper: accent bar + content
        wrapper = QHBoxLayout(self._card)
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(0)

        # Green left-accent strip (shown when selected)
        self._accent_bar = QFrame()
        self._accent_bar.setFixedWidth(3)
        self._accent_bar.setStyleSheet(
            f"background:{COLOR_ACCENT};border-radius:3px;border:none;"
        )
        self._accent_bar.hide()
        wrapper.addWidget(self._accent_bar)

        # Content inside the card
        content = QWidget()
        content.setStyleSheet("background:transparent;border:none;")
        layout = QHBoxLayout(content)
        layout.setContentsMargins(11, 9, 10, 9)
        layout.setSpacing(12)

        # LEFT — 28×28 initials box, status-coloured
        raw = re.sub(r'[^a-zA-Z]', '', self.subdomain).upper()
        initials = (raw[:2] if len(raw) >= 2 else (raw or "?").ljust(1)[:2])
        self._icon_label = QLabel(initials)
        self._icon_label.setFixedSize(28, 28)
        self._icon_label.setAlignment(Qt.AlignCenter)
        bg, fg = self._STATUS_COLORS["idle"]
        self._icon_label.setStyleSheet(
            f"background:{bg};color:{fg};font-size:10px;font-weight:700;"
            f"border-radius:6px;{_lb}"
        )
        layout.addWidget(self._icon_label)

        # CENTER — domain name + meta line
        center = QWidget()
        center.setStyleSheet("background:transparent;border:none;")
        cl = QVBoxLayout(center)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(2)

        self.subdomain_label = QLabel(self.subdomain)
        self.subdomain_label.setStyleSheet(
            f"color:#f0f0f0;font-weight:700;font-size:12px;{_lb}"
        )
        self.subdomain_label.setTextInteractionFlags(Qt.NoTextInteraction)
        cl.addWidget(self.subdomain_label)

        self._meta_label = QLabel("0 subdomains · click ▸ to expand")
        self._meta_label.setStyleSheet(f"color:#888888;font-size:9px;{_lb}")
        cl.addWidget(self._meta_label)

        layout.addWidget(center, stretch=1)

        # RIGHT — status badge (pill) stacked over task counter
        right = QWidget()
        right.setStyleSheet("background:transparent;border:none;")
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(3)
        rl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)

        self._status_badge = QLabel("idle")
        self._status_badge.setAlignment(Qt.AlignCenter)
        self._status_badge.setStyleSheet(
            f"background:#2d2d2d;color:#888888;font-size:8px;font-weight:600;"
            f"padding:2px 7px;border-radius:100px;{_lb}"
        )
        rl.addWidget(self._status_badge, alignment=Qt.AlignRight)

        self.task_count_label = QLabel("0")
        self.task_count_label.setAlignment(Qt.AlignCenter)
        self.task_count_label.setStyleSheet(
            f"background:#2d2d2d;color:#888888;font-size:9px;font-weight:500;"
            f"padding:2px 6px;border-radius:40px;min-width:18px;{_lb}"
        )
        rl.addWidget(self.task_count_label, alignment=Qt.AlignRight)

        layout.addWidget(right)

        # CHEVRON expand/collapse button
        self._chevron = QPushButton("▸")
        self._chevron.setFixedSize(22, 22)
        self._chevron.setToolTip("Expand / collapse subdomains")
        self._chevron.setStyleSheet(
            "QPushButton{background:transparent;border:none;"
            "color:#888888;font-size:11px;font-weight:bold;padding:0px;}"
            "QPushButton:hover{color:#f0f0f0;}"
        )
        self._chevron.clicked.connect(self.toggle_expand)
        layout.addWidget(self._chevron)

        # DOTS BUTTON
        self.menu_btn = _make_dots_btn(self._card)
        self.menu_btn.setToolTip("Domain Tasks")
        self.menu_btn.setStyleSheet(
            "QPushButton{background-color:transparent;"
            "border:1px solid #3c3f41;border-radius:4px;padding:0px;}"
            "QPushButton:hover{background-color:#2d2d2d;border-color:#2b7de9;}"
        )
        self.menu_btn.clicked.connect(self._show_domain_task_menu)
        layout.addWidget(self.menu_btn)

        wrapper.addWidget(content, stretch=1)

    def _build_sub_card(self):
        """Subdomain row: left-accent | indent | status dot | name | count pill | menu."""
        _lb = "border:none;background:transparent;"

        # Outer wrapper: accent bar + content (same pattern as domain card)
        wrapper = QHBoxLayout(self._card)
        wrapper.setContentsMargins(0, 0, 0, 0)
        wrapper.setSpacing(0)

        # Blue left-accent strip (shown when selected)
        self._accent_bar = QFrame()
        self._accent_bar.setFixedWidth(3)
        self._accent_bar.setStyleSheet("background:#2b7de9;border-radius:2px;border:none;")
        self._accent_bar.hide()
        wrapper.addWidget(self._accent_bar)

        # Content
        content = QWidget()
        content.setStyleSheet("background:transparent;border:none;")
        layout = QHBoxLayout(content)
        layout.setContentsMargins(24, 7, 10, 7)  # 24 px left nesting
        layout.setSpacing(10)

        # Status dot — 6×6 px circle
        self._status_dot = QLabel()
        self._status_dot.setFixedSize(6, 6)
        self._status_dot.setStyleSheet("background:#555555;border-radius:3px;border:none;")
        layout.addWidget(self._status_dot)

        # Subdomain name (stretches, truncates)
        self.subdomain_label = QLabel(self.subdomain)
        self.subdomain_label.setStyleSheet(
            f"color:#f0f0f0;font-weight:500;font-size:11px;letter-spacing:0.2px;{_lb}"
        )
        self.subdomain_label.setTextInteractionFlags(Qt.NoTextInteraction)
        layout.addWidget(self.subdomain_label, stretch=1)

        # Task-count pill
        self.task_count_label = QLabel("0")
        self.task_count_label.setAlignment(Qt.AlignCenter)
        self.task_count_label.setStyleSheet(
            f"background:#2d2d2d;color:#888888;font-size:9px;font-weight:500;"
            f"padding:2px 6px;border-radius:40px;min-width:18px;{_lb}"
        )
        layout.addWidget(self.task_count_label)

        # Dots menu button
        self.menu_btn = _make_dots_btn(content)
        self.menu_btn.setToolTip("Subdomain Tasks")
        self.menu_btn.setStyleSheet(
            "QPushButton{background-color:transparent;"
            "border:1px solid #3c3f41;border-radius:4px;padding:0px;}"
            "QPushButton:hover{background-color:#2d2d2d;border-color:#2b7de9;}"
        )
        self.menu_btn.clicked.connect(self._show_task_menu)
        layout.addWidget(self.menu_btn)

        wrapper.addWidget(content, stretch=1)

    def set_domain_status(self, status: str):
        """Update icon and badge colours. status: 'idle'|'active'|'running'|'error'."""
        if not self.is_domain:
            return
        self._domain_status = status
        bg, fg = self._STATUS_COLORS.get(status, self._STATUS_COLORS["idle"])
        _lb = "border:none;background:transparent;"
        self._icon_label.setStyleSheet(
            f"background:{bg};color:{fg};font-size:10px;font-weight:700;"
            f"border-radius:6px;{_lb}"
        )
        self._status_badge.setStyleSheet(
            f"background:{bg};color:{fg};font-size:8px;font-weight:600;"
            f"padding:2px 7px;border-radius:100px;{_lb}"
        )
        self._status_badge.setText(status)

    def set_sub_status(self, status: str):
        """Update subdomain status dot. status: 'gray'|'green'|'amber'|'red'."""
        if self.is_domain or not hasattr(self, '_status_dot'):
            return
        _DOT = {
            "gray":  "background:#555555;",
            "green": "background:#2bda77;box-shadow:0 0 6px #2bda77;",
            "amber": "background:#f5a623;box-shadow:0 0 4px #f5a623;",
            "red":   "background:#e5484d;box-shadow:0 0 4px #e5484d;",
        }
        style = _DOT.get(status, _DOT["gray"])
        self._status_dot.setStyleSheet(f"{style}border-radius:3px;border:none;")

    def set_subdomain_count(self, n: int):
        """Update the subdomain count shown in the domain card meta line."""
        if not self.is_domain:
            return
        self._subdomain_count = n
        try:
            tasks = int(self.task_count_label.text())
        except ValueError:
            tasks = 0
        self._meta_label.setText(
            f"{n} subdomain{'s' if n != 1 else ''} "
            f"\u00b7 {tasks} task{'s' if tasks != 1 else ''}"
        )

    def add_subdomain_row(self, widget: 'SubdomainWidget'):
        """Attach a subdomain widget into this domain's inline sub-container."""
        if self.is_domain:
            self._sub_layout.addWidget(widget)

    def remove_all_subs(self):
        """Remove and delete all subdomain rows from this domain's sub-container."""
        if not self.is_domain:
            return
        while self._sub_layout.count():
            item = self._sub_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _get_tool_statuses(self) -> dict:
        """Return {tool_key: latest_status} for tasks matching this widget's target."""
        statuses = {}
        if not self.parent_tab:
            return statuses
        for td in getattr(self.parent_tab, "tasks", {}).values():
            if td.get("domain", "").lower() == self.subdomain.lower():
                tool = td.get("tool", "")
                if tool:
                    statuses[tool] = td.get("status", "")
        return statuses

    def _task_pfx(self, statuses: dict, tool_key: str) -> str:
        """Return a 2-char prefix icon indicating the task's last known status."""
        s = statuses.get(tool_key, "")
        if s == "completed": return "✓ "
        if s == "running":   return "▶ "
        if s == "error":     return "✗ "
        return "  "

    def _show_domain_task_menu(self):
        """Domain-level recon task menu."""
        st = self._get_tool_statuses()
        p  = lambda k: self._task_pfx(st, k)

        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background-color:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:4px;}}"
            f"QMenu::item{{padding:6px 20px;border-radius:3px;}}"
            f"QMenu::item:selected{{background-color:{COLOR_ACCENT};color:black;}}"
            f"QMenu::separator{{background-color:{COLOR_BORDER};height:1px;margin:3px 8px;}}"
        )

        # ── 📋 Whois ──────────────────────────────────────────────────────
        whois_title = menu.addAction("──  Domain Info ──")
        whois_title.setEnabled(False)
        whois_a = menu.addAction(p("whois") + "Whois Lookup")
        menu.addSeparator()

        # ── 🔎 Dorks ──────────────────────────────────────────────────────
        dorks_title = menu.addAction("──  Dorks & OSINT ──")
        dorks_title.setEnabled(False)
        google_dorks_a   = menu.addAction(p("google_dorks")   + "Google Dorks (dorks_hunter)")
        github_dorks_a   = menu.addAction(p("github_dorks")   + "GitHub Dorks (gitdorks_go)")
        github_secrets_a = menu.addAction(p("github_secrets") + "GitHub Secrets (trufflehog)")
        emails_a         = menu.addAction(p("emails")         + "Email Discovery (emailfinder)")
        metadata_a       = menu.addAction(p("metadata")       + "Metadata Finder (metafinder)")
        menu.addSeparator()

        # ── 🌐 Subdomains ─────────────────────────────────────────────────
        subs_title = menu.addAction("── 🌐 Subdomain Enumeration ──")
        subs_title.setEnabled(False)
        passive_subs_a = menu.addAction(p("passive_subdomains") + "Passive Subdomains (amass+subfinder+crt.sh+findomain)")
        active_subs_a  = menu.addAction(p("active_subdomains")  + "Active Brute-Force (gobuster dns)")
        guess_subs_a   = menu.addAction(p("guess_subdomains")   + "Guess Subdomains (altdns)")
        vhost_a        = menu.addAction(p("vhost")              + "VHost Discovery (ffuf)")
        menu.addSeparator()

        # ── 🎯 Analysis ───────────────────────────────────────────────────
        analysis_title = menu.addAction("──  Subdomains Analysis ──")
        analysis_title.setEnabled(False)
        bypass_a     = menu.addAction(p("bypass_40x")   + "40x Bypass (byp4xx)")
        takeover_a   = menu.addAction(p("takeover")     + "Subdomain Takeover (subjack)")
        svc_scan_a   = menu.addAction(p("service_scan") + "Service Scan (smap)")
        cloud_a      = menu.addAction(p("cloud_enum")   + "Cloud Enum (cloud_enum)")
        screenshot_a = menu.addAction(p("screenshot")   + "Screenshots (eyewitness)")
        menu.addSeparator()

        # ── 📊 Report ─────────────────────────────────────────────────────
        report_title = menu.addAction("── 📊 Report ──")
        report_title.setEnabled(False)
        open_report_a = menu.addAction("📊  Open Domain Report")

        btn_pos = self.menu_btn.mapToGlobal(QPoint(0, self.menu_btn.height()))
        action = menu.exec_(btn_pos)

        mapping = {
            whois_a:          "whois",
            google_dorks_a:   "google_dorks",
            github_dorks_a:   "github_dorks",
            github_secrets_a: "github_secrets",
            emails_a:         "emails",
            metadata_a:       "metadata",
            passive_subs_a:   "passive_subdomains",
            active_subs_a:    "active_subdomains",
            guess_subs_a:     "guess_subdomains",
            vhost_a:          "vhost",
            bypass_a:         "bypass_40x",
            takeover_a:       "takeover",
            svc_scan_a:       "service_scan",
            cloud_a:          "cloud_enum",
            screenshot_a:     "screenshot",
        }

        if action == open_report_a:
            self._open_domain_report()
        elif action in mapping:
            self._run_task(mapping[action])

    def _open_domain_report(self):
        """Open the domain HTML report in the system browser."""
        import subprocess, sys
        domain_dir = os.path.join(self.project_dir, "domains", self.subdomain)
        report_path = os.path.join(domain_dir, "report.html")
        if os.path.isfile(report_path):
            try:
                if sys.platform.startswith("linux"):
                    subprocess.Popen(["xdg-open", report_path])
                elif sys.platform == "darwin":
                    subprocess.Popen(["open", report_path])
                else:
                    subprocess.Popen(["start", report_path], shell=True)
            except Exception as exc:
                from PyQt5.QtWidgets import QMessageBox
                QMessageBox.information(self, "Report", f"Report path:\n{report_path}")
        else:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.information(self, "No Report",
                "No report yet.\nRun at least one domain task to generate it.")

    def _show_task_menu(self):
        st = self._get_tool_statuses()
        p  = lambda k: self._task_pfx(st, k)

        menu = QMenu(self)
        menu.setStyleSheet(
            f"QMenu{{background-color:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:4px;}}"
            f"QMenu::item{{padding:6px 20px;border-radius:3px;}}"
            f"QMenu::item:selected{{background-color:{COLOR_ACCENT};color:black;}}"
            f"QMenu::separator{{background-color:{COLOR_BORDER};height:1px;margin:3px 8px;}}"
        )

        # ── 🕸️ Crawling ──────────────────────────────────────────────────────
        crawl_title = menu.addAction("──  Crawling ──")
        crawl_title.setEnabled(False)
        spider_a  = menu.addAction(p("spider")  + "Spider (gospider + cariddi + katana + linkfinder + paramspider)")
        archive_a = menu.addAction(p("archive") + "Web Archive (wayback + gau + waymore + gauplus)")
        menu.addSeparator()

        # ── 🔍 Recon ─────────────────────────────────────────────────────────
        recon_title = menu.addAction("──  Recon ──")
        recon_title.setEnabled(False)
        ipinfo_a  = menu.addAction(p("ipinfo")  + "IP Info")
        headers_a = menu.addAction(p("headers") + "HTTP Headers")
        tech_a    = menu.addAction(p("tech")    + "Tech Detection (wad)")
        waf_a     = menu.addAction(p("waf")     + "WAF Detection (wafw00f)")
        cms_a     = menu.addAction(p("cms")     + "CMS Detection (cmseek)")
        ports_a   = menu.addAction(p("ports")   + "Port Scan (nmap top-1000 + scripts)")
        menu.addSeparator()

        # ── ⚡ Fuzzing ────────────────────────────────────────────────────────
        fuzz_title = menu.addAction("──  Fuzzing ──")
        fuzz_title.setEnabled(False)
        bruteforce_a = menu.addAction(p("bruteforce") + "Content Bruteforce (feroxbuster + tech wordlists)")
        menu.addSeparator()

        # ── ☢️ Scanning ───────────────────────────────────────────────────────
        scan_title = menu.addAction("──  Vulnerability Scanning ──")
        scan_title.setEnabled(False)
        nuclei_a = menu.addAction(p("nuclei") + "Nuclei (all templates)")
        nikto_a  = menu.addAction(p("nikto")  + "Nikto")
        menu.addSeparator()

        # ── 📰 CMS Scanners ───────────────────────────────────────────────────
        cms_scan_title = menu.addAction("──  CMS Scanners ──")
        cms_scan_title.setEnabled(False)
        wpscan_a   = menu.addAction(p("wpscan")     + "WPScan (WordPress)")
        joomscan_a = menu.addAction(p("joomscan")   + "JoomScan (Joomla)")
        droope_a   = menu.addAction(p("droopescan") + "Droopescan (Drupal)")
        menu.addSeparator()

        # ── 🌿 Enumeration ────────────────────────────────────────────────────
        enum_title = menu.addAction("──  Enumeration ──")
        enum_title.setEnabled(False)
        subs4_a = menu.addAction(p("subdomains4") + "4th-Level Subdomains (amass + subfinder + crt.sh)")

        # Position below the Tasks button
        btn_bottom_left = self.menu_btn.mapToGlobal(QPoint(0, self.menu_btn.height()))
        action = menu.exec_(btn_bottom_left)

        mapping = {
            spider_a:    "spider",
            archive_a:   "archive",
            ipinfo_a:    "ipinfo",
            headers_a:   "headers",
            tech_a:      "tech",
            waf_a:       "waf",
            cms_a:       "cms",
            ports_a:     "ports",
            bruteforce_a:"bruteforce",
            nuclei_a:    "nuclei",
            nikto_a:     "nikto",
            wpscan_a:    "wpscan",
            joomscan_a:  "joomscan",
            droope_a:    "droopescan",
            subs4_a:     "subdomains4",
        }
        if action in mapping:
            self._run_task(mapping[action])

    def _run_task(self, tool_name: str):
        # Get auto-detected cookie from dashboard tab
        prefill = getattr(self.parent_tab, "_last_detected_cookie", "")
        dlg = TaskInputDialog(self.subdomain, tool_name, self.parent_tab,
                              main_window=self.main_window, prefill_cookie=prefill)
        if dlg.exec_() == QDialog.Accepted:
            self.parent_tab.add_task(dlg.get_config())

    def update_task_count(self, count: int):
        if self.is_domain:
            self.task_count_label.setText(str(count))
            n = self._subdomain_count
            self._meta_label.setText(
                f"{n} subdomain{'s' if n != 1 else ''} "
                f"\u00b7 {count} task{'s' if count != 1 else ''}"
            )
            # Auto-update status badge
            if count == 0:
                status = "idle"
            else:
                status = self._domain_status if self._domain_status != "idle" else "active"
            self.set_domain_status(status)
        else:
            self.task_count_label.setText(str(count))
            self.set_sub_status("green" if count > 0 else "gray")


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard Tab
# ─────────────────────────────────────────────────────────────────────────────

class DashboardTab(QWidget):
    """Main dashboard tab for task management."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_window = parent

        # Project dir
        self.project_dir: Optional[str] = None
        if hasattr(parent, "_project_paths") and parent._project_paths:
            self.project_dir = parent._project_paths.get("project_dir")
        if not self.project_dir:
            self.project_dir = os.path.expanduser("~/hackrecon_projects/default")
            os.makedirs(self.project_dir, exist_ok=True)

        # Current scope context
        self._current_slug      = ""
        self._current_domain    = ""
        self._current_subdomain = ""
        self._selected_target   = None
        self._selected_widget   = None
        self._selected_is_domain = False

        # Cookie state
        self._last_detected_cookie = ""

        # Task management
        self.tasks:              Dict[str, Dict[str, Any]] = {}
        self.task_widgets:       Dict[str, TaskWidget]     = {}
        self.task_workers:       Dict[str, TaskWorker]     = {}
        self.target_task_counts: Dict[str, int]            = {}
        self.plan_orchestrators: Dict[str, MultiTaskOrchestrator] = {}
        self.domain_widgets:     Dict[str, SubdomainWidget] = {}
        self.subdomain_widgets:     Dict[str, SubdomainWidget] = {}

        # Currently selected task for inline output viewer
        self._viewed_task_id: Optional[str] = None

        self._setup_ui()

        # Do NOT call load_tasks() here — update_scope() will call it after
        # subdomain_widgets are populated from scope, ensuring correct filtering.

        # Periodic save
        self._save_timer = QTimer(self)
        self._save_timer.timeout.connect(self.save_tasks)
        self._save_timer.start(30_000)

        # Connect to scope tab — scope_tab is guaranteed to exist before DashboardTab
        # is constructed (hunt_gui creates scope_tab first now)
        if hasattr(parent, "scope_tab"):
            parent.scope_tab.scope_changed.connect(self.update_scope)
        else:
            # Defensive fallback: poll until scope_tab exists then connect
            self._scope_connect_timer = QTimer(self)
            self._scope_connect_timer.timeout.connect(self._try_connect_scope)
            self._scope_connect_timer.start(100)

        # Fallback initial load — fires if scope_tab emitted before we connected
        # (shouldn't happen with new ordering, but kept as safety net)
        QTimer.singleShot(800, self._initial_scope_load)

        # Background cookie monitor (polls every 15 s)
        self._cookie_poll_timer = QTimer(self)
        self._cookie_poll_timer.timeout.connect(self._poll_for_login_cookie)
        self._cookie_poll_timer.start(15_000)

        # Traffic-based auto-discovery: scan findings for new in-scope hosts every 10 s
        self._traffic_scan_timer = QTimer(self)
        self._traffic_scan_timer.timeout.connect(self.refresh_from_traffic)
        self._traffic_scan_timer.start(10_000)

        # Traffic-based subdomain auto-discovery (polls every 5 s)
        # Watches HTTP history findings and adds any in-scope hostnames not yet shown
        self._traffic_seen_hosts: set = set()   # hosts we've already added
        self._traffic_monitor_timer = QTimer(self)
        self._traffic_monitor_timer.timeout.connect(self._poll_traffic_hosts)
        self._traffic_monitor_timer.start(5_000)

    # ─────────────────────────────────────────────────────────────────────────
    # UI
    # ─────────────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        header = QWidget()
        header.setStyleSheet(f"background-color:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        header.setMaximumHeight(56)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 6, 16, 6)

        title = QLabel("📊 Task Dashboard")
        title.setStyleSheet(f"color:{COLOR_ACCENT};font-weight:bold;font-size:{FONT_SIZE_LARGE};")
        hl.addWidget(title)

        hl.addStretch()

        # Cookie status indicator
        self._cookie_badge = QLabel("")
        self._cookie_badge.setStyleSheet(f"color:{COLOR_SUCCESS};font-size:{FONT_SIZE_SMALL};")
        hl.addWidget(self._cookie_badge)

        detect_cookie_btn = QPushButton("🔍 Detect Cookie")
        detect_cookie_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:4px 10px;border-radius:4px;}}"
            f"QPushButton:hover{{background-color:{COLOR_HOVER};}}"
        )
        detect_cookie_btn.clicked.connect(self._manual_cookie_detect)
        hl.addWidget(detect_cookie_btn)

        multi_task_btn = QPushButton("⚡ Multi-Task")
        multi_task_btn.setToolTip("Build and run a multi-task plan with parallel groups")
        multi_task_btn.setStyleSheet(
            f"QPushButton{{background-color:#5533FF;color:white;font-weight:bold;"
            f"padding:5px 12px;border:none;border-radius:4px;}}"
            f"QPushButton:hover{{background-color:#7755FF;}}"
        )
        multi_task_btn.clicked.connect(self._open_multi_task_dialog)
        hl.addWidget(multi_task_btn)

        add_subdomain_btn = QPushButton("✚ Add Subdomain")
        add_subdomain_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_SUCCESS};color:black;font-weight:bold;"
            f"padding:5px 12px;border:none;border-radius:4px;}}"
            f"QPushButton:hover{{background-color:#00FF8C;}}"
        )
        add_subdomain_btn.clicked.connect(self._add_subdomain_dialog)
        hl.addWidget(add_subdomain_btn)

        traffic_btn = QPushButton("↻ Refresh")
        traffic_btn.setToolTip(
            "Refresh targets from HTTP history (adds in-scope hosts)"
        )
        traffic_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};padding:5px 12px;border-radius:4px;font-weight:600;}}"
            f"QPushButton:hover{{background-color:{COLOR_ACCENT};color:black;}}"
        )
        traffic_btn.clicked.connect(self.on_refresh_clicked)
        hl.addWidget(traffic_btn)

        root.addWidget(header)

        # ── Main horizontal splitter ──────────────────────────────────────────
        outer_splitter = QSplitter(Qt.Horizontal)
        outer_splitter.setHandleWidth(4)
        outer_splitter.setStyleSheet(
            f"QSplitter::handle:horizontal{{background-color:{COLOR_BORDER};}}"
            f"QSplitter::handle:horizontal:hover{{background-color:{COLOR_ACCENT};}}"
        )

        # ── Left: Subdomains panel ────────────────────────────────────────────
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(0)

        # ── Targets panel (unified accordion) ────────────────────────────────
        targets_hdr = QWidget()
        targets_hdr.setStyleSheet(
            f"background-color:{COLOR_DARK_BG};"
            f"border-bottom:1px solid {COLOR_BORDER};"
        )
        targets_hdr.setMaximumHeight(32)
        tgt_hl = QHBoxLayout(targets_hdr)
        tgt_hl.setContentsMargins(12, 6, 12, 6)
        tgt_hl.addWidget(QLabel("🌐 Targets"))
        tgt_hl.addStretch()
        self._domain_count_label = QLabel("0")
        self._domain_count_label.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:{FONT_SIZE_SMALL};"
        )
        tgt_hl.addWidget(self._domain_count_label)
        # Keep a ref so existing code updating subdomain count doesn't crash
        self._subdomain_count_label = QLabel("0")
        self._subdomain_count_label.hide()
        ll.addWidget(targets_hdr)

        targets_scroll = QScrollArea()
        targets_scroll.setWidgetResizable(True)
        targets_scroll.setStyleSheet(
            "QScrollArea{background-color:#1e1e1e;border:none;}"
        )
        self._targets_container = QWidget()
        self._targets_container.setStyleSheet("background:#1e1e1e;")
        self._targets_layout = QVBoxLayout(self._targets_container)
        self._targets_layout.setContentsMargins(8, 8, 8, 8)
        self._targets_layout.setSpacing(6)
        self._targets_layout.addStretch()
        targets_scroll.setWidget(self._targets_container)
        ll.addWidget(targets_scroll, stretch=1)

        left.setMinimumWidth(280)
        outer_splitter.addWidget(left)

        # ── Right: Tasks + Output ─────────────────────────────────────────────
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)

        # ── Tasks header ──────────────────────────────────────────────────
        tasks_hdr = QWidget()
        tasks_hdr.setStyleSheet(
            f"background-color:{COLOR_DARK_BG};border-bottom:1px solid {COLOR_BORDER};"
        )
        tasks_hdr.setMaximumHeight(38)
        thl = QHBoxLayout(tasks_hdr)
        thl.setContentsMargins(12, 6, 12, 6)
        hdr_title = QLabel("⚙️ Tasks")
        hdr_title.setStyleSheet("color:#f0f0f0;font-weight:600;font-size:11px;border:none;")
        thl.addWidget(hdr_title)
        thl.addStretch()

        self._tasks_stats_label = QLabel("")
        self._tasks_stats_label.setStyleSheet("color:#888888;font-size:10px;border:none;")
        thl.addWidget(self._tasks_stats_label)

        clear_btn = QPushButton("🗑️")
        clear_btn.setFixedSize(26, 26)
        clear_btn.setToolTip("Clear completed / errored tasks")
        clear_btn.setStyleSheet(
            "QPushButton{background:#2d2d2d;border:1px solid #3c3f41;"
            "border-radius:6px;font-size:12px;padding:0;}"
            "QPushButton:hover{background:#3c3f41;border-color:#e5484d;}"
        )
        clear_btn.clicked.connect(self._clear_completed)
        thl.addWidget(clear_btn)

        rl.addWidget(tasks_hdr)

        # ── Pill filter row ───────────────────────────────────────────────
        filter_bar = QWidget()
        filter_bar.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};"
            f"border:1px solid {COLOR_BORDER};"
            f"border-radius:10px;"
        )
        filter_bar.setMaximumHeight(44)
        fbl = QHBoxLayout(filter_bar)
        fbl.setContentsMargins(10, 6, 10, 6)
        fbl.setSpacing(6)

        self._filter_pills: Dict[str, QPushButton] = {}
        _pill_labels = ["All Tasks", "Running", "Completed", "Pending", "Errors"]
        for label in _pill_labels:
            btn = QPushButton(label)
            btn.setStyleSheet(
                "QPushButton{background:#1e1e1e;border:1px solid #3c3f41;"
                "padding:4px 14px;border-radius:12px;font-size:11px;"
                "font-weight:500;color:#888888;}"
                "QPushButton:hover{background:#2d2d2d;color:#f0f0f0;border-color:#5a5d60;}"
            )
            btn.clicked.connect(lambda checked, l=label: self._on_filter_pill(l))
            fbl.addWidget(btn)
            self._filter_pills[label] = btn
        fbl.addStretch()

        # Fake QComboBox kept for backward-compat (currentText used in _on_target_selected)
        self._task_filter = QComboBox()
        self._task_filter.addItems(_pill_labels)
        self._task_filter.hide()
        self._task_filter.currentTextChanged.connect(self._filter_tasks)

        rl.addWidget(filter_bar)

        # Activate "All Tasks" pill by default
        self._on_filter_pill("All Tasks")

        # Vertical splitter: tasks list / output viewer
        right_vsplit = QSplitter(Qt.Vertical)
        right_vsplit.setHandleWidth(5)
        right_vsplit.setStyleSheet(
            f"QSplitter::handle:vertical{{background-color:{COLOR_BORDER};}}"
            f"QSplitter::handle:vertical:hover{{background-color:{COLOR_ACCENT};}}"
        )

        # Tasks scroll
        tasks_scroll = QScrollArea()
        tasks_scroll.setWidgetResizable(True)
        tasks_scroll.setStyleSheet("QScrollArea{background-color:#141414;border:none;}")
        self._tasks_container = QWidget()
        self._tasks_container.setStyleSheet("QWidget{background-color:#141414;}")
        self._tasks_layout = QVBoxLayout(self._tasks_container)
        self._tasks_layout.setContentsMargins(8, 8, 8, 8)
        self._tasks_layout.setSpacing(6)
        self._tasks_layout.addStretch()
        tasks_scroll.setWidget(self._tasks_container)
        right_vsplit.addWidget(tasks_scroll)

        # Output viewer panel
        output_panel = QWidget()
        output_panel.setStyleSheet(
            f"QWidget{{background-color:{COLOR_DARK_BG};border-top:2px solid {COLOR_BORDER};}}"
        )
        opl = QVBoxLayout(output_panel)
        opl.setContentsMargins(0, 0, 0, 0)
        opl.setSpacing(0)

        out_hdr = QWidget()
        out_hdr.setStyleSheet(f"background-color:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        out_hdr.setMaximumHeight(32)
        ohl = QHBoxLayout(out_hdr)
        ohl.setContentsMargins(12, 4, 12, 4)

        self._output_title = QLabel("Task Output")
        self._output_title.setStyleSheet(f"color:{COLOR_ACCENT};font-weight:bold;font-size:{FONT_SIZE_SMALL};")
        ohl.addWidget(self._output_title)
        ohl.addStretch()

        copy_btn = QPushButton("📋 Copy")
        copy_btn.setMaximumWidth(70)
        copy_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:2px 6px;font-size:{FONT_SIZE_SMALL};}}"
            f"QPushButton:hover{{background-color:{COLOR_HOVER};}}"
        )
        copy_btn.clicked.connect(self._copy_output)
        ohl.addWidget(copy_btn)

        copy_path_btn = QPushButton("📋 Copy Path")
        copy_path_btn.setMaximumWidth(90)
        copy_path_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:2px 6px;font-size:{FONT_SIZE_SMALL};}}"
            f"QPushButton:hover{{background-color:{COLOR_HOVER};}}"
        )
        copy_path_btn.clicked.connect(self._copy_output_path)
        ohl.addWidget(copy_path_btn)

        open_file_btn = QPushButton("☰ Open File")
        open_file_btn.setMaximumWidth(85)
        open_file_btn.setStyleSheet(
            f"QPushButton{{background-color:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};padding:2px 6px;font-size:{FONT_SIZE_SMALL};}}"
            f"QPushButton:hover{{background-color:{COLOR_HOVER};}}"
        )
        open_file_btn.clicked.connect(self._open_output_file)
        ohl.addWidget(open_file_btn)

        opl.addWidget(out_hdr)

        self._output_viewer = QTextEdit()
        self._output_viewer.setReadOnly(True)
        self._output_viewer.setFont(QFont(FONT_FAMILY_MONO, 9))
        self._output_viewer.setLineWrapMode(QTextEdit.NoWrap)
        self._output_viewer.setStyleSheet(
            f"QTextEdit{{background-color:{COLOR_DARK_BG};color:{COLOR_TEXT};"
            f"border:none;font-family:{FONT_FAMILY_MONO};}}"
        )
        self._output_viewer.setPlaceholderText(
            "Select a task and click '📄 View Output' to see results here…"
        )
        opl.addWidget(self._output_viewer)
        right_vsplit.addWidget(output_panel)

        right_vsplit.setSizes([300, 400])
        rl.addWidget(right_vsplit)

        right.setMinimumWidth(500)
        outer_splitter.addWidget(right)
        outer_splitter.setSizes([320, 900])

        root.addWidget(outer_splitter)

        # ── Status bar (compact, single line) ────────────────────────────────
        status_strip = QWidget()
        status_strip.setFixedHeight(22)
        status_strip.setStyleSheet(
            f"background-color:{COLOR_ELEVATED_BG};"
            f"border-top:1px solid {COLOR_BORDER};"
        )
        ssl = QHBoxLayout(status_strip)
        ssl.setContentsMargins(10, 0, 10, 0)
        ssl.setSpacing(12)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(f"color:{COLOR_TEXT_MUTED};font-size:{FONT_SIZE_SMALL};")
        ssl.addWidget(self._status_label)

        ssl.addStretch()

        self._stats_label = QLabel("")
        self._stats_label.setStyleSheet(f"color:{COLOR_ACCENT};font-size:{FONT_SIZE_SMALL};")
        ssl.addWidget(self._stats_label)

        root.addWidget(status_strip)

    # ─────────────────────────────────────────────────────────────────────────
    # Scope integration
    # ─────────────────────────────────────────────────────────────────────────

    def _try_connect_scope(self):
        """Defensive: keep trying to connect scope_changed until scope_tab exists."""
        pw = self.parent_window
        if pw and hasattr(pw, "scope_tab"):
            pw.scope_tab.scope_changed.connect(self.update_scope)
            self._scope_connect_timer.stop()
            # Now do initial load since we may have missed the first emission
            self._initial_scope_load()

    def _initial_scope_load(self):
        """Fallback load: fires if scope signal was missed or fired before connection."""
        pw = self.parent_window
        if not pw or not hasattr(pw, "_project_slug"):
            return
        # Already loaded via signal — don't double-load
        if self._current_slug:
            return
        slug = getattr(pw, "_project_slug", "")
        if slug:
            self.update_scope(
                slug,
                getattr(pw, "_project_domain", ""),
                getattr(pw, "_project_subdomain", ""),
            )

    def update_scope(self, slug: str, domain: str, subdomain: str):
        """Called when scope changes in ScopeTab. Rebuilds domain list and reloads tasks."""
        self._current_slug      = slug
        self._current_domain    = domain
        self._current_subdomain = subdomain

        # Update project_dir to match the new slug
        if slug:
            import project_manager as pm
            pm.ensure_project_dirs(slug)
            paths = pm.get_project_paths(slug)
            self.project_dir = paths["project_dir"]

        self._clear_targets_ui()
        # Also clear loaded tasks so load_tasks re-reads from the correct file
        self._clear_tasks_ui()
        # Reset traffic discovery so new scope re-scans history
        self._traffic_seen_hosts = set()

        if not slug:
            self._set_status("No project selected.")
            return

        import project_manager as pm

        # Logic 1: Program as target (slug set, domain="", subdomain="")
        if slug and not domain and not subdomain:
            # Add all domains of this program to Domain Level
            all_domains = pm.list_domains(slug)
            for d in all_domains:
                self._add_domain_widget(d)
            
            # Add all subdomains of all domains to Subdomain Level
            for d in all_domains:
                subs = pm.list_subdomains(slug, d)
                for s in subs:
                    self._add_subdomain_widget(s)

        # Logic 2: Domain as target (slug set, domain set, subdomain="")
        elif slug and domain and not subdomain:
            # Add this domain to Domain Level
            self._add_domain_widget(domain)
            
            # Add all subdomains of this domain to Subdomain Level
            subs = pm.list_subdomains(slug, domain)
            for s in subs:
                self._add_subdomain_widget(s)

        # Logic 3: Subdomain as target (slug set, domain set, subdomain set)
        elif slug and subdomain:
            # Add the domain of this subdomain to Domain Level
            if domain:
                self._add_domain_widget(domain)
            # Add this subdomain to Subdomain Level
            self._add_subdomain_widget(subdomain)

        self._update_target_counts()
        self._refresh_domain_subdomain_counts()

        # Now load tasks filtered to the current scope domains
        self.load_tasks()
        self._update_stats()
        self._set_status(f"Scope updated.")

        # Immediately scan traffic for any already-seen in-scope hosts
        QTimer.singleShot(200, self.refresh_from_traffic)

    # ─────────────────────────────────────────────────────────────────────────
    # Subdomain management
    # ─────────────────────────────────────────────────────────────────────────

    def _add_subdomain_dialog(self):
        subdomain, ok = QInputDialog.getText(
            self, "Add Subdomain", "Enter subdomain (e.g., api.example.com):"
        )
        if ok and subdomain:
            subdomain = subdomain.strip()
            if subdomain.startswith(("http://", "https://")):
                from urllib.parse import urlparse
                parsed = urlparse(subdomain)
                subdomain = parsed.netloc or parsed.path
            self._add_subdomain_widget(subdomain)
            self._update_target_counts()

    def _adjust_domains_height(self):
        """No-op: kept for compatibility; splitter replaced by unified scroll area."""
        pass

    def _add_domain_widget(self, domain: str):
        if domain in self.domain_widgets:
            return
        w = SubdomainWidget(domain, self.project_dir, parent_tab=self, main_window=self.parent_window,
                            is_domain=True)
        w.clicked.connect(self._on_target_selected)
        self._targets_layout.insertWidget(self._targets_layout.count() - 1, w)
        self.domain_widgets[domain] = w
        count = self.target_task_counts.get(domain, 0)
        w.update_task_count(count)

    def _refresh_domain_subdomain_counts(self):
        """Update every domain widget's subdomain count badge from current subdomain_widgets."""
        for domain, dw in self.domain_widgets.items():
            n = sum(
                1 for sub in self.subdomain_widgets
                if sub.endswith("." + domain) or sub == domain
            )
            dw.set_subdomain_count(n)

    def _add_subdomain_widget(self, subdomain: str):
        if subdomain in self.subdomain_widgets:
            return
        w = SubdomainWidget(subdomain, self.project_dir, parent_tab=self, main_window=self.parent_window)
        w.clicked.connect(self._on_target_selected)

        # Attach inline under the parent domain if possible, otherwise fall back to targets layout
        parent_domain = next(
            (d for d in self.domain_widgets if subdomain.endswith("." + d) or subdomain == d),
            None
        )
        if parent_domain and parent_domain in self.domain_widgets:
            self.domain_widgets[parent_domain].add_subdomain_row(w)
        else:
            self._targets_layout.insertWidget(self._targets_layout.count() - 1, w)

        self.subdomain_widgets[subdomain] = w
        count = self.target_task_counts.get(subdomain, 0)
        w.update_task_count(count)
        self._refresh_domain_subdomain_counts()

    def _clear_targets_ui(self):
        for w in list(self.domain_widgets.values()):
            w.remove_all_subs()
            w.deleteLater()
        self.domain_widgets.clear()

        # Any orphan subdomain widgets (not under a domain) live in _targets_layout
        for w in list(self.subdomain_widgets.values()):
            if w.parent() is not None and w.parent().parent() is self._targets_container:
                w.deleteLater()
        self.subdomain_widgets.clear()
        self._selected_target = None
        self._selected_widget = None

    def _clear_tasks_ui(self):
        """Remove all task widgets from UI and clear in-memory state (workers stopped first)."""
        for worker in list(self.task_workers.values()):
            worker.stop()
            worker.wait(1000)
        self.task_workers.clear()

        for w in list(self.task_widgets.values()):
            w.deleteLater()
        self.task_widgets.clear()
        self.tasks.clear()
        self.target_task_counts.clear()

        self._viewed_task_id = None
        self._output_viewer.clear()
        self._output_title.setText("Task Output")

    def _update_target_counts(self):
        nd = len(self.domain_widgets)
        ns = len(self.subdomain_widgets)
        total = nd + ns
        self._domain_count_label.setText(f"{total}")
        # Keep hidden label in sync for any code that reads it
        self._subdomain_count_label.setText(f"{ns}")

    def _is_host_in_current_scope(self, host: str) -> bool:
        """Check if host matches both project scope rules AND current view selection."""
        import project_manager as pm
        
        # 1. Check global project scope rules (includes/excludes)
        if not pm.is_host_in_scope(self._current_slug, host):
            return False
            
        # 2. Check view filters (if user drilled down to a specific domain/subdomain)
        if self._current_subdomain:
            return host == self._current_subdomain
        if self._current_domain:
            return host == self._current_domain or host.endswith("." + self._current_domain)
            
        return True

    def on_refresh_clicked(self):
        """Manual refresh: clear UI, reload from project, then scan traffic."""
        self.update_scope(self._current_slug, self._current_domain, self._current_subdomain)

    def refresh_from_traffic(self):
        """
        Scan HTTP history for hosts that are in the current scope but not yet
        shown in the left panel, and add them automatically — like the sitemap.

        This gives you live discovery: as you browse through the proxy, new
        subdomains appear in the dashboard ready to run tasks against.
        """
        pw = self.parent_window
        if not pw or not self._current_slug:
            return
        if not hasattr(pw, "findings") or not pw.findings:
            return

        import project_manager as pm
        # Get list of defined domains in the project to categorize correctly
        project_domains = set(pm.list_domains(self._current_slug))

        findings = list(pw.findings)   # snapshot
        seen_hosts: set = set()

        for finding in findings:
            url = finding.get("url", "")
            if not url:
                continue
            try:
                host = _safe_urlparse_host(url)
            except Exception:
                continue
            if not host:
                continue
            # Only add hosts that are in scope
            if not self._is_host_in_current_scope(host):
                continue
            
            # Add to set for processing
            seen_hosts.add(host)

        added = 0
        for host in sorted(seen_hosts):
            # Check if it's already displayed
            if host in self.domain_widgets or host in self.subdomain_widgets:
                continue

            # Decide where to add it
            if host in project_domains:
                # It's a known project domain -> add to Domains panel
                self._add_domain_widget(host)
            else:
                # It's a subdomain or discovered host -> add to Subdomains panel
                self._add_subdomain_widget(host)
            
            self._traffic_seen_hosts.add(host)
            added += 1

        if added:
            self._update_target_counts()
            self._set_status(f"🗺️ {added} new host{'s' if added != 1 else ''} discovered from traffic.")



    # ─────────────────────────────────────────────────────────────────────────
    # Task management
    # ─────────────────────────────────────────────────────────────────────────

    def add_task(self, config: Dict[str, Any], return_id: bool = False):
        """Create and start a new task. If return_id=True, returns the task_id string."""
        tool   = config["tool"]
        domain = config["domain"]

        # Build a stable, human-readable task ID keyed to scope + tool + domain
        slug   = _safe_slug(domain)
        # ts     = int(time.time() * 1000) # REMOVED: User wants overwriteable tasks
        task_id = f"{_safe_slug(tool)}_{slug}"

        # Auto-set proxy only when the key is completely absent from config.
        # If the key exists but is empty (""), the user explicitly unchecked
        # "Use Proxy" in the dialog — respect that and do not inject.
        if "proxy" not in config:
            pw = self.parent_window
            if pw and getattr(pw, "proxy_running", False):
                config["proxy"] = f"http://127.0.0.1:{pw.proxy_port}"

        # Auto-set github_token from global settings if not provided
        if "github_token" not in config or not config.get("github_token"):
            if hasattr(self.parent_window, "_global_settings"):
                global_token = self.parent_window._global_settings.get("github_token", "")
                if global_token:
                    config["github_token"] = global_token

        # Auto-set tools_dir from global settings
        if "tools_dir" not in config:
            default_tools = os.path.expanduser("~/tools")
            if hasattr(self.parent_window, "_global_settings"):
                config["tools_dir"] = self.parent_window._global_settings.get("tools_dir", default_tools)
            else:
                config["tools_dir"] = default_tools

        # Auto-set seclists_dir from global settings
        if "seclists_dir" not in config:
            if hasattr(self.parent_window, "_global_settings"):
                config["seclists_dir"] = self.parent_window._global_settings.get("seclists_dir", "")

        # Determine output file path: tasks/<task_id>/output.log
        task_dir    = os.path.join(self.project_dir, "tasks", task_id)
        output_file = os.path.join(task_dir, "output.log")
        os.makedirs(task_dir, exist_ok=True)

        task_data: Dict[str, Any] = {
            "id":           task_id,
            "domain":       domain,
            "tool":         tool,
            "cookie":       config.get("cookie", ""),
            "proxy":        config.get("proxy", ""),
            "input_file":   config.get("input_file", ""),
            "status":       "pending",
            "status_message": "Queued",
            "timestamp":    datetime.now().isoformat(),
            "output_file":  output_file,
            "output_content": "",
            # Scope context so we can reload per-target
            # Config may override scope to associate the task with a specific host
            # (e.g. when launched from HTTP history for a particular subdomain).
            "scope_slug":      config.get("scope_slug",      self._current_slug),
            "scope_domain":    config.get("scope_domain",    self._current_domain),
            "scope_subdomain": config.get("scope_subdomain", self._current_subdomain),
            # Optional per-task fields forwarded from the task config dialog
            "wordlist":        config.get("wordlist", ""),
            "github_token":    config.get("github_token", ""),
            "censys_id":       config.get("censys_id", ""),
            "censys_secret":   config.get("censys_secret", ""),
            "proxy_replay":    config.get("proxy_replay", False),
            "proxy_replay_codes": config.get("proxy_replay_codes", []),
            "auth_headers":    config.get("auth_headers", []),
            "manual_techs":    config.get("manual_techs", []),
            "filter_codes":    config.get("filter_codes", None),
            "tools_dir":       config.get("tools_dir", os.path.expanduser("~/tools")),
            "seclists_dir":    config.get("seclists_dir", ""),
        }

        self.tasks[task_id] = task_data

        widget = TaskWidget(task_data, self.project_dir)
        widget.remove_requested.connect(self.remove_task)
        widget.show_output_requested.connect(self.show_task_output)
        self._tasks_layout.insertWidget(self._tasks_layout.count() - 1, widget)
        self.task_widgets[task_id] = widget

        # Update subdomain badge.
        # domain may be "host/path/" for path-specific tasks (e.g. content
        # bruteforce launched from HTTP history). In that case fall back to
        # the hostname portion so the correct widget badge is updated.
        self.target_task_counts[domain] = self.target_task_counts.get(domain, 0) + 1
        badge_domain = domain
        if domain not in self.subdomain_widgets and domain not in self.domain_widgets:
            host_only = domain.split("/")[0]
            if host_only and host_only != domain:
                badge_domain = host_only
                self.target_task_counts[badge_domain] = (
                    self.target_task_counts.get(badge_domain, 0) + 1
                )
        if badge_domain in self.subdomain_widgets:
            self.subdomain_widgets[badge_domain].update_task_count(
                self.target_task_counts[badge_domain]
            )
        elif badge_domain in self.domain_widgets:
            self.domain_widgets[badge_domain].update_task_count(
                self.target_task_counts[badge_domain]
            )

        self.save_tasks()
        self._execute_task(task_id)
        self._update_stats()
        self._set_status(f"✅ {tool.title()} queued for {domain}")
        if return_id:
            return task_id

    def _execute_task(self, task_id: str):
        task_data = self.tasks.get(task_id)
        if not task_data:
            return
        task_data["status"] = "running"
        task_data["status_message"] = "Starting…"
        if task_id in self.task_widgets:
            self.task_widgets[task_id].update_status("running", "Starting…")

        worker = TaskWorker(task_data, self.project_dir)
        worker.output_received.connect(self._on_task_output)
        worker.status_changed.connect(self._on_task_status_change)
        worker.task_completed.connect(self._on_task_completed)
        self.task_workers[task_id] = worker
        worker.start()
        self.save_tasks()
        self._update_stats()

    def _on_task_output(self, task_id: str, line: str):
        task_data = self.tasks.get(task_id)
        if task_data:
            current = task_data.get("output_content", "")
            new_content = current + line + "\n"
            # Keep last 10 000 lines
            lines = new_content.split("\n")
            if len(lines) > 10_000:
                new_content = "\n".join(lines[-10_000:])
            task_data["output_content"] = new_content

            # Live-stream to inline viewer if this task is selected
            if self._viewed_task_id == task_id:
                self._output_viewer.append(line)

    def _on_task_status_change(self, task_id: str, status: str, message: str):
        task_data = self.tasks.get(task_id)
        if task_data:
            task_data["status"] = status
            task_data["status_message"] = message
        if task_id in self.task_widgets:
            self.task_widgets[task_id].update_status(status, message)
        self.save_tasks()
        self._update_stats()

    def _on_task_completed(self, task_id: str, success: bool, output_file: str):
        task_data = self.tasks.get(task_id)
        if task_data:
            if output_file:
                task_data["output_file"] = output_file
            if task_id in self.task_widgets:
                self.task_widgets[task_id].update_status(
                    task_data.get("status", "completed"),
                    task_data.get("status_message", "")
                )
        self.task_workers.pop(task_id, None)
        self.save_tasks()
        self._update_stats()

    def remove_task(self, task_id: str):
        if task_id in self.task_workers:
            self.task_workers[task_id].stop()
            self.task_workers[task_id].wait(2000)
            del self.task_workers[task_id]

        task_data = self.tasks.pop(task_id, {})
        domain = task_data.get("domain")
        if domain:
            self.target_task_counts[domain] = max(0, self.target_task_counts.get(domain, 0) - 1)
            if domain in self.subdomain_widgets:
                self.subdomain_widgets[domain].update_task_count(self.target_task_counts[domain])
            elif domain in self.domain_widgets:
                self.domain_widgets[domain].update_task_count(self.target_task_counts[domain])

        if task_id in self.task_widgets:
            self.task_widgets[task_id].deleteLater()
            del self.task_widgets[task_id]

        if self._viewed_task_id == task_id:
            self._viewed_task_id = None
            self._output_viewer.clear()
            self._output_title.setText("📄 Task Output")

        self.save_tasks()
        self._update_stats()

    def show_task_output(self, task_id: str):
        """Display the output of task_id in the inline viewer."""
        task_data = self.tasks.get(task_id)
        if not task_data:
            return

        self._viewed_task_id = task_id
        tool   = task_data.get("tool", "")
        domain = task_data.get("domain", "")
        self._output_title.setText(f"Output — {tool.title()} on {domain}")

        # Prefer live content; fall back to reading the output file
        content = task_data.get("output_content", "")
        if not content:
            output_file = task_data.get("output_file", "")
            if output_file and os.path.exists(output_file):
                try:
                    with open(output_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                    task_data["output_content"] = content
                except Exception as e:
                    content = f"Error loading file: {e}"

        self._output_viewer.setPlainText(content)
        self._output_viewer.moveCursor(QTextCursor.End)

    # ─────────────────────────────────────────────────────────────────────────
    # Output panel helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _copy_output(self):
        text = self._output_viewer.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            self._set_status("📋 Output copied to clipboard.")

    def _copy_output_path(self):
        if not self._viewed_task_id:
            return
        task_data = self.tasks.get(self._viewed_task_id, {})
        path = task_data.get("output_file", "")
        if path:
            QApplication.clipboard().setText(path)
            self._set_status(f"📁 Path copied: {path}")
        else:
            self._set_status("No output file path available.")

    def _open_output_file(self):
        if not self._viewed_task_id:
            return
        task_data = self.tasks.get(self._viewed_task_id, {})
        out = task_data.get("output_file", "")
        if out and os.path.exists(out):
            QDesktopServices.openUrl(QUrl.fromLocalFile(out))
        else:
            self._set_status("No output file available yet.")

    # ─────────────────────────────────────────────────────────────────────────
    # Traffic-based subdomain auto-discovery
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_traffic_hosts(self):
        """
        Scan HTTP history every 5 s and auto-add any in-scope hostnames
        not yet shown in the left panel — exactly like the sitemap in HTTP History.

        Logic:
          1. Get current scope hosts from project_manager.
          2. For each finding in parent.findings, parse the URL host.
          3. If the host is in scope AND not yet in subdomain_widgets, add it.
          4. Track added hosts in _traffic_seen_hosts so we only process each once.
        """
        if not self._current_slug:
            return
        pw = self.parent_window
        if not pw or not hasattr(pw, "findings") or not pw.findings:
            return

        # Collect all hosts seen in traffic
        new_hosts = set()
        for finding in pw.findings:
            url = finding.get("url", "")
            if not url:
                continue
            try:
                host = _safe_urlparse_host(url)
                if not host:
                    continue
                # Only care about hosts in current scope
                if not self._is_host_in_current_scope(host):
                    continue
                # Already processed or already in panel
                if (host in self._traffic_seen_hosts or 
                    host in self.subdomain_widgets or 
                    host in self.domain_widgets):
                    continue
                new_hosts.add(host)
            except Exception:
                continue

        if not new_hosts:
            return

        # Add new hostnames to the panel (sorted for consistent display)
        added = 0
        for host in sorted(new_hosts):
            self._traffic_seen_hosts.add(host)
            if host not in self.subdomain_widgets and host not in self.domain_widgets:
                self._add_subdomain_widget(host)
                added += 1

        if added:
            self._update_target_counts()
            self._set_status(f"🌐 {added} new host{'s' if added != 1 else ''} discovered from traffic.")

    # ─────────────────────────────────────────────────────────────────────────
    # Cookie detection
    # ─────────────────────────────────────────────────────────────────────────

    def _poll_for_login_cookie(self):
        """Background poll: silently check for new login cookies every 15 s."""
        pw = self.parent_window
        if not pw or not hasattr(pw, "findings") or not pw.findings:
            return
        # Don't spawn a new thread if the previous one is still running
        if hasattr(self, "_detector") and self._detector and self._detector.isRunning():
            return
        import project_manager as pm
        scope_hosts = pm.get_scope_hosts(
            self._current_slug, self._current_domain, self._current_subdomain
        )
        self._detector = CookieDetectorThread(pw.findings, scope_hosts=scope_hosts, parent=self)
        self._detector.cookie_found.connect(self._on_background_cookie_found)
        self._detector.start()

    def _on_background_cookie_found(self, cookie_val: str, url: str):
        """Background cookie detected — show badge but don't auto-prompt."""
        if cookie_val == self._last_detected_cookie:
            return
        self._last_detected_cookie = cookie_val
        self._cookie_badge.setText("Cookie detected")
        self._cookie_badge.setToolTip(
            f"Login cookie detected from: {url}\nClick 'Detect Cookie' to use it."
        )

    def _manual_cookie_detect(self):
        """User explicitly triggers cookie detection and gets the prompt."""
        pw = self.parent_window
        if not pw or not hasattr(pw, "findings") or not pw.findings:
            QMessageBox.information(self, "No History", "No requests in HTTP History yet.")
            return
        import project_manager as pm
        scope_hosts = pm.get_scope_hosts(
            self._current_slug, self._current_domain, self._current_subdomain
        )
        self._manual_detector = CookieDetectorThread(pw.findings, scope_hosts=scope_hosts, parent=self)
        self._manual_detector.cookie_found.connect(self._on_manual_cookie_found)
        self._manual_detector.finished.connect(self._on_manual_detector_done)
        self._no_cookie_found = True
        self._manual_detector.start()

    def _on_manual_cookie_found(self, cookie_val: str, url: str):
        self._no_cookie_found = False
        dlg = CookiePromptDialog(cookie_val, url, self)
        if dlg.exec_() == QDialog.Accepted:
            if dlg.choice in (CookiePromptDialog.USE_COOKIE, CookiePromptDialog.CHANGE):
                self._last_detected_cookie = dlg.final_cookie
                self._cookie_badge.setText("🍪 Cookie active")
                self._set_status("Cookie saved — it will be pre-filled in new tasks.")
            else:
                self._last_detected_cookie = ""
                self._cookie_badge.setText("")

    def _on_manual_detector_done(self):
        if self._no_cookie_found:
            QMessageBox.information(
                self, "No Cookie Found",
                "No session cookie was found in recent successful login responses.\n"
                "You can manually paste a cookie when configuring a task."
            )

    # ─────────────────────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────────────────────

    # ─────────────────────────────────────────────────────────────────────────
    # Multi-Task Plan support
    # ─────────────────────────────────────────────────────────────────────────

    def _open_multi_task_dialog(self):
        """Open the multi-task plan builder dialog."""
        default = self._selected_target or ""
        dlg = MultiTaskDialog(self, default_target=default, parent=self)
        dlg.exec_()   # plan is launched inside dialog via self.run_multi_task_plan()

    def run_multi_task_plan(self, plan: dict):
        """Create and start a MultiTaskOrchestrator for the given plan."""
        plan_id = plan["id"]
        orch = MultiTaskOrchestrator(plan, self, parent=self)
        self.plan_orchestrators[plan_id] = orch

        # Wire up status signals so the user sees progress
        orch.log.connect(lambda pid, msg: self._on_plan_log(pid, msg))
        orch.plan_started.connect(lambda pid: self._set_status(
            f"⚡ Plan '{plan['name']}' started ({len(plan['groups'])} groups)"))
        orch.group_started.connect(lambda pid, gi, tot: self._set_status(
            f"⚡ Plan '{plan['name']}' — running group {gi+1}/{tot}…", 8000))
        orch.plan_done.connect(lambda pid, ok: self._on_plan_done(pid, ok))

        # Show a plan header widget in the task list
        self._insert_plan_header(plan)

        orch.start()

    def _insert_plan_header(self, plan: dict):
        """Insert a visual divider into the tasks list showing the plan start."""
        lbl = QLabel(
            f"⚡ <b>{plan['name']}</b>  ·  {len(plan['groups'])} group(s)  "
            f"·  {sum(len(g) for g in plan['groups'])} task(s)  "
            f"·  target: <b>{plan['target']}</b>"
        )
        lbl.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_ACCENT};border-radius:4px;"
            f"padding:5px 10px;font-size:{FONT_SIZE_SMALL};"
        )
        lbl.setWordWrap(True)
        # Store plan_id so we can remove it later if needed
        lbl.setProperty("plan_id", plan["id"])
        self._tasks_layout.insertWidget(self._tasks_layout.count() - 1, lbl)

    def _on_plan_log(self, plan_id: str, msg: str):
        """Append plan log lines to a dedicated plan widget (status bar for now)."""
        logger.info(f"[plan {plan_id}] {msg}")

    def _on_plan_done(self, plan_id: str, success: bool):
        orch = self.plan_orchestrators.pop(plan_id, None)
        plan_name = orch._plan["name"] if orch else plan_id
        if success:
            self._set_status(f"✅ Plan '{plan_name}' completed successfully!", 8000)
        else:
            self._set_status(f"⚠️ Plan '{plan_name}' finished with errors.", 8000)

    def save_tasks(self):
        if not self.project_dir:
            return
        tasks_file = os.path.join(self.project_dir, "dashboard_tasks.json")
        to_save = {}
        for tid, td in self.tasks.items():
            copy = td.copy()
            # Don't persist huge in-memory content; the file on disk is the source of truth
            if "output_content" in copy and len(copy["output_content"]) > 100_000:
                copy["output_content"] = ""
            to_save[tid] = copy
        try:
            with open(tasks_file, "w") as f:
                json.dump(to_save, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save tasks: {e}")

    def load_tasks(self):
        """Load tasks from disk, showing only those belonging to the current scope."""
        if not self.project_dir:
            return
        tasks_file = os.path.join(self.project_dir, "dashboard_tasks.json")
        if not os.path.exists(tasks_file):
            return

        try:
            with open(tasks_file) as f:
                loaded: Dict[str, Any] = json.load(f)
        except Exception as e:
            logger.error(f"Failed to load tasks: {e}")
            return

        # Get scope definition to filter tasks
        import project_manager as pm
        scope_hosts = pm.get_scope_hosts(
            self._current_slug, self._current_domain, self._current_subdomain
        )

        for task_id, task_data in loaded.items():
            # Skip tasks already loaded
            if task_id in self.tasks:
                continue

            domain = task_data.get("domain")
            if not domain:
                continue

            # If scope is set, only show tasks for domains in scope
            in_scope = False
            for sh in scope_hosts:
                if domain == sh or domain.endswith("." + sh):
                    in_scope = True
                    break
            
            if not in_scope:
                continue
            
            # Ensure widget exists for this task's domain
            if domain not in self.subdomain_widgets:
                # If it's a domain-level task but not in UI, add to subdomains list for visibility
                # or check if it should be in domain list. For simplicity, add to subdomains list
                # if not present, as it acts as a generic "Targets" list for tasks.
                # However, with the new split, we should check if it's a domain or subdomain.
                # Since we don't know easily here without pm lookup, we'll default to subdomain list
                # if not found in either.
                if domain not in self.domain_widgets:
                    self._add_subdomain_widget(domain)

            self.tasks[task_id] = task_data

            widget = TaskWidget(task_data, self.project_dir)
            widget.remove_requested.connect(self.remove_task)
            widget.show_output_requested.connect(self.show_task_output)
            self._tasks_layout.insertWidget(self._tasks_layout.count() - 1, widget)
            self.task_widgets[task_id] = widget

            if domain:
                self.target_task_counts[domain] = self.target_task_counts.get(domain, 0) + 1
                if domain in self.subdomain_widgets:
                    self.subdomain_widgets[domain].update_task_count(self.target_task_counts[domain])
                elif domain in self.domain_widgets:
                    self.domain_widgets[domain].update_task_count(self.target_task_counts[domain])

        self._update_stats()

    # ─────────────────────────────────────────────────────────────────────────
    # UI helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _on_target_selected(self, target: str):
        sender = self.sender()
        if self._selected_widget and self._selected_widget != sender:
            self._selected_widget.set_selected(False)

        self._selected_widget = sender
        self._selected_widget.set_selected(True)
        self._selected_target = target
        # Track whether the selection is a domain-level entry or a specific subdomain
        self._selected_is_domain = target in self.domain_widgets

        # Re-apply filters
        self._filter_tasks(self._task_filter.currentText())

    def _on_filter_pill(self, label: str):
        """Activate a pill button and apply the filter."""
        _active = (
            "QPushButton{background:#2b7de9;border:1px solid #2b7de9;"
            "padding:4px 14px;border-radius:12px;font-size:11px;"
            "font-weight:500;color:white;}"
        )
        _inactive = (
            "QPushButton{background:#1e1e1e;border:1px solid #3c3f41;"
            "padding:4px 14px;border-radius:12px;font-size:11px;"
            "font-weight:500;color:#888888;}"
            "QPushButton:hover{background:#2d2d2d;color:#f0f0f0;border-color:#5a5d60;}"
        )
        for lbl, btn in self._filter_pills.items():
            btn.setStyleSheet(_active if lbl == label else _inactive)
        idx = self._task_filter.findText(label)
        if idx >= 0:
            self._task_filter.setCurrentIndex(idx)
        self._filter_tasks(label)

    def _filter_tasks(self, filter_text: str):
        mapping = {"Running": "running", "Completed": "completed",
                   "Pending": "pending", "Errors": "error"}
        status_filter = mapping.get(filter_text)
        for task_id, widget in self.task_widgets.items():
            task_data = self.tasks.get(task_id, {})
            status = task_data.get("status", "")
            task_domain = task_data.get("domain", "")

            # ── Target filter ──────────────────────────────────────────────
            if self._selected_target:
                if getattr(self, '_selected_is_domain', False):
                    # Domain selected: show tasks for this domain AND any of its subdomains
                    sel = self._selected_target
                    match = (
                        task_domain == sel
                        or task_domain.endswith("." + sel)
                    )
                else:
                    # Subdomain selected: exact match, or path-scoped tasks under this host
                    # (e.g. bruteforce task for "www.ex.com/dir/" belongs to "www.ex.com")
                    match = (
                        task_domain == self._selected_target
                        or task_domain.startswith(self._selected_target + "/")
                    )
                if not match:
                    widget.hide()
                    continue

            # ── Status filter ──────────────────────────────────────────────
            if filter_text == "All Tasks":
                widget.show()
            elif status_filter and status == status_filter:
                widget.show()
            else:
                widget.hide()

    def _clear_completed(self):
        done = [tid for tid, td in self.tasks.items() if td.get("status") in ("completed", "error")]
        for tid in done:
            self.remove_task(tid)

    def _update_stats(self):
        total     = len(self.tasks)
        running   = sum(1 for t in self.tasks.values() if t.get("status") == "running")
        completed = sum(1 for t in self.tasks.values() if t.get("status") == "completed")
        errors    = sum(1 for t in self.tasks.values() if t.get("status") == "error")
        summary = f"{total} tasks  ·  {running} running  ·  {completed} done  ·  {errors} errors"
        self._stats_label.setText(summary)
        if hasattr(self, '_tasks_stats_label'):
            self._tasks_stats_label.setText(summary)

    def _set_status(self, msg: str, duration: int = 4000):
        self._status_label.setText(msg)
        QTimer.singleShot(duration, lambda: self._status_label.setText(""))

    # ─────────────────────────────────────────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────────────────────────────────────────

    def stop_all_tasks(self):
        for orch in list(self.plan_orchestrators.values()):
            orch.stop()
        self.plan_orchestrators.clear()
        for worker in self.task_workers.values():
            worker.stop()
            worker.wait(2000)

    def closeEvent(self, event):
        self._cookie_poll_timer.stop()
        self._traffic_monitor_timer.stop()
        self.stop_all_tasks()
        self.save_tasks()
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def add_dashboard_tab(parent):
    """Add dashboard tab to main window."""
    tab = DashboardTab(parent)
    parent.dashboard_tab = tab
    parent.tab_widget.addTab(tab, "📊 Dashboard")
    return tab