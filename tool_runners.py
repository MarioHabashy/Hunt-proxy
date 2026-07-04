#!/usr/bin/env python3
"""
tool_runners.py - Pure runner classes for security tools (no Qt dependency).

Each runner owns:
  build_command(*args) -> List[str]   — returns the argv list, no side-effects
  parse_output(content) -> str        — transforms raw output to pretty text

These classes have zero Qt dependency and are fully unit-testable with plain
pytest/unittest — no display, no subprocesses, no filesystem required.

Imported by dashboard_tab.py (TaskWorker) and by test_runners.py.
"""

import os
import re
import subprocess
import logging
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

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
    def build_command(self, domain: str, cookie: str = "", proxy: str = "") -> List[str]:
        cmd = ["curl", "-I", f"https://{domain}", "-s", "-k", "--max-time", "30"]
        if cookie:
            cmd.extend(["--cookie", cookie])
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

    def build_httpx_cmd(self, cookie: str = "", proxy: str = "") -> List[str]:
        cmd = ["httpx", "-silent", "-fc", "404", "-mc", "200", "-td"]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
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
        "django":     r"django|csrfmiddlewaretoken",                  
        "rails":      r"rails|ruby on rails|authenticity_token",       
        "laravel":    r"laravel|livewire",                           
        "sharepoint": r"sharepoint",
        "sap":        r"sap|/sap/", 
        "apache":     r"apache|litespeed",
        "nginx":      r"nginx",
        "tomcat":     r"tomcat|jsessionid",
        "iis":        r"iis|asp\.net|x-aspnet-version|asp\.net_sessionid",
        "graphql":    r"graphql",
        "api":        r"\bapi\b|rest|swagger|express",
        "swagger":    r"swagger|api-docs",                              
        "spring":     r"spring|springframework|spring-boot",           
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
                ["find", base_path, "-type", "f", "-iname", "*.txt"],
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
                      tools_dir: str = os.path.expanduser("~/tools"),
                      extra_headers: Optional[List[str]] = None,
                      filter_codes: Optional[List[int]] = None) -> List[str]:
        _filter = filter_codes if filter_codes is not None else [400, 404, 429]
        filter_args: List[str] = []
        for code in _filter:
            filter_args.extend(["-C", str(code)])
        cmd  = [
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
                # Try to extract byte size from the line
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
                      cookie: str = "", proxy: str = "") -> List[str]:
        cmd = ["nuclei", "-u", domain, "-nh", "-o", output_file]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
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
            for finding in lines[:1000]:
                formatted += f"  {finding}\n"
            if len(lines) > 1000:
                formatted += f"  ... and {len(lines)-1000} more\n"
            formatted += "\n"
        if not any_findings:
            formatted += "✅ No findings detected.\n"
        return formatted


class NiktoRunner:
    def build_command(self, domain: str, proxy: str = "") -> List[str]:
        # No -o flag: nikto infers output format from the file extension and
        # rejects ".log" with "Invalid output format". Output is captured via
        # stdout by _run_cmd_to_file instead.
        cmd = ["nikto", "-h", domain, "-maxtime", "600", "-nointeractive"]
        if proxy:
            cmd.extend(["-useproxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        return content  # nikto output is already well-structured


class WpscanRunner:
    def build_command(self, domain: str, output_file: str,
                      cookie: str = "", proxy: str = "") -> List[str]:
        cmd = ["wpscan", "--url", domain, "-o", output_file]
        if cookie:
            cmd.extend(["--cookie", cookie])
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
    def build_command(self, domain: str, cookie: str = "") -> List[str]:
        cmd = ["joomscan", "-u", domain]
        if cookie:
            cmd.extend(["--cookie", cookie])
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
# Domain-Level Runners
# ─────────────────────────────────────────────────────────────────────────────

class WhoisRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["whois", domain]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip() and not l.startswith("%")]
        formatted = "🔍 WHOIS LOOKUP\n" + "═" * 50 + "\n\n"
        formatted += "\n".join(lines)
        return formatted


class GoogleDorksRunner:
    """dorks_hunter.py wrapper — generates Google dork search URLs."""
    def build_command(self, domain: str, tools_dir: str, output_file: str) -> List[str]:
        script = os.path.join(tools_dir, "dorks_hunter", "dorks_hunter.py")
        return ["python3", script, "-d", domain, "-o", output_file]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "🔎 GOOGLE DORKS\n" + "═" * 50 + "\n\n"
        formatted += f"Total dork URLs: {len(lines)}\n\n"
        formatted += "\n".join(lines)
        return formatted


class GithubDorksRunner:
    """gitdorks_go wrapper — searches GitHub for sensitive data."""
    def build_command(self, domain: str, github_token: str, dorks_file: str) -> List[str]:
        return [
            "gitdorks_go",
            "-gd", dorks_file,
            "-nws", "20",
            "-target", domain,
            "-token", github_token,
            "-ew", "3",
        ]

    def parse_output(self, content: str) -> str:
        lines = content.splitlines()
        # Filter noise lines (0 results)
        filtered = [l for l in lines if l.strip() and "(0)" not in l]
        formatted = "🐙 GITHUB DORKS\n" + "═" * 50 + "\n\n"
        formatted += f"Findings: {len(filtered)}\n\n"
        formatted += "\n".join(filtered)
        return formatted


class TrufflehogRunner:
    """trufflehog — scan GitHub org for verified secrets."""
    def build_command(self, domain: str, github_token: str) -> List[str]:
        company = domain.split(".")[0]
        return [
            "trufflehog", "github",
            f"--org={company}",
            f"--token={github_token}",
            "--only-verified",
        ]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "🔑 GITHUB SECRETS SCAN (trufflehog)\n" + "═" * 50 + "\n\n"
        formatted += f"Verified secrets found: {len(lines)}\n\n"
        formatted += "\n".join(lines)
        return formatted


class EmailfinderRunner:
    def build_command(self, domain: str) -> List[str]:
        return ["emailfinder", "-d", domain]

    def parse_output(self, content: str) -> str:
        emails = sorted({
            l.strip() for l in content.splitlines()
            if "@" in l and "|" not in l and "_" not in l.split("@")[0]
        })
        formatted = "📧 EMAIL DISCOVERY\n" + "═" * 50 + "\n\n"
        formatted += f"Emails found: {len(emails)}\n\n"
        formatted += "\n".join(emails)
        return formatted


class MetafinderRunner:
    def build_command(self, domain: str, output_dir: str) -> List[str]:
        return [
            "metafinder",
            "-d", domain,
            "-l", "250",
            "-o", output_dir,
            "-go", "-bi", "-ba",
        ]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "📄 METADATA FINDER\n" + "═" * 50 + "\n\n"
        formatted += "\n".join(lines)
        return formatted


class PassiveSubdomainsRunner:
    """Runs amass+subfinder+github-subdomains+crt.sh+findomain+hackertarget → merged."""

    def build_amass_cmd(self, domain: str, out: str) -> List[str]:
        return ["amass", "enum", "-passive", "-d", domain, "-o", out]

    def build_subfinder_cmd(self, domain: str, out: str) -> List[str]:
        return ["subfinder", "-all", "-d", domain, "-o", out]

    def build_github_subs_cmd(self, domain: str, token: str, out: str) -> List[str]:
        return ["github-subdomains", "-d", domain, "-k", "-q", "-t", token, "-o", out]

    def build_findomain_cmd(self, domain: str, out: str) -> List[str]:
        return ["findomain", "-t", domain, "-u", out]

    def fetch_hackertarget(self, domain: str) -> List[str]:
        import urllib.request
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            with urllib.request.urlopen(url, timeout=20) as resp:
                data = resp.read().decode()
            return [
                line.split(",")[0]
                for line in data.splitlines()
                if domain in line
            ]
        except Exception:
            return []

    def fetch_crtsh(self, domain: str) -> List[str]:
        import urllib.request, json as _json
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            with urllib.request.urlopen(url, timeout=30) as resp:
                data = _json.loads(resp.read())
            subs = set()
            for entry in data:
                for s in entry.get("name_value", "").split("\n"):
                    s = s.strip().lstrip("*.")
                    if s.endswith(f".{domain}") or s == domain:
                        subs.add(s)
            return sorted(subs)
        except Exception:
            return []

    def parse_output(self, subdomains: List[str], domain: str) -> str:
        unique = sorted(set(subdomains))
        formatted = "🌐 PASSIVE SUBDOMAIN ENUMERATION\n" + "═" * 50 + "\n\n"
        formatted += f"Total unique subdomains found: {len(unique)}\n\n"
        for s in unique:
            formatted += f"  {s}\n"
        return formatted


class ActiveSubdomainsRunner:
    """gobuster dns brute-force."""

    _SECLISTS_CANDIDATES = [
        "/usr/share/seclists",
        "/usr/share/SecLists",
        os.path.expanduser("~/SecLists"),
        os.path.expanduser("~/seclists"),
        "/opt/seclists",
        "/opt/SecLists",
    ]
    _DNS_WORDLIST_REL = "Discovery/DNS/subdomains-top1million-5000.txt"

    def find_seclists(self) -> Optional[str]:
        return next((p for p in self._SECLISTS_CANDIDATES if os.path.isdir(p)), None)

    def get_default_wordlist(self, seclists_dir: Optional[str] = None) -> str:
        """Return the default DNS wordlist path from SecLists, or empty string if not found."""
        base = seclists_dir if (seclists_dir and os.path.isdir(seclists_dir)) else self.find_seclists()
        if base:
            candidate = os.path.join(base, self._DNS_WORDLIST_REL)
            if os.path.exists(candidate):
                return candidate
        return ""

    def build_command(self, domain: str, wordlist: str) -> List[str]:
        return [
            "gobuster", "dns",
            "-d", domain,
            "-w", wordlist,
            "-q",
        ]

    def parse_output(self, content: str) -> str:
        # gobuster dns output: "Found: subdomain.example.com"
        subs = []
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("Found:"):
                sub = line.split("Found:", 1)[1].strip()
                subs.append(sub)
            elif line and not line.startswith("["):
                subs.append(line)
        formatted = "🔊 ACTIVE SUBDOMAIN BRUTE-FORCE (gobuster dns)\n" + "═" * 50 + "\n\n"
        formatted += f"Subdomains found: {len(subs)}\n\n"
        for s in subs:
            formatted += f"  {s}\n"
        return formatted


class AltdnsRunner:
    """altdns — permutation-based subdomain guessing."""
    def build_command(self, domain: str, input_file: str, output_file: str, words_file: str) -> List[str]:
        return [
            "altdns",
            "-i", input_file,
            "-o", output_file + ".generated",
            "-w", words_file,
            "-r", "-e",
            "-s", output_file,
        ]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "🔀 SUBDOMAIN PERMUTATION (altdns)\n" + "═" * 50 + "\n\n"
        formatted += f"Guessed subdomains: {len(lines)}\n\n"
        for s in lines[:500]:
            formatted += f"  {s}\n"
        if len(lines) > 500:
            formatted += f"  ... and {len(lines)-500} more\n"
        return formatted


class VhostRunner:
    """ffuf vhost discovery."""
    def build_command(self, domain: str, ip: str, wordlist: str) -> List[str]:
        default_wl = wordlist or "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        return [
            "ffuf",
            "-w", default_wl,
            "-u", f"http://{ip}",
            "-H", f"Host: FUZZ.{domain}",
            "-mc", "200",
        ]

    def parse_output(self, content: str) -> str:
        import re
        # Strip ANSI color codes
        clean = re.sub(r'\x1B\[[0-9;]*[mGK]', '', content)
        lines = [l for l in clean.splitlines() if l.strip()]
        formatted = "🏠 VHOST DISCOVERY (ffuf)\n" + "═" * 50 + "\n\n"
        formatted += "\n".join(lines)
        return formatted


class HttpxLiveRunner:
    """httpx — check live subdomains with response codes."""
    def build_command(self, input_file: str, output_file: str) -> List[str]:
        return [
            "httpx",
            "-follow-host-redirects",
            "-l", input_file,
            "-td", "-cl", "-title", "-ip", "-sc",
            "-retries", "2",
            "-content-type",
            "-o", output_file,
        ]

    def parse_output(self, content: str) -> str:
        import re
        clean = re.sub(r'\x1B\[[0-9;]*[mGK]', '', content)
        lines = [l for l in clean.splitlines() if l.strip()]
        formatted = "🌐 LIVE SUBDOMAINS + RESPONSE CODES (httpx)\n" + "═" * 50 + "\n\n"
        formatted += f"Live subdomains: {len(lines)}\n\n"
        formatted += "\n".join(lines)
        return formatted


class Byp4xxRunner:
    """byp4xx — bypass 401/403 responses."""
    def build_command(self, input_file: str) -> List[str]:
        return ["byp4xx", "-m", "4", input_file]

    def parse_output(self, content: str) -> str:
        import re
        clean = re.sub(r'\x1B\[[0-9;]*[mGK]', '', content)
        lines = [l for l in clean.splitlines() if l.strip()]
        bypassed = [l for l in lines if any(c in l for c in ["200", "301", "302"])]
        formatted = "🔓 40X BYPASS (byp4xx)\n" + "═" * 50 + "\n\n"
        formatted += f"Total results: {len(lines)} | Bypassed (200/301/302): {len(bypassed)}\n\n"
        formatted += "\n".join(lines)
        return formatted


class SubjackRunner:
    """subjack — subdomain takeover detection."""
    def build_command(self, input_file: str) -> List[str]:
        return [
            "subjack",
            "-w", input_file,
            "-t", "100",
            "-timeout", "30",
            "-ssl",
            "-c", "/usr/share/subjack/fingerprints.json",
            "-v", "3",
        ]

    def parse_output(self, content: str) -> str:
        import re
        clean = re.sub(r'\x1B\[[0-9;]*[mGK]', '', content)
        lines = clean.splitlines()
        vuln = [l for l in lines if "[Not Vulnerable]" not in l and l.strip()]
        safe = [l for l in lines if "[Not Vulnerable]" in l]
        formatted = "🎯 SUBDOMAIN TAKEOVER (subjack)\n" + "═" * 50 + "\n\n"
        formatted += f"Vulnerable: {len(vuln)} | Not vulnerable: {len(safe)}\n\n"
        if vuln:
            formatted += "⚠️ VULNERABLE:\n"
            for l in vuln:
                formatted += f"  {l}\n"
            formatted += "\n"
        if safe:
            formatted += "✅ NOT VULNERABLE:\n"
            for l in safe:
                formatted += f"  {l}\n"
        return formatted


class SmapRunner:
    """smap — fast port scanner using Shodan data."""
    def build_command(self, input_file: str, output_base: str) -> List[str]:
        return [
            "smap",
            "-iL", input_file,
            "-T5",
            "-oA", output_base,
        ]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "🔌 SERVICE SCAN (smap)\n" + "═" * 50 + "\n\n"
        formatted += "\n".join(lines)
        return formatted


class CloudEnumRunner:
    """cloud_enum — enumerate cloud assets (S3, GCP, Azure)."""
    def build_command(self, domain: str, output_file: str) -> List[str]:
        keyword = domain.split(".")[0]
        return ["cloud_enum", "-k", keyword, "-l", output_file]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        open_assets = [l for l in lines if any(x in l.lower() for x in ["open", "public", "accessible"])]
        formatted = "☁️ CLOUD ENUMERATION (cloud_enum)\n" + "═" * 50 + "\n\n"
        formatted += f"Total assets: {len(lines)} | Open/Public: {len(open_assets)}\n\n"
        formatted += "\n".join(lines)
        return formatted


class EyewitnessRunner:
    """eyewitness — screenshot web targets."""
    def build_command(self, input_file: str, output_dir: str) -> List[str]:
        return [
            "eyewitness",
            "-f", input_file,
            "-d", output_dir,
            "--no-prompt",
            "--timeout", "10",
            "--delay", "3",
        ]

    def parse_output(self, content: str) -> str:
        lines = [l for l in content.splitlines() if l.strip()]
        formatted = "📸 SCREENSHOT REPORT (eyewitness)\n" + "═" * 50 + "\n\n"
        formatted += "\n".join(lines)
        return formatted


# ─────────────────────────────────────────────────────────────────────────────
# Spider-enhancement Runners  (gospider, cariddi, linkfinder, paramspider)
# ─────────────────────────────────────────────────────────────────────────────

class GospiderRunner:
    """gospider — fast web spider (links + forms + JS + sitemap + robots)."""

    def build_command(self, domain: str, output_dir: str,
                      cookie: str = "", proxy: str = "", depth: int = 3) -> List[str]:
        cmd = [
            "gospider",
            "-s", f"https://{domain}",
            "-o", output_dir,
            "-c", "10",           # concurrency
            "-d", str(depth),
            "--js",               # extract from JS files
            "--sitemap",          # fetch sitemap.xml
            "--robots",           # fetch robots.txt
            "--other",            # extract from non-HTML responses
            "--include-subs",     # include subdomains
            "-q",                 # quiet (no banner)
        ]
        if cookie:
            cmd.extend(["-H", f"Cookie: {cookie}"])
        if proxy:
            cmd.extend(["--proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        """Extract plain URLs from gospider output lines."""
        urls = []
        for line in content.splitlines():
            # gospider lines: [url] - [source] - [type] - <url>
            # or just a plain URL
            m = re.search(r'https?://\S+', line)
            if m:
                urls.append(m.group(0).rstrip("]\"'"))
        return "\n".join(sorted(set(urls)))


class CariddiRunner:
    """cariddi — headless endpoint/parameter/secret crawler (AJAX spider)."""

    def build_command(self, domain: str, output_file: str,
                      cookie: str = "", proxy: str = "", depth: int = 3) -> List[str]:
        cmd = [
            "cariddi",
            "-s", f"https://{domain}",
            "-c", "10",
            "-d", str(depth),
            "-e",          # extract endpoints
            "-js",         # extract JS files
            "-intensive",  # intensive mode (like AJAX spider)
            "-plain",      # plain text output (one URL per line)
            "-o", output_file,
        ]
        if cookie:
            cmd.extend(["-headers", f"Cookie: {cookie}"])
        if proxy:
            cmd.extend(["-proxy", proxy])
        return cmd

    def parse_output(self, content: str) -> str:
        urls = [l.strip() for l in content.splitlines() if l.strip().startswith("http")]
        formatted = "🕷️ CARIDDI SPA CRAWL\n" + "═" * 50 + "\n\n"
        formatted += f"URLs discovered: {len(urls)}\n\n"
        for u in urls[:50]:
            formatted += f"  {u}\n"
        if len(urls) > 50:
            formatted += f"  ... and {len(urls) - 50} more\n"
        return formatted


class LinkFinderRunner:
    """linkfinder — extract endpoints from JS files."""

    def build_command(self, js_url: str, tools_dir: str) -> List[str]:
        # LinkFinder is typically a Python script — locate linkfinder.py
        candidates = [
            os.path.join(tools_dir, "LinkFinder", "linkfinder.py"),
            os.path.join(tools_dir, "linkfinder", "linkfinder.py"),
            os.path.expanduser("~/tools/LinkFinder/linkfinder.py"),
        ]
        script = next((p for p in candidates if os.path.isfile(p)), "linkfinder.py")
        return ["python3", script, "-i", js_url, "-o", "cli"]

    def parse_output(self, content: str) -> str:
        endpoints = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("<!")]
        formatted = "📜 LINKFINDER — JS ENDPOINTS\n" + "═" * 50 + "\n\n"
        formatted += f"Endpoints found: {len(endpoints)}\n\n"
        for ep in endpoints[:200]:
            formatted += f"  {ep}\n"
        if len(endpoints) > 200:
            formatted += f"  ... and {len(endpoints) - 200} more\n"
        return formatted


class ParamSpiderRunner:
    """paramspider — parameter discovery from URLs."""

    def build_command(self, domain: str, output_file: str) -> List[str]:
        return [
            "paramspider",
            "-d", domain,
            "--level", "high",
            "--quiet",
            "-o", output_file,
        ]

    def parse_output(self, content: str) -> str:
        params = [l.strip() for l in content.splitlines() if l.strip().startswith("http")]
        formatted = "🔎 PARAMSPIDER — PARAMETER DISCOVERY\n" + "═" * 50 + "\n\n"
        formatted += f"Parameterised URLs found: {len(params)}\n\n"
        for p in params[:100]:
            formatted += f"  {p}\n"
        if len(params) > 100:
            formatted += f"  ... and {len(params) - 100} more\n"
        return formatted