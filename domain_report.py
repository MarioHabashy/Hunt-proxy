#!/usr/bin/env python3
"""
domain_report.py — Generates a rich HTML recon dashboard for a single domain.
Matches the output of recon_dashboard.sh exactly:
  - Subdomains tab: Final subdomains + Interesting classification + status badges
    + screenshot thumbnails + Add to Analysis Targets + Kanban board
  - Dorks tab: Google / GitHub / Secrets with checkboxes persisted in localStorage
  - Emails tab: role-highlighted emails
  - Cloud tab: per-provider cards (S3, GCP, Firebase, Azure, AWS) + open/all filter
  - Services tab: per-host nmap output + port & service filter buttons
  - Takeovers tab: vulnerable / safe filter
  - Access Bypass tab: 40x bypass + POST/GET bruteforce sorted by SC + filter buttons
  - Screenshots tab: link to eyewitness report

Output: <domain_dir>/report.html  (no Qt dependency)
"""

import os
import re
import html
from datetime import datetime
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# File helpers
# ─────────────────────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return ""

def _lines(path: str) -> List[str]:
    return [l.rstrip() for l in _read(path).splitlines() if l.strip()]

def _h(text: str) -> str:
    return html.escape(str(text))

def _strip_ansi(text: str) -> str:
    return re.sub(r'\x1B\[[0-9;]*[mGK]', '', text)

def _safe_slug(s: str) -> str:
    return re.sub(r'[^a-z0-9_\-]', '_', s.lower().strip()).strip('_')


# ─────────────────────────────────────────────────────────────────────────────
# Data collector
# ─────────────────────────────────────────────────────────────────────────────

class DomainReconData:
    def __init__(self, domain: str, domain_dir: str, tasks_dir: str,
                 live_subdomains_file: Optional[str] = None):
        self.domain      = domain
        self.domain_dir  = domain_dir
        self.tasks_dir   = tasks_dir

        slug   = _safe_slug(domain)
        shared = os.path.join(tasks_dir, f"subdomains_{slug}")

        # ── Live subdomains (httpx output) ────────────────────────────────────
        raw_live = ""
        for candidate in [
            live_subdomains_file,
            os.path.join(shared, "live_subdomains.txt"),
            os.path.join(shared, "all_subdomains.txt"),
        ]:
            if candidate and os.path.isfile(candidate) and os.path.getsize(candidate) > 0:
                raw_live = _read(candidate)
                break
        if not raw_live:
            for tool in ("passive_subdomains", "active_subdomains"):
                p = self._task_file_path(tool, "live_subdomains.txt")
                if p:
                    raw_live = _read(p); break
        if not raw_live:
            raw_live = (self._task_output("live_subdomains") or
                        self._task_output("passive_subdomains") or
                        self._task_output("active_subdomains"))

        self.live_lines: List[str] = [
            _strip_ansi(l) for l in raw_live.splitlines()
            if l.strip() and not l.startswith(("🌐","🌿","═","─","Live","Total","..."))
        ]

        # ── final_subdomains: plain hostnames ─────────────────────────────────
        final_p = os.path.join(shared, "final_subdomains.txt")
        if os.path.isfile(final_p) and os.path.getsize(final_p) > 0:
            self.final_subdomains: List[str] = [
                l.strip() for l in _read(final_p).splitlines() if l.strip()
            ]
        else:
            self.final_subdomains = []
            for line in self.live_lines:
                m = re.match(r'https?://([a-zA-Z0-9._:-]+)', line)
                if m:
                    self.final_subdomains.append(m.group(1).split(":")[0])
                else:
                    tok = line.strip().split()[0] if line.strip() else ""
                    if tok and "." in tok and not tok.startswith("["):
                        self.final_subdomains.append(tok.lstrip("*."))

        # ── Status code + info maps from httpx lines ──────────────────────────
        self.status_map: Dict[str, int] = {}
        self.info_map:   Dict[str, str] = {}
        for line in self.live_lines:
            m_url = re.match(r'(https?://([a-zA-Z0-9._:-]+))', line)
            if not m_url:
                continue
            host = m_url.group(2).split(":")[0]
            m_code = re.search(r'\[(\d{3})\]', line)
            if m_code:
                self.status_map[host] = int(m_code.group(1))
            rest = line[m_url.end():].strip()
            if rest:
                self.info_map[host] = rest

        # ── Dorks ─────────────────────────────────────────────────────────────
        self.google_dorks   = self._read_task_or_file("google_dorks",  "dorks/google_dorks.txt")
        self.github_dorks   = self._read_task_or_file("github_dorks",  "dorks/github_dorks.txt")
        self.github_secrets = self._read_task_or_file("github_secrets","dorks/verified_secrets_scan_repos.txt")

        # ── Emails ────────────────────────────────────────────────────────────
        self.emails_raw     = self._read_task_or_file("emails","emails_discovery/emails.txt")

        # ── Service scan ──────────────────────────────────────────────────────
        self.service_scan   = _strip_ansi(self._read_task_or_file("service_scan","service_scan/nmap.nmap"))

        # ── Takeovers ─────────────────────────────────────────────────────────
        self.takeovers_raw  = self._read_task_or_file("takeover","potential_takeovers/potential_takeovers.txt")

        # ── Cloud (per-provider) ──────────────────────────────────────────────
        cloud_map = {
            "AWS S3 Buckets":       "cloud/s3_buckets.txt",
            "Google Cloud Buckets": "cloud/gcp_buckets.txt",
            "Firebase RTDB":        "cloud/firebase_rtdb.txt",
            "AWS Apps":             "cloud/aws_apps.txt",
            "Azure Web Apps":       "cloud/azure_webapps.txt",
        }
        self.cloud: Dict[str, List[str]] = {}
        for label, rel in cloud_map.items():
            rows = _lines(os.path.join(domain_dir, rel))
            if rows:
                self.cloud[label] = rows

        # ── Bypass / brute-force ──────────────────────────────────────────────
        def _bypass(rel, task_file="output.log"):
            rows = _lines(os.path.join(domain_dir, rel))
            if not rows:
                rows = _lines(self._task_file_path("bypass_40x", task_file))
            return rows

        self.bypass_40x      = _bypass("subdomains/bypass_40x_subdomains_summary.txt")
        self.post_bruteforce = _lines(os.path.join(domain_dir, "subdomains/POST_bruteforce_404_subdomains.txt"))
        self.get_bruteforce  = _lines(os.path.join(domain_dir, "subdomains/GET_bruteforce_404_subdomains.txt"))

        # ── Screenshots ───────────────────────────────────────────────────────
        self.screenshot_report = os.path.join(domain_dir, "screenshot_report/report.html")

    def _task_output(self, tool: str) -> str:
        p = self._task_file_path(tool, "output.log")
        return _read(p) if p else ""

    def _task_file_path(self, tool: str, filename: str) -> str:
        slug = _safe_slug(self.domain)
        p = os.path.join(self.tasks_dir, f"{tool}_{slug}", filename)
        return p if os.path.isfile(p) else ""

    def _read_task_or_file(self, tool: str, rel: str) -> str:
        return self._task_output(tool) or _read(os.path.join(self.domain_dir, rel))

    @property
    def all_subdomains(self) -> List[str]:
        return sorted(set(self.final_subdomains))

    @property
    def email_list(self) -> List[str]:
        return [l for l in self.emails_raw.splitlines() if "@" in l]

    @property
    def takeover_lines(self) -> List[str]:
        return [_strip_ansi(l) for l in self.takeovers_raw.splitlines() if l.strip()]


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain classification
# ─────────────────────────────────────────────────────────────────────────────

_CLASSIFY = [
    (["admin","dashboard","control","manage","panel","login","auth","portal","root","administrator"],
     "🔴 CRITICAL","badge-admin","admin-highlight","fa-cog","Admin"),
    (["db","database","mysql","mongo","mongodb","postgres","postgresql","redis","mariadb","oracle"],
     "🔴 CRITICAL","badge-admin","admin-highlight","fa-database","DB"),
    (["api","gateway","endpoint","rest","graphql","ws","websocket"],
     "🟠 HIGH","badge-api","api-highlight","fa-plug","API"),
    (["ftp","sftp","ssh","remote","vpn","rdp","telnet"],
     "🟠 HIGH","badge-remote","remote-highlight","fa-terminal","Remote"),
    (["monitor","monitoring","grafana","kibana","prometheus","logs","logging","metrics","elk"],
     "🟡 MEDIUM","badge-cdn","content-highlight","fa-chart-line","Monitor"),
    (["mail","email","smtp","imap","pop3","exchange","owa","webmail"],
     "🟡 MEDIUM","badge-email","email-highlight","fa-envelope","Email"),
    (["cdn","assets","static","media","img","images","files"],
     "🔵 LOW","badge-cdn","cdn-highlight","fa-cloud","CDN"),
    (["dev","development","staging","stage","test","testing","qa","preprod","sandbox","uat"],
     "🔵 LOW","badge-dev","development-highlight","fa-flask","Dev"),
]

def _classify(sub: str) -> Optional[Tuple]:
    low = sub.lower()
    main = low.split(".")[0]
    for keywords, priority, badge_cls, hl_cls, icon, label in _CLASSIFY:
        for kw in keywords:
            if main == kw or f"-{kw}" in low or f"_{kw}" in low or f".{kw}." in low or low.startswith(f"{kw}."):
                return (priority, badge_cls, hl_cls, icon, label)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Status badge
# ─────────────────────────────────────────────────────────────────────────────

def _status_badge(code: Optional[int]) -> Tuple[str, str]:
    """Returns (html, group)"""
    if code is None:
        return ('<span class="status-badge status-other"><i class="fas fa-question-circle"></i> N/A</span>', "unknown")
    if 200 <= code < 300:
        return (f'<span class="status-badge status-200"><i class="fas fa-check-circle"></i> {code}</span>', "200")
    if 300 <= code < 400:
        return (f'<span class="status-badge status-301"><i class="fas fa-redo-alt"></i> {code}</span>', "300")
    if 400 <= code < 500:
        return (f'<span class="status-badge status-401"><i class="fas fa-lock"></i> {code}</span>', "400")
    if 500 <= code < 600:
        return (f'<span class="status-badge status-500"><i class="fas fa-exclamation-triangle"></i> {code}</span>', "500")
    return (f'<span class="status-badge status-other">{code}</span>', "unknown")


# ─────────────────────────────────────────────────────────────────────────────
# CSS + JS (embedded)
# ─────────────────────────────────────────────────────────────────────────────

CSS = """
:root{--bg-primary:#1e1e1e;--bg-secondary:#2d2d2d;--bg-tertiary:#3c3c3c;--border:#404040;
--text-primary:#e8e8e8;--text-secondary:#a0a0a0;--accent:#ffa500;--critical:#ff4444;
--high:#ff8800;--medium:#ffcc00;--low:#00cc66;--info:#4da6ff;--warning:#ff8800;--success:#00cc66;}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'JetBrains Mono','Fira Code',Consolas,monospace;background:var(--bg-primary);color:var(--text-primary);line-height:1.6}
.container{max-width:1800px;margin:0 auto;padding:20px}
.header{text-align:center;margin-bottom:30px;padding:25px;background:linear-gradient(135deg,var(--bg-secondary),var(--bg-tertiary));border-radius:12px;border:1px solid var(--border)}
.header h1{color:var(--accent);margin-bottom:12px;font-size:2.2em;font-weight:700}
.header .domain{color:var(--text-secondary);font-size:1.3em}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:15px;margin-bottom:30px}
.stat-card{background:linear-gradient(145deg,var(--bg-secondary),var(--bg-tertiary));padding:20px;border-radius:10px;text-align:center;border:1px solid var(--border);transition:all .3s;position:relative;overflow:hidden}
.stat-card::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,.1),transparent);transition:left .5s}
.stat-card:hover::before{left:100%}
.stat-card:hover{transform:translateY(-5px);border-color:var(--accent);box-shadow:0 8px 25px rgba(0,0,0,.15)}
.stat-number{font-size:2.4em;font-weight:800;margin-bottom:8px;background:linear-gradient(135deg,var(--accent),var(--text-primary));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
.stat-label{color:var(--text-secondary);font-size:.95em;font-weight:500;text-transform:uppercase;letter-spacing:.5px}
.tabs{display:flex;background:var(--bg-secondary);border-radius:10px;margin-bottom:25px;overflow-x:auto;border:1px solid var(--border);padding:4px;gap:2px}
.tab{padding:16px 28px;background:transparent;border:none;color:var(--text-secondary);cursor:pointer;white-space:nowrap;transition:all .3s;border-radius:8px;font-weight:500;font-family:inherit;font-size:.9em;position:relative}
.tab:hover{color:var(--text-primary);background:var(--bg-tertiary);transform:translateY(-2px)}
.tab.active{color:var(--accent);background:var(--bg-primary);border:1px solid var(--border)}
.tab.active::after{content:'';position:absolute;bottom:0;left:50%;transform:translateX(-50%);width:60%;height:3px;background:var(--accent);border-radius:2px}
.tab-content{display:none;background:var(--bg-secondary);border-radius:12px;padding:30px;border:1px solid var(--border)}
.tab-content.active{display:block;animation:fadeIn .4s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.content-section{margin-bottom:30px}
.section-title{font-size:1.4em;color:var(--accent);margin-bottom:20px;padding-bottom:12px;border-bottom:2px solid var(--border);display:flex;align-items:center;gap:12px;font-weight:600}
.data-card{background:var(--bg-primary);border:1px solid var(--border);border-radius:10px;margin-bottom:20px;overflow:hidden;transition:all .3s}
.data-card:hover{box-shadow:0 4px 15px rgba(0,0,0,.12)}
.data-card-header{padding:20px;background:linear-gradient(135deg,var(--bg-tertiary),var(--bg-secondary));border-bottom:1px solid var(--border);cursor:pointer;display:flex;justify-content:space-between;align-items:center}
.data-card-header:hover{background:var(--bg-tertiary)}
.data-card-title{font-weight:700;display:flex;align-items:center;gap:12px;font-size:1.1em}
.data-card-count{background:var(--accent);color:white;padding:6px 14px;border-radius:20px;font-size:.85em;font-weight:600}
.data-card-content{padding:0;max-height:0;overflow:hidden;transition:all .4s cubic-bezier(.4,0,.2,1)}
.data-card.expanded .data-card-content{padding:25px;max-height:900px;overflow-y:auto}
/* Subdomains */
.subdomain-item,.interesting-subdomain-item{padding:10px 15px;border-bottom:1px solid var(--border);transition:all .3s;position:relative}
.subdomain-item:hover,.interesting-subdomain-item:hover{transform:translateX(5px)}
.subdomain-content-wrapper{display:flex;align-items:center;width:100%;gap:12px}
.subdomain-info-container{flex:1;min-width:0;display:flex;flex-direction:column;gap:5px}
.subdomain-main-row{display:flex;justify-content:space-between;align-items:center;width:100%}
.interesting-subdomain-link{display:flex;align-items:center;gap:8px;color:var(--text-primary);text-decoration:none;transition:color .2s}
.interesting-subdomain-link:hover{color:var(--accent)}
.interesting-subdomain-url{word-break:break-all;font-weight:500}
.status-badge{padding:8px 14px;border-radius:20px;font-size:.9em;font-weight:bold;display:flex;align-items:center;gap:6px;min-width:85px;justify-content:center;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.status-200{background:var(--low);color:white}
.status-301{background:var(--info);color:white}
.status-401{background:var(--high);color:black}
.status-500{background:var(--critical);color:white}
.status-other{background:var(--bg-tertiary);color:var(--text-secondary)}
.subdomain-badge{padding:6px 12px;border-radius:20px;font-size:.8em;font-weight:bold;display:flex;align-items:center;gap:6px;justify-content:center}
.badge-admin{background:var(--critical);color:white}
.badge-api{background:var(--accent);color:white}
.badge-dev{background:var(--warning);color:black}
.badge-email{background:var(--info);color:white}
.badge-remote{background:var(--high);color:black}
.badge-cdn{background:var(--low);color:white}
.admin-highlight{background:rgba(239,68,68,.1);border-left:3px solid var(--critical)}
.api-highlight{background:rgba(59,130,246,.1);border-left:3px solid var(--accent)}
.development-highlight{background:rgba(245,158,11,.1);border-left:3px solid var(--warning)}
.email-highlight{background:rgba(6,182,212,.1);border-left:3px solid var(--info)}
.remote-highlight{background:rgba(245,158,11,.1);border-left:3px solid var(--high)}
.cdn-highlight{background:rgba(16,185,129,.1);border-left:3px solid var(--low)}
.content-highlight{background:rgba(234,179,8,.1);border-left:3px solid var(--medium)}
.interesting-highlight{background:rgba(148,163,184,.1);border-left:3px solid var(--text-secondary)}
.danger-highlight{background:rgba(239,68,68,.1);border-left:3px solid var(--critical)}
.warning-highlight{background:rgba(245,158,11,.1);border-left:3px solid var(--warning)}
.success-highlight{background:rgba(16,185,129,.1);border-left:3px solid var(--low)}
.response-additional-info{font-size:.85em;color:var(--text-secondary);font-family:'Fira Code',monospace;margin-top:4px;padding-left:24px}
.subdomain-controls{display:flex;gap:15px;margin:10px 0}
.subdomain-controls input,.subdomain-controls select{padding:8px;border:1px solid var(--border);border-radius:5px;background:var(--bg-secondary);color:var(--text-primary);font-family:inherit}
.subdomain-controls input{flex:1}
.add-target-btn{background:var(--success);color:white;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:.8em;transition:all .3s;font-family:inherit}
.add-target-btn:hover{background:#00b359;transform:translateY(-2px)}
/* Screenshot */
.screenshot-placeholder{width:50px;height:50px;background:var(--bg-tertiary);border-radius:6px;border:2px dashed var(--border);display:flex;align-items:center;justify-content:center;color:var(--text-secondary);font-size:.7em;flex-shrink:0;opacity:.5}
.subdomain-screenshot{width:50px;height:50px;object-fit:cover;border-radius:6px;border:2px solid var(--border);cursor:zoom-in;flex-shrink:0;display:none}
.subdomain-screenshot.loaded{display:block}
.subdomain-screenshot:hover{border-color:var(--accent);transform:scale(1.1)}
.screenshot-modal{display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,.9);z-index:10000;justify-content:center;align-items:center;cursor:zoom-out}
.screenshot-modal.active{display:flex}
.screenshot-modal img{max-width:90%;max-height:90%;object-fit:contain;border:4px solid var(--accent);border-radius:8px}
.screenshot-modal-close{position:absolute;top:20px;right:40px;font-size:40px;color:white;cursor:pointer;z-index:10001}
/* Dorks */
.dork-item{display:flex;align-items:center;padding:6px 10px;border-bottom:1px solid var(--border);font-family:'Fira Code',monospace;font-size:.9em;transition:all .3s;min-height:32px}
.dork-item:hover{background:rgba(59,130,246,.05);transform:translateX(5px)}
.dork-item.checked{background:rgba(34,197,94,.15)!important;border-left:3px solid var(--success)}
.dork-checkbox{margin:0;cursor:pointer;width:18px;height:18px;accent-color:var(--low);flex-shrink:0}
.dork-content{display:flex;align-items:center;gap:8px;flex:1;margin-left:8px}
.dork-icon{color:var(--accent);font-size:.8em;width:16px;text-align:center}
.dork-text{flex:1;word-break:break-word}
.dork-link{color:inherit;text-decoration:none;flex:1;display:flex;align-items:center;gap:8px}
.dork-link:hover{color:var(--accent)}
.dorks-container{max-height:800px;overflow-y:auto}
.secret-highlight-span{background:var(--critical);color:white;padding:2px 4px;border-radius:3px;font-weight:bold}
/* Email */
.email-item{padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;transition:all .3s}
.email-item:hover{transform:translateX(5px)}
/* Cloud */
.cloud-item{padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;transition:all .3s}
.cloud-item:hover{transform:translateX(5px)}
/* Services */
.filter-bar{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
.filter-btn{padding:8px 14px;background:var(--bg-secondary);color:var(--text-primary);border:1px solid var(--border);border-radius:8px;cursor:pointer;font-size:.85em;font-weight:600;transition:all .25s;font-family:inherit}
.filter-btn:hover{background:var(--bg-tertiary);transform:translateY(-1px)}
.filter-btn.active,.btn.active{background:orange;color:black;border-color:#c9b100;box-shadow:0 0 8px rgba(255,215,0,.5)}
.host-scan{border-bottom:1px solid var(--border);padding:12px 10px;margin-bottom:12px;background:var(--bg-primary);border-radius:8px}
.host-title{font-weight:bold;color:var(--accent);margin-bottom:6px}
.service-item{padding:4px 6px;margin:3px 0;border-radius:6px;background:var(--bg-tertiary);display:block;font-family:monospace;transition:all .2s}
.service-item:hover{background:var(--bg-secondary)}
/* Takeovers / vulns */
.takeover-item,.vuln-item{padding:8px 12px;border-bottom:1px solid var(--border);font-family:monospace;transition:all .3s}
.takeover-item:hover,.vuln-item:hover{transform:translateX(5px)}
.vuln-item.clickable{cursor:pointer;border-radius:6px}
.badge-danger{background:var(--critical);color:white;padding:3px 8px;border-radius:6px;font-weight:bold}
.badge-warning{background:var(--high);color:black;padding:3px 8px;border-radius:6px;font-weight:bold}
.badge-success{background:var(--low);color:white;padding:3px 8px;border-radius:6px;font-weight:bold}
.badge-info{background:var(--info);color:white;padding:3px 8px;border-radius:6px;font-weight:bold}
.badge-default{background:var(--bg-tertiary);color:var(--text-secondary);padding:3px 8px;border-radius:6px}
/* Buttons */
.btn{padding:8px 16px;background:var(--bg-tertiary);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);cursor:pointer;font-size:.85em;transition:all .3s;font-weight:500;text-decoration:none;display:inline-flex;align-items:center;gap:6px;font-family:inherit}
.btn:hover{border-color:var(--accent);color:var(--accent);transform:translateY(-2px)}
.btn-primary{background:var(--accent);border-color:var(--accent);color:white}
.btn-primary:hover{background:#e59400;color:white}
.btn-secondary{background:var(--bg-tertiary);border-color:var(--border)}
.btn-success{background:var(--low);border-color:var(--low);color:white}
.btn-danger{background:var(--critical);border-color:var(--critical);color:white}
.btn-info{background:var(--info);border-color:var(--info);color:white}
.copy-btn{background:var(--bg-tertiary);border:1px solid var(--border);color:var(--text-secondary);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:.75em;margin-left:12px;transition:all .3s;font-family:inherit}
.copy-btn:hover{background:var(--accent);color:white}
/* Kanban */
.kanban-board{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:25px;margin-top:25px}
.kanban-column{background:var(--bg-primary);border:1px solid var(--border);border-radius:12px;min-height:550px}
.kanban-column-header{padding:18px 22px;border-bottom:1px solid var(--border);background:linear-gradient(135deg,var(--bg-tertiary),var(--bg-secondary));border-radius:12px 12px 0 0;display:flex;justify-content:space-between;align-items:center}
.kanban-column-title{font-weight:bold;font-size:1.1em;display:flex;align-items:center;gap:8px}
.kanban-column-count{background:var(--accent);color:white;padding:6px 14px;border-radius:20px;font-size:.85em;font-weight:600}
.kanban-column-content{padding:15px;max-height:600px;overflow-y:auto}
.kanban-column-content.drag-over{background:rgba(59,130,246,.15);border:2px dashed var(--accent)}
.kanban-card{background:linear-gradient(145deg,var(--bg-secondary),var(--bg-tertiary));border:1px solid var(--border);border-radius:10px;padding:20px;margin-bottom:16px;cursor:move;transition:all .3s;border-left:4px solid var(--warning);box-shadow:0 3px 10px rgba(0,0,0,.15);animation:cardSlideIn .4s ease-out}
@keyframes cardSlideIn{from{opacity:0;transform:translateY(20px) scale(.95)}to{opacity:1;transform:translateY(0) scale(1)}}
.kanban-card:hover{transform:translateY(-4px) scale(1.02);box-shadow:0 8px 25px rgba(0,0,0,.2);border-color:var(--accent)}
.kanban-card.tested{border-left-color:var(--success);background:linear-gradient(145deg,rgba(16,185,129,.08),rgba(16,185,129,.03))}
.kanban-card.vulnerable{border-left-color:var(--critical);background:linear-gradient(145deg,rgba(239,68,68,.08),rgba(239,68,68,.03))}
.kanban-card.in-progress{border-left-color:var(--info)}
.kanban-card.dragging{opacity:.5;transform:rotate(5deg)}
.kanban-card-header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px;gap:12px}
.kanban-card-url{font-family:'Fira Code',monospace;font-size:.92em;font-weight:600;color:var(--text-primary);text-decoration:none;word-break:break-all;display:block;padding:4px 0}
.kanban-card-url:hover{color:var(--accent);text-decoration:underline}
.kanban-card-actions{display:flex;gap:6px;flex-shrink:0}
.kanban-card-badges{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.kanban-badge{padding:4px 10px;border-radius:12px;font-size:.72em;font-weight:700;display:flex;align-items:center;gap:4px;text-transform:uppercase}
.badge-tested-k{background:linear-gradient(135deg,var(--success),#00b359);color:white}
.badge-pending-k{background:linear-gradient(135deg,var(--warning),#e59400);color:black}
.badge-vuln-k{background:linear-gradient(135deg,var(--critical),#e63939);color:white}
.badge-prog-k{background:linear-gradient(135deg,var(--info),#3b82f6);color:white}
.kanban-card-info{background:rgba(255,255,255,.05);padding:12px 14px;border-radius:6px;border-left:3px solid var(--accent);margin-top:8px}
.kanban-response-info{font-family:'Fira Code',monospace;font-size:.78em;color:var(--text-secondary);line-height:1.5}
.empty-column{text-align:center;color:var(--text-secondary);padding:50px 25px;font-style:italic;opacity:.7}
.empty-column i{font-size:2.5em;margin-bottom:15px;display:block}
.empty{text-align:center;color:var(--text-secondary);padding:40px;font-style:italic}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:var(--bg-primary);border-radius:5px}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:5px;border:2px solid var(--bg-primary)}
::-webkit-scrollbar-thumb:hover{background:var(--accent)}
"""

JS = r"""
// Tab management
document.querySelectorAll('.tab').forEach(tab=>{
  tab.addEventListener('click',function(){
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c=>c.classList.remove('active'));
    this.classList.add('active');
    document.getElementById(this.dataset.tab+'-tab').classList.add('active');
  });
});
// Cards
document.querySelectorAll('.data-card-header').forEach(h=>{
  h.addEventListener('click',()=>h.parentElement.classList.toggle('expanded'));
});
// Copy
function copyToClipboard(text){
  navigator.clipboard.writeText(text).then(()=>alert('Copied!')).catch(e=>console.error(e));
}
// Subdomain filter
function filterSubdomains(){
  const search=document.getElementById('subdomainSearch').value.toLowerCase();
  const type=document.getElementById('typeFilter').value;
  const status=document.getElementById('statusFilter').value;
  document.querySelectorAll('.subdomain-item,.interesting-subdomain-item').forEach(item=>{
    let show=true;
    const url=item.innerText.toLowerCase();
    const itype=item.getAttribute('data-type');
    const grp=item.getAttribute('data-status-group');
    if(search&&!url.includes(search))show=false;
    if(type!=='all'&&itype!==type)show=false;
    if(status!=='all'){
      if(status==='unknown'&&grp!=='unknown')show=false;
      else if(status!=='unknown'&&grp!==status)show=false;
    }
    item.style.display=show?'block':'none';
  });
}
// Dork checkboxes
const storagePrefix=document.querySelector('meta[name="dashboard-storage-prefix"]').getAttribute('content');
function getStorageKey(el){return storagePrefix+(el.closest('.dork-item').dataset.storageKey||el.id);}
function loadCheckboxStates(){
  document.querySelectorAll('.dork-checkbox').forEach(cb=>{
    const key=getStorageKey(cb);
    const checked=localStorage.getItem(key)==='true';
    cb.checked=checked;
    if(checked)cb.closest('.dork-item').classList.add('checked');
  });
}
function saveCheckboxState(cb){
  localStorage.setItem(getStorageKey(cb),cb.checked);
  cb.closest('.dork-item').classList.toggle('checked',cb.checked);
}
document.addEventListener('click',e=>{
  if(e.target.closest('.dork-link')){
    const cb=e.target.closest('.dork-item').querySelector('.dork-checkbox');
    if(cb&&!cb.checked){cb.checked=true;saveCheckboxState(cb);}
  }
});
document.addEventListener('change',e=>{
  if(e.target.classList.contains('dork-checkbox'))saveCheckboxState(e.target);
});
// Kanban
function generateId(){return 'target_'+Math.random().toString(36).substr(2,9);}
function getAnalysisTargets(){const r=localStorage.getItem(storagePrefix+'analysis_targets');return r?JSON.parse(r):[];}
function saveAnalysisTargets(t){localStorage.setItem(storagePrefix+'analysis_targets',JSON.stringify(t));}
function addToAnalysisTargets(sub,info){
  const targets=getAnalysisTargets();
  if(targets.some(t=>t.subdomain===sub)){alert('Already in targets: '+sub);return;}
  targets.push({id:generateId(),subdomain:sub,additionalInfo:info||'',tested:false,status:'pending',createdAt:new Date().toISOString()});
  saveAnalysisTargets(targets);updateKanbanBoard();updateStats();alert('Added: '+sub);
}
function removeFromAnalysisTargets(id){
  saveAnalysisTargets(getAnalysisTargets().filter(t=>t.id!==id));
  updateKanbanBoard();updateStats();
}
function updateTargetStatus(id,status){
  const targets=getAnalysisTargets();
  const t=targets.find(x=>x.id===id);
  if(t){t.status=status;t.tested=status==='tested';saveAnalysisTargets(targets);}
  updateKanbanBoard();updateStats();
}
function generateDashboardPath(sub){return'subdomains/subdomain_analysis/'+sub.replace(/[^a-zA-Z0-9.-]/g,'_')+'/dashboard.html';}
function renderKanbanCard(target){
  const badges={
    pending:'<div class="kanban-badge badge-pending-k"><i class="fas fa-clock"></i> Pending</div>',
    'in-progress':'<div class="kanban-badge badge-prog-k"><i class="fas fa-spinner"></i> In Progress</div>',
    tested:'<div class="kanban-badge badge-tested-k"><i class="fas fa-check-circle"></i> Tested</div>',
    vulnerable:'<div class="kanban-badge badge-vuln-k"><i class="fas fa-exclamation-triangle"></i> Vulnerable</div>'
  };
  const sb=badges[target.status]||badges.pending;
  const info=target.additionalInfo?`<div class="kanban-card-info"><div class="kanban-response-info">${target.additionalInfo}</div></div>`:'';
  const dashBtn=(target.status!=='pending')?`<button class="btn btn-info" onclick="window.open('${generateDashboardPath(target.subdomain)}','_blank')"><i class="fas fa-tachometer-alt"></i></button>`:'';
  const cc=target.status==='tested'?'tested':target.status==='vulnerable'?'vulnerable':target.status==='in-progress'?'in-progress':'';
  return`<div class="kanban-card ${cc}" data-target-id="${target.id}" draggable="true">
    <div class="kanban-card-header">
      <a href="https://${target.subdomain}" target="_blank" class="kanban-card-url">${target.subdomain}</a>
      <div class="kanban-card-actions">
        ${dashBtn}
        <button class="btn btn-primary" onclick="window.open('https://${target.subdomain}','_blank')"><i class="fas fa-external-link-alt"></i></button>
        <button class="btn btn-danger" onclick="removeFromAnalysisTargets('${target.id}')"><i class="fas fa-trash"></i></button>
      </div>
    </div>
    <div class="kanban-card-badges">${sb}</div>${info}
  </div>`;
}
function updateKanbanColumn(status,targets){
  const col=document.querySelector('.kanban-column-content[data-status="'+status+'"]');
  if(!col)return;
  col.innerHTML=targets.length?targets.map(renderKanbanCard).join(''):
    `<div class="empty-column"><i class="fas fa-bug"></i><div>No ${status} targets</div></div>`;
}
function updateKanbanBoard(){
  const all=getAnalysisTargets();
  const groups={pending:[],  'in-progress':[],tested:[],vulnerable:[]};
  all.forEach(t=>{if(groups[t.status])groups[t.status].push(t);});
  const el=document.getElementById('analysis-targets-count');if(el)el.textContent=all.length+' targets';
  ['pending','in-progress','tested','vulnerable'].forEach(s=>{
    const ce=document.getElementById(s+'-count');if(ce)ce.textContent=groups[s].length;
    updateKanbanColumn(s,groups[s]);
  });
  initializeDragAndDrop();updateStats();
}
function initializeDragAndDrop(){
  document.querySelectorAll('.kanban-card').forEach(card=>{
    card.addEventListener('dragstart',e=>{e.dataTransfer.setData('text/plain',e.target.dataset.targetId);e.target.classList.add('dragging');setTimeout(()=>e.target.style.opacity='.4',0);});
    card.addEventListener('dragend',e=>{e.target.classList.remove('dragging');e.target.style.opacity='';document.querySelectorAll('.kanban-column-content').forEach(c=>c.classList.remove('drag-over'));});
  });
  document.querySelectorAll('.kanban-column-content').forEach(col=>{
    col.addEventListener('dragover',e=>{e.preventDefault();e.dataTransfer.dropEffect='move';});
    col.addEventListener('dragenter',e=>{e.preventDefault();const c=e.target.closest('.kanban-column-content');if(c)c.classList.add('drag-over');});
    col.addEventListener('dragleave',e=>{const c=e.target.closest('.kanban-column-content');if(c&&!c.contains(e.relatedTarget))c.classList.remove('drag-over');});
    col.addEventListener('drop',e=>{
      e.preventDefault();
      const id=e.dataTransfer.getData('text/plain');
      const c=e.target.closest('.kanban-column-content');
      if(c)updateTargetStatus(id,c.dataset.status);
      document.querySelectorAll('.kanban-column-content').forEach(x=>x.classList.remove('drag-over'));
    });
  });
}
function updateStats(){
  document.getElementById('stat-subdomains').textContent=document.querySelectorAll('.subdomain-item,.interesting-subdomain-item').length;
  document.getElementById('stat-emails').textContent=document.querySelectorAll('.email-item').length;
  document.getElementById('stat-dorks').textContent=document.querySelectorAll('.dork-item').length;
  document.getElementById('stat-takeovers').textContent=document.querySelectorAll('.takeover-item').length;
  document.getElementById('stat-cloud').textContent=document.querySelectorAll('.cloud-item').length;
  document.getElementById('stat-vulnerabilities').textContent=document.querySelectorAll('.vuln-item').length;
  const targets=getAnalysisTargets();
  document.getElementById('stat-analysis-targets').textContent=targets.length;
  document.getElementById('stat-vulnerable-targets').textContent=targets.filter(t=>t.status==='vulnerable').length;
}
// Cloud filters
function filterOpenCloudItems(btn){
  btn.parentElement.querySelectorAll('.btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.cloud-item').forEach(i=>{i.style.display=i.dataset.status==='open'?'block':'none';});
}
function showAllCloudItems(btn){
  btn.parentElement.querySelectorAll('.btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.cloud-item').forEach(i=>{i.style.display='block';});
}
// Service filters
function filterHostsByPort(btn,port){
  btn.parentElement.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.host-scan').forEach(h=>{
    if(port==='all'){h.style.display='block';return;}
    h.style.display=[...h.querySelectorAll('.service-item')].some(i=>i.dataset.port===port)?'block':'none';
  });
}
function filterHostsByService(btn,svc){
  btn.parentElement.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.host-scan').forEach(h=>{
    if(svc==='all'){h.style.display='block';return;}
    h.style.display=[...h.querySelectorAll('.service-item')].some(i=>i.dataset.service===svc)?'block':'none';
  });
}
// Takeover filter
function filterTakeovers(btn,group){
  btn.parentElement.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.querySelectorAll('.takeover-item').forEach(item=>{
    item.style.display=(group==='all'||item.dataset.statusGroup===group)?'block':'none';
  });
}
// SC filter
function filterBySC(btn,group,cid){
  const items=document.getElementById(cid).querySelectorAll('.vuln-item');
  btn.parentElement.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  items.forEach(item=>{item.style.display=(group==='all'||item.dataset.statusGroup===group)?'block':'none';});
}
// Screenshot modal
function openScreenshotModal(src){const m=document.getElementById('screenshotModal');document.getElementById('modalScreenshot').src=src;m.classList.add('active');}
function closeScreenshotModal(){document.getElementById('screenshotModal').classList.remove('active');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeScreenshotModal();});
// Screenshot loader
function loadScreenshots(){
  document.querySelectorAll('.subdomain-screenshot').forEach(img=>{
    const sub=img.getAttribute('data-subdomain');
    const base='screenshot_report/screens/';
    const fmts=['http.'+sub+'.png','https.'+sub+'.png',
      sub.replace(/[^a-zA-Z0-9.-]/g,'_')+'.png',
      'http.'+sub.replace(/[^a-zA-Z0-9.-]/g,'_')+'.png',
      'https.'+sub.replace(/[^a-zA-Z0-9.-]/g,'_')+'.png',
      sub.replace(/\./g,'_')+'.png',sub+'.png'];
    function tryNext(i){
      if(i>=fmts.length){img.style.display='none';img.nextElementSibling.style.display='flex';return;}
      const t=new Image();
      t.onload=()=>{img.src=base+fmts[i];img.classList.add('loaded');img.style.display='block';img.nextElementSibling.style.display='none';img.onclick=e=>{e.stopPropagation();openScreenshotModal(base+fmts[i]);};};
      t.onerror=()=>tryNext(i+1);
      t.src=base+fmts[i];
    }
    tryNext(0);
  });
}
// Init
document.addEventListener('DOMContentLoaded',()=>{
  document.querySelectorAll('.data-card-content').forEach(content=>{
    const h=content.previousElementSibling;
    const btn=document.createElement('button');
    btn.className='copy-btn';btn.innerHTML='<i class="fas fa-copy"></i> Copy';
    btn.onclick=e=>{e.stopPropagation();copyToClipboard(content.textContent||content.innerText);};
    h.appendChild(btn);
  });
  loadCheckboxStates();
  updateKanbanBoard();
  initializeDragAndDrop();
  updateStats();
  loadScreenshots();
  document.querySelectorAll('.data-card').forEach((c,i)=>{if(i===0)c.classList.add('expanded');});
});
"""


# ─────────────────────────────────────────────────────────────────────────────
# Tab builders
# ─────────────────────────────────────────────────────────────────────────────

def _tab_subdomains(data: DomainReconData) -> str:
    subs = data.all_subdomains
    o = ['<div class="content-section">',
         '<div class="section-title"><i class="fas fa-sitemap"></i> Subdomain Intelligence</div>',
         f'<div class="data-card"><div class="data-card-header">'
         f'<div class="data-card-title"><i class="fas fa-network-wired"></i> Final Subdomains</div>'
         f'<div class="data-card-count">{len(subs)} subdomains</div></div>',
         '<div class="data-card-content">',
         '''<div class="subdomain-controls">
  <input type="text" id="subdomainSearch" placeholder="Search subdomains..." onkeyup="filterSubdomains()"/>
  <select id="typeFilter" onchange="filterSubdomains()">
    <option value="all">All</option><option value="interesting">Interesting</option><option value="regular">Regular</option>
  </select>
  <select id="statusFilter" onchange="filterSubdomains()">
    <option value="all">All Codes</option><option value="200">200 OK</option>
    <option value="300">3xx Redirects</option><option value="400">4xx Errors</option>
    <option value="500">5xx Server Errors</option><option value="unknown">No Response</option>
  </select>
</div>''',
         '<div class="subdomain-list" style="max-height:800px;overflow-y:auto">']

    if not subs:
        o.append('<div class="empty"><i class="fas fa-search" style="font-size:2em;display:block;margin-bottom:10px"></i>No subdomains discovered yet</div>')
    else:
        for sub in sorted(subs, key=lambda s: (data.status_map.get(s, 999), s)):
            hs   = _h(sub)
            code = data.status_map.get(sub)
            info = data.info_map.get(sub, "")
            badge_html, grp = _status_badge(code)
            cls_info = _classify(sub)
            shot = f'screenshot_report/screens/{sub}.png'

            if cls_info:
                priority, badge_cls, hl_cls, icon, label = cls_info
                sbadge = f'<span class="subdomain-badge {badge_cls}"><i class="fas {icon}"></i> {label}</span>'
                o.append(f'<div class="interesting-subdomain-item {hl_cls}" data-type="interesting" data-status-group="{grp}" style="border-left:4px solid;margin-bottom:8px">')
                o.append(f'<div class="subdomain-content-wrapper">')
                o.append(f'<img class="subdomain-screenshot" data-src="{shot}" data-subdomain="{hs}" alt=""/>')
                o.append(f'<div class="screenshot-placeholder"><i class="fas fa-image"></i></div>')
                o.append(f'<div class="subdomain-info-container"><div class="subdomain-main-row">')
                o.append(f'<a href="https://{hs}" target="_blank" class="interesting-subdomain-link"><i class="fas {icon}"></i><span class="interesting-subdomain-url">{hs}</span></a>')
                o.append(f'<div style="display:flex;align-items:center;gap:10px"><span style="font-size:.7em;font-weight:bold">{priority}</span> {sbadge} {badge_html}')
                o.append(f'<button class="add-target-btn" onclick="addToAnalysisTargets(\'{hs}\',\'\')"><i class="fas fa-bug"></i> Add to Analysis</button></div>')
                o.append(f'</div>')
                if info:
                    o.append(f'<div class="response-additional-info">{_h(info[:150])}</div>')
                o.append('</div></div></div>')
            else:
                extra = ""
                if re.match(r'^(dev|staging|test|qa)', sub): extra = "warning-highlight"
                elif re.match(r'^(api|gateway|auth)', sub): extra = "content-highlight"
                elif re.match(r'^(admin|dashboard|control)', sub): extra = "danger-highlight"
                o.append(f'<div class="subdomain-item {extra}" data-type="regular" data-status-group="{grp}" style="padding:10px 15px">')
                o.append(f'<div class="subdomain-content-wrapper">')
                o.append(f'<img class="subdomain-screenshot" data-src="{shot}" data-subdomain="{hs}" alt=""/>')
                o.append(f'<div class="screenshot-placeholder"><i class="fas fa-image"></i></div>')
                o.append(f'<div class="subdomain-info-container"><div class="subdomain-main-row">')
                o.append(f'<a href="https://{hs}" target="_blank" class="interesting-subdomain-link"><i class="fas fa-globe"></i><span class="interesting-subdomain-url">{hs}</span></a>')
                o.append(f'<div style="display:flex;align-items:center;gap:10px"> {badge_html}')
                o.append(f'<button class="add-target-btn" onclick="addToAnalysisTargets(\'{hs}\',\'\')"><i class="fas fa-bug"></i> Add to Analysis</button></div>')
                o.append('</div>')
                if info:
                    o.append(f'<div class="response-additional-info">{_h(info[:150])}</div>')
                o.append('</div></div></div>')

    o += ['</div>', '</div>', '</div>',
          # Screenshot modal
          '<div class="screenshot-modal" id="screenshotModal" onclick="closeScreenshotModal()"><span class="screenshot-modal-close">&times;</span><img id="modalScreenshot" src="" alt=""></div>',
          # Kanban
          '''<div class="data-card">
<div class="data-card-header"><div class="data-card-title"><i class="fas fa-crosshairs"></i> Analysis Targets - Kanban Board</div><div class="data-card-count" id="analysis-targets-count">0 targets</div></div>
<div class="data-card-content"><div class="kanban-board">
<div class="kanban-column"><div class="kanban-column-header"><div class="kanban-column-title"><i class="fas fa-clock"></i> Pending</div><div class="kanban-column-count" id="pending-count">0</div></div><div class="kanban-column-content" data-status="pending"><div class="empty-column"><i class="fas fa-bug"></i><div>No pending targets</div></div></div></div>
<div class="kanban-column"><div class="kanban-column-header"><div class="kanban-column-title"><i class="fas fa-spinner"></i> In Progress</div><div class="kanban-column-count" id="in-progress-count">0</div></div><div class="kanban-column-content" data-status="in-progress"><div class="empty-column"><i class="fas fa-bug"></i><div>No in-progress targets</div></div></div></div>
<div class="kanban-column"><div class="kanban-column-header"><div class="kanban-column-title"><i class="fas fa-shield-alt"></i> Tested</div><div class="kanban-column-count" id="tested-count">0</div></div><div class="kanban-column-content" data-status="tested"><div class="empty-column"><i class="fas fa-bug"></i><div>No tested targets</div></div></div></div>
<div class="kanban-column"><div class="kanban-column-header"><div class="kanban-column-title"><i class="fas fa-exclamation-triangle"></i> Vulnerable</div><div class="kanban-column-count" id="vulnerable-count">0</div></div><div class="kanban-column-content" data-status="vulnerable"><div class="empty-column"><i class="fas fa-bug"></i><div>No vulnerable targets</div></div></div></div>
</div></div></div>''',
          '</div>']
    return "\n".join(o)


def _tab_dorks(data: DomainReconData) -> str:
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-search"></i> Dorks Intelligence</div>']

    def _card(title, icon, raw, prefix, is_secret=False):
        # Filter out header lines and empty lines
        lines = [l for l in raw.splitlines() 
                 if l.strip() and 
                 not l.startswith(('🔎', '════', 'Total dork URLs','🐙','Findings:','[+] got','error:'))]  # Skip header lines
        
        if not lines:
            return
            
        o.append(f'<div class="data-card"><div class="data-card-header">'
                 f'<div class="data-card-title"><i class="{icon}"></i> {title}</div>'
                 f'<div class="data-card-count">{len(lines)}</div></div>'
                 f'<div class="data-card-content"><div class="dorks-container">')
        
        for i, line in enumerate(lines):
            sk = re.sub(r'[^a-zA-Z0-9]', '_', f'{prefix}_{i}_{line}')[:80]
            cls = "dork-item"
            if is_secret: 
                cls += " danger-highlight"
            elif re.search(r'(password|passwd|secret|api[_-]?key)', line, re.I): 
                cls += " danger-highlight"
            elif re.search(r'(admin|login|dashboard)', line, re.I): 
                cls += " warning-highlight"
            elif re.search(r'(backup|sql|dump|database)', line, re.I): 
                cls += " content-highlight"

            mu = re.search(r'(https?://\S+)', line)
            url = mu.group(1) if mu else ""
            if url:
                desc = line.replace(url,"").strip().lstrip("#").strip() or "Search"
                icon_i = 'fab fa-github' if 'github' in url else 'fas fa-external-link-alt'
                content = (f'<div class="dork-content"><a href="{_h(url)}" target="_blank" class="dork-link">'
                           f'<i class="{icon_i} dork-icon"></i><span class="dork-text">{_h(desc)}</span></a></div>')
            elif is_secret:
                colored = _h(line)
                colored = re.sub(r'(AKIA[0-9A-Z]{16})', r'<span class="secret-highlight-span">\1 🔑 AWS</span>', colored)
                colored = re.sub(r'(ghp_[a-zA-Z0-9]{36})', r'<span class="secret-highlight-span">\1 🔐 GitHub</span>', colored)
                colored = re.sub(r'(xoxb-[a-zA-Z0-9-]+)', r'<span class="secret-highlight-span">\1 💬 Slack</span>', colored)
                content = f'<div class="dork-content"><i class="fas fa-shield-alt dork-icon"></i><span class="dork-text">{colored}</span></div>'
            else:
                content = f'<div class="dork-content"><i class="fas fa-search dork-icon"></i><span class="dork-text">{_h(line)}</span></div>'

            o.append(f'<div class="{cls}" data-storage-key="{sk}"><input type="checkbox" class="dork-checkbox" id="{sk}"> {content}</div>')
        o.append('</div></div></div>')

    _card("Google Dorks",       "fab fa-google", data.google_dorks,   "gdork")
    _card("GitHub Dorks",       "fab fa-github", data.github_dorks,   "ghdork")
    _card("GitHub Secrets Scan","fas fa-key",    data.github_secrets, "secret", is_secret=True)
    o.append('</div>')
    return "\n".join(o)


def _tab_emails(data: DomainReconData) -> str:
    emails = data.email_list
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-envelope"></i> Email Discovery</div>',
         f'<div class="data-card"><div class="data-card-header"><div class="data-card-title"><i class="fas fa-users"></i> Discovered Emails</div><div class="data-card-count">{len(emails)}</div></div>',
         '<div class="data-card-content">']
    if not emails:
        o.append('<div class="empty">No emails found yet</div>')
    for e in emails:
        he = _h(e)
        if re.search(r'(admin|root|administrator)', e, re.I): cls, ic = "email-item danger-highlight", "fa-crown"
        elif re.search(r'(security|sec|soc)', e, re.I): cls, ic = "email-item warning-highlight", "fa-shield-alt"
        elif re.search(r'(dev|developer|engineer)', e, re.I): cls, ic = "email-item content-highlight", "fa-code"
        else: cls, ic = "email-item", "fa-user"
        o.append(f'<div class="{cls}"><i class="fas {ic}"></i> {he}</div>')
    o += ['</div></div>', '</div>']
    return "\n".join(o)


def _tab_cloud(data: DomainReconData) -> str:
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-cloud"></i> Cloud Infrastructure</div>',
         '<div style="margin-bottom:10px">',
         '<button class="btn btn-secondary active" onclick="showAllCloudItems(this)">Show All</button>',
         '<button class="btn btn-secondary" onclick="filterOpenCloudItems(this)">Show Only Open/Accessible</button>',
         '</div>']
    if not data.cloud:
        o.append('<div class="empty">Run Cloud Enum task to populate</div>')
    for label, lines in data.cloud.items():
        o.append(f'<div class="data-card"><div class="data-card-header"><div class="data-card-title"><i class="fas fa-cloud"></i> {_h(label)}</div><div class="data-card-count">{len(lines)}</div></div>'
                 f'<div class="data-card-content"><div class="data-content">')
        for line in lines:
            is_open = bool(re.search(r'(open|200|accessible)', line, re.I))
            cls = "cloud-item danger-highlight" if is_open else "cloud-item"
            st  = "open" if is_open else "closed"
            icon = '<i class="fas fa-bucket"></i> ' if is_open else ""
            o.append(f'<div class="{cls}" data-status="{st}">{icon}{_h(line)}</div>')
        o.append('</div></div></div>')
    o.append('</div>')
    return "\n".join(o)


def _tab_services(data: DomainReconData) -> str:
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-server"></i> Service Discovery</div>']
    if not data.service_scan:
        o += ['<div class="empty">Run Service Scan task to populate</div>', '</div>']
        return "\n".join(o)

    ports: set = set()
    svcs:  set = set()
    for line in data.service_scan.splitlines():
        m = re.match(r'(\d+/(tcp|udp))\s+\S+\s+(\S+)', line)
        if m:
            ports.add(m.group(1))
            if m.group(3) not in ("", "unknown", ""):
                svcs.add(m.group(3))

    o.append('<div class="filter-bar"><button class="filter-btn active" onclick="filterHostsByPort(this,\'all\')">All Ports</button>')
    for p in sorted(ports):
        o.append(f'<button class="filter-btn" onclick="filterHostsByPort(this,\'{_h(p)}\')">{_h(p)}</button>')
    o.append('</div>')
    o.append('<div class="filter-bar" style="margin-bottom:12px"><button class="filter-btn active" onclick="filterHostsByService(this,\'all\')">All Services</button>')
    for s in sorted(svcs):
        o.append(f'<button class="filter-btn" onclick="filterHostsByService(this,\'{_h(s)}\')">{_h(s)}</button>')
    o.append('</div>')

    host_idx = 0
    in_host = False
    for line in data.service_scan.splitlines():
        if re.match(r'Nmap scan report for', line):
            if in_host: o.append('</div>')
            host_idx += 1
            o.append(f'<div class="host-scan" id="host-{host_idx}"><div class="host-title">{_h(line)}</div>')
            in_host = True
        elif re.match(r'\d+/(tcp|udp)', line):
            parts = line.split()
            port = parts[0]; state = parts[1] if len(parts)>1 else ""; svc = parts[2] if len(parts)>2 else ""
            icon = "✅" if "open" in state else ("🔒" if "filtered" in state else "❌")
            o.append(f'<div class="service-item" data-port="{_h(port)}" data-service="{_h(svc)}">{_h(port)} {_h(state)} {_h(svc)} {icon}</div>')
        elif in_host:
            o.append(f'<div>{_h(line)}</div>')
    if in_host: o.append('</div>')
    o.append('</div>')
    return "\n".join(o)


def _tab_takeovers(data: DomainReconData) -> str:
    lines = data.takeover_lines
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-skull-crossbones"></i> Subdomain Takeovers</div>']
    if not lines:
        o += ['<div class="empty">Run Takeover Scan task to populate</div>', '</div>']
        return "\n".join(o)

    # Filter out header and formatting lines to get only actual result lines
    result_lines = [l for l in lines 
                    if l.strip() and  # Skip empty lines
                    not l.startswith(('🎯', '════', 'Vulnerable:', '✅'))]  # Skip header lines
    
    # Count vulnerabilities only from actual result lines
    vuln = sum(1 for l in result_lines 
               if not re.search(r'Not Vulnerable|\[Not Vulnerable\]', l))
    
    o.append(f'<div class="filter-bar">'
             f'<button class="filter-btn active" onclick="filterTakeovers(this,\'all\')">All ({len(result_lines)})</button>'
             f'<button class="filter-btn" onclick="filterTakeovers(this,\'vulnerable\')">Vulnerable Only ({vuln})</button></div>')
    
    o.append('<div class="data-card"><div class="data-card-header"><div class="data-card-title"><i class="fas fa-exclamation-triangle"></i> Takeover Analysis</div></div><div class="data-card-content"><div class="data-content">')
    
    # Only display actual result lines, not headers
    for line in result_lines:
        is_vuln = not re.search(r'Not Vulnerable|\[Not Vulnerable\]', line)
        grp = "vulnerable" if is_vuln else "safe"
        cls = "takeover-item danger-highlight" if is_vuln else "takeover-item"
        icon = '<i class="fas fa-bug"></i>' if is_vuln else '<i class="fas fa-shield-alt"></i>'
        o.append(f'<div class="{cls}" data-status-group="{grp}">{icon} {_h(line)}</div>')
    
    o += ['</div></div></div>', '</div>']
    return "\n".join(o)


def _tab_bypass(data: DomainReconData) -> str:
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-bug"></i> Security Findings</div>']

    def _sc_group(c): return "2xx" if 200<=c<300 else "3xx" if 300<=c<400 else "4xx" if 400<=c<500 else "5xx" if 500<=c<600 else "unknown"
    def _badge(c): return "badge-danger" if c>=400 else "badge-warning" if c>=300 else "badge-success" if c>=200 else "badge-info" if c>=100 else "badge-default"
    def _icon(c): return "fa-skull-crossbones" if c>=400 else "fa-exchange-alt" if c>=300 else "fa-check-circle" if c>=200 else "fa-info-circle" if c>=100 else "fa-dot-circle"
    def _parse_code(line):
        m = re.search(r'\b(\d{3})\b', line)
        return int(m.group(1)) if m else 999

    def _card(title, icon, lines, cid):
        if not lines: return
        items = sorted((_parse_code(l), l) for l in lines)
        counts = {"2xx":0,"3xx":0,"4xx":0,"5xx":0,"unknown":0}
        for code, _ in items: counts[_sc_group(code)] += 1
        total = len(items)
        o.append('<div class="filter-bar">')
        o.append(f'<button class="filter-btn active" onclick="filterBySC(this,\'all\',\'{cid}\')">All ({total})</button>')
        for g in ("2xx","3xx","4xx","5xx","unknown"):
            o.append(f'<button class="filter-btn" onclick="filterBySC(this,\'{g}\',\'{cid}\')">{g} ({counts[g]})</button>')
        o.append('</div>')
        o.append(f'<div class="data-card"><div class="data-card-header"><div class="data-card-title"><i class="fas {icon}"></i> {title}</div><div class="data-card-count">{total}</div></div>')
        o.append(f'<div class="data-card-content" id="{cid}"><div class="data-content">')
        for code, line in items:
            grp = _sc_group(code)
            mu = re.search(r'(https?://\S+)', line)
            url = mu.group(1) if mu else ""
            dom = line.split(":")[0].strip() if not url else re.sub(r'^https?://','',url).split("/")[0]
            click = f"onclick=\"window.open('{_h(url or 'https://'+dom)}','_blank')\"" if dom else ""
            cb = f' <span class="{_badge(code)}"><i class="fas {_icon(code)}"></i> {code if code!=999 else ""}</span>' if code != 999 else ""
            o.append(f'<div class="vuln-item clickable" data-status-group="{grp}" {click}>{_h(dom or line)}{cb}</div>')
        o.append('</div></div></div>')

    _card("40x Subdomains Bypass Results",   "fa-unlock", data.bypass_40x,     "bypass-container")
    _card("404 POST Bruteforce Results",      "fa-hammer", data.post_bruteforce,"post-container")
    _card("404 GET Bruteforce Results",       "fa-hammer", data.get_bruteforce, "get-container")

    if not data.bypass_40x and not data.post_bruteforce and not data.get_bruteforce:
        o.append('<div class="empty">Run Bypass 40x task to populate</div>')
    o.append('</div>')
    return "\n".join(o)


def _tab_screenshots(data: DomainReconData) -> str:
    o = ['<div class="content-section"><div class="section-title"><i class="fas fa-camera"></i> Visual Reconnaissance</div>']
    if os.path.isfile(data.screenshot_report):
        rel = os.path.relpath(data.screenshot_report, data.domain_dir)
        o.append(f'''<div class="data-card"><div class="data-card-header"><div class="data-card-title"><i class="fas fa-images"></i> Eyewitness Screenshot Report</div><div class="data-card-count">Available</div></div>
<div class="data-card-content">
  <p style="margin-bottom:14px">Screenshots have been captured and are ready to view.</p>
  <a href="{_h(rel)}" target="_blank" class="btn btn-primary"><i class="fas fa-external-link-alt"></i> Open Screenshot Report</a>
</div></div>''')
    else:
        o.append('<div class="empty">Run Screenshot task to populate</div>')
    o.append('</div>')
    return "\n".join(o)


# ─────────────────────────────────────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────────────────────────────────────

def generate(domain: str, project_dir: str,
             live_subdomains_file: Optional[str] = None) -> str:
    domain_dir = os.path.join(project_dir, "domains", domain)
    tasks_dir  = os.path.join(project_dir, "tasks")
    os.makedirs(domain_dir, exist_ok=True)

    data = DomainReconData(domain, domain_dir, tasks_dir,
                           live_subdomains_file=live_subdomains_file)

    storage_prefix = re.sub(r'[^a-zA-Z0-9]', '_', f'recondash_{domain}_')

    dork_count = (len([l for l in data.google_dorks.splitlines() if l.strip()]) +
                  len([l for l in data.github_dorks.splitlines() if l.strip()]))
    stats = [
        ("stat-subdomains",        "Subdomains",          len(data.all_subdomains)),
        ("stat-emails",            "Emails",              len(data.email_list)),
        ("stat-dorks",             "Dorks Results",       dork_count),
        ("stat-takeovers",         "Potential Takeovers", len(data.takeover_lines)),
        ("stat-cloud",             "Cloud Assets",        sum(len(v) for v in data.cloud.values())),
        ("stat-vulnerabilities",   "Security Findings",   len(data.bypass_40x)+len(data.post_bruteforce)+len(data.get_bruteforce)),
        ("stat-analysis-targets",  "Analysis Targets",    0),
        ("stat-vulnerable-targets","Vulnerable Targets",  0),
    ]
    stats_html = "".join(
        f'<div class="stat-card"><div class="stat-number" id="{sid}">{val}</div><div class="stat-label">{label}</div></div>'
        for sid, label, val in stats
    )

    tab_icons = {
        "subdomains":"sitemap","dorks":"search","emails":"envelope","cloud":"cloud",
        "services":"server","takeovers":"skull-crossbones","access-bypass":"hammer","screenshots":"camera"
    }
    tabs = [
        ("subdomains",   "🌐 Subdomains",   _tab_subdomains(data)),
        ("dorks",        "🔎 Dorks",         _tab_dorks(data)),
        ("emails",       "📧 Emails",        _tab_emails(data)),
        ("cloud",        "☁️ Cloud",         _tab_cloud(data)),
        ("services",     "🔌 Services",      _tab_services(data)),
        ("takeovers",    "🎯 Takeovers",     _tab_takeovers(data)),
        ("access-bypass","🔓 Access Bypass", _tab_bypass(data)),
        ("screenshots",  "📸 Screenshots",   _tab_screenshots(data)),
    ]
    tab_btns = "".join(
        f'<button class="tab{" active" if i==0 else ""}" data-tab="{tid}">'
        f'<i class="fas fa-{tab_icons.get(tid, "circle")}"></i> {label}</button>'
        for i,(tid,label,_) in enumerate(tabs)
    )
    tab_contents = "".join(
        f'<div id="{tid}-tab" class="tab-content{" active" if i==0 else ""}">{content}</div>'
        for i,(tid,_,content) in enumerate(tabs)
    )

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="dashboard-storage-prefix" content="{_h(storage_prefix)}">
<title>Hackrecon Reconnaissance Dashboard - {_h(domain)}</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>{CSS}</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1><i class="fas fa-crosshairs"></i> HACKRECON RECONNAISSANCE DASHBOARD</h1>
    <div class="domain">{_h(domain)}</div>
    <div style="margin-top:10px;color:var(--text-secondary);font-size:.9em">Generated on {now}</div>
  </div>
  <div class="stats-grid">{stats_html}</div>
  <div class="tabs">{tab_btns}</div>
  {tab_contents}
</div>
<script>{JS}</script>
</body>
</html>"""

    out_path = os.path.join(domain_dir, "report.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return out_path


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: domain_report.py <domain> <project_dir>")
        sys.exit(1)
    path = generate(sys.argv[1], sys.argv[2])
    print(f"Report: {path}")