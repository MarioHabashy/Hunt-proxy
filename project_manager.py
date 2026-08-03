#!/usr/bin/env python3
"""
project_manager.py - Persistent project storage for HackRecon Hunt GUI

Stores everything under ~/hackrecon_projects/<program_slug>/
Structure:
    ~/hackrecon_projects/
        projects.json           <- index of all programs
        <program_slug>/
            project.json        <- program meta + domains + subdomains
            scope_rules.json    <- include/exclude scope rules
            hunt.jsonl          <- captured traffic
            requests/           <- raw request files
            responses/          <- raw response files
            notes.json          <- user notes

Scope Rules Format (scope_rules.json):
[
  {
    "enabled": true,
    "type": "include",         # "include" | "exclude"
    "protocol": "any",         # "any" | "http" | "https"
    "host": "example.com",     # exact host, *.example.com for wildcard, or "" for any
    "all_subdomains": true,    # if true, *.host is also in scope
    "port": "",                # "" means any port
    "comment": ""
  }
]
"""

import os
import json
import re
import time
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any


# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

HACKRECON_DIR = os.path.expanduser("~/hackrecon_projects")
PROJECTS_INDEX = os.path.join(HACKRECON_DIR, "projects.json")


def _ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def _slug(name: str) -> str:
    """Convert program name to filesystem-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9_\-]", "_", slug)
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug or "unnamed"


# ─────────────────────────────────────────────────────────────────────────────
# Index helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_index() -> Dict[str, Any]:
    _ensure_dir(HACKRECON_DIR)
    if os.path.exists(PROJECTS_INDEX):
        try:
            with open(PROJECTS_INDEX, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"programs": {}}


def _save_index(index: Dict[str, Any]):
    _ensure_dir(HACKRECON_DIR)
    with open(PROJECTS_INDEX, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# Program CRUD
# ─────────────────────────────────────────────────────────────────────────────

def list_programs() -> List[Dict[str, Any]]:
    """Return list of all programs sorted by name."""
    index = _load_index()
    programs = []
    for slug, meta in index.get("programs", {}).items():
        programs.append({
            "slug": slug,
            "name": meta.get("name", slug),
            "platform": meta.get("platform", ""),
            "platform_url": meta.get("platform_url", ""),
            "created_at": meta.get("created_at", ""),
        })
    programs.sort(key=lambda p: p["name"].lower())
    return programs


def create_program(name: str, platform: str = "", platform_url: str = "") -> str:
    """
    Create a new program. Returns its slug.
    Raises ValueError if name already exists.
    """
    slug = _slug(name)
    index = _load_index()

    if slug in index.get("programs", {}):
        raise ValueError(f"Program '{name}' already exists (slug: {slug})")

    project_dir = os.path.join(HACKRECON_DIR, slug)
    _ensure_dir(project_dir)
    _ensure_dir(os.path.join(project_dir, "requests"))
    _ensure_dir(os.path.join(project_dir, "responses"))

    project_data = {
        "name": name,
        "platform": platform,
        "platform_url": platform_url,
        "created_at": datetime.now().isoformat(),
        "updated_at": datetime.now().isoformat(),
        "domains": {}   # domain -> {subdomains: [], notes: "", all_subdomains_in_scope: bool}
    }

    _write_project(slug, project_data)

    index.setdefault("programs", {})[slug] = {
        "name": name,
        "platform": platform,
        "platform_url": platform_url,
        "created_at": project_data["created_at"],
    }
    _save_index(index)
    return slug


def delete_program(slug: str, delete_data: bool = False):
    """Delete program from index, optionally wipe disk data."""
    index = _load_index()
    index.get("programs", {}).pop(slug, None)
    _save_index(index)

    if delete_data:
        project_dir = os.path.join(HACKRECON_DIR, slug)
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)


def get_program(slug: str) -> Optional[Dict[str, Any]]:
    """Load full program data including domains/subdomains."""
    path = _project_path(slug)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["slug"] = slug
        return data
    except Exception:
        return None


def update_program_meta(slug: str, name: str = None, platform: str = None,
                        platform_url: str = None):
    """Update top-level metadata fields."""
    data = get_program(slug)
    if data is None:
        raise ValueError(f"Program '{slug}' not found")

    if name is not None:
        data["name"] = name
    if platform is not None:
        data["platform"] = platform
    if platform_url is not None:
        data["platform_url"] = platform_url
    data["updated_at"] = datetime.now().isoformat()

    _write_project(slug, data)

    # Update index too
    index = _load_index()
    entry = index.get("programs", {}).get(slug, {})
    if name is not None:
        entry["name"] = name
    if platform is not None:
        entry["platform"] = platform
    if platform_url is not None:
        entry["platform_url"] = platform_url
    index["programs"][slug] = entry
    _save_index(index)


# ─────────────────────────────────────────────────────────────────────────────
# Domain CRUD
# ─────────────────────────────────────────────────────────────────────────────

def list_domains(slug: str) -> List[str]:
    data = get_program(slug)
    if data is None:
        return []
    return sorted(data.get("domains", {}).keys())


def add_domain(slug: str, domain: str, all_subdomains_in_scope: bool = False):
    domain = domain.strip().lower()
    if not domain:
        raise ValueError("Domain cannot be empty")
    data = get_program(slug)
    if data is None:
        raise ValueError(f"Program '{slug}' not found")
    data.setdefault("domains", {})
    if domain not in data["domains"]:
        data["domains"][domain] = {
            "subdomains": [],
            "notes": "",
            "all_subdomains_in_scope": all_subdomains_in_scope
        }
    else:
        data["domains"][domain]["all_subdomains_in_scope"] = all_subdomains_in_scope
    data["updated_at"] = datetime.now().isoformat()
    _write_project(slug, data)

    # Sync to scope rules
    _sync_scope_rules_from_domains(slug)


def remove_domain(slug: str, domain: str):
    data = get_program(slug)
    if data is None:
        return
    data.get("domains", {}).pop(domain, None)
    data["updated_at"] = datetime.now().isoformat()
    _write_project(slug, data)
    _sync_scope_rules_from_domains(slug)


def get_domain_settings(slug: str, domain: str) -> Optional[Dict]:
    """Get settings for a specific domain, like `all_subdomains_in_scope`."""
    data = get_program(slug)
    if data:
        return data.get("domains", {}).get(domain)
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Subdomain CRUD
# ─────────────────────────────────────────────────────────────────────────────

def list_subdomains(slug: str, domain: str) -> List[str]:
    data = get_program(slug)
    if data is None:
        return []
    return sorted(data.get("domains", {}).get(domain, {}).get("subdomains", []))


def add_subdomain(slug: str, domain: str, subdomain: str):
    subdomain = subdomain.strip().lower()
    if not subdomain:
        raise ValueError("Subdomain cannot be empty")
    data = get_program(slug)
    if data is None:
        raise ValueError(f"Program '{slug}' not found")
    subs = data.get("domains", {}).get(domain, {}).get("subdomains", [])
    if subdomain not in subs:
        subs.append(subdomain)
        subs.sort()
        data["domains"][domain]["subdomains"] = subs
    data["updated_at"] = datetime.now().isoformat()
    _write_project(slug, data)
    _sync_scope_rules_from_domains(slug)


def remove_subdomain(slug: str, domain: str, subdomain: str):
    data = get_program(slug)
    if data is None:
        return
    subs = data.get("domains", {}).get(domain, {}).get("subdomains", [])
    if subdomain in subs:
        subs.remove(subdomain)
        data["domains"][domain]["subdomains"] = subs
    data["updated_at"] = datetime.now().isoformat()
    _write_project(slug, data)
    _sync_scope_rules_from_domains(slug)


def bulk_add_subdomains(slug: str, domain: str, subdomains: List[str]):
    """Add multiple subdomains at once (e.g. paste from amass output)."""
    data = get_program(slug)
    if data is None:
        raise ValueError(f"Program '{slug}' not found")
    data["domains"].setdefault(domain, {"subdomains": [], "notes": ""})
    existing = set(data["domains"][domain]["subdomains"])
    cleaned = [s.strip().lower() for s in subdomains if s.strip()]
    existing.update(cleaned)
    data["domains"][domain]["subdomains"] = sorted(existing)
    data["updated_at"] = datetime.now().isoformat()
    _write_project(slug, data)
    _sync_scope_rules_from_domains(slug)


# ─────────────────────────────────────────────────────────────────────────────
#  Scope Rules
# ─────────────────────────────────────────────────────────────────────────────

def _scope_rules_path(slug: str) -> str:
    return os.path.join(HACKRECON_DIR, slug, "scope_rules.json")


def load_scope_rules(slug: str) -> List[Dict[str, Any]]:
    """
    Load scope rules from disk.
    Returns list of rule dicts:
    {
        "enabled": bool,
        "type": "include" | "exclude",
        "protocol": "any" | "http" | "https",
        "host": str,           # e.g. "example.com" or "*.example.com"
        "all_subdomains": bool,
        "port": str,           # "" = any
        "comment": str
    }
    """
    path = _scope_rules_path(slug)
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def save_scope_rules(slug: str, rules: List[Dict[str, Any]]):
    """Persist scope rules to disk."""
    path = _scope_rules_path(slug)
    _ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2)


def add_scope_rule(slug: str, rule_type: str, host: str,
                   all_subdomains: bool = True,
                   protocol: str = "any", port: str = "",
                   comment: str = "", enabled: bool = True) -> Dict[str, Any]:
    """
    Add a single scope rule. Returns the new rule.
    rule_type: "include" | "exclude"
    """
    rule = {
        "enabled": enabled,
        "type": rule_type,
        "protocol": protocol,
        "host": host.strip().lower(),
        "all_subdomains": all_subdomains,
        "port": port.strip(),
        "comment": comment.strip(),
    }
    rules = load_scope_rules(slug)
    rules.append(rule)
    save_scope_rules(slug, rules)
    return rule


def remove_scope_rule(slug: str, index: int):
    """Remove scope rule at given index."""
    rules = load_scope_rules(slug)
    if 0 <= index < len(rules):
        rules.pop(index)
        save_scope_rules(slug, rules)


def update_scope_rule(slug: str, index: int, updates: Dict[str, Any]):
    """Update fields of rule at given index."""
    rules = load_scope_rules(slug)
    if 0 <= index < len(rules):
        rules[index].update(updates)
        save_scope_rules(slug, rules)


def _sync_scope_rules_from_domains(slug: str):
    """
    Keep scope_rules.json in sync with project.json domains/subdomains.
    Called after any domain/subdomain add/remove.
    Ensures every domain and subdomain has a corresponding include rule.
    Does NOT remove rules that were manually added by the user.
    """
    data = get_program(slug)
    if not data:
        return

    existing_rules = load_scope_rules(slug)

    # Build set of host values already in rules
    existing_hosts = {r["host"] for r in existing_rules if r.get("type") == "include"}

    new_rules = list(existing_rules)

    for domain, info in data.get("domains", {}).items():
        if domain not in existing_hosts:
            new_rules.append({
                "enabled": True,
                "type": "include",
                "protocol": "any",
                "host": domain,
                "all_subdomains": info.get("all_subdomains_in_scope", False),
                "port": "",
                "comment": f"Auto-added domain",
            })
        else:
            # Update all_subdomains flag to match domain setting
            for r in new_rules:
                if r.get("host") == domain and r.get("type") == "include":
                    r["all_subdomains"] = info.get("all_subdomains_in_scope", r.get("all_subdomains", False))
                    break

        for sub in info.get("subdomains", []):
            if sub not in existing_hosts:
                new_rules.append({
                    "enabled": True,
                    "type": "include",
                    "protocol": "any",
                    "host": sub,
                    "all_subdomains": False,
                    "port": "",
                    "comment": f"Auto-added subdomain of {domain}",
                })

    save_scope_rules(slug, new_rules)


# ─────────────────────────────────────────────────────────────────────────────
# Smart scope matching
# ─────────────────────────────────────────────────────────────────────────────

def _host_matches_rule_host(host: str, rule_host: str, all_subdomains: bool) -> bool:
    """
    Check if `host` matches the rule's host pattern.
    - Exact match: host == rule_host
    - Wildcard prefix: rule_host starts with "*." → matches any subdomain
    - all_subdomains=True: *.rule_host is also in scope
    """
    host = host.lower().strip()
    rule_host = rule_host.lower().strip()

    if not rule_host:
        return True  # empty = match all

    # Explicit wildcard: *.example.com
    if rule_host.startswith("*."):
        base = rule_host[2:]
        return host == base or host.endswith("." + base)

    # Exact match
    if host == rule_host:
        return True

    # all_subdomains flag: treat rule_host as base, include subdomains
    if all_subdomains and host.endswith("." + rule_host):
        return True

    return False


def _protocol_matches(scheme: str, rule_protocol: str) -> bool:
    if rule_protocol in ("any", ""):
        return True
    return scheme.lower() == rule_protocol.lower()


def _port_matches(port: str, rule_port: str) -> bool:
    if not rule_port or rule_port == "any":
        return True
    return str(port) == str(rule_port)


def is_in_scope(slug: str, url: str) -> bool:
    """
    Scope check: a URL is in scope if:
      1. At least one INCLUDE rule matches
      2. No EXCLUDE rule matches
    If no include rules exist at all, everything is in scope (capture all).
    """
    if not slug:
        return True

    rules = load_scope_rules(slug)
    if not rules:
        return True  # no rules = capture everything

    # Parse url components
    try:
        from urllib.parse import urlparse as _urlparse
        parsed = _urlparse(url if "://" in url else "http://" + url)
        scheme = parsed.scheme.lower() or "http"
        host = parsed.hostname or ""
        port = str(parsed.port or ("443" if scheme == "https" else "80"))
    except Exception:
        return False

    include_rules = [r for r in rules if r.get("enabled", True) and r.get("type") == "include"]
    exclude_rules = [r for r in rules if r.get("enabled", True) and r.get("type") == "exclude"]

    if not include_rules:
        # No include rules = everything is in scope
        matched_include = True
    else:
        matched_include = False
        for rule in include_rules:
            if (
                _host_matches_rule_host(host, rule.get("host", ""), rule.get("all_subdomains", False))
                and _protocol_matches(scheme, rule.get("protocol", "any"))
                and _port_matches(port, rule.get("port", ""))
            ):
                matched_include = True
                break

    if not matched_include:
        return False

    # Check exclude rules - any match → out of scope
    for rule in exclude_rules:
        if (
            _host_matches_rule_host(host, rule.get("host", ""), rule.get("all_subdomains", False))
            and _protocol_matches(scheme, rule.get("protocol", "any"))
            and _port_matches(port, rule.get("port", ""))
        ):
            return False

    return True


def is_host_in_scope(slug: str, host: str, scheme: str = "http", port: str = "") -> bool:
    """Convenience: check a raw host (no URL needed)."""
    url = f"{scheme}://{host}"
    if port:
        url += f":{port}"
    return is_in_scope(slug, url)


# ─────────────────────────────────────────────────────────────────────────────
# Project file paths (used by GUI to set JSONL/requests/responses dirs)
# ─────────────────────────────────────────────────────────────────────────────

def get_project_paths(slug: str) -> Dict[str, str]:
    """Return all important paths for a project."""
    project_dir = os.path.join(HACKRECON_DIR, slug)
    return {
        "project_dir": project_dir,
        "jsonl": os.path.join(project_dir, "hunt.jsonl"),
        "requests_dir": os.path.join(project_dir, "requests"),
        "responses_dir": os.path.join(project_dir, "responses"),
        "notes_file": os.path.join(project_dir, "notes.json"),
        "highlights_file": os.path.join(project_dir, "highlights.json"),
        "scope_rules_file": os.path.join(project_dir, "scope_rules.json"),
    }


def ensure_project_dirs(slug: str):
    """Create all required directories for a project."""
    paths = get_project_paths(slug)
    for key in ("project_dir", "requests_dir", "responses_dir"):
        _ensure_dir(paths[key])


# ─────────────────────────────────────────────────────────────────────────────
# Scope helpers (used by hunt_script addon and dashboard)
# ─────────────────────────────────────────────────────────────────────────────

def get_scope_hosts(slug: str, domain: str = "", subdomain: str = "") -> List[str]:
    """
    Return list of hosts that are in scope for the current selection.
    - If subdomain is set → only that subdomain
    - If domain is set but no subdomain → domain + all its subdomains
    - If neither → all domains/subdomains of the program

    This is used for display/dashboard purposes.
    For proxy filtering, use is_in_scope() with scope rules instead.
    """
    data = get_program(slug)
    if data is None:
        return []

    if subdomain:
        return [subdomain]

    hosts = []
    for d, info in data.get("domains", {}).items():
        if domain and d != domain:
            continue
        hosts.append(d)
        hosts.extend(info.get("subdomains", []))

    return list(set(hosts))


def get_all_scope_targets(slug: str) -> Dict[str, List[str]]:
    """
    Returns a dict of {domain: [subdomains]} for all domains in the project.
    Also extracts parent domains from subdomain entries.
    e.g. if subdomain is "api.sub.example.com", parent domain "example.com" is also returned
    in the domains set if it's already registered.

    Used by Dashboard to auto-populate domain and subdomain sections.
    """
    data = get_program(slug)
    if not data:
        return {}

    result: Dict[str, List[str]] = {}

    for domain, info in data.get("domains", {}).items():
        subs = info.get("subdomains", [])
        result[domain] = sorted(subs)

    return result


def extract_parent_domain(host: str, registered_domains: List[str]) -> Optional[str]:
    """
    Given a hostname like 'api.sub.example.com' and a list of registered domains,
    find which registered domain it belongs to.
    Returns the registered parent domain, or None.
    """
    host = host.lower().strip()
    for d in sorted(registered_domains, key=len, reverse=True):
        if host == d or host.endswith("." + d):
            return d
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _project_path(slug: str) -> str:
    return os.path.join(HACKRECON_DIR, slug, "project.json")


def _write_project(slug: str, data: Dict[str, Any]):
    path = _project_path(slug)
    _ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)