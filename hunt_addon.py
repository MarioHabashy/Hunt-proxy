#!/usr/bin/env python3
"""
hunt_addon.py – mitmproxy addon for Hunt GUI

Enhanced scope checking:
  - Reads HUNT_SCOPE_RULES_FILE (JSON) with Burp-style include/exclude rules
  - Falls back to HUNT_SCOPE_HOSTS (simple JSON list) if no rules file
  - Supports wildcard hosts (*.example.com), all_subdomains flag, protocol/port filtering
  - Auto-reloads scope rules file when it changes on disk (no proxy restart needed for scope edits)
"""

import os
import json
import base64
import uuid
import time
import threading
import logging
import gzip
import re
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional
from mitmproxy import http
from urllib.parse import urlparse as _urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("HuntAddon")


# ─────────────────────────────────────────────────────────────────────────────
# Scope rule matching helpers (duplicated from project_manager to avoid Qt deps)
# ─────────────────────────────────────────────────────────────────────────────

def _host_matches_rule(host: str, rule_host: str, all_subdomains: bool) -> bool:
    """
    Check if `host` matches the rule's host pattern.
    - Empty rule_host → match all
    - *.example.com → any subdomain of example.com (incl. example.com itself)
    - all_subdomains=True → host or *.host
    """
    host = host.lower().strip()
    rule_host = rule_host.lower().strip()

    if not rule_host:
        return True

    if rule_host.startswith("*."):
        base = rule_host[2:]
        return host == base or host.endswith("." + base)

    if host == rule_host:
        return True

    if all_subdomains and host.endswith("." + rule_host):
        return True

    return False


def _protocol_matches(scheme: str, rule_protocol: str) -> bool:
    if not rule_protocol or rule_protocol in ("any", ""):
        return True
    return scheme.lower() == rule_protocol.lower()


def _port_matches(port_str: str, rule_port: str) -> bool:
    if not rule_port or rule_port in ("any", ""):
        return True
    return str(port_str) == str(rule_port)


def check_scope_rules(rules: List[Dict[str, Any]], host: str,
                      scheme: str = "http", port: str = "") -> bool:
    """
    Burp-style scope check using a list of include/exclude rules.
    Returns True if host is in scope.
    """
    if not rules:
        return True  # no rules = everything in scope

    include_rules = [r for r in rules if r.get("enabled", True) and r.get("type") == "include"]
    exclude_rules = [r for r in rules if r.get("enabled", True) and r.get("type") == "exclude"]

    if not include_rules:
        matched_include = True
    else:
        matched_include = False
        for rule in include_rules:
            if (
                _host_matches_rule(host, rule.get("host", ""), rule.get("all_subdomains", False))
                and _protocol_matches(scheme, rule.get("protocol", "any"))
                and _port_matches(port, rule.get("port", ""))
            ):
                matched_include = True
                break

    if not matched_include:
        return False

    for rule in exclude_rules:
        if (
            _host_matches_rule(host, rule.get("host", ""), rule.get("all_subdomains", False))
            and _protocol_matches(scheme, rule.get("protocol", "any"))
            and _port_matches(port, rule.get("port", ""))
        ):
            return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# Main addon
# ─────────────────────────────────────────────────────────────────────────────

class HuntProxyAddon:
    """
    Mitmproxy addon that:
      1. Captures all in-scope HTTP traffic → JSONL + request/response files
      2. Optionally intercepts (pauses) flows for GUI editing/dropping
      3. Uses Burp-style scope rules (include/exclude) from scope_rules.json
      4. Auto-reloads scope rules when the file changes (no proxy restart needed)
    """

    def __init__(self):
        self.request_count = 0
        self._lock = threading.Lock()

        # Populated in configure()
        self.out_jsonl = ""
        self.out_ws_jsonl = ""          # WebSocket message log
        self.requests_dir = ""
        self.responses_dir = ""
        self.intercept_queue_file = ""
        self.intercept_actions_dir = ""
        self.intercept_enabled_file = ""
        self.intercept_responses_file = ""
        self.ws_intercept_enabled_file = ""
        self.proxy_rules_file = ""

        # Scope — rules take priority over legacy hosts list
        self.scope_rules: List[Dict[str, Any]] = []
        self.scope_rules_file: str = ""
        self._scope_rules_mtime: float = 0.0
        self.scope_hosts: List[str] = []   # legacy fallback

        # Match & replace rules (proxy_config.json → "match_replace")
        self.match_replace_rules: List[Dict[str, Any]] = []

        # Header injection entries (proxy_config.json → "header_inject")
        self.header_inject_entries: List[Dict[str, Any]] = []

        # Drop rules (proxy_config.json → "drop_rules")
        self.drop_rules: List[Dict[str, Any]] = []

        # SSL / redirect config (proxy_config.json → "ssl")
        self.ssl_config: Dict[str, Any] = {}

        # Rate-limiting config (proxy_config.json → "rate_limit")
        self.rate_config: Dict[str, Any] = {}
        self._last_request_time: float = 0.0

        # One-shot per-flow response intercept
        # (set when GUI chooses "Intercept response for this request")
        self._one_shot_lock = threading.Lock()
        self._one_shot_response_intercepts: set = set()   # stores mitmproxy flow.id strings

        # Bounded thread pool for intercept polling — prevents thread exhaustion
        # when many flows are intercepted simultaneously (max 50 concurrent pollers)
        self._intercept_pool = ThreadPoolExecutor(max_workers=50,
                                                  thread_name_prefix="intercept")

    # ── mitmproxy lifecycle ────────────────────────────────────────────────

    def configure(self, updated):
        self.out_jsonl              = os.environ.get("HUNT_MODE_JSONL",          "/tmp/hunt.jsonl")
        self.out_ws_jsonl           = os.environ.get("HUNT_WS_JSONL",            "/tmp/hunt_ws.jsonl")
        self.requests_dir           = os.environ.get("HUNT_MODE_REQUESTS_DIR",   "/tmp/requests")
        self.responses_dir          = os.environ.get("HUNT_MODE_RESPONSES_DIR",  "/tmp/responses")
        self.intercept_queue_file   = os.environ.get("HUNT_INTERCEPT_QUEUE",     "/tmp/intercept_queue.jsonl")
        self.intercept_actions_dir  = os.environ.get("HUNT_INTERCEPT_ACTIONS",   "/tmp/intercept_actions")
        self.intercept_enabled_file = os.environ.get("HUNT_INTERCEPT_ENABLED",   "/tmp/intercept_enabled")
        self.intercept_responses_file = os.environ.get("HUNT_INTERCEPT_RESPONSES", "/tmp/intercept_responses")
        self.ws_intercept_enabled_file = os.environ.get("HUNT_WS_INTERCEPT_ENABLED", "/tmp/ws_intercept_enabled")
        self.proxy_rules_file       = os.environ.get("HUNT_PROXY_RULES",         "")
        self.scope_rules_file       = os.environ.get("HUNT_SCOPE_RULES_FILE",    "")

        # Load Burp-style scope rules from file
        self._load_scope_rules()

        # Legacy fallback: HUNT_SCOPE_HOSTS env var
        scope_json = os.environ.get("HUNT_SCOPE_HOSTS", "[]")
        try:
            self.scope_hosts = json.loads(scope_json)
        except Exception:
            self.scope_hosts = []

        # If no rules file but have legacy hosts, synthesize rules from hosts
        if not self.scope_rules and self.scope_hosts:
            self.scope_rules = [
                {
                    "enabled": True,
                    "type": "include",
                    "protocol": "any",
                    "host": h.lower().strip(),
                    "all_subdomains": True,
                    "port": "",
                    "comment": "from HUNT_SCOPE_HOSTS",
                }
                for h in self.scope_hosts
            ]

        # Create directories
        os.makedirs(self.requests_dir,          exist_ok=True, mode=0o755)
        os.makedirs(self.responses_dir,         exist_ok=True, mode=0o755)
        os.makedirs(self.intercept_actions_dir, exist_ok=True, mode=0o755)

        # ── Recover request_count from existing JSONL so seq continues ────
        # Only do this once at startup (request_count == 0 means not yet set)
        with self._lock:
            if self.request_count == 0 and os.path.exists(self.out_jsonl):
                max_seq = 0
                try:
                    with open(self.out_jsonl, "r", encoding="utf-8", errors="replace") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                entry = json.loads(line)
                                seq = int(entry.get("seq", 0))
                                if seq > max_seq:
                                    max_seq = seq
                            except Exception:
                                continue
                except Exception as e:
                    logger.warning(f"Could not read JSONL for seq recovery: {e}")
                if max_seq > 0:
                    self.request_count = max_seq
                    logger.info(f"Seq counter restored to {max_seq} from existing JSONL")

        if not os.path.exists(self.intercept_queue_file):
            open(self.intercept_queue_file, "a").close()
        else:
            self._cleanup_old_queue_entries()

        # Load unified proxy config (proxy_config.json) or fall back to legacy proxy_rules.json
        proxy_config_file = os.environ.get("HUNT_PROXY_CONFIG", "")
        if proxy_config_file and os.path.exists(proxy_config_file):
            try:
                with open(proxy_config_file, "r") as f:
                    cfg = json.load(f)
                self.match_replace_rules   = cfg.get("match_replace",  [])
                self.header_inject_entries = cfg.get("header_inject",  [])
                self.drop_rules            = cfg.get("drop_rules",     [])
                self.ssl_config            = cfg.get("ssl",            {})
                self.rate_config           = cfg.get("rate_limit",     {})
                logger.info(
                    f"Loaded proxy config: {len(self.match_replace_rules)} M&R rules, "
                    f"{len(self.header_inject_entries)} header injections, "
                    f"{len(self.drop_rules)} drop rules"
                )
            except Exception as e:
                logger.error(f"Failed to load proxy config: {e}")
        elif self.proxy_rules_file and os.path.exists(self.proxy_rules_file):
            # Legacy fallback: plain match & replace list
            try:
                with open(self.proxy_rules_file, "r") as f:
                    self.match_replace_rules = json.load(f)
                logger.info(f"Loaded {len(self.match_replace_rules)} match & replace rules (legacy)")
            except Exception as e:
                logger.error(f"Failed to load proxy rules: {e}")

        logger.info("HuntProxyAddon configured")
        logger.info(f"  JSONL:       {self.out_jsonl}")
        logger.info(f"  Scope rules: {len(self.scope_rules)} rules from {self.scope_rules_file or 'env'}")
        logger.info(f"  Requests:    {self.requests_dir}")
        logger.info(f"  Responses:   {self.responses_dir}")

        # Start background scope rules watcher
        self._start_scope_watcher()

    def _load_scope_rules(self):
        """Load scope rules from scope_rules_file if available."""
        if not self.scope_rules_file:
            return
        if not os.path.exists(self.scope_rules_file):
            return
        try:
            mtime = os.path.getmtime(self.scope_rules_file)
            with open(self.scope_rules_file, "r", encoding="utf-8") as f:
                self.scope_rules = json.load(f)
            self._scope_rules_mtime = mtime
            logger.info(f"Loaded {len(self.scope_rules)} scope rules from {self.scope_rules_file}")
        except Exception as e:
            logger.error(f"Failed to load scope rules: {e}")

    def _start_scope_watcher(self):
        """Background thread: poll scope_rules.json for changes and hot-reload."""
        if not self.scope_rules_file:
            return

        def _watch():
            while True:
                try:
                    if os.path.exists(self.scope_rules_file):
                        mtime = os.path.getmtime(self.scope_rules_file)
                        if mtime > self._scope_rules_mtime:
                            self._load_scope_rules()
                            logger.info("🔄 Scope rules hot-reloaded (file changed)")
                except Exception:
                    pass
                time.sleep(2)

        t = threading.Thread(target=_watch, daemon=True, name="scope-watcher")
        t.start()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _in_scope(self, host: str, scheme: str = "http", port: str = "") -> bool:
        """
        Burp-style scope check.
        Uses loaded scope_rules (include/exclude).
        Falls back to legacy scope_hosts list if no rules defined.
        """
        # If both empty → capture everything
        if not self.scope_rules and not self.scope_hosts:
            return True

        # Use scope rules if available
        if self.scope_rules:
            return check_scope_rules(self.scope_rules, host, scheme, port)

        # Legacy: simple host list match
        host_lower = host.lower()
        return any(
            host_lower == s.lower() or host_lower.endswith("." + s.lower())
            for s in self.scope_hosts
        )

    def _intercept_enabled(self) -> bool:
        return os.path.exists(self.intercept_enabled_file)

    def _intercept_responses_enabled(self) -> bool:
        return os.path.exists(self.intercept_responses_file)

    def _ws_intercept_enabled(self) -> bool:
        return os.path.exists(self.ws_intercept_enabled_file)

    # ── mitmproxy hooks ───────────────────────────────────────────────────

    def request(self, flow):
        """Process request — rate-limit, drop rules, M&R, header injection, SSL upgrade."""
        try:

            # ── Rate limiting ─────────────────────────────────────────────────
            self._apply_rate_limit(flow)

            # ── Drop rules (request phase) ────────────────────────────────────
            if self._should_drop(flow, "request"):
                flow.kill()
                return

            # ── Match & Replace (request) ─────────────────────────────────────
            self._apply_rules(flow, "request")

            # ── Header injection (request) ────────────────────────────────────
            self._inject_headers(flow, "Request")

            # ── HTTPS upgrade ─────────────────────────────────────────────────
            if self.ssl_config.get("upgrade_to_https") and flow.request.scheme == "http":
                flow.request.scheme = "https"
                if flow.request.port == 80:
                    flow.request.port = 443

            # ── Scope check ───────────────────────────────────────────────────
            port   = str(flow.request.port or "")
            scheme = flow.request.scheme or "http"
            if not self._in_scope(flow.request.host, scheme, port):
                return

            logger.debug(f"Request: {flow.request.method} {flow.request.pretty_url}")
            self._save_request_immediate(flow)

            if self._intercept_enabled():
                self._pause_flow(flow, "request")

        except Exception as e:
            logger.error(
                f"Unhandled error in request hook for "
                f"{getattr(flow.request, 'pretty_url', '?')}: {e}",
                exc_info=True,
            )
    def response(self, flow):
        """Process response — drop rules, M&R, header injection, SSL strip, security header removal."""
        try:

            # ── Drop rules (response phase) ───────────────────────────────────
            if self._should_drop(flow, "response"):
                flow.kill()
                return

            # ── Match & Replace (response) ────────────────────────────────────
            self._apply_rules(flow, "response")

            # ── Header injection (response) ───────────────────────────────────
            self._inject_headers(flow, "Response")

            # ── SSL strip: rewrite Location https → http ──────────────────────
            if self.ssl_config.get("ssl_strip") and flow.response:
                loc = flow.response.headers.get("Location", "")
                if loc.startswith("https://"):
                    flow.response.headers["Location"] = "http://" + loc[8:]

            # ── Security header removal ────────────────────────────────────────
            if flow.response:
                if self.ssl_config.get("remove_hsts"):
                    flow.response.headers.pop("Strict-Transport-Security", None)
                if self.ssl_config.get("remove_csp"):
                    flow.response.headers.pop("Content-Security-Policy", None)
                    flow.response.headers.pop("Content-Security-Policy-Report-Only", None)
                if self.ssl_config.get("remove_xframe"):
                    flow.response.headers.pop("X-Frame-Options", None)
                if self.ssl_config.get("remove_xcto"):
                    flow.response.headers.pop("X-Content-Type-Options", None)

            # ── CORS bypass ────────────────────────────────────────────────────
            if self.ssl_config.get("cors_bypass") and flow.response:
                flow.response.headers["Access-Control-Allow-Origin"]      = "*"
                flow.response.headers["Access-Control-Allow-Credentials"] = "true"
                flow.response.headers["Access-Control-Allow-Methods"]     = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
                flow.response.headers["Access-Control-Allow-Headers"]     = "*"

            # ── Scope check ───────────────────────────────────────────────────
            port   = str(flow.request.port or "")
            scheme = flow.request.scheme or "http"
            if not self._in_scope(flow.request.host, scheme, port):
                return

            resp_code = flow.response.status_code if flow.response else "?"
            resp_enabled = self._intercept_responses_enabled()
            logger.info(
                f"Response: {flow.request.pretty_url} → {resp_code} "
                f"[intercept_responses={resp_enabled}]"
            )
            self._save_response_immediate(flow)

            # ── One-shot response intercept ────────────────────────
            _one_shot_resp = False

            # Primary: file-based marker (most reliable across thread/timing boundaries)
            _marker = os.path.join(self.intercept_actions_dir, f"oneshot_resp_{flow.id}")
            if os.path.exists(_marker):
                try:
                    os.remove(_marker)
                except Exception:
                    pass
                _one_shot_resp = True
                logger.info(f"File-based one-shot response intercept for {flow.id}")

            # Fallback: in-memory set (registered by _poll_action thread)
            if not _one_shot_resp:
                with self._one_shot_lock:
                    if flow.id in self._one_shot_response_intercepts:
                        self._one_shot_response_intercepts.discard(flow.id)
                        _one_shot_resp = True
                        logger.info(f"Memory-based one-shot response intercept for {flow.id}")

            if ((_one_shot_resp
                 or (self._intercept_enabled() and self._intercept_responses_enabled()))
                    and not getattr(flow, "hunt_dropped", False)):
                logger.info(f"Intercepting response for {flow.request.pretty_url} (one_shot={_one_shot_resp})")
                self._pause_flow(flow, "response")
            else:
                logger.debug(
                    f"Passing response through (one_shot={_one_shot_resp}, "
                    f"resp_enabled={self._intercept_responses_enabled()}, "
                    f"dropped={getattr(flow, 'hunt_dropped', False)})"
                )

            self._capture_flow_complete(flow)

        except Exception as e:
            logger.error(
                f"Unhandled error in response hook for "
                f"{getattr(flow.request, 'pretty_url', '?')}: {e}",
                exc_info=True,
            )
    # ── WebSocket hooks ────────────────────────────────────────────────────

    async def websocket_message(self, flow):
        """Capture every WebSocket message (client→server and server→client).
        When both the main intercept toggle and the WS toggle are enabled,
        pauses the message so the user can edit or drop it in the Intercept tab.
        """
        try:
            port   = str(flow.server_conn.address[1] if flow.server_conn and flow.server_conn.address else "")
            scheme = "wss" if (flow.server_conn and getattr(flow.server_conn, "ssl_established", False)) else "ws"

            if not self._in_scope(flow.request.host, scheme, port):
                return

            msg = flow.websocket.messages[-1]

            # Determine opcode label
            try:
                from wsproto.frame_protocol import Opcode as _Opcode
                opcode = "binary" if msg.type == _Opcode.BINARY else "text"
            except Exception:
                opcode = "binary" if getattr(msg, "type", None) and msg.type != 1 else "text"

            raw_content = msg.content if isinstance(msg.content, (bytes, bytearray)) else b""

            # Build payload representation for logging
            if opcode == "text":
                try:
                    payload = raw_content.decode("utf-8", errors="replace")
                except Exception:
                    payload = repr(raw_content)
            else:
                payload = raw_content.hex()

            direction = "client→server" if msg.from_client else "server→client"

            entry_log = {
                "host":       flow.request.host,
                "path":       flow.request.path,
                "url":        flow.request.pretty_url.replace("http://", "ws://").replace("https://", "wss://"),
                "direction":  direction,
                "opcode":     opcode,
                "length":     len(raw_content),
                "payload":    payload,
                "timestamp":  time.strftime("%Y-%m-%dT%H:%M:%S"),
            }

            with self._lock:
                with open(self.out_ws_jsonl, "a", encoding="utf-8") as f:
                    json.dump(entry_log, f)
                    f.write("\n")

            # ── WS Intercept ────────────────────────────────────────────────────────────
            if not (self._intercept_enabled() and self._ws_intercept_enabled()):
                return

            flow_id = str(uuid.uuid4())
            intercept_entry = {
                "id":   flow_id,
                "type": "ws_message",
                "data": base64.b64encode(raw_content).decode(),
                "meta": {
                    "id":        flow_id,
                    "type":      "ws_message",
                    "direction": direction,
                    "opcode":    opcode,
                    "host":      flow.request.host,
                    "url":       flow.request.pretty_url.replace("http://", "ws://").replace("https://", "wss://"),
                    "length":    len(raw_content),
                    "timestamp": time.time(),
                },
            }

            try:
                with open(self.intercept_queue_file, "a", encoding="utf-8") as fq:
                    json.dump(intercept_entry, fq)
                    fq.write("\n")
                    fq.flush()
                    os.fsync(fq.fileno())
            except Exception as e:
                logger.error(f"Failed to write WS intercept queue: {e}")
                return

            logger.info(
                f"WS intercepting {flow_id}: {direction} {len(raw_content)} bytes "
                f"@ {flow.request.host}"
            )

            action_file = os.path.join(self.intercept_actions_dir, f"{flow_id}.action")
            result: Dict[str, Any] = {}

            def _wait_for_action():
                deadline = time.time() + 300
                while time.time() < deadline:
                    if os.path.exists(action_file):
                        try:
                            with open(action_file, "r") as af:
                                result["data"] = json.load(af)
                            os.remove(action_file)
                        except Exception as _e:
                            logger.error(f"Error reading WS action file: {_e}")
                            result["data"] = {"action": "forward"}
                        return
                    time.sleep(0.2)
                logger.warning(f"WS intercept timeout for {flow_id}; forwarding")
                result["data"] = {"action": "forward"}

            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, _wait_for_action)

            action_data = result.get("data", {})
            action      = action_data.get("action", "forward")

            if action == "drop":
                try:
                    msg.kill()
                except Exception:
                    msg.content = b""   # fallback: send empty frame
                return

            edited_b64 = action_data.get("edited_data")
            if edited_b64:
                try:
                    msg.content = base64.b64decode(edited_b64)
                except Exception as _e:
                    logger.error(f"Error applying WS edit: {_e}")

        except Exception as e:
            logger.error(f"WebSocket message error: {e}")

    # ── Rate limiting ──────────────────────────────────────────────────────

    def _apply_rate_limit(self, flow):
        """Sleep if rate limiting is enabled and the request URL matches the filter."""
        cfg = self.rate_config
        if not cfg.get("enabled"):
            return
        url_filter = cfg.get("url_filter", "")
        if url_filter:
            try:
                if not re.search(url_filter, flow.request.pretty_url):
                    return
            except re.error:
                pass

        delay  = float(cfg.get("delay",  0.5))
        jitter = float(cfg.get("jitter", 0.0))
        if jitter > 0:
            import random
            delay += random.uniform(-jitter, jitter)
            delay = max(0.0, delay)

        now     = time.time()
        elapsed = now - self._last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request_time = time.time()

    # ── Drop rules ──────────────────────────────────────────────────────────

    def _should_drop(self, flow, hook_type: str) -> bool:
        """Return True if any enabled drop rule matches this flow at the given hook."""
        for rule in self.drop_rules:
            if not rule.get("enabled", True):
                continue
            target = rule.get("target", "Request")
            if (target == "Request"  and hook_type != "request"):
                continue
            if (target == "Response" and hook_type != "response"):
                continue

            field   = rule.get("field", "URL")
            pattern = rule.get("pattern", "")
            if not pattern:
                continue

            try:
                subject = ""
                if field == "URL":
                    subject = flow.request.pretty_url
                elif field == "Method":
                    subject = flow.request.method
                elif field == "Request header":
                    subject = "\r\n".join(f"{k}: {v}" for k, v in flow.request.headers.items())
                elif field == "Request body":
                    subject = flow.request.get_text(strict=False) or ""
                elif field == "Response header" and flow.response:
                    subject = "\r\n".join(f"{k}: {v}" for k, v in flow.response.headers.items())
                elif field == "Response body" and flow.response:
                    subject = flow.response.get_text(strict=False) or ""
                elif field == "Status code" and flow.response:
                    subject = str(flow.response.status_code)

                if re.search(pattern, subject):
                    logger.info(f"Drop rule matched [{rule.get('comment','no comment')}]: {flow.request.pretty_url}")
                    return True
            except Exception as e:
                logger.error(f"Error evaluating drop rule: {e}")
        return False

    # ── Header injection ────────────────────────────────────────────────────

    def _inject_headers(self, flow, target: str):
        """Inject headers onto request or response for all matching entries."""
        for entry in self.header_inject_entries:
            if not entry.get("enabled", True):
                continue
            if entry.get("target", "Request") != target:
                continue
            name      = entry.get("name", "").strip()
            value     = entry.get("value", "")
            overwrite = entry.get("overwrite", True)
            if not name:
                continue
            try:
                if target == "Request":
                    if overwrite or name not in flow.request.headers:
                        flow.request.headers[name] = value
                elif target == "Response" and flow.response:
                    if overwrite or name not in flow.response.headers:
                        flow.response.headers[name] = value
            except Exception as e:
                logger.error(f"Error injecting header '{name}': {e}")

    # ── Match & Replace ───────────────────────────────────────────────────

    def _apply_rules(self, flow, hook_type):
        if not self.match_replace_rules:
            return

        for rule in self.match_replace_rules:
            if not rule.get("enabled", True):
                continue

            rtype = rule.get("type")
            match_pattern = rule.get("match")
            replace_str = rule.get("replace")

            if not match_pattern:
                continue

            try:
                if hook_type == "request":
                    if rtype == "Request body":
                        if flow.request.content:
                            content = flow.request.get_text(strict=False)
                            if content:
                                new_content = re.sub(match_pattern, replace_str, content)
                                if new_content != content:
                                    flow.request.set_text(new_content)

                    elif rtype == "Request header":
                        for key, value in list(flow.request.headers.items()):
                            header_line = f"{key}: {value}"
                            if re.search(match_pattern, header_line):
                                new_line = re.sub(match_pattern, replace_str, header_line)
                                if not new_line.strip():
                                    del flow.request.headers[key]
                                elif ": " in new_line:
                                    new_key, new_val = new_line.split(": ", 1)
                                    if new_key != key:
                                        del flow.request.headers[key]
                                    flow.request.headers[new_key] = new_val

                elif hook_type == "response":
                    if rtype == "Response body":
                        if flow.response and flow.response.content:
                            content = flow.response.get_text(strict=False)
                            if content:
                                new_content = re.sub(match_pattern, replace_str, content)
                                if new_content != content:
                                    flow.response.set_text(new_content)

                    elif rtype == "Response header":
                        if flow.response:
                            for key, value in list(flow.response.headers.items()):
                                header_line = f"{key}: {value}"
                                if re.search(match_pattern, header_line):
                                    new_line = re.sub(match_pattern, replace_str, header_line)
                                    if not new_line.strip():
                                        del flow.response.headers[key]
                                    elif ": " in new_line:
                                        new_key, new_val = new_line.split(": ", 1)
                                        if new_key != key:
                                            del flow.response.headers[key]
                                        flow.response.headers[new_key] = new_val

            except Exception as e:
                logger.error(f"Error applying rule '{rule.get('comment', '')}': {e}")

    # ── Save helpers ──────────────────────────────────────────────────────

    def _save_request_immediate(self, flow):
        try:
            with self._lock:
                self.request_count += 1
                flow.hunt_req_id = f"{int(time.time())}_{self.request_count}"

            req_path = os.path.join(self.requests_dir, f"{flow.hunt_req_id}.txt")
            with open(req_path, "wb") as f:
                f.write(self._serialise_request(flow))
        except Exception as e:
            logger.error(f"Failed to save request: {e}")

    def _re_save_request(self, flow):
        try:
            req_id = getattr(flow, "hunt_req_id", None)
            if not req_id:
                return
            req_path = os.path.join(self.requests_dir, f"{req_id}.txt")
            with open(req_path, "wb") as f:
                f.write(self._serialise_request(flow))
        except Exception as e:
            logger.error(f"Failed to re-save request: {e}")

    def _save_response_immediate(self, flow):
        try:
            if not flow.response:
                return
            req_id = getattr(flow, "hunt_req_id", None)
            if not req_id:
                return
            resp_path = os.path.join(self.responses_dir, f"{req_id}.txt")
            with open(resp_path, "wb") as f:
                f.write(self._serialise_response(flow))
        except Exception as e:
            logger.error(f"Failed to save response: {e}")

    def _capture_flow_complete(self, flow):
        try:
            req_id = getattr(flow, "hunt_req_id", None)
            if not req_id:
                return

            finding = {
                "url":           flow.request.pretty_url,
                "method":        flow.request.method,
                "host":          flow.request.host,
                "path":          flow.request.path,
                "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%S"),
                "seq":           int(req_id.split("_")[-1]) if "_" in req_id else 0,
                "request_file":  os.path.join(self.requests_dir, f"{req_id}.txt"),
                "response_file": os.path.join(self.responses_dir, f"{req_id}.txt"),
            }

            if flow.response:
                finding["status"]          = flow.response.status_code
                finding["content_type"]    = flow.response.headers.get("content-type", "")
                finding["response_length"] = len(flow.response.content or b"")

            with open(self.out_jsonl, "a", encoding="utf-8") as f:
                json.dump(finding, f)
                f.write("\n")

            logger.info(
                f"Captured: {flow.request.method} {flow.request.pretty_url} → "
                f"{flow.response.status_code if flow.response else '?'}"
            )
        except Exception as e:
            logger.error(f"JSONL write error: {e}")

    # ── Intercept (pause/resume) ──────────────────────────────────────────

    def _pause_flow(self, flow, flow_type: str):
        flow_id = str(uuid.uuid4())
        logger.info(f"Intercepting {flow_type} {flow_id}: {flow.request.pretty_url}")

        raw = self._serialise_request(flow) if flow_type == "request" else self._serialise_response(flow)

        meta = {
            "id":          flow_id,
            "mitmflow_id": flow.id,        # mitmproxy's stable flow UUID (used for one-shot marker files)
            "type":        flow_type,
            "method":      flow.request.method,
            "url":         flow.request.pretty_url,
            "host":        flow.request.host,
            "status":      flow.response.status_code if flow.response else None,
            "timestamp":   time.time(),
        }

        entry = {
            "id":   flow_id,
            "type": flow_type,
            "data": base64.b64encode(raw).decode(),
            "meta": meta,
        }

        try:
            with self._lock:
                with open(self.intercept_queue_file, "a", encoding="utf-8") as fq:
                    json.dump(entry, fq)
                    fq.write("\n")
                    fq.flush()
                    os.fsync(fq.fileno())
        except Exception as e:
            logger.error(f"Failed to write intercept queue: {e}")
            return

        flow.intercept()

        def _poll_action():
            action_file = os.path.join(self.intercept_actions_dir, f"{flow_id}.action")
            deadline = time.time() + 300

            while time.time() < deadline:
                if os.path.exists(action_file):
                    try:
                        with open(action_file, "r") as af:
                            action_data = json.load(af)
                        os.remove(action_file)

                        action = action_data.get("action", "forward")

                        # Register one-shot response intercept BEFORE resuming
                        if action_data.get("intercept_response"):
                            # Write file marker directly from addon — guarantees the exact
                            # flow.id used here matches what the response() hook checks.
                            _oneshot_marker = os.path.join(
                                self.intercept_actions_dir,
                                f"oneshot_resp_{flow.id}"
                            )
                            try:
                                with open(_oneshot_marker, "w") as _mf:
                                    _mf.write(flow.id)
                            except Exception as _me:
                                logger.warning(f"Could not write one-shot marker: {_me}")
                            with self._one_shot_lock:
                                self._one_shot_response_intercepts.add(flow.id)
                            logger.info(f"One-shot response intercept queued for {flow.id}")

                        if action == "drop":
                            if flow_type == "request":
                                flow.response = http.Response.make(
                                    403,
                                    b"Request dropped by Hunt Proxy Tool",
                                    {"Content-Type": "text/plain"}
                                )
                                flow.hunt_dropped = True
                                flow.resume()
                            else:
                                flow.kill()
                            return

                        edited_b64 = action_data.get("edited_data")
                        if edited_b64:
                            edited_raw = base64.b64decode(edited_b64)
                            if flow_type == "request":
                                self._apply_edited_request(flow, edited_raw)
                                self._re_save_request(flow)
                            else:
                                self._apply_edited_response(flow, edited_raw)

                        if flow_type == "request" and flow.response:
                            flow.response = None

                        flow.resume()
                        return

                    except Exception as e:
                        logger.error(f"Error processing action file: {e}", exc_info=True)
                        flow.resume()
                        return

                time.sleep(0.2)

            logger.warning(f"Intercept timeout for {flow_id}, resuming")
            flow.resume()

        self._intercept_pool.submit(_poll_action)

    # ── Serialisation ─────────────────────────────────────────────────────

    def _fix_cookie_line(self, line: str) -> str:
        """Restore semicolons in Cookie header if commas were mistakenly introduced."""
        if not line.lower().startswith("cookie:"):
            return line
        parts = line.split(": ", 1)
        if len(parts) != 2:
            return line
        key, value = parts
        # Replace ", " with "; " and any remaining commas with ";"
        new_value = value.replace(", ", "; ").replace(",", ";")
        return f"{key}: {new_value}"

    def _serialise_request(self, flow) -> bytes:
        out = bytearray()
        # Normalize to HTTP/1.1 for display
        ver = "HTTP/1.1"
        out += f"{flow.request.method} {flow.request.path} {ver}\r\n".encode()

        port = flow.request.port
        port_s = f":{port}" if port not in (80, 443) else ""
        out += f"Host: {flow.request.host}{port_s}\r\n".encode()

        for k, v in flow.request.headers.items():
            if k.lower() != "host":
                header_line = f"{k}: {v}"
                header_line = self._fix_cookie_line(header_line)   # <-- FIX
                out += f"{header_line}\r\n".encode()

        out += b"\r\n"
        if flow.request.content:
            out += flow.request.content
        return bytes(out)

    def _serialise_response(self, flow) -> bytes:
        if not flow.response:
            return b""
        out = bytearray()
        # Normalize to HTTP/1.1 for display
        ver = "HTTP/1.1"
        reason = flow.response.reason or ""
        out += f"{ver} {flow.response.status_code} {reason}\r\n".encode()
        for k, v in flow.response.headers.items():
            out += f"{k}: {v}\r\n".encode()
        out += b"\r\n"
        if flow.response.content:
            out += flow.response.content
        return bytes(out)

    # ── Edit application ──────────────────────────────────────────────────

    def _apply_edited_request(self, flow, raw: bytes):
        try:
            if b"\r\n\r\n" in raw:
                sep = raw.find(b"\r\n\r\n")
                eol = b"\r\n"
                body_offset = 4
            else:
                sep = raw.find(b"\n\n")
                eol = b"\n"
                body_offset = 2

            if sep == -1:
                return

            headers_raw = raw[:sep].decode("utf-8", errors="replace")
            body = raw[sep + body_offset:]
            lines = headers_raw.split(eol.decode("utf-8"))

            if not lines:
                return

            request_line = lines[0].strip()
            parts = request_line.split(" ", 2)
            if len(parts) >= 2:
                flow.request.method = parts[0]
                flow.request.path = parts[1]
                if len(parts) == 3:
                    flow.request.http_version = parts[2]

            flow.request.headers.clear()

            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key.lower() == "content-length":
                        continue
                    flow.request.headers[key] = value

            if body:
                flow.request.content = body
                flow.request.headers["content-length"] = str(len(body))
            else:
                flow.request.content = b""

            if "host" not in flow.request.headers and flow.request.host:
                flow.request.headers["host"] = flow.request.host
                if flow.request.port not in (80, 443):
                    flow.request.headers["host"] += f":{flow.request.port}"

        except Exception as e:
            logger.error(f"Error applying edited request: {e}", exc_info=True)

    def _apply_edited_response(self, flow, raw: bytes):
        try:
            if not flow.response:
                return

            if b"\r\n\r\n" in raw:
                sep = raw.find(b"\r\n\r\n")
                eol = b"\r\n"
                body_offset = 4
            else:
                sep = raw.find(b"\n\n")
                eol = b"\n"
                body_offset = 2

            if sep == -1:
                return

            headers_raw = raw[:sep].decode("utf-8", errors="replace")
            body = raw[sep + body_offset:]
            lines = headers_raw.split(eol.decode("utf-8"))

            if not lines:
                return

            status_line = lines[0].strip()
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                flow.response.http_version = parts[0]
                try:
                    flow.response.status_code = int(parts[1])
                except ValueError:
                    pass
                if len(parts) == 3:
                    flow.response.reason = parts[2]

            flow.response.headers.clear()

            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key.lower() == "content-length":
                        continue
                    flow.response.headers[key] = value

            if body:
                flow.response.content = body
                flow.response.headers["content-length"] = str(len(body))
            else:
                flow.response.content = b""

        except Exception as e:
            logger.error(f"Error applying edited response: {e}", exc_info=True)

    # ── Cleanup ────────────────────────────────────────────────────────────

    def _cleanup_old_queue_entries(self):
        try:
            if not os.path.exists(self.intercept_queue_file):
                return
            current_time = time.time()
            one_day_ago = current_time - 86400

            with open(self.intercept_queue_file, "r") as f:
                lines = f.readlines()

            recent_lines = []
            for line in lines:
                try:
                    entry = json.loads(line.strip())
                    timestamp = entry.get("meta", {}).get("timestamp", 0)
                    if timestamp > one_day_ago:
                        recent_lines.append(line)
                except Exception:
                    recent_lines.append(line)

            with open(self.intercept_queue_file, "w") as f:
                f.writelines(recent_lines)

        except Exception as e:
            logger.error(f"Failed to cleanup queue: {e}")


# Module-level instance - required by mitmproxy
addons = [
    HuntProxyAddon()
]