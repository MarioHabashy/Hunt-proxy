#!/usr/bin/env python3
"""
intercept_tab.py  –  Burp-style intercept tab for Hunt GUI

Architecture:
  • HuntProxyAddon   – a mitmproxy Addon class that runs INSIDE mitmdump as
                       an inline addon (replaces the old hunt_script.py external file).
                       It writes a shared queue file so the GUI can talk to it,
                       and reads response files the GUI drops for edited flows.

  • InterceptTab     – PyQt5 QWidget shown in the main tab bar.
                       Lets the user pause/resume interception, edit the
                       intercepted request or response, then Forward or Drop it.

Communication between GUI process and mitmdump process:
  ┌──────────────┐   intercept queue JSONL      ┌─────────────────┐
  │  mitmdump    │ ──────────────────────────▶ │   GUI process   │
  │  (HuntProxy  │                              │  InterceptTab   │
  │   Addon)     │ ◀────────────────────────── │                 │
  └──────────────┘   action files              └─────────────────┘

The intercept queue file:  <project_dir>/intercept_queue.jsonl
  Each line: {"id":"<uuid>", "type":"request"|"response", "data": <base64>, "meta": {...}}

Action files (GUI writes, addon polls):
  <project_dir>/intercept_actions/<id>.action
  Content (JSON): {"action": "forward"|"drop", "edited_data": "<base64 or null>"}
"""

import os
import json
import base64
import uuid
import time
import threading
import logging
import urllib.parse
import html as _html_module
from typing import Dict, Optional, List
from inspector_card import (
    _InspectorCard,
    analyze_selection as _analyze_selection_cards,
    reencode_decoded_value,
)

try:
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QTextEdit, QSplitter, QFrame, QComboBox, QGroupBox,
        QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox,
        QTabWidget, QLineEdit, QCheckBox, QShortcut, QMenu, QAction,
        QScrollArea, QApplication, QStackedWidget
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt5.QtGui import QColor, QBrush, QFont, QTextCursor, QTextDocument, QTextCharFormat, QPainter, QPen, QKeySequence
    _PYQT_AVAILABLE = True
except ImportError:
    _PYQT_AVAILABLE = False

logger = logging.getLogger(__name__)

try:
    from constants import (
        COLOR_BACKGROUND, COLOR_DARK_BG, COLOR_CARD_BG, COLOR_ELEVATED_BG,
        COLOR_TEXT, COLOR_TEXT_BRIGHT, COLOR_TEXT_MUTED,
        COLOR_BORDER, COLOR_ACCENT, COLOR_SUCCESS, COLOR_CRITICAL, HttpSyntaxHighlighter,
        COLOR_HIGH, COLOR_MEDIUM, COLOR_LOW, COLOR_HOVER,
        FONT_FAMILY, FONT_FAMILY_MONO, FONT_SIZE_NORMAL, FONT_SIZE_SMALL,
        GQLSyntaxHighlighter, JSONSyntaxHighlighter,
    )
except ImportError:
    COLOR_BACKGROUND = "#1e1e2e"; COLOR_DARK_BG = "#181825"
    COLOR_CARD_BG = "#24273a"; COLOR_ELEVATED_BG = "#2a2d3e"
    COLOR_TEXT = "#cdd6f4"; COLOR_TEXT_BRIGHT = "#ffffff"
    COLOR_TEXT_MUTED = "#6c7086"; COLOR_BORDER = "#45475a"
    COLOR_ACCENT = "#89b4fa"; COLOR_SUCCESS = "#a6e3a1"
    COLOR_CRITICAL = "#f38ba8"; COLOR_HIGH = "#fe640b"
    COLOR_MEDIUM = "#fab387"; COLOR_LOW = "#89dceb"; COLOR_HOVER = "#313244"
    FONT_FAMILY = "Segoe UI, Arial, sans-serif"
    FONT_FAMILY_MONO = "Consolas, Courier New, monospace"
    FONT_SIZE_NORMAL = "12px"; FONT_SIZE_SMALL = "11px"


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

INTERCEPT_QUEUE_FILE = None   # set at runtime: <project_dir>/intercept_queue.jsonl
INTERCEPT_ACTIONS_DIR = None  # set at runtime: <project_dir>/intercept_actions/
INTERCEPT_ENABLED_FILE = None # set at runtime: <project_dir>/intercept_enabled

MAX_PENDING = 1               # Only hold 1 flow at a time (Burp default)


# ─────────────────────────────────────────────────────────────────────────────
# mitmproxy Addon (runs inside mitmdump)
# ─────────────────────────────────────────────────────────────────────────────

class HuntProxyAddon:
    """
    Unified mitmproxy addon that handles:
      1. Capturing all HTTP traffic → JSONL + request/response files
      2. Optional intercept (pause flow, wait for GUI action)
      3. Scope filtering
    
    This class is imported by mitmdump via -s flag as a module-level instance.
    All paths are read from environment variables at startup (set by GUI).
    """

    def __init__(self):
        self.request_count = 0
        self._lock = threading.Lock()
        self._one_shot_lock = threading.Lock()
        # mitmproxy flow IDs whose *response* must be intercepted (one-shot)
        self._one_shot_response_intercepts: set = set()

        # Paths (populated in configure())
        self.out_jsonl = ""
        self.requests_dir = ""
        self.responses_dir = ""
        self.intercept_queue_file = ""
        self.intercept_actions_dir = ""
        self.intercept_enabled_file = ""
        self.intercept_responses_file = ""

        # Scope
        self.scope_hosts: List[str] = []

        # Pending intercept flows: tracked by background threads now

    # ── mitmproxy lifecycle ────────────────────────────────────────────────

    def configure(self, updated):
        import os, json, logging
        logging.basicConfig(level=logging.INFO)
        self._log = logging.getLogger("HuntProxyAddon")

        self.out_jsonl           = os.environ.get("HUNT_MODE_JSONL",          "/tmp/hunt.jsonl")
        self.requests_dir        = os.environ.get("HUNT_MODE_REQUESTS_DIR",   "/tmp/requests")
        self.responses_dir       = os.environ.get("HUNT_MODE_RESPONSES_DIR",  "/tmp/responses")
        self.intercept_queue_file = os.environ.get("HUNT_INTERCEPT_QUEUE",    "/tmp/intercept_queue.jsonl")
        self.intercept_actions_dir = os.environ.get("HUNT_INTERCEPT_ACTIONS", "/tmp/intercept_actions")
        self.intercept_enabled_file = os.environ.get("HUNT_INTERCEPT_ENABLED","/tmp/intercept_enabled")
        # Responses intercept file lives beside the intercept_enabled file
        _intercept_dir = os.path.dirname(self.intercept_enabled_file) or "/tmp"
        self.intercept_responses_file = os.path.join(_intercept_dir, "intercept_responses")

        scope_json = os.environ.get("HUNT_SCOPE_HOSTS", "[]")
        try:
            self.scope_hosts = json.loads(scope_json)
        except Exception:
            self.scope_hosts = []

        os.makedirs(self.requests_dir,       exist_ok=True)
        os.makedirs(self.responses_dir,      exist_ok=True)
        os.makedirs(self.intercept_actions_dir, exist_ok=True)

        self._log.info("HuntProxyAddon configured")
        self._log.info(f"  JSONL:    {self.out_jsonl}")
        self._log.info(f"  Scope:    {self.scope_hosts or 'ALL'}")
        self._log.info(f"  Intercept queue: {self.intercept_queue_file}")

    # ── Scope check ────────────────────────────────────────────────────────

    def _in_scope(self, host: str) -> bool:
        if not self.scope_hosts:
            return True
        host_lower = host.lower()
        return any(host_lower == s.lower() or host_lower.endswith("." + s.lower())
                   for s in self.scope_hosts)

    # ── Intercept check ────────────────────────────────────────────────────

    def _intercept_enabled(self) -> bool:
        return os.path.exists(self.intercept_enabled_file)

    def _response_intercept_enabled(self) -> bool:
        return os.path.exists(self.intercept_responses_file)

    # ── Request hook ──────────────────────────────────────────────────────

    def request(self, flow):
        """Called when request is ready (before sending upstream)."""
        if not self._in_scope(flow.request.host):
            return

        if self._intercept_enabled():
            self._intercept_flow(flow, flow_type="request")
            # Note: flow is paused here; _capture_flow will be called in response()
            # after the flow is resumed and the response arrives.

    # ── Response hook ─────────────────────────────────────────────────────

    def response(self, flow):
        """Called when response is received."""
        if not self._in_scope(flow.request.host):
            return

        # One-shot response intercept ("Intercept response for this request")
        one_shot = False
        with self._one_shot_lock:
            if flow.id in self._one_shot_response_intercepts:
                self._one_shot_response_intercepts.discard(flow.id)
                one_shot = True

        # Intercept response only when:
        #   - one-shot (user explicitly requested it), regardless of global toggles, OR
        #   - intercept is ON  AND  response-intercept is ON
        # When intercept is OFF nothing is intercepted, even if responses switch is ON.
        if one_shot or (self._intercept_enabled() and self._response_intercept_enabled()):
            self._intercept_flow(flow, flow_type="response")

        # Always capture
        self._capture_flow(flow)

    # ── Intercept logic ───────────────────────────────────────────────────

    def _intercept_flow(self, flow, flow_type: str):
        """
        Pause flow using mitmproxy's native flow.intercept() mechanism.
        A background daemon thread polls for the GUI action file so the
        mitmproxy event loop is NEVER blocked.
        """
        import base64 as b64

        flow_id = str(uuid.uuid4())

        # Serialise the intercepted message
        if flow_type == "request":
            raw = self._serialise_request(flow)
        else:
            raw = self._serialise_response(flow)

        meta = {
            "id": flow_id,
            "type": flow_type,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.host,
            "status": flow.response.status_code if flow.response else None,
            "timestamp": time.time(),
        }

        entry = {
            "id": flow_id,
            "type": flow_type,
            "data": b64.b64encode(raw).decode(),
            "meta": meta,
        }

        # Write to intercept queue so GUI picks it up
        try:
            with open(self.intercept_queue_file, "a", encoding="utf-8") as fq:
                json.dump(entry, fq)
                fq.write("\n")
        except Exception as e:
            self._log.error(f"Failed to write intercept queue: {e}")
            return

        # Pause the flow via mitmproxy — does not block the event loop
        flow.intercept()

        # Poll for action file in a separate daemon thread, then resume
        def _poll_action():
            action_file = os.path.join(self.intercept_actions_dir, f"{flow_id}.action")
            deadline = time.time() + 300  # 5 min timeout
            
            logger.info(f"Polling for action file: {action_file}")
            
            while time.time() < deadline:
                if os.path.exists(action_file):
                    try:
                        logger.info(f"Found action file for {flow_id}")
                        
                        with open(action_file, 'r') as af:
                            action_data = json.load(af)
                        
                        # Remove action file immediately
                        os.remove(action_file)
                        
                        action = action_data.get("action", "forward")
                        logger.info(f"Action for {flow_id}: {action}")

                        # Register one-shot response intercept before resuming
                        if action_data.get("intercept_response"):
                            with self._one_shot_lock:
                                self._one_shot_response_intercepts.add(flow.id)
                            logger.info(f"One-shot response intercept registered for flow {flow_id}")

                        if action == "drop":
                            logger.info(f"Dropping flow {flow_id}")
                            flow.kill()
                            return
                        
                        # Apply edits if present
                        edited_b64 = action_data.get("edited_data")
                        if edited_b64:
                            logger.info(f"Applying edited {flow_type} for {flow_id}")
                            edited_raw = base64.b64decode(edited_b64)
                            
                            if flow_type == "request":
                                self._apply_edited_request(flow, edited_raw)
                            else:
                                self._apply_edited_response(flow, edited_raw)
                        
                        # CRITICAL FIX: Resume with proper state
                        if flow.killed:
                            logger.info(f"Flow already killed, cannot resume")
                            return
                        
                        # For requests, ensure we're not in an inconsistent state
                        if flow_type == "request" and flow.response:
                            # If we already have a response, clear it to force re-request
                            flow.response = None
                        
                        # Resume the flow
                        logger.info(f"Resuming flow {flow_id}")
                        flow.resume()
                        
                        # Give mitmproxy time to process
                        time.sleep(0.1)
                        
                        return
                        
                    except Exception as e:
                        logger.error(f"Error processing action file: {e}", exc_info=True)
                        # Try to resume even on error
                        try:
                            flow.resume()
                        except:
                            pass
                        return
                
                time.sleep(0.2)
            
            # Timeout - resume flow
            logger.warning(f"Intercept timeout for {flow_id}, resuming")
            try:
                flow.resume()
            except:
                pass
        t = threading.Thread(target=_poll_action, daemon=True, name=f"intercept-{flow_id[:8]}")
        t.start()

    def _apply_action(self, flow, flow_type: str, action_data: dict):
        """Apply forward/edit action to a paused flow (drop is handled by caller)."""
        import base64 as b64

        edited_b64 = action_data.get("edited_data")
        if not edited_b64:
            return  # forward as-is, no edits

        edited_raw = b64.b64decode(edited_b64)

        if flow_type == "request":
            self._apply_edited_request(flow, edited_raw)
        else:
            self._apply_edited_response(flow, edited_raw)

    def _apply_edited_request(self, flow, raw: bytes):
        """Apply edited request with proper HTTP parsing"""
        try:
            # Find the header-body boundary
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                logger.error("No header-body separator found in edited request")
                return
                
            # Split headers and body
            headers_raw = raw[:sep].decode("utf-8", errors="replace")
            body = raw[sep + 4:]
            
            # Split into request line and headers
            lines = headers_raw.split("\r\n")
            if not lines:
                logger.error("No lines in edited request headers")
                return
                
            # Parse request line
            request_line = lines[0].strip()
            parts = request_line.split(" ", 2)
            if len(parts) >= 2:
                flow.request.method = parts[0]
                flow.request.path = parts[1]
                if len(parts) == 3:
                    flow.request.http_version = parts[2].replace("HTTP/2", "HTTP/2.0")
            
            # Parse and apply headers
            new_headers = {}
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key.lower() not in ['host', 'content-length']:  # Handle these separately
                        new_headers[key] = value
            
            # Update flow headers
            for key, value in new_headers.items():
                flow.request.headers[key] = value
            
            # Update content and content-length
            if body:
                flow.request.content = body
                flow.request.headers["content-length"] = str(len(body))
            else:
                flow.request.content = b""
                if "content-length" in flow.request.headers:
                    del flow.request.headers["content-length"]
            
            logger.info(f"Applied edited request: {flow.request.method} {flow.request.path}")
            
        except Exception as e:
            logger.error(f"apply_edited_request error: {e}", exc_info=True)

    def _apply_edited_response(self, flow, raw: bytes):
        """Apply edited response with proper HTTP parsing"""
        try:
            if not flow.response:
                logger.error("No response to edit")
                return
                
            # Find the header-body boundary
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                logger.error("No header-body separator found in edited response")
                return
                
            # Split headers and body
            headers_raw = raw[:sep].decode("utf-8", errors="replace")
            body = raw[sep + 4:]
            
            # Split into status line and headers
            lines = headers_raw.split("\r\n")
            if not lines:
                logger.error("No lines in edited response headers")
                return
                
            # Parse status line
            status_line = lines[0].strip()
            parts = status_line.split(" ", 2)
            if len(parts) >= 2:
                flow.response.http_version = parts[0].replace("HTTP/2", "HTTP/2.0")
                try:
                    flow.response.status_code = int(parts[1])
                except ValueError:
                    logger.error(f"Invalid status code: {parts[1]}")
                if len(parts) == 3:
                    flow.response.reason = parts[2]
            
            # Parse and apply headers
            new_headers = {}
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    continue
                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()
                    if key.lower() != 'content-length':  # Handle separately
                        new_headers[key] = value
            
            # Update flow headers
            for key, value in new_headers.items():
                flow.response.headers[key] = value
            
            # Update content and content-length
            if body:
                flow.response.content = body
                flow.response.headers["content-length"] = str(len(body))
            else:
                flow.response.content = b""
                if "content-length" in flow.response.headers:
                    del flow.response.headers["content-length"]
            
            logger.info(f"Applied edited response: {flow.response.status_code}")
            
        except Exception as e:
            logger.error(f"apply_edited_response error: {e}", exc_info=True)

    def _apply_edited_response(self, flow, raw: bytes):
        """Parse edited raw bytes back into the flow's response."""
        try:
            header_end = raw.find(b"\r\n\r\n")
            if header_end == -1:
                return
            header_section = raw[:header_end].decode("utf-8", errors="replace")
            body = raw[header_end + 4:]
            lines = header_section.split("\r\n")
            if lines:
                parts = lines[0].split(" ", 2)
                if len(parts) >= 2:
                    flow.response.status_code = int(parts[1])
            flow.response.content = body
            if body:
                flow.response.headers["content-length"] = str(len(body))
        except Exception as e:
            self._log.error(f"Failed to apply edited response: {e}")

    # ── Capture ───────────────────────────────────────────────────────────

    def _capture_flow(self, flow):
        import gzip
        with self._lock:
            self.request_count += 1
            req_id = f"{int(time.time())}_{self.request_count}"

        req_file  = self._save_request(flow, req_id)
        resp_file = self._save_response(flow, req_id)

        finding = {
            "url":           flow.request.pretty_url,
            "method":        flow.request.method,
            "host":          flow.request.host,
            "path":          flow.request.path,
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%S"),
            "seq":           self.request_count,
            "request_file":  req_file,
            "response_file": resp_file,
        }
        if flow.response:
            finding["status"]          = flow.response.status_code
            finding["content_type"]    = flow.response.headers.get("content-type", "")
            finding["response_length"] = len(flow.response.content or b"")

        try:
            with open(self.out_jsonl, "a", encoding="utf-8") as f:
                json.dump(finding, f)
                f.write("\n")
        except Exception as e:
            self._log.error(f"JSONL write error: {e}")

        self._log.info(
            f"[{self.request_count}] {flow.request.method} "
            f"{flow.request.pretty_url} → "
            f"{flow.response.status_code if flow.response else '?'}"
        )

    # ── Serialisation helpers ──────────────────────────────────────────────

    def _serialise_request(self, flow) -> bytes:
        out = bytearray()
        ver = flow.request.http_version.replace("HTTP/2.0", "HTTP/2")
        out += f"{flow.request.method} {flow.request.path} {ver}\r\n".encode()
        if flow.request.host:
            port_s = f":{flow.request.port}" if flow.request.port not in (80, 443) else ""
            out += f"Host: {flow.request.host}{port_s}\r\n".encode()
        for k, v in flow.request.headers.items():
            if k.lower() != "host":
                out += f"{k}: {v}\r\n".encode()
        out += b"\r\n"
        if flow.request.content:
            out += flow.request.content
        return bytes(out)

    def _serialise_response(self, flow) -> bytes:
        if not flow.response:
            return b""
        out = bytearray()
        ver = flow.response.http_version.replace("HTTP/2.0", "HTTP/2")
        reason = flow.response.reason or ""
        out += f"{ver} {flow.response.status_code} {reason}\r\n".encode()
        for k, v in flow.response.headers.items():
            out += f"{k}: {v}\r\n".encode()
        out += b"\r\n"
        if flow.response.content:
            import gzip
            content = flow.response.content
            enc = flow.response.headers.get("content-encoding", "").lower()
            if "gzip" in enc:
                try:
                    content = gzip.decompress(content)
                except Exception:
                    pass
            out += content
        return bytes(out)

    def _save_request(self, flow, req_id: str) -> str:
        try:
            path = os.path.join(self.requests_dir, f"{req_id}.txt")
            with open(path, "wb") as f:
                f.write(self._serialise_request(flow))
            return path
        except Exception as e:
            self._log.error(f"save_request error: {e}")
            return ""

    def _save_response(self, flow, req_id: str) -> str:
        if not flow.response:
            return ""
        try:
            path = os.path.join(self.responses_dir, f"{req_id}.txt")
            with open(path, "wb") as f:
                f.write(self._serialise_response(flow))
            return path
        except Exception as e:
            self._log.error(f"save_response error: {e}")
            return ""


# Module-level instance so mitmdump picks it up automatically when loaded via -s flag.
# When the GUI imports this module, PyQt5 IS available so _PYQT_AVAILABLE=True,
# but the addon instance is harmless (it's just a plain Python object, no threads started
# until mitmproxy calls configure() on it).
addon = HuntProxyAddon()


def _url_safe_chars_from_original(original: str) -> str:
    """Return characters that appeared LITERALLY (not as %XX sequences) in
    the original URL-encoded string — these should stay unencoded on re-encode."""
    safe = set()
    i = 0
    while i < len(original):
        if original[i] == '%' and i + 2 < len(original) and \
                original[i+1] in '0123456789ABCDEFabcdef' and \
                original[i+2] in '0123456789ABCDEFabcdef':
            i += 3
        else:
            c = original[i]
            if c != '%':
                safe.add(c)
            i += 1
    return ''.join(sorted(safe))


# ─────────────────────────────────────────────────────────────────────────────
# GUI – InterceptQueueReader (QThread)
# ─────────────────────────────────────────────────────────────────────────────

class InterceptQueueReader(QThread):
    """
    Monitors the intercept_queue.jsonl file and emits new_flow signal
    whenever a new intercepted flow appears.
    """
    new_flow = pyqtSignal(dict)  # emits the parsed JSON entry

    def __init__(self, queue_file: str, parent=None):
        super().__init__(parent)
        self._queue_file = queue_file
        self._running = True
        self._last_pos = 0
        self._processed_ids = set()  # Track processed flow IDs
        self._state_file = queue_file + ".processed"  # State file for persistence
        
        # Load previously processed IDs from state file
        self._load_processed_ids()

    def _load_processed_ids(self):
        """Load processed flow IDs from state file"""
        try:
            if os.path.exists(self._state_file):
                with open(self._state_file, 'r') as f:
                    self._processed_ids = set(json.load(f))
                logger.info(f"Loaded {len(self._processed_ids)} processed flow IDs")
        except Exception as e:
            logger.error(f"Failed to load processed IDs: {e}")
            self._processed_ids = set()

    def _save_processed_ids(self):
        """Save processed flow IDs to state file"""
        try:
            with open(self._state_file, 'w') as f:
                json.dump(list(self._processed_ids), f)
        except Exception as e:
            logger.error(f"Failed to save processed IDs: {e}")

    def run(self):
        while self._running:
            try:
                if os.path.exists(self._queue_file):
                    with open(self._queue_file, "r", encoding="utf-8") as f:
                        # If file was truncated/rewritten, reset position
                        if self._last_pos > os.path.getsize(self._queue_file):
                            self._last_pos = 0

                        f.seek(self._last_pos)
                        new_entries = False

                        while True:
                            # Record position BEFORE reading so we can rewind on
                            # a partial write (writer didn't finish the line yet).
                            line_start = f.tell()
                            line = f.readline()

                            if not line:
                                # Genuine EOF — nothing more to read this cycle.
                                break

                            stripped = line.strip()
                            if not stripped:
                                # Blank / whitespace-only line — advance past it.
                                self._last_pos = f.tell()
                                continue

                            try:
                                entry = json.loads(stripped)
                                flow_id = entry.get("id")
                                if flow_id and flow_id not in self._processed_ids:
                                    self.new_flow.emit(entry)
                                    self._processed_ids.add(flow_id)
                                    new_entries = True
                                # Advance _last_pos only after a successful parse.
                                self._last_pos = f.tell()
                            except Exception:
                                # The line is malformed — most likely a partial write
                                # still in progress. Rewind to line_start so the
                                # next cycle re-reads the full (completed) line.
                                self._last_pos = line_start
                                break

                        if new_entries:
                            self._save_processed_ids()

            except Exception as e:
                logger.error(f"InterceptQueueReader error: {e}")
            time.sleep(0.3)

    def stop(self):
        self._running = False
        self._save_processed_ids()  # Save on stop
        self.wait(1000)


# ─────────────────────────────────────────────────────────────────────────────
# Custom Widgets
# ─────────────────────────────────────────────────────────────────────────────

class ToggleSwitch(QCheckBox):
    def __init__(self, width=44, height=24, parent=None):
        super().__init__(parent)
        self.setFixedSize(width, height)
        self.setCursor(Qt.PointingHandCursor)

    def hitButton(self, pos):
        return self.contentsRect().contains(pos)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        
        rect = self.contentsRect()
        height = rect.height()
        
        if self.isChecked():
            p.setBrush(QColor(COLOR_SUCCESS))
        else:
            p.setBrush(QColor("#4c4c4c"))
        p.setPen(Qt.NoPen)
        
        radius = height / 2
        p.drawRoundedRect(0, 0, rect.width(), height, radius, radius)
        
        p.setBrush(QColor("#ffffff"))
        
        knob_size = height - 6
        if self.isChecked():
            x = rect.width() - knob_size - 3
        else:
            x = 3
            
        p.drawEllipse(x, 3, knob_size, knob_size)


# ─────────────────────────────────────────────────────────────────────────────
# GUI – InterceptTab widget
# ─────────────────────────────────────────────────────────────────────────────

class InterceptTab(QWidget):
    """
    Burp-like Intercept tab.
    Shows intercepted flows one at a time; user can edit then Forward or Drop.
    """

    popup_requested = pyqtSignal(dict)
    intercept_changed = pyqtSignal(bool)  # True = ON, False = OFF

    def __init__(self, parent=None):
        super().__init__(parent)
        self._project_dir: str = ""
        self._current_flow: Optional[dict] = None
        self._queue_reader: Optional[InterceptQueueReader] = None
        self._pending_flows: List[dict] = []
        self._intercept_enabled = False
        self._build_ui()

    # ── UI ─────────────────────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        # ── Top toolbar ───────────────────────────────────────────────────
        toolbar = QFrame()
        toolbar.setStyleSheet(
            f"QFrame {{ background-color: {COLOR_ELEVATED_BG}; "
            f"border: 1px solid {COLOR_BORDER}; border-radius: 5px; }}"
        )
        tb_layout = QHBoxLayout(toolbar)
        tb_layout.setContentsMargins(10, 6, 10, 6)

        # Toggle button
        self.intercept_toggle_btn = QPushButton("⏸ Intercept: OFF")
        self.intercept_toggle_btn.setCheckable(True)
        self.intercept_toggle_btn.setMinimumWidth(160)
        self.intercept_toggle_btn.clicked.connect(self._toggle_intercept)
        self.intercept_toggle_btn.setStyleSheet(self._toggle_style(False))
        tb_layout.addWidget(self.intercept_toggle_btn)

        tb_layout.addSpacing(10)

        self.popup_lbl = QLabel("Popup: OFF")
        self.popup_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: bold;")
        tb_layout.addWidget(self.popup_lbl)

        self.popup_switch = ToggleSwitch()
        self.popup_switch.clicked.connect(self._toggle_popup)
        tb_layout.addWidget(self.popup_switch)

        tb_layout.addSpacing(10)

        self.resp_int_lbl = QLabel("📥 Responses: OFF")
        self.resp_int_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: bold;")
        tb_layout.addWidget(self.resp_int_lbl)

        self.resp_int_switch = ToggleSwitch()
        self.resp_int_switch.clicked.connect(self._toggle_response_intercept)
        tb_layout.addWidget(self.resp_int_switch)

        tb_layout.addSpacing(10)

        self.ws_int_lbl = QLabel("WS: OFF")
        self.ws_int_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-weight: bold;")
        tb_layout.addWidget(self.ws_int_lbl)

        self.ws_int_switch = ToggleSwitch()
        self.ws_int_switch.clicked.connect(self._toggle_ws_intercept)
        tb_layout.addWidget(self.ws_int_switch)

        tb_layout.addSpacing(20)

        # Forward
        self.forward_btn = QPushButton("▶ Forward")
        self.forward_btn.setEnabled(False)
        self.forward_btn.setToolTip("Forward intercepted request (Ctrl+Enter)")
        self.forward_btn.clicked.connect(self._forward)
        self.forward_btn.setStyleSheet(self._action_btn_style(COLOR_SUCCESS))
        tb_layout.addWidget(self.forward_btn)

        # Drop
        self.drop_btn = QPushButton("✕ Drop")
        self.drop_btn.setEnabled(False)
        self.drop_btn.setToolTip("Drop intercepted request (Ctrl+Delete)")
        self.drop_btn.clicked.connect(self._drop)
        self.drop_btn.setStyleSheet(self._action_btn_style(COLOR_CRITICAL))
        tb_layout.addWidget(self.drop_btn)

        # Forward all
        self.fwd_all_btn = QPushButton("⏭ Forward All")
        self.fwd_all_btn.setEnabled(False)
        self.fwd_all_btn.clicked.connect(self._forward_all)
        self.fwd_all_btn.setStyleSheet(self._action_btn_style(COLOR_ACCENT))
        tb_layout.addWidget(self.fwd_all_btn)

        tb_layout.addStretch()

        # Queue size
        self.queue_lbl = QLabel("Queue: 0")
        self.queue_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL};"
        )
        tb_layout.addWidget(self.queue_lbl)

        # Flow info
        self.flow_info_lbl = QLabel("No flow intercepted")
        self.flow_info_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}; padding: 0 12px;"
        )
        tb_layout.addWidget(self.flow_info_lbl)

        root.addWidget(toolbar)

        # ── Editor splitter ───────────────────────────────────────────────
        splitter = QSplitter(Qt.Horizontal)
        splitter.setStyleSheet(
            f"QSplitter::handle {{ background-color: {COLOR_BORDER}; width: 3px; }}"
        )

        # Left: intercepted content editor
        left = QGroupBox("Intercepted Message (editable)")
        left.setStyleSheet(self._groupbox_style())
        left_layout = QVBoxLayout(left)

        # Header row for Type label + Search
        header_row = QHBoxLayout()
        
        self.editor_type_lbl = QLabel("—")
        self.editor_type_lbl.setStyleSheet(
            f"color: {COLOR_ACCENT}; font-size: {FONT_SIZE_SMALL}; font-weight: 600;"
        )
        header_row.addWidget(self.editor_type_lbl)

        _gql_btn_style = (
            f"QPushButton {{ background-color: transparent; color: {COLOR_ACCENT};"
            f" border: 1px solid {COLOR_ACCENT}; border-radius: 3px;"
            f" padding: 1px 7px; font-size: 10px; font-weight: 600; }}"
            f" QPushButton:hover {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
            f" QPushButton:checked {{ background-color: {COLOR_ACCENT}; color: {COLOR_DARK_BG}; }}"
        )
        self._gql_btn = QPushButton("⬡ GraphQL")
        self._gql_btn.setCheckable(True)
        self._gql_btn.setStyleSheet(_gql_btn_style)
        self._gql_btn.setToolTip("Switch to GraphQL pretty-print view")
        self._gql_btn.setVisible(False)
        self._gql_btn.clicked.connect(self._toggle_gql_view)
        header_row.addWidget(self._gql_btn)

        header_row.addStretch()
        
        # Search controls
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search...")
        self.search_input.setFixedWidth(250)
        self.search_input.setFixedHeight(24)
        self.search_input.setStyleSheet(f"background-color: {COLOR_DARK_BG}; color: {COLOR_TEXT_BRIGHT}; border: 1px solid {COLOR_BORDER}; border-radius: 3px; padding: 2px;")
        self.search_input.textChanged.connect(self._highlight_matches)
        self.search_input.returnPressed.connect(self._search_next)
        
        self.search_prev_btn = QPushButton("◀")
        self.search_prev_btn.setFixedSize(24, 24)
        self.search_prev_btn.setStyleSheet(f"background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; border: 1px solid {COLOR_BORDER}; border-radius: 3px;")
        self.search_prev_btn.clicked.connect(self._search_prev)
        
        self.search_next_btn = QPushButton("▶")
        self.search_next_btn.setFixedSize(24, 24)
        self.search_next_btn.setStyleSheet(f"background-color: {COLOR_ELEVATED_BG}; color: {COLOR_TEXT}; border: 1px solid {COLOR_BORDER}; border-radius: 3px;")
        self.search_next_btn.clicked.connect(self._search_next)
        
        self.search_count_lbl = QLabel("")
        self.search_count_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: {FONT_SIZE_SMALL}; margin-left: 5px;")
        
        header_row.addWidget(self.search_input)
        header_row.addWidget(self.search_prev_btn)
        header_row.addWidget(self.search_next_btn)
        header_row.addWidget(self.search_count_lbl)
        
        left_layout.addLayout(header_row)

        self.editor = QTextEdit()
        self.editor.setStyleSheet(
            f"""
            QTextEdit {{
                background-color: {COLOR_DARK_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                border-radius: 4px;
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                padding: 6px;
            }}
            """
        )
        self.editor.setReadOnly(True)
        self.highlighter = HttpSyntaxHighlighter(self.editor.document())
        
        # Context menu & Shortcuts
        self.editor.setContextMenuPolicy(Qt.CustomContextMenu)
        self.editor.customContextMenuRequested.connect(self._show_context_menu)

        self.shortcut_repeater = QShortcut(QKeySequence("Ctrl+R"), self, context=Qt.WidgetWithChildrenShortcut)
        self.shortcut_repeater.activated.connect(self._send_to_repeater)
        
        self.shortcut_intruder = QShortcut(QKeySequence("Ctrl+I"), self, context=Qt.WidgetWithChildrenShortcut)
        self.shortcut_intruder.activated.connect(self._send_to_intruder)
        
        self.shortcut_scanner = QShortcut(QKeySequence("Ctrl+S"), self, context=Qt.WidgetWithChildrenShortcut)
        self.shortcut_scanner.activated.connect(self._send_to_scanner)

        self.shortcut_forward = QShortcut(QKeySequence("Ctrl+Return"), self, context=Qt.WidgetWithChildrenShortcut)
        self.shortcut_forward.activated.connect(self._forward)

        self.shortcut_drop = QShortcut(QKeySequence("Ctrl+Delete"), self, context=Qt.WidgetWithChildrenShortcut)
        self.shortcut_drop.activated.connect(self._drop)

        self.shortcut_ai_toggle = QShortcut(QKeySequence("Ctrl+Shift+C"), self)
        self.shortcut_ai_toggle.activated.connect(self._ai_toggle_panel)

        _gql_spl_style = (
            f"QSplitter::handle:vertical {{ background-color: {COLOR_BORDER}; min-height: 4px; }}"
            f" QSplitter::handle:vertical:hover {{ background-color: {COLOR_ACCENT}; }}"
        )
        self._gql_req_splitter = QSplitter(Qt.Vertical)
        self._gql_req_splitter.setHandleWidth(5)
        self._gql_req_splitter.setChildrenCollapsible(False)
        self._gql_req_splitter.setStyleSheet(_gql_spl_style)
        (self._gql_query_panel,
         self._gql_query_text)   = self._make_gql_panel("⬡  QUERY",          COLOR_TEXT_BRIGHT, read_only=False, highlight="gql")
        (self._gql_vars_panel,
         self._gql_vars_text)    = self._make_gql_panel("⬡  VARIABLES",      COLOR_ACCENT,      read_only=False, highlight="json")
        (self._gql_opname_panel,
         self._gql_opname_text)  = self._make_gql_panel("⬡  OPERATION NAME", COLOR_TEXT_MUTED,  read_only=False)
        self._gql_req_splitter.addWidget(self._gql_query_panel)
        self._gql_req_splitter.addWidget(self._gql_vars_panel)
        self._gql_req_splitter.addWidget(self._gql_opname_panel)
        self._gql_resp_splitter = QSplitter(Qt.Vertical)
        self._gql_resp_splitter.setHandleWidth(5)
        self._gql_resp_splitter.setChildrenCollapsible(False)
        self._gql_resp_splitter.setStyleSheet(_gql_spl_style)
        (self._gql_errors_panel,
         self._gql_errors_text)  = self._make_gql_panel("⬡  ERRORS",     "#e05c5c")
        (self._gql_data_panel,
         self._gql_data_text)    = self._make_gql_panel("⬡  DATA",       COLOR_SUCCESS,   highlight="json")
        (self._gql_exts_panel,
         self._gql_exts_text)    = self._make_gql_panel("⬡  EXTENSIONS", COLOR_TEXT_MUTED, highlight="json")
        self._gql_resp_splitter.addWidget(self._gql_errors_panel)
        self._gql_resp_splitter.addWidget(self._gql_data_panel)
        self._gql_resp_splitter.addWidget(self._gql_exts_panel)
        self._gql_view_stack = QStackedWidget()
        self._gql_view_stack.addWidget(self._gql_req_splitter)
        self._gql_view_stack.addWidget(self._gql_resp_splitter)
        self._gql_main_stack = QStackedWidget()
        self._gql_main_stack.addWidget(self.editor)
        self._gql_main_stack.addWidget(self._gql_view_stack)
        self._gql_state     = {}
        self._gql_mode      = False
        self._gql_flow_type = "request"
        left_layout.addWidget(self._gql_main_stack)

        splitter.addWidget(left)

        # Right: queued flows
        right = QGroupBox("Pending Queue")
        right.setStyleSheet(self._groupbox_style())
        right_layout = QVBoxLayout(right)

        self.queue_table = QTableWidget(0, 4)
        self.queue_table.setHorizontalHeaderLabels(["#", "Type", "Method", "URL"])
        self.queue_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.queue_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.queue_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.queue_table.setAlternatingRowColors(True)
        self.queue_table.itemSelectionChanged.connect(self._on_queue_selection_changed)
        self.queue_table.setStyleSheet(
            f"""
            QTableWidget {{
                background-color: {COLOR_DARK_BG};
                alternate-background-color: {COLOR_CARD_BG};
                color: {COLOR_TEXT};
                border: 1px solid {COLOR_BORDER};
                font-family: {FONT_FAMILY_MONO};
                font-size: {FONT_SIZE_SMALL};
                outline: none;
            }}
            QTableWidget::item:selected {{ background-color: {COLOR_ACCENT}; color: #000; }}
            QHeaderView::section {{
                background-color: {COLOR_ELEVATED_BG};
                color: {COLOR_TEXT_BRIGHT};
                border: 1px solid {COLOR_BORDER};
                padding: 5px 8px;
                font-weight: 600;
            }}
            """
        )

        # ── Vertical splitter inside the right panel ───────────────────────
        right_vsplit = QSplitter(Qt.Vertical)
        right_vsplit.setStyleSheet(
            f"QSplitter::handle {{ background-color: {COLOR_BORDER}; height: 3px; }}"
        )
        right_vsplit.addWidget(self.queue_table)

        # ── Selection Inspector (lower half of pending queue) ──────────────
        self._sel_inspector_widget = self._build_selection_inspector()
        right_vsplit.addWidget(self._sel_inspector_widget)
        right_vsplit.setSizes([200, 220])

        right_layout.addWidget(right_vsplit)

        splitter.addWidget(right)
        splitter.setSizes([700, 300])

        # ── AI chat outer splitter (panel is reparented here on demand) ─────────────
        self._ai_outer_splitter = QSplitter(Qt.Horizontal)
        self._ai_outer_splitter.setHandleWidth(1)
        self._ai_outer_splitter.setChildrenCollapsible(True)
        self._ai_outer_splitter.addWidget(splitter)
        root.addWidget(self._ai_outer_splitter, stretch=1)

        # Connect selection changed AFTER editor is created
        self.editor.selectionChanged.connect(self._on_intercept_selection_changed)
        self._sel_debounce_timer = QTimer(self)
        self._sel_debounce_timer.setSingleShot(True)
        self._sel_debounce_timer.setInterval(110)
        self._sel_debounce_timer.timeout.connect(self._process_intercept_selection)
        self._sel_pending_text = ""
        self._sel_last_analysis = None  # (text, cards, enc, dec)

    # ── Intercept toggle ───────────────────────────────────────────────────

    def _toggle_intercept(self, checked: bool):
        self._intercept_enabled = checked
        self.intercept_toggle_btn.setText(
            "⏸ Intercept: ON" if checked else "⏸ Intercept: OFF"
        )
        self.intercept_toggle_btn.setStyleSheet(self._toggle_style(checked))
        self.intercept_changed.emit(checked)

        if self._project_dir:
            enabled_file = os.path.join(self._project_dir, "intercept_enabled")
            if checked:
                open(enabled_file, "w").close()
            else:
                try:
                    os.remove(enabled_file)
                except FileNotFoundError:
                    pass
                # Auto-forward any flows still waiting in the queue
                if self._pending_flows:
                    self._forward_all()

    def _toggle_popup(self, checked: bool):
        self.popup_lbl.setText(
            " Popup: ON" if checked else " Popup: OFF"
        )
        self.popup_lbl.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT if checked else COLOR_TEXT_MUTED}; font-weight: bold;")

    def _toggle_response_intercept(self):
        checked = self.resp_int_switch.isChecked()
        self.resp_int_lbl.setText(
            "📥 Responses: ON" if checked else "📥 Responses: OFF"
        )
        self.resp_int_lbl.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT if checked else COLOR_TEXT_MUTED}; font-weight: bold;")
        
        if self._project_dir:
            f = os.path.join(self._project_dir, "intercept_responses")
            if checked:
                open(f, "w").close()
            else:
                if os.path.exists(f):
                    os.remove(f)

    def _toggle_ws_intercept(self):
        checked = self.ws_int_switch.isChecked()
        self._update_ws_int_label(checked)
        if self._project_dir:
            f = os.path.join(self._project_dir, "ws_intercept_enabled")
            if checked:
                open(f, "w").close()
            else:
                if os.path.exists(f):
                    os.remove(f)

    def _update_ws_int_label(self, checked: bool):
        self.ws_int_lbl.setText("WS: ON" if checked else "WS: OFF")
        self.ws_int_lbl.setStyleSheet(
            f"color: {COLOR_TEXT_BRIGHT if checked else COLOR_TEXT_MUTED}; font-weight: bold;"
        )

    # ── Queue reader setup ─────────────────────────────────────────────────

    def set_project_dir(self, project_dir: str):
        """Called when a project is loaded/switched."""
        # Stop old reader
        if self._queue_reader:
            self._queue_reader.stop()
            self._queue_reader = None

        self._project_dir = project_dir
        
        # Clean up old action files
        self._cleanup_old_actions()
        
        queue_file = os.path.join(project_dir, "intercept_queue.jsonl")
        
        # Create queue file if it doesn't exist
        if not os.path.exists(queue_file):
            open(queue_file, 'a').close()

        self._queue_reader = InterceptQueueReader(queue_file, self)
        self._queue_reader.new_flow.connect(self._on_new_intercepted_flow)
        self._queue_reader.start()

        # Always reset intercept to OFF on project load — safe default for a fresh session
        enabled_file = os.path.join(project_dir, "intercept_enabled")
        try:
            os.remove(enabled_file)
        except FileNotFoundError:
            pass
        self._intercept_enabled = False
        self.intercept_toggle_btn.setChecked(False)
        self.intercept_toggle_btn.setText("⏸ Intercept: OFF")
        self.intercept_toggle_btn.setStyleSheet(self._toggle_style(False))
        self.intercept_changed.emit(False)

        # Sync response intercept state
        resp_file = os.path.join(project_dir, "intercept_responses")
        resp_enabled = os.path.exists(resp_file)
        self.resp_int_switch.setChecked(resp_enabled)
        self.resp_int_lbl.setText("📥 Responses: ON" if resp_enabled else "📥 Responses: OFF")
        self.resp_int_lbl.setStyleSheet(f"color: {COLOR_TEXT_BRIGHT if resp_enabled else COLOR_TEXT_MUTED}; font-weight: bold;")

        # Sync WS intercept state
        ws_file = os.path.join(project_dir, "ws_intercept_enabled")
        ws_enabled = os.path.exists(ws_file)
        self.ws_int_switch.setChecked(ws_enabled)
        self._update_ws_int_label(ws_enabled)

    # ── Flow handling ──────────────────────────────────────────────────────

    def _on_new_intercepted_flow(self, entry: dict):
        """Incoming intercepted flow from queue reader."""
        MAX_PENDING = 50  # Maximum number of pending flows to keep

        # Check if we've reached the limit
        if len(self._pending_flows) >= MAX_PENDING:
            logger.warning(f"Pending flow queue full ({MAX_PENDING}), dropping oldest flow")
            # Remove oldest flow
            oldest = self._pending_flows.pop(0)
            # Send forward action for dropped flow
            self._send_action(oldest["id"], "forward", None)
            # Remove from table
            self._remove_flow_from_table(oldest["id"])

        flow_type = entry.get("type", "")

        # Responses are inserted at the FRONT of the pending queue so they
        # surface immediately after the current flow is forwarded — instead of
        # being buried behind a backlog of pending requests.
        # This mirrors Burp-style behaviour: Request → Response → Next request.
        if flow_type == "response" and self._pending_flows:
            self._pending_flows.insert(0, entry)
            self._add_queue_row(entry, insert_at=0)
        else:
            self._pending_flows.append(entry)
            self._add_queue_row(entry)

        self._update_queue_label()
        self.fwd_all_btn.setEnabled(True)

        # Auto-show only when the editor is empty.
        if self._current_flow is None:
            self._show_flow(self._pending_flows[0])
            self.queue_table.selectRow(0)

        # Emit popup signal if enabled
        if self.popup_switch.isChecked():
            self.popup_requested.emit(entry)

    def _remove_flow_from_table(self, flow_id: str):
        """Remove a flow from the queue table by ID"""
        for row in range(self.queue_table.rowCount()):
            item = self.queue_table.item(row, 3)
            if item and item.data(Qt.UserRole) == flow_id:
                self.queue_table.removeRow(row)
                break

    def _add_queue_row(self, entry: dict, insert_at: int = -1):
        """Add a row to the queue table.  Pass insert_at=0 to prepend."""
        meta = entry.get("meta", {})
        if insert_at >= 0:
            row = insert_at
        else:
            row = self.queue_table.rowCount()
        self.queue_table.insertRow(row)
        self.queue_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))

        flow_type = entry.get("type", "")
        if flow_type == "ws_message":
            type_item = QTableWidgetItem("WS")
            direction = meta.get("direction", "")
            dir_arrow = "↑" if direction.startswith("client") else "↓"
            opcode = meta.get("opcode", "text")
            method_item = QTableWidgetItem(f"{dir_arrow} {opcode}")
        else:
            type_item = QTableWidgetItem(flow_type)
            method_item = QTableWidgetItem(meta.get("method", ""))

        self.queue_table.setItem(row, 1, type_item)
        self.queue_table.setItem(row, 2, method_item)
        url_item = QTableWidgetItem(meta.get("url", "")[:120])
        url_item.setData(Qt.UserRole, entry.get("id"))
        self.queue_table.setItem(row, 3, url_item)

        # Highlight intercepted responses so they stand out from pending requests
        if flow_type == "response":
            bg = QColor("#1a3a2a")   # dark green tint
            fg = QColor("#a6e3a1")   # green text
            for col in range(4):
                it = self.queue_table.item(row, col)
                if it:
                    it.setBackground(bg)
                    it.setForeground(fg)

    def _on_queue_selection_changed(self):
        row = self.queue_table.currentRow()
        self._on_queue_row_selected(row)

    def _on_queue_row_selected(self, row: int):
        if row < 0 or row >= len(self._pending_flows):
            return
        self._show_flow(self._pending_flows[row])

    def _show_flow(self, entry: dict):
        """Display an intercepted flow in the editor"""
        self._current_flow = entry
        meta = entry.get("meta", {})
        flow_type = entry.get("type", "")

        if flow_type == "ws_message":
            # WebSocket message: show raw payload directly
            raw = base64.b64decode(entry.get("data", ""))
            opcode    = meta.get("opcode", "text")
            direction = meta.get("direction", "")

            if opcode == "text":
                text = raw.decode("utf-8", errors="replace")
            else:
                # Binary: display as hex for easy editing
                text = raw.hex()

            self.editor.setReadOnly(False)
            self.editor.setPlainText(text)

            dir_arrow = "↑" if direction.startswith("client") else "↓"
            host = meta.get("host", "")
            header = (
                f"WS {dir_arrow}  •  {opcode.upper()}  •  "
                f"{host}  [{len(raw)} bytes]"
            )
            self.editor_type_lbl.setText(header)
            self.flow_info_lbl.setText(
                f"WS {dir_arrow} {direction}  •  {meta.get('url', '')[:70]}"
            )
            self.forward_btn.setEnabled(True)
            self.drop_btn.setEnabled(True)
            logger.debug(f"Displayed WS flow {entry.get('id')} ({direction})")
            return

        # ── HTTP request / response ───────────────────────────────────────
        # Decode the base64 data
        raw = base64.b64decode(entry.get("data", ""))
        
        # Try to decode as text, preserving structure
        try:
            # First try UTF-8
            text = raw.decode('utf-8', errors='replace')
        except Exception:
            # Fallback to repr for binary data
            text = repr(raw)
        
        # Ensure proper line endings for display
        text = text.replace('\r\n', '\n')
        
        # Set editor content
        self.editor.setReadOnly(False)
        self.editor.setPlainText(text)
        
        # Create detailed header
        if flow_type == "request":
            header = f"🔴 REQUEST  •  {meta.get('method', '')} {meta.get('url', '')[:100]}"
        else:
            status = meta.get('status', '')
            header = f"🟢 RESPONSE •  HTTP {status}  •  {meta.get('url', '')[:80]}"
        
        self.editor_type_lbl.setText(header)
        
        # Update flow info label
        self.flow_info_lbl.setText(
            f"{meta.get('method', '')} {meta.get('url', '')[:60]}  "
            f"[{meta.get('status', '') or '—'}]"
        )
        
        # Enable buttons
        self.forward_btn.setEnabled(True)
        self.drop_btn.setEnabled(True)
        
        logger.debug(f"Displayed flow {entry.get('id')} ({flow_type})")
        # GraphQL detection
        self._update_gql_state(meta.get("url", ""), text, flow_type)

    def _forward(self):
        if self._current_flow is None:
            return

        # If in GQL edit mode for a request, sync panel edits back to editor first
        if self._gql_mode and self._gql_flow_type != "response":
            self._sync_gql_to_raw()

        flow_type = self._current_flow.get("type", "")
        if flow_type == "ws_message":
            # Encode editor content as the new WS payload
            text = self.editor.toPlainText()
            opcode = self._current_flow.get("meta", {}).get("opcode", "text")
            if opcode == "binary":
                # Editor shows hex string; convert back to bytes
                try:
                    data = bytes.fromhex(text.replace(" ", "").replace("\n", ""))
                except ValueError:
                    data = text.encode("utf-8")
            else:
                data = text.encode("utf-8")
        else:
            data = self.editor.toPlainText().encode("utf-8")

        self._send_action(self._current_flow["id"], "forward", data)
        self._remove_current_flow()

    def _drop(self):
        if self._current_flow is None:
            return
        self._send_action(self._current_flow["id"], "drop", None)
        self._remove_current_flow()

    def _forward_all(self):
        for flow in list(self._pending_flows):
            self._send_action(flow["id"], "forward", None)

        self._pending_flows = []
        self.queue_table.setRowCount(0)
        self._current_flow = None
        self._clear_editor()
        self.fwd_all_btn.setEnabled(False)
        self._update_queue_label()

    def _highlight_matches(self):
        """Highlight all search matches"""
        search_text = self.search_input.text()
        if not search_text:
            self.editor.setExtraSelections([])
            self.search_count_lbl.setText("")
            return

        extra_selections = []
        color = QColor("#4d4d1a") # Dark yellow
        fmt = QTextCharFormat()
        fmt.setBackground(QBrush(color))
        
        doc = self.editor.document()
        cursor = QTextCursor(doc)
        
        while True:
            cursor = doc.find(search_text, cursor)
            if cursor.isNull():
                break
            
            selection = QTextEdit.ExtraSelection()
            selection.cursor = cursor
            selection.format = fmt
            extra_selections.append(selection)
            
        self.editor.setExtraSelections(extra_selections)
        self._update_search_label()

    def _update_search_label(self):
        """Update the 1/N label"""
        search_text = self.search_input.text()
        if not search_text:
            self.search_count_lbl.setText("")
            return
            
        # Count total matches
        doc = self.editor.document()
        cursor = QTextCursor(doc)
        total = 0
        while True:
            cursor = doc.find(search_text, cursor)
            if cursor.isNull():
                break
            total += 1
            
        if total == 0:
            self.search_count_lbl.setText("0/0")
            return

        # Find current index
        current_cursor = self.editor.textCursor()
        if not current_cursor.hasSelection() or current_cursor.selectedText() != search_text:
             self.search_count_lbl.setText(f"?/{total}")
             return
             
        pos = current_cursor.selectionStart()
        cursor = QTextCursor(doc)
        index = 0
        found_index = 0
        
        while True:
            cursor = doc.find(search_text, cursor)
            if cursor.isNull():
                break
            index += 1
            if cursor.selectionStart() == pos:
                found_index = index
                break
        
        if found_index > 0:
            self.search_count_lbl.setText(f"{found_index}/{total}")
        else:
            self.search_count_lbl.setText(f"?/{total}")

    def _search_next(self):
        text = self.search_input.text()
        if not text:
            return
        
        found = self.editor.find(text)
        if not found:
            # Wrap around
            cursor = self.editor.textCursor()
            cursor.movePosition(QTextCursor.Start)
            self.editor.setTextCursor(cursor)
            self.editor.find(text)
        self._update_search_label()

    def _search_prev(self):
        text = self.search_input.text()
        if not text:
            return
            
        found = self.editor.find(text, QTextDocument.FindBackward)
        if not found:
            # Wrap around
            cursor = self.editor.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.editor.setTextCursor(cursor)
            self.editor.find(text, QTextDocument.FindBackward)
        self._update_search_label()

    def _show_context_menu(self, pos):
        if not self._current_flow:
            return
        
        menu = self.editor.createStandardContextMenu()
        menu.addSeparator()

        repeater_act = menu.addAction("→ Send to Repeater (Ctrl+R)")
        repeater_act.triggered.connect(self._send_to_repeater)

        intruder_act = menu.addAction("→ Send to Intruder (Ctrl+I)")
        intruder_act.triggered.connect(self._send_to_intruder)

        scanner_act = menu.addAction("→ Send to Scanner (Ctrl+S)")
        scanner_act.triggered.connect(self._send_to_scanner)

        poc_act = menu.addAction("→ Send to PoC Generator")
        poc_act.triggered.connect(self._send_to_poc)

        jwt_act = menu.addAction("→ Send to JWT Analyzer")
        jwt_act.triggered.connect(self._send_to_jwt)

        endpoints_act = menu.addAction("→ Send to Attack Surface")
        endpoints_act.triggered.connect(self._send_to_endpoints)

        report_act = menu.addAction("� Report Bug")
        report_act.triggered.connect(self._send_to_report)

        menu.addSeparator()
        if self._current_flow and self._current_flow.get("type") == "request":
            intercept_resp_act = menu.addAction(" Intercept response for this request")
            intercept_resp_act.setToolTip(
                "Forward this request and intercept its response — "
                "without enabling global response intercept"
            )
            intercept_resp_act.triggered.connect(self._intercept_response_for_this)

        menu.addSeparator()
        ai_analyze_act = menu.addAction("✨ AI Analyze  (Ctrl+Shift+C)")
        ai_analyze_act.triggered.connect(self._ai_analyze)
        send_to_ai_act = menu.addAction("✨ Send to AI")
        send_to_ai_act.triggered.connect(self._send_to_ai)

        menu.exec_(self.editor.mapToGlobal(pos))

    def _send_to_repeater(self):
        self._send_to_tool("Repeater", switch_tab=False)

    def _send_to_intruder(self):
        self._send_to_tool("Intruder", switch_tab=False)

    def _send_to_scanner(self):
        self._send_to_tool("Scanner", switch_tab=False)

    def _send_to_poc(self):
        self._send_to_tool("PoC", switch_tab=True)

    def _send_to_jwt(self):
        """Send the intercepted request to the JWT Analyzer tab."""
        if not self._current_flow:
            return
        try:
            main_win = self.window()
            jwt_tab = getattr(main_win, "jwt_tab", None)
            if jwt_tab is None or not hasattr(jwt_tab, "load_request"):
                return
            raw_data = self.editor.toPlainText()
            meta = self._current_flow.get("meta", {})
            host = meta.get("host", "")
            port = int(meta.get("port", 443))
            is_https = meta.get("scheme", "https") == "https"
            jwt_tab.load_request(raw_data, host=host, port=port, is_https=is_https)
            if hasattr(main_win, "_switch_to_tools_subtab"):
                main_win._switch_to_tools_subtab("JWT")
        except Exception as e:
            logger.error(f"[InterceptTab] send to JWT: {e}")

    def _send_to_endpoints(self):
        """Send the intercepted request to the Attack Surface tab."""
        if not self._current_flow:
            return
        try:
            main_win = self.window()
            if not hasattr(main_win, 'attack_surface_tab'):
                return
            raw_data = self.editor.toPlainText()
            meta = self._current_flow.get("meta", {})
            url    = meta.get("url", "")
            method = meta.get("method", "GET")
            finding = {
                "url":          url,
                "method":       method,
                "status":       "",
                "request_text": raw_data,
                "source":       "Intercept",
            }
            main_win.attack_surface_tab.add_from_http_history(finding)
            for i in range(main_win.tab_widget.count()):
                if "Attack Surface" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            logger.error(f"[InterceptTab] send to attack surface: {e}")

    def _send_to_report(self):
        """Open the Report Bug dialog pre-filled from the current intercepted request."""
        if not self._current_flow:
            return
        try:
            main_win = self.window()
            report_tab = getattr(main_win, 'report_tab', None)
            if report_tab is None or not hasattr(report_tab, 'add_from_finding'):
                return
            meta = self._current_flow.get("meta", {})
            finding = {
                "url":    meta.get("url", ""),
                "method": meta.get("method", "GET"),
                "source": "Intercept",
            }
            report_tab.add_from_finding(finding)
            for i in range(main_win.tab_widget.count()):
                if "Report" in main_win.tab_widget.tabText(i):
                    main_win.tab_widget.setCurrentIndex(i)
                    break
        except Exception as e:
            logger.error(f"[InterceptTab] send to report: {e}")

    # ── AI Chat helpers ───────────────────────────────────────────────────────

    def _get_ai_panel(self):
        """Return the shared _AIChatPanel from the main window, or None."""
        try:
            return getattr(self.window(), '_ai_chat_panel', None)
        except Exception:
            return None

    def _get_ai_traffic_settings(self) -> dict:
        """Return AI settings from the main window."""
        try:
            main_win = self.window()
            if hasattr(main_win, '_ai_traffic_settings'):
                return main_win._ai_traffic_settings()
            gs = getattr(main_win, '_global_settings', None)
            if gs:
                return gs
        except Exception:
            pass
        return {}

    def _ensure_ai_panel_visible(self):
        """Reparent the shared AI panel into this tab's outer splitter and show it."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        splitter = self._ai_outer_splitter
        if panel.parent() is not splitter:
            splitter.addWidget(panel)
        sizes = splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            splitter.setSizes([max(300, int(total * 0.55)), max(350, int(total * 0.45))])
        settings = self._get_ai_traffic_settings()
        if settings and not panel._last_settings:
            panel._last_settings = settings

    def _ai_toggle_panel(self):
        """Toggle the shared AI chat panel inside this tab — no tab switching."""
        panel = self._get_ai_panel()
        if panel is None:
            return
        splitter = self._ai_outer_splitter
        if panel.parent() is not splitter:
            self._ensure_ai_panel_visible()
            return
        sizes = splitter.sizes()
        total = sum(sizes) or 1200
        if len(sizes) < 2 or sizes[-1] < 200:
            splitter.setSizes([max(300, int(total * 0.55)), max(350, int(total * 0.45))])
            settings = self._get_ai_traffic_settings()
            if settings and not panel._last_settings:
                panel._last_settings = settings
        else:
            splitter.setSizes([total, 0])

    def _ai_analyze(self):
        """Run a full AI security analysis on the current intercepted request."""
        if not self._current_flow:
            return
        panel = self._get_ai_panel()
        if panel is None:
            return
        settings  = self._get_ai_traffic_settings()
        provider  = settings.get("ai_provider", "openai")
        api_key   = settings.get("ai_api_key", "").strip()
        if provider != "ollama" and not api_key:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "AI Analyze", "No AI API key configured.")
            return
        meta      = self._current_flow.get("meta", {})
        req_text  = self.editor.toPlainText()
        resp_text = ""
        url       = meta.get("url", "")
        self._ensure_ai_panel_visible()
        panel.start_analysis(settings, req_text, resp_text, url)

    def _send_to_ai(self):
        """Pin the current intercepted request in the AI chat panel."""
        if not self._current_flow:
            return
        panel = self._get_ai_panel()
        if panel is None:
            return
        settings  = self._get_ai_traffic_settings()
        provider  = settings.get("ai_provider", "openai")
        api_key   = settings.get("ai_api_key", "").strip()
        if provider != "ollama" and not api_key:
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Send to AI", "No AI API key configured.")
            return
        meta      = self._current_flow.get("meta", {})
        req_text  = self.editor.toPlainText()
        resp_text = ""
        url       = meta.get("url", "")
        self._ensure_ai_panel_visible()
        panel.set_context(settings, req_text, resp_text, url)

    def _send_to_tool(self, tool_name, switch_tab=False):
        if not self._current_flow:
            return
            
        raw_data = self.editor.toPlainText()
        meta = self._current_flow.get("meta", {})
        url = meta.get("url", "")
        host = meta.get("host", "")
        
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme
        if not host:
            host = parsed.hostname or ""
        port = parsed.port
        if not port:
            port = 443 if scheme == 'https' else 80
        use_ssl = (scheme == 'https')
        
        main_win = self.window()
        if tool_name == "Repeater" and hasattr(main_win, "repeater_tab"):
            main_win.repeater_tab.add_request(raw_data, host, port, use_ssl, tab_name="Intercept")
            if switch_tab:
                main_win.tab_widget.setCurrentWidget(main_win.repeater_tab)
            else:
                if hasattr(main_win, "flash_tab"):
                    main_win.flash_tab("Repeater")
        elif tool_name == "Intruder" and hasattr(main_win, "intruder_tab"):
            main_win.intruder_tab.load_request(raw_data, host, port, use_ssl)
            if switch_tab:
                main_win.tab_widget.setCurrentWidget(main_win.intruder_tab)
            else:
                if hasattr(main_win, "flash_tab"):
                    main_win.flash_tab("Intruder")
        elif tool_name == "Scanner" and hasattr(main_win, "scanner_tab"):
            # Construct request_data for scanner
            request_data = {
                "url": url,
                "method": meta.get("method", "GET"),
                "request_text": raw_data,
                "response_text": "",
                "finding": {}
            }
            main_win.scanner_tab.add_request_to_queue(request_data)
            if switch_tab:
                main_win.tab_widget.setCurrentWidget(main_win.scanner_tab)
            else:
                if hasattr(main_win, "flash_tab"):
                    main_win.flash_tab("Scanner")
        elif tool_name == "PoC" and hasattr(main_win, "poc_tab"):
            main_win.poc_tab.load_request(raw_data, host, port, use_ssl)
            if switch_tab:
                main_win.tab_widget.setCurrentWidget(main_win.poc_tab)
            else:
                if hasattr(main_win, "flash_tab"):
                    main_win.flash_tab("PoC")

    def resolve_flow(self, flow_id: str, action: str, data: Optional[bytes] = None):
        """Resolve a specific flow by ID (used by popup dialog)"""
        # Find flow
        flow = next((f for f in self._pending_flows if f["id"] == flow_id), None)
        if not flow:
            return

        self._send_action(flow_id, action, data)
        
        # Remove from internal list
        self._pending_flows = [f for f in self._pending_flows if f["id"] != flow_id]
        
        # Remove from table
        self._remove_flow_from_table(flow_id)
        
        # If it was the current flow being displayed, update UI
        if self._current_flow and self._current_flow["id"] == flow_id:
            if self._pending_flows:
                self._show_flow(self._pending_flows[0])
                self.queue_table.selectRow(0)
            else:
                self._remove_current_flow() # Handles clearing editor

    def _send_action(self, flow_id: str, action: str, data: Optional[bytes],
                     intercept_response: bool = False):
        """Send action for an intercepted flow"""
        if not self._project_dir:
            return

        actions_dir = os.path.join(self._project_dir, "intercept_actions")
        os.makedirs(actions_dir, exist_ok=True)

        action_file = os.path.join(actions_dir, f"{flow_id}.action")

        payload = {"action": action}
        if intercept_response:
            payload["intercept_response"] = True

        if data is not None:
            # CRITICAL FIX: Preserve the raw HTTP format exactly
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # IMPORTANT: Do NOT normalize line endings for HTTP
            # HTTP requires CRLF (\r\n) line endings
            # If we're editing, assume the user has provided proper HTTP format
            
            payload["edited_data"] = base64.b64encode(data).decode()
            logger.debug(f"Sending edited data for {flow_id}: {len(data)} bytes")
        
        # Write action file atomically
        temp_file = action_file + ".tmp"
        try:
            with open(temp_file, "w") as f:
                json.dump(payload, f)
                f.flush()
                os.fsync(f.fileno())  # Ensure it's written to disk
            os.rename(temp_file, action_file)
            logger.info(f"Sent {action} action for {flow_id}")
            
            # CRITICAL FIX: Give the addon time to process before removing from GUI
            QTimer.singleShot(500, lambda: None)  # Small delay
            
        except Exception as e:
            logger.error(f"Failed to write action file: {e}")

    def _intercept_response_for_this(self):
        """Forward the current request and intercept its response (one-shot, no global toggle)."""
        if self._current_flow is None:
            return
        if self._current_flow.get("type") != "request":
            QMessageBox.information(
                self, "Requests Only",
                "\"Intercept response for this request\" only applies to intercepted requests."
            )
            return
        # If in GQL edit mode sync panel edits back first
        if getattr(self, '_gql_mode', False) and getattr(self, '_gql_flow_type', '') != 'response':
            self._sync_gql_to_raw()

        # Write a file-based marker so the addon reliably intercepts this response
        # even when many flows are in flight concurrently.
        mitmflow_id = self._current_flow.get("meta", {}).get("mitmflow_id", "")
        if mitmflow_id and self._project_dir:
            marker_path = os.path.join(
                self._project_dir, "intercept_actions",
                f"oneshot_resp_{mitmflow_id}"
            )
            try:
                os.makedirs(os.path.dirname(marker_path), exist_ok=True)
                open(marker_path, "w").close()
                logger.info(f"One-shot response marker written for mitmflow {mitmflow_id}")
            except Exception as e:
                logger.warning(f"Could not write one-shot marker: {e}")

        data = self.editor.toPlainText().encode("utf-8")
        self._send_action(
            self._current_flow["id"], "forward", data, intercept_response=True
        )
        self._remove_current_flow()

    def _remove_current_flow(self):
        if self._current_flow is None:
            return
        flow_id = self._current_flow.get("id")
        self._pending_flows = [f for f in self._pending_flows if f.get("id") != flow_id]

        # Remove from table
        for row in range(self.queue_table.rowCount()):
            item = self.queue_table.item(row, 3)
            if item and item.data(Qt.UserRole) == flow_id:
                self.queue_table.removeRow(row)
                break

        # Show next
        if self._pending_flows:
            self._show_flow(self._pending_flows[0])
            self.queue_table.selectRow(0)
        else:
            self._current_flow = None
            self._clear_editor()
            self.fwd_all_btn.setEnabled(False)

        self._update_queue_label()

    def _clear_editor(self):
        self.editor.setReadOnly(True)
        self.editor.clear()
        self.editor_type_lbl.setText("—")
        self.flow_info_lbl.setText("No flow intercepted")
        self.forward_btn.setEnabled(False)
        self.drop_btn.setEnabled(False)

    def _update_queue_label(self):
        self.queue_lbl.setText(f"Queue: {len(self._pending_flows)}")

    def stop(self):
        if self._queue_reader:
            self._queue_reader.stop()

    # ── Styles ─────────────────────────────────────────────────────────────

    def _toggle_style(self, active: bool) -> str:
        c = COLOR_SUCCESS if active else COLOR_CRITICAL
        return (
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {c}; "
            f"border: 2px solid {c}; border-radius: 4px; padding: 5px 14px; "
            f"font-weight: 700; font-size: {FONT_SIZE_NORMAL}; }}"
            f"QPushButton:hover {{ background-color: {c}; color: #000; }}"
        )

    def _action_btn_style(self, color: str) -> str:
        return (
            f"QPushButton {{ background-color: {COLOR_ELEVATED_BG}; color: {color}; "
            f"border: 1px solid {color}; border-radius: 4px; padding: 5px 14px; "
            f"font-weight: 600; font-size: {FONT_SIZE_SMALL}; min-width: 100px; }}"
            f"QPushButton:hover {{ background-color: {color}; color: #000; }}"
            f"QPushButton:disabled {{ color: {COLOR_TEXT_MUTED}; border-color: {COLOR_BORDER}; }}"
        )

    def _groupbox_style(self) -> str:
        return (
            f"QGroupBox {{ border: 1px solid {COLOR_BORDER}; border-radius: 6px; "
            f"margin-top: 10px; padding-top: 14px; background-color: {COLOR_CARD_BG}; "
            f"font-weight: 600; color: {COLOR_TEXT_BRIGHT}; }}"
            f"QGroupBox::title {{ subcontrol-origin: margin; left: 12px; "
            f"padding: 0 8px; color: {COLOR_ACCENT}; background-color: {COLOR_CARD_BG}; }}"
        )
        
    # ── Selection Inspector ─────────────────────────────────────────────────

    def _build_selection_inspector(self) -> QWidget:
        """Build the Selection Inspector widget for the lower half of the Pending Queue panel."""
        self._sel_current_text: str = ""
        self._sel_detected_encoding: str = ""
        self._sel_decoded_original: str = ""

        container = QWidget()
        container.setStyleSheet(
            f"QWidget {{ background-color: {COLOR_CARD_BG}; }}"
        )
        clayout = QVBoxLayout(container)
        clayout.setContentsMargins(0, 0, 0, 0)
        clayout.setSpacing(0)

        # Header bar
        header = QWidget()
        header.setFixedHeight(28)
        header.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};border-top:1px solid {COLOR_BORDER};"
            f"border-bottom:1px solid {COLOR_BORDER};"
        )
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(8, 3, 8, 3)
        h_layout.setSpacing(6)

        hdr_lbl = QLabel("🔬 Selection Inspector")
        hdr_lbl.setStyleSheet(
            f"color:{COLOR_ACCENT};font-weight:700;font-size:11px;background:transparent;"
        )
        h_layout.addWidget(hdr_lbl)

        self._sel_source_badge = QLabel("")
        self._sel_source_badge.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:10px;background:transparent;"
        )
        h_layout.addWidget(self._sel_source_badge)
        h_layout.addStretch()

        _copy_btn = QPushButton("📋 Copy")
        _copy_btn.setFixedHeight(20)
        _copy_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 6px;"
        )
        _copy_btn.setToolTip("Copy raw selected text")
        _copy_btn.clicked.connect(
            lambda: QApplication.clipboard().setText(self._sel_current_text)
        )

        _dec_btn = QPushButton("Open in Decoder")
        _dec_btn.setFixedHeight(20)
        _dec_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_ACCENT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 6px;"
        )
        _dec_btn.setToolTip("Send selected text to Decoder tab")
        _dec_btn.clicked.connect(self._send_intercept_selection_to_decoder)

        h_layout.addWidget(_copy_btn)
        h_layout.addWidget(_dec_btn)
        clayout.addWidget(header)

        # Card scroll area
        self._sel_card_scroll = QScrollArea()
        self._sel_card_scroll.setWidgetResizable(True)
        self._sel_card_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._sel_card_scroll.setStyleSheet(
            "QScrollArea{border:none;background:transparent;}"
            "QScrollBar:vertical{width:6px;background:transparent;}"
            "QScrollBar::handle:vertical{background:#555;border-radius:3px;min-height:20px;}"
        )
        self._sel_card_scroll.setVisible(False)
        card_container = QWidget()
        card_container.setStyleSheet("background:transparent;")
        self._sel_card_layout = QVBoxLayout(card_container)
        self._sel_card_layout.setContentsMargins(4, 4, 4, 4)
        self._sel_card_layout.setSpacing(4)
        self._sel_card_scroll.setWidget(card_container)
        clayout.addWidget(self._sel_card_scroll, 1)

        # Persistent re-encode card (hidden until encoding detected)
        reenc_body = QWidget()
        reenc_body.setStyleSheet("background:transparent;")
        rb_layout = QVBoxLayout(reenc_body)
        rb_layout.setContentsMargins(4, 4, 4, 4)
        rb_layout.setSpacing(4)

        self._reenc_edit = QTextEdit()
        self._reenc_edit.setFixedHeight(70)
        self._reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:4px;"
        )
        rb_layout.addWidget(self._reenc_edit)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        _reset_btn = QPushButton("↩ Reset")
        _reset_btn.setFixedHeight(22)
        _reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 8px;"
        )
        _reset_btn.clicked.connect(self._reset_reenc_edit)
        _apply_btn = QPushButton("✔ Apply & Re-encode")
        _apply_btn.setFixedHeight(22)
        _apply_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;"
            f"border:1px solid {COLOR_SUCCESS};border-radius:3px;"
            f"font-size:10px;font-weight:700;padding:0 10px;"
        )
        _apply_btn.clicked.connect(self._apply_reencoded)
        btn_row.addWidget(_reset_btn)
        btn_row.addWidget(_apply_btn)
        rb_layout.addLayout(btn_row)

        self._sel_reenc_card = _InspectorCard(
            "✏  Edit Decoded", "#4A9EFF", body_widget=reenc_body
        )
        self._sel_reenc_card.setVisible(False)
        clayout.addWidget(self._sel_reenc_card)

        # Placeholder label when nothing is selected
        self._sel_placeholder = QLabel(
            "Select text in the intercepted message editor to inspect it"
        )
        self._sel_placeholder.setAlignment(Qt.AlignCenter)
        self._sel_placeholder.setStyleSheet(
            f"color:{COLOR_TEXT_MUTED};font-size:11px;background:transparent;padding:16px;"
        )
        clayout.addWidget(self._sel_placeholder)

        return container

    def _make_inline_final_card(self, label: str, color: str, body_html: str):
        body = QWidget()
        body.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(body)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(4)

        self._reenc_edit = QTextEdit()
        self._reenc_edit.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._reenc_edit.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._reenc_edit.setStyleSheet(
            f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;"
            f"font-family:{FONT_FAMILY_MONO};font-size:11px;padding:4px;"
        )
        self._reenc_edit.setHtml(body_html)
        self._reenc_edit.textChanged.connect(
            lambda: self._fit_inline_edit_height(self._reenc_edit)
        )
        QTimer.singleShot(0, lambda: self._fit_inline_edit_height(self._reenc_edit))
        lay.addWidget(self._reenc_edit)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        _reset_btn = QPushButton("↩ Reset")
        _reset_btn.setFixedHeight(22)
        _reset_btn.setStyleSheet(
            f"background:{COLOR_ELEVATED_BG};color:{COLOR_TEXT_MUTED};"
            f"border:1px solid {COLOR_BORDER};border-radius:3px;font-size:10px;padding:0 8px;"
        )
        _reset_btn.clicked.connect(self._reset_reenc_edit)
        _apply_btn = QPushButton("✔ Apply & Re-encode")
        _apply_btn.setFixedHeight(22)
        _apply_btn.setStyleSheet(
            f"background:{COLOR_SUCCESS};color:#000;"
            f"border:1px solid {COLOR_SUCCESS};border-radius:3px;"
            f"font-size:10px;font-weight:700;padding:0 10px;"
        )
        _apply_btn.clicked.connect(self._apply_reencoded)
        btn_row.addWidget(_reset_btn)
        btn_row.addWidget(_apply_btn)
        lay.addLayout(btn_row)

        return _InspectorCard(label, color, body_widget=body)

    def _build_sel_inspector_cards(self, card_data: list, encoding: str = "", decoded_val: str = ""):
        """Rebuild the selection inspector card scroll area."""
        # Null out reference BEFORE deleteLater to avoid RuntimeError
        self._reenc_edit = None
        lay = self._sel_card_layout
        while lay.count() > 0:
            item = lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._sel_reenc_original_html = ""
        for label, color, body, warn, crit, is_html in card_data:
            if encoding and decoded_val is not None and "Final Decoded" in label:
                self._sel_reenc_original_html = body
                card = self._make_inline_final_card(label, color, body)
            else:
                card = _InspectorCard(label, color, body, warn=warn, crit=crit, is_html=is_html)
            lay.addWidget(card)
        lay.addStretch()
        QApplication.processEvents()
        if hasattr(self, '_reenc_edit') and self._reenc_edit is not None:
            self._fit_inline_edit_height(self._reenc_edit)
        self._sel_card_scroll.verticalScrollBar().setValue(0)

    def _fit_inline_edit_height(self, edit: QTextEdit, min_h: int = 78, max_h: int = 420):
        """Auto-size inline edit fields to content, avoiding inner scrollbars."""
        if edit is None:
            return
        try:
            doc = edit.document()
            vw = edit.viewport().width()
            if vw <= 0:
                vw = max(edit.width() - 12, 120)
            doc.setTextWidth(max(vw, 60))
            h = int(doc.documentLayout().documentSize().height())
            margin = int(doc.documentMargin())
            target = h + margin * 2 + 12
            edit.setFixedHeight(max(min_h, min(max_h, target)))
        except RuntimeError:
            pass  # Widget was deleted between the check and the call

    def _on_intercept_selection_changed(self):
        """Called when the selection in the intercepted message editor changes."""
        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            text = cursor.selectedText().replace('\u2029', '\n').replace('\u2028', '\n')
            if text and len(text.strip()) >= 2:
                self._sel_current_text = text
                self._sel_source_badge.setText(
                    f"\u2022 {len(text)} chars \u2022 {len(text.encode('utf-8'))} bytes"
                )
                self._sel_pending_text = text
                self._sel_debounce_timer.start()
                self._sel_placeholder.setVisible(False)
                self._sel_card_scroll.setVisible(True)
                return
        # No selection or too short
        self._sel_debounce_timer.stop()
        self._sel_pending_text = ""
        self._sel_current_text = ""
        self._sel_detected_encoding = ""
        self._sel_decoded_original = ""
        self._sel_source_badge.setText("")
        self._sel_card_scroll.setVisible(False)
        self._sel_reenc_card.setVisible(False)
        self._sel_placeholder.setVisible(True)

    def _process_intercept_selection(self):
        """Run heavy selection analysis after debounce delay."""
        text = getattr(self, '_sel_pending_text', '')
        if not text:
            return
        cached = self._sel_last_analysis
        if cached and cached[0] == text:
            _text, cards, encoding, decoded_val = cached
        else:
            cards, encoding, decoded_val = _analyze_selection_cards(text)
            self._sel_last_analysis = (text, cards, encoding, decoded_val)
        self._sel_detected_encoding = encoding
        self._sel_decoded_original = decoded_val or ""
        self._build_sel_inspector_cards(cards, encoding, decoded_val or "")
        self._sel_reenc_card.setVisible(False)

    def _reset_reenc_edit(self):
        """Reset the edit box to the originally decoded value."""
        if hasattr(self, '_reenc_edit') and self._reenc_edit is not None:
            html = getattr(self, '_sel_reenc_original_html', '')
            if html:
                self._reenc_edit.setHtml(html)
            elif hasattr(self, '_sel_decoded_original'):
                self._reenc_edit.setPlainText(self._sel_decoded_original)

    def _apply_reencoded(self):
        """Re-encode the edited text and replace the selection in the editor."""
        edited = self._reenc_edit.toPlainText()
        enc = self._sel_detected_encoding
        if not enc:
            return

        try:
            reencoded = reencode_decoded_value(edited, enc, self._sel_current_text)
        except Exception as e:
            QMessageBox.warning(self, "Re-encode Error", f"Could not re-encode: {e}")
            return

        cursor = self.editor.textCursor()
        if cursor.hasSelection():
            cursor.insertText(reencoded)
            self.editor.setTextCursor(cursor)
        else:
            QMessageBox.information(
                self, "No Selection",
                "The original selection was lost. Please re-select the text and try again."
            )

    def _send_intercept_selection_to_decoder(self):
        """Send the currently selected text to the Decoder tab."""
        text = getattr(self, '_sel_current_text', '')
        if not text:
            return
        main_win = self.window()
        if hasattr(main_win, 'tab_widget'):
            tw = main_win.tab_widget
            for i in range(tw.count()):
                if 'Decoder' in tw.tabText(i):
                    tw.setCurrentIndex(i)
                    break
        for te in main_win.findChildren(QTextEdit):
            if te.objectName() == 'decoder_input' and not te.isReadOnly():
                te.setPlainText(text)
                te.setFocus()
                break

    def _make_gql_panel(self, title: str, title_color: str, read_only: bool = True, highlight: str = None):
        panel = QWidget()
        panel.setMinimumHeight(50)
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(0, 0, 0, 0)
        pl.setSpacing(0)
        hdr = QFrame()
        hdr.setFixedHeight(22)
        hdr.setStyleSheet(f"background:{COLOR_ELEVATED_BG};border-bottom:1px solid {COLOR_BORDER};")
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(10, 0, 8, 0)
        lbl = QLabel(title)
        lbl.setStyleSheet(f"color:{title_color};font-weight:700;font-size:10px;letter-spacing:1px;")
        hl.addWidget(lbl)
        hl.addStretch()
        pl.addWidget(hdr)
        te = QTextEdit()
        te.setReadOnly(read_only)
        te._title_lbl = lbl
        if read_only:
            te.setStyleSheet(f"background:{COLOR_DARK_BG};color:{COLOR_TEXT};font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;padding:4px;")
        else:
            te.setStyleSheet(
                f"background:{COLOR_DARK_BG};color:{COLOR_TEXT_BRIGHT};"
                f"font-family:{FONT_FAMILY_MONO};font-size:12px;border:none;padding:4px;"
            )
        if highlight == "gql":
            te._hl = GQLSyntaxHighlighter(te.document())
        elif highlight == "json":
            te._hl = JSONSyntaxHighlighter(te.document())
        pl.addWidget(te)
        return panel, te

    def _detect_graphql(self, url: str, text: str, flow_type: str) -> dict:
        import json
        url_lower = (url or "").lower()
        url_hint  = any(p in url_lower for p in
                        ("/graphql", "/gql", "/graphiql", "/playground", "graphql.json", "graphql.php"))
        if flow_type == "response":
            resp_json_hint = False
            try:
                pos = text.find("\n\n")
                if pos == -1: pos = text.find("\r\n\r\n")
                rb  = text[pos:].strip() if pos != -1 else text
                if rb.startswith("{"):
                    rd = json.loads(rb)
                    if isinstance(rd, dict) and ("data" in rd or "errors" in rd):
                        resp_json_hint = True
            except Exception: pass
            if not (url_hint or resp_json_hint): return {}
            return {"is_graphql": True, "flow_type": "response", "_resp_text": text, "url_hint": url_hint}
        req_headers: dict = {}; body = ""
        if text:
            lines = text.split("\n"); in_body = False
            for line in lines[1:]:
                stripped = line.rstrip("\r")
                if not in_body:
                    if stripped == "": in_body = True
                    elif ":" in stripped:
                        k, _, v = stripped.partition(":")
                        req_headers[k.strip().lower()] = v.strip()
                else:
                    body += stripped + "\n"
            body = body.strip()
        ct = req_headers.get("content-type", "")
        ct_graphql = "application/graphql" in ct
        ct_json    = "application/json" in ct or ct == ""
        query = ""; variables: dict = {}; operation_name = ""; operation_type = "query"
        if body and ct_json:
            try:
                p = json.loads(body)
                if isinstance(p, dict):
                    query = p.get("query", "") or ""
                    variables = p.get("variables") or {}
                    operation_name = p.get("operationName") or ""
            except Exception: pass
        if not query and ct_graphql and body: query = body
        qs = query.lstrip()
        if qs.startswith("mutation"):       operation_type = "mutation"
        elif qs.startswith("subscription"): operation_type = "subscription"
        introspection = "__schema" in query or "__type" in query or "IntrospectionQuery" in (operation_name + query)
        if not (url_hint or (query and (ct_graphql or ct_json))): return {}
        return {
            "is_graphql": True, "flow_type": "request",
            "query": query, "variables": variables,
            "operation_name": operation_name, "operation_type": operation_type,
            "introspection": introspection, "url_hint": url_hint,
        }

    def _update_gql_state(self, url: str, text: str, flow_type: str) -> None:
        if flow_type == "ws_message":
            self._gql_state = {}; self._gql_mode = False
            self._gql_btn.setVisible(False)
            self._gql_main_stack.setCurrentIndex(0)
            return
        gql = self._detect_graphql(url, text, flow_type)
        self._gql_state = gql; self._gql_flow_type = flow_type
        self._gql_mode = False
        self._gql_btn.blockSignals(True)
        self._gql_btn.setChecked(False)
        self._gql_btn.blockSignals(False)
        self._gql_btn.setText("⬡ GraphQL")
        self._gql_btn.setVisible(bool(gql))
        self._gql_main_stack.setCurrentIndex(0)

    def _sync_gql_to_raw(self) -> None:
        """Write editable GQL panel contents back into self.editor (the raw HTTP editor)."""
        import json
        raw = self.editor.toPlainText()
        if "\r\n\r\n" in raw:
            header_part, _ = raw.split("\r\n\r\n", 1)
            sep = "\r\n\r\n"
        elif "\n\n" in raw:
            header_part, _ = raw.split("\n\n", 1)
            sep = "\n\n"
        else:
            header_part = raw
            sep = "\n\n"
        query    = self._gql_query_text.toPlainText().strip()
        vars_txt = self._gql_vars_text.toPlainText().strip()
        op_name  = self._gql_opname_text.toPlainText().strip().splitlines()[0].strip() if self._gql_opname_text.toPlainText().strip() else ""
        variables: dict = {}
        if vars_txt:
            try:
                variables = json.loads(vars_txt)
            except Exception:
                pass
        body_dict: dict = {"query": query}
        if variables:
            body_dict["variables"] = variables
        if op_name:
            body_dict["operationName"] = op_name
        new_body   = json.dumps(body_dict, indent=2, ensure_ascii=False)
        body_bytes = new_body.encode("utf-8")
        header_lines = header_part.splitlines()
        new_header_lines = []
        for line in header_lines:
            if line.lower().startswith("content-length:"):
                new_header_lines.append(f"Content-Length: {len(body_bytes)}")
            else:
                new_header_lines.append(line)
        self.editor.setPlainText("\n".join(new_header_lines) + sep + new_body)
        # Keep in-memory gql state in sync
        self._gql_state["query"]          = query
        self._gql_state["variables"]      = variables
        self._gql_state["operation_name"] = op_name

    def _toggle_gql_view(self) -> None:
        self._gql_mode = self._gql_btn.isChecked()
        if self._gql_mode:
            gql = self._gql_state
            if gql.get("flow_type") == "response":
                self._populate_gql_resp_panels(gql.get("_resp_text", ""))
                self._gql_view_stack.setCurrentIndex(1)
            else:
                self._populate_gql_req_panels(gql)
                self._gql_view_stack.setCurrentIndex(0)
            self._gql_main_stack.setCurrentIndex(1)
            self._gql_btn.setText("◎ Raw")
        else:
            # If we were in request GQL edit mode, sync panel edits back to editor
            if self._gql_flow_type != "response":
                self._sync_gql_to_raw()
            self._gql_main_stack.setCurrentIndex(0)
            self._gql_btn.setText("⬡ GraphQL")

    def _populate_gql_req_panels(self, gql: dict) -> None:
        import json
        query = gql.get("query", ""); vars_ = gql.get("variables") or {}
        op_name = gql.get("operation_name", ""); op_type = gql.get("operation_type", "query")
        is_intro = gql.get("introspection", False)
        # Update query panel title with operation type badge
        type_badge = f"  ·  {op_type.upper()}" + ("  ·  Introspection" if is_intro else "")
        if hasattr(self._gql_query_text, "_title_lbl"):
            self._gql_query_text._title_lbl.setText(f"⬡  QUERY{type_badge}")
        self._gql_query_text.setPlainText(query.strip() or "")
        self._gql_query_panel.setVisible(True)
        if vars_:
            self._gql_vars_text.setPlainText(json.dumps(vars_, indent=2))
        else:
            self._gql_vars_text.setPlainText("")
        self._gql_vars_panel.setVisible(True)
        # Operation name panel: editable plain name
        if op_name:
            self._gql_opname_text.setPlainText(op_name)
            self._gql_opname_panel.setVisible(True)
        else:
            self._gql_opname_text.setPlainText("")
            self._gql_opname_panel.setVisible(False)
        panels = [self._gql_query_panel, self._gql_vars_panel, self._gql_opname_panel]
        weights = [700, 250, 50]
        sizes  = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self._gql_req_splitter.setSizes(sizes)

    def _populate_gql_resp_panels(self, response_text: str) -> None:
        import json
        resp_body = ""
        if response_text:
            pos = response_text.find("\n\n")
            if pos == -1: pos = response_text.find("\r\n\r\n")
            resp_body = response_text[pos:].strip() if pos != -1 else response_text.strip()
        parsed = None
        if resp_body:
            try: parsed = json.loads(resp_body)
            except Exception: pass
        data   = parsed.get("data")       if isinstance(parsed, dict) else None
        errors = parsed.get("errors")     if isinstance(parsed, dict) else None
        exts   = parsed.get("extensions") if isinstance(parsed, dict) else None
        if errors:
            if isinstance(errors, list):
                lines_out: list = []
                for idx, err in enumerate(errors, 1):
                    msg  = err.get("message", str(err)) if isinstance(err, dict) else str(err)
                    locs = err.get("locations", []) if isinstance(err, dict) else []
                    path = err.get("path", [])     if isinstance(err, dict) else []
                    lines_out.append(f"[{idx}]  {msg}")
                    for loc in locs:
                        lines_out.append(f"       at line {loc.get('line', '?')}, column {loc.get('column', '?')}")
                    if path: lines_out.append("       path: " + " \u2192 ".join(str(p) for p in path))
                    lines_out.append("")
                self._gql_errors_text.setPlainText("\n".join(lines_out).rstrip())
            else:
                self._gql_errors_text.setPlainText(json.dumps(errors, indent=2))
            self._gql_errors_panel.setVisible(True)
        else:
            self._gql_errors_panel.setVisible(False)
        if parsed is not None:
            self._gql_data_text.setPlainText("(null)" if data is None else json.dumps(data, indent=2))
            self._gql_data_panel.setVisible(True)
        else:
            self._gql_data_text.setPlainText("(could not parse response body as JSON)")
            self._gql_data_panel.setVisible(True)
        if exts:
            self._gql_exts_text.setPlainText(json.dumps(exts, indent=2))
            self._gql_exts_panel.setVisible(True)
        else:
            self._gql_exts_panel.setVisible(False)
        panels = [self._gql_errors_panel, self._gql_data_panel, self._gql_exts_panel]
        weights = [150, 700, 150]
        sizes  = [w if p.isVisible() else 0 for p, w in zip(panels, weights)]
        self._gql_resp_splitter.setSizes(sizes)

    # ── Cleanup ─────────────────────────────────────────────────────────────

    def _cleanup_old_actions(self):
        """Clean up old action files that might be left behind"""
        if not self._project_dir:
            return
            
        actions_dir = os.path.join(self._project_dir, "intercept_actions")
        if not os.path.exists(actions_dir):
            return
            
        try:
            # Remove action files older than 1 hour
            current_time = time.time()
            for filename in os.listdir(actions_dir):
                if filename.endswith('.action'):
                    filepath = os.path.join(actions_dir, filename)
                    file_age = current_time - os.path.getmtime(filepath)
                    if file_age > 3600:  # 1 hour
                        try:
                            os.remove(filepath)
                            logger.info(f"Removed old action file: {filename}")
                        except Exception as e:
                            logger.error(f"Failed to remove old action file {filename}: {e}")
        except Exception as e:
            logger.error(f"Error cleaning up actions: {e}")