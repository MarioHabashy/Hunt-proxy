"""
ai_client.py – Unified AI client for Hunt GUI

Supports:
  - OpenAI  (gpt-4o, gpt-4-turbo, gpt-3.5-turbo, …)
  - Anthropic (claude-sonnet-4-5, claude-3-5-sonnet-20241022, …)
  - Ollama  (local – any model via Ollama's OpenAI-compatible API)

Zero additional dependencies beyond optional keyring — uses Python's built-in urllib.request.

Settings are read from ~/.config/hunt-proxy/settings.json:
  ai_provider : "openai" | "anthropic" | "ollama"
  ai_api_key  : str  (API key; leave empty for Ollama)
  ai_model    : str  (model name)
  ai_base_url : str  (base URL; used by Ollama, e.g. http://localhost:11434)

Improvements:
  - API keys loaded from OS keyring when available (secure storage)
  - Retry logic with exponential backoff on timeout
  - Response caching (MD5 keyed) to avoid re-analyzing identical traffic
  - Unified _dispatch_chat — no duplicate routing logic
  - Smarter truncation: response gets more budget than request
  - PoC and URL truncation in report prompts
  - Updated default models (Ollama: 7b, Anthropic: claude-sonnet-4-5)
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import time
import urllib.request
import urllib.error
from PyQt5.QtCore import QThread, pyqtSignal

# Optional secure key storage — falls back to plain settings dict if not installed
try:
    import keyring as _keyring
    _KEYRING_AVAILABLE = True
except ImportError:
    _KEYRING_AVAILABLE = False

_KEYRING_SERVICE = "hunt-proxy"


# ── Default models per provider ───────────────────────────────────────────────

PROVIDER_DEFAULTS = {
    "openai":     {"model": "gpt-4o",                                    "base_url": "https://api.openai.com"},
    "anthropic":  {"model": "claude-sonnet-4-5",                         "base_url": "https://api.anthropic.com"},
    "groq":       {"model": "llama-3.3-70b-versatile",                   "base_url": "https://api.groq.com/openai"},
    "gemini":     {"model": "gemini-2.0-flash",                          "base_url": "https://generativelanguage.googleapis.com/v1beta/openai"},
    "openrouter": {"model": "meta-llama/llama-3.3-70b-instruct:free",    "base_url": "https://openrouter.ai/api"},
    "ollama":     {"model": "qwen2.5-coder:7b",                          "base_url": "http://localhost:11434"},
}

# Known model prefixes / substrings per provider — used to detect provider/model mismatches.
# If the saved ai_model doesn't look like it belongs to the active provider, we fall back
# to that provider's default model instead of sending a foreign model name to the API.
_PROVIDER_MODEL_HINTS: dict = {
    "openai":     ("gpt-", "o1", "o3", "text-"),
    "anthropic":  ("claude-",),
    "groq":       ("llama", "mixtral", "gemma", "whisper", "distil"),
    "gemini":     ("gemini-",),
    "openrouter": ("/",),          # OpenRouter model names always contain a "/"
    "ollama":     (":",),          # Ollama model names always contain a ":" (e.g. model:tag)
}


def _coerce_model(provider: str, model: str) -> str:
    """Return *model* if it looks valid for *provider*, otherwise return the provider default."""
    if not model:
        return PROVIDER_DEFAULTS[provider]["model"]
    hints = _PROVIDER_MODEL_HINTS.get(provider)
    if hints and not any(model.lower().startswith(h) or h in model.lower() for h in hints):
        return PROVIDER_DEFAULTS[provider]["model"]
    return model


# ── Secure API key resolution ──────────────────────────────────────────────────

def _resolve_api_key(settings: dict, provider: str) -> str:
    """
    Return the API key for *provider*, preferring OS keyring over plain settings dict.
    Store a key securely with:
        keyring.set_password("HackRecon", "openai_api_key", "<key>")
    Falls back gracefully when keyring is not installed.
    """
    if _KEYRING_AVAILABLE:
        stored = _keyring.get_password(_KEYRING_SERVICE, f"{provider}_api_key")
        if stored:
            return stored.strip()
    # Check per-provider key store (new unified format)
    per_keys = settings.get("ai_provider_keys", {})
    if per_keys.get(provider, ""):
        return per_keys[provider].strip()
    # Fall back to legacy single-key field
    return settings.get("ai_api_key", "").strip()


def save_api_key_to_keyring(provider: str, key: str) -> bool:
    """Persist *key* in the OS keyring. Returns True on success."""
    if not _KEYRING_AVAILABLE:
        return False
    _keyring.set_password(_KEYRING_SERVICE, f"{provider}_api_key", key)
    return True


# ── Response cache (MD5-keyed, in-process) ────────────────────────────────────

_analysis_cache: dict = {}


def _cache_key(*parts: str) -> str:
    combined = "\x00".join(parts)
    return hashlib.md5(combined.encode()).hexdigest()


def _cache_get(key: str):
    return _analysis_cache.get(key)


def _cache_set(key: str, value) -> None:
    """Store value; evict oldest entry when cache exceeds 500 items."""
    if len(_analysis_cache) >= 500:
        oldest = next(iter(_analysis_cache))
        del _analysis_cache[oldest]
    _analysis_cache[key] = value


def clear_analysis_cache() -> None:
    """Public helper — call from UI to reset the in-process cache."""
    _analysis_cache.clear()


# ── Prompt templates ──────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are an expert security researcher and professional bug bounty hunter. "
    "Write clear, accurate, and submission-ready vulnerability reports for platforms "
    "like HackerOne and Bugcrowd. Be technical but concise. Never add fluff."
)

_USER_PROMPT_TMPL = """\
Write a professional vulnerability report for the following finding.

Title       : {title}
Severity    : {severity}
Method      : {method}
Target URL  : {url}
Parameter   : {parameter}
Endpoint    : {endpoint}

Proof of Concept:
{poc}

Respond ONLY with a valid JSON object — no markdown fences, no extra commentary.
The JSON must have exactly these four string keys:
{{
  "description": "Precise technical description of the vulnerability and why it is exploitable.",
  "steps": "Numbered reproduction steps (e.g. 1. Log in\\n2. Navigate to ...\\n3. Observe ...).",
  "impact": "What an attacker can achieve; what data or systems are at risk.",
  "remediation": "Specific developer-facing fix recommendations."
}}
"""


def _build_user_prompt(report: dict) -> str:
    poc = (report.get("poc", "(none provided)") or "(none provided)")[:1500]
    url = (report.get("url", "") or "")[:200]
    return _USER_PROMPT_TMPL.format(
        title     = report.get("title",     "Untitled"),
        severity  = report.get("severity",  ""),
        method    = report.get("method",    ""),
        url       = url,
        parameter = report.get("parameter", ""),
        endpoint  = report.get("endpoint",  ""),
        poc       = poc,
    )


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _post_json(url: str, headers: dict, payload: dict, timeout: int = 120) -> dict:
    """Blocking POST → parse JSON response.
    On HTTP errors, reads the response body and raises a descriptive ValueError.
    """
    # Always include a User-Agent — Cloudflare (used by Groq, OpenRouter, etc.)
    # blocks requests with the default 'Python-urllib/3.x' agent (error 1010).
    merged_headers = {"User-Agent": "HuntGUI/1.0"}
    merged_headers.update(headers)
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(url, data=data, headers=merged_headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read().decode(errors="replace")
        except Exception:
            body = "(no body)"
        try:
            detail = json.loads(body)
            msg = (
                detail.get("error", {}).get("message")
                or detail.get("message")
                or body[:400]
            )
        except Exception:
            msg = body[:400]
        code  = exc.code
        url_s = exc.url or ""
        # --- Friendly messages for well-known HTTP errors ----------------------
        if code == 429:
            if "generativelanguage.googleapis.com" in url_s:
                raise ValueError(
                    "Gemini 429 — Rate limit reached.\n"
                    "Free tier limits: 15 req/min, 1,500 req/day for Gemini 2.0 Flash.\n"
                    "• Wait ~1 minute and retry\n"
                    "• Switch to gemini-2.0-flash-lite (higher free-tier limits)\n"
                    "• Or check https://ai.dev/rate-limit for your current usage\n\n"
                    f"API detail: {msg[:300]}"
                ) from exc
            if "api.groq.com" in url_s:
                raise ValueError(
                    "Groq 429 — Rate limit reached (free tier has per-minute/daily caps).\n"
                    "Wait a few seconds and retry, or switch to a different Groq model.\n\n"
                    f"API detail: {msg[:300]}"
                ) from exc
            if "openrouter.ai" in url_s:
                raise ValueError(
                    "OpenRouter 429 — Rate limit or credits exhausted.\n"
                    "Check your credits at https://openrouter.ai/settings/credits. "
                    "Switch to a :free model if you have no credits.\n\n"
                    f"API detail: {msg[:300]}"
                ) from exc
            raise ValueError(
                f"HTTP 429 — Rate limit exceeded.\nWait and retry, or switch to a different model.\n\n{msg[:300]}"
            ) from exc
        if code == 401:
            raise ValueError(
                f"HTTP 401 — Invalid or missing API key.\n"
                "Go to Edit → Tool Settings and check your API key under AI Settings.\n\n"
                f"Detail: {msg[:200]}"
            ) from exc
        if code == 403:
            raise ValueError(
                f"HTTP 403 — Access denied (Cloudflare block or insufficient permissions).\n"
                f"Detail: {msg[:200]}"
            ) from exc
        if code in (502, 503, 529):
            raise TimeoutError(
                f"HTTP {code} — AI provider temporarily unavailable (service overloaded).\n"
                "This is a transient server error — wait a moment and retry.\n\n"
                f"Detail: {msg[:200]}"
            ) from exc
        raise ValueError(f"HTTP {code} from {url_s}:\n{msg}") from exc
    except (socket.timeout, TimeoutError) as exc:
        raise TimeoutError(
            f"Request timed out after {timeout}s.\n"
            "The AI model is taking too long to respond.\n"
            "Try again, reduce request size, or switch to a faster model "
            "(e.g. gpt-4o-mini, claude-3-haiku, mistral:7b)."
        ) from exc
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, (socket.timeout, TimeoutError)) or "timed out" in str(reason).lower():
            raise TimeoutError(
                f"Request timed out after {timeout}s.\n"
                "The AI model is taking too long to respond.\n"
                "Try again, reduce request size, or switch to a faster model."
            ) from exc
        raise ConnectionError(f"Connection error: {reason}") from exc


def _post_json_with_retry(
    url: str,
    headers: dict,
    payload: dict,
    timeout: int = 120,
    retries: int = 2,
) -> dict:
    """
    Wrapper around _post_json that retries on TimeoutError with exponential backoff.
    Non-timeout errors (HTTP 4xx/5xx, connection refused) are NOT retried.
    """
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return _post_json(url, headers, payload, timeout)
        except TimeoutError as exc:
            # Covers real timeouts AND transient HTTP 502/503/529 (re-raised as TimeoutError)
            last_exc = exc
            if attempt < retries:
                wait = 2 ** attempt          # 1s, 2s, …
                time.sleep(wait)
        # ValueError (HTTP 4xx client errors) and ConnectionError bubble up immediately
    raise last_exc  # type: ignore[misc]


# ── Provider calls ────────────────────────────────────────────────────────────

def _call_gemini_native(api_key: str, model: str, messages: list, max_tokens: int = 4096) -> str:
    """
    Call the Gemini native generateContent API.
    Uses the same endpoint as the Google AI Studio / curl workflow, which has the correct
    free-tier quota (unlike the OpenAI-compat wrapper which uses a separate quota bucket).
    Converts OpenAI-format messages (role: system/user/assistant) to Gemini format.
    """
    system_parts: list = []
    contents:     list = []
    for m in messages:
        role = m.get("role", "user")
        text = m.get("content", "")
        if role == "system":
            system_parts.append({"text": text})
        else:
            g_role = "model" if role == "assistant" else "user"
            contents.append({"role": g_role, "parts": [{"text": text}]})
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload: dict = {
        "contents":         contents,
        "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.3},
    }
    if system_parts:
        payload["systemInstruction"] = {"parts": system_parts}
    resp = _post_json_with_retry(
        url,
        {"Content-Type": "application/json", "x-goog-api-key": api_key},
        payload,
    )
    return resp["candidates"][0]["content"]["parts"][0]["text"]


def _call_openai_compat(settings: dict, report: dict, provider: str) -> str:
    """Call any OpenAI-compatible API (OpenAI, Groq, OpenRouter) for report generation."""
    if provider == "gemini":
        api_key = _resolve_api_key(settings, "gemini")
        if not api_key:
            raise ValueError(
                "Gemini API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        model = _coerce_model("gemini", settings.get("ai_model", "").strip())
        msgs  = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_prompt(report)},
        ]
        return _call_gemini_native(api_key, model, msgs)
    api_key  = _resolve_api_key(settings, provider)
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["openai"])
    model    = settings.get("ai_model", "").strip() or defaults["model"]
    if provider == "openai":
        base_url = (settings.get("ai_base_url", "") or defaults["base_url"]).rstrip("/")
    else:
        base_url = defaults["base_url"].rstrip("/")

    if not api_key:
        raise ValueError(
            f"{provider.capitalize()} API key is not set.\n"
            "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
        )

    url     = f"{base_url}/v1/chat/completions"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"}
    is_reasoning = model.startswith(("o1", "o3"))
    if is_reasoning:
        payload = {
            "model": model, "max_completion_tokens": 2048,
            "messages": [{"role": "user", "content": f"{_SYSTEM_PROMPT}\n\n{_build_user_prompt(report)}"}],
        }
    else:
        payload = {
            "model": model, "max_tokens": 1024, "temperature": 0.3,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": _build_user_prompt(report)},
            ],
        }
    resp = _post_json_with_retry(url, headers, payload)
    return resp["choices"][0]["message"]["content"]


def _call_openai(settings: dict, report: dict) -> str:
    api_key  = _resolve_api_key(settings, "openai")
    model    = settings.get("ai_model", "").strip() or PROVIDER_DEFAULTS["openai"]["model"]
    base_url = (settings.get("ai_base_url", "") or PROVIDER_DEFAULTS["openai"]["base_url"]).rstrip("/")

    if not api_key:
        raise ValueError(
            "OpenAI API key is not set.\n"
            "Go to Edit → Tool Settings and enter your key under 'AI Settings'."
        )

    url     = f"{base_url}/v1/chat/completions"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    # o1 / o3 family: no temperature, no system role, use max_completion_tokens
    is_reasoning = model.startswith(("o1", "o3"))

    if is_reasoning:
        # reasoning models: system content injected as a user-prefixed message
        messages = [
            {"role": "user",
             "content": f"{_SYSTEM_PROMPT}\n\n{_build_user_prompt(report)}"},
        ]
        payload = {
            "model":                model,
            "max_completion_tokens": 2048,
            "messages":             messages,
        }
    else:
        payload = {
            "model":       model,
            "max_tokens":  1024,
            "temperature": 0.3,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user",   "content": _build_user_prompt(report)},
            ],
        }

    resp = _post_json_with_retry(url, headers, payload)
    return resp["choices"][0]["message"]["content"]


def _call_anthropic(settings: dict, report: dict) -> str:
    api_key = _resolve_api_key(settings, "anthropic")
    model   = settings.get("ai_model", "").strip() or PROVIDER_DEFAULTS["anthropic"]["model"]

    if not api_key:
        raise ValueError(
            "Anthropic API key is not set.\n"
            "Go to Edit → Tool Settings and enter your key under 'AI Settings'."
        )

    url     = "https://api.anthropic.com/v1/messages"
    headers = {
        "Content-Type":      "application/json",
        "x-api-key":         api_key,
        "anthropic-version": "2023-06-01",
    }
    payload = {
        "model":      model,
        "max_tokens": 1024,
        "system":     _SYSTEM_PROMPT,
        "messages":   [{"role": "user", "content": _build_user_prompt(report)}],
    }
    resp = _post_json_with_retry(url, headers, payload)
    return resp["content"][0]["text"]


def _call_ollama(settings: dict, report: dict) -> str:
    base_url = (settings.get("ai_base_url", "") or PROVIDER_DEFAULTS["ollama"]["base_url"]).rstrip("/")
    model    = settings.get("ai_model", "").strip() or PROVIDER_DEFAULTS["ollama"]["model"]

    # Use Ollama's OpenAI-compatible endpoint
    url     = f"{base_url}/v1/chat/completions"
    headers = {"Content-Type": "application/json"}
    payload = {
        "model":       model,
        "max_tokens":  1024,
        "temperature": 0.3,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user",   "content": _build_user_prompt(report)},
        ],
    }
    resp = _post_json_with_retry(url, headers, payload)
    return resp["choices"][0]["message"]["content"]


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report_fields(settings: dict, report: dict) -> dict:
    """
    Call the configured AI provider and return a dict with keys:
      description, steps, impact, remediation

    Raises ValueError or urllib.error.URLError on failure.
    """
    def _try_provider(s: dict) -> str:
        prov = s.get("ai_provider", "openai").lower()
        if prov == "anthropic":
            return _call_anthropic(s, report)
        elif prov == "ollama":
            return _call_ollama(s, report)
        elif prov in ("groq", "gemini", "openrouter"):
            return _call_openai_compat(s, report, prov)
        else:
            return _call_openai_compat(s, report, "openai")

    try:
        raw = _try_provider(settings)
    except Exception as primary_exc:
        sec_provider = settings.get("ai_secondary_provider", "")
        if sec_provider and sec_provider not in ("none", ""):
            sec_settings = {
                "ai_provider":      sec_provider,
                "ai_model":         settings.get("ai_secondary_model", ""),
                "ai_provider_keys": settings.get("ai_secondary_provider_keys", {}),
                "ai_api_key":       settings.get("ai_secondary_provider_keys", {}).get(sec_provider, ""),
                "ai_base_url":      settings.get("ai_base_url", ""),
            }
            raw = _try_provider(sec_settings)  # propagate if secondary also fails
        else:
            raise primary_exc

    # Strip markdown fences that some models add despite instructions
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"AI returned non-JSON output.\n\nRaw response:\n{raw[:600]}"
        ) from exc

    required = {"description", "steps", "impact", "remediation"}
    missing  = required - set(parsed.keys())
    if missing:
        raise ValueError(
            f"AI response is missing fields: {missing}\n\nRaw:\n{raw[:600]}"
        )

    return {k: str(parsed[k]) for k in ("description", "steps", "impact", "remediation")}


# ── QThread worker ────────────────────────────────────────────────────────────

class AIWorker(QThread):
    """Runs generate_report_fields() in a background thread, non-blocking."""

    finished = pyqtSignal(dict)  # emits parsed fields on success
    error    = pyqtSignal(str)   # emits error message on failure

    def __init__(self, settings: dict, report: dict, parent=None):
        super().__init__(parent)
        self._settings = settings
        self._report   = report

    def run(self):
        try:
            fields = generate_report_fields(self._settings, self._report)
            self.finished.emit(fields)
        except Exception as exc:
            self.error.emit(str(exc))


# ── Generic chat dispatch (traffic analysis & future features) ────────────────

def _dispatch_chat_primary(settings: dict, system: str, user: str, max_tokens: int = 2048) -> str:
    """Route a system+user prompt to the configured provider and return the reply text."""
    provider = settings.get("ai_provider", "openai").lower()
    model    = _coerce_model(provider, settings.get("ai_model", "").strip())

    if provider == "anthropic":
        api_key = _resolve_api_key(settings, "anthropic")
        if not api_key:
            raise ValueError(
                "Anthropic API key is not set.\n"
                "Go to Edit → Tool Settings and enter your key under 'AI Settings'."
            )
        resp = _post_json_with_retry(
            "https://api.anthropic.com/v1/messages",
            {"Content-Type": "application/json",
             "x-api-key": api_key,
             "anthropic-version": "2023-06-01"},
            {"model": model, "max_tokens": max_tokens,
             "system": system,
             "messages": [{"role": "user", "content": user}]},
        )
        return resp["content"][0]["text"]

    elif provider == "ollama":
        base_url = (settings.get("ai_base_url", "") or
                    PROVIDER_DEFAULTS["ollama"]["base_url"]).rstrip("/")
        resp = _post_json_with_retry(
            f"{base_url}/v1/chat/completions",
            {"Content-Type": "application/json"},
            {"model": model, "max_tokens": max_tokens, "temperature": 0.3,
             "messages": [{"role": "system", "content": system},
                          {"role": "user",   "content": user}]},
        )
        return resp["choices"][0]["message"]["content"]

    elif provider == "gemini":
        api_key = _resolve_api_key(settings, "gemini")
        if not api_key:
            raise ValueError(
                "Gemini API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        return _call_gemini_native(
            api_key, model,
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens,
        )

    elif provider in ("groq", "openrouter"):
        api_key = _resolve_api_key(settings, provider)
        if not api_key:
            raise ValueError(
                f"{provider.capitalize()} API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        base_url = PROVIDER_DEFAULTS[provider]["base_url"].rstrip("/")
        resp = _post_json_with_retry(
            f"{base_url}/v1/chat/completions",
            {"Content-Type": "application/json",
             "Authorization": f"Bearer {api_key}"},
            {"model": model, "max_tokens": max_tokens, "temperature": 0.3,
             "messages": [{"role": "system", "content": system},
                          {"role": "user",   "content": user}]},
        )
        return resp["choices"][0]["message"]["content"]

    else:  # openai (default)
        api_key = _resolve_api_key(settings, "openai")
        if not api_key:
            raise ValueError(
                "OpenAI API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        base_url = (settings.get("ai_base_url", "") or
                    PROVIDER_DEFAULTS["openai"]["base_url"]).rstrip("/")
        is_reasoning = model.startswith(("o1", "o3"))
        if is_reasoning:
            payload = {
                "model": model,
                "max_completion_tokens": max_tokens,
                "messages": [{"role": "user", "content": f"{system}\n\n{user}"}],
            }
        else:
            payload = {
                "model": model, "max_tokens": max_tokens, "temperature": 0.3,
                "messages": [{"role": "system", "content": system},
                             {"role": "user",   "content": user}],
            }
        resp = _post_json_with_retry(
            f"{base_url}/v1/chat/completions",
            {"Content-Type":  "application/json",
             "Authorization": f"Bearer {api_key}"},
            payload,
        )
        return resp["choices"][0]["message"]["content"]


def _dispatch_chat(settings: dict, system: str, user: str, max_tokens: int = 2048) -> str:
    """
    Public wrapper around _dispatch_chat_primary.
    On primary failure, automatically retries with the secondary provider
    (if configured via Tool Settings → Fallback AI Provider).
    """
    try:
        return _dispatch_chat_primary(settings, system, user, max_tokens)
    except Exception as primary_exc:
        sec_provider = settings.get("ai_secondary_provider", "")
        if sec_provider and sec_provider not in ("none", ""):
            sec_settings = {
                "ai_provider":      sec_provider,
                "ai_model":         settings.get("ai_secondary_model", ""),
                "ai_provider_keys": settings.get("ai_secondary_provider_keys", {}),
                "ai_api_key":       settings.get("ai_secondary_provider_keys", {}).get(sec_provider, ""),
                "ai_base_url":      settings.get("ai_base_url", ""),
            }
            try:
                return _dispatch_chat_primary(sec_settings, system, user, max_tokens)
            except Exception:
                pass  # fall through and raise the original error
        raise primary_exc


# ── Payload Context Suggester ─────────────────────────────────────────────────

_PAYLOAD_SUGGEST_SYSTEM = (
    "You are an elite offensive security researcher specializing in WAF bypass. "
    "Your ONLY output must be a raw JSON array of payload strings — nothing else. "
    "No prose, no markdown, no numbered lists, no mitigations, no explanations, "
    "no code blocks, no headers. Output ONLY the JSON array and nothing before or after it. "
    "Example of the ONLY acceptable output format: "
    '["payload1","payload2","payload3"]'
)

_PAYLOAD_SUGGEST_TMPL = """\
OUTPUT FORMAT: Respond ONLY with a valid JSON array of strings.
DO NOT include any explanation, prose, markdown, numbered lists, or text outside the array.
Example: ["<script>alert(1)</script>", "payload2"]

Generate targeted {scan_type} bypass payloads for this scan context.

Parameter Name : {param_name}
Current Value  : {current_value}
Scan Type      : {scan_type}
WAF/Filter     : {waf_fingerprint}

Response Snippet (last probe response, first 800 chars):
---
{response_snippet}
---

Based on the WAF/filter fingerprint and response snippet above, generate 10–15 highly \
targeted payloads with the best chance of bypassing the detected defenses and confirming \
a {scan_type} vulnerability.

Bypass focus:
- If the filter HTML-encodes < > : use event-handler / JS URI / CSS injection vectors
- If the filter strips keywords like "script": use alternative tags, obfuscated variants
- If the filter URL-encodes output: use double-encoding, Unicode normalization
- For SQLi: include encoding bypasses, alternative comment styles, inline comment tricks
- Include at least one time-based or out-of-band blind detection variant
- For XSS: if "DOM/JS Source Context" section is present above, analyze the listed sinks \
  (innerHTML, eval, location.href, etc.) and the reflected-in line to generate DOM-based \
  vectors that target those exact sinks. Prioritize DOM XSS over reflected XSS when DOM \
  sinks are visible.

OUTPUT REMINDER: Your entire response must be ONLY a JSON array. No text before or after.
Example: ["payload1","payload2","payload3"]
"""


# Characters that must appear in a valid injection payload
_PAYLOAD_INJECT_CHARS = frozenset('<>\'"`;(){}[]|&$\\%/')


def _clean_ai_payload(p: str) -> str:
    """
    Sanitise a single AI-generated payload string:
    - Strip leading numbered-list prefixes: "8. ", "12. ", etc.
    - Strip surrounding backtick markdown: `payload`
    - Remove embedded newlines / carriage returns (would break an HTTP request line)
    - Strip surrounding whitespace
    - Discard entries that are clearly prose, not payloads:
        * no injection characters AND length > 30  (explanatory sentences)
        * length > 350 (definitely not a single payload)
    Returns an empty string for discard; caller must filter these out.
    """
    p = p.strip()
    # Remove leading numbered list prefix (e.g. "8. ", "12. ")
    p = re.sub(r'^\d+\.\s*', '', p)
    # Strip surrounding backticks
    p = p.strip('`').strip()
    # Collapse / remove embedded newlines (protects HTTP request line integrity)
    p = re.sub(r'[\r\n]+', '', p)
    p = p.strip()
    # Discard if only whitespace or a lone list-number remnant
    if re.fullmatch(r'[\d\.\s]*', p):
        return ''
    # Hard cap — payloads are never this long
    if len(p) > 350:
        return ''
    # Prose filter: long string with no injection characters → explanatory text, not a payload
    if len(p) > 30 and not any(c in _PAYLOAD_INJECT_CHARS for c in p):
        return ''
    return p


def suggest_bypass_payloads(
    settings: dict,
    param_name: str,
    current_value: str,
    response_snippet: str,
    waf_fingerprint: str,
    scan_type: str = "XSS",
) -> list:
    """
    Ask the configured AI provider for targeted bypass payloads tailored to
    the probe response and WAF/filter fingerprint observed during scanning.

    Returns a list of payload strings.  Returns an empty list on any error
    (missing API key, network failure, malformed response, etc.) so callers
    can fall back to static wordlists gracefully.
    """
    user_prompt = _PAYLOAD_SUGGEST_TMPL.format(
        scan_type        = scan_type,
        param_name       = (param_name or "unknown")[:100],
        current_value    = (current_value or "")[:200],
        waf_fingerprint  = waf_fingerprint or "No filter detected — raw reflection",
        response_snippet = (response_snippet or "")[:800],
    )
    raw = _dispatch_chat(settings, _PAYLOAD_SUGGEST_SYSTEM, user_prompt, max_tokens=2048)

    # Strip optional markdown fences that some models add
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    # Locate a JSON array anywhere in the response (model may add preamble)
    start = raw.find("[")
    end   = raw.rfind("]") + 1
    if start != -1 and end > start:
        try:
            parsed = json.loads(raw[start:end])
            if isinstance(parsed, list):
                result = [_clean_ai_payload(str(p)) for p in parsed if str(p).strip()]
                result = [p for p in result if p]
                if result:
                    return result
        except Exception:
            pass  # fall through to regex extraction below

    # Fallback: regex-extract quoted strings — handles truncated JSON (no closing "]")
    # and JSON with minor escaping issues (e.g. unescaped backslashes from some models)
    search_from = raw[start:] if start != -1 else raw
    extracted = re.findall(r'"((?:[^"\\]|\\.)*)"', search_from)
    # Apply full cleaning + prose filter; require at least one injection character
    payloads = []
    for p in extracted:
        cleaned = _clean_ai_payload(p)
        if cleaned and any(c in _PAYLOAD_INJECT_CHARS for c in cleaned):
            payloads.append(cleaned)
    if payloads:
        return payloads

    raise ValueError(f"AI returned no usable payloads. Raw reply: {raw[:300]!r}")


# ── Traffic Analysis ───────────────────────────────────────────────────────────

_TRAFFIC_SYSTEM_PROMPT = (
    "You are an elite offensive security researcher, bug bounty hunter, and web application "
    "penetration tester. Analyze raw HTTP request/response pairs with the thoroughness of a "
    "manual tester: reason about context, cross-reference request and response fields together, "
    "and surface vulnerabilities that automated regex scanners cannot detect. "
    "Report only real, exploitable findings — never theoretical noise. Be precise and concise."
)

_TRAFFIC_USER_TMPL = """\
Perform a comprehensive security assessment of the following HTTP request/response pair.

=== REQUEST ===
{request}

=== RESPONSE ===
{response}

Check for ALL of the following vulnerability categories. For each finding reason about BOTH
the request AND the response together — many issues only become visible when cross-referenced.

1. Access Control & IDOR
   - Insecure Direct Object Reference: numeric/UUID IDs in URL, body, or headers that
     could reference another user’s resource; does the response return others’ data?
   - Horizontal/vertical privilege escalation: low-privilege token accessing admin endpoints
   - Broken function-level access control: sensitive actions (delete, admin, export) with
     inadequate authorization checks
   - Parameter tampering: role, is_admin, account_type fields in request body

2. Business Logic Flaws
   - Price/quantity manipulation: negative values, zero amounts, integer overflow
   - Workflow bypass: skipping payment, verification, or approval steps
   - Coupon / discount / referral abuse signals
   - Mass assignment: extra body fields reflected back in response with elevated privileges
   - Account takeover via logic: password reset token in response, predictable tokens

3. Injection Attacks (context-aware)
   - SQL Injection: error messages, timing hints, boolean differences in response
   - NoSQL Injection: $where, $gt, $regex operators in body; unexpected data returned
   - SSTI (Server-Side Template Injection): {{7*7}}, ${{7*7}} in any parameter
   - Command Injection: fields containing filenames, paths, or system command fragments
   - XSS (reflected/stored): user input mirrored in response body without encoding
   - XXE: XML Content-Type in request; error messages or file content in response
   - SSRF: URL/IP parameters; internal service responses, cloud metadata (169.254.169.254)
   - SSTI via redirect URLs or error messages embedding user input
   - Path Traversal: ../ sequences in file/path parameters; file content in response
   - LDAP / XPath injection in auth or search fields

4. Authentication & Session Flaws
   - Missing or weak authentication: 200 OK response with data to an unauthenticated request
   - JWT vulnerabilities:
     * alg:none attack: JWT with algorithm set to "none" accepted
     * Algorithm confusion (RS256 → HS256): HMAC signed with the RSA public key
     * Weak secret: short/dictionary secret detectable from a visible JWT payload
     * Expired tokens accepted; iat/exp not validated
     * Sensitive data in JWT payload (PII, role, internal paths)
   - Session fixation: session token unchanged after login
   - Insecure token in URL (Bearer token, API key, session ID as GET parameter)
   - Cookie security: missing HttpOnly, Secure, SameSite=None without __Host- prefix
   - Default or predictable credentials hinted by response content

5. CORS Misconfiguration
   - Access-Control-Allow-Origin reflecting arbitrary Origin header verbatim
   - Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true
   - Null origin accepted: ACAO: null
   - Overly broad wildcard subdomains (*.example.com) or trusted attacker-controllable origins
   - CORS headers present on sensitive endpoints (account, payment, admin)

6. Host Header Injection
   - Host header reflected in Location, Link, or body (password reset poisoning)
   - X-Forwarded-Host / X-Forwarded-For / Forwarded accepted and reflected
   - Ambiguous Host header (duplicate Host headers) causing routing manipulation
   - Virtual host routing bypass: accessing internal vhosts via Host header

7. HTTP Request Smuggling Signals
   - Inconsistent Content-Length vs Transfer-Encoding: chunked headers
   - Responses that include unexpected data prepended from a prior request
   - Chunked encoding with obfuscated TE header (Transfer-Encoding: xchunked, space, tab)

8. GraphQL-Specific
   - Introspection enabled: __schema or __type queries returning full schema
   - Batching attacks: array of multiple operations in single request
   - Field suggestions leaking schema ("Did you mean X?" in error messages)
   - Deeply nested queries without depth limiting (DoS signal)
   - Mutations performing sensitive operations without proper authorization
   - Verbose error messages exposing resolver internals or DB queries

9. File Upload Vulnerabilities
   - MIME type not validated: server accepts dangerous Content-Type (application/x-php, etc.)
   - Extension bypass: double extension (.php.jpg), null byte, Unicode tricks
   - Path traversal in filename: ../../etc/passwd in Content-Disposition filename
   - Stored XSS via SVG, HTML, or XML upload
   - Response reveals upload path (full filesystem path, predictable URL)

10. Information Disclosure
    - Stack traces, framework versions, DB query details, internal paths in response
    - Internal IP addresses, hostnames, AWS account IDs, ARNs
    - Verbose error messages differentiating between valid/invalid usernames (enumeration)
    - API keys, tokens, or secrets in response body or headers
    - Source maps (.map files) linked or returned
    - Git metadata exposed (X-Git-*, /.git/ response)

11. Security Header Weaknesses
    - Missing or misconfigured CSP: absent, unsafe-inline, unsafe-eval, wildcard *
    - Missing HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy
    - Server / X-Powered-By / X-AspNet-Version headers leaking technology
    - Cache-Control on responses containing sensitive data (no-store missing)

12. OAuth 2.0 / SSO Flaws
    - State parameter missing or static (CSRF on OAuth flow)
    - Redirect URI not strictly validated (open redirect in OAuth callback)
    - Authorization code reuse: code accepted more than once
    - Token leakage in Referer header or response body
    - Implicit flow returning access_token in URL fragment (logged in history)

13. Cache Poisoning / Cache Deception Signals
    - Unkeyed headers (X-Forwarded-Host, X-Original-URL) reflected in cacheable response
    - Cache headers (X-Cache: HIT) on personalized/sensitive responses
    - Path confusion: /account.css returning account page content
    - Vary header missing for user-specific responses

14. Rate Limiting / DoS Signals
    - No rate-limit headers (X-RateLimit-*, Retry-After) on authentication or OTP endpoints
    - No CAPTCHA or challenge on login/registration/password-reset
    - Regex or computation-heavy parameter (ReDoS signal)

For each finding:
- Give a confidence score 0-100
- Cite specific evidence from the request AND/OR response
- Suggest 2-4 concrete follow-up payloads or reproduction steps

Respond ONLY with a valid JSON array — no markdown fences, no extra commentary.
[
  {{
    "title": "Short vulnerability title",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": <integer 0-100>,
    "reasoning": "Specific evidence from the traffic that supports this finding.",
    "payloads": ["payload1", "payload2"]
  }}
]
If no findings are identified, return an empty array: []
"""


def analyze_traffic(settings: dict, request_text: str, response_text: str) -> list:
    """
    Send an HTTP request/response pair to the configured AI provider and return a list
    of security findings: [{"title", "severity", "confidence", "reasoning", "payloads"}, ...]
    Results are cached by content hash to avoid re-analyzing identical pairs.
    Raises ValueError or urllib.error.URLError on failure.
    """
    # Give the response more budget — it carries most of the exploitable signal
    req  = (request_text  or "(empty)").strip()[:2000]
    resp = (response_text or "(empty)").strip()[:6000]

    # Cache check — skip AI call if we've seen this exact pair before
    ck = _cache_key("traffic", req, resp)
    cached = _cache_get(ck)
    if cached is not None:
        return cached  # type: ignore[return-value]

    user = _TRAFFIC_USER_TMPL.format(request=req, response=resp)

    raw = _dispatch_chat(settings, _TRAFFIC_SYSTEM_PROMPT, user, max_tokens=4096)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"AI returned non-JSON output.\n\nRaw response:\n{raw[:600]}"
        ) from exc

    if not isinstance(parsed, list):
        raise ValueError(f"AI returned {type(parsed).__name__}, expected a JSON array")

    _cache_set(ck, parsed)
    return parsed


class AITrafficWorker(QThread):
    """Non-blocking worker for AI-assisted HTTP traffic analysis."""

    finished = pyqtSignal(list)  # list of finding dicts on success
    error    = pyqtSignal(str)   # error message string on failure

    def __init__(self, settings: dict, request_text: str, response_text: str, parent=None):
        super().__init__(parent)
        self._settings      = settings
        self._request_text  = request_text
        self._response_text = response_text

    def run(self):
        try:
            results = analyze_traffic(
                self._settings, self._request_text, self._response_text
            )
            self.finished.emit(results)
        except Exception as exc:
            self.error.emit(str(exc))


# ── Source Code Security Review ─────────────────────────────────────────────────

_CODE_REVIEW_SYSTEM_PROMPT = (
    "You are an elite application security engineer, penetration tester, and manual code reviewer "
    "specializing in web and JavaScript security. Analyze source code with the depth of a thorough "
    "manual pentest and bug bounty review. Report only real, exploitable issues — never theoretical "
    "noise. Always cite the exact vulnerable code snippet as evidence."
)

_CODE_REVIEW_USER_TMPL = """\
Perform a comprehensive security code review on the following web page source code.

URL: {url}

=== SOURCE CODE ===
{source}

Analyze for ALL of the following vulnerability categories:

1. DOM-Based Vulnerabilities
   - DOM XSS: sources (location.hash, location.search, location.href, document.URL,
     document.referrer, document.cookie, window.name, URLSearchParams.get(),
     postMessage event.data) flowing into sinks (innerHTML, outerHTML, document.write,
     document.writeln, insertAdjacentHTML, eval(), new Function(), setTimeout(string),
     setInterval(string), location.href=, location.replace(), location.assign(),
     element.src=, element.href=, element.action=, jQuery.html(), $.globalEval(),
     angular expressions $compile/$eval with user input)
   - DOM Clobbering: id/name HTML attributes that shadow window or document globals
     used in JS (e.g., <a id=x href=...> clobbering window.x)
   - Prototype Pollution: merge / clone / extend / deepCopy / assign / defaults /
     setDefaults functions accepting user-controlled keys (__proto__, constructor,
     prototype); also look for lodash _.merge, jQuery.extend(true,...)
   - Open Redirect (client-side): location.href = param, window.open(param),
     history.pushState/replaceState with external input, meta refresh with user data
   - DOM-based CSRF: form action or fetch/XHR target built from user-controlled input
   - AngularJS sandbox escape: ng-app with user-controlled expressions,
     {{{{constructor.constructor(\\'alert(1)\\')()}}}}

2. Sensitive Data Exposure in Source
   - Hardcoded API keys, access tokens, OAuth client_secret, private keys (RSA/EC PEM)
   - Hardcoded credentials (username, password, connection strings)
   - Internal hostnames, staging/dev endpoints, private RFC-1918 IP addresses
   - JWT tokens, Bearer tokens, session cookies, CSRF tokens hardcoded in JS
   - Cloud provider credentials: AWS (AKIA...), GCP service account JSON fragments,
     Azure SAS tokens, Stripe sk_live_, Twilio AuthToken, SendGrid SG., GitHub tokens
   - Database connection strings (mongodb://, postgres://, mysql://)
   - Encryption keys, salts, or IVs hardcoded in source

3. Dangerous JavaScript Patterns
   - eval() / new Function(userInput) / setTimeout(userInput) / setInterval(userInput)
   - postMessage handlers that do not validate event.origin strictly
     (trusting substring match, endsWith, or no check at all)
   - JSONP endpoints: injecting script tags whose callback is user-controlled
   - document.domain relaxation allowing cross-subdomain attacks
   - Insecure deserialization: JSON.parse(userInput) result used in dangerous sinks
   - dangerouslySetInnerHTML={{{{}}}} (JSX double-brace) in React with non-sanitized data
   - v-html directive in Vue with external data
   - innerHTML += userInput without sanitization
   - WebSocket message handlers that trust message.data without validation
   - Service Worker fetch handlers with unvalidated URL patterns

4. Client-Side Logic & Access Control Flaws
   - Authorization or role checks enforced only in JavaScript (if(user.role==='admin'))
   - Payment / pricing / quota logic enforced only on the client
   - Feature flags or A/B test conditions that unlock hidden functionality client-side
   - Hidden admin / debug / internal endpoints discoverable from minified JS or comments
   - Debug mode flags (debug=true, verbose=true, isDev) active in production builds
   - Commented-out code revealing internal paths, credentials, or architectural details
   - Anti-automation bypass: CAPTCHA bypassed via JS flag or disabled in a parameter

5. Insecure Client-Side Storage
   - Passwords, tokens, PII, session data stored in localStorage or sessionStorage
   - Sensitive data in IndexedDB without encryption
   - Sensitive data written to window.* globals accessible by injected scripts
   - Sensitive data in URL hash (leaked in Referer / access logs)

6. Content Security Policy (CSP) Weaknesses
   - CSP absent entirely
   - unsafe-inline in script-src (nullifies XSS protection)
   - unsafe-eval in script-src
   - Wildcard (*) in script-src, object-src, or base-uri
   - Trusted but bypassable origins in script-src: CDNs with JSONP endpoints
     (e.g., accounts.google.com, ajax.googleapis.com, cdn.jsdelivr.net)
   - base-uri not restricted (allows base-tag injection to hijack relative URLs)
   - Missing object-src 'none' (allows Flash/plugin injection)
   - report-uri vs report-to only (reporting not blocking)
   - Nonce or hash values exposed in source that can be reused

7. Subresource Integrity (SRI) & Supply Chain
   - External scripts/stylesheets (CDN) loaded without integrity= and crossorigin= attributes
   - Dynamic script injection without integrity check
   - Dependency confusion: internal package names referenced from public CDNs

8. CSRF & Same-Origin Weaknesses
   - CSRF token absent on state-changing forms or fetch/XHR calls
   - CSRF token visible in URL, page source, or JS variable
   - SameSite cookie attribute not set (inferred from Set-Cookie in inline JS)
   - Custom CSRF header (X-Requested-With) as sole CSRF defence
   - CORS fetch with credentials:include to a wildcard or reflected origin

9. Clickjacking & UI Redressing
   - Missing X-Frame-Options or CSP frame-ancestors directive
   - Sensitive forms (login, payment, settings) embeddable in iframes
   - Overlay / cursor tricks possible via CSS if framing is allowed

10. Server-Side Template Injection Signals in HTML
    - Template delimiters echoed into HTML: {{{{, }}}}, <%, %>, #{{, ${{, {{#, {{/
    - Error pages showing template engine names (Jinja2, Twig, Freemarker, Velocity)
    - Reflected math expressions (e.g., 7*7=49 when input was 7*7)

11. Vulnerable or Outdated Libraries
    - jQuery < 3.5.0 (XSS in .html()/.append())
    - AngularJS 1.x any version (sandbox escapes, widespread EOL)
    - Bootstrap < 3.4.1 / < 4.3.1 (XSS in data-* attributes)
    - Lodash < 4.17.21 (prototype pollution)
    - Moment.js (unmaintained; ReDoS in certain locales)
    - marked.js < 4.0.10, DOMPurify < 2.3.6, handlebars < 4.7.7
    - Any library with a pinned version matching a known CVE

12. Mixed Content & Protocol Downgrade
    - HTTPS page loading resources over HTTP (images, scripts, iframes)
    - WebSocket connections over ws:// on an HTTPS page
    - HTTP URLs in form action on an HTTPS page

For each finding:
- Quote the exact vulnerable code as \"evidence\" (verbatim, max 250 chars)
- Give a confidence score 0-100
- Explain why it is exploitable and what the impact is
- Suggest 2-3 concrete payloads or PoC reproduction steps

Respond ONLY with a valid JSON array — no markdown fences, no extra commentary.
[
  {{
    \"title\": \"Short vulnerability title\",
    \"severity\": \"CRITICAL|HIGH|MEDIUM|LOW|INFO\",
    \"confidence\": <integer 0-100>,
    \"category\": \"DOM XSS|Hardcoded Secret|Prototype Pollution|CSP Bypass|...\",
    \"evidence\": \"Exact vulnerable code snippet quoted verbatim.\",
    \"reasoning\": \"Why this is exploitable and what the impact is.\",
    \"payloads\": [\"payload or PoC step 1\", \"payload or PoC step 2\"]
  }}
]
If no findings are identified, return an empty array: []
"""


def analyze_source_code(settings: dict, source_text: str, url: str = "") -> list:
    """
    Send HTML/JS source code to the configured AI for a full security code review.
    Returns a list of findings: [{"title", "severity", "confidence", "category",
    "evidence", "reasoning", "payloads"}, ...]
    Results are cached by content hash to avoid re-analyzing identical source.
    Raises ValueError or urllib.error.URLError on failure.
    """
    source = (source_text or "(empty)").strip()[:8000]   # larger cap — source code needs it

    # Cache check
    ck = _cache_key("source", url or "", source)
    cached = _cache_get(ck)
    if cached is not None:
        return cached  # type: ignore[return-value]

    user = _CODE_REVIEW_USER_TMPL.format(url=url or "(unknown)", source=source)

    raw = _dispatch_chat(settings, _CODE_REVIEW_SYSTEM_PROMPT, user, max_tokens=4096)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
    if raw.endswith("```"):
        raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"AI returned non-JSON output.\n\nRaw response:\n{raw[:600]}"
        ) from exc

    if not isinstance(parsed, list):
        raise ValueError(f"AI returned {type(parsed).__name__}, expected a JSON array")

    _cache_set(ck, parsed)
    return parsed


class AISourceCodeWorker(QThread):
    """Non-blocking worker for AI-assisted HTML/JS source code security review."""

    finished = pyqtSignal(list)   # list of finding dicts on success
    error    = pyqtSignal(str)    # error message string on failure

    def __init__(self, settings: dict, source_text: str, url: str = "", parent=None):
        super().__init__(parent)
        self._settings    = settings
        self._source_text = source_text
        self._url         = url

    def run(self):
        try:
            results = analyze_source_code(self._settings, self._source_text, self._url)
            self.finished.emit(results)
        except Exception as exc:
            self.error.emit(str(exc))


# ── General-purpose security assistant (free-form chat, no traffic context) ──

_GENERAL_CHAT_SYSTEM = (
    "Your name is Hunt Assistant — an elite AI security co-pilot embedded inside a professional "
    "web application pentesting and bug bounty hunting tool. "
    "The person you are talking to is an experienced web application pentester and bug bounty hunter. "
    "Your mission is to actively help them discover, exploit, and report vulnerabilities in web applications. "
    "You assist with: vulnerability detection & exploitation (XSS, SQLi, SSRF, IDOR, LFI, RCE, "
    "XXE, CORS, Open Redirect, SSTI, etc.), payload crafting, PoC development, HTTP traffic analysis, "
    "JavaScript source review, authentication/authorization bypass, bug bounty report writing, "
    "CVE research, and pentest methodology. "
    "Always be concise, precise, and deeply technical. "
    "Use Markdown: ## headings, **bold**, `inline code`, ```code blocks```. "
    "Never add unnecessary disclaimers — the user is a professional and has authorization."
)


# ── Multi-turn AI Security Chat ────────────────────────────────────────────────

_AI_CHAT_SYSTEM_TMPL = """\
Your name is Hunt Assistant \u2014 an elite AI security co-pilot embedded inside a professional \
web application pentesting and bug bounty hunting tool. \
The person you are talking to is an experienced web application pentester and bug bounty hunter, \
and your mission is to help them find, exploit, and report vulnerabilities.

You have been given the following HTTP traffic and page source code for security review:

URL: {url}

=== HTTP REQUEST ===
{request}

=== HTTP RESPONSE ===
{response}

=== PAGE SOURCE (HTML/JS — for client-side security analysis) ===
{source}

Your behaviour:
- Provide technically precise, actionable security assessments
- Use Markdown: ## headings, **bold**, `inline code`, ```code blocks```
- Reference specific lines, headers, parameters, or code from the traffic above
- On follow-up questions, answer concisely referencing the context above
- Suggest concrete payloads, PoC reproduction steps, and remediation advice
- Never fabricate vulnerabilities; only report what is evidenced in the data above
"""


def _chat_completion_with_settings(settings: dict, messages: list, max_tokens: int = 4096) -> str:
    """Route a multi-turn messages list to the configured provider and return the reply."""
    provider = settings.get("ai_provider", "openai").lower()
    model    = _coerce_model(provider, settings.get("ai_model", "").strip())

    if provider == "ollama":
        base_url = (settings.get("ai_base_url", "") or
                    PROVIDER_DEFAULTS["ollama"]["base_url"]).rstrip("/")
        resp = _post_json_with_retry(
            f"{base_url}/api/chat",
            {"Content-Type": "application/json"},
            {"model": model, "messages": messages, "stream": False},
        )
        return resp["message"]["content"]

    elif provider == "anthropic":
        api_key = _resolve_api_key(settings, "anthropic")
        if not api_key:
            raise ValueError(
                "Anthropic API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        base_url = (settings.get("ai_base_url", "") or
                    PROVIDER_DEFAULTS["anthropic"]["base_url"]).rstrip("/")
        system_content = ""
        conv = []
        for m in messages:
            if m["role"] == "system":
                system_content = m["content"]
            else:
                conv.append({"role": m["role"], "content": m["content"]})
        payload = {
            "model": model, "max_tokens": max_tokens, "temperature": 0.3,
            "messages": conv,
        }
        if system_content:
            payload["system"] = system_content
        resp = _post_json_with_retry(
            f"{base_url}/v1/messages",
            {"Content-Type": "application/json",
             "x-api-key": api_key,
             "anthropic-version": "2023-06-01"},
            payload,
        )
        return resp["content"][0]["text"]

    elif provider == "gemini":
        api_key = _resolve_api_key(settings, "gemini")
        if not api_key:
            raise ValueError(
                "Gemini API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        return _call_gemini_native(api_key, model, messages, max_tokens)

    elif provider in ("groq", "openrouter"):
        api_key = _resolve_api_key(settings, provider)
        if not api_key:
            raise ValueError(
                f"{provider.capitalize()} API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        base_url = PROVIDER_DEFAULTS[provider]["base_url"].rstrip("/")
        resp = _post_json_with_retry(
            f"{base_url}/v1/chat/completions",
            {"Content-Type": "application/json",
             "Authorization": f"Bearer {api_key}"},
            {"model": model, "max_tokens": max_tokens, "temperature": 0.3,
             "messages": messages},
        )
        return resp["choices"][0]["message"]["content"]

    else:  # openai (default)
        api_key = _resolve_api_key(settings, "openai")
        if not api_key:
            raise ValueError(
                "OpenAI API key is not set.\n"
                "Go to Edit \u2192 Tool Settings and enter your key under \u2018AI Settings\u2019."
            )
        base_url = (settings.get("ai_base_url", "") or
                    PROVIDER_DEFAULTS["openai"]["base_url"]).rstrip("/")
        is_reasoning = model.startswith(("o1", "o3"))
        if is_reasoning:
            merged = "\n\n".join(m["content"] for m in messages)
            payload = {
                "model": model,
                "max_completion_tokens": max_tokens,
                "messages": [{"role": "user", "content": merged}],
            }
        else:
            payload = {
                "model": model, "max_tokens": max_tokens, "temperature": 0.3,
                "messages": messages,
            }
        resp = _post_json_with_retry(
            f"{base_url}/v1/chat/completions",
            {"Content-Type":  "application/json",
             "Authorization": f"Bearer {api_key}"},
            payload,
        )
        return resp["choices"][0]["message"]["content"]


def chat_completion(settings: dict, messages: list) -> str:
    """
    Multi-turn chat completion using the configured AI provider.
    messages = [{"role": "system"|"user"|"assistant", "content": "..."}, ...]
    Returns the AI's reply as a plain string.

    Automatically falls back to the secondary provider if the primary fails.
    """
    try:
        return _chat_completion_with_settings(settings, messages)
    except Exception as primary_exc:
        sec_provider = settings.get("ai_secondary_provider", "")
        if sec_provider and sec_provider not in ("none", ""):
            sec_settings = {
                "ai_provider":      sec_provider,
                "ai_model":         settings.get("ai_secondary_model", ""),
                "ai_provider_keys": settings.get("ai_secondary_provider_keys", {}),
                "ai_api_key":       settings.get("ai_secondary_provider_keys", {}).get(sec_provider, ""),
                "ai_base_url":      settings.get("ai_base_url", ""),
            }
            try:
                return _chat_completion_with_settings(sec_settings, messages)
            except Exception:
                pass  # fall through and raise original error
        raise primary_exc


class AIChatWorker(QThread):
    """Non-blocking worker for multi-turn AI security chat."""

    finished = pyqtSignal(str)   # AI's reply as plain text
    error    = pyqtSignal(str)   # error message string

    def __init__(self, settings: dict, messages: list, parent=None):
        super().__init__(parent)
        self._settings = settings
        self._messages = messages

    def run(self):
        try:
            reply = chat_completion(self._settings, self._messages)
            self.finished.emit(reply)
        except Exception as exc:
            self.error.emit(str(exc))