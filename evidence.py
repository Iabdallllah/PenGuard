"""Structured, redacted evidence for findings.

Evidence is an audit artifact, not a log dump. It records what was sent, what
came back, how confident the detector is, and what could change that judgment.
Secrets are redacted before persistence and before rendering into PDF/SARIF.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional


REDACTED = "[REDACTED]"
BODY_EXCERPT_CHARS = 2000

SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
})

SENSITIVE_PARAMS = frozenset({
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "password",
    "passwd",
    "pwd",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "cookie",
    "csrf",
    "xsrf",
})

_QUERY_SECRET_RE = re.compile(
    r"([?&](?:" + "|".join(sorted(re.escape(p) for p in SENSITIVE_PARAMS)) + r")=)([^&#\s]*)",
    re.IGNORECASE,
)
_USERINFO_RE = re.compile(r"(//)([^/@\s]+)@")
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_RE = re.compile(r"(?i)\b(basic\s+)[A-Za-z0-9+/=]{6,}")
_HEADER_LINE_RE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*).+$"
)
_JSON_SECRET_RE = re.compile(
    r"""(?ix)
    ("?(?:secret(?:_token)?|secret_key|password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|token|client[_-]?secret)"?\s*[:=]\s*)
    ("?)([^\s",;}]+)
    """
)
_HEADER_VALUE_RE = re.compile(
    r"(?i)\b(?:authorization|cookie|set-cookie|x-api-key)\s*[:=]\s*[^\s,;]+"
)


def redact_url(url: Optional[str]) -> str:
    raw = str(url or "")
    if not raw:
        return ""
    raw = _USERINFO_RE.sub(r"\1" + REDACTED + "@", raw)
    raw = _QUERY_SECRET_RE.sub(lambda m: m.group(1) + REDACTED, raw)
    return raw


def redact_text(value: Any, limit: Optional[int] = None) -> str:
    text = "" if value is None else str(value)
    text = _BEARER_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _BASIC_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _HEADER_LINE_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _HEADER_VALUE_RE.sub(REDACTED, text)
    text = _QUERY_SECRET_RE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _JSON_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)
    if limit is not None and limit >= 0:
        text = text[:limit]
    return text


def redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for index, (name, value) in enumerate(headers.items()):
        if index >= 40:
            break
        key = str(name)
        if key.lower() in SENSITIVE_HEADERS:
            out[key] = REDACTED
        else:
            out[key] = redact_text(value, limit=300)
    return out


def body_sha256(body: Optional[str]) -> Optional[str]:
    if body is None:
        return None
    return hashlib.sha256(str(body).encode("utf-8", errors="replace")).hexdigest()


def _confidence(detection: Dict[str, Any]) -> Optional[float]:
    raw = detection.get("confidence_score")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if 0.0 <= value <= 1.0 else None


def _reproduction(method: str, url: str, payload: str) -> str:
    safe_url = redact_url(url)
    if method.upper() == "POST" and payload:
        return f"curl -X POST {safe_url} -H 'Content-Type: application/json' -d '{redact_text(payload)}'"
    return f"curl -X {method.upper() or 'GET'} {safe_url}"


def build_evidence(state: Dict[str, Any]) -> Dict[str, Any]:
    """Build the persisted evidence pack from one pipeline state/record."""
    attack_plan = state.get("attack_plan") or {}
    detection = state.get("detection_report") or {}
    method = str(attack_plan.get("http_method") or state.get("http_method") or "GET").upper()
    url = str(attack_plan.get("target_endpoint") or state.get("target") or "")
    payload = str(attack_plan.get("payload_json") or "")
    body = str(state.get("response_body") or "")
    status = state.get("http_status")
    headers = state.get("response_headers")
    request_headers = state.get("request_headers")
    latency = state.get("probe_latency_ms") or state.get("duration_ms")

    detection_text = redact_text(detection.get("technical_findings") or "", limit=1200)
    confidence = _confidence(detection)
    retest_status = state.get("retest_status")
    retest_body = state.get("retest_response_body")
    retest_headers = state.get("retest_response_headers")

    evidence: Dict[str, Any] = {
        "schema_version": 1,
        "request": {
            "method": method,
            "url": redact_url(url),
            "headers": redact_headers(request_headers),
            "payload": redact_text(payload, limit=2000),
            "reproduction": _reproduction(method, url, payload),
        },
        "response": {
            "status": status,
            "headers": redact_headers(headers if isinstance(headers, dict) else {}),
            "body_excerpt": redact_text(body, limit=BODY_EXCERPT_CHARS),
            "body_sha256": body_sha256(body),
            "body_length": len(body),
            "latency_ms": latency,
        },
        "confidence": confidence,
        "confidence_source": detection.get("confidence_source") or "unknown",
        "confidence_rationale": detection_text or "No detection rationale was recorded.",
        "assumptions": [
            "The probe was executed without operator-supplied credentials.",
            "The captured response is the target's response at the recorded timestamp.",
        ],
        "counterevidence": (
            detection_text
            if not detection.get("threat_detected")
            else "No counterevidence was observed in this single probe; absence of an upstream WAF cannot be inferred."
        ),
        "severity_change_conditions": (
            "Re-score if the endpoint requires authenticated authorization, "
            "if the exposed data is non-sensitive, or if an upstream control blocks the payload."
        ),
        "limitations": [
            "Single-shot probe; stateful or multi-step exploitation is not represented.",
            "Edge/WAF behavior may differ from the sandbox at the recorded time.",
        ],
        "redaction": {
            "headers": sorted(SENSITIVE_HEADERS),
            "body_and_query": True,
        },
        "complete": bool(status not in (None, 0) and body and detection),
    }

    if retest_status is not None:
        retest_body_text = str(retest_body or "")
        evidence["retest"] = {
            "status": retest_status,
            "headers": redact_headers(retest_headers if isinstance(retest_headers, dict) else {}),
            "body_excerpt": redact_text(retest_body_text, limit=BODY_EXCERPT_CHARS),
            "body_sha256": body_sha256(retest_body_text),
            "outcome": "blocked" if retest_status in (400, 401, 403) else "not_blocked",
            "patch_applied": bool(state.get("patch_applied")),
        }
    return evidence


def find_secret_leaks(texts: Iterable[str], secrets: Iterable[str]) -> List[str]:
    """Test helper: return any supplied secret still present in rendered text."""
    haystack = "\n".join(str(t or "") for t in texts)
    return [secret for secret in secrets if secret and secret in haystack]
