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


def _as_status(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _response_delta(
    baseline_status: Optional[int],
    baseline_body: Optional[str],
    exploit_status: Optional[int],
    exploit_body: Optional[str],
) -> str:
    if baseline_status is None or exploit_status is None:
        return "not_observable"
    if baseline_status != exploit_status:
        return "status_changed"
    if body_sha256(baseline_body) != body_sha256(exploit_body):
        return "body_changed"
    return "none"


def _differential_analysis(state: Dict[str, Any], detection: Dict[str, Any]) -> Dict[str, Any]:
    """Compare benign baseline, exploit, and post-patch re-test probes.

    Causality is only asserted when the exploit produced a byte-level response
    delta against a successful benign baseline. Identical responses are
    reported as unconfirmed — never as a fabricated zero-false-positive claim.
    """
    baseline_status = _as_status(state.get("baseline_status"))
    exploit_status = _as_status(state.get("http_status"))
    retest_status = _as_status(state.get("retest_status"))
    baseline_body = str(state.get("baseline_response_body") or "")
    exploit_body = str(state.get("response_body") or "")
    retest_body = str(state.get("retest_response_body") or "")

    baseline_to_exploit = _response_delta(
        baseline_status, baseline_body, exploit_status, exploit_body
    )
    if retest_status is None:
        exploit_to_retest = "not_retested"
    elif retest_status in (400, 401, 403) and exploit_status not in (400, 401, 403):
        exploit_to_retest = "blocked"
    elif (
        retest_status == exploit_status
        and body_sha256(retest_body) == body_sha256(exploit_body)
    ):
        exploit_to_retest = "unchanged"
    else:
        exploit_to_retest = "changed"

    baseline_valid = baseline_status is not None and 200 <= baseline_status < 300
    exploit_reached = exploit_status is not None and 200 <= exploit_status < 300
    observed_delta = baseline_to_exploit in ("status_changed", "body_changed")
    causality_confirmed = bool(
        detection.get("threat_detected") and baseline_valid and exploit_reached and observed_delta
    )
    retest_blocked = retest_status in (400, 401, 403)

    if baseline_status is None or exploit_status is None:
        interpretation = (
            "Baseline or exploit probe is missing; causality cannot be established."
        )
    elif causality_confirmed:
        interpretation = (
            "Exploit-only behavior delta observed against a successful benign baseline; "
            "responses differ deterministically (status or SHA-256 body hash)."
        )
        if retest_blocked:
            interpretation += f" Post-patch re-test was blocked with HTTP {retest_status}."
        elif retest_status is not None:
            interpretation += f" Post-patch re-test returned HTTP {retest_status} (not blocked)."
    else:
        interpretation = (
            "Baseline and exploit responses are indistinguishable or the baseline was "
            "not successful; causality is unconfirmed and no zero-false-positive claim is made."
        )

    return {
        "baseline_status": baseline_status,
        "exploit_status": exploit_status,
        "retest_status": retest_status,
        "behavior_delta": baseline_to_exploit,
        "exploit_to_retest": exploit_to_retest,
        "causality_confirmed": causality_confirmed,
        "zero_false_positive": causality_confirmed,
        "false_positive_risk": "low" if causality_confirmed else "unconfirmed",
        "mitigation_verified": bool(causality_confirmed and retest_blocked),
        "baseline_response_sha256": body_sha256(baseline_body),
        "exploit_response_sha256": body_sha256(exploit_body),
        "retest_response_sha256": body_sha256(retest_body) if retest_status is not None else None,
        "interpretation": interpretation,
    }


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
    retest_latency = state.get("retest_latency_ms")
    baseline_request = state.get("baseline_request") or {}
    baseline_status = state.get("baseline_status")
    baseline_body = str(state.get("baseline_response_body") or "")
    baseline_headers = state.get("baseline_response_headers")
    baseline_latency = state.get("baseline_latency_ms")
    skill_playbook = state.get("skill_playbook") or attack_plan.get("skill_playbook")
    remediation_metadata = state.get("remediation_metadata")

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
        "baseline": {
            "request": {
                "method": str(baseline_request.get("http_method") or "GET").upper(),
                "url": redact_url(str(baseline_request.get("target_endpoint") or "")),
                "payload": redact_text(baseline_request.get("payload_json") or "", limit=2000),
            },
            "status": baseline_status,
            "headers": redact_headers(
                baseline_headers if isinstance(baseline_headers, dict) else {}
            ),
            "body_excerpt": redact_text(baseline_body, limit=BODY_EXCERPT_CHARS),
            "body_sha256": body_sha256(baseline_body) if baseline_status is not None else None,
            "body_length": len(baseline_body),
            "latency_ms": baseline_latency,
            "outcome": (
                "control"
                if isinstance(baseline_status, int) and 200 <= baseline_status < 300
                else "baseline_failed"
            ),
        },
        "differential_analysis": _differential_analysis(state, detection),
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
            "body_length": len(retest_body_text),
            "latency_ms": retest_latency,
            "outcome": "blocked" if retest_status in (400, 401, 403) else "not_blocked",
            "patch_applied": bool(state.get("patch_applied")),
        }
    if skill_playbook:
        evidence["skill_playbook"] = skill_playbook
    if remediation_metadata:
        evidence["remediation"] = remediation_metadata
    return evidence


def find_secret_leaks(texts: Iterable[str], secrets: Iterable[str]) -> List[str]:
    """Test helper: return any supplied secret still present in rendered text."""
    haystack = "\n".join(str(t or "") for t in texts)
    return [secret for secret in secrets if secret and secret in haystack]
