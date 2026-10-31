"""Security outcome, finding identity, dedupe, and coverage primitives.

This module is intentionally dependency-light so the API, orchestrator, report
generators, and tests all use one definition of truth.

Separation of concerns:
  * An *episode* is one immutable attempt (one dispatch of the pipeline).
  * A *finding* is the current state of one unique weakness. Repeated attempts
    update it; they never create a second posture deduction.
  * *Coverage* is the negative space: which vectors were tested, and how each
    attempt closed.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit


# ── Outcome vocabulary ──────────────────────────────────────────────────────
OUTCOME_CLEAN = "clean"
OUTCOME_MITIGATED = "mitigated"
OUTCOME_UNPATCHED = "unpatched"
OUTCOME_INCONCLUSIVE = "inconclusive"
OUTCOME_INTERRUPTED = "interrupted"
OUTCOME_BUDGET_LIMITED = "budget_limited"

ALL_OUTCOMES = (
    OUTCOME_CLEAN,
    OUTCOME_MITIGATED,
    OUTCOME_UNPATCHED,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_INTERRUPTED,
    OUTCOME_BUDGET_LIMITED,
)

CONCLUSIVE_OUTCOMES = frozenset({OUTCOME_CLEAN, OUTCOME_MITIGATED, OUTCOME_UNPATCHED})
THREAT_OUTCOMES = frozenset({OUTCOME_UNPATCHED, OUTCOME_MITIGATED})
PATCH_BLOCK_CODES = frozenset({400, 401, 403})

# Canonical eight-vector order used by the API, dashboard, PDF, and SARIF.
VECTOR_KEYS: Tuple[str, ...] = (
    "idor",
    "sql_injection",
    "business_logic",
    "xss",
    "csrf",
    "ssrf",
    "broken_auth",
    "misconfig",
)

_SCENARIO_ALIASES = {
    "idor": "idor",
    "sql injection": "sql_injection",
    "sql_injection": "sql_injection",
    "sqli": "sql_injection",
    "business logic abuse": "business_logic",
    "business_logic_abuse": "business_logic",
    "business_logic": "business_logic",
    "xss": "xss",
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
    "csrf": "csrf",
    "cross site request forgery": "csrf",
    "cross-site request forgery": "csrf",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "server-side request forgery": "ssrf",
    "broken authentication": "broken_auth",
    "broken_auth": "broken_auth",
    "security misconfiguration": "misconfig",
    "misconfiguration": "misconfig",
    "misconfig": "misconfig",
}

_DEFAULT_METHODS = {
    "business_logic": "POST",
    "csrf": "POST",
    "broken_auth": "POST",
}

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_ID_RE = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_scenario(value: Optional[str]) -> str:
    """Normalize a scenario label/key to one of ``VECTOR_KEYS``.

    Unknown values are returned as a lower-case slug rather than silently
    mapped onto IDOR; honesty matters more than a convenient default.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    key = raw.lower().replace("-", " ").strip()
    if key in _SCENARIO_ALIASES:
        return _SCENARIO_ALIASES[key]
    slug = re.sub(r"[^a-z0-9]+", "_", raw.lower()).strip("_")
    return _SCENARIO_ALIASES.get(slug, slug)


def default_method(scenario: str) -> str:
    return _DEFAULT_METHODS.get(normalize_scenario(scenario), "GET")


def _safe_port(parsed) -> Optional[int]:
    try:
        return parsed.port
    except ValueError:
        return None


def normalize_path(path: Optional[str]) -> str:
    """Normalize a URL path for stable finding identity.

    Numeric object identifiers and UUIDs are placeholders, so ``/api/user/101``
    and ``/api/user/102`` are the same weakness rather than two findings.
    """
    raw = (path or "").strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    segments: List[str] = []
    for segment in raw.split("/"):
        if not segment:
            continue
        if segment.isdigit():
            segments.append("{id}")
        elif _UUID_RE.match(segment):
            segments.append("{uuid}")
        elif _HEX_ID_RE.match(segment):
            segments.append("{hex}")
        else:
            segments.append(segment)
    return "/" + "/".join(segments) if segments else "/"


def normalize_target(value: Optional[str]) -> str:
    """Return a stable scheme://host[:port]/path identity.

    Query strings, fragments, credentials, default ports, and trailing slashes
    are removed. Paths are normalized with :func:`normalize_path`.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw.rstrip("/")
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    if not host:
        return raw.rstrip("/")
    port = _safe_port(parsed)
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = normalize_path(parsed.path)
    if path == "/":
        return f"{scheme}://{host}"
    return f"{scheme}://{host}{path}"


def target_identity(url: Optional[str]) -> str:
    """Origin-level identity for coverage grouping."""
    normalized = normalize_target(url)
    if not normalized:
        return ""
    try:
        parsed = urlsplit(normalized)
    except ValueError:
        return normalized
    host = (parsed.hostname or "").lower()
    port = _safe_port(parsed)
    if port and not ((parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    return f"{(parsed.scheme or 'http').lower()}://{host}"


def endpoint_path(url: Optional[str]) -> str:
    try:
        return normalize_path(urlsplit((url or "").strip()).path)
    except ValueError:
        return "/"


def parameter_identity(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        value = ",".join(str(v) for v in value)
    return re.sub(r"\s+", " ", str(value).strip().lower())


def finding_key(
    *,
    target: Optional[str],
    scenario: Optional[str],
    method: Optional[str],
    path: Optional[str],
    parameter: Any = "",
) -> str:
    """Deterministic key: sha256(target | scenario | method | path | parameter)."""
    identity = "|".join(
        (
            normalize_target(target),
            normalize_scenario(scenario),
            (method or "").strip().upper(),
            normalize_path(path),
            parameter_identity(parameter),
        )
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def episode_target(episode: Dict[str, Any]) -> str:
    return (episode.get("base_url") or episode.get("target") or "").strip()


def episode_endpoint(episode: Dict[str, Any]) -> str:
    return (episode.get("target") or episode.get("base_url") or "").strip()


def episode_parameter(episode: Dict[str, Any]) -> str:
    recon = episode.get("recon_data") or {}
    if isinstance(recon, dict):
        return parameter_identity(recon.get("target_parameter"))
    return ""


def episode_method(episode: Dict[str, Any]) -> str:
    method = (episode.get("http_method") or "").strip().upper()
    if method:
        return method
    scenario = normalize_scenario(episode.get("scenario") or episode.get("attack_type"))
    return default_method(scenario)


def episode_finding_key(episode: Dict[str, Any]) -> Optional[str]:
    scenario = normalize_scenario(episode.get("scenario") or episode.get("attack_type"))
    target = episode_target(episode)
    endpoint = episode_endpoint(episode)
    if not scenario or not (target or endpoint):
        return None
    path = endpoint_path(endpoint) if endpoint else "/"
    return finding_key(
        target=target or endpoint,
        scenario=scenario,
        method=episode_method(episode),
        path=path,
        parameter=episode_parameter(episode),
    )


def _as_status(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def derive_outcome(
    *,
    threat_detected: Any,
    http_status: Any,
    patch_applied: Any = False,
    retest_status: Any = None,
    interrupted: bool = False,
    budget_limited: bool = False,
    evidence_ok: bool = True,
) -> str:
    """Derive one explicit outcome from pipeline facts.

    A failed probe (status 0/None, timeout, 3xx/5xx), missing evidence, or a
    budget/interruption stop is never ``clean`` and never worthy of a perfect
    score (score 0 for inconclusive, never 100).

    A *confirmed* threat is an open finding (``unpatched``) unless the
    remediation was verified by a re-test that blocked (``mitigated``). The
    score for an unconfirmed-but-explored state stays conservative, so a
    confirmed threat never produces a perfect score through an evidence gap.
    """
    if interrupted:
        return OUTCOME_INTERRUPTED
    if budget_limited:
        return OUTCOME_BUDGET_LIMITED
    status = _as_status(http_status)
    retest = _as_status(retest_status)
    if patch_applied and retest in PATCH_BLOCK_CODES:
        return OUTCOME_MITIGATED
    if threat_detected:
        return OUTCOME_UNPATCHED
    # No threat: only a completed probe with acceptable evidence can be clean.
    if status is None or status == 0:
        return OUTCOME_INCONCLUSIVE
    if not evidence_ok:
        return OUTCOME_INCONCLUSIVE
    if 200 <= status <= 499:
        return OUTCOME_CLEAN
    return OUTCOME_INCONCLUSIVE


def outcome_for_episode(episode: Dict[str, Any]) -> str:
    """Derive an outcome for new and legacy episode records."""
    explicit = (episode.get("outcome") or "").strip().lower()
    if explicit in ALL_OUTCOMES:
        return explicit

    run_status = str(episode.get("run_status") or "").strip().lower()
    if run_status == "interrupted":
        return OUTCOME_INTERRUPTED
    if run_status in ("queued", "running"):
        return OUTCOME_INCONCLUSIVE
    if run_status in ("failed", "timeout"):
        return OUTCOME_INTERRUPTED if episode.get("interrupted") else OUTCOME_INCONCLUSIVE

    status = _as_status(episode.get("status"))
    detection = episode.get("detection_report")
    evidence_ok = bool(detection) or status in (400, 401, 403, 404, 405, 422)
    return derive_outcome(
        threat_detected=bool(episode.get("threat_flag")),
        http_status=status,
        patch_applied=bool(episode.get("patch_applied")),
        retest_status=episode.get("retest_status"),
        interrupted=bool(episode.get("interrupted")),
        budget_limited=bool(episode.get("budget_limited")),
        evidence_ok=evidence_ok,
    )


def score_for_outcome(outcome: str) -> float:
    """UI-compatible score derived from the outcome, never the reverse."""
    if outcome == OUTCOME_CLEAN:
        return 100.0
    if outcome == OUTCOME_MITIGATED:
        return 100.0
    if outcome == OUTCOME_UNPATCHED:
        return 60.0
    # Inconclusive/interrupted/budget-limited attempts are not a pass. Zero is
    # deliberately conservative and is always paired with the explicit outcome.
    return 0.0


def _finding_id(key: str) -> str:
    return f"F-{key[:12]}"


def _timestamp(episode: Dict[str, Any]) -> str:
    return str(episode.get("timestamp") or episode.get("created_at") or "")


def _new_finding(episode: Dict[str, Any], key: str, outcome: str, timestamp: str) -> Dict[str, Any]:
    scenario = normalize_scenario(episode.get("scenario") or episode.get("attack_type"))
    target = episode_target(episode)
    endpoint = episode_endpoint(episode)
    return {
        "id": _finding_id(key),
        "finding_key": key,
        "target": normalize_target(target) or normalize_target(endpoint),
        "target_identity": target_identity(target or endpoint),
        "scenario": scenario,
        "endpoint": endpoint,
        "path": endpoint_path(endpoint),
        "parameter": episode_parameter(episode),
        "method": episode_method(episode),
        "title": episode.get("attack_label") or scenario,
        "outcome": outcome,
        "state": "open" if outcome == OUTCOME_UNPATCHED else "mitigated",
        "severity": episode.get("severity"),
        "cvss": episode.get("cvss_score"),
        "cwe": episode.get("cwe"),
        "mitre_id": episode.get("mitre_id"),
        "mitre_technique": episode.get("mitre_technique"),
        "mitre_tactic": episode.get("mitre_tactic"),
        "confidence": episode.get("confidence"),
        "evidence": episode.get("evidence") or {},
        "remediation": episode.get("remediation") or "",
        "first_seen": timestamp,
        "pr_url": episode.get("pr_url"),
        "approved": bool(episode.get("approved")),
        "last_seen": timestamp,
        "attempts": 1,
        "inconclusive_attempts": 0,
        "latest_episode_id": episode.get("id"),
        "reopened": False,
        "reopen_count": 0,
        "reopened_at": None,
        "mitigated_at": timestamp if outcome == OUTCOME_MITIGATED else None,
        "resolved_at": None,
        "active": outcome == OUTCOME_UNPATCHED,
    }


def build_findings(episodes: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse episodes into unique findings with lifecycle state.

    Rules:
      * Only confirmed threats create findings.
      * A clean re-test resolves an existing finding instead of creating a
        second one.
      * An inconclusive re-test never erases a prior confirmed state.
      * A previously mitigated/resolved finding that becomes exploitable again
        is reopened in place (same key and id).
    """
    findings: Dict[str, Dict[str, Any]] = {}
    for episode in episodes or []:
        run_status = str(episode.get("run_status") or "").strip().lower()
        if run_status in ("queued", "running"):
            continue
        key = episode_finding_key(episode)
        if not key:
            continue
        outcome = outcome_for_episode(episode)
        timestamp = _timestamp(episode)
        threat = bool(episode.get("threat_flag")) and outcome in THREAT_OUTCOMES
        current = findings.get(key)

        if current is None:
            if not threat:
                continue
            findings[key] = _new_finding(episode, key, outcome, timestamp)
            continue

        current["attempts"] = int(current.get("attempts") or 0) + 1
        current["last_seen"] = timestamp or current.get("last_seen")
        current["latest_episode_id"] = episode.get("id")
        current["last_attempt_outcome"] = outcome

        if outcome in (OUTCOME_INCONCLUSIVE, OUTCOME_INTERRUPTED, OUTCOME_BUDGET_LIMITED):
            current["inconclusive_attempts"] = int(current.get("inconclusive_attempts") or 0) + 1
            continue

        if outcome == OUTCOME_CLEAN:
            current["outcome"] = OUTCOME_CLEAN
            current["state"] = "resolved"
            current["active"] = False
            current["resolved_at"] = timestamp
            current["resolution"] = "no threat reproduced in a completed scan"
            continue

        previous_state = current.get("state")
        if outcome == OUTCOME_UNPATCHED and previous_state in ("mitigated", "resolved", "clean"):
            current["reopened"] = True
            current["reopen_count"] = int(current.get("reopen_count") or 0) + 1
            current["reopened_at"] = timestamp

        current["outcome"] = outcome
        current["state"] = "open" if outcome == OUTCOME_UNPATCHED else "mitigated"
        current["active"] = outcome == OUTCOME_UNPATCHED
        if outcome == OUTCOME_MITIGATED:
            current["mitigated_at"] = timestamp
            current["resolved_at"] = None
        elif outcome == OUTCOME_UNPATCHED:
            current["resolved_at"] = None
        # Refresh the current evidence/metadata from the latest attempt.
        current["evidence"] = episode.get("evidence") or current.get("evidence") or {}
        current["confidence"] = episode.get("confidence") or current.get("confidence")
        current["remediation"] = episode.get("remediation") or current.get("remediation") or ""
        current["severity"] = episode.get("severity") or current.get("severity")
        current["cvss"] = episode.get("cvss_score") if episode.get("cvss_score") is not None else current.get("cvss")
        current["cwe"] = episode.get("cwe") or current.get("cwe")
        current["mitre_id"] = episode.get("mitre_id") or current.get("mitre_id")
        current["mitre_technique"] = episode.get("mitre_technique") or current.get("mitre_technique")
        current["mitre_tactic"] = episode.get("mitre_tactic") or current.get("mitre_tactic")

    ordered = sorted(
        findings.values(),
        key=lambda f: (str(f.get("last_seen") or ""), str(f.get("id") or "")),
        reverse=True,
    )
    return ordered


def coverage_for_target(episodes: Iterable[Dict[str, Any]], target: Optional[str] = None) -> Dict[str, Any]:
    """Build the eight-vector coverage matrix for one target (or all targets)."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for episode in episodes or []:
        if str(episode.get("run_status") or "").strip().lower() in ("queued", "running"):
            continue
        identity = target_identity(episode_target(episode) or episode_endpoint(episode))
        if not identity:
            continue
        grouped.setdefault(identity, []).append(episode)

    requested = target_identity(target) if target else None
    if requested and requested not in grouped:
        grouped[requested] = []

    identities = [requested] if requested else sorted(grouped)
    if not identities:
        identities = [""]

    targets = []
    for identity in identities:
        target_episodes = grouped.get(identity, [])
        by_scenario: Dict[str, List[Dict[str, Any]]] = {key: [] for key in VECTOR_KEYS}
        for episode in target_episodes:
            scenario = normalize_scenario(episode.get("scenario") or episode.get("attack_type"))
            if scenario in by_scenario:
                by_scenario[scenario].append(episode)

        vectors = []
        counts = {status: 0 for status in ("not_run", "clean", "vulnerable", "mitigated", "inconclusive")}
        for key in VECTOR_KEYS:
            attempts = by_scenario[key]
            status, last_episode, last_outcome = _coverage_status(attempts)
            counts[status] += 1
            vectors.append({
                "key": key,
                "status": status,
                "attempts": len(attempts),
                "last_outcome": last_outcome,
                "last_episode_id": (last_episode or {}).get("id"),
                "last_seen": _timestamp(last_episode or {}),
                "evidence_present": bool((last_episode or {}).get("evidence")),
            })
        conclusive = counts["clean"] + counts["mitigated"] + counts["vulnerable"]
        tested = len(VECTOR_KEYS) - counts["not_run"]
        targets.append({
            "target_key": identity,
            "vectors": vectors,
            "counts": counts,
            "tested": tested,
            "conclusive": conclusive,
            "inconclusive": counts["inconclusive"],
            "coverage_percent": round(conclusive / len(VECTOR_KEYS) * 100, 1),
            "complete": conclusive == len(VECTOR_KEYS),
        })

    return {
        "vectors": list(VECTOR_KEYS),
        "targets": targets,
        "coverage_percent": round(
            sum(t["coverage_percent"] for t in targets) / len(targets), 1
        ) if targets else 0.0,
        "complete": all(t["complete"] for t in targets) if targets else False,
    }


def _coverage_status(attempts: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    if not attempts:
        return "not_run", None, None
    conclusive = [ep for ep in attempts if outcome_for_episode(ep) in CONCLUSIVE_OUTCOMES]
    latest = attempts[-1]
    latest_outcome = outcome_for_episode(latest)
    chosen = conclusive[-1] if conclusive else None
    if chosen is None:
        # Inconclusive / interrupted / budget-limited attempts are never "clean".
        return "inconclusive", latest, latest_outcome
    outcome = outcome_for_episode(chosen)
    if latest_outcome not in CONCLUSIVE_OUTCOMES and outcome == OUTCOME_UNPATCHED:
        # A failed re-test must not erase prior confirmed exposure.
        return "vulnerable", chosen, latest_outcome
    cov_status = {"clean": "clean", "mitigated": "mitigated", "unpatched": "vulnerable"}.get(
        outcome, "inconclusive"
    )
    return cov_status, chosen, outcome
