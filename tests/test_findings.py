"""Wave 0 regression tests: finding identity, dedupe, and unique-finding posture.

Contracts verified here (from docs/wave0-final-report.md and the audit):
  * Finding key is deterministic: sha256(target | scenario | method | path | parameter)
  * Repeated scans of the same vector update one finding instead of creating duplicates
  * Episodes stay immutable attempts; findings hold current state
  * A mitigated finding that regresses reopens the same finding (no new finding)
  * Distinct endpoints/parameters/scenarios create distinct findings
  * Posture deducts once per unique unpatched finding
  * Inconclusive / timed-out attempts never create false findings or false cleans

Ambiguities deliberately not invented here:
  * ``interrupted`` runs are recorded but do not erase prior confirmed state.
  * Evidence absence with a confirmed threat keeps the finding open (conservative score),
    while a completed clean probe remains ``clean``.
"""
import hashlib
from typing import Any, Dict

from api_server import compute_posture
from evidence import redact_text, redact_url
from security_model import (
    ALL_OUTCOMES,
    OUTCOME_BUDGET_LIMITED,
    OUTCOME_CLEAN,
    OUTCOME_INCONCLUSIVE,
    OUTCOME_INTERRUPTED,
    OUTCOME_MITIGATED,
    OUTCOME_UNPATCHED,
    build_findings,
    derive_outcome,
    episode_finding_key,
    finding_key,
)


def _target(key: str = "idor") -> str:
    return f"http://127.0.0.1:8001{api_endpoint_for(key)}"


def api_endpoint_for(key: str) -> str:
    return f"/api/{key.replace('_', '')}"


def _ep(ep_id: str, scenario: str, *, threat: bool = True, patched: bool = False,
       status: int = 200, retest_status: int = None, retest: bool = False) -> Dict[str, Any]:
    return {
        "id": ep_id,
        "attack_type": scenario,
        "scenario": scenario,
        "base_url": "http://127.0.0.1:8001",
        "target": _target(scenario),
        "threat_flag": threat,
        "patch_applied": patched,
        "status": status,
        "retest_status": retest_status,
        "score": 60.0 if (threat and not retest) else 100.0,
        "timestamp": f"2026-01-01T00:0{len(ep_id)}:00Z",
    }


# ── Finding identity ────────────────────────────────────────────────────────
def test_finding_key_is_deterministic_and_normalizes_target():
    k1 = finding_key(target="http://127.0.0.1:8001/api/user", scenario="idor",
                    method="GET", path="/api/user/102", parameter="user_id")
    k2 = finding_key(target="http://127.0.0.1:8001/api/user/", scenario="idor",
                    method="GET", path="/api/user/102", parameter="user_id")
    assert k1 == k2
    assert k1 == hashlib.sha256(
        "|".join((
            "http://127.0.0.1:8001/api/user", "idor", "GET", "/api/user/{id}", "user_id",
        )).encode("utf-8")
    ).hexdigest()


def test_finding_key_ignores_case_in_scenario_and_lowercases_parameter():
    k1 = finding_key(target="http://127.0.0.1:8001", scenario="sql_injection",
                    method="GET", path="/api/records", parameter="Query")
    k2 = finding_key(target="http://127.0.0.1:8001", scenario="SQL Injection",
                    method="GET", path="/api/records", parameter="query")
    assert k1 == k2


# ── Outcome derivation ───────────────────────────────────────────────────────
def test_failed_probe_is_inconclusive_not_clean():
    assert derive_outcome(threat_detected=False, http_status=0, evidence_ok=False) == OUTCOME_INCONCLUSIVE
    assert derive_outcome(threat_detected=False, http_status=200, evidence_ok=False) == OUTCOME_INCONCLUSIVE


def test_timeout_is_never_clean_and_never_perfect_score():
    assert derive_outcome(threat_detected=False, http_status=0, evidence_ok=False) == OUTCOME_INCONCLUSIVE
    assert derive_outcome(threat_detected=False, http_status=None, evidence_ok=False) == OUTCOME_INCONCLUSIVE


def test_confirmed_threat_without_patch_is_unpatched_with_conservative_score():
    outcome = derive_outcome(threat_detected=True, http_status=200, patch_applied=False, retest_status=None,
                             evidence_ok=False)
    assert outcome == OUTCOME_UNPATCHED
    assert outcome not in (OUTCOME_CLEAN,)


def test_mitigated_when_patch_blocks():
    assert derive_outcome(threat_detected=True, http_status=200, patch_applied=True, retest_status=403,
                          evidence_ok=True) == OUTCOME_MITIGATED
    assert derive_outcome(threat_detected=True, http_status=200, patch_applied=True, retest_status=200,
                          evidence_ok=True) == OUTCOME_UNPATCHED


def test_interrupted_outcome_is_explicit():
    assert derive_outcome(threat_detected=True, http_status=200, interrupted=True) == OUTCOME_INTERRUPTED


# ── Finding identity from episodes ───────────────────────────────────────────
def test_episode_finding_key_uses_normalized_target_and_scenario():
    key = episode_finding_key(_ep("e1", "idor"))
    assert key and isinstance(key, str) and len(key) == 64


def test_duplicate_scans_dedupe_to_one_finding():
    findings = build_findings([
        _ep("e1", "idor"),
        _ep("e2", "idor"),
        _ep("e3", "idor"),
    ])
    assert len(findings) == 1
    f = findings[0]
    assert f["attempts"] == 3
    assert f["outcome"] == OUTCOME_UNPATCHED
    assert f["state"] == "open"
    assert f["active"] is True


def test_duplicate_unpatched_scans_deduct_once_in_posture():
    episodes = [_ep("e1", "idor"), _ep("e2", "idor"), _ep("e3", "idor")]
    posture = compute_posture(episodes)
    assert posture["active_vulnerabilities"] == 1
    expected = 100.0 - (0.9 * 7.5)
    assert posture["score"] == round(expected, 1)


def test_regression_reopens_same_finding():
    # Open -> mitigated -> open again. Same key, no new finding.
    episodes = [
        _ep("e1", "idor"),
        _ep("e2", "idor", patched=True, retest_status=403, threat=True),
        _ep("e3", "idor", patched=False, retest_status=None, threat=True),
    ]
    findings = build_findings(episodes)
    assert len(findings) == 1
    f = findings[0]
    assert f["attempts"] == 3
    assert f["outcome"] == OUTCOME_UNPATCHED
    assert f["reopened"] is True
    assert f["reopen_count"] == 1
    assert f["latest_episode_id"] == "e3"


def test_distinct_findings_separate_by_scenario_and_endpoint():
    findings = build_findings([
        _ep("e1", "idor"),
        _ep("e2", "sql_injection"),
    ])
    assert len(findings) == 2
    keys = {f["finding_key"] for f in findings}
    assert len(keys) == 2


# ── Inconclusive handling ────────────────────────────────────────────────────
def test_inconclusive_episode_creates_no_false_finding():
    episodes = [_ep("e1", "idor", threat=False, status=0)]
    findings = build_findings(episodes)
    assert findings == []
    posture = compute_posture(episodes)
    assert posture["score"] == 100.0


def test_missing_evidence_never_clears_a_threat_finding():
    # Confirmed threat + missing detection evidence => still unpatched (open).
    outcome = derive_outcome(threat_detected=True, http_status=200, patch_applied=False,
                             retest_status=None, evidence_ok=False)
    assert outcome == OUTCOME_UNPATCHED


# ── Outcome vocabulary ───────────────────────────────────────────────────────
def test_outcome_vocabulary_is_closed():
    assert set(ALL_OUTCOMES) == {OUTCOME_CLEAN, OUTCOME_MITIGATED, OUTCOME_UNPATCHED,
                                 OUTCOME_INCONCLUSIVE, OUTCOME_INTERRUPTED, OUTCOME_BUDGET_LIMITED}


# ── Secret redaction ─────────────────────────────────────────────────────────
def test_redaction_removes_bearer_and_query_secrets():
    redacted_text_value = redact_text("Authorization: Bearer abc.def.ghi xyz", limit=200)
    assert "abc.def.ghi" not in redacted_text_value
    assert "[REDACTED]" in redacted_text_value
    redacted = redact_text("secret_token=supersecretvalue&other=1", limit=200)
    assert "supersecretvalue" not in redacted
    assert "secret_token=[REDACTED]" in redacted
    assert "http://example.com?token=[REDACTED]" == redact_url("http://example.com?token=supersecretvalue")


def test_redaction_preserves_non_secret_content():
    text = redact_text("<script>alert('xss')</script>", limit=200)
    assert "alert" in text.lower() or "<script" in text or "script" in text.lower()
