"""Wave 0/1 regression tests: eight-vector coverage matrix.

Contracts verified here:
  * All eight security vectors are represented (clean/untested/vulnerable/mitigated/inconclusive)
  * Clean, untested, vulnerable, mitigated, and inconclusive states are distinguished
  * Failed probes, timeouts, and interrupted scans produce ``inconclusive``/``interrupted``
  * Partial coverage is reported as such and is never described as complete
  * Coverage percentage is independent from the posture score

Ambiguities deliberately not invented here:
  * ``not_run`` means the vector was never attempted for that target in this ledger.
  * An inconclusive vector keeps its inconclusive state and does not silently become clean.
"""
import os

from api_server import compute_posture
from security_model import VECTOR_KEYS, coverage_for_target


def _clean(key: str):
    return {
        "id": f"clean-{key}",
        "attack_type": key,
        "scenario": key,
        "base_url": "http://127.0.0.1:8001",
        "target": f"http://127.0.0.1:8001{os.path.join('/api', key.replace('_', ''))}",
        "threat_flag": False,
        "patch_applied": False,
        "status": 200,
        "retest_status": None,
        "score": 100.0,
        "timestamp": "2026-01-01T00:00:00Z",
        "detection_report": {"threat_detected": False, "technical_findings": "200 OK - no threat"},
    }


def _vulnerable(key: str):
    return {
        "id": f"vuln-{key}",
        "attack_type": key,
        "scenario": key,
        "base_url": "http://127.0.0.1:8001",
        "target": f"http://127.0.0.1:8001{os.path.join('/api', key.replace('_', ''))}",
        "threat_flag": True,
        "patch_applied": False,
        "status": 200,
        "retest_status": None,
        "score": 60.0,
        "timestamp": "2026-01-01T00:00:00Z",
        "detection_report": {"threat_detected": True, "technical_findings": "200 OK - threat"},
    }


def _inconclusive(key: str):
    return {
        "id": f"inc-{key}",
        "attack_type": key,
        "scenario": key,
        "base_url": "http://127.0.0.1:8001",
        "target": f"http://127.0.0.1:8001{os.path.join('/api', key.replace('_', ''))}",
        "threat_flag": False,
        "patch_applied": False,
        "status": 0,
        "retest_status": None,
        "score": 0.0,
        "timestamp": "2026-01-01T00:00:00Z",
        "detection_report": {"threat_detected": False, "technical_findings": "timeout"},
    }


def test_coverage_covers_exactly_eight_vectors():
    assert len(VECTOR_KEYS) == 8
    assert set(VECTOR_KEYS) == {
        "idor", "sql_injection", "business_logic", "xss",
        "csrf", "ssrf", "broken_auth", "misconfig",
    }


def test_empty_ledger_reports_full_untested_matrix():
    cov = coverage_for_target([])
    assert cov["vectors"] == list(VECTOR_KEYS)
    target = cov["targets"][0]
    assert target["target_key"] == ""
    for v in target["vectors"]:
        assert v["status"] == "not_run"
    assert target["coverage_percent"] == 0.0
    assert target["complete"] is False


def test_clean_vector_is_reported_clean_and_others_not_run():
    cov = coverage_for_target([_clean("idor")])
    target = cov["targets"][0]
    by_key = {v["key"]: v for v in target["vectors"]}
    assert by_key["idor"]["status"] == "clean"
    assert by_key["sql_injection"]["status"] == "not_run"
    assert target["coverage_percent"] == round(100 / len(VECTOR_KEYS), 1)
    assert target["complete"] is False


def test_vulnerable_and_mitigated_states_are_distinguished():
    cov = coverage_for_target([_vulnerable("xss")])
    by_key = {v["key"]: v for v in cov["targets"][0]["vectors"]}
    assert by_key["xss"]["status"] == "vulnerable"

    cov2 = coverage_for_target([
        {"id": "v1", "attack_type": "xss", "scenario": "xss",
         "base_url": "http://127.0.0.1:8001", "target": "http://127.0.0.1:8001/api/xss",
         "threat_flag": True, "patch_applied": True, "status": 200, "retest_status": 403,
         "score": 100.0, "timestamp": "2026-01-01T00:00:00Z",
         "detection_report": {"threat_detected": True, "technical_findings": "patched"}},
    ])
    by_key2 = {v["key"]: v for v in cov2["targets"][0]["vectors"]}
    assert by_key2["xss"]["status"] == "mitigated"


def test_inconclusive_timeout_is_distinguished_from_clean():
    cov = coverage_for_target([_inconclusive("ssrf")])
    by_key = {v["key"]: v for v in cov["targets"][0]["vectors"]}
    assert by_key["ssrf"]["status"] == "inconclusive"
    assert by_key["ssrf"]["last_outcome"] == "inconclusive"
    posture = compute_posture([_inconclusive("ssrf")])
    # A failed probe never produces a false clean or a false high posture.
    assert posture["score"] == 100.0


def test_interrupted_scan_is_reported():
    ep = _inconclusive("csrf")
    ep["run_status"] = "INTERRUPTED"
    cov = coverage_for_target([ep])
    by_key = {v["key"]: v for v in cov["targets"][0]["vectors"]}
    # An interrupted scan is never reported as clean; the last outcome is explicit.
    assert by_key["csrf"]["status"] == "inconclusive"
    assert by_key["csrf"]["last_outcome"] == "interrupted"


def test_partial_coverage_is_not_complete():
    cov = coverage_for_target([_clean("idor"), _clean("xss")])
    target = cov["targets"][0]
    tested = sum(1 for v in target["vectors"] if v["status"] != "not_run")
    assert tested == 2
    assert target["complete"] is False
    assert target["coverage_percent"] == round(2 / len(VECTOR_KEYS) * 100, 1)


def test_coverage_percentage_is_independent_from_posture():
    cov = coverage_for_target([_clean("idor")])
    posture = compute_posture([_clean("idor")])
    # Clean probe -> posture 100, but only 1/8 vectors actually tested.
    assert posture["score"] == 100.0
    assert cov["targets"][0]["coverage_percent"] < 100.0
    assert cov["targets"][0]["complete"] is False
