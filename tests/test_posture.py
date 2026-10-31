"""Posture equation S(t) = max(0, 100 - sum(w*CVSS)) over unique unpatched findings."""
from api_server import compute_posture


def _ep(key, threat=True, patched=False, score=100.0, status=200, retest_status=None):
    return {"id": key, "attack_type": key, "scenario": key,
            "base_url": "http://127.0.0.1:8001",
            "target": f"http://127.0.0.1:8001{api_endpoint_for(key)}",
            "threat_flag": threat, "patch_applied": patched, "status": status,
            "retest_status": retest_status, "score": score, "timestamp": "2026-01-01T00:00:00Z"}


def api_endpoint_for(key: str) -> str:
    return f"/api/{key.replace('_', '')}"


def test_empty_ledger_healthy():
    p = compute_posture([])
    assert p == {"score": 100.0, "status": "HEALTHY", "active_vulnerabilities": 0,
                 "mitigated_vulnerabilities": 0, "last_audit_timestamp": None}


def test_single_unpatched_deducts_exact():
    p = compute_posture([_ep("sql_injection")])  # 8.6 * 1.0
    assert p["score"] == 91.4
    assert p["status"] == "HEALTHY"
    assert p["active_vulnerabilities"] == 1
    assert p["mitigated_vulnerabilities"] == 0


def test_patched_not_deducted():
    p = compute_posture([_ep("sql_injection", patched=True, retest_status=403)])
    assert p["score"] == 100.0
    assert p["mitigated_vulnerabilities"] == 1
    assert p["active_vulnerabilities"] == 0


def test_bands():
    many = [_ep(k) for k in ("sql_injection", "ssrf", "broken_auth", "idor")]  # 8.6+8.5+7.29+6.75
    p = compute_posture(many)
    assert p["status"] == "DEGRADED"
    all8 = [_ep(k) for k in ("sql_injection", "ssrf", "broken_auth", "idor",
                             "business_logic", "csrf", "xss", "misconfig")]
    p2 = compute_posture(all8)
    assert p2["status"] == "DEGRADED"  # max single-set deduction is 47.92
    # Repeated unpatched scans of the same unique finding must not inflate posture.
    p3 = compute_posture(all8 + all8)
    assert p3["score"] == p2["score"]
    assert p3["status"] == p2["status"]
    assert p3["active_vulnerabilities"] == p2["active_vulnerabilities"]
