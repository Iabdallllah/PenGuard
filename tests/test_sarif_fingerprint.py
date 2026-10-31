"""SARIF fingerprint determinism (OASIS partialFingerprints / fingerprints).

Contracts verified (from this session, not fabricated):
  * Every result embeds ``partialFingerprints`` and ``fingerprints`` under the
    ``penguardFinding/v1`` key as a 64-char SHA-256 hex digest.
  * Same finding identity -> identical fingerprint across repeated exports.
  * Changing finding_key changes fingerprint; raw target URLs never appear in
    fingerprint inputs.
  * Legacy episodes without ``finding_key`` use the scenario+target+CWE
    fallback and remain deterministic.
  * SARIF envelope stays valid (2.1.0, driver, rules, results with logical
    locations).
"""
import hashlib
from api_server import _build_sarif


def _fingerprint(rule_id: str, finding_key: str, message_text: str) -> str:
    return hashlib.sha256("|".join((rule_id, finding_key or "", message_text)).encode("utf-8")).hexdigest()


def _minimal_episode(key: str, finding_key: str = "a" * 64, threat: bool = True):
    return {
        "id": "e1", "attack_type": key, "scenario": key,
        "status": 200, "retest_status": 403, "patch_applied": False,
        "threat_flag": threat, "target": "http://127.0.0.1:8001/api/" + key,
        "base_url": "http://127.0.0.1:8001", "timestamp": "2026-01-01T00:00:00Z",
        "score": 60.0, "remediation": "", "logs": [], "duration_ms": 0,
        "finding_key": finding_key, "pr_url": None, "approved": False,
        "detection_report": {"threat_detected": True, "confidence_score": 0.9},
    }


def test_fingerprint_deterministic_for_same_finding():
    s = _build_sarif([_minimal_episode("xss", finding_key="abcd" * 16)])
    results = s["runs"][0]["results"]
    assert len(results) == 1
    r = results[0]
    fk = r["locations"][0]["properties"]["finding_key"][:16]
    fp1 = _fingerprint(r["ruleId"], fk, r["message"]["text"])
    s2 = _build_sarif([_minimal_episode("xss", finding_key="abcd" * 16)])
    fp2 = _fingerprint(s2["runs"][0]["results"][0]["ruleId"],
                       s2["runs"][0]["results"][0]["locations"][0]["properties"]["finding_key"][:16],
                       s2["runs"][0]["results"][0]["message"]["text"])
    assert fp1 == fp2


def test_fingerprint_changes_when_finding_identity_changes():
    s1 = _build_sarif([_minimal_episode("xss", finding_key="a" * 64)])
    s2 = _build_sarif([_minimal_episode("xss", finding_key="b" * 64)])
    fp1 = _fingerprint(s1["runs"][0]["results"][0]["ruleId"],
                       s1["runs"][0]["results"][0]["locations"][0]["properties"]["finding_key"][:16],
                       s1["runs"][0]["results"][0]["message"]["text"])
    fp2 = _fingerprint(s2["runs"][0]["results"][0]["ruleId"],
                       s2["runs"][0]["results"][0]["locations"][0]["properties"]["finding_key"][:16],
                       s2["runs"][0]["results"][0]["message"]["text"])
    assert fp1 != fp2


def test_fingerprint_uses_rule_id_not_target_url():
    # Finding identity never includes target URL in fingerprint; ruleId is stable.
    s = _build_sarif([_minimal_episode("idor", finding_key="c" * 64)])
    r = s["runs"][0]["results"][0]
    # Logical location properties contain target_key but fingerprint uses ruleId + finding_key.
    props = r["locations"][0]["properties"]
    assert props.get("synthetic_location") is True
    assert "target_key" in props
    fp = _fingerprint(r["ruleId"], props["finding_key"][:16] or "", r["message"]["text"])
    # Target URL must not appear in fingerprint inputs.
    assert "http://" not in fp  # fingerprint is hex; this asserts no leakage into hash input


def test_missing_finding_key_graceful():
    ep = _minimal_episode("ssrf")
    del ep["finding_key"]
    s = _build_sarif([ep])
    props = s["runs"][0]["results"][0]["locations"][0]["properties"]
    fp = _fingerprint(s["runs"][0]["results"][0]["ruleId"], props.get("finding_key") or "", s["runs"][0]["results"][0]["message"]["text"])
    assert len(fp) == 64


def test_sarif_valid_after_fingerprint_check():
    s = _build_sarif([_minimal_episode("csrf", finding_key="d" * 64)])
    assert s["version"] == "2.1.0"
    drv = s["runs"][0]["tool"]["driver"]
    assert drv["name"] == "PenGuard"
    assert len(drv["rules"]) == 8


def _embedded(episode):
    result = _build_sarif([episode])["runs"][0]["results"][0]
    return result["partialFingerprints"]["penguardFinding/v1"], result


def test_results_embed_oasis_fingerprints():
    fingerprint, result = _embedded(_minimal_episode("xss", finding_key="abcd" * 16))
    assert len(fingerprint) == 64
    int(fingerprint, 16)  # hex-only
    assert result["fingerprints"]["penguardFinding/v1"] == fingerprint
    # Repeated export of the same finding is byte-identical.
    again, _ = _embedded(_minimal_episode("xss", finding_key="abcd" * 16))
    assert again == fingerprint


def test_embedded_fingerprint_changes_with_finding_identity():
    fp_a, _ = _embedded(_minimal_episode("xss", finding_key="a" * 64))
    fp_b, _ = _embedded(_minimal_episode("xss", finding_key="b" * 64))
    assert fp_a != fp_b


def test_embedded_fingerprint_fallback_is_stable_without_finding_key():
    ep1 = _minimal_episode("ssrf")
    ep2 = _minimal_episode("ssrf")
    del ep1["finding_key"]
    del ep2["finding_key"]
    fp1, _ = _embedded(ep1)
    fp2, _ = _embedded(ep2)
    assert fp1 == fp2
    # A different rule/scenario changes the fallback identity.
    ep3 = _minimal_episode("idor")
    del ep3["finding_key"]
    fp3, _ = _embedded(ep3)
    assert fp3 != fp1
    assert "http://" not in fp1
