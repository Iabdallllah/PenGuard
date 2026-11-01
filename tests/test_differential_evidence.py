"""Differential probing: baseline vs exploit vs post-patch evidence."""
import evidence
import orchestrator as orch
import config


def _state(**overrides):
    state = {
        "attack_plan": {
            "vulnerability_target": "XSS",
            "target_endpoint": "http://target/api/search?q=<script>",
            "http_method": "GET",
            "payload_json": None,
        },
        "http_status": 200,
        "response_body": '{"html": "<div>Search: <script>alert(1)</script></div>"}',
        "response_headers": {"content-type": "application/json"},
        "baseline_request": {
            "http_method": "GET",
            "target_endpoint": "http://target/api/search?q=hello",
            "payload_json": None,
        },
        "baseline_status": 200,
        "baseline_response_body": '{"html": "<div>Search: hello</div>"}',
        "baseline_response_headers": {"content-type": "application/json"},
        "retest_status": 403,
        "retest_response_body": '{"detail": "Forbidden"}',
        "retest_response_headers": {"content-type": "application/json"},
        "patch_applied": True,
        "detection_report": {
            "threat_detected": True,
            "vulnerability_type": "XSS",
            "confidence_score": 0.97,
            "technical_findings": "script reflected",
        },
    }
    state.update(overrides)
    return state


def test_differential_confirms_causality_and_mitigation():
    ev = evidence.build_evidence(_state())
    diff = ev["differential_analysis"]

    assert diff["baseline_status"] == 200
    assert diff["exploit_status"] == 200
    assert diff["retest_status"] == 403
    assert diff["behavior_delta"] == "body_changed"
    assert diff["exploit_to_retest"] == "blocked"
    assert diff["causality_confirmed"] is True
    assert diff["zero_false_positive"] is True
    assert diff["false_positive_risk"] == "low"
    assert diff["mitigation_verified"] is True
    assert ev["baseline"]["outcome"] == "control"
    assert ev["retest"]["outcome"] == "blocked"
    assert ev["baseline"]["body_sha256"] != ev["response"]["body_sha256"]


def test_identical_baseline_and_exploit_never_claim_zero_false_positive():
    same = "same response"
    ev = evidence.build_evidence(_state(
        response_body=same,
        baseline_response_body=same,
    ))
    diff = ev["differential_analysis"]

    assert diff["behavior_delta"] == "none"
    assert diff["causality_confirmed"] is False
    assert diff["zero_false_positive"] is False
    assert diff["false_positive_risk"] == "unconfirmed"
    assert "no zero-false-positive claim" in diff["interpretation"]


def test_missing_baseline_is_not_observable():
    ev = evidence.build_evidence(_state(
        baseline_status=None,
        baseline_response_body=None,
        baseline_request=None,
    ))
    diff = ev["differential_analysis"]
    assert diff["behavior_delta"] == "not_observable"
    assert diff["causality_confirmed"] is False
    assert ev["baseline"]["outcome"] == "baseline_failed"


def test_baseline_secrets_are_redacted():
    ev = evidence.build_evidence(_state(
        baseline_request={
            "http_method": "POST",
            "target_endpoint": "http://target/api/login?token=abc123",
            "payload_json": '{"username": "alice", "password": "alice123"}',
        },
    ))
    request = ev["baseline"]["request"]
    assert "abc123" not in request["url"]
    assert "alice123" not in request["payload"]
    assert evidence.REDACTED in request["url"]


def test_skill_and_ast_metadata_are_preserved_in_evidence():
    playbook = {
        "skill_id": "penguard-xss-v1",
        "tactics_applied": ["baseline", "exploit", "retest"],
        "verification_rule": "script marker absent from baseline",
    }
    remediation = {
        "engine": "python-ast",
        "ast_verified": True,
        "transformed_nodes": ["AsyncFunctionDef:search_xss", "Assign:html_escape_output"],
    }
    ev = evidence.build_evidence(_state(
        skill_playbook=playbook,
        remediation_metadata=remediation,
    ))
    assert ev["skill_playbook"] == playbook
    assert ev["remediation"] == remediation


def test_red_execution_captures_baseline_probe(monkeypatch):
    calls = []

    class _Response:
        def __init__(self, status, body):
            self.status_code = status
            self.text = body
            self.headers = {"content-type": "application/json"}

    def fake_get(url, **kwargs):
        calls.append(("GET", url))
        if "q=hello" in url:
            return _Response(200, '{"html": "hello"}')
        return _Response(200, '{"html": "<script>alert(1)</script>"}')

    monkeypatch.setattr(orch, "llm", None)
    monkeypatch.setattr(config, "VECTOR_SKILLS_ENABLED", True)
    monkeypatch.setattr(orch.requests, "get", fake_get)

    out = orch.red_execution_agent({
        "target_url": "http://target",
        "scenario": "xss",
        "recon_data": {"suspected_vulnerability": "XSS"},
    })

    assert out["http_status"] == 200
    assert out["baseline_status"] == 200
    assert out["baseline_response_body"] == '{"html": "hello"}'
    assert out["skill_playbook"]["skill_id"] == "penguard-xss-v1"
    assert "baseline" in out["skill_playbook"]["tactics_applied"]
    assert calls == [
        ("GET", "http://target/api/search?q=%3Cscript%3Ealert('xss')%3C/script%3E"),
        ("GET", "http://target/api/search?q=hello"),
    ]
