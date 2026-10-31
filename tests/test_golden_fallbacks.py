"""Golden contract for the deterministic fallbacks.

Captured before any Markdown-skill externalization so parity can be proven.
These values mirror the existing fallback implementation, not aspirational
behavior. If the fallback changes intentionally, update the golden explicitly.
"""
import json

import pytest

import config
import orchestrator as orch

BASE = "http://127.0.0.1:8001"

GOLDEN_PLANS = {
    "idor": {
        "vulnerability_target": "IDOR",
        "path": "/api/user/102",
        "method": "GET",
        "payload": None,
        "hypothesis": "Direct object reference without authorization",
    },
    "sql_injection": {
        "vulnerability_target": "SQL Injection",
        "path": "/api/records?query=' UNION SELECT id, name, secret_token FROM users -- ",
        "method": "GET",
        "payload": None,
        "hypothesis": "Unsanitized query concatenation allows token dump",
    },
    "business_logic": {
        "vulnerability_target": "Business Logic Abuse",
        "path": "/api/checkout",
        "method": "POST",
        "payload": {"item_id": "license_pro", "quantity": -1, "unit_price": 250.0},
        "hypothesis": "Negative quantity bypasses billing invariant",
    },
    "xss": {
        "vulnerability_target": "XSS",
        "path": "/api/search?q=%3Cscript%3Ealert('xss')%3C/script%3E",
        "method": "GET",
        "payload": None,
        "hypothesis": "Reflected XSS via unsanitized q parameter",
    },
    "csrf": {
        "vulnerability_target": "CSRF",
        "path": "/api/transfer",
        "method": "POST",
        "payload": {"to": "attacker", "amount": 1000},
        "hypothesis": "Missing CSRF token allows forged transfer",
    },
    "ssrf": {
        "vulnerability_target": "SSRF",
        "path": "/api/fetch?url=http://169.254.169.254/latest/meta-data/",
        "method": "GET",
        "payload": None,
        "hypothesis": "Server fetches internal metadata URL",
    },
    "broken_auth": {
        "vulnerability_target": "Broken Authentication",
        "path": "/api/login",
        "method": "POST",
        "payload": {"username": "admin", "password": "wrongpass"},
        "hypothesis": "Any password authenticates admin",
    },
    "misconfig": {
        "vulnerability_target": "Security Misconfiguration",
        "path": "/api/debug",
        "method": "GET",
        "payload": None,
        "hypothesis": "Debug endpoint leaks secrets",
    },
}


@pytest.mark.parametrize("scenario,golden", GOLDEN_PLANS.items())
def test_golden_fallback_plan(scenario, golden):
    plan = orch._fallback_attack_plan(scenario, BASE, "")
    assert plan["vulnerability_target"] == golden["vulnerability_target"]
    assert plan["target_endpoint"] == BASE + golden["path"]
    assert plan["http_method"] == golden["method"]
    payload = plan["payload_json"]
    if golden["payload"] is None:
        assert payload is None
    else:
        assert json.loads(payload) == golden["payload"]
    assert plan["hypothesis"] == golden["hypothesis"]


GOLDEN_DETECTION = [
    ("http://x/api/user/102", 200, "secret token admin", "IDOR"),
    ("http://x/api/records?query=x", 200, "MASTER_SECRET_KEY leak", "SQL Injection"),
    ("http://x/api/checkout", 200, '{"total_billed": -250}', "Business Logic Abuse"),
    ("http://x/api/search?q=x", 200, "<script>alert('xss')</script>", "XSS"),
    ("http://x/api/transfer", 200, "transferred", "CSRF"),
    ("http://x/api/fetch?url=x", 200, "leaked ami-id metadata", "SSRF"),
    ("http://x/api/login", 200, "bypass-token authenticated", "Broken Authentication"),
    ("http://x/api/debug", 200, "secret_key exposed", "Security Misconfiguration"),
]


@pytest.mark.parametrize("url,status,body,vuln", GOLDEN_DETECTION)
def test_golden_fallback_detection_positive(url, status, body, vuln):
    report = orch._fallback_detection(url, status, body, "")
    assert report["threat_detected"] is True
    assert report["vulnerability_type"] == vuln
    assert 0.0 <= report["confidence_score"] <= 1.0


def test_golden_fallback_detection_blocked_is_clean():
    report = orch._fallback_detection("http://x/api/user/102", 403, "blocked", "")
    assert report["threat_detected"] is False
    assert report["vulnerability_type"] == "None"


GOLDEN_RULES = {
    "IDOR": "block_unauthorized_idor",
    "SQL Injection": "block_sql_injection",
    "Business Logic Abuse": "block_business_logic_abuse",
    "XSS": "block_xss",
    "CSRF": "block_csrf",
    "SSRF": "block_ssrf",
    "Broken Authentication": "block_broken_auth",
    "Security Misconfiguration": "block_misconfig",
}


@pytest.mark.parametrize("vuln,rule", GOLDEN_RULES.items())
def test_golden_fallback_hardening(vuln, rule):
    plan = orch._fallback_hardening(True, vuln)
    assert plan["target_rule_name"] == rule
    assert plan["remediation_suggestion"]
    assert plan["mitigation_action"]


def test_golden_fallback_hardening_no_threat():
    plan = orch._fallback_hardening(False, "None")
    assert plan["target_rule_name"] == "none"


def test_skill_enabled_plan_matches_golden(monkeypatch):
    monkeypatch.setattr(config, "VECTOR_SKILLS_ENABLED", True)
    for scenario, golden in GOLDEN_PLANS.items():
        plan = orch._fallback_attack_plan(scenario, BASE, "")
        assert plan["target_endpoint"] == BASE + golden["path"]
        assert plan["http_method"] == golden["method"]
        assert plan["vulnerability_target"] == golden["vulnerability_target"]
