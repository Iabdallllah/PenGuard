"""SARIF 2.1.0 export shape: 8 rules, threat-only results."""


def test_sarif_envelope(client):
    r = client.get("/api/reports/sarif")
    assert r.status_code == 200
    s = r.json()
    assert s["version"] == "2.1.0"
    driver = s["runs"][0]["tool"]["driver"]
    assert driver["name"] == "PenGuard"
    assert len(driver["rules"]) == 8
    assert {x["id"] for x in driver["rules"]} == {
        "PENGUARD-IDOR", "PENGUARD-SQL_INJECTION", "PENGUARD-BUSINESS_LOGIC",
        "PENGUARD-XSS", "PENGUARD-CSRF", "PENGUARD-SSRF",
        "PENGUARD-BROKEN_AUTH", "PENGUARD-MISCONFIG",
    }


def _record(eid, attack_type, label, threat, patched, status, retest):
    return {"id": eid, "attack_type": attack_type, "attack_label": label,
            "threat_flag": threat, "patch_applied": patched, "status": status,
            "retest_status": retest, "score": 100.0, "remediation": "",
            "logs": [], "timestamp": "2026-01-01T00:00:00Z", "duration_ms": 0,
            "scenario": attack_type, "base_url": "http://x", "target": "http://x/api",
            "pr_url": None, "recon_data": None, "detection_report": None,
            "hardening_plan": None, "response_body": "",
            "cvss_score": 8.6, "severity": "HIGH", "cwe": "CWE-89"}


def test_sarif_taxonomies_and_rule_tags(client):
    drv = client.get("/api/reports/sarif").json()["runs"][0]["tool"]["driver"]
    tax = drv["taxonomies"][0]
    assert tax["name"] == "MITRE-ATT&CK-Enterprise"
    assert {t["id"] for t in tax["taxa"]} >= {"T1190", "T1059.007", "T1078", "T1082", "T1185"}
    xss = next(r for r in drv["rules"] if r["id"] == "PENGUARD-XSS")
    assert "T1059.007" in xss["properties"]["tags"]
    rel = xss["relationships"][0]
    assert rel["target"]["id"] == "T1059.007"
    assert rel["kinds"] == ["relevant"]


def test_sarif_threat_only(client, clean_ledger):
    import api_server
    api_server._db_add_episode(_record("s1", "sql_injection", "SQL Injection", True, True, 200, 403))
    api_server._db_add_episode(_record("s2", "xss", "XSS", False, False, 400, None))
    results = client.get("/api/reports/sarif").json()["runs"][0]["results"]
    by_ep = {x["properties"]["episode_id"]: x for x in results}
    assert "s1" in by_ep and "s2" not in by_ep
    assert by_ep["s1"]["ruleId"] == "PENGUARD-SQL_INJECTION"
    assert by_ep["s1"]["level"] == "error"  # HIGH severity
