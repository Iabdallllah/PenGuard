"""API contract: routes, auth boundaries, shapes. No docker, no network."""
import api_server

REQUIRED_VECTORS = {"idor", "sql_injection", "business_logic", "xss", "csrf", "ssrf", "broken_auth", "misconfig"}


def test_health_ok(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_scenarios_exactly_eight(client):
    r = client.get("/api/scenarios")
    assert r.status_code == 200
    data = r.json()
    assert {s["key"] for s in data} == REQUIRED_VECTORS
    for s in data:
        for field in ("key", "label", "owasp", "cvss", "severity", "cwe", "weight",
                      "mitre_id", "mitre_technique", "mitre_tactic"):
            assert field in s, f"missing {field} in {s.get('key')}"


def test_mitre_mapping_spot_checks():
    by_key = {s["key"]: s for s in api_server.list_scenarios()}
    assert by_key["sql_injection"]["mitre_id"] == "T1190"
    assert by_key["xss"]["mitre_id"] == "T1059.007"
    assert by_key["xss"]["mitre_tactic"] == "Execution"
    assert by_key["misconfig"]["mitre_id"] == "T1082"
    assert api_server._mitre_for("nope")["mitre_id"] == "T1190"  # safe fallback


def test_vector_metrics_cover_contract():
    assert REQUIRED_VECTORS <= set(api_server.VECTOR_METRICS)
    assert REQUIRED_VECTORS <= set(api_server.VULN_TO_SCENARIO)
    assert REQUIRED_VECTORS <= api_server.ALLOWED_SCENARIOS


def test_selective_auth(client):
    # mutating routes require the key
    assert client.post("/api/episodes/run", json={"scenario": "xss"}).status_code == 401
    assert client.delete("/api/episodes").status_code == 401
    assert client.post("/api/episodes/nope/approve").status_code == 401
    # reads stay open
    assert client.get("/api/episodes").status_code == 200
    assert client.get("/api/posture").status_code == 200
    assert client.get("/api/scenarios").status_code == 200
    assert client.get("/api/reports/sarif").status_code == 200
    assert client.get("/metrics").status_code == 200


def test_unknown_episode_404(client):
    assert client.get("/api/episodes/does-not-exist").status_code == 404


def test_approve_unknown_404(client, auth_headers):
    r = client.post("/api/episodes/does-not-exist/approve", headers=auth_headers)
    assert r.status_code == 404


def test_approve_without_pr_409(client, auth_headers, clean_ledger):
    clean_ledger.append({
        "id": "testnopr", "attack_type": "xss", "run_status": "complete",
        "pr_url": None, "threat_flag": True,
    })
    r = client.post("/api/episodes/testnopr/approve", headers=auth_headers)
    assert r.status_code == 409


def test_approve_running_409(client, auth_headers, clean_ledger):
    clean_ledger.append({
        "id": "testrun", "attack_type": "xss", "run_status": "RUNNING",
        "pr_url": "https://github.com/Iabdallllah/PenGuard/pull/9",
        "threat_flag": True,
    })
    r = client.post("/api/episodes/testrun/approve", headers=auth_headers)
    assert r.status_code == 409


def test_approve_unconfigured_github_503(client, auth_headers, clean_ledger, monkeypatch):
    clean_ledger.append({
        "id": "testpr", "attack_type": "xss", "run_status": "complete",
        "pr_url": "https://github.com/Iabdallllah/PenGuard/pull/9",
        "threat_flag": True,
    })
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TARGET_REPO", raising=False)
    r = client.post("/api/episodes/testpr/approve", headers=auth_headers)
    assert r.status_code == 503
