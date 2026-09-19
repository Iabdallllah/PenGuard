"""Safety guards: crypto probe never raises, reflection router bounded, 202 wiring."""
import api_server
import orchestrator as orch


def test_crypto_posture_never_raises():
    for url in ("", "http://127.0.0.1:9", "not-a-url", "https://127.0.0.1:9"):
        out = orch._crypto_posture_check(url)
        assert isinstance(out, str) and out.startswith("Crypto-posture:")


def test_reflection_router():
    base = {"threat_detected": True, "patch_applied": True, "vulnerability_type": "XSS"}
    assert orch._route_after_retest({**base, "retest_status": 200, "reflection_attempts": 0}) == "reflect"
    assert orch._route_after_retest({**base, "retest_status": 403, "reflection_attempts": 0}) == "score"
    assert orch._route_after_retest({**base, "retest_status": 200, "reflection_attempts": 3}) == "score"
    assert orch._route_after_retest({"threat_detected": False, "patch_applied": False,
                                     "retest_status": None, "reflection_attempts": 0}) == "score"


def test_run_202_with_mocked_pipeline(client, auth_headers, clean_ledger, monkeypatch):
    async def fake_execute(ep_id, scenario_norm, custom_target, is_sandbox_request):
        for i, e in enumerate(api_server.episodes_db):
            if e.get("id") == ep_id:
                e.update({"run_status": "complete", "status": 200, "retest_status": 403,
                          "patch_applied": True, "threat_flag": True})
                api_server.episodes_db[i] = e
        api_server._run_in_progress = None

    monkeypatch.setattr(api_server, "_execute_episode", fake_execute)
    r = client.post("/api/episodes/run", json={"scenario": "xss"}, headers=auth_headers)
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "QUEUED" and body["episode_id"]
    # TestClient drains background tasks: placeholder already completed in place
    ep = client.get(f"/api/episodes/{body['episode_id']}").json()
    assert ep["run_status"] == "complete"
    assert ep["retest_status"] == 403


def test_run_concurrency_guard(client, auth_headers, clean_ledger):
    api_server.episodes_db.append({"id": "busy1", "run_status": "RUNNING"})
    api_server._run_in_progress = "busy1"
    r = client.post("/api/episodes/run", json={"scenario": "xss"}, headers=auth_headers)
    assert r.status_code == 409


def test_custom_target_offline_completes(client, auth_headers, clean_ledger):
    # Closed port: pipeline must complete (status 0) without NameError
    r = client.post("/api/episodes/run",
                    json={"scenario": "idor", "target_url": "http://127.0.0.1:9"},
                    headers=auth_headers)
    assert r.status_code == 202
    ep = client.get(f"/api/episodes/{r.json()['episode_id']}").json()
    assert ep["run_status"] == "complete"
    assert "NameError" not in str(ep.get("logs"))


def test_invalid_target_rejected(client, auth_headers):
    r = client.post("/api/episodes/run", json={"scenario": "xss", "target_url": "not-a-url"},
                    headers=auth_headers)
    assert r.status_code == 400
