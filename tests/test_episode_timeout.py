"""Episode execution failure paths: timeout and budget-limited outcomes.

These exercise the real ``_execute_episode`` coroutine with a stubbed graph so
the persistence/broadcast side effects are the ones under test. Timeouts must
never leave a run looking clean or complete.
"""
import asyncio
import time

import pytest

import api_server
import config


class _DummyGraph:
    def __init__(self, result=None, delay=0.0):
        self.result = result or {}
        self.delay = delay

    def invoke(self, _state):
        if self.delay:
            time.sleep(self.delay)
        return self.result


@pytest.fixture()
def isolated_run(monkeypatch):
    """Keep the episode ledger and external side effects inside the test."""
    monkeypatch.setattr(api_server, "_save_episodes", lambda: None)
    monkeypatch.setattr(api_server, "_db_add_episode", lambda _record: None)
    monkeypatch.setattr(api_server, "_notify_webhook", lambda _record: None)

    async def _noop_broadcast():
        return None

    monkeypatch.setattr(api_server, "broadcast_episodes", _noop_broadcast)
    added_ids = set()

    def _add(ep_id):
        added_ids.add(ep_id)
        api_server.episodes_db.append(
            {"id": ep_id, "run_status": "QUEUED", "outcome": None, "score": None, "logs": []}
        )
        return ep_id

    def _find(ep_id):
        for e in api_server.episodes_db:
            if e.get("id") == ep_id:
                return e
        raise AssertionError(f"episode {ep_id} not found in ledger")

    def _cleanup():
        for e in list(api_server.episodes_db):
            if e.get("id") in added_ids:
                api_server.episodes_db.remove(e)

    try:
        yield _add, _find, _cleanup
    finally:
        _cleanup()
        api_server._run_in_progress = None


def test_episode_timeout_marks_interrupted_and_zero(isolated_run, monkeypatch):
    _add, _find, _cleanup = isolated_run
    ep_id = _add("timeout-episode")
    record = _find(ep_id)
    monkeypatch.setattr(api_server, "app_graph", _DummyGraph({"ignored": True}, delay=0.3))
    monkeypatch.setattr(config, "EPISODE_TIMEOUT_SECONDS", 0.05)
    api_server._run_in_progress = ep_id

    asyncio.run(api_server._execute_episode(ep_id, "idor", "http://127.0.0.1:9", False))

    assert record["run_status"] == "timeout"
    assert record["outcome"] == "interrupted"
    assert record["score"] == 0.0
    assert any("episode budget" in line for line in record["logs"])
    assert any("never clean" in line for line in record["logs"])
    # The single-flight guard must be released even on timeout.
    assert api_server._run_in_progress is None


def test_episode_timeout_fires_for_runtime_config(isolated_run, monkeypatch):
    _add, _find, _cleanup = isolated_run
    ep_id = _add("timeout-episode-2")
    record = _find(ep_id)
    monkeypatch.setattr(api_server, "app_graph", _DummyGraph({}, delay=0.5))
    monkeypatch.setattr(config, "EPISODE_TIMEOUT_SECONDS", 0.02)

    asyncio.run(api_server._execute_episode(ep_id, "idor", "http://127.0.0.1:9", False))

    assert record["outcome"] == "interrupted"
    assert record["run_status"] == "timeout"
    assert "0.02s" in str(record["logs"])


def test_pipeline_budget_limited_outcome_is_preserved(isolated_run, monkeypatch):
    _add, _find, _cleanup = isolated_run
    ep_id = _add("budget-episode")
    record = _find(ep_id)
    result = {
        "episode_id": ep_id,
        "scenario": "idor",
        "attack_plan": {
            "vulnerability_target": "IDOR",
            "target_endpoint": "http://127.0.0.1:9/api/user/102",
            "http_method": "GET",
        },
        "http_status": 200,
        "response_body": "{}",
        "threat_detected": False,
        "vulnerability_type": "None",
        "remediation": "",
        "patch_applied": False,
        "retest_status": None,
        "posture_score": 0.0,
        "outcome": "budget_limited",
        "detection_report": {
            "threat_detected": False,
            "confidence_score": 0.0,
            "technical_findings": "budget exhausted before analysis",
        },
        "recon_data": {},
    }
    monkeypatch.setattr(api_server, "app_graph", _DummyGraph(result))

    asyncio.run(api_server._execute_episode(ep_id, "idor", "http://127.0.0.1:9", False))

    record = _find(ep_id)
    assert record["run_status"] == "complete"
    assert record["outcome"] == "budget_limited"
    assert record["score"] == 0.0
