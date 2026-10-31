"""Phase 4 reliability unit tests: bounded retries, budget guard, timeouts."""
import pytest

import config
import orchestrator as orch
import reliability


class _Http503(Exception):
    status_code = 503


class _Http400(Exception):
    status_code = 400


def test_transient_error_retries_then_succeeds():
    calls = {"n": 0}
    delays = []

    def fn():
        calls["n"] += 1
        if calls["n"] < 3:
            raise _Http503("temporary")
        return "ok"

    result = reliability.invoke_with_retry(fn, attempts=3, base_delay=0.1, sleep=delays.append)
    assert result == "ok"
    assert calls["n"] == 3
    assert len(delays) == 2
    # exponential backoff, bounded
    assert delays[0] >= 0.1
    assert delays[1] >= 0.2


def test_non_transient_error_fails_fast():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise _Http400("bad request")

    with pytest.raises(_Http400):
        reliability.invoke_with_retry(fn, attempts=5, sleep=lambda _: None)
    assert calls["n"] == 1


def test_retries_are_bounded_and_raise_final_error():
    calls = {"n": 0}

    def fn():
        calls["n"] += 1
        raise TimeoutError("timeout")

    with pytest.raises(TimeoutError):
        reliability.invoke_with_retry(fn, attempts=3, base_delay=0.0, sleep=lambda _: None)
    assert calls["n"] == 3


def test_is_transient_classification():
    assert reliability.is_transient(_Http503())
    assert reliability.is_transient(TimeoutError())
    assert not reliability.is_transient(_Http400())
    assert not reliability.is_transient(ValueError("schema"))


def test_budget_guard_tokens(monkeypatch):
    monkeypatch.setattr(config, "MAX_TOKENS_PER_EPISODE", 100)
    monkeypatch.setattr(config, "MAX_COST_USD_PER_EPISODE", None)
    monkeypatch.setattr(orch, "_USAGE", {"prompt_tokens": 60, "completion_tokens": 50})
    assert orch._budget_exceeded() is True
    monkeypatch.setattr(orch, "_USAGE", {"prompt_tokens": 10, "completion_tokens": 10})
    assert orch._budget_exceeded() is False


def test_budget_guard_cost_only_when_priced(monkeypatch):
    monkeypatch.setattr(config, "MAX_TOKENS_PER_EPISODE", None)
    monkeypatch.setattr(config, "MAX_COST_USD_PER_EPISODE", 0.001)
    monkeypatch.setattr(orch, "_USAGE", {"prompt_tokens": 1000, "completion_tokens": 1000})
    # No prices => cost is None => not measurable => never invented.
    monkeypatch.setattr(config, "PRICE_PER_1K_IN_USD", None)
    monkeypatch.setattr(config, "PRICE_PER_1K_OUT_USD", None)
    assert orch._usage_cost_usd() is None
    assert orch._budget_exceeded() is False
    monkeypatch.setattr(config, "PRICE_PER_1K_IN_USD", 0.001)
    monkeypatch.setattr(config, "PRICE_PER_1K_OUT_USD", 0.001)
    assert orch._budget_exceeded() is True


def test_configured_llm_raises_budget_exceeded(monkeypatch):
    monkeypatch.setattr(config, "MAX_TOKENS_PER_EPISODE", 1)
    monkeypatch.setattr(orch, "_USAGE", {"prompt_tokens": 5, "completion_tokens": 5})
    monkeypatch.setattr(orch, "llm", object())
    monkeypatch.setattr(orch, "_usage_handler", object())
    with pytest.raises(orch.BudgetExceeded):
        orch._configured_llm()


def test_episode_timeout_config_is_explicit():
    assert config.EPISODE_TIMEOUT_SECONDS > 0
    assert config.LLM_TIMEOUT_SECONDS > 0
    assert config.TARGET_HTTP_TIMEOUT_SECONDS > 0
    assert config.SANDBOX_CONTROL_TIMEOUT_SECONDS > 0


def test_scoring_marks_budget_limited_never_clean(monkeypatch):
    monkeypatch.setattr(config, "MAX_TOKENS_PER_EPISODE", 1)
    monkeypatch.setattr(orch, "_USAGE", {"prompt_tokens": 100, "completion_tokens": 100})
    monkeypatch.setattr(orch, "store_episode_memory", lambda **_: None)
    state = {
        "episode_id": "budget-1",
        "scenario": "idor",
        "target_url": "http://x",
        "attack_plan": {"vulnerability_target": "IDOR", "target_endpoint": "http://x/api/user/102"},
        "http_status": 200,
        "response_body": "",
        "threat_detected": True,
        "vulnerability_type": "IDOR",
        "remediation": "",
        "patch_applied": True,
        "retest_status": 403,
        "detection_report": {"threat_detected": True},
        "node_latencies_ms": {},
    }
    out = orch.scoring_and_storage_node(state)
    assert out["outcome"] == "budget_limited"
    assert out["posture_score"] == 0.0
