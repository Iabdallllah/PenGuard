"""Markdown vector skills: validation, rejection, and parity with fallbacks."""
import json

import pytest

import config
import orchestrator as orch
import vector_skills
from security_model import VECTOR_KEYS


def test_all_eight_skills_load_and_validate():
    skills = vector_skills.load_skills()
    assert set(skills) == set(VECTOR_KEYS)
    assert vector_skills.validate_skills(skills) == []
    for key, skill in skills.items():
        assert skill["endpoint"].startswith("/")
        assert skill["method"] in ("GET", "POST")
        payload = skill.get("payload_json")
        if payload is not None:
            json.loads(payload)


def test_skill_unknown_key_rejected(tmp_path):
    (tmp_path / "bad.md").write_text(
        "---\nkey: not_a_vector\nlabel: Bad\nendpoint: /api/bad\nmethod: GET\n"
        "vulnerability_target: Bad\npayload_json: null\nhardening_rule: none\n"
        "hypothesis: bad\n---\n# Bad\n",
        encoding="utf-8",
    )
    skills = vector_skills.load_skills(str(tmp_path))
    with pytest.raises(vector_skills.VectorSkillError):
        vector_skills.validate_skills(skills)


def test_skill_missing_field_rejected(tmp_path):
    (tmp_path / "bad.md").write_text(
        "---\nkey: idor\nlabel: IDOR\nendpoint: /api/user/102\nmethod: GET\n---\n# IDOR\n",
        encoding="utf-8",
    )
    skills = vector_skills.load_skills(str(tmp_path))
    with pytest.raises(vector_skills.VectorSkillError):
        vector_skills.validate_skills(skills)


def test_skill_invalid_payload_json_rejected(tmp_path):
    content = {
        "key": "idor",
        "label": "IDOR",
        "endpoint": "/api/user/102",
        "method": "GET",
        "vulnerability_target": "IDOR",
        "payload_json": "{not json",
        "hardening_rule": "block_unauthorized_idor",
        "hypothesis": "x",
    }
    lines = "\n".join(f"{k}: {v}" for k, v in content.items())
    (tmp_path / "bad.md").write_text(f"---\n{lines}\n---\n# Bad\n", encoding="utf-8")
    skills = vector_skills.load_skills(str(tmp_path))
    with pytest.raises(vector_skills.VectorSkillError):
        vector_skills.validate_skills(skills)


def test_invalid_skills_warn_when_disabled(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VECTOR_SKILLS_ENABLED", False)
    warnings = vector_skills.validate_or_warn(str(tmp_path))
    assert warnings and "fallbacks remain active" in warnings[0]


def test_invalid_skills_fail_closed_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VECTOR_SKILLS_ENABLED", True)
    with pytest.raises(RuntimeError):
        vector_skills.validate_or_warn(str(tmp_path))


def test_disabled_skills_preserve_builtin_fallback(monkeypatch):
    monkeypatch.setattr(config, "VECTOR_SKILLS_ENABLED", False)
    plan = orch._fallback_attack_plan("idor", "http://x", "")
    assert plan["hypothesis"] == "Direct object reference without authorization"


def test_skill_lookup_unknown_scenario_returns_none():
    assert vector_skills.skill_for("not-a-vector") is None
