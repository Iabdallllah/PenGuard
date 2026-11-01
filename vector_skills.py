"""Validated Markdown vector skills.

Skills are declarative metadata for the eight canonical vectors. They mirror
the deterministic fallback contracts (golden tests) and enrich both LLM prompts
and heuristic execution metadata. The fixed LangGraph pipeline remains the
source of truth; skills are additive guidance, enabled by default and
disable-able with ``PENGUARD_VECTOR_SKILLS_ENABLED=false``.

Skill files are Markdown with a small YAML-like front matter block. Parsing is
intentionally dependency-free and strict; malformed skills are rejected rather
than silently ignored when the feature is enabled.
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional

import config
from security_model import VECTOR_KEYS, normalize_scenario

REQUIRED_FIELDS = (
    "key",
    "label",
    "endpoint",
    "method",
    "vulnerability_target",
    "hardening_rule",
    "hypothesis",
)
VALID_METHODS = frozenset({"GET", "POST"})
_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)


class VectorSkillError(ValueError):
    """Raised when a Markdown skill fails validation while enabled."""


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value or value.lower() in ("null", "none", "~"):
        return None
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def parse_front_matter(text: str) -> Dict[str, Any]:
    match = _FRONT_MATTER.match(text or "")
    if not match:
        raise VectorSkillError("missing front matter block (--- ... ---)")
    data: Dict[str, Any] = {}
    for line in match.group(1).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise VectorSkillError(f"invalid front matter line: {line!r}")
        key, raw = line.split(":", 1)
        data[key.strip()] = _parse_scalar(raw)
    return data


def _skills_dir(directory: Optional[str] = None) -> str:
    return directory or config.VECTOR_SKILLS_DIR


def load_skills(directory: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """Load every ``*.md`` skill in ``directory`` keyed by canonical vector."""
    root = _skills_dir(directory)
    if not os.path.isdir(root):
        raise VectorSkillError(f"skills directory not found: {root}")
    skills: Dict[str, Dict[str, Any]] = {}
    for name in sorted(os.listdir(root)):
        if not name.endswith(".md"):
            continue
        path = os.path.join(root, name)
        with open(path, "r", encoding="utf-8") as handle:
            data = parse_front_matter(handle.read())
        key = normalize_scenario(str(data.get("key") or ""))
        if not key:
            raise VectorSkillError(f"{name}: missing key")
        if key in skills:
            raise VectorSkillError(f"{name}: duplicate skill key {key!r}")
        data["key"] = key
        data["_file"] = name
        skills[key] = data
    return skills


def validate_skills(skills: Dict[str, Dict[str, Any]]) -> List[str]:
    """Raise ``VectorSkillError`` on invalid content; return no warnings on success."""
    unknown = sorted(set(skills) - set(VECTOR_KEYS))
    missing = sorted(set(VECTOR_KEYS) - set(skills))
    if unknown:
        raise VectorSkillError(f"unknown vector skill keys: {unknown}")
    if missing:
        raise VectorSkillError(f"missing vector skills: {missing}")
    for key, skill in skills.items():
        for field in REQUIRED_FIELDS:
            if skill.get(field) in (None, ""):
                raise VectorSkillError(f"{skill.get('_file', key)}: missing {field}")
        method = str(skill["method"]).upper()
        if method not in VALID_METHODS:
            raise VectorSkillError(f"{skill['_file']}: invalid method {skill['method']!r}")
        skill["method"] = method
        endpoint = str(skill["endpoint"])
        if not endpoint.startswith("/"):
            raise VectorSkillError(f"{skill['_file']}: endpoint must start with '/'")
        rule = str(skill["hardening_rule"])
        if rule != "none" and not rule.startswith("block_"):
            raise VectorSkillError(f"{skill['_file']}: invalid hardening_rule {rule!r}")
        payload = skill.get("payload_json")
        if payload not in (None, ""):
            try:
                json.loads(payload)
            except (TypeError, ValueError) as exc:
                raise VectorSkillError(
                    f"{skill['_file']}: payload_json is not valid JSON ({exc})"
                ) from exc
        status = skill.get("detection_status")
        if status is not None:
            try:
                status_int = int(status)
            except (TypeError, ValueError) as exc:
                raise VectorSkillError(f"{skill['_file']}: invalid detection_status") from exc
            if not 100 <= status_int <= 599:
                raise VectorSkillError(f"{skill['_file']}: detection_status out of range")
    return []


def validate_or_warn(directory: Optional[str] = None) -> List[str]:
    """Validate skills at startup.

    When the feature is disabled, problems are warnings (pipeline unchanged).
    When enabled, invalid or missing skills fail closed with ``RuntimeError``.
    """
    try:
        skills = load_skills(directory)
        validate_skills(skills)
    except Exception as exc:
        if config.VECTOR_SKILLS_ENABLED:
            raise RuntimeError(
                f"PENGUARD_VECTOR_SKILLS_ENABLED is enabled but invalid: {exc}"
            ) from exc
        return [f"vector skills not loaded ({exc}); deterministic fallbacks remain active"]
    if not config.VECTOR_SKILLS_ENABLED:
        return [f"vector skills validated ({len(skills)}/8) but disabled (PENGUARD_VECTOR_SKILLS_ENABLED=false)"]
    return []


def _tactics(raw: Any) -> List[str]:
    if isinstance(raw, (list, tuple)):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return []


def skill_playbook(skill: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return stable, additive playbook metadata for prompts and evidence."""
    if not skill:
        return None
    key = normalize_scenario(str(skill.get("key") or ""))
    return {
        "skill_id": skill.get("skill_id") or f"penguard-{key or 'unknown'}-v1",
        "label": skill.get("label"),
        "source_file": skill.get("_file"),
        "tactics_applied": _tactics(skill.get("tactics_applied")),
        "verification_rule": skill.get("verification_rule") or f"verify: {skill.get('hypothesis', '')}".strip(),
        "baseline_rule": skill.get("baseline_rule"),
        "exploit_rule": skill.get("exploit_rule"),
        "owasp": skill.get("owasp"),
        "hypothesis": skill.get("hypothesis"),
        "hardening_rule": skill.get("hardening_rule"),
    }


def skill_prompt_context(skill: Optional[Dict[str, Any]]) -> str:
    """Render a compact playbook block for LLM system prompts."""
    playbook = skill_playbook(skill)
    if not playbook:
        return ""
    parts = [
        f"Active vector skill: {playbook['skill_id']} ({playbook.get('label') or playbook['skill_id']}).",
        f"Tactics: {', '.join(playbook['tactics_applied']) or 'probe, detect, harden, retest'}.",
        f"Verification rule: {playbook['verification_rule']}.",
    ]
    if playbook.get("baseline_rule"):
        parts.append(f"Baseline rule: {playbook['baseline_rule']}.")
    if playbook.get("exploit_rule"):
        parts.append(f"Exploit rule: {playbook['exploit_rule']}.")
    if skill and skill.get("baseline_endpoint"):
        parts.append(
            f"Benign baseline probe: {skill.get('baseline_method') or skill.get('method') or 'GET'} "
            f"{skill['baseline_endpoint']}."
        )
    return " ".join(parts)


def skill_for(scenario: str, directory: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Return a validated skill for a scenario, or ``None`` if unavailable."""
    key = normalize_scenario(scenario)
    if not key:
        return None
    try:
        skills = load_skills(directory)
        validate_skills(skills)
    except Exception:
        return None
    return skills.get(key)
