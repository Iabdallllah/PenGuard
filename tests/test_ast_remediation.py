"""AST remediation: all eight vectors, syntax validation, and safe fallback."""
import ast
from pathlib import Path

import pytest

import remediator

TARGET_APP = Path(__file__).resolve().parents[1] / "target_app.py"

VECTOR_EXPECTATIONS = {
    "idor": ("get_user_profile", "Bearer admin-valid-token"),
    "sql_injection": ("search_records", "LIKE ?"),
    "business_logic": ("process_checkout", "server invariant"),
    "xss": ("search_xss", "html.escape(q, quote=True)"),
    "csrf": ("transfer", "valid-csrf-token"),
    "ssrf": ("fetch_ssrf", "Forbidden: SSRF blocked - private address"),
    "broken_auth": ("login", "admin password policy"),
    "misconfig": ("debug_info", "Debug endpoint disabled in production"),
}


@pytest.mark.parametrize("scenario", sorted(VECTOR_EXPECTATIONS))
def test_ast_patch_is_generated_and_syntax_valid(scenario):
    function, marker = VECTOR_EXPECTATIONS[scenario]
    original = TARGET_APP.read_text(encoding="utf-8")

    result = remediator.remediate_source(scenario, original)

    assert result["engine"] == "python-ast"
    assert result["scenario"] == scenario
    assert result["function"] == function
    assert result["applied"] is True
    assert result["ast_verified"] is True
    assert result["transformed_nodes"], "AST metadata must list transformed nodes"
    assert any(function in label for label in result["transformed_nodes"])
    assert marker in result["patch"]
    # The generated patch itself must survive a full parse round-trip.
    ast.parse(result["patch"])
    assert result["patch_sha256"] != result["original_sha256"]


def test_non_python_input_falls_back_without_fabricating_a_patch():
    source = "this is not { valid python"
    result = remediator.remediate_source("xss", source)

    assert result["applied"] is False
    assert result["ast_verified"] is False
    assert result["patch"] == source
    assert result["transformed_nodes"] == []
    assert result["fallback_reason"] == "non-python-input"


def test_missing_target_function_is_a_safe_no_op():
    result = remediator.remediate_source("ssrf", "def unrelated():\n    return 1\n")

    assert result["applied"] is False
    assert result["ast_verified"] is False
    assert result["fallback_reason"] == "function-not-found"
    ast.parse(result["patch"])


def test_unknown_scenario_is_a_safe_no_op():
    result = remediator.remediate_source("not-a-vector", "def f():\n    return 1\n")
    assert result["applied"] is False
    assert result["fallback_reason"] == "unsupported-scenario"
