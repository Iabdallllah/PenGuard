"""Operational transparency: seals, security.txt, FinOps, explainability."""
import re

import api_server
import orchestrator as orch


def test_seal_roundtrip(client, auth_headers, clean_ledger):
    assert client.post("/api/reports/seal").status_code == 401
    r = client.post("/api/reports/seal", headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert re.fullmatch(r"[0-9a-f]{64}", body["hash"])
    assert body["persisted"] is True
    v = client.get(f"/api/reports/verify/{body['hash']}")
    assert v.status_code == 200
    assert v.json()["match"] is True
    assert v.json()["report"]["version"] == "2.1.0"
    assert client.get("/api/reports/verify/" + "0" * 64).status_code == 404


def test_security_txt(client):
    r = client.get("/.well-known/security.txt")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    for field in ("Contact:", "Expires:", "Policy:", "Canonical:"):
        assert field in r.text


def test_pdf_footer_seal_line():
    html = api_server._build_dynamic_html([])
    assert "Audit Seal (SHA-256)" in html


def test_explainability_helper():
    result = {"detection_report": {"confidence_score": 0.96},
              "hardening_plan": {"target_rule_name": "block_csrf"},
              "remediation": "Enforce tokens."}
    ex = api_server._build_explainability(result)
    assert ex == {"confidence": 0.96, "confidence_source": "heuristic-fallback",
                  "rule": "block_csrf", "rationale": "Enforce tokens."}


def test_inference_metrics_fallback_shape():
    state = {"episode_id": "t", "scenario": "idor", "target_url": "http://x",
             "attack_plan": {"vulnerability_target": "IDOR", "target_endpoint": "http://x/api/user/102"},
             "http_status": 200, "response_body": "", "threat_detected": True,
             "vulnerability_type": "IDOR", "remediation": "", "patch_applied": True,
             "retest_status": 403, "node_latencies_ms": {"red_recon": 2.5}}
    out = orch.scoring_and_storage_node(state)
    im = out["inference_metrics"]
    assert im["mode"] == "fallback-deterministic"
    assert im["model"] is None
    assert im["tokens_prompt"] is None and im["tokens_measured"] is False
    assert im["estimated_cost_usd"] is None
    assert im["node_latencies_ms"]["red_recon"] == 2.5
