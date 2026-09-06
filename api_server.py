import os
import asyncio
import subprocess
import uuid
import traceback
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from orchestrator import app_graph, sandbox

app = FastAPI(title="PenGuard Engine API")

# Prometheus metrics — always exposed at /metrics (free, no env needed)
try:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator(should_group_status_codes=False, should_ignore_untemplated=True).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
    print("[metrics] Prometheus /metrics enabled")
except Exception as _e:
    print(f"[metrics] instrumentator not enabled: {_e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_STORE_PATH = os.path.join(os.path.dirname(__file__), "episodes_store.json")

def _load_episodes() -> List[Dict[str, Any]]:
    if os.path.exists(_STORE_PATH):
        try:
            with open(_STORE_PATH, encoding="utf-8") as f:
                data = f.read().strip()
                if not data:
                    return []
                j = __import__("json").loads(data)
                if isinstance(j, list):
                    return j
        except Exception as e:
            print(f"[store] load failed: {e}")
    return []

def _save_episodes():
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            __import__("json").dump(episodes_db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[store] save failed: {e}")

episodes_db: List[Dict[str, Any]] = _load_episodes()

# ── Scenario normalization (UI ↔ orchestrator) ──
# UI uses: idor, sql_injection, business_logic, xss
# Orchestrator vulnerability_target: IDOR, SQL Injection, Business Logic Abuse, XSS
VULN_TO_SCENARIO = {
    "idor": "idor",
    "sql injection": "sql_injection",
    "sql_injection": "sql_injection",
    "business logic abuse": "business_logic",
    "business_logic": "business_logic",
    "xss": "xss",
    "cross site scripting": "xss",
    "cross-site scripting": "xss",
}
SCENARIO_TO_LABEL = {
    "idor": "IDOR",
    "sql_injection": "SQL Injection",
    "business_logic": "Business Logic Abuse",
    "xss": "XSS",
}
ALLOWED_SCENARIOS = {"idor", "sql_injection", "business_logic", "xss"}
# Production: TARGET_URL env (e.g. https://purple-target.onrender.com) or fallback to local TARGET_PORT
TARGET_URL_ENV = os.getenv("TARGET_URL", "").strip()
TARGET_PORT_ENV = os.getenv("TARGET_PORT", "8001")
SANDBOX_DEFAULT_URL = (TARGET_URL_ENV.rstrip("/") if TARGET_URL_ENV else f"http://127.0.0.1:{TARGET_PORT_ENV}")

class RunRequest(BaseModel):
    scenario: str = "sql_injection"
    target_url: Optional[str] = None

def _normalize_scenario(s: str) -> str:
    s = (s or "").strip().lower()
    if s in VULN_TO_SCENARIO:
        return VULN_TO_SCENARIO[s]
    # handle raw forms like "SQL Injection" with case
    key = s.replace("_", " ").lower()
    return VULN_TO_SCENARIO.get(key, "idor")

def _normalize_attack_type_for_ui(vuln_target: Optional[str], scenario_fallback: str) -> str:
    """Return scenario key for UI so SCENARIOS[attack_type] resolves correctly."""
    if vuln_target:
        k = vuln_target.strip().lower().replace("_", " ")
        if k in VULN_TO_SCENARIO:
            return VULN_TO_SCENARIO[k]
    return _normalize_scenario(scenario_fallback)

def _build_logs(result: Dict[str, Any], base_url: str, duration_ms: int) -> List[str]:
    logs: List[str] = []
    logs.append(f"[{datetime.utcnow().isoformat()}Z] Episode {result.get('episode_id')} initiated · scenario={result.get('scenario')} · target={base_url}")
    if result.get("past_memory"):
        logs.append(f"[memory] Context retrieved: {str(result.get('past_memory'))[:180]}")
    if result.get("recon_data"):
        rd = result["recon_data"]
        logs.append(f"[recon] surface={rd.get('target_surface')} vuln={rd.get('suspected_vulnerability')} param={rd.get('target_parameter')}")
    if result.get("attack_plan"):
        ap = result["attack_plan"]
        logs.append(f"[exploit] {ap.get('http_method')} {ap.get('target_endpoint')} payload={ap.get('payload_json') or '—'}")
    if result.get("http_status") is not None:
        logs.append(f"[probe] initial status={result.get('http_status')} body={str(result.get('response_body'))[:240]}")
    if result.get("detection_report"):
        dr = result["detection_report"]
        logs.append(f"[detection] threat={dr.get('threat_detected')} type={dr.get('vulnerability_type')} confidence={dr.get('confidence_score')} findings={dr.get('technical_findings','')[:180]}")
    if result.get("hardening_plan"):
        hp = result["hardening_plan"]
        logs.append(f"[hardening] rule={hp.get('target_rule_name')} action={hp.get('mitigation_action')}")
    logs.append(f"[patch] applied={result.get('patch_applied')} retest_status={result.get('retest_status')}")
    logs.append(f"[score] posture={result.get('posture_score')} duration={duration_ms}ms")
    # sandbox container logs if available
    try:
        s_logs = sandbox.get_logs()
        if s_logs:
            # take last 8 lines to avoid flooding
            for line in s_logs[-8:]:
                logs.append(f"[sandbox] {line.strip()}")
    except Exception:
        pass
    return logs

@app.get("/api/health")
def health():
    return {"status": "ok", "episodes": len(episodes_db), "time": datetime.utcnow().isoformat() + "Z"}

@app.get("/api/scenarios")
def list_scenarios():
    return [
        {"key": "idor", "label": "IDOR / Broken Access Control", "owasp": "A01:2021"},
        {"key": "sql_injection", "label": "SQL Injection", "owasp": "A03:2021"},
        {"key": "business_logic", "label": "Business Logic Abuse", "owasp": "A04:2021"},
        {"key": "xss", "label": "Cross-Site Scripting (XSS)", "owasp": "A03:2021"},
    ]

@app.get("/api/episodes")
def get_episodes():
    return episodes_db

@app.get("/api/episodes/{episode_id}")
def get_episode(episode_id: str):
    for ep in episodes_db:
        if ep["id"] == episode_id:
            return ep
    raise HTTPException(status_code=404, detail="Episode not found")

# WebSocket real-time — replaces 5s polling when available
connected_ws: set = set()

@app.websocket("/ws/episodes")
async def ws_episodes(ws: WebSocket):
    await ws.accept()
    connected_ws.add(ws)
    try:
        await ws.send_json(episodes_db)
        while True:
            await asyncio.sleep(30)
            # keepalive
            try:
                await ws.send_json({"type": "ping", "count": len(episodes_db)})
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        connected_ws.discard(ws)

async def broadcast_episodes():
    dead = set()
    for ws in list(connected_ws):
        try:
            await ws.send_json(episodes_db)
        except Exception:
            dead.add(ws)
    for ws in dead:
        connected_ws.discard(ws)

@app.get("/api/reports/compliance")
def get_compliance_report():
    pdf_path = os.path.abspath("purple-web-executive-audit-report.pdf")
    html_path = os.path.abspath("compliance_report.html")

    if not os.path.exists(pdf_path):
        # try generate via create_report.py (brave) -> fallback to generate_pdf.py (weasyprint) -> fallback minimal
        generated = False
        for script in ["create_report.py", "generate_pdf.py"]:
            if os.path.exists(script):
                try:
                    subprocess.run(["python", script], check=True, timeout=30)
                    if os.path.exists(pdf_path):
                        generated = True
                        break
                except Exception as e:
                    print(f"[compliance] {script} failed: {e}")
                    continue
        if not generated and os.path.exists(html_path) and not os.path.exists(pdf_path):
            # fallback: try weasyprint directly if available
            try:
                import weasyprint
                with open(html_path, encoding="utf-8") as f:
                    html = f.read()
                weasyprint.HTML(string=html).write_pdf(pdf_path)
                generated = True
            except Exception as e:
                print(f"[compliance] weasyprint fallback failed: {e}")

    if not os.path.exists(pdf_path):
        raise HTTPException(status_code=500, detail="Compliance report generation failed - no PDF available")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename="purple-web-executive-audit-report.pdf",
        headers={
            "Content-Disposition": "attachment; filename=purple-web-executive-audit-report.pdf",
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )

@app.post("/api/episodes/run")
async def trigger_run(payload: RunRequest):
    started = datetime.utcnow()
    # normalize scenario to allowed keys
    scenario_norm = _normalize_scenario(payload.scenario)
    if scenario_norm not in ALLOWED_SCENARIOS:
        raise HTTPException(status_code=400, detail=f"Invalid scenario '{payload.scenario}'. Allowed: {ALLOWED_SCENARIOS}")

    # Determine target handling: empty or sandbox default => use isolated sandbox lifecycle
    raw_target = (payload.target_url or "").strip()
    # treat explicit sandbox URL as sandbox request (not custom external)
    is_sandbox_request = False
    if not raw_target:
        is_sandbox_request = True
    elif raw_target.rstrip("/") == SANDBOX_DEFAULT_URL:
        is_sandbox_request = True
    else:
        # validate URL format for custom targets
        try:
            from urllib.parse import urlparse
            parsed = urlparse(raw_target)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError("missing scheme/netloc")
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid target_url: {raw_target}")

    base_url: str
    used_sandbox = False
    try:
        if is_sandbox_request:
            # Try sandbox container; fallback to direct target_app if docker unavailable
            try:
                sandbox.build_image()
                base_url = sandbox.reset_state(host_port=8001)
                used_sandbox = True
            except Exception as e:
                print(f"[sandbox] container unavailable, fallback to direct {SANDBOX_DEFAULT_URL}: {e}")
                traceback.print_exc()
                base_url = SANDBOX_DEFAULT_URL
                used_sandbox = False

            # For fallback (no container), ensure clean state before probe
            if not used_sandbox:
                try:
                    import requests as _rq
                    _rq.post(f"{SANDBOX_DEFAULT_URL}/admin/reset-mitigation", timeout=2)
                    print("[sandbox] fallback reset complete")
                except Exception as _e:
                    print(f"[sandbox] fallback reset failed: {_e}")
        else:
            base_url = raw_target.rstrip("/")

        ep_id = str(uuid.uuid4())[:8]

        initial_state = {
            "episode_id": ep_id,
            "scenario": scenario_norm,
            "target_url": base_url,
            "past_memory": "",
            "attack_plan": None,
            "http_status": None,
            "response_body": None,
            "threat_detected": None,
            "vulnerability_type": None,
            "remediation": None,
            "patch_applied": False,
            "retest_status": None,
            "posture_score": None
        }

        result = await asyncio.to_thread(app_graph.invoke, initial_state)

        ended = datetime.utcnow()
        duration_ms = int((ended - started).total_seconds() * 1000)

        # build UI-compatible record
        raw_attack = result.get("attack_plan", {}).get("vulnerability_target") if result.get("attack_plan") else None
        attack_type_ui = _normalize_attack_type_for_ui(raw_attack, scenario_norm)

        # prefer endpoint path stripping base_url for brevity? keep full endpoint for UI
        target_endpoint = result.get("attack_plan", {}).get("target_endpoint") if result.get("attack_plan") else base_url

        logs = _build_logs(result, base_url, duration_ms)

        record = {
            "id": result.get("episode_id", ep_id),
            "target": target_endpoint or base_url,
            "attack_type": attack_type_ui,
            "attack_label": SCENARIO_TO_LABEL.get(attack_type_ui, raw_attack or attack_type_ui),
            "status": result.get("http_status") or 0,
            "retest_status": result.get("retest_status"),
            "patch_applied": bool(result.get("patch_applied", False)),
            "threat_flag": bool(result.get("threat_detected", False)),
            "score": float(result.get("posture_score") or 0),
            "remediation": result.get("remediation") or "",
            "logs": logs,
            "timestamp": ended.isoformat() + "Z",
            "duration_ms": duration_ms,
            "scenario": scenario_norm,
            "base_url": base_url,
            "pr_url": result.get("pr_url"),
            # expose extra telemetry for inspector without breaking UI
            "recon_data": result.get("recon_data"),
            "detection_report": result.get("detection_report"),
            "hardening_plan": result.get("hardening_plan"),
            "response_body": (str(result.get("response_body") or "")[:2000]),
        }

        episodes_db.append(record)
        _save_episodes()
        try:
            await broadcast_episodes()
        except Exception:
            pass

        if used_sandbox:
            try:
                sandbox.stop_container()
            except Exception:
                pass

        return {"status": "complete", "episode": record}
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        # ensure sandbox cleanup on error if we started it
        if 'used_sandbox' in locals() and used_sandbox:
            try:
                sandbox.stop_container()
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=str(e))