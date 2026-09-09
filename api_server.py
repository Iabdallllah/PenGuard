import os
import asyncio
import subprocess
import uuid
import traceback
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Response
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from orchestrator import app_graph, sandbox

app = FastAPI(title="PenGuard API")

try:
    from prometheus_fastapi_instrumentator import Instrumentator

    Instrumentator().instrument(app)
    print("[metrics] Prometheus instrumented")
except Exception as _e:
    print(f"[metrics] instrument failed: {_e}")

from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

# Register both /metrics and /api/metrics to cover any proxy prefix
@app.get("/metrics", include_in_schema=False)
@app.get("/api/metrics", include_in_schema=False)
def metrics_endpoint():
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

print("[metrics] /metrics and /api/metrics enabled")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

_STORE_PATH = os.path.join(os.path.dirname(__file__), "episodes_store.json")

# --- DB with fallback ---
try:
    from database import SessionLocal, Episode as DBEpisode, PostureMetric, init_db, _db_available, engine
    _use_db = _db_available and engine is not None
    if _use_db:
        print(f"[database] using {str(engine.url).split('@')[-1][:40]}")
except Exception as _e:
    print(f"[database] import failed, fallback to JSON: {_e}")
    _use_db = False
    SessionLocal = None
    DBEpisode = None

def _load_episodes() -> List[Dict[str, Any]]:
    # Try DB first
    if _use_db and SessionLocal and DBEpisode:
        try:
            db = SessionLocal()
            rows = db.query(DBEpisode).order_by(DBEpisode.created_at).all()
            db.close()
            result = []
            for r in rows:
                result.append({
                    "id": r.id, "target": r.target, "attack_type": r.attack_type, "attack_label": r.attack_label,
                    "status": r.status, "retest_status": r.retest_status, "patch_applied": r.patch_applied,
                    "threat_flag": r.threat_flag, "score": r.score, "remediation": r.remediation,
                    "logs": r.logs or [], "timestamp": r.timestamp, "duration_ms": r.duration_ms,
                    "scenario": r.scenario, "base_url": r.base_url, "pr_url": r.pr_url,
                    "recon_data": r.recon_data, "detection_report": r.detection_report,
                    "hardening_plan": r.hardening_plan, "response_body": r.response_body,
                })
            if result:
                print(f"[store] loaded {len(result)} episodes from DB")
                return result
        except Exception as e:
            print(f"[store] DB load failed, fallback to JSON: {e}")
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
    # Save to DB if available, always also to JSON as backup
    if _use_db and SessionLocal and DBEpisode:
        try:
            db = SessionLocal()
            # For simplicity, clear and re-insert (small dataset < 1000)
            # In production, use upsert
            pass  # actual save is done per-episode in trigger_run
            db.close()
        except Exception as e:
            print(f"[store] DB save placeholder failed: {e}")
    try:
        with open(_STORE_PATH, "w", encoding="utf-8") as f:
            __import__("json").dump(episodes_db, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[store] save failed: {e}")

def _db_add_episode(record: Dict[str, Any]):
    if not (_use_db and SessionLocal and DBEpisode):
        return
    try:
        db = SessionLocal()
        # Upsert
        existing = db.query(DBEpisode).filter(DBEpisode.id == record["id"]).first()
        if existing:
            db.delete(existing)
            db.commit()
        ep = DBEpisode(
            id=record["id"], target=record.get("target"), attack_type=record.get("attack_type"),
            attack_label=record.get("attack_label"), status=record.get("status"), retest_status=record.get("retest_status"),
            patch_applied=record.get("patch_applied"), threat_flag=record.get("threat_flag"), score=record.get("score"),
            remediation=record.get("remediation"), logs=record.get("logs"), timestamp=record.get("timestamp"),
            duration_ms=record.get("duration_ms"), scenario=record.get("scenario"), base_url=record.get("base_url"),
            pr_url=record.get("pr_url"), recon_data=record.get("recon_data"), detection_report=record.get("detection_report"),
            hardening_plan=record.get("hardening_plan"), response_body=record.get("response_body")
        )
        db.add(ep)
        db.commit()
        # Also save posture metric
        try:
            pm = PostureMetric(posture_score=record.get("score", 0), total_episodes=len(episodes_db)+1, patched_count=sum(1 for e in episodes_db if e.get("patch_applied")))
            db.add(pm)
            db.commit()
        except Exception:
            pass
        db.close()
    except Exception as e:
        print(f"[database] add episode failed, fallback to JSON: {e}")

def _db_clear():
    if _use_db and SessionLocal and DBEpisode:
        try:
            db = SessionLocal()
            db.query(DBEpisode).delete()
            db.query(PostureMetric).delete()
            db.commit()
            db.close()
            print("[database] cleared")
        except Exception as e:
            print(f"[database] clear failed: {e}")

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
    "csrf": "csrf",
    "cross site request forgery": "csrf",
    "ssrf": "ssrf",
    "server side request forgery": "ssrf",
    "broken authentication": "broken_auth",
    "broken_auth": "broken_auth",
    "security misconfiguration": "misconfig",
    "misconfig": "misconfig",
    "misconfiguration": "misconfig",
}
SCENARIO_TO_LABEL = {
    "idor": "IDOR",
    "sql_injection": "SQL Injection",
    "business_logic": "Business Logic Abuse",
    "xss": "XSS",
    "csrf": "CSRF",
    "ssrf": "SSRF",
    "broken_auth": "Broken Authentication",
    "misconfig": "Security Misconfiguration",
}
ALLOWED_SCENARIOS = {"idor", "sql_injection", "business_logic", "xss", "csrf", "ssrf", "broken_auth", "misconfig"}
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
        {"key": "csrf", "label": "Cross-Site Request Forgery (CSRF)", "owasp": "A01:2021"},
        {"key": "ssrf", "label": "Server-Side Request Forgery (SSRF)", "owasp": "A10:2021"},
        {"key": "broken_auth", "label": "Broken Authentication", "owasp": "A07:2021"},
        {"key": "misconfig", "label": "Security Misconfiguration", "owasp": "A05:2021"},
    ]

@app.get("/api/episodes")
def get_episodes():
    # Try DB first, fallback to memory
    if _use_db and SessionLocal and DBEpisode:
        try:
            db = SessionLocal()
            rows = db.query(DBEpisode).order_by(DBEpisode.created_at).all()
            db.close()
            if rows:
                return [
                    {
                        "id": r.id, "target": r.target, "attack_type": r.attack_type, "attack_label": r.attack_label,
                        "status": r.status, "retest_status": r.retest_status, "patch_applied": r.patch_applied,
                        "threat_flag": r.threat_flag, "score": r.score, "remediation": r.remediation,
                        "logs": r.logs or [], "timestamp": r.timestamp, "duration_ms": r.duration_ms,
                        "scenario": r.scenario, "base_url": r.base_url, "pr_url": r.pr_url,
                        "recon_data": r.recon_data, "detection_report": r.detection_report,
                        "hardening_plan": r.hardening_plan, "response_body": r.response_body,
                    }
                    for r in rows
                ]
        except Exception as e:
            print(f"[get] DB read failed: {e}")
    return episodes_db

@app.delete("/api/episodes")
async def clear_episodes():
    """Clear old records — solves 'old recordings still present' issue. Keeps filesystem clean."""
    count = len(episodes_db)
    episodes_db.clear()
    _save_episodes()
    _db_clear()
    # Clear Chroma episodic memory as well
    try:
        from memory_manager import collection, _chroma_available
        if _chroma_available and collection is not None:
            # Delete all ids by fetching
            try:
                # Chroma 0.5+ supports get with no args
                all_ids = collection.get().get("ids", [])
                if all_ids:
                    collection.delete(ids=all_ids)
            except Exception as e:
                print(f"[clear] chroma delete failed: {e}")
    except Exception as e:
        print(f"[clear] memory clear failed: {e}")
    try:
        await broadcast_episodes()
    except Exception:
        pass
    return {"status": "cleared", "deleted": count}

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

def _build_dynamic_html(episodes: List[Dict[str, Any]]) -> str:
    import html as _h
    n = len(episodes)
    patches = sum(1 for e in episodes if e.get("patch_applied"))
    avg_score = round(sum(e.get("score", 0) for e in episodes) / n) if n else 100
    # Build episode rows
    rows = ""
    remediation_blocks = ""
    for ep in episodes[-20:]:  # last 20 for brevity
        eid = _h.escape(ep.get("id", "")[:8])
        atk = _h.escape(ep.get("attack_label") or ep.get("attack_type", ""))
        tgt = _h.escape((ep.get("target") or "")[:60])
        init_s = ep.get("status", 0)
        retest_s = ep.get("retest_status") or "—"
        patch = "ACTIVE" if ep.get("patch_applied") else "NONE"
        # Determine final state
        final = "SECURED" if ep.get("patch_applied") and ep.get("retest_status") in [400, 401, 403] else ("VULNERABLE" if ep.get("threat_flag") else "CLEAN")
        rows += f"<tr><td class='mono'>{eid}</td><td><strong>{atk}</strong></td><td class='mono'>{tgt}</td><td><span class='tag-fail'>{init_s} OK</span></td><td><span class='tag-pass'>{retest_s}</span></td><td><span class='tag-active'>{patch}</span></td><td><span class='tag-pass'>{final}</span></td></tr>\n"
        # Remediation
        adv = _h.escape(ep.get("remediation", "")[:400])
        route = _h.escape(ep.get("target", ""))
        remediation_blocks += f"<div class='remediation-box'><div class='remediation-title'>Episode {eid} - {atk} Remediation</div><div class='remediation-route'>{route}</div><div class='callout-advisory'><strong>Engine Advisory:</strong> {adv}<br><strong>Patch:</strong> {patch} | <strong>Retest:</strong> {retest_s}</div></div>\n"
    if not rows:
        rows = "<tr><td colspan='7' style='text-align:center; padding:20px; color:#94a3b8;'>No episodes yet — dispatch a scenario to generate evidence.</td></tr>"
        remediation_blocks = "<p style='color:#64748b;'>No remediation data yet.</p>"
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
@page {{ size: A4; margin: 12mm 10mm; background-color: #0b0f19; }}
* {{ -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; box-sizing: border-box; }}
body {{ margin:0; padding:0; font-family: system-ui, -apple-system, sans-serif; color: #cbd5e1; background-color: #0b0f19; font-size: 8.5pt; line-height: 1.45; }}
.header-card {{ background: #111827; border: 1px solid #312e81; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px; }}
.title-main {{ font-size: 16pt; font-weight: 800; color: #ffffff; margin: 0 0 4px 0; }}
.badge {{ display: inline-block; background-color: #4c1d95; color: #c4b5fd; font-size: 7.5pt; font-weight: 700; text-transform: uppercase; padding: 2px 7px; border-radius: 4px; border: 1px solid #6d28d9; margin-right: 6px; }}
.meta-text {{ font-size: 8pt; color: #94a3b8; margin-top: 6px; }}
.meta-highlight {{ color: #38bdf8; font-family: monospace; }}
.kpi-table {{ width: 100%; border-collapse: separate; border-spacing: 6px 0; margin-bottom: 14px; }}
.kpi-card {{ background-color: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 8px; text-align: center; width: 25%; }}
.kpi-val {{ font-size: 14pt; font-weight: 800; font-family: monospace; margin: 2px 0; }}
.kpi-score {{ color: #a855f7; }} .kpi-success {{ color: #10b981; }} .kpi-indigo {{ color: #818cf8; }}
.kpi-lbl {{ font-size: 7pt; font-weight: 600; text-transform: uppercase; color: #64748b; }}
.kpi-sub {{ font-size: 6.5pt; color: #475569; }}
h2 {{ color: #f1f5f9; font-size: 10.5pt; font-weight: 700; border-left: 3px solid #8b5cf6; padding-left: 8px; margin: 14px 0 6px 0; text-transform: uppercase; }}
p {{ margin: 0 0 6px 0; color: #94a3b8; }}
table.data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 12px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; }}
table.data-table th {{ background-color: #1e293b; color: #e2e8f0; font-size: 7.5pt; font-weight: 700; text-transform: uppercase; padding: 6px 8px; text-align: left; border-bottom: 1px solid #334155; }}
table.data-table td {{ padding: 6px 8px; font-size: 8pt; border-bottom: 1px solid #1e293b; color: #cbd5e1; }}
.tag-pass {{ display: inline-block; padding: 2px 5px; background-color: #064e3b; color: #34d399; border: 1px solid #059669; border-radius: 3px; font-size: 7pt; font-weight: 700; font-family: monospace; }}
.tag-fail {{ display: inline-block; padding: 2px 5px; background-color: #4c0519; color: #f87171; border: 1px solid #dc2626; border-radius: 3px; font-size: 7pt; font-weight: 700; font-family: monospace; }}
.tag-active {{ display: inline-block; padding: 2px 5px; background-color: #31104b; color: #c084fc; border: 1px solid #7e22ce; border-radius: 3px; font-size: 7pt; font-weight: 700; font-family: monospace; }}
.mono {{ font-family: monospace; font-size: 7.5pt; color: #38bdf8; }}
.remediation-box {{ background-color: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 8px 10px; margin-bottom: 8px; }}
.remediation-title {{ font-weight: 700; font-size: 8.5pt; color: #f8fafc; margin-bottom: 4px; }}
.remediation-route {{ font-family: monospace; font-size: 7.5pt; color: #a5b4fc; background-color: #1e1b4b; padding: 2px 5px; border-radius: 4px; display: inline-block; margin-bottom: 4px; }}
.callout-advisory {{ font-size: 7.5pt; color: #cbd5e1; line-height: 1.4; background-color: #111827; border-left: 3px solid #10b981; padding: 5px 8px; border-radius: 0 4px 4px 0; margin-top: 4px; }}
</style></head><body>
<div class="header-card">
<span class="badge">SEC-OPS CERTIFIED</span><span class="badge" style="background:#064e3b; color:#34d399; border-color:#059669;">ZERO HUMAN INTERVENTION</span>
<h1 class="title-main">EXECUTIVE AUDIT & COMPLIANCE REPORT</h1>
<div class="meta-text"><strong>Platform:</strong> PenGuard Autonomous Hardening Core &bull; <strong>Engine:</strong> LangGraph Multi-Agent (2 Red + 2 Blue)<br>
<strong>Target:</strong> <span class="meta-highlight">Medical Portal Sandbox (FastAPI / Isolated Docker)</span> &bull; <strong>Generated At:</strong> {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC &bull; <strong>Episodes:</strong> {n}</div>
</div>
<table class="kpi-table"><tr>
<td class="kpi-card"><div class="kpi-lbl">Posture Score</div><div class="kpi-val kpi-score">{avg_score} / 100</div><div class="kpi-sub">Post-Remediation Verification</div></td>
<td class="kpi-card"><div class="kpi-lbl">Episodes Tested</div><div class="kpi-val kpi-indigo">{n} / 8</div><div class="kpi-sub">Vector Coverage</div></td>
<td class="kpi-card"><div class="kpi-lbl">Auto-Patches</div><div class="kpi-val kpi-success">{patches} Applied</div><div class="kpi-sub">Zero-Downtime Injection</div></td>
<td class="kpi-card"><div class="kpi-lbl">Automation Level</div><div class="kpi-val kpi-success">100%</div><div class="kpi-sub">Autonomous Closed-Loop</div></td>
</tr></table>
<h2>1. Executive Summary & Autonomous Workflow</h2>
<p>This audit was executed autonomously by the <strong>PenGuard Closed-Loop Cyber Hardening Core</strong>. Episodes are executed in an isolated sandbox with dynamic recon, exploit, detection, hardening and re-test.</p>
<h2>2. Episode Verification Ledger (Closed-Loop Evidence)</h2>
<table class="data-table"><thead><tr><th>Episode ID</th><th>Attack Vector</th><th>Target Endpoint</th><th>Initial Hit</th><th>Retest Hit</th><th>Auto-Patch</th><th>Final State</th></tr></thead><tbody>
{rows}
</tbody></table>
<h2>3. Technical Remediation & Hardening Ledger</h2>
{remediation_blocks}
<h2>4. Attestation & Continuous Assurance</h2>
<p>This digital audit report serves as verifiable attestation of continuous automated security posture management. Generated dynamically per operation on {datetime.utcnow().isoformat()}Z.</p>
</body></html>"""
    return html

@app.get("/api/reports/compliance")
def get_compliance_report():
    # Dynamic per-operation: always regenerate from current episodes_db
    pdf_path = os.path.abspath("penguard-executive-audit-report.pdf")
    # Keep legacy path for compatibility
    legacy_pdf = os.path.abspath("purple-web-executive-audit-report.pdf")
    html = _build_dynamic_html(episodes_db)
    html_path = os.path.abspath("compliance_report.html")
    try:
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
    except Exception:
        pass
    # Try weasyprint first (lightweight, no browser)
    try:
        import weasyprint
        weasyprint.HTML(string=html).write_pdf(pdf_path)
        # Also keep legacy copy for old endpoint consumers
        try:
            import shutil
            shutil.copy(pdf_path, legacy_pdf)
        except Exception:
            pass
    except Exception as e:
        print(f"[compliance] weasyprint failed: {e}")
        # Fallback to brave if available
        try:
            cmd = ["brave-browser", "--headless=new", "--disable-gpu", "--no-pdf-header-footer", f"--print-to-pdf={pdf_path}", f"file://{html_path}"]
            subprocess.run(cmd, check=True, timeout=30)
        except Exception as e2:
            print(f"[compliance] fallback failed: {e2}")
            raise HTTPException(status_code=500, detail="Compliance report generation failed")
    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename="penguard-executive-audit-report.pdf",
        headers={
            "Content-Disposition": "attachment; filename=penguard-audit-report.pdf",
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

            # Ensure clean state before probe (for both Docker and fallback) — fixes sqli/xss staying blocked
            try:
                import requests as _rq
                reset_url = base_url if used_sandbox else SANDBOX_DEFAULT_URL
                _rq.post(f"{reset_url}/admin/reset-mitigation", timeout=2)
                print(f"[sandbox] reset complete for {reset_url}")
            except Exception as _e:
                print(f"[sandbox] reset failed: {_e}")
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
        _db_add_episode(record)
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