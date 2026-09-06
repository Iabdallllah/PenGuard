import os
import uuid
import json
import requests
from typing import TypedDict, Optional, Dict, Any
from pydantic import BaseModel, Field
from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from memory_manager import store_episode_memory, retrieve_past_context
from sandbox_manager import SandboxManager

sandbox = SandboxManager()

# ── Groq LLM lazy init with graceful fallback (no API key => mock) ──
def _get_llm():
    api_key = os.getenv("GROQ_API_KEY") or os.getenv("GROQ_APIKEY")
    if not api_key:
        return None
    try:
        from langchain_groq import ChatGroq
        return ChatGroq(model_name="openai/gpt-oss-20b", temperature=0)
    except Exception as e:
        print(f"[orchestrator] Groq init failed, fallback to mock: {e}")
        return None

llm = _get_llm()

# ── Deterministic fallbacks mirroring system prompts ──
def _fallback_recon(scenario: str):
    if scenario == "sql_injection":
        return {"target_surface": "/api/records", "suspected_vulnerability": "SQL Injection", "target_parameter": "query", "recon_notes": "Dynamic search query endpoint"}
    elif scenario == "business_logic":
        return {"target_surface": "/api/checkout", "suspected_vulnerability": "Business Logic Abuse", "target_parameter": "quantity, unit_price", "recon_notes": "Order processing calculation route"}
    else:
        return {"target_surface": "/api/user/102", "suspected_vulnerability": "IDOR", "target_parameter": "user_id", "recon_notes": "Direct object identifier parameter"}

def _fallback_attack_plan(scenario: str, base_url: str, vuln: str):
    # vuln is from recon suspected_vulnerability
    if vuln == "SQL Injection" or scenario == "sql_injection":
        return {
            "vulnerability_target": "SQL Injection",
            "target_endpoint": f"{base_url}/api/records?query=' UNION SELECT id, name, secret_token FROM users -- ",
            "http_method": "GET",
            "payload_json": None,
            "hypothesis": "Unsanitized query concatenation allows token dump"
        }
    elif vuln == "Business Logic Abuse" or scenario == "business_logic":
        return {
            "vulnerability_target": "Business Logic Abuse",
            "target_endpoint": f"{base_url}/api/checkout",
            "http_method": "POST",
            "payload_json": json.dumps({"item_id": "license_pro", "quantity": -1, "unit_price": 250.0}),
            "hypothesis": "Negative quantity bypasses billing invariant"
        }
    else:
        return {
            "vulnerability_target": "IDOR",
            "target_endpoint": f"{base_url}/api/user/102",
            "http_method": "GET",
            "payload_json": None,
            "hypothesis": "Direct object reference without authorization"
        }

def _fallback_detection(url: str, status: int, body: str, payload: str = ""):
    body_l = (body or "").lower()
    url_l = (url or "").lower()
    # replicate system prompt logic
    if status == 200 and "/api/user/" in url_l and any(x in body_l for x in ["secret", "token", "admin"]):
        return {"threat_detected": True, "vulnerability_type": "IDOR", "confidence_score": 0.97, "technical_findings": "200 OK exposed confidential record with secret_token leak"}
    if status == 200 and "/api/checkout" in url_l and "total_billed" in body_l and ("-250" in body_l or '"total_billed": -' in body):
        return {"threat_detected": True, "vulnerability_type": "Business Logic Abuse", "confidence_score": 0.96, "technical_findings": "200 OK with negative total_billed indicates business logic bypass"}
    if status == 200 and "/api/records" in url_l and ("master_secret" in body_l or "secret_token" in body_l or "bob-token" in body_l):
        return {"threat_detected": True, "vulnerability_type": "SQL Injection", "confidence_score": 0.98, "technical_findings": "200 OK leaked user tokens via UNION SELECT injection"}
    if 400 <= status <= 499:
        return {"threat_detected": False, "vulnerability_type": "None", "confidence_score": 0.92, "technical_findings": f"{status} correctly blocked - boundary enforced"}
    # fallback based on status 200 generally is threat if not 4xx and endpoint matches scenario
    if status == 200:
        if "/api/records" in url_l:
            return {"threat_detected": True, "vulnerability_type": "SQL Injection", "confidence_score": 0.85, "technical_findings": "200 OK on injection surface suggests vulnerability"}
        if "/api/user" in url_l:
            return {"threat_detected": True, "vulnerability_type": "IDOR", "confidence_score": 0.85, "technical_findings": "200 OK exposed object without auth"}
        if "/api/checkout" in url_l:
            # check if body contains negative
            if "-" in body:
                return {"threat_detected": True, "vulnerability_type": "Business Logic Abuse", "confidence_score": 0.85, "technical_findings": "200 OK with anomalous billing"}
    return {"threat_detected": False, "vulnerability_type": "None", "confidence_score": 0.7, "technical_findings": "No clear threat pattern - requires manual triage"}

def _fallback_hardening(threat_detected: bool, vuln_type: str):
    mapping = {
        "IDOR": "block_unauthorized_idor",
        "SQL Injection": "block_sql_injection",
        "Business Logic Abuse": "block_business_logic_abuse",
    }
    if not threat_detected:
        return {
            "target_rule_name": "none",
            "mitigation_action": "no action - no threat",
            "remediation_suggestion": "No remediation required - controls effective. Continue monitoring and periodic re-test."
        }
    rule = mapping.get(vuln_type, "none")
    suggestions = {
        "block_unauthorized_idor": "Implement robust authorization middleware validating caller claims against requested resource identifiers. Decouple private attributes (tokens, secret notes) from public serialization. Enforce RBAC on /api/user/* with Bearer token validation.",
        "block_sql_injection": "Refactor database query handler from dynamic string concatenation to parameterized queries / ORM prepared statements. Implement input sanitization rejecting union/select patterns. Enforce least privilege on DB user.",
        "block_business_logic_abuse": "Add strict server-side schema invariants ensuring quantity is strictly positive (>0) and total price matches authoritative catalog pricing rather than client-submitted payloads. Reject non-positive quantities with 400.",
    }
    actions = {
        "block_unauthorized_idor": "Dynamic route gate requiring valid admin Bearer token for /api/user/*",
        "block_sql_injection": "WAF token filtering for SQL metadata (', --, union, select) on /api/records",
        "block_business_logic_abuse": "Server validation rejecting non-positive quantity/price and price tampering",
    }
    return {
        "target_rule_name": rule,
        "mitigation_action": actions.get(rule, "dynamic filtering"),
        "remediation_suggestion": suggestions.get(rule, "Review logs and apply defense in depth.")
    }

class ReconOutput(BaseModel):
    target_surface: str = Field(description="Identified endpoint path")
    suspected_vulnerability: str = Field(description="Target vulnerability type")
    target_parameter: str = Field(description="Parameter to probe")
    recon_notes: str = Field(description="Architectural boundary notes")

class AttackPlan(BaseModel):
    vulnerability_target: str = Field(description="Target category")
    target_endpoint: str = Field(description="Full target URL")
    http_method: str = Field(description="GET or POST")
    payload_json: Optional[str] = Field(default=None, description="JSON string payload")
    hypothesis: str = Field(description="Validation hypothesis")

class DetectionReport(BaseModel):
    threat_detected: bool = Field(description="True if unexpected boundary breach succeeded")
    vulnerability_type: str = Field(description="IDOR, Business Logic Abuse, or SQL Injection")
    confidence_score: float = Field(description="Confidence value between 0.0 and 1.0")
    technical_findings: str = Field(description="Technical rationale from HTTP response")

class HardeningPlan(BaseModel):
    target_rule_name: str = Field(description="block_unauthorized_idor, block_business_logic_abuse, block_sql_injection, or none")
    mitigation_action: str = Field(description="Dynamic filtering action to invoke")
    remediation_suggestion: str = Field(description="Engineering remediation guidance")

class EpisodeState(TypedDict):
    episode_id: str
    scenario: str
    target_url: str
    past_memory: str
    recon_data: Optional[Dict[str, Any]]
    attack_plan: Optional[Dict[str, Any]]
    http_status: Optional[int]
    response_body: Optional[str]
    detection_report: Optional[Dict[str, Any]]
    hardening_plan: Optional[Dict[str, Any]]
    threat_detected: Optional[bool]
    vulnerability_type: Optional[str]
    remediation: Optional[str]
    patch_applied: Optional[bool]
    retest_status: Optional[int]
    posture_score: Optional[float]

def memory_retrieval_node(state: EpisodeState) -> Dict[str, Any]:
    try:
        context = retrieve_past_context(f"{state['scenario']} security audit")
    except Exception as e:
        print(f"[memory] retrieval failed: {e}")
        context = "No prior episode records available."
    return {"past_memory": context}

def red_recon_agent(state: EpisodeState) -> Dict[str, Any]:
    scenario = state.get("scenario", "idor")
    # fallback deterministic if no LLM or on error
    if llm is None:
        return {"recon_data": _fallback_recon(scenario)}

    if scenario == "sql_injection":
        instruction = (
            "Target route is '/api/records'. "
            "Set target_surface to '/api/records', suspected_vulnerability to 'SQL Injection', "
            "target_parameter to 'query', recon_notes to 'Dynamic search query endpoint'."
        )
    elif scenario == "business_logic":
        instruction = (
            "Target route is '/api/checkout'. "
            "Set target_surface to '/api/checkout', suspected_vulnerability to 'Business Logic Abuse', "
            "target_parameter to 'quantity, unit_price', recon_notes to 'Order processing calculation route'."
        )
    else:
        instruction = (
            "Target route is '/api/user/102'. "
            "Set target_surface to '/api/user/102', suspected_vulnerability to 'IDOR', "
            "target_parameter to 'user_id', recon_notes to 'Direct object identifier parameter'."
        )

    try:
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an automated Reconnaissance Agent (Red Agent 1). " + instruction),
            ("human", "Target Base: {base_url}\nPast Records: {past_memory}\nProduce surface reconnaissance output:")
        ])
        structured_recon = llm.with_structured_output(ReconOutput)
        recon = (prompt | structured_recon).invoke({
            "base_url": state["target_url"],
            "past_memory": state["past_memory"]
        })
        return {"recon_data": recon.model_dump()}
    except Exception as e:
        print(f"[recon] LLM failed, using fallback: {e}")
        return {"recon_data": _fallback_recon(scenario)}

def red_execution_agent(state: EpisodeState) -> Dict[str, Any]:
    recon = state["recon_data"]
    scenario = state.get("scenario", "idor")
    vuln = recon.get("suspected_vulnerability", "IDOR")

    # prepare fallback plan immediately
    fallback_plan = _fallback_attack_plan(scenario, state["target_url"], vuln)

    if llm is None:
        plan_dict = fallback_plan
    else:
        if vuln == "SQL Injection":
            instruction = (
                "Formulate SQL validation request on endpoint: {base_url}/api/records?query=' UNION SELECT id, name, secret_token FROM users -- . "
                "Set vulnerability_target to 'SQL Injection'. "
                "Set target_endpoint to \"{base_url}/api/records?query=' UNION SELECT id, name, secret_token FROM users -- \". "
                "Set http_method to 'GET'. "
                "Set payload_json to null."
            )
        elif vuln == "Business Logic Abuse":
            instruction = (
                "Formulate arithmetic validation request on endpoint: {base_url}/api/checkout. "
                "Set vulnerability_target to 'Business Logic Abuse'. "
                "Set target_endpoint to '{base_url}/api/checkout'. "
                "Set http_method to 'POST'. "
                "Set payload_json to '{{\"item_id\": \"license_pro\", \"quantity\": -1, \"unit_price\": 250.0}}'."
            )
        else:
            instruction = (
                "Formulate authorization verification request on endpoint: {base_url}/api/user/102. "
                "Set vulnerability_target to 'IDOR'. "
                "Set target_endpoint to '{base_url}/api/user/102'. "
                "Set http_method to 'GET'. "
                "Set payload_json to null."
            )
        try:
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are an automated Security Test Formulation Agent (Red Agent 2). " + instruction),
                ("human", "Recon Data: {recon}\nBase URL: {base_url}\nGenerate validation request plan:")
            ])
            structured_exec = llm.with_structured_output(AttackPlan)
            plan_obj = (prompt | structured_exec).invoke({
                "recon": json.dumps(recon),
                "base_url": state["target_url"]
            })
            plan_dict = plan_obj.model_dump()
        except Exception as e:
            print(f"[execution] LLM failed, using fallback: {e}")
            plan_dict = fallback_plan

    # Execute HTTP request with timeouts and error handling
    headers = {"Content-Type": "application/json"}
    try:
        if plan_dict["http_method"].upper() == "POST":
            payload = json.loads(plan_dict["payload_json"]) if plan_dict.get("payload_json") else {}
            resp = requests.post(plan_dict["target_endpoint"], json=payload, headers=headers, timeout=5)
        else:
            resp = requests.get(plan_dict["target_endpoint"], timeout=5)
        status = resp.status_code
        body = resp.text
    except Exception as e:
        print(f"[execution] request failed: {e}")
        status = 0
        body = f"Request failed: {e}"

    return {
        "attack_plan": plan_dict,
        "http_status": status,
        "response_body": body
    }

def blue_detection_agent(state: EpisodeState) -> Dict[str, Any]:
    url = state["attack_plan"]["target_endpoint"]
    status = state["http_status"]
    payload = state["attack_plan"].get("payload_json") or ""
    body = state["response_body"]

    if llm is None:
        report_dict = _fallback_detection(url, status, body, payload)
        return {
            "detection_report": report_dict,
            "threat_detected": report_dict["threat_detected"],
            "vulnerability_type": report_dict["vulnerability_type"]
        }

    try:
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are an automated Telemetry Analysis Engine (Blue Agent 1). "
                       "Analyze the transaction: "
                       "1. If status is 200 on /api/user/* exposing confidential records, threat_detected=True, vulnerability_type='IDOR'. "
                       "2. If status is 200 on /api/checkout with negative total_billed, threat_detected=True, vulnerability_type='Business Logic Abuse'. "
                       "3. If status is 200 on /api/records exposing user tokens or MASTER_SECRET_KEY, threat_detected=True, vulnerability_type='SQL Injection'. "
                       "4. If status is 4xx, threat_detected=False."),
            ("human", "Endpoint: {url}\nStatus: {status}\nPayload: {payload}\nResponse: {body}\nEvaluate telemetry:")
        ])
        structured_detection = llm.with_structured_output(DetectionReport)
        report = (prompt | structured_detection).invoke({
            "url": url,
            "status": status,
            "payload": payload,
            "body": body
        })
        return {
            "detection_report": report.model_dump(),
            "threat_detected": report.threat_detected,
            "vulnerability_type": report.vulnerability_type
        }
    except Exception as e:
        print(f"[detection] LLM failed, fallback: {e}")
        report_dict = _fallback_detection(url, status, body, payload)
        return {
            "detection_report": report_dict,
            "threat_detected": report_dict["threat_detected"],
            "vulnerability_type": report_dict["vulnerability_type"]
        }

def blue_hardening_agent(state: EpisodeState) -> Dict[str, Any]:
    det = state["detection_report"]

    if llm is None:
        fallback = _fallback_hardening(det.get("threat_detected", False), det.get("vulnerability_type", "None"))
        plan_dict = fallback
    else:
        try:
            prompt = ChatPromptTemplate.from_messages([
                ("system", "You are an automated Policy Hardening Engine (Blue Agent 2). "
                           "If threat_detected is False, target_rule_name='none'. "
                           "If vulnerability_type is 'IDOR', target_rule_name='block_unauthorized_idor'. "
                           "If vulnerability_type is 'Business Logic Abuse', target_rule_name='block_business_logic_abuse'. "
                           "If vulnerability_type is 'SQL Injection', target_rule_name='block_sql_injection'."),
                ("human", "Detection Report: {report}\nDetermine mitigation action and engineering remediation:")
            ])
            structured_hardening = llm.with_structured_output(HardeningPlan)
            plan_obj = (prompt | structured_hardening).invoke({
                "report": json.dumps(det)
            })
            plan_dict = plan_obj.model_dump()
        except Exception as e:
            print(f"[hardening] LLM failed, fallback: {e}")
            plan_dict = _fallback_hardening(det.get("threat_detected", False), det.get("vulnerability_type", "None"))

    patch_ok = False
    if det.get("threat_detected") and plan_dict.get("target_rule_name") != "none":
        try:
            r = requests.post(
                f"{state['target_url']}/admin/apply-mitigation",
                json={"rule": plan_dict["target_rule_name"]},
                timeout=3
            )
            patch_ok = (r.status_code == 200)
        except Exception as e:
            print(f"[hardening] patch apply failed: {e}")
            patch_ok = False

    return {
        "hardening_plan": plan_dict,
        "remediation": plan_dict.get("remediation_suggestion", ""),
        "patch_applied": patch_ok
    }

def retest_node(state: EpisodeState) -> Dict[str, Any]:
    retest_status = None
    if state.get("patch_applied"):
        plan = state["attack_plan"]
        headers = {"Content-Type": "application/json"}
        try:
            if plan["http_method"].upper() == "POST":
                payload = json.loads(plan["payload_json"]) if plan.get("payload_json") else {}
                resp = requests.post(plan["target_endpoint"], json=payload, headers=headers, timeout=5)
            else:
                resp = requests.get(plan["target_endpoint"], timeout=5)
            retest_status = resp.status_code
        except Exception as e:
            print(f"[retest] failed: {e}")
            retest_status = 0
    return {"retest_status": retest_status}

def scoring_and_storage_node(state: EpisodeState) -> Dict[str, Any]:
    score = 100.0
    if state["threat_detected"] and state["http_status"] == 200:
        if state.get("retest_status") in [400, 401, 403]:
            score = 100.0
        else:
            score = 60.0
    elif not state.get("threat_detected"):
        score = 100.0

    try:
        store_episode_memory(
            episode_id=state["episode_id"],
            attack_target=state["attack_plan"]["vulnerability_target"],
            endpoint=state["attack_plan"]["target_endpoint"],
            finding=f"Initial: {state['http_status']} | Re-test: {state['retest_status']}",
            mitigation=state["remediation"]
        )
    except Exception as e:
        print(f"[storage] memory store failed: {e}")
    return {"posture_score": score}

workflow = StateGraph(EpisodeState)

workflow.add_node("retrieve_memory", memory_retrieval_node)
workflow.add_node("red_recon", red_recon_agent)
workflow.add_node("red_execution", red_execution_agent)
workflow.add_node("blue_detection", blue_detection_agent)
workflow.add_node("blue_hardening", blue_hardening_agent)
workflow.add_node("retest_step", retest_node)
workflow.add_node("scoring_and_storage", scoring_and_storage_node)

workflow.set_entry_point("retrieve_memory")
workflow.add_edge("retrieve_memory", "red_recon")
workflow.add_edge("red_recon", "red_execution")
workflow.add_edge("red_execution", "blue_detection")
workflow.add_edge("blue_detection", "blue_hardening")
workflow.add_edge("blue_hardening", "retest_step")
workflow.add_edge("retest_step", "scoring_and_storage")
workflow.add_edge("scoring_and_storage", END)

app_graph = workflow.compile()