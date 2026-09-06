import html
import sqlite3
import logging
from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

app = FastAPI(title="Vulnerable Target App")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("target_logger")

DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)
cursor = DB_CONN.cursor()

cursor.execute("CREATE TABLE users (id TEXT, name TEXT, role TEXT, secret_token TEXT)")
cursor.execute("INSERT INTO users VALUES ('101', 'Alice', 'user', 'alice-token-111')")
cursor.execute("INSERT INTO users VALUES ('102', 'Bob', 'user', 'bob-token-222')")
cursor.execute("INSERT INTO users VALUES ('999', 'Admin', 'admin', 'MASTER_SECRET_KEY_XYZ999')")

cursor.execute("CREATE TABLE medical_records (id INTEGER PRIMARY KEY, patient_name TEXT, diagnosis TEXT)")
cursor.execute("INSERT INTO medical_records VALUES (1, 'John Doe', 'Hypertension')")
cursor.execute("INSERT INTO medical_records VALUES (2, 'Jane Smith', 'Diabetes')")
cursor.execute("INSERT INTO medical_records VALUES (3, 'Bob', 'Routine Checkup')")
DB_CONN.commit()

ITEM_CATALOG = {
    "license_pro": 250.0
}

SECURITY_RULES = {
    "block_unauthorized_idor": False,
    "block_business_logic_abuse": False,
    "block_sql_injection": False,
    "block_xss": False
}

class CheckoutPayload(BaseModel):
    item_id: str
    quantity: int
    unit_price: float

@app.middleware("http")
async def dynamic_security_filter(request: Request, call_next):
    client_ip = request.client.host
    path = request.url.path

    if SECURITY_RULES["block_unauthorized_idor"]:
        if path.startswith("/api/user/"):
            auth_header = request.headers.get("Authorization")
            if not auth_header or auth_header != "Bearer admin-valid-token":
                logger.warning(f"BLOCKED IDOR ATTEMPT from {client_ip} to {path}")
                return Response(
                    content='{"detail":"Forbidden: Unauthorized IDOR Access Blocked"}',
                    status_code=403,
                    media_type="application/json"
                )

    if SECURITY_RULES["block_sql_injection"]:
        if path.startswith("/api/records"):
            raw_query = str(request.query_params.get("query", ""))
            forbidden_tokens = ["'", "--", "union", "select", "or 1=1"]
            if any(token in raw_query.lower() for token in forbidden_tokens):
                logger.warning(f"BLOCKED SQL INJECTION ATTEMPT from {client_ip}")
                return Response(
                    content='{"detail":"Forbidden: SQL Injection Payload Detected"}',
                    status_code=403,
                    media_type="application/json"
                )

    if SECURITY_RULES["block_xss"]:
        if path.startswith("/api/search"):
            q = str(request.query_params.get("q", "") or request.query_params.get("query", ""))
            if "<script" in q.lower() or "onerror" in q.lower() or "javascript:" in q.lower():
                logger.warning(f"BLOCKED XSS ATTEMPT from {client_ip} q={q[:60]}")
                return Response(
                    content='{"detail":"Forbidden: XSS Payload Detected"}',
                    status_code=403,
                    media_type="application/json"
                )

    response = await call_next(request)
    return response

@app.post("/admin/apply-mitigation")
async def apply_mitigation(rule_payload: dict):
    rule_name = rule_payload.get("rule")
    if rule_name in SECURITY_RULES:
        SECURITY_RULES[rule_name] = True
        return {"status": "mitigation_applied", "active_rules": SECURITY_RULES}
    raise HTTPException(status_code=400, detail="Invalid rule")

@app.post("/admin/reset-mitigation")
async def reset_mitigation():
    for k in SECURITY_RULES:
        SECURITY_RULES[k] = False
    return {"status": "reset_complete"}

@app.get("/")
def home():
    return {"message": "Welcome to the Medical Portal API"}

@app.get("/api/user/{user_id}")
async def get_user_profile(user_id: str, request: Request):
    client_ip = request.client.host
    logger.info(f"Incoming request from {client_ip} targeting user_id: {user_id}")
    cur = DB_CONN.cursor()
    cur.execute("SELECT id, name, role, secret_token FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    if row:
        return {"id": row[0], "name": row[1], "role": row[2], "secret_note": row[3]}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/checkout")
async def process_checkout(payload: CheckoutPayload, request: Request):
    client_ip = request.client.host
    logger.info(f"Checkout received from {client_ip}: item={payload.item_id}, qty={payload.quantity}, price={payload.unit_price}")
    
    if SECURITY_RULES["block_business_logic_abuse"]:
        if payload.quantity <= 0 or payload.unit_price <= 0:
            logger.warning(f"BLOCKED BUSINESS LOGIC ABUSE: Non-positive values rejected from {client_ip}")
            raise HTTPException(status_code=400, detail="Validation Error: Quantity and price must be positive")
        if payload.item_id in ITEM_CATALOG and payload.unit_price != ITEM_CATALOG[payload.item_id]:
            logger.warning(f"BLOCKED BUSINESS LOGIC ABUSE: Price mismatch tampering from {client_ip}")
            raise HTTPException(status_code=400, detail="Validation Error: Price parameter tampering detected")

    total_cost = payload.unit_price * payload.quantity
    return {
        "status": "order_confirmed",
        "item_id": payload.item_id,
        "quantity": payload.quantity,
        "total_billed": total_cost,
        "message": "Order processed successfully"
    }

@app.get("/api/records")
async def search_records(query: str = "", request: Request = None):
    client_ip = request.client.host if request else "unknown"
    logger.info(f"Search records received query '{query}' from {client_ip}")
    cur = DB_CONN.cursor()
    raw_sql = f"SELECT id, patient_name, diagnosis FROM medical_records WHERE diagnosis LIKE '%{query}%'"
    try:
        cur.execute(raw_sql)
        rows = cur.fetchall()
        return [{"id": r[0], "patient_name": r[1], "diagnosis": r[2]} for r in rows]
    except Exception as e:
        return {"error": str(e)}

@app.get("/api/search")
async def search_xss(q: str = "", request: Request = None):
    client_ip = request.client.host if request else "unknown"
    logger.info(f"Search XSS q='{q}' from {client_ip}")
    # Patched: output encoding to prevent reflected XSS
    safe_q = html.escape(q)
    return {"query": safe_q, "result": f"Results for: {safe_q}", "html": f"<div>Search: {safe_q}</div>"}
