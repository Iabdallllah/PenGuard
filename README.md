# PenGuard: Autonomous Purple Team Platform

[![CI](https://github.com/Iabdallllah/PenGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/Iabdallllah/PenGuard/actions)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Next.js-000?logo=nextdotjs&logoColor=white)](https://nextjs.org)
[![Vercel](https://img.shields.io/badge/Vercel-000?logo=vercel&logoColor=white)](https://vercel.com)
[![Railway](https://img.shields.io/badge/Railway-0B0D0E?logo=railway&logoColor=white)](https://railway.app)
[![Prometheus](https://img.shields.io/badge/Prometheus-E6522C?logo=prometheus&logoColor=white)](https://prometheus.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Live Demo:** Frontend → **[https://pen-guard-wafy.vercel.app](https://pen-guard-wafy.vercel.app)** · API → **[https://heroic-insight-production-d97d.up.railway.app/api/health](https://heroic-insight-production-d97d.up.railway.app/api/health)** · Grafana → `http://localhost:3001` (admin/admin)

PenGuard (formerly Purple Web) is an enterprise-grade, **closed-loop DevSecOps** platform. **Red Agent → Blue Agent → GitHub PR → CI/CD Preview → Verified Patch** — all autonomous, no human in the loop. Built on **LangGraph + Groq + Neo4j-ready Graph-RAG + PostgreSQL + WebSockets**.

```text
                [User: base_url + scenario]
                         │
                         ▼
              ┌──────────────────────┐
              │   VANGUARD Dashboard │  (Next.js, WebSocket /ws/episodes)
              └──────────┬───────────┘
                         │ POST /api/episodes/run
                         ▼
              ┌──────────────────────┐      ┌─────────────────────┐
              │  Red Agent (Recon)   │─────►│   Blue Agent (Fix)  │
              │  Auto-Crawl + Exploit│      │  AST-safe Patch     │
              └──────────┬───────────┘      └──────────┬──────────┘
                         │                             │ create_git_ref
                         └──────────────┬──────────────┘
                                        ▼
                              ┌──────────────────┐
                              │  GitHub PR       │──► Vercel Preview ──► Verifier
                              └──────────────────┘         │
                                                           ▼
                                                    ┌─────────────┐
                                                    │  CI Green   │
                                                    └─────────────┘
```

---

## Core Capabilities

- **Autonomous Closed-Loop Hardening:** Reconnaissance -> Exploit -> Telemetry Detection -> Dynamic Patching -> Retest Verification.
- **Multi-Agent Orchestration:** Powered by LangGraph and Groq LLM inference, separating concerns into dedicated adversarial and defensive agents.
- **Dynamic Container Sandboxing:** Ephemeral container isolation utilizing Docker Engine to prevent test bleed and state contamination.
- **Continuous Compliance Engine:** Automated mapping of findings and mitigation evidence directly to OWASP Top 10, SOC 2 Type II, ISO/IEC 27001, and NIST SP 800-53 controls.
- **Episodic Long-Term Memory:** Persistent retrieval-augmented memory backed by ChromaDB to record remediation efficacy and avoid duplicate exploit paths.

---

## System Architecture

```text
               +-------------------------------------------------------------+
               |                  PURPLE WEB ORCHESTRATOR                    |
               +-------------------------------------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |    ChromaDB Episodic Memory   |
                              |  (Retrieves Past Hardening)   |
                              +-------------------------------+
                                              |
                     +------------------------+------------------------+
                     |                                                 |
                     v                                                 v
        +-------------------------+                       +-------------------------+
        |     RED TEAM ENGINE     |                       |    BLUE TEAM ENGINE     |
        +-------------------------+                       +-------------------------+
        |  1. Reconnaissance      |                       |  3. Telemetry Detection |
        |     (Route & Param Scan)|                       |     (Log & Leak Triage) |
        |                         |                       |                         |
        |  2. Exploit Formulation |                       |  4. Hardening & Patch   |
        |     (Targeted Payload)  |                       |     (Dynamic Rule WAF)  |
        +-------------------------+                       +-------------------------+
                     |                                                 ^
                     | (Adversarial Traffic)                           | (Policy Injection)
                     v                                                 |
        +---------------------------------------------------------------------------+
        |                          ISOLATED DOCKER SANDBOX                          |
        |                    FastAPI Medical Portal Target (Port 8001)              |
        +---------------------------------------------------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              |   Automated Retest Cycle      |
                              |   (Confirms 400 / 403 Status) |
                              +-------------------------------+
                                              |
                                              v
                              +-------------------------------+
                              | Compliance & Executive Export |
                              | (SOC 2, ISO 27001, OWASP, PDF)|
                              +-------------------------------+
```

---

## Multi-Agent Execution Flow

```text
[Episode Trigger]
       │
       ▼
[Retrieve Memory] ──► Query ChromaDB for historical attack surfaces and patch notes.
       │
       ▼
[Red: Recon]      ──► Analyze target routes, expected schemas, and parameter vulnerabilities.
       │
       ▼
[Red: Exploit]    ──► Formulate structured exploit request (GET/POST payload).
       │
       ▼
[Sandbox Probe]   ──► Execute exploit against ephemeral Docker sandbox.
       │
       ▼
[Blue: Detection] ──► Parse HTTP response status, body leaks, and classify threat flags.
       │
       ▼
[Blue: Hardening] ──► Select mitigation rule and inject dynamic filtering into target runtime.
       │
       ▼
[Retest Step]     ──► Re-execute identical exploit payload to confirm 4xx boundary enforcement.
       │
       ▼
[Posture Scoring] ──► Calculate updated posture score (0-100) and commit episode to ChromaDB.
```

---

## Attack Vectors & Compliance Controls

| Vector | Target Surface | Initial State | Secured State | Framework Controls |
| :--- | :--- | :--- | :--- | :--- |
| **Broken Access Control (IDOR)** | `/api/user/{id}` | 200 OK (Data Leak) | 403 Forbidden | OWASP A01:2021, SOC 2 CC6.1, NIST AC-3 |
| **SQL Injection** | `/api/records?query=` | 200 OK (Token Dump) | 403 Forbidden | OWASP A03:2021, ISO 27001 A.8.28 |
| **Business Logic Abuse** | `/api/checkout` | 200 OK (Negative Billing) | 400 Bad Request | OWASP A04:2021, SOC 2 CC7.1, NIST SI-4 |

---

## Project Structure

```text
PenGuard/
├── api_server.py           # FastAPI orchestrator server & compliance reporting engine
├── orchestrator.py         # LangGraph multi-agent execution workflow (2 Red + 2 Blue)
├── sandbox_manager.py      # Docker SDK client managing ephemeral sandbox life cycles
├── memory_manager.py       # ChromaDB vector store for audit retrieval and retention
├── generate_pdf.py         # WeasyPrint executive compliance report PDF generator
├── sandbox/
│   ├── Dockerfile          # Containerized sandbox environment definition
│   ├── target_app.py       # Vulnerable target web app with dynamic mitigation gates
│   └── requirements.txt    # Sandbox runtime dependencies
└── dashboard/              # Next.js 16 telemetry & control UI (VANGUARD SOC)
    ├── src/app/page.tsx    # Real-time metrics, execution inspector, and trend graphs
    └── package.json
```

---

## Installation & Setup

### Prerequisites
- Linux OS (Ubuntu 22.04+ recommended)
- Python 3.11+
- Docker Engine & Docker Daemon running
- Node.js 18+ and npm
- Groq Cloud API Key

### 1. Environment Setup

```bash
git clone https://github.com/Iabdallllah/PenGuard.git
cd PenGuard

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Set your Groq API Key:
```bash
export GROQ_API_KEY="your-groq-api-key-here"
```

### 2. Pre-build Target Sandbox Image

```bash
docker build --network=host -t purple-target:latest -f sandbox/Dockerfile .
```

### 3. Start Backend + Target (Offline Fallback - One Command Each)

```bash
# Terminal 1: Target (vulnerable app)
uvicorn target_app:app --host 127.0.0.1 --port 8001 --reload

# Terminal 2: API + Orchestrator (with live metrics)
uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
# Metrics: http://127.0.0.1:8000/metrics  &  http://127.0.0.1:8000/api/metrics

# Terminal 3: Monitoring (optional, for Grafana demo)
docker compose -f docker-compose.monitoring.yml up -d
# Prometheus: http://localhost:9090/targets → 1/1 UP
# Grafana: http://localhost:3001 → admin/admin → Import grafana-dashboard.json
```

### 4. Start Telemetry Dashboard

In a separate terminal:
```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000` in your browser. For production, set `NEXT_PUBLIC_API_BASE=https://heroic-insight-production-d97d.up.railway.app`.

**Offline Demo Fallback (for viva without internet):**
- The two `uvicorn` commands above are sufficient — no Docker or external API needed (fallback mock works without `GROQ_API_KEY`).
- Pre-save screenshots in `docs/screenshots/` (Grafana + Dashboard + PR) to show in slides if network is blocked.

---

## Screenshots

| Dashboard | Grafana | PR |
|---|---|---|
| docs/screenshots/dashboard.png | docs/screenshots/grafana.png | docs/screenshots/pr.png |
| *Place your screenshots here* | | |

---

## API Reference

- `GET /api/health` — liveness probe
- `GET /api/episodes` — list all episodes (persistent in Postgres, fallback to JSON)
- `GET /api/episodes/{id}` — episode detail
- `POST /api/episodes/run` — dispatch `{"scenario": "idor"|"sql_injection"|"business_logic"|"xss"|"csrf"|"ssrf"|"broken_auth"|"misconfig"}` (only `base_url` + `scenario` required — sub-path auto-discovered via `Auto-Recon`)
- `DELETE /api/episodes` — clear history (for demo reset)
- `GET /api/scenarios` — list 8 OWASP vectors
- `GET /api/reports/compliance` — dynamic PDF (generated per operation from current ledger)
- `GET /metrics` & `GET /api/metrics` — Prometheus metrics
- `WS /ws/episodes` — real-time episode streaming (replaces 5s polling)
- `WS /ws/telemetry` — mobile spec (see `docs/mobile-api.md`)

---

## License
MIT License. Built for advanced cybersecurity and autonomous agent research.# PenGuard
