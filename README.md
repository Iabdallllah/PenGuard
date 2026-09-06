# Purple Web: Autonomous Penetration & Hardening System

Purple Web is an enterprise-grade, closed-loop cyber resilience platform. Operating via an autonomous 4-agent architecture (2 Red + 2 Blue), it emulates targeted attacks against web applications, detects security violations in real-time, dynamically injects zero-downtime runtime mitigations into isolated Docker environments, and verifies remediation through automated re-testing.

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
purple-web/
├── api_server.py           # FastAPI orchestrator server & compliance reporting engine
├── orchestrator.py         # LangGraph multi-agent execution workflow (2 Red + 2 Blue)
├── sandbox_manager.py      # Docker SDK client managing ephemeral sandbox life cycles
├── memory_manager.py       # ChromaDB vector store for audit retrieval and retention
├── generate_pdf.py         # WeasyPrint executive compliance report PDF generator
├── sandbox/
│   ├── Dockerfile          # Containerized sandbox environment definition
│   ├── target_app.py       # Vulnerable target web app with dynamic mitigation gates
│   └── requirements.txt    # Sandbox runtime dependencies
└── dashboard/              # Next.js 14 telemetry & control UI
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
git clone [https://github.com/your-username/purple-web.git](https://github.com/your-username/purple-web.git)
cd purple-web

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

### 3. Start Backend Orchestrator

```bash
uvicorn api_server:app --host 127.0.0.1 --port 8000 --reload
```

### 4. Start Telemetry Dashboard

In a separate terminal:
```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:3000` in your browser.

---

## API Reference

- `GET /api/episodes`: Retrieve all executed penetration and hardening records.
- `POST /api/episodes/run`: Dispatch an autonomous hardening loop (`{"scenario": "sql_injection" | "business_logic" | "idor"}`).
- `GET /api/reports/compliance`: Generate and stream downloadable compliance audit report (`.md`).

---

## License
MIT License. Built for advanced cybersecurity and autonomous agent research.# PenGuard
