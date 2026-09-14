# System Architecture & Knowledge Graph (Neo4j + MITRE/STIX 2.1)

## 1. Theoretical Motivation: The Relational Deficit of Flat Vector RAG

Autonomous DevSecOps pipelines commonly leverage dense vector retrieval (e.g., ChromaDB, FAISS) to augment Large Language Model (LLM) agents with historical security telemetry. While effective for semantic code similarity, dense embeddings project multi-dimensional dependency topologies into flat vector spaces, causing severe relational deficits:

* **Inability to Reason Across Attack Graphs:** Vector similarity treats vulnerabilities ($V_i$) as discrete, independent events, failing to evaluate chained exploits (e.g., Cross-Site Scripting enabling session credential harvesting, which in turn permits administrative API manipulation).
* **Blast-Radius Blindness:** Code remediation engines unaware of Abstract Syntax Tree (AST) dependencies risk introducing fatal regressions—such as decoupling shared schema models (`TransferPayload`) while modifying dependent endpoints (`/api/transfer`).

To eliminate these constraints, the proposed architecture introduces a **Hybrid Graph-RAG Memory Engine** underpinned by Neo4j and formal Cyber Threat Intelligence (CTI) ontologies.

---

## 2. CTI Ontology & STIX 2.1 Specification

Security entities and architectural assets are modeled in strict adherence to the **OASIS STIX 2.1** and **MITRE ATT&CK** standards. The knowledge base operates as a Directed Property Graph (DPG) $G = (\mathcal{V}, \mathcal{E})$, where vertices $\mathcal{V}$ represent threat entities and edges $\mathcal{E}$ define functional or adversarial relationships.

| STIX Entity / Label | Node Attributes | Conceptual Mapping |
| --- | --- | --- |
| **`AttackPattern`** | `external_id` (MITRE ID), `name`, `kill_chain_phases` | Adversarial technique (e.g., `T1059.007: JavaScript Injection`) |
| **`Vulnerability`** | `cwe_id`, `cvss_score`, `severity`, `vector_string` | Standardized weakness definition (e.g., `CWE-79`, `CWE-639`) |
| **`Asset`** | `file_path`, `endpoint_url`, `ast_signature`, `http_method` | Concrete target component (e.g., `/api/search`, `target_app.py`) |
| **`CourseOfAction`** | `remediation_strategy`, `diff_signature`, `confidence` | Verified defense patch or WAF inspection rule |

**Formal Relationship Topologies ($\mathcal{E}$):**

* `(:AttackPattern)-[:TARGETS]->(:Asset)`
* `(:AttackPattern)-[:EXPLOITS]->(:Vulnerability)`
* `(:Vulnerability)-[:LOCATED_IN]->(:Asset)`
* `(:CourseOfAction)-[:MITIGATES {verified: bool}]->(:Vulnerability)`
* `(:Vulnerability)-[:ENABLES {hop_distance: int}]->(:Vulnerability)` *(Transitive privilege escalation paths)*

---

## 3. Dual-Agent Operational Mechanics via Graph Traversal

**Red Agent (Adversarial Path Traversal):**
Rather than executing blind, brute-force fuzzing, the Red Agent traverses incoming subgraphs using Cypher execution paths to identify adjacent attack surfaces:

```cypher
MATCH (a:Asset {endpoint_url: "/api/search"})<-[:LOCATED_IN]-(v:Vulnerability)
MATCH (v)<-[:EXPLOITS]-(ap:AttackPattern)-[:ENABLES*1..3]->(target_ap:AttackPattern)
RETURN target_ap.external_id AS NextVector, target_ap.name AS Technique
```

This traversal uncovers multi-hop privilege escalation trajectories, prioritizing high-impact payloads over isolated scans.

**Blue Agent (Context-Aware AST Remediation):**
The Blue Agent queries bidirectional inbound and outbound references prior to generating PR patches. By inspecting the `LOCATED_IN` and `DEPENDS_ON` relations, the LLM prompt is dynamically contextualized with all shared dependencies, preventing the accidental excision of structural contracts (`BaseModel` subclasses) and ensuring preview build invariants hold.

---

## 4. Mathematical Model of Dynamic Security Posture

The platform quantifies the temporal infrastructure posture via a continuous, bounded metric $S(t) \in [0, 100]$. The implemented engine (`compute_posture`) sums only validated, unpatched threat episodes:

$$
S(t) = \max \left(0, \; 100 - \sum_{i \in \mathcal{V}_{\text{active}}} w_i \cdot \text{CVSS}_i \right)
$$

Where:

* $\mathcal{V}_{\text{active}}$: The set of validated, unmitigated vulnerabilities detected in the active runtime ledger (`threat_flag=true`, `patch_applied=false`).
* $w_i \in (0, 1]$: Static business weight from `VECTOR_METRICS` (e.g., SQLi 1.0, SSRF 1.0, broken_auth 0.9, IDOR 0.9, business_logic 0.8, CSRF 0.7, XSS 0.6, misconfig 0.5), reflecting the critical exposure of the targeted asset. Roadmap: compute via PageRank over graph $G$ after Neo4j integration (Phase 3).
* $\text{CVSS}_i$: CVSS base score for vulnerability $i$ (SQLi 8.6, SSRF 8.5, broken_auth 8.1, IDOR 7.5, business_logic 7.4, CSRF 6.5, XSS 6.1, misconfig 5.3).
* Status bands: $\ge 80$ HEALTHY · $50$–$79$ DEGRADED · $< 50$ CRITICAL. Roadmap: add a CI-verification confidence term $+\sum_j \gamma_j \cdot \Delta_j$ once preview-environment verification lands.

---

## 5. Persistence & Ingestion Architecture

To guarantee performance and high availability, PenGuard implements a tiered storage architecture:

* **Relational Layer (PostgreSQL via SQLAlchemy):** Manages transactional scan episodes, audit ledgers, and real-time telemetry logs.
* **Graph Engine (Neo4j Community/Aura):** Traversed asynchronously via the official Neo4j Bolt driver for exploit route planning and semantic graph queries.
* **Telemetry & Ingestion (Prometheus & Grafana):** Scrapes real-time application throughput, p95 latency, and defensive HTTP response codes directly from the `/metrics` instrumentation layer.
