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

The platform quantifies the temporal infrastructure posture via a continuous, bounded metric $S(t) \in [0, 100]$:

$$
S(t) = \max \left(0, \; S_0 - \sum_{i \in \mathcal{V}_{\text{active}}} \omega_i \cdot \text{CVSS}_i + \sum_{j \in \mathcal{M}_{\text{verified}}} \gamma_j \cdot \Delta_j \right)
$$

Where:

* $S_0$: Baseline organizational posture score ($S_0 = 100$).
* $\mathcal{V}_{\text{active}}$: The set of validated, unmitigated vulnerabilities detected in the active runtime ledger.
* $\omega_i \in (0, 1]$: Topological centrality weight computed via PageRank over graph $G$, reflecting the critical exposure of the targeted asset.
* $\text{CVSS}_i$: Common Vulnerability Scoring System v3.1 base score for vulnerability $i$.
* $\mathcal{M}_{\text{verified}}$: Set of candidate patches validated by isolated CI test executions and Vercel preview environments.
* $\gamma_j \in [0, 1]$: CI verification confidence factor ($\gamma_j = 1.0$ for clean preview deployment and zero regressions).

---

## 5. Persistence & Ingestion Architecture

To guarantee performance and high availability, PenGuard implements a tiered storage architecture:

* **Relational Layer (PostgreSQL via SQLAlchemy):** Manages transactional scan episodes, audit ledgers, and real-time telemetry logs.
* **Graph Engine (Neo4j Community/Aura):** Traversed asynchronously via the official Neo4j Bolt driver for exploit route planning and semantic graph queries.
* **Telemetry & Ingestion (Prometheus & Grafana):** Scrapes real-time application throughput, p95 latency, and defensive HTTP response codes directly from the `/metrics` instrumentation layer.
