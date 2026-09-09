# PenGuard: Autonomous Closed-Loop DevSecOps Platform via Multi-Agent LLMs and Cyber Threat Knowledge Graphs
## Academic Project Proposal
**Degree:** B.Sc. in Computer Science | **Focus:** Applied AI, Autonomous Cyber Defense, DevSecOps, Knowledge Graphs

### 1. Abstract
Modern software delivery relies on continuous deployment pipelines where code modifications are released at high frequency. While Static and Dynamic Application Security Testing (SAST/DAST) frameworks identify vulnerabilities, they remain fundamentally passive: they produce high rates of false positives, offer decoupled remediation guidance, and fail to prevent functional regressions when patches are applied.

This project presents **PenGuard**, a closed-loop, autonomous DevSecOps platform powered by collaborative multi-agent reinforcement architectures and structured Cyber Threat Intelligence (CTI). PenGuard pairs an offensive discovery agent (Red Agent) executing contextual exploit chains with a defensive synthesis agent (Blue Agent) capable of generating Abstract Syntax Tree (AST)-preserving remediation patches. Patches are autonomously submitted as GitHub Pull Requests and verified against continuous integration (CI) and ephemeral preview deployments. By replacing flat vector embeddings with a Hybrid Graph-RAG engine grounded in Neo4j and OASIS STIX 2.1/MITRE ATT&CK standards, PenGuard bridges automated threat detection and non-breaking, production-grade automated remediation.

### 2. Problem Statement & Motivation
DevSecOps workflows suffer from three critical bottlenecks:

1.  **The Remediation Chasm:** DAST/SAST scanners report vulnerabilities without verifying exploitability in running environments, inundating developers with unprioritized vulnerability ledgers.
2.  **Regression-Prone Automated Patching:** Current generative AI patch generators lack dependency awareness. Modifying a vulnerable endpoint frequently excises shared schema definitions (e.g., Pydantic payload models), introducing `NameError` or runtime import failures in downstream APIs.
3.  **Relational Blindness of Flat Vector Stores:** Vector retrieval approaches (e.g., ChromaDB) treat vulnerabilities as isolated text chunks, rendering them incapable of evaluating multi-hop attack trajectories (e.g., IDOR chained into session hijacking).

### 3. Related Work & Research Gap
**Automated Penetration Testing:** Recent research frameworks such as PentestGPT (Deng et al., 2024) utilize LLMs to structure penetration testing workflows. However, they stop at vulnerability identification and require human operators to interpret payloads and engineer defenses.

**Automated Program Repair (APR):** Traditional APR techniques rely on genetic programming or neural machine translation, but lack contextual awareness of modern API runtime topologies and microservice boundaries.

**Research Gap:** No existing production-grade system closes the loop between dynamic runtime exploitation, AST-preserving automated PR generation, preview environment verification, and graph-based threat modeling (STIX 2.1) in a unified pipeline.

### 4. Proposed Methodology & Architecture
#### 4.1 System Overview
PenGuard is engineered across four integrated planes:

```
[ Target Application Runtime / AST ]
                 |
      (Auto-Recon / Crawl)
                 v
         [ Red Agent ] --(Validated Exploit)--> [ Telemetry Layer ]
                 |                               (Postgres + Prometheus)
        (STIX 2.1 Context)                                |
                 v                                        v
         [ Neo4j Graph ] <--(Blast Radius)--- [ Blue Agent ]
                                                          |
                                                    (Safe Patch)
                                                          v
                                                [ GitHub PR + CI/CD ]
                                                          |
                                              (Vercel Preview Deploy)
```

- **Autonomous Reconnaissance & Exploitation (Red Agent):** Employs DOM traversal and route discovery to uncover attack surfaces across 8 critical OWASP categories.
- **Defensive Synthesis Engine (Blue Agent):** Synthesizes minimal diffs that mitigate root causes while maintaining AST contracts.
- **Continuous Verification (DevSecOps Loop):** Automatically generates isolated branches, commits patches, and monitors CI and preview environments.
- **Hybrid Graph-RAG Layer (Neo4j + STIX 2.1):** Maps threats, assets, and courses of action to model exploit chaining and blast radius.

#### 4.2 Dynamic Posture Formulation
Systemic security posture is modeled as a continuous state metric $S(t) \in [0, 100]$:

$$S(t) = \max \left(0, \; S_0 - \sum_{i \in \mathcal{V}_{\text{active}}} \omega_i \cdot \text{CVSS}_i + \sum_{j \in \mathcal{M}_{\text{verified}}} \gamma_j \cdot \Delta_j \right)$$

Where $S_0=100$ is baseline, $\omega_i$ is PageRank centrality, $\text{CVSS}_i$ is severity, and $\gamma_j$ is CI verification confidence.

### 5. Experimental Setup & Evaluation Metrics
#### 5.1 Prototype Implementation & Baseline
Backend: FastAPI, Python 3.11, SQLAlchemy, PostgreSQL. Observability: Prometheus scraping `/metrics` and Grafana. Frontend: Next.js, Tailwind, WebSocket, dynamic PDF. Target: FastAPI testbed with 8 OWASP scenarios.

#### 5.2 Evaluation Benchmarks
- **Exploit Success Rate (ESR):** % of vectors successfully weaponized.
- **Patch Acceptance Rate (PAR):** % of patches passing CI/preview without manual intervention.
- **Mean Time to Remediate (MTTR):** Time from discovery to verified PR.
- **Regression Incidence:** Frequency of secondary breakage.

### 6. Project Roadmap & Implementation Timeline
| Phase | Milestone / Deliverable | Status | Target Date |
|---|---|---|---|
| Phase 1 | Prototype Engine (8 OWASP vectors, FastAPI, Vercel UI, PostgreSQL) | Completed | Q3 2026 |
| Phase 2 | Live Observability (Prometheus, Grafana, CI/CD PR loop) | Completed | Q3 2026 |
| Phase 3 | Neo4j Integration & STIX 2.1 Threat Ontology (Hybrid Graph-RAG) | Planned | Q4 2026 |
| Phase 4 | Mobile Client (Flutter, WebSocket, FCM alerts) | Planned | Q1 2027 |
| Phase 5 | Empirical Evaluation, Benchmark vs SOTA, Thesis Defense | Planned | Q2 2027 |

### 7. Expected Contributions
- **First-of-its-Kind Closed Loop:** Dynamic pentest findings → verified GitHub PRs within minutes.
- **Regression-Free AI Patching:** AST-preserving prompting eliminating cascading dependencies.
- **Graph-RAG DevSecOps Formalization:** Reproducible STIX 2.1 knowledge graph schema.

### 8. References
See `docs/references.bib` for complete citation index (STIX 2.1, MITRE ATT&CK, PentestGPT, GraphRAG).
