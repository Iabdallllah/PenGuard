# Security Policy

## Supported Versions

Only the `main` branch is supported. PenGuard is a research/demo platform —
do not expose it to untrusted networks without reviewing the notes below.

## Reporting a Vulnerability

Open a **GitHub Security Advisory** on `Iabdallllah/PenGuard`
(`Security → Advisories → New draft advisory`). Include:

- Affected endpoint or vector (`/api/...`, scenario key)
- Steps to reproduce (curl or episode ID)
- Impact assessment (read-only leak vs. write/persistence)

We aim to acknowledge within 72 hours. Do not open public issues for
unpatched vulnerabilities.

## Secret Handling

| Secret | Env var | Scope |
|---|---|---|
| API auth | `PENGUARD_API_KEY` | `POST /api/episodes/run`, `POST /api/episodes/{id}/approve`, `DELETE /api/episodes` |
| Dashboard key | `NEXT_PUBLIC_API_KEY` | Must match `PENGUARD_API_KEY` (sent as `X-API-Key`) |
| GitHub PRs/reviews | `GITHUB_TOKEN`, `GITHUB_TARGET_REPO` | `Iabdallllah/PenGuard` (capital `I`) |
| SOC alerts | `PENGUARD_WEBHOOK_URL` | Discord/Slack incoming webhook (optional) |
| LLM fallback | `GROQ_API_KEY` | Absence degrades to deterministic mock agents |

Rules enforced by `.gitignore` + CI:

- Real `.env*` files are never committed — only `.env.example` (placeholders).
- The `PENGUARD_API_KEY` dev default (`penguard-dev-token-2026`) is a
  **known fail-open fallback for local development**. Production MUST set a
  strong random value in Railway Variables, otherwise API "auth" is theater.
- Webhook payloads carry verdict fields only — never secrets or raw exploit
  query strings (XSS payloads in URLs are stripped to `base_url`).
- The `approve` endpoint verifies PR-URL ownership before posting any review.

## Cryptography Posture

- TLS terminates at the platform edge (Railway/Vercel/CDN); origin traffic
  stays inside the provider network or the isolated Docker sandbox.
- The `misconfig` vector probes TLS version (≥ 1.2), HSTS/CSP headers, and
  certificate validity; PQ-hybrid key agreement (X25519MLKEM768, FIPS 203)
  must be confirmed at the edge — see `docs/proposal.md §4.3`.
- Symmetric API keys rely on 256-bit randomness; Grover-class quantum
  speedups do not threaten them at this key size.

## Scope Notes (by design)

- Only the `xss` vector opens real GitHub PRs; other vectors return
  `pr_url: null` and approve with `409`.
- Background runs are single-flight; a redeploy mid-run drops the in-flight
  task (the episode stays `QUEUED`/`RUNNING` — re-dispatch after deploy).
