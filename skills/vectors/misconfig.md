---
key: misconfig
label: Security Misconfiguration
endpoint: /api/debug
method: GET
vulnerability_target: Security Misconfiguration
payload_json: null
hardening_rule: block_misconfig
hypothesis: Debug endpoint leaks secrets
owasp: A05:2021
---
# Security Misconfiguration

Probe a debug surface for leaked secrets and confirm the endpoint is reachable
without authentication.
