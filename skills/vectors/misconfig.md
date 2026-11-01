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
skill_id: penguard-misconfig-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: public home endpoint returns only the welcome message
exploit_rule: debug endpoint returns secret_key, db_password, and stack data
verification_rule: exploit body contains secret/debug markers absent from the public baseline
baseline_endpoint: /
baseline_method: GET
baseline_payload_json: null
---
# Security Misconfiguration

Probe a debug surface for leaked secrets and confirm the endpoint is reachable
without authentication.
