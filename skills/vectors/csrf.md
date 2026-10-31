---
key: csrf
label: CSRF
endpoint: /api/transfer
method: POST
vulnerability_target: CSRF
payload_json: '{"to": "attacker", "amount": 1000}'
hardening_rule: block_csrf
hypothesis: Missing CSRF token allows forged transfer
owasp: A01:2021
---
# CSRF

Submit a state-changing transfer without a CSRF token and check whether it is
accepted.
