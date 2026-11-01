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
skill_id: penguard-csrf-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: benign transfer to friend without a token establishes normal transfer behavior
exploit_rule: forged transfer to attacker succeeds without an X-CSRF-Token
verification_rule: exploit transfer is accepted with status 200 and no CSRF token
baseline_endpoint: /api/transfer
baseline_method: POST
baseline_payload_json: '{"to": "friend", "amount": 10}'
---
# CSRF

Submit a state-changing transfer without a CSRF token and check whether it is
accepted.
