---
key: idor
label: IDOR
endpoint: /api/user/102
method: GET
vulnerability_target: IDOR
payload_json: null
hardening_rule: block_unauthorized_idor
hypothesis: Direct object reference without authorization
owasp: A01:2021
skill_id: penguard-idor-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: legitimate object 101 returns the normal record schema
exploit_rule: cross-tenant object 102 returns another user's secret_note
verification_rule: exploit returns 200 with secret_note for object 102 while the benign baseline targets object 101
baseline_endpoint: /api/user/101
baseline_method: GET
baseline_payload_json: null
---
# IDOR

Probe a direct object reference that returns another user's confidential record.
A confirmed finding means authorization is not enforced on the object identifier.
