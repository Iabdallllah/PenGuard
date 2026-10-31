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
---
# IDOR

Probe a direct object reference that returns another user's confidential record.
A confirmed finding means authorization is not enforced on the object identifier.
