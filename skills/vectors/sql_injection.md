---
key: sql_injection
label: SQL Injection
endpoint: "/api/records?query=' UNION SELECT id, name, secret_token FROM users -- "
method: GET
vulnerability_target: SQL Injection
payload_json: null
hardening_rule: block_sql_injection
hypothesis: Unsanitized query concatenation allows token dump
owasp: A03:2021
skill_id: penguard-sql-injection-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: benign query checkup returns only matching records
exploit_rule: UNION SELECT returns secret_token or MASTER_SECRET_KEY
verification_rule: exploit body contains token/secret markers absent from the benign baseline
baseline_endpoint: /api/records?query=checkup
baseline_method: GET
baseline_payload_json: null
---
# SQL Injection

Probe the records search surface with a UNION SELECT payload and look for token
or secret leakage in the response body.
