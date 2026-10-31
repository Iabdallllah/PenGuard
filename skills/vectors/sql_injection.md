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
---
# SQL Injection

Probe the records search surface with a UNION SELECT payload and look for token
or secret leakage in the response body.
