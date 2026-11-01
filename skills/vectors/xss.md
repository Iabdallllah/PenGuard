---
key: xss
label: XSS
endpoint: "/api/search?q=%3Cscript%3Ealert('xss')%3C/script%3E"
method: GET
vulnerability_target: XSS
payload_json: null
hardening_rule: block_xss
hypothesis: Reflected XSS via unsanitized q parameter
owasp: A03:2021
skill_id: penguard-xss-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: benign q=hello is reflected as plain text
exploit_rule: script payload is reflected without encoding
verification_rule: exploit body contains a script marker absent from the benign baseline
baseline_endpoint: /api/search?q=hello
baseline_method: GET
baseline_payload_json: null
---
# Reflected XSS

Submit a script payload to the search surface and check whether it is reflected
without encoding.
