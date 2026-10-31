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
---
# Reflected XSS

Submit a script payload to the search surface and check whether it is reflected
without encoding.
