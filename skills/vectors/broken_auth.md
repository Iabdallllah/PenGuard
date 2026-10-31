---
key: broken_auth
label: Broken Authentication
endpoint: /api/login
method: POST
vulnerability_target: Broken Authentication
payload_json: '{"username": "admin", "password": "wrongpass"}'
hardening_rule: block_broken_auth
hypothesis: Any password authenticates admin
owasp: A07:2021
---
# Broken Authentication

Attempt an admin login with an invalid password and check whether a bypass token
or authenticated session is returned.
