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
skill_id: penguard-broken-auth-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: valid non-admin user login returns that user's token
exploit_rule: admin login with a wrong password returns an admin bypass token
verification_rule: exploit response contains an admin bypass token while the baseline authenticates a different user
baseline_endpoint: /api/login
baseline_method: POST
baseline_payload_json: '{"username": "alice", "password": "alice123"}'
---
# Broken Authentication

Attempt an admin login with an invalid password and check whether a bypass token
or authenticated session is returned.
