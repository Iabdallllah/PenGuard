---
key: ssrf
label: SSRF
endpoint: "/api/fetch?url=http://169.254.169.254/latest/meta-data/"
method: GET
vulnerability_target: SSRF
payload_json: null
hardening_rule: block_ssrf
hypothesis: Server fetches internal metadata URL
owasp: A10:2021
---
# SSRF

Ask the target to fetch a link-local metadata URL and check whether internal
metadata is returned.
