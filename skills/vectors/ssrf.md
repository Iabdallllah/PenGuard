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
skill_id: penguard-ssrf-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: external https example.com fetch returns non-leaked content
exploit_rule: link-local metadata URL returns leaked internal metadata
verification_rule: exploit body contains leaked/ami-id/secret markers absent from the benign baseline
baseline_endpoint: /api/fetch?url=https://example.com
baseline_method: GET
baseline_payload_json: null
---
# SSRF

Ask the target to fetch a link-local metadata URL and check whether internal
metadata is returned.
