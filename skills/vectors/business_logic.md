---
key: business_logic
label: Business Logic Abuse
endpoint: /api/checkout
method: POST
vulnerability_target: Business Logic Abuse
payload_json: '{"item_id": "license_pro", "quantity": -1, "unit_price": 250.0}'
hardening_rule: block_business_logic_abuse
hypothesis: Negative quantity bypasses billing invariant
owasp: A04:2021
skill_id: penguard-business-logic-v1
tactics_applied: baseline,exploit,detect,harden,retest
baseline_rule: quantity 1 at catalog price is accepted with a positive total_billed
exploit_rule: quantity -1 produces a negative total_billed
verification_rule: exploit total_billed is negative while the benign baseline total_billed is positive
baseline_endpoint: /api/checkout
baseline_method: POST
baseline_payload_json: '{"item_id": "license_pro", "quantity": 1, "unit_price": 250.0}'
---
# Business Logic Abuse

Submit a negative quantity/price payload and check whether the server accepts an
impossible billing state.
