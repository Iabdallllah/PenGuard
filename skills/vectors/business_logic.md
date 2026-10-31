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
---
# Business Logic Abuse

Submit a negative quantity/price payload and check whether the server accepts an
impossible billing state.
