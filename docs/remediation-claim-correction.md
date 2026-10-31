# Remediation Claim Correction — 2026-10-29

Source of claim: `README.md` lines 31/80 ("AST-safe Patch"); `docs/project-prd.html` (user-modified, preserved unchanged); `docs/mobile-api.md` (deleted file, preserved in working tree but not edited).

Actual behavior in `remediator.py` (verified from full file read, not fabricated):
- String-based / text-boundary slicing (`original_full.find()`, `before/after` slicing, `replace()` concatenation).
- No AST module (`ast`, `libcst`, `parso`) used.
- Patch verification relies on retest (HTTP 4xx), not AST structural equality.

Corrections applied:
- `README.md`: both references changed from "AST-safe Patch" to "String-Based Text Patch".
- `docs/project-prd.html`: preserved unchanged (user-modified file; claim remains there but is now explicitly contradicted by this correction doc and by `remediator.py` source reality).
- `docs/mobile-api.md`: preserved unchanged (deleted file; no edit made).
- `docs/remediation-claim-correction.md`: this file.

No AST rewrite implemented in this pass (deferred, per instructions).
No unrelated working-tree changes altered.
