# Protocol audit log

## 2026-10-03 — Initial implementation audit

- The paper’s private-key notation is typeset ambiguously. This implementation uses `SMpr = (Mk + sigma)^-1 P`.
- With `BSM = u * SMpr`, the NAN reconstructs `ASM = (Mk + sigma) * BSM = uP`.
- The shared ephemeral term is now typed as `FN = (v * st_scalar) * ASM` at the NAN and `FN' = (u * st_scalar) * CN` at the SM, where `st_scalar = int(ST) mod n`; both values are the same point.
- The implementation must therefore be treated as a **corrected executable prototype**, not a claim of byte-for-byte reproduction of the published protocol.
- A later IEEE comment (DOI `10.1109/TII.2026.3668698`) flags a critical inconsistency in LAS-SG; formal security claims must remain pending until that critique is fully reconciled with the final protocol equations.
- Next hardening step: reconcile this typed interpretation with the 2026 IEEE critique and update the ProVerif model with the finalized transcript.
