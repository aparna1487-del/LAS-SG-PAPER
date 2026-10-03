# LAS-SG

Research implementation of the LAS-SG elliptic-curve-based lightweight authentication scheme for smart-grid environments.

## Status

This is a **corrected research prototype**. The paper contains ambiguous ECC notation, so the implementation freezes the interpretation `SMpr = (Mk + sigma)^-1 P` and validates the algebraic invariant `(Mk + sigma) * BSM = ASM`. It is not suitable for real grid-control systems.

## Run

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest
python benchmarks/benchmark_authentication.py
```

## Security posture

The prototype uses P-256-style prime-field point arithmetic for reproducible research, HMAC-SHA256, HKDF, and AES-GCM helpers. Before production use, replace the isolated arithmetic layer with a vetted, audited ECC library and add a formal ProVerif model, side-channel review, secure provisioning, rate limiting, and a complete deployment threat model.
