# Execute the LAS-SG project

This repository is currently a Python protocol implementation, not a website or mobile app.

From the repository root:

```bash
python3 -m pip install -e '.[test]'
python3 examples/run_demo.py
pytest
python3 benchmarks/benchmark_authentication.py
```

The demo registers one smart meter with a NAN gateway, exchanges the two LAS-SG messages, derives the session key at both sides, and prints whether the keys match.
