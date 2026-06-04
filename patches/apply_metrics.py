#!/usr/bin/env python3
"""Idempotent patcher: wire metrics into src/main.py and add the dependency.

Run from the repo root:  python3 patches/apply_metrics.py
"""
import pathlib
import sys

root = pathlib.Path(".")
main_py = root / "src" / "main.py"
pyproject = root / "pyproject.toml"

if not main_py.exists() or not pyproject.exists():
    sys.exit("Run this from the repo root (src/main.py and pyproject.toml must exist).")

# --- patch src/main.py ---
s = main_py.read_text()
if "push_metrics" in s:
    print("main.py already patched")
else:
    # Start a timer right before the scan phase.
    s = s.replace(
        "    # Phase 1: Scan\n",
        "    import time as _time\n"
        "    _run_start = _time.monotonic()\n\n"
        "    # Phase 1: Scan\n",
        1,
    )
    # Push metrics after the act phase, before output.
    s = s.replace(
        "    # Output\n",
        "    # Phase 4: Metrics (best-effort; no-op unless PUSHGATEWAY_URL is set)\n"
        "    from src.metrics import push_metrics\n"
        "    push_metrics(result, _time.monotonic() - _run_start)\n\n"
        "    # Output\n",
        1,
    )
    main_py.write_text(s)
    print("patched src/main.py")

# --- add prometheus-client dependency ---
p = pyproject.read_text()
if "prometheus-client" in p:
    print("pyproject.toml already has prometheus-client")
else:
    p = p.replace(
        '    "requests>=2.31.0",\n',
        '    "requests>=2.31.0",\n    "prometheus-client>=0.20.0",\n',
        1,
    )
    pyproject.write_text(p)
    print("added prometheus-client to pyproject.toml")

print("done")
