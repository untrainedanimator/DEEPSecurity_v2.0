#!/usr/bin/env bash
# Launcher for continuous_tests on Unix. Uses the venv's Python if present.
set -e
cd "$(dirname "$0")/.."
if [ -x .venv/bin/python ]; then
  .venv/bin/python scripts/continuous_tests.py "$@"
else
  python3 scripts/continuous_tests.py "$@"
fi
