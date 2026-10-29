#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/docs/evidence"
(cd "$ROOT" && .venv/bin/pytest -q) >"$ROOT/docs/evidence/tests.txt" 2>&1
(cd "$ROOT" && examples/demo.sh) >"$ROOT/docs/evidence/demo.txt" 2>&1
printf 'Evidence written to %s/docs/evidence/\n' "$ROOT"
