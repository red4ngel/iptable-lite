#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
EVIDENCE_TMP=$(mktemp -d "${TMPDIR:-/tmp}/iptable-lite-live.XXXXXX")
mkdir -p "$ROOT/docs/evidence/live"

# Keep the evidence directory owned by the invoking user; sudo only runs the
# opt-in namespace test and writes into this pre-created temporary directory.
set +e
sudo env \
  IPTABLE_LITE_LIVE=1 \
  IPTABLE_LITE_LIVE_EVIDENCE_DIR="$EVIDENCE_TMP" \
  PYTHONPATH="$ROOT" \
  "$ROOT/.venv/bin/pytest" -q \
  "$ROOT/tests/integration/test_live_nfqueue_namespace.py" \
  >"$EVIDENCE_TMP/pytest.txt" 2>&1
TEST_STATUS=$?
set -e

cp "$EVIDENCE_TMP"/* "$ROOT/docs/evidence/live/"
printf 'Live evidence written to %s/docs/evidence/live/\n' "$ROOT"
exit "$TEST_STATUS"
