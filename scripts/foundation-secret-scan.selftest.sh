#!/usr/bin/env bash
# Verifies the foundation secret scan never prints matched credential material.
# Run from repo root: bash scripts/foundation-secret-scan.selftest.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WF="$ROOT/.github/workflows/_checks.yml"

fail() { echo "FAIL: $*" >&2; exit 1; }

# Policy: the workflow must redact HITS, not echo them raw.
grep -q 'echo "\$HITS"' "$WF" && fail "_checks.yml still contains unredacted echo \"\$HITS\""
grep -q 'match redacted' "$WF" || fail "_checks.yml is missing file:line redaction"

# Behavior: raw grep includes the canary; the sed used in _checks.yml must strip it.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# Runtime-only canary — never committed. Matches ghp_[A-Za-z0-9]{30}.
CANARY="ghp_$(python3 -c 'print("A"*36)')"
printf 'token = %s\n' "$CANARY" > "$TMP/leak.txt"

RAW="$(
  grep -rIEn 'ghp_[A-Za-z0-9]{30}' --exclude-dir=.git "$TMP" || true
)"
[[ "$RAW" == *"$CANARY"* ]] || fail "fixture did not match the secret-scan pattern"

REDACTED="$(printf '%s\n' "$RAW" | sed -E 's/^([^:]+:[0-9]+):.*/\1: «match redacted — open this location to view»/')"
[[ "$REDACTED" == *"$CANARY"* ]] && fail "redaction leaked the matched value"
[[ "$REDACTED" == *leak.txt:* ]] || fail "redaction dropped the file:line locator"
[[ "$REDACTED" == *match\ redacted* ]] || fail "redaction marker missing"

echo "foundation-secret-scan.selftest: OK"
