#!/usr/bin/env bash
# Fixture tests for body-policy.sh.
#
# Deliberately fixture-only: the gate is NEVER proved by writing a real leak into a
# live public PR body, because doing so would publish the exact thing it guards.
#
# The negatives here are the load-bearing half. A leak gate that blocks everything
# is trivially "correct" and useless — it gets disabled within a week. The bare
# cross-reference case below is the one that keeps this gate deployable.
set -uo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/body-policy.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# The names the real gate is configured with come from an org variable; the tests
# pin their own so they are hermetic and do not depend on CI configuration.
#
# Every name below is INVENTED. This file is public and sits inside
# scripts/public-repo-guard/, which the tree scan and gitleaks deliberately
# exclude (the gate cannot scan its own fixtures without blocking itself), so a
# REAL private repo name or credential name written here would be published with
# no check standing in its way. Keep the names obviously fictional.
export GUARD_PRIVATE_REPOS="example-private-alpha, example-private-beta, example-private-gamma"

PASS=0; FAIL=0

# expect <exit-code> <name> <body-text>
expect() {
  local want="$1" name="$2" body="$3" out rc
  printf '%s\n' "$body" > "$TMP/body.txt"
  out="$(bash "$SCRIPT" "$TMP/body.txt" 2>&1)"; rc=$?
  if [[ "$rc" == "$want" ]]; then
    PASS=$((PASS+1)); printf '  ok   %s\n' "$name"
  else
    FAIL=$((FAIL+1)); printf '  FAIL %s — want exit %s, got %s\n%s\n' "$name" "$want" "$rc" "$out"
  fi
  # The annotation is world-readable; a hit must never echo the matched text.
  if [[ "$rc" == 1 ]] && printf '%s' "$out" | grep -qF "$body"; then
    FAIL=$((FAIL+1)); printf '  FAIL %s — LEAKED the matched text into the annotation\n' "$name"
  fi
}

echo "body-policy fixtures"

# --- must BLOCK ---------------------------------------------------------------
expect 1 'private repo + credential name' \
  'Flip is live: EXAMPLE_LEASE_ROTATION_SECRET is bound on example-private-alpha now.'
expect 1 'private repo + credential name, reverse order' \
  'The EXAMPLE_JOIN_SECRET was added; example-private-beta picks it up on deploy.'
# Regression: `_` is a word character, so a `\b`-anchored class without it could
# never enter EXAMPLE_LEASE_ROTATION_SECRET past its first segment in this order.
expect 1 'private repo FIRST + multi-segment credential name' \
  'example-private-alpha now reads EXAMPLE_LEASE_ROTATION_SECRET at boot.'
# Regression: prose detail stays case-insensitive after case scoping was fixed.
expect 1 'capitalized prose detail still blocks' \
  'This adds a Service Binding from the worker to example-private-gamma.'
expect 1 'private repo + secret count' \
  'example-private-alpha went from 74 secrets to 75 after this change.'
expect 1 'private repo + service binding' \
  'This adds a service binding from the worker to example-private-gamma for settlement.'
expect 1 'operator home path' \
  'Repro: run it from /Users/someoperator/Documents/notes and it fails.'  # enforce-ignore (fixture)
expect 1 'internal-only marker' \
  'Attaching the internal-only rollout plan for context.'
# Regression: the marker rule is case-insensitive — the most natural phrasing of
# a not-for-public warning starts a sentence with a capital.
expect 1 'sentence-initial capitalized marker' \
  'Do not share this rollout doc outside the team.'
# Assembled at run time rather than written as a literal: a fixture that LOOKS like
# a live AWS key trips this repo's own pre-commit secret scanners (it did, on the
# first draft). Splitting the prefix keeps the fixture exercising the real regex
# without parking a credential-shaped string in source.
AKID_FIXTURE="AKI""A1234567890ABCDEF"
expect 1 'AWS access key id' \
  "The failing job had ${AKID_FIXTURE} configured."
# Regression: the about-the-control exemption is internal-marker-only. A
# credential or wiring topology is a leak even on a line that names the gate:
# quoting a hit to discuss it re-publishes it.
expect 1 'credential on a line that also names the control' \
  "public-repo-guard already flagged ${AKID_FIXTURE} once; reposting for context."
expect 1 'topology on a line that names the control' \
  'body-policy should have flagged EXAMPLE_SECRET bound on example-private-alpha here.'
expect 1 'internal tailscale IP' \
  'It resolves to 100.71.4.19 from inside the fleet.'

# --- must PASS (precision — these keep the gate deployable) -------------------
expect 0 'bare private-repo cross-reference' \
  'This is the companion change to example-private-beta#260; merge that one first.'
expect 0 'two private repos, no operational detail' \
  'Both example-private-alpha and example-private-beta will need a follow-up for this.'
expect 0 'credential NAME with no private repo nearby' \
  'The handler now reads SOME_API_TOKEN from the environment instead of a literal.'
# Regression: case sensitivity is scoped. Lowercase identifiers are everyday
# code words, not SCREAMING_CASE credential names; a global (?i) blocked these.
expect 0 'lowercase api_key near a private repo' \
  'Companion to example-private-beta#260; fixes the api_key parsing.'
expect 0 'lowercase cache_key rename in a private repo' \
  'example-private-alpha: rename cache_key to slot_key.'
expect 0 'public runner path is not an operator path' \
  'CI checks out to /home/runner/work/repo/repo before the scan runs.'  # enforce-ignore (fixture)
expect 0 'talking about the control' \
  'body-policy blocks a private repo named next to a SECRET_TOKEN; that is intended.'
expect 0 'explicit guard:allow with a reason' \
  'Example for the docs: example-private-alpha holds EXAMPLE_SECRET — guard:allow documented-example'
expect 0 'ordinary clean body' \
  'Bumps the draft revision and regenerates the fixtures. No behaviour change.'
# Regression: the first CI run of this job failed on its own PR, because a review
# bot edited the body to summarize the change and quoted the marker verbatim.
expect 0 'marker MENTIONED in straight quotes is a description' \
  'Blocks infra identifiers and markers (account_id, home paths, "internal-only" text).'
expect 0 'marker MENTIONED in a code span' \
  'The rule matches `internal-only` and `for internal use` in body text.'
expect 0 'marker MENTIONED in smart quotes' \
  'Blocks operator home paths and “internal-only” text.'
expect 1 'marker USED unquoted still blocks' \
  'Attaching the internal-only rollout plan; do not share outside the team.'

# --- fail closed --------------------------------------------------------------
# Invoked directly, not through expect(): expect() always materializes a file, so
# it cannot reach these paths. A gate that returns "OK" when it was handed nothing
# to scan is the failure mode this whole file exists to prevent.
for case in "no argument at all::" "nonexistent path::$TMP/does-not-exist.txt"; do
  name="${case%%::*}"; arg="${case##*::}"
  if [[ -n "$arg" ]]; then bash "$SCRIPT" "$arg" >/dev/null 2>&1; else bash "$SCRIPT" >/dev/null 2>&1; fi
  rc=$?
  if [[ "$rc" == 2 ]]; then
    PASS=$((PASS+1)); printf '  ok   %s → exit 2 (fails closed)\n' "$name"
  else
    FAIL=$((FAIL+1)); printf '  FAIL %s — want exit 2, got %s\n' "$name" "$rc"
  fi
done

echo "  ---"
if (( FAIL > 0 )); then
  echo "  $PASS passed, $FAIL FAILED"; exit 1
fi
echo "  $PASS passed, 0 failed"
