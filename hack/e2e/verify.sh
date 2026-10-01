#!/usr/bin/env bash
# Scan the fixture with each token and compare every verdict against
# expected/<profile>.tsv. Exits 1 on any difference.
#
#   ./verify.sh                 every profile, then the scope and exit checks
#   ./verify.sh admin           one profile
#   BIN=/path/to/jenkins-bench ./verify.sh
#
# Beside the verdicts it asserts what the tool promises about itself, against a
# real controller rather than a stand-in:
#   - the closing accounting line reports zero writes, for every token;
#   - no secret planted in casc.yaml reaches a snapshot or a report;
#   - reports and snapshots are written 0600;
#   - a token without Job/Read makes the scan exit 2, not 0;
#   - --folder and --job narrow the scan, and a target that does not exist is
#     an error, not an empty report.
set -euo pipefail
cd "$(dirname "$0")"

BIN=${BIN:-../../bin/jenkins-bench}
OUT=out
# shellcheck disable=SC1091
. "$OUT/tokens.env"

python3 expected.py >/dev/null

# A case rather than an associative array: macOS still ships bash 3.2.
token_for() {
  case "$1" in
  admin) echo "$ADMIN_TOKEN" ;;
  reader) echo "$READER_TOKEN" ;;
  extended) echo "$EXTENDED_TOKEN" ;;
  sysread) echo "$SYSREAD_TOKEN" ;;
  nojob) echo "$NOJOB_TOKEN" ;;
  *)
    echo "unknown profile $1" >&2
    exit 2
    ;;
  esac
}

# Every secret the fixture plants, straight from the file that plants them.
secrets=$(grep -o 'e2e-planted[A-Za-z0-9-]*' casc.yaml | sort -u)

# A config file in the working directory or the user's config directory must
# not leak into the comparison, so every scan runs against this one. failOn
# none: a finding is exit 1 by design, and exit 1 is not what is under test.
printf 'scan:\n  failOn: none\n' >"$OUT/empty.yaml"

# mode prints a file's permission bits on macOS and Linux alike.
mode() { stat -f '%Lp' "$1" 2>/dev/null || stat -c '%a' "$1"; }

scan() {
  local profile=$1
  shift
  "$BIN" scan --config "$OUT/empty.yaml" --url "$JENKINS_URL" \
    --username "$profile" --token "$(token_for "$profile")" "$@"
}

failed=0
fail() {
  echo "$*" >&2
  failed=1
}

profiles=("$@")
[ ${#profiles[@]} -eq 0 ] && profiles=(admin reader extended sysread)

for profile in "${profiles[@]}"; do
  report=$OUT/$profile.report.json
  snapshot=$OUT/$profile.snapshot.json
  rm -f "$report" "$snapshot"
  set +e
  scan "$profile" -v --snapshot-out "$snapshot" -o json --output-file "$report" 2>"$OUT/$profile.stderr"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    fail "[$profile] scan exited $status:"
    tail -5 "$OUT/$profile.stderr" >&2
    continue
  fi
  if ! grep -q ' 0 writes · read-only' "$OUT/$profile.stderr"; then
    fail "[$profile] the closing trace does not assert read-only:"
    grep '✓\|✗' "$OUT/$profile.stderr" >&2 || true
  fi
  for secret in $secrets; do
    if grep -q -- "$secret" "$snapshot" "$report" "$OUT/$profile.stderr"; then
      fail "[$profile] the planted secret $secret reached the output"
    fi
  done
  for file in "$report" "$snapshot"; do
    if [ "$(mode "$file")" != "600" ]; then
      fail "[$profile] $file is mode $(mode "$file"), not 600"
    fi
  done
  if ! python3 - "$profile" "$report" <<'EOF'; then failed=1; fi
import json, sys
profile, report = sys.argv[1], sys.argv[2]
want = {}
for line in open(f"expected/{profile}.tsv"):
    if line.startswith("#") or not line.strip():
        continue
    control, resource, status = line.rstrip("\n").split("\t")
    want[(control, resource)] = status
got, details = {}, {}
for f in json.load(open(report))["findings"]:
    key = (f["checkId"], f["resource"])
    got[key] = f["status"]
    details[key] = f.get("details", "")
bad = []
for key in sorted(set(want) | set(got)):
    w, g = want.get(key, "absent"), got.get(key, "absent")
    if w != g:
        bad.append((key, w, g))
if bad:
    print(f"[{profile}] {len(bad)} of {len(want)} verdicts differ:")
    for (control, resource), w, g in bad:
        print(f"  {control:<22} {resource:<32} want {w:<6} got {g:<6} {details.get((control, resource), '')[:100]}")
    sys.exit(1)
print(f"[{profile}] all {len(want)} verdicts as expected")
EOF
done

# The rest runs only with every profile, so `./verify.sh admin` stays quick.
if [ $# -gt 0 ]; then
  exit $failed
fi

# A token without Job/Read is handed an empty job list, not a refusal. That
# scan audited no job, and must say so with exit 2.
set +e
scan nojob -o json --output-file "$OUT/nojob.report.json" 2>"$OUT/nojob.stderr"
status=$?
set -e
if [ "$status" -ne 2 ] || ! grep -q 'Job/Read' "$OUT/nojob.stderr"; then
  fail "[nojob] exit $status; a scan that saw no job must exit 2 and name Job/Read:"
  tail -3 "$OUT/nojob.stderr" >&2
else
  echo "[nojob] exit 2: no job was evaluated"
fi
# And the reports say so themselves, for a CI view that draws them without
# reading the exit code: its controller test cases can all pass.
scan nojob -o sarif --output-file "$OUT/nojob.sarif" 2>/dev/null || true
scan nojob -o junit --output-file "$OUT/nojob.xml" 2>/dev/null || true
if ! python3 - "$OUT/nojob.sarif" "$OUT/nojob.xml" <<'EOF'; then
import json, sys
import xml.etree.ElementTree as ET
sarif = json.load(open(sys.argv[1]))
assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False, "SARIF says the run succeeded"
cases = ET.parse(sys.argv[2]).getroot().iter("testcase")
assert any(c.get("name") == "jobs" and c.get("classname") == "scan.coverage" and c.find("failure") is not None
           for c in cases), "JUnit has no failing scan.coverage case for the jobs"
EOF
  fail "[nojob] the SARIF or JUnit report reads as a clean run"
else
  echo "[nojob] SARIF marks the run unsuccessful; JUnit fails scan.coverage/jobs"
fi

# resources prints the job resources a JSON report holds, one per line.
resources() {
  python3 -c 'import json,sys; print("\n".join(sorted({f["resource"] for f in json.load(open(sys.argv[1]))["findings"] if f["resourceType"] == "job"})))' "$1"
}

# --folder: everything under it, at any depth, and nothing else.
scan admin --folder org -o json --output-file "$OUT/scope-folder.json" 2>/dev/null || true
if [ "$(resources "$OUT/scope-folder.json")" != "org/team-a/deep/nightly" ]; then
  fail "[scope] --folder org reported: $(resources "$OUT/scope-folder.json" | tr '\n' ' ')"
fi

# --job, repeatable and additive: a name that needs percent-encoding, and a
# branch job whose name carries an encoded slash (release%2F1.0), which has to
# be encoded again on the way into a URL.
scan admin --job 'Équipe A+B/déploiement (prod)' --job 'platform/multibranch-app/release%2F1.0' \
  -o json --output-file "$OUT/scope-job.json" 2>/dev/null || true
want=$(printf '%s\n%s' 'platform/multibranch-app/release%2F1.0' 'Équipe A+B/déploiement (prod)')
if [ "$(resources "$OUT/scope-job.json")" != "$want" ]; then
  fail "[scope] --job reported: $(resources "$OUT/scope-job.json" | tr '\n' ' ')"
fi

# A target that does not exist is an error naming it, not an empty report.
set +e
scan admin --folder no-such-folder -o json --output-file "$OUT/scope-missing.json" 2>"$OUT/scope-missing.stderr"
status=$?
set -e
if [ "$status" -ne 2 ] || ! grep -q 'no-such-folder' "$OUT/scope-missing.stderr"; then
  fail "[scope] --folder no-such-folder exited $status; want 2 naming it"
fi
if [ "$failed" -eq 0 ]; then
  echo "[scope] --folder, --job and a missing target behave"
fi

exit $failed
