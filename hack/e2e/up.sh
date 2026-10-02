#!/usr/bin/env bash
# Boot the end-to-end fixture from scratch and mint one API token per account.
#
# The image is hack/recon's (the same Dockerfile, which carries the plugins the
# fixture needs); the configuration is this directory's casc.yaml. It takes the
# recon instance's name and port by default: both are disposable, and two
# Jenkins JVMs on one laptop is one more than either needs.
#
# Two boots rather than one, as in recon: the multibranch projects need a git
# repository to index, and it has to exist inside the container before JCasC
# creates them.
#
# Writes out/tokens.env (0600). Minting a token is a POST with a crumb — the
# harness writes to its own disposable controller; the scan never does.
set -euo pipefail
cd "$(dirname "$0")"

NAME=${NAME:-jenkins-bench-recon}
PORT=${PORT:-18080}
IMAGE=${IMAGE:-jenkins-bench-recon:lts}
BASE="http://localhost:$PORT"
OUT=out
ACCOUNTS="admin reader extended sysread nojob"

if [ "${SKIP_BUILD:-}" != "1" ]; then
  docker build -q -t "$IMAGE" ../recon >/dev/null
fi

docker rm -f "$NAME" >/dev/null 2>&1 || true
# SystemRead and ExtendedRead are opt-in permissions: without these properties
# matrix-auth refuses to grant them, and the README's permission table could
# not be measured.
docker run -d --name "$NAME" -p "$PORT:8080" \
  -e ADMIN_PASSWORD=adminpw -e READER_PASSWORD=readerpw -e EXTENDED_PASSWORD=extendedpw \
  -e SYSREAD_PASSWORD=sysreadpw -e NOJOB_PASSWORD=nojobpw \
  -e JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Djenkins.security.SystemReadPermission=true -Dhudson.security.ExtendedReadPermission=true" \
  -v "$PWD/casc.yaml:/var/jenkins_conf/casc.yaml:ro" \
  "$IMAGE" >/dev/null

wait_up() {
  for _ in $(seq 1 120); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/login" 2>/dev/null)" = "200" ]; then
      return 0
    fi
    sleep 2
  done
  echo "the controller did not come up on :$PORT" >&2
  docker logs --tail 40 "$NAME" >&2
  exit 1
}

wait_up
docker exec "$NAME" bash -c '
  set -e
  rm -rf /var/jenkins_home/seed-repo
  mkdir -p /var/jenkins_home/seed-repo && cd /var/jenkins_home/seed-repo
  git init -q -b main .
  git config user.email e2e@example.com && git config user.name e2e
  printf "pipeline { agent any; stages { stage(\"a\") { steps { echo \"main\" } } } }\n" > Jenkinsfile
  git add -A && git commit -qm "main"
  git checkout -q -b release/1.0
  git commit -q --allow-empty -m "release"
  git checkout -q main
' >/dev/null

docker restart "$NAME" >/dev/null
wait_up
echo "up on :$PORT — $(curl -s -I "$BASE/login" | grep -i '^x-jenkins:' | tr -d '\r')"

if docker logs "$NAME" 2>&1 | grep -q "SEVERE.*ConfigurationAsCode\|ConfiguratorException\|ScriptException"; then
  echo "JCasC FAILED:" >&2
  docker logs "$NAME" 2>&1 | grep -B2 -A6 "SEVERE\|ConfiguratorException\|ScriptException" | grep -vE '^\s+at ' | head -40 >&2
  exit 1
fi

# Branch indexing runs asynchronously after boot. The verdicts do not depend on
# it — the scan never descends into a multibranch project — but a fixture
# still indexing is a fixture still changing under the scan.
for _ in $(seq 1 60); do
  if curl -sg -u admin:adminpw "$BASE/job/platform/job/multibranch-app/api/json?tree=jobs[name]" | jq -e '.jobs | length == 2' >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

mkdir -p "$OUT"
umask 077
: >"$OUT/tokens.env"
for user in $ACCOUNTS; do
  pw="${user}pw"
  jar=$(mktemp)
  crumb=$(curl -s -c "$jar" -u "$user:$pw" "$BASE/crumbIssuer/api/json" | jq -r '.crumbRequestField + ":" + .crumb')
  token=$(curl -s -b "$jar" -u "$user:$pw" -H "$crumb" -X POST \
    "$BASE/me/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken?newTokenName=e2e" |
    jq -r '.data.tokenValue')
  rm -f "$jar"
  if [ -z "$token" ] || [ "$token" = "null" ]; then
    echo "could not mint an API token for $user" >&2
    exit 1
  fi
  upper=$(printf '%s' "$user" | tr '[:lower:]' '[:upper:]')
  printf '%s_TOKEN=%s\n' "$upper" "$token" >>"$OUT/tokens.env"
done
printf 'JENKINS_URL=%s\n' "$BASE" >>"$OUT/tokens.env"

echo "job tree:"
curl -sg -u admin:adminpw "$BASE/api/json?tree=jobs[fullName,_class,jobs[fullName,_class,jobs[fullName,_class,jobs[fullName,_class]]]]" |
  jq -r '[.. | objects | select(has("fullName"))] | .[] | "  \(.fullName)  \(._class|split(".")|last)"'
echo "tokens written to $OUT/tokens.env"
