#!/usr/bin/env bash
# Bring up the recon instance from scratch, deterministically.
#
# Two boots rather than one: the multibranch job needs a git repo to index, and
# the repo has to exist inside the container before JCasC creates the job. The
# first boot only exists to give us a filesystem to seed.
set -euo pipefail
cd "$(dirname "$0")"

CASC=${1:-casc.yaml}
NAME=jenkins-bench-recon
PORT=${PORT:-18080}

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "$PORT:8080" \
  -e ADMIN_PASSWORD=adminpw -e READER_PASSWORD=readerpw \
  -v "$PWD/$CASC:/var/jenkins_conf/casc.yaml:ro" \
  jenkins-bench-recon:lts >/dev/null

sleep 3
docker exec "$NAME" bash -c '
  set -e
  rm -rf /var/jenkins_home/seed-repo
  mkdir -p /var/jenkins_home/seed-repo && cd /var/jenkins_home/seed-repo
  git init -q -b main .
  git config user.email r@example.com && git config user.name recon
  printf "pipeline { agent any; stages { stage(\"a\") { steps { echo \"main\" } } } }\n" > Jenkinsfile
  git add -A && git commit -qm "main"
  git checkout -q -b release/1.0
  git commit -q --allow-empty -m "release"
  git checkout -q main
' >/dev/null

docker restart "$NAME" >/dev/null
for i in $(seq 1 90); do
  if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/login" 2>/dev/null)" = "200" ]; then
    echo "up on :$PORT after $((i*2))s — $(curl -s -I "http://localhost:$PORT/login" | grep -i '^x-jenkins:' | tr -d '\r')"
    break
  fi
  sleep 2
done

if docker logs "$NAME" 2>&1 | grep -q "SEVERE.*ConfigurationAsCode"; then
  echo "JCasC FAILED:" >&2
  docker logs "$NAME" 2>&1 | grep -A2 "SEVERE" | grep -vE '^\s+at ' | head -10 >&2
  exit 1
fi
# Multibranch indexing runs asynchronously on first boot.
sleep 20
echo "job tree:"
curl -sg -u admin:adminpw "http://localhost:$PORT/api/json?tree=jobs[fullName,_class,jobs[fullName,_class,jobs[fullName,_class]]]" \
  | jq -r '[.. | objects | select(has("fullName"))] | .[] | "  \(.fullName)  \(._class|split(".")|last)"'
