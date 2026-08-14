#!/usr/bin/env bash
# Probe every candidate endpoint with each credential and record what came back.
#
# The output is the point: for each (endpoint, credential) pair we want the HTTP
# status and the body, because the status is what the fetcher turns into an
# `available` key and the body is what the snapshot has to be able to hold.
set -uo pipefail

BASE=${BASE:-http://localhost:18080}
OUT=${OUT:-$(dirname "$0")/out}
mkdir -p "$OUT"

# name:credential pairs. admin has Overall/Administer; reader has only
# Overall/Read + Job/Read, and anon has nothing.
declare -a CREDS=("admin:admin:adminpw" "reader:reader:readerpw" "anon:")

SUMMARY="$OUT/summary.tsv"
: > "$SUMMARY"
printf 'endpoint\tadmin\treader\tanon\n' >> "$SUMMARY"

probe() {
  local label=$1 path=$2
  local row="$label"
  for entry in "${CREDS[@]}"; do
    local who=${entry%%:*}
    local userpass=${entry#*:}
    local file="$OUT/${label}.${who}"
    local code
    if [ -z "$userpass" ]; then
      # -g turns off curl's URL globbing: Jenkins tree= expressions are full of
      # [ ] and *, which curl otherwise tries to expand and then refuses the URL.
      code=$(curl -sg -o "$file" -w '%{http_code}' "$BASE$path")
    else
      code=$(curl -sg -o "$file" -w '%{http_code}' -u "$userpass" "$BASE$path")
    fi
    row="$row\t$code"
    # A non-2xx body is an HTML error page; keep the status, drop the noise.
    if [ "$code" != "200" ]; then
      printf '%s\n' "HTTP $code" > "$file"
    fi
  done
  printf "$row\n" >> "$SUMMARY"
}

# --- controller-level ------------------------------------------------------
probe "root-api"          "/api/json"
probe "root-config-xml"   "/config.xml"
probe "crumb"             "/crumbIssuer/api/json"
probe "whoami"            "/whoAmI/api/json"
probe "plugins"           "/pluginManager/api/json?depth=1"
probe "computers"         "/computer/api/json?depth=1"
probe "queue"             "/queue/api/json"
# depth=3 minimum: at depth=2 the array is the right length and every element is
# an empty object, so a fetcher that counts is satisfied and every field it then
# reads is blank. A tree= over these map-valued fields
# returns the wrappers and no credentials at any depth, which looks exactly like
# an instance with none.
probe "credentials"       "/credentials/api/json?depth=3"
probe "credentials-tree"  "/credentials/api/json?tree=stores[*[domains[*[credentials[id,typeName]]]]]"
probe "credentials-store" "/credentials/store/system/domain/_/api/json?depth=2"
probe "manage-nodes-xml"  "/computer/build-agent-1/config.xml"
probe "updatecenter"      "/updateCenter/site/default/api/json"
probe "systeminfo"        "/systemInfo"

# --- job listing: does tree recurse into folders? --------------------------
probe "jobs-flat"         "/api/json?tree=jobs[fullName,name,_class,color]"
probe "jobs-nested2"      "/api/json?tree=jobs[fullName,_class,jobs[fullName,_class,jobs[fullName,_class]]]"
probe "jobs-depth2"       "/api/json?depth=2&tree=jobs[fullName,_class,jobs[fullName,_class]]"

# --- per-job ---------------------------------------------------------------
for job in "legacy-build" "disabled-job" "platform/api-service" "platform/inline-deploy" \
           "platform/inline-nosandbox" "platform/multibranch-app" "platform/multibranch-app/main"; do
  # A nested job is addressed as /job/a/job/b — every path segment gets its own
  # /job/ prefix. sed rather than bash substitution, which leaves the escaping
  # backslashes in the replacement literal.
  jobpath="/job/$(printf '%s' "$job" | sed 's#/#/job/#g')"
  label="job-$(echo "$job" | tr '/' '_')"
  probe "$label-api"    "$jobpath/api/json"
  probe "$label-config" "$jobpath/config.xml"
done

column -t -s $'\t' "$SUMMARY"
