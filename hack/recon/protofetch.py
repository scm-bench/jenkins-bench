"""Build a jenkins-snapshot from a live controller and validate it.

A throwaway prototype of the fetcher, written to answer one question before any
Go exists: can the schema hold what the API actually returns? It follows the
same rules the real fetcher must — GET only, no secret leaves the controller,
and nothing is decided here that a policy should decide.
"""
import base64, json, sys, urllib.request, urllib.error, urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:18080"
USER, PW = (sys.argv[2] if len(sys.argv) > 2 else "admin:adminpw").split(":", 1)

GETS = []  # every request, so the read-only property can be asserted


def get(path, auth=True):
    """GET path. Returns (status, body_bytes, headers) and never raises."""
    url = BASE + path
    GETS.append(("GET", path))
    req = urllib.request.Request(url, method="GET")
    if auth:
        tok = base64.b64encode(f"{USER}:{PW}".encode()).decode()
        req.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, b"", dict(e.headers)
    except Exception:
        return 0, b"", {}


def getjson(path):
    code, body, _ = get(path)
    if code != 200:
        return code, None
    try:
        return code, json.loads(body)
    except json.JSONDecodeError:
        return code, None


def jobpath(full_name):
    """platform/api-service -> /job/platform/job/api-service

    Segments are percent-encoded. A name like "Team A" is ordinary, and quoting
    it with form rules (+ for space) returns a 404 that looks exactly like a job
    that does not exist.
    """
    segs = full_name.split("/")
    return "".join("/job/" + urllib.parse.quote(s, safe="") for s in segs)


# --- controller -----------------------------------------------------------
warnings, errors, available = [], [], {}

code, _, headers = get("/login", auth=False)
version = headers.get("X-Jenkins", "")

code, root = getjson("/api/json")
available["root"] = root is not None
if root is None:
    errors.append(f"instance API returned HTTP {code}")

security = {}
if root is not None:
    security = {
        "enabled": bool(root.get("useSecurity", False)), "enabledKnown": "useSecurity" in root,
        "csrfProtection": bool(root.get("useCrumbs", False)), "csrfProtectionKnown": "useCrumbs" in root,
    }
# The authorization strategy is not exposed anywhere, so anonymous read is
# measured rather than read: issue the same GET with no credentials.
anon_code, _, _ = get("/api/json", auth=False)
security["anonymousRead"] = anon_code == 200
security["anonymousReadKnown"] = anon_code in (200, 401, 403)

code, computers = getjson("/computer/api/json?depth=1")
available["agents"] = computers is not None
built_in, agents = {"numExecutorsKnown": False}, []
if computers is None:
    errors.append(f"nodes returned HTTP {code}")
else:
    for c in computers.get("computer") or []:
        if c.get("_class", "").endswith("Hudson$MasterComputer"):
            built_in = {"numExecutors": c.get("numExecutors", 0), "numExecutorsKnown": "numExecutors" in c}
        else:
            agents.append({
                "name": c.get("displayName", ""),
                "offline": bool(c.get("offline", False)),
                "temporarilyOffline": bool(c.get("temporarilyOffline", False)),
                "numExecutors": c.get("numExecutors", 0),
                "labels": [l["name"] for l in (c.get("assignedLabels") or [])],
            })

code, plug = getjson("/pluginManager/api/json?depth=1")
available["plugins"] = plug is not None
plugins = []
if plug is None:
    errors.append(f"plugins returned HTTP {code}; Overall/Administer is required")
else:
    plugins = [{
        "shortName": p.get("shortName", ""), "version": p.get("version", ""),
        "enabled": bool(p.get("enabled", False)), "active": bool(p.get("active", False)),
        "hasUpdate": bool(p.get("hasUpdate", False)),
    } for p in plug.get("plugins") or []]

code, uc = getjson("/updateCenter/site/default/api/json")
update_site = {"dataTimestampKnown": False}
available["updateSite"] = uc is not None
if uc is not None:
    ts = uc.get("dataTimestamp")
    update_site = {"url": uc.get("url", ""), "dataTimestampKnown": ts is not None}
    if ts:
        update_site["dataTimestamp"] = datetime.fromtimestamp(ts / 1000, timezone.utc).isoformat()

# Credentials: a 200 with no stores is what an unauthorised read looks like, so
# availability cannot come from the status. A successful /pluginManager read
# needs Overall/Administer, which proves any store that existed would be shown.
code, cred = getjson("/credentials/api/json?depth=3")
credentials, saw_a_store = [], False
if cred is not None:
    for store_name, store in (cred.get("stores") or {}).items():
        saw_a_store = True
        for dom_name, dom in (store.get("domains") or {}).items():
            for c in dom.get("credentials") or []:
                credentials.append({
                    "id": c.get("id", ""), "type": c.get("typeName", ""),
                    "store": store_name, "domain": dom_name,
                    "description": c.get("description", ""),
                })
available["credentials"] = cred is not None and (saw_a_store or available["plugins"])
if not available["credentials"]:
    errors.append("credential stores were not visible to this token")

controller = {
    "version": version, "security": security, "builtInNode": built_in,
    "agents": agents, "credentials": credentials, "plugins": plugins,
    "updateSite": update_site, "available": available, "errors": errors,
}

# --- jobs -----------------------------------------------------------------
CONTAINER = ("com.cloudbees.hudson.plugins.folder.Folder",)
MULTIBRANCH = "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"

def kind_of(cls):
    if cls == MULTIBRANCH:
        return "multibranch"
    if cls.endswith("WorkflowJob"):
        return "pipeline"
    if cls.endswith("FreeStyleProject"):
        return "freestyle"
    return "other"


def walk(path, out):
    """Walk folders recursively. A fixed-depth tree= expression silently drops
    anything nested deeper than it was written for."""
    code, data = getjson(path + "/api/json?tree=jobs[fullName,name,url,_class]")
    if data is None:
        return
    for j in data.get("jobs") or []:
        cls, full = j.get("_class", ""), j.get("fullName", "")
        if cls in CONTAINER:
            walk(jobpath(full), out)
            continue
        out.append(j)
        # A multibranch project is one job. Descending would produce one copy of
        # every finding per branch.


raw_jobs = []
walk("", raw_jobs)

builtin_labels = {"built-in", "master"}
jobs = []
for j in raw_jobs:
    full, cls = j["fullName"], j.get("_class", "")
    k = kind_of(cls)
    segs = full.split("/")
    job = {
        "fullName": full, "name": segs[-1], "folder": "/".join(segs[:-1]),
        "url": j.get("url", ""), "class": cls, "kind": k,
        "available": {}, "errors": [],
    }

    code, api = getjson(jobpath(full) + "/api/json")
    job["available"]["api"] = api is not None
    if api is not None:
        job["disabled"] = bool(api.get("disabled", False))
        job["buildable"] = bool(api.get("buildable", False))

    code, body, _ = get(jobpath(full) + "/config.xml")
    job["available"]["config"] = code == 200
    if code != 200:
        job["errors"].append(f"job configuration returned HTTP {code}; Job/ExtendedRead is required")
        job["runsOnBuiltInNodeKnown"] = False
        job["remoteTriggerTokenKnown"] = False
        jobs.append(job)
        continue

    x = ET.fromstring(body)
    # Never carry the raw XML or any of its text into the snapshot.
    d = x.find("definition")
    if k == "multibranch":
        definition = {"source": "scm"}
        src = x.find(".//sources//source/remote")
        if src is not None and src.text:
            definition["scmUrls"] = [src.text]
    elif d is not None:
        dc = d.get("class", "")
        if dc.endswith("CpsScmFlowDefinition"):
            definition = {"source": "scm"}
            sp = d.find("scriptPath")
            if sp is not None and sp.text:
                definition["scriptPath"] = sp.text
            urls = [u.text for u in d.findall(".//url") if u.text]
            if urls:
                definition["scmUrls"] = urls
        elif dc.endswith("CpsFlowDefinition"):
            sb = d.find("sandbox")
            definition = {
                "source": "inline",
                "sandbox": (sb is not None and (sb.text or "").strip() == "true"),
                "sandboxKnown": sb is not None,
            }
        else:
            definition = {"source": "unknown"}
    elif x.tag == "project":
        definition = {"source": "ui"}
    else:
        definition = {"source": "unknown"}
    job["definition"] = definition

    triggers = [{"type": t.tag.split(".")[-1], "spec": (t.findtext("spec") or "")}
                for t in x.findall(".//triggers/*")]
    job["triggers"] = triggers

    # Presence only. config.xml returns the token in cleartext.
    job["remoteTriggerToken"] = x.find("authToken") is not None
    job["remoteTriggerTokenKnown"] = True

    # Resolved in the fetcher: label expression + canRoam + the built-in node's
    # labels. A pipeline picks its agent in the Jenkinsfile, which the
    # controller does not expose, so the answer is unknown there.
    if k in ("pipeline", "multibranch"):
        job["runsOnBuiltInNodeKnown"] = False
    else:
        assigned = (x.findtext("assignedNode") or "").strip()
        can_roam = (x.findtext("canRoam") or "").strip() == "true"
        if assigned:
            job["runsOnBuiltInNode"] = assigned.lower() in builtin_labels
        else:
            job["runsOnBuiltInNode"] = can_roam and built_in.get("numExecutors", 0) > 0
        job["runsOnBuiltInNodeKnown"] = built_in.get("numExecutorsKnown", False)

    jobs.append(job)

snapshot = {
    "schemaVersion": "1",
    "metadata": {
        "tool": "protofetch", "toolVersion": "0", "platform": "jenkins",
        "baseUrl": BASE, "generatedAt": datetime.now(timezone.utc).isoformat(),
        "warnings": warnings,
    },
    "controller": controller,
    "jobs": jobs,
}

out = sys.argv[3] if len(sys.argv) > 3 else "snapshot.json"
json.dump(snapshot, open(out, "w"), indent=2, sort_keys=True)

non_get = [m for m, _ in GETS if m != "GET"]
print(f"requests: {len(GETS)}, non-GET: {len(non_get)}")
print(f"jobs: {len(jobs)}, plugins: {len(plugins)}, credentials: {len(credentials)}, agents: {len(agents)}")
print(f"written: {out}")
