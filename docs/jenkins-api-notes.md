# What a Jenkins controller will tell you

Measured against **Jenkins 2.541.2** (`jenkins/jenkins:lts`, August 2026) using the
harness in [`hack/recon/`](../hack/recon). Every status code and field name below
was observed, not recalled. Re-run `hack/recon/up.sh && hack/recon/probe.sh` to
reproduce the table.

This exists because the snapshot schema and the control set both depend on one
question — *which parts of a controller can a read-only HTTP client actually
see, and at what permission level?* — and that question cannot be answered by
reading documentation.

---

## Three credentials, three answers

The recon instance defines two accounts under a global matrix strategy:

- **admin** — `Overall/Administer`
- **reader** — `Overall/Read` + `Job/Read`, and deliberately *not*
  `Job/ExtendedRead`
- **anonymous** — nothing

| Endpoint | admin | reader | anon |
| --- | --- | --- | --- |
| `/api/json` | 200 | 200 | 403 |
| `/whoAmI/api/json` | 200 | 200 | **200** |
| `/crumbIssuer/api/json` | 200 | 200 | 403 |
| `/computer/api/json?depth=1` | 200 | 200 | 403 |
| `/queue/api/json` | 200 | 200 | 403 |
| `/credentials/api/json?depth=2` | 200 | **200, empty** | 403 |
| `/credentials/store/system/domain/_/api/json` | 200 | **404** | 403 |
| `/pluginManager/api/json?depth=1` | 200 | **403** | 403 |
| `/updateCenter/site/default/api/json` | 200 | **403** | 403 |
| `/computer/<agent>/config.xml` | 200 | **403** | 403 |
| `/systemInfo` | 200 | **403** | 403 |
| `/job/<path>/api/json` | 200 | 200 | 403 |
| `/job/<path>/config.xml` | 200 | **403** | 403 |

Read the bolded cells as the shape of this bench's `available` map. Everything a
`reader` cannot see has to become `MANUAL`, and there is a lot of it.

### The `X-Jenkins` header needs no credential at all

`GET /login` returns `X-Jenkins: 2.541.2` unauthenticated. The controller version
is therefore always knowable, even when nothing else is — useful for
`metadata`, and worth stating plainly in a report.

---

## The five findings that change the design

### 1. There is no endpoint for the controller's security configuration

`GET /config.xml` at the root does **not** return `$JENKINS_HOME/config.xml`. The
root URL is the primary view, so it returns that view's configuration:

```xml
<?xml version="1.1" encoding="UTF-8"?>
<hudson.model.AllView>
  <name>all</name>
  ...
</hudson.model.AllView>
```

`tree=securityRealm[*]` and `tree=authorizationStrategy[*]` both return
`{"_class":"hudson.model.Hudson"}` — the fields are not exported. `/manage/api/json`
carries nothing useful and `/configureSecurity/api/json` is a 404.

**So the security realm and authorization strategy class names cannot be read at
all.** Any control phrased as "is the authorization strategy X?" is
`automated: false` — permanently.

What *is* readable, from `/api/json`, is enough to ask the questions that matter:

| Field | Meaning |
| --- | --- |
| `useSecurity` | security is enabled at all |
| `useCrumbs` | CSRF protection is on |
| `numExecutors` | the built-in node's executor count |
| `slaveAgentPort` | `-1` disabled, `0` random, otherwise fixed |
| `mode` | `NORMAL` or `EXCLUSIVE` |
| `quietingDown` | |

And for anonymous access, the answer is a **probe, not a field**: issue the same
`GET /api/json` with no credentials. Verified in both directions —

- anonymous granted nothing → `403`
- anonymous granted `Overall/Read` → `200`

This is a read-only, idempotent GET, so it stays inside the contract's
GET-only rule. It is the only way to answer the question.

### 2. `config.xml` returns secrets in cleartext

A freestyle job's remote trigger token comes back as-is:

```xml
<authToken>notarealtoken</authToken>
```

A snapshot is written to disk and re-evaluated later, elsewhere. **The fetcher
must never put raw `config.xml` into the snapshot**, and must extract booleans
and class names only — `remoteTriggerToken: true`, never the token. This belongs
in the domain schema as a rule, not left to each fetcher's judgement.

### 3. Every job-scope control needs `config.xml`, which `reader` cannot fetch

`/job/<path>/api/json` exposes `_class`, `disabled`, `buildable`,
`concurrentBuild`, `description`, build history — and **nothing about how the job
is defined**. No `definition`, no `sandbox`, no `authToken`, no `assignedNode`.

Everything the interesting controls need is in `config.xml`, which requires
`Job/ExtendedRead` (or `Job/Configure`):

| Question | Where the answer lives |
| --- | --- |
| Are build steps defined as code? | `<definition class="…CpsScmFlowDefinition">` vs `CpsFlowDefinition` vs a `<project>` root element (freestyle) |
| Is the Groovy sandbox on? | `<sandbox>true\|false</sandbox>` |
| Is there a remote trigger token? | `<authToken>` present |
| Is the job pinned to the built-in node? | `<assignedNode>` + `<canRoam>` |
| Is the job disabled? | `<disabled>` (also in `api/json`) |
| What triggers it? | `<triggers>`, or `PipelineTriggersJobProperty` under `<properties>` for pipelines |

The three definition shapes, observed:

```xml
<!-- pipeline as code, from SCM -->
<definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition">
  <scm class="hudson.plugins.git.GitSCM">…</scm>
  <scriptPath>Jenkinsfile</scriptPath>
</definition>

<!-- pipeline script stored in Jenkins -->
<definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
  <script>…</script>
  <sandbox>true</sandbox>
</definition>

<!-- freestyle: build steps are UI configuration, not code -->
<project>
  <builders><hudson.tasks.Shell><command>echo building</command></hudson.tasks.Shell></builders>
  <assignedNode>built-in</assignedNode>
  <authToken>…</authToken>
</project>
```

A token with `Overall/Read` + `Job/Read` therefore produces a report in which
**every job-scope control is `MANUAL`**. That is the correct answer, and it is
worth making the report say so loudly rather than printing an empty findings
table.

### 4. An unreadable credentials store looks exactly like an empty one

```
admin  → {"stores":{"system":{"domains":{"_":{…}}}}}
reader → {"stores":{}}                                    HTTP 200
```

No 403, no error — a `200` with nothing in it. A fetcher that records
`credentials: []` here hands the policy layer a lie, and a control counting
global credentials would report `PASS`.

This is the domain-schema rule from `scm-snapshot.md` ("a count of 0, an empty
list and a missing capability must never be the same value") arriving in its
sharpest form. The snapshot needs an explicit completeness flag, and the
`available` key has to be set from *whether the store list was non-empty for a
principal that should see stores*, not from the HTTP status.

The per-store URL is more honest — `reader` gets a `404` on
`/credentials/store/system/domain/_/api/json` — but a `404` is also what a
controller without the credentials plugin returns, so it cannot be read as
"permission denied" either.

Two things about the query itself, both of which fail the same silent way —
`200` with no credentials, indistinguishable from an instance that has none:

- **`depth` must be at least 2.** At `depth=1` the response stops at the domain
  wrapper.
- **A `tree=` expression does not work here.** `tree=stores[*[domains[*[credentials[id,typeName]]]]]`
  returns the wrappers and no credentials at *any* depth, because the `*`
  wildcard does not descend into these map-valued fields. Use plain `depth=2`,
  or the explicit per-store URL, which needs no `depth` at all.

In both failure modes the `credentials` key is **absent from the domain object**,
not present and empty — which is the one piece of luck here, because it gives
the fetcher something to test. Anything that counts before checking gets the
wrong answer silently: `null` and `[]` both have length zero.

Store and domain names are discoverable rather than fixed — `stores` and
`domains` are objects keyed by name (`system`, then `_` for the global domain),
so the fetcher enumerates keys instead of hard-coding `system/_`.

Nothing secret is exposed: credentials come back as `id`, `typeName`,
`description`, `fullName`, and a `displayName` that is already masked
(`deployer/****** (Global deploy credential)`).

### 5. Multibranch projects expand into one child job per branch

```
platform/multibranch-app                 WorkflowMultiBranchProject
platform/multibranch-app/main            WorkflowJob
platform/multibranch-app/release%2F1.0   WorkflowJob
```

A repository with 200 branches produces 200 child jobs whose configuration is
generated, identical, and not something an operator edits. Evaluating job-scope
controls against them would produce 200 copies of the same finding and drown the
report.

**The fetcher treats a `WorkflowMultiBranchProject` as one job and does not
descend into it.** Branch children are identifiable two ways if that ever needs
revisiting: structurally, by their parent's `_class`; or by the
`BranchJobProperty` in their own `config.xml`.

Note the `%2F` — a branch name containing a slash is URL-encoded inside
`fullName`. Path construction has to cope with it.

---

## Walking the job tree

`/api/json?tree=jobs[…]` returns **only top-level items**. Folders are items too
(`com.cloudbees.hudson.plugins.folder.Folder`), and their contents appear only if
the tree expression nests explicitly:

```
tree=jobs[fullName,_class,jobs[fullName,_class,jobs[fullName,_class]]]
```

That works but silently truncates at whatever depth you wrote — a folder nested
one level deeper simply vanishes, with no error and no signal in the response.
**The fetcher walks folders recursively instead**, so depth is unbounded and a
missing job is impossible rather than invisible.

`fullName` carries the full path (`platform/api-service`); the URL for it is
`/job/platform/job/api-service` — every path segment takes its own `/job/`
prefix.

---

## Plugins

`/pluginManager/api/json?depth=1` needs `Overall/Administer` and returns 66
entries on a minimal install, each with:

```
active backupVersion bundled deleted dependencies detached downgradable
enabled hasUpdate longName pinned requiredCoreVersion shortName
supportsDynamicLoad url version
```

**There is no security-warning or deprecation field.** Jenkins renders those in
the plugin manager UI from the update centre's `warnings` array, which lives at
`updates.jenkins.io`, not on the controller. A control claiming to find
vulnerable plugins would have to fetch a third-party feed — a different tool
than "audit this controller".

What the controller *can* answer is whether plugins are current: `hasUpdate`.
With one caveat that makes the difference between a real control and a false
`PASS`:

```json
{"id":"default","url":"https://updates.jenkins.io/update-center.json",
 "hasUpdates":false,"dataTimestamp":1786650950902}
```

`hasUpdate` is computed against cached update-centre data. On a controller that
has never reached `updates.jenkins.io` — an air-gapped one, or one behind a
proxy that never worked — every plugin reports `hasUpdate: false` and the
control would report `PASS` on an instance that has no idea whether it is out of
date. **`dataTimestamp` must be checked first, and a stale or absent one means
`MANUAL`.**

---

## Agents

`/computer/api/json?depth=1` is readable by `reader` and returns, per node:

```
_class assignedLabels description displayName executors icon iconClassName
idle jnlpAgent launchSupported loadStatistics manualLaunchAllowed monitorData
numExecutors offline offlineCause offlineCauseReason oneOffExecutors
temporarilyOffline
```

The built-in node is `hudson.model.Hudson$MasterComputer`; agents are
`hudson.slaves.SlaveComputer`. Its `numExecutors` matches the root
`/api/json` `numExecutors`, so the built-in node's executor count has two
independent sources.

An agent that has never connected reports `offline: true` with
`offlineCause: null` and an empty `offlineCauseReason` — so "offline" must not be
read as "absent" or as "misconfigured".

Per-node `config.xml` requires `Administer`.

---

## Two candidate controls that recon killed

Both were in the plan before this spike. Neither survives contact with a current
LTS, and both are recorded here so nobody proposes them again.

**Legacy agent protocols.** JCasC rejects `jenkins.agentProtocols` outright:

```
io.jenkins.plugins.casc.ConfiguratorException: 'agentProtocols' is deprecated
```

Modern Jenkins speaks only `JNLP4-connect`. There is nothing left to check.

**Agent → Controller Access Control.** Mandatory since Jenkins 2.326
([JEP-235](https://www.jenkins.io/doc/book/security/controller-isolation/jep-235/)).
`AdminWhitelistRule` is a stub whose kill-switch methods only log a message
saying they no longer do anything. A control here could only ever return `PASS`,
and a control that cannot fail is noise in a report.

**CSRF protection survives, narrowly.** The UI toggle was removed in 2.222.x, but
the system property `hudson.security.csrf.GlobalCrumbIssuerConfiguration.DISABLE_CSRF_PROTECTION`
still works. Verified by booting a second controller with it set:

| | `useCrumbs` | `/crumbIssuer/api/json` |
| --- | --- | --- |
| default | `true` | `200` |
| property set | `false` | `404` |

Two independent signals for the same fact, so the fetcher can cross-check them.
This control will almost always pass — but an instance that took the escape
hatch is worth naming.

---

## Authentication

API tokens work for every endpoint above and require no CSRF crumb, which is
what makes a GET-only client possible:

```
curl -u "<user>:<api-token>" https://jenkins.example.com/api/json
```

Verified: token-authenticated `GET` to `/api/json`, `/pluginManager/api/json` and
a job's `config.xml` all return `200` with no crumb header. Username-and-password
basic auth also works against a local security realm, but tokens are what the
bench should document.

Mint one at *People → \<user\> → Security → API Token*, or over HTTP with a
`POST` to
`/me/descriptorByName/jenkins.security.ApiTokenProperty/generateNewToken` —
which needs a crumb, being a `POST`, and is not something the bench itself ever
does.
