<!--
  The banner lives in scm-bench/.github (brand/), which is also where the
  organization profile and the uploaded avatar draw from, so there is one copy
  rather than one per repository. The URLs are absolute for two reasons: a
  relative path cannot cross repositories, and README.md ships inside every
  release tarball, where a repository-relative image resolves to nothing.
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-jenkins-bench-light-1760x440.png" alt="jenkins-bench — audit a Jenkins controller against the CIS supply chain benchmark" width="880">
  </picture>
</p>

<p align="center">
  <a href="https://github.com/scm-bench/jenkins-bench/actions/workflows/ci.yml"><img src="https://github.com/scm-bench/jenkins-bench/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/scm-bench/jenkins-bench/releases"><img src="https://img.shields.io/github/v/release/scm-bench/jenkins-bench?include_prereleases&sort=semver" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="Apache 2.0"></a>
</p>

Audit a **Jenkins controller** against the **Build Pipelines** section of the
[CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

jenkins-bench captures a **read-only** snapshot of your controller — its jobs,
credentials, agents and plugins — evaluates it against policies written in Rego,
and tells you what is misconfigured, along with the exact settings path to fix
it.

```
jenkins-bench scan --url https://jenkins.example.com --username audit --token <api-token>
```

[简体中文](README.zh-CN.md)

## The one design decision worth knowing

**A control that cannot be evaluated reports `MANUAL`, never `PASS` or `FAIL`.**
A scan is never credited for a question it could not ask, and never penalised
for one either.

On Jenkins that rule earns its keep immediately. A least-privilege token —
`Overall/Read` plus `Job/Read` — cannot read a single job's configuration, and
nothing about how a job is defined appears anywhere else in the API. Such a
scan reports `MANUAL` for every job-scope control, says so on stderr while it
runs, and the score excludes them. That is the honest result, and
`scan.maxManual` exists so CI can refuse to accept a scan that saw too little.

The same rule decides what a scan that *could not finish* does: it exits 2.
A token without `Job/Read` is not refused the job list — Jenkins hands it an
empty one — and a folder whose listing failed takes its jobs out of the scan
without leaving one behind to report on. Neither is a clean result, and
neither exits 0.

## What the token can read decides what the report can say

Measured against Jenkins 2.580.1, with one account per row in
[`hack/e2e`](hack/e2e):

| Token permission | What becomes answerable |
| --- | --- |
| `Overall/Read` | the security posture: authentication, CSRF, the anonymous probe, the built-in node's executors, mode and labels, agents |
| + `Job/Read` | the job list, and which jobs are disabled. Without it the controller answers with an *empty* list, and the scan exits 2 |
| + `Job/ExtendedRead` | everything job-scope: how each job is defined, its sandbox and Groovy scripts, its triggers |
| + `Overall/SystemRead` | plugins and their update state — the read-only administrator, enough for both plugin controls |
| + `Credentials/View` (implied by `Overall/Administer`) | credential metadata from the controller's own stores |

The account to scan with is `Overall/Read`, `Job/Read`, `Job/ExtendedRead` and
`Overall/SystemRead`: it answers every automated control without being able to
change anything. `Job/ExtendedRead` and `Overall/SystemRead` are opt-in
permissions — start the controller with
`-Dhudson.security.ExtendedReadPermission=true` and
`-Djenkins.security.SystemReadPermission=true` to grant them. Under
folder-scoped authorization a token sees only the folders it may read; a
folder it cannot see is invisible to it, not an error.

Use an API token (*People → \<user\> → Security → API Token*), not a password.
Every request is a GET — enforced by a test, refused by the client's transport
otherwise, and accounted for at the end of every scan:

```
[INFO] ✓ 31 requests · 31 GET · 0 writes · read-only
```

The snapshot holds no secrets by construction: a trigger token is recorded as
present or absent, never as a value, credentials embedded in SCM URLs are
stripped before anything is kept, and a `--snapshot-out` file is safe to attach
to a bug report.

## Install

```sh
go install github.com/scm-bench/jenkins-bench/cmd/jenkins-bench@latest
```

Or download an archive from
[Releases](https://github.com/scm-bench/jenkins-bench/releases), or use the
container image:

```sh
docker run --rm ghcr.io/scm-bench/jenkins-bench:latest \
  scan --url https://jenkins.example.com --username audit --token $TOKEN
```

## Quick start

```sh
# Scan a controller. Credentials may also come from the environment:
# JENKINS_URL, JENKINS_USER, JENKINS_TOKEN; a flag beats the environment.
jenkins-bench scan --url https://jenkins.example.com --username audit --token $TOKEN

# Expand per-job findings and full remediation steps.
jenkins-bench scan ... --details

# Narrow the scan: every job under a folder, or one job, by full name.
# Both repeat and add up; a name the controller does not know exits 2.
jenkins-bench scan ... --folder platform/backend --job release/deploy-prod

# Watch every request as it goes out.
jenkins-bench scan ... -v

# Keep the snapshot, and re-ask questions later without another scan.
jenkins-bench scan ... --snapshot-out jenkins.json
jenkins-bench scan --snapshot-in jenkins.json --details

# Machine formats, for CI, code scanning and test views — to a file,
# written 0600 and atomically.
jenkins-bench scan ... -o json  --output-file report.json
jenkins-bench scan ... -o sarif --output-file jenkins.sarif
jenkins-bench scan ... -o junit --output-file jenkins-bench.xml

# Write a commented config with every default stated.
jenkins-bench init
```

`--format` is the old name of `-o`; it still works, and says it is deprecated.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | the scan completed and nothing breached a threshold |
| `1` | a threshold was breached — `scan.failOn` (are there failures this severe?), `scan.failUnder` (is the score acceptable?), or `scan.maxManual` (did the scan see enough to have an opinion at all?) |
| `2` | the scan could not complete: the controller could not be read, the credentials were rejected, a `--folder` or `--job` target does not exist, a policy failed to evaluate, **no job was evaluated**, or **the job list is incomplete** |

A scan that evaluated no job — a token without `Job/Read`, or a controller with
none — exits 2: nothing job-scope was audited, and a green CI step must not say
otherwise. A scan in which some folder could not be listed still writes its
report, names every folder it missed in the scan warnings, marks the SARIF run
as not executed successfully, and exits 2 unless `scan.allowIncomplete: true`
accepts a partial scan in writing.

An exception (below) stops an accepted failure from tripping `scan.failOn`,
and an accepted MANUAL from counting against `scan.maxManual`; it changes
neither the finding nor the score.

Every scan names the config file it read — `using config jenkins-bench.yaml` on
stderr — so a file dropped into a working directory by the pull request being
gated cannot change the gate unseen.

## In CI

The thresholds live in a `jenkins-bench.yaml` committed next to the pipeline,
so the pipeline and a laptop read the same file and disagree about nothing.

**GitHub Actions** — upload the SARIF to code scanning. It is what code
scanning both accepts and displays: every result carries a physical location
(`jenkins/<host>/<job full name>`, which need not exist in the repository),
MANUAL results never display as a severity, and runs are categorised per
controller. The scan exits `1` when it finds something, which is the point,
but that would end the job before the upload, so the failure is deferred to
the last step. The upload needs `security-events: write` in the job's
`permissions` — and, in a private repository, `actions: read` and
`contents: read` too. Give each controller its own `category`, so two
controllers uploading to one repository do not close each other's alerts:

```yaml
- name: Audit Jenkins
  id: audit
  continue-on-error: true
  run: jenkins-bench scan -o sarif --output-file jenkins.sarif
  env:
    JENKINS_URL: https://jenkins.example.com
    JENKINS_USER: audit
    JENKINS_TOKEN: ${{ secrets.JENKINS_TOKEN }}

- name: Upload to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: jenkins.sarif
    category: jenkins-bench/jenkins.example.com

- name: Fail the job if the audit did
  if: steps.audit.outcome == 'failure'
  run: exit 1
```

Code scanning keeps at most 5,000 results per run, so the SARIF does the same —
most severe first — and says how many it withheld; `-o json` carries every
finding.

**Jenkins** — the JUnit publisher draws the result in the build's own test
view, one suite per control and one case per job:

```groovy
stage('Audit Jenkins') {
  steps {
    withCredentials([string(credentialsId: 'jenkins-bench-token', variable: 'JENKINS_TOKEN')]) {
      sh '''
        jenkins-bench scan --url https://jenkins.example.com --username audit \
          -o junit --output-file jenkins-bench.xml
      '''
    }
  }
  post {
    always {
      // Draws the report; the scan's exit code has already decided the build.
      junit testResults: 'jenkins-bench.xml', allowEmptyResults: true, skipMarkingBuildUnstable: true
    }
  }
}
```

**Azure Pipelines** — the same file, through `PublishTestResults`:

```yaml
- script: |
    jenkins-bench scan --url "$(JENKINS_URL)" --username audit -o junit --output-file jenkins-bench.xml
  displayName: Audit Jenkins
  env:
    JENKINS_TOKEN: $(JENKINS_TOKEN)
- task: PublishTestResults@2
  condition: succeededOrFailed()
  inputs:
    testResultsFormat: JUnit
    testResultsFiles: jenkins-bench.xml
    failTaskOnFailedTests: false   # the scan's exit code is the gate
```

In every recipe the scan's exit code decides the build and the report only
draws it. A test report cannot carry the gate: JUnit has no notion of
severity, so every unaccepted `FAIL` is a failing test — `LOW` included — and
a publisher left to fail the build on failing tests gates on something
stricter than `scan.failOn`. And a scan whose exit code is thrown away — a
`returnStatus: true`, a `|| true` — lets a breached `scan.maxManual` or
`scan.failUnder` through, and an exit 2 with it: as a yellow build, since
Jenkins' `junit` step marks failing tests `UNSTABLE` rather than failed, or as
a green one when nothing happened to fail as a test. The reports say so
themselves where they can — a scan that could not vouch for its coverage marks
the SARIF run unsuccessful and adds failing `scan` cases to the JUnit file —
but only the exit code covers every case.

## Large controllers

- **Narrow the scan.** `--folder` and `--job` read only what they name; a team
  that owns one folder need not wait for — or hold a token that can read — the
  rest.
- **Each job costs one request**, its `config.xml`; every other endpoint is
  asked only for the fields the scan reads. `scan.concurrency` (default 8)
  bounds how many are in flight, `scan.timeout` (default 30s) bounds one, and
  `scan.maxDuration` bounds the whole scan.
- **Evaluation is not the bottleneck**: a 10,000-job snapshot of a controller
  with 1,000 agents evaluates in under three seconds on a laptop.
- **`--details` on thousands of jobs is thousands of sections**;
  `--max-resources` caps them and says how many were left out.
- Keep the snapshot (`--snapshot-out`) and re-ask questions offline with
  `--snapshot-in` rather than scanning again.

## Coverage

Section 2 of the guide holds 28 controls across build environments, build
workers, pipeline instructions and pipeline integrity. Not all of them are
answerable from a controller's API — and several of the obvious candidates are
not answerable by *anything*, because the API does not expose what they ask
about. The 15 below are what this release ships: every control that could be
automated against a controller's API, plus the ones whose only honest form is
a manual control whose text says where the answer lives. The remaining
section-2 controls (2.2.2, 2.2.5, 2.2.7, 2.3.2, 2.3.3, 2.3.6, 2.3.7 and the
2.4 pipeline-integrity block) are being dispositioned the same way — measured
against a live controller first — and land as they are settled rather than
being guessed at.

| ID | Severity | Scope | Automated | Title |
| --- | --- | --- | --- | --- |
| CIS-2.1.1 | MEDIUM | job | manual | Ensure each pipeline has a single responsibility |
| CIS-2.1.2 | HIGH | job | yes | Ensure all aspects of the pipeline infrastructure and configuration are immutable |
| CIS-2.1.3 | MEDIUM | controller | yes | Ensure the build environment is logged |
| CIS-2.1.4 | MEDIUM | controller | manual | Ensure the creation of the build environment is automated |
| CIS-2.1.5 | MEDIUM | controller | yes | Ensure access to build environments is limited |
| CIS-2.1.6 | HIGH | controller | yes | Ensure users must authenticate to access the build environment |
| CIS-2.2.1 | MEDIUM | controller | manual | Ensure build workers are single-used |
| CIS-2.2.3 | HIGH | controller | yes | Ensure the duties of each build worker are segregated |
| CIS-2.2.4 | MEDIUM | controller | manual | Ensure build workers have minimal network connectivity |
| CIS-2.2.6 | MEDIUM | controller | manual | Ensure build workers are automatically scanned for vulnerabilities |
| CIS-2.3.1 | HIGH | job | yes | Ensure all build steps are defined as code |
| CIS-2.3.4 | MEDIUM | job | manual | Ensure changes to pipeline files are tracked and reviewed |
| CIS-2.3.5 | MEDIUM | job | yes | Ensure access to build process triggering is minimized |
| CIS-2.3.8 | MEDIUM | controller | manual | Ensure scanners are in place to identify and prevent sensitive data in pipeline files |
| JENKINS-PLUGIN-UPDATES | MEDIUM | controller | yes | Ensure installed plugins are up to date |

`JENKINS-PLUGIN-UPDATES` carries no CIS number on purpose: the guide has no
entry for keeping the CI system's own components current, and borrowing a
neighbouring number would make the mapping dishonest. It is a supplement, and
it sorts after the mapped controls.

Two controls that recon killed before they could ship as noise: legacy agent
protocols and Agent → Controller Access Control are both mandatory on a current
LTS, so a control about either could only ever report `PASS`. The evidence is
in [`docs/jenkins-api-notes.md`](docs/jenkins-api-notes.md).

Three controls read more than their names suggest, because the obvious
reading produced false passes:

- **CIS-2.3.5** fails on any trigger that starts a build without Jenkins'
  per-user authorization — the core remote trigger token *and* a Generic
  Webhook Trigger, whose endpoint needs no login — and reports `MANUAL` for a
  trigger it has not been taught, or a multibranch project, whose triggers
  live in its branches' Jenkinsfiles.
- **CIS-2.3.1** judges a multibranch project by its branch factory: one whose
  script comes from the controller (inline-pipeline, or a Config File Provider
  file) fails like an inline pipeline.
- **CIS-2.1.2** fails on Groovy outside the sandbox wherever a job carries it —
  a System Groovy step, a Groovy Postbuild publisher, an Active Choices
  parameter, a Job DSL step — not only in an inline pipeline.

### What "automated" is built on

Everything a control reads was measured against a live controller before the
schema was written — see [`docs/jenkins-api-notes.md`](docs/jenkins-api-notes.md)
for what a Jenkins API will and will not tell you, including the findings that
shaped this tool:

- **The authorization strategy is not readable.** No endpoint exposes it, so
  *"does this controller require login?"* is answered by a probe: the same GET,
  issued with no credentials, and both outcomes verified against real
  controllers.
- **An unreadable credential store returns `200` with an empty list**, not
  `403`. Availability is earned, not inferred from a status code.
- **`hasUpdate` is only as good as the update-centre cache.** An air-gapped
  controller reports every plugin current because nothing ever told it
  otherwise; that is `MANUAL`, not a pass. It is also judged against the
  update-centre tier for the controller's own core version: on an old core,
  "current" means the newest plugin that core can run.
- **A sign-in page is not anonymous access.** The probe follows no redirect
  and counts only the Jenkins API itself as an answer; behind an
  authenticating proxy it reports `MANUAL` and says where the request was sent.

## Scoring

```
score = floor(Σ weight(passed) / Σ weight(passed + failed) × 100)
```

with `HIGH = 3`, `MEDIUM = 2`, `LOW = 1`. `MANUAL` and `NA` are in neither sum.
Floored, never rounded, so a failing finding can never print `100`. The
arithmetic is printed so the number is checkable:

```
SCORE 58/100   12 passed  7 failed  17 manual  4 n/a
      weighted 28/48 (HIGH=3, MEDIUM=2, LOW=1; manual and n/a excluded)
```

When nothing was decidable the score is `0`, not `100` — an empty numerator
over an empty denominator must not read as a clean bill of health.

## Configuration

`jenkins-bench init` writes a commented `jenkins-bench.yaml` with every default
stated; `scan` finds it on its own (and names it on stderr). One-off overrides
need no file: `--set scan.failOn=none`. See
[`examples/config.yaml`](examples/config.yaml) for the reference, including
`auditPluginNames` (which plugins satisfy the logging control) and
`thresholds.updateSiteMaxAgeDays` (how stale update-centre data may be before
plugin currency stops being answerable).

### Transport

- **An internal CA**: `scan.caFile: /etc/ssl/certs/corp-root-ca.pem` names a
  PEM bundle trusted *in addition to* the system roots. It is checked at
  startup — a missing file, or one with no certificate in it, exits 2 — and is
  what a controller behind an internal CA needs instead of `scan.insecure`,
  which stops checking who answered at all. The two cannot be set together.
- **A proxy**: `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` are honoured, as by
  every Go tool.
- **Cleartext**: an `http://` URL to anything but this machine is refused
  unless `scan.allowPlaintext: true` says otherwise in writing.
- **Redirects** are followed only within the controller's origin (scheme, host
  and port), at most five times, and never carry the token anywhere else; a
  redirect from https to http is an error naming both URLs.

### Exceptions

A finding your organisation has decided to live with — for a stated reason,
until a stated date — is accepted in the config:

```yaml
exceptions:
  - control: CIS-2.3.5              # exact control ID
    resources: [platform/legacy-*]   # globs over job full names; * stops at "/";
                                     # "controller" for a controller-scope control
    reason: Vendor job, replaced in Q1
    owner: platform-team@example.com # optional
    expires: 2027-03-31              # applies through that day (UTC)
```

An accepted finding is still reported, under "Accepted by exceptions", still
`FAIL`, and still counted in the score: the score describes the controller, and
accepting a finding does not change the controller. What it stops doing is
failing the run on `scan.failOn` — or, for a `MANUAL` finding, counting against
`scan.maxManual`. JSON carries the waiver on the finding, SARIF a suppression
that code scanning shows as dismissed with the justification, JUnit a skipped
case. An exception that has lapsed, or that accepts nothing any more, is
reported on every run so the list cannot rot quietly.

## How it works

```
Jenkins API ──► fetcher ──► snapshot.json ──► Rego policies ──► report
             (GET only)     (normalized,     (one per control)   table/json/sarif/junit
                             no secrets)
```

Capture and evaluation are separate: a snapshot taken on the runner that holds
the token can be re-evaluated later, elsewhere, with no network and no token,
and produces byte-identical findings. A snapshot carries its schema version;
this release reads version 2 and refuses older captures, whose shape lacks what
the current controls decide on — capture again after upgrading.

Anything version-dependent or fiddly — label expressions, definition classes
and branch factories, which triggers skip authorization, XML that says version
1.1 — is resolved in the fetcher, in Go, so a rule asks *"can this job run on
the controller?"* and never *"does `built-in && linux` match this node?"*

## The specification it implements

This bench follows the family's generic
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
— the same four statuses, the same `metadata.json`, the same scoring, the same
report formats plus JUnit — and publishes the
[Jenkins domain snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md),
the second domain in the family and the first outside source control. This
release's snapshot is version 2, ahead of the published schema, which still
describes version 1.

A `FAIL` here means exactly what a `FAIL` from
[bitbucket-bench](https://github.com/scm-bench/bitbucket-bench) means.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contribution
is running this against a real controller and reporting what differed: a
fetcher tested against a stand-in server is proven self-consistent, not proven
to match the platform. `hack/recon/` holds the harness that measured everything
this tool believes about the Jenkins API, so a claim can be rechecked rather
than trusted, and [`hack/e2e/`](hack/e2e) boots a controller with every
control in a known state and checks each verdict, for each kind of token,
against what the fixture actually is.

## License

Apache 2.0. See [LICENSE](LICENSE).

<sub>Not affiliated with CIS or the Jenkins project.</sub>
