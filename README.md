<!--
  The banner lives in scm-bench/.github (brand/), which is also where the
  organization profile and the uploaded avatar draw from, so there is one copy
  rather than one per repository. The URLs are absolute for two reasons: a
  relative path cannot cross repositories, and README.md ships inside every
  release tarball, where a repository-relative image resolves to nothing.
-->
<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-dark-1760x440.png">
    <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-light-1760x440.png">
    <img src="https://raw.githubusercontent.com/scm-bench/.github/main/brand/banner-light-1760x440.png" alt="scm-bench — audit the software supply chain against the CIS benchmark" width="880">
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
`Overall/Read` plus `Job/Read`, which is what a scanning account should have —
cannot read a single job's configuration, and nothing about how a job is
defined appears anywhere else in the API. Such a scan reports `MANUAL` for
every job-scope control, says so on stderr while it runs, and the score
excludes them. That is the honest result, and `scan.maxManual` exists so CI can
refuse to accept a scan that saw too little.

## What the token can read decides what the report can say

| Token permission | What becomes answerable |
| --- | --- |
| `Overall/Read` | the security posture: authentication, CSRF, the anonymous probe, executors, agents |
| + `Job/Read` | the job list and which jobs are disabled |
| + `Job/ExtendedRead` | everything job-scope: how each job is defined, sandbox, trigger tokens |
| + `Overall/Administer` | plugins, their update state, and credential metadata |

Use an API token (*People → \<user\> → Security → API Token*), not a password.
Every request is a GET — enforced by a test, not a convention — and the
snapshot holds no secrets by construction: a job's remote trigger token is
recorded as present or absent, never as a value, so a `--snapshot-out` file is
safe to attach to a bug report.

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
# JENKINS_URL, JENKINS_USER, JENKINS_TOKEN.
jenkins-bench scan --url https://jenkins.example.com --username audit --token $TOKEN

# Expand per-job findings and full remediation steps.
jenkins-bench scan ... --details

# Keep the snapshot, and re-ask questions later without another scan.
jenkins-bench scan ... --snapshot-out jenkins.json
jenkins-bench scan --snapshot-in jenkins.json --details

# Machine formats, for CI and code scanning.
jenkins-bench scan ... --format json
jenkins-bench scan ... --format sarif

# Write a commented config with every default stated.
jenkins-bench init
```

Exit codes: `0` clean, `1` a threshold was breached, `2` the scan could not
complete. Three settings drive exit `1`, answering different questions:
`scan.failOn` (are there failures this severe?), `scan.failUnder` (is the score
acceptable?), and `scan.maxManual` (did the scan see enough to have an opinion
at all?).

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
  otherwise; that is `MANUAL`, not a pass.

## Scoring

```
score = Σ weight(passed) / Σ weight(passed + failed) × 100
```

with `HIGH = 3`, `MEDIUM = 2`, `LOW = 1`. `MANUAL` and `NA` are in neither sum,
and the arithmetic is printed so the number is checkable:

```
SCORE 58/100   12 passed  7 failed  17 manual  4 n/a
      weighted 28/48 (HIGH=3, MEDIUM=2, LOW=1; manual and n/a excluded)
```

When nothing was decidable the score is `0`, not `100` — an empty numerator
over an empty denominator must not read as a clean bill of health.

## Configuration

`jenkins-bench init` writes a commented `jenkins-bench.yaml` with every default
stated; `scan` finds it on its own. One-off overrides need no file:
`--set scan.failOn=none`. See [`examples/config.yaml`](examples/config.yaml)
for the reference, including `auditPluginNames` (which plugins satisfy the
logging control) and `thresholds.updateSiteMaxAgeDays` (how stale update-centre
data may be before plugin currency stops being answerable).

## How it works

```
Jenkins API ──► fetcher ──► snapshot.json ──► Rego policies ──► report
             (GET only)     (normalized,     (one per control)   table/json/sarif
                             no secrets)
```

Capture and evaluation are separate: a snapshot taken on the runner that holds
the token can be re-evaluated later, elsewhere, with no network and no token,
and produces byte-identical findings. Anything version-dependent or fiddly —
label expressions, definition classes, XML that says version 1.1 — is resolved
in the fetcher, in Go, so a rule asks *"can this job run on the controller?"*
and never *"does `built-in && linux` match this node?"*

## The specification it implements

This bench follows the family's generic
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
unchanged — the same four statuses, the same `metadata.json`, the same scoring,
the same three report formats — and publishes the
[Jenkins domain snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md),
the second domain in the family and the first outside source control.

A `FAIL` here means exactly what a `FAIL` from
[bitbucket-bench](https://github.com/scm-bench/bitbucket-bench) means.

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable contribution
is running this against a real controller and reporting what differed: a
fetcher tested against a stand-in server is proven self-consistent, not proven
to match the platform. `hack/recon/` holds the harness that measured everything
this tool believes about the Jenkins API, so a claim can be rechecked rather
than trusted.

## License

Apache 2.0. See [LICENSE](LICENSE).

<sub>Not affiliated with CIS or the Jenkins project.</sub>
