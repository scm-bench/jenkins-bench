# jenkins-bench

Audit a **Jenkins controller** — its jobs, credentials, agents and plugins —
against the build-pipeline sections of the
[CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

**Status: early.** The policy bundle and the CLI that lists it exist; there is
no `scan` command yet, so nothing here talks to a controller. The
[coverage table](#controls) is one row long on purpose.

## What it is

A read-only CLI, in the shape every bench in this family takes: capture a
normalized snapshot of a controller, evaluate it with Rego policies — one
directory per control — and print what is misconfigured along with the exact
settings path to fix it.

```
jenkins-bench list-checks
```

## Controls

| ID | Severity | Scope | Title |
| --- | --- | --- | --- |
| CIS-2.1.6 | HIGH | controller | Ensure users must authenticate to access the build environment |

The target is section 2, *Build Pipelines*, of the benchmark — 28 controls
across build environments, build workers, pipeline instructions and pipeline
integrity. Not all of them are answerable by a controller's API, and the ones
that are not will ship as `MANUAL` rather than be left out, so the mapping is
complete rather than quietly partial.

Jenkins is the first bench in this family that is not a source control platform,
and that is the interesting part. The
[SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md)
is built around organizations, repositories and branch protections; a Jenkins
controller has none of those. Its world is jobs and their triggers, credentials
and what can read them, agents and what they are trusted to run, and a plugin set
that decides most of the security posture.

So this bench publishes its own
[domain snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md)
in the umbrella repository, and follows the generic
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
unchanged: the same four statuses, the same `metadata.json`, the same scoring, the
same three report formats. A `FAIL` here means exactly what a `FAIL` from any
other bench means.

Working out which parts of that contract are genuinely generic, rather than
merely shared by two source control tools, is what this repository is for. The
first answer arrived on day one: the family's control metadata schema enumerated
`repository` and `organization` as the only legal scopes, so no bench outside
the SCM domain could have passed validation. That enum is gone.

## Before contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Then:

- The [bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
  — what a verdict, a control's metadata and a score are required to mean.
- [`docs/jenkins-api-notes.md`](docs/jenkins-api-notes.md) — what a controller
  will and will not tell you, measured rather than recalled. Read it before
  proposing a control, because several obvious ones are not answerable.
- [bitbucket-bench](https://github.com/scm-bench/bitbucket-bench) — the reference
  implementation of that contract. Read it for the structure, not for the domain:
  the fetcher/policy split, the directory-per-control layout and the two test
  suites all carry over.

The rule that outranks the rest: **a control that cannot be evaluated reports
`MANUAL`, never `PASS` or `FAIL`.** A scan is never credited for a question it
could not ask, and never penalised for one either. On Jenkins that rule earns its
keep immediately, and more sharply than expected. A least-privilege token —
`Overall/Read` plus `Job/Read`, which is what a scanning account should have —
cannot read a single job's configuration, and nothing about how a job is defined
appears anywhere else. Such a scan reports `MANUAL` for every job-scope control.
That is the correct answer.

## License

Apache 2.0. See [LICENSE](LICENSE).

<sub>Not affiliated with CIS or the Jenkins project.</sub>
