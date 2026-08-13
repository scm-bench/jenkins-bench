# jenkins-bench

Audit a **Jenkins controller** — its jobs, credentials, agents and plugins —
against the build-pipeline sections of the
[CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

**Status: planned.** There is no code here yet. This repository exists so the
work has a home and a name before it has commits.

## What it will be

A read-only CLI, in the shape every bench in this family takes: capture a
normalized snapshot of a controller, evaluate it with Rego policies — one
directory per control — and print what is misconfigured along with the exact
settings path to fix it.

Jenkins is the first bench in this family that is not a source control platform,
and that is the interesting part. The
[SCM snapshot schema](https://github.com/scm-bench/scm-bench/blob/main/docs/scm-snapshot.md)
is built around organizations, repositories and branch protections; a Jenkins
controller has none of those. Its world is jobs and their triggers, credentials
and what can read them, agents and what they are trusted to run, and a plugin set
that decides most of the security posture.

So this bench will publish its own domain snapshot schema in the umbrella
repository, and follow the generic
[bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
unchanged: the same four statuses, the same `metadata.json`, the same scoring, the
same three report formats. A `FAIL` here will mean exactly what a `FAIL` from any
other bench means.

Working out which parts of that contract are genuinely generic, rather than
merely shared by two source control tools, is what this repository is for.

## Before contributing

- The [bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md)
  — what a verdict, a control's metadata and a score are required to mean. Start
  here.
- [bitbucket-bench](https://github.com/scm-bench/bitbucket-bench) — the reference
  implementation of that contract. Read it for the structure, not for the domain:
  the fetcher/policy split, the directory-per-control layout and the two test
  suites all carry over.

The rule that outranks the rest: **a control that cannot be evaluated reports
`MANUAL`, never `PASS` or `FAIL`.** A scan is never credited for a question it
could not ask, and never penalised for one either. On Jenkins that rule earns its
keep immediately — a great deal depends on which plugins are installed, and an
absent plugin is missing knowledge, not a passing grade.

## License

Apache 2.0. See [LICENSE](LICENSE).

<sub>Not affiliated with CIS or the Jenkins project.</sub>
