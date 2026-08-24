# Contributing

jenkins-bench audits a Jenkins controller against section 2, *Build Pipelines*,
of the [CIS Software Supply Chain Security Guide](https://www.cisecurity.org/benchmark/software-supply-chain-security).

The most valuable contribution here is usually not code. A control that fires
wrongly against a real instance, or remediation text that does not match what the
UI actually says, is worth more than a refactor — most of this has only ever run
against a stand-in server.

## Getting set up

```
git clone https://github.com/scm-bench/jenkins-bench.git
cd jenkins-bench
make check      # gofmt, vet, race-enabled tests, and the policy suite
```

You need Go (the version in `go.mod`) and `opa` on PATH.

## The one rule that matters

**A control that cannot be evaluated reports `MANUAL`, never `PASS` or `FAIL`.**

If the token lacks a permission, if an add-on is not installed, if the API never
returned the field — the answer is "I could not tell", and the control leaves the
score. A confident wrong answer is the worst thing this tool can do, because it
teaches people to ignore its output. The rest of the design follows: the fetcher
records what it could not read in `available` and never substitutes a zero for
missing data, and policies check availability *before* they check the setting.

## How the pieces fit

```
internal/
  ci/                   normalized snapshot types (the fetcher/policy contract)
    jenkins/            API client, fetcher, the matching the fetcher resolves
  checks/policies/      one directory per control: check.rego, check_test.rego,
                        metadata.json
  engine/               compiles the bundle once, evaluates, scores
  report/               table, json, sarif
  config/               thresholds handed to Rego as input.config
  cli/                  flags, exit codes, the scan trace
```

Anything version-dependent or fiddly is resolved in Go rather than Rego. On this
platform that means three things in particular:

- **Where a job can run.** Answering it combines the job's `assignedNode` label
  expression, its `canRoam` flag and the labels the built-in node carries —
  three fields in two documents with Jenkins' label semantics in between. The
  fetcher hands Rego `runsOnBuiltInNode`, a boolean. A rule asks *"can this job
  run on the controller?"*, not *"does `built-in && linux` match this node?"*
- **How a job is defined.** `CpsScmFlowDefinition`, `CpsFlowDefinition`, a
  `<project>` root element and a multibranch project all answer the same
  question differently. The fetcher normalizes them to
  `definition.source: scm | inline | ui | unknown`.
- **Whether a credential store was really empty.** Reading credentials without
  permission returns `200` with an empty store list rather than `403`, so
  `available.credentials` is not set from the HTTP status. See
  [`docs/jenkins-api-notes.md`](docs/jenkins-api-notes.md).

And the rule that outranks those: **no secret goes into a snapshot.** A job's
`config.xml` returns its remote trigger token in cleartext, and a snapshot gets
written to disk and passed around. The fetcher extracts booleans, counts and
class names. `remoteTriggerToken` is a `true`, never a token.

## Adding a control

Create a directory under `internal/checks/policies/jenkins/`. No Go changes —
the bundle is embedded and discovered at load time. Three files:

**`check.rego`** returns a single `result` document.

```rego
package scmbench.rules.cis_x_y_z

import rego.v1
import data.scmbench.lib

result := {"status": "MANUAL", "details": "..."} if {
	not lib.available("<the thing this control reads>")
} else := {"status": "PASS", "details": "..."} if {
	<the condition>
} else := {
	"status": "FAIL",
	"details": "<what is wrong, and what it lets happen>",
	"evidence": ["<the value behind the verdict>"],
}
```

The `MANUAL` branch comes first on purpose: deciding what the data says is only
sound once you have established that you have the data.

One branch outranks it. A job-scope control opens with `lib.job_disabled` →
`NA`, ahead of the availability check, because whether a job is disabled comes
from the job API that `Job/Read` already reads — a job that cannot run is not
made more decidable by reading its configuration. Say in the `details` that
re-enabling the job brings the control back, so an `NA` is not mistaken for a
clean bill of health.

**Read every list through `lib.list`**, never `object.get`. A nil Go slice
marshals to JSON `null`, and `object.get` only substitutes its default for an
*absent* key — a key present with a null value comes back null, and passing that
to `concat` or `sort` makes the rule undefined, so the control reports nothing at
all.

**`check_test.rego`** is not optional. Every PASS, FAIL and MANUAL branch is
covered and CI holds the bundle at 100% — an uncovered branch is a verdict nobody
has ever seen the rule produce.

**`metadata.json`** carries the ID, severity, scope and remediation, all in
English: the tool has one output language, so there is nothing to translate.
Remediation is written twice, at two lengths:

- `remediation` — the full paragraph: the settings path, the higher-scope variant
  covering many resources at once, the exemptions worth granting, and the config
  key that changes what the control counts.
- `fixSummary` — the first move in one imperative line, under 100 characters.
  This is what each finding's table cell prints, so it must stand alone.

Both must name a concrete place — a settings path, a file to add, or an explicit
statement that nothing applies. Vague remediation is worse than none: it wastes
the reader's time before they discover it does not help.

The full format is specified in
[the bench contract](https://github.com/scm-bench/scm-bench/blob/main/docs/bench-contract.md),
with a JSON Schema at
[`schemas/metadata.schema.json`](https://github.com/scm-bench/scm-bench/blob/main/schemas/metadata.schema.json).

Then add the control to the coverage table in the README.

## Testing

Two suites, because the project is written in two languages and `go test -cover`
cannot see Rego. Go covers the fetcher, engine, reporters and CLI; Rego covers
the controls, held at 100%.

The Go suite runs every control against hardened, misconfigured, unreadable and
zero-valued fixtures, asserting each produces a verdict in every case. Add your
control's expected status to each. **The zero-valued case is not optional** — it
catches the bug where a rule silently produces no verdict, which looks exactly
like a passing test run.

The fetcher is tested against a stand-in server. That proves the code is
self-consistent; it does **not** prove the platform behaves like the stand-in. If
you have a real instance, running against it and reporting what differed is the
single most valuable thing you can do here.

## Releasing

Push a tag, or run the **Release** workflow from the Actions tab and give it the
tag to create. The workflow does the rest.

```bash
git tag -a v0.1.0 -m "jenkins-bench v0.1.0" && git push origin v0.1.0
```

Three things that have each gone wrong once in this family:

- **All three components, and the `v`** — `v0.1.0`, never `v0.1`. Go accepts
  `v0.1` as a semver string but not a canonical one, so the module system
  ignores the tag and `go install ...@latest` will not find it. goreleaser
  builds it happily and produces artifacts nobody can install.
- **Publish the draft goreleaser made.** Never start a new release from the
  Releases page: it gets the notes and none of the files.
- **Use `-rc.N` while something is unverified.** Go's `@latest` resolves to the
  newest *release* version, so a prerelease reaches only those who ask for it by
  name, and you can iterate without spending `v0.1.0`.

Signing needs nothing from you — cosign works keylessly from the workflow's OIDC
token. Before publishing, check `checksums.txt.bundle` and the SBOMs are
attached: a release whose signing step was skipped looks complete otherwise.

## Pull requests

One change per pull request. Label it so it lands in the right release-notes
section. Commit messages follow Conventional Commits, with `!` for anything that
breaks the config file, the snapshot shape or a verdict.

## Reporting a problem

- **A control is wrong** — tell us the Jenkins version, which plugins are
  installed, what the setting actually is, and what the tool said. A
  `--snapshot-out` file is ideal, and safe to attach: it holds no secrets by
  construction.
- **A security issue** — do not open an issue. See [SECURITY.md](SECURITY.md).
  Vulnerabilities in Jenkins itself or in a plugin go to the Jenkins security
  team instead.

## Licence

Apache 2.0. By contributing you agree your work is licensed under it.
