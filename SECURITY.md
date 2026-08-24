# Security Policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/scm-bench/jenkins-bench/security/advisories/new).
That keeps the report confidential until a fix is available and gives us a
private space to work with you on it.

Please do not open a public issue for a security problem.

If you cannot use GitHub advisories, email **xianpeng.shen@gmail.com** with
`jenkins-bench security` in the subject.

**What to expect**

| | |
|---|---|
| First response | within 5 working days |
| Assessment and plan | within 10 working days |
| Fix released | as soon as it is ready; we will keep you updated if it takes longer |

Credit in the advisory and release notes is offered by default. Tell us if you
would rather not be named.

## Supported versions

| Version | Supported |
|---|---|
| `0.x` (latest release) | ✅ |
| Anything older | ❌ |

Before `1.0.0`, only the most recent release receives fixes. Upgrading is the
supported path.

## What matters most in this project

jenkins-bench reads a customer's Jenkins controller with a credential they
supplied and writes a file describing exactly where that controller is weak.
Reports of the following are especially welcome:

- **A credential leaking** into a snapshot, a report, a log line, or a crash.
  Tokens must never appear in output at any verbosity.
- **Anything that makes the tool write.** Scanning is read-only and enforced by
  test; a path that issues a non-`GET` request against an audited instance is a
  serious bug.
- **A control reporting `PASS` when it did not actually verify the setting.**
  A false pass is worse than a crash: it tells someone they are secure when
  nobody checked. This is the failure mode the project is built to avoid, and
  we treat it as a security issue rather than a correctness one.
- **Snapshot or report files written with permissive modes.** A snapshot is a
  precise map of an instance's weak points and is written `0600` on purpose.
  That mode is enforced on Unix-like systems; Windows has no equivalent bit and
  the file inherits its directory's ACL, which is a known gap rather than a
  vulnerability report — though a way to make Go's `os` package honour it would
  be a welcome contribution.

## Scope

In scope: the `jenkins-bench` binary, the policy bundle, the release pipeline, and
the published container images.

Out of scope: vulnerabilities in Jenkins itself, in a plugin, or in any other
audited platform. Report those to the Jenkins security team at
https://www.jenkins.io/security/ — they run a coordinated disclosure process
and it is the right place for them. We will happily help you word it.
