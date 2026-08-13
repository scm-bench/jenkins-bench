# The recon instance

A disposable Jenkins controller with a deliberately mixed security posture, used
to answer *what does the API actually return, and at what permission level?*
The answers are written up in [`docs/jenkins-api-notes.md`](../../docs/jenkins-api-notes.md);
this directory is how to reproduce them.

Nothing here ships in the binary. It exists so that a claim in the notes, or a
fixture in a test, can be checked against a real controller rather than trusted.

```sh
docker build -t jenkins-bench-recon:lts .
./up.sh          # boot, seed a git repo, create the jobs, print the job tree
./probe.sh       # hit every endpoint as admin / reader / anonymous
```

`probe.sh` writes one file per (endpoint, credential) pair into `out/` and prints
a status-code matrix. `out/` is gitignored: it holds raw controller
configuration, and a job's `config.xml` contains its remote trigger token in
cleartext — the same reason the fetcher never puts raw `config.xml` in a
snapshot.

## What it sets up

| | |
| --- | --- |
| `admin` / `adminpw` | `Overall/Administer` |
| `reader` / `readerpw` | `Overall/Read` + `Job/Read`, and **not** `Job/ExtendedRead` |
| anonymous | nothing |

The `reader` account is the point of the whole exercise. It is what a
least-privilege scanning token looks like, and the gap between what it can and
cannot read is what the bench has to report as `MANUAL`.

Jobs, chosen so one scan produces every verdict:

| Job | What it demonstrates |
| --- | --- |
| `platform/api-service` | pipeline as code, `Jenkinsfile` from SCM — the hardened shape |
| `platform/inline-deploy` | script stored in Jenkins, sandbox on |
| `platform/inline-nosandbox` | script stored in Jenkins, sandbox off |
| `platform/multibranch-app` | expands into one child job per branch |
| `legacy-build` | freestyle, pinned to the built-in node, has a remote trigger token |
| `disabled-job` | disabled, for the `NA` path |

The controller itself is misconfigured on purpose: two executors on the built-in
node, so builds run on the controller.

## The second posture

`casc-anon.yaml` grants anonymous `Overall/Read`. It exists to prove the
anonymous-access probe in both directions — with it, an unauthenticated
`GET /api/json` returns `200`; with the default `casc.yaml`, `403`. A probe
verified in only one direction is an assumption.

```sh
./up.sh casc-anon.yaml
```

## Cleaning up

```sh
docker rm -f jenkins-bench-recon
```
