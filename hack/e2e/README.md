# The end-to-end suite

The Go tests prove the fetcher agrees with a stand-in controller. This proves
it agrees with a real one: a disposable Jenkins, a fixture that puts every
automated control in a known state — including each shape the v0.1 audit found
the tool misreading — and the verdicts a correct scan of it reports, written
down from what the fixture *is*, not from what the tool printed.

```sh
./up.sh          # build hack/recon's image, boot the fixture, mint API tokens (about two minutes)
make -C ../.. build
./verify.sh      # scan with each token and check every verdict and promise
```

`verify.sh` exits 1 on any difference and prints each one with the tool's own
explanation beside it. Beside the verdicts it checks, against the real
controller:

- the closing accounting line of every scan says `0 writes · read-only`;
- no secret planted in `casc.yaml` (every string containing `e2e-planted`)
  reaches a snapshot, a report or the trace;
- reports and snapshots are written `0600`;
- a token without `Job/Read` makes the scan exit 2 rather than pass;
- `--folder` and `--job` narrow the scan — including a name that needs
  percent-encoding and a branch job whose name carries an encoded slash —
  and a target that does not exist exits 2, naming it.

`./verify.sh admin` checks one profile's verdicts and skips the rest.

## The image and the container

The image is [`hack/recon`](../recon)'s — the same Dockerfile, which carries
the plugins the fixture needs — with this directory's `casc.yaml`. `up.sh`
takes the recon instance's name and port by default (`jenkins-bench-recon`,
`:18080`): both are disposable, and two Jenkins JVMs on one machine is one
more than either needs. `NAME`, `PORT` and `IMAGE` override them, and
`SKIP_BUILD=1` reuses an image already built.

Every job is created by Job DSL from `casc.yaml`, so each `config.xml` the scan
reads is the one the plugin itself writes — not a hand-written guess at it.

## The accounts

`up.sh` mints an API token for each (`out/tokens.env`); the scan never sees a
password.

| Profile | Permissions | Sees |
| --- | --- | --- |
| `admin` | `Overall/Administer` | everything a token can |
| `reader` | `Overall/Read`, `Job/Read` | the job list and the instance flags; no `config.xml`, no plugin list, no credentials |
| `extended` | `reader` + `Job/ExtendedRead` | every job's `config.xml` too |
| `sysread` | `reader` + `Overall/SystemRead` | the plugin manager and the update site — and an empty credential store list, which must not read as "no credentials" |
| `nojob` | `Overall/Read` | an empty job list, answered with 200: the scan must exit 2 |

`Overall/SystemRead` and `Job/ExtendedRead` are opt-in permissions;
`up.sh` turns them on with the two system properties that enable them.

## The fixture

| Job | What it puts in a known state |
| --- | --- |
| `platform/api-service` | Jenkinsfile from SCM, polled — the hardened shape |
| `platform/inline-deploy` | inline script, sandbox on |
| `platform/inline-nosandbox` | inline script, sandbox off |
| `platform/multibranch-app` | multibranch over a repository with `main` and `release/1.0`; its branch triggers are in branch jobs the scan does not read |
| `legacy-build` | freestyle, pinned to the built-in node, remote trigger token |
| `legacy-maven` | a Maven job (`maven2-moduleset`), build steps in form fields |
| `disabled-job` | disabled: everything about how it builds is NA |
| `hooks/gwt-token` | **audit**: a Generic Webhook Trigger token, which starts the build with no login — v0.1 said CIS-2.3.5 PASS |
| `teams/inline-mb` | **audit**: a multibranch project whose branches all run one script stored on the controller, sandbox off (inline-pipeline) — v0.1 said CIS-2.3.1 PASS, CIS-2.1.2 NA |
| `teams/defaults-mb` | the same with the script in a Config File Provider file (pipeline-multibranch-defaults) |
| `secrets/creds-in-url` | **audit**: a pipeline whose SCM URL embeds a token, which v0.1 copied into the snapshot |
| `secrets/mb-creds-in-url` | the same for a multibranch source |
| `scripts/system-groovy` | **audit**: a freestyle System Groovy step with the sandbox off — Groovy on the controller in a job with no Pipeline, which v0.1 called NA |
| `org/team-a/deep/nightly` | three folders deep, on a timer |
| `Équipe A+B/déploiement (prod)` | names that need percent-encoding |

Instance level: two executors on the built-in node (CIS-2.2.3 FAIL),
`audit-trail` installed (CIS-2.1.3 PASS where the plugin list is readable),
anonymous access denied (CIS-2.1.6 PASS), and an update site pointed at an
address that never answers. That last one is deliberate: with no update-centre
data, every plugin reports `hasUpdate: false` because nothing ever said
otherwise, and plugin currency has to be MANUAL rather than PASS — whether or
not the machine running the suite can reach updates.jenkins.io today.

The expected verdicts and the reasoning behind each are in
[`expected.py`](expected.py), which writes `expected/<profile>.tsv`. When a
verdict and the tool disagree, read the reasoning before changing either: a
difference is a finding about the tool until proven otherwise.

## Cleaning up

```sh
docker rm -f jenkins-bench-recon
```

`out/` holds API tokens for the instance and every report and snapshot the
suite wrote; it is gitignored, and worthless once the container is gone.
