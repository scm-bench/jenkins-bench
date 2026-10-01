#!/usr/bin/env python3
"""The verdicts a correct scan of casc.yaml's fixture reports, per token.

Derived from what the fixture is, not from what the tool printed: each row
says what the controller actually holds, so a mismatch is a finding about the
tool until proven otherwise. Writes expected/<profile>.tsv.

Four tokens, four views of one controller (up.sh mints an API token each):

  admin     Overall/Administer. Reads everything a token can.
  reader    Overall/Read + Job/Read: the least-privilege scanning account.
            config.xml needs Job/ExtendedRead, so every job-scope control is
            MANUAL, and the plugin manager needs Overall/SystemRead.
  extended  reader + Job/ExtendedRead, the README's recommendation for a scan
            that can judge jobs. Controller reads as for reader.
  sysread   reader + Overall/SystemRead, the read-only administrator: the
            plugin manager and update centre, but not config.xml, and not the
            credential stores, which answer it 200 with none in them.

The fifth account, nojob (Overall/Read only), sees an empty job list and must
make the scan exit 2; verify.sh checks that separately.
"""
import os

P, F, M, N = "PASS", "FAIL", "MANUAL", "NA"

JOB_CONTROLS = ["CIS-2.1.1", "CIS-2.1.2", "CIS-2.3.1", "CIS-2.3.4", "CIS-2.3.5"]

# CIS-2.1.1 and CIS-2.3.4 are MANUAL by design (no API answers them) for any
# job that can run, and NA for a disabled one. The other three, in order:
# CIS-2.1.2 (sandbox), CIS-2.3.1 (defined as code), CIS-2.3.5 (triggering),
# as a token that can read config.xml sees them.
JOBS = {
    # Disabled: nothing about how it builds applies.
    "disabled-job": (N, N, N),
    # Freestyle, pinned to the built-in node, with a remote trigger token.
    "legacy-build": (N, F, F),
    # A Maven job: form fields under maven2-moduleset.
    "legacy-maven": (N, F, P),
    # Pipeline from SCM with a Generic Webhook Trigger token — the audit's
    # first false PASS on CIS-2.3.5.
    "hooks/gwt-token": (N, P, F),
    # Freestyle three folders deep, on a cron timer.
    "org/team-a/deep/nightly": (N, F, P),
    # Jenkinsfile from SCM, polled.
    "platform/api-service": (N, P, P),
    # Inline script, sandbox on / off.
    "platform/inline-deploy": (P, F, P),
    "platform/inline-nosandbox": (F, F, P),
    # Multibranch with the default factory: each branch's own Jenkinsfile. The
    # triggers its builds run under live in the branch jobs, which a scan does
    # not read, so CIS-2.3.5 cannot be decided.
    "platform/multibranch-app": (N, P, M),
    # System Groovy with the sandbox off: Groovy on the controller with its own
    # privileges, in a job with no Pipeline at all.
    "scripts/system-groovy": (F, F, P),
    # SCM URLs with planted credentials; verify.sh checks they never reach the
    # snapshot. Otherwise a pipeline from SCM and a default multibranch.
    "secrets/creds-in-url": (N, P, P),
    "secrets/mb-creds-in-url": (N, P, M),
    # Multibranch whose script comes from a Config File Provider file, sandbox
    # on, and one whose script is inline in the project, sandbox off — the
    # audit's false PASS on CIS-2.3.1 and false NA on CIS-2.1.2.
    "teams/defaults-mb": (P, F, M),
    "teams/inline-mb": (F, F, M),
    # Names that need percent-encoding: an inline script, sandbox on.
    "Équipe A+B/déploiement (prod)": (P, F, P),
}

CONTROLLER = "controller"
ALWAYS_MANUAL = ["CIS-2.1.4", "CIS-2.2.1", "CIS-2.2.4", "CIS-2.2.6", "CIS-2.3.8"]


def controller(plugins_readable):
    rows = {c: M for c in ALWAYS_MANUAL}
    # Security on, and an anonymous GET of the instance API is refused.
    rows["CIS-2.1.6"] = P
    rows["CIS-2.1.5"] = P
    # Two executors on the built-in node.
    rows["CIS-2.2.3"] = F
    # audit-trail is installed and active — visible only with the plugin list.
    rows["CIS-2.1.3"] = P if plugins_readable else M
    # The fixture points the update site at an address that never answers, so
    # the controller holds no update data at all: hasUpdate is false for every
    # plugin because nothing ever said otherwise, and that is MANUAL, not PASS.
    rows["JENKINS-PLUGIN-UPDATES"] = M
    return rows


def jobs(config_readable):
    rows = {}
    for job, (sandbox, as_code, triggering) in JOBS.items():
        disabled = job == "disabled-job"
        by_design = N if disabled else M
        if config_readable:
            judged = (sandbox, as_code, triggering)
        else:
            # Without config.xml nothing about how a job builds is known —
            # except that a disabled job cannot run, which the job list says.
            judged = (N, N, N) if disabled else (M, M, M)
        rows[job] = dict(zip(JOB_CONTROLS, [by_design, judged[0], judged[1], by_design, judged[2]]))
    return rows


PROFILES = {
    "admin": (True, True),
    "reader": (False, False),
    "extended": (False, True),
    "sysread": (True, False),
}


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    os.makedirs(os.path.join(here, "expected"), exist_ok=True)
    for profile, (plugins_readable, config_readable) in PROFILES.items():
        rows = [(c, CONTROLLER, s) for c, s in controller(plugins_readable).items()]
        for job, verdicts in jobs(config_readable).items():
            rows += [(c, job, s) for c, s in verdicts.items()]
        with open(os.path.join(here, "expected", f"{profile}.tsv"), "w") as out:
            out.write("# generated by expected.py; edit that, not this\n")
            for c, r, s in sorted(rows):
                out.write(f"{c}\t{r}\t{s}\n")
        print(f"{profile}: {len(rows)} verdicts")


if __name__ == "__main__":
    main()
