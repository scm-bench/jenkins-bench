<!--
Label this pull request so it lands in the right release-notes section:
bug · enhancement · policy · documentation · test · ci · dependencies ·
breaking-change · deprecated
An unlabelled pull request still appears, under "Other changes".
-->

## What this changes

<!-- One or two sentences. The diff shows what; explain why it is right. -->

## Why

<!-- What was wrong, or what was missing. -->

## Verification

<!--
What you actually ran, and what it showed. Be specific: "make check green" is
useful, "tested" is not.
-->

- [ ] `make check` passes (gofmt, vet, race-enabled tests)

<!-- If this touches the policy bundle: -->
- [ ] `opa check --strict internal/checks/policies` passes
- [ ] Expected status added to the hardened, misconfigured, unreadable **and**
      zero-valued fixtures
- [ ] Remediation text names a concrete settings path, file, or explicit "no
      action applies"

## What you could not verify

<!--
Say so plainly. "Not tested against a real instance" is a completely acceptable
answer and far more useful than silence — most of this project has only ever run
against a stand-in.
-->
