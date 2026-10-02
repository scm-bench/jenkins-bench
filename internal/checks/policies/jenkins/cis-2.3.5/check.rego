# Can this job be started without Jenkins' per-user authorization?
#
# The fetcher resolves trigger classes into two lists — mechanisms known to skip
# Job/Build, and classes it has not been taught — and says whether the
# configuration it read is where the job's triggers live at all. The snapshot
# names mechanisms only, never a token: config.xml returns tokens in cleartext
# and a snapshot is written to disk.
#
# FAIL needs one proven mechanism; PASS needs every trigger accounted for. That
# is why the unknowns sit between them.
package scmbench.rules.cis_2_3_5

import rego.v1

import data.scmbench.lib

unauthenticated := lib.list(["unauthenticatedTriggers"])

unrecognized := lib.list(["unrecognizedTriggers"])

# describe names a mechanism the way the job's configuration page does.
describe(name) := "a remote trigger token (\"Trigger builds remotely\")" if {
	name == "authToken"
} else := "a Generic Webhook Trigger" if {
	name == "GenericTrigger"
} else := name

described := [describe(name) | some name in unauthenticated]

result := {
	"status": "NA",
	"details": "The job is disabled and cannot run, so nothing can start a build of it. Re-enabling it brings this control back.",
} if {
	lib.job_disabled
} else := {
	"status": "MANUAL",
	"details": "The job's configuration could not be read (it requires Job/ExtendedRead), so how its builds can be started is unknown.",
} if {
	not lib.available("config")
} else := {
	"status": "FAIL",
	"details": sprintf("A build can be started without Jenkins' per-user Job/Build permission, through %s: whoever holds the token — or, for a Generic Webhook Trigger without one, anyone who can read the job — starts it, and the build is attributed to no one.", [concat(" and ", described)]),
	"evidence": [sprintf("unauthenticated trigger: %s", [name]) | some name in unauthenticated],
} if {
	count(unauthenticated) > 0
} else := {
	"status": "MANUAL",
	"details": "This multibranch project's builds run under triggers declared in each branch's Jenkinsfile, and those land in the generated branch jobs, which this scan does not read. Check the Jenkinsfiles for a triggers { } block or properties([pipelineTriggers(...)]) that uses a token.",
} if {
	not lib.known(["triggers"])
	object.get(lib.resource, "kind", "") == "multibranch"
} else := {
	"status": "MANUAL",
	"details": "This job's type keeps its build triggers somewhere this scan does not read, so how its builds can be started is unknown.",
} if {
	not lib.known(["triggers"])
} else := {
	"status": "MANUAL",
	"details": sprintf("The job has a trigger this tool does not recognise (%s), so whether it can start a build without Jenkins' authorization is unknown.", [lib.joined(unrecognized, 3)]),
	"evidence": [sprintf("unrecognized trigger: %s", [name]) | some name in unrecognized],
} if {
	count(unrecognized) > 0
} else := {
	"status": "PASS",
	"details": "Nothing configured on this job starts a build without going through Jenkins' own scheduling or authorization.",
}
