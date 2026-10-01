# Does every Groovy script this job carries run inside the sandbox?
#
# Two places hold one. The pipeline definition — an inline script, or a
# multibranch factory supplying one from the controller — and the job's other
# configuration: a System Groovy build step, a Groovy Postbuild publisher, an
# Active Choices parameter, a Job DSL step, which the fetcher resolves into
# `scripts`. A job with neither is NA rather than PASS: nothing was verified
# about it.
#
# FAIL needs one script proven outside the sandbox; PASS needs every script's
# flag read.
package scmbench.rules.cis_2_1_2

import rego.v1

import data.scmbench.lib

sandboxed := object.get(lib.resource, ["definition", "sandbox"], false)

unsandboxed_scripts := [s.holder |
	some s in lib.list(["scripts"])
	s.sandbox == false
]

sandboxed_scripts := [s.holder |
	some s in lib.list(["scripts"])
	s.sandbox == true
]

result := {
	"status": "NA",
	"details": "The job is disabled and cannot run, so its script never reaches an executor, sandboxed or not. Re-enabling it brings this control back.",
} if {
	lib.job_disabled
} else := {
	"status": "MANUAL",
	"details": "The job's configuration could not be read (it requires Job/ExtendedRead), so whether its script is sandboxed is unknown.",
} if {
	not lib.available("config")
} else := {
	"status": "FAIL",
	"details": sprintf("A Groovy script in this job's %s runs outside the Groovy sandbox, with the controller's own privileges: it can read every credential and rewrite the running instance.", [lib.joined(unsandboxed_scripts, 3)]),
	"evidence": [sprintf("sandbox = false in %s", [holder]) | some holder in unsandboxed_scripts],
} if {
	count(unsandboxed_scripts) > 0
} else := {
	"status": "FAIL",
	"details": "The inline pipeline script runs outside the Groovy sandbox, with the controller's own privileges: it can read every credential and rewrite the running instance.",
	"evidence": ["definition.sandbox = false"],
} if {
	lib.definition_source == "inline"
	lib.known(["definition", "sandbox"])
	sandboxed == false
} else := {
	"status": "MANUAL",
	"details": "The job's definition is of a class this scan does not recognize, so whether it carries an inline script — and whether that script is sandboxed — is unknown.",
} if {
	lib.definition_source == "unknown"
} else := {
	"status": "MANUAL",
	"details": "The job has an inline script but its sandbox setting could not be read.",
} if {
	lib.definition_source == "inline"
	not lib.known(["definition", "sandbox"])
} else := {
	"status": "PASS",
	"details": "The inline pipeline script runs inside the Groovy sandbox.",
} if {
	lib.definition_source == "inline"
} else := {
	"status": "PASS",
	"details": sprintf("Every Groovy script this job carries runs inside the sandbox (%s).", [lib.joined(sandboxed_scripts, 3)]),
} if {
	count(sandboxed_scripts) > 0
} else := {
	"status": "NA",
	"details": "The job carries no Groovy script — no inline pipeline, and no script in its build steps, publishers or parameters — so the sandbox does not apply.",
}
