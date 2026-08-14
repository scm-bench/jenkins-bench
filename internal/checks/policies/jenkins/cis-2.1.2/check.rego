# Does the inline script run inside the Groovy sandbox? Only inline pipelines
# have the switch; everything else is NA rather than PASS — nothing was
# verified about them.
package scmbench.rules.cis_2_1_2

import rego.v1

import data.scmbench.lib

sandboxed := object.get(lib.resource, ["definition", "sandbox"], false)

result := {
	"status": "MANUAL",
	"details": "The job's configuration could not be read (it requires Job/ExtendedRead), so whether its script is sandboxed is unknown.",
} if {
	not lib.available("config")
} else := {
	"status": "NA",
	"details": "The job has no inline pipeline script, so the sandbox setting does not apply.",
} if {
	lib.definition_source != "inline"
} else := {
	"status": "MANUAL",
	"details": "The job has an inline script but its sandbox setting could not be read.",
} if {
	not lib.known(["definition", "sandbox"])
} else := {
	"status": "PASS",
	"details": "The inline pipeline script runs inside the Groovy sandbox.",
} if {
	sandboxed == true
} else := {
	"status": "FAIL",
	"details": "The inline pipeline script runs outside the Groovy sandbox, with the controller's own privileges: it can read every credential and rewrite the running instance.",
	"evidence": ["definition.sandbox = false"],
}
