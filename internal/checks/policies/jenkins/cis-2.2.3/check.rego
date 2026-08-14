# Does the controller run builds itself?
#
# The executor count has two failure modes that read as zero: a hardened
# controller, and one whose count could not be read. numExecutorsKnown is what
# tells them apart, and it is checked first — a fetcher that got nothing must
# not produce the same PASS as a controller that got it right.
package scmbench.rules.cis_2_2_3

import rego.v1

import data.scmbench.lib

executors := object.get(lib.resource, ["builtInNode", "numExecutors"], 0)

result := {
	"status": "MANUAL",
	"details": "The built-in node's executor count could not be read, so whether builds run on the controller is unknown.",
} if {
	not lib.known(["builtInNode", "numExecutors"])
} else := {
	"status": "PASS",
	"details": "The built-in node has no executors, so builds cannot run on the controller.",
} if {
	executors == 0
} else := {
	"status": "FAIL",
	"details": sprintf("The built-in node has %d executor(s), so builds run on the controller itself — alongside every credential and the controller's own configuration.", [executors]),
	"evidence": [sprintf("builtInNode.numExecutors = %d", [executors])],
}
