# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_2_1

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Whether agents are single-use is decided by how they are provisioned, which the node list does not reveal. Confirm each build gets a clean worker — one-shot containers or pods, or images reset between builds — rather than a long-lived machine carrying earlier builds' residue.",
}
