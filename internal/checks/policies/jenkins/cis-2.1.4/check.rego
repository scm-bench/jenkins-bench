# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_1_4

import rego.v1

result := {
	"status": "MANUAL",
	"details": "How this controller is deployed is not visible from its API. Confirm that a fresh, identical instance can be produced from versioned sources — JCasC, a baked image, or a provisioning tool — without copying files off the running one.",
}
