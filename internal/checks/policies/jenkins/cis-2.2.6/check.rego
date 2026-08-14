# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_2_6

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Worker scanning happens in registries and host tooling the controller's API cannot see. Confirm the images or hosts agents run on are scanned automatically and rebuilt when findings land.",
}
