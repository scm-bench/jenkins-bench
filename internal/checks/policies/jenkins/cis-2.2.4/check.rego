# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_2_4

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Worker network policy lives in firewalls, security groups and cluster configuration, none of which the controller's API exposes. Confirm agents can reach only the controller, source hosts, artifact stores and approved mirrors.",
}
