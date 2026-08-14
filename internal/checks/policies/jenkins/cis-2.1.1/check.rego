# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_1_1

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Whether a pipeline has a single responsibility is a judgement about its purpose, which no API exposes. Review what this job does end to end, and split it if one run carries more than one duty's credentials.",
}
