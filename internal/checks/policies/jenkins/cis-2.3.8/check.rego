# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_3_8

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Secret scanners for pipeline files run on the SCM platform and in developer tooling, which this controller cannot see. Confirm push protection or an equivalent scanner covers the repositories Jenkinsfiles live in.",
}
