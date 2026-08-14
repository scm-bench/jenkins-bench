# Always MANUAL: what this control asks about is not visible from the
# controller's API. It is carried so the benchmark mapping is complete rather
# than quietly partial, and so the report points at where the answer lives.
package scmbench.rules.cis_2_3_4

import rego.v1

result := {
	"status": "MANUAL",
	"details": "Whether Jenkinsfile changes are reviewed is branch protection on the source repository, which this controller cannot see. Confirm the branch each pipeline reads its definition from requires review — an SCM bench in this family automates that half.",
}
