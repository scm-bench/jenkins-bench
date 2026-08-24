# MANUAL for any job that can run: what this control asks about is not visible
# from the controller's API. It is carried so the benchmark mapping is complete
# rather than quietly partial. A disabled job is the exception — no run to have
# an opinion about.
package scmbench.rules.cis_2_3_4

import rego.v1

import data.scmbench.lib

result := {
	"status": "NA",
	"details": "The job is disabled and cannot run, so no definition of it reaches a build. Re-enabling it brings this control back.",
} if {
	lib.job_disabled
} else := {
	"status": "MANUAL",
	"details": "Whether Jenkinsfile changes are reviewed is branch protection on the source repository, which this controller cannot see. Confirm the branch each pipeline reads its definition from requires review — an SCM bench in this family automates that half.",
}
