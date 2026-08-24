# MANUAL for any job that can run: what this control asks about is not visible
# from the controller's API. It is carried so the benchmark mapping is complete
# rather than quietly partial. A disabled job is the exception — no run to have
# an opinion about.
package scmbench.rules.cis_2_1_1

import rego.v1

import data.scmbench.lib

result := {
	"status": "NA",
	"details": "The job is disabled and cannot run, so no build of it carries any duty's credentials. Re-enabling it brings this control back.",
} if {
	lib.job_disabled
} else := {
	"status": "MANUAL",
	"details": "Whether a pipeline has a single responsibility is a judgement about its purpose, which no API exposes. Review what this job does end to end, and split it if one run carries more than one duty's credentials.",
}
