package scmbench.rules.cis_2_1_1_test

import rego.v1

import data.scmbench.rules.cis_2_1_1
import data.scmbench.testdata

# A control no API can answer reports MANUAL for every resource, including one
# the fetcher could read everything about: the gap is in what Jenkins exposes,
# not in what the token could reach.
test_always_manual if {
	r := cis_2_1_1.result with input as testdata.job_input({})
	r.status == "MANUAL"
}

test_manual_even_for_an_empty_resource if {
	r := cis_2_1_1.result with input as testdata.input_for({})
	r.status == "MANUAL"
}

# A disabled job has no run to have an opinion about, so the always-MANUAL
# control steps aside rather than filling the report with review requests for
# jobs nobody can trigger.
test_na_for_a_disabled_job if {
	r := cis_2_1_1.result with input as testdata.job_input({"disabled": true})
	r.status == "NA"
	contains(r.details, "Re-enabling")
}
