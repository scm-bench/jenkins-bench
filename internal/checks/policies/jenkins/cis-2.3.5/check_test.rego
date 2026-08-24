package scmbench.rules.cis_2_3_5_test

import rego.v1

import data.scmbench.rules.cis_2_3_5
import data.scmbench.testdata

test_passes_with_no_token if {
	r := cis_2_3_5.result with input as testdata.job_input({})
	r.status == "PASS"
}

test_fails_when_a_token_is_configured if {
	r := cis_2_3_5.result with input as testdata.job_input({"remoteTriggerToken": true})
	r.status == "FAIL"
	contains(r.details, "unauthenticated")
}

test_manual_when_the_configuration_was_unreadable if {
	r := cis_2_3_5.result with input as testdata.job_input({"available": testdata.without(testdata.job_available, "config")})
	r.status == "MANUAL"
}

# False with the Known flag absent is a fetcher that read nothing, not a job
# without a token.
test_manual_when_presence_was_not_established if {
	j := testdata.replacing(testdata.job({}), "remoteTriggerTokenKnown", false)
	r := cis_2_3_5.result with input as testdata.input_for(j)
	r.status == "MANUAL"
}

test_produces_a_verdict_for_an_empty_job if {
	r := cis_2_3_5.result with input as testdata.input_for({})
	r.status == "MANUAL"
}

# A token on a disabled job starts nothing, so the FAIL branch must not win.
test_na_for_a_disabled_job_even_with_a_token if {
	r := cis_2_3_5.result with input as testdata.job_input({"disabled": true, "remoteTriggerToken": true})
	r.status == "NA"
}
