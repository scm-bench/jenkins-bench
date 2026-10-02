package scmbench.rules.cis_2_3_5_test

import rego.v1

import data.scmbench.rules.cis_2_3_5
import data.scmbench.testdata

test_passes_with_no_token if {
	r := cis_2_3_5.result with input as testdata.job_input({})
	r.status == "PASS"
}

test_fails_when_a_token_is_configured if {
	r := cis_2_3_5.result with input as testdata.job_input({"remoteTriggerToken": true, "unauthenticatedTriggers": ["authToken"]})
	r.status == "FAIL"
	contains(r.details, "Trigger builds remotely")
	r.evidence == ["unauthenticated trigger: authToken"]
}

# The audit's false PASS: a Generic Webhook Trigger starts a build with no
# Jenkins login, and v0.1 looked only at <authToken>.
test_fails_for_a_generic_webhook_trigger if {
	r := cis_2_3_5.result with input as testdata.job_input({"unauthenticatedTriggers": ["GenericTrigger"]})
	r.status == "FAIL"
	contains(r.details, "Generic Webhook Trigger")
}

test_names_every_mechanism if {
	r := cis_2_3_5.result with input as testdata.job_input({"unauthenticatedTriggers": ["GenericTrigger", "authToken"]})
	r.status == "FAIL"
	count(r.evidence) == 2
	contains(r.details, " and ")
}

# A mechanism the policy has no wording for still fails, under its own name.
test_fails_for_a_mechanism_it_has_no_words_for if {
	r := cis_2_3_5.result with input as testdata.job_input({"unauthenticatedTriggers": ["SomeFutureTrigger"]})
	r.status == "FAIL"
	contains(r.details, "SomeFutureTrigger")
}

# A trigger nobody taught the fetcher about may or may not authenticate.
test_manual_for_an_unrecognized_trigger if {
	r := cis_2_3_5.result with input as testdata.job_input({"unrecognizedTriggers": ["com.example.MysteryTrigger"]})
	r.status == "MANUAL"
	contains(r.details, "com.example.MysteryTrigger")
}

# One proven bypass is enough to fail, whatever else is unknown.
test_fails_when_a_bypass_sits_beside_an_unknown if {
	r := cis_2_3_5.result with input as testdata.job_input({
		"unauthenticatedTriggers": ["GenericTrigger"],
		"unrecognizedTriggers": ["com.example.MysteryTrigger"],
	})
	r.status == "FAIL"
}

# A multibranch project's builds run under triggers its branch jobs carry, which
# the scan does not read. v0.1 reported PASS here.
test_manual_for_a_multibranch_project if {
	j := testdata.replacing(testdata.job({"kind": "multibranch"}), "triggersKnown", false)
	r := cis_2_3_5.result with input as testdata.input_for(j)
	r.status == "MANUAL"
	contains(r.details, "branch")
}

test_manual_when_the_job_type_keeps_triggers_elsewhere if {
	j := testdata.replacing(testdata.job({"kind": "other"}), "triggersKnown", false)
	r := cis_2_3_5.result with input as testdata.input_for(j)
	r.status == "MANUAL"
	contains(r.details, "type")
}

test_manual_when_the_configuration_was_unreadable if {
	r := cis_2_3_5.result with input as testdata.job_input({"available": testdata.without(testdata.job_available, "config")})
	r.status == "MANUAL"
}

test_produces_a_verdict_for_an_empty_job if {
	r := cis_2_3_5.result with input as testdata.input_for({})
	r.status == "MANUAL"
}

# A token on a disabled job starts nothing, so the FAIL branch must not win.
test_na_for_a_disabled_job_even_with_a_token if {
	r := cis_2_3_5.result with input as testdata.job_input({"disabled": true, "unauthenticatedTriggers": ["authToken"]})
	r.status == "NA"
}

# Go marshals a nil slice to null; the lists must read as empty, not error.
test_null_lists_read_as_empty if {
	j := testdata.replacing(testdata.replacing(testdata.job({}), "unauthenticatedTriggers", null), "unrecognizedTriggers", null)
	r := cis_2_3_5.result with input as testdata.input_for(j)
	r.status == "PASS"
}
