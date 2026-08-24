package scmbench.rules.cis_2_1_2_test

import rego.v1

import data.scmbench.rules.cis_2_1_2
import data.scmbench.testdata

test_passes_for_a_sandboxed_inline_script if {
	r := cis_2_1_2.result with input as testdata.job_input({"definition": {"source": "inline", "sandbox": true, "sandboxKnown": true}})
	r.status == "PASS"
}

test_fails_for_an_unsandboxed_inline_script if {
	r := cis_2_1_2.result with input as testdata.job_input({"definition": {"source": "inline", "sandbox": false, "sandboxKnown": true}})
	r.status == "FAIL"
	contains(r.details, "outside the Groovy sandbox")
}

# NA, not PASS: a pipeline from SCM was not verified by this control, it simply
# has no inline script for the sandbox to apply to.
test_na_for_a_pipeline_from_scm if {
	r := cis_2_1_2.result with input as testdata.job_input({})
	r.status == "NA"
}

test_na_for_a_freestyle_job if {
	r := cis_2_1_2.result with input as testdata.job_input({
		"kind": "freestyle",
		"class": "hudson.model.FreeStyleProject",
		"definition": {"source": "ui"},
	})
	r.status == "NA"
}

# An inline script whose sandbox flag was not in the document: false and absent
# are different answers.
test_manual_when_the_sandbox_flag_was_not_read if {
	r := cis_2_1_2.result with input as testdata.job_input({"definition": {"source": "inline"}})
	r.status == "MANUAL"
}

test_manual_when_the_configuration_was_unreadable if {
	r := cis_2_1_2.result with input as testdata.job_input({"available": testdata.without(testdata.job_available, "config")})
	r.status == "MANUAL"
}

test_produces_a_verdict_for_an_empty_job if {
	r := cis_2_1_2.result with input as testdata.input_for({})
	r.status == "MANUAL"
}

# MANUAL, not NA: a definition class the fetcher has not been taught about may
# well carry an inline script — nobody verified that it does not.
test_manual_for_an_unrecognized_definition_class if {
	r := cis_2_1_2.result with input as testdata.job_input({"definition": {"source": "unknown"}})
	r.status == "MANUAL"
	contains(r.details, "not recognize")
}

# NA ahead of everything else: a disabled job cannot run a script, sandboxed or
# not, and that stays true whether or not its configuration was readable.
test_na_for_a_disabled_job if {
	r := cis_2_1_2.result with input as testdata.job_input({"disabled": true, "definition": {"source": "inline", "sandbox": false, "sandboxKnown": true}})
	r.status == "NA"
}

test_na_for_a_disabled_job_whose_configuration_was_unreadable if {
	r := cis_2_1_2.result with input as testdata.job_input({"disabled": true, "available": testdata.without(testdata.job_available, "config")})
	r.status == "NA"
}
