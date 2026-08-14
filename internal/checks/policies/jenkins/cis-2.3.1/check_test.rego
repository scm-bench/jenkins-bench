package scmbench.rules.cis_2_3_1_test

import rego.v1

import data.scmbench.rules.cis_2_3_1
import data.scmbench.testdata

test_passes_for_a_pipeline_from_scm if {
	r := cis_2_3_1.result with input as testdata.job_input({})
	r.status == "PASS"
	contains(r.details, "Jenkinsfile")
}

test_passes_for_a_multibranch_project if {
	r := cis_2_3_1.result with input as testdata.job_input({
		"kind": "multibranch",
		"class": "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject",
		"definition": {"source": "scm"},
	})
	r.status == "PASS"
}

test_fails_for_an_inline_script if {
	r := cis_2_3_1.result with input as testdata.job_input({"definition": {"source": "inline", "sandbox": true, "sandboxKnown": true}})
	r.status == "FAIL"
	contains(r.details, "not in version control")
}

test_fails_for_a_freestyle_job if {
	r := cis_2_3_1.result with input as testdata.job_input({
		"kind": "freestyle",
		"class": "hudson.model.FreeStyleProject",
		"definition": {"source": "ui"},
	})
	r.status == "FAIL"
	contains(r.details, "form-field")
}

# A definition class the fetcher was not taught is missing knowledge, not a
# missing Jenkinsfile.
test_manual_for_an_unrecognised_definition if {
	r := cis_2_3_1.result with input as testdata.job_input({
		"class": "com.example.SomePluginJob",
		"definition": {"source": "unknown"},
	})
	r.status == "MANUAL"
	contains(r.details, "com.example.SomePluginJob")
}

test_manual_when_the_configuration_was_unreadable if {
	r := cis_2_3_1.result with input as testdata.job_input({"available": testdata.without(testdata.job_available, "config")})
	r.status == "MANUAL"
	contains(r.details, "Job/ExtendedRead")
}

test_produces_a_verdict_for_an_empty_job if {
	r := cis_2_3_1.result with input as testdata.input_for({})
	r.status == "MANUAL"
}

# The fallbacks that keep a message from reading "read from  in version
# control" or naming an empty class.
test_pass_message_falls_back_when_the_script_path_is_absent if {
	# replacing, not job_input: object.union merges recursively, so the default
	# definition's scriptPath would survive a merged override and this test
	# would assert the fallback against a message that never uses it.
	j := testdata.replacing(testdata.job({}), "definition", {"source": "scm"})
	r := cis_2_3_1.result with input as testdata.input_for(j)
	r.status == "PASS"
	contains(r.details, "a Jenkinsfile")
}

test_manual_message_falls_back_when_the_class_is_absent if {
	j := testdata.replacing(testdata.job({"definition": {"source": "unknown"}}), "class", "")
	r := cis_2_3_1.result with input as testdata.input_for(j)
	r.status == "MANUAL"
	contains(r.details, "unknown")
}
