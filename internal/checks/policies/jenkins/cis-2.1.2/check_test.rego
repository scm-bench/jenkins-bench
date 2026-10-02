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

# A multibranch project whose branch factory supplies an unsandboxed script is
# the same exposure as an inline pipeline, in every branch at once. v0.1 said
# NA here.
test_fails_for_a_multibranch_project_with_an_unsandboxed_factory_script if {
	r := cis_2_1_2.result with input as testdata.job_input({
		"kind": "multibranch",
		"definition": {
			"source": "inline",
			"class": "org.jenkinsci.plugins.inlinepipeline.InlineDefinitionBranchProjectFactory",
			"sandbox": false, "sandboxKnown": true,
		},
	})
	r.status == "FAIL"
}

# A System Groovy build step with its sandbox off is Groovy on the controller
# with the controller's privileges, in a job with no pipeline at all. This
# control said NA for it.
test_fails_for_an_unsandboxed_script_outside_the_definition if {
	r := cis_2_1_2.result with input as testdata.job_input({
		"kind": "freestyle",
		"definition": {"source": "ui"},
		"scripts": [
			{"holder": "hudson.plugins.groovy.SystemGroovy", "sandbox": false},
			{"holder": "org.jvnet.hudson.plugins.groovypostbuild.GroovyPostbuildRecorder", "sandbox": true},
		],
	})
	r.status == "FAIL"
	contains(r.details, "hudson.plugins.groovy.SystemGroovy")
	r.evidence == ["sandbox = false in hudson.plugins.groovy.SystemGroovy"]
}

# One unsandboxed script fails the job even when the definition is unknown.
test_fails_for_an_unsandboxed_script_beside_an_unknown_definition if {
	r := cis_2_1_2.result with input as testdata.job_input({
		"definition": {"source": "unknown"},
		"scripts": [{"holder": "javaposse.jobdsl.plugin.ExecuteDslScripts", "sandbox": false}],
	})
	r.status == "FAIL"
}

test_passes_when_every_script_is_sandboxed if {
	r := cis_2_1_2.result with input as testdata.job_input({
		"kind": "freestyle",
		"definition": {"source": "ui"},
		"scripts": [{"holder": "hudson.plugins.groovy.SystemGroovy", "sandbox": true}],
	})
	r.status == "PASS"
	contains(r.details, "hudson.plugins.groovy.SystemGroovy")
}

test_null_scripts_read_as_none if {
	j := testdata.replacing(testdata.job({"kind": "freestyle", "definition": {"source": "ui"}}), "scripts", null)
	r := cis_2_1_2.result with input as testdata.input_for(j)
	r.status == "NA"
}
