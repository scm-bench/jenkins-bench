# Tests for the helpers every control leans on.
#
# They are exercised indirectly by the control tests, but the branches that only
# appear at the edges — a list that came back as JSON null, a field whose
# "Known" flag is absent, a job list long enough to be truncated — are reached
# from here, where the case can be stated plainly.
package scmbench.lib_test

import rego.v1

import data.scmbench.lib
import data.scmbench.testdata

# --- available -------------------------------------------------------------

test_available_is_true_for_a_successful_fetch if {
	lib.available("plugins") with input as testdata.controller_input({})
}

test_available_is_false_for_a_failed_fetch if {
	not lib.available("plugins") with input as testdata.controller_input({"available": testdata.without(testdata.controller_available, "plugins")})
}

# A key nobody set is unavailable, not available. This is the direction that
# matters: the other way round, a fetcher that forgot to record a key would
# produce verdicts about data it never read.
test_available_is_false_for_a_key_that_was_never_recorded if {
	not lib.available("something-nobody-fetched") with input as testdata.controller_input({})
}

# --- list ------------------------------------------------------------------

test_list_reads_a_present_list if {
	got := lib.list("plugins") with input as testdata.controller_input({"plugins": [{"shortName": "git"}]})
	count(got) == 1
}

test_list_substitutes_for_a_missing_key if {
	got := lib.list("nothing-here") with input as testdata.controller_input({})
	got == []
}

# The reason this helper exists. Go marshals a nil slice to null rather than [],
# and object.get only substitutes its default when the key is *absent* — a key
# present with a null value comes back null. Passing that to count or sort
# raises a type error, which makes the calling rule undefined, and a control
# that is undefined reports nothing at all.
test_list_treats_an_explicit_null_as_missing if {
	got := lib.list("plugins") with input as testdata.controller_input({"plugins": null})
	got == []
}

test_list_reads_a_nested_path if {
	got := lib.list(["definition", "scmUrls"]) with input as testdata.job_input({"definition": {"scmUrls": ["https://example.invalid/r.git"]}})
	count(got) == 1
}

# --- known -----------------------------------------------------------------

test_known_is_true_when_the_flag_is_set if {
	lib.known(["builtInNode", "numExecutors"]) with input as testdata.controller_input({})
}

test_known_is_false_when_the_flag_is_absent if {
	c := testdata.replacing(testdata.controller({}), "builtInNode", {"numExecutors": 0})
	not lib.known(["builtInNode", "numExecutors"]) with input as testdata.input_for(c)
}

test_known_is_false_when_the_flag_is_explicitly_false if {
	not lib.known(["runsOnBuiltInNode"]) with input as testdata.job_input({})
}

test_known_handles_a_top_level_field if {
	lib.known(["remoteTriggerToken"]) with input as testdata.job_input({})
}

# --- joined ----------------------------------------------------------------

test_joined_lists_everything_below_the_limit if {
	msg := lib.joined(["b", "a"], 5)
	msg == "a, b"
}

# A controller with hundreds of jobs must not produce a finding that is one
# unreadable line.
test_joined_truncates_above_the_limit if {
	msg := lib.joined(["a", "b", "c", "d"], 2)
	msg == "a, b and 2 more"
}

test_joined_returns_empty_for_a_null if {
	msg := lib.joined(null, 5)
	msg == ""
}

# --- plugin_installed ------------------------------------------------------

test_plugin_installed_finds_an_active_plugin if {
	lib.plugin_installed("audit-trail") with input as testdata.controller_input({"plugins": [{"shortName": "audit-trail", "active": true}]})
}

# Present but disabled is not installed for any purpose a control cares about:
# a disabled plugin does not run, so whatever it was going to enforce is not
# being enforced.
test_plugin_installed_ignores_an_inactive_plugin if {
	not lib.plugin_installed("audit-trail") with input as testdata.controller_input({"plugins": [{"shortName": "audit-trail", "active": false}]})
}

test_plugin_installed_is_false_when_absent if {
	not lib.plugin_installed("audit-trail") with input as testdata.controller_input({})
}

# --- job helpers -----------------------------------------------------------

test_job_disabled_is_false_for_a_live_job if {
	not lib.job_disabled with input as testdata.job_input({})
}

test_job_disabled_is_true_for_a_disabled_job if {
	lib.job_disabled with input as testdata.job_input({"disabled": true})
}

test_definition_source_reads_the_resolved_value if {
	src := lib.definition_source with input as testdata.job_input({"definition": {"source": "inline"}})
	src == "inline"
}

# An unreadable configuration carries no definition at all. Falling back to
# "unknown" keeps a rule from going undefined; the rule still has to check
# available("config") first, because "unknown" is not a verdict.
test_definition_source_falls_back_when_there_is_no_definition if {
	j := testdata.replacing(testdata.job({}), "definition", {})
	src := lib.definition_source with input as testdata.input_for(j)
	src == "unknown"
}

test_job_name_uses_the_full_path if {
	name := lib.job_name with input as testdata.job_input({})
	name == "platform/api-service"
}

# Falls back rather than rendering an empty string, so a message never reads
# "builds of  are not defined as code".
test_job_name_falls_back_when_unnamed if {
	j := testdata.replacing(testdata.job({}), "fullName", "")
	name := lib.job_name with input as testdata.input_for(j)
	name == "this job"
}

# --- cfg -------------------------------------------------------------------

test_cfg_is_the_config_document if {
	c := lib.cfg with input as {"resource": {}, "config": {"thresholds": {"example": 3}}}
	c.thresholds.example == 3
}
