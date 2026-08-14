package scmbench.rules.cis_2_2_3_test

import rego.v1

import data.scmbench.rules.cis_2_2_3
import data.scmbench.testdata

test_passes_with_zero_executors if {
	r := cis_2_2_3.result with input as testdata.controller_input({})
	r.status == "PASS"
}

test_fails_when_builds_run_on_the_controller if {
	r := cis_2_2_3.result with input as testdata.controller_input({"builtInNode": {"numExecutors": 2, "numExecutorsKnown": true}})
	r.status == "FAIL"
	contains(r.details, "2 executor(s)")
}

# Zero with the Known flag absent is the unreadable case, not the hardened one.
# Producing PASS here would credit a controller nobody measured.
test_manual_when_the_count_was_not_read if {
	c := testdata.replacing(testdata.controller({}), "builtInNode", {"numExecutors": 0})
	r := cis_2_2_3.result with input as testdata.input_for(c)
	r.status == "MANUAL"
}

test_produces_a_verdict_for_an_empty_controller if {
	r := cis_2_2_3.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
