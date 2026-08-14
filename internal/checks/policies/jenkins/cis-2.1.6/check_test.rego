package scmbench.rules.cis_2_1_6_test

import rego.v1

import data.scmbench.rules.cis_2_1_6
import data.scmbench.testdata

test_passes_when_security_is_on_and_anonymous_is_denied if {
	r := cis_2_1_6.result with input as testdata.controller_input({})
	r.status == "PASS"
}

test_fails_when_an_unauthenticated_client_can_read_the_controller if {
	r := cis_2_1_6.result with input as testdata.controller_input({"security": {
		"enabled": true,
		"enabledKnown": true,
		"anonymousRead": true,
		"anonymousReadKnown": true,
	}})
	r.status == "FAIL"
	contains(r.details, "unauthenticated client can read")
}

test_fails_when_security_is_disabled_entirely if {
	r := cis_2_1_6.result with input as testdata.controller_input({"security": {
		"enabled": false,
		"enabledKnown": true,
		"anonymousRead": true,
		"anonymousReadKnown": true,
	}})
	r.status == "FAIL"
	contains(r.details, "Security is disabled")
}

# Security off is reported as itself rather than as anonymous access, because
# the remediation differs: one turns security on, the other edits a matrix.
test_reports_disabled_security_before_anonymous_access if {
	r := cis_2_1_6.result with input as testdata.controller_input({"security": {
		"enabled": false,
		"enabledKnown": true,
		"anonymousRead": false,
		"anonymousReadKnown": true,
	}})
	r.status == "FAIL"
	contains(r.details, "Security is disabled")
}

test_manual_when_the_instance_api_was_unreadable if {
	r := cis_2_1_6.result with input as testdata.controller_input({"available": testdata.without(testdata.controller_available, "root")})
	r.status == "MANUAL"
}

test_manual_when_whether_security_is_enabled_is_unknown if {
	c := testdata.replacing(testdata.controller({}), "security", {"enabled": false})
	r := cis_2_1_6.result with input as testdata.input_for(c)
	r.status == "MANUAL"
	contains(r.details, "security is enabled")
}

# The probe failing is not the same as the probe returning "denied". A network
# error leaves anonymousRead false, and reading that as a denial would report
# PASS on a controller nobody checked.
test_manual_when_the_anonymous_probe_did_not_conclude if {
	c := testdata.replacing(testdata.controller({}), "security", {
		"enabled": true,
		"enabledKnown": true,
		"anonymousRead": false,
	})
	r := cis_2_1_6.result with input as testdata.input_for(c)
	r.status == "MANUAL"
	contains(r.details, "probe did not reach a conclusion")
}

# The zero-valued case: a controller object carrying nothing at all. It must
# still produce a verdict. A rule that goes undefined here reports nothing, and
# a control that reports nothing looks exactly like a control that passed.
test_produces_a_verdict_for_an_empty_controller if {
	r := cis_2_1_6.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
