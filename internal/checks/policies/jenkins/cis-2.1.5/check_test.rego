package scmbench.rules.cis_2_1_5_test

import rego.v1

import data.scmbench.rules.cis_2_1_5
import data.scmbench.testdata

test_passes_when_csrf_protection_is_on if {
	r := cis_2_1_5.result with input as testdata.controller_input({})
	r.status == "PASS"
}

test_fails_when_the_escape_hatch_was_taken if {
	r := cis_2_1_5.result with input as testdata.controller_input({"security": {
		"enabled": true, "enabledKnown": true,
		"csrfProtection": false, "csrfProtectionKnown": true,
	}})
	r.status == "FAIL"
	contains(r.details, "DISABLE_CSRF_PROTECTION")
}

test_manual_when_the_instance_api_was_unreadable if {
	r := cis_2_1_5.result with input as testdata.controller_input({"available": testdata.without(testdata.controller_available, "root")})
	r.status == "MANUAL"
}

# False with no Known flag is a fetcher that read nothing, not a controller
# that turned protection off.
test_manual_when_the_flag_was_not_read if {
	c := testdata.replacing(testdata.controller({}), "security", {"csrfProtection": false})
	r := cis_2_1_5.result with input as testdata.input_for(c)
	r.status == "MANUAL"
}

test_produces_a_verdict_for_an_empty_controller if {
	r := cis_2_1_5.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
