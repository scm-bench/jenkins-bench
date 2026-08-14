package scmbench.rules.cis_2_1_3_test

import rego.v1

import data.scmbench.rules.cis_2_1_3
import data.scmbench.testdata

test_passes_with_an_audit_plugin_active if {
	r := cis_2_1_3.result with input as testdata.controller_input({"plugins": [
		{"shortName": "audit-trail", "version": "3.14", "active": true},
		{"shortName": "git", "version": "5.10.1", "active": true},
	]})
	r.status == "PASS"
	contains(r.details, "audit-trail")
}

test_fails_with_no_audit_plugin if {
	r := cis_2_1_3.result with input as testdata.controller_input({"plugins": [{"shortName": "git", "active": true}]})
	r.status == "FAIL"
}

# Installed but disabled does not audit anything.
test_fails_when_the_audit_plugin_is_inactive if {
	r := cis_2_1_3.result with input as testdata.controller_input({"plugins": [{"shortName": "audit-trail", "active": false}]})
	r.status == "FAIL"
}

# The accepted set comes from configuration, because which plugin counts is
# deployment-specific.
test_honours_the_configured_plugin_names if {
	r := cis_2_1_3.result with input as {
		"resource": testdata.controller({"plugins": [{"shortName": "my-audit-shipper", "active": true}]}),
		"config": {"auditPluginNames": ["my-audit-shipper"]},
	}
	r.status == "PASS"
}

test_manual_when_the_plugin_list_was_unreadable if {
	r := cis_2_1_3.result with input as testdata.controller_input({"available": testdata.without(testdata.controller_available, "plugins")})
	r.status == "MANUAL"
	contains(r.details, "Overall/Administer")
}

test_produces_a_verdict_for_an_empty_controller if {
	r := cis_2_1_3.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
