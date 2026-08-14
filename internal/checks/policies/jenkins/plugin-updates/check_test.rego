package scmbench.rules.jenkins_plugin_updates_test

import rego.v1

import data.scmbench.rules.jenkins_plugin_updates as rule
import data.scmbench.testdata

# The engine hands every control the snapshot metadata; generatedAt is what the
# cache age is measured against.
fresh_input(fields) := object.union(
	testdata.controller_input(object.union(
		{"updateSite": {
			"url": "https://updates.jenkins.io/update-center.json",
			"dataTimestamp": "2026-08-13T06:00:00Z",
			"dataTimestampKnown": true,
		}},
		fields,
	)),
	{"metadata": {"generatedAt": "2026-08-14T09:00:00Z"}},
)

test_passes_when_everything_is_current if {
	r := rule.result with input as fresh_input({"plugins": [
		{"shortName": "git", "hasUpdate": false, "active": true},
		{"shortName": "matrix-auth", "hasUpdate": false, "active": true},
	]})
	r.status == "PASS"
}

test_fails_and_names_the_outdated_plugins if {
	r := rule.result with input as fresh_input({"plugins": [
		{"shortName": "git", "hasUpdate": true, "active": true},
		{"shortName": "matrix-auth", "hasUpdate": false, "active": true},
		{"shortName": "credentials", "hasUpdate": true, "active": true},
	]})
	r.status == "FAIL"
	contains(r.details, "2 plugin(s)")
	contains(r.details, "credentials")
	contains(r.details, "git")
}

test_manual_when_the_plugin_list_was_unreadable if {
	r := rule.result with input as fresh_input({"available": testdata.without(testdata.controller_available, "plugins")})
	r.status == "MANUAL"
}

test_manual_when_the_update_site_was_unreadable if {
	r := rule.result with input as fresh_input({"available": testdata.without(testdata.controller_available, "updateSite")})
	r.status == "MANUAL"
	contains(r.details, "cannot be trusted")
}

# The air-gapped case this control exists to not get wrong: every plugin says
# hasUpdate false because nothing ever told the controller otherwise, and no
# timestamp exists at all.
test_manual_when_the_controller_never_fetched_update_data if {
	r := rule.result with input as object.union(
		testdata.controller_input({
			"updateSite": {"dataTimestampKnown": false},
			"plugins": [{"shortName": "git", "hasUpdate": false, "active": true}],
		}),
		{"metadata": {"generatedAt": "2026-08-14T09:00:00Z"}},
	)
	r.status == "MANUAL"
	contains(r.details, "no data timestamp")
}

test_manual_when_the_update_data_is_stale if {
	r := rule.result with input as object.union(
		testdata.controller_input({
			"updateSite": {
				"dataTimestamp": "2026-01-01T00:00:00Z",
				"dataTimestampKnown": true,
			},
			"plugins": [{"shortName": "git", "hasUpdate": false, "active": true}],
		}),
		{"metadata": {"generatedAt": "2026-08-14T09:00:00Z"}},
	)
	r.status == "MANUAL"
	contains(r.details, "day(s) old")
}

test_produces_a_verdict_for_an_empty_controller if {
	r := rule.result with input as testdata.input_for({})
	r.status == "MANUAL"
}
