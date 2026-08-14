# Does the controller require you to log in? The authorization strategy is not
# exported, so anonymousRead is a probe result, not a setting — and the Known
# flag is checked first, because a probe that never ran looks like a denial.
package scmbench.rules.cis_2_1_6

import rego.v1

import data.scmbench.lib

security_enabled := object.get(lib.resource, ["security", "enabled"], false)

anonymous_read := object.get(lib.resource, ["security", "anonymousRead"], false)

result := {
	"status": "MANUAL",
	"details": "The instance API could not be read, so it is unknown whether the controller requires authentication.",
} if {
	not lib.available("root")
} else := {
	"status": "MANUAL",
	"details": "Whether security is enabled could not be determined.",
} if {
	not lib.known(["security", "enabled"])
} else := {
	"status": "FAIL",
	"details": "Security is disabled: every visitor is an administrator, and no action on this controller can be attributed to anyone.",
	"evidence": ["useSecurity = false"],
} if {
	security_enabled == false
} else := {
	"status": "MANUAL",
	"details": "The unauthenticated probe did not reach a conclusion, so anonymous access could not be determined.",
} if {
	not lib.known(["security", "anonymousRead"])
} else := {
	"status": "FAIL",
	"details": "An unauthenticated client can read this controller, so its jobs, build history and console output are public and no action can be attributed to an actor.",
	"evidence": ["an unauthenticated GET of the instance API returned 200"],
} if {
	anonymous_read == true
} else := {
	"status": "PASS",
	"details": "Security is enabled and an unauthenticated client cannot read the controller.",
}
