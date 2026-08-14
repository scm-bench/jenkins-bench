# Does anything bypass per-user authorization to trigger this job?
#
# The snapshot records only that a token exists, never its value — config.xml
# returns it in cleartext and a snapshot is written to disk. Presence is enough
# to decide: the token's whole mechanism is authentication-free triggering.
package scmbench.rules.cis_2_3_5

import rego.v1

import data.scmbench.lib

has_token := object.get(lib.resource, "remoteTriggerToken", false)

result := {
	"status": "MANUAL",
	"details": "The job's configuration could not be read (it requires Job/ExtendedRead), so whether a remote trigger token exists is unknown.",
} if {
	not lib.available("config")
} else := {
	"status": "MANUAL",
	"details": "Whether a remote trigger token is configured could not be determined.",
} if {
	not lib.known(["remoteTriggerToken"])
} else := {
	"status": "FAIL",
	"details": "A remote trigger token is configured: anyone who has ever seen the URL can start this build, unauthenticated and unattributed.",
	"evidence": ["an authentication token is set under Build Triggers"],
} if {
	has_token == true
} else := {
	"status": "PASS",
	"details": "No remote trigger token is configured; triggering goes through Jenkins' own authorization.",
}
