# Is CSRF protection on? Passes almost everywhere — only the
# DISABLE_CSRF_PROTECTION system property can turn it off, and an instance that
# took that escape hatch is exactly the one worth naming.
package scmbench.rules.cis_2_1_5

import rego.v1

import data.scmbench.lib

protected := object.get(lib.resource, ["security", "csrfProtection"], false)

result := {
	"status": "MANUAL",
	"details": "The instance API could not be read, so whether CSRF protection is enabled is unknown.",
} if {
	not lib.available("root")
} else := {
	"status": "MANUAL",
	"details": "Whether CSRF protection is enabled could not be determined.",
} if {
	not lib.known(["security", "csrfProtection"])
} else := {
	"status": "PASS",
	"details": "CSRF protection is enabled: state-changing requests require a crumb.",
} if {
	protected == true
} else := {
	"status": "FAIL",
	"details": "CSRF protection is disabled, so any web page a logged-in user visits can submit requests in their name. Only the DISABLE_CSRF_PROTECTION system property can produce this state.",
	"evidence": ["useCrumbs = false"],
}
