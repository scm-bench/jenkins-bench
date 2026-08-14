# Is anything auditing the build environment? An unreadable plugin list is
# missing knowledge, not a missing plugin — MANUAL, the common case for a
# least-privilege token.
package scmbench.rules.cis_2_1_3

import rego.v1

import data.scmbench.lib

accepted := lib.list_from(lib.cfg, "auditPluginNames")

installed := [name |
	some name in accepted
	lib.plugin_installed(name)
]

result := {
	"status": "MANUAL",
	"details": "The plugin list could not be read (it requires Overall/Administer), so whether the build environment is audited is unknown.",
} if {
	not lib.available("plugins")
} else := {
	"status": "PASS",
	"details": sprintf("Build-environment auditing is provided by: %s.", [lib.joined(installed, 5)]),
	"evidence": [sprintf("active audit plugins: %s", [lib.joined(installed, 5)])],
} if {
	count(installed) > 0
} else := {
	"status": "FAIL",
	"details": "No audit plugin is active, so changes to jobs, configuration and access leave no trail beyond individual build logs.",
	"evidence": [sprintf("none of the accepted plugins are active: %s", [lib.joined(accepted, 10)])],
}
