# Are the installed plugins current? hasUpdate is computed against cached
# update-centre data, so freshness is checked before counting: an air-gapped
# controller reports every plugin current because nothing ever told it
# otherwise.
package scmbench.rules.jenkins_plugin_updates

import rego.v1

import data.scmbench.lib

max_age_days := object.get(lib.cfg, ["thresholds", "updateSiteMaxAgeDays"], 30)

data_timestamp := object.get(lib.resource, ["updateSite", "dataTimestamp"], "")

generated_at := object.get(input, ["metadata", "generatedAt"], "")

# data_age_days is how old the update-centre cache was at capture time.
# Undefined when either timestamp is missing or unparseable, which the MANUAL
# branches catch via known/available first.
data_age_days := days if {
	captured := time.parse_rfc3339_ns(generated_at)
	fetched := time.parse_rfc3339_ns(data_timestamp)
	days := (captured - fetched) / (((((1000 * 1000) * 1000) * 60) * 60) * 24)
}

outdated := [p.shortName |
	some p in lib.list("plugins")
	p.hasUpdate == true
]

result := {
	"status": "MANUAL",
	"details": "The plugin list could not be read (it requires Overall/Administer), so plugin currency is unknown.",
} if {
	not lib.available("plugins")
} else := {
	"status": "MANUAL",
	"details": "The update-centre data's age could not be read, so hasUpdate cannot be trusted: a controller that has never fetched update data reports every plugin as current.",
} if {
	not lib.available("updateSite")
} else := {
	"status": "MANUAL",
	"details": "The update centre reports no data timestamp, so hasUpdate cannot be trusted: a controller that has never fetched update data reports every plugin as current.",
} if {
	not lib.known(["updateSite", "dataTimestamp"])
} else := {
	"status": "MANUAL",
	"details": sprintf("The update-centre data is %d day(s) old (the limit is %d), so hasUpdate is a comparison against a stale catalogue. Let the controller reach its update site, or lower thresholds.updateSiteMaxAgeDays if this is expected.", [floor(data_age_days), max_age_days]),
} if {
	data_age_days > max_age_days
} else := {
	"status": "PASS",
	"details": "Every installed plugin is at its current version, per update-centre data fresh enough to trust.",
} if {
	count(outdated) == 0
} else := {
	"status": "FAIL",
	"details": sprintf("%d plugin(s) have updates pending: %s.", [count(outdated), lib.joined(outdated, 5)]),
	"evidence": [sprintf("plugins with hasUpdate: %s", [lib.joined(outdated, 20)])],
}
