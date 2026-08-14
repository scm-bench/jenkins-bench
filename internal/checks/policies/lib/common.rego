# Helpers shared by every control. Each control returns one result document:
#   {"status": "PASS"|"FAIL"|"MANUAL"|"NA", "details": "...", "evidence": [...]}
# MANUAL = not enough data to decide; NA = does not apply. Only PASS and FAIL
# affect the score.
package scmbench.lib

import rego.v1

# resource is the controller or the job under evaluation.
resource := input.resource

# cfg holds the thresholds, so no control hard-codes a number.
cfg := input.config

# available reports whether a given part of the snapshot was fetched
# successfully. A missing key is treated as unavailable.
available(key) if {
	object.get(resource, ["available", key], false) == true
}

# list reads a list-valued field, treating an explicit JSON null like a missing
# one. Load-bearing: Go marshals a nil slice to null, null errors concat/sort,
# and an errored rule is undefined — the control reports nothing at all.
list(path) := value if {
	value := object.get(resource, path, [])
	is_array(value)
} else := []

# list_from is list() for a document other than the resource (the config,
# usually). Same null trap, same cure.
list_from(doc, key) := value if {
	value := object.get(doc, key, [])
	is_array(value)
} else := []

# known reports whether a field with a legitimate zero/false was actually
# measured, via its sibling "…Known" flag: an unread executor count and a
# hardened zero are the same value otherwise. Defined only when true, like
# available(), so `not known(...)` means what it looks like.
known(path) if {
	n := count(path)
	flag := array.concat(array.slice(path, 0, n - 1), [sprintf("%sKnown", [path[n - 1]])])
	object.get(resource, flag, false) == true
}

# joined renders a list for a message, capping the length so a controller with
# hundreds of jobs does not produce an unreadable line. The is_array guards keep
# a null from erroring the rule that calls it.
joined(items, limit) := msg if {
	is_array(items)
	count(items) > limit
	shown := array.slice(sort(items), 0, limit)
	msg := sprintf("%s and %d more", [concat(", ", shown), count(items) - limit])
} else := msg if {
	is_array(items)
	msg := concat(", ", sort(items))
} else := ""

# --- controller helpers ----------------------------------------------------

# plugin_installed reports whether a plugin is present and active. An absent
# plugin is missing knowledge, not a passing grade: a control that depends on
# one must check `available("plugins")` first and report MANUAL when the plugin
# list could not be read at all, which needs Overall/Administer.
plugin_installed(short_name) if {
	some p in list("plugins")
	p.shortName == short_name
	p.active == true
}

# --- job helpers -----------------------------------------------------------

# job_disabled is true for a job that cannot run. Controls about how a job
# builds report NA for one, the way a branch protection control reports NA for
# a repository with no commits: there is nothing to get wrong.
job_disabled if {
	object.get(resource, "disabled", false) == true
}

# definition_source is how the build is described: scm, inline, ui, or unknown.
# The fetcher resolves it from the job's definition class, so a rule never has
# to know that CpsScmFlowDefinition and a multibranch project are the same
# answer to the same question.
definition_source := source if {
	source := object.get(resource, ["definition", "source"], "")
	source != ""
} else := "unknown"

# job_name is the path a report shows.
job_name := name if {
	name := object.get(resource, "fullName", "")
	name != ""
} else := "this job"
