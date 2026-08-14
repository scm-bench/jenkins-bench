# Helpers shared by every control.
#
# The contract each control implements is a single `result` document:
#
#   result := {"status": "PASS"|"FAIL"|"MANUAL"|"NA", "details": "...", "evidence": [...]}
#
# MANUAL means the controller did not expose enough data to decide — never a
# guess dressed up as a verdict. NA means the control does not apply to this
# resource at all. Only PASS and FAIL affect the score.
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

# list reads a list-valued field, treating an explicit JSON null exactly like a
# missing one.
#
# This is load-bearing. Go marshals a nil slice to null rather than [], and
# object.get only substitutes its default when the key is *absent* — a key
# present with a null value comes back as null. Passing that null to concat or
# sort raises a type error, which makes the whole rule undefined and the control
# report nothing at all. Always read lists through this.
list(path) := value if {
	value := object.get(resource, path, [])
	is_array(value)
} else := []

# list_from is list() for a document other than the resource — the config,
# usually. Same trap, same cure: a nil Go slice marshals to null, and a rule
# that passes null to count or iteration goes undefined and reports nothing.
list_from(doc, key) := value if {
	value := object.get(doc, key, [])
	is_array(value)
} else := []

# known reports whether a field that has a legitimate zero or false was actually
# measured. The argument is the value's path; the flag is its sibling with
# "Known" appended.
#
# Jenkins hands out zeros and falses that mean two different things. A built-in
# node with no executors is a hardened controller; a built-in node whose
# executor count could not be read is also 0. An instance that denies anonymous
# access reads false; so does one where the probe never ran. Every such field
# carries a `…Known` companion, and a rule reads it before it reads the value.
# It is defined only when the flag is true, the same shape as available(), so
# that `not known(...)` reads the way it looks. A version returning a boolean
# was tried first and does not: a function that returns false is still defined,
# and `not` over it does not mean what a reader expects.
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
