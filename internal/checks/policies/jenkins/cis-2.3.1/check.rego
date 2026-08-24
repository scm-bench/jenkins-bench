# Are the build steps defined as code, in version control? The fetcher resolves
# definition classes to four sources; "unknown" is missing knowledge, not a
# missing Jenkinsfile, and reports MANUAL.
package scmbench.rules.cis_2_3_1

import rego.v1

import data.scmbench.lib

result := {
	"status": "NA",
	"details": "The job is disabled and cannot run, so its build steps never execute. Re-enabling it brings this control back.",
} if {
	lib.job_disabled
} else := {
	"status": "MANUAL",
	"details": "The job's configuration could not be read (it requires Job/ExtendedRead), so how its build steps are defined is unknown.",
} if {
	not lib.available("config")
} else := {
	"status": "PASS",
	"details": sprintf("Build steps are defined as code: the pipeline is read from %s in version control.", [script_path]),
} if {
	lib.definition_source == "scm"
} else := {
	"status": "FAIL",
	"details": "The pipeline script is stored inline in the controller: it is code, but it is not in version control, so it is neither reviewed nor recoverable.",
	"evidence": ["definition.source = inline"],
} if {
	lib.definition_source == "inline"
} else := {
	"status": "FAIL",
	"details": "Build steps are form-field configuration, not code: nothing reviews them and no history records their changes.",
	"evidence": [sprintf("definition.source = ui (class %s)", [job_class])],
} if {
	lib.definition_source == "ui"
} else := {
	"status": "MANUAL",
	"details": sprintf("The job's definition class (%s) is not one this tool recognises, so whether its build steps are in version control is unknown.", [job_class]),
}

script_path := path if {
	path := object.get(lib.resource, ["definition", "scriptPath"], "")
	path != ""
} else := "a Jenkinsfile"

job_class := class if {
	class := object.get(lib.resource, "class", "")
	class != ""
} else := "unknown"
