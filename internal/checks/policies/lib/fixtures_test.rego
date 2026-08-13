# Shared fixtures for the control unit tests.
#
# The configuration here mirrors config.Default() in internal/config. It is
# restated rather than derived because that is the point: if someone changes a
# default in Go without meaning to change what the rules assert, the tests that
# pin the behaviour keep asserting the old numbers and the difference shows up
# as a failure rather than as a quietly different verdict.
package scmbench.testdata

import rego.v1

config := {"thresholds": {}}

# controller_available lists the instance-level fetches a rule may ask about.
# Tests start from all of them succeeding and switch off the one under
# examination, so a MANUAL case says which fetch failed rather than which five
# did not.
controller_available := {
	"root": true,
	"agents": true,
	"credentials": true,
	"plugins": true,
	"updateSite": true,
}

# job_available lists the per-job fetches. There are only two, and the one that
# matters is `config`: a token without Job/ExtendedRead gets a 403 there, and
# nothing about how a job is defined is available anywhere else.
job_available := {
	"api": true,
	"config": true,
}

# controller builds a hardened controller with everything readable, and the
# given fields merged over the top.
#
# Hardened rather than empty on purpose. A fixture that starts from zeros makes
# every test look like it is exercising the failure path, and hides the case
# where a rule produces no verdict at all because the fields it reads are simply
# absent.
controller(fields) := object.union(
	{
		"version": "2.541.2",
		"security": {
			"enabled": true,
			"enabledKnown": true,
			"csrfProtection": true,
			"csrfProtectionKnown": true,
			"anonymousRead": false,
			"anonymousReadKnown": true,
		},
		"builtInNode": {"numExecutors": 0, "numExecutorsKnown": true},
		"agents": [],
		"credentials": [],
		"plugins": [],
		"available": controller_available,
	},
	fields,
)

# job builds a job defined as code in version control, everything readable.
job(fields) := object.union(
	{
		"fullName": "platform/api-service",
		"name": "api-service",
		"folder": "platform",
		"class": "org.jenkinsci.plugins.workflow.job.WorkflowJob",
		"kind": "pipeline",
		"disabled": false,
		"buildable": true,
		"definition": {"source": "scm", "scriptPath": "Jenkinsfile"},
		"triggers": [],
		"remoteTriggerToken": false,
		"remoteTriggerTokenKnown": true,
		"runsOnBuiltInNodeKnown": false,
		"available": job_available,
	},
	fields,
)

# replacing overrides one top-level key of a resource outright.
#
# object.union merges *recursively*, which is what you want for
# controller({"security": {"anonymousRead": true}}) — the other security
# defaults stay in place. It is exactly wrong for a test whose point is that a
# field is absent: the default's `…Known` flag survives the override and the
# rule reads a value the test meant to take away. Both of the MANUAL tests here
# passed against a rule that could not have produced MANUAL, until this existed.
replacing(base, key, value) := object.union(object.remove(base, [key]), {key: value})

# input_for wraps a resource as the engine does.
input_for(resource) := {"resource": resource, "config": config}

# controller_input and job_input are the common cases: a resource, wrapped.
controller_input(fields) := input_for(controller(fields))

job_input(fields) := input_for(job(fields))

# without marks one availability key as failed, leaving the rest readable.
without(available, key) := object.union(available, {key: false})
