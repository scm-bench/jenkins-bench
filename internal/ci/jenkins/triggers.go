package jenkins

import "sort"

// What the fetcher knows about how a build can be started.
//
// CIS-2.3.5 asks whether starting a build goes through Jenkins' own per-user
// authorization. v0.1 answered it from <authToken> alone, and a Generic
// Webhook Trigger token — which starts a build with no Jenkins login at all —
// came back PASS. Which trigger classes skip that authorization is plugin
// knowledge, version-dependent and fiddly, so it is resolved here, in Go, and a
// rule only counts what this file names.
//
// A class this file does not know is neither: it is reported as unrecognized,
// and the control says it could not tell, rather than guessing either way.

// mechanismAuthToken names the core "Trigger builds remotely" token, which
// lives in <authToken> rather than among the triggers.
const mechanismAuthToken = "authToken"

// unauthenticatedTriggers are trigger classes that start a build without the
// caller holding Job/Build on it, keyed to the name the snapshot records.
var unauthenticatedTriggers = map[string]string{
	// POST /generic-webhook-trigger/invoke is an unprotected root action.
	// With a token configured, anyone holding the token starts the build
	// with no login at all; without one, anyone who can read the job starts
	// it, Job/Build or not. Both measured against 2.580.1 with
	// generic-webhook-trigger 2.4.3.
	"org.jenkinsci.plugins.gwt.GenericTrigger": "GenericTrigger",
}

// authorizedTriggers are trigger classes that start builds only through
// Jenkins' own scheduling, so nothing outside it can make them fire.
var authorizedTriggers = map[string]bool{
	// Build periodically: a cron schedule.
	"hudson.triggers.TimerTrigger": true,
	// Poll SCM. The git plugin's notifyCommit endpoint only schedules a
	// poll, which builds nothing unless the repository actually changed.
	"hudson.triggers.SCMTrigger": true,
	// "Build after other projects are built": the upstream build's own
	// authorization decides.
	"jenkins.triggers.ReverseBuildTrigger": true,
	// A multibranch project's or organization folder's periodic re-scan.
	"com.cloudbees.hudson.plugins.folder.computed.PeriodicFolderTrigger": true,
	// "GitHub hook trigger for GITScm polling": a push event runs a poll,
	// and a build follows only if the poll finds a change — a forged
	// payload can at most make the controller look.
	"com.cloudbees.jenkins.GitHubPushTrigger": true,
}

// triggerAssessment is what a job's configuration says about how its builds
// start.
type triggerAssessment struct {
	unauthenticated []string
	unrecognized    []string
}

// assessTriggers classifies a job's triggers. authToken is the core remote
// trigger token's presence; classes are the trigger elements' names, which
// XStream writes as the trigger's class.
func assessTriggers(authToken bool, classes []string) triggerAssessment {
	var a triggerAssessment
	seen := map[string]bool{}
	add := func(list *[]string, name string) {
		if !seen[name] {
			seen[name] = true
			*list = append(*list, name)
		}
	}
	if authToken {
		add(&a.unauthenticated, mechanismAuthToken)
	}
	for _, class := range classes {
		switch {
		case unauthenticatedTriggers[class] != "":
			add(&a.unauthenticated, unauthenticatedTriggers[class])
		case authorizedTriggers[class]:
		default:
			add(&a.unrecognized, class)
		}
	}
	sort.Strings(a.unauthenticated)
	sort.Strings(a.unrecognized)
	return a
}
