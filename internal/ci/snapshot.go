// Package ci defines the normalized snapshot that fetchers produce and Rego
// policies consume. Shape:
// https://github.com/scm-bench/scm-bench/blob/main/docs/jenkins-snapshot.md
//
// No field in this package holds a secret — snapshots are written to disk and
// passed around. Presence is a bool, a value is never carried;
// TestSnapshotHoldsNoSecrets asserts it.
package ci

import "time"

// SchemaVersion is bumped whenever the snapshot shape changes in a way that
// existing policies would misread.
const SchemaVersion = "1"

// Platform identifiers used in Metadata.Platform and check metadata.
const (
	PlatformJenkins = "jenkins"
)

// Snapshot is the complete, normalized view of one Jenkins controller.
type Snapshot struct {
	SchemaVersion string     `json:"schemaVersion"`
	Metadata      Metadata   `json:"metadata"`
	Controller    Controller `json:"controller"`
	// Jobs is flat: FullName carries the folder path. Folders are containers
	// and do not appear, and a multibranch project is one entry rather than one
	// per branch.
	Jobs []Job `json:"jobs,omitempty"`
}

// Metadata records how and when the snapshot was captured.
type Metadata struct {
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"toolVersion"`
	Platform    string    `json:"platform"`
	BaseURL     string    `json:"baseUrl"`
	GeneratedAt time.Time `json:"generatedAt"`
	// Warnings collects instance-wide fetch problems — an endpoint that
	// returned 403, an API missing on an older controller. Rules turn the
	// corresponding gaps into MANUAL rather than FAIL.
	Warnings []string `json:"warnings,omitempty"`
}

// Controller is the instance-level view.
type Controller struct {
	// Version comes from the X-Jenkins response header, which is returned
	// without credentials — so it is known even when nothing else is.
	Version     string          `json:"version,omitempty"`
	Security    Security        `json:"security"`
	BuiltInNode BuiltInNode     `json:"builtInNode"`
	Agents      []Agent         `json:"agents,omitempty"`
	Credentials []Credential    `json:"credentials,omitempty"`
	Plugins     []Plugin        `json:"plugins,omitempty"`
	UpdateSite  UpdateSite      `json:"updateSite"`
	Available   map[string]bool `json:"available"`
	Errors      []string        `json:"errors,omitempty"`
}

// Security is what can be established about the controller's posture: flags
// from the instance API plus probe results. Jenkins exposes neither its
// security realm nor its authorization strategy, so "is the strategy X?" is
// not automatable here.
type Security struct {
	// Enabled is the controller's useSecurity flag.
	Enabled      bool `json:"enabled"`
	EnabledKnown bool `json:"enabledKnown"`
	// CSRFProtection is the useCrumbs flag. It cannot be turned off from the
	// UI on a current controller, but the DISABLE_CSRF_PROTECTION system
	// property still works, so this is not always true.
	CSRFProtection      bool `json:"csrfProtection"`
	CSRFProtectionKnown bool `json:"csrfProtectionKnown"`
	// AnonymousRead is measured, not read: the fetcher issues the same GET
	// with no credentials and records whether it succeeded. AnonymousReadKnown
	// is false when the probe did not reach a conclusion — a network error
	// leaves the same false as a denial, and reading one as the other reports
	// PASS on a controller nobody checked.
	AnonymousRead      bool `json:"anonymousRead"`
	AnonymousReadKnown bool `json:"anonymousReadKnown"`
}

// BuiltInNode is the controller's own executors. A hardened controller runs no
// builds itself.
type BuiltInNode struct {
	NumExecutors int `json:"numExecutors"`
	// NumExecutorsKnown distinguishes "zero executors, correctly configured"
	// from "the count could not be read", which are the same value above.
	NumExecutorsKnown bool `json:"numExecutorsKnown"`
	// Labels are what the built-in node answers to. "built-in" is the modern
	// one and "master" survives on upgraded controllers, but an operator can
	// add any label they like — and a job pinned to that label runs on the
	// controller exactly as one pinned to "built-in" does. Resolving where a
	// job runs against a hard-coded pair would have missed every such job.
	Labels []string `json:"labels,omitempty"`
}

// Agent is one node attached to the controller.
type Agent struct {
	Name string `json:"name"`
	// Offline is true for an agent that has never connected, with no cause
	// recorded. Offline is neither absent nor misconfigured, and a rule must
	// not read it as either.
	Offline            bool     `json:"offline"`
	TemporarilyOffline bool     `json:"temporarilyOffline"`
	NumExecutors       int      `json:"numExecutors"`
	Labels             []string `json:"labels,omitempty"`
}

// Credential is credential metadata. Never a secret, and never the masked
// display string either, which carries a username.
type Credential struct {
	// ID is the identifier a job references.
	ID   string `json:"id"`
	Type string `json:"type,omitempty"`
	// Store is the reach of a credential: one in the system store is offered to
	// everything on the controller, one in a folder store only within that
	// folder. Jenkins' own GLOBAL/SYSTEM scope is not exposed by the API at any
	// depth, so it is not modelled — a field nothing can fill would be read by
	// a policy as a value.
	Store       string `json:"store,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Description string `json:"description,omitempty"`
}

// Plugin is one installed plugin.
type Plugin struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version,omitempty"`
	Enabled   bool   `json:"enabled"`
	Active    bool   `json:"active"`
	// HasUpdate is computed by the controller against cached update-centre
	// data, so it is only meaningful when UpdateSite.DataTimestamp is recent.
	// There is no vulnerability or deprecation signal on a controller at all;
	// Jenkins renders those from a feed on updates.jenkins.io.
	HasUpdate bool `json:"hasUpdate"`
}

// UpdateSite records how fresh the update-centre data is.
//
// A controller that has never reached updates.jenkins.io — air-gapped, or
// behind a proxy that never worked — reports HasUpdate false for every plugin,
// which would otherwise read as a clean bill of health.
type UpdateSite struct {
	URL                string    `json:"url,omitempty"`
	DataTimestamp      time.Time `json:"dataTimestamp,omitempty"`
	DataTimestampKnown bool      `json:"dataTimestampKnown"`
}

// Job is one job, plus every setting the rules need.
type Job struct {
	// FullName is the folder path, and what reports show. A branch name
	// containing a slash arrives percent-encoded inside it.
	FullName string `json:"fullName"`
	Name     string `json:"name,omitempty"`
	// Folder is everything before the last segment; empty at the top level.
	Folder string `json:"folder"`
	URL    string `json:"url,omitempty"`
	// Class is the Jenkins class. Kept alongside the normalized Kind because it
	// is the ground truth, and because a fetcher that loses it cannot explain
	// an unknown definition.
	Class      string     `json:"class,omitempty"`
	Kind       string     `json:"kind,omitempty"`
	Disabled   bool       `json:"disabled"`
	Buildable  bool       `json:"buildable"`
	Definition Definition `json:"definition"`
	Triggers   []Trigger  `json:"triggers,omitempty"`
	// RemoteTriggerToken is whether one is configured. Never the token.
	RemoteTriggerToken      bool `json:"remoteTriggerToken"`
	RemoteTriggerTokenKnown bool `json:"remoteTriggerTokenKnown"`
	// RunsOnBuiltInNode is resolved by the fetcher from the job's label
	// expression, its canRoam flag and the built-in node's labels. A rule asks
	// whether the job can run on the controller, never how labels match.
	RunsOnBuiltInNode bool `json:"runsOnBuiltInNode"`
	// RunsOnBuiltInNodeKnown is false for a pipeline, whose agent is chosen in
	// the Jenkinsfile rather than in job configuration.
	RunsOnBuiltInNodeKnown bool            `json:"runsOnBuiltInNodeKnown"`
	Available              map[string]bool `json:"available"`
	Errors                 []string        `json:"errors,omitempty"`
}

// Job kinds. Normalized from the Jenkins class.
const (
	KindPipeline    = "pipeline"
	KindMultibranch = "multibranch"
	KindFreestyle   = "freestyle"
	KindOther       = "other"
)

// Definition is how the build is described.
type Definition struct {
	Source     string   `json:"source,omitempty"`
	ScriptPath string   `json:"scriptPath,omitempty"`
	SCMURLs    []string `json:"scmUrls,omitempty"`
	// Sandbox is whether the Groovy sandbox is on. Only meaningful for
	// SourceInline.
	Sandbox      bool `json:"sandbox"`
	SandboxKnown bool `json:"sandboxKnown"`
}

// Definition sources: the resolved answer to "are the build steps defined as
// code?".
const (
	// SourceSCM is a pipeline read from a Jenkinsfile in version control. A
	// multibranch project is always this; that is what it does.
	SourceSCM = "scm"
	// SourceInline is a pipeline script stored in the controller. It is code,
	// but it is not in version control, so it is neither reviewed nor
	// recoverable.
	SourceInline = "inline"
	// SourceUI is a freestyle or matrix job, whose build steps are
	// configuration clicked into a form.
	SourceUI = "ui"
	// SourceUnknown is a definition class from a plugin the fetcher has not
	// been taught about. Distinct from an unreadable configuration, which
	// leaves Available["config"] false and no Definition at all.
	SourceUnknown = "unknown"
)

// Trigger is one configured build trigger. Spec is a cron-like expression and
// never a token.
type Trigger struct {
	Type string `json:"type"`
	Spec string `json:"spec,omitempty"`
}
