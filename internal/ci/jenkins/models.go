package jenkins

import (
	"encoding/json"
	"encoding/xml"
)

// The shapes a controller actually returns. Field names and the depth needed to
// populate them were measured, not read from documentation — see
// docs/jenkins-api-notes.md.

// instance is GET /api/json. useSecurity and useCrumbs are the only security
// posture the API exposes; securityRealm and authorizationStrategy are not
// exported at all.
type instance struct {
	// Pointers, all three, because absent and false are different answers —
	// the …Known flags in the snapshot carry that difference to the policies.
	NumExecutors *int  `json:"numExecutors"`
	UseSecurity  *bool `json:"useSecurity"`
	UseCrumbs    *bool `json:"useCrumbs"`
	// The root object is also the built-in node, so its mode and labels come
	// with Overall/Read — no node list needed. Nil when not exported.
	Mode           *string  `json:"mode"`
	AssignedLabels *[]label `json:"assignedLabels"`
}

// Every endpoint is asked for the fields the scan reads and nothing else.
// Without tree=, Jenkins renders whatever the object exports at the default
// depth: the root API a colour per job, a job's API up to a hundred builds and
// every last*Build, the node list each label's tiedJobs. On a large controller
// that is what hits the request timeout and the response cap, for fields no
// control reads.
const (
	instanceTree = "useSecurity,useCrumbs,numExecutors,mode,assignedLabels[name]"
	computerTree = "computer[_class,displayName,offline,temporarilyOffline,numExecutors,assignedLabels[name]]"
	pluginTree   = "plugins[shortName,version,enabled,active,hasUpdate]"
	// jobs[_class]{0,1} asks each item for at most one child: enough to tell
	// an item that holds others from one that does not, at the cost of one
	// small object per folder.
	listingTree = "jobs[" + itemTree + "]"
	// itemTree is one item's fields, as a listing reports them and as a
	// scoping flag's target is read on its own.
	itemTree = "_class,name,fullName,url,disabled,buildable,jobs[_class]{0,1}"
)

// item is one entry in a job listing. A folder is an item too.
//
// disabled and buildable are everything a Job/Read token can see of how a job
// behaves, and notably not much: no definition, no sandbox, no authToken, no
// assignedNode. All of those live in config.xml, which needs Job/ExtendedRead.
// A multibranch project exports buildable only; its disabled flag is read from
// its configuration.
type item struct {
	Class     string `json:"_class"`
	Name      string `json:"name"`
	FullName  string `json:"fullName"`
	URL       string `json:"url"`
	Disabled  bool   `json:"disabled"`
	Buildable bool   `json:"buildable"`
	// Children is non-nil exactly when the item exports a jobs array — an
	// empty one included, which is a folder with nothing in it this token
	// can see. A job has no jobs array at all.
	Children []json.RawMessage `json:"jobs"`
}

// jobListing is GET /api/json?tree=jobs[...] against the root or a folder.
type jobListing struct {
	Jobs []item `json:"jobs"`
}

// computers is GET /computer/api/json?tree=computer[...].
type computers struct {
	Computer []computer `json:"computer"`
}

type computer struct {
	Class              string  `json:"_class"`
	DisplayName        string  `json:"displayName"`
	Offline            bool    `json:"offline"`
	TemporarilyOffline bool    `json:"temporarilyOffline"`
	NumExecutors       *int    `json:"numExecutors"`
	AssignedLabels     []label `json:"assignedLabels"`
}

type label struct {
	Name string `json:"name"`
}

// builtInComputerClass identifies the controller's own node. Agents are
// hudson.slaves.SlaveComputer.
const builtInComputerClass = "hudson.model.Hudson$MasterComputer"

// pluginManager is GET /pluginManager/api/json?tree=plugins[...]
// (Overall/SystemRead, which Overall/Administer implies).
// No security-warning or deprecation field exists; Jenkins renders those from
// a feed on updates.jenkins.io, not from the controller.
type pluginManager struct {
	Plugins []plugin `json:"plugins"`
}

type plugin struct {
	ShortName string `json:"shortName"`
	Version   string `json:"version"`
	Enabled   bool   `json:"enabled"`
	Active    bool   `json:"active"`
	HasUpdate bool   `json:"hasUpdate"`
}

// updateSite is GET /updateCenter/site/default/api/json.
type updateSite struct {
	URL string `json:"url"`
	// DataTimestamp is milliseconds since the epoch, and is what makes
	// hasUpdate meaningful. A controller that never reached the update centre
	// reports hasUpdate false for everything.
	DataTimestamp *int64 `json:"dataTimestamp"`
}

// credentialsRoot is GET /credentials/api/json?depth=3. depth=3 is the
// minimum: at depth=2 the array has the right length and every element is {}.
// A tree= expression returns no credentials at any depth. An unreadable store
// is not a 403 — it is a 200 with {"stores":{}}.
type credentialsRoot struct {
	Stores map[string]credentialStore `json:"stores"`
}

type credentialStore struct {
	Domains map[string]credentialDomain `json:"domains"`
}

type credentialDomain struct {
	// A pointer, because both ways of asking at too low a depth leave the key
	// out of the domain object rather than empty — the one difference between
	// "not read" and "none" this endpoint offers.
	Credentials *[]credential `json:"credentials"`
}

// credential omits displayName on purpose. Jenkins masks the secret in it —
// "deployer/****** (…)" — but leaves the username, and a field that is not
// decoded cannot be carried into a snapshot by accident later.
type credential struct {
	ID          string `json:"id"`
	TypeName    string `json:"typeName"`
	Description string `json:"description"`
}

// --- config.xml ------------------------------------------------------------

// jobConfig is the part of a job's config.xml the rules need.
//
// Only these fields are decoded, and only booleans and class names reach the
// snapshot. The document also contains <authToken> in cleartext and a
// <script> that may contain anything, and a snapshot gets written to disk.
type jobConfig struct {
	XMLName    xml.Name          `xml:""`
	Definition *configDefinition `xml:"definition"`
	// Disabled appears on both freestyle and pipeline jobs.
	Disabled string `xml:"disabled"`
	// AuthToken is the remote build trigger token. Decoded only so its presence
	// can be recorded; the value never leaves this struct.
	AuthToken *string `xml:"authToken"`
	// AssignedNode and CanRoam decide where a freestyle job runs.
	AssignedNode string `xml:"assignedNode"`
	CanRoam      string `xml:"canRoam"`
	// Triggers is the freestyle location: a <triggers> element directly under
	// the document root. encoding/xml matches a tag against direct children
	// only, so the pipeline location — <properties><…PipelineTriggersJobProperty>
	// <triggers> — needs its own path below; one tag does not cover both.
	Triggers configTriggers `xml:"triggers"`
	// PipelineTriggers is where a pipeline job keeps the same element.
	PipelineTriggers configTriggers `xml:"properties>org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>triggers"`
	// Sources is a multibranch project's branch sources.
	Sources configSources `xml:"sources"`
	// Factory is how a multibranch project turns a branch into a job: what
	// its branches build from is decided here, not by the project's class.
	Factory configFactory `xml:"factory"`
}

// configFactory is a multibranch project's <factory>. Only the class and the
// flags are decoded; an inline factory's <script> never leaves the document.
type configFactory struct {
	Class      string `xml:"class,attr"`
	ScriptPath string `xml:"scriptPath"`
	// Sandbox is inline-pipeline's flag, UseSandbox the defaults plugin's.
	// Pointers, so an absent flag is not read as an off one.
	Sandbox    *string `xml:"sandbox"`
	UseSandbox *string `xml:"useSandbox"`
}

type configDefinition struct {
	Class string `xml:"class,attr"`
	// ScriptPath is the Jenkinsfile location for an SCM-backed pipeline.
	ScriptPath string `xml:"scriptPath"`
	// Sandbox applies to an inline script. A pointer so that absent is
	// distinguishable from false: absent means the field was not in the
	// document, which is not the same as the sandbox being off.
	Sandbox *string `xml:"sandbox"`
	// UseSandbox is pipeline-multibranch-defaults' spelling of the same flag,
	// on the definition it gives each branch job.
	UseSandbox *string   `xml:"useSandbox"`
	SCM        configSCM `xml:"scm"`
}

type configSCM struct {
	UserRemoteConfigs struct {
		Configs []struct {
			URL string `xml:"url"`
		} `xml:"hudson.plugins.git.UserRemoteConfig"`
	} `xml:"userRemoteConfigs"`
}

type configSources struct {
	Data struct {
		BranchSources []struct {
			Source struct {
				Remote string `xml:"remote"`
			} `xml:"source"`
		} `xml:"jenkins.branch.BranchSource"`
	} `xml:"data"`
}

type configTriggers struct {
	Entries []configTrigger `xml:",any"`
}

type configTrigger struct {
	XMLName xml.Name
	Spec    string `xml:"spec"`
}

// jobDocument is what the fetcher knows about one kind of job configuration,
// keyed by the document's root element.
type jobDocument struct {
	// ui is true for the project types, whose build steps are form fields and
	// whose <assignedNode>/<canRoam> decide where they run.
	ui bool
	// project is true where the fields this fetcher reads are where it reads
	// them: <authToken> at the root, and triggers under <triggers> or, for a
	// pipeline, PipelineTriggersJobProperty.
	project bool
}

// jobDocuments are the root elements read as job configurations, each from a
// document Jenkins wrote on 2.580.1. Anything else is a job type this fetcher
// has not been taught — read, but with nothing in it taken as known — or not
// a configuration at all.
var jobDocuments = map[string]jobDocument{
	"project":          {ui: true, project: true}, // freestyle
	"matrix-project":   {ui: true, project: true},
	"maven2-moduleset": {ui: true, project: true}, // maven-plugin
	"flow-definition":  {project: true},           // pipeline
	classMultibranch:   {},                        // decided by its branch factory
}

// Definition classes, as they appear in config.xml.
const (
	classCpsScmFlowDefinition = "org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"
	classCpsFlowDefinition    = "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition"
	// The definitions a multibranch project's factories give its branch
	// jobs, reachable when a branch job is scanned on its own.
	classSCMBinder            = "org.jenkinsci.plugins.workflow.multibranch.SCMBinder"
	classInlineFlowDefinition = "org.jenkinsci.plugins.inlinepipeline.InlineFlowDefinition"
	classDefaultsBinder       = "org.jenkinsci.plugins.pipeline.multibranch.defaults.DefaultsBinder"
)

// Multibranch branch factories. Each shape was read off a 2.580.1 controller
// with the plugin that writes it.
const (
	// The default: every branch builds the Jenkinsfile at scriptPath in its
	// own source.
	classWorkflowBranchProjectFactory = "org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory"
	// inline-pipeline: every branch builds one <script> stored on the
	// controller, with or without the sandbox.
	classInlineBranchProjectFactory = "org.jenkinsci.plugins.inlinepipeline.InlineDefinitionBranchProjectFactory"
	// pipeline-multibranch-defaults: every branch builds a Jenkinsfile kept
	// in a Config File Provider file on the controller.
	classDefaultsBranchProjectFactory = "org.jenkinsci.plugins.pipeline.multibranch.defaults.PipelineBranchDefaultsProjectFactory"
)

// Jenkins item classes.
const (
	classFolder      = "com.cloudbees.hudson.plugins.folder.Folder"
	classOrgFolder   = "jenkins.branch.OrganizationFolder"
	classMultibranch = "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"
	classWorkflowJob = "org.jenkinsci.plugins.workflow.job.WorkflowJob"
	classFreestyle   = "hudson.model.FreeStyleProject"
)

// isContainer reports whether an item is a container to walk into rather than
// a job to record.
//
// Structurally: an item that exports a jobs array holds other items. It used
// to be two class names, Folder and OrganizationFolder, and anything else was
// recorded as a job — a CloudBees CI team folder, or any folder subclass a
// plugin defines, came out as one job of kind "other", and every job inside it
// vanished from the scan without a word. The two classes stay as a fallback
// for a listing that did not carry the array.
//
// A multibranch project is deliberately NOT a container, although it holds
// items: its children are generated per-branch copies of one job, and
// descending would repeat every finding per branch.
func isContainer(it item) bool {
	if it.Class == classMultibranch {
		return false
	}
	return it.Children != nil || it.Class == classFolder || it.Class == classOrgFolder
}
