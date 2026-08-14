package jenkins

import "encoding/xml"

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
}

// item is one entry in a job listing. A folder is an item too.
type item struct {
	Class    string `json:"_class"`
	Name     string `json:"name"`
	FullName string `json:"fullName"`
	URL      string `json:"url"`
}

// jobListing is GET /api/json?tree=jobs[...] against the root or a folder.
type jobListing struct {
	Jobs []item `json:"jobs"`
}

// jobDetail is GET /job/<path>/api/json.
//
// This is everything a Job/Read token can see, and it is notably not much: no
// definition, no sandbox, no authToken, no assignedNode. All of those live in
// config.xml, which needs Job/ExtendedRead.
type jobDetail struct {
	FullName  string `json:"fullName"`
	Disabled  bool   `json:"disabled"`
	Buildable bool   `json:"buildable"`
}

// computers is GET /computer/api/json?depth=1.
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

// pluginManager is GET /pluginManager/api/json?depth=1 (Overall/Administer).
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
	Credentials []credential `json:"credentials"`
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
	// Triggers is the freestyle location. Pipelines carry them under
	// <properties><...PipelineTriggersJobProperty><triggers>, which
	// triggersFrom finds by walking instead.
	Triggers configTriggers `xml:"triggers"`
	// Sources is a multibranch project's branch sources.
	Sources configSources `xml:"sources"`
}

type configDefinition struct {
	Class string `xml:"class,attr"`
	// ScriptPath is the Jenkinsfile location for an SCM-backed pipeline.
	ScriptPath string `xml:"scriptPath"`
	// Sandbox applies to an inline script. A pointer so that absent is
	// distinguishable from false: absent means the field was not in the
	// document, which is not the same as the sandbox being off.
	Sandbox *string   `xml:"sandbox"`
	SCM     configSCM `xml:"scm"`
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

// Definition classes, as they appear in config.xml.
const (
	classCpsScmFlowDefinition = "org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"
	classCpsFlowDefinition    = "org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition"
)

// Jenkins item classes.
const (
	classFolder      = "com.cloudbees.hudson.plugins.folder.Folder"
	classMultibranch = "org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject"
	classWorkflowJob = "org.jenkinsci.plugins.workflow.job.WorkflowJob"
	classFreestyle   = "hudson.model.FreeStyleProject"
)
