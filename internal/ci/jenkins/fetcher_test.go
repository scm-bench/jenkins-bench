package jenkins

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

// stand is a controller stand-in. It records every request, and fails the test
// on anything that is not a GET.
type stand struct {
	t *testing.T
	// handlers maps a request path to a response. A path with no handler
	// returns 404, which is what a controller does for a plugin that is not
	// installed.
	handlers map[string]standResponse
	// forbidden lists path prefixes this token may not read.
	forbidden []string

	mu    sync.Mutex
	paths []string
}

type standResponse struct {
	body    string
	headers map[string]string
}

func newStand(t *testing.T) *stand {
	return &stand{t: t, handlers: map[string]standResponse{}}
}

func (s *stand) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The read-only property is a test, not a promise. A fetcher that learned
	// to write would fail here rather than in production.
	if r.Method != http.MethodGet {
		s.t.Errorf("the fetcher issued a %s to %s; every request must be a GET", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	full := r.URL.Path
	if r.URL.RawQuery != "" {
		full += "?" + r.URL.RawQuery
	}
	s.mu.Lock()
	s.paths = append(s.paths, full)
	s.mu.Unlock()

	if _, _, ok := r.BasicAuth(); !ok && r.URL.Path != "/login" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	for _, prefix := range s.forbidden {
		if strings.HasPrefix(r.URL.Path, prefix) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	}

	resp, ok := s.handlers[r.URL.Path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	for k, v := range resp.headers {
		w.Header().Set(k, v)
	}
	fmt.Fprint(w, resp.body)
}

func (s *stand) requested(path string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.paths {
		if p == path || strings.HasPrefix(p, path+"?") {
			return true
		}
	}
	return false
}

// hardened wires a stand-in returning a well-configured controller.
func hardened(t *testing.T) *stand {
	s := newStand(t)
	s.handlers["/login"] = standResponse{headers: map[string]string{"X-Jenkins": "2.541.2"}}
	s.handlers["/api/json"] = standResponse{body: `{
		"mode":"NORMAL","numExecutors":0,"useSecurity":true,"useCrumbs":true,"slaveAgentPort":-1,
		"jobs":[{"_class":"hudson.model.FreeStyleProject","name":"build","fullName":"build","url":"http://x/job/build/"}]}`}
	s.handlers["/computer/api/json"] = standResponse{body: `{"computer":[
		{"_class":"hudson.model.Hudson$MasterComputer","displayName":"Built-In Node","offline":false,"numExecutors":0,"assignedLabels":[{"name":"built-in"}]},
		{"_class":"hudson.slaves.SlaveComputer","displayName":"agent-1","offline":true,"numExecutors":4,"assignedLabels":[{"name":"linux"}]}]}`}
	s.handlers["/pluginManager/api/json"] = standResponse{body: `{"plugins":[
		{"shortName":"git","version":"5.10.1","enabled":true,"active":true,"hasUpdate":false}]}`}
	s.handlers["/updateCenter/site/default/api/json"] = standResponse{body: `{"url":"https://updates.jenkins.io/update-center.json","dataTimestamp":1786650950902}`}
	s.handlers["/credentials/api/json"] = standResponse{body: `{"stores":{"system":{"domains":{"_":{"credentials":[
		{"id":"deploy","typeName":"Username with password","description":"d","displayName":"deployer/****** (d)"}]}}}}}`}
	s.handlers["/job/build/api/json"] = standResponse{body: `{"_class":"hudson.model.FreeStyleProject","fullName":"build","disabled":false,"buildable":true}`}
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version="1.0" encoding="UTF-8"?><project>
		<disabled>false</disabled><canRoam>false</canRoam><assignedNode>linux</assignedNode>
		<triggers><hudson.triggers.SCMTrigger><spec>H/5 * * * *</spec></hudson.triggers.SCMTrigger></triggers></project>`}
	return s
}

func fetchFrom(t *testing.T, s *stand) *ci.Snapshot {
	t.Helper()
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)

	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	snap, err := NewFetcher(client).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	return snap
}

func TestFetcherIssuesOnlyGets(t *testing.T) {
	s := hardened(t)
	fetchFrom(t, s)
	// The assertion lives in ServeHTTP so that it also covers the requests a
	// future control adds without anyone remembering to extend this test.
	if len(s.paths) == 0 {
		t.Fatal("the fetcher made no requests")
	}
}

func TestFetcherReadsAHardenedController(t *testing.T) {
	snap := fetchFrom(t, hardened(t))
	c := snap.Controller

	if snap.SchemaVersion != ci.SchemaVersion {
		t.Errorf("schemaVersion = %q", snap.SchemaVersion)
	}
	if c.Version != "2.541.2" {
		t.Errorf("version = %q, want the X-Jenkins header value", c.Version)
	}
	if !c.Security.Enabled || !c.Security.EnabledKnown {
		t.Errorf("security = %+v", c.Security)
	}
	if !c.Security.CSRFProtection || !c.Security.CSRFProtectionKnown {
		t.Errorf("csrf = %+v", c.Security)
	}
	if c.BuiltInNode.NumExecutors != 0 || !c.BuiltInNode.NumExecutorsKnown {
		t.Errorf("builtInNode = %+v, want 0 executors and known", c.BuiltInNode)
	}
	if len(c.Agents) != 1 || c.Agents[0].Name != "agent-1" {
		t.Errorf("agents = %+v; the built-in node must not appear among them", c.Agents)
	}
	if !c.UpdateSite.DataTimestampKnown {
		t.Error("the update site timestamp should be known")
	}
	if len(snap.Jobs) != 1 || snap.Jobs[0].FullName != "build" {
		t.Fatalf("jobs = %+v", snap.Jobs)
	}
	job := snap.Jobs[0]
	if job.Definition.Source != ci.SourceUI {
		t.Errorf("a freestyle job's build steps are not code: source = %q", job.Definition.Source)
	}
	if job.RunsOnBuiltInNode || !job.RunsOnBuiltInNodeKnown {
		t.Errorf("a job pinned to linux does not run on the controller: %+v", job)
	}
	if len(job.Triggers) != 1 || job.Triggers[0].Type != "SCMTrigger" {
		t.Errorf("triggers = %+v", job.Triggers)
	}
}

// The probe is the only way to answer whether an anonymous client can read the
// controller, because the authorization strategy is not exposed anywhere.
func TestFetcherProbesAnonymousAccess(t *testing.T) {
	s := hardened(t)
	snap := fetchFrom(t, s)
	if snap.Controller.Security.AnonymousRead {
		t.Error("the stand-in denies unauthenticated reads")
	}
	if !snap.Controller.Security.AnonymousReadKnown {
		t.Error("a 403 to the probe is a conclusion, not a failure to reach one")
	}
}

func TestFetcherRecordsAnonymousAccessWhenAllowed(t *testing.T) {
	s := hardened(t)
	// Serve the instance API to everyone, as a controller granting anonymous
	// Overall/Read does.
	inner := s.handlers["/api/json"]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" {
			fmt.Fprint(w, inner.body)
			return
		}
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := NewFetcher(client).Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Controller.Security.AnonymousRead || !snap.Controller.Security.AnonymousReadKnown {
		t.Errorf("security = %+v, want anonymous read detected", snap.Controller.Security)
	}
}

// A least-privilege token is the case this whole design exists for.
func TestFetcherRecordsWhatItCouldNotRead(t *testing.T) {
	s := hardened(t)
	s.forbidden = []string{"/pluginManager", "/updateCenter", "/job/build/config.xml"}
	s.handlers["/credentials/api/json"] = standResponse{body: `{"stores":{}}`}

	snap := fetchFrom(t, s)
	c := snap.Controller

	if c.Available[AvailPlugins] {
		t.Error("plugins should be unavailable")
	}
	if c.Available[AvailUpdateSite] {
		t.Error("the update site should be unavailable")
	}
	// The trap: 200 with an empty store list is what an unauthorised read looks
	// like, and it is indistinguishable from a controller with no credentials.
	// With the plugin read denied there is no evidence the set was real.
	if c.Available[AvailCredentials] {
		t.Error("an empty store list with no administrator access must not read as available")
	}
	if len(c.Errors) == 0 {
		t.Error("the controller should record why each read failed")
	}
	if len(snap.Metadata.Warnings) == 0 {
		t.Error("a token that cannot read the plugin list should produce a warning")
	}
	if snap.Jobs[0].Available[AvailJobConfig] {
		t.Error("the job configuration should be unavailable")
	}
	if snap.Jobs[0].Definition.Source != "" {
		t.Error("an unreadable configuration carries no definition at all, not an unknown one")
	}
}

// An empty credential list is only trustworthy when something proves the token
// would have been shown a store. Reading /pluginManager needs
// Overall/Administer, so succeeding at it is that proof.
func TestFetcherTrustsAnEmptyCredentialListWithAdministratorAccess(t *testing.T) {
	s := hardened(t)
	s.handlers["/credentials/api/json"] = standResponse{body: `{"stores":{}}`}
	snap := fetchFrom(t, s)
	if !snap.Controller.Available[AvailCredentials] {
		t.Error("with the plugin list readable, an empty store list is genuinely empty")
	}
	if len(snap.Controller.Credentials) != 0 {
		t.Error("no credentials should have been recorded")
	}
}

// Jenkins re-serializes a job's configuration as XML 1.1 whenever it saves one,
// and Go's encoding/xml rejects that outright. Every job that had ever been
// saved came back unreadable.
func TestFetcherParsesXML11Configurations(t *testing.T) {
	s := hardened(t)
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@1571">
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition" plugin="workflow-cps@4362">
    <scm class="hudson.plugins.git.GitSCM">
      <userRemoteConfigs><hudson.plugins.git.UserRemoteConfig><url>https://example.invalid/r.git</url></hudson.plugins.git.UserRemoteConfig></userRemoteConfigs>
    </scm>
    <scriptPath>Jenkinsfile</scriptPath>
  </definition>
  <disabled>false</disabled>
</flow-definition>`}

	snap := fetchFrom(t, s)
	job := snap.Jobs[0]
	if !job.Available[AvailJobConfig] {
		t.Fatalf("an XML 1.1 configuration must parse; errors: %v", job.Errors)
	}
	if job.Definition.Source != ci.SourceSCM {
		t.Errorf("definition.source = %q, want scm", job.Definition.Source)
	}
	if job.Definition.ScriptPath != "Jenkinsfile" {
		t.Errorf("scriptPath = %q", job.Definition.ScriptPath)
	}
	if len(job.Definition.SCMURLs) != 1 {
		t.Errorf("scmUrls = %v", job.Definition.SCMURLs)
	}
}

// A folder name with a space is ordinary. Encoding the path with form rules —
// "+" for a space — or double-encoding it returns a 404 indistinguishable from
// a job that does not exist, and the whole folder vanishes from the scan.
func TestFetcherWalksFoldersWithSpacesInTheirNames(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"Team A","fullName":"Team A","url":"http://x/job/Team%20A/"}]}`}
	s.handlers["/job/Team A/api/json"] = standResponse{body: `{"jobs":[
		{"_class":"hudson.model.FreeStyleProject","name":"Case 01 - Default","fullName":"Team A/Case 01 - Default","url":"http://x/"}]}`}
	s.handlers["/job/Team A/job/Case 01 - Default/api/json"] = standResponse{body: `{"fullName":"Team A/Case 01 - Default","buildable":true}`}
	s.handlers["/job/Team A/job/Case 01 - Default/config.xml"] = standResponse{body: `<?xml version="1.0"?><project><canRoam>true</canRoam></project>`}

	snap := fetchFrom(t, s)
	if len(snap.Jobs) != 1 {
		t.Fatalf("jobs = %+v; the folder should have been walked", snap.Jobs)
	}
	job := snap.Jobs[0]
	if job.FullName != "Team A/Case 01 - Default" {
		t.Errorf("fullName = %q", job.FullName)
	}
	if job.Folder != "Team A" || job.Name != "Case 01 - Default" {
		t.Errorf("folder = %q, name = %q", job.Folder, job.Name)
	}
	if !job.Available[AvailJobConfig] {
		t.Errorf("the configuration should have been read; errors: %v", job.Errors)
	}
	if !s.requested("/job/Team%20A/api/json") && !s.requested("/job/Team A/api/json") {
		t.Errorf("the folder was never requested; paths: %v", s.paths)
	}
}

// A multibranch project expands into a child job per branch, generated from
// that branch's Jenkinsfile and identical across branches. Descending would
// produce one copy of every finding per branch.
func TestFetcherTreatsAMultibranchProjectAsOneJob(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"app","fullName":"app","url":"http://x/"}]}`}
	s.handlers["/job/app/api/json"] = standResponse{body: `{"fullName":"app","buildable":true,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"main","fullName":"app/main","url":"http://x/"}]}`}
	s.handlers["/job/app/config.xml"] = standResponse{body: `<?xml version='1.1'?><org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>
		<sources><data><jenkins.branch.BranchSource><source><remote>https://example.invalid/r.git</remote></source></jenkins.branch.BranchSource></data></sources>
		</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}

	snap := fetchFrom(t, s)
	if len(snap.Jobs) != 1 {
		t.Fatalf("jobs = %+v, want the project only", snap.Jobs)
	}
	job := snap.Jobs[0]
	if job.Kind != ci.KindMultibranch {
		t.Errorf("kind = %q", job.Kind)
	}
	// A multibranch project reads a Jenkinsfile from each branch. That is
	// pipeline-as-code by construction.
	if job.Definition.Source != ci.SourceSCM {
		t.Errorf("definition.source = %q, want scm", job.Definition.Source)
	}
	if job.RunsOnBuiltInNodeKnown {
		t.Error("where a pipeline runs is decided in the Jenkinsfile, which is not readable here")
	}
}

func TestFetcherClassifiesDefinitionSources(t *testing.T) {
	tests := []struct {
		name       string
		class      string
		config     string
		wantSource string
		wantSbox   bool
	}{
		{
			name:  "inline with the sandbox on",
			class: classWorkflowJob,
			config: `<?xml version='1.1'?><flow-definition><definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
				<script>echo 1</script><sandbox>true</sandbox></definition></flow-definition>`,
			wantSource: ci.SourceInline, wantSbox: true,
		},
		{
			name:  "inline with the sandbox off",
			class: classWorkflowJob,
			config: `<?xml version='1.1'?><flow-definition><definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition">
				<script>echo 1</script><sandbox>false</sandbox></definition></flow-definition>`,
			wantSource: ci.SourceInline, wantSbox: false,
		},
		{
			name:       "a definition class from a plugin we do not know",
			class:      classWorkflowJob,
			config:     `<?xml version='1.0'?><flow-definition><definition class="com.example.SomeOtherDefinition"/></flow-definition>`,
			wantSource: ci.SourceUnknown,
		},
		{
			name:       "a matrix project is still configuration in a form",
			class:      "hudson.matrix.MatrixProject",
			config:     `<?xml version='1.0'?><matrix-project><canRoam>true</canRoam></matrix-project>`,
			wantSource: ci.SourceUI,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := hardened(t)
			s.handlers["/api/json"] = standResponse{body: fmt.Sprintf(
				`{"useSecurity":true,"numExecutors":0,"jobs":[{"_class":%q,"name":"j","fullName":"j","url":"http://x/"}]}`, tt.class)}
			s.handlers["/job/j/api/json"] = standResponse{body: `{"fullName":"j","buildable":true}`}
			s.handlers["/job/j/config.xml"] = standResponse{body: tt.config}

			snap := fetchFrom(t, s)
			got := snap.Jobs[0].Definition
			if got.Source != tt.wantSource {
				t.Errorf("source = %q, want %q (errors: %v)", got.Source, tt.wantSource, snap.Jobs[0].Errors)
			}
			if tt.wantSource == ci.SourceInline {
				if got.Sandbox != tt.wantSbox || !got.SandboxKnown {
					t.Errorf("sandbox = %v known = %v, want %v", got.Sandbox, got.SandboxKnown, tt.wantSbox)
				}
			}
		})
	}
}

// config.xml returns the remote trigger token in cleartext, and a snapshot is
// written to disk and passed to people who were not there when it was captured.
func TestSnapshotHoldsNoSecrets(t *testing.T) {
	const token = "s3cr3t-trigger-token"
	s := hardened(t)
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version='1.1'?><project>
		<canRoam>true</canRoam><authToken>` + token + `</authToken>
		<builders><hudson.tasks.Shell><command>echo hunter2</command></hudson.tasks.Shell></builders></project>`}
	s.handlers["/credentials/api/json"] = standResponse{body: `{"stores":{"system":{"domains":{"_":{"credentials":[
		{"id":"deploy","typeName":"Username with password","description":"d","displayName":"deployer/****** (d)"}]}}}}}`}

	snap := fetchFrom(t, s)

	if !snap.Jobs[0].RemoteTriggerToken || !snap.Jobs[0].RemoteTriggerTokenKnown {
		t.Error("the presence of a remote trigger token must be recorded")
	}
	encoded, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, "hunter2", "deployer/******"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the snapshot carries %q", secret)
		}
	}
}

// A folder that cannot be listed must not abort the scan, and must not vanish
// without trace either.
func TestFetcherWarnsAboutAnUnreadableFolder(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"secret","fullName":"secret","url":"http://x/"}]}`}
	s.forbidden = []string{"/job/secret"}

	snap := fetchFrom(t, s)
	if len(snap.Jobs) != 0 {
		t.Errorf("jobs = %+v", snap.Jobs)
	}
	found := false
	for _, w := range snap.Metadata.Warnings {
		if strings.Contains(w, "secret") {
			found = true
		}
	}
	if !found {
		t.Errorf("an unreadable folder must be warned about; warnings: %v", snap.Metadata.Warnings)
	}
}
