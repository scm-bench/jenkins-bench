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
	// status overrides the 200 a handled path answers with. Zero means 200.
	status int
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

	// A controller stamps its version on every response, refusals included.
	w.Header().Set("X-Jenkins", "2.541.2")
	if _, _, ok := r.BasicAuth(); !ok {
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
	if resp.status != 0 {
		w.WriteHeader(resp.status)
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
		<factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory"><scriptPath>Jenkinsfile</scriptPath></factory>
		</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}

	snap := fetchFrom(t, s)
	if len(snap.Jobs) != 1 {
		t.Fatalf("jobs = %+v, want the project only", snap.Jobs)
	}
	job := snap.Jobs[0]
	if job.Kind != ci.KindMultibranch {
		t.Errorf("kind = %q", job.Kind)
	}
	// The default branch factory reads each branch's own Jenkinsfile.
	if job.Definition.Source != ci.SourceSCM || job.Definition.ScriptPath != "Jenkinsfile" {
		t.Errorf("definition = %+v, want scm from Jenkinsfile", job.Definition)
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

// An operator can give the built-in node any label. A job pinned to that label
// runs on the controller exactly as one pinned to "built-in" does, and
// resolving against a hard-coded pair missed every such job.
func TestFetcherResolvesCustomBuiltInNodeLabels(t *testing.T) {
	s := hardened(t)
	s.handlers["/computer/api/json"] = standResponse{body: `{"computer":[
		{"_class":"hudson.model.Hudson$MasterComputer","displayName":"Built-In Node","offline":false,"numExecutors":2,
		 "assignedLabels":[{"name":"built-in"},{"name":"controller-only"}]}]}`}
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version="1.0"?><project>
		<canRoam>false</canRoam><assignedNode>controller-only</assignedNode></project>`}

	snap := fetchFrom(t, s)
	if got := snap.Controller.BuiltInNode.Labels; len(got) != 2 {
		t.Errorf("built-in node labels = %v, want both recorded", got)
	}
	job := snap.Jobs[0]
	if !job.RunsOnBuiltInNode || !job.RunsOnBuiltInNodeKnown {
		t.Errorf("a job pinned to a custom built-in label runs on the controller: %+v", job)
	}
}

// The pair is always included, because the node list may not have been
// readable — and a job pinned to "master" runs on the controller whether or not
// the fetcher managed to confirm the label exists.
func TestFetcherKnowsTheLegacyMasterLabel(t *testing.T) {
	s := hardened(t)
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version="1.0"?><project>
		<canRoam>false</canRoam><assignedNode>master</assignedNode></project>`}

	snap := fetchFrom(t, s)
	if !snap.Jobs[0].RunsOnBuiltInNode {
		t.Error(`a job pinned to "master" runs on the controller`)
	}
}

// A controller that never answers is not a scan result. Degrading it to "every
// control is MANUAL" produces a report with a clean exit code that reads
// exactly like a healthy least-privilege scan — so the fetch must fail
// instead, and the CLI turns that into exit 2.
func TestFetchFailsWhenTheControllerIsUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens here any more

	client, err := NewClient(Options{BaseURL: url, Username: "u", Token: "t", MaxRetries: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFetcher(client).Fetch(context.Background()); err == nil {
		t.Fatal("a scan that read nothing must fail, not report every control MANUAL")
	}
}

// A 401 on the authenticated instance read means the token was rejected. That
// is operator error, not a permission posture, and carrying on would render
// the mistyped-token report the unreachable-controller test above describes.
func TestFetchFailsWhenTheCredentialsAreRejected(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{status: http.StatusUnauthorized, body: `Invalid password/token`}

	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "wrong"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewFetcher(client).Fetch(context.Background())
	if err == nil {
		t.Fatal("a rejected token must fail the scan")
	}
	if !strings.Contains(err.Error(), "credentials") {
		t.Errorf("the error should say the credentials were rejected: %v", err)
	}
}

// A 200 that is not the Jenkins API — a login page, a proxy's splash screen —
// is a wrong URL, not a readable controller.
func TestFetchFailsWhenTheAnswerIsNotTheAPI(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `<html>welcome to the proxy</html>`}

	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFetcher(client).Fetch(context.Background()); err == nil {
		t.Fatal("a response that does not decode as the instance API must fail the scan")
	}
}

// A 403 is different: the credential was accepted and this part of the API was
// denied, which is the ordinary least-privilege case the rest of the scan is
// built to degrade through. The scan carries on and says so.
func TestFetchDegradesWhenTheInstanceAPIIsDenied(t *testing.T) {
	s := hardened(t)
	s.forbidden = append(s.forbidden, "/api/json")

	snap := fetchFrom(t, s)
	if snap.Controller.Available[AvailRoot] {
		t.Error("a denied instance API must be recorded as unavailable")
	}
	if len(snap.Controller.Errors) == 0 {
		t.Error("a denied instance API should leave an error in the snapshot")
	}
}

// Pipelines keep their triggers under <properties>, not under the root the
// way freestyle jobs do — and encoding/xml matches a tag against direct
// children only, so the two locations need their own paths.
func TestFetcherReadsPipelineTriggers(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"p","fullName":"p","url":"http://x/job/p/"}]}`}
	s.handlers["/job/p/api/json"] = standResponse{body: `{"fullName":"p","disabled":false,"buildable":true}`}
	s.handlers["/job/p/config.xml"] = standResponse{body: `<?xml version='1.1'?>
<flow-definition>
  <properties>
    <org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
      <triggers>
        <hudson.triggers.SCMTrigger><spec>H/15 * * * *</spec></hudson.triggers.SCMTrigger>
      </triggers>
    </org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty>
  </properties>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"><scriptPath>Jenkinsfile</scriptPath></definition>
</flow-definition>`}

	snap := fetchFrom(t, s)
	job := snap.Jobs[0]
	if len(job.Triggers) != 1 || job.Triggers[0].Type != "SCMTrigger" || job.Triggers[0].Spec != "H/15 * * * *" {
		t.Errorf("pipeline triggers = %+v, want the SCMTrigger under <properties>", job.Triggers)
	}
}

// A label expression is not a label. The fetcher does not evaluate
// expressions, and recording false for one would assert that a job which may
// well run on the controller cannot — unknown is the honest answer.
func TestFetcherLeavesLabelExpressionsUnknown(t *testing.T) {
	s := hardened(t)
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version="1.0"?><project>
		<canRoam>false</canRoam><assignedNode>built-in || linux</assignedNode></project>`}

	snap := fetchFrom(t, s)
	job := snap.Jobs[0]
	if job.RunsOnBuiltInNodeKnown {
		t.Errorf("an unevaluated label expression must leave runsOnBuiltInNode unknown, got %+v", job)
	}
}

// An organization folder is a container: its children are the multibranch
// projects. Treating it as a leaf job would drop all of them from the scan.
func TestFetcherWalksIntoOrganizationFolders(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"jenkins.branch.OrganizationFolder","name":"gh-org","fullName":"gh-org","url":"http://x/job/gh-org/"}]}`}
	s.handlers["/job/gh-org/api/json"] = standResponse{body: `{"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"app","fullName":"gh-org/app","url":"http://x/job/gh-org/job/app/"}]}`}
	s.handlers["/job/gh-org/job/app/api/json"] = standResponse{body: `{"fullName":"gh-org/app","disabled":false,"buildable":true}`}
	s.handlers["/job/gh-org/job/app/config.xml"] = standResponse{body: `<?xml version='1.1'?><org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>
		<sources class="jenkins.branch.MultiBranchProject$BranchSourceList"><data>
		<jenkins.branch.BranchSource><source class="org.jenkinsci.plugins.github__branch__source.GitHubSCMSource"><remote>https://github.com/org/app</remote></source></jenkins.branch.BranchSource>
		</data></sources></org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}

	snap := fetchFrom(t, s)
	if len(snap.Jobs) != 1 || snap.Jobs[0].FullName != "gh-org/app" {
		t.Fatalf("jobs = %+v, want the multibranch project inside the organization folder", snap.Jobs)
	}
	if snap.Jobs[0].Kind != ci.KindMultibranch {
		t.Errorf("kind = %q, want multibranch", snap.Jobs[0].Kind)
	}
}

// A folder that cannot be listed takes its jobs out of the scan. The warning
// says so; Unlisted and available["jobs"] are what make the scan exit 2 for it.
func TestFetcherMarksTheJobListIncompleteForAnUnlistableFolder(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"hudson.model.FreeStyleProject","name":"build","fullName":"build","url":"http://x/job/build/"},
		{"_class":"com.cloudbees.hudson.plugins.folder.Folder","name":"prod","fullName":"prod","url":"http://x/job/prod/"}]}`}
	s.handlers["/job/prod/api/json"] = standResponse{status: http.StatusInternalServerError, body: `oops`}

	snap := fetchFrom(t, s)
	if snap.Controller.Available[AvailJobs] {
		t.Error("a folder that could not be listed leaves the job list incomplete")
	}
	if len(snap.Controller.Unlisted) != 1 || snap.Controller.Unlisted[0] != "prod" {
		t.Errorf("unlisted = %v, want [prod]", snap.Controller.Unlisted)
	}
	if len(snap.Jobs) != 1 {
		t.Errorf("the job outside the folder is still scanned: %+v", snap.Jobs)
	}
}

// The top level is a container too, and the one whose loss costs everything.
func TestFetcherNamesTheTopLevelWhenItCannotBeListed(t *testing.T) {
	s := hardened(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/json" && strings.Contains(r.URL.RawQuery, "tree=jobs") {
			w.WriteHeader(http.StatusForbidden)
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
	if len(snap.Controller.Unlisted) != 1 || snap.Controller.Unlisted[0] != rootContainer {
		t.Errorf("unlisted = %v, want the top level", snap.Controller.Unlisted)
	}
}

// A complete walk says so explicitly: a missing key would read as incomplete.
func TestFetcherRecordsACompleteJobList(t *testing.T) {
	snap := fetchFrom(t, hardened(t))
	if !snap.Controller.Available[AvailJobs] || len(snap.Controller.Unlisted) != 0 {
		t.Errorf("available = %v, unlisted = %v", snap.Controller.Available, snap.Controller.Unlisted)
	}
}

// triggerJob serves one pipeline whose PipelineTriggersJobProperty holds the
// given trigger elements.
func triggerJob(t *testing.T, triggers string) ci.Job {
	t.Helper()
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"p","fullName":"p","url":"http://x/job/p/"}]}`}
	s.handlers["/job/p/api/json"] = standResponse{body: `{"disabled":false,"buildable":true}`}
	s.handlers["/job/p/config.xml"] = standResponse{body: `<?xml version='1.1' encoding='UTF-8'?><flow-definition>
		<properties><org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty><triggers>` + triggers + `
		</triggers></org.jenkinsci.plugins.workflow.job.properties.PipelineTriggersJobProperty></properties>
		<definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition"><scriptPath>Jenkinsfile</scriptPath></definition>
		</flow-definition>`}
	return fetchFrom(t, s).Jobs[0]
}

// The shape generic-webhook-trigger 2.4.3 writes, read off a 2.580.1
// controller. Its token starts the build with no Jenkins login, and the
// snapshot must say so without carrying the token.
func TestFetcherRecognisesAGenericWebhookTrigger(t *testing.T) {
	job := triggerJob(t, `<org.jenkinsci.plugins.gwt.GenericTrigger plugin="generic-webhook-trigger@2.4.3">
		<spec></spec><genericVariables/><token>s3cret-gwt</token><silentResponse>false</silentResponse>
		</org.jenkinsci.plugins.gwt.GenericTrigger>`)
	if len(job.UnauthenticatedTriggers) != 1 || job.UnauthenticatedTriggers[0] != "GenericTrigger" {
		t.Errorf("unauthenticatedTriggers = %v, want [GenericTrigger]", job.UnauthenticatedTriggers)
	}
	if !job.TriggersKnown {
		t.Error("a pipeline's triggers are in its own configuration")
	}
	encoded, _ := json.Marshal(job)
	if strings.Contains(string(encoded), "s3cret-gwt") {
		t.Error("the snapshot carries the webhook token")
	}
}

// Without a token a Generic Webhook Trigger is still a way round Job/Build:
// anyone who can read the job starts it (measured: a Job/Read-only account
// did).
func TestFetcherRecognisesATokenlessGenericWebhookTrigger(t *testing.T) {
	job := triggerJob(t, `<org.jenkinsci.plugins.gwt.GenericTrigger><spec></spec></org.jenkinsci.plugins.gwt.GenericTrigger>`)
	if len(job.UnauthenticatedTriggers) != 1 {
		t.Errorf("unauthenticatedTriggers = %v", job.UnauthenticatedTriggers)
	}
}

func TestFetcherAcceptsTriggersThatGoThroughJenkins(t *testing.T) {
	job := triggerJob(t, `<hudson.triggers.SCMTrigger><spec>H/15 * * * *</spec></hudson.triggers.SCMTrigger>
		<hudson.triggers.TimerTrigger><spec>H 2 * * *</spec></hudson.triggers.TimerTrigger>
		<jenkins.triggers.ReverseBuildTrigger><spec></spec><upstreamProjects>a</upstreamProjects></jenkins.triggers.ReverseBuildTrigger>
		<com.cloudbees.jenkins.GitHubPushTrigger plugin="github@1.40"><spec></spec></com.cloudbees.jenkins.GitHubPushTrigger>`)
	if len(job.UnauthenticatedTriggers) != 0 || len(job.UnrecognizedTriggers) != 0 {
		t.Errorf("unauthenticated = %v, unrecognized = %v; all four go through Jenkins", job.UnauthenticatedTriggers, job.UnrecognizedTriggers)
	}
	if len(job.Triggers) != 4 {
		t.Errorf("triggers = %+v", job.Triggers)
	}
}

// A trigger class nobody taught the fetcher is neither safe nor unsafe.
func TestFetcherRecordsTriggersItDoesNotKnow(t *testing.T) {
	job := triggerJob(t, `<com.example.MysteryTrigger><spec></spec></com.example.MysteryTrigger>`)
	if len(job.UnrecognizedTriggers) != 1 || job.UnrecognizedTriggers[0] != "com.example.MysteryTrigger" {
		t.Errorf("unrecognizedTriggers = %v", job.UnrecognizedTriggers)
	}
	if len(job.UnauthenticatedTriggers) != 0 {
		t.Errorf("unauthenticatedTriggers = %v; an unknown class proves nothing", job.UnauthenticatedTriggers)
	}
}

// The core token lives in <authToken>, not among the triggers.
func TestFetcherCountsTheRemoteTriggerTokenAsUnauthenticated(t *testing.T) {
	s := hardened(t)
	s.handlers["/job/build/config.xml"] = standResponse{body: `<?xml version='1.1'?><project>
		<canRoam>true</canRoam><authToken>tok</authToken></project>`}
	job := fetchFrom(t, s).Jobs[0]
	if len(job.UnauthenticatedTriggers) != 1 || job.UnauthenticatedTriggers[0] != "authToken" {
		t.Errorf("unauthenticatedTriggers = %v, want [authToken]", job.UnauthenticatedTriggers)
	}
	if !job.TriggersKnown {
		t.Error("a freestyle job's triggers are in its own configuration")
	}
}

// What starts a multibranch project's builds is declared in each branch's
// Jenkinsfile and lands in the branch jobs, which the fetcher does not read.
func TestFetcherDoesNotKnowAMultibranchProjectsTriggers(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"mb","fullName":"mb","url":"http://x/"}]}`}
	s.handlers["/job/mb/api/json"] = standResponse{body: `{"buildable":true}`}
	s.handlers["/job/mb/config.xml"] = standResponse{body: `<?xml version='1.1'?><org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>
		<triggers><com.cloudbees.hudson.plugins.folder.computed.PeriodicFolderTrigger><spec>H * * * *</spec><interval>3600000</interval></com.cloudbees.hudson.plugins.folder.computed.PeriodicFolderTrigger></triggers>
		</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}
	job := fetchFrom(t, s).Jobs[0]
	if job.TriggersKnown {
		t.Error("a multibranch project's build triggers are in its branch jobs, which were not read")
	}
	if len(job.UnrecognizedTriggers) != 0 {
		t.Errorf("the re-scan schedule is a known trigger: %v", job.UnrecognizedTriggers)
	}
}

// multibranchDefinitionFor fetches one multibranch project whose branch jobs
// come from the given <factory> element.
func multibranchDefinitionFor(t *testing.T, factory string) ci.Definition {
	t.Helper()
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"mb","fullName":"mb","url":"http://x/"}]}`}
	s.handlers["/job/mb/api/json"] = standResponse{body: `{"buildable":true}`}
	s.handlers["/job/mb/config.xml"] = standResponse{body: `<?xml version="1.1" encoding="UTF-8"?>
<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject plugin="workflow-multibranch@842.v3a_b_59b_57b_e6e">
  <triggers/>
  <disabled>false</disabled>
  <sources class="jenkins.branch.MultiBranchProject$BranchSourceList" plugin="branch-api@2.1303.v9f3b_95dc329d">
    <data><jenkins.branch.BranchSource><source class="jenkins.plugins.git.GitSCMSource" plugin="git@5.10.1">
      <id>seed</id><remote>/var/jenkins_home/seed-repo</remote>
    </source></jenkins.branch.BranchSource></data>
  </sources>
  ` + factory + `
</org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}
	snap := fetchFrom(t, s)
	encoded, _ := json.Marshal(snap)
	if strings.Contains(string(encoded), "planted") {
		t.Errorf("a factory's script reached the snapshot: %s", encoded)
	}
	return snap.Jobs[0].Definition
}

// The three factories a 2.580.1 controller wrote for the e2e fixture, verbatim
// apart from the script. v0.1 called all of them "scm".
func TestFetcherDecidesAMultibranchProjectByItsFactory(t *testing.T) {
	inline := multibranchDefinitionFor(t, `<factory class="org.jenkinsci.plugins.inlinepipeline.InlineDefinitionBranchProjectFactory" plugin="inline-pipeline@1.0.32.vf433f2d57630">
    <owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/>
    <script>node { echo &apos;planted&apos; }</script>
    <sandbox>false</sandbox>
    <markerFile>Jenkinsfile</markerFile>
  </factory>`)
	if inline.Source != ci.SourceInline || inline.Sandbox || !inline.SandboxKnown {
		t.Errorf("inline-pipeline factory: %+v, want inline with the sandbox known to be off", inline)
	}
	if inline.Class != classInlineBranchProjectFactory {
		t.Errorf("class = %q, want the factory's", inline.Class)
	}

	defaults := multibranchDefinitionFor(t, `<factory class="org.jenkinsci.plugins.pipeline.multibranch.defaults.PipelineBranchDefaultsProjectFactory" plugin="pipeline-multibranch-defaults@2.1">
    <owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/>
    <scriptId>e2e-default-jenkinsfile</scriptId>
    <useSandbox>true</useSandbox>
  </factory>`)
	if defaults.Source != ci.SourceInline || !defaults.Sandbox || !defaults.SandboxKnown {
		t.Errorf("defaults factory: %+v, want inline with the sandbox known to be on", defaults)
	}

	standard := multibranchDefinitionFor(t, `<factory class="org.jenkinsci.plugins.workflow.multibranch.WorkflowBranchProjectFactory">
    <owner class="org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject" reference="../.."/>
    <scriptPath>ci/Jenkinsfile</scriptPath>
  </factory>`)
	if standard.Source != ci.SourceSCM || standard.ScriptPath != "ci/Jenkinsfile" || len(standard.SCMURLs) != 1 {
		t.Errorf("default factory: %+v, want scm from ci/Jenkinsfile", standard)
	}
}

// A factory nobody taught the fetcher is unknown — not assumed to be the
// default, which is how every multibranch project passed in v0.1. No factory
// at all is the same answer.
func TestFetcherLeavesAnUnknownFactoryUnknown(t *testing.T) {
	if def := multibranchDefinitionFor(t, `<factory class="com.example.RemoteJenkinsfileFactory"/>`); def.Source != ci.SourceUnknown || def.Class != "com.example.RemoteJenkinsfileFactory" {
		t.Errorf("definition = %+v, want unknown naming the factory", def)
	}
	if def := multibranchDefinitionFor(t, ``); def.Source != ci.SourceUnknown {
		t.Errorf("definition = %+v, want unknown without a factory", def)
	}
}

// A branch job scanned on its own carries the definition its factory gave it:
// SCMBinder for the default, and the inline and defaults plugins' own.
func TestFetcherReadsBranchJobDefinitions(t *testing.T) {
	cases := map[string]struct {
		config  string
		source  string
		sandbox bool
		known   bool
	}{
		"scm binder": {`<definition class="org.jenkinsci.plugins.workflow.multibranch.SCMBinder"><scriptPath>Jenkinsfile</scriptPath></definition>`, ci.SourceSCM, false, false},
		"inline":     {`<definition class="org.jenkinsci.plugins.inlinepipeline.InlineFlowDefinition"><script>x</script><sandbox>false</sandbox></definition>`, ci.SourceInline, false, true},
		"defaults":   {`<definition class="org.jenkinsci.plugins.pipeline.multibranch.defaults.DefaultsBinder"><scriptId>f</scriptId><useSandbox>true</useSandbox></definition>`, ci.SourceInline, true, true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := hardened(t)
			s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
				{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"b","fullName":"b","url":"http://x/"}]}`}
			s.handlers["/job/b/api/json"] = standResponse{body: `{"buildable":true}`}
			s.handlers["/job/b/config.xml"] = standResponse{body: `<?xml version="1.1"?><flow-definition>` + tc.config + `</flow-definition>`}
			def := fetchFrom(t, s).Jobs[0].Definition
			if def.Source != tc.source || def.Sandbox != tc.sandbox || def.SandboxKnown != tc.known {
				t.Errorf("definition = %+v", def)
			}
		})
	}
}

// An SCM URL can carry a credential — https://deploy:<token>@host/… is how a
// great many Jenkinsfiles were first wired up — and v0.1 copied remotes into
// the snapshot verbatim. The README promised a snapshot safe to attach to a
// bug report. Every URL the snapshot keeps is stripped of userinfo, query and
// fragment, wherever it came from.
func TestSnapshotHoldsNoCredentialsFromURLs(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"p","fullName":"p","url":"https://jenkins:urlpass-in-job-url@jenkins.example.com/job/p/"},
		{"_class":"org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject","name":"mb","fullName":"mb","url":"http://x/job/mb/"},
		{"_class":"org.jenkinsci.plugins.workflow.job.WorkflowJob","name":"scp","fullName":"scp","url":"http://x/job/scp/"}]}`}
	s.handlers["/job/p/api/json"] = standResponse{body: `{"disabled":false}`}
	s.handlers["/job/mb/api/json"] = standResponse{body: `{}`}
	s.handlers["/job/scp/api/json"] = standResponse{body: `{}`}
	s.handlers["/job/p/config.xml"] = standResponse{body: `<flow-definition><definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition">
		<scm class="hudson.plugins.git.GitSCM"><userRemoteConfigs><hudson.plugins.git.UserRemoteConfig>
		<url>https://deploy:ghp_PLANTEDTOKEN1@github.com/acme/app.git?access_token=PLANTEDQUERY#PLANTEDFRAG</url>
		</hudson.plugins.git.UserRemoteConfig></userRemoteConfigs></scm><scriptPath>Jenkinsfile</scriptPath></definition></flow-definition>`}
	s.handlers["/job/mb/config.xml"] = standResponse{body: `<org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject><sources><data><jenkins.branch.BranchSource>
		<source class="jenkins.plugins.git.GitSCMSource"><remote>https://bot:glpat-PLANTEDTOKEN2@gitlab.example.com/a/b.git</remote></source>
		</jenkins.branch.BranchSource></data></sources></org.jenkinsci.plugins.workflow.multibranch.WorkflowMultiBranchProject>`}
	s.handlers["/job/scp/config.xml"] = standResponse{body: `<flow-definition><definition class="org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition">
		<scm class="hudson.plugins.git.GitSCM"><userRemoteConfigs><hudson.plugins.git.UserRemoteConfig>
		<url>deploy:PLANTEDTOKEN3@git.example.com:acme/app.git</url>
		</hudson.plugins.git.UserRemoteConfig></userRemoteConfigs></scm></definition></flow-definition>`}
	s.handlers["/updateCenter/site/default/api/json"] = standResponse{body: `{"url":"https://mirror:PLANTEDTOKEN4@updates.example.com/update-center.json","dataTimestamp":1786650950902}`}

	snap := fetchFrom(t, s)
	encoded, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"urlpass-in-job-url", "PLANTEDTOKEN1", "PLANTEDQUERY", "PLANTEDFRAG", "PLANTEDTOKEN2", "PLANTEDTOKEN3", "PLANTEDTOKEN4", "deploy:", "bot:"} {
		if strings.Contains(string(encoded), secret) {
			t.Errorf("the snapshot carries %q", secret)
		}
	}
	// Where the definition comes from is still worth knowing.
	if !strings.Contains(string(encoded), "https://github.com/acme/app.git") ||
		!strings.Contains(string(encoded), "https://gitlab.example.com/a/b.git") ||
		!strings.Contains(string(encoded), "git.example.com:acme/app.git") {
		t.Errorf("the remotes should survive without their credentials: %s", encoded)
	}
}

// The version comes from the instance API's own response — a 403 carries it
// too — and no longer from an authenticated GET of /login made first: the
// page an SSO realm redirects, and so the likeliest request to meet an https
// to http bounce with the token attached.
func TestFetcherReadsTheVersionWithoutVisitingTheLoginPage(t *testing.T) {
	s := hardened(t)
	s.forbidden = []string{"/api/json"}
	snap := fetchFrom(t, s)
	if snap.Controller.Version != "2.541.2" {
		t.Errorf("version = %q, want it read off the refusal", snap.Controller.Version)
	}
	if s.requested("/login") {
		t.Error("the fetcher requested /login")
	}
}

// Every API request names its fields. Without tree=, the root API renders a
// colour per job, a job's API up to a hundred builds and every last*Build, and
// the node list each label's tiedJobs — on a large controller, the timeouts
// and the response cap, for nothing any control reads. The credentials
// endpoint is the one exception: a tree= over its map-valued stores returns
// no credentials at any depth (docs/jenkins-api-notes.md), so it takes depth=3.
func TestFetcherAsksOnlyForTheFieldsItReads(t *testing.T) {
	s := hardened(t)
	fetchFrom(t, s)
	for _, p := range s.paths {
		switch {
		case strings.HasSuffix(p, "/config.xml"):
		case p == "/credentials/api/json?depth=3":
		case strings.Contains(p, "/api/json?tree="):
		default:
			t.Errorf("GET %s names no fields", p)
		}
	}
	// A job's own API is no longer requested at all: the listing that found
	// it already carried disabled and buildable.
	if s.requested("/job/build/api/json") {
		t.Error("the per-job API was requested; the listing carries what it was read for")
	}
}

// Whether a job is disabled now comes from the listing that found it.
func TestFetcherTakesDisabledFromTheListing(t *testing.T) {
	s := hardened(t)
	s.handlers["/api/json"] = standResponse{body: `{"useSecurity":true,"numExecutors":0,"jobs":[
		{"_class":"hudson.model.FreeStyleProject","name":"build","fullName":"build","url":"http://x/","disabled":true,"buildable":false}]}`}
	job := fetchFrom(t, s).Jobs[0]
	if !job.Disabled || job.Buildable || !job.Available[AvailJobAPI] {
		t.Errorf("job = %+v, want disabled, not buildable, from the listing", job)
	}
}
