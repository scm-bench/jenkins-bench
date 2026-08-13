package jenkins

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

// Availability keys. A policy reads these through lib.available, so the names
// are part of the fetcher/policy contract and not an implementation detail.
const (
	AvailRoot        = "root"
	AvailAgents      = "agents"
	AvailPlugins     = "plugins"
	AvailUpdateSite  = "updateSite"
	AvailCredentials = "credentials"

	AvailJobAPI    = "api"
	AvailJobConfig = "config"
)

// Fetcher captures a snapshot of one controller.
type Fetcher struct {
	client *Client
	// Concurrency bounds the per-job fetches. Each job costs two requests, and
	// a controller with a thousand jobs is not unusual.
	Concurrency int
	// ToolVersion is recorded in the snapshot metadata.
	ToolVersion string

	mu       sync.Mutex
	warnings []string
}

// NewFetcher returns a fetcher reading through c.
func NewFetcher(c *Client) *Fetcher {
	return &Fetcher{client: c, Concurrency: 8}
}

func (f *Fetcher) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	f.mu.Lock()
	f.warnings = append(f.warnings, msg)
	f.mu.Unlock()
	f.client.warnf("%s", msg)
}

// Fetch reads the controller and returns a normalized snapshot.
//
// It decides nothing. Every read that fails becomes an availability key set to
// false and an error recorded in plain words, never a zero substituted for
// missing data. A scan with a least-privilege token succeeds and produces a
// snapshot in which most things are unknown, which is the honest result.
func (f *Fetcher) Fetch(ctx context.Context) (*ci.Snapshot, error) {
	snap := &ci.Snapshot{
		SchemaVersion: ci.SchemaVersion,
		Metadata: ci.Metadata{
			Tool:        "jenkins-bench",
			ToolVersion: f.ToolVersion,
			Platform:    ci.PlatformJenkins,
			BaseURL:     f.client.BaseURL(),
			GeneratedAt: time.Now().UTC(),
		},
	}

	controller, err := f.fetchController(ctx)
	if err != nil {
		return nil, err
	}
	snap.Controller = *controller

	jobs, err := f.fetchJobs(ctx, controller)
	if err != nil {
		return nil, err
	}
	snap.Jobs = jobs

	f.mu.Lock()
	snap.Metadata.Warnings = append([]string(nil), f.warnings...)
	f.mu.Unlock()
	return snap, nil
}

func (f *Fetcher) fetchController(ctx context.Context) (*ci.Controller, error) {
	c := &ci.Controller{Available: map[string]bool{}}

	// The version arrives as a response header on any page, including one that
	// needs no credentials, so it is knowable even when everything else is not.
	if headers, err := f.client.Head(ctx, "/login"); err == nil {
		c.Version = headers.Get("X-Jenkins")
	}

	var inst instance
	err := f.client.GetJSON(ctx, "/api/json", &inst)
	c.Available[AvailRoot] = err == nil
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil:
		// Not fatal. A controller that denies the instance API still has a
		// version and can still be probed anonymously, and a snapshot saying
		// "nothing could be read" is a better artefact than an aborted scan.
		c.Errors = append(c.Errors, fmt.Sprintf("the instance API could not be read (%v)", err))
		f.warn("the instance API could not be read; most controller checks will report MANUAL")
	default:
		if inst.UseSecurity != nil {
			c.Security.Enabled, c.Security.EnabledKnown = *inst.UseSecurity, true
		}
		if inst.UseCrumbs != nil {
			c.Security.CSRFProtection, c.Security.CSRFProtectionKnown = *inst.UseCrumbs, true
		}
		if inst.NumExecutors != nil {
			c.BuiltInNode.NumExecutors, c.BuiltInNode.NumExecutorsKnown = *inst.NumExecutors, true
		}
	}

	// Measured, not read. See ProbeAnonymous.
	allowed, conclusive := f.client.ProbeAnonymous(ctx, "/api/json")
	c.Security.AnonymousRead, c.Security.AnonymousReadKnown = allowed, conclusive
	if !conclusive {
		c.Errors = append(c.Errors, "the unauthenticated probe did not reach a conclusion")
	}

	f.fetchNodes(ctx, c)
	f.fetchPlugins(ctx, c)
	f.fetchUpdateSite(ctx, c)
	f.fetchCredentials(ctx, c)
	return c, nil
}

func (f *Fetcher) fetchNodes(ctx context.Context, c *ci.Controller) {
	var nodes computers
	if err := f.client.GetJSON(ctx, "/computer/api/json?depth=1", &nodes); err != nil {
		c.Available[AvailAgents] = false
		c.Errors = append(c.Errors, fmt.Sprintf("the node list could not be read (%v)", err))
		return
	}
	c.Available[AvailAgents] = true
	for _, n := range nodes.Computer {
		if n.Class == builtInComputerClass {
			// Agrees with the root API's numExecutors. Taken here as well
			// because a token that can read /computer but not /api/json still
			// gets an answer.
			if n.NumExecutors != nil && !c.BuiltInNode.NumExecutorsKnown {
				c.BuiltInNode.NumExecutors, c.BuiltInNode.NumExecutorsKnown = *n.NumExecutors, true
			}
			continue
		}
		agent := ci.Agent{
			Name:               n.DisplayName,
			Offline:            n.Offline,
			TemporarilyOffline: n.TemporarilyOffline,
		}
		if n.NumExecutors != nil {
			agent.NumExecutors = *n.NumExecutors
		}
		for _, l := range n.AssignedLabels {
			agent.Labels = append(agent.Labels, l.Name)
		}
		c.Agents = append(c.Agents, agent)
	}
}

func (f *Fetcher) fetchPlugins(ctx context.Context, c *ci.Controller) {
	var pm pluginManager
	if err := f.client.GetJSON(ctx, "/pluginManager/api/json?depth=1", &pm); err != nil {
		c.Available[AvailPlugins] = false
		c.Errors = append(c.Errors, fmt.Sprintf("the plugin list could not be read (%v); Overall/Administer is required", err))
		if IsForbidden(err) {
			f.warn("this token cannot read the plugin list, which needs Overall/Administer; plugin checks will report MANUAL")
		}
		return
	}
	c.Available[AvailPlugins] = true
	for _, p := range pm.Plugins {
		c.Plugins = append(c.Plugins, ci.Plugin{
			ShortName: p.ShortName,
			Version:   p.Version,
			Enabled:   p.Enabled,
			Active:    p.Active,
			HasUpdate: p.HasUpdate,
		})
	}
	sort.Slice(c.Plugins, func(i, j int) bool { return c.Plugins[i].ShortName < c.Plugins[j].ShortName })
}

func (f *Fetcher) fetchUpdateSite(ctx context.Context, c *ci.Controller) {
	var site updateSite
	if err := f.client.GetJSON(ctx, "/updateCenter/site/default/api/json", &site); err != nil {
		c.Available[AvailUpdateSite] = false
		c.Errors = append(c.Errors, fmt.Sprintf("the update site could not be read (%v)", err))
		return
	}
	c.Available[AvailUpdateSite] = true
	c.UpdateSite.URL = site.URL
	if site.DataTimestamp != nil && *site.DataTimestamp > 0 {
		c.UpdateSite.DataTimestamp = time.UnixMilli(*site.DataTimestamp).UTC()
		c.UpdateSite.DataTimestampKnown = true
	}
}

// fetchCredentials reads credential metadata, and works out whether it saw the
// real set.
//
// Availability cannot come from the HTTP status here. Reading credentials
// without permission returns 200 with `{"stores":{}}` — no error, nothing to
// branch on, and a fetcher that recorded `credentials: []` would tell the
// policy layer the controller has none.
//
// So the fetcher earns the answer instead: it believes it saw the real set when
// a store came back, or when the plugin list read succeeded. That second one is
// the useful part — /pluginManager needs Overall/Administer, so a token that
// managed it would have been shown any store that existed, and an empty list is
// then genuinely empty.
func (f *Fetcher) fetchCredentials(ctx context.Context, c *ci.Controller) {
	var root credentialsRoot
	if err := f.client.GetJSON(ctx, "/credentials/api/json?depth=3", &root); err != nil {
		c.Available[AvailCredentials] = false
		c.Errors = append(c.Errors, fmt.Sprintf("credentials could not be read (%v)", err))
		return
	}

	storeNames := make([]string, 0, len(root.Stores))
	for name := range root.Stores {
		storeNames = append(storeNames, name)
	}
	sort.Strings(storeNames)

	for _, storeName := range storeNames {
		store := root.Stores[storeName]
		domainNames := make([]string, 0, len(store.Domains))
		for name := range store.Domains {
			domainNames = append(domainNames, name)
		}
		sort.Strings(domainNames)
		for _, domainName := range domainNames {
			for _, cred := range store.Domains[domainName].Credentials {
				c.Credentials = append(c.Credentials, ci.Credential{
					ID:          cred.ID,
					Type:        cred.TypeName,
					Store:       storeName,
					Domain:      domainName,
					Description: cred.Description,
				})
			}
		}
	}

	sawAStore := len(root.Stores) > 0
	c.Available[AvailCredentials] = sawAStore || c.Available[AvailPlugins]
	if !c.Available[AvailCredentials] {
		c.Errors = append(c.Errors, "no credential store was visible to this token, which is indistinguishable from a controller that has none")
		f.warn("credential stores were not visible to this token; credential checks will report MANUAL")
	}
}

// --- jobs ------------------------------------------------------------------

// jobPath builds the URL for a job's full name.
//
// Every path segment takes its own /job/ prefix and is percent-encoded. A job
// called "Case 01 - Default" inside a folder called "Team A" is an ordinary
// name, and encoding it with form rules — "+" for a space — returns a 404 that
// looks exactly like a job that does not exist.
func jobPath(fullName string) string {
	var b strings.Builder
	for _, seg := range strings.Split(fullName, "/") {
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(seg))
	}
	return b.String()
}

// listJobs walks folders recursively.
//
// A nested tree= expression would do it in one request, but it truncates at
// whatever depth it was written for: a folder one level deeper simply vanishes,
// with no error and nothing in the response to say so. Walking costs a request
// per folder and cannot silently lose a job.
func (f *Fetcher) listJobs(ctx context.Context, prefix string, out *[]item) error {
	var listing jobListing
	path := prefix + "/api/json?tree=jobs[fullName,name,url,_class]"
	if err := f.client.GetJSON(ctx, path, &listing); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f.warn("the job list under %q could not be read (%v); jobs there are missing from this scan", displayPrefix(prefix), err)
		return nil
	}
	for _, it := range listing.Jobs {
		if it.Class == classFolder {
			if err := f.listJobs(ctx, jobPath(it.FullName), out); err != nil {
				return err
			}
			continue
		}
		// A multibranch project is one job. Jenkins expands it into a child job
		// per branch, generated from that branch's Jenkinsfile and identical
		// across branches, so descending would produce one copy of every
		// finding per branch and bury the report.
		*out = append(*out, it)
	}
	return nil
}

func displayPrefix(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return prefix
}

func (f *Fetcher) fetchJobs(ctx context.Context, controller *ci.Controller) ([]ci.Job, error) {
	var items []item
	if err := f.listJobs(ctx, "", &items); err != nil {
		return nil, err
	}

	builtInLabels := builtInNodeLabels(controller)
	jobs := make([]ci.Job, len(items))

	concurrency := f.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var firstErr error
	var errOnce sync.Once

	for i, it := range items {
		wg.Add(1)
		go func(i int, it item) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			job, err := f.fetchJob(ctx, it, controller, builtInLabels)
			if err != nil {
				errOnce.Do(func() { firstErr = err })
				return
			}
			jobs[i] = job
		}(i, it)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].FullName < jobs[j].FullName })
	return jobs, nil
}

func builtInNodeLabels(c *ci.Controller) map[string]bool {
	// "built-in" is the modern label; "master" is what controllers upgraded
	// from an older version still carry, and a job pinned to it runs on the
	// controller just the same.
	return map[string]bool{"built-in": true, "master": true}
}

func (f *Fetcher) fetchJob(ctx context.Context, it item, controller *ci.Controller, builtInLabels map[string]bool) (ci.Job, error) {
	segs := strings.Split(it.FullName, "/")
	job := ci.Job{
		FullName:  it.FullName,
		Name:      segs[len(segs)-1],
		Folder:    strings.Join(segs[:len(segs)-1], "/"),
		URL:       it.URL,
		Class:     it.Class,
		Kind:      kindOf(it.Class),
		Available: map[string]bool{},
	}
	path := jobPath(it.FullName)

	var detail jobDetail
	if err := f.client.GetJSON(ctx, path+"/api/json", &detail); err != nil {
		if ctx.Err() != nil {
			return job, ctx.Err()
		}
		job.Available[AvailJobAPI] = false
		job.Errors = append(job.Errors, fmt.Sprintf("the job API could not be read (%v)", err))
	} else {
		job.Available[AvailJobAPI] = true
		job.Disabled = detail.Disabled
		job.Buildable = detail.Buildable
	}

	body, err := f.client.GetRaw(ctx, path+"/config.xml")
	if err != nil {
		if ctx.Err() != nil {
			return job, ctx.Err()
		}
		job.Available[AvailJobConfig] = false
		job.Errors = append(job.Errors, fmt.Sprintf("the job configuration could not be read (%v); Job/ExtendedRead is required", err))
		return job, nil
	}

	cfg, err := decodeJobConfig(body)
	if err != nil {
		job.Available[AvailJobConfig] = false
		job.Errors = append(job.Errors, fmt.Sprintf("the job configuration could not be parsed (%v)", err))
		return job, nil
	}
	job.Available[AvailJobConfig] = true
	f.applyConfig(&job, cfg, controller, builtInLabels)
	return job, nil
}

// xmlDeclaration matches a leading XML declaration and captures its version.
var xmlDeclaration = regexp.MustCompile(`^(\s*<\?xml\s[^?]*?version\s*=\s*['"])([0-9.]+)(['"])`)

// decodeJobConfig parses a job's config.xml, working around Jenkins writing
// XML 1.1.
//
// Jenkins re-serializes a job's configuration with `<?xml version='1.1'?>`
// whenever it saves one — which is to say, for almost every job on a real
// controller. Go's encoding/xml supports only 1.0 and rejects the document
// outright with "unsupported version", so the fetcher recorded
// available["config"] = false for exactly the jobs that had ever been saved,
// and every job-scope control reported MANUAL against a controller that was
// answering perfectly well. It was found by diffing this fetcher against the
// prototype in hack/recon, which is written in a language whose parser does not
// care.
//
// Only the version in the declaration is rewritten; the encoding is left alone,
// so a document that is genuinely not UTF-8 still fails rather than being
// silently mis-decoded. The two versions differ in which control characters are
// legal in content, so a document that uses one will still fail to parse — as a
// recorded parse error, which is the honest outcome.
func decodeJobConfig(body []byte) (*jobConfig, error) {
	body = xmlDeclaration.ReplaceAll(body, []byte(`${1}1.0${3}`))
	var cfg jobConfig
	if err := xml.Unmarshal(body, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyConfig extracts what the rules need from a job's configuration.
//
// Booleans, counts and class names only. The document it is reading contains
// the remote trigger token in cleartext and a pipeline script that may contain
// anything, and a snapshot is written to disk and passed around.
func (f *Fetcher) applyConfig(job *ci.Job, cfg *jobConfig, controller *ci.Controller, builtInLabels map[string]bool) {
	if cfg.Disabled == "true" {
		job.Disabled = true
	}

	// Presence only.
	job.RemoteTriggerToken = cfg.AuthToken != nil && strings.TrimSpace(*cfg.AuthToken) != ""
	job.RemoteTriggerTokenKnown = true

	job.Definition = definitionFrom(job.Kind, cfg)
	job.Triggers = triggersFrom(cfg)

	// Where a job runs. A pipeline picks its agent in the Jenkinsfile, which
	// the controller does not parse into anything readable, so the answer is
	// unknown rather than false.
	if job.Kind == ci.KindPipeline || job.Kind == ci.KindMultibranch {
		job.RunsOnBuiltInNodeKnown = false
		return
	}
	if !controller.BuiltInNode.NumExecutorsKnown {
		job.RunsOnBuiltInNodeKnown = false
		return
	}
	assigned := strings.TrimSpace(cfg.AssignedNode)
	switch {
	case assigned != "":
		job.RunsOnBuiltInNode = builtInLabels[strings.ToLower(assigned)]
	default:
		// No label restriction: the job runs wherever there is an executor,
		// which includes the controller when it has any.
		job.RunsOnBuiltInNode = cfg.CanRoam == "true" && controller.BuiltInNode.NumExecutors > 0
	}
	job.RunsOnBuiltInNodeKnown = true
}

func definitionFrom(kind string, cfg *jobConfig) ci.Definition {
	// A multibranch project reads a Jenkinsfile from each branch. That is
	// pipeline-as-code by construction, whatever its <definition> says.
	if kind == ci.KindMultibranch {
		def := ci.Definition{Source: ci.SourceSCM}
		for _, bs := range cfg.Sources.Data.BranchSources {
			if bs.Source.Remote != "" {
				def.SCMURLs = append(def.SCMURLs, bs.Source.Remote)
			}
		}
		return def
	}

	if cfg.Definition == nil {
		// No <definition> element and a <project> root: a freestyle or matrix
		// job, whose build steps are configuration clicked into a form.
		if cfg.XMLName.Local == "project" || cfg.XMLName.Local == "matrix-project" {
			return ci.Definition{Source: ci.SourceUI}
		}
		return ci.Definition{Source: ci.SourceUnknown}
	}

	switch cfg.Definition.Class {
	case classCpsScmFlowDefinition:
		def := ci.Definition{Source: ci.SourceSCM, ScriptPath: cfg.Definition.ScriptPath}
		for _, rc := range cfg.Definition.SCM.UserRemoteConfigs.Configs {
			if rc.URL != "" {
				def.SCMURLs = append(def.SCMURLs, rc.URL)
			}
		}
		return def
	case classCpsFlowDefinition:
		def := ci.Definition{Source: ci.SourceInline}
		if cfg.Definition.Sandbox != nil {
			def.Sandbox = strings.TrimSpace(*cfg.Definition.Sandbox) == "true"
			def.SandboxKnown = true
		}
		return def
	default:
		// A definition class from a plugin this fetcher has not been taught
		// about. Distinct from an unreadable configuration, which leaves
		// available["config"] false and no definition at all.
		return ci.Definition{Source: ci.SourceUnknown}
	}
}

// triggersFrom collects trigger types and their schedules.
//
// A freestyle job carries them under <triggers>; a pipeline carries them under
// <properties><...PipelineTriggersJobProperty><triggers>. Both decode into the
// same element here because the struct tag matches on the element name at any
// depth the decoder reaches it.
func triggersFrom(cfg *jobConfig) []ci.Trigger {
	var out []ci.Trigger
	for _, t := range cfg.Triggers.Entries {
		out = append(out, ci.Trigger{
			Type: shortClassName(t.XMLName.Local),
			Spec: strings.TrimSpace(t.Spec),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

// shortClassName turns hudson.triggers.SCMTrigger into SCMTrigger. Reports name
// the trigger, and the package prefix is noise in a table cell.
func shortClassName(s string) string {
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func kindOf(class string) string {
	switch class {
	case classMultibranch:
		return ci.KindMultibranch
	case classWorkflowJob:
		return ci.KindPipeline
	case classFreestyle:
		return ci.KindFreestyle
	default:
		return ci.KindOther
	}
}
