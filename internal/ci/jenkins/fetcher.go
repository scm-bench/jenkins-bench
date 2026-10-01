package jenkins

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

// deniedNotBroken reports whether err is the controller answering "you may not
// read this" — the case the whole scan is built to degrade through — as
// opposed to the scan not getting an answer it could reason about. 404 and 405
// count as denials because what a controller means by them is not reliably
// different from 403: an absent plugin and an unreadable store both answer
// 404.
func deniedNotBroken(err error) bool {
	switch Status(err) {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusMethodNotAllowed:
		return true
	}
	return false
}

// Availability keys. A policy reads these through lib.available, so the names
// are part of the fetcher/policy contract and not an implementation detail.
const (
	AvailRoot        = "root"
	AvailAgents      = "agents"
	AvailPlugins     = "plugins"
	AvailUpdateSite  = "updateSite"
	AvailCredentials = "credentials"

	// AvailJobs is true when every container in the job tree was listed. It
	// lives on the controller because what it qualifies is the job list as a
	// whole: a folder that could not be listed takes its jobs out of the scan
	// without leaving a job behind to carry the error.
	AvailJobs = "jobs"

	AvailJobAPI    = "api"
	AvailJobConfig = "config"
)

// rootContainer names the top level in Controller.Unlisted. A job's full name
// never starts with a slash, so it cannot collide with a folder.
const rootContainer = "/"

// Fetcher captures a snapshot of one controller.
type Fetcher struct {
	client *Client
	// Concurrency bounds the per-job fetches. Each job costs two requests, and
	// a controller with a thousand jobs is not unusual.
	Concurrency int
	// ToolVersion is recorded in the snapshot metadata.
	ToolVersion string
	// Progress, when set, is told after each job is read how many of how
	// many are done. Called from the fetch goroutines.
	Progress func(done, total int)

	mu       sync.Mutex
	warnings []string
	// unlisted collects the containers whose listing failed, for
	// Controller.Unlisted.
	unlisted []string
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

// Fetch reads the controller and returns a normalized snapshot. It decides
// nothing: a failed read becomes available[key]=false plus an error in plain
// words, never a zero standing in for missing data.
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

	jobs, err := f.fetchJobs(ctx, controller)
	if err != nil {
		return nil, err
	}
	// After the jobs, not before: listing them is what decides whether the
	// job list is complete, and that is recorded on the controller.
	snap.Controller = *controller
	snap.Jobs = jobs

	f.mu.Lock()
	snap.Metadata.Warnings = append([]string(nil), f.warnings...)
	f.mu.Unlock()
	return snap, nil
}

func (f *Fetcher) fetchController(ctx context.Context) (*ci.Controller, error) {
	c := &ci.Controller{Available: map[string]bool{}}

	var inst instance
	headers, err := f.client.GetJSONHeaders(ctx, "/api/json?tree="+instanceTree, &inst)
	c.Available[AvailRoot] = err == nil
	// The version arrives as a response header on every response, a refusal
	// included, so it is knowable even when nothing else is. It used to come
	// from a GET of /login made first, with credentials attached — the page an
	// SSO realm redirects, and the request most likely to meet an https to
	// http bounce. One request fewer, and that one gone.
	if headers != nil {
		c.Version = headers.Get("X-Jenkins")
	}
	switch {
	case err != nil && ctx.Err() != nil:
		return nil, ctx.Err()
	case err != nil && f.client.HasCredentials() && Status(err) == http.StatusUnauthorized:
		// A 401 on the authenticated read means the token itself was rejected.
		// Without this, a mistyped token produces a complete-looking report —
		// every control MANUAL, score 0, exit 0 — which is indistinguishable
		// from a real result unless the reader notices that *everything* is
		// MANUAL. The worst possible output for an audit tool, so it fails
		// instead.
		return nil, fmt.Errorf("the controller rejected the credentials: %w\n"+
			"check --username/--token (JENKINS_USER/JENKINS_TOKEN); use an API token, not a password", err)
	case err != nil && !deniedNotBroken(err):
		// No answer at all — connection refused, DNS, TLS, a 5xx that survived
		// the retries, or a response that is not the Jenkins API. A permission
		// denial degrades to MANUAL below because a scan can still say
		// something; a scan that got nothing to reason about must fail rather
		// than render a clean-looking report of MANUALs and exit 0.
		return nil, fmt.Errorf("the controller could not be read: %w", err)
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
		if inst.Mode != nil && *inst.Mode != "" {
			c.BuiltInNode.Mode, c.BuiltInNode.ModeKnown = *inst.Mode, true
		}
		if inst.AssignedLabels != nil {
			for _, l := range *inst.AssignedLabels {
				addLabel(&c.BuiltInNode, l.Name)
			}
			c.BuiltInNode.LabelsKnown = true
		}
	}

	// Measured, not read. See ProbeAnonymous.
	probe := f.client.ProbeAnonymous(ctx, "/api/json?tree=useSecurity")
	c.Security.AnonymousRead, c.Security.AnonymousReadKnown = probe.Allowed, probe.Conclusive
	if !probe.Conclusive {
		c.Errors = append(c.Errors, "the unauthenticated probe did not reach a conclusion: "+probe.Reason)
		f.warn("whether anonymous users can read the controller is unknown: %s", probe.Reason)
	}

	f.fetchNodes(ctx, c)
	f.fetchPlugins(ctx, c)
	f.fetchUpdateSite(ctx, c)
	f.fetchCredentials(ctx, c)
	return c, nil
}

func (f *Fetcher) fetchNodes(ctx context.Context, c *ci.Controller) {
	var nodes computers
	if err := f.client.GetJSON(ctx, "/computer/api/json?tree="+computerTree, &nodes); err != nil {
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
			for _, l := range n.AssignedLabels {
				addLabel(&c.BuiltInNode, l.Name)
			}
			c.BuiltInNode.LabelsKnown = true
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
	if err := f.client.GetJSON(ctx, "/pluginManager/api/json?tree="+pluginTree, &pm); err != nil {
		c.Available[AvailPlugins] = false
		c.Errors = append(c.Errors, fmt.Sprintf("the plugin list could not be read (%v); it needs Overall/SystemRead, which Overall/Administer implies", err))
		if IsForbidden(err) {
			f.warn("this token cannot read the plugin list, which needs Overall/SystemRead or Overall/Administer; plugin checks will report MANUAL")
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
	if err := f.client.GetJSON(ctx, "/updateCenter/site/default/api/json?tree=url,dataTimestamp", &site); err != nil {
		c.Available[AvailUpdateSite] = false
		c.Errors = append(c.Errors, fmt.Sprintf("the update site could not be read (%v)", err))
		return
	}
	c.Available[AvailUpdateSite] = true
	c.UpdateSite.URL = stripCredentials(site.URL)
	if site.DataTimestamp != nil && *site.DataTimestamp > 0 {
		c.UpdateSite.DataTimestamp = time.UnixMilli(*site.DataTimestamp).UTC()
		c.UpdateSite.DataTimestampKnown = true
	}
}

// fetchCredentials reads credential metadata from the controller's own stores.
// Folder stores are not read.
//
// Availability cannot come from the HTTP status: an unauthorised read returns
// 200 with {"stores":{}}. It is earned from the body instead — at least one
// store came back, and every domain in it carried its credentials list. v0.1
// also took a readable plugin list as proof, on the belief that it needs
// Overall/Administer; it needs only Overall/SystemRead, and an account holding
// that was shown {"stores":{}} by a 2.580.1 controller with two credentials.
func (f *Fetcher) fetchCredentials(ctx context.Context, c *ci.Controller) {
	var root credentialsRoot
	if err := f.client.GetJSON(ctx, "/credentials/api/json?depth=3", &root); err != nil {
		c.Available[AvailCredentials] = false
		c.Errors = append(c.Errors, fmt.Sprintf("credentials could not be read (%v)", err))
		return
	}

	complete := true
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
			listed := store.Domains[domainName].Credentials
			if listed == nil {
				complete = false
				continue
			}
			for _, cred := range *listed {
				if cred.ID == "" {
					// depth=2's failure mode: the right number of
					// elements, every one of them empty.
					complete = false
					continue
				}
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

	c.Available[AvailCredentials] = len(root.Stores) > 0 && complete
	switch {
	case len(root.Stores) == 0:
		c.Errors = append(c.Errors, "no credential store was visible to this token, which is indistinguishable from a controller that has none")
		f.warn("credential stores were not visible to this token; credential checks will report MANUAL")
	case !complete:
		c.Errors = append(c.Errors, "a credential store came back without its credentials listed, so the set read is not the whole of it")
	}
}

// --- jobs ------------------------------------------------------------------

// jobPath builds the URL for a job's full name: each segment gets its own
// /job/ prefix, percent-encoded. Form-encoding a space as "+" returns a 404
// indistinguishable from a missing job.
func jobPath(fullName string) string {
	var b strings.Builder
	for _, seg := range strings.Split(fullName, "/") {
		b.WriteString("/job/")
		b.WriteString(url.PathEscape(seg))
	}
	return b.String()
}

// maxFolderDepth is how deep the walk follows folders. Jenkins puts no limit
// on nesting, and no controller in use comes near this; a tree that does is
// something answering on the controller's behalf.
const maxFolderDepth = 64

// listJobs walks folders recursively. A nested tree= expression truncates at
// whatever depth it was written for, silently losing deeper folders.
//
// container is the folder's full name, "" for the top level; depth is how many
// folders deep it is.
func (f *Fetcher) listJobs(ctx context.Context, container string, depth int, out *[]item) error {
	var listing jobListing
	prefix := ""
	if container != "" {
		prefix = jobPath(container)
	}
	path := prefix + "/api/json?tree=" + listingTree
	if err := f.client.GetJSON(ctx, path, &listing); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Not fatal — the rest of the tree is still worth auditing — but not
		// a footnote either. The jobs in here are not failing or passing,
		// they are absent, and a scan that cannot say how many is
		// incomplete: Controller.Unlisted carries the name to the exit code.
		// A token Jenkins filters the folder's contents for gets a 200 with
		// fewer jobs, not an error, and lands nowhere near here.
		f.unlist(container, "the job list of %s could not be read (%v); the jobs in it are missing from this scan", describeContainer(container), err)
		return nil
	}

	// Jenkins lists an item only inside the folder that holds it, so its
	// full name is the folder's plus one segment. A listing that breaks that
	// is not this folder's — a proxy answering every URL with the same page
	// made the walk recurse until the deadline, 35,933 requests in two
	// seconds against the audit's stand-in — and none of it is trusted.
	for _, it := range listing.Jobs {
		if !childOf(container, it.FullName) {
			f.unlist(container, "the job list of %s holds %q, which is not inside it, so it is not that folder's list — "+
				"something other than the controller may be answering; the jobs in it are missing from this scan",
				describeContainer(container), it.FullName)
			return nil
		}
	}

	for _, it := range listing.Jobs {
		if isContainer(it) {
			if depth+1 > maxFolderDepth {
				f.unlist(it.FullName, "%s is nested more than %d folders deep, past which the walk stops; the jobs in it are missing from this scan",
					describeContainer(it.FullName), maxFolderDepth)
				continue
			}
			if err := f.listJobs(ctx, it.FullName, depth+1, out); err != nil {
				return err
			}
			continue
		}
		// A multibranch project is one job: descending into its generated
		// per-branch children would repeat every finding per branch.
		*out = append(*out, it)
	}
	return nil
}

// childOf reports whether fullName is an item directly inside container.
func childOf(container, fullName string) bool {
	if fullName == "" {
		return false
	}
	rest := fullName
	if container != "" {
		var ok bool
		if rest, ok = strings.CutPrefix(fullName, container+"/"); !ok {
			return false
		}
	}
	return rest != "" && !strings.Contains(rest, "/")
}

// unlist records a container whose jobs the scan could not list, and warns.
func (f *Fetcher) unlist(container, format string, args ...any) {
	name := container
	if name == "" {
		name = rootContainer
	}
	f.mu.Lock()
	f.unlisted = append(f.unlisted, name)
	f.mu.Unlock()
	f.warn(format, args...)
}

// describeContainer names a container in a sentence.
func describeContainer(container string) string {
	if container == "" {
		return "the top level"
	}
	return fmt.Sprintf("folder %q", container)
}

func (f *Fetcher) fetchJobs(ctx context.Context, controller *ci.Controller) ([]ci.Job, error) {
	var items []item
	if err := f.listJobs(ctx, "", 0, &items); err != nil {
		return nil, err
	}
	f.mu.Lock()
	controller.Unlisted = append([]string(nil), f.unlisted...)
	f.mu.Unlock()
	controller.Available[AvailJobs] = len(controller.Unlisted) == 0

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
	var done atomic.Int64

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
			if f.Progress != nil {
				f.Progress(int(done.Add(1)), len(items))
			}
		}(i, it)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].FullName < jobs[j].FullName })
	return jobs, nil
}

// addLabel records one of the built-in node's labels once, whichever of the
// two endpoints that carry them reported it.
func addLabel(n *ci.BuiltInNode, name string) {
	for _, existing := range n.Labels {
		if existing == name {
			return
		}
	}
	n.Labels = append(n.Labels, name)
}

// builtInNodeLabels is every label that means "the controller": the well-known
// pair (the node list may not have been readable) plus whatever the built-in
// node actually reported — an operator can name it anything.
func builtInNodeLabels(c *ci.Controller) map[string]bool {
	labels := map[string]bool{"built-in": true, "master": true}
	for _, l := range c.BuiltInNode.Labels {
		labels[strings.ToLower(l)] = true
	}
	return labels
}

func (f *Fetcher) fetchJob(ctx context.Context, it item, controller *ci.Controller, builtInLabels map[string]bool) (ci.Job, error) {
	segs := strings.Split(it.FullName, "/")
	job := ci.Job{
		FullName:  it.FullName,
		Name:      segs[len(segs)-1],
		Folder:    strings.Join(segs[:len(segs)-1], "/"),
		URL:       stripCredentials(it.URL),
		Class:     it.Class,
		Kind:      kindOf(it.Class),
		Available: map[string]bool{},
	}
	path := jobPath(it.FullName)

	// What a Job/Read token can see of a job — whether it is disabled, and
	// buildable — came from the listing that found it. It used to cost a
	// request per job of its own, to /job/<path>/api/json with no tree=,
	// which renders up to a hundred builds, the health report and every
	// last*Build for each job: on a large controller, the bulk of a scan's
	// load for two booleans.
	job.Available[AvailJobAPI] = true
	job.Disabled = it.Disabled
	job.Buildable = it.Buildable

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
	// A proxy's sign-in or error page, served at the config.xml URL with a
	// 200, can be well-formed XHTML. v0.1 parsed one as a job whose root
	// happened to be <html> — available, no token in it, CIS-2.3.5 PASS.
	root := cfg.XMLName.Local
	if strings.EqualFold(root, "html") || cfg.XMLName.Space == "http://www.w3.org/1999/xhtml" {
		job.Available[AvailJobConfig] = false
		job.Errors = append(job.Errors, "the configuration request was answered with an HTML page, not a job configuration — "+
			"most likely a sign-in or error page from something in front of the controller")
		return job, nil
	}
	job.Available[AvailJobConfig] = true
	doc, known := jobDocuments[root]
	if known {
		scripts, err := findScripts(body)
		if err != nil {
			// The document decoded a moment ago, so this does not happen;
			// if it ever does, the scripts are unknown, not absent.
			job.Available[AvailJobConfig] = false
			job.Errors = append(job.Errors, fmt.Sprintf("the job configuration could not be scanned for scripts (%v)", err))
			return job, nil
		}
		job.Scripts = scripts
	}
	if !known {
		// A job type nobody taught this fetcher: what defines it, what
		// triggers it and where it runs could be anywhere in the document,
		// so none of it is taken as known, and the controls say so.
		if cfg.Disabled == "true" {
			job.Disabled = true
		}
		job.Definition = ci.Definition{Source: ci.SourceUnknown, Class: root}
		return job, nil
	}
	f.applyConfig(&job, cfg, doc, controller, builtInLabels)
	return job, nil
}

// xmlDeclaration matches a leading XML declaration and captures its version.
var xmlDeclaration = regexp.MustCompile(`^(\s*<\?xml\s[^?]*?version\s*=\s*['"])([0-9.]+)(['"])`)

// controlCharRef matches a numeric character reference, decimal or hex.
var controlCharRef = regexp.MustCompile(`&#(x[0-9a-fA-F]+|[0-9]+);`)

// utf8BOM is the byte-order mark some editors and proxies put in front.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// decodeJobConfig parses a job's config.xml.
//
// Go's encoding/xml reads XML 1.0, and Jenkins writes 1.1 whenever it saves a
// job, so three things are smoothed over first — each of which used to turn a
// readable job into a MANUAL one:
//
//   - the 1.1 declaration is rewritten to 1.0, after a byte-order mark is
//     dropped (one in front hid the declaration from the rewrite);
//   - character references to C0 control characters, legal in 1.1 and how
//     XStream writes an ANSI escape in a description, become U+FFFD — no
//     field this fetcher reads can hold one meaningfully;
//   - an ISO-8859-1 or US-ASCII declaration is decoded rather than refused.
//
// Anything else 1.1 permits and 1.0 does not still fails, as a recorded parse
// error rather than a guess.
func decodeJobConfig(body []byte) (*jobConfig, error) {
	var cfg jobConfig
	if err := newConfigDecoder(prepareConfigXML(body)).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// prepareConfigXML smooths a config.xml over for encoding/xml; see
// decodeJobConfig.
func prepareConfigXML(body []byte) []byte {
	body = bytes.TrimPrefix(body, utf8BOM)
	body = xmlDeclaration.ReplaceAll(body, []byte(`${1}1.0${3}`))
	return controlCharRef.ReplaceAllFunc(body, func(ref []byte) []byte {
		digits := string(ref[2 : len(ref)-1])
		base := 10
		if digits[0] == 'x' {
			digits, base = digits[1:], 16
		}
		n, err := strconv.ParseUint(digits, base, 32)
		if err != nil || n == 0 || n > 0x1F || n == '\t' || n == '\n' || n == '\r' {
			return ref
		}
		return []byte("&#xFFFD;")
	})
}

// newConfigDecoder reads a prepared config.xml.
func newConfigDecoder(body []byte) *xml.Decoder {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	decoder.CharsetReader = charsetReader
	return decoder
}

// charsetReader decodes the single-byte encodings a config.xml declaration
// has been seen to name. Every byte of ISO-8859-1 is the code point of the
// same number, so the conversion is a loop; US-ASCII is its subset.
func charsetReader(charset string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "utf-8", "utf8":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "us-ascii", "ascii":
		raw, err := io.ReadAll(input)
		if err != nil {
			return nil, err
		}
		var b strings.Builder
		b.Grow(len(raw))
		for _, c := range raw {
			b.WriteRune(rune(c))
		}
		return strings.NewReader(b.String()), nil
	}
	return nil, fmt.Errorf("the configuration declares encoding %q, which this scan does not decode", charset)
}

// applyConfig extracts booleans, counts and class names — nothing else. The
// document holds the trigger token in cleartext, and snapshots are written to
// disk and passed around.
func (f *Fetcher) applyConfig(job *ci.Job, cfg *jobConfig, doc jobDocument, controller *ci.Controller, builtInLabels map[string]bool) {
	if cfg.Disabled == "true" {
		job.Disabled = true
	}

	// Presence only.
	job.RemoteTriggerToken = cfg.AuthToken != nil && strings.TrimSpace(*cfg.AuthToken) != ""
	job.RemoteTriggerTokenKnown = doc.project

	job.Definition = definitionFrom(doc, cfg)
	job.Triggers = triggersFrom(cfg)

	var classes []string
	for _, entries := range [][]configTrigger{cfg.Triggers.Entries, cfg.PipelineTriggers.Entries} {
		for _, t := range entries {
			classes = append(classes, t.XMLName.Local)
		}
	}
	assessed := assessTriggers(job.RemoteTriggerToken, classes)
	job.UnauthenticatedTriggers = assessed.unauthenticated
	job.UnrecognizedTriggers = assessed.unrecognized
	// A multibranch project's own <triggers> are its re-scan schedule. What
	// starts its builds is declared in each branch's Jenkinsfile and lands in
	// the generated branch jobs, which the scan does not descend into — so
	// the answer is unknown, whatever the project itself says.
	job.TriggersKnown = doc.project

	// Where a job runs. A pipeline picks its agent in the Jenkinsfile, which
	// the controller does not parse into anything readable, so the answer is
	// unknown rather than false; only the project types say it here.
	if !doc.ui {
		job.RunsOnBuiltInNodeKnown = false
		return
	}
	job.RunsOnBuiltInNode, job.RunsOnBuiltInNodeKnown = placeJob(cfg, controller.BuiltInNode, builtInLabels)
}

// placeJob answers whether a project-type job can run on the built-in node,
// by Jenkins' own rules — AbstractProject.getAssignedLabel and the node's
// mode — and reports known=false wherever the data to apply them is missing.
func placeJob(cfg *jobConfig, node ci.BuiltInNode, builtInLabels map[string]bool) (runs, known bool) {
	assigned := strings.TrimSpace(cfg.AssignedNode)
	canRoam := strings.TrimSpace(cfg.CanRoam)
	switch {
	case canRoam == "true":
		// No label restriction: the job runs wherever there is an executor.
		// The built-in node takes it only with executors to offer, and only
		// in NORMAL mode — EXCLUSIVE takes nothing that does not name it.
		if !node.NumExecutorsKnown {
			return false, false
		}
		if node.NumExecutors == 0 {
			return false, true
		}
		if !node.ModeKnown {
			return false, false
		}
		return !strings.EqualFold(node.Mode, "EXCLUSIVE"), true
	case canRoam == "false" && assigned == "":
		// Jenkins assigns a job that may not roam and names no node to the
		// controller's own label: it is pinned there. v0.1 read it as running
		// nowhere near the controller.
		return true, true
	case canRoam == "false" && isLabelExpression(assigned):
		// <assignedNode> can hold a label expression — "built-in || linux",
		// "!windows && x86" — and this fetcher does not evaluate those.
		// Recording false for one would assert, as measured fact, that a job
		// which may well run on the controller cannot.
		return false, false
	case canRoam == "false":
		if builtInLabels[strings.ToLower(assigned)] {
			return true, true
		}
		// Not one of the built-in node's labels — if they could be read at
		// all. Otherwise only the two well-known names can be placed.
		if !node.LabelsKnown {
			return false, false
		}
		return false, true
	default:
		// No <canRoam> in the document at all: not a shape Jenkins writes
		// for these job types, so nothing is assumed about it.
		return false, false
	}
}

// isLabelExpression reports whether an <assignedNode> value is a label
// expression rather than one bare label. The operators are the Jenkins set —
// && || ! ( ) -> <-> plus quoting and whitespace; a bare label contains none
// of them. '-' alone is not an operator: "built-in" is a label.
func isLabelExpression(s string) bool {
	return strings.ContainsAny(s, "&|!()<>\"' \t")
}

func definitionFrom(doc jobDocument, cfg *jobConfig) ci.Definition {
	switch {
	case cfg.XMLName.Local == classMultibranch:
		return multibranchDefinition(cfg)
	case doc.ui:
		// A freestyle, matrix or Maven job: build steps are configuration
		// clicked into a form.
		return ci.Definition{Source: ci.SourceUI}
	case cfg.Definition == nil:
		return ci.Definition{Source: ci.SourceUnknown}
	}

	d := cfg.Definition
	switch d.Class {
	case classCpsScmFlowDefinition:
		def := ci.Definition{Source: ci.SourceSCM, Class: d.Class, ScriptPath: d.ScriptPath}
		for _, rc := range d.SCM.UserRemoteConfigs.Configs {
			if rc.URL != "" {
				def.SCMURLs = append(def.SCMURLs, stripCredentials(rc.URL))
			}
		}
		return def
	case classSCMBinder:
		// A standard multibranch project's branch job: its own branch's
		// Jenkinsfile.
		return ci.Definition{Source: ci.SourceSCM, Class: d.Class, ScriptPath: d.ScriptPath}
	case classCpsFlowDefinition, classInlineFlowDefinition:
		return withSandbox(ci.Definition{Source: ci.SourceInline, Class: d.Class}, d.Sandbox)
	case classDefaultsBinder:
		return withSandbox(ci.Definition{Source: ci.SourceInline, Class: d.Class}, d.UseSandbox)
	default:
		// A definition class from a plugin this fetcher has not been taught
		// about. Distinct from an unreadable configuration, which leaves
		// available["config"] false and no definition at all.
		return ci.Definition{Source: ci.SourceUnknown, Class: d.Class}
	}
}

// multibranchDefinition decides what a multibranch project's branches build
// from, which is its factory's business and not its class's.
//
// v0.1 returned "scm" for every multibranch project, on the reasoning that
// reading a Jenkinsfile per branch is what one does. The factory can say
// otherwise: inline-pipeline gives every branch one script stored on the
// controller, sandbox optional, and pipeline-multibranch-defaults one kept in
// a Config File Provider file. Both scored CIS-2.3.1 PASS and CIS-2.1.2 NA. A
// factory this fetcher has not been taught is unknown, not assumed to be the
// default.
func multibranchDefinition(cfg *jobConfig) ci.Definition {
	f := cfg.Factory
	var def ci.Definition
	switch f.Class {
	case classWorkflowBranchProjectFactory:
		def = ci.Definition{Source: ci.SourceSCM, ScriptPath: f.ScriptPath}
	case classInlineBranchProjectFactory:
		def = withSandbox(ci.Definition{Source: ci.SourceInline}, f.Sandbox)
	case classDefaultsBranchProjectFactory:
		def = withSandbox(ci.Definition{Source: ci.SourceInline}, f.UseSandbox)
	default:
		def = ci.Definition{Source: ci.SourceUnknown}
	}
	def.Class = f.Class
	for _, bs := range cfg.Sources.Data.BranchSources {
		if bs.Source.Remote != "" {
			def.SCMURLs = append(def.SCMURLs, stripCredentials(bs.Source.Remote))
		}
	}
	return def
}

// withSandbox records a sandbox flag when the document carried one. Absent is
// not off: it leaves SandboxKnown false, and the control reports MANUAL.
func withSandbox(def ci.Definition, flag *string) ci.Definition {
	if flag != nil {
		def.Sandbox = strings.TrimSpace(*flag) == "true"
		def.SandboxKnown = true
	}
	return def
}

// triggersFrom collects trigger types and their schedules from both places a
// job keeps them: <triggers> under the root for a freestyle job, and under
// <properties><…PipelineTriggersJobProperty> for a pipeline. A job has one or
// the other, never both.
func triggersFrom(cfg *jobConfig) []ci.Trigger {
	var out []ci.Trigger
	for _, entries := range [][]configTrigger{cfg.Triggers.Entries, cfg.PipelineTriggers.Entries} {
		for _, t := range entries {
			out = append(out, ci.Trigger{
				Type: shortClassName(t.XMLName.Local),
				Spec: strings.TrimSpace(t.Spec),
			})
		}
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
