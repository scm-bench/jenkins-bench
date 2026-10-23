package jenkins

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/scm-bench/jenkins-bench/internal/ci"
)

// cancelling serves s, except that a request for one path cancels the scan's
// context and then hangs until the client gives up — a Ctrl-C landing while
// that request is in flight, every time, with no timing involved.
func cancelling(t *testing.T, s *stand, path string) (*Fetcher, context.Context) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == path {
			cancel()
			<-r.Context().Done()
			return
		}
		s.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return NewFetcher(client), ctx
}

// A cancelled scan stops with the cancellation, wherever it lands: in a
// folder's listing, a nested folder's, a named target's lookup or a job's
// configuration. None of these is recorded as an unreadable item and the scan
// carried on — that would report a partial scan as a finished one.
func TestFetchStopsWhenCancelled(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		folders []string
		jobs    []string
	}{
		{name: "nested folder listing", path: "/job/Team A/job/sub/api/json"},
		{name: "named folder listing", path: "/job/Team A/api/json", folders: []string{"Team A"}},
		{name: "named job lookup", path: "/job/build/api/json", jobs: []string{"build"}},
		{name: "job configuration", path: "/job/build/config.xml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scopedStand(t)
			if len(tc.folders) > 0 {
				// The lookup of the folder itself must succeed; its listing is
				// the request that is cancelled. Both share a path, so the
				// lookup is answered by the query-free variant below.
				tc.path = "/job/Team A/job/sub/api/json"
			}
			f, ctx := cancelling(t, s, tc.path)
			f.Folders, f.Jobs = tc.folders, tc.jobs
			snap, err := f.Fetch(ctx)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Fetch() = %v, %v; want context.Canceled", snap, err)
			}
		})
	}
}

func TestFetcherRunsWithNoConcurrencySet(t *testing.T) {
	s := hardened(t)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	client, err := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	f := NewFetcher(client)
	f.Concurrency = 0
	snap, err := f.Fetch(context.Background())
	if err != nil || len(snap.Jobs) != 1 {
		t.Fatalf("Fetch() = %d jobs, %v; want one job read one at a time", len(snap.Jobs), err)
	}
}

func TestFetcherSortsPluginsByName(t *testing.T) {
	s := hardened(t)
	s.handlers["/pluginManager/api/json"] = standResponse{body: `{"plugins":[
		{"shortName":"workflow-cps","version":"1"},{"shortName":"git","version":"2"},{"shortName":"matrix-auth","version":"3"}]}`}
	var names []string
	for _, p := range fetchFrom(t, s).Controller.Plugins {
		names = append(names, p.ShortName)
	}
	if got := strings.Join(names, ","); got != "git,matrix-auth,workflow-cps" {
		t.Errorf("plugins = %s, want them sorted by name", got)
	}
}

func TestFetcherRecordsUnreadableCredentials(t *testing.T) {
	s := hardened(t)
	s.forbidden = []string{"/credentials/"}
	c := fetchFrom(t, s).Controller
	if c.Available[AvailCredentials] {
		t.Error("credentials marked available after a 403")
	}
	if !strings.Contains(strings.Join(c.Errors, "\n"), "credentials could not be read") {
		t.Errorf("errors = %q, want the credentials failure", c.Errors)
	}
}

func TestChildOfRefusesAnUnnamedItem(t *testing.T) {
	if childOf("", "") || childOf("Team A", "") {
		t.Error("an item with no full name is inside nothing")
	}
}

// A lookup answered without a full name keeps the name the flag gave; one
// answered with an error other than 404 says so rather than "no such item".
func TestLookupFillsInTheNameAndReportsOtherFailures(t *testing.T) {
	s := scopedStand(t)
	s.handlers["/job/build/api/json"] = standResponse{body: `{"_class":"hudson.model.FreeStyleProject","name":"build"}`}
	snap, err := scopedFetch(t, s, nil, []string{"build"})
	if err != nil {
		t.Fatal(err)
	}
	if jobNames(snap) != "build" {
		t.Errorf("jobs = %s, want build", jobNames(snap))
	}

	s.handlers["/job/build/api/json"] = standResponse{status: http.StatusForbidden}
	_, err = scopedFetch(t, s, nil, []string{"build"})
	if err == nil || !strings.Contains(err.Error(), `--job "build" could not be read`) {
		t.Errorf("err = %v, want the read failure named", err)
	}
}

func TestFetcherRecordsAConfigurationItCannotParse(t *testing.T) {
	cases := map[string]string{
		"truncated":        `<project><disabled>false`,
		"unknown encoding": `<?xml version="1.0" encoding="EBCDIC-US"?><project/>`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			job := configFor(t, body)
			if job.Available[AvailJobConfig] || !strings.Contains(strings.Join(job.Errors, "\n"), "could not be parsed") {
				t.Errorf("available=%v errors=%q; want an unparsed configuration", job.Available[AvailJobConfig], job.Errors)
			}
		})
	}
}

// The job document decodes, but something after its root element does not.
// The scripts in it are then unknown, not absent.
func TestFetcherRecordsAConfigurationItCannotScanForScripts(t *testing.T) {
	job := configFor(t, `<project><disabled>false</disabled></project><`)
	if job.Available[AvailJobConfig] || !strings.Contains(strings.Join(job.Errors, "\n"), "scanned for scripts") {
		t.Errorf("available=%v errors=%q; want the scan failure recorded", job.Available[AvailJobConfig], job.Errors)
	}
}

func TestFetcherReadsDisabledFromTheConfiguration(t *testing.T) {
	for _, body := range []string{
		`<project><disabled>true</disabled><canRoam>true</canRoam></project>`,
		`<com.example.UnknownJob><disabled>true</disabled></com.example.UnknownJob>`,
	} {
		if job := configFor(t, body); !job.Disabled {
			t.Errorf("%s: job not marked disabled", body)
		}
	}
}

func TestFetcherReadsAConfigurationDeclaredAsUTF8WithoutTheDash(t *testing.T) {
	job := configFor(t, `<?xml version="1.0" encoding="utf8"?><project><canRoam>false</canRoam></project>`)
	if !job.Available[AvailJobConfig] {
		t.Errorf("errors = %q; utf8 is UTF-8", job.Errors)
	}
}

func TestPlacementIsUnknownWithoutTheExecutorCountOrCanRoam(t *testing.T) {
	noCount := strings.Replace(twoExecutors, `"numExecutors":2,`, ``, 1)
	if _, known := placement(t, noCount, `<project><canRoam>true</canRoam></project>`, http.StatusInternalServerError); known {
		t.Error("a roaming job's placement needs the built-in node's executor count")
	}
	if _, known := placement(t, twoExecutors, `<project><assignedNode>linux</assignedNode></project>`, 0); known {
		t.Error("with no <canRoam> the placement is not known")
	}
}

func TestPipelineWithoutADefinitionIsUnknown(t *testing.T) {
	job := configFor(t, `<flow-definition><disabled>false</disabled></flow-definition>`)
	if job.Definition.Source != ci.SourceUnknown {
		t.Errorf("definition = %+v, want unknown", job.Definition)
	}
}

func TestTriggerWithoutAPackageKeepsItsName(t *testing.T) {
	if got := shortClassName("TimerTrigger"); got != "TimerTrigger" {
		t.Errorf("shortClassName = %q", got)
	}
}

func TestPrepareConfigXMLLeavesHarmlessReferencesAlone(t *testing.T) {
	for _, ref := range []string{"&#0;", "&#9;", "&#x0A;", "&#13;", "&#32;", "&#99999999999;"} {
		if got := string(prepareConfigXML([]byte(ref))); got != ref {
			t.Errorf("prepareConfigXML(%q) = %q, want it unchanged", ref, got)
		}
	}
	if got := string(prepareConfigXML([]byte("&#x1B;"))); got != "&#xFFFD;" {
		t.Errorf("an escape character became %q, want U+FFFD", got)
	}
}

func TestCharsetReader(t *testing.T) {
	r, err := charsetReader("UTF-8", strings.NewReader("x"))
	if err != nil || r == nil {
		t.Errorf("UTF-8: %v", err)
	}
	if _, err := charsetReader("latin1", iotest.ErrReader(errors.New("disk gone"))); err == nil {
		t.Error("a failed read was not reported")
	}
}

// A script-security object at the document's root, or under no element named
// like a class, is still found and named by what holds it.
func TestFindScriptsAtTheRootAndUnderPlainElements(t *testing.T) {
	scripts, err := findScripts([]byte(`<project><sandbox>false</sandbox><script>x</script></project>`))
	if err != nil || len(scripts) != 1 || scripts[0].Holder != "project" || scripts[0].Sandbox {
		t.Errorf("root script = %+v, %v", scripts, err)
	}
	scripts, err = findScripts([]byte(`<project><builders><step><sandbox>true</sandbox><scriptText>x</scriptText></step></builders></project>`))
	if err != nil || len(scripts) != 1 || scripts[0].Holder != "step" || !scripts[0].Sandbox {
		t.Errorf("plain script = %+v, %v", scripts, err)
	}
}

func TestStripCredentialsFromAnUnparseableURLWithAQuery(t *testing.T) {
	got := stripCredentials("https://user:secret@bad host/repo.git?token=abc")
	if strings.Contains(got, "secret") || strings.Contains(got, "token") {
		t.Errorf("stripCredentials = %q, still carries a secret", got)
	}
}

// A machine with no readable system pool still trusts the bundle it was given.
func TestCAFileWorksWithoutASystemPool(t *testing.T) {
	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("no system roots") }
	t.Cleanup(func() { systemCertPool = orig })

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer srv.Close()
	c, err := NewClient(Options{BaseURL: srv.URL, CAFile: writeCA(t, srv)})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.GetJSON(context.Background(), "/api/json", nil); err != nil {
		t.Errorf("the bundle alone should verify the controller: %v", err)
	}
}

func TestNewClientRejectsAURLItCannotParse(t *testing.T) {
	_, err := NewClient(Options{BaseURL: "https://user:secret@[::1"})
	if err == nil || !strings.Contains(err.Error(), "parse controller URL") || strings.Contains(err.Error(), "secret") {
		t.Errorf("err = %v, want a parse error with the credentials redacted", err)
	}
}

func TestClientRejectsAPathItCannotBuildARequestFor(t *testing.T) {
	c, err := NewClient(Options{BaseURL: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.GetJSON(context.Background(), "/job/%zz/api/json", nil); err == nil || !strings.Contains(err.Error(), "build request for") {
		t.Errorf("err = %v, want a request-building error", err)
	}
}

// A body cut off mid-transfer is a transient failure and is retried.
func TestClientRetriesABodyCutOffMidTransfer(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			conn, buf, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"partial\":")
			buf.Flush()
			conn.Close()
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c, err := NewClient(Options{BaseURL: srv.URL, MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	var out struct{ OK bool }
	if err := c.GetJSON(context.Background(), "/api/json", &out); err != nil || !out.OK || attempts.Load() != 2 {
		t.Errorf("GetJSON = %v after %d attempts, ok=%v; want success on the retry", err, attempts.Load(), out.OK)
	}

	// With no retry left, the read failure is what is reported.
	attempts.Store(0)
	c, _ = NewClient(Options{BaseURL: srv.URL, MaxRetries: 0})
	if err := c.GetJSON(context.Background(), "/api/json", nil); err == nil || !strings.Contains(err.Error(), "read body") {
		t.Errorf("err = %v, want a read-body error", err)
	}
}

// The server's own Retry-After paces the retry, and a cancellation during
// that wait ends it at once.
func TestClientWaitsAsToldAndStopsWhenCancelled(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c, err := NewClient(Options{BaseURL: srv.URL, MaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.GetJSON(context.Background(), "/api/json", nil); err != nil {
		t.Fatalf("GetJSON after a Retry-After of 0: %v", err)
	}
	// Retry-After replaced the backoff (at least a second), it did not add to it.
	if took := time.Since(start); took > 900*time.Millisecond {
		t.Errorf("the retry took %s; Retry-After 0 should not also back off", took)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer slow.Close()
	c, _ = NewClient(Options{BaseURL: slow.URL, MaxRetries: 2})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.GetJSON(ctx, "/api/json", nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want the deadline, not a 30s wait", err)
	}
}

func TestEffectivePortOfAnotherScheme(t *testing.T) {
	if got := effectivePort(&url.URL{Scheme: "ftp", Host: "h"}); got != "" {
		t.Errorf("effectivePort(ftp) = %q, want none", got)
	}
}
