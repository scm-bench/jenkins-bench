package jenkins

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewClientRejectsUnusableURLs(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"no scheme", "jenkins.example.com"},
		{"no host", "https://"},
		{"not http", "ftp://jenkins.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewClient(Options{BaseURL: tt.url}); err == nil {
				t.Errorf("%q was accepted", tt.url)
			}
		})
	}
}

// Sending a credential over http:// to somewhere that is not this machine
// should take an explicit decision.
func TestNewClientRefusesCleartextToARemoteHost(t *testing.T) {
	_, err := NewClient(Options{BaseURL: "http://jenkins.example.com", Username: "u", Token: "t"})
	if err == nil {
		t.Fatal("cleartext to a remote host was accepted")
	}
	if !strings.Contains(err.Error(), "cleartext") || !strings.Contains(err.Error(), "--allow-plaintext") {
		t.Errorf("the error should say what to do: %v", err)
	}

	if _, err := NewClient(Options{BaseURL: "http://jenkins.example.com", AllowPlaintext: true}); err != nil {
		t.Errorf("--allow-plaintext should permit it: %v", err)
	}
}

// Loopback is decided by name and by literal address, without DNS: a name that
// merely happens to point at 127.0.0.1 today is not a property to rely on.
func TestNewClientAllowsCleartextToLoopback(t *testing.T) {
	for _, url := range []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if _, err := NewClient(Options{BaseURL: url}); err != nil {
			t.Errorf("%s should be allowed: %v", url, err)
		}
	}
}

// A URL carrying a password must not reach an error message intact — including
// when it was too malformed to parse, which is exactly as capable of carrying
// one.
func TestCredentialsInAURLAreRedacted(t *testing.T) {
	tests := []struct {
		raw    string
		secret string
	}{
		{"https://user:hunter2@jenkins.example.com", "hunter2"},
		{"https://user:hunter2@jenkins.example.com:80 80/x", "hunter2"},
		{"::not a url at all::user:hunter2@host", "hunter2"},
	}
	for _, tt := range tests {
		got := redactURL(tt.raw)
		if strings.Contains(got, tt.secret) {
			t.Errorf("redactURL(%q) = %q, which still carries the password", tt.raw, got)
		}
	}
}

func TestClientStripsCredentialsFromTheBaseURL(t *testing.T) {
	c, err := NewClient(Options{BaseURL: "https://user:hunter2@jenkins.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(c.BaseURL(), "hunter2") {
		t.Errorf("BaseURL() = %q", c.BaseURL())
	}
}

func TestClientRetriesServerErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	c, err := NewClient(Options{BaseURL: srv.URL, MaxRetries: 3})
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.GetJSON(context.Background(), "/api/json", &out); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if !out.OK || attempts.Load() != 3 {
		t.Errorf("attempts = %d, decoded = %+v", attempts.Load(), out)
	}
}

// 403 and 404 are answers, not transient failures. Retrying them wastes a
// scan's time against every job a token cannot read.
func TestClientDoesNotRetryAnAnswer(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound, http.StatusUnauthorized} {
		var attempts atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts.Add(1)
			w.WriteHeader(status)
		}))

		c, err := NewClient(Options{BaseURL: srv.URL, MaxRetries: 3})
		if err != nil {
			t.Fatal(err)
		}
		err = c.GetJSON(context.Background(), "/api/json", nil)
		if err == nil {
			t.Errorf("HTTP %d should be an error", status)
		}
		if got := Status(err); got != status {
			t.Errorf("Status(err) = %d, want %d", got, status)
		}
		if attempts.Load() != 1 {
			t.Errorf("HTTP %d was retried %d times", status, attempts.Load())
		}
		srv.Close()
	}
}

func TestIsForbiddenCoversBothPermissionStatuses(t *testing.T) {
	if !IsForbidden(&APIError{StatusCode: http.StatusForbidden}) {
		t.Error("403 is a permission problem")
	}
	if !IsForbidden(&APIError{StatusCode: http.StatusUnauthorized}) {
		t.Error("401 is a permission problem")
	}
	if IsForbidden(&APIError{StatusCode: http.StatusNotFound}) {
		t.Error("404 is not a permission problem: it is also what a controller without the plugin returns")
	}
	if Status(context.Canceled) != 0 {
		t.Error("a non-API error has no status")
	}
}

func TestClientHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	c, err := NewClient(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := c.GetJSON(ctx, "/api/json", nil); err == nil {
		t.Error("a cancelled request should return an error")
	}
}

// The probe distinguishes three outcomes, and the third is the one that
// matters: a transport error is not a denial, and reading it as one would
// report PASS on a controller nobody checked.
func TestProbeAnonymousDistinguishesDenialFromFailure(t *testing.T) {
	allowed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer allowed.Close()
	denied := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer denied.Close()

	c, _ := NewClient(Options{BaseURL: allowed.URL})
	if ok, conclusive := c.ProbeAnonymous(context.Background(), "/api/json"); !ok || !conclusive {
		t.Errorf("a 200 means anonymous read: ok=%v conclusive=%v", ok, conclusive)
	}

	c, _ = NewClient(Options{BaseURL: denied.URL})
	if ok, conclusive := c.ProbeAnonymous(context.Background(), "/api/json"); ok || !conclusive {
		t.Errorf("a 403 is a conclusion: ok=%v conclusive=%v", ok, conclusive)
	}

	// Nothing listening: not a denial.
	unreachable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := unreachable.URL
	unreachable.Close()
	c, _ = NewClient(Options{BaseURL: url, Timeout: 200 * time.Millisecond})
	if ok, conclusive := c.ProbeAnonymous(context.Background(), "/api/json"); ok || conclusive {
		t.Errorf("an unreachable controller is not a denial: ok=%v conclusive=%v", ok, conclusive)
	}
}

// The probe must not send the token: it is asking what an unauthenticated
// client can see.
func TestProbeAnonymousSendsNoCredentials(t *testing.T) {
	var sawAuth atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			sawAuth.Store(true)
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	c, _ := NewClient(Options{BaseURL: srv.URL, Username: "u", Token: "t"})
	c.ProbeAnonymous(context.Background(), "/api/json")
	if sawAuth.Load() {
		t.Error("the anonymous probe sent an Authorization header")
	}
}

func TestRetryAfterIsCapped(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	if _, ok := retryAfter(resp); ok {
		t.Error("no header means no wait")
	}
	resp.Header.Set("Retry-After", "5")
	if d, ok := retryAfter(resp); !ok || d != 5*time.Second {
		t.Errorf("Retry-After: 5 = %v", d)
	}
	// A controller asking us to sleep for an hour should surface as an error
	// rather than a hung scan.
	resp.Header.Set("Retry-After", "3600")
	if d, _ := retryAfter(resp); d > time.Minute {
		t.Errorf("Retry-After should be capped, got %v", d)
	}
	resp.Header.Set("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
	if _, ok := retryAfter(resp); ok {
		t.Error("an HTTP-date Retry-After is not parsed, so it must report no wait")
	}
}

// The shift is clamped before it happens: 1 << (attempt-1) overflows past the
// thirty-fifth attempt and comes back negative, and a negative duration
// reaches rand.N, which panics on a non-positive argument.
func TestBackoffIsBoundedAtEveryAttempt(t *testing.T) {
	for _, attempt := range []int{-1, 0, 1, 2, 5, 35, 64, 1 << 20} {
		d := backoff(attempt)
		if d <= 0 {
			t.Errorf("backoff(%d) = %v, which is not a usable delay", attempt, d)
		}
		if d > 30*time.Second {
			t.Errorf("backoff(%d) = %v, past the ceiling", attempt, d)
		}
	}
}

func TestTLSInsecureIsOnlyReachableByOption(t *testing.T) {
	if cfg := tlsInsecureConfig(); !cfg.InsecureSkipVerify {
		t.Error("tlsInsecureConfig should skip verification")
	}
	c, err := NewClient(Options{BaseURL: "https://jenkins.example.com", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Transport == http.DefaultTransport {
		t.Error("--insecure should install its own transport")
	}
}

func TestClientReportsRequestsForProgress(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	var events []RequestEvent
	var logged, warned int
	c, err := NewClient(Options{
		BaseURL:   srv.URL,
		OnRequest: func(e RequestEvent) { events = append(events, e) },
		Logf:      func(string, ...any) { logged++ },
		Warnf:     func(string, ...any) { warned++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.GetJSON(context.Background(), "/api/json", nil); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %+v", events)
	}
	if events[0].Method != http.MethodGet {
		t.Errorf("event method = %q; this client cannot issue anything else", events[0].Method)
	}
	c.logf("x")
	c.warnf("y")
	if logged != 1 || warned != 1 {
		t.Errorf("logf/warnf were not forwarded: %d %d", logged, warned)
	}
}

func TestGetRawReturnsTheBodyUndecoded(t *testing.T) {
	const body = `<?xml version='1.1' encoding='UTF-8'?><project/>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	c, _ := NewClient(Options{BaseURL: srv.URL})
	got, err := c.GetRaw(context.Background(), "/job/x/config.xml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("GetRaw returned %q", got)
	}
}

func TestGetJSONReportsUndecodableBodies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>not json</html>`))
	}))
	defer srv.Close()

	c, _ := NewClient(Options{BaseURL: srv.URL})
	var out struct{}
	err := c.GetJSON(context.Background(), "/api/json", &out)
	if err == nil {
		t.Fatal("a non-JSON body should be an error")
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("the error should say what went wrong: %v", err)
	}
}

// A path with a percent-encoded segment has to arrive at the controller
// unchanged. Encoding it twice returns a 404 indistinguishable from a job that
// does not exist.
func TestEncodedPathsSurviveURLConstruction(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.URL.EscapedPath()
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, _ := NewClient(Options{BaseURL: srv.URL})
	if err := c.GetJSON(context.Background(), jobPath("Team A/Case 01")+"/api/json", nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(seen, "%25") {
		t.Errorf("the path was encoded twice: %s", seen)
	}
	if seen != "/job/Team%20A/job/Case%2001/api/json" {
		t.Errorf("path = %s", seen)
	}
}
