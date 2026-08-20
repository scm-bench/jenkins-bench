// Package jenkins reads a controller over its HTTP API into a ci.Snapshot.
// Every request is a GET: the client exposes no way to issue anything else,
// and the tests fail on any other method.
package jenkins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client reads one controller.
type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	username   string
	token      string
	maxRetries int
	onRequest  func(RequestEvent)

	// Logf receives progress detail. Nil means silent.
	Logf func(format string, args ...any)
	// Warnf receives problems worth surfacing in the report's metadata.
	Warnf func(format string, args ...any)
}

// RequestEvent reports one completed request, for progress display and for the
// scan trace.
type RequestEvent struct {
	Method  string
	Path    string
	Status  int
	Took    time.Duration
	Attempt int
	Err     error
}

// Options configures a Client.
type Options struct {
	// BaseURL is the controller root, e.g. https://jenkins.example.com.
	BaseURL string
	// Username and Token authenticate. Token is an API token, which is what
	// the controller expects and what avoids needing a CSRF crumb; a password
	// works against a local security realm but is not what to document.
	Username string
	Token    string

	Timeout    time.Duration
	MaxRetries int
	// Insecure disables certificate verification.
	Insecure bool
	// AllowPlaintext permits sending credentials over http:// to a non-loopback
	// host.
	AllowPlaintext bool

	Logf      func(format string, args ...any)
	Warnf     func(format string, args ...any)
	OnRequest func(RequestEvent)
}

// NewClient validates the options and builds a client.
func NewClient(opts Options) (*Client, error) {
	if strings.TrimSpace(opts.BaseURL) == "" {
		return nil, errors.New("a controller URL is required")
	}
	u, err := url.Parse(strings.TrimRight(opts.BaseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("parse controller URL %s: %w", redactURL(opts.BaseURL), err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("controller URL %s must be http or https", redactURL(opts.BaseURL))
	}
	if u.Host == "" {
		return nil, fmt.Errorf("controller URL %s has no host", redactURL(opts.BaseURL))
	}
	// Credentials in the URL are stripped before anything else can log it.
	u.User = nil

	if err := checkTransport(u, opts.AllowPlaintext); err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if opts.Insecure {
		transport.TLSClientConfig = tlsInsecureConfig()
	}

	return &Client{
		baseURL:    u,
		httpClient: &http.Client{Timeout: timeout, Transport: transport},
		username:   opts.Username,
		token:      opts.Token,
		maxRetries: opts.MaxRetries,
		onRequest:  opts.OnRequest,
		Logf:       opts.Logf,
		Warnf:      opts.Warnf,
	}, nil
}

// BaseURL returns the controller root.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// HasCredentials reports whether requests carry an Authorization header. The
// fetcher needs the distinction once: a 401 with credentials means they were
// rejected, while a 401 without them is just a controller requiring login.
func (c *Client) HasCredentials() bool { return c.username != "" }

// APIError is a non-2xx response.
type APIError struct {
	StatusCode int
	Path       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("GET %s: HTTP %d %s", e.Path, e.StatusCode, http.StatusText(e.StatusCode))
}

// Status returns the HTTP status of err, or 0 if it was not an API error. The
// fetcher records the number rather than branching on it, because what a
// controller means by 403 and by 404 is not reliably different: an unreadable
// credential store returns 404, and so does a controller without the plugin.
func Status(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode
	}
	return 0
}

// IsForbidden reports whether err was a permission problem.
func IsForbidden(err error) bool {
	s := Status(err)
	return s == http.StatusForbidden || s == http.StatusUnauthorized
}

// GetJSON reads path and decodes the response into out.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	body, _, err := c.raw(ctx, path, true)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("GET %s: decode response: %w", path, err)
	}
	return nil
}

// GetRaw reads path and returns the body undecoded, for config.xml.
func (c *Client) GetRaw(ctx context.Context, path string) ([]byte, error) {
	body, _, err := c.raw(ctx, path, true)
	return body, err
}

// Head reads path only for its response headers. Used for the version, which
// arrives as X-Jenkins on any response including the login page.
func (c *Client) Head(ctx context.Context, path string) (http.Header, error) {
	_, headers, err := c.raw(ctx, path, true)
	return headers, err
}

// ProbeAnonymous issues path with no credentials — the only way to answer
// "can an unauthenticated client read this?", since the authorization strategy
// is not exposed. conclusive is false on transport errors: a probe that never
// ran is not a denial.
func (c *Client) ProbeAnonymous(ctx context.Context, path string) (allowed, conclusive bool) {
	_, _, err := c.raw(ctx, path, false)
	if err == nil {
		return true, true
	}
	switch Status(err) {
	case http.StatusForbidden, http.StatusUnauthorized:
		return false, true
	}
	return false, false
}

// raw issues a GET and returns the body and response headers, retrying
// throttled and transient responses with exponential backoff.
//
// There is no method parameter. A caller cannot ask this package to write.
func (c *Client) raw(ctx context.Context, path string, authenticate bool) ([]byte, http.Header, error) {
	// Built as a string and parsed once. path arrives percent-encoded, and
	// assigning it to URL.Path (the decoded form) double-encodes it —
	// "Team%20A" goes out as "Team%2520A", the controller answers 404, and a
	// whole folder silently vanishes from the scan.
	endpointStr := strings.TrimRight(c.baseURL.String(), "/") + path
	endpoint, err := url.Parse(endpointStr)
	if err != nil {
		return nil, nil, fmt.Errorf("build request for %s: %w", path, err)
	}

	var lastErr error
	waited := false // a Retry-After already paced this retry
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 && !waited {
			delay := backoff(attempt)
			c.logf("retrying %s in %s (attempt %d/%d)", path, delay, attempt, c.maxRetries)
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		waited = false

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
		if err != nil {
			return nil, nil, fmt.Errorf("build request for %s: %w", path, err)
		}
		req.Header.Set("Accept", "application/json, text/xml, */*")
		if authenticate && c.username != "" {
			req.SetBasicAuth(c.username, c.token)
		}

		started := time.Now()
		resp, err := c.httpClient.Do(req)
		if err != nil {
			// Transport errors are worth retrying; a cancelled context is not.
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
			c.emit(req.Method, path, 0, time.Since(started), attempt, err)
			lastErr = fmt.Errorf("GET %s: %w", path, err)
			continue
		}

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		c.emit(req.Method, path, resp.StatusCode, time.Since(started), attempt, readErr)
		if readErr != nil {
			lastErr = fmt.Errorf("GET %s: read body: %w", path, readErr)
			continue
		}

		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return body, resp.Header, nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			lastErr = &APIError{StatusCode: resp.StatusCode, Path: path}
			if wait, ok := retryAfter(resp); ok && attempt < c.maxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(wait):
				}
				// The server named its own pace; adding the loop head's
				// exponential backoff on top would sleep twice per retry.
				waited = true
			}
			continue
		default:
			// 401, 403, 404 and the rest are answers, not failures to retry.
			// Every one of them is something the fetcher turns into an
			// availability key rather than an aborted scan.
			return nil, resp.Header, &APIError{StatusCode: resp.StatusCode, Path: path}
		}
	}
	return nil, nil, lastErr
}

func (c *Client) emit(method, path string, status int, took time.Duration, attempt int, err error) {
	if c.onRequest == nil {
		return
	}
	c.onRequest(RequestEvent{Method: method, Path: path, Status: status, Took: took, Attempt: attempt, Err: err})
}

func (c *Client) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c *Client) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
	}
}

func checkTransport(u *url.URL, allowPlaintext bool) error {
	if u.Scheme != "http" || isLoopback(u) || allowPlaintext {
		return nil
	}
	// Redacted() rather than the URL itself: NewClient strips userinfo before
	// calling this, but an error message about protecting a credential is the
	// last place that should depend on someone upstream having remembered to.
	return fmt.Errorf("refusing to send credentials in cleartext to %s\n"+
		"use https://, or override once with --set scan.allowPlaintext=true if this network is genuinely trusted", u.Redacted())
}

// redactURL renders a URL for an error message with any password removed.
//
// It takes a string rather than a *url.URL because the callers that need it
// most are on the path where parsing has already failed, and an unparseable
// URL is exactly as capable of carrying a password as a valid one.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Redacted()
	}
	start := 0
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		start = scheme + 3
	}
	authority := raw[start:]
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	at := strings.LastIndex(authority, "@")
	if at < 0 {
		return raw
	}
	return raw[:start] + "xxxxx@" + raw[start+at+1:]
}

// isLoopback reports whether the host resolves to this machine by name or by
// literal address, without performing DNS: a name that merely happens to point
// at 127.0.0.1 today is not a property the transport check can rely on.
func isLoopback(u *url.URL) bool {
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func retryAfter(resp *http.Response) (time.Duration, bool) {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		// Cap it: a controller asking us to sleep for an hour should surface as
		// an error rather than a hung scan.
		if secs > 60 {
			secs = 60
		}
		return time.Duration(secs) * time.Second, true
	}
	return 0, false
}

func backoff(attempt int) time.Duration {
	// Clamped before the shift, not after. `1 << (attempt-1)` overflows int64
	// somewhere past the thirty-fifth attempt and comes back negative, which
	// the 16s ceiling below cannot catch — and a negative duration reaches
	// rand.N, which panics on a non-positive argument.
	const maxShift = 4 // 1<<4 seconds == the 16s ceiling
	shift := attempt - 1
	if shift > maxShift {
		shift = maxShift
	}
	if shift < 0 {
		shift = 0
	}
	base := time.Duration(1<<shift) * time.Second
	// Jitter, so a controller that throttled several concurrent job fetches
	// does not get them all back at the same instant.
	return base + rand.N(base/2+1)
}
