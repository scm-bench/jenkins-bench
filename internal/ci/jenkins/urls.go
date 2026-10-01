package jenkins

import (
	"net/url"
	"strings"
)

// stripCredentials removes anything credential-shaped from a URL the snapshot
// keeps: userinfo, the query and the fragment.
//
// A snapshot is written to disk and attached to bug reports, and URLs are where
// credentials hide in a Jenkins configuration — https://deploy:<token>@host/…
// is how a great many Jenkinsfiles were first wired up, and v0.1 copied SCM
// remotes into the snapshot verbatim. The query and fragment go too: a token in
// ?access_token= is as much a token, and where a definition is read from is
// fully said by the scheme, host and path.
//
// scp-like git remotes ([user@]host:path) are not URLs to net/url, so their
// userinfo is cut by hand; so is that of a URL net/url cannot parse at all,
// which is exactly as capable of carrying a password as one it can.
func stripCredentials(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	if u, err := url.Parse(raw); err == nil && u.Scheme != "" && u.Host != "" {
		u.User = nil
		u.RawQuery = ""
		u.ForceQuery = false
		u.Fragment = ""
		u.RawFragment = ""
		return u.String()
	}

	rest, scheme := raw, ""
	if i := strings.Index(raw, "://"); i >= 0 {
		scheme, rest = raw[:i+3], raw[i+3:]
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	// The authority ends at the first slash; for scp syntax the path starts
	// after a colon, but a colon can also separate a user from a password, so
	// the last '@' before the first slash is the boundary either way.
	authority := rest
	if i := strings.Index(rest, "/"); i >= 0 {
		authority = rest[:i]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return scheme + rest
}
