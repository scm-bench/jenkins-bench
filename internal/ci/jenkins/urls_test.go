package jenkins

import "testing"

func TestStripCredentials(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://deploy:ghp_x@github.com/acme/app.git", "https://github.com/acme/app.git"},
		{"https://token@github.com/acme/app.git", "https://github.com/acme/app.git"},
		{"https://github.com/acme/app.git?private_token=x#frag", "https://github.com/acme/app.git"},
		{"ssh://git:pw@git.example.com:2222/acme/app.git", "ssh://git.example.com:2222/acme/app.git"},
		// scp syntax is not a URL to net/url, with or without a password.
		{"git@github.com:acme/app.git", "github.com:acme/app.git"},
		{"deploy:tok@git.example.com:acme/app.git", "git.example.com:acme/app.git"},
		// An '@' in a password that was never escaped: the last one before
		// the host is the boundary.
		{"https://user:p@ss@host.example.com/r.git", "https://host.example.com/r.git"},
		// Unparseable, and still carrying a password.
		{"https://user:hunter2@host.example.com:80 80/x", "https://host.example.com:80 80/x"},
		// Nothing to strip.
		{"/var/jenkins_home/seed-repo", "/var/jenkins_home/seed-repo"},
		{"file:///srv/git/app.git", "file:///srv/git/app.git"},
		{"https://host.example.com/path@v1/r.git", "https://host.example.com/path@v1/r.git"},
		{"  ", ""},
	}
	for _, tc := range cases {
		if got := stripCredentials(tc.in); got != tc.want {
			t.Errorf("stripCredentials(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
