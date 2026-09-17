// Unit tests for credential-safe backend URL rendering in logs, errors, and
// CLI status text.
package urlredact

import (
	"strings"
	"testing"
)

func TestURL(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"safe https", "https://example.com/org/repo.git", "https://example.com/org/repo.git"},
		{"userinfo password query fragment", "https://alice:p%40ss@example.com:8443/org/repo.git?token=secret#private", "https://example.com:8443/org/repo.git"},
		{"ssh username", "ssh://git@example.com/org/repo.git", "ssh://git@example.com/org/repo.git"},
		{"cloak prefix", "cloak::https://token@example.com/repo?signature=secret", "cloak::https://example.com/repo"},
		{"digit helper scheme", "1evil://token@example.com/repo?signature=secret", "1evil://example.com/repo"},
		{"nested helper prefix", "cloak::cloak::ssh://git@example.com/repo", "cloak::cloak::ssh://git@example.com/repo"},
		{"scp like", "git@example.com:org/repo.git", "git@example.com:org/repo.git"},
		{"scp password and suffix", "alice:secret@example.com:org/repo.git?token=secret#private", "example.com:org/repo.git"},
		{"scp IPv6", "git@[2001:db8::1]:org/repo.git", "git@[2001:db8::1]:org/repo.git"},
		{"scp without user", "example.com:org/repo.git", "example.com:org/repo.git"},
		{"local path", "/tmp/user@example.com:repo?literal#name", "/tmp/user@example.com:repo?literal#name"},
		{"remote name", "origin", "origin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := URL(tt.in); got != tt.want {
				t.Fatalf("URL(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCredentialRisk(t *testing.T) {
	for _, safe := range []string{
		"git@github.com:org/repo.git",
		"ssh://git@example.com/org/repo.git",
		"https://example.com/org/repo.git",
		"/srv/git/repo.git",
	} {
		if got := CredentialRisk(safe); got != "" {
			t.Errorf("CredentialRisk(%q) = %q, want safe", safe, got)
		}
	}
	for _, unsafe := range []string{
		"https://token@example.com/org/repo.git",
		"https://user:password@example.com/org/repo.git",
		"https://example.com/org/repo.git?token=secret",
		"ssh://user:password@example.com/org/repo.git",
		"user:password@example.com:org/repo.git",
		"git@example.com:org/repo.git?token=secret",
		"example.com:org/repo.git?token=secret",
	} {
		if got := CredentialRisk(unsafe); got == "" {
			t.Errorf("CredentialRisk(%q) = safe, want rejection", unsafe)
		}
	}
}

func TestIsSupportedTransport(t *testing.T) {
	for _, safe := range []string{
		"/srv/git/repo.git",
		"../repo.git",
		"git@example.com:org/repo.git",
		"file:///srv/git/repo.git",
		"git://example.com/org/repo.git",
		"http://example.com/org/repo.git",
		"https://example.com/org/repo.git",
		"ssh://git@example.com/org/repo.git",
		"git+ssh://git@example.com/org/repo.git",
	} {
		if !IsSupportedTransport(safe) {
			t.Errorf("IsSupportedTransport(%q) = false, want true", safe)
		}
	}
	for _, unsafe := range []string{
		"ext::sh -c false",
		"cloak::/nested",
		"evil://example.invalid/repo",
		"1evil://example.invalid/repo",
		"rsync://example.invalid/repo",
		"git+https://example.invalid/repo",
	} {
		if IsSupportedTransport(unsafe) {
			t.Errorf("IsSupportedTransport(%q) = true, want false", unsafe)
		}
	}
}

func TestShellArg(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"cloak::git@github.com:org/repo.git", "cloak::git@github.com:org/repo.git"},
		{"origin", "origin"},
		{"name with spaces", "'name with spaces'"},
		{"x; touch /tmp/pwned", "'x; touch /tmp/pwned'"},
		{"it's", "'it'\"'\"'s'"},
		{"", "''"},
	} {
		if got := ShellArg(tc.in); got != tc.want {
			t.Errorf("ShellArg(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestTextAndKnownURL(t *testing.T) {
	const raw = "cloak::https://alice:password@example.com/repo.git?token=secret#private"
	text := "failed to fetch " + raw + "; fallback ssh was git@example.com:org/repo.git; ssh said git@example.com: Permission denied"
	got := KnownURL(text, raw)
	for _, secret := range []string{"alice", "password", "token=secret", "private"} {
		if strings.Contains(got, secret) {
			t.Fatalf("KnownURL leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "cloak::https://example.com/repo.git") ||
		!strings.Contains(got, "example.com:org/repo.git") {
		t.Fatalf("KnownURL removed useful host/path context: %q", got)
	}
}
