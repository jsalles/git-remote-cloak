// Fuzz tests for the setup package's backend-URL transport guard.
//
// resolveBackendURL is the point where the URL git hands the remote helper
// (git-remote-cloak <remote> <url>, or remote.<name>.url) is turned into the
// real backend URL handed to the backend git. Its security job is to strip the
// cloak:: prefix and refuse both explicit remote-helper transports (ext::,
// fd::, nested cloak::) and unknown scheme:// transports (which Git resolves
// through git-remote-<scheme>), so hostile config cannot select an executable
// transport helper. These targets fuzz that pure guard directly:
// when the input URL is non-empty, resolveBackendURL never touches its *gitx.G
// argument (the only g use is behind the input "url == \"\"" config-lookup
// branch), so it runs with no subprocess or filesystem side effects, unlike
// the heavyweight OpenLocal path the fixed TestOpenLocalTransportGuard cases
// take.
package setup

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
)

// FuzzResolveBackendURL fuzzes the full guard over arbitrary non-empty URLs,
// pinning its decision faithfully and asserting the load-bearing security
// invariant on the accepted output: no remote-helper transport token survives.
func FuzzResolveBackendURL(f *testing.F) {
	seeds := []string{
		"cloak::ext::sh -c 'touch pwned'",
		"cloak::fd::3",
		"cloak::cloak::/tmp/nested.git",
		"cloak::",
		"cloak::/home/user/bare.git",
		"cloak::file:///srv/f.git",
		"cloak::ssh://git@example.invalid/r.git",
		"cloak::git@example.invalid:r.git",
		"cloak::https://example.invalid/r.git",
		"cloak::evil://example.invalid/r.git",
		"cloak::1evil://example.invalid/r.git",
		"cloak::https://token@example.invalid/r.git",
		"cloak::https://example.invalid/r.git?token=secret",
		"ext::sh -c 'x'",
		"/plain/local/path.git",
		"a.b-c+d::payload",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, url string) {
		// Only the input "url == \"\"" branch dereferences g; a non-empty
		// input keeps the guard pure, so a nil *gitx.G is provably never used.
		if url == "" {
			return
		}

		out, err := resolveBackendURL(nil, "", "", url)

		// Determinism: the guard is a pure function of the input URL.
		out2, err2 := resolveBackendURL(nil, "", "", url)
		if out != out2 || (err == nil) != (err2 == nil) {
			t.Fatalf("non-deterministic on %q: (%q,%v) vs (%q,%v)", url, out, err, out2, err2)
		}

		// Independent model of the documented contract: strip exactly one
		// cloak:: prefix, reject an empty remainder, any surviving remote-helper
		// transport token, and embedded credential material.
		deCloaked := strings.TrimPrefix(url, "cloak::")
		wantAccept := deCloaked != "" && urlredact.IsSupportedTransport(deCloaked) &&
			urlredact.CredentialRisk(deCloaked) == ""
		if (err == nil) != wantAccept {
			t.Fatalf("decision mismatch on %q: accepted=%v want=%v (out=%q err=%v)",
				url, err == nil, wantAccept, out, err)
		}

		if err == nil {
			// Faithful passthrough: the accepted backend URL is exactly the
			// de-cloaked input, unmodified.
			if out != deCloaked {
				t.Fatalf("accepted URL altered: in %q -> out %q, want %q", url, out, deCloaked)
			}
			// Security invariant: whatever is handed to the backend git can
			// never itself begin with a remote-helper transport token, so no
			// nested helper / ext:: / fd:: invocation can reach git.
			if out == "" {
				t.Fatalf("accepted an empty backend URL from %q", url)
			}
			if urlredact.IsHelperTransport(out) {
				t.Fatalf("accepted URL %q still carries a remote-helper transport prefix (from %q)", out, url)
			}
			if !urlredact.IsSupportedTransport(out) {
				t.Fatalf("accepted URL %q would select an external remote helper (from %q)", out, url)
			}
		}
	})
}

// FuzzBackendURLRejectsHelperTransport states the core harm independently of
// urlredact.IsHelperTransport: a cloak:: URL whose payload is any
// <scheme>::<rest> external
// helper must always be refused. It generalizes the three fixed dangerous
// cases (ext::, fd::, nested cloak::) to every transport scheme, with an oracle
// that only checks for rejection (no reference to the production regex).
func FuzzBackendURLRejectsHelperTransport(f *testing.F) {
	f.Add("ext", "sh -c 'touch pwned'")
	f.Add("fd", "3")
	f.Add("cloak", "/tmp/nested.git")
	f.Add("transport-helper", "anything")
	f.Fuzz(func(t *testing.T, scheme, rest string) {
		// Sanitize scheme to git's external-helper token grammar
		// ([A-Za-z0-9] then [A-Za-z0-9+.-]*) so "cloak::<scheme>::<rest>" is a
		// genuine nested-helper URL that the guard must reject.
		tok := sanitizeScheme(scheme)
		if tok == "" {
			return
		}
		url := "cloak::" + tok + "::" + rest
		out, err := resolveBackendURL(nil, "", "", url)
		if err == nil {
			t.Fatalf("accepted nested helper transport %q -> backend URL %q", url, out)
		}
	})
}

// sanitizeScheme keeps the longest leading run matching git's external-helper
// token grammar: a leading [A-Za-z0-9] followed by any of [A-Za-z0-9+.-]. It
// returns "" when no usable token can be formed.
func sanitizeScheme(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlnum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		isExtra := c == '+' || c == '.' || c == '-'
		if b.Len() == 0 {
			if isAlnum {
				b.WriteByte(c)
			}
			continue
		}
		if isAlnum || isExtra {
			b.WriteByte(c)
		} else {
			break
		}
	}
	return b.String()
}
