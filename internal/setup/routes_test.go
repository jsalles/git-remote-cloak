// Tests for the plaintext-route guard: a cloak remote whose url/pushurl list
// also contains a URL Git would not hand to git-remote-cloak must be refused
// by every session (helper and CLI), and remote.<name>.vcs=cloak must be
// accepted as routing every URL through cloak.
package setup

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func TestOpenLocalPlaintextRouteGuard(t *testing.T) {
	cases := []struct {
		name   string
		config [][]string // extra `git config` argument lists after `remote add origin cloak::<host>`
		helper string     // URL git hands the helper ("" = CLI session)
		ok     bool
	}{
		{name: "single cloak url", ok: true},
		{name: "plain pushurl", config: [][]string{{"remote.origin.pushurl", "<plain>"}}},
		{name: "extra plain url", config: [][]string{{"--add", "remote.origin.url", "<plain>"}}},
		{name: "extra plain url seen by helper", config: [][]string{{"--add", "remote.origin.url", "<plain>"}}, helper: "cloak::<host>"},
		{name: "cloak pushurls only", config: [][]string{
			{"remote.origin.pushurl", "cloak::<host>"},
			{"--add", "remote.origin.pushurl", "cloak::<mirror>"},
		}, ok: true},
		{name: "insteadOf strips cloak prefix", config: [][]string{{"url.<plain>.insteadOf", "cloak::<host>"}}},
		{name: "vcs cloak routes plain urls", config: [][]string{
			{"remote.origin.vcs", "cloak"},
			{"remote.origin.pushurl", "<plain>"},
		}, ok: true},
		{name: "vcs cloak with another helper", config: [][]string{
			{"remote.origin.vcs", "cloak"},
			{"remote.origin.pushurl", "ext::sh -c true"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, gitDir := initRepo(t)
			dir := t.TempDir()
			host := filepath.Join(dir, "host.git")
			subst := strings.NewReplacer("<host>", host, "<plain>", filepath.Join(dir, "plain.git"),
				"<mirror>", filepath.Join(dir, "mirror.git"))
			mustGit(t, g, gitDir, "remote", "add", "origin", "cloak::"+host)
			for _, args := range tc.config {
				full := []string{"config"}
				for _, a := range args {
					full = append(full, subst.Replace(a))
				}
				mustGit(t, g, gitDir, full...)
			}
			s, err := OpenLocal("origin", subst.Replace(tc.helper), io.Discard, "helper")
			if s != nil {
				s.Close()
			}
			if tc.ok {
				if err != nil {
					t.Fatalf("OpenLocal refused a cloak-only remote: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("OpenLocal accepted a remote with a plaintext route")
			}
			// The route guard or, for the remote's first URL, CLI URL resolution
			// may refuse first; either way the session must not open.
			msg := err.Error()
			if kind, _ := cloakerr.KindOf(err); kind != cloakerr.LocalGit ||
				!(strings.Contains(msg, "does not go through cloak") || strings.Contains(msg, "not a cloak:: remote")) {
				t.Fatalf("unexpected refusal: %v", err)
			}
		})
	}
}

// The CLI used to check the cloak:: prefix on the LAST remote.<name>.url while
// operating on the FIRST, so `git cloak status` vouched for a remote whose
// effective fetch URL was plain.
func TestResolveBackendURLValidatesFirstURL(t *testing.T) {
	g, gitDir := initRepo(t)
	dir := t.TempDir()
	mustGit(t, g, gitDir, "remote", "add", "origin", filepath.Join(dir, "plain.git"))
	mustGit(t, g, gitDir, "config", "--add", "remote.origin.url", "cloak::"+filepath.Join(dir, "host.git"))
	if _, err := resolveBackendURL(g, gitDir, "origin", ""); err == nil || !strings.Contains(err.Error(), "not a cloak:: remote") {
		t.Fatalf("plain first URL accepted by CLI resolution: %v", err)
	}
}

func TestResolveBackendURLAcceptsVCSCloakRemote(t *testing.T) {
	g, gitDir := initRepo(t)
	host := filepath.Join(t.TempDir(), "host.git")
	mustGit(t, g, gitDir, "remote", "add", "origin", host)
	mustGit(t, g, gitDir, "config", "remote.origin.vcs", "cloak")
	got, err := resolveBackendURL(g, gitDir, "origin", "")
	if err != nil {
		t.Fatalf("vcs=cloak remote refused: %v", err)
	}
	if got != host {
		t.Fatalf("backend URL = %q, want %q", got, host)
	}
}

func mustGit(t *testing.T, g *gitx.G, gitDir string, args ...string) {
	t.Helper()
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, args...); err != nil {
		t.Fatal(err)
	}
}
