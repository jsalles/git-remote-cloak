// Unit tests for session construction without touching any remote:
// OpenLocal wiring (paths, config, key, state lock, backend mirror) and
// its rejection of non-cloak and unconfigured remotes.
package setup

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// initRepo creates a plain repository with a file-backend master key wired
// into cloak.keyref, and chdirs into it (OpenLocal resolves the repo from
// the working directory, as git does for helpers).
func initRepo(t *testing.T) (g *gitx.G, gitDir string) {
	t.Helper()
	g = gitx.New(slog.New(slog.DiscardHandler))
	dir := t.TempDir()
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--initial-branch", "main", dir); err != nil {
		t.Fatal(err)
	}
	// Resolve through git so symlinked temp dirs (macOS /var -> /private/var)
	// compare equal to the paths OpenLocal resolves the same way.
	gitDir, err := g.Out(gitx.Opts{Dir: dir}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		t.Fatal(err)
	}

	keyPath := filepath.Join(dir, "masterkey")
	k, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := keystore.Save("file:"+keyPath, k); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "config", "cloak.keyRef", "file:"+keyPath); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	return g, gitDir
}

func TestOpenLocalWiresSession(t *testing.T) {
	g, gitDir := initRepo(t)
	host := filepath.Join(t.TempDir(), "host.git")
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "remote", "add", "origin", "cloak::"+host); err != nil {
		t.Fatal(err)
	}

	s, err := OpenLocal("origin", "cloak::"+host, io.Discard, "cli")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if s.Eng == nil || s.St == nil || s.Log == nil || s.G == nil {
		t.Fatal("session has unwired fields")
	}
	if s.Eng.Key.IsZero() {
		t.Fatal("session key not loaded")
	}
	if s.Cfg.Branch != "cloak" {
		t.Fatalf("default branch = %q, want cloak", s.Cfg.Branch)
	}
	stateRoot := filepath.Join(gitDir, "cloak", "origin")
	if s.St.Root != stateRoot {
		t.Fatalf("state root = %q, want %q", s.St.Root, stateRoot)
	}
	if _, err := os.Stat(s.St.BackendGitDir()); err != nil {
		t.Fatalf("backend mirror not initialized: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateRoot, "lock")); err != nil {
		t.Fatalf("state lock file missing: %v", err)
	}
}

func TestOpenLocalCleansStaleScratchBeforeKeyLoad(t *testing.T) {
	g, gitDir := initRepo(t)
	host := filepath.Join(t.TempDir(), "host.git")
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "remote", "add", "origin", "cloak::"+host); err != nil {
		t.Fatal(err)
	}
	st, err := state.Open(gitDir, "origin", host)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(st.TmpDir(), "pack-crash.pack")
	if err := os.WriteFile(stale, []byte("plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	keyRef, err := g.Out(gitx.Opts{GitDir: gitDir}, "config", "--get", "cloak.keyRef")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(strings.TrimPrefix(keyRef, "file:")); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("origin", "", io.Discard, "cli"); err == nil || !strings.Contains(err.Error(), "master key") {
		t.Fatalf("OpenLocal missing-key error = %v", err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale plaintext survived failed key load: %v", err)
	}
}

func TestOpenLocalDoesNotEchoExportMistakenForKeyRef(t *testing.T) {
	g, gitDir := initRepo(t)
	const secret = "cloak-key-v0:SUPER-SECRET-EXPORT-MATERIAL"
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir, SensitiveArgs: true},
		"config", "cloak.keyRef", secret); err != nil {
		t.Fatal(err)
	}
	_, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli")
	if err == nil {
		t.Fatal("export-shaped keyRef unexpectedly loaded")
	}
	if strings.Contains(err.Error(), "SUPER-SECRET") || strings.Contains(err.Error(), secret) {
		t.Fatalf("keyRef error leaked exported key material: %v", err)
	}
	if !strings.Contains(err.Error(), "configured cloak.keyRef") {
		t.Fatalf("keyRef error lost actionable context: %v", err)
	}
}

func TestOpenLocalRejectsAlteredHistoryTopology(t *testing.T) {
	commit := func(t *testing.T, g *gitx.G, gitDir, name string) string {
		t.Helper()
		worktree := filepath.Dir(gitDir)
		if err := os.WriteFile(filepath.Join(worktree, name), []byte(name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, args := range [][]string{
			{"config", "user.name", "test"},
			{"config", "user.email", "test@example.invalid"},
			{"add", name},
			{"commit", "-q", "-m", name},
		} {
			if _, _, err := g.Run(gitx.Opts{GitDir: gitDir, Dir: worktree}, args...); err != nil {
				t.Fatal(err)
			}
		}
		head, err := g.Out(gitx.Opts{GitDir: gitDir}, "rev-parse", "HEAD")
		if err != nil {
			t.Fatal(err)
		}
		return head
	}

	t.Run("shallow repository", func(t *testing.T) {
		g, gitDir := initRepo(t)
		head := commit(t, g, gitDir, "one.md")
		if err := os.WriteFile(filepath.Join(gitDir, "shallow"), []byte(head+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli"); err == nil || !strings.Contains(err.Error(), "shallow repositories") {
			t.Fatalf("OpenLocal shallow error = %v", err)
		}
	})

	t.Run("replace objects", func(t *testing.T) {
		g, gitDir := initRepo(t)
		first := commit(t, g, gitDir, "one.md")
		second := commit(t, g, gitDir, "two.md")
		if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "replace", first, second); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli"); err == nil || !strings.Contains(err.Error(), "replace objects") {
			t.Fatalf("OpenLocal replace error = %v", err)
		}
	})

	t.Run("grafts", func(t *testing.T) {
		g, gitDir := initRepo(t)
		head := commit(t, g, gitDir, "one.md")
		grafts := filepath.Join(gitDir, "info", "grafts")
		if err := os.MkdirAll(filepath.Dir(grafts), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(grafts, []byte(head+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli"); err == nil || !strings.Contains(err.Error(), "grafts") {
			t.Fatalf("OpenLocal graft error = %v", err)
		}
	})
}

func TestOpenLocalRejectsTrackedGitLFS(t *testing.T) {
	g, gitDir := initRepo(t)
	worktree := filepath.Dir(gitDir)
	if err := os.WriteFile(filepath.Join(worktree, ".gitattributes"), []byte("*.bin filter=lfs diff=lfs merge=lfs -text\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(worktree, "asset.bin"), []byte("content\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir, Dir: worktree}, "add", ".gitattributes", "asset.bin"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted a tracked Git LFS path")
	} else if !strings.Contains(err.Error(), "filter=lfs") || !strings.Contains(err.Error(), "bypasses cloak") {
		t.Fatalf("Git LFS rejection is not actionable: %v", err)
	}
}

func TestOpenLocalRejectsGitLFSPrePushHook(t *testing.T) {
	_, gitDir := initRepo(t)
	hook := filepath.Join(gitDir, "hooks", "pre-push")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\ngit lfs pre-push \"$@\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli")
	if err != nil {
		t.Fatalf("OpenLocal rejected a non-executable hook Git would ignore: %v", err)
	}
	s.Close()
	if err := os.Chmod(hook, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("origin", "cloak::/unused", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted an active pre-push hook")
	} else if !strings.Contains(err.Error(), "Git LFS") || !strings.Contains(err.Error(), "plaintext transport") {
		t.Fatalf("pre-push hook rejection is not actionable: %v", err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err = OpenLocal("origin", "cloak::/unused", io.Discard, "cli")
	if err != nil {
		t.Fatalf("OpenLocal rejected an ordinary pre-push hook: %v", err)
	}
	s.Close()
}

// State keying per backend URL (issue #3): the remote name keys the state dir
// only for the remote's fetch URL; every other URL -- extra push URLs,
// unconfigured names -- gets its own url-hash dir with an independent pin set,
// and a Selector so alarm messages print the accept command that reaches it.
func TestOpenLocalStateKeying(t *testing.T) {
	mustGit := func(t *testing.T, g *gitx.G, gitDir string, args ...string) {
		t.Helper()
		if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, args...); err != nil {
			t.Fatal(err)
		}
	}
	open := func(t *testing.T, remote, url string) *Session {
		t.Helper()
		s, err := OpenLocal(remote, url, io.Discard, "helper")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	expect := func(t *testing.T, s *Session, root, selector string) {
		t.Helper()
		defer s.Close()
		if s.St.Root != root {
			t.Fatalf("state root = %q, want %q", s.St.Root, root)
		}
		if s.St.Selector != selector {
			t.Fatalf("selector = %q, want %q", s.St.Selector, selector)
		}
	}

	t.Run("pushurl keys by url hash", func(t *testing.T) {
		g, gitDir := initRepo(t)
		hostA := filepath.Join(t.TempDir(), "a.git")
		hostB := filepath.Join(t.TempDir(), "b.git")
		mustGit(t, g, gitDir, "remote", "add", "origin", "cloak::"+hostA)
		mustGit(t, g, gitDir, "config", "--add", "remote.origin.pushurl", "cloak::"+hostA)
		mustGit(t, g, gitDir, "config", "--add", "remote.origin.pushurl", "cloak::"+hostB)

		// The fetch URL (also the first pushurl) keys by remote name, exactly
		// as a single-URL remote does.
		expect(t, open(t, "origin", "cloak::"+hostA),
			filepath.Join(gitDir, "cloak", "origin"), "")
		// The extra pushurl gets an independent url-hash dir.
		expect(t, open(t, "origin", "cloak::"+hostB),
			filepath.Join(gitDir, "cloak", state.DirName("", hostB)), "--url cloak::"+hostB)
	})

	t.Run("cli empty url keys by remote name", func(t *testing.T) {
		g, gitDir := initRepo(t)
		host := filepath.Join(t.TempDir(), "host.git")
		mustGit(t, g, gitDir, "remote", "add", "mirror", "cloak::"+host)
		expect(t, open(t, "mirror", ""),
			filepath.Join(gitDir, "cloak", "mirror"), "--remote mirror")
	})

	t.Run("insteadOf-rewritten fetch url still keys by remote name", func(t *testing.T) {
		g, gitDir := initRepo(t)
		host := filepath.Join(t.TempDir(), "real.git")
		mustGit(t, g, gitDir, "config", "url.cloak::"+host+".insteadOf", "cloak::SHORT")
		mustGit(t, g, gitDir, "remote", "add", "origin", "cloak::SHORT")
		// git hands the helper the rewritten address, not the raw config value.
		expect(t, open(t, "origin", "cloak::"+host),
			filepath.Join(gitDir, "cloak", "origin"), "")
	})

	t.Run("inner insteadOf rewrite still keys by remote name", func(t *testing.T) {
		g, gitDir := initRepo(t)
		const alias = "gh:org/repo.git"
		const effective = "git@github.com:org/repo.git"
		mustGit(t, g, gitDir, "config", "url.git@github.com:.insteadOf", "gh:")
		mustGit(t, g, gitDir, "remote", "add", "origin", "cloak::"+alias)
		expect(t, open(t, "origin", "cloak::"+effective),
			filepath.Join(gitDir, "cloak", "origin"), "")
	})

	t.Run("unconfigured remote name keys by url hash", func(t *testing.T) {
		_, gitDir := initRepo(t)
		host := filepath.Join(t.TempDir(), "host.git")
		expect(t, open(t, "nosuchremote", "cloak::"+host),
			filepath.Join(gitDir, "cloak", state.DirName("", host)), "--url cloak::"+host)
	})

	t.Run("scp ssh username remains executable in selector", func(t *testing.T) {
		_, gitDir := initRepo(t)
		const host = "git@github.com:org/repo.git"
		expect(t, open(t, "nosuchremote", "cloak::"+host),
			filepath.Join(gitDir, "cloak", state.DirName("", host)), "--url cloak::"+host)
	})

	t.Run("selector shell-quotes unsafe URL characters", func(t *testing.T) {
		g, gitDir := initRepo(t)
		const host = "/tmp/my repo;echo PWN.git"
		_, selector := stateIdentity(g, gitDir, "origin", host, true)
		if want := "--url 'cloak::/tmp/my repo;echo PWN.git'"; selector != want {
			t.Fatalf("selector = %q, want %q", selector, want)
		}
	})
}

func TestOpenLocalRejectsCredentialBearingURL(t *testing.T) {
	initRepo(t)
	const backendURL = "https://alice-sentinel:password-sentinel@example.invalid/org/repo.git?token=token-sentinel#fragment-sentinel"
	_, err := OpenLocal("origin", "cloak::"+backendURL, io.Discard, "cli")
	if err == nil {
		t.Fatal("OpenLocal accepted credentials embedded in a backend URL")
	}
	for _, secret := range []string{"alice-sentinel", "password-sentinel", "token-sentinel", "fragment-sentinel"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("credential rejection leaked %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "credential helper") {
		t.Fatalf("credential rejection is not actionable: %v", err)
	}
}

func TestResolveBackendURLErrorsRedactCredentials(t *testing.T) {
	g, gitDir := initRepo(t)
	const rawURL = "https://alice-sentinel:password-sentinel@example.invalid/repo.git?token=token-sentinel#fragment-sentinel"
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "remote", "add", "origin", rawURL); err != nil {
		t.Fatal(err)
	}
	_, err := resolveBackendURL(g, gitDir, "origin", "")
	if err == nil {
		t.Fatal("resolveBackendURL accepted a non-cloak remote")
	}
	for _, secret := range []string{"alice-sentinel", "password-sentinel", "token-sentinel", "fragment-sentinel"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("non-cloak error leaked %q: %v", secret, err)
		}
	}
	if !strings.Contains(err.Error(), "https://example.invalid/repo.git") {
		t.Fatalf("non-cloak error lost useful redacted URL context: %v", err)
	}

	_, err = resolveBackendURL(g, gitDir, "origin", "cloak::ext::https://alice-sentinel:password-sentinel@example.invalid/repo")
	if err == nil {
		t.Fatal("resolveBackendURL accepted a nested helper URL")
	}
	if strings.Contains(err.Error(), "alice-sentinel") || strings.Contains(err.Error(), "password-sentinel") {
		t.Fatalf("transport validation error leaked credentials: %v", err)
	}
}

func TestResolveBackendURLRejectsCredentialBearingRewrite(t *testing.T) {
	g, gitDir := initRepo(t)
	const rewritten = "https://token-sentinel@example.invalid/"
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir, SensitiveArgs: true},
		"config", "url."+rewritten+".insteadOf", "gh:"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "remote", "add", "origin", "cloak::gh:org/repo.git"); err != nil {
		t.Fatal(err)
	}
	_, err := resolveBackendURL(g, gitDir, "origin", "")
	if err == nil {
		t.Fatal("resolveBackendURL accepted an alias rewritten to credential-bearing HTTPS")
	}
	if strings.Contains(err.Error(), "token-sentinel") {
		t.Fatalf("rewrite rejection leaked embedded credential: %v", err)
	}
	if !strings.Contains(err.Error(), "credential helper") {
		t.Fatalf("rewrite rejection is not actionable: %v", err)
	}
}

func TestResolveBackendURLRejectsHelperRewrite(t *testing.T) {
	g, gitDir := initRepo(t)
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir},
		"config", "url.ext::sh -c 'false'.insteadOf", "unsafe:"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "remote", "add", "origin", "cloak::unsafe:repo"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveBackendURL(g, gitDir, "origin", ""); err == nil || !strings.Contains(err.Error(), "remote-helper transport") {
		t.Fatalf("helper rewrite was not rejected: %v", err)
	}
}

func TestResolveBackendURLTreatsLeadingDashAsURLData(t *testing.T) {
	g, gitDir := initRepo(t)
	got, err := resolveBackendURL(g, gitDir, "origin", "cloak::--upload-pack=evil")
	if err != nil {
		t.Fatal(err)
	}
	if got != "--upload-pack=evil" {
		t.Fatalf("leading-dash URL resolved as %q, want literal URL", got)
	}
}

func TestOpenLocalRejectsNonCloakRemote(t *testing.T) {
	g, gitDir := initRepo(t)
	if _, _, err := g.Run(gitx.Opts{GitDir: gitDir},
		"remote", "add", "origin", "https://example.invalid/repo.git"); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal("origin", "", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted a non-cloak:: remote")
	}
}

func TestOpenLocalRejectsUnknownRemote(t *testing.T) {
	initRepo(t)
	if _, err := OpenLocal("nosuch", "", io.Discard, "cli"); err == nil {
		t.Fatal("OpenLocal accepted a remote with no configured URL")
	}
}

// A backend URL using git's remote-helper syntax (ext::, fd::, nested cloak::)
// must be refused so a malicious cloak:: URL cannot reach git's
// arbitrary-command transports. Real transports and local paths must pass.
func TestOpenLocalTransportGuard(t *testing.T) {
	rejected := []string{
		"cloak::ext::sh -c 'touch pwned'",
		"cloak::fd::3",
		"cloak::cloak::" + filepath.Join(t.TempDir(), "nested.git"),
		"cloak::evil://example.invalid/repo.git",
		"cloak::1evil://example.invalid/repo.git",
	}
	for _, url := range rejected {
		initRepo(t)
		if s, err := OpenLocal("origin", url, io.Discard, "cli"); err == nil {
			s.Close()
			t.Fatalf("OpenLocal accepted dangerous transport %q", url)
		}
	}
	accepted := []string{
		"cloak::" + filepath.Join(t.TempDir(), "bare.git"), // local path
		"cloak::file://" + filepath.Join(t.TempDir(), "f.git"),
		"cloak::ssh://git@example.invalid/r.git",
		"cloak::git@example.invalid:r.git", // scp-like SSH
		"cloak::https://example.invalid/r.git",
	}
	for _, url := range accepted {
		initRepo(t)
		s, err := OpenLocal("origin", url, io.Discard, "cli")
		if err != nil {
			t.Fatalf("OpenLocal rejected legitimate transport %q: %v", url, err)
		}
		s.Close()
	}
}
