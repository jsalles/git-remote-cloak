// Unit tests for the backend mirror that need no remote host: commit
// determinism (fixed identity, generation-derived dates) and the structure
// of built trees. Network behavior is covered by the integration suite.
package backend

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

func open(t *testing.T) *Backend {
	t.Helper()
	lg := slog.New(slog.DiscardHandler)
	b, err := Open(gitx.New(lg), t.TempDir()+"/backend.git", "/nonexistent-host", "cloak", lg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenRejectsCredentialURLWithoutLoggingIt(t *testing.T) {
	const rawURL = "https://alice-sentinel:password-sentinel@example.invalid/org/repo.git?token=token-sentinel#fragment-sentinel"
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := gitx.New(lg)
	gitDir := filepath.Join(t.TempDir(), "backend.git")
	if _, err := Open(g, gitDir, rawURL, "cloak", lg); err == nil {
		t.Fatal("Open accepted credentials embedded in its transport URL")
	} else if !strings.Contains(err.Error(), "credential helper") {
		t.Fatalf("credential rejection is not actionable: %v", err)
	}
	if _, err := os.Stat(gitDir); !os.IsNotExist(err) {
		t.Fatalf("unsafe URL was persisted before rejection: stat error %v", err)
	}
	for _, secret := range []string{"alice-sentinel", "password-sentinel", "token-sentinel", "fragment-sentinel"} {
		if strings.Contains(logs.String(), secret) {
			t.Fatalf("backend setup log leaked %q: %s", secret, logs.String())
		}
	}
	if logs.Len() != 0 {
		t.Fatalf("unsafe URL reached git/logging before preflight rejection: %s", logs.String())
	}
}

func TestOpenPruneCannotFollowInheritedObjectDirectory(t *testing.T) {
	lg := slog.New(slog.DiscardHandler)
	g := gitx.New(lg)
	source := filepath.Join(t.TempDir(), "source.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", source); err != nil {
		t.Fatal(err)
	}
	oid, err := g.Out(gitx.Opts{GitDir: source, Stdin: strings.NewReader("source sentinel")},
		"hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(source, "objects", oid[:2], oid[2:])
	if _, err := os.Stat(objectPath); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GIT_OBJECT_DIRECTORY", filepath.Join(source, "objects"))
	if _, err := Open(g, filepath.Join(t.TempDir(), "backend.git"), "/nonexistent-host", "cloak", lg); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(objectPath); err != nil {
		t.Fatalf("backend initialization/prune touched redirected source object: %v", err)
	}
}

// An inherited GIT_CONFIG used to become the target of every mirror `git
// config` write, planting the carrier as a plain remote.origin in (for example)
// the user's global config, from where ordinary pushes sent plaintext.
func TestOpenIgnoresInheritedGitConfig(t *testing.T) {
	redirected := filepath.Join(t.TempDir(), "gitconfig")
	const original = "[user]\n\tname = someone\n"
	if err := os.WriteFile(redirected, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG", redirected)
	lg := slog.New(slog.DiscardHandler)
	g := gitx.New(lg)
	b, err := Open(g, filepath.Join(t.TempDir(), "backend.git"), "/nonexistent-host", "cloak", lg)
	if err != nil {
		t.Fatalf("Open with inherited GIT_CONFIG: %v", err)
	}
	b.disablePartial()
	got, err := os.ReadFile(redirected)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Fatalf("mirror configuration leaked into GIT_CONFIG target:\n%s", got)
	}
	url, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "config", "--file", b.configPath(), "--get", "remote.origin.url")
	if err != nil || url != "/nonexistent-host" {
		t.Fatalf("mirror remote.origin.url = %q, %v; want /nonexistent-host", url, err)
	}
}

func TestOpenPinsBackendObjectFormatToSHA1(t *testing.T) {
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, []byte("[init]\n\tdefaultObjectFormat = sha256\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	lg := slog.New(slog.DiscardHandler)
	g := gitx.New(lg)
	b, err := Open(g, filepath.Join(t.TempDir(), "backend.git"), "/nonexistent-host", "cloak", lg)
	if err != nil {
		t.Fatal(err)
	}
	format, err := g.Out(gitx.Opts{GitDir: b.gitDir}, "rev-parse", "--show-object-format")
	if err != nil {
		t.Fatal(err)
	}
	if format != "sha1" {
		t.Fatalf("backend format = %q, want sha1", format)
	}
}

func TestOpenRejectsCredentialBearingPushInsteadOf(t *testing.T) {
	global := filepath.Join(t.TempDir(), "gitconfig")
	const secretURL = "https://token-sentinel@example.invalid/"
	if err := os.WriteFile(global, []byte("[url \""+secretURL+"\"]\n\tpushInsteadOf = gh:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	_, err := Open(gitx.New(lg), filepath.Join(t.TempDir(), "backend.git"), "gh:org/repo.git", "cloak", lg)
	if err == nil {
		t.Fatal("Open accepted a credential-bearing pushInsteadOf rewrite")
	}
	for _, output := range []string{err.Error(), logs.String()} {
		if strings.Contains(output, "token-sentinel") {
			t.Fatalf("pushInsteadOf rejection leaked credential: %q", output)
		}
	}
	if !strings.Contains(err.Error(), "credential helper") {
		t.Fatalf("pushInsteadOf rejection is not actionable: %v", err)
	}
}

func TestOpenRejectsHelperPushInsteadOf(t *testing.T) {
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, []byte("[url \"ext::sh -c false\"]\n\tpushInsteadOf = gh:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_ALLOW_PROTOCOL", "ext:file:ssh:https")

	lg := slog.New(slog.DiscardHandler)
	_, err := Open(gitx.New(lg), filepath.Join(t.TempDir(), "backend.git"), "gh:org/repo.git", "cloak", lg)
	if err == nil || !strings.Contains(err.Error(), "remote-helper transport") {
		t.Fatalf("Open did not reject helper pushInsteadOf: %v", err)
	}
}

func TestOpenRejectsUnknownSchemePushInsteadOf(t *testing.T) {
	global := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(global, []byte("[url \"evil://example.invalid/\"]\n\tpushInsteadOf = gh:\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_ALLOW_PROTOCOL", "evil:file:ssh:https")

	lg := slog.New(slog.DiscardHandler)
	_, err := Open(gitx.New(lg), filepath.Join(t.TempDir(), "backend.git"), "gh:org/repo.git", "cloak", lg)
	if err == nil || !strings.Contains(err.Error(), "external remote helper") {
		t.Fatalf("Open did not reject unknown-scheme pushInsteadOf: %v", err)
	}
}

func TestClassifyProbedPushState(t *testing.T) {
	tests := []struct {
		name                string
		commit, expectedOld string
		head                string
		exists              bool
		want                PushResult
	}{
		{"attempt accepted", "new", "old", "new", true, PushOK},
		{"concurrent update", "new", "old", "other", true, PushCASLost},
		{"concurrent deletion", "new", "old", "", false, PushCASLost},
		{"concurrent initial create", "new", "", "other", true, PushCASLost},
		{"stable existing head", "new", "old", "old", true, PushFailed},
		{"stable absent head", "new", "", "", false, PushFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyProbedPushState(tc.commit, tc.expectedOld, tc.head, tc.exists); got != tc.want {
				t.Fatalf("result = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestIsMissingPacksTree pins the sentinel detection PackBlobOIDs uses to tell a
// manifest-only commit (no packs/ subtree -> empty pack set) apart from a real
// ls-tree failure (surface it as LocalGit). The wrapped-error case is the
// regression guard: the prior direct type assertion (err.(*gitx.GitError))
// returned false for a wrapped GitError, which would have escalated a benign
// "no packs subtree" into a hard error and failed the push; errors.As sees
// through the wrap.
func TestIsMissingPacksTree(t *testing.T) {
	missing := &gitx.GitError{Args: []string{"ls-tree"}, Stderr: "fatal: Not a valid object name HEAD:packs"}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"bare missing subtree", missing, true},
		{"wrapped missing subtree", fmt.Errorf("list remote pack blobs: %w", missing), true},
		{"other git failure", &gitx.GitError{Args: []string{"ls-tree"}, Stderr: "fatal: not a git repository"}, false},
		{"non-git error", fmt.Errorf("some other error"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		if got := isMissingPacksTree(c.err); got != c.want {
			t.Errorf("%s: isMissingPacksTree = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBuildCommitDeterministic(t *testing.T) {
	b1, b2 := open(t), open(t)
	build := func(b *Backend) string {
		t.Helper()
		moid, err := b.HashObject(strings.NewReader("manifest-ciphertext"))
		if err != nil {
			t.Fatal(err)
		}
		poid, err := b.HashObject(strings.NewReader("pack-ciphertext"))
		if err != nil {
			t.Fatal(err)
		}
		id := strings.Repeat("ab", 32)
		commit, err := b.BuildCommit("", moid, map[string]string{id: poid}, 7)
		if err != nil {
			t.Fatal(err)
		}
		return commit
	}
	c1, c2 := build(b1), build(b2)
	if c1 != c2 {
		t.Fatalf("identical inputs produced different commits: %s vs %s (nondeterministic metadata)", c1, c2)
	}
}

func TestBuildCommitTreeShape(t *testing.T) {
	b := open(t)
	moid, _ := b.HashObject(strings.NewReader("m"))
	poid, _ := b.HashObject(strings.NewReader("p"))
	id := strings.Repeat("cd", 32)
	commit, err := b.BuildCommit("", moid, map[string]string{id: poid}, 1)
	if err != nil {
		t.Fatal(err)
	}
	out, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "ls-tree", "-r", "--name-only", commit)
	if err != nil {
		t.Fatal(err)
	}
	want := "manifest.age\npacks/" + id + ".age"
	if out != want {
		t.Fatalf("tree = %q, want %q", out, want)
	}
	meta, err := b.g.Out(gitx.Opts{GitDir: b.gitDir}, "log", "-1", "--format=%an|%ae|%s", commit)
	if err != nil {
		t.Fatal(err)
	}
	if meta != "cloak|cloak@cloak|cloak" {
		t.Fatalf("commit metadata = %q", meta)
	}
}
