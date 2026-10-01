// Tests for the first-push foreign-ref check: creating the carrier on a host
// repository that already holds other refs (typically the plaintext history of
// a notes repository switched to cloak::) must be refused unless explicitly
// allowed, because those refs stay unencrypted on the host.
package engine

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

func TestFirstPushRefusesHostWithForeignRefs(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	plantPlaintextBranch(t, g, host, "refs/heads/main")
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, host, key)
	a.commit(t, "note.md", "secret")

	_, _, err = a.e.Push(a.load(t), []RefUpdate{{Src: mainRef, Dst: mainRef}}, false)
	if err == nil || !strings.Contains(err.Error(), "not written by cloak") {
		t.Fatalf("first push onto a host with plaintext refs: err = %v, want refusal", err)
	}
	if _, err := g.Out(gitx.Opts{GitDir: host}, "rev-parse", "--verify", "refs/heads/cloak"); err == nil {
		t.Fatal("refused push still created the carrier branch")
	}

	a.e.Cfg.AllowHostRefs = true
	if _, rs := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef}); rs.Manifest == nil {
		t.Fatal("explicitly allowed first push did not create the carrier")
	}
}

// plantPlaintextBranch writes a commit with a plaintext file straight into the
// host repository under ref, as a plain (non-cloak) push would.
func plantPlaintextBranch(t *testing.T, g *gitx.G, host, ref string) {
	t.Helper()
	blob, err := g.Out(gitx.Opts{GitDir: host, Stdin: strings.NewReader("plaintext note\n")}, "hash-object", "-w", "--stdin")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := g.Out(gitx.Opts{GitDir: host, Stdin: strings.NewReader("100644 blob " + blob + "\tnote.md\n")}, "mktree")
	if err != nil {
		t.Fatal(err)
	}
	commit, err := g.Out(gitx.Opts{GitDir: host, Scrub: true, Env: []string{
		"GIT_AUTHOR_NAME=u", "GIT_AUTHOR_EMAIL=u@u", "GIT_COMMITTER_NAME=u", "GIT_COMMITTER_EMAIL=u@u",
	}}, "commit-tree", tree, "-m", "plain")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "update-ref", ref, commit); err != nil {
		t.Fatal(err)
	}
}
