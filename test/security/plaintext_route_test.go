// End-to-end proof that cloak refuses to keep syncing when plaintext can leave
// the machine around it: a plain pushurl on the cloak remote makes the helper
// fail on fetch (so a pull-then-push tool stops before pushing), `git cloak
// status` refuses instead of reporting a healthy remote, and the first push
// onto a host that already holds plaintext branches is refused.
package security

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestPlainPushURLStopsCloakSessions(t *testing.T) {
	key := harness.NewKeyFile(t)
	host := harness.NewHost(t)
	c := harness.NewClient(t, "route-guard", key)
	c.InitRepo()
	c.AddOrigin(host.Dir)
	c.WriteFile("note.md", "private\n")
	c.Commit("first")
	c.MustGit("push", "-u", "origin", "HEAD:refs/heads/main")

	plain := harness.NewHost(t)
	c.MustGit("remote", "set-url", "--push", "origin", plain.Dir)

	if _, stderr, err := c.Git("fetch", "origin"); err == nil || !strings.Contains(stderr, "does not go through cloak") {
		t.Fatalf("fetch with a plain pushurl: err=%v stderr=%s; want route-guard refusal", err, stderr)
	}
	if _, stderr, err := c.Cloak("status"); err == nil || !strings.Contains(stderr, "does not go through cloak") {
		t.Fatalf("status with a plain pushurl: err=%v stderr=%s; want route-guard refusal", err, stderr)
	}

	// remote.<name>.vcs=cloak routes every URL through the helper, so the same
	// pushurl is then encrypted and the sessions work again.
	c.MustGit("config", "remote.origin.vcs", "cloak")
	c.MustGit("fetch", "origin")
	c.MustCloak("status")
}

func TestFirstPushRefusesHostWithPlaintextBranch(t *testing.T) {
	key := harness.NewKeyFile(t)
	host := harness.NewHost(t)

	// A plain clone left readable history on the host before cloak was used.
	old := harness.NewClient(t, "old-plain", key)
	old.InitRepo()
	old.WriteFile("diary.md", "plaintext history\n")
	old.Commit("plain")
	old.MustGit("push", host.Dir, "HEAD:refs/heads/main")

	c := harness.NewClient(t, "migrator", key)
	c.InitRepo()
	c.AddOrigin(host.Dir)
	c.WriteFile("note.md", "private\n")
	c.Commit("first")
	status, _, err := c.Cloak("status")
	if err != nil || !strings.Contains(status, "NOT encrypted") || !strings.Contains(status, "refs/heads/main") {
		t.Fatalf("status did not warn about the plaintext host branch: err=%v\n%s", err, status)
	}
	if _, stderr, err := c.Git("push", "origin", "HEAD:refs/heads/main"); err == nil || !strings.Contains(stderr, "not written by cloak") {
		t.Fatalf("first push onto a host with plaintext refs: err=%v stderr=%s; want refusal", err, stderr)
	}
	if out := host.Git("for-each-ref", "--format=%(refname)"); strings.Contains(out, "refs/heads/cloak") {
		t.Fatalf("refused first push still created the carrier: %s", out)
	}
}
