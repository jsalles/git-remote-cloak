// Regression scenarios for trust-anchor robustness: a stale applied-pack cache
// after local gc must not freeze the rollback pin behind a false tamper alarm,
// and accepting an empty remote must not let the host restore an older state
// of the same repository silently.
package integration

import (
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// TestPrunedUntrackedRefDoesNotFreezePin: objects of a carrier ref that a
// single-branch clone does not track arrive in an applied pack, and local gc
// prunes them. The next generation used to raise a false TAMPER ALARM and leave
// the rollback pin behind, so a host rewind to the old generation went
// undetected. The fetch must now repair from the live packs and pin.
func TestPrunedUntrackedRefDoesNotFreezePin(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)
	a := harness.NewClient(t, "a", key)
	a.InitRepo()
	a.WriteFile("readme.md", "initial\n")
	a.Commit("c0")
	a.MustGit("checkout", "-q", "-b", "side")
	a.WriteFile("side.md", "only on side\n")
	a.Commit("s1")
	sideTip := a.HeadOID()
	a.MustGit("checkout", "-q", "main")
	a.AddOrigin(host.Dir)
	a.MustGit("push", "-u", "origin", "main", "side") // one push, one pack

	b := harness.NewClient(t, "b", key)
	if out, errb, err := b.Git("clone", "--single-branch", "--branch", "main", "cloak::"+host.Dir, b.Dir); err != nil {
		t.Fatalf("single-branch clone: %v\n%s\n%s", err, out, errb)
	}
	b.MustGit("reflog", "expire", "--expire=now", "--all")
	b.MustGit("-c", "gc.pruneExpire=now", "gc", "--prune=now", "--quiet")
	if _, _, err := b.Git("cat-file", "-e", sideTip); err == nil {
		t.Fatal("precondition: gc did not prune the untracked side branch objects")
	}

	previousCarrier := host.Git("rev-parse", "refs/heads/cloak")
	// Without consolidation the new generation adds a pack instead of merging
	// the old one, so b's stale applied set is what decides what it downloads.
	a.MustGit("config", "cloak.geometricFactor", "0")
	a.WriteFile("more.md", "second generation\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")
	want := pinGeneration(t, a)

	if _, stderr, err := b.Git("fetch", "origin"); err != nil {
		t.Fatalf("fetch after local gc raised: %v\n%s", err, stderr)
	}
	if got := pinGeneration(t, b); got != want {
		t.Fatalf("rollback pin = %d after a successful fetch, want %d", got, want)
	}

	host.Git("update-ref", "refs/heads/cloak", previousCarrier)
	if _, stderr, err := b.Git("fetch", "origin"); err == nil || !strings.Contains(stderr, "ROLLBACK") {
		t.Fatalf("host rewind not detected: err=%v\n%s", err, stderr)
	}
}

// TestAcceptedEmptyRemoteRefusesRestoredOldState: the host deletes the carrier,
// the owner accepts the "remote is empty" alarm, then the host restores an old
// carrier commit. That replay used to be trusted on first use.
func TestAcceptedEmptyRemoteRefusesRestoredOldState(t *testing.T) {
	host, _, a := pushSetup(t)
	oldCarrier := host.Git("rev-parse", "refs/heads/cloak")
	for _, name := range []string{"c1", "c2"} {
		a.WriteFile(name+".md", name+"\n")
		a.Commit(name)
		a.MustGit("push", "origin", "main")
	}

	host.Git("update-ref", "-d", "refs/heads/cloak")
	if _, stderr, err := a.Git("fetch", "origin"); err == nil || !strings.Contains(stderr, "ROLLBACK") {
		t.Fatalf("precondition: deleted carrier not alarmed: err=%v\n%s", err, stderr)
	}
	if out, stderr, err := a.Cloak("accept-rollback", "--force-insecure"); err != nil {
		t.Fatalf("accept-rollback on empty remote: %v\n%s\n%s", err, out, stderr)
	}

	host.Git("update-ref", "refs/heads/cloak", oldCarrier)
	if _, stderr, err := a.Git("fetch", "origin"); err == nil || !strings.Contains(stderr, "ROLLBACK") {
		t.Fatalf("restored old carrier accepted after accepting an empty remote: err=%v\n%s", err, stderr)
	}
}
