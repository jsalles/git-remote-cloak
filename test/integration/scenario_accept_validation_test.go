// Regression scenarios for explicit trust-anchor changes: an accept command
// must validate the carrier's live packs before replacing either local pin.
package integration

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestAcceptRollbackRejectsMissingPackAndRestoresPins(t *testing.T) {
	host, key, a := pushSetup(t)
	oldBackendHead := host.Git("rev-parse", "cloak")

	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	a.WriteFile("more.md", "second generation\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")
	b.MustGit("fetch", "origin")
	pinBefore, repoIDBefore := readTrustAnchors(t, b)

	// Roll back to generation 1, then remove the pack that its authenticated
	// manifest promises. Manifest-only acceptance used to pin this state.
	host.Git("update-ref", "refs/heads/cloak", oldBackendHead)
	host.RemoveTreeEntry(t, "cloak", onlyHostPackPath(t, host))

	_, stderr, err := b.Cloak("accept-rollback", "--remote", "origin", "--force-insecure")
	if err == nil {
		t.Fatal("accept-rollback accepted a manifest whose live pack is missing")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("missing pack was not reported as tamper: %s", stderr)
	}
	assertTrustAnchorsEqual(t, b, pinBefore, repoIDBefore)
}

func TestAcceptRepoChangeRejectsCorruptPackAndRestoresPins(t *testing.T) {
	hostA, key, _ := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(hostA.Dir)
	pinBefore, repoIDBefore := readTrustAnchors(t, b)

	hostB := harness.NewHost(t)
	writer := harness.NewClient(t, "writer", key)
	writer.InitRepo()
	writer.WriteFile("different.md", "different repository\n")
	writer.Commit("different root")
	writer.AddOrigin(hostB.Dir)
	writer.MustGit("push", "-u", "origin", "main")
	validBackendHead := hostB.Git("rev-parse", "cloak")
	corruptHostBlob(t, hostB, "packs/", func(raw []byte) []byte {
		out := append([]byte(nil), raw...)
		out[len(out)/2] ^= 0x01
		return out
	})

	b.MustGit("remote", "set-url", "origin", "cloak::"+hostB.Dir)
	_, stderr, err := b.Cloak("accept-repo-change", "--remote", "origin", "--force-insecure")
	if err == nil {
		t.Fatal("accept-repo-change accepted a manifest whose live pack is corrupt")
	}
	if !strings.Contains(stderr, "TAMPER ALARM") {
		t.Fatalf("corrupt pack was not reported as tamper: %s", stderr)
	}
	assertTrustAnchorsEqual(t, b, pinBefore, repoIDBefore)

	// Once the carrier is restored, the same explicit acceptance succeeds,
	// applies the new repository's pack, and replaces both old trust anchors.
	hostB.Git("update-ref", "refs/heads/cloak", validBackendHead)
	out, stderr, err := b.Cloak("accept-repo-change", "--remote", "origin", "--force-insecure")
	if err != nil {
		t.Fatalf("accept-repo-change did not recover after restoring the pack: %v\nstdout: %s\nstderr: %s", err, out, stderr)
	}
	if !strings.Contains(out, "Accepted") {
		t.Fatalf("accept-repo-change success output = %q", out)
	}
	b.MustGit("cat-file", "-e", writer.HeadOID()+"^{commit}")
	newPin, newRepoID := readTrustAnchors(t, b)
	if bytes.Equal(newPin, pinBefore) || bytes.Equal(newRepoID, repoIDBefore) {
		t.Fatalf("successful repo change kept old trust anchors: pin %q, repo id %q", newPin, newRepoID)
	}
}

func onlyHostPackPath(t *testing.T, host *harness.Host) string {
	t.Helper()
	var packs []string
	for _, path := range host.LsTreeR("cloak") {
		if strings.HasPrefix(path, "packs/") {
			packs = append(packs, path)
		}
	}
	if len(packs) != 1 {
		t.Fatalf("expected exactly one live host pack, found %d: %v", len(packs), packs)
	}
	return packs[0]
}

func readTrustAnchors(t *testing.T, c *harness.Client) (pin, repoID []byte) {
	t.Helper()
	pin, err := os.ReadFile(soleStateFile(t, c, "generation", "rollback pin"))
	if err != nil {
		t.Fatal(err)
	}
	repoID, err = os.ReadFile(soleStateFile(t, c, "repoid", "repo-id pin"))
	if err != nil {
		t.Fatal(err)
	}
	return pin, repoID
}

func assertTrustAnchorsEqual(t *testing.T, c *harness.Client, wantPin, wantRepoID []byte) {
	t.Helper()
	gotPin, gotRepoID := readTrustAnchors(t, c)
	if !bytes.Equal(gotPin, wantPin) {
		t.Fatalf("failed acceptance did not preserve rollback pin: got %q, want %q", gotPin, wantPin)
	}
	if !bytes.Equal(gotRepoID, wantRepoID) {
		t.Fatalf("failed acceptance did not preserve repo-id pin: got %q, want %q", gotRepoID, wantRepoID)
	}
}
