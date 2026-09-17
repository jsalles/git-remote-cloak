// Regression scenarios for list-only fetches: when Git already has every
// advertised object it sends no fetch batch, so the helper must repair trusted
// state from the validated advertisement itself rather than wait forever for a
// batch that will never arrive.
package integration

import (
	"os"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

// TestListOnlyFetchPinsPrepopulatedRepository covers first contact from a
// repository whose object store was populated out of band. Git sees that the
// advertised tip is already complete and therefore never asks the helper to
// fetch it, but the validated remote still has to become rollback- and
// identity-pinned.
func TestListOnlyFetchPinsPrepopulatedRepository(t *testing.T) {
	host, key, a := pushSetup(t)

	b := harness.NewClient(t, "b", key)
	b.InitRepo()
	// Populate B with the exact closure advertised by cloak without creating
	// cloak state. FETCH_HEAD keeps the fetched tip reachable for the following
	// remote-helper negotiation.
	b.MustGit("fetch", a.Dir, "main")
	b.AddOrigin(host.Dir)

	beforeBatches := strings.Count(b.DebugLog(), "fetch batch complete")
	b.MustGit("fetch", "origin")
	if after := strings.Count(b.DebugLog(), "fetch batch complete"); after != beforeBatches {
		t.Fatalf("pre-populated fetch unexpectedly sent a fetch batch: before=%d after=%d", beforeBatches, after)
	}
	assertPinsPresentAt(t, b, pinGeneration(t, a))
	pin, err := os.ReadFile(pinFilePath(t, b))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pin))
	if len(fields) != 2 {
		t.Fatalf("pin format = %q", pin)
	}
	status := b.MustCloak("status", "--remote", "origin")
	if !strings.Contains(status, "Manifest:   "+fields[1]+" (current remote)") {
		t.Fatalf("status does not expose the full current manifest hash:\n%s", status)
	}
}

// TestListOnlyFetchRepairsPinsMissingAfterApply models a crash after
// FetchApply has indexed and recorded all packs but before CommitPin persists
// either trust anchor. The next no-op fetch must recreate both pins.
func TestListOnlyFetchRepairsPinsMissingAfterApply(t *testing.T) {
	host, key, _ := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)
	wantGeneration := pinGeneration(t, b)

	for _, name := range []string{"generation", "repoid"} {
		if err := os.Remove(soleStateFile(t, b, name, name+" state file")); err != nil {
			t.Fatal(err)
		}
	}

	beforeBatches := strings.Count(b.DebugLog(), "fetch batch complete")
	b.MustGit("fetch", "origin")
	if after := strings.Count(b.DebugLog(), "fetch batch complete"); after != beforeBatches {
		t.Fatalf("post-apply recovery unexpectedly sent a fetch batch: before=%d after=%d", beforeBatches, after)
	}
	assertPinsPresentAt(t, b, wantGeneration)
}

// TestListOnlyFetchAdvancesStalePinAfterApply models a crash that left the
// rollback pin at generation N after generation N+1's objects were applied.
// A subsequent no-op fetch must advance the stale pin without a false alarm.
func TestListOnlyFetchAdvancesStalePinAfterApply(t *testing.T) {
	host, key, a := pushSetup(t)
	b := harness.NewClient(t, "b", key)
	b.MustClone(host.Dir)

	stalePin, err := os.ReadFile(pinFilePath(t, b))
	if err != nil {
		t.Fatal(err)
	}
	staleGeneration := pinGeneration(t, b)

	a.WriteFile("more.md", "second generation\n")
	a.Commit("c1")
	a.MustGit("push", "origin", "main")
	b.MustGit("fetch", "origin")
	wantGeneration := pinGeneration(t, b)
	if wantGeneration <= staleGeneration {
		t.Fatalf("setup did not advance the remote pin: %d <= %d", wantGeneration, staleGeneration)
	}

	if err := os.WriteFile(pinFilePath(t, b), stalePin, 0o600); err != nil {
		t.Fatal(err)
	}
	beforeBatches := strings.Count(b.DebugLog(), "fetch batch complete")
	b.MustGit("fetch", "origin")
	if after := strings.Count(b.DebugLog(), "fetch batch complete"); after != beforeBatches {
		t.Fatalf("stale-pin recovery unexpectedly sent a fetch batch: before=%d after=%d", beforeBatches, after)
	}
	assertPinsPresentAt(t, b, wantGeneration)
}

func assertPinsPresentAt(t *testing.T, c *harness.Client, wantGeneration uint64) {
	t.Helper()
	if got := pinGeneration(t, c); got != wantGeneration {
		t.Fatalf("rollback pin generation = %d, want %d", got, wantGeneration)
	}
	repoIDPath := soleStateFile(t, c, "repoid", "repo-id pin")
	b, err := os.ReadFile(repoIDPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) == "" {
		t.Fatal("repo-id pin is empty")
	}
}
