// Unit tests for the backend mirror against a local bare "host" repository
// (no network): empty-remote detection, fast-forward push and fetch round
// trip, blob reads, pack blob oid listing, and the compare-and-swap
// outcomes of PushFF and PushLease.
package backend

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
)

type failingBlobWriter struct{ err error }

func (w failingBlobWriter) Write([]byte) (int, error) { return 0, w.err }

// newHost creates a local bare repository configured like the integration
// harness host (filter support enabled, backend branch "cloak").
func newHost(t *testing.T) (g *gitx.G, hostDir string) {
	t.Helper()
	g = gitx.New(slog.New(slog.DiscardHandler))
	hostDir = filepath.Join(t.TempDir(), "host.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--initial-branch", "cloak", hostDir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: hostDir}, "config", "uploadpack.allowfilter", "true"); err != nil {
		t.Fatal(err)
	}
	return g, hostDir
}

func openMirror(t *testing.T, g *gitx.G, host string) *Backend {
	t.Helper()
	b, err := Open(g, filepath.Join(t.TempDir(), "backend.git"), host, "cloak", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// seedCommit builds a root backend commit in b's mirror with one manifest
// blob and one pack blob, returning the commit and the pack blob oid.
func seedCommit(t *testing.T, b *Backend, manifestCT, packCT string, generation uint64) (commit, packOID string) {
	t.Helper()
	moid, err := b.HashObject(strings.NewReader(manifestCT))
	if err != nil {
		t.Fatal(err)
	}
	packOID, err = b.HashObject(strings.NewReader(packCT))
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	commit, err = b.BuildCommit("", moid, map[string]string{id: packOID}, generation)
	if err != nil {
		t.Fatal(err)
	}
	return commit, packOID
}

func TestFetchEmptyRemote(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	head, empty, err := b.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if !empty || head != "" {
		t.Fatalf("Fetch on empty host = (%q, empty=%v), want (\"\", true)", head, empty)
	}
}

func TestPushFFFetchReadRoundTrip(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	commit, packOID := seedCommit(t, a, "manifest-ct", "pack-ct", 1)
	res, err := a.PushFF(commit, "")
	if err != nil || res != PushOK {
		t.Fatalf("PushFF = (%v, %v), want PushOK", res, err)
	}

	b := openMirror(t, g, host)
	head, empty, err := b.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if empty || head != commit {
		t.Fatalf("Fetch = (%q, empty=%v), want (%q, false)", head, empty, commit)
	}
	ct, err := b.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		t.Fatal(err)
	}
	if string(ct) != "manifest-ct" {
		t.Fatalf("manifest blob = %q, want %q", ct, "manifest-ct")
	}
	oids, err := b.PackBlobOIDs(head)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("ab", 32)
	if len(oids) != 1 || oids[id] != packOID {
		t.Fatalf("PackBlobOIDs = %v, want {%s: %s}", oids, id, packOID)
	}
}

func TestReadBlobClassifiesDestinationFailureAsLocal(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	commit, _ := seedCommit(t, b, "manifest-ct", "pack-ct", 1)
	sentinel := errors.New("scratch disk full")
	err := b.ReadBlob(commit, "manifest.age", failingBlobWriter{sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("destination error was not preserved: %v", err)
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.LocalGit {
		t.Fatalf("destination error kind = %v, want LocalGit (err: %v)", kind, err)
	}
}

func TestPackBlobOIDsEmptyCommit(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	oids, err := b.PackBlobOIDs("")
	if err != nil || len(oids) != 0 {
		t.Fatalf("PackBlobOIDs(\"\") = (%v, %v), want empty map", oids, err)
	}
}

func TestPackBlobOIDsBoundsUnauthenticatedCarrierTree(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	manifestOID, err := b.HashObject(strings.NewReader("manifest"))
	if err != nil {
		t.Fatal(err)
	}
	packOID, err := b.HashObject(strings.NewReader("ciphertext"))
	if err != nil {
		t.Fatal(err)
	}
	// More fixed-shape entries than an honest max-sized manifest can name make
	// ls-tree exceed maxPackTreeBytes. The backend must reject the carrier junk
	// after bounded capture rather than materializing the whole tree in memory.
	packs := make(map[string]string, 18_000)
	for i := 0; i < 18_000; i++ {
		packs[fmt.Sprintf("%064x", i)] = packOID
	}
	commit, err := b.BuildCommit("", manifestOID, packs, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.PackBlobOIDs(commit)
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.Tamper {
		t.Fatalf("oversized packs tree error = %v, want Tamper", err)
	}
}

func TestPruneUnreachableBackendObjects(t *testing.T) {
	g, host := newHost(t)
	b := openMirror(t, g, host)
	oid, err := b.HashObject(strings.NewReader("unreachable candidate"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: b.gitDir}, "cat-file", "-e", oid); err != nil {
		t.Fatalf("setup object missing: %v", err)
	}
	if err := b.pruneUnreachable(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: b.gitDir}, "cat-file", "-e", oid); err == nil {
		t.Fatal("unreachable candidate survived backend prune")
	}
}

func TestPushFFLosesCAS(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c1, _ := seedCommit(t, a, "m1", "p1", 1)
	if res, err := a.PushFF(c1, ""); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	// A second writer that never fetched pushes an unrelated root commit:
	// the push must classify as a lost compare-and-swap, not an error.
	b := openMirror(t, g, host)
	c2, _ := seedCommit(t, b, "m2", "p2", 2)
	res, err := b.PushFF(c2, "")
	if err != nil {
		t.Fatalf("PushFF returned error: %v", err)
	}
	if res != PushCASLost {
		t.Fatalf("PushFF = %v, want PushCASLost", res)
	}
}

func TestPushRecognizesAcceptedCommitAfterTransportFailure(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	g, host := newHost(t)
	b := openMirror(t, g, host)
	commit, _ := seedCommit(t, b, "manifest", "pack", 1)

	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "git")
	script := `#!/bin/sh
for arg in "$@"; do
	if [ "$arg" = push ]; then
	    "$REAL_GIT" "$@" || exit $?
	    echo "GH001: Large files detected; simulated disconnect after receive" >&2
    exit 1
  fi
done
exec "$REAL_GIT" "$@"
`
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REAL_GIT", realGit)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := b.PushFF(commit, "")
	if err != nil || result != PushOK {
		t.Fatalf("ambiguous accepted push = (%v, %v), want PushOK", result, err)
	}
	if got := strings.TrimSpace(hostGit(t, realGit, host, "rev-parse", "cloak")); got != commit {
		t.Fatalf("carrier head = %s, want accepted commit %s", got, commit)
	}
}

func TestPushReportsUnknownOutcomeWhenConfirmationProbeFails(t *testing.T) {
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	g, host := newHost(t)
	b := openMirror(t, g, host)
	commit, _ := seedCommit(t, b, "manifest", "pack", 1)

	shimDir := t.TempDir()
	shim := filepath.Join(shimDir, "git")
	script := `#!/bin/sh
for arg in "$@"; do
  if [ "$arg" = push ]; then
    "$REAL_GIT" "$@" || exit $?
    echo "simulated disconnect after receive" >&2
    exit 1
  fi
  if [ "$arg" = ls-remote ]; then
    echo "simulated probe outage" >&2
    exit 2
  fi
done
exec "$REAL_GIT" "$@"
`
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REAL_GIT", realGit)
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	result, err := b.PushFF(commit, "")
	if result != PushFailed || !errors.Is(err, ErrPushOutcomeUnknown) {
		t.Fatalf("unconfirmable push = (%v, %v), want PushFailed/ErrPushOutcomeUnknown", result, err)
	}
	if got := strings.TrimSpace(hostGit(t, realGit, host, "rev-parse", "cloak")); got != commit {
		t.Fatalf("test did not model an accepted remote update: %s != %s", got, commit)
	}
}

func hostGit(t *testing.T, git, gitDir string, args ...string) string {
	t.Helper()
	cmd := exec.Command(git, append([]string{"--git-dir", gitDir}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("host git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestPushFFLeaseDetectsCarrierRewindAndDeletion(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c0, _ := seedCommit(t, a, "m0", "p0", 1)
	if res, err := a.PushFF(c0, ""); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	buildChild := func(parent, manifestText, packText string, generation uint64) string {
		moid, err := a.HashObject(strings.NewReader(manifestText))
		if err != nil {
			t.Fatal(err)
		}
		poid, err := a.HashObject(strings.NewReader(packText))
		if err != nil {
			t.Fatal(err)
		}
		commit, err := a.BuildCommit(parent, moid,
			map[string]string{strings.Repeat("cd", 32): poid}, generation)
		if err != nil {
			t.Fatal(err)
		}
		return commit
	}
	c1 := buildChild(c0, "m1", "p1", 2)
	if res, err := a.PushFF(c1, c0); err != nil || res != PushOK {
		t.Fatalf("second push = (%v, %v)", res, err)
	}
	c2 := buildChild(c1, "m2", "p2", 3)

	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "update-ref", "refs/heads/cloak", c0); err != nil {
		t.Fatal(err)
	}
	if res, err := a.PushFF(c2, c1); err != nil || res != PushCASLost {
		t.Fatalf("push after carrier rewind = (%v, %v), want PushCASLost", res, err)
	}
	if got, err := g.Out(gitx.Opts{GitDir: host}, "rev-parse", "refs/heads/cloak"); err != nil || got != c0 {
		t.Fatalf("push overwrote rewound carrier: got=%q want=%q err=%v", got, c0, err)
	}

	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "update-ref", "-d", "refs/heads/cloak"); err != nil {
		t.Fatal(err)
	}
	if res, err := a.PushFF(c2, c1); err != nil || res != PushCASLost {
		t.Fatalf("push after carrier deletion = (%v, %v), want PushCASLost", res, err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: host}, "rev-parse", "--verify", "refs/heads/cloak"); err == nil {
		t.Fatal("push recreated a carrier branch deleted after advertisement")
	}
}

func TestPushFFPolicyRejectionIsNotCAS(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c1, _ := seedCommit(t, a, "m1", "p1", 1)
	if res, err := a.PushFF(c1, ""); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	manifestOID, err := a.HashObject(strings.NewReader("m2"))
	if err != nil {
		t.Fatal(err)
	}
	packOID, err := a.HashObject(strings.NewReader("p2"))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := a.BuildCommit(c1, manifestOID,
		map[string]string{strings.Repeat("cd", 32): packOID}, 2)
	if err != nil {
		t.Fatal(err)
	}
	hook := filepath.Join(host, "hooks", "pre-receive")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho 'carrier policy rejects writes' >&2\nexit 1\n"), 0o755); err != nil { // #nosec G306 -- test hook must be executable
		t.Fatal(err)
	}

	res, err := a.PushFF(c2, c1)
	if err == nil || res != PushFailed {
		t.Fatalf("policy-rejected PushFF = (%v, %v), want (PushFailed, error)", res, err)
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.LocalGit {
		t.Fatalf("policy rejection kind = %v, want LocalGit (err: %v)", kind, err)
	}
	got, headErr := g.Out(gitx.Opts{GitDir: host}, "rev-parse", "refs/heads/cloak")
	if headErr != nil {
		t.Fatal(headErr)
	}
	if got != c1 {
		t.Fatalf("policy-rejected push changed host head: %s != %s", got, c1)
	}
}

func TestPushLeaseOKAndStale(t *testing.T) {
	g, host := newHost(t)
	a := openMirror(t, g, host)
	c1, _ := seedCommit(t, a, "m1", "p1", 1)
	if res, err := a.PushFF(c1, ""); err != nil || res != PushOK {
		t.Fatalf("initial push = (%v, %v)", res, err)
	}

	c2, _ := seedCommit(t, a, "m2", "p2", 2)
	res, err := a.PushLease(c2, c1)
	if err != nil || res != PushOK {
		t.Fatalf("PushLease with matching lease = (%v, %v), want PushOK", res, err)
	}

	// Remote is now at c2; a lease still expecting c1 must lose the CAS.
	c3, _ := seedCommit(t, a, "m3", "p3", 3)
	res, err = a.PushLease(c3, c1)
	if err != nil {
		t.Fatalf("stale PushLease returned error: %v", err)
	}
	if res != PushCASLost {
		t.Fatalf("stale PushLease = %v, want PushCASLost", res)
	}
}
