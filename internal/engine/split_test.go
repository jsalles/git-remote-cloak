// In-process unit tests for the multi-pack push split path: buildPacks splits an
// over-limit push into several self-contained sub-limit packs, and refuses a
// single file whose encrypted pack alone exceeds the limit. These exercise the
// engine directly (no subprocess helper), so coverage is attributed in-process.
package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
)

// incompressibleBytes returns n high-entropy bytes (xorshift from seed) so the
// packed/encrypted size tracks the byte count; distinct seeds yield blobs git
// will not delta-compress together, which is needed to force a multi-pack split.
func incompressibleBytes(seed uint32, n int) []byte {
	b := make([]byte, n)
	x := seed
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

func TestBuildPacksSplitsOversizedPush(t *testing.T) {
	g := gitx.New(discard())
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, newHostRepo(t, g), key)
	const limit = 2 << 20 // 2 MiB per-file cap
	a.e.Cfg.MaxPackBytes = limit

	// Four distinct ~1 MiB incompressible files: each fits, but together they
	// exceed the limit, so buildPacks must split into several sub-limit packs.
	var head string
	for i, name := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
		head = a.commit(t, name, string(incompressibleBytes(uint32(i+1)*2654435761, 1<<20)))
	}

	packs, err := a.e.buildPacks([]string{head}, map[string]string{})
	if err != nil {
		t.Fatalf("buildPacks: %v", err)
	}
	t.Cleanup(func() {
		for _, p := range packs {
			_ = os.Remove(p.path)
		}
	})

	if len(packs) < 2 {
		t.Fatalf("oversized push not split: got %d pack(s), want >= 2", len(packs))
	}
	for _, p := range packs {
		if p.size > limit {
			t.Fatalf("split pack %.12s over limit: %d > %d", p.id, p.size, limit)
		}
		if !p.applied {
			t.Fatalf("freshly built split pack %.12s not marked applied", p.id)
		}
		assertPackSelfContained(t, g, key, p.path)
	}
}

// assertPackSelfContained decrypts the ciphertext pack and indexes it into a
// fresh EMPTY bare repo exactly as fetch does (index-pack --stdin, no --strict):
// that resolves the pack's deltas without any other object present, so a thin
// pack (a delta whose base lives in a sibling pack) would fail with a missing
// base. Success proves the pack is non-thin -- the property fetch relies on when
// it applies each pack independently. (--strict is deliberately omitted: it adds
// an fsck connectivity check that a single pack of a multi-pack set cannot
// satisfy, since it references commits/trees/blobs held in sibling packs.)
func assertPackSelfContained(t *testing.T, g *gitx.G, key keystore.Key, ctPath string) {
	t.Helper()
	ct, err := os.Open(ctPath) // #nosec G304 -- test-controlled TmpDir ciphertext path
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ct.Close() }()
	plain, err := agecrypt.Decrypt(ct, key)
	if err != nil {
		t.Fatalf("decrypt pack: %v", err)
	}
	bare := filepath.Join(t.TempDir(), "verify.git")
	if _, _, err := g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--quiet", bare); err != nil {
		t.Fatal(err)
	}
	if _, _, err := g.Run(gitx.Opts{GitDir: bare, Stdin: plain}, "index-pack", "--stdin"); err != nil {
		t.Fatalf("split pack %q is thin (index-pack into empty repo failed): %v", ctPath, err)
	}
}

func TestBuildPacksRefusesSingleOversizeFile(t *testing.T) {
	g := gitx.New(discard())
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, newHostRepo(t, g), key)
	a.e.Cfg.MaxPackBytes = 2 << 20

	// One 3 MiB incompressible file: its pack alone exceeds the 2 MiB cap, which
	// no split can fix, so buildPacks must refuse with the single-file error.
	head := a.commit(t, "huge.bin", string(incompressibleBytes(99, 3<<20)))

	_, err = a.e.buildPacks([]string{head}, map[string]string{})
	if err == nil {
		t.Fatal("single over-limit file should be refused")
	}
	if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
		t.Fatalf("error not classified TooLarge: %v", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "push blocked") || !strings.Contains(msg, "per-file limit") {
		t.Fatalf("residual error not the single-file message: %q", msg)
	}
	if !strings.Contains(msg, "huge.bin") {
		t.Fatalf("residual error did not name the offending file: %q", msg)
	}
}

func TestFullRepackSplitsAndRekeyUsesNewKey(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	oldKey, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, host, oldKey)

	var head string
	for i, name := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
		head = a.commit(t, name, string(incompressibleBytes(uint32(i+1)*2654435761, 1<<20)))
	}
	_, rs := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})
	originalIDs := manifestPackIDs(rs.Manifest.Packs)

	const limit = 2 << 20
	a.e.Cfg.MaxPackBytes = limit
	rs, err = a.e.FullRepack(rs, nil)
	if err != nil {
		t.Fatalf("multi-pack repack: %v", err)
	}
	assertSplitRepack(t, rs, originalIDs, limit)

	newKey, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	repackedIDs := manifestPackIDs(rs.Manifest.Packs)
	rs, err = a.e.FullRepack(rs, &newKey)
	if err != nil {
		t.Fatalf("multi-pack rekey: %v", err)
	}
	assertSplitRepack(t, rs, repackedIDs, limit)

	// Every replacement must actually be encrypted under the supplied new key:
	// a fresh new-key client can apply the whole set and reconstruct HEAD, while
	// first contact with the old key fails on the manifest.
	b := newMachine(t, g, host, newKey)
	rsB := b.load(t)
	if _, err := b.e.FetchApply(rsB); err != nil {
		t.Fatalf("apply multi-pack rekey: %v", err)
	}
	if !b.e.HaveObject(head) {
		t.Fatal("new-key client did not reconstruct repacked HEAD")
	}
	c := newMachine(t, g, host, oldKey)
	if _, err := c.e.LoadRemoteState(); err == nil {
		t.Fatal("old key decrypted a multi-pack rekey manifest")
	}
	if got, err := g.Out(gitx.Opts{GitDir: host}, "rev-list", "--count", "cloak"); err != nil || got != "1" {
		t.Fatalf("full rekey did not squash backend chain: count=%q err=%v", got, err)
	}
}

func TestFullRepackRefusesSingleOversizeFile(t *testing.T) {
	g := gitx.New(discard())
	host := newHostRepo(t, g)
	key, err := keystore.Generate()
	if err != nil {
		t.Fatal(err)
	}
	a := newMachine(t, g, host, key)
	a.commit(t, "huge.bin", string(incompressibleBytes(99, 3<<20)))
	_, rs := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})
	before := rs.Head
	a.e.Cfg.MaxPackBytes = 2 << 20

	if _, err := a.e.FullRepack(rs, nil); err == nil {
		t.Fatal("repack accepted a single object over the per-pack limit")
	} else {
		if kind, ok := cloakerr.KindOf(err); !ok || kind != cloakerr.TooLarge {
			t.Fatalf("oversized repack kind = %v, want TooLarge (err: %v)", kind, err)
		}
		msg := err.Error()
		if !strings.Contains(msg, "repack blocked") || !strings.Contains(msg, "huge.bin") {
			t.Fatalf("oversized repack lacks operation/file detail: %q", msg)
		}
		if !strings.Contains(msg, "Do not use Git LFS") {
			t.Fatalf("oversized repack does not warn that Git LFS bypasses encryption: %q", msg)
		}
	}
	if got, err := g.Out(gitx.Opts{GitDir: host}, "rev-parse", "cloak"); err != nil || got != before {
		t.Fatalf("failed repack changed carrier head: got=%q want=%q err=%v", got, before, err)
	}
}

func assertSplitRepack(t *testing.T, rs *RemoteState, oldIDs []string, limit int64) {
	t.Helper()
	if len(rs.Manifest.Packs) < 2 {
		t.Fatalf("full repack produced %d pack(s), want at least 2", len(rs.Manifest.Packs))
	}
	for i, p := range rs.Manifest.Packs {
		if p.Size > limit {
			t.Fatalf("replacement pack %d exceeds limit: %d > %d", i, p.Size, limit)
		}
		if len(p.Replaces) != 0 {
			t.Fatalf("split replacement pack %d has quadratic Replaces lineage: %v (old ids %v)", i, p.Replaces, oldIDs)
		}
	}
}

func TestSplitRepackManifestGrowthIsLinear(t *testing.T) {
	const count = 500
	old := make([]manifest.Pack, 0, count)
	newPacks := make([]plannedPack, 0, count)
	for i := 0; i < count; i++ {
		old = append(old, manifest.Pack{ID: fmt.Sprintf("%064x", i+1), Size: 1})
		newPacks = append(newPacks, plannedPack{id: fmt.Sprintf("%064x", count+i+1), size: 1})
	}
	cur := &RemoteState{Manifest: &manifest.Manifest{
		Version: manifest.Version, RepoID: strings.Repeat("a", 32), Refs: map[string]string{}, Packs: old,
	}}
	man, err := repackManifest(cur, newPacks)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := manifest.Encode(man)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 128<<10 {
		t.Fatalf("split-repack manifest grew nonlinearly: %d bytes for %d packs", len(encoded), count)
	}
	for i, p := range man.Packs {
		if len(p.Replaces) != 0 {
			t.Fatalf("split replacement %d copied %d old ids", i, len(p.Replaces))
		}
	}
}

func manifestPackIDs(packs []manifest.Pack) []string {
	ids := make([]string, 0, len(packs))
	for _, p := range packs {
		ids = append(ids, p.ID)
	}
	return ids
}
