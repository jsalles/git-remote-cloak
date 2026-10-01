// Regression tests for repositories whose path contains glob metacharacters.
// The split push and full repack/rekey paths once listed git's split output
// with filepath.Glob over a path that embeds the repository location, so a
// '[...]' or backslash in that path matched nothing and an oversized push
// (or repack) silently published zero packs.
package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
)

// metacharDirs are working-tree locations that used to defeat the glob.
var metacharDirs = []string{"Vault [work]", `Vault\x`, "Vault*", "Vault?"}

func TestListPackFilesIsLiteral(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Vault [work]", "Vault*", "Vault-old"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"pack-1.pack", "pack-1.keep", "pack-1.idx", "other.pack"} {
			if err := os.WriteFile(filepath.Join(dir, f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Mkdir(filepath.Join(root, "Vault [work]", "pack-dir.pack"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := listPackFiles(filepath.Join(root, "Vault [work]"), ".pack")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "Vault [work]", "pack-1.pack"); len(got) != 1 || got[0] != want {
		t.Fatalf("bracketed dir: got %q, want only %q", got, want)
	}
	got, err = listPackFiles(filepath.Join(root, "Vault*"), ".keep")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(root, "Vault*", "pack-1.keep"); len(got) != 1 || got[0] != want {
		t.Fatalf("'*' dir must not reach sibling repos: got %q, want only %q", got, want)
	}
}

func TestSplitPushAndRepackFromMetacharPaths(t *testing.T) {
	for _, name := range metacharDirs {
		t.Run(name, func(t *testing.T) {
			g := gitx.New(discard())
			host := newHostRepo(t, g)
			key, err := keystore.Generate()
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(t.TempDir(), name)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			a := newMachineIn(t, g, host, key, dir)
			const limit = 2 << 20
			a.e.Cfg.MaxPackBytes = limit

			var head string
			for i, f := range []string{"a.bin", "b.bin", "c.bin", "d.bin"} {
				head = a.commit(t, f, string(incompressibleBytes(uint32(i+1)*2654435761, 1<<20)))
			}
			_, rs := a.push(t, a.load(t), RefUpdate{Src: mainRef, Dst: mainRef})
			if len(rs.Manifest.Packs) < 2 {
				t.Fatalf("oversized push from %q published %d pack(s), want a split", name, len(rs.Manifest.Packs))
			}
			assertFreshClientHas(t, g, host, key, head)

			rs, err = a.e.FullRepack(rs, nil)
			if err != nil {
				t.Fatalf("repack from %q: %v", name, err)
			}
			if len(rs.Manifest.Packs) == 0 {
				t.Fatalf("repack from %q published no packs", name)
			}
			assertFreshClientHas(t, g, host, key, head)

			newKey, err := keystore.Generate()
			if err != nil {
				t.Fatal(err)
			}
			rs, err = a.e.FullRepack(rs, &newKey)
			if err != nil {
				t.Fatalf("rekey from %q: %v", name, err)
			}
			if len(rs.Manifest.Packs) == 0 {
				t.Fatalf("rekey from %q published no packs", name)
			}
			assertFreshClientHas(t, g, host, newKey, head)
		})
	}
}

// assertFreshClientHas proves the carrier alone is enough to rebuild head: a
// brand-new client applies every live pack and must end up with the object.
func assertFreshClientHas(t *testing.T, g *gitx.G, host string, key keystore.Key, head string) {
	t.Helper()
	b := newMachine(t, g, host, key)
	rs := b.load(t)
	if _, err := b.e.FetchApply(rs); err != nil {
		t.Fatalf("fresh client apply: %v", err)
	}
	if !b.e.HasObjectClosure([]string{head}) {
		t.Fatalf("fresh client cannot rebuild %.12s from the carrier", head)
	}
}
