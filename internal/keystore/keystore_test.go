// Unit tests for the keystore: generation, export/import, file backend
// permission handling, and the redaction guarantees of the Key type.
package keystore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestGenerateUnique(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Export() == b.Export() {
		t.Fatal("two generated keys are identical")
	}
}

func TestKeyEqualComparesFullMaterial(t *testing.T) {
	raw := make([]byte, KeySize)
	raw[0] = 1
	a, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewKey(append([]byte(nil), raw...))
	if err != nil {
		t.Fatal(err)
	}
	other := append([]byte(nil), raw...)
	other[len(other)-1] = 2
	c, err := NewKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatal("identical full keys compare unequal")
	}
	if a.Equal(c) {
		t.Fatal("different full keys compare equal")
	}
	if a.Equal(Key{}) {
		t.Fatal("non-zero key compares equal to zero key")
	}
}

func TestExportRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseExport(k.Export() + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if got.Export() != k.Export() || got.ID() != k.ID() {
		t.Fatal("export round trip mismatch")
	}
	if _, err := ParseExport("not-a-key"); err == nil {
		t.Fatal("ParseExport accepted garbage")
	}
}

func TestFileSaveLoad(t *testing.T) {
	ref := "file:" + filepath.Join(t.TempDir(), "sub", "key")
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	got, err := Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Export() != k.Export() {
		t.Fatal("file round trip mismatch")
	}
	fi, err := os.Stat(strings.TrimPrefix(ref, "file:"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key file mode = %04o, want 0600", perm)
	}
}

func TestFileSaveRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	ref := "file:" + path
	first, _ := Generate()
	second, _ := Generate()
	if err := Save(ref, first); err != nil {
		t.Fatal(err)
	}
	if err := Save(ref, second); err == nil {
		t.Fatal("Save overwrote an existing key file")
	} else if !errors.Is(err, ErrKeyExists) {
		t.Fatalf("overwrite error = %v, want ErrKeyExists", err)
	}
	got, err := Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(first) {
		t.Fatal("failed overwrite changed the existing key")
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".key.tmp-*")); err != nil || len(matches) != 0 {
		t.Fatalf("failed overwrite left temporary key files: %v (glob err %v)", matches, err)
	}
}

func TestConcurrentFileSaveInstallsOneCompleteKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	ref := "file:" + path
	const writers = 8
	keys := make([]Key, writers)
	for i := range keys {
		var err error
		keys[i], err = Generate()
		if err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = Save(ref, keys[i])
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner >= 0 {
				t.Fatalf("multiple concurrent saves succeeded: writers %d and %d", winner, i)
			}
			winner = i
		case !errors.Is(err, ErrKeyExists):
			t.Fatalf("writer %d error = %v, want ErrKeyExists", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no concurrent save succeeded")
	}
	got, err := Load(ref)
	if err != nil {
		t.Fatalf("load concurrently saved key: %v", err)
	}
	if !got.Equal(keys[winner]) {
		t.Fatal("final key is partial or differs from the sole successful writer")
	}
	if matches, err := filepath.Glob(filepath.Join(dir, ".key.tmp-*")); err != nil || len(matches) != 0 {
		t.Fatalf("concurrent saves left temporary key files: %v (glob err %v)", matches, err)
	}
}

func TestLoadRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	k, _ := Generate()
	if err := os.WriteFile(path, []byte(k.Export()+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("file:" + path); err == nil {
		t.Fatal("Load accepted a group/world-readable key file")
	}
}

func TestLoadFileSizeBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oversized-key")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", maxKeyFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("file:" + path); err == nil || !strings.Contains(err.Error(), "key-file limit") {
		t.Fatalf("oversized key file error = %v", err)
	}
}

func TestDeleteRemovesInterruptedSaveTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	ref := "file:" + path
	k, _ := Generate()
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".key.tmp-123456789")
	if err := os.Link(path, stale); err != nil {
		t.Fatal(err)
	}
	other, _ := Generate()
	preLinkStale := filepath.Join(dir, ".key.tmp-987654321")
	if err := os.WriteFile(preLinkStale, []byte(other.Export()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(dir, ".key.tmp-backup")
	if err := os.WriteFile(unrelated, []byte("keep me\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Delete(ref); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, stale, preLinkStale} {
		if _, err := os.Stat(candidate); !os.IsNotExist(err) {
			t.Fatalf("key material still reachable at %s: %v", candidate, err)
		}
	}
	if got, err := os.ReadFile(unrelated); err != nil || string(got) != "keep me\n" {
		t.Fatalf("prefix-colliding unrelated file was changed: %q, %v", got, err)
	}
}

func TestLoadRemovesInterruptedSaveTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	ref := "file:" + path
	k, _ := Generate()
	if err := Save(ref, k); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".key.tmp-123456789")
	if err := os.Link(path, stale); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, ".key.lock")); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.Equal(k) {
		t.Fatal("loaded key changed while cleaning stale temp")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("ordinary key load left stale key material: %v", err)
	}
}

func TestLoadRejectsSymlinkAndNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	k, _ := Generate()
	target := filepath.Join(dir, "key")
	if err := Save("file:"+target, k); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "key-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"symlink":   link,
		"directory": dir,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Load("file:" + path); err == nil {
				t.Fatalf("Load accepted %s key path", name)
			}
		})
	}
}

func TestKeyRedactionEverywhere(t *testing.T) {
	raw := make([]byte, KeySize)
	for i := range raw {
		raw[i] = 0xAB
	}
	k, err := NewKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	leaks := []string{
		hex.EncodeToString(raw),
		base64.StdEncoding.EncodeToString(raw),
		base64.RawStdEncoding.EncodeToString(raw),
		string(raw),
	}
	jsonOut, err := json.Marshal(k)
	if err != nil {
		t.Fatal(err)
	}
	jsonStruct, err := json.Marshal(struct{ K Key }{k})
	if err != nil {
		t.Fatal(err)
	}
	outputs := map[string]string{
		"%v":          fmt.Sprintf("%v", k),
		"%+v":         fmt.Sprintf("%+v", k),
		"%#v":         fmt.Sprintf("%#v", k),
		"%s":          fmt.Sprintf("%s", k),
		"%x":          fmt.Sprintf("%x", k),
		"%q":          fmt.Sprintf("%q", k),
		"json":        string(jsonOut),
		"json-struct": string(jsonStruct),
		"slog-value":  fmt.Sprintf("%v", k.LogValue()),
	}
	for name, out := range outputs {
		for _, leak := range leaks {
			if strings.Contains(out, leak) {
				t.Fatalf("%s leaked key material: %q", name, out)
			}
		}
		if !strings.Contains(out, "redacted") {
			t.Fatalf("%s does not look redacted: %q", name, out)
		}
	}
}
