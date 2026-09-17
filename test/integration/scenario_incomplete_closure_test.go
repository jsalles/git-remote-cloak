// Regression coverage for the debug seeder's source-topology guard. A shallow
// source cannot produce a self-contained encrypted carrier.
package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestSeedRemoteRejectsShallowSource(t *testing.T) {
	host := harness.NewHost(t)
	key := harness.NewKeyFile(t)

	// Mark the tip as a shallow boundary. Without the guard, pack-objects can
	// emit the tip while omitting its referenced parent.
	src := harness.NewClient(t, "shallow-source", key)
	src.InitRepo()
	src.WriteFile("one.md", "one\n")
	src.Commit("one")
	src.WriteFile("two.md", "two\n")
	src.Commit("two")
	if err := os.WriteFile(filepath.Join(src.Dir, ".git", "shallow"),
		[]byte(src.HeadOID()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := src.Cloak("debug", "seed-remote", "--from", src.Dir,
		"--key", "file:"+key, host.Dir)
	if err == nil {
		t.Fatal("debug seed-remote accepted a shallow source")
	}
	if !strings.Contains(stderr, "shallow") || !strings.Contains(stderr, "full history") {
		t.Fatalf("shallow source rejection is not actionable: %s", stderr)
	}
	if refs := host.Git("for-each-ref", "--format=%(refname)"); refs != "" {
		t.Fatalf("rejected shallow seed changed the carrier: %s", refs)
	}
}
