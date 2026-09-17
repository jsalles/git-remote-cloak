// End-to-end proof that cloak refuses Git's executable external transports:
// explicit ext:: syntax and unknown scheme:// helpers must fail without ever
// running their sentinel command/binary.
package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/test/harness"
)

func TestExtTransportCloneRejected(t *testing.T) {
	key := harness.NewKeyFile(t)
	c := harness.NewClient(t, "victim", key)
	sentinel := filepath.Join(c.Base, "pwned")

	// git clone cloak::ext::sh -c 'touch <sentinel>': the helper must reject
	// the ext:: backend URL before git's ext transport can run the command.
	_, stderr, err := c.GitEnv([]string{"GIT_ALLOW_PROTOCOL=cloak:ext:fd:file:ssh:https"},
		"clone", "cloak::ext::sh -c 'touch "+sentinel+"'", c.Dir)
	if err == nil {
		t.Fatalf("clone of an ext:: backend URL succeeded\nstderr: %s", stderr)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("ext:: transport executed: sentinel %s was created", sentinel)
	}
	if !strings.Contains(stderr, "cloak:") {
		t.Fatalf("clone failed without a cloak diagnostic: %s", stderr)
	}
}

func TestUnknownSchemeHelperCloneRejected(t *testing.T) {
	key := harness.NewKeyFile(t)
	c := harness.NewClient(t, "unknown-helper-victim", key)
	sentinel := filepath.Join(c.Base, "unknown-helper-ran")
	helperDir := t.TempDir()
	helper := filepath.Join(helperDir, "git-remote-evil")
	script := "#!/bin/sh\n: > \"$CLOAK_EVIL_SENTINEL\"\nexit 99\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	path := helperDir + string(os.PathListSeparator) + harness.MustBinDir(t) +
		string(os.PathListSeparator) + os.Getenv("PATH")

	// Unknown scheme:// transports execute git-remote-<scheme>. The cloak URL
	// allowlist must reject this before inner Git can select our sentinel helper;
	// the fixed child GIT_ALLOW_PROTOCOL whitelist is a second line of defense.
	_, stderr, err := c.GitEnv([]string{
		"PATH=" + path,
		"CLOAK_EVIL_SENTINEL=" + sentinel,
		"GIT_ALLOW_PROTOCOL=cloak:evil:file:ssh:https",
	}, "clone", "cloak::evil://example.invalid/repo", c.Dir)
	if err == nil {
		t.Fatalf("clone of an unknown-scheme backend URL succeeded\nstderr: %s", stderr)
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("unknown transport helper executed: sentinel %s was created", sentinel)
	}
	if !strings.Contains(stderr, "external remote helper") {
		t.Fatalf("clone failed without an actionable cloak transport diagnostic: %s", stderr)
	}
}
