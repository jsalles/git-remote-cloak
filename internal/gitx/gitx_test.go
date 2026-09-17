// Unit tests for the git subprocess runner: output trimming, error typing
// with captured stderr, and GIT_DIR environment control.
package gitx

import (
	"bytes"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func runner() *G {
	return New(slog.New(slog.DiscardHandler))
}

func TestOutTrims(t *testing.T) {
	out, err := runner().Out(Opts{}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "git version") || strings.HasSuffix(out, "\n") {
		t.Fatalf("Out = %q", out)
	}
}

func TestGitErrorCarriesStderrAndExit(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	_, _, err := runner().Run(Opts{Dir: dir}, "rev-parse", "--verify", "refs/heads/nope")
	ge, ok := err.(*GitError)
	if !ok {
		t.Fatalf("error type = %T (%v)", err, err)
	}
	if ge.ExitCode == 0 || !strings.Contains(ge.Error(), "rev-parse") {
		t.Fatalf("GitError = %+v", ge)
	}
}

func TestRunRedactsSensitiveArgsAndURLDiagnostics(t *testing.T) {
	const secretURL = "https://alice:password@example.invalid/repo.git?token=secret#private"
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	g := New(lg)

	_, stderr, err := g.Run(Opts{SensitiveArgs: true, SensitiveURLs: []string{secretURL}},
		"hash-object", secretURL)
	if err == nil {
		t.Fatal("hash-object of a nonexistent URL-shaped path succeeded")
	}
	for name, output := range map[string]string{
		"returned stderr": stderr,
		"returned error":  err.Error(),
		"debug log":       logs.String(),
	} {
		for _, secret := range []string{"alice", "password", "token=secret", "private"} {
			if strings.Contains(output, secret) {
				t.Errorf("%s leaked %q: %q", name, secret, output)
			}
		}
	}
	if !strings.Contains(err.Error(), "[redacted arguments]") {
		t.Fatalf("returned error does not show argument redaction: %q", err)
	}
	if !strings.Contains(stderr, "https://example.invalid/repo.git") {
		t.Fatalf("stderr lost useful redacted URL context: %q", stderr)
	}
}

func TestApplyGitEnvCannotReenableCommandTransports(t *testing.T) {
	got := applyGitEnv([]string{
		"PATH=/bin",
		"GIT_ALLOW_PROTOCOL=ssh:ext:fd:https",
		"GIT_OBJECT_DIRECTORY=/source/objects",
		"GIT_WORK_TREE=/source",
	}, Opts{Env: []string{
		"GIT_ALLOW_PROTOCOL=file:ext",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES=/source/other",
	}})
	want := []string{
		"PATH=/bin",
		"GIT_ALLOW_PROTOCOL=" + allowedGitProtocols,
	}
	if len(got) != len(want) {
		t.Fatalf("environment = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("environment[%d] = %q, want %q (all %q)", i, got[i], want[i], got)
		}
	}
}

func TestRunBlocksUnknownTransportDespiteInheritedWhitelist(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "helper-ran")
	helper := filepath.Join(dir, "git-remote-evil")
	script := "#!/bin/sh\n: > \"$GITX_EVIL_SENTINEL\"\nexit 99\n"
	if err := os.WriteFile(helper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GITX_EVIL_SENTINEL", sentinel)
	t.Setenv("GIT_ALLOW_PROTOCOL", "evil:file:ssh:https")

	_, stderr, err := runner().Run(Opts{}, "ls-remote", "evil://example.invalid/repo")
	if err == nil {
		t.Fatal("unknown external transport unexpectedly succeeded")
	}
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Fatalf("external transport helper executed: %s", sentinel)
	}
	if !strings.Contains(stderr, "transport 'evil' not allowed") {
		t.Fatalf("Git did not report protocol-whitelist rejection: %q", stderr)
	}
}

func TestRunCapsCapturedStdout(t *testing.T) {
	// Uncapped (MaxCapture 0, the default) captures the full output.
	full, _, err := runner().Run(Opts{}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if len(full) <= 4 {
		t.Skipf("git version output unexpectedly short: %q", full)
	}
	// A tiny cap truncates captured stdout to a faithful prefix; the git process
	// still runs to completion (no error from the short capture).
	capped, _, err := runner().Run(Opts{MaxCapture: 4}, "version")
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 4 || !strings.HasPrefix(full, capped) {
		t.Fatalf("capped stdout = %q (len %d), want a 4-byte prefix of %q", capped, len(capped), full)
	}
}

func TestGitDirEnvControl(t *testing.T) {
	dir := t.TempDir()
	if out, err := exec.Command("git", "init", dir).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	got, err := runner().Out(Opts{GitDir: dir + "/.git"}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(got, "/.git") {
		t.Fatalf("absolute git dir = %q", got)
	}
}
