// Unit tests for the helper protocol loop (M0: capabilities exchange,
// clean EOF termination, unknown-command failure).
package helper

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/b4ryon/git-remote-cloak/internal/engine"
	"github.com/b4ryon/git-remote-cloak/internal/progress"
)

type failingProtocolWriter struct{ err error }

func (w failingProtocolWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCapabilities(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"origin", "cloak::/dev/null"},
		strings.NewReader("capabilities\n\n"), &out, &errb)
	if code != 0 {
		t.Fatalf("exit code = %d, stderr: %s", code, errb.String())
	}
	want := "fetch\npush\noption\n\n"
	if out.String() != want {
		t.Fatalf("capabilities output = %q, want %q", out.String(), want)
	}
}

func TestProtocolOutputFailureIsFatal(t *testing.T) {
	sentinel := errors.New("git stopped reading")
	var errb bytes.Buffer
	code := Main([]string{"origin", "cloak::/dev/null"},
		strings.NewReader("capabilities\n"), failingProtocolWriter{sentinel}, &errb)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), sentinel.Error()) {
		t.Fatalf("stderr did not surface protocol output failure: %q", errb.String())
	}
}

func TestEmptyRemoteFetchBatchDoesNotPanic(t *testing.T) {
	s := &session{
		eng:   &engine.Engine{},
		rs:    &engine.RemoteState{},
		log:   slog.New(slog.DiscardHandler),
		spin:  progress.New(io.Discard),
		ready: true,
	}
	locks, err := s.fetchBatch(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(locks) != 0 {
		t.Fatalf("empty remote returned locks: %v", locks)
	}
}

func TestEOFCleanExit(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"origin", "cloak::/dev/null"}, strings.NewReader(""), &out, &errb)
	if code != 0 {
		t.Fatalf("exit code on immediate EOF = %d", code)
	}
}

func TestNoArgsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := Main(nil, strings.NewReader(""), &out, &errb); code != 2 {
		t.Fatalf("exit code with no args = %d, want 2", code)
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var out, errb bytes.Buffer
	code := Main([]string{"origin", "cloak::/dev/null"}, strings.NewReader("frobnicate\n"), &out, &errb)
	if code == 0 {
		t.Fatal("expected non-zero exit for unknown command")
	}
	if !strings.Contains(errb.String(), "cloak:") {
		t.Fatalf("stderr should carry a cloak-prefixed message, got %q", errb.String())
	}
}

func TestOptionReplies(t *testing.T) {
	var out, errb bytes.Buffer
	in := "capabilities\noption verbosity 2\noption progress false\noption dry-run true\noption depth 5\n\n"
	code := Main([]string{"origin", "cloak::/dev/null"}, strings.NewReader(in), &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, errb.String())
	}
	want := "fetch\npush\noption\n\nok\nok\nok\nunsupported\n"
	if out.String() != want {
		t.Fatalf("output = %q, want %q", out.String(), want)
	}
}
