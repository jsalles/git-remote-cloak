// Package userpresence gates sensitive cloak operations behind a device-owner
// check: Touch ID with password fallback on macOS. The remote-helper sync path
// never calls this, so unattended sync never prompts. Require retains the
// legacy non-interactive skip used by non-destructive setup; RequireExplicit
// makes key deletion, rekey, and trust-anchor overrides fail closed unless the
// caller supplied --force-insecure. The keychain item ACL, not these prompts,
// is the boundary against same-user code.
package userpresence

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ErrNonInteractive is returned when a security-sensitive operation is run
// without a terminal and the caller did not explicitly allow bypassing the
// device-owner prompt.
var ErrNonInteractive = errors.New("cloak: refusing sensitive operation with non-interactive stdin; run it from a terminal or pass --force-insecure explicitly")

// IsInteractive reports whether stdin is an interactive terminal. The test
// must be a real isatty check: /dev/null is a character device, so a mode
// check would misclassify headless subprocess invocations as interactive.
func IsInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// Require runs the platform user-presence check for an interactive
// session; non-interactive sessions pass with a notice on stderr. The
// terminal test must be a real isatty check: /dev/null is a character
// device, so a mode check would misclassify headless subprocess
// invocations as interactive and fire authentication prompts from
// background jobs.
func Require(reason string, stderr io.Writer) error {
	if !IsInteractive() {
		fmt.Fprintf(stderr, "cloak: note: user-presence check for %s skipped (non-interactive session)\n", reason)
		return nil
	}
	return require(reason)
}

// RequireExplicit protects operations which change trust anchors or remote
// encryption. Interactive calls always perform the platform presence check.
// Headless calls fail closed unless the CLI supplied an explicit insecure
// bypass; routine fetch/push never calls this function.
func RequireExplicit(reason string, stderr io.Writer, forceInsecure bool) error {
	if !IsInteractive() && !forceInsecure {
		return ErrNonInteractive
	}
	return Require(reason, stderr)
}
