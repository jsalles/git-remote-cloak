// Pins the exact-CAS invariant at the source: every backend push carries a
// force-with-lease expected value, including an empty value that asserts the
// branch does not yet exist.
package backend

import (
	"strings"
	"testing"
)

func TestPushArgsNeverPlainForce(t *testing.T) {
	for _, lease := range []string{"", "0123456789abcdef0123456789abcdef01234567"} {
		args := pushArgs("cloak", "deadbeef", lease)
		for _, a := range args {
			if a == "--force" || a == "-f" {
				t.Fatalf("plain force in backend push argv: %v", args)
			}
		}
		joined := strings.Join(args, " ")
		if !strings.Contains(joined, "--force-with-lease=refs/heads/cloak:"+lease) {
			t.Fatalf("push missing exact expected value: %v", args)
		}
	}
}
