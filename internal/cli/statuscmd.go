// git-cloak status and accept-rollback: operator visibility into the
// remote (generation, packs, applied state, rollback pin) and the
// explicit, one-shot acceptance of a remote generation regression.
package cli

import (
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/setup"
	"github.com/b4ryon/git-remote-cloak/internal/state"
	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("status", stderr)
	remote := fs.String("remote", "origin", "cloak remote to inspect")
	url := urlFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, err := setup.Open(*remote, *url, stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()

	fmt.Fprintf(stdout, "Remote:     %s\n", urlredact.URL(*remote))
	if *url != "" {
		fmt.Fprintf(stdout, "URL:        %s\n", urlredact.URL(*url))
	}
	fmt.Fprintf(stdout, "Key:        %s (%s)\n", sess.Eng.Key.ID(), sess.Cfg.KeyRef)
	printHostRefs(sess, stdout)
	if sess.RS.Manifest == nil {
		fmt.Fprintln(stdout, "State:      empty (no backend branch yet; first push creates it)")
		return 0
	}
	return printManifestStatus(sess, stdout, stderr)
}

// maxListedHostRefs bounds how many foreign host refs status prints by name.
const maxListedHostRefs = 10

// printHostRefs reports refs on the host that cloak did not write: their
// history is not encrypted. A listing failure is shown but does not fail
// status, which has already verified the carrier itself. Ref names come from
// the host, so they are printed quoted.
func printHostRefs(sess *setup.Session, stdout io.Writer) {
	refs, err := sess.Eng.Be.ForeignHostRefs()
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "Host refs:  could not list (%v)\n", err)
	case len(refs) == 0:
		fmt.Fprintln(stdout, "Host refs:  carrier branch only")
	default:
		fmt.Fprintf(stdout, "Host refs:  WARNING: %d ref(s) not written by cloak; their history is NOT encrypted:\n", len(refs))
		for i, ref := range refs {
			if i == maxListedHostRefs {
				fmt.Fprintf(stdout, "            ... and %d more\n", len(refs)-i)
				break
			}
			fmt.Fprintf(stdout, "            %q\n", ref)
		}
	}
}

// printManifestStatus renders the populated-remote status block: pack-size
// totals, applied-pack count, local verification/identity records, and the
// sync verdict. It returns an exit code so the AppliedSet read error can route
// through cliFailLogged exactly as the inline body did.
func printManifestStatus(sess *setup.Session, stdout, stderr io.Writer) int {
	m := sess.RS.Manifest
	total, largest, smallest := packSizeStats(m.Packs)
	applied, err := sess.St.AppliedSet()
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	appliedLive := countAppliedLive(m.Packs, applied)

	pin, pinned, err := sess.St.LoadPin()
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	printGenerationLine(stdout, m, pin, pinned)
	fmt.Fprintf(stdout, "Manifest:   %s (current remote)\n", sess.RS.ManifestHash)
	rid, ridOK, err := sess.St.LoadRepoID()
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	printRepoIDLine(stdout, m, rid, ridOK)
	fmt.Fprintf(stdout, "Head:       %s\n", m.Head)
	fmt.Fprintf(stdout, "Refs:       %d\n", len(m.Refs))
	fmt.Fprintf(stdout, "Packs:      %d live, %d bytes total (largest %d, smallest %d)\n",
		len(m.Packs), total, largest, smallest)
	fmt.Fprintf(stdout, "Applied:    %d of %d live packs already indexed on this machine\n", appliedLive, len(m.Packs))
	printSyncState(stdout, m, pin, pinned)
	return 0
}

// packSizeStats returns the total, largest, and smallest ciphertext size over
// the live packs. smallest stays -1 for an empty pack list, matching the
// sentinel the "smallest %d" status line prints.
func packSizeStats(packs []manifest.Pack) (total, largest, smallest int64) {
	smallest = -1
	for _, p := range packs {
		total += p.Size
		if p.Size > largest {
			largest = p.Size
		}
		if smallest < 0 || p.Size < smallest {
			smallest = p.Size
		}
	}
	return total, largest, smallest
}

// countAppliedLive counts how many live packs have already been indexed
// (applied) on this machine.
func countAppliedLive(packs []manifest.Pack, applied map[string]bool) int {
	n := 0
	for _, p := range packs {
		if applied[p.ID] {
			n++
		}
	}
	return n
}

// printGenerationLine prints the Generation status line, noting this machine's
// last-verified generation and manifest when a pin exists.
func printGenerationLine(stdout io.Writer, m *manifest.Manifest, pin state.Pin, pinned bool) {
	if pinned {
		fmt.Fprintf(stdout, "Generation: %d (last verified on this machine: %d, manifest %.12s)\n", m.Generation, pin.Generation, pin.ManifestHash)
	} else {
		fmt.Fprintf(stdout, "Generation: %d (nothing verified on this machine yet)\n", m.Generation)
	}
}

// printRepoIDLine prints the Repo-ID status line, noting whether the remote
// repo id matches this machine's record.
func printRepoIDLine(stdout io.Writer, m *manifest.Manifest, rid string, ridOK bool) {
	if ridOK {
		note := "matches this machine's record"
		if rid != m.RepoID {
			note = "DIFFERS from this machine's record"
		}
		fmt.Fprintf(stdout, "Repo-ID:    %s (%s)\n", m.RepoID, note)
	} else {
		fmt.Fprintf(stdout, "Repo-ID:    %s (no record on this machine yet)\n", m.RepoID)
	}
}

// printSyncState prints the one-line sync verdict comparing the remote
// generation against this machine's last-verified pin.
func printSyncState(stdout io.Writer, m *manifest.Manifest, pin state.Pin, pinned bool) {
	switch {
	case pinned && m.Generation > pin.Generation:
		fmt.Fprintln(stdout, "Sync:       remote is ahead of this machine; run `git pull` to catch up")
	case pinned:
		fmt.Fprintln(stdout, "Sync:       up to date with the remote")
	default:
		fmt.Fprintln(stdout, "Sync:       first contact (run `git pull` to fetch and pin the remote)")
	}
}

// acceptSpec captures the parts that differ between the two user-presence-gated
// "accept" overrides; runAccept holds their common verified replacement path.
type acceptSpec struct {
	name        string // flagset name
	remoteUsage string // -remote flag help text
	presence    string // userpresence action, e.g. "accept rollback"
	noun        string // local anchor being replaced, e.g. "pin" / "repo-id pin"
	repinFail   string // re-pin error tail, e.g. "re-pinning failed"
	// requireMatchingRepoID prevents accept-rollback from also accepting an
	// unrelated repository identity. accept-repo-change deliberately disables it.
	requireMatchingRepoID bool
	// describe reports what is being discarded (or that nothing was set).
	describe func(sess *setup.Session)
	// clear removes obsolete anchors when an explicitly accepted remote is empty.
	clear func(sess *setup.Session) error
	// accepted reports the final pinned state.
	accepted func(sess *setup.Session)
}

func runAccept(spec acceptSpec, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet(spec.name, stderr)
	remote := fs.String("remote", "origin", spec.remoteUsage)
	url := urlFlag(fs)
	forceInsecure := fs.Bool("force-insecure", false,
		"allow non-interactive trust-anchor changes without a user-presence check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := userpresence.RequireExplicit(spec.presence+" on remote "+describeTarget(*remote, *url), stderr, *forceInsecure); err != nil {
		return cliFail(stderr, err)
	}
	sess, err := setup.OpenLocal(*remote, *url, stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()
	return runAcceptOnSession(spec, sess, stdout, stderr)
}

// runAcceptOnSession leaves the old trust anchors installed while the candidate
// remote is fetched and fully verified, then replaces both anchors. Only an
// explicitly accepted empty remote requires clearing state.
func runAcceptOnSession(spec acceptSpec, sess *setup.Session, stdout, stderr io.Writer) int {
	spec.describe(sess)
	if err := sess.LoadRemoteUnchecked(); err != nil {
		return cliFailLogged(stderr, sess,
			fmt.Errorf("candidate remote could not be read; existing %s remains unchanged: %w", spec.noun, err))
	}
	if sess.RS.Manifest == nil {
		if err := spec.clear(sess); err != nil {
			return cliFailLogged(stderr, sess, err)
		}
		fmt.Fprintln(stdout, "Accepted: remote is currently empty; next push recreates it.")
		return 0
	}
	if err := sess.Eng.VerifyApplyAndCommitPin(sess.RS, spec.requireMatchingRepoID); err != nil {
		return cliFailLogged(stderr, sess,
			fmt.Errorf("candidate remote rejected; existing %s remains unchanged because %s: %w", spec.noun, spec.repinFail, err))
	}
	spec.accepted(sess)
	return 0
}

func cmdAcceptRollback(args []string, stdout, stderr io.Writer) int {
	return runAccept(acceptSpec{
		name:                  "accept-rollback",
		remoteUsage:           "cloak remote to accept the regression for",
		presence:              "accept rollback",
		noun:                  "pin",
		repinFail:             "re-pinning the current state failed",
		requireMatchingRepoID: true,
		describe: func(sess *setup.Session) {
			// A corrupt/unreadable pin is exactly what accept-rollback exists to
			// clear, so surface the load error instead of silently reporting
			// "nothing to accept"; clear() below still discards it.
			switch pin, ok, err := sess.St.LoadPin(); {
			case err != nil:
				fmt.Fprintf(stdout, "Will replace unreadable rollback pin after verification (%v).\n", err)
			case ok:
				fmt.Fprintf(stdout, "Current rollback pin to replace after verification: generation %d, manifest %.12s\n", pin.Generation, pin.ManifestHash)
			default:
				fmt.Fprintln(stdout, "No rollback pin was set (nothing to accept).")
			}
		},
		clear: func(sess *setup.Session) error { return sess.St.ClearPin() },
		accepted: func(sess *setup.Session) {
			fmt.Fprintf(stdout, "Accepted: now pinned at generation %d.\n", sess.RS.Manifest.Generation)
		},
	}, args, stdout, stderr)
}

// cmdAcceptRepoChange is the explicit, user-presence-gated override for a
// repository-identity mismatch: it clears the local repo-id pin AND the
// rollback (generation) pin, then re-pins both from the current remote, so the
// next fetch re-establishes trust-on-first-use for the new repository. Both are
// cleared because a different repository has an unrelated generation history
// (keeping the old one is meaningless and would trip the CR-005 consistency
// cross-check). Use only after deliberately re-pointing a remote at a different
// repository.
func cmdAcceptRepoChange(args []string, stdout, stderr io.Writer) int {
	return runAccept(acceptSpec{
		name:                  "accept-repo-change",
		remoteUsage:           "cloak remote to accept the repo-identity change for",
		presence:              "accept repo-identity change",
		noun:                  "repo-id pin",
		repinFail:             "re-pinning failed",
		requireMatchingRepoID: false,
		describe: func(sess *setup.Session) {
			switch rid, ok, err := sess.St.LoadRepoID(); {
			case err != nil:
				fmt.Fprintf(stdout, "Will replace unreadable repo-id pin after verification (%v).\n", err)
			case ok:
				fmt.Fprintf(stdout, "Current repo id to replace after verification: %s\n", rid)
			default:
				fmt.Fprintln(stdout, "No repo id was pinned (nothing to accept).")
			}
		},
		clear: func(sess *setup.Session) error {
			if err := sess.St.ClearRepoID(); err != nil {
				return err
			}
			// Also reset the rollback pin: a different repository has an
			// unrelated generation history, so keeping the old generation pin
			// would trip the repo-id/generation consistency cross-check (CR-005)
			// during re-validation and could raise a spurious rollback alarm.
			// This clear path is used only when the accepted remote is empty;
			// populated candidates replace both pins after full verification.
			return sess.St.ClearPin()
		},
		accepted: func(sess *setup.Session) {
			fmt.Fprintf(stdout, "Accepted: now pinned to repo id %s (generation %d).\n",
				sess.RS.Manifest.RepoID, sess.RS.Manifest.Generation)
		},
	}, args, stdout, stderr)
}
