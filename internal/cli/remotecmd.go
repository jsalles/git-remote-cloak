// git-cloak remote-operating commands: repack (full consolidation +
// squash) and rekey (full repack under a new master key). Both take the
// same per-remote lock as the helper, so they serialize with running syncs.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/setup"
	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
	"github.com/b4ryon/git-remote-cloak/internal/userpresence"
)

func cliFail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, cloakerr.Message(err))
	return 1
}

// printFail writes err verbatim to stderr and returns exit code 1 - the
// failure idiom the key/debug subcommands use for errors that already carry
// their own context. Unlike cliFail it does NOT force the 'cloak:' prefix, so
// the printed text is byte-for-byte the error as produced.
func printFail(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, err)
	return 1
}

// cliFailLogged reports err and, when a session is open, points the operator
// at that remote's debug log for self-service troubleshooting (F5).
func cliFailLogged(stderr io.Writer, sess *setup.Session, err error) int {
	code := cliFail(stderr, err)
	if sess != nil && sess.St != nil {
		fmt.Fprintln(stderr, "see the debug log for details: "+sess.St.LogPath())
	}
	return code
}

// newFlagSet returns a ContinueOnError flag set named name whose usage and
// parse errors are written to stderr - the convention every git-cloak
// subcommand uses, so a parse failure can be reported as exit code 2.
func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// keyFlag registers the standard --key master-key reference flag on fs and
// returns the bound value. Its name, default (keystore.DefaultRef), and
// usage text are shared by every key-consuming subcommand, so they live in
// one place. Both file and macOS Keychain references are accepted.
func keyFlag(fs *flag.FlagSet) *string {
	return fs.String("key", keystore.DefaultRef(), "key reference (file:<path>; keychain:<name> on macOS)")
}

// urlFlag registers the standard --url backend selector on fs. A remote with
// extra push URLs has one independent cloak backend (and local state dir) per
// URL; this flag picks which one the command operates on. Empty (the default)
// selects the remote's fetch URL.
func urlFlag(fs *flag.FlagSet) *string {
	return fs.String("url", "", "backend URL to operate on, for remotes with multiple push URLs (e.g. cloak::https://host/repo); default: the remote's fetch URL")
}

// describeTarget names the backend a command operates on for display: the
// remote name alone for its fetch URL, name plus URL for a --url selection.
func describeTarget(remote, url string) string {
	if url == "" {
		return urlredact.URL(remote)
	}
	return urlredact.URL(remote) + " " + urlredact.URL(url)
}

func cmdRepack(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("repack", stderr)
	remote := fs.String("remote", "origin", "cloak remote to repack")
	url := urlFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	sess, err := setup.Open(*remote, *url, stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()
	rs, err := sess.Eng.FullRepack(sess.RS, nil)
	if err != nil {
		return cliFailLogged(stderr, sess, err)
	}
	if len(rs.Manifest.Packs) == 0 {
		return cliFailLogged(stderr, sess, fmt.Errorf("repack produced a manifest with no packs (internal error)"))
	}
	total, _, _ := packSizeStats(rs.Manifest.Packs)
	fmt.Fprintf(stdout, "Repacked remote %q: generation %d, %d %s totaling %d bytes (%d refs)\n",
		describeTarget(*remote, *url), rs.Manifest.Generation, len(rs.Manifest.Packs),
		packWord(len(rs.Manifest.Packs)), total, len(rs.Manifest.Refs))
	return 0
}

func cmdRekey(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("rekey", stderr)
	remote := fs.String("remote", "origin", "cloak remote to rekey")
	url := urlFlag(fs)
	newRef := fs.String("new-key", "", "key reference holding the NEW master key (required; create with keygen)")
	forceInsecure := fs.Bool("force-insecure", false,
		"allow non-interactive rekeying without a user-presence check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *newRef == "" {
		fmt.Fprintln(stderr, "cloak: rekey requires --new-key <ref> (generate one first: git cloak keygen --key <ref>)")
		return 2
	}
	if err := userpresence.RequireExplicit("rekey the remote", stderr, *forceInsecure); err != nil {
		return cliFail(stderr, err)
	}
	newKey, err := keystore.Load(*newRef)
	if err != nil {
		return cliFail(stderr, err)
	}
	defer newKey.Wipe()
	sess, err := setup.Open(*remote, *url, stderr, "cli")
	if err != nil {
		return cliFail(stderr, err)
	}
	defer sess.Close()
	return runRekey(describeTarget(*remote, *url), *newRef, &newKey, sess, stdout, stderr)
}

// runRekey performs the post-setup rekey phase once the new key is loaded and
// the session is open: it rejects a no-op rekey, drives the full repack under
// newKey, repoints this repo's cloak.keyRef, and prints the success guidance.
// The newKey.Wipe and sess.Close defers stay with the caller so resource
// lifetimes are unchanged.
func runRekey(remote, newRef string, newKey *keystore.Key, sess *setup.Session, stdout, stderr io.Writer) int {
	if newKey.Equal(sess.Eng.Key) {
		fmt.Fprintln(stderr, "cloak: --new-key holds the same key the remote already uses")
		return 2
	}
	rs, err := sess.Eng.FullRepack(sess.RS, newKey)
	if err != nil && rs == nil {
		if errors.Is(err, backend.ErrPushOutcomeUnknown) {
			return cliFailLogged(stderr, sess, fmt.Errorf("rekey push outcome is unknown: the carrier may already require key %s, so keep BOTH keys and do not retry blindly: %w\n  after connectivity returns, try: git config cloak.keyRef %s && git cloak status\n  if that cannot decrypt the remote, restore: git config cloak.keyRef %s",
				newKey.ID(), err, urlredact.ShellArg(newRef), urlredact.ShellArg(sess.Cfg.KeyRef)))
		}
		return cliFailLogged(stderr, sess, err)
	}
	_, _, configErr := sess.G.Run(gitx.Opts{GitDir: sess.Eng.LocalGitDir},
		"config", "cloak.keyRef", newRef)
	if configErr != nil {
		configErr = fmt.Errorf("updating this repo's cloak.keyRef failed: %w", configErr)
	}
	if configErr != nil {
		combined := configErr
		if err != nil {
			combined = errors.Join(err, configErr)
		}
		return cliFailLogged(stderr, sess, fmt.Errorf("remote rekeyed under key %s but local recovery is incomplete: %w\n  fix the key selection manually:  git config cloak.keyRef %s",
			newKey.ID(), combined, urlredact.ShellArg(newRef)))
	}
	if err != nil {
		return cliFailLogged(stderr, sess, fmt.Errorf("remote rekeyed under key %s and this repo now selects the new key, but local verification state could not be saved: %w\n  fix the reported local-state problem, then run git fetch",
			newKey.ID(), err))
	}
	if len(rs.Manifest.Packs) == 0 {
		return cliFailLogged(stderr, sess, fmt.Errorf("rekey produced a manifest with no packs (internal error)"))
	}
	total, _, _ := packSizeStats(rs.Manifest.Packs)
	fmt.Fprintf(stdout, "Rekeyed remote %q under key %s: generation %d, %d %s totaling %d bytes\n",
		remote, newKey.ID(), rs.Manifest.Generation, len(rs.Manifest.Packs),
		packWord(len(rs.Manifest.Packs)), total)
	fmt.Fprintln(stdout, "This repo's cloak.keyRef now points at the new key.")
	fmt.Fprintln(stdout, "OTHER MACHINES: import the new key into a fresh local reference, then configure that repository to use it:")
	fmt.Fprintln(stdout, "  git cloak key import --key <new-ref>")
	fmt.Fprintln(stdout, "  git config cloak.keyRef <new-ref>")
	fmt.Fprintln(stdout, "A bare import will not overwrite the old default key.")
	fmt.Fprintln(stdout, "NOTE: rekey does NOT protect history the host already stored under the OLD key; a leaked old key still decrypts everything pushed before this rekey. It limits exposure of FUTURE writes only. Rotate any secrets that ever appeared in history if this was a compromise response.")
	return 0
}

func packWord(n int) string {
	if n == 1 {
		return "pack"
	}
	return "packs"
}
