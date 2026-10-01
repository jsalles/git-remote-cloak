// Package backend manages the hidden bare mirror of the remote backend
// branch (.git/cloak/<remote>/backend.git): fetching the encrypted state
// from the host (partial blob:none mirror with automatic full-fetch
// fallback), reading manifest/pack blobs, building the deterministic
// chained/squash commits without a worktree, and pushing them. This is the
// ONLY package allowed to construct a backend `git push` command line; it
// exposes no code path that can emit a plain --force.
package backend

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/term"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
)

// filterRejectedRe matches the git stderr a host emits when it refuses the
// partial-clone filter. It is deliberately specific so an unrelated error
// merely containing the word "filter" does not silently disable the partial
// mirror.
var filterRejectedRe = regexp.MustCompile(`(?i)(filter[a-z]*\b.*(not recognized|not supported|unsupported|declined|not allowed))|((not recognized|not supported|unsupported).*filter)`)

// stdinIsTTY reports whether this process's stdin is an interactive
// terminal, used to avoid imposing a timeout that could kill a credential or
// passphrase prompt during a human-driven network operation.
func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// remoteHeadRef is where the fetched backend branch tip is stored locally.
const remoteHeadRef = "refs/cloak/remote-head"

// partialFilter keeps every blob out of the initial carrier fetch. Git's
// promisor machinery fetches a requested blob into the private backend mirror
// before ReadBlob can stream it through the engine's size/integrity checks, so
// those checks bound later scratch/decrypt/apply work, not carrier traffic or
// mirror disk use.
const partialFilter = "blob:none"

// Backend is an opened bare mirror bound to a host URL and branch.
type Backend struct {
	g       *gitx.G
	gitDir  string
	url     string
	branch  string
	log     *slog.Logger
	partial bool
}

// Open initializes (if needed) and configures the bare mirror at gitDir for
// the given host URL. The remote is configured as a blob:none promisor so
// pack blobs download lazily; if the host rejects filtering, Fetch falls
// back to full fetches and logs it.
func Open(g *gitx.G, gitDir, url, branch string, log *slog.Logger) (*Backend, error) {
	if err := validateRawURL(url); err != nil {
		return nil, err
	}
	b := &Backend{g: g, gitDir: gitDir, url: url, branch: branch, log: log, partial: true}
	if _, _, err := b.g.Run(gitx.Opts{Scrub: true}, "init", "--bare", "--object-format=sha1", "--initial-branch", branch, gitDir); err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "init backend mirror", err)
	}
	format, err := b.g.Out(gitx.Opts{GitDir: gitDir}, "rev-parse", "--show-object-format")
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "inspect backend object format", err)
	}
	if format != "sha1" {
		return nil, cloakerr.Newf(cloakerr.LocalGit, "inspect backend object format",
			"backend mirror uses %s objects; cloak requires sha1", format)
	}
	// blob:none downloads blobs lazily via the promisor machinery only when
	// actually read, which keeps pack transfer behind the engine's verification
	// path and lets consolidation lineage (Replaces) skip downloads.
	cfg := [][2]string{
		{"remote.origin.url", url},
		{"remote.origin.fetch", "+refs/heads/" + branch + ":" + remoteHeadRef},
		{"remote.origin.tagopt", "--no-tags"},
		{"remote.origin.promisor", "true"},
		{"remote.origin.partialclonefilter", partialFilter},
		{"gc.auto", "0"},
	}
	for _, kv := range cfg {
		opts := gitx.Opts{GitDir: gitDir}
		if kv[0] == "remote.origin.url" {
			opts.SensitiveArgs = true
			opts.SensitiveURLs = []string{url}
		}
		// An explicit --file pins every write to the mirror's own config even
		// if a config-redirecting variable ever reaches the child (see gitx).
		if _, _, err := b.g.Run(opts, "config", "--file", b.configPath(), kv[0], kv[1]); err != nil {
			return nil, cloakerr.New(cloakerr.LocalGit, "configure backend mirror", err)
		}
	}
	if err := b.validateEffectiveURLs(); err != nil {
		return nil, err
	}
	if err := b.pruneUnreachable(); err != nil {
		return nil, err
	}
	return b, nil
}

// validateRawURL rejects unsafe transport input before it is written to the
// private mirror's config. setup normally performs the same validation, but
// Backend is also used directly by the shipped debug seeder and by tests.
func validateRawURL(raw string) error {
	if raw == "" {
		return cloakerr.Newf(cloakerr.LocalGit, "validate backend URL", "empty backend URL")
	}
	if risk := urlredact.CredentialRisk(raw); risk != "" {
		return cloakerr.Newfh(cloakerr.LocalGit, "validate backend URL",
			"use an SSH URL or Git credential helper; do not embed authentication material in backend URLs",
			"refusing %s in backend URL %q", risk, urlredact.URL(raw))
	}
	if urlredact.IsHelperTransport(raw) || !urlredact.IsSupportedTransport(raw) {
		return cloakerr.Newf(cloakerr.LocalGit, "validate backend URL",
			"refusing external remote-helper transport")
	}
	return nil
}

// validateEffectiveURLs applies Git's fetch/push URL rewrite rules without
// contacting the host. A pushInsteadOf rule must not silently route ciphertext
// to a different carrier, and no rewrite may reintroduce credentials which the
// setup layer already rejected.
func (b *Backend) validateEffectiveURLs() error {
	fetchURL, err := b.g.Out(gitx.Opts{GitDir: b.gitDir, SensitiveArgs: true, SensitiveURLs: []string{b.url}},
		"remote", "get-url", "origin")
	if err != nil {
		return cloakerr.New(cloakerr.LocalGit, "resolve effective backend fetch URL", err)
	}
	pushOut, err := b.g.Out(gitx.Opts{GitDir: b.gitDir, SensitiveArgs: true, SensitiveURLs: []string{b.url}},
		"remote", "get-url", "--push", "--all", "origin")
	if err != nil {
		return cloakerr.New(cloakerr.LocalGit, "resolve effective backend push URL", err)
	}
	if risk := urlredact.CredentialRisk(fetchURL); risk != "" {
		return cloakerr.Newfh(cloakerr.LocalGit, "validate effective backend fetch URL",
			"use an SSH URL or Git credential helper; do not embed authentication material in URL rewrites",
			"refusing %s in backend URL %q", risk, urlredact.URL(fetchURL))
	}
	if urlredact.IsHelperTransport(fetchURL) {
		return cloakerr.Newf(cloakerr.LocalGit, "validate effective backend fetch URL",
			"refusing remote-helper transport after URL rewriting")
	}
	if !urlredact.IsSupportedTransport(fetchURL) {
		return cloakerr.Newf(cloakerr.LocalGit, "validate effective backend fetch URL",
			"refusing unsupported URL scheme after URL rewriting because Git would execute an external remote helper")
	}
	for _, pushURL := range strings.Split(strings.TrimSpace(pushOut), "\n") {
		if pushURL == "" {
			continue
		}
		if risk := urlredact.CredentialRisk(pushURL); risk != "" {
			return cloakerr.Newfh(cloakerr.LocalGit, "validate effective backend push URL",
				"use an SSH URL or Git credential helper; do not embed authentication material in URL rewrites",
				"refusing %s in backend URL %q", risk, urlredact.URL(pushURL))
		}
		if urlredact.IsHelperTransport(pushURL) {
			return cloakerr.Newf(cloakerr.LocalGit, "validate effective backend push URL",
				"refusing remote-helper transport after URL rewriting")
		}
		if !urlredact.IsSupportedTransport(pushURL) {
			return cloakerr.Newf(cloakerr.LocalGit, "validate effective backend push URL",
				"refusing unsupported URL scheme after URL rewriting because Git would execute an external remote helper")
		}
		if pushURL != fetchURL {
			return cloakerr.Newfh(cloakerr.LocalGit, "validate effective backend push URL",
				"configure multiple encrypted destinations as cloak:: push URLs on the source remote; do not redirect cloak's inner carrier with pushInsteadOf",
				"effective push URL %q differs from fetch URL %q", urlredact.URL(pushURL), urlredact.URL(fetchURL))
		}
	}
	return nil
}

// URL returns a display-safe version of the host URL this mirror is bound to.
// Transport code uses the private raw value directly.
func (b *Backend) URL() string { return urlredact.URL(b.url) }

// disablePartial removes the promisor/filter configuration after a host
// rejected filtering, so subsequent fetches are full.
func (b *Backend) disablePartial() {
	b.partial = false
	for _, key := range []string{"remote.origin.promisor", "remote.origin.partialclonefilter"} {
		_, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir}, "config", "--file", b.configPath(), "--unset", key)
		var gerr *gitx.GitError
		if err != nil && !(errors.As(err, &gerr) && gerr.ExitCode == configKeyAbsent) {
			// The fallback fetch reports its own failure if the filter stays
			// configured; record why so that failure can be explained.
			b.log.Warn("could not remove partial-clone setting from backend mirror", "key", key, "err", err)
		}
	}
	b.log.Warn("host does not support partial fetch (blob:none); falling back to full fetches; consolidated packs will re-download")
}

// configKeyAbsent is `git config --unset`'s exit status when the key is not set.
const configKeyAbsent = 5

// configPath is the mirror's own config file, the only file cloak writes.
func (b *Backend) configPath() string { return filepath.Join(b.gitDir, "config") }

// Fetch updates the mirror from the host. It returns the backend branch tip
// oid, or empty=true when the branch does not exist yet (fresh remote).
func (b *Backend) Fetch() (head string, empty bool, err error) {
	args := []string{"fetch", "--no-tags"}
	if b.partial {
		args = append(args, "--filter="+partialFilter)
	}
	args = append(args, "origin")
	_, stderr, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY(),
		MaxCapture: maxCapturedTransportBytes, SensitiveURLs: []string{b.url}}, args...)
	if err != nil {
		return b.classifyFetchErr(stderr, err)
	}
	head, err = b.g.Out(gitx.Opts{GitDir: b.gitDir}, "rev-parse", "--verify", remoteHeadRef)
	if err != nil {
		// Fetch succeeded but the ref is absent: empty remote repository.
		return "", true, nil
	}
	return head, false, nil
}

// classifyFetchErr maps a failed backend fetch to its Fetch result. A rejected
// partial filter triggers a one-time fallback to a full fetch (retrying the
// whole operation); a missing remote ref means the repository is empty;
// anything else is reported as a transport error.
func (b *Backend) classifyFetchErr(stderr string, err error) (head string, empty bool, _ error) {
	low := strings.ToLower(stderr)
	if b.partial && filterRejectedRe.MatchString(stderr) {
		b.disablePartial()
		return b.Fetch()
	}
	if strings.Contains(low, "couldn't find remote ref") ||
		strings.Contains(low, "no matching refs") {
		return "", true, nil
	}
	return "", false, gitx.ClassifyTransport("fetch backend branch", err)
}

// MaxManifestBytes bounds how much of a manifest-sized blob ReadBlobBytes will
// buffer. The host serves the (untrusted) ciphertext, so without a cap a
// malicious or broken host could force unbounded memory by serving a giant
// manifest.age. 16 MiB is far above any honest manifest (one short JSON record
// per live pack, capped at manifest.maxPacks) yet bounds the read.
const MaxManifestBytes = 1 << 24

// maxCapturedTransportBytes bounds the in-memory stdout/stderr capture for the
// host-facing git calls (fetch/push and the lazy-fetch blob read). The host
// relays unbounded remote: progress/sideband on stderr, so without a cap it
// could grow helper memory without limit; 16 MiB is far beyond any honest
// transport diagnostics yet bounds a hostile flood. Passed as gitx.Opts
// MaxCapture; local plumbing leaves it 0 (uncapped) since its output is the
// user's own repo data.
const maxCapturedTransportBytes = 1 << 24

// maxPackTreeBytes bounds the host-controlled `ls-tree <commit>:packs` output
// materialized while constructing a new carrier commit. An honest SHA-1 tree
// with manifest.maxPacks (16,384) fixed 64-hex filenames is under 2 MiB; extra
// entries are unauthenticated carrier junk and must not force unbounded memory.
const maxPackTreeBytes = 2 << 20

// ReadBlobBytes returns the full content of <commit>:<path> (manifest-sized
// blobs only; packs stream via ReadBlob). The read is bounded to
// MaxManifestBytes; an oversized blob is reported rather than buffered whole.
func (b *Backend) ReadBlobBytes(commit, path string) ([]byte, error) {
	var buf strings.Builder
	cap := &cappingWriter{w: &buf, limit: MaxManifestBytes}
	if err := b.ReadBlob(commit, path, cap); err != nil {
		return nil, err
	}
	if cap.overflow {
		return nil, cloakerr.New(cloakerr.Tamper, "read remote blob "+path,
			fmt.Errorf("blob exceeds maximum size %d bytes", int64(MaxManifestBytes)))
	}
	return []byte(buf.String()), nil
}

// ReadBlob streams the content of <commit>:<path> into dst. With the
// partial mirror, missing blobs are fetched lazily by git's promisor
// machinery during this call; if that machinery fails on this host and
// nothing has been written to dst yet, the mirror falls back to a full
// fetch once and retries before reporting tamper.
func (b *Backend) ReadBlob(commit, path string, dst io.Writer) error {
	cw := &countingWriter{w: dst}
	_, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdout: cw, MaxCapture: maxCapturedTransportBytes,
		SensitiveURLs: []string{b.url}},
		"cat-file", "blob", commit+":"+path)
	if cw.err != nil {
		return cloakerr.New(cloakerr.LocalGit, "write remote blob "+path, cw.err)
	}
	if err != nil && b.partial && cw.n == 0 {
		b.log.Warn("blob read failed under partial mirror; retrying with a full fetch", "path", path)
		b.disablePartial()
		_, _, ferr := b.Fetch()
		if ferr != nil {
			return ferr // already transport-classified by Fetch
		}
		_, _, err = b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdout: cw, MaxCapture: maxCapturedTransportBytes,
			SensitiveURLs: []string{b.url}},
			"cat-file", "blob", commit+":"+path)
		if cw.err != nil {
			return cloakerr.New(cloakerr.LocalGit, "write remote blob "+path, cw.err)
		}
	}
	if err != nil {
		return classifyBlobRead(path, err)
	}
	return nil
}

// classifyBlobRead maps a blob read failure. Lazy promisor fetches run
// inside the cat-file call, so a network or auth outage surfaces here; it
// must report as transport, not tamper, or flaky networks would fire false
// TAMPER alarms that a sync wrapper escalates instead of retrying. Only a
// failure that is not transport-classifiable means content the manifest
// promised is unreadable, which is the tamper taxonomy.
func classifyBlobRead(path string, err error) error {
	// Classify against client-origin diagnostics only: a withholding host can
	// inject "remote:" sideband text (e.g. "connection reset") that git relays
	// into stderr, which would otherwise downgrade a genuine missing-blob
	// Tamper into a retryable Network error. Strip that host-controlled text
	// first; the original err is still wrapped for context.
	classifyErr := err
	var ge *gitx.GitError
	if errors.As(err, &ge) {
		sanitized := *ge
		sanitized.Stderr = gitx.StripServerSideband(ge.Stderr)
		classifyErr = &sanitized
	}
	terr := gitx.ClassifyTransport("read remote blob "+path, classifyErr)
	if kind, ok := cloakerr.KindOf(terr); ok && kind != cloakerr.LocalGit {
		return terr
	}
	return cloakerr.New(cloakerr.Tamper, "read remote blob "+path,
		fmt.Errorf("blob listed by manifest is unreadable: %w", err))
}

// countingWriter tracks whether any bytes reached dst (retry safety).
type countingWriter struct {
	w io.Writer
	n int64
	// err records a destination failure separately from git's process error so
	// local ENOSPC/EIO is never mislabeled as host tampering.
	err error
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil && c.err == nil {
		c.err = err
	}
	return n, err
}

// cappingWriter forwards to w until limit bytes have been written, then
// discards the rest and records overflow. It always reports a full write so
// the streaming git process runs to completion (memory stays bounded by the
// discard) and the caller can distinguish overflow from a transport failure.
type cappingWriter struct {
	w        io.Writer
	n        int64
	limit    int64
	overflow bool
}

func (c *cappingWriter) Write(p []byte) (int, error) {
	if c.overflow {
		return len(p), nil
	}
	room := c.limit - c.n
	if room >= int64(len(p)) {
		// Fits within the cap: forward the whole chunk.
		if wn, err := c.writeChunk(p); err != nil {
			return wn, err
		}
		return len(p), nil
	}
	// Exceeds the cap: forward what still fits, discard the rest, and record
	// the overflow so later writes are acknowledged but dropped.
	if room > 0 {
		if wn, err := c.writeChunk(p[:room]); err != nil {
			return wn, err
		}
	}
	c.overflow = true
	return len(p), nil
}

// writeChunk forwards b to the underlying writer and accumulates the bytes
// actually written, giving the two Write branches one place to keep n in sync
// with the destination.
func (c *cappingWriter) writeChunk(b []byte) (int, error) {
	wn, err := c.w.Write(b)
	c.n += int64(wn)
	return wn, err
}

// PackBlobOIDs maps pack id -> blob oid for every pack in the commit's
// packs/ subtree, so a new commit's tree can reuse the existing blobs
// without rehashing them.
func (b *Backend) PackBlobOIDs(commit string) (map[string]string, error) {
	if commit == "" {
		return map[string]string{}, nil
	}
	var out strings.Builder
	cap := &cappingWriter{w: &out, limit: maxPackTreeBytes}
	_, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdout: cap}, "ls-tree", commit+":packs")
	if err != nil {
		if isMissingPacksTree(err) {
			return map[string]string{}, nil
		}
		return nil, cloakerr.New(cloakerr.LocalGit, "list remote pack blobs", err)
	}
	if cap.overflow {
		return nil, cloakerr.Newf(cloakerr.Tamper, "list remote pack blobs",
			"carrier packs tree exceeds the %d-byte safety limit", maxPackTreeBytes)
	}
	return parsePackBlobTree(out.String()), nil
}

// isMissingPacksTree reports whether err is the "this commit carries no packs/
// subtree" outcome of `git ls-tree <commit>:packs` (a manifest-only commit),
// which is a normal empty-pack-set result, not a failure. It matches git's "Not
// a valid object name" stderr and goes through errors.As (not a direct type
// assertion) so it still recognizes the sentinel if the error is ever wrapped
// further up the call chain, matching the errors.As idiom classifyBlobRead in
// this package already uses. Any other failure falls through and is reported as
// LocalGit, never silently collapsed to "no packs".
func isMissingPacksTree(err error) bool {
	var ge *gitx.GitError
	return errors.As(err, &ge) && strings.Contains(ge.Stderr, "Not a valid object name")
}

// parsePackBlobTree turns `git ls-tree <commit>:packs` output into a map from
// pack id (the <id>.age filename with the suffix stripped) to its blob oid,
// skipping any line that is not a well-formed "100644 blob <oid>\t<id>.age"
// tree entry.
func parsePackBlobTree(out string) map[string]string {
	oids := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		// Format: "100644 blob <oid>\t<id>.age"
		meta, name, found := strings.Cut(line, "\t")
		if !found {
			continue
		}
		fields := strings.Fields(meta)
		if len(fields) != 3 || fields[1] != "blob" {
			continue
		}
		oids[strings.TrimSuffix(name, ".age")] = fields[2]
	}
	return oids
}

// HashObject writes a blob into the mirror's object store and returns its oid.
func (b *Backend) HashObject(r io.Reader) (string, error) {
	out, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Stdin: r},
		"hash-object", "-w", "--stdin")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "hash-object", err)
	}
	return strings.TrimSpace(out), nil
}

// packTreeText serializes the pack-blob map into the `git mktree` input for the
// packs/ subtree: one "100644 blob <oid>\t<id>.age" entry per pack id, sorted by
// id so the same pack set always yields a byte-identical tree (and thus a
// reproducible commit identity, the compare-and-swap push relies on). It is the
// exact write-side inverse of parsePackBlobTree.
func packTreeText(packs map[string]string) string {
	var packTree strings.Builder
	ids := make([]string, 0, len(packs))
	for id := range packs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(&packTree, "100644 blob %s\t%s.age\n", packs[id], id)
	}
	return packTree.String()
}

// BuildCommit assembles the backend tree (manifest.age at the root, pack
// blobs under packs/) and creates a commit with deterministic identity and
// generation-derived timestamps. parent="" creates a root (squash) commit.
func (b *Backend) BuildCommit(parent, manifestOID string, packs map[string]string, generation uint64) (string, error) {
	packTreeOID, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true,
		Stdin: strings.NewReader(packTreeText(packs))}, "mktree")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "mktree packs", err)
	}
	root := fmt.Sprintf("100644 blob %s\tmanifest.age\n040000 tree %s\tpacks\n",
		manifestOID, strings.TrimSpace(packTreeOID))
	rootOID, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true,
		Stdin: strings.NewReader(root)}, "mktree")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "mktree root", err)
	}

	// Deterministic metadata: fixed identity, timestamp derived from the
	// generation (epoch base 2001-09-09) so commits leak no local clock.
	date := fmt.Sprintf("%d +0000", 1_000_000_000+generation)
	env := []string{
		"GIT_AUTHOR_NAME=cloak", "GIT_AUTHOR_EMAIL=cloak@cloak", "GIT_AUTHOR_DATE=" + date,
		"GIT_COMMITTER_NAME=cloak", "GIT_COMMITTER_EMAIL=cloak@cloak", "GIT_COMMITTER_DATE=" + date,
	}
	args := []string{"commit-tree", strings.TrimSpace(rootOID), "-m", "cloak"}
	if parent != "" {
		args = append(args, "-p", parent)
	}
	commit, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true, Env: env}, args...)
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "commit-tree", err)
	}
	return strings.TrimSpace(commit), nil
}

// PushResult classifies one backend push attempt.
type PushResult int

// ErrPushOutcomeUnknown marks the failure mode where the push transport died
// without a per-ref result and a follow-up carrier probe also failed. The host
// may have committed the attempted ref update; rekey callers need distinct
// recovery guidance because neither old nor new key can be selected safely.
var ErrPushOutcomeUnknown = errors.New("backend push outcome is unknown; the carrier may have accepted the attempted commit")

const (
	// PushOK: the ref updated.
	PushOK PushResult = iota
	// PushCASLost: a rejected update was followed by a fresh probe that found
	// the remote at a different head than the caller expected; re-fetch and retry.
	PushCASLost
	// PushFailed: transport or other failure; see error.
	PushFailed
)

// PushFF pushes a commit which is expected to be a fast-forward while still
// enforcing an exact carrier compare-and-swap. expectedOldOID is the tip on
// which commit was built; "" asserts that the branch must not exist. The lease
// is required even for a descendant commit because a concurrent actor could
// delete or rewind the carrier ref, after which a plain fast-forward/create
// would otherwise succeed and hide that unexpected state change.
func (b *Backend) PushFF(commit, expectedOldOID string) (PushResult, error) {
	return b.push(commit, expectedOldOID)
}

// PushLease force-pushes commit (squash/repack/rekey) guarded by an
// explicit --force-with-lease expected value. Never a plain --force.
func (b *Backend) PushLease(commit, expectedOldOID string) (PushResult, error) {
	return b.push(commit, expectedOldOID)
}

// pushArgs builds the sole backend push form: force-with-lease carrying an
// explicit expected value. An empty expected value asserts branch absence. A
// plain --force or unguarded fast-forward push is structurally impossible.
func pushArgs(branch, commit, expectedOldOID string) []string {
	args := []string{"push", "--porcelain",
		"--force-with-lease=refs/heads/" + branch + ":" + expectedOldOID}
	return append(args, "origin", commit+":refs/heads/"+branch)
}

func (b *Backend) push(commit, expectedOldOID string) (result PushResult, retErr error) {
	result = PushFailed
	defer func() {
		if result == PushOK {
			return
		}
		if err := b.pruneUnreachable(); err != nil {
			result = PushFailed
			retErr = errors.Join(retErr, err)
		}
	}()
	args := pushArgs(b.branch, commit, expectedOldOID)
	stdout, stderr, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY(),
		MaxCapture: maxCapturedTransportBytes, SensitiveURLs: []string{b.url}}, args...)
	if err == nil {
		return PushOK, nil
	}
	// A porcelain "!" only proves that the ref update was rejected. It does not
	// identify why: branch protection, a pre-receive hook, and a stale ref all
	// use the same flag. Probe the actual carrier head and retry only when it no
	// longer matches the head the caller built on. A stable head means policy or
	// another hard rejection, whose original diagnostic must reach the user.
	if backendRefRejected(stdout, b.branch) {
		probed, probeErr := b.probePushResult(commit, expectedOldOID)
		if probeErr != nil {
			return PushFailed, probeErr
		}
		switch probed {
		case PushOK:
			b.log.Warn("backend reported a rejected push but the carrier now points at the attempted commit; treating it as accepted")
			return PushOK, nil
		case PushCASLost:
			b.log.Info("backend push lost compare-and-swap")
			return PushCASLost, nil
		}
		if hostFileLimitRejection(stdout, stderr) {
			return PushFailed, classifyPushFailure(stdout, stderr, err)
		}
		return PushFailed, classifyStableRefRejection(err)
	}
	// No ref-level rejection line: the transport failed before git could report
	// per-ref status. Probe once: a connection can drop after the server commits
	// the update but before Git reports success. Confirming the exact attempted
	// oid prevents rekey from leaving the local repo configured with the old key.
	if probed, probeErr := b.probePushResult(commit, expectedOldOID); probeErr == nil {
		switch probed {
		case PushOK:
			b.log.Warn("backend push transport failed after the carrier accepted the attempted commit; treating it as accepted")
			return PushOK, nil
		case PushCASLost:
			b.log.Info("backend moved while push outcome was ambiguous; retrying as a lost compare-and-swap")
			return PushCASLost, nil
		}
	} else {
		b.log.Warn("could not resolve ambiguous backend push outcome", "err", probeErr)
		return PushFailed, errors.Join(
			ErrPushOutcomeUnknown,
			classifyPushFailure(stdout, stderr, err),
			fmt.Errorf("confirm backend head after ambiguous push: %w", probeErr),
		)
	}
	return PushFailed, classifyPushFailure(stdout, stderr, err)
}

// pruneUnreachable removes loose candidate objects left by interrupted,
// rejected, or CAS-losing pushes. The private mirror is serialized by cloak's
// per-remote lock in production, and gc.auto is disabled above, so no other Git
// writer should race this reachability sweep. Remote state remains rooted at
// remoteHeadRef and can always be fetched again from the carrier.
func (b *Backend) pruneUnreachable() error {
	if _, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Scrub: true},
		"prune", "--expire=now"); err != nil {
		return cloakerr.New(cloakerr.LocalGit, "prune unreachable backend objects", err)
	}
	return nil
}

// probePushResult queries the host after a failed/ambiguous push. The exact
// attempted commit proves acceptance; a head different from the expected old
// state is a lost CAS; an unchanged head leaves the original failure in force.
// expectedOldOID == "" represents an absent branch. The query is independent
// of the mirror's tracking ref, which may still hold the last fetched state.
func (b *Backend) probePushResult(commit, expectedOldOID string) (PushResult, error) {
	ref := "refs/heads/" + b.branch
	stdout, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY(),
		MaxCapture: maxCapturedTransportBytes, SensitiveURLs: []string{b.url}},
		"ls-remote", "--refs", "origin", ref)
	if err != nil {
		return PushFailed, gitx.ClassifyTransport("inspect backend head after rejected push", err)
	}
	head, exists, err := parseRemoteHead(stdout, ref)
	if err != nil {
		return PushFailed, err
	}
	return classifyProbedPushState(commit, expectedOldOID, head, exists), nil
}

func classifyProbedPushState(commit, expectedOldOID, head string, exists bool) PushResult {
	if exists && head == commit {
		return PushOK
	}
	if expectedOldOID == "" {
		if exists {
			return PushCASLost
		}
		return PushFailed
	}
	if !exists || head != expectedOldOID {
		return PushCASLost
	}
	return PushFailed
}

// classifyStableRefRejection reports a porcelain rejection whose follow-up
// probe found the carrier ref unchanged. It is deliberately non-retryable even
// if host-controlled hook text happens to contain a network/auth marker: the
// successful probe has established that this was not CAS contention, and the
// original git error retains the host's actionable diagnostic.
func classifyStableRefRejection(err error) error {
	return cloakerr.New(cloakerr.LocalGit, "push backend branch rejected by host", err).WithHint(
		"the carrier ref did not change; check branch protection, pre-receive hooks, repository permissions, and host policy")
}

// ForeignHostRefs lists every ref the host advertises other than the carrier
// branch. cloak only ever writes refs/heads/<branch>, so anything else on the
// carrier repository was pushed by something else and is not encrypted by
// cloak (typically plaintext history left from before the repository was
// switched to cloak, or a machine still pushing to the plain URL).
func (b *Backend) ForeignHostRefs() ([]string, error) {
	stdout, _, err := b.g.Run(gitx.Opts{GitDir: b.gitDir, Interactive: stdinIsTTY(),
		MaxCapture: maxCapturedTransportBytes, SensitiveURLs: []string{b.url}},
		"ls-remote", "--refs", "origin")
	if err != nil {
		return nil, gitx.ClassifyTransport("list host refs", err)
	}
	return foreignRefs(stdout, b.branch), nil
}

// foreignRefs extracts the non-carrier ref names from `git ls-remote --refs`
// output. A line without the expected "<oid>\t<ref>" shape is reported whole
// rather than skipped, so malformed host output cannot hide a ref.
func foreignRefs(lsRemote, branch string) []string {
	carrier := "refs/heads/" + branch
	var refs []string
	for _, line := range strings.Split(strings.TrimSpace(lsRemote), "\n") {
		if line == "" {
			continue
		}
		ref := line
		if _, name, ok := strings.Cut(line, "\t"); ok {
			ref = name
		}
		if ref != carrier {
			refs = append(refs, ref)
		}
	}
	return refs
}

// parseRemoteHead parses the exact-ref output of `git ls-remote --refs`.
// Honest output is either empty (the branch is absent) or one `<oid> <ref>`
// line. Anything else is ambiguous remote data and fails closed rather than
// guessing whether a rejected push is safe to retry.
func parseRemoteHead(stdout, expectedRef string) (head string, exists bool, err error) {
	trimmed := strings.TrimSpace(stdout)
	if trimmed == "" {
		return "", false, nil
	}
	lines := strings.Split(trimmed, "\n")
	if len(lines) != 1 {
		return "", false, cloakerr.Newf(cloakerr.Protocol, "inspect backend head after rejected push",
			"host advertised %d entries for exact ref %s", len(lines), expectedRef)
	}
	fields := strings.Fields(lines[0])
	if len(fields) != 2 || fields[0] == "" || fields[1] != expectedRef {
		return "", false, cloakerr.Newf(cloakerr.Protocol, "inspect backend head after rejected push",
			"host returned malformed exact-ref advertisement for %s", expectedRef)
	}
	return fields[0], true, nil
}

// hostFileLimitMarkers are substrings a host prints when it refuses a push
// because a file (one encrypted pack blob) exceeds its per-file size cap. The
// combined push output is lowercased before matching, so these are written in
// lower case. Plain substrings, not a regex: each is a fixed phrase. GitHub
// prints "GH001: Large files detected" and
// "exceeds GitHub's file size limit of 100.00 MB"; git's own receive.maxInputSize
// guard prints "pack exceeds maximum allowed size".
var hostFileLimitMarkers = []string{
	"file size limit",
	"gh001",
	"large files detected",
	"large file detected",
	"maximum allowed size",
}

// classifyPushFailure maps a failed (non-CAS) backend push to its taxonomy. A
// host file-size rejection is the host-side counterpart to the pre-flight
// cloak.maxPackBytes guard (which catches the common case before upload): when
// the configured limit is unset or larger than the host's real cap, the push
// reaches the host and is rejected here, so this turns that rejection into a
// clear TooLarge error instead of a generic local-git failure. Every other
// failure falls through to the transport classifier. Matching the host's
// "remote:" sideband is safe here: the worst a hostile host can do is mislabel
// its own push rejection as "too large", which leaks nothing and (unlike the
// integrity read path) cannot downgrade a security class.
func classifyPushFailure(stdout, stderr string, err error) error {
	if hostFileLimitRejection(stdout, stderr) {
		return cloakerr.New(cloakerr.TooLarge, "push backend branch", err).WithHint(
			"the host refused the push because an encrypted pack exceeds its per-file size limit (GitHub: 100 MiB); cloak stores each pack as one file, so shrink or remove the large file(s) and re-commit, or set `git config cloak.maxPackBytes` to catch this before upload")
	}
	return gitx.ClassifyTransport("push backend branch", err)
}

// hostFileLimitRejection reports whether the combined push output shows the host
// refused a pack blob for exceeding its per-file size limit. Matching the host's
// "remote:" sideband is intentional and safe (see classifyPushFailure): the
// worst a hostile host can do is mislabel its own rejection as "too large",
// which leaks nothing and only changes the surfaced error message, and genuine
// host file-size rejections do arrive on "remote:" lines.
func hostFileLimitRejection(stdout, stderr string) bool {
	combined := strings.ToLower(stdout + "\n" + stderr)
	for _, m := range hostFileLimitMarkers {
		if strings.Contains(combined, m) {
			return true
		}
	}
	return false
}

// backendRefRejected reports whether git's --porcelain push output (stdout)
// carries a rejection line for our backend branch. The porcelain status format
// is
//
//	<flag> TAB <from>:<to> TAB <summary>
//
// and git renders a refused ref update with a "!" flag whatever the host's
// reason. That flag and the line structure are produced LOCALLY by git's push
// machinery, so -- unlike the parenthesised reason text, which is relayed
// verbatim from the untrusted host -- it is a trustworthy signal to perform a
// fresh head probe. It is not itself proof of a CAS loss. Only stdout is scanned
// (the host's "remote:" sideband lands on stderr and never begins with "!\t"),
// and the match is anchored to our branch's "to" ref so an unrelated ref's
// status never counts.
func backendRefRejected(porcelainStdout, branch string) bool {
	want := "refs/heads/" + branch
	for _, line := range strings.Split(porcelainStdout, "\n") {
		if !strings.HasPrefix(line, "!\t") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			continue
		}
		// fields[1] is "<from>:<to>"; the pushed "to" ref is the suffix after
		// the last colon (a from-oid never contains one). A field with no colon
		// is malformed porcelain and ignored.
		spec := fields[1]
		i := strings.LastIndex(spec, ":")
		if i < 0 {
			continue
		}
		if spec[i+1:] == want {
			return true
		}
	}
	return false
}
