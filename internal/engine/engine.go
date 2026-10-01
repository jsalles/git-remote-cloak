// Package engine implements cloak's push/fetch algorithms over the backend
// mirror, the manifest, and git plumbing in the local repository: remote
// state validation (AEAD, rollback pin), pack application on fetch, and
// (from M3) pack creation with chained-CAS pushes and retry. It contains no
// protocol I/O; the helper package drives it.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/agecrypt"
	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/manifest"
	"github.com/b4ryon/git-remote-cloak/internal/state"
)

// Engine binds the local repository, per-remote state, backend mirror, and
// master key together for one helper or CLI invocation.
type Engine struct {
	G           *gitx.G
	LocalGitDir string
	St          *state.Dir
	Be          *backend.Backend
	Key         keystore.Key
	Cfg         config.Config
	Log         *slog.Logger
	// Progress, when set, receives coarse phase labels for a live UI spinner
	// (push/fetch). nil = silent, so non-helper callers (CLI, tests) need not
	// supply one. It is purely cosmetic and never affects correctness.
	Progress Progress
}

// Progress receives the human-readable label of the engine's current slow
// phase ("uploading to host", "applying pack 2/5", ...). The helper backs it
// with a terminal spinner; the engine calls it through the nil-safe phase
// helper so a nil Progress is a no-op.
type Progress interface {
	Phase(label string)
}

// phase reports the current slow phase to e.Progress, if any. Cosmetic only.
func (e *Engine) phase(format string, args ...any) {
	if e.Progress != nil {
		e.Progress.Phase(fmt.Sprintf(format, args...))
	}
}

// RemoteState is the validated view of the remote after one fetch.
type RemoteState struct {
	// Head is the backend branch tip commit ("" when the remote is empty).
	Head string
	// Manifest is the decrypted, validated manifest (nil when empty).
	Manifest *manifest.Manifest
	// ManifestHash is the SHA-256 hex of the manifest ciphertext.
	ManifestHash string
}

// validateRetryAdvance binds one operation to the authenticated state it has
// already observed. Durable pins can legitimately lag during first contact or
// a push-only session, so re-running LoadRemoteState after a lost carrier CAS
// is not by itself enough: a host must not switch repositories, replay an older
// generation, present different ciphertext at the same generation, or make a
// previously observed non-empty carrier disappear mid-operation. An operation
// that began empty may adopt the non-empty state created by the CAS winner.
func validateRetryAdvance(operation string, previous, next *RemoteState) error {
	previousPopulated := previous != nil && previous.Manifest != nil
	nextPopulated := next != nil && next.Manifest != nil
	if !nextPopulated {
		return cloakerr.Newf(cloakerr.Rollback, operation+" retry",
			"carrier is empty after a lost compare-and-swap; refusing to recreate state across an ambiguous deletion or rewind")
	}
	if !previousPopulated {
		return nil
	}
	if next.Manifest.RepoID != previous.Manifest.RepoID {
		return cloakerr.Newf(cloakerr.Tamper, operation+" retry",
			"repository identity changed during one operation (%s != %s)", next.Manifest.RepoID, previous.Manifest.RepoID)
	}
	switch {
	case next.Manifest.Generation > previous.Manifest.Generation:
		return nil
	case next.Manifest.Generation < previous.Manifest.Generation:
		return cloakerr.Newf(cloakerr.Rollback, operation+" retry",
			"remote generation regressed during one operation (%d < %d)", next.Manifest.Generation, previous.Manifest.Generation)
	case next.ManifestHash != previous.ManifestHash:
		return cloakerr.Newf(cloakerr.Tamper, operation+" retry",
			"remote manifest changed without a generation bump during one operation (generation %d)", next.Manifest.Generation)
	default:
		return cloakerr.Newf(cloakerr.Rollback, operation+" retry",
			"carrier head changed without an authenticated generation advance (still generation %d)", next.Manifest.Generation)
	}
}

// ciphertextHash returns the SHA-256 hex digest of a manifest ciphertext. It
// is the value recorded as the rollback pin's ManifestHash, so the read path
// (LoadRemoteState, which checks the pin) and the write path
// (buildBackendCommit, which stores it) MUST compute it identically for a
// freshly pushed pin to match on the next fetch; centralizing it here guarantees
// the two cannot drift apart.
func ciphertextHash(ct []byte) string {
	sum := sha256.Sum256(ct)
	return hex.EncodeToString(sum[:])
}

// LoadRemoteState fetches the backend branch, decrypts and validates the
// manifest, and enforces the rollback pin and repository-identity TOFU. It
// does NOT advance the local pins: those are persisted by CommitPin only
// after the state is fully fetched, verified, and applied, so a host serving
// a valid manifest while withholding or corrupting its packs cannot move the
// pin off honest state.
func (e *Engine) LoadRemoteState() (*RemoteState, error) {
	rs, err := e.LoadRemoteStateUnchecked()
	if err != nil {
		return nil, err
	}
	if rs.Manifest == nil {
		if err := e.St.CheckPin(nil, ""); err != nil {
			return nil, err
		}
		return rs, nil
	}
	if err := e.St.CheckPin(rs.Manifest, rs.ManifestHash); err != nil {
		return nil, err
	}
	if err := e.St.CheckRepoID(rs.Manifest); err != nil {
		return nil, err
	}
	e.Log.Info("remote state validated", "generation", rs.Manifest.Generation,
		"refs", len(rs.Manifest.Refs), "packs", len(rs.Manifest.Packs))
	return rs, nil
}

// LoadRemoteStateUnchecked fetches, decrypts, and structurally validates the
// carrier state without consulting local rollback or repository-identity pins.
// Only explicit accept-* recovery uses this path, so it can verify a candidate
// state fully before atomically replacing the old trust anchors. Routine
// fetch/push must use LoadRemoteState.
func (e *Engine) LoadRemoteStateUnchecked() (*RemoteState, error) {
	e.phase("downloading from host")
	head, empty, err := e.Be.Fetch()
	if err != nil {
		return nil, err
	}
	if empty {
		e.Log.Info("remote is empty (no backend branch yet)")
		return &RemoteState{}, nil
	}
	return e.loadPopulatedStateUnchecked(head)
}

// loadPopulatedStateUnchecked reads, decrypts, and structurally validates the
// manifest at a non-empty backend head. Trust-anchor validation belongs to the
// ordinary LoadRemoteState caller; explicit acceptance verifies storage before
// replacing those anchors.
func (e *Engine) loadPopulatedStateUnchecked(head string) (*RemoteState, error) {
	ct, err := e.Be.ReadBlobBytes(head, "manifest.age")
	if err != nil {
		return nil, err
	}
	hash := ciphertextHash(ct)
	pt, err := agecrypt.DecryptBytes(e.Key, ct)
	if err != nil {
		// The manifest is the first thing decrypted on every fetch/clone, and at
		// the AEAD layer a wrong master key is indistinguishable from genuine
		// tampering. On first contact the overwhelmingly common cause is a
		// wrong/missing key, so steer the user there (still Tamper-classified).
		return nil, cloakerr.WithHintOn(err,
			"the manifest is the first thing decrypted, and a wrong master key is indistinguishable from tamper here; verify `git config cloak.keyRef` and re-import the key with `git cloak key import` if this is a new machine")
	}
	m, err := manifest.Decode(pt)
	if err != nil {
		// The bytes already passed AEAD verification, so this is NOT tampering:
		// it is a manifest this build cannot parse (version/format skew).
		return nil, cloakerr.Newfh(cloakerr.Protocol, "decode manifest",
			"the remote decrypted correctly but its manifest is not understood by this version; upgrade git-remote-cloak (the other machine may be on a newer format)",
			"remote manifest invalid: %v", err)
	}
	return &RemoteState{Head: head, Manifest: m, ManifestHash: hash}, nil
}

// CommitPin persists the rollback pin and the repository-identity pin for a
// remote state that has been fully fetched, verified, and applied. It is the
// single point at which the local pins advance: callers invoke it only after
// the complete advertised object closure has been verified; explicit trust
// changes additionally verify every live remote pack. No-op for an empty
// remote (no manifest to pin).
func (e *Engine) CommitPin(rs *RemoteState) error {
	if rs == nil || rs.Manifest == nil {
		return nil
	}
	// Persist both pins together so a partial save can never leave a generation
	// pin without its repo-id pin (which would silently revert repo-identity
	// protection to TOFU); see state.SavePins.
	return e.St.SavePins(state.Pin{Generation: rs.Manifest.Generation, ManifestHash: rs.ManifestHash}, rs.Manifest.RepoID)
}

// CommitPinIfComplete repairs missing or stale trust anchors when the local
// object store already contains the complete closure of every advertised ref.
// This is the list-only fetch path: Git does not send a fetch batch when it
// already has the objects, so fetchBatch has no opportunity to call CommitPin.
//
// The state is re-validated immediately before any repair. This keeps the
// operation fail-closed if a pin became corrupt or inconsistent after the
// RemoteState was loaded, rather than letting the repair overwrite an alarm.
// Existing current pins are left untouched without walking the object graph.
// It returns true only when it persisted repaired pins.
func (e *Engine) CommitPinIfComplete(rs *RemoteState) (bool, error) {
	if rs == nil || rs.Manifest == nil {
		return false, nil
	}
	if err := e.St.CheckPin(rs.Manifest, rs.ManifestHash); err != nil {
		return false, err
	}
	if err := e.St.CheckRepoID(rs.Manifest); err != nil {
		return false, err
	}

	pin, hasPin, err := e.St.LoadPin()
	if err != nil {
		return false, fmt.Errorf("inspect rollback pin before repair: %w", err)
	}
	repoID, hasRepoID, err := e.St.LoadRepoID()
	if err != nil {
		return false, fmt.Errorf("inspect repo-identity pin before repair: %w", err)
	}
	if hasPin && pin.Generation == rs.Manifest.Generation && pin.ManifestHash == rs.ManifestHash &&
		hasRepoID && repoID == rs.Manifest.RepoID {
		return false, nil
	}

	tips := manifestRefTips(rs.Manifest)
	if !e.HasObjectClosure(tips) {
		return false, nil
	}
	if err := e.CommitPin(rs); err != nil {
		return false, fmt.Errorf("repair pins from complete local objects: %w", err)
	}
	return true, nil
}

// VerifyApplyAndCommitPin establishes trust anchors for an explicitly
// accepted remote only after proving that every live pack exists and its
// ciphertext matches the authenticated manifest. A complete local object
// closure avoids redundant indexing but never skips remote pack verification.
// When the closure is incomplete, every live pack is applied regardless of
// the applied set, Replaces lineage, or the usual closure shortcut; this also
// repairs stale local applied state. The final closure check proves the packs
// supplied every object reachable from the advertised refs before any pin is
// persisted.
func (e *Engine) VerifyApplyAndCommitPin(rs *RemoteState, requireMatchingRepoID bool) error {
	if rs == nil || rs.Manifest == nil {
		return nil
	}
	if requireMatchingRepoID {
		if err := e.St.CheckRepoID(rs.Manifest); err != nil {
			return err
		}
	}

	tips := manifestRefTips(rs.Manifest)
	apply := !e.HasObjectClosure(tips)
	appliedIDs := make([]string, 0, len(rs.Manifest.Packs))
	for i, p := range rs.Manifest.Packs {
		if apply {
			e.phase("verifying and applying pack %d/%d", i+1, len(rs.Manifest.Packs))
			if _, err := e.applyPack(rs.Head, p); err != nil {
				return err
			}
			appliedIDs = append(appliedIDs, p.ID)
			continue
		}
		e.phase("verifying pack %d/%d", i+1, len(rs.Manifest.Packs))
		if err := e.verifyPackWithoutApply(rs.Head, p); err != nil {
			return err
		}
	}
	if !e.HasObjectClosure(tips) {
		return cloakerr.New(cloakerr.Tamper, "verify accepted remote",
			fmt.Errorf("live packs did not provide the complete object closure of every advertised ref"))
	}
	if len(appliedIDs) > 0 {
		if err := e.St.MarkApplied(appliedIDs...); err != nil {
			return fmt.Errorf("record verified accepted packs: %w", err)
		}
	}
	if err := e.CommitPin(rs); err != nil {
		return fmt.Errorf("pin verified accepted remote: %w", err)
	}
	return nil
}

// verifyPackWithoutApply downloads one live pack through the same bounded
// size-and-hash checks as applyPack, but leaves the already-complete local
// object store untouched.
func (e *Engine) verifyPackWithoutApply(head string, p manifest.Pack) (retErr error) {
	ctPath := filepath.Join(e.St.TmpDir(), "verify-pack-"+p.ID[:12]+".age")
	defer joinScratchRemoval(ctPath, "verified pack ciphertext", &retErr)
	return e.downloadVerifyPack(head, ctPath, p)
}

// joinScratchRemoval removes a transient file and attaches cleanup failure to
// the operation's return error. A missing path is expected when setup failed
// before creation; every other failure is surfaced so plaintext/ciphertext is
// never silently left behind.
func joinScratchRemoval(path, description string, retErr *error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		*retErr = errors.Join(*retErr, fmt.Errorf("remove %s %q: %w", description, path, err))
	}
}

// manifestRefTips returns every object id advertised by m. The order is not
// security-sensitive; callers pass the complete set to git rev-list.
func manifestRefTips(m *manifest.Manifest) []string {
	tips := make([]string, 0, len(m.Refs))
	for _, oid := range m.Refs {
		tips = append(tips, oid)
	}
	return tips
}

// HaveObject reports whether the local repository has the object.
func (e *Engine) HaveObject(oid string) bool {
	_, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir}, "cat-file", "-e", oid)
	return err == nil
}

// HasObjectClosure reports whether the local repository contains the COMPLETE
// set of objects reachable from every given tip, not merely the tip objects
// themselves (which is all HaveObject checks). It walks each tip with
// rev-list --objects --missing=print and reports complete only when rev-list
// succeeds and names no missing object. Any uncertainty (a rev-list error, or
// any reported-missing object) returns false, so a caller that uses this to
// skip a download fails safe by downloading instead.
func (e *Engine) HasObjectClosure(oids []string) bool {
	complete, err := e.ObjectClosure(oids)
	return err == nil && complete
}

// ObjectClosure is HasObjectClosure for callers that must tell a genuinely
// incomplete closure (false, nil) from a local failure to check it (an error
// classified as LocalGit). A walk that fails while some tip object is absent
// is reported as incomplete: rev-list may refuse a missing starting point
// rather than print it. Only when every tip exists is the failure a local
// problem (a timeout, a corrupt store), which must not be reported as host
// tampering.
func (e *Engine) ObjectClosure(oids []string) (bool, error) {
	if len(oids) == 0 {
		return true, nil
	}
	shallow, err := e.G.Out(gitx.Opts{GitDir: e.LocalGitDir}, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return false, cloakerr.New(cloakerr.LocalGit, "inspect shallow repository state", err)
	}
	if shallow == "true" {
		return false, cloakerr.Newf(cloakerr.LocalGit, "verify object closure", "repository is shallow")
	}
	// Stream revisions on stdin instead of expanding one argv entry per ref.
	// A manifest may legitimately advertise enough refs to exceed the OS command
	// line limit; treating that exec failure as an incomplete closure would make
	// such a remote impossible to fetch and pin even after all packs were applied.
	var revs strings.Builder
	revs.Grow(len(oids) * 41)
	for _, oid := range oids {
		revs.WriteString(oid)
		revs.WriteByte('\n')
	}
	// GIT_COMMIT_GRAPH_PARANOIA makes rev-list confirm that commits listed in a
	// (possibly stale) commit-graph still exist in the object store; otherwise a
	// lost commit would be walked through and not reported missing.
	out, _, err := e.G.Run(gitx.Opts{
		GitDir: e.LocalGitDir,
		Env:    []string{"GIT_NO_REPLACE_OBJECTS=1", "GIT_COMMIT_GRAPH_PARANOIA=1"},
		Stdin:  strings.NewReader(revs.String()),
	}, "rev-list", "--objects", "--missing=print", "--stdin")
	if err != nil {
		for _, oid := range oids {
			if !e.HaveObject(oid) {
				return false, nil
			}
		}
		return false, cloakerr.New(cloakerr.LocalGit, "walk local object closure", err)
	}
	return !revListReportsMissing(out), nil
}

// RepairAdvertisedClosure re-applies every live pack of rs, ignoring the
// applied set, Replaces lineage and the closure shortcut. The applied set is a
// cache: objects it vouches for can legitimately disappear (git gc prunes
// objects no local ref reaches, e.g. on a single-branch clone), so before a
// fetch raises a tamper alarm it rebuilds from the authenticated packs. Each
// pack still passes the size, hash and AEAD checks. The re-applied packs keep
// their cloak .keep (they are not reported to git as fetch locks), so
// ReapOrphanKeeps holds them while their objects stay unreachable and gc
// cannot prune them again.
func (e *Engine) RepairAdvertisedClosure(rs *RemoteState) error {
	if rs == nil || rs.Manifest == nil {
		return nil
	}
	applied, err := e.St.AppliedSet()
	if err != nil {
		return err
	}
	var newlyApplied []string
	for i, p := range rs.Manifest.Packs {
		e.phase("re-applying pack %d/%d", i+1, len(rs.Manifest.Packs))
		if _, err := e.applyPack(rs.Head, p); err != nil {
			return err
		}
		if !applied[p.ID] {
			newlyApplied = append(newlyApplied, p.ID)
		}
	}
	return e.St.MarkApplied(newlyApplied...)
}

// revListReportsMissing reports whether git rev-list --objects --missing=print
// output names any missing object: a line that, after trimming surrounding
// whitespace, begins with "?". HasObjectClosure treats any such line as the
// closure being incomplete and fails safe by downloading the pack instead, so a
// parse that under-reports a "?" line would skip a download the local repo
// actually needs. Extracted as a pure function so it can be fuzzed without a
// git host.
func revListReportsMissing(out string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "?") {
			return true
		}
	}
	return false
}

// FetchApply downloads and indexes every manifest pack the local repo has
// not applied yet (honoring consolidation lineage via Replaces), verifying
// each blob's SHA-256 against its manifest id and decrypting fully BEFORE
// anything reaches git index-pack, so tampered data never enters the local
// object store. Returns the .keep file paths created by index-pack, for the
// protocol's lock lines.
func (e *Engine) FetchApply(rs *RemoteState) (keepFiles []string, err error) {
	if rs.Manifest == nil {
		return nil, nil
	}
	applied, err := e.St.AppliedSet()
	if err != nil {
		return nil, err
	}
	keepFiles, newlyApplied, err := e.applyManifestPacks(rs, applied)
	if err != nil {
		return nil, err
	}
	if err := e.St.MarkApplied(newlyApplied...); err != nil {
		return nil, err
	}
	return keepFiles, nil
}

// applyManifestPacks walks the manifest packs in order, downloading and
// indexing each not-yet-applied pack unless it can be skipped, and returns the
// .keep files created plus the ids to mark applied. The applied map is updated
// as it goes so a later pack's predecessor check sees earlier packs.
func (e *Engine) applyManifestPacks(rs *RemoteState, applied map[string]bool) (keepFiles, newlyApplied []string, err error) {
	closure := e.lazyClosure(rs.Manifest.Refs)
	total := len(rs.Manifest.Packs)
	for i, p := range rs.Manifest.Packs {
		if applied[p.ID] {
			continue
		}
		e.phase("applying pack %d/%d", i+1, total)
		keep, err := e.downloadUnlessSkippable(rs.Head, p, applied, closure)
		if err != nil {
			return nil, nil, err
		}
		if keep != "" {
			keepFiles = append(keepFiles, keep)
		}
		newlyApplied = append(newlyApplied, p.ID)
		applied[p.ID] = true
	}
	return keepFiles, newlyApplied, nil
}

// downloadUnlessSkippable downloads and indexes pack p unless packSkippable
// reports it can be marked applied without downloading, in which case it
// returns an empty keep path. The returned keep is the .keep file created by
// index-pack (empty when the pack was skipped or carried no keep file).
func (e *Engine) downloadUnlessSkippable(head string, p manifest.Pack, applied map[string]bool, closure func() bool) (keep string, err error) {
	if e.packSkippable(p, applied, closure) {
		return "", nil
	}
	return e.applyPack(head, p)
}

// packSkippable reports whether pack p can be marked applied without
// downloading it: either every pack it replaces is already applied, or the
// local repo already holds the complete object closure of every ref tip.
func (e *Engine) packSkippable(p manifest.Pack, applied map[string]bool, closure func() bool) bool {
	if replacesCovered(p, applied) {
		e.Log.Info("pack covered by applied predecessors; skipping download",
			"pack", p.ID[:12], "replaces", len(p.Replaces))
		return true
	}
	// Local repo already holds every object this pack would deliver.
	return closure()
}

// replacesCovered reports whether pack p supersedes earlier packs and every
// one of them is already applied locally, so p delivers nothing new.
func replacesCovered(p manifest.Pack, applied map[string]bool) bool {
	if len(p.Replaces) == 0 {
		return false
	}
	for _, r := range p.Replaces {
		if !applied[r] {
			return false
		}
	}
	return true
}

// lazyClosure returns a memoized predicate reporting whether the local repo
// holds the COMPLETE object closure of every manifest ref tip, not merely the
// tips. A tip can be present while its history is not (e.g. an interrupted
// prior index-pack, a graft, a partial prune); marking a pack applied in that
// case would permanently skip the pack that carries the missing objects, since
// the applied set is never re-examined. The check is computed at most once, and
// only when a pack actually needs the shortcut, so the common case where every
// pack is already applied pays nothing.
func (e *Engine) lazyClosure(refs map[string]string) func() bool {
	tips := make([]string, 0, len(refs))
	for _, oid := range refs {
		tips = append(tips, oid)
	}
	checked, complete := false, false
	return func() bool {
		if !checked {
			complete = e.HasObjectClosure(tips)
			checked = true
		}
		return complete
	}
}

// packTamperHint is attached to pack verify/decrypt failures. Unlike the
// manifest, a pack is only reached after the manifest already decrypted under
// the same key, so the key is provably correct and a failure here points at
// the host serving bad data rather than a wrong key.
const packTamperHint = "the manifest decrypted under this key but this pack did not, so the key is correct; the host likely served corrupted or tampered pack data. Re-fetch and check the debug log"

var errPackExceedsRecordedSize = errors.New("pack blob exceeds size recorded in manifest")

// exactSizeWriter streams at most expected bytes to dst and records the exact
// byte count. It stops the producer on the first excess byte instead of first
// writing an attacker-controlled blob of unbounded size to scratch storage.
type exactSizeWriter struct {
	dst      io.Writer
	expected int64
	written  int64
	overflow bool
}

func (w *exactSizeWriter) Write(p []byte) (int, error) {
	remaining := w.expected - w.written
	if remaining <= 0 {
		w.overflow = len(p) > 0
		return 0, errPackExceedsRecordedSize
	}
	if int64(len(p)) > remaining {
		n, err := w.dst.Write(p[:remaining])
		w.written += int64(n)
		w.overflow = true
		if err != nil {
			return n, err
		}
		if int64(n) != remaining {
			return n, io.ErrShortWrite
		}
		return n, errPackExceedsRecordedSize
	}
	n, err := w.dst.Write(p)
	w.written += int64(n)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// downloadVerifyPack downloads packs/<id>.age from the backend commit head
// into ctPath, hashing the ciphertext as it streams, and fails if the hash
// does not match the manifest pack id (the host served corrupted or tampered
// data, since the key is already proven correct by the manifest decrypt).
func (e *Engine) downloadVerifyPack(head, ctPath string, p manifest.Pack) error {
	if e.Cfg.MaxPackBytes > 0 && p.Size > e.Cfg.MaxPackBytes {
		return cloakerr.Newfh(cloakerr.TooLarge, "download pack "+p.ID[:12],
			"raise `git config cloak.maxPackBytes <bytes>` only after confirming this remote intentionally contains a pack of that size",
			"manifest records %d bytes, exceeding the local receive limit of %d", p.Size, e.Cfg.MaxPackBytes)
	}
	f, err := os.OpenFile(ctPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- ctPath is TmpDir()+content-addressed name (pack id is 64-hex, manifest.Validate); no untrusted path component
	if err != nil {
		return fmt.Errorf("create pack ciphertext scratch file %q: %w", ctPath, err)
	}
	hasher := sha256.New()
	exact := &exactSizeWriter{dst: io.MultiWriter(f, hasher), expected: p.Size}
	readErr := e.Be.ReadBlob(head, "packs/"+p.ID+".age", exact)
	if exact.overflow || errors.Is(readErr, errPackExceedsRecordedSize) {
		closeErr := f.Close()
		tamperErr := cloakerr.Newf(cloakerr.Tamper, "verify pack "+p.ID[:12],
			"remote blob exceeds the authenticated manifest size of %d bytes", p.Size).WithHint(packTamperHint)
		if closeErr != nil {
			return errors.Join(tamperErr, fmt.Errorf("close pack ciphertext scratch file %q: %w", ctPath, closeErr))
		}
		return tamperErr
	}
	if readErr != nil {
		if closeErr := f.Close(); closeErr != nil {
			return errors.Join(readErr, fmt.Errorf("close pack ciphertext scratch file %q: %w", ctPath, closeErr))
		}
		return readErr
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close pack ciphertext scratch file %q: %w", ctPath, err)
	}
	if exact.written != p.Size {
		return cloakerr.Newf(cloakerr.Tamper, "verify pack "+p.ID[:12],
			"remote blob is %d bytes but the authenticated manifest records %d", exact.written, p.Size).WithHint(packTamperHint)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != p.ID {
		return cloakerr.Newf(cloakerr.Tamper, "verify pack "+p.ID[:12],
			"ciphertext hash %s does not match manifest id %s", got, p.ID).WithHint(packTamperHint)
	}
	return nil
}

// verifyReusedPackBlob streams an already-stored pack blob (packs/<id>.age) from
// the given backend commit and confirms its ciphertext still hashes to its
// manifest pack id. The push path reuses host-served pack blobs from the current
// backend tree by OID without re-downloading them (treePackBlobs); without this
// check a host that swapped a pack blob's content under the same manifest id
// could be laundered into a freshly signed new generation that every client then
// fails to fetch (CR-001). This mirrors downloadVerifyPack's fetch-side check
// but hashes only (no temp file), since the reused blob is not applied locally.
// ReadBlob streams into the hasher, so memory stays bounded regardless of pack
// size; the cost is re-reading reused live packs (local I/O, bounded by
// geometric consolidation keeping the live-pack count ~log(pushes)).
func (e *Engine) verifyReusedPackBlob(commit string, p manifest.Pack) error {
	if e.Cfg.MaxPackBytes > 0 && p.Size > e.Cfg.MaxPackBytes {
		return cloakerr.Newfh(cloakerr.TooLarge, "verify reused pack "+p.ID[:12],
			"raise `git config cloak.maxPackBytes <bytes>` only after confirming this remote intentionally contains a pack of that size",
			"manifest records %d bytes, exceeding the local receive limit of %d", p.Size, e.Cfg.MaxPackBytes)
	}
	hasher := sha256.New()
	exact := &exactSizeWriter{dst: hasher, expected: p.Size}
	readErr := e.Be.ReadBlob(commit, "packs/"+p.ID+".age", exact)
	if exact.overflow || errors.Is(readErr, errPackExceedsRecordedSize) {
		return cloakerr.Newf(cloakerr.Tamper, "verify reused pack "+p.ID[:12],
			"remote blob exceeds the authenticated manifest size of %d bytes", p.Size).WithHint(packTamperHint)
	}
	if readErr != nil {
		return readErr
	}
	if exact.written != p.Size {
		return cloakerr.Newf(cloakerr.Tamper, "verify reused pack "+p.ID[:12],
			"remote blob is %d bytes but the authenticated manifest records %d", exact.written, p.Size).WithHint(packTamperHint)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); got != p.ID {
		return cloakerr.Newf(cloakerr.Tamper, "verify reused pack "+p.ID[:12],
			"ciphertext hash %s does not match manifest id %s", got, p.ID).WithHint(packTamperHint)
	}
	return nil
}

// applyPack downloads packs/<id>.age, verifies and decrypts it, and feeds
// the plaintext pack to git index-pack in the local repository.
func (e *Engine) applyPack(head string, p manifest.Pack) (keepFile string, err error) {
	short := p.ID[:12]
	ctPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".age")
	ptPath := filepath.Join(e.St.TmpDir(), "pack-"+short+".pack")
	defer joinScratchRemoval(ctPath, "pack ciphertext", &err)
	defer joinScratchRemoval(ptPath, "decrypted pack", &err)

	if err := e.downloadVerifyPack(head, ctPath, p); err != nil {
		return "", err
	}
	if err := e.decryptPackTo(ctPath, ptPath); err != nil {
		return "", err
	}
	return e.indexPackFile(ptPath, short, p.Size)
}

// decryptPackTo decrypts the age ciphertext at ctPath and writes the
// plaintext pack to ptPath, classifying AEAD failures as Tamper.
func (e *Engine) decryptPackTo(ctPath, ptPath string) (retErr error) {
	ct, err := os.Open(ctPath) // #nosec G304 -- ctPath is TmpDir()+content-addressed name (pack id is 64-hex, manifest.Validate); no untrusted path component
	if err != nil {
		return fmt.Errorf("open pack ciphertext scratch file %q: %w", ctPath, err)
	}
	defer func() {
		if err := ct.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close pack ciphertext scratch file %q: %w", ctPath, err))
		}
	}()
	plain, err := agecrypt.Decrypt(ct, e.Key)
	if err != nil {
		return cloakerr.WithHintOn(err, packTamperHint)
	}
	ptFile, err := os.OpenFile(ptPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600) // #nosec G304 -- ptPath is TmpDir()+content-addressed name (pack id is 64-hex, manifest.Validate); no untrusted path component
	if err != nil {
		return fmt.Errorf("create pack plaintext scratch file %q: %w", ptPath, err)
	}
	if _, err := io.Copy(ptFile, plain); err != nil {
		closeErr := ptFile.Close()
		return errors.Join(cloakerr.WithHintOn(err, packTamperHint), closeErr) // Tamper-classified by agecrypt on AEAD failure
	}
	if err := ptFile.Close(); err != nil {
		return fmt.Errorf("close pack plaintext scratch file %q: %w", ptPath, err)
	}
	return nil
}

// indexPackFile feeds the plaintext pack at ptPath to git index-pack in the
// local repo and returns the .keep file it created (empty if none).
func (e *Engine) indexPackFile(ptPath, short string, size int64) (keepFile string, err error) {
	pt, err := os.Open(ptPath) // #nosec G304 -- ptPath is TmpDir()+content-addressed name (pack id is 64-hex, manifest.Validate); no untrusted path component
	if err != nil {
		return "", fmt.Errorf("open pack plaintext scratch file %q: %w", ptPath, err)
	}
	defer func() {
		if closeErr := pt.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close pack plaintext scratch file %q: %w", ptPath, closeErr))
		}
	}()
	out, _, err := e.G.Run(gitx.Opts{GitDir: e.LocalGitDir, Stdin: pt},
		"index-pack", "--stdin", "--keep=cloak")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "index pack "+short, err)
	}
	e.Log.Info("applied pack", "pack", short, "ciphertext_bytes", size)
	return keepFileFromIndexPack(e.LocalGitDir, out), nil
}

// keepFileFromIndexPack parses `git index-pack --keep=cloak` stdout for the
// first "keep\t<hash>" line and returns the matching .keep lock-file path
// (gitDir/objects/pack/pack-<hash>.keep), or "" when no keep line is present.
// index-pack prints exactly one such line per kept pack ("keep" then a tab then
// the pack sha); the returned path is what the helper reports to git as the
// fetch "lock" line (helper.go handleFetch), the marker that stops git from
// garbage-collecting the just-applied pack, so a mis-parse would drop a lock git
// needs or name the wrong file. Extracted from indexPackFile (behavior-
// preserving) so the parse is fuzz-reachable without a git host.
func keepFileFromIndexPack(gitDir, out string) string {
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		kind, hash, found := strings.Cut(strings.TrimSpace(line), "\t")
		if found && kind == "keep" {
			return filepath.Join(gitDir, "objects", "pack", "pack-"+hash+".keep")
		}
	}
	return ""
}

// HeadForList resolves the symref target to advertise for HEAD: the
// manifest head if valid, else main > master > first branch alphabetically.
func HeadForList(m *manifest.Manifest) string {
	if m == nil {
		return ""
	}
	if m.Head != "" {
		if _, ok := m.Refs[m.Head]; ok {
			return m.Head
		}
	}
	for _, cand := range []string{"refs/heads/main", "refs/heads/master"} {
		if _, ok := m.Refs[cand]; ok {
			return cand
		}
	}
	return firstBranch(m)
}

// firstBranch returns the alphabetically-first refs/heads/* ref in the
// manifest, or "" when the manifest advertises no branches. It is the final
// fallback for HeadForList once the manifest head and main/master are ruled out.
func firstBranch(m *manifest.Manifest) string {
	var branches []string
	for name := range m.Refs {
		if strings.HasPrefix(name, "refs/heads/") {
			branches = append(branches, name)
		}
	}
	if len(branches) == 0 {
		return ""
	}
	sort.Strings(branches)
	return branches[0]
}
