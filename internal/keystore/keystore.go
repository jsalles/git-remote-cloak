// Package keystore manages the cloak master key behind a small interface:
// key generation, a redacting Key type that cannot leak through logging or
// serialization, an export/import encoding for the one-time machine transfer
// and backups, and storage backends. M1 ships the file backend (0600,
// FileVault as at-rest protection); the darwin native Keychain backend with
// Touch ID gating lands in M5.
package keystore

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
)

// ErrKeyExists is wrapped by Save when a key already exists at the reference,
// so callers (e.g. keygen) can detect it and guide the user to delete first.
var ErrKeyExists = errors.New("a key already exists at this reference")

// KeySize is the master key length in bytes (256-bit).
const KeySize = 32

// maxKeyFileBytes bounds reads of the tiny text export format. It leaves ample
// room for whitespace while preventing a corrupt or misconfigured 0600 path
// from being materialized without limit.
const maxKeyFileBytes = 4096

// exportPrefix tags the copy-paste-safe export encoding so imports can
// validate they were handed a cloak key and not something else.
const exportPrefix = "cloak-key-v0:"

// Key holds master key bytes. It redacts itself in every formatter and
// serializer; the raw bytes are reachable only via Bytes(), which only the
// agecrypt package may consume. Key bytes MUST never reach a logger.
type Key struct {
	bytes []byte
	id    string
}

// NewKey copies b into a Key. b must be exactly KeySize bytes.
func NewKey(b []byte) (Key, error) {
	if len(b) != KeySize {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "new key",
			"key must be %d bytes, got %d", KeySize, len(b))
	}
	cp := make([]byte, KeySize)
	copy(cp, b)
	sum := sha256.Sum256(cp)
	return Key{bytes: cp, id: hex.EncodeToString(sum[:4])}, nil
}

// Generate returns a fresh random master key.
func Generate() (Key, error) {
	b := make([]byte, KeySize)
	if _, err := rand.Read(b); err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "generate key", err)
	}
	return NewKey(b)
}

// ID returns a short non-secret fingerprint (first 8 hex of SHA-256).
func (k Key) ID() string { return k.id }

// IsZero reports whether k holds no key material.
func (k Key) IsZero() bool { return len(k.bytes) == 0 }

// Equal compares complete key material in constant time. The short ID is for
// diagnostics only and must never be used to make key-management decisions.
func (k Key) Equal(other Key) bool {
	if len(k.bytes) != KeySize || len(other.bytes) != KeySize {
		return false
	}
	return subtle.ConstantTimeCompare(k.bytes, other.bytes) == 1
}

// Bytes returns the raw key. RESTRICTED: only the agecrypt wrap/unwrap path
// may call this; the result must never be logged or serialized.
func (k Key) Bytes() []byte { return k.bytes }

// Wipe best-effort zeroes the key's backing bytes. This is defense in depth,
// NOT a guarantee: Go's garbage collector may relocate or have already copied
// the array, and derived material inside crypto primitives is not reached.
// All copies of a Key share one backing array, so wiping any copy clears it
// for the rest. Call when the key is no longer needed (e.g. session close).
func (k Key) Wipe() {
	for i := range k.bytes {
		k.bytes[i] = 0
	}
}

func (k Key) redacted() string {
	if k.IsZero() {
		return "[redacted:keyid=none]"
	}
	return "[redacted:keyid=" + k.id + "]"
}

// String implements fmt.Stringer with redaction.
func (k Key) String() string { return k.redacted() }

// GoString implements fmt.GoStringer with redaction (covers %#v).
func (k Key) GoString() string { return k.redacted() }

// Format implements fmt.Formatter so every verb, including %x and %+v,
// emits the redacted form instead of key bytes.
func (k Key) Format(f fmt.State, verb rune) { fmt.Fprint(f, k.redacted()) }

// MarshalJSON redacts the key in JSON output (e.g. structured logs).
func (k Key) MarshalJSON() ([]byte, error) { return json.Marshal(k.redacted()) }

// MarshalText redacts the key in text serializers.
func (k Key) MarshalText() ([]byte, error) { return []byte(k.redacted()), nil }

// LogValue redacts the key under log/slog.
func (k Key) LogValue() any { return k.redacted() }

// Export returns the copy-paste-safe transfer/backup encoding. Handle the
// result like the key itself.
func (k Key) Export() string {
	return exportPrefix + base64.StdEncoding.EncodeToString(k.bytes)
}

// ParseExport decodes the Export encoding back into a Key.
func ParseExport(s string) (Key, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, exportPrefix)
	if !ok {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "import key",
			"input does not look like a cloak key export (missing %q prefix)", exportPrefix)
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "import key", err)
	}
	return NewKey(b)
}

// Keychain hooks, installed by keychain_darwin.go on cgo darwin builds.
var (
	keychainAvailable bool
	keychainLoad      func(name string) ([]byte, error)
	keychainSave      func(name string, data []byte) error
	keychainDelete    func(name string) error
)

// FileDefaultRef is the file-backend default location, used as the default
// keyRef on platforms without Keychain support and as the documented
// fallback on darwin.
func FileDefaultRef() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "file:cloak-master-key"
	}
	return "file:" + filepath.Join(home, ".config", "cloak", "keys", "default")
}

// refKind classifies a key reference's transport scheme. Load, Save, and
// Delete share this single decision so the three operations always route a
// given reference to the same backend (or reject it identically) -- a drift
// between them could, for example, save a key under one backend while delete
// looks in another and silently leaves key material behind.
type refKind int

const (
	refMalformed refKind = iota // no ":" separator -> not a key reference at all
	refFile                     // file:<path>
	refKeychain                 // keychain:<name>
	refUnknown                  // a ":"-bearing reference whose scheme is unrecognized
)

// classifyRef splits ref on its first ":" and classifies the scheme. scheme is
// the portion before that first ":" (the whole reference when there is none);
// rest is the portion after it (the file path or keychain name), empty for a
// malformed reference. Only an exact "file"/"keychain" scheme selects a
// backend; everything else fails closed (refMalformed or refUnknown).
func classifyRef(ref string) (refKind, string, string) {
	scheme, rest, found := strings.Cut(ref, ":")
	switch {
	case !found:
		return refMalformed, scheme, rest
	case scheme == "file":
		return refFile, scheme, rest
	case scheme == "keychain":
		return refKeychain, scheme, rest
	default:
		return refUnknown, scheme, rest
	}
}

// Load resolves a key reference ("file:<path>" or "keychain:<name>") and
// loads the key.
func Load(ref string) (Key, error) {
	kind, scheme, rest := classifyRef(ref)
	switch kind {
	case refFile:
		return loadFile(expandHome(rest))
	case refKeychain:
		if !keychainAvailable {
			return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
				"this build has no Keychain support (non-darwin or cgo disabled); use file:<path>")
		}
		b, err := keychainLoad(rest)
		if err != nil {
			return Key{}, err
		}
		return ParseExport(string(b))
	case refMalformed:
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
			"malformed key reference %q (want file:<path> or keychain:<name>)", ref)
	default:
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key",
			"unknown key reference scheme %q", scheme)
	}
}

// Save stores the key at the given reference. Both backends refuse to
// overwrite an existing key.
func Save(ref string, k Key) error {
	kind, scheme, rest := classifyRef(ref)
	switch kind {
	case refFile:
		return saveFile(expandHome(rest), k)
	case refKeychain:
		if !keychainAvailable {
			return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
				"this build has no Keychain support (non-darwin or cgo disabled); use file:<path>")
		}
		return keychainSave(rest, []byte(k.Export()))
	case refMalformed:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
			"malformed key reference %q", ref)
	default:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "save key",
			"unknown key reference scheme %q", scheme)
	}
}

// Delete removes a stored key (used by tests and key rotation cleanup).
func Delete(ref string) error {
	kind, scheme, rest := classifyRef(ref)
	switch kind {
	case refFile:
		// Wrap with the same operation context and Kind as loadFile/saveFile and
		// the sibling switch arms, so a failed file delete (missing key, no
		// permission) surfaces as a classified "delete key file" error instead of
		// a bare os.PathError - the only delete branch that previously leaked one.
		return deleteFile(expandHome(rest))
	case refKeychain:
		if !keychainAvailable {
			return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "no Keychain support in this build")
		}
		return keychainDelete(rest)
	case refMalformed:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "malformed key reference %q", ref)
	default:
		return cloakerr.Newf(cloakerr.KeyUnavailable, "delete key", "unknown key reference scheme %q", scheme)
	}
}

// removeStaleKeyTemps removes private regular temp files matching saveFile's
// reserved basename prefix. A crash can leave a complete key either before the
// hard-link install (different inode) or after it (same inode as final); the
// per-key flock ensures no current Save owns a matching temp while this runs.
func removeStaleKeyTemps(path string) error {
	dir := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	removed := false
	for _, entry := range entries {
		if !isGeneratedKeyTemp(prefix, entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, owned := info.Sys().(*syscall.Stat_t)
		if info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && owned && int(stat.Uid) == os.Getuid() {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
			removed = true
		}
	}
	if removed {
		return syncParentDir(dir)
	}
	return nil
}

// isGeneratedKeyTemp recognizes the numeric suffix emitted by os.CreateTemp
// for saveFile's ".<base>.tmp-*" pattern. Merely sharing the human-readable
// prefix is insufficient: an operator's `.key.tmp-backup` must not be deleted.
func isGeneratedKeyTemp(prefix, name string) bool {
	suffix, ok := strings.CutPrefix(name, prefix)
	if !ok || suffix == "" {
		return false
	}
	for i := range len(suffix) {
		if suffix[i] < '0' || suffix[i] > '9' {
			return false
		}
	}
	return true
}

func expandHome(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(p[1:], "/"))
		}
	}
	return p
}

func loadFile(path string) (key Key, retErr error) {
	if unlock, locked, err := lockExistingFileKey(path); err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "lock key file for load", err)
	} else if locked {
		defer func() {
			if err := unlock(); err != nil {
				if retErr == nil {
					key.Wipe()
					key = Key{}
				}
				retErr = errors.Join(retErr, cloakerr.New(cloakerr.KeyUnavailable, "unlock key file after load", err))
			}
		}()
		if err := removeStaleKeyTemps(path); err != nil {
			return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "clean stale key temp files before load", err)
		}
	}
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key file",
			"%s is a symbolic link; refusing to follow key-file symlinks", path)
	}
	if !pathInfo.Mode().IsRegular() {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key file",
			"%s is not a regular file", path)
	}
	f, err := os.Open(path) // #nosec G304 -- path is the operator's own configured key file; the lstat/fstat checks below reject symlinks and replacement races
	if err != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", err)
	}
	openedInfo, statErr := f.Stat()
	currentInfo, lstatErr := os.Lstat(path)
	if statErr != nil || lstatErr != nil || !openedInfo.Mode().IsRegular() ||
		currentInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, currentInfo) || !os.SameFile(pathInfo, openedInfo) {
		closeErr := f.Close()
		cause := errors.Join(statErr, lstatErr, closeErr)
		if cause == nil {
			cause = errors.New("key path changed while it was being opened")
		}
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", cause)
	}
	if perm := openedInfo.Mode().Perm(); perm&0o077 != 0 {
		closeErr := f.Close()
		err := cloakerr.Newf(cloakerr.KeyUnavailable, "load key file",
			"%s has mode %04o; refusing group/world-accessible key files (want 0600)", path, perm)
		if closeErr != nil {
			return Key{}, errors.Join(err, cloakerr.New(cloakerr.KeyUnavailable, "close key file", closeErr))
		}
		return Key{}, err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	closeErr := f.Close()
	if readErr != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "load key file", errors.Join(readErr, closeErr))
	}
	if closeErr != nil {
		return Key{}, cloakerr.New(cloakerr.KeyUnavailable, "close key file", closeErr)
	}
	if len(b) > maxKeyFileBytes {
		return Key{}, cloakerr.Newf(cloakerr.KeyUnavailable, "load key file",
			"%s exceeds the %d-byte key-file limit", path, maxKeyFileBytes)
	}
	return ParseExport(string(b))
}

func saveFile(path string, k Key) (retErr error) {
	dir := filepath.Dir(path)
	if err := durableMkdirAll(dir, 0o700); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	unlock, err := lockFileKey(path)
	if err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "lock key file for save", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			retErr = errors.Join(retErr, cloakerr.New(cloakerr.KeyUnavailable, "unlock key file after save", err))
		}
	}()
	if err := removeStaleKeyTemps(path); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "clean stale key temp files before save", err)
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-") // #nosec G304 -- the operator chooses the destination directory; CreateTemp supplies an unpredictable O_EXCL name in that same directory
	if err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	tmp := f.Name()
	defer func() {
		if tmp == "" {
			return
		}
		if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
			cleanupErr := cloakerr.New(cloakerr.KeyUnavailable, "save key file",
				fmt.Errorf("remove temporary key file %q: %w", tmp, err))
			retErr = errors.Join(retErr, cleanupErr)
			return
		}
		if err := syncParentDir(dir); err != nil {
			cleanupErr := cloakerr.New(cloakerr.KeyUnavailable, "save key file",
				fmt.Errorf("sync parent directory %q after temporary-file cleanup: %w", dir, err))
			retErr = errors.Join(retErr, cleanupErr)
		}
	}()

	// Build and fsync the complete key under an unpredictable 0600 name in the
	// destination directory. The final path remains absent until installation,
	// so a crash or ordinary write failure can never expose a partial key there.
	if err := f.Chmod(0o600); err != nil {
		closeErr := f.Close()
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", errors.Join(err, closeErr))
	}
	payload := k.Export() + "\n"
	n, err := f.WriteString(payload)
	if err == nil && n != len(payload) {
		err = io.ErrShortWrite
	}
	if err != nil {
		closeErr := f.Close()
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", errors.Join(err, closeErr))
	}
	if err := f.Sync(); err != nil {
		closeErr := f.Close()
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", errors.Join(err, closeErr))
	}
	if err := f.Close(); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}

	// A same-directory hard link is an atomic no-replace installation on both
	// macOS and Linux: it either creates path pointing at the fully-synced inode,
	// or fails with EEXIST without touching the old key. A rename cannot provide
	// that invariant portably because os.Rename replaces its destination.
	if err := os.Link(tmp, path); err != nil {
		if os.IsExist(err) {
			return cloakerr.New(cloakerr.KeyUnavailable, "save key file",
				fmt.Errorf("%s already exists; refusing to overwrite a key: %w", path, ErrKeyExists))
		}
		return cloakerr.New(cloakerr.KeyUnavailable, "save key file", err)
	}
	if err := os.Remove(tmp); err != nil {
		// Still fsync the directory below: the complete final key is installed,
		// even though removing its temporary hard link failed.
		retErr = cloakerr.New(cloakerr.KeyUnavailable, "save key file",
			fmt.Errorf("remove temporary key file %q: %w", tmp, err))
	} else {
		tmp = ""
	}
	if err := syncParentDir(dir); err != nil {
		retErr = errors.Join(retErr, cloakerr.New(cloakerr.KeyUnavailable, "save key file",
			fmt.Errorf("sync parent directory %q: %w", dir, err)))
	}
	return retErr
}

func deleteFile(path string) (retErr error) {
	unlock, err := lockFileKey(path)
	if err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "lock key file for delete", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			retErr = errors.Join(retErr, cloakerr.New(cloakerr.KeyUnavailable, "unlock key file after delete", err))
		}
	}()
	if err := removeStaleKeyTemps(path); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "delete key file", err)
	}
	if err := os.Remove(path); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "delete key file", err)
	}
	if err := syncParentDir(filepath.Dir(path)); err != nil {
		return cloakerr.New(cloakerr.KeyUnavailable, "delete key file",
			fmt.Errorf("sync parent directory after deletion: %w", err))
	}
	return nil
}

func lockFileKey(path string) (func() error, error) {
	dir := filepath.Dir(path)
	lockPath := filepath.Join(dir, "."+filepath.Base(path)+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lock lives beside the operator-configured key and contains no secret
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		closeErr := f.Close()
		return nil, errors.Join(err, closeErr)
	}
	if err := syncParentDir(dir); err != nil {
		return nil, errors.Join(err, syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
	}
	return func() error {
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		closeErr := f.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}

// lockExistingFileKey acquires the persistent lock created by Save. If it is
// missing (including after a crash before the directory entry became durable),
// it creates a new durable lock and then cleans any stale temp under it. A
// manually provisioned key in a read-only directory may load without a lock
// only when no cloak-shaped temp exists and no writer can create one there.
func lockExistingFileKey(path string) (unlock func() error, locked bool, err error) {
	lockPath := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".lock")
	f, err := os.Open(lockPath) // #nosec G304 -- lock lives beside the operator-configured key and contains no secret
	if os.IsNotExist(err) {
		unlock, err := lockFileKey(path)
		if err == nil {
			return unlock, true, nil
		}
		if !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.EROFS) {
			return nil, false, err
		}
		hasTemp, scanErr := hasGeneratedKeyTemp(path)
		if scanErr != nil {
			return nil, false, errors.Join(err, scanErr)
		}
		if hasTemp {
			return nil, false, fmt.Errorf("cannot lock key file while an interrupted-save temp exists: %w", err)
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return nil, false, errors.Join(err, f.Close())
	}
	return func() error {
		return errors.Join(syscall.Flock(int(f.Fd()), syscall.LOCK_UN), f.Close())
	}, true, nil
}

func hasGeneratedKeyTemp(path string) (bool, error) {
	dir := filepath.Dir(path)
	prefix := "." + filepath.Base(path) + ".tmp-"
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if isGeneratedKeyTemp(prefix, entry.Name()) {
			return true, nil
		}
	}
	return false, nil
}

// durableMkdirAll creates path and fsyncs every parent whose directory entry
// was newly added. Without those parent syncs, a power loss after a first key
// save could preserve the key inode but lose one of its newly created ancestor
// directories, making the only local key disappear on reboot.
func durableMkdirAll(path string, perm os.FileMode) error {
	var missing []string
	for cur := filepath.Clean(path); ; cur = filepath.Dir(cur) {
		if _, err := os.Stat(cur); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return err
		}
		missing = append(missing, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
	}
	if err := os.MkdirAll(path, perm); err != nil {
		return err
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := syncParentDir(filepath.Dir(missing[i])); err != nil {
			return fmt.Errorf("sync parent of new key directory %q: %w", missing[i], err)
		}
	}
	return nil
}

func syncParentDir(path string) error {
	d, err := os.Open(path) // #nosec G304 -- path is the operator-selected parent directory of the configured key file
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		closeErr := d.Close()
		return errors.Join(err, closeErr)
	}
	if err := d.Close(); err != nil {
		return err
	}
	return nil
}
