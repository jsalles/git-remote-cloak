// Package setup constructs a ready cloak session, shared by the remote
// helper and the git-cloak operator commands: repository path resolution,
// SHA-1 object-format check, cloak.* config, master key, per-remote state
// directory with its flock, per-repo file logging, the backend mirror, and
// the validated remote state (fetch + AEAD + rollback pin).
package setup

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/backend"
	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/config"
	"github.com/b4ryon/git-remote-cloak/internal/engine"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/keystore"
	"github.com/b4ryon/git-remote-cloak/internal/logx"
	"github.com/b4ryon/git-remote-cloak/internal/state"
	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
)

// Session is a fully wired engine plus validated remote state. Close
// releases the state lock and the log file.
type Session struct {
	G   *gitx.G
	Eng *engine.Engine
	RS  *engine.RemoteState
	Log *slog.Logger
	Cfg config.Config
	St  *state.Dir

	closers []func()
}

// Close releases resources in reverse order.
func (s *Session) Close() {
	for i := len(s.closers) - 1; i >= 0; i-- {
		s.closers[i]()
	}
}

// Open builds the session and validates the remote (fetch + AEAD +
// rollback pin). url may be empty, in which case it is resolved from
// remote.<remoteName>.url and must use the cloak:: scheme (the helper
// passes the url git gave it; CLI commands pass "").
func Open(remoteName, url string, stderr io.Writer, role string) (*Session, error) {
	s, err := OpenLocal(remoteName, url, stderr, role)
	if err != nil {
		return nil, err
	}
	if err := s.LoadRemote(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// LoadRemote fetches and validates the remote state into s.RS.
func (s *Session) LoadRemote() error {
	rs, err := s.Eng.LoadRemoteState()
	if err != nil {
		return err
	}
	s.RS = rs
	return nil
}

// LoadRemoteUnchecked refreshes s.RS without applying local rollback or
// repository-identity pins. It exists only for explicit accept-* recovery,
// which verifies all referenced storage before replacing the old anchors.
func (s *Session) LoadRemoteUnchecked() error {
	rs, err := s.Eng.LoadRemoteStateUnchecked()
	if err != nil {
		return err
	}
	s.RS = rs
	return nil
}

// OpenLocal wires everything local (paths, config, key, state lock,
// logging, backend mirror, engine) WITHOUT touching the remote. Explicit
// accept-* recovery uses it to retain the old trust anchors while loading and
// verifying a candidate through LoadRemoteUnchecked.
func OpenLocal(remoteName, url string, stderr io.Writer, role string) (*Session, error) {
	boot, _ := logx.Setup(logx.Options{Stderr: stderr, StderrLevel: slog.LevelWarn, Role: role})
	g := gitx.New(boot)

	localGitDir, common, err := resolveGitDirs(g)
	if err != nil {
		return nil, err
	}

	cfg, err := config.Load(g, localGitDir)
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "read cloak config", err)
	}

	explicitURL := url != ""
	url, err = resolveBackendURL(g, localGitDir, remoteName, url)
	if err != nil {
		return nil, err
	}
	if err := checkPlaintextRoutes(g, localGitDir, remoteName); err != nil {
		return nil, err
	}
	stateName, selector := stateIdentity(g, localGitDir, remoteName, url, explicitURL)

	return wireSession(g, cfg, sessionPaths{
		localGitDir: localGitDir, common: common, url: url,
		remoteName: remoteName, stateName: stateName, selector: selector,
	}, stderr, role)
}

// stateIdentity decides how this backend's local state directory is keyed and
// how git-cloak commands address it. The remote name keys the state only when
// url IS the remote's fetch URL (CLI calls resolve url from it, so they always
// match); any other URL -- an extra push URL, an anonymous cloak:: URL, a
// direct helper invocation with an unconfigured name -- keys by the URL itself
// (state.DirName's url-hash branch), giving every backend an independent
// mirror, lock, pin set, and applied set. Fixes the shared-state rollback
// alarm on remotes with multiple push URLs (issue #3). The returned selector
// is the flag suffix alarm messages append to accept-rollback /
// accept-repo-change so the printed command targets this exact state dir
// (empty when a bare `git cloak <cmd>` already does).
func stateIdentity(g *gitx.G, localGitDir, remoteName, url string, explicitURL bool) (stateName, selector string) {
	if !explicitURL || matchesFetchURL(g, localGitDir, remoteName, url) {
		if remoteName != "origin" {
			return remoteName, "--remote " + urlredact.ShellArg(urlredact.URL(remoteName))
		}
		return remoteName, ""
	}
	return "", "--url " + urlredact.ShellArg(urlredact.URL("cloak::"+url))
}

// matchesFetchURL reports whether url (already cloak::-stripped) is
// remoteName's configured fetch URL. Git applies url.<base>.insteadOf
// rewrites before invoking a helper, so the raw config value is compared
// first and `git ls-remote --get-url` (which applies the same rewrites
// without contacting the remote) second. Only the FIRST configured
// remote.<name>.url counts: git fetches from it alone, while extra url
// entries -- like pushurl entries -- are push-only targets that need their
// own state. An unconfigured remoteName never matches: git only passes
// configured names, so anything else keys by URL.
func matchesFetchURL(g *gitx.G, localGitDir, remoteName, url string) bool {
	if remoteName == "" {
		return false
	}
	raw, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{remoteName}},
		"config", "--get-all", "remote."+remoteName+".url")
	if err != nil || raw == "" {
		return false
	}
	if i := strings.IndexByte(raw, '\n'); i >= 0 {
		raw = raw[:i]
	}
	resolved, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{raw}},
		"ls-remote", "--get-url", "--", remoteName)
	if err != nil {
		return false
	}
	inner := strings.TrimPrefix(resolved, "cloak::")
	innerResolved, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{inner}},
		"ls-remote", "--get-url", "--", inner)
	return err == nil && innerResolved == url
}

// resolveGitDirs resolves the local git directory (honoring GIT_DIR) and the
// git common dir, then rejects non-sha1 object formats (v0 is sha1-only).
func resolveGitDirs(g *gitx.G) (localGitDir, common string, err error) {
	gd := os.Getenv("GIT_DIR")
	localGitDir, err = g.Out(gitx.Opts{GitDir: gd}, "rev-parse", "--absolute-git-dir")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "resolve git dir", err)
	}
	common, err = g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--git-common-dir")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "resolve git common dir", err)
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(localGitDir, common)
	}
	common = filepath.Clean(common)

	format, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--show-object-format")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect object format", err)
	}
	if format != "sha1" {
		return "", "", cloakerr.Newf(cloakerr.LocalGit, "object format",
			"%s repositories are not supported in v0 (sha1 only)", format)
	}
	shallow, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--is-shallow-repository")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect shallow repository state", err)
	}
	if shallow == "true" {
		return "", "", cloakerr.Newf(cloakerr.LocalGit, "repository topology",
			"shallow repositories are not supported because omitted history would weaken object-closure verification")
	}
	replacements, err := g.Out(gitx.Opts{GitDir: localGitDir}, "replace", "-l")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect replacement objects", err)
	}
	if replacements != "" {
		return "", "", cloakerr.Newf(cloakerr.LocalGit, "repository topology",
			"git replace objects are not supported because they alter authenticated history traversal")
	}
	graftsPath, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--path-format=absolute", "--git-path", "info/grafts")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect grafts path", err)
	}
	if fi, statErr := os.Stat(graftsPath); statErr == nil && fi.Size() > 0 {
		return "", "", cloakerr.Newf(cloakerr.LocalGit, "repository topology",
			"git grafts are not supported because they alter authenticated history traversal")
	} else if statErr != nil && !os.IsNotExist(statErr) {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect grafts file", statErr)
	}
	if path, err := lfsTrackedPath(g, localGitDir); err != nil {
		return "", "", err
	} else if path != "" {
		return "", "", cloakerr.Newfh(cloakerr.LocalGit, "repository attributes",
			"remove Git LFS attributes and objects before using cloak; the LFS transport bypasses cloak encryption",
			"tracked path %q uses filter=lfs", path)
	}
	hookPath, err := g.Out(gitx.Opts{GitDir: localGitDir}, "rev-parse", "--path-format=absolute", "--git-path", "hooks/pre-push")
	if err != nil {
		return "", "", cloakerr.New(cloakerr.LocalGit, "inspect pre-push hook path", err)
	}
	if usesLFS, err := lfsPrePushHook(hookPath); err != nil {
		return "", "", err
	} else if usesLFS {
		return "", "", cloakerr.Newfh(cloakerr.LocalGit, "repository hooks",
			"remove the Git LFS pre-push hook before using cloak; LFS uploads use a separate plaintext transport",
			"pre-push hook at %q invokes Git LFS", hookPath)
	}
	return localGitDir, common, nil
}

func lfsPrePushHook(path string) (bool, error) {
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, cloakerr.New(cloakerr.LocalGit, "inspect pre-push hook", err)
	}
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o111 == 0 {
		return false, nil // Git will not execute it as a hook.
	}
	const maxHookInspectionBytes = 1 << 20
	if fi.Size() > maxHookInspectionBytes {
		return false, cloakerr.Newfh(cloakerr.LocalGit, "inspect pre-push hook",
			"reduce or remove the hook, or verify manually that it cannot invoke a plaintext side transport such as Git LFS",
			"executable pre-push hook %q exceeds the %d-byte inspection limit", path, maxHookInspectionBytes)
	}
	f, err := os.Open(path) // #nosec G304 -- path comes from git rev-parse --git-path for the current repository
	if err != nil {
		return false, cloakerr.New(cloakerr.LocalGit, "inspect pre-push hook", err)
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxHookInspectionBytes+1))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil {
		return false, cloakerr.New(cloakerr.LocalGit, "read pre-push hook", errors.Join(readErr, closeErr))
	}
	if len(data) > maxHookInspectionBytes {
		return false, cloakerr.Newfh(cloakerr.LocalGit, "inspect pre-push hook",
			"reduce or remove the hook, or verify manually that it cannot invoke a plaintext side transport such as Git LFS",
			"executable pre-push hook %q changed beyond the %d-byte inspection limit", path, maxHookInspectionBytes)
	}
	lower := bytes.ToLower(data)
	return bytes.Contains(lower, []byte("git lfs pre-push")) ||
		bytes.Contains(lower, []byte("git-lfs pre-push")), nil
}

// lfsTrackedPath returns one indexed path whose effective Git attributes select
// the LFS filter. It asks Git to resolve repository, info, and global attribute
// rules exactly as a push hook would; NUL framing preserves unusual filenames.
func lfsTrackedPath(g *gitx.G, gitDir string) (string, error) {
	paths, _, err := g.Run(gitx.Opts{GitDir: gitDir}, "ls-files", "-z")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "enumerate tracked files for LFS", err)
	}
	if paths == "" {
		return "", nil
	}
	attrs, _, err := g.Run(gitx.Opts{GitDir: gitDir, Stdin: strings.NewReader(paths)},
		"check-attr", "--cached", "-z", "--stdin", "filter")
	if err != nil {
		return "", cloakerr.New(cloakerr.LocalGit, "inspect Git LFS attributes", err)
	}
	fields := bytes.Split([]byte(attrs), []byte{0})
	for i := 0; i+2 < len(fields); i += 3 {
		if string(fields[i+1]) == "filter" && string(fields[i+2]) == "lfs" {
			return string(fields[i]), nil
		}
	}
	return "", nil
}

// resolveBackendURL resolves and validates the backend transport URL. When url
// is empty it is the remote's first effective URL (the one Git fetches from),
// which must go through cloak (cloak:: prefix, or remote.<name>.vcs=cloak);
// the cloak:: prefix is then stripped and the result is rejected if empty or
// any external remote-helper transport (explicit ext::/fd::/nested syntax or
// an unknown scheme:// URL).
func resolveBackendURL(g *gitx.G, localGitDir, remoteName, url string) (string, error) {
	if url == "" {
		if _, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{remoteName}},
			"config", "--get-all", "remote."+remoteName+".url"); err != nil {
			return "", cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
				"remote %q has no configured URL", urlredact.URL(remoteName))
		}
		// Resolve url.*.insteadOf exactly as Git does before invoking a helper,
		// and validate that same first URL: it is the one Git fetches from.
		// --get-url performs no network access.
		resolved, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{remoteName}},
			"ls-remote", "--get-url", "--", remoteName)
		if err != nil {
			return "", cloakerr.New(cloakerr.LocalGit, "resolve rewritten remote URL", err)
		}
		vcs, err := remoteUsesCloakVCS(g, localGitDir, remoteName)
		if err != nil {
			return "", err
		}
		if !routesThroughCloak(resolved, vcs) {
			return "", cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
				"remote %q is not a cloak:: remote (url %q)", urlredact.URL(remoteName), urlredact.URL(resolved))
		}
		url = resolved
	}
	url = strings.TrimPrefix(url, "cloak::")
	if url == "" {
		return "", cloakerr.Newf(cloakerr.LocalGit, "resolve remote",
			"empty backend URL after the cloak:: prefix")
	}
	// The underlying transport is itself subject to url.*.insteadOf when the
	// private backend mirror invokes Git. Resolve and validate that effective URL
	// too, otherwise a harmless-looking alias could expand to embedded secrets.
	if g != nil {
		resolved, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{url}},
			"ls-remote", "--get-url", "--", url)
		if err != nil {
			return "", cloakerr.New(cloakerr.LocalGit, "resolve effective backend URL", err)
		}
		url = resolved
	}
	if risk := urlredact.CredentialRisk(url); risk != "" {
		return "", cloakerr.Newfh(cloakerr.LocalGit, "validate remote credentials",
			"use an SSH URL or Git credential helper; do not place credentials, query tokens, or fragments in a cloak backend URL",
			"refusing %s in backend URL %q", risk, urlredact.URL(url))
	}
	if urlredact.IsHelperTransport(url) {
		return "", cloakerr.Newf(cloakerr.LocalGit, "validate remote transport",
			"refusing remote-helper transport in backend URL (cloak does not allow ext::/fd:: or nested helpers)")
	}
	if !urlredact.IsSupportedTransport(url) {
		return "", cloakerr.Newfh(cloakerr.LocalGit, "validate remote transport",
			"use a local path, scp-like SSH location, or a file, git, http, https, ssh, or git+ssh URL",
			"refusing unsupported URL scheme because Git would execute an external remote helper")
	}
	return url, nil
}

// sessionPaths bundles the resolved local paths and remote identity threaded
// into wireSession, keeping its signature readable.
type sessionPaths struct {
	localGitDir string
	common      string
	url         string
	remoteName  string
	stateName   string // state-dir key; "" keys by url hash (non-fetch URL)
	selector    string // git-cloak flag suffix addressing this state dir
}

// wireSession opens the per-remote state dir and lock, sets up per-repo file
// logging, opens the backend mirror, and assembles the Engine. The returned
// Session owns the lock and log-file closers.
func wireSession(g *gitx.G, cfg config.Config, p sessionPaths, stderr io.Writer, role string) (*Session, error) {
	st, err := state.Open(p.common, p.stateName, p.url)
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "open state dir", err)
	}
	st.Selector = p.selector
	unlock, err := st.Lock()
	if err != nil {
		return nil, cloakerr.New(cloakerr.LocalGit, "lock state dir", err)
	}
	if err := st.CleanTmp(); err != nil {
		unlockErr := unlock()
		return nil, cloakerr.New(cloakerr.LocalGit, "clean stale scratch data", errors.Join(err, unlockErr))
	}
	key, err := keystore.Load(cfg.KeyRef)
	if err != nil {
		// Clean stale plaintext before attempting the key load. Name the actual
		// ref so a missing/misconfigured backend still has an actionable path.
		keyErr := cloakerr.WithHintOn(err,
			"the configured cloak.keyRef could not be loaded; verify it points at a key reference (never paste exported key material into Git config), then run `git cloak keygen` on the first machine or `git cloak key import` on a new machine")
		return nil, errors.Join(keyErr, unlock())
	}
	s := &Session{G: g, Cfg: cfg, St: st}
	// Release the lock (logging a failed unlock/close instead of dropping it)
	// then best-effort wipe the master key bytes when the session ends (see
	// keystore.Key.Wipe for the Go limitation).
	s.closers = []func(){
		func() {
			if err := unlock(); err != nil && s.Log != nil {
				s.Log.Warn("releasing state lock failed", "err", err)
			}
		},
		key.Wipe,
	}

	lg, closeLog := logx.Setup(logx.Options{
		Stderr:      stderr,
		StderrLevel: slog.LevelWarn,
		FilePath:    st.LogPath(),
		FileLevel:   logx.FileLevel(cfg.LogLevel),
		Role:        role,
	})
	s.Log = lg.With("remote", urlredact.URL(p.remoteName))
	s.closers = append(s.closers, closeLog)
	g.SetLogger(s.Log)
	s.Log.Info("session start", "url", urlredact.URL(p.url), "keyid", key.ID(), "branch", cfg.Branch)

	be, err := backend.Open(g, st.BackendGitDir(), p.url, cfg.Branch, s.Log)
	if err != nil {
		s.Close()
		return nil, err
	}
	s.Eng = &engine.Engine{
		G: g, LocalGitDir: p.localGitDir, St: st, Be: be,
		Key: key, Cfg: cfg, Log: s.Log,
	}
	// Reap any of cloak's own leftover pack .keep lock files now that the engine
	// and the per-remote lock are both in place. git can clean only one pack
	// lock per fetch, so multi-pack fetches (notably clones) leave orphan .keep
	// files that would otherwise pin those packs against gc/repack forever; this
	// removes the ones whose objects are now reachable from refs. Best-effort and
	// fail-safe: it never fails the session and touches nothing it cannot prove
	// safe (see engine.ReapOrphanKeeps).
	s.Eng.ReapOrphanKeeps()
	return s, nil
}
