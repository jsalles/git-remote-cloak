// Package gitx runs git subprocesses for cloak with a controlled
// environment, captured stderr, duration logging, and typed errors that the
// error-taxonomy classifier (M5) consumes. Every git invocation in the
// helper and engine goes through this package.
package gitx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
)

// defaultGitTimeout bounds a git invocation when no context is supplied and
// the call is not interactive, so a dead or stalled host cannot hang the
// helper (and the user's git) indefinitely.
const defaultGitTimeout = 120 * time.Second

// allowedGitProtocols is the complete transport set cloak permits its child
// Git processes to use. GIT_ALLOW_PROTOCOL is an absolute whitelist, so it
// also blocks arbitrary git-remote-<scheme> helpers for unknown scheme:// URLs
// as defense in depth behind setup's URL allowlist.
const allowedGitProtocols = "file:git:http:https:ssh"

// defaultTimeout resolves the per-invocation deadline. CLOAK_GIT_TIMEOUT
// overrides it with a Go duration (e.g. "30s", "5m"); "0" or "off" disables
// the deadline. An unparseable value falls back to the default.
func defaultTimeout() time.Duration {
	return parseTimeout(os.Getenv("CLOAK_GIT_TIMEOUT"))
}

// parseTimeout maps a raw CLOAK_GIT_TIMEOUT value to a deadline. The empty
// string (unset) and any unparseable or non-positive duration fall back to the
// default bound; "0" or "off" (case-insensitive, surrounding space trimmed)
// explicitly disable the deadline. The result is therefore never negative, and
// is 0 only for those explicit opt-out tokens, so a stalled host stays bounded
// unless the operator deliberately turns the deadline off. Split out from
// defaultTimeout so the env-free parse is fuzz-reachable.
func parseTimeout(raw string) time.Duration {
	v := strings.TrimSpace(raw)
	switch {
	case v == "":
		return defaultGitTimeout
	case v == "0" || strings.EqualFold(v, "off"):
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return defaultGitTimeout
}

// G runs git commands. The logger is swappable so the helper can upgrade
// from a bootstrap stderr logger to the per-repo file logger once the state
// directory is known.
type G struct {
	log *slog.Logger
}

// New returns a runner logging through lg.
func New(lg *slog.Logger) *G { return &G{log: lg} }

// SetLogger swaps the logger (used after the per-repo log file opens).
func (g *G) SetLogger(lg *slog.Logger) { g.log = lg }

// Opts controls one git invocation.
type Opts struct {
	// Dir is the process working directory ("" = inherit).
	Dir string
	// GitDir sets GIT_DIR explicitly; "" removes it from the environment
	// so the command resolves the repo from Dir.
	GitDir string
	// Env appends extra KEY=VAL pairs.
	Env []string
	// Scrub disables system/global git config; used for object building in
	// the private backend repo so user config cannot interfere. Network
	// operations are NOT scrubbed (user transport config like
	// core.sshCommand must keep working).
	Scrub bool
	// Stdin streams to the command if non-nil.
	Stdin io.Reader
	// Stdout streams from the command if non-nil; otherwise captured.
	Stdout io.Writer
	// Ctx, when non-nil, bounds the invocation; on expiry the process is
	// killed and Run returns a *TimeoutError (or *CanceledError on cancel).
	Ctx context.Context
	// Interactive marks an invocation that may prompt on the tty (credential
	// or passphrase entry); no default timeout is imposed so a human prompt
	// is not killed. Ignored when Ctx is set.
	Interactive bool
	// MaxCapture bounds how many bytes of captured stdout/stderr Run buffers in
	// memory (0 = unlimited, the default). Host-facing transport calls set it so
	// an untrusted host streaming unbounded remote: sideband cannot grow helper
	// memory without limit; local plumbing leaves it 0 since its output is the
	// user's own repo data and may legitimately be large. A caller streaming via
	// Stdout is unaffected (that path is never buffered).
	MaxCapture int64
	// SensitiveArgs prevents command arguments from reaching debug logs or
	// returned errors. The real argv is still passed to git. Use this for
	// credential-bearing values such as a configured remote URL.
	SensitiveArgs bool
	// SensitiveURLs removes credentials, query parameters, and fragments from
	// captured stderr before it can reach a returned error or diagnostic log.
	// Stdout remains raw because many plumbing commands return URLs as data which
	// callers must validate before deciding whether and how to display them.
	// The original values are passed to git unchanged.
	SensitiveURLs []string
}

// GitError is a non-zero git exit with its captured stderr.
type GitError struct {
	Args     []string
	ExitCode int
	Stderr   string
}

func (e *GitError) Error() string {
	s := strings.TrimSpace(e.Stderr)
	if s == "" {
		s = "(no stderr)"
	}
	return fmt.Sprintf("git %s: exit %d: %s", strings.Join(e.Args, " "), e.ExitCode, s)
}

// TimeoutError is returned when a git invocation exceeded its deadline and
// was killed. ClassifyTransport maps it to cloakerr.Network so a stalled host
// is never mistaken for tamper.
type TimeoutError struct {
	Args    []string
	Elapsed time.Duration
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("git %s: timed out after %s", strings.Join(e.Args, " "), e.Elapsed)
}

// CanceledError is returned when a git invocation's context was canceled.
type CanceledError struct{ Args []string }

func (e *CanceledError) Error() string {
	return fmt.Sprintf("git %s: canceled", strings.Join(e.Args, " "))
}

// resolveContext picks the deadline context for one invocation. It returns a
// cancel func that is always safe to defer: a no-op when o.Ctx is supplied or
// no deadline applies, the real WithTimeout cancel otherwise.
func resolveContext(o Opts) (context.Context, context.CancelFunc) {
	if o.Ctx != nil {
		return o.Ctx, func() {}
	}
	if d := defaultTimeout(); d > 0 && !o.Interactive {
		return context.WithTimeout(context.Background(), d)
	}
	return context.Background(), func() {}
}

// buildEnv assembles the child process environment: inherited GIT_DIR and
// GIT_ALLOW_PROTOCOL entries are dropped, then GIT_DIR/scrub/extra pairs and
// cloak's fixed transport whitelist are applied per o.
func buildEnv(o Opts) []string {
	return applyGitEnv(os.Environ(), o)
}

// applyGitEnv builds the child git environment from a parent environment and
// the invocation options. It drops every inherited GIT_DIR= entry (so a stray
// GIT_DIR cannot redirect the subprocess) and every GIT_ALLOW_PROTOCOL= entry
// (so the caller cannot re-enable an external helper), applies the requested
// local options, then installs cloak's fixed transport whitelist last. Pure so
// the isolation contract is fuzz-reachable without touching process state.
func applyGitEnv(parent []string, o Opts) []string {
	env := make([]string, 0, len(parent)+len(o.Env)+5)
	for _, kv := range parent {
		if isRepositoryRedirectEnv(kv) || strings.HasPrefix(kv, "GIT_ALLOW_PROTOCOL=") {
			continue
		}
		env = append(env, kv)
	}
	if o.GitDir != "" {
		env = append(env, "GIT_DIR="+o.GitDir)
	}
	if o.Scrub {
		env = append(env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	}
	for _, kv := range o.Env {
		if isRepositoryRedirectEnv(kv) || strings.HasPrefix(kv, "GIT_ALLOW_PROTOCOL=") {
			continue
		}
		env = append(env, kv)
	}
	return append(env, "GIT_ALLOW_PROTOCOL="+allowedGitProtocols)
}

// isRepositoryRedirectEnv identifies Git environment variables that can point
// a command at object, ref, index, worktree, shallow, graft, or replacement
// state outside the explicit Opts.GitDir. Inheriting any of them would let a
// backend maintenance command (notably prune) mutate the source repository.
func isRepositoryRedirectEnv(kv string) bool {
	key, _, _ := strings.Cut(kv, "=")
	switch key {
	case "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
		"GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_INDEX_FILE", "GIT_INDEX_VERSION",
		"GIT_SHALLOW_FILE", "GIT_REPLACE_REF_BASE", "GIT_GRAFT_FILE", "GIT_NAMESPACE",
		"GIT_PREFIX", "GIT_SUPER_PREFIX", "GIT_INTERNAL_SUPER_PREFIX", "GIT_QUARANTINE_PATH":
		return true
	default:
		return false
	}
}

// classifyExit maps a finished invocation to its typed error (nil on success).
// A deadline/cancel kills the process, so it is surfaced as a *TimeoutError or
// *CanceledError; the classifier then reports network (a stall), never tamper.
func classifyExit(args []string, ctxErr, runErr error, exit int, dur time.Duration, stderr string) error {
	if runErr == nil {
		return nil
	}
	switch ctxErr {
	case context.DeadlineExceeded:
		return &TimeoutError{Args: args, Elapsed: dur}
	case context.Canceled:
		return &CanceledError{Args: args}
	}
	if exit == -1 {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), runErr)
	}
	return &GitError{Args: args, ExitCode: exit, Stderr: stderr}
}

// Run executes git with args. Returns captured stdout (when not streamed)
// and the captured stderr; err is *GitError on non-zero exit.
func (g *G) Run(o Opts, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := resolveContext(o)
	defer cancel()
	// Refuse git's arbitrary-command transports (ext::, fd::) explicitly on
	// every invocation as defense in depth behind both setup's URL validation
	// and the GIT_ALLOW_PROTOCOL whitelist. Harmless for local plumbing.
	gitArgs := append([]string{
		"-c", "protocol.ext.allow=never",
		"-c", "protocol.fd.allow=never",
	}, args...)
	cmd := exec.CommandContext(ctx, "git", gitArgs...) // #nosec G204 -- git remote helper: command is the fixed "git" binary; variable args are inherent, and ext/fd transports are disabled above as defense in depth
	cmd.Dir = o.Dir
	cmd.Env = buildEnv(o)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdin = o.Stdin
	// Bound captured output when o.MaxCapture > 0 so a host streaming unbounded
	// remote: sideband cannot grow helper memory without limit. A caller
	// streaming via o.Stdout is unaffected; o.MaxCapture == 0 keeps the
	// historical unbounded capture for local plumbing.
	var outCap, errCap *cappingWriter
	if o.Stdout != nil {
		cmd.Stdout = o.Stdout
	} else {
		cmd.Stdout, outCap = capture(&outBuf, o.MaxCapture)
	}
	cmd.Stderr, errCap = capture(&errBuf, o.MaxCapture)

	start := time.Now()
	runErr := cmd.Run()
	dur := time.Since(start)

	stdout = outBuf.String()
	stderr = errBuf.String()
	for _, rawURL := range o.SensitiveURLs {
		stderr = urlredact.KnownURL(stderr, rawURL)
	}
	displayArgs := args
	if o.SensitiveArgs {
		if len(args) > 0 {
			displayArgs = []string{args[0], "[redacted arguments]"}
		} else {
			displayArgs = []string{"[redacted arguments]"}
		}
	}
	if g.log != nil && (overflowed(outCap) || overflowed(errCap)) {
		g.log.Warn("git output exceeded capture cap; truncated for classification",
			"args", strings.Join(displayArgs, " "), "cap_bytes", o.MaxCapture,
			"stdout_capped", overflowed(outCap), "stderr_capped", overflowed(errCap))
	}
	exit := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	if g.log != nil {
		g.log.Debug("git", "args", strings.Join(displayArgs, " "), "dir", o.Dir,
			"gitdir", o.GitDir, "exit", exit, "ms", dur.Milliseconds(),
			"stderr_bytes", len(stderr))
	}
	return stdout, stderr, classifyExit(displayArgs, ctx.Err(), runErr, exit, dur, stderr)
}

// Out runs git and returns whitespace-trimmed stdout.
func (g *G) Out(o Opts, args ...string) (string, error) {
	stdout, _, err := g.Run(o, args...)
	return strings.TrimSpace(stdout), err
}

// capture returns the writer to hand the subprocess for one captured stream and
// the cappingWriter wrapping it (nil when uncapped). Output is always collected
// into sink; with limit > 0 it is bounded to limit bytes.
func capture(sink *bytes.Buffer, limit int64) (io.Writer, *cappingWriter) {
	if limit <= 0 {
		return sink, nil
	}
	cw := &cappingWriter{w: sink, limit: limit}
	return cw, cw
}

// overflowed reports whether a (possibly nil) capping writer dropped output.
func overflowed(c *cappingWriter) bool { return c != nil && c.overflow }

// cappingWriter forwards to w until limit bytes have been written, then discards
// the rest and records overflow. It always reports a full write so the git
// subprocess runs to completion (memory stays bounded by the discard) rather
// than dying on a short write. Duplicated from internal/backend's identical
// helper because gitx is the lowest-level package and cannot import backend;
// keep the two in sync.
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
		if wn, err := c.writeChunk(p); err != nil {
			return wn, err
		}
		return len(p), nil
	}
	if room > 0 {
		if wn, err := c.writeChunk(p[:room]); err != nil {
			return wn, err
		}
	}
	c.overflow = true
	return len(p), nil
}

func (c *cappingWriter) writeChunk(b []byte) (int, error) {
	wn, err := c.w.Write(b)
	c.n += int64(wn)
	return wn, err
}
