// Package urlredact renders backend URLs without authentication material.
// It is deliberately presentation-only: callers retain the original URL for
// transport and state identity, and use these helpers only at output borders.
package urlredact

import (
	"regexp"
	"strings"
)

const cloakPrefix = "cloak::"

var (
	standardURLRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9+.-]*://[^\s'"<>]+`)
	scpURLRe      = regexp.MustCompile(`[^\s'"<>/@]+@[^\s'"<>]+:[^\s'"<>]*`)
	helperURLRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+.-]*::`)
)

// IsHelperTransport reports whether raw starts with Git's external remote
// helper syntax. cloak must never pass such a URL to its inner Git transport,
// where helpers such as ext:: can execute commands.
func IsHelperTransport(raw string) bool { return helperURLRe.MatchString(raw) }

// IsSupportedTransport reports whether raw names one of cloak's explicitly
// supported built-in Git transports, an scp-like SSH location, or a local
// path. Git treats an unknown <scheme>:// URL as a request to execute the
// external git-remote-<scheme> helper, so accepting arbitrary URL schemes
// would bypass the narrower <scheme>:: helper check above.
func IsSupportedTransport(raw string) bool {
	if IsHelperTransport(raw) {
		return false
	}
	i := strings.Index(raw, "://")
	if i <= 0 || strings.ContainsAny(raw[:i], `/\`) {
		return true // local path or scp-like SSH syntax
	}
	switch strings.ToLower(raw[:i]) {
	case "file", "git", "http", "https", "ssh", "git+ssh":
		return true
	default:
		return false
	}
}

// ShellArg quotes one value for copy/paste into a POSIX shell command. Values
// containing only common remote/path characters stay readable; everything
// else uses single quotes with embedded quotes escaped safely.
func ShellArg(s string) string {
	if s != "" {
		safe := true
		for i := 0; i < len(s); i++ {
			c := s[i]
			if !asciiLetter(c) && (c < '0' || c > '9') && !strings.ContainsRune("_./:@+-", rune(c)) {
				safe = false
				break
			}
		}
		if safe {
			return s
		}
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// URL removes credential-bearing userinfo plus query/fragment data while
// retaining transport, host, and path for useful diagnostics. Username-only
// SSH and scp-like locations remain executable; HTTP(S) userinfo and embedded
// passwords are removed. Non-URL local paths and remote names are unchanged.
func URL(raw string) string {
	prefix, rest := splitHelperPrefixes(raw)
	if i := strings.Index(rest, "://"); i > 0 && !strings.ContainsAny(rest[:i], `/\`) {
		scheme := strings.ToLower(rest[:i])
		start := i + len("://")
		end := len(rest)
		if n := strings.IndexAny(rest[start:], "/?#"); n >= 0 {
			end = start + n
		}
		authority := rest[start:end]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			userinfo := authority[:at]
			if (scheme != "ssh" && scheme != "git+ssh") || strings.ContainsRune(userinfo, ':') {
				authority = authority[at+1:]
			}
		}
		tail := rest[end:]
		if n := strings.IndexAny(tail, "?#"); n >= 0 {
			tail = tail[:n]
		}
		return prefix + rest[:start] + authority + tail
	}

	base := rest
	if n := strings.IndexAny(base, "?#"); n >= 0 {
		base = base[:n]
	}
	at := strings.LastIndexByte(base, '@')
	hostPath := base
	if at > 0 && !strings.ContainsRune(base[:at], '/') {
		hostPath = base[at+1:]
	}
	if isSCPHostPath(hostPath) {
		if at > 0 && strings.ContainsRune(base[:at], ':') {
			return prefix + hostPath
		}
		return prefix + base
	}
	return raw
}

// CredentialRisk reports whether a transport URL embeds authentication
// material which cannot be represented safely in executable diagnostics.
// HTTP(S) userinfo, passwords, and query/fragment credentials are refused;
// SSH usernames are routing information and remain supported.
func CredentialRisk(raw string) string {
	_, rest := splitHelperPrefixes(raw)
	i := strings.Index(rest, "://")
	if i <= 0 || strings.ContainsAny(rest[:i], `/\`) {
		// scp-like SSH permits a username but never user:password syntax.
		base := rest
		hasSuffix := false
		if n := strings.IndexAny(base, "?#"); n >= 0 {
			base = base[:n]
			hasSuffix = true
		}
		at := strings.LastIndexByte(base, '@')
		hostPath := base
		if at > 0 && !strings.ContainsRune(base[:at], '/') {
			hostPath = base[at+1:]
		}
		if isSCPHostPath(hostPath) {
			if at > 0 && strings.ContainsRune(base[:at], ':') {
				return "embedded password in scp-like URL"
			}
			if hasSuffix {
				return "URL query or fragment"
			}
		}
		return ""
	}
	scheme := strings.ToLower(rest[:i])
	start := i + len("://")
	end := len(rest)
	if n := strings.IndexAny(rest[start:], "/?#"); n >= 0 {
		end = start + n
	}
	authority := rest[start:end]
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo := authority[:at]
		if strings.ContainsRune(userinfo, ':') {
			return "embedded password in URL"
		}
		if scheme != "ssh" && scheme != "git+ssh" {
			return "embedded HTTP(S) or transport username/token"
		}
	}
	if strings.ContainsAny(rest[end:], "?#") {
		return "URL query or fragment"
	}
	return ""
}

// Text redacts every standard or scp-like URL found in diagnostic text.
func Text(s string) string {
	s = standardURLRe.ReplaceAllStringFunc(s, URL)
	return scpURLRe.ReplaceAllStringFunc(s, URL)
}

// KnownURL redacts rawURL from diagnostic text, then scans for normalized URL
// spellings a transport may have emitted (for example after dropping a
// password). The exact replacement runs first so query/fragment secrets are
// removed even from unusual but accepted URL spellings.
func KnownURL(s, rawURL string) string {
	if rawURL != "" {
		s = strings.ReplaceAll(s, rawURL, URL(rawURL))
		if bare := strings.TrimPrefix(rawURL, cloakPrefix); bare != rawURL {
			s = strings.ReplaceAll(s, bare, URL(bare))
		}
	}
	return Text(s)
}

// splitHelperPrefixes preserves git remote-helper prefixes while exposing the
// underlying transport to the redactor. Repeating the loop also makes rejected
// nested helper URLs safe to render.
func splitHelperPrefixes(raw string) (prefix, rest string) {
	rest = raw
	for {
		i := strings.Index(rest, "::")
		if i <= 0 || !validTransportToken(rest[:i]) {
			return prefix, rest
		}
		prefix += rest[:i+2]
		rest = rest[i+2:]
	}
}

func validTransportToken(s string) bool {
	if s == "" || !asciiLetter(s[0]) && (s[0] < '0' || s[0] > '9') {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !asciiLetter(c) && (c < '0' || c > '9') && c != '+' && c != '.' && c != '-' {
			return false
		}
	}
	return true
}

func asciiLetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isSCPHostPath(s string) bool {
	if s == "" {
		return false
	}
	if s[0] == '[' {
		close := strings.IndexByte(s, ']')
		return close > 1 && close+1 < len(s) && s[close+1] == ':'
	}
	colon := strings.IndexByte(s, ':')
	return colon > 0 && !strings.ContainsRune(s[:colon], '/')
}
