// Plaintext-route guard. Git runs git-remote-cloak only for cloak:: URLs, or
// for every URL of a remote configured with remote.<name>.vcs=cloak. Any other
// url or pushurl entry on a cloak remote makes Git send the unencrypted
// repository straight to that host while cloak fetches keep succeeding, so a
// session refuses such a remote instead of reporting it healthy.
package setup

import (
	"errors"
	"strings"

	"github.com/b4ryon/git-remote-cloak/internal/cloakerr"
	"github.com/b4ryon/git-remote-cloak/internal/gitx"
	"github.com/b4ryon/git-remote-cloak/internal/urlredact"
)

// checkPlaintextRoutes refuses a configured remote whose effective fetch or
// push URLs (after url.*.insteadOf / pushInsteadOf) include one that Git would
// not route through cloak. An anonymous cloak:: URL is not a configured remote
// and has no other routes to check.
func checkPlaintextRoutes(g *gitx.G, localGitDir, remoteName string) error {
	configured, err := isConfiguredRemote(g, localGitDir, remoteName)
	if err != nil || !configured {
		return err
	}
	vcs, err := remoteUsesCloakVCS(g, localGitDir, remoteName)
	if err != nil {
		return err
	}
	for _, kind := range []string{"fetch", "push"} {
		args := []string{"remote", "get-url", "--all"}
		if kind == "push" {
			args = append(args, "--push")
		}
		out, err := g.Out(gitx.Opts{GitDir: localGitDir, SensitiveArgs: true, SensitiveURLs: []string{remoteName}},
			append(args, "--", remoteName)...)
		if err != nil {
			return cloakerr.New(cloakerr.LocalGit, "resolve remote "+kind+" URLs", err)
		}
		for _, u := range strings.Split(out, "\n") {
			if u != "" && !routesThroughCloak(u, vcs) {
				return cloakerr.Newfh(cloakerr.LocalGit, "check plaintext routes",
					"every url and pushurl of a cloak remote must start with cloak:: (inspect them with `git remote -v`), or run `git config remote."+remoteName+".vcs cloak` to route all of them through cloak; if anything was already pushed to that URL, treat it as exposed",
					"remote %q has %s URL %q that does not go through cloak; Git would send the unencrypted repository there",
					urlredact.URL(remoteName), kind, urlredact.URL(u))
			}
		}
	}
	return nil
}

// routesThroughCloak reports whether Git hands url to git-remote-cloak: an
// explicit cloak:: prefix always does; on a vcs=cloak remote any URL does
// unless it names a different helper with its own <helper>:: prefix.
func routesThroughCloak(url string, vcsCloak bool) bool {
	if strings.HasPrefix(url, "cloak::") {
		return true
	}
	return vcsCloak && !urlredact.IsHelperTransport(url)
}

// isConfiguredRemote reports whether remoteName is one of the repository's
// configured remotes (as opposed to a URL git passed for an anonymous remote).
func isConfiguredRemote(g *gitx.G, localGitDir, remoteName string) (bool, error) {
	out, err := g.Out(gitx.Opts{GitDir: localGitDir}, "remote")
	if err != nil {
		return false, cloakerr.New(cloakerr.LocalGit, "list remotes", err)
	}
	for _, name := range strings.Split(out, "\n") {
		if name == remoteName {
			return true, nil
		}
	}
	return false, nil
}

// remoteUsesCloakVCS reports whether remote.<name>.vcs is "cloak". An unset
// key (git config exit 1) is false; any other config failure is surfaced.
func remoteUsesCloakVCS(g *gitx.G, localGitDir, remoteName string) (bool, error) {
	val, err := g.Out(gitx.Opts{GitDir: localGitDir}, "config", "--get", "remote."+remoteName+".vcs")
	if err != nil {
		var ge *gitx.GitError
		if errors.As(err, &ge) && ge.ExitCode == 1 {
			return false, nil
		}
		return false, cloakerr.New(cloakerr.LocalGit, "read remote vcs setting", err)
	}
	return val == "cloak", nil
}
