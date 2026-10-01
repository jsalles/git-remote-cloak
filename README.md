# git-remote-cloak

[![CI](https://github.com/b4ryon/git-remote-cloak/actions/workflows/ci.yml/badge.svg)](https://github.com/b4ryon/git-remote-cloak/actions/workflows/ci.yml)

A git remote helper that stores an end-to-end encrypted mirror of a git
repository on any ordinary git host. The host sees only opaque
AEAD-encrypted blobs: no file contents, no filenames, no commit messages,
no source branch names, and no source history graph. It still sees the fixed
carrier layout and its update cadence. Local repositories stay plain git.

![git-remote-cloak illustration](illustration.png)

## Good fit

cloak suits small, sensitive, mostly-text repositories shared across a few
trusted machines that hold the key:

- Encrypted notes / knowledge bases (Obsidian vaults, markdown zettelkasten,
  research notebooks) synced across your machines.
- Versioned secrets and config, solo or small team (certs, `.env`,
  ansible-vault material, password-store data, dotfiles-with-secrets).
- Code you would rather not donate to someone else's model training.
- Private journaling and high-sensitivity writing (medical, legal,
  source-protection drafts).
- Confidential small-document collaboration through a host you would rather
  not trust with plaintext.
- Off-site encrypted backup of small sensitive datasets.
- A tamper- and rollback-evident mirror on an untrusted host, within each
  client's locally pinned history (see the split-view limitation below).

## Not a good fit

- Source you want host-side features on (CI, pull requests, blame, code
  search), the host sees only ciphertext; use a normal private repo.
- Large or binary-heavy repos, they work, but inefficiently (whole-pack
  ciphertext, no source-object-level host dedup or partial clone, no git-LFS).
  Host file-size limits apply to the encrypted packs: GitHub, for example,
  rejects any pushed file over 100 MB and caps a single push at ~2 GB. cloak
  splits pushes and full repacks into multiple encrypted packs below the
  configured per-file limit; a single object that cannot fit is refused before
  upload with its path named (`cloak.maxPackBytes`, default 100 MiB).

> [!WARNING]
> Do not add Git LFS to a cloak-backed repository. LFS objects use a separate
> transport and are not protected by cloak's encrypted remote. cloak refuses
> tracked `filter=lfs` attributes and standard Git LFS pre-push hooks before
> sync; it cannot intercept a separately invoked `git lfs push` command.
- Many users needing differentiated access, one shared key, no per-user ACLs.
- Shallow repositories, grafts, or `git replace` overlays. cloak rejects them
  because incomplete/rewritten traversal would weaken closure verification.
- Hiding traffic rather than content, repo existence, owner, push timing, and
  pack sizes/counts still leak.
- Cases where you already trust the host, a plain private repo is simpler.

## Replacement for git-remote-gcrypt

A ground-up replacement for `git-remote-gcrypt` that fixes its known design
problems:

- Concurrent pushes use an exact expected-head `--force-with-lease`
  compare-and-swap, including normal fast-forward updates and initial branch
  creation. Destructive inner-ref retries retain their original advertised
  destination state rather than silently clobbering a winner.
- No GPG: encryption uses the age v1 format with a single shared symmetric
  key (ChaCha20-Poly1305), stored in the macOS Keychain or a key file.
- Host rollback/replay below one client's last locally pinned state is detected
  and refused (monotonic generation plus same-generation ciphertext checks),
  not silently accepted. This is not a cross-client transparency guarantee.
- Substituting another repository's encrypted state under the same key is
  refused after that identity has been pinned, not merely warned about: a
  random repository identity is bound inside the AEAD manifest and pinned
  (trust-on-first-use); a mismatch is a hard error needing an explicit
  override.
- Pack consolidation is geometric, with no periodic full-history re-upload.
- Errors are reported as what they are (auth vs network vs missing repo vs
  tamper vs rollback).

## Usage

### Install

Prerequisites: git and Go 1.26.6 or newer. The module's `go` directive enforces
that security patch level; a compatible older launcher with automatic
toolchain selection may download it. Install 1.26.6 directly for offline builds. On macOS, install
the Xcode command line tools (`xcode-select --install`) for the cgo
Keychain/Touch ID key backend; Linux builds are pure Go and use a key file.
Library versions are locked by `go.mod`/`go.sum`: currently `filippo.io/age`
v1.3.2, `golang.org/x/crypto` v0.57.0, `golang.org/x/term` v0.46.0, and
`golang.org/x/text` v0.42.0 are direct dependencies. No separate `age`
executable is used.

```
git clone https://github.com/b4ryon/git-remote-cloak.git
cd git-remote-cloak
make install                   # builds + installs git-remote-cloak and the
                               # git-cloak symlink into ~/bin (override PREFIX=).
                               # Version identifies the exact tag/commit/dirty tree.
```

Both names must be on your PATH: git runs `git-remote-cloak` for `cloak::` URLs,
and `git cloak ...` resolves to the `git-cloak` symlink. Add the PATH line to
your shell profile so new shells inherit it. Apps launched from the macOS
Finder do not normally read shell startup files; see the Obsidian note below.

```
export PATH="$HOME/bin:$PATH"  # put this in ~/.zshrc / ~/.bashrc, then open a NEW shell
git cloak version              # verify the CLI: prints e.g. "git-cloak v0.2.9"
command -v git-remote-cloak    # verify git can find the helper for cloak:: URLs
                               # (must print a path; if empty, the PATH is wrong)
```

The `command -v` check matters because git resolves the helper itself: if
`git-remote-cloak` is not on PATH, `git cloak version` can still pass while a
later `git clone cloak::...` fails with "helper not found". The full end-to-end
check is a `cloak::` clone (or `git ls-remote cloak::<your-host>`) once you have
a key and a host repo configured.

Alternative: `go install github.com/b4ryon/git-remote-cloak/cmd/git-remote-cloak@v0.2.9`,
then `ln -sf git-remote-cloak "$(go env GOPATH)/bin/git-cloak"`.

### First repository

```
# first machine
git cloak keygen                     # generate the shared master key
git cloak key export                 # back it up to two safe places (see note)

# optional: make the current folder a git repo (skip if it already is one)
git init -b main                     # git < 2.28: git init && git branch -M main
git add -A && git commit -m "initial commit"

# optional: create the EMPTY, private repo on the host first
gh repo create you/private-repo --private   # no README/license; or create it in the web UI

git remote add origin cloak::git@github.com:you/private-repo.git
git push -u origin main

# second machine
git cloak key import                 # paste the exported key
git clone cloak::git@github.com:you/private-repo.git
```

The carrier branch (named `cloak` by default) must permit force updates. Full
repack, rekey, and automatic consolidation replace its commit chain with an exact
`--force-with-lease`; a GitHub ruleset that forbids force pushes will block
those operations. Do not add required CI checks to this ciphertext-only branch.

If this repository uses a non-default, per-repository key reference, the new
clone must receive that setting before its first fetch:

```
git cloak key import --key keychain:private-repo
git clone --config cloak.keyRef=keychain:private-repo \
  cloak::git@github.com:you/private-repo.git
```

Use an appropriate fresh `file:<absolute-path>` reference instead on systems
without Keychain support. A bare `key import` targets the platform default and
will refuse to overwrite an old key already stored there.

Prefer SSH carrier URLs as shown above. If you use HTTPS, let Git's credential
helper supply authentication. cloak refuses HTTP(S) userinfo and transport URLs
containing passwords, queries, or fragments, because a safe diagnostic could
not also reproduce those URLs for recovery. SSH usernames remain supported.
Backend URLs are limited to local paths, scp-like SSH locations, and Git's
built-in `file`, `git`, `http`, `https`, `ssh`, and `git+ssh` schemes; arbitrary
`git-remote-<scheme>` helpers are not executed.
Diagnostics additionally redact credential-shaped URLs as defense in depth.
The host and repository path remain visible, so choose a non-sensitive carrier
name. Redaction is not secret storage.

The key lives only on your machines (the host holds only ciphertext), so losing
every copy makes the data unrecoverable: back the key up before pushing real
data, and keep the repository private. cloak hides contents, filenames, and
history structure, but not the repo's existence, owner, or push metadata (pack
sizes, count, and timing).

The ciphertext uses an age v1 container with cloak's custom `cloak/v1`
recipient stanza. Stock `age` cannot decrypt it. Recovery therefore requires
the key **and** a compatible `git-remote-cloak` build; archive a pinned source
revision or verified binary with your recovery material.

Every fetch and push URL configured on the source repository must invoke the
`cloak::` transport. A plain SSH/HTTPS URL bypasses this helper and sends the
ordinary Git repository. cloak refuses to fetch, push, or report `status` for a
remote whose effective `url`/`pushurl` list (after `insteadOf` rewriting)
contains any non-`cloak::` entry, so a pull-then-push sync stops before the
plain push. `git config remote.origin.vcs cloak` routes every URL of that remote
through cloak and is accepted. cloak cannot see pushes that never invoke it
(another remote, an explicit plain URL, or a plain URL listed first), so still
inspect `git remote -v` after setup or configuration changes.

Use a new, empty host repository. The first push refuses a host repository that
already has branches or tags cloak did not write, because their history stays
unencrypted on the host; `git cloak status` lists any such refs.

### Everyday use

There is no separate sync command: once the `cloak::` remote is configured, use
git as usual. `git push`, `git pull`, `git fetch`, and `git clone` transparently
encrypt outbound and decrypt inbound. (Scheduled/background auto-sync is not part
of the tool.)

If Git discovers that every advertised ref is already present locally, it may
send only a `list` request and no fetch batch. cloak verifies the complete local
object closure in that path and repairs an absent pin pair or a stale generation
pin. It does not advance a pin when the closure is incomplete, and inconsistent
or mismatched pin state still fails closed. This makes an interruption after
pack application self-healing without turning list-only operations into an
integrity bypass.

### Replicating to a second host (multiple push URLs)

A remote can push to more than one host, so every `git push` also updates an
independent encrypted mirror (replication, not failover: fetches only ever use
the remote's fetch URL):

```
git config --add remote.origin.pushurl cloak::git@github.com:you/notes-private.git
git config --add remote.origin.pushurl cloak::git@backup-host:you/notes-mirror.git
```

(The first `--add` repeats the fetch URL: once any pushurl is set, git no
longer pushes to the fetch URL.) Every entry must retain its `cloak::` prefix.
Each push URL is its own cloak backend with
its own local state (mirror, rollback pin, repo identity) under `.git/cloak/`,
so integrity alarms and recovery are per URL. `git cloak` commands operate on
the fetch URL by default; select another backend with `--url`:

```
git cloak status --remote origin --url cloak::git@backup-host:you/notes-mirror.git
```

`status`, `repack`, `rekey`, `accept-rollback`, and `accept-repo-change` all
take `--url`. When rekeying a multi-URL remote, rekey every backend with the
same `--new-key`; each rekey repoints `cloak.keyRef` at the new key, so reset
it to the old ref before rekeying the next still-old backend.

### Obsidian vault sync (example)

A vault is just a folder of files, so there is nothing Obsidian-specific to
install on cloak's side. After the key and remote setup above, in your vault:

```
cd /path/to/YourVault
git init -b main  # git < 2.28: git init && git branch -M main
printf '\n/.obsidian\n/.obsidian.backup\n/.trash\n.DS_Store\n' >> .gitignore
git remote add origin cloak::git@github.com:you/notes-private.git
git add -A && git commit -m "initial vault" && git push -u origin main
```

The command appends rather than overwrites; review and deduplicate an existing
`.gitignore` as needed. In particular, `/.obsidian` intentionally has no trailing
slash: that form excludes both a real directory and an `.obsidian` symlink;
`/.obsidian/` does not ignore the symlink itself. Confirm none of these paths is
already tracked before the first encrypted push. Do not add Git LFS for images
or other attachments: its separate object transport bypasses cloak. cloak also
refuses standard Git LFS pre-push hooks.

For automatic commit-and-sync, use the [Obsidian Git](https://github.com/Vinzent03/obsidian-git)
community plugin: on desktop it shells out to your system git, so cloak runs
transparently. Ensure `git-remote-cloak` is on the PATH of the Obsidian process,
not merely an interactive shell. On each desktop, add the absolute directory
containing both cloak binaries (for example `/Users/you/bin`) under Obsidian
Git's **Additional PATH environment variable paths** setting, one directory per
line, then use **Reload with new environment variables**.
Alternatively install them in a directory already on Obsidian's PATH. Perform
one supervised plugin sync to verify helper discovery before enabling background
sync. Mobile Obsidian is unsupported: its Git plugin uses a pure-JavaScript git
(isomorphic-git) that cannot run remote helpers.

macOS code-signing note: the Keychain key backend binds its access control to
the helper's code signature. The build default is an ad-hoc signature, which
changes on every rebuild and invalidates that access, so each rebuild triggers
a fresh Touch ID / password prompt on the next sync. To avoid recurring prompts,
build with a stable self-signed code-signing certificate
(`make install CLOAK_SIGN_ID=<cert-name>`). The file key backend
(`cloak.keyRef=file:...`) is unaffected.

### Operator commands (`git cloak`)

- `status`, remote generation, repo id, packs, applied state.
- `repack` / `rekey`, rewrite reachable objects into a size-bounded pack set /
  re-encrypt that set under a new key. Either command may produce multiple
  encrypted packs.
- `accept-rollback` / `accept-repo-change`, one-shot overrides for a detected
  generation regression or repository-identity change (user-presence gated).
- `key export [--force-insecure]` / `key import` / `key delete`, key transfer,
  backup, and removal (delete requires a typed YES confirmation).

Remote-facing commands take `--remote <name>` (default `origin`) and, on a
remote with multiple push URLs, `--url <cloak::url>` to pick which backend to
operate on (default: the fetch URL).

`rekey`, `key delete`, `accept-rollback`, and `accept-repo-change` require an
interactive user-presence check. A headless invocation is refused unless it
explicitly passes `--force-insecure`; that flag records the caller's decision
to bypass the prompt and must not be added casually to general-purpose
automation. `key delete` still requires the separate typed `YES` confirmation.
If a rekey's transport and confirmation probe both fail, its error treats the
outcome as unknown and tells you how to test the new key without discarding the
old one.

For a key rotation, create and export a fresh reference before rekeying. On each
other machine, import the new key into a fresh local reference, then point that
repository at it:

```
git cloak key import --key keychain:private-repo-next
git config cloak.keyRef keychain:private-repo-next
```

Use a suitable `file:<absolute-path>` reference where Keychain is unavailable.
Bare `git cloak key import` cannot overwrite the old default key.

### Configuration

git config (`cloak.*`):

- `keyRef`, where the master key lives. The default differs by OS:
  `keychain:default` (macOS Keychain) and `file:~/.config/cloak/keys/default`
  (Linux/other). Each machine uses its own platform default, so a Mac+Linux pair
  works without touching this. Set `cloak.keyRef` explicitly only if you store
  the key elsewhere, and use the right form for that machine's platform
  (`keychain:<name>` or `file:<path>`).
- `geometricFactor`, pack-consolidation aggressiveness (default 2; `0` disables).
- `pushRetries`, compare-and-swap retry budget under concurrent pushes (default 5).
- `branch`, the backend branch name on the host (default `cloak`).
- `allowHostRefs`, create the carrier on a host repository that already holds
  other refs (default `false`). Those refs keep their plaintext history.
- `maxPackBytes`, the largest encrypted pack (one host file) cloak will publish.
  Pushes, repacks, and rekeys that exceed it in aggregate are split into several
  self-contained packs. A single object that still exceeds it is refused
  *before upload*, naming the file so you know what to shrink and leaving no
  partial upload. Do not use Git LFS; it bypasses cloak's encrypted transport.
  Default `104857600` (100 MiB, GitHub's per-file hard cap); set `0` to disable
  (a self-hosted host with no limit), or raise it for a host with a higher cap.
  A consolidation that would cross the limit is skipped rather than failing the
  push. If the limit is left unset/too high and the host rejects the push, cloak
  still reports it clearly as a "pack too large for host" error.
  The same value bounds cloak's receive-side scratch copy, decryption, and
  application. Git's promisor fetch necessarily transfers and stores a requested
  outer blob in the private backend mirror before cloak can inspect its size;
  a carrier that ignores partial-clone filters may transfer all blobs eagerly.
  The carrier therefore retains a network/backend-cache denial-of-service path.

Environment: `CLOAK_GIT_TIMEOUT` (git subprocess timeout, default 120s; `0`/`off`
disables), `CLOAK_LOG` (per-repo debug log level).

### Trust model and accepted risks

cloak hides repository contents, filenames, and history structure from the host;
a few properties are accepted trade-offs rather than protected:

- **Metadata leaks.** The host still sees the repo's existence, owner, total
  size, pack count, and push timing. The backend branch is named `cloak` by
  default, which fingerprints the repo as a cloak target; rename it with
  `git config cloak.branch <name>` if you would rather not advertise the tool.
- **First contact is trust-on-first-use.** On a fresh clone (or after the local
  `.git/cloak/<remote>/` state is deleted) there is no pin yet, so the first
  manifest that decrypts under your key is trusted. A host that tampered with the
  *initial* state could serve any state that validates under the shared key. To
  mitigate this, compare `git cloak status` (repo id, generation, and manifest
  hash) against the other machine before trusting a brand-new clone.
- **Pins do not prevent a Byzantine split view.** Pins are local and there is
  no transparency log, cross-device gossip, or authenticated single-history
  proof. A malicious host that possesses multiple valid ciphertext histories
  can keep different clients on different monotonically advancing forks, or
  later move a client to a higher-generation fork, without triggering the
  lower-generation/same-generation checks. Compare status out of band and keep
  an independent backup if this attacker is in scope.
- **Rekey is not retroactive erasure.** It replaces the current carrier state
  with ciphertext under the new key, but a host, backup, reflog, or attacker may
  retain older ciphertext. A compromised old key can still decrypt everything
  encrypted under it; rekey protects future writes only. Treat old content as
  exposed and rotate any rotatable secrets that appeared in history. Moving
  future writes to a fresh carrier can reduce further exposure, but cannot
  erase ciphertext someone already copied.
- **Endpoints hold plaintext.** The working repository, Git object database,
  editor, backups, and the running helper are trusted. cloak does not protect
  against malware, administrators, or monitoring on an unlocked client.
- **Local scratch and cache capacity are endpoint concerns.** cloak bounds the
  ciphertext it copies into decrypt/apply scratch, and bounds the initial
  encrypted pack build. Git can still cache a carrier blob before that check,
  and an unsplittable local object can make Git materialize an over-limit
  plaintext split pack before cloak refuses it. Stale cloak scratch is cleaned
  under the per-remote lock on the next session.
- **A sync mirror is not the only backup.** Remote deletion, account loss,
  local key loss, or a software defect can still make the mirror unavailable.
  Keep an independently encrypted, restore-tested backup of repository data,
  key material, and a compatible cloak binary or pinned source revision.
- **Sensitive overrides can be scripted deliberately.** `key export`, `key
  delete`, `rekey`, `accept-rollback`, and `accept-repo-change` are
  user-presence gated, but
  `--force-insecure` deliberately permits non-interactive use. Any process
  running as you can request that bypass; treat it as an exceptional operator
  action, not a routine sync option.

## Build and test

```
make build              # bin/git-remote-cloak + git-cloak symlink
make test               # unit tests
make test-integration   # hermetic integration + security suites (real git)
make test-race          # race detector across in-process + integration suites
make test-darwin        # Keychain backend tests
make vuln               # govulncheck (needs network to the Go vuln database)
make test-e2e           # live tests against a scratch GitHub repo (CLOAK_E2E=1)
make check              # vet + lint + vuln + test + test-integration + test-darwin
```

## Acknowledgments

cloak builds on:

- [age](https://age-encryption.org) (`filippo.io/age` v1.3.2) by Filippo Valsorda and
  contributors, the encryption format and the stanza/STREAM primitives.
- [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto),
  [`golang.org/x/term`](https://pkg.go.dev/golang.org/x/term), and
  [`golang.org/x/text`](https://pkg.go.dev/golang.org/x/text) by the Go Authors,
  ChaCha20-Poly1305 and HKDF for the cloak/v1 stanza, terminal detection for the
  user-presence gate, and Unicode handling in the tests.
- [git](https://git-scm.com), cloak is a remote helper; git does all local
  object storage and transport.

Inspired by: [git-remote-gcrypt](https://github.com/spwhitton/git-remote-gcrypt),
whose design this project set out to improve on.

## License

MIT, see LICENSE.
