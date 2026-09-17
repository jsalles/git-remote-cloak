# git-remote-cloak HOWTO

End-to-end encrypted git remotes on any git host. The host stores only
opaque blobs; your local repo stays plain git. Everything below assumes
macOS with the binaries on PATH.

## Install

```
make install        # builds and installs git-remote-cloak + git-cloak into ~/bin
git cloak version
```

Requirements: git and Go 1.26.6 or newer. The module's `go` directive enforces
that patch level; a compatible older launcher with automatic selection may download it.
Install 1.26.6 directly for an offline build. Direct Go
dependencies are pinned by `go.mod`/`go.sum` (`filippo.io/age` v1.3.2,
`golang.org/x/crypto` v0.57.0, `golang.org/x/term` v0.46.0, and
`golang.org/x/text` v0.42.0); no separate `age` binary is required. On macOS
the master key lives in the login Keychain; on Linux in a 0600 key file.

For Obsidian launched from the Finder, add the absolute directory containing
both cloak binaries (for example `/Users/you/bin`) to Obsidian Git's
**Additional PATH environment variable paths** setting, then select **Reload
with new environment variables**. A shell-profile PATH alone is not inherited.

## One-time setup, first machine

0. Generate the master key (Touch ID prompt when run from a terminal):

```
git cloak keygen
```

1. Back it up NOW to two independent places (password manager + sealed
   offline copy). Recovery requires the remote ciphertext, this key, and a
   compatible cloak binary or pinned source revision. A new machine also has
   no prior rollback/repo-id pins; verify its status out of band as described
   below:

```
git cloak key export
```

   A single master key can serve multiple cloak remotes: each remote mints a
   random repository identity at first push, bound inside the AEAD manifest and
   pinned locally (trust-on-first-use), so a host that later serves a different
   repository's state under the same key is refused as a hard error (override
   deliberately with `git cloak accept-repo-change`). A separate key per remote
   is still the safer isolation boundary if one key is exposed.

2. Create an empty private repo on your host (no README), then point your
   repo at it with the cloak:: scheme and push:

```
git remote add origin cloak::git@github.com:YOU/REPO.git
git push -u origin main
```

Prefer an SSH URL. For HTTPS, use Git's credential helper. cloak refuses
HTTP(S) userinfo and transport URLs containing passwords, queries, or fragments;
SSH usernames remain supported. Diagnostics also redact credential-shaped URLs
as defense in depth. Only local paths, scp-like SSH locations, and the built-in
`file`, `git`, `http`, `https`, `ssh`, and `git+ssh` URL schemes are accepted;
arbitrary external Git transport helpers are refused. Host and repository path
remain visible, so choose a non-sensitive carrier name.

Every fetch or push URL configured on the source repository must invoke
`cloak::`; a plain SSH/HTTPS URL bypasses the helper and sends the ordinary Git
repository. Check `git remote -v` after setup or configuration changes. The
carrier branch (default `cloak`) must permit force updates: repack, rekey, and
automatic consolidation use an exact `--force-with-lease`, so a GitHub ruleset
that forbids force pushes will block them.

3. Verify on the host web UI: you must see ONLY `manifest.age` and
   `packs/<hex>.age`, commits authored "cloak". If you can read a filename,
   stop and investigate.

## One-time setup, second machine

0. Import the key (paste the export line):

```
git cloak key import
```

1. Clone through the helper:

```
git clone cloak::git@github.com:YOU/REPO.git
```

For a non-default per-repository key reference, set it before clone's initial
fetch (this example uses macOS Keychain):

```
git cloak key import --key keychain:notes
git clone --config cloak.keyRef=keychain:notes \
  cloak::git@github.com:YOU/REPO.git
```

Use a fresh `file:<absolute-path>` reference instead where Keychain is
unavailable. A bare import will not overwrite an old key at the default ref.

## Obsidian vault exclusions

Install these exact ignore rules before the first commit:

```gitignore
/.obsidian
/.obsidian.backup
/.trash
.DS_Store
```

`/.obsidian` deliberately has no trailing slash, so it ignores `.obsidian`
whether it is a directory or a symlink. A `/.obsidian/` rule does not ignore the
symlink itself. If any of these paths was already committed, merely adding the
ignore rule does not remove it from Git's index; fix that before the first cloak
push.

Do not use Git LFS in this repository. LFS uploads objects through a separate
transport that cloak does not encrypt. cloak refuses tracked `filter=lfs`
attributes and standard Git LFS pre-push hooks before sync; it cannot intercept
a separately invoked `git lfs push`. Keep attachments within
`cloak.maxPackBytes`, exclude them, or back them up through a separate encrypted
system.

## Daily workflow

Plain git. Nothing else to learn:

```
git pull origin main
git add -A && git commit -m "..."
git push origin main
```

- Branches and tags work like a normal remote.
- Concurrent pushes from both machines are safe: the loser of the race
  retries automatically when the carrier honors Git's atomic ref-update
  semantics; a genuinely diverged branch is rejected as a normal
  non-fast-forward (pull --rebase, push again).
- Pack housekeeping (geometric consolidation) happens automatically during
  push; no scheduled maintenance is required.
- Shallow repositories, grafts, and `git replace` overlays are rejected because
  they would make complete-history verification ambiguous.
- An up-to-date fetch may consist only of Git's ref-list exchange. If the full
  advertised object closure is already local, cloak repairs an absent pin pair
  or a stale local generation pin during that exchange; incomplete closures and
  inconsistent/mismatched pins still fail closed.

## Inspect and maintain

```
git cloak status                 # generation, refs, packs, applied state
git cloak repack                 # rewrite reachable objects into bounded pack(s)
git cloak rekey --new-key <ref>  # re-encrypt everything under a new key
```

Before `rekey`, generate and export a key at a fresh reference. Afterwards,
other machines must import it into a fresh local reference and update
`cloak.keyRef`; bare import will not overwrite their old default key:

```
git cloak key import --key keychain:notes-next
git config cloak.keyRef keychain:notes-next
```

Use a suitable `file:<absolute-path>` reference where Keychain is unavailable.
The old key no longer decrypts the new current state.
Repack and rekey may each produce multiple encrypted packs to stay below
`cloak.maxPackBytes`.

Rekey is not retroactive erasure. A host, reflog, backup, or attacker may retain
old ciphertext, and the old key can still decrypt data previously encrypted
under it. Rekey protects future writes only. If the old key was compromised,
treat old content as exposed and rotate any rotatable secrets that appeared in
history. A fresh carrier can reduce further exposure but cannot erase copies
already retained elsewhere.

Interactive rekey performs the platform user-presence check. Scripts must make
the bypass explicit:

```
git cloak rekey --new-key <ref> --force-insecure
```

If rekey reports that the push outcome is unknown, keep both keys and do not
retry blindly. The error prints commands for testing the new key after
connectivity returns and for restoring the old `cloak.keyRef` if the carrier did
not accept the update.

## Alarms (do not retry blindly)

- `cloak: TAMPER ALARM ...` - ciphertext failed verification or the wrong
  key is configured. The failing ciphertext is not applied and trust anchors
  are not advanced (earlier valid packs in a multi-pack operation may already
  have been indexed). Check `cloak.keyRef` first; if the key is right, treat
  the remote as tampered.
- `cloak: ROLLBACK ALARM ...` - the host served an older state than this
  machine has already seen. If expected (you restored the host from a
  backup), accept once:

```
git cloak accept-rollback
```

For a deliberate headless recovery, add `--force-insecure`; without it,
`key delete`, `rekey`, `accept-rollback`, and `accept-repo-change` refuse
non-interactive execution. Do not put these overrides into routine sync
automation. `key delete` also retains its typed `YES` confirmation.
An accept command verifies every live remote pack and the complete advertised
object closure before replacing the local trust anchors; a missing or corrupt
pack aborts the acceptance.

Auth, network, and missing-repo failures are reported as such and are safe
to retry.

## Configuration (git config, per repo)

| Key | Default | Meaning |
|-----|---------|---------|
| cloak.keyRef | keychain:default (macOS), file:~/.config/cloak/keys/default (Linux) | Master key location |
| cloak.geometricFactor | 2 | Pack consolidation factor; 0 disables |
| cloak.pushRetries | 5 | Concurrent-push retry cap |
| cloak.branch | cloak | Backend branch name on the host |
| cloak.logLevel | info | Debug log level |
| cloak.maxPackBytes | 104857600 | Per-encrypted-pack limit; pushes, repacks, and rekeys split into multiple packs when possible; 0 disables the limit |

## Troubleshooting

- Debug log: `.git/cloak/<remote>/log` (JSON lines). Raise verbosity for
  one command with `CLOAK_LOG=debug git push origin main`.
- Local helper caches are reconstructible, but deleting `.git/cloak/` also
  deletes the rollback and repository-identity trust anchors. The next fetch
  restarts as trust-on-first-use; compare `git cloak status` with another
  trusted machine before accepting it.
- Interactive sensitive commands use the platform user-presence check. A
  non-interactive `key export`, `key delete`, `rekey`, `accept-rollback`, or
  `accept-repo-change` requires `--force-insecure`; scripts and launchd jobs
  never prompt silently.

## Trust limits

- First contact is trust-on-first-use. A new machine has no independent proof
  that its first decryptable manifest is the intended repository; compare its
  repo id, generation, and manifest hash out of band.
- Pins are local, not a transparency log. A Byzantine host can present
  different valid, monotonically advancing ciphertext histories to different
  machines without tripping a local lower-generation/same-generation alarm.
- The repository is plaintext on each client. Disk encryption and endpoint
  security remain necessary.
- The host still observes repository ownership, total size, pack counts and
  sizes, and operation timing.
- A single unsplittable object may make Git materialize an over-limit plaintext
  scratch pack before cloak can identify and refuse it. Scratch stays inside the
  repository state directory and stale artifacts are removed at the next
  locked session, but local free space remains an endpoint concern.

## Disaster recovery

With the host ciphertext, a key backup, and a compatible cloak build:

```
git cloak key import --key keychain:notes-recovery
git clone --config cloak.keyRef=keychain:notes-recovery \
  cloak::git@github.com:YOU/REPO.git
```

Full history, branches, and tags come back. Without the key, the remote is
permanently unreadable; that is the point. The files use an age v1 container
with a custom `cloak/v1` recipient stanza, so stock `age` cannot decrypt them;
preserve a verified binary or pinned source revision with the key. A recovery
with no saved local pin is again trust-on-first-use, so compare
`git cloak status` with another trusted record before treating it as the latest
state. Keep an independent encrypted, restore-tested backup as well as the sync
carrier.
