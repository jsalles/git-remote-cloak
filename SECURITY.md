# Security Policy

git-remote-cloak is an encryption tool, so the correctness of its security
invariants is the whole point. Reports showing a way to break confidentiality,
integrity, authenticity, rollback or repo-identity protection, or the
fail-closed behavior are especially valuable. The project is maintained on a
best-effort basis by a single maintainer; the process below reflects what can
actually be operated, not a formal program.

## Supported versions

Security fixes are issued only for the latest released version (the most recent
git tag). Older pre-1.0 versions do not receive updates; upgrade to the latest
release.

| Version                          | Supported |
|----------------------------------|-----------|
| Latest release (most recent tag) | Yes       |
| Any older version                | No        |

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues,
pull requests, or discussions, or via social media or direct messages.

Report privately through GitHub's private vulnerability reporting: the
repository's Security tab -> Report a vulnerability
(https://github.com/b4ryon/git-remote-cloak/security/advisories/new). This
opens an advisory visible only to you and the maintainer.

## What to include

Where you can, include:

- the affected version, tag, or commit SHA;
- a clear description of the issue and why it is a security problem;
- steps to reproduce or a proof of concept;
- relevant logs, payloads, or screenshots;
- the security impact, and any known mitigation or fix.

Never send real secrets in a report: no master key, exported key material, or
plaintext repository contents (redacted or synthetic examples are enough). Do
not run destructive tests against hosts or data you do not own, and do not
publish an exploit before a fix is available.

## Response expectations

- Acknowledgment within 5 business days.
- An initial assessment (confirmed or not, and likely severity) as triage time
  allows, with follow-up through the private advisory thread.

This is a personal open-source project: best-effort response times, no bug
bounty.

## Disclosure

Confirmed vulnerabilities are handled through GitHub Security Advisories. A fix
is prepared and released first, then the advisory is published, crediting the
reporter unless you ask otherwise; timing is coordinated with you where
practical.

## Security boundary and operating constraints

- The carrier stores AEAD-encrypted manifests and packs. Plain filenames,
  branch names, commit messages, and history structure stay inside trusted
  clients; repository ownership, ciphertext sizes/counts, and operation timing
  remain visible to the carrier.
- Ciphertext uses an age v1 container with the custom `cloak/v1` recipient
  stanza. Stock `age` cannot decrypt it; disaster recovery requires the key and
  a compatible cloak binary or pinned source revision.
- Rollback and repository-identity checks are anchored in each client's local
  `.git/cloak/` state. A list-only fetch repairs an absent pin pair or a stale
  generation pin only after proving the complete advertised object closure is
  already local; inconsistent or mismatched pins still fail closed.
  Explicit rollback/repository-change acceptance additionally verifies the
  presence and authenticated ciphertext hash of every live pack before pinning.
- Do not use Git LFS. LFS uses a separate object transport and its payloads do
  not pass through cloak encryption. cloak rejects tracked `filter=lfs`
  attributes and standard Git LFS pre-push hooks before sync, but cannot
  intercept an independently invoked `git lfs push` command.
- Receive-side size checks bound cloak's scratch copy, decryption, and pack
  application. Git's promisor machinery necessarily transfers/stores each
  requested outer blob in the private backend mirror before cloak can inspect
  its size; a carrier that rejects or ignores partial-clone filters may transfer
  every blob eagerly. Carrier-controlled network/cache exhaustion therefore
  remains an availability risk.
- Outbound encrypted streaming stops at `cloak.maxPackBytes` before switching
  to Git's split-pack mode. Git itself must still materialize each plaintext
  split pack; one unsplittable object can temporarily exceed that limit before
  cloak identifies and refuses it. Scratch is inside `.git/cloak/` and stale
  artifacts are removed under the per-remote lock on the next session.
- Prefer SSH carrier URLs. With HTTPS, use Git's credential helper. cloak
  refuses HTTP(S) userinfo and transport URLs containing passwords, queries, or
  fragments; SSH usernames remain supported. Diagnostics also redact
  credential-shaped URLs as defense in depth. Backend transports are allowlisted
  to local/scp-like paths and Git's built-in file/git/http/https/ssh variants;
  unknown external remote helpers are refused. Host and repository path remain
  visible.
- `key export`, `key delete`, `rekey`, `accept-rollback`, and
  `accept-repo-change` refuse a non-interactive invocation unless the caller
  deliberately supplies `--force-insecure`. This prevents an accidental
  headless bypass; it is not an authorization boundary against code already
  running as the user.

## Out of scope

These are documented, accepted trade-offs of the design, not vulnerabilities
(see "Trust model and accepted risks" in `README.md`):

- Metadata the host inevitably observes: the repository's existence, owner,
  total size, pack count and sizes, carrier commit/update topology, and timing.
- Trust-on-first-use on a brand-new clone (no pin yet); mitigate it by comparing
  `git cloak status` against another machine over a trusted channel.
- Byzantine split views. Pins detect a lower generation or changed ciphertext
  at the same generation relative to one client's last accepted state. There
  is no transparency log, cross-client gossip, or authenticated proof that all
  clients saw one history, so a malicious carrier can serve different valid,
  monotonically advancing forks to different clients.
- Local or endpoint compromise: cloak trusts the machines that hold the key and
  their Keychain/disk.
- Historical ciphertext after rekey. Rekey replaces the current carrier state
  but cannot erase old ciphertext retained in reflogs, backups, caches, or by an
  attacker; the old key still decrypts data previously encrypted under it, and
  no later operation can revoke copies an observer already retained.
- Key deletion is unlinking, not guaranteed physical erasure. cloak removes its
  configured file and any interrupted-save hard-link aliases it can identify,
  but filesystem snapshots, backups, copied exports, and storage remanence are
  outside its control.
- Explicit `--force-insecure` use on key export/delete, rekey, or either accept
  command deliberately skips the user-presence gate for a non-interactive
  caller.
