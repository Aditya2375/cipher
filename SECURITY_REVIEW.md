# Security review

Reviewed 2026-11-03. This is educational cryptography, not an audited tool
for real secrets. Passing tests and scanners is not proof of no vulnerabilities.

## Evidence

- Gitleaks 8.30.1: full history and working directory scanned. Zero real
  secrets. One exact historical fingerprint is excluded: public prose
  the algorithm name following a passphrase description mistaken for an API key. No broad allowlist.
- Semgrep community rules (`p/security-audit`, `p/c`, `p/javascript`):
  99 rules, zero findings. Zero parsing errors; the bridge is also manually reviewed and
  compiler-tested.
- GCC `-fanalyzer -Wall -Wextra -Werror`: no diagnostics.
- 24 unit checks, 14 CLI integration checks, 6 WebAssembly checks,
  5 worker checks. ASan/UBSan cover unit tests and parser mutations.
- Six fuzz seeds, 60 blobs each, including valid multi-chunk files,
  random data, changed ciphertext and truncated containers. Driver accepts
  full multi-chunk inputs and clamps the KDF only inside the fuzz harness.
- 1,000 complete AEAD ciphertext/tag comparisons with the independent
  `cryptography` implementation, including empty and 64 KB messages.
  This oracle is an optional development check, not a runtime dependency.
- No runtime packages beyond libc. Web build uses emscripten 6.0.13.
  CI actions are immutable commit pins; permissions are `contents: read`.
- GitHub secret scanning, push protection, vulnerability alerts and
  automated dependency security updates enabled. No application database,
  server, account system, analytics, remote API or cloud file storage.
- HTTP redirects to HTTPS at the live project path. GitHub Pages provides
  HSTS but does not allow custom response headers. Meta CSP and referrer
  policy are included. No third-party scripts or fonts.
- MDN Observatory was attempted on the hostname. It failed because the
  account root returns 404; this API scans hosts, not the `/cipher/` path.
  No grade is claimed. Custom frame protection is a hosting limitation.

## Findings fixed

Exclusive 0600 output creation prevents overwrites, symlink following and
plaintext exposure to other local users. Failed operations remove only the
newly created output. Password reads reject overlength rather than silently
truncate; terminal setup failures abort. Password/key buffers use volatile
zeroing, although browser strings and OS copies cannot be reliably erased.

The browser bridge uses memory streams rather than persistent temporary
files. Work runs in a short-lived worker; old download URLs are revoked,
password fields cleared, byte buffers wiped, and file selection locked
during an operation. Encryption requires password confirmation. File limits
are checked in both the page and worker and allow ciphertext overhead when
decrypting. Untrusted filenames and errors are rendered as text, never HTML.

Fuzzing found and fixed a driver-only tag-boundary overread. ASan found and
fixed an undersized long-key test buffer. Neither was a production primitive
failure. CI's fuzz setup now builds and verifies its seed generator, uses a
private temporary directory, and fails on setup errors.

## Checklist cross-check (45 items)

| # | Result and scope |
|---|---|
| 1 | Pass: history + build-output secret scans; exact prose false positive reviewed. |
| 2 | Pass: no service/API keys or client credentials. |
| 3 | Pass: secret patterns ignored; fail-closed local gitleaks pre-commit hook installed. |
| 4 | N/A: no real leaked secret detected. |
| 5 | N/A: no database or RLS surface. |
| 6 | N/A: no remote storage; browser data not persisted. |
| 7 | N/A: no server or private API; public static assets are intentional. |
| 8 | Pass: no personal data collected or logged. |
| 9 | Pass: DOM text APIs, no eval or untrusted HTML. |
| 10 | Pass: no application SQL or shell execution. Test subprocesses use argument lists. |
| 11 | Pass: local CLI paths are user-selected; output cannot overwrite or follow links. No URL fetch input. |
| 12 | Pass: no added runtime package; emscripten and pinned CI action identities inspected. |
| 13 | Pass by scope: no package graph/lockfile; dependency alerts enabled; CI pins exact actions. |
| 14 | Pass: no imported agent/editor instruction files. |
| 15 | N/A: no production service credentials or data. |
| 16 | Pass: actual project path redirects HTTP to HTTPS. |
| 17 | Partial hosting constraint: meta CSP and no-referrer; no custom frame/header control on Pages. Observatory failed at root 404. |
| 18 | Pass: no source maps, hidden debug control or verbose secret errors. Public source is intentional. |
| 19 | N/A: no login/session system; file password KDF is PBKDF2, not authentication storage. |
| 20 | N/A: no public compute endpoint; local size and KDF work bounds enforced. |
| 21 | Pass: invalid tags/containers fail; no output survives CLI failure. Non-secret errors only. |
| 22 | Owner-only account decision: not inspected or changed. |
| 23 | Pass: published assets inspected; no personal data, keys or private files. |
| 24 | Pass: no client login/admin mechanism. |
| 25 | N/A: not Vercel; build output scanned separately. |
| 26 | Pass: scripts, wasm and styles self-hosted; system fonts only. |
| 27 | N/A: no remote form or mail endpoint. |
| 28 | Out of scope: no abandoned deployment created; other repos untouched. |
| 29 | N/A: no APK. |
| 30 | N/A: no Android manifest. |
| 31 | N/A: no Android traffic. |
| 32 | N/A: no Android secret storage. |
| 33 | N/A: no Android permissions. |
| 34 | N/A: no Android signing key. |
| 35 | N/A: no Android release. |
| 36 | N/A: no WebView/deep link handler. |
| 37 | N/A: no relay channel. |
| 38 | N/A: no relay/agent command intake. |
| 39 | N/A: no app update channel. |
| 40 | Pass by scope: development scripts contain no account credentials. |
| 41 | N/A: no account/money monitor. |
| 42 | Pass: tests use synthetic data; no sensitive logs or snapshots shipped. |
| 43 | Pass by scope: no scraped content, pickle or unsafe YAML parsing. |
| 44 | Pass: read-only workflow permissions, exact action commits, no workflow secrets. |
| 45 | N/A: no external alert channel. |

## Remaining limits

PBKDF2 is not memory-hard. Algorithm implementations have not received an
independent side-channel audit. Randomness depends on the operating system
or browser runtime. File size is visible, filenames are not encrypted,
and disk/buffer copies are not securely erased. Decryption can spend up to
10 million KDF iterations before authentication, so hostile input can use
CPU within that bound. The format API authenticates each chunk before
writing it; callers must discard all output on any error. The CLI does so,
and the browser releases a download only after the whole file succeeds.
