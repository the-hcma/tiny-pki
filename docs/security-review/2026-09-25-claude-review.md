# Security review — Claude (Sonnet 5)

- **Date:** 2026-09-25
- **Model / agent:** Claude Sonnet 5 (`claude-sonnet-5`), via Claude Code (interactive session)
- **Commit reviewed:** `b3bbf011b06b490136e03473775858b201dd7218` (`main`)
- **Scope:** full-repo review per issue #34's brief — crypto correctness, input
  handling, the filesystem store, CLI, supply chain/CI, and docs.
- **Method:** manual read of every module under `src/tiny_pki/` (issuance, CRL,
  PKCS#12, secrets, store, check, inspect, names, CLI entry/handlers/completion),
  the GitHub Actions workflows and their `.github/ci/*` scripts, and the
  security-relevant docs (`docs/security.md`, `docs/store.md`, `README.md`).
  Two findings below were confirmed with a live proof-of-concept against this
  checkout rather than inferred from reading; PoC commands are included so they
  can be re-run.

This is a single-model report (Claude only). Per issue #34, a second reviewer
from an independent model vendor is still outstanding — see the parent issue
and the "second reviewer" sub-issue. Nothing here should be treated as a full
disposition until that report exists and both are triaged together.

---

## Findings

### 1. [HIGH] CN can carry `../` path separators, letting `export pem` write outside the intended directory

**Where:** `tiny_pki.names.normalize_subject_attribute` (`src/tiny_pki/names.py`),
consumed by `generate_ca_certificate` / `generate_client_certificate` /
`generate_server_certificate` in `src/tiny_pki/issue.py`; the unsanitized value
then flows into `CertificateStore.add_certificate`'s `common_name` field
(`src/tiny_pki/store.py`) and from there into
`tiny_pki.cli.handlers._cmd_export`'s default output path
(`src/tiny_pki/cli/handlers.py:485-489`).

**Issue:** `normalize_subject_attribute` only rejects empty/over-long values and
Unicode `Cc/Cf/Co/Cs/Zl/Zp` categories (control/format/private-use/separator
chars). It does **not** reject `/` or `\`, so a common name like
`../../../tmp/evil` is accepted, stored verbatim in the X.509 CN, and kept
verbatim as `IssuedCertificate.common_name` in `index.json`.

The store itself is safe: `add_certificate` builds the on-disk filename through
`_safe_filename()` (which does escape non-alnum/`-._` chars) before calling
`_path_under_root()`, so the *store's* copies of the cert/key are never written
outside the store. But `_cmd_export`'s **pem** path does not go through
`_safe_filename` or `_path_under_root` — when `--out` is omitted it defaults to
`Path(f"{entry.common_name}.pem")` and writes the certificate **and private
key** there via `_write_secret_file`, relative to the CLI's current working
directory.

**Proof of concept** (run from this worktree):

```bash
mkdir -p /tmp/tpki-poc/store /tmp/tpki-poc/out && cd /tmp/tpki-poc/out
uv run tiny-pki --store /tmp/tpki-poc/store init
uv run tiny-pki --store /tmp/tpki-poc/store create client '../../../../tmp/tpki-poc/evil'
uv run tiny-pki --store /tmp/tpki-poc/store export pem '../../../../tmp/tpki-poc/evil'
# -> "wrote ../../../../tmp/tpki-poc/evil.pem"
ls -la /tmp/tpki-poc/evil.pem   # landed outside out/, at /tmp/tpki-poc/
```

Confirmed: the private key PEM is written to `/tmp/tpki-poc/evil.pem`, two
directories above the CLI's working directory, purely from the identity string
resolving to a live certificate.

**Impact:** A consuming application that lets an end user pick a device/person
name and passes it straight through as the CN (a very plausible integration —
neither `generate_client_certificate`/`generate_server_certificate` nor the CLI
`create` command restrict the character set beyond what
`normalize_subject_attribute` does) can plant a CN that later causes
`tiny-pki export pem <identity>` (no `--out`) to write cert + private key
material to an attacker-chosen path relative to the current working directory
of whatever process runs the export — e.g. overwriting a file the operator
didn't intend to touch, or exfiltrating key material to a location the CN's
author can read but the store's owner did not intend to expose it to.

**Suggested fix:** Either (a) reject `/` and `\` (and `..` sequences) in
`normalize_subject_attribute`, since a CN with a path separator is nonsensical
for an X.509 name, or (b) sanitize `entry.common_name` in `_cmd_export`'s
default-filename branch the same way `_safe_filename()` already does for the
store's own file layout, or (c) both — (a) closes the hole at the source for
every caller (including library consumers who never touch the CLI at all), (b)
defends the CLI specifically. Add a regression test mirroring
`test_add_certificate_rejects_symlink_escape` in `tests/test_store.py`, but for
`export pem` with a `../`-laden identity.

---

### 2. [HIGH] The CA cert/key, CRL, and index files follow pre-planted symlinks; only leaf cert/key paths are hardened

**Where:** `CertificateStore.write_ca`, `write_crl`, `_write_index`, and the
`ca_cert_path` / `ca_key_path` / `crl_path` / `index_path` properties in
`src/tiny_pki/store.py`.

**Issue:** `add_certificate` and `write_bundle` route every leaf path through
`_path_under_root()`, which calls `.resolve()` (following symlinks) and then
checks the *resolved* path is still under the store root — this correctly
rejects a pre-planted symlink at a leaf cert/key path, and is already covered
by `tests/test_store.py::test_add_certificate_rejects_symlink_escape`.

The CA certificate/key, the CRL, and `index.json` do **not** go through that
helper. `ca_cert_path`, `ca_key_path`, `crl_path`, and `index_path` are plain
`self.root / "ca" / "<fixed name>"` properties, and `write_ca` / `write_crl` /
`_write_index` call `write_bytes()` / `os.open(..., O_CREAT | O_TRUNC, 0o600)`
directly on them — both follow an existing symlink at that exact path, and
neither passes `O_NOFOLLOW`.

**Proof of concept:**

```bash
mkdir -p /tmp/tpki-sym/store/ca
echo "PRE-EXISTING SENSITIVE CONTENT" > /tmp/tpki-sym/target-secret.txt
chmod 644 /tmp/tpki-sym/target-secret.txt
ln -s /tmp/tpki-sym/target-secret.txt /tmp/tpki-sym/store/ca/ca.key
uv run tiny-pki --store /tmp/tpki-sym/store init
cat /tmp/tpki-sym/target-secret.txt   # now contains the freshly generated CA private key
ls -la /tmp/tpki-sym/target-secret.txt  # mode is now 0600 — chmod followed the symlink too
```

Confirmed on this checkout: `init` wrote the newly generated CA private key
through the symlink into `target-secret.txt` (an unrelated file elsewhere on
disk) and `chmod`'d that file to `0600`, overwriting whatever was there before.
The symlink itself is left in place (`ca.key` still points at the same
external file), so every subsequent read/write of the CA key in that store
silently operates on the external target.

**Impact:** Requires an attacker who can write into the store directory
*before* `init`/a later `write_ca`/`write_crl` runs (e.g. a shared multi-tenant
host, a store path under a world-writable parent, or a setup race where the
directory is created before the real owner's `init`). Given that
precondition, this is a **CA private-key confidentiality/integrity** issue:
the attacker chooses where the CA key lands (potentially a location only they
can read) or corrupts an arbitrary file the invoking user can write, which
lines up with this issue's "path traversal and symlink attacks under
`--store`" and "TOCTOU window on secret writes" scope items. It is a real gap
relative to the protection the codebase already gives leaf cert/key paths —
the fix that exists for leaves (`_path_under_root`) does not need reinventing,
it needs applying (or an explicit `O_NOFOLLOW` / `path.is_symlink()` guard,
the same pattern `tiny_pki.cli.completion.run_completion` already uses for
completion-script installs) to the four fixed CA/CRL/index paths.

**Suggested fix:** Refuse (or explicitly resolve-and-revalidate) a symlink at
`ca_cert_path` / `ca_key_path` / `crl_path` / `index_path` before writing —
either route them through `_path_under_root`-style resolution, or check
`path.is_symlink()` and raise before opening, matching `completion.py`'s
existing pattern. Add a test parallel to
`test_add_certificate_rejects_symlink_escape` for `write_ca`/`write_crl`.

---

### 3. [MEDIUM] `tiny_pki.secrets`' Fernet key derivation has no domain separation, and the README's own example encourages secret reuse

**Where:** `src/tiny_pki/secrets.py:52-54` (`_derive_fernet_key`); `README.md`
line ~190 ("the secret you pass (e.g. Django `SECRET_KEY`)").

**Issue:** The module's docstring is explicit and correct that this is *not* a
password-hashing KDF — it's a single SHA-256 of an already-high-entropy secret,
which is a reasonable, documented design choice for a caller who passes a
dedicated random value. The gap is that the one example the project's own docs
give — Django's `SECRET_KEY` — is a secret Django itself uses for several
*other* purposes (session signing, CSRF tokens, password-reset tokens,
`django.core.signing`). `_derive_fernet_key` has no context/domain-separation
string (e.g. HKDF with an `info` parameter), so deriving the CA-key-encryption
key from the *same* `SECRET_KEY` a Django app also uses for unrelated signing
means a leak of that key through any unrelated Django vector (a debug page, a
signing oracle, a `SECRET_KEY` rotation mistake) also exposes every encrypted
CA/leaf private key stored via this helper.

**Impact:** Medium — this only bites consumers who follow the README's literal
example without deriving a dedicated secret first; it's a documentation/API
footgun more than a bug in the module's stated contract, but the stated
contract ("this is not a password-hashing KDF... for explicit-secret callers
that already manage secret strength") assumes the caller understands the
secret needs to be *dedicated*, and the example right next to it in `README.md`
doesn't reflect that.

**Suggested fix:** Either (a) change the README example to show deriving a
distinct secret (e.g. `hashlib.sha256(settings.SECRET_KEY.encode() +
b"tiny-pki-ca-key").hexdigest()` or an explicit separately-generated value),
or (b) add an `info`/context parameter to `derive_fernet_key` /
`encrypt_private_key` (HKDF-style domain separation) so reusing an app-wide
secret is safe by construction, and update `docs/security.md`'s "Rotating the
Fernet secret" section to call out key reuse explicitly. Either is a docs-only
or small-API change, not a crypto rewrite.

---

### 4. [LOW] `MIN_PKCS12_PASSWORD_LENGTH = 8` is a low floor for a bundle that can be brute-forced fully offline

**Where:** `src/tiny_pki/constants.py` (`MIN_PKCS12_PASSWORD_LENGTH = 8`),
enforced in `src/tiny_pki/bundle.py:36-37`.

**Issue:** `docs/security.md` already tells operators to "use a long, random
[password]" and that "the bundle can be attacked offline," which is the right
guidance — but the library only *enforces* an 8-character floor. Eight
characters, even prompted via `getpass`, is well within reach of an offline
PBKDF2 attack against a captured `.p12` file (the modern default is AES-256
with PBKDF2-HMAC-SHA256, which is far better than the `--legacy` PBES1/SHA-1
path, but still bounded by password entropy).

**Suggested fix:** Consider raising the floor (e.g. 12–16), or leave the floor
as a sanity check but have the CLI's interactive prompt warn (not block) on a
password under some higher watermark, similar to the existing
`TinyPkiWarning` pattern used elsewhere in `issue.py`. Low priority — the docs
already carry the real guidance — but worth a deliberate decision either way
rather than an inherited default.

---

### 5. [LOW / INFO] REPL history file permissions aren't pinned to `0600`

**Where:** `src/tiny_pki/cli/main.py:95-102` (`_repl_history`), which hands
`~/.cache/tiny-pki/history` to `prompt_toolkit.history.FileHistory` without
any explicit mode.

**Issue:** No password ever reaches this history file — passwords are read via
`getpass.getpass()` (a separate raw terminal read, confirmed by reading
`_prompt_p12_password` / `_cmd_export`) or `--password-file` (a path, not the
password itself), so this is not a secret-exposure finding in the way the
issue brief's "REPL history persistence" bullet might suggest. It does persist
every CN/org/store-path/identity ever typed in the REPL, unencrypted, with
whatever mode `FileHistory`'s `open()` + the process umask produce (typically
`0644` on a default umask) rather than the `0600` this codebase already uses
everywhere else it writes something sensitive (`_write_secret`,
`_write_secret_file`). On a shared multi-user host this leaks CN/org naming
and store paths (reconnaissance value) to other local users, even though it
doesn't leak keys.

**Suggested fix:** `os.chmod(_HISTORY_PATH, 0o600)` after creating the parent
dir / first write, for consistency with the rest of the codebase's secret-file
hygiene, and to close the gap before someone assumes (reasonably, given the
pattern everywhere else) that it's already `0600`.

---

### 6. [INFO] `dependabot-auto-merge.yml`'s `pull_request_target` trigger is safe as written, but fragile if extended

**Where:** `.github/workflows/dependabot-auto-merge.yml`.

**Issue:** Not a vulnerability as written — the job never checks out the PR
head ref or runs any code from it; it only calls `gh pr merge --auto --squash`
gated on `github.actor == 'dependabot[bot]'`, with `contents: write` /
`pull-requests: write`. `pull_request_target` runs with the base repo's
token/secrets by design, which is exactly why it's conventionally flagged: the
moment someone "helpfully" adds an `actions/checkout` of the PR head to this
job (e.g. to run tests before merging), it becomes the classic
`pull_request_target` code-execution pattern this repo's own `cve-check.yml`
comment explicitly warns about (the `tj-actions/changed-files`-style attack).

**Suggested fix:** Add a short comment in the workflow (mirroring the one
already in `cve-check.yml`) stating that this job must never check out or
execute the PR's head ref, so a future edit doesn't reintroduce the pattern
those SHA-pinning comments elsewhere in this repo are already defending
against.

---

## Areas reviewed with no findings

- **Certificate/CRL construction** (`issue.py`, `revoke.py`): BasicConstraints,
  KeyUsage, EKU, SKI/AKI, Name Constraints enforcement (including the
  OpenSSL-compatible CN-as-DNS-ID fallback), serial generation
  (`x509.random_serial_number()`), SHA-256 signing, CRL number bounds (RFC 5280
  §5.2.3's 20-octet limit), backdating for clock skew — all consistent with
  RFC 5280 and the documented Apple/CA-Browser-Forum constraints. Leaf-outlives-CA
  and validity-cap enforcement (`_leaf_validity_window`) match `docs/defaults.md`'s
  stated rationale.
- **Name/SAN parsing** (`names.py`): control-character rejection, IDNA2008
  A-label conversion with an explicit IDNA2003/2008 nameprep mismatch check
  (protects against the "ß→ss" confusable-mapping class of bug), CIDR/URL/
  scoped-IPv6 rejection in SAN entries, wildcard placement rules. Solid.
- **PKCS#12** (`bundle.py`): correct default (AES-256-CBC + PBKDF2-HMAC-SHA256 +
  HMAC-SHA256), `--legacy` clearly scoped to compatibility only.
- **RSA key loading** (`_rsa.py`): explicitly rejects encrypted keys and
  non-RSA keys with a clear error, no silent fallback.
- **Store index handling**: `index.json` tampering (non-list, wrong types,
  bad `kind`, traversal in `cert_path`/`key_path`) is already rejected by
  `_entry_from_dict`/`_path_under_root`/`_read_index`, with tests
  (`test_migrate_rejects_path_traversal`, `test_index_path_traversal_rejected`).
  Legacy-layout migration is re-entrant and order-safe (leaves before CA files)
  so a mid-migration crash resumes correctly.
- **CLI password handling**: no password ever appears as a CLI flag value or
  in `ps`; `getpass` for interactive entry, `--password-file` for automation
  (first line only, explicit UTF-8/OSError handling), and the CLI already
  offers to delete the password file after a successful `p12` export.
- **CI/supply chain**: every third-party Action is pinned to a full commit SHA
  with a version comment; `persist-credentials: false` on checkouts that don't
  need to push; `secret-scan` downloads gitleaks over HTTPS and verifies a
  hardcoded SHA-256 before extracting; `cve-check.yml` carries an explicit,
  well-reasoned comment about why every action there must stay SHA-pinned;
  `uv.lock` is committed and version-checked against `pyproject.toml`
  (`assert-uv-lock-version`); the packaging gate asserts the wheel installs
  only `cryptography` (+ its native deps) without the `[cli]` extra. This is
  already at a high bar; no changes suggested.
- **Docs** (`docs/security.md`, `docs/store.md`, `README.md`): guidance is
  consistent and doesn't steer consumers toward an insecure default (CA key
  handling, CRL freshness, nginx `ssl_crl` wiring all correctly described).

## Not reviewed / out of scope for this pass

- **Repo governance settings** (branch protection, Actions allowlist,
  CODEOWNERS, PyPI trusted-publishing config) — the issue's Part 2 checklist
  asks to audit these against `SECURITY.md`'s claims; this pass hit a GitHub
  API rate limit partway through and did not complete that audit. Tracked as
  a follow-up (see the triage table and the sub-issue for it).
- **The second, independent-vendor reviewer** required by this issue's Part 1
  — this report is Claude-only.
