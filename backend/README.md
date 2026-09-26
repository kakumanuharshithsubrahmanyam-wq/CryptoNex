# CryptoNex backend

Deterministic static analysis for cryptographic inventory, migration planning,
and reviewable patch proposals. The scanner never executes repository code,
never installs scanned dependencies, and never claims that a repository is
quantum-safe.

## Automatic migration patch generation

A generated patch is a **proposal**. CryptoNex does not apply it, commit it,
open a pull request, or mark the finding resolved.

Pipeline:

Finding → migration plan → blast radius → patch strategy → generator →
unified diff → validation → proposal

`source_migrated` is always `false`. Generating a patch is not a successful
migration.

### Patch status values

| Status | Meaning |
| --- | --- |
| `generated` | A deterministic unified diff was produced and passed validation. |
| `manual_migration_required` | The mapping is known, but a safe one-line rewrite would fabricate code. |
| `unsupported` | No deterministic transformation is registered (modern primitives, dependency-only evidence, unknown APIs). |
| `validation_failed` | A rewrite was attempted and rejected (missing source, mismatch, traversal, size, secrets). |

`applied` is not a valid status. This feature does not apply patches.

### Safety model

The generator reads only the already-ingested workspace snapshot.

It does not:

- run subprocesses, shells, or scanned repository code
- install packages
- commit, push, or create pull requests
- reach the scanned repository over the network
- write files outside the controlled project workspace

Paths are contained. Patch size is limited by `MAX_PATCH_BYTES` (default 16384).
Evidence and diffs reuse the existing secret-redaction utilities. A diff that
would include a redacted secret is rejected.

### Deterministic vs AI responsibilities

Detection, migration mapping, rewrite, and validation are deterministic.

The optional AI provider may later summarize rationale. It must not invent
source, invent findings, or override scanner evidence. This implementation
does not use AI to produce patch content.

### Supported deterministic transformations

Only unambiguous legacy-hash API replacements are generated today, when the
stored line span matches a registered rewrite and the replacement is in the
migration registry:

- Python `hashlib.md5` / `hashes.MD5` → SHA-256
- Python `hashlib.sha1` / `hashes.SHA1` → SHA-256
- Java `MessageDigest.getInstance("MD5"|"SHA-1")` → SHA-256
- Go `md5.New` / `sha1.New` → `sha256.New`
- Rust `Md5` / `Sha1` type tokens → `Sha256`
- C/C++ `EVP_md5` / `EVP_sha1` and explicit `"MD5"` / `"SHA-1"` factory strings → SHA-256

Registered classical counterparts also include SHA-384, SHA-512, SHA-3, BLAKE2,
and BLAKE3 for MD5/SHA-1 when requested explicitly.

### Manual migration behavior

RSA, ECDSA, Ed25519, ECDH, X25519, Diffie-Hellman, and DSA are not rewritten
as one-liners. The proposal returns `manual_migration_required` with:

- reason
- affected files, dependencies, protocols, and certificates from blast-radius
- a validation checklist
- a suggested migration strategy from the existing planner

Legacy ciphers (DES, 3DES, Blowfish) are also manual. Dependency-only findings
are `unsupported` because versions must not be guessed.

### API

```
POST /api/v1/scans/{scan_id}/migrations/{finding_id}/patch
GET  /api/v1/scans/{scan_id}/migrations/{finding_id}/patch
```

Request body:

```json
{ "replacement": "SHA-256", "mode": "minimal" }
```

`replacement` is optional. When present it must exist in the migration
registry for that finding. `mode` is `minimal` or `migration`. GET returns the
latest stored proposal (`PATCH_NOT_FOUND` if none).

Existing migration, blast-radius, and what-if endpoints are unchanged.

## Planned automation (not implemented)

These stages are designed to attach later without rewriting the proposal
service. They are not available now:

1. Apply an approved patch in an isolated workspace, rescan, and compare findings.
2. CI/CD attachment of a proposal when policy fails.
3. Optional pull-request creation only after explicit user opt-in.
4. Crypto-debt batching of related findings.
5. Dependency declaration patches when versions are explicit and registered.
6. Drift remediation proposals from scan comparison.

## Language detection notes

Rust `.rs` files are scanned for typed API usage (`Type::method(`) and
recognized `use` paths. Cargo.toml remains dependency evidence only.

C/C++ detection covers OpenSSL and Botan-style APIs, including X25519, ML-KEM,
ML-DSA, SLH-DSA, TLS, and X.509 types. A cryptographic toolkit repository may
legitimately have no external application dependencies.

Certificate artifacts keep every occurrence and location. Duplicate content
shares a stable `content_fingerprint`. Test fixtures, generated test data,
embedded source PEMs, and configuration references are classified; they are
not deleted because they appear in tests.
