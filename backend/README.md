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

`applied` is not a patch status. Generating a proposal does not modify the repository. Verification, below, applies a stored proposal only in an isolated copy.

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

## Automatic remediation verification

Explicit verification extends a stored patch proposal:

Detect → plan → generate patch → review → verify in isolation → rescan →
compare → detect regression

```
POST /api/v1/scans/{scan_id}/migrations/{finding_id}/patch/verify
GET  /api/v1/scans/{scan_id}/migrations/{finding_id}/patch/verify
```

Request:

```json
{ "patch_id": 1 }
```

The endpoint accepts only `patch_status = generated`. It copies the ingested
snapshot into a temporary workspace under the CryptoNex workspace root, applies
the stored unified diff with an internal applier, and runs the existing
scanner. The verification scan is stored separately (`kind = verification`)
and is excluded from project drift and the latest policy scan. The original
scan and source tree stay unchanged.

### Verification states

| Status | Meaning |
| --- | --- |
| `verified` | The targeted algorithm usage is gone, the registered replacement is present, and no regression was detected. |
| `partially_verified` | The targeted algorithm is gone, but the observed replacement is not the registered one and the role remains. |
| `manual_review_required` | The original usage and the replacement are both still present. |
| `no_change` | The patch applied and the targeted finding is unchanged. |
| `verification_failed` | The scanner cannot confirm the intended change. |
| `patch_failed` | The stored diff was rejected or did not apply. |
| `rescan_failed` | The isolated scanner run failed. |
| `regression_detected` | Deterministic evidence shows a new finding, policy failure, dependency change, certificate/protocol change, CBOM change outside the intended edit, or an unrelated finding disappeared. |

`target_status` is `resolved`, `still_present`, `partially_resolved`, or `unknown`.
`verified` is not returned merely because the diff applied.

Policy comparison reports whether failures decreased, stayed unchanged, or
increased. There is no numeric security score. A CBOM change is described as
`expected`, `unexpected`, or `unchanged`. A changed CBOM does not prove the
repository is secure or quantum-safe.

### Isolation safety

Verification does not run repository code, install packages, compile, commit,
push, or open a pull request. Paths must stay inside the copied snapshot.
Absolute paths, `..`, missing files, oversized diffs, and secret-bearing diffs
fail as `patch_failed`.

Complex public-key migrations (RSA, ECDSA, Ed25519, ECDH, X25519, DH, DSA)
remain `manual_migration_required` and are not rewritten into PQC one-liners.

## Planned automation (not implemented)

Isolated apply, rescan, and comparison are implemented above. These stages
are not implemented:

1. CI/CD attachment of a proposal when policy fails.
2. Optional pull-request creation only after explicit user opt-in.
3. Crypto-debt batching of related findings.
4. Dependency declaration patches when versions are explicit and registered.
5. Drift remediation proposals from scan comparison.
6. Automatic merging, GitHub push, or runtime instrumentation.

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
