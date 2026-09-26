# CryptoNex

## Overview

CryptoNex is a platform for post-quantum cryptography migration and crypto-agility. Phase 1 ingests a public GitHub repository or a ZIP archive into an isolated workspace and records a file manifest. Phase 2 runs deterministic static analysis on that manifest and records evidence-backed cryptographic findings. Phase 3 attaches deterministic evidence, confidence, and cryptographic context to those findings. Phase 4 builds a static dependency inventory and links source findings to declared packages. CryptoNex does not execute repository code.

## Current Phase

Phase 4 — Dependency Intelligence

The API still exposes `GET /api/v1/health`. A project can be created from a public GitHub HTTPS URL or a ZIP upload, then ingested with `POST /api/v1/projects/{id}/ingest`. After ingestion succeeds, `POST /api/v1/projects/{id}/scan` runs detection, context classification, and dependency inventory together and returns a scan summary. Stored scans can be read from `GET /api/v1/scans/{scan_id}`, `GET /api/v1/scans/{scan_id}/findings`, and `GET /api/v1/scans/{scan_id}/dependencies`. This is deterministic static analysis. It does not establish that a system is quantum-safe or quantum-vulnerable.

## Architecture

The backend and frontend are separate applications.

- The backend is a FastAPI service. Route handlers stay thin and call services. Settings, logging, database sessions, and API errors live in dedicated modules.
- The frontend is a React application. It reads the API origin from `VITE_API_BASE_URL` and calls the backend through a small API client.
- The browser talks to the API directly. CORS allows only the origins listed in `CORS_ORIGINS`.

Later phases can add routes, services, and models beside this layout without changing the split between the two applications.

## Technology Stack

- Python 3.11+
- FastAPI
- Pydantic v2
- Pydantic Settings
- SQLAlchemy 2
- SQLite (local development)
- Uvicorn
- pytest
- httpx
- httpx2 (used by the current Starlette test client)
- React
- TypeScript
- Vite

## Project Structure

```text
.
├── backend/
│   ├── app/
│   │   ├── api/v1/          # versioned HTTP routes
│   │   ├── core/            # settings, logging, database, errors
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # API request and response models
│   │   ├── services/        # health, ingestion, scanning, context, dependencies
│   │   └── main.py          # application factory
│   ├── tests/
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   └── src/
├── samples/
├── docs/
├── scripts/
├── .env.example
├── .gitignore
└── README.md
```

## Backend Setup

Requires Python 3.11 or newer. From the repository root:

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

If `python3` is older than 3.11, create the virtual environment with a newer interpreter, for example `python3.13 -m venv .venv`.

The health check is `GET http://127.0.0.1:8000/api/v1/health`.

Startup creates the SQLite schema. Copy `../.env.example` to `../.env` or `backend/.env` when you want file-based settings. Environment variables override those files.

## Frontend Setup

From the repository root:

```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

The dev server prints a local URL, usually `http://localhost:5173`. The page calls `GET /api/v1/health` and shows **CryptoNex API Connected** when the backend responds. It accepts a GitHub repository URL or a ZIP file, shows the ingestion result, and can run a crypto scan on a ready project.

## Environment Variables

Backend (process environment or `.env`):

| Variable | Purpose | Default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database URL | `sqlite:///./cryptonex.db` |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | `http://localhost:5173,http://127.0.0.1:5173` |
| `ENVIRONMENT` | Runtime name, such as `development`, `test`, or `production` | `development` |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` | `INFO` |
| `WORKSPACE_ROOT` | Directory for ingested files | `./workspaces` |
| `GIT_EXECUTABLE` | Git binary used for clones | `git` |
| `MAX_REPOSITORY_SIZE_MB` | Maximum cloned tree size, including `.git` | `100` |
| `MAX_FILE_COUNT` | Maximum files in a repository or ZIP | `10000` |
| `MAX_FILE_SIZE_MB` | Maximum size of one file | `10` |
| `CLONE_TIMEOUT_SECONDS` | Maximum git clone duration | `120` |
| `MAX_ZIP_SIZE_MB` | Maximum uploaded ZIP size | `50` |
| `MAX_ZIP_EXTRACTED_SIZE_MB` | Maximum uncompressed ZIP size | `200` |
| `SCAN_EXCLUDED_DIRECTORIES` | Comma-separated directories skipped by the scanner | `node_modules,vendor,dist,build,.git,__pycache__,.venv,venv,target` |
| `EVIDENCE_MAX_CHARS` | Maximum characters in a finding evidence snippet | `240` |

When `ENVIRONMENT=production`, `CORS_ORIGINS` must be an explicit list. An empty value or `*` fails startup.

Frontend:

| Variable | Purpose |
| --- | --- |
| `VITE_API_BASE_URL` | API origin, for example `http://localhost:8000` |

Vite reads this variable at dev-server and production-build time. Do not commit `.env`.

## Testing

Backend tests, from `backend` with the virtual environment activated:

```bash
pytest
```

Frontend type check and production build, from `frontend`:

```bash
npm run typecheck
VITE_API_BASE_URL=http://localhost:8000 npm run build
```

## Git/GitHub Development Workflow

The working branch is `main`. `origin` is the public GitHub repository:

https://github.com/kakumanuharshithsubrahmanyam-wq/CryptoNex

1. Create a branch for each change.
2. Keep secrets, virtual environments, `node_modules`, local databases, and build output out of Git. `.env` is ignored. Use `.env.example` and `frontend/.env.example` as templates.
3. Run `pytest` in `backend` and `npm run typecheck` plus `npm run build` in `frontend` before pushing.
4. Commit on the branch and open a pull request against `main`.

## Repository Ingestion

Supported GitHub URLs are public HTTPS repository URLs:

```text
https://github.com/user/repository
https://github.com/user/repository/
https://github.com/user/repository.git
```

Other hosts, `http://` URLs, query strings, fragments, credentials, and extra path segments are rejected. Private repositories and authentication are not supported.

ZIP upload is the secondary source: `POST /api/v1/projects/uploads` with multipart fields `name` and `file`.

Example create request:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/projects \
  -H 'Content-Type: application/json' \
  -d '{"name":"Hello","repository_url":"https://github.com/octocat/Hello-World"}'
```

Example ingest response after a successful run:

```json
{
  "id": 1,
  "name": "Hello",
  "repository_url": "https://github.com/octocat/Hello-World",
  "source_type": "github",
  "status": "ready",
  "manifest": {
    "file_count": 1,
    "total_size": 12,
    "languages": { "Python": 1 },
    "files": [
      {
        "relative_path": "src/main.py",
        "filename": "main.py",
        "extension": ".py",
        "detected_language": "Python",
        "file_size": 12,
        "line_count": 1,
        "sha256": "…",
        "category": "source"
      }
    ]
  }
}
```

Each file record uses `relative_path`, `filename`, `extension`, `detected_language`, `file_size`, `line_count`, `sha256`, and `category`. Categories come from filename and extension heuristics: source, configuration, dependency, certificate, documentation, binary, or unknown.

Repositories are analyzed as untrusted data. CryptoNex does not execute repository code, install dependencies, run build scripts, or fetch Git submodules. Git is invoked with a fixed argument list and `shell` is never enabled. The user-supplied URL is parsed and replaced with a canonical `https://github.com/{owner}/{name}.git` value before clone. ZIP entry paths are normalized and must stay inside the server workspace. Failed ingestions delete that workspace. API responses do not include server filesystem paths, git output, secrets, or stack traces.

## Deterministic Cryptographic Detection

`POST /api/v1/projects/{id}/scan` requires a project whose ingestion status is `ready`. The scanner reads the stored manifest, analyzes eligible files in the workspace, and persists a scan plus cryptographic findings. The response is a summary:

```json
{
  "scan_id": 1,
  "project_id": 1,
  "status": "completed",
  "summary": {
    "files_scanned": 3,
    "files_skipped": 1,
    "skip_reasons": { "documentation": 1 },
    "findings": 2,
    "high_confidence": 1,
    "medium_confidence": 0,
    "low_confidence": 1,
    "algorithms": { "RSA": 1 },
    "confirmed_findings": 1,
    "probable_findings": 0,
    "weak_signal_findings": 1,
    "dependencies": 2,
    "crypto_dependencies": 1,
    "malformed_manifests": 0
  }
}
```

`files_skipped` and `skip_reasons` record why a manifest entry was not treated as source. Dependency-only findings are included in `findings` and confidence counts. They are omitted from `algorithms` because a package name is not an algorithm. Additional summary fields count finding statuses and the dependency inventory. Existing Phase 2 fields keep their meaning.

### Languages

Python, Java, JavaScript, TypeScript, Go, C, and C++. Python uses `ast.parse` on source text. The other languages use language-aware patterns on comment-masked source. The parser never executes AST nodes.

### Algorithms

Asymmetric: RSA, DSA, ECDSA, ECDH, Diffie-Hellman, Ed25519, Ed448.

Symmetric: AES, DES, 3DES, Blowfish, ChaCha20, ChaCha20-Poly1305.

Hash: MD5, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-3, BLAKE2, BLAKE3.

MAC: HMAC, CMAC, Poly1305.

Key derivation: PBKDF2, scrypt, Argon2, HKDF.

Canonical names, aliases, and families live in one algorithm registry. A finding leaves `key_size`, `mode`, `curve`, and `algorithm` null when the source does not state them.

### Libraries

Python `cryptography` and PyCryptodome; Java `javax.crypto`, `java.security`, and Bouncy Castle; Web Crypto and Node.js `crypto`; Go `crypto/rsa`, `crypto/aes`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/sha256`, and `crypto/hmac`; OpenSSL EVP, RSA, and EC calls. A library is recorded only when an import, API call, or dependency declaration supports it.

### Dependency manifests

`requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `go.sum`, `Cargo.toml`, and `Cargo.lock`.

A known cryptographic dependency produces a finding with `usage` `dependency_only`, `detection_method` `dependency_detection`, `confidence` `low`, and `algorithm` null. Dependency presence does not prove active cryptographic usage.

### Evidence and confidence

Each finding stores a relative file path, line range, a bounded snippet, and a detection method: `import_detection`, `api_detection`, `ast_detection`, `pattern_detection`, `dependency_detection`, or `configuration_detection`. Confidence is `high`, `medium`, or `low`. High confidence requires a known library or API call plus an identifiable algorithm. Medium confidence is a strong pattern with incomplete context. Low confidence is a weak lexical or dependency indication.

Comments, documentation, README text, and names that merely contain an algorithm word are not confirmed usage. Documentation files are skipped and counted under `skip_reasons`.

### Limitations

This is deterministic static analysis of an initial set of APIs. It does not cover every cryptographic library or every call shape. Indirect or dynamically constructed parameters stay unknown. A scan does not score risk, recommend migrations, or decide quantum safety. CryptoNex does not execute repository code, install dependencies, run package managers, or evaluate repository expressions.

## Evidence, Confidence, and Cryptographic Context

Phase 3 classifies each Phase 2 finding with deterministic rules. There is no risk score, no model, and no external lookup.

### Evidence types

Phase 2 `detection_method` values map to:

| Detection method | Evidence type |
| --- | --- |
| `ast_detection`, `api_detection` | `confirmed_api_usage` |
| `import_detection` | `confirmed_import` |
| `configuration_detection` | `confirmed_configuration` |
| `dependency_detection` | `dependency_presence` |
| `pattern_detection` | `weak_textual_reference` |

Dependency presence stays `dependency_presence`. It is never upgraded to confirmed usage.

### Confidence and reasons

Confidence remains `high`, `medium`, or `low`.

- High: a recognized API call, a confirmed library, and an identified algorithm.
- Medium: a strong cryptographic signal with incomplete context, such as an import without a call or an API call whose library was not confirmed.
- Low: a dependency declaration, a weak textual signal, or unknown evidence.

Every finding stores machine-readable `confidence_reasons`, for example `recognized_crypto_api_call`, `recognized_crypto_library`, `algorithm_identified_from_api`, `explicit_key_size_detected`, `crypto_dependency_declared`, and `no_confirmed_source_api_usage`.

### Finding status

- `confirmed`: high-confidence source usage.
- `probable`: a strong indication with incomplete context.
- `weak_signal`: dependency or textual evidence without confirmed active usage.

### Usage, role, and parameters

Usage stays the Phase 2 classification. `Cipher.getInstance(...)` remains `algorithm_selection`. `EC_KEY_new_by_curve_name(...)` records a curve and leaves the algorithm unknown.

Cryptographic role is derived from usage, not from the algorithm name alone:

- encryption or decryption → `confidentiality`
- hashing → `integrity`
- MAC → `authentication`
- signing or verification → `digital_signature`
- key agreement → `key_establishment`
- password-based KDF (`PBKDF2`, `scrypt`, `Argon2`) → `password_protection`
- otherwise → `unknown`

Parameter completeness is `complete`, `partial`, or `unknown` from the parameters already extracted. RSA with `key_size=2048` is complete. AES-GCM without a key size is partial. Missing values stay null.

### Security concern and quantum relevance

These fields classify the primitive, not the application.

Security concern examples: `legacy_hash` (MD5, SHA-1), `legacy_cipher` (DES, 3DES), `classical_public_key` (RSA), `classical_signature` (DSA, ECDSA, Ed25519), `classical_key_exchange` (ECDH, Diffie-Hellman), `symmetric_cryptography` (AES, ChaCha20), `modern_hash` (SHA-256), `key_derivation`, `mac`.

Quantum relevance examples: `classical_public_key`, `classical_signature`, `classical_key_establishment`, `symmetric`, `hash`, `mac`, `key_derivation`.

CryptoNex does not store `quantum_safe` or `quantum_vulnerable`, and it does not determine that an entire application is quantum-safe or quantum-vulnerable from these findings.

Evidence snippets remain bounded by `EVIDENCE_MAX_CHARS`. Values that look like private keys, tokens, passwords, or URL credentials are redacted before storage.

## Dependency Intelligence

Phase 4 parses the same dependency manifests as Phase 2 and stores a normalized inventory. The Phase 2 dependency detector now emits findings from that inventory instead of parsing the same files a second time.

### Ecosystems

- Python: `requirements.txt`, `pyproject.toml`, `Pipfile`, `poetry.lock`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- JavaScript/TypeScript: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`

Coverage is representative, not complete.

### Versions

An exact pin such as `cryptography==42.0.5` stores `version` `42.0.5` and leaves `version_constraint` null. A range such as `cryptography>=42,<44` stores the constraint and leaves `version` null. CryptoNex does not resolve a constraint to an installed version and does not query package registries.

### Direct versus transitive

A declaration file records `direct` when the manifest says so. A lockfile entry is `direct` when a sibling declaration file lists the same package, `transitive` when that sibling is present and does not list it, and `unknown` when the sibling is missing or the lockfile does not support the distinction. CryptoNex does not guess.

### Crypto-library registry

Packages are classified only from a maintained registry: `cryptographic_library`, `crypto_related`, `non_crypto`, or `unknown`. A name that contains `crypto`, `security`, `secure`, or `auth` is not enough. Node's built-in `crypto` module remains a platform API; the npm package named `crypto` is recorded as `unknown`.

### Finding-to-dependency relationships

A source finding links to a declared package only when the registry says that package supplies the detected library, the ecosystems match, and the manifest directory contains the source file. The stored relationship types are:

- `finding_uses_dependency`: confirmed source usage of a declared library
- `dependency_only`: the weak-signal finding created from the declaration
- `transitive_dependency`: a lockfile parent-to-child edge

A Dependency row is the declared dependency. `crypto_relevance` plus `library` is the detected cryptographic library. Those facts are not duplicated as extra relationship rows.

`cryptography==42.0.5` in `requirements.txt` means the package is declared. It does not mean RSA is used. Algorithm usage still requires source evidence, and dependency-only findings keep `algorithm` null.

### Static-only analysis

Dependency analysis reads manifest text. It does not run `pip`, `npm`, Maven, Gradle, `go get`, or Cargo, and it does not consult CVE, NVD, OSV, or GitHub Advisory databases.

## Security Baseline

- Repository contents are untrusted. The scanner reads and parses text. It does not execute repository code, import repository modules, or run commands derived from repository content.
- Request bodies are validated with Pydantic where a route accepts JSON input.
- ZIP uploads are read with a size cap and are not executed.
- Error responses use one JSON envelope and do not include stack traces or exception text.
- Logs record project id, source type, and exception type. They do not record database URLs, tokens, request bodies, or workspace paths.
- CORS is an explicit allowlist. Production configuration rejects unrestricted origins.
