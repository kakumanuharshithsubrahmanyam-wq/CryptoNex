"""Rust source API detection and false-positive guards.

Fixtures are local and synthetic. External repositories are not cloned.
"""

from pathlib import Path

from app.core.config import Settings
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest

RUST_USAGE = """
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use blake2::Blake2b512;
use blake3::Hasher;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use pbkdf2::Pbkdf2;
use argon2::Argon2;
use scrypt::Scrypt;
use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use ed25519_dalek::SigningKey;
use ecdsa::SigningKey as EcdsaKey;
use rsa::RsaPrivateKey;
use x25519_dalek::{StaticSecret, PublicKey};
use ml_kem::MlKem768;
use xwing::XWingKem;
use hpke::Hpke;

fn demo(data: &[u8], key: &[u8]) {
    let _ = Sha256::digest(data);
    let _ = Sha256::new();
    let _ = Sha3_256::digest(data);
    let _ = Blake2b512::digest(data);
    let _ = Hasher::new();
    let _ = Hmac::<Sha256>::new_from_slice(key);
    let _ = Hkdf::<Sha256>::new(None, key);
    let _ = Pbkdf2::new();
    let _ = Argon2::new();
    let _ = Scrypt::new();
    let _ = Aes256Gcm::new();
    let _ = ChaCha20Poly1305::new();
    let _ = XChaCha20Poly1305::new();
    let _ = SigningKey::generate();
    let _ = RsaPrivateKey::new();
    let _ = StaticSecret::diffie_hellman();
    let _ = X25519::diffie_hellman();
    let _ = MlKem768::encapsulate();
    let _ = XWingKem::encapsulate();
    let _ = Hpke::setup_sender();
}
"""

COMMENTS_ONLY = """
// Sha256::digest(data) must not be detected from a comment.
/// ChaCha20Poly1305::new() in docs is not usage.
/* Argon2::new() still a comment. */
let sha256 = 1;
fn sha256() {}
"""


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _scan(tmp_path: Path, files: dict[str, str]):
    root = tmp_path / "source"
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    settings = _settings(tmp_path)
    return scan_manifest(root, build_manifest(root, settings), settings)


def _one(run, **expected):
    matches = [
        finding
        for finding in run.findings
        if all(getattr(finding, field) == value for field, value in expected.items())
    ]
    assert matches, [(item.algorithm, item.library, item.usage, item.file_path, item.detection_method) for item in run.findings]
    return matches[0]


def test_rust_api_usage_is_detected(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"src/lib.rs": RUST_USAGE})
    sha = _one(run, algorithm="SHA-256", usage="hashing", detection_method="api_detection")
    assert sha.language == "Rust"
    assert sha.library_resolved is True
    _one(run, algorithm="SHA-3", usage="hashing")
    _one(run, algorithm="BLAKE2", usage="hashing")
    _one(run, algorithm="HMAC", usage="mac")
    _one(run, algorithm="HKDF", usage="key_derivation")
    _one(run, algorithm="PBKDF2", usage="key_derivation")
    _one(run, algorithm="Argon2", usage="key_derivation")
    _one(run, algorithm="scrypt", usage="key_derivation")
    aes = _one(run, algorithm="AES", usage="encryption")
    assert aes.key_size == 256
    assert aes.mode == "GCM"
    _one(run, algorithm="ChaCha20-Poly1305")
    _one(run, algorithm="XChaCha20-Poly1305")
    _one(run, algorithm="Ed25519")
    _one(run, algorithm="RSA")
    _one(run, algorithm="X25519", usage="key_agreement")
    _one(run, algorithm="ML-KEM", usage="key_agreement")
    _one(run, algorithm="X-Wing", usage="key_agreement")
    _one(run, algorithm="HPKE")


def test_rust_comments_docs_and_names_are_not_confirmed(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "src/notes.rs": COMMENTS_ONLY,
            "README.md": "Call Sha256::digest and ChaCha20Poly1305::new in production.\n",
            "docs/guide.md": "Argon2id and ML-KEM examples.\n",
        },
    )
    assert not any(item.detection_method == "api_detection" for item in run.findings)
    assert all(item.algorithm is None or item.usage == "dependency_only" for item in run.findings)
    assert run.skip_reasons.get("documentation", 0) >= 2


def test_rust_dependency_only_is_not_an_algorithm(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "Cargo.toml": '[dependencies]\nsha2 = "0.10"\nchacha20poly1305 = "0.10"\nargon2 = "0.5"\n',
            "src/main.rs": "fn main() { let unused = 1; }\n",
        },
    )
    deps = [item for item in run.findings if item.detection_method == "dependency_detection"]
    assert deps
    assert all(item.algorithm is None for item in deps)
    assert all(item.usage == "dependency_only" for item in deps)
    assert all(item.confidence == "low" for item in deps)
    assert not any(item.detection_method == "api_detection" for item in run.findings)


def test_rust_unrelated_identifiers_are_ignored(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"src/app.rs": "fn digest() {}\nstruct New;\nlet hmac = 3;\n"})
    assert run.findings == []
