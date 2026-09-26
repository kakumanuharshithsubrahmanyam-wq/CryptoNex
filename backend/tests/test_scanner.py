"""Deterministic cryptographic detection."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.models.scan import CryptoFinding
from app.schemas.project import RepositoryManifest
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import dedupe, scan_manifest
from app.services.scanner.findings import RawFinding

PYTHON_RSA = """
from cryptography.hazmat.primitives.asymmetric import rsa

rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)
"""

PYTHON_RSA_4096 = """
from Crypto.PublicKey import RSA
RSA.generate(4096)
"""

PYTHON_AES = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
Cipher(algorithms.AES(b"0123456789abcdef"), modes.GCM(b"123456789012")).encryptor()
"""

PYTHON_HASHES = """
import hashlib
hashlib.sha256()
hashlib.sha1()
hashlib.md5()
"""

PYTHON_EC = """
from cryptography.hazmat.primitives.asymmetric import ec
ec.generate_private_key(ec.SECP256R1())
ec.ECDSA(None)
ec.ECDH()
"""

PYTHON_HMAC_KDF = """
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
hmac.HMAC(b"key", hashes.SHA256())
PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=b"salt", iterations=1000)
HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"")
"""

PYTHON_CHACHA = """
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
ChaCha20Poly1305(b"0123456789abcdef0123456789abcdef")
"""

JAVA_SAMPLE = """
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.Mac;
import javax.crypto.KeyAgreement;
class CryptoDemo {
    void run() {
        Cipher.getInstance("AES/GCM/NoPadding");
        KeyPairGenerator.getInstance("RSA");
        Signature.getInstance("SHA256withRSA");
        Mac.getInstance("HmacSHA256");
        MessageDigest.getInstance("SHA-256");
        KeyAgreement.getInstance("ECDH");
    }
}
"""

JS_SAMPLE = """
const crypto = require("crypto");
crypto.subtle.encrypt({ name: "AES-GCM" }, key, data);
crypto.subtle.decrypt({ name: "AES-GCM" }, key, data);
crypto.subtle.sign({ name: "ECDSA" }, key, data);
crypto.subtle.verify({ name: "ECDSA" }, key, signature, data);
crypto.subtle.digest("SHA-256", data);
crypto.createCipheriv("aes-256-gcm", key, iv);
crypto.createDecipheriv("aes-128-gcm", key, iv);
crypto.createHmac("sha256", key);
crypto.pbkdf2Sync(password, salt, 1000, 32, "sha256");
"""

GO_SAMPLE = """
package main
import (
    "crypto/rsa"
    "crypto/aes"
    "crypto/ecdsa"
    "crypto/sha256"
    "crypto/hmac"
)
func demo() {
    rsa.GenerateKey(nil, 2048)
    aes.NewCipher(key)
    ecdsa.GenerateKey(curve, rand)
    sha256.New()
    hmac.New(sha256.New, key)
}
"""

C_SAMPLE = """
#include <openssl/evp.h>
void demo(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}
"""

FALSE_POSITIVE = """
# RSA is an asymmetric algorithm.
# rsa.generate_private_key(key_size=2048)
rsa_token = "user-rsa"
note = "Our old system used AES."
def unrelated():
    return rsa_token
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
    manifest = build_manifest(root, settings)
    return scan_manifest(root, manifest, settings)


def _one(run, **expected):
    matches = [
        finding
        for finding in run.findings
        if all(getattr(finding, field) == value for field, value in expected.items())
    ]
    assert matches, [(item.algorithm, item.library, item.usage, item.file_path, item.line_start) for item in run.findings]
    return matches[0]


def test_python_rsa_parameters_and_evidence(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"src/auth.py": PYTHON_RSA})
    finding = _one(run, algorithm="RSA", library="cryptography", usage="key_generation", key_size=2048)
    assert finding.file_path == "src/auth.py"
    assert finding.line_start >= 3
    assert finding.line_end >= finding.line_start
    assert "generate_private_key" in finding.evidence
    assert "2048" in finding.evidence
    assert len(finding.evidence) <= 240
    assert finding.detection_method == "ast_detection"
    assert finding.confidence == "high"
    assert finding.algorithm_family == "asymmetric"


def test_pycryptodome_rsa_4096(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"rsa_demo.py": PYTHON_RSA_4096})
    finding = _one(run, algorithm="RSA", library="PyCryptodome", key_size=4096, usage="key_generation")
    assert finding.confidence == "high"


def test_algorithm_and_library_coverage(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "py/aes.py": PYTHON_AES,
            "py/hashes.py": PYTHON_HASHES,
            "py/ec.py": PYTHON_EC,
            "py/kdf.py": PYTHON_HMAC_KDF,
            "py/chacha.py": PYTHON_CHACHA,
            "java/Demo.java": JAVA_SAMPLE,
            "web/crypto.js": JS_SAMPLE,
            "go/main.go": GO_SAMPLE,
            "native/openssl.c": C_SAMPLE,
        },
    )
    _one(run, algorithm="AES", mode="GCM", usage="encryption", library="cryptography")
    _one(run, algorithm="SHA-256", library="hashlib", usage="hashing")
    _one(run, algorithm="SHA-1", library="hashlib")
    _one(run, algorithm="MD5", library="hashlib")
    _one(run, algorithm="ECDSA", library="cryptography")
    _one(run, algorithm="ECDH", library="cryptography", usage="key_agreement")
    curve = _one(run, curve="secp256r1", usage="key_generation", library="cryptography")
    assert curve.algorithm is None
    _one(run, algorithm="HMAC", library="cryptography", usage="mac")
    _one(run, algorithm="PBKDF2", usage="key_derivation")
    _one(run, algorithm="HKDF", usage="key_derivation")
    _one(run, algorithm="ChaCha20-Poly1305", library="cryptography")
    _one(run, algorithm="AES", mode="GCM", library="javax.crypto")
    signature = _one(
        run,
        algorithm="RSA",
        library="java.security",
        file_path="java/Demo.java",
        usage="algorithm_selection",
    )
    assert signature.metadata.get("hash") == "SHA-256"
    _one(run, algorithm="SHA-256", library="java.security", usage="hashing")
    _one(run, algorithm="HMAC", library="javax.crypto")
    _one(run, algorithm="ECDH", library="javax.crypto", usage="key_agreement")
    _one(run, algorithm="AES", mode="GCM", library="Web Crypto", usage="encryption")
    _one(run, algorithm="AES", usage="decryption", library="Web Crypto")
    _one(run, algorithm="ECDSA", library="Web Crypto", usage="signing")
    _one(run, algorithm="ECDSA", library="Web Crypto", usage="signature_verification")
    node_aes = _one(run, algorithm="AES", library="node:crypto", key_size=256)
    assert node_aes.mode == "GCM"
    _one(run, algorithm="AES", library="node:crypto", key_size=128, usage="decryption")
    _one(run, algorithm="HMAC", library="node:crypto", usage="mac")
    _one(run, algorithm="PBKDF2", library="node:crypto", usage="key_derivation")
    _one(run, algorithm="RSA", library="crypto/rsa", usage="key_generation", confidence="high")
    _one(run, algorithm="AES", library="crypto/aes")
    _one(run, algorithm="ECDSA", library="crypto/ecdsa", usage="key_generation")
    _one(run, algorithm="SHA-256", library="crypto/sha256", usage="hashing")
    _one(run, algorithm="HMAC", library="crypto/hmac", usage="mac")
    _one(run, algorithm="AES", library="OpenSSL", key_size=256, usage="encryption", mode="GCM")
    _one(run, algorithm="AES", library="OpenSSL", key_size=128, usage="decryption")
    _one(run, algorithm="SHA-256", library="OpenSSL", usage="hashing")
    _one(run, algorithm="RSA", library="OpenSSL", key_size=2048, usage="key_generation")
    openssl_curve = _one(run, library="OpenSSL", curve="secp256r1")
    assert openssl_curve.algorithm is None


def test_comments_readme_and_names_are_not_usage(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "src/notes.py": FALSE_POSITIVE,
            "README.md": "Our old system used AES.\nRSA is mentioned here.\n",
            "docs/guide.md": "Call rsa.generate_private_key when rotating keys.\n",
        },
    )
    assert run.findings == []
    assert run.files_scanned == 1
    assert run.skip_reasons.get("documentation", 0) >= 2


def test_dependency_is_not_algorithm_usage(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "requirements.txt": "cryptography==42.0.5\nrequests==2.32.0\n",
            "package.json": '{"dependencies": {"crypto-js": "^4.2.0"}}\n',
            "pom.xml": """
                <dependency>
                  <groupId>org.bouncycastle</groupId>
                  <artifactId>bcprov-jdk18on</artifactId>
                  <version>1.78</version>
                </dependency>
            """,
            "go.mod": "module example.com/demo\nrequire golang.org/x/crypto v0.28.0\n",
        },
    )
    assert run.findings
    assert all(finding.algorithm is None for finding in run.findings)
    assert all(finding.usage == "dependency_only" for finding in run.findings)
    assert all(finding.confidence == "low" for finding in run.findings)
    assert all(finding.detection_method == "dependency_detection" for finding in run.findings)
    crypto_dep = _one(run, library="cryptography", library_version="42.0.5")
    assert "cryptography==42.0.5" in crypto_dep.evidence
    _one(run, library="crypto-js")
    _one(run, library="Bouncy Castle", library_version="1.78")
    _one(run, library="golang.org/x/crypto", library_version="v0.28.0")
    assert run.findings and all(item.algorithm is None for item in run.findings)


def test_duplicate_api_call_is_collapsed() -> None:
    finding = RawFinding(
        file_path="a.py",
        line_start=4,
        line_end=4,
        language="Python",
        algorithm="AES",
        algorithm_family="symmetric",
        library="cryptography",
        library_version=None,
        usage="algorithm_selection",
        key_size=None,
        curve=None,
        mode="GCM",
        evidence="Cipher(...)",
        detection_method="ast_detection",
        confidence="high",
    )
    stronger = RawFinding(
        file_path="a.py",
        line_start=4,
        line_end=4,
        language="Python",
        algorithm="AES",
        algorithm_family="symmetric",
        library="cryptography",
        library_version=None,
        usage="encryption",
        key_size=None,
        curve=None,
        mode="GCM",
        evidence="encryptor()",
        detection_method="ast_detection",
        confidence="high",
    )
    deduped = dedupe([finding, stronger, stronger])
    assert len(deduped) == 1
    assert deduped[0].usage == "encryption"


def test_scanner_does_not_execute_repository_code(tmp_path: Path) -> None:
    marker = tmp_path / "should-not-exist"
    source = (
        "import os\n"
        f"os.system('touch {marker}')\n"
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "rsa.generate_private_key(public_exponent=65537, key_size=2048)\n"
    )
    run = _scan(tmp_path, {"src/unsafe.py": source})
    assert not marker.exists()
    _one(run, algorithm="RSA", usage="key_generation")


def test_empty_manifest_completes_without_findings(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    manifest = RepositoryManifest(file_count=0, total_size=0, languages={}, files=[])
    run = scan_manifest(root, manifest, _settings(tmp_path))
    assert run.files_scanned == 0
    assert run.findings == []


def test_scan_api_requires_ingestion_and_returns_summary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        destination.mkdir(parents=True)
        (destination / "src").mkdir()
        (destination / "src" / "auth.py").write_text(PYTHON_RSA, encoding="utf-8")
        (destination / "README.md").write_text("AES is mentioned.\n", encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        missing = client.post("/api/v1/projects/999/scan")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "PROJECT_NOT_FOUND"

        created = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        not_ready = client.post(f"/api/v1/projects/{project_id}/scan")
        assert not_ready.status_code == 409
        assert not_ready.json()["error"]["code"] == "PROJECT_NOT_INGESTED"

        ingested = client.post(f"/api/v1/projects/{project_id}/ingest")
        assert ingested.status_code == 200
        scanned = client.post(f"/api/v1/projects/{project_id}/scan")
        assert scanned.status_code == 200
        body = scanned.json()
        assert body["status"] == "completed"
        assert body["project_id"] == project_id
        assert body["summary"]["findings"] >= 1
        assert body["summary"]["algorithms"]["RSA"] == 1
        assert body["summary"]["high_confidence"] >= 1
        assert str(tmp_path) not in scanned.text
        assert "Traceback" not in scanned.text
        stored = client.app.state.session_factory()
        try:
            row = stored.query(CryptoFinding).filter_by(scan_id=body["scan_id"]).one()
            assert row.file_path == "src/auth.py"
            assert row.evidence
            assert row.key_size == 2048
        finally:
            stored.close()


def test_scan_failure_uses_error_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        Path(args[-1]).mkdir(parents=True)
        (Path(args[-1]) / "app.py").write_text("x = 1\n", encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    monkeypatch.setattr(
        "app.services.scanner.service.scan_manifest",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret path /tmp/hidden")),
    )
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
        failed = client.post(f"/api/v1/projects/{project_id}/scan")
        assert failed.status_code == 500
        assert failed.json()["error"]["code"] == "SCAN_FAILED"
        assert "secret path" not in failed.text
        assert "Traceback" not in failed.text
