"""C/C++ OpenSSL and Botan detection, including false-positive guards."""

from pathlib import Path

from app.core.config import Settings
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest

BOTAN_USAGE = """
#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/hash.h>
#include <botan/kdf.h>
#include <botan/mac.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>

void demo() {
   Botan::AutoSeeded_RNG rng;
   Botan::RSA_PrivateKey rsa(rng, 2048);
   const auto group = Botan::EC_Group::from_name("secp256r1");
   Botan::ECDSA_PrivateKey ecdsa(rng, group);
   Botan::ECDH_PrivateKey ecdh(rng, group);
   Botan::Ed25519_PrivateKey ed(rng);
   Botan::PK_Signer signer(rsa, rng, Botan::PK_Signature_Options().with_hash("SHA-256"));
   Botan::PK_Verifier verifier(rsa, Botan::PK_Signature_Options().with_hash("SHA-256"));
   const auto hash = Botan::HashFunction::create_or_throw("SHA-256");
   const auto sha3 = Botan::HashFunction::create_or_throw("SHA-3");
   const auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
   const auto cmac = Botan::MessageAuthenticationCode::create_or_throw("CMAC(AES-128)");
   const auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
   const auto cipher = Botan::BlockCipher::create_or_throw("AES-256");
   const auto chacha = Botan::StreamCipher::create_or_throw("ChaCha(20)");
   const auto aead = Botan::AEAD_Mode::create_or_throw("ChaCha20Poly1305");
   Botan::PK_Key_Agreement ka(ecdh, rng, Botan::PK_Key_Agreement_Options());
}
"""

OPENSSL_USAGE = """
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
void demo(EVP_CIPHER_CTX *ctx, unsigned char *key, unsigned char *iv) {
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, iv);
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    RSA_sign(NID_sha256, m, mlen, sig, &siglen, rsa);
    RSA_verify(NID_sha256, m, mlen, sig, siglen, rsa);
    RSA_public_encrypt(flen, from, to, rsa, RSA_PKCS1_PADDING);
    RSA_private_decrypt(flen, from, to, rsa, RSA_PKCS1_PADDING);
    ECDSA_sign(0, dgst, dgstlen, sig, &siglen, eckey);
    ECDSA_verify(0, dgst, dgstlen, sig, siglen, eckey);
    ECDH_compute_key(out, outlen, pub, eckey, NULL);
    DH_compute_key(out, pub, dh);
    HMAC_Init_ex(ctx, key, len, EVP_sha256(), NULL);
    PKCS5_PBKDF2_HMAC(pass, plen, salt, slen, iter, EVP_sha256(), dklen, out);
    EVP_PBE_scrypt(pass, plen, salt, slen, n, r, p, maxmem, out, outlen);
    EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, NULL, key, 57);
}
"""

INCLUDE_ONLY = """
#include <botan/rsa.h>
#include <openssl/evp.h>
int rsa_token = 1;
"""

CAPABILITY_ONLY = """
#if defined(BOTAN_HAS_RSA)
#if defined(BOTAN_HAS_AES)
void unused() {}
#endif
#endif
"""

COMMENTS_ONLY = """
// RSA is an asymmetric algorithm.
/* AES-256-GCM should not be detected from a comment. */
int rsa_token = 1;
int ecdsa_label = 2;
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
    assert matches, [(item.algorithm, item.library, item.usage, item.file_path) for item in run.findings]
    return matches[0]


def test_botan_apis_includes_and_usage(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"src/demo.cpp": BOTAN_USAGE})
    botan_import = _one(run, library="Botan", detection_method="import_detection")
    assert botan_import.algorithm is None
    assert botan_import.usage == "unknown"
    rsa = _one(run, algorithm="RSA", library="Botan", usage="key_generation")
    assert rsa.key_size == 2048
    assert rsa.detection_method == "api_detection"
    _one(run, algorithm="ECDSA", library="Botan")
    _one(run, algorithm="ECDH", library="Botan", usage="key_agreement")
    _one(run, algorithm="Ed25519", library="Botan")
    _one(run, usage="signing", library="Botan", detection_method="api_detection")
    _one(run, usage="signature_verification", library="Botan")
    _one(run, algorithm="SHA-256", library="Botan", usage="hashing")
    _one(run, algorithm="SHA-3", library="Botan", usage="hashing")
    hmac = _one(run, algorithm="HMAC", library="Botan", usage="mac")
    assert hmac.metadata.get("hash") == "SHA-256"
    _one(run, algorithm="CMAC", library="Botan", usage="mac")
    _one(run, algorithm="HKDF", library="Botan", usage="key_derivation")
    aes = _one(run, algorithm="AES", library="Botan", key_size=256)
    assert aes.usage in {"algorithm_selection", "unknown"}
    _one(run, algorithm="ChaCha20", library="Botan")
    _one(run, algorithm="ChaCha20-Poly1305", library="Botan")
    curve = _one(run, library="Botan", curve="secp256r1")
    assert curve.algorithm is None


def test_openssl_extended_apis(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"native/more.c": OPENSSL_USAGE})
    _one(run, algorithm="AES", library="OpenSSL", usage="encryption", key_size=256, mode="GCM")
    _one(run, algorithm="3DES", library="OpenSSL", usage="decryption")
    _one(run, algorithm="ChaCha20-Poly1305", library="OpenSSL", usage="encryption")
    _one(run, algorithm="SHA-384", library="OpenSSL", usage="hashing")
    _one(run, algorithm="RSA", library="OpenSSL", usage="signing")
    _one(run, algorithm="RSA", library="OpenSSL", usage="signature_verification")
    _one(run, algorithm="RSA", library="OpenSSL", usage="encryption")
    _one(run, algorithm="RSA", library="OpenSSL", usage="decryption")
    _one(run, algorithm="ECDSA", library="OpenSSL", usage="signing")
    _one(run, algorithm="ECDSA", library="OpenSSL", usage="signature_verification")
    _one(run, algorithm="ECDH", library="OpenSSL", usage="key_agreement")
    _one(run, algorithm="Diffie-Hellman", library="OpenSSL", usage="key_agreement")
    _one(run, algorithm="HMAC", library="OpenSSL", usage="mac")
    _one(run, algorithm="PBKDF2", library="OpenSSL", usage="key_derivation")
    _one(run, algorithm="scrypt", library="OpenSSL", usage="key_derivation")
    _one(run, algorithm="HKDF", library="OpenSSL", usage="key_derivation")
    _one(run, algorithm="Ed25519", library="OpenSSL")
    _one(run, algorithm="Ed448", library="OpenSSL")
    include = _one(run, library="OpenSSL", detection_method="import_detection")
    assert include.algorithm is None


def test_include_alone_is_not_algorithm_usage(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"src/headers.cpp": INCLUDE_ONLY})
    assert {item.library for item in run.findings} == {"Botan", "OpenSSL"}
    assert all(item.algorithm is None for item in run.findings)
    assert all(item.detection_method == "import_detection" for item in run.findings)


def test_cpp_false_positives_are_not_confirmed_usage(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "src/notes.cpp": COMMENTS_ONLY,
            "README.md": "Our product uses AES and RSA.\n",
            "docs/guide.md": "Call ECDSA and Botan::RSA_PrivateKey in production.\n",
            "src/capability.cpp": CAPABILITY_ONLY,
            "CMakeLists.txt": "find_package(OpenSSL 3.0 REQUIRED)\n",
        },
    )
    assert all(item.algorithm is None for item in run.findings)
    assert all(item.usage in {"unknown", "dependency_only"} for item in run.findings)
    assert not any(item.detection_method == "api_detection" for item in run.findings)
    assert run.skip_reasons.get("documentation", 0) >= 2


def test_botan_hmac_constructor_is_not_openssl(tmp_path: Path) -> None:
    source = """
#include <botan/mac.h>
HMAC() : Command("hmac --hash=SHA-256") {}
auto hmac = HMAC(m_hash->new_object());
HMAC::HMAC(std::unique_ptr<HashFunction> hash) {}
"""
    run = _scan(tmp_path, {"src/lib/mac/hmac.cpp": source})
    assert not any(item.library == "OpenSSL" for item in run.findings)


def test_botan_pqc_tls_and_x509_patterns(tmp_path: Path) -> None:
    source = """
#include <botan/tls_client.h>
#include <botan/x509cert.h>
#include <botan/ml_kem.h>
void demo(Botan::RandomNumberGenerator& rng) {
   Botan::X25519_PrivateKey x25519(rng);
   Botan::ML_KEM_PrivateKey mlkem(rng, Botan::ML_KEM_Mode::ML_KEM_768);
   Botan::ML_DSA_PrivateKey mldsa(rng);
   Botan::SLH_DSA_PrivateKey slh(rng);
   Botan::SHA_1 sha1;
   Botan::TLS::Client client;
   Botan::TLS::Protocol_Version::TLS_V13 version;
   Botan::X509_Certificate cert;
   auto gcm = Botan::AEAD_Mode::create_or_throw("AES-256/GCM");
   auto kem = Botan::PK_Key_Agreement::create("ML-KEM");
}
"""
    run = _scan(tmp_path, {"src/pqc.cpp": source})
    _one(run, algorithm="X25519", library="Botan", usage="key_agreement")
    _one(run, algorithm="ML-KEM", library="Botan")
    _one(run, algorithm="ML-DSA", library="Botan")
    _one(run, algorithm="SLH-DSA", library="Botan")
    _one(run, algorithm="SHA-1", library="Botan", usage="hashing")
    _one(run, algorithm="AES", library="Botan", key_size=256, mode="GCM")
    assert any(item.metadata.get("api") == "tls" or item.metadata.get("tls_version") for item in run.findings)
    assert any(item.metadata.get("api") == "x509" for item in run.findings)


def test_cli_hmac_command_class_is_not_botan_hmac(tmp_path: Path) -> None:
    source = """
#include <botan/mac.h>
namespace Botan_CLI {
class HMAC final : public Command {
   void go() {}
};
}
"""
    run = _scan(tmp_path, {"src/cli/hmac.cpp": source})
    assert not any(item.algorithm == "HMAC" for item in run.findings)
    _one(run, library="Botan", detection_method="import_detection")
