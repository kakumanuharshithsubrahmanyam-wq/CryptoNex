"""Certificate, TLS, SSH, and protocol artifact detection."""

import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.models.artifact import SecurityArtifact
from app.services.ingestion.manifest import build_manifest
from app.services.scanner.engine import scan_manifest

RSA_CERT = """-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIUCKLPzD8Sg88uAxCBY8HNCaxFNd4wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCVVMxFzAVBgNVBAoMDkNyeXB0b05leCBUZXN0MR0wGwYD
VQQDDBR0ZXN0LmNyeXB0b25leC5sb2NhbDAeFw0yNjA5MjYwNzE2MTVaFw0zNjA5
MjMwNzE2MTVaMEUxCzAJBgNVBAYTAlVTMRcwFQYDVQQKDA5DcnlwdG9OZXggVGVz
dDEdMBsGA1UEAwwUdGVzdC5jcnlwdG9uZXgubG9jYWwwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCqUugykv/6dFJydVzugbNUNy+/A1bLI8wa0Ef/E51b
ZwU2v1pS4hq0ZQur69H5hO/DIF4fL4/+nbaps4KiroqCZEBrBvXucIhUFH9IC5PN
ceNcQw9mWKos0XNqO0+kFwp5G8O6EPRmADlhQWC9m9gwx+ge3JrgtVaiisi1FCu9
gDaKEKi54mkOxg22OzdWU1iYQwgEpJkcHF4o2I9dbvkjvC1EqecTN4YIrYweBVC4
0lLzl+DEQFY2UH05YCzY7OKAhcIcYq5XvLk+dgQklxhYGqyVyRST69A3pngvg37i
3k0twk+WAkFu4PRzyqsAWVTLzJuOONuNsKMBZA6GUfnRAgMBAAGjgYYwgYMwHQYD
VR0OBBYEFAdexq2vZQ9bgMszyveDvSs6SFmjMB8GA1UdIwQYMBaAFAdexq2vZQ9b
gMszyveDvSs6SFmjMA8GA1UdEwEB/wQFMAMBAf8wMAYDVR0RBCkwJ4IUdGVzdC5j
cnlwdG9uZXgubG9jYWyCCWxvY2FsaG9zdIcEfwAAATANBgkqhkiG9w0BAQsFAAOC
AQEAnFoU0YBfgotRnRGKetmjKFAPMnBUbmWkiD8lh6tIf4a5+rXK+HqGGd+mX5mx
hwOcaE0vMHRFeZn7KmqgsL44Bt0dr45aHLfCl/zn5d1vzEGKeD1w4yvUnJmbt5WV
B0/dgQjIS1DfD8cyzNgC5+wLda400yWfPHOumauqYMt7/cUYB/JZmu1PLSJWaOXt
n+eEeI1wg+vyZS10iEEv8CjeH4HCRUhnPfi3ijQfPl4Xv6cBTMVjwdCWjMteG0dT
fKEU15h48pRo/hM6RMHQG7grechHgNvKQeE7PdGLRPr5+uo6V+nEWKb+25zYcEQE
ujcRo4D776k6dv42QJD9rt08hA==
-----END CERTIFICATE-----
"""

EC_CERT = """-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUWi72mcqvdIFvNwAUBLXB5GPVbAcwCgYIKoZIzj0EAwIw
HTEbMBkGA1UEAwwSZWMuY3J5cHRvbmV4LmxvY2FsMB4XDTI2MDkyNjA3MTYxNVoX
DTM2MDkyMzA3MTYxNVowHTEbMBkGA1UEAwwSZWMuY3J5cHRvbmV4LmxvY2FsMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJIsYeVl734XlNRxYLNHtJgDkzxnfmV9J
1jDSt0MVkVye7Z/pF+7LM23x3AbXPoocjNWSAqdQaax7qJg9bAny2qNTMFEwHQYD
VR0OBBYEFBPq4yyowRFauRl2MuBpfFjzqJM7MB8GA1UdIwQYMBaAFBPq4yyowRFa
uRl2MuBpfFjzqJM7MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIg
NKA4c55Lv/1PHNhqjqXCTJxLoC1T41K3OnyU2tCUpl0CIQDWw+xSsGFXWackghOP
O7D4WyCQaC7A4jjO4PU4TcWaCQ==
-----END CERTIFICATE-----
"""

EC_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIInC89bDlBjWK8loG3mhxASWpaXeoLQ2R+Bvxg/OmLjMoAoGCCqGSM49
AwEHoUQDQgAEJIsYeVl734XlNRxYLNHtJgDkzxnfmV9J1jDSt0MVkVye7Z/pF+7L
M23x3AbXPoocjNWSAqdQaax7qJg9bAny2g==
-----END EC PRIVATE KEY-----
"""

RSA_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCqUugykv/6dFJy
dVzugbNUNy+/A1bLI8wa0Ef/E51bZwU2v1pS4hq0ZQur69H5hO/DIF4fL4/+nbap
s4KiroqCZEBrBvXucIhUFH9IC5PNceNcQw9mWKos0XNqO0+kFwp5G8O6EPRmADlh
QWC9m9gwx+ge3JrgtVaiisi1FCu9gDaKEKi54mkOxg22OzdWU1iYQwgEpJkcHF4o
2I9dbvkjvC1EqecTN4YIrYweBVC40lLzl+DEQFY2UH05YCzY7OKAhcIcYq5XvLk+
dgQklxhYGqyVyRST69A3pngvg37i3k0twk+WAkFu4PRzyqsAWVTLzJuOONuNsKMB
ZA6GUfnRAgMBAAECggEAEPRDv/tsY5/klrDvP6Ar6G9XePbghhDZv+mJR4jKTYJ8
8GAuO4Xdc3Hp4YLBDTEAaAOQZ7l/GeQISyHFS5axzum8lJ35KQzzZRTNPq/evI3G
1gF1RpJlp74Jp3XT9AxSTI/ijpW73jnNFgAOAytaL8p8y2WmPRJcvb1KEUxUT+Tw
XV859JYwtpwx5ab8NQarkVjROYKOuPZQk7SDuoD+Al3Q0TmgQNVoZRbD7hbaVR5P
roG/s2n61H/Lft0tatqcb725wJARs06vLVCUjsqPRD3SyVRRhpOUUolGyf6VGiKA
kwgNmycUyHh5KCoVSoWv3u5eMotA7QGwFz0D0R4b6QKBgQDmPXVC57eBUNTUCWmk
HC8Q9+tpOc1i44cHFZA56Uinh5qPLCzux7I3YPjykbUa2tqrPryhn0rxqCfcwImM
A5VuQiiFnwtUnc0TqDsN8zJkOjMyNNwnSKhEhQg1LdWL2xvTdblsKCztb03aMuqO
/n6WJIY1op8sCApc9v3ZGw0KAwKBgQC9YVPEmxzuXbNcGrGDDxUL1hrFxT7VU9bo
hYdM5/LQHsx+gQ8UvEDOGBSv9ghFWGSvece2LNHMZxCQU1Pw3tJHRiS7VxxV77rW
2/sgqXI3X7Wxwkv8I7YlAR5DwdlvBeQ+MvKm/vSFMbVKCn/8zz2moPCWEuk+DhQD
q1vGpCBOmwKBgQCp/IIQzYd8YDNiATkPwwc03fXekKCE/Dt7DX6YYxYTKlkAj7r0
6Fc578ydOtqdYyvC9uTJ5xOr61zS7QwgZZzz9MB6NvxkksUQWEqReBaiTR3zWXeZ
QVmKjTWMHbTmNvUKYIZvxhG1k1HFYYYv4NGRBJJaEyC1n5IXJPwySHiOBQKBgGdg
vLiDL+zSy3kIvUPctNFsQ9sXzC/pf1QYp/4MU9jWJy0bSF86UGnwbUKMnIE2Omgr
oyBIIRJiZIFUa2r+R21O1fhKGhazMZveI5z1wnqFzYpGlPIDkIdsr9eu9wGLBsgJ
SbptTI90zhCn4KvheTb/fbV+h0Ivry89mHC74ULnAoGAKWQXVO53Dq+nMJeHQwrE
0r5JMe4WOBfxWL15sNRhXkztRkot/ZLlD9jkdRWep16IXtEDi7wXhGrEz+pmsKYL
bausQVs0Yr/WOQQREFm9u7CBGC+BYdGV2EPgzkqnrUVt7PCwl899jZ2GFM88FiCM
IJRYSOG0xndweZ8gKrnFTOI=
-----END PRIVATE KEY-----
"""

TLS_CONFIG = """
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_AES_128_GCM_SHA256;
ssl.client.auth=need
"""

JAVA_SSL = """
javax.net.ssl.keyStore=/opt/app/keystore.jks
javax.net.ssl.keyStoreType=JKS
javax.net.ssl.trustStore=/opt/app/truststore.jks
javax.net.ssl.trustStorePassword=changeit
"""

SSH_CONFIG = """
HostKeyAlgorithms ssh-rsa,ssh-ed25519
KexAlgorithms curve25519-sha256,diffie-hellman-group14-sha256
"""

SSH_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKeyMaterial comment\n"


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'cryptonex.db'}",
        environment="test",
        log_level="WARNING",
        workspace_root=str(tmp_path / "workspaces"),
        cors_origins="http://localhost:5173",
    )


def _scan(tmp_path: Path, files: dict[str, str | bytes]):
    root = tmp_path / "source"
    for relative, content in files.items():
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            destination.write_bytes(content)
        else:
            destination.write_text(content, encoding="utf-8")
    settings = _settings(tmp_path)
    return scan_manifest(root, build_manifest(root, settings), settings)


def _one(run, **expected):
    matches = [
        item
        for item in run.artifacts
        if all(getattr(item, field) == value for field, value in expected.items())
    ]
    assert matches, [(item.artifact_type, item.algorithm, item.protocol, item.file_path) for item in run.artifacts]
    return matches[0]


def test_pem_certificate_metadata(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"certs/server.crt": RSA_CERT})
    cert = _one(run, artifact_type="certificate", algorithm="RSA")
    assert cert.format == "PEM"
    assert cert.key_size == 2048
    assert cert.subject and "test.cryptonex.local" in cert.subject
    assert cert.issuer == cert.subject
    assert cert.serial_number
    assert cert.validity_start == "2026-09-26T07:16:15Z"
    assert cert.validity_end == "2036-09-23T07:16:15Z"
    assert "test.cryptonex.local" in cert.metadata.get("san", "")
    assert "BEGIN CERTIFICATE" in cert.evidence
    assert cert.confidence == "high"


def test_ec_certificate_curve(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"certs/ec.crt": EC_CERT})
    cert = _one(run, artifact_type="certificate", algorithm="EC")
    assert cert.curve == "secp256r1"
    assert cert.key_size is None


def test_rsa_and_ec_private_key_metadata_is_redacted(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"certs/rsa.key": RSA_KEY, "certs/ec.key": EC_KEY})
    rsa = _one(run, artifact_type="private_key", algorithm="RSA")
    assert rsa.key_size == 2048
    assert rsa.format == "PEM"
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj" not in rsa.evidence
    assert "[REDACTED PRIVATE KEY BLOCK]" in rsa.evidence
    ec = _one(run, artifact_type="private_key", algorithm="EC")
    assert ec.curve == "secp256r1"
    assert "MHcCAQEEIInC89bDlBjWK8loG3mhxASW" not in ec.evidence


def test_p12_and_jks_containers(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "store/app.p12": b"\x30\x82\x01\x00" + b"\x00" * 16,
            "store/truststore.jks": b"\xfe\xed\xfe\xed" + b"\x00" * 16,
        },
    )
    pkcs12 = _one(run, file_path="store/app.p12")
    assert pkcs12.format == "PKCS#12"
    assert pkcs12.artifact_type == "keystore"
    jks = _one(run, file_path="store/truststore.jks")
    assert jks.format == "JKS"
    assert jks.artifact_type == "truststore"


def test_tls_versions_cipher_suites_and_mtls(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"nginx.conf": TLS_CONFIG})
    versions = {item.metadata.get("tls_version") for item in run.artifacts if item.artifact_type == "protocol" and item.protocol == "TLS"}
    assert {"1.2", "1.3"} <= versions
    ecdhe = _one(run, cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert ecdhe.algorithm == "AES"
    assert ecdhe.key_size == 128
    assert ecdhe.metadata["key_exchange"] == "ECDH"
    assert ecdhe.metadata["authentication"] == "RSA"
    tls13 = _one(run, cipher_suite="TLS_AES_128_GCM_SHA256")
    assert tls13.algorithm == "AES"
    assert any(item.metadata.get("mtls") == "true" for item in run.artifacts)


def test_java_keystore_configuration(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"application.properties": JAVA_SSL})
    keystore = _one(run, artifact_type="keystore")
    assert keystore.metadata["reference"] == "/opt/app/keystore.jks"
    assert keystore.metadata["keystore_type"] == "JKS"
    trust = _one(run, artifact_type="truststore")
    assert trust.metadata["reference"] == "/opt/app/truststore.jks"
    assert "changeit" not in trust.evidence


def test_ssh_algorithms_and_public_key(tmp_path: Path) -> None:
    run = _scan(tmp_path, {".ssh/config": SSH_CONFIG, ".ssh/id_ed25519.pub": SSH_PUB})
    assert _one(run, artifact_type="ssh_key", algorithm="Ed25519")
    assert _one(run, algorithm="RSA", protocol="SSH")
    assert _one(run, algorithm="X25519")
    assert _one(run, algorithm="Diffie-Hellman")


def test_comments_and_docs_are_not_confirmed(tmp_path: Path) -> None:
    run = _scan(
        tmp_path,
        {
            "src/notes.py": "# TLSv1.2\n# -----BEGIN CERTIFICATE-----\nlabel = 'ssh-rsa'\n",
            "README.md": "We terminate TLS 1.2 and use ssh-rsa keys.\n",
        },
    )
    assert run.artifacts == []
    assert run.skip_reasons.get("documentation", 0) >= 1


def test_malformed_certificate_is_recorded_without_guessing(tmp_path: Path) -> None:
    run = _scan(tmp_path, {"bad.pem": "-----BEGIN CERTIFICATE-----\nnot-valid-base64!!!\n-----END CERTIFICATE-----\n"})
    cert = _one(run, artifact_type="certificate")
    assert cert.algorithm is None
    assert cert.key_size is None
    assert cert.metadata.get("malformed") == "true"


def test_repeated_artifact_scan_is_identical(tmp_path: Path) -> None:
    files = {"certs/server.crt": RSA_CERT, "nginx.conf": TLS_CONFIG, ".ssh/id_ed25519.pub": SSH_PUB}
    first = [(item.dedupe_key(), item.algorithm, item.evidence) for item in _scan(tmp_path / "a", files).artifacts]
    second = [(item.dedupe_key(), item.algorithm, item.evidence) for item in _scan(tmp_path / "b", files).artifacts]
    assert first == second
    assert first


def test_no_network_or_execution(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*_args, **_kwargs):
        raise AssertionError("artifact scanner attempted a network connection")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    run = _scan(tmp_path, {"certs/server.crt": RSA_CERT})
    assert run.artifacts


def test_artifact_api_redacts_private_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args, *, timeout, env, cwd):
        destination = Path(args[-1])
        (destination / "certs").mkdir(parents=True)
        (destination / "certs" / "tls.key").write_text(RSA_KEY, encoding="utf-8")
        (destination / "certs" / "tls.crt").write_text(RSA_CERT, encoding="utf-8")
        return 0

    monkeypatch.setattr("app.services.ingestion.github.run_git", fake_run)
    application = create_app(_settings(tmp_path))
    with TestClient(application) as client:
        created = client.post(
            "/api/v1/projects",
            json={"name": "Demo", "repository_url": "https://github.com/octocat/Hello-World"},
        )
        project_id = created.json()["id"]
        assert client.post(f"/api/v1/projects/{project_id}/ingest").status_code == 200
        scanned = client.post(f"/api/v1/projects/{project_id}/scan")
        assert scanned.status_code == 200
        scan_id = scanned.json()["scan_id"]
        missing = client.get("/api/v1/scans/999/artifacts")
        assert missing.status_code == 404
        assert missing.json()["error"]["code"] == "SCAN_NOT_FOUND"
        body = client.get(f"/api/v1/scans/{scan_id}/artifacts").json()
        text = client.get(f"/api/v1/scans/{scan_id}/artifacts").text
        assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj" not in text
        assert any(item["artifact_type"] == "private_key" for item in body["items"])
        session = client.app.state.session_factory()
        try:
            stored = session.query(SecurityArtifact).filter_by(scan_id=scan_id, artifact_type="private_key").one()
            assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSj" not in stored.evidence
        finally:
            session.close()
