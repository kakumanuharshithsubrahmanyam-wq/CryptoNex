"""Shared fakes for migration, AI, PQC, and policy unit tests."""

from types import SimpleNamespace


def finding(**overrides) -> SimpleNamespace:
    values = dict(
        id=1,
        algorithm="RSA",
        algorithm_family="asymmetric",
        usage="key_generation",
        library="cryptography",
        library_version="42.0.5",
        key_size=2048,
        curve=None,
        mode=None,
        cryptographic_role="unknown",
        security_concern="classical_public_key",
        quantum_relevance="classical_public_key",
        finding_status="confirmed",
        confidence="high",
        evidence_type="confirmed_api_usage",
        detection_method="ast_detection",
        file_path="src/auth.py",
        line_start=3,
        line_end=6,
        evidence="rsa.generate_private_key(key_size=2048)",
        parameter_completeness="complete",
    )
    values.update(overrides)
    return SimpleNamespace(**values)


def snapshot(findings=None, artifacts=None, dependencies=None, graph=None) -> SimpleNamespace:
    rows = findings or []
    return SimpleNamespace(
        scan=SimpleNamespace(id=1),
        project=SimpleNamespace(id=1, workspace_path=None),
        findings=rows,
        artifacts=artifacts or [],
        dependencies=dependencies or [],
        links=[],
        graph=graph or {"nodes": [], "edges": [], "summary": {"nodes": 0, "edges": 0}},
        finding=lambda finding_id: next(row for row in rows if row.id == finding_id),
    )


def rsa_graph() -> dict:
    return {
        "nodes": [
            {"id": "finding:1", "type": "crypto_finding", "label": "RSA", "metadata": {"algorithm": "RSA", "file_path": "src/auth.py", "usage": "key_generation"}},
            {"id": "finding:2", "type": "crypto_finding", "label": "RSA", "metadata": {"algorithm": "RSA", "file_path": "src/tls.py", "usage": "signing"}},
            {"id": "algorithm:RSA", "type": "algorithm", "label": "RSA", "metadata": {"family": "asymmetric"}},
            {"id": "file:src/auth.py", "type": "file", "label": "src/auth.py", "metadata": {"file_path": "src/auth.py"}},
            {"id": "library:cryptography", "type": "crypto_library", "label": "cryptography", "metadata": {}},
            {"id": "dependency:9", "type": "dependency", "label": "cryptography", "metadata": {}},
            {"id": "certificate:4", "type": "certificate", "label": "server.crt", "metadata": {"algorithm": "RSA"}},
            {"id": "protocol:5", "type": "protocol", "label": "TLS", "metadata": {}},
            {"id": "cipher_suite:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "type": "cipher_suite", "label": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "metadata": {}},
            {"id": "project:1", "type": "project", "label": "Demo", "metadata": {}},
            {"id": "scan:1", "type": "scan", "label": "scan-1", "metadata": {}},
        ],
        "edges": [
            {"source": "finding:1", "target": "algorithm:RSA", "type": "USES_ALGORITHM"},
            {"source": "finding:1", "target": "file:src/auth.py", "type": "LOCATED_IN"},
            {"source": "finding:1", "target": "library:cryptography", "type": "USES_LIBRARY"},
            {"source": "library:cryptography", "target": "dependency:9", "type": "PROVIDED_BY"},
            {"source": "finding:2", "target": "algorithm:RSA", "type": "USES_ALGORITHM"},
            {"source": "certificate:4", "target": "algorithm:RSA", "type": "USES_ALGORITHM"},
            {"source": "protocol:5", "target": "cipher_suite:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "type": "USES_CIPHER_SUITE"},
            {"source": "protocol:5", "target": "algorithm:RSA", "type": "USES_ALGORITHM"},
            {"source": "project:1", "target": "scan:1", "type": "HAS_SCAN"},
            {"source": "scan:1", "target": "finding:1", "type": "CONTAINS_FINDING"},
        ],
        "summary": {"nodes": 11, "edges": 10},
    }
