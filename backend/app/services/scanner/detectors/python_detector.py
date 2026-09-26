"""Python cryptographic API detection via the standard library parser.

ast.parse reads source text and does not execute it.
"""

import ast

from app.core.config import Settings
from app.services.scanner.evidence import snippet
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import lookup_algorithm, lookup_curve

_AES_MODES = {
    "GCM": "GCM",
    "CBC": "CBC",
    "CTR": "CTR",
    "ECB": "ECB",
    "MODE_GCM": "GCM",
    "MODE_CBC": "CBC",
    "MODE_CTR": "CTR",
    "MODE_ECB": "ECB",
}
_HASH_ATTRS = {
    "SHA1": "SHA-1",
    "SHA224": "SHA-224",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
    "SHA3_224": "SHA-3",
    "SHA3_256": "SHA-3",
    "SHA3_384": "SHA-3",
    "SHA3_512": "SHA-3",
    "MD5": "MD5",
    "BLAKE2b": "BLAKE2",
    "BLAKE2s": "BLAKE2",
    "sha1": "SHA-1",
    "sha224": "SHA-224",
    "sha256": "SHA-256",
    "sha384": "SHA-384",
    "sha512": "SHA-512",
    "sha3_256": "SHA-3",
    "md5": "MD5",
    "blake2b": "BLAKE2",
    "blake2s": "BLAKE2",
}


def detect_python(source: str, file_path: str, settings: Settings) -> list[RawFinding]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    imports = _import_map(tree)
    findings: list[RawFinding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            findings.extend(_match_call(node, imports, source, file_path, settings))
    return findings


def _import_map(tree: ast.AST) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                mapping[local] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                mapping[local] = f"{node.module}.{alias.name}"
    return mapping


def _match_call(
    node: ast.Call,
    imports: dict[str, str],
    source: str,
    file_path: str,
    settings: Settings,
) -> list[RawFinding]:
    if isinstance(node.func, ast.Attribute) and node.func.attr in {"encryptor", "decryptor"}:
        inner = node.func.value if isinstance(node.func.value, ast.Call) else None
        if inner is not None:
            base = _describe_cipher(inner, imports)
            if base is not None:
                usage = "encryption" if node.func.attr == "encryptor" else "decryption"
                return [_finding(node, source, file_path, settings, usage=usage, confidence="high", **base)]

    resolved = _resolve_call(node.func, imports)
    if resolved is None:
        return []
    library = _library_of(resolved)
    confidence = "high" if library else "medium"

    if resolved.endswith("rsa.generate_private_key") or resolved.endswith("RSA.generate"):
        if library not in {"cryptography", "PyCryptodome"} and not resolved.endswith("RSA.generate"):
            return []
        if resolved.endswith("RSA.generate") and library not in {"PyCryptodome", None}:
            return []
        if resolved.endswith("RSA.generate"):
            library = library or "PyCryptodome"
            confidence = "high" if _library_of(resolved) == "PyCryptodome" else "medium"
        else:
            library = library or "cryptography"
            confidence = "high" if _library_of(resolved) == "cryptography" else "medium"
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="RSA",
                family="asymmetric",
                library=library,
                usage="key_generation",
                key_size=_key_size(node),
                confidence=confidence,
                method="ast_detection",
            )
        ]

    if resolved.endswith("Hash.SHA256.new") or resolved.endswith("SHA256.new"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="SHA-256",
                family="hash",
                library=library or "PyCryptodome",
                usage="hashing",
                confidence="high" if library == "PyCryptodome" else "medium",
                method="ast_detection",
            )
        ]

    hash_name = _hash_from_name(resolved)
    if hash_name and (resolved.startswith("hashlib.") or ".hashes." in resolved or resolved.startswith("hashes.")):
        hash_library = "hashlib" if resolved.startswith("hashlib.") else "cryptography"
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm=hash_name,
                family="hash",
                library=hash_library,
                usage="hashing",
                confidence="high",
                method="ast_detection",
            )
        ]

    if resolved.endswith("hmac.HMAC") or resolved.endswith("hmac.new"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="HMAC",
                family="mac",
                library="cryptography" if resolved.endswith("hmac.HMAC") else "hmac",
                usage="mac",
                confidence="high" if library or resolved.startswith("hmac.") or ".hmac." in resolved else "medium",
                method="ast_detection",
                metadata=_hash_metadata(node),
            )
        ]

    if resolved.endswith("PBKDF2HMAC") or resolved.endswith("pbkdf2_hmac"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="PBKDF2",
                family="kdf",
                library="cryptography" if resolved.endswith("PBKDF2HMAC") else "hashlib",
                usage="key_derivation",
                confidence="high",
                method="ast_detection",
            )
        ]

    if resolved.endswith(".HKDF") or resolved.rsplit(".", 1)[-1] == "HKDF":
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="HKDF",
                family="kdf",
                library=library or "cryptography",
                usage="key_derivation",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("scrypt") or resolved.endswith("hashlib.scrypt"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="scrypt",
                family="kdf",
                library=library or "hashlib",
                usage="key_derivation",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("ChaCha20Poly1305"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="ChaCha20-Poly1305",
                family="symmetric",
                library=library or "cryptography",
                usage="algorithm_selection",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("ec.ECDSA") or resolved.endswith(".ECDSA"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="ECDSA",
                family="asymmetric",
                library=library or "cryptography",
                usage="algorithm_selection",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("ec.ECDH") or resolved.endswith(".ECDH"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="ECDH",
                family="asymmetric",
                library=library or "cryptography",
                usage="key_agreement",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("Ed25519PrivateKey.generate") or resolved.endswith("ed25519.Ed25519PrivateKey.generate"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm="Ed25519",
                family="asymmetric",
                library=library or "cryptography",
                usage="key_generation",
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    if resolved.endswith("ec.generate_private_key"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                algorithm=None,
                family=None,
                library=library or "cryptography",
                usage="key_generation",
                curve=_curve_from_args(node),
                confidence="high" if library else "medium",
                method="ast_detection",
            )
        ]

    described = _describe_cipher(node, imports)
    if described and (library == "cryptography" or described.get("library") == "PyCryptodome"):
        return [
            _finding(
                node,
                source,
                file_path,
                settings,
                usage="algorithm_selection",
                confidence="high" if library or described.get("library") else "medium",
                method="ast_detection",
                **described,
            )
        ]
    return []


def _describe_cipher(node: ast.Call, imports: dict[str, str]) -> dict | None:
    resolved = _resolve_call(node.func, imports) or ""
    algorithm = None
    mode = None
    key_size = None
    library = _library_of(resolved)
    if resolved.endswith("AES.new") or resolved.endswith(".AES.new"):
        library = "PyCryptodome"
        algorithm = "AES"
        if node.args:
            key_size = _bytes_key_size(node.args[0])
        mode = _mode_from_call(node)
    for arg in node.args:
        if not isinstance(arg, ast.Call):
            continue
        name = _dotted_name(arg.func) or ""
        resolved_arg = _resolve_name(name, imports)
        if resolved_arg.endswith("AES") or name.endswith("AES"):
            algorithm = "AES"
            library = library or "cryptography"
            if arg.args:
                key_size = _bytes_key_size(arg.args[0])
        leaf = (resolved_arg or name).rsplit(".", 1)[-1]
        if leaf in _AES_MODES:
            mode = _AES_MODES[leaf]
    if algorithm is None:
        return None
    return {
        "algorithm": algorithm,
        "family": "symmetric",
        "library": library,
        "mode": mode,
        "key_size": key_size,
    }


def _finding(
    node: ast.AST,
    source: str,
    file_path: str,
    settings: Settings,
    *,
    algorithm: str | None,
    family: str | None,
    library: str | None,
    usage: str,
    confidence: str,
    method: str = "ast_detection",
    key_size: int | None = None,
    curve: str | None = None,
    mode: str | None = None,
    metadata: dict[str, str] | None = None,
) -> RawFinding:
    start = getattr(node, "lineno", 1)
    end = getattr(node, "end_lineno", start) or start
    return RawFinding(
        file_path=file_path,
        line_start=start,
        line_end=end,
        language="Python",
        algorithm=algorithm,
        algorithm_family=family,
        library=library,
        library_version=None,
        usage=usage,
        key_size=key_size,
        curve=curve,
        mode=mode,
        evidence=snippet(source, start, end, settings),
        detection_method=method,
        confidence=confidence,
        metadata=metadata or {},
        # Every Python rule lowers confidence only when the import was not resolved.
        library_resolved=confidence == "high",
    )


def _resolve_call(func: ast.AST, imports: dict[str, str]) -> str | None:
    name = _dotted_name(func)
    if name is None:
        return None
    return _resolve_name(name, imports)


def _resolve_name(name: str, imports: dict[str, str]) -> str:
    root = name.split(".", 1)[0]
    if root in imports:
        return imports[root] + name[len(root) :]
    return name


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        if base is None:
            return node.attr
        return f"{base}.{node.attr}"
    return None


def _library_of(resolved: str) -> str | None:
    if resolved.startswith("cryptography.") or ".cryptography." in resolved:
        return "cryptography"
    if resolved.startswith("Crypto.") or resolved.startswith("Cryptodome."):
        return "PyCryptodome"
    if resolved.startswith("hashlib.") or resolved == "hashlib":
        return "hashlib"
    if resolved.startswith("hmac.") or resolved == "hmac":
        return "hmac"
    return None


def _key_size(node: ast.Call) -> int | None:
    for keyword in node.keywords:
        if keyword.arg == "key_size":
            return _const_int(keyword.value)
    if node.args:
        return _const_int(node.args[0])
    return None


def _const_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _bytes_key_size(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (bytes, bytearray)):
        bits = len(node.value) * 8
        if bits in {128, 192, 256}:
            return bits
    return None


def _mode_from_call(node: ast.Call) -> str | None:
    for arg in node.args[1:]:
        name = _dotted_name(arg) or ""
        leaf = name.rsplit(".", 1)[-1]
        if leaf in _AES_MODES:
            return _AES_MODES[leaf]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            name = _dotted_name(keyword.value) or ""
            leaf = name.rsplit(".", 1)[-1]
            if leaf in _AES_MODES:
                return _AES_MODES[leaf]
    return None


def _hash_from_name(resolved: str) -> str | None:
    leaf = resolved.rsplit(".", 1)[-1]
    if leaf in _HASH_ATTRS:
        return _HASH_ATTRS[leaf]
    spec = lookup_algorithm(leaf)
    if spec and spec.family == "hash":
        return spec.canonical_name
    return None


def _hash_metadata(node: ast.Call) -> dict[str, str]:
    for arg in node.args:
        name = _dotted_name(arg) or ""
        leaf = name.rsplit(".", 1)[-1]
        if leaf in _HASH_ATTRS:
            return {"hash": _HASH_ATTRS[leaf]}
        if isinstance(arg, ast.Call):
            nested = _hash_from_name(_dotted_name(arg.func) or "")
            if nested:
                return {"hash": nested}
    return {}


def _curve_from_args(node: ast.Call) -> str | None:
    for arg in node.args:
        target = arg.func if isinstance(arg, ast.Call) else arg
        name = _dotted_name(target) or ""
        curve = lookup_curve(name.rsplit(".", 1)[-1])
        if curve:
            return curve
    return None
