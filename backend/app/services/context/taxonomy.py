"""Closed vocabularies for finding context.

Values are stored as strings. None of them rate an application or state that a
system is quantum-safe or quantum-vulnerable.
"""

from enum import Enum


class EvidenceType(str, Enum):
    CONFIRMED_API_USAGE = "confirmed_api_usage"
    CONFIRMED_IMPORT = "confirmed_import"
    CONFIRMED_CONFIGURATION = "confirmed_configuration"
    DEPENDENCY_PRESENCE = "dependency_presence"
    WEAK_TEXTUAL_REFERENCE = "weak_textual_reference"
    UNKNOWN = "unknown"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfidenceReason(str, Enum):
    RECOGNIZED_API_CALL = "recognized_crypto_api_call"
    RECOGNIZED_LIBRARY = "recognized_crypto_library"
    LIBRARY_NOT_CONFIRMED = "library_not_confirmed_by_import"
    ALGORITHM_FROM_API = "algorithm_identified_from_api"
    ALGORITHM_NOT_IDENTIFIED = "algorithm_not_identified"
    CURVE_WITHOUT_ALGORITHM = "curve_identified_algorithm_unknown"
    EXPLICIT_KEY_SIZE = "explicit_key_size_detected"
    EXPLICIT_MODE = "explicit_mode_detected"
    EXPLICIT_CURVE = "explicit_curve_detected"
    EXPLICIT_HASH = "explicit_hash_detected"
    RECOGNIZED_IMPORT = "recognized_crypto_import"
    ALGORITHM_FROM_IMPORT = "algorithm_identified_from_import"
    NO_API_CALL = "no_api_call_observed"
    CONFIGURATION_ENTRY = "recognized_crypto_configuration"
    DEPENDENCY_DECLARED = "crypto_dependency_declared"
    NO_SOURCE_USAGE = "no_confirmed_source_api_usage"
    WEAK_TEXTUAL = "weak_textual_reference"
    UNKNOWN_EVIDENCE = "unknown_evidence_type"


class FindingStatus(str, Enum):
    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    WEAK_SIGNAL = "weak_signal"


class CryptographicRole(str, Enum):
    CONFIDENTIALITY = "confidentiality"
    INTEGRITY = "integrity"
    AUTHENTICATION = "authentication"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_ESTABLISHMENT = "key_establishment"
    PASSWORD_PROTECTION = "password_protection"
    RANDOM_GENERATION = "random_generation"
    UNKNOWN = "unknown"


class ParameterCompleteness(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class SecurityConcern(str, Enum):
    LEGACY_HASH = "legacy_hash"
    LEGACY_CIPHER = "legacy_cipher"
    CLASSICAL_PUBLIC_KEY = "classical_public_key"
    CLASSICAL_SIGNATURE = "classical_signature"
    CLASSICAL_KEY_EXCHANGE = "classical_key_exchange"
    SYMMETRIC_CRYPTOGRAPHY = "symmetric_cryptography"
    MODERN_HASH = "modern_hash"
    KEY_DERIVATION = "key_derivation"
    MAC = "mac"
    UNKNOWN = "unknown"


class QuantumRelevance(str, Enum):
    CLASSICAL_PUBLIC_KEY = "classical_public_key"
    CLASSICAL_SIGNATURE = "classical_signature"
    CLASSICAL_KEY_ESTABLISHMENT = "classical_key_establishment"
    SYMMETRIC = "symmetric"
    HASH = "hash"
    MAC = "mac"
    KEY_DERIVATION = "key_derivation"
    UNKNOWN = "unknown"
