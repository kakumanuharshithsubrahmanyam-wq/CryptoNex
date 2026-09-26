"""Deterministic context rules for a detected finding.

Every output is a pure function of the finding's detection method, library,
algorithm, usage, and explicit parameters. There is no scoring and no model.
"""

from dataclasses import dataclass

from app.services.context.taxonomy import (
    Confidence,
    ConfidenceReason,
    CryptographicRole,
    EvidenceType,
    FindingStatus,
    ParameterCompleteness,
    QuantumRelevance,
    SecurityConcern,
)
from app.services.scanner.findings import RawFinding
from app.services.scanner.registry import PASSWORD_BASED_KDFS, lookup_algorithm

_EVIDENCE_BY_METHOD = {
    "ast_detection": EvidenceType.CONFIRMED_API_USAGE,
    "api_detection": EvidenceType.CONFIRMED_API_USAGE,
    "import_detection": EvidenceType.CONFIRMED_IMPORT,
    "configuration_detection": EvidenceType.CONFIRMED_CONFIGURATION,
    "dependency_detection": EvidenceType.DEPENDENCY_PRESENCE,
    "pattern_detection": EvidenceType.WEAK_TEXTUAL_REFERENCE,
}
_WEAK_EVIDENCE = {
    EvidenceType.DEPENDENCY_PRESENCE,
    EvidenceType.WEAK_TEXTUAL_REFERENCE,
    EvidenceType.UNKNOWN,
}
_ROLE_BY_USAGE = {
    "encryption": CryptographicRole.CONFIDENTIALITY,
    "decryption": CryptographicRole.CONFIDENTIALITY,
    "signing": CryptographicRole.DIGITAL_SIGNATURE,
    "signature_verification": CryptographicRole.DIGITAL_SIGNATURE,
    "hashing": CryptographicRole.INTEGRITY,
    "mac": CryptographicRole.AUTHENTICATION,
    "key_agreement": CryptographicRole.KEY_ESTABLISHMENT,
    "random_generation": CryptographicRole.RANDOM_GENERATION,
}


@dataclass(frozen=True)
class FindingContext:
    evidence_type: EvidenceType
    confidence: Confidence
    confidence_reasons: tuple[ConfidenceReason, ...]
    finding_status: FindingStatus
    cryptographic_role: CryptographicRole
    parameter_completeness: ParameterCompleteness
    security_concern: SecurityConcern
    quantum_relevance: QuantumRelevance


def classify(finding: RawFinding) -> FindingContext:
    evidence_type = evidence_type_for(finding.detection_method)
    confidence, reasons = _confidence(finding, evidence_type)
    return FindingContext(
        evidence_type=evidence_type,
        confidence=confidence,
        confidence_reasons=reasons,
        finding_status=_status(evidence_type, confidence),
        cryptographic_role=_role(finding, evidence_type),
        parameter_completeness=_completeness(finding),
        security_concern=_concern(finding),
        quantum_relevance=_quantum_relevance(finding),
    )


def evidence_type_for(detection_method: str) -> EvidenceType:
    return _EVIDENCE_BY_METHOD.get(detection_method, EvidenceType.UNKNOWN)


def _confidence(
    finding: RawFinding, evidence_type: EvidenceType
) -> tuple[Confidence, tuple[ConfidenceReason, ...]]:
    if evidence_type == EvidenceType.CONFIRMED_API_USAGE:
        return _api_confidence(finding)
    if evidence_type == EvidenceType.CONFIRMED_IMPORT:
        reasons = [ConfidenceReason.RECOGNIZED_IMPORT]
        if finding.algorithm:
            reasons.append(ConfidenceReason.ALGORITHM_FROM_IMPORT)
        reasons.append(ConfidenceReason.NO_API_CALL)
        return Confidence.MEDIUM, tuple(reasons)
    if evidence_type == EvidenceType.CONFIRMED_CONFIGURATION:
        reasons = [ConfidenceReason.CONFIGURATION_ENTRY, ConfidenceReason.NO_API_CALL]
        level = Confidence.MEDIUM if finding.algorithm else Confidence.LOW
        return level, tuple(reasons)
    if evidence_type == EvidenceType.DEPENDENCY_PRESENCE:
        return Confidence.LOW, (ConfidenceReason.DEPENDENCY_DECLARED, ConfidenceReason.NO_SOURCE_USAGE)
    if evidence_type == EvidenceType.WEAK_TEXTUAL_REFERENCE:
        return Confidence.LOW, (ConfidenceReason.WEAK_TEXTUAL, ConfidenceReason.NO_SOURCE_USAGE)
    return Confidence.LOW, (ConfidenceReason.UNKNOWN_EVIDENCE,)


def _api_confidence(finding: RawFinding) -> tuple[Confidence, tuple[ConfidenceReason, ...]]:
    reasons = [ConfidenceReason.RECOGNIZED_API_CALL]
    library_confirmed = bool(finding.library) and finding.library_resolved
    reasons.append(
        ConfidenceReason.RECOGNIZED_LIBRARY if library_confirmed else ConfidenceReason.LIBRARY_NOT_CONFIRMED
    )
    if finding.algorithm:
        reasons.append(ConfidenceReason.ALGORITHM_FROM_API)
    elif finding.curve:
        reasons.append(ConfidenceReason.CURVE_WITHOUT_ALGORITHM)
    else:
        reasons.append(ConfidenceReason.ALGORITHM_NOT_IDENTIFIED)
    reasons.extend(_parameter_reasons(finding))
    level = Confidence.HIGH if library_confirmed and finding.algorithm else Confidence.MEDIUM
    return level, tuple(reasons)


def _parameter_reasons(finding: RawFinding) -> list[ConfidenceReason]:
    reasons: list[ConfidenceReason] = []
    if finding.key_size is not None:
        reasons.append(ConfidenceReason.EXPLICIT_KEY_SIZE)
    if finding.mode:
        reasons.append(ConfidenceReason.EXPLICIT_MODE)
    if finding.curve:
        reasons.append(ConfidenceReason.EXPLICIT_CURVE)
    if finding.metadata.get("hash"):
        reasons.append(ConfidenceReason.EXPLICIT_HASH)
    return reasons


def _status(evidence_type: EvidenceType, confidence: Confidence) -> FindingStatus:
    if evidence_type in _WEAK_EVIDENCE or confidence == Confidence.LOW:
        return FindingStatus.WEAK_SIGNAL
    if confidence == Confidence.HIGH:
        return FindingStatus.CONFIRMED
    return FindingStatus.PROBABLE


def _role(finding: RawFinding, evidence_type: EvidenceType) -> CryptographicRole:
    if evidence_type in _WEAK_EVIDENCE:
        return CryptographicRole.UNKNOWN
    if finding.usage == "key_derivation":
        if finding.algorithm in PASSWORD_BASED_KDFS:
            return CryptographicRole.PASSWORD_PROTECTION
        return CryptographicRole.UNKNOWN
    return _ROLE_BY_USAGE.get(finding.usage, CryptographicRole.UNKNOWN)


def _completeness(finding: RawFinding) -> ParameterCompleteness:
    if not finding.algorithm:
        return ParameterCompleteness.PARTIAL if finding.curve else ParameterCompleteness.UNKNOWN
    spec = lookup_algorithm(finding.algorithm)
    if spec is None:
        return ParameterCompleteness.UNKNOWN
    if not spec.parameters:
        return ParameterCompleteness.COMPLETE
    present = {
        "key_size": finding.key_size is not None,
        "mode": bool(finding.mode),
        "curve": bool(finding.curve),
        "hash": bool(finding.metadata.get("hash")),
    }
    known = sum(1 for name in spec.parameters if present.get(name, False))
    if known == len(spec.parameters):
        return ParameterCompleteness.COMPLETE
    if known:
        return ParameterCompleteness.PARTIAL
    return ParameterCompleteness.UNKNOWN


def _concern(finding: RawFinding) -> SecurityConcern:
    if finding.algorithm:
        spec = lookup_algorithm(finding.algorithm)
        return SecurityConcern(spec.security_concern) if spec else SecurityConcern.UNKNOWN
    if finding.curve:
        return SecurityConcern.CLASSICAL_PUBLIC_KEY
    return SecurityConcern.UNKNOWN


def _quantum_relevance(finding: RawFinding) -> QuantumRelevance:
    if finding.algorithm:
        spec = lookup_algorithm(finding.algorithm)
        return QuantumRelevance(spec.quantum_relevance) if spec else QuantumRelevance.UNKNOWN
    if finding.curve:
        return QuantumRelevance.CLASSICAL_PUBLIC_KEY
    return QuantumRelevance.UNKNOWN
