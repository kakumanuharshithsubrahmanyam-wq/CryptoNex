"""Classify crypto-agility from stored findings and graph evidence only."""

from __future__ import annotations

from app.services.migration.registry import canonical_algorithm

_CONFIG_HINTS = (".yml", ".yaml", ".json", ".toml", ".ini", ".conf", ".properties", ".xml")


def analyze_agility(snapshot) -> dict:
    findings = [row for row in snapshot.findings if getattr(row, "usage", None) != "dependency_only"]
    if not findings:
        return {
            "scan_id": snapshot.scan.id,
            "classification": "unknown",
            "evidence": ["No source cryptographic findings are available."],
            "signals": {},
            "notes": ["Crypto-agility cannot be inferred beyond stored repository evidence."],
        }

    files = sorted({row.file_path for row in findings if row.file_path})
    algorithms = sorted({canonical_algorithm(row.algorithm) or "" for row in findings if row.algorithm} - {""})
    api_calls = [row for row in findings if getattr(row, "evidence_type", None) == "confirmed_api_usage"]
    selections = [row for row in findings if getattr(row, "usage", None) == "algorithm_selection"]
    config_files = [path for path in files if path.lower().endswith(_CONFIG_HINTS)]
    libraries = sorted({row.library for row in findings if row.library})
    hardcoded = [
        row
        for row in findings
        if getattr(row, "algorithm", None)
        and getattr(row, "usage", None) not in {"algorithm_selection", "dependency_only"}
        and getattr(row, "evidence_type", None) in {"confirmed_api_usage", "confirmed_configuration"}
    ]

    evidence: list[str] = []
    score = 0
    if config_files and selections:
        evidence.append("centralized algorithm configuration")
        score += 2
    if len(libraries) == 1:
        evidence.append("centralized crypto provider")
        score += 1
    if selections:
        evidence.append("abstraction or algorithm-selection interfaces")
        score += 1
    if hardcoded:
        evidence.append("hardcoded algorithm strings")
        score -= 1
    if len(api_calls) >= 3 and len(files) >= 3:
        evidence.append("multiple direct crypto API calls")
        score -= 2
    if len(files) >= 5:
        evidence.append("cryptographic usage is scattered across many files")
        score -= 2
    if len(files) <= 2 and api_calls:
        evidence.append("cryptographic usage is concentrated in few files")
        score += 1

    if not evidence:
        classification = "unknown"
        evidence.append("Available evidence is insufficient to classify agility.")
    elif score >= 2:
        classification = "high_agility"
    elif score <= -2:
        classification = "low_agility"
    else:
        classification = "moderate_agility"

    return {
        "scan_id": snapshot.scan.id,
        "classification": classification,
        "evidence": evidence,
        "signals": {
            "source_files": files,
            "algorithms": algorithms,
            "libraries": libraries,
            "confirmed_api_calls": len(api_calls),
            "algorithm_selection_sites": len(selections),
            "hardcoded_algorithm_sites": len(hardcoded),
            "configuration_files": config_files,
        },
        "notes": [
            "Classification uses stored findings and graph-adjacent file paths only.",
            "CryptoNex does not infer architecture beyond available evidence.",
        ],
    }
