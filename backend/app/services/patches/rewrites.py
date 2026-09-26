"""Deterministic source rewrites for unambiguous legacy primitives.

Each rule replaces a recognized API token on the finding's stored line span.
Public-key PQC migrations are not rewritten here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class LineRewrite:
    languages: frozenset[str]
    algorithm: str
    replacement: str
    pattern: re.Pattern[str]
    substitute: str


REWRITES: tuple[LineRewrite, ...] = (
    LineRewrite(frozenset({"Python"}), "MD5", "SHA-256", re.compile(r"\bhashlib\.md5\b"), "hashlib.sha256"),
    LineRewrite(frozenset({"Python"}), "MD5", "SHA-256", re.compile(r"\bhashes\.MD5\b"), "hashes.SHA256"),
    LineRewrite(frozenset({"Python"}), "SHA-1", "SHA-256", re.compile(r"\bhashlib\.sha1\b"), "hashlib.sha256"),
    LineRewrite(frozenset({"Python"}), "SHA-1", "SHA-256", re.compile(r"\bhashes\.SHA1\b"), "hashes.SHA256"),
    LineRewrite(
        frozenset({"Java"}),
        "MD5",
        "SHA-256",
        re.compile(r'MessageDigest\.getInstance\(\s*"MD5"\s*\)'),
        'MessageDigest.getInstance("SHA-256")',
    ),
    LineRewrite(
        frozenset({"Java"}),
        "SHA-1",
        "SHA-256",
        re.compile(r'MessageDigest\.getInstance\(\s*"SHA-?1"\s*\)'),
        'MessageDigest.getInstance("SHA-256")',
    ),
    LineRewrite(frozenset({"Go"}), "MD5", "SHA-256", re.compile(r"\bmd5\.New\b"), "sha256.New"),
    LineRewrite(frozenset({"Go"}), "SHA-1", "SHA-256", re.compile(r"\bsha1\.New\b"), "sha256.New"),
    LineRewrite(frozenset({"Rust"}), "MD5", "SHA-256", re.compile(r"\bMd5\b"), "Sha256"),
    LineRewrite(frozenset({"Rust"}), "SHA-1", "SHA-256", re.compile(r"\bSha1\b"), "Sha256"),
    LineRewrite(frozenset({"C", "C++"}), "MD5", "SHA-256", re.compile(r"\bEVP_md5\b"), "EVP_sha256"),
    LineRewrite(frozenset({"C", "C++"}), "SHA-1", "SHA-256", re.compile(r"\bEVP_sha1\b"), "EVP_sha256"),
    LineRewrite(frozenset({"C", "C++"}), "MD5", "SHA-256", re.compile(r'"MD5"'), '"SHA-256"'),
    LineRewrite(frozenset({"C", "C++"}), "SHA-1", "SHA-256", re.compile(r'"SHA-1"'), '"SHA-256"'),
)


def apply_rewrite(language: str | None, algorithm: str, replacement: str, text: str) -> str | None:
    """Return rewritten text when exactly one registered rule matches the span."""
    matched: list[tuple[LineRewrite, str]] = []
    for rule in REWRITES:
        if language not in rule.languages:
            continue
        if rule.algorithm != algorithm or rule.replacement != replacement:
            continue
        if rule.pattern.search(text) is None:
            continue
        updated = rule.pattern.sub(rule.substitute, text)
        if updated != text:
            matched.append((rule, updated))
    if len(matched) != 1:
        return None
    return matched[0][1]


def replace_span(source: str, line_start: int, line_end: int, updated_span: str) -> str:
    lines = source.splitlines(keepends=True)
    if not lines or line_start < 1 or line_end > len(lines) or line_start > line_end:
        raise ValueError("finding line span is outside the stored source")
    prefix = "".join(lines[: line_start - 1])
    suffix = "".join(lines[line_end:])
    if updated_span and not updated_span.endswith(("\n", "\r\n")) and suffix:
        updated_span = updated_span.rstrip("\n") + ("\n" if source.endswith("\n") or suffix else "")
    return prefix + updated_span + suffix


def span_text(source: str, line_start: int, line_end: int) -> str:
    lines = source.splitlines(keepends=True)
    if line_start < 1 or line_end > len(lines) or line_start > line_end:
        raise ValueError("finding line span is outside the stored source")
    return "".join(lines[line_start - 1 : line_end])
