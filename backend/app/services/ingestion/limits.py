"""Shared size helpers for ingestion limits."""


def megabytes_to_bytes(value: int) -> int:
    return value * 1024 * 1024
