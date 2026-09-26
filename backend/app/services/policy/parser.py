"""Safe policy parsing. Configuration is data; it is never executed."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from app.core.exceptions import AppError

_FORBIDDEN = re.compile(r"(!!|!\w|&\w|\*)")
_VALID_ACTIONS = frozenset({"fail", "warn", "allow"})


@dataclass(frozen=True)
class PolicyRule:
    rule: str
    action: str
    algorithm: str | None = None
    security_concern: str | None = None
    usage: str | None = None
    max_key_size: int | None = None
    min_key_size: int | None = None


def parse_policy(text: str | None) -> list[PolicyRule]:
    if text is None or not str(text).strip():
        raise AppError("POLICY_INVALID", "Policy document is empty.", status_code=400)
    raw = str(text)
    if _FORBIDDEN.search(raw):
        raise AppError("POLICY_INVALID", "Policy document contains unsupported YAML constructs.", status_code=400)
    stripped = raw.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        document = _load_json(raw)
    else:
        document = _load_simple_yaml(raw)
    return _rules_from_document(document)


def _load_json(text: str):
    try:
        loaded = json.loads(text)
    except ValueError as exc:
        raise AppError("POLICY_INVALID", "Policy JSON is malformed.", status_code=400) from exc
    return loaded


def _load_simple_yaml(text: str) -> dict:
    lines: list[tuple[int, str]] = []
    for index, original in enumerate(text.splitlines(), start=1):
        stripped = original.split("#", 1)[0].rstrip()
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        if "\t" in original.split("#", 1)[0]:
            raise AppError("POLICY_INVALID", "Policy YAML must use spaces, not tabs.", status_code=400)
        if indent % 2 != 0:
            raise AppError("POLICY_INVALID", f"Policy YAML indent is invalid on line {index}.", status_code=400)
        lines.append((indent, stripped.strip()))
    if not lines:
        raise AppError("POLICY_INVALID", "Policy document is empty.", status_code=400)
    document, index = _parse_map(lines, 0, lines[0][0])
    if index != len(lines):
        raise AppError("POLICY_INVALID", "Policy YAML has leftover content.", status_code=400)
    if not isinstance(document, dict):
        raise AppError("POLICY_INVALID", "Policy YAML must be a mapping.", status_code=400)
    return document


def _parse_map(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[dict, int]:
    mapping: dict = {}
    index = start
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise AppError("POLICY_INVALID", "Policy YAML structure is malformed.", status_code=400)
        if content.startswith("- "):
            raise AppError("POLICY_INVALID", "Policy YAML expected a mapping key.", status_code=400)
        if ":" not in content:
            raise AppError("POLICY_INVALID", "Policy YAML mapping entries must use key: value.", status_code=400)
        key, rest = content.split(":", 1)
        key = key.strip()
        rest = rest.strip()
        index += 1
        if rest:
            mapping[key] = _scalar(rest)
            continue
        if index >= len(lines) or lines[index][0] <= indent:
            mapping[key] = None
            continue
        next_indent, next_content = lines[index]
        if next_content.startswith("- "):
            mapping[key], index = _parse_list(lines, index, next_indent)
        else:
            mapping[key], index = _parse_map(lines, index, next_indent)
    return mapping, index


def _parse_list(lines: list[tuple[int, str]], start: int, indent: int) -> tuple[list, int]:
    items: list = []
    index = start
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent or not content.startswith("- "):
            raise AppError("POLICY_INVALID", "Policy YAML list is malformed.", status_code=400)
        remainder = content[2:].strip()
        index += 1
        if remainder and ":" in remainder:
            key, rest = remainder.split(":", 1)
            item = {key.strip(): _scalar(rest.strip()) if rest.strip() else None}
            if index < len(lines) and lines[index][0] > indent:
                nested, index = _parse_map(lines, index, lines[index][0])
                if not isinstance(nested, dict):
                    raise AppError("POLICY_INVALID", "Policy YAML list item is malformed.", status_code=400)
                item.update(nested)
            items.append(item)
        elif remainder:
            items.append(_scalar(remainder))
        elif index < len(lines) and lines[index][0] > indent:
            nested_indent, nested_content = lines[index]
            if nested_content.startswith("- "):
                nested, index = _parse_list(lines, index, nested_indent)
            else:
                nested, index = _parse_map(lines, index, nested_indent)
            items.append(nested)
        else:
            items.append(None)
    return items, index


def _scalar(value: str):
    if value in {"null", "Null", "~"}:
        return None
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _rules_from_document(document) -> list[PolicyRule]:
    if not isinstance(document, dict):
        raise AppError("POLICY_INVALID", "Policy document must be a mapping.", status_code=400)
    rows = document.get("policies")
    if not isinstance(rows, list) or not rows:
        raise AppError("POLICY_INVALID", "Policy document must contain a non-empty policies list.", status_code=400)
    rules: list[PolicyRule] = []
    for row in rows:
        if not isinstance(row, dict):
            raise AppError("POLICY_INVALID", "Each policy rule must be a mapping.", status_code=400)
        name = str(row.get("rule") or "").strip()
        action = str(row.get("action") or "").strip().lower()
        if not name or action not in _VALID_ACTIONS:
            raise AppError("POLICY_INVALID", "Each rule needs a name and action fail, warn, or allow.", status_code=400)
        max_key = row.get("max_key_size")
        min_key = row.get("min_key_size")
        if max_key is not None and (not isinstance(max_key, int) or max_key < 1):
            raise AppError("POLICY_INVALID", "max_key_size must be a positive integer.", status_code=400)
        if min_key is not None and (not isinstance(min_key, int) or min_key < 1):
            raise AppError("POLICY_INVALID", "min_key_size must be a positive integer.", status_code=400)
        algorithm = row.get("algorithm")
        concern = row.get("security_concern")
        usage = row.get("usage")
        rules.append(
            PolicyRule(
                rule=name,
                action=action,
                algorithm=str(algorithm).strip() if algorithm else None,
                security_concern=str(concern).strip() if concern else None,
                usage=str(usage).strip() if usage else None,
                max_key_size=max_key,
                min_key_size=min_key,
            )
        )
    return rules
