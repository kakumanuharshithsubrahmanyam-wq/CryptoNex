"""Comment masking and bounded evidence snippets.

Masking keeps newlines and string length stable so match offsets stay aligned
with the original file. Snippets are taken from the original text, redacted,
and capped.
"""

import re

from app.core.config import Settings

REDACTED = "[REDACTED]"

_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)",
    re.DOTALL,
)
_SECRET_ASSIGNMENT = re.compile(
    r"""(?ix)
    (\b[\w\-]*(?:password|passwd|passphrase|pwd|secret|token|api[_\-]?key|access[_\-]?key
        |private[_\-]?key|client[_\-]?secret|credential)s?[\w\-]*["']?\s*[:=]\s*)
    (?:
        ([bru]{0,2})("[^"\n]*"|'[^'\n]*')
        |
        ([^\s#;]+)
    )
    """
)
_URL_CREDENTIALS = re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/@\s:]+:[^/@\s]+@")
_TOKEN_FORMATS = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
    r"|sk-[A-Za-z0-9]{20,}|xox[abprs]-[A-Za-z0-9\-]{10,})\b"
)


def _redact_assignment(match: re.Match[str]) -> str:
    if match.group(3):
        return f"{match.group(1)}{match.group(2)}{match.group(3)[0]}{REDACTED}{match.group(3)[0]}"
    return f"{match.group(1)}{REDACTED}"


def redact_secrets(text: str) -> str:
    """Remove values that look like credentials before evidence is stored."""
    redacted = _PRIVATE_KEY_BLOCK.sub("[REDACTED PRIVATE KEY BLOCK]", text)
    redacted = _SECRET_ASSIGNMENT.sub(_redact_assignment, redacted)
    redacted = _URL_CREDENTIALS.sub(lambda match: f"{match.group(1)}{REDACTED}@", redacted)
    return _TOKEN_FORMATS.sub(REDACTED, redacted)


def bounded(text: str, settings: Settings) -> str:
    collapsed = " ".join(redact_secrets(text).split())
    limit = settings.evidence_max_chars
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "…"
    return collapsed


def mask_comments(source: str, style: str) -> tuple[str, list[tuple[int, int]]]:
    """Replace comments with spaces and return string spans that must not start a match."""
    chars = list(source)
    spans: list[tuple[int, int]] = []
    index = 0
    length = len(chars)
    while index < length:
        if _starts_triple(chars, index):
            end = _blank_until(chars, index + 3, chars[index] * 3)
            spans.append((index, end))
            index = end
            continue
        current = chars[index]
        if current in {'"', "'"} or (style == "go" and current == "`"):
            end = _skip_string(chars, index, current)
            spans.append((index, end))
            index = end
            continue
        if style == "python" and current == "#":
            index = _blank_until_newline(chars, index)
            continue
        if style in {"c", "go"} and current == "/" and _peek(chars, index) == "/":
            index = _blank_until_newline(chars, index)
            continue
        if style in {"c", "go"} and current == "/" and _peek(chars, index) == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index = _blank_until(chars, index + 2, "*/")
            continue
        index += 1
    return "".join(chars), spans


def in_span(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def line_bounds(source: str, start: int, end: int) -> tuple[int, int]:
    line_start = source.count("\n", 0, start) + 1
    line_end = source.count("\n", 0, max(start, end - 1)) + 1
    return line_start, line_end


def snippet(source: str, line_start: int, line_end: int, settings: Settings) -> str:
    lines = source.splitlines()
    selected = lines[max(0, line_start - 1) : max(line_start, line_end)]
    text = "\n".join(line.strip() for line in selected if line.strip())
    return bounded(text, settings) or "[call]"


def _peek(chars: list[str], index: int) -> str:
    if index + 1 >= len(chars):
        return ""
    return chars[index + 1]


def _starts_triple(chars: list[str], index: int) -> bool:
    if index + 2 >= len(chars):
        return False
    return chars[index] in {'"', "'"} and chars[index] == chars[index + 1] == chars[index + 2]


def _blank_until_newline(chars: list[str], index: int) -> int:
    while index < len(chars) and chars[index] != "\n":
        chars[index] = " "
        index += 1
    return index


def _blank_until(chars: list[str], index: int, terminator: str) -> int:
    size = len(terminator)
    while index < len(chars):
        if "".join(chars[index : index + size]) == terminator:
            for offset in range(size):
                if chars[index + offset] != "\n":
                    chars[index + offset] = " "
            return index + size
        if chars[index] != "\n":
            chars[index] = " "
        index += 1
    return index


def _skip_string(chars: list[str], index: int, quote: str) -> int:
    """Skip a string without blanking it. Comments inside strings stay data."""
    index += 1
    while index < len(chars):
        if chars[index] == "\\":
            index += 2
            continue
        if chars[index] == quote:
            return index + 1
        index += 1
    return index
