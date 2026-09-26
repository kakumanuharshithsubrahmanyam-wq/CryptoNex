"""Comment masking and bounded evidence snippets.

Masking keeps newlines and string length stable so match offsets stay aligned
with the original file. Snippets are taken from the original text and capped.
"""

from app.core.config import Settings


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
    text = " ".join(line.strip() for line in selected if line.strip())
    collapsed = " ".join(text.split())
    limit = settings.evidence_max_chars
    if len(collapsed) > limit:
        return collapsed[: limit - 1] + "…"
    return collapsed or "[call]"


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
