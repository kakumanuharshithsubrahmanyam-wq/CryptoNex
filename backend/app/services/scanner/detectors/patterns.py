"""Shared search over comment-masked source."""

import re

from app.services.scanner.evidence import in_span, line_bounds, mask_comments


def each_match(
    source: str,
    style: str,
    pattern: re.Pattern,
    *,
    masked: str | None = None,
    spans: list[tuple[int, int]] | None = None,
):
    if masked is None or spans is None:
        masked, spans = mask_comments(source, style)
    for match in pattern.finditer(masked):
        if in_span(match.start(), spans):
            continue
        line_start, line_end = line_bounds(masked, match.start(), match.end())
        yield match, line_start, line_end
