"""Public GitHub HTTPS URL validation.

The raw user string is parsed and then discarded. Callers clone only the
canonical URL built from validated owner and repository name characters.
"""

from dataclasses import dataclass
from urllib.parse import urlsplit

from app.core.exceptions import AppError

_ALLOWED_NAME = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")


@dataclass(frozen=True)
class GitHubRepository:
    owner: str
    name: str
    clone_url: str
    display_url: str


def validate_github_repository_url(value: str) -> GitHubRepository:
    """Accept a public https://github.com/{owner}/{name} URL."""
    if not isinstance(value, str):
        raise _invalid("Repository URL must be a string.")
    candidate = value.strip()
    if not candidate or any(character in candidate for character in "\x00\r\n\t "):
        raise _invalid("Repository URL is malformed.")

    try:
        parts = urlsplit(candidate)
    except ValueError as exc:
        raise _invalid("Repository URL is malformed.") from exc

    if parts.username or parts.password:
        raise _invalid("Repository URL must not include credentials.")
    if parts.query or parts.fragment:
        raise _invalid("Repository URL must not include a query string or fragment.")
    if parts.scheme != "https":
        raise _invalid("Only HTTPS GitHub repository URLs are supported.")

    host = (parts.hostname or "").lower()
    if host != "github.com":
        raise AppError(
            "UNSUPPORTED_REPOSITORY_HOST",
            "Only public github.com repositories are supported.",
            status_code=400,
        )
    if parts.port not in (None, 443):
        raise _invalid("Repository URL must not include a custom port.")

    path = parts.path.strip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    segments = [segment for segment in path.split("/") if segment]
    if len(segments) != 2:
        raise _invalid("Repository URL must be https://github.com/{owner}/{repository}.")

    owner, name = segments
    _validate_component(owner, "owner", maximum=39)
    _validate_component(name, "repository", maximum=100)
    return GitHubRepository(
        owner=owner,
        name=name,
        clone_url=f"https://github.com/{owner}/{name}.git",
        display_url=f"https://github.com/{owner}/{name}",
    )


def _validate_component(value: str, label: str, maximum: int) -> None:
    if value in {".", ".."} or value.startswith(".") or not (1 <= len(value) <= maximum):
        raise _invalid(f"Repository URL has an invalid {label}.")
    if any(character not in _ALLOWED_NAME for character in value):
        raise _invalid(f"Repository URL has an invalid {label}.")


def _invalid(message: str) -> AppError:
    return AppError("INVALID_REPOSITORY_URL", message, status_code=400)
