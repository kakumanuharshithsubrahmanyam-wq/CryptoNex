"""GitHub repository URL validation."""

import pytest

from app.core.exceptions import AppError
from app.services.ingestion.validation import validate_github_repository_url


def test_valid_github_url() -> None:
    repository = validate_github_repository_url("https://github.com/octocat/Hello-World")
    assert repository.owner == "octocat"
    assert repository.name == "Hello-World"
    assert repository.clone_url == "https://github.com/octocat/Hello-World.git"
    assert repository.display_url == "https://github.com/octocat/Hello-World"


def test_trailing_slash_is_accepted() -> None:
    repository = validate_github_repository_url("https://github.com/octocat/Hello-World/")
    assert repository.clone_url == "https://github.com/octocat/Hello-World.git"


def test_git_suffix_is_accepted() -> None:
    repository = validate_github_repository_url("https://github.com/octocat/Hello-World.git")
    assert repository.name == "Hello-World"
    assert repository.clone_url == "https://github.com/octocat/Hello-World.git"


@pytest.mark.parametrize(
    ("value", "code"),
    [
        ("https://gitlab.com/octocat/Hello-World", "UNSUPPORTED_REPOSITORY_HOST"),
        ("https://github.com.evil.com/octocat/Hello-World", "UNSUPPORTED_REPOSITORY_HOST"),
        ("http://github.com/octocat/Hello-World", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat/Hello-World?ref=main", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat/Hello-World#readme", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat", "INVALID_REPOSITORY_URL"),
        ("not a url", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat/Hello-World;rm -rf /", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat/Hello-World`id`", "INVALID_REPOSITORY_URL"),
        ("https://github.com/octocat/Hello-World$(id)", "INVALID_REPOSITORY_URL"),
        ("https://user:token@github.com/octocat/Hello-World", "INVALID_REPOSITORY_URL"),
        ("https://github.com/../Hello-World", "INVALID_REPOSITORY_URL"),
    ],
)
def test_rejects_unsafe_or_unsupported_urls(value: str, code: str) -> None:
    with pytest.raises(AppError) as captured:
        validate_github_repository_url(value)
    assert captured.value.code == code
