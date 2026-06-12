from code_guardian.github import fetch_popularity, parse_github_repo


def test_parse_github_https() -> None:
    assert parse_github_repo("https://github.com/OWASP/NodeGoat") == ("OWASP", "NodeGoat")


def test_parse_github_ssh() -> None:
    assert parse_github_repo("git@github.com:OWASP/NodeGoat.git") == ("OWASP", "NodeGoat")


def test_parse_non_github() -> None:
    assert parse_github_repo("https://gitlab.com/foo/bar") is None


def test_fetch_popularity_non_github() -> None:
    popularity = fetch_popularity("https://gitlab.com/foo/bar")
    assert popularity.source == "unavailable"
