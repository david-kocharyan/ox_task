from code_guardian.cli import _parse_repo_input


def test_parse_single_repo() -> None:
    assert _parse_repo_input("https://github.com/OWASP/NodeGoat") == [
        "https://github.com/OWASP/NodeGoat"
    ]


def test_parse_multiple_repos_space_separated() -> None:
    assert _parse_repo_input(
        "https://github.com/OWASP/NodeGoat"
    ) == [
        "https://github.com/OWASP/NodeGoat"
    ]


def test_parse_multiple_repos_comma_separated() -> None:
    assert _parse_repo_input(
        "https://github.com/OWASP/NodeGoat, https://github.com/OWASP/railsgoat"
    ) == [
        "https://github.com/OWASP/NodeGoat",
        "https://github.com/OWASP/railsgoat",
    ]
