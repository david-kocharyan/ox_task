from code_guardian.trivy import _friendly_trivy_error


def test_friendly_error_for_maven_rate_limit() -> None:
    stderr = (
        "FATAL Error remote Maven repository returned 429 Too Many Requests for "
        "https://repo.maven.apache.org/maven2/... Retry-After: 1539."
    )
    message = _friendly_trivy_error(stderr, "https://github.com/WebGoat/WebGoat")
    assert message is not None
    assert "rate-limited" in message
    assert "~25 minutes" in message
