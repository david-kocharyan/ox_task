from code_guardian.graph import render_dependency_dot
from code_guardian.models import (
    DependencyEdge,
    Popularity,
    ScanResult,
    SeverityCounts,
    Vulnerability,
    Severity,
)


def test_render_highlights_critical_nodes() -> None:
    result = ScanResult(
        repository="https://github.com/example/repo",
        repository_name="repo",
        popularity=Popularity(),
        severity_counts=SeverityCounts(critical=1),
        vulnerabilities=[
            Vulnerability(
                vulnerability_id="CVE-1",
                pkg_name="lodash",
                installed_version="1.0.0",
                fixed_version=None,
                severity=Severity.CRITICAL,
                title="bad",
                target="lock",
            )
        ],
        dependencies=[DependencyEdge(parent="app@1.0.0", child="lodash@1.0.0")],
    )
    dot = render_dependency_dot(result)
    assert "#ffcccc" in dot
    assert "lodash@1.0.0" in dot
