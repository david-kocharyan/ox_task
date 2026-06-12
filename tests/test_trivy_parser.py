from code_guardian.models import Popularity, Severity
from code_guardian.trivy import parse_trivy_report, repository_slug


SAMPLE_PAYLOAD = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Packages": [
                {
                    "Name": "lodash",
                    "Version": "4.17.15",
                    "DependsOn": ["minimist@1.2.0"],
                },
                {"Name": "minimist", "Version": "1.2.0"},
            ],
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2020-1234",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.15",
                    "FixedVersion": "4.17.21",
                    "Severity": "CRITICAL",
                    "Title": "Prototype pollution",
                },
                {
                    "VulnerabilityID": "CVE-2020-5678",
                    "PkgName": "minimist",
                    "InstalledVersion": "1.2.0",
                    "Severity": "HIGH",
                    "Title": "Prototype pollution",
                },
            ],
        }
    ]
}


def test_parse_trivy_report() -> None:
    result = parse_trivy_report(
        "https://github.com/example/repo",
        SAMPLE_PAYLOAD,
        repository_name="repo",
        popularity_source=Popularity(stars=10, forks=2),
    )
    assert result.severity_counts.critical == 1
    assert result.severity_counts.high == 1
    assert len(result.vulnerabilities) == 2
    assert result.vulnerabilities[0].severity == Severity.CRITICAL
    assert len(result.dependencies) == 1
    assert result.dependencies[0].parent == "lodash@4.17.15"


def test_repository_slug() -> None:
    assert repository_slug("https://github.com/OWASP/NodeGoat.git") == "NodeGoat"
