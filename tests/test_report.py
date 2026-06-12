import json
from pathlib import Path

from code_guardian.models import Popularity, ScanResult, SeverityCounts
from code_guardian.report import write_result_file


def test_write_result_file(tmp_path: Path) -> None:
    result = ScanResult(
        repository="https://github.com/example/repo",
        repository_name="repo",
        popularity=Popularity(stars=1, forks=0),
        severity_counts=SeverityCounts(),
    )
    path = write_result_file(result, tmp_path, render_graph_png=False)
    assert path.exists()
    data = json.loads(path.read_text())
    assert data["repository_name"] == "repo"
    assert Path(data["artifacts"]["dependency_graph_dot"]).exists()
