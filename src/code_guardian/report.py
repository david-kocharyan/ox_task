"""Stdout summaries and per-repository result files."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from rich.console import Console
from rich.table import Table

from code_guardian.graph import write_graph_artifacts
from code_guardian.models import ScanResult

logger = logging.getLogger(__name__)
console = Console()


def print_summary(result: ScanResult) -> None:
    counts = result.severity_counts
    if result.error:
        console.print(
            f"[red]✗[/red] {result.repository} — scan failed: {result.error}"
        )
        return

    console.print(
        f"[green]✓[/green] {result.repository} "
        f"({result.popularity.display}) — "
        f"CRITICAL={counts.critical} HIGH={counts.high} "
        f"MEDIUM={counts.medium} LOW={counts.low} "
        f"(total {counts.total})"
    )


def write_result_file(
    result: ScanResult,
    output_dir: Path,
    *,
    render_graph_png: bool = True,
) -> Path:
    """Persist JSON report and graph artifacts for one repository."""
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / f"{result.repository_name}.json"

    dot_path, png_path = write_graph_artifacts(
        result,
        output_dir,
        render_png=render_graph_png,
    )

    payload = result.to_dict()
    payload["artifacts"] = {
        "dependency_graph_dot": str(dot_path),
        "dependency_graph_png": str(png_path) if png_path else None,
    }

    result_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    logger.info("Wrote result file to %s", result_path)
    return result_path


def print_run_table(results: list[ScanResult]) -> None:
    table = Table(title="Code Guardian Scan Summary")
    table.add_column("Repository")
    table.add_column("Popularity")
    table.add_column("CRIT", justify="right")
    table.add_column("HIGH", justify="right")
    table.add_column("MED", justify="right")
    table.add_column("LOW", justify="right")
    table.add_column("Status")

    for result in results:
        if result.error:
            table.add_row(
                result.repository,
                result.popularity.display,
                "-",
                "-",
                "-",
                "-",
                f"[red]failed[/red]",
            )
            continue
        c = result.severity_counts
        table.add_row(
            result.repository,
            result.popularity.display,
            str(c.critical),
            str(c.high),
            str(c.medium),
            str(c.low),
            "[green]ok[/green]",
        )

    console.print(table)
