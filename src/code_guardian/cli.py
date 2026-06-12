"""Code Guardian CLI entry point."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Annotated

import typer

from code_guardian import __version__
from code_guardian.logging_config import setup_logging
from code_guardian.report import print_run_table
from code_guardian.runner import run_scan
from code_guardian.trivy import TrivyNotFoundError

app = typer.Typer(
    name="code-guardian",
    help="Scan Git repositories with Trivy and produce security reports.",
    add_completion=False,
    no_args_is_help=True,
)


def version_callback(value: bool) -> None:
    if value:
        typer.echo(f"code-guardian {__version__}")
        raise typer.Exit()


def _parse_repo_input(raw: str) -> list[str]:
    return [part for part in re.split(r"[,\s]+", raw.strip()) if part]


def prompt_repositories() -> list[str]:
    typer.echo("Enter one or more Git repository URLs to scan.")
    typer.echo("Separate multiple repos with spaces or commas.")
    while True:
        raw = typer.prompt("Repository URL(s)")
        repositories = _parse_repo_input(raw)
        if repositories:
            return repositories
        typer.echo("Please provide at least one repository URL.", err=True)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", callback=version_callback, is_eager=True),
    ] = None,
) -> None:
    """Code Guardian CLI."""


@app.command("scan")
def scan_command(
    repositories: Annotated[
        list[str] | None,
        typer.Argument(
            help="Git repository URLs. If omitted, you will be prompted interactively.",
        ),
    ] = None,
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-o", help="Directory for per-repo result files."),
    ] = Path("results"),
    trivy_path: Annotated[
        str | None,
        typer.Option("--trivy-path", help="Path to the Trivy binary."),
    ] = None,
    timeout: Annotated[
        int,
        typer.Option("--timeout", help="Per-repository Trivy timeout in seconds."),
    ] = 600,
    workers: Annotated[
        int,
        typer.Option("--workers", "-w", help="Parallel repository scans."),
    ] = 2,
    cache_dir: Annotated[
        Path | None,
        typer.Option("--cache-dir", help="Shared Trivy cache directory."),
    ] = None,
    log_level: Annotated[
        str,
        typer.Option("--log-level", help="Logging level (DEBUG, INFO, WARNING, ERROR)."),
    ] = "INFO",
    no_png: Annotated[
        bool,
        typer.Option("--no-png", help="Skip Graphviz PNG rendering (DOT still written)."),
    ] = False,
    summary_table: Annotated[
        bool,
        typer.Option("--summary-table", help="Print a Rich summary table at the end."),
    ] = True,
) -> None:
    """Scan repositories and write reports."""
    setup_logging(log_level)

    repo_list = list(repositories) if repositories else prompt_repositories()
    if not repo_list:
        typer.echo("Provide at least one repository URL.", err=True)
        raise typer.Exit(code=2)

    try:
        results = run_scan(
            repo_list,
            output_dir=output_dir,
            trivy_path=trivy_path,
            timeout=timeout,
            workers=workers,
            cache_dir=cache_dir,
            render_graph_png=not no_png,
        )
    except TrivyNotFoundError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc

    if summary_table:
        print_run_table(results)

    failures = [r for r in results if not r.succeeded]
    if failures and len(failures) == len(results):
        raise typer.Exit(code=2)
    if failures:
        raise typer.Exit(code=1)
    raise typer.Exit(code=0)


def run() -> None:
    try:
        app()
    except typer.Exit as exc:
        sys.exit(exc.exit_code)


if __name__ == "__main__":
    run()
