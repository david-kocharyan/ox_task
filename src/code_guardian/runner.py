"""Orchestrate scanning multiple repositories."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from code_guardian.github import fetch_popularity
from code_guardian.models import Popularity, ScanResult, SeverityCounts
from code_guardian.report import print_summary, write_result_file
from code_guardian.trivy import (
    TrivyNotFoundError,
    TrivyScanError,
    parse_trivy_report,
    repository_slug,
    scan_repository,
    warm_trivy_database,
)

logger = logging.getLogger(__name__)


def _scan_one(
    repo_url: str,
    *,
    output_dir: Path,
    trivy_path: str | None,
    timeout: int,
    cache_dir: Path | None,
    render_graph_png: bool,
) -> ScanResult:
    slug = repository_slug(repo_url)
    popularity = fetch_popularity(repo_url)

    try:
        payload = scan_repository(
            repo_url,
            trivy_path=trivy_path,
            timeout=timeout,
            cache_dir=cache_dir,
        )
        result = parse_trivy_report(
            repo_url,
            payload,
            repository_name=slug,
            popularity_source=popularity,
        )
        write_result_file(result, output_dir, render_graph_png=render_graph_png)
        print_summary(result)
        return result
    except (TrivyScanError, ValueError) as exc:
        logger.exception("Scan failed for %s", repo_url)
        failed = ScanResult(
            repository=repo_url,
            repository_name=slug,
            popularity=popularity,
            severity_counts=SeverityCounts(),
            error=str(exc),
        )
        write_result_file(failed, output_dir, render_graph_png=False)
        print_summary(failed)
        return failed


def run_scan(
    repositories: list[str],
    *,
    output_dir: Path,
    trivy_path: str | None = None,
    timeout: int = 600,
    workers: int = 2,
    cache_dir: Path | None = None,
    render_graph_png: bool = True,
) -> list[ScanResult]:
    """Scan repositories, optionally in parallel."""
    if not repositories:
        return []

    # Fail fast if Trivy is missing before spawning workers.
    from code_guardian.trivy import resolve_trivy_path

    resolve_trivy_path(trivy_path)

    output_dir.mkdir(parents=True, exist_ok=True)
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        warm_trivy_database(trivy_path=trivy_path, cache_dir=cache_dir, timeout=min(timeout, 300))
    except TrivyScanError as exc:
        logger.warning("Trivy DB warm-up failed, continuing anyway: %s", exc)

    worker_count = max(1, min(workers, len(repositories)))
    logger.info(
        "Scanning %d repositories with %d workers; output -> %s",
        len(repositories),
        worker_count,
        output_dir,
    )

    results: list[ScanResult] = []
    if worker_count == 1:
        for repo in repositories:
            results.append(
                _scan_one(
                    repo,
                    output_dir=output_dir,
                    trivy_path=trivy_path,
                    timeout=timeout,
                    cache_dir=cache_dir,
                    render_graph_png=render_graph_png,
                )
            )
        return results

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(
                _scan_one,
                repo,
                output_dir=output_dir,
                trivy_path=trivy_path,
                timeout=timeout,
                cache_dir=cache_dir,
                render_graph_png=render_graph_png,
            ): repo
            for repo in repositories
        }
        for future in as_completed(future_map):
            repo = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                logger.exception("Unexpected failure for %s", repo)
                slug = repository_slug(repo)
                failed = ScanResult(
                    repository=repo,
                    repository_name=slug,
                    popularity=Popularity(),
                    severity_counts=SeverityCounts(),
                    error=str(exc),
                )
                write_result_file(failed, output_dir, render_graph_png=False)
                print_summary(failed)
                results.append(failed)

    return results
