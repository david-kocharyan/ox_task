"""Trivy scanner integration and JSON parsing."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from code_guardian.models import (
    DependencyEdge,
    ScanResult,
    Severity,
    SeverityCounts,
    Vulnerability,
)

logger = logging.getLogger(__name__)

# Trivy shares a local cache; parallel `trivy repo` runs can race and return empty output.
_TRIVY_LOCK = threading.Lock()


class TrivyNotFoundError(RuntimeError):
    """Raised when the Trivy binary is not available."""


class TrivyScanError(RuntimeError):
    """Raised when Trivy exits with an unexpected failure."""


def resolve_trivy_path(explicit: str | None = None) -> str:
    if explicit:
        path = Path(explicit)
        if not path.exists() and shutil.which(explicit) is None:
            raise TrivyNotFoundError(f"Trivy not found at configured path: {explicit}")
        return explicit

    found = shutil.which("trivy")
    if not found:
        raise TrivyNotFoundError(
            "Trivy is not installed or not on PATH. Install Trivy or use the Docker image."
        )
    return found


def warm_trivy_database(
    *,
    trivy_path: str | None = None,
    cache_dir: Path | None = None,
    timeout: int = 300,
) -> None:
    """Download the vulnerability DB once before parallel repository scans."""
    binary = resolve_trivy_path(trivy_path)
    cmd = [binary, "image", "--download-db-only"]
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["--cache-dir", str(cache_dir)])

    logger.info("Warming Trivy vulnerability database")
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyScanError(f"Trivy database download timed out after {timeout}s") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise TrivyScanError(f"Failed to download Trivy database: {stderr[:500]}")


def _friendly_trivy_error(stderr: str, repo_url: str) -> str | None:
    """Turn common Trivy stderr patterns into actionable messages."""
    if not stderr:
        return None

    if "429 Too Many Requests" in stderr or "rate limit" in stderr.lower():
        retry_match = re.search(r"Retry-After:\s*(\d+)", stderr)
        retry_hint = ""
        if retry_match:
            minutes = max(1, int(retry_match.group(1)) // 60)
            retry_hint = f" Try again in ~{minutes} minutes."
        return (
            f"Registry rate-limited {repo_url} while resolving dependencies "
            f"(common for Java/Maven repos when scanning many repositories).{retry_hint} "
            "Re-run this repo alone later, reduce batch size, or wait for the block to clear."
        )

    fatal_lines = [line.strip() for line in stderr.splitlines() if "FATAL" in line]
    if fatal_lines:
        return fatal_lines[-1][:500]

    return None


def _raise_trivy_failure(repo_url: str, stderr: str, *, context: str) -> None:
    friendly = _friendly_trivy_error(stderr, repo_url)
    if friendly:
        raise TrivyScanError(friendly)
    snippet = stderr.strip()[:500] or "no stderr"
    raise TrivyScanError(f"{context} for {repo_url}: {snippet}")


def _run_trivy_repo(
    cmd: list[str],
    *,
    repo_url: str,
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyScanError(f"Trivy timed out after {timeout}s for {repo_url}") from exc


def scan_repository(
    repo_url: str,
    *,
    trivy_path: str | None = None,
    timeout: int = 600,
    cache_dir: Path | None = None,
) -> dict[str, Any]:
    """Run `trivy repo` and return parsed JSON."""
    binary = resolve_trivy_path(trivy_path)
    cmd = [
        binary,
        "repo",
        "--scanners",
        "vuln",
        "--format",
        "json",
        "--quiet",
        repo_url,
    ]
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)
        cmd.extend(["--cache-dir", str(cache_dir), "--skip-db-update"])

    logger.info("Starting Trivy scan for %s", repo_url)
    logger.debug("Running command: %s", " ".join(cmd))

    completed: subprocess.CompletedProcess[str] | None = None
    for attempt in range(1, 4):
        with _TRIVY_LOCK:
            completed = _run_trivy_repo(cmd, repo_url=repo_url, timeout=timeout)

        stderr = (completed.stderr or completed.stdout or "").strip()

        if completed.returncode not in (0, 1):
            _raise_trivy_failure(
                repo_url,
                stderr,
                context=f"Trivy failed (exit {completed.returncode})",
            )

        output = completed.stdout.strip()
        if output:
            break

        if "429 Too Many Requests" in stderr:
            _raise_trivy_failure(repo_url, stderr, context="Trivy scan blocked by registry rate limit")

        logger.warning(
            "Trivy returned empty output for %s (attempt %d/3)%s",
            repo_url,
            attempt,
            f": {stderr[:200]}" if stderr else "",
        )
        if attempt < 3:
            time.sleep(attempt * 2)

    if not completed or not completed.stdout.strip():
        stderr = (completed.stderr.strip() if completed else "") or ""
        _raise_trivy_failure(
            repo_url,
            stderr,
            context="Trivy produced no output after retries",
        )

    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise TrivyScanError(f"Malformed Trivy JSON for {repo_url}: {exc}") from exc


def _package_id(pkg: dict[str, Any]) -> str:
    name = pkg.get("Name") or pkg.get("ID") or "unknown"
    version = pkg.get("Version") or ""
    return f"{name}@{version}" if version else str(name)


def parse_trivy_report(
    repo_url: str,
    payload: dict[str, Any],
    *,
    repository_name: str,
    popularity_source: Any = None,
) -> ScanResult:
    """Convert Trivy JSON into a ScanResult."""
    from code_guardian.models import Popularity

    popularity = popularity_source if isinstance(popularity_source, Popularity) else Popularity()
    severity_counts = SeverityCounts()
    vulnerabilities: list[Vulnerability] = []
    edges: list[DependencyEdge] = []
    seen_edges: set[tuple[str, str]] = set()

    results = payload.get("Results") or []
    if not isinstance(results, list):
        raise ValueError("Trivy payload missing Results list")

    for result in results:
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or repository_name)

        packages = result.get("Packages") or []
        pkg_by_id: dict[str, dict[str, Any]] = {}
        if isinstance(packages, list):
            for pkg in packages:
                if isinstance(pkg, dict):
                    pkg_by_id[_package_id(pkg)] = pkg
                    for dep in pkg.get("DependsOn") or []:
                        if not isinstance(dep, str):
                            continue
                        edge = (_package_id(pkg), dep)
                        if edge not in seen_edges:
                            seen_edges.add(edge)
                            edges.append(DependencyEdge(parent=edge[0], child=edge[1]))

        vulns = result.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for item in vulns:
            if not isinstance(item, dict):
                continue
            severity = Severity.from_trivy(item.get("Severity"))
            severity_counts.increment(severity)
            vulnerabilities.append(
                Vulnerability(
                    vulnerability_id=str(item.get("VulnerabilityID") or "UNKNOWN"),
                    pkg_name=str(item.get("PkgName") or item.get("PkgID") or "unknown"),
                    installed_version=str(item.get("InstalledVersion") or ""),
                    fixed_version=item.get("FixedVersion"),
                    severity=severity,
                    title=str(item.get("Title") or item.get("Description") or ""),
                    target=target,
                )
            )

    return ScanResult(
        repository=repo_url,
        repository_name=repository_name,
        popularity=popularity,
        severity_counts=severity_counts,
        vulnerabilities=vulnerabilities,
        dependencies=edges,
    )


def repository_slug(repo_url: str) -> str:
    """Filesystem-safe short name for output files."""
    cleaned = repo_url.strip().rstrip("/").removesuffix(".git")
    if "/" in cleaned:
        cleaned = cleaned.split("/")[-1]
    slug = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in cleaned)
    return slug or "repository"
