"""Dependency graph rendering with Graphviz DOT."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

from code_guardian.models import DependencyEdge, ScanResult, Severity

logger = logging.getLogger(__name__)


def _critical_packages(result: ScanResult) -> set[str]:
    critical: set[str] = set()
    for vuln in result.vulnerabilities:
        if vuln.severity == Severity.CRITICAL:
            label = vuln.pkg_name
            if vuln.installed_version:
                label = f"{vuln.pkg_name}@{vuln.installed_version}"
            critical.add(label)
            critical.add(vuln.pkg_name)
    return critical


def _node_id(name: str) -> str:
    return '"' + name.replace('"', '\\"') + '"'


def render_dependency_dot(result: ScanResult) -> str:
    """Build a Graphviz DOT document highlighting CRITICAL packages."""
    critical = _critical_packages(result)
    lines = [
        "digraph dependencies {",
        "  rankdir=LR;",
        '  node [shape=box, style="rounded,filled", fillcolor="#f5f5f5", fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
        f'  label="Dependency graph — {result.repository_name}";',
        "  labelloc=t;",
    ]

    nodes: set[str] = set()
    for edge in result.dependencies:
        nodes.add(edge.parent)
        nodes.add(edge.child)

    for node in sorted(nodes):
        attrs = []
        if node in critical or any(node.startswith(c + "@") for c in critical):
            attrs.append('fillcolor="#ffcccc"')
            attrs.append('color="#cc0000"')
            attrs.append("penwidth=2")
        lines.append(f"  {_node_id(node)} [{', '.join(attrs)}];")

    for edge in result.dependencies:
        lines.append(f"  {_node_id(edge.parent)} -> {_node_id(edge.child)};")

    if not result.dependencies:
        lines.append('  placeholder [label="No dependency edges reported by Trivy", shape=note];')

    lines.append("}")
    return "\n".join(lines)


def write_graph_artifacts(
    result: ScanResult,
    output_dir: Path,
    *,
    render_png: bool = True,
) -> tuple[Path, Path | None]:
    """Write .dot file and optionally render .png via the graphviz `dot` CLI."""
    output_dir.mkdir(parents=True, exist_ok=True)
    dot_path = output_dir / f"{result.repository_name}.dot"
    dot_content = render_dependency_dot(result)
    dot_path.write_text(dot_content, encoding="utf-8")
    logger.info("Wrote dependency graph DOT to %s", dot_path)

    png_path: Path | None = None
    if not render_png:
        return dot_path, png_path

    dot_binary = shutil.which("dot")
    if not dot_binary:
        logger.warning("graphviz `dot` not found; skipping PNG render for %s", result.repository_name)
        return dot_path, png_path

    png_path = output_dir / f"{result.repository_name}.png"
    try:
        subprocess.run(
            [dot_binary, "-Tpng", str(dot_path), "-o", str(png_path)],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info("Rendered dependency graph PNG to %s", png_path)
    except subprocess.CalledProcessError as exc:
        logger.warning(
            "Failed to render PNG for %s: %s",
            result.repository_name,
            (exc.stderr or exc.stdout or str(exc)).strip(),
        )
        png_path = None

    return dot_path, png_path
