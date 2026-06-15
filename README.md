# Code Guardian

A CLI that wraps [Trivy](https://github.com/aquasecurity/trivy) to scan one or more Git repositories, print a concise stdout summary, and write per-repository result files with vulnerability details and a Graphviz dependency graph (CRITICAL packages highlighted).

Built for the OX Security home assignment — focused on clear engineering trade-offs rather than feature sprawl.

## Quick start (Docker — recommended)

```bash
docker build -t code-guardian .
```

### Interactive mode (prompts for repos)

```bash
docker compose run --rm -it code-guardian scan \
  --output-dir /results \
  --cache-dir /trivy-cache
```

You will be asked:

```
Enter one or more Git repository URLs to scan.
Separate multiple repos with spaces or commas.
Repository URL(s): https://github.com/OWASP/NodeGoat https://github.com/david-kocharyan/yophonepy
```

### Pass repos directly (non-interactive)

```bash
docker run --rm \
  -v "$(pwd)/results:/results" \
  -v code-guardian-cache:/trivy-cache \
  code-guardian scan \
  --output-dir /results \
  --cache-dir /trivy-cache \
  https://github.com/OWASP/NodeGoat
```

Scan multiple repositories in parallel:

```bash
docker run --rm \
  -v "$(pwd)/results:/results" \
  -v code-guardian-cache:/trivy-cache \
  code-guardian scan -w 3 \
  --output-dir /results \
  --cache-dir /trivy-cache \
  https://github.com/OWASP/NodeGoat \
  https://github.com/OWASP/railsgoat \
  https://github.com/david-kocharyan/yophonepy
```

### Output

**Stdout** — one line per repository with severity counts and GitHub popularity:

```
✓ https://github.com/OWASP/NodeGoat (★ 1234 / forks 567) — CRITICAL=2 HIGH=5 MEDIUM=3 LOW=1 (total 11)
```

**Per-repo files** in `--output-dir` (default `./results`):

| File | Contents |
|------|----------|
| `{repo}.json` | Repository metadata, popularity, severity stats, full vulnerability list |
| `{repo}.dot` | Graphviz dependency graph (CRITICAL nodes in red) |
| `{repo}.png` | Rendered graph (when Graphviz `dot` is available) |

## Quick start (local)

Requirements: Python 3.11+, [Trivy](https://aquasecurity.github.io/trivy/latest/getting-started/installation/), optional [Graphviz](https://graphviz.org/) for PNG rendering.

This project uses **pip** (not Poetry).

### 1. Install dependencies

```bash
cd /path/to/ox_task

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

pip install -e .
```

Install Trivy and Graphviz (macOS example):

```bash
brew install trivy graphviz
```

Verify:

```bash
trivy --version
code-guardian --help
```

### 2. Interactive mode (prompts for repos)

```bash
code-guardian scan -o results --cache-dir .trivy-cache
```

You will be asked:

```
Enter one or more Git repository URLs to scan.
Separate multiple repos with spaces or commas.
Repository URL(s): https://github.com/OWASP/NodeGoat https://github.com/david-kocharyan/yophonepy
```

### 3. Pass repos directly (non-interactive)

Single repository:

```bash
code-guardian scan \
  -o results \
  --cache-dir .trivy-cache \
  https://github.com/OWASP/NodeGoat
```

Multiple repositories in parallel:

```bash
code-guardian scan -w 3 \
  -o results \
  --cache-dir .trivy-cache \
  https://github.com/OWASP/NodeGoat \
  https://github.com/OWASP/railsgoat \
  https://github.com/david-kocharyan/yophonepy
```

Results are written to `./results/` (JSON, DOT, and PNG files).

## CLI reference

```
code-guardian scan [REPO ...] [OPTIONS]

If no REPO arguments are given, the CLI prompts interactively for one or more URLs
(space- or comma-separated).

Options:
  -o, --output-dir PATH   Result directory (default: results)
  -w, --workers INT       Parallel scans (default: 2)
  --trivy-path PATH       Explicit Trivy binary
  --timeout INT           Per-repo timeout in seconds (default: 600)
  --cache-dir PATH        Shared Trivy cache (speeds up repeat runs)
  --log-level LEVEL       DEBUG | INFO | WARNING | ERROR
  --no-png                Skip PNG render; still writes .dot
  --summary-table         Rich table at end (default: on)
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | All repositories scanned successfully |
| `1` | Partial failure (some repos failed, others succeeded) |
| `2` | Total failure or fatal error (e.g. Trivy missing, bad arguments) |

Vulnerabilities do **not** change the exit code — this tool reports findings; it is not a CI gate.

## Design decisions & trade-offs

### Architecture

Small, layered modules with no framework beyond Typer:

- `trivy` — subprocess wrapper + JSON parsing (keeps Trivy as the source of truth)
- `github` — popularity lookup (isolated, easy to mock)
- `graph` — DOT generation + optional PNG via system `dot`
- `runner` — orchestration and per-repo error isolation
- `report` — stdout + JSON artifacts

**Why not a plugin framework or async?** The workload is subprocess- and network-bound; a `ThreadPoolExecutor` gives most of the parallelism benefit with simpler failure modes. A heavier architecture would not demonstrate better judgment for this scope.

### Trivy integration

- Uses `trivy repo` so we do not manage clones ourselves — fewer moving parts, Trivy handles cache and updates.
- Parses JSON once into typed dataclasses; large outputs are streamed to memory as a single JSON blob. For very large monorepos this could be swapped for `ijson` streaming without changing the CLI contract.
- Accepts exit code `1` (vulnerabilities found) as success — only infrastructure failures are errors.

### Handling multiple repositories

- Default `--workers 2` balances speed vs. CPU/memory (each Trivy scan is heavy).
- Shared `--cache-dir` avoids re-downloading vulnerability DB and git metadata across runs.
- Each repo is isolated: a bad URL or scan failure writes an error result file and does not abort siblings.

### Resilience

| Failure | Behavior |
|---------|----------|
| Unreachable / invalid repo | Per-repo error in JSON + stderr log; continue |
| Trivy missing | Fail fast before spawning workers (exit 2) |
| Malformed Trivy JSON | Per-repo error |
| Maven/npm registry 429 | Per-repo error with retry guidance (common for Java repos in large batches) |
| GitHub API down | Popularity marked `github-error`; scan continues |
| Graphviz missing | DOT still written; PNG skipped with warning |

### Operability

- Structured logging to **stderr** (stdout reserved for human summaries).
- `--log-level` for troubleshooting without code changes.
- Docker image bundles Trivy, git, and Graphviz — the intended shipping unit.

### Output format

JSON per repository rather than one combined file:

- Easier to diff, archive, and feed downstream tools per repo.
- Embeds artifact paths for DOT/PNG.
- Graphviz DOT is also written standalone for manual `dot -Tpng` rendering.

### What I deliberately did not build

- Web UI, database, or scheduled scans
- SARIF/CSV exporters (JSON is enough for the assignment)
- Private registry auth for non-public repos
- Custom severity policy / CI gate exit codes

These are reasonable extensions but would dilute the assignment's focus on CLI design, resilience, and packaging.

## License

MIT
