"""Fetch repository popularity from GitHub."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

from code_guardian.models import Popularity

logger = logging.getLogger(__name__)

_GITHUB_RE = re.compile(
    r"^(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


def parse_github_repo(url: str) -> tuple[str, str] | None:
    url = url.strip().rstrip("/")
    if url.startswith("git@"):
        # git@github.com:owner/repo.git
        match = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?$", url)
        if match:
            return match.group("owner"), match.group("repo").removesuffix(".git")
        return None

    parsed = urlparse(url if "://" in url else f"https://{url}")
    path = parsed.path.strip("/")
    if parsed.netloc not in ("github.com", "www.github.com") or "/" not in path:
        return None
    owner, repo = path.split("/", 1)
    return owner, repo.removesuffix(".git")


def fetch_popularity(repo_url: str, timeout: float = 10.0) -> Popularity:
    parsed = parse_github_repo(repo_url)
    if not parsed:
        logger.info("Skipping popularity lookup for non-GitHub repo: %s", repo_url)
        return Popularity(source="unavailable")

    owner, repo = parsed
    api_url = f"https://api.github.com/repos/{owner}/{repo}"
    logger.debug("Fetching GitHub metadata from %s", api_url)

    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(
                api_url,
                headers={"Accept": "application/vnd.github+json"},
            )
            if response.status_code == 404:
                logger.warning("GitHub repo not found: %s/%s", owner, repo)
                return Popularity(source="github-not-found")
            response.raise_for_status()
            data = response.json()
            return Popularity(
                stars=data.get("stargazers_count"),
                forks=data.get("forks_count"),
                source="github",
            )
    except httpx.HTTPError as exc:
        logger.warning("Failed to fetch GitHub popularity for %s: %s", repo_url, exc)
        return Popularity(source="github-error")
