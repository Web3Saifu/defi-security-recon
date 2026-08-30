from __future__ import annotations

import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Iterable
from urllib.parse import quote

from .models import Evidence, FileDelta, PageDocument, Repository, parse_datetime
from .net import HttpClient, RateLimitError, SourceError
from .sources import parse_document


CONTRACT_SUFFIXES = (".sol", ".vy", ".move")
DEPLOYMENT_PATH_RE = re.compile(
    r"(?i)(?:^|/)(?:deployments?|addresses?|broadcast|releases?|manifests?|config)(?:/|$)|"
    r"(?:addresses|deployments|contracts|networks|manifest)[^/]*\.(?:json|toml|ya?ml)$"
)
IGNORE_PATH_MARKERS = (
    "/test/", "/tests/", ".t.sol", "/mock/", "/mocks/", "/lib/", "/node_modules/",
    "/vendor/", "/examples/", "/docs/",
)
REPO_SECURITY_TERMS = (
    "contract", "protocol", "solidity", "foundry", "hardhat", "evm", "move", "anchor", "program",
    "vault", "lending", "dex", "staking", "oracle", "bridge", "core", "deployment",
)


class GitHubSource:
    API = "https://api.github.com"

    def __init__(self, http: HttpClient, token: str | None = None, min_remaining: int = 75):
        self.http = http
        self.token = token or os.getenv("GITHUB_TOKEN", "")
        self.min_remaining = min_remaining
        self.rate_remaining: int | None = None
        self._rate_lock = threading.Lock()
        self._tree_cache: dict[tuple[str, str], list[dict[str, Any]]] = {}

    @property
    def headers(self) -> dict[str, str]:
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _get(self, path: str, *, params: dict[str, Any] | None = None, max_bytes: int | None = None) -> Any:
        with self._rate_lock:
            if self.rate_remaining is not None and self.rate_remaining <= self.min_remaining:
                raise RateLimitError(f"GitHub request budget stopped at {self.rate_remaining} remaining")
        response = self.http.get(f"{self.API}{path}", self.headers, params=params, max_bytes=max_bytes, cache=False)
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining and remaining.isdigit():
            with self._rate_lock:
                self.rate_remaining = int(remaining)
        return response.json()

    def repository(self, full_name: str, evidence: list[Evidence] | None = None) -> Repository | None:
        try:
            raw = self._get(f"/repos/{full_name}")
        except SourceError as exc:
            if exc.status == 404:
                return None
            raise
        return self._repository_from_raw(raw, evidence or [])

    def owner_repositories(self, owner: str, max_repositories: int = 300) -> list[Repository]:
        result: list[Repository] = []
        page = 1
        while len(result) < max_repositories:
            try:
                raw_items = self._get(f"/orgs/{owner}/repos", params={"type": "public", "sort": "pushed", "per_page": 100, "page": page})
            except SourceError as exc:
                if exc.status != 404:
                    raise
                raw_items = self._get(f"/users/{owner}/repos", params={"type": "owner", "sort": "pushed", "per_page": 100, "page": page})
            if not raw_items:
                break
            result.extend(self._repository_from_raw(raw, []) for raw in raw_items)
            if len(raw_items) < 100:
                break
            page += 1
        return result[:max_repositories]

    def discover_repositories(self, seeded_repos: Iterable[str], owners: Iterable[str]) -> list[Repository]:
        repositories: dict[str, Repository] = {}
        for full_name in sorted(set(seeded_repos)):
            evidence = [Evidence(
                "official repository link", full_name, f"https://github.com/{full_name}", "official-metadata-or-site-link", 1.0,
            )]
            repository = self.repository(full_name, evidence)
            if repository:
                repository.relevance += 5
                repositories[repository.full_name.lower()] = repository
        for owner in sorted(set(owners)):
            for repository in self.owner_repositories(owner):
                key = repository.full_name.lower()
                if key in repositories:
                    continue
                repository.source_evidence.append(Evidence(
                    "repository belongs to official linked GitHub owner", repository.full_name,
                    f"https://github.com/{owner}", "official-github-owner", 0.9,
                ))
                repositories[key] = repository

        # Inspect plausible and recently pushed repositories. All organization repositories remain represented,
        # while tree evidence decides which ones enter contract change monitoring.
        candidates = sorted(
            (repo for repo in repositories.values() if not repo.archived and not repo.fork),
            key=lambda repo: (repo.relevance, repo.pushed_at or datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True,
        )
        def inspect(repository: Repository) -> tuple[Repository, list[dict[str, Any]]]:
            try:
                return repository, self.tree(repository.full_name, repository.default_branch)
            except SourceError:
                return repository, []

        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="github-tree") as executor:
            futures = [executor.submit(inspect, repository) for repository in candidates]
            for future in as_completed(futures):
                repository, tree = future.result()
                repository.contract_files = sum(
                    1 for item in tree if item.get("type") == "blob" and is_contract_path(str(item.get("path") or ""))
                )
                if repository.contract_files:
                    repository.relevance += min(10, repository.contract_files)
                if any(DEPLOYMENT_PATH_RE.search(str(item.get("path") or "")) for item in tree):
                    repository.relevance += 2
        return sorted(repositories.values(), key=lambda repo: (repo.relevance, repo.contract_files), reverse=True)

    def tree(self, full_name: str, ref: str) -> list[dict[str, Any]]:
        cache_key = (full_name.lower(), ref)
        if cache_key in self._tree_cache:
            return self._tree_cache[cache_key]
        raw = self._get(f"/repos/{full_name}/git/trees/{quote(ref, safe='')}", params={"recursive": "1"}, max_bytes=8_000_000)
        result = list(raw.get("tree") or [])
        self._tree_cache[cache_key] = result
        return result

    def security_documents(self, repository: Repository, max_files: int = 12) -> list[PageDocument]:
        paths = {"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md", "security.md"}
        try:
            tree = self.tree(repository.full_name, repository.default_branch)
        except SourceError:
            tree = []
        for item in tree:
            path = str(item.get("path") or "")
            lower = path.lower()
            if item.get("type") == "blob" and lower.endswith((".md", ".rst", ".txt")) and any(
                term in lower for term in ("security", "bount", "responsible-disclosure", "vulnerability-disclosure")
            ):
                paths.add(path)
        documents: list[PageDocument] = []
        for path in sorted(paths, key=lambda value: ("bount" not in value.lower(), len(value)))[:max_files]:
            try:
                text = self.raw_file(repository, repository.default_branch, path)
            except SourceError:
                continue
            if not text:
                continue
            html_url = f"https://github.com/{repository.full_name}/blob/{repository.default_branch}/{path}"
            documents.append(parse_document(html_url, html_url, text, "text/plain"))
        return documents

    def recent_commit_summaries(self, repository: Repository, since: datetime, max_pages: int = 10) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            items = self._get(
                f"/repos/{repository.full_name}/commits",
                params={"since": since.isoformat().replace("+00:00", "Z"), "per_page": 100, "page": page},
            )
            result.extend(items)
            if len(items) < 100:
                break
        return result

    def commit_detail(self, repository: Repository, sha: str) -> dict[str, Any]:
        return self._get(f"/repos/{repository.full_name}/commits/{sha}", max_bytes=6_000_000)

    def raw_file(self, repository: Repository, ref: str, path: str) -> str:
        safe_path = "/".join(quote(part, safe="") for part in path.split("/"))
        url = f"https://raw.githubusercontent.com/{repository.full_name}/{quote(ref, safe='')}/{safe_path}"
        try:
            return self.http.get(url, max_bytes=2_000_000, cache=False).text
        except SourceError as exc:
            if exc.status == 404:
                return ""
            raise

    def deployment_artifacts(self, repository: Repository, commit: str, max_files: int = 80) -> list[tuple[str, str]]:
        tree = self.tree(repository.full_name, commit)
        paths = [
            str(item.get("path")) for item in tree
            if item.get("type") == "blob" and DEPLOYMENT_PATH_RE.search(str(item.get("path") or ""))
            and int(item.get("size") or 0) <= 1_500_000
        ]
        result: list[tuple[str, str]] = []
        for path in paths[:max_files]:
            lower = path.lower()
            if not lower.endswith((".json", ".toml", ".yaml", ".yml", ".txt", ".md", ".sol")):
                continue
            text = self.raw_file(repository, commit, path)
            if text:
                result.append((path, text))
        return result

    @staticmethod
    def file_deltas(detail: dict[str, Any]) -> list[FileDelta]:
        return [
            FileDelta(
                filename=str(item.get("filename") or ""), status=str(item.get("status") or "modified"),
                additions=int(item.get("additions") or 0), deletions=int(item.get("deletions") or 0),
                patch=str(item.get("patch") or "")[:100_000], previous_filename=str(item.get("previous_filename") or ""),
            )
            for item in detail.get("files") or []
        ]

    @staticmethod
    def commit_time(detail: dict[str, Any]) -> datetime:
        commit = detail.get("commit") or {}
        person = commit.get("committer") or commit.get("author") or {}
        return parse_datetime(person.get("date")) or datetime.now(timezone.utc)

    @staticmethod
    def _repository_from_raw(raw: dict[str, Any], evidence: list[Evidence]) -> Repository:
        corpus = " ".join([
            str(raw.get("name") or ""), str(raw.get("description") or ""),
            str(raw.get("language") or ""), " ".join(raw.get("topics") or []),
        ]).lower()
        relevance = sum(1 for term in REPO_SECURITY_TERMS if term in corpus)
        return Repository(
            full_name=str(raw.get("full_name") or ""), html_url=str(raw.get("html_url") or ""),
            default_branch=str(raw.get("default_branch") or "main"), description=str(raw.get("description") or ""),
            language=str(raw.get("language") or ""), topics=list(raw.get("topics") or []),
            archived=bool(raw.get("archived")), fork=bool(raw.get("fork")),
            pushed_at=parse_datetime(raw.get("pushed_at")), relevance=relevance, source_evidence=evidence,
        )


def is_contract_path(path: str) -> bool:
    normalized = "/" + path.lower().replace("\\", "/")
    if any(marker in normalized for marker in IGNORE_PATH_MARKERS):
        return False
    if normalized.endswith(CONTRACT_SUFFIXES):
        return True
    return normalized.endswith(".rs") and any(marker in normalized for marker in ("/programs/", "/contracts/", "/src/"))
