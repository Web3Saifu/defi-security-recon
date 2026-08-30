from __future__ import annotations

import json
import os
import re
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from importlib.resources import files
from ipaddress import ip_address
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener

from .models import (
    BountyFinding,
    BountyType,
    Change,
    Deployment,
    DeploymentStatus,
    Evidence,
    Protocol,
    ScopeFinding,
    parse_datetime,
    utc_now,
)


USER_AGENT = "defi-security-recon/0.1 (+evidence-first research tool)"
PLATFORM_HOSTS = {
    "immunefi.com",
    "sherlock.xyz",
    "cantina.xyz",
    "hackenproof.com",
    "code4rena.com",
    "bugcrowd.com",
    "hackerone.com",
}
BOUNTY_PATHS = (
    "/.well-known/security.txt",
    "/security",
    "/bug-bounty",
    "/security/bug-bounty",
    "/security-researchers",
    "/docs/security",
    "/docs/bug-bounty",
    "/security-policy",
)


class SourceError(RuntimeError):
    pass


@dataclass(slots=True)
class HttpResponse:
    url: str
    status: int
    body: bytes
    content_type: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.text)


def _validate_public_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SourceError(f"unsupported URL: {url}")
    host = parsed.hostname.lower().rstrip(".")
    if host == "localhost" or host.endswith(".localhost"):
        raise SourceError("local URLs are not allowed")
    try:
        address = ip_address(host)
    except ValueError:
        return
    if not address.is_global:
        raise SourceError("non-public IP addresses are not allowed")


class HttpClient:
    def __init__(self, timeout: float = 12, retries: int = 2, max_bytes: int = 2_000_000):
        self.timeout = timeout
        self.retries = retries
        self.max_bytes = max_bytes
        self._opener = build_opener()
        self._cache: dict[str, HttpResponse] = {}

    def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
    ) -> HttpResponse:
        _validate_public_url(url)
        if url in self._cache:
            return self._cache[url]
        request_headers = {"User-Agent": USER_AGENT, "Accept": "application/json,text/html;q=0.9,*/*;q=0.5"}
        request_headers.update(headers or {})
        last_error: Exception | None = None
        response_limit = max_bytes or self.max_bytes
        for attempt in range(self.retries + 1):
            try:
                request = Request(url, headers=request_headers)
                with self._opener.open(request, timeout=self.timeout) as response:
                    final_url = response.geturl()
                    _validate_public_url(final_url)
                    body = response.read(response_limit + 1)
                    if len(body) > response_limit:
                        raise SourceError(f"response exceeded {response_limit} bytes")
                    result = HttpResponse(
                        url=final_url,
                        status=response.status,
                        body=body,
                        content_type=response.headers.get_content_type(),
                    )
                    self._cache[url] = result
                    return result
            except HTTPError as exc:
                if exc.code in {404, 410}:
                    raise SourceError(f"HTTP {exc.code}: {url}") from exc
                last_error = exc
            except (URLError, TimeoutError, ssl.SSLError, SourceError) as exc:
                last_error = exc
            if attempt < self.retries:
                time.sleep(0.25 * (2**attempt))
        raise SourceError(f"failed to fetch {url}: {last_error}")


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "svg"}:
            self._ignored_depth += 1
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth and data.strip():
            self.text_parts.append(data.strip())


def parse_page(html: str, base_url: str) -> tuple[str, list[str]]:
    parser = _PageParser()
    parser.feed(html)
    text = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()
    links = [urljoin(base_url, href) for href in parser.links]
    return text, links


def registrable_host(url: str) -> str:
    # Conservative equality helper; it intentionally does not guess public suffixes.
    host = (urlparse(url).hostname or "").lower().removeprefix("www.")
    return host


def _parse_github_repos(values: Iterable[str]) -> list[str]:
    repos: set[str] = set()
    for value in values:
        match = re.search(r"github\.com/([^/#?]+)/([^/#?]+)", value, re.I)
        if match:
            owner, repo = match.group(1), match.group(2).removesuffix(".git")
            if repo.lower() not in {"orgs", "repositories"}:
                repos.add(f"{owner}/{repo}")
        elif re.fullmatch(r"[\w.-]+/[\w.-]+", value):
            repos.add(value)
    return sorted(repos)


class DefiLlamaSource:
    API = "https://api.llama.fi"

    def __init__(self, http: HttpClient):
        self.http = http

    def protocols(self) -> list[Protocol]:
        payload = self.http.get(f"{self.API}/protocols", max_bytes=25_000_000).json()
        result: list[Protocol] = []
        for raw in payload:
            slug = str(raw.get("slug") or raw.get("name") or raw.get("id"))
            listed = raw.get("listedAt")
            listed_at = datetime.fromtimestamp(listed, timezone.utc) if isinstance(listed, (int, float)) else None
            result.append(
                Protocol(
                    id=str(raw.get("id") or slug),
                    name=str(raw.get("name") or slug),
                    slug=slug,
                    category=str(raw.get("category") or "Unknown"),
                    chains=list(raw.get("chains") or []),
                    tvl=float(raw.get("tvl") or 0),
                    website=str(raw.get("url") or ""),
                    defillama_url=f"https://defillama.com/protocol/{slug}",
                    github_repos=_parse_github_repos(raw.get("github") or []),
                    audits=int(raw.get("audits") or 0) if str(raw.get("audits") or "0").isdigit() else 0,
                    listed_at=listed_at,
                )
            )
        return result

    def enrich(self, protocol: Protocol) -> Protocol:
        try:
            raw = self.http.get(f"{self.API}/protocol/{protocol.slug}").json()
        except (SourceError, json.JSONDecodeError):
            return protocol
        github_values: list[str] = []
        github = raw.get("github")
        if isinstance(github, str):
            github_values.append(github)
        elif isinstance(github, list):
            github_values.extend(str(value) for value in github)
        protocol.github_repos = sorted(set(protocol.github_repos + _parse_github_repos(github_values)))
        return protocol


class BountyDetector:
    def __init__(self, http: HttpClient):
        self.http = http

    def detect(self, protocol: Protocol, override: dict[str, Any] | None = None) -> BountyFinding:
        if override:
            return _bounty_from_override(override)
        if not protocol.website:
            return BountyFinding(BountyType.UNKNOWN)
        base = protocol.website.rstrip("/")
        official_host = registrable_host(base)
        saw_official_site = False
        platform_evidence: list[Evidence] = []
        for path in BOUNTY_PATHS:
            url = urljoin(base + "/", path.lstrip("/"))
            try:
                response = self.http.get(url)
            except SourceError:
                continue
            final_host = registrable_host(response.url)
            if final_host != official_host:
                if any(final_host == host or final_host.endswith("." + host) for host in PLATFORM_HOSTS):
                    platform_evidence.append(Evidence(response.url, response.url, "official-redirect", 0.95))
                continue
            saw_official_site = True
            text, links = parse_page(response.text, response.url)
            corpus = text.lower()
            relevant = "bug bounty" in corpus or ("security" in corpus and "reward" in corpus and "report" in corpus)
            linked_platforms = [link for link in links if any(host in registrable_host(link) for host in PLATFORM_HOSTS)]
            if relevant and linked_platforms:
                platform_evidence.append(
                    Evidence(linked_platforms[0], response.url, "official-bounty-page", 0.96, note="official page links to platform")
                )
                continue
            if relevant:
                evidence = Evidence(
                    value="first-party bug bounty page",
                    source=response.url,
                    source_type="official-bounty-page",
                    confidence=0.94,
                    note="bounty and direct reporting/reward language found on official origin",
                )
                scope_status = "CONFIRMED" if any(term in corpus for term in ("in scope", "out of scope", "scope")) else "EVIDENCE_NOT_FOUND"
                return BountyFinding(
                    bounty_type=BountyType.FIRST_PARTY,
                    url=response.url,
                    host=official_host,
                    scope_url=response.url if scope_status == "CONFIRMED" else "",
                    scope_status=scope_status,
                    evidence=[evidence],
                    confidence=0.94,
                )
        if platform_evidence:
            return BountyFinding(
                bounty_type=BountyType.PLATFORM_HOSTED,
                url=str(platform_evidence[0].value),
                host=registrable_host(str(platform_evidence[0].value)),
                evidence=platform_evidence,
                confidence=max(item.confidence for item in platform_evidence),
            )
        return BountyFinding(
            BountyType.NO_BOUNTY_FOUND if saw_official_site else BountyType.UNKNOWN,
            confidence=0.6 if saw_official_site else 0.0,
        )


class ScopeExtractor:
    def __init__(self, http: HttpClient):
        self.http = http

    def extract(self, bounty: BountyFinding) -> ScopeFinding:
        if bounty.bounty_type != BountyType.FIRST_PARTY or not bounty.url:
            return ScopeFinding()
        try:
            response = self.http.get(bounty.scope_url or bounty.url)
        except SourceError:
            return ScopeFinding()
        text, _ = parse_page(response.text, response.url)
        patterns = {
            "in_scope": r"(?i)(?:in[ -]scope|eligible (?:assets|targets|impacts?))\s*[:\-]?\s*(.{10,500}?)(?=out[ -]of[ -]scope|rules?|rewards?|$)",
            "out_of_scope": r"(?i)(?:out[ -]of[ -]scope|excluded)\s*[:\-]?\s*(.{10,500}?)(?=in[ -]scope|rules?|rewards?|$)",
            "rules": r"(?i)(?:rules?|testing restrictions?|responsible disclosure)\s*[:\-]?\s*(.{10,500}?)(?=rewards?|in[ -]scope|out[ -]of[ -]scope|$)",
            "rewards": r"(?i)(?:rewards?|severity)\s*[:\-]?\s*(.{10,500}?)(?=rules?|in[ -]scope|out[ -]of[ -]scope|$)",
        }
        found: dict[str, list[Evidence]] = {key: [] for key in patterns}
        for key, pattern in patterns.items():
            match = re.search(pattern, text)
            if match:
                value = match.group(1).strip(" :-")[:500]
                found[key].append(Evidence(value, response.url, "official-bounty-page", 0.9))
        confirmed = bool(found["in_scope"] or found["out_of_scope"])
        populated = sum(bool(value) for value in found.values())
        return ScopeFinding(
            status="CONFIRMED" if confirmed else "EVIDENCE_NOT_FOUND",
            in_scope=found["in_scope"],
            out_of_scope=found["out_of_scope"],
            rules=found["rules"],
            rewards=found["rewards"],
            confidence=round(min(0.95, 0.55 + populated * 0.1), 2) if populated else 0,
        )


class GitHubSource:
    API = "https://api.github.com"

    def __init__(self, http: HttpClient, token: str | None = None):
        self.http = http
        self.token = token or os.getenv("GITHUB_TOKEN", "")

    @property
    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def recent_changes(self, repository: str, days: int, max_commits: int = 12) -> list[Change]:
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat().replace("+00:00", "Z")
        url = f"{self.API}/repos/{repository}/commits?since={since}&per_page={max_commits}"
        try:
            commits = self.http.get(url, self.headers).json()
        except (SourceError, json.JSONDecodeError):
            return []
        result: list[Change] = []
        for item in commits[:max_commits]:
            sha = str(item.get("sha") or "")
            if not sha:
                continue
            try:
                detail = self.http.get(f"{self.API}/repos/{repository}/commits/{sha}", self.headers).json()
            except (SourceError, json.JSONDecodeError):
                continue
            commit_data = detail.get("commit") or {}
            author = commit_data.get("committer") or commit_data.get("author") or {}
            timestamp = parse_datetime(author.get("date")) or utc_now()
            file_data = detail.get("files") or []
            filenames = [str(value.get("filename")) for value in file_data if value.get("filename")]
            patches = [str(value.get("patch"))[:20_000] for value in file_data if value.get("patch")]
            evidence = Evidence(
                value=sha,
                source=str(detail.get("html_url") or item.get("html_url") or ""),
                source_type="github-commit",
                confidence=0.92,
            )
            result.append(
                Change(
                    repository=repository,
                    commit=sha,
                    url=evidence.source,
                    committed_at=timestamp,
                    message=str(commit_data.get("message") or "").splitlines()[0],
                    changed_files=filenames,
                    patches=patches,
                    evidence=[evidence],
                )
            )
        return result


def _bounty_from_override(raw: dict[str, Any]) -> BountyFinding:
    bounty_type = BountyType(raw.get("type", "UNKNOWN"))
    url = str(raw.get("url") or "")
    confidence = float(raw.get("confidence") or 0)
    evidence = []
    if url:
        evidence.append(Evidence(raw.get("claim", bounty_type.value), url, "manual-official-source", confidence))
    return BountyFinding(
        bounty_type=bounty_type,
        url=url,
        host=registrable_host(url),
        scope_url=str(raw.get("scope_url") or url),
        scope_status=str(raw.get("scope_status") or "EVIDENCE_NOT_FOUND"),
        evidence=evidence,
        confidence=confidence,
    )


def deployment_from_override(raw: dict[str, Any] | None) -> Deployment:
    if not raw:
        return Deployment()
    source = str(raw.get("source") or "")
    confidence = float(raw.get("confidence") or 0)
    status = DeploymentStatus(raw.get("status", "UNKNOWN"))
    evidence = []
    if source:
        evidence.append(Evidence(status.value, source, "manual-on-chain-source", confidence))
    return Deployment(
        status=status,
        chain=str(raw.get("chain") or ""),
        contract_address=str(raw.get("contract_address") or ""),
        implementation_address=str(raw.get("implementation_address") or ""),
        transaction_hash=str(raw.get("transaction_hash") or ""),
        deployment_time=parse_datetime(raw.get("deployment_time")),
        evidence=evidence,
        confidence=confidence,
    )


def load_demo_fixture() -> dict[str, Any]:
    fixture = files("defi_recon").joinpath("fixtures/demo.json")
    return json.loads(fixture.read_text(encoding="utf-8"))


def protocol_from_dict(raw: dict[str, Any]) -> Protocol:
    return Protocol(
        id=str(raw["id"]),
        name=str(raw["name"]),
        slug=str(raw["slug"]),
        category=str(raw["category"]),
        chains=list(raw.get("chains") or []),
        tvl=float(raw.get("tvl") or 0),
        website=str(raw.get("website") or ""),
        defillama_url=str(raw.get("defillama_url") or ""),
        github_repos=list(raw.get("github_repos") or []),
        audits=int(raw.get("audits") or 0),
        listed_at=parse_datetime(raw.get("listed_at")),
    )


def change_from_dict(raw: dict[str, Any]) -> Change:
    source = str(raw.get("url") or "")
    return Change(
        repository=str(raw["repository"]),
        commit=str(raw["commit"]),
        url=source,
        committed_at=parse_datetime(raw["committed_at"]) or utc_now(),
        message=str(raw.get("message") or ""),
        changed_files=list(raw.get("changed_files") or []),
        patches=list(raw.get("patches") or []),
        evidence=[Evidence(raw["commit"], source, "fixture-github-commit", float(raw.get("confidence") or 0.9))],
    )
