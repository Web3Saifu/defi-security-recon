from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .classifiers import category_matches, classify_change, score_candidate
from .models import BountyType, Candidate, ScopeFinding
from .sources import (
    BountyDetector,
    DefiLlamaSource,
    GitHubSource,
    HttpClient,
    ScopeExtractor,
    SourceError,
    change_from_dict,
    deployment_from_override,
    load_demo_fixture,
    parse_page,
    protocol_from_dict,
    _parse_github_repos,
)


@dataclass(slots=True)
class ResearchOptions:
    category: str = "all"
    days: int = 30
    top: int = 10
    min_score: int = 55
    min_confidence: float = 0.85
    min_tvl: float = 1_000_000
    max_protocols: int = 100
    max_commits: int = 12
    first_party_only: bool = True
    require_deployment: bool = False
    new_integration_only: bool = False
    demo: bool = False
    overrides_path: Path | None = None


@dataclass(slots=True)
class ResearchResult:
    candidates: list[Candidate]
    scanned: int
    eligible: int
    warnings: list[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


Progress = Callable[[str], None]


def load_overrides(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        raise ValueError(f"override file does not exist: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("override file must be a JSON object keyed by protocol slug")
    return data


def discover_repositories(protocol, http: HttpClient) -> list[str]:
    repos = list(protocol.github_repos)
    if protocol.website:
        try:
            response = http.get(protocol.website)
            _, links = parse_page(response.text, response.url)
            repos.extend(_parse_github_repos(links))
        except SourceError:
            pass
    return sorted(set(repos))


def _fixture_scope(raw: dict[str, Any] | None) -> ScopeFinding:
    if not raw:
        return ScopeFinding()
    from .models import Evidence

    source = str(raw.get("source") or "")
    confidence = float(raw.get("confidence") or 0)

    def evidence_list(key: str) -> list[Evidence]:
        return [Evidence(value, source, "fixture-official-bounty-page", confidence) for value in raw.get(key, [])]

    return ScopeFinding(
        status=str(raw.get("status") or "EVIDENCE_NOT_FOUND"),
        in_scope=evidence_list("in_scope"),
        out_of_scope=evidence_list("out_of_scope"),
        rules=evidence_list("rules"),
        rewards=evidence_list("rewards"),
        confidence=confidence,
    )


def _run_demo(options: ResearchOptions, progress: Progress) -> ResearchResult:
    fixture = load_demo_fixture()
    candidates: list[Candidate] = []
    scanned = 0
    eligible = 0
    from .sources import _bounty_from_override

    for raw in fixture["protocols"]:
        protocol = protocol_from_dict(raw)
        if not category_matches(protocol.category, options.category) or protocol.tvl < options.min_tvl:
            continue
        scanned += 1
        bounty = _bounty_from_override(raw["bounty"])
        if options.first_party_only and bounty.bounty_type != BountyType.FIRST_PARTY:
            continue
        eligible += 1
        deployment = deployment_from_override(raw.get("deployment"))
        scope = _fixture_scope(raw.get("scope"))
        for raw_change in raw.get("changes", []):
            change = classify_change(change_from_dict(raw_change), protocol.category)
            if not change.meaningful:
                continue
            candidate = score_candidate(
                protocol,
                bounty,
                change,
                deployment,
                scope,
                require_first_party=options.first_party_only,
                require_deployment=options.require_deployment,
            )
            if options.new_integration_only and not change.integration_novelty:
                continue
            if not candidate.gate_failures and candidate.score >= options.min_score and candidate.confidence >= options.min_confidence:
                candidates.append(candidate)
    progress(f"demo: screened {scanned} protocols; {eligible} passed bounty eligibility")
    candidates.sort(key=lambda item: (item.score, item.confidence), reverse=True)
    return ResearchResult(candidates[: options.top], scanned, eligible)


def run_research(options: ResearchOptions, progress: Progress | None = None) -> ResearchResult:
    progress = progress or (lambda _: None)
    if options.demo:
        return _run_demo(options, progress)

    overrides = load_overrides(options.overrides_path)
    http = HttpClient()
    llama = DefiLlamaSource(http)
    bounty_detector = BountyDetector(http)
    scope_extractor = ScopeExtractor(http)
    github = GitHubSource(http)
    warnings: list[str] = []

    progress("fetching DeFiLlama protocol universe")
    protocols = [
        protocol
        for protocol in llama.protocols()
        if category_matches(protocol.category, options.category) and protocol.tvl >= options.min_tvl
    ]
    protocols.sort(key=lambda item: item.tvl, reverse=True)
    protocols = protocols[: options.max_protocols]
    scanned = len(protocols)
    eligible = 0
    candidates: list[Candidate] = []

    for index, protocol in enumerate(protocols, 1):
        progress(f"[{index}/{scanned}] screening {protocol.name}")
        override = overrides.get(protocol.slug, {})
        bounty = bounty_detector.detect(protocol, override.get("bounty"))
        if options.first_party_only and bounty.bounty_type != BountyType.FIRST_PARTY:
            continue
        eligible += 1
        scope = _fixture_scope(override.get("scope")) if override.get("scope") else scope_extractor.extract(bounty)
        protocol = llama.enrich(protocol)
        if override.get("github_repos"):
            protocol.github_repos = sorted(set(protocol.github_repos + list(override["github_repos"])))
        repositories = discover_repositories(protocol, http)
        if not repositories:
            warnings.append(f"{protocol.name}: no GitHub repository evidence found")
            continue

        changes = []
        for repository in repositories[:3]:
            changes.extend(github.recent_changes(repository, options.days, options.max_commits))
        classified = [classify_change(change, protocol.category) for change in changes]
        meaningful = [change for change in classified if change.meaningful]
        if not meaningful:
            continue
        meaningful.sort(key=lambda item: (item.significance, item.committed_at), reverse=True)
        deployment = deployment_from_override(override.get("deployment"))
        for change in meaningful[:3]:
            candidate = score_candidate(
                protocol,
                bounty,
                change,
                deployment,
                scope,
                require_first_party=options.first_party_only,
                require_deployment=options.require_deployment,
            )
            if options.new_integration_only and not change.integration_novelty:
                continue
            if not candidate.gate_failures and candidate.score >= options.min_score and candidate.confidence >= options.min_confidence:
                candidates.append(candidate)

    candidates.sort(key=lambda item: (item.score, item.confidence), reverse=True)
    return ResearchResult(candidates[: options.top], scanned, eligible, warnings)
