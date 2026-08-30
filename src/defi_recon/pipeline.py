from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from .classifiers import classify_change, score_candidate, semantic_drift
from .deployment import DeploymentVerifier, RpcRegistry, extract_address_artifacts, infer_chain
from .github_source import GitHubSource, is_contract_path
from .models import (
    AddressArtifact,
    BountyType,
    Change,
    Evidence,
    JobStage,
    Protocol,
    ScopeFinding,
)
from .net import HttpClient, RateLimitError, SourceError
from .sources import (
    DefiLlamaSource,
    OfficialSiteResearcher,
    classify_official_github_security,
    extract_scope,
    github_references,
)
from .storage import ReconStore


Progress = Callable[[str], None]


@dataclass(slots=True)
class ResearchOptions:
    category: str = "all"
    protocol_slug: str = ""
    days: int = 30
    top: int = 20
    min_score: int = 55
    min_confidence: float = 0.85
    work_limit: int = 0
    time_budget_seconds: int = 900
    until_complete: bool = False
    max_site_pages: int = 16
    refresh_hours: int = 24
    sync_universe: bool = True
    rpc_config: Path | None = None


@dataclass(slots=True)
class ResearchResult:
    universe_count: int = 0
    new_protocols: int = 0
    queued: int = 0
    processed: int = 0
    completed: int = 0
    retried: int = 0
    targets: list[dict] = field(default_factory=list)
    stopped_reason: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: dict = field(default_factory=dict)


def sync_universe(store: ReconStore, http: HttpClient, refresh_hours: int = 24) -> tuple[int, int]:
    source = DefiLlamaSource(http)
    protocols, payload_hash = source.fetch_universe()
    return store.sync_universe(protocols, f"{source.API}/protocols", payload_hash, refresh_hours)


def run_research(store: ReconStore, options: ResearchOptions, progress: Progress | None = None,
                 http: HttpClient | None = None) -> ResearchResult:
    progress = progress or (lambda _: None)
    http = http or HttpClient()
    result = ResearchResult()
    store.recover_leases()
    if options.sync_universe:
        progress("Syncing the complete DeFiLlama protocol universe (no TVL cutoff or truncation)")
        result.universe_count, result.new_protocols = sync_universe(store, http, options.refresh_hours)
        progress(f"Stored {result.universe_count} DeFiLlama protocols ({result.new_protocols} new)")

    work_items = store.work_items(options.category, options.work_limit, options.protocol_slug)
    result.queued = len(work_items)
    github = GitHubSource(http)
    llama = DefiLlamaSource(http)
    site = OfficialSiteResearcher(http, options.max_site_pages)
    verifier = DeploymentVerifier(http, RpcRegistry.load(options.rpc_config))
    started = time.monotonic()
    budget = 0 if options.until_complete else options.time_budget_seconds

    for index, protocol in enumerate(work_items, 1):
        if budget and time.monotonic() - started >= budget:
            result.stopped_reason = f"time budget of {budget}s reached; rerun to resume"
            break
        progress(f"[{index}/{len(work_items)}] {protocol.name}: official-source discovery")
        store.mark_running(protocol.id)
        try:
            candidates = _research_protocol(protocol, options, store, http, llama, site, github, verifier, progress)
            for candidate in candidates:
                store.save_target(candidate)
            store.mark_complete(protocol.id, options.refresh_hours)
            result.completed += 1
        except RateLimitError as exc:
            store.mark_retry(protocol.id, str(exc), retry_hours=1)
            result.retried += 1
            result.stopped_reason = str(exc) + "; rerun after the reset to resume"
            break
        except SourceError as exc:
            store.mark_retry(protocol.id, str(exc), retry_hours=6 if exc.retryable else 24)
            result.retried += 1
            progress(f"  retry queued: {exc}")
        except KeyboardInterrupt:
            store.mark_retry(protocol.id, "interrupted by user", retry_hours=0)
            raise
        except Exception as exc:
            store.mark_retry(protocol.id, f"{type(exc).__name__}: {exc}", retry_hours=6)
            result.retried += 1
            progress(f"  retry queued after unexpected error: {type(exc).__name__}: {exc}")
        result.processed += 1

    result.targets = store.target_records(options.category, options.days, options.min_score,
                                          options.min_confidence, options.top)
    result.status = store.status()
    return result


def _research_protocol(protocol: Protocol, options: ResearchOptions, store: ReconStore, http: HttpClient,
                       llama: DefiLlamaSource, site: OfficialSiteResearcher, github: GitHubSource,
                       verifier: DeploymentVerifier, progress: Progress) -> list:
    protocol = llama.fetch_detail(protocol)
    discovery = site.research(protocol)
    if discovery.bounty.bounty_type == BountyType.PLATFORM_HOSTED:
        # Official evidence already fails the user's first-party eligibility gate. Preserve the completed
        # record without spending hundreds of GitHub requests on a protocol that cannot enter the target set.
        store.save_discovery(protocol.id, discovery.bounty, discovery.scope, [], discovery.pages)
        progress("  official source confirms a platform-hosted bounty; first-party gate closed")
        return []
    seed_repos, seed_owners = github_references(protocol.github_refs)
    seed_repos.update(discovery.github_repos)
    seed_owners.update(discovery.github_owners)

    progress(f"  GitHub discovery: {len(seed_repos)} direct repositories, {len(seed_owners)} owners")
    repositories = github.discover_repositories(seed_repos, seed_owners) if seed_repos or seed_owners else []
    official_security_pages = []
    security_repositories = [repo for repo in repositories if repo.contract_files > 0 or repo.relevance >= 2][:25]
    for repository in security_repositories:
        # Only accept repository security policy as official after the site/DeFiLlama supplied its repo or owner.
        if repository.source_evidence:
            official_security_pages.extend(github.security_documents(repository))

    bounty = discovery.bounty
    all_scope_pages = list(discovery.pages)
    if bounty.bounty_type != BountyType.FIRST_PARTY and official_security_pages:
        github_bounty = classify_official_github_security(protocol.website, official_security_pages)
        if github_bounty.bounty_type in {BountyType.FIRST_PARTY, BountyType.PLATFORM_HOSTED}:
            bounty = github_bounty
    all_scope_pages.extend(official_security_pages)
    scope = extract_scope(protocol, all_scope_pages, bounty)
    store.save_discovery(protocol.id, bounty, scope, repositories, all_scope_pages)
    progress(f"  bounty={bounty.bounty_type.value}, scope={scope.status}, repositories={len(repositories)}")

    # This is the required eligibility funnel, but every protocol retains its completed evidence record.
    if bounty.bounty_type != BountyType.FIRST_PARTY:
        return []
    contract_repositories = [repo for repo in repositories if repo.contract_files > 0 and repo.relevance > 0]
    if not contract_repositories:
        return []

    store.set_stage(protocol.id, JobStage.CHANGE_SCAN)
    candidates = []
    for repository in contract_repositories:
        checkpoint = store.repo_checkpoint(protocol.id, repository.full_name)
        since = checkpoint - timedelta(minutes=10) if checkpoint else datetime.now(timezone.utc) - timedelta(days=options.days)
        summaries = github.recent_commit_summaries(repository, since)
        latest_commit = str(summaries[0].get("sha") or "") if summaries else ""
        progress(f"  {repository.full_name}: {len(summaries)} commits since {since.date()}")
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="github-commit") as executor:
            for change in executor.map(lambda item: _analyze_commit(protocol, repository, item, github), summaries):
                if change is None:
                    continue
                store.save_change(protocol.id, change)
                if not change.meaningful:
                    continue
                store.set_stage(protocol.id, JobStage.DEPLOYMENT)
                deployments = _deployments_for_change(protocol, repository, change, scope, github, verifier, store)
                store.set_stage(protocol.id, JobStage.ANALYSIS)
                candidate = score_candidate(protocol, bounty, scope, change, deployments)
                if not candidate.gate_failures:
                    candidates.append(candidate)
        store.save_checkpoint(protocol.id, repository.full_name, latest_commit)
    return candidates


def _analyze_commit(protocol: Protocol, repository, summary: dict, github: GitHubSource) -> Change | None:
    sha = str(summary.get("sha") or "")
    if not sha:
        return None
    detail = github.commit_detail(repository, sha)
    all_deltas = github.file_deltas(detail)
    contract_deltas = [item for item in all_deltas if is_contract_path(item.filename)]
    if not contract_deltas:
        return None
    parent = str(((detail.get("parents") or [{}])[0]).get("sha") or "")
    file_pairs = []
    for delta in contract_deltas:
        try:
            old_source = "" if delta.status == "added" or not parent else github.raw_file(
                repository, parent, delta.previous_filename or delta.filename
            )
            new_source = "" if delta.status == "removed" else github.raw_file(repository, sha, delta.filename)
        except SourceError:
            old_source, new_source = "", ""
        file_pairs.append((delta.filename, old_source, new_source))
    drift = semantic_drift(file_pairs, [item.patch for item in contract_deltas], protocol.category)
    commit_data = detail.get("commit") or {}
    message = str(commit_data.get("message") or "").splitlines()[0]
    commit_url = str(detail.get("html_url") or f"https://github.com/{repository.full_name}/commit/{sha}")
    return classify_change(Change(
        repository.full_name, sha, parent, commit_url, github.commit_time(detail), message, all_deltas, drift,
        evidence=[Evidence("GitHub commit and changed production-contract files", sha, commit_url,
                           "github-commit", 1.0, excerpt=message)],
    ))


def _deployments_for_change(protocol: Protocol, repository, change: Change, scope: ScopeFinding,
                            github: GitHubSource, verifier: DeploymentVerifier, store: ReconStore) -> list:
    changed_paths = {item.filename for item in change.files}
    artifacts = github.deployment_artifacts(repository, change.commit)
    address_artifacts = [
        item for item in extract_address_artifacts(protocol, repository.full_name, change.commit, artifacts)
        if item.path in changed_paths
    ]
    # Scope addresses are verified too, but never associated with the commit merely because they are in scope.
    for item in scope.addresses:
        chain_hint = scope.chains[0].value if len(scope.chains) == 1 else (protocol.chains[0] if len(protocol.chains) == 1 else "")
        chain, chain_id = infer_chain(chain_hint, chain_hint, protocol)
        address_artifacts.append(AddressArtifact(
            repository.full_name, change.commit, "official-bounty-scope", item.value, chain, chain_id,
            "in-scope contract", evidence=[item.evidence],
        ))
    unique: dict[tuple[str, int | None], AddressArtifact] = {}
    for artifact in address_artifacts:
        unique[(artifact.address.lower(), artifact.chain_id)] = artifact
    deployments = []
    for artifact in list(unique.values())[:150]:
        deployment = verifier.verify(artifact, change)
        store.save_deployment(protocol.id, deployment)
        deployments.append(deployment)
    return deployments
