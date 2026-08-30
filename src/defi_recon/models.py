from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def stable_hash(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8", errors="replace")
    return hashlib.sha256(value).hexdigest()


class BountyType(StrEnum):
    FIRST_PARTY = "FIRST_PARTY"
    PLATFORM_HOSTED = "PLATFORM_HOSTED"
    NO_BOUNTY_FOUND = "NO_BOUNTY_FOUND"
    UNKNOWN = "UNKNOWN"


class DeploymentStatus(StrEnum):
    UNCHECKED = "UNCHECKED"
    RPC_UNAVAILABLE = "RPC_UNAVAILABLE"
    NO_CODE = "NO_CODE"
    ONCHAIN_CODE = "ONCHAIN_CODE"
    PROXY_ACTIVE = "PROXY_ACTIVE"
    VERIFIED_SOURCE = "VERIFIED_SOURCE"
    REPLACED = "REPLACED"
    ERROR = "ERROR"


class EvidenceLevel(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"


class JobStage(StrEnum):
    DISCOVERY = "DISCOVERY"
    CHANGE_SCAN = "CHANGE_SCAN"
    DEPLOYMENT = "DEPLOYMENT"
    ANALYSIS = "ANALYSIS"
    COMPLETE = "COMPLETE"


class JobState(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    RETRY = "RETRY"
    COMPLETE = "COMPLETE"
    BLOCKED = "BLOCKED"


class Priority(StrEnum):
    TARGET_NOW = "TARGET_NOW"
    HIGH_PRIORITY = "HIGH_PRIORITY"
    WATCHLIST = "WATCHLIST"
    LOW_PRIORITY = "LOW_PRIORITY"
    IGNORE = "IGNORE"


@dataclass(slots=True)
class Evidence:
    claim: str
    value: Any
    source_url: str
    source_type: str
    confidence: float
    captured_at: datetime = field(default_factory=utc_now)
    excerpt: str = ""
    content_hash: str = ""

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if not self.content_hash and self.excerpt:
            self.content_hash = stable_hash(self.excerpt)


@dataclass(slots=True)
class Protocol:
    id: str
    name: str
    slug: str
    category: str
    chains: list[str]
    tvl: float
    website: str
    defillama_url: str
    symbol: str = ""
    chain_tvls: dict[str, float] = field(default_factory=dict)
    change_1d: float | None = None
    change_7d: float | None = None
    github_refs: list[str] = field(default_factory=list)
    audits: int = 0
    audit_links: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    observed_at: datetime = field(default_factory=utc_now)


@dataclass(slots=True)
class Repository:
    full_name: str
    html_url: str
    default_branch: str = "main"
    description: str = ""
    language: str = ""
    topics: list[str] = field(default_factory=list)
    archived: bool = False
    fork: bool = False
    pushed_at: datetime | None = None
    relevance: int = 0
    contract_files: int = 0
    source_evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class PageDocument:
    url: str
    final_url: str
    title: str
    text: str
    links: list[str]
    sections: dict[str, str]
    fetched_at: datetime = field(default_factory=utc_now)
    content_hash: str = ""

    def __post_init__(self) -> None:
        if not self.content_hash:
            self.content_hash = stable_hash(self.text)


@dataclass(slots=True)
class BountyFinding:
    bounty_type: BountyType
    url: str = ""
    host: str = ""
    submission_url: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    checked_urls: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass(slots=True)
class ScopeItem:
    kind: str
    value: str
    evidence: Evidence


@dataclass(slots=True)
class ScopeFinding:
    status: str = "EVIDENCE_NOT_FOUND"
    in_scope: list[ScopeItem] = field(default_factory=list)
    out_of_scope: list[ScopeItem] = field(default_factory=list)
    rules: list[ScopeItem] = field(default_factory=list)
    rewards: list[ScopeItem] = field(default_factory=list)
    addresses: list[ScopeItem] = field(default_factory=list)
    chains: list[ScopeItem] = field(default_factory=list)
    repositories: list[ScopeItem] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(slots=True)
class FileDelta:
    filename: str
    status: str
    additions: int = 0
    deletions: int = 0
    patch: str = ""
    previous_filename: str = ""


@dataclass(slots=True)
class SoliditySurface:
    contracts: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    state_variables: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SemanticDrift:
    added_functions: list[str] = field(default_factory=list)
    removed_functions: list[str] = field(default_factory=list)
    changed_functions: list[str] = field(default_factory=list)
    added_state_variables: list[str] = field(default_factory=list)
    removed_state_variables: list[str] = field(default_factory=list)
    added_imports: list[str] = field(default_factory=list)
    removed_imports: list[str] = field(default_factory=list)
    added_external_calls: list[str] = field(default_factory=list)
    removed_external_calls: list[str] = field(default_factory=list)
    added_addresses: list[str] = field(default_factory=list)
    security_smells: list[str] = field(default_factory=list)
    security_domains: list[str] = field(default_factory=list)
    integrations: list[str] = field(default_factory=list)
    summary: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Change:
    repository: str
    commit: str
    parent_commit: str
    url: str
    committed_at: datetime
    message: str
    files: list[FileDelta]
    drift: SemanticDrift = field(default_factory=SemanticDrift)
    change_type: str = "unknown"
    significance: int = 0
    integration_novelty: int = 0
    meaningful: bool = False
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class AddressArtifact:
    repository: str
    commit: str
    path: str
    address: str
    chain: str
    chain_id: int | None
    label: str
    transaction_hash: str = ""
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class Deployment:
    address: str
    chain: str
    chain_id: int | None
    status: DeploymentStatus = DeploymentStatus.UNCHECKED
    implementation_address: str = ""
    beacon_address: str = ""
    admin_address: str = ""
    transaction_hash: str = ""
    block_number: int | None = None
    deployment_time: datetime | None = None
    runtime_code_hash: str = ""
    verified_source: bool = False
    source_match: str = ""
    associated_commit: str = ""
    association_status: str = "UNPROVEN"
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    error: str = ""


@dataclass(slots=True)
class ScoreBreakdown:
    bounty: float = 0
    deployment: float = 0
    significance: float = 0
    sensitivity: float = 0
    integration: float = 0
    value: float = 0
    low_competition: float = 0
    scope_clarity: float = 0

    @property
    def total(self) -> int:
        return round(sum(asdict(self).values()))


@dataclass(slots=True)
class Candidate:
    protocol: Protocol
    bounty: BountyFinding
    scope: ScopeFinding
    change: Change
    deployments: list[Deployment]
    competition_score: int
    breakdown: ScoreBreakdown
    priority: Priority
    evidence_level: EvidenceLevel
    confidence: float
    reasons: list[str]
    manual_focus: list[str]
    gate_failures: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        return self.breakdown.total


def to_primitive(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if is_dataclass(value):
        return {key: to_primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, list):
        return [to_primitive(item) for item in value]
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    return value


def json_dumps(value: Any) -> str:
    return json.dumps(to_primitive(value), ensure_ascii=False, separators=(",", ":"))
