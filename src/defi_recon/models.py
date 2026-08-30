from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class BountyType(StrEnum):
    FIRST_PARTY = "FIRST_PARTY"
    PLATFORM_HOSTED = "PLATFORM_HOSTED"
    NO_BOUNTY_FOUND = "NO_BOUNTY_FOUND"
    UNKNOWN = "UNKNOWN"


class DeploymentStatus(StrEnum):
    UNKNOWN = "UNKNOWN"
    NOT_DEPLOYED = "NOT_DEPLOYED"
    DEPLOYED = "DEPLOYED"
    ACTIVE = "ACTIVE"
    REPLACED = "REPLACED"


class EvidenceLevel(StrEnum):
    E0 = "E0"
    E1 = "E1"
    E2 = "E2"
    E3 = "E3"
    E4 = "E4"
    E5 = "E5"


class Priority(StrEnum):
    TARGET_NOW = "TARGET_NOW"
    HIGH_PRIORITY = "HIGH_PRIORITY"
    WATCHLIST = "WATCHLIST"
    LOW_PRIORITY = "LOW_PRIORITY"
    IGNORE = "IGNORE"


@dataclass(slots=True)
class Evidence:
    value: Any
    source: str
    source_type: str
    confidence: float
    observed_at: datetime = field(default_factory=utc_now)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["observed_at"] = self.observed_at.isoformat()
        return result


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
    github_repos: list[str] = field(default_factory=list)
    audits: int = 0
    listed_at: datetime | None = None


@dataclass(slots=True)
class BountyFinding:
    bounty_type: BountyType
    url: str = ""
    host: str = ""
    scope_url: str = ""
    scope_status: str = "EVIDENCE_NOT_FOUND"
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(slots=True)
class Change:
    repository: str
    commit: str
    url: str
    committed_at: datetime
    message: str
    changed_files: list[str]
    patches: list[str] = field(default_factory=list)
    change_type: str = "unknown"
    security_domains: list[str] = field(default_factory=list)
    significance: int = 0
    integration_novelty: int = 0
    meaningful: bool = False
    evidence: list[Evidence] = field(default_factory=list)


@dataclass(slots=True)
class Deployment:
    status: DeploymentStatus = DeploymentStatus.UNKNOWN
    chain: str = ""
    contract_address: str = ""
    implementation_address: str = ""
    transaction_hash: str = ""
    deployment_time: datetime | None = None
    evidence: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(slots=True)
class ScopeFinding:
    status: str = "EVIDENCE_NOT_FOUND"
    in_scope: list[Evidence] = field(default_factory=list)
    out_of_scope: list[Evidence] = field(default_factory=list)
    rules: list[Evidence] = field(default_factory=list)
    rewards: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0


@dataclass(slots=True)
class ScoreBreakdown:
    bounty: float = 0
    freshness: float = 0
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
    change: Change
    deployment: Deployment
    scope: ScopeFinding
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

    def to_dict(self) -> dict[str, Any]:
        def encode(value: Any) -> Any:
            if isinstance(value, StrEnum):
                return str(value)
            if isinstance(value, datetime):
                return value.isoformat()
            if hasattr(value, "__dataclass_fields__"):
                return {key: encode(item) for key, item in asdict(value).items()}
            if isinstance(value, list):
                return [encode(item) for item in value]
            if isinstance(value, dict):
                return {key: encode(item) for key, item in value.items()}
            return value

        return encode(self)

