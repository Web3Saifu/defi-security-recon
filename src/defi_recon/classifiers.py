from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from pathlib import PurePosixPath

from .models import (
    BountyFinding,
    BountyType,
    Candidate,
    Change,
    Deployment,
    DeploymentStatus,
    EvidenceLevel,
    Priority,
    Protocol,
    ScopeFinding,
    ScoreBreakdown,
)


CATEGORY_ALIASES = {
    "all": "all",
    "dex": "dexes",
    "dexes": "dexes",
    "lending": "lending",
    "liquid-staking": "liquid staking",
    "liquid staking": "liquid staking",
    "restaking": "restaking",
    "yield": "yield",
    "vault": "yield",
    "vaults": "yield",
    "stablecoin": "stablecoin",
    "rwa": "rwa",
    "derivatives": "derivatives",
    "perpetuals": "derivatives",
    "options": "options",
    "bridge": "bridge",
    "bridges": "bridge",
    "oracle": "oracle",
    "asset-management": "asset management",
    "cdp": "cdp",
    "liquidity-management": "liquidity manager",
    "intent": "intent",
    "solver": "intent",
    "aggregator": "aggregator",
    "insurance": "insurance",
    "prediction-market": "prediction market",
    "nft-finance": "nft lending",
}

CATEGORY_LENSES = {
    "lending": {
        "oracle": ("oracle", "price feed", "chainlink", "pyth"),
        "liquidation": ("liquidat", "health factor", "ltv", "threshold"),
        "collateral": ("collateral", "borrow cap", "supply cap", "isolation", "e-mode"),
        "accounting": ("reserve index", "interest rate", "debt", "accru", "accounting"),
        "flash-loan": ("flashloan", "flash loan"),
    },
    "dexes": {
        "callback": ("callback", "hook"),
        "liquidity-accounting": ("liquidity", "reserve", "tick", "sqrtprice", "accounting"),
        "router": ("router", "route", "swap"),
        "fees": ("fee", "protocolfee"),
        "oracle": ("oracle", "twap"),
    },
    "liquid staking": {
        "share-accounting": ("share", "exchange rate", "rebase"),
        "withdrawal-queue": ("withdrawal queue", "redeem", "unstake"),
        "validator-accounting": ("validator", "slashing", "delegat", "reward"),
        "oracle": ("oracle", "price feed"),
    },
    "yield": {
        "strategy": ("strategy", "harvest", "rebalance"),
        "share-accounting": ("share price", "convertto", "totalassets", "accounting"),
        "withdrawal": ("withdraw", "redeem", "idle funds"),
        "fees": ("performance fee", "management fee", "fee"),
        "loss-accounting": ("loss", "debt", "write-off"),
    },
    "stablecoin": {
        "mint-burn": ("mint", "burn"),
        "liquidation": ("liquidat", "auction"),
        "oracle": ("oracle", "price feed"),
        "debt-accounting": ("bad debt", "stability fee", "interest", "debt"),
        "peg": ("peg", "collateral ratio"),
    },
    "cdp": {
        "mint-burn": ("mint", "burn"),
        "liquidation": ("liquidat", "auction"),
        "oracle": ("oracle", "price feed"),
        "debt-accounting": ("bad debt", "stability fee", "interest", "debt"),
    },
}

GENERIC_LENS = {
    "external-call": ("external call", ".call(", "delegatecall", "callback"),
    "access-control": ("onlyowner", "role", "permission", "authority"),
    "upgradeability": ("upgrade", "proxy", "implementation", "initialize"),
    "accounting": ("accounting", "balance", "share", "round", "decimal"),
    "oracle": ("oracle", "price", "twap"),
    "cross-chain": ("bridge", "cross-chain", "message"),
}

INTEGRATION_SIGNALS = {
    "external-protocol": (10, ("integration", "integrate", "connector")),
    "oracle": (10, ("new oracle", "chainlink", "pyth", "price feed")),
    "token-or-collateral": (8, ("new collateral", "add asset", "new token")),
    "strategy": (8, ("new strategy", "add strategy")),
    "chain": (6, ("new chain", "deploy to", "deployment")),
    "adapter": (8, ("new adapter", "adapter")),
    "liquidation": (10, ("new liquidation", "liquidation mechanism")),
    "accounting": (10, ("accounting mechanism", "accounting model")),
    "router": (7, ("new router", "router")),
}


def normalize_category(value: str) -> str:
    normalized = re.sub(r"[_\s]+", " ", value.strip().lower()).replace("—", "-")
    return CATEGORY_ALIASES.get(normalized, normalized)


def category_matches(actual: str, requested: str) -> bool:
    wanted = normalize_category(requested)
    if wanted == "all":
        return True
    current = normalize_category(actual)
    return current == wanted or wanted in current or current in wanted


def _is_contract_file(filename: str) -> bool:
    path = filename.lower().replace("\\", "/")
    return path.endswith((".sol", ".vy", ".move", ".rs")) and not any(
        marker in path for marker in ("/test/", "/tests/", ".t.sol", "/mock/", "/mocks/")
    )


def classify_change(change: Change, category: str) -> Change:
    filenames = [name.replace("\\", "/") for name in change.changed_files]
    contract_files = [name for name in filenames if _is_contract_file(name)]
    corpus = "\n".join([change.message, *filenames, *change.patches]).lower()

    if not contract_files:
        change.change_type = "non-contract"
        change.significance = 0
        change.meaningful = False
        return change

    rules = (
        (10, "major protocol upgrade", ("major upgrade", "v2 migration", "v3 migration", "architecture")),
        (9, "new financial primitive", ("new market", "new pool", "new vault", "new primitive")),
        (8, "migration", ("migration", "migrate")),
        (7, "proxy upgrade", ("upgrade", "proxy", "implementation")),
        (6, "accounting mechanism", ("accounting", "totalassets", "convertto", "exchange rate", "interest rate")),
        (5, "new integration", ("integration", "adapter", "oracle", "collateral", "strategy")),
        (4, "new contract", ("new contract", "add contract", "create mode", "initial commit")),
    )
    score, change_type = 3, "contract change"
    for candidate_score, candidate_type, terms in rules:
        if any(term in corpus for term in terms):
            score, change_type = candidate_score, candidate_type
            break

    lens = dict(GENERIC_LENS)
    lens.update(CATEGORY_LENSES.get(normalize_category(category), {}))
    domains = [domain for domain, terms in lens.items() if any(term in corpus for term in terms)]

    novelty = 0
    for _, (weight, terms) in INTEGRATION_SIGNALS.items():
        if any(term in corpus for term in terms):
            novelty = max(novelty, weight)

    change.change_type = change_type
    change.significance = score
    change.security_domains = sorted(set(domains))
    change.integration_novelty = novelty
    change.meaningful = score >= 3
    return change


def freshness_factor(age_days: int) -> float:
    if age_days <= 3:
        return 1.5
    if age_days <= 7:
        return 1.3
    if age_days <= 15:
        return 1.1
    if age_days <= 30:
        return 1.0
    if age_days <= 60:
        return 0.7
    return 0.4


def estimate_competition(protocol: Protocol) -> int:
    # Explicitly a heuristic, never evidence of actual researcher activity.
    tvl_component = min(40, max(0, math.log10(max(protocol.tvl, 1)) - 5) * 12)
    audit_component = min(30, protocol.audits * 6)
    age_component = 0
    if protocol.listed_at:
        years = max(0, (datetime.now(timezone.utc) - protocol.listed_at).days / 365)
        age_component = min(20, years * 4)
    return round(min(100, tvl_component + audit_component + age_component))


def evidence_level(bounty: BountyFinding, change: Change, deployment: Deployment) -> EvidenceLevel:
    sensitive = bool(change.security_domains)
    if (
        bounty.bounty_type == BountyType.FIRST_PARTY
        and deployment.status == DeploymentStatus.ACTIVE
        and sensitive
    ):
        return EvidenceLevel.E5
    if deployment.status == DeploymentStatus.ACTIVE:
        return EvidenceLevel.E4
    if deployment.status == DeploymentStatus.DEPLOYED:
        return EvidenceLevel.E3
    if change.meaningful:
        return EvidenceLevel.E2
    if change.commit:
        return EvidenceLevel.E1
    return EvidenceLevel.E0


def _priority(score: int, deployment: Deployment, gate_failures: list[str]) -> Priority:
    if gate_failures:
        return Priority.IGNORE
    if deployment.status != DeploymentStatus.ACTIVE:
        # A code-only lead is never promoted as an immediately auditable target.
        return Priority.WATCHLIST if score >= 55 else Priority.LOW_PRIORITY
    if score >= 85:
        return Priority.TARGET_NOW
    if score >= 70:
        return Priority.HIGH_PRIORITY
    if score >= 55:
        return Priority.WATCHLIST
    if score >= 40:
        return Priority.LOW_PRIORITY
    return Priority.IGNORE


def score_candidate(
    protocol: Protocol,
    bounty: BountyFinding,
    change: Change,
    deployment: Deployment,
    scope: ScopeFinding,
    now: datetime | None = None,
    require_first_party: bool = True,
    require_deployment: bool = False,
) -> Candidate:
    now = now or datetime.now(timezone.utc)
    age_days = max(0, (now - change.committed_at).days)
    competition = estimate_competition(protocol)
    scope_points = 5 * scope.confidence if scope.status == "CONFIRMED" else 0
    breakdown = ScoreBreakdown(
        bounty=20 if bounty.bounty_type == BountyType.FIRST_PARTY else 0,
        freshness=min(20, 13.34 * freshness_factor(age_days)),
        significance=change.significance * 2,
        sensitivity=min(15, len(change.security_domains) * 4),
        integration=change.integration_novelty,
        value=min(5, max(0, math.log10(max(protocol.tvl, 1)) - 4)),
        low_competition=5 * (1 - competition / 100),
        scope_clarity=scope_points,
    )
    failures: list[str] = []
    if require_first_party and bounty.bounty_type != BountyType.FIRST_PARTY:
        failures.append("first-party bounty not established")
    if not change.meaningful:
        failures.append("no meaningful smart-contract change")
    if require_deployment and deployment.status != DeploymentStatus.ACTIVE:
        failures.append("active production deployment not established")

    confidence_inputs = [bounty.confidence]
    confidence_inputs.extend(item.confidence for item in change.evidence)
    if deployment.evidence:
        confidence_inputs.append(deployment.confidence)
    if scope.confidence:
        confidence_inputs.append(scope.confidence)
    confidence = round(sum(confidence_inputs) / max(1, len(confidence_inputs)), 2)

    reasons = [f"{change.change_type} scored {change.significance}/10"]
    if change.security_domains:
        reasons.append("Security-sensitive domains: " + ", ".join(change.security_domains))
    if change.integration_novelty:
        reasons.append(f"New trust-boundary signal scored {change.integration_novelty}/10")
    if deployment.status == DeploymentStatus.ACTIVE:
        reasons.append("Production-active deployment has evidence")
    else:
        reasons.append("Production deployment is unverified; treat as a watch lead")

    focus = change.security_domains[:5]
    if not focus:
        focus = [PurePosixPath(name).stem for name in change.changed_files[:5]]

    priority = _priority(breakdown.total, deployment, failures)
    return Candidate(
        protocol=protocol,
        bounty=bounty,
        change=change,
        deployment=deployment,
        scope=scope,
        competition_score=competition,
        breakdown=breakdown,
        priority=priority,
        evidence_level=evidence_level(bounty, change, deployment),
        confidence=confidence,
        reasons=reasons,
        manual_focus=focus,
        gate_failures=failures,
    )
