from __future__ import annotations

import math
import re
from dataclasses import fields
from datetime import datetime, timezone
from typing import Iterable

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
    SemanticDrift,
    SoliditySurface,
)


CATEGORY_ALIASES = {
    "dex": "dexes", "dexes": "dexes", "liquid-staking": "liquid staking", "vault": "yield",
    "vaults": "yield", "perpetuals": "derivatives", "bridge": "bridge", "bridges": "bridge",
    "asset-management": "asset management", "liquidity-management": "liquidity manager",
    "prediction-market": "prediction market", "nft-finance": "nft lending", "solver": "intent",
    "on-chain capital allocator": "onchain capital allocator",
    "on-chain-capital-allocator": "onchain capital allocator",
    "yield aggregator": "yield", "yield-aggregator": "yield",
}
CATEGORY_LENSES: dict[str, dict[str, tuple[str, ...]]] = {
    "lending": {
        "oracle": ("oracle", "pricefeed", "chainlink", "pyth", "twap"),
        "liquidation": ("liquidat", "healthfactor", "ltv", "threshold", "baddebt"),
        "collateral": ("collateral", "borrowcap", "supplycap", "isolation", "emode"),
        "interest-accounting": ("reserveindex", "interestrate", "borrowindex", "accrue", "debt"),
        "flash-loan": ("flashloan", "flash loan"),
    },
    "dexes": {
        "callback-hook": ("callback", "hook", "afterswap", "beforeswap"),
        "liquidity-accounting": ("liquidity", "reserve", "tick", "sqrtprice", "invariant"),
        "router": ("router", "route", "multicall", "swap"),
        "fee-accounting": ("protocolfee", "swapfee", "fee"),
        "oracle": ("oracle", "twap", "observation"),
    },
    "liquid staking": {
        "share-accounting": ("share", "exchangerate", "rebase", "convertto"),
        "withdrawal-queue": ("withdrawalqueue", "redeem", "unstake", "claimwithdrawal"),
        "validator-accounting": ("validator", "slashing", "delegat", "reward"),
        "oracle": ("oracle", "pricefeed"),
    },
    "restaking": {
        "slashing": ("slash", "jail", "penalty"), "delegation": ("delegat", "operator", "strategy"),
        "withdrawal-delay": ("withdraw", "queue", "delay"), "share-accounting": ("share", "exchangerate"),
    },
    "yield": {
        "strategy": ("strategy", "harvest", "rebalance", "allocate"),
        "share-accounting": ("shareprice", "convertto", "totalassets", "pps"),
        "withdrawal": ("withdraw", "redeem", "idlefunds", "queue"),
        "fee-accounting": ("performancefee", "managementfee", "fee"),
        "loss-accounting": ("loss", "debt", "writeoff", "report"),
    },
    "stablecoin": {
        "mint-burn": ("mint", "burn"), "liquidation": ("liquidat", "auction"),
        "oracle": ("oracle", "pricefeed"), "debt-accounting": ("baddebt", "stabilityfee", "interest", "debt"),
        "peg": ("peg", "collateralratio", "redemption"),
    },
    "cdp": {
        "mint-burn": ("mint", "burn"), "liquidation": ("liquidat", "auction"),
        "oracle": ("oracle", "pricefeed"), "debt-accounting": ("baddebt", "stabilityfee", "interest", "debt"),
    },
    "bridge": {
        "message-verification": ("message", "proof", "validator", "signature", "root"),
        "replay-protection": ("nonce", "replay", "processed"), "mint-burn": ("mint", "burn", "lock", "release"),
    },
    "derivatives": {
        "margin": ("margin", "collateral", "leverage"), "liquidation": ("liquidat", "bankrupt"),
        "funding": ("funding", "borrowfee"), "oracle": ("oracle", "pricefeed", "markprice"),
        "pnl-accounting": ("pnl", "profit", "loss", "position"),
    },
    "options": {
        "option-settlement": ("settle", "expiry", "expiration", "exercise"),
        "collateral-margin": ("collateral", "margin", "maintenance"),
        "pricing-volatility": ("volatility", "iv", "blackscholes", "premium", "strike"),
        "oracle": ("oracle", "pricefeed", "markprice"),
    },
    "rwa": {
        "asset-attestation": ("attestation", "reserve", "proof", "custodian"),
        "issuer-permissions": ("issuer", "whitelist", "freeze", "blacklist", "compliance"),
        "redemption": ("redeem", "redemption", "settlement"),
        "valuation": ("nav", "valuation", "oracle", "price"),
    },
    "oracle": {
        "price-validation": ("price", "answer", "round", "deviation", "heartbeat"),
        "staleness": ("stale", "updatedat", "timestamp", "heartbeat"),
        "aggregation": ("median", "aggregate", "quorum", "reporter"),
        "fallback": ("fallback", "secondary", "circuitbreaker"),
    },
    "asset management": {
        "allocation": ("allocate", "rebalance", "weight", "portfolio"),
        "share-accounting": ("share", "nav", "totalassets", "convertto"),
        "strategy": ("strategy", "adapter", "integration"),
        "fees": ("managementfee", "performancefee", "fee"),
    },
    "onchain capital allocator": {
        "allocation": ("allocate", "rebalance", "weight", "market"),
        "strategy": ("strategy", "adapter", "integration"),
        "risk-limits": ("cap", "limit", "exposure", "risk"),
        "accounting": ("share", "totalassets", "profit", "loss"),
    },
    "liquidity manager": {
        "range-management": ("tick", "range", "position", "sqrtprice"),
        "rebalance": ("rebalance", "compound", "harvest"),
        "liquidity-accounting": ("liquidity", "reserve", "share", "amount0", "amount1"),
        "slippage": ("slippage", "minamount", "price", "twap"),
    },
    "intent": {
        "solver-trust": ("solver", "executor", "filler", "relayer"),
        "signature-replay": ("signature", "nonce", "replay", "permit"),
        "settlement": ("settle", "fill", "execute", "callback"),
        "price-bounds": ("quote", "price", "slippage", "minreturn"),
    },
    "aggregator": {
        "router": ("router", "route", "multicall", "executor"),
        "external-call": ("call", "adapter", "target", "calldata"),
        "token-flow": ("transfer", "allowance", "balance", "refund"),
        "slippage": ("slippage", "minreturn", "quote"),
    },
    "insurance": {
        "claims": ("claim", "payout", "incident", "assessment"),
        "capital-accounting": ("capital", "reserve", "solvency", "coverage"),
        "pricing": ("premium", "price", "risk"),
        "governance": ("vote", "adjudicat", "dispute"),
    },
    "prediction market": {
        "resolution": ("resolve", "outcome", "oracle", "dispute"),
        "market-accounting": ("market", "position", "share", "payout"),
        "liquidity": ("liquidity", "amm", "pool"),
    },
    "nft lending": {
        "nft-custody": ("erc721", "erc1155", "nft", "custody"),
        "valuation": ("valuation", "floorprice", "oracle", "appraisal"),
        "liquidation": ("liquidat", "auction", "seize"),
        "loan-accounting": ("loan", "debt", "interest", "repay"),
    },
}
GENERIC_LENSES = {
    "external-call": (".call", "delegatecall", "staticcall", "callback"),
    "access-control": ("onlyowner", "onlyrole", "permission", "authority", "admin"),
    "upgradeability": ("upgrade", "proxy", "implementation", "initialize", "reinitialize"),
    "accounting": ("accounting", "balance", "share", "round", "decimal", "totalassets"),
    "oracle": ("oracle", "price", "twap"), "cross-chain": ("bridge", "crosschain", "message"),
}
SMELL_RULES = {
    "new-external-call": (".call", ".delegatecall", ".staticcall", "safetransfer"),
    "new-callback": ("callback", "hook", "onerc", "tokensreceived"),
    "new-token": ("ierc20", "token", "asset"), "new-oracle": ("oracle", "pricefeed", "chainlink", "pyth"),
    "new-accounting": ("totalassets", "share", "balance", "accrue", "index"),
    "new-price-dependency": ("price", "twap", "latestanswer", "latestRoundData"),
    "new-permission": ("onlyowner", "onlyrole", "grantrole", "authority"),
    "new-upgrade-authority": ("upgrade", "implementation", "proxyadmin"),
    "new-initialization": ("initialize", "reinitialize", "initializer"),
    "storage-layout-change": ("storage", "state variable"), "new-rounding": ("muldiv", "round", "ceil", "floor"),
    "new-decimal-conversion": ("decimal", "1e6", "1e8", "1e18"),
    "new-liquidation-path": ("liquidat", "baddebt"), "new-share-calculation": ("share", "convertto"),
    "new-fee": ("fee", "commission"), "new-withdrawal-path": ("withdraw", "redeem"),
    "new-strategy": ("strategy", "harvest", "rebalance"), "new-bridge": ("bridge", "crosschain"),
    "new-adapter": ("adapter", "connector", "integration"), "new-trust-assumption": ("trusted", "whitelist", "oracle"),
}
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")


def normalize_category(value: str) -> str:
    normalized = re.sub(r"[_\s]+", " ", value.strip().lower())
    return CATEGORY_ALIASES.get(normalized, normalized)


def category_matches(actual: str, requested: str) -> bool:
    wanted = normalize_category(requested)
    if wanted == "all":
        return True
    current = normalize_category(actual)
    return wanted == current or wanted in current or current in wanted


def parse_solidity_surface(source: str) -> SoliditySurface:
    clean = _strip_comments(source)
    compact = re.sub(r"\s+", " ", clean)
    surface = SoliditySurface()
    surface.contracts = sorted(set(re.findall(r"\b(?:contract|interface|library)\s+([A-Za-z_]\w*)", clean)))
    surface.functions = sorted(set(_normalize_signature(match.group(0)) for match in re.finditer(
        r"\bfunction\s+[A-Za-z_]\w*\s*\([^)]*\)(?:\s+(?!(?:returns)\b)[A-Za-z_]\w*(?:\([^)]*\))?)*"
        r"(?:\s+returns\s*\([^)]*\))?", compact
    )))
    surface.modifiers = sorted(set(match.group(1) for match in re.finditer(r"\bmodifier\s+([A-Za-z_]\w*)\s*(?:\([^)]*\))?", compact)))
    surface.events = sorted(set(_normalize_signature(match.group(0)) for match in re.finditer(r"\bevent\s+[A-Za-z_]\w*\s*\([^;]*\)", compact)))
    surface.errors = sorted(set(_normalize_signature(match.group(0)) for match in re.finditer(r"\berror\s+[A-Za-z_]\w*\s*\([^;]*\)", compact)))
    surface.imports = sorted(set(re.findall(r"\bimport\s+(?:[^;]*?from\s+)?[\"']([^\"']+)[\"']\s*;", clean)))
    surface.external_calls = sorted(set(re.findall(
        r"[A-Za-z_][\w.\[\]()]*\.(?:call|delegatecall|staticcall|transfer|send|safeTransfer|safeTransferFrom)\b", clean
    )))
    surface.addresses = sorted(set(address.lower() for address in ADDRESS_RE.findall(clean)))
    surface.state_variables = _state_variables(clean)
    return surface


def semantic_drift(file_pairs: Iterable[tuple[str, str, str]], patches: Iterable[str], category: str) -> SemanticDrift:
    before = SoliditySurface()
    after = SoliditySurface()
    for _, old_source, new_source in file_pairs:
        _merge_surface(before, parse_solidity_surface(old_source))
        _merge_surface(after, parse_solidity_surface(new_source))
    drift = SemanticDrift(
        added_functions=_difference(after.functions, before.functions),
        removed_functions=_difference(before.functions, after.functions),
        added_state_variables=_difference(after.state_variables, before.state_variables),
        removed_state_variables=_difference(before.state_variables, after.state_variables),
        added_imports=_difference(after.imports, before.imports), removed_imports=_difference(before.imports, after.imports),
        added_external_calls=_difference(after.external_calls, before.external_calls),
        removed_external_calls=_difference(before.external_calls, after.external_calls),
        added_addresses=_difference(after.addresses, before.addresses),
    )
    before_by_name = {_function_name(item): item for item in before.functions}
    after_by_name = {_function_name(item): item for item in after.functions}
    drift.changed_functions = sorted(name for name in before_by_name.keys() & after_by_name.keys() if before_by_name[name] != after_by_name[name])
    added_lines = "\n".join(
        line[1:].strip() for patch in patches for line in patch.splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )
    corpus = _compact_security_text("\n".join([added_lines, *drift.added_functions, *drift.added_state_variables,
                                                 *drift.added_imports, *drift.added_external_calls]))
    drift.security_smells = sorted(name for name, terms in SMELL_RULES.items() if any(_compact_security_text(term) in corpus for term in terms))
    if drift.added_state_variables or drift.removed_state_variables:
        drift.security_smells.append("storage-layout-change")
    lens = dict(GENERIC_LENSES)
    lens.update(CATEGORY_LENSES.get(normalize_category(category), {}))
    drift.security_domains = sorted(name for name, terms in lens.items() if any(_compact_security_text(term) in corpus for term in terms))
    drift.integrations = sorted(set(drift.added_imports + drift.added_addresses))
    if drift.added_functions:
        drift.summary.append(f"Added functions: {', '.join(drift.added_functions[:8])}")
    if drift.changed_functions:
        drift.summary.append(f"Changed function signatures: {', '.join(drift.changed_functions[:8])}")
    if drift.added_state_variables:
        drift.summary.append(f"Added state variables: {', '.join(drift.added_state_variables[:8])}")
    if drift.added_external_calls:
        drift.summary.append(f"Added external-call sites: {', '.join(drift.added_external_calls[:8])}")
    if drift.integrations:
        drift.summary.append(f"New imports/addresses: {', '.join(drift.integrations[:8])}")
    return drift


def classify_change(change: Change) -> Change:
    corpus = _compact_security_text("\n".join([change.message, *(item.patch for item in change.files), *change.drift.summary]))
    score, change_type = 3, "contract change"
    rules = (
        (10, "major protocol upgrade", ("majorupgrade", "architecture", "protocolv2", "protocolv3")),
        (9, "new financial primitive", ("newmarket", "newpool", "newvault", "newprimitive")),
        (8, "migration", ("migration", "migrate")),
        (7, "proxy upgrade", ("upgrade", "proxy", "implementation", "reinitialize")),
        (6, "accounting mechanism", ("accounting", "totalassets", "convertto", "exchangerate", "interestrate")),
        (5, "new integration", ("integration", "adapter", "oracle", "collateral", "strategy", "connector")),
        (4, "new contract", ("newcontract", "addcontract")),
    )
    for candidate_score, candidate_type, terms in rules:
        if any(term in corpus for term in terms):
            score, change_type = candidate_score, candidate_type
            break
    if change.drift.added_functions:
        score = max(score, 4)
    if change.drift.added_state_variables:
        score = max(score, 5)
    if change.drift.added_external_calls:
        score = max(score, 5)
    novelty = 0
    if change.drift.integrations:
        novelty = 8
    if any(domain in change.drift.security_domains for domain in ("oracle", "liquidation", "callback-hook", "cross-chain")) and change.drift.integrations:
        novelty = 10
    change.significance = score
    change.change_type = change_type
    change.integration_novelty = novelty
    change.meaningful = bool(change.files) and score >= 3
    return change


def estimate_competition(protocol: Protocol) -> int:
    tvl = min(40, max(0, math.log10(max(protocol.tvl, 1)) - 5) * 12)
    audits = min(35, protocol.audits * 7)
    return round(min(100, tvl + audits))


def freshness_factor(age_days: int) -> float:
    if age_days <= 3: return 1.5
    if age_days <= 7: return 1.3
    if age_days <= 15: return 1.1
    if age_days <= 30: return 1.0
    if age_days <= 60: return 0.7
    return 0.4


def score_candidate(protocol: Protocol, bounty: BountyFinding, scope: ScopeFinding, change: Change,
                    deployments: list[Deployment], now: datetime | None = None) -> Candidate:
    now = now or datetime.now(timezone.utc)
    age_days = max(0, (now - change.committed_at).days)
    competition = estimate_competition(protocol)
    associated = [item for item in deployments if item.associated_commit == change.commit and item.association_status == "ARTIFACT_CHANGED_IN_COMMIT"]
    active = [item for item in associated if item.status == DeploymentStatus.PROXY_ACTIVE]
    onchain = [item for item in associated if item.status in {DeploymentStatus.ONCHAIN_CODE, DeploymentStatus.VERIFIED_SOURCE, DeploymentStatus.PROXY_ACTIVE}]
    deployment_points = 20 if active else (15 if onchain else 0)
    breakdown = ScoreBreakdown(
        bounty=20 if bounty.bounty_type == BountyType.FIRST_PARTY else 0,
        deployment=deployment_points,
        significance=min(20, change.significance * 2 * freshness_factor(age_days)),
        sensitivity=min(15, len(change.drift.security_domains) * 3 + len(change.drift.security_smells)),
        integration=change.integration_novelty,
        value=min(5, max(0, math.log10(max(protocol.tvl, 1)) - 4)),
        low_competition=5 * (1 - competition / 100),
        scope_clarity=5 * scope.confidence if scope.status == "CONFIRMED" else 0,
    )
    failures = []
    if bounty.bounty_type != BountyType.FIRST_PARTY:
        failures.append("first-party bounty not established")
    if not change.meaningful:
        failures.append("meaningful contract change not established")
    evidence_level = EvidenceLevel.E2 if change.meaningful else EvidenceLevel.E1
    if onchain:
        evidence_level = EvidenceLevel.E3
    if active:
        evidence_level = EvidenceLevel.E4
    if active and bounty.bounty_type == BountyType.FIRST_PARTY and change.drift.security_domains:
        evidence_level = EvidenceLevel.E5
    score = breakdown.total
    if failures:
        priority = Priority.IGNORE
    elif not active:
        priority = Priority.WATCHLIST if score >= 55 else Priority.LOW_PRIORITY
    elif score >= 85:
        priority = Priority.TARGET_NOW
    elif score >= 70:
        priority = Priority.HIGH_PRIORITY
    elif score >= 55:
        priority = Priority.WATCHLIST
    else:
        priority = Priority.LOW_PRIORITY
    confidences = [bounty.confidence, *[item.confidence for item in change.evidence]]
    if scope.confidence:
        confidences.append(scope.confidence)
    confidences.extend(item.confidence for deployment in associated for item in deployment.evidence)
    confidence = round(sum(confidences) / len(confidences), 3) if confidences else 0.0
    reasons = [f"{change.change_type} scored {change.significance}/10"] + change.drift.summary[:5]
    if not associated:
        reasons.append("No deployment artifact changed in this commit; production association remains unproven.")
    elif not active:
        reasons.append("Associated address has evidence, but active proxy implementation was not confirmed.")
    else:
        reasons.append("An artifact changed in this commit and its proxy currently points to an on-chain implementation.")
    focus = list(dict.fromkeys(change.drift.security_domains + change.drift.security_smells))[:10]
    return Candidate(protocol, bounty, scope, change, deployments, competition, breakdown, priority,
                     evidence_level, confidence, reasons, focus, failures)


def _strip_comments(source: str) -> str:
    return re.sub(r"//[^\n]*|/\*.*?\*/", "", source, flags=re.S)


def _state_variables(source: str) -> list[str]:
    variables: list[str] = []
    depth = 0
    buffer = ""
    for char in source:
        if char == "{":
            depth += 1
        elif char == "}":
            depth = max(0, depth - 1)
        if depth == 1:
            buffer += char
            if char == ";":
                statement = re.sub(r"\s+", " ", buffer).strip(" {};\n\t")
                buffer = ""
                if statement and not statement.startswith(("using ", "event ", "error ", "import ", "pragma ", "struct ", "enum ")):
                    if "(" not in statement and re.search(r"\b(?:public|private|internal|constant|immutable|mapping|address|uint|int|bool|bytes|string)\b", statement):
                        variables.append(statement[:300])
        elif depth < 1:
            buffer = ""
    return sorted(set(variables))


def _merge_surface(target: SoliditySurface, source: SoliditySurface) -> None:
    for item in fields(SoliditySurface):
        setattr(target, item.name, sorted(set(getattr(target, item.name) + getattr(source, item.name))))


def _difference(first: list[str], second: list[str]) -> list[str]:
    return sorted(set(first) - set(second))


def _normalize_signature(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _function_name(signature: str) -> str:
    match = re.search(r"\bfunction\s+([A-Za-z_]\w*)", signature)
    return match.group(1) if match else signature


def _compact_security_text(value: str) -> str:
    return re.sub(r"[^a-z0-9.$]+", "", value.lower())
