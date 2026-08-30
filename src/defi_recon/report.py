from __future__ import annotations

import json
from pathlib import Path

from .models import Candidate, DeploymentStatus
from .pipeline import ResearchOptions, ResearchResult


PRIORITY_LABELS = {
    "TARGET_NOW": "TARGET NOW",
    "HIGH_PRIORITY": "HIGH PRIORITY",
    "WATCHLIST": "WATCHLIST",
    "LOW_PRIORITY": "LOW PRIORITY",
    "IGNORE": "IGNORE",
}


def money(value: float) -> str:
    if value >= 1_000_000_000:
        return f"${value / 1_000_000_000:.2f}B"
    if value >= 1_000_000:
        return f"${value / 1_000_000:.2f}M"
    if value >= 1_000:
        return f"${value / 1_000:.2f}K"
    return f"${value:.0f}"


def _source_list(candidate: Candidate) -> list[str]:
    urls: list[tuple[str, str]] = []
    if candidate.bounty.url:
        urls.append(("Official bounty", candidate.bounty.url))
    if candidate.change.url:
        urls.append(("GitHub commit", candidate.change.url))
    for item in candidate.deployment.evidence:
        if item.source:
            urls.append(("Deployment evidence", item.source))
    if candidate.protocol.defillama_url:
        urls.append(("DeFiLlama", candidate.protocol.defillama_url))
    deduped: list[str] = []
    seen: set[str] = set()
    for label, url in urls:
        if url not in seen:
            deduped.append(f"[{label}]({url})")
            seen.add(url)
    return deduped


def render_markdown(result: ResearchResult, options: ResearchOptions) -> str:
    lines = [
        "# DeFi Security Target Report",
        "",
        result.generated_at.strftime("%d %b %Y %H:%M UTC"),
        "",
        "## Filters",
        "",
        f"- Category: {options.category}",
        f"- Bounty: {'first-party only' if options.first_party_only else 'all bounty states'}",
        f"- Change window: {options.days} days",
        f"- Active deployment required: {'yes' if options.require_deployment else 'no (unverified leads are capped at WATCHLIST)'}",
        f"- Minimum score: {options.min_score}",
        f"- Minimum confidence: {options.min_confidence:.0%}",
        f"- Universe screened: {result.scanned}; bounty-eligible: {result.eligible}",
        "",
    ]
    if not result.candidates:
        lines.extend(
            [
                "## No qualifying candidates",
                "",
                "No protocol met every enabled evidence gate. This is not evidence that no opportunity exists.",
                "",
            ]
        )
    for index, candidate in enumerate(result.candidates, 1):
        protocol, change = candidate.protocol, candidate.change
        lines.extend(
            [
                f"## {index}. {protocol.name}",
                "",
                f"- Score: **{candidate.score}/100**",
                f"- Priority: **{PRIORITY_LABELS[candidate.priority.value]}**",
                f"- Evidence level: **{candidate.evidence_level.value}**",
                f"- Confidence: **{candidate.confidence:.0%}**",
                f"- Category: {protocol.category}",
                f"- TVL: {money(protocol.tvl)}",
                f"- Competition heuristic: {candidate.competition_score}/100",
                f"- First-party bounty: {'confirmed' if candidate.bounty.bounty_type.value == 'FIRST_PARTY' else candidate.bounty.bounty_type.value}",
                f"- Recent change: {change.committed_at.strftime('%d %b %Y')}",
                f"- Change: {change.change_type} ({change.significance}/10 significance)",
                f"- Repository: `{change.repository}`",
                f"- Commit: `{change.commit[:12]}`",
                f"- Deployment: {candidate.deployment.status.value}",
                f"- Scope: {candidate.scope.status}",
                "",
                "Why it is interesting:",
                "",
            ]
        )
        lines.extend(f"- {reason}" for reason in candidate.reasons)
        lines.extend(["", "Recommended manual focus:", ""])
        lines.extend(f"{number}. {focus}" for number, focus in enumerate(candidate.manual_focus, 1))
        lines.extend(["", "Changed contracts:", ""])
        lines.extend(f"- `{name}`" for name in change.changed_files[:12])
        lines.extend(["", "Evidence:", ""])
        lines.extend(f"- {source}" for source in _source_list(candidate))
        if candidate.deployment.status == DeploymentStatus.UNKNOWN:
            lines.extend(
                [
                    "",
                    "> Deployment is not verified. Do not treat this code change as production-active until on-chain evidence is added.",
                ]
            )
        lines.append("")
    if result.warnings:
        lines.extend(["## Collection warnings", ""])
        lines.extend(f"- {warning}" for warning in result.warnings[:50])
        lines.append("")
    lines.extend(
        [
            "## Evidence policy",
            "",
            "`NO_BOUNTY_FOUND` means the crawler found no evidence; it does not claim that no bounty exists. "
            "Scores prioritize recon leads, not proof of a vulnerability. On-chain and official evidence must override heuristics.",
            "",
        ]
    )
    return "\n".join(lines)


def write_reports(result: ResearchResult, options: ResearchOptions, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = result.generated_at.strftime("%Y%m%d-%H%M%S")
    category = options.category.lower().replace(" ", "-")
    markdown_path = directory / f"recon-{category}-{stamp}.md"
    json_path = directory / f"recon-{category}-{stamp}.json"
    markdown_path.write_text(render_markdown(result, options), encoding="utf-8")
    payload = {
        "generated_at": result.generated_at.isoformat(),
        "filters": {
            "category": options.category,
            "days": options.days,
            "top": options.top,
            "min_score": options.min_score,
            "min_confidence": options.min_confidence,
            "first_party_only": options.first_party_only,
            "require_deployment": options.require_deployment,
        },
        "counts": {"scanned": result.scanned, "eligible": result.eligible, "candidates": len(result.candidates)},
        "warnings": result.warnings,
        "candidates": [candidate.to_dict() for candidate in result.candidates],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return markdown_path, json_path

