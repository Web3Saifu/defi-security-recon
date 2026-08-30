from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .pipeline import ResearchOptions, ResearchResult


def money(value: float) -> str:
    if value >= 1_000_000_000: return f"${value / 1_000_000_000:.2f}B"
    if value >= 1_000_000: return f"${value / 1_000_000:.2f}M"
    if value >= 1_000: return f"${value / 1_000:.2f}K"
    return f"${value:.0f}"


def coverage(status: dict[str, Any]) -> tuple[int, int]:
    total = int(status.get("protocols") or 0)
    complete = sum(int(item["count"]) for item in status.get("jobs", []) if item["state"] == "COMPLETE")
    return complete, total


def render_status(status: dict[str, Any]) -> str:
    complete, total = coverage(status)
    lines = [
        "# DeFiLlama Research - Coverage Status", "", f"- DeFiLlama protocols stored: {total}",
        f"- Protocol research complete: {complete}/{total}",
        f"- Official repositories mapped: {status.get('repositories', 0)}",
        f"- Meaningful changes stored: {status.get('changes', 0)}",
        f"- Deployments checked: {status.get('deployments', 0)}",
        f"- Ranked target records: {status.get('targets', 0)}", "", "## Jobs", "",
    ]
    for item in status.get("jobs", []):
        lines.append(f"- {item['stage']} / {item['state']}: {item['count']}")
    lines.extend(["", "## Bounty classifications", ""])
    for item in status.get("bounties", []):
        lines.append(f"- {item['type']}: {item['count']}")
    return "\n".join(lines) + "\n"


def render_markdown(result: ResearchResult, options: ResearchOptions) -> str:
    complete, total = coverage(result.status)
    lines = [
        "# DeFiLlama Research - Target Report", "", result.generated_at.strftime("%d %b %Y %H:%M UTC"), "",
        "## Coverage", "",
        f"- DeFiLlama universe stored: **{total} protocols**",
        f"- Research pipeline complete: **{complete}/{total} protocols**",
        f"- Processed this run: {result.processed}; completed: {result.completed}; retry queued: {result.retried}",
    ]
    if complete < total:
        lines.extend([
            "", "> **INCOMPLETE UNIVERSE COVERAGE:** this report ranks only protocols whose evidence jobs have completed. "
            "Rerun the resumable crawler; do not interpret missing protocols as rejected targets.",
        ])
    if result.stopped_reason:
        lines.extend(["", f"> Crawl stopped: {result.stopped_reason}"])
    lines.extend([
        "", "## Filters", "", f"- Category: {options.category}", f"- Change window: {options.days} days",
        "- Bounty: first-party only", f"- Minimum score: {options.min_score}",
        f"- Minimum evidence confidence: {options.min_confidence:.0%}", "",
    ])
    if not result.targets:
        lines.extend([
            "## No evidence-qualified targets yet", "",
            "No completed record meets all enabled gates. This is not evidence that no eligible target exists.", "",
        ])
    for index, target in enumerate(result.targets, 1):
        protocol = target["protocol"]
        bounty = target["bounty"]
        scope = target["scope"]
        change = target["change"]
        deployments = target.get("deployments") or []
        lines.extend([
            f"## {index}. {protocol['name']}", "",
            f"- Score: **{sum(float(v) for v in target['breakdown'].values()):.0f}/100**",
            f"- Priority: **{target['priority']}**",
            f"- Evidence level: **{target['evidence_level']}**",
            f"- Confidence: **{float(target['confidence']):.0%}**",
            f"- Category: {protocol['category']}", f"- TVL: {money(float(protocol['tvl']))}",
            f"- First-party bounty: [{bounty['url']}]({bounty['url']})",
            f"- Scope status: {scope['status']}", f"- Repository: `{change['repository']}`",
            f"- Commit: [{change['commit'][:12]}]({change['url']})",
            f"- Commit time: {change['committed_at']}",
            f"- Change: {change['change_type']} ({change['significance']}/10)", "",
            "### Semantic production drift", "",
        ])
        drift = change["drift"]
        for summary in drift.get("summary") or ["No structured semantic delta extracted."]:
            lines.append(f"- {summary}")
        lines.extend(["", "### Security focus", ""])
        for item in target.get("manual_focus") or ["Manual review required"]:
            lines.append(f"- {item}")
        lines.extend(["", "### Deployment evidence", ""])
        associated = [item for item in deployments if item.get("associated_commit") == change["commit"]]
        if not associated:
            lines.append("- **UNPROVEN:** no official deployment artifact changed in this commit and matched on-chain state.")
        for deployment in associated:
            lines.extend([
                f"- `{deployment['address']}` on {deployment['chain']}: **{deployment['status']}**",
                f"  - Association: {deployment['association_status']}",
                f"  - Current implementation: `{deployment.get('implementation_address') or 'not detected'}`",
                f"  - Sourcify verified: {deployment.get('verified_source', False)}",
            ])
        lines.extend(["", "### Evidence sources", ""])
        urls: list[tuple[str, str]] = [
            ("DeFiLlama", protocol["defillama_url"]), ("Official bounty", bounty["url"]),
            ("GitHub commit", change["url"]),
        ]
        for deployment in associated:
            for evidence in deployment.get("evidence") or []:
                urls.append((evidence["source_type"], evidence["source_url"]))
        seen = set()
        for label, url in urls:
            if url and url not in seen:
                lines.append(f"- [{label}]({url})")
                seen.add(url)
        lines.append("")
    lines.extend([
        "## Interpretation", "",
        "A ranked target is a research lead, not a vulnerability claim. `ONCHAIN_CODE` proves bytecode exists; only "
        "`PROXY_ACTIVE` plus `ARTIFACT_CHANGED_IN_COMMIT` supports a current implementation association. "
        "`NO_BOUNTY_FOUND` records unsuccessful discovery and never proves that a bounty does not exist.", "",
    ])
    return "\n".join(lines)


def write_reports(result: ResearchResult, options: ResearchOptions, directory: Path) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    stamp = result.generated_at.strftime("%Y%m%d-%H%M%S")
    category = options.category.lower().replace(" ", "-")
    markdown_path = directory / f"live-recon-{category}-{stamp}.md"
    json_path = directory / f"live-recon-{category}-{stamp}.json"
    markdown_path.write_text(render_markdown(result, options), encoding="utf-8")
    json_path.write_text(json.dumps({
        "mode": "LIVE_ONLY", "generated_at": result.generated_at.isoformat(),
        "coverage": result.status, "stopped_reason": result.stopped_reason,
        "filters": {"category": options.category, "days": options.days, "min_score": options.min_score,
                    "min_confidence": options.min_confidence},
        "targets": result.targets,
    }, indent=2), encoding="utf-8")
    return markdown_path, json_path


def report_from_store(targets: list[dict], status: dict, category: str, days: int,
                      min_score: int, min_confidence: float, top: int) -> tuple[ResearchResult, ResearchOptions]:
    options = ResearchOptions(category=category, days=days, min_score=min_score,
                              min_confidence=min_confidence, top=top, sync_universe=False)
    return ResearchResult(targets=targets, status=status), options
