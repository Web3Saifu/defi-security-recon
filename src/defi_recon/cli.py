from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .pipeline import ResearchOptions, run_research
from .report import render_markdown, write_reports
from .sources import SourceError
from .storage import ReconStore


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defi-recon",
        description="Evidence-first DeFi security target reconnaissance",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    research = subcommands.add_parser("research", help="screen and rank protocols")
    research.add_argument("category", nargs="?", default="all", help="lending, dex, liquid-staking, all, ...")
    research.add_argument("--days", type=int, default=30)
    research.add_argument("--top", type=int, default=10)
    research.add_argument("--min-score", type=int, default=55)
    research.add_argument("--min-confidence", type=float, default=0.85)
    research.add_argument("--min-tvl", type=float, default=1_000_000)
    research.add_argument("--max-protocols", type=int, default=100)
    research.add_argument("--max-commits", type=int, default=12)
    research.add_argument("--include-platform-bounties", action="store_true")
    research.add_argument("--deployment-verified", action="store_true", help="require ACTIVE deployment evidence")
    research.add_argument("--new-integration", action="store_true")
    research.add_argument("--overrides", type=Path, help="evidence overrides JSON")
    research.add_argument("--demo", action="store_true", help="run deterministic offline fixture")
    research.add_argument("--no-save", action="store_true")
    research.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "recon.db")
    research.add_argument("--reports", type=Path, default=PROJECT_ROOT / "reports")
    research.add_argument("--quiet", action="store_true")

    demo = subcommands.add_parser("demo", help="run the offline end-to-end demonstration")
    demo.add_argument("category", nargs="?", default="all")
    demo.add_argument("--reports", type=Path, default=PROJECT_ROOT / "reports")
    demo.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "recon.db")
    demo.add_argument("--no-save", action="store_true")

    history = subcommands.add_parser("history", help="show recent stored runs")
    history.add_argument("--database", type=Path, default=PROJECT_ROOT / "data" / "recon.db")
    history.add_argument("--limit", type=int, default=10)
    return parser


def _validate(options: ResearchOptions) -> None:
    if not 1 <= options.days <= 365:
        raise ValueError("--days must be between 1 and 365")
    if not 1 <= options.top <= 100:
        raise ValueError("--top must be between 1 and 100")
    if not 0 <= options.min_score <= 100:
        raise ValueError("--min-score must be between 0 and 100")
    if not 0 <= options.min_confidence <= 1:
        raise ValueError("--min-confidence must be between 0 and 1")
    if options.max_protocols < 1 or options.max_commits < 1 or options.min_tvl < 0:
        raise ValueError("limits must be positive")


def _research(args: argparse.Namespace) -> int:
    demo = args.command == "demo" or getattr(args, "demo", False)
    options = ResearchOptions(
        category=args.category,
        days=getattr(args, "days", 30),
        top=getattr(args, "top", 10),
        min_score=getattr(args, "min_score", 55),
        min_confidence=getattr(args, "min_confidence", 0.85),
        min_tvl=getattr(args, "min_tvl", 1_000_000),
        max_protocols=getattr(args, "max_protocols", 100),
        max_commits=getattr(args, "max_commits", 12),
        first_party_only=not getattr(args, "include_platform_bounties", False),
        require_deployment=getattr(args, "deployment_verified", False),
        new_integration_only=getattr(args, "new_integration", False),
        demo=demo,
        overrides_path=getattr(args, "overrides", None),
    )
    _validate(options)
    quiet = getattr(args, "quiet", False)
    progress = (lambda message: None) if quiet else (lambda message: print(message, file=sys.stderr))
    result = run_research(options, progress)
    markdown_path, json_path = write_reports(result, options, args.reports)
    if not args.no_save:
        with ReconStore(args.database) as store:
            run_id = store.save(result, options)
        progress(f"stored run {run_id} in {args.database}")
    print(render_markdown(result, options))
    progress(f"wrote {markdown_path} and {json_path}")
    return 0


def _history(args: argparse.Namespace) -> int:
    if not args.database.exists():
        print(f"No database found at {args.database}")
        return 0
    with ReconStore(args.database) as store:
        rows = store.recent_runs(args.limit)
    if not rows:
        print("No saved runs.")
        return 0
    print("ID  GENERATED (UTC)                 CATEGORY        SCANNED  ELIGIBLE  CANDIDATES")
    for row in rows:
        print(
            f"{row['id']:<3} {row['generated_at'][:25]:<31} {row['category']:<15} "
            f"{row['scanned']:<8} {row['eligible']:<9} {row['candidate_count']}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "history":
            return _history(args)
        return _research(args)
    except (ValueError, SourceError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    return 2

