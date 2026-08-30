from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .net import HttpClient, SourceError
from .pipeline import ResearchOptions, run_research, sync_universe
from .report import render_markdown, render_status, report_from_store, write_reports
from .storage import ReconStore


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DB = PROJECT_ROOT / "data" / "recon-v2.db"
DEFAULT_REPORTS = PROJECT_ROOT / "reports"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="defi-recon", description="Live evidence-first DeFi security reconnaissance V1-V5")
    commands = parser.add_subparsers(dest="command", required=True)

    sync = commands.add_parser("sync", help="store every protocol returned by DeFiLlama")
    sync.add_argument("--database", type=Path, default=DEFAULT_DB)

    research = commands.add_parser("research", help="resume live research jobs and produce a target report")
    research.add_argument("category", nargs="?", default="all")
    research.add_argument("--slug", default="", help="research one exact DeFiLlama slug")
    research.add_argument("--days", type=int, default=30)
    research.add_argument("--top", type=int, default=20)
    research.add_argument("--min-score", type=int, default=55)
    research.add_argument("--min-confidence", type=float, default=0.85)
    research.add_argument("--work-limit", type=int, default=0, help="0 means every currently queued protocol")
    research.add_argument(
        "--time-budget", type=int, default=900,
        help="soft seconds checked between protocol jobs; ignored by --until-complete",
    )
    research.add_argument("--until-complete", action="store_true", help="continue until the queue is empty or a source rate limit stops it")
    research.add_argument("--max-site-pages", type=int, default=16)
    research.add_argument("--refresh-hours", type=int, default=24)
    research.add_argument("--no-sync", action="store_true")
    research.add_argument("--rpc-config", type=Path)
    research.add_argument("--database", type=Path, default=DEFAULT_DB)
    research.add_argument("--reports", type=Path, default=DEFAULT_REPORTS)
    research.add_argument("--quiet", action="store_true")

    status = commands.add_parser("status", help="show full-universe research coverage")
    status.add_argument("--database", type=Path, default=DEFAULT_DB)

    report = commands.add_parser("report", help="regenerate a report from verified stored records")
    report.add_argument("category", nargs="?", default="all")
    report.add_argument("--days", type=int, default=30)
    report.add_argument("--top", type=int, default=20)
    report.add_argument("--min-score", type=int, default=55)
    report.add_argument("--min-confidence", type=float, default=0.85)
    report.add_argument("--database", type=Path, default=DEFAULT_DB)
    report.add_argument("--reports", type=Path, default=DEFAULT_REPORTS)

    protocol = commands.add_parser("protocol", help="show the stored evidence record for one DeFiLlama slug")
    protocol.add_argument("slug")
    protocol.add_argument("--database", type=Path, default=DEFAULT_DB)
    return parser


def _validate(args: argparse.Namespace) -> None:
    for name in ("days", "top"):
        if hasattr(args, name) and getattr(args, name) < 1:
            raise ValueError(f"--{name.replace('_', '-')} must be positive")
    if hasattr(args, "min_score") and not 0 <= args.min_score <= 100:
        raise ValueError("--min-score must be between 0 and 100")
    if hasattr(args, "min_confidence") and not 0 <= args.min_confidence <= 1:
        raise ValueError("--min-confidence must be between 0 and 1")
    if hasattr(args, "work_limit") and args.work_limit < 0:
        raise ValueError("--work-limit cannot be negative")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _validate(args)
        if args.command == "sync":
            with ReconStore(args.database) as store:
                total, new = sync_universe(store, HttpClient())
                print(f"Stored the complete DeFiLlama universe: {total} protocols ({new} new).")
                print(render_status(store.status()))
            return 0
        if args.command == "status":
            if not args.database.exists():
                print(f"No V2 database at {args.database}. Run `defi-recon sync` first.")
                return 1
            with ReconStore(args.database) as store:
                print(render_status(store.status()))
            return 0
        if args.command == "protocol":
            with ReconStore(args.database) as store:
                record = store.protocol_record(args.slug)
            if record is None:
                print(f"Protocol slug not found: {args.slug}", file=sys.stderr)
                return 1
            print(json.dumps(record, indent=2))
            return 0
        if args.command == "report":
            with ReconStore(args.database) as store:
                targets = store.target_records(args.category, args.days, args.min_score, args.min_confidence, args.top)
                result, options = report_from_store(targets, store.status(), args.category, args.days,
                                                    args.min_score, args.min_confidence, args.top)
            markdown, machine = write_reports(result, options, args.reports)
            print(render_markdown(result, options))
            print(f"Wrote {markdown} and {machine}", file=sys.stderr)
            return 0

        options = ResearchOptions(
            category=args.category, protocol_slug=args.slug, days=args.days, top=args.top, min_score=args.min_score,
            min_confidence=args.min_confidence, work_limit=args.work_limit,
            time_budget_seconds=args.time_budget, until_complete=args.until_complete,
            max_site_pages=args.max_site_pages, refresh_hours=args.refresh_hours,
            sync_universe=not args.no_sync, rpc_config=args.rpc_config,
        )
        if not os.getenv("GITHUB_TOKEN") and not args.quiet:
            print("Warning: GITHUB_TOKEN is unset; GitHub's unauthenticated rate limit will stop a full crawl early.", file=sys.stderr)
        progress = (lambda _: None) if args.quiet else (lambda message: print(message, file=sys.stderr, flush=True))
        with ReconStore(args.database) as store:
            result = run_research(store, options, progress)
        markdown, machine = write_reports(result, options, args.reports)
        print(render_markdown(result, options))
        progress(f"Wrote {markdown} and {machine}")
        return 0
    except (ValueError, SourceError, RuntimeError) as exc:
        parser.error(str(exc))
    except KeyboardInterrupt:
        database = getattr(args, "database", None)
        if database:
            try:
                with ReconStore(database) as store:
                    store.recover_leases(0)
            except Exception:
                pass
        print("Interrupted; completed jobs are saved and the queue can be resumed.", file=sys.stderr)
        return 130
    return 2
