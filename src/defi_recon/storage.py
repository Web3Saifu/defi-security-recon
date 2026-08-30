from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator

from .classifiers import category_matches
from .models import (
    BountyFinding,
    Candidate,
    Change,
    Deployment,
    JobStage,
    JobState,
    Protocol,
    Repository,
    ScopeFinding,
    json_dumps,
    parse_datetime,
    to_primitive,
    utc_now,
)


SCHEMA_VERSION = 2
SCHEMA = """
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS universe_runs (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    protocol_count INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    payload_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS protocols (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    chains_json TEXT NOT NULL,
    tvl REAL NOT NULL,
    website TEXT NOT NULL,
    defillama_url TEXT NOT NULL,
    symbol TEXT NOT NULL,
    github_refs_json TEXT NOT NULL,
    audits INTEGER NOT NULL,
    raw_json TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    universe_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_protocols_category ON protocols(category);
CREATE INDEX IF NOT EXISTS idx_protocols_tvl ON protocols(tvl DESC);
CREATE TABLE IF NOT EXISTS protocol_jobs (
    protocol_id TEXT PRIMARY KEY REFERENCES protocols(id) ON DELETE CASCADE,
    stage TEXT NOT NULL,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    next_scan_at TEXT,
    leased_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_work ON protocol_jobs(state,stage,next_scan_at);
CREATE TABLE IF NOT EXISTS pages (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    final_url TEXT NOT NULL,
    title TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    fetched_at TEXT NOT NULL,
    relevant INTEGER NOT NULL,
    PRIMARY KEY(protocol_id,url)
);
CREATE TABLE IF NOT EXISTS bounties (
    protocol_id TEXT PRIMARY KEY REFERENCES protocols(id) ON DELETE CASCADE,
    bounty_type TEXT NOT NULL,
    bounty_url TEXT NOT NULL,
    submission_url TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    checked_urls_json TEXT NOT NULL,
    checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS scope_items (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    group_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(protocol_id,group_name,kind,value)
);
CREATE TABLE IF NOT EXISTS repositories (
    full_name TEXT PRIMARY KEY,
    html_url TEXT NOT NULL,
    default_branch TEXT NOT NULL,
    description TEXT NOT NULL,
    language TEXT NOT NULL,
    topics_json TEXT NOT NULL,
    archived INTEGER NOT NULL,
    fork INTEGER NOT NULL,
    pushed_at TEXT,
    relevance INTEGER NOT NULL,
    contract_files INTEGER NOT NULL,
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS protocol_repositories (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL REFERENCES repositories(full_name) ON DELETE CASCADE,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY(protocol_id,full_name)
);
CREATE TABLE IF NOT EXISTS repo_checkpoints (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL,
    last_scanned_at TEXT NOT NULL,
    latest_commit TEXT NOT NULL,
    PRIMARY KEY(protocol_id,full_name)
);
CREATE TABLE IF NOT EXISTS changes (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    parent_commit TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    meaningful INTEGER NOT NULL,
    significance INTEGER NOT NULL,
    change_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    PRIMARY KEY(protocol_id,repository,commit_sha)
);
CREATE INDEX IF NOT EXISTS idx_changes_recent ON changes(committed_at DESC,meaningful);
CREATE TABLE IF NOT EXISTS deployments (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    chain_id INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    associated_commit TEXT NOT NULL,
    association_status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    checked_at TEXT NOT NULL,
    PRIMARY KEY(protocol_id,address,chain_id)
);
CREATE TABLE IF NOT EXISTS targets (
    protocol_id TEXT NOT NULL REFERENCES protocols(id) ON DELETE CASCADE,
    repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    score INTEGER NOT NULL,
    priority TEXT NOT NULL,
    evidence_level TEXT NOT NULL,
    confidence REAL NOT NULL,
    target_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(protocol_id,repository,commit_sha)
);
"""


class ReconStore:
    def __init__(self, path: Path | str):
        self.path = Path(path) if path != ":memory:" else Path(":memory:")
        if path != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(SCHEMA)
        existing = self.connection.execute("SELECT value FROM metadata WHERE key='schema_version'").fetchone()
        if existing and int(existing["value"]) != SCHEMA_VERSION:
            raise RuntimeError(f"database schema {existing['value']} is incompatible with {SCHEMA_VERSION}")
        self.connection.execute(
            "INSERT INTO metadata(key,value) VALUES('schema_version',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "ReconStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def sync_universe(self, protocols: list[Protocol], source_url: str, payload_hash: str, refresh_hours: int) -> tuple[int, int]:
        now = utc_now().isoformat()
        new_count = 0
        with self.transaction() as connection:
            for protocol in protocols:
                existing = connection.execute("SELECT id FROM protocols WHERE id=?", (protocol.id,)).fetchone()
                if not existing:
                    new_count += 1
                connection.execute(
                    """INSERT INTO protocols VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(id) DO UPDATE SET slug=excluded.slug,name=excluded.name,category=excluded.category,
                       chains_json=excluded.chains_json,tvl=excluded.tvl,website=excluded.website,
                       defillama_url=excluded.defillama_url,symbol=excluded.symbol,
                       github_refs_json=excluded.github_refs_json,audits=excluded.audits,raw_json=excluded.raw_json,
                       universe_seen_at=excluded.universe_seen_at""",
                    (
                        protocol.id, protocol.slug, protocol.name, protocol.category, json_dumps(protocol.chains),
                        protocol.tvl, protocol.website, protocol.defillama_url, protocol.symbol,
                        json_dumps(protocol.github_refs), protocol.audits, json_dumps(protocol.raw), now, now,
                    ),
                )
                job = connection.execute("SELECT state,next_scan_at FROM protocol_jobs WHERE protocol_id=?", (protocol.id,)).fetchone()
                due = not job or not job["next_scan_at"] or job["next_scan_at"] <= now
                if not job:
                    connection.execute(
                        "INSERT INTO protocol_jobs(protocol_id,stage,state,updated_at) VALUES(?,?,?,?)",
                        (protocol.id, JobStage.DISCOVERY.value, JobState.PENDING.value, now),
                    )
                elif due and job["state"] in {JobState.COMPLETE.value, JobState.BLOCKED.value}:
                    connection.execute(
                        "UPDATE protocol_jobs SET stage=?,state=?,last_error='',updated_at=? WHERE protocol_id=?",
                        (JobStage.DISCOVERY.value, JobState.PENDING.value, now, protocol.id),
                    )
            connection.execute(
                "INSERT INTO universe_runs(started_at,completed_at,protocol_count,source_url,payload_hash) VALUES(?,?,?,?,?)",
                (now, now, len(protocols), source_url, payload_hash),
            )
        return len(protocols), new_count

    def work_items(self, category: str = "all", limit: int = 0, slug: str = "") -> list[Protocol]:
        now = utc_now().isoformat()
        parameters: list[Any] = [JobState.PENDING.value, JobState.RETRY.value, now]
        where = "j.state IN (?,?) AND (j.next_scan_at IS NULL OR j.next_scan_at<=?)"
        if slug:
            where += " AND p.slug=?"
            parameters.append(slug)
        sql = f"SELECT p.* FROM protocols p JOIN protocol_jobs j ON j.protocol_id=p.id WHERE {where} ORDER BY p.tvl DESC"
        protocols = [
            self._row_protocol(row)
            for row in self.connection.execute(sql, parameters).fetchall()
            if category_matches(row["category"], category)
        ]
        return protocols[:limit] if limit > 0 else protocols

    def mark_running(self, protocol_id: str) -> None:
        self.connection.execute(
            "UPDATE protocol_jobs SET state=?,leased_at=?,updated_at=? WHERE protocol_id=?",
            (JobState.RUNNING.value, utc_now().isoformat(), utc_now().isoformat(), protocol_id),
        )
        self.connection.commit()

    def set_stage(self, protocol_id: str, stage: JobStage) -> None:
        self.connection.execute(
            "UPDATE protocol_jobs SET stage=?,state=?,updated_at=? WHERE protocol_id=?",
            (stage.value, JobState.RUNNING.value, utc_now().isoformat(), protocol_id),
        )
        self.connection.commit()

    def mark_complete(self, protocol_id: str, refresh_hours: int = 24) -> None:
        now = utc_now()
        self.connection.execute(
            """UPDATE protocol_jobs SET stage=?,state=?,last_error='',updated_at=?,next_scan_at=?,leased_at=NULL
               WHERE protocol_id=?""",
            (JobStage.COMPLETE.value, JobState.COMPLETE.value, now.isoformat(),
             (now + timedelta(hours=refresh_hours)).isoformat(), protocol_id),
        )
        self.connection.commit()

    def mark_retry(self, protocol_id: str, error: str, retry_hours: int = 6) -> None:
        now = utc_now()
        self.connection.execute(
            """UPDATE protocol_jobs SET state=?,attempts=attempts+1,last_error=?,updated_at=?,next_scan_at=?,leased_at=NULL
               WHERE protocol_id=?""",
            (JobState.RETRY.value, error[:1000], now.isoformat(), (now + timedelta(hours=retry_hours)).isoformat(), protocol_id),
        )
        self.connection.commit()

    def recover_leases(self, older_than_minutes: int = 60) -> int:
        cutoff = (utc_now() - timedelta(minutes=older_than_minutes)).isoformat()
        cursor = self.connection.execute(
            "UPDATE protocol_jobs SET state=?,leased_at=NULL WHERE state=? AND leased_at<?",
            (JobState.RETRY.value, JobState.RUNNING.value, cutoff),
        )
        self.connection.commit()
        return cursor.rowcount

    def save_discovery(self, protocol_id: str, bounty: BountyFinding, scope: ScopeFinding,
                       repositories: list[Repository], pages: list[Any]) -> None:
        now = utc_now().isoformat()
        with self.transaction() as connection:
            for page in pages:
                relevant = int(any(term in page.text.lower() for term in ("bug bounty", "in scope", "security policy")))
                connection.execute(
                    "INSERT OR REPLACE INTO pages VALUES(?,?,?,?,?,?,?)",
                    (protocol_id, page.url, page.final_url, page.title, page.content_hash, page.fetched_at.isoformat(), relevant),
                )
            connection.execute(
                "INSERT OR REPLACE INTO bounties VALUES(?,?,?,?,?,?,?,?,?)",
                (protocol_id, bounty.bounty_type.value, bounty.url, bounty.submission_url, bounty.confidence,
                 bounty.reason, json_dumps(bounty.evidence), json_dumps(bounty.checked_urls), now),
            )
            connection.execute("DELETE FROM scope_items WHERE protocol_id=?", (protocol_id,))
            for group_name in ("in_scope", "out_of_scope", "rules", "rewards", "addresses", "chains", "repositories"):
                for item in getattr(scope, group_name):
                    connection.execute(
                        "INSERT OR REPLACE INTO scope_items VALUES(?,?,?,?,?)",
                        (protocol_id, group_name, item.kind, item.value, json_dumps(item.evidence)),
                    )
            for repository in repositories:
                connection.execute(
                    """INSERT INTO repositories VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(full_name) DO UPDATE SET html_url=excluded.html_url,default_branch=excluded.default_branch,
                       description=excluded.description,language=excluded.language,topics_json=excluded.topics_json,
                       archived=excluded.archived,fork=excluded.fork,pushed_at=excluded.pushed_at,relevance=excluded.relevance,
                       contract_files=excluded.contract_files,metadata_json=excluded.metadata_json,updated_at=excluded.updated_at""",
                    (repository.full_name, repository.html_url, repository.default_branch, repository.description,
                     repository.language, json_dumps(repository.topics), int(repository.archived), int(repository.fork),
                     repository.pushed_at.isoformat() if repository.pushed_at else None, repository.relevance,
                     repository.contract_files, json_dumps(repository), now),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO protocol_repositories VALUES(?,?,?)",
                    (protocol_id, repository.full_name, json_dumps(repository.source_evidence)),
                )

    def repositories(self, protocol_id: str) -> list[Repository]:
        rows = self.connection.execute(
            """SELECT r.* FROM repositories r JOIN protocol_repositories pr ON pr.full_name=r.full_name
               WHERE pr.protocol_id=? AND r.archived=0 AND r.fork=0 ORDER BY r.relevance DESC,r.pushed_at DESC""",
            (protocol_id,),
        ).fetchall()
        result = []
        for row in rows:
            raw = json.loads(row["metadata_json"])
            result.append(Repository(
                full_name=raw["full_name"], html_url=raw["html_url"], default_branch=raw["default_branch"],
                description=raw["description"], language=raw["language"], topics=raw["topics"],
                archived=raw["archived"], fork=raw["fork"], pushed_at=parse_datetime(raw["pushed_at"]),
                relevance=raw["relevance"], contract_files=raw["contract_files"], source_evidence=[],
            ))
        return result

    def repo_checkpoint(self, protocol_id: str, full_name: str) -> datetime | None:
        row = self.connection.execute(
            "SELECT last_scanned_at FROM repo_checkpoints WHERE protocol_id=? AND full_name=?",
            (protocol_id, full_name),
        ).fetchone()
        return parse_datetime(row["last_scanned_at"]) if row else None

    def save_checkpoint(self, protocol_id: str, full_name: str, latest_commit: str) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO repo_checkpoints VALUES(?,?,?,?)",
            (protocol_id, full_name, utc_now().isoformat(), latest_commit),
        )
        self.connection.commit()

    def save_change(self, protocol_id: str, change: Change) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO changes VALUES(?,?,?,?,?,?,?,?,?)",
            (protocol_id, change.repository, change.commit, change.parent_commit, change.committed_at.isoformat(),
             int(change.meaningful), change.significance, change.change_type, json_dumps(change)),
        )
        self.connection.commit()

    def save_deployment(self, protocol_id: str, deployment: Deployment) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO deployments VALUES(?,?,?,?,?,?,?,?,?)",
            (protocol_id, deployment.address.lower(), deployment.chain_id or 0, deployment.status.value,
             deployment.associated_commit, deployment.association_status, json_dumps(deployment),
             utc_now().isoformat()),
        )
        self.connection.commit()

    def save_target(self, candidate: Candidate) -> None:
        self.connection.execute(
            "INSERT OR REPLACE INTO targets VALUES(?,?,?,?,?,?,?,?,?)",
            (candidate.protocol.id, candidate.change.repository, candidate.change.commit, candidate.score,
             candidate.priority.value, candidate.evidence_level.value, candidate.confidence,
             json_dumps(candidate), utc_now().isoformat()),
        )
        self.connection.commit()

    def target_records(self, category: str, days: int, min_score: int, min_confidence: float, top: int) -> list[dict[str, Any]]:
        cutoff = (utc_now() - timedelta(days=days)).isoformat()
        parameters: list[Any] = [cutoff, min_score, min_confidence]
        where = "c.committed_at>=? AND t.score>=? AND t.confidence>=?"
        rows = self.connection.execute(
            f"""SELECT t.target_json,p.category FROM targets t JOIN protocols p ON p.id=t.protocol_id
                JOIN changes c ON c.protocol_id=t.protocol_id AND c.repository=t.repository AND c.commit_sha=t.commit_sha
                WHERE {where} ORDER BY t.score DESC,t.confidence DESC""",
            parameters,
        ).fetchall()
        return [
            json.loads(row["target_json"])
            for row in rows
            if category_matches(row["category"], category)
        ][:top]

    def status(self) -> dict[str, Any]:
        total = self.connection.execute("SELECT COUNT(*) AS n FROM protocols").fetchone()["n"]
        job_rows = self.connection.execute(
            "SELECT stage,state,COUNT(*) AS n FROM protocol_jobs GROUP BY stage,state ORDER BY stage,state"
        ).fetchall()
        bounty_rows = self.connection.execute(
            "SELECT bounty_type,COUNT(*) AS n FROM bounties GROUP BY bounty_type ORDER BY bounty_type"
        ).fetchall()
        return {
            "protocols": total,
            "jobs": [{"stage": row["stage"], "state": row["state"], "count": row["n"]} for row in job_rows],
            "bounties": [{"type": row["bounty_type"], "count": row["n"]} for row in bounty_rows],
            "repositories": self.connection.execute("SELECT COUNT(*) AS n FROM repositories").fetchone()["n"],
            "changes": self.connection.execute("SELECT COUNT(*) AS n FROM changes WHERE meaningful=1").fetchone()["n"],
            "deployments": self.connection.execute("SELECT COUNT(*) AS n FROM deployments").fetchone()["n"],
            "targets": self.connection.execute("SELECT COUNT(*) AS n FROM targets").fetchone()["n"],
        }

    def protocol_record(self, slug: str) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM protocols WHERE slug=?", (slug,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["job"] = dict(self.connection.execute("SELECT * FROM protocol_jobs WHERE protocol_id=?", (row["id"],)).fetchone())
        bounty = self.connection.execute("SELECT * FROM bounties WHERE protocol_id=?", (row["id"],)).fetchone()
        result["bounty"] = dict(bounty) if bounty else None
        result["repositories"] = [dict(item) for item in self.connection.execute(
            "SELECT r.* FROM repositories r JOIN protocol_repositories pr ON pr.full_name=r.full_name WHERE pr.protocol_id=?",
            (row["id"],),
        ).fetchall()]
        result["changes"] = [json.loads(item["payload_json"]) for item in self.connection.execute(
            "SELECT payload_json FROM changes WHERE protocol_id=? ORDER BY committed_at DESC", (row["id"],)
        ).fetchall()]
        result["deployments"] = [json.loads(item["payload_json"]) for item in self.connection.execute(
            "SELECT payload_json FROM deployments WHERE protocol_id=?", (row["id"],)
        ).fetchall()]
        return result

    @staticmethod
    def _row_protocol(row: sqlite3.Row) -> Protocol:
        raw = json.loads(row["raw_json"])
        return Protocol(
            id=row["id"], name=row["name"], slug=row["slug"], category=row["category"],
            chains=json.loads(row["chains_json"]), tvl=row["tvl"], website=row["website"],
            defillama_url=row["defillama_url"], symbol=row["symbol"],
            chain_tvls=raw.get("chainTvls") or {}, change_1d=raw.get("change_1d"), change_7d=raw.get("change_7d"),
            github_refs=json.loads(row["github_refs_json"]), audits=row["audits"],
            audit_links=list(raw.get("audit_links") or []), raw=raw,
            observed_at=parse_datetime(row["universe_seen_at"]) or utc_now(),
        )
