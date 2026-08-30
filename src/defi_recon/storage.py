from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import Candidate
from .pipeline import ResearchOptions, ResearchResult


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    generated_at TEXT NOT NULL,
    category TEXT NOT NULL,
    options_json TEXT NOT NULL,
    scanned INTEGER NOT NULL,
    eligible INTEGER NOT NULL,
    candidate_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS protocols (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,
    chains_json TEXT NOT NULL,
    tvl REAL NOT NULL,
    website TEXT NOT NULL,
    github_json TEXT NOT NULL,
    defillama_url TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS bounties (
    protocol_id TEXT PRIMARY KEY REFERENCES protocols(id),
    bounty_type TEXT NOT NULL,
    bounty_url TEXT NOT NULL,
    host TEXT NOT NULL,
    scope_url TEXT NOT NULL,
    scope_status TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL,
    last_verified TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS changes (
    protocol_id TEXT NOT NULL REFERENCES protocols(id),
    commit_sha TEXT NOT NULL,
    repository TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    changed_files_json TEXT NOT NULL,
    change_type TEXT NOT NULL,
    security_domains_json TEXT NOT NULL,
    significance INTEGER NOT NULL,
    deployment_verified INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (protocol_id, commit_sha)
);
CREATE TABLE IF NOT EXISTS deployments (
    protocol_id TEXT NOT NULL REFERENCES protocols(id),
    commit_sha TEXT NOT NULL,
    status TEXT NOT NULL,
    chain TEXT NOT NULL,
    contract_address TEXT NOT NULL,
    implementation_address TEXT NOT NULL,
    deployment_tx TEXT NOT NULL,
    deployment_time TEXT,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL,
    PRIMARY KEY (protocol_id, commit_sha)
);
CREATE TABLE IF NOT EXISTS targets (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    protocol_id TEXT NOT NULL REFERENCES protocols(id),
    commit_sha TEXT NOT NULL,
    score INTEGER NOT NULL,
    priority TEXT NOT NULL,
    evidence_level TEXT NOT NULL,
    confidence REAL NOT NULL,
    reason_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    PRIMARY KEY (run_id, protocol_id, commit_sha)
);
"""


class ReconStore:
    def __init__(self, path: Path | str):
        self.path = Path(path) if path != ":memory:" else Path(":memory:")
        if path != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(path))
        self.connection.executescript(SCHEMA)

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

    def save(self, result: ResearchResult, options: ResearchOptions) -> int:
        generated = result.generated_at.isoformat()
        option_data = {
            "category": options.category,
            "days": options.days,
            "top": options.top,
            "min_score": options.min_score,
            "min_confidence": options.min_confidence,
            "first_party_only": options.first_party_only,
            "require_deployment": options.require_deployment,
            "demo": options.demo,
        }
        with self.transaction() as connection:
            cursor = connection.execute(
                "INSERT INTO runs(generated_at,category,options_json,scanned,eligible,candidate_count) VALUES(?,?,?,?,?,?)",
                (generated, options.category, json.dumps(option_data), result.scanned, result.eligible, len(result.candidates)),
            )
            run_id = int(cursor.lastrowid)
            for candidate in result.candidates:
                self._save_candidate(connection, run_id, candidate, generated)
        return run_id

    @staticmethod
    def _save_candidate(connection: sqlite3.Connection, run_id: int, candidate: Candidate, generated: str) -> None:
        protocol = candidate.protocol
        connection.execute(
            """INSERT INTO protocols VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET name=excluded.name,category=excluded.category,chains_json=excluded.chains_json,
               tvl=excluded.tvl,website=excluded.website,github_json=excluded.github_json,updated_at=excluded.updated_at""",
            (
                protocol.id, protocol.name, protocol.slug, protocol.category, json.dumps(protocol.chains), protocol.tvl,
                protocol.website, json.dumps(protocol.github_repos), protocol.defillama_url, generated,
            ),
        )
        bounty = candidate.bounty
        connection.execute(
            """INSERT INTO bounties VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol_id) DO UPDATE SET bounty_type=excluded.bounty_type,bounty_url=excluded.bounty_url,
               host=excluded.host,scope_url=excluded.scope_url,scope_status=excluded.scope_status,
               confidence=excluded.confidence,evidence_json=excluded.evidence_json,last_verified=excluded.last_verified""",
            (
                protocol.id, bounty.bounty_type.value, bounty.url, bounty.host, bounty.scope_url, bounty.scope_status,
                bounty.confidence, json.dumps([item.to_dict() for item in bounty.evidence]), generated,
            ),
        )
        change = candidate.change
        verified = int(candidate.deployment.status.value in {"DEPLOYED", "ACTIVE"})
        connection.execute(
            """INSERT INTO changes VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol_id,commit_sha) DO UPDATE SET committed_at=excluded.committed_at,
               changed_files_json=excluded.changed_files_json,change_type=excluded.change_type,
               security_domains_json=excluded.security_domains_json,significance=excluded.significance,
               deployment_verified=excluded.deployment_verified,evidence_json=excluded.evidence_json""",
            (
                protocol.id, change.commit, change.repository, change.committed_at.isoformat(),
                json.dumps(change.changed_files), change.change_type, json.dumps(change.security_domains),
                change.significance, verified, json.dumps([item.to_dict() for item in change.evidence]),
            ),
        )
        deployment = candidate.deployment
        connection.execute(
            """INSERT INTO deployments VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(protocol_id,commit_sha) DO UPDATE SET status=excluded.status,chain=excluded.chain,
               contract_address=excluded.contract_address,implementation_address=excluded.implementation_address,
               deployment_tx=excluded.deployment_tx,deployment_time=excluded.deployment_time,
               confidence=excluded.confidence,evidence_json=excluded.evidence_json""",
            (
                protocol.id, change.commit, deployment.status.value, deployment.chain, deployment.contract_address,
                deployment.implementation_address, deployment.transaction_hash,
                deployment.deployment_time.isoformat() if deployment.deployment_time else None,
                deployment.confidence, json.dumps([item.to_dict() for item in deployment.evidence]),
            ),
        )
        connection.execute(
            "INSERT INTO targets VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                run_id, protocol.id, change.commit, candidate.score, candidate.priority.value,
                candidate.evidence_level.value, candidate.confidence, json.dumps(candidate.reasons),
                json.dumps(candidate.to_dict()), "NEW",
            ),
        )

    def recent_runs(self, limit: int = 10) -> list[sqlite3.Row]:
        self.connection.row_factory = sqlite3.Row
        return self.connection.execute(
            "SELECT id,generated_at,category,scanned,eligible,candidate_count FROM runs ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
