from __future__ import annotations

import unittest

from defi_recon.pipeline import ResearchOptions, run_research
from defi_recon.storage import ReconStore


class PipelineStorageTests(unittest.TestCase):
    def test_demo_hard_filters_platform_bounty(self) -> None:
        result = run_research(ResearchOptions(demo=True, min_confidence=0.85))
        names = [candidate.protocol.name for candidate in result.candidates]
        self.assertIn("Northstar Lending", names)
        self.assertIn("Harbor Vaults", names)
        self.assertNotIn("Meridian DEX", names)

    def test_category_filter_is_strict(self) -> None:
        result = run_research(ResearchOptions(category="lending", demo=True, min_confidence=0.85))
        self.assertEqual([candidate.protocol.name for candidate in result.candidates], ["Northstar Lending"])

    def test_deployment_gate_removes_unverified_watchlist(self) -> None:
        result = run_research(
            ResearchOptions(category="all", demo=True, require_deployment=True, min_confidence=0.85)
        )
        self.assertEqual([candidate.protocol.name for candidate in result.candidates], ["Northstar Lending"])

    def test_store_persists_normalized_run(self) -> None:
        result = run_research(ResearchOptions(category="lending", demo=True, min_confidence=0.85))
        with ReconStore(":memory:") as store:
            run_id = store.save(result, ResearchOptions(category="lending", demo=True))
            self.assertEqual(run_id, 1)
            rows = store.recent_runs()
            self.assertEqual(rows[0]["candidate_count"], 1)
            self.assertEqual(store.connection.execute("SELECT COUNT(*) FROM protocols").fetchone()[0], 1)
            self.assertEqual(store.connection.execute("SELECT evidence_level FROM targets").fetchone()[0], "E5")


if __name__ == "__main__":
    unittest.main()
