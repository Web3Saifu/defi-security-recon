from __future__ import annotations

import unittest
from datetime import datetime, timezone

from defi_recon.classifiers import category_matches, classify_change, freshness_factor, score_candidate
from defi_recon.models import (
    BountyFinding,
    BountyType,
    Change,
    Deployment,
    DeploymentStatus,
    Evidence,
    Priority,
    Protocol,
    ScopeFinding,
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


def protocol(category: str = "Lending") -> Protocol:
    return Protocol("p1", "Protocol", "protocol", category, ["Ethereum"], 100_000_000, "https://p.example", "")


def bounty() -> BountyFinding:
    return BountyFinding(
        BountyType.FIRST_PARTY,
        "https://p.example/security",
        "p.example",
        evidence=[Evidence("direct bounty", "https://p.example/security", "official", 0.95, NOW)],
        confidence=0.95,
    )


def change(message: str, files: list[str], patches: list[str] | None = None) -> Change:
    return Change(
        "org/repo",
        "abc",
        "https://github.com/org/repo/commit/abc",
        datetime(2026, 8, 28, tzinfo=timezone.utc),
        message,
        files,
        patches or [],
        evidence=[Evidence("abc", "https://github.com/org/repo/commit/abc", "github", 0.92, NOW)],
    )


class ClassifierTests(unittest.TestCase):
    def test_category_aliases(self) -> None:
        self.assertTrue(category_matches("Dexes", "dex"))
        self.assertTrue(category_matches("Liquid Staking", "liquid-staking"))
        self.assertFalse(category_matches("Lending", "dex"))

    def test_docs_only_is_not_meaningful(self) -> None:
        result = classify_change(change("Update docs", ["README.md", "docs/security.md"]), "Lending")
        self.assertFalse(result.meaningful)
        self.assertEqual(result.significance, 0)

    def test_solidity_integration_finds_lending_domains(self) -> None:
        result = classify_change(
            change(
                "Add new collateral and Chainlink oracle adapter with liquidation support",
                ["contracts/OracleAdapter.sol", "contracts/Liquidation.sol"],
            ),
            "Lending",
        )
        self.assertTrue(result.meaningful)
        self.assertEqual(result.integration_novelty, 10)
        self.assertIn("oracle", result.security_domains)
        self.assertIn("liquidation", result.security_domains)
        self.assertIn("collateral", result.security_domains)

    def test_tests_only_are_not_contract_changes(self) -> None:
        result = classify_change(change("Add liquidation tests", ["test/Liquidation.t.sol"]), "Lending")
        self.assertFalse(result.meaningful)

    def test_freshness_bands(self) -> None:
        self.assertEqual(freshness_factor(2), 1.5)
        self.assertEqual(freshness_factor(7), 1.3)
        self.assertEqual(freshness_factor(30), 1.0)
        self.assertEqual(freshness_factor(61), 0.4)

    def test_unverified_deployment_caps_priority(self) -> None:
        classified = classify_change(
            change("Major upgrade with new oracle accounting architecture", ["contracts/Pool.sol"]), "Lending"
        )
        candidate = score_candidate(protocol(), bounty(), classified, Deployment(), ScopeFinding(), now=NOW)
        self.assertEqual(candidate.priority, Priority.WATCHLIST)
        self.assertEqual(candidate.evidence_level.value, "E2")

    def test_active_deployment_can_promote(self) -> None:
        classified = classify_change(
            change("Major upgrade with new oracle accounting architecture", ["contracts/Pool.sol"]), "Lending"
        )
        deployment = Deployment(
            DeploymentStatus.ACTIVE,
            evidence=[Evidence("ACTIVE", "https://etherscan.io/tx/0x1", "on-chain", 0.99, NOW)],
            confidence=0.99,
        )
        scope = ScopeFinding(status="CONFIRMED", confidence=0.95)
        candidate = score_candidate(protocol(), bounty(), classified, deployment, scope, now=NOW)
        self.assertIn(candidate.priority, {Priority.TARGET_NOW, Priority.HIGH_PRIORITY})
        self.assertEqual(candidate.evidence_level.value, "E5")

    def test_first_party_gate_fails_closed(self) -> None:
        classified = classify_change(change("Add new oracle", ["contracts/Oracle.sol"]), "Lending")
        no_bounty = BountyFinding(BountyType.NO_BOUNTY_FOUND)
        candidate = score_candidate(protocol(), no_bounty, classified, Deployment(), ScopeFinding(), now=NOW)
        self.assertTrue(candidate.gate_failures)
        self.assertEqual(candidate.priority, Priority.IGNORE)


if __name__ == "__main__":
    unittest.main()

