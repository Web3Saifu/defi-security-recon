from __future__ import annotations

import unittest
from datetime import datetime, timezone

from defi_recon.classifiers import (
    classify_change, freshness_factor, parse_solidity_surface, score_candidate, semantic_drift,
)
from defi_recon.models import (
    BountyFinding, BountyType, Change, Deployment, DeploymentStatus, Evidence, FileDelta,
    Priority, Protocol, ScopeFinding,
)


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


class AnalysisTests(unittest.TestCase):
    def test_freshness_multiplier_is_dynamic(self) -> None:
        self.assertEqual(freshness_factor(2), 1.5)
        self.assertEqual(freshness_factor(10), 1.1)
        self.assertEqual(freshness_factor(45), 0.7)

    def test_named_v4_categories_have_specific_security_lenses(self) -> None:
        cases = {
            "RWA": ("contract R { function redeem() external { custodian.attestation(); } }", "asset-attestation"),
            "Oracle": ("contract O { function read() external { aggregator.heartbeat(); } }", "staleness"),
            "Insurance": ("contract I { function submitClaim() external { reserve.payout(); } }", "claims"),
            "Prediction Market": ("contract P { function resolveOutcome() external { oracle.dispute(); } }", "resolution"),
            "NFT Lending": ("contract N { function seizeNFT() external { floorPrice.oracle(); } }", "nft-custody"),
        }
        for category, (source, expected) in cases.items():
            with self.subTest(category=category):
                drift = semantic_drift([("New.sol", "contract Old {}", source)], ["+ " + source], category)
                self.assertIn(expected, drift.security_domains)
    def test_semantic_drift_extracts_real_surface_changes(self) -> None:
        old = """contract Pool { uint256 public totalAssets; function deposit(uint256 x) external {} }"""
        new = """
        import {IOracle} from "./IOracle.sol";
        contract Pool {
          uint256 public totalAssets;
          IOracle public oracle;
          function deposit(uint256 x) external {}
          function liquidate(address user) external { oracle.getPrice(); payable(user).call(""); }
        }
        """
        drift = semantic_drift([("Pool.sol", old, new)], ["+ IOracle public oracle;\n+ function liquidate(address user) external"], "Lending")
        self.assertTrue(any("liquidate" in item for item in drift.added_functions))
        self.assertIn("./IOracle.sol", drift.added_imports)
        self.assertIn("liquidation", drift.security_domains)
        self.assertIn("new-external-call", drift.security_smells)

    def test_change_classification_uses_semantic_drift(self) -> None:
        drift = semantic_drift([("Oracle.sol", "contract O {}", "contract O { address public oracle; }")],
                               ["+ address public oracle;"], "Lending")
        change = Change("org/repo", "abc", "parent", "https://github.com/org/repo/commit/abc", NOW,
                        "Add new oracle integration", [FileDelta("contracts/Oracle.sol", "modified", patch="+ oracle")], drift)
        classify_change(change)
        self.assertTrue(change.meaningful)
        self.assertGreaterEqual(change.significance, 5)

    def test_unassociated_deployment_never_promotes_above_watchlist(self) -> None:
        protocol = Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 100_000_000, "https://acme.example", "")
        bounty = BountyFinding(BountyType.FIRST_PARTY, "https://acme.example/security", confidence=1.0)
        drift = semantic_drift([("Pool.sol", "contract P {}", "contract P { function liquidate() external {} }")],
                               ["+ function liquidate() external"], "Lending")
        change = classify_change(Change("org/repo", "abc", "p", "https://github.com/x", NOW,
                                        "Major upgrade liquidation architecture", [FileDelta("contracts/Pool.sol", "modified")], drift,
                                        evidence=[Evidence("commit", "abc", "https://github.com/x", "github", 1.0)]))
        deployment = Deployment("0x1111111111111111111111111111111111111111", "Ethereum", 1,
                                DeploymentStatus.PROXY_ACTIVE, associated_commit="", association_status="UNPROVEN")
        candidate = score_candidate(protocol, bounty, ScopeFinding(), change, [deployment], NOW)
        self.assertIn(candidate.priority, {Priority.WATCHLIST, Priority.LOW_PRIORITY})
        self.assertEqual(candidate.evidence_level.value, "E2")


if __name__ == "__main__":
    unittest.main()
