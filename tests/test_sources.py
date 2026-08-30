from __future__ import annotations

import json
import unittest

from defi_recon.models import BountyType, Protocol
from defi_recon.net import HttpResponse, SourceError, validate_public_url
from defi_recon.sources import (
    DefiLlamaSource,
    OfficialSiteResearcher,
    classify_bounty,
    extract_scope,
    parse_document,
)


class FakeHttp:
    def __init__(self, responses: dict[str, HttpResponse]):
        self.responses = responses

    def get(self, url, headers=None, **kwargs):
        if url not in self.responses:
            raise SourceError("not found", status=404, retryable=False)
        return self.responses[url]


def protocol() -> Protocol:
    return Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 5_000_000,
                    "https://acme.example", "https://defillama.com/protocol/acme")


class SourceTests(unittest.TestCase):
    def test_defillama_universe_keeps_every_record_including_zero_tvl(self) -> None:
        payload = [
            {"id": "1", "name": "One", "slug": "one", "category": "Lending", "chains": ["Ethereum"], "tvl": 1},
            {"id": "2", "name": "Two", "slug": "two", "category": "Dexes", "chains": [], "tvl": 0},
            {"id": "3", "name": "Three", "slug": "three", "category": None, "chains": [], "tvl": None},
        ]
        body = json.dumps(payload).encode()
        http = FakeHttp({"https://api.llama.fi/protocols": HttpResponse("https://api.llama.fi/protocols", 200, body, "application/json")})
        protocols, payload_hash = DefiLlamaSource(http).fetch_universe()
        self.assertEqual(len(protocols), 3)
        self.assertEqual(protocols[1].tvl, 0)
        self.assertEqual(len(payload_hash), 64)

    def test_first_party_requires_direct_official_submission_channel(self) -> None:
        page = parse_document(
            "https://acme.example/security", "https://acme.example/security",
            "<h1>Bug Bounty</h1><p>Rewards up to $100k. Report a vulnerability to security@acme.example.</p>",
            "text/html",
        )
        finding = classify_bounty("https://acme.example", [page])
        self.assertEqual(finding.bounty_type, BountyType.FIRST_PARTY)
        self.assertEqual(finding.submission_url, "security@acme.example")

    def test_platform_link_is_not_first_party(self) -> None:
        page = parse_document(
            "https://acme.example/security", "https://acme.example/security",
            '<h1>Bug Bounty</h1><p>Rewards</p><a href="https://immunefi.com/bug-bounty/acme">Submit report</a>',
            "text/html",
        )
        finding = classify_bounty("https://acme.example", [page])
        self.assertEqual(finding.bounty_type, BountyType.PLATFORM_HOSTED)

    def test_scope_is_heading_based_and_preserves_evidence(self) -> None:
        body = """
        <h1>Bug Bounty</h1><p>Email security@acme.example. Rewards available.</p>
        <h2>In scope</h2><p>Pool at 0x1111111111111111111111111111111111111111 on Ethereum.</p>
        <h2>Out of scope</h2><p>Frontend and testnet deployments.</p>
        <h2>Rules</h2><p>No mainnet testing. Proof of concept required.</p>
        <h2>Rewards</h2><p>Critical: $100,000</p>
        """
        page = parse_document("https://acme.example/security", "https://acme.example/security", body, "text/html")
        bounty = classify_bounty("https://acme.example", [page])
        scope = extract_scope(protocol(), [page], bounty)
        self.assertEqual(scope.status, "CONFIRMED")
        self.assertEqual(scope.addresses[0].value, "0x1111111111111111111111111111111111111111")
        self.assertTrue(scope.in_scope)
        self.assertTrue(scope.out_of_scope)
        self.assertTrue(any(item.kind == "mainnet_testing_prohibited" for item in scope.rules))
        self.assertTrue(scope.addresses[0].evidence.source_url.startswith("https://acme.example"))

    def test_markdown_security_policy_gets_sections(self) -> None:
        page = parse_document("https://github.com/acme/core/SECURITY.md", "https://github.com/acme/core/SECURITY.md",
                              "# Security\n## In scope\nCore.sol\n## Rules\nNo mainnet testing", "text/plain")
        self.assertIn("in scope", page.sections)
        self.assertIn("Core.sol", page.sections["in scope"])

    def test_private_literal_url_is_blocked(self) -> None:
        with self.assertRaises(SourceError):
            validate_public_url("http://127.0.0.1/admin")


if __name__ == "__main__":
    unittest.main()

