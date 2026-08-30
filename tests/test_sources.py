from __future__ import annotations

import unittest

from defi_recon.models import BountyType, Protocol
from defi_recon.sources import BountyDetector, HttpResponse, ScopeExtractor, SourceError, _validate_public_url, parse_page


class FakeHttp:
    def __init__(self, responses: dict[str, HttpResponse]):
        self.responses = responses

    def get(self, url: str, headers=None) -> HttpResponse:
        if url not in self.responses:
            raise SourceError("not found")
        return self.responses[url]


def protocol() -> Protocol:
    return Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 1, "https://acme.example", "")


class SourceTests(unittest.TestCase):
    def test_page_parser_extracts_visible_text_and_links(self) -> None:
        text, links = parse_page('<script>ignore</script><a href="/security">Bug bounty</a>', "https://acme.example")
        self.assertEqual(text, "Bug bounty")
        self.assertEqual(links, ["https://acme.example/security"])

    def test_first_party_bounty_needs_official_page_language(self) -> None:
        url = "https://acme.example/security"
        fake = FakeHttp({url: HttpResponse(url, 200, b"<h1>Bug bounty</h1><p>Report issues for a reward.</p>", "text/html")})
        finding = BountyDetector(fake).detect(protocol())
        self.assertEqual(finding.bounty_type, BountyType.FIRST_PARTY)
        self.assertGreater(finding.confidence, 0.9)

    def test_platform_link_is_not_first_party(self) -> None:
        url = "https://acme.example/security"
        html = b'<h1>Bug bounty</h1><p>Rewards</p><a href="https://immunefi.com/bug-bounty/acme">Report</a>'
        fake = FakeHttp({url: HttpResponse(url, 200, html, "text/html")})
        finding = BountyDetector(fake).detect(protocol())
        self.assertEqual(finding.bounty_type, BountyType.PLATFORM_HOSTED)

    def test_unknown_is_distinct_from_no_bounty_found(self) -> None:
        finding = BountyDetector(FakeHttp({})).detect(protocol())
        self.assertEqual(finding.bounty_type, BountyType.UNKNOWN)

    def test_scope_extractor_requires_explicit_sections(self) -> None:
        url = "https://acme.example/security"
        html = b"<p>In scope: Pool proxy and OracleAdapter. Out of scope: frontend. Rules: no mainnet tests. Rewards: Critical $100k.</p>"
        fake = FakeHttp({url: HttpResponse(url, 200, html, "text/html")})
        from defi_recon.models import BountyFinding
        scope = ScopeExtractor(fake).extract(BountyFinding(BountyType.FIRST_PARTY, url, scope_url=url))
        self.assertEqual(scope.status, "CONFIRMED")
        self.assertTrue(scope.in_scope)
        self.assertTrue(scope.out_of_scope)

    def test_private_literal_urls_are_blocked(self) -> None:
        with self.assertRaises(SourceError):
            _validate_public_url("http://127.0.0.1/admin")


if __name__ == "__main__":
    unittest.main()

