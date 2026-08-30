from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

from .models import (
    BountyFinding,
    BountyType,
    Evidence,
    PageDocument,
    Protocol,
    ScopeFinding,
    ScopeItem,
    parse_datetime,
    stable_hash,
    utc_now,
)
from .net import HttpClient, SourceError


PLATFORM_HOSTS = {
    "immunefi.com", "sherlock.xyz", "cantina.xyz", "hackenproof.com", "code4rena.com",
    "bugcrowd.com", "hackerone.com",
}
SECURITY_PATHS = (
    "/.well-known/security.txt", "/security.txt", "/security", "/bug-bounty",
    "/security/bug-bounty", "/security-researchers", "/responsible-disclosure",
    "/docs/security", "/docs/bug-bounty", "/security-policy", "/terms",
)
RELEVANT_TERMS = (
    "security", "bug-bounty", "bug_bounty", "bounty", "responsible-disclosure", "disclosure",
    "researcher", "audit", "scope", "security-policy",
)
BINARY_EXTENSIONS = (".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".zip", ".tar", ".gz", ".mp4", ".webm")
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
GITHUB_RE = re.compile(r"https?://(?:www\.)?github\.com/([^/#?]+)/?([^/#?]*)", re.I)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
MONEY_RE = re.compile(r"(?i)(?:USD\s*)?\$\s?[0-9][0-9,.]*(?:\s?[kmb])?|[0-9][0-9,.]*\s?(?:USD|USDC|DAI)")
COMMON_TWO_LEVEL_SUFFIXES = {"co.uk", "org.uk", "com.au", "com.br", "co.jp", "co.kr", "com.sg"}


def clean_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def hostname(url: str) -> str:
    return (urlparse(url).hostname or "").lower().removeprefix("www.").rstrip(".")


def domain_family(url: str) -> str:
    host = hostname(url)
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    return ".".join(labels[-3:]) if last_two in COMMON_TWO_LEVEL_SUFFIXES else last_two


def is_same_family(first: str, second: str) -> bool:
    return bool(domain_family(first)) and domain_family(first) == domain_family(second)


def github_references(values: Iterable[str]) -> tuple[set[str], set[str]]:
    repos: set[str] = set()
    owners: set[str] = set()
    reserved = {"orgs", "organizations", "features", "topics", "marketplace", "settings", "login", "search"}
    for value in values:
        match = GITHUB_RE.search(str(value))
        if match:
            owner = match.group(1)
            repo = match.group(2).removesuffix(".git").strip("/")
            if owner.lower() in reserved:
                continue
            owners.add(owner)
            if repo and repo.lower() not in reserved:
                repos.add(f"{owner}/{repo}")
        elif re.fullmatch(r"[\w.-]+/[\w.-]+", str(value)):
            owner, repo = str(value).split("/", 1)
            owners.add(owner)
            repos.add(f"{owner}/{repo.removesuffix('.git')}")
    return repos, owners


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self.sections: dict[str, list[str]] = {"document": []}
        self.current_section = "document"
        self._heading_parts: list[str] = []
        self._heading_tag = ""
        self._title_parts: list[str] = []
        self._in_title = False
        self._ignored_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "svg", "noscript"}:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        attrs_map = dict(attrs)
        if tag == "a" and attrs_map.get("href"):
            self.links.append(str(attrs_map["href"]))
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._heading_tag = tag
            self._heading_parts = []
        if tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg", "noscript"}:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if tag == self._heading_tag:
            heading = re.sub(r"\s+", " ", " ".join(self._heading_parts)).strip().lower()
            if heading:
                self.current_section = heading[:160]
                self.sections.setdefault(self.current_section, [])
            self._heading_tag = ""
        if tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        value = re.sub(r"\s+", " ", data).strip()
        if not value:
            return
        self.text_parts.append(value)
        self.sections.setdefault(self.current_section, []).append(value)
        if self._heading_tag:
            self._heading_parts.append(value)
        if self._in_title:
            self._title_parts.append(value)

    @property
    def title(self) -> str:
        return " ".join(self._title_parts).strip()


def parse_document(source_url: str, final_url: str, body: str, content_type: str) -> PageDocument:
    if "html" not in content_type and not body.lstrip().startswith(("<", "<!")):
        text = re.sub(r"\s+", " ", body).strip()
        sections: dict[str, str] = {"document": text}
        current = "document"
        buckets: dict[str, list[str]] = {current: []}
        for line in body.splitlines():
            heading = re.match(r"^\s{0,3}#{1,6}\s+(.+?)\s*$", line)
            if heading:
                current = heading.group(1).strip().lower()[:160]
                buckets.setdefault(current, [])
            elif line.strip():
                buckets.setdefault(current, []).append(line.strip())
        sections.update({key: re.sub(r"\s+", " ", " ".join(values)).strip() for key, values in buckets.items() if values})
        lines = body.splitlines()
        rst_buckets: dict[str, list[str]] = {}
        current_rst = "document"
        for index, line in enumerate(lines):
            if index + 1 < len(lines) and line.strip() and re.fullmatch(r"\s*[=~`^\-:*+#<>]{3,}\s*", lines[index + 1]):
                current_rst = line.strip().lower()[:160]
                rst_buckets.setdefault(current_rst, [])
                continue
            if index > 0 and re.fullmatch(r"\s*[=~`^\-:*+#<>]{3,}\s*", line):
                continue
            if line.strip():
                rst_buckets.setdefault(current_rst, []).append(line.strip())
        sections.update({key: re.sub(r"\s+", " ", " ".join(values)).strip() for key, values in rst_buckets.items() if values})
        links = re.findall(r"https?://[^\s)>\]]+", body)
        return PageDocument(source_url, final_url, "", text, sorted(set(links)), sections)
    parser = _DocumentParser()
    parser.feed(body)
    text = re.sub(r"\s+", " ", " ".join(parser.text_parts)).strip()
    links = [clean_url(urljoin(final_url, link)) for link in parser.links if link and not link.startswith(("javascript:", "data:"))]
    sections = {heading: re.sub(r"\s+", " ", " ".join(values)).strip() for heading, values in parser.sections.items()}
    return PageDocument(source_url, final_url, parser.title, text, sorted(set(links)), sections)


class DefiLlamaSource:
    API = "https://api.llama.fi"

    def __init__(self, http: HttpClient):
        self.http = http

    def fetch_universe(self) -> tuple[list[Protocol], str]:
        response = self.http.get(f"{self.API}/protocols", max_bytes=30_000_000, cache=False)
        raw_protocols = response.json()
        protocols: list[Protocol] = []
        for raw in raw_protocols:
            protocol = self._from_raw(raw)
            if protocol.id and protocol.slug:
                protocols.append(protocol)
        return protocols, stable_hash(response.body)

    def fetch_detail(self, protocol: Protocol) -> Protocol:
        try:
            response = self.http.get(f"{self.API}/protocol/{protocol.slug}", max_bytes=20_000_000, cache=False)
            raw = response.json()
        except (SourceError, json.JSONDecodeError):
            return protocol
        protocol.website = str(raw.get("url") or protocol.website)
        values: list[str] = list(protocol.github_refs)
        github = raw.get("github")
        if isinstance(github, str):
            values.append(github)
        elif isinstance(github, list):
            values.extend(str(value) for value in github)
        protocol.github_refs = sorted(set(values))
        protocol.audit_links = list(raw.get("audit_links") or protocol.audit_links)
        protocol.audits = _int_value(raw.get("audits"), protocol.audits)
        # Store useful metadata, not multi-megabyte historical arrays.
        for key in ("url", "description", "twitter", "github", "audit_links", "audits", "oracles", "forkedFrom", "listedAt"):
            if key in raw:
                protocol.raw[key] = raw[key]
        return protocol

    @staticmethod
    def _from_raw(raw: dict[str, Any]) -> Protocol:
        identifier = str(raw.get("id") or raw.get("slug") or "")
        slug = str(raw.get("slug") or raw.get("name") or identifier).strip().lower().replace(" ", "-")
        github = raw.get("github") or []
        github_refs = [github] if isinstance(github, str) else [str(value) for value in github]
        chain_tvls = {str(key): float(value or 0) for key, value in (raw.get("chainTvls") or {}).items() if isinstance(value, (int, float))}
        return Protocol(
            id=identifier, name=str(raw.get("name") or slug), slug=slug,
            category=str(raw.get("category") or "Unknown"), chains=[str(value) for value in raw.get("chains") or []],
            tvl=float(raw.get("tvl") or 0), website=str(raw.get("url") or ""),
            defillama_url=f"https://defillama.com/protocol/{slug}", symbol=str(raw.get("symbol") or ""),
            chain_tvls=chain_tvls, change_1d=_float_or_none(raw.get("change_1d")),
            change_7d=_float_or_none(raw.get("change_7d")), github_refs=github_refs,
            audits=_int_value(raw.get("audits"), 0), audit_links=list(raw.get("audit_links") or []), raw=raw,
        )


@dataclass(slots=True)
class DiscoveryResult:
    pages: list[PageDocument]
    bounty: BountyFinding
    scope: ScopeFinding
    github_repos: set[str]
    github_owners: set[str]


class OfficialSiteResearcher:
    def __init__(self, http: HttpClient, max_pages: int = 16):
        self.http = http
        self.max_pages = max_pages

    def research(self, protocol: Protocol) -> DiscoveryResult:
        if not protocol.website:
            bounty = BountyFinding(BountyType.UNKNOWN, reason="DeFiLlama has no official website URL")
            repos, owners = github_references(protocol.github_refs)
            return DiscoveryResult([], bounty, ScopeFinding(), repos, owners)
        base = clean_url(protocol.website)
        queue: deque[str] = deque([base, *[urljoin(base, path) for path in SECURITY_PATHS]])
        visited: set[str] = set()
        pages: list[PageDocument] = []
        all_links: set[str] = set(protocol.github_refs)
        while queue and len(pages) < self.max_pages:
            url = clean_url(queue.popleft())
            if url in visited:
                continue
            visited.add(url)
            if not is_same_family(base, url):
                continue
            try:
                response = self.http.get(url, cache=False)
            except SourceError:
                continue
            if response.content_type not in {"text/html", "text/plain", "application/xhtml+xml"}:
                continue
            document = parse_document(url, response.url, response.text, response.content_type)
            pages.append(document)
            all_links.update(document.links)
            ranked_links = sorted(
                (link for link in document.links if is_same_family(base, link) and link not in visited
                 and not urlparse(link).path.lower().endswith(BINARY_EXTENSIONS)),
                key=_relevant_url_score,
                reverse=True,
            )
            for link in ranked_links:
                if _relevant_url_score(link) > 0:
                    queue.append(link)
        repos, owners = github_references(all_links)
        bounty = classify_bounty(base, pages)
        scope = extract_scope(protocol, pages, bounty)
        return DiscoveryResult(pages, bounty, scope, repos, owners)


def classify_bounty(official_url: str, pages: list[PageDocument]) -> BountyFinding:
    checked = [page.final_url for page in pages]
    platform_evidence: list[Evidence] = []
    first_party_candidates: list[tuple[int, PageDocument, str]] = []
    official_family = domain_family(official_url)
    for page in pages:
        corpus = page.text.lower()
        phrase_score = 0
        if "bug bounty" in corpus:
            phrase_score += 3
        if "vulnerability disclosure" in corpus or "responsible disclosure" in corpus:
            phrase_score += 1
        if "reward" in corpus or "bounty reward" in corpus:
            phrase_score += 1
        platform_links = [link for link in page.links if any(hostname(link) == host or hostname(link).endswith("." + host) for host in PLATFORM_HOSTS)]
        for link in platform_links:
            platform_evidence.append(Evidence(
                "bounty hosted by external platform", link, page.final_url, "official-page-link", 1.0,
                excerpt=_excerpt(page.text, "bug bounty"),
            ))
        emails = EMAIL_RE.findall(page.text)
        official_emails = [email for email in emails if email.lower().endswith("@" + official_family)]
        direct_links = [link for link in page.links if is_same_family(official_url, link) and any(term in link.lower() for term in ("submit", "report", "contact"))]
        direct_language = any(term in corpus for term in ("email us", "report a vulnerability", "submit a vulnerability", "send your report"))
        direct = official_emails[0] if official_emails else (direct_links[0] if direct_links else (page.final_url if direct_language else ""))
        if phrase_score >= 3 and direct and not platform_links:
            first_party_candidates.append((phrase_score, page, direct))
    if first_party_candidates:
        score, page, submission = max(first_party_candidates, key=lambda item: item[0])
        evidence = Evidence(
            "first-party bounty accepts direct reports", submission, page.final_url, "official-bounty-page", 1.0,
            excerpt=_excerpt(page.text, "bug bounty"),
        )
        return BountyFinding(
            BountyType.FIRST_PARTY, page.final_url, hostname(page.final_url), submission,
            [evidence], min(1.0, 0.7 + score * 0.06), checked,
            "Official-domain bounty language and a direct first-party submission channel were both found.",
        )
    if platform_evidence:
        return BountyFinding(
            BountyType.PLATFORM_HOSTED, str(platform_evidence[0].value), hostname(str(platform_evidence[0].value)), "",
            platform_evidence, 1.0, checked, "Official material directs researchers to an external bounty platform.",
        )
    if pages:
        return BountyFinding(
            BountyType.NO_BOUNTY_FOUND, confidence=0.0, checked_urls=checked,
            reason="No qualifying first-party bounty evidence was found on the official pages checked; absence is not proven.",
        )
    return BountyFinding(BountyType.UNKNOWN, confidence=0.0, checked_urls=checked, reason="Official pages could not be retrieved.")


def classify_official_github_security(official_url: str, pages: list[PageDocument]) -> BountyFinding:
    """Classify security/bounty documents only after their repositories were linked by an official source."""
    platform: list[Evidence] = []
    for page in pages:
        corpus = page.text.lower()
        if "bug bounty" not in corpus:
            continue
        platform_links = [link for link in page.links if any(hostname(link) == host or hostname(link).endswith("." + host) for host in PLATFORM_HOSTS)]
        if platform_links:
            platform.append(Evidence(
                "official repository security policy links to bounty platform", platform_links[0], page.final_url,
                "official-github-security-policy", 1.0, excerpt=_excerpt(page.text, "bug bounty"),
            ))
            continue
        emails = EMAIL_RE.findall(page.text)
        official_family = domain_family(official_url)
        official_emails = [email for email in emails if official_family and email.lower().endswith("@" + official_family)]
        official_links = [link for link in page.links if is_same_family(official_url, link) and any(term in link.lower() for term in ("security", "report", "bounty", "contact"))]
        direct = official_emails[0] if official_emails else (official_links[0] if official_links else "")
        if direct and ("reward" in corpus or "bounty" in corpus):
            evidence = Evidence(
                "official repository publishes direct first-party bounty instructions", direct, page.final_url,
                "official-github-security-policy", 1.0, excerpt=_excerpt(page.text, "bug bounty"),
            )
            return BountyFinding(
                BountyType.FIRST_PARTY, page.final_url, hostname(page.final_url), direct, [evidence], 0.95,
                [page.final_url for page in pages],
                "An officially linked repository document contains bounty terms and a direct first-party channel.",
            )
    if platform:
        return BountyFinding(
            BountyType.PLATFORM_HOSTED, str(platform[0].value), hostname(str(platform[0].value)), "", platform, 1.0,
            [page.final_url for page in pages], "Official repository security policy directs researchers to a platform.",
        )
    return BountyFinding(BountyType.UNKNOWN, checked_urls=[page.final_url for page in pages], reason="No qualifying bounty evidence in official repository security policies.")


def extract_scope(protocol: Protocol, pages: list[PageDocument], bounty: BountyFinding) -> ScopeFinding:
    if bounty.bounty_type != BountyType.FIRST_PARTY:
        return ScopeFinding()
    result = ScopeFinding()
    relevant_pages = sorted(pages, key=lambda page: (page.final_url != bounty.url, -_relevant_url_score(page.final_url)))
    seen: set[tuple[str, str, str]] = set()

    def add(group: str, kind: str, value: str, page: PageDocument, heading: str, confidence: float = 1.0) -> None:
        clean = re.sub(r"\s+", " ", value).strip(" :-•\t")[:1000]
        key = (group, kind, clean.lower())
        if len(clean) < 2 or key in seen:
            return
        seen.add(key)
        evidence = Evidence(f"scope {group}", clean, page.final_url, "official-bounty-scope", confidence,
                            excerpt=f"{heading}: {clean}"[:1200])
        getattr(result, group).append(ScopeItem(kind, clean, evidence))

    for page in relevant_pages:
        for heading, section in page.sections.items():
            heading_lower = heading.lower()
            group = ""
            if any(term in heading_lower for term in ("out of scope", "out-of-scope", "excluded", "not eligible")):
                group = "out_of_scope"
            elif any(term in heading_lower for term in ("in scope", "in-scope", "eligible asset", "scope")):
                group = "in_scope"
            elif any(term in heading_lower for term in ("rule", "testing", "disclosure", "prohibited", "restriction", "requirement")):
                group = "rules"
            elif any(term in heading_lower for term in ("reward", "severity", "payout")):
                group = "rewards"
            if group:
                for item in _split_scope_items(section):
                    add(group, "text", item, page, heading)
            for address in ADDRESS_RE.findall(section):
                add("addresses", "contract_address", address, page, heading)
            repos, _ = github_references(page.links + [section])
            for repository in repos:
                add("repositories", "github_repository", repository, page, heading)
            for chain in protocol.chains:
                if re.search(rf"(?i)\b{re.escape(chain)}\b", section):
                    add("chains", "chain", chain, page, heading)
            for amount in MONEY_RE.findall(section):
                if "reward" in heading_lower or any(term in section.lower() for term in ("critical", "high", "medium", "low", "reward")):
                    add("rewards", "amount", amount, page, heading)
        corpus = page.text.lower()
        rule_signals = {
            "poc_required": ("proof of concept required", "poc required"),
            "mainnet_testing_prohibited": ("do not test on mainnet", "mainnet testing is prohibited", "no mainnet testing"),
            "kyc": ("kyc", "know your customer"),
            "responsible_disclosure": ("responsible disclosure", "coordinated disclosure"),
            "known_issues": ("known issues", "known vulnerabilities"),
        }
        for kind, terms in rule_signals.items():
            term = next((term for term in terms if term in corpus), "")
            if term:
                add("rules", kind, _excerpt(page.text, term), page, "document", 0.95)
    result.status = "CONFIRMED" if result.in_scope or result.out_of_scope or result.addresses else "EVIDENCE_NOT_FOUND"
    confirmed_groups = sum(bool(getattr(result, name)) for name in ("in_scope", "out_of_scope", "rules", "rewards", "addresses"))
    result.confidence = min(1.0, 0.55 + confirmed_groups * 0.09) if result.status == "CONFIRMED" else 0.0
    return result


def _split_scope_items(text: str) -> list[str]:
    parts = re.split(r"(?:\s*[•▪◦]\s*|\s+[-–—]\s+|\n+|(?<=[.;])\s+(?=[A-Z0-9]))", text)
    return [part.strip() for part in parts if 5 <= len(part.strip()) <= 1000][:80]


def _relevant_url_score(url: str) -> int:
    lower = url.lower()
    return sum(2 if term in lower else 0 for term in RELEVANT_TERMS) - (2 if any(term in lower for term in ("blog", "press", "career")) else 0)


def _excerpt(text: str, needle: str, radius: int = 220) -> str:
    lower = text.lower()
    index = lower.find(needle.lower())
    if index < 0:
        return text[: radius * 2]
    return text[max(0, index - radius): index + len(needle) + radius].strip()


def _int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float_or_none(value: Any) -> float | None:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
