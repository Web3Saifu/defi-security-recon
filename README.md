# DeFiLlama Research

**DeFiLlama Research** is a live-source, evidence-first research agent covering the complete DeFiLlama
protocol universe. The current implementation includes V1–V5.

This is a resumable research pipeline—not a demo-data target generator and not a vulnerability detector. It stores every protocol returned by DeFiLlama, progressively enriches each protocol from official and on-chain sources, and only ranks records that satisfy explicit evidence gates.

## What is implemented

### V1 — Full universe, bounty, and contract changes

- Downloads `https://api.llama.fi/protocols` without a TVL cutoff or protocol-count truncation.
- Persists every protocol and creates a resumable research job for each one.
- Crawls official websites, security paths, responsible-disclosure pages, and relevant same-domain links.
- Distinguishes direct first-party bounties from platform-hosted bounties.
- Discovers GitHub repositories from DeFiLlama metadata and official-site links.
- Expands officially linked GitHub organizations and identifies repositories containing production contract files.
- Reads official repository `SECURITY.md` policies.
- Collects all recent commits within the selected window, subject to GitHub pagination and rate limits.
- Rejects docs, dependency, mock, and test-only changes.
- Ranks up to 20 evidence-qualified records by default; `--top` can narrow or expand the result.

### V2 — Deployment verification

- Extracts addresses and transaction hashes from official repository deployment/address/broadcast artifacts.
- Extracts explicitly in-scope contract addresses from first-party bounty pages.
- Uses configured JSON-RPC endpoints to call `eth_getCode`, `eth_getStorageAt`, `eth_call`, transaction receipts, and blocks.
- Resolves ERC-1967 implementation, beacon, and admin slots.
- Resolves ERC-1167 minimal-proxy implementations.
- Checks that the current implementation also has runtime bytecode.
- Looks up verified source using Sourcify API v2.
- Separates `ONCHAIN_CODE` from `PROXY_ACTIVE`.
- Associates a deployment with a GitHub change only when the deployment artifact itself changed in that commit.

### V3 — Deterministic semantic drift

- Downloads old and new versions of every changed production contract.
- Extracts contracts, functions, modifiers, events, errors, imports, state variables, low-level/external calls, and literal addresses.
- Compares old and new semantic surfaces.
- Records added/removed/changed functions, state layout changes, imports, calls, addresses, and new integrations.
- Produces a bounded drift summary without claiming that a bug exists.

### V4 — Category security lenses

Current lenses include lending, DEX, liquid staking, restaking, yield/vault, stablecoin/CDP, bridges,
derivatives/perpetuals, options, RWA, oracle, asset management, on-chain capital allocation, liquidity
management, intent/solver, aggregator, insurance, prediction markets, and NFT finance. Generic lenses cover
external calls, access control, upgrades, accounting, oracles, and cross-chain messaging.

The security-smell engine detects new callbacks, tokens, oracles, accounting, price dependencies, permissions, upgrade authority, initialization, storage changes, rounding, decimals, liquidation, shares, fees, withdrawals, strategies, bridges, adapters, and trust assumptions.

### V5 — Evidence-backed scope extraction

- Parses HTML and Markdown heading sections rather than applying one regex to an entire page.
- Extracts in-scope and out-of-scope text, addresses, chains, repositories, rules, reward amounts, PoC requirements, KYC, mainnet-testing restrictions, responsible disclosure, and known-issue exclusions.
- Stores the source URL, exact excerpt, capture time, content hash, and confidence with each claim.
- Returns `EVIDENCE_NOT_FOUND` when the official source does not establish a field.

## Requirements

- Python 3.11+
- A GitHub token for a complete crawl. Public unauthenticated access is too rate-limited for organization/repository/commit analysis.
- JSON-RPC URLs for chains whose deployments should be verified.

No third-party Python packages are required.

## Setup

```powershell
cd E:\FY\defi-security-recon
$env:PYTHONPATH = "src"
$env:GITHUB_TOKEN = gh auth token
```

Copy [the RPC configuration example](config/rpc-config.example.json) to a private file and replace the placeholder endpoints. The private file should not be committed. Alternatively, configure endpoints through variables such as `RPC_URL_1`, `RPC_URL_8453`, and `RPC_URL_42161`.

## Run

First ingest the complete DeFiLlama universe:

```powershell
python -m defi_recon sync
```

Inspect coverage:

```powershell
python -m defi_recon status
```

Research every queued protocol until the queue is empty or an upstream rate limit stops the run:

```powershell
python -m defi_recon research all --until-complete --rpc-config config/rpc-config.json
```

The job is resumable. Run the same command again after a rate-limit reset or interruption. Completed evidence remains in `data/recon-v2.db`.

Category-specific research is isolated:

```powershell
python -m defi_recon research lending --until-complete --rpc-config config/rpc-config.json
python -m defi_recon research dex --until-complete --rpc-config config/rpc-config.json
```

For a bounded operational run, use the soft time budget. It is checked between protocol jobs, so an in-flight
protocol is allowed to finish or reach a source timeout before the runner stops:

```powershell
python -m defi_recon research all --time-budget 900 --rpc-config config/rpc-config.json
```

Regenerate a report without crawling:

```powershell
python -m defi_recon report lending --days 30 --top 10
```

Inspect one protocol’s evidence and job state:

```powershell
python -m defi_recon protocol aave
```

## Coverage semantics

Reports always state:

- how many DeFiLlama protocols are stored;
- how many protocol jobs are complete;
- whether the report covers the whole universe;
- why a crawl stopped;
- which records need retrying.

An incomplete crawl is prominently labeled. A protocol missing from the target list is not treated as rejected until its evidence job is complete.

## Evidence semantics

| State | Meaning |
|---|---|
| `NO_BOUNTY_FOUND` | The checked official sources yielded no qualifying evidence; absence is not proven. |
| `ONCHAIN_CODE` | The address currently has runtime bytecode. It does not prove association with a commit. |
| `VERIFIED_SOURCE` | Sourcify has a source record for the address. |
| `PROXY_ACTIVE` | The current proxy storage resolves to an implementation that has runtime bytecode. |
| `ARTIFACT_CHANGED_IN_COMMIT` | An official deployment artifact containing the address changed in the analyzed commit. |
| `E2` | A meaningful production-contract change is confirmed. |
| `E3` | An associated deployment has on-chain evidence. |
| `E4` | An associated current proxy implementation is confirmed. |
| `E5` | First-party bounty + sensitive change + associated active proxy evidence. |

GitHub changes without an associated active deployment can never be promoted above `WATCHLIST`.

## Source authority

The pipeline uses:

- DeFiLlama for protocol universe, categories, chains, and TVL;
- official protocol domains and officially linked repositories for bounty and scope;
- GitHub’s API and raw immutable commit content for changes and deployment artifacts;
- chain JSON-RPC for runtime bytecode and proxy state;
- Sourcify API v2 for verified-source lookup.

It does not use synthetic protocols, fabricated addresses, manual score overrides, or LLM guesses as evidence.

## Scaling model

“Research all protocols” does not mean repeating every expensive request every day. Initial ingestion creates one persistent job per protocol. Subsequent runs revisit records after `next_scan_at`, scan commits since repository checkpoints, and retry unresolved sources independently. This makes full-universe coverage practical while preserving an auditable terminal state for every DeFiLlama protocol.

## Test

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Tests cover full-universe persistence, zero-TVL retention, first-party/platform separation, HTML and Markdown scope sections, semantic Solidity drift, category lenses, deployment artifact provenance, ERC-1967 active-implementation verification, and deployment-association gating.

## Honest limitations

- Websites requiring JavaScript may remain unresolved until a browser-rendering adapter is added.
- Non-EVM chains require chain-specific deployment verifiers; current automated RPC verification is EVM-focused.
- Diamond proxies are identified by repository/code semantics but are not yet resolved facet-by-facet on-chain.
- A deployment can occur without a committed deployment artifact. In that case the agent intentionally leaves commit association unproven.
- Contract source parsing is deterministic and conservative, not a full Solidity compiler AST. Complex generated code can require manual inspection.
- “First-party” requires an official-domain or officially linked repository policy with direct submission evidence. Ambiguous programs remain `UNKNOWN` or `NO_BOUNTY_FOUND`.
- The system prioritizes research opportunities. It does not prove exploitability or generate vulnerability findings.
