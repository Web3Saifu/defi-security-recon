# DeFi Security Recon

An evidence-first reconnaissance agent that reduces a DeFi protocol universe to a small list of security research leads. It does **not** claim that a recent commit is deployed or vulnerable. Every important claim carries a source, source type, confidence, and observation time.

This repository implements the V1 pipeline from the supplied design:

```text
DeFiLlama universe
  -> category and TVL eligibility
  -> conservative first-party bounty detection
  -> GitHub repository discovery
  -> recent contract-change collection
  -> category-aware change classification
  -> evidence gates and scoring
  -> Markdown + JSON report
  -> SQLite research memory
```

The deployment, scope, and normalized database models are already present so later phases can be added without changing the output contract. V1 never invents deployment evidence: an unverified code change is capped at `WATCHLIST`.

## Quick start

Python 3.11 or newer is the only runtime requirement.

```powershell
cd E:\FY\defi-security-recon
$env:PYTHONPATH = "src"
python -m defi_recon demo
```

The demo is deterministic and offline. It proves all important branches:

- an active, scoped, first-party bounty lead reaches `E5`;
- a meaningful but deployment-unverified change remains `E2 / WATCHLIST`;
- a platform-hosted bounty is removed by the hard filter.

For a live scan:

```powershell
$env:PYTHONPATH = "src"
$env:GITHUB_TOKEN = "your-read-only-token"
python -m defi_recon research lending --days 30 --top 10 --max-protocols 100
```

Or install the command in a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e .
.venv\Scripts\defi-recon research lending --days 30 --top 10
```

The live adapters use the public [DeFiLlama API](https://defillama.com/docs/api) and GitHub's [REST commit endpoints](https://docs.github.com/en/rest/commits/commits). A GitHub token is strongly recommended because commit-detail analysis consumes API requests; the token only needs public repository read access.

## Commands

```text
defi-recon research all
defi-recon research lending --days 30 --top 10
defi-recon research dex --min-score 70
defi-recon research lending --new-integration
defi-recon research lending --deployment-verified
defi-recon research lending --overrides config/my-evidence.json
defi-recon demo lending
defi-recon history
```

Useful controls:

| Option | Default | Meaning |
|---|---:|---|
| `--days` | 30 | GitHub collection window |
| `--top` | 10 | Maximum report entries |
| `--min-score` | 55 | Minimum normalized opportunity score |
| `--min-confidence` | 0.85 | Minimum mean confidence of established claims |
| `--min-tvl` | 1,000,000 | Economic-value prescreen |
| `--max-protocols` | 100 | Bounded live crawl size |
| `--max-commits` | 12 | Commit details inspected per repository |
| `--include-platform-bounties` | off | Disable the first-party hard gate |
| `--deployment-verified` | off | Require explicit `ACTIVE` deployment evidence |
| `--new-integration` | off | Keep only new trust-boundary signals |
| `--no-save` | off | Do not write SQLite history |

Reports are saved under `reports/`; normalized state is saved to `data/recon.db`.

## Evidence levels and gates

| Level | Required evidence |
|---|---|
| `E0` | No useful evidence |
| `E1` | GitHub commit only |
| `E2` | Meaningful contract change + commit |
| `E3` | Deployment evidence |
| `E4` | Current active implementation confirmed |
| `E5` | First-party bounty + active deployment + sensitive change |

Hard gates run before promotion:

1. A first-party bounty must be established unless explicitly disabled.
2. A meaningful production-code file must have changed; docs and test-only commits fail.
3. `--deployment-verified` requires `ACTIVE`, not merely `DEPLOYED` or a deployment script.
4. Failed gates are excluded, not rescued by additive scoring.

`NO_BOUNTY_FOUND` only means an official site was reachable but the crawler found no bounty evidence. `UNKNOWN` means it could not establish enough evidence to decide. Neither state means the protocol definitely has no bounty.

## Scoring

The 100-point score follows the supplied architecture:

| Signal | Points |
|---|---:|
| First-party bounty | 20 |
| Change freshness | 20 |
| Change significance | 20 |
| Security sensitivity | 15 |
| Integration novelty | 10 |
| TVL/value | 5 |
| Low competition heuristic | 5 |
| Scope clarity | 5 |

Freshness and novelty are separate. Category lenses recognize lending, DEX, liquid-staking, yield/vault, stablecoin, and CDP terminology. Unknown categories still receive generic upgradeability, accounting, oracle, external-call, access-control, and cross-chain lenses.

Competition is visibly labeled a heuristic. It uses TVL, published audit count, and protocol age; it is not represented as factual evidence of researcher activity.

## Adding verified evidence

Automatic on-chain deployment verification is deliberately not faked in V1. Add known official/on-chain evidence through an overrides file using [the example](config/protocol-overrides.example.json):

```powershell
python -m defi_recon research lending --overrides config/my-evidence.json --deployment-verified
```

Overrides are keyed by the DeFiLlama slug and can supply:

- GitHub repositories that were not discoverable from official metadata;
- a directly verified first-party bounty URL;
- exact scope evidence;
- active proxy/implementation and transaction evidence.

Treat overrides as curated evidence, not as a way to force a score. Use official pages and explorer/on-chain sources, and set confidence conservatively.

## Data model

SQLite stores `runs`, `protocols`, `bounties`, `changes`, `deployments`, and `targets`. Raw evidence is preserved as JSON alongside normalized query fields. The JSON report is the stable machine-readable handoff for a later deployment verifier, semantic drift analyzer, or security reasoning agent.

## Test

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

The suite covers category isolation, docs/test false-positive rejection, category security lenses, evidence-level promotion, first-party gating, platform rejection, scope extraction, SSRF defense for literal private URLs, deployment gating, and normalized persistence.

## Current boundaries

- JavaScript-rendered bounty pages may require a future browser adapter.
- Official-site heuristics are intentionally conservative and can return `UNKNOWN`.
- GitHub metadata does not prove deployment; only supplied on-chain evidence can do that in V1.
- Scope extraction is deterministic and section-based. Ambiguous prose stays `EVIDENCE_NOT_FOUND`.
- The crawler is bounded and synchronous so API usage is predictable. Scheduled execution and worker queues belong in the next operational phase.
- The tool prioritizes where to investigate. It does not find bugs, test mainnet, or claim exploitability.

## Next implementation phases

1. RPC/explorer deployment verifier with EIP-1967, beacon, diamond, and non-proxy strategies.
2. Old-production versus new-production ABI/storage/semantic drift.
3. Integration graph and first-seen trust-boundary memory.
4. Stronger category-specific lenses and explicit security-smell output.
5. Structured scope and rule extraction for JS-rendered official pages.
6. Audits/contests/researcher-activity competition inputs.
7. Bounded reasoning handoff that asks what changed without claiming a bug.
