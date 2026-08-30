from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import (
    AddressArtifact,
    Change,
    Deployment,
    DeploymentStatus,
    Evidence,
    Protocol,
    stable_hash,
)
from .net import HttpClient, SourceError


EIP1967_IMPLEMENTATION = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
EIP1967_ADMIN = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
BEACON_IMPLEMENTATION_SELECTOR = "0x5c60da1b"
ADDRESS_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
TX_RE = re.compile(r"\b0x[a-fA-F0-9]{64}\b")
MINIMAL_PROXY_RE = re.compile(r"363d3d373d3d3d363d73([a-fA-F0-9]{40})5af43d82803e903d91602b57fd5bf3")


@dataclass(frozen=True, slots=True)
class ChainInfo:
    name: str
    chain_id: int
    aliases: tuple[str, ...]


CHAINS = (
    ChainInfo("Ethereum", 1, ("ethereum", "mainnet", "eth")),
    ChainInfo("Optimism", 10, ("optimism", "opmainnet", "op")),
    ChainInfo("BNB Chain", 56, ("bsc", "bnb", "binance")),
    ChainInfo("Gnosis", 100, ("gnosis", "xdai")),
    ChainInfo("Polygon", 137, ("polygon", "matic")),
    ChainInfo("Sonic", 146, ("sonic",)),
    ChainInfo("zkSync Era", 324, ("zksync", "era")),
    ChainInfo("Moonbeam", 1284, ("moonbeam",)),
    ChainInfo("Polygon zkEVM", 1101, ("polygonzkevm", "zkevm")),
    ChainInfo("Mantle", 5000, ("mantle",)),
    ChainInfo("Base", 8453, ("base", "basemainnet")),
    ChainInfo("Arbitrum", 42161, ("arbitrum", "arb", "arbitrumone")),
    ChainInfo("Avalanche", 43114, ("avalanche", "avax", "cchain")),
    ChainInfo("Linea", 59144, ("linea",)),
    ChainInfo("Blast", 81457, ("blast",)),
    ChainInfo("Scroll", 534352, ("scroll",)),
)
CHAIN_BY_ID = {item.chain_id: item for item in CHAINS}


@dataclass(slots=True)
class RpcRegistry:
    urls: dict[int, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path | None = None) -> "RpcRegistry":
        urls: dict[int, str] = {}
        if path:
            if not path.is_file():
                raise ValueError(f"RPC configuration file does not exist: {path}")
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError(f"RPC configuration is not valid JSON: {path}: {exc}") from exc
            values = raw.get("rpc_urls", raw)
            if not isinstance(values, dict):
                raise ValueError("RPC configuration must be an object or contain an rpc_urls object")
            for key, value in values.items():
                if value:
                    try:
                        chain_id = int(key)
                    except (TypeError, ValueError) as exc:
                        raise ValueError(f"RPC chain id must be an integer: {key}") from exc
                    urls[chain_id] = str(value)
        for chain in CHAINS:
            env_value = os.getenv(f"RPC_URL_{chain.chain_id}") or os.getenv(f"RPC_{re.sub(r'[^A-Z0-9]+', '_', chain.name.upper())}")
            if env_value:
                urls[chain.chain_id] = env_value
        return cls(urls)

    def url(self, chain_id: int | None) -> str:
        return self.urls.get(chain_id or 0, "")


def infer_chain(path: str, text: str, protocol: Protocol) -> tuple[str, int | None]:
    corpus = re.sub(r"[^a-z0-9]+", "", f"{path} {text[:2000]}".lower())
    explicit_id = re.search(r"(?i)(?:chain[_ -]?id|chainId)[\"']?\s*[:=]\s*[\"']?(\d+)", text[:20_000])
    if explicit_id:
        chain_id = int(explicit_id.group(1))
        chain = CHAIN_BY_ID.get(chain_id)
        return (chain.name if chain else f"chain-{chain_id}", chain_id)
    for chain in CHAINS:
        if any(re.sub(r"[^a-z0-9]+", "", alias) in corpus for alias in chain.aliases):
            return chain.name, chain.chain_id
    if len(protocol.chains) == 1:
        name = protocol.chains[0]
        for chain in CHAINS:
            if name.lower() == chain.name.lower() or name.lower() in chain.aliases:
                return chain.name, chain.chain_id
        return name, None
    return "UNKNOWN", None


def extract_address_artifacts(protocol: Protocol, repository: str, commit: str,
                              artifacts: Iterable[tuple[str, str]]) -> list[AddressArtifact]:
    result: list[AddressArtifact] = []
    seen: set[tuple[str, str, int | None]] = set()
    for path, text in artifacts:
        chain, chain_id = infer_chain(path, text, protocol)
        parsed = None
        if path.lower().endswith(".json"):
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                pass
        records = _json_addresses(parsed) if parsed is not None else _text_addresses(text)
        for label, address, transaction_hash in records:
            address = address.lower()
            if int(address, 16) == 0 or int(address, 16) <= 9:
                continue
            key = (address, chain, chain_id)
            if key in seen:
                continue
            seen.add(key)
            url = f"https://github.com/{repository}/blob/{commit}/{path}"
            result.append(AddressArtifact(
                repository, commit, path, address, chain, chain_id, label[:200], transaction_hash,
                [Evidence("official repository publishes contract address", address, url, "github-deployment-artifact", 1.0,
                          excerpt=f"{label}: {address}")],
            ))
    return result


class DeploymentVerifier:
    def __init__(self, http: HttpClient, registry: RpcRegistry):
        self.http = http
        self.registry = registry
        self._rpc_id = 0

    def verify(self, artifact: AddressArtifact, change: Change | None = None) -> Deployment:
        deployment = Deployment(
            address=artifact.address, chain=artifact.chain, chain_id=artifact.chain_id,
            transaction_hash=artifact.transaction_hash, evidence=list(artifact.evidence),
        )
        changed_paths = {item.filename for item in change.files} if change else set()
        if change and artifact.path in changed_paths and artifact.commit == change.commit:
            deployment.associated_commit = change.commit
            deployment.association_status = "ARTIFACT_CHANGED_IN_COMMIT"
            deployment.evidence.append(Evidence(
                "deployment artifact changed in analyzed commit", artifact.path, change.url,
                "github-commit-file", 1.0, excerpt=artifact.path,
            ))
        rpc_url = self.registry.url(artifact.chain_id)
        if not rpc_url:
            deployment.status = DeploymentStatus.RPC_UNAVAILABLE
            deployment.error = f"No RPC configured for {artifact.chain} ({artifact.chain_id})"
            return deployment
        try:
            code = self._rpc(rpc_url, "eth_getCode", [artifact.address, "latest"])
            if not code or code == "0x":
                deployment.status = DeploymentStatus.NO_CODE
                deployment.confidence = 1.0
                deployment.evidence.append(Evidence(
                    "address has no runtime bytecode at latest block", "0x", rpc_url,
                    "onchain-json-rpc", 1.0,
                ))
                return deployment
            deployment.runtime_code_hash = stable_hash(bytes.fromhex(code[2:]))
            deployment.status = DeploymentStatus.ONCHAIN_CODE
            deployment.confidence = 1.0
            deployment.evidence.append(Evidence(
                "address has runtime bytecode at latest block", deployment.runtime_code_hash, rpc_url,
                "onchain-json-rpc", 1.0,
            ))
            implementation = _storage_address(self._rpc(rpc_url, "eth_getStorageAt", [artifact.address, EIP1967_IMPLEMENTATION, "latest"]))
            beacon = _storage_address(self._rpc(rpc_url, "eth_getStorageAt", [artifact.address, EIP1967_BEACON, "latest"]))
            admin = _storage_address(self._rpc(rpc_url, "eth_getStorageAt", [artifact.address, EIP1967_ADMIN, "latest"]))
            minimal = MINIMAL_PROXY_RE.search(code[2:])
            if not implementation and minimal:
                implementation = "0x" + minimal.group(1).lower()
            if not implementation and beacon:
                raw_impl = self._rpc(rpc_url, "eth_call", [{"to": beacon, "data": BEACON_IMPLEMENTATION_SELECTOR}, "latest"])
                implementation = _storage_address(raw_impl)
            deployment.implementation_address = implementation
            deployment.beacon_address = beacon
            deployment.admin_address = admin
            if implementation:
                implementation_code = self._rpc(rpc_url, "eth_getCode", [implementation, "latest"])
                if implementation_code and implementation_code != "0x":
                    deployment.status = DeploymentStatus.PROXY_ACTIVE
                    deployment.evidence.append(Evidence(
                        "proxy currently points to implementation with runtime code", implementation, rpc_url,
                        "onchain-proxy-storage", 1.0,
                    ))
            if artifact.transaction_hash:
                self._attach_transaction(rpc_url, deployment)
            self._attach_sourcify(deployment)
            return deployment
        except (SourceError, ValueError, TypeError, json.JSONDecodeError) as exc:
            deployment.status = DeploymentStatus.ERROR
            deployment.error = str(exc)
            return deployment

    def _rpc(self, url: str, method: str, params: list[Any]) -> Any:
        self._rpc_id += 1
        payload = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method, "params": params}
        raw = self.http.post_json(url, payload).json()
        if raw.get("error"):
            raise SourceError(f"RPC {method} error: {raw['error']}")
        return raw.get("result")

    def _attach_transaction(self, rpc_url: str, deployment: Deployment) -> None:
        receipt = self._rpc(rpc_url, "eth_getTransactionReceipt", [deployment.transaction_hash])
        if not receipt:
            return
        deployment.block_number = int(receipt["blockNumber"], 16)
        block = self._rpc(rpc_url, "eth_getBlockByNumber", [receipt["blockNumber"], False])
        if block and block.get("timestamp"):
            deployment.deployment_time = datetime.fromtimestamp(int(block["timestamp"], 16), timezone.utc)
        deployment.evidence.append(Evidence(
            "deployment transaction receipt exists", deployment.transaction_hash, rpc_url,
            "onchain-transaction-receipt", 1.0,
        ))

    def _attach_sourcify(self, deployment: Deployment) -> None:
        if not deployment.chain_id:
            return
        address = deployment.implementation_address or deployment.address
        url = f"https://sourcify.dev/server/v2/contract/{deployment.chain_id}/{address}?fields=all"
        try:
            raw = self.http.get(url, max_bytes=8_000_000, cache=False).json()
        except (SourceError, json.JSONDecodeError):
            return
        match = raw.get("match") or raw.get("runtimeMatch") or raw.get("creationMatch")
        if raw and not raw.get("error"):
            deployment.verified_source = True
            deployment.source_match = str(match or "verified")
            deployment.evidence.append(Evidence(
                "verified source record exists", deployment.source_match, url, "sourcify-v2", 1.0,
            ))
            if deployment.status == DeploymentStatus.ONCHAIN_CODE:
                deployment.status = DeploymentStatus.VERIFIED_SOURCE


def _json_addresses(value: Any, path: str = "") -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    if isinstance(value, dict):
        transaction_hash = next((str(item) for key, item in value.items() if re.search(r"(?i)(tx|transaction).*hash", str(key)) and isinstance(item, str) and TX_RE.fullmatch(item)), "")
        for key, item in value.items():
            current = f"{path}.{key}".strip(".")
            if isinstance(item, str) and ADDRESS_RE.fullmatch(item):
                result.append((current, item, transaction_hash))
            else:
                result.extend(_json_addresses(item, current))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_json_addresses(item, f"{path}[{index}]"))
    return result


def _text_addresses(text: str) -> list[tuple[str, str, str]]:
    result = []
    txs = TX_RE.findall(text)
    for match in ADDRESS_RE.finditer(text):
        context = text[max(0, match.start() - 120):match.start()]
        label_match = re.search(r"([A-Za-z_][A-Za-z0-9_. -]{0,80})\s*[:=]\s*[\"']?$", context)
        label = label_match.group(1).strip() if label_match else "unlabelled"
        result.append((label, match.group(0), txs[0] if len(txs) == 1 else ""))
    return result


def _storage_address(value: str | None) -> str:
    if not value or value == "0x":
        return ""
    clean = value.removeprefix("0x").rjust(64, "0")
    address = clean[-40:].lower()
    return "" if int(address, 16) == 0 else "0x" + address
