from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from defi_recon.deployment import DeploymentVerifier, RpcRegistry, extract_address_artifacts
from defi_recon.models import Change, FileDelta, Protocol
from defi_recon.net import HttpResponse, SourceError


class RpcHttp:
    def post_json(self, url, payload, headers=None):
        method = payload["method"]
        if method == "eth_getCode":
            result = "0x60016000" if payload["params"][0].lower().endswith(("1111", "2222")) else "0x"
        elif method == "eth_getStorageAt":
            slot = payload["params"][1]
            result = "0x" + ("0" * 24 + "2" * 40 if slot.startswith("0x3608") else "0" * 64)
        else:
            result = None
        return HttpResponse(url, 200, json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode(), "application/json")

    def get(self, url, **kwargs):
        if "sourcify" in url:
            return HttpResponse(url, 200, b'{"match":"exact_match"}', "application/json")
        raise SourceError("not found", status=404, retryable=False)


class DeploymentTests(unittest.TestCase):
    def test_invalid_rpc_configuration_has_an_actionable_error(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not exist"):
            RpcRegistry.load(Path("definitely-missing-rpc-config.json"))

    def test_artifact_parser_keeps_chain_and_transaction_provenance(self) -> None:
        protocol = Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 1, "", "")
        payload = json.dumps({"chainId": 1, "PoolProxy": "0x1111111111111111111111111111111111111111",
                              "transactionHash": "0x" + "a" * 64})
        artifacts = extract_address_artifacts(protocol, "acme/core", "abc", [("deployments/mainnet.json", payload)])
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].chain_id, 1)
        self.assertEqual(artifacts[0].transaction_hash, "0x" + "a" * 64)

    def test_rpc_verifies_current_eip1967_implementation_and_association(self) -> None:
        protocol = Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 1, "", "")
        artifacts = extract_address_artifacts(protocol, "acme/core", "abc", [
            ("deployments/mainnet.json", '{"chainId":1,"Pool":"0x1111111111111111111111111111111111111111"}')
        ])
        change = Change("acme/core", "abc", "p", "https://github.com/acme/core/commit/abc",
                        datetime(2026, 8, 30, tzinfo=timezone.utc),
                        "deploy", [FileDelta("deployments/mainnet.json", "modified")])
        deployment = DeploymentVerifier(RpcHttp(), RpcRegistry({1: "https://rpc.example"})).verify(artifacts[0], change)
        self.assertEqual(deployment.status.value, "PROXY_ACTIVE")
        self.assertEqual(deployment.implementation_address, "0x" + "2" * 40)
        self.assertEqual(deployment.association_status, "ARTIFACT_CHANGED_IN_COMMIT")
        self.assertTrue(deployment.verified_source)


if __name__ == "__main__":
    unittest.main()
