from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone

from defi_recon.deployment import DeploymentVerifier, RpcRegistry
from defi_recon.models import FileDelta, Protocol, Repository
from defi_recon.net import HttpResponse, SourceError
from defi_recon.pipeline import _analyze_commit


NOW = datetime(2026, 8, 30, tzinfo=timezone.utc)


class FakeGitHub:
    def commit_detail(self, repository, sha):
        return {
            "sha": sha,
            "html_url": f"https://github.com/{repository.full_name}/commit/{sha}",
            "parents": [{"sha": "parent"}],
            "commit": {
                "message": "Upgrade pool and publish mainnet deployment",
                "committer": {"date": NOW.isoformat()},
            },
            "files": [
                {
                    "filename": "contracts/Pool.sol",
                    "status": "modified",
                    "patch": "+ function liquidate(address user) external {}",
                },
                {
                    "filename": "deployments/mainnet.json",
                    "status": "modified",
                    "patch": '+ "PoolProxy": "0x1111111111111111111111111111111111111111"',
                },
            ],
        }

    @staticmethod
    def file_deltas(detail):
        return [
            FileDelta(
                str(item["filename"]), str(item["status"]), patch=str(item.get("patch") or "")
            )
            for item in detail["files"]
        ]

    @staticmethod
    def raw_file(repository, ref, path):
        if ref == "parent":
            return "contract Pool {}"
        return "contract Pool { function liquidate(address user) external {} }"

    @staticmethod
    def commit_time(detail):
        return NOW


class RpcHttp:
    def post_json(self, url, payload, headers=None):
        method = payload["method"]
        if method == "eth_getCode":
            result = "0x60016000"
        elif method == "eth_getStorageAt":
            slot = payload["params"][1]
            result = "0x" + ("0" * 24 + "2" * 40 if slot.startswith("0x3608") else "0" * 64)
        else:
            result = None
        return HttpResponse(
            url,
            200,
            json.dumps({"jsonrpc": "2.0", "id": payload["id"], "result": result}).encode(),
            "application/json",
        )

    def get(self, url, **kwargs):
        raise SourceError("not found", status=404, retryable=False)


class PipelineTests(unittest.TestCase):
    def test_contract_analysis_preserves_changed_deployment_artifact_for_v2_association(self) -> None:
        protocol = Protocol("1", "Acme", "acme", "Lending", ["Ethereum"], 1, "", "")
        repository = Repository("acme/core", "https://github.com/acme/core")

        change = _analyze_commit(protocol, repository, {"sha": "abc"}, FakeGitHub())

        self.assertIsNotNone(change)
        self.assertEqual(
            {item.filename for item in change.files},
            {"contracts/Pool.sol", "deployments/mainnet.json"},
        )
        self.assertTrue(change.meaningful)

        # This proves V2 receives the provenance it needs to make the commit/deployment association.
        from defi_recon.deployment import extract_address_artifacts

        artifacts = extract_address_artifacts(
            protocol,
            repository.full_name,
            change.commit,
            [("deployments/mainnet.json", '{"chainId":1,"PoolProxy":"0x1111111111111111111111111111111111111111"}')],
        )
        deployment = DeploymentVerifier(RpcHttp(), RpcRegistry({1: "https://rpc.example"})).verify(
            artifacts[0], change
        )
        self.assertEqual(deployment.association_status, "ARTIFACT_CHANGED_IN_COMMIT")
        self.assertEqual(deployment.status.value, "PROXY_ACTIVE")


if __name__ == "__main__":
    unittest.main()
