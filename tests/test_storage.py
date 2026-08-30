from __future__ import annotations

import unittest

from defi_recon.models import Protocol
from defi_recon.storage import ReconStore


class StorageTests(unittest.TestCase):
    def test_full_universe_is_persisted_without_tvl_filter_or_limit(self) -> None:
        protocols = [
            Protocol(str(index), f"P{index}", f"p{index}", "Unknown", [], float(index), "", f"https://defillama.com/p/{index}", raw={"id": str(index)})
            for index in range(250)
        ]
        with ReconStore(":memory:") as store:
            total, new = store.sync_universe(protocols, "https://api.llama.fi/protocols", "hash", 24)
            self.assertEqual((total, new), (250, 250))
            self.assertEqual(len(store.work_items("all", 0)), 250)
            self.assertEqual(store.status()["protocols"], 250)

    def test_category_aliases_select_the_expected_defillama_category(self) -> None:
        with ReconStore(":memory:") as store:
            protocols = [
                Protocol("1", "Liquid", "liquid", "Liquid Staking", ["Ethereum"], 2, "", ""),
                Protocol("2", "Exchange", "exchange", "Dexes", ["Ethereum"], 1, "", ""),
            ]
            store.sync_universe(protocols, "https://api.llama.fi/protocols", "hash", 24)
            self.assertEqual([item.slug for item in store.work_items("liquid-staking")], ["liquid"])
            self.assertEqual([item.slug for item in store.work_items("dex")], ["exchange"])


if __name__ == "__main__":
    unittest.main()
