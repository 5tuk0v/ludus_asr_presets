#!/usr/bin/env python3
"""Tests for the offline ASR preset refresh tooling."""

from __future__ import annotations

from argparse import Namespace
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from asr_catalog import (  # noqa: E402
    CatalogRefreshError,
    catalog_rule_map,
    compare_rules,
    extract_archive_rules,
    normalized_rules_sha256,
)
from update_catalog import build_updated_catalog  # noqa: E402
from check_upstream import (  # noqa: E402
    _RestrictedRedirectHandler,
    discover_downloads,
    download_archives,
)


RULE_A = "11111111-1111-1111-1111-111111111111"
RULE_B = "22222222-2222-2222-2222-222222222222"


def policy_rules_xml(rules: dict[str, int]) -> bytes:
    entries = "".join(
        "<ComputerConfig>"
        "<Key>Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender "
        "Exploit Guard\\ASR\\Rules</Key>"
        f"<Value>{rule_id}</Value><RegType>REG_SZ</RegType>"
        f"<RegData>{action}</RegData>"
        "</ComputerConfig>"
        for rule_id, action in rules.items()
    )
    return f"<PolicyRules>{entries}</PolicyRules>".encode()


def write_archive(path: Path, documents: list[dict[str, int]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for index, rules in enumerate(documents):
            archive.writestr(
                f"Baseline/Documentation/source-{index}.PolicyRules",
                policy_rules_xml(rules),
            )


class ArchiveTests(unittest.TestCase):
    def test_extracts_rules_from_policy_rules_xml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "baseline.zip"
            write_archive(archive, [{RULE_A: 1, RULE_B: 2}])

            rules, policy_files = extract_archive_rules(archive)

        self.assertEqual(rules, {RULE_A: 1, RULE_B: 2})
        self.assertEqual(len(policy_files), 1)
        self.assertEqual(
            normalized_rules_sha256(rules),
            normalized_rules_sha256({RULE_B: 2, RULE_A: 1}),
        )

    def test_rejects_conflicting_policy_rules_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "baseline.zip"
            write_archive(archive, [{RULE_A: 1}, {RULE_A: 2}])

            with self.assertRaisesRegex(CatalogRefreshError, "conflicts"):
                extract_archive_rules(archive)

    def test_rejects_unexpected_registry_type(self) -> None:
        xml = policy_rules_xml({RULE_A: 1}).replace(b"REG_SZ", b"REG_DWORD")
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "baseline.zip"
            with zipfile.ZipFile(archive, "w") as baseline:
                baseline.writestr("Documentation/source.PolicyRules", xml)

            with self.assertRaisesRegex(CatalogRefreshError, "registry type"):
                extract_archive_rules(archive)

    def test_compares_added_removed_and_changed_rules(self) -> None:
        differences = compare_rules(
            {RULE_A: 1, RULE_B: 1},
            {RULE_A: 2, "33333333-3333-3333-3333-333333333333": 1},
        )

        self.assertEqual(
            differences["changed"], [{"id": RULE_A, "from": 1, "to": 2}]
        )
        self.assertEqual(differences["removed"], [{"id": RULE_B, "action": 1}])
        self.assertEqual(len(differences["added"]), 1)


class DownloadInventoryTests(unittest.TestCase):
    def test_reads_microsoft_download_inventory(self) -> None:
        details = {
            "dlcDetailsView": {
                "downloadFile": [
                    {
                        "name": "Example Security Baseline.zip",
                        "url": "https://download.microsoft.com/download/id/Example.zip",
                        "size": "123",
                        "datePublished": "9/27/2026",
                    }
                ]
            }
        }
        html = f"<script>window.__DLCDetails__={json.dumps(details)}</script>".encode()

        class FakeResponse:
            def __init__(self) -> None:
                self.stream = io.BytesIO(html)

            def __enter__(self) -> "FakeResponse":
                return self

            def __exit__(self, *args: object) -> None:
                return None

            def geturl(self) -> str:
                return "https://www.microsoft.com/en-us/download/details.aspx?id=55319"

            def read(self, size: int = -1) -> bytes:
                return self.stream.read(size)

        class FakeOpener:
            def open(self, request: Request, timeout: int) -> FakeResponse:
                return FakeResponse()

        with patch("check_upstream.build_opener", return_value=FakeOpener()):
            inventory = discover_downloads(
                "https://www.microsoft.com/en-us/download/details.aspx?id=55319"
            )

        self.assertEqual(inventory[0]["name"], "Example Security Baseline.zip")
        self.assertEqual(inventory[0]["size"], "123")

    def test_rejects_non_microsoft_source_page(self) -> None:
        with self.assertRaisesRegex(CatalogRefreshError, "non-Microsoft"):
            discover_downloads("https://example.invalid/download")

    def test_rejects_redirect_before_contacting_unapproved_host(self) -> None:
        handler = _RestrictedRedirectHandler({"download.microsoft.com"})
        with self.assertRaisesRegex(CatalogRefreshError, "unexpected host"):
            handler.redirect_request(
                Request("https://download.microsoft.com/file.zip"),
                None,
                302,
                "Found",
                {},
                "https://example.invalid/file.zip",
            )

    def test_reports_a_withdrawn_recorded_package(self) -> None:
        catalog = {
            "old": {
                "display_name": "Old baseline",
                "source_file": "Old Security Baseline.zip",
                "source_url": "https://www.microsoft.com/download/details.aspx?id=55319",
            }
        }
        with tempfile.TemporaryDirectory() as directory, patch(
            "check_upstream.discover_downloads", return_value=[]
        ):
            inventory, unavailable = download_archives(
                Namespace(archives_dir=Path(directory)), catalog
            )

        self.assertEqual(inventory, [])
        self.assertEqual(unavailable[0]["preset"], "old")
        self.assertEqual(unavailable[0]["source_file"], "Old Security Baseline.zip")


class UpdateTests(unittest.TestCase):
    def test_updates_only_reported_preset_block(self) -> None:
        catalog_data = {
            "ludus_asr_presets_catalog_version": "2026-01-01",
            "ludus_asr_presets_catalog": {
                "example": {
                    "display_name": "Example",
                    "source_name": "Example baseline",
                    "source_version": "v1",
                    "source_file": "Example.zip",
                    "source_sha256": "0" * 64,
                    "source_url": "https://example.invalid",
                    "rules": [
                        {"id": RULE_A, "name": "Rule A", "source_action": 1}
                    ],
                },
                "untouched": {
                    "display_name": "Untouched",
                    "source_name": "Reference",
                    "source_version": "v1",
                    "source_url": "https://example.invalid/reference",
                    "rules": [
                        {"id": RULE_B, "name": "Rule B", "source_action": 1}
                    ],
                },
            },
        }
        report = {
            "schema_version": 1,
            "retrieved_on": "2026-09-27",
            "catalog_version": "2026-01-01",
            "comparisons": [
                {
                    "preset": "example",
                    "status": "rules_changed",
                    "source_file": "Example.zip",
                    "archive_sha256": "a" * 64,
                    "recorded_sha256": "0" * 64,
                    "upstream_rules_sha256": normalized_rules_sha256(
                        {RULE_A: 2, RULE_B: 1}
                    ),
                    "catalog_rules_sha256": normalized_rules_sha256({RULE_A: 1}),
                    "rules": {RULE_A: 2, RULE_B: 1},
                }
            ],
        }

        with tempfile.TemporaryDirectory() as directory:
            catalog_path = Path(directory) / "main.yml"
            catalog_path.write_text(
                yaml.safe_dump(catalog_data, sort_keys=False), encoding="utf-8"
            )
            report["catalog"] = str(catalog_path)
            updated = build_updated_catalog(
                report, catalog_path, set(), {RULE_B: "Rule B"}
            )
            parsed = yaml.safe_load(updated)

            report["comparisons"][0]["upstream_rules_sha256"] = "c" * 64
            with self.assertRaisesRegex(CatalogRefreshError, "does not match its rules"):
                build_updated_catalog(report, catalog_path, set(), {RULE_B: "Rule B"})

        self.assertEqual(parsed["ludus_asr_presets_catalog_version"], "2026-09-27")
        example = parsed["ludus_asr_presets_catalog"]["example"]
        self.assertEqual(example["source_sha256"], "a" * 64)
        self.assertEqual(example["source_retrieved_at"], "2026-09-27")
        self.assertEqual(
            {rule["id"]: rule["source_action"] for rule in example["rules"]},
            {RULE_A: 2, RULE_B: 1},
        )
        self.assertEqual(
            parsed["ludus_asr_presets_catalog"]["untouched"],
            catalog_data["ludus_asr_presets_catalog"]["untouched"],
        )
        self.assertIn("    rules:\n      - id:", updated)

    def test_rejects_source_actions_outside_role_contract(self) -> None:
        catalog = yaml.safe_load(
            (ROOT / "vars" / "main.yml").read_text(encoding="utf-8")
        )
        report = {
            "schema_version": 1,
            "retrieved_on": "2026-09-27",
            "catalog_version": catalog["ludus_asr_presets_catalog_version"],
            "catalog": str(ROOT / "vars" / "main.yml"),
            "comparisons": [
                {
                    "preset": "windows_server_2022",
                    "status": "rules_changed",
                    "source_file": "Windows Server 2022 Security Baseline.zip",
                    "archive_sha256": "a" * 64,
                    "recorded_sha256": (
                        "49590cc694626d171fc934fafea6494f13ecd3843086704b7a5b98355909b8e0"
                    ),
                    "upstream_rules_sha256": normalized_rules_sha256({RULE_A: 6}),
                    "catalog_rules_sha256": normalized_rules_sha256(
                        catalog_rule_map(
                            catalog["ludus_asr_presets_catalog"][
                                "windows_server_2022"
                            ]
                        )
                    ),
                    "rules": {RULE_A: 6},
                }
            ],
        }
        with self.assertRaisesRegex(
            CatalogRefreshError, "outside the role's source contract"
        ):
            build_updated_catalog(
                report,
                ROOT / "vars" / "main.yml",
                {"windows_server_2022"},
                {RULE_A: "A"},
            )


if __name__ == "__main__":
    unittest.main()
