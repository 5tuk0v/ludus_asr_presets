#!/usr/bin/env python3
"""Validate the versioned ASR preset catalog without contacting Microsoft."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
GUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
EXPECTED = {
    "microsoft_basic": (3, {}),
    "windows_server_2022": (13, {}),
    "windows_server_2025": (8, {}),
    "windows_11_24h2": (14, {}),
    "windows_11_25h2": (15, {"d1e49aac-8f56-4280-b9ba-993a6d77406c": 2}),
}


def main() -> None:
    data = yaml.safe_load((ROOT / "vars" / "main.yml").read_text(encoding="utf-8"))
    catalog = data["ludus_asr_presets_catalog"]
    assert set(catalog) == set(EXPECTED), "unexpected preset names"

    names_by_guid: dict[str, str] = {}
    for preset_name, preset in catalog.items():
        expected_count, action_exceptions = EXPECTED[preset_name]
        rules = preset["rules"]
        assert len(rules) == expected_count, f"{preset_name}: unexpected rule count"
        ids = [rule["id"] for rule in rules]
        assert len(ids) == len(set(ids)), f"{preset_name}: duplicate GUID"

        for rule in rules:
            rule_id = rule["id"]
            assert GUID.fullmatch(rule_id), f"{preset_name}: invalid GUID {rule_id}"
            expected_action = action_exceptions.get(rule_id, 1)
            assert rule["source_action"] == expected_action, (
                f"{preset_name}: unexpected source action for {rule_id}"
            )
            previous_name = names_by_guid.setdefault(rule_id, rule["name"])
            assert previous_name == rule["name"], f"inconsistent name for {rule_id}"

    print("ASR preset catalog validation passed")


if __name__ == "__main__":
    main()
