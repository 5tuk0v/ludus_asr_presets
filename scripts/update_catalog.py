#!/usr/bin/env python3
"""Prepare or apply catalog updates from a check_upstream JSON report."""

from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from asr_catalog import (
    CatalogRefreshError,
    GUID,
    SOURCE_ACTIONS,
    catalog_names,
    catalog_rule_map,
    extract_archive_rules,
    load_catalog,
    normalized_rules_sha256,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "vars" / "main.yml"
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class IndentedSafeDumper(yaml.SafeDumper):
    """Keep sequence indentation consistent with the hand-maintained catalog."""

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Prepare a catalog update from a reviewed upstream report."
    )
    parser.add_argument("report", type=Path, help="JSON from check_upstream.py")
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument(
        "--preset",
        action="append",
        default=[],
        help="update only this preset (repeatable; default: every changed preset)",
    )
    parser.add_argument(
        "--rule-names",
        type=Path,
        help="JSON object mapping newly added GUIDs to Microsoft rule names",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="write vars/main.yml; without this flag only show the proposed diff",
    )
    return parser.parse_args()


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogRefreshError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CatalogRefreshError(f"{path} must contain a JSON object")
    return value


def _replace_preset_block(text: str, preset_name: str, preset: dict[str, Any]) -> str:
    lines = text.splitlines(keepends=True)
    marker = f"  {preset_name}:\n"
    try:
        start = lines.index(marker)
    except ValueError as exc:
        raise CatalogRefreshError(f"cannot locate preset block {preset_name}") from exc
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if re.match(r"^  [a-z0-9_]+:\s*$", lines[index]):
            end = index
            break

    rendered = yaml.dump(
        {preset_name: preset},
        Dumper=IndentedSafeDumper,
        sort_keys=False,
        allow_unicode=True,
        width=1000,
    )
    replacement = [f"  {line}" for line in rendered.splitlines(keepends=True)]
    if end < len(lines) and replacement and replacement[-1].strip():
        replacement.append("\n")
    return "".join(lines[:start] + replacement + lines[end:])


def build_updated_catalog(
    report: dict[str, Any],
    catalog_path: Path,
    selected: set[str],
    extra_names: dict[str, str],
    verify_archives: bool = False,
) -> str:
    if report.get("schema_version") != 1:
        raise CatalogRefreshError("unsupported or missing report schema_version")
    try:
        retrieved_on = date.fromisoformat(str(report.get("retrieved_on", ""))).isoformat()
    except ValueError as exc:
        raise CatalogRefreshError("report has an invalid retrieved_on date") from exc
    data = load_catalog(catalog_path)
    reported_catalog = report.get("catalog")
    if not reported_catalog or Path(reported_catalog).resolve() != catalog_path.resolve():
        raise CatalogRefreshError(
            "report was generated from a different catalog path; rerun the checker"
        )
    if report.get("catalog_version") != data["ludus_asr_presets_catalog_version"]:
        raise CatalogRefreshError(
            "report catalog_version does not match the current catalog; rerun the checker"
        )
    catalog = data["ludus_asr_presets_catalog"]
    names = catalog_names(catalog)
    names.update({key.lower(): value for key, value in extra_names.items()})
    raw_comparisons = report.get("comparisons")
    if not isinstance(raw_comparisons, list):
        raise CatalogRefreshError("report comparisons must be a list")
    comparisons: dict[str, dict[str, Any]] = {}
    for item in raw_comparisons:
        if not isinstance(item, dict) or not isinstance(item.get("preset"), str):
            raise CatalogRefreshError("report contains an invalid comparison")
        preset_name = item["preset"]
        if preset_name in comparisons:
            raise CatalogRefreshError(f"report contains duplicate preset {preset_name}")
        comparisons[preset_name] = item
    targets = selected or {
        name for name, item in comparisons.items() if item["status"] != "current"
    }
    if not targets:
        raise CatalogRefreshError("report contains no catalog updates")
    missing = sorted(targets - set(comparisons))
    if missing:
        raise CatalogRefreshError("report has no comparison for: " + ", ".join(missing))

    updated_presets: dict[str, dict[str, Any]] = {}
    for preset_name in sorted(targets):
        if preset_name not in catalog:
            raise CatalogRefreshError(f"catalog has no preset {preset_name}")
        item = comparisons[preset_name]
        current = dict(catalog[preset_name])
        if item.get("recorded_sha256") != current.get("source_sha256"):
            raise CatalogRefreshError(
                f"{preset_name} source hash changed after the report was generated; "
                "rerun the checker"
            )
        current_rules_sha256 = normalized_rules_sha256(catalog_rule_map(current))
        if item.get("catalog_rules_sha256") != current_rules_sha256:
            raise CatalogRefreshError(
                f"{preset_name} rule map changed after the report was generated; "
                "rerun the checker"
            )
        archive_sha256 = str(item.get("archive_sha256", ""))
        upstream_rules_sha256 = str(item.get("upstream_rules_sha256", ""))
        if not SHA256.fullmatch(archive_sha256):
            raise CatalogRefreshError(f"{preset_name} report has an invalid archive SHA-256")
        if not SHA256.fullmatch(upstream_rules_sha256):
            raise CatalogRefreshError(
                f"{preset_name} report has an invalid normalized rule-map SHA-256"
            )
        if not isinstance(item.get("rules"), dict):
            raise CatalogRefreshError(f"{preset_name} report rules must be an object")
        upstream: dict[str, int] = {}
        for key, value in item["rules"].items():
            rule_id = str(key).lower()
            if not GUID.fullmatch(rule_id):
                raise CatalogRefreshError(
                    f"{preset_name} report has an invalid rule GUID: {key!r}"
                )
            try:
                upstream[rule_id] = int(value)
            except (TypeError, ValueError) as exc:
                raise CatalogRefreshError(
                    f"{preset_name} report has a nonnumeric action for {rule_id}"
                ) from exc
        calculated_rules_sha256 = normalized_rules_sha256(upstream)
        if calculated_rules_sha256 != upstream_rules_sha256:
            raise CatalogRefreshError(
                f"{preset_name} report rule-map hash does not match its rules"
            )
        if verify_archives:
            archive = Path(str(item.get("archive", "")))
            if archive.name != item.get("source_file"):
                raise CatalogRefreshError(
                    f"{preset_name} report source filename does not match its archive path"
                )
            if sha256_file(archive) != archive_sha256:
                raise CatalogRefreshError(
                    f"{preset_name} archive no longer matches the report SHA-256"
                )
            archive_rules, _ = extract_archive_rules(archive)
            if archive_rules != upstream:
                raise CatalogRefreshError(
                    f"{preset_name} archive rule map no longer matches the report"
                )
        unsupported = {
            rule_id: action
            for rule_id, action in upstream.items()
            if action not in SOURCE_ACTIONS
        }
        if unsupported:
            details = ", ".join(
                f"{rule_id}={action}" for rule_id, action in unsupported.items()
            )
            raise CatalogRefreshError(
                f"{preset_name} contains actions outside the role's source contract: {details}"
            )
        unnamed = sorted(rule_id for rule_id in upstream if rule_id not in names)
        if unnamed:
            raise CatalogRefreshError(
                "supply Microsoft reference names with --rule-names for: "
                + ", ".join(unnamed)
            )

        current_order = [str(rule["id"]).lower() for rule in current["rules"]]
        order = [rule_id for rule_id in current_order if rule_id in upstream]
        order.extend(rule_id for rule_id in upstream if rule_id not in current_order)

        preset: dict[str, Any] = {}
        preferred_metadata = (
            "display_name",
            "source_name",
            "source_version",
            "source_file",
            "source_retrieved_at",
            "source_sha256",
            "source_rules_sha256",
            "source_url",
        )
        replacements = {
            "source_file": item["source_file"],
            "source_retrieved_at": retrieved_on,
            "source_sha256": archive_sha256,
            "source_rules_sha256": upstream_rules_sha256,
        }
        for key in preferred_metadata:
            if key in replacements:
                preset[key] = replacements[key]
            elif key in current:
                preset[key] = current[key]
        for key, value in current.items():
            if key not in preset and key != "rules":
                preset[key] = value
        preset["rules"] = [
            {"id": rule_id, "name": names[rule_id], "source_action": upstream[rule_id]}
            for rule_id in order
        ]
        updated_presets[preset_name] = preset

    original = catalog_path.read_text(encoding="utf-8")
    updated = original
    for preset_name, preset in updated_presets.items():
        updated = _replace_preset_block(updated, preset_name, preset)
    updated = re.sub(
        r"(?m)^ludus_asr_presets_catalog_version:.*$",
        f"ludus_asr_presets_catalog_version: '{retrieved_on}'",
        updated,
        count=1,
    )
    return updated


def main() -> int:
    args = parse_args()
    try:
        report = _load_json_object(args.report)
        extra_names = _load_json_object(args.rule_names) if args.rule_names else {}
        updated = build_updated_catalog(
            report,
            args.catalog,
            set(args.preset),
            {str(key): str(value) for key, value in extra_names.items()},
            verify_archives=args.write,
        )
        original = args.catalog.read_text(encoding="utf-8")
    except (CatalogRefreshError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    diff = "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=str(args.catalog),
            tofile=str(args.catalog),
        )
    )
    if not diff:
        print("No catalog changes are required.")
        return 0
    print(diff, end="")
    if args.write:
        args.catalog.write_text(updated, encoding="utf-8")
        print(f"Updated {args.catalog}")
    else:
        print("Dry run only; pass --write after reviewing the evidence and diff.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
