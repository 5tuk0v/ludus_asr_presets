#!/usr/bin/env python3
"""Shared helpers for comparing Microsoft baseline archives with the catalog."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path
from typing import Any

import yaml


ASR_RULES_KEY = (
    r"software\policies\microsoft\windows defender\windows defender exploit guard"
    r"\asr\rules"
)
GUID = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
KNOWN_ACTIONS = {0, 1, 2, 5, 6}
SOURCE_ACTIONS = {1, 2}
MAX_POLICY_FILE_BYTES = 16 * 1024 * 1024
MAX_POLICY_TOTAL_BYTES = 64 * 1024 * 1024


class CatalogRefreshError(RuntimeError):
    """Raised when source evidence cannot be interpreted safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalized_rules_sha256(rules: dict[str, int]) -> str:
    normalized = json.dumps(
        {rule_id: rules[rule_id] for rule_id in sorted(rules)},
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def load_catalog(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "ludus_asr_presets_catalog" not in data:
        raise CatalogRefreshError(f"{path} does not contain the ASR preset catalog")
    return data


def catalog_rule_map(preset: dict[str, Any]) -> dict[str, int]:
    return {
        str(rule["id"]).lower(): int(rule["source_action"])
        for rule in preset["rules"]
    }


def catalog_names(catalog: dict[str, Any]) -> dict[str, str]:
    names: dict[str, str] = {}
    for preset in catalog.values():
        for rule in preset["rules"]:
            names[str(rule["id"]).lower()] = str(rule["name"])
    return names


def _child_text(element: ET.Element, name: str) -> str | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return child.text
    return None


def _rules_from_policy_xml(xml_bytes: bytes, source: str) -> dict[str, int]:
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise CatalogRefreshError(f"cannot parse {source}: {exc}") from exc

    rules: dict[str, int] = {}
    for entry in root.iter():
        if entry.tag.rsplit("}", 1)[-1] != "ComputerConfig":
            continue
        key = (_child_text(entry, "Key") or "").lower()
        if key != ASR_RULES_KEY:
            continue
        rule_id = (_child_text(entry, "Value") or "").lower()
        registry_type = _child_text(entry, "RegType") or ""
        action_text = _child_text(entry, "RegData") or ""
        if not GUID.fullmatch(rule_id):
            raise CatalogRefreshError(f"{source}: invalid ASR rule GUID {rule_id!r}")
        if registry_type.upper() != "REG_SZ":
            raise CatalogRefreshError(
                f"{source}: ASR rule {rule_id} uses unexpected registry type "
                f"{registry_type!r}"
            )
        try:
            action = int(action_text)
        except ValueError as exc:
            raise CatalogRefreshError(
                f"{source}: ASR rule {rule_id} has nonnumeric action {action_text!r}"
            ) from exc
        if action not in KNOWN_ACTIONS:
            raise CatalogRefreshError(
                f"{source}: ASR rule {rule_id} has unknown action {action}"
            )
        previous = rules.get(rule_id)
        if previous is not None and previous != action:
            raise CatalogRefreshError(
                f"{source}: ASR rule {rule_id} has conflicting actions "
                f"{previous} and {action}"
            )
        rules[rule_id] = action
    return rules


def extract_archive_rules(archive: Path) -> tuple[dict[str, int], list[str]]:
    if not archive.is_file():
        raise CatalogRefreshError(f"archive does not exist: {archive}")
    if not zipfile.is_zipfile(archive):
        raise CatalogRefreshError(f"archive is not a ZIP file: {archive}")

    combined: dict[str, int] = {}
    policy_files: list[str] = []
    with zipfile.ZipFile(archive) as baseline:
        members = sorted(
            (
                info
                for info in baseline.infolist()
                if info.filename.lower().endswith(".policyrules")
            ),
            key=lambda info: info.filename,
        )
        if not members:
            raise CatalogRefreshError(
                f"{archive} contains no .PolicyRules evidence; inspect the package manually"
            )
        total_size = sum(member.file_size for member in members)
        if total_size > MAX_POLICY_TOTAL_BYTES:
            raise CatalogRefreshError(
                f"{archive} contains oversized .PolicyRules evidence ({total_size} bytes)"
            )
        for member in members:
            if member.file_size > MAX_POLICY_FILE_BYTES:
                raise CatalogRefreshError(
                    f"{archive}: {member.filename} exceeds the policy-file size limit"
                )
            policy_files.append(member.filename)
            with baseline.open(member) as source:
                xml_bytes = source.read(MAX_POLICY_FILE_BYTES + 1)
            if len(xml_bytes) > MAX_POLICY_FILE_BYTES:
                raise CatalogRefreshError(
                    f"{archive}: {member.filename} exceeds the policy-file size limit"
                )
            extracted = _rules_from_policy_xml(xml_bytes, member.filename)
            for rule_id, action in extracted.items():
                previous = combined.get(rule_id)
                if previous is not None and previous != action:
                    raise CatalogRefreshError(
                        f"{archive}: ASR rule {rule_id} conflicts across .PolicyRules files "
                        f"({previous} and {action})"
                    )
                combined[rule_id] = action

    if not combined:
        raise CatalogRefreshError(f"{archive} contains no configured ASR rules")
    return combined, policy_files


def compare_rules(current: dict[str, int], upstream: dict[str, int]) -> dict[str, Any]:
    added = [
        {"id": rule_id, "action": upstream[rule_id]}
        for rule_id in upstream
        if rule_id not in current
    ]
    removed = [
        {"id": rule_id, "action": current[rule_id]}
        for rule_id in current
        if rule_id not in upstream
    ]
    changed = [
        {"id": rule_id, "from": current[rule_id], "to": upstream[rule_id]}
        for rule_id in current
        if rule_id in upstream and current[rule_id] != upstream[rule_id]
    ]
    return {"added": added, "removed": removed, "changed": changed}


def action_label(action: int) -> str:
    return {
        0: "Disabled",
        1: "Block",
        2: "Audit",
        5: "Not configured",
        6: "Warn",
    }.get(action, f"Unknown ({action})")
