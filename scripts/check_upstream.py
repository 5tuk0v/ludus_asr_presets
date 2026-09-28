#!/usr/bin/env python3
"""Compare Microsoft Security Compliance Toolkit archives with ASR presets."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from asr_catalog import (
    CatalogRefreshError,
    action_label,
    catalog_names,
    catalog_rule_map,
    compare_rules,
    extract_archive_rules,
    load_catalog,
    normalized_rules_sha256,
    sha256_file,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = ROOT / "vars" / "main.yml"
DOWNLOAD_PAGE_HOSTS = {"microsoft.com", "www.microsoft.com"}
DOWNLOAD_FILE_HOST = "download.microsoft.com"
MAX_PAGE_BYTES = 8 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 1024 * 1024 * 1024


def _archive_assignment(value: str) -> tuple[str, Path]:
    preset, separator, path = value.partition("=")
    if not separator or not preset or not path:
        raise argparse.ArgumentTypeError("use PRESET=/path/to/baseline.zip")
    return preset, Path(path).expanduser().resolve()


def _iso_date(value: str) -> str:
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise argparse.ArgumentTypeError("use an ISO date such as 2026-09-27") from exc


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a report-only comparison of Microsoft baseline archives."
    )
    parser.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        type=_archive_assignment,
        metavar="PRESET=ZIP",
        help="compare one preset with a downloaded Microsoft baseline ZIP",
    )
    parser.add_argument(
        "--archives-dir",
        type=Path,
        help="directory containing ZIPs named by each preset's source_file",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="download current official packages into --archives-dir before checking",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="require an archive for every archive-backed preset",
    )
    parser.add_argument(
        "--retrieved-on",
        type=_iso_date,
        default=date.today().isoformat(),
        help="date the supplied source archives were retrieved (default: today)",
    )
    parser.add_argument("--json-report", type=Path)
    parser.add_argument("--markdown-report", type=Path)
    return parser.parse_args()


def _https_url_on_host(url: str, allowed_hosts: set[str]) -> bool:
    parsed = urlparse(url)
    return parsed.scheme == "https" and parsed.hostname in allowed_hosts


def _encoded_url(url: str) -> str:
    return quote(url, safe=":/?&=%")


class _RestrictedRedirectHandler(HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Request | None:
        destination = urljoin(req.full_url, newurl)
        if not _https_url_on_host(destination, self.allowed_hosts):
            raise CatalogRefreshError(
                f"refusing redirect to an unexpected host: {destination}"
            )
        return super().redirect_request(req, fp, code, msg, headers, destination)


def _read_limited(response: Any, limit: int, label: str) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(1024 * 1024, limit - total + 1))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise CatalogRefreshError(f"{label} exceeds the {limit}-byte size limit")
    return b"".join(chunks)


def discover_downloads(source_url: str) -> list[dict[str, str]]:
    if not _https_url_on_host(source_url, DOWNLOAD_PAGE_HOSTS):
        raise CatalogRefreshError(f"refusing non-Microsoft source page: {source_url}")
    request = Request(
        _encoded_url(source_url),
        headers={"User-Agent": "ludus-asr-presets-maintenance/1"},
    )
    opener = build_opener(_RestrictedRedirectHandler(DOWNLOAD_PAGE_HOSTS))
    try:
        with opener.open(request, timeout=60) as response:
            final_url = response.geturl()
            if not _https_url_on_host(final_url, DOWNLOAD_PAGE_HOSTS):
                raise CatalogRefreshError(
                    f"Microsoft source page redirected to an unexpected host: {final_url}"
                )
            html = _read_limited(response, MAX_PAGE_BYTES, "Microsoft source page").decode(
                "utf-8", errors="replace"
            )
    except OSError as exc:
        raise CatalogRefreshError(f"cannot retrieve {source_url}: {exc}") from exc

    marker = "window.__DLCDetails__="
    start = html.find(marker)
    if start < 0:
        raise CatalogRefreshError(
            f"{source_url} does not contain the expected Microsoft download inventory"
        )
    try:
        details, _ = json.JSONDecoder().raw_decode(html[start + len(marker) :])
        files = details["dlcDetailsView"]["downloadFile"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CatalogRefreshError(
            f"cannot parse the Microsoft download inventory at {source_url}"
        ) from exc
    if not isinstance(files, list):
        raise CatalogRefreshError(f"{source_url} returned an invalid download inventory")

    inventory: list[dict[str, str]] = []
    for item in files:
        if not isinstance(item, dict):
            raise CatalogRefreshError(f"{source_url} returned an invalid download entry")
        name = str(item.get("name", ""))
        download_url = str(item.get("url", ""))
        if not name or Path(name).name != name:
            raise CatalogRefreshError(f"Microsoft inventory contains an unsafe filename: {name!r}")
        if not _https_url_on_host(download_url, {DOWNLOAD_FILE_HOST}):
            raise CatalogRefreshError(
                f"Microsoft inventory contains an unexpected download URL: {download_url}"
            )
        inventory.append(
            {
                "name": name,
                "url": download_url,
                "size": str(item.get("size", "")),
                "date_published": str(item.get("datePublished", "")),
            }
        )
    return inventory


def _download_file(item: dict[str, str], destination: Path) -> None:
    request = Request(
        _encoded_url(item["url"]),
        headers={"User-Agent": "ludus-asr-presets-maintenance/1"},
    )
    advertised_size = int(item["size"]) if item["size"].isdigit() else None
    if advertised_size is not None and advertised_size > MAX_DOWNLOAD_BYTES:
        raise CatalogRefreshError(
            f"{item['name']} exceeds the {MAX_DOWNLOAD_BYTES}-byte download limit"
        )
    opener = build_opener(_RestrictedRedirectHandler({DOWNLOAD_FILE_HOST}))
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".part",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            with opener.open(request, timeout=120) as response:
                final_url = response.geturl()
                if not _https_url_on_host(final_url, {DOWNLOAD_FILE_HOST}):
                    raise CatalogRefreshError(
                        f"download redirected to an unexpected host: {final_url}"
                    )
                total = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise CatalogRefreshError(
                            f"{item['name']} exceeds the "
                            f"{MAX_DOWNLOAD_BYTES}-byte download limit"
                        )
        if advertised_size is not None and total != advertised_size:
            raise CatalogRefreshError(
                f"{item['name']} size is {total}; Microsoft advertised {item['size']}"
            )
        os.replace(temporary, destination)
    except (OSError, ValueError, CatalogRefreshError):
        temporary.unlink(missing_ok=True)
        raise


def download_archives(
    args: argparse.Namespace, catalog: dict[str, Any]
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    if not args.archives_dir:
        raise CatalogRefreshError("--download requires --archives-dir")
    directory = args.archives_dir.expanduser().resolve()
    directory.mkdir(parents=True, exist_ok=True)
    source_urls = {
        str(preset["source_url"])
        for preset in catalog.values()
        if preset.get("source_file")
    }
    inventory: list[dict[str, str]] = []
    for source_url in sorted(source_urls):
        inventory.extend(discover_downloads(source_url))
    by_name = {item["name"]: item for item in inventory}
    unavailable: list[dict[str, str]] = []
    for preset_name, preset in catalog.items():
        source_file = preset.get("source_file")
        if not source_file:
            continue
        if source_file not in by_name:
            unavailable.append(
                {
                    "preset": preset_name,
                    "display_name": str(preset["display_name"]),
                    "source_file": str(source_file),
                }
            )
            print(
                f"Warning: Microsoft no longer lists {source_file!r} for {preset_name}",
                file=sys.stderr,
            )
            continue
        destination = directory / str(source_file)
        print(f"Downloading {source_file}", file=sys.stderr)
        _download_file(by_name[str(source_file)], destination)
    return inventory, unavailable


def _resolve_archives(
    args: argparse.Namespace,
    catalog: dict[str, Any],
    unavailable_presets: set[str] | None = None,
) -> dict[str, Path]:
    unavailable_presets = unavailable_presets or set()
    resolved: dict[str, Path] = {}
    if args.archives_dir:
        directory = args.archives_dir.expanduser().resolve()
        for preset_name, preset in catalog.items():
            source_file = preset.get("source_file")
            if source_file and preset_name not in unavailable_presets:
                candidate = directory / str(source_file)
                if candidate.is_file():
                    resolved[preset_name] = candidate

    for preset_name, archive in args.archive:
        if preset_name in resolved:
            raise CatalogRefreshError(f"archive supplied twice for {preset_name}")
        resolved[preset_name] = archive

    archive_presets = {
        name for name, preset in catalog.items() if preset.get("source_file")
    }
    unknown = sorted(set(resolved) - archive_presets)
    if unknown:
        raise CatalogRefreshError(
            "unknown or non-archive preset(s): " + ", ".join(unknown)
        )
    if args.all:
        missing = sorted(archive_presets - set(resolved) - unavailable_presets)
        if missing:
            raise CatalogRefreshError(
                "missing archive(s) for: " + ", ".join(missing)
            )
    if not resolved and not unavailable_presets:
        raise CatalogRefreshError("supply --archive or --archives-dir")
    return resolved


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    data = load_catalog(args.catalog)
    catalog = data["ludus_asr_presets_catalog"]
    if args.download:
        download_inventory, unavailable = download_archives(args, catalog)
    else:
        download_inventory, unavailable = [], []
    unavailable_presets = {item["preset"] for item in unavailable}
    archives = _resolve_archives(args, catalog, unavailable_presets)
    names = catalog_names(catalog)
    comparisons: list[dict[str, Any]] = []

    for preset_name in sorted(archives):
        preset = catalog[preset_name]
        archive = archives[preset_name]
        expected_file = str(preset["source_file"])
        if archive.name != expected_file:
            raise CatalogRefreshError(
                f"{preset_name} expects {expected_file!r}, not {archive.name!r}; "
                "treat a newly named Microsoft baseline as a new preset"
            )
        upstream, policy_files = extract_archive_rules(archive)
        current = catalog_rule_map(preset)
        differences = compare_rules(current, upstream)
        archive_sha256 = sha256_file(archive)
        recorded_sha256 = str(preset.get("source_sha256", ""))
        rules_changed = any(differences.values())
        hash_changed = archive_sha256 != recorded_sha256
        if rules_changed:
            status = "rules_changed"
        elif hash_changed:
            status = "source_changed_rules_unchanged"
        else:
            status = "current"
        comparisons.append(
            {
                "preset": preset_name,
                "display_name": preset["display_name"],
                "status": status,
                "archive": str(archive),
                "source_file": archive.name,
                "archive_sha256": archive_sha256,
                "recorded_sha256": recorded_sha256,
                "archive_hash_changed": hash_changed,
                "upstream_rules_sha256": normalized_rules_sha256(upstream),
                "catalog_rules_sha256": normalized_rules_sha256(current),
                "policy_files": policy_files,
                "rules": upstream,
                "differences": differences,
                "known_names": {
                    rule_id: names[rule_id]
                    for rule_id in upstream
                    if rule_id in names
                },
            }
        )

    for item in unavailable:
        comparisons.append(
            {
                **item,
                "status": "source_unavailable",
                "archive_sha256": "-",
                "rules": {},
            }
        )
    comparisons.sort(key=lambda item: item["preset"])

    return {
        "schema_version": 1,
        "retrieved_on": args.retrieved_on,
        "catalog": str(args.catalog.resolve()),
        "catalog_version": data["ludus_asr_presets_catalog_version"],
        "download_inventory": download_inventory,
        "comparisons": comparisons,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# ASR preset upstream comparison",
        "",
        f"Source archives retrieved: {report['retrieved_on']}",
        f"Catalog version: {report['catalog_version']}",
        "",
        "| Preset | Status | Archive SHA-256 | Rules |",
        "| --- | --- | --- | ---: |",
    ]
    for item in report["comparisons"]:
        lines.append(
            f"| `{item['preset']}` | {item['status']} | "
            f"`{item['archive_sha256']}` | {len(item['rules'])} |"
        )

    for item in report["comparisons"]:
        lines.extend(["", f"## {item['display_name']}", ""])
        lines.append(f"- Source file: `{item['source_file']}`")
        if item["status"] == "source_unavailable":
            lines.extend(
                [
                    "",
                    "Microsoft no longer lists this recorded package. Review the current "
                    "inventory before changing or removing the preset.",
                ]
            )
            continue
        lines.append(f"- Recorded SHA-256: `{item['recorded_sha256']}`")
        lines.append(f"- Retrieved SHA-256: `{item['archive_sha256']}`")
        lines.append(
            f"- Normalized upstream rule-map SHA-256: "
            f"`{item['upstream_rules_sha256']}`"
        )
        differences = item["differences"]
        if not any(differences.values()):
            lines.extend(["", "No ASR rule-map changes detected."])
            continue
        names = item["known_names"]
        if differences["added"]:
            lines.extend(["", "### Added", ""])
            for rule in differences["added"]:
                name = names.get(rule["id"], "name requires Microsoft reference review")
                lines.append(
                    f"- `{rule['id']}` — {action_label(rule['action'])}; {name}"
                )
        if differences["removed"]:
            lines.extend(["", "### Removed", ""])
            for rule in differences["removed"]:
                name = names.get(rule["id"], "unknown rule")
                lines.append(
                    f"- `{rule['id']}` — {action_label(rule['action'])}; {name}"
                )
        if differences["changed"]:
            lines.extend(["", "### Action changes", ""])
            for rule in differences["changed"]:
                name = names.get(rule["id"], "unknown rule")
                lines.append(
                    f"- `{rule['id']}` — {action_label(rule['from'])} → "
                    f"{action_label(rule['to'])}; {name}"
                )

    inventory = report.get("download_inventory", [])
    if inventory:
        tracked = {item["source_file"] for item in report["comparisons"]}
        other_windows_baselines = sorted(
            item["name"]
            for item in inventory
            if "Windows" in item["name"]
            and "Security Baseline" in item["name"]
            and item["name"] not in tracked
        )
        lines.extend(["", "## Other Windows baselines currently offered", ""])
        if other_windows_baselines:
            lines.extend(f"- `{name}`" for name in other_windows_baselines)
        else:
            lines.append("None.")
        lines.extend(
            [
                "",
                "Review this inventory for a newly supported Windows release. Existing older "
                "baselines do not require catalog entries unless the role expands its scope.",
            ]
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    try:
        report = build_report(args)
    except (CatalogRefreshError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    markdown = render_markdown(report)
    if args.markdown_report:
        args.markdown_report.write_text(markdown, encoding="utf-8")
    else:
        print(markdown, end="")
    if args.json_report:
        args.json_report.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )

    changed = any(item["status"] != "current" for item in report["comparisons"])
    return 2 if changed else 0


if __name__ == "__main__":
    raise SystemExit(main())
