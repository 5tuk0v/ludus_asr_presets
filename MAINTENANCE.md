# Preset Maintenance

ASR presets are maintained from Microsoft primary sources. AI assistance may
help retrieve, extract, and compare baseline data, but it does not replace
maintainer review of the source package, resulting diff, and runtime evidence.

## Agent quick start

The deployed role never downloads rules. `vars/main.yml` is the versioned source
of truth. A refresh is a separate, report-first repository maintenance task.

When asked to check or refresh the presets, an agent must:

1. Read this file completely.
2. Use only the Microsoft sources listed below.
3. Download source packages to a temporary directory outside the repository.
4. Run the report-only checker before editing the catalog.
5. Review every package, GUID, action, and rule-name change.
6. Use the updater only after the report has authoritative supporting evidence.
7. Run the offline checks and report the remaining runtime validation separately.
8. Leave committing, tagging, publishing, and dependency upgrades to an explicit
   maintainer request.

Example full archive check:

```bash
python3 scripts/check_upstream.py \
  --archives-dir /tmp/asr-baselines \
  --download \
  --all \
  --json-report /tmp/asr-upstream.json \
  --markdown-report /tmp/asr-upstream.md
```

With `--download`, the checker reads Microsoft's structured Download Center
inventory, accepts packages only from `https://download.microsoft.com`, and
downloads the exact `source_file` names recorded in `vars/main.yml`. Omit the
flag to inspect packages already present in the directory. Exit status `0` means
every supplied package and rule map matches. Exit status `2` means the report
contains a package or rule-map change; it is a review result, not a script
failure. Exit status `1` means the evidence could not be processed safely.

To preview a catalog update from a reviewed report:

```bash
python3 scripts/update_catalog.py /tmp/asr-upstream.json
```

The updater prints a diff and does not write by default. If Microsoft introduced
a GUID not already named anywhere in the catalog, create a temporary JSON object
mapping that GUID to the exact name in the ASR rules reference, then use
`--rule-names /tmp/asr-rule-names.json`. Apply the reviewed result with `--write`.

Both tools use the `.PolicyRules` evidence included in Microsoft's baseline ZIPs.
They do not execute package contents or require Windows. The updater refuses
source actions outside this role's Block/Audit contract instead of guessing.

## Review cadence

Check for upstream changes:

- before each role release;
- when Microsoft publishes or revises a supported Windows security baseline;
- when Microsoft adds, removes, renames, or changes the supported actions of an
  ASR rule; and
- at least quarterly while the role is actively maintained.

Use the Microsoft Security Compliance Toolkit for OS-baseline presets and the
Microsoft ASR rules reference for the `microsoft_basic` preset and rule metadata.
Do not treat search results, third-party lists, or an AI-generated rule list as
authoritative input.

## Update procedure

1. Inventory the Windows baseline packages currently offered by Microsoft.
   Record any new Windows release that does not have a catalog preset. The
   Download Center page date covers the entire collection and does not prove an
   individual package changed.
2. Use `scripts/check_upstream.py --download` to inventory and download every
   applicable baseline package directly from Microsoft into a temporary
   directory. The generated report records the exact filenames and retrieval
   date. Use predownloaded archives only when network retrieval is unavailable.
3. Run `scripts/check_upstream.py`. It calculates each archive SHA-256, extracts
   configured ASR GUIDs/actions from `.PolicyRules`, calculates a normalized
   rule-map SHA-256, and compares the evidence with `vars/main.yml`.
4. Review additions, removals, and action changes individually against
   Microsoft's ASR rules reference. Preserve Microsoft's numeric action
   semantics: `1` is Block and `2` is Audit. Stop for maintainer review if the
   source contains Disabled, Not configured, Warn, an unknown action, conflicting
   entries, or lacks `.PolicyRules` evidence.
5. Review the `microsoft_basic` standard-protection list directly against the ASR
   rules reference because it does not come from a baseline ZIP.
6. For a revision of the same named Microsoft baseline, update that preset's
   source metadata and contents. For a new Windows or baseline generation, add
   a new preset instead of silently changing an older generation's semantics.
7. Use `scripts/update_catalog.py` for an existing archive-backed preset. Add a
   genuinely new preset manually with its exact Microsoft source metadata.
8. Update `ludus_asr_presets_catalog_version`, `tests/validate_presets.py`, and
   `CHANGELOG.md`. Preserve the old preset unless Microsoft withdrew it or the
   role explicitly announces a breaking removal.
9. Review the complete diff and confirm that every checked-in GUID, action,
   source version, URL, and package hash is supported by the retained evidence.

Do not commit downloaded baseline archives to this repository. The source name,
version, URL, and digest in `vars/main.yml` are the reproducibility record.

## Validation

Run the offline catalog check:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/validate_presets.py
```

When Ansible tooling is available, also run the syntax test:

```bash
ansible-playbook --syntax-check tests/syntax.yml
```

Then test the affected preset on a disposable Windows host applicable to that
baseline:

1. Apply `source` and verify every effective GUID/action.
2. Reapply `source` and require an unchanged result.
3. Transition to `audit`, reapply it unchanged, and verify effective state.
4. Transition to `block`, reapply it unchanged, and verify effective state.
5. Apply `native`, verify only role-owned entries are removed, and reapply it
   unchanged.
6. Confirm an unsupported preset or mode fails validation before mutation.

Record the tested OS build, Defender platform version, role version, transition
results, and any rule whose supported actions differ from the general contract.

## Release

- Bump the role version according to the compatibility impact.
- Describe preset additions, removals, and source-action changes in the
  changelog.
- Publish the role only after the offline checks and disposable-host matrix
  pass.
- Update dependent Sources to the new pinned role version separately; do not
  silently replace a dependency during unrelated Source work.
