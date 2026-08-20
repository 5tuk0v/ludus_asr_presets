# Preset Maintenance

ASR presets are maintained from Microsoft primary sources. AI assistance may
help retrieve, extract, and compare baseline data, but it does not replace
maintainer review of the source package, resulting diff, and runtime evidence.

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

1. Download the applicable baseline package directly from Microsoft.
2. Record its exact product/release name, retrieval date, and SHA-256 digest.
3. Extract the configured ASR rule GUIDs and actions from the baseline policy.
   Preserve Microsoft's numeric action semantics: `1` is Block and `2` is Audit.
4. Compare the extracted GUID/action map with the applicable entry in
   `vars/main.yml`. Review additions, removals, action changes, and renamed
   rules individually against Microsoft's ASR rules reference.
5. For a revision of the same named Microsoft baseline, update that preset's
   source metadata and contents. For a new Windows or baseline generation, add
   a new preset instead of silently changing an older generation's semantics.
6. Update `ludus_asr_presets_catalog_version`, `tests/validate_presets.py`, and
   `CHANGELOG.md`. Preserve the old preset unless Microsoft withdrew it or the
   role explicitly announces a breaking removal.
7. Review the complete diff and confirm that every checked-in GUID, action,
   source version, URL, and package hash is supported by the retained evidence.

Do not commit downloaded baseline archives to this repository. The source name,
version, URL, and digest in `vars/main.yml` are the reproducibility record.

## Validation

Run the offline catalog check:

```bash
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

