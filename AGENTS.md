# Repository instructions

## Preset maintenance

When asked to check, refresh, or update ASR presets, read and follow
`MAINTENANCE.md` before changing the catalog. Use the report-only checker first.
Do not infer upstream changes from the Microsoft Download Center page date, and
do not edit rule GUIDs or actions without evidence extracted from an official
Microsoft baseline package.

Keep downloaded packages and generated reports outside the repository. Do not
publish, tag, or import a role release unless the user explicitly requests it.

## Validation

After catalog or maintenance-tool changes, run:

```bash
python3 -m unittest discover -s tests -p 'test_*.py'
python3 tests/validate_presets.py
ANSIBLE_ROLES_PATH="$(dirname "$PWD")" ansible-playbook --syntax-check tests/syntax.yml
git diff --check
```
