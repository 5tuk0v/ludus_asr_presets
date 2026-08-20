# Ansible Role: ludus_asr_presets ([Ludus](https://ludus.cloud))

Configure versioned Microsoft Defender Attack Surface Reduction (ASR) presets
on Windows hosts in a Ludus range.

> [!WARNING]
> Use one management authority per ASR rule GUID. Do not combine this role with
> Intune, Defender security settings management, Configuration Manager, another
> GPO, or another role that manages the same rules.

## Requirements

- Windows with Microsoft Defender Antivirus and `Get-MpPreference` available.
- Ansible 2.15 or later and the `ansible.windows` collection.
- A disposable target while validating new presets or modes.

## Role Variables

Available variables are listed below, along with their default values (see
`defaults/main.yml`):

```yaml
ludus_asr_presets_preset: microsoft_basic
ludus_asr_presets_mode: audit
```

Supported presets are `microsoft_basic`, `windows_server_2022`,
`windows_server_2025`, `windows_11_24h2`, and `windows_11_25h2`. Exact rule
GUIDs, source actions, versions, and source-package hashes are in
`vars/main.yml`.

Supported modes:

- `audit` — set every selected rule to Audit (default).
- `block` — set every selected rule to Block.
- `source` — apply each rule's action from the selected Microsoft baseline
  (usually Block; some rules may be set to Audit).
- `native` — remove ASR policy entries previously applied by this role, returning
  those rules to their unmanaged Defender behavior. ASR rules this role never
  managed are left unchanged.

`warn` is not supported because some included ASR rules do not support it.

## Dependencies

None.

## Example Ludus Range Config

```yaml
ludus:
  - vm_name: "{{ range_id }}-wks01"
    hostname: WKS01
    template: win11-24h2-x64-enterprise-tpm-template
    vlan: 10
    ip_last_octet: 30
    ram_gb: 4
    cpus: 2
    windows:
      sysprep: true
    roles:
      - 5tuk0v.ludus_asr_presets
    role_vars:
      ludus_asr_presets_preset: windows_11_24h2
      ludus_asr_presets_mode: audit
```

## Sources

- [Microsoft ASR rules reference](https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Security Compliance Toolkit](https://www.microsoft.com/download/details.aspx?id=55319)
- [Ludus Ansible role template](https://github.com/badsectorlabs/ludus_ansible_role_template)

See [Preset maintenance](MAINTENANCE.md) for the upstream review cadence,
baseline update procedure, validation matrix, and release checklist.

## Credits

This role builds upon [ZephrFish's Ludus Defender Lab](https://github.com/ZephrFish/ludus-defender-lab)
and [curi0usJack's Ludus MDE/MDI Roles](https://github.com/curi0usJack/Ludus-MDE-MDI-Roles),
adding versioned ASR presets, additional rulesets and modes, explicit policy
ownership tracking, and validation coverage.

## AI disclosure

This role was developed with assistance from OpenAI Codex using the Terra model.
AI-assisted changes were reviewed and tested by the maintainer.

## License

MIT

## Author Information

This role was created by [5tuk0v](https://github.com/5tuk0v) for
[Ludus](https://ludus.cloud).
