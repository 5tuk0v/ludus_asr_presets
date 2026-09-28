# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

## [0.1.1] - 2026-09-28

- Add report-first tooling for comparing Microsoft baseline archives with the
  checked-in ASR catalog and preparing reviewed catalog updates.
- Add exact source filenames and an agent-oriented preset refresh runbook.
- Record the 2026-09-28 upstream review: all four baseline packages and the
  Microsoft standard protection rule set still match the checked-in rules.

## [0.1.0] - 2026-08-16

- Create the role from the Ludus Ansible role template.
- Add five versioned Microsoft-derived ASR presets.
- Add `source`, `audit`, `block`, and `native` modes.
- Add role-owned policy cleanup and effective-state validation.
