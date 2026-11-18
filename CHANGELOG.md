# Changelog

## Unreleased

## 0.2.1 — 2026-11-19

### Changed
- Renamed from `passport-github` to `@passport/github` (gtr ADR-0012): `gtr add @passport/github`, `import "passport/github"`; published to the gtr registry. Dependencies on other passport packages are registry ranges (`^0.2`) instead of `github:` sources.

## 0.1.1 — 2026-11-09

### Changed
- Requires `passport ^0.2` (the first published release of the core; `^0.1` matched no tag).

### Added
- The `passport-github` package.
