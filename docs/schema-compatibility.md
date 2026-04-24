# Schema Compatibility Policy

## Purpose

This document defines how manifest and provider-profile schema evolution works in this repository.
It exists to keep provider operations predictable and to prevent silent drift between generated profiles, signed manifests, and client-side validation.

## Current Supported Versions

- `schema_version = 1` for signed manifest documents;
- `provider_profile_schema_version = 1` for provider-profile manifests;
- provider-profile endpoints compiled by the repository compiler also carry `metadata.provider_profile_schema_version = 1`.

## Compatibility Rules

### Manifest Schema

- The loader accepts missing `schema_version` and treats it as version `1` for backward compatibility with older repository examples.
- The loader rejects any explicit manifest `schema_version` other than `1`.
- New manifest-level compatibility logic must be introduced deliberately before version `2` is emitted anywhere.

### Provider Profile Schema

- `provider_profile_schema_version` is only valid when `features.profile_kind = "provider-profile"`.
- The loader accepts a missing top-level `provider_profile_schema_version` and treats it as version `1` for backward compatibility.
- The loader rejects any explicit `provider_profile_schema_version` other than `1`.
- Provider-profile endpoints must either omit `metadata.provider_profile_schema_version` or match the top-level provider-profile schema version exactly.

### Provider Compiler Contract

- The repository compiler currently emits `provider_profile_schema_version = 1`.
- Each compiled endpoint is stamped with matching `metadata.provider_profile_schema_version = 1`.
- A logical server payload must not declare a provider-profile schema version that differs from the manifest schema version being built.

## Migration Policy

When a future schema version is introduced:

1. Add the new schema constants and compatibility checks in code.
2. Define whether the change is additive, restrictive, or incompatible.
3. Update the provider compiler to emit the new version explicitly.
4. Add migration tests for old-to-new and new-to-old handling.
5. Update repository examples only after loader and compiler behavior are both in place.

## Non-Goals

- Silent best-effort parsing of unknown future schema versions.
- Implicit provider-profile schema upgrades at load time.
- Mixing multiple provider-profile schema versions inside one generated provider-profile manifest.
