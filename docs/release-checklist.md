# MVP Release Checklist

## Purpose

This checklist defines the minimum release gate for the first honest MVP contour:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

It is intentionally narrower than a full cross-platform product release.

## Release Scope Check

- Confirm the release notes describe the product as a Linux-first MVP contour, not a full cross-platform client.
- Confirm `windows`, `macos`, and `android` are still described as planned or partial runtime tracks.
- Confirm `ios` is still described as bridge-only and not production-ready.
- Confirm the release does not claim full native platform parity, app-store readiness, or completed Apple runtime support.

## Change Gate

- Confirm the release branch includes the latest merged baseline from `main`.
- Confirm PR `#7` or its merged equivalent is present in the release branch.
- Confirm no unrelated experimental changes are bundled into the release candidate.
- Confirm `.cache/` runtime artefacts are not included in the release diff.

## CI And Local Verification

- Confirm GitHub Actions `CI` is green for the release candidate.
- Run `python -m compileall src tests`.
- Run `PYTHONPATH=src python -m unittest discover -s tests -v`.
- Confirm the runtime support assessment still marks `linux + xray-core + linux adapter` as `mvp-supported`.

## Manifest And Config Contract

- Confirm manifest verification still requires valid signatures.
- Confirm `schema_version` and `provider_profile_schema_version` handling matches [schema-compatibility.md](./schema-compatibility.md).
- Confirm `features.session_health_policy` validation still accepts only bounded values.
- Confirm provider-profile compilation and endpoint targeting still validate correctly.
- Confirm no release change widens provider contract behavior without corresponding compatibility notes.

## Runtime Behavior

- Confirm startup recovery still records stale runtime cleanup in support output.
- Confirm repeated failure handling still produces bounded cooldown and retry behavior.
- Confirm reason-aware health monitoring still exports `failure_class` and `reason_code` surfaces.
- Confirm the Linux runtime contour still renders the expected Xray config and platform command plan.
- Confirm incident summary generation still runs for degraded or failed sessions.

## Support Bundle Contract

- Confirm the support bundle still exports at least:
  - `incident_summary`
  - `startup_recovery`
  - `transport_recovery`
  - `endpoint_health`
  - `dataplane_runtime`
  - `runtime_support`
  - `session_health_policy_resolved`
  - `transport_reenable_policy_resolved`
  - `transport_failure_policy_resolved`
- Confirm `runtime_support.tier` and `runtime_support.in_mvp_scope` are present.
- Confirm `endpoint_health[*].last_reason_code` and transport soft-failure buckets are present.
- Confirm background re-enable policy values are bounded and visible for the transports you expect to support.
- Confirm crash and soft-failure disable policy values are bounded and visible for the transports you expect to support.
- Confirm `incident_summary.primary_transport_issue` is populated for degraded scenarios where one transport is the obvious local focus.
- Confirm bundle output remains bounded and does not dump unreviewed sensitive material.

## Operator-Facing Sanity Check

- Run one clean happy-path CLI session for the Linux Xray contour.
- Run one degraded-path CLI scenario and verify the incident summary is readable.
- Export one support bundle and inspect it manually.
- Confirm the recommended action in the incident summary is still useful to an operator.

## Rollback Readiness

- Confirm the release can be rolled back to the previous known-good version of the repository and manifest/compiler contract.
- Confirm no incompatible manifest or provider-profile version bump is included without an explicit migration plan.
- Confirm the previous release baseline remains tagged or otherwise easy to restore.
- Confirm release notes mention any operator action required after rollback.

## Release Notes Gate

- State the exact MVP contour supported by this release.
- State known non-goals and unsupported runtime paths.
- Call out any changes to support bundle structure or incident diagnostics.
- Call out any manifest/schema compatibility considerations.
- Include the local verification commands that were run.

## Do Not Release If

- CI is red or missing for the release candidate.
- Full unit suite is not green locally.
- The Linux Xray contour no longer assesses as `mvp-supported`.
- The release notes imply production readiness for placeholder or bridge-only paths.
- The support bundle no longer explains degraded and failed sessions clearly enough for operator triage.
