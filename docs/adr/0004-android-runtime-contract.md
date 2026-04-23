# ADR-0004: Android VpnService Runtime Contract

## Status

Accepted

## Context

The Android path uses `xray-core` as its transport engine direction, but the engine alone is not the runtime contract. Android also needs a stable lifecycle boundary around `VpnService`, permission flow, route ownership, and behavior under battery and network-change constraints.

## Decision

We define an Android runtime contract alongside the existing iOS bridge protocol.

The Android request payload includes:

- `schema_version`
- `request_kind`
- `session_id`
- `config` for `VpnService` behavior and backend ownership
- `remote` endpoint selection
- `routes`
- `dns`
- `lifecycle`

The initial lifecycle state begins at `permission_required`, and the expected progression is:

- `permission_required`
- `service_bound`
- `vpn_established`
- `backend_started`
- `running`
- `stop_requested`
- `stopped`
- `failed`

## Consequences

Positive:

- Android now has an explicit lifecycle model instead of being implied by the Xray process model;
- provider manifests can carry Android-specific runtime hints in a validated way;
- the future Android adapter can implement a stable contract without reinterpreting raw endpoint metadata ad hoc.

Tradeoffs:

- another runtime contract must now be versioned;
- Android-specific policy hints need discipline so they do not become an unbounded metadata dump.
