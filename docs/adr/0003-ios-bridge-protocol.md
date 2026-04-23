# ADR-0003: iOS Bridge App To Extension Protocol

## Status

Accepted

## Context

The repository now has an `ios-bridge` backend, but a raw config file is not enough for a maintainable Apple integration. The app side and the future `Network Extension` side need a stable, versioned exchange format so they can evolve without depending on internal Python structures or raw manifest fields.

## Decision

We define a versioned iOS bridge protocol with two JSON artifacts:

- a `request` payload written by the app/backend side;
- a `status` payload reserved for the future extension side.

The request contains:

- `schema_version`
- `request_kind`
- `session_id`
- normalized transport/auth `config`
- `dns` policy block
- `routing` policy block
- `telemetry` policy block

The status contains:

- `schema_version`
- `session_id`
- lifecycle `state`
- human-readable `detail`
- `network_ready`
- `tunnel_file_descriptor_ready`
- optional `last_error`

Initial and expected lifecycle states:

- `awaiting_extension`
- `extension_acknowledged`
- `network_ready`
- `tunnel_fd_ready`
- `running`
- `stop_requested`
- `stopped`
- `failed`

## Consequences

Positive:

- the iOS path now has a stable boundary between app code and extension code;
- the protocol can be tested without needing a live Apple runtime;
- routing, DNS, and telemetry policy can evolve explicitly instead of leaking through ad hoc fields.

Tradeoffs:

- protocol versioning now becomes part of release compatibility;
- the eventual Apple runtime must respect this schema instead of inventing a new private format.

## Implementation Notes

The app currently writes both files in dry-run form:

- `*.json` for the request payload;
- `*.status.json` for the initial waiting state.

The extension runtime is still not implemented, but the repository now includes status-transition helpers so the expected handshake is already explicit on the app side.
