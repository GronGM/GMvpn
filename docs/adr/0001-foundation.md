# ADR-0001: Foundation Architecture

## Status

Accepted

## Context

The client has to survive protocol blocking, endpoint loss, unstable mobile internet, and operational mistakes in the control plane. A single transport and a thin GUI wrapper would create too much fragility.

## Decision

We start with a modular client core:

- signed manifests for endpoint and policy distribution;
- session orchestrator as a state machine;
- transport abstraction with pluggable profiles;
- policy engine and post-connect network layer;
- data-plane backend interface separated from control plane;
- separate probe engine for network classification;
- persistent local state for endpoint reputation and incident flags;
- local cache for last-known-good manifests.

## Consequences

Positive:

- safer remote operations because config trust is local;
- lower coupling between UI, transport, and policy;
- clearer incident response and transport rollback path.

Tradeoffs:

- more code and testing surface from day one;
- transport capability matrix must be maintained carefully;
- platform networking work still remains ahead.
