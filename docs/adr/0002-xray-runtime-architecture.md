# ADR-0002: Xray Runtime Architecture And Platform Split

## Status

Accepted

## Context

The current repository already has the right control-plane shape: signed manifests, endpoint scheduling, state persistence, startup recovery, and a data-plane backend abstraction.

The next architectural step is choosing how `xray-core` fits into this design without locking the project into a desktop-only model or making false assumptions about `iOS`.

## Decision

We adopt an `Xray-first, platform-adapted` architecture:

- `xray-core` is the default data-plane backend for `Windows`, `macOS`, and `Android`-class runtimes where a managed process model is realistic;
- the product configuration model remains product-owned and transport-agnostic, not raw Xray JSON;
- Xray JSON is compiled locally from endpoint metadata by a dedicated renderer layer;
- platform route, DNS, and kill-switch behavior remain outside the Xray renderer and stay in platform adapters;
- `iOS` is treated as a separate runtime track with a `Network Extension` bridge and an Xray-compatible config compiler, not as a promise of identical process embedding.

## Consequences

Positive:

- the existing `DataPlaneBackend` abstraction remains valid and now has a concrete Xray implementation path;
- desktop and Android can converge on one engine model with shared diagnostics and crash handling;
- iOS is kept honest from day one and does not inherit assumptions that will fail under Apple runtime restrictions.

Tradeoffs:

- endpoint metadata now needs a stricter capability contract for Xray-backed transports;
- the config compiler becomes a compatibility surface that must be versioned carefully;
- platform adapters still carry substantial work for `Windows`, `macOS`, `Android`, and especially `iOS`.

## Platform Direction

- `Windows`: Xray-backed data plane plus native route/DNS management.
- `macOS`: Xray-backed runtime with a platform-specific network integration layer.
- `Android`: Xray-backed runtime coordinated with the Android VPN service lifecycle.
- `iOS`: separate adapter/runtime path using Apple networking extension constraints and an Xray-compatible config translation layer.

## Implementation Notes

The repository now adds a dedicated `xray-core` backend and renderer as the first concrete implementation of this decision.
