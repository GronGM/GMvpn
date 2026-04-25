# Product Positioning

## What This Repository Is

`GMvpn` is best understood today as a Linux-first reference client and control-plane foundation for resilient VPN runtimes built around `xray-core`.

It is strongest in three areas:

- signed provider-facing manifests and provider-profile compilation;
- runtime orchestration, policy resolution, and failure handling;
- operator-facing diagnostics, support bundles, and release guardrails.

## What This Repository Is Not

It is not yet:

- a polished end-user VPN application;
- a GUI-first consumer product;
- a production-ready cross-platform client with parity across Windows, macOS, Android, and iOS;
- a replacement for mature mass-market clients such as Hiddify, NekoBox, v2rayN, or similar tools.

## Recommended Reading Of The Project

The repository should currently be read as:

- one honest Linux release-track runtime contour: `client-platform=linux`, linux adapter, `dataplane=xray-core`;
- one provider/control-plane contract surface for manifests, runtime policies, and diagnostics;
- several future platform/runtime tracks that are still contracts, placeholders, or bridge-only paths.

That means the project is closer to a reference implementation or SDK-adjacent foundation than to a finished VPN app.

## Who It Is For

The most likely useful audience today is:

- engineers building or operating subscription-driven VPN services;
- teams that need signed profile delivery, provider-policy validation, and bounded support diagnostics;
- researchers or engineers exploring resilience under blocking, DPI, and degraded networks;
- Linux-first operators who want an inspectable reference contour around `xray-core`.

## Who It Is Not For

The least realistic audience today is:

- mainstream end users expecting desktop/mobile GUI parity;
- teams looking for an immediately brandable cross-platform retail VPN client;
- operators who need app-store-ready Apple and Android packaging out of the box.

## Strategic Focus

The best near-term path is:

1. Keep the Linux Xray contour releaseable, observable, and honest.
2. Strengthen provider-profile compilation, schema compatibility, and runtime-policy contracts.
3. Keep diagnostics and support bundles strong enough for real incident triage.
4. Treat non-Linux platforms as explicit runtime contracts until they have real implementations.

The weaker path would be trying to chase full consumer-client parity too early.

## Product Promise

The repository can reasonably promise:

- signed profile handling;
- explicit runtime support assessment;
- reproducible Linux/Xray reference behavior;
- bounded diagnostics and release checks;
- a clean separation between control-plane logic and dataplane execution.

It should not yet promise:

- broad consumer usability;
- broad packaging/distribution readiness;
- cross-platform feature parity;
- finished mobile and Apple runtimes.
