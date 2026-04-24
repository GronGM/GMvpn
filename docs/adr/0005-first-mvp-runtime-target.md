# ADR-0005: First Honest MVP Runtime Target

## Status

Accepted

## Context

The repository has grown into a strong shared control-plane foundation, but the runtime surface is still uneven:

- Linux has the most concrete network adapter and lifecycle behavior.
- `xray-core` is the chosen engine direction for desktop-class and Android-style runtimes.
- `windows`, `macos`, and `android` still use placeholder-level platform adapters in this repository.
- `ios` remains a bridge-only track until a real Apple runtime exists.

Without an explicit first MVP target, release language will outrun implementation reality.

## Decision

We define the first honest MVP runtime target as:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

This contour becomes the first release-track runtime for hardening, diagnostics, and support expectations.

## Consequences

Positive:

- release claims can stay concrete and honest;
- support bundles and operator playbooks can anchor on one runtime contour first;
- later Windows, macOS, and Android work can converge on the same Xray-oriented product model without pretending parity already exists.

Tradeoffs:

- `linux-userspace` remains valuable for reference and debugging but is not the primary MVP release contour;
- other platform paths must be documented as planned or bridge-only until their runtime contracts mature;
- the CLI and support surface now need to expose support tier explicitly so operators can tell whether a run is inside or outside MVP scope.
