# Resilient VPN Client

This repository is a Linux-first reference implementation for a resilient VPN runtime and control-plane layer built for unstable, degraded, and operationally hostile network conditions.

What exists today:

- signed manifests with local signature verification;
- explicit manifest and provider-profile schema versions;
- shared session orchestration with failover, cooldowns, and known-good reuse;
- provider-profile compilation and strict platform capability validation;
- Linux platform command planning with startup reconciliation diagnostics;
- `xray-core` config rendering and backend lifecycle management;
- privacy-safe support bundle export and incident-oriented diagnostics;
- CLI workflows for local dry-run and recovery testing;
- unit tests plus a compact release guardrail for release-facing checks.

Compatibility rules are documented in [docs/schema-compatibility.md](/workspace/docs/schema-compatibility.md).
Project framing and audience are described in [docs/product-positioning.md](/workspace/docs/product-positioning.md).
Operational docs live in [docs/release-checklist.md](/workspace/docs/release-checklist.md), [docs/incident-playbook.md](/workspace/docs/incident-playbook.md), and [docs/roadmap.md](/workspace/docs/roadmap.md).

This is still not a production-ready cross-platform VPN client. The repository is best read as:

- a Linux-first reference client for one honest `xray-core` runtime contour;
- a control-plane and runtime-orchestration foundation;
- a provider-facing contract, diagnostics, and policy layer;
- not a finished consumer VPN product.

## What This Project Is For

The most realistic use cases for the repository today are:

- building and testing signed provider manifests and provider-profile compilation flows;
- validating runtime policy, diagnostics, and support-bundle contracts around `xray-core`;
- running a Linux-first reference contour for release and incident work;
- using the codebase as a reference implementation for orchestration, failure handling, and operator-facing diagnostics.

If your goal is "an end-user VPN app that competes with Hiddify, NekoBox, v2rayN, or sing-box frontends", this repository is not there today and should not be evaluated on that basis.

## Honest MVP Target

The first honest MVP runtime target is now explicit:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

This is the contour we treat as the first release-track runtime for hardening and support.

Everything else should be read more conservatively:

- `linux-userspace` remains a useful reference and debugging path, but it is not the release-track contour;
- `windows`, `macos`, and `android` follow the same product model but still depend on placeholder-level platform adapters in this repository today;
- `ios` remains bridge-only until a real Apple `Network Extension` runtime exists;
- the support bundle and release checklist are intentionally anchored on the Linux Xray contour first.

## Current Repository Status

The current repository state is intentionally conservative:

- the default CLI stays in dry-run-friendly mode and does not apply Linux network changes unless `--apply-network-changes` is set;
- the CLI default dataplane is still `routed` for local testing, so the release-track contour should be selected explicitly when you want to exercise the MVP path;
- runtime support assessment is explicit, and only `linux + xray-core + linux adapter` is currently assessed as `mvp-supported`;
- Xray-backed runs in real mode fail fast if the binary is missing or the rendered config does not pass Xray preflight validation.

## Strategic Direction

The strongest path for this repository is not "become another mass-market VPN client UI".

The stronger path is:

- keep one releaseable Linux reference contour honest and observable;
- harden provider manifests, compiler outputs, runtime policy, and diagnostics;
- make the repository useful as a control-plane/orchestration layer around `xray-core`;
- treat other platforms as explicit runtime contracts until they have real implementations.

## Repository Layout

- `src/vpn_client/` - application core
- `tests/` - unit tests
- `tools/` - development helpers
- `docs/adr/` - architectural decisions

## Quick Start

1. Create demo assets:

```bash
python tools/generate_demo_assets.py
```

2. Run the Linux MVP contour in dry-run mode:

```bash
PYTHONPATH=src python -m vpn_client.cli \
  --manifest examples/demo_manifest.json \
  --public-key examples/demo_public_key.pem \
  --platform linux \
  --client-platform linux \
  --dataplane xray-core \
  --support-bundle output/demo-support-bundle.json
```

This keeps Linux command planning in dry-run mode while still rendering the release-track Xray runtime path and exporting a support bundle.

3. Run tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

4. Run the compact release guardrail:

```bash
python tools/release_guardrail.py
```

Pull requests and pushes to `main` are now expected to keep the CI test workflow green.
The baseline automated gate runs:

- `python -m compileall src tests`
- `PYTHONPATH=src python -m unittest discover -s tests -v`
- `python tools/release_guardrail.py --allow-dirty-tree --run-local-checks` in the `release-contract` job

Before cutting or reviewing a release candidate, you can also run the compact repo guardrail:

- `python tools/release_guardrail.py`
- `python tools/release_guardrail.py --allow-dirty-tree`
- `python tools/release_guardrail.py --run-local-checks`

Linux-first network planning stays in dry-run mode by default and prints the command plan it would apply.
The data-plane backends also stay in dry-run mode by default and print the command they would launch.
When you leave dry-run for `xray-core`, the client checks that the Xray binary exists and validates the rendered config before attempting startup.

## Xray Direction

The repository now treats `xray-core` as the release-track dataplane for the first Linux MVP contour and as the long-term engine direction for other runtime contracts, while keeping the product config model independent from raw Xray JSON.

- `xray-core` is wired in as a concrete `DataPlaneBackend`;
- endpoint metadata can now carry Xray-specific rendering fields such as protocol, stream, and TLS or Reality settings;
- route, DNS, and kill-switch enforcement stay in the platform layer instead of being hardcoded into the Xray renderer;
- `iOS` remains a separate runtime track and is not modeled as “the same Xray process on another platform”.

See [docs/adr/0002-xray-runtime-architecture.md](/workspace/docs/adr/0002-xray-runtime-architecture.md) for the platform split and rationale.

## Xray Metadata Example

An endpoint can provide the minimum Xray renderer inputs through `metadata`:

```json
{
  "id": "ru-spb-vless-reality-1",
  "host": "edge.example.net",
  "port": 443,
  "transport": "https",
  "region": "ru-spb",
  "metadata": {
    "xray_protocol": "vless",
    "xray_user_id": "11111111-1111-1111-1111-111111111111",
    "xray_stream_network": "tcp",
    "xray_security": "reality",
    "xray_server_name": "cdn.example.net",
    "xray_fingerprint": "chrome",
    "xray_reality_public_key": "PUBLIC_KEY_HERE",
    "xray_reality_short_id": "0123456789abcdef"
  }
}
```

The CLI still defaults to `--dataplane routed` in dry-run mode for local safety, so use `--dataplane xray-core` when you want to exercise the MVP path directly.

Endpoints that declare `metadata.dataplane = "xray-core"` are now validated during manifest load, so broken Xray profiles fail early instead of surfacing later as opaque runtime connect errors.
Endpoints without an explicit dataplane declaration stay on the default `linux-userspace` backend, which lets one manifest safely mix native-style and Xray-backed profiles.

## Platform Runtime Matrix

The CLI now separates the local test network stack from the target client runtime:

- `--platform` chooses the prototype network-stack implementation used in this repo today;
- `--client-platform` describes the product target we are modeling: `linux`, `windows`, `macos`, `android`, `ios`, or `simulated`.

Current backend policy:

- CLI defaults stay conservative for local runs: `--dataplane routed` unless you choose another backend explicitly;
- `windows`, `macos`, and `android` default to `xray-core` when modeled as target client platforms;
- `ios` defaults to `ios-bridge`, which currently renders a tunnel contract but still stops before a real Apple runtime starts.

This keeps the architecture honest: `iOS` is now a separate contract path in the codebase, but still remains a separate engineering track until a dedicated bridge/runtime exists.

The CLI now also classifies the selected runtime contour into a support tier and exports that assessment in the support bundle.
For the current repository state, only the explicit `linux + xray-core + linux adapter` contour is considered `mvp-supported`.

## Platform Adapters

The network layer is no longer modeled as only `linux` plus a generic fallback. The repository now has a platform adapter factory:

- `linux` uses the real command-planning adapter with startup reconciliation support;
- `windows`, `macos`, `android`, and `ios` use explicit placeholder adapters today;
- control-plane code now depends on a shared platform adapter contract instead of hard-coding Linux classes in most places.

## Platform Capabilities

Signed manifests can now declare `platform_capabilities`, which makes the product support matrix explicit inside the configuration itself:

- supported dataplanes per platform;
- selected network adapter family;
- whether startup reconciliation is expected;
- rollout status and short operator notes.

This gives providers and client code one shared source of truth for what each platform is supposed to do.

Desktop-oriented endpoint variants can now also carry a structured `desktop_policy` block with platform-specific ranking hints.

## Provider Profile Example

The repository now includes a provider-style example manifest at [examples/provider_profile_manifest.json](/workspace/examples/provider_profile_manifest.json).

It shows one logical server, `spb-main`, exposed through two runtime paths:

- `spb-main-desktop` for desktop and Android through `xray-core`;
- `spb-main-ios` for iOS through `ios-bridge`.

Those endpoints now also declare `supported_client_platforms`, and the client uses `--client-platform` to prefer the matching path automatically during scheduling.

The provider example is now generated from one logical server definition through a small compiler helper instead of being hand-expanded endpoint by endpoint.
That compiler now also validates its generated variants so duplicate ids or missing logical-server metadata fail fast.

## Android Runtime Contract

The Android side now also has an explicit runtime contract around `VpnService`, documented in [docs/adr/0004-android-runtime-contract.md](/workspace/docs/adr/0004-android-runtime-contract.md).

The provider profile example carries Android-specific runtime hints such as:

- `android_policy.session_name`
- `android_policy.protect_socket_api`
- `android_policy.meter_handling`
- `android_policy.on_boot_reconnect`
- `android_policy.respect_doze`
- `android_policy.reassert_on_network_change`
- `android_policy.rank_priority`
- `desktop_policy.platform_rank_priority`

## iOS Bridge Contract

The prototype now includes an `ios-bridge` backend that renders a Packet Tunnel style contract for future Apple integration.

- it accepts only `ios-bridge` endpoints with explicit auth and transport metadata;
- it translates the shared endpoint model into a versioned app-to-extension request payload plus initial status file;
- it still returns a controlled failure after rendering because the actual `Network Extension` runtime is not implemented yet.

See [docs/adr/0003-ios-bridge-protocol.md](/workspace/docs/adr/0003-ios-bridge-protocol.md) for the exchange format.

## Stale Runtime Demo

To reproduce startup recovery after an abnormal previous exit in one command:

```bash
PYTHONPATH=src python -m vpn_client.cli \
  --manifest examples/demo_manifest.json \
  --public-key examples/demo_public_key.pem \
  --platform simulated \
  --dataplane null \
  --simulate-stale-runtime-endpoint ru-spb-https-1 \
  --support-bundle output/demo-support-bundle-stale-runtime.json
```

This seeds a stale runtime marker for `ru-spb-https-1`, forces startup cleanup, and exports a support bundle that includes:

- `startup_recovery.cleanup_enabled`
- `startup_recovery.stale_marker_found`
- `startup_recovery.actions`
- `startup_recovery.simulated_endpoint_id`

## Session Health Policy

Signed manifests can now carry a bounded `features.session_health_policy` block for post-connect monitoring:

```json
{
  "session_health_policy": {
    "default": {
      "checks": 1,
      "auto_reconnect": false,
      "failure_threshold": 3
    },
    "by_client_platform": {
      "android": {
        "checks": 2
      }
    },
    "by_transport": {
      "https": {
        "auto_reconnect": true
      }
    }
  }
}
```

Rules:

- `default` sets the base behavior;
- `by_client_platform` overrides it for one client target such as `android` or `ios`;
- `by_transport` overrides it for one transport such as `https` or `wireguard`;
- `checks` must stay in the bounded range `0..10`;
- `auto_reconnect` is a boolean;
- `failure_threshold` must stay in the bounded range `1..5`.

CLI behavior is tri-state:

- if `--health-checks` is omitted, the client uses the resolved manifest value;
- if `--auto-reconnect-on-health-failure` or `--no-auto-reconnect-on-health-failure` is omitted, the client uses the resolved manifest value;
- if either flag is passed locally, that local value wins for the current run.

The CLI prints the resolved values as `session_health_checks`, `session_health_auto_reconnect`, and `session_health_failure_threshold`.

The manifest can also carry two small runtime contracts for release-facing maintenance semantics:

```json
{
  "features": {
    "runtime_support_policy": {
      "default": {
        "enforce_contract_match": true
      }
    },
    "runtime_tick_policy": {
      "default": {
        "reevaluate_pending_transports_limit": 1
      }
    }
  }
}
```

Rules:

- `runtime_support_policy.default.enforce_contract_match` is boolean;
- when it is `true`, a `contract-mismatch` runtime support assessment blocks startup unless the operator passes `--allow-runtime-contract-mismatch`;
- `runtime_tick_policy.default.reevaluate_pending_transports_limit` must stay in the bounded range `1..5`;
- `--reevaluate-pending-transports` remains a local one-shot override for the current run.

The manifest can also bound the background transport re-enable backoff:

```json
{
  "features": {
    "transport_reenable_policy": {
      "default": {
        "retry_delay_seconds": 120,
        "max_retry_delay_seconds": 1800
      },
      "by_transport": {
        "wireguard": {
          "retry_delay_seconds": 300,
          "max_retry_delay_seconds": 2400
        }
      }
    }
  }
}
```

Rules:

- `default` sets the base retry delay and cap for failed background re-enable probes;
- `by_transport` can override that policy for a specific transport;
- `retry_delay_seconds` must stay in the bounded range `60..900`;
- `max_retry_delay_seconds` must stay in the bounded range `120..3600`;
- `max_retry_delay_seconds` must not be lower than `retry_delay_seconds`.

The manifest can also bound local transport disable semantics for repeated crashes and soft failures:

```json
{
  "features": {
    "transport_failure_policy": {
      "default": {
        "crash_threshold": 1,
        "soft_fail_threshold": 3,
        "crash_disable_ttl_seconds": 900,
        "soft_fail_disable_ttl_seconds": 300
      },
      "by_transport": {
        "wireguard": {
          "soft_fail_threshold": 2,
          "soft_fail_disable_ttl_seconds": 600
        }
      }
    }
  }
}
```

Rules:

- `default` sets the base crash and soft-failure disable behavior;
- `by_transport` can override that behavior for a specific transport;
- `crash_threshold` and `soft_fail_threshold` must stay in the bounded range `1..5`;
- `crash_disable_ttl_seconds` must stay in the bounded range `60..3600`;
- `soft_fail_disable_ttl_seconds` must stay in the bounded range `60..1800`.

## Support Bundle Diagnostics

The support bundle now exports the effective monitoring policy and the persistent state used to reason about repeated soft failures:

- `session_health_checks`
- `session_health_auto_reconnect`
- `session_health_failure_threshold`
- `runtime_support_policy_resolved`
- `runtime_tick_policy_resolved`
- `session_health_policy_resolved`
- `transport_reenable_policy_resolved`
- `transport_failure_policy_resolved`
- `session_health_fail_streak`
- `session_health_fail_bucket`
- `transport_crash_buckets`
- `transport_soft_fail_streaks`
- `transport_soft_fail_buckets`
- `endpoint_health[*].last_failure_class`
- `endpoint_health[*].last_reason_code`

`transport_soft_fail_buckets` and `session_health_fail_bucket` use the format `failure_class:reason_code`.
That means the runtime does not keep one shared streak for unrelated symptoms. A repeated `network_down:dataplane_healthcheck_failed` pattern is treated separately from `network_down:dataplane_session_inactive`.

`transport_crash_buckets` keep the last crash reason-code bucket used for local transport disable decisions, so repeated crashes with different root symptoms do not silently accumulate as one shared streak.

## Reason Codes

Each runtime failure still carries the coarse `failure_class`, but it now also emits a machine-readable `reason_code` so support tooling can distinguish different symptoms inside the same class.

Typical examples:

- `dns_interference:dns_lookup_failed`
- `tls_interference:tls_handshake_failed`
- `udp_blocked:udp_filtered`
- `tcp_blocked:tcp_connect_failed`
- `network_down:route_programming_failed`
- `network_down:dataplane_healthcheck_failed`
- `network_down:dataplane_backend_crashed`
- `unknown:transport_not_registered`

Operationally, this means:

- a one-off soft health failure no longer degrades the session immediately when persistent state is available;
- transient recovery clears the pending monitoring streak and emits `session_health_recovered`;
- a dataplane crash still bypasses soft hysteresis and is escalated immediately.

## Local Guidance Overrides

You can apply unsigned local incident guidance overrides on top of the signed manifest by passing a JSON file:

```bash
PYTHONPATH=src python -m vpn_client.cli \
  --manifest examples/demo_manifest.json \
  --public-key examples/demo_public_key.pem \
  --incident-guidance-file local-incident-guidance.json
```

Example `local-incident-guidance.json`:

```json
{
  "tls_interference": {
    "severity": "critical",
    "recommended_action": "Use the provider emergency fallback profile before retrying."
  }
}
```

Local overrides take priority over `features.incident_guidance_overrides` from the signed manifest, but must match the same validation rules.

If `--incident-guidance-file` is not provided, the CLI will also auto-load `incident-guidance.json` from `--cache-dir` when that file exists.

## MVP Principles

- local verification before trust;
- last-known-good configuration cache;
- transport agility instead of single-protocol coupling;
- explicit state machine for connection lifecycle;
- policy-driven network layer after transport establishment;
- persistent scoring of endpoint health for better failover ordering;
- startup cleanup path for stale runtime markers after abnormal exits;
- privacy-first diagnostics with bounded metadata.
