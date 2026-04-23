# Resilient VPN Client

This repository is the first working foundation for an open-source VPN client aimed at high resilience, security, and maintainability under unstable and adversarial network conditions.

Current scope:

- signed configuration manifests with local verification;
- transport abstraction for multiple delivery profiles;
- session orchestration with failover and known-good tracking;
- local network policy layer with kill switch semantics;
- persistent local state for endpoint health and incident flags;
- data-plane backend abstraction with Linux-first userspace backend;
- privacy-safe telemetry and support bundle export;
- probe engine with coarse network error classification;
- CLI demo for local testing;
- unit tests covering trust and orchestration behavior.

This is not a production VPN yet. It is the control-plane and orchestration skeleton that a production-grade client can grow on top of.

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

2. Run the CLI demo:

```bash
PYTHONPATH=src python -m vpn_client.cli \
  --manifest examples/demo_manifest.json \
  --public-key examples/demo_public_key.pem \
  --support-bundle output/demo-support-bundle.json
```

3. Run tests:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

Linux-first network planning stays in dry-run mode by default and prints the command plan it would apply.
The userspace data-plane backend also stays in dry-run mode by default and prints the command it would launch.

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
