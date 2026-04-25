# Product Roadmap And Platform Target Matrix

## Purpose

This document turns the current repository from "a promising control-plane foundation" into a staged product plan.
The target outcome is a resilient VPN client family with one product model and multiple platform runtimes, not a pile of unrelated per-platform experiments.

The immediate goal is not full parity with mature commercial clients.
The immediate goal is to build a reliable shared core, ship one honest Linux-first MVP contour, and then widen platform coverage without breaking the operational model.

## Product Shape

The intended product shape is:

- one provider-facing configuration model;
- one shared orchestration core for config trust, endpoint selection, recovery, failover, incident reporting, and local state;
- multiple platform-specific runtime paths for Linux, Windows, macOS, Android, and later iOS;
- one support and release model across the product family.

This means the client can eventually feel like one product to providers and end users while still using different runtime adapters and data-plane backends under the hood.

## Current Positioning

The repository should currently be read as:

- a Linux-first reference client with one explicit release-track contour;
- a shared control plane and provider-facing contract layer that is ahead of most platform runtimes;
- a codebase that already takes release/support contracts seriously;
- not yet a production-ready cross-platform client.

For practical release and operator work, the only contour that should be described as supported today is:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

The intended strategic reading is therefore:

- near-term: Linux reference contour plus provider/control-plane hardening;
- mid-term: stronger SDK-like contract surface around manifests, policy, and diagnostics;
- not near-term: competing head-on as a GUI-first consumer VPN product.

## Guiding Principles

- build one reliable orchestration core before chasing broad platform parity;
- keep the provider contract stable and versioned before widening operational surface area;
- treat iOS as a separate engineering track with explicit constraints;
- prefer controlled degraded mode over false promises;
- make supportability, rollback, and incident visibility part of the product, not afterthoughts.

## Delivery Stages

### Stage 1: Core Runtime Hardening

Goal:
Make the existing orchestration and backend lifecycle predictable under normal failures.

Scope:

- stabilize connect, monitor, reconnect, degrade, and shutdown transitions;
- unify backend state, runtime markers, and incident summaries;
- tighten contracts between scheduler, policy, dataplane, and platform adapters;
- expand tests around crash loops, stale runtime cleanup, partial recovery, and health-failure handling.

Exit criteria:

- repeated failures lead to deterministic cooldown and retry behavior;
- startup cleanup is reproducible and visible in support bundles;
- support bundle output is sufficient to explain why the last session failed;
- the core test suite remains green on every change.

Key risk:
Trying to improve transport logic and platform specifics at the same time will blur failure ownership.

### Stage 2: Provider Profile And Manifest Stabilization

Goal:
Turn the configuration model into a controlled compatibility surface for providers and control-plane integrations.

Scope:

- version the manifest and provider profile schema explicitly;
- define compatibility rules and migration behavior for older manifests;
- validate platform capabilities, rollout flags, incident guidance, and backend-specific metadata more strictly;
- document safe emergency overrides and local guidance precedence.

Exit criteria:

- a provider can generate and validate profiles without hidden platform ambiguity;
- broken Xray, iOS bridge, or platform capability declarations fail early;
- schema evolution rules are documented before the next incompatible change.
- the manifest/compiler layer is useful on its own even outside the CLI reference client.

Key risk:
If schema changes stay informal, operational drift will outrun client reliability.

### Stage 3: Resilience Logic For Adversarial Networks

Goal:
Make the client behave well under blocking, degradation, and unstable links instead of only under happy-path connectivity.

Scope:

- improve failure classification around transport, TLS interference, runtime crash, and route/DNS failure;
- refine cooldown, retry budgets, and known-good preference rules;
- add policy for emergency fallback profiles and bounded local disable flags;
- tighten probe-driven reenable logic and recovery heuristics.

Exit criteria:

- the client can explain why it changed endpoint or transport;
- repeated failures do not create reconnect thrash;
- temporary fallback behavior is controlled, bounded, and observable.

Key risk:
Overly aggressive automation can hide real incidents or amplify unstable states.

### Stage 4: Platform Runtime Maturation

Goal:
Deepen the real runtime contracts for the first supported product platforms.

Scope:

- finish hardening the Linux-first command-planning and reconciliation path as the active MVP contour;
- harden Xray-backed runtime contracts for Windows, macOS, and Android;
- keep iOS on an explicit bridge track until a real Apple runtime exists;
- define per-platform capability gaps and degraded-mode behavior.

Exit criteria:

- desktop and Android paths share one honest Xray-oriented runtime contract;
- platform adapters expose enough state for recovery and incident analysis;
- iOS remains clearly marked as a separate track, not implied parity.

Key risk:
Pretending all platforms are equivalent will create brittle abstractions and release risk.

### Stage 5: Operational Readiness

Goal:
Make the Linux reference contour and provider-facing contracts releaseable and supportable, not just runnable.

Scope:

- finalize support bundle contract and bounded telemetry model;
- keep release readiness checklist, runtime support assessment, and incident playbooks aligned around the Linux Xray MVP contour;
- add compatibility and regression test matrix by platform class;
- document incident triage flow and post-release monitoring expectations.

Exit criteria:

- there is a repeatable release checklist;
- incident handling has a default playbook;
- regressions in config compatibility or runtime recovery are caught before release.

Key risk:
Without an operations contour, each release becomes manual firefighting.

### Stage 6: Product Surface Expansion

Goal:
Expand platform and user-facing functionality only after the Linux reference contour and control-plane contracts are dependable.

Scope:

- narrow the MVP-to-v1 gap per platform;
- add richer provider controls only where the operational model can support them;
- plan UI, packaging, and distribution against already-stable runtime contracts.

Exit criteria:

- product additions do not require rethinking core trust, recovery, or support flows;
- platform-specific feature work can be prioritized without reopening the architecture.

Key risk:
Shipping UX or packaging too early can conceal unfinished control-plane risk.

## Positioning Constraint

Do not plan the roadmap as if the repository must become a mass-market VPN client before it is useful.

It is already useful if it becomes:

- a strong Linux reference implementation;
- a provider-profile and runtime-policy contract layer;
- a diagnostics/support bundle reference surface around `xray-core`.

## MVP Boundary

The first honest MVP should mean:

- signed manifests with local verification;
- provider profile compilation and strict validation;
- endpoint selection, failover, cooldown, and known-good reuse;
- one reliable Linux-first Xray-oriented runtime contour with explicit support assessment;
- safe local state and startup recovery behavior;
- Linux command planning and startup reconciliation diagnostics;
- Xray binary/config preflight diagnostics for real-mode startup;
- support bundle export and incident summary generation;
- explicit iOS bridge contract without promising a complete Apple runtime.

This is enough to call the project "a real client foundation with a releasable control plane", but not yet "full cross-platform parity".

For the first honest MVP release contour, we now narrow that further to:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

This keeps the release target concrete and prevents the repository from implying production parity across placeholder or bridge-only paths.

## Platform Target Matrix

### Linux

Role:
Reference runtime, active MVP contour, and earliest operational baseline.

Near-term target:

- keep Linux as the most inspectable command-planning and reconciliation path;
- use it to validate policy behavior, startup cleanup, support bundle shape, lifecycle logic, and Xray preflight behavior.

MVP expectation:

- deterministic dry-run and reconciliation behavior;
- explicit runtime support assessment as `mvp-supported`;
- reliable state transitions and rollback planning;
- strong incident visibility.

### Windows

Role:
Planned desktop target on the Xray-backed path after the Linux contour is stable.

Near-term target:

- define route, DNS, kill-switch, and process supervision contract around the shared core.

MVP expectation:

- Xray-backed session orchestration with platform adapter semantics defined;
- explicit degraded-mode behavior where native integration is still incomplete.

### macOS

Role:
Planned desktop target sharing the Xray-backed product model but with distinct network integration constraints.

Near-term target:

- keep runtime and platform integration separate from renderer logic;
- preserve supportability and clear failure attribution.

MVP expectation:

- same provider contract as Windows and Android-class runtimes;
- platform adapter contract documented and testable.

### Android

Role:
Planned mobile runtime track using the shared Xray-oriented dataplane model.

Near-term target:

- harden `VpnService` lifecycle contract, reconnect triggers, and runtime supervision behavior.

MVP expectation:

- Android runtime request contract stays versioned and explicit;
- session reassertion, boot reconnect policy, and meter handling are visible in config and state.

### iOS

Role:
Separate engineering track with explicit Apple constraints.

Near-term target:

- keep iOS on a bridge contract and configuration translation path;
- avoid implying that desktop or Android runtime assumptions carry over directly.

MVP expectation:

- valid bridge payload generation and status exchange only;
- no false claim of a finished production runtime until Apple-specific work exists.

## Recommended Work Order

1. Core runtime hardening.
2. Provider profile and schema stabilization.
3. Resilience logic under degraded networks.
4. Platform runtime maturation.
5. Operational readiness.
6. Product surface expansion.

## What Not To Do Yet

- do not chase full UI parity across all platforms before runtime contracts are stable;
- do not add provider-side schema flexibility without explicit versioning rules;
- do not treat iOS as "the same Xray process on another OS";
- do not widen telemetry without a clear privacy and incident-use justification.

## Immediate Next Practical Steps

1. Open a `P0` issue group for runtime hardening and incident visibility.
2. Open a `P0` issue group for manifest and provider schema versioning.
3. Open a `P1` issue group for resilience heuristics and failure classification.
4. Keep Windows, macOS, Android, and iOS work behind explicit platform contracts instead of ad hoc patches.
