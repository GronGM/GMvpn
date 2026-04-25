# MVP Incident Playbook

## Purpose

This playbook describes the default operator triage flow for the first honest MVP contour:

- `client-platform=linux`
- linux platform adapter
- `dataplane=xray-core`

Use it for degraded sessions, failed sessions, repeated transport disable events, and startup recovery after abnormal exits.

Everything outside that contour should be treated as development-track work unless explicitly escalated.

## First Response

- Capture the CLI output from the failing run.
- Export a support bundle if one is not already available.
- Record the manifest version and the runtime contour in use.
- Record whether the operator used CLI defaults or explicitly selected the Linux Xray contour.
- Confirm whether the run is inside MVP scope by checking `runtime_support`.

If `runtime_support.in_mvp_scope` is `false`, treat the incident as outside the first supported release contour unless explicitly escalated for development work.

## What To Inspect First

Read these support bundle fields before changing anything:

- `incident_summary`
- `events[*].incident_severity`
- `events[*].primary_transport_issue`
- `runtime_support`
- `runtime_support_policy_resolved`
- `runtime_tick_policy_resolved`
- `startup_recovery`
- `transport_recovery`
- `incident_summary.primary_transport_issue`
- `endpoint_health`
- `dataplane_runtime`
- `dataplane_runtime.preflight_error`
- `linux_execution`
- `linux_reconciliation.failure_reason_code`
- `session_health_policy_resolved`
- `session_health_failure_threshold`
- `transport_reenable_policy_resolved`
- `transport_failure_policy_resolved`
- recent telemetry `events`

## Incident Classes

### 1. Startup Recovery Triggered

Signals:

- `startup_recovery.stale_marker_found = true`
- incident summary headline mentions startup recovery

Interpretation:

- The previous runtime did not shut down cleanly.
- The client recovered enough state to continue, but this may indicate a dataplane crash or interrupted process.

Immediate actions:

- Inspect `transport_recovery[*].crash_reason`.
- Inspect `backend_state_record` and `dataplane_runtime`.
- If `dataplane_runtime.crashed = true`, inspect `last_exit_code`, `running`, and stderr/stdout tails before retrying.
- Watch for repeated crashes on the same transport after recovery.

Escalate when:

- startup recovery repeats across consecutive runs;
- the same transport keeps collecting crash streaks;
- the recovered session immediately degrades again.

### 2. Degraded Session

Signals:

- CLI `state=SessionState.DEGRADED`
- support bundle `incident_summary.severity=warning` or `critical`

Interpretation:

- The client connected far enough to establish a session, but post-connect checks or runtime behavior signaled unhealthy state.

Immediate actions:

- Inspect `incident_summary.failure_class`.
- Inspect the latest telemetry event `reason_code`.
- Inspect `session_health_fail_streak` and `session_health_fail_bucket`.
- Inspect `transport_soft_fail_buckets`.

If the same `failure_class:reason_code` bucket repeats:

- treat it as a persistent transport/runtime symptom, not a one-off flap.

### 3. Failed Session

Signals:

- CLI `state=SessionState.FAILED`
- no stable selected endpoint survives the connect attempt chain

Interpretation:

- The client could not reach or hold a working session within the current retry budget.

Immediate actions:

- Inspect `attempts` in CLI output or bundle.
- Inspect `incident_summary.selected_transport` and `cooling_down_endpoints`.
- Inspect `transport_recovery` for disabled or pending transports.
- Separate endpoint failure from dataplane/runtime failure using `reason_code`.

### 4. Transport Disable Or Reenable Loop

Signals:

- `transport_recovery[*].disable_flag_active = true`
- repeated `reenable_fail_streak`
- transport returns to pending and quickly fails again

Interpretation:

- The client has identified repeated bad outcomes on that transport and is trying to avoid reconnect thrash.

Immediate actions:

- Inspect `soft_fail_bucket`, crash reason, and disable expiry.
- Check whether the symptom is transport-specific or global across all endpoints.
- Avoid manually forcing repeated reconnect attempts without changing conditions.

Escalate when:

- all viable transports enter the same disable pattern;
- a single transport never leaves reenable failure state;
- behavior differs from the configured retry budget or cooldown expectations.

## Reading Failure Signals

Use `failure_class` for the broad incident bucket and `reason_code` for the concrete symptom.

Examples:

- `dns_interference:dns_lookup_failed`
- `tls_interference:tls_handshake_failed`
- `network_down:route_programming_failed`
- `network_down:dataplane_backend_crashed`
- `network_down:dataplane_healthcheck_failed`

Operator rule:

- do not treat all `network_down` incidents as the same;
- route programming failure, crashed backend, and failed health check have different owners and fixes.

## Linux Xray MVP Triage

For the current MVP contour, focus on these ownership boundaries:

- Linux platform adapter:
  - route plan
  - DNS policy application
  - kill-switch plan
  - startup reconciliation
- Xray dataplane:
  - config rendering
  - process startup
  - process liveness
  - crash output / exit behavior
  - post-start exit attribution
- Shared control plane:
  - endpoint selection
  - cooldown and retry budget
  - incident summary
  - support bundle export
  - reason-aware hysteresis

This separation matters because it tells you where to fix the bug instead of masking it with more retries.

Also remember one practical source of confusion during triage:

- the CLI default dataplane remains `routed` for local safety;
- MVP support expectations are anchored on an explicit `--dataplane xray-core` Linux run.

If the incident came from a default local CLI invocation, first confirm whether it is actually evidence about the release-track contour.

## When To Roll Back

Prefer rollback over continued rollout when:

- CI was green but operator sanity checks fail on the MVP contour;
- support bundle output lost key diagnostic fields;
- degraded or failed sessions are no longer explainable from incident summary plus bundle;
- the Linux Xray contour no longer assesses as `mvp-supported`;
- repeated crash or disable patterns appear after the release and were not present in the previous known-good baseline.

## What To Attach To An Engineering Escalation

- manifest version
- selected runtime contour
- CLI output
- support bundle
- whether the issue is reproducible
- whether it is new to the current release
- whether rollback removes the symptom

## Non-Goals

- This is not a playbook for iOS production support.
- This is not a guarantee of parity for Windows, macOS, or Android paths in the current repository state.
- This does not replace release notes or schema migration docs.
