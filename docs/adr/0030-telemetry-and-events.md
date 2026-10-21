# ADR-0030: Telemetry from counters, ETW and controller export, events by webhook

**Status:** Accepted (2026-10-20, from the SDN spec #176 that Hilmi filed; recorded by SDN-1, #177). Follows the ETW and Prometheus rows of ADR-0008.

## Context

The new core has no telemetry. Operators of an SDN need to see who sends what and which rules hit, Windows administrators expect local events in their usual tools, existing monitoring (Prometheus, OpenTelemetry) should pick Ranz up without adapters, and alerts must arrive without polling. The slim fork's web admin plans a Prometheus `/metrics` endpoint on its admin listener (ADR-0021); in the new core the controller is the place where fleet-wide numbers come together (ADR-0026).

## Decision

1. **Counters in the node per peer, per VRF and per policy rule.**
2. **Local node events go to ETW**, so Windows administrators read them with the tools they already use.
3. **Nodes push summaries to the controller** over the control stream (ADR-0027). **The controller exports Prometheus and OTLP.**
4. **IPFIX flow records** are the last telemetry step of v1, for traffic analysis per flow.
5. **Events by webhook:** node down, gateway failover, IPAM pool near exhaustion (ADR-0028) and an automatic rollback (ADR-0031). The same conditions are exported as metrics.

## Consequences

- The controller conformance seam (ADR-0026) checks events and metrics as external behaviour: a scenario that takes a node down or exhausts a pool produces the webhook call and the metric.
- The delivery order of #176 puts telemetry after IPAM and DNS and before the intent API; IPFIX comes last inside telemetry.
- The unified-management spec #224 adds an audit log (SDN-49, #242) and usage reports per user, group and network built from traffic counters (SDN-51, #244).
- Tickets: SDN-16 (#192).
