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

## Amendment 2026-10-23: the audit log (SDN-49)

Recorded by SDN-49 (#242), the audit log that the unified-management spec #224 adds to the telemetry of this ADR (user story 55).

- **An Audit record is not an Event.** The controller keeps an audit log beside the Events of decision 5: one Audit record for each login, logout, failed authentication, enrolment, change of the intent and operation, with its actor, its time, its source, its outcome and, for a change of the intent, the revision that it made. An Event is a condition that operators are told about; an Audit record is the controller's account of who did what. The two have their own tables, their own API and their own targets, so a webhook of events never receives an Audit record.
- **What each kind records today.** `intent-change`: every revision (apply, delete, rollback, import, the first start and the automatic rollback), written by the controller with the revision, under the API token that asked for it or the system; an apply, delete, rollback or import that an API call asked for and that failed is a record with outcome failure, the reason and no revision. `operation`: every other call of the API that changes something (a licence key, an export or audit target, an API token, the retention), with the call as its action, so the live operations of SDN-50 (#243) are audited from the day they exist. `auth-failed`: a call of the API whose bearer token is missing or unknown, a request that the admin source allowlist of SDN-39 refused, and a node whose static key no Node resource holds (its actor is the key, so an operator can write the resource). `enrolment`: the first Hello of a static key, and with the outcome failure a node that a Network refused to enrol because of its source address (`enrolSources`, SDN-39); both refusals are Events as well, and are recorded here as often as the Event is. `login` and `logout`: a control stream of a node that was accepted and that ended; the logins of users and administrators (SDN-32, #226) record themselves as the same kinds through `Controller.RecordAudit`. A controller that closes ends every stream and records no logout for them. A source that fails to authenticate again within 10 seconds is not recorded again, so a caller that guesses tokens cannot fill the store.
- **Export.** An audit target is an export target of its own kind, kept in its own table and managed under `/api/v1/audit/targets`: a `webhook` receives each record as a JSON POST signed with the secret of the target (`X-Ranz-Signature`, the form of the webhook of events), and a `syslog` receiver each record as an RFC 5424 message over UDP, TCP or TLS (the facility is log audit, the severity warning for a failure; over TCP and TLS each message has its length in front of it, RFC 6587 and RFC 5425). A target may name the kinds it wants. The leader sends each target the records in the order they were made and the store keeps the last record each target was sent, so a controller that restarts, or the next leader, goes on where the last one stopped; a target that fails is tried again with a growing wait, and no record is skipped for it. A new target starts at the latest record.
- **Retention.** The leader removes the records older than the retention policy, and the oldest beyond its maximum number, every hour. The policy is `{"days": 365, "maxRecords": 2000000}` until an operator sets another through `/api/v1/audit/retention`; the maximum number is what keeps a flood of failed authentications from filling the disk. The id of a record is never used twice, also after every record was removed, so the record of what a target was sent stays valid.
- **Reading.** `GET /api/v1/audit` lists the records oldest first, with `kind`, `actor`, `since`, `until`, `after` and `limit`. It needs the role viewer, since the API gives every read that role; keeping the audit log from viewers needs a rule in the Guard (`api.Needs`), which is not part of this change. The source of a call that a standby forwarded to the leader is the address of the standby.
- **ETW on the nodes** stays with the node (decision 2): the control message that tells a node what to log, and the C code that writes the events, are not part of this change.
