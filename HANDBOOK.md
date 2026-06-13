# Snypshark — Master Roadmap & Architecture Handbook

## Purpose

This document serves as the authoritative roadmap, architecture reference, and long-term planning handbook for Snypshark.

Project execution is managed through GitHub using:

* Milestones
* Epics
* Issues
* Pull Requests
* GitHub Projects

GitHub is the operational source of truth.

This document preserves:

* Product vision
* Architectural evolution
* Design rationale
* Release objectives
* Planned capabilities
* Long-term roadmap
* Technical implementation intent

---

# GitHub Project Structure

Snypshark follows the following hierarchy:

```text
Milestone
    └── Epic
            └── Issue
                    └── Pull Request
```

## Workflow

```text
Backlog
    ↓
Ready
    ↓
In Progress
    ↓
Review
    ↓
Testing
    ↓
Done
```

---

# Release Roadmap

| Phase   | Milestone | Epic                                  | Status   |
| ------- | --------- | ------------------------------------- | -------- |
| Phase 0 | v0.1.0    | PCAP Forensic Analyzer                | Complete |
| Phase 1 | v0.2.0    | Forensic Telemetry Foundation         | Active   |
| Phase 2 | v0.3.0    | On-Host Live Capabilities             | Planned  |
| Phase 3 | v0.4.0    | Log Ingestion & Cross-Source Timeline | Planned  |
| Phase 4 | v0.5.0    | Telemetry Detection Engine            | Planned  |
| Phase 5 | v1.0.0    | Incident Response UX & Sweep Mode     | Planned  |

---

# Phase 0 — v0.1.0 · PCAP Forensic Analyzer

Baseline release.

Implemented and closed.

Reference:

* GitHub Milestone: v0.1.0
* GitHub Release: v0.1.0

---

# Phase 1 — v0.2.0 · Forensic Telemetry Foundation

## GitHub Mapping

### Epic

```text
[EPIC] Forensic Telemetry Foundation
```

### Milestone

```text
v0.2.0
```

### Primary Components

```text
Core
Telemetry
CLI
Testing
```

### Priority

```text
P0
```

---

## Goal

Decouple the engine from its PCAP-only input.

Introduce a source abstraction layer so the same analysis pipeline can consume any telemetry stream, not just packet captures.

This phase is primarily architectural and establishes the telemetry abstraction model required by all future capabilities.

---

## Deliverables

### TelemetrySource ABC

GitHub Issue

```text
feat(core): implement TelemetrySource abstraction
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Feature                              |
| Priority   | P0                                   |
| Components | Core, Telemetry                      |

Description

Define an abstract base class `TelemetrySource` with a single required method:

```python
stream_events() -> Iterator[TelemetryEvent]
```

All telemetry providers must implement this interface.

Purpose

Remove the tight coupling between the analysis engine and pyshark-specific file readers.

Target Module

```text
analyzer/core/telemetry_source.py
```

---

### TelemetryEvent Dataclass

GitHub Issue

```text
feat(core): create TelemetryEvent model
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Feature                              |
| Priority   | P0                                   |
| Components | Core, Telemetry                      |

Description

Define a normalized event model:

```python
TelemetryEvent(
    type: str,
    timestamp: datetime,
    source_id: str,
    payload: dict
)
```

Supported event categories:

```text
network_packet
process_start
log_entry
```

Purpose

Replace raw pyshark packet objects as the canonical unit flowing through the analysis pipeline.

Target Module

```text
analyzer/core/telemetry_event.py
```

Notes

This component is a direct dependency of the TelemetrySource abstraction.

---

### PCAPFileSource

GitHub Issue

```text
feat(telemetry): implement PCAPFileSource
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Feature                              |
| Priority   | P0                                   |
| Components | Telemetry, Capture                   |

Description

Wrap the current pyshark-based packet reading implementation in a concrete TelemetrySource.

Proposed interface:

```python
PCAPFileSource(path)
```

Behavior

Each packet is converted into:

```python
TelemetryEvent(
    type="network_packet",
    ...
)
```

Purpose

Allow the rest of the platform to operate independently of the underlying telemetry source.

After implementation, the engine becomes source-agnostic.

---

### TelemetryProcessor Abstraction

GitHub Issue

```text
refactor(core): introduce TelemetryProcessor abstraction
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Refactor                             |
| Priority   | P0                                   |
| Components | Core, Telemetry                      |

Description

Generalize packet processing into a telemetry-aware processing model.

Replace or extend PacketProcessor with:

```python
TelemetryProcessor
```

Primary interface:

```python
process_event(event: TelemetryEvent)
```

Behavior

Introduce event-type filtering logic so processors only execute when relevant.

Default compatibility target:

```text
network_packet
```

Existing packet processors must remain operational without modification.

Purpose

Prepare the processing pipeline for future telemetry sources.

---

### TelemetryEngine

GitHub Issue

```text
refactor(core): replace PCAPAnalyzer with TelemetryEngine
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Refactor                             |
| Priority   | P0                                   |
| Components | Core, Telemetry                      |

Description

Replace the current PCAPAnalyzer with a source-independent execution engine.

Proposed interface:

```python
TelemetryEngine(source: TelemetrySource)
```

Responsibilities

* Consume events from any telemetry source
* Iterate event streams
* Dispatch events to registered processors
* Coordinate execution workflow

Existing parallel processing logic remains in:

```text
core/parallel_engine.py
```

Purpose

Establish the central execution engine for all future telemetry-driven capabilities.

---

### CLI Integration

GitHub Issue

```text
feat(cli): integrate PCAPFileSource into CLI
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Feature                              |
| Priority   | P1                                   |
| Components | CLI                                  |

Description

Update CLI entrypoints so file-based analysis uses the new telemetry architecture.

Files impacted:

```text
cli.py
main.py
```

Behavior

The supplied file path should instantiate:

```python
PCAPFileSource(path)
```

and pass it to:

```python
TelemetryEngine
```

Requirements

* Preserve all existing CLI arguments
* Preserve current workflows
* Preserve current output formats

---

### Test Suite Migration

GitHub Issue

```text
enhancement(testing): migrate test suite to telemetry architecture
```

Metadata

| Field      | Value                                |
| ---------- | ------------------------------------ |
| Epic       | [EPIC] Forensic Telemetry Foundation |
| Type       | Enhancement                          |
| Priority   | P1                                   |
| Components | Testing, Core                        |

Description

Update the entire test suite to operate on the new telemetry abstractions.

Areas impacted:

* conftest.py
* fixtures
* unit tests
* integration tests

Requirements

* Introduce TelemetryEvent fixtures
* Introduce TelemetryEngine coverage
* Validate processor compatibility
* Guarantee zero regressions

---

# Phase 2 — v0.3.0 · On-Host Live Capabilities

## Epic

```text
[EPIC] On-Host Live Capabilities
```

## Goal

Enable Snypshark to run directly on a host during a security incident, capturing live traffic from network interfaces and correlating network activity with operating system processes.

## Deliverables

### LiveCaptureSource

GitHub Issue

```text
feat(capture): implement LiveCaptureSource
```

Description

Concrete TelemetrySource implementation capable of ingesting traffic from a live network interface.

Potential backends:

* pyshark.LiveCapture
* tcpdump
* future libpcap integrations

Enables:

```bash
snypshark --live eth0 --duration 60
```

---

### ProcessNetworkMapper

GitHub Issue

```text
feat(host): implement ProcessNetworkMapper
```

Description

Correlate network connections with process ownership.

Data sources:

* /proc/net/tcp
* /proc/net/tcp6
* /proc/[pid]/fd
* /proc/[pid]/cmdline

Purpose

Answer:

```text
Which process opened this connection?
```

---

### HostContextCollector

GitHub Issue

```text
feat(host): implement HostContextCollector
```

Description

Capture a forensic snapshot of host state.

Collected artifacts:

* Running processes
* Listening ports
* Active connections
* Logged-in users
* Active systemd units
* Recent configuration modifications

Purpose

Provide investigation context and forensic evidence.

---

### Live Capture CLI Mode

GitHub Issue

```text
feat(cli): add live capture mode
```

Description

Expose live capture as a first-class operating mode.

Options:

```bash
--live
--interface
--duration
```

Behavior

Mutually exclusive with file-based analysis.

---

# Phase 3 — v0.4.0 · Log Ingestion & Cross-Source Timeline

## Epic

```text
[EPIC] Log Ingestion & Cross-Source Timeline
```

## Goal

Ingest operating system logs and correlate events across telemetry domains through a unified timeline.

## Deliverables

### JournaldSource

GitHub Issue

```text
feat(logs): implement JournaldSource
```

### SyslogFileSource

GitHub Issue

```text
feat(logs): implement SyslogFileSource
```

### Timeline Correlation Engine

GitHub Issue

```text
enhancement(reporting): extend TimelineAnalyzer
```

---

# Phase 4 — v0.5.0 · Telemetry Detection Engine

## Epic

```text
[EPIC] Telemetry Detection Engine
```

## Goal

Introduce behavioral detections powered by host and network telemetry correlation.

## Deliverables

### Beaconing Detector

GitHub Issue

```text
feat(detections): implement beaconing detector
```

### Exfiltration Detector

GitHub Issue

```text
feat(detections): implement exfiltration detector
```

### DNS Tunneling Detector

GitHub Issue

```text
feat(detections): implement DNS tunneling detector
```

### Confidence Scoring Framework

GitHub Issue

```text
enhancement(detections): implement confidence scoring
```

---

# Phase 5 — v1.0.0 · Incident Response UX & Sweep Mode

## Epic

```text
[EPIC] Incident Response UX & Sweep Mode
```

## Goal

Deliver a single command capable of generating actionable forensic intelligence during active incident response operations.

## Deliverables

### Sweep Mode

GitHub Issue

```text
feat(cli): implement sweep mode
```

### ForensicReport

GitHub Issue

```text
feat(reporting): implement ForensicReport
```

### Incident Summary Output

GitHub Issue

```text
feat(reporting): implement incident summary output
```

### Global Time Filtering

GitHub Issue

```text
enhancement(cli): implement global time filtering
```

---

# Future Phase Template

When introducing a new phase:

1. Create a GitHub Milestone.
2. Create a corresponding Epic.
3. Define release objectives.
4. Create child Issues.
5. Assign labels.
6. Update this document.

Required metadata:

```text
Milestone
Epic
Priority
Components
```

Required sections:

```text
Goal
Deliverables
Dependencies
Success Criteria
Architecture Notes
```

# Work Item Classification

All work introduced into Snypshark must be classified according to the project's GitHub governance model.

Every new GitHub Issue must define:

* Type
* Priority
* Component
* Milestone
* Epic (when applicable)

Issues must be created using the naming conventions defined below.

---

## Feature Issues

Used for new functionality, capabilities, architectural components, or user-facing improvements.

Naming Convention:

```text
feat(<component>): <short description>
```

Examples:

```text
feat(core): implement TelemetrySource abstraction

feat(telemetry): implement PCAPFileSource

feat(host): implement ProcessNetworkMapper

feat(cli): add live capture mode
```

Required Labels:

```text
feature
<Component>
<priority>
```

Example:

```text
feature
core
p0
```

---

## Enhancement Issues

Used when extending existing functionality without introducing entirely new capabilities.

Naming Convention:

```text
enhancement(<component>): <short description>
```

Examples:

```text
enhancement(reporting): extend TimelineAnalyzer

enhancement(cli): implement global time filtering

enhancement(detections): implement confidence scoring
```

Required Labels:

```text
enhancement
<Component>
<priority>
```

---

## Refactor Issues

Used for internal architecture improvements that do not directly change user-facing functionality.

Naming Convention:

```text
refactor(<component>): <short description>
```

Examples:

```text
refactor(core): replace PCAPAnalyzer with TelemetryEngine

refactor(core): introduce TelemetryProcessor abstraction
```

Required Labels:

```text
refactor
<Component>
<priority>
```

---

## Research Issues

Used for investigations, proof-of-concepts, architectural studies, and technology evaluations.

Naming Convention:

```text
research(<component>): <short description>
```

Examples:

```text
research(capture): evaluate eBPF capture backends

research(host): investigate Windows telemetry collection

research(detections): evaluate Sigma integration
```

Required Labels:

```text
research
<Component>
<priority>
```

---

## Bug Issues

Used when existing functionality behaves incorrectly.

Bugs are considered defects in previously implemented behavior.

Naming Convention:

```text
bug(<component>): <short description>
```

Examples:

```text
bug(telemetry): PCAPFileSource skips fragmented packets

bug(cli): invalid duration validation

bug(reporting): timeline output ordering incorrect
```

Required Labels:

```text
bug
<Component>
<priority>
```

Additional Metadata:

* Affected version
* Reproduction steps
* Expected behavior
* Actual behavior
* Root cause (when known)

---

## Security Vulnerability Issues

Used for confirmed security weaknesses.

Security issues should never be created as Feature, Enhancement, or Bug issues.

Naming Convention:

```text
security(<component>): <short description>
```

Examples:

```text
security(cli): command injection via interface parameter

security(reporting): sensitive data leakage in JSON output

security(host): insufficient permission validation
```

Required Labels:

```text
security
<Component>
<p0>
```

Additional Metadata:

* CVSS score (if applicable)
* Impact assessment
* Exploitability assessment
* Affected versions
* Mitigation plan

Guidelines:

* Security issues are always treated as P0 unless explicitly downgraded.
* Public disclosure should occur only after remediation.
* Sensitive vulnerabilities should be tracked in private repositories when possible.

---

## Conflict Issues

Used when architectural, dependency, compatibility, or design conflicts are discovered.

Conflict issues are not bugs.

Conflict issues identify competing implementations, incompatible dependencies, or design disagreements requiring resolution.

Naming Convention:

```text
conflict(<component>): <short description>
```

Examples:

```text
conflict(capture): pyshark dependency limits portability

conflict(core): event schema incompatible with detection engine

conflict(host): Linux-only implementation blocks Windows roadmap
```

Required Labels:

```text
conflict
<Component>
<priority>
```

Conflict Resolution Process:

1. Document the conflicting approaches.
2. Identify architectural impact.
3. Identify long-term maintenance impact.
4. Evaluate implementation complexity.
5. Record final decision.
6. Link decision to related Epic and Issues.

---

## Epic Creation Rules

An Epic should be created when:

* Multiple issues contribute to a single objective.
* A new architectural capability is introduced.
* A new release milestone is planned.

Naming Convention:

```text
[EPIC] <initiative name>
```

Examples:

```text
[EPIC] Forensic Telemetry Foundation

[EPIC] On-Host Live Capabilities

[EPIC] Log Ingestion & Cross-Source Timeline
```

An Epic should never contain implementation details.

Implementation belongs to child Issues.

---

## Milestone Creation Rules

A new Milestone should be created when:

* A release version is planned.
* A major capability group is introduced.
* Multiple Epics contribute toward a common release.

Naming Convention:

```text
vX.Y.Z - Release Name
```

Examples:

```text
v0.2.0 - Forensic Telemetry Foundation

v0.3.0 - On-Host Live Capabilities

v1.0.0 - Incident Response UX & Sweep Mode
```

Milestones represent releases.

Epics represent initiatives.

Issues represent implementation work.
