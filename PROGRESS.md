# Snypshark — Progress & Phases

This file tracks development phases and their tasks. Each phase maps to a version
release. A phase is closed when all its tasks are marked complete.

---

## Phase Status

| Phase | Version | Focus | Status |
|-------|---------|-------|--------|
| Phase 0 | v0.1.0 | PCAP Forensic Analyzer (baseline) | ✅ Complete |
| Phase 1 | v0.2.0 | Forensic Telemetry Foundation | 🔄 In Progress |
| Phase 2 | v0.3.0 | On-Host Live Capabilities | Pending |
| Phase 3 | v0.4.0 | Log Ingestion & Cross-Source Timeline | Pending |
| Phase 4 | v0.5.0 | Telemetry Detection Engine | Pending |
| Phase 5 | v1.0.0 | Incident Response UX & Sweep Mode | Pending |

---

## Phase 0 — v0.1.0 · PCAP Forensic Analyzer ✅

Baseline release. Snypshark operates as an offline PCAP analyzer ingesting `.pcap`
and `.pcapng` capture files and delivering protocol inspection, anomaly detection,
and structured reporting from a single CLI command.

**All tasks complete. Phase closed.**

---

## Phase 1 — v0.2.0 · Forensic Telemetry Foundation 🔄

**Goal:** Decouple the engine from its PCAP-only input. Introduce a source abstraction
layer so the same analysis pipeline can consume any telemetry stream — not just
packet captures. This phase is purely architectural; no new end-user features land
until the foundation is in place.

### Tasks

- [ ] **T1.1 — `TelemetrySource` ABC**
  Define an abstract base class `TelemetrySource` in `core/` with a single required
  method `stream_events() -> Iterator[TelemetryEvent]`. All input sources must
  implement this interface. Replaces the tight coupling between `PCAPAnalyzer` and
  `pyshark` file objects.

- [ ] **T1.2 — `TelemetryEvent` dataclass**
  Define a normalized event type `TelemetryEvent(type: str, timestamp: datetime,
  source_id: str, payload: dict)`. The `type` field is a string constant
  (e.g. `"network_packet"`, `"process_start"`, `"log_entry"`) that processors
  use to decide whether to handle the event. Replaces raw pyshark packet objects
  as the unit flowing through the pipeline.

- [ ] **T1.3 — `PCAPFileSource` (migrate existing behavior)**
  Wrap the current `pyshark`-based packet reading in a concrete `TelemetrySource`
  implementation: `PCAPFileSource(path)`. It yields `TelemetryEvent(type="network_packet", ...)`
  for each packet. After this task, the rest of the pipeline is source-agnostic.

- [ ] **T1.4 — Generalize `PacketProcessor` to `TelemetryProcessor`**
  Rename / extend the ABC to `TelemetryProcessor` with `process_event(event: TelemetryEvent)`
  as the primary method. Add a default guard so existing processors only fire on
  `type == "network_packet"`, making all current processors valid without changes.

- [ ] **T1.5 — Refactor `PCAPAnalyzer` into `TelemetryEngine`**
  Replace `PCAPAnalyzer` with `TelemetryEngine(source: TelemetrySource)`. The engine
  accepts any `TelemetrySource`, iterates events, and dispatches to registered
  `TelemetryProcessor` instances. Parallel batch logic stays in `core/parallel_engine.py`.

- [ ] **T1.6 — Update CLI to instantiate `PCAPFileSource`**
  Adjust `cli.py` and `main.py` so the file path argument constructs a
  `PCAPFileSource`, which is passed to `TelemetryEngine`. All existing CLI flags
  and behavior remain identical from the user's perspective.

- [ ] **T1.7 — Update tests to the new interfaces**
  Adapt `conftest.py` fixtures and all existing test files to use `TelemetryEvent`
  and `TelemetryEngine`. Ensure zero test regressions before closing the phase.

---

## Phase 2 — v0.3.0 · On-Host Live Capabilities

**Goal:** Enable Snypshark to run directly on a host during a security incident —
capturing live traffic from a network interface and mapping connections back to the
operating system processes that opened them.

### Tasks (planned)

- [ ] **T2.1 — `LiveCaptureSource`**
  Concrete `TelemetrySource` that uses `pyshark.LiveCapture` (or `tcpdump` subprocess)
  to stream packets from a live network interface. Enables
  `snypshark --live eth0 --duration 60`.

- [ ] **T2.2 — `ProcessNetworkMapper` processor**
  Reads `/proc/net/tcp`, `/proc/net/tcp6`, and per-PID `/proc/[pid]/fd/` and
  `/proc/[pid]/cmdline` to correlate each active or recent connection with the
  process name and PID that owns it. Answers: "which process opened this connection?"

- [ ] **T2.3 — `HostContextCollector`**
  Snapshots the live host state at analysis time: running processes, listening
  ports, established connections, logged-in users, active systemd units, recent
  file modifications in `/etc`. Provides the forensic baseline context for all
  findings in the session.

- [ ] **T2.4 — `--live` and `--interface` CLI flags**
  Expose live capture as a first-class CLI mode. Mutually exclusive with the
  positional `FILE` argument. Includes `--duration N` (seconds) and
  `--interface NAME` options.

---

## Phase 3 — v0.4.0 · Log Ingestion & Cross-Source Timeline

**Goal:** Ingest system log streams as a telemetry source and correlate log events
with network events on a unified timeline.

### Tasks (planned)

- [ ] **T3.1 — `JournaldSource`**
  Concrete `TelemetrySource` that reads from `journald` (via `systemd.journal` or
  `journalctl` subprocess) and emits `TelemetryEvent(type="log_entry", ...)`.
  Supports time-range filtering (`--since`, `--until`).

- [ ] **T3.2 — `SyslogFileSource`**
  Fallback `TelemetrySource` for hosts without systemd. Parses structured lines
  from `/var/log/syslog`, `/var/log/auth.log`, and similar files.

- [ ] **T3.3 — Cross-source `TimelineAnalyzer` extension**
  Extend the existing `TimelineAnalyzer` to accept events from multiple source
  types on a single timeline. Enables queries like: "show all events — network,
  process, log — in the 30 seconds around this anomaly."

---

## Phase 4 — v0.5.0 · Telemetry Detection Engine

**Goal:** Add detections that are only possible with host telemetry context: beaconing,
exfiltration patterns, and DNS tunneling.

### Tasks (planned)

- [ ] **T4.1 — Beaconing detector**
  Statistical analysis of outbound connection intervals per destination IP/port.
  Flags regularity (low coefficient of variation) as a C2 beaconing indicator.

- [ ] **T4.2 — Exfiltration detector**
  Identifies flows where outbound byte volume significantly exceeds inbound volume
  toward external IPs, correlated with process identity from `ProcessNetworkMapper`.

- [ ] **T4.3 — DNS tunneling detector**
  Extends `DNSProcessor` to flag: high-entropy subdomains, abnormally large DNS
  payloads, and unusual query rates to a single authoritative nameserver.

- [ ] **T4.4 — Confidence scoring**
  Assign a `confidence: float` and `finding_type: str` to every security finding.
  Replaces the current boolean hit/miss model with a graded severity scale.

---

## Phase 5 — v1.0.0 · Incident Response UX & Sweep Mode

**Goal:** Deliver a single command that an analyst can run on a host during an
active alert and receive a structured, actionable forensic report.

### Tasks (planned)

- [ ] **T5.1 — `snypshark sweep` subcommand**
  Orchestrates a full on-host forensic sweep: host context snapshot → live capture
  (short window) → log ingestion → process mapping → all detectors. Accepts
  `--since N` (look-back window in minutes/hours) and `--interface NAME`.

- [ ] **T5.2 — `ForensicReport` output format**
  Structured JSON report designed for incident response: `timestamp`, `host`,
  `process`, `dst_ip`, `dst_port`, `bytes_out`, `finding_type`, `confidence`,
  `evidence`. Replaces the stats-focused current report for sweep mode output.

- [ ] **T5.3 — Human-readable IR summary**
  Narrative terminal output for sweep results: a chronological list of findings
  in plain language ("at 14:32:01, process nginx (pid 1823) opened an outbound
  connection to 203.0.113.5:4444 — beaconing confidence: 0.87").

- [ ] **T5.4 — `--since` time-range flag (global)**
  Apply a time-range filter across all sources so analysts can scope the sweep to
  the window of interest (e.g. `--since 2h` = last 2 hours).

---

*Updated after each task is completed. Phase closed when all tasks are checked.*
