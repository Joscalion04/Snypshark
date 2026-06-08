# CLAUDE.md — Snypshark

## Role

You are a **Senior OpenSource Software Engineer** working on Snypshark, a CLI-based PCAP network forensic analyzer written in Python. You write clean, idiomatic Python, value modularity through abstract base classes, and understand network protocols at the packet level. You contribute as if preparing code for public review — clear, minimal, well-tested, and documented only where non-obvious.

---

## Project Overview

**Snypshark** is a terminal-based tool that ingests `.pcap` / `.pcapng` capture files and delivers deep protocol analysis, security threat detection, and statistical reporting — all from a rich interactive CLI. It is built for network engineers, security analysts, and forensic investigators.

Core value propositions:
- Multi-protocol deep inspection (TCP, UDP, IP, ICMP, DNS, HTTP, DHCP)
- Parallel packet processing engine for performance on large captures
- Pandas-powered analytics: time series, top talkers, anomaly scoring
- Export to Excel (XLSX) and JSON
- Zero external dashboard required — everything runs in the terminal

**Entry point:** `main.py` (root) → imports from `analyzer/`

---

## Project Structure

```
snypshark/
├── main.py                     # CLI entry point — orchestrates the full analysis flow
│
├── analyzer/                   # Main package — all application logic lives here
│   ├── main.py                 # Alternate entry / dev runner (same logic as root main.py)
│   ├── __init__.py
│   │
│   ├── core/                   # Engine — packet loading, parallel dispatch, processor registry
│   │   ├── analyzer.py         # PCAPAnalyzer: registers processors, drives analysis loop
│   │   ├── packet_processor.py # Abstract base class (ABC) all processors must implement
│   │   └── parallel_engine.py  # Thread pool + batch processor for high-throughput parsing
│   │
│   ├── processors/             # One module per protocol — each implements PacketProcessor ABC
│   │   ├── tcp_processor.py    # TCP flag analysis, stream tracking, port stats
│   │   ├── udp_processor.py    # UDP port distribution, payload size
│   │   ├── ip_processor.py     # TTL analysis, fragmentation, protocol distribution
│   │   ├── icmp_processor.py   # ICMP type/code decoding, error message tracking
│   │   ├── dns_processor.py    # Query/response correlation, suspicious domain detection
│   │   ├── http_processor.py   # Method tracking, host analysis, user-agent monitoring
│   │   ├── dhcp_processor.py   # Lease monitoring, message type analysis
│   │   └── pattern_processor.py# Custom regex threat-hunting patterns across all traffic
│   │
│   ├── analytics/              # Pandas layer — builds DataFrames from processor output
│   │   ├── pandas_analyzer.py  # Orchestrator: builds all DataFrames, generates security report
│   │   ├── security_analyzer.py# Port scan detection, anomaly scoring, protocol violations
│   │   ├── statistical_analyzer.py # Mean/median/stddev, top-N analysis, correlations
│   │   └── timeline_analyzer.py    # Time series: traffic over time, burst detection
│   │
│   ├── ui/                     # Terminal UI — all display and interaction logic
│   │   ├── cli_interface.py    # InteractiveMenu: main post-analysis navigation menu
│   │   ├── menu_system.py      # Menu rendering helpers, category grouping
│   │   ├── progress_renderer.py# Animated ProgressBar used during packet analysis
│   │   └── osi_visualizer.py   # OSIVisualizer: quick OSI-layer breakdown on small captures
│   │
│   ├── utils/                  # Stateless helper functions — no business logic
│   │   ├── file_utils.py       # Path validation, file size formatting
│   │   ├── performance_utils.py# Memory optimization, system info (CPU/RAM)
│   │   ├── validation_utils.py # Input sanitization and format checks
│   │   └── export_utils.py     # Excel/JSON serialization helpers
│   │
│   └── config/                 # Constants and tunable settings — no logic, only data
│       ├── settings.py         # User-facing configuration knobs
│       ├── constants.py        # Protocol constants, magic numbers, regex patterns
│       └── performance_config.py # PerformanceConfig: batch sizes, thread counts, thresholds
│
├── tests/                      # Pytest test suite
│   ├── conftest.py             # Shared fixtures (sample PCAP paths, mock packets)
│   ├── test_analyzer.py        # Core engine integration tests
│   ├── test_flag_descriptor.py # TCP/ICMP flag decoding unit tests
│   ├── test_osi_layers.py      # OSI layer detection tests
│   └── test_pattern_matcher.py # Regex pattern matching tests
│
├── assets/                     # Static assets — logos only, not imported by code
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # Dev/test dependencies (pytest, black, mypy, etc.)
├── pyproject.toml              # Build config and tool settings (pytest, black, mypy)
├── setup.py                    # Legacy setuptools entrypoint
├── COMMIT_GUIDELINES.md        # Project commit message conventions
├── NETWORK_PROTOCOLS.md        # Protocol reference used during development
└── LICENSE                     # MIT
```

---

## Architecture Patterns

**Processor pattern:** All protocol analyzers implement `PacketProcessor` (ABC in `core/packet_processor.py`). `PCAPAnalyzer.add_processor()` registers them; the engine calls each processor per packet. To add a new protocol, subclass `PacketProcessor` and register it in `main.py`.

**Parallel engine:** `ParallelProcessingEngine` (thread pool) + `BatchProcessor` split large captures into batches. Batch size and thread count live in `config/performance_config.py`. Do not add concurrency logic outside `core/`.

**Analytics layer:** `PandasAnalyzer` is itself a `PacketProcessor` — it accumulates raw data during the analysis loop, then `build_dataframes()` converts it to DataFrames post-loop. `security_analyzer`, `statistical_analyzer`, and `timeline_analyzer` operate on those DataFrames.

---

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt          # runtime
pip install -r requirements-dev.txt      # dev + test

# Run the analyzer (always from project root)
python main.py

# Run tests
pytest
pytest --cov=analyzer                    # with coverage
pytest tests/test_analyzer.py -v        # single module
```

**Runtime requirement:** `tshark` (from Wireshark) must be installed and on `$PATH`.

**Note:** The root `main.py` is the canonical entry point. It adds `analyzer/` to `sys.path` so all imports work. `analyzer/main.py` is a thin shim for running from that subdirectory — do not duplicate application logic there.

---

## Commit Conventions

Follow `COMMIT_GUIDELINES.md`. Short form:

| Prefix | Use |
|--------|-----|
| `add [name]` | New feature or module |
| `fix [name]` | Bug fix |
| `update [name]` | Improvement to existing code/docs |
| `setup [name]` | Config, environment, dependencies |
| `delete [name]` | Remove obsolete code |
| `tofix [name]` | Temporary patch, needs follow-up |

Keep messages under 72 characters. Imperative mood.

---

## Development Guidelines

- **Add a new protocol processor:** subclass `PacketProcessor`, implement `process_packet()`, register in `main.py` processors dict.
- **Modify analytics:** touch only `analytics/`. Do not add DataFrame logic to processors.
- **UI changes:** only `ui/`. Keep display concerns out of core and processors.
- **Config changes:** add knobs to `config/settings.py` or `config/constants.py`. Hard-coded values belong in `constants.py`, not scattered through processors.
- **Tests:** place in `tests/`, prefix files with `test_`. Use fixtures from `conftest.py` rather than real PCAP files.
- **No comments on obvious code.** Only comment hidden constraints, workarounds, or protocol-level non-obvious behavior.
- **Type hints on all public functions.** `mypy` is configured in `pyproject.toml`.
