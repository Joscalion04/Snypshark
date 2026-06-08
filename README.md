# Snypshark — PCAP Network Traffic Analyzer

<div align="center">
  <img src="assets/logo_2.png" alt="Snypshark logo" width="200"/>
</div>

<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Version](https://img.shields.io/badge/version-0.1.0-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)

</div>

Snypshark is a terminal-based PCAP analysis tool for network forensics, security investigation, and traffic inspection. It ingests `.pcap` and `.pcapng` capture files and delivers deep protocol analysis, anomaly detection, and structured reporting — entirely from a CLI.

---

## Features

### Protocol Analysis
- **Full OSI coverage**: Layers 2–7 with per-protocol deep inspection
- **TCP**: flag analysis, stream tracking, port statistics
- **UDP**: port distribution, conversation mapping
- **IP**: TTL analysis, fragmentation, protocol distribution
- **ICMP**: type/code decoding, error tracking
- **DNS**: query/response correlation, top domain ranking
- **HTTP**: method tracking, host analysis, user-agent monitoring
- **DHCP**: message type distribution, lease monitoring

### Security Detection
- Port scan detection (SYN-based heuristics)
- Anomaly scoring via statistical outlier analysis
- Custom regex pattern matching across all traffic
- Top talkers analysis by byte volume

### Advanced Analytics (Pandas)
- DataFrame-based aggregation for large captures
- Time series: traffic volume over time, burst detection
- Statistical summary: mean, median, stddev, min/max packet size
- Excel export with multiple worksheets
- JSON export for integration with external tools

### User Interface
- Interactive hierarchical CLI menu
- Real-time progress bar with ETA
- OSI layer overview for small captures
- Clean text output — no external dependencies for display

---

## Requirements

- Python 3.8 or higher
- `tshark` installed and available on `$PATH` (Wireshark CLI toolkit)
- 4 GB RAM minimum (8 GB recommended for captures > 500 MB)

---

## Installation

```bash
git clone https://github.com/joscalion04/snypshark.git
cd snypshark

python -m venv venv
source venv/bin/activate       # Linux / macOS
# venv\Scripts\activate        # Windows

pip install -r requirements.txt
```

For development:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

---

## Installation

### Quick install (Debian / Ubuntu / Arch / Manjaro)

```bash
git clone https://github.com/joscalion04/snypshark.git
cd snypshark
./install.sh
```

The installer:
1. Detects your distro and installs `python3`, `python3-pip`, `python3-venv`, and `tshark` / `wireshark-cli` via `apt` or `pacman`
2. Creates a virtual environment in `./venv/`
3. Installs the Python package and all dependencies
4. Registers the `snypshark` command at `/usr/local/bin/snypshark`
5. Adds your user to the `wireshark` group (required for non-root capture)

**Note:** Re-login or run `newgrp wireshark` for group membership to take effect.

### User-local install (no sudo for command link)

```bash
./install.sh --user
```

Installs the command to `~/.local/bin/snypshark`. Ensure `~/.local/bin` is in your `$PATH`.

### Uninstall

```bash
./install.sh --uninstall
```

### Manual install (any platform)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Then run with `python main.py` or `snypshark` (if the venv bin is on your PATH).

---

## Usage

```bash
snypshark FILE [options]
```

### Options

| Flag | Description |
|------|-------------|
| `--batch` | Non-interactive: print structured report and exit |
| `--protocols LIST` | Comma-separated protocols to load (default: all) |
| `--pandas` | Enable advanced pandas analysis |
| `--security` | Include security findings section in batch report |
| `--osi` | Show OSI layer overview regardless of capture size |
| `--export FORMAT` | Export results: `excel`, `json`, or `both` |
| `--output NAME` | Base filename for exports (default: `analysis`) |
| `--top N` | Top-N items in batch reports (default: 10) |
| `--quiet` | Suppress progress output |
| `--version` | Show version and exit |
| `--help` | Show help and exit |

Available protocols: `tcp`, `udp`, `ip`, `icmp`, `dns`, `http`, `dhcp`, `patterns`, `pandas`

### Examples

```bash
# Interactive analysis (default)
snypshark capture.pcap

# Print full report and exit — no interaction
snypshark capture.pcap --batch

# Security-focused batch report with JSON export
snypshark capture.pcap --batch --security --pandas --export json --output report

# Only load TCP and DNS processors, top 20 items
snypshark capture.pcap --protocols tcp,dns --batch --top 20

# Export to both Excel and JSON after interactive session
snypshark capture.pcap --pandas --export both --output my_analysis

# Fully automated pipeline (CI/scripting)
snypshark capture.pcap --batch --quiet --pandas --export json --output out
```

---

## User Manual

### 1. Launching the tool

```bash
snypshark capture.pcap          # interactive (default)
snypshark capture.pcap --batch  # non-interactive, prints report and exits
```

If installed without the CLI entry point, use `python main.py` from the project root.

### 2. File selection (interactive mode only)

```
FILE SELECTION
==================================================
Enter path to .pcap/.pcapng file:
```

Enter the full path to your capture file. You can drag and drop the file into the terminal on most systems. The tool validates the file before proceeding and reports its size.

Accepted formats: `.pcap`, `.pcapng`. Files without these extensions will prompt for confirmation.

### 3. Analysis startup

The tool counts packets, reports system resources (CPU cores, RAM), and — for captures under 10 000 packets — prints an OSI layer overview showing the first few packets with their protocol chains and a layer frequency table.

Each protocol processor is then registered (TCP, IP, ICMP, DNS, HTTP, DHCP, UDP, Pattern, Pandas) and the parallel analysis loop starts. A live progress bar shows completion percentage and estimated time remaining.

After the analysis loop completes, you are asked:

```
Enable advanced pandas analysis? (y/N):
```

Answering `y` builds pandas DataFrames from the collected data and prints a summary (packet count, byte volume, unique IPs, anomalies). This step is optional and adds memory overhead; skip it for quick inspections.

### 4. Interactive menu

After analysis, the main menu is presented:

```
MAIN ANALYSIS MENU
============================================================
  1. Packet Statistics
  2. Protocol Analysis
  3. Security Findings
  4. Advanced Analysis
  5. Export Results
  0. Exit
============================================================
Select an option (0-5):
```

Each option opens a submenu. Navigate by entering the number shown. In any submenu, the highest-numbered option returns to the parent menu. Typing `b` at the "Press Enter to continue" prompt also returns.

#### 4.1 Packet Statistics

| Option | Description |
|--------|-------------|
| Total packets | Total number of packets processed |
| Protocol distribution | Top-N protocol names by frequency |
| Source IPs | Top-N source IP addresses by packet count |
| TTL analysis | Most common TTL values observed |

For "top-N" views, you are prompted to enter how many items to display (default: shown in brackets).

#### 4.2 Protocol Analysis

| Submenu | Contents |
|---------|----------|
| TCP | Flag distribution (SYN, ACK, FIN, RST, etc.), unique stream count |
| UDP | Top port flows (src->dst), conversation count |
| DNS | Query list, top queried domains, response count |
| HTTP | Method distribution (GET, POST, ...), top hosts |
| ICMP | Type/code distribution |

#### 4.3 Security Findings

| Option | Description |
|--------|-------------|
| Pattern matches | Keyword hits from the regex pattern engine |
| Anomalies detected | Total anomaly count and breakdown by type |
| Port scan detection | Count of heuristically flagged SYN-only packets |

> **Note:** Pattern matching and anomaly data require the pandas analysis pass to have run. If skipped, these options report unavailability.

#### 4.4 Advanced Analysis (Pandas)

Available only if the pandas analysis pass was enabled at startup.

| Option | Description |
|--------|-------------|
| Security Report | Full overview: packets, bytes, IPs, anomaly breakdown |
| Top Talkers | Top 10 source IPs ranked by byte volume |
| Protocol Analysis | Protocol distribution with percentage share |
| Anomalies | Anomaly type breakdown and top offending IPs |
| DNS Analysis | Query count, unique domains, top queried names |
| HTTP Analysis | Request count, method distribution, top hosts |
| Timeline Analysis | Peak traffic timestamp, max packets/min, max bytes/min |

#### 4.5 Export Results

| Option | Output |
|--------|--------|
| Export to Excel | Multi-sheet `.xlsx`: Packets, Connections, DNS, HTTP, Anomalies, Summary |
| Export to JSON | Single `.json` with the full security report structure |

You are prompted for a filename. If none is entered, a default name is used (`network_analysis.xlsx` or `security_report.json`).

### 5. Interrupting analysis

Press `Ctrl+C` at any time to interrupt. The tool exits cleanly with a goodbye message.

---

## Testing

```bash
pytest                          # run all tests
pytest --cov=analyzer           # with coverage report
pytest tests/test_analyzer.py -v
```

---

## Project Structure

```
snypshark/
├── main.py                     # Entry point
│
├── analyzer/                   # Main package
│   ├── core/                   # Packet engine, parallel processing, processor registry
│   ├── processors/             # Per-protocol analyzers (TCP, UDP, IP, ICMP, DNS, HTTP, DHCP, Pattern)
│   ├── analytics/              # Pandas-based analytics (security, statistical, timeline)
│   ├── ui/                     # CLI interface, menus, progress bar, OSI visualizer
│   ├── utils/                  # File, performance, validation, and export helpers
│   └── config/                 # Settings, constants, and performance tuning
│
├── tests/                      # Pytest suite
│
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
└── LICENSE
```

---

## Dependencies

### Runtime
```
pyshark>=0.5.0
pandas>=1.5.0
numpy>=1.24.0
openpyxl>=3.1.0
colorama>=0.4.0
tqdm>=4.65.0
python-dateutil>=2.8.0
psutil>=5.9.0
```

### Development
```
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0
black>=23.0.0
flake8>=6.0.0
isort>=5.12.0
mypy>=1.0.0
pre-commit>=3.0.0
```

---

## Roadmap

- [ ] Real-time capture support (live interface sniffing)
- [ ] Custom rule engine for threat detection
- [ ] Integration with threat intelligence feeds
- [ ] Machine learning anomaly scoring
- [ ] REST API for automated analysis pipelines

---

## AI Usage Policy

This project permits the use of AI-assisted development tools (code generation, refactoring suggestions, documentation drafting). However, their use is subject to the following non-negotiable conditions.

### What is allowed

- Using AI tools to accelerate boilerplate, explore approaches, or draft initial implementations.
- Using AI to assist with documentation, commit messages, and test scaffolding.
- Using AI to review or explain existing code during a PR process.

### What is required

Every piece of AI-generated code that enters this repository must pass a **mandatory human technical review** before being committed. This means:

- The contributor must read, understand, and be able to explain every line they submit.
- The code must be validated against the project's existing architecture, patterns, and style — not just accepted because it compiles or passes tests.
- Logic correctness, edge cases, security implications, and performance impact are the contributor's responsibility, not the AI's.

### What is not acceptable

- Committing large AI-generated blocks without reviewing them line by line ("vibecoding").
- Using AI output as a substitute for understanding the problem.
- Hiding AI authorship: if a significant portion of a contribution was AI-generated, note it in the PR description.
- Accepting AI-generated security-sensitive code (packet parsing, anomaly detection, export logic) without explicit scrutiny.

### The underlying principle

AI is a development tool, not a developer. The human contributor is the author of record and bears full responsibility for what they submit. When in doubt, write it yourself.

---

## Contributing

Contributions are welcome. See [COMMIT_GUIDELINES.md](COMMIT_GUIDELINES.md) for commit conventions.

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit following project conventions
4. Push and open a Pull Request

---

## Resources

- [Documentation Wiki](https://deepwiki.com/Joscalion04/Snypshark)
- [Architecture Diagram](https://www.mermaidchart.com/app/projects/a663c48d-527d-4c70-b522-0ad40306e1dc/diagrams/973efd02-85fd-4319-9870-c246cc08adad/version/v0.1/edit)
- [Issue Tracker](https://github.com/joscalion04/snypshark/issues)
- [Discussions](https://github.com/joscalion04/snypshark/discussions)

---

## License

MIT — see [LICENSE](LICENSE).

## Authors

**Joseph Leon (Joscalion04)** — initial development and maintenance
