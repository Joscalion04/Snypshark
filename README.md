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

## Usage

```bash
python main.py
```

---

## User Manual

### 1. Launching the tool

Run `python main.py` from the project root. The banner prints and the tool enters file selection mode.

### 2. File selection

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
