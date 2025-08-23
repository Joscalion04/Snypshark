# 🕵️‍♂️ PCAP Network Traffic Analyzer – Snypshark

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Snypshark is a **command-line Python application** for analyzing network capture files (`.pcap` / `.pcapng`). It provides **OSI layer analysis**, **anomaly detection**, and plans for **advanced data analytics** and **visual dashboards**.

---

## Features

### 📊 OSI Layer Analysis
- Detects and displays OSI layers for each packet (Ethernet, IP, TCP/UDP, ICMP, DNS, HTTP, HTTPS, ARP, DHCP, etc.)
- Provides statistics on protocol distribution across the capture
- Visualizes sample packets with hierarchical layer breakdowns
- Future support: pandas-based analysis for **data aggregation, filtering, and trends**

### 🔍 Anomaly Detection
- Identifies unusual TCP flag combinations (e.g., FIN+SYN+ACK `0x13`)
- Detects non-standard ICMP types (beyond echo request/reply)
- Flags suspicious traffic patterns and malformed packets
- Monitors DNS queries/responses for anomalies
- Future support: Machine-learning-friendly output for anomaly scoring

### 📈 Interactive Reporting
- Menu-driven interface for navigating analysis results
- Protocol frequency charts
- Alerts for suspicious activity
- Future support: HTML dashboard generation with **interactive charts and tables**, fully translatable

### 🌐 Protocol Coverage
Currently supports:
- **Ethernet**: Layer 2 encapsulation
- **ARP**: Address resolution detection
- **IPv4 / IPv6**
- **TCP / UDP**
- **ICMP**: Echo request/reply, type/code validation
- **DNS**: Query/response, suspicious patterns
- **HTTP / HTTPS**
- **DHCP**: Lease monitoring
- Other protocols can be added via `protocol_handlers/`

---

## Project Structure
```
snypshark/
├── analyzer/
│ ├── init.py
│ ├── analyzer.py # Core analysis engine
│ ├── protocol_handlers/ # Protocol-specific processing modules
│ │ ├── tcp_handler.py
│ │ ├── ip_handler.py
│ │ ├── icmp_handler.py
│ │ ├── dns_handler.py
│ │ └── ...
│ ├── utils/ # Helper utilities
│ │ ├── pattern_matcher.py
│ │ └── ...
│ └── ui/ # CLI interface modules
│ ├── menu.py
│ └── osi_layers.py
├── data/ # Sample PCAP files for testing
├── docs/ # Project documentation
├── tests/ # Unit tests
├── main.py # CLI entry point
├── requirements.txt # Python dependencies
├── setup.py # Package configuration
└── README.md
```

## Requirements

- Python 3.8+
- [pyshark](https://github.com/KimiNewt/pyshark)
- [Click](https://click.palletsprojects.com/) (CLI)
- Future: pandas, matplotlib/plotly for enhanced analytics

---

## Installation

```bash
# Clone repository
git clone https://github.com/joscalion04/snypshark.git
cd snypshark

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## Usage
```bash
python main.py path/to/your_capture.pcapng
```

## Example Output
```bash
===== [OSI Layer Overview] =====
Showing first 5 packets as sample:

📦 Packet #1:
ETH -> IP -> TCP -> HTTP

📦 Packet #2:
ETH -> IP -> UDP -> DNS

📊 Layer statistics:
IP: 1432 occurrences
TCP: 982 occurrences
HTTP: 420 occurrences
DNS: 210 occurrences

===== [Anomaly Detection] =====
🚩 Unusual TCP Flags:
SYN+ACK+URG: 3 occurrences
RST+PSH: 2 occurrences

📶 Non-standard ICMP:
Type 13 (Timestamp): 5 packets
```

## Key improvements:
1. Professional header with badges
2. Clear feature breakdown
3. Modern project structure visualization
4. Complete installation/usage instructions
5. Example output section
6. Standard open-source sections (contributing, license, contact)
7. Consistent formatting
8. All technical terms in English

## Roadmap / Future Enhancements
- Expanded protocol coverage (ARP, DHCP, HTTP/HTTPS, TLS, etc.)
- Data analytics with pandas for filtering, aggregation, and time-series analysis
- Graphical reporting using matplotlib or plotly
- Static HTML dashboard generation for shareable reports
- User-configurable alert rules for anomalies
- Localization for multi-language support

## Contributing
- Contributions are welcome!
- Fork the repository
- Create a feature branch (git checkout -b feature/my-feature)
- Commit changes (git commit -m 'Add feature')
- Push to branch (git push origin feature/my-feature)
- Open a Pull Request

## Wiki
 - https://deepwiki.com/Joscalion04/Snypshark

## Author:
 - Joseph Leon (Joscalion04)
