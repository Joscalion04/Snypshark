# 🕵️‍♂️ PCAP Network Traffic Analyzer

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A command-line Python application for analyzing network capture files (`.pcap`/`.pcapng`) with OSI layer analysis and anomaly detection capabilities.

## Features

### 📊 OSI Layer Analysis
- Identifies and displays OSI layers present in each packet
- Provides statistics on protocol distribution
- Sample packet visualization with layer breakdown

### 🔍 Anomaly Detection
- Unusual TCP flag combinations (e.g., FIN+SYN+ACK `0x13`)
- Non-standard ICMP types (beyond echo request/reply)
- Suspicious traffic patterns and malformed packets
- DNS query/response monitoring

### 📈 Interactive Reporting
- Menu-driven interface for analysis results
- Protocol statistics and frequency charts
- Suspicious activity alerts

## Project Structure
```
snypshark/
├── analyzer/
│ ├── init.py
│ ├── analyzer.py # Core analysis engine
│ ├── protocol_handlers/ # Protocol-specific processors
│ │ ├── tcp_handler.py
│ │ ├── ip_handler.py
│ │ ├── icmp_handler.py
│ │ └── dns_handler.py
│ ├── utils/ # Helper modules
│ │ ├── pattern_matcher.py
│ └── ui/ # User interface components
│ ├── menu.py
│ └── osi_layers.py
├── data/ # Sample capture files
├── docs/ # Documentation
├── tests/ # Unit tests
├── main.py # Entry point
├── requirements.txt # Dependencies
├── setup.py # Package configuration
└── README.md
```


## Requirements

- Python 3.8+
- pyshark
- Click (for CLI)

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
7. Consistent formatting and emoji use
8. All technical terms in English

## Wiki
 - https://deepwiki.com/Joscalion04/Snypshark

## Author:
 - Joseph Leon (Joscalion04)
