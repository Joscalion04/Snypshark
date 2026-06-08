#!/usr/bin/env python3
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'analyzer'))

from core.analyzer import PCAPAnalyzer
from processors.tcp_processor import TCPProcessor
from processors.ip_processor import IPProcessor
from processors.icmp_processor import ICMPProcessor
from processors.dns_processor import DNSProcessor
from processors.http_processor import HTTPProcessor
from processors.dhcp_processor import DHCPProcessor
from processors.udp_processor import UDPProcessor
from processors.pattern_processor import PatternProcessor
from analytics.pandas_analyzer import PandasAnalyzer
from ui.cli_interface import InteractiveMenu
from ui.osi_visualizer import OSIVisualizer
from ui.progress_renderer import ProgressBar
from utils.file_utils import validate_file_path, get_file_size
from utils.performance_utils import optimize_memory_settings, get_system_info

BANNER = """
    +-------------------------------------------------+
    |                                                 |
    |              SNYPSHARK ANALYZER                 |
    |           Network Forensic Tool v1.0            |
    |                                                 |
    +-------------------------------------------------+
"""


def get_file_path() -> str:
    print("FILE SELECTION")
    print("=" * 50)

    while True:
        file_path = input("Enter path to .pcap/.pcapng file: ").strip()

        if not file_path:
            print("Please enter a file path.")
            continue

        file_path = os.path.expanduser(os.path.expandvars(file_path))

        if not validate_file_path(file_path):
            print("File not found or inaccessible.")
            print("Tip: You can drag and drop the file into the terminal.")
            continue

        if not file_path.lower().endswith(('.pcap', '.pcapng')):
            print("Warning: File extension is not .pcap or .pcapng")
            confirm = input("Continue anyway? (y/N): ").strip().lower()
            if confirm != 'y':
                continue

        _, size_str = get_file_size(file_path)
        file_name = os.path.basename(file_path)

        print(f"File : {file_name}")
        print(f"Size : {size_str}")
        print("=" * 50)

        return file_path


def _show_pandas_summary(pandas_analyzer) -> None:
    if not pandas_analyzer:
        return

    report = pandas_analyzer.generate_security_report()

    print("\n" + "=" * 60)
    print("PANDAS ANALYSIS SUMMARY")
    print("=" * 60)

    overview = report.get('overview', {})
    print(f"Total packets : {overview.get('total_packets', 0):,}")
    print(f"Total bytes   : {overview.get('total_bytes', 0):,}")
    print(f"Unique IPs    : {overview.get('unique_ips', 0)}")
    print(f"Duration      : {overview.get('time_duration', 'N/A')}")

    anomalies = report.get('anomalies_detected', {})
    if anomalies.get('total_anomalies', 0) > 0:
        print(f"Anomalies     : {anomalies['total_anomalies']}")
        for anomaly, count in anomalies.get('anomaly_types', {}).items():
            print(f"  {anomaly}: {count}")

    print("=" * 60)


def analyze_file(file_path: str):
    print("\nSTARTING ANALYSIS")
    print("=" * 50)

    optimize_memory_settings()

    print("Counting packets...")
    total_packets = PCAPAnalyzer.count_packets(file_path)

    if total_packets == 0:
        print("No packets found in capture.")
        return None, None, None

    print(f"Total packets : {total_packets:,}")

    system_info = get_system_info()
    if system_info:
        print(f"CPU cores     : {system_info.get('cpu_count', 'N/A')}")
        print(f"Memory        : {system_info.get('total_memory_gb', 0):.1f} GB")

    if total_packets < 10000:
        print("\nOSI LAYER OVERVIEW")
        print("-" * 30)
        OSIVisualizer.analyze(file_path, sample_size=3)

    analyzer = PCAPAnalyzer(file_path)

    processors = {
        'tcp':      TCPProcessor(),
        'ip':       IPProcessor(),
        'icmp':     ICMPProcessor(),
        'dns':      DNSProcessor(),
        'http':     HTTPProcessor(),
        'dhcp':     DHCPProcessor(),
        'udp':      UDPProcessor(),
        'patterns': PatternProcessor(),
        'pandas':   PandasAnalyzer(),
    }

    for name, processor in processors.items():
        analyzer.add_processor(processor)
        print(f"Loaded {name.upper()} processor")

    print(f"\nAnalyzing {total_packets:,} packets...")
    bar = ProgressBar(total=total_packets, length=40, prefix="Progress")

    start_time = time.time()
    analyzer.analyze(progress_callback=bar.update)
    bar.finish()

    elapsed = time.time() - start_time
    print(f"Completed in {elapsed:.2f}s  ({total_packets / elapsed:.0f} packets/s)")

    use_pandas = input("\nEnable advanced pandas analysis? (y/N): ").strip().lower() == 'y'

    if use_pandas:
        print("\nBUILDING ADVANCED ANALYSIS")
        print("-" * 30)
        pandas_analyzer = processors['pandas']
        pandas_analyzer.build_dataframes()
        _show_pandas_summary(pandas_analyzer)
    else:
        pandas_analyzer = None

    return analyzer, processors, pandas_analyzer


def main() -> None:
    try:
        print(BANNER)
        file_path = get_file_path()
        analyzer, processors, _ = analyze_file(file_path)

        if analyzer is None:
            sys.exit(1)

        print("\n" + "=" * 60)
        print("INTERACTIVE ANALYSIS MENU")
        print("=" * 60)

        menu = InteractiveMenu(analyzer, processors)
        menu.display_menu()

    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\n" + "=" * 60)
        print("Snypshark Analyzer — session ended.")
        print("=" * 60)


if __name__ == "__main__":
    main()
