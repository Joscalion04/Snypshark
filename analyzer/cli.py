#!/usr/bin/env python3
"""
Snypshark CLI entry point.
Registered as the `snypshark` command via setup.py / pyproject.toml.
"""
import argparse
import json
import os
import sys
import time

# ------------------------------------------------------------------
# Path bootstrap — must run before any local imports.
# When invoked as a console script, Python has the project root on
# sys.path, so `analyzer` is an importable package. Inserting the
# analyzer/ directory itself also allows existing internal imports
# (e.g. "from core.analyzer import ...") to resolve without changes.
# ------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

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

VERSION = "0.1.0"

ALL_PROTOCOLS = ("tcp", "udp", "ip", "icmp", "dns", "http", "dhcp", "patterns", "pandas")

_PROCESSOR_MAP = {
    "tcp":      TCPProcessor,
    "ip":       IPProcessor,
    "icmp":     ICMPProcessor,
    "dns":      DNSProcessor,
    "http":     HTTPProcessor,
    "dhcp":     DHCPProcessor,
    "udp":      UDPProcessor,
    "patterns": PatternProcessor,
    "pandas":   PandasAnalyzer,
}


# ------------------------------------------------------------------
# Argument parser
# ------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snypshark",
        description="Snypshark — PCAP network traffic analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""\
available protocols:
  {", ".join(ALL_PROTOCOLS)}

examples:
  snypshark capture.pcap
  snypshark capture.pcap --batch
  snypshark capture.pcap --batch --security --export json
  snypshark capture.pcap --protocols tcp,dns,http --top 20
  snypshark capture.pcap --pandas --export excel --output report
  snypshark capture.pcap --batch --pandas --export both --output analysis
  snypshark capture.pcap --osi --quiet --batch --export json
""",
    )

    parser.add_argument(
        "file",
        metavar="FILE",
        help="path to .pcap or .pcapng capture file",
    )

    # -- Mode --
    parser.add_argument(
        "--batch",
        action="store_true",
        help="non-interactive: print structured report and exit",
    )

    # -- Protocol selection --
    parser.add_argument(
        "--protocols",
        metavar="LIST",
        default=",".join(ALL_PROTOCOLS),
        help=(
            "comma-separated list of protocols to load "
            f"(default: all). available: {', '.join(ALL_PROTOCOLS)}"
        ),
    )

    # -- Analysis options --
    parser.add_argument(
        "--pandas",
        action="store_true",
        help="enable advanced pandas analysis (automatically enabled by --export)",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help="include security findings in batch report",
    )
    parser.add_argument(
        "--osi",
        action="store_true",
        help="show OSI layer overview regardless of capture size",
    )

    # -- Output --
    parser.add_argument(
        "--export",
        choices=["excel", "json", "both"],
        metavar="FORMAT",
        help="export results after analysis: excel | json | both (requires --pandas)",
    )
    parser.add_argument(
        "--output",
        metavar="NAME",
        default="analysis",
        help="base filename for exports (default: analysis)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=10,
        metavar="N",
        help="top-N items in batch reports (default: 10)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="suppress progress output (still prints final report in --batch mode)",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"snypshark {VERSION}",
    )

    return parser


# ------------------------------------------------------------------
# Batch report
# ------------------------------------------------------------------

def _divider(char: str = "-", width: int = 50) -> str:
    return char * width


def _section(title: str) -> None:
    print(f"\n{title}")
    print(_divider())


def run_batch_report(analyzer, processors: dict, args: argparse.Namespace) -> None:
    top = args.top

    _section("PACKET STATISTICS")
    print(f"  Total packets  : {analyzer.stats['total_packets']:,}")

    ip = processors.get("ip")
    if ip:
        print(f"  Unique IPs     : {ip.get_unique_ip_count()}")

    proto_counter = analyzer.stats.get("protocol_counter")
    if proto_counter:
        total = sum(proto_counter.values()) or 1
        print(f"\n  Top {top} protocols:")
        for proto, count in proto_counter.most_common(top):
            pct = count / total * 100
            print(f"    {proto:<14} : {count:>8,}  ({pct:5.1f}%)")

    # TCP
    tcp = processors.get("tcp")
    if tcp:
        _section("TCP ANALYSIS")
        print(f"  Streams        : {tcp.get_stream_count()}")
        flags = sorted(tcp.get_flag_counts().items(), key=lambda x: -x[1])
        for flag, count in flags[:top]:
            print(f"  {flag:<16} : {count:,}")

    # UDP
    udp = processors.get("udp")
    if udp:
        stats = udp.get_stats()
        _section("UDP ANALYSIS")
        print(f"  Unique ports   : {stats['unique_ports']}")
        print(f"  Conversations  : {stats['conversation_count']}")
        print(f"  Top {top} port flows:")
        for flow, count in list(stats["top_ports"].items())[:top]:
            print(f"    {flow}: {count}")

    # DNS
    dns = processors.get("dns")
    if dns:
        stats = dns.get_stats()
        _section("DNS ANALYSIS")
        print(f"  Total queries  : {stats['total_queries']}")
        print(f"  Unique queries : {stats['unique_queries']}")
        if stats.get("top_queries"):
            print(f"  Top {top} domains:")
            for domain, count in list(stats["top_queries"].items())[:top]:
                print(f"    {domain}: {count}")

    # HTTP
    http = processors.get("http")
    if http:
        stats = http.get_stats()
        _section("HTTP ANALYSIS")
        print(f"  Total requests : {stats['total_requests']}")
        for method, count in stats.get("methods", {}).items():
            print(f"  {method:<10} : {count}")
        if stats.get("hosts"):
            print(f"  Top {top} hosts:")
            for host, count in list(stats["hosts"].items())[:top]:
                print(f"    {host}: {count}")

    # ICMP
    icmp = processors.get("icmp")
    if icmp:
        stats = icmp.get_stats()
        if stats["type_distribution"]:
            _section("ICMP ANALYSIS")
            for icmp_type, count in stats["type_distribution"].items():
                print(f"  Type {icmp_type:<3} : {count}")

    # DHCP
    dhcp = processors.get("dhcp")
    if dhcp:
        stats = dhcp.get_stats()
        if stats["total_messages"] > 0:
            _section("DHCP ANALYSIS")
            print(f"  Total messages : {stats['total_messages']}")
            print(f"  Unique types   : {stats['unique_types']}")

    # Security
    if args.security:
        _section("SECURITY FINDINGS")

        pat = processors.get("patterns")
        if pat:
            pat_stats = pat.get_stats()
            print(f"  Pattern matches: {pat_stats['total_matches']}")
            for pattern, count in sorted(
                pat_stats["pattern_matches"].items(), key=lambda x: -x[1]
            )[:top]:
                print(f"    {pattern}: {count}")

        pa = processors.get("pandas")
        if pa and pa.df_anomalies is not None:
            report = pa.generate_security_report()
            anomalies = report.get("anomalies_detected", {})
            print(f"  Total anomalies: {anomalies.get('total_anomalies', 0)}")
            for atype, count in anomalies.get("anomaly_types", {}).items():
                print(f"    {atype}: {count}")
        elif not pa:
            print("  [NOTE] Run with --security --pandas for anomaly detection.")

    # Pandas summary (always shown if pandas was loaded)
    pa = processors.get("pandas")
    if pa and pa.df_packets is not None:
        _section("ADVANCED ANALYSIS SUMMARY")
        report = pa.generate_security_report()
        overview = report.get("overview", {})
        print(f"  Total bytes    : {overview.get('total_bytes', 0):,}")
        print(f"  Avg pkt size   : {overview.get('avg_packet_size', 0):.2f} bytes")
        print(f"  Duration       : {overview.get('time_duration', 'N/A')}")
        top_talkers = report.get("top_talkers", [])[:top]
        if top_talkers:
            print(f"\n  Top {top} talkers by bytes:")
            for i, t in enumerate(top_talkers, 1):
                print(
                    f"    {i:2}. {t.get('src_ip', 'N/A'):<18}"
                    f" {t.get('total_bytes', 0):>12,} bytes"
                )


# ------------------------------------------------------------------
# Export
# ------------------------------------------------------------------

def do_export(processors: dict, args: argparse.Namespace) -> None:
    pa = processors.get("pandas")
    if not pa:
        print("[WARNING] Pandas analyzer not loaded; export skipped.")
        return

    fmt = args.export
    base = args.output

    if fmt in ("excel", "both"):
        filename = f"{base}.xlsx"
        try:
            pa.export_to_excel(filename)
            print(f"Exported: {filename}")
        except Exception as e:
            print(f"[ERROR] Excel export failed: {e}")

    if fmt in ("json", "both"):
        filename = f"{base}.json"
        try:
            report = pa.generate_security_report()
            with open(filename, "w") as f:
                json.dump(report, f, indent=2, default=str)
            print(f"Exported: {filename}")
        except Exception as e:
            print(f"[ERROR] JSON export failed: {e}")


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    file_path = os.path.expanduser(os.path.expandvars(args.file))

    if not validate_file_path(file_path):
        print(f"[ERROR] File not found or not readable: {file_path}")
        sys.exit(1)

    if not file_path.lower().endswith((".pcap", ".pcapng")):
        print(f"[WARNING] Unexpected file extension: {file_path}")

    # --export implies --pandas
    if args.export:
        args.pandas = True

    # Resolve requested protocol set
    requested = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    unknown = [p for p in requested if p not in ALL_PROTOCOLS]
    if unknown:
        print(f"[ERROR] Unknown protocols: {', '.join(unknown)}")
        print(f"        Available: {', '.join(ALL_PROTOCOLS)}")
        sys.exit(1)

    if args.pandas and "pandas" not in requested:
        requested.append("pandas")

    # Header
    _, size_str = get_file_size(file_path)
    if not args.quiet:
        print(f"Snypshark Analyzer v{VERSION}")
        print("=" * 50)
        print(f"File     : {os.path.basename(file_path)} ({size_str})")
        print("Counting packets...")

    total_packets = PCAPAnalyzer.count_packets(file_path)

    if total_packets == 0:
        print("[ERROR] No packets found in capture.")
        sys.exit(1)

    if not args.quiet:
        print(f"Packets  : {total_packets:,}")
        sys_info = get_system_info()
        if sys_info:
            print(
                f"System   : {sys_info.get('cpu_count', '?')} cores"
                f" / {sys_info.get('total_memory_gb', 0):.1f} GB RAM"
            )

    # OSI overview
    show_osi = args.osi or (total_packets < 10_000 and not args.quiet and not args.batch)
    if show_osi:
        print("\nOSI LAYER OVERVIEW")
        print("-" * 30)
        OSIVisualizer.analyze(file_path, sample_size=3)

    # Build processors
    optimize_memory_settings()
    processors = {name: _PROCESSOR_MAP[name]() for name in requested}

    analyzer = PCAPAnalyzer(file_path)
    for processor in processors.values():
        analyzer.add_processor(processor)

    if not args.quiet:
        active = ", ".join(requested)
        print(f"\nProcessors : {active}")

    # Analysis
    if args.quiet:
        analyzer.analyze()
    else:
        bar = ProgressBar(total=total_packets, length=40, prefix="Progress")
        start = time.time()
        analyzer.analyze(progress_callback=bar.update)
        bar.finish()
        elapsed = time.time() - start
        print(f"Completed  : {elapsed:.2f}s  ({total_packets / elapsed:.0f} pkt/s)")

    # Pandas dataframes (built post-loop)
    pa = processors.get("pandas")
    if pa:
        if not args.quiet:
            print("Building dataframes...")
        pa.build_dataframes()

    # Output mode
    if args.batch:
        run_batch_report(analyzer, processors, args)
    else:
        print("\n" + "=" * 60)
        print("INTERACTIVE ANALYSIS MENU")
        print("=" * 60)
        menu = InteractiveMenu(analyzer, processors)
        menu.display_menu()

    # Export (runs regardless of interactive/batch mode)
    if args.export:
        do_export(processors, args)


if __name__ == "__main__":
    main()
