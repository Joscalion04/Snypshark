from typing import Any, Dict, Optional
import json
import os

from analytics.pandas_analyzer import PandasAnalyzer


class InteractiveMenu:
    def __init__(self, analyzer, processors):
        self.analyzer = analyzer
        self.processors = processors

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def _header(self, title: str) -> None:
        print(f"\n{title}")
        print("-" * 50)

    def _clear_screen(self) -> None:
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except Exception:
            print("\n" * 50)

    def _ask_top(self, default: int = 5) -> int:
        try:
            raw = input(f"How many items to show? [{default}]: ").strip()
            return max(1, min(100, int(raw))) if raw else default
        except ValueError:
            return default

    # ------------------------------------------------------------------
    # Main menu
    # ------------------------------------------------------------------

    def display_menu(self) -> None:
        options = {
            '1': ("Packet Statistics",    self._packet_stats_menu),
            '2': ("Protocol Analysis",    self._protocol_analysis_menu),
            '3': ("Security Findings",    self._security_menu),
            '4': ("Advanced Analysis",    self._pandas_submenu),
            '5': ("Export Results",       self._export_menu),
            '0': ("Exit",                 None),
        }

        while True:
            self._clear_screen()
            print("\n" + "=" * 60)
            print("MAIN ANALYSIS MENU")
            print("=" * 60)
            for key, (desc, _) in options.items():
                print(f"  {key}. {desc}")
            print("=" * 60)

            choice = input("\nSelect an option (0-5): ").strip()

            if choice == '0':
                print("\nGoodbye.")
                break

            action = options.get(choice)
            if not action:
                input("\n[ERROR] Invalid option. Press Enter to continue...")
                continue

            try:
                result = action[1]()
                if result is not None:
                    print(f"\n{result}")
                input("\nPress Enter to return to main menu...")
            except Exception as e:
                print(f"\n[ERROR] {e}")
                input("Press Enter to continue...")

    # ------------------------------------------------------------------
    # Submenus
    # ------------------------------------------------------------------

    def _packet_stats_menu(self) -> None:
        options = {
            '1': ("Total packets",        self._get_total_packets),
            '2': ("Protocol distribution", self._get_common_protocols),
            '3': ("Source IPs",           self._get_source_ips),
            '4': ("TTL analysis",         self._get_ttls),
            '5': ("Back",                 None),
        }
        return self._run_submenu(options, "PACKET STATISTICS")

    def _protocol_analysis_menu(self) -> None:
        options = {
            '1': ("TCP Analysis",         self._tcp_submenu),
            '2': ("UDP Analysis",         self._get_udp_ports),
            '3': ("DNS Analysis",         self._dns_submenu),
            '4': ("HTTP Analysis",        self._http_submenu),
            '5': ("ICMP Analysis",        self._get_icmp_types),
            '6': ("Back",                 None),
        }
        return self._run_submenu(options, "PROTOCOL ANALYSIS")

    def _security_menu(self) -> None:
        options = {
            '1': ("Pattern matches",      self._get_patterns),
            '2': ("Anomalies detected",   self._get_anomalies_summary),
            '3': ("Port scan detection",  self._get_port_scan_info),
            '4': ("Back",                 None),
        }
        return self._run_submenu(options, "SECURITY FINDINGS")

    def _export_menu(self) -> None:
        options = {
            '1': ("Export to Excel",      self._export_to_excel),
            '2': ("Export to JSON",       self._export_to_json),
            '3': ("Back",                 None),
        }
        return self._run_submenu(options, "EXPORT RESULTS")

    def _tcp_submenu(self) -> None:
        options = {
            '1': ("TCP Flags",            self._get_tcp_flags),
            '2': ("TCP Streams",          self._get_tcp_streams),
            '3': ("Back",                 None),
        }
        return self._run_submenu(options, "TCP ANALYSIS")

    def _dns_submenu(self) -> None:
        options = {
            '1': ("DNS Queries",          self._get_dns_queries),
            '2': ("DNS Responses",        self._get_dns_responses),
            '3': ("Back",                 None),
        }
        return self._run_submenu(options, "DNS ANALYSIS")

    def _http_submenu(self) -> None:
        http = self.processors.get('http')
        if not http:
            return "HTTP data not available."
        options = {
            '1': ("HTTP Methods",         lambda: self._http_methods(http)),
            '2': ("HTTP Hosts",           lambda: self._http_hosts(http)),
            '3': ("Back",                 None),
        }
        return self._run_submenu(options, "HTTP ANALYSIS")

    def _pandas_submenu(self) -> None:
        pandas_analyzer = self.processors.get('pandas')
        if not pandas_analyzer:
            return "Advanced analysis data not available."
        options = {
            '1': ("Security Report",      lambda: self._pandas_security_report(pandas_analyzer)),
            '2': ("Top Talkers",          lambda: self._pandas_top_talkers(pandas_analyzer)),
            '3': ("Protocol Analysis",    lambda: self._pandas_protocol_analysis(pandas_analyzer)),
            '4': ("Anomalies",            lambda: self._pandas_anomalies(pandas_analyzer)),
            '5': ("DNS Analysis",         lambda: self._pandas_dns_analysis(pandas_analyzer)),
            '6': ("HTTP Analysis",        lambda: self._pandas_http_analysis(pandas_analyzer)),
            '7': ("Timeline Analysis",    lambda: self._pandas_timeline_analysis(pandas_analyzer)),
            '8': ("Back",                 None),
        }
        return self._run_submenu(options, "ADVANCED ANALYSIS")

    def _run_submenu(self, options: dict, title: str) -> Any:
        while True:
            self._clear_screen()
            self._header(title)
            for key, (desc, _) in options.items():
                print(f"  {key}. {desc}")

            choice = input("\nSelect an option: ").strip()
            back_option = str(len(options))

            if choice == back_option:
                return None

            action = options.get(choice)
            if not action:
                print("[ERROR] Invalid option.")
                input("Press Enter to continue...")
                continue

            if action[1] is None:
                return None

            result = action[1]()
            if result is not None:
                print(f"\n{result}")

            print("\n" + "-" * 50)
            cont = input("Press Enter to continue, or 'b' to go back: ").strip().lower()
            if cont == 'b':
                return result

    # ------------------------------------------------------------------
    # Packet stats
    # ------------------------------------------------------------------

    def _get_total_packets(self) -> str:
        return f"Total packets: {self.analyzer.stats['total_packets']:,}"

    def _get_common_protocols(self) -> str:
        n = self._ask_top(10)
        protocols = self.analyzer.stats['protocol_counter'].most_common(n)
        lines = [f"  {i}. {proto}: {count}" for i, (proto, count) in enumerate(protocols, 1)]
        return "Top protocols:\n" + "\n".join(lines)

    def _get_source_ips(self) -> str:
        ip = self.processors.get('ip')
        if not (ip and hasattr(ip, 'ip_source_counter')):
            return "IP source data not available."
        n = self._ask_top(10)
        lines = [f"  {i}. {addr}: {count}" for i, (addr, count) in enumerate(ip.ip_source_counter.most_common(n), 1)]
        return "Top source IPs:\n" + "\n".join(lines)

    def _get_ttls(self) -> str:
        ip = self.processors.get('ip')
        if not (ip and hasattr(ip, 'ttl_histogram')):
            return "TTL data not available."
        n = self._ask_top(8)
        lines = [f"  {i}. TTL {ttl}: {count}" for i, (ttl, count) in enumerate(ip.ttl_histogram.most_common(n), 1)]
        return "TTL distribution:\n" + "\n".join(lines)

    # ------------------------------------------------------------------
    # TCP
    # ------------------------------------------------------------------

    def _get_tcp_flags(self) -> str:
        tcp = self.processors.get('tcp')
        if not (tcp and hasattr(tcp, 'get_flag_counts')):
            return "TCP flag data not available."
        lines = [f"  {flag}: {count}" for flag, count in tcp.get_flag_counts().items()]
        return "TCP flags:\n" + "\n".join(lines)

    def _get_tcp_streams(self) -> str:
        streams = len(self.analyzer.stats.get('tcp_streams', set()))
        return f"Unique TCP streams: {streams}"

    # ------------------------------------------------------------------
    # UDP
    # ------------------------------------------------------------------

    def _get_udp_ports(self) -> str:
        udp = self.processors.get('udp')
        if not (udp and hasattr(udp, 'port_flows')):
            return "UDP port data not available."
        n = self._ask_top(15)
        lines = [f"  {i}. {port}: {count}" for i, (port, count) in enumerate(udp.port_flows.most_common(n), 1)]
        return "Top UDP port flows:\n" + "\n".join(lines)

    # ------------------------------------------------------------------
    # DNS
    # ------------------------------------------------------------------

    def _get_dns_queries(self) -> str:
        dns = self.processors.get('dns')
        if not (dns and hasattr(dns, 'dns_queries')):
            return "DNS query data not available."
        unique = len(set(dns.dns_queries))
        result = f"DNS queries: {len(dns.dns_queries)} (unique: {unique})"
        stats = dns.get_query_stats()
        if stats:
            n = self._ask_top(15)
            top = sorted(stats.items(), key=lambda x: x[1], reverse=True)[:n]
            result += "\nTop queries:\n" + "\n".join(f"  {i}. {q}: {c}" for i, (q, c) in enumerate(top, 1))
        return result

    def _get_dns_responses(self) -> str:
        dns = self.processors.get('dns')
        if not (dns and hasattr(dns, 'dns_responses')):
            return "DNS response data not available."
        unique = len(set(dns.dns_responses))
        return f"DNS responses: {len(dns.dns_responses)} (unique: {unique})"

    # ------------------------------------------------------------------
    # ICMP
    # ------------------------------------------------------------------

    def _get_icmp_types(self) -> str:
        icmp = self.processors.get('icmp')
        if not (icmp and hasattr(icmp, 'icmp_types')):
            return "ICMP data not available."
        lines = [f"  Type {t}: {c}" for t, c in icmp.icmp_types.items()]
        return "ICMP type distribution:\n" + "\n".join(lines)

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _http_methods(self, http) -> str:
        if not hasattr(http, 'methods'):
            return "HTTP method data not available."
        n = self._ask_top(10)
        lines = [f"  {i}. {m}: {c}" for i, (m, c) in enumerate(http.methods.most_common(n), 1)]
        return "HTTP methods:\n" + "\n".join(lines)

    def _http_hosts(self, http) -> str:
        if not hasattr(http, 'hosts'):
            return "HTTP host data not available."
        n = self._ask_top(10)
        lines = [f"  {i}. {h}: {c}" for i, (h, c) in enumerate(http.hosts.most_common(n), 1)]
        return "HTTP hosts:\n" + "\n".join(lines)

    # ------------------------------------------------------------------
    # Patterns / security
    # ------------------------------------------------------------------

    def _get_patterns(self) -> str:
        pat = self.processors.get('patterns')
        if not (pat and hasattr(pat, 'pattern_occurrences')):
            return "Pattern matching data not available."
        patterns = dict(pat.pattern_occurrences)
        if not patterns:
            return "No pattern matches detected."
        lines = [f"  '{p}': {c}" for p, c in sorted(patterns.items(), key=lambda x: x[1], reverse=True)]
        return "Pattern matches:\n" + "\n".join(lines)

    def _get_port_scan_info(self) -> str:
        pa = self.processors.get('pandas')
        if not pa:
            return "Port scan analysis not available."
        report = pa.generate_security_report()
        count = report.get('anomalies_detected', {}).get('anomaly_types', {}).get('possible_port_scan', 0)
        return f"Possible port scan attempts: {count}"

    def _get_anomalies_summary(self) -> str:
        pa = self.processors.get('pandas')
        if not pa:
            return "Anomaly detection not available."
        report = pa.generate_security_report()
        anomalies = report.get('anomalies_detected', {})
        result = f"Total anomalies: {anomalies.get('total_anomalies', 0)}"
        if anomalies.get('anomaly_types'):
            lines = [f"  {a}: {c}" for a, c in anomalies['anomaly_types'].items()]
            result += "\nAnomaly types:\n" + "\n".join(lines)
        return result

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_to_excel(self) -> str:
        pa = self.processors.get('pandas')
        if not pa:
            return "Pandas analyzer not available for export."
        filename = input("Excel filename (e.g. analysis.xlsx): ").strip() or "network_analysis.xlsx"
        if not filename.endswith('.xlsx'):
            filename += '.xlsx'
        try:
            pa.export_to_excel(filename)
            return f"Exported to {filename}"
        except Exception as e:
            return f"[ERROR] Export failed: {e}"

    def _export_to_json(self) -> str:
        pa = self.processors.get('pandas')
        if not pa:
            return "Pandas analyzer not available for export."
        filename = input("JSON filename (e.g. report.json): ").strip() or "security_report.json"
        if not filename.endswith('.json'):
            filename += '.json'
        try:
            report = pa.generate_security_report()
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            return f"Exported to {filename}"
        except Exception as e:
            return f"[ERROR] Export failed: {e}"

    # ------------------------------------------------------------------
    # Pandas report sections
    # ------------------------------------------------------------------

    def _pandas_security_report(self, pa) -> str:
        report = pa.generate_security_report()
        overview = report.get('overview', {})
        anomalies = report.get('anomalies_detected', {})

        lines = [
            "SECURITY REPORT",
            "=" * 50,
            "OVERVIEW:",
            f"  Total packets  : {overview.get('total_packets', 0):,}",
            f"  Total bytes    : {overview.get('total_bytes', 0):,}",
            f"  Unique IPs     : {overview.get('unique_ips', 0)}",
            f"  Duration       : {overview.get('time_duration', 'N/A')}",
            f"  Avg packet size: {overview.get('avg_packet_size', 0):.2f} bytes",
            "",
            "ANOMALIES:",
            f"  Total: {anomalies.get('total_anomalies', 0)}",
        ]
        for a, c in anomalies.get('anomaly_types', {}).items():
            lines.append(f"    {a}: {c}")

        return "\n".join(lines)

    def _pandas_top_talkers(self, pa) -> str:
        top = pa.generate_security_report().get('top_talkers', [])[:10]
        lines = ["TOP TALKERS (by bytes):", "-" * 40]
        for i, t in enumerate(top, 1):
            lines.append(f"  {i:2d}. {t.get('src_ip', 'N/A'):15} : {t.get('total_bytes', 0):,} bytes")
        return "\n".join(lines)

    def _pandas_protocol_analysis(self, pa) -> str:
        protocols = pa.generate_security_report().get('protocol_analysis', {})
        lines = ["PROTOCOL DISTRIBUTION:", "-" * 40]
        for proto, stats in protocols.items():
            if isinstance(stats, dict):
                lines.append(f"  {proto:12} : {stats.get('count', 0):6} packets ({stats.get('percentage', 0):5.1f}%)")
            else:
                lines.append(f"  {proto:12} : {stats}")
        return "\n".join(lines)

    def _pandas_anomalies(self, pa) -> str:
        anomalies = pa.generate_security_report().get('anomalies_detected', {})
        lines = [f"TOTAL ANOMALIES: {anomalies.get('total_anomalies', 0)}"]
        for a, c in anomalies.get('anomaly_types', {}).items():
            lines.append(f"  {a}: {c}")
        for ip, c in anomalies.get('top_offenders', {}).items():
            lines.append(f"  Offender {ip}: {c}")
        return "\n".join(lines)

    def _pandas_dns_analysis(self, pa) -> str:
        dns = pa.generate_security_report().get('dns_analysis', {})
        lines = [
            "DNS ANALYSIS:", "-" * 40,
            f"Total queries  : {dns.get('total_queries', 0)}",
            f"Unique domains : {dns.get('unique_domains', 0)}",
        ]
        if dns.get('top_queried_domains'):
            lines.append("Top domains:")
            for domain, count in list(dns['top_queried_domains'].items())[:10]:
                lines.append(f"  {domain}: {count}")
        return "\n".join(lines)

    def _pandas_http_analysis(self, pa) -> str:
        http = pa.generate_security_report().get('http_analysis', {})
        lines = ["HTTP ANALYSIS:", "-" * 40, f"Total requests: {http.get('total_requests', 0)}"]
        for method, count in http.get('http_methods', {}).items():
            lines.append(f"  {method}: {count}")
        for host, count in list(http.get('top_hosts', {}).items())[:5]:
            lines.append(f"  {host}: {count}")
        return "\n".join(lines)

    def _pandas_timeline_analysis(self, pa) -> str:
        tl = pa.generate_security_report().get('timeline_analysis', {})
        lines = [
            "TIMELINE ANALYSIS:", "-" * 40,
            f"Peak traffic time  : {tl.get('peak_traffic_time', 'N/A')}",
            f"Max packets/min    : {tl.get('max_packets_per_minute', 0)}",
            f"Max bytes/min      : {tl.get('max_bytes_per_minute', 0):,}",
        ]
        return "\n".join(lines)
