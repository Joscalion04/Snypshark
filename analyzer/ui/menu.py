from typing import Any, Dict, Optional
import json
from collections import Counter

class InteractiveMenu:
    """
    UI de consola: muestra métricas y permite consultar detalles.
    Diseño simple, extensible via métodos _get_* por cada procesador.
    """
    def __init__(self, analyzer, processors):
        self.analyzer = analyzer
        self.processors = processors

    def _ask_top(self, default: int = 5) -> int:
        """Pide al usuario el N para top-N; usa default si vacío o inválido."""
        raw = input(f"How many items to show? [default {default}]: ").strip()
        if not raw:
            return default
        try:
            n = int(raw)
            return max(1, min(100, n))
        except ValueError:
            return default

    def display_menu(self):
        options = {
            '1': ("Total packets", self._get_total_packets),
            '2': ("Common protocols (top-N)", self._get_common_protocols),
            '3': ("TCP Flags", self._get_tcp_flags),
            '4': ("TCP Streams (unique count)", self._get_tcp_streams),
            '5': ("Source IPs (top-N)", self._get_source_ips),
            '6': ("Common TTLs/HopLimit (top-N)", self._get_ttls),
            '7': ("Pattern matches", self._get_patterns),
            '8': ("DNS Queries (count/unique)", self._get_dns_queries),
            '9': ("DNS Responses (count/unique)", self._get_dns_responses),
            '10': ("ICMP Types", self._get_icmp_types),
            '11': ("UDP Ports (top-N)", self._get_udp_ports),
            '12': ("HTTP ▶ submenu", self._http_submenu),
            '13': ("DHCP Message Types (top-N)", self._get_dhcp_msgs),
            '14': ("Pandas Analysis ▶ submenu", self._pandas_submenu),
            '0': ("Exit", None),
        }

        while True:
            print("\n==== ANALYSIS MENU ====")
            for key, (desc, _) in options.items():
                print(f"{key}. {desc}")

            choice = input("\n→ Select an option (or '0' to exit): ").strip()
            if choice == '0':
                print("👋 Exiting...")
                break

            action = options.get(choice)
            if not action:
                print("❌ Invalid option. Please try again.")
                continue

            try:
                result = action[1]()
                if result is not None:
                    print(result)
            except Exception as e:
                print(f"⚠️ Error: {str(e)}")

    # --------- simple helpers --------- #
    def _get_total_packets(self):
        return f"📦 Total: {self.analyzer.stats['total_packets']}"

    def _get_common_protocols(self):
        n = self._ask_top(10)
        return f"📊 Protocols: {self.analyzer.stats['protocol_counter'].most_common(n)}"

    def _get_tcp_flags(self):
        tcp_processor = self.processors.get('tcp')
        if hasattr(tcp_processor, 'get_flag_counts'):
            return f"🚩 TCP Flags: {tcp_processor.get_flag_counts()}"
        return "TCP data not available"

    def _get_tcp_streams(self):
        return f"🔄 TCP Streams: {len(self.analyzer.stats.get('tcp_streams', set()))} unique streams"

    def _get_source_ips(self):
        ip_processor = self.processors.get('ip')
        if ip_processor and hasattr(ip_processor, 'ip_source_counter'):
            n = self._ask_top(5)
            return f"📡 Source IPs: {ip_processor.ip_source_counter.most_common(n)}"
        return "IP data not available"

    def _get_ttls(self):
        ip_processor = self.processors.get('ip')
        if ip_processor and hasattr(ip_processor, 'ttl_histogram'):
            n = self._ask_top(5)
            return f"⏳ TTLs/HopLimit: {ip_processor.ttl_histogram.most_common(n)}"
        return "IP data not available"

    def _get_patterns(self):
        pattern_processor = self.processors.get('patterns')
        if pattern_processor and hasattr(pattern_processor, 'pattern_occurrences'):
            return f"🔍 Patterns: {dict(pattern_processor.pattern_occurrences)}"
        return "Pattern data not available"

    def _get_dns_queries(self):
        dns_processor = self.processors.get('dns')
        if dns_processor and hasattr(dns_processor, 'dns_queries'):
            unique = len(set(dns_processor.dns_queries))
            return f"❓ DNS queries: {len(dns_processor.dns_queries)} (unique: {unique})"
        return "DNS data not available"

    def _get_dns_responses(self):
        dns_processor = self.processors.get('dns')
        if dns_processor and hasattr(dns_processor, 'dns_responses'):
            unique = len(set(dns_processor.dns_responses))
            return f"✔️ DNS responses: {len(dns_processor.dns_responses)} (unique: {unique})"
        return "DNS data not available"

    def _get_icmp_types(self):
        icmp_processor = self.processors.get('icmp')
        if icmp_processor and hasattr(icmp_processor, 'icmp_types'):
            return f"📶 ICMP types: {dict(icmp_processor.icmp_types)}"
        return "ICMP data not available"

    def _get_udp_ports(self):
        udp_processor = self.processors.get('udp')
        if udp_processor and hasattr(udp_processor, 'ports'):
            n = self._ask_top(10)
            return f"🎯 UDP Ports: {udp_processor.ports.most_common(n)}"
        return "UDP data not available"

    def _get_dhcp_msgs(self):
        dhcp_processor = self.processors.get('dhcp')
        if dhcp_processor and hasattr(dhcp_processor, 'message_types'):
            n = self._ask_top(5)
            return f"📡 DHCP Messages: {dhcp_processor.message_types.most_common(n)}"
        return "DHCP data not available"

    # --------- HTTP submenu --------- #
    def _http_submenu(self):
        http_processor = self.processors.get('http')
        if not http_processor:
            print("HTTP data not available")
            return

        sub = {
            '1': ("Methods (top-N)", lambda: self._http_methods(http_processor)),
            '2': ("Hosts (top-N)", lambda: self._http_hosts(http_processor)),
            '0': ("Back", None)
        }
        while True:
            print("\n— HTTP Submenu —")
            for k, (d, _) in sub.items():
                print(f"{k}. {d}")
            ch = input("\n→ Select: ").strip()
            if ch == '0':
                break
            if ch in sub:
                res = sub[ch][1]()
                if res is not None:
                    print(res)
            else:
                print("❌ Invalid option.")

    def _http_methods(self, http_processor):
        if hasattr(http_processor, 'methods'):
            n = self._ask_top(5)
            return f"🌐 HTTP Methods: {http_processor.methods.most_common(n)}"
        return "HTTP methods data not available"

    def _http_hosts(self, http_processor):
        if hasattr(http_processor, 'hosts'):
            n = self._ask_top(5)
            return f"🏷️ HTTP Hosts: {http_processor.hosts.most_common(n)}"
        return "HTTP hosts data not available"

    # --------- pandas submenu --------- #
    def _pandas_submenu(self):
        pandas_analyzer = self.processors.get('pandas')
        if not pandas_analyzer:
            print("Pandas analysis data not available")
            return

        sub = {
            '1': ("Security Report", lambda: self._pandas_security_report(pandas_analyzer)),
            '2': ("Top Talkers", lambda: self._pandas_top_talkers(pandas_analyzer)),
            '3': ("Protocol Analysis", lambda: self._pandas_protocol_analysis(pandas_analyzer)),
            '4': ("Anomalies Detected", lambda: self._pandas_anomalies(pandas_analyzer)),
            '5': ("DNS Analysis", lambda: self._pandas_dns_analysis(pandas_analyzer)),
            '6': ("HTTP Analysis", lambda: self._pandas_http_analysis(pandas_analyzer)),
            '7': ("Export to Excel", lambda: self._pandas_export_excel(pandas_analyzer)),
            '0': ("Back", None)
        }
        
        while True:
            print("\n— PANDAS Analysis Submenu —")
            for k, (d, _) in sub.items():
                print(f"{k}. {d}")
            ch = input("\n→ Select: ").strip()
            if ch == '0':
                break
            if ch in sub:
                res = sub[ch][1]()
                if res is not None:
                    print(res)
            else:
                print("❌ Invalid option.")

    def _pandas_security_report(self, pandas_analyzer):
        """Muestra el reporte completo de seguridad"""
        report = pandas_analyzer.generate_security_report()
        return f"🔒 Security Report:\n{json.dumps(report, indent=2, default=str)}"

    def _pandas_top_talkers(self, pandas_analyzer):
        """Muestra los top talkers"""
        report = pandas_analyzer.generate_security_report()
        top_talkers = report.get('top_talkers', [])
        result = "📡 Top Talkers (by bytes):\n"
        for i, talker in enumerate(top_talkers, 1):
            result += f"{i}. {talker['src_ip']}: {talker['total_bytes']:,} bytes\n"
        return result

    def _pandas_protocol_analysis(self, pandas_analyzer):
        """Análisis de protocolos"""
        report = pandas_analyzer.generate_security_report()
        protocols = report.get('protocol_analysis', {})
        result = "📊 Protocol Distribution:\n"
        for proto, stats in protocols.items():
            if isinstance(stats, dict) and 'count' in stats and 'percentage' in stats:
                result += f"{proto}: {stats['count']} packets ({stats['percentage']:.1f}%)\n"
            else:
                result += f"{proto}: {stats}\n"
        return result

    def _pandas_anomalies(self, pandas_analyzer):
        """Anomalías detectadas"""
        report = pandas_analyzer.generate_security_report()
        anomalies = report.get('anomalies_detected', {})
        result = f"🚨 Total Anomalies: {anomalies.get('total_anomalies', 0)}\n"
        if anomalies.get('anomaly_types'):
            result += "Anomaly Types:\n"
            for anomaly, count in anomalies['anomaly_types'].items():
                result += f"  {anomaly}: {count}\n"
        return result

    def _pandas_dns_analysis(self, pandas_analyzer):
        """Análisis DNS"""
        report = pandas_analyzer.generate_security_report()
        dns = report.get('dns_analysis', {})
        result = f"🌐 DNS Analysis:\n"
        result += f"Total queries: {dns.get('total_queries', 0)}\n"
        result += f"Unique domains: {dns.get('unique_domains', 0)}\n"
        if dns.get('top_queried_domains'):
            result += "Top domains:\n"
            for domain, count in list(dns.get('top_queried_domains', {}).items())[:5]:
                result += f"  {domain}: {count}\n"
        return result

    def _pandas_http_analysis(self, pandas_analyzer):
        """Análisis HTTP"""
        report = pandas_analyzer.generate_security_report()
        http = report.get('http_analysis', {})
        result = f"🌍 HTTP Analysis:\n"
        result += f"Total requests: {http.get('total_requests', 0)}\n"
        if http.get('http_methods'):
            result += "Methods:\n"
            for method, count in http.get('http_methods', {}).items():
                result += f"  {method}: {count}\n"
        return result

    def _pandas_export_excel(self, pandas_analyzer):
        """Exporta a Excel"""
        filename = input("Enter Excel filename (e.g., analysis.xlsx): ").strip()
        if not filename:
            filename = "network_analysis.xlsx"
        
        try:
            pandas_analyzer.export_to_excel(filename)
            return f"✅ Exported to {filename}"
        except Exception as e:
            return f"❌ Export failed: {str(e)}"