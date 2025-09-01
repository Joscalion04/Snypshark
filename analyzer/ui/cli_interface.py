from typing import Any, Dict, Optional
import json
import os
from collections import Counter

from analytics.pandas_analyzer import PandasAnalyzer
from utils.file_utils import validate_file_path

class InteractiveMenu:
    """Sistema de menú interactivo mejorado y corregido"""
    
    def __init__(self, analyzer, processors):
        self.analyzer = analyzer
        self.processors = processors
        self.current_menu = "main"

    def _print_header(self, title: str):
        """Imprime un encabezado bonito"""
        print(f"\n🎯 {title}")
        print("─" * 50)

    def _print_success(self, message: str):
        """Mensaje de éxito"""
        print(f"✅ {message}")

    def _print_warning(self, message: str):
        """Mensaje de advertencia"""
        print(f"⚠️  {message}")

    def _print_error(self, message: str):
        """Mensaje de error"""
        print(f"❌ {message}")

    def _ask_top(self, default: int = 5) -> int:
        """Pide al usuario el N para top-N con mejor formato"""
        try:
            raw = input(f"🔢 How many items to show? [{default}]: ").strip()
            if not raw:
                return default
            n = int(raw)
            return max(1, min(100, n))
        except ValueError:
            return default

    def _clear_screen(self):
        """Intenta limpiar la pantalla"""
        try:
            os.system('cls' if os.name == 'nt' else 'clear')
        except:
            print("\n" * 50)  # Fallback: imprimir muchas líneas nuevas

    def display_menu(self):
        """Menú principal con mejor estética"""
        options = {
            '1': ("📦 Packet Statistics", self._packet_stats_menu),
            '2': ("🌐 Protocol Analysis", self._protocol_analysis_menu),
            '3': ("🔍 Security Findings", self._security_menu),
            '4': ("📊 Advanced Pandas Analysis", self._pandas_submenu),
            '5': ("💾 Export Results", self._export_menu),
            '0': ("🚪 Exit", self._exit_program),
        }

        while True:
            self._clear_screen()
            print("\n" + "═" * 60)
            print("🎮 MAIN ANALYSIS MENU")
            print("═" * 60)
            
            for key, (desc, _) in options.items():
                print(f"{key}. {desc}")
            
            print("═" * 60)
            choice = input("\n🎯 Select an option (0-5): ").strip()
            
            if choice == '0':
                print("\n👋 Thank you for using Snypshark Analyzer!")
                print("✨ Happy hunting!")
                break

            action = options.get(choice)
            if not action:
                input("\n❌ Invalid option. Press Enter to continue...")
                continue

            try:
                result = action[1]()
                if result is not None:
                    print(f"\n{result}")
                input("\n⏎ Press Enter to return to main menu...")
            except Exception as e:
                print(f"\n❌ Error: {str(e)}")
                input("⏎ Press Enter to continue...")

    def _packet_stats_menu(self):
        """Submenú de estadísticas de paquetes"""
        self._print_header("PACKET STATISTICS")
        
        options = {
            '1': ("Total packets", self._get_total_packets),
            '2': ("Protocol distribution", self._get_common_protocols),
            '3': ("Source IPs", self._get_source_ips),
            '4': ("TTL analysis", self._get_ttls),
            '5': ("Back to main menu", None)
        }
        
        return self._run_submenu(options, "📊 Packet Statistics")

    def _protocol_analysis_menu(self):
        """Submenú de análisis de protocolos"""
        self._print_header("PROTOCOL ANALYSIS")
        
        options = {
            '1': ("TCP Analysis", self._tcp_submenu),
            '2': ("UDP Analysis", self._get_udp_ports),
            '3': ("DNS Analysis", self._dns_submenu),
            '4': ("HTTP Analysis", self._http_submenu),
            '5': ("ICMP Analysis", self._get_icmp_types),
            '6': ("Back to main menu", None)
        }
        
        return self._run_submenu(options, "🌐 Protocol Analysis")

    def _security_menu(self):
        """Submenú de hallazgos de seguridad"""
        self._print_header("SECURITY FINDINGS")
        
        options = {
            '1': ("Pattern matches", self._get_patterns),
            '2': ("Anomalies detected", self._get_anomalies_summary),
            '3': ("Port scan detection", self._get_port_scan_info),
            '4': ("Back to main menu", None)
        }
        
        return self._run_submenu(options, "🔍 Security Findings")

    def _export_menu(self):
        """Submenú de exportación"""
        self._print_header("EXPORT RESULTS")
        
        options = {
            '1': ("Export to Excel", self._export_to_excel),
            '2': ("Generate JSON report", self._export_to_json),
            '3': ("Back to main menu", None)
        }
        
        return self._run_submenu(options, "💾 Export Options")

    def _run_submenu(self, options, title):
        """Ejecuta un submenú genérico CORREGIDO"""
        while True:
            self._clear_screen()
            self._print_header(title)
            
            for key, (desc, _) in options.items():
                print(f"{key}. {desc}")
            
            choice = input("\n🎯 Select an option: ").strip()
            
            # Verificar si es la opción de volver
            back_option = str(len(options))
            if choice == back_option:
                return None
                
            action = options.get(choice)
            if not action:
                print("❌ Invalid option. Please try again.")
                input("⏎ Press Enter to continue...")
                continue
                
            if action[1] is None:
                return None
                
            # Ejecutar la acción y mostrar resultados
            result = action[1]()
            if result is not None:
                print(f"\n{result}")
            
            # Preguntar si quiere continuar en el submenú
            print("\n" + "─" * 50)
            cont = input("⏎ Press Enter to continue in this menu, or 'b' to go back: ").strip().lower()
            
            if cont == 'b':
                return result

    def _tcp_submenu(self):
        """Submenú de análisis TCP"""
        tcp_processor = self.processors.get('tcp')
        if not tcp_processor:
            return "TCP data not available"
            
        options = {
            '1': ("TCP Flags", self._get_tcp_flags),
            '2': ("TCP Streams", self._get_tcp_streams),
            '3': ("Back", None)
        }
        
        return self._run_submenu(options, "📡 TCP Analysis")

    def _dns_submenu(self):
        """Submenú de análisis DNS"""
        dns_processor = self.processors.get('dns')
        if not dns_processor:
            return "DNS data not available"
            
        options = {
            '1': ("DNS Queries", self._get_dns_queries),
            '2': ("DNS Responses", self._get_dns_responses),
            '3': ("Back", None)
        }
        
        return self._run_submenu(options, "🌐 DNS Analysis")

    def _get_port_scan_info(self):
        """Información de detección de port scanning"""
        pandas_analyzer = self.processors.get('pandas')
        if pandas_analyzer:
            report = pandas_analyzer.generate_security_report()
            anomalies = report.get('anomalies_detected', {})
            port_scans = anomalies.get('anomaly_types', {}).get('possible_port_scan', 0)
            return f"🔍 Port scan attempts detected: {port_scans}"
        return "Port scan analysis not available"

    def _get_anomalies_summary(self):
        """Resumen de anomalías"""
        pandas_analyzer = self.processors.get('pandas')
        if pandas_analyzer:
            report = pandas_analyzer.generate_security_report()
            anomalies = report.get('anomalies_detected', {})
            result = f"🚨 Total anomalies: {anomalies.get('total_anomalies', 0)}\n"
            if anomalies.get('anomaly_types'):
                result += "Anomaly types:\n"
                for anomaly, count in anomalies['anomaly_types'].items():
                    result += f"  ⚠️  {anomaly}: {count}\n"
            return result
        return "Anomaly detection not available"

    def _export_to_excel(self):
        """Exportar a Excel"""
        pandas_analyzer = self.processors.get('pandas')
        if not pandas_analyzer:
            return "Pandas analyzer not available for export"
            
        filename = input("📝 Enter Excel filename (e.g., analysis.xlsx): ").strip()
        if not filename:
            filename = "network_analysis.xlsx"
        
        if not filename.endswith('.xlsx'):
            filename += '.xlsx'
            
        try:
            pandas_analyzer.export_to_excel(filename)
            return f"✅ Successfully exported to {filename}"
        except Exception as e:
            return f"❌ Export failed: {str(e)}"

    def _export_to_json(self):
        """Exportar a JSON"""
        pandas_analyzer = self.processors.get('pandas')
        if not pandas_analyzer:
            return "Pandas analyzer not available for export"
            
        filename = input("📝 Enter JSON filename (e.g., report.json): ").strip()
        if not filename:
            filename = "security_report.json"
        
        if not filename.endswith('.json'):
            filename += '.json'
            
        try:
            report = pandas_analyzer.generate_security_report()
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            return f"✅ Successfully exported to {filename}"
        except Exception as e:
            return f"❌ Export failed: {str(e)}"

    # --------- Métodos de análisis básico --------- #
    def _get_total_packets(self):
        return f"📦 Total packets: {self.analyzer.stats['total_packets']:,}"

    def _get_common_protocols(self):
        n = self._ask_top(10)
        protocols = self.analyzer.stats['protocol_counter'].most_common(n)
        result = "📊 Top protocols:\n"
        for i, (proto, count) in enumerate(protocols, 1):
            result += f"  {i}. {proto}: {count} packets\n"
        return result

    def _get_tcp_flags(self):
        tcp_processor = self.processors.get('tcp')
        if hasattr(tcp_processor, 'get_flag_counts'):
            flags = tcp_processor.get_flag_counts()
            result = "🚩 TCP Flags:\n"
            for flag, count in flags.items():
                result += f"  {flag}: {count}\n"
            return result
        return "TCP flags data not available"

    def _get_tcp_streams(self):
        streams = len(self.analyzer.stats.get('tcp_streams', set()))
        return f"🔄 Unique TCP streams: {streams}"

    def _get_source_ips(self):
        ip_processor = self.processors.get('ip')
        if ip_processor and hasattr(ip_processor, 'ip_source_counter'):
            n = self._ask_top(10)
            ips = ip_processor.ip_source_counter.most_common(n)
            result = "📡 Top source IPs:\n"
            for i, (ip, count) in enumerate(ips, 1):
                result += f"  {i}. {ip}: {count} packets\n"
            return result
        return "IP source data not available"

    def _get_ttls(self):
        ip_processor = self.processors.get('ip')
        if ip_processor and hasattr(ip_processor, 'ttl_histogram'):
            n = self._ask_top(8)
            ttls = ip_processor.ttl_histogram.most_common(n)
            result = "⏳ Common TTL values:\n"
            for i, (ttl, count) in enumerate(ttls, 1):
                result += f"  {i}. TTL {ttl}: {count} packets\n"
            return result
        return "TTL data not available"

    def _get_patterns(self):
        pattern_processor = self.processors.get('patterns')
        if pattern_processor and hasattr(pattern_processor, 'pattern_occurrences'):
            patterns = dict(pattern_processor.pattern_occurrences)
            if not patterns:
                return "🔍 No patterns detected"
            result = "🔍 Pattern matches:\n"
            for pattern, count in sorted(patterns.items(), key=lambda x: x[1], reverse=True):
                result += f"  '{pattern}': {count} matches\n"
            return result
        return "Pattern matching not available"

    def _get_dns_queries(self):
        dns_processor = self.processors.get('dns')
        if dns_processor and hasattr(dns_processor, 'dns_queries'):
            unique = len(set(dns_processor.dns_queries))
            n = self._ask_top(15)
            result = f"❓ DNS queries: {len(dns_processor.dns_queries)} (unique: {unique})\n"
            if hasattr(dns_processor, 'dns_query_counter'):
                top_queries = dns_processor.dns_query_counter.most_common(n)
                result += "Top queries:\n"
                for i, (query, count) in enumerate(top_queries, 1):
                    result += f"  {i}. {query}: {count}\n"
            return result
        return "DNS query data not available"

    def _get_dns_responses(self):
        dns_processor = self.processors.get('dns')
        if dns_processor and hasattr(dns_processor, 'dns_responses'):
            unique = len(set(dns_processor.dns_responses))
            return f"✔️ DNS responses: {len(dns_processor.dns_responses)} (unique: {unique})"
        return "DNS response data not available"

    def _get_icmp_types(self):
        icmp_processor = self.processors.get('icmp')
        if icmp_processor and hasattr(icmp_processor, 'icmp_types'):
            types = dict(icmp_processor.icmp_types)
            result = "📶 ICMP types:\n"
            for type_code, count in types.items():
                result += f"  Type {type_code}: {count} packets\n"
            return result
        return "ICMP data not available"

    def _get_udp_ports(self):
        udp_processor = self.processors.get('udp')
        if udp_processor and hasattr(udp_processor, 'ports'):
            n = self._ask_top(15)
            ports = udp_processor.ports.most_common(n)
            result = "🎯 Top UDP ports:\n"
            for i, (port, count) in enumerate(ports, 1):
                result += f"  {i}. Port {port}: {count} packets\n"
            return result
        return "UDP port data not available"

    def _get_dhcp_msgs(self):
        dhcp_processor = self.processors.get('dhcp')
        if dhcp_processor and hasattr(dhcp_processor, 'message_types'):
            n = self._ask_top(5)
            messages = dhcp_processor.message_types.most_common(n)
            result = "📡 DHCP message types:\n"
            for i, (msg_type, count) in enumerate(messages, 1):
                result += f"  {i}. Type {msg_type}: {count} messages\n"
            return result
        return "DHCP data not available"

    # --------- HTTP submenu --------- #
    def _http_submenu(self):
        http_processor = self.processors.get('http')
        if not http_processor:
            return "HTTP data not available"

        options = {
            '1': ("HTTP Methods", lambda: self._http_methods(http_processor)),
            '2': ("HTTP Hosts", lambda: self._http_hosts(http_processor)),
            '3': ("Back", None)
        }
        
        return self._run_submenu(options, "🌍 HTTP Analysis")

    def _http_methods(self, http_processor):
        if hasattr(http_processor, 'methods'):
            n = self._ask_top(10)
            methods = http_processor.methods.most_common(n)
            result = "🌐 HTTP Methods:\n"
            for i, (method, count) in enumerate(methods, 1):
                result += f"  {i}. {method}: {count} requests\n"
            return result
        return "HTTP methods data not available"

    def _http_hosts(self, http_processor):
        if hasattr(http_processor, 'hosts'):
            n = self._ask_top(10)
            hosts = http_processor.hosts.most_common(n)
            result = "🏷️ HTTP Hosts:\n"
            for i, (host, count) in enumerate(hosts, 1):
                result += f"  {i}. {host}: {count} requests\n"
            return result
        return "HTTP hosts data not available"

    # --------- pandas submenu --------- #
    def _pandas_submenu(self):
        pandas_analyzer = self.processors.get('pandas')
        if not pandas_analyzer:
            return "Pandas analysis data not available"

        options = {
            '1': ("Security Report", lambda: self._pandas_security_report(pandas_analyzer)),
            '2': ("Top Talkers", lambda: self._pandas_top_talkers(pandas_analyzer)),
            '3': ("Protocol Analysis", lambda: self._pandas_protocol_analysis(pandas_analyzer)),
            '4': ("Anomalies Detected", lambda: self._pandas_anomalies(pandas_analyzer)),
            '5': ("DNS Analysis", lambda: self._pandas_dns_analysis(pandas_analyzer)),
            '6': ("HTTP Analysis", lambda: self._pandas_http_analysis(pandas_analyzer)),
            '7': ("Timeline Analysis", lambda: self._pandas_timeline_analysis(pandas_analyzer)),
            '8': ("Back to main menu", None)
        }
        
        return self._run_submenu(options, "📊 Pandas Analysis")

    def _pandas_security_report(self, pandas_analyzer):
        """Muestra el reporte completo de seguridad"""
        report = pandas_analyzer.generate_security_report()
        
        result = "🔒 SECURITY REPORT\n"
        result += "═" * 50 + "\n"
        
        # Overview
        overview = report.get('overview', {})
        result += "📊 OVERVIEW:\n"
        result += f"  Total packets: {overview.get('total_packets', 0):,}\n"
        result += f"  Total bytes: {overview.get('total_bytes', 0):,}\n"
        result += f"  Unique IPs: {overview.get('unique_ips', 0)}\n"
        result += f"  Time duration: {overview.get('time_duration', 'N/A')}\n"
        result += f"  Avg packet size: {overview.get('avg_packet_size', 0):.2f} bytes\n\n"
        
        # Anomalies
        anomalies = report.get('anomalies_detected', {})
        result += "🚨 ANOMALIES:\n"
        result += f"  Total anomalies: {anomalies.get('total_anomalies', 0)}\n"
        if anomalies.get('anomaly_types'):
            result += "  Anomaly types:\n"
            for anomaly, count in anomalies['anomaly_types'].items():
                result += f"    ⚠️  {anomaly}: {count}\n"
        result += "\n"
        
        return result

    def _pandas_top_talkers(self, pandas_analyzer):
        """Muestra los top talkers"""
        report = pandas_analyzer.generate_security_report()
        top_talkers = report.get('top_talkers', [])[:10]
        result = "📡 TOP TALKERS (by bytes):\n"
        result += "─" * 40 + "\n"
        for i, talker in enumerate(top_talkers, 1):
            result += f"{i:2d}. {talker.get('src_ip', 'N/A'):15} : {talker.get('total_bytes', 0):,} bytes\n"
        return result

    def _pandas_protocol_analysis(self, pandas_analyzer):
        """Análisis de protocolos"""
        report = pandas_analyzer.generate_security_report()
        protocols = report.get('protocol_analysis', {})
        result = "📊 PROTOCOL DISTRIBUTION:\n"
        result += "─" * 40 + "\n"
        for proto, stats in protocols.items():
            if isinstance(stats, dict):
                result += f"{proto:12} : {stats.get('count', 0):6} packets ({stats.get('percentage', 0):5.1f}%)\n"
            else:
                result += f"{proto:12} : {stats}\n"
        return result

    def _pandas_anomalies(self, pandas_analyzer):
        """Anomalías detectadas"""
        report = pandas_analyzer.generate_security_report()
        anomalies = report.get('anomalies_detected', {})
        result = f"🚨 TOTAL ANOMALIES: {anomalies.get('total_anomalies', 0)}\n"
        if anomalies.get('anomaly_types'):
            result += "ANOMALY TYPES:\n"
            for anomaly, count in anomalies['anomaly_types'].items():
                result += f"  ⚠️  {anomaly}: {count}\n"
        
        if anomalies.get('top_offenders'):
            result += "\nTOP OFFENDERS:\n"
            for ip, count in anomalies['top_offenders'].items():
                result += f"  🎯 {ip}: {count} anomalies\n"
                
        return result

    def _pandas_dns_analysis(self, pandas_analyzer):
        """Análisis DNS"""
        report = pandas_analyzer.generate_security_report()
        dns = report.get('dns_analysis', {})
        result = "🌐 DNS ANALYSIS:\n"
        result += "─" * 40 + "\n"
        result += f"Total queries: {dns.get('total_queries', 0)}\n"
        result += f"Unique domains: {dns.get('unique_domains', 0)}\n"
        
        if dns.get('top_queried_domains'):
            result += "\nTOP DOMAINS:\n"
            for domain, count in list(dns['top_queried_domains'].items())[:10]:
                result += f"  {domain}: {count}\n"
                
        return result

    def _pandas_http_analysis(self, pandas_analyzer):
        """Análisis HTTP"""
        report = pandas_analyzer.generate_security_report()
        http = report.get('http_analysis', {})
        result = "🌍 HTTP ANALYSIS:\n"
        result += "─" * 40 + "\n"
        result += f"Total requests: {http.get('total_requests', 0)}\n"
        
        if http.get('http_methods'):
            result += "\nHTTP METHODS:\n"
            for method, count in http['http_methods'].items():
                result += f"  {method}: {count}\n"
                
        if http.get('top_hosts'):
            result += "\nTOP HOSTS:\n"
            for host, count in list(http['top_hosts'].items())[:5]:
                result += f"  {host}: {count}\n"
                
        return result

    def _pandas_timeline_analysis(self, pandas_analyzer):
        """Análisis temporal"""
        report = pandas_analyzer.generate_security_report()
        timeline = report.get('timeline_analysis', {})
        result = "⏰ TIMELINE ANALYSIS:\n"
        result += "─" * 40 + "\n"
        result += f"Peak traffic time: {timeline.get('peak_traffic_time', 'N/A')}\n"
        result += f"Max packets/min: {timeline.get('max_packets_per_minute', 0)}\n"
        result += f"Max bytes/min: {timeline.get('max_bytes_per_minute', 0):,}\n"
        return result

    def _exit_program(self):
        """Sale del programa"""
        print("\n👋 Thank you for using Snypshark Analyzer!")
        print("✨ Happy hunting!")
        return None