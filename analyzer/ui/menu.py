from typing import Any

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
            '1': ("Total packets", lambda: f"📦 Total: {self.analyzer.stats['total_packets']}"),
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
    def _get_common_protocols(self):
        n = self._ask_top(10)
        return f"📊 Protocols: {self.analyzer.stats['protocol_counter'].most_common(n)}"

    def _get_tcp_flags(self):
        tcp_processor = self.processors.get('tcp')
        return f"🚩 TCP Flags: {tcp_processor.get_flag_counts()}" if tcp_processor else "TCP data not available"

    def _get_tcp_streams(self):
        # Si TCPProcessor llena sus propios streams, podría usarse también
        return f"🔄 TCP Streams: {len(self.analyzer.stats['tcp_streams'])} unique streams"

    def _get_source_ips(self):
        ip = self.processors.get('ip')
        if not ip:
            return "IP data not available"
        n = self._ask_top(5)
        return f"📡 Source IPs: {ip.ip_source_counter.most_common(n)}"

    def _get_ttls(self):
        ip = self.processors.get('ip')
        if not ip:
            return "IP data not available"
        n = self._ask_top(5)
        return f"⏳ TTLs/HopLimit: {ip.ttl_histogram.most_common(n)}"

    def _get_patterns(self):
        p = self.processors.get('patterns')
        if not p:
            return "Pattern data not available"
        return f"🔍 Patterns: {dict(p.pattern_occurrences)}"

    def _get_dns_queries(self):
        dns = self.processors.get('dns')
        if not dns:
            return "DNS data not available"
        unique = len(set(dns.dns_queries))
        return f"❓ DNS queries: {len(dns.dns_queries)} (unique: {unique})"

    def _get_dns_responses(self):
        dns = self.processors.get('dns')
        if not dns:
            return "DNS data not available"
        unique = len(set(dns.dns_responses))
        return f"✔️ DNS responses: {len(dns.dns_responses)} (unique: {unique})"

    def _get_icmp_types(self):
        icmp = self.processors.get('icmp')
        if not icmp:
            return "ICMP data not available"
        return f"📶 ICMP types: {dict(icmp.icmp_types)}"

    def _get_udp_ports(self):
        udp = self.processors.get('udp')
        if not udp:
            return "UDP data not available"
        n = self._ask_top(10)
        return f"🎯 UDP Ports: {udp.ports.most_common(n)}"

    def _get_dhcp_msgs(self):
        dhcp = self.processors.get('dhcp')
        if not dhcp:
            return "DHCP data not available"
        n = self._ask_top(5)
        return f"📡 DHCP Messages: {dhcp.message_types.most_common(n)}"

    # --------- HTTP submenu --------- #
    def _http_submenu(self):
        http = self.processors.get('http')
        if not http:
            print("HTTP data not available")
            return

        sub = {
            '1': ("Methods (top-N)", lambda: self._http_methods(http)),
            '2': ("Hosts (top-N)", lambda: self._http_hosts(http)),
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

    def _http_methods(self, http):
        n = self._ask_top(5)
        return f"🌐 HTTP Methods: {http.methods.most_common(n)}"

    def _http_hosts(self, http):
        n = self._ask_top(5)
        return f"🏷️ HTTP Hosts: {http.hosts.most_common(n)}"
