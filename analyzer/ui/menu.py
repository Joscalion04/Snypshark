class InteractiveMenu:
    """Handles the interactive menu display (Single Responsibility)"""
    def __init__(self, analyzer, processors):
        self.analyzer = analyzer
        self.processors = processors
        
    def display_menu(self):
        options = {
            '1': ("Total packets", lambda: f"📦 Total: {self.analyzer.stats['total_packets']}"),
            '2': ("Common protocols", lambda: f"📊 Protocols: {self.analyzer.stats['protocol_counter'].most_common(5)}"),
            '3': ("TCP Flags", self._get_tcp_flags),
            '4': ("TCP Streams", self._get_tcp_streams),
            '5': ("Source IPs", self._get_source_ips),
            '6': ("Common TTLs", self._get_ttls),
            '7': ("Pattern matches", self._get_patterns),
            '8': ("DNS Queries", self._get_dns_queries),
            '9': ("DNS Responses", self._get_dns_responses),
            '10': ("ICMP Types", self._get_icmp_types),
            '0': ("Exit", None)
        }
        
        while True:
            print("\n==== ANALYSIS MENU ====")
            for key, (desc, _) in options.items():
                print(f"{key}. {desc}")

            choice = input("\n→ Select an option (or '0' to exit): ").strip()
            
            if choice == '0':
                print("👋 Exiting...")
                break
                
            if choice in options:
                try:
                    print(options[choice][1]())
                except Exception as e:
                    print(f"⚠️ Error: {str(e)}")
            else:
                print("❌ Invalid option. Please try again.")
    
    def _get_tcp_flags(self):
        tcp_processor = self.processors.get('tcp')
        return f"🚩 TCP Flags: {tcp_processor.get_flag_counts()}" if tcp_processor else "TCP data not available"
    
    def _get_tcp_streams(self):
        return f"🔄 TCP Streams: {len(self.analyzer.stats['tcp_streams'])} unique streams"
    
    def _get_source_ips(self):
        ip_processor = self.processors.get('ip')
        if ip_processor:
            return f"📡 Source IPs: {ip_processor.ip_source_counter.most_common(5)}"
        return "IP data not available"
    
    def _get_ttls(self):
        ip_processor = self.processors.get('ip')
        if ip_processor:
            return f"⏳ TTLs: {ip_processor.ttl_histogram.most_common(5)}"
        return "IP data not available"
    
    def _get_patterns(self):
        pattern_matcher = self.processors.get('patterns')
        if pattern_matcher:
            return f"🔍 Patterns: {dict(pattern_matcher.pattern_occurrences)}"
        return "Pattern data not available"
    
    def _get_dns_queries(self):
        dns_processor = self.processors.get('dns')
        if dns_processor:
            unique = len(set(dns_processor.dns_queries))
            return f"❓ DNS queries: {len(dns_processor.dns_queries)} (unique: {unique})"
        return "DNS data not available"
    
    def _get_dns_responses(self):
        dns_processor = self.processors.get('dns')
        if dns_processor:
            unique = len(set(dns_processor.dns_responses))
            return f"✔️ DNS responses: {len(dns_processor.dns_responses)} (unique: {unique})"
        return "DNS data not available"
    
    def _get_icmp_types(self):
        icmp_processor = self.processors.get('icmp')
        if icmp_processor:
            return f"📶 ICMP types: {dict(icmp_processor.icmp_types)}"
        return "ICMP data not available"