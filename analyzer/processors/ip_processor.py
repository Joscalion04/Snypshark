import threading
from collections import Counter

from core.packet_processor import PacketProcessor


class IPProcessor(PacketProcessor):
    """Handles IP-specific packet processing with optimization"""

    def __init__(self):
        self.ip_source_counter = Counter()
        self.ttl_histogram = Counter()
        self._source_lock = threading.Lock()
        self._ttl_lock = threading.Lock()
        self._unique_ips = set()

    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == "ip":
                    self._process_ip_layer(packet.ip)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_ip_layer(self, ip_layer):
        """Procesa la capa IP de forma optimizada"""
        try:
            src_ip = ip_layer.src
            ttl_value = int(ip_layer.ttl)

            with self._source_lock:
                self.ip_source_counter[src_ip] += 1
                self._unique_ips.add(src_ip)

            with self._ttl_lock:
                self.ttl_histogram[ttl_value] += 1

        except (ValueError, AttributeError):
            pass

    def get_unique_ip_count(self):
        """Devuelve el número de IPs únicas"""
        with self._source_lock:
            return len(self._unique_ips)

    def get_stats(self):
        with self._source_lock:
            with self._ttl_lock:
                return {
                    "unique_ips": len(self._unique_ips),
                    "top_sources": dict(self.ip_source_counter.most_common(10)),
                    "ttl_distribution": dict(self.ttl_histogram.most_common(10)),
                }
