from collections import Counter
from core.packet_processor import PacketProcessor
import threading

class ICMPProcessor(PacketProcessor):
    """Handles ICMP-specific packet processing with optimized type handling"""
    def __init__(self):
        self.icmp_types = Counter()
        self._lock = threading.Lock()
        self._type_cache = set()

    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == 'icmp':
                    self._process_icmp_layer(packet.icmp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_icmp_layer(self, icmp_layer):
        """Procesa la capa ICMP de forma optimizada"""
        try:
            if hasattr(icmp_layer, 'type'):
                icmp_type = int(icmp_layer.type)
                with self._lock:
                    self.icmp_types[icmp_type] += 1
                    self._type_cache.add(icmp_type)
                    
        except (ValueError, AttributeError):
            pass

    def get_unique_types(self):
        """Devuelve tipos ICMP únicos detectados"""
        with self._lock:
            return sorted(self._type_cache)

    def get_stats(self):
        with self._lock:
            return {
                'unique_types': sorted(self._type_cache),
                'type_distribution': dict(self.icmp_types)
            }