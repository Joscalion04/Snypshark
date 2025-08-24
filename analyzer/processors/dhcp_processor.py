from core.packet_processor import PacketProcessor
from collections import Counter
import threading
from collections import defaultdict

class DHCPProcessor(PacketProcessor):
    """Handles DHCP-specific packet processing with message type optimization"""
    def __init__(self):
        self.message_types = Counter()
        self._lock = threading.Lock()
        self._type_cache = defaultdict(int)
        self._unique_types = set()
    
    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == 'bootp':
                    self._process_bootp_layer(packet.bootp)
                    break
        except (AttributeError, TypeError):
            pass
    
    def _process_bootp_layer(self, bootp_layer):
        """Procesa la capa bootp de forma optimizada"""
        try:
            if hasattr(bootp_layer, 'option_dhcp'):
                msg_type = bootp_layer.option_dhcp
                with self._lock:
                    self.message_types[msg_type] += 1
                    self._type_cache[msg_type] += 1
                    self._unique_types.add(msg_type)
                    
        except (AttributeError, UnicodeDecodeError):
            pass
    
    def get_unique_message_types(self):
        """Devuelve tipos de mensaje únicos"""
        with self._lock:
            return sorted(self._unique_types)
    
    def get_message_type_distribution(self):
        """Devuelve distribución de tipos de mensaje"""
        with self._lock:
            return dict(self._type_cache)

    def get_stats(self):
        with self._lock:
            return {
                'total_messages': sum(self._type_cache.values()),
                'unique_types': len(self._unique_types),
                'message_distribution': dict(self._type_cache)
            }