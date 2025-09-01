from core.packet_processor import PacketProcessor
from collections import Counter
import threading

class HTTPProcessor(PacketProcessor):
    """Handles HTTP-specific packet processing with thread-safe optimization"""
    def __init__(self):
        self.methods = Counter()
        self.hosts = Counter()
        self._methods_lock = threading.Lock()
        self._hosts_lock = threading.Lock()
        self._processed_count = 0
    
    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == 'http':
                    self._process_http_layer(packet.http)
                    break
        except (AttributeError, TypeError):
            pass
    
    def _process_http_layer(self, http_layer):
        """Procesa la capa HTTP de forma optimizada y thread-safe"""
        try:
            if hasattr(http_layer, 'request_method'):
                method = http_layer.request_method
                with self._methods_lock:
                    self.methods[method] += 1
            
            if hasattr(http_layer, 'host'):
                host = http_layer.host.lower()
                with self._hosts_lock:
                    self.hosts[host] += 1
                    
            self._processed_count += 1
            
        except (AttributeError, UnicodeDecodeError):
            pass
    
    def get_processed_count(self):
        return self._processed_count

    def get_stats(self):
        with self._methods_lock:
            with self._hosts_lock:
                return {
                    'total_requests': self._processed_count,
                    'methods': dict(self.methods),
                    'hosts': dict(self.hosts.most_common(10))
                }