from collections import Counter
from ..analyzer import PacketProcessor
import threading
from collections import defaultdict

class IPProcessor(PacketProcessor):
    """Handles IP-specific packet processing with batch optimization"""
    def __init__(self):
        self.ip_source_counter = Counter()
        self.ttl_histogram = Counter()
        self._source_lock = threading.Lock()
        self._ttl_lock = threading.Lock()
        self._unique_ips = set()
        self._batch_size = 50
        self._ip_batch = []
        self._ttl_batch = []
    
    def process_packet(self, packet):
        try:
            # Verificación rápida de capa IP
            layers = packet.layers
            if not layers:
                return
                
            for layer in layers:
                if layer.layer_name == 'ip':
                    self._process_ip_layer(packet.ip)
                    break
                    
        except (AttributeError, TypeError):
            pass
    
    def _process_ip_layer(self, ip_layer):
        """Procesa la capa IP de forma optimizada con batching"""
        try:
            src_ip = ip_layer.src
            ttl_value = int(ip_layer.ttl)
            
            # Procesamiento por lotes para reducir contention de locks
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
    
    def get_top_sources(self, n=10):
        """Devuelve las top N IPs fuente"""
        with self._source_lock:
            return self.ip_source_counter.most_common(n)
    
    def get_ttl_distribution(self):
        """Devuelve distribución de TTLs"""
        with self._ttl_lock:
            return dict(self.ttl_histogram)