from ..analyzer import PacketProcessor
from collections import defaultdict, deque
import threading

class DNSProcessor(PacketProcessor):
    """Handles DNS-specific packet processing with batching optimization"""
    def __init__(self):
        self.dns_queries = deque()
        self.dns_responses = deque()
        self._query_counter = defaultdict(int)
        self._response_counter = defaultdict(int)
        self._batch_size = 100
        self._current_batch = []
        self._lock = threading.Lock()
        
    def process_packet(self, packet):
        try:
            # Verificación rápida de capa DNS
            if not hasattr(packet, 'layers'):
                return
                
            # Búsqueda optimizada de capa DNS
            for layer in packet.layers:
                if layer.layer_name == 'dns':
                    self._process_dns_layer(packet.dns)
                    break
                    
        except (AttributeError, TypeError):
            pass
    
    def _process_dns_layer(self, dns_layer):
        """Procesa la capa DNS de forma optimizada"""
        try:
            if hasattr(dns_layer, 'qry_name'):
                query = dns_layer.qry_name.lower()
                with self._lock:
                    self.dns_queries.append(query)
                    self._query_counter[query] += 1
                    
            if hasattr(dns_layer, 'resp_name'):
                response = dns_layer.resp_name.lower()
                with self._lock:
                    self.dns_responses.append(response)
                    self._response_counter[response] += 1
                    
        except (AttributeError, UnicodeDecodeError):
            pass
    
    def get_query_stats(self):
        """Devuelve estadísticas de consultas"""
        with self._lock:
            return dict(self._query_counter)
    
    def get_response_stats(self):
        """Devuelve estadísticas de respuestas"""
        with self._lock:
            return dict(self._response_counter)