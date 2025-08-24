from core.packet_processor import PacketProcessor
from collections import defaultdict, deque
import threading

class DNSProcessor(PacketProcessor):
    """Handles DNS-specific packet processing with batching optimization"""
    def __init__(self):
        self.dns_queries = deque()
        self.dns_responses = deque()
        self._query_counter = defaultdict(int)
        self._response_counter = defaultdict(int)
        self._lock = threading.Lock()
        
    def process_packet(self, packet):
        try:
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

    def get_stats(self):
        with self._lock:
            return {
                'total_queries': len(self.dns_queries),
                'total_responses': len(self.dns_responses),
                'unique_queries': len(self._query_counter),
                'unique_responses': len(self._response_counter),
                'top_queries': dict(sorted(self._query_counter.items(), 
                                         key=lambda x: x[1], reverse=True)[:10])
            }