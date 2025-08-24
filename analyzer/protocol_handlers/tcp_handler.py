from collections import Counter
from ..analyzer import PacketProcessor
import threading
from collections import defaultdict

class TCPProcessor(PacketProcessor):
    """Handles TCP-specific packet processing with stream optimization"""
    def __init__(self):
        self.tcp_flags = Counter()
        self.tcp_streams = set()
        self._flags_lock = threading.Lock()
        self._streams_lock = threading.Lock()
        self._flag_cache = defaultdict(int)
        self._stream_cache = set()
        self._batch_size = 100
    
    def process_packet(self, packet):
        try:
            # Verificación rápida de capa TCP
            layers = packet.layers
            if not layers:
                return
                
            for layer in layers:
                if layer.layer_name == 'tcp':
                    self._process_tcp_layer(packet.tcp, packet)
                    break
                    
        except (AttributeError, TypeError):
            pass
    
    def _process_tcp_layer(self, tcp_layer, packet):
        """Procesa la capa TCP de forma optimizada"""
        try:
            # Procesamiento de flags
            if hasattr(tcp_layer, 'flags'):
                flags = int(tcp_layer.flags, 16)
                with self._flags_lock:
                    self.tcp_flags[flags] += 1
                    self._flag_cache[flags] += 1
            
            # Procesamiento de streams
            if hasattr(tcp_layer, 'stream'):
                stream_id = tcp_layer.stream
                with self._streams_lock:
                    self.tcp_streams.add(stream_id)
                    self._stream_cache.add(stream_id)
                    
        except (ValueError, AttributeError):
            pass
                
    def get_flag_counts(self):
        """Returns flag counts with descriptive names - optimized"""
        flag_names = {
            0x02: "SYN", 0x12: "SYN+ACK", 0x10: "ACK",
            0x01: "FIN", 0x11: "FIN+ACK", 0x18: "PSH+ACK",
            0x04: "RST", 0x14: "RST+ACK", 0x19: "FIN+PSH+ACK"
        }
        
        with self._flags_lock:
            return {flag_names.get(f, f"0x{f:02x}"): c for f, c in self._flag_cache.items()}
    
    def get_stream_count(self):
        """Devuelve el número de streams únicos"""
        with self._streams_lock:
            return len(self._stream_cache)
    
    def clear_cache(self):
        """Limpia la caché para liberar memoria"""
        with self._flags_lock:
            self._flag_cache.clear()
        with self._streams_lock:
            self._stream_cache.clear()