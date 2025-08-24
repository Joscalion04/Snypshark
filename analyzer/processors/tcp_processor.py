from collections import Counter, defaultdict
import threading
from core.packet_processor import PacketProcessor

class TCPProcessor(PacketProcessor):
    """Procesador optimizado para protocolo TCP"""
    
    def __init__(self):
        self.tcp_flags = Counter()
        self.tcp_streams = set()
        self._flags_lock = threading.Lock()
        self._streams_lock = threading.Lock()
        self._flag_cache = defaultdict(int)
        self._stream_cache = set()

    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == 'tcp':
                    self._process_tcp_layer(packet.tcp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_tcp_layer(self, tcp_layer):
        try:
            if hasattr(tcp_layer, 'flags'):
                flags = int(tcp_layer.flags, 16)
                with self._flags_lock:
                    self.tcp_flags[flags] += 1
                    self._flag_cache[flags] += 1
            
            if hasattr(tcp_layer, 'stream'):
                stream_id = tcp_layer.stream
                with self._streams_lock:
                    self.tcp_streams.add(stream_id)
                    self._stream_cache.add(stream_id)
                    
        except (ValueError, AttributeError):
            pass

    def get_flag_counts(self):
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

    def get_stats(self):
        with self._flags_lock:
            with self._streams_lock:
                return {
                    'flag_counts': dict(self._flag_cache),
                    'stream_count': len(self._stream_cache),
                    'unique_streams': list(self._stream_cache)[:10] if self._stream_cache else []
                }