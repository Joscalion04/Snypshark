from core.packet_processor import PacketProcessor
from collections import Counter
import threading
from collections import defaultdict

class UDPProcessor(PacketProcessor):
    """Handles UDP-specific packet processing with port optimization"""
    def __init__(self):
        self.ports = Counter()
        self._lock = threading.Lock()
        self._port_cache = defaultdict(int)
        self._unique_ports = set()
        self._conversations = defaultdict(int)

    def process_packet(self, packet):
        try:
            for layer in packet.layers:
                if layer.layer_name == 'udp':
                    self._process_udp_layer(packet.udp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_udp_layer(self, udp_layer):
        """Procesa la capa UDP de forma optimizada"""
        try:
            src_port = udp_layer.srcport
            dst_port = udp_layer.dstport
            
            with self._lock:
                self.ports[f"{src_port}->{dst_port}"] += 1
                self._port_cache[f"{src_port}->{dst_port}"] += 1
                self._unique_ports.add(src_port)
                self._unique_ports.add(dst_port)
                
                conversation_key = f"{src_port}-{dst_port}" if src_port < dst_port else f"{dst_port}-{src_port}"
                self._conversations[conversation_key] += 1
                
        except (AttributeError, ValueError):
            pass

    def get_unique_port_count(self):
        """Devuelve número de puertos únicos"""
        with self._lock:
            return len(self._unique_ports)

    def get_conversation_stats(self):
        """Devuelve estadísticas de conversaciones"""
        with self._lock:
            return dict(self._conversations)

    def get_stats(self):
        with self._lock:
            return {
                'unique_ports': len(self._unique_ports),
                'top_ports': dict(self.ports.most_common(10)),
                'conversation_count': len(self._conversations)
            }