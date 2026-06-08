from collections import Counter
import threading
from core.packet_processor import PacketProcessor


class ICMPProcessor(PacketProcessor):
    def __init__(self):
        self.icmp_types: Counter = Counter()
        self._lock = threading.Lock()

    def process_packet(self, packet) -> None:
        try:
            for layer in packet.layers:
                if layer.layer_name == 'icmp':
                    self._process_icmp_layer(packet.icmp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_icmp_layer(self, icmp_layer) -> None:
        try:
            if hasattr(icmp_layer, 'type'):
                with self._lock:
                    self.icmp_types[int(icmp_layer.type)] += 1
        except (ValueError, AttributeError):
            pass

    def get_unique_types(self) -> list:
        with self._lock:
            return sorted(self.icmp_types.keys())

    def get_stats(self) -> dict:
        with self._lock:
            return {
                'unique_types': sorted(self.icmp_types.keys()),
                'type_distribution': dict(self.icmp_types),
            }
