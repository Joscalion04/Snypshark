import threading
from collections import Counter

from core.packet_processor import PacketProcessor


class DHCPProcessor(PacketProcessor):
    def __init__(self):
        self.message_counts: Counter = Counter()
        self._lock = threading.Lock()

    def process_packet(self, packet) -> None:
        try:
            for layer in packet.layers:
                if layer.layer_name == "bootp":
                    self._process_bootp_layer(packet.bootp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_bootp_layer(self, bootp_layer) -> None:
        try:
            if hasattr(bootp_layer, "option_dhcp"):
                with self._lock:
                    self.message_counts[bootp_layer.option_dhcp] += 1
        except (AttributeError, UnicodeDecodeError):
            pass

    def get_unique_message_types(self) -> list:
        with self._lock:
            return sorted(self.message_counts.keys())

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_messages": sum(self.message_counts.values()),
                "unique_types": len(self.message_counts),
                "message_distribution": dict(self.message_counts),
            }
