import threading
from collections import Counter

from core.packet_processor import PacketProcessor

_FLAG_NAMES = {
    0x02: "SYN",
    0x12: "SYN+ACK",
    0x10: "ACK",
    0x01: "FIN",
    0x11: "FIN+ACK",
    0x18: "PSH+ACK",
    0x04: "RST",
    0x14: "RST+ACK",
    0x19: "FIN+PSH+ACK",
}


class TCPProcessor(PacketProcessor):
    def __init__(self):
        self.flag_counts: Counter = Counter()
        self.streams: set = set()
        self._lock = threading.Lock()

    def process_packet(self, packet) -> None:
        try:
            for layer in packet.layers:
                if layer.layer_name == "tcp":
                    self._process_tcp_layer(packet.tcp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_tcp_layer(self, tcp_layer) -> None:
        try:
            with self._lock:
                if hasattr(tcp_layer, "flags"):
                    self.flag_counts[int(tcp_layer.flags, 16)] += 1
                if hasattr(tcp_layer, "stream"):
                    self.streams.add(tcp_layer.stream)
        except (ValueError, AttributeError):
            pass

    def get_flag_counts(self) -> dict:
        with self._lock:
            return {_FLAG_NAMES.get(f, f"0x{f:02x}"): c for f, c in self.flag_counts.items()}

    def get_stream_count(self) -> int:
        with self._lock:
            return len(self.streams)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "flag_counts": dict(self.flag_counts),
                "stream_count": len(self.streams),
                "unique_streams": list(self.streams)[:10],
            }
