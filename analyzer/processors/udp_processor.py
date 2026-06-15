import threading
from collections import Counter, defaultdict

from core.packet_processor import PacketProcessor


class UDPProcessor(PacketProcessor):
    def __init__(self):
        self.port_flows: Counter = Counter()
        self._unique_ports: set = set()
        self._conversations: defaultdict = defaultdict(int)
        self._lock = threading.Lock()

    def process_packet(self, packet) -> None:
        try:
            for layer in packet.layers:
                if layer.layer_name == "udp":
                    self._process_udp_layer(packet.udp)
                    break
        except (AttributeError, TypeError):
            pass

    def _process_udp_layer(self, udp_layer) -> None:
        try:
            src = udp_layer.srcport
            dst = udp_layer.dstport
            conv_key = f"{src}-{dst}" if src < dst else f"{dst}-{src}"

            with self._lock:
                self.port_flows[f"{src}->{dst}"] += 1
                self._unique_ports.add(src)
                self._unique_ports.add(dst)
                self._conversations[conv_key] += 1
        except (AttributeError, ValueError):
            pass

    def get_unique_port_count(self) -> int:
        with self._lock:
            return len(self._unique_ports)

    def get_conversation_stats(self) -> dict:
        with self._lock:
            return dict(self._conversations)

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "unique_ports": len(self._unique_ports),
                "top_ports": dict(self.port_flows.most_common(10)),
                "conversation_count": len(self._conversations),
            }
