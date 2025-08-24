from ..analyzer import PacketProcessor
from collections import Counter

class UDPProcessor(PacketProcessor):
    """Handles UDP-specific packet processing"""
    def __init__(self):
        self.ports = Counter()
    
    def process_packet(self, packet):
        if 'udp' in [layer.layer_name for layer in packet.layers]:
            try:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                self.ports[f"{src_port}->{dst_port}"] += 1
            except AttributeError:
                pass
