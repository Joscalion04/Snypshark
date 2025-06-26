from collections import Counter
from ..analyzer import PacketProcessor

class ICMPProcessor(PacketProcessor):
    """Handles ICMP-specific packet processing"""
    def __init__(self):
        self.icmp_types = Counter()
        
    def process_packet(self, packet):
        if 'icmp' in [layer.layer_name for layer in packet.layers]:
            try:
                self.icmp_types[int(packet.icmp.type)] += 1
            except (AttributeError, ValueError):
                pass