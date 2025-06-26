from collections import Counter
from ..analyzer import PacketProcessor

class IPProcessor(PacketProcessor):
    """Handles IP-specific packet processing"""
    def __init__(self):
        self.ip_source_counter = Counter()
        self.ttl_histogram = Counter()
        
    def process_packet(self, packet):
        if 'ip' in [layer.layer_name for layer in packet.layers]:
            try:
                self.ip_source_counter[packet.ip.src] += 1
                self.ttl_histogram[int(packet.ip.ttl)] += 1
            except (AttributeError, ValueError):
                pass