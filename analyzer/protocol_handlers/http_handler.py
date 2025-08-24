from ..analyzer import PacketProcessor
from collections import Counter

class HTTPProcessor(PacketProcessor):
    """Handles HTTP-specific packet processing"""
    def __init__(self):
        self.methods = Counter()
        self.hosts = Counter()
    
    def process_packet(self, packet):
        if 'http' in [layer.layer_name for layer in packet.layers]:
            try:
                if hasattr(packet.http, 'request_method'):
                    self.methods[packet.http.request_method] += 1
                if hasattr(packet.http, 'host'):
                    self.hosts[packet.http.host.lower()] += 1
            except AttributeError:
                pass
