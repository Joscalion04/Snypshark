from ..analyzer import PacketProcessor
from collections import Counter

class DHCPProcessor(PacketProcessor):
    """Handles DHCP-specific packet processing"""
    def __init__(self):
        self.message_types = Counter()
    
    def process_packet(self, packet):
        if 'bootp' in [layer.layer_name for layer in packet.layers]:
            try:
                if hasattr(packet.bootp, 'option_dhcp'):
                    msg_type = packet.bootp.option_dhcp
                    self.message_types[msg_type] += 1
            except AttributeError:
                pass
