from collections import Counter
from ..analyzer import PacketProcessor

class TCPProcessor(PacketProcessor):
    """Handles TCP-specific packet processing (Single Responsibility)"""
    def __init__(self):
        self.tcp_flags = Counter()
        self.tcp_streams = set()
        
    def process_packet(self, packet):
        if 'tcp' in [layer.layer_name for layer in packet.layers]:
            try:
                flags = int(packet.tcp.flags, 16)
                self.tcp_flags[flags] += 1
                if hasattr(packet.tcp, 'stream'):
                    self.tcp_streams.add(packet.tcp.stream)
            except AttributeError:
                pass
                
    def get_flag_counts(self):
        """Returns flag counts with descriptive names"""
        flag_names = {
            0x02: "SYN", 0x12: "SYN+ACK", 0x10: "ACK",
            0x01: "FIN", 0x11: "FIN+ACK", 0x18: "PSH+ACK",
            0x04: "RST", 0x14: "RST+ACK"
        }
        return {flag_names.get(f, f"0x{f:02x}"): c for f, c in self.tcp_flags.items()}