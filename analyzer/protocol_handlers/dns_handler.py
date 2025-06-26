from ..analyzer import PacketProcessor

class DNSProcessor(PacketProcessor):
    """Handles DNS-specific packet processing"""
    def __init__(self):
        self.dns_queries = []
        self.dns_responses = []
        
    def process_packet(self, packet):
        if 'dns' in [layer.layer_name for layer in packet.layers]:
            try:
                if hasattr(packet.dns, 'qry_name'):
                    self.dns_queries.append(packet.dns.qry_name.lower())
                if hasattr(packet.dns, 'resp_name'):
                    self.dns_responses.append(packet.dns.resp_name.lower())
            except AttributeError:
                pass