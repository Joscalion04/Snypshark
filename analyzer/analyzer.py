from abc import ABC, abstractmethod
from collections import Counter, defaultdict
import pyshark
import re

class PacketProcessor(ABC):
    """Abstract base class for packet processors"""
    @abstractmethod
    def process_packet(self, packet):
        pass

class PCAPAnalyzer:
    """Main analyzer class following Single Responsibility Principle"""
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.packet_processors = []
        self.stats = {
            'total_packets': 0,
            'protocol_counter': Counter(),
            'tcp_streams': set()
        }
        
    def add_processor(self, processor: PacketProcessor):
        """Add a packet processor (Open/Closed Principle)"""
        self.packet_processors.append(processor)
        
    def analyze(self):
        """Analyze the PCAP file"""
        try:
            capture = pyshark.FileCapture(
                self.pcap_path,
                only_summaries=False,
                keep_packets=False,
                use_json=True
            )
            
            for packet in capture:
                self._process_packet(packet)
                
        finally:
            capture.close()
            
    def _process_packet(self, packet):
        """Process each packet through all registered processors"""
        self.stats['total_packets'] += 1
        layers = [layer.layer_name for layer in packet.layers]
        self.stats['protocol_counter'].update(layers)
        
        for processor in self.packet_processors:
            processor.process_packet(packet)