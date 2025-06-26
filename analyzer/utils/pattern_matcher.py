from collections import defaultdict
import re
from ..analyzer import PacketProcessor

class PatternMatcher(PacketProcessor):
    """Searches for patterns in packet payloads"""
    def __init__(self, patterns=None):
        self.pattern_occurrences = defaultdict(int)
        self.patterns = re.compile(
            patterns or r'microsoft|google|intel|login|http|https|ftp|ssh', 
            re.IGNORECASE
        )
        
    def process_packet(self, packet):
        try:
            payload = str(packet).lower()
            matches = self.patterns.findall(payload)
            for match in matches:
                self.pattern_occurrences[match] += 1
        except:
            pass