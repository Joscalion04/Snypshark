from collections import defaultdict, Counter
import re
from typing import Dict, Any, Set
import threading

class FastPacketProcessor:
    """Base class for optimized packet processors"""
    
    def __init__(self):
        self._local_data = threading.local()
        self._batch_buffer = []
        self._batch_size = 100
        
    def process_packet_batch(self, packets: list):
        """Process a batch of packets (to be overridden)"""
        pass
        
    def process_packet(self, packet):
        """Process individual packet with batching"""
        self._batch_buffer.append(packet)
        
        if len(self._batch_buffer) >= self._batch_size:
            self.process_packet_batch(self._batch_buffer)
            self._batch_buffer = []
    
    def flush(self):
        """Process remaining packets in buffer"""
        if self._batch_buffer:
            self.process_packet_batch(self._batch_buffer)
            self._batch_buffer = []