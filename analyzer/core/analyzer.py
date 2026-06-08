from __future__ import annotations
from collections import Counter
from typing import Callable, Dict, List, Optional
import pyshark
import threading
import os

from .packet_processor import PacketProcessor
from .parallel_engine import ParallelProcessingEngine, BatchProcessor
from utils.performance_utils import optimize_memory_settings
from config.performance_config import PerformanceConfig


class PCAPAnalyzer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packet_processors: List[PacketProcessor] = []
        self.stats: Dict[str, object] = {
            'total_packets': 0,
            'protocol_counter': Counter(),
            'tcp_streams': set(),
        }
        self._parallel_engine = ParallelProcessingEngine()
        self._batch_processor = BatchProcessor()
        self._buffer_lock = threading.Lock()

    def add_processor(self, processor: PacketProcessor) -> None:
        self.packet_processors.append(processor)

    def analyze(self, progress_callback: Optional[Callable[[int], None]] = None) -> None:
        optimize_memory_settings()

        file_size = os.path.getsize(self.pcap_path) / (1024 * 1024)
        max_workers = PerformanceConfig.get_optimal_workers(file_size)
        self._parallel_engine = ParallelProcessingEngine(max_workers)

        with pyshark.FileCapture(
            self.pcap_path,
            only_summaries=False,
            keep_packets=False,
            use_json=True,
            use_ek=True,
        ) as capture:
            packet_count = 0
            sample_packets = []

            for packet in capture:
                packet_count += 1

                if packet_count <= 100:
                    sample_packets.append(packet)

                if self._batch_processor.add_packet(packet):
                    self._batch_processor.process_batch(self.packet_processors)

                if progress_callback:
                    progress_callback(packet_count)

            self._batch_processor.flush(self.packet_processors)

            if sample_packets:
                self._batch_processor.optimize_batch_size(sample_packets)

            self.stats['total_packets'] = packet_count

        engine_stats = self._parallel_engine.get_stats()
        print(f"Packets processed : {engine_stats['packets_processed']:,}")
        print(f"Processing time   : {engine_stats['processing_time']:.2f}s")
        print(f"Packets/second    : {engine_stats.get('packets_per_second', 0):.0f}")
        print(f"Workers used      : {engine_stats['workers_used']}")

    @staticmethod
    def count_packets(pcap_path: str) -> int:
        total = 0
        with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
            for _ in capture:
                total += 1
        return total

    def get_processing_stats(self) -> Dict[str, object]:
        return self._parallel_engine.get_stats()
