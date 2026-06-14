import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

import psutil
from utils.logger import get_logger

from .packet_processor import PacketProcessor

logger = get_logger(__name__)


class ParallelProcessingEngine:
    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max_workers or self._get_optimal_workers()
        self._lock = threading.Lock()
        self._stats: Dict[str, Any] = {
            "packets_processed": 0,
            "processing_time": 0,
            "workers_used": self.max_workers,
        }
        self._worker_stats: Dict[int, Dict[str, float]] = defaultdict(
            lambda: {"packets": 0, "time": 0}
        )

    def _get_optimal_workers(self) -> int:
        cpu_count = psutil.cpu_count(logical=False) or 4
        memory_gb = psutil.virtual_memory().total / (1024**3)

        if memory_gb < 4:
            return min(cpu_count, 4)
        elif memory_gb < 8:
            return min(cpu_count, 8)
        return min(cpu_count, 12)

    def process_packets(
        self,
        packets: List,
        processors: List[PacketProcessor],
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> Dict[str, Any]:
        start_time = time.time()
        total_packets = len(packets)

        if total_packets == 0:
            return self._stats

        chunk_size = max(1, total_packets // (self.max_workers * 2))
        chunks = [packets[i : i + chunk_size] for i in range(0, total_packets, chunk_size)]

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(self._process_chunk, chunk, processors, idx): idx
                for idx, chunk in enumerate(chunks)
            }

            completed = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    chunk_index = futures[future]
                    completed += result["processed"]

                    with self._lock:
                        self._stats["packets_processed"] += result["processed"]
                        self._worker_stats[chunk_index] = {
                            "packets": result["processed"],
                            "time": result["processing_time"],
                        }

                    if progress_callback:
                        progress_callback(completed)

                except Exception as e:
                    logger.warning("Error processing chunk: %s", e)

        self._stats["processing_time"] = time.time() - start_time
        return self._stats

    def _process_chunk(
        self, chunk: List, processors: List[PacketProcessor], chunk_index: int
    ) -> Dict[str, Any]:
        chunk_start = time.time()
        processed = 0

        for packet in chunk:
            try:
                for processor in processors:
                    processor.process_packet(packet)
                processed += 1
            except Exception:
                continue

        return {
            "processed": processed,
            "processing_time": time.time() - chunk_start,
            "chunk_index": chunk_index,
            "chunk_size": len(chunk),
        }

    def get_stats(self) -> Dict[str, Any]:
        stats = self._stats.copy()

        if stats["processing_time"] > 0:
            stats["packets_per_second"] = stats["packets_processed"] / stats["processing_time"]

        worker_stats = {}
        for worker_id, data in self._worker_stats.items():
            if data["time"] > 0:
                worker_stats[worker_id] = {
                    "packets_processed": data["packets"],
                    "processing_time": data["time"],
                    "packets_per_second": data["packets"] / data["time"],
                }

        stats["worker_stats"] = worker_stats
        return stats

    def reset_stats(self) -> None:
        self._stats = {
            "packets_processed": 0,
            "processing_time": 0,
            "workers_used": self.max_workers,
        }
        self._worker_stats.clear()

    def optimize_batch_size(self, sample_packets: List) -> int:
        if not sample_packets:
            return 1000
        avg_complexity = self._estimate_packet_complexity(sample_packets)
        if avg_complexity < 0.3:
            return 2000
        elif avg_complexity < 0.7:
            return 1000
        return 500

    def _estimate_packet_complexity(self, packets: List) -> float:
        complexities = []
        for packet in packets[:100]:
            try:
                layers = len(getattr(packet, "layers", []))
                size = int(getattr(packet, "length", 0))
                complexities.append(min(1.0, (layers / 10) + (size / 5000)))
            except Exception:
                complexities.append(0.5)
        return sum(complexities) / len(complexities) if complexities else 0.5


class BatchProcessor:
    def __init__(self, batch_size: int = 1000):
        self.batch_size = batch_size
        self.current_batch: List = []
        self.parallel_engine = ParallelProcessingEngine()

    def add_packet(self, packet) -> bool:
        self.current_batch.append(packet)
        return len(self.current_batch) >= self.batch_size

    def process_batch(self, processors: List[PacketProcessor]) -> Dict[str, Any]:
        if not self.current_batch:
            return {}
        stats = self.parallel_engine.process_packets(self.current_batch, processors)
        self.current_batch = []
        return stats

    def flush(self, processors: List[PacketProcessor]) -> Dict[str, Any]:
        return self.process_batch(processors)

    def optimize_batch_size(self, sample_packets: List) -> int:
        self.batch_size = self.parallel_engine.optimize_batch_size(sample_packets)
        return self.batch_size
