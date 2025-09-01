from __future__ import annotations
from abc import ABC, abstractmethod
from collections import Counter
from typing import Callable, Dict, List, Optional, Set
import pyshark
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

from .packet_processor import PacketProcessor
from .parallel_engine import ParallelProcessingEngine, BatchProcessor
from utils.performance_utils import optimize_memory_settings
from config.performance_config import PerformanceConfig

class PCAPAnalyzer:
    """
    Motor principal de análisis con procesamiento paralelo optimizado
    """
    
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
        """Registra un procesador de paquetes"""
        self.packet_processors.append(processor)

    def analyze(self, progress_callback: Optional[Callable[[int], None]] = None) -> None:
        """Analiza el archivo PCAP con procesamiento paralelo optimizado"""
        optimize_memory_settings()
        
        file_size = os.path.getsize(self.pcap_path) / (1024 * 1024)
        max_workers = PerformanceConfig.get_optimal_workers(file_size)
        
        # Configurar motor paralelo
        self._parallel_engine = ParallelProcessingEngine(max_workers)
        
        with pyshark.FileCapture(
            self.pcap_path,
            only_summaries=False,
            keep_packets=False,
            use_json=True,
            use_ek=True
        ) as capture:
            
            packet_count = 0
            sample_packets = []  # Para optimización de batch size
            
            for packet in capture:
                packet_count += 1
                
                # Recolectar muestra para optimización
                if packet_count <= 100:
                    sample_packets.append(packet)
                
                # Añadir paquete al batch processor
                batch_ready = self._batch_processor.add_packet(packet)
                
                if batch_ready:
                    # Procesar batch completo
                    self._batch_processor.process_batch(self.packet_processors)
                
                if progress_callback:
                    progress_callback(packet_count)
            
            # Procesar batch final
            self._batch_processor.flush(self.packet_processors)
            
            # Optimizar batch size para futuras ejecuciones
            if sample_packets:
                optimal_size = self._batch_processor.optimize_batch_size(sample_packets)
                print(f"⚡ Optimal batch size: {optimal_size}")
            
            self.stats['total_packets'] = packet_count
        
        # Mostrar estadísticas de rendimiento
        engine_stats = self._parallel_engine.get_stats()
        print(f"📊 Parallel processing stats:")
        print(f"   Packets processed: {engine_stats['packets_processed']:,}")
        print(f"   Processing time: {engine_stats['processing_time']:.2f}s")
        print(f"   Packets/second: {engine_stats.get('packets_per_second', 0):.0f}")
        print(f"   Workers used: {engine_stats['workers_used']}")

    def _process_packet_batch(self, packets: List, start_index: int) -> None:
        """Procesa un lote de paquetes en paralelo"""
        batch_stats = {'protocol_counter': Counter(), 'tcp_streams': set()}
        
        for packet in packets:
            try:
                layers = [layer.layer_name for layer in packet.layers]
                batch_stats['protocol_counter'].update(layers)
                
                for processor in self.packet_processors:
                    processor.process_packet(packet)
                    
            except Exception:
                continue
        
        with self._buffer_lock:
            self.stats['protocol_counter'].update(batch_stats['protocol_counter'])
            self.stats['tcp_streams'].update(batch_stats['tcp_streams'])

    @staticmethod
    def count_packets(pcap_path: str) -> int:
        """Conteo rápido de paquetes"""
        total = 0
        with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
            for _ in capture:
                total += 1
        return total

    def get_processing_stats(self) -> Dict[str, any]:
        """Obtiene estadísticas detalladas del procesamiento"""
        return self._parallel_engine.get_stats()