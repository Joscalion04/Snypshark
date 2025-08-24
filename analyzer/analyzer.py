from __future__ import annotations
from abc import ABC, abstractmethod
from collections import Counter, defaultdict
from typing import Callable, Dict, Iterable, List, Optional, Set
import pyshark
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class PacketProcessor(ABC):
    @abstractmethod
    def process_packet(self, packet) -> None:
        raise NotImplementedError

class PCAPAnalyzer:
    """
    Versión optimizada del analizador con procesamiento paralelo
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packet_processors: List[PacketProcessor] = []
        self.stats: Dict[str, object] = {
            'total_packets': 0,
            'protocol_counter': Counter(),
            'tcp_streams': set(),
        }
        self._packet_buffer = []
        self._buffer_lock = threading.Lock()
        self._buffer_size = 1000  # Procesar en lotes de 1000 paquetes

    def add_processor(self, processor: PacketProcessor) -> None:
        self.packet_processors.append(processor)

    def analyze(
        self,
        progress_callback: Optional[Callable[[int], None]] = None,
        max_workers: int = 4
    ) -> None:
        """
        Analiza el archivo PCAP con procesamiento paralelo
        """
        print(f"⚡ Using {max_workers} workers for parallel processing")
        
        with pyshark.FileCapture(
            self.pcap_path,
            only_summaries=False,
            keep_packets=False,
            use_json=True,
            use_ek=True  # Usar EK para mejor rendimiento
        ) as capture:
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []
                packet_count = 0
                
                for packet in capture:
                    packet_count += 1
                    self._packet_buffer.append(packet)
                    
                    # Procesar buffer cuando esté lleno
                    if len(self._packet_buffer) >= self._buffer_size:
                        futures.append(
                            executor.submit(
                                self._process_packet_batch,
                                self._packet_buffer.copy(),
                                packet_count - len(self._packet_buffer)
                            )
                        )
                        self._packet_buffer = []
                    
                    if progress_callback:
                        progress_callback(packet_count)
                
                # Procesar paquetes restantes
                if self._packet_buffer:
                    futures.append(
                        executor.submit(
                            self._process_packet_batch,
                            self._packet_buffer.copy(),
                            packet_count - len(self._packet_buffer)
                        )
                    )
                
                # Esperar a que terminen todos los trabajos
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        print(f"⚠️ Error in parallel processing: {e}")
                
                self.stats['total_packets'] = packet_count

    def _process_packet_batch(self, packets: List, start_index: int) -> None:
        """Procesa un lote de paquetes en paralelo"""
        batch_stats = {
            'protocol_counter': Counter(),
            'tcp_streams': set()
        }
        
        for i, packet in enumerate(packets):
            try:
                # Extraer protocolos rápidamente
                layers = [layer.layer_name for layer in packet.layers]
                batch_stats['protocol_counter'].update(layers)
                
                # Procesar con cada processor
                for processor in self.packet_processors:
                    processor.process_packet(packet)
                    
            except Exception as e:
                # Error silencioso para no interrumpir el procesamiento
                continue
        
        # Actualizar estadísticas globales de forma segura
        with self._buffer_lock:
            self.stats['protocol_counter'].update(batch_stats['protocol_counter'])
            self.stats['tcp_streams'].update(batch_stats['tcp_streams'])

    @staticmethod
    def count_packets(pcap_path: str) -> int:
        """Conteo rápido de paquetes usando tshark directamente"""
        import subprocess
        import sys
        
        try:
            # Usar tshark directamente para mayor velocidad
            cmd = [
                'tshark', '-r', pcap_path, '-T', 'fields', '-e', 'frame.number',
                '|', 'tail', '-n', '1'
            ]
            
            if sys.platform == 'win32':
                cmd = ['cmd', '/c'] + cmd
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # Timeout de 30 segundos
            )
            
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
                
        except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
            pass
        
        # Fallback al método original
        total = 0
        with pyshark.FileCapture(
            pcap_path,
            only_summaries=True,
            keep_packets=False
        ) as capture:
            for _ in capture:
                total += 1
        return total