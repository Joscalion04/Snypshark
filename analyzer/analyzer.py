from __future__ import annotations
from abc import ABC, abstractmethod
from collections import Counter
from typing import Callable, Dict, Iterable, List, Optional
import pyshark


class PacketProcessor(ABC):
    """Interfaz base para procesadores de paquetes (SRP)."""
    @abstractmethod
    def process_packet(self, packet) -> None:
        """Procesa un paquete individual."""
        raise NotImplementedError


class PCAPAnalyzer:
    """
    Orquestador de análisis de PCAP:
      - Itera paquetes y despacha a procesadores
      - Mantiene estadísticas generales
      - Ofrece pre-conteo de paquetes para barras de progreso
    """
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.packet_processors: List[PacketProcessor] = []
        self.stats: Dict[str, object] = {
            'total_packets': 0,
            'protocol_counter': Counter(),
            'tcp_streams': set(),  # opcional si algún processor la llena
        }

    def add_processor(self, processor: PacketProcessor) -> None:
        """Registra un procesador (Open/Closed)."""
        self.packet_processors.append(processor)

    def analyze(
        self,
        progress_callback: Optional[Callable[[int], None]] = None
    ) -> None:
        """
        Analiza el archivo PCAP y envía cada paquete a los procesadores.

        Args:
            progress_callback: función que recibe el contador actual (1..N)
                               para pintar barra de progreso (opcional).
        """
        # Context manager evita problemas de event loop al cerrar
        with pyshark.FileCapture(
            self.pcap_path,
            only_summaries=False,
            keep_packets=False,
            use_json=True
        ) as capture:
            for idx, packet in enumerate(capture, start=1):
                self._process_packet(packet)
                if progress_callback:
                    progress_callback(idx)

    def _process_packet(self, packet) -> None:
        """Actualiza stats globales y ejecuta todos los procesadores."""
        self.stats['total_packets'] += 1
        try:
            layers = [layer.layer_name for layer in packet.layers]
            self.stats['protocol_counter'].update(layers)
        except Exception:
            # En algunas capturas ciertas propiedades pueden faltar
            pass

        for processor in self.packet_processors:
            try:
                processor.process_packet(packet)
            except Exception:
                # Aísla fallos de un processor sin abortar todo el análisis
                pass

    # ------------ Utilidad para pre-conteo (progreso) ------------ #
    @staticmethod
    def count_packets(pcap_path: str) -> int:
        """
        Itera una vez en modo resumen para obtener el total de paquetes.
        Rápido y sin mantener en memoria (keep_packets=False).
        """
        total = 0
        with pyshark.FileCapture(
            pcap_path,
            only_summaries=True,
            keep_packets=False
        ) as capture:
            for _ in capture:
                total += 1
        return total
