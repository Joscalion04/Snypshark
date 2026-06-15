import re
from collections import defaultdict

from core.packet_processor import PacketProcessor


class PatternProcessor(PacketProcessor):
    """
    Busca patrones sencillos en representaciones string del paquete.
    Evita romper el análisis si no hay payloads decodificables.
    """

    def __init__(self, patterns=None):
        self.pattern_occurrences = defaultdict(int)
        self.patterns = re.compile(
            patterns or r"microsoft|google|intel|login|http|https|ftp|ssh", re.IGNORECASE
        )

    def process_packet(self, packet) -> None:
        try:
            payload = str(packet)
            for m in self.patterns.findall(payload):
                self.pattern_occurrences[m.lower()] += 1
        except Exception:
            pass

    def get_stats(self):
        return {
            "pattern_matches": dict(self.pattern_occurrences),
            "total_matches": sum(self.pattern_occurrences.values()),
        }
