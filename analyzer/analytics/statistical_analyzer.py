from typing import Dict, List

import numpy as np

from core.packet_processor import PacketProcessor
from config.constants import SecurityThresholds


class StatisticalAnalyzer(PacketProcessor):
    """Collects packet-level metrics and derives descriptive statistics."""

    def __init__(self):
        self.packet_sizes: List[int] = []
        self.inter_arrival_times: List[float] = []
        self._last_packet_time = None

    # ------------------------------------------------------------------
    # PacketProcessor interface
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> None:
        try:
            size = int(getattr(packet, 'length', 0))
            self.packet_sizes.append(size)

            current_time = getattr(packet, 'sniff_time', None)
            if self._last_packet_time is not None and current_time is not None:
                delta = (current_time - self._last_packet_time).total_seconds()
                if delta >= 0:
                    self.inter_arrival_times.append(delta)
            self._last_packet_time = current_time

        except (AttributeError, ValueError):
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_anomalous_count(self) -> int:
        """Packets whose size exceeds ANOMALY_THRESHOLD standard deviations."""
        if len(self.packet_sizes) < 2:
            return 0
        arr = np.array(self.packet_sizes, dtype=float)
        std = arr.std()
        if std == 0:
            return 0
        z_scores = np.abs((arr - arr.mean()) / std)
        return int((z_scores > SecurityThresholds.ANOMALY_THRESHOLD).sum())

    def get_stats(self) -> Dict:
        sizes = np.array(self.packet_sizes, dtype=float)
        times = np.array(self.inter_arrival_times, dtype=float)

        stats: Dict = {
            'total_packets': len(self.packet_sizes),
            'anomalous_packets': self.get_anomalous_count(),
        }

        if len(sizes) > 0:
            stats.update({
                'packet_size_mean': float(sizes.mean()),
                'packet_size_std':  float(sizes.std()),
                'packet_size_min':  int(sizes.min()),
                'packet_size_max':  int(sizes.max()),
            })

        if len(times) > 0:
            stats.update({
                'inter_arrival_mean_ms': float(times.mean() * 1000),
                'inter_arrival_std_ms':  float(times.std() * 1000),
                'inter_arrival_min_ms':  float(times.min() * 1000),
                'inter_arrival_max_ms':  float(times.max() * 1000),
            })

        return stats
