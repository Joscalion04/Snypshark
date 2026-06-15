from datetime import datetime
from typing import Dict, List

import pandas as pd
from config.constants import SecurityThresholds
from core.packet_processor import PacketProcessor

_LAYER_PRIORITY = ("http", "dns", "tcp", "udp", "icmp")


class TimelineAnalyzer(PacketProcessor):
    """Records per-packet timestamps and derives time-series traffic stats."""

    def __init__(self, resolution: str = "1min"):
        self.resolution = resolution
        self._records: List[Dict] = []

    # ------------------------------------------------------------------
    # PacketProcessor interface
    # ------------------------------------------------------------------

    def process_packet(self, packet) -> None:
        try:
            timestamp = getattr(packet, "sniff_time", datetime.now())
            protocol = self._dominant_protocol(packet)
            size = int(getattr(packet, "length", 0))
            self._records.append(
                {
                    "timestamp": timestamp,
                    "protocol": protocol,
                    "size": size,
                }
            )
        except (AttributeError, ValueError):
            pass

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _dominant_protocol(self, packet) -> str:
        layer_names = {layer.layer_name for layer in getattr(packet, "layers", [])}
        for proto in _LAYER_PRIORITY:
            if proto in layer_names:
                return proto
        return "other"

    def _build_timeline(self) -> pd.DataFrame:
        if not self._records:
            return pd.DataFrame()
        df = pd.DataFrame(self._records)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        timeline = (
            df.set_index("timestamp")
            .resample(self.resolution)
            .agg(packet_count=("size", "count"), total_bytes=("size", "sum"))
        )
        return timeline

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_burst_windows(self) -> List[str]:
        """
        Time windows where packets/s exceeded DDOS_THRESHOLD.
        Resolution is '1min', so threshold is scaled to packets/minute.
        """
        timeline = self._build_timeline()
        if timeline.empty:
            return []
        # Convert DDOS_THRESHOLD (pkt/s) to packets per resolution window
        seconds_per_window = pd.tseries.frequencies.to_offset(self.resolution).nanos / 1e9
        pkt_threshold = SecurityThresholds.DDOS_THRESHOLD * seconds_per_window
        burst_idx = timeline[timeline["packet_count"] >= pkt_threshold].index
        return [str(ts) for ts in burst_idx]

    def get_timeline_stats(self) -> Dict:
        timeline = self._build_timeline()
        if timeline.empty:
            return {}
        peak_idx = timeline["total_bytes"].idxmax()
        return {
            "peak_traffic_time": (
                peak_idx.isoformat() if hasattr(peak_idx, "isoformat") else str(peak_idx)
            ),
            "max_packets_per_window": int(timeline["packet_count"].max()),
            "max_bytes_per_window": int(timeline["total_bytes"].max()),
            "resolution": self.resolution,
            "windows": len(timeline),
        }

    def get_stats(self) -> Dict:
        stats = {
            "timeline_records": len(self._records),
            "resolution": self.resolution,
            "burst_windows": len(self.get_burst_windows()),
        }
        stats.update(self.get_timeline_stats())
        return stats
