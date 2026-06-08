from typing import Dict, List
from core.packet_processor import PacketProcessor


class SecurityAnalyzer(PacketProcessor):
    def __init__(self):
        self.threats_detected: List[dict] = []
        self.port_scan_attempts: int = 0

    def process_packet(self, packet) -> None:
        self._detect_port_scans(packet)

    def _detect_port_scans(self, packet) -> None:
        try:
            if hasattr(packet, 'tcp') and getattr(packet.tcp, 'flags', None) == '0x0002':
                self.port_scan_attempts += 1
                self.threats_detected.append({
                    'type': 'port_scan',
                    'src_ip': getattr(packet.ip, 'src', 'unknown'),
                    'timestamp': getattr(packet, 'sniff_time', 'unknown'),
                })
        except AttributeError:
            pass

    def get_stats(self) -> Dict:
        return {
            'threats_detected': len(self.threats_detected),
            'port_scan_attempts': self.port_scan_attempts,
        }
