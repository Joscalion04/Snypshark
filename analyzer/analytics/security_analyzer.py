from typing import Dict, List
import pandas as pd
from core.packet_processor import PacketProcessor

class SecurityAnalyzer(PacketProcessor):
    """Analizador especializado en detección de amenazas de seguridad"""
    
    def __init__(self):
        self.threats_detected = []
        self.suspicious_activities = []
        self.port_scan_attempts = 0
        self.ddos_attempts = 0
    
    def process_packet(self, packet):
        """Analiza paquetes en busca de amenazas de seguridad"""
        self._detect_port_scans(packet)
        self._detect_ddos_attempts(packet)
        self._detect_suspicious_patterns(packet)
    
    def _detect_port_scans(self, packet):
        """Detección de escaneos de puertos"""
        try:
            if hasattr(packet, 'tcp') and hasattr(packet.tcp, 'flags'):
                flags = packet.tcp.flags
                if flags == '0x0002':  # SYN flag only
                    self.port_scan_attempts += 1
                    self.threats_detected.append({
                        'type': 'port_scan',
                        'src_ip': getattr(packet.ip, 'src', 'unknown'),
                        'timestamp': getattr(packet, 'sniff_time', 'unknown')
                    })
        except AttributeError:
            pass
    
    def _detect_ddos_attempts(self, packet):
        """Detección de intentos DDoS"""
        pass  # Implementación futura
    
    def _detect_suspicious_patterns(self, packet):
        """Detección de patrones sospechosos"""
        pass  # Implementación futura
    
    def get_stats(self) -> Dict:
        return {
            'threats_detected': len(self.threats_detected),
            'port_scan_attempts': self.port_scan_attempts,
            'ddos_attempts': self.ddos_attempts,
            'suspicious_activities': len(self.suspicious_activities)
        }