from typing import Dict, List
import pandas as pd
from datetime import datetime
from core.packet_processor import PacketProcessor

class TimelineAnalyzer(PacketProcessor):
    """Analizador de línea de tiempo para tráfico de red"""
    
    def __init__(self, resolution: str = '1min'):
        self.resolution = resolution
        self.timeline_data = []
        self.protocol_timeline = {}
    
    def process_packet(self, packet):
        """Registra datos temporales de paquetes"""
        try:
            timestamp = getattr(packet, 'sniff_time', datetime.now())
            protocol = None
            
            # Determinar protocolo principal
            for layer in packet.layers:
                if layer.layer_name in ['tcp', 'udp', 'icmp', 'dns', 'http']:
                    protocol = layer.layer_name
                    break
            
            self.timeline_data.append({
                'timestamp': timestamp,
                'protocol': protocol,
                'size': int(getattr(packet, 'length', 0))
            })
            
        except (AttributeError, ValueError):
            pass
    
    def get_timeline_stats(self) -> Dict:
        """Genera estadísticas de línea de tiempo"""
        if not self.timeline_data:
            return {}
        
        df = pd.DataFrame(self.timeline_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        timeline = df.set_index('timestamp').resample(self.resolution).agg({
            'size': ['count', 'sum'],
            'protocol': lambda x: x.mode()[0] if not x.mode().empty else 'unknown'
        })
        
        timeline.columns = ['packet_count', 'total_bytes', 'dominant_protocol']
        
        return timeline.to_dict(orient='index')
    
    def get_stats(self) -> Dict:
        return {
            'timeline_records': len(self.timeline_data),
            'resolution': self.resolution
        }