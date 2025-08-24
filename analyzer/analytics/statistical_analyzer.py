from typing import Dict
import numpy as np
from core.packet_processor import PacketProcessor

class StatisticalAnalyzer(PacketProcessor):
    """Analizador estadístico para métricas de red"""
    
    def __init__(self):
        self.packet_sizes = []
        self.inter_arrival_times = []
        self.last_packet_time = None
    
    def process_packet(self, packet):
        """Recolecta datos estadísticos de paquetes"""
        try:
            # Tamaño del paquete
            size = int(getattr(packet, 'length', 0))
            self.packet_sizes.append(size)
            
            # Tiempo entre paquetes
            current_time = getattr(packet, 'sniff_time', None)
            if self.last_packet_time and current_time:
                time_diff = (current_time - self.last_packet_time).total_seconds()
                self.inter_arrival_times.append(time_diff)
            
            self.last_packet_time = current_time
            
        except (AttributeError, ValueError):
            pass
    
    def get_stats(self) -> Dict:
        """Calcula estadísticas descriptivas"""
        sizes = np.array(self.packet_sizes)
        times = np.array(self.inter_arrival_times)
        
        stats = {
            'total_packets': len(self.packet_sizes),
            'packet_size_mean': float(np.mean(sizes)) if len(sizes) > 0 else 0,
            'packet_size_std': float(np.std(sizes)) if len(sizes) > 0 else 0,
            'packet_size_min': int(np.min(sizes)) if len(sizes) > 0 else 0,
            'packet_size_max': int(np.max(sizes)) if len(sizes) > 0 else 0,
        }
        
        if len(times) > 0:
            stats.update({
                'inter_arrival_mean': float(np.mean(times)),
                'inter_arrival_std': float(np.std(times)),
                'inter_arrival_min': float(np.min(times)),
                'inter_arrival_max': float(np.max(times)),
            })
        
        return stats