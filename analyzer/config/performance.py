import os
from typing import Dict, Any

class PerformanceConfig:
    """Configuración de rendimiento para el analizador"""
    
    # Configuración basada en el tamaño del archivo
    CONFIG_PROFILES = {
        'small': {'max_workers': 2, 'buffer_size': 500, 'use_ek': True},
        'medium': {'max_workers': 4, 'buffer_size': 1000, 'use_ek': True},
        'large': {'max_workers': 8, 'buffer_size': 2000, 'use_ek': True},
        'huge': {'max_workers': 12, 'buffer_size': 5000, 'use_ek': True}
    }
    
    @staticmethod
    def get_optimized_config(pcap_path: str) -> Dict[str, Any]:
        """Obtiene configuración optimizada basada en el tamaño del archivo"""
        try:
            file_size = os.path.getsize(pcap_path) / (1024 * 1024)  # MB
            
            if file_size < 10:    # < 10 MB
                return PerformanceConfig.CONFIG_PROFILES['small']
            elif file_size < 100: # < 100 MB
                return PerformanceConfig.CONFIG_PROFILES['medium']
            elif file_size < 500: # < 500 MB
                return PerformanceConfig.CONFIG_PROFILES['large']
            else:                 # > 500 MB
                return PerformanceConfig.CONFIG_PROFILES['huge']
                
        except OSError:
            return PerformanceConfig.CONFIG_PROFILES['medium']
    
    @staticmethod
    def optimize_memory():
        """Optimiza la configuración de memoria de Python"""
        import gc
        
        # Configurar garbage collector
        gc.set_threshold(70000, 10, 10)
        
        # Prevenir fragmentación de memoria
        try:
            import numpy as np
            np.zeros(1)  # Pre-cargar numpy
        except ImportError:
            pass