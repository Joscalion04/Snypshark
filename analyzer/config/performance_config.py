import multiprocessing
from typing import Any, Dict

import psutil


class PerformanceConfig:
    """Configuración de rendimiento para el analizador"""

    # Configuración basada en el tamaño del archivo
    CONFIG_PROFILES = {
        "small": {"max_workers": 2, "buffer_size": 500, "use_ek": True},
        "medium": {"max_workers": 4, "buffer_size": 1000, "use_ek": True},
        "large": {"max_workers": 6, "buffer_size": 2000, "use_ek": True},
        "huge": {"max_workers": 8, "buffer_size": 5000, "use_ek": True},
        "massive": {"max_workers": 12, "buffer_size": 10000, "use_ek": True},
    }

    @staticmethod
    def get_optimal_config(pcap_path: str) -> Dict[str, Any]:
        """Configuración optimizada según tamaño del archivo y recursos del sistema."""
        try:
            import os

            file_size_mb = os.path.getsize(pcap_path) / (1024 * 1024)
            return PerformanceConfig.get_config_by_size(file_size_mb)
        except OSError:
            return PerformanceConfig.CONFIG_PROFILES["medium"]

    @staticmethod
    def get_config_by_size(file_size_mb: float) -> Dict[str, Any]:
        """Obtiene configuración basada en el tamaño del archivo"""
        cpu_count = multiprocessing.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)

        if file_size_mb < 10:
            profile = "small"
        elif file_size_mb < 100:
            profile = "medium"
        elif file_size_mb < 500:
            profile = "large"
        elif file_size_mb < 1024:
            profile = "huge"
        else:
            profile = "massive"

        config = PerformanceConfig.CONFIG_PROFILES[profile].copy()

        # Ajustar basado en recursos del sistema
        config["max_workers"] = min(config["max_workers"], cpu_count)

        if memory_gb < 4:
            config["max_workers"] = min(config["max_workers"], 4)
            config["buffer_size"] = min(config["buffer_size"], 1000)
        elif memory_gb < 8:
            config["max_workers"] = min(config["max_workers"], 8)

        return config

    @staticmethod
    def get_optimal_workers(file_size_mb: float) -> int:
        """Obtiene el número óptimo de workers"""
        config = PerformanceConfig.get_config_by_size(file_size_mb)
        return config["max_workers"]
