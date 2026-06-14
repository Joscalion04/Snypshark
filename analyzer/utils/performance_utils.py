import gc
import multiprocessing
from typing import Any, Dict

import psutil


def optimize_memory_settings():
    """Optimiza la configuración de memoria para mejor rendimiento"""
    gc.set_threshold(70000, 10, 10)  # Configurar garbage collector

    # Pre-cargar bibliotecas comunes
    try:
        import numpy as np

        np.zeros(1)  # Pre-cargar numpy
    except ImportError:
        pass

    try:
        import pandas as pd

        pd.DataFrame()  # Pre-cargar pandas
    except ImportError:
        pass


def get_optimal_workers(file_size_mb: float) -> int:
    """Determina el número óptimo de workers basado en el tamaño del archivo"""
    cpu_count = multiprocessing.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)

    # Lógica basada en tamaño de archivo y recursos del sistema
    if file_size_mb < 10:  # < 10 MB
        workers = min(2, cpu_count)
    elif file_size_mb < 100:  # < 100 MB
        workers = min(4, cpu_count)
    elif file_size_mb < 500:  # < 500 MB
        workers = min(6, cpu_count)
    elif file_size_mb < 1024:  # < 1 GB
        workers = min(8, cpu_count)
    else:  # > 1 GB
        workers = min(12, cpu_count)

    # Ajustar basado en memoria disponible
    if memory_gb < 4:
        workers = min(workers, 4)
    elif memory_gb < 8:
        workers = min(workers, 8)

    return max(1, workers)


def get_system_info() -> Dict[str, Any]:
    """Obtiene información del sistema"""
    try:
        import platform

        return {
            "system": platform.system(),
            "processor": platform.processor(),
            "cpu_count": multiprocessing.cpu_count(),
            "total_memory_gb": psutil.virtual_memory().total / (1024**3),
            "available_memory_gb": psutil.virtual_memory().available / (1024**3),
            "python_version": platform.python_version(),
        }
    except ImportError:
        return {}


def monitor_memory_usage() -> Dict[str, float]:
    """Monitorea el uso de memoria actual"""
    process = psutil.Process()
    return {
        "memory_rss_mb": process.memory_info().rss / (1024**2),
        "memory_vms_mb": process.memory_info().vms / (1024**2),
        "memory_percent": process.memory_percent(),
        "cpu_percent": process.cpu_percent(),
    }
