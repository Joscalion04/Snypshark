import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Callable, Optional, Dict, Any
import time
from collections import defaultdict
import psutil

from .packet_processor import PacketProcessor

class ParallelProcessingEngine:
    """Motor de procesamiento paralelo optimizado para análisis de paquetes"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or self._get_optimal_workers()
        self._lock = threading.Lock()
        self._stats = {
            'packets_processed': 0,
            'processing_time': 0,
            'workers_used': self.max_workers
        }
        self._worker_stats = defaultdict(lambda: {'packets': 0, 'time': 0})
    
    def _get_optimal_workers(self) -> int:
        """Calcula el número óptimo de workers basado en los recursos del sistema"""
        cpu_count = psutil.cpu_count(logical=False) or 4  # CPUs físicos
        memory_gb = psutil.virtual_memory().total / (1024 ** 3)
        
        # Lógica de optimización
        if memory_gb < 4:
            return min(cpu_count, 4)
        elif memory_gb < 8:
            return min(cpu_count, 8)
        else:
            return min(cpu_count, 12)
    
    def process_packets(self, packets: List, processors: List[PacketProcessor],
                       progress_callback: Optional[Callable[[int], None]] = None) -> Dict[str, Any]:
        """
        Procesa un lote de paquetes en paralelo usando múltiples workers
        
        Args:
            packets: Lista de paquetes a procesar
            processors: Lista de procesadores a aplicar
            progress_callback: Función callback para reportar progreso
        
        Returns:
            Diccionario con estadísticas del procesamiento
        """
        start_time = time.time()
        total_packets = len(packets)
        
        if total_packets == 0:
            return self._stats
        
        # Dividir paquetes en chunks para mejor balance de carga
        chunk_size = max(1, total_packets // (self.max_workers * 2))
        chunks = [packets[i:i + chunk_size] for i in range(0, total_packets, chunk_size)]
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for chunk_index, chunk in enumerate(chunks):
                future = executor.submit(
                    self._process_chunk,
                    chunk, processors, chunk_index
                )
                futures[future] = chunk_index
            
            # Procesar resultados conforme se completan
            completed = 0
            for future in as_completed(futures):
                try:
                    result = future.result()
                    chunk_index = futures[future]
                    completed += result['processed']
                    
                    # Actualizar estadísticas
                    with self._lock:
                        self._stats['packets_processed'] += result['processed']
                        self._worker_stats[chunk_index] = {
                            'packets': result['processed'],
                            'time': result['processing_time']
                        }
                    
                    if progress_callback:
                        progress_callback(completed)
                        
                except Exception as e:
                    print(f"⚠️ Error processing chunk: {e}")
        
        self._stats['processing_time'] = time.time() - start_time
        return self._stats
    
    def _process_chunk(self, chunk: List, processors: List[PacketProcessor], 
                      chunk_index: int) -> Dict[str, Any]:
        """
        Procesa un chunk de paquetes (ejecutado por cada worker)
        """
        chunk_start = time.time()
        processed = 0
        
        for packet in chunk:
            try:
                # Aplicar todos los procesadores al paquete
                for processor in processors:
                    processor.process_packet(packet)
                processed += 1
            except Exception as e:
                # Error silencioso para no interrumpir el procesamiento
                continue
        
        return {
            'processed': processed,
            'processing_time': time.time() - chunk_start,
            'chunk_index': chunk_index,
            'chunk_size': len(chunk)
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Obtiene estadísticas detalladas del procesamiento"""
        stats = self._stats.copy()
        
        # Calcular métricas adicionales
        if stats['processing_time'] > 0:
            stats['packets_per_second'] = stats['packets_processed'] / stats['processing_time']
            stats['throughput_mbps'] = (stats['packets_processed'] * 1500) / (stats['processing_time'] * 1024 * 1024)  # Estimación
        
        # Estadísticas por worker
        worker_stats = {}
        for worker_id, data in self._worker_stats.items():
            if data['time'] > 0:
                worker_stats[worker_id] = {
                    'packets_processed': data['packets'],
                    'processing_time': data['time'],
                    'packets_per_second': data['packets'] / data['time'] if data['time'] > 0 else 0
                }
        
        stats['worker_stats'] = worker_stats
        return stats
    
    def reset_stats(self):
        """Reinicia las estadísticas del motor"""
        self._stats = {
            'packets_processed': 0,
            'processing_time': 0,
            'workers_used': self.max_workers
        }
        self._worker_stats.clear()
    
    def optimize_batch_size(self, sample_packets: List) -> int:
        """
        Calcula el tamaño óptimo de batch basado en una muestra de paquetes
        """
        if not sample_packets:
            return 1000
        
        # Estimación basada en complejidad promedio de los paquetes
        avg_complexity = self._estimate_packet_complexity(sample_packets)
        
        # Tamaño de batch basado en complejidad y recursos
        if avg_complexity < 0.3:  # Paquetes simples
            return 2000
        elif avg_complexity < 0.7:  # Complejidad media
            return 1000
        else:  # Paquetes complejos
            return 500
    
    def _estimate_packet_complexity(self, packets: List) -> float:
        """
        Estima la complejidad promedio de procesamiento de los paquetes
        """
        if not packets:
            return 0.5  # Valor por defecto
        
        complexities = []
        for packet in packets[:100]:  # Muestra de 100 paquetes
            try:
                # Estimación basada en número de capas y tamaño
                layers = len(getattr(packet, 'layers', []))
                size = int(getattr(packet, 'length', 0))
                
                # Fórmula simple de complejidad (0-1)
                complexity = min(1.0, (layers / 10) + (size / 5000))
                complexities.append(complexity)
            except:
                complexities.append(0.5)  # Valor por defecto en caso de error
        
        return sum(complexities) / len(complexities) if complexities else 0.5

class BatchProcessor:
    """Procesador por lotes con optimización de memoria"""
    
    def __init__(self, batch_size: int = 1000):
        self.batch_size = batch_size
        self.current_batch = []
        self.parallel_engine = ParallelProcessingEngine()
    
    def add_packet(self, packet) -> bool:
        """
        Añade un paquete al batch actual
        Returns: True si el batch está lleno y listo para procesar
        """
        self.current_batch.append(packet)
        return len(self.current_batch) >= self.batch_size
    
    def process_batch(self, processors: List[PacketProcessor]) -> Dict[str, Any]:
        """Procesa el batch actual y lo limpia"""
        if not self.current_batch:
            return {}
        
        stats = self.parallel_engine.process_packets(self.current_batch, processors)
        self.current_batch = []  # Limpiar batch
        return stats
    
    def flush(self, processors: List[PacketProcessor]) -> Dict[str, Any]:
        """Procesa los paquetes restantes en el batch"""
        if not self.current_batch:
            return {}
        
        return self.process_batch(processors)
    
    def optimize_batch_size(self, sample_packets: List):
        """Optimiza el tamaño del batch basado en una muestra"""
        self.batch_size = self.parallel_engine.optimize_batch_size(sample_packets)
        return self.batch_size