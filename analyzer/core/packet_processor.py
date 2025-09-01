from abc import ABC, abstractmethod

class PacketProcessor(ABC):
    """Interfaz base para todos los procesadores de paquetes"""
    
    @abstractmethod
    def process_packet(self, packet) -> None:
        """Procesa un paquete individual"""
        raise NotImplementedError
    
    def flush(self) -> None:
        """Limpia buffers internos (opcional)"""
        pass
    
    def get_stats(self) -> dict:
        """Devuelve estadísticas del procesador"""
        return {}