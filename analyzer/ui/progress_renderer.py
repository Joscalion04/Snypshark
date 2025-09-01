import sys
import time
from typing import Optional

class ProgressBar:
    """
    Barra de progreso con estilo mejorado y colores
    """
    def __init__(self, total: int, length: int = 40, prefix: str = ""):
        self.total = max(1, total)
        self.length = max(10, length)
        self.prefix = prefix
        self.current = 0
        self.start_time = time.time()
        self._render(0)

    def update(self, current: int) -> None:
        self.current = current
        self._render(self.current / self.total)

    def finish(self) -> None:
        self.current = self.total
        self._render(1.0)
        sys.stdout.write("\n")
        sys.stdout.flush()

    def _render(self, ratio: float) -> None:
        ratio = max(0.0, min(1.0, ratio))
        filled = int(self.length * ratio)
        
        # Barra con caracteres Unicode más bonitos
        bar = "█" * filled + "░" * (self.length - filled)
        
        # Porcentaje con color
        pct = f"{ratio * 100:6.2f}%"
        
        # Tiempo transcurrido y estimado
        elapsed = time.time() - self.start_time
        if ratio > 0:
            eta = elapsed * (1 - ratio) / ratio
            time_info = f" [Elapsed: {elapsed:.1f}s, ETA: {eta:.1f}s]"
        else:
            time_info = " [Starting...]"
        
        # Mensaje completo
        msg = f"\r{self.prefix} [{bar}] {pct} ({self.current:,}/{self.total:,}){time_info}"
        
        sys.stdout.write(msg)
        sys.stdout.flush()

class MultiProgressBar:
    """Múltiples barras de progreso para operaciones paralelas"""
    
    def __init__(self, num_bars: int, total: int, prefixes: list = None):
        self.num_bars = num_bars
        self.totals = [total] * num_bars
        self.currents = [0] * num_bars
        self.bars = []
        
        for i in range(num_bars):
            prefix = prefixes[i] if prefixes and i < len(prefixes) else f"Worker {i+1}"
            self.bars.append(ProgressBar(total, 20, prefix))
    
    def update(self, bar_index: int, value: int) -> None:
        if 0 <= bar_index < self.num_bars:
            self.currents[bar_index] = value
            self.bars[bar_index].update(value)
    
    def finish_all(self) -> None:
        for bar in self.bars:
            bar.finish()