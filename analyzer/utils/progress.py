import sys
from typing import Optional

class ProgressBar:
    """
    Barra de progreso simple sin dependencias externas.
    Llama a .update(current) en cada iteración y .finish() al final.
    """
    def __init__(self, total: int, length: int = 30, prefix: str = ""):
        self.total = max(1, total)
        self.length = max(10, length)
        self.prefix = prefix
        self.current = 0
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
        bar = "#" * filled + "-" * (self.length - filled)
        pct = f"{ratio * 100:6.2f}%"
        msg = f"\r{self.prefix} [{bar}] {pct}  ({self.current}/{self.total})"
        sys.stdout.write(msg)
        sys.stdout.flush()
