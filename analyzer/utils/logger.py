import logging
import sys
from typing import Optional

_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Prevents "No handlers could be found" warnings when imported as a library.
logging.getLogger("snypshark").addHandler(logging.NullHandler())


def configure_logging(level: str = "WARNING", log_file: Optional[str] = None) -> None:
    root = logging.getLogger("snypshark")
    root.setLevel(getattr(logging, level.upper(), logging.WARNING))
    # Drop all non-NullHandler handlers before adding new ones.
    root.handlers = [h for h in root.handlers if isinstance(h, logging.NullHandler)]

    formatter = logging.Formatter(_FORMAT, datefmt=_DATE_FORMAT)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    root.addHandler(stderr_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"snypshark.{name}")
