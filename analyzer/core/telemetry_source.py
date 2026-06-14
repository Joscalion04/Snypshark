from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator

from .telemetry_event import TelemetryEvent


class TelemetrySource(ABC):
    """Abstract base for all telemetry input sources.

    A TelemetrySource knows how to open a data stream and yield normalized
    TelemetryEvent objects one at a time.  The analysis engine consumes only
    this interface — it has no knowledge of the underlying medium (PCAP file,
    live interface, journald, /proc, etc.).

    Subclasses must implement:
        stream_events() — the core generator that yields events.

    Subclasses should override:
        source_id       — a human-readable identifier (file path, iface name…).
        close()         — release file handles, sockets, or other resources.

    Usage (as context manager — preferred):
        with PCAPFileSource("capture.pcap") as src:
            for event in src.stream_events():
                engine.dispatch(event)

    Usage (manual):
        src = PCAPFileSource("capture.pcap")
        try:
            for event in src.stream_events():
                engine.dispatch(event)
        finally:
            src.close()
    """

    @property
    def source_id(self) -> str:
        """Identifies this source instance in TelemetryEvent.source_id fields."""
        return type(self).__name__

    @abstractmethod
    def stream_events(self) -> Iterator[TelemetryEvent]:
        """Yield TelemetryEvent objects until the source is exhausted or closed."""
        ...

    def close(self) -> None:  # noqa: B027 — intentional optional hook, not abstract
        """Release resources held by this source.

        Called automatically by __exit__.  Safe to call more than once.
        """

    def __enter__(self) -> TelemetrySource:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
