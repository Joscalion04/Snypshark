from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict


class TelemetryEventType:
    """String constants for the TelemetryEvent.type field.

    Using plain strings (not an Enum) keeps downstream comparisons simple
    and lets future sources define their own types without subclassing.
    """

    NETWORK_PACKET = "network_packet"
    PROCESS_START  = "process_start"
    PROCESS_END    = "process_end"
    LOG_ENTRY      = "log_entry"
    CONNECTION     = "connection"
    HOST_CONTEXT   = "host_context"


@dataclass
class TelemetryEvent:
    """Normalized unit of telemetry flowing through the analysis pipeline.

    Every TelemetrySource emits these; every TelemetryProcessor consumes them.
    The *type* field determines which processors handle the event — processors
    ignore types they do not recognize.

    Attributes:
        type:      One of TelemetryEventType or any custom string constant.
        timestamp: When the event occurred (not when it was emitted).
        source_id: Opaque identifier for the source that produced this event
                   (e.g. file path, interface name, "journald").
        payload:   Source-specific data.  Keys are documented by each source.
    """

    type:      str
    timestamp: datetime
    source_id: str
    payload:   Dict[str, Any] = field(default_factory=dict)
