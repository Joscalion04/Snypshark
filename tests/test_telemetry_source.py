"""
Unit tests for TelemetryEvent, TelemetryEventType, and TelemetrySource.

TelemetrySource is an ABC — tests drive it through a minimal concrete stub
(StubSource) defined here. No real I/O is performed.
"""
from datetime import datetime
from typing import Iterator
from unittest.mock import MagicMock, call, patch

import pytest

from core.telemetry_event import TelemetryEvent, TelemetryEventType
from core.telemetry_source import TelemetrySource


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(
    etype: str = TelemetryEventType.NETWORK_PACKET,
    source_id: str = "stub",
    payload: dict | None = None,
    ts: datetime | None = None,
) -> TelemetryEvent:
    return TelemetryEvent(
        type=etype,
        timestamp=ts or datetime(2024, 6, 1, 12, 0, 0),
        source_id=source_id,
        payload=payload or {},
    )


class StubSource(TelemetrySource):
    """Minimal concrete source for testing the ABC contract."""

    def __init__(self, events: list[TelemetryEvent] | None = None):
        self._events = events or []
        self.close_called = 0

    def stream_events(self) -> Iterator[TelemetryEvent]:
        yield from self._events

    def close(self) -> None:
        self.close_called += 1


class OverrideIdSource(TelemetrySource):
    """Concrete source with a custom source_id."""

    @property
    def source_id(self) -> str:
        return "custom-source-id"

    def stream_events(self) -> Iterator[TelemetryEvent]:
        return iter([])


# ---------------------------------------------------------------------------
# TelemetryEventType
# ---------------------------------------------------------------------------

class TestTelemetryEventType:
    def test_all_constants_are_strings(self):
        for attr in ("NETWORK_PACKET", "PROCESS_START", "PROCESS_END",
                     "LOG_ENTRY", "CONNECTION", "HOST_CONTEXT"):
            assert isinstance(getattr(TelemetryEventType, attr), str)

    def test_expected_constant_values(self):
        assert TelemetryEventType.NETWORK_PACKET == "network_packet"
        assert TelemetryEventType.PROCESS_START  == "process_start"
        assert TelemetryEventType.PROCESS_END    == "process_end"
        assert TelemetryEventType.LOG_ENTRY      == "log_entry"
        assert TelemetryEventType.CONNECTION     == "connection"
        assert TelemetryEventType.HOST_CONTEXT   == "host_context"

    def test_constants_are_distinct(self):
        constants = [
            TelemetryEventType.NETWORK_PACKET,
            TelemetryEventType.PROCESS_START,
            TelemetryEventType.PROCESS_END,
            TelemetryEventType.LOG_ENTRY,
            TelemetryEventType.CONNECTION,
            TelemetryEventType.HOST_CONTEXT,
        ]
        assert len(constants) == len(set(constants))


# ---------------------------------------------------------------------------
# TelemetryEvent
# ---------------------------------------------------------------------------

class TestTelemetryEvent:
    def test_construction_with_required_fields(self):
        ts = datetime(2024, 1, 1, 0, 0, 0)
        e = TelemetryEvent(
            type=TelemetryEventType.NETWORK_PACKET,
            timestamp=ts,
            source_id="pcap:/tmp/test.pcap",
        )
        assert e.type == "network_packet"
        assert e.timestamp == ts
        assert e.source_id == "pcap:/tmp/test.pcap"
        assert e.payload == {}

    def test_payload_defaults_to_empty_dict(self):
        e = _event()
        assert e.payload == {}
        assert isinstance(e.payload, dict)

    def test_payload_stored_as_provided(self):
        data = {"src": "192.168.1.1", "dst": "8.8.8.8", "port": 443}
        e = _event(payload=data)
        assert e.payload == data

    def test_payload_instances_are_independent(self):
        # Two events created without explicit payload must not share the same dict.
        e1 = _event()
        e2 = _event()
        e1.payload["key"] = "value"
        assert "key" not in e2.payload

    def test_equality_by_value(self):
        ts = datetime(2024, 6, 1, 12, 0, 0)
        e1 = TelemetryEvent("network_packet", ts, "src", {"a": 1})
        e2 = TelemetryEvent("network_packet", ts, "src", {"a": 1})
        assert e1 == e2

    def test_inequality_on_different_type(self):
        ts = datetime(2024, 6, 1, 12, 0, 0)
        e1 = TelemetryEvent("network_packet", ts, "src", {})
        e2 = TelemetryEvent("log_entry",      ts, "src", {})
        assert e1 != e2

    def test_inequality_on_different_timestamp(self):
        e1 = _event(ts=datetime(2024, 1, 1, 0, 0, 0))
        e2 = _event(ts=datetime(2024, 1, 1, 0, 0, 1))
        assert e1 != e2

    def test_inequality_on_different_source_id(self):
        e1 = _event(source_id="a")
        e2 = _event(source_id="b")
        assert e1 != e2

    def test_accepts_any_string_as_type(self):
        # Custom source types must be accepted without validation.
        e = _event(etype="custom_event_type")
        assert e.type == "custom_event_type"

    def test_type_field_is_string(self):
        e = _event()
        assert isinstance(e.type, str)

    def test_timestamp_field_is_datetime(self):
        e = _event()
        assert isinstance(e.timestamp, datetime)

    def test_repr_includes_type(self):
        e = _event(etype="network_packet")
        assert "network_packet" in repr(e)


# ---------------------------------------------------------------------------
# TelemetrySource (via StubSource)
# ---------------------------------------------------------------------------

class TestTelemetrySourceAbstract:
    def test_cannot_instantiate_abc_directly(self):
        with pytest.raises(TypeError):
            TelemetrySource()  # type: ignore[abstract]

    def test_subclass_without_stream_events_is_abstract(self):
        class Incomplete(TelemetrySource):
            pass

        with pytest.raises(TypeError):
            Incomplete()  # type: ignore[abstract]

    def test_stream_events_is_required(self):
        assert "stream_events" in TelemetrySource.__abstractmethods__

    def test_concrete_subclass_instantiates(self):
        src = StubSource()
        assert src is not None


class TestTelemetrySourceBehavior:
    def test_stream_events_yields_provided_events(self):
        events = [_event(), _event(etype=TelemetryEventType.LOG_ENTRY)]
        src = StubSource(events)
        result = list(src.stream_events())
        assert result == events

    def test_stream_events_empty_by_default(self):
        src = StubSource()
        assert list(src.stream_events()) == []

    def test_stream_events_returns_telemetry_event_instances(self):
        src = StubSource([_event()])
        for event in src.stream_events():
            assert isinstance(event, TelemetryEvent)

    def test_default_source_id_is_class_name(self):
        src = StubSource()
        assert src.source_id == "StubSource"

    def test_overridden_source_id_is_returned(self):
        src = OverrideIdSource()
        assert src.source_id == "custom-source-id"

    def test_close_is_callable_and_no_op_by_default(self):
        # TelemetrySource.close() must not raise when called with no override.
        class MinimalSource(TelemetrySource):
            def stream_events(self) -> Iterator[TelemetryEvent]:
                return iter([])

        src = MinimalSource()
        src.close()  # must not raise

    def test_close_called_on_context_manager_exit(self):
        src = StubSource()
        with src:
            assert src.close_called == 0
        assert src.close_called == 1

    def test_enter_returns_self(self):
        src = StubSource()
        result = src.__enter__()
        assert result is src

    def test_context_manager_yields_source(self):
        src = StubSource([_event()])
        with src as active:
            events = list(active.stream_events())
        assert len(events) == 1

    def test_close_called_on_exception_inside_context(self):
        src = StubSource()
        with pytest.raises(ValueError):
            with src:
                raise ValueError("simulated failure")
        assert src.close_called == 1

    def test_multiple_close_calls_do_not_raise(self):
        src = StubSource()
        src.close()
        src.close()
        assert src.close_called == 2

    def test_stream_events_called_multiple_times(self):
        # Each call to stream_events must produce a fresh iteration.
        events = [_event()]
        src = StubSource(events)
        first  = list(src.stream_events())
        second = list(src.stream_events())
        assert first == second
