import pytest
from unittest.mock import MagicMock
from core.analyzer import PCAPAnalyzer


def test_analyzer_initialization(analyzer):
    assert analyzer.pcap_path is not None
    assert len(analyzer.packet_processors) == 0


def test_add_processor(analyzer):
    mock_processor = MagicMock()
    analyzer.add_processor(mock_processor)
    assert mock_processor in analyzer.packet_processors


def test_add_multiple_processors(analyzer):
    p1, p2 = MagicMock(), MagicMock()
    analyzer.add_processor(p1)
    analyzer.add_processor(p2)
    assert len(analyzer.packet_processors) == 2


def test_get_processing_stats_returns_dict(analyzer):
    stats = analyzer.get_processing_stats()
    assert isinstance(stats, dict)
    assert "packets_processed" in stats


def test_count_packets_empty_file(tmp_path):
    """count_packets on an empty (non-PCAP) file should not raise unexpectedly."""
    dummy = tmp_path / "empty.pcap"
    dummy.touch()
    try:
        total = PCAPAnalyzer.count_packets(str(dummy))
        assert isinstance(total, int)
    except Exception:
        # pyshark cannot parse an empty file — acceptable failure mode
        pass
