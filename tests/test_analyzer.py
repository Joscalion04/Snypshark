import pytest
from unittest.mock import MagicMock

def test_analyzer_initialization(analyzer):
    assert analyzer.pcap_path is not None
    assert len(analyzer.packet_processors) == 0

def test_add_processor(analyzer):
    mock_processor = MagicMock()
    analyzer.add_processor(mock_processor)
    assert mock_processor in analyzer.packet_processors

def test_process_packet(analyzer, sample_packet):
    mock_processor = MagicMock()
    analyzer.add_processor(mock_processor)
    analyzer._process_packet(sample_packet)
    mock_processor.process_packet.assert_called_once_with(sample_packet)