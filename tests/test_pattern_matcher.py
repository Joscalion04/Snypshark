from unittest.mock import MagicMock

from processors.pattern_processor import PatternProcessor


class TestPatternProcessor:
    def test_matches_custom_pattern(self):
        processor = PatternProcessor(patterns=r"test|pattern")
        mock_packet = MagicMock()
        mock_packet.__str__ = MagicMock(return_value="This is a test pattern")

        processor.process_packet(mock_packet)

        assert processor.pattern_occurrences["test"] == 1
        assert processor.pattern_occurrences["pattern"] == 1

    def test_no_matches_returns_empty(self):
        processor = PatternProcessor()
        mock_packet = MagicMock()
        mock_packet.__str__ = MagicMock(return_value="Normal traffic data")

        processor.process_packet(mock_packet)

        assert len(processor.pattern_occurrences) == 0

    def test_multiple_occurrences_accumulate(self):
        processor = PatternProcessor(patterns=r"http")
        mock_packet = MagicMock()
        mock_packet.__str__ = MagicMock(return_value="http request http response")

        processor.process_packet(mock_packet)

        assert processor.pattern_occurrences["http"] == 2

    def test_get_stats_structure(self):
        processor = PatternProcessor(patterns=r"ssh")
        mock_packet = MagicMock()
        mock_packet.__str__ = MagicMock(return_value="ssh connection")

        processor.process_packet(mock_packet)
        stats = processor.get_stats()

        assert "pattern_matches" in stats
        assert "total_matches" in stats
        assert stats["total_matches"] >= 1

    def test_case_insensitive_matching(self):
        processor = PatternProcessor(patterns=r"google")
        mock_packet = MagicMock()
        mock_packet.__str__ = MagicMock(return_value="GOOGLE DNS request")

        processor.process_packet(mock_packet)

        assert processor.pattern_occurrences.get("google", 0) == 1
