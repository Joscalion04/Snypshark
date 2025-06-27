from analyzer.utils.pattern_matcher import PatternMatcher
from unittest.mock import MagicMock

class TestPatternMatcher:
    def test_pattern_matching(self):
        matcher = PatternMatcher(patterns=r'test|pattern')
        mock_packet = MagicMock()
        mock_packet.__str__.return_value = "This is a test pattern"
        
        matcher.process_packet(mock_packet)
        assert matcher.pattern_occurrences['test'] == 1
        assert matcher.pattern_occurrences['pattern'] == 1
    
    def test_no_matches(self):
        matcher = PatternMatcher()
        mock_packet = MagicMock()
        mock_packet.__str__.return_value = "Normal traffic"
        
        matcher.process_packet(mock_packet)
        assert len(matcher.pattern_occurrences) == 0