from analyzer.ui.osi_layers import OSILayerAnalyzer
from unittest.mock import patch, MagicMock

class TestOSILayerAnalyzer:
    @patch('pyshark.FileCapture')
    def test_analyze(self, mock_capture):
        mock_packet = MagicMock()
        mock_packet.protocol = "eth:ip:tcp:http"
        mock_capture.return_value = [mock_packet]
        
        OSILayerAnalyzer.analyze("dummy.pcap", sample_size=1)
        mock_capture.assert_called_once_with("dummy.pcap", only_summaries=True)