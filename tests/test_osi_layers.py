from unittest.mock import MagicMock, patch

from ui.osi_visualizer import OSIVisualizer


class TestOSIVisualizer:
    @patch("pyshark.FileCapture")
    def test_analyze_calls_file_capture(self, mock_capture_class):
        mock_packet = MagicMock()
        mock_packet.protocol = "eth:ip:tcp:http"
        mock_packet.info = "GET / HTTP/1.1"

        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(return_value=iter([mock_packet]))
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_capture_class.return_value = mock_cm

        OSIVisualizer.analyze("dummy.pcap", sample_size=1)
        mock_capture_class.assert_called_once()

    @patch("pyshark.FileCapture")
    def test_get_layer_distribution_returns_dict(self, mock_capture_class):
        mock_packet = MagicMock()
        mock_packet.protocol = "eth:ip:tcp"

        mock_cm = MagicMock()
        mock_cm.__enter__ = MagicMock(return_value=iter([mock_packet]))
        mock_cm.__exit__ = MagicMock(return_value=False)
        mock_capture_class.return_value = mock_cm

        dist = OSIVisualizer.get_layer_distribution("dummy.pcap")
        assert isinstance(dist, dict)

    @patch("pyshark.FileCapture")
    def test_analyze_handles_exception_gracefully(self, mock_capture_class):
        mock_capture_class.side_effect = Exception("File not found")
        # Should not raise
        OSIVisualizer.analyze("bad.pcap", sample_size=1)
