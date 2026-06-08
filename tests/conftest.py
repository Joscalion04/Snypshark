import pytest
from core.analyzer import PCAPAnalyzer
from utils.flag_descriptor import TCPFlagDescriptor


class MockLayer:
    """Minimal packet layer stub."""

    def __init__(self, name: str, **attrs):
        self.layer_name = name
        for key, value in attrs.items():
            setattr(self, key, value)


class MockPacket:
    """Minimal packet stub that mimics the pyshark packet interface."""

    def __init__(self, layers=None, length: int = 100):
        self.layers = layers or []
        self.length = length
        self.sniff_time = None

    def __str__(self) -> str:
        return "mock packet content"


@pytest.fixture
def sample_packet():
    ip_layer  = MockLayer("ip",  src="192.168.1.1", dst="10.0.0.1", ttl="64")
    tcp_layer = MockLayer("tcp", flags="0x12", stream="1")
    return MockPacket(layers=[ip_layer, tcp_layer], length=100)


@pytest.fixture
def analyzer(tmp_path):
    dummy = tmp_path / "empty.pcap"
    dummy.touch()
    return PCAPAnalyzer(str(dummy))


@pytest.fixture
def flag_descriptor():
    return TCPFlagDescriptor()
