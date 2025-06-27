import pytest
from analyzer.analyzer import PCAPAnalyzer
from analyzer.utils.flag_descriptor import TCPFlagDescriptor

@pytest.fixture
def sample_packet():
    class MockPacket:
        class layers:
            tcp = type('TCP', (), {'flags': '0x12', 'stream': '1'})
            ip = type('IP', (), {'src': '192.168.1.1', 'ttl': '64'})
            icmp = type('ICMP', (), {'type': '8'})
            dns = type('DNS', (), {'qry_name': 'example.com'})
            
        def __init__(self):
            self.layers = self.layers()
            
    return MockPacket()

@pytest.fixture
def analyzer(tmp_path):
    dummy_file = tmp_path / "empty.pcap"
    dummy_file.touch()
    return PCAPAnalyzer(str(dummy_file))

@pytest.fixture
def flag_descriptor():
    return TCPFlagDescriptor()