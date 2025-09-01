from analyzer.utils.flag_descriptor import TCPFlagDescriptor

class TestTCPFlagDescriptor:
    def test_single_flags(self):
        descriptor = TCPFlagDescriptor()
        assert descriptor.describe_flags(0x01) == "FIN"
        assert descriptor.describe_flags(0x02) == "SYN"
        assert descriptor.describe_flags(0x04) == "RST"
    
    def test_combined_flags(self):
        descriptor = TCPFlagDescriptor()
        assert descriptor.describe_flags(0x12) == "SYN+ACK"
        assert descriptor.describe_flags(0x13) == "SYN+FIN+ACK"
    
    def test_unknown_combination(self):
        descriptor = TCPFlagDescriptor()
        assert descriptor.describe_flags(0x03) == "FIN+SYN"
        assert descriptor.describe_flags(0xFF) == "FIN+SYN+RST+PSH+ACK+URG+ECE+CWR"
    
    def test_invalid_input(self):
        descriptor = TCPFlagDescriptor()
        assert descriptor.describe_flags("invalid") == "Invalid flags: invalid"