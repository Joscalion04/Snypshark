from utils.flag_descriptor import TCPFlagDescriptor


class TestTCPFlagDescriptor:
    def setup_method(self):
        self.descriptor = TCPFlagDescriptor()

    def test_single_fin(self):
        assert self.descriptor.describe_flags(0x01) == "FIN"

    def test_single_syn(self):
        assert self.descriptor.describe_flags(0x02) == "SYN"

    def test_single_rst(self):
        assert self.descriptor.describe_flags(0x04) == "RST"

    def test_combined_syn_ack(self):
        assert self.descriptor.describe_flags(0x12) == "SYN+ACK"

    def test_combined_fin_syn_ack(self):
        assert self.descriptor.describe_flags(0x13) == "FIN+SYN+ACK"

    def test_combined_fin_syn(self):
        assert self.descriptor.describe_flags(0x03) == "FIN+SYN"

    def test_all_flags(self):
        assert self.descriptor.describe_flags(0xFF) == "FIN+SYN+RST+PSH+ACK+URG+ECE+CWR"

    def test_hex_string_input(self):
        assert self.descriptor.describe_flags("0x02") == "SYN"

    def test_invalid_string_input(self):
        result = self.descriptor.describe_flags("invalid")
        assert result == "Invalid flags: invalid"

    def test_zero_flags(self):
        result = self.descriptor.describe_flags(0x00)
        assert result == "0x00"
