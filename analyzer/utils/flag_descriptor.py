class TCPFlagDescriptor:
    """Converts raw TCP flag values to human-readable strings."""

    # Ordered by bit position (low → high)
    _BITS = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
        0x40: "ECE",
        0x80: "CWR",
    }

    def describe_flags(self, flags) -> str:
        try:
            if isinstance(flags, str):
                value = int(flags, 16) if flags.startswith("0x") else int(flags)
            else:
                value = int(flags)
        except (ValueError, TypeError):
            return f"Invalid flags: {flags}"

        names = [name for bit, name in self._BITS.items() if value & bit]
        return "+".join(names) if names else f"0x{value:02x}"
