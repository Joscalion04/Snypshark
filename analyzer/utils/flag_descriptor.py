"""
TCP Flag Descriptor Module

Converts numeric TCP flag combinations to human-readable descriptions
using bitmask operations for accurate flag detection.
"""

from typing import Dict

class TCPFlagDescriptor:
    """
    Handles conversion between numeric TCP flags and their textual representations.
    Implements Singleton pattern to avoid duplicate flag mappings in memory.
    """
    
    _instance = None
    _flag_map = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
        0x40: "ECE",
        0x80: "CWR",
        # Common combinations
        0x12: "SYN+ACK",
        0x11: "FIN+ACK",
        0x14: "RST+ACK",
        0x18: "PSH+ACK",
        0x13: "SYN+FIN+ACK"
    }

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def describe_flags(self, flag_value: int) -> str:
        """
        Convert numeric TCP flags to human-readable string
        
        Args:
            flag_value: Integer representation of TCP flags
            
        Returns:
            String describing the flag combination (e.g. "SYN+ACK")
            Returns hex value if combination isn't predefined
        """
        try:
            # Check for known combinations first
            if flag_value in self._flag_map:
                return self._flag_map[flag_value]
            
            # Build description dynamically for unknown combinations
            flags = []
            for mask, name in self._flag_map.items():
                if mask <= 0x20 and flag_value & mask:
                    flags.append(name)
            
            return "+".join(flags) if flags else f"0x{flag_value:02x}"
        except (TypeError, ValueError):
            return f"Invalid flags: {flag_value}"

    def get_all_known_flags(self) -> Dict[int, str]:
        """Return copy of the flag mapping dictionary"""
        return self._flag_map.copy()


# Singleton instance for easy import
flag_descriptor = TCPFlagDescriptor()