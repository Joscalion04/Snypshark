import re
import ipaddress
from typing import Optional, Union

def validate_pcap_file(file_path: str) -> tuple:
    """Valida si un archivo es un PCAP válido"""
    try:
        # Verificación básica de extensión
        if not file_path.lower().endswith(('.pcap', '.pcapng', '.cap')):
            return False, "File extension must be .pcap, .pcapng, or .cap"
        
        # Verificación de existencia y acceso
        import os
        if not os.path.exists(file_path):
            return False, "File does not exist"
        if not os.access(file_path, os.R_OK):
            return False, "File is not readable"
        
        # Verificación de tamaño
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return False, "File is empty"
        
        return True, "Valid PCAP file"
        
    except Exception as e:
        return False, f"Validation error: {str(e)}"

def is_valid_ip(ip: str) -> bool:
    """Valida si una cadena es una dirección IP válida"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_port(port: Union[str, int]) -> bool:
    """Valida si un puerto es válido"""
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_valid_mac(mac: str) -> bool:
    """Valida si una dirección MAC es válida"""
    mac_pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
    return bool(mac_pattern.match(mac))

def validate_time_range(start_time: str, end_time: str) -> tuple:
    """Valida un rango de tiempo"""
    try:
        from datetime import datetime
        start = datetime.fromisoformat(start_time)
        end = datetime.fromisoformat(end_time)
        
        if start >= end:
            return False, "Start time must be before end time"
        
        return True, "Valid time range"
    except ValueError:
        return False, "Invalid time format. Use ISO format: YYYY-MM-DD HH:MM:SS"