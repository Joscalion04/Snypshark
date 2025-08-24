import subprocess
import sys
from pathlib import Path

from analyzer.analyzer import PCAPAnalyzer

def fast_count_packets(pcap_path: str) -> int:
    """
    Conteo ultra-rápido de paquetes usando tshark nativo
    """
    try:
        # Método 1: Usar tshark directamente (más rápido)
        cmd = [
            'tshark', '-r', pcap_path, '-T', 'fields', '-e', 'frame.number',
            '|', 'tail', '-n', '1'
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
            
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError):
        pass
    
    try:
        # Método 2: Usar capinfos (si está disponible)
        cmd = ['capinfos', '-c', pcap_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Number of packets' in line:
                    return int(line.split('=')[1].strip())
                    
    except (subprocess.SubprocessError, ValueError, IndexError):
        pass
    
    # Fallback al método de Python
    return PCAPAnalyzer.count_packets(pcap_path)