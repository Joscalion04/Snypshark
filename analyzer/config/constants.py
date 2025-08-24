"""
Constantes y umbrales para el análisis de red
"""

class ProtocolConstants:
    """Constantes relacionadas con protocolos de red"""
    
    # Puertos comunes
    COMMON_PORTS = {
        80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
        25: 'SMTP', 110: 'POP3', 143: 'IMAP', 993: 'IMAPS',
        995: 'POP3S', 21: 'FTP', 23: 'TELNET', 3389: 'RDP',
        3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB'
    }
    
    # Protocolos comunes
    PROTOCOL_NAMES = {
        'tcp': 'Transmission Control Protocol',
        'udp': 'User Datagram Protocol',
        'icmp': 'Internet Control Message Protocol',
        'ip': 'Internet Protocol',
        'ipv6': 'Internet Protocol v6',
        'dns': 'Domain Name System',
        'http': 'Hypertext Transfer Protocol',
        'https': 'HTTP Secure',
        'dhcp': 'Dynamic Host Configuration Protocol',
        'arp': 'Address Resolution Protocol',
        'ssl': 'Secure Sockets Layer',
        'tls': 'Transport Layer Security'
    }
    
    # Códigos ICMP comunes
    ICMP_TYPES = {
        0: 'Echo Reply', 3: 'Destination Unreachable',
        5: 'Redirect Message', 8: 'Echo Request',
        11: 'Time Exceeded', 13: 'Timestamp'
    }

class SecurityThresholds:
    """Umbrales para detección de seguridad"""
    
    PORT_SCAN_THRESHOLD = 10  # Número de SYN packets para considerar port scan
    DDOS_THRESHOLD = 1000     # Paquetes por segundo para considerar DDoS
    ANOMALY_THRESHOLD = 3.0   # Desviación estándar para detección de anomalías
    
    SUSPICIOUS_PATTERNS = [
        r'password', r'login', r'admin', r'root',
        r'select.*from', r'insert.*into', r'update.*set',
        r'delete.*from', r'drop.*table'
    ]
    
    MALICIOUS_DOMAINS = [
        'malware.com', 'phishing.com', 'botnet.com',
        'exploit.com', 'attack.com'
    ]