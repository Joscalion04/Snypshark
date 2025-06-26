import pyshark
from collections import Counter, defaultdict
import re

class PcapAnalyzer:
    def __init__(self, ruta_pcap):
        # Configuración optimizada para lectura más rápida
        self.captura = pyshark.FileCapture(
            ruta_pcap,
            only_summaries=False,
            keep_packets=False,  # No mantener paquetes en memoria
            use_json=True        # Más eficiente para algunos casos
        )
        self.total_paquetes = 0
        self.protocolo_contador = Counter()
        self.tcp_flags = Counter()
        self.icmp_types = Counter()
        self.ip_origen_contador = Counter()
        self.ttl_histograma = Counter()
        self.texto_ocurrencias = defaultdict(int)
        self.tcp_streams = set()  # Usamos set para streams únicos
        self.dns_queries = []
        self.dns_respuestas = []
        
        # Patrones precompilados para búsqueda más rápida
        self.palabras_clave = re.compile(r'microsoft|google|intel|login|http|https|ftp|ssh', re.IGNORECASE)

    def analizar(self):
        try:
            for pkt in self.captura:
                self._procesar_paquete(pkt)
        finally:
            self.captura.close()

    def _procesar_paquete(self, pkt):
        self.total_paquetes += 1
        capas = [layer.layer_name for layer in pkt.layers]
        
        # Conteo de protocolos por capa
        self.protocolo_contador.update(capas)
        
        # Procesamiento específico por protocolo
        if 'tcp' in capas:
            self._procesar_tcp(pkt)
        if 'icmp' in capas:
            self._procesar_icmp(pkt)
        if 'ip' in capas:
            self._procesar_ip(pkt)
        if 'dns' in capas:
            self._procesar_dns(pkt)
        
        # Búsqueda de patrones en el payload
        self._buscar_patrones(pkt)

    def _procesar_tcp(self, pkt):
        try:
            flags = int(pkt.tcp.flags, 16)
            self.tcp_flags[flags] += 1
            if hasattr(pkt.tcp, 'stream'):
                self.tcp_streams.add(pkt.tcp.stream)
        except AttributeError:
            pass

    def _procesar_icmp(self, pkt):
        try:
            self.icmp_types[int(pkt.icmp.type)] += 1
        except (AttributeError, ValueError):
            pass

    def _procesar_ip(self, pkt):
        try:
            self.ip_origen_contador[pkt.ip.src] += 1
            self.ttl_histograma[int(pkt.ip.ttl)] += 1
        except (AttributeError, ValueError):
            pass

    def _procesar_dns(self, pkt):
        try:
            if hasattr(pkt.dns, 'qry_name'):
                self.dns_queries.append(pkt.dns.qry_name.lower())
            if hasattr(pkt.dns, 'resp_name'):
                self.dns_respuestas.append(pkt.dns.resp_name.lower())
        except AttributeError:
            pass

    def _buscar_patrones(self, pkt):
        try:
            payload = str(pkt).lower()
            matches = self.palabras_clave.findall(payload)
            for match in matches:
                self.texto_ocurrencias[match] += 1
        except:
            pass

    def _describir_tcp_flags(self):
        nombres = {
            0x02: "SYN", 0x12: "SYN+ACK", 0x10: "ACK",
            0x01: "FIN", 0x11: "FIN+ACK", 0x18: "PSH+ACK",
            0x04: "RST", 0x14: "RST+ACK"
        }
        return {nombres.get(f, f"0x{f:02x}"): c for f, c in self.tcp_flags.items()}