import pyshark
from collections import Counter, defaultdict

class PcapAnalyzer:
    def __init__(self, ruta_pcap):
        self.captura = pyshark.FileCapture(ruta_pcap, only_summaries=False)
        self.total_paquetes = 0
        self.protocolo_contador = Counter()
        self.tcp_flags = Counter()
        self.icmp_types = Counter()
        self.ip_origen_contador = Counter()
        self.ttl_histograma = Counter()
        self.texto_ocurrencias = defaultdict(int)
        self.tcp_streams = Counter()
        self.dns_queries = []
        self.dns_respuestas = []

    def analizar(self):
        for pkt in self.captura:
            self.total_paquetes += 1
            capas = [layer.layer_name for layer in pkt.layers]

            for capa in capas:
                self.protocolo_contador[capa] += 1

            if 'tcp' in capas:
                try:
                    flags = int(pkt.tcp.flags, 16)
                    self.tcp_flags[flags] += 1
                    self.tcp_streams[pkt.tcp.stream] += 1
                except:
                    pass

            if 'icmp' in capas:
                try:
                    tipo = int(pkt.icmp.type)
                    self.icmp_types[tipo] += 1
                except:
                    pass

            if 'ip' in capas:
                try:
                    self.ip_origen_contador[pkt.ip.src] += 1
                    self.ttl_histograma[int(pkt.ip.ttl)] += 1
                except:
                    pass

            if hasattr(pkt, 'data'):
                payload = str(pkt).lower()
                for palabra in ['microsoft', 'google', 'intel', 'login']:
                    if palabra in payload:
                        self.texto_ocurrencias[palabra] += 1

            if 'dns' in capas:
                if hasattr(pkt.dns, 'qry_name'):
                    self.dns_queries.append(pkt.dns.qry_name.lower())
                if hasattr(pkt.dns, 'resp_name'):
                    self.dns_respuestas.append(pkt.dns.resp_name.lower())

    def _describir_tcp_flags(self):
        nombres = {
            0x02: "SYN",
            0x12: "SYN+ACK",
            0x10: "ACK",
            0x01: "FIN",
            0x11: "FIN+ACK",
            0x18: "PSH+ACK",
            0x04: "RST",
        }
        salida = {}
        for flag, count in self.tcp_flags.items():
            desc = nombres.get(flag, f"0x{flag:02x}")
            salida[desc] = count
        return salida
