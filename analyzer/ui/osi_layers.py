import pyshark
from collections import defaultdict

class OSILayerAnalyzer:
    """
    Muestra una vista rápida de los primeros paquetes y acumula
    estadísticas por "protocol" del summary de tshark.
    """
    @staticmethod
    def analyze(pcap_path: str, sample_size: int = 5) -> None:
        capture = None
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                stats = defaultdict(int)
                print(f"Showing first {sample_size} packets as sample:")

                for i, packet in enumerate(capture):
                    if i >= sample_size:
                        break
                    layers = packet.protocol.split(':')
                    print(f"\n📦 Packet #{i+1}:")
                    print(" -> ".join(layers))
                    for layer in layers:
                        stats[layer.strip()] += 1

            print("\n📊 Layer statistics:")
            for layer, count in sorted(stats.items(), key=lambda x: -x[1]):
                print(f"{layer}: {count} occurrences")
        except Exception as e:
            print(f"⚠️ Error analyzing OSI layers: {str(e)}")
