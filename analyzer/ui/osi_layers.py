import pyshark
from collections import defaultdict

class OSILayerAnalyzer:
    """
    Muestra una vista rápida de los primeros paquetes con mejor formato
    """
    @staticmethod
    def analyze(pcap_path: str, sample_size: int = 3) -> None:
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                stats = defaultdict(int)
                print(f"🔍 Showing first {sample_size} packets as sample:")
                print("─" * 50)

                for i, packet in enumerate(capture):
                    if i >= sample_size:
                        break
                    
                    layers = packet.protocol.split(':')
                    layer_chain = " → ".join(layers)
                    
                    print(f"📦 Packet #{i+1}:")
                    print(f"   {layer_chain}")
                    print(f"   Summary: {packet.info}")
                    print()
                    
                    for layer in layers:
                        stats[layer.strip()] += 1

            print("📊 Layer statistics:")
            print("─" * 30)
            for layer, count in sorted(stats.items(), key=lambda x: -x[1]):
                print(f"   {layer}: {count} occurrences")
                
        except Exception as e:
            print(f"⚠️  Error analyzing OSI layers: {str(e)}")