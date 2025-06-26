import pyshark
from collections import defaultdict

class OSILayerAnalyzer:
    """Analyzes OSI layers in PCAP file"""
    @staticmethod
    def analyze(pcap_path, sample_size=5):
        try:
            capture = pyshark.FileCapture(pcap_path, only_summaries=True)
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
        finally:
            capture.close()