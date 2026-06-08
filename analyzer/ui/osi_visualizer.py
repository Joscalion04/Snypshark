from collections import defaultdict
import pyshark
from utils.logger import get_logger

logger = get_logger(__name__)


class OSIVisualizer:
    @staticmethod
    def analyze(pcap_path: str, sample_size: int = 5) -> None:
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                stats: defaultdict = defaultdict(int)
                print(f"Sample — first {sample_size} packets:")
                print("-" * 50)

                for i, packet in enumerate(capture):
                    if i >= sample_size:
                        break
                    layers = packet.protocol.split(':')
                    chain = " -> ".join(layer.strip() for layer in layers)
                    print(f"  Packet #{i + 1}: {chain}")
                    print(f"  Summary: {packet.info}")
                    print()
                    for layer in layers:
                        stats[layer.strip()] += 1

            print("Layer statistics:")
            print("-" * 30)
            for layer, count in sorted(stats.items(), key=lambda x: -x[1]):
                print(f"  {layer}: {count}")

        except Exception as e:
            logger.warning("Error analyzing OSI layers: %s", e)

    @staticmethod
    def get_layer_distribution(pcap_path: str) -> dict:
        stats: defaultdict = defaultdict(int)
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                for packet in capture:
                    for layer in packet.protocol.split(':'):
                        stats[layer.strip()] += 1
        except Exception:
            pass
        return dict(stats)
