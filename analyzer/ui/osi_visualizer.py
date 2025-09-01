from collections import defaultdict
import pyshark

class OSIVisualizer:
    """
    Visualizador de capas OSI con formato mejorado
    """
    
    LAYER_EMOJIS = {
        'eth': '🔗', 'ip': '🌐', 'ipv6': '🌐', 
        'tcp': '📡', 'udp': '📨', 'icmp': '📶',
        'dns': '🔍', 'http': '🌍', 'https': '🔒',
        'dhcp': '📡', 'bootp': '📡', 'arp': '🔄',
        'ssl': '🔐', 'tls': '🔐'
    }
    
    @staticmethod
    def analyze(pcap_path: str, sample_size: int = 5) -> None:
        """
        Muestra una vista rápida de los primeros paquetes con mejor formato
        """
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                stats = defaultdict(int)
                print(f"🔍 Showing first {sample_size} packets as sample:")
                print("─" * 50)

                for i, packet in enumerate(capture):
                    if i >= sample_size:
                        break
                    
                    layers = packet.protocol.split(':')
                    layer_chain = " → ".join(
                        f"{OSIVisualizer.LAYER_EMOJIS.get(layer.strip().lower(), '📦')} {layer.strip()}"
                        for layer in layers
                    )
                    
                    print(f"📦 Packet #{i+1}:")
                    print(f"   {layer_chain}")
                    print(f"   Summary: {packet.info}")
                    print()
                    
                    for layer in layers:
                        stats[layer.strip()] += 1

            print("📊 Layer statistics:")
            print("─" * 30)
            for layer, count in sorted(stats.items(), key=lambda x: -x[1]):
                emoji = OSIVisualizer.LAYER_EMOJIS.get(layer.lower(), '📊')
                print(f"   {emoji} {layer}: {count} occurrences")
                
        except Exception as e:
            print(f"⚠️  Error analyzing OSI layers: {str(e)}")
    
    @staticmethod
    def get_layer_distribution(pcap_path: str) -> dict:
        """Obtiene distribución de capas OSI"""
        stats = defaultdict(int)
        try:
            with pyshark.FileCapture(pcap_path, only_summaries=True, keep_packets=False) as capture:
                for packet in capture:
                    layers = packet.protocol.split(':')
                    for layer in layers:
                        stats[layer.strip()] += 1
        except Exception:
            pass
        
        return dict(stats)