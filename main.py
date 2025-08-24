from analyzer.analyzer import PCAPAnalyzer
from analyzer.protocol_handlers.dhcp_handler import DHCPProcessor
from analyzer.protocol_handlers.http_handler import HTTPProcessor
from analyzer.protocol_handlers.tcp_handler import TCPProcessor
from analyzer.protocol_handlers.ip_handler import IPProcessor
from analyzer.protocol_handlers.icmp_handler import ICMPProcessor
from analyzer.protocol_handlers.dns_handler import DNSProcessor
from analyzer.protocol_handlers.udp_handler import UDPProcessor
from analyzer.utils.pattern_matcher import PatternMatcher
from analyzer.ui.menu import InteractiveMenu
from analyzer.ui.osi_layers import OSILayerAnalyzer
from analyzer.utils.progress import ProgressBar

import time
import os
import sys


def main():
    """
    Punto de entrada CLI:
      1) Solicita ruta de PCAP
      2) Muestra overview OSI (muestra)
      3) Analiza con procesadores y barra de progreso
      4) Lanza menú interactivo
    """
    try:
        file_path = input("📂 Enter path to .pcap/.pcapng file: ").strip()
        if not os.path.isfile(file_path):
            print("❌ Error: File not found")
            sys.exit(1)

        print("\n===== [OSI Layer Overview] =====")
        OSILayerAnalyzer.analyze(file_path, sample_size=5)

        # Pre-conteo para barra de progreso
        print("\n⏳ Counting packets for progress bar...")
        total_packets = PCAPAnalyzer.count_packets(file_path)
        if total_packets == 0:
            print("⚠️ No packets found in capture.")
            sys.exit(0)

        analyzer = PCAPAnalyzer(file_path)

        # Dependency Injection: registra procesadores
        processors = {
            'tcp': TCPProcessor(),
            'ip': IPProcessor(),
            'icmp': ICMPProcessor(),
            'dns': DNSProcessor(),
            'http': HTTPProcessor(),
            'dhcp': DHCPProcessor(),
            'udp': UDPProcessor(),
            'patterns': PatternMatcher()
        }
        for p in processors.values():
            analyzer.add_processor(p)

        # Barra de progreso
        print("\n🔍 Analyzing file... (progress below)")
        bar = ProgressBar(total=total_packets, length=32, prefix="Analyzing")

        start_time = time.time()
        analyzer.analyze(progress_callback=bar.update)
        bar.finish()

        elapsed = time.time() - start_time
        print(f"\n⏱️ Analysis time: {elapsed:.2f} seconds")

        # Menú
        print("\n===== [Interactive Analysis] =====")
        menu = InteractiveMenu(analyzer, processors)
        menu.display_menu()

    except KeyboardInterrupt:
        print("\n🛑 Interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")


if __name__ == "__main__":
    main()
