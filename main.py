from analyzer.analyzer import PCAPAnalyzer
from analyzer.protocol_handlers.dhcp_handler import DHCPProcessor
from analyzer.protocol_handlers.http_handler import HTTPProcessor
from analyzer.protocol_handlers.tcp_handler import TCPProcessor
from analyzer.protocol_handlers.ip_handler import IPProcessor
from analyzer.protocol_handlers.icmp_handler import ICMPProcessor
from analyzer.protocol_handlers.dns_handler import DNSProcessor
from analyzer.protocol_handlers.udp_handler import UDPProcessor
from analyzer.utils.pattern_matcher import PatternMatcher
from analyzer.data_analysis.pandas_analyzer import PandasAnalyzer  
from analyzer.ui.menu import InteractiveMenu
from analyzer.ui.osi_layers import OSILayerAnalyzer
from analyzer.utils.progress import ProgressBar

import time
import os
import sys
import json

import time
import os
import sys
import json

def _show_pandas_summary(pandas_analyzer):
    """Muestra un resumen rápido del análisis con pandas"""
    report = pandas_analyzer.generate_security_report()
    
    print("\n" + "="*50)
    print("📈 PANDAS ANALYSIS SUMMARY")
    print("="*50)
    
    overview = report.get('overview', {})
    print(f"Total packets: {overview.get('total_packets', 0):,}")
    print(f"Total bytes: {overview.get('total_bytes', 0):,}")
    print(f"Unique IPs: {overview.get('unique_ips', 0)}")
    print(f"Time duration: {overview.get('time_duration', 'N/A')}")
    
    anomalies = report.get('anomalies_detected', {})
    if anomalies.get('total_anomalies', 0) > 0:
        print(f"🚨 Anomalies detected: {anomalies['total_anomalies']}")
        print(f"   Types: {json.dumps(anomalies.get('anomaly_types', {}), indent=2)}")
    
    print("="*50)

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
            'patterns': PatternMatcher(),
            'pandas': PandasAnalyzer()  # Nuevo procesador
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

        # Construir DataFrames de pandas
        print("\n📊 Building pandas DataFrames...")
        pandas_analyzer = processors['pandas']
        pandas_analyzer.build_dataframes()
        
        # Mostrar resumen rápido
        _show_pandas_summary(pandas_analyzer)

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