#!/usr/bin/env python3
"""
Snypshark - Punto de entrada principal
"""

import sys
import os
import time

# Añadir src al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.analyzer import PCAPAnalyzer
from processors.tcp_processor import TCPProcessor
from processors.ip_processor import IPProcessor
from processors.icmp_processor import ICMPProcessor
from processors.dns_processor import DNSProcessor
from processors.http_processor import HTTPProcessor
from processors.dhcp_processor import DHCPProcessor
from processors.udp_processor import UDPProcessor
from processors.pattern_processor import PatternProcessor
from analytics.pandas_analyzer import PandasAnalyzer
from ui.cli_interface import InteractiveMenu
from ui.osi_visualizer import OSIVisualizer
from ui.progress_renderer import ProgressBar
from utils.file_utils import validate_file_path, get_file_size
from utils.performance_utils import optimize_memory_settings, get_system_info

def print_banner():
    """Muestra el banner de la aplicación"""
    banner = r"""
    ┌───────────────────────────────────────────────────┐
    │                                                   │
    │              🕵️ SNYPSHARK ANALYZER                │
    │           Network Forensic Tool v1.0              │
    │                                                   │
    └───────────────────────────────────────────────────┘
    """
    print(banner)

def get_file_path():
    """Obtiene la ruta del archivo de forma interactiva"""
    print("📁 FILE SELECTION")
    print("═" * 50)
    
    while True:
        file_path = input("📂 Enter path to .pcap/.pcapng file: ").strip()
        
        if not file_path:
            print("❌ Please enter a file path")
            continue
            
        # Expandir ~ y variables de entorno
        file_path = os.path.expanduser(os.path.expandvars(file_path))
        
        if not validate_file_path(file_path):
            print("❌ File not found or inaccessible. Please check the path.")
            print("💡 Tip: You can drag and drop the file into the terminal")
            continue
            
        if not file_path.lower().endswith(('.pcap', '.pcapng')):
            print("⚠️  Warning: File extension is not .pcap or .pcapng")
            confirm = input("   Continue anyway? (y/N): ").strip().lower()
            if confirm != 'y':
                continue
        
        # Mostrar información del archivo
        file_size, size_str = get_file_size(file_path)
        file_name = os.path.basename(file_path)
        
        print(f"✅ File found: {file_name}")
        print(f"📊 Size: {size_str}")
        print("═" * 50)
        
        return file_path

def analyze_file(file_path):
    """Realiza el análisis del archivo"""
    print("\n🔍 STARTING ANALYSIS")
    print("═" * 50)
    
    # Optimizar configuración
    optimize_memory_settings()
    
    # Pre-conteo de paquetes
    print("⏳ Counting packets...")
    total_packets = PCAPAnalyzer.count_packets(file_path)
    
    if total_packets == 0:
        print("❌ No packets found in capture.")
        return None, None, None
    
    print(f"📦 Total packets to analyze: {total_packets:,}")
    
    # Mostrar información del sistema
    system_info = get_system_info()
    if system_info:
        print(f"💻 CPU: {system_info.get('cpu_count', 'N/A')} cores")
        print(f"🧠 Memory: {system_info.get('total_memory_gb', 'N/A'):.1f} GB")
    
    # Overview OSI (solo para archivos pequeños)
    if total_packets < 10000:
        print("\n🌐 OSI LAYER OVERVIEW")
        print("─" * 30)
        OSIVisualizer.analyze(file_path, sample_size=3)
    else:
        print("\n⏩ Skipping OSI overview for large file...")
    
    # Inicializar analyzer
    analyzer = PCAPAnalyzer(file_path)
    
    # Registrar procesadores
    processors = {
        'tcp': TCPProcessor(),
        'ip': IPProcessor(),
        'icmp': ICMPProcessor(),
        'dns': DNSProcessor(),
        'http': HTTPProcessor(),
        'dhcp': DHCPProcessor(),
        'udp': UDPProcessor(),
        'patterns': PatternProcessor(),
        'pandas': PandasAnalyzer()
    }
    
    for name, processor in processors.items():
        analyzer.add_processor(processor)
        print(f"✅ Loaded {name.upper()} processor")
    
    # Barra de progreso
    print(f"\n🚀 Analyzing {total_packets:,} packets...")
    bar = ProgressBar(total=total_packets, length=40, prefix="Progress")
    
    start_time = time.time()
    analyzer.analyze(progress_callback=bar.update)
    bar.finish()
    
    elapsed = time.time() - start_time
    print(f"⏱️  Analysis completed in {elapsed:.2f} seconds")
    
    if elapsed > 0:
        speed = total_packets / elapsed
        print(f"🚀 Processing speed: {speed:.0f} packets/second")
    
    # Pandas analysis opcional
    use_pandas = input("\n📊 Enable advanced pandas analysis? (y/N): ").strip().lower() == 'y'
    
    if use_pandas:
        print("\n📈 BUILDING ADVANCED ANALYSIS")
        print("─" * 30)
        pandas_analyzer = processors['pandas']
        pandas_analyzer.build_dataframes()
        
        # Mostrar resumen rápido
        _show_pandas_summary(pandas_analyzer)
    else:
        pandas_analyzer = None
        print("⏩ Skipping pandas analysis...")
    
    return analyzer, processors, pandas_analyzer

def _show_pandas_summary(pandas_analyzer):
    """Muestra un resumen rápido del análisis con pandas"""
    if not pandas_analyzer:
        return
        
    report = pandas_analyzer.generate_security_report()
    
    print("\n" + "═" * 60)
    print("📊 PANDAS ANALYSIS SUMMARY")
    print("═" * 60)
    
    overview = report.get('overview', {})
    print(f"📦 Total packets: {overview.get('total_packets', 0):,}")
    print(f"💾 Total bytes: {overview.get('total_bytes', 0):,}")
    print(f"🌐 Unique IPs: {overview.get('unique_ips', 0)}")
    print(f"⏰ Time duration: {overview.get('time_duration', 'N/A')}")
    
    anomalies = report.get('anomalies_detected', {})
    if anomalies.get('total_anomalies', 0) > 0:
        print(f"🚨 Anomalies detected: {anomalies['total_anomalies']}")
        for anomaly, count in anomalies.get('anomaly_types', {}).items():
            print(f"   ⚠️  {anomaly}: {count}")
    
    print("═" * 60)

def main():
    """Función principal"""
    try:
        # Mostrar banner
        print_banner()
        
        # Obtener archivo
        file_path = get_file_path()
        
        # Analizar archivo
        analyzer, processors, pandas_analyzer = analyze_file(file_path)
        
        if analyzer is None:
            sys.exit(1)
        
        # Menú interactivo
        print("\n" + "═" * 60)
        print("🎮 INTERACTIVE ANALYSIS MENU")
        print("═" * 60)
        
        menu = InteractiveMenu(analyzer, processors)
        menu.display_menu()

    except KeyboardInterrupt:
        print("\n\n🛑 Analysis interrupted by user")
        print("👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        print("💡 Please check if the file is a valid PCAP capture")
    finally:
        print("\n" + "═" * 60)
        print("✨ Thank you for using Snypshark Analyzer!")
        print("═" * 60)

if __name__ == "__main__":
    main()