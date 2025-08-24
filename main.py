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
from pathlib import Path
import multiprocessing

def print_banner():
    """Muestra un banner atractivo"""
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
    """Obtiene la ruta del archivo con interfaz amigable"""
    print("📁 FILE SELECTION")
    print("═" * 50)
    
    while True:
        file_path = input("📂 Enter path to .pcap/.pcapng file: ").strip()
        
        if not file_path:
            print("❌ Please enter a file path")
            continue
            
        # Expandir ~ y variables de entorno
        file_path = os.path.expanduser(os.path.expandvars(file_path))
        
        if not os.path.isfile(file_path):
            print("❌ File not found. Please check the path and try again.")
            print("💡 Tip: You can drag and drop the file into the terminal")
            continue
            
        if not file_path.lower().endswith(('.pcap', '.pcapng')):
            print("⚠️  Warning: File extension is not .pcap or .pcapng")
            confirm = input("   Continue anyway? (y/N): ").strip().lower()
            if confirm != 'y':
                continue
        
        # Mostrar información del archivo
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        print(f"✅ File found: {file_name}")
        print(f"📊 Size: {file_size / (1024*1024):.2f} MB")
        print("═" * 50)
        
        return file_path

def get_optimal_workers(file_size_mb):
    """Determina el número óptimo de workers basado en el tamaño del archivo"""
    cpu_count = multiprocessing.cpu_count()
    
    if file_size_mb < 10:    # < 10 MB
        return min(2, cpu_count)
    elif file_size_mb < 100: # < 100 MB
        return min(4, cpu_count)
    elif file_size_mb < 500: # < 500 MB
        return min(8, cpu_count)
    else:                    # > 500 MB
        return min(12, cpu_count)

def optimize_memory_settings():
    """Optimiza la configuración de memoria para mejor rendimiento"""
    import gc
    gc.set_threshold(70000, 10, 10)  # Configurar garbage collector
    
    # Pre-cargar bibliotecas comunes
    try:
        import numpy as np
        np.zeros(1)  # Pre-cargar numpy
    except ImportError:
        pass

def analyze_file(file_path):
    """Realiza el análisis del archivo con interfaz mejorada y paralelización"""
    print("\n🔍 STARTING ANALYSIS")
    print("═" * 50)
    
    # Optimizar configuración de memoria
    optimize_memory_settings()
    
    # Determinar configuración óptima
    file_size = os.path.getsize(file_path) / (1024 * 1024)  # MB
    max_workers = get_optimal_workers(file_size)
    
    print(f"⚡ Performance mode: {max_workers} workers")
    print(f"📊 File size: {file_size:.2f} MB")
    
    # Pre-conteo rápido
    print("⏳ Counting packets (fast method)...")
    total_packets = PCAPAnalyzer.count_packets(file_path)
    
    if total_packets == 0:
        print("❌ No packets found in capture.")
        return None, None, None
    
    print(f"📦 Total packets to analyze: {total_packets:,}")
    
    # Overview OSI (muestra solo para archivos pequeños)
    if total_packets < 10000:
        print("\n🌐 OSI LAYER OVERVIEW")
        print("─" * 30)
        OSILayerAnalyzer.analyze(file_path, sample_size=3)
    else:
        print("\n⏩ Skipping OSI overview for large file...")
    
    # Inicializar analyzer
    analyzer = PCAPAnalyzer(file_path)
    
    # Registrar procesadores optimizados
    processors = {
        'tcp': TCPProcessor(),
        'ip': IPProcessor(),
        'icmp': ICMPProcessor(),
        'dns': DNSProcessor(),
        'http': HTTPProcessor(),
        'dhcp': DHCPProcessor(),
        'udp': UDPProcessor(),
        'patterns': PatternMatcher(),
        'pandas': PandasAnalyzer()
    }
    
    for name, processor in processors.items():
        analyzer.add_processor(processor)
        print(f"✅ Loaded {name.upper()} processor")
    
    # Barra de progreso con estilo mejorado
    print(f"\n🚀 Analyzing {total_packets:,} packets with {max_workers} workers...")
    bar = ProgressBar(total=total_packets, length=40, prefix="Progress")
    
    start_time = time.time()
    
    # Análisis paralelo optimizado
    analyzer.analyze(
        progress_callback=bar.update,
        max_workers=max_workers
    )
    
    bar.finish()
    
    elapsed = time.time() - start_time
    print(f"⏱️  Analysis completed in {elapsed:.2f} seconds")
    
    if elapsed > 0:
        speed = total_packets / elapsed
        print(f"🚀 Processing speed: {speed:.0f} packets/second")
        print(f"📈 Throughput: {(file_size / elapsed):.2f} MB/s")
    
    # Construir DataFrames de pandas (solo si es necesario)
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
    """
    Punto de entrada CLI con interfaz mejorada
    """
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