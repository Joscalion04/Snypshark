from analyzer.analyzer import PCAPAnalyzer
from analyzer.protocol_handlers.tcp_handler import TCPProcessor
from analyzer.protocol_handlers.ip_handler import IPProcessor
from analyzer.protocol_handlers.icmp_handler import ICMPProcessor
from analyzer.protocol_handlers.dns_handler import DNSProcessor
from analyzer.utils.pattern_matcher import PatternMatcher
from analyzer.ui.menu import InteractiveMenu
from analyzer.ui.osi_layers import OSILayerAnalyzer

import time

def main():
    try:
        file_path = input("📂 Enter path to .pcap/.pcapng file: ").strip()
        
        print("\n🔍 Analyzing file... (this may take time)")
        start_time = time.time()
        
        # OSI Layer Analysis (quick overview)
        print("\n===== [OSI Layer Overview] =====")
        OSILayerAnalyzer.analyze(file_path, sample_size=5)
        
        # Full analysis
        analyzer = PCAPAnalyzer(file_path)
        
        # Register processors (Dependency Injection)
        processors = {
            'tcp': TCPProcessor(),
            'ip': IPProcessor(),
            'icmp': ICMPProcessor(),
            'dns': DNSProcessor(),
            'patterns': PatternMatcher()
        }
        
        for processor in processors.values():
            analyzer.add_processor(processor)
        
        analyzer.analyze()
        
        print(f"\n⏱️ Analysis time: {time.time() - start_time:.2f} seconds")
        
        # Interactive menu
        print("\n===== [Interactive Analysis] =====")
        menu = InteractiveMenu(analyzer, processors)
        menu.display_menu()
        
    except FileNotFoundError:
        print("❌ Error: File not found")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()