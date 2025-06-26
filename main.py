from analisis.capa_osi import analizar_capas_osi
from analisis.deteccion_anomalias import PcapAnalyzer
from analisis.resumen import mostrar_menu_interactivo
import time

def main():
    try:
        archivo = input("📂 Ingrese la ruta del archivo .pcap/.pcapng: ").strip()
        
        print("\n🔍 Analizando archivo... (esto puede tomar tiempo)")
        start_time = time.time()
        
        # Análisis de capas OSI (muestra solo primeros paquetes para vista general)
        print("\n===== [Vista General de Capas] =====")
        analizar_capas_osi(archivo, muestra=5)
        
        # Análisis completo
        analizador = PcapAnalyzer(archivo)
        analizador.analizar()
        
        print(f"\n⏱️ Tiempo de análisis: {time.time() - start_time:.2f} segundos")
        
        # Menú interactivo
        print("\n===== [Resumen Interactivo] =====")
        mostrar_menu_interactivo(analizador)
        
    except FileNotFoundError:
        print("❌ Error: Archivo no encontrado")
    except Exception as e:
        print(f"❌ Error inesperado: {str(e)}")

if __name__ == "__main__":
    main()