import pyshark
from collections import defaultdict

def analizar_capas_osi(ruta_pcap, muestra=5):
    try:
        captura = pyshark.FileCapture(ruta_pcap, only_summaries=True)
        estadisticas = defaultdict(int)
        paquetes_procesados = 0
        
        print(f"Mostrando primeros {muestra} paquetes como muestra:")
        
        for i, paquete in enumerate(captura):
            if i >= muestra:
                break
            capas = paquete.protocol.split(':')
            print(f"\n📦 Paquete #{i+1}:")
            print(" -> ".join(capas))
            for capa in capas:
                estadisticas[capa.strip()] += 1
        
        print("\n📊 Estadísticas generales de capas:")
        for capa, count in sorted(estadisticas.items(), key=lambda x: -x[1]):
            print(f"{capa}: {count} ocurrencias")
            
    except Exception as e:
        print(f"⚠️ Error al analizar capas OSI: {str(e)}")
    finally:
        captura.close()