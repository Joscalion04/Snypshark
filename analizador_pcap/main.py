from analisis.capa_osi import mostrar_capas_osi
from analisis.deteccion_anomalias import detectar_anomalias

def main():
    archivo = input("Ingrese la ruta del archivo .pcapng: ")
    
    print("\n===== Análisis de Capas OSI =====")
    mostrar_capas_osi(archivo)
    
    print("\n===== Detección de Anomalías =====")
    detectar_anomalias(archivo)

if __name__ == "__main__":
    main()
