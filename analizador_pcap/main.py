### main.py
from analisis.capa_osi import mostrar_capas_osi
from analisis.deteccion_anomalias import PcapAnalyzer
from analisis.resumen import mostrar_menu

def main():
    archivo = input("📂 Ingrese la ruta del archivo .pcapng: ")

    print("\n===== [Capa OSI] =====")
    mostrar_capas_osi(archivo)

    print("\n===== [Análisis de Captura] =====")
    analizador = PcapAnalyzer(archivo)
    analizador.analizar()

    print("\n===== [Resumen Interactivo] =====")
    mostrar_menu(analizador)

if __name__ == "__main__":
    main()

