
### analisis/capa_osi.py
import pyshark

def mostrar_capas_osi(ruta_pcap):
    captura = pyshark.FileCapture(ruta_pcap)
    for i, paquete in enumerate(captura):
        print(f"\n--- Paquete #{i+1} ---")
        capas = [layer.layer_name for layer in paquete.layers]
        print(f"Capas detectadas: {capas}")
    captura.close()