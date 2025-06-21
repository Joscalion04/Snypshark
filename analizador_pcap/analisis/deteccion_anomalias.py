import pyshark

def detectar_anomalias(ruta_pcap):
    captura = pyshark.FileCapture(ruta_pcap)
    
    for i, paquete in enumerate(captura):
        capas = [layer.layer_name for layer in paquete.layers]

        # Ejemplo de análisis simple de flags TCP sospechosos
        if 'tcp' in capas:
            flags = paquete.tcp.flags
            if flags == '0x13':  # FIN + SYN + ACK juntos = comportamiento raro
                print(f"\n⚠️ Paquete {i+1}: Flags TCP sospechosos: {flags}")

        # Ejemplo: detectar paquetes ICMP inusuales
        if 'icmp' in capas:
            tipo_icmp = paquete.icmp.type
            if tipo_icmp not in ['0', '8']:
                print(f"\n⚠️ Paquete {i+1}: Tipo ICMP inusual: {tipo_icmp}")

    captura.close()
