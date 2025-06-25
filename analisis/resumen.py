### analisis/resumen.py
def mostrar_menu(analizador):
    print("\n==== MENÚ DE CONSULTAS ====")
    print("1. Total de paquetes")
    print("2. Protocolos")
    print("3. TCP Flags")
    print("4. Streams TCP")
    print("5. IPs de origen")
    print("6. TTLs")
    print("7. Palabras clave")
    print("8. DNS Queries")
    print("9. DNS Respuestas")
    print("10. ICMP Tipos")
    print("0. Salir")

    while True:
        opcion = input("\n→ Seleccione una opción: ")
        match opcion:
            case '1':
                print(f"Total: {analizador.total_paquetes}")
            case '2':
                print(f"Protocolos: {analizador.protocolo_contador}")
            case '3':
                print(f"TCP Flags: {analizador._describir_tcp_flags()}")
            case '4':
                print(f"Streams TCP: {analizador.tcp_streams}")
            case '5':
                print(f"IPs origen: {analizador.ip_origen_contador}")
            case '6':
                print(f"TTLs: {analizador.ttl_histograma}")
            case '7':
                print(f"Palabras: {analizador.texto_ocurrencias}")
            case '8':
                print(f"DNS queries: {analizador.dns_queries}")
            case '9':
                print(f"DNS respuestas: {analizador.dns_respuestas}")
            case '10':
                print(f"ICMP tipos: {analizador.icmp_types}")
            case '0':
                print("Saliendo del resumen...")
                break
            case _:
                print("Opción no válida. Intente de nuevo.")
