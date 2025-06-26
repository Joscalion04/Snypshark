def mostrar_menu_interactivo(analizador):
    OPCIONES = {
        '1': ("Total de paquetes", lambda: f"📦 Total: {analizador.total_paquetes}"),
        '2': ("Protocolos más comunes", lambda: f"📊 Protocolos: {analizador.protocolo_contador.most_common(5)}"),
        '3': ("TCP Flags", lambda: f"🚩 TCP Flags: {analizador._describir_tcp_flags()}"),
        '4': ("Streams TCP", lambda: f"🔄 Streams TCP: {len(analizador.tcp_streams)} streams únicos"),
        '5': ("IPs de origen", lambda: f"📡 IPs origen: {analizador.ip_origen_contador.most_common(5)}"),
        '6': ("TTLs comunes", lambda: f"⏳ TTLs: {analizador.ttl_histograma.most_common(5)}"),
        '7': ("Palabras clave", lambda: f"🔍 Palabras: {dict(analizador.texto_ocurrencias)}"),
        '8': ("DNS Queries", lambda: f"❓ DNS queries: {len(analizador.dns_queries)} (únicas: {len(set(analizador.dns_queries))})"),
        '9': ("DNS Respuestas", lambda: f"✔️ DNS respuestas: {len(analizador.dns_respuestas)} (únicas: {len(set(analizador.dns_respuestas))})"),
        '10': ("ICMP Tipos", lambda: f"📶 ICMP tipos: {dict(analizador.icmp_types)}"),
        '0': ("Salir", None)
    }

    while True:
        print("\n==== MENÚ DE CONSULTAS ====")
        for key, (desc, _) in OPCIONES.items():
            print(f"{key}. {desc}")

        opcion = input("\n→ Seleccione una opción (o '0' para salir): ").strip()
        
        if opcion == '0':
            print("👋 Saliendo del resumen...")
            break
            
        if opcion in OPCIONES:
            try:
                print(OPCIONES[opcion][1]())
            except Exception as e:
                print(f"⚠️ Error al obtener datos: {str(e)}")
        else:
            print("❌ Opción no válida. Intente de nuevo.")