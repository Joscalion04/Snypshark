# 🕵️‍♂️ Analizador de Capturas `.pcapng` con Python

Este proyecto es una aplicación simple de línea de comandos escrita en Python que analiza archivos de captura de red (`.pcap` / `.pcapng`). Está orientada a fines académicos y tiene como objetivo mostrar:

- Las **capas del modelo OSI** presentes en cada paquete.
- Comportamientos **anómalos** o sospechosos a nivel de red, como combinaciones inusuales de flags TCP o tipos ICMP no estándar.

---

## ⚙️ Funcionalidad Actual

### ✅ Análisis de Capas OSI

El programa procesa cada paquete del archivo `.pcapng` y muestra qué capas del modelo OSI están presentes. Por ejemplo:


### ✅ Detección de Anomalías

Se detectan comportamientos inusuales como:

- 🔺 Flags TCP poco comunes, como `FIN + SYN + ACK` (`0x13`)
- 🔺 Tipos de ICMP que no sean eco (8) o respuesta (0)

Esto puede ayudar a identificar intentos de escaneo, tráfico malformado o pruebas de penetración.

---

## 📁 Estructura del Proyecto

analizador_pcap/
├── main.py
├── analisis/
│ ├── init.py
│ ├── capa_osi.py
│ ├── deteccion_anomalias.py
│ └── resumen.py # (en construcción)
├── data/
│ └── ejemplo.pcapng # archivo de muestra (no incluido)
├── README.md
└── requirements.txt



---

## 🚀 Cómo Ejecutarlo

### 1. Clonar el repositorio

```bash
git clone https://github.com/tu_usuario/analizador_pcap.git
cd analizador_pcap
```

