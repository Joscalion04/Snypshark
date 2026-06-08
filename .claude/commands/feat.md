# /feat — Crear un nuevo módulo o funcionalidad

**Feature a crear:** $ARGUMENTS

---

## Protocolo de ejecución

### 1. Clasificar el feature antes de tocar código

Determina a cuál capa pertenece basándote en el argumento y en `CLAUDE.md`:

| Tipo | Ubicación | Patrón |
|------|-----------|--------|
| Procesador de protocolo | `analyzer/processors/` | Hereda `PacketProcessor`, implementa `process_packet()` y `get_stats()` |
| Analizador analytics | `analyzer/analytics/` | Hereda `PacketProcessor` o es clase autónoma post-loop |
| Utilidad stateless | `analyzer/utils/` | Funciones puras, sin estado de instancia |
| Componente UI | `analyzer/ui/` | Solo lógica de display, sin lógica de negocio |
| Constante / configuración | `analyzer/config/` | Solo datos, sin lógica |

Si el argumento es ambiguo, lee `CLAUDE.md` sección "Architecture Patterns" y los archivos `__init__.py` del módulo candidato para decidir.

### 2. Lectura obligatoria antes de implementar

Lee en paralelo:

- El `__init__.py` del módulo destino para entender qué ya está exportado.
- Un módulo existente del mismo tipo para extraer el patrón exacto (si es procesador, lee `analyzer/processors/tcp_processor.py`; si es analytics, lee `analyzer/analytics/security_analyzer.py`).
- `analyzer/core/packet_processor.py` si el feature implementa `PacketProcessor`.
- `analyzer/config/constants.py` para reutilizar constantes existentes en lugar de hardcodear valores.

### 3. Reglas de implementación

- **No duplicar lógica existente.** Si hay una función en `utils/` que ya hace lo que necesitas, úsala.
- **Type hints en todas las funciones públicas.** Sin excepción.
- **Sin comentarios obvios.** Solo comenta restricciones no evidentes, workarounds de protocolo, o invariantes que sorprenderían a un lector.
- **Sin manejo de errores defensivo para casos que no pueden ocurrir.** Solo valida en la frontera del sistema (entrada del usuario, red, archivos externos).
- **Logging con `get_logger(__name__)`** para cualquier warning o error — nunca `print(f"[WARNING]...")`.
- **Constantes en `config/constants.py`**, no hardcodeadas en el módulo.
- **Sin abstracciones prematuras.** Implementa exactamente lo que el feature requiere. Tres líneas similares es mejor que una abstracción innecesaria.

### 4. Registro del módulo

Cuando el feature sea un procesador nuevo:
1. Añádelo a `analytics/__init__.py` o `processors/__init__.py` según corresponda.
2. Añade la clave al diccionario `_PROCESSOR_MAP` en `analyzer/cli.py`.
3. Añade la clave a `ALL_PROTOCOLS` en `analyzer/cli.py`.
4. Añade el import en `analyzer/cli.py`.

Cuando el feature sea una utilidad nueva:
1. Añádela a `utils/__init__.py` con su export en `__all__`.

### 5. Tests obligatorios

Al terminar la implementación, sin esperar instrucción, ejecuta `/testing $ARGUMENTS` para escribir los tests del módulo recién creado. El feature no está completo si no tiene tests pasando.

### 6. Formato de entrega

Reporta:
- Archivo(s) creado(s) con su path completo
- Archivo(s) modificados para el registro (cli.py, __init__.py)
- Resultado del suite de tests: `N passed`
- Cualquier dependencia nueva que haya que añadir a `requirements.txt`
