# /refactor — Refactorizar un módulo existente

**Módulo a refactorizar:** $ARGUMENTS

---

## Protocolo de ejecución

### 1. Leer antes de proponer

Lee el módulo objetivo completo. Lee también su archivo de tests correspondiente en `tests/` para entender cuál es la API pública que **no puede cambiar** externamente.

Identifica además los callers del módulo: busca con grep los imports del módulo en el resto del codebase para saber qué funciones y clases son utilizadas externamente.

### 2. Diagnóstico — lista los problemas antes de refactorizar

Escribe una lista enumerada de los problemas concretos que justifican el refactor. Para cada uno:
- **Qué es:** duplicación, nombre confuso, estructura innecesariamente compleja, violación de una de las reglas del proyecto.
- **Dónde está:** línea o bloque específico.
- **Por qué importa:** qué problema práctico causa (dificulta cambios, oculta bugs, violaría el patrón del proyecto).

**No refactorices sin este diagnóstico.** Si no encuentras problemas concretos que justifiquen el cambio, reporta eso y no toques el código.

### 3. Qué SÍ está dentro del alcance

- Eliminar duplicación interna (extraer función privada compartida).
- Renombrar variables o métodos privados para mayor claridad.
- Simplificar lógica equivalente (reemplazar 4 líneas por 1 expresión idiomática de Python).
- Eliminar estado interno redundante (dos estructuras que trackean lo mismo).
- Separar responsabilidades mezcladas en un mismo método.
- Añadir type hints faltantes en funciones públicas.
- Reemplazar `print(f"[WARNING]...")` por `logger.warning()` si se encontraron.
- Reemplazar literales hardcodeados por constantes de `config/constants.py` si existen.

### 4. Qué NO está dentro del alcance

- Añadir funcionalidad nueva (eso es `/feat`).
- Cambiar la API pública (nombres de métodos públicos, parámetros, tipo de retorno). Si hay que hacerlo, documenta por qué y pide confirmación antes.
- Cambiar el comportamiento observable desde tests existentes.
- Refactorizar módulos que no fueron solicitados, aunque estén relacionados.
- Introducir abstracciones nuevas (clases base, decoradores, metaclases) que no existían.

### 5. Verificación obligatoria

Antes de reportar el refactor como completo:

1. Ejecuta `pyenv exec pytest tests/ -v`.
2. Confirma que **todos los tests preexistentes siguen pasando** con exactamente el mismo comportamiento.
3. Si algún test falla: deshaz el cambio específico que lo causó o corrígelo — nunca elimines el test.

Reporta:
- Lista de cambios aplicados (una línea por cambio, referenciando archivo:línea).
- Resultado del suite: `N passed`.
- Qué cambios **no** aplicaste y por qué (decisiones tomadas).
