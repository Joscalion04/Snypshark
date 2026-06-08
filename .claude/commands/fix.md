# /fix — Corregir un bug en un módulo

**Fix a aplicar:** $ARGUMENTS

El argumento tiene la forma `<módulo> <descripción del bug>`. Ejemplo: `tcp_processor flags vacíos causan KeyError` o `pandas_analyzer build_dataframes falla con captura vacía`.

---

## Protocolo de ejecución

### 1. Localizar el problema antes de asumir

Lee el módulo mencionado en el argumento completo. No hagas suposiciones sobre dónde está el bug hasta haber leído el archivo.

Además, busca con grep si el síntoma (nombre de método, variable, excepción) aparece en otros archivos relacionados — el bug puede estar en el caller, no en el módulo reportado.

Revisa si hay un test existente que debería haber capturado este bug. Si existe y no lo capturó, el test tiene un problema también.

### 2. Diagnóstico — describe el bug antes de tocar código

Escribe en texto plano (no en código):
- **Causa raíz:** qué condición exacta produce el comportamiento incorrecto.
- **Ruta de ejecución:** qué llamadas llevan a ese estado.
- **Por qué no fue detectado antes:** gap en tests, caso edge no contemplado, cambio en un módulo upstream.

Este diagnóstico es obligatorio. No apliques el fix sin antes haber escrito el diagnóstico.

### 3. Reglas del fix

- **Mínimo blast radius.** Toca solo las líneas necesarias para corregir el bug. No refactorices el entorno del fix, no renombres variables, no reorganices imports sin relación directa.
- **Sin backwards-compatibility hacks.** Si hay que cambiar la firma de una función que ya no funcionaba bien, cámbiala. No añadas parámetros opcionales para evitar el cambio.
- **Sin `--no-verify` ni bypasses de validación.** Si el test suite falla por el fix, investiga por qué y corrígelo. No ignores los fallos.
- **Sin manejo de errores para enmascarar el bug.** Un `try/except Exception: pass` que silencia el problema no es un fix.
- **Logging correcto:** si el bug producía un estado silencioso que debería ser visible, añade `logger.warning()` o `logger.error()` con `get_logger(__name__)`.

### 4. Regression test obligatorio

Después de aplicar el fix, escribe o modifica un test en `tests/` que:
- Falle **antes** del fix (reproduce el bug exacto).
- Pase **después** del fix.

El test debe vivir en el archivo de test del módulo afectado. Si ese archivo no existe, créalo.

### 5. Verificación

Ejecuta `pyenv exec pytest tests/ -v` y confirma que:
- El test nuevo pasa.
- Ningún test preexistente rompió.

Reporta el conteo final `N passed` y el nombre del test de regresión añadido.
