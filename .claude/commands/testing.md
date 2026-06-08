# /testing — Escribir tests para un feature o módulo

**Target:** $ARGUMENTS

---

## Protocolo de ejecución

### 1. Lectura obligatoria antes de escribir una sola línea

Ejecuta estas lecturas en paralelo:

- Lee el módulo objetivo: busca en `analyzer/` el archivo que corresponda al argumento (procesadores en `processors/`, analytics en `analytics/`, utils en `utils/`, UI en `ui/`).
- Lee `tests/conftest.py` para conocer los fixtures disponibles (`MockLayer`, `MockPacket`, `sample_packet`, `analyzer`, `flag_descriptor`).
- Lee el archivo de test más similar que ya exista en `tests/` para respetar el patrón de nomenclatura y estructura.
- Lee `pyproject.toml` sección `[tool.pytest.ini_options]` para confirmar `pythonpath = ["analyzer"]`.

### 2. Reglas que NO se negocian

- **Solo API pública.** No testees métodos privados (`_método`). Si el comportamiento interno importa, exponlo a través del método público que lo invoca.
- **Sin imports absolutos desde la raíz.** El `pythonpath` apunta a `analyzer/`, por lo que los imports van sin prefijo: `from processors.tcp_processor import TCPProcessor`, no `from analyzer.processors...`.
- **Fixtures de conftest primero.** Reutiliza `sample_packet`, `analyzer`, o `MockPacket`/`MockLayer` si aplican. Crea fixtures locales solo si conftest no cubre el caso.
- **Sin archivos PCAP reales.** Usa `tmp_path` de pytest o `MagicMock` para simular paquetes. Nunca dependas de archivos externos.
- **Arrange / Act / Assert implícito.** Cada test tiene una sola razón para fallar. Nada de tests con múltiples asserts no relacionados.
- **Cubre edge cases, no solo el happy path:** entrada vacía, valores límite, tipos incorrectos donde aplique, excepción esperada.
- **Nombrado:** `test_<comportamiento>_<condición>`. Ejemplo: `test_process_packet_ignores_non_tcp`, `test_get_stats_returns_zero_on_empty`.
- **Sin comentarios descriptivos** dentro de los tests. El nombre del test ya dice qué hace.

### 3. Estructura del archivo de salida

```
tests/test_<nombre_módulo>.py
```

Usa clases de test agrupadas por clase o comportamiento principal:

```python
class Test<ClasePrincipal>:
    def test_...(self):
        ...

class Test<OtroComportamiento>:
    def test_...(self):
        ...
```

### 4. Cobertura mínima requerida

Para cada clase o función pública del módulo:
- Constructor/inicialización con estado vacío
- Método principal (`process_packet`, `get_stats`, o equivalente) con input válido
- Método principal con input inválido o vacío
- Al menos un edge case específico del dominio (flags TCP, ICMP size, DNS query, etc.)
- Si el módulo acumula estado entre llamadas, test de acumulación correcta

### 5. Después de escribir

Ejecuta `pyenv exec pytest tests/test_<nombre>.py -v` y corrige cualquier fallo antes de reportar el trabajo como completo. Reporta el resultado final con el conteo `N passed`.
