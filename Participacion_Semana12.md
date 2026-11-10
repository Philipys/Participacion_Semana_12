# Participación — Cyber Detective: alguien entró al sistema

**Programación Asistida de Aplicaciones · USFQ** — Prof. Jose David Vega Sánchez · Semana 12: Agent Skills, Plugins y evaluación

**Tiempo:** 60 minutos · **Modalidad:** individual, con apoyo de tu agente de código
**Entrega:** pull request desde una rama; no hacer `push` directo a `main`.

> **Situación:** Son las 02:17. El sistema registra varios fallos de acceso y después una autenticación exitosa. Además, hay actividad administrativa y registros de depuración inusuales. No vas a adivinar: vas a **enseñarle a tu agente a investigar** mediante un Agent Skill reutilizable y a demostrar, con evidencia, cuándo se activa, cuándo no y qué cambia frente a una sesión sin skill.

## Objetivo de aprendizaje

Diseñar, instalar/probar y evaluar un Agent Skill llamado `incident-investigator` que guíe a tu agente en la investigación reproducible de logs sintéticos: cuándo debe activarse, cuándo no, qué recursos consulta y cómo cambia la respuesta frente a una sesión sin skill.

> **Lo que se evalúa es el skill, no tu Python.** El script es opcional. Un skill no es «más código»: es un conjunto reutilizable de instrucciones y recursos que hace que el agente sepa **cuándo, cómo y con qué evidencias** ejecutar una tarea especializada.

## Material disponible

- `logs_sinteticos.csv` (se entrega junto con este enunciado): registros inventados para la clase, sin datos reales ni secretos utilizables. Columnas: `timestamp`, `ip`, `user`, `event`, `result`, `detail`.
- Python 3.10+ (solo si decides usar un script auxiliar), un agente de código con soporte de skills (Claude Code, Codex u otro) y Git.
- El agente puede ayudarte a redactar, pero **tú verificas** y justificas la evidencia. Si tu plataforma no admite skills, avisa al docente antes de empezar: no simules una función que no existe.

## Tiempos

| Etapa | Tiempo |
|---|---:|
| 1. Misión, CSV y rama | 5 min |
| 2. Diseñar `SKILL.md` y la referencia de reglas | 18 min |
| 3. Instalación, activación explícita y contextual | 10 min |
| 4. Control negativo y ajuste de `description` | 7 min |
| 5. Experimento sin skill / con skill | 12 min |
| 6. Plugin Detective, reflexión y PR | 8 min |
| **Total** | **60 min** |

Prepara capturas y el PR mientras avanzas, no al final.

## Misión 1 — Preparación (5 minutos)

```bash
git switch -c skills/cyber-detective
```

Abre `logs_sinteticos.csv` e identifica sus columnas. No modifiques el original. Trabaja sin conexión a servicios externos y **no consultes las IP**: son direcciones reservadas para documentación.

## Misión 2 — Diseña tu skill (18 minutos)

Estructura:

```text
incident-investigator/
├── SKILL.md                    # obligatorio: es lo que se evalúa
├── references/
│   └── detection-rules.md      # obligatorio: reglas de dominio consultables
└── scripts/                    # opcional: solo si añade valor
    └── analyze_logs.py
```

Instala o coloca el skill según la documentación de **tu** agente (las rutas y comandos varían por plataforma; no los inventes).

### Qué debe contener `SKILL.md`

1. **Frontmatter YAML** con `name: incident-investigator` y una `description` que diga **qué hace**, **sobre qué materiales** y **cuándo usarlo**, con señales positivas y límites de alcance.
2. **Procedimiento** paso a paso: inspeccionar columnas y formato → leer las reglas → analizar evidencias → distinguir alerta de hecho confirmado → reportar hallazgos con filas → declarar incertidumbre.
3. **Cuándo abrir** `references/detection-rules.md`, sin copiar necesariamente todas las reglas dentro de `SKILL.md`.
4. **Salida estandarizada**: por ejemplo una tabla con `alerta`, `severidad orientativa`, `regla`, `timestamp`, `ip`, `usuario`, `filas/evidencia`, `limitaciones`.
5. **Seguridad y límites**: solo logs inventados, sin red, sin inventar eventos, sin tratar las IP de documentación como infraestructura real, sin mostrar tokens.
6. **No activación**: peticiones de conteo o visualización descriptiva sin investigación de incidentes **no deben activar** el skill por defecto.

Debe servir para **otro CSV compatible**, no memorizar las respuestas de este archivo.

### Reglas que el skill debe saber aplicar (`references/detection-rules.md`)

- **Fuerza bruta probable:** 6 o más `login/failed` desde la misma IP hacia el mismo usuario dentro de una ventana de 5 minutos. Anota por separado si aparece después un `login/success` en los 5 minutos siguientes.
- **Password spraying probable:** `login/failed` desde una misma IP contra al menos 5 usuarios distintos dentro de 5 minutos.
- **Token potencialmente expuesto:** un `detail` que contenga `token=`. Nunca imprimas el valor completo; usa `[REDACTED]`.
- **Escalada no autorizada según el registro:** `role_change/success` con `approved=false`. No infieras culpabilidad.
- **Falsos positivos:** 3 fallos aislados no alcanzan el umbral; un `healthcheck` no es un `login/failed`.

Convenciones: ordena por `timestamp` antes de revisar ventanas; la ventana dura **≤ 5 minutos** incluyendo ambos extremos; cuenta solo eventos cuyos `event` y `result` coincidan exactamente; cita **números de fila del CSV original** (el encabezado es la fila 1); si no puedes identificar duplicados de forma inequívoca, indica la limitación en lugar de inventar una regla. Los resultados son **alertas justificadas**, no conclusiones forenses.

### Prompt sugerido para tu agente

```text
Ayúdame a crear un Agent Skill reutilizable llamado incident-investigator para
investigar logs CSV de autenticación y seguridad. El elemento principal debe ser
SKILL.md con name/description, criterios de activación y no activación, flujo de
investigación y formato de evidencias. Coloca las reglas detalladas en
references/detection-rules.md y explica cuándo debe consultarlas el agente.

El skill debe funcionar sobre archivos CSV compatibles, no solo memorizar este
archivo. No inventes ataques ni atribuciones; cita filas originales y oculta
cualquier secreto detectado. No uses Internet ni modifiques el CSV.

NO priorices programar un detector en Python: puedes utilizar herramientas
existentes del agente y, solo si añade valor, un script auxiliar opcional.
Quiero comprobar después la activación contextual y la no activación, y comparar
la investigación con y sin el skill.
```

## Misión 3 — Instalación y activación (10 minutos)

Ejecuta tres pruebas en tu agente y guarda evidencia real de cada una.

- **Prueba A — explícita:** «Utiliza `incident-investigator` para investigar `logs_sinteticos.csv` y entrega hallazgos con filas de evidencia.» Comprueba que el entorno encuentra el skill y aplica sus instrucciones.
- **Prueba B — contextual (sin nombrarlo):** «Revisa estos registros de autenticación. ¿Ves intentos sospechosos, cambios no aprobados o posibles secretos expuestos? Cita las filas que respaldan cada alerta.» Observa si el agente usa el skill por su `description`. No se exige que se active solo; se exige que registres fielmente lo ocurrido.

Guarda el informe de hallazgos en `hallazgos.md` (o `hallazgos.json`), con evidencia por fila. Verifica al menos un hallazgo contra las filas originales del CSV, sin confiar solo en el texto del modelo, y explica por qué los 3 fallos aislados **no** son una alerta de fuerza bruta.

**Evidencia:** captura o traza que muestre la activación o lectura de `SKILL.md` y/o de `references/detection-rules.md`. Que el modelo mencione el nombre del skill **no** prueba que se activó. Si tu plataforma no expone trazas, documenta cómo lo instalaste e invocaste y qué archivos observaste, distinguiendo lo que **viste** de lo que **infieres**. No fabriques capturas.

## Misión 4 — Control negativo y ajuste (7 minutos)

- **Prueba C — control negativo:** «Muéstrame cuántos eventos hay por hora en este CSV; no investigues incidentes ni clasifiques amenazas.» Aquí el skill **no** debería usarse: que no se active es un resultado deseable.

Si la Prueba B no activó el skill, o la C lo activó sin motivo, mejora la `description` (señales positivas y límites), explica el cambio y repite la prueba una vez.

## Misión 5 — ¿Mejora realmente el skill? (12 minutos)

En **dos sesiones independientes** (cierra el contexto entre una y otra; si la segunda hereda la primera, la comparación no vale), con el mismo CSV, la misma solicitud y, si es posible, el mismo modelo:

> Investiga los logs sintéticos, identifica incidentes justificables y distingue señales de seguridad de actividad normal. Devuelve evidencia concreta.

- **Sin skill:** no cargues `SKILL.md` ni `detection-rules.md`, y no des el script como ayuda indirecta.
- **Con skill:** comprueba que está realmente instalado y disponible.

Completa `comparacion.md`:

| Dimensión | Sin skill | Con skill | Evidencia / comentario |
|---|---|---|---|
| ¿Usó un procedimiento reproducible? | | | |
| ¿Citó filas concretas? | | | |
| Alertas sustentadas | | | |
| Falsos positivos detectados o evitados | | | |
| ¿Ocultó posibles tokens? | | | |
| ¿Reconoció incertidumbre? | | | |
| ¿Qué hizo gracias al skill? | | | |

Escribe además **qué aportó tu skill en concreto**: ¿la activación, el procedimiento, la referencia, el formato, la contención de invenciones? Una mejora solo estética no basta. «No hubo mejora» es una respuesta válida si explicas por qué y qué cambiarías. Tiempo o tokens: anótalos solo si tu entorno los mide de forma confiable; si no, escribe «no disponible». Una corrida por condición es una **comparación didáctica**, no una prueba estadística.

## Misión 6 — Plugin Detective y entrega (8 minutos)

Responde en `respuestas.md`, con brevedad (no se pide construir un plugin ni instalar Ralph Loop):

1. **Skill frente a plugin:** ¿por qué `incident-investigator` es un skill y qué otros componentes (comando, hook, MCP, manifiesto, según tu plataforma) podrían empaquetarse para distribuirlo como plugin?
2. **Ralph Loop:** ¿cómo podría repetirse el análisis para corregir errores detectados por comprobaciones verificables, con **máximo 3 iteraciones** y un criterio de parada explícito, sin fabricar evidencia nueva?

Recuerda: un **hook** automatiza acciones ante eventos del entorno; un **skill** contiene instrucciones y recursos contextuales; **MCP** estandariza el acceso a capacidades externas; un **plugin** puede empaquetar varias extensiones. Los formatos dependen del producto.

## Entrega

Un PR desde tu rama con:

```text
incident-investigator/
  SKILL.md
  references/detection-rules.md
  scripts/                     # opcional
hallazgos.md                   # o hallazgos.json
comparacion.md
respuestas.md
evidencias/
  activacion_explicita.png     # o traza textual real
  activacion_contextual.png    # o documentación de la limitación del entorno
  control_negativo.png         # o traza textual real
logs_sinteticos.csv            # original, sin modificar
```

No hay número fijo de capturas: una traza auténtica que muestre lo mismo vale igual. Si tu agente no permite autoactivación ni trazas, no se te penaliza por la plataforma: documenta la limitación. No incluyas soluciones del docente, datos reales ni secretos; ningún token completo en tus informes.

### Antes de enviar

- [ ] `description` precisa: qué hace, sobre qué materiales, cuándo usarlo y cuándo no.
- [ ] `SKILL.md` indica procedimiento, formato de salida y cuándo abrir la referencia.
- [ ] Evidencia real de la activación explícita, la contextual y el control negativo (o su limitación documentada).
- [ ] Los hallazgos citan filas del CSV original y verificaste al menos uno a mano.
- [ ] La comparación se hizo en sesiones independientes y dice qué aportó el skill.
- [ ] Ningún token completo aparece en el PR; el CSV original no fue modificado.
- [ ] El PR sale de una rama; `main` queda intacta.

**Idea clave:** el skill aporta el procedimiento y el criterio de cuándo aplicarlo; el agente interpreta; la evidencia sale de las filas, no de lo que el modelo afirma.
