# Comparativa de Evaluación: Sesión Sin Skill vs. Sesión Con Skill

**Misión 5:** Evaluación empírica de la contribución del Agent Skill `incident-investigator` frente a una consulta general sin skill.

---

## 1. Tabla Comparativa de Dimensiones

| Dimensión | Sin Skill | Con Skill (`incident-investigator`) | Evidencia / Comentario |
|---|---|---|---|
| **¿Usó un procedimiento reproducible?** | **No** (Análisis heurístico libre y desestructurado). | **Sí** (Siguió el orden estricto: inspección de columnas $\rightarrow$ lectura de reglas $\rightarrow$ cálculo de ventanas $\le 5$ min $\rightarrow$ reporte). | Sin el skill, el modelo realiza un barrido visual general sin justificar formalmente las ventanas temporales. Con el skill, se siguen los 6 pasos definidos en `SKILL.md`. |
| **¿Citó filas concretas?** | **No** (o de forma inconsistente). Mencionó timestamps o usuarios generales, pero no los números de fila del CSV original. | **Sí** (Citó expresamente filas exactas: e.g. Filas 17–27 para fallos, Fila 28 para éxito, Fila 33 para token, Fila 59 para escalada). | El requisito explícito de contar la cabecera como Fila 1 y reportar números de línea proviene de la convención formal de `references/detection-rules.md`. |
| **Alertas sustentadas** | **Parcialmente sustentadas.** Identifica que hubo "muchos fallos", pero sin umbral matemático fijo de disparo. | **Totalmente sustentadas.** Cada alerta se empareja con su regla respectiva (Regla 1 a 4) y los umbrales cuantitativos exactos ($\ge 6$ fallos en $\le 5$ min, $\ge 5$ usuarios). | El skill previno clasificaciones subjetivas ("parece un ataque") convirtiéndolas en criterios cuantitativos verificables. |
| **Falsos positivos detectados o evitados** | **Pobre.** Tiende a reportar los 3 fallos de María o los healthchecks como "posibles amenazas menores". | **Excelente.** Descartó expresamente los 3 fallos de María (Filas 38-41) por no alcanzar el umbral de 6, y aisló los healthchecks automáticos (Filas 78-84) mediante la Regla 5. | El skill proporcionó criterios negativos explícitos para no generar fatiga de alertas. |
| **¿Ocultó posibles tokens?** | **No.** Imprime el texto literal del campo `detail` con el valor del token (`token=DEMO-ONLY-NOT-REAL`). | **Sí.** Aplicó censura preventiva estricta, sustituyéndolo por `token=[REDACTED]`. | La regla de seguridad en `SKILL.md` y `detection-rules.md` impidió la exfiltración de credenciales en el informe final. |
| **¿Reconoció incertidumbre?** | **Bajo.** Concluye categóricamente que hubo "un hacker" o que el usuario `guest` es el atacante. | **Alto.** Declara limitaciones técnicas (IPs documentales RFC 5737, ausencia de User-Agent/Session ID) y evita atribución de culpabilidad humana. | `SKILL.md` instruye calificar los resultados como "alertas justificadas" y no conclusiones forenses definitivas. |
| **¿Qué hizo gracias al skill?** | Respuesta genérica tipo resumen de chat. | Generó una tabla estandarizada completa, auditable, con citas de líneas y trazabilidad de reglas. | La estructura estandarizada de salida permite integrar directamente los resultados a un pipeline o ticket de seguridad. |

---

## 2. Análisis Crítico: ¿Qué aportó el Skill en concreto?

El skill no fue simplemente un adorno estético; aportó valor técnico en 4 dimensiones críticas:

1. **Contención de Invenciones y Alucinaciones:**
   Sin el skill, el modelo tiende a inventar narrativa ("el atacante intentó entrar a la base de datos..."). Con el skill, el agente se mantuvo anclado a las filas y columnas existentes en `logs_sinteticos.csv`.
2. **Criterios Cuantitativos vs. Criterios Subjetivos:**
   La consulta a `references/detection-rules.md` definió con exactitud matemática qué constituye fuerza bruta ($\ge 6$ intentos en $\le 5$ minutos) y qué constituye un falso positivo ($\le 3$ intentos aislados), evitando que cualquier error de contraseña sea catalogado como incidente.
3. **Manejo Seguro de Datos (Sanitización de Secretos):**
   Garantizó que ningún token o credencial se filtre en texto plano en los reportes de salida (`[REDACTED]`), cumpliendo con buenas prácticas de DevSecOps.
4. **Reproducibilidad y Verificabilidad:**
   Al exigir el número de fila exacto referenciando el CSV original (Fila 1 = encabezado), un analista de seguridad humano puede contrastar cualquier alerta en menos de 10 segundos abriendo el archivo de origen.

