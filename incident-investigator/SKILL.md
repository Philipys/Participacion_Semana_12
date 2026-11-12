---
name: incident-investigator
description: >-
  Investiga logs CSV de autenticación y seguridad para detectar incidentes reproducibles
  (fuerza bruta, password spraying, tokens expuestos y escaladas de privilegios no autorizadas).
  Úsalo cuando el usuario pida investigar incidentes, auditar registros sospechosos, detectar ataques
  o analizar anomalías de seguridad en archivos de logs con columnas timestamp, ip, user, event, result, detail.
  NO lo uses para consultas descriptivas simples, conteos genéricos de eventos por hora, resúmenes estadísticos
  o visualizaciones que no involucren una investigación de seguridad o detección de incidentes.
---

# Incident Investigator Skill

Este skill proporciona un procedimiento estricto, reproducible y acotado para auditar archivos de logs CSV de autenticación y seguridad, distinguiendo anomalías justificadas de actividad operativa normal.

---

## 1. Principios de Seguridad y Restricciones

* **Modo Aislado (Sin Red):** No realizar consultas externas, geolocalización de IPs ni escaneos a servicios externos. Las direcciones IP corresponden a rangos de prueba/documentación (ej. RFC 5737).
* **Integridad del Archivo:** Nunca modificar el archivo CSV original ni inferir eventos que no figuren explícitamente en el registro.
* **Manejo Estricto de Secretos:** Si un log contiene cadenas sensibles como `token=`, se debe **ocultar y redactar inmediatamente** como `[REDACTED]`. Nunca reflejar secretos en texto plano.
* **Atribución Técnica:** Los resultados son **alertas técnicas justificadas**, no acusaciones judiciales ni hechos confirmados. No inferir intencionalidad humana ni culpabilidad.

---

## 2. Procedimiento de Investigación Paso a Paso

### Paso 1: Inspección de Estructura y Columnas
1. Verificar que el archivo objetivo sea un CSV compatible con las columnas estándar:
   `timestamp`, `ip`, `user`, `event`, `result`, `detail`.
2. Validar el formato ISO-8601 de los timestamps y la codificación de caracteres.

### Paso 2: Consulta Obligatoria de Reglas de Detección
* Antes de clasificar cualquier evento, **abrir y consultar obligatoriamente** el archivo:
  `references/detection-rules.md`
* Aplicar los umbrales cuantitativos exactos definidos en dicho documento (umbrales de intentos, ventanas de 5 minutos, criterios de coincidencia exacta).

### Paso 3: Análisis Temporal y Agrupación
1. Ordenar los registros cronológicamente de forma ascendente por la columna `timestamp`.
2. Evaluar ventanas móviles de tiempo $\le 5$ minutos:
   * **Fuerza Bruta:** $\ge 6$ fallos consecutivos (`event=login`, `result=failed`) desde la misma IP y hacia el mismo usuario en $\le 5$ min. Revisar si ocurre un `login/success` dentro de los 5 minutos siguientes.
   * **Password Spraying:** intentos de `login/failed` desde una misma IP contra $\ge 5$ usuarios diferentes en $\le 5$ min.
   * **Tokens Filtrados:** buscar coincidencias de `token=` en la columna `detail`.
   * **Escalada No Autorizada:** eventos `event=role_change`, `result=success` con `approved=false` en `detail`.
3. Descartar falsos positivos conocidos (por ejemplo, 3 o menos fallos aislados no constituyen fuerza bruta; eventos `healthcheck` son operativos y no representan fallos de login).

### Paso 4: Referenciación de Evidencia
* Para cada alerta encontrada, registrar el **número exacto de fila** correspondiente en el archivo CSV original.
* Nota: La fila de encabezados (`timestamp,ip,user...`) se cuenta como la **Fila 1**.

### Paso 5: Generación del Reporte Estandarizado
Presentar los hallazgos en una tabla con el siguiente formato uniforme:

| Alerta | Severidad Orientativa | Regla Aplicada | Timestamp | IP | Usuario | Filas / Evidencia | Justificación y Limitaciones |
|---|---|---|---|---|---|---|---|

### Paso 6: Declaración de Incertidumbre y Cierre
* Incluir una sección que documente las limitaciones del análisis (e.g. registros incompletos, identificadores ambiguos, logs ausentes).
* Explicar explícitamente los casos analizados que se determinaron como no maliciosos (falsos positivos descartados).

