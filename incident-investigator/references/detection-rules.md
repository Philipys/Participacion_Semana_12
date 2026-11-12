# Reglas de Detección de Incidentes de Seguridad

Este documento define los umbrales formales, convenciones y criterios para la identificación de incidentes en logs sintéticos de autenticación y acceso.

---

## 1. Convenciones Generales de Análisis

1. **Orden Temporal Obligatorio:**
   * Los registros deben ordenarse cronológicamente por la columna `timestamp` antes de evaluar ventanas temporales.
2. **Ventana Temporal:**
   * Las ventanas temporales son de **duración $\le 5$ minutos**, incluyendo ambos extremos temporales ($[t_{\text{inicio}}, t_{\text{inicio}} + 5\text{ min}]$).
3. **Coincidencia Exacta de Campos:**
   * Solo deben contabilizarse eventos cuyos valores en `event` y `result` coincidan de manera literal y exacta con los criterios de la regla.
4. **Citación de Evidencia:**
   * Toda evidencia citada debe referenciar el **número de fila exacto del archivo CSV original**, considerando la fila de encabezado (`timestamp,ip,user,event,result,detail`) como la **Fila 1**.
5. **Alcance y Naturaleza de las Conclusiones:**
   * Los hallazgos generados son **alertas justificadas basadas en registros**, no conclusiones forenses definitivas ni atribuciones de culpabilidad humana. Si existe ambigüedad o eventos duplicados no identificables inequívocamente, debe declararse la limitación técnica.

---

## 2. Catálogo de Reglas

### Regla 1: Fuerza Bruta Probable (Brute Force)
* **Criterio de Disparo:** Se detectan **6 o más** eventos con `event=login` y `result=failed` originados desde la **misma IP** y dirigidos hacia el **mismo usuario** dentro de una ventana de tiempo $\le 5$ minutos.
* **Seguimiento Crítico:** Si dentro de los 5 minutos posteriores al último intento fallido de la ventana se registra un evento `event=login` y `result=success` para ese mismo usuario e IP, debe reportarse de forma explícita y separada como una alerta de severidad crítica (posible compromiso exitoso tras fuerza bruta).

### Regla 2: Password Spraying Probable
* **Criterio de Disparo:** Se detectan eventos con `event=login` y `result=failed` originados desde la **misma IP** contra al menos **5 usuarios distintos** dentro de una ventana de tiempo $\le 5$ minutos.
* **Propósito:** Detectar intentos distribuidos de probar credenciales comunes contra múltiples cuentas para evadir bloqueos por usuario.

### Regla 3: Token Potencialmente Expuesto
* **Criterio de Disparo:** El campo `detail` contiene la cadena `token=` o variantes de asignación de secretos en texto plano.
* **Medida de Seguridad Obligatoria:** **NUNCA** imprimir, reflejar ni almacenar el valor completo del token en reportes o salidas. El valor del secreto debe reemplazarse estrictamente por la etiqueta `[REDACTED]`.

### Regla 4: Escalada No Autorizada según Registro
* **Criterio de Disparo:** Se registra un evento con `event=role_change` y `result=success` donde el campo `detail` especifica `approved=false`.
* **Interpretación:** Reportar como una anomalía de privilegios administrativos no autorizados según los registros del sistema. No inferir intencionalidad ni culpabilidad directa del usuario.

### Regla 5: Falsos Positivos y Actividad No Amenazante
* **Intentos Fallidos Aislados:** Intentos fallidos aislados (por ejemplo, 3 o menos fallos dispersos o fuera de la ventana de 5 minutos) corresponden a olvidos de contraseña típicos o errores de digitación; **no** deben clasificarse como fuerza bruta.
* **Eventos de Mantenimiento:** Eventos con `event=healthcheck` o tareas automatizadas no corresponden a intentos de login y no deben sumarse como `login/failed`.

