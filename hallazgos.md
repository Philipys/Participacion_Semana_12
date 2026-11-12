# Informe de Hallazgos de Seguridad — Cyber Detective

**Archivo auditado:** `logs_sinteticos.csv` (94 filas: 1 cabecera + 93 registros)  
**Skill aplicado:** `incident-investigator`  
**Referencia consultada:** `incident-investigator/references/detection-rules.md`  

---

## 1. Tabla Resumen de Alertas Justificadas

| Alerta | Severidad Orientativa | Regla Aplicada | Timestamp | IP | Usuario | Filas / Evidencia (CSV original) | Justificación y Limitaciones |
|---|---|---|---|---|---|---|---|
| **Fuerza bruta probable con acceso posterior** | **Crítica** | Regla 1 (Fuerza Bruta: $\ge 6$ fallos en $\le 5$ min + éxito posterior en $\le 5$ min) | 2026-11-05 01:14:00 a 01:19:00 | `198.51.100.77` | `admin` | **Filas 17, 19, 20, 22, 23, 25, 26, 27** (fallos) y **Fila 28** (éxito) | Se registraron 8 intentos fallidos consecutivos en 4 minutos contra el usuario `admin`, seguidos inmediatamente a las 01:19:00 por una autenticación exitosa (`login after multiple failures`). *Limitación:* Dirección IP documental (RFC 5737); alerta técnica sin atribución de autoría humana. |
| **Token potencialmente expuesto** | **Media** | Regla 3 (Token en texto plano en columna `detail`) | 2026-11-05 01:27:00 | `192.0.2.44` | `api_service` | **Fila 33** | Registro con `event=debug`, `result=warning` expone credencial secreta en texto plano: `token=[REDACTED]; debug output`. *Medida:* Token redactado para evitar propagación de secretos. |
| **Escalada no autorizada de privilegios** | **Alta** | Regla 4 (role_change exitoso con `approved=false`) | 2026-11-05 01:50:00 | `203.0.113.42` | `guest` | **Fila 59** | Evento `role_change` exitoso con detalle explícito `role=user->admin; approved=false`. *Limitación:* El registro técnico no indica si fue una falla del mecanismo de control de acceso o una inyección; no se infiere culpabilidad del usuario `guest`. |
| **Password Spraying probable** | **Alta** | Regla 2 (Password Spraying: fallos desde misma IP contra $\ge 5$ usuarios en $\le 5$ min) | 2026-11-05 02:01:00 a 02:03:00 | `203.0.113.89` | Múltiples (`ana`, `carlos`, `luisa`, `diego`, `maria`, `sofia`) | **Filas 67, 68, 70, 71, 73, 74** | En una ventana de 2 minutos, la IP `203.0.113.89` intentó autenticarse sin éxito contra 6 cuentas de usuario distintas, indicando un patrón horizontal de prueba de contraseñas. |

---

## 2. Análisis de Falsos Positivos y Actividad Descartada

Conforme a la **Regla 5**, se evaluaron y descartaron formalmente los siguientes patrones:

1. **Tres fallos aislados de la usuaria `maria` (Filas 38, 39 y 41):**
   * *Timestamps:* 01:35:00, 01:36:00 y 01:37:00 desde la IP `192.0.2.25`.
   * *Detalle:* `mistyped password`.
   * *Justificación de descarte:* Ocurrieron 3 fallos y posteriormente un login exitoso en la Fila 42 (01:38:00). **No alcanza el umbral mínimo de 6 intentos fallidos** exigido por la Regla 1 para fuerza bruta. Corresponde al comportamiento benigno típico de olvido o error al escribir la contraseña.

2. **Monitoreo automatizado `healthbot` (Filas 78, 80, 81, 82, 83, 84):**
   * *Timestamps:* 02:10:00 a 02:15:00 desde la IP `192.0.2.200`.
   * *Evento:* `event=healthcheck`, `result=success`, `detail=scheduled monitoring`.
   * *Justificación de descarte:* Son verificaciones de estado rutinarias del sistema; no corresponden a eventos de `login/failed` ni constituyen anomalías operativas.

---

## 3. Verificación Manual Cruzada (Humana)

* **Fila seleccionada para verificación:** **Fila 28** del CSV original.
* **Contenido textual exacto en `logs_sinteticos.csv`:**
  ```text
  2026-11-05T01:19:00-05:00,198.51.100.77,admin,login,success,login after multiple failures
  ```
* **Concordancia:** Verificado directamente contra el archivo físico original. El registro confirma una autenticación exitosa a las 01:19:00 desde `198.51.100.77` para `admin`, exactamente un minuto después del octavo fallo consecutivo (Fila 27, 01:18:00), confirmando el evento de compromiso crítico sin depender de alucinaciones del modelo.

---

## 4. Limitaciones Técnicas y Declaración de Incertidumbre

1. **Aislamiento de red:** Las direcciones analizadas pertenecen a rangos de prueba y documentación (RFC 5737: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). No representan entidades reales en Internet.
2. **Ausencia de contexto de red adicional:** Los logs no contienen identificadores de sesión (session_id) ni agentes de usuario (User-Agent), lo cual impide determinar si múltiples eventos con la misma IP provinieron de un proxy compartido o NAT corporativo.

