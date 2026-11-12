 """Script auxiliar opcional para análisis reproducible de logs CSV de seguridad.

Aplica las reglas definidas en references/detection-rules.md:
- Fuerza bruta (>= 6 logins fallidos en <= 5 min misma IP y usuario + éxito posterior)
- Password spraying (>= 5 usuarios distintos fallidos en <= 5 min misma IP)
- Tokens expuestos (redacción con [REDACTED])
- Escalada no autorizada (role_change/success con approved=false)
- Descarte de falsos positivos (<= 3 fallos aislados, healthchecks)
"""

import csv
import re
from datetime import datetime


def parse_iso(ts_str):
    # Formato ISO-8601 con zona horaria
    # Ej: 2026-11-05T01:01:00-05:00
    # Python 3.7+ fromisoformat soporta offsets
    return datetime.fromisoformat(ts_str)


def analyze_csv(filepath):
    with open(filepath, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        records = []
        # Fila 1 es el encabezado en csv.DictReader, así que el primer registro es fila 2
        for idx, row in enumerate(reader, start=2):
            records.append({
                "row": idx,
                "timestamp_str": row["timestamp"],
                "dt": parse_iso(row["timestamp"]),
                "ip": row["ip"],
                "user": row["user"],
                "event": row["event"],
                "result": row["result"],
                "detail": row["detail"]
            })

    # Asegurar orden temporal
    records.sort(key=lambda x: x["dt"])

    findings = []

    # 1. Búsqueda de Tokens Expuestos
    for r in records:
        if "token=" in r["detail"]:
            redacted_detail = re.sub(r"token=[^;\s]+", "token=[REDACTED]", r["detail"])
            findings.append({
                "alerta": "Token potencialmente expuesto",
                "severidad": "Media",
                "regla": "Regla 3: Token en texto plano",
                "timestamp": r["timestamp_str"],
                "ip": r["ip"],
                "usuario": r["user"],
                "filas": [r["row"]],
                "detalle": redacted_detail,
                "limitaciones": "Secreto detectado en traza de depuración; no se expone el valor real."
            })

    # 2. Búsqueda de Escalada No Autorizada
    for r in records:
        if r["event"] == "role_change" and r["result"] == "success" and "approved=false" in r["detail"]:
            findings.append({
                "alerta": "Escalada no autorizada de privilegios",
                "severidad": "Alta",
                "regla": "Regla 4: role_change con approved=false",
                "timestamp": r["timestamp_str"],
                "ip": r["ip"],
                "usuario": r["user"],
                "filas": [r["row"]],
                "detalle": r["detail"],
                "limitaciones": "Registro marca approved=false. No se infiere culpabilidad o intencionalidad humana."
            })

    # 3. Fuerza Bruta
    # Agrupar por (ip, user) con event=login y result=failed
    user_ip_fails = {}
    for r in records:
        if r["event"] == "login" and r["result"] == "failed":
            key = (r["ip"], r["user"])
            user_ip_fails.setdefault(key, []).append(r)

    for (ip, user), fails in user_ip_fails.items():
        # Ventanas móviles de <= 5 minutos
        for i in range(len(fails)):
            window = [fails[i]]
            for j in range(i + 1, len(fails)):
                delta = (fails[j]["dt"] - fails[i]["dt"]).total_seconds()
                if delta <= 300: # 5 minutos
                    window.append(fails[j])
                else:
                    break
            if len(window) >= 6:
                rows = [w["row"] for w in window]
                # Verificar éxito posterior dentro de 5 min del último fallo
                last_fail_dt = window[-1]["dt"]
                subsequent_success = [
                    r for r in records
                    if r["ip"] == ip and r["user"] == user and r["event"] == "login" and r["result"] == "success"
                    and 0 < (r["dt"] - last_fail_dt).total_seconds() <= 300
                ]
                succ_rows = [s["row"] for s in subsequent_success]
                findings.append({
                    "alerta": "Fuerza bruta probable",
                    "severidad": "Alta" if not succ_rows else "Crítica (con login exitoso posterior)",
                    "regla": "Regla 1: >= 6 login/failed en <= 5 min",
                    "timestamp": f"{window[0]['timestamp_str']} a {window[-1]['timestamp_str']}",
                    "ip": ip,
                    "usuario": user,
                    "filas": rows + (succ_rows if succ_rows else []),
                    "detalle": f"{len(window)} fallos consecutivos." + (f" Éxito posterior en fila(s) {succ_rows}." if succ_rows else ""),
                    "limitaciones": "Basado en ventana móvil <= 5 min. Registros corresponden a IPs de prueba."
                })
                break # Evitar duplicar alertas de la misma ráfaga

    # 4. Password Spraying
    # Agrupar por IP con event=login y result=failed
    ip_fails = {}
    for r in records:
        if r["event"] == "login" and r["result"] == "failed":
            ip_fails.setdefault(r["ip"], []).append(r)

    for ip, fails in ip_fails.items():
        for i in range(len(fails)):
            window = [fails[i]]
            for j in range(i + 1, len(fails)):
                delta = (fails[j]["dt"] - fails[i]["dt"]).total_seconds()
                if delta <= 300:
                    window.append(fails[j])
                else:
                    break
            distinct_users = {w["user"] for w in window}
            if len(distinct_users) >= 5:
                rows = [w["row"] for w in window]
                findings.append({
                    "alerta": "Password spraying probable",
                    "severidad": "Alta",
                    "regla": "Regla 2: login/failed contra >= 5 usuarios en <= 5 min",
                    "timestamp": f"{window[0]['timestamp_str']} a {window[-1]['timestamp_str']}",
                    "ip": ip,
                    "usuario": f"Múltiples ({len(distinct_users)} usuarios: {', '.join(sorted(distinct_users))})",
                    "filas": rows,
                    "detalle": f"Ataque distribuido contra {len(distinct_users)} cuentas distintas.",
                    "limitaciones": "Ventana temporal de 5 min evaluada sobre la misma IP de origen."
                })
                break

    return findings


if __name__ == "__main__":
    import json
    res = analyze_csv("logs_sinteticos.csv")
    print(json.dumps(res, indent=2, ensure_ascii=False))

