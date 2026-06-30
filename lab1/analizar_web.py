#!/usr/bin/env python3
"""
analizar_web.py
Lab 1 - Tarea 1.2: Analisis de access.log (Combined Log Format de Apache)
Detecta escaneo de directorios, errores 4xx/5xx por IP e intentos de SQL Injection.
"""
import re
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).parent / "access.log"
REPORT_PATH = Path(__file__).parent / "reporte_web.json"

VENTANA_ESCANEO_SEG = 60
UMBRAL_RUTAS_DISTINTAS = 20

PATRONES_SQLI = ["UNION", "SELECT", "--", "OR 1=1", "'"]

PATRON_CLF = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ '
    r'\[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)

FORMATO_FECHA_APACHE = "%d/%b/%Y:%H:%M:%S %z"


def parsear_access_log(ruta):
    registros = []
    if not ruta.exists():
        print(f"[ERROR] No se encontro el archivo: {ruta}")
        sys.exit(1)

    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = PATRON_CLF.search(linea)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("fecha"), FORMATO_FECHA_APACHE)
            except ValueError:
                continue
            registros.append({
                "ip": m.group("ip"),
                "timestamp": ts,
                "metodo": m.group("metodo"),
                "ruta": m.group("ruta"),
                "status": int(m.group("status")),
            })
    return registros


def detectar_escaneo_directorios(registros):
    por_ip = defaultdict(list)
    for r in registros:
        por_ip[r["ip"]].append(r)

    hallazgos = []
    for ip, eventos in por_ip.items():
        eventos.sort(key=lambda e: e["timestamp"])
        inicio = 0
        for fin in range(len(eventos)):
            while (eventos[fin]["timestamp"] - eventos[inicio]["timestamp"]).total_seconds() > VENTANA_ESCANEO_SEG:
                inicio += 1
            rutas_en_ventana = {eventos[i]["ruta"] for i in range(inicio, fin + 1)}
            if len(rutas_en_ventana) > UMBRAL_RUTAS_DISTINTAS:
                hallazgos.append({
                    "ip": ip,
                    "rutas_distintas": len(rutas_en_ventana),
                    "ventana_inicio": eventos[inicio]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                    "ventana_fin": eventos[fin]["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                })
                break
    return hallazgos


def detectar_errores_por_ip(registros):
    errores = defaultdict(lambda: {"4xx": 0, "5xx": 0})
    for r in registros:
        if 400 <= r["status"] < 500:
            errores[r["ip"]]["4xx"] += 1
        elif 500 <= r["status"] < 600:
            errores[r["ip"]]["5xx"] += 1
    return {ip: v for ip, v in errores.items() if v["4xx"] or v["5xx"]}


def detectar_sqli(registros):
    hallazgos = []
    for r in registros:
        ruta_upper = r["ruta"].upper()
        coincidencias = [p for p in PATRONES_SQLI if p.upper() in ruta_upper]
        if coincidencias:
            hallazgos.append({
                "ip": r["ip"],
                "ruta": r["ruta"],
                "patrones_detectados": coincidencias,
                "timestamp": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
            })
    return hallazgos


def main():
    registros = parsear_access_log(LOG_PATH)
    print(f"Total de peticiones parseadas: {len(registros)}")

    print("\n--- Escaneo de directorios detectado ---")
    escaneos = detectar_escaneo_directorios(registros)
    if escaneos:
        for h in escaneos:
            print(f"[ALERTA] Posible escaneo de directorios desde {h['ip']}: "
                  f"{h['rutas_distintas']} rutas distintas entre "
                  f"{h['ventana_inicio']} y {h['ventana_fin']}")
    else:
        print("Sin escaneos de directorios detectados con el umbral configurado.")

    print("\n--- Errores 4xx/5xx agrupados por IP (top 10) ---")
    errores = detectar_errores_por_ip(registros)
    for ip, v in sorted(errores.items(), key=lambda x: -(x[1]["4xx"] + x[1]["5xx"]))[:10]:
        print(f"  {ip:<18} 4xx={v['4xx']:<4} 5xx={v['5xx']}")

    print("\n--- Posibles intentos de SQL Injection ---")
    sqli = detectar_sqli(registros)
    for h in sqli[:20]:
        print(f"[ALERTA] SQLi sospechoso desde {h['ip']} -> {h['ruta']} "
              f"(patrones: {', '.join(h['patrones_detectados'])})")
    if not sqli:
        print("Sin patrones de SQLi detectados.")

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_peticiones": len(registros),
        "escaneo_directorios": escaneos,
        "errores_por_ip": errores,
        "intentos_sqli": sqli,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Reporte exportado a: {REPORT_PATH}")


if __name__ == "__main__":
    main()