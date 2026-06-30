#!/usr/bin/env python3
"""
analizar_ssh.py
Lab 1 - Tarea 1.1: Parseo y estadisticas de auth.log
Detecta intentos fallidos de SSH, genera ranking de IPs y un reporte JSON.
"""
import re
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_PATH = Path(__file__).parent / "auth.log"
REPORT_PATH = Path(__file__).parent / "reporte_ssh.json"
UMBRAL_ALERTA = 50          # intentos para disparar [ALERTA]
TOP_N = 10

# Cubre: "Failed password for root from X port Y ssh2"
#    y:  "Failed password for invalid user bob from X port Y ssh2"
PATRON_FALLO = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)


def parsear_auth_log(ruta):
    """Lee el archivo linea por linea y devuelve la lista de intentos fallidos."""
    intentos = []
    if not ruta.exists():
        print(f"[ERROR] No se encontro el archivo: {ruta}")
        sys.exit(1)

    with open(ruta, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = PATRON_FALLO.search(linea)
            if m:
                intentos.append({
                    "usuario": m.group("user"),
                    "ip": m.group("ip"),
                    "puerto": m.group("port"),
                })
    return intentos


def main():
    intentos = parsear_auth_log(LOG_PATH)
    total = len(intentos)

    conteo_por_ip = Counter(i["ip"] for i in intentos)
    top_ips = conteo_por_ip.most_common(TOP_N)

    print("=" * 60)
    print(" RANKING DE IPs CON MAS INTENTOS FALLIDOS DE SSH (Top 10)")
    print("=" * 60)
    for pos, (ip, cuenta) in enumerate(top_ips, start=1):
        print(f"  {pos:2d}. {ip:<18} -> {cuenta} intentos fallidos")
    print("-" * 60)
    print(f" Total de intentos fallidos analizados: {total}")
    print("-" * 60)

    ips_sospechosas = []
    for ip, cuenta in conteo_por_ip.most_common():
        es_alerta = cuenta > UMBRAL_ALERTA
        ips_sospechosas.append({
            "ip": ip,
            "intentos": cuenta,
            "alerta": es_alerta,
        })
        if es_alerta:
            print(f"[ALERTA] IP: {ip} - {cuenta} intentos fallidos "
                  f"- Posible ataque de fuerza bruta")

    reporte = {
        "fecha_analisis": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_intentos_fallidos": total,
        "ips_sospechosas": ips_sospechosas[:TOP_N],
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(reporte, f, indent=2, ensure_ascii=False)

    print(f"\n[OK] Reporte exportado a: {REPORT_PATH}")


if __name__ == "__main__":
    main()