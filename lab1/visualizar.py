#!/usr/bin/env python3
"""
visualizar.py
Lab 1 - Tarea 1.3: Genera 3 graficas a partir de auth.log y access.log
"""
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

BASE = Path(__file__).parent
OUT_DIR = BASE / "graficas"
OUT_DIR.mkdir(exist_ok=True)

PATRON_SSH = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)"
)
PATRON_CLF = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ '
    r'\[(?P<fecha>[^\]]+)\] '
    r'"(?P<metodo>\S+) (?P<ruta>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
)
FORMATO_FECHA_APACHE = "%d/%b/%Y:%H:%M:%S %z"


def grafico_top10_ssh():
    conteo = Counter()
    with open(BASE / "auth.log", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = PATRON_SSH.search(linea)
            if m:
                conteo[m.group("ip")] += 1

    top10 = conteo.most_common(10)
    ips, valores = zip(*top10)

    plt.figure(figsize=(10, 6))
    sns.barplot(x=list(valores), y=list(ips), palette="Reds_r", orient="h")
    plt.title("Top 10 IPs con más intentos fallidos SSH")
    plt.xlabel("Número de intentos fallidos")
    plt.ylabel("Dirección IP")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "top10_ssh.png", dpi=150)
    plt.close()
    print("[OK] Generado: graficas/top10_ssh.png")


def _parsear_web():
    registros = []
    with open(BASE / "access.log", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            m = PATRON_CLF.search(linea)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group("fecha"), FORMATO_FECHA_APACHE)
            except ValueError:
                continue
            registros.append({"timestamp": ts, "status": int(m.group("status"))})
    return registros


def grafico_timeline_http(registros):
    df = pd.DataFrame(registros)
    df["hora"] = df["timestamp"].dt.floor("h")
    serie = df.groupby("hora").size()

    plt.figure(figsize=(12, 5))
    serie.plot(kind="line", marker="o", color="#1f77b4")
    plt.title("Peticiones HTTP por hora")
    plt.xlabel("Hora")
    plt.ylabel("Número de peticiones")
    plt.xticks(rotation=45)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "timeline_http.png", dpi=150)
    plt.close()
    print("[OK] Generado: graficas/timeline_http.png")


def grafico_heatmap_http(registros):
    df = pd.DataFrame(registros)
    df["hora_dia"] = df["timestamp"].dt.hour
    codigos_interes = [200, 301, 404, 500]
    df_filtrado = df[df["status"].isin(codigos_interes)]

    tabla = df_filtrado.pivot_table(index="status", columns="hora_dia", aggfunc="size", fill_value=0)
    tabla = tabla.reindex(codigos_interes)

    plt.figure(figsize=(14, 5))
    sns.heatmap(tabla, annot=True, fmt="d", cmap="YlOrRd", cbar_kws={"label": "Peticiones"})
    plt.title("Peticiones HTTP por hora y código de respuesta")
    plt.xlabel("Hora del día")
    plt.ylabel("Código de respuesta")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "heatmap_http.png", dpi=150)
    plt.close()
    print("[OK] Generado: graficas/heatmap_http.png")


def main():
    sns.set_style("whitegrid")
    grafico_top10_ssh()
    registros_web = _parsear_web()
    grafico_timeline_http(registros_web)
    grafico_heatmap_http(registros_web)
    print("\n[OK] Las 3 graficas fueron guardadas en lab1/graficas/")


if __name__ == "__main__":
    main()