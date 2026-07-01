#!/usr/bin/env python3
"""
predecir.py
Lab 3 - Tarea 3.4: Carga el modelo entrenado y clasifica trafico nuevo.

Uso:
    python predecir.py nuevo_trafico.csv
"""
import sys
import joblib
import numpy as np
import pandas as pd
from pathlib import Path

BASE = Path(__file__).parent
MODELO_PATH = BASE / "modelo_anomalias.pkl"
SCALER_PATH = BASE / "scaler.pkl"

FEATURES = [
    "bytes_sent", "bytes_recv", "duration_sec", "packets",
    "ratio_bytes", "bytes_por_segundo", "paquetes_por_segundo", "fuera_horario",
]
COLUMNAS_SESGADAS = ["bytes_sent", "bytes_recv", "duration_sec", "packets",
                      "ratio_bytes", "bytes_por_segundo", "paquetes_por_segundo"]


def construir_features(df):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["ratio_bytes"] = df["bytes_sent"] / (df["bytes_recv"] + 1)
    df["bytes_por_segundo"] = (df["bytes_sent"] + df["bytes_recv"]) / (df["duration_sec"] + 0.01)
    df["paquetes_por_segundo"] = df["packets"] / (df["duration_sec"] + 0.01)
    df["hora"] = df["timestamp"].dt.hour
    df["fuera_horario"] = ((df["hora"] >= 22) | (df["hora"] < 6)).astype(int)

    df_features = df[FEATURES].copy()
    for col in COLUMNAS_SESGADAS:
        df_features[col] = np.log1p(df_features[col])
    return df, df_features


def main():
    if len(sys.argv) != 2:
        print("Uso: python predecir.py <archivo.csv>")
        sys.exit(1)

    ruta_csv = Path(sys.argv[1])
    if not ruta_csv.exists():
        print(f"[ERROR] No se encontro el archivo: {ruta_csv}")
        sys.exit(1)

    modelo = joblib.load(MODELO_PATH)
    scaler = joblib.load(SCALER_PATH)

    df_original = pd.read_csv(ruta_csv)
    df_original, df_features = construir_features(df_original)

    X = scaler.transform(df_features)
    df_original["prediccion"] = modelo.predict(X)
    df_original["score_anomalia"] = modelo.decision_function(X)

    anomalos = df_original[df_original["prediccion"] == -1].sort_values("score_anomalia")

    print(f"Registros analizados: {len(df_original)}")
    print(f"Anomalias detectadas: {len(anomalos)}\n")

    if anomalos.empty:
        print("No se detectaron anomalias en este archivo.")
        return

    print(f"{'src_ip':<16}{'dst_ip':<16}{'dst_port':<10}{'bytes_sent':<14}{'score':<10}")
    print("-" * 66)
    for _, fila in anomalos.iterrows():
        print(f"{fila['src_ip']:<16}{fila['dst_ip']:<16}{fila['dst_port']:<10}"
              f"{fila['bytes_sent']:<14}{fila['score_anomalia']:.4f}")


if __name__ == "__main__":
    main()