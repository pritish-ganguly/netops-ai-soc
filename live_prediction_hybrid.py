from pathlib import Path
import time

import joblib
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "random_forest_hybrid_classifier.joblib"
FLOW_PATH = BASE_DIR / "data" / "live_network_flows.csv"
OUTPUT_PATH = BASE_DIR / "data" / "live_predictions.csv"
POLL_INTERVAL = 5

FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sttl",
    "dttl",
    "sload",
    "dload",
]

RAW_FEATURES = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
]

print()
print("=" * 60)
print("NETOPS AI - CONTINUOUS HYBRID ML ENGINE")
print("=" * 60)
print("\nLoading Hybrid Random Forest model...")

if not MODEL_PATH.exists():
    raise FileNotFoundError(f"Model not found:\n{MODEL_PATH}")

model = joblib.load(MODEL_PATH)

print("Hybrid model loaded successfully.")
print(f"\nMonitoring:")
print(FLOW_PATH)
print(f"\nPrediction output:")
print(OUTPUT_PATH)
print(f"\nPolling interval: {POLL_INTERVAL} seconds")
print("\nML engine is running.")
print("Press CTRL+C to stop.")

last_signature = None


def run_prediction():
    try:
        if not FLOW_PATH.exists():
            print("\n[ML] Waiting for flow collector...")
            return

        stat = FLOW_PATH.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        flows = pd.read_csv(FLOW_PATH)

        if flows.empty:
            print("\n[ML] Flow file is empty.")
            return

        print(
            f"\n[ML] New flow data detected | "
            f"Flows: {len(flows)}"
        )

        missing_raw = [
            feature for feature in RAW_FEATURES
            if feature not in flows.columns
        ]

        if missing_raw:
            print(f"[ML ERROR] Missing raw features: {missing_raw}")
            return

        for column in RAW_FEATURES:
            flows[column] = pd.to_numeric(
                flows[column],
                errors="coerce",
            )

        flows[RAW_FEATURES] = flows[RAW_FEATURES].fillna(0)

        flows["safe_dur"] = flows["dur"].replace(0, 0.000001)

        flows["rate"] = (
            flows["spkts"] + flows["dpkts"]
        ) / flows["safe_dur"]

        flows["sload"] = (
            flows["sbytes"] * 8
        ) / flows["safe_dur"]

        flows["dload"] = (
            flows["dbytes"] * 8
        ) / flows["safe_dur"]

        for column in ["rate", "sload", "dload"]:
            flows[column] = (
                flows[column]
                .replace([np.inf, -np.inf], 0)
                .fillna(0)
            )

        missing_features = [
            feature for feature in FEATURES
            if feature not in flows.columns
        ]

        if missing_features:
            print(
                "[ML ERROR] Missing model features: "
                f"{missing_features}"
            )
            return

        X = flows[FEATURES].copy()
        X = (
            X
            .replace([np.inf, -np.inf], 0)
            .fillna(0)
        )

        predictions = model.predict(X)

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X)
            classes = list(model.classes_)

            if 1 in classes:
                attack_index = classes.index(1)
                confidence = probabilities[:, attack_index]
            else:
                confidence = np.zeros(len(X))
        else:
            confidence = predictions.astype(float)

        results = flows.copy()
        results["prediction"] = predictions
        results["confidence"] = confidence
        results["status"] = np.where(
            results["prediction"] == 1,
            "ATTACK",
            "NORMAL",
        )

        OUTPUT_PATH.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        results.to_csv(
            OUTPUT_PATH,
            index=False,
        )

        output_stat = OUTPUT_PATH.stat()

        normal = int((results["prediction"] == 0).sum())
        attacks = int((results["prediction"] == 1).sum())

        print(
            f"[ML] Prediction complete | "
            f"Flows: {len(results)} | "
            f"Normal: {normal} | "
            f"Attack: {attacks}"
        )

        print(
            f"[ML] CSV updated | "
            f"Size: {output_stat.st_size} bytes | "
            f"Time: {time.strftime('%H:%M:%S')}"
        )

        return signature

    except Exception as error:
        print(f"\n[ML ERROR] {error}")
        return None


try:
    while True:
        current_signature = None

        if FLOW_PATH.exists():
            stat = FLOW_PATH.stat()
            current_signature = (stat.st_mtime_ns, stat.st_size)

        if last_signature is None:
            new_signature = run_prediction()

            if new_signature is not None:
                last_signature = new_signature

        elif current_signature != last_signature:
            new_signature = run_prediction()

            if new_signature is not None:
                last_signature = new_signature

        else:
            print(
                f"[ML] Waiting for new flow data... "
                f"{time.strftime('%H:%M:%S')}"
            )

        time.sleep(POLL_INTERVAL)

except KeyboardInterrupt:
    print()
    print("=" * 60)
    print("HYBRID ML ENGINE STOPPED")
    print("=" * 60)
