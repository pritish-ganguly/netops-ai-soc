from pathlib import Path
import ipaddress
import time
import sqlite3
from datetime import datetime

import pandas as pd

from database import initialize_database, save_alert, build_alert_key


# ============================================================
# NETOPS AI SOC - LIVE DETECTION / RISK ENGINE
# ============================================================
#
# Pipeline:
#
# live_predictions.csv
#        +
# live_network_flows.csv
#        ↓
# feature normalization
#        ↓
# connection/context analysis
#        ↓
# ML + traffic risk scoring
#        ↓
# severity + attack category + evidence
#        ↓
# SQLite alert database
#
# Database:
#     data/netops_alerts.db
#
# ============================================================


BASE_DIR = Path(__file__).resolve().parent

PREDICTIONS_PATH = (
    BASE_DIR / "data" / "live_predictions.csv"
)

FLOWS_PATH = (
    BASE_DIR / "data" / "live_network_flows.csv"
)

ALERTS_PATH = (
    BASE_DIR / "data" / "live_alerts.csv"
)

CHECK_INTERVAL = 5


# ============================================================
# RISK THRESHOLDS
# ============================================================

ML_LOW = 0.60
ML_HIGH = 0.75

PACKET_RATE_HIGH = 500
PACKET_RATE_VERY_HIGH = 1000

BYTE_RATE_HIGH = 500_000

REPEATED_CONNECTIONS = 4
VERY_REPEATED_CONNECTIONS = 10

PUBLIC_DESTINATION_SCORE = 5
MULTICAST_SUPPRESSION_SCORE = 70

# Minimum risk for a non-explicit-ATTACK event to become a
# persistent SOC security alert. ML predictions remain in the
# live prediction file; this threshold prevents alert flooding.
MIN_SECURITY_ALERT_RISK = 50


# ============================================================
# DATABASE
# ============================================================

initialize_database()


# ============================================================
# SAFE NUMERIC CONVERSION
# ============================================================

def number(value, default=0.0):

    try:
        value = float(value)

        if pd.isna(value):
            return default

        return value

    except (TypeError, ValueError):
        return default


def integer(value, default=0):

    try:
        value = int(float(value))

        return value

    except (TypeError, ValueError):
        return default


# ============================================================
# IP CONTEXT
# ============================================================

def is_private_ip(ip):

    try:
        return ipaddress.ip_address(
            str(ip)
        ).is_private

    except ValueError:
        return False


def is_multicast_ip(ip):

    try:
        return ipaddress.ip_address(
            str(ip)
        ).is_multicast

    except ValueError:
        return False


def is_loopback_ip(ip):

    try:
        return ipaddress.ip_address(
            str(ip)
        ).is_loopback

    except ValueError:
        return False


# ============================================================
# PROTOCOL CONTEXT
# ============================================================

def protocol_context(row):

    protocol = str(
        row.get("protocol", "")
    ).lower()

    src_port = integer(
        row.get("src_port", 0)
    )

    dst_port = integer(
        row.get("dst_port", 0)
    )

    if (
        protocol == "udp"
        and (
            src_port == 5353
            or dst_port == 5353
        )
    ):
        return "MDNS"

    if (
        protocol == "udp"
        and (
            src_port == 1900
            or dst_port == 1900
        )
    ):
        return "SSDP"

    if (
        protocol == "udp"
        and (
            src_port == 53
            or dst_port == 53
        )
    ):
        return "DNS"

    if (
        src_port == 80
        or dst_port == 80
    ):
        return "HTTP"

    if (
        src_port == 443
        or dst_port == 443
    ):
        return "HTTPS"

    if protocol in ("1", "icmp"):
        return "ICMP"

    return "OTHER"


# ============================================================
# ATTACK CATEGORY
# ============================================================

def determine_attack_category(
    categories,
    context,
    confidence,
    packet_rate,
    byte_rate,
    connection_count,
    destination_ip,
):

    categories = list(categories)

    if (
        connection_count >= VERY_REPEATED_CONNECTIONS
        and packet_rate >= PACKET_RATE_HIGH
    ):
        return "CONNECTION_FLOOD"

    if packet_rate >= PACKET_RATE_VERY_HIGH:
        return "HIGH_RATE_ANOMALY"

    if byte_rate >= BYTE_RATE_HIGH:
        return "HIGH_VOLUME_TRAFFIC"

    if (
        "ML_HIGH_CONFIDENCE"
        in categories
    ):
        return "ML_HIGH_CONFIDENCE"

    if (
        "REPEATED_CONNECTION"
        in categories
    ):
        return "REPEATED_CONNECTION"

    if (
        "ML_ANOMALY"
        in categories
    ):
        return "ML_ANOMALY"

    if (
        is_multicast_ip(destination_ip)
        and context in ("MDNS", "SSDP")
    ):
        return "NETWORK_DISCOVERY"

    if confidence >= ML_LOW:
        return "ML_ANOMALY"

    return "TRAFFIC_ANOMALY"


# ============================================================
# SEVERITY
# ============================================================

def calculate_severity(risk_score):

    risk_score = number(risk_score)

    if risk_score >= 75:
        return "HIGH"

    if risk_score >= 50:
        return "MEDIUM"

    return "LOW"


# ============================================================
# RISK ENGINE
# ============================================================

def calculate_risk(row):

    confidence = number(
        row.get("confidence")
    )

    packet_rate = number(
        row.get("packet_rate")
    )

    byte_rate = number(
        row.get("byte_rate")
    )

    connection_count = integer(
        row.get("connection_count")
    )

    src_ip = str(
        row.get("src_ip", "")
    )

    dst_ip = str(
        row.get("dst_ip", "")
    )

    protocol = str(
        row.get("protocol", "")
    ).lower()

    context = protocol_context(row)

    score = 0.0

    evidence = []

    categories = []

    # --------------------------------------------------------
    # ML CONFIDENCE
    # --------------------------------------------------------

    if confidence >= ML_HIGH:

        score += 35

        categories.append(
            "ML_HIGH_CONFIDENCE"
        )

        evidence.append(
            f"ML confidence {confidence:.2f}"
        )

    elif confidence >= ML_LOW:

        score += 20

        categories.append(
            "ML_ANOMALY"
        )

        evidence.append(
            f"Moderate ML confidence {confidence:.2f}"
        )

    else:

        evidence.append(
            f"Low ML confidence {confidence:.2f}"
        )

    # --------------------------------------------------------
    # PACKET RATE
    # --------------------------------------------------------

    if packet_rate >= PACKET_RATE_VERY_HIGH:

        score += 25

        categories.append(
            "HIGH_PACKET_RATE"
        )

        evidence.append(
            f"Very high packet rate "
            f"{packet_rate:.1f}/s"
        )

    elif packet_rate >= PACKET_RATE_HIGH:

        score += 15

        categories.append(
            "HIGH_PACKET_RATE"
        )

        evidence.append(
            f"High packet rate "
            f"{packet_rate:.1f}/s"
        )

    # --------------------------------------------------------
    # BYTE RATE
    # --------------------------------------------------------

    if byte_rate >= BYTE_RATE_HIGH:

        score += 15

        categories.append(
            "HIGH_BYTE_RATE"
        )

        evidence.append(
            f"High byte rate "
            f"{byte_rate:.0f}/s"
        )

    # --------------------------------------------------------
    # REPEATED CONNECTIONS
    # --------------------------------------------------------

    if connection_count >= VERY_REPEATED_CONNECTIONS:

        score += 20

        categories.append(
            "REPEATED_CONNECTION"
        )

        evidence.append(
            f"Very frequent connection pattern "
            f"({connection_count} connections)"
        )

    elif connection_count >= REPEATED_CONNECTIONS:

        score += 10

        categories.append(
            "REPEATED_CONNECTION"
        )

        evidence.append(
            f"Repeated connection pattern "
            f"({connection_count} connections)"
        )

    # --------------------------------------------------------
    # PUBLIC DESTINATION
    # --------------------------------------------------------

    if (
        is_private_ip(src_ip)
        and not is_private_ip(dst_ip)
        and not is_multicast_ip(dst_ip)
    ):

        score += PUBLIC_DESTINATION_SCORE

        evidence.append(
            "Private source communicating "
            "with public destination"
        )

    # --------------------------------------------------------
    # PROTOCOL CONTEXT
    # --------------------------------------------------------

    if context in ("MDNS", "SSDP"):

        evidence.append(
            f"Local discovery protocol: {context}"
        )

    elif context == "DNS":

        evidence.append(
            "DNS traffic observed"
        )

    elif context == "ICMP":

        evidence.append(
            "ICMP traffic observed"
        )

    # --------------------------------------------------------
    # MULTICAST DISCOVERY SHOULD NOT BE OVER-PENALIZED
    # --------------------------------------------------------

    if (
        is_multicast_ip(dst_ip)
        and context in ("MDNS", "SSDP")
    ):

        score = min(
            score,
            MULTICAST_SUPPRESSION_SCORE
        )

    # --------------------------------------------------------
    # CAP SCORE
    # --------------------------------------------------------

    score = min(
        round(score, 2),
        100.0
    )

    attack_category = determine_attack_category(
        categories=categories,
        context=context,
        confidence=confidence,
        packet_rate=packet_rate,
        byte_rate=byte_rate,
        connection_count=connection_count,
        destination_ip=dst_ip,
    )

    severity = calculate_severity(
        score
    )

    if not evidence:

        evidence.append(
            "Traffic anomaly detected by "
            "the live detection engine"
        )

    return {
        "severity": severity,
        "risk_score": score,
        "confidence": round(
            confidence,
            4
        ),
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "protocol": protocol,
        "source_port": integer(
            row.get("src_port")
        ),
        "destination_port": integer(
            row.get("dst_port")
        ),
        "packet_rate": round(
            packet_rate,
            4
        ),
        "byte_rate": round(
            byte_rate,
            4
        ),
        "connection_count": connection_count,
        "protocol_context": context,
        "attack_category": attack_category,
        "evidence": " | ".join(
            evidence
        ),
    }


# ============================================================
# LOAD DATA
# ============================================================

def load_live_data():

    if not PREDICTIONS_PATH.exists():

        print(
            "[WAIT] Prediction file not found:"
        )

        print(
            PREDICTIONS_PATH
        )

        return pd.DataFrame()

    if not FLOWS_PATH.exists():

        print(
            "[WAIT] Flow file not found:"
        )

        print(
            FLOWS_PATH
        )

        return pd.DataFrame()

    try:

        predictions = pd.read_csv(
            PREDICTIONS_PATH
        )

        flows = pd.read_csv(
            FLOWS_PATH
        )

    except Exception as error:

        print(
            "[ERROR] Could not read live data:",
            error
        )

        return pd.DataFrame()

    if predictions.empty:

        return pd.DataFrame()

    if flows.empty:

        return pd.DataFrame()

    return predictions, flows


# ============================================================
# PREPARE LIVE DATA
# ============================================================

def prepare_data(predictions, flows):

    predictions = predictions.copy()

    flows = flows.copy()

    # --------------------------------------------------------
    # Normalize names
    # --------------------------------------------------------

    if "src_ip" not in predictions.columns:
        return pd.DataFrame()

    if "dst_ip" not in predictions.columns:
        return pd.DataFrame()

    # --------------------------------------------------------
    # Normalize prediction fields
    # --------------------------------------------------------

    predictions["confidence"] = pd.to_numeric(
        predictions.get(
            "confidence",
            0
        ),
        errors="coerce"
    ).fillna(0)

    predictions["status"] = (
        predictions.get(
            "status",
            "NORMAL"
        )
        .astype(str)
        .str.upper()
    )

    # --------------------------------------------------------
    # Merge on the network-flow identity where possible.
    #
    # If multiple rows have the same identity, preserve the
    # newest prediction row for that identity.
    # --------------------------------------------------------

    identity = [
        "src_ip",
        "dst_ip",
        "protocol",
    ]

    available_identity = [
        column
        for column in identity
        if (
            column in predictions.columns
            and column in flows.columns
        )
    ]

    if not available_identity:

        return pd.DataFrame()

    prediction_columns = [
        column
        for column in [
            "src_ip",
            "dst_ip",
            "protocol",
            "status",
            "prediction",
            "confidence",
        ]
        if column in predictions.columns
    ]

    prediction_view = (
        predictions[
            prediction_columns
        ]
        .drop_duplicates(
            subset=available_identity,
            keep="last"
        )
    )

    merged = flows.merge(
        prediction_view,
        on=available_identity,
        how="left",
        suffixes=(
            "",
            "_prediction"
        )
    )

    # --------------------------------------------------------
    # Fill prediction values
    # --------------------------------------------------------

    if "confidence_prediction" in merged.columns:

        merged["confidence"] = (
            merged["confidence_prediction"]
            .fillna(
                merged.get(
                    "confidence",
                    0
                )
            )
        )

    elif "confidence" not in merged.columns:

        merged["confidence"] = 0.0

    if "status_prediction" in merged.columns:

        merged["status"] = (
            merged["status_prediction"]
            .fillna(
                merged.get(
                    "status",
                    "NORMAL"
                )
            )
        )

    elif "status" not in merged.columns:

        merged["status"] = "NORMAL"

    # --------------------------------------------------------
    # Numeric traffic fields
    # --------------------------------------------------------

    numeric_columns = [
        "dur",
        "spkts",
        "dpkts",
        "sbytes",
        "dbytes",
        "rate",
        "sload",
        "dload",
    ]

    for column in numeric_columns:

        if column in merged.columns:

            merged[column] = pd.to_numeric(
                merged[column],
                errors="coerce"
            ).fillna(0)

    # --------------------------------------------------------
    # Packet rate
    #
    # Prefer model-generated rate.
    # --------------------------------------------------------

    if "rate" in merged.columns:

        merged["packet_rate"] = (
            merged["rate"]
            .astype(float)
        )

    else:

        merged["packet_rate"] = 0.0

    # --------------------------------------------------------
    # Byte rate
    #
    # sload + dload are bits/sec in UNSW-NB15 style data.
    # Convert to bytes/sec for the risk engine.
    # --------------------------------------------------------

    if (
        "sload" in merged.columns
        and "dload" in merged.columns
    ):

        merged["byte_rate"] = (
            (
                merged["sload"].fillna(0)
                + merged["dload"].fillna(0)
            )
            / 8.0
        )

    elif (
        "sbytes" in merged.columns
        and "dbytes" in merged.columns
    ):

        merged["byte_rate"] = (
            merged["sbytes"].fillna(0)
            + merged["dbytes"].fillna(0)
        )

    else:

        merged["byte_rate"] = 0.0

    # --------------------------------------------------------
    # Connection count
    # --------------------------------------------------------

    group_columns = [
        column
        for column in [
            "src_ip",
            "dst_ip",
            "protocol",
        ]
        if column in merged.columns
    ]

    if group_columns:

        counts = (
            merged
            .groupby(
                group_columns,
                dropna=False
            )
            .size()
            .rename(
                "connection_count"
            )
            .reset_index()
        )

        merged = merged.merge(
            counts,
            on=group_columns,
            how="left"
        )

    else:

        merged["connection_count"] = 1

    merged["connection_count"] = (
        pd.to_numeric(
            merged[
                "connection_count"
            ],
            errors="coerce"
        )
        .fillna(1)
        .astype(int)
    )

    return merged


# ============================================================
# PROCESS ONE BATCH
# ============================================================

def build_alert(row):

    status = str(
        row.get("status", "NORMAL")
    ).upper()

    confidence = number(
        row.get("confidence", 0)
    )

    # Explicit model ATTACK or sufficiently confident ML anomaly.
    if not (
        status == "ATTACK"
        or confidence >= ML_LOW
    ):
        return None

    risk = calculate_risk(row)

    # Local discovery traffic with low risk is telemetry, not a
    # persistent security alert.
    if (
        risk["attack_category"] == "NETWORK_DISCOVERY"
        and risk["risk_score"] < MIN_SECURITY_ALERT_RISK
    ):
        return None

    # Do not flood the SOC database with LOW-risk anomalies.
    # Explicit ATTACK predictions are retained regardless of score.
    if (
        status != "ATTACK"
        and risk["risk_score"] < MIN_SECURITY_ALERT_RISK
    ):
        return None

    alert = {
        "timestamp": datetime.now().isoformat(),
        "source": "NetOps AI",
        "event_type": "ML_ANOMALY",
        "severity": risk["severity"],
        "description": (
            "Hybrid ML and traffic-analysis engine detected "
            "potentially suspicious network activity."
        ),
        "status": "OPEN",
        "confidence": risk["confidence"],
        "source_ip": risk["source_ip"],
        "destination_ip": risk["destination_ip"],
        "protocol": risk["protocol"],
        "source_port": risk["source_port"],
        "destination_port": risk["destination_port"],
        "attack_category": risk["attack_category"],
        "risk_score": risk["risk_score"],
        "packet_rate": risk["packet_rate"],
        "byte_rate": risk["byte_rate"],
        "connection_count": risk["connection_count"],
        "evidence": risk["evidence"],
        "protocol_context": risk["protocol_context"],
    }

    # Stable SOC identity. Deliberately excludes timestamp,
    # confidence, risk, evidence, packet rate and connection count.
    alert["alert_key"] = build_alert_key(alert)

    return alert


def process_batch():

    data = load_live_data()

    if not data:
        return 0, 0, 0

    predictions, flows = data

    merged = prepare_data(
        predictions,
        flows
    )

    if merged.empty:
        print("[WAIT] No usable live traffic records.")
        return 0, 0, 0

    # --------------------------------------------------------
    # FIRST-LEVEL DEDUPLICATION
    # --------------------------------------------------------
    # Multiple flow rows representing the same SOC event are
    # reduced to one candidate before touching SQLite.
    unique_alerts = {}
    ignored = 0
    qualifying_rows = 0

    for _, row in merged.iterrows():

        alert = build_alert(row)

        if alert is None:
            ignored += 1
            continue

        qualifying_rows += 1
        key = alert["alert_key"]

        if key not in unique_alerts:
            unique_alerts[key] = alert
        else:
            # Keep the strongest observation for this event.
            existing = unique_alerts[key]
            if alert["risk_score"] > existing["risk_score"]:
                unique_alerts[key] = alert

    alerts = list(unique_alerts.values())

    batch_duplicates = (
        qualifying_rows - len(alerts)
    )

    inserted = 0
    duplicates = 0

    # --------------------------------------------------------
    # SAVE UNIQUE ALERTS ONLY
    # --------------------------------------------------------
    for alert in alerts:

        try:
            result = save_alert(alert)

            if result["inserted"]:
                inserted += 1

                print(
                    "[ALERT] New alert inserted | "
                    f"{alert['source_ip']} -> "
                    f"{alert['destination_ip']} | "
                    f"{alert['protocol']} | "
                    f"{alert['severity']} | "
                    f"Risk={alert['risk_score']:.1f} | "
                    f"{alert['attack_category']}"
                )
            else:
                duplicates += 1

        except Exception as error:
            print(
                "[ERROR] Failed to process alert:",
                error
            )

    # --------------------------------------------------------
    # Current unique alert snapshot
    # --------------------------------------------------------
    try:
        if alerts:
            pd.DataFrame(alerts).to_csv(
                ALERTS_PATH,
                index=False
            )
    except Exception as error:
        print(
            "[WARNING] Could not update live_alerts.csv:",
            error
        )

    return (
        inserted,
        batch_duplicates + duplicates,
        len(alerts)
    )


# ============================================================
# STARTUP
# ============================================================

print()
print(
    "=============================================="
)

print(
    " NETOPS AI SOC - RISK & DETECTION ENGINE"
)

print(
    "=============================================="
)

print(
    "Prediction source:",
    PREDICTIONS_PATH
)

print(
    "Flow source:",
    FLOWS_PATH
)

print(
    "Database:",
    BASE_DIR / "data" / "netops_alerts.db"
)

print(
    "Check interval:",
    f"{CHECK_INTERVAL}s"
)

print(
    "=============================================="
)


# ============================================================
# CONTINUOUS LIVE LOOP
# ============================================================

last_prediction_mtime = None
last_flow_mtime = None


while True:

    try:

        prediction_mtime = (
            PREDICTIONS_PATH.stat().st_mtime
            if PREDICTIONS_PATH.exists()
            else None
        )

        flow_mtime = (
            FLOWS_PATH.stat().st_mtime
            if FLOWS_PATH.exists()
            else None
        )

        # ----------------------------------------------------
        # Only process when either source has changed.
        # This prevents unnecessary duplicate processing.
        # ----------------------------------------------------

        changed = (
            prediction_mtime
            != last_prediction_mtime
            or
            flow_mtime
            != last_flow_mtime
        )

        if changed:

            inserted, duplicates, unique_candidates = (
                process_batch()
            )

            print(
                "[ENGINE] Batch processed | "
                f"Unique candidates: {unique_candidates} | "
                f"New alerts: {inserted} | "
                f"Duplicates skipped: {duplicates} | "
                f"Time: "
                f"{datetime.now().strftime('%H:%M:%S')}"
            )

            last_prediction_mtime = (
                prediction_mtime
            )

            last_flow_mtime = (
                flow_mtime
            )

        time.sleep(
            CHECK_INTERVAL
        )

    except KeyboardInterrupt:

        print()
        print(
            "Detection engine stopped."
        )

        break

    except Exception as error:

        print(
            "[ENGINE ERROR]",
            error
        )

        time.sleep(
            CHECK_INTERVAL
        )
