from pathlib import Path
from datetime import datetime
import sqlite3

import pandas as pd
import streamlit as st

try:
    from streamlit_autorefresh import st_autorefresh
    AUTO_REFRESH = True
except ImportError:
    AUTO_REFRESH = False


st.set_page_config(
    page_title="NetOps AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "netops_alerts.db"
FLOW_PATH = BASE_DIR / "data" / "live_network_flows.csv"
PREDICTION_PATH = BASE_DIR / "data" / "live_predictions.csv"

REFRESH_SECONDS = 5
STALE_SECONDS = 20


st.markdown(
    """
    <style>
    .block-container {
        padding-top: 1.4rem;
        padding-bottom: 2rem;
        max-width: 1550px;
    }

    .netops-title {
        font-size: 2.2rem;
        font-weight: 800;
        letter-spacing: -0.6px;
    }

    .netops-subtitle {
        opacity: .65;
        font-size: 1rem;
        margin-bottom: 10px;
    }

    .live-badge {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 12px;
        border-radius: 999px;
        border: 1px solid rgba(0,190,110,.35);
        background: rgba(0,190,110,.08);
        color: #00a86b;
        font-size: .76rem;
        font-weight: 750;
        letter-spacing: .6px;
    }

    .live-dot {
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: #00c878;
        box-shadow: 0 0 0 4px rgba(0,200,120,.12);
        animation: pulse 1.5s infinite;
    }

    @keyframes pulse {
        0% { transform: scale(.85); opacity: .65; }
        50% { transform: scale(1.15); opacity: 1; }
        100% { transform: scale(.85); opacity: .65; }
    }

    .section-title {
        font-size: 1.15rem;
        font-weight: 760;
        margin-top: 1.3rem;
        margin-bottom: .75rem;
    }

    .status-card {
        border: 1px solid rgba(128,128,128,.20);
        border-radius: 12px;
        padding: 14px 16px;
        min-height: 110px;
        background: rgba(128,128,128,.035);
    }

    .status-name {
        font-size: .82rem;
        opacity: .68;
    }

    .status-value {
        font-size: 1.05rem;
        font-weight: 750;
        margin-top: 7px;
    }

    .status-detail {
        font-size: .74rem;
        opacity: .55;
        margin-top: 5px;
    }

    .online { color: #00a86b; }
    .stale { color: #d88900; }
    .offline { color: #d64545; }

    .footer {
        text-align: center;
        opacity: .45;
        font-size: .72rem;
        margin-top: 2rem;
        padding-top: 1rem;
        border-top: 1px solid rgba(128,128,128,.15);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


if AUTO_REFRESH:
    st_autorefresh(
        interval=REFRESH_SECONDS * 1000,
        key="netops_live_refresh",
    )


def get_mtime(path):
    try:
        if path.exists():
            return datetime.fromtimestamp(path.stat().st_mtime)
    except Exception:
        pass
    return None


def age_seconds(ts):
    if ts is None:
        return None
    return max(0, (datetime.now() - ts).total_seconds())


def component_status(path):
    ts = get_mtime(path)

    if ts is None:
        return "OFFLINE", None

    if age_seconds(ts) <= STALE_SECONDS:
        return "ONLINE", ts

    return "STALE", ts


def age_text(ts):
    age = age_seconds(ts)

    if age is None:
        return "No data"

    if age < 60:
        return f"{int(age)}s ago"

    if age < 3600:
        return f"{int(age // 60)}m ago"

    return f"{int(age // 3600)}h ago"


def load_csv(path):
    try:
        if not path.exists():
            return pd.DataFrame()
        return pd.read_csv(path)
    except Exception:
        return pd.DataFrame()


@st.cache_data(ttl=2)
def load_alert_database(path_string):
    path = Path(path_string)

    if not path.exists():
        return pd.DataFrame(), "Database not found"

    connection = None

    try:
        connection = sqlite3.connect(path, timeout=5)

        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(alerts)"
            ).fetchall()
        }

        wanted = [
            "id",
            "timestamp",
            "severity",
            "risk_score",
            "confidence",
            "source_ip",
            "destination_ip",
            "protocol",
            "source_port",
            "destination_port",
            "packet_rate",
            "byte_rate",
            "connection_count",
            "attack_category",
            "evidence",
            "protocol_context",
            "alert_key",
        ]

        available = [c for c in wanted if c in columns]

        if not available:
            return pd.DataFrame(), "No readable alert columns found"

        query = f"""
            SELECT {", ".join(available)}
            FROM alerts
            ORDER BY id DESC
        """

        df = pd.read_sql_query(query, connection)

        return df, None

    except Exception as exc:
        return pd.DataFrame(), str(exc)

    finally:
        if connection is not None:
            connection.close()


def numeric(df, column):
    if column not in df.columns:
        return pd.Series(dtype=float)

    return pd.to_numeric(
        df[column],
        errors="coerce"
    ).fillna(0)


def safe_value(row, column, default="UNKNOWN"):
    value = row.get(column, default)

    if pd.isna(value):
        return default

    return value


flow_status, flow_time = component_status(FLOW_PATH)
ml_status, ml_time = component_status(PREDICTION_PATH)

flows = load_csv(FLOW_PATH)
predictions = load_csv(PREDICTION_PATH)
alerts, db_error = load_alert_database(str(DB_PATH))


st.markdown(
    """
    <div class="netops-title">🛡️ NetOps AI SOC</div>
    <div class="netops-subtitle">
        AI-Powered Network Operations & Anomaly Detection
    </div>
    <div class="live-badge">
        <span class="live-dot"></span>
        LIVE MONITORING
    </div>
    """,
    unsafe_allow_html=True,
)

st.caption(
    f"Dashboard refreshed: {datetime.now():%H:%M:%S} "
    f"• Automatic refresh every {REFRESH_SECONDS} seconds"
)


st.markdown(
    '<div class="section-title">🟢 System Status</div>',
    unsafe_allow_html=True,
)

status_cols = st.columns(3)


def status_card(container, name, status, detail):
    css = {
        "ONLINE": "online",
        "STALE": "stale",
        "OFFLINE": "offline",
    }.get(status, "offline")

    container.markdown(
        f"""
        <div class="status-card">
            <div class="status-name">{name}</div>
            <div class="status-value {css}">● {status}</div>
            <div class="status-detail">{detail}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


status_card(
    status_cols[0],
    "📡 Flow Collector",
    flow_status,
    (
        f"Last data update: {flow_time:%H:%M:%S} "
        f"({age_text(flow_time)})"
        if flow_time
        else "No live flow data"
    ),
)

status_card(
    status_cols[1],
    "🤖 ML Prediction Engine",
    ml_status,
    (
        f"Last prediction update: {ml_time:%H:%M:%S} "
        f"({age_text(ml_time)})"
        if ml_time
        else "No prediction data"
    ),
)

if db_error:
    database_status = "OFFLINE"
    database_detail = db_error
else:
    database_status = "ONLINE"
    database_detail = f"{len(alerts):,} unique alerts stored"

status_card(
    status_cols[2],
    "🗄️ Alert Database",
    database_status,
    database_detail,
)


st.markdown(
    '<div class="section-title">📡 Operations Overview</div>',
    unsafe_allow_html=True,
)

flow_count = len(flows)
prediction_count = len(predictions)
alert_count = len(alerts)

severity = (
    alerts["severity"].astype(str).str.upper()
    if "severity" in alerts.columns
    else pd.Series(dtype=str)
)

high = int((severity == "HIGH").sum())
medium = int((severity == "MEDIUM").sum())
low = int((severity == "LOW").sum())

cols = st.columns(6)

cols[0].metric("Network Flows", f"{flow_count:,}")
cols[1].metric("ML Predictions", f"{prediction_count:,}")
cols[2].metric("Security Alerts", f"{alert_count:,}")
cols[3].metric("🔴 High", f"{high:,}")
cols[4].metric("🟠 Medium", f"{medium:,}")
cols[5].metric("🟢 Low", f"{low:,}")


st.markdown(
    '<div class="section-title">🚨 Security Summary</div>',
    unsafe_allow_html=True,
)

risk = numeric(alerts, "risk_score")
confidence = numeric(alerts, "confidence")

total_risk = float(risk.sum()) if len(risk) else 0
average_risk = float(risk.mean()) if len(risk) else 0
average_confidence = float(confidence.mean()) if len(confidence) else 0

summary = st.columns(4)

summary[0].metric("Total Risk Score", f"{total_risk:,.1f}")
summary[1].metric("Average Risk", f"{average_risk:,.1f}")
summary[2].metric("Average ML Confidence", f"{average_confidence:.2f}")
summary[3].metric("Active Alerts", f"{alert_count:,}")


st.markdown(
    '<div class="section-title">📊 Security Analytics</div>',
    unsafe_allow_html=True,
)

tab1, tab2, tab3, tab4 = st.tabs(
    [
        "Severity",
        "Protocols",
        "Top Sources",
        "ML Analysis",
    ]
)


with tab1:
    if not alerts.empty and "severity" in alerts.columns:
        severity_counts = (
            alerts["severity"]
            .astype(str)
            .str.upper()
            .value_counts()
            .reindex(
                ["HIGH", "MEDIUM", "LOW"],
                fill_value=0,
            )
        )

        st.bar_chart(severity_counts)

    else:
        st.info("No severity data available.")


with tab2:
    if not alerts.empty and "protocol" in alerts.columns:
        protocol_counts = (
            alerts["protocol"]
            .fillna("UNKNOWN")
            .astype(str)
            .value_counts()
            .head(10)
        )

        st.bar_chart(protocol_counts)

    elif not flows.empty and "protocol" in flows.columns:
        protocol_counts = (
            flows["protocol"]
            .fillna("UNKNOWN")
            .astype(str)
            .value_counts()
            .head(10)
        )

        st.bar_chart(protocol_counts)

    else:
        st.info("No protocol data available.")


with tab3:
    if not alerts.empty and "source_ip" in alerts.columns:
        source_counts = (
            alerts["source_ip"]
            .fillna("UNKNOWN")
            .astype(str)
            .value_counts()
            .head(10)
        )

        st.bar_chart(source_counts)

    else:
        st.info("No source IP data available.")


with tab4:
    normal = 0
    attacks = 0

    if "prediction" in predictions.columns:
        p = pd.to_numeric(
            predictions["prediction"],
            errors="coerce",
        ).fillna(0)

        attacks = int((p == 1).sum())
        normal = int((p == 0).sum())

    elif "status" in predictions.columns:
        s = (
            predictions["status"]
            .fillna("")
            .astype(str)
            .str.upper()
        )

        attacks = int((s == "ATTACK").sum())
        normal = int((s == "NORMAL").sum())

    ml_df = pd.DataFrame(
        {
            "Traffic": ["Normal", "Potential Attack"],
            "Flows": [normal, attacks],
        }
    ).set_index("Traffic")

    st.bar_chart(ml_df)

    total_ml = normal + attacks

    if total_ml:
        st.metric(
            "Attack Ratio",
            f"{attacks / total_ml * 100:.1f}%",
        )
    else:
        st.info("No ML prediction data available.")


st.markdown(
    '<div class="section-title">🎯 Attack Category Distribution</div>',
    unsafe_allow_html=True,
)

if not alerts.empty and "attack_category" in alerts.columns:

    category_counts = (
        alerts["attack_category"]
        .fillna("UNKNOWN")
        .astype(str)
        .replace("", "UNKNOWN")
        .value_counts()
    )

    if not category_counts.empty:


        category_table = category_counts.rename(
            "Alerts"
        ).reset_index()

        category_table.columns = [
            "Attack Category",
            "Alerts",
        ]

        category_cols = st.columns(2)

        with category_cols[0]:
            st.dataframe(
                category_table,
                use_container_width=True,
                hide_index=True,
            )

        with category_cols[1]:
            st.bar_chart(
                category_counts,
                use_container_width=True,
            )

    else:
        st.info("No attack-category data available.")

else:
    st.info("Attack category information is not available.")


st.markdown(
    '<div class="section-title">🚨 Recent Security Alerts</div>',
    unsafe_allow_html=True,
)

if alerts.empty:
    st.info("No alerts available.")
else:
    recent = alerts.head(25).copy()

    display_cols = [
        "id",
        "timestamp",
        "severity",
        "risk_score",
        "confidence",
        "source_ip",
        "destination_ip",
        "protocol",
        "attack_category",
        "evidence",
    ]

    display_cols = [
        c for c in display_cols
        if c in recent.columns
    ]

    st.dataframe(
        recent[display_cols],
        use_container_width=True,
        hide_index=True,
    )


st.markdown(
    '<div class="section-title">🔎 Incident Investigation</div>',
    unsafe_allow_html=True,
)

if alerts.empty or "id" not in alerts.columns:
    st.info("No incidents available for investigation.")
else:

    ids = (
        pd.to_numeric(
            alerts["id"],
            errors="coerce",
        )
        .dropna()
        .astype(int)
        .tolist()
    )

    if ids:

        selected_id = st.selectbox(
            "Select alert ID",
            ids[:200],
        )

        selected = alerts[
            pd.to_numeric(
                alerts["id"],
                errors="coerce",
            ) == selected_id
        ]

        if not selected.empty:

            row = selected.iloc[0]

            incident_cols = st.columns(4)

            incident_cols[0].metric(
                "Severity",
                str(safe_value(row, "severity")),
            )

            try:
                selected_risk = float(
                    safe_value(row, "risk_score", 0)
                )
            except (TypeError, ValueError):
                selected_risk = 0.0

            try:
                selected_confidence = float(
                    safe_value(row, "confidence", 0)
                )
            except (TypeError, ValueError):
                selected_confidence = 0.0

            incident_cols[1].metric(
                "Risk",
                f"{selected_risk:.2f}",
            )

            incident_cols[2].metric(
                "Confidence",
                f"{selected_confidence:.3f}",
            )

            incident_cols[3].metric(
                "Protocol",
                str(safe_value(row, "protocol")),
            )

            left, right = st.columns(2)

            with left:
                st.write("**Source**")
                st.code(
                    str(
                        safe_value(
                            row,
                            "source_ip",
                        )
                    )
                )

                st.write("**Destination**")
                st.code(
                    str(
                        safe_value(
                            row,
                            "destination_ip",
                        )
                    )
                )

                st.write("**Attack Category**")
                st.write(
                    str(
                        safe_value(
                            row,
                            "attack_category",
                            "ML_ANOMALY",
                        )
                    )
                )

            with right:
                st.write("**Evidence**")
                st.info(
                    str(
                        safe_value(
                            row,
                            "evidence",
                            "No evidence recorded.",
                        )
                    )
                )

                st.write("**Protocol Context**")
                st.write(
                    str(
                        safe_value(
                            row,
                            "protocol_context",
                            "No protocol context recorded.",
                        )
                    )
                )

    else:
        st.info("No valid alert IDs available.")


st.markdown(
    '<div class="section-title">🌐 Current Network Flow Data</div>',
    unsafe_allow_html=True,
)

if flows.empty:
    st.info("No current network flow data available.")
else:
    st.dataframe(
        flows.tail(25).iloc[::-1],
        use_container_width=True,
        hide_index=True,
    )


st.markdown(
    '<div class="section-title">🤖 Latest ML Predictions</div>',
    unsafe_allow_html=True,
)

if predictions.empty:
    st.info("No current ML prediction data available.")
else:
    prediction_view = predictions.tail(25).iloc[::-1]

    st.dataframe(
        prediction_view,
        use_container_width=True,
        hide_index=True,
    )


with st.expander("System Diagnostics"):

    unique_keys = "N/A"

    if "alert_key" in alerts.columns:
        unique_keys = alerts["alert_key"].nunique()

    st.write(
        {
            "Dashboard": "ONLINE",
            "Flow Collector": flow_status,
            "ML Prediction Engine": ml_status,
            "Alert Database": database_status,
            "Database Path": str(DB_PATH),
            "Flow File": str(FLOW_PATH),
            "Prediction File": str(PREDICTION_PATH),
            "Flow File Age": age_text(flow_time),
            "Prediction File Age": age_text(ml_time),
            "Stored Alerts": alert_count,
            "Unique Alert Keys": unique_keys,
        }
    )


st.markdown(
    f"""
    <div class="footer">
        <strong>NetOps AI SOC</strong><br>
        Designed &amp; Developed by <strong>Pritish Ganguly</strong><br>
        AI • Network Security • Machine Learning
        <br><br>
        Live refresh: {REFRESH_SECONDS}s
        • Detection and ML results are displayed from the local pipeline
    </div>
    """,
    unsafe_allow_html=True,
)
