from pathlib import Path
from datetime import datetime
import sqlite3

import pandas as pd
import streamlit as st
from database import initialize_ticketing, create_ticket, update_ticket

try:
    from streamlit_autorefresh import st_autorefresh
    AUTO_REFRESH = True
except ImportError:
    AUTO_REFRESH = False


# ============================================================
# NETOPS AI SOC - PRODUCTION DASHBOARD
# ============================================================

st.set_page_config(
    page_title="NetOps AI SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)






TICKET_NOTIFICATION_CSS = '<style>\n.netops-ticket-toast{position:fixed;top:78px;right:24px;z-index:999999;width:360px;padding:16px 18px;border:1px solid rgba(67,217,255,.35);border-radius:14px;background:linear-gradient(145deg,rgba(13,20,31,.98),rgba(7,12,19,.98));box-shadow:0 18px 55px rgba(0,0,0,.45);color:#edf4ff;animation:netops-ticket-in .35s ease-out;backdrop-filter:blur(12px)}\n.netops-ticket-toast .toast-head{display:flex;align-items:center;gap:9px;font-weight:800;font-size:.88rem;margin-bottom:8px}\n.netops-ticket-toast .toast-icon{width:28px;height:28px;display:flex;align-items:center;justify-content:center;border-radius:8px;background:rgba(67,217,255,.12);font-size:16px}\n.netops-ticket-toast .toast-ticket{color:#43d9ff;font-family:monospace;font-size:.78rem;font-weight:700}\n.netops-ticket-toast .toast-title{font-size:.84rem;font-weight:650;margin-bottom:7px}\n.netops-ticket-toast .toast-meta{color:#9aa9bd;font-size:.73rem;line-height:1.5}\n.netops-ticket-toast .toast-priority{display:inline-block;margin-top:9px;padding:4px 8px;border-radius:6px;background:rgba(62,229,139,.10);color:#3ee58b;font-size:.68rem;font-weight:800}\n@keyframes netops-ticket-in{from{opacity:0;transform:translateX(35px) translateY(-8px)}to{opacity:1;transform:translateX(0) translateY(0)}}\n</style>'
st.markdown(TICKET_NOTIFICATION_CSS, unsafe_allow_html=True)
INCIDENT_DETAIL_CSS = '\n<style>\n.netops-incident-card{\n    padding:20px;\n    border:1px solid rgba(120,150,190,.20);\n    border-radius:16px;\n    background:linear-gradient(145deg,rgba(15,23,35,.96),rgba(8,14,23,.96));\n    margin:8px 0 18px 0;\n}\n.netops-incident-title{\n    font-size:1.35rem;\n    font-weight:800;\n    margin-bottom:4px;\n}\n.netops-incident-subtitle{\n    color:#91a0b5;\n    font-size:.78rem;\n    margin-bottom:16px;\n}\n.netops-detail-label{\n    color:#8291a6;\n    font-size:.68rem;\n    text-transform:uppercase;\n    letter-spacing:.08em;\n    font-weight:700;\n}\n.netops-detail-value{\n    font-size:.92rem;\n    font-weight:650;\n    margin-top:3px;\n    word-break:break-word;\n}\n.netops-evidence{\n    padding:14px;\n    border-radius:10px;\n    background:rgba(0,0,0,.20);\n    border:1px solid rgba(120,150,190,.12);\n    font-family:monospace;\n    font-size:.78rem;\n    white-space:pre-wrap;\n}\n</style>\n'
st.markdown(INCIDENT_DETAIL_CSS, unsafe_allow_html=True)

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "netops_alerts.db"
FLOW_PATH = BASE_DIR / "data" / "live_network_flows.csv"
PREDICTION_PATH = BASE_DIR / "data" / "live_predictions.csv"

REFRESH_SECONDS = 5
STALE_SECONDS = 20

initialize_ticketing()

# Ticket notification state.
if "netops_known_ticket_ids" not in st.session_state:
    st.session_state.netops_known_ticket_ids = None

if "netops_last_ticket_notification" not in st.session_state:
    st.session_state.netops_last_ticket_notification = None



# ============================================================
# CSS
# ============================================================

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


# ============================================================
# AUTO REFRESH
# ============================================================

if AUTO_REFRESH:
    st_autorefresh(
        interval=REFRESH_SECONDS * 1000,
        key="netops_live_refresh",
    )


# ============================================================
# HELPERS
# ============================================================

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



@st.cache_data(ttl=2)
def load_ticket_database(path_string):

    path = Path(path_string)

    if not path.exists():
        return pd.DataFrame(), "Database not found"

    connection = None

    try:
        connection = sqlite3.connect(path, timeout=5)

        df = pd.read_sql_query(
            """
            SELECT
                id,
                ticket_number,
                alert_id,
                title,
                description,
                severity,
                priority,
                category,
                status,
                assigned_to,
                resolution_notes,
                created_at,
                updated_at,
                resolved_at
            FROM tickets
            ORDER BY id DESC
            """,
            connection,
        )

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


# ============================================================
# LOAD LIVE DATA
# ============================================================

flow_status, flow_time = component_status(FLOW_PATH)
ml_status, ml_time = component_status(PREDICTION_PATH)

flows = load_csv(FLOW_PATH)
predictions = load_csv(PREDICTION_PATH)
alerts, db_error = load_alert_database(str(DB_PATH))
tickets, ticket_db_error = load_ticket_database(str(DB_PATH))


# ============================================================
# NEW TICKET NOTIFICATION
# ============================================================

def show_new_ticket_notification(ticket_df):

    if ticket_df is None or ticket_df.empty:
        return

    if "id" not in ticket_df.columns:
        return

    current_ids = set(
        pd.to_numeric(
            ticket_df["id"],
            errors="coerce",
        )
        .dropna()
        .astype(int)
        .tolist()
    )

    previous_ids = st.session_state.netops_known_ticket_ids

    # First dashboard load establishes the baseline.
    # Existing tickets do NOT trigger notifications.
    if previous_ids is None:
        st.session_state.netops_known_ticket_ids = current_ids
        return

    new_ids = current_ids - previous_ids

    if new_ids:

        newest_id = max(new_ids)

        rows = ticket_df[
            pd.to_numeric(
                ticket_df["id"],
                errors="coerce",
            ) == newest_id
        ]

        if not rows.empty:

            ticket = rows.iloc[0]

            ticket_number = str(
                safe_value(
                    ticket,
                    "ticket_number",
                    f"NET-{newest_id}",
                )
            )

            title = str(
                safe_value(
                    ticket,
                    "title",
                    "New security incident",
                )
            )

            severity = str(
                safe_value(
                    ticket,
                    "severity",
                    "LOW",
                )
            ).upper()

            priority = str(
                safe_value(
                    ticket,
                    "priority",
                    "P3",
                )
            ).upper()

            category = str(
                safe_value(
                    ticket,
                    "category",
                    "SECURITY",
                )
            )

            alert_id = str(
                safe_value(
                    ticket,
                    "alert_id",
                    "N/A",
                )
            )

            toast = f"""
            <div class="netops-ticket-toast">
                <div class="toast-head">
                    <div class="toast-icon">🎫</div>
                    <div>New Security Ticket</div>
                </div>

                <div class="toast-ticket">{ticket_number}</div>

                <div class="toast-title">{title}</div>

                <div class="toast-meta">
                    <strong>Severity:</strong> {severity}
                    &nbsp; • &nbsp;
                    <strong>Category:</strong> {category}<br>
                    <strong>Alert:</strong> #{alert_id}
                </div>

                <div class="toast-priority">
                    {priority} • NEW INCIDENT
                </div>
            </div>
            """

            st.markdown(
                toast,
                unsafe_allow_html=True,
            )

            # Also use Streamlit's native notification/toast.
            try:
                st.toast(
                    f"🎫 {ticket_number} — New {severity} ticket",
                    icon="🚨" if severity == "HIGH" else "🎫",
                )
            except Exception:
                pass

            st.session_state.netops_last_ticket_notification = newest_id

    st.session_state.netops_known_ticket_ids = current_ids



# ============================================================
# HEADER
# ============================================================

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


# ============================================================
# SYSTEM STATUS
# ============================================================

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


# ============================================================
# OPERATIONS OVERVIEW
# ============================================================

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


# ============================================================
# SECURITY SUMMARY
# ============================================================

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


# ============================================================
# ANALYTICS
# ============================================================

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


# ============================================================
# ATTACK CATEGORY ANALYSIS
# ============================================================

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

        # Compatible with older pandas versions.
        # Do NOT use reset_index(names=...).
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


# ============================================================
# RECENT ALERTS
# ============================================================

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


# ============================================================
# INCIDENT INVESTIGATION
# ============================================================

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





@st.cache_data(ttl=2)
def load_incident_alert(alert_id, db_path):
    connection = None

    try:
        connection = sqlite3.connect(db_path, timeout=5)
        tables = pd.read_sql_query(
            "SELECT name FROM sqlite_master WHERE type='table'",
            connection,
        )["name"].tolist()

        if "alerts" not in tables:
            return None

        row = pd.read_sql_query(
            "SELECT * FROM alerts WHERE id = ? LIMIT 1",
            connection,
            params=(int(alert_id),),
        )

        if row.empty:
            return None

        return row.iloc[0]

    except Exception:
        return None

    finally:
        if connection is not None:
            connection.close()



# ============================================================
# INCIDENT DETAIL VIEW
# ============================================================

st.markdown(
    '<div class="section-title">🔎 Incident Investigation</div>',
    unsafe_allow_html=True,
)

if tickets.empty:
    st.info("Create or receive a ticket to investigate an incident.")
else:

    incident_numbers = (
        tickets["ticket_number"]
        .dropna()
        .astype(str)
        .tolist()
    )

    selected_incident_number = st.selectbox(
        "Select Incident",
        incident_numbers,
        key="incident_detail_select",
    )

    incident = tickets[
        tickets["ticket_number"].astype(str)
        == selected_incident_number
    ].iloc[0]

    alert_id_value = safe_value(incident, "alert_id", None)

    alert = None

    try:
        if alert_id_value is not None and str(alert_id_value) not in {
            "", "None", "nan", "NaN"
        }:
            alert = load_incident_alert(
                int(float(alert_id_value)),
                str(DB_PATH),
            )
    except (ValueError, TypeError):
        alert = None

    st.markdown(
        f"""
        <div class="netops-incident-card">
            <div class="netops-incident-title">
                🎫 {selected_incident_number}
            </div>
            <div class="netops-incident-subtitle">
                {safe_value(incident, "title", "Security Incident")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    top = st.columns(4)

    top[0].metric(
        "Status",
        str(safe_value(incident, "status", "OPEN")).upper(),
    )
    top[1].metric(
        "Severity",
        str(safe_value(incident, "severity", "LOW")).upper(),
    )
    top[2].metric(
        "Priority",
        str(safe_value(incident, "priority", "P3")).upper(),
    )
    top[3].metric(
        "Assigned To",
        str(safe_value(incident, "assigned_to", "SOC Team")),
    )

    st.markdown("### 🌐 Network Context")

    network_cols = st.columns(4)

    source_ip = "N/A"
    destination_ip = "N/A"
    protocol = "N/A"
    alert_category = str(
        safe_value(incident, "category", "SECURITY")
    )

    if alert is not None:

        source_ip = str(
            safe_value(
                alert,
                "source_ip",
                safe_value(alert, "src_ip", "N/A"),
            )
        )

        destination_ip = str(
            safe_value(
                alert,
                "destination_ip",
                safe_value(alert, "dst_ip", "N/A"),
            )
        )

        protocol = str(
            safe_value(alert, "protocol", "N/A")
        )

        alert_category = str(
            safe_value(
                alert,
                "attack_category",
                safe_value(
                    alert,
                    "category",
                    alert_category,
                ),
            )
        )

    network_cols[0].metric("Source IP", source_ip)
    network_cols[1].metric("Destination IP", destination_ip)
    network_cols[2].metric("Protocol", protocol)
    network_cols[3].metric("Category", alert_category)

    st.markdown("### 🤖 ML & Risk Analysis")

    ml_cols = st.columns(4)

    risk_value = safe_value(
        alert,
        "risk_score",
        safe_value(incident, "risk_score", 0)
        if alert is None else 0,
    )

    confidence_value = safe_value(
        alert,
        "confidence",
        safe_value(
            alert,
            "ml_confidence",
            0,
        ),
    )

    prediction_value = safe_value(
        alert,
        "prediction",
        safe_value(
            alert,
            "ml_prediction",
            "N/A",
        ),
    )

    evidence_value = safe_value(
        alert,
        "evidence",
        "No evidence recorded.",
    )

    ml_cols[0].metric(
        "Risk Score",
        str(risk_value),
    )
    ml_cols[1].metric(
        "ML Confidence",
        str(confidence_value),
    )
    ml_cols[2].metric(
        "Prediction",
        str(prediction_value),
    )
    ml_cols[3].metric(
        "Alert ID",
        str(alert_id_value or "N/A"),
    )

    st.markdown("### 🔍 Detection Evidence")

    st.markdown(
        f'<div class="netops-evidence">{evidence_value}</div>',
        unsafe_allow_html=True,
    )

    st.markdown("### 📝 Incident Description")

    st.text_area(
        "Incident description",
        value=str(
            safe_value(
                incident,
                "description",
                "No description recorded.",
            )
        ),
        height=150,
        disabled=True,
        key="incident_description_view",
    )

    st.markdown("### 👨‍💻 Investigation")

    investigation_notes = st.text_area(
        "Investigation / Resolution Notes",
        value=str(
            safe_value(
                incident,
                "resolution_notes",
                "",
            )
        ),
        height=150,
        key="incident_investigation_notes",
    )

    action_cols = st.columns(4)

    with action_cols[0]:
        detail_status = st.selectbox(
            "Status",
            ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
            index=(
                ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"].index(
                    str(
                        safe_value(
                            incident,
                            "status",
                            "OPEN",
                        )
                    ).upper()
                )
                if str(
                    safe_value(
                        incident,
                        "status",
                        "OPEN",
                    )
                ).upper()
                in ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]
                else 0
            ),
            key="incident_detail_status",
        )

    with action_cols[1]:
        detail_priority = st.selectbox(
            "Priority",
            ["P1", "P2", "P3", "P4"],
            index=(
                ["P1", "P2", "P3", "P4"].index(
                    str(
                        safe_value(
                            incident,
                            "priority",
                            "P3",
                        )
                    ).upper()
                )
                if str(
                    safe_value(
                        incident,
                        "priority",
                        "P3",
                    )
                ).upper()
                in ["P1", "P2", "P3", "P4"]
                else 2
            ),
            key="incident_detail_priority",
        )

    with action_cols[2]:
        detail_assignee = st.text_input(
            "Assigned To",
            value=str(
                safe_value(
                    incident,
                    "assigned_to",
                    "SOC Team",
                )
            ),
            key="incident_detail_assignee",
        )

    with action_cols[3]:
        st.write("")
        st.write("")
        save_incident = st.button(
            "💾 Save Investigation",
            use_container_width=True,
            type="primary",
            key="save_incident_detail",
        )

    if save_incident:

        updated = update_ticket(
            ticket_id=int(incident["id"]),
            status=detail_status,
            assigned_to=detail_assignee.strip() or "SOC Team",
            priority=detail_priority,
            resolution_notes=investigation_notes.strip(),
        )

        if updated:
            st.success(
                f"{selected_incident_number} updated successfully."
            )
            st.cache_data.clear()
            st.rerun()
        else:
            st.error("Could not update the incident.")


# ============================================================
# INCIDENT TICKETING SYSTEM
# ============================================================

show_new_ticket_notification(tickets)

st.markdown(
    '<div class="section-title">🎫 Incident Ticketing</div>',
    unsafe_allow_html=True,
)

ticket_tabs = st.tabs(
    ["📋 Tickets", "➕ Create Ticket", "🔧 Manage Ticket"]
)

with ticket_tabs[0]:

    if tickets.empty:
        st.info("No incident tickets have been created yet.")
    else:

        status_series = (
            tickets["status"]
            .fillna("OPEN")
            .astype(str)
            .str.upper()
        )

        metric_cols = st.columns(4)

        metric_cols[0].metric("Total Tickets", f"{len(tickets):,}")
        metric_cols[1].metric("Open", int((status_series == "OPEN").sum()))
        metric_cols[2].metric(
            "Investigating",
            int((status_series == "INVESTIGATING").sum()),
        )
        metric_cols[3].metric(
            "Resolved / Closed",
            int(status_series.isin(["RESOLVED", "CLOSED"]).sum()),
        )

        display_columns = [
            "ticket_number",
            "alert_id",
            "title",
            "severity",
            "priority",
            "category",
            "status",
            "assigned_to",
            "created_at",
        ]

        display_columns = [
            c for c in display_columns if c in tickets.columns
        ]

        st.dataframe(
            tickets[display_columns],
            use_container_width=True,
            hide_index=True,
        )

with ticket_tabs[1]:

    if alerts.empty or "id" not in alerts.columns:
        st.info("No alerts are available for ticket creation.")
    else:

        working_alerts = alerts.copy()

        working_alerts["id_numeric"] = pd.to_numeric(
            working_alerts["id"],
            errors="coerce",
        )

        working_alerts = working_alerts.dropna(
            subset=["id_numeric"]
        )

        if working_alerts.empty:
            st.info("No valid alerts are available.")
        else:

            alert_ids = (
                working_alerts["id_numeric"]
                .astype(int)
                .tolist()
            )

            def alert_label(alert_id):
                row = working_alerts[
                    working_alerts["id_numeric"] == alert_id
                ].iloc[0]

                category = str(
                    safe_value(
                        row,
                        "attack_category",
                        "SECURITY_EVENT",
                    )
                )

                source = str(
                    safe_value(row, "source_ip", "UNKNOWN")
                )

                destination = str(
                    safe_value(row, "destination_ip", "UNKNOWN")
                )

                return (
                    f"Alert #{alert_id} | {category} | "
                    f"{source} → {destination}"
                )

            selected_alert_id = st.selectbox(
                "Source Alert",
                alert_ids[:200],
                format_func=alert_label,
                key="ticket_alert_select",
            )

            selected_alert = working_alerts[
                working_alerts["id_numeric"] == selected_alert_id
            ].iloc[0]

            default_severity = str(
                safe_value(selected_alert, "severity", "LOW")
            ).upper()

            if default_severity not in ["HIGH", "MEDIUM", "LOW"]:
                default_severity = "LOW"

            default_category = str(
                safe_value(
                    selected_alert,
                    "attack_category",
                    "SECURITY_EVENT",
                )
            )

            source_ip = str(
                safe_value(selected_alert, "source_ip", "UNKNOWN")
            )

            destination_ip = str(
                safe_value(
                    selected_alert,
                    "destination_ip",
                    "UNKNOWN",
                )
            )

            with st.form("create_ticket_form"):

                title = st.text_input(
                    "Ticket Title",
                    value=(
                        f"{default_category} — "
                        f"{source_ip} → {destination_ip}"
                    ),
                )

                description = st.text_area(
                    "Incident Description",
                    value=(
                        "Security event detected by NetOps AI.\n\n"
                        f"Source: {source_ip}\n"
                        f"Destination: {destination_ip}\n"
                        f"Category: {default_category}\n"
                        f"Risk: {safe_value(selected_alert, 'risk_score', 0)}\n"
                        f"Confidence: {safe_value(selected_alert, 'confidence', 0)}\n"
                        f"Evidence: {safe_value(selected_alert, 'evidence', 'No evidence recorded.')}"
                    ),
                    height=180,
                )

                form_cols = st.columns(3)

                with form_cols[0]:
                    severity = st.selectbox(
                        "Severity",
                        ["HIGH", "MEDIUM", "LOW"],
                        index=["HIGH", "MEDIUM", "LOW"].index(
                            default_severity
                        ),
                    )

                with form_cols[1]:
                    priority = st.selectbox(
                        "Priority",
                        ["P1", "P2", "P3", "P4"],
                        index={
                            "HIGH": 0,
                            "MEDIUM": 1,
                            "LOW": 2,
                        }.get(default_severity, 2),
                    )

                with form_cols[2]:
                    assigned_to = st.text_input(
                        "Assigned To",
                        value="SOC Team",
                    )

                submitted = st.form_submit_button(
                    "🎫 Create Incident Ticket",
                    use_container_width=True,
                    type="primary",
                )

            if submitted:

                if not title.strip():
                    st.error("Ticket title is required.")
                else:

                    result = create_ticket(
                        alert_id=int(selected_alert_id),
                        title=title.strip(),
                        description=description.strip(),
                        severity=severity,
                        priority=priority,
                        category=default_category,
                        assigned_to=assigned_to.strip() or "SOC Team",
                    )

                    if result.get("created"):
                        st.success(
                            f"Ticket {result['ticket_number']} created successfully."
                        )
                        st.cache_data.clear()
                        st.rerun()

                    elif result.get("duplicate"):
                        st.warning(
                            f"This alert already has ticket "
                            f"{result['ticket_number']} "
                            f"({result['status']})."
                        )

                    else:
                        st.error("Ticket could not be created.")

with ticket_tabs[2]:

    if tickets.empty:
        st.info("No tickets available to manage.")
    else:

        ticket_numbers = (
            tickets["ticket_number"]
            .dropna()
            .astype(str)
            .tolist()
        )

        selected_ticket_number = st.selectbox(
            "Select Ticket",
            ticket_numbers,
            key="manage_ticket_select",
        )

        selected_ticket = tickets[
            tickets["ticket_number"].astype(str)
            == selected_ticket_number
        ].iloc[0]

        st.write(
            f"**{selected_ticket_number}** — "
            f"{safe_value(selected_ticket, 'title', 'Incident')}"
        )

        current_status = str(
            safe_value(selected_ticket, "status", "OPEN")
        ).upper()

        current_priority = str(
            safe_value(selected_ticket, "priority", "P3")
        ).upper()

        manage_cols = st.columns(3)

        with manage_cols[0]:
            new_status = st.selectbox(
                "Status",
                ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"],
                index=(
                    ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]
                    .index(current_status)
                    if current_status
                    in ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"]
                    else 0
                ),
            )

        with manage_cols[1]:
            new_priority = st.selectbox(
                "Priority",
                ["P1", "P2", "P3", "P4"],
                index=(
                    ["P1", "P2", "P3", "P4"].index(current_priority)
                    if current_priority in ["P1", "P2", "P3", "P4"]
                    else 2
                ),
            )

        with manage_cols[2]:
            new_assignee = st.text_input(
                "Assigned To",
                value=str(
                    safe_value(
                        selected_ticket,
                        "assigned_to",
                        "SOC Team",
                    )
                ),
            )

        resolution_notes = st.text_area(
            "Resolution / Investigation Notes",
            value=str(
                safe_value(
                    selected_ticket,
                    "resolution_notes",
                    "",
                )
            ),
            height=120,
        )

        if st.button(
            "💾 Update Ticket",
            use_container_width=True,
            key="update_ticket_button",
        ):

            success = update_ticket(
                ticket_id=int(selected_ticket["id"]),
                status=new_status,
                assigned_to=new_assignee.strip() or "SOC Team",
                priority=new_priority,
                resolution_notes=resolution_notes.strip(),
            )

            if success:
                st.success(
                    f"{selected_ticket_number} updated successfully."
                )
                st.cache_data.clear()
                st.rerun()
            else:
                st.error("Ticket update failed.")


# ============================================================
# FLOW DATA
# ============================================================

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


# ============================================================
# ML PREDICTIONS
# ============================================================

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


# ============================================================
# SYSTEM DIAGNOSTICS
# ============================================================

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
            "Stored Tickets": len(tickets),
            "Ticket DB Error": ticket_db_error,
        }
    )


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    f"""
    <div class="footer">
        <strong>NetOps AI SOC</strong><br>
        Designed &amp; Developed by <strong>Pritish Ganguly</strong><br>
        AI • Network Security • Machine Learning • Incident Ticketing
        <br><br>
        Live refresh: {REFRESH_SECONDS}s
        • Detection and ML results are displayed from the local pipeline
    </div>
    """,
    unsafe_allow_html=True,
)
