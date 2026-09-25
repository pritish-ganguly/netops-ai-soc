import os
import sqlite3
from datetime import datetime

DATABASE_PATH = "data/netops_alerts.db"

def get_connection():
    os.makedirs(
        os.path.dirname(DATABASE_PATH),
        exist_ok=True
    )

    connection = sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    )

    connection.execute("PRAGMA busy_timeout = 10000")

    return connection

REQUIRED_COLUMNS = {
    "timestamp": "TEXT",
    "source": "TEXT",
    "event_type": "TEXT",
    "severity": "TEXT",
    "description": "TEXT",
    "status": "TEXT",
    "confidence": "REAL",
    "source_ip": "TEXT",
    "destination_ip": "TEXT",
    "protocol": "TEXT",
    "source_port": "INTEGER",
    "destination_port": "INTEGER",
    "attack_category": "TEXT",
    "risk_score": "REAL",
    "packet_rate": "REAL",
    "byte_rate": "REAL",
    "connection_count": "INTEGER",
    "evidence": "TEXT",
    "protocol_context": "TEXT",
    "alert_key": "TEXT",
}

def initialize_database():

    connection = get_connection()
    cursor = connection.cursor()

    try:

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT,

                source TEXT,

                event_type TEXT,

                severity TEXT,

                description TEXT,

                status TEXT,

                confidence REAL,

                source_ip TEXT,

                destination_ip TEXT,

                protocol TEXT,

                source_port INTEGER,

                destination_port INTEGER,

                attack_category TEXT,

                risk_score REAL,

                packet_rate REAL,

                byte_rate REAL,

                connection_count INTEGER,

                evidence TEXT,

                protocol_context TEXT,

                alert_key TEXT
            )
            """
        )

        connection.commit()

        existing_columns = {
            row[1]
            for row in cursor.execute(
                "PRAGMA table_info(alerts)"
            ).fetchall()
        }

        for column, column_type in REQUIRED_COLUMNS.items():

            if column not in existing_columns:

                cursor.execute(
                    f"""
                    ALTER TABLE alerts
                    ADD COLUMN {column} {column_type}
                    """
                )

        connection.commit()

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alert_timestamp
            ON alerts(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alert_source_ip
            ON alerts(source_ip)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alert_severity
            ON alerts(severity)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_alert_category
            ON alerts(attack_category)
            """
        )

        cursor.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            idx_alert_unique_key
            ON alerts(alert_key)
            WHERE alert_key IS NOT NULL
            """
        )

        connection.commit()

    finally:
        connection.close()

    print("Database initialized successfully.")
    print("Database:", DATABASE_PATH)
    print("Alerts table ready.")
    initialize_ticketing()

def build_alert_key(alert):

    source_ip = str(
        alert.get("source_ip") or ""
    ).strip()

    destination_ip = str(
        alert.get("destination_ip") or ""
    ).strip()

    protocol = str(
        alert.get("protocol") or ""
    ).strip().lower()

    source_port = str(
        alert.get("source_port") or ""
    ).strip()

    destination_port = str(
        alert.get("destination_port") or ""
    ).strip()

    category = str(
        alert.get("attack_category") or ""
    ).strip().upper()

    event_type = str(
        alert.get("event_type") or ""
    ).strip().upper()

    return "|".join(
        [
            source_ip,
            destination_ip,
            protocol,
            source_port,
            destination_port,
            category,
            event_type,
        ]
    )

def normalize_alert(alert):

    alert = dict(alert)

    if not alert.get("timestamp"):
        alert["timestamp"] = datetime.now().isoformat()

    if not alert.get("source"):
        alert["source"] = "NetOps AI"

    if not alert.get("event_type"):
        alert["event_type"] = "ML_ANOMALY"

    if not alert.get("status"):
        alert["status"] = "OPEN"

    if not alert.get("attack_category"):
        alert["attack_category"] = "ML_ANOMALY"

    if not alert.get("description"):
        alert["description"] = (
            f"Network security event detected: "
            f"{alert['attack_category']}"
        )

    if not alert.get("alert_key"):
        alert["alert_key"] = build_alert_key(alert)

    return alert

def save_alert(alert):

    alert = normalize_alert(alert)

    connection = get_connection()
    cursor = connection.cursor()

    try:

        alert_key = alert.get("alert_key")

        if alert_key:

            existing = cursor.execute(
                """
                SELECT id
                FROM alerts
                WHERE alert_key = ?
                LIMIT 1
                """,
                (alert_key,)
            ).fetchone()

            if existing:

                return {
                    "inserted": False,
                    "duplicate": True,
                    "id": existing[0],
                    "alert_key": alert_key,
                }

        cursor.execute(
            """
            INSERT INTO alerts (

                timestamp,
                source,
                event_type,
                severity,
                description,
                status,
                confidence,
                source_ip,
                destination_ip,
                protocol,
                source_port,
                destination_port,
                attack_category,
                risk_score,
                packet_rate,
                byte_rate,
                connection_count,
                evidence,
                protocol_context,
                alert_key

            )

            VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            """,
            (
                alert.get("timestamp"),
                alert.get("source"),
                alert.get("event_type"),
                alert.get("severity", "LOW"),
                alert.get("description"),
                alert.get("status", "OPEN"),
                alert.get("confidence"),
                alert.get("source_ip"),
                alert.get("destination_ip"),
                alert.get("protocol"),
                alert.get("source_port"),
                alert.get("destination_port"),
                alert.get("attack_category"),
                alert.get("risk_score", 0),
                alert.get("packet_rate", 0),
                alert.get("byte_rate", 0),
                alert.get("connection_count", 0),
                alert.get("evidence"),
                alert.get("protocol_context"),
                alert.get("alert_key"),
            )
        )

        connection.commit()

        alert_id = cursor.lastrowid

        return {
            "inserted": True,
            "duplicate": False,
            "id": alert_id,
            "alert_key": alert_key,
        }

    finally:
        connection.close()

def save_alerts(alerts):

    inserted = 0
    duplicates = 0
    failed = 0

    for alert in alerts:

        try:

            result = save_alert(alert)

            if result["inserted"]:
                inserted += 1
            else:
                duplicates += 1

        except Exception as exc:

            failed += 1

            print(
                "[DATABASE] Failed to save alert:",
                exc
            )

    print()
    print("[DATABASE] Alert processing complete")
    print("[DATABASE] New alerts:", inserted)
    print("[DATABASE] Duplicates skipped:", duplicates)
    print("[DATABASE] Failed:", failed)
    print()
    print("Database saved to:")
    print(os.path.abspath(DATABASE_PATH))

    return {
        "inserted": inserted,
        "duplicates": duplicates,
        "failed": failed,
    }

def get_database_stats():

    connection = get_connection()

    try:

        cursor = connection.cursor()

        count = cursor.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        unique_keys = cursor.execute(
            """
            SELECT COUNT(DISTINCT alert_key)
            FROM alerts
            WHERE alert_key IS NOT NULL
            """
        ).fetchone()[0]

        latest_id = cursor.execute(
            "SELECT MAX(id) FROM alerts"
        ).fetchone()[0]

        return {
            "count": count,
            "unique_keys": unique_keys,
            "latest_id": latest_id,
        }

    finally:
        connection.close()

def initialize_ticketing():

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ticket_number TEXT NOT NULL UNIQUE,
                alert_id INTEGER,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'LOW',
                priority TEXT DEFAULT 'P3',
                category TEXT,
                status TEXT DEFAULT 'OPEN',
                assigned_to TEXT DEFAULT 'SOC Team',
                resolution_notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            )
            """
        )

        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ticket_status ON tickets(status)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ticket_alert ON tickets(alert_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_ticket_created ON tickets(created_at)"
        )

        connection.commit()

    finally:
        connection.close()

def _ticket_priority(severity):

    severity = str(severity or "LOW").upper()

    if severity == "HIGH":
        return "P1"

    if severity == "MEDIUM":
        return "P2"

    return "P3"

def _next_ticket_number(cursor):

    year = datetime.now().year
    prefix = f"NET-{year}-"

    row = cursor.execute(
        """
        SELECT ticket_number
        FROM tickets
        WHERE ticket_number LIKE ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (f"{prefix}%",)
    ).fetchone()

    if not row:
        sequence = 1
    else:
        try:
            sequence = int(str(row[0]).split("-")[-1]) + 1
        except (ValueError, IndexError):
            sequence = 1

    return f"{prefix}{sequence:05d}"

def create_ticket(
    alert_id,
    title,
    description,
    severity="LOW",
    category="SECURITY",
    priority=None,
    assigned_to="SOC Team",
):

    initialize_ticketing()

    connection = get_connection()
    cursor = connection.cursor()

    try:

        if alert_id is not None:
            existing = cursor.execute(
                """
                SELECT id, ticket_number, status
                FROM tickets
                WHERE alert_id = ?
                LIMIT 1
                """,
                (int(alert_id),)
            ).fetchone()

            if existing:
                return {
                    "created": False,
                    "duplicate": True,
                    "id": existing[0],
                    "ticket_number": existing[1],
                    "status": existing[2],
                }

        now = datetime.now().isoformat()
        priority = priority or _ticket_priority(severity)
        ticket_number = _next_ticket_number(cursor)

        cursor.execute(
            """
            INSERT INTO tickets (
                ticket_number,
                alert_id,
                title,
                description,
                severity,
                priority,
                category,
                status,
                assigned_to,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?, ?)
            """,
            (
                ticket_number,
                alert_id,
                title,
                description,
                str(severity or "LOW").upper(),
                str(priority).upper(),
                category or "SECURITY",
                assigned_to or "SOC Team",
                now,
                now,
            )
        )

        connection.commit()

        return {
            "created": True,
            "duplicate": False,
            "id": cursor.lastrowid,
            "ticket_number": ticket_number,
            "status": "OPEN",
        }

    finally:
        connection.close()

def update_ticket(
    ticket_id,
    status=None,
    assigned_to=None,
    priority=None,
    resolution_notes=None,
):

    initialize_ticketing()

    connection = get_connection()
    cursor = connection.cursor()

    try:

        current = cursor.execute(
            """
            SELECT status, assigned_to, priority, resolution_notes
            FROM tickets
            WHERE id = ?
            """,
            (int(ticket_id),)
        ).fetchone()

        if not current:
            return False

        new_status = status if status is not None else current[0]
        new_assigned = assigned_to if assigned_to is not None else current[1]
        new_priority = priority if priority is not None else current[2]
        new_notes = resolution_notes if resolution_notes is not None else current[3]

        resolved_at = None

        if str(new_status).upper() in {"RESOLVED", "CLOSED"}:
            resolved_at = datetime.now().isoformat()

        cursor.execute(
            """
            UPDATE tickets
            SET
                status = ?,
                assigned_to = ?,
                priority = ?,
                resolution_notes = ?,
                updated_at = ?,
                resolved_at = ?
            WHERE id = ?
            """,
            (
                str(new_status).upper(),
                new_assigned,
                str(new_priority).upper(),
                new_notes,
                datetime.now().isoformat(),
                resolved_at,
                int(ticket_id),
            )
        )

        connection.commit()
        return True

    finally:
        connection.close()

if __name__ == "__main__":

    initialize_database()

    stats = get_database_stats()

    print()
    print("Database statistics:")
    print("Count:", stats["count"])
    print("Unique keys:", stats["unique_keys"])
    print("Latest ID:", stats["latest_id"])
