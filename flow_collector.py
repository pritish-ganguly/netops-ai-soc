from pathlib import Path
from datetime import datetime
import threading
import time
import uuid

import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, conf


# ============================================================
# NETOPS AI - LIVE FLOW COLLECTOR
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

OUTPUT_PATH = DATA_DIR / "live_network_flows.csv"

INTERFACE = conf.iface

CSV_UPDATE_INTERVAL = 5


# ============================================================
# GLOBAL FLOW STORAGE
# ============================================================

flows = {}

flows_lock = threading.Lock()

stop_event = threading.Event()


# ============================================================
# EXPECTED CSV COLUMNS
# ============================================================

FLOW_COLUMNS = [
    "flow_id",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "start_time",
    "last_time",
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "sttl",
    "dttl",
]


# ============================================================
# CREATE FLOW
# ============================================================

def create_flow(
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    protocol
):

    return {

        "flow_id":
            f"flow_"
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_"
            f"{uuid.uuid4().hex[:8]}",

        "start_time": None,

        "last_time": None,

        "src_ip": src_ip,

        "dst_ip": dst_ip,

        "src_port": src_port,

        "dst_port": dst_port,

        "protocol": protocol,

        "src_packets": 0,

        "dst_packets": 0,

        "src_bytes": 0,

        "dst_bytes": 0,

        "src_ttl": None,

        "dst_ttl": None,
    }


# ============================================================
# PROCESS PACKET
# ============================================================

def process_packet(packet):

    try:

        # ----------------------------------------------------
        # IPv4 only
        # ----------------------------------------------------

        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst


        # ----------------------------------------------------
        # TCP
        # ----------------------------------------------------

        if packet.haslayer(TCP):

            protocol = "tcp"

            src_port = int(packet[TCP].sport)

            dst_port = int(packet[TCP].dport)


        # ----------------------------------------------------
        # UDP
        # ----------------------------------------------------

        elif packet.haslayer(UDP):

            protocol = "udp"

            src_port = int(packet[UDP].sport)

            dst_port = int(packet[UDP].dport)


        # ----------------------------------------------------
        # Other IP protocol
        # ----------------------------------------------------

        else:

            protocol = str(ip.proto)

            src_port = 0

            dst_port = 0


        # ----------------------------------------------------
        # Bidirectional flow key
        # ----------------------------------------------------

        endpoint_a = (
            src_ip,
            src_port
        )

        endpoint_b = (
            dst_ip,
            dst_port
        )


        if endpoint_a <= endpoint_b:

            flow_key = (
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol
            )

            direction = "forward"


        else:

            flow_key = (
                dst_ip,
                dst_port,
                src_ip,
                src_port,
                protocol
            )

            direction = "reverse"


        # ----------------------------------------------------
        # Packet timestamp
        # ----------------------------------------------------

        timestamp = float(packet.time)


        # ----------------------------------------------------
        # Packet size
        # ----------------------------------------------------

        packet_length = len(packet)


        # ----------------------------------------------------
        # Update flow
        # ----------------------------------------------------

        with flows_lock:

            if flow_key not in flows:

                flows[flow_key] = create_flow(
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol
                )

                flows[flow_key]["start_time"] = timestamp


            flow = flows[flow_key]

            flow["last_time"] = timestamp


            # ------------------------------------------------
            # Forward direction
            # ------------------------------------------------

            if direction == "forward":

                flow["src_packets"] += 1

                flow["src_bytes"] += packet_length


                if flow["src_ttl"] is None:

                    flow["src_ttl"] = int(ip.ttl)


            # ------------------------------------------------
            # Reverse direction
            # ------------------------------------------------

            else:

                flow["dst_packets"] += 1

                flow["dst_bytes"] += packet_length


                if flow["dst_ttl"] is None:

                    flow["dst_ttl"] = int(ip.ttl)


    except Exception as error:

        print(
            f"[PACKET ERROR] {error}"
        )


# ============================================================
# BUILD DATAFRAME
# ============================================================

def build_dataframe():

    rows = []


    with flows_lock:

        snapshot = list(
            flows.values()
        )


    for flow in snapshot:

        if flow["start_time"] is None:
            continue

        if flow["last_time"] is None:
            continue


        duration = (
            flow["last_time"]
            -
            flow["start_time"]
        )


        rows.append({

            "flow_id":
                flow["flow_id"],

            "src_ip":
                flow["src_ip"],

            "dst_ip":
                flow["dst_ip"],

            "src_port":
                flow["src_port"],

            "dst_port":
                flow["dst_port"],

            "protocol":
                flow["protocol"],

            "start_time":
                flow["start_time"],

            "last_time":
                flow["last_time"],

            "dur":
                max(duration, 0),

            "spkts":
                flow["src_packets"],

            "dpkts":
                flow["dst_packets"],

            "sbytes":
                flow["src_bytes"],

            "dbytes":
                flow["dst_bytes"],

            "sttl":
                flow["src_ttl"]
                if flow["src_ttl"] is not None
                else 0,

            "dttl":
                flow["dst_ttl"]
                if flow["dst_ttl"] is not None
                else 0,
        })


    if not rows:

        return pd.DataFrame(
            columns=FLOW_COLUMNS
        )


    return pd.DataFrame(
        rows,
        columns=FLOW_COLUMNS
    )


# ============================================================
# SAVE LIVE CSV
# ============================================================

def save_live_csv():

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True
        )


        df = build_dataframe()


        if df.empty:

            return


        # ----------------------------------------------------
        # Atomic-ish write:
        # write temporary file first
        # ----------------------------------------------------

        temp_path = OUTPUT_PATH.with_suffix(
            ".tmp"
        )


        df.to_csv(
            temp_path,
            index=False
        )


        # Replace previous CSV
        temp_path.replace(
            OUTPUT_PATH
        )


        file_size = OUTPUT_PATH.stat().st_size

        current_time = datetime.now().strftime(
            "%H:%M:%S"
        )


        print(
            f"[LIVE] CSV updated | "
            f"Flows: {len(df)} | "
            f"Size: {file_size} bytes | "
            f"Time: {current_time}"
        )


    except Exception as error:

        print(
            f"[CSV ERROR] {error}"
        )


# ============================================================
# CSV WRITER THREAD
# ============================================================

def csv_writer():

    print(
        f"[LIVE] CSV writer started "
        f"(every {CSV_UPDATE_INTERVAL} seconds)"
    )


    while not stop_event.is_set():

        save_live_csv()

        stop_event.wait(
            CSV_UPDATE_INTERVAL
        )


    print(
        "[LIVE] Final CSV update..."
    )

    save_live_csv()


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("========================================")
    print("NETOPS AI LIVE FLOW COLLECTOR")
    print("========================================")

    print(
        f"\nWorking directory:\n{BASE_DIR}"
    )

    print(
        f"\nInterface:\n{INTERFACE}"
    )

    print(
        f"\nOutput file:\n{OUTPUT_PATH}"
    )

    print(
        f"\nCSV update interval:\n"
        f"{CSV_UPDATE_INTERVAL} seconds"
    )


    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    # --------------------------------------------------------
    # Start CSV writer
    # --------------------------------------------------------

    writer_thread = threading.Thread(
        target=csv_writer,
        name="CSVWriter",
        daemon=True
    )

    writer_thread.start()


    print()
    print("========================================")
    print("STARTING LIVE PACKET CAPTURE")
    print("========================================")

    print(
        "\nGenerate network traffic."
    )

    print(
        "Open websites, ping hosts, "
        "use applications, etc."
    )

    print(
        "\nPress CTRL+C to stop."
    )

    print()


    try:

        sniff(
            iface=INTERFACE,
            prn=process_packet,
            store=False
        )


    except KeyboardInterrupt:

        print(
            "\nStopping packet capture..."
        )


    except Exception as error:

        print()
        print("========================================")
        print("PACKET CAPTURE ERROR")
        print("========================================")

        print(error)


    finally:

        stop_event.set()

        writer_thread.join(
            timeout=10
        )


        final_df = build_dataframe()


        print()
        print("========================================")
        print("FLOW COLLECTION COMPLETE")
        print("========================================")

        print(
            f"Flows captured: "
            f"{len(final_df)}"
        )


        if OUTPUT_PATH.exists():

            print(
                f"File size: "
                f"{OUTPUT_PATH.stat().st_size} bytes"
            )

            print(
                f"\nSaved to:\n"
                f"{OUTPUT_PATH}"
            )


        if not final_df.empty:

            print()
            print("Sample flows:")

            print(
                final_df[
                    [
                        "flow_id",
                        "src_ip",
                        "dst_ip",
                        "protocol",
                        "dur",
                        "spkts",
                        "dpkts",
                        "sbytes",
                        "dbytes",
                    ]
                ]
                .head(10)
                .to_string(index=False)
            )


        print()
        print("Collector stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()