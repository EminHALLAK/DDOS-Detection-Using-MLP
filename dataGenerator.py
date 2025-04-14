import pyshark
import time
import signal
import sys
import pandas as pd
import numpy as np

# --------------------------
# 1) User-specified columns
# --------------------------
COLUMNS = [
    "ip",
    "timestamp",
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Pkt Len Mean",
    "FIN Flag Cnt",
    "SYN Flag Cnt",
    "RST Flag Cnt",
    "PSH Flag Cnt",
    "ACK Flag Cnt",
    "URG Flag Cnt",
    "Label",
]

# We'll store flows in a dictionary keyed by (src_ip, dst_ip, src_port, dst_port, proto)
# Each flow entry will track basic stats + TCP flags counters
flows = {}


def signal_handler(sig, frame):
    """Handle Ctrl+C to finalize flows and write CSV."""
    print("Stopping capture and writing CSV...")
    write_csv("ddos/no_attack.csv")
    sys.exit(0)


def write_csv(filename):
    """Convert flows to DataFrame and save to CSV."""
    rows = []
    for (src_ip, dst_ip, sport, dport, proto), data in flows.items():
        start_time = data["start"]
        end_time = data["end"]
        duration = end_time - start_time
        if duration <= 0:
            duration = 1e-6

        # We'll treat all packets as forward in this simple example
        tot_fwd_pkts = data["pkt_count"]
        tot_bwd_pkts = 0
        totlen_fwd_pkts = data["byte_count"]
        totlen_bwd_pkts = 0

        bps = data["byte_count"] / duration
        pps = data["pkt_count"] / duration
        pkt_len_mean = np.mean([data["byte_count"]]) if data["pkt_count"] else 0

        row = {
            "ip": src_ip,
            "timestamp": start_time,  # store the flow's start time
            "Dst Port": dport,
            "Protocol": proto,
            "Flow Duration": duration,
            "Tot Fwd Pkts": tot_fwd_pkts,
            "Tot Bwd Pkts": tot_bwd_pkts,
            "TotLen Fwd Pkts": totlen_fwd_pkts,
            "TotLen Bwd Pkts": totlen_bwd_pkts,
            "Flow Byts/s": bps,
            "Flow Pkts/s": pps,
            "Pkt Len Mean": pkt_len_mean,
            "FIN Flag Cnt": data["fin_cnt"],
            "SYN Flag Cnt": data["syn_cnt"],
            "RST Flag Cnt": data["rst_cnt"],
            "PSH Flag Cnt": data["psh_cnt"],
            "ACK Flag Cnt": data["ack_cnt"],
            "URG Flag Cnt": data["urg_cnt"],
            "Label": 0,  # when generating no attack data make label 0 and when generating attack data make label 1
        }
        rows.append(row)

    df = pd.DataFrame(rows, columns=COLUMNS)
    df.to_csv(filename, index=False)
    print(f"Saved {len(df)} flows to {filename}")


def bool_flag_to_int(value):
    """
    Convert PyShark boolean-like strings to int (0 or 1).
    For example, 'False' -> 0, 'True' -> 1, '1' -> 1, '0' -> 0, None -> 0.
    """
    if value in ("True", "1"):
        return 1
    # e.g. 'False' or '0' or None
    return 0


def process_packet(pkt):
    """Aggregate packets into flows, track TCP flags if present."""
    if not hasattr(pkt, 'ip'):
        return

    ip_src = pkt.ip.src
    ip_dst = pkt.ip.dst
    # Protocol number
    try:
        proto = int(pkt.ip.get_field_value('ip.proto'))
    except:
        proto = 0

    # Ports
    sport = 0
    dport = 0
    if hasattr(pkt, 'tcp'):
        sport = int(pkt.tcp.srcport)
        dport = int(pkt.tcp.dstport)
    elif hasattr(pkt, 'udp'):
        sport = int(pkt.udp.srcport)
        dport = int(pkt.udp.dstport)

    key = (ip_src, ip_dst, sport, dport, proto)

    try:
        ts = float(pkt.sniff_timestamp)
    except:
        ts = time.time()

    # Packet length
    try:
        length = int(pkt.length)
    except:
        length = 0

    # Initialize flow if not exist
    if key not in flows:
        flows[key] = {
            "start": ts,
            "end": ts,
            "pkt_count": 0,
            "byte_count": 0,
            # TCP flag counters
            "fin_cnt": 0,
            "syn_cnt": 0,
            "rst_cnt": 0,
            "psh_cnt": 0,
            "ack_cnt": 0,
            "urg_cnt": 0,
        }
    flow = flows[key]
    flow["end"] = ts
    flow["pkt_count"] += 1
    flow["byte_count"] += length

    # If packet is TCP, increment the relevant flags
    if hasattr(pkt, 'tcp'):
        fin_val = pkt.tcp.get_field_value('flags_fin')
        syn_val = pkt.tcp.get_field_value('flags_syn')
        rst_val = pkt.tcp.get_field_value('flags_reset')
        psh_val = pkt.tcp.get_field_value('flags_push')
        ack_val = pkt.tcp.get_field_value('flags_ack')
        urg_val = pkt.tcp.get_field_value('flags_urg')

        flow["fin_cnt"] += bool_flag_to_int(fin_val)
        flow["syn_cnt"] += bool_flag_to_int(syn_val)
        flow["rst_cnt"] += bool_flag_to_int(rst_val)
        flow["psh_cnt"] += bool_flag_to_int(psh_val)
        flow["ack_cnt"] += bool_flag_to_int(ack_val)
        flow["urg_cnt"] += bool_flag_to_int(urg_val)


if __name__ == "__main__":
    # Handle Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    # Ethernet 3
    interface_name = "Wi-Fi"  # replace with your interface
    print(f"Starting PyShark live capture on interface: {interface_name}")
    capture = pyshark.LiveCapture(interface=interface_name)

    try:
        for packet in capture.sniff_continuously():
            process_packet(packet)
    except KeyboardInterrupt:
        print("User interrupted. Writing CSV...")
    finally:
        write_csv("ddos/no_attack.csv")