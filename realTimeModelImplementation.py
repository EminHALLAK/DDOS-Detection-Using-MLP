import pyshark
import pickle
import time
import pandas as pd
import numpy as np
from collections import deque, defaultdict
import socket

# === Load Model & Scaler ===
with open("mlp_ddos_model.pkl", "rb") as f:
    model = pickle.load(f)

with open("mlp_ddos_scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

# === Dictionaries to track last timestamp and recent time differences per IP ===
ip_last_time = defaultdict(float)
ip_time_diffs = defaultdict(lambda: deque(maxlen=5))

# === Live Packet Sniffing Setup ===
capture = pyshark.LiveCapture(interface='Ethernet0')# or 'eth0' on Linux
my_ip = socket.gethostbyname(socket.gethostname())
print(my_ip)
print("Listening for packets... (Press Ctrl+C to stop)")

for packet in capture.sniff_continuously():
    try:
        if packet.ip.src == my_ip:
            continue
        if 'IP' not in packet:
            continue

        # Basic packet details
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        timestamp = float(packet.sniff_timestamp)
        # Determine protocol: if TCP then 6, if UDP then 17
        protocol = int(packet.transport_layer == 'TCP') * 6 + int(packet.transport_layer == 'UDP') * 17
        dst_port = int(packet[packet.transport_layer].dstport)
        pkt_len = int(packet.length)

        # TCP flags (only applicable for TCP; for UDP we just use 0)
        if 'TCP' in packet:
            flags = packet.tcp.flags  # This returns a string; use membership test on the string
            fin = int('0x01' in flags)
            syn = int('0x02' in flags)
            rst = int('0x04' in flags)
            psh = int('0x08' in flags)
            ack = int('0x10' in flags)
            urg = int('0x20' in flags)
        else:
            fin = syn = rst = psh = ack = urg = 0

        # --- Calculate Flow Duration & Rates ---
        last_time = ip_last_time[ip_src]
        if last_time == 0:
            # First packet from this source: assign a default small duration
            flow_duration = 0.001  # 1 millisecond default
            time_diff = 0  # No previous packet difference
        else:
            flow_duration = timestamp - last_time
            if flow_duration <= 0:
                flow_duration = 0.001
            time_diff = flow_duration

        ip_last_time[ip_src] = timestamp

        # Update rolling window of time differences for this IP
        ip_time_diffs[ip_src].append(time_diff)
        rolling_avg = np.mean(ip_time_diffs[ip_src]) if ip_time_diffs[ip_src] else 0

        # Flow-based metrics; assume the current packet is a new flow or contributes as a singular flow unit
        fwd_pkts = 1
        totlen_fwd = pkt_len

        # Compute traffic rates using the computed flow duration
        bytes_per_sec = totlen_fwd / flow_duration
        pkts_per_sec = fwd_pkts / flow_duration
        pkt_len_mean = pkt_len

        # === Create Feature Vector ===
        # The order must match the training data exactly.
        row = [
            ip_src,
            timestamp,
            dst_port,
            protocol,
            flow_duration,
            fwd_pkts,
            totlen_fwd,
            bytes_per_sec,
            pkts_per_sec,
            pkt_len_mean,
            fin,
            syn,
            rst,
            psh,
            ack,
            urg,
            time_diff,
            rolling_avg
        ]

        columns = [
            'ip', 'timestamp', 'Dst Port', 'Protocol', 'Flow Duration', 'Tot Fwd Pkts',
            'TotLen Fwd Pkts', 'Flow Byts/s', 'Flow Pkts/s', 'Pkt Len Mean',
            'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt',
            'ACK Flag Cnt', 'URG Flag Cnt', 'time_diff', 'rolling_avg'
        ]

        df = pd.DataFrame([row], columns=columns)

        # Drop non-feature columns ('ip' and 'timestamp') to create the input vector for the model.
        X_live = df.drop(columns=["ip", "timestamp"])
        X_scaled = scaler.transform(X_live)

        # Predict using the loaded model (an MLPClassifier; prediction is a class label)
        pred = model.predict(X_scaled)[0]

        # Based on your threshold, assume a prediction of 1 indicates DDoS detection.
        if pred > 0.5:
            label = "🚨 DDoS DETECTED"
        else:
            label = "✅ Normal Traffic"

        print(f"[{ip_src}] - {dst_port} - {protocol} - {flow_duration:.5f} -> {label} - Predicted value: {pred}")

    except Exception as e:
        print("Error processing packet:", e)