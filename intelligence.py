from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time
import csv
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import LabelEncoder
import google.generativeai as genai


# Load the trained Random Forest model
rf_model = joblib.load('random_forest_model.pkl')
label_encoder = joblib.load('label_encoder.pkl') 
# scaler = joblib.load('iso_forest_scaler.pkl') 
# feature_names = joblib.load('iso_forest_X_test.pkl')

print("label_encoder: ", label_encoder)

# CSV file name
csv_filename = "window_captured_flow_data.csv"

# Define CSV headers
csv_headers = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min", "Label"
]

# Create and write headers to CSV
with open(csv_filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(csv_headers)

# Initialize variables to store flow data
flow_data = defaultdict(lambda: {
    "start_time": None,
    "end_time": None,
    "fwd_packets": 0,
    "bwd_packets": 0,
    "total_fwd_len": 0,
    "total_bwd_len": 0,
    "fwd_packet_lengths": [],
    "bwd_packet_lengths": [],
    "fwd_iat": [],
    "bwd_iat": [],
    "flags": {
        "fwd_psh": 0,
        "bwd_psh": 0,
        "fwd_urg": 0,
        "bwd_urg": 0,
    },
    "header_lengths": {
        "fwd": 0,
        "bwd": 0,
    },
    "subflow": {
        "fwd_packets": 0,
        "fwd_bytes": 0,
        "bwd_packets": 0,
        "bwd_bytes": 0,
    },
    "window_sizes": {
        "fwd": 0,
        "bwd": 0,
    },
    "active_times": [],
    "idle_times": [],
})

# Function to explain threats using Gemini
def explain_threat(packet_data):
    prompt = f"""
    Explain the following network traffic anomaly:
    - Source IP: {packet_data['src_ip']}
    - Destination IP: {packet_data['dst_ip']}
    - Predicted Label: {packet_data['Label']}
    - Flow Duration: {packet_data['Flow Duration']}
    - Total Fwd Packets: {packet_data['Total Fwd Packets']}
    - Total Backward Packets: {packet_data['Total Backward Packets']}
    - Total Length of Fwd Packets: {packet_data['Total Length of Fwd Packets']}
    - Total Length of Bwd Packets: {packet_data['Total Length of Bwd Packets']}
    - Fwd Packet Length Max: {packet_data['Fwd Packet Length Max']}
    - Fwd Packet Length Min: {packet_data['Fwd Packet Length Min']}
    """
    model = genai.GenerativeModel("gemini-pro")
    response = model.generate_content(prompt)
    return response.text

# Function to classify threats using Gemini
def classify_threat(packet_data):
    prompt = f"""
    Classify the following network traffic anomaly:
    - Source IP: {packet_data['src_ip']}
    - Destination IP: {packet_data['dst_ip']}
    - Predicted Label: {packet_data['Label']}
    - Flow Duration: {packet_data['Flow Duration']}
    - Total Fwd Packets: {packet_data['Total Fwd Packets']}
    - Total Backward Packets: {packet_data['Total Backward Packets']}
    - Total Length of Fwd Packets: {packet_data['Total Length of Fwd Packets']}
    - Total Length of Bwd Packets: {packet_data['Total Length of Bwd Packets']}
    - Fwd Packet Length Max: {packet_data['Fwd Packet Length Max']}
    - Fwd Packet Length Min: {packet_data['Fwd Packet Length Min']}

    Possible categories: DDoS, Port Scan, Brute Force, Benign.
    """
    model = genai.GenerativeModel("gemini-pro")
    response = model.generate_content(prompt)
    return response.text

def process_packet(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flow_key = (src_ip, dst_ip, src_port, dst_port)

        current_time = time.time()
        flow = flow_data[flow_key]

        if flow["start_time"] is None:
            flow["start_time"] = current_time
        flow["end_time"] = current_time

        packet_length = len(packet)
        if packet[IP].src == src_ip:
            flow["fwd_packets"] += 1
            flow["total_fwd_len"] += packet_length
            flow["fwd_packet_lengths"].append(packet_length)
            if len(flow["fwd_iat"]) > 0:
                flow["fwd_iat"].append(current_time - flow["end_time"])
            flow["header_lengths"]["fwd"] += len(packet[TCP].payload)
            flow["subflow"]["fwd_packets"] += 1
            flow["subflow"]["fwd_bytes"] += packet_length
        else:
            flow["bwd_packets"] += 1
            flow["total_bwd_len"] += packet_length
            flow["bwd_packet_lengths"].append(packet_length)
            if len(flow["bwd_iat"]) > 0:
                flow["bwd_iat"].append(current_time - flow["end_time"])
            flow["header_lengths"]["bwd"] += len(packet[TCP].payload)
            flow["subflow"]["bwd_packets"] += 1
            flow["subflow"]["bwd_bytes"] += packet_length

          # Update flags
        if packet[TCP].flags & 0x01:  # FIN flag
            flow["flags"]["fin"] = flow["flags"].get("fin", 0) + 1
        if packet[TCP].flags & 0x02:  # SYN flag
            flow["flags"]["syn"] = flow["flags"].get("syn", 0) + 1
        if packet[TCP].flags & 0x04:  # RST flag
            flow["flags"]["rst"] = flow["flags"].get("rst", 0) + 1
        if packet[TCP].flags & 0x08:  # PSH flag
            flow["flags"]["psh"] = flow["flags"].get("psh", 0) + 1
        if packet[TCP].flags & 0x10:  # ACK flag
            flow["flags"]["ack"] = flow["flags"].get("ack", 0) + 1
        if packet[TCP].flags & 0x20:  # URG flag
            flow["flags"]["urg"] = flow["flags"].get("urg", 0) + 1

        # Update window sizes
        if packet[IP].src == src_ip:
            flow["window_sizes"]["fwd"] = packet[TCP].window
        else:
            flow["window_sizes"]["bwd"] = packet[TCP].window


        # Update active and idle times
        if len(flow["active_times"]) > 0:
            flow["active_times"].append(current_time - flow["end_time"])
        if len(flow["idle_times"]) > 0:
            flow["idle_times"].append(current_time - flow["end_time"])

def finalize_flow(flow_key):
    flow = flow_data[flow_key]
    duration = flow["end_time"] - flow["start_time"]

    src_ip = flow_key[0]
    dst_ip = flow_key[1]

    packet_data = {
        "Destination Port": flow_key[3],
        "Flow Duration": duration,
        "Total Fwd Packets": flow["fwd_packets"],
        "Total Backward Packets": flow["bwd_packets"],
        "Total Length of Fwd Packets": flow["total_fwd_len"],
        "Total Length of Bwd Packets": flow["total_bwd_len"],
        "Fwd Packet Length Max": max(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,
        "Fwd Packet Length Min": min(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,
        "Fwd Packet Length Mean": sum(flow["fwd_packet_lengths"]) / len(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,
        "Fwd Packet Length Std": (sum((x - sum(flow["fwd_packet_lengths"]) / len(flow["fwd_packet_lengths"])) ** 2 for x in flow["fwd_packet_lengths"]) / len(flow["fwd_packet_lengths"])) ** 0.5 if flow["fwd_packet_lengths"] else 0,
        "Bwd Packet Length Max": max(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,
        "Bwd Packet Length Min": min(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,
        "Bwd Packet Length Mean": sum(flow["bwd_packet_lengths"]) / len(flow["bwd_packet_lengths"]) if flow["bwd_packet_lengths"] else 0,
        "Bwd Packet Length Std": (sum((x - sum(flow["bwd_packet_lengths"]) / len(flow["bwd_packet_lengths"])) ** 2 for x in flow["bwd_packet_lengths"]) / len(flow["bwd_packet_lengths"])) ** 0.5 if flow["bwd_packet_lengths"] else 0,
        "Flow Bytes/s": (flow["total_fwd_len"] + flow["total_bwd_len"]) / duration if duration > 0 else 0,
        "Flow Packets/s": (flow["fwd_packets"] + flow["bwd_packets"]) / duration if duration > 0 else 0,
        "Flow IAT Mean": (sum(flow["fwd_iat"]) + sum(flow["bwd_iat"])) / (len(flow["fwd_iat"]) + len(flow["bwd_iat"])) if (len(flow["fwd_iat"]) + len(flow["bwd_iat"])) > 0 else 0,
        "Flow IAT Std": (sum((x - (sum(flow["fwd_iat"]) + sum(flow["bwd_iat"])) / (len(flow["fwd_iat"]) + len(flow["bwd_iat"]))) ** 2 for x in flow["fwd_iat"] + flow["bwd_iat"]) / (len(flow["fwd_iat"]) + len(flow["bwd_iat"]))) ** 0.5 if (len(flow["fwd_iat"]) + len(flow["bwd_iat"])) > 0 else 0,
        "Flow IAT Max": max(flow["fwd_iat"] + flow["bwd_iat"]) if (len(flow["fwd_iat"]) + len(flow["bwd_iat"])) > 0 else 0,
        "Flow IAT Min": min(flow["fwd_iat"] + flow["bwd_iat"]) if (len(flow["fwd_iat"]) + len(flow["bwd_iat"])) > 0 else 0,
        "Fwd IAT Total": sum(flow["fwd_iat"]),
        "Fwd IAT Mean": sum(flow["fwd_iat"]) / len(flow["fwd_iat"]) if len(flow["fwd_iat"]) > 0 else 0,
        "Fwd IAT Std": (sum((x - sum(flow["fwd_iat"]) / len(flow["fwd_iat"])) ** 2 for x in flow["fwd_iat"]) / len(flow["fwd_iat"])) ** 0.5 if len(flow["fwd_iat"]) > 0 else 0,
        "Fwd IAT Max": max(flow["fwd_iat"]) if len(flow["fwd_iat"]) > 0 else 0,
        "Fwd IAT Min": min(flow["fwd_iat"]) if len(flow["fwd_iat"]) > 0 else 0,
        "Bwd IAT Total": sum(flow["bwd_iat"]),
        "Bwd IAT Mean": sum(flow["bwd_iat"]) / len(flow["bwd_iat"]) if len(flow["bwd_iat"]) > 0 else 0,
        "Bwd IAT Std": (sum((x - sum(flow["bwd_iat"]) / len(flow["bwd_iat"])) ** 2 for x in flow["bwd_iat"]) / len(flow["bwd_iat"])) ** 0.5 if len(flow["bwd_iat"]) > 0 else 0,
        "Bwd IAT Max": max(flow["bwd_iat"]) if len(flow["bwd_iat"]) > 0 else 0,
        "Bwd IAT Min": min(flow["bwd_iat"]) if len(flow["bwd_iat"]) > 0 else 0,
        "Fwd PSH Flags": flow["flags"]["fwd_psh"],
        "Bwd PSH Flags": flow["flags"]["bwd_psh"],
        "Fwd URG Flags": flow["flags"]["fwd_urg"],
        "Bwd URG Flags": flow["flags"]["bwd_urg"],
        "Fwd Header Length": flow["header_lengths"]["fwd"],
        "Bwd Header Length": flow["header_lengths"]["bwd"],
        "Fwd Packets/s": flow["fwd_packets"] / duration if duration > 0 else 0,
        "Bwd Packets/s": flow["bwd_packets"] / duration if duration > 0 else 0,
        "Min Packet Length": min(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,
        "Max Packet Length": max(flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) if (flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) else 0,
        "Packet Length Mean": (sum(flow["fwd_packet_lengths"]) + sum(flow["bwd_packet_lengths"])) / (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"])) if (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"])) > 0 else 0,
        "Packet Length Std": (sum((x - (sum(flow["fwd_packet_lengths"]) + sum(flow["bwd_packet_lengths"])) / (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"]))) ** 2 for x in flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) / (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"]))) ** 0.5 if (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"])) > 0 else 0,
        "Packet Length Variance": (sum(((x - (sum(flow["fwd_packet_lengths"]) + sum(flow["bwd_packet_lengths"])) / (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"]))) ** 2) for x in flow["fwd_packet_lengths"] + flow["bwd_packet_lengths"]) / (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"]))) if (len(flow["fwd_packet_lengths"]) + len(flow["bwd_packet_lengths"])) > 0 else 0,
        "FIN Flag Count": flow["flags"].get("fin", 0),
        "SYN Flag Count": flow["flags"].get("syn", 0),
        "RST Flag Count": flow["flags"].get("rst", 0),
        "PSH Flag Count": flow["flags"].get("psh", 0),
        "ACK Flag Count": flow["flags"].get("ack", 0),
        "URG Flag Count": flow["flags"].get("urg", 0),
        "CWE Flag Count": 0,  # Not directly available in TCP
        "ECE Flag Count": 0,  # Not directly available in TCP
        "Down/Up Ratio": flow["bwd_packets"] / flow["fwd_packets"] if flow["fwd_packets"] > 0 else 0,
        "Average Packet Size": (flow["total_fwd_len"] + flow["total_bwd_len"]) / (flow["fwd_packets"] + flow["bwd_packets"]) if (flow["fwd_packets"] + flow["bwd_packets"]) > 0 else 0,
        "Avg Fwd Segment Size": flow["total_fwd_len"] / flow["fwd_packets"] if flow["fwd_packets"] > 0 else 0,
        "Avg Bwd Segment Size": flow["total_bwd_len"] / flow["bwd_packets"] if flow["bwd_packets"] > 0 else 0,
        "Fwd Header Length.1": flow["header_lengths"]["fwd"],
        "Fwd Avg Bytes/Bulk": 0,  # Not directly available
        "Fwd Avg Packets/Bulk": 0,  # Not directly available
        "Fwd Avg Bulk Rate": 0,  # Not directly available
        "Bwd Avg Bytes/Bulk": 0,  # Not directly available
        "Bwd Avg Packets/Bulk": 0,  # Not directly available
        "Bwd Avg Bulk Rate": 0,  # Not directly available
        "Subflow Fwd Packets": flow["subflow"]["fwd_packets"],
        "Subflow Fwd Bytes": flow["subflow"]["fwd_bytes"],
        "Subflow Bwd Packets": flow["subflow"]["bwd_packets"],
        "Subflow Bwd Bytes": flow["subflow"]["bwd_bytes"],
        "Init_Win_bytes_forward": flow["window_sizes"]["fwd"],
        "Init_Win_bytes_backward": flow["window_sizes"]["bwd"],
        "act_data_pkt_fwd": flow["fwd_packets"],
        "min_seg_size_forward": min(flow["fwd_packet_lengths"]) if flow["fwd_packet_lengths"] else 0,
        "Active Mean": sum(flow["active_times"]) / len(flow["active_times"]) if len(flow["active_times"]) > 0 else 0,
        "Active Std": (sum((x - sum(flow["active_times"]) / len(flow["active_times"])) ** 2 for x in flow["active_times"]) / len(flow["active_times"])) ** 0.5 if len(flow["active_times"]) > 0 else 0,
        "Active Max": max(flow["active_times"]) if len(flow["active_times"]) > 0 else 0,
        "Active Min": min(flow["active_times"]) if len(flow["active_times"]) > 0 else 0,
        "Idle Mean": sum(flow["idle_times"]) / len(flow["idle_times"]) if len(flow["idle_times"]) > 0 else 0,
        "Idle Std": (sum((x - sum(flow["idle_times"]) / len(flow["idle_times"])) ** 2 for x in flow["idle_times"]) / len(flow["idle_times"])) ** 0.5 if len(flow["idle_times"]) > 0 else 0,
        "Idle Max": max(flow["idle_times"]) if len(flow["idle_times"]) > 0 else 0,
        "Idle Min": min(flow["idle_times"]) if len(flow["idle_times"]) > 0 else 0,
        # "Label": "Normal"  # Default label, can be updated based on detection logic
    }

# Convert packet_data to DataFrame for preprocessing
    flow_df = pd.DataFrame([packet_data])


    # Ensure the new DataFrame has the same columns as the training data
    # flow_df = flow_df.reindex(columns=feature_names, fill_value=0)

    # Handle missing/infinite values
    flow_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    flow_df.fillna(0, inplace=True)

    # Scale the features using the pre-trained scaler

    scaler = StandardScaler()
    # label_encoder = LabelEncoder()
    scaled_features = scaler.fit_transform(flow_df)
    print(f"Flow data: {flow_df}")
    print(f"Scaled flow data: {scaled_features}")

    # Predict the label using the Random Forest model
    predicted_label_encoded = rf_model.predict(scaled_features)
    
    print(f"Predicted label_encoded: {predicted_label_encoded}")

    predicted_label = label_encoder.inverse_transform(predicted_label_encoded)[0]

    print(f"Predicted label: {predicted_label}")

    # Add the predicted label to packet_data
    packet_data["Label"] = predicted_label


    # Append data to CSV file
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([packet_data.get(header, 0) for header in csv_headers])
    # Insert packet data into your collection
    # collection.insert_one(packet_data)

    packet_data["src_ip"] = src_ip
    packet_data["dst_ip"] = dst_ip

    # Use Gemini to explain and classify the threat
    # threat_explanation = explain_threat(packet_data)
    # threat_classification = classify_threat(packet_data)

    print(f"Predicted Label: {predicted_label}")
    # print(f"Threat Explanation: {threat_explanation}")
    # print(f"Threat Classification: {threat_classification}")

    # Take action based on the predicted label
    if predicted_label != "BENIGN":
        print(f"ALERT: Anomaly detected! Threat Type: {predicted_label}")
        # Example: Block the source IP (requires root privileges)
        # subprocess.run(f"iptables -A INPUT -s {packet_data['src_ip']} -j DROP", shell=True)
    print(f"Sent to collection: {packet_data}")

# Start sniffing in real-time
print("Starting packet capture...")
for i in range(10):
    print(f"Iteration {i + 1}")
    sniff(iface="Ethernet", prn=process_packet, count=1)  # Capture 100 packets

    # Finalize all flows after capture
    for flow_key in flow_data:
        finalize_flow(flow_key)

    # Clear flow_data for the next iteration (optional, depending on your use case)
    flow_data.clear()

print("Packet capture completed.")