from scapy.all import sniff, IP, TCP, UDP
import sqlite3
import matplotlib.pyplot as plt
from datetime import datetime

# -------------------------
# Database Setup
# -------------------------
conn = sqlite3.connect("packets.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS traffic_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    length INTEGER
)
""")
conn.commit()

# -------------------------
# Alert System
# -------------------------
packet_count = {}

def detect_anomaly(src_ip):
    packet_count[src_ip] = packet_count.get(src_ip, 0) + 1
    if packet_count[src_ip] > 50:  # Threshold for suspicious traffic
        print(f"[ALERT] Possible Port Scan or Flood detected from {src_ip}")

# -------------------------
# Packet Processing
# -------------------------
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        length = len(packet)
        protocol = "OTHER"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save to DB
        cursor.execute("INSERT INTO traffic_log (timestamp, src_ip, dst_ip, protocol, length) VALUES (?, ?, ?, ?, ?)",
                       (timestamp, src_ip, dst_ip, protocol, length))
        conn.commit()

        # Run anomaly detection
        detect_anomaly(src_ip)

# -------------------------
# Run Sniffer
# -------------------------
print("Starting Packet Sniffer... Press CTRL+C to stop.")
sniff(prn=process_packet, store=False, count=200)

# -------------------------
# Visualization
# -------------------------
print("Generating Traffic Graph...")

cursor.execute("SELECT protocol, COUNT(*) FROM traffic_log GROUP BY protocol")
data = cursor.fetchall()

protocols = [row[0] for row in data]
counts = [row[1] for row in data]

plt.bar(protocols, counts)
plt.title("Traffic by Protocol")
plt.xlabel("Protocol")
plt.ylabel("Packet Count")
plt.show()
