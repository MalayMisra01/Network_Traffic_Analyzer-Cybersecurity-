from scapy.all import sniff
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
import time

captured_packets = []

def packet_callback(pkt):
    proto = None
    src = None
    dst = None
    timestamp = time.time()  # Add timestamp for each packet

    if pkt.haslayer('IP'):
        src = pkt['IP'].src
        dst = pkt['IP'].dst
        if pkt.haslayer('TCP'):
            proto = 'TCP'
        elif pkt.haslayer('UDP'):
            proto = 'UDP'
        else:
            proto = 'IP'
    elif pkt.haslayer('ARP'):
        proto = 'ARP'
        src = pkt.psrc
        dst = pkt.pdst
    else:
        proto = type(pkt).__name__
    
    captured_packets.append({'protocol': proto, 'src': src, 'dst': dst, 'timestamp': timestamp})

# ----------- Start Packet Capture -----------
print("Capturing packets for 30 seconds. Please generate some traffic (browsing, pinging, etc.).")
sniff(timeout=30, prn=packet_callback, store=0)
print("Done capturing.\n")

# ----------- Data Analysis and Anomaly Detection -----------
df = pd.DataFrame(captured_packets)
df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')

# 1. Unusual Traffic Spike Detection
ANOMALY_WINDOW = '5S'
PACKET_RATE_THRESHOLD = 50  # Adjust to your network

print("\n-- Anomaly Detection --")
for proto in ['TCP', 'UDP']:
    proto_df = df[df['protocol'] == proto]
    if not proto_df.empty:
        rate = proto_df.resample(ANOMALY_WINDOW, on='timestamp').size()
        spikes = rate[rate > PACKET_RATE_THRESHOLD]
        for idx, value in spikes.items():
            print(f"ALERT: {value} {proto} packets in {ANOMALY_WINDOW} at {idx} — Possible anomaly/spike!")

# 2. New/Unknown Hosts Detection
known_hosts = set()
for ip in df['src'].unique():
    if ip and ip not in known_hosts:
        print(f"ALERT: Detected new host/source IP: {ip}")
    known_hosts.add(ip)

# 3. Port Scan Detection (many unique ports by one host)
for ip, group in df[df['protocol'] == 'TCP'].groupby('src'):
    unique_ports = group['dst'].nunique()
    if unique_ports > 10:
        print(f"ALERT: {ip} connected to {unique_ports} different TCP destination ports (possible port scan)")

# ----------- Visualization & Reporting -----------
proto_counts = Counter(df['protocol'])
plt.figure(figsize=(8,6))
pd.Series(proto_counts).plot(kind='bar')
plt.title('Protocol Usage Histogram')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.tight_layout()
plt.show()

if 'src' in df.columns:
    print("\nTop Source IPs:")
    print(df['src'].value_counts().head(5))

if 'dst' in df.columns:
    print("\nTop Destination IPs:")
    print(df['dst'].value_counts().head(5))

df.to_csv('traffic_capture.csv', index=False)
print("\nTraffic data saved to traffic_capture.csv")
