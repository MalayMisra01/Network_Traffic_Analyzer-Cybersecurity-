Network Traffic Analyzer & Anomaly Detection
Author: Malay Misra
Affiliation: KIIT University
Certifications: AICTE–EduSkills Virtual Internship, Palo Alto Networks Security Operations, Network, Cloud & Cybersecurity Fundamentals

Overview
This project is a Python-based tool for real-time network packet capture, protocol analysis, traffic visualization, and cybersecurity anomaly detection.
It simulates a mini Security Operations Center (SOC) for basic threat monitoring and network forensics, incorporating concepts from my cybersecurity certifications.

Features
📡 Live Packet Capture: Captures network packets using Scapy.

📊 Protocol Analytics: Visualizes protocol usage (TCP, UDP, ARP, etc.) via bar charts.

🚨 Anomaly Detection Alerts:

Detects sudden spikes in protocol-specific traffic (possible DDoS/attack).

Flags connections from new or unknown hosts.

Alerts for possible port scans (multiple unique port accesses).

📋 Data Export: Saves all captured traffic data to a CSV file for further inspection.

🛠️ Easy Customization: Thresholds and windows for traffic spike detection are easily adjustable.

Getting Started
Prerequisites
Python 3.x

pip

Scapy: pip install scapy

Pandas: pip install pandas

Matplotlib: pip install matplotlib

Npcap (for Windows): Download and install from the official site.

Installation
Clone the repository:

text
git clone https://github.com/yourusername/network-traffic-analyzer.git
cd network-traffic-analyzer
Install required Python packages:

text
pip install -r requirements.txt
(If no requirements file, use the pip install commands in Prerequisites.)

Usage
Run as Administrator (required for packet sniffing):

text
python network_traffic_analyzer.py
During capture interval (default 30s):
Use your network normally (browse, ping, etc.) to generate traffic.

Output:

Bar chart visualization of protocol usage.

Console alerts for anomalies (traffic spikes, new hosts, possible port scans).

CSV export: traffic_capture.csv in the same directory.

Project Structure
text
network-traffic-analyzer/
│
├── network_traffic_analyzer.py   # Main project script
├── README.md                     # Project documentation
└── traffic_capture.csv           # (Generated) CSV packet log
Learning Outcomes
Hands-on experience with network packet analysis and real-time threat monitoring

Practical application of concepts from:

Security Operations Fundamentals

Network Security Fundamentals

Cloud Security Fundamentals

Cybersecurity Fundamentals

Screenshots
Protocol Usage Chart
(include your bar chart image here)
License
This project is for educational purposes.
