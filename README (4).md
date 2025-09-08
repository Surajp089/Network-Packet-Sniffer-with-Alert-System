# Network Packet Sniffer with Alert System

## Introduction
This project, **Network Packet Sniffer with Alert System**, was developed as part of a cybersecurity internship.  
The tool captures live packets, logs traffic details, detects anomalies such as flooding or port scanning, and visualizes data for better understanding.  
It simulates the role of a SOC (Security Operations Center) analyst by providing real-time monitoring, detection, and alerting.

## Abstract
The project implements a packet sniffer using **Python** and **Scapy** to capture packets in real-time.  
Each packet’s metadata (timestamp, source IP, destination IP, protocol, and size) is stored in an **SQLite database** for structured logging.  
An anomaly detection algorithm checks if an IP address exceeds a defined traffic threshold and triggers alerts for suspicious activity (e.g., port scanning, DoS).  
Additionally, **Matplotlib** is used to generate traffic graphs across protocols (TCP, UDP, ICMP), combining monitoring, detection, and reporting.

## Objectives
- Build a Python-based sniffer capable of capturing real-time network packets  
- Log traffic details for analysis and forensic purposes  
- Implement anomaly detection rules for suspicious activity  
- Generate alerts when traffic thresholds are exceeded  
- Visualize captured data for better understanding of network behavior  

## Tools Used
- **Python** – Programming language  
- **Scapy** – Packet sniffing and manipulation  
- **SQLite** – Structured log storage  
- **Matplotlib** – Graph visualization  
- **SMTP** – Sending email alerts  

## Steps Involved
1. Installed Python and required dependencies (`scapy`, `matplotlib`).  
2. Configured Scapy to sniff packets from the network interface.  
3. Extracted key details: source IP, destination IP, protocol, and size.  
4. Logged details into SQLite database (`packets.db`).  
5. Applied threshold rule (>50 packets from the same IP = suspicious).  
6. Triggered alerts when rules matched.  
7. Visualized results in bar charts (TCP, UDP, ICMP distribution).  

## Results
- **Logs**: Database entries show timestamps, IPs, protocol, and size.  
- **Alerts**: Triggered alerts for possible port scans and flooding attempts.  
- **Visualization**: Graphs showing packet counts by protocol.  

## Conclusion
The **Network Packet Sniffer with Alert System** successfully simulates the role of a SOC analyst.  
It demonstrates essential cybersecurity skills, including packet capture, traffic inspection, anomaly detection, and alerting.  
This project highlights how monitoring and visualization can aid in identifying and mitigating network threats.  
