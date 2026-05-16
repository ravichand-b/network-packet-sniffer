# Network Packet Sniffer

A Python-based network packet sniffer that captures live network traffic in real time and detects suspicious activity.

## Features
- Captures TCP, UDP and ICMP packets live
- Shows source IP, destination IP and port numbers
- Detects common service ports (HTTP, SSH, FTP, HTTPS)
- Saves all packets to packet_log.txt automatically

## Tools Used
- Python 3
- Scapy
- Npcap (Windows packet capture driver)
- datetime

## How to Run
1. Install Npcap from npcap.com
2. Run VS Code as Administrator
3. Run: python sniffer.py
4. Live packets will show in terminal
5. Check packet_log.txt for saved logs

## Sample Output
[TCP] 192.168.1.18:50430 --> 20.42.73.24:443
[UDP] 192.168.1.6:5353 --> 224.0.0.251:5353
Total packets captured: 50

## Disclaimer
This tool is for educational purposes only.
Use only on networks you own or have permission to monitor.
