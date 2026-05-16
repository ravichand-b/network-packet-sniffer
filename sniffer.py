from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

# ---- Packet Counter ----
packet_count = 0

# ---- Process Each Packet ----
def process_packet(packet):
    global packet_count
    packet_count += 1

    time_now = datetime.now().strftime("%H:%M:%S")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP Packet
        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"[{time_now}] [TCP] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

            # Detect possible port scan (many different ports)
            if dst_port in [21, 22, 23, 80, 443, 3306, 8080]:
                print(f"  ⚠  Common service port accessed — Port {dst_port}")

        # UDP Packet
        elif packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{time_now}] [UDP] {src_ip}:{src_port} --> {dst_ip}:{dst_port}")

        # ICMP Packet (ping)
        elif packet.haslayer(ICMP):
            print(f"[{time_now}] [ICMP/PING] {src_ip} --> {dst_ip}")

    # Save to log file
    with open("packet_log.txt", "a") as f:
        f.write(f"[{time_now}] Packet {packet_count}: {packet.summary()}\n")

# ---- Start Sniffing ----
print("="*50)
print("   NETWORK PACKET SNIFFER STARTED")
print("="*50)
print("Capturing packets... Press Ctrl+C to stop\n")

try:
    sniff(prn=process_packet, store=False, count=50)
except KeyboardInterrupt:
    print("\nSniffer stopped.")

print(f"\nTotal packets captured: {packet_count}")
print("Packets saved to packet_log.txt")