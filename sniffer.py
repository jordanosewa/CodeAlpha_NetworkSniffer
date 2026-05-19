from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

packet_count = 0


def process_packet(packet):
    global packet_count
    packet_count += 1

    print(f"\n========== Packet #{packet_count} ==========")

    # Timestamp
    time_now = datetime.now().strftime("%H:%M:%S")
    print(f"Time: {time_now}")

    # Packet size
    print(f"Packet Size: {len(packet)} bytes")

    # IP Layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")

        # TCP Protocol
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            print(
                f"Protocol: TCP | "
                f"Src Port: {tcp_layer.sport} → "
                f"Dst Port: {tcp_layer.dport}"
            )

        # UDP Protocol
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]

            print(
                f"Protocol: UDP | "
                f"Src Port: {udp_layer.sport} → "
                f"Dst Port: {udp_layer.dport}"
            )

    # Payload Data
    if packet.haslayer(Raw):
        payload = packet[Raw].load

        print(f"Payload: {payload[:50]}")

    print("======================================")


# Start sniffing
try:
    print("Starting packet sniffer... Press CTRL + C to stop.\n")

    sniff(
        filter="tcp or udp",
        prn=process_packet,
        store=False
    )

except KeyboardInterrupt:
    print("\nSniffing stopped.")