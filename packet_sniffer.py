from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        protocol = "Other"

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        print(f"Source: {ip_layer.src} -> Destination: {ip_layer.dst} | Protocol: {protocol}")

        if packet.haslayer(Raw):
            print(f"Payload: {packet[Raw].load}")
        print("-" * 80)


print("Starting packet capture...... Press Ctrl+C to stop !!")
sniff(filter="ip",prn=process_packet, store=0)