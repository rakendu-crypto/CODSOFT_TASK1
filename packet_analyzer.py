from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw


def analyze_packet(packet):
    if IP in packet:

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        packet_length = len(packet)

        if Raw in packet:
            packet_data = packet[Raw].load
        else:
            packet_data = "No data"

        print("\n====================================")
        print("        PACKET INFORMATION")
        print("====================================")
        print("Source IP      :", source_ip)
        print("Destination IP :", destination_ip)
        print("Protocol       :", protocol)
        print("Packet Length  :", packet_length, "bytes")
        print("Packet Data    :", packet_data)
        print("====================================")


print("====================================")
print("       NETWORK PACKET ANALYZER")
print("====================================")
print("Capturing packets...")
print("Please wait...\n")

sniff(prn=analyze_packet, count=10)

print("\n====================================")
print("Packet capturing completed!")
print("====================================")