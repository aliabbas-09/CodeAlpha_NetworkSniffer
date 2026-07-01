from scapy.all import sniff, IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        proto_name = "OTHER"
        if TCP in packet:
            proto_name = "TCP"
        elif UDP in packet:
            proto_name = "UDP"
        elif ICMP in packet:
            proto_name = "ICMP"

        print(f"[+] Source IP: {src_ip}  ->  Destination IP: {dst_ip}  | Protocol: {proto_name}")

        if TCP in packet:
            print(f"    TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif UDP in packet:
            print(f"    UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}")

        if packet.haslayer('Raw'):
            payload = packet['Raw'].load
            print(f"    Payload size: {len(payload)} bytes")

        print("-" * 60)


def main():
    print("Network Sniffer Shuru Ho Raha Hai...")
    print("Rukne ke liye Ctrl+C press karo\n")
    sniff(prn=packet_callback, filter="ip", store=False, count=0)


if __name__ == "__main__":
    main()