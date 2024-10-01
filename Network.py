from scapy.all import sniff, IP, TCP, UDP, Raw


def process_ip_packet(packet):
    ip_layer = packet[IP]
    print(f"\n[+] New Packet: {ip_layer.src} -> {ip_layer.dst}")
    

    if TCP in packet:
        process_tcp_packet(packet)
    elif UDP in packet:
        process_udp_packet(packet)
    
    
    if Raw in packet:
        process_raw_data(packet)


def process_tcp_packet(packet):
    tcp_layer = packet[TCP]
    ip_layer = packet[IP]
    print(f"TCP Packet: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")


def process_udp_packet(packet):
    udp_layer = packet[UDP]
    ip_layer = packet[IP]
    print(f"UDP Packet: {ip_layer.src}:{udp_layer.sport} -> {ip_layer.dst}:{udp_layer.dport}")


def process_raw_data(packet):
    raw_data = packet[Raw].load
    print(f"Raw Data: {raw_data}")


def packet_handler(packet):
    if IP in packet:
        process_ip_packet(packet)


def start_sniffer(interface=None, packet_count=0):
    print(f"Starting network sniffer{' on ' + interface if interface else ''}...")
    sniff(iface=interface, prn=packet_handler, count=packet_count)


start_sniffer(interface="eth0", packet_count=0)  
