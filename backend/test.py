from scapy.all import sniff, IP, TCP, UDP

def capture_packet_info(packet):
    packet_info = {}
    if IP in packet:
        packet_info['src_ip'] = packet[IP].src
        packet_info['dst_ip'] = packet[IP].dst
    if TCP in packet:
        packet_info['protocol'] = 'TCP'
        packet_info['src_port'] = packet[TCP].sport
        packet_info['dst_port'] = packet[TCP].dport

    elif UDP in packet:
        packet_info['protocol'] = 'UDP'
        packet_info['src_port'] = packet[UDP].sport
        packet_info['dst_port'] = packet[UDP].dport
    return packet_info

def capture_packets(duration=3):
    packets = sniff(timeout=duration)
    return [capture_packet_info(packet) for packet in packets]

print(capture_packets())
""" import json
print(json.dumps(capture_packets(), indent=4)) """