from collections import defaultdict
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

def capture_packets(duration=5):
    packets = sniff(timeout=duration)
    packet_counts = defaultdict(int)
    for packet in packets:
        packet_info = capture_packet_info(packet)
        packet_key = tuple(packet_info.items())
        packet_counts[packet_key] += 1
    aggregated_packets = [{"count": count, **dict(packet_key)} for packet_key, count in packet_counts.items()]
    return aggregated_packets