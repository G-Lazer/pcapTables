import sys
import pandas as pd
from scapy.all import rdpcap, TCP, UDP

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    port_counts = {}

    for packet in packets:  # Should be able to optimize this loop.
        counted_ports = set()  # Set to track ports already counted in this packet.
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                if src_port not in counted_ports:
                    port_counts[src_port] = port_counts.get(src_port, 0) + 1
                    counted_ports.add(src_port)
                if dst_port not in counted_ports:
                    port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
                    counted_ports.add(dst_port)
            if packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                if src_port not in counted_ports:
                    port_counts[src_port] = port_counts.get(src_port, 0) + 1
                    counted_ports.add(src_port)
                if dst_port not in counted_ports:
                    port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
                    counted_ports.add(dst_port)

    port_df = pd.DataFrame(list(port_counts.items()), columns=['Port', 'Count']).sort_values(by='Count', ascending=False)
    print(port_df.to_string(index=False))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <path_to_pcap_file>")
        sys.exit(1)
    if not sys.argv[1].endswith('.pcap'):
        print("Error: The file must be a '.pcap' file.")
        sys.exit(1)
    analyze_pcap(sys.argv[1])
