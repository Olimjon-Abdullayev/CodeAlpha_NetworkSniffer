import sys
from scapy.all import *


def handle_packets(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        print(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

def get_interface():
    interfaces = get_if_list()
    for interface in interfaces:
        if interface != "lo":
            return interface
    return None

def main(verbose=False):
    interface = get_interface()
    if interface is None:
        print("Error: No suitable network interface found.")
        sys.exit(1)
    try:
        if verbose:
            sniff(iface=interface, prn=handle_packets, store=0, verbose=verbose)
        else:
            sniff(iface=interface, prn=handle_packets, store=0)
    except KeyboardInterrupt:
        sys.exit(0)

main()

