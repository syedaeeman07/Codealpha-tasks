"""
CodeAlpha - Task 1: Basic Network Sniffer
Captures network packets and shows source/destination IPs, ports,
protocol, packet size and a short preview of the payload.

Usage (run as Administrator / sudo):
    python sniffer.py                 # capture 50 packets
    python sniffer.py -c 100          # capture 100 packets
    python sniffer.py -f "tcp port 80"  # only HTTP traffic
    python sniffer.py -o capture.pcap # also save packets to a file
"""
import argparse
from collections import Counter
from datetime import datetime

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, wrpcap

PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}
captured = []
stats = Counter()


def payload_preview(packet, max_len=50):
    """Return the first bytes of the payload as readable text."""
    if not packet.haslayer(Raw):
        return "-"
    data = bytes(packet[Raw].load)[:max_len]
    text = data.decode("utf-8", errors="replace")
    return "".join(ch if ch.isprintable() else "." for ch in text)


def process_packet(packet):
    """Called by scapy for every captured packet."""
    if not packet.haslayer(IP):
        return  # skip non-IP packets (e.g. ARP)

    captured.append(packet)
    ip = packet[IP]
    proto = PROTOCOLS.get(ip.proto, f"OTHER({ip.proto})")
    stats[proto] += 1

    src, dst = ip.src, ip.dst
    if packet.haslayer(TCP):
        src += f":{packet[TCP].sport}"
        dst += f":{packet[TCP].dport}"
    elif packet.haslayer(UDP):
        src += f":{packet[UDP].sport}"
        dst += f":{packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        proto = f"ICMP(type {packet[ICMP].type})"

    time = datetime.now().strftime("%H:%M:%S")
    print(f"[{time}] #{len(captured):<4} {proto:<13} {src:<22} -> {dst:<22} "
          f"size={len(packet):<5} payload: {payload_preview(packet)}")


def main():
    parser = argparse.ArgumentParser(description="CodeAlpha Basic Network Sniffer")
    parser.add_argument("-c", "--count", type=int, default=50,
                        help="number of packets to capture (0 = unlimited, stop with Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None,
                        help='BPF filter, e.g. "tcp", "udp port 53", "icmp"')
    parser.add_argument("-i", "--iface", default=None,
                        help="network interface (default: scapy chooses)")
    parser.add_argument("-o", "--output", default=None,
                        help="save captured packets to a .pcap file (open in Wireshark)")
    args = parser.parse_args()

    print("=" * 100)
    print(" CodeAlpha Basic Network Sniffer  |  press Ctrl+C to stop")
    print(f" Count: {args.count or 'unlimited'}  |  Filter: {args.filter or 'none'}")
    print("=" * 100)

    try:
        sniff(prn=process_packet, count=args.count, filter=args.filter,
              iface=args.iface, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("Permission denied: run this program as Administrator (Windows) or with sudo (Linux/Mac).")
        return

    print("\n" + "=" * 100)
    print(f" Capture finished. Total IP packets: {len(captured)}")
    for proto, n in stats.most_common():
        print(f"   {proto:<12} {n}")

    if args.output and captured:
        wrpcap(args.output, captured)
        print(f" Packets saved to {args.output}")


if __name__ == "__main__":
    main()
