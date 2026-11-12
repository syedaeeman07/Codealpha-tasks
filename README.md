# Task 1 – Basic Network Sniffer

Task 1 of the CodeAlpha Cyber Security Internship.

A Python program that captures live network traffic using **Scapy** and displays,
for every packet: time, protocol (TCP / UDP / ICMP), source and destination IP
and port, packet size, and a readable preview of the payload. At the end it
prints a summary of packets per protocol and can save the capture to a `.pcap`
file for analysis in Wireshark.

## Requirements
- Python 3
- Scapy: `pip install scapy`
- Windows only: [Npcap](https://npcap.com) (install with "WinPcap API-compatible Mode")

## How to run
Open a terminal **as Administrator** (Windows) or use `sudo` (Linux/Mac):

```
python sniffer.py                    # capture 50 packets
python sniffer.py -c 100             # capture 100 packets
python sniffer.py -f "tcp port 443"  # only HTTPS traffic
python sniffer.py -f icmp            # only ping packets
python sniffer.py -o capture.pcap    # save packets to a file
```

## What I learned
- How data travels across the network in packets with layered headers (IP, TCP/UDP).
- How ports identify services (80 = HTTP, 443 = HTTPS, 53 = DNS).
- Why HTTPS payloads look unreadable (encryption) while plain HTTP/DNS are readable.

## Screenshots
![Sniffer Output](output.png)

## Disclaimer
Use only on your own network or with permission.
