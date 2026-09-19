"""
multi_stage_generator.py
------------------------
Generates a valid PCAP file for the 'Multi-Stage Exfiltration' scenario using Scapy.

Attack Scenario Stages (all from Source IP 10.0.1.55):
  Stage 1: Reconnaissance (Port scanning probes)
  Stage 2: C2 Beaconing (Periodic low-jitter keepalive connections)
  Stage 3: DNS Tunnelling (High-entropy subdomain queries)
  Stage 4: Data Exfiltration (Heavy outbound byte asymmetry)

Usage:
  python backend/multi_stage_generator.py
"""

import os
import sys
import time
import math
import random
import struct

def build_pcap_bytes_pure_python() -> bytes:
    """
    Constructs PCAP binary data for the 'Multi-Stage Exfiltration' scenario
    without requiring external libraries.
    Source IP: 10.0.1.55 (Attacker host for cross-flow correlation)
    """
    pcap_data = bytearray()
    # Global header (24 bytes): Magic 0xa1b2c3d4, v2.4, tz 0, sig 0, snaplen 65535, linktype 1 (Ethernet)
    pcap_data.extend(struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

    src_ip_bytes = bytes([10, 0, 1, 55])
    src_mac = b"\x02\x42\xac\x11\x00\x02"
    dst_mac = b"\x02\x42\xac\x11\x00\x01"

    current_ts = time.time()

    def add_packet(data: bytes, timestamp: float):
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1_000_000)
        pkt_len = len(data)
        # Packet header: ts_sec, ts_usec, incl_len, orig_len
        pcap_data.extend(struct.pack("<IIII", sec, usec, pkt_len, pkt_len))
        pcap_data.extend(data)

    def ip_checksum(header: bytes) -> int:
        if len(header) % 2 == 1:
            header += b"\x00"
        s = sum((header[i] << 8) + header[i+1] for i in range(0, len(header), 2))
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return (~s) & 0xffff

    def make_eth_ip_tcp(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, flags: int, seq: int, ack: int, payload: bytes = b"") -> bytes:
        # TCP Header (20 bytes + payload)
        tcp_hdr = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 64240, 0, 0)
        tcp_pkt = tcp_hdr + payload

        # IP Header (20 bytes)
        total_len = 20 + len(tcp_pkt)
        ip_hdr_no_cksum = struct.pack(">BBHHHBBH", 0x45, 0, total_len, random.randint(1000, 60000), 0x4000, 64, 6, 0) + src_ip + dst_ip
        cksum = ip_checksum(ip_hdr_no_cksum)
        ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, total_len, random.randint(1000, 60000), 0x4000, 64, 6, cksum) + src_ip + dst_ip

        # Eth Header (14 bytes)
        eth_hdr = dst_mac + src_mac + b"\x08\x00"
        return eth_hdr + ip_hdr + tcp_pkt

    def make_eth_ip_udp_dns(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, qname: str, payload_pad: bytes = b"") -> bytes:
        # Build DNS Query Label
        dns_qname = b""
        for part in qname.split("."):
            dns_qname += bytes([len(part)]) + part.encode("utf-8")
        dns_qname += b"\x00"
        dns_hdr = struct.pack(">HHHHHH", random.randint(1000, 60000), 0x0100, 1, 0, 0, 0) + dns_qname + struct.pack(">HH", 1, 1) + payload_pad

        # UDP Header (8 bytes)
        udp_len = 8 + len(dns_hdr)
        udp_hdr = struct.pack(">HHHH", sport, dport, udp_len, 0)
        udp_pkt = udp_hdr + dns_hdr

        # IP Header
        total_len = 20 + len(udp_pkt)
        ip_hdr_no_cksum = struct.pack(">BBHHHBBH", 0x45, 0, total_len, random.randint(1000, 60000), 0, 64, 17, 0) + src_ip + dst_ip
        cksum = ip_checksum(ip_hdr_no_cksum)
        ip_hdr = struct.pack(">BBHHHBBH", 0x45, 0, total_len, random.randint(1000, 60000), 0, 64, 17, cksum) + src_ip + dst_ip

        eth_hdr = dst_mac + src_mac + b"\x08\x00"
        return eth_hdr + ip_hdr + udp_pkt

    # STAGE 1: RECONNAISSANCE (Port Scan)
    target_ip = bytes([192, 168, 1, 10])
    for port in [21, 22, 23, 80, 443, 445, 3389, 8080]:
        sport = random.randint(49152, 65535)
        syn = make_eth_ip_tcp(src_ip_bytes, target_ip, sport, port, 0x02, 1000, 0) # SYN flag
        add_packet(syn, current_ts)
        current_ts += 0.05
        rst = make_eth_ip_tcp(target_ip, src_ip_bytes, port, sport, 0x04, 0, 1001) # RST flag
        add_packet(rst, current_ts)
        current_ts += 0.10

    current_ts += 2.0

    # STAGE 2: C2 BEACONING (Periodic TCP keepalives, low jitter)
    c2_ip = bytes([91, 195, 240, 117])
    c2_sport = 52344
    for b_idx in range(12):
        c2_payload = b"\x17\x03\x03\x00\x40" + bytes([random.randint(0, 255) for _ in range(60)])
        pkt_out = make_eth_ip_tcp(src_ip_bytes, c2_ip, c2_sport, 443, 0x18, 1000 + b_idx * 70, 5000, c2_payload) # PUSH+ACK
        add_packet(pkt_out, current_ts)
        current_ts += 2.00 # Fixed 2.00s interval

    current_ts += 2.0

    # STAGE 3: DNS TUNNELLING
    dns_ip = bytes([8, 8, 8, 8])
    dns_sport = 41233
    tunnel_chunks = [
        "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4.exfil.tunnel.evil.com",
        "ff887766554433221100aabbccddeeff.exfil.tunnel.evil.com",
        "99887766554433221100112233445566.exfil.tunnel.evil.com",
        "7766554433221100aabbccddeeff9988.exfil.tunnel.evil.com",
        "554433221100aabbccddeeff99887766.exfil.tunnel.evil.com",
    ]
    for chunk in tunnel_chunks:
        pad = bytes([random.randint(0, 255) for _ in range(120)])
        dns_pkt = make_eth_ip_udp_dns(src_ip_bytes, dns_ip, dns_sport, 53, chunk, pad)
        add_packet(dns_pkt, current_ts)
        current_ts += 0.15

    current_ts += 2.0

    # STAGE 4: DATA EXFILTRATION
    exfil_ip = bytes([198, 51, 100, 45])
    exfil_sport = 61200
    exfil_data = bytes([random.randint(0, 255) for _ in range(1400)])
    for i in range(50):
        pkt_out = make_eth_ip_tcp(src_ip_bytes, exfil_ip, exfil_sport, 8443, 0x18, 10000 + i * 1400, 2000, exfil_data)
        add_packet(pkt_out, current_ts)
        current_ts += 0.02
    pkt_ack = make_eth_ip_tcp(exfil_ip, src_ip_bytes, 8443, exfil_sport, 0x10, 2000, 10000 + 50 * 1400)
    add_packet(pkt_ack, current_ts + 0.01)

    return bytes(pcap_data)

def generate_multi_stage_pcap(output_path: str = "backend/scenarios/multi_stage_exfiltration.pcap") -> str:
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    try:
        from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, wrpcap, Raw
        # Try Scapy generation first
        packets = []
        base_time = time.time()
        current_time = base_time
        src_mac = "02:42:ac:11:00:02"
        dst_mac = "02:42:ac:11:00:01"
        src_ip = "10.0.1.55"

        # Stage 1: Recon
        for port in [21, 22, 23, 80, 443, 445, 3389, 8080]:
            sport = random.randint(49152, 65535)
            syn_pkt = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst="192.168.1.10") / TCP(sport=sport, dport=port, flags="S", seq=1000)
            syn_pkt.time = current_time
            packets.append(syn_pkt)
            current_time += 0.05
            rst_pkt = Ether(src=dst_mac, dst=src_mac) / IP(src="192.168.1.10", dst=src_ip) / TCP(sport=port, dport=sport, flags="R", seq=0, ack=1001)
            rst_pkt.time = current_time
            packets.append(rst_pkt)
            current_time += 0.10

        current_time += 2.0

        # Stage 2: C2 Beacon
        for beacon_idx in range(12):
            payload = b"\x17\x03\x03\x00\x40" + bytes([random.randint(0, 255) for _ in range(60)])
            pkt_fwd = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst="91.195.240.117") / TCP(sport=52344, dport=443, flags="PA", seq=1000 + beacon_idx * 70, ack=5000) / Raw(load=payload)
            pkt_fwd.time = current_time
            packets.append(pkt_fwd)
            current_time += 2.00

        current_time += 2.0

        # Stage 3: DNS Tunnel
        tunnel_chunks = [
            "a9f8b7c6d5e4f3a2b1c0d9e8f7a6b5c4.exfil.tunnel.evil.com",
            "ff887766554433221100aabbccddeeff.exfil.tunnel.evil.com",
            "99887766554433221100112233445566.exfil.tunnel.evil.com",
            "7766554433221100aabbccddeeff9988.exfil.tunnel.evil.com",
            "554433221100aabbccddeeff99887766.exfil.tunnel.evil.com",
        ]
        for chunk in tunnel_chunks:
            padding = bytes([random.randint(0, 255) for _ in range(150)])
            dns_req = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst="8.8.8.8") / UDP(sport=41233, dport=53) / DNS(rd=1, qd=DNSQR(qname=chunk)) / Raw(load=padding)
            dns_req.time = current_time
            packets.append(dns_req)
            current_time += 0.15

        current_time += 2.0

        # Stage 4: Data Exfil
        exfil_payload = bytes([random.randint(0, 255) for _ in range(1400)])
        for pkt_i in range(50):
            pkt_out = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst="198.51.100.45") / TCP(sport=61200, dport=8443, flags="PA", seq=10000 + pkt_i * 1400, ack=2000) / Raw(load=exfil_payload)
            pkt_out.time = current_time
            packets.append(pkt_out)
            current_time += 0.02
        pkt_ack = Ether(src=dst_mac, dst=src_mac) / IP(src="198.51.100.45", dst=src_ip) / TCP(sport=8443, dport=61200, flags="A", seq=2000, ack=10000 + 50 * 1400)
        pkt_ack.time = current_time + 0.01
        packets.append(pkt_ack)

        wrpcap(output_path, packets)
    except Exception as scapy_err:
        # Fallback to pure python PCAP generator
        raw_pcap = build_pcap_bytes_pure_python()
        with open(output_path, "wb") as f:
            f.write(raw_pcap)

    return output_path

if __name__ == "__main__":
    out = generate_multi_stage_pcap()
    print(f"Generated multi-stage attack PCAP at: {out}")

