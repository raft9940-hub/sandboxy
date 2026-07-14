# Sandboxy 🧪

Sandboxy is a lightweight Linux utility that runs applications inside a strictly isolated network namespace while sniffing and logging all network activity (including DNS queries, HTTP host headers, TLS SNI handshakes, and raw TCP/UDP packets). It features an interactive live TUI dashboard and post-run structured log generation for behavior analysis.

---

## ⚠️ CRITICAL SECURITY WARNING

> [!WARNING]
> **Sandboxy is a NETWORK isolation tool only.**
> * It does **not** isolate the filesystem, running processes, CPU/memory, or other Linux namespaces.
> * Any command or binary executed inside Sandboxy runs directly on your host filesystem and processes. If you run untrusted or destructive malware inside Sandboxy, it can still compromise, encrypt, or delete files on your machine.
> * **Always run Sandboxy inside a Linux Virtual Machine (VM)** when analyzing actual untrusted binaries, malware, or suspicious programs. Do not run them on your primary host system.

---

## Features

* **Strict Network Isolation:** Spawns commands inside a custom Linux network namespace (`sandboxy_ns`) using a virtual ethernet (`veth`) pair.
* **Dual IPv4 and IPv6 Support:** Routes both IPv4 (`10.200.1.0/24`) and IPv6 (`fd00::/64`) traffic to the internet via local gateway NAT routing (`iptables` / `ip6tables`).
* **Offline / Air-Gapped Mode:** Disable outbound NAT routing completely to run malware in a strictly local, air-gapped environment.
* **Deep Packet Inspection (DPI):** Sniffs `veth_host` via raw packet sockets (`AF_PACKET`) to decode:
  * **DNS Queries & Answers:** Both IPv4 (A) and IPv6 (AAAA) lookups.
  * **HTTP Traffic:** Extracts plaintext `Host` headers.
  * **HTTPS/TLS Traffic:** Extracts Server Name Indication (SNI) from the Client Hello handshake.
  * **TCP & UDP Beacons:** Displays TCP flags (SYN, FIN, RST) and UDP traffic payloads.
* **Live TUI Dashboard:** Real-time terminal UI showing statistics, chronological timeline events, and standard output/error streams of the sandboxed app.
* **Forensic JSON Reports:** Outputs raw event streams to `sandboxy_raw.json` and structured, aggregated behavior profiles to `sandboxy_summary.json`.

---

## Prerequisites

Sandboxy requires standard Linux networking commands and root access to manage network namespaces and firewall rules.

* **Operating System:** Linux
* **Python Version:** Python 3.6+
* **System Utilities:**
  * `iproute2` (for `ip netns`, `ip link`, etc.)
  * `iptables` & `ip6tables` (for NAT masquerading rules)
  * `sudo` / Root access (required to configure interfaces and raw sockets)

---

## Quick Start

### 1. Interactive Terminal Mode
Spawn an isolated shell inside the network namespace. Any command run inside this shell will be isolated and logged:
```bash
sudo python3 sandboxy.py
```

### 2. Run a Specific Command
Run a specific command (such as a python script, curl command, or executable) directly and monitor its output:
```bash
sudo python3 sandboxy.py run "python3 demo.py"
```

### 3. Air-Gapped/Offline Mode
Isolate an application entirely from the internet (loopback and internal host routing only):
```bash
sudo python3 sandboxy.py run --offline "python3 demo.py"
```

### 4. Analyze Log Files
Compile a clean human-readable network report from a previous run's log file (does **not** require root permissions):
```bash
python3 sandboxy.py analyze sandboxy_raw.json
```

---

## Simulation Demo
The repository contains a `demo.py` script that simulates typical steps a malware payload might perform (C2 DNS resolutions, HTTP checks, HTTPS connections, raw TCP reverse shells, and UDP exfiltration beacons over both IPv4 and IPv6).

To see Sandboxy in action:
```bash
sudo python3 sandboxy.py run "python3 demo.py"
```

---

## How It Works Under the Hood

```
                    +------------------------------------+
                    |             HOST SYSTEM            |
                    |                                    |
                    |   [ Raw Packet Socket Sniffer ]    |
                    |                 |                  |
                    |            veth_host               |
                    |          (10.200.1.1)              |
                    |            (fd00::1)               |
                    +-----------------+------------------+
                                      |
                             [ Virtual VETH Tunnel ]
                                      |
                    +-----------------+------------------+
                    |        sandboxy_ns NAMESPACE       |
                    |                                    |
                    |             veth_ns                |
                    |          (10.200.1.2)              |
                    |            (fd00::2)               |
                    |                                    |
                    |    [ Isolated Application Process ]|
                    +------------------------------------+
```

1. **Namespace Creation:** Creates a new network namespace called `sandboxy_ns`.
2. **Tunnel Configuration:** Establishes a virtual ethernet pair (`veth_host` on the host side, `veth_ns` inside the namespace).
3. **Addressing & Routing:** Configures host/guest IPs and routes default traffic for both IPv4 and IPv6 inside the namespace back to the host veth interface.
4. **NAT Masquerading:** Automatically detects the host's active internet-facing network interface and appends `iptables`/`ip6tables` MASQUERADE rules.
5. **Raw Sniffing:** Spawns a background thread listening on `veth_host` using a raw socket (`socket.AF_PACKET`, `socket.SOCK_RAW`). The packet filter ignores non-IP traffic and decodes standard application headers in real-time.
