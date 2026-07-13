#!/usr/bin/env python3
import os
import sys
import time
import argparse
import subprocess
import socket
import struct
import select
import signal
import json
import threading
from datetime import datetime

# Terminate codes for colorful console prints
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
C_CYAN = "\033[36m"
C_WHITE = "\033[37m"

# Override built-in print to prevent the "staircase effect" in TUI mode
_builtin_print = print

def print(*args, **kwargs):
    sep = kwargs.get("sep", " ")
    end = kwargs.get("end", "\n")
    file = kwargs.get("file", sys.stdout)
    
    if tui_active and (file is sys.stdout or file is sys.stderr):
        text = sep.join(str(arg) for arg in args)
        t_end = "\r\n" if end == "\n" else end
        lines = text.split("\n")
        for i, line in enumerate(lines):
            line_end = t_end if i == len(lines) - 1 else "\r\n"
            sys.stdout.write(f"\r{line}{line_end}")
        sys.stdout.flush()
    else:
        _builtin_print(*args, **kwargs)

NS_NAME = "sandboxy_ns"
VETH_HOST = "veth_host"
VETH_NS = "veth_ns"
HOST_IP = "10.200.1.1"
NS_IP = "10.200.1.2"
SUBNET_MASK = "255.255.255.0"
CIDR = "10.200.1.0/24"

# Global flags for signal cleanup
cleanup_needed = False
active_interface = None
offline_mode = False

# Thread safety and statistics for Live Dashboard
list_lock = threading.Lock()
stats = {"packets": 0, "dns": 0, "tls": 0, "http": 0, "tcp": 0, "udp": 0}
latest_events = []
all_raw_events = []

# Logging handles and files
raw_log_handle = None
raw_log_path = None
summary_log_path = None
tui_active = False

def clear_screen():
    sys.stdout.write("\r\033[H\033[J")
    sys.stdout.flush()

def reset_stats():
    global stats, latest_events, all_raw_events
    with list_lock:
        stats = {"packets": 0, "dns": 0, "tls": 0, "http": 0, "tcp": 0, "udp": 0}
        latest_events = []
        all_raw_events = []

def log_event(event_type, source_ip, source_port, dest_ip, dest_port, message, extra=None):
    timestamp = datetime.now().isoformat()
    color = C_RESET
    if event_type == "DNS":
        color = C_GREEN
    elif event_type == "TLS/HTTPS":
        color = C_CYAN
    elif event_type == "HTTP":
        color = C_YELLOW
    elif event_type == "TCP":
        color = C_MAGENTA
    elif event_type == "UDP":
        color = C_BLUE
    elif event_type == "ERROR":
        color = C_RED

    console_msg = f"{C_BOLD}[{timestamp.split('T')[1][:12]}]{C_RESET} {color}[{event_type}]{C_RESET} {source_ip}:{source_port} -> {dest_ip}:{dest_port} | {message}"
    
    # Store locally for the Live Dashboard timeline and final summary compilation
    with list_lock:
        # Increment stats counters
        stats["packets"] += 1
        if event_type == "DNS":
            stats["dns"] += 1
        elif event_type == "TLS/HTTPS":
            stats["tls"] += 1
        elif event_type == "HTTP":
            stats["http"] += 1
        elif event_type == "TCP" and extra and extra.get("tcp_flag") == "SYN":
            stats["tcp"] += 1
        elif event_type == "UDP" and dest_port != 53:
            stats["udp"] += 1
            
        latest_events.append(console_msg)
        if len(latest_events) > 15:
            latest_events.pop(0)
            
        # Keep copy of raw log structure in memory
        log_data = {
            "timestamp": timestamp,
            "type": event_type,
            "src_ip": source_ip,
            "src_port": source_port,
            "dst_ip": dest_ip,
            "dst_port": dest_port,
            "info": message
        }
        if extra:
            log_data["details"] = extra
        all_raw_events.append(log_data)

    # Print to console ONLY if TUI Live Dashboard is not active to prevent UI corruption
    if not tui_active:
        print(console_msg)
        sys.stdout.flush()

    # Write to raw JSON file if enabled
    if raw_log_handle:
        try:
            raw_log_handle.write(json.dumps(log_data) + "\n")
            raw_log_handle.flush()
        except Exception:
            pass

def compile_and_write_summary():
    """Generates the collapsed structured JSON analysis report at the end of the session."""
    if not summary_log_path:
        return
        
    print(f"\n{C_BLUE}[*] Compiling analysis summary...{C_RESET}")
    
    ip_domains = {}
    with list_lock:
        events = list(all_raw_events)
        
    for ev in events:
        dst_ip = ev.get("dst_ip")
        t = ev.get("type")
        details = ev.get("details", {})
        if not dst_ip or dst_ip == "-":
            continue
        
        domain = details.get("tls_sni") or details.get("http_host")
        if domain:
            if dst_ip not in ip_domains:
                ip_domains[dst_ip] = set()
            ip_domains[dst_ip].add(domain)
            
    # Compile unique hosts
    unique_hosts = []
    seen_unique = set()
    for ev in events:
        t = ev.get("type")
        dst_ip = ev.get("dst_ip")
        dst_port = ev.get("dst_port")
        details = ev.get("details", {})
        
        domain = details.get("tls_sni") or details.get("http_host")
        if domain:
            host_key = (t, domain, dst_port)
            if host_key not in seen_unique:
                seen_unique.add(host_key)
                unique_hosts.append({
                    "protocol": "HTTPS" if t == "TLS/HTTPS" else "HTTP",
                    "host": domain,
                    "ip": dst_ip,
                    "port": dst_port
                })
        elif t in ("TCP", "UDP") and dst_ip != "-" and dst_port != 53:
            domains = ip_domains.get(dst_ip, set())
            if not domains:
                host_key = (t, dst_ip, dst_port)
                if host_key not in seen_unique:
                    seen_unique.add(host_key)
                    unique_hosts.append({
                        "protocol": t,
                        "host": dst_ip,
                        "ip": dst_ip,
                        "port": dst_port
                    })
                    
    # Compile chronological timeline (collapsed)
    timeline = []
    seen_flows = set()
    for ev in events:
        t = ev.get("type")
        dst = ev.get("dst_ip")
        dst_port = ev.get("dst_port")
        ts = ev.get("timestamp")
        details = ev.get("details", {})
        
        if t == "DNS":
            domain = details.get("dns_domain", "")
            action = details.get("dns_action", "")
            flow_key = ("DNS", domain, action)
            if flow_key not in seen_flows:
                seen_flows.add(flow_key)
                timeline.append({
                    "timestamp": ts,
                    "type": "DNS",
                    "description": f"DNS {action} for {domain}"
                })
        elif t in ("TLS/HTTPS", "HTTP"):
            domain = details.get("tls_sni") or details.get("http_host")
            flow_key = (t, domain, dst)
            if flow_key not in seen_flows:
                seen_flows.add(flow_key)
                proto_label = "HTTPS" if t == "TLS/HTTPS" else "HTTP"
                timeline.append({
                    "timestamp": ts,
                    "type": proto_label,
                    "description": f"Connection established to {domain} ({dst}:{dst_port})"
                })
        elif t in ("TCP", "UDP"):
            domains = ip_domains.get(dst, set())
            dst_label = f"{', '.join(domains)} ({dst})" if domains else dst
            flag = details.get("tcp_flag", "")
            if flag == "SYN":
                flow_key = ("TCP_CONNECT", dst_label, dst_port)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    timeline.append({
                        "timestamp": ts,
                        "type": "TCP_CONN",
                        "description": f"TCP handshake initiated with {dst_label}:{dst_port}"
                    })
            elif t == "UDP" and dst_port != 53:
                flow_key = ("UDP_FLOW", dst_label, dst_port)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    timeline.append({
                        "timestamp": ts,
                        "type": "UDP",
                        "description": f"UDP traffic sent to {dst_label}:{dst_port}"
                    })
                    
    report = {
        "timestamp_generated": datetime.now().isoformat(),
        "total_packets_logged": len(events),
        "unique_destinations": unique_hosts,
        "timeline_workflow": timeline
    }
    
    try:
        with open(summary_log_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"{C_GREEN}[+] Structured analysis report successfully written to: {summary_log_path}{C_RESET}")
    except Exception as e:
        print(f"{C_RED}[!] Error writing analysis report: {e}{C_RESET}")

def run_cmd(cmd, check=True):
    """Helper to run a shell command."""
    try:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if check and res.returncode != 0:
            raise RuntimeError(f"Command '{cmd}' failed with exit code {res.returncode}. Stderr: {res.stderr.strip()}")
        return res
    except Exception as e:
        if check:
            raise
        return None

def detect_active_interface():
    """Finds the host's active internet routing interface."""
    res = run_cmd("ip route show | grep default", check=False)
    if res and res.returncode == 0:
        parts = res.stdout.split()
        try:
            dev_idx = parts.index("dev")
            return parts[dev_idx + 1]
        except (ValueError, IndexError):
            pass
    return None

def setup_network(offline=False):
    global cleanup_needed, active_interface, offline_mode
    offline_mode = offline
    print(f"{C_BOLD}{C_BLUE}[*] Setting up network namespace: {NS_NAME}{C_RESET}")
    
    # 1. Create network namespace
    run_cmd(f"ip netns add {NS_NAME}")
    cleanup_needed = True

    # 2. Create virtual ethernet (veth) pair
    run_cmd(f"ip link add {VETH_HOST} type veth peer name {VETH_NS}")

    # 3. Move veth_ns to netns
    run_cmd(f"ip link set {VETH_NS} netns {NS_NAME}")

    # 4. Set host interface IP and bring it up
    run_cmd(f"ip addr add {HOST_IP}/24 dev {VETH_HOST}")
    run_cmd(f"ip link set {VETH_HOST} up")

    # 5. Set guest interfaces inside netns up
    run_cmd(f"ip netns exec {NS_NAME} ip link set lo up")
    run_cmd(f"ip netns exec {NS_NAME} ip addr add {NS_IP}/24 dev {VETH_NS}")
    run_cmd(f"ip netns exec {NS_NAME} ip link set {VETH_NS} up")

    # 6. Add default routing inside netns pointing to host IP
    run_cmd(f"ip netns exec {NS_NAME} ip route add default via {HOST_IP}")

    # 7. Configure nameserver for the netns
    os.makedirs(f"/etc/netns/{NS_NAME}", exist_ok=True)
    with open(f"/etc/netns/{NS_NAME}/resolv.conf", "w") as f:
        f.write("nameserver 1.1.1.1\nnameserver 8.8.8.8\n")

    # 8. Setup Internet Access via NAT/iptables if not offline
    if not offline:
        active_interface = detect_active_interface()
        if active_interface:
            print(f"{C_BLUE}[*] Routing namespace traffic through internet interface: {active_interface}{C_RESET}")
            # Enable IP forwarding
            run_cmd("sysctl -w net.ipv4.ip_forward=1")
            # Setup masquerade (both iptables / nftables check)
            run_cmd(f"iptables -t nat -A POSTROUTING -s {CIDR} -o {active_interface} -j MASQUERADE")
            run_cmd(f"iptables -A FORWARD -i {active_interface} -o {VETH_HOST} -m state --state RELATED,ESTABLISHED -j ACCEPT")
            run_cmd(f"iptables -A FORWARD -i {VETH_HOST} -o {active_interface} -j ACCEPT")
        else:
            print(f"{C_YELLOW}[!] Warning: No active internet interface detected. Internet access might be unavailable.{C_RESET}")

def cleanup():
    global cleanup_needed, active_interface, raw_log_handle
    if not cleanup_needed:
        return
    print(f"\n{C_BOLD}{C_BLUE}[*] Cleaning up network resources...{C_RESET}")

    # 1. Clean up resolv.conf directory for namespace
    run_cmd(f"rm -rf /etc/netns/{NS_NAME}", check=False)

    # 2. Delete iptables NAT/forwarding rules if active_interface was set
    if active_interface:
        run_cmd(f"iptables -t nat -D POSTROUTING -s {CIDR} -o {active_interface} -j MASQUERADE", check=False)
        run_cmd(f"iptables -D FORWARD -i {active_interface} -o {VETH_HOST} -m state --state RELATED,ESTABLISHED -j ACCEPT", check=False)
        run_cmd(f"iptables -D FORWARD -i {VETH_HOST} -o {active_interface} -j ACCEPT", check=False)

    # 3. Delete netns (this also automatically removes veth_host and veth_ns)
    run_cmd(f"ip netns delete {NS_NAME}", check=False)

    if raw_log_handle:
        try:
            raw_log_handle.close()
        except Exception:
            pass
        raw_log_handle = None

    cleanup_needed = False
    print(f"{C_BOLD}{C_GREEN}[*] Cleanup complete.{C_RESET}")

def parse_dns_question(payload, offset):
    """Simple parser for DNS queries within a payload starting at offset."""
    try:
        if len(payload) < offset + 12:
            return None
        
        qdcount = struct.unpack("!H", payload[offset+4:offset+6])[0]
        if qdcount == 0:
            return None
        
        curr = offset + 12
        labels = []
        while curr < len(payload):
            length = payload[curr]
            if length == 0:
                curr += 1
                break
            if (length & 0xC0) == 0xC0:
                break
            if curr + 1 + length > len(payload):
                break
            label = payload[curr+1:curr+1+length].decode('utf-8', errors='ignore')
            labels.append(label)
            curr += 1 + length
        
        domain = ".".join(labels)
        if len(payload) >= curr + 4:
            qtype, qclass = struct.unpack("!HH", payload[curr:curr+4])
            type_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 2: "NS"}
            qtype_str = type_map.get(qtype, f"TYPE-{qtype}")
            return f"{domain} ({qtype_str})"
        return domain
    except Exception:
        return None

def parse_tls_sni(payload, offset):
    """Simple parser for TLS SNI (Server Name Indication) in Client Hello."""
    try:
        data = payload[offset:]
        if len(data) < 5:
            return None
        
        content_type = data[0]
        if content_type != 22: # Handshake record
            return None
        
        record_len = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + record_len:
            return None
            
        handshake_data = data[5:5+record_len]
        if len(handshake_data) < 4:
            return None
            
        handshake_type = handshake_data[0]
        if handshake_type != 1: # Client Hello
            return None
            
        curr = 38
        if curr >= len(handshake_data):
            return None
        session_id_len = handshake_data[curr]
        curr += 1 + session_id_len
        
        if curr + 2 > len(handshake_data):
            return None
        cipher_suites_len = struct.unpack("!H", handshake_data[curr:curr+2])[0]
        curr += 2 + cipher_suites_len
        
        if curr + 1 > len(handshake_data):
            return None
        comp_methods_len = handshake_data[curr]
        curr += 1 + comp_methods_len
        
        if curr + 2 > len(handshake_data):
            return None
        extensions_len = struct.unpack("!H", handshake_data[curr:curr+2])[0]
        curr += 2
        
        ext_end = curr + extensions_len
        if ext_end > len(handshake_data):
            return None
            
        while curr + 4 <= ext_end:
            ext_type, ext_len = struct.unpack("!HH", handshake_data[curr:curr+4])
            curr += 4
            if curr + ext_len > ext_end:
                break
            
            if ext_type == 0: # Server Name Indication
                sni_data = handshake_data[curr:curr+ext_len]
                if len(sni_data) < 2:
                    break
                sni_list_len = struct.unpack("!H", sni_data[0:2])[0]
                inner_curr = 2
                while inner_curr + 3 <= 2 + sni_list_len:
                    name_type = sni_data[inner_curr]
                    name_len = struct.unpack("!H", sni_data[inner_curr+1:inner_curr+3])[0]
                    inner_curr += 3
                    if inner_curr + name_len > len(sni_data):
                        break
                    if name_type == 0: # host_name
                        hostname = sni_data[inner_curr:inner_curr+name_len].decode('utf-8', errors='ignore')
                        return hostname
                    inner_curr += name_len
            curr += ext_len
    except Exception:
        pass
    return None

def parse_http_host(payload, offset):
    """Simple parser for HTTP Host header in plain HTTP payloads."""
    try:
        data = payload[offset:]
        methods = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"OPTIONS ", b"DELETE ", b"CONNECT "]
        is_http = any(data.startswith(m) for m in methods)
        if not is_http:
            return None
            
        lines = data.split(b"\r\n")
        for line in lines:
            if line.lower().startswith(b"host:"):
                host = line[5:].strip().decode('utf-8', errors='ignore')
                return host
    except Exception:
        pass
    return None

def sniffer_loop(stop_event):
    """Background sniffer loop capturing from veth_host using raw packet socket."""
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        sock.bind((VETH_HOST, 0))
        sock.setblocking(False)
    except PermissionError:
        log_event("ERROR", "-", "-", "-", "-", "Sniffer requires root permissions to open raw socket.")
        return
    except Exception as e:
        log_event("ERROR", "-", "-", "-", "-", f"Failed to initialize raw socket: {e}")
        return

    while not stop_event.is_set():
        ready_to_read, _, _ = select.select([sock], [], [], 0.2)
        if not ready_to_read:
            continue

        try:
            packet, _ = sock.recvfrom(65535)
        except Exception:
            continue

        if len(packet) < 14:
            continue
        eth_header = struct.unpack("!6s6sH", packet[:14])
        eth_proto = eth_header[2]
        if eth_proto != 0x0800:
            continue # Only monitor IPv4

        ip_header_start = 14
        if len(packet) < ip_header_start + 20:
            continue
        ip_header = struct.unpack("!BBHHHBBH4s4s", packet[ip_header_start:ip_header_start+20])
        version_ihl = ip_header[0]
        ihl = version_ihl & 0x0F
        iph_length = ihl * 4
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dst_ip = socket.inet_ntoa(ip_header[9])

        payload_offset = ip_header_start + iph_length

        if protocol == 17: # UDP
            udp_header_start = payload_offset
            if len(packet) < udp_header_start + 8:
                continue
            udp_header = struct.unpack("!HHHH", packet[udp_header_start:udp_header_start+8])
            src_port = udp_header[0]
            dst_port = udp_header[1]
            udp_len = udp_header[2]
            
            udp_payload_offset = udp_header_start + 8
            
            if src_port == 53 or dst_port == 53:
                dns_query = parse_dns_question(packet, udp_payload_offset)
                if dns_query:
                    action = "Query" if dst_port == 53 else "Response"
                    log_event("DNS", src_ip, src_port, dst_ip, dst_port, f"DNS {action}: {dns_query}", {"dns_domain": dns_query, "dns_action": action})
                else:
                    log_event("UDP", src_ip, src_port, dst_ip, dst_port, "DNS/UDP query payload (unparsed)")
            else:
                log_event("UDP", src_ip, src_port, dst_ip, dst_port, f"UDP Packet ({udp_len - 8} bytes payload)")

        elif protocol == 6: # TCP
            tcp_header_start = payload_offset
            if len(packet) < tcp_header_start + 20:
                continue
            tcp_header = struct.unpack("!HHLLBBHHH", packet[tcp_header_start:tcp_header_start+20])
            src_port = tcp_header[0]
            dst_port = tcp_header[1]
            data_offset = (tcp_header[4] >> 4) * 4
            
            tcp_payload_offset = tcp_header_start + data_offset
            
            if len(packet) > tcp_payload_offset:
                http_host = parse_http_host(packet, tcp_payload_offset)
                if http_host:
                    log_event("HTTP", src_ip, src_port, dst_ip, dst_port, f"HTTP Request Host: {http_host}", {"http_host": http_host})
                    continue

                tls_sni = parse_tls_sni(packet, tcp_payload_offset)
                if tls_sni:
                    log_event("TLS/HTTPS", src_ip, src_port, dst_ip, dst_port, f"TLS Client Hello SNI: {tls_sni}", {"tls_sni": tls_sni})
                    continue

            flags = tcp_header[5]
            syn_flag = (flags & 0x02) > 0
            fin_flag = (flags & 0x01) > 0
            rst_flag = (flags & 0x04) > 0
            
            if syn_flag:
                log_event("TCP", src_ip, src_port, dst_ip, dst_port, "Connection Initiate (SYN)", {"tcp_flag": "SYN"})
            elif fin_flag:
                log_event("TCP", src_ip, src_port, dst_ip, dst_port, "Connection Terminate (FIN)", {"tcp_flag": "FIN"})
            elif rst_flag:
                log_event("TCP", src_ip, src_port, dst_ip, dst_port, "Connection Reset (RST)", {"tcp_flag": "RST"})

def handle_sigint(signum, frame):
    sys.exit(0)

def analyze_log(log_path):
    if not os.path.exists(log_path):
        print(f"{C_BOLD}{C_RED}[!] Error: Log file '{log_path}' not found.{C_RESET}")
        return

    # Check if this is a structured analysis report or raw JSON lines
    events = []
    is_structured_report = False
    
    with open(log_path, "r", encoding="utf-8") as f:
        # Check first line to see if it is raw jsonl or a structured report
        first_line = f.readline().strip()
        f.seek(0)
        
        if first_line.startswith("{") and not first_line.endswith("}"):
            # Multi-line JSON (probably structured summary)
            try:
                report_data = json.load(f)
                is_structured_report = True
            except Exception:
                f.seek(0)
        
        if not is_structured_report:
            # Parse line by line
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except Exception:
                    pass

    # If it is a structured report, print it beautifully
    if is_structured_report:
        print_structured_report(report_data, log_path)
        return

    if not events:
        print(f"{C_BOLD}{C_YELLOW}[!] No valid log events found in '{log_path}'.{C_RESET}")
        return

    # Process and build tables
    ip_domains = {}
    for ev in events:
        dst_ip = ev.get("dst_ip")
        t = ev.get("type")
        details = ev.get("details", {})
        if not dst_ip or dst_ip == "-":
            continue
        
        domain = details.get("tls_sni") or details.get("http_host")
        if domain:
            if dst_ip not in ip_domains:
                ip_domains[dst_ip] = set()
            ip_domains[dst_ip].add(domain)

    timeline = []
    seen_flows = set()
    
    for ev in events:
        t = ev.get("type")
        src = ev.get("src_ip")
        dst = ev.get("dst_ip")
        dst_port = ev.get("dst_port")
        info = ev.get("info", "")
        ts = ev.get("timestamp")
        details = ev.get("details", {})
        
        try:
            dt = datetime.fromisoformat(ts)
            ts_short = dt.strftime("%H:%M:%S.%f")[:-3]
        except Exception:
            ts_short = ts

        if t == "DNS":
            domain = details.get("dns_domain", "")
            action = details.get("dns_action", "")
            flow_key = ("DNS", domain, action)
            if flow_key not in seen_flows:
                seen_flows.add(flow_key)
                timeline.append({
                    "time": ts_short,
                    "type": "DNS",
                    "desc": f"DNS {action} for {domain}"
                })
        elif t in ("TLS/HTTPS", "HTTP"):
            domain = details.get("tls_sni") or details.get("http_host")
            flow_key = (t, domain, dst)
            if flow_key not in seen_flows:
                seen_flows.add(flow_key)
                proto_label = "HTTPS (TLS)" if t == "TLS/HTTPS" else "HTTP"
                timeline.append({
                    "time": ts_short,
                    "type": t,
                    "desc": f"Established {proto_label} connection to {domain} ({dst}:{dst_port})"
                })
        elif t in ("TCP", "UDP"):
            domains = ip_domains.get(dst, set())
            dst_label = f"{', '.join(domains)} ({dst})" if domains else dst
            
            flag = details.get("tcp_flag", "")
            if flag == "SYN":
                flow_key = ("TCP_CONNECT", dst_label, dst_port)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    timeline.append({
                        "time": ts_short,
                        "type": "TCP_CONN",
                        "desc": f"Initiated TCP connection to {dst_label}:{dst_port}"
                    })
            elif t == "UDP" and dst_port != 53:
                flow_key = ("UDP_FLOW", dst_label, dst_port)
                if flow_key not in seen_flows:
                    seen_flows.add(flow_key)
                    timeline.append({
                        "time": ts_short,
                        "type": "UDP",
                        "desc": f"Sent UDP traffic to {dst_label}:{dst_port}"
                    })

    print(f"\n{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
    print(f"{C_BOLD}{C_GREEN}                   SANDBOXY NETWORK ANALYSIS REPORT{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
    print(f"Log File: {log_path}")
    print(f"Total Logged Packets/Events: {len(events)}")
    print(f"Unique Host Destinations Contacted: {len(ip_domains)}")
    print(f"{C_BOLD}{C_CYAN}----------------------------------------------------------------------{C_RESET}")

    print(f"\n{C_BOLD}{C_YELLOW}[*] UNIQUE HOSTS & DOMAINS CONTACTED:{C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{'Protocol':<12} | {'Domain/Host / Destination IP':<45} | {'Port':<6}{C_RESET}")
    print("-" * 70)
    
    unique_hosts_printed = set()
    for ev in events:
        t = ev.get("type")
        dst_ip = ev.get("dst_ip")
        dst_port = ev.get("dst_port")
        details = ev.get("details", {})
        
        domain = details.get("tls_sni") or details.get("http_host")
        if domain:
            host_key = (t, domain, dst_port)
            if host_key not in unique_hosts_printed:
                unique_hosts_printed.add(host_key)
                proto_label = "HTTPS/TLS" if t == "TLS/HTTPS" else "HTTP"
                print(f"{proto_label:<12} | {domain:<45} | {dst_port:<6}")
        elif t in ("TCP", "UDP") and dst_ip != "-" and dst_port != 53:
            domains = ip_domains.get(dst_ip, set())
            if not domains:
                host_key = (t, dst_ip, dst_port)
                if host_key not in unique_hosts_printed:
                    unique_hosts_printed.add(host_key)
                    print(f"{t:<12} | {dst_ip:<45} | {dst_port:<6}")

    print(f"\n{C_BOLD}{C_YELLOW}[*] CHRONOLOGICAL NETWORK WORKFLOW TIMELINE:{C_RESET}")
    print("-" * 70)
    for step in timeline:
        color = C_RESET
        stype = step["type"]
        if stype == "DNS":
            color = C_GREEN
        elif stype == "TLS/HTTPS":
            color = C_CYAN
        elif stype == "HTTP":
            color = C_YELLOW
        elif stype == "TCP_CONN":
            color = C_MAGENTA
        elif stype == "UDP":
            color = C_BLUE
            
        print(f"[{step['time']}] {color}[{stype:<8}]{C_RESET} {step['desc']}")
        
    print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}\n")

def print_structured_report(report, log_path):
    """Outputs a summary based on a pre-generated structured JSON summary log file."""
    print(f"\n{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
    print(f"{C_BOLD}{C_GREEN}             SANDBOXY PRE-COMPILED ANALYSIS REPORT{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
    print(f"Log File: {log_path}")
    print(f"Report Generated At: {report.get('timestamp_generated')}")
    print(f"Total Logged Packets: {report.get('total_packets_logged')}")
    print(f"{C_BOLD}{C_CYAN}----------------------------------------------------------------------{C_RESET}")

    print(f"\n{C_BOLD}{C_YELLOW}[*] UNIQUE HOSTS & DOMAINS CONTACTED:{C_RESET}")
    print(f"{C_BOLD}{C_WHITE}{'Protocol':<12} | {'Domain/Host / IP Address':<45} | {'Port':<6}{C_RESET}")
    print("-" * 70)
    for host in report.get("unique_destinations", []):
        proto = host.get("protocol")
        domain = host.get("host")
        port = host.get("port")
        print(f"{proto:<12} | {domain:<45} | {port:<6}")

    print(f"\n{C_BOLD}{C_YELLOW}[*] CHRONOLOGICAL NETWORK WORKFLOW TIMELINE:{C_RESET}")
    print("-" * 70)
    for step in report.get("timeline_workflow", []):
        ts = step.get("timestamp")
        try:
            ts_short = ts.split("T")[1][:12]
        except Exception:
            ts_short = ts
        stype = step.get("type")
        color = C_RESET
        if stype == "DNS":
            color = C_GREEN
        elif stype == "HTTPS" or stype == "TLS/HTTPS":
            color = C_CYAN
        elif stype == "HTTP":
            color = C_YELLOW
        elif stype == "TCP_CONN" or stype == "TCP":
            color = C_MAGENTA
        elif stype == "UDP":
            color = C_BLUE
            
        print(f"[{ts_short}] {color}[{stype:<8}]{C_RESET} {step.get('description')}")
    print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}\n")

# Interactive TUI input helpers
def tui_get_input(prompt, default=None):
    prompt_str = f"\r{C_BOLD}{C_WHITE}{prompt}{C_RESET}"
    if default is not None:
        prompt_str += f" [{default}]: "
    else:
        prompt_str += ": "
    try:
        val = input(prompt_str).strip()
        if not val and default is not None:
            return default
        return val
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled.")
        return None

def tui_get_bool(prompt, default_val=True):
    default_str = "Y/n" if default_val else "y/N"
    res = tui_get_input(f"{prompt} ({default_str})")
    if res is None:
        return None
    if not res:
        return default_val
    return res.lower().startswith('y')

def show_tui():
    global tui_active
    tui_active = True
    while True:
        clear_screen()
        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
        print(f"{C_BOLD}{C_GREEN}    S A N D B O X Y  -  I s o l a t e d   P a c k e t   M o n i t o r{C_RESET}")
        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
        print(f"  {C_BOLD}{C_WHITE}[1]{C_RESET} Run Command in Network Sandbox")
        print(f"  {C_BOLD}{C_WHITE}[2]{C_RESET} Open Interactive Sandbox Shell")
        print(f"  {C_BOLD}{C_WHITE}[3]{C_RESET} Analyze / View Existing Log File")
        print(f"  {C_BOLD}{C_WHITE}[4]{C_RESET} Exit")
        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
        
        choice = tui_get_input("Choose Option (1-4)", "1")
        if choice is None or choice == "4":
            print("\nExiting Sandboxy. Goodbye!")
            break
            
        if choice not in ("1", "2", "3"):
            input(f"\n{C_RED}[!] Invalid Choice. Press Enter to retry...{C_RESET}")
            continue

        if choice == "3":
            # Analyze existing log
            log_to_read = tui_get_input("Enter log file path (e.g. run_http.json)")
            if log_to_read:
                clear_screen()
                analyze_log(log_to_read)
                input(f"{C_BOLD}{C_WHITE}Press Enter to return to menu...{C_RESET}")
            continue

        # Option 1 or 2: Configuring Sandbox network session
        is_shell = (choice == "2")
        cmd_to_run = None
        if not is_shell:
            cmd_to_run = tui_get_input("Enter command to execute (e.g., 'curl -I http://google.com')")
            if not cmd_to_run:
                input(f"\n{C_RED}[!] Command cannot be empty. Press Enter to retry...{C_RESET}")
                continue

        enable_net = tui_get_bool("Enable Internet Routing for the Sandbox?", True)
        if enable_net is None: continue
        is_offline = not enable_net

        # Logs outputs configuration
        global raw_log_path, summary_log_path, raw_log_handle
        raw_log_path = None
        summary_log_path = None
        raw_log_handle = None

        log_raw = tui_get_bool("Enable Raw packet JSONL logging?", True)
        if log_raw is None: continue
        if log_raw:
            raw_log_path = tui_get_input("Raw log filename", "sandboxy_raw.json")
            if not raw_log_path: continue

        log_summary = tui_get_bool("Enable Analyzed summary JSON logging?", True)
        if log_summary is None: continue
        if log_summary:
            summary_log_path = tui_get_input("Summary report filename", "sandboxy_summary.json")
            if not summary_log_path: continue

        # Begin Sandbox execution
        reset_stats()
        if raw_log_path:
            try:
                raw_log_handle = open(raw_log_path, "w", encoding="utf-8")
            except Exception as e:
                input(f"{C_RED}[!] Error opening raw log: {e}. Press Enter to retry...{C_RESET}")
                continue

        # Set up network namespace and iptables rules
        clear_screen()
        print(f"{C_BOLD}{C_BLUE}[*] Initializing network namespace environments...{C_RESET}")
        try:
            setup_network(offline=is_offline)
            
            # Start background sniffer
            stop_event = threading.Event()
            sniffer_thread = threading.Thread(target=sniffer_loop, args=(stop_event,), daemon=True)
            sniffer_thread.start()
            time.sleep(0.5)

            # Execution
            sudo_user = os.environ.get("SUDO_USER")
            gui_vars = ["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]
            env_prefix = " ".join(f"{var}={os.environ.get(var)}" for var in gui_vars if os.environ.get(var))
            if env_prefix:
                env_prefix += " "

            if is_shell:
                # Interactive shell session runs directly in terminal window without live stats dashboard
                clear_screen()
                print(f"{C_BOLD}{C_GREEN}[*] Launching interactive shell inside sandbox...{C_RESET}")
                print(f"{C_YELLOW}[!] Type 'exit' or press Ctrl+D to exit. Network logging is active in background.{C_RESET}\n")
                if sudo_user:
                    exec_cmd = f"ip netns exec {NS_NAME} sudo -u {sudo_user} {env_prefix}bash"
                else:
                    exec_cmd = f"ip netns exec {NS_NAME} {env_prefix}bash"
                    
                p = subprocess.Popen(exec_cmd, shell=True)
                p.wait()
                # Cure staircase effect and restore terminal settings after shell exits
                subprocess.run("stty sane", shell=True)
            else:
                # Run CLI/GUI command with redirection to log file and interactive dashboard update
                print(f"{C_BOLD}{C_GREEN}[*] Executing: {cmd_to_run}{C_RESET}\n")
                if sudo_user:
                    exec_cmd = f"ip netns exec {NS_NAME} sudo -u {sudo_user} {env_prefix}{cmd_to_run}"
                else:
                    exec_cmd = f"ip netns exec {NS_NAME} {env_prefix}{cmd_to_run}"

                # Redirect output so dashboard stays clean
                out_log = open("sandbox_output.log", "w", encoding="utf-8")
                p = subprocess.Popen(exec_cmd, shell=True, stdout=out_log, stderr=out_log)

                # Dashboard refresh loop
                net_mode = "OFFLINE" if is_offline else f"ONLINE (NAT via {active_interface or 'host'})"
                try:
                    # Hide terminal cursor to prevent TUI flickering
                    sys.stdout.write("\033[?25l")
                    sys.stdout.flush()
                    
                    while p.poll() is None:
                        # Draw Live TUI Dashboard
                        clear_screen()
                        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
                        print(f"{C_BOLD}{C_GREEN}                   SANDBOXY LIVE TRAFFIC MONITOR{C_RESET}")
                        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
                        print(f" Command: {C_BOLD}{C_WHITE}{cmd_to_run}{C_RESET}")
                        print(f" Status:  {C_GREEN}RUNNING (PID: {p.pid}){C_RESET}       Mode: {C_YELLOW}{net_mode}{C_RESET}")
                        print(f"{C_BOLD}{C_CYAN}----------------------------------------------------------------------{C_RESET}")
                        
                        with list_lock:
                            curr_stats = dict(stats)
                            curr_events = list(latest_events)
                            
                        print(f" Total Packets:  {C_BOLD}{curr_stats['packets']:<6}{C_RESET}      DNS Queries:    {C_GREEN}{curr_stats['dns']:<6}{C_RESET}")
                        print(f" HTTPS/TLS SNI:  {C_CYAN}{curr_stats['tls']:<6}{C_RESET}      HTTP Requests:  {C_YELLOW}{curr_stats['http']:<6}{C_RESET}")
                        print(f" TCP Syn Flows:  {C_MAGENTA}{curr_stats['tcp']:<6}{C_RESET}      UDP Raw:        {C_BLUE}{curr_stats['udp']:<6}{C_RESET}")
                        print(f"{C_BOLD}{C_CYAN}----------------------------------------------------------------------{C_RESET}")
                        print(f" Latest Intercepted Events:")
                        
                        # Print latest events
                        for ev in curr_events[-8:]:
                            print(f"  {ev}")
                        for _ in range(8 - len(curr_events[-8:])):
                            print()
                            
                        print(f"{C_BOLD}{C_CYAN}======================================================================{C_RESET}")
                        print(f" Output redirected to: sandbox_output.log")
                        print(f" Press Ctrl+C to terminate sandboxed process.")
                        sys.stdout.flush()
                        time.sleep(0.2)
                except KeyboardInterrupt:
                    print(f"\n{C_RED}[!] Force terminating active command...{C_RESET}")
                    p.terminate()
                    p.wait()
                finally:
                    # Restore terminal cursor visibility
                    sys.stdout.write("\033[?25h")
                    sys.stdout.flush()
                    out_log.close()
                    # Cure staircase effect and restore terminal settings after command finishes
                    subprocess.run("stty sane", shell=True)

            # Tear down monitoring threads
            stop_event.set()
            sniffer_thread.join(timeout=1.5)
            
            # Close raw log if active
            if raw_log_handle:
                raw_log_handle.close()
                raw_log_handle = None
                print(f"{C_GREEN}[+] Raw JSON log written to: {raw_log_path}{C_RESET}")

            # Compile analysis summary file if chosen
            if summary_log_path:
                compile_and_write_summary()
                
            input(f"\n{C_BOLD}{C_WHITE}Sandbox Session Complete. Press Enter to return to menu...{C_RESET}")

        except Exception as e:
            input(f"\n{C_RED}[!] Execution Error: {e}. Press Enter to return to menu...{C_RESET}")
        finally:
            cleanup()

def main():
    parser = argparse.ArgumentParser(description="Sandboxy: Isolate and monitor application network traffic.")
    subparsers = parser.add_subparsers(dest="command", required=False)

    # Sub-command run
    run_parser = subparsers.add_parser("run", help="Run a specific command in the isolated network namespace.")
    run_parser.add_argument("cmd", type=str, help="The command to execute (e.g., 'curl https://example.com' or 'firefox')")
    run_parser.add_argument("--offline", action="store_true", help="Completely disconnect the namespace from the internet.")
    run_parser.add_argument("--log", type=str, help="JSON log file path to record events.")

    # Sub-command shell
    shell_parser = subparsers.add_parser("shell", help="Launch an interactive bash session inside the isolated namespace.")
    shell_parser.add_argument("--offline", action="store_true", help="Completely disconnect the namespace from the internet.")
    shell_parser.add_argument("--log", type=str, help="JSON log file path to record events.")

    # Sub-command analyze
    analyze_parser = subparsers.add_parser("analyze", help="Analyze and summarize a network log file.")
    analyze_parser.add_argument("logfile", type=str, help="The JSON log file path to analyze.")

    args = parser.parse_args()

    # If no arguments passed, launch TUI Mode!
    if args.command is None:
        if os.getuid() != 0:
            print(f"{C_BOLD}{C_RED}[!] Error: Sandboxy must be run with root privileges (sudo) to launch TUI.{C_RESET}")
            sys.exit(1)
        show_tui()
        sys.exit(0)

    # If running analyze subcommand, root is NOT required
    if args.command == "analyze":
        analyze_log(args.logfile)
        sys.exit(0)

    # Command line run or shell commands require root
    if os.getuid() != 0:
        print(f"{C_BOLD}{C_RED}[!] Error: Sandboxy must be run with root privileges (sudo).{C_RESET}")
        sys.exit(1)

    global raw_log_path, raw_log_handle
    if args.log:
        raw_log_path = args.log
        try:
            raw_log_handle = open(raw_log_path, "w", encoding="utf-8")
            print(f"{C_BLUE}[*] Writing JSON log events to: {raw_log_path}{C_RESET}")
        except Exception as e:
            print(f"{C_BOLD}{C_RED}[!] Error opening log file: {e}{C_RESET}")
            sys.exit(1)

    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigint)

    try:
        setup_network(offline=args.offline)

        stop_event = threading.Event()
        sniffer_thread = threading.Thread(target=sniffer_loop, args=(stop_event,), daemon=True)
        sniffer_thread.start()
        time.sleep(0.5)

        if args.command == "run":
            print(f"{C_BOLD}{C_GREEN}[*] Executing in isolation: {args.cmd}{C_RESET}\n")
            sudo_user = os.environ.get("SUDO_USER")
            gui_vars = ["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]
            env_prefix = " ".join(f"{var}={os.environ.get(var)}" for var in gui_vars if os.environ.get(var))
            if env_prefix:
                env_prefix += " "
                
            if sudo_user:
                exec_cmd = f"ip netns exec {NS_NAME} sudo -u {sudo_user} {env_prefix}{args.cmd}"
            else:
                exec_cmd = f"ip netns exec {NS_NAME} {env_prefix}{args.cmd}"
            
            p = subprocess.Popen(exec_cmd, shell=True)
            p.wait()
            # Cure staircase effect and restore terminal settings after command exits
            subprocess.run("stty sane", shell=True)
            time.sleep(1)

        elif args.command == "shell":
            print(f"{C_BOLD}{C_GREEN}[*] Starting interactive shell inside isolated namespace...{C_RESET}")
            print(f"{C_YELLOW}[!] Type 'exit' or press Ctrl+D to terminate the sandbox session.{C_RESET}\n")
            
            sudo_user = os.environ.get("SUDO_USER")
            gui_vars = ["DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"]
            env_prefix = " ".join(f"{var}={os.environ.get(var)}" for var in gui_vars if os.environ.get(var))
            if env_prefix:
                env_prefix += " "
                
            if sudo_user:
                exec_cmd = f"ip netns exec {NS_NAME} sudo -u {sudo_user} {env_prefix}bash"
            else:
                exec_cmd = f"ip netns exec {NS_NAME} {env_prefix}bash"
                
            p = subprocess.Popen(exec_cmd, shell=True)
            p.wait()
            # Cure staircase effect and restore terminal settings after shell exits
            subprocess.run("stty sane", shell=True)
            time.sleep(1)

        stop_event.set()
        sniffer_thread.join(timeout=2)

    finally:
        cleanup()

if __name__ == "__main__":
    main()
