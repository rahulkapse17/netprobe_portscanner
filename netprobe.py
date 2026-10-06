#!/usr/bin/env python3
"""
=============================================================================
   NetProbe - Network Port Analysis & Server Discovery Suite  (single file)
   Team: Logic Link | Domain: Computer Networks & Cybersecurity
=============================================================================
   Scanner + LAN discovery + security risk analyzer in one script.
   Standard library only. Scan only systems you own or have permission to test.
=============================================================================
"""

import datetime
import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


SERVICES = {

    20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 69: "TFTP",
    115: "SFTP", 3389: "RDP", 5900: "VNC",

    25: "SMTP", 110: "POP3", 143: "IMAP", 465: "SMTPS", 587: "SMTP-Submission",
    993: "IMAPS", 995: "POP3S",

    80: "HTTP", 443: "HTTPS", 3000: "Node.js/React", 4200: "Angular Dev",
    5000: "Flask/Dev API", 5173: "Vite Dev", 8000: "HTTP-Dev",
    8008: "HTTP-Alt", 8080: "HTTP-Proxy/Alt", 8081: "HTTP-Alt/Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alternate", 9000: "SonarQube/PHP-FPM",

    53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 123: "NTP", 161: "SNMP",
    162: "SNMP-Trap", 389: "LDAP", 636: "LDAPS",

    88: "Kerberos", 135: "MSRPC", 137: "NetBIOS-Name", 138: "NetBIOS-Datagram",
    139: "NetBIOS-Session", 445: "SMB", 5040: "Windows RPC",
    5357: "WSDAPI", 7680: "WUDO (Delivery Opt.)",

    1433: "MS SQL Server", 1521: "Oracle DB", 3306: "MySQL/MariaDB",
    5432: "PostgreSQL", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB", 28017: "MongoDB Web",

    1883: "MQTT", 5672: "RabbitMQ", 9092: "Apache Kafka",
}

TOP_30_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433,
    1521, 3000, 3306, 3389, 5000, 5040, 5432, 6379, 7680, 8000, 8080, 8443,
    9092, 27017, 31337,
]
HTTP_PORTS = {80, 3000, 5000, 8000, 8080}
PROBE_PORTS = (80, 443, 445, 135, 22, 53, 8080)
PRESETS = {
    "1": TOP_30_PORTS,
    "2": range(1, 1025),
    "3": range(1, 10001),
    "5": range(1, 65536),
}


RISKS = {
    21: ("HIGH", "FTP sends passwords in plain text; use SFTP/FTPS"),
    23: ("HIGH", "Telnet is unencrypted; replace with SSH"),
    69: ("HIGH", "TFTP has no authentication"),
    445: ("HIGH", "SMB is a prime ransomware/worm target; block outside LAN"),
    3389: ("HIGH", "RDP is heavily brute-forced; use VPN + MFA"),
    5900: ("HIGH", "VNC is often weakly protected; tunnel it or disable"),
    1433: ("HIGH", "Database exposed to network; bind to localhost/firewall it"),
    1521: ("HIGH", "Database exposed to network; bind to localhost/firewall it"),
    3306: ("HIGH", "Database exposed to network; bind to localhost/firewall it"),
    5432: ("HIGH", "Database exposed to network; bind to localhost/firewall it"),
    6379: ("HIGH", "Redis is often unauthenticated; never expose it"),
    9200: ("HIGH", "Elasticsearch often has no auth; never expose it"),
    11211: ("HIGH", "Memcached has no auth and enables DDoS amplification"),
    27017: ("HIGH", "MongoDB exposed; enable auth and firewall it"),
    31337: ("HIGH", "Classic backdoor port; investigate immediately"),
    135: ("MEDIUM", "MSRPC exposes Windows internals; restrict to LAN"),
    139: ("MEDIUM", "NetBIOS leaks host/share info; disable if unused"),
    3000: ("MEDIUM", "Dev server; should not be reachable in production"),
    5000: ("MEDIUM", "Dev API server; should not be reachable in production"),
    8000: ("MEDIUM", "Dev server; should not be reachable in production"),
    8080: ("MEDIUM", "Alternate web/proxy port; check authentication"),
    80: ("LOW", "Unencrypted HTTP; redirect to HTTPS"),
    22: ("LOW", "SSH is fine with key auth and root login disabled"),
    443: ("INFO", "Encrypted web service; keep TLS up to date"),
}
RISK_POINTS = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def assess(port):
    return RISKS.get(port, ("INFO", "No known risk rule for this port"))


def overall_risk(open_ports):
    """Return (rating, score 0-100) for a list of open port numbers."""
    score = min(100, sum(RISK_POINTS[assess(p)[0]] for p in open_ports))
    levels = {assess(p)[0] for p in open_ports}
    rating = ("HIGH" if "HIGH" in levels else "MEDIUM" if "MEDIUM" in levels
              else "LOW" if "LOW" in levels else "NONE")
    return rating, score


def probe(ip, port, timeout=0.5):
    """Return 'open', 'closed' (RST received) or 'filtered' (timeout / no route)."""
    try:
        with socket.create_connection((ip, port), timeout):
            return "open"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "filtered"


def grab_banner(ip, port, timeout=0.6):
    """Read a service banner; returns a short printable string or ''."""
    try:
        with socket.create_connection((ip, port), timeout) as s:
            s.settimeout(timeout)
            if port in HTTP_PORTS:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
            try:
                data = s.recv(512)
            except socket.timeout:
                data = b""
            if not data and port not in HTTP_PORTS:
                s.sendall(b"\r\n")
                data = s.recv(512)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="ignore")
    for line in text.splitlines():
        if line.lower().startswith("server:"):
            return line.strip()
    runs = re.findall(r"[\x20-\x7e]{4,}", text)
    return runs[0][:60] if runs else ""


def build_report(target, ip, start, end, elapsed, results):
    """Single formatter used for both the screen and the saved file."""
    ts = "%Y-%m-%d %H:%M:%S"
    count = lambda st: sum(r[1] == st for r in results)
    lines = [
        "=" * 70,
        "   NetProbe - Network Port Analysis Report  (Team: Logic Link)",
        "=" * 70,
        f"Target        : {target} ({ip})",
        f"Scan Started  : {start.strftime(ts)}",
        f"Scan Finished : {end.strftime(ts)}",
        f"Duration      : {elapsed:.2f}s ({len(results) / max(elapsed, 0.001):.0f} ports/sec)",
        f"Scanned       : {len(results)}  | Open: {count('open')}  "
        f"Closed: {count('closed')}  Filtered: {count('filtered')}",
        "-" * 70,
        f"{'PORT':<7} {'STATE':<7} {'SERVICE':<18} {'RISK':<7} BANNER",
        "-" * 70,
    ]
    open_res = sorted(r for r in results if r[1] == "open")
    lines += [f"{p:<7} {st.upper():<7} {SERVICES.get(p, 'Unknown'):<18} {assess(p)[0]:<7} {b}"
              for p, st, b in open_res]
    rating, score = overall_risk([r[0] for r in open_res])
    lines += ["-" * 70, f"OVERALL RISK: {rating}  (score {score}/100)", "SECURITY FINDINGS:"]
    findings = sorted(open_res, key=lambda r: (SEVERITY_ORDER[assess(r[0])[0]], r[0]))
    lines += [f"  [{assess(p)[0]:<6}] port {p:<5} {assess(p)[1]}"
              for p, _, _ in findings if assess(p)[0] != "INFO"] or ["  No risky ports found."]
    lines.append("=" * 70)
    return "\n".join(lines)


def run_scan(target, ports, banners=True):
    """Multi-threaded TCP connect scan with report output."""
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[-] Could not resolve '{target}'.")
        return
    addr = ipaddress.ip_address(ip)
    if not (addr.is_private or addr.is_loopback):
        ok = input("[!] Public target. Do you own it or have permission to scan it? (y/n): ")
        if ok.strip().lower() != "y":
            print("[-] Scan cancelled.")
            return

    ports = list(ports)
    threads = 150 if len(ports) > 10000 else 100
    print(f"\n  Scanning {target} ({ip}) - {len(ports)} ports, {threads} threads...")

    def work(port):
        state = probe(ip, port)
        return port, state, grab_banner(ip, port) if state == "open" and banners else ""

    start, t0, results = datetime.datetime.now(), time.time(), []
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for fut in as_completed([ex.submit(work, p) for p in ports]):
            res = fut.result()
            results.append(res)
            if res[1] == "open":
                print(f"  [+] {res[0]:<6} OPEN  {SERVICES.get(res[0], 'Unknown'):<18} risk: {assess(res[0])[0]}")
    elapsed, end = time.time() - t0, datetime.datetime.now()

    report = build_report(target, ip, start, end, elapsed, results)
    print("\n" + report)
    fname = f"netprobe_report_{ip}_{start.strftime('%Y%m%d_%H%M%S')}.txt"
    try:
        with open(fname, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"[+] Report saved to {fname}")
    except OSError as e:
        print(f"[-] Could not save report: {e}")


def local_subnet():
    """Local IP and /24 base, found via a UDP 'connect' (sends no packets)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        return ip, ip.rsplit(".", 1)[0]
    except OSError:
        return "127.0.0.1", "127.0.0"


def discover_lan():
    """Sweep the local /24. A host counts as alive if any probe port answers
    (open OR refused/RST); only silence (timeout) means 'no response'."""
    local_ip, base = local_subnet()
    print(f"\n  Local IP: {local_ip} | Sweeping {base}.1 - {base}.254 ...")

    def check(ip):
        for port in PROBE_PORTS:
            if probe(ip, port, 0.3) != "filtered":
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except OSError:
                    name = "Active Device"
                return ip, port, name
        return None

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=100) as ex:
        found = [h for h in ex.map(check, [f"{base}.{i}" for i in range(1, 255)]) if h]
    found.sort(key=lambda h: int(h[0].rsplit(".", 1)[1]))

    hosts = []
    for ip, port, name in found:
        role = ("This Machine" if ip == local_ip
                else "Gateway / Router" if ip.endswith(".1") else name)
        print(f"  [+] {ip:<16} responder port {port:<5} | {role}")
        hosts.append((ip, role))
    print(f"  Done in {time.time() - t0:.2f}s - {len(hosts)} host(s) found.")

    if not hosts:
        print("[-] No hosts responded on the default probe ports.")
        return None
    print("\nSelect a host to scan:")
    for i, (ip, role) in enumerate(hosts, 1):
        print(f"  [{i}] {ip:<16} ({role})")
    print(f"  [{len(hosts) + 1}] Enter custom IP / domain\n  [0] Back")
    choice = input("Enter choice: ").strip()
    if choice.isdigit():
        c = int(choice)
        if 1 <= c <= len(hosts):
            return hosts[c - 1][0]
        if c == len(hosts) + 1:
            return input("Target IP or domain: ").strip()
    return None


def ask_ports():
    print("\nSelect port range:")
    print("  [1] Fast (Top 30)   [2] Standard (1-1024)   [3] Extended (1-10000)")
    print("  [4] Custom range    [5] Full (1-65535)")
    choice = input("Select preset (1-5, default 2): ").strip() or "2"
    if choice == "4":
        try:
            lo, hi = int(input("Start port: ")), int(input("End port: "))
        except ValueError:
            print("[-] Invalid port numbers.")
            return None
        if not 1 <= lo <= hi <= 65535:
            print("[-] Ports must satisfy 1 <= start <= end <= 65535.")
            return None
        return range(lo, hi + 1)
    return PRESETS.get(choice, PRESETS["2"])


def interactive_menu():
    while True:
        print("\n" + "=" * 62)
        print("        NetProbe - Network Port Analysis Suite")
        print("                   Team: Logic Link")
        print("=" * 62)
        print("  [1] Scan a host or domain")
        print("  [2] Discover servers on local network (LAN sweep)")
        print("  [3] Exit")
        choice = input("Enter option (1-3): ").strip()

        if choice == "1":
            target = input("\nTarget IP or domain (default 127.0.0.1): ").strip() or "127.0.0.1"
            ports = ask_ports()
            if ports:
                run_scan(target, ports)
        elif choice == "2":
            host = discover_lan()
            if host:
                run_scan(host, TOP_30_PORTS)
        elif choice == "3":
            print("\nExiting NetProbe. Thank you!\n")
            break
        else:
            print("[-] Invalid selection, enter 1-3.")


if __name__ == "__main__":
    try:
        interactive_menu()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye!")
