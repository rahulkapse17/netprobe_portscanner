# NetProbe

**Network Port Analysis & Server Discovery Suite**
Team: **Logic Link** | Domain: Computer Networks & Cybersecurity

NetProbe is a single-file Python tool that combines a multi-threaded TCP port scanner, a LAN host discovery sweep, and a security risk analyzer. It uses only the Python standard library, so there is nothing to install.

> ⚠️ **Legal notice:** Only scan systems you own or have explicit permission to test. Unauthorized port scanning may be illegal.

---

## Features

- **Multi-threaded TCP connect scan** with open / closed / filtered detection
- **Banner grabbing** for open ports (including HTTP `Server:` headers)
- **LAN discovery**: sweeps the local /24 subnet and lets you pick a host to scan
- **Service identification** for 60+ well-known ports
- **Risk analysis**: each open port is rated HIGH / MEDIUM / LOW / INFO with a remediation tip
- **Overall risk score** (0-100) per scan
- **Auto-saved reports** as timestamped `.txt` files
- **Safety prompt** that asks for confirmation before scanning public IPs
- **Zero dependencies**: standard library only

---

## Requirements

- Python 3.6+
- Works on Windows, Linux and macOS

---

## Installation

```bash
git clone https://github.com/rahulkapse17/netprobe.git
cd netprobe
```

---

## Usage

```bash
python3 netprobe.py
```

You will see an interactive menu:

```
[1] Scan a host or domain
[2] Discover servers on local network (LAN sweep)
[3] Exit
```

### 1. Scan a host or domain

Enter an IP or domain (default `127.0.0.1`), then choose a port range:

| Option | Preset | Ports |
|--------|--------|-------|
| 1 | Fast | Top 30 common ports |
| 2 | Standard (default) | 1-1024 |
| 3 | Extended | 1-10000 |
| 4 | Custom | Your own start/end |
| 5 | Full | 1-65535 |

### 2. LAN sweep

Detects your local IP, sweeps `x.x.x.1` to `x.x.x.254`, lists responding hosts (with hostnames where available), and lets you select one to scan with the Top 30 preset.

---

## Sample Output

```
Target        : 127.0.0.1 (127.0.0.1)
Scanned       : 30  | Open: 3  Closed: 27  Filtered: 0
----------------------------------------------------------------------
PORT    STATE   SERVICE            RISK    BANNER
----------------------------------------------------------------------
80      OPEN    HTTP               LOW     Server: nginx
445     OPEN    SMB                HIGH
3306    OPEN    MySQL/MariaDB      HIGH
----------------------------------------------------------------------
OVERALL RISK: HIGH  (score 22/100)
SECURITY FINDINGS:
  [HIGH  ] port 445   SMB is a prime ransomware/worm target; block outside LAN
  [HIGH  ] port 3306  Database exposed to network; bind to localhost/firewall it
  [LOW   ] port 80    Unencrypted HTTP; redirect to HTTPS
```

Reports are saved automatically as `netprobe_report_<ip>_<YYYYMMDD_HHMMSS>.txt`.

---

## How Risk Scoring Works

| Severity | Points per open port | Examples |
|----------|---------------------|----------|
| HIGH | 10 | Telnet, FTP, SMB, RDP, exposed databases, Redis |
| MEDIUM | 5 | MSRPC, NetBIOS, dev servers (3000, 5000, 8000, 8080) |
| LOW | 2 | HTTP, SSH |
| INFO | 0 | HTTPS, ports with no known rule |

The score is the sum of points, capped at 100. The overall rating is the highest severity found.

---

## How It Works

1. **Probe:** a TCP connect attempt. Success means *open*, a refused connection (RST) means *closed*, and a timeout means *filtered*.
2. **Banner grab:** for open ports, reads the service banner (sends a `HEAD /` request for HTTP ports).
3. **Assess:** maps each open port to a risk rule and builds the report.
4. **Discover:** for the LAN sweep, a host counts as alive if any probe port answers (open or refused).

---

## Limitations

- TCP only. UDP services (DNS, NTP, SNMP, TFTP, DHCP) cannot be reliably detected.
- LAN sweep assumes a /24 subnet.
- Fixed 0.5s connection timeout, so results over slow links may show open ports as filtered.
- Risk ratings are rule-based on port number, not on actual vulnerability testing.

---

## Project Structure

```
netprobe/
├── netprobe.py   # entire application
└── README.md
```

---

## Team

**Logic Link**

---

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. The authors are not responsible for any misuse.
