# PortScan

```
  ██████╗  ██████╗ ██████╗ ████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║   ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

A fast multi-threaded port scanner with CLI and interactive mode.

## Installation

```bash
git clone https://github.com/RDaneel-5090/portscan.git
cd portscan
pip install scapy  # optional, for advanced scans
```

> **Windows**: Install [Npcap](https://npcap.com) first.

## Usage

```bash
# Interactive mode
python portscan_pro.py

# CLI mode
python portscan.py -H 192.168.1.1 -p 22,80,443
python portscan.py -H example.com -r 1-1000
python portscan.py -H 10.0.0.1 -p top -o results.json
```

## Commands (Interactive)

| Command | Description |
|---------|-------------|
| `scan`  | Custom scan (choose target, ports, type) |
| `quick` | Quick scan — top 100 ports |
| `full`  | Full scan — all 65535 ports |
| `common`| Web ports only (80, 443, 8080...) |
| `help`  | Show scan types |
| `exit`  | Quit |

## CLI Options

| Option | Description |
|--------|-------------|
| `-H`   | Target host (IP or hostname) |
| `-p`   | Ports (`22,80,443` or `top` or `*`) |
| `-r`   | Port range (`1-1000`) |
| `-s`   | Scan type (1-8) |
| `-t`   | Timeout in seconds |
| `-T`   | Number of threads |
| `-o`   | Output file (.txt or .json) |
| `-v`   | Verbose mode |

## Port Formats

| Format | Example | Description |
|--------|---------|-------------|
| Single | `80` | Scan port 80 |
| Range | `1-1000` | Scan ports 1 to 1000 |
| List | `22,80,443` | Scan specific ports |
| Top | `top` | Top 100 common ports |
| All | `*` | All 65535 ports |

## Scan Types

| # | Type | Description |
|---|------|-------------|
| 1 | TCP Connect | Full handshake — reliable, no root |
| 2 | TCP SYN | Half-open — stealth, needs root |
| 3 | UDP | UDP scan — slow |
| 4 | NULL | No flags — evades firewalls |
| 5 | FIN | FIN flag only |
| 6 | Xmas | FIN+PSH+URG flags |
| 7 | ACK | Firewall detection |
| 8 | Window | TCP window analysis |

> Types 2-8 require Scapy and root privileges.

## Output

```
[✓] open          — Port is open
[✗] closed        — Port is closed  
[!] filtered      — Blocked by firewall
[!] open|filtered — No response (UDP)
```

## Features

- Multi-threaded scanning (100 threads default)
- Works with or without Scapy
- JSON and TXT export
- 50+ known services detection
- Progress bar for large scans

## Disclaimer

For educational and authorized testing only. Unauthorized scanning is illegal.

## Author

RDaneel-5090
