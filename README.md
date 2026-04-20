# NetScan — Multithreaded TCP Port Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

A fast, clean, production-quality TCP port scanner built in **pure Python — zero external dependencies**. Supports multithreaded scanning, banner grabbing, and CSV export.

> **Disclaimer:** This tool is for authorized security testing and educational purposes only. Never scan systems you don't own or have explicit written permission to test.

---

## Features

- **Multithreaded** — scans 200 ports simultaneously (configurable)
- **Banner grabbing** — pulls service version info from open ports
- **Smart service detection** — maps 25+ common ports to service names
- **CSV export** — saves results to a timestamped report file
- **Flexible port selection** — ranges, comma-separated lists, or common-ports preset
- **Colorized output** — works on Windows 10+, Linux, macOS
- **Zero dependencies** — pure Python standard library only

---

## Demo Output

```
  Target  : scanme.nmap.org  ->  45.33.32.156
  Ports   : 1,000 queued  |  Threads : 200

  [OPEN]  Port 22      SSH               SSH-2.0-OpenSSH_6.6.1p1
  [OPEN]  Port 80      HTTP              HTTP/1.1 200 OK
  [OPEN]  Port 9929    Unknown
  [OPEN]  Port 31337   Unknown

  Scan complete — 4.87s elapsed
  4 open port(s) found
```

---

## Installation

```bash
git clone https://github.com/yourusername/netscan.git
cd netscan
python scanner.py --help
```

No `pip install` needed.

---

## Usage

```bash
# Default: scan top 1000 ports
python scanner.py 192.168.1.1

# Scan a hostname
python scanner.py scanme.nmap.org

# Port range
python scanner.py 192.168.1.1 -p 1-500

# Specific ports
python scanner.py 192.168.1.1 -p 22,80,443,3306,3389

# Well-known ports only (fast mode)
python scanner.py 192.168.1.1 --common

# Export to CSV
python scanner.py 192.168.1.1 --csv

# Full scan with CSV
python scanner.py 10.0.0.1 -p 1-65535 --csv --threads 300
```

---

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `target` | IP address or hostname | required |
| `-p`, `--ports` | Range `1-1000` or list `22,80,443` | `1-1000` |
| `--common` | Scan top 25 well-known ports | off |
| `--csv` | Save results to CSV | off |
| `--threads` | Concurrent thread count | 200 |

---

## How It Works

1. Target hostname is resolved to an IP
2. Port list is built and loaded into a thread-safe queue
3. A pool of worker threads pulls ports from the queue and attempts TCP `connect_ex()`
4. On success, a banner grab is attempted (reads first response bytes)
5. Results are collected, sorted, and printed — and optionally exported to CSV

---

## Legal Notice

Only use on systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal. Legal practice targets: [scanme.nmap.org](http://scanme.nmap.org), HackTheBox, TryHackMe.

---

## Author

**Your Name** | [GitHub](https://github.com/yourusername) | [LinkedIn](https://linkedin.com/in/yourprofile)

MIT License
