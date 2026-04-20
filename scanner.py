#!/usr/bin/env python3
"""
NetScan - Professional Port Scanner
Author  : Your Name
GitHub  : github.com/yourusername/netscan
License : MIT
"""

import socket
import threading
import argparse
import csv
import sys
import ipaddress
from datetime import datetime
from queue import Queue

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────
MAX_THREADS    = 200
SOCKET_TIMEOUT = 0.8
BANNER_TIMEOUT = 1.5

COMMON_PORTS = {
    21:    "FTP",           22:    "SSH",          23:    "Telnet",
    25:    "SMTP",          53:    "DNS",           80:    "HTTP",
    110:   "POP3",          111:   "RPC",           135:   "MSRPC",
    139:   "NetBIOS",       143:   "IMAP",          443:   "HTTPS",
    445:   "SMB",           993:   "IMAPS",         995:   "POP3S",
    1433:  "MSSQL",         1521:  "Oracle DB",     3306:  "MySQL",
    3389:  "RDP",           5432:  "PostgreSQL",    5900:  "VNC",
    6379:  "Redis",         8080:  "HTTP-Alt",      8443:  "HTTPS-Alt",
    8888:  "Jupyter",       9200:  "Elasticsearch", 27017: "MongoDB",
}

class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

# ──────────────────────────────────────────────
#  BANNER GRABBER
# ──────────────────────────────────────────────
def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(BANNER_TIMEOUT)
            s.connect((ip, port))
            if port in (80, 8080, 8888):
                s.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            else:
                s.send(b"\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner.split("\n")[0][:80] if banner else ""
    except Exception:
        return ""

# ──────────────────────────────────────────────
#  PORT SCANNER WORKER
# ──────────────────────────────────────────────
def scan_port(ip, port, results, lock):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(SOCKET_TIMEOUT)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner  = grab_banner(ip, port)
                entry   = {"port": port, "state": "OPEN", "service": service, "banner": banner}
                with lock:
                    results.append(entry)
                    banner_str = f"  {C.DIM}{banner}{C.RESET}" if banner else ""
                    print(
                        f"  {C.GREEN}[OPEN]{C.RESET}  "
                        f"Port {C.BOLD}{port:<6}{C.RESET}  "
                        f"{C.CYAN}{service:<18}{C.RESET}"
                        f"{banner_str}"
                    )
    except Exception:
        pass

# ──────────────────────────────────────────────
#  THREAD POOL
# ──────────────────────────────────────────────
def run_scan(ip, ports):
    results = []
    lock    = threading.Lock()
    queue   = Queue()
    for port in ports:
        queue.put(port)

    def worker():
        while not queue.empty():
            try:
                port = queue.get_nowait()
            except Exception:
                break
            scan_port(ip, port, results, lock)
            queue.task_done()

    threads = []
    for _ in range(min(MAX_THREADS, len(ports))):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

    return sorted(results, key=lambda x: x["port"])

# ──────────────────────────────────────────────
#  CSV EXPORT
# ──────────────────────────────────────────────
def export_csv(results, ip):
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_{ip.replace('.','_')}_{ts}.csv"
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["port","state","service","banner"])
        writer.writeheader()
        writer.writerows(results)
    return filename

# ──────────────────────────────────────────────
#  RESOLVE TARGET
# ──────────────────────────────────────────────
def resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{C.RED}[!] Cannot resolve '{target}'.{C.RESET}")
        sys.exit(1)

# ──────────────────────────────────────────────
#  ARGUMENT PARSER
# ──────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="NetScan — Multithreaded TCP Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python scanner.py 192.168.1.1\n"
            "  python scanner.py scanme.nmap.org -p 1-1000\n"
            "  python scanner.py 10.0.0.1 --common --csv\n"
            "  python scanner.py 192.168.1.1 -p 22,80,443,3306\n"
        )
    )
    parser.add_argument("target",        help="Target IP or hostname")
    parser.add_argument("-p","--ports",  help="Ports: '1-1000' or '22,80,443'", default=None)
    parser.add_argument("--common",      help="Scan well-known ports only", action="store_true")
    parser.add_argument("--csv",         help="Export results to CSV",       action="store_true")
    parser.add_argument("--threads",     help=f"Thread count (default {MAX_THREADS})", type=int, default=MAX_THREADS)
    return parser.parse_args()

def build_port_list(args):
    if args.common:
        return sorted(COMMON_PORTS.keys())
    if args.ports:
        if "," in args.ports:
            return [int(p.strip()) for p in args.ports.split(",")]
        if "-" in args.ports:
            start, end = args.ports.split("-")
            return list(range(int(start), int(end) + 1))
        return [int(args.ports)]
    return list(range(1, 1001))

# ──────────────────────────────────────────────
#  DISPLAY
# ──────────────────────────────────────────────
def print_header(ip, target, ports):
    print()
    print(f"{C.BOLD}{C.CYAN}  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚██╗{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝{C.RESET}")
    print()
    print(f"  {C.DIM}Multithreaded TCP Port Scanner | For authorized use only{C.RESET}")
    print(f"  {'─'*56}")
    print(f"  Target  : {C.WHITE}{target}{C.RESET}  ->  {C.YELLOW}{ip}{C.RESET}")
    print(f"  Ports   : {C.WHITE}{len(ports):,}{C.RESET} queued")
    print(f"  Threads : {C.WHITE}{MAX_THREADS}{C.RESET}")
    print(f"  Time    : {C.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{C.RESET}")
    print(f"  {'─'*56}")
    print()

def print_summary(results, elapsed, csv_file=None):
    print()
    print(f"  {'─'*56}")
    print(f"  {C.BOLD}Scan complete{C.RESET} — {elapsed:.2f}s elapsed")
    print()
    if results:
        print(f"  {C.GREEN}{C.BOLD}{len(results)} open port(s) found:{C.RESET}")
        print()
        print(f"  {'PORT':<8}{'SERVICE':<20}BANNER")
        print(f"  {'─'*54}")
        for r in results:
            banner = (r['banner'][:43] + "…") if len(r['banner']) > 43 else r['banner']
            print(
                f"  {C.YELLOW}{r['port']:<8}{C.RESET}"
                f"{C.CYAN}{r['service']:<20}{C.RESET}"
                f"{C.DIM}{banner}{C.RESET}"
            )
    else:
        print(f"  {C.RED}No open ports detected.{C.RESET}")
    if csv_file:
        print()
        print(f"  {C.GREEN}[+]{C.RESET} Saved -> {C.WHITE}{csv_file}{C.RESET}")
    print()

# ──────────────────────────────────────────────
#  ENTRY POINT
# ──────────────────────────────────────────────
def main():
    if sys.platform == "win32":
        import os
        os.system("color")   # enable ANSI on Windows terminal

    args  = parse_args()
    ip    = resolve_target(args.target)
    ports = build_port_list(args)
    global MAX_THREADS
    MAX_THREADS = args.threads

    print_header(ip, args.target, ports)

    start   = datetime.now()
    results = run_scan(ip, ports)
    elapsed = (datetime.now() - start).total_seconds()

    csv_file = None
    if args.csv and results:
        csv_file = export_csv(results, ip)

    print_summary(results, elapsed, csv_file)


if __name__ == "__main__":
    main()
