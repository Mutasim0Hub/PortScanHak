import asyncio
import argparse
import socket
import sys
import logging
from datetime import datetime

DEFAULT_TIMEOUT = 2
DEFAULT_THREADS = 500
ALL_PORTS_RANGE = (1, 65535)
FAST_PORTS_RANGE = (1, 1025)

def print_banner():
    print(r"""
  ____            _   ____            _   _       _    
 |  _ \ ___  _ __| |_/ ___| ___  __ _| | | | __ _| | __
 | |_) / _ \| '__| __\___ \/ __|/ _` | |_| |/ _` | |/ /
 |  __/ (_) | |  | |_ ___) \__ \ (_| |  _  | (_| |   < 
 |_|   \___/|_|   \__|____/|___/\__,_|_| |_|\__,_|_|\_\
-Created by: Mutasim0Hub ^_^ -GitHub: https://github.com/Mutasim0Hub
               
        PortScanHak - Async Network Scanner
    """)
    
async def scan_port(ip, port, timeout, semaphore):
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, True
        except:
            return port, False


async def scan_ports(ip, ports, timeout, threads):
    semaphore = asyncio.Semaphore(threads)
    tasks = [scan_port(ip, p, timeout, semaphore) for p in ports]
    return await asyncio.gather(*tasks)


def get_service(port):
    try:
        return socket.getservbyport(port, "tcp")
    except:
        return "unknown"


async def grab_banner(ip, port, timeout):
    """
    Improved service-aware banner grabbing
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )

        if port in (80, 8080, 8000, 8888):
            req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: PortScan\r\n\r\n"
            writer.write(req.encode())
            await writer.drain()

        elif port == 25:
            writer.write(b"Hello example.com\r\n")
            await writer.drain()

    
        elif port not in (21, 22, 3306):
            writer.write(b"\r\n")
            await writer.drain()

        data = await asyncio.wait_for(reader.read(4096), timeout=timeout)

        writer.close()
        await writer.wait_closed()

        banner = data.decode(errors="ignore").strip()
        if not banner:
            return ""

        return banner.split("\n")[0].strip()

    except:
        return ""


def guess_os(open_ports):
    if 22 in open_ports and 80 in open_ports:
        return "Linux (Likely)"
    if 445 in open_ports or 3389 in open_ports:
        return "Windows (Likely)"
    return "Unknown"

async def run_scan(args):
    target = args.target
    timeout = args.timeout
    threads = args.threads

   
    if args.fast:
        ports = range(*FAST_PORTS_RANGE)
    elif args.p_all:
        ports = range(*ALL_PORTS_RANGE)
    elif args.ports:
        ports = args.ports
    else:
        ports = range(*FAST_PORTS_RANGE)

    logging.info(f"Scanning {target}")

    results = await scan_ports(target, ports, timeout, threads)

    ports_data = []
    open_ports = []

    for port, status in results:
        if status:
            entry = {
                "port": port,
                "state": "open",
                "service": get_service(port),
                "version": ""
            }
            open_ports.append(port)
            ports_data.append(entry)

        elif args.show_closed:
            ports_data.append({
                "port": port,
                "state": "closed",
                "service": get_service(port),
                "version": ""
            })

    if args.version or args.aggressive:
        for entry in ports_data:
            if entry["state"] == "open":
                banner = await grab_banner(target, entry["port"], timeout)
                if banner and len(banner) > 5:
                    entry["version"] = banner

    scan_data = {
        "target": target,
        "scan_time": datetime.now().isoformat(),
        "ports": ports_data
    }

    if args.os or args.aggressive:
        scan_data["os_guess"] = guess_os(open_ports)

    return scan_data

def print_results(data):
    print(f"\nNmap scan report for {data['target']}")
    print("=" * 72)
    print(f"{'PORT':<9} {'STATE':<7} {'SERVICE':<10} {'VERSION'}")
    print("-" * 72)

    for entry in data["ports"]:
        port_str = f"{entry['port']}/tcp"
        version = entry["version"][:60] if entry["version"] else ""
        print(f"{port_str:<9} {entry['state']:<7} {entry['service']:<10} {version}")

    if "os_guess" in data:
        print(f"\nOS details: {data['os_guess']}")

def parse_args():
    parser = argparse.ArgumentParser(
        description="PortScanHak - Educational Async Network Scanner",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument("target", help="Target IP or hostname")

    parser.add_argument("-sT", action="store_true", help="TCP Connect Scan (default)")
    parser.add_argument("-sS", action="store_true", help="SYN Scan (simulated)")

    parser.add_argument("-p", dest="ports", nargs="+", type=int,
                        help="Scan specific ports (e.g. -p 22 80 443)")
    parser.add_argument("-p-", dest="p_all", action="store_true",
                        help="Scan all ports (1-65535)")
    parser.add_argument("-f", dest="fast", action="store_true",
                        help="Fast scan (Top 1024 ports)")
  
    parser.add_argument("-V", dest="version", action="store_true",
                        help="Service & version detection")
    parser.add_argument("-O", dest="os", action="store_true",
                        help="OS detection (heuristic)")
    parser.add_argument("-A", dest="aggressive", action="store_true",
                        help="Aggressive scan (-V -O)")

    parser.add_argument("--show-closed", action="store_true",
                        help="Show closed ports")

    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="Connection timeout (seconds)")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help="Max concurrent connections")

    return parser.parse_args()

def main():
    args = parse_args()
    print_banner()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    try:
        data = asyncio.run(run_scan(args))
        print_results(data)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)

if __name__ == "__main__":
    main()
