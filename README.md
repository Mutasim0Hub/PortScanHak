# PortScanHak

**PortScanHak** is an asynchronous network port scanner inspired by Nmap.  
It allows fast and comprehensive scanning of open ports, detects service versions, grabs banners, and provides heuristic OS guesses.

> ⚠ **Disclaimer:** This tool is intended for educational purposes and authorized testing only. Do not use it on systems without permission.

## Features

- Asynchronous TCP port scanning using Python's `asyncio`.
- Support for:
  - Fast scan (Top 1024 ports)
  - Full scan (Ports 1-65535)
  - Custom ports
- Service detection and banner grabbing.
- Heuristic OS guessing based on open ports.
- Aggressive mode for version and OS detection.
- Configurable timeout and maximum concurrent connections.
- CLI with clear and informative output.

## Requirements

- Python 3.8+
- No additional external libraries required (built-in modules used).

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/PortScanHak.git
cd PortScanHak