# Network Intrusion Detection System (NIDS)

This Python script implements a simple **Network Intrusion Detection System (NIDS)** that monitors network traffic for suspicious activity, including port scanning, DNS and ICMP flooding, and unauthorized access attempts. The system integrates with `iptables` to block malicious IP addresses and stores events in an SQLite database for analysis.

## Features

- **Traffic Monitoring**: Sniffs network traffic on a specified interface using `scapy` and analyzes incoming packets for suspicious activity.
- **Suspicious Activity Detection**:
  - **Port Scanning**: Detects rapid connection attempts to various ports.
  - **Flooding**: Identifies excessive DNS or ICMP requests, as well as rapid connection attempts to known critical ports.
  - **Suspicious Port Access**: Monitors connections to commonly targeted ports (SSH, RDP, SMB) and logs attempts.
- **IP Blocking**: Automatically blocks suspicious IPs using `iptables` to prevent further malicious activity.
- **Whitelisting**: Allows adding trusted IPs to a whitelist to avoid blocking legitimate traffic.
- **Database Logging**: Logs security events, blocked IPs, and whitelisted IPs in an SQLite database for tracking and auditing purposes.
- **Logging**: Maintains a log file (`ids.log`) for all actions and events for easy review.

## Requirements

- Python 3.x
- `scapy` library
- SQLite
- `iptables` for IP blocking

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/network-ids.git
    cd network-ids
    ```

2. Install dependencies:
    ```bash
    pip install scapy
    ```

## Usage

Run the script with the desired network interface to monitor:

```bash
python3 nids.py -i eth0
```
