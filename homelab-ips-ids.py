#!/usr/bin/env python3

import scapy.all as scapy
from datetime import datetime
import sqlite3
import argparse
import logging
from collections import defaultdict
import threading
import time

class NetworkIDS:
    def __init__(self, interface, db_path="ids.db"):
        self.interface = interface
        self.db_path = db_path
        self.suspicious_ips = set()
        self.connection_attempts = defaultdict(int)
        self.dns_requests = defaultdict(int)
        self.icmp_requests = defaultdict(int)
        self.last_cleanup = time.time()
        self.whitelisted_ips = set()
        
        # Configure logging
        logging.basicConfig(
            filename='ids.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        
        # Initialize database
        self.init_database()
        
        # Load whitelisted IPs
        self.load_whitelist()
        
        # Thresholds for detecting suspicious activity
        self.MAX_CONNECTIONS_PER_MINUTE = 100
        self.PORT_SCAN_THRESHOLD = 15
        self.DNS_FLOOD_THRESHOLD = 50
        self.ICMP_FLOOD_THRESHOLD = 50
        self.BLOCKED_PORTS = {22, 3389, 445}  # SSH, RDP, SMB
        
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        # Create tables for storing events and blocked IPs
        c.execute('''CREATE TABLE IF NOT EXISTS security_events
                    (timestamp TEXT, source_ip TEXT, destination_ip TEXT, 
                     port INTEGER, event_type TEXT, action_taken TEXT)''')
        
        c.execute('''CREATE TABLE IF NOT EXISTS blocked_ips
                    (ip_address TEXT PRIMARY KEY, timestamp TEXT, reason TEXT)''')
        
        # Create whitelist table
        c.execute('''CREATE TABLE IF NOT EXISTS whitelist
                    (ip_address TEXT PRIMARY KEY, timestamp TEXT, description TEXT)''')
        
        conn.commit()
        conn.close()
    
    def load_whitelist(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        
        c.execute("SELECT ip_address FROM whitelist")
        whitelist = c.fetchall()
        self.whitelisted_ips = set(ip[0] for ip in whitelist)
        
        conn.close()
        
    def add_to_whitelist(self, ip_address, description="Allowed SSH connection"):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        c.execute('''INSERT OR REPLACE INTO whitelist VALUES (?, ?, ?)''',
                 (ip_address, timestamp, description))
        
        conn.commit()
        conn.close()
        
        self.whitelisted_ips.add(ip_address)
        logging.info(f"Added {ip_address} to whitelist - {description}")
        
        # Remove from blocked IPs if present
        if ip_address in self.suspicious_ips:
            self.suspicious_ips.remove(ip_address)
            # Remove iptables rule if exists
            import subprocess
            try:
                subprocess.run(['sudo', 'iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'DROP'])
                logging.info(f"Removed iptables block rule for whitelisted IP {ip_address}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to remove iptables rule: {e}")
    
    def log_event(self, source_ip, dest_ip, port, event_type, action):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        timestamp = datetime.now().isoformat()
        
        c.execute('''INSERT INTO security_events VALUES (?, ?, ?, ?, ?, ?)''',
                 (timestamp, source_ip, dest_ip, port, event_type, action))
        
        conn.commit()
        conn.close()
        logging.info(f"Security Event: {event_type} from {source_ip} to {dest_ip}:{port} - {action}")
    
    def block_ip(self, ip_address, reason):
        if ip_address not in self.suspicious_ips and ip_address not in self.whitelisted_ips:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            timestamp = datetime.now().isoformat()
            
            c.execute('''INSERT OR REPLACE INTO blocked_ips VALUES (?, ?, ?)''',
                     (ip_address, timestamp, reason))
            
            conn.commit()
            conn.close()
            
            self.suspicious_ips.add(ip_address)
            logging.warning(f"Blocked IP {ip_address} - Reason: {reason}")
            
            # Add iptables rule to block the IP
            import subprocess
            try:
                subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'])
                logging.info(f"Added iptables rule to block {ip_address}")
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to add iptables rule: {e}")
    
    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            
            # Skip if source IP is whitelisted
            if src_ip in self.whitelisted_ips:
                return
            
            # Skip if source IP is already blocked
            if src_ip in self.suspicious_ips:
                return
            
            # DNS Flood Detection
            if packet.haslayer(scapy.DNSQR):
                self.dns_requests[src_ip] += 1
                if self.dns_requests[src_ip] > self.DNS_FLOOD_THRESHOLD:
                    self.block_ip(src_ip, "DNS Flooding Detected")
                    return

            # ICMP Flood Detection
            if packet.haslayer(scapy.ICMP):
                self.icmp_requests[src_ip] += 1
                if self.icmp_requests[src_ip] > self.ICMP_FLOOD_THRESHOLD:
                    self.block_ip(src_ip, "ICMP Flooding Detected")
                    return
            
            # Check for suspicious ports (SSH, RDP, SMB)
            if packet.haslayer(scapy.TCP):
                dst_port = packet[scapy.TCP].dport
                if dst_port in self.BLOCKED_PORTS:
                    self.log_event(src_ip, dst_ip, dst_port, "Suspicious Port Access", "Monitored")
                    self.connection_attempts[src_ip] += 1
            
            # Potential port scanning detection
            if time.time() - self.last_cleanup > 60:  # Cleanup every minute
                self.connection_attempts.clear()
                self.dns_requests.clear()
                self.icmp_requests.clear()
                self.last_cleanup = time.time()
            
            # Detect rapid connection attempts (Port Scanning)
            if self.connection_attempts[src_ip] > self.PORT_SCAN_THRESHOLD:
                self.block_ip(src_ip, "Potential Port Scanning")
            
            # Detect flooding (excessive connections)
            if self.connection_attempts[src_ip] > self.MAX_CONNECTIONS_PER_MINUTE:
                self.block_ip(src_ip, "Connection Flooding")

    def start_monitoring(self):
        logging.info(f"Starting network monitoring on interface {self.interface}")
        try:
            scapy.sniff(iface=self.interface, store=False, prn=self.analyze_packet)
        except KeyboardInterrupt:
            logging.info("Stopping network monitoring")
        except Exception as e:
            logging.error(f"Error during monitoring: {e}")

def main():
    parser = argparse.ArgumentParser(description='Network Intrusion Detection System')
    parser.add_argument('-i', '--interface', required=True, help='Network interface to monitor')
    parser.add_argument('-d', '--database', default='ids.db', help='Path to SQLite database')
    parser.add_argument('--whitelist', help='Add IP to whitelist')
    parser.add_argument('--whitelist-desc', help='Description for whitelisted IP')
    args = parser.parse_args()
    
    ids = NetworkIDS(args.interface, args.database)
    
    # Add IP to whitelist if specified
    if args.whitelist:
        ids.add_to_whitelist(args.whitelist, args.whitelist_desc or "Added via command line")
    
    ids.start_monitoring()

if __name__ == "__main__":
    main()
