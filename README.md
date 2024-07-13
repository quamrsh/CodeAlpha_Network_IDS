Simple Network Intrusion Detection System (IDS)
This project implements a simple Network Intrusion Detection System (IDS) using Python and Scapy. The IDS monitors network traffic and logs suspicious activities based on predefined rules.

Features
Suspicious IP Detection: Logs and alerts when traffic involves specific suspicious IP addresses.
Suspicious Port Detection: Logs and alerts when traffic involves specific suspicious ports, such as Telnet ports (commonly used for attacks).
Prerequisites
Python 3.x
Scapy library
Installation
Install Python: If you don't have Python installed, download and install it from the official website.

Install Scapy: Use pip to install Scapy.

pip install scapy

Usage
Download the Code: Save the provided script as network_ids.py.

Run the Script: Execute the script with the network interface you want to monitor.

python network_ids.py
Make sure to replace "Wi-Fi" with the appropriate network interface name for your system.



Code Explanation
Imports

from scapy.all import sniff, IP, TCP
from datetime import datetime
sniff: Function from Scapy to capture network packets.
IP, TCP: Classes from Scapy to handle IP and TCP layers.
datetime: Module to handle date and time for logging.


Logging Suspicious Activities

def log_suspicious_activity(activity):
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {activity}\n")
    print(activity)
log_suspicious_activity: Function to log and print suspicious activities.


Detecting Suspicious Packets

def detect_suspicious_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        suspicious_ips = ["192.168.1.100", "10.0.0.1"]
        if ip_layer.src in suspicious_ips or ip_layer.dst in suspicious_ips:
            log_suspicious_activity(f"Suspicious IP detected: {ip_layer.src} -> {ip_layer.dst}")

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            suspicious_ports = [23, 2323]
            if tcp_layer.sport in suspicious_ports or tcp_layer.dport in suspicious_ports:
                log_suspicious_activity(f"Suspicious port detected: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")
detect_suspicious_packet: Function to detect and log suspicious packets based on IP addresses and TCP ports.


Starting the Sniffer

def start_sniffer(interface):
    try:
        print(f"Starting sniffer on interface {interface}...")
        sniff(iface=interface, prn=detect_suspicious_packet, store=False)
    except OSError as e:
        print(f"Error opening adapter: {e}")
start_sniffer: Function to start the network sniffer on the specified interface.


Main Function

if __name__ == "__main__":
    interface = "Wi-Fi"
    start_sniffer(interface)

The main function sets the network interface and starts the sniffer.


Customization
Suspicious IPs: Modify the suspicious_ips list to include IP addresses you want to monitor.
Suspicious Ports: Modify the suspicious_ports list to include ports you want to monitor.


Logging
Suspicious activities are logged in the intrusion_log.txt file with a timestamp.


Disclaimer
This is a simple educational project and should not be used as a sole security measure for any network. For production environments, consider using more sophisticated and comprehensive IDS solutions.

