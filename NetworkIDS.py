from scapy.all import sniff, IP, TCP
from datetime import datetime

# Define a function to log suspicious activities
def log_suspicious_activity(activity):
    with open("intrusion_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()} - {activity}\n")
    print(activity)

# Define a function to detect suspicious packets
def detect_suspicious_packet(packet):
    # Check if the packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet[IP]

        # Example Rule 1: Detect traffic to/from suspicious IP
        suspicious_ips = ["192.168.1.100", "10.0.0.1"]
        if ip_layer.src in suspicious_ips or ip_layer.dst in suspicious_ips:
            log_suspicious_activity(f"Suspicious IP detected: {ip_layer.src} -> {ip_layer.dst}")

        # Check if the packet has a TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            # Example Rule 2: Detect traffic on suspicious ports
            suspicious_ports = [23, 2323]  # Telnet ports (commonly used for attacks)
            if tcp_layer.sport in suspicious_ports or tcp_layer.dport in suspicious_ports:
                log_suspicious_activity(f"Suspicious port detected: {ip_layer.src}:{tcp_layer.sport} -> {ip_layer.dst}:{tcp_layer.dport}")

# Define a function to start the sniffer
def start_sniffer(interface):
    try:
        print(f"Starting sniffer on interface {interface}...")
        sniff(iface=interface, prn=detect_suspicious_packet, store=False)
    except OSError as e:
        print(f"Error opening adapter: {e}")

# Main function
if __name__ == "__main__":
    interface = "Wi-Fi"  # Change this to the network interface you want to use
    start_sniffer(interface)