import scapy.all as scapy
import numpy as np
import time

# Set the mean and standard deviation for the normal distribution
mean_value = 100
std_dev = 10
count=0

# Generate random values from a normal distribution
def random_normal():
    return int(np.random.normal(mean_value, std_dev))

# Create Ethernet packet
def create_eth_packet(src_mac, dst_mac):
    eth_packet = scapy.Ether(src=src_mac, dst=dst_mac)
    return eth_packet

# Create IP packet
def create_ip_packet(src_ip, dst_ip):
    ip_packet = scapy.IP(src=src_ip, dst=dst_ip)
    return ip_packet

# Create ICMP packet
def create_icmp_packet():
    icmp_packet = scapy.ICMP(type=random_normal() % 255, code=random_normal() % 255)
    return icmp_packet

# Create TCP packet
def create_tcp_packet(src_port, dst_port):
    tcp_packet = scapy.TCP(sport=src_port, dport=dst_port)
    return tcp_packet

# Create UDP packet
def create_udp_packet(src_port, dst_port):
    udp_packet = scapy.UDP(sport=src_port, dport=dst_port)
    return udp_packet

# Create SMTP packet
def create_smtp_packet(src_port, dst_port):
    smtp_packet = scapy.TCP(sport=src_port, dport=dst_port)
    smtp_payload = scapy.Raw(load="EHLO example.com\r\n")
    return smtp_packet / smtp_payload

# Create POP3 packet
def create_pop3_packet(src_port, dst_port):
    pop3_packet = scapy.TCP(sport=src_port, dport=dst_port)
    pop3_payload = scapy.Raw(load="USER username\r\nPASS password\r\n")
    return pop3_packet / pop3_payload

# Create FTP packet
def create_ftp_packet(src_port, dst_port):
    ftp_packet = scapy.TCP(sport=src_port, dport=dst_port)
    ftp_payload = scapy.Raw(load="USER username\r\nPASS password\r\n")
    return ftp_packet / ftp_payload

# Create HTTPS packet
def create_https_packet(src_port, dst_port):
    https_packet = scapy.TCP(sport=src_port, dport=dst_port)
    https_payload = scapy.Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return https_packet / https_payload

# Create HTTP packet
def create_http_packet(src_port, dst_port):
    http_packet = scapy.TCP(sport=src_port, dport=dst_port)
    http_payload = scapy.Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    return http_packet / http_payload

# Create encrypted packet (placeholder)
def create_encrypted_packet(src_port, dst_port):
    encrypted_packet = scapy.Raw(load="ENCRYPTED_PAYLOAD")
    return encrypted_packet

# Generate and send packets at specified rate
def send_packets(rate_gbps, num_packets, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port):
    global count
    # Calculate sleep time based on rate
    sleep_time = (1 / (rate_gbps * 10**9 / 8)) - 0.000001  # Subtract a small constant to account for processing time

    # Ensure sleep_time is non-negative
    if sleep_time < 0:
        sleep_time = 0

    for _ in range(num_packets):
        packet_type = np.random.choice(['tcp', 'udp', 'smtp', 'pop3', 'ftp', 'https', 'http', 'encrypted'])

        if packet_type == 'tcp':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_tcp_packet(src_port, dst_port)
        elif packet_type == 'udp':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_udp_packet(src_port, dst_port)
        elif packet_type == 'smtp':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_smtp_packet(25, dst_port)
        elif packet_type == 'pop3':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_pop3_packet(110, dst_port)
        elif packet_type == 'ftp':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_ftp_packet(21, dst_port)
        elif packet_type == 'https':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_https_packet(443, dst_port)
        elif packet_type == 'http':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_http_packet(80, dst_port)
        elif packet_type == 'encrypted':
            pkt = create_eth_packet(src_mac, dst_mac) / create_ip_packet(src_ip, dst_ip) / create_encrypted_packet(443, dst_port)

        scapy.sendp(pkt, iface="en0")  # Replace "en0" with your network interface name
        count+=1
        print(count)
        time.sleep(sleep_time)

# Parameters
num_packets = 1000  # Number of packets to send
rate_gbps = 10  # Desired rate in Gbps
src_mac = "00:00:00:00:00:00"  # Source MAC address
dst_mac = "00:00:00:00:00:00"  # Destination MAC address
src_ip = "YOUR_SRC_IP" # Source IP address
dst_ip = "YOUR_DST_IP" # Destination IP address
src_port = 12345  # Source port
dst_port = 12001  # Destination port

# Send packets
send_packets(rate_gbps, num_packets, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
