from scapy.all import sniff
import threading

packet_count = 0
stop_sniffing = threading.Event()

def packet_handler(packet):
    global packet_count
    packet_count += 1
    print(f"Packets captured: {packet_count}")

def stop_filter(packet):
    return stop_sniffing.is_set()

def start_capture():
    interface = 'en0'
    port = '12001'
    capture_filter = f"port {port}"

    print(f"Starting packet capture on interface {interface} for port {port}...")
    sniff(iface=interface, filter=capture_filter, prn=packet_handler, stop_filter=stop_filter)

def stop_capture():
    stop_sniffing.set()

if __name__ == "__main__":
    capture_thread = threading.Thread(target=start_capture)
    capture_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        stop_capture()
        capture_thread.join()
        print("Packet capture stopped.")
