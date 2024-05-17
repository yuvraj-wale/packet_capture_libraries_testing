import pcap

count=0

def packet_handler(ts, pkt):
    global count
    count+=1
    print(f"Packet captured: length {count}")

def main():
    interface = 'en0'
    p = pcap.pcap(name=interface, promisc=True, immediate=True)
    p.setfilter('port 12001')

    try:
        for ts, pkt in p:
            packet_handler(ts, pkt)
    except KeyboardInterrupt:
        print("Stopping packet capture")

if __name__ == "__main__":
    main()
